(* Frama-C kernel AST dump: one JSON object per defined function, written to $FRAMAC_AST_DUMP_OUT.

   Compiled and loaded by scripts/kernel_ast.py (`ocamlfind ocamlopt -shared`, then
   `frama-c -load-module`). It reports what the C/ACSL lexer in acsl_ast.py cannot see: the code
   after macro expansion, resolved types, and kernel normalization (a single `return`, explicit
   temporaries). It only reads the AST and has no effect on any analysis result.

   Everything printed is the kernel's normalized C, so it can differ textually from the source.
   Locations stay raw strings (Fclib.Fileloc.pretty): kernel_ast.py parses them, which keeps this
   file independent of the Fileloc API that is still moving between Frama-C versions. *)

open Frama_c_kernel
open Cil_types

(* --- JSON ------------------------------------------------------------------------------------ *)

type json =
  | S of string
  | I of int
  | B of bool
  | Null
  | L of json list
  | O of (string * json) list

let escape s =
  let b = Buffer.create (String.length s + 8) in
  String.iter
    (fun c ->
       match c with
       | '"' -> Buffer.add_string b "\\\""
       | '\\' -> Buffer.add_string b "\\\\"
       | '\n' -> Buffer.add_string b "\\n"
       | '\r' -> Buffer.add_string b "\\r"
       | '\t' -> Buffer.add_string b "\\t"
       | c when Char.code c < 0x20 -> Buffer.add_string b (Printf.sprintf "\\u%04x" (Char.code c))
       | c -> Buffer.add_char b c)
    s;
  Buffer.contents b

let rec write b = function
  | S s -> Buffer.add_char b '"'; Buffer.add_string b (escape s); Buffer.add_char b '"'
  | I i -> Buffer.add_string b (string_of_int i)
  | B v -> Buffer.add_string b (if v then "true" else "false")
  | Null -> Buffer.add_string b "null"
  | L items ->
    Buffer.add_char b '[';
    List.iteri (fun i x -> if i > 0 then Buffer.add_char b ','; write b x) items;
    Buffer.add_char b ']'
  | O fields ->
    Buffer.add_char b '{';
    List.iteri
      (fun i (k, v) ->
         if i > 0 then Buffer.add_char b ',';
         write b (S k);
         Buffer.add_char b ':';
         write b v)
      fields;
    Buffer.add_char b '}'

(* --- Printing -------------------------------------------------------------------------------- *)

(* One line, however long: the Format margin would otherwise fold expressions. *)
let one_line pp x =
  let b = Buffer.create 64 in
  let f = Format.formatter_of_buffer b in
  Format.pp_set_margin f 1_000_000;
  Format.pp_set_max_indent f 999_999;
  pp f x;
  Format.pp_print_flush f ();
  String.concat " " (List.filter (fun s -> s <> "") (String.split_on_char '\n' (Buffer.contents b)))

let exp_s = one_line Printer.pp_exp
let lval_s = one_line Printer.pp_lval
let typ_s = one_line Printer.pp_typ
let loc_s = one_line Fclib.Fileloc.pretty

(* Bounds what one pathological function can add to the dump; a cut is reported as `truncated`. *)
let max_items = 64
let max_paths = 32

(* --- Bases and accesses ------------------------------------------------------------------------ *)

(* The variable an address expression is derived from: `p + i`, `&a[i]`, `(char * )p->q`. *)
let rec base_of_exp e =
  match (Cil.stripCasts e).enode with
  | Lval (Var v, _) | StartOf (Var v, _) | AddrOf (Var v, _) -> Some v
  | Lval (Mem e', _) | StartOf (Mem e', _) | AddrOf (Mem e', _) -> base_of_exp e'
  | BinOp ((PlusPI | MinusPI), a, _, _) -> base_of_exp a
  | _ -> None

let base_of_lval = function
  | Var v, _ -> Some v
  | Mem e, _ -> base_of_exp e

let base_kind (v : varinfo) =
  if v.vglob then "global" else if v.vformal then "formal" else "local"

(* Written or read memory: not a plain scalar local or formal, whose access is not a frame fact. *)
let is_memory_access (host, off) =
  match host with
  | Mem _ -> true
  | Var v -> v.vglob || off <> NoOffset

let rec offset_mentions_strided_index = function
  | NoOffset -> false
  | Field (_, off) -> offset_mentions_strided_index off
  | Index (e, off) -> exp_is_strided e || offset_mentions_strided_index off

and exp_is_strided e =
  match (Cil.stripCasts e).enode with
  | BinOp (Mult, a, b, _) ->
    let is_int_const x = Option.is_some (Cil.isInteger (Cil.stripCasts x)) in
    let stride x =
      match Cil.isInteger (Cil.stripCasts x) with
      | Some k -> Z.gt k Z.one
      | None -> false
    in
    (stride a && not (is_int_const b)) || (stride b && not (is_int_const a))
  | BinOp ((PlusA | MinusA | PlusPI | MinusPI), a, b, _) -> exp_is_strided a || exp_is_strided b
  | _ -> false

(* `a[2*i]`, `*(a + 2*i)`, `*(a + (2*i + 1))`: an index stepping by a constant stride over 1. *)
let lval_is_strided (host, off) =
  (match host with
   | Mem e -> exp_is_strided e
   | Var _ -> false)
  || offset_mentions_strided_index off

(* --- Function-wide feature scan ---------------------------------------------------------------- *)

type features = {
  mutable floats : bool;
  mutable unions : bool;
  mutable structs : bool;
  mutable pointer_arith : bool;
  mutable pointer_compare : bool;
  mutable char_pointers : bool;
  mutable nul_test : bool;
  mutable division : bool;
  mutable bitwise : bool;
  mutable nonlinear : bool;
  mutable switch_stmt : bool;
  mutable goto_stmt : bool;
  mutable arrays : bool;
}

let new_features () =
  { floats = false; unions = false; structs = false; pointer_arith = false; pointer_compare = false;
    char_pointers = false; nul_test = false; division = false; bitwise = false;
    nonlinear = false; switch_stmt = false; goto_stmt = false; arrays = false }

let scan_type feats t =
  let t = Ast_types.unroll t in
  if Ast_types.is_float t then feats.floats <- true;
  if Ast_types.is_char_ptr t then feats.char_pointers <- true;
  if Ast_types.is_array t then begin
    feats.arrays <- true;
    if Ast_types.is_char_array t then feats.char_pointers <- true
  end;
  match t.tnode with
  | TComp ci -> if ci.cstruct then feats.structs <- true else feats.unions <- true
  | _ -> ()

(* `*p == 0`, `!*p`, `*p`: a plain char read through a pointer and tested for the terminator. *)
let rec tests_nul (c : exp) =
  match (Cil.stripCasts c).enode with
  | UnOp (LNot, e, _) -> tests_nul e
  | BinOp ((Eq | Ne), a, b, _) when Cil.isZero (Cil.stripCasts b) -> tests_nul a
  | Lval ((Mem _, _) as lv) -> Ast_types.is_char (Ast_types.unroll (Cil.typeOfLval lv))
  | _ -> false

class feature_scan feats = object
  inherit Visitor.frama_c_inplace

  method! vvdec v = scan_type feats v.vtype; Cil.DoChildren

  method! voffs = function
    | Field (fi, _) ->
      if fi.fcomp.cstruct then feats.structs <- true else feats.unions <- true;
      Cil.DoChildren
    | _ -> Cil.DoChildren

  method! vexpr e =
    if Ast_types.is_float (Cil.typeOf e) then feats.floats <- true;
    (match e.enode with
     | BinOp ((PlusPI | MinusPI | MinusPP), _, _, _) -> feats.pointer_arith <- true
     (* Frama-C 34 removed the implicit array-to-pointer conversion in comparisons, so an
        array operand keeps its array type here; match both pointers and arrays. *)
     | BinOp ((Lt | Gt | Le | Ge | Eq | Ne), a, b, _)
       when (Ast_types.is_ptr (Cil.typeOf a) || Ast_types.is_array (Cil.typeOf a))
         && (Ast_types.is_ptr (Cil.typeOf b) || Ast_types.is_array (Cil.typeOf b))
         && not (Cil.isZero (Cil.stripCasts a) || Cil.isZero (Cil.stripCasts b)) ->
       feats.pointer_compare <- true
     | BinOp ((Div | Mod), _, d, _) when Option.is_none (Cil.isInteger (Cil.stripCasts d)) ->
       feats.division <- true
     | BinOp ((Shiftlt | Shiftrt | BAnd | BOr | BXor), _, _, _) | UnOp (BNot, _, _) ->
       feats.bitwise <- true
     | BinOp (Mult, a, b, _)
       when Option.is_none (Cil.isInteger (Cil.stripCasts a))
         && Option.is_none (Cil.isInteger (Cil.stripCasts b)) ->
       feats.nonlinear <- true
     | _ -> ());
    Cil.DoChildren

  method! vstmt s =
    (match s.skind with
     | Switch _ -> feats.switch_stmt <- true
     | Goto ({ contents = target }, _) ->
       (* The kernel's own labels (`return_label`, `_LAND`) are not gotos of the source. *)
       if List.exists (function Label (_, _, from_source) -> from_source | _ -> false) target.labels then
         feats.goto_stmt <- true
     | If (c, _, _, _) -> if tests_nul c then feats.nul_test <- true
     | _ -> ());
    Cil.DoChildren
end

(* --- Reads ------------------------------------------------------------------------------------- *)

(* Lvalues read by an expression (not the written lvalue itself): collected by a visitor. *)
class read_scan add = object
  inherit Visitor.frama_c_inplace
  method! vexpr e =
    (match e.enode with
     | Lval lv when is_memory_access lv -> add lv
     | _ -> ());
    Cil.DoChildren
end

let collect_reads add e = ignore (Visitor.visitFramacExpr (new read_scan add) e)

(* A written lvalue also reads the address and index expressions inside it. *)
let collect_reads_in_lval add (host, off) =
  (match host with
   | Mem e -> collect_reads add e
   | Var _ -> ());
  let rec go = function
    | NoOffset -> ()
    | Field (_, o) -> go o
    | Index (e, o) -> collect_reads add e; go o
  in
  go off

(* --- Walk: loops, calls, writes, return paths -------------------------------------------------- *)

type access = {
  a_lval : string;
  a_base : string;
  a_kind : string;
  a_ptr : bool;
  a_temp : bool; (* the base is a kernel temporary, which the source does not name *)
  a_line : string;
}

type loop_rec = {
  l_index : int;
  l_parent : int option;
  l_loc : string;
  mutable l_guard : string option;
  mutable l_writes : (string, access * string list) Hashtbl.t;
  mutable l_reads : (string, access) Hashtbl.t;
  mutable l_calls : string list;
  mutable l_exits : json list;
  mutable l_walkers : string list;
  mutable l_strided : string list;
}

type ctx = {
  mutable loops : loop_rec list; (* newest first *)
  mutable loop_stack : loop_rec list; (* innermost first *)
  mutable calls : json list;
  mutable writes : (string * access * string list ref) list; (* lval -> access + RHS values seen *)
  mutable reads : (string * access) list;
  mutable paths : json list;
  mutable n_paths : int;
  mutable truncated : bool;
  temp_defs : (int, (string list * string) list) Hashtbl.t; (* temporary vid -> (conds, value) *)
  derived : (int, varinfo) Hashtbl.t; (* local pointer vid -> formal it derives from *)
}

let access_of (lv : lval) line =
  let base = base_of_lval lv in
  { a_lval = lval_s lv;
    a_base = (match base with Some v -> v.vorig_name | None -> "");
    a_kind = (match base with Some v -> base_kind v | None -> "unknown");
    a_ptr = (match fst lv with Mem _ -> true | Var _ -> false);
    a_temp = (match base with Some v -> v.vtemp | None -> false);
    a_line = line }

let add_unique tbl key x = if not (List.mem_assoc key !tbl) then tbl := (key, x) :: !tbl

let record_read ctx line (lv : lval) =
  let acc = access_of lv line in
  let r = ref ctx.reads in
  if List.length !r < max_items then add_unique r acc.a_lval acc else ctx.truncated <- true;
  ctx.reads <- !r;
  List.iter
    (fun l -> if not (Hashtbl.mem l.l_reads acc.a_lval) then Hashtbl.replace l.l_reads acc.a_lval acc)
    ctx.loop_stack

let record_write ctx line (lv : lval) (value : string option) =
  let acc = access_of lv line in
  if is_memory_access lv then begin
    let w = ref ctx.writes in
    (match List.find_opt (fun (k, _, _) -> k = acc.a_lval) !w with
     | Some (_, _, vs) ->
       (* Same lval written again (another path/iteration): keep its other RHS values too. *)
       (match value with
        | Some v when (not (List.mem v !vs)) && List.length !vs < 3 -> vs := !vs @ [ v ]
        | _ -> ())
     | None ->
       if List.length !w < max_items then
         w := (acc.a_lval, acc, ref (match value with Some v -> [ v ] | None -> [])) :: !w
       else ctx.truncated <- true);
    ctx.writes <- !w
  end;
  let is_temp = match lv with Var v, NoOffset -> v.vtemp | _ -> false in
  if not is_temp then
    List.iter
      (fun l ->
         let values =
           match Hashtbl.find_opt l.l_writes acc.a_lval with
           | Some (_, vs) -> vs
           | None -> []
         in
         let values =
           match value with
           | Some v when (not (List.mem v values)) && List.length values < 3 -> values @ [ v ]
           | _ -> values
         in
         Hashtbl.replace l.l_writes acc.a_lval (acc, values);
         (match lv with
          | Var v, NoOffset when Ast_types.is_ptr v.vtype ->
            if not (List.mem v.vorig_name l.l_walkers) then l.l_walkers <- v.vorig_name :: l.l_walkers
          | _ -> ());
         if lval_is_strided lv && not (List.mem acc.a_base l.l_strided) then
           l.l_strided <- acc.a_base :: l.l_strided)
      ctx.loop_stack

let note_derivation ctx (lv : lval) (e : exp) =
  match lv with
  | Var q, NoOffset when (not q.vformal) && (not q.vglob) && Ast_types.is_ptr q.vtype ->
    (match base_of_exp e with
     | Some v when v.vformal -> Hashtbl.replace ctx.derived q.vid v
     | Some v ->
       (match Hashtbl.find_opt ctx.derived v.vid with
        | Some f -> Hashtbl.replace ctx.derived q.vid f
        | None -> ())
     | None -> ())
  | _ -> ()

let add_path ctx ~conds ~value ~line ~partial =
  if ctx.n_paths >= max_paths then ctx.truncated <- true
  else begin
    ctx.n_paths <- ctx.n_paths + 1;
    ctx.paths <-
      O
        [ ("value", match value with Some v -> S v | None -> Null);
          ("conditions", L (List.rev_map (fun c -> S c) conds));
          ("conditions_partial", B partial);
          ("in_loop", match ctx.loop_stack with l :: _ -> S l.l_loc | [] -> Null);
          ("loc", S line) ]
      :: ctx.paths
  end

let is_return_var (v : varinfo) = v.vtemp && v.vname = "__retres"

let is_return_goto (s : stmt) =
  match s.skind with
  | Goto ({ contents = target }, _) ->
    List.exists (function Label ("return_label", _, _) -> true | _ -> false) target.labels
  | _ -> false

(* True when control never reaches the end of the statement list. *)
let rec block_exits (b : block) =
  match List.rev b.bstmts with
  | [] -> false
  | last :: _ -> stmt_exits last

and stmt_exits (s : stmt) =
  match s.skind with
  | Return _ | Goto _ | Break _ | Continue _ -> true
  | Block b -> block_exits b
  | If (_, a, b, _) -> block_exits a && block_exits b
  | _ -> false

(* How an argument relates to the caller's formals, for a recursive call's termination measure. *)
let arg_shape (e : exp) =
  let formal x =
    match (Cil.stripCasts x).enode with
    | Lval (Var v, NoOffset) when v.vformal -> Some v
    | _ -> None
  in
  let const x = Option.is_some (Cil.isInteger (Cil.stripCasts x)) in
  let shape kind (v : varinfo) ?by () =
    Some
      (O
         ([ ("shape", S kind); ("formal", S v.vorig_name) ]
          @ match by with Some (b : varinfo) -> [ ("bounded_by", S b.vorig_name) ] | None -> []))
  in
  let on_formal x k =
    match formal x with
    | Some v -> k v
    | None -> None
  in
  match (Cil.stripCasts e).enode with
  | BinOp (MinusA, a, b, _) when const b -> on_formal a (fun v -> shape "minus_const" v ())
  | BinOp ((Div | Shiftrt), a, b, _) when const b -> on_formal a (fun v -> shape "divide" v ())
  | BinOp (Mod, a, b, _) ->
    (match formal a, formal b with
     | Some v, Some d -> shape "modulo" v ~by:d ()
     | Some v, None -> shape "modulo" v ()
     | _ -> None)
  | BinOp (PlusPI, a, b, _) when const b -> on_formal a (fun v -> shape "pointer_advance" v ())
  | Lval (Mem a, Field _) -> on_formal a (fun v -> shape "field_descent" v ())
  | _ -> None

let call_json ctx ~lhost ~args ~loc ~in_loop ~conds ~partial =
  let args_s = List.map exp_s args in
  match lhost with
  | Var f ->
    let name = f.vorig_name in
    let shapes =
      List.concat
        (List.mapi
           (fun i a ->
              match arg_shape a with
              | Some (O fields) -> [ O (("position", I i) :: ("arg", S (exp_s a)) :: fields) ]
              | _ -> [])
           args)
    in
    ctx.calls <-
      O
        [ ("callee", S name); ("kernel_name", S f.vname); ("indirect", B false);
          ("args", L (List.map (fun a -> S a) args_s)); ("arg_shapes", L shapes);
          ("conditions", L (List.rev_map (fun c -> S c) conds)); ("conditions_partial", B partial);
          ("loc", S loc); ("in_loop", B in_loop) ]
      :: ctx.calls;
    name
  | Mem e ->
    let shown = exp_s e in
    ctx.calls <-
      O
        [ ("callee", Null); ("expr", S shown); ("indirect", B true);
          ("args", L (List.map (fun a -> S a) args_s)); ("loc", S loc); ("in_loop", B in_loop) ]
      :: ctx.calls;
    Printf.sprintf "(*%s)" shown

let rec walk_block ctx conds partial (b : block) =
  (* A branch that always leaves turns its negated condition into a fact for what follows. *)
  let conds = ref conds and partial = ref partial in
  List.iter
    (fun (s : stmt) ->
       (* A statement reachable through a user label or a case can be entered from elsewhere. *)
       let user_label =
         List.exists (function Label (_, _, from_source) -> from_source | _ -> false) s.labels
       in
       let other_entry =
         List.exists
           (function
             | Label ("return_label", _, _) -> false
             | Label _ | Case _ | Default _ -> true)
           s.labels
       in
       if user_label then conds := [];
       if user_label || other_entry then partial := true;
       walk_stmt ctx !conds !partial s;
       match s.skind with
       | If (c, th, el, _) when block_exits th && not (block_exits el) ->
         conds := Printf.sprintf "!(%s)" (exp_s c) :: !conds
       | If (c, th, el, _) when block_exits el && not (block_exits th) ->
         conds := exp_s c :: !conds
       | _ -> ())
    b.bstmts

and walk_stmt ctx conds partial (s : stmt) =
  match s.skind with
  | Instr (Set (lv, e, loc)) ->
    let line = loc_s loc in
    note_derivation ctx lv e;
    collect_reads (record_read ctx line) e;
    collect_reads_in_lval (record_read ctx line) lv;
    let value = exp_s e in
    record_write ctx line lv (Some value);
    (match lv with
     | Var v, NoOffset when is_return_var v -> add_return ctx conds partial (Some e) line
     | Var v, NoOffset when v.vtemp ->
       let prev = Option.value (Hashtbl.find_opt ctx.temp_defs v.vid) ~default:[] in
       if List.length prev < 8 then Hashtbl.replace ctx.temp_defs v.vid (prev @ [ (conds, value) ])
     | _ -> ())
  | Instr (Local_init (v, AssignInit (SingleInit e), loc)) ->
    let line = loc_s loc in
    note_derivation ctx (Var v, NoOffset) e;
    collect_reads (record_read ctx line) e
  | Instr (Local_init (_, ConsInit (f, args, _), loc)) ->
    let line = loc_s loc in
    List.iter (collect_reads (record_read ctx line)) args;
    let name = call_json ctx ~lhost:(Var f) ~args ~loc:line ~in_loop:(ctx.loop_stack <> []) ~conds ~partial in
    List.iter (fun l -> if not (List.mem name l.l_calls) then l.l_calls <- name :: l.l_calls) ctx.loop_stack
  | Instr (Local_init _) -> ()
  | Instr (Call (ret, lhost, args, loc)) ->
    let line = loc_s loc in
    List.iter (collect_reads (record_read ctx line)) args;
    let name = call_json ctx ~lhost ~args ~loc:line ~in_loop:(ctx.loop_stack <> []) ~conds ~partial in
    List.iter (fun l -> if not (List.mem name l.l_calls) then l.l_calls <- name :: l.l_calls) ctx.loop_stack;
    (match ret with
     | Some lv ->
       collect_reads_in_lval (record_read ctx line) lv;
       let shown = Printf.sprintf "%s(%s)" name (String.concat ", " (List.map exp_s args)) in
       record_write ctx line lv (Some shown);
       (match lv with
        | Var v, NoOffset when is_return_var v -> add_path ctx ~conds ~value:(Some shown) ~line ~partial
        | Var v, NoOffset when v.vtemp ->
          let prev = Option.value (Hashtbl.find_opt ctx.temp_defs v.vid) ~default:[] in
          if List.length prev < 8 then Hashtbl.replace ctx.temp_defs v.vid (prev @ [ (conds, shown) ])
        | _ -> ())
     | None -> ())
  | Instr _ -> ()
  | Return (Some e, loc) ->
    (match e.enode with
     | Lval (Var v, NoOffset) when is_return_var v -> ()
     | _ -> collect_reads (record_read ctx (loc_s loc)) e; add_return ctx conds partial (Some e) (loc_s loc))
  | Return (None, loc) -> add_path ctx ~conds ~value:None ~line:(loc_s loc) ~partial
  | If (c, th, el, loc) ->
    collect_reads (record_read ctx (loc_s loc)) c;
    let shown = exp_s c in
    note_exit ctx conds s;
    walk_block ctx (shown :: conds) partial th;
    walk_block ctx (Printf.sprintf "!(%s)" shown :: conds) partial el
  | Switch (e, b, _, loc) ->
    collect_reads (record_read ctx (loc_s loc)) e;
    walk_block ctx (Printf.sprintf "switch (%s)" (exp_s e) :: conds) partial b
  | Loop (_, b, loc, _, _) ->
    let index = List.length ctx.loops in
    let l =
      { l_index = index;
        l_parent = (match ctx.loop_stack with p :: _ -> Some p.l_index | [] -> None);
        l_loc = loc_s loc;
        l_guard = guard_of b;
        l_writes = Hashtbl.create 8;
        l_reads = Hashtbl.create 8;
        l_calls = [];
        l_exits = [];
        l_walkers = [];
        l_strided = [] }
    in
    ctx.loops <- l :: ctx.loops;
    ctx.loop_stack <- l :: ctx.loop_stack;
    walk_block ctx conds partial b;
    ctx.loop_stack <- List.tl ctx.loop_stack
  | Block b -> walk_block ctx conds partial b
  | UnspecifiedSequence seq ->
    List.iter (fun (st, _, _, _, _) -> walk_stmt ctx conds partial st) seq
  | Break _ | Continue _ | Goto _ | Throw _ | TryCatch _ | TryFinally _ | TryExcept _ -> ()

(* An `if (c) break;`, or a kernel `goto return_label` under `if (c)`, leaves the current loop. *)
and note_exit ctx _conds (s : stmt) =
  match ctx.loop_stack, s.skind with
  | l :: _, If (c, th, el, loc) ->
    let rec kind_of (b : block) =
      match List.rev b.bstmts with
      | { skind = Break _; _ } :: _ -> Some "break"
      | { skind = Return _; _ } :: _ -> Some "return"
      | last :: _ when is_return_goto last -> Some "return"
      | { skind = Goto _; _ } :: _ -> Some "goto"
      | { skind = Block inner; _ } :: _ -> kind_of inner
      | _ -> None
    in
    let add kind cond =
      if List.length l.l_exits < 16 then
        l.l_exits <- O [ ("kind", S kind); ("condition", S cond); ("loc", S (loc_s loc)) ] :: l.l_exits
    in
    let shown = exp_s c in
    (* The guard itself is reported as `guard`, not as an exit. *)
    (match kind_of th with
     | Some k when Some (Printf.sprintf "!(%s)" shown) <> l.l_guard && not (is_negated_guard l c) -> add k shown
     | _ -> ());
    (match kind_of el with
     | Some k when Some shown <> l.l_guard -> add k (Printf.sprintf "!(%s)" shown)
     | _ -> ())
  | _ -> ()

and is_negated_guard l (c : exp) =
  match c.enode with
  | UnOp (LNot, inner, _) -> Some (exp_s inner) = l.l_guard
  | _ -> false

(* The loop condition after normalization: `while (1) { if (c) ; else break; ... }`, possibly after
   statements computing temporaries (`while ( *s++)`), or as the last statement of a do-while. *)
and guard_of (b : block) =
  let breaks (x : block) =
    match x.bstmts with
    | [ { skind = Break _; _ } ] -> true
    | _ -> false
  in
  let empty (x : block) = x.bstmts = [] in
  let from_if (s : stmt) =
    match s.skind with
    | If (c, th, el, _) when empty th && breaks el -> Some (exp_s c)
    | If (c, th, el, _) when breaks th && empty el ->
      (match c.enode with
       | UnOp (LNot, inner, _) -> Some (exp_s inner)
       | _ -> Some (Printf.sprintf "!(%s)" (exp_s c)))
    | _ -> None
  in
  (* Statements without control flow before the condition compute its temporaries. *)
  let rec plain (st : stmt) =
    match st.skind with
    | Instr _ -> true
    | Block inner -> List.for_all plain inner.bstmts
    | UnspecifiedSequence seq -> List.for_all (fun (x, _, _, _, _) -> plain x) seq
    | _ -> false
  in
  let rec first (stmts : stmt list) =
    match stmts with
    | [] -> None
    | st :: tl when plain st -> first tl
    | { skind = Block inner; _ } :: _ -> first inner.bstmts
    | ({ skind = If _; _ } as st) :: _ -> from_if st
    | _ -> None
  in
  match first b.bstmts with
  | Some g -> Some g
  | None ->
    (match List.rev b.bstmts with
     | last :: _ -> from_if last
     | [] -> None)

and add_return ctx conds partial (e : exp option) line =
  match e with
  | None -> add_path ctx ~conds ~value:None ~line ~partial
  | Some e ->
    (match (Cil.stripCasts e).enode with
     | Lval (Var v, NoOffset) when v.vtemp && Hashtbl.mem ctx.temp_defs v.vid ->
       (* `return tmp` from a ternary: one path per definition, under that definition's conditions. *)
       List.iter
         (fun (def_conds, value) -> add_path ctx ~conds:def_conds ~value:(Some value) ~line ~partial)
         (Hashtbl.find ctx.temp_defs v.vid)
     | _ -> add_path ctx ~conds ~value:(Some (exp_s e)) ~line ~partial)

(* --- Formals and aliasing ---------------------------------------------------------------------- *)

let pointee_of t =
  match (Ast_types.unroll t).tnode with
  | TPtr inner -> Some inner
  | TArray (inner, _) -> Some inner
  | _ -> None

(* Canonical pointee: typedefs unrolled, qualifiers dropped, so `uint8_t const` matches `uint8_t`. *)
let canon_type t = typ_s (Ast_types.remove_qualifiers_deep (Ast_types.unroll_deep t))

let formal_json (v : varinfo) =
  let t = Ast_types.unroll v.vtype in
  let is_fn_ptr = Ast_types.is_fun (Option.value (pointee_of t) ~default:t) && Ast_types.is_ptr t in
  let pointer = Ast_types.is_ptr t || Ast_types.is_array t in
  let restrict = Ast_attributes.contains "restrict" t.tattr in
  let base =
    [ ("name", S v.vorig_name); ("type", S (typ_s v.vtype));
      ("kind", S (if is_fn_ptr then "function_pointer" else if pointer then "pointer" else if Ast_types.is_struct_or_union t then "aggregate" else "scalar"));
      ("restrict", B restrict) ]
  in
  match pointee_of t with
  | Some p when not is_fn_ptr ->
    O
      (base
       @ [ ("pointee", S (typ_s p)); ("pointee_canon", S (canon_type p));
           ("pointee_const", B (Ast_types.is_const p));
           ("char_like", B (Ast_types.is_any_char (Ast_types.unroll p) || Ast_types.is_void (Ast_types.unroll p))) ])
  | _ -> O base

(* --- One function ------------------------------------------------------------------------------ *)

let access_json (a : access) =
  O [ ("lval", S a.a_lval); ("base", S a.a_base); ("base_kind", S a.a_kind);
      ("base_temp", B a.a_temp); ("through_pointer", B a.a_ptr); ("loc", S a.a_line) ]

let write_json (a : access) (values : string list) =
  O [ ("lval", S a.a_lval); ("base", S a.a_base); ("base_kind", S a.a_kind);
      ("base_temp", B a.a_temp); ("through_pointer", B a.a_ptr); ("loc", S a.a_line);
      ("values", L (List.map (fun v -> S v) values)) ]

let hashtbl_sorted tbl key_of =
  List.sort (fun a b -> compare (key_of a) (key_of b)) (Hashtbl.fold (fun _ v acc -> v :: acc) tbl [])

let loop_json (l : loop_rec) =
  let writes = hashtbl_sorted l.l_writes (fun ((a : access), _) -> a.a_lval) in
  let reads = hashtbl_sorted l.l_reads (fun (a : access) -> a.a_lval) in
  O
    [ ("index", I l.l_index);
      ("parent", match l.l_parent with Some p -> I p | None -> Null);
      ("loc", S l.l_loc);
      ("guard", match l.l_guard with Some g -> S g | None -> Null);
      ("writes",
       L (List.map
            (fun ((a : access), values) ->
               O [ ("lval", S a.a_lval); ("base", S a.a_base); ("base_kind", S a.a_kind);
                   ("base_temp", B a.a_temp); ("through_pointer", B a.a_ptr);
                   ("values", L (List.map (fun v -> S v) values)) ])
            writes));
      ("reads", L (List.map access_json reads));
      ("calls", L (List.rev_map (fun c -> S c) l.l_calls));
      ("exits", L (List.rev l.l_exits));
      ("pointer_walkers", L (List.rev_map (fun c -> S c) l.l_walkers));
      ("strided_writes", L (List.rev_map (fun c -> S c) l.l_strided)) ]

let function_json kf =
  let vi = Kernel_function.get_vi kf in
  let f = Kernel_function.get_definition kf in
  let feats = new_features () in
  ignore (Visitor.visitFramacFunction (new feature_scan feats) f);
  let ctx =
    { loops = []; loop_stack = []; calls = []; writes = []; reads = []; paths = [];
      n_paths = 0; truncated = false; temp_defs = Hashtbl.create 8; derived = Hashtbl.create 8 }
  in
  walk_block ctx [] false f.sbody;
  let derived =
    Hashtbl.fold
      (fun vid (formal : varinfo) acc ->
         let local = List.find_opt (fun (l : varinfo) -> l.vid = vid) f.slocals in
         match local with
         | Some l -> O [ ("local", S l.vorig_name); ("formal", S formal.vorig_name) ] :: acc
         | None -> acc)
      ctx.derived []
  in
  let return_type =
    match (Ast_types.unroll vi.vtype).tnode with
    | TFun (ret, _, _) -> typ_s ret
    | _ -> ""
  in
  let variadic =
    match (Ast_types.unroll vi.vtype).tnode with
    | TFun (_, _, v) -> v
    | _ -> false
  in
  O
    [ ("kernel_name", S vi.vname);
      ("name", S vi.vorig_name);
      ("loc", S (loc_s vi.vdecl));
      ("static", B (vi.vstorage = Static));
      ("variadic", B variadic);
      ("return_type", S return_type);
      ("formals", L (List.map formal_json (Kernel_function.get_formals kf)));
      ("loops", L (List.rev_map loop_json ctx.loops));
      ("calls", L (List.rev ctx.calls));
      ("writes", L (List.rev_map (fun (_, a, vs) -> write_json a !vs) ctx.writes));
      ("reads", L (List.rev_map (fun (_, a) -> access_json a) ctx.reads));
      ("return_paths", L (List.rev ctx.paths));
      ("derived_pointers", L derived);
      ("truncated", B ctx.truncated);
      ("features",
       O
         [ ("floats", B feats.floats); ("unions", B feats.unions); ("structs", B feats.structs);
           ("pointer_arith", B feats.pointer_arith); ("pointer_compare", B feats.pointer_compare);
           ("char_pointers", B feats.char_pointers); ("nul_test", B feats.nul_test);
           ("division", B feats.division); ("bitwise", B feats.bitwise);
           ("nonlinear", B feats.nonlinear); ("switch", B feats.switch_stmt);
           ("goto", B feats.goto_stmt); ("arrays", B feats.arrays) ]) ]

let run () =
  match Sys.getenv_opt "FRAMAC_AST_DUMP_OUT" with
  | None | Some "" -> ()
  | Some out ->
    Ast.compute ();
    let functions = ref [] in
    Globals.Functions.iter
      (fun kf -> if Kernel_function.is_definition kf then functions := function_json kf :: !functions);
    let doc =
      O
        [ ("schema", I 1);
          ("functions", L (List.rev !functions)) ]
    in
    let b = Buffer.create 65536 in
    write b doc;
    let tmp = out ^ ".tmp" in
    let oc = open_out_bin tmp in
    Buffer.output_buffer oc b;
    close_out oc;
    Sys.rename tmp out

let () = Boot.Main.extend run
