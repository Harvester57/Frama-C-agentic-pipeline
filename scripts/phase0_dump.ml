(* Phase 0 model: inventory and call graph from the Frama-C kernel AST, written to $FRAMAC_P0_DUMP_OUT.

   Compiled and loaded by phase0_model.py (`ocamlfind ocamlopt -shared`, then `frama-c -load-module`),
   like scripts/kernel_ast_dump.ml, but limited to what Phase 0 needs (docs/plans/archive/phase0-implementation-plan.md
   step I3):
   - every defined function: kernel name, source name, definition location and line span, storage,
     signature, loops and cyclomatic complexity;
   - its direct calls (with the project functions passed as arguments: thread start routines,
     callbacks, the string literals passed: schema 4, and whether the call is the initializer of a
     local: schema 5) and its indirect call sites, with the called signature;
   - every function whose address is taken (in code or in a global initializer): the only possible
     targets of an indirect call;
   - where addresses flow from (schema 6, the unit split's address-flow reach,
     docs/plans/unit-split-address-flow.md): per function body, the functions whose address it
     takes (`address_refs`) and the globals it names (`global_refs`); per defined global, the
     functions and globals its initializer names (`init_functions`, `init_globals`). Kernel names.
   - per defined function and global, the file Frama-C parsed it from (schema 7, `root`): the
     outermost file of its location's inclusion chain, so a location that a line directive moved
     into a header can still be traced to its compiled source.

   Locations stay raw strings (Fclib.Fileloc.pretty), parsed by phase0_model.py; line spans are
   source lines (Fclib.Filepos.line), not lines of the preprocessed file. *)

open Frama_c_kernel
open Cil_types

type json = S of string | I of int | B of bool | L of json list | O of (string * json) list

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
  | L items ->
    Buffer.add_char b '[';
    List.iteri (fun i x -> if i > 0 then Buffer.add_char b ','; write b x) items;
    Buffer.add_char b ']'
  | O fields ->
    Buffer.add_char b '{';
    List.iteri
      (fun i (k, v) -> if i > 0 then Buffer.add_char b ','; write b (S k); Buffer.add_char b ':'; write b v)
      fields;
    Buffer.add_char b '}'

let one_line pp x =
  let b = Buffer.create 64 in
  let f = Format.formatter_of_buffer b in
  Format.pp_set_margin f 1_000_000;
  pp f x;
  Format.pp_print_flush f ();
  String.concat " " (List.filter (fun s -> s <> "") (String.split_on_char '\n' (Buffer.contents b)))

let loc_s = one_line Fclib.Fileloc.pretty
let exp_s = one_line Printer.pp_exp

(* Schema 7: the file Frama-C parsed that a location comes from, absolute: the outermost position of
   its inclusion chain, or the location's own file when it is in no included file. Line directives
   can make the location name a file that does not hold the code (a `#line "toke.l"` Frama-C ignores
   leaves the position in the last header entered); the root is still the compiled source, which
   phase0_model.py uses to attribute such a definition. "" when unknown. *)
let root_s (loc : location) =
  try
    let p = Fclib.Fileloc.start_pos loc in
    let r = match List.rev (Fclib.Filepos.inclusions p) with [] -> p | outer :: _ -> outer in
    Fclib.Filepath.to_string_abs (Fclib.Filepos.path r)
  with _ -> ""

(* First and last source line of a location; 0 for a generated or unknown one. *)
let lines (loc : location) =
  try
    let a = Fclib.Filepos.line (Fclib.Fileloc.start_pos loc)
    and b = Fclib.Filepos.line (Fclib.Fileloc.end_pos loc) in
    (a, max a b)
  with _ -> (0, 0)

(* Canonical type: typedefs unrolled, qualifiers dropped, so call sites and definitions compare. *)
let canon t = one_line Printer.pp_typ (Ast_types.remove_qualifiers_deep (Ast_types.unroll_deep t))

(* Signature without parameter names: `ret(arg1,arg2,...)`. *)
let signature t =
  match (Ast_types.unroll t).tnode with
  | TFun (ret, args, variadic) ->
    let args = match args with None -> [] | Some l -> List.map (fun (_, t, _) -> canon t) l in
    Printf.sprintf "%s(%s%s)" (canon ret) (String.concat "," args) (if variadic then ",..." else "")
  | _ -> canon t

let is_fun_var (v : varinfo) = Ast_types.is_fun v.vtype

let is_constructor (v : varinfo) =
  Ast_attributes.contains "constructor" v.vattr || Ast_attributes.contains "constructor" v.vtype.tattr

(* Functions whose address is taken anywhere, collected over the whole AST. *)
let address_taken : (string, unit) Hashtbl.t = Hashtbl.create 64

class addr_scan = object
  inherit Visitor.frama_c_inplace
  method! vexpr e =
    (match e.enode with
     | AddrOf (Var v, NoOffset) | StartOf (Var v, NoOffset) when is_fun_var v ->
       Hashtbl.replace address_taken v.vname ()
     | _ -> ());
    Cil.DoChildren
end

(* Where function addresses flow from (schema 6): the functions whose address an expression takes,
   and the globals it names (read, written or address-taken; never a string literal, a global since
   Frama-C 32). A direct call's callee is no address. Kernel names. *)
type refs = { mutable faddr : string list; mutable gvars : string list }

let new_refs () = { faddr = []; gvars = [] }

let note_expr (r : refs) (e : exp) =
  match e.enode with
  | AddrOf (Var v, NoOffset) | StartOf (Var v, NoOffset) when is_fun_var v ->
    if not (List.mem v.vname r.faddr) then r.faddr <- v.vname :: r.faddr
  | _ -> ()

let note_var (r : refs) (v : varinfo) =
  if v.vglob && (not (is_fun_var v)) && (not (Ast_info.is_string_literal v)) && not (List.mem v.vname r.gvars)
  then r.gvars <- v.vname :: r.gvars

(* The same for a global's initializer. *)
class ref_scan (r : refs) = object
  inherit Visitor.frama_c_inplace
  method! vexpr e = note_expr r e; Cil.DoChildren
  method! vvrbl v = note_var r v; Cil.DoChildren
end

(* The variable a pointer expression is based on (`p`, `p + i`, `(char * )p`), if any. *)
let rec base_var (e : exp) =
  match (Cil.stripCasts e).enode with
  | Lval (Var v, NoOffset) -> Some v
  | BinOp ((PlusPI | MinusPI), e1, _, _) -> base_var e1
  | _ -> None

(* Writes of a function body (step I9, the frame and security obligations): writes through a
   pointer, the formals they go through, and the globals written directly. *)
type writes = { mutable pointer : int; mutable params : string list; mutable globals : string list }

let add_unique x l = if List.mem x l then l else x :: l

let record_write (w : writes) ((host, _) : lval) =
  match host with
  | Mem e ->
    w.pointer <- w.pointer + 1;
    (match base_var e with
     | Some v when v.vformal -> w.params <- add_unique v.vorig_name w.params
     | _ -> ())
  | Var v when v.vglob && not (is_fun_var v) -> w.globals <- add_unique v.vorig_name w.globals
  | Var _ -> ()

(* Formals with their pointer kind: `pointer` (non-const pointee: may be written), `const_pointer`. *)
let formals_json kf =
  let formals = try Kernel_function.get_formals kf with _ -> [] in
  L
    (List.map
       (fun (v : varinfo) ->
          let t = Ast_types.unroll v.vtype in
          let kind =
            if Ast_types.is_ptr t then
              if Ast_types.C.has_qualifier "const" (Ast_types.direct_pointed_type t) then "const_pointer" else "pointer"
            else if Ast_types.is_array t then "pointer"
            else "value"
          in
          O [ ("name", S v.vorig_name); ("kind", S kind) ])
       formals)

(* Bytes of a type, when it has a size. *)
let bytes_of t =
  try
    let b = Cil.bitsSizeOf t in
    if b > 0 && b mod 8 = 0 then Some (b / 8) else None
  with _ -> None

let const_int e = try Option.map Z.to_int (Cil.constFoldToInt e) with _ -> None

(* Bytes left, from where a pointer argument points to the end of the object it points into, when the
   expression shows it: an array (`buf`, `&buf[4]`, `buf + 4`), an object's address (`&key`). Fixed-size
   buffers passed without a length (a key, a nonce) get their size from the callers this way. *)
let rec arg_size (e : exp) =
  match (Cil.stripCasts e).enode with
  | StartOf lv -> bytes_of (Cil.typeOfLval lv)
  | AddrOf lv ->
    (match Cil.removeOffsetLval lv with
     | parent, Index (i, NoOffset) ->
       (match bytes_of (Cil.typeOfLval parent), bytes_of (Cil.typeOfLval lv), const_int i with
        | Some whole, Some elt, Some k when k >= 0 && whole - k * elt > 0 -> Some (whole - k * elt)
        | _ -> None)
     | _ -> if Ast_types.is_fun (Cil.typeOfLval lv) then None else bytes_of (Cil.typeOfLval lv))
  | BinOp (PlusPI, p, off, t) ->
    (match arg_size p, bytes_of (Ast_types.direct_pointed_type (Ast_types.unroll t)), const_int off with
     | Some whole, Some elt, Some k when k >= 0 && whole - k * elt > 0 -> Some (whole - k * elt)
     | _ -> None)
  | _ -> None

let arg_sizes args =
  O
    (List.concat
       (List.mapi
          (fun i a -> match (try arg_size a with _ -> None) with Some n -> [ (string_of_int i, I n) ] | None -> [])
          args))

(* String-literal arguments (plan step M2, M5): argument index -> the literal's bytes, those outside
   printable ASCII but CR, LF, tab and NUL replaced by '?' (the JSON stays UTF-8; the security
   properties decide on CR, LF and NUL only). Since Frama-C 32 a literal is a global const array
   (Ast_info.is_string_literal) the argument points to the start of: `"abc"` or `&"abc"[0]`. A
   pointer into it (`"abc" + 1`) is not recorded. A wide literal keeps its code points below 128. *)
let literal_text s =
  String.map (fun c -> if c = '\r' || c = '\n' || c = '\t' || c = '\000' || (c >= ' ' && c <= '~') then c else '?') s

let string_literal (v : varinfo) =
  if not (Ast_info.is_string_literal v) then None
  else
    match Globals.Vars.get_string_literal v with
    | Str s -> Some (literal_text s)
    | Wstr l ->
      let ascii c = if Int64.compare c 0L >= 0 && Int64.compare c 128L < 0 then Char.chr (Int64.to_int c) else '?' in
      Some (literal_text (String.concat "" (List.map (fun c -> String.make 1 (ascii c)) l)))
    | exception _ -> None

let literal_args args =
  O
    (List.concat
       (List.mapi
          (fun i a ->
             let lit =
               match (Cil.stripCasts a).enode with
               | StartOf (Var v, NoOffset) -> string_literal v
               | AddrOf (Var v, Index (z, NoOffset)) when const_int z = Some 0 -> string_literal v
               | _ -> None
             in
             match lit with Some s -> [ (string_of_int i, S s) ] | None -> [])
          args))

(* Calls, loops, decisions, writes, address and global references and the last line of a function
   body, in one pass. *)
class body_scan (calls : json list ref) (loops : int ref) (decisions : int ref) (last : int ref) (w : writes)
    (r : refs) =
object
  inherit Visitor.frama_c_inplace
  method! vexpr e = note_expr r e; Cil.DoChildren
  method! vvrbl v = note_var r v; Cil.DoChildren
  method! vstmt s =
    let _, l = lines (Cil_datatype.Stmt.loc s) in
    if l > !last then last := l;
    (* Cyclomatic complexity: decisions + 1. A loop's own decision is the `if` that CIL makes of its
       condition, and `&&`/`||` are already separate `if`s. *)
    (match s.skind with
     | Loop _ -> incr loops
     | If _ -> incr decisions
     | Switch (_, _, cases, _) -> decisions := !decisions + max 0 (List.length cases - 1)
     | _ -> ());
    Cil.DoChildren
  method! vinst i =
    (match i with
     | Set (lv, _, _) | Call (Some lv, _, _, _) -> record_write w lv
     | _ -> ());
    (* `initializer` (schema 5): the call is the initializer of a local (`int n = f(x);`, a
       Local_init with ConsInit). MetAcsl 0.12 gives such a call no \calling instance, no \writing
       instance from the callee's assigns and no \strong_invariant instance, so
       scripts/security_props.py writes an in-code check there instead. *)
    let site =
      match i with
      | Call (_, lhost, args, loc) -> Some (lhost, args, loc, false)
      | Local_init (_, ConsInit (f, args, _), loc) -> Some (Var f, args, loc, true)
      | _ -> None
    in
    (match site with
     | Some (lhost, args, loc, init) ->
       (match lhost with
        | Var f ->
          let fn_args =
            List.filter_map
              (fun a ->
                 match (Cil.stripCasts a).enode with
                 | AddrOf (Var v, NoOffset) | StartOf (Var v, NoOffset) when is_fun_var v -> Some (S v.vname)
                 | _ -> None)
              args
          in
          calls :=
            O [ ("kernel_name", S f.vname); ("name", S f.vorig_name); ("indirect", B false);
                ("function_args", L fn_args); ("arg_sizes", arg_sizes args);
                ("literal_args", literal_args args); ("initializer", B init); ("loc", S (loc_s loc)) ]
            :: !calls
        | Mem e ->
          let called = Cil.typeOfLval (Mem e, NoOffset) in
          calls :=
            O [ ("indirect", B true); ("expr", S (exp_s e)); ("signature", S (signature called));
                ("loc", S (loc_s loc)) ]
            :: !calls)
     | _ -> ());
    Cil.DoChildren
end

let function_json kf =
  let vi = Kernel_function.get_vi kf in
  let f = Kernel_function.get_definition kf in
  (* The definition's location: vi.vdecl is the first declaration, often a header prototype. *)
  let def_loc = Cil_datatype.Global.loc (Kernel_function.get_global kf) in
  let first, def_last = lines def_loc in
  let calls = ref [] and loops = ref 0 and decisions = ref 0 and last = ref def_last in
  let w = { pointer = 0; params = []; globals = [] } in
  let r = new_refs () in
  ignore (Visitor.visitFramacFunction (new body_scan calls loops decisions last w r) f);
  let names l = L (List.map (fun s -> S s) (List.sort compare l)) in
  O
    [ ("kernel_name", S vi.vname);
      ("name", S vi.vorig_name);
      ("loc", S (loc_s def_loc));
      ("root", S (root_s def_loc));
      ("first_line", I first);
      ("last_line", I (max first !last));
      ("static", B (vi.vstorage = Static));
      ("inline", B vi.vinline);
      ("constructor", B (is_constructor vi));
      ("signature", S (signature vi.vtype));
      ("loops", I !loops);
      ("cyclomatic", I (1 + !decisions));
      ("formals", formals_json kf);
      ("writes", O [ ("pointer", I w.pointer); ("params", names w.params); ("globals", names w.globals) ]);
      ("address_refs", names r.faddr);
      ("global_refs", names r.gvars);
      ("calls", L (List.rev !calls)) ]

let run () =
  match Sys.getenv_opt "FRAMAC_P0_DUMP_OUT" with
  | None | Some "" -> ()
  | Some out ->
    Ast.compute ();
    Visitor.visitFramacFileSameGlobals (new addr_scan) (Ast.get ());
    let functions = ref [] and declared = ref [] in
    Globals.Functions.iter (fun kf ->
        let vi = Kernel_function.get_vi kf in
        if Kernel_function.is_definition kf then functions := function_json kf :: !functions
        else
          (* `decl`: its first declaration (the header that declares it); `proto`: that declaration as C,
             with typedef names and parameter names, for the stub skeletons (scripts/stub_gen.py). *)
          declared :=
            O [ ("kernel_name", S vi.vname); ("name", S vi.vorig_name); ("signature", S (signature vi.vtype));
                ("formals", formals_json kf); ("decl", S (loc_s vi.vdecl)); ("proto", S (one_line Printer.pp_vdecl vi)) ]
            :: !declared);
    let taken = Hashtbl.fold (fun k () acc -> S k :: acc) address_taken [] in
    (* Defined global variables, where the security properties that name them are anchored (I9), and
       what their initializers name (schema 6). *)
    let names l = L (List.map (fun s -> S s) (List.sort compare l)) in
    let globals =
      List.filter_map
        (function
          | GVar (vi, _, loc) as g when not (is_fun_var vi) ->
            let r = new_refs () in
            ignore (Visitor.visitFramacGlobal (new ref_scan r) g);
            let gvars = List.filter (fun n -> n <> vi.vname) r.gvars in
            let size_field = match bytes_of vi.vtype with Some n -> [ ("size", I n) ] | None -> [] in
            Some
              (O ([ ("name", S vi.vorig_name); ("kernel_name", S vi.vname); ("loc", S (loc_s loc));
                    ("root", S (root_s loc)); ("static", B (vi.vstorage = Static)); ("type", S (canon vi.vtype)) ]
                  @ size_field
                  @ [ ("init_functions", names r.faddr); ("init_globals", names gvars) ]))
          | _ -> None)
        (Ast.get ()).globals
    in
    let doc =
      O [ ("schema", I 7); ("functions", L (List.rev !functions)); ("declared", L !declared);
          ("address_taken", L taken); ("globals", L globals) ]
    in
    let b = Buffer.create 65536 in
    write b doc;
    let tmp = out ^ ".tmp" in
    let oc = open_out_bin tmp in
    Buffer.output_buffer oc b;
    close_out oc;
    Sys.rename tmp out

let () = Boot.Main.extend run
