(* Phase 0 PoC: inventory and call graph from the Frama-C kernel AST, written to $P0_DUMP_OUT.

   Compiled and loaded by phase0b.py (`ocamlfind ocamlopt -shared`, then `frama-c -load-module`),
   like scripts/kernel_ast_dump.ml, but limited to what Phase 0 needs:
   - every defined function: kernel name, source name, location, storage, signature;
   - its direct calls and its indirect call sites, with the called signature;
   - every function whose address is taken (in code or in a global initializer): the only
     possible targets of an indirect call. *)

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

(* Functions whose address is taken anywhere, collected over the whole file. *)
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

class call_scan (calls : json list ref) = object
  inherit Visitor.frama_c_inplace
  method! vinst i =
    let site =
      match i with
      | Call (_, lhost, args, loc) -> Some (lhost, args, loc)
      | Local_init (_, ConsInit (f, args, _), loc) -> Some (Var f, args, loc)
      | _ -> None
    in
    (match site with
     | Some (lhost, args, loc) ->
       (match lhost with
        | Var f ->
          (* Functions passed as arguments (thread start routines, callbacks), by kernel name. *)
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
                ("function_args", L fn_args); ("loc", S (loc_s loc)) ]
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

class loop_count (n : int ref) = object
  inherit Visitor.frama_c_inplace
  method! vstmt s =
    (match s.skind with Loop _ -> incr n | _ -> ());
    Cil.DoChildren
end

let function_json kf =
  let vi = Kernel_function.get_vi kf in
  let f = Kernel_function.get_definition kf in
  let calls = ref [] and loops = ref 0 in
  ignore (Visitor.visitFramacFunction (new call_scan calls) f);
  ignore (Visitor.visitFramacFunction (new loop_count loops) f);
  (* The definition's location: vi.vdecl is the first declaration, often a header prototype. *)
  let def_loc = Cil_datatype.Global.loc (Kernel_function.get_global kf) in
  O
    [ ("kernel_name", S vi.vname);
      ("name", S vi.vorig_name);
      ("loc", S (loc_s def_loc));
      ("static", B (vi.vstorage = Static));
      ("signature", S (signature vi.vtype));
      ("loops", I !loops);
      ("calls", L (List.rev !calls)) ]

let run () =
  match Sys.getenv_opt "P0_DUMP_OUT" with
  | None | Some "" -> ()
  | Some out ->
    Ast.compute ();
    Visitor.visitFramacFileSameGlobals (new addr_scan) (Ast.get ());
    let functions = ref [] and declared = ref [] in
    Globals.Functions.iter (fun kf ->
        let vi = Kernel_function.get_vi kf in
        if Kernel_function.is_definition kf then functions := function_json kf :: !functions
        else declared := O [ ("kernel_name", S vi.vname); ("signature", S (signature vi.vtype)) ] :: !declared);
    let taken = Hashtbl.fold (fun k () acc -> S k :: acc) address_taken [] in
    let doc =
      O [ ("schema", I 1); ("functions", L (List.rev !functions)); ("declared", L !declared);
          ("address_taken", L taken) ]
    in
    let b = Buffer.create 65536 in
    write b doc;
    let tmp = out ^ ".tmp" in
    let oc = open_out_bin tmp in
    Buffer.output_buffer oc b;
    close_out oc;
    Sys.rename tmp out

let () = Boot.Main.extend run
