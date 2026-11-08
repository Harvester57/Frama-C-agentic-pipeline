(* Phase 0 model, Alias narrowing (docs/phase0-implementation-plan.md step I4): for every indirect call
   site of the parse, the functions Frama-C's Alias plugin says the called pointer may point to, written
   to $FRAMAC_P0_ALIAS_OUT.

   Loaded by phase0_model.py next to scripts/phase0_dump.ml, in the same Frama-C run (so the same AST),
   only when the model runs with --alias. It writes its own file, after the dump wrote its own: an Alias
   failure, time-out or crash never loses the dump.

   Sites are reported in the dump's order, with the same caller kernel name, location and expression
   strings, so phase0_model.py matches them one to one. Per site:
   - `targets`: the function variables of the vertex of `*e` in Alias's state before the call. That is
     the set the plugin itself uses to resolve the call (Analysis.do_function_call);
   - `no_state`: Alias has no state before the statement (unreached or bottom);
   - `no_targets`: the vertex holds no function (a parameter, a field written in another function);
   - `error`: the query raised.

   The analysis runs under $FRAMAC_P0_ALIAS_TIMEOUT seconds (SIGALRM). Its own failures are fatal
   errors of the plugin (`Options.fatal`), caught here. *)

open Frama_c_kernel
open Cil_types

type json = S of string | I of int | F of float | L of json list | O of (string * json) list

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
  | F f -> Buffer.add_string b (Printf.sprintf "%.3f" f)
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

(* The same printers as phase0_dump.ml, so the strings match. *)
let one_line pp x =
  let b = Buffer.create 64 in
  let f = Format.formatter_of_buffer b in
  Format.pp_set_margin f 1_000_000;
  pp f x;
  Format.pp_print_flush f ();
  String.concat " " (List.filter (fun s -> s <> "") (String.split_on_char '\n' (Buffer.contents b)))

let loc_s = one_line Fclib.Fileloc.pretty
let exp_s = one_line Printer.pp_exp
let short s = if String.length s > 300 then String.sub s 0 300 else s

exception Budget

let site_json kf stmt e loc =
  let base = [ ("expr", S (exp_s e)); ("loc", S (loc_s loc)) ] in
  let result =
    match Alias.API.get_state_before_stmt kf stmt with
    | None -> [ ("status", S "no_state") ]
    | Some state ->
      (try
         let vars = Alias.API.Abstract_state.find_vars (Mem e, NoOffset) state in
         let fns =
           Alias.API.VarSet.fold
             (fun v acc -> if Ast_types.is_fun v.vtype then S v.vname :: acc else acc)
             vars []
         in
         if fns = [] then [ ("status", S "no_targets") ] else [ ("status", S "targets"); ("targets", L fns) ]
       with exn -> [ ("status", S "error"); ("error", S (short (Printexc.to_string exn))) ])
  in
  O (base @ result)

class site_scan kf (sites : json list ref) = object
  inherit Visitor.frama_c_inplace
  method! vstmt s =
    (match s.skind with
     | Instr (Call (_, Mem e, _, loc)) -> sites := site_json kf s e loc :: !sites
     | _ -> ());
    Cil.DoChildren
end

let run () =
  match Sys.getenv_opt "FRAMAC_P0_ALIAS_OUT" with
  | None | Some "" -> ()
  | Some out ->
    Ast.compute ();
    let budget =
      match Stdlib.Option.bind (Sys.getenv_opt "FRAMAC_P0_ALIAS_TIMEOUT") int_of_string_opt with
      | Some n when n > 0 -> n
      | _ -> 300
    in
    let t0 = Unix.gettimeofday () in
    let previous = Sys.signal Sys.sigalrm (Sys.Signal_handle (fun _ -> raise Budget)) in
    let status, error =
      match ignore (Unix.alarm budget); Alias.Analysis.compute () with
      | () -> ("ok", "")
      | exception Budget -> ("timeout", Printf.sprintf "Alias did not finish within %d s" budget)
      | exception exn -> ("failed", short (Printexc.to_string exn))
    in
    ignore (Unix.alarm 0);
    Sys.set_signal Sys.sigalrm previous;
    let seconds = Unix.gettimeofday () -. t0 in
    let functions = ref [] in
    if status = "ok" then
      Globals.Functions.iter (fun kf ->
          if Kernel_function.is_definition kf then begin
            let sites = ref [] in
            ignore (Visitor.visitFramacFunction (new site_scan kf sites) (Kernel_function.get_definition kf));
            if !sites <> [] then
              functions :=
                O [ ("kernel_name", S (Kernel_function.get_vi kf).vname); ("sites", L (List.rev !sites)) ]
                :: !functions
          end);
    let doc =
      O [ ("schema", I 1); ("status", S status); ("error", S error); ("seconds", F seconds);
          ("functions", L (List.rev !functions)) ]
    in
    let b = Buffer.create 16384 in
    write b doc;
    let tmp = out ^ ".tmp" in
    let oc = open_out_bin tmp in
    Buffer.output_buffer oc b;
    close_out oc;
    Sys.rename tmp out

let () = Boot.Main.extend run
