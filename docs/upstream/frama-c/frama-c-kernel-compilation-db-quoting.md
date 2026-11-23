# [INTERNAL — DO NOT FILE PUBLICLY] Kernel (`-compilation-db`): Shell Quoting Defects, Crash on Lone Quote, and Potential Command Injection

> **DISCLOSURE HOLD — INTERNAL ANALYSIS DRAFT ONLY**
>
> This document is a private internal analysis draft for hunt candidate **H13**.
> It is intentionally excluded from [`./filing/`](./filing/README.md), [`./repro/`](./repro/README.md),
> [`./patches/`](./patches/README.md), and upstream overview issue `#2832`.
> Because code inspection shows an unquoted shell-execution path (`Sys.command`) reachable from
> `compile_commands.json` (`"arguments"`, `"command"`, and `"directory"`), **do not open a public
> issue, push a public branch, or mention these details in a public tracker** until the owner
> chooses the disclosure channel (for example, private security contact with the Frama-C/CEA
> maintainers versus a coordinated public report).
>
> No arbitrary command-execution payloads were tested during this analysis; only benign inputs
> (non-ASCII UTF-8 strings, `$HOME`, a tab character, spaces in paths/directories, and a single
> quote character) were executed to confirm the broken quoting and crash.

- **Parent index:** [`./README.md`](./README.md)
- **Hunt origin:** Candidate `H13` in [`./frama-c-hunt-2026-11-18-candidates.md`](./frama-c-hunt-2026-11-18-candidates.md)
- **Affected component:** Kernel (`src/kernel/services/ast_queries/json_compilation_database.ml`, `src/kernel/services/ast_queries/file.ml`)
- **Affected versions (verified on stock images):**
  - `35.0~~dev (Bromine)`, upstream `master` at `189053d4a2bd460c5c557dba8569474ff0419e73` (`189053d4a2`)
  - `34.0~beta (Selenium)` (`framac-analysis:latest`)
  - Environment: Debian GNU/Linux 13 (trixie; glibc 2.41, gcc 14.2.0)

---

## 1. Summary

When preprocessing a C file with `-compilation-db <path>`, Frama-C extracts selected flags
(`-I`, `-idirafter`, `-include`, `-imacros`, `-isystem`, `-D`, `-U`, `-std=`) and the working
directory (`"directory"`) from `compile_commands.json` (or a `build_commands.json` with
`"sources"`), concatenates them into a single shell command string, and executes that string
through `Sys.command` (`file.ml:663`, and `file.ml:1822` under `-audit-prepare`).

Four distinct defects exist in that pipeline:

1. **OCaml `%S` quoting used as POSIX shell quoting for `-D` (`json_compilation_database.ml:128`):**
   `quote_define_argument arg = Format.sprintf "%S" arg` emits an OCaml double-quoted literal
   rather than a POSIX shell-quoted word. Non-ASCII UTF-8 bytes become OCaml decimal escapes
   (`\195\169`, which C parses as octal), tabs become literal `\t` (C syntax error), and `/bin/sh`
   still performs parameter/command expansion (`$VAR`, `$(...)`, backticks) inside double quotes.
2. **No shell quoting at all for `Path`, `Undefine`, `Std`, or `"command"` flags (`json_compilation_database.ml:133-151`):**
   `-I`, `-idirafter`, `-include`, `-imacros`, `-isystem`, `-U`, and `-std=` values are pasted
   bare into the shell command, and `"command"` entries have their outer double quotes stripped by
   `remove_extraneous_quotes` while `requote` is `false`. Paths or macro definitions containing
   spaces split on whitespace and fail preprocessing.
3. **Uncaught `Invalid_argument("String.sub / Bytes.sub")` crash on a 1-character `"\""` argument (`json_compilation_database.ml:144-150`):**
   `remove_extraneous_quotes` checks `String.get arg 0 = '"' && String.get arg (len-1) = '"'`
   without requiring `len >= 2`, evaluating `String.sub arg 1 (-1)` when `arg = "\""` (exit 125).
4. **Unquoted `"directory"` in `cd <dir> && ...` (`file.ml:430`):**
   `adjust_pwd` builds `"cd " ^ (Filepath.to_string_abs dir) ^ " && " ^ cpp_command` without
   passing `~quoted:true` (unlike `file.ml:551-552`), breaking any build directory whose path
   contains a space (and passing `"directory"` raw to `/bin/sh`).

Per the [Clang JSON Compilation Database specification](https://clang.llvm.org/docs/JSONCompilationDatabase.html),
`"arguments"` is an `argv` vector of already-unescaped strings that must **never** be interpreted
by a shell. Because unquoted flags, double-quoted `-D` values, and unquoted `"directory"` values
all reach `/bin/sh` via `Sys.command`, analyzing a project with an untrusted `compile_commands.json`
exposes an OS command-injection surface.

---

## 2. Exact Source Locations (`master` `189053d4a2`)

### 2.1 `src/kernel/services/ast_queries/json_compilation_database.ml`

- **Lines 27-37 (`whitelisted_prefixes`):**
  `-I`, `-idirafter`, `-include`, `-imacros`, `-isystem` (`Path`), `-D` (`Define`), `-U`
  (`Undefine`), `-std=` (`Std`).
- **Lines 70-120 (`split_command_args`):**
  Hand-written splitter for the `"command"` string that keeps outer quotes on each token and does
  not implement full POSIX shell unescaping.
- **Line 128 (`quote_define_argument`):**
  ```ocaml
  let quote_define_argument arg = Format.sprintf "%S" arg
  ```
- **Lines 133-151 (`filter_useful_flags`, `process_prefix`, `remove_extraneous_quotes`):**
  ```ocaml
  let filter_useful_flags ~requote option_list =
    let convert_define arg =
      if requote then quote_define_argument arg else arg
    in
    let process_prefix prefix suffix =
      match prefix with
      | Path s -> s ^ suffix
      | Define s -> s ^ convert_define suffix
      | Undefine s -> s ^ suffix
      | Std s -> s ^ suffix
    in
    let remove_extraneous_quotes arg =
      let len = String.length arg in
      if len = 0 then arg
      else
      if String.get arg 0 = '"' && String.get arg (len-1) = '"' then
        String.sub arg 1 (len-2)
      else arg
    in
  ```
- **Lines 236-250 (`parse_build_entry`):**
  Calls `filter_useful_flags ~requote:true args` for build databases (`"sources"` + `"arguments"`).
- **Lines 252-284 (`parse_compilation_entry`):**
  Uses `requote = true` for `"arguments"` (preferred over `"command"` when both exist) and
  `split_command_args s, false` for `"command"`.
- **Lines 309-315 (`compute_flags_from_file`):**
  Catches only `Sys_error`, `Yojson.Json_error`, and `Yojson.Basic.Util.Type_error`; `Invalid_argument`
  from `String.sub` escapes as an unhandled crash (`exit 125`).

### 2.2 `src/kernel/services/ast_queries/file.ml`

- **Lines 91-103 (`from_filename`):**
  Retrieves `Json_compilation_database.get_flags f` as `extra_for_this_file`.
- **Lines 419-432 (`adjust_pwd`):**
  ```ocaml
  let adjust_pwd fp cpp_command =
    if Kernel.CompilationDb.is_set () || Kernel.MopsaDb.is_set () then
      let cwd = Filepath.pwd () in
      let dir =
        if Kernel.CompilationDb.is_set () then
          match Json_compilation_database.get_dir fp with
          | None -> cwd
          | Some d -> d
        else (* MopsaDB being used *)
          Option.value ~default:cwd (Parse_env.get_workdir fp)
      in
      if cwd <> dir then Some dir, "cd " ^ (Filepath.to_string_abs dir) ^ " && " ^ cpp_command
      else None, cpp_command
    else None, cpp_command
  ```
  Notice `file.ml:551-552` explicitly uses `Filepath.to_string_abs ~quoted:true`, whereas line 430
  omits `~quoted:true`.
- **Lines 527-595 (`build_cpp_cmd`):**
  Joins `extra_for_this_file` with spaces via `concat_strs ~pre:" " ~sep:" " extra` (line 592)
  into the preprocessor command string.
- **Line 663 (`parse_cabs`) and line 1822 (`compute_sources_table`):**
  Executes the resulting string via `Sys.command cpp_command` (invoking `/bin/sh -c`).

### 2.3 Documentation Check

`doc/userman/user-sources.tex:104-127` documents `-compilation-db` as reading standard CMake/Bear
JSON compilation databases and states no restriction against spaces, UTF-8 characters, `$` in
macro definitions, or paths with spaces.

---

## 3. Benign Verification Results (Stock `master` `189053d4a2` and Stock `34.0~beta`)

All eight benign cases below produced identical results on both `framac-master-audit:189053d`
(`35.0~~dev (Bromine)`) and `framac-analysis:latest` (`34.0~beta (Selenium)`).

### Case 1: `"arguments"` `-D` with UTF-8 and `$HOME`

`g.c`:

```c
const char name[] = NAME;
const char price[] = PRICE;
```

`db_args_def.json`:

```json
[{"directory": "/tmp/h13", "file": "g.c",
  "arguments": ["gcc", "-DNAME=\"café\"", "-DPRICE=\"$HOME\"", "-c", "g.c"]}]
```

- **GCC ground truth** (`gcc '-DNAME="café"' '-DPRICE="$HOME"' -E g.c`):
  ```c
  const char name[] = "café";
  const char price[] = "$HOME";
  ```
- **Frama-C** (`frama-c -compilation-db db_args_def.json -print g.c`):
  ```c
  char const name[9UL] = "caf\00195\0169";
  char const price[11UL] = "/home/opam";
  ```
  The analyzed program has corrupted string contents and lengths, and embeds the invoking user's
  `HOME` environment variable.

### Case 2: `"arguments"` `-I` path containing a space

`db_args_incdir.json`: `"arguments": ["gcc", "-I", "/tmp/h13/my inc", "-c", "h1.c"]`

- **Frama-C output:**
  ```text
  /tmp/h13/h1.c:1:10: fatal error: h.h: No such file or directory
  [kernel] User Error: failed to run: gcc -E ... -I/tmp/h13/my inc '/tmp/h13/h1.c' -o '/tmp/h1.c....i'
  ```

### Case 3: `"arguments"` two-argument `-include` with a space

`db_args_include.json`: `"arguments": ["gcc", "-include", "my inc/h.h", "-c", "h2.c"]`

- **Frama-C output:**
  ```text
  gcc: fatal error: cannot specify ‘-o’ with ‘-c’, ‘-S’ or ‘-E’ with multiple files
  [kernel] User Error: failed to run: gcc -E ... -includemy inc/h.h '/tmp/h13/h2.c' -o '/tmp/h2.c....i'
  ```
  (Note: `-include` with a space-free path `["-include", "h.h"]` happens to work under GCC because
  GCC accepts `-includeh.h`, but fails as soon as the path contains whitespace.)

### Case 4: `"arguments"` `-D` containing a literal TAB

`db_args_tab.json`: `"arguments": ["gcc", "-DN=1\t+ 2", "-c", "tab.c"]`

- **Frama-C output:**
  ```text
  [kernel] tab.c:1: User Error: 
    Invalid symbol:
    Location: "tab.c", line 1, before or at token: \
          int v = 1\t+ 2;
                   ^
  ```

### Case 5: `"arguments"` lone `"\""` crashes with unhandled `Invalid_argument`

`db_args_crash.json`: `"arguments": ["gcc", "\"", "-c", "g.c"]`

- **Command:** `OCAMLRUNPARAM=b frama-c -debug 1 -compilation-db db_args_crash.json g.c` (exit `125`)
- **Verbatim output (`master` `189053d4a2`; identical stack on `34.0~beta`):**
  ```text
  [kernel:backtrace] 
    Current location was: <generated by Frama-C kernel>
    The full backtrace is:
    Raised at Stdlib.invalid_arg in file "stdlib.ml", line 30, characters 20-45
    Called from Stdlib__String.sub in file "string.ml", line 45, characters 2-23
    Called from Frama_c_kernel_base__Json_compilation_database.filter_useful_flags.(fun) in file "src/kernel/services/ast_queries/json_compilation_database.ml", line 157, characters 18-46
    Called from Stdlib__List.fold_left in file "list.ml", line 125, characters 24-34
    Called from Frama_c_kernel_base__Json_compilation_database.filter_useful_flags in file "src/kernel/services/ast_queries/json_compilation_database.ml", lines 156-185, characters 4-30
    Called from Frama_c_kernel_base__Json_compilation_database.parse_compilation_entry in file "src/kernel/services/ast_queries/json_compilation_database.ml", line 283, characters 14-61
    Called from Stdlib__List.iter in file "list.ml", line 114, characters 12-15
    Called from Frama_c_kernel_base__Json_compilation_database.compute_flags_from_file in file "src/kernel/services/ast_queries/json_compilation_database.ml", line 308, characters 6-70
    Called from Frama_c_kernel_base__Json_compilation_database.get_flags in file "src/kernel/services/ast_queries/json_compilation_database.ml", line 320, characters 39-65
    Called from Frama_c_kernel_base__File.from_filename in file "src/kernel/services/ast_queries/file.ml", line 96, characters 21-58
    Called from Stdlib__List.map in file "list.ml", line 85, characters 15-19
    Called from Frama_c_kernel_base__File.init_from_cmdline in file "src/kernel/services/ast_queries/file.ml", line 1999, characters 14-55
    Called from Frama_c_kernel_base__Ast.force_compute in file "src/kernel/services/ast_data/ast.ml", line 99, characters 2-28
    Called from Frama_c_kernel_base__Ast.compute in file "src/kernel/services/ast_data/ast.ml", line 108, characters 53-71
    Called from Frama_c_kernel_base__Boot.play_analysis in file "src/kernel/internals/runtime/boot.ml", line 17, characters 6-20
    Called from Frama_c_kernel_base__Cmdline.play_in_toplevel_one_shot in file "src/kernel/services/cmdline_parameters/cmdline.ml", line 946, characters 2-9
    Called from Frama_c_kernel_base__Cmdline.play_in_toplevel in file "src/kernel/services/cmdline_parameters/cmdline.ml", line 979, characters 18-64
    Called from Frama_c_kernel_base__Cmdline.catch_toplevel_run in file "src/kernel/services/cmdline_parameters/cmdline.ml", line 189, characters 4-8
  [kernel] Unexpected error (Invalid_argument("String.sub / Bytes.sub")).
  ```

### Cases 6 & 7: `"command"` form with spaces in `-I` or `-D`

- `db_cmd_incdir.json`: `"command": "gcc \"-I/tmp/h13/my inc\" -c h1.c"`
  -> `remove_extraneous_quotes` strips the outer quotes, emitting unquoted `-I/tmp/h13/my inc` ->
  `fatal error: h.h: No such file or directory`.
- `db_cmd_def.json`: `"command": "gcc \"-DNAME=\\\"a b\\\"\" -DPRICE=\\\"x\\\" -c g.c"`
  -> `remove_extraneous_quotes` strips the outer quotes while `requote = false`, emitting
  `-DNAME=\"a b\"` -> `gcc: error: b": linker input file not found`.

### Case 8: `"directory"` containing a space (`file.ml:430`)

`db_space_dir.json`: `"directory": "/tmp/h13/my dir"`, `"file": "d.c"`, `"arguments": ["gcc", "-c", "d.c"]`

- **Frama-C output** (`frama-c -compilation-db db_space_dir.json -print "my dir/d.c"`):
  ```text
  sh: 1: cd: can't cd to /tmp/h13/my
  [kernel] User Error: failed to run: cd /tmp/h13/my dir && gcc -E ... '/tmp/h13/my dir/d.c' -o '/tmp/d.c....i'
  ```

---

## 4. Security Analysis (Code Inspection Only)

No command-execution payload was constructed or executed. By code inspection of `master`
`189053d4a2`:

1. In `"arguments"` mode (`parse_compilation_entry:274-275`, `parse_build_entry:245-246`), every
   whitelisted `Path`, `Undefine`, and `Std` argument is concatenated raw onto `cpp_command`
   (`json_compilation_database.ml:139,141,142` -> `file.ml:592`), and every `Define` argument is
   wrapped only in double quotes by OCaml `%S` (`json_compilation_database.ml:128,140`), where
   POSIX `/bin/sh` still performs `$()` / `` `...` `` command substitution and parameter expansion.
2. `"directory"` from `compile_commands.json` (or `build_commands.json`, or MopsaDB) is
   concatenated raw into `"cd " ^ (Filepath.to_string_abs dir) ^ " && " ^ cpp_command`
   (`file.ml:430`).
3. `cpp_command` is passed directly to `Sys.command` (`file.ml:663`, and `file.ml:1822`).
4. While `"command"` is a shell-encoded command string in the LLVM schema, `"arguments"` is
   explicitly specified as an argument vector that avoids shell quoting/interpretation. Any user
   running `frama-c -compilation-db` against a repository whose `compile_commands.json` is
   untrusted or crafted is exposed to unintended shell evaluation.

---

## 5. Duplicate Check & Pipeline Impact

- **Duplicate check (2026-11-22, benign read-only `glab api` queries against `pub/frama-c` project
  780, issues and MRs, all states):** `compilation database`, `json_compilation_database`,
  `quote_define_argument`, `remove_extraneous_quotes`, `compile_commands`, plus
  [`./pub-frama-c_work_items_2026-11-09.csv`](./pub-frama-c_work_items_2026-11-09.csv) and
  packages `01` to `50` in [`./README.md`](./README.md) -> **0 duplicates**.
- **Pipeline impact:** Not affected. No script under `scripts/` invokes Frama-C with
  `-compilation-db` or `-json-compilation-database`; the pipeline constructs preprocessor arguments
  directly.

---

## 6. Recommended Fix Direction

1. **`json_compilation_database.ml`:**
   - Replace `quote_define_argument` (`Format.sprintf "%S"`) with POSIX single-quote shell quoting
     (`Filename.quote`) applied to **every** extracted flag (`Path`, `Define`, `Undefine`, `Std`)
     produced from `"arguments"` (and `parse_build_entry`), keeping the prefix and argument cleanly
     separated where appropriate (e.g., `Filename.quote (s ^ suffix)` or `s ^ " " ^ Filename.quote suffix`).
   - Fix `remove_extraneous_quotes` to require `len >= 2` (or remove it in favor of proper shell
     word unescaping inside `split_command_args` for `"command"`, followed by `Filename.quote` on
     each resulting argv element so both `"arguments"` and `"command"` produce properly quoted
     arguments).
   - Longer term, executing the preprocessor via `Unix.create_process` (argv array, no `/bin/sh`)
     eliminates the entire shell-quoting class of bugs, though `-cpp-command` custom shell strings
     would still need a fallback path.
2. **`file.ml:430` (`adjust_pwd`):**
   - Use `Filepath.to_string_abs ~quoted:true dir` (consistent with `file.ml:551-552`) instead of
     `Filepath.to_string_abs dir`.
3. **Regression tests (`tests/jcdb/`):**
   - Add test cases covering `-D` with UTF-8 bytes, `$VAR`, tabs, `-I`/`-include` paths with
     spaces, `"command"` entries with quoted spaces, a lone `"\""` argument, and a `"directory"`
     containing spaces.

---

## 7. Open Decision for the Owner

- Decide whether to disclose H13 privately to the Frama-C maintainers (CEA) first, or wait for the
  maintainers' response on `#2832` and ask for a private security reporting channel before sending
  any details.
