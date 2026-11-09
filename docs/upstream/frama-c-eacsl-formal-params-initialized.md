# E-ACSL: formal parameters are registered in shadow memory but never marked initialized, so `\initialized` on a by-value struct field fails on every call (#177 is back)

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). Not filed yet.

**Same bug as [#177](https://git.frama-c.com/pub/frama-c/-/work_items/177)**, closed on 2022-09-28 with
"The assertion does not fail anymore." Its program fails again on 34 and 35 (see
[Tracker](#tracker)). **Same family as
[frama-c-eacsl-struct-result-initialized.md](frama-c-eacsl-struct-result-initialized.md)**
(Issue 8): there the wrapper's `__retres` is registered but never marked initialized, here the formals
are. File the two together.

## Summary

The first read of a field of a struct passed by value fails at runtime on every call, whatever the
caller passed. It needs no option: a user annotation is enough, as in #177's program:

```text
i177.c: In function 'foo'
i177.c:6: Error: Assertion failed:
	The failing predicate is:
	\initialized(&s.t).
	With values at failure point:
	- \initialized(&s.t): 0
	- sizeof(int): 4
	- &s.t: 0x7ffced05689c
Aborted
```

With initialization checks on (`-rte -rte-initialized`), the RTE guard on a field read fails the same
way, so every function that reads a field of a by-value struct parameter aborts on its first call.
A scalar formal read through its address (`int *pk = &k; return *pk;`) fails E-ACSL's own
`\initialized(pk)` check, even right after an explicit assignment `k = 7;`.

This is a false positive on correct code. The assertion is blocking and usually sits at the
function's first statement, so nothing after it in the function is ever checked. Under a fuzzer,
every input that reaches the function "crashes". On QCBOR, 13 of 29 crash candidates in one campaign
were this false alarm. In a 594-input sample of that campaign's corpus, 305 inputs stopped at it
before reaching the code under test.

### Cause

For every formal it tracks, the instrumented function begins with
`__e_acsl_store_block((void *)(& p), sizeof(p));` but never emits
`__e_acsl_full_init((void *)(& p));`, although the caller has just written the parameter:

```c
int f_struct(struct S s, int k)
{
  int __retres;
  {
    int __gen_e_acsl_initialized;
    __e_acsl_store_block((void *)(& s),16UL);   /* no __e_acsl_full_init(&s) */
    __e_acsl_assert_data_t __gen_e_acsl_assert_data = {.values = (void *)0};
    __gen_e_acsl_initialized = __e_acsl_initialized((void *)(& s.len),
                                                    sizeof(unsigned long));
```

The store comes from `inject_in_stmt` (`plugins/e-acsl/src/code_generator/injector.ml:470`), which
calls `Memory_observer.store` on the formals. That function emits `__e_acsl_store_block` only.

The rest of E-ACSL assumes formals are initialized:

- `add_initializer` (`injector.ml:161-168`) emits no `__e_acsl_full_init` for an assignment to a
  whole formal: `may_safely_ignore` returns true for `vi.vglob || vi.vformal`. That is why `k = 7;`
  does not help.
- `needs_guard` (`plugins/e-acsl/src/analyses/rte_analysis.ml:493-501`) adds no initialization guard
  to a read of a whole formal (`not (vi.vglob || vi.vformal || vi.vtemp)`). So `if (k > 0)` is not
  checked, but `s.len` (a formal with a field offset) and `*pk` are. Those checks read shadow memory
  where the formal was never marked initialized.

Globals get the same assumption and are marked: `global_observer.ml:138`, "a global is both allocated
and initialized", emits `__e_acsl_store_block` and then `__e_acsl_full_init`. That was the fix for
[#975](https://git.frama-c.com/pub/frama-c/-/work_items/975) ("Global variables are not marked as
initialized", 2014). Formals never got the second call. Locals do not have the problem, since
E-ACSL emits `__e_acsl_full_init` at each of their assignments.

## Versions

- Reproduced with Frama-C `35.0~~dev (Bromine)`, built from `master` at `ad24dca` (2026-11-02),
  Debian 13, gcc 14.2.0 and clang 19.1.7, with and without `-M` (full memory tracking).
- Same behaviour in `34.0~~dev (Selenium)` (#177's program, gcc and clang, with and without `-M`).
- #177 was closed in 2022 as no longer failing. I cannot tell which release brought it back.

## Reproduction

`t.c`:

```c
struct S { const void *p; unsigned long len; };

int f_struct(struct S s, int k) { if(s.len > 3) return k + 1; return k; }
int f_scalar(int k) { int *pk = &k; return *pk * 2; }

int main(void)
{
   struct S full = {0, 5}; /* fully initialized */
   return f_struct(full, 2) + f_scalar(3) - 9;
}
```

```text
$ e-acsl-gcc -G clang -F "-rte -rte-initialized @all" -o t.inst.c -O t t.c && ./t.e-acsl
t.c: In function 'f_struct'
t.c:3: Error: Assertion failed:
	The failing predicate is:
	rte/initialization:
		\initialized(&s.len).
	With values at failure point:
	- rte: initialization: \initialized(&s.len): 0
	- sizeof(unsigned long): 8
Aborted
```

With `main` calling only `f_scalar` (`s.c`), the program aborts there instead:

```text
s.c: In function 'f_scalar'
s.c:4: Error: E-ACSL RTE failed:
	The failing predicate is:
	uninitialized:
		\initialized(pk).
...
Aborted
```

Without initialization checks (`e-acsl-gcc -G clang -o t.inst.c -O t t.c`), `t.c` runs and exits 0.

No RTE option is needed for a contract on the function either. `c.c`, built with plain
`e-acsl-gcc -G clang -o c.inst.c -O c c.c`:

```c
struct S { const void *p; unsigned long len; };
/*@ requires \initialized(&s.len); */
int f_req(struct S s) { return s.len > 3; }
int main(void) { struct S full = {0, 5}; return f_req(full) - 1; }
```

```text
c.c: In function 'f_req'
c.c:3: Error: Precondition failed:
	The failing predicate is:
	\initialized(&s.len).
...
Aborted
```

#177's program (`i177.c`, quoted on the issue) fails with plain `e-acsl-gcc i177.c`, as shown in the
[Summary](#summary).

## Proposed fix

Where E-ACSL stores the formals, also mark each one fully initialized, as `global_observer.ml` does
for globals:

```diff
--- a/plugins/e-acsl/src/code_generator/injector.ml
+++ b/plugins/e-acsl/src/code_generator/injector.ml
@@ -467,7 +467,8 @@ and inject_in_stmt env kf stmt =
           env
         else
           let env =
-            Memory_observer.store env kf (Kernel_function.get_formals kf)
+            Memory_observer.store_formals
+              env kf (Kernel_function.get_formals kf)
           in
           Temporal.handle_function_parameters kf env
       in
--- a/plugins/e-acsl/src/code_generator/memory_observer.ml
+++ b/plugins/e-acsl/src/code_generator/memory_observer.ml
@@ -29,6 +29,19 @@ let store env kf vars =
     kf
     vars
 
+let store_formals env kf formals =
+  tracking_stmt
+    List.fold_right (* small list *)
+    (fun vi ->
+       (* on function entry, a formal is both allocated and initialized (with
+          the value of the corresponding argument) *)
+       Smart_stmt.block_from_stmts
+         [ Smart_stmt.store_stmt vi;
+           Smart_stmt.initialize ~loc:vi.vdecl (Cil.var vi) ])
+    env
+    kf
+    formals
+
 let duplicate_store env kf vars =
   tracking_stmt
     Varinfo.Set.fold
--- a/plugins/e-acsl/src/code_generator/memory_observer.mli
+++ b/plugins/e-acsl/src/code_generator/memory_observer.mli
@@ -16,6 +16,10 @@ val store: Env.t -> kernel_function -> varinfo list -> Env.t
 (** For each variable of the given list, if necessary according to the mtracking
     analysis, add a call to [__e_acsl_store_block] in the given environment. *)
 
+val store_formals: Env.t -> kernel_function -> varinfo list -> Env.t
+(** Same as [store] for the formals of a function, which are also marked as
+    initialized with a call to [__e_acsl_full_init]. *)
+
 val duplicate_store: Env.t -> kernel_function -> Varinfo.Set.t -> Env.t
 (** Same as [store], with a call to [__e_acsl_duplicate_store_block]. *)
 
```

`Smart_stmt.initialize` on a whole variable emits `__e_acsl_full_init((void *)(& p))`. The block
prints flat, so the output reads:

```c
    __e_acsl_store_block((void *)(& s),16UL);
    __e_acsl_full_init((void *)(& s));
```

The `__gen_e_acsl_<fn>` wrapper of a function with a contract gets the same two calls for its own
formals.

Skipping the guard in `needs_guard` for formals with any offset, as the Issue 8 patch does for
`\result`, would not be enough. It covers RTE guards only. A user annotation (`\initialized(&s.t)`
in #177, the `requires` in `c.c`) and a read through a pointer (`*pk`) consult shadow memory, so the
shadow state itself has to be right.

**Cost.** A struct passed by value with an uninitialized member is no longer reported when the callee
reads that member (`p.c` below). Today that check fails on every call, so it cannot tell the two
cases apart anyway. Scalars lose nothing: an uninitialized scalar argument is read, and so checked, at
the call site (`su.c` below).

### More precise variant (not implemented)

Copy the argument's initialization state instead of marking the whole formal initialized. The caller
knows the argument lvalue, and the callee knows the formal's address. Temporal analysis already
passes per-argument metadata this way: `__e_acsl_temporal_save_*_parameter` runs at the call site,
and `__e_acsl_temporal_pull_parameter` runs in the callee. An initialization counterpart would copy
the argument's init bits when the argument is a tracked lvalue, and fall back to full
initialization otherwise. Only struct and union formals need it. I have not implemented it.

## Validation of the proposed fix

Built from `ad24dca` with the patch, then installed over the switch of a throwaway copy of the
35 image. Every program was built with `e-acsl-gcc -G clang`, and `-F` is
`-F "-rte -rte-initialized @all"`.

| Check | `master` | Patched |
|---|---|---|
| `t.c`, `-F` | false `\initialized(&s.len)`, abort | runs, exit 0 |
| `t.c`, `-M -F` | false `\initialized(&s.len)`, abort | runs, exit 0 |
| `s.c` (`f_scalar` only), `-F` | false `\initialized(pk)`, abort | runs, exit 0 |
| `a.c` (`k = 7; int *pk = &k; return *pk;`), `-F` | false `\initialized(pk)`, abort | runs, exit 0 |
| `c.c` (`requires \initialized(&s.len)`), no `-F`; and with `-F` | false precondition, abort | runs, exit 0 (wrapper and function both mark `s`) |
| #177's `i177.c`, no options, `-G gcc`/`-G clang`, with and without `-M` | `Assertion failed` (4 of 4) | runs, exit 0 (4 of 4) |
| `t.c` without initialization checks | exit 0 | exit 0 |
| `u.c`, a genuinely uninitialized local (`int x; if (c) x = 1; return x;` with `c == 0`), `-F` | reported | still reported (`\initialized(&x)`) |
| `su.c`, an uninitialized `int` passed by value, `-F` | reported at the call (`\initialized(&u)`) | still reported at the call |
| `p.c`, a struct passed with `.len` uninitialized, callee reads `.len`, `-F` | reported, like a correct call | **not reported** (the cost above) |
| ptests `plugins/e-acsl/tests`, default configuration (197 results) | — | 57 oracle changes, all `gen_*.c`: each adds `__e_acsl_full_init((void *)(& <formal>));` after the formal's `__e_acsl_store_block` (210 lines added, none removed or changed). No `.res.oracle` changes |
| ptests, E-ACSL `dev` configuration (195 tests, each compiled and run) | — | all match `oracle_dev` |
| With the Issue 8 patch applied too | — | both apply cleanly together; `struct_repro.c` (Issue 8), `t.c` and `i177.c` run clean; `u.c` and Issue 8's `uninit_neg.c` still report |

The 57 oracles are spread over `bts` (12), `memory` (13), `temporal` (8), `constructs` (6),
`builtin` (4), `concurrency` (4), `special` (4), `libc` (3), `format` (2) and `inductive` (1). They
need promoting with the patch. No existing test checks `\initialized` on a formal, which is why the
suite never caught this.

## Workaround

[`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py) (`mark_formals_initialized`)
post-processes the instrumented C between `e-acsl-gcc -n` and `-C`. In each function definition, it
inserts `__e_acsl_full_init((void *)(& p));` after the first `__e_acsl_store_block` of each formal
`p`, and declares the runtime function when Frama-C pruned its prototype. It has the same cost as
the proposed fix.

On QCBOR (1,083 formals), it removes all 13 false alarms. Every real alarm the campaign had found
still fires, and two real uninitialized reads that the false alarm had hidden now show up.

Without the post-pass, the only workaround is to turn off initialization checks
(`-rte-initialized`), which loses them everywhere, and to avoid `\initialized` on struct formals in
contracts.

## Tracker

- [#177](https://git.frama-c.com/pub/frama-c/-/work_items/177), "Incorrect handling of
  \initialized when initialized struct is passed to a function by value". It was reported in 2017
  from the Toyota ITC benchmark (`uninit_var.c`, case 012). A maintainer closed it on 2022-09-28
  with "The assertion does not fail anymore." Its program fails on 34 and 35. Ask for it to be
  reopened, or file a new issue that links it.
- [#975](https://git.frama-c.com/pub/frama-c/-/work_items/975), "Global variables are not marked
  as initialized" (2014, fixed): the same bug for globals.
- Nothing else matches. I checked the 202 open issues in the 2026-11-09 export
  ([`pub-frama-c_work_items_2026-11-09.csv`](pub-frama-c_work_items_2026-11-09.csv)), and searched
  all issues, open and closed, for `full_init`, `formal`, `store_block`, `parameter initialized`,
  `initialized struct`, `uninitialized` and `initialized`.
