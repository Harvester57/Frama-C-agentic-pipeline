# E-ACSL: formal parameters are registered in shadow memory but never marked initialized, so `\initialized` on a by-value struct field fails on every call

Draft bug report for the Frama-C issue tracker (https://git.frama-c.com/pub/frama-c/-/issues). Not filed yet.

## Summary

With initialization checks on (`-rte -rte-initialized`), the first read of a field of a struct passed
by value fails at runtime on every call, whatever the caller passed:

```text
t.c: In function 'f_struct'
t.c:3: Error: Assertion failed:
	The failing predicate is:
	rte/initialization:
		\initialized(&s.len).
	With values at failure point:
	- rte: initialization: \initialized(&s.len): 0
	- sizeof(unsigned long): 8
	- &s.len: 0x7ffe29c3c5a8
Aborted
```

A scalar formal read through its address (`int *pk = &k; return *pk;`) fails E-ACSL's own
`\initialized(pk)` check the same way.

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

By contrast, the local `pk` in `f_scalar` gets `__e_acsl_full_init((void *)(& pk));` at its
assignment.

The parameter's shadow memory therefore reads as uninitialized. Locals do not have the problem:
E-ACSL emits `__e_acsl_full_init` at each of their assignments.

## Versions

- Reproduced with Frama-C `35.0~~dev (Bromine)` (Debian 13, clang 19.1.7), with `-G clang` and with
  or without `-M` (full memory tracking).

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
...
Aborted
```

With `main` calling only `f_scalar`, the program aborts there instead:

```text
s.c: In function 'f_scalar'
s.c:4: Error: E-ACSL RTE failed:
	The failing predicate is:
	uninitialized:
		\initialized(pk).
...
Aborted
```

Without initialization checks (`e-acsl-gcc -G clang -o t.inst.c -O t t.c`), it runs and exits 0.

## Proposed fix

Where E-ACSL emits the `__e_acsl_store_block` of a formal, also emit its `__e_acsl_full_init`. A
formal holds the caller's argument on entry, the same way a local holds the value it was just
assigned. For full precision, E-ACSL could instead copy the argument's initialization state at each
call site, so that a struct passed with uninitialized members is still reported. I have not
implemented either in Frama-C.

The workaround below applies the first fix to the generated C. On QCBOR (1,083 formals), it removes
all 13 false alarms. Every real alarm the campaign had found still fires, and two real
uninitialized reads that the false alarm had hidden now show up.

## Workaround

[`../../scripts/eacsl_toolchain.py`](../../scripts/eacsl_toolchain.py) (`mark_formals_initialized`)
post-processes the instrumented C between `e-acsl-gcc -n` and `-C`. In each function definition, it
inserts `__e_acsl_full_init((void *)(& p));` after the first `__e_acsl_store_block` of each formal
`p`, and declares the runtime function when Frama-C pruned its prototype.

The cost is that a struct passed by value with uninitialized members is no longer reported. Before
the workaround, that check failed on every call, so it could not tell the two cases apart anyway.

Without the post-pass, the only workaround is to turn off initialization checks
(`-rte-initialized`), which loses them everywhere.
