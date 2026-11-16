# [E-ACSL] \object_pointer is false at run time on read-only data (string literals, const arrays), so every -warn-invalid-pointer guard on it fails

<!-- Everything below this line is the issue description. -->

### Summary

In a program instrumented by E-ACSL, `\object_pointer(p)` is false whenever `p` points into a string literal, a `const` global array or `stdin`, although `\valid_read(p)` holds on the same pointer. The runtime implements `\object_pointer` with the implementation of `\valid`, which requires the block to be writable, and E-ACSL marks these blocks read-only. The ACSL definition of `\object_pointer` (manual, section 2.7.1: the pointer points to an element of an array object, or one past its last element) does not ask for writability.

Users meet it through `-warn-invalid-pointer`: the RTE guard `\null == p || \object_pointer(p)` then fails on the first read through a pointer to a string literal or a constant table. On two real code bases this made the option unusable when replaying a fuzzing corpus through an E-ACSL build: in minmea, 371 of 372 inputs abort at `while (*format)`, where `format` is a format string literal; in nettle (SHA-3), 15 of 24 inputs abort on `&nettle_sha3_permute_rc[i]`, a `static const` table.

### Steps to reproduce the issue

`direct.c`:

```c
static const char const_table[4] = {1, 2, 3, 0};
static char plain_table[4] = {1, 2, 3, 0};

static void check(const char *p) {
  /*@ assert \valid_read(p); */
  /*@ assert \object_pointer(p); */
}

int main(int argc, char **argv) {
  char local[4] = {1, 2, 3, 0};
  int which = argc > 1 ? argv[1][0] - '0' : 0;
  if (which == 0) check(local);
  if (which == 1) check(plain_table);
  if (which == 2) check(const_table);
  if (which == 3) check("abc");
  return 0;
}
```

`rte.c`, the same objects read through a pointer, with `-rte -warn-invalid-pointer`:

```c
static const unsigned char const_table[4] = {1, 2, 3, 0};
static unsigned char plain_table[4] = {1, 2, 3, 0};

static int scan(const unsigned char *p) {
  int n = 0;
  while (*p) {
    unsigned char v = *p++;
    n += v;
  }
  return n;
}

int main(int argc, char **argv) {
  unsigned char local[4] = {1, 2, 3, 0};
  int which = argc > 1 ? argv[1][0] - '0' : 0;
  int n = 0;
  if (which == 0) n = scan(local);
  if (which == 1) n = scan(plain_table);
  if (which == 2) n = scan(const_table);
  if (which == 3) n = scan((const unsigned char *)"abc");
  return n == 6 || n == 'a' + 'b' + 'c' ? 0 : 1;
}
```

```sh
e-acsl-gcc -q -c -o direct.inst.c -O direct direct.c
for i in 0 1 2 3; do ./direct.e-acsl $i; echo "exit $?"; done
e-acsl-gcc -q -c -F "-rte -warn-invalid-pointer" -o rte.inst.c -O rte rte.c
for i in 0 1 2 3; do ./rte.e-acsl $i; echo "exit $?"; done
```

### Expected behaviour

All eight runs exit 0: each pointer points into an object, and Eva (`frama-c -eva direct.c`) reports both assertions of `check` valid.

### Actual behaviour

Objects 0 (local array) and 1 (writable global array) pass. Objects 2 (`const` array) and 3 (string literal) pass `\valid_read(p)` and then fail `\object_pointer(p)`; object 2 (bash):

```text
direct.c: In function 'check'
direct.c:6: Error: Assertion failed:
	The failing predicate is:
	\object_pointer(p).
	With values at failure point:
	- \object_pointer(p): 0
	- sizeof(char const): 1
	- p: 0x5ebde54730aa
bash: line 1:    66 Aborted                 (core dumped) ./direct.e-acsl $i
exit 134
```

and with `-warn-invalid-pointer`, at the first read in `scan`, object 2:

```text
rte.c: In function 'scan'
rte.c:6: Error: E-ACSL RTE failed:
	The failing predicate is:
	invalid pointer:
		\null ≡ p ∨ \object_pointer(p).
	With values at failure point:
	- \object_pointer(p): 0
	- sizeof(unsigned char const): 1
	- p: 0x574b28d107b0
bash: line 1:   121 Aborted                 (core dumped) ./rte.e-acsl $i
exit 134
```

Object 3 prints the same, with another address.

Same result with `-G clang`, with `-M` (`-e-acsl-full-mtracking`), with both, and with `--temporal`. With `-m bittree` all runs pass, but only because that model does not keep the read-only mark: `\valid(p)` is true there for the `const` array and the literal too. `\object_pointer(stdin)` is false as well (segment model): `stdin` is registered as a non-writable safe location.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 3dff90fc70; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** `plugins/e-acsl/share/e-acsl/observation_model/e_acsl_observation_model.c:103-107`:

```c
int eacsl_object_pointer(void *ptr, size_t size, void *ptr_base,
                         void *addrof_base) {
  return eacsl_valid(ptr, size, ptr_base, addrof_base)
         || eacsl_valid(ptr - size, size, ptr_base, addrof_base);
}
```

`eacsl_valid` implements `\valid`: in the segment model it is `allocated(...) && !readonly(ptr)`, in the bittree model `blk != NULL && !blk->is_readonly`, and for a safe location `safeloc->writeable`. `eacsl_valid_read` is the same test without the writability condition. String literals and `const` globals are marked with `__e_acsl_mark_readonly` in `__e_acsl_globals_init`, so `eacsl_valid` is 0 at `ptr` and at `ptr - size`. The translation is fine: `Rte_analysis` builds `\null == p || \object_pointer(p)`, and `Memory_translate.call_valid` passes the pointer, `sizeof(*p)`, the base and its address to `__e_acsl_object_pointer` as it does for `\valid` and `\valid_read`. The ACSL contract of the builtin (`e_acsl_observation_model.h`, behaviours `valid`, `minus_one` and `invalid_pointer_ptr`) also uses `\valid`, so it states the same writability requirement; Eva, which analyses the instrumented code in the E-ACSL test suite, concludes from it that `\object_pointer` is false on a `const` array.

No test covers the case: `tests/memory/objects.c` checks `\object_pointer` on writable objects only, and `tests/acsl-rte/rte.c` has no string literal or `const` object.

**Fix.** Use `eacsl_valid_read` in `eacsl_object_pointer`, and `\valid_read` in the three behaviours of its contract. One past the end and out-of-bounds pointers keep their meaning: the base check and the `ptr - size` case are unchanged. A merge request with this fix and a regression test follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the reproducer and tests described above.
