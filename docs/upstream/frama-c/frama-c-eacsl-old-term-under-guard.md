# E-ACSL: an `\old` Term Under a False-Making Guard Aborts at Function Entry

**Status:** draft, not filed, no package number. Filing is paused until the maintainers answer on
[#2832](https://git.frama-c.com/pub/frama-c/-/work_items/2832), see [`./README.md`](./README.md).

**Found on:** libmodbus `run-1`, 2026-11-18, candidate
`src/modbus-rtu.c#modbus_rtu_set_serial_mode::rte::2820aa2803`, which the run's crash verifier
rejected as an instrumentation artifact.

## Summary

A postcondition can protect a dereference with a guard on the pre-state pointer:

```c
/*@ ensures keep: \old(p) == \null || p->debug == \old(p->debug); */
```

For `p == NULL` the first disjunct holds, so the clause is true and the right side should not
matter. E-ACSL still evaluates `\old(p->debug)` when the function is entered, before the guard is
known, and stops the program with an RTE alarm on the valid call `f(NULL)`.

## Reproducer

```c
#include <stddef.h>

struct s {
  int pad;
  int debug;
};

/*@ ensures keep: \old(p) == \null || p->debug == \old(p->debug);
*/
int f(struct s *p)
{
  if (p == NULL)
    return -1;
  return 0;
}

int main(void)
{
  return f(NULL) == -1 ? 0 : 1;
}
```

```bash
e-acsl-gcc -c -G clang -F -e-acsl-full-mtracking -O out eold_guard.c
./out.e-acsl
```

## Observed

The same result on `34.0~beta` (`framac-analysis:latest`) and on `35.0~~dev`
(`framac-master-audit:b80fcac`): exit code 134, with this message.

```text
eold_guard.c: In function 'f'
eold_guard.c:8: Error: E-ACSL RTE failed:
	The failing predicate is:
	memory access:
		\valid_read(&p->debug).
	With values at failure point:
	- "memory access": \valid_read(&p->debug): 0
	- sizeof(int): 4
	- &p->debug: 0x4
Aborted
```

## Expected

The program exits with 0, or E-ACSL reports that it cannot evaluate this clause. The clause holds for
every call of `f`.

## Control

Moving the guard inside `\old` keeps the dereference from being evaluated, and the same call exits
with 0 on both versions:

```c
/*@ ensures keep: \old(p == \null ? 0 : p->debug) == \old(p == \null ? 0 : p->debug); */
```

That clause only shows that a guarded pre-state term runs cleanly. It is not a useful contract. The
same form can serve as a workaround: compare the post-state field with
`\old(p == \null ? 0 : p->debug)` under the outer guard.

## Not Checked

- Whether the E-ACSL manual documents this as a limitation of `\old`. If it does, the report becomes
  a request for a clearer diagnostic.
- The live tracker. The 2026-11-09 work-item snapshot has no matching E-ACSL item, but it predates
  the later reports.
- The cause in the E-ACSL sources. No patch was attempted.
