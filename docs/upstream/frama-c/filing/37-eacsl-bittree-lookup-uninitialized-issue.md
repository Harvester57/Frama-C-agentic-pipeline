# [E-ACSL] bittree memory model: pt_lookup returns an uninitialized pointer when it finds the block (every free aborts, \freeable and read-only marks are wrong), and a program that stores no block crashes at exit

<!-- Everything below this line is the issue description. -->

### Summary

With `e-acsl-gcc -m bittree`, every operation of the runtime that looks a block up by its start address gets an uninitialized pointer when the block exists: `pt_lookup` in `observation_model/internals/e_acsl_patricia_trie.c` never assigns its result on the found path. With gcc `-O2` (the default) this reads as "not found": read-only marks are lost, a local is not marked initialized and stays valid after its scope, `\freeable(malloc(...))` is false, and every `free` aborts with "Not a start of block". Without optimisation (`-G clang`, which drops `-O2` (#2810), or `--rt-debug`) the garbage reaches the allocator and the program crashes before any check.

Separately, `bt_clean` dereferences the tree, which only exists once a block was stored: `int main(void) { return 0; }` built without `-M` crashes at exit. The existing test `special/e-acsl-bittree-model.c` runs only with `--full-mtracking` and frees nothing, so neither shows in the suite; !41 saw that test abort under clang without a diagnosis.

### Steps to reproduce the issue

`lookup.c`:

```c
#include <stdlib.h>

static const char table[4] = {1, 2, 3, 0};

int main(int argc, char **argv) {
  const char *t = table;
  //@ check RO: \valid_read(t) && !\valid(t);

  int *q;
  {
    int x = 1;
    q = &x;
    //@ check IN_SCOPE: \valid(q) && \initialized(q);
  }
  //@ check OUT_OF_SCOPE: !\valid(q);

  int *p = malloc(sizeof(int));
  //@ check FREEABLE: \freeable(p);
  free(p);
  return 0;
}
```

`empty.c`:

```c
int main(void) { return 0; }
```

```sh
e-acsl-gcc -q -c -m bittree -o lookup.inst.c -O lookup lookup.c && ./lookup.e-acsl; echo "exit $?"
e-acsl-gcc -q -c -m bittree -o empty.inst.c -O empty empty.c && ./empty.e-acsl; echo "exit $?"
```

### Expected behaviour

Both programs exit 0 with no failed check, as they do with the default segment model (`-m segment`).

### Actual behaviour

`lookup.c` (`...` marks lines left out):

```text
lookup.c: In function 'main'
lookup.c:7: Error: Assertion failed:
	The failing predicate is:
	RO:
		\valid_read(t) ∧ ¬\valid(t).
	With values at failure point:
	- \valid(t): 1
	- \valid_read(t): 1
	- sizeof(char const): 1
	- t: 0x5a24c1d8d1ea
lookup.c: In function 'main'
lookup.c:13: Error: Assertion failed:
	The failing predicate is:
	IN_SCOPE:
		\valid(q) ∧ \initialized(q).
	With values at failure point:
	- \initialized(q): 0
	- \valid(q): 1
	...
lookup.c:15: Error: Assertion failed:
	...
	OUT_OF_SCOPE:
		¬\valid(q).
	...
lookup.c:18: Error: Assertion failed:
	...
	FREEABLE:
		\freeable(p).
	With values at failure point:
	- FREEABLE: \freeable(p): 0
	- p: 0x71760fb6d400
Not a start of block (0x7176-0fb6-d400) in free
Aborted
exit 134
```

`empty.c`: `Segmentation fault`, exit 139.

The same with `-M` for `lookup.c` (`empty.c` passes with `-M`, which stores blocks). With `-G clang`, `lookup.c` aborts (exit 134) before any check, and `empty.c` crashes (139) without `-M` and aborts (134) with `-M`. With `--rt-debug`, `empty.c` reports `e_acsl_bittree.c:126: bittree != NULL`. The segment model passes every case.

### Contextual information

- Frama-C installation mode: from source (`master`) and opam (Docker image based on `framac/frama-c:dev`)
- Frama-C version: 35.0~~dev (Bromine), `master` at 95408044f7; also 34.0~beta (Selenium)
- Plug-in used: E-ACSL (`e-acsl-gcc`, `--memory-model bittree`)
- OS name: Debian GNU/Linux
- OS version: 13 (trixie)

### Additional information (optional)

**Cause.** `pt_lookup` (`plugins/e-acsl/share/e-acsl/observation_model/internals/e_acsl_patricia_trie.c:423-464`) declares `pt_leaf_t res;`, sets it to NULL on the mismatch paths, and returns it, but has no assignment when the leaf matches. Before `29af68df0e` ("[eacsl] Add C support for concurrency", 25.0) the function ended with `return tmp->leaf;`; the rewrite with a read lock and `goto end` lost it. `bt_lookup`, which is `pt_lookup` on the bittree, is used by `full_init`, `mark_readonly`, `\freeable`, `delete_block`, `store_block_duplicate`, `realloc` and `free` in `bittree_model/e_acsl_bittree_observation_model.c`.

The same function also asserts `pt->root != NULL` and dereferences the root, which is NULL again once every block has been removed (for example a double `free` of the only block). And `bt_clean` (`bittree_model/e_acsl_bittree.c:125-133`) asserts `bittree != NULL`, but the tree is only created by the first `bt_insert`.

This also explains why, with `-m bittree`, `\valid` holds on a `const` array or a string literal (the read-only mark is set by `mark_readonly`, which does not find the block).

**Fix.** In `pt_lookup`: initialise `res` to NULL, return NULL on an empty trie, and set `res = tmp->leaf` on a match. In `bt_clean`: return when the tree was never created. The lookup change alone is not enough: `empty.c` would still crash in `bt_clean`, and a double `free` would crash in `pt_lookup` instead of reporting "Not a start of block". A merge request with this fix and a regression test follows.

The analysis and fix were prepared with LLM assistance (Claude Code); I reviewed them and ran the reproducer and tests described above.
