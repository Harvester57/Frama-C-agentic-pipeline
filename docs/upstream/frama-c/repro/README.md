# Frama-C reproducers

- **Parent index and coverage table:** [`../README.md`](../README.md)

One POSIX `sh` script per bug, `NN-<slug>.sh`, with its C sources (`NN-<slug>.c`, and
`NN-<slug>-<variant>.c|.h` where there is more than one case). Each script's header says which
Frama-C it needs, the command to run, and the real output before and after the fix.

Run a script from this folder inside a Frama-C image, for example:

```sh
docker run --rm -v "$PWD:/w" -w /w --entrypoint sh framac-analysis:fc34 NN-<slug>.sh
```

- `framac-analysis:fc34` is the `34.0~beta` release.
- The 2026-11-15 audit also used `framac-master-audit:3dff90f`, a local build of upstream `master`
  `3dff90fc70`. That image is scratch, not part of the pipeline, and its MetAcsl plug-in does not
  load.
- E-ACSL reproducers that abort on purpose are slow on a Docker Desktop / WSL2 host. Run them under
  `prlimit --core=1:1`; see "Every `abort()`" in
  [`../../../troubleshooting/resources-and-infra.md`](../../../troubleshooting/resources-and-infra.md).
  The scripts of 28 to 31 use `prlimit --core=0`, which a piped `core_pattern` ignores: they give
  the right result, only more slowly, and print "core dumped".
- **2026-11-17:** `framac-master-audit:3dff90f` and the patched images below no longer exist. The
  current one is `framac-master-audit:9540804` (`master` `95408044f7`), built from
  [`../../../../tools/upstream_audit/Dockerfile`](../../../../tools/upstream_audit/Dockerfile);
  [`../../../../tools/upstream_audit/revalidate.sh`](../../../../tools/upstream_audit/revalidate.sh)
  runs a reproducer before and after its patch. An abort in a container now takes 6 ms on this
  host with the core limit at 0, so the slowness described above is gone.
- The scripts of 32, 33, 36, 37 and 38 print a table and always exit 0: compare their output with the
  "before" and "after" blocks in their headers. Their optional `EACSL_SHARE` points `e-acsl-gcc` at
  another copy of the runtime sources. 34 has no patch and 40's patch only changes the manual, so both have only a "before" output.
  41 prints one line per `TIOCM_*` name and exits 1 while the bug is present, 0
  once it is fixed. Its "before" and "after" outputs were taken on `master` `b80fcac74f`: the audit
  image's tree fast-forwarded (`git fetch https://git.frama-c.com/pub/frama-c.git master`), rebuilt
  and reinstalled.
  42 runs one C file four times (`-DCASE_contract`, `lemma`, `suffix`, `real`) with
  `-wp-prover none -wp-print`, so it needs no prover; it exits 1 while the bug is present and 0
  once it is fixed. Its outputs were taken on `master` `b80fcac74f` in the same way as 41's.
  43 builds one C file six times with `e-acsl-gcc` (`-DCASE_exponent`, `tolerance`,
  `exponent_false`, `hexadecimal`, `long_double`, `long_double_false`) and runs each binary. It
  prints one line per case, and exits 1 while the bug is present (6 of 6 cases fail) and 0 once
  it is fixed. It finds the script under either name: the audit image installs `e-acsl-gcc`,
  other installations `e-acsl-gcc.sh`. Its outputs were taken on `b80fcac74f` too.
  44 runs nine checks on four C files: five Eva checks compared with the compiled program,
  two WP callers (one whose postcondition is false at run time and must not be proved), a
  byte-loop `strlcat` that WP must prove against the contract of `<string.h>`, and an
  overlapping call that Eva must reject. It needs gcc and
  Alt-Ergo, prints one line per check, and exits 1 while the bug is present (9 of 9 checks
  fail) and 0 once it is fixed. Its outputs were taken on the image
  `framac-master-audit:b80fcac`; `34.0~beta` gives the same "before" lines.
  45 is about the MetAcsl plug-in: it needs `framac-analysis:latest` (the audit image's MetAcsl
  does not load) and Alt-Ergo, prints one line per case, and exits 1 while `\result` is refused
  in a `\postcond` property. It has only a "before" output: no patched build exists.
  47, 48 and 49 are about MetAcsl too and need `framac-analysis:latest`. Each prints one line per
  case and exits 1 while the defect is present. 47 runs three labels (`Old` through a labelled
  logic function, `\old`, `Pre`) through a kernel reparse, WP and E-ACSL (`Here` under `After` is
  covered in the patch's test); 48 compares a folded and an unfolded instance in `-report` and in
  an `e-acsl-gcc` binary; 49 compares the Frama-C libc with the system headers and runs nine
  `e-acsl-gcc` binaries (including a plain `*p = 1` out-of-bounds write; needs gcc). Their "after"
  outputs were taken with a patched MetAcsl built in a throwaway container of the same image.
- Patched images `framac-master-audit:3dff90f-p28` to `-p31` held `master` with one patch each
  (the "after" runs of 28 to 31). In the master image, install a rebuilt tree with
  `dune install --release --prefix /home/opam/.opam/5.5` (plain `dune install` fails with
  "The mandir installation directory is unknown").
