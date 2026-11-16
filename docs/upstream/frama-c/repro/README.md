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
- Patched images `framac-master-audit:3dff90f-p28` to `-p31` hold `master` with one patch each
  (the "after" runs of 28 to 31). In the master image, install a rebuilt tree with
  `dune install --release --prefix /home/opam/.opam/5.5` (plain `dune install` fails with
  "The mandir installation directory is unknown").
