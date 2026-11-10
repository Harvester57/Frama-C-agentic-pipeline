#!/bin/sh
# Docker scenario for tests/test_stub_check.py (S3): a fake target snapshot with a library `mylib`, the
# stub overlay stub_gen.py writes for it, filled by hand, then `stub_check.py run`. Prints the report.
# $1: `good` (contracts the library meets) or `bad` (ml_hash promises a result it does not return).
set -e
S=/opt/framac-pipeline/scripts
mkdir -p /tmp/run && cd /tmp/run
SNAP=/tmp/run/workspace/snapshot
mkdir -p $SNAP/root/usr/include/mylib $SNAP/root/usr/lib workspace/reports
cp /fixture/mylib.h /fixture/mylib_impl.h $SNAP/root/usr/include/mylib/
gcc -shared -fPIC -o $SNAP/root/usr/lib/libmylib.so /fixture/mylib.c
cat > $SNAP/manifest.json <<'EOF'
{"digest": "test", "files": {"/usr/include/mylib/mylib.h": "x", "/usr/include/mylib/mylib_impl.h": "x", "/usr/lib/libmylib.so": "x"}}
EOF
export FRAMAC_SNAPSHOT_DIR=$SNAP FRAMAC_STUB_OVERLAY_DIR=/tmp/run/workspace/stubs FRAMAC_CACHE=off
mkdir -p $FRAMAC_STUB_OVERLAY_DIR
D=$SNAP/root/usr/include/mylib/mylib_impl.h
cat > workspace/reports/phase0_model.json <<EOF
{"status": "ok",
 "functions": {"src/a.c#use": {"external_calls": ["ml_hash", "ml_name"]}},
 "externals": ["ml_hash", "ml_name"],
 "external_formals": {"ml_hash": [{"name": "ctx", "kind": "pointer"}, {"name": "data", "kind": "const_pointer"},
                                  {"name": "len", "kind": "value"}, {"name": "out", "kind": "pointer"}],
                      "ml_name": [{"name": "ctx", "kind": "const_pointer"}]},
 "external_decls": {
   "ml_hash": {"decl": "$D:1", "proto": "int ml_hash(ml_ctx *ctx, unsigned char const *data, size_t len, unsigned char out[32])"},
   "ml_name": {"decl": "$D:2", "proto": "char const *ml_name(ml_ctx const *ctx)"}}}
EOF
cat > workspace/reports/callgraph_dag.json <<'EOF'
{"modules": {"liba": {"functions": [], "external_callees": ["ml_hash", "ml_name"], "ldflags": ["-lmylib"],
                      "lexer_modules": ["liba_lex"]},
             "other": {"functions": [], "external_callees": ["strlen"]}}}
EOF
python3 $S/stub_gen.py run >/dev/null
H=workspace/stubs/mylib/mylib.h
test -f $H
python3 - "$1" "$H" <<'EOF'
import sys
mode, path = sys.argv[1], sys.argv[2]
text = open(path).read()
head = text.split("/* fc-stub:")[0]
result = r"\result == 0" if mode == "good" else r"\result == 1"
text = head + f"""/* fc-stub: ml_hash */
/*@
  requires valid_data: len > 0 ==> \\valid_read(data + (0 .. len - 1));
  requires valid_out: \\valid(out + (0 .. 31));
  assigns out[0 .. 31], \\result \\from data[0 .. len - 1], len;
  ensures ok: {result};
*/
extern int ml_hash(ml_ctx *ctx, unsigned char const *data, size_t len, unsigned char out[32]);

/* fc-stub: ml_name */
/*@
  assigns \\result \\from ctx;
  ensures named: \\result != \\null;
*/
extern char const *ml_name(ml_ctx const *ctx);
"""
open(path, "w").write(text)
EOF
python3 $S/stub_gen.py run >/dev/null
set +e
python3 $S/stub_check.py run --trials 8 > check.out 2>&1
echo "rc=$?"
cat check.out
echo "REPORT-BEGIN"
cat workspace/reports/stub_check.json
echo "REPORT-END"
python3 $S/phase0_gates.py check --module liba_lex --need reach 2>&1 | head -3
