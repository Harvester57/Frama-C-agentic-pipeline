# make-wrapper repair tips (ported from upstream `share/analysis-scripts/make_wrapper.py`)

Upstream `frama-c-script make-wrapper` parses `make` output and prints recommendations when it
recognizes these patterns. The pipeline ports them as `repair_hints` in the Eva report JSON
(`scripts/run_eva_slice.py`), mapped to pipeline actions:

| Log pattern (regex) | Upstream tip | Pipeline action |
|---|---|---|
| `detected recursive call` followed by `^\s+stack:` lines until a line starting with `[` | "Consider patching, stubbing or adding an ACSL specification to the recursive call, then re-run the analysis." | `pipeline_make.py params set --module <mod> --eva-recursion-fallback` (passes `-eva-warn-key assigns:missing=warning`, recorded in `reduced_checks`), or add an `assigns` contract / stub for the callee |
| `Neither code nor (specification|[^ ]+ assigns clause) for function ([^,]+),` | Runs `frama-c-script find-fun <fname>` and prints the file(s) defining it: "Add the following file to the list of sources to be parsed" or "provide a stub" | Locate the defining file via `build_callgraph_dag.py`'s function index and add it to the module sources, or add a stub to `templates/acsl/external_stubs.h` |

Upstream regexes (verbatim, for the port):

```python
re_missing_spec = re.compile(
    "Neither code nor (specification|[^ ]+ assigns clause) for function ([^,]+),"
)
re_recursive_call_start = re.compile("detected recursive call")
re_recursive_call_stack_start = re.compile(r"^\s+stack:")
re_recursive_call_stack_end = re.compile(r"^\[")
```
