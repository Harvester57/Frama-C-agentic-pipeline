/**
 * @name Functions untrusted data reaches
 * @description For scripts/codeql_trust.py (plan step I7): every defined function whose parameter a
 *              local or remote flow source taints (argv, environment, stdin and file reads, sockets),
 *              and every function holding such a source. One row per (function, source).
 * @kind table
 * @id framac/untrusted-functions
 */

import cpp
import semmle.code.cpp.ir.dataflow.TaintTracking
import semmle.code.cpp.security.FlowSources

module UntrustedConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof FlowSource }

  predicate isSink(DataFlow::Node n) { exists(n.asParameter(_)) }
}

module UntrustedFlow = TaintTracking::Global<UntrustedConfig>;

from Function f, string kind, string param, FlowSource src, Location def
where
  f.hasDefinition() and
  def = f.getDefinitionLocation() and
  (
    exists(DataFlow::Node sink, Parameter p |
      UntrustedFlow::flow(src, sink) and
      p = sink.asParameter(_) and
      f = p.getFunction() and
      kind = "parameter" and
      param = p.getName()
    )
    or
    f = src.getFunction() and kind = "source_site" and param = ""
  )
select f.getName(), def.getFile().getAbsolutePath(), def.getStartLine(), kind, param, src.getSourceType(),
  src.getLocation().getFile().getAbsolutePath(), src.getLocation().getStartLine()
