# x509-parser threat model (benchmark asset)

x509-parser parses DER-encoded X.509 certificates and CRLs. A certificate arrives from a TLS peer, a
file or a certificate store, so the bytes given to the parsing functions are attacker-controlled. The
library allocates nothing and writes only into the parsing context its caller passes.

- **Input:** the buffer and length given to `parse_x509_cert`, `parse_x509_crl` and their `_relaxed`
  variants (the API of `x509-parser.h`, `x509-cert-parser.h` and `x509-crl-parser.h`). The command-line
  tool `src/main.c` maps the file named by `argv[1]` with `mmap` and hands it to the relaxed parsers.
- **Callers:** the library exports about sixty helpers of `x509-common.c` and `x509-utils.c`
  (`parse_x509_Name`, `get_length`, ...) because its files share them. No public header documents
  them for applications: only the library's own parsers call them, with bounds those parsers checked.
  They are called by trusted code only, so their preconditions may constrain values.
- **Secrets, authentication, output:** none. The parser holds no key, makes no access decision and
  writes only its caller's context.

```json framac-threat-model
{
  "schema_version": 1,
  "target": "x509-parser",
  "summary": "DER X.509 certificate and CRL parser; the encoded bytes are attacker-controlled.",
  "input_sources": [
    {"function": "parse_x509_cert", "role": "entry", "params": ["buf", "len"], "description": "Parses a DER certificate received from outside."},
    {"function": "parse_x509_cert_relaxed", "role": "entry", "params": ["buf", "len"], "description": "Parses a DER certificate at the start of a buffer received from outside."},
    {"function": "parse_x509_crl", "role": "entry", "params": ["buf", "len"], "description": "Parses a DER CRL received from outside."},
    {"function": "parse_x509_crl_relaxed", "role": "entry", "params": ["buf", "len"], "description": "Parses a DER CRL at the start of a buffer received from outside."},
    {"function": "mmap", "role": "reader", "description": "src/main.c maps the certificate file named on its command line."}
  ],
  "trusted_callers": [
    {
      "unit": "x509-parser.a",
      "except": ["parse_x509_cert", "parse_x509_cert_relaxed", "parse_x509_crl", "parse_x509_crl_relaxed"],
      "reason": "helpers shared between the library's own files; no public header offers them to applications"
    },
    {
      "unit": "x509-parser.so",
      "except": ["parse_x509_cert", "parse_x509_cert_relaxed", "parse_x509_crl", "parse_x509_crl_relaxed"],
      "reason": "helpers shared between the library's own files; no public header offers them to applications"
    }
  ],
  "secrets": [],
  "auth_gates": [],
  "output_sinks": []
}
```
