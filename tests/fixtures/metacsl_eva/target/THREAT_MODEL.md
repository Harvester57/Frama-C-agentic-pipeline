# Threat model: prog (MetAcsl under Eva fixture)

A login gate protects an admin command; what reaches the network sink must be initialized.

```json framac-threat-model
{
  "schema_version": 1,
  "target": "prog",
  "summary": "The password and the command come from outside; send_bytes writes to the network.",
  "input_sources": [
    {"function": "handle", "role": "entry", "params": ["pw", "cmd"], "description": "A request received from outside."}
  ],
  "trusted_callers": [],
  "secrets": [],
  "auth_gates": [
    {"function": "login", "state": "auth_ok", "protects": ["admin"], "description": "The password check sets auth_ok; the admin command needs it."}
  ],
  "output_sinks": [
    {"function": "send_bytes", "kind": "network", "params": ["buf"], "length": "n", "description": "Bytes sent to the peer."}
  ]
}
```
