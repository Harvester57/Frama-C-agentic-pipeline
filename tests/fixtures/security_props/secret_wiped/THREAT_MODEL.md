# Threat model: session (step I9 fixture)

A login gate protects an admin command; the session key must not outlive the session or reach the log.

```json framac-threat-model
{
  "schema_version": 1,
  "target": "session",
  "summary": "Session library: the password is attacker-controlled, the key is a secret.",
  "input_sources": [
    {"function": "session_login", "role": "entry", "params": ["pw", "n"], "description": "Checks a password received from outside."}
  ],
  "trusted_callers": [],
  "secrets": [
    {"name": "session_key", "kind": "global", "function": "session_close", "description": "The session key: wiped when the session closes, never logged."}
  ],
  "auth_gates": [
    {"function": "session_login", "state": "auth_ok", "protects": ["session_admin"], "description": "The password check sets auth_ok; the admin command needs it."}
  ],
  "output_sinks": [
    {"function": "log_line", "kind": "log", "params": ["msg"], "description": "Lines written to the system log."}
  ]
}
```
