# minmea threat model (benchmark asset)

minmea is a parser library for NMEA 0183 sentences: the lines a GPS receiver writes on a serial port.
The receiver, the cable and anything that can inject data on the link are outside the application's
control, so every sentence handed to the library is attacker-controlled. The library allocates
nothing, keeps no state between calls, and writes only into the structures its caller passes.

- **Input:** a NUL-terminated sentence passed to the identification, checksum and parse functions.
  The parsed structures (dates, times, fixed-point values) carry values chosen by the sender, so the
  conversion functions that read them (`minmea_getdatetime`, `minmea_gettime`) are on the attacker's
  path too: the benchmark's MINMEA-01 is reached that way.
- **Callers:** the library has no internal-only API worth trusting: every exported function is
  documented for applications.
- **Secrets, authentication, output:** none. The library has no secret, no access control, and
  writes nothing but its caller's structures.
- **Example program:** `example.c` reads sentences from standard input with `fgets`, which the
  pipeline's input-reader rule already covers.

```json framac-threat-model
{
  "schema_version": 1,
  "target": "minmea",
  "summary": "NMEA 0183 sentence parser; every sentence is attacker-controlled.",
  "input_sources": [
    {"function": "minmea_check", "role": "entry", "params": ["sentence"], "description": "Validates the checksum of a received sentence."},
    {"function": "minmea_checksum", "role": "entry", "params": ["sentence"], "description": "Computes the checksum of a received sentence."},
    {"function": "minmea_sentence_id", "role": "entry", "params": ["sentence"], "description": "Identifies the type of a received sentence."},
    {"function": "minmea_talker_id", "role": "entry", "params": ["sentence"], "description": "Reads the talker identifier of a received sentence."},
    {"function": "minmea_scan", "role": "entry", "params": ["sentence"], "description": "Generic field scanner over a received sentence (public API)."},
    {"function": "minmea_parse_gbs", "role": "entry", "params": ["sentence"], "description": "Parses a received GBS sentence."},
    {"function": "minmea_parse_gga", "role": "entry", "params": ["sentence"], "description": "Parses a received GGA sentence."},
    {"function": "minmea_parse_gll", "role": "entry", "params": ["sentence"], "description": "Parses a received GLL sentence."},
    {"function": "minmea_parse_gsa", "role": "entry", "params": ["sentence"], "description": "Parses a received GSA sentence."},
    {"function": "minmea_parse_gst", "role": "entry", "params": ["sentence"], "description": "Parses a received GST sentence."},
    {"function": "minmea_parse_gsv", "role": "entry", "params": ["sentence"], "description": "Parses a received GSV sentence."},
    {"function": "minmea_parse_rmc", "role": "entry", "params": ["sentence"], "description": "Parses a received RMC sentence."},
    {"function": "minmea_parse_vtg", "role": "entry", "params": ["sentence"], "description": "Parses a received VTG sentence."},
    {"function": "minmea_parse_zda", "role": "entry", "params": ["sentence"], "description": "Parses a received ZDA sentence."},
    {"function": "minmea_getdatetime", "role": "entry", "params": ["date", "time_"], "description": "Converts a parsed date and time, whose fields the sender chose, to struct tm."},
    {"function": "minmea_gettime", "role": "entry", "params": ["date", "time_"], "description": "Converts a parsed date and time, whose fields the sender chose, to struct timespec."},
    {"function": "minmea_tocoord", "role": "entry", "params": ["f"], "description": "Public static inline conversion of a parsed coordinate, whose digits the sender chose."},
    {"function": "minmea_tofloat", "role": "entry", "params": ["f"], "description": "Public static inline conversion of a parsed fixed-point value, whose digits the sender chose."},
    {"function": "minmea_rescale", "role": "entry", "params": ["f"], "description": "Public static inline rescaling of a parsed fixed-point value, whose digits the sender chose."}
  ],
  "trusted_callers": [],
  "secrets": [],
  "auth_gates": [],
  "output_sinks": []
}
```
