# Threat model of libmodbus (structured block only)

```json framac-threat-model
{
  "schema_version": 1,
  "target": "libmodbus",
  "summary": "Modbus TCP/RTU client, server and gateway library; every byte received from a socket or serial line, and every request or response buffer derived from it, is attacker-controlled.",
  "input_sources": [
    {"function": "_modbus_receive_msg", "role": "reader", "description": "Frames one indication or confirmation from the socket or serial line into msg; read lengths come from the received function code and byte count (src/modbus.c:365-547)."},
    {"function": "src/modbus-tcp.c#_modbus_tcp_recv", "role": "reader", "description": "TCP backend recv callback, reached through ctx->backend->recv, filling the receive buffer from the socket with recv(2) (src/modbus-tcp.c:190-193)."},
    {"function": "src/modbus-rtu.c#_modbus_rtu_recv", "role": "reader", "description": "RTU backend recv callback, reached through ctx->backend->recv, filling the receive buffer from the serial line with read(2) (src/modbus-rtu.c:342-349)."},
    {"function": "modbus_receive", "role": "reader", "description": "Public server API that stores a received request in the caller's req buffer (src/modbus.c:550-558)."},
    {"function": "modbus_receive_confirmation", "role": "reader", "description": "Public client API that stores a received response in the caller's rsp buffer without correlating it with a request (src/modbus.c:560-576)."},
    {"function": "modbus_reply", "role": "entry", "params": ["req", "req_length"], "description": "Server request handler: parses the received request and reads or writes the mapping tables and the response buffer; mb_mapping is application state (src/modbus.c:802-1265)."},
    {"function": "modbus_reply_exception", "role": "entry", "params": ["req"], "description": "Builds an exception response from the received request header without a length parameter (src/modbus.c:1267-1298)."},
    {"function": "modbus_proxy", "role": "entry", "params": ["req", "req_length"], "description": "Gateway: re-frames the frontend request for the backend, then relays the backend response to the frontend (src/modbus.c:1303-1445)."},
    {"function": "modbus_send_raw_request_tid", "role": "entry", "params": ["raw_req", "raw_req_length"], "description": "Frames a raw PDU for the backend; modbus_proxy passes it the attacker's frontend PDU (src/modbus.c:230-266, src/modbus.c:1370-1371)."},
    {"function": "modbus_set_bits_from_bytes", "role": "entry", "params": ["tab_byte"], "description": "Unpacks packed coil bytes; modbus_reply passes the request's data bytes, with idx and nb_bits from the checked request (src/modbus-data.c:43-57, src/modbus.c:1078-1079)."},
    {"function": "modbus_set_bits_from_byte", "role": "entry", "params": ["value"], "description": "Public helper unpacking one received byte into bit values (src/modbus-data.c:32-39)."},
    {"function": "modbus_get_byte_from_bits", "role": "entry", "params": ["src"], "description": "Public helper packing received bit values into a byte; nb_bits is capped at 8 (src/modbus-data.c:61-76)."},
    {"function": "modbus_get_float", "role": "entry", "params": ["src"], "description": "Deprecated float decoder applied to two received registers (src/modbus-data.c:164-167)."},
    {"function": "modbus_get_float_abcd", "role": "entry", "params": ["src"], "description": "Float decoder (ABCD order) applied to two received registers (src/modbus-data.c:79-101)."},
    {"function": "modbus_get_float_dcba", "role": "entry", "params": ["src"], "description": "Float decoder (DCBA order) applied to two received registers (src/modbus-data.c:104-121)."},
    {"function": "modbus_get_float_badc", "role": "entry", "params": ["src"], "description": "Float decoder (BADC order) applied to two received registers (src/modbus-data.c:124-141)."},
    {"function": "modbus_get_float_cdab", "role": "entry", "params": ["src"], "description": "Float decoder (CDAB order) applied to two received registers (src/modbus-data.c:144-161)."}
  ],
  "trusted_callers": [],
  "secrets": [],
  "auth_gates": [],
  "output_sinks": [
    {"function": "src/modbus.c#send_msg", "kind": "network", "params": ["msg"], "length": "msg_length", "description": "Single path of every outgoing request and response frame, before the backend appends any checksum and sends it (src/modbus.c:169-228)."},
    {"function": "src/modbus-tcp.c#_modbus_tcp_send", "kind": "network", "params": ["req"], "length": "req_length", "description": "Sends every outgoing TCP frame with send(2), reached through ctx->backend->send (src/modbus-tcp.c:176-183)."},
    {"function": "src/modbus-rtu.c#_modbus_rtu_send", "kind": "network", "params": ["req"], "length": "req_length", "description": "Writes every outgoing RTU frame, CRC included, to the serial line with write(2), reached through ctx->backend->send (src/modbus-rtu.c:266-317)."},
    {"function": "src/modbus.c#response_exception", "kind": "other", "params": ["template"], "format": "template", "description": "Debug diagnostic: vfprintf to stderr with a printf-style template that must be a literal; received values reach it only as integer arguments (src/modbus.c:763-780)."}
  ]
}
```
