# QCBOR threat model (benchmark asset)

QCBOR encodes and decodes CBOR (RFC 8949). The decoder is documented for hostile input: the bytes
handed to `QCBORDecode_Init` come from a peer, a file or a token, and every decoding function reads
them through the decode context. The encoder takes the application's own values and writes into a
buffer the application supplies; its output then leaves the application.

- **Input:** the encoded CBOR given to `QCBORDecode_Init`, and the buffers the number decoder and
  `UsefulInputBuf` read. Every exported decoding function works on that input through the context,
  so the library-API rule already marks them untrusted; the entries below say where the bytes enter.
- **Callers:** `src/ieee754.c` is the library's private floating-point helper (its header is not
  installed). The encoder and the decoder are its only callers, so its exported NaN tests are called
  by trusted code only. The benchmark's QCBOR-02 and QCBOR-03 are in this file and are classed
  `internal_api` for the same reason.
- **Output:** the encoded CBOR the encoder returns (`QCBOREncode_Finish`) goes to a peer or a file.
- **Secrets, authentication:** none. QCBOR stores no key and enforces no access control.

```json framac-threat-model
{
  "schema_version": 1,
  "target": "QCBOR",
  "summary": "CBOR encoder/decoder; decoder input is attacker-controlled, encoder input is the application's.",
  "input_sources": [
    {"function": "QCBORDecode_Init", "role": "entry", "params": ["EncodedCBOR"], "description": "Starts decoding a CBOR buffer received from outside."},
    {"function": "QCBORDecode_ProcessBigNumber", "role": "entry", "description": "Converts a big number read from the decoded input (QCBOR-01)."},
    {"function": "UsefulInputBuf_GetBytes", "role": "entry", "description": "Reads bytes from an input buffer the decoder walks."},
    {"function": "UsefulInputBuf_Compare", "role": "entry", "description": "Compares bytes of an input buffer the decoder walks."}
  ],
  "trusted_callers": [
    {
      "functions": ["IEEE754_DoubleIsNonTrivialNaN", "IEEE754_SingleIsNonTrivialNaN"],
      "reason": "private floating-point helpers of src/ieee754.c (ieee754.h is not installed); only the encoder and decoder call them"
    }
  ],
  "secrets": [],
  "auth_gates": [],
  "output_sinks": [
    {"function": "QCBOREncode_Finish", "kind": "buffer", "params": ["pEncodedCBOR"], "description": "Returns the encoded CBOR the application sends or stores."}
  ]
}
```
