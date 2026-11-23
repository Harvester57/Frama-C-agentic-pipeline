#!/usr/bin/env python3
"""
A harness for a module's whole API, built from the Phase 0 model (scripts/generate_harness.py --api).

A pinned or hand-written harness drives the entry points someone chose; the rest of the API is never
fuzzed. This one gives every API entry point of the module's scope a dispatch case (the first input
byte selects it), with arguments built from the model's signature of each function:

  - a scalar, an enum, or a struct by value without pointers: read from the input
    (`memcpy(&a, FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off), sizeof a)`: the input, or in `eva_main` an
    initialized shadow of it, see templates/harness_dual.c.template);
  - a struct by value with pointers (a `{ptr, len}` slice such as QCBOR's `UsefulBufC`): never read
    from the input as a whole, so no input byte becomes a pointer. Its layout comes from the target's
    headers (`probe_layouts`: clang's AST of the harness). Each (pointer, length) field pair gets
    generator-owned storage: an input pair (`const` pointee) takes the rest of the input when it is
    still free, else a `PAIR_BYTES` buffer read from the input; an output pair a zeroed spare buffer;
    the length is read from the input and clamped to that storage. Another pointer field points to a
    zeroed spare buffer, a function pointer stays NULL (a table of function pointers is rule G's,
    below), every other field is read from the input. A struct whose layout is unknown is zeroed, and
    the case's `notes` say why;
  - a byte pointer followed by a length (a `(buf, len)` pair: an unsigned integer, or a signed one
    whose formal name says length, never an enum): the first input pair gets the rest of the input
    itself, so a read past it is caught; an output pair gets a spare buffer and a length read from
    the input, clamped to the buffer. A length-named integer before a `const` byte pointer it counts
    (`X__unpack(allocator, size_t len, const uint8_t *data)`, `_len_ptr_params`) is bound the same way;
  - pointers to non-byte elements followed by their count (`const char *strings[], size_t count`;
    `const char *keys[], bool found[], size_t count`; `mpack_node_data_t *node_pool, size_t
    node_pool_count`; `_array_count`: the count's formal name says count, or length or size when no
    array points to a struct): each array gets ARRAY_ELEMENTS valid elements (an array of byte
    strings distinct NUL-terminated strings, other pointers NULL, scalars and structs zeroed with
    element 0 read from the input as one object would be), and the count, still read from the input,
    is mapped into 1..ARRAY_ELEMENTS (never 0: mpack asserts `count != 0`). A single object passed
    for such an array was read past for any count above 1 (mpack run-3, `mpack_expect_enum`);
  - a byte pointer with a size the call sites in the code base agree on (`param_sizes` in the model,
    step "call-site sizes"): a buffer of exactly that size (the largest), read from the input when it
    is an input (a `const` pointee), else zeroed. An input byte array whose call sites pass several
    sizes, with no length after it, is ended by a terminator (QCBOR's `QCBOR_TYPE_NONE`-terminated
    type lists): its last byte is set to 0 after the input fills it. An array of wider scalars of that
    shape is left as read (its sentinel value is not known) and the case's `notes` say so;
  - a byte pointer without a known size: a zeroed spare buffer (`2 * MAX_INPUT_SIZE + 1024` bytes), so
    an unknown contract does not read as a target bug; a `const char *` alone takes the rest of the
    input as a NUL-terminated string;
  - a pointer to a non-byte scalar without a known size or count (`_scalar_array`): ARRAY_ELEMENTS
    zeroed elements, element 0 read from the input as one object would be (libmodbus run-1:
    `modbus_get_float_abcd(const uint16_t *src)` reads `src[0]` and `src[1]`). A call that also takes a
    count or an index of such buffers (`_indexed_scalars`: named like a count, `nb` included, or
    `idx`/`index`/`offset`/`pos`) and no (buffer, length) pair gets spare buffers' worth of elements,
    and each count or index is kept within half of the smallest such buffer (`_index_rules`:
    `modbus_set_bits_from_bytes(dest, idx, nb_bits, tab_byte)`, `modbus_read_bits(ctx, addr, nb, dest)`);
  - a pointer to a struct the unit has an initializer for (a function of the unit, also from another
    cluster than the module's, named like `*_Init`, `*_init`, `*Init*`, `*_new`, `*_create` whose
    first parameter is a non-const pointer to that struct; never an error or `FILE *` one, else first
    one reading a (buffer, length) pair, see `initializers`): one object, initialized by that call
    before the call under test (its own arguments built by the same rules; the case's `inits` name
    it). An initializer or destructor from outside the module's scope is in the sidecar's
    `api_helpers` (`case_helpers`), which the reach gate counts as no root of the module. The
    initializer's own case does not call it first. After the call under test the object is released
    with the struct's destructor when the unit has one (a function of the unit named like a
    destructor whose one parameter is a non-const pointer to that struct, `struct_destructors`):
    `mpack_writer_init_growable` mallocs and `mpack_writer_init_filename` opens a file, and a case run
    millions of times must not keep either. The initializer's own case releases its object the same
    way; the destructor's own case does not release twice. The release reads no input: the layout
    does not change;
  - a byte-string parameter named like a file-system path (`filename`, `file_name`, `fname`, `path`,
    `pathname`, `filePath`, `dirname`; `path_parameter`): the function is skipped with the reason,
    and is never chosen as an initializer or constructor. A path read from the input makes the
    target open or create a file the fuzzer names, anywhere the sandbox user can write (the run
    directory included), on every execution;
  - an opaque handle (a typedef of `void *`, or a pointer to a struct the headers only declare, as
    the layout probe saw the parameter written): the result of the API's constructor for that type
    (a function named like an initializer that returns it), released after the call under test with
    the API's destructor (a function of that one parameter named like `*_release`, `*_free`,
    `*_destroy`); a call under test that returns a handle has its result released the same way. A
    zeroed byte buffer is no such object: it is not aligned for the struct behind
    the handle and fails the target's own validity checks. Built only when the call takes one handle
    of the type and both functions are known; otherwise, and without a probe, the parameter is a
    byte pointer as below and the case's `notes` say why. When no constructor returns the handle, an
    out-parameter constructor builds it (`outparam_constructors`: `ares_dns_record_create(H **, ...)`
    writes `H *h = NULL` through `&h`; the call runs only on a non-NULL `h`), and a child handle with
    no destructor is added to a parent built first, which is released after the call
    (`ares_dns_record_rr_add(ares_dns_rr_t **, ares_dns_record_t *, ...)`). A pointer to a struct the
    headers only declare is never declared as an object (it would not compile): with no constructor,
    no destructor, or two such handles in one call the function is skipped with the reason;
  - a pointer to another scalar or struct: one object (an output, or read from the input when `const`
    and the struct has no pointers; zeroed otherwise). A pointer to an anonymous enum (the model's
    `enum __anonenum_ares_dns_class_t_7 *` for c-ares's `typedef enum { ... } ares_dns_class_t`)
    declares its object through the header's typedef, as the layout probe saw the parameter written
    (`enum_pointer_spellings`); with no typedef name the function is skipped. A pointer to an
    anonymous struct or union (the model's `struct __anonstruct_ngx_str_t_13 *` for nginx's
    `typedef struct { size_t len; u_char *data; } ngx_str_t`) declares and casts its object through
    the header's typedef (`anon_record_tags`, from the parameters the layout probe saw written
    through it) and is laid out, initialized, filled and released as a named struct of its shape;
    with no typedef name (a struct declared in a parameter list) the function is skipped, and so is a
    typedef the harness's headers do not declare. A length field before a byte pointer (`{len,
    data}`) is paired with it as a (pointer, length) pair is; one before a pointer to wider elements
    (GMP's `{_mp_alloc, _mp_size, _mp_d}`) stays 0. A pointer to a qualified pointer (c-ares's
    `const char **name`, which the model spells `char **`) is cast and its object declared as the
    header writes it (`qualified_pointer_spellings`: `const char *c0a2[1]`, `(const char **)c0a2`),
    so the call keeps the nested `const` the compiler checks;
  - a function pointer: a callback stub of its prototype (`callback_stub`, defined after the headers:
    it writes nothing and returns the zero value of its type), when the layout probe spelled the
    prototype from the headers' own typedefs (`callback_prototypes`); else NULL. Either way the case's
    `notes` say which. A function pointer inside a struct stays NULL, except in a table of them;
  - a pointer to a table of function pointers (rule G, `_vtable_layout`: function pointers make at
    least half of its fields, as protobuf-c's `ProtobufCAllocator` and `ProtobufCBuffer`): NULL when a
    doc comment of the headers says NULL selects a default for that type (`null_default_records`),
    else an object of harness functions (`_table_stub`: malloc/calloc/realloc/free wrappers in an
    allocator, no-op stubs otherwise), else the function is skipped with the reason. Never zeroed:
    the callee calls through it. A destructor named for freeing that also takes such tables
    (`struct_owners`: `X__free_unpacked(X *, ProtobufCAllocator *)`) gets only what its producer
    returned in the same case (`struct_producers`: `X *m = X__unpack(...)`, the call under test run
    when `m` is not NULL), and is skipped when no function of the unit produces one; the producer's
    own case frees its result with it;
  - argument domains (mpack run-4, `_domain_rules`, `_realloc_like`, `_owned_result`): a value read
    from the input that breaks a documented precondition is normalized after the read, and only
    then, so slots and seeds do not move: (min, max) bounds ordered, and a lone bound an inline
    wrapper forwards to such a range with a literal other bound kept past it (A, `bound_forwards`); a NUL-terminated output's
    capacity and a limit setter's `max_*` at least 1 (B); an initializer's (buffer, size, count)
    count at most the size (C); an enum by value one of its declared constants (D, from the probe);
    a realloc-like call given a harness malloc (E); a heap result or `char **` output the caller
    owns freed (F); tables of function pointers and the objects their destructors free (G, above).
    Each restriction is in the case's `notes`.

Recorded call sequences (seed_harvest.py traces) add sequence cases: the calls of one traced chain in
order, the buffers they share passed between them, so a later call sees what an earlier one produced
(a key pair before the box that uses it). A handle type with a constructor and a destructor gets one
synthesized lifecycle case (`lifecycle_case`; a recorded chain passes a shared handle as a zeroed
buffer, so it does not stand in for one): build the
handle, make up to LIFECYCLE_MAX_CALLS calls on it, each chosen by an input byte among the functions
taking it, then release it, so use after free, double free and call after error stay reachable. Both
kinds share the MAX_SEQUENCE_CASES cap, recorded chains first.

A variadic function (a signature ending in `...`, or a last formal named `__va_params`) has no
signature for the arguments after the fixed ones. It is called the way the target's own programs
call it (`variadic_case`; the call sites come from scripts/variadic_calls.py, which reads the tests
and examples with clang): one case, kind `variadic`, per distinct (format, objects) of its call
sites with a literal format, at most MAX_VARIADIC_CASES per function, after the single cases. The
format (the last fixed parameter, `const char *`) is that call site's literal, never input bytes;
each argument after it is a zeroed object of exactly the call site's type and size, on the stack
(`char value[80]` passed by name, `struct minmea_float` passed by address), so a write past it is
caught at its real size; the other fixed parameters follow the rules above, and the first `const`
byte pointer among them takes the rest of the input as a NUL-terminated string. A call site whose
case is left out (over the cap, a type the harness cannot name, a case the compiler refuses) goes to
the sidecar's `api_variadic_dropped` with the reason.

Hand-written cases (`--api --dispatch-case '<stmts>'`, for a function the generator skipped) come last,
in the same switch: their layout is `{kind: custom, calls: [], slots: [], rest: null}`, so the seed
writers make nothing for them, and a later `--api` run without the flag keeps them.

The layout of every case (which input bytes feed which argument) goes to the sidecar as `api_cases`,
which seed_harvest.py write reads to turn recorded calls (and, for a `variadic` case, the literal
data of its call sites) into seeds for each case. Functions the generator cannot call (static, a
variadic function with no usable call site, an anonymous struct by value, a pointer to an
anonymous struct, union or enum the headers name no typedef for, a case the compiler
refuses, with the compiler's first error) go to `api_skipped` with the reason, and the reach gate
reports an entry point the harness does not call directly as a gap. A variadic function leaves
`api_skipped` once one of its cases is in the harness.
"""

from __future__ import annotations

import copy
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from framac_common import load_json_optional  # noqa: E402
from generate_harness import DISPATCH_MAX_CASES_WIDE  # noqa: E402
from seed_harvest import (  # noqa: E402
    _CHAR_POINTEES,
    _LEN_NAME_RE,
    _QUALIFIERS_RE,
    _norm_type,
    classify_type,
    is_length,
    is_length_ptr,
    is_variadic,
    split_signature,
)

MODEL_JSON = Path("workspace/reports/phase0_model.json")
TRACES_JSONL = Path("workspace/seed_records/traces.jsonl")
MAX_SEQUENCE_CASES = 16  # recorded chains first, then synthesized lifecycle cases (H2)
GLOBAL_SETUP_MAX_PREFIX = 12  # max global-state setup calls prepended to one recorded sequence case
_GLOBAL_ADDITIVE_WORDS = frozenset({"add", "register", "append", "insert", "push", "put"})
_GLOBAL_SETUP_WORDS = frozenset(
    {
        "init",
        "initialize",
        "initialise",
        "config",
        "configure",
        "setup",
        "register",
        "set",
        "add",
        "enable",
        "start",
        "open",
        "create",
        "new",
    }
)
_GLOBAL_INIT_WORDS = frozenset({"init", "initialize", "initialise", "setup"})
_GLOBAL_TEARDOWN_WORDS = frozenset(
    {
        "shutdown",
        "cleanup",
        "deinit",
        "uninit",
        "fini",
        "finalize",
        "finalise",
        "destroy",
        "free",
        "teardown",
        "reset",
        "close",
        "stop",
        "release",
    }
)
# Words on a non-`const` byte buffer or its paired length parameter that positively indicate an
# input / in-out buffer (e.g. `p_ingest`, `len_ingest`, `in_buf`, `src`), vs unambiguous output words
# (`out`, `dst`, `reply`, `result`) that must stay zeroed unless explicitly marked by a threat model.
_IN_BUF_WORDS = frozenset({"in", "input", "inbuf", "ingest", "src", "source"})
_OUT_BUF_WORDS = frozenset({"out", "output", "dst", "dest", "destination", "result", "reply", "resp", "response"})
# Upper bound of positive values for narrow length types when clamping `rest_n` into a length scalar.
_SCALAR_MAX_POS: dict[str, int] = {
    "signed char": 127,
    "unsigned char": 255,
    "short": 32767,
    "unsigned short": 65535,
}
# Functions that query heap allocation metadata on a caller-supplied buffer (`Crypto_check_buffer_size`
# calling `malloc_usable_size(pTfBuffer)`): passing a static or stack array triggers ASan
# `bad-malloc_usable_size` and glibc UB, so writable byte buffers for callers reaching these use `calloc`+`free`.
_HEAP_SIZE_PROBERS = frozenset({"malloc_usable_size", "malloc_size", "_msize"})
LIFECYCLE_MAX_CALLS = 8  # calls on the handle per run of a lifecycle case, each picked by one input byte
MAX_VARIADIC_CASES = 32  # per variadic function: one case per harvested (format, objects)
# Two selector bytes above 256 cases (generate_harness.DISPATCH_SELECTOR_IDENTITY16, D7).
MAX_CASES = DISPATCH_MAX_CASES_WIDE - 1
# One input byte picks a lifecycle case's method (`fc_op % <n>U`): more methods would never be called.
LIFECYCLE_MAX_METHODS = 255
VARIADIC_KIND = "variadic"  # the layout kind of a case built from a call site (scripts/variadic_calls.py)
NO_VARIADIC_SITE = "variadic: no call site with a literal format and sized objects in the target's own sources"
CUSTOM_KIND = "custom"  # the layout kind of a hand-written case (`--api --dispatch-case`)
PAIR_BYTES = 256  # an input (pointer, length) field pair that does not get the rest of the input
# A pointer to non-byte elements followed by their count (`mpack_expect_enum(reader, const char
# *strings[], size_t count)`): an array of ARRAY_ELEMENTS elements, the count mapped into
# 1..ARRAY_ELEMENTS. Never 0: `mpack_expect_enum_optional` asserts `count != 0`, which a release build
# turns into `__builtin_unreachable()`, a crash only the harness would make.
ARRAY_ELEMENTS = 4
# The elements of an array of byte strings: distinct, NUL-terminated, the empty string included.
ARRAY_STRINGS = ("", "a", "bc", "def")
ARRAY_STRING_BYTES = 16  # the storage of each element of an array of `const` strings
# An input string of no known size whose call may not take the rest of the input (a constructor
# that builds a handle: libmodbus's `modbus_new_tcp(const char *ip, int port)`): a slot of this many
# input bytes, its last byte 0. Small, since the slot is read whole or not at all; room for a dotted
# IPv4 address or `/dev/ttyUSB0` and its NUL.
STRING_SLOT_BYTES = 16
# Under FRAMAC_API_TRUST_SCHEMA, a trusted NUL-terminated string (`const char *szLabel` the threat
# model does not list as attacker data; QCBOR run-1's map labels) is bound to a fixed literal, a value
# the application could pass: the one the target's tests pass most often (recorded seed traces), else
# this one. Recorded strings longer than TRUSTED_STRING_MAX_BYTES, empty or not printable ASCII are
# never taken.
TRUSTED_STRING_DEFAULT = "a"
TRUSTED_STRING_MAX_BYTES = 64
MAX_RECORDED_SCALARS = 8  # values a trusted scalar of a sequence case keeps, of those the tests passed
# The formal name of an element count: `count`, `cnt`, `n`, `nItems`, `num_pts`, `nmemb`, `nelem`,
# and `nb` as a word (libmodbus's `nb`, `nb_bits`, `write_nb`, `read_nb`).
_ARRAY_COUNT_RE = re.compile(
    r"[Cc]ount|[Cc]nt|^n(?:[A-Z_0-9]|$)|^num|^N$|[Nn]memb|[Nn]elem|[Nn]items|(?:^|_)nb(?:[A-Z_0-9]|$)"
)
# The formal name of an index into a buffer: libmodbus's `modbus_set_bits_from_bytes(dest, idx, ...)`.
_INDEX_WORDS = frozenset({"idx", "index", "offset", "pos", "position"})
# `len` and `size` count elements too, except after a struct pointer: `(struct ctx *c, size_t size)`
# is far more often a context and some size than an array of contexts.
_ARRAY_LEN_RE = re.compile(r"[Ll]en|[Ss]ize")
MAX_DIAGNOSTIC_CHARS = 300
POINTER_BYTES = 8  # x86_64, as SCALAR_BYTES
# The source of a copy the harness makes itself: the input, or in eva_main an initialized shadow of it
# (templates/harness_dual.c.template defines the macro for both entries).
FUZZ_COPY = "FRAMAC_FUZZ_COPY(fuzz_buf, fuzz_off)"
# Initializer names: QCBORDecode_Init, UsefulOutBuf_Init, ctx_init, foo_new, bar_create, and
# `<lib>_new_<kind>` (libmodbus's modbus_new_tcp, modbus_new_rtu): `new`/`create` as a whole word.
_INIT_NAME_RE = re.compile(r"(?:^|(?<=[a-z0-9_]))Init(?=[A-Z0-9_]|$)|(?:^|_)(?:init|new|create)(?:$|_)")
# Out-parameter constructor names (`H **` written by the call): the initializer names, and parsers and
# adders (c-ares's ares_dns_record_create, ares_init, ares_dns_parse, ares_dns_record_rr_add).
_OUT_CTOR_NAME_RE = re.compile(rf"{_INIT_NAME_RE.pattern}|(?:^|_)(?:create|new|alloc|parse|add)(?:$|_)")
MAX_HANDLE_DEPTH = 3  # parents built for a child handle (a record set needs its record)
# Destructor names: seccomp_release, foo_free, bar_destroy, ctx_close, FooFree.
_DTOR_NAME_RE = re.compile(
    r"(?:^|_)(?:release|free|destroy|delete|close|cleanup|deinit|fini|unref)(?:$|_)|"
    r"(?:^|(?<=[a-z0-9_]))(?:Free|Destroy|Release)(?=[A-Z0-9_]|$)"
)
# Destructor names that release memory, chosen over the others (`close`, `cleanup`, `deinit`, `fini`):
# libmodbus's `modbus_close` only closes the socket, `modbus_free` frees the context (run-1 leaked
# one context per execution while `modbus_close` was the destructor).
_FREEING_DTOR_RE = re.compile(
    r"(?:^|_)(?:release|free|destroy|delete|unref)(?:$|_)|"
    r"(?:^|(?<=[a-z0-9_]))(?:Free|Destroy|Release)(?=[A-Z0-9_]|$)"
)
# A destructor-named function that closes the handle (`modbus_close`): run before the freeing one.
_CLOSE_DTOR_RE = re.compile(r"(?:^|_)close(?:$|_)|(?:^|(?<=[a-z0-9_]))Close(?=[A-Z0-9_]|$)")
# File-system path parameter names, as words of the formal's name (`filename`, `file_name`, `filePath`).
_PATH_WORDS = frozenset({"filename", "fname", "path", "pathname", "filepath", "dirname", "dirpath"})
_PATH_WORD_PAIRS = frozenset({("file", "name"), ("file", "path"), ("dir", "name"), ("dir", "path"), ("path", "name")})
_NAME_WORD_RE = re.compile(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])")
PATH_SKIP_REASON = (
    "takes a file-system path (parameter `{name}`): the harness never passes input bytes as a path, "
    "which would open or create a file the fuzzer names on every execution"
)

# --- argument domains (mpack run-4) ------------------------------------------------------------------
# Each rule below normalizes an argument after it is read from the input, and only when the value is
# outside the domain the API documents: a value inside it is passed as read, so recorded seeds keep
# their meaning and no slot moves. A rule never widens what reaches the call; each one is a documented
# precondition whose violation the Crash Verifier rejects as `harness_induced`, never a library bug.
#
# A. The bounds of a range (`min_value`/`max_value`, `lo`/`hi`, `low`/`high`, `lower`/`upper`,
#    `minimum`/`maximum`: the same name but for that one word, the same scalar type) are ordered, and a
#    NaN bound of a floating range replaced (MPack: `mpack_assert(min_value <= max_value)`).
#    A lone bound whose function forwards it to such a range with a literal other bound (an inline
#    function of the headers, read from the probe's AST: `bound_forwards`) is kept on its side of
#    that literal (mpack run-4: `mpack_expect_i8_max(reader, -1)` reached the same assert).
_RANGE_WORDS = frozenset({("min", "max"), ("lo", "hi"), ("low", "high"), ("lower", "upper"), ("minimum", "maximum")})
# B. The capacity of a writable NUL-terminated output (a byte pair of a function named with the word
#    `cstr`) is at least 1: room for the terminator (`mpack_node_copy_cstr`: "you must have room for
#    at least a null-terminator"; `mpack_node_copy_data` takes 0 and is left alone). A `max_*` limit
#    of a limit setter (`mpack_tree_set_limits`), or forwarded under the same formal name to one by a
#    function that calls it (`mpack_tree_init_stream`), is at least 1 too (MPack asserts
#    `max_message_size > 0`, `max_message_nodes > 0`; `limit_parameters`). A `max_*` of any other
#    function is left alone: `mpack_tree_init_stdfile(tree, file, max_bytes, ...)` reads 0 as
#    "unlimited size".
_CSTR_WORDS = frozenset({"cstr"})
_LIMIT_SETTER_RE = re.compile(r"(?:^|_)set_limits?$|[a-z0-9]SetLimits?$")
# C. In a (buffer, size, count) triple an initializer records, the count of bytes already in the
#    buffer is at most its size (`mpack_reader_init(reader, buffer, size, count)`: "count: the number
#    of bytes already in the buffer"). The size's name says size or capacity, the count's says count,
#    used, fill or length. Only an initializer: it stores the triple and cannot reject it, while an
#    operation given a byte count larger than its buffer must check it (`mpack_read_cstr` flags
#    `mpack_error_too_big`), which is a check the fuzzer is there to exercise.
_TRIPLE_SIZE_WORDS = frozenset({"size", "cap", "capacity", "bufsize"})
_TRIPLE_COUNT_WORDS = frozenset({"count", "used", "fill", "filled", "len", "length", "avail"})
# E. A realloc-like function (named `*_realloc`/`*Realloc`, first parameter a writable `void *`, the
#    rest sizes, reaching an allocator) gets a pointer the harness allocated (REALLOC_OLD_BYTES), never
#    a static buffer (ASan: "attempting free on address which was not malloc-ed"). The used size stays
#    within that allocation and the new size; the new size is in 1..spare: 0 frees the old pointer
#    (C23 makes `realloc(p, 0)` undefined), and a size above libFuzzer's malloc limit is an OOM report
#    the harness made. The result is freed, or the old pointer when the call failed.
_REALLOC_NAME_RE = re.compile(r"(?:^|_)realloc$|[a-z0-9]Realloc$")
_REALLOC_USED_WORDS = frozenset({"used", "old", "cur", "current"})
REALLOC_OLD_BYTES = 64
# F. A result the caller owns is freed after the call: a pointer returned by a function named with
#    the word `alloc` or `dup` (`mpack_expect_cstr_alloc`, `mpack_read_bytes_alloc_impl`, `*_strdup`)
#    that reaches an allocator (`ALLOCATORS`, through the model's call sites) and whose header does
#    not return a `const` pointee (the model drops that `const`: `mpack_type_to_string` is `char *`
#    there). The same goes for a writable `char **`/`void **` output of such a function, or of one
#    named `*growable*` (`mpack_writer_init_growable`'s `*target_data`), freed after the object's
#    destructor. A pool or arena slot named `*_alloc` reaches no allocator and is never freed.
_OWNED_RESULT_WORDS = frozenset({"alloc", "dup", "strdup", "strndup"})
_OWNED_OUT_WORDS = _OWNED_RESULT_WORDS | {"growable", "copy", "clone"}
_OWNED_PRODUCER_WORDS = frozenset(
    {
        "prepare",
        "make",
        "build",
        "create",
        "new",
        "copy",
        "clone",
        "encode",
        "decode",
        "format",
        "serialize",
        "pack",
        "unpack",
        "render",
        "generate",
        "concat",
        "join",
    }
)
_BORROWED_OUT_WORDS = frozenset({"get", "peek", "find", "lookup", "search", "query", "view", "slice", "borrow", "ref"})
_CURSOR_OUT_WORDS = frozenset(
    {"end", "endptr", "next", "cur", "cursor", "pos", "tail", "rest", "err", "error", "msg", "errmsg"}
)
_OWNED_BYTE_RET_TYPES = frozenset({"char *", "unsigned char *", "signed char *", "void *"})
ALLOCATORS = frozenset({"malloc", "calloc", "realloc", "reallocarray", "strdup", "strndup", "aligned_alloc"})
# G (sudo run-1, protobuf-c's `liblogsrv_a`). A table of function pointers (`_vtable_layout`: an
#    allocator `{alloc, free, allocator_data}`, an ops table, a sink `{append}`) is never passed zeroed:
#    the callee calls through it (`do_alloc` called a NULL `alloc`). NULL when a doc comment of the
#    headers says a NULL pointer of that type selects a default (`null_default_records`: protobuf-c's
#    "May be NULL to specify the default allocator"), else an object whose function pointers are
#    harness functions (`_table_stub`: malloc/calloc/realloc/free wrappers in an allocator, no-op
#    stubs otherwise), else the case is skipped. A destructor named for freeing that also takes such
#    tables (`X__free_unpacked(X *, ProtobufCAllocator *)`, `struct_owners`) frees what its producer
#    returned (`struct_producers`: `X__unpack`), never a stack object: its case calls the producer
#    first and frees the result only when it is not NULL; the producer's own case frees its result.
_PRODUCER_NAME_RE = re.compile(
    rf"{_OUT_CTOR_NAME_RE.pattern}|(?:^|_)(?:unpack|decode|deserialize|dup|clone|copy|load|from)(?:$|_)"
)
_TABLE_ALLOC_WORDS = frozenset({"alloc", "malloc", "allocate"})
_TABLE_CALLOC_WORDS = frozenset({"calloc"})
_TABLE_REALLOC_WORDS = frozenset({"realloc", "reallocate"})
_TABLE_FREE_WORDS = frozenset({"free", "dealloc", "deallocate"})
_NULL_WORD_RE = re.compile(r"\bNULL\b")
# "must not be NULL", "cannot be NULL", "never NULL", "non-NULL": the opposite of a NULL default.
_NOT_NULL_RE = re.compile(r"\b(?:not|never|cannot|can't|mustn't|non)\b[\s-]+(?:be\s+)?(?:a\s+)?NULL\b", re.IGNORECASE)
_DEFAULT_WORD_RE = re.compile(r"\b(?:default|system|standard|built-?in)\b", re.IGNORECASE)

# --- P2A schema/trust-driven API harness (FRAMAC_API_TRUST_SCHEMA, default on) -----------------------
API_TRUST_SCHEMA_ENV = "FRAMAC_API_TRUST_SCHEMA"
_OFF_VALUES = frozenset({"off", "0", "false", "no"})
MAX_SCHEMA_INSTANCES = 4
NO_ATTACKER_DATA_REASON = "no attacker data per the threat model"
TRUSTED_PARAM_NO_INSTANCE_FMT = "trusted parameter {name} has no instance"
CALLER_STORAGE_NOTE = "trusted caller-storage buffer: backed by fixed harness array"
REFCOUNT_EXEMPT_REASON = "refcount helper requires producer-allocated object"
STATIC_NOT_CALLABLE_REASON = "static: not callable from the harness"
_NULLABLE_ALLOCATOR_NAMES = frozenset({"allocator", "alloc", "mem_alloc"})
# S2 widened builder names (by-value builders like `pb_istream_from_buffer`, schema-taking builders like
# `pb_field_iter_begin`, `mbedtls_cipher_setup`, `foo_make_*`).
_BY_VAL_BUILDER_NAME_RE = re.compile(
    rf"{_INIT_NAME_RE.pattern}|(?:^|_)(?:from|make|begin)(?:$|_)|(?:^|(?<=[a-z0-9_]))(?:From|Make|Begin)(?=[A-Z0-9_]|$)"
)
_SCHEMA_INIT_NAME_RE = re.compile(
    rf"{_INIT_NAME_RE.pattern}|(?:^|_)(?:begin|setup|make|from)(?:$|_)|"
    r"(?:^|(?<=[a-z0-9_]))(?:Begin|Setup|Make|From)(?=[A-Z0-9_]|$)"
)
# Refcount helpers (`sudo_rcstr_addref`, `sudo_rcstr_delref`, `foo_unref`, `bar_decref`): their parameter
# carries a producer-allocated header (often via `container_of`), never a stack object or plain byte buffer.
_REFCOUNT_NAME_RE = re.compile(
    r"(?:^|_)(?:addref|delref|unref|decref)(?:$|_)|(?:^|(?<=[a-z0-9_]))(?:AddRef|DelRef|Unref|DecRef)(?=[A-Z0-9_]|$)"
)
_CTOR_BOILERPLATE_WORDS = frozenset({"new", "init", "create", "alloc", "make", "open", "from"})


def api_trust_schema_enabled(env: Mapping[str, str] | None = None) -> bool:
    """Whether P2A schema/trust-driven `--api` upgrades are enabled (`FRAMAC_API_TRUST_SCHEMA`, default on)."""
    src = os.environ if env is None else env
    return (src.get(API_TRUST_SCHEMA_ENV) or "").strip().lower() not in _OFF_VALUES


def _words(name: str | None) -> list[str]:
    """The lowercase words of an identifier (`max_message_nodes`, `maxNodes`, `mpack_expect_cstr`)."""
    return [w.lower() for w in _NAME_WORD_RE.findall(name or "")]


# Byte size of the scalars a slot can hold (x86_64): a seed needs it to lay out the input.
SCALAR_BYTES = {
    "_Bool": 1,
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "short": 2,
    "unsigned short": 2,
    "int": 4,
    "unsigned int": 4,
    "long": 8,
    "unsigned long": 8,
    "long long": 8,
    "unsigned long long": 8,
    "float": 4,
    "double": 8,
    "long double": 16,
}


class ApiHarnessError(ValueError):
    pass


class _CaseError(Exception):
    """A case the generator cannot build: it is skipped with the exception's text as the reason."""


class _DeclError(_CaseError):
    """A case would declare a variable twice, or under a name that is not an identifier: the case is skipped."""


class _Unbuildable(_CaseError):
    """
    A case needs an object the generator cannot make: an opaque handle (a pointer to a struct the headers
    only declare) with no constructor or destructor known. A stack object of that struct would not compile.
    """


class _AutoExempt(_CaseError):
    """
    A case skipped under `FRAMAC_API_TRUST_SCHEMA` with an automatic reach-gate exemption reason
    (trusted parameter without a schema instance, or refcount helper without a producer).
    """


_IDENT_RE = re.compile(r"[A-Za-z_]\w*")


def spare_bytes(max_input_size: int) -> int:
    """The size of a buffer whose contract the model does not give: room for any length the input holds."""
    return 2 * max_input_size + 1024


def param_size(rec: dict, index: int) -> int | None:
    """The byte size the call sites agree a pointer parameter points to (largest seen), if the model has one."""
    sizes = (rec.get("param_sizes") or {}).get(str(index))
    if isinstance(sizes, dict):
        try:
            n = int(sizes.get("max") or 0)
        except (TypeError, ValueError):
            return None
        return n if n > 0 else None
    return None


def _sentinel_sized(rec: dict, index: int) -> bool:
    """
    Whether a pointer parameter's call sites pass arrays of different sizes (`param_sizes` min < max).
    The generator calls this only for a pointer with no length parameter after it, so the callee can
    only find the end by a terminator. A buffer every call site passes at one size (a key, a digest)
    is not one.
    """
    sizes = (rec.get("param_sizes") or {}).get(str(index))
    if not isinstance(sizes, dict):
        return False
    try:
        lo, hi = int(sizes.get("min") or 0), int(sizes.get("max") or 0)
    except (TypeError, ValueError):
        return False
    return 0 < lo < hi


def _sizes_text(rec: dict, index: int) -> str:
    sizes = (rec.get("param_sizes") or {}).get(str(index)) or {}
    return f"{sizes.get('min')}..{sizes.get('max')}"


def _storage(size: int | None) -> str:
    """
    Spare buffers (no known size) are `static`, zeroed on every call: a case may hold several and a
    harness many cases. A buffer of a known size stays on the stack, where an overflow is caught exactly.
    """
    return "" if size else "static "


# The alignment of every byte buffer a case declares: `alignof(max_align_t)` on x86_64, the
# strictest of any object Frama-C accepts (its machdep refuses `_Alignas(32)`: "exceeds
# alignof(max_align_t): 16, and machdep does not allow extended alignment"). Spelled as a number:
# `max_align_t` is missing from C99 headers, and E-ACSL builds compile with -std=c99. A buffer backs
# typed objects (`node.data = (void *)c0a0f0`, a struct shared by a sequence): a plain
# `unsigned char[]` left `\aligned(node.data, 8)` Unknown for Eva (mpack run-3). `_Alignas` is what
# Eva reads; it does not use a trailing `__attribute__((aligned(16)))` on such an array.
BYTE_BUFFER_ALIGN = 16


def _byte_buffer(storage: str, var: str, n: int | str) -> str:
    """The zeroed declaration of byte buffer `var[n]`, aligned for any object (`BYTE_BUFFER_ALIGN`)."""
    return f"{storage}_Alignas({BYTE_BUFFER_ALIGN}) unsigned char {var}[{n}]; memset({var}, 0, sizeof({var}));"


def _is_input(formals: list[dict], index: int) -> bool:
    """A pointer the function only reads (`const` pointee), per the model; unknown counts as input."""
    if index < len(formals) and isinstance(formals[index], dict):
        return formals[index].get("kind") != "pointer"
    return True


@dataclass
class ApiInfo:
    """
    What the generator knows of the module's API beyond each signature: the layouts of the structs the
    target's headers define (`probe_layouts`; `probed` says whether a probe ran), and per struct type
    (`struct tag`) the initializer to call on a pointer to it and every initializer candidate.
    """

    structs: dict[str, dict] = field(default_factory=dict)
    pointer_free_records: set[str] = field(default_factory=set)
    probed: bool = False
    inits: dict[str, str] = field(default_factory=dict)
    candidates: dict[str, set[str]] = field(default_factory=dict)
    records: dict[str, dict] = field(default_factory=dict)
    # Opaque handles (`handle_functions`): per function, parameter index -> handle type; per handle
    # type, its constructor, its destructor and every function named like a destructor of it.
    handles: dict[str, dict[int, str]] = field(default_factory=dict)
    ctors: dict[str, str] = field(default_factory=dict)
    dtors: dict[str, str] = field(default_factory=dict)
    dtor_names: dict[str, set[str]] = field(default_factory=dict)
    # Per handle type whose destructor frees it, the destructor-named `close` that runs first
    # (`handle_closers`: libmodbus's `modbus_close(ctx); modbus_free(ctx);`).
    closers: dict[str, str] = field(default_factory=dict)
    returns: dict[str, str] = field(default_factory=dict)  # function -> the handle type it returns
    # Out-parameter handles (`outparam_constructors`): per function, parameter index -> the handle type
    # it writes through `H **`; per handle type, the out-parameter constructor chosen (when no
    # constructor returns it) with its out index, every candidate, and the parent handle the chosen
    # one takes (parameter index, type): a child handle the parent owns.
    outs: dict[str, dict[int, str]] = field(default_factory=dict)
    out_ctors: dict[str, tuple[str, int]] = field(default_factory=dict)
    out_ctor_names: dict[str, set[str]] = field(default_factory=dict)
    parents: dict[str, tuple[int, str]] = field(default_factory=dict)
    # Function-pointer parameters whose prototype the layout probe spelled (`callback_prototypes`), and
    # the callback stubs the cases use (stub name -> its file-scope definition, `callback_stub`).
    callbacks: dict[str, dict[int, dict[str, Any]]] = field(default_factory=dict)
    stubs: dict[str, str] = field(default_factory=dict)
    # Pointers to an enum the headers name by a typedef (`enum_pointer_spellings`): per function,
    # parameter index -> {type, pointee} as the declaration writes them (`cls_t *`, `cls_t`). A pointer
    # to an anonymous enum (`enum __anonenum_cls_t_7 *` in the model) is spelled only through these.
    enum_ptrs: dict[str, dict[int, dict[str, str]]] = field(default_factory=dict)
    # Pointers to a qualified pointer (`qualified_pointer_spellings`): per function, parameter index ->
    # {type, pointee} as the declaration writes them (`const char **`, `const char *`). The model drops
    # the nested `const` (`char **`), which a compiler refuses to pass (gcc 14) or warns about (clang).
    qual_ptrs: dict[str, dict[int, dict[str, str]]] = field(default_factory=dict)
    # Anonymous structs and unions a header names by a typedef (`anon_record_tags`): the model's tag
    # -> the typedef name (`struct __anonstruct_ngx_str_t_13` -> `ngx_str_t`). An object of such a
    # type is declared, cast and sized only through these; `structs` holds its layout under both.
    anon_tags: dict[str, str] = field(default_factory=dict)
    # Struct objects (`struct_destructors`): per struct type, the destructor that releases what an
    # initializer set up in it, and every function named like a destructor of it.
    struct_dtors: dict[str, str] = field(default_factory=dict)
    struct_dtor_names: dict[str, set[str]] = field(default_factory=dict)
    # Per struct type, the destructor that frees an object a constructor returned (`struct_freers`:
    # libmodbus's `modbus_mapping_free` for `modbus_mapping_new*`).
    struct_freers: dict[str, str] = field(default_factory=dict)
    # Argument domains (`_domain_rules`): per function, enum parameter index -> the enum's declared
    # constants (`param_enums`); the functions whose header returns a `const` pointee
    # (`const_returns`); the functions that reach an allocator through the model's call sites
    # (`allocating_functions`); per function, the formal names of its limits (`limit_parameters`).
    enum_params: dict[str, dict[int, list[str]]] = field(default_factory=dict)
    const_returns: set[str] = field(default_factory=set)
    allocating: set[str] = field(default_factory=set)
    limits: dict[str, set[str]] = field(default_factory=dict)
    # Per struct type, notes explaining cross-cluster initializers skipped for exceeding cluster limits.
    init_skip_notes: dict[str, list[str]] = field(default_factory=dict)
    # Per function, parameter index -> (">=" or "<=", constant) of a lone range bound (`bound_forwards`).
    bounds: dict[str, dict[int, tuple[str, str]]] = field(default_factory=dict)
    # Rule G: the struct types a doc comment documents as NULL for a default (`null_default_records`);
    # whether a table of function pointers may get harness functions (False after a stub failed to
    # compile, as for callback parameters); per struct type, its destructor that also takes tables
    # (`struct_owners`: the chosen one, every one, and the table types they take) and its producers,
    # best first (`struct_producers`).
    null_defaults: set[str] = field(default_factory=set)
    table_stubs: bool = True
    owners: dict[str, str] = field(default_factory=dict)
    owner_names: dict[str, set[str]] = field(default_factory=dict)
    owner_tables: dict[str, set[str]] = field(default_factory=dict)
    producers: dict[str, list[str]] = field(default_factory=dict)
    # P2A (FRAMAC_API_TRUST_SCHEMA): gated schema/trust/builder/hygiene metadata.
    trust_schema: bool = False
    ctor_cands: dict[str, list[str]] = field(default_factory=dict)
    byval_inits: set[str] = field(default_factory=set)
    schema_inits: dict[str, tuple[int, str]] = field(default_factory=dict)
    schema_globals: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    schema_externs: dict[str, str] = field(default_factory=dict)
    # Per function, per argument index: the string the recorded traces pass most often there
    # (`recorded_strings`), the literal of a trusted string parameter (`_trusted_string_arg`).
    trusted_strings: dict[str, dict[int, str]] = field(default_factory=dict)
    # Per function, per argument index: the integers the recorded traces pass there, (byte width,
    # unsigned value), most frequent first (`recorded_scalars`): what a trusted scalar takes in a
    # sequence case.
    trusted_scalars: dict[str, dict[int, list[tuple[int, int]]]] = field(default_factory=dict)
    # Per function: argument indices where recorded seed traces observed a non-empty, non-zero byte
    # buffer (`b` record) on entry (`recorded_input_buffers`), evidencing that a non-`const` byte
    # pointer pair carries input data (including in-place read/write buffers).
    recorded_input_buffers: dict[str, set[int]] = field(default_factory=dict)
    # Functions that transitively call `_HEAP_SIZE_PROBERS` (`malloc_usable_size` etc.): their
    # writable byte buffers are heap-allocated (`calloc`/`free`) rather than `static` arrays.
    heap_buffer_fns: set[str] = field(default_factory=set)
    # Functions that transitively call `free` (used to give `*_free*(byte *)` helpers heap memory).
    freeing: set[str] = field(default_factory=set)
    # Per global-state setup function, the trace-observed 0-arg global teardown function (`Crypto_Shutdown`)
    # that releases its global allocations/state after a single case or teardown-less sequence.
    global_teardown: dict[str, str] = field(default_factory=dict)
    # Per function, canonical/raw record pointee types whose non-const pointer parameter may be
    # stored in a non-const global pointer that its global teardown frees (allocate with calloc)
    # vs retains without a freeing teardown (allocate static so it never dangles past return).
    global_freed_ptrs: dict[str, set[str]] = field(default_factory=dict)
    global_retained_ptrs: dict[str, set[str]] = field(default_factory=dict)
    # Functions whose global_variables type metadata is known, allowing safe single-case global
    # teardown even when the function takes non-const record pointer parameters.
    global_types_known: set[str] = field(default_factory=set)


class _Case:
    """One dispatch case under construction: its statements, input slots and the rest-of-input binding."""

    def __init__(self, spare: int, api: ApiInfo | None = None, calls: int = 1) -> None:
        self.spare = spare
        self.api = api or ApiInfo()
        self.ncalls = calls
        self.decls: list[str] = []
        self.post: list[str] = []
        self.slots: list[dict[str, Any]] = []
        self.rest: dict[str, Any] | None = None
        self.inits: list[dict[str, Any]] = []
        self.notes: list[str] = []
        self.declared: set[str] = set()
        # Frees of heap outputs of an initializer or constructor call (rule F), placed after the
        # releases of the call they were built for.
        self.owned_frees: list[str] = []
        self.schema_instance: str | None = None
        self.builder: str | None = None
        # A sequence case replays calls the target's tests made: a trusted scalar takes one of the
        # values they passed there (`ApiInfo.trusted_scalars`) instead of 0.
        self.recorded_scalars = False

    def declare(self, name: str) -> str:
        """
        `name`, recorded as a variable this case declares. Every declaration the generator emits goes
        through here: a name that is not a C identifier, or one the case already declared, would be a
        compile error blamed on the target's headers, so the case is refused instead (`_DeclError`).
        """
        if not _IDENT_RE.fullmatch(name):
            raise _DeclError(f"generator defect: variable name {name!r} is not a C identifier")
        if name in self.declared:
            raise _DeclError(f"generator defect: variable {name!r} would be declared twice in the case")
        self.declared.add(name)
        return name

    def slot(
        self, var: str, size: int | None, call: int, param: int, kind: str, addr: bool = True, **extra: Any
    ) -> None:
        ref = f"&{var}" if addr else var
        self.decls.append(
            f"if (fuzz_len >= fuzz_off + sizeof({var})) {{ memcpy({ref}, {FUZZ_COPY}, sizeof({var}));"
            f" fuzz_off += sizeof({var}); }}"
        )
        self.slots.append({"call": call, "param": param, "size": size, "kind": kind, **extra})

    def bool_slot(self, var: str, call: int, param: int, kind: str, **extra: Any) -> None:
        """
        A `_Bool` read from the input: only 0 and 1 are values of the type (any other byte is undefined
        behavior in the harness itself, which UBSan reports at the first load), so the byte's low bit.
        """
        self.slot(var, 1, call, param, kind, **extra)
        self.decls.append(f"{{ unsigned char fc_b; memcpy(&fc_b, &{var}, 1); {var} = (fc_b & 1U) != 0; }}")

    def note(self, call: int, param: int, why: str) -> None:
        self.notes.append(f"call {call} argument {param}: {why}")

    def layout(self, kind: str, calls: list[str]) -> dict[str, Any]:
        out: dict[str, Any] = {"kind": kind, "calls": calls, "slots": self.slots, "rest": self.rest}
        if self.inits:
            out["inits"] = self.inits
        if self.notes:
            out["notes"] = self.notes
        if self.schema_instance:
            out["schema_instance"] = self.schema_instance
        if self.builder:
            out["builder"] = self.builder
        return out

    def statements(self, calls: list[str]) -> str:
        body = ["size_t fuzz_off = 0;", *self.decls, *self.post, *calls, "(void)fuzz_off;"]
        return " ".join(body)


def _name(formals: list[dict], i: int) -> str | None:
    if i < len(formals) and isinstance(formals[i], dict) and isinstance(formals[i].get("name"), str):
        return formals[i]["name"]
    return None


def _charlike(p: dict) -> bool:
    return p.get("pointee") in _CHAR_POINTEES or p.get("pointee") == ""


def _is_pair(params: list[dict], i: int, formals: list[dict] | None = None) -> bool:
    """A byte pointer followed by a length (never an enum): a (buffer, length) pair."""
    p = params[i]
    nxt = params[i + 1] if i + 1 < len(params) else None
    return p["kind"] == "ptr" and _charlike(p) and nxt is not None and is_length(nxt, _name(formals or [], i + 1))


def _is_buf_len_ptr_pair(params: list[dict], i: int, formals: list[dict] | None = None) -> bool:
    """
    A byte pointer followed by a pointer to a length-named integer (`uint8_t *ingest, int *len_ingest`):
    a (buffer, length *) pair where the length is passed by pointer (often in-out).
    """
    p = params[i]
    nxt = params[i + 1] if i + 1 < len(params) else None
    return p["kind"] == "ptr" and _charlike(p) and nxt is not None and is_length_ptr(nxt, _name(formals or [], i + 1))


def _len_cap_expr(ctype: str, buf_expr: str) -> str:
    """Upper bound expression for `rest_n` so casting to `ctype` never truncates or overflows."""
    limit = _SCALAR_MAX_POS.get(ctype)
    if limit is None:
        return buf_expr
    return f"({buf_expr} < {limit}U ? {buf_expr} : {limit}U)"


def _rest_len_post(ln: str, ctype: str) -> str:
    """Statement setting `ln` to remaining input bytes, clamped to `ctype`'s positive range if narrow."""
    limit = _SCALAR_MAX_POS.get(ctype)
    clamp = f"if (rest_n > {limit}U) {{ rest_n = {limit}U; }} " if limit is not None else ""
    return f"{{ size_t rest_n = (fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U; {clamp}{ln} = ({ctype})rest_n; }}"


def _can_copy_sequence_rest(case: _Case, call: int) -> bool:
    """Whether an earlier call in this sequence already claimed `case.rest` as bytes."""
    return (
        isinstance(case.rest, dict)
        and case.rest is not _RESERVED_REST
        and case.rest.get("kind") == "bytes"
        and case.rest.get("call") != call
    )


def _bind_secondary_rest_buf(
    case: _Case,
    call: int,
    i: int,
    v: str,
    ln: str,
    ltype: str,
    *,
    heap_capacity: bool,
    guards: list[str],
    after: list[str],
) -> None:
    """
    Bind a subsequent call's unsized input buffer in a multi-call sequence by copying up to `ln`
    bytes of `case.rest` (before any earlier call can mutate `fuzz_buf`). Uses a spare-sized heap
    capacity buffer for `heap_buffer_fns`, or an exact-size `malloc` allocation (one-past-end for
    0 bytes) otherwise so ASan and E-ACSL enforce exact right-hand bounds.
    """
    limit = _SCALAR_MAX_POS.get(ltype)
    case.decls.append(f"{ltype} {case.declare(ln)}; memset(&{ln}, 0, sizeof({ln}));")
    case.slot(ln, SCALAR_BYTES.get(ltype), call, i + 1, "int")
    if heap_capacity:
        buf = case.spare
        case.decls.append(f"unsigned char *{case.declare(v)} = (unsigned char *)calloc(1, {buf}U);")
        guards.append(f"{v} != 0")
        after.append(f"free({v});")
        cap = _len_cap_expr(ltype, f"{buf}U")
        case.post.append(
            f"{{ size_t rest_n = (fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U; "
            f"if (rest_n > {cap}) {{ rest_n = {cap}; }} "
            f"if ((unsigned long long){ln} > (unsigned long long)rest_n) {{ {ln} = ({ltype})rest_n; }} "
            f"if ({v} != 0 && (size_t){ln} > 0U) {{ memcpy({v}, {FUZZ_COPY}, (size_t){ln}); }} }}"
        )
        case.note(call, i, "writable capacity input buffer: copied from the rest of the input for subsequent call")
    else:
        alloc = case.declare(f"{v}_alloc")
        case.decls.append(f"unsigned char *{alloc} = 0; unsigned char *{case.declare(v)} = 0;")
        guards.append(f"{alloc} != 0")
        after.append(f"free({alloc});")
        clamp = f"if (rest_n > {limit}U) {{ rest_n = {limit}U; }} " if limit is not None else ""
        n_var = f"{v}_n"
        case.post.append(
            f"{{ size_t rest_n = (fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U; {clamp}"
            f"if ((unsigned long long){ln} > (unsigned long long)rest_n) {{ {ln} = ({ltype})rest_n; }} "
            f"size_t {n_var} = (size_t){ln}; "
            f"{alloc} = (unsigned char *)malloc({n_var} > 0U ? {n_var} : 1U); "
            f"if ({alloc} != 0) {{ {v} = ({n_var} > 0U) ? {alloc} : ({alloc} + 1); "
            f"if ({n_var} > 0U) {{ memcpy({v}, {FUZZ_COPY}, {n_var}); }} }} }}"
        )
        case.note(call, i, "exact-size input buffer: copied from the rest of the input for subsequent call")


def recorded_input_buffers(traces: list[list[dict]] | None) -> dict[str, set[int]]:
    """
    Per function name, the parameter indices where recorded seed traces captured a non-empty,
    non-zero length-sized byte buffer (`b` record) on entry. Pointee-only `p` records are ignored
    because they are non-zero for scalar out-parameters too.
    """
    out: dict[str, set[int]] = {}
    for trace in traces or []:
        for call in trace:
            fn = call.get("fn")
            if not isinstance(fn, str):
                continue
            for k_s, vals in (call.get("args") or {}).items():
                if not str(k_s).isdigit() or not isinstance(vals, list):
                    continue
                for entry in vals:
                    if not isinstance(entry, list) or len(entry) < 3 or entry[0] != "b":
                        continue
                    hx = entry[2]
                    if not isinstance(hx, str) or not hx:
                        continue
                    try:
                        raw = bytes.fromhex(hx)
                    except ValueError:
                        continue
                    if raw and any(raw):
                        out.setdefault(fn, set()).add(int(k_s))
                        break
    return out


def _is_nonconst_input_buf(
    name: str,
    params: list[dict],
    i: int,
    formals: list[dict],
    api: ApiInfo,
    *,
    role: str | None = None,
    entry_trust: _EntryTrust | None = None,
    is_len_ptr: bool = False,
) -> bool:
    """
    Whether a non-`const` byte buffer at `i` (paired with a length or length-pointer at `i + 1`)
    carries input data (read-only missing `const`, or read-and-modified in place).

    Never promotes parameters marked `output`, `caller_storage`, or `trusted` by a threat model.
    Requires positive evidence from at least one of:
      1. Threat model explicitly naming parameter `i` in `attacker_params`;
      2. Recorded seed traces passing a non-empty, non-zero `b` byte buffer at entry;
      3. Parameter or paired-length formal name containing an input word (`_IN_BUF_WORDS`),
         while neither formal name contains an output word (`_OUT_BUF_WORDS`).
    For `(byte *, int)` pairs, when the length formal is named, it must match `_LEN_NAME_RE`
    (so `(char *hostname, uint16_t port)` or `(uint8_t *p, uint16_t byte_idx)` is never promoted).
    """
    if role in ("output", "caller_storage", "trusted"):
        return False
    if i + 1 >= len(params) or params[i]["kind"] != "ptr" or not _charlike(params[i]):
        return False
    if _is_input(formals, i):
        return False
    pname = _name(formals, i)
    lname = _name(formals, i + 1)
    if not is_len_ptr and lname is not None and not _LEN_NAME_RE.search(lname):
        return False
    if entry_trust is not None and entry_trust.attacker_params is not None and pname in entry_trust.attacker_params:
        return True
    pwords = set(_words(pname or ""))
    lwords = set(_words(lname or ""))
    if (pwords | lwords) & _OUT_BUF_WORDS:
        return False
    if i in (api.recorded_input_buffers.get(name) or ()):
        return True
    return bool((pwords | lwords) & _IN_BUF_WORDS)


def _array_element(p: dict) -> bool:
    return p["kind"] == "ptr" and not _charlike(p) and not p.get("anon_enum")


def _array_count(params: list[dict], i: int, formals: list[dict]) -> int | None:
    """
    The index of the count of the arrays starting at parameter `i`, or None. An array is a pointer to
    non-byte elements; one or more of them in a row followed by their count make a group
    (`const char *strings[], size_t count`; `const char *keys[], bool found[], size_t count`). The
    count is an integer `is_length` accepts whose formal name says count (`_ARRAY_COUNT_RE`), or
    length or size when no array of the group points to a struct. Only the last array of a group
    may point to a struct, and only with a count-named count: `(struct ctx *c, size_t size)` is far
    more often a context and some size than an array of contexts. Without the count's name nothing
    says it counts elements: a pointer and a value (`int *dst, unsigned value`) are no group (the
    pointer is a small array, `_scalar_array`, and the value stays as read).
    """
    j = i
    while j < len(params) and _array_element(params[j]):
        j += 1
    if j == i or j >= len(params):
        return None
    name = _name(formals, j)
    if name is None or not is_length(params[j], name):
        return None
    records = [_is_record(str(params[k].get("pointee") or "")) for k in range(i, j)]
    if any(records[:-1]):
        return None
    if _ARRAY_COUNT_RE.search(name):
        return j
    return None if records[-1] or not _ARRAY_LEN_RE.search(name) else j


def _array_object(case: _Case, call: int, i: int, p: dict, size: int | None, is_input: bool) -> str:
    """
    Declare the array behind parameter `i` (`_array_count`); returns its element count as a C
    expression. It has ARRAY_ELEMENTS valid elements (or the elements of its call sites' size,
    `param_size`): an array of byte strings points each element to a distinct NUL-terminated string
    (`ARRAY_STRINGS`, in writable storage), other pointer elements are NULL, scalars and structs are
    zeroed, and element 0 is read from the input as the one object was before, so the layout does
    not change. A pointer element is never read from the input.
    """
    v = f"c{call}a{i}"
    pointee = str(p.get("pointee") or "void")
    elem = str(p.get("decl") or pointee)
    n_expr = f"{ARRAY_ELEMENTS}ULL"
    if pointee.endswith("*"):
        inner = pointee[:-1].strip()
        case.decls.append(f"{elem} {case.declare(v)}[{ARRAY_ELEMENTS}]; memset({v}, 0, sizeof({v}));")
        if inner in ("char", "signed char", "unsigned char"):
            # `const` strings get room for their text; strings the callee may write a spare buffer each.
            width = ARRAY_STRING_BYTES if "const" in elem.rsplit("*", 1)[0] else case.spare
            store = case.declare(f"{v}s")
            case.decls.append(
                f"static {inner} {store}[{ARRAY_ELEMENTS}][{width}]; memset({store}, 0, sizeof({store}));"
            )
            for k, s in enumerate(ARRAY_STRINGS[:ARRAY_ELEMENTS]):
                if s:
                    case.decls.append(f'memcpy({store}[{k}], "{s}", {len(s)});')
                case.decls.append(f"{v}[{k}] = ({elem}){store}[{k}];")
            what = "distinct NUL-terminated strings"
        else:
            what = "NULL pointers"
    else:
        lay = case.api.structs.get(pointee) if _is_record(pointee) else None
        raw_ok = pointee != "_Bool" and (not _is_record(pointee) or _raw_ok(lay))
        if is_input and not raw_ok and lay is None:
            case.note(call, i, f"{_layout_why(case.api, pointee)}: the elements are zeroed, not read from the input")
        if size:
            case.decls.append(
                f"{elem} {case.declare(v)}[({size} + sizeof({elem}) - 1) / sizeof({elem})]; memset({v}, 0, sizeof({v}));"
            )
            if is_input and raw_ok:
                case.slot(v, size, call, i, "bytes", addr=False)
            n_expr = f"(sizeof({v}) / sizeof({v}[0]))"
        else:
            case.decls.append(f"{elem} {case.declare(v)}[{ARRAY_ELEMENTS}]; memset({v}, 0, sizeof({v}));")
            if is_input and pointee == "_Bool":
                case.bool_slot(f"{v}[0]", call, i, "pointee")
            elif is_input and raw_ok:
                case.slot(f"{v}[0]", SCALAR_BYTES.get(pointee) or (lay or {}).get("size"), call, i, "pointee")
        if is_input and not raw_ok and lay is not None and lay.get("what") == "struct":
            _fill_fields(case, call, i, f"{v}[0]", lay, 0)
        what = "zeroed elements, element 0 read from the input" if is_input else "zeroed elements"
    if size:
        case.note(call, i, f"array of the call sites' {size} bytes ({what}); its count is mapped into 1..its elements")
    else:
        n = ARRAY_ELEMENTS
        case.note(call, i, f"array of {n} elements ({what}); its count is mapped into 1..{n}")
    return n_expr


def _array_args(
    case: _Case, call: int, params: list[dict], formals: list[dict], rec: dict, i: int, j: int
) -> list[str]:
    """
    The arguments of arrays `i`..`j - 1` and their count `j` (`_array_count`). The count keeps the
    input slot it had and is mapped into 1..elements of the smallest array: never past an array, and
    never 0 (`ARRAY_ELEMENTS`).
    """
    args: list[str] = []
    bound = ""
    for k in range(i, j):
        n_expr = _array_object(case, call, k, params[k], param_size(rec, k), _is_input(formals, k))
        bound = n_expr if not bound or bound == n_expr else f"({bound} < {n_expr} ? {bound} : {n_expr})"
        args.append(f"({params[k]['type']})c{call}a{k}")
    ln = f"c{call}a{j}"
    ct = params[j]["ctype"]
    case.decls.append(f"{ct} {case.declare(ln)}; memset(&{ln}, 0, sizeof({ln}));")
    case.slot(ln, SCALAR_BYTES.get(ct), call, j, "int")
    # 1..bound, counts 1..bound kept as read; no unsigned wrap (a short input leaves the count 0),
    # which -warn-unsigned-overflow and E-ACSL's --rte=all would report in the harness.
    case.decls.append(f"{ln} = ({ct})(1ULL + ((unsigned long long){ln} % {bound} + ({bound} - 1ULL)) % {bound});")
    return [*args, ln]


def _variable_length(
    params: list[dict],
    formals: list[dict],
    rec: dict,
    shared: dict[int, str],
    *,
    name: str = "",
    api: ApiInfo | None = None,
    roles: list[str] | None = None,
    entry_trust: _EntryTrust | None = None,
) -> bool:
    """
    Whether the call reads an input pair of no known size, so its length comes from the fuzz input. A
    lone output pointer of such a call (crypto_box's `c`, sized by `mlen`) may receive that many bytes,
    whatever size its call sites showed: it gets a spare buffer.
    """
    for i in range(len(params)):
        if i in shared or param_size(rec, i) is not None:
            continue
        role = roles[i] if roles is not None else None
        if _is_pair(params, i, formals):
            if _is_input(formals, i) or (
                api is not None
                and _is_nonconst_input_buf(name, params, i, formals, api, role=role, entry_trust=entry_trust)
            ):
                return True
        elif _is_buf_len_ptr_pair(params, i, formals):
            if _is_input(formals, i) or (
                api is not None
                and _is_nonconst_input_buf(
                    name, params, i, formals, api, role=role, entry_trust=entry_trust, is_len_ptr=True
                )
            ):
                return True
    return False


def _lone_output(params: list[dict], formals: list[dict], i: int) -> bool:
    return (
        params[i]["kind"] == "ptr"
        and not str(params[i].get("pointee") or "").endswith("*")
        and not _is_pair(params, i, formals)
        and not _is_buf_len_ptr_pair(params, i, formals)
        and not _is_input(formals, i)
    )


def _is_record(t: str) -> bool:
    return t.startswith(("struct ", "union "))


def _layout_why(api: ApiInfo, ctype: str) -> str:
    if not api.probed:
        return f"{ctype}: no struct layout (the layout probe did not run)"
    return f"{ctype}: layout not known (not defined in the headers, a bit-field, packed, or an anonymous member)"


def _raw_ok(lay: dict | None) -> bool:
    """Whether a struct, union or member may be copied from input bytes: no pointer and no `_Bool` in it."""
    return lay is not None and not lay.get("pointers") and not lay.get("bools")


def _len_field(f: dict) -> bool:
    return f.get("kind") == "int" and is_length({"kind": "int", "ctype": f.get("ctype")}, f.get("name"))


_BYTE_POINTEES = frozenset({"char", "signed char", "unsigned char", "void"})


def _len_before_ptr(fields: list[dict], i: int) -> bool:
    """
    Whether field `i` is a length the field's name says (`len`, `size`, `count`, ...: an unsigned
    field before a pointer is not always its length) followed by a pointer no length follows: a
    (pointer, length) pair keeps its own (`{size_t n; char *buf; size_t buf_len;}` pairs `buf` with
    `buf_len`).
    """
    if i + 1 >= len(fields) or not _len_field(fields[i]) or fields[i + 1]["kind"] != "ptr":
        return False
    if not _LEN_NAME_RE.search(str(fields[i].get("name") or "")):
        return False
    return not (i + 2 < len(fields) and _len_field(fields[i + 2]))


def _len_ptr_pair(fields: list[dict], i: int) -> bool:
    """
    Whether fields `i`, `i + 1` are a (length, pointer) pair: nginx's `ngx_str_t { size_t len; u_char
    *data; }` (`_len_before_ptr`), the pointer a byte pointer, so a length clamped to its storage in
    bytes keeps every access inside it. A length before a pointer to wider elements (GMP's
    `__mpz_struct { int _mp_alloc; int _mp_size; mp_limb_t *_mp_d; }`) counts elements of a size the
    layout does not give: `_fill_fields` leaves it 0 rather than read it from the input.
    """
    return _len_before_ptr(fields, i) and bool(fields[i + 1].get("bytes"))


def _bsd_queue_head_fields(lay: dict | None) -> tuple[str, str] | None:
    """
    BSD `TAILQ_HEAD` / `STAILQ_HEAD` layout: a 2-pointer struct whose fields match
    `(tqh_first, tqh_last)` or `(stqh_first, stqh_last)`. Leaving `tqh_last == NULL` crashes
    `TAILQ_INSERT_TAIL` (`*head->tqh_last = elm`) immediately.
    """
    if not isinstance(lay, dict) or lay.get("what") != "struct":
        return None
    fields = list(lay.get("fields") or [])
    if len(fields) != 2 or not all(isinstance(f, dict) and f.get("kind") == "ptr" for f in fields):
        return None
    pair = (str(fields[0].get("name") or ""), str(fields[1].get("name") or ""))
    if pair in (("tqh_first", "tqh_last"), ("stqh_first", "stqh_last")):
        return pair
    return None


def _init_bsd_queues(case: _Case, expr: str, lay: dict | None, seen: frozenset[str] = frozenset()) -> bool:
    """
    Emit valid empty-list initialization for BSD `TAILQ_HEAD` / `STAILQ_HEAD` (`obj.tqh_first = NULL;
    obj.tqh_last = &obj.tqh_first;`), recursively for nested structs. Returns True when any queue
    head was initialized.
    """
    pair = _bsd_queue_head_fields(lay)
    if pair is not None:
        case.decls.append(f"{expr}.{pair[0]} = NULL; {expr}.{pair[1]} = &{expr}.{pair[0]};")
        return True
    if not isinstance(lay, dict) or lay.get("what") != "struct":
        return False
    did = False
    for f in lay.get("fields") or []:
        if isinstance(f, dict) and f.get("kind") == "record" and f.get("what") == "struct":
            sub_ctype = str(f.get("ctype") or "")
            sub_lay = case.api.structs.get(sub_ctype)
            if sub_lay is not None and sub_ctype not in seen:
                if _init_bsd_queues(case, f"{expr}.{f['name']}", sub_lay, seen | {sub_ctype}):
                    did = True
    return did


def _fill_fields(case: _Case, call: int, param: int, expr: str, lay: dict, base: int) -> None:
    """
    Fill the fields of a struct with pointers (`expr`, already zeroed) without putting an input byte
    into a pointer: (pointer, length) pairs, and (length, byte pointer) pairs (`_len_ptr_pair`), get
    generator-owned storage and a length clamped to it, other pointers a zeroed spare buffer,
    function pointers stay NULL, scalars and pointer-free members come from the input, except the
    length of a pointer to wider elements before it (`_len_before_ptr`), which stays 0.
    """
    if case.api.trust_schema and (qpair := _bsd_queue_head_fields(lay)) is not None:
        case.decls.append(f"{expr}.{qpair[0]} = NULL; {expr}.{qpair[1]} = &{expr}.{qpair[0]};")
        return
    fields = list(lay.get("fields") or [])
    i = 0
    while i < len(fields):
        f = fields[i]
        fx = f"{expr}.{f['name']}"
        off = base + int(f["off"])
        nxt = fields[i + 1] if i + 1 < len(fields) else None
        # The storage of a pointer field, named after the field's path. The path of an object in an
        # array is `c0a0[0]`: every character an identifier cannot hold becomes `_` (`c0a0_0_f2`).
        tag = f"{re.sub(r'[^A-Za-z0-9_]', '_', expr)}f{i}"
        pair: tuple[dict, dict, int] | None = None  # (pointer field, length field, pointer index)
        if f["kind"] == "ptr" and nxt is not None and _len_field(nxt):
            pair = (f, nxt, i)
        elif nxt is not None and _len_ptr_pair(fields, i):
            pair = (nxt, f, i + 1)
        elif nxt is not None and _len_before_ptr(fields, i):
            # The length of a pointer to elements of a size the layout does not give (GMP's `_mp_size`
            # before `_mp_d`): a value read from the input could reach past the pointer's spare buffer.
            case.note(
                call, param, f"field {f['name']}: the length of {nxt['name']}, whose elements have no known size: 0"
            )
            i += 1
            continue
        if pair is not None:
            pf, lf, k = pair
            px, lx, poff = f"{expr}.{pf['name']}", f"{expr}.{lf['name']}", base + int(pf["off"])
            ptag = f"{re.sub(r'[^A-Za-z0-9_]', '_', expr)}f{k}"
            if pf.get("const") and case.rest is None:
                case.rest = {"call": call, "param": param, "kind": "bytes", "off": poff}
                case.post.append(f"{px} = (void *)(fuzz_buf + fuzz_off); {lx} = ({lf['ctype']})(fuzz_len - fuzz_off);")
            else:
                size = PAIR_BYTES if pf.get("const") else case.spare
                case.decls.append(_byte_buffer(_storage(None), case.declare(ptag), size))
                if pf.get("const"):
                    case.slot(ptag, size, call, param, "field_bytes", addr=False, off=poff)
                case.slot(lx, int(lf["size"]), call, param, "field_len", off=poff, max=size)
                case.decls.append(
                    f"if ((unsigned long long){lx} > {size}ULL) {{ {lx} = ({lf['ctype']}){size}; }} {px} = (void *){ptag};"
                )
            i += 2
            continue
        if f["kind"] == "ptr":
            case.decls.append(f"{_byte_buffer('static ', case.declare(tag), case.spare)} {fx} = (void *){tag};")
        elif f["kind"] == "int" and f.get("ctype") == "_Bool":
            case.bool_slot(fx, call, param, "field", off=off)
        elif f["kind"] in ("int", "float", "enum") or (f["kind"] in ("array", "record") and _raw_ok(f)):
            case.slot(fx, int(f["size"]), call, param, "field", addr=f["kind"] != "array", off=off)
        elif f["kind"] == "record" and f.get("what") == "struct" and f.get("ctype") in case.api.structs:
            _fill_fields(case, call, param, fx, case.api.structs[f["ctype"]], off)
        elif f["kind"] != "fnptr":
            case.note(call, param, f"field {f['name']}: holds pointers or _Bool the generator cannot place: zeroed")
        i += 1


def _struct_value(case: _Case, call: int, param: int, v: str, ctype: str) -> None:
    """A struct (or union) by value: read from the input without pointers, else filled field by field."""
    case.decls.append(f"{ctype} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
    lay = case.api.structs.get(ctype)
    if lay is None:
        case.note(call, param, f"{_layout_why(case.api, ctype)}: zeroed, not read from the input")
    elif _raw_ok(lay):
        case.slot(v, int(lay["size"]), call, param, "struct")
    elif lay.get("what") == "struct":
        _fill_fields(case, call, param, v, lay, 0)
    else:
        case.note(call, param, f"{ctype}: a union with pointers or _Bool: zeroed, not read from the input")


def _is_nullable_allocator_param(param_name: str | None, p: dict[str, Any]) -> bool:
    """
    Under `FRAMAC_API_TRUST_SCHEMA`, whether a `"trusted"` pointer parameter is a nullable default
    allocator (`ProtobufCAllocator *allocator`, `alloc`, `mem_alloc`) that may safely bind to `NULL`.
    Never matches schema/descriptor/iterator/field pointers (`pb_msgdesc_t`,
    `ProtobufCMessageDescriptor`, `pb_field_iter_t`, `pb_field_t`, etc.).
    """
    if p.get("kind") != "ptr":
        return False
    pname_low = (param_name or "").strip().lower()
    if pname_low in _NULLABLE_ALLOCATOR_NAMES or "allocator" in _words(param_name):
        return True
    for spelling in (p.get("pointee"), p.get("decl"), p.get("type")):
        if isinstance(spelling, str) and "allocator" in spelling.lower():
            return True
    return False


def _is_writable_byte_ptr_field(f: dict[str, Any]) -> bool:
    """Whether a struct field is a non-const byte/void pointer (`void *`, `unsigned char *`, `uint8_t *`, `char *`)."""
    if f.get("kind") != "ptr" or f.get("const"):
        return False
    if f.get("bytes") is True:
        return True
    if f.get("bytes") is False:
        return False
    pointee = str(f.get("pointee") or "").strip()
    if pointee:
        norm = _norm_type(pointee)
        return norm in _BYTE_POINTEES or norm == "uint8_t"
    return False


def _is_caller_storage_len_field(f: dict[str, Any]) -> bool:
    """Whether a struct field is a size/length integer field of a caller-storage buffer struct."""
    if not _len_field(f):
        return False
    fname = str(f.get("name") or "")
    return bool(_LEN_NAME_RE.search(fname) or (set(_words(fname)) & _TRIPLE_SIZE_WORDS))


def _writable_buffer_struct_fields(lay: dict[str, Any] | None) -> tuple[dict[str, Any], dict[str, Any]] | None:
    """
    S2 caller-storage shape (a): a struct whose fields are exactly one writable byte/void pointer
    (`void *`, `unsigned char *`, `uint8_t *`, `char *`, non-`const` pointee) and one size/length
    integer field, in either `{ptr, len}` or `{len, ptr}` field order, with no function-pointer or
    other pointer fields (e.g. QCBOR's `UsefulBuf { void *ptr; size_t len; }`).
    Returns `(ptr_field, len_field)` or None.
    """
    if not isinstance(lay, dict) or lay.get("what") != "struct":
        return None
    fields = list(lay.get("fields") or [])
    if len(fields) != 2 or not all(isinstance(f, dict) for f in fields):
        return None
    f0, f1 = fields[0], fields[1]
    if _is_writable_byte_ptr_field(f0) and _is_caller_storage_len_field(f1):
        return f0, f1
    if _is_caller_storage_len_field(f0) and _is_writable_byte_ptr_field(f1):
        return f1, f0
    return None


def _is_caller_storage_pair(
    params: list[dict[str, Any]],
    i: int,
    formals: list[dict[str, Any]],
    rec: dict[str, Any],
    api: ApiInfo,
) -> bool:
    """
    S2 caller-storage shape (b): a trusted writable `(void */byte *, size_t)` scratch pair whose
    pointer is non-`const` (`formals[i]["kind"] == "pointer"`), not an opaque handle, followed by
    a length integer whose name says length/size/capacity (or an unnamed `size_t`/`unsigned long`).
    """
    if i + 1 >= len(params) or not _is_pair(params, i, formals):
        return False
    if _is_input(formals, i):
        return False
    fn_name = str(rec.get("name") or "")
    if i in (api.handles.get(fn_name) or {}):
        return False
    lname = _name(formals, i + 1)
    if lname:
        return bool(_LEN_NAME_RE.search(lname) or (set(_words(lname)) & _TRIPLE_SIZE_WORDS))
    return str(params[i + 1].get("ctype") or "") in ("unsigned long", "unsigned long long")


def _is_trusted_cstring(params: list[dict], formals: list[dict], rec: dict, i: int, roles: list[str] | None) -> bool:
    """
    Under `FRAMAC_API_TRUST_SCHEMA`, whether trusted parameter `i` is a NUL-terminated string the
    application chooses (QCBOR's `const char *szLabel`), bound to a literal (`_trusted_string_arg`)
    instead of exempting the entry point. Only a `char`/`signed char` pointee the model positively
    marks read-only (`const_pointer`), with no size its call sites give: a byte buffer (`void`,
    `unsigned char`), a fixed-size object or a pointer the callee may write keeps the
    `TRUSTED_PARAM_NO_INSTANCE_FMT` exemption. An unsigned scalar beside it that the threat model
    leaves trusted (`trusted_scalar`: QCBOR's `szLabel, uint32_t uConvertTypes`) is no length of
    the string, only zeroed; one it gives the attacker would be a length beside a literal: exempt.
    """
    if roles is None or i >= len(params) or i >= len(formals) or i >= len(roles) or roles[i] != "trusted":
        return False
    p = params[i]
    if p.get("kind") != "ptr" or str(p.get("pointee") or "") not in ("char", "signed char"):
        return False
    if not isinstance(formals[i], dict) or formals[i].get("kind") != "const_pointer":
        return False
    if param_size(rec, i) is not None:
        return False
    if _is_pair(params, i, formals) and (i + 1 >= len(roles) or roles[i + 1] != "trusted_scalar"):
        return False
    return not (i > 0 and _len_ptr_params(params, i - 1, formals, rec) and roles[i - 1] != "trusted_scalar")


def recorded_strings(traces: list[list[dict]] | None) -> dict[str, dict[int, str]]:
    """
    Per function and argument index, the NUL-terminated string (`s` records of seed_harvest.py
    traces) the target's tests pass most often there; ties go to the shorter, then the smaller text.
    Only printable ASCII of 1 to `TRUSTED_STRING_MAX_BYTES` bytes counts, so the literal is stable.
    """
    counts: dict[tuple[str, int], dict[str, int]] = {}
    for trace in traces or []:
        for call in trace:
            fn = call.get("fn")
            args = call.get("args")
            if not isinstance(fn, str) or not isinstance(args, dict):
                continue
            for idx, vals in args.items():
                if not str(idx).isdigit() or not isinstance(vals, list):
                    continue
                for val in vals:
                    if not (isinstance(val, list) and len(val) == 3 and val[0] == "s" and isinstance(val[2], str)):
                        continue
                    try:
                        data = bytes.fromhex(val[2])
                    except ValueError:
                        continue
                    if not 0 < len(data) <= TRUSTED_STRING_MAX_BYTES or not all(0x20 <= b < 0x7F for b in data):
                        continue
                    seen = counts.setdefault((fn, int(idx)), {})
                    text = data.decode("ascii")
                    seen[text] = seen.get(text, 0) + 1
    out: dict[str, dict[int, str]] = {}
    for (fn, idx), seen in sorted(counts.items()):
        out.setdefault(fn, {})[idx] = min(seen, key=lambda t: (-seen[t], len(t), t))
    return out


def recorded_scalars(traces: list[list[dict]] | None) -> dict[str, dict[int, list[tuple[int, int]]]]:
    """
    Per function and argument index, the integers (`i` records of seed_harvest.py traces, little
    endian, at most 8 bytes) the target's tests pass there, as (byte width, unsigned value): at most
    `MAX_RECORDED_SCALARS` distinct ones, the most frequent first, ties by value.
    `_recorded_scalar_arg` reads them with the parameter's signedness.
    """
    counts: dict[tuple[str, int], dict[tuple[int, int], int]] = {}
    for trace in traces or []:
        for call in trace:
            fn = call.get("fn")
            args = call.get("args")
            if not isinstance(fn, str) or not isinstance(args, dict):
                continue
            for idx, vals in args.items():
                if not str(idx).isdigit() or not isinstance(vals, list):
                    continue
                for val in vals:
                    if not (isinstance(val, list) and len(val) == 3 and val[0] == "i" and val[1] == 0):
                        continue
                    try:
                        data = bytes.fromhex(str(val[2]))
                    except ValueError:
                        continue
                    if not 0 < len(data) <= 8:
                        continue
                    seen = counts.setdefault((fn, int(idx)), {})
                    key = (len(data), int.from_bytes(data, "little"))
                    seen[key] = seen.get(key, 0) + 1
    out: dict[str, dict[int, list[tuple[int, int]]]] = {}
    for (fn, idx), seen in sorted(counts.items()):
        out.setdefault(fn, {})[idx] = sorted(seen, key=lambda k: (-seen[k], k[1], k[0]))[:MAX_RECORDED_SCALARS]
    return out


def _recorded_scalar_arg(case: _Case, call: int, i: int, p: dict, v: str, recorded: list[tuple[int, int]]) -> None:
    """
    A trusted scalar of a sequence case (`_Case.recorded_scalars`) the traces recorded: read from the
    input, then kept to the values the target's tests passed there (the application's own choices,
    as `_trusted_string_arg`'s literal), never zero unless they passed zero.
    """
    ctype = str(p["ctype"])
    signed = not (ctype.startswith(("unsigned", "enum", "_Bool")) or ctype in ("char", "size_t", "uint8_t"))
    values: list[int] = []
    for width, value in recorded:
        if signed and value >= 1 << (8 * width - 1):
            value -= 1 << (8 * width)
        if value not in values:
            values.append(value)
    lits = [f"{x}LL" if x < 0 else f"{x}ULL" for x in values]
    case.slot(v, SCALAR_BYTES.get(ctype), call, i, "int")
    member = " || ".join(f"(long long){v} == (long long){lit}" for lit in lits)
    case.decls.append(
        f"if (!({member})) {{ static const long long fc_r[{len(lits)}] = {{ {', '.join(f'(long long){lit}' for lit in lits)} }}; "
        f"{v} = ({ctype})fc_r[(unsigned long long){v} % {len(lits)}U]; }}"
    )
    case.note(
        call,
        i,
        f"trusted scalar parameter per threat model: one of the {len(lits)} values the target's tests pass "
        "there (recorded seed traces), picked by the input",
    )


def _trusted_string_arg(case: _Case, call: int, i: int, p: dict, name: str) -> str:
    """The argument of a trusted string parameter (`_is_trusted_cstring`): a string literal, no slot."""
    recorded = (case.api.trusted_strings.get(name) or {}).get(i)
    text = recorded if recorded is not None else TRUSTED_STRING_DEFAULT
    literal = c_string_literal(text.encode("ascii"))
    why = (
        "the value the target's tests pass most often (recorded seed traces)"
        if recorded is not None
        else "a fixed literal (no value recorded from the target's tests)"
    )
    case.note(
        call,
        i,
        f"trusted string parameter per threat model: the literal {literal}, {why}, a value the application "
        "could pass; not read from the input",
    )
    return f"({p['type']}){literal}"


def _strip_builder_pair_sizes(params: list[dict], formals: list[dict], rec: dict) -> dict:
    """
    Drop call-site `param_sizes` entries on an S2 builder's read-only `(buf, len)` / `(len, buf)`
    pairs so internal small-buffer call sites (e.g. nanopb's 10-byte `pb_istream_from_buffer`
    call site) do not pin the builder to a fixed stack buffer instead of feeding whole-input `rest`.
    """
    raw_sizes = rec.get("param_sizes")
    if not isinstance(raw_sizes, dict) or not raw_sizes:
        return rec
    drop: set[str] = set()
    n = len(params)
    for idx in range(n):
        if _is_pair(params, idx, formals) and _is_input(formals, idx):
            drop.add(str(idx))
        elif (
            idx + 1 < n
            and params[idx]["kind"] == "int"
            and (fname := _name(formals, idx))
            and _LEN_NAME_RE.search(fname)
            and is_length(params[idx], fname)
            and params[idx + 1]["kind"] == "ptr"
            and _charlike(params[idx + 1])
            and idx + 1 < len(formals)
            and isinstance(formals[idx + 1], dict)
            and formals[idx + 1].get("kind") == "const_pointer"
            and not _is_pair(params, idx + 1, formals)
        ):
            drop.add(str(idx + 1))
    if not drop:
        return rec
    return {**rec, "param_sizes": {k: v for k, v in raw_sizes.items() if k not in drop}}


def _struct_claims_rest(api: ApiInfo, lay: dict | None, seen: frozenset[str] = frozenset()) -> bool:
    """Whether `_fill_fields` would claim `case.rest` for a struct value or const struct pointer."""
    if not isinstance(lay, dict) or lay.get("what") != "struct" or _raw_ok(lay):
        return False
    if api.trust_schema and _bsd_queue_head_fields(lay) is not None:
        return False
    fields = list(lay.get("fields") or [])
    i = 0
    while i < len(fields):
        f = fields[i]
        nxt = fields[i + 1] if i + 1 < len(fields) else None
        pair: tuple[dict, dict] | None = None
        if f["kind"] == "ptr" and nxt is not None and _len_field(nxt):
            pair = (f, nxt)
        elif nxt is not None and _len_ptr_pair(fields, i):
            pair = (nxt, f)
        if pair is not None:
            if pair[0].get("const"):
                return True
            i += 2
            continue
        if f["kind"] == "record" and f.get("what") == "struct":
            sub_ctype = str(f.get("ctype") or "")
            if sub_ctype in api.structs and sub_ctype not in seen:
                if _struct_claims_rest(api, api.structs[sub_ctype], seen | {sub_ctype}):
                    return True
        i += 1
    return False


def _target_claims_rest(
    name: str,
    params: list[dict],
    formals: list[dict],
    rec: dict,
    api: ApiInfo,
    shared: dict[int, str],
    roles: list[str] | None,
    schema_bindings: dict[int, tuple[str, bool]],
    entry_trust: _EntryTrust | None = None,
) -> bool:
    """
    Whether any parameter of target function `name` itself (excluding S2 builder-initialized params
    and trusted params) would claim `case.rest`. When False, an S2 stream/buffer builder IS the
    whole-input consumer and feeds its read-only `(buf, len)` pair directly from `rest`.
    """
    varlen = _variable_length(params, formals, rec, shared, name=name, api=api, roles=roles, entry_trust=entry_trust)
    handles = api.handles.get(name) or {}
    outs = api.outs.get(name) or {}
    i = 0
    n = len(params)
    while i < n:
        p = params[i]
        nxt = params[i + 1] if i + 1 < n else None
        role = roles[i] if roles is not None else None
        if i in schema_bindings or role in ("trusted_scalar", "caller_storage_len"):
            i += 1
            continue
        if (
            api.trust_schema
            and role == "trusted"
            and p["kind"] == "ptr"
            and i not in shared
            and _is_nullable_allocator_param(_name(formals, i), p)
        ):
            i += 1
            continue
        htype = handles.get(i) if i not in shared and p["kind"] == "ptr" else None
        if htype is not None and _constructible(api, htype) and _releasable(api, htype):
            if sum(1 for t in handles.values() if t == htype) == 1:
                i += 1
                continue
        if i not in shared and p["kind"] == "ptr" and not _is_input(formals, i) and outs.get(i) is not None:
            i += 1
            continue
        if i in shared:
            if nxt is not None and (i + 1) not in shared and _is_pair(params, i, formals):
                i += 2
            else:
                i += 1
            continue
        if p["kind"] == "int" and (i + 1) not in shared and _len_ptr_params(params, i, formals, rec):
            return True
        if p["kind"] == "fnptr":
            i += 1
            continue
        if p["kind"] == "ptr":
            pointee = str(p.get("pointee") or "void")
            is_input = False if role in ("output", "caller_storage") else _is_input(formals, i)
            size = None if varlen and _lone_output(params, formals, i) else param_size(rec, i)
            own_init = (i == 0 and name in api.candidates.get(pointee, set())) or (
                api.trust_schema and name in api.candidates.get(pointee, set())
            )
            if pointee in api.inits and not own_init:
                i += 1
                continue
            if _table_type(api, p) is not None or role == "trusted":
                i += 1
                continue
            if role == "caller_storage":
                if _is_pair(params, i, formals) and nxt is not None and (i + 1) not in shared:
                    i += 2
                else:
                    i += 1
                continue
            j = _array_count(params, i, formals)
            if j is not None and not any(
                k in shared or k in handles or k in outs or str(params[k].get("pointee") or "") in api.inits
                for k in range(i, j + 1)
            ):
                i = j + 1
                continue
            if (
                _is_pair(params, i, formals)
                and nxt is not None
                and (i + 1) not in shared
                and (roles is None or roles[i + 1] != "trusted_scalar")
            ):
                nonconst_in = not is_input and _is_nonconst_input_buf(
                    name, params, i, formals, api, role=role, entry_trust=entry_trust
                )
                if (is_input or nonconst_in) and size is None:
                    return True
                i += 2
                continue
            if (
                _is_buf_len_ptr_pair(params, i, formals)
                and nxt is not None
                and (i + 1) not in shared
                and (roles is None or roles[i + 1] != "trusted_scalar")
            ):
                nonconst_in = not is_input and _is_nonconst_input_buf(
                    name, params, i, formals, api, role=role, entry_trust=entry_trust, is_len_ptr=True
                )
                if (is_input or nonconst_in) and size is None:
                    return True
                if is_input or nonconst_in:
                    i += 2
                    continue
            if _charlike(p):
                if size is None and is_input and pointee in ("char", "signed char"):
                    return True
                i += 1
                continue
            if is_input and _is_record(pointee) and _struct_claims_rest(api, api.structs.get(pointee)):
                return True
            i += 1
            continue
        if p["kind"] == "struct":
            ctype = str(p.get("ctype") or "")
            if api.trust_schema and ctype in api.inits and name not in api.candidates.get(ctype, set()):
                i += 1
                continue
            if role in ("trusted", "caller_storage"):
                i += 1
                continue
            if _struct_claims_rest(api, api.structs.get(ctype)):
                return True
            i += 1
            continue
        i += 1
    return False


def _init_call(
    case: _Case,
    pointee: str,
    target: str,
    call: int,
    param: int,
    *,
    var: str | None = None,
    schema_inst: dict[str, Any] | None = None,
    feed_rest: bool = False,
) -> str:
    """
    The initializer or S2 builder call of a struct object before call `call`.
    For a pointer initializer, `target` is its address expression (`&var` or a shared buffer);
    for a by-value builder (S2, `fn in api.byval_inits`), `var` is assigned the returned struct.
    When `feed_rest=True` under `FRAMAC_API_TRUST_SCHEMA`, call-site `param_sizes` on read-only
    `(buf, len)` / `(len, buf)` pairs are stripped so the builder consumes whole-input `rest`.
    """
    fn = case.api.inits[pointee]
    rec = case.api.records.get(fn) or {}
    formals = list(rec.get("formals") or [])
    params, _ = plan_params(str(rec.get("signature") or ""), formals)
    k = case.ncalls + len(case.inits)
    case.inits.append({"fn": fn, "call": k, "for": {"call": call, "param": param}})
    if case.api.trust_schema and case.builder is None:
        case.builder = fn
    schema_bindings: dict[int, tuple[str, bool]] | None = None
    if case.api.trust_schema and fn in case.api.schema_inits:
        s_idx, s_pointee = case.api.schema_inits[fn]
        inst = schema_inst
        if inst is None:
            insts = _lookup_schema_instances(case.api, s_pointee)
            if not insts:
                raise _AutoExempt(TRUSTED_PARAM_NO_INSTANCE_FMT.format(name=f"param{param}"))
            inst = insts[0]
        gname = str(inst["name"])
        _record_schema_extern(case.api, inst, s_pointee)
        schema_bindings = {s_idx: (gname, True)}
    use_builder_rest = case.api.trust_schema and feed_rest
    call_rec = _strip_builder_pair_sizes(params or [], formals, rec) if use_builder_rest else rec
    if case.api.trust_schema and fn in case.api.byval_inits:
        stmt = _bind_call(
            case,
            k,
            fn,
            params or [],
            formals,
            call_rec,
            shared={},
            allow_init=False,
            schema_bindings=schema_bindings,
            builder_rest=use_builder_rest,
        )
        if isinstance(case.rest, dict) and case.rest.get("call") == k:
            case.builder = fn
        lhs = var or target.lstrip("&")
        return stmt.replace(f"(void){fn}(", f"{lhs} = {fn}(", 1)
    stmt = _bind_call(
        case,
        k,
        fn,
        params or [],
        formals,
        call_rec,
        {0: target},
        allow_init=False,
        schema_bindings=schema_bindings,
        builder_rest=use_builder_rest,
    )
    if case.api.trust_schema and isinstance(case.rest, dict) and case.rest.get("call") == k:
        case.builder = fn
    return stmt


def _choose_handle_ctor(api: ApiInfo, htype: str, caller_name: str | None) -> str:
    """
    Pick the handle constructor for `htype` when calling `caller_name`. Under `FRAMAC_API_TRUST_SCHEMA`,
    score candidate constructors by shared distinctive identifier words with `caller_name`
    (`modbus_tcp_pi_listen` -> `modbus_new_tcp_pi`, `modbus_rtu_*` -> `modbus_new_rtu`) before
    falling back to fewest parameters and name.
    """
    default = api.ctors[htype]
    cands = api.ctor_cands.get(htype) or []
    if not api.trust_schema or not caller_name or len(cands) <= 1:
        return default
    cand_word_sets = {c: set(_words(c)) for c in cands}
    common = set.intersection(*cand_word_sets.values()) if cand_word_sets else set()
    caller_words = set(_words(caller_name))
    distinctive = {c: ws - common - _CTOR_BOILERPLATE_WORDS for c, ws in cand_word_sets.items()}
    matched_any = any(bool(distinctive[c] & caller_words) for c in cands)
    if not matched_any:
        return default

    def score(c: str) -> tuple[int, int, int, str]:
        d = distinctive[c]
        rec = api.records.get(c) or {}
        parts = split_signature(str(rec.get("signature") or ""))
        nparams = len(parts[1]) if parts else 99
        return (-len(d & caller_words), len(d - caller_words), nparams, c)

    return min(cands, key=score)


def _handle_call(case: _Case, htype: str, var: str, call: int, param: int, caller_name: str | None = None) -> str:
    """`<handle type> var = <constructor>(...);` before call `call`, the constructor's arguments by the usual rules."""
    fn = _choose_handle_ctor(case.api, htype, caller_name)
    rec = case.api.records.get(fn) or {}
    params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
    k = case.ncalls + len(case.inits)
    case.inits.append({"fn": fn, "call": k, "for": {"call": call, "param": param}})
    stmt = _bind_call(case, k, fn, params or [], list(rec.get("formals") or []), rec, allow_init=False)
    # Without initializers the statement is the call alone: keep its result instead of dropping it.
    return stmt.replace("(void)", f"{htype} {case.declare(var)} = ", 1)


def _opaque(htype: str) -> bool:
    """
    A handle type naming a pointer to a struct the headers only declare (`struct tag *`, as
    `handle_prototypes` names it): no object of the struct can be declared, only pointers to one. A
    typedef of `void *` (`scmp_filter_ctx`) is not: a zeroed buffer stands in for it and compiles.
    """
    return htype.endswith("*")


def _constructible(api: ApiInfo, htype: str) -> bool:
    return htype in api.ctors or htype in api.out_ctors


def _releasable(api: ApiInfo, htype: str) -> bool:
    """A destructor releases the handle, or it is a child its parent owns (no destructor, built from a parent)."""
    return htype in api.dtors or (htype not in api.ctors and htype in api.parents)


_RESERVED_REST: dict[str, Any] = {"reserved": True}


def _construct(
    case: _Case,
    htype: str,
    var: str,
    call: int,
    param: int,
    depth: int = 0,
    caller_name: str | None = None,
) -> tuple[list[str], str | None, list[str], str | None]:
    """
    Build a handle of `htype` in `var` before call `call`: (the statements that declare and build it,
    its own release or None, the releases of the parents built for it (child first), the guard the
    call needs or None). A constructor that returns the handle is called as before (`_handle_call`).
    An out-parameter constructor gets `&var` (`H var = 0;`), and the call runs only when it wrote a
    handle (`var != 0`); a child handle's parent is built first, the child's constructor runs only on
    a built parent, and the parent is released after the call: it owns the child. An out-parameter
    constructor never takes the rest of the input: it stays for the call under test (an unsized
    input string of it is a `STRING_SLOT_BYTES` slot, NUL-terminated, `_bind_call`).
    """
    api = case.api
    if htype in api.ctors:
        return (
            [_handle_call(case, htype, var, call, param, caller_name=caller_name)],
            _handle_release(api, htype, var),
            [],
            None,
        )
    fn, out = api.out_ctors[htype]
    rec = api.records.get(fn) or {}
    params, why = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
    if params is None:
        raise _Unbuildable(f"{fn}, the constructor of opaque handle {htype}: {why}")
    before: list[str] = []
    later: list[str] = []
    shared = {out: f"&{var}"}
    parent_guard: str | None = None
    if htype in api.parents:
        pidx, ptype = api.parents[htype]
        if depth >= MAX_HANDLE_DEPTH or not _constructible(api, ptype):
            raise _Unbuildable(f"no constructor for opaque handle {ptype}")
        if not _releasable(api, ptype):
            raise _Unbuildable(f"no destructor for opaque handle {ptype}")
        pvar = f"{var}p"
        pstmts, prelease, pparents, pguard = _construct(case, ptype, pvar, call, param, depth + 1)
        before += pstmts
        later = [*([prelease] if prelease else []), *pparents]
        shared[pidx] = pvar
        parent_guard = pguard or f"{pvar} != 0"
    k = case.ncalls + len(case.inits)
    case.inits.append({"fn": fn, "call": k, "for": {"call": call, "param": param}})
    reserved = case.rest is None
    if reserved:
        case.rest = _RESERVED_REST
    try:
        stmt = _bind_call(case, k, fn, params, list(rec.get("formals") or []), rec, shared, allow_init=False)
    finally:
        if reserved and case.rest is _RESERVED_REST:
            case.rest = None
    if parent_guard:
        stmt = f"if ({parent_guard}) {{ {stmt} }}"
    before.append(f"{htype} {case.declare(var)} = 0; {stmt}")
    return before, _handle_release(api, htype, var), later, f"{var} != 0"


def _handle_release(api: ApiInfo, htype: str, var: str, called: str | None = None) -> str | None:
    """
    The release of handle `var` of `htype` after call `called`, or None: no destructor, or `called`
    is itself named like a destructor of the handle. The handle's `close` (`api.closers`) runs before
    its freeing destructor; when `called` is that `close`, only the destructor follows it.
    """
    dtor = api.dtors.get(htype)
    if dtor is None:
        return None
    closer = api.closers.get(htype)
    if called is not None and called in api.dtor_names.get(htype, set()) and called != closer:
        return None
    calls = [f"(void){f}({var});" for f in (closer, dtor) if f and f != called]
    return f"if ({var} != 0) {{ {' '.join(calls)} }}"


def _made_struct(name: str, rec: dict, params: list[dict], api: ApiInfo) -> str | None:
    """
    The struct type whose object call `name` makes and hands to its caller, or None: named like an
    initializer (`modbus_mapping_new_start_address`), returning `struct S *` (a complete struct, so no
    handle), taking no `struct S *`, reaching an allocator, its header not returning a `const`
    pointee, and `S` has a destructor named for freeing (`api.struct_freers`: `modbus_mapping_free`).
    A wrong release would be a crash only the harness makes, so every condition must hold.
    """
    ret = _return_type(rec)
    if not ret.endswith("*") or not _INIT_NAME_RE.search(name):
        return None
    pointee = ret[:-1].strip()
    if not _is_record(pointee) or "*" in pointee or pointee not in api.struct_freers:
        return None
    if name not in api.allocating or name in api.const_returns:
        return None
    if any(p["kind"] == "ptr" and str(p.get("pointee") or "") == pointee for p in params):
        return None
    return pointee


def _struct_release(api: ApiInfo, pointee: str, name: str, expr: str) -> str | None:
    """The release of struct object `expr` after call `name`, or None (no destructor, or `name` is one)."""
    dtor = api.struct_dtors.get(pointee)
    if dtor is None or name in api.struct_dtor_names.get(pointee, set()):
        return None
    return f"(void){dtor}({expr});"


def _return_type(rec: dict) -> str:
    parts = split_signature(str(rec.get("signature") or ""))
    return " ".join(parts[0].split()) if parts else ""


def _realloc_like(
    name: str, params: list[dict], formals: list[dict], rec: dict, api: ApiInfo
) -> tuple[list[int], list[int]] | None:
    """
    (used-size indices, new-size indices) of a realloc-like function (rule E), or None: named like
    `*_realloc`, a writable `void *` first, then only integers, at least one of them a new size, a
    pointer returned, and an allocator reached.
    """
    if not _REALLOC_NAME_RE.search(name) or name not in api.allocating or not params:
        return None
    p0 = params[0]
    if p0["kind"] != "ptr" or str(p0.get("pointee") or "") not in ("void", "") or _is_input(formals, 0):
        return None
    if not _return_type(rec).endswith("*"):
        return None
    used: list[int] = []
    new: list[int] = []
    for k in range(1, len(params)):
        if params[k]["kind"] != "int" or params[k].get("enum") or params[k].get("ctype") == "_Bool":
            return None
        (used if set(_words(_name(formals, k))) & _REALLOC_USED_WORDS else new).append(k)
    return (used, new) if new else None


def _free_byte_ptr_like(name: str, params: list[dict], formals: list[dict], api: ApiInfo) -> bool:
    """Whether `name` is a single-argument `*_free*(byte */void *)` helper reaching `free` (rule E)."""
    if len(params) != 1 or name not in api.freeing or not _FREEING_DTOR_RE.search(name):
        return False
    p0 = params[0]
    return p0["kind"] == "ptr" and _charlike(p0) and not _is_input(formals, 0)


def _owned_out_param(name: str, params: list[dict], formals: list[dict], i: int, api: ApiInfo) -> bool:
    """
    Whether parameter `i` is a writable `byte **` out-parameter through which an allocating
    function returns a caller-owned heap buffer (rule F): e.g. `mpack_writer_init_growable`,
    `crypto_deep_copy_string`, or `(uint8_t **out_buf, uint16_t *out_len)` allocating out-pairs
    such as `Crypto_TC_ApplySecurity` / `ares_dns_write`.
    """
    if name not in api.allocating or _is_input(formals, i) or i in (api.qual_ptrs.get(name) or {}):
        return False
    pointee = str(params[i].get("pointee") or "")
    if pointee not in ("char *", "void *", "unsigned char *"):
        return False
    if set(_words(_name(formals, i))) & _CURSOR_OUT_WORDS:
        return False
    fn_words = set(_words(name))
    if fn_words & _OWNED_OUT_WORDS:
        return True
    if fn_words & _BORROWED_OUT_WORDS:
        return False
    return i + 1 < len(params) and is_length_ptr(params[i + 1], _name(formals, i + 1))


def _owned_result(name: str, rec: dict, params: list[dict], formals: list[dict], api: ApiInfo) -> bool:
    """Whether the call returns a heap object its caller frees (rule F)."""
    ret = _return_type(rec)
    if name in api.const_returns or not ret.endswith("*"):
        return False
    fn_words = set(_words(name))
    if bool(fn_words & _OWNED_RESULT_WORDS) and name in api.allocating:
        return True
    # A producer/builder function returning a non-const byte/void pointer that directly calls an
    # allocator, writes no globals, and takes no writable pointer parameter (so it cannot alias an
    # input) returns a freshly allocated buffer the caller owns (e.g. `Crypto_Prepare_TC_AAD`).
    if ret not in _OWNED_BYTE_RET_TYPES:
        return False
    if (rec.get("writes") or {}).get("globals"):
        return False
    direct_alloc = any(isinstance(cs, dict) and cs.get("callee") in ALLOCATORS for cs in (rec.get("call_sites") or []))
    if not direct_alloc:
        return False
    ptr_indices = [k for k, p in enumerate(params) if p["kind"] == "ptr"]
    if not all(_is_input(formals, k) for k in ptr_indices):
        return False
    if fn_words & _OWNED_PRODUCER_WORDS:
        return True
    return not ptr_indices and not (fn_words & (_BORROWED_OUT_WORDS | {"error", "strerror", "name", "str"}))


def _vtable_layout(lay: dict | None) -> bool:
    """
    Whether a struct layout is a table of function pointers (rule G): at least one function pointer,
    and function pointers make at least half of its fields (protobuf-c's `ProtobufCAllocator {alloc,
    free, allocator_data}`, `ProtobufCBuffer {append}`). A struct with one callback among its data
    (`{flags, name, cb, data}`) is not one.
    """
    if not lay or lay.get("what") != "struct":
        return False
    fields = list(lay.get("fields") or [])
    fns = sum(1 for f in fields if f.get("kind") == "fnptr")
    return fns >= 1 and 2 * fns >= len(fields)


def _table_type(api: ApiInfo, p: dict) -> str | None:
    """The table-of-function-pointers struct parameter `p` points to (`_vtable_layout`), or None."""
    pointee = str(p.get("pointee") or "")
    if p["kind"] != "ptr" or not _is_record(pointee) or "*" in pointee:
        return None
    return pointee if _vtable_layout(api.structs.get(pointee)) else None


_SCALAR_SPELLING_RE = re.compile(r"^[A-Za-z_][\w ]*$")


def _table_stub(stub: str, proto: dict[str, Any], field_name: str, allocator: bool) -> str:
    """
    The harness function for a function-pointer field `field_name` of a table (rule G), defined at
    file scope on one line: in an allocator (a table with an allocating field), a field named for
    allocating returns `malloc` of its last integer parameter (`calloc` of two, `realloc` of its last
    pointer and integer), and one named for freeing `free`s its last pointer parameter, so what the
    callee allocates through the table is real heap memory it can free through it. Any other field is
    a `callback_stub`: it writes nothing and returns zero.
    """
    params = list(proto["params"])
    ret = str(proto["ret"])
    ints = [k for k, t in enumerate(params) if "*" not in t and _SCALAR_SPELLING_RE.match(t) and not _is_record(t)]
    ptrs = [k for k, t in enumerate(params) if "*" in t]
    words = set(_words(field_name))
    body: str | None = None
    if ret.rstrip().endswith("*"):
        if words & _TABLE_CALLOC_WORDS and len(ints) >= 2:
            body = f"return ({ret})calloc((size_t)fc_p{ints[-2]}, (size_t)fc_p{ints[-1]});"
        elif words & _TABLE_REALLOC_WORDS and ints and ptrs:
            body = f"return ({ret})realloc((void *)fc_p{ptrs[-1]}, (size_t)fc_p{ints[-1]});"
        elif words & _TABLE_ALLOC_WORDS and ints:
            body = f"return ({ret})malloc((size_t)fc_p{ints[-1]});"
    elif allocator and _spelled(ret) == "void" and words & _TABLE_FREE_WORDS and ptrs:
        body = f"free((void *)fc_p{ptrs[-1]});"
    if body is None:
        return callback_stub(stub, proto)
    decl = ", ".join(f"{t} fc_p{k}" for k, t in enumerate(params)) or "void"
    uses = " ".join(f"(void)fc_p{k};" for k in range(len(params)))
    return f"static {ret} {stub}({decl}) {{ {uses} {body} }} /* {CALLBACK_STUB_MARKER} */"


def _allocating_field(f: dict) -> bool:
    return f.get("kind") == "fnptr" and bool(
        set(_words(f.get("name"))) & (_TABLE_ALLOC_WORDS | _TABLE_CALLOC_WORDS | _TABLE_REALLOC_WORDS)
    )


def _table_arg(case: _Case, call: int, i: int, p: dict, var: str, noted: bool = True) -> str:
    """
    The argument of a pointer to a table of function pointers (rule G, `_table_type`): NULL when the
    headers document NULL as the default for its type (`api.null_defaults`); else an object whose
    function pointers are harness functions (`_table_stub`), its data pointers spare buffers and its
    other fields zero (no input is read: the layout does not move); else the case is refused. A zeroed
    table is never passed: the callee would call a NULL function pointer, a crash only the harness made.
    `noted` False leaves the case's notes alone (a release's table, which the release's note covers).
    """
    api = case.api
    pointee = str(p.get("pointee") or "")
    if pointee in api.null_defaults:
        if noted:
            case.note(
                call, i, f"{pointee}: a table of function pointers the headers document as NULL for the default: NULL"
            )
        return f"({p['type']})0"
    fields = list((api.structs.get(pointee) or {}).get("fields") or [])
    fns = [f for f in fields if f.get("kind") == "fnptr"]
    unspelled = [str(f.get("name")) for f in fns if not f.get("proto")]
    if not api.table_stubs or unspelled:
        why = (
            "no harness function compiles for them (a stub failed)"
            if not api.table_stubs
            else f"the layout probe could not spell {', '.join(unspelled)}"
        )
        raise _CaseError(
            f"{pointee} is a table of function pointers the callee calls through: a zeroed one would be a NULL call "
            f"only the harness makes, no doc comment of the headers says NULL selects a default, and {why}"
        )
    allocator = any(_allocating_field(f) for f in fns)
    elem = p.get("decl") or _anon_record_spelling(api, pointee)
    case.decls.append(f"{elem} {case.declare(var)}; memset(&{var}, 0, sizeof({var}));")
    tag = re.sub(r"\W+", "_", pointee).strip("_")
    for k, f in enumerate(fields):
        if f.get("kind") == "fnptr":
            stub = f"framac_cb_vt_{tag}_{f['name']}"
            api.stubs.setdefault(stub, _table_stub(stub, f["proto"], str(f["name"]), allocator))
            case.decls.append(f"{var}.{f['name']} = {stub};")
        elif f.get("kind") == "ptr":
            buf = case.declare(f"{var}f{k}")
            case.decls.append(f"{_byte_buffer('static ', buf, case.spare)} {var}.{f['name']} = (void *){buf};")
    what = "malloc/free wrappers and no-op stubs" if allocator else "no-op stubs"
    if noted:
        case.note(call, i, f"{pointee}: a table of function pointers, filled with harness functions ({what})")
    return f"&{var}"


def _len_ptr_params(params: list[dict], i: int, formals: list[dict], rec: dict) -> bool:
    """
    Whether parameters `i`, `i + 1` are a length and the byte pointer it counts, in that order
    (protobuf-c's `X__unpack(allocator, size_t len, const uint8_t *data)`): an integer `is_length`
    accepts whose formal name says length (`_LEN_NAME_RE`), then a byte pointer the call only reads,
    with no length after it and no size its call sites give. Bound as a (pointer, length) pair is: a
    length read from the input on its own let the callee read past the harness's buffer.
    """
    if i + 1 >= len(params) or i + 1 >= len(formals):
        return False
    name = _name(formals, i)
    if not name or not _LEN_NAME_RE.search(name) or not is_length(params[i], name):
        return False
    q = params[i + 1]
    if q["kind"] != "ptr" or not _charlike(q) or not isinstance(formals[i + 1], dict):
        return False
    if formals[i + 1].get("kind") != "const_pointer":
        return False
    return param_size(rec, i + 1) is None and not _is_pair(params, i + 1, formals)


def _produced_struct(name: str, rec: dict, params: list[dict], api: ApiInfo) -> str | None:
    """The struct type `name` makes for a destructor that takes tables (`api.producers`), or None."""
    ret = _return_type(rec)
    if not ret.endswith("*"):
        return None
    made = ret[:-1].strip()
    if name not in api.producers.get(made, []) or made not in api.owners:
        return None
    if any(p["kind"] == "ptr" and str(p.get("pointee") or "") == made for p in params):
        return None
    return made


def _produced_object(case: _Case, made: str, var: str, call: int, param: int) -> str:
    """
    `S *var = <producer>(...)` before call `call` (rule G): the object its destructor may free, made
    by the struct's best producer with its arguments by the usual rules (a byte input is the rest of
    the input). The call under test runs only when it is not NULL (the caller's guard).
    """
    fn = case.api.producers[made][0]
    rec = case.api.records.get(fn) or {}
    params, why = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
    if params is None:
        raise _CaseError(f"{fn}, the producer of {made}: {why}")
    k = case.ncalls + len(case.inits)
    case.inits.append({"fn": fn, "call": k, "for": {"call": call, "param": param}})
    stmt = _bind_call(case, k, fn, params, list(rec.get("formals") or []), rec, allow_init=False)
    target = f"(void){fn}("
    if stmt.count(target) != 1:
        raise _CaseError(f"{fn}, the producer of {made}: its call cannot be kept for the call under test")
    spelled = _anon_record_spelling(case.api, made)
    return f"{spelled} *{case.declare(var)} = 0; " + stmt.replace(target, f"{var} = ({spelled} *){fn}(", 1)


def _owner_release(case: _Case, call: int, made: str, expr: str) -> str:
    """The release of object `expr` of `made` by its destructor that takes tables (`api.owners`), each table by `_table_arg`."""
    api = case.api
    fn = api.owners[made]
    rec = api.records.get(fn) or {}
    formals = list(rec.get("formals") or [])
    params, why = plan_params(str(rec.get("signature") or ""), formals)
    if not params:
        raise _CaseError(f"{fn}, the destructor of {made}: {why}")
    args = [f"({params[0]['type']}){expr}"]
    for j in range(1, len(params)):
        if api.trust_schema and _is_nullable_allocator_param(_name(formals, j), params[j]):
            args.append("NULL")
            continue
        if _table_type(api, params[j]) is None:
            raise _CaseError(f"{fn}, the destructor of {made}: argument {j} is not a table of function pointers")
        args.append(_table_arg(case, call, j, params[j], f"c{call}d{j}", noted=False))
    return f"(void){fn}({', '.join(args)});"


def _range_partner(a: str | None, b: str | None) -> bool:
    """Whether formals `a` and `b` are the bounds of one range, `a` the lower (rule A)."""
    wa, wb = _words(a), _words(b)
    if not wa or len(wa) != len(wb):
        return False
    diff = [(x, y) for x, y in zip(wa, wb, strict=True) if x != y]
    return len(diff) == 1 and diff[0] in _RANGE_WORDS


def _domain_rules(
    case: _Case,
    call: int,
    name: str,
    params: list[dict],
    formals: list[dict],
    scalars: dict[int, str],
    pairs: list[tuple[int, str, bool]],
) -> None:
    """
    Rules A-D (see `_RANGE_WORDS` and below) on the arguments of one call, once all of them are read:
    statements appended to the case's declarations (after every input slot, before the call), or to
    its `post` statements for a length that is the rest of the input. `scalars` maps a parameter read
    as one scalar to its variable; `pairs` lists each byte (pointer, length) pair as (pointer index,
    length expression, whether the length is the rest of the input).
    """

    def plain(k: int) -> bool:
        p = params[k]
        return p["kind"] in ("int", "float") and not p.get("enum") and p.get("ctype") != "_Bool"

    # A: ordered bounds.
    taken: set[int] = set()
    for i in sorted(scalars):
        for j in sorted(scalars):
            if j <= i or i in taken or j in taken or not (plain(i) and plain(j)):
                continue
            if params[i]["ctype"] != params[j]["ctype"] or not _range_partner(_name(formals, i), _name(formals, j)):
                continue
            a, b, ct = scalars[i], scalars[j], params[i]["ctype"]
            if params[i]["kind"] == "float":
                case.decls.append(f"if ({a} != {a}) {{ {a} = 0; }} if ({b} != {b}) {{ {b} = {a}; }}")
            case.decls.append(f"if ({b} < {a}) {{ {ct} fc_t = {a}; {a} = {b}; {b} = fc_t; }}")
            case.note(
                call,
                j,
                f"range bound: ordered after argument {i} (the API requires {_name(formals, i)} <= {_name(formals, j)})",
            )
            taken |= {i, j}
    # A': a lone bound forwarded to a range-like callee with a constant other bound (`bound_forwards`).
    for k, (op, const) in sorted((case.api.bounds.get(name) or {}).items()):
        if k not in scalars or k in taken or not plain(k):
            continue
        num = _number(const)
        if num is None or (str(params[k]["ctype"]).startswith("unsigned") and num <= 0):
            continue  # an unsigned value is never below 0, and a negative constant does not fit it
        v = scalars[k]
        if params[k]["kind"] == "float":
            case.decls.append(f"if ({v} != {v}) {{ {v} = {const}; }}")
        cmp = "<" if op == ">=" else ">"
        case.decls.append(f"if ({v} {cmp} {const}) {{ {v} = {const}; }}")
        side = "upper" if op == ">=" else "lower"
        case.note(
            call,
            k,
            f"range bound: forwarded as the {side} bound of a range whose other bound is {const}: kept {op} {const}",
        )
    lengths = {i + 1: (ln, rest) for i, ln, rest in pairs}
    # B: a NUL-terminated output's capacity; a limit of an initializer or a limit setter.
    if set(_words(name)) & _CSTR_WORDS:
        for i, ln, rest in pairs:
            if not rest and not _is_input(formals, i):
                case.decls.append(f"if ({ln} < 1) {{ {ln} = 1; }}")
                case.note(call, i + 1, "capacity of a NUL-terminated output: at least 1 (room for the terminator)")
    limits = case.api.limits.get(name) or set()
    if limits:
        ints = {**scalars, **{k: ln for k, (ln, rest) in lengths.items() if not rest}}
        for k in sorted(ints):
            if _name(formals, k) in limits and params[k]["kind"] == "int" and plain(k):
                case.decls.append(f"if ({ints[k]} < 1) {{ {ints[k]} = 1; }}")
                case.note(call, k, "limit of a limit setter: at least 1")
    # C: (buffer, size, count) of an initializer.
    for i, ln, rest in pairs if _INIT_NAME_RE.search(name) else []:
        c = i + 2
        if c not in scalars or not plain(c) or not is_length(params[c], _name(formals, c)):
            continue
        if not set(_words(_name(formals, i + 1))) & _TRIPLE_SIZE_WORDS:
            continue
        if not set(_words(_name(formals, c))) & _TRIPLE_COUNT_WORDS:
            continue
        v, ct = scalars[c], params[c]["ctype"]
        stmt = f"if ((unsigned long long){v} > (unsigned long long){ln}) {{ {v} = ({ct}){ln}; }}"
        (case.post if rest else case.decls).append(stmt)
        case.note(call, c, f"count of a (buffer, size, count) triple: at most argument {i + 1}")
    # D: an enum by value is one of its declared constants.
    for k in sorted(scalars):
        if not params[k].get("enum"):
            continue
        names = (case.api.enum_params.get(name) or {}).get(k)
        if not names:
            case.note(
                call,
                k,
                "enum: its declared constants are not known (no layout probe, a flag enum, or not in the headers): passed as read",
            )
            continue
        v, ct, n = scalars[k], params[k]["ctype"], len(names)
        # A plain disjunction, which Eva narrows the value by, unlike a loop over the table.
        member = " || ".join(f"(long long){v} == (long long){c}" for c in names)
        case.decls.append(
            f"if (!({member})) {{ static const long long fc_e[{n}] = {{ {', '.join(names)} }}; "
            f"{v} = ({ct})fc_e[(unsigned int){v} % {n}U]; }}"
        )
        case.note(call, k, f"enum: a value none of its {n} declared constants is mapped onto one")


def _realloc_rules(
    case: _Case, call: int, scalars: dict[int, str], params: list[dict], used: list[int], new: list[int]
) -> None:
    """Rule E's sizes: each new size in 1..spare, then each used size within the old allocation and every new size."""
    spare = case.spare
    new = [k for k in new if k in scalars]
    used = [k for k in used if k in scalars]
    for k in new:
        v, ct = scalars[k], params[k]["ctype"]
        case.decls.append(
            f"if ({v} < 1 || (unsigned long long){v} > {spare}ULL) {{ {v} = ({ct})(1ULL + (unsigned long long){v} % {spare}ULL); }}"
        )
        case.note(call, k, f"new size of a realloc-like call: in 1..{spare}")
    for k in used:
        v, ct = scalars[k], params[k]["ctype"]
        case.decls.append(f"if ((unsigned long long){v} > {REALLOC_OLD_BYTES}ULL) {{ {v} = {REALLOC_OLD_BYTES}; }}")
        for m in new:
            case.decls.append(
                f"if ((unsigned long long){v} > (unsigned long long){scalars[m]}) {{ {v} = ({ct}){scalars[m]}; }}"
            )
        case.note(
            call,
            k,
            f"used size of a realloc-like call: within the {REALLOC_OLD_BYTES}-byte old allocation and the new size",
        )


def _scalar_array(p: dict) -> bool:
    """A pointer to a non-byte arithmetic scalar (`uint16_t *`, `int *`, `float *`): no struct, enum, `_Bool` or pointer."""
    pointee = str(p.get("pointee") or "")
    return (
        p["kind"] == "ptr"
        and not _charlike(p)
        and pointee in SCALAR_BYTES
        and pointee != "_Bool"
        and not p.get("anon_enum")
    )


def _indexed_scalars(params: list[dict], formals: list[dict]) -> set[int]:
    """
    The integer parameters that index a buffer the call gets with no length beside it (libmodbus's
    `modbus_set_bits_from_bytes(uint8_t *dest, int idx, unsigned int nb_bits, const uint8_t *tab_byte)`,
    `modbus_read_bits(ctx, int addr, int nb, uint8_t *dest)`): named as an element count
    (`_ARRAY_COUNT_RE`) or an index (`_INDEX_WORDS`), at least two bytes wide, not an enum. None when
    the call takes a (buffer, length) pair or an array and its count: the callee can check an index
    against that length, and a missing check is its bug, not the harness's.
    """
    if any(_is_pair(params, i, formals) or _array_count(params, i, formals) is not None for i in range(len(params))):
        return set()
    out: set[int] = set()
    for i, p in enumerate(params):
        if p["kind"] != "int" or p.get("enum") or p.get("anon_enum") or SCALAR_BYTES.get(p.get("ctype") or "", 0) < 2:
            continue
        name = _name(formals, i)
        if name and (_ARRAY_COUNT_RE.search(name) or set(_words(name)) & _INDEX_WORDS):
            out.add(i)
    return out


def _index_rules(
    case: _Case, call: int, params: list[dict], scalars: dict[int, str], indexed: set[int], bare: list[str]
) -> None:
    """
    Keep each count or index of a call (`_indexed_scalars`) within half of the smallest buffer the
    harness made for it with no length (`bare`: element counts as C expressions), so an index plus a
    count stays inside every buffer. With no length the callee cannot check them: the caller's
    contract says they fit, and a value past the buffer is a crash only the harness makes (libmodbus
    run-1: `modbus_get_byte_from_bits(src, idx, nb_bits)` read `src[idx + i]` for any `idx`). A value
    within the bound is passed as read and a negative one becomes the bound; no slot moves.
    """
    if not bare:
        return
    m = bare[0]
    for x in bare[1:]:
        m = f"({m} < {x} ? {m} : {x})"
    limit = f"{m} / 2ULL"
    for k in sorted(indexed):
        v = scalars.get(k)
        if v is None:
            continue
        ct = params[k]["ctype"]
        case.decls.append(f"if ((unsigned long long){v} > {limit}) {{ {v} = ({ct})({limit}); }}")
        case.note(call, k, "count or index into a buffer of no length: within half of its elements")


@dataclass
class _EntryTrust:
    """Resolved per-function threat-model metadata (S1, FRAMAC_API_TRUST_SCHEMA)."""

    input_role: str | None = None
    attacker_params: list[str] | None = None
    trusted_caller: bool = False


def _match_tm_ref(ref: str, key: str, name: str) -> bool:
    if not ref:
        return False
    if "#" in ref:
        return ref == key or ref.endswith(f"#{name}") and key.endswith(f"#{name}") and ref == key
    return ref == name or ref == key


def _resolve_threat_model(
    dag: dict,
    model: dict,
    trust: dict[str, Any] | None = None,
    unit: str | None = None,
) -> tuple[bool, dict[str, _EntryTrust]]:
    """
    Resolve active threat-model status and per-entry trust roles (S1, FRAMAC_API_TRUST_SCHEMA).
    Reads per-function `trust.input_role` / `trust.attacker_params` / `trust.value` from DAG or
    model records first, and falls back to `trust["threat_model"]["input_sources"]` or the recorded
    `THREAT_MODEL.md` file when a pre-existing DAG does not carry per-function `input_role` yet.
    """
    explicit: dict[str, Any] = trust if isinstance(trust, dict) else {}
    raw_dag_trust = dag.get("trust")
    dag_trust: dict[str, Any] = raw_dag_trust if isinstance(raw_dag_trust, dict) else {}
    raw_model_trust = model.get("trust")
    model_trust: dict[str, Any] = raw_model_trust if isinstance(raw_model_trust, dict) else {}
    tm_info: dict[str, Any] = {}
    for src in (explicit, dag_trust, model_trust):
        cand = src.get("threat_model")
        if isinstance(cand, dict) and cand.get("status"):
            tm_info = cand
            break
    if tm_info.get("status") != "ok":
        return False, {}

    fallback_sources: list[dict[str, Any]] = []
    fallback_trusted: list[dict[str, Any]] = []
    if isinstance(tm_info.get("input_sources"), list):
        fallback_sources = [x for x in tm_info["input_sources"] if isinstance(x, dict)]
    elif isinstance(explicit.get("input_sources"), list):
        fallback_sources = [x for x in explicit["input_sources"] if isinstance(x, dict)]
    if isinstance(tm_info.get("trusted_callers"), list):
        fallback_trusted = [x for x in tm_info["trusted_callers"] if isinstance(x, dict)]
    elif isinstance(explicit.get("trusted_callers"), list):
        fallback_trusted = [x for x in explicit["trusted_callers"] if isinstance(x, dict)]

    if not fallback_sources and isinstance(tm_info.get("path"), str) and tm_info["path"]:
        tm_path = Path(tm_info["path"])
        if tm_path.is_file():
            try:
                import trust as trust_mod

                loaded = trust_mod.load_threat_model(tm_path)
                want_sha = tm_info.get("sha256")
                if loaded.get("status") == "ok" and (not want_sha or loaded.get("sha256") == want_sha):
                    block = loaded.get("block") or {}
                    if isinstance(block.get("input_sources"), list):
                        fallback_sources = [x for x in block["input_sources"] if isinstance(x, dict)]
                    if isinstance(block.get("trusted_callers"), list):
                        fallback_trusted = [x for x in block["trusted_callers"] if isinstance(x, dict)]
            except Exception:  # noqa: BLE001 - fall back to per-function trust records
                pass

    dag_fns = dag.get("functions") or {}
    raw_explicit_fns = explicit.get("functions")
    explicit_fns: dict[str, Any] = raw_explicit_fns if isinstance(raw_explicit_fns, dict) else {}

    def _is_in_fallback_trusted(key: str, name: str) -> bool:
        for item in fallback_trusted:
            if "functions" in item:
                if any(_match_tm_ref(str(r), key, name) for r in item.get("functions") or []):
                    return True
            elif "unit" in item and unit:
                u_ref = str(item.get("unit") or "")
                if u_ref == unit or Path(unit).name == u_ref:
                    exc = item.get("except") or []
                    if not any(_match_tm_ref(str(r), key, name) for r in exc):
                        return True
        return False

    def _fallback_source(key: str, name: str) -> dict[str, Any] | None:
        for item in fallback_sources:
            if _match_tm_ref(str(item.get("function") or ""), key, name):
                return item
        return None

    roles: dict[str, _EntryTrust] = {}
    for key, drec in dag_fns.items():
        if not isinstance(drec, dict):
            continue
        name = str(drec.get("name") or str(key).split("#")[-1])
        mrec = _model_record(model, drec, key)
        ftrust: dict[str, Any] = {}
        for cand_t in (
            drec.get("trust"),
            mrec.get("trust") if isinstance(mrec, dict) else None,
            explicit_fns.get(key),
            explicit_fns.get(name),
        ):
            if isinstance(cand_t, dict):
                ftrust = {**cand_t, **ftrust}
        trusted_caller = (
            ftrust.get("value") == "trusted" and ftrust.get("source") == "threat_model"
        ) or _is_in_fallback_trusted(key, name)
        input_role: str | None = str(ftrust["input_role"]) if ftrust.get("input_role") in ("entry", "reader") else None
        attacker_params: list[str] | None = (
            [str(p) for p in ftrust["attacker_params"]] if isinstance(ftrust.get("attacker_params"), list) else None
        )
        if input_role is None:
            fb = _fallback_source(key, name)
            if fb is not None and fb.get("role") in ("entry", "reader"):
                input_role = str(fb["role"])
                if attacker_params is None and isinstance(fb.get("params"), list):
                    attacker_params = [str(p) for p in fb["params"]]
        elif attacker_params is None:
            fb = _fallback_source(key, name)
            if fb is not None and isinstance(fb.get("params"), list):
                attacker_params = [str(p) for p in fb["params"]]
        roles[key] = _EntryTrust(
            input_role=input_role,
            attacker_params=attacker_params,
            trusted_caller=trusted_caller,
        )
    return True, roles


def _merge_global_variables(
    model: dict,
    dag: dict,
    explicit: dict[str, dict] | None = None,
) -> dict[str, dict[str, Any]]:
    """Merge global_variables from model, DAG, and explicit override, keeping richest fields."""
    merged: dict[str, dict[str, Any]] = {}
    for source in (dag.get("global_variables"), model.get("global_variables"), explicit):
        if not isinstance(source, dict):
            continue
        for gid, g in source.items():
            if not isinstance(g, dict):
                continue
            prev = merged.get(gid) or {}
            merged[gid] = {**prev, **{k: v for k, v in g.items() if v is not None}}
    return merged


def _schema_rank_key(g: dict[str, Any]) -> tuple[int, int, str]:
    size = int(g.get("size") or 0) if isinstance(g.get("size"), int) else 0
    raw_fields = g.get("field_count")
    if isinstance(raw_fields, int):
        richness = raw_fields
    else:
        richness = len(g.get("init_globals") or []) + len(g.get("init_functions") or [])
    return (-size, -richness, str(g.get("name") or ""))


def _schema_instances_index(
    global_variables: dict[str, dict[str, Any]],
    unit: str | None = None,
    unit_links: Collection[str] | None = None,
    anon_tags: dict[str, str] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    """
    S3: index eligible const, initialized, non-static global schema instances by canonical and raw
    type name (`pb_msgdesc_t`, `struct pb_msgdesc_s`, `ProtobufCMessageDescriptor`, ...).
    Ranked by largest `size`, then most init/field references, then deterministically by name, and
    capped at `MAX_SCHEMA_INSTANCES`.
    """
    allowed_units = ({unit, *(unit_links or ())} - {None, ""}) if unit else set()
    typedef_to_tags: dict[str, list[str]] = {}
    for tag, tdef in (anon_tags or {}).items():
        typedef_to_tags.setdefault(_spelled(tdef), []).append(_spelled(tag))

    buckets: dict[str, dict[str, dict[str, Any]]] = {}
    for gid, g in sorted(global_variables.items()):
        if not isinstance(g, dict):
            continue
        if g.get("const") is not True or g.get("has_init") is not True or g.get("static"):
            continue
        name = str(g.get("name") or gid.split("#")[-1])
        if not _IDENT_RE.fullmatch(name):
            continue
        g_units = [str(u) for u in g.get("units") or [] if u]
        if allowed_units and g_units and not (set(g_units) & allowed_units):
            continue
        raw_t = str(g.get("raw_type") or "").strip()
        canon_t = str(g.get("type") or "").strip()
        if any("[" in t or "*" in t or "(" in t for t in (raw_t, canon_t) if t):
            continue
        keys: set[str] = set()
        for t in (canon_t, raw_t):
            norm = _spelled(t)
            if norm:
                keys.add(norm)
                for tag in typedef_to_tags.get(norm, []):
                    keys.add(tag)
        if not keys:
            continue
        rec = {**g, "name": name}
        for k in keys:
            buckets.setdefault(k, {})[name] = rec
    return {k: sorted(items.values(), key=_schema_rank_key)[:MAX_SCHEMA_INSTANCES] for k, items in buckets.items()}


def _lookup_schema_instances_raw(
    schema_globals: dict[str, list[dict[str, Any]]],
    pointee: str,
    decl: str | None = None,
    anon_tags: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    keys: list[str] = []
    for cand in (pointee, decl or "", (anon_tags or {}).get(pointee, "")):
        norm = _spelled(cand)
        if norm and norm not in keys:
            keys.append(norm)
    found: dict[str, dict[str, Any]] = {}
    for k in keys:
        for inst in schema_globals.get(k) or []:
            found.setdefault(str(inst["name"]), inst)
    return sorted(found.values(), key=_schema_rank_key)[:MAX_SCHEMA_INSTANCES]


def _lookup_schema_instances(api: ApiInfo, pointee: str, decl: str | None = None) -> list[dict[str, Any]]:
    return _lookup_schema_instances_raw(api.schema_globals, pointee, decl, api.anon_tags)


def _record_schema_extern(api: ApiInfo, inst: dict[str, Any], pointee: str, decl: str | None = None) -> None:
    """Record a file-scope `extern const <T> <name>;` declaration for a bound S3 schema global."""
    name = str(inst.get("name") or "")
    if not name or not _IDENT_RE.fullmatch(name) or name in api.schema_externs:
        return
    raw_t = " ".join(str(inst.get("raw_type") or "").split())
    if raw_t and "__anon" not in raw_t and not any(c in raw_t for c in "[]()*"):
        if re.search(r"\bconst\b", raw_t):
            api.schema_externs[name] = f"extern {raw_t} {name};"
        else:
            api.schema_externs[name] = f"extern const {raw_t} {name};"
        return
    t = " ".join(str(decl or api.anon_tags.get(pointee) or pointee).split())
    if t and "__anon" not in t and not any(c in t for c in "[]()*"):
        api.schema_externs[name] = f"extern const {t} {name};"


def _is_refcount_without_producer(name: str, params: list[dict], api: ApiInfo) -> bool:
    """
    Skip standalone single cases for refcount helpers (`*_addref`, `*_delref`, `*_unref`, `*_decref`)
    whose pointer parameter has no producer/initializer (`container_of` / refcounted string or struct).
    """
    if not api.trust_schema or not _REFCOUNT_NAME_RE.search(name):
        return False
    handles = api.handles.get(name) or {}
    for i, p in enumerate(params):
        if p["kind"] != "ptr":
            continue
        htype = handles.get(i)
        if htype is not None and _constructible(api, htype) and _releasable(api, htype):
            return False
        if _charlike(p):
            return True
        pointee = str(p.get("pointee") or "")
        if _is_record(pointee) and "*" not in pointee:
            if pointee in api.inits or bool(api.producers.get(pointee)):
                return False
            return True
        return False
    return False


def _param_roles(
    params: list[dict],
    formals: list[dict],
    rec: dict,
    api: ApiInfo,
    entry_trust: _EntryTrust,
) -> list[str]:
    """
    S1/S2 per-parameter roles when a threat model is active:
      - `attacker`: fuzzed as today (or built via an S2 byte-taking builder);
      - `caller_storage`: trusted caller-owned writable buffer struct (`{ptr, len}` / `{len, ptr}`
        with a single writable byte/void pointer and length) or writable `(void */byte *, size_t)`
        scratch pair -> backed by a fixed `_Alignas(16)` harness array;
      - `caller_storage_len`: trusted length integer paired with a `caller_storage` pointer -> set
        to `sizeof(<var>_buf)` (zeroed if standalone);
      - `trusted`: pointer/struct not in `attacker_params` -> ONLY S3 schema instance or S2 builder
        (a read-only NUL-terminated string: a fixed literal, `_is_trusted_cstring`), else skipped
        with `"trusted parameter <name> has no instance"`;
      - `output`: non-const writable buffer or scalar out-parameter -> clean zeroed buffer;
      - `trusted_scalar`: scalar not in `attacker_params` -> zeroed without fuzz slot.
    """
    n = len(params)
    if entry_trust.input_role == "entry":
        if entry_trust.attacker_params is None:
            return ["attacker"] * n
        att = set(entry_trust.attacker_params)
        roles: list[str] = []
        for i, p in enumerate(params):
            fname = _name(formals, i)
            is_in = _is_input(formals, i)
            if fname in att:
                roles.append("attacker")
            elif (
                i > 0
                and (_is_pair(params, i - 1, formals) or _is_buf_len_ptr_pair(params, i - 1, formals))
                and _name(formals, i - 1) in att
            ):
                roles.append("attacker")
            elif i + 1 < n and _len_ptr_params(params, i, formals, rec) and _name(formals, i + 1) in att:
                roles.append("attacker")
            elif (
                i > 0
                and roles[i - 1] == "caller_storage"
                and _is_caller_storage_pair(params, i - 1, formals, rec, api)
            ):
                roles.append("caller_storage_len")
            elif p["kind"] == "struct":
                ctype = str(p.get("ctype") or "")
                if _writable_buffer_struct_fields(api.structs.get(ctype)) is not None:
                    roles.append("caller_storage")
                else:
                    roles.append("trusted")
            elif p["kind"] == "ptr":
                pointee = str(p.get("pointee") or "")
                if (_is_record(pointee) and "*" not in pointee) or is_in:
                    roles.append("trusted")
                elif _is_caller_storage_pair(params, i, formals, rec, api):
                    roles.append("caller_storage")
                else:
                    roles.append("output")
            elif p["kind"] == "fnptr":
                roles.append("trusted")
            else:
                roles.append("trusted_scalar")
        return roles
    if entry_trust.input_role == "reader":
        att = set(entry_trust.attacker_params) if entry_trust.attacker_params is not None else set()
        roles = []
        for i, p in enumerate(params):
            fname = _name(formals, i)
            is_in = _is_input(formals, i)
            if fname in att:
                roles.append("attacker")
            elif p["kind"] == "ptr" and str(p.get("pointee") or "") in api.inits:
                roles.append("attacker")
            elif p["kind"] == "struct" and str(p.get("ctype") or "") in api.inits:
                roles.append("attacker")
            elif (
                p["kind"] == "struct"
                and _writable_buffer_struct_fields(api.structs.get(str(p.get("ctype") or ""))) is not None
            ):
                roles.append("caller_storage")
            elif p["kind"] == "ptr" and not is_in:
                if _is_caller_storage_pair(params, i, formals, rec, api):
                    roles.append("caller_storage")
                else:
                    roles.append("output")
            elif p["kind"] == "ptr" and _is_record(str(p.get("pointee") or "")) and is_in:
                roles.append("trusted")
            else:
                roles.append("attacker")
        return roles
    return ["attacker"] * n


def _bind_call(
    case: _Case,
    call: int,
    name: str,
    params: list[dict],
    formals: list[dict],
    rec: dict,
    shared: dict[int, str] | None = None,
    allow_init: bool = True,
    extra_args: list[str] | None = None,
    entry_trust: _EntryTrust | None = None,
    schema_bindings: dict[int, tuple[str, bool]] | None = None,
    builder_schema: dict[int, dict[str, Any]] | None = None,
    builder_rest: bool = False,
) -> str:
    """
    The declarations and slots of one call's arguments (added to `case`); returns the call statement,
    preceded by the initializer calls of its struct objects. `extra_args` follow the arguments built
    from `params` as they are (the objects behind a variadic call, `variadic_case`).
    """
    shared = shared or {}
    schema_bindings = schema_bindings or {}
    builder_schema = builder_schema or {}
    params = _respell_anon_records(case.api, _respell_enum_pointers(case.api, name, params))
    params = _respell_qualified_pointers(case.api, name, params)
    api = case.api
    if allow_init and _is_refcount_without_producer(name, params, api):
        raise _AutoExempt(REFCOUNT_EXEMPT_REASON)
    roles = (
        _param_roles(params, formals, rec, api, entry_trust) if (api.trust_schema and entry_trust is not None) else None
    )
    target_claims_rest = (
        api.trust_schema
        and allow_init
        and _target_claims_rest(name, params, formals, rec, api, shared, roles, schema_bindings, entry_trust)
    )
    varlen = _variable_length(params, formals, rec, shared, name=name, api=api, roles=roles, entry_trust=entry_trust)
    args: list[str] = []
    before: list[str] = []
    after: list[str] = []
    guards: list[str] = []
    bound_handles: set[int] = set()  # parameters a handle constructor built (released as handles)
    handles = api.handles.get(name) or {}
    outs = api.outs.get(name) or {}
    # Argument domains (`_domain_rules`): the variables of the scalars and byte pairs read for this call.
    scalars: dict[int, str] = {}
    pairs: list[tuple[int, str, bool]] = []
    owned_outs: list[str] = []
    global_heap_vars: list[str] = []
    realloc = _realloc_like(name, params, formals, rec, api) if allow_init and 0 not in shared else None
    realloc_old: str | None = None
    # `_index_rules`: the element counts of the buffers the harness made with no length beside them,
    # and the count- and index-named scalars that index them.
    bare: list[str] = []
    indexed = _indexed_scalars(params, formals)
    i = 0
    n = len(params)
    while i < n:
        p = params[i]
        v = f"c{call}a{i}"
        nxt = params[i + 1] if i + 1 < n else None
        role = roles[i] if roles is not None else None
        if i in schema_bindings:
            gname, by_ref = schema_bindings[i]
            if case.schema_instance is None:
                case.schema_instance = gname
            case.note(call, i, f"trusted parameter: const schema instance {gname}")
            args.append(f"&{gname}" if by_ref else gname)
            i += 1
            continue
        if role in ("trusted_scalar", "caller_storage_len"):
            case.decls.append(f"{p['ctype']} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
            recorded = (
                (api.trusted_scalars.get(name) or {}).get(i)
                if case.recorded_scalars and p["kind"] == "int" and p.get("ctype") != "_Bool"
                else None
            )
            if recorded:
                # QCBOR run-1: a zeroed `uType` made `EnterBoundedMapOrArray` enter nothing in a chain.
                _recorded_scalar_arg(case, call, i, p, v, recorded)
            else:
                case.note(call, i, "trusted scalar parameter per threat model: zeroed, not read from the input")
            args.append(v)
            i += 1
            continue
        if (
            api.trust_schema
            and role == "trusted"
            and p["kind"] == "ptr"
            and i not in shared
            and _is_nullable_allocator_param(_name(formals, i), p)
        ):
            case.note(call, i, "trusted nullable default allocator parameter: NULL")
            args.append("NULL")
            i += 1
            continue
        if api.trust_schema and i not in shared and _is_trusted_cstring(params, formals, rec, i, roles):
            # QCBOR run-1: a label the application chooses (`const char *szLabel`) is a literal it
            # could pass, never fuzz bytes; without it the entry point was exempted unreached.
            args.append(_trusted_string_arg(case, call, i, p, name))
            i += 1
            continue
        htype = handles.get(i) if i not in shared and p["kind"] == "ptr" else None
        # A pointer to a struct the headers only declare is a handle or nothing: never a stack object.
        if htype is not None and (allow_init or _opaque(htype)):
            same = sum(1 for t in handles.values() if t == htype)
            if not allow_init or not _constructible(api, htype):
                if _opaque(htype):
                    raise _Unbuildable(f"no constructor for opaque handle {htype}")
            elif not _releasable(api, htype):
                if _opaque(htype):
                    raise _Unbuildable(f"no destructor for opaque handle {htype}")
                case.note(call, i, f"{htype}: no destructor known: a zeroed buffer, not a constructed handle")
            elif same > 1:
                why = f"{htype}: the call takes {same} such handles and who owns them afterwards is not known"
                if _opaque(htype):
                    raise _Unbuildable(why)
                case.note(call, i, f"{why}: zeroed buffers, not constructed handles")
            else:
                # A handle: the constructor's result, released afterwards unless this call is the release.
                made_here, release, parents_release, guard = _construct(case, htype, v, call, i, caller_name=name)
                bound_handles.add(i)
                before += made_here
                if guard:
                    guards.append(guard)
                if release and name in api.dtor_names.get(htype, set()):
                    # The call under test is a destructor: nothing after it, or only the freeing
                    # destructor after the handle's `close`.
                    release = _handle_release(api, htype, v, name)
                if release:
                    after.append(release)
                after += parents_release
                args.append(f"({p['type']}){v}")
                i += 1
                continue
        out_h = outs.get(i) if i not in shared and p["kind"] == "ptr" and not _is_input(formals, i) else None
        if out_h is not None:
            # A handle the call writes (`H **`): a NULL handle, its address passed. A constructor's own
            # case releases what it built; another function's output may be borrowed, and a child's
            # parent owns it, so neither is released.
            case.decls.append(f"{out_h} {case.declare(v)} = 0;")
            args.append(f"({p['type']})&{v}")
            out_release = _handle_release(api, out_h, v)
            if allow_init and name in api.out_ctor_names.get(out_h, set()) and out_release:
                after.append(out_release)
            i += 1
            continue
        if i in shared:
            if i == 0 and p["kind"] == "ptr" and name in api.owner_names.get(str(p.get("pointee") or ""), set()):
                # Rule G: a buffer a recorded chain shares is no object the destructor's producer made.
                raise _CaseError(
                    f"{name} frees its argument: a buffer the harness shares is no object its producer made"
                )
            args.append(f"({p['type']}){shared[i]}")
            if nxt is not None and (i + 1) not in shared and _is_pair(params, i, formals):
                sh_in = (
                    role not in ("output", "caller_storage", "trusted")
                    and param_size(rec, i) is None
                    and (
                        _is_input(formals, i)
                        or _is_nonconst_input_buf(name, params, i, formals, api, role=role, entry_trust=entry_trust)
                    )
                )
                ln = f"c{call}a{i + 1}"
                if sh_in and case.rest is None:
                    case.decls.append(f"{nxt['ctype']} {case.declare(ln)} = 0;")
                    case.rest = {"call": call, "param": i, "kind": "bytes"}
                    cap = _len_cap_expr(nxt["ctype"], f"sizeof({shared[i]})")
                    case.post.append(
                        f"{{ size_t rest_n = (fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U; "
                        f"if (rest_n > {cap}) {{ rest_n = {cap}; }} "
                        f"if (rest_n > 0) {{ memcpy({shared[i]}, {FUZZ_COPY}, rest_n); }} "
                        f"{ln} = ({nxt['ctype']})rest_n; }}"
                    )
                    case.note(call, i, "shared input buffer: copied from the rest of the input")
                    args.append(ln)
                    pairs.append((i, ln, True))
                else:
                    # The length of a shared buffer: from the input, clamped to that buffer.
                    case.decls.append(f"{nxt['ctype']} {case.declare(ln)}; memset(&{ln}, 0, sizeof({ln}));")
                    case.slot(ln, SCALAR_BYTES.get(nxt["ctype"]), call, i + 1, "int")
                    case.decls.append(
                        f"if ((unsigned long long){ln} > sizeof({shared[i]})) {{ {ln} = ({nxt['ctype']})sizeof({shared[i]}); }}"
                    )
                    args.append(ln)
                    pairs.append((i, ln, False))
                i += 2
                continue
            if nxt is not None and (i + 1) not in shared and _is_buf_len_ptr_pair(params, i, formals):
                sh_lp_in = role not in ("output", "caller_storage", "trusted") and (
                    _is_input(formals, i)
                    or _is_nonconst_input_buf(
                        name, params, i, formals, api, role=role, entry_trust=entry_trust, is_len_ptr=True
                    )
                )
                if sh_lp_in:
                    lpt = str(nxt.get("pointee") or "int")
                    ln = f"c{call}a{i + 1}"
                    if case.rest is None and param_size(rec, i) is None:
                        case.decls.append(f"{lpt} {case.declare(ln)} = 0;")
                        case.rest = {"call": call, "param": i, "kind": "bytes"}
                        cap = _len_cap_expr(lpt, f"sizeof({shared[i]})")
                        case.post.append(
                            f"{{ size_t rest_n = (fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U; "
                            f"if (rest_n > {cap}) {{ rest_n = {cap}; }} "
                            f"if (rest_n > 0) {{ memcpy({shared[i]}, {FUZZ_COPY}, rest_n); }} "
                            f"{ln} = ({lpt})rest_n; }}"
                        )
                        case.note(
                            call, i, "shared input buffer with pointer-to-length: copied from the rest of the input"
                        )
                        args.append(f"({nxt['type']})&{ln}")
                        pairs.append((i, ln, True))
                    else:
                        case.decls.append(f"{lpt} {case.declare(ln)}; memset(&{ln}, 0, sizeof({ln}));")
                        case.slot(ln, SCALAR_BYTES.get(lpt), call, i + 1, "int")
                        case.decls.append(
                            f"if ((unsigned long long){ln} > sizeof({shared[i]})) {{ {ln} = ({lpt})sizeof({shared[i]}); }}"
                        )
                        args.append(f"({nxt['type']})&{ln}")
                        pairs.append((i, ln, False))
                    i += 2
                    continue
            i += 1
            continue
        if p["kind"] == "int" and (i + 1) not in shared and _len_ptr_params(params, i, formals, rec):
            # A length before the byte pointer it counts (`X__unpack(allocator, len, data)`): the rest of
            # the input, as a (pointer, length) pair; else a spare buffer and a length clamped to it.
            q = params[i + 1]
            if case.rest is None:
                case.rest = {"call": call, "param": i + 1, "kind": "bytes"}
                if builder_rest:
                    empty_var = case.declare(f"{v}_empty")
                    case.decls.append(f"static uint8_t {empty_var}[1] = {{0}};")
                    args.append(f"({p['type']})((fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U)")
                    args.append(f"({q['type']})((fuzz_len > fuzz_off) ? (fuzz_buf + fuzz_off) : {empty_var})")
                else:
                    args.append(f"({p['type']})(fuzz_len - fuzz_off)")
                    args.append(f"({q['type']})(fuzz_buf + fuzz_off)")
                case.note(call, i, "length before the byte pointer it counts: the rest of the input")
            else:
                dv = f"c{call}a{i + 1}"
                case.decls.append(f"{p['ctype']} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
                case.slot(v, SCALAR_BYTES.get(p["ctype"]), call, i, "int")
                case.decls.append(_byte_buffer(_storage(None), case.declare(dv), case.spare))
                case.decls.append(
                    f"if ((unsigned long long){v} > {case.spare}ULL) {{ {v} = ({p['ctype']}){case.spare}; }}"
                )
                args += [v, f"({q['type']}){dv}"]
                case.note(call, i, "length before the byte pointer it counts: clamped to a zeroed spare buffer")
            i += 2
            continue
        if p["kind"] == "fnptr":
            proto = (case.api.callbacks.get(name) or {}).get(i)
            if proto is not None:
                # A NULL callback crashes a function that calls it unchecked: a crash only the harness made.
                stub = f"framac_cb_{name}_{i}"
                case.api.stubs.setdefault(stub, callback_stub(stub, proto))
                case.note(call, i, f"function pointer: {stub}, a stub that writes nothing and returns zero")
                args.append(stub)
            else:
                case.note(
                    call, i, "function pointer: NULL (no callback stub: no layout probe, or its prototype not spelled)"
                )
                args.append("0")
            i += 1
            continue
        if p["kind"] == "ptr" and i == 0 and realloc is not None:
            # Rule E: the old pointer of a realloc-like call is the harness's own allocation.
            realloc_old = case.declare(v)
            case.decls.append(
                f"unsigned char *{v} = (unsigned char *)malloc({REALLOC_OLD_BYTES}); "
                f"if ({v} != 0) {{ memset({v}, 0, {REALLOC_OLD_BYTES}); }}"
            )
            case.note(call, i, f"old pointer of a realloc-like call: a {REALLOC_OLD_BYTES}-byte malloc of the harness")
            args.append(f"({p['type']}){v}")
            i += 1
            continue
        if (
            p["kind"] == "ptr"
            and i == 0
            and allow_init
            and 0 not in shared
            and _free_byte_ptr_like(name, params, formals, api)
        ):
            # Rule E: a single-argument `*_free*(byte *)` helper frees a heap pointer, never a static array.
            case.decls.append(f"unsigned char *{case.declare(v)} = (unsigned char *)calloc(1, {REALLOC_OLD_BYTES}U);")
            case.note(call, i, f"argument of a freeing helper: a {REALLOC_OLD_BYTES}-byte calloc of the harness")
            args.append(f"({p['type']}){v}")
            i += 1
            continue
        if p["kind"] == "ptr":
            pointee = p.get("pointee") or "void"
            is_input = False if role in ("output", "caller_storage") else _is_input(formals, i)
            size = None if varlen and _lone_output(params, formals, i) else param_size(rec, i)
            charlike = _charlike(p)
            pair = _is_pair(params, i, formals)
            own_init = (i == 0 and name in case.api.candidates.get(pointee, set())) or (
                api.trust_schema and name in case.api.candidates.get(pointee, set())
            )
            if i == 0 and name in api.owner_names.get(pointee, set()):
                # Rule G (sudo run-1: `change_window_size__free_unpacked(&c0a0, &c0a1)` on a stack
                # message): a destructor that also takes tables frees what its producer returned. The
                # producer runs first, and the call under test only on a non-NULL result.
                if not api.producers.get(pointee):
                    raise _CaseError(
                        f"frees an object only its producer makes: no function of the unit returns the {pointee} * "
                        f"{name} frees; a stack or zeroed object would be an invalid free only the harness makes"
                    )
                before.append(_produced_object(case, pointee, v, call, i))
                guards.append(f"{v} != 0")
                case.note(
                    call, i, f"the {pointee} {api.producers[pointee][0]} returned, freed by this call when not NULL"
                )
                args.append(f"({p['type']}){v}")
                i += 1
                continue
            if (
                allow_init
                and i not in shared
                and pointee not in case.api.inits
                and name in case.api.struct_dtor_names.get(pointee, set())
                and _FREEING_DTOR_RE.search(name)
            ):
                # libmodbus run-1: `modbus_mapping_free(&c0a0)` on a zeroed stack object, an invalid
                # free only the harness made. With no initializer nothing sets up an object on the
                # stack; the case of a constructor that returns one releases it (`_made_struct`).
                raise _CaseError(
                    f"frees its argument: a zeroed {p.get('decl') or pointee} on the stack would be an invalid free only the "
                    "harness makes (no initializer of the struct); a constructor's case releases what it returns"
                )
            if allow_init and pointee in case.api.inits and not own_init:
                # A context object: its initializer runs first, never a zeroed or input-filled object.
                if (
                    api.trust_schema
                    and api.inits[pointee] in api.schema_inits
                    and i not in builder_schema
                    and not _lookup_schema_instances(api, api.schema_inits[api.inits[pointee]][1])
                ):
                    pname = _name(formals, i) or f"param{i}"
                    raise _AutoExempt(TRUSTED_PARAM_NO_INSTANCE_FMT.format(name=pname))
                case.decls.append(f"{p.get('decl') or pointee} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
                if api.trust_schema and target_claims_rest:
                    reserved = case.rest is None
                    if reserved:
                        case.rest = _RESERVED_REST
                    try:
                        before.append(
                            _init_call(case, pointee, f"&{v}", call, i, var=v, schema_inst=builder_schema.get(i))
                        )
                    finally:
                        if reserved and case.rest is _RESERVED_REST:
                            case.rest = None
                else:
                    before.append(
                        _init_call(
                            case,
                            pointee,
                            f"&{v}",
                            call,
                            i,
                            var=v,
                            schema_inst=builder_schema.get(i),
                            feed_rest=api.trust_schema,
                        )
                    )
                args.append(f"&{v}")
                release = _struct_release(api, pointee, name, f"&{v}")
                if release:
                    after.append(release)
                i += 1
                continue
            if _table_type(api, p) is not None:
                # Rule G: a table of function pointers is NULL (a documented default) or harness functions.
                args.append(_table_arg(case, call, i, p, v))
                i += 1
                continue
            if role == "trusted":
                # SD2(c): a trusted pointer with no schema instance and no builder is never fuzzed or zeroed.
                pname = _name(formals, i) or f"param{i}"
                raise _AutoExempt(TRUSTED_PARAM_NO_INSTANCE_FMT.format(name=pname))
            if allow_init and not own_init and pointee in case.api.init_skip_notes:
                for note_msg in case.api.init_skip_notes[pointee]:
                    case.note(call, i, note_msg)
            j = _array_count(params, i, formals)
            # No array of the group may be an object the generator builds otherwise: shared with
            # another call, a handle, or a struct the unit initializes.
            if j is not None and not any(
                k in shared or k in handles or k in outs or str(params[k].get("pointee") or "") in api.inits
                for k in range(i, j + 1)
            ):
                args += _array_args(case, call, params, formals, rec, i, j)
                i = j + 1
                continue
            if (
                api.trust_schema
                and role == "caller_storage"
                and pair
                and nxt is not None
                and (i + 1) not in shared
            ):
                # S2 caller-storage shape (b): trusted writable `(void */byte *, size_t)` scratch pair.
                buf_var = case.declare(f"{v}_buf")
                case.decls.append(_byte_buffer("static ", buf_var, case.spare))
                ln = f"c{call}a{i + 1}"
                attacker_sized = roles is not None and roles[i + 1] == "attacker"
                if attacker_sized:
                    case.decls.append(f"{nxt['ctype']} {case.declare(ln)}; memset(&{ln}, 0, sizeof({ln}));")
                    case.slot(ln, SCALAR_BYTES.get(nxt["ctype"]), call, i + 1, "int")
                    case.decls.append(
                        f"if ((unsigned long long){ln} > sizeof({buf_var})) {{ {ln} = ({nxt['ctype']})sizeof({buf_var}); }}"
                    )
                    case.note(
                        call,
                        i,
                        f"{CALLER_STORAGE_NOTE} (attacker-sized length clamped to 0..sizeof({buf_var}))",
                    )
                else:
                    case.decls.append(f"{nxt['ctype']} {case.declare(ln)} = ({nxt['ctype']})sizeof({buf_var});")
                    case.note(call, i, CALLER_STORAGE_NOTE)
                args.append(f"({p['type']}){buf_var}")
                args.append(ln)
                pairs.append((i, ln, False))
                i += 2
                continue
            if (
                pair
                and nxt is not None
                and (i + 1) not in shared
                and (roles is None or roles[i + 1] != "trusted_scalar")
            ):
                nonconst_in = not is_input and _is_nonconst_input_buf(
                    name, params, i, formals, api, role=role, entry_trust=entry_trust
                )
                if is_input and case.rest is None and size is None:
                    case.rest = {"call": call, "param": i, "kind": "bytes"}
                    if builder_rest:
                        empty_var = case.declare(f"{v}_empty")
                        case.decls.append(f"static uint8_t {empty_var}[1] = {{0}};")
                        args.append(f"({p['type']})((fuzz_len > fuzz_off) ? (fuzz_buf + fuzz_off) : {empty_var})")
                        args.append(f"({nxt['type']})((fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U)")
                        pairs.append((i, "((fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U)", True))
                    else:
                        args.append(f"({p['type']})(fuzz_buf + fuzz_off)")
                        args.append(f"({nxt['type']})(fuzz_len - fuzz_off)")
                        pairs.append((i, "(fuzz_len - fuzz_off)", True))
                elif nonconst_in and case.rest is None and size is None:
                    ln = f"c{call}a{i + 1}"
                    case.decls.append(f"{nxt['ctype']} {case.declare(ln)} = 0;")
                    case.rest = {"call": call, "param": i, "kind": "bytes"}
                    if name in api.heap_buffer_fns:
                        # Callers querying `malloc_usable_size` require a heap-block base pointer
                        # (not the interior `fuzz_buf + fuzz_off` after the dispatch selector) with
                        # capacity for the configured maximum frame size.
                        buf = case.spare
                        case.decls.append(f"unsigned char *{case.declare(v)} = (unsigned char *)calloc(1, {buf}U);")
                        guards.append(f"{v} != 0")
                        after.append(f"free({v});")
                        cap = _len_cap_expr(nxt["ctype"], f"{buf}U")
                        case.post.append(
                            f"{{ size_t rest_n = (fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U; "
                            f"if (rest_n > {cap}) {{ rest_n = {cap}; }} "
                            f"if ({v} != 0 && rest_n > 0) {{ memcpy({v}, {FUZZ_COPY}, rest_n); }} "
                            f"{ln} = ({nxt['ctype']})rest_n; }}"
                        )
                        case.note(call, i, "writable heap capacity input buffer: copied from the rest of the input")
                        args.append(f"({p['type']}){v}")
                    else:
                        # `fuzz_buf` in harness_dual.c.template is already a writable exact-size heap
                        # copy in LLVMFuzzerTestOneInput (and writable input_buf in eva_main), so
                        # passing `fuzz_buf + fuzz_off` directly preserves exact end bounds for ASan,
                        # E-ACSL, and Eva without zero-padding past the frame length.
                        case.post.append(_rest_len_post(ln, nxt["ctype"]))
                        case.note(call, i, "writable input buffer: the rest of the input (exact bounds)")
                        args.append(f"({p['type']})(fuzz_buf + fuzz_off)")
                    args.append(ln)
                    pairs.append((i, ln, True))
                elif (is_input or nonconst_in) and size is None and _can_copy_sequence_rest(case, call):
                    ln = f"c{call}a{i + 1}"
                    _bind_secondary_rest_buf(
                        case,
                        call,
                        i,
                        v,
                        ln,
                        nxt["ctype"],
                        heap_capacity=(name in api.heap_buffer_fns and not is_input),
                        guards=guards,
                        after=after,
                    )
                    args.append(f"({p['type']}){v}")
                    args.append(ln)
                    pairs.append((i, ln, True))
                else:
                    buf = size or case.spare
                    heap_buf = name in api.heap_buffer_fns and not is_input
                    if heap_buf:
                        case.decls.append(f"unsigned char *{case.declare(v)} = (unsigned char *)calloc(1, {buf}U);")
                        guards.append(f"{v} != 0")
                        after.append(f"free({v});")
                        if size and nonconst_in:
                            case.decls.append(
                                f"if ({v} != 0 && fuzz_len >= fuzz_off + {size}U) {{ "
                                f"memcpy({v}, {FUZZ_COPY}, {size}U); fuzz_off += {size}U; }}"
                            )
                            case.slots.append({"call": call, "param": i, "size": size, "kind": "bytes"})
                    else:
                        case.decls.append(_byte_buffer(_storage(size), case.declare(v), buf))
                        if size and (is_input or nonconst_in):
                            case.slot(v, size, call, i, "bytes", addr=False)
                    ln = f"c{call}a{i + 1}"
                    case.decls.append(f"{nxt['ctype']} {case.declare(ln)}; memset(&{ln}, 0, sizeof({ln}));")
                    case.slot(ln, SCALAR_BYTES.get(nxt["ctype"]), call, i + 1, "int")
                    case.decls.append(f"if ((unsigned long long){ln} > {buf}ULL) {{ {ln} = ({nxt['ctype']}){buf}; }}")
                    args.append(f"({p['type']}){v}")
                    args.append(ln)
                    pairs.append((i, ln, False))
                i += 2
                continue
            if (
                _is_buf_len_ptr_pair(params, i, formals)
                and nxt is not None
                and (i + 1) not in shared
                and (roles is None or roles[i + 1] != "trusted_scalar")
            ):
                nonconst_lp_in = not is_input and _is_nonconst_input_buf(
                    name, params, i, formals, api, role=role, entry_trust=entry_trust, is_len_ptr=True
                )
                if is_input or nonconst_lp_in:
                    buf = size or case.spare
                    lpt = str(nxt.get("pointee") or "int")
                    ln = f"c{call}a{i + 1}"
                    if size is None and case.rest is None:
                        case.decls.append(f"{lpt} {case.declare(ln)} = 0;")
                        case.rest = {"call": call, "param": i, "kind": "bytes"}
                        if name in api.heap_buffer_fns and not is_input:
                            case.decls.append(f"unsigned char *{case.declare(v)} = (unsigned char *)calloc(1, {buf}U);")
                            guards.append(f"{v} != 0")
                            after.append(f"free({v});")
                            cap = _len_cap_expr(lpt, f"{buf}U")
                            case.post.append(
                                f"{{ size_t rest_n = (fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U; "
                                f"if (rest_n > {cap}) {{ rest_n = {cap}; }} "
                                f"if ({v} != 0 && rest_n > 0) {{ memcpy({v}, {FUZZ_COPY}, rest_n); }} "
                                f"{ln} = ({lpt})rest_n; }}"
                            )
                            case.note(
                                call,
                                i,
                                "writable heap capacity input buffer with pointer-to-length: copied from the rest of the input",
                            )
                            args.append(f"({p['type']}){v}")
                        else:
                            case.post.append(_rest_len_post(ln, lpt))
                            case.note(
                                call,
                                i,
                                "writable input buffer with pointer-to-length: the rest of the input (exact bounds)",
                            )
                            args.append(f"({p['type']})(fuzz_buf + fuzz_off)")
                        args.append(f"({nxt['type']})&{ln}")
                        pairs.append((i, ln, True))
                    elif size is None and _can_copy_sequence_rest(case, call):
                        _bind_secondary_rest_buf(
                            case,
                            call,
                            i,
                            v,
                            ln,
                            lpt,
                            heap_capacity=(name in api.heap_buffer_fns and not is_input),
                            guards=guards,
                            after=after,
                        )
                        args.append(f"({p['type']}){v}")
                        args.append(f"({nxt['type']})&{ln}")
                        pairs.append((i, ln, True))
                    else:
                        heap_buf = name in api.heap_buffer_fns and not is_input
                        if heap_buf:
                            case.decls.append(f"unsigned char *{case.declare(v)} = (unsigned char *)calloc(1, {buf}U);")
                            guards.append(f"{v} != 0")
                            after.append(f"free({v});")
                            if size:
                                case.decls.append(
                                    f"if ({v} != 0 && fuzz_len >= fuzz_off + {size}U) {{ "
                                    f"memcpy({v}, {FUZZ_COPY}, {size}U); fuzz_off += {size}U; }}"
                                )
                                case.slots.append({"call": call, "param": i, "size": size, "kind": "bytes"})
                        else:
                            case.decls.append(_byte_buffer(_storage(size), case.declare(v), buf))
                            if size:
                                case.slot(v, size, call, i, "bytes", addr=False)
                        case.decls.append(f"{lpt} {case.declare(ln)}; memset(&{ln}, 0, sizeof({ln}));")
                        case.slot(ln, SCALAR_BYTES.get(lpt), call, i + 1, "int")
                        case.decls.append(f"if ((unsigned long long){ln} > {buf}ULL) {{ {ln} = ({lpt}){buf}; }}")
                        args.append(f"({p['type']}){v}")
                        args.append(f"({nxt['type']})&{ln}")
                        pairs.append((i, ln, False))
                    i += 2
                    continue
            if (
                charlike
                and size is None
                and is_input
                and pointee in ("char", "signed char")
                and (case.rest is _RESERVED_REST)
            ):
                # A string of a call that may not take the rest (a constructor, `_construct`, or a
                # lifecycle case's): a bounded input slot, NUL-terminated. A zeroed buffer would be the
                # empty string, which a constructor may refuse (modbus_new_tcp returns NULL on it).
                case.decls.append(_byte_buffer(_storage(STRING_SLOT_BYTES), case.declare(v), STRING_SLOT_BYTES))
                case.slot(v, STRING_SLOT_BYTES, call, i, "bytes", addr=False)
                case.post.append(f"{v}[sizeof({v}) - 1] = 0;")
                case.note(
                    call,
                    i,
                    f"string of no known size: a {STRING_SLOT_BYTES}-byte input slot, NUL-terminated "
                    "(the rest of the input stays for the calls after it)",
                )
                args.append(f"({p['type']}){v}")
                i += 1
                continue
            if charlike:
                buf = size or case.spare
                case.decls.append(_byte_buffer(_storage(size), case.declare(v), buf))
                if size and is_input:
                    case.slot(v, size, call, i, "bytes", addr=False)
                    if _sentinel_sized(rec, i):
                        # No length goes with it and the call sites pass several sizes: the callee finds
                        # the end by a terminator, as a string's NUL (QCBOR's QCBOR_TYPE_NONE-terminated
                        # type lists). The last byte stays 0 after the input fills the array.
                        case.post.append(f"{v}[sizeof({v}) - 1] = 0;")
                        case.note(
                            call,
                            i,
                            f"byte array of {_sizes_text(rec, i)} bytes at the call sites and no length: "
                            "zero-terminated (its last byte is 0)",
                        )
                elif size is None and is_input and pointee in ("char", "signed char") and case.rest is None:
                    case.rest = {"call": call, "param": i, "kind": "string"}
                    case.post.append(
                        f"{{ size_t rest_n = (fuzz_len > fuzz_off) ? (fuzz_len - fuzz_off) : 0U; "
                        f"if (rest_n > sizeof({v}) - 1) {{ rest_n = sizeof({v}) - 1; }} "
                        f"if (rest_n > 0) {{ memcpy({v}, {FUZZ_COPY}, rest_n); }} {v}[rest_n] = 0; }}"
                    )
                bare.append(f"(sizeof({v}) / sizeof({v}[0]))")
                args.append(f"({p['type']}){v}")
                i += 1
                continue
            # A pointer to a scalar or a struct: an array of the known size, else one object. A struct
            # with pointers (or of unknown layout) is never read from the input as raw bytes, nor is a
            # pointer (`const char **`): input bytes would become an address the callee follows.
            lay = case.api.structs.get(pointee) if _is_record(pointee) else None
            raw_ok = pointee != "_Bool" and not pointee.endswith("*") and (not _is_record(pointee) or _raw_ok(lay))
            if is_input and pointee.endswith("*"):
                case.note(call, i, f"{pointee}: a pointer, zeroed (NULL), never read from the input")
            elif is_input and not raw_ok and lay is None:
                case.note(call, i, f"{_layout_why(case.api, pointee)}: the object is zeroed, not read from the input")
            # The object's type as declared: the header's spelling of a qualified pointer (`decl`,
            # `_respell_qualified_pointers`), else the model's pointee.
            elem = p.get("decl") or pointee
            if size:
                case.decls.append(
                    f"{elem} {case.declare(v)}[({size} + sizeof({elem}) - 1) / sizeof({elem})]; memset({v}, 0, sizeof({v}));"
                )
                if is_input and raw_ok:
                    case.slot(v, size, call, i, "bytes", addr=False)
                    if _sentinel_sized(rec, i) and not _is_record(pointee):
                        # Its terminator value is not known (QCBOR ends tag-number lists on
                        # CBOR_TAG_INVALID64, not 0): left as read, and said so.
                        case.note(
                            call,
                            i,
                            f"{pointee} array of {_sizes_text(rec, i)} bytes at the call sites and no length: "
                            "probably terminated by a sentinel the generator does not know; not terminated",
                        )
                elif is_input and lay is not None and lay.get("what") == "struct":
                    _fill_fields(case, call, i, f"{v}[0]", lay, 0)
                elif api.trust_schema and not is_input and lay is not None and lay.get("what") == "struct":
                    _init_bsd_queues(case, f"{v}[0]", lay)
                elif _owned_out_param(name, params, formals, i, api):
                    # Rule F: a heap object the call hands to its caller through `char **`.
                    owned_outs.append(f"{v}[0]")
                    case.note(call, i, "heap output the caller owns: freed after the call and its object's release")
                if not _is_record(pointee):
                    bare.append(f"(sizeof({v}) / sizeof({v}[0]))")
                args.append(f"({p['type']}){v}")
            elif varlen and _lone_output(params, formals, i):
                case.decls.append(_byte_buffer("static ", case.declare(v), case.spare))
                args.append(f"({p['type']}){v}")
            elif _scalar_array(p):
                # A pointer to a non-byte scalar of no known size (libmodbus run-1: `modbus_get_float_abcd(
                # const uint16_t *src)` reads src[0] and src[1]): zeroed elements, element 0 read from the
                # input as the one object was, so the layout does not move. A larger buffer never makes a
                # crash; a smaller one does. A call indexing it by a count or an index
                # (`_indexed_scalars`) gets a spare buffer's worth of elements, which bounds them.
                if indexed:
                    case.decls.append(
                        f"static {elem} {case.declare(v)}[({case.spare} + sizeof({elem}) - 1) / sizeof({elem})]; "
                        f"memset({v}, 0, sizeof({v}));"
                    )
                    what = f"{case.spare} bytes of elements"
                else:
                    case.decls.append(f"{elem} {case.declare(v)}[{ARRAY_ELEMENTS}]; memset({v}, 0, sizeof({v}));")
                    what = f"{ARRAY_ELEMENTS} elements"
                if is_input:
                    case.slot(f"{v}[0]", SCALAR_BYTES.get(pointee), call, i, "pointee")
                case.note(
                    call,
                    i,
                    f"{pointee} of no known size: an array of {what}, zeroed"
                    + (", element 0 read from the input" if is_input else ""),
                )
                bare.append(f"(sizeof({v}) / sizeof({v}[0]))")
                args.append(f"({p['type']}){v}")
            else:
                pt_keys = (
                    {_spelled(pointee), _spelled(elem), _spelled(api.anon_tags.get(pointee, ""))} - {""}
                    if _is_record(pointee) and not is_input
                    else set()
                )
                if allow_init and case.ncalls == 1 and pt_keys and (pt_keys & api.global_freed_ptrs.get(name, set())):
                    case.decls.append(f"{elem} *{case.declare(v)} = ({elem} *)calloc(1, sizeof({elem}));")
                    if api.trust_schema and lay is not None and lay.get("what") == "struct":
                        n_before = len(case.decls)
                        _init_bsd_queues(case, f"(*{v})", lay)
                        if len(case.decls) > n_before:
                            q_inits = case.decls[n_before:]
                            del case.decls[n_before:]
                            case.decls.append(f"if ({v} != 0) {{ {' '.join(q_inits)} }}")
                    guards.append(f"{v} != 0")
                    global_heap_vars.append(v)
                    case.note(
                        call,
                        i,
                        f"heap-allocated with calloc: stored in a global pointer released by "
                        f"{api.global_teardown.get(name, 'teardown')}",
                    )
                    args.append(v)
                elif (
                    allow_init
                    and case.ncalls == 1
                    and pt_keys
                    and (pt_keys & api.global_retained_ptrs.get(name, set()))
                ):
                    case.decls.append(f"static {elem} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
                    if api.trust_schema and lay is not None and lay.get("what") == "struct":
                        _init_bsd_queues(case, v, lay)
                    case.note(call, i, "static storage: pointer may be retained in a global variable")
                    args.append(f"&{v}")
                else:
                    case.decls.append(f"{elem} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
                    if is_input and pointee == "_Bool":
                        case.bool_slot(v, call, i, "pointee")
                    elif is_input and raw_ok:
                        case.slot(v, SCALAR_BYTES.get(pointee) or (lay or {}).get("size"), call, i, "pointee")
                    elif is_input and lay is not None and lay.get("what") == "struct":
                        _fill_fields(case, call, i, v, lay, 0)
                    elif api.trust_schema and not is_input and lay is not None and lay.get("what") == "struct":
                        _init_bsd_queues(case, v, lay)
                    elif _owned_out_param(name, params, formals, i, api):
                        # Rule F: a heap object the call hands to its caller through `char **`.
                        owned_outs.append(v)
                        case.note(call, i, "heap output the caller owns: freed after the call and its object's release")
                    args.append(f"&{v}")
            i += 1
            continue
        if p["kind"] == "struct":
            ctype = p["ctype"]
            if api.trust_schema and allow_init and ctype in api.inits and name not in api.candidates.get(ctype, set()):
                if (
                    api.inits[ctype] in api.schema_inits
                    and i not in builder_schema
                    and not _lookup_schema_instances(api, api.schema_inits[api.inits[ctype]][1])
                ):
                    pname = _name(formals, i) or f"param{i}"
                    raise _AutoExempt(TRUSTED_PARAM_NO_INSTANCE_FMT.format(name=pname))
                case.decls.append(f"{ctype} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
                if api.trust_schema and target_claims_rest:
                    reserved = case.rest is None
                    if reserved:
                        case.rest = _RESERVED_REST
                    try:
                        before.append(
                            _init_call(case, ctype, f"&{v}", call, i, var=v, schema_inst=builder_schema.get(i))
                        )
                    finally:
                        if reserved and case.rest is _RESERVED_REST:
                            case.rest = None
                else:
                    before.append(
                        _init_call(
                            case,
                            ctype,
                            f"&{v}",
                            call,
                            i,
                            var=v,
                            schema_inst=builder_schema.get(i),
                            feed_rest=api.trust_schema,
                        )
                    )
                args.append(v)
                i += 1
                continue
            if api.trust_schema and role == "caller_storage":
                # S2 caller-storage shape (a): trusted by-value writable buffer struct (`{ptr, len}` / `{len, ptr}`).
                buf_fields = _writable_buffer_struct_fields(api.structs.get(ctype))
                if buf_fields is not None:
                    pf, lf = buf_fields
                    buf_var = case.declare(f"{v}_buf")
                    case.decls.append(_byte_buffer("static ", buf_var, case.spare))
                    case.decls.append(f"{ctype} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
                    case.decls.append(
                        f"{v}.{pf['name']} = (void *){buf_var}; {v}.{lf['name']} = ({lf['ctype']})sizeof({buf_var});"
                    )
                    case.note(call, i, CALLER_STORAGE_NOTE)
                    args.append(v)
                    i += 1
                    continue
                pname = _name(formals, i) or f"param{i}"
                raise _AutoExempt(TRUSTED_PARAM_NO_INSTANCE_FMT.format(name=pname))
            if role == "trusted":
                pname = _name(formals, i) or f"param{i}"
                raise _AutoExempt(TRUSTED_PARAM_NO_INSTANCE_FMT.format(name=pname))
            _struct_value(case, call, i, v, ctype)
            args.append(v)
            i += 1
            continue
        # A scalar or an enum.
        case.decls.append(f"{p['ctype']} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
        if p["ctype"] == "_Bool":
            case.bool_slot(v, call, i, "int")
        else:
            case.slot(v, SCALAR_BYTES.get(p["ctype"]), call, i, "int")
        scalars[i] = v
        args.append(v)
        i += 1
    if realloc is not None:
        _realloc_rules(case, call, scalars, params, *realloc)
    _domain_rules(case, call, name, params, formals, scalars, pairs)
    _index_rules(case, call, params, scalars, indexed, bare)
    args += extra_args or []
    if allow_init and params and 0 not in shared and 0 not in bound_handles and params[0]["kind"] == "ptr":
        # An initializer's own case: what it set up in its (unshared) object is released after it. A
        # handle a constructor built is released as a handle already (`_construct`), never twice.
        pointee0 = str(params[0].get("pointee") or "")
        if name in api.candidates.get(pointee0, set()):
            release = _struct_release(api, pointee0, name, args[0])
            if release:
                after.append(release)
    made = case.api.returns.get(name) if allow_init else None
    made_struct = _made_struct(name, rec, params, api) if allow_init else None
    produced = _produced_struct(name, rec, params, api) if allow_init and made_struct is None else None
    if made is not None and made in case.api.dtors:
        # The call under test makes a handle: release it, or every run of the case leaks one.
        r = f"c{call}r"
        own = f"{{ {made} {r} = {name}({', '.join(args)}); {_handle_release(api, made, r)} }}"
    elif made_struct is not None:
        # The call under test makes a struct object its caller frees (libmodbus's modbus_mapping_new*).
        r = f"c{call}r"
        freer = api.struct_freers[made_struct]
        made_c = _anon_record_spelling(api, made_struct)
        own = f"{{ {made_c} * {r} = {name}({', '.join(args)}); if ({r} != 0) {{ (void){freer}({r}); }} }}"
        case.notes.append(f"call {call} result: a {made_struct} the caller owns, released with {freer}")
    elif produced is not None:
        # Rule G: the object a producer returns is freed by the destructor that takes its tables
        # (`X__unpack` -> `X__free_unpacked(r, allocator)`), or every run of the case leaks one.
        r = f"c{call}r"
        made_c = _anon_record_spelling(api, produced)
        release = _owner_release(case, call, produced, r)
        own = f"{{ {made_c} * {r} = {name}({', '.join(args)}); if ({r} != 0) {{ {release} }} }}"
        case.notes.append(f"call {call} result: a {produced} the caller owns, released with {api.owners[produced]}")
    elif realloc_old is not None:
        # Rule E: the result is freed; on failure (a new size of at least 1) the old pointer still is the caller's.
        r = f"c{call}r"
        own = (
            f"if ({realloc_old} != 0) {{ void *{r} = (void *){name}({', '.join(args)}); "
            f"if ({r} != 0) {{ free({r}); }} else {{ free({realloc_old}); }} }}"
        )
    elif allow_init and _owned_result(name, rec, params, formals, api):
        # Rule F: a heap result the caller owns, freed, or every run of the case leaks it.
        r = f"c{call}r"
        own = f"{{ void *{r} = (void *){name}({', '.join(args)}); free({r}); }}"
        case.notes.append(f"call {call} result: a heap object the caller owns, freed after the call")
    else:
        own = f"(void){name}({', '.join(args)});"
    if allow_init:
        # Rule F's outputs: after this call's releases, the destructor that hands them over included.
        # Those of an initializer or a constructor run first wait for the call under test's.
        after += [*(f"free({v});" for v in owned_outs), *case.owned_frees]
        case.owned_frees = []
        has_nonconst_record_ptr = any(
            p["kind"] == "ptr" and _is_record(str(p.get("pointee") or "")) and not _is_input(formals, k)
            for k, p in enumerate(params)
        )
        if (
            case.ncalls == 1
            and name in api.global_teardown
            and (not has_nonconst_record_ptr or name in api.global_types_known)
        ):
            gtd = api.global_teardown[name]
            if global_heap_vars:
                own = f"{own} (void){gtd}();"
            else:
                after.append(f"(void){gtd}();")
            case.notes.append(f"call {call}: global state reset after setup with {gtd}")
    else:
        case.owned_frees += [f"free({v});" for v in owned_outs]
    if guards:
        # Only on handles an out-parameter constructor built or calloc'd global-pointer args:
        # on partial allocation failure, free every heap-allocated global-pointer argument.
        if global_heap_vars:
            oom_free = " ".join(f"free({v});" for v in global_heap_vars)
            own = f"if ({' && '.join(guards)}) {{ {own} }} else {{ {oom_free} }}"
        else:
            own = f"if ({' && '.join(guards)}) {{ {own} }}"
    return " ".join([*before, own, *after])


def plan_params(signature: str, formals: Sequence[Any] | None = None) -> tuple[list[dict] | None, str | None]:
    """
    The parameters of a model signature as the generator spells them, or why it cannot call it.
    `formals` are the model record's: a definition Frama-C translated shows it is variadic only by
    its last formal (`seed_harvest.is_variadic`), and the generator has no arguments for the rest.
    """
    parts = split_signature(signature)
    if parts is None:
        return None, f"signature {signature!r} not understood"
    _, params_s, _ = parts
    if is_variadic(signature, formals):
        return None, "variadic"
    return _spell_params(params_s)


_ANON_TAG_RE = re.compile(r"\b(struct|union|enum)\s+__anon\w*")
_ANON_ENUM_RE = re.compile(r"enum\s+__anon\w*")
_ANON_RECORD_RE = re.compile(r"\b(struct|union)\s+__anon\w*")


def _spell_params(params_s: Sequence[str]) -> tuple[list[dict] | None, str | None]:
    """
    The parameter types of a model signature as the generator spells them, or why it cannot. A pointer
    to an anonymous enum (Frama-C's `enum __anonenum_cls_t_7 *` for a header's `cls_t *`) is accepted
    and flagged `anon_enum`: `_bind_call` spells it through the header's typedef, or skips the case.
    A pointer to an anonymous struct or union (`struct __anonstruct_ngx_str_t_13 *` for nginx's
    `ngx_str_t *`) is accepted and flagged `anon_record`: `_bind_call` declares its object through
    the header's typedef (`ApiInfo.anon_tags`), or skips the case when the headers name none.
    """
    params: list[dict] = []
    for t in params_s:
        c = classify_type(t)
        if c["kind"] in ("unsupported", "void"):
            return None, c.get("why") or "void parameter"
        if c["kind"] == "struct" and str(c.get("tag", "")).startswith("__anon"):
            return None, "anonymous struct by value"
        pointee = str(c.get("pointee") or "")
        if c["kind"] == "ptr" and "__anon" in pointee:
            if _ANON_ENUM_RE.fullmatch(pointee):
                c["anon_enum"] = True
            elif _ANON_RECORD_RE.search(pointee) and not _ANON_ENUM_RE.search(pointee):
                c["anon_record"] = True
            else:
                m = _ANON_TAG_RE.search(pointee)
                return None, f"pointer to an anonymous {m.group(1) if m else 'struct'}"
        # An array parameter is a pointer: cast to `void *`, which converts to it. An array of pointers
        # (`char *[]`) points to pointers, as `char **` does; any other array stays a byte buffer.
        if c["kind"] == "ptr" and "[" in t:
            elem = _norm_type(t[: t.index("[")])
            if elem.endswith("*"):
                c["pointee"] = elem
        c["type"] = "void *" if "[" in t else " ".join(t.split())
        params.append(c)
    return params, None


def _respell_enum_pointers(api: ApiInfo, name: str, params: list[dict]) -> list[dict]:
    """
    `params` with each pointer to an anonymous enum spelled as the header declares it (`cls_t *`,
    `ApiInfo.enum_ptrs`): its object is declared and cast through the typedef, never through Frama-C's
    generated tag, which no header defines. With no such spelling the case cannot be built: an integer
    stand-in would be a pointer of another type, and its size need not be the enum's.
    """
    if not any(p.get("anon_enum") for p in params):
        return params
    spelled = api.enum_ptrs.get(name) or {}
    out: list[dict] = []
    for i, p in enumerate(params):
        if p.get("anon_enum"):
            s = spelled.get(i)
            if s is None:
                why = "the headers name no typedef for it" if api.probed else "no layout probe to read its typedef"
                raise _Unbuildable(f"pointer to an anonymous enum {p.get('pointee')}: {why}")
            p = {**p, "pointee": s["pointee"], "type": s["type"]}
        out.append(p)
    return out


def _anon_record_spelling(api: ApiInfo, t: str) -> str:
    """
    `t`, a type of the model, with each anonymous struct or union tag Frama-C made up
    (`struct __anonstruct_ngx_str_t_13`) spelled by the header's typedef name (`ngx_str_t`,
    `ApiInfo.anon_tags`). A tag no typedef names cannot be declared: the case is skipped.
    """

    def spell(m: re.Match[str]) -> str:
        tag = " ".join(m.group(0).split())
        name = api.anon_tags.get(tag)
        if name is None:
            why = "the headers name no typedef for it" if api.probed else "no layout probe to read its typedef"
            raise _Unbuildable(f"pointer to an anonymous {m.group(1)} (`{tag}`): {why}")
        return name

    return _ANON_RECORD_RE.sub(spell, t)


def _respell_anon_records(api: ApiInfo, params: list[dict]) -> list[dict]:
    """
    `params` with each pointer to an anonymous struct or union spelled as the header declares it: the
    object behind it (`decl`, `ngx_str_t`) and the cast (`type`, `ngx_str_t *`). `pointee` stays the
    model's tag, so the object is classified (a record), laid out (`ApiInfo.structs` holds the
    typedef's layout under the tag too), initialized and released as a named struct of its shape.
    """
    if not any(p.get("anon_record") for p in params):
        return params
    out: list[dict] = []
    for p in params:
        if p.get("anon_record"):
            decl = _anon_record_spelling(api, str(p.get("pointee") or ""))
            p = {**p, "decl": decl, "type": _anon_record_spelling(api, str(p["type"]))}
        out.append(p)
    return out


def anon_record_tags(model_functions: dict, visible: set[str] | None) -> dict[str, str]:
    """
    Frama-C's tag of each anonymous struct or union a header names by a typedef: `struct
    __anonstruct_ngx_str_t_13` -> `ngx_str_t`. Read from the declarations the layout probe saw
    (`Declared.anon_record_pointers`): a parameter (or return) the model types as a pointer to the
    tag and the header writes as a pointer to the typedef. A tag two records claim is left out.
    """
    spelled = getattr(visible, "anon_record_pointers", None) or {}
    anon = getattr(visible, "anon_records", None) or {}
    seen: dict[str, set[str]] = {}
    for key, rec in model_functions.items():
        if not isinstance(rec, dict):
            continue
        written = spelled.get(str(rec.get("name") or str(key).split("#")[-1]))
        parts = split_signature(str(rec.get("signature") or "")) if written else None
        if not written or parts is None:
            continue
        for i, t in [(-1, parts[0]), *enumerate(parts[1])]:
            tags = {" ".join(m.group(0).split()): m.group(1) for m in _ANON_RECORD_RE.finditer(t)}
            tname = written.get(i)
            if len(tags) != 1 or tname not in anon:
                continue
            ((tag, what),) = tags.items()
            if anon[tname].get("what") == what:
                seen.setdefault(tag, set()).add(tname)
    out: dict[str, str] = {}
    for tag, names in seen.items():
        if len({anon[n].get("id") for n in names}) == 1:
            out[tag] = min(names)
    # Fallback for anonymous typedef structs/unions that appear only in undeclared functions (never
    # in a declared header prototype): CIL names them `struct __anonstruct_<Typedef>_<digits>` /
    # `union __anonunion_<Typedef>_<digits>`. Accept only when `<Typedef>` is an anonymous record
    # of the same kind (`struct`/`union`) observed by the layout probe in the included headers.
    if anon:
        for rec in model_functions.values():
            if not isinstance(rec, dict):
                continue
            sig = str(rec.get("signature") or "")
            for m in _ANON_RECORD_RE.finditer(sig):
                tag = " ".join(m.group(0).split())
                if tag in out:
                    continue
                what = m.group(1)
                prefix = f"__anon{what}_"
                raw_name = tag.split()[-1]
                if not raw_name.startswith(prefix):
                    continue
                tail = raw_name[len(prefix) :]
                head, sep, digits = tail.rpartition("_")
                if sep and digits.isdigit() and head in anon and anon[head].get("what") == what:
                    out[tag] = head
    return out


def _unspelled_anon_record(rec: dict, tags: dict[str, str]) -> bool:
    """
    Whether a parameter of a model record points to an anonymous struct or union no typedef spells
    (`anon_record_tags`). Such a function has no case, so it is no initializer, destructor or
    constructor either, as when `plan_params` refused every such pointer.
    """
    parts = split_signature(str(rec.get("signature") or ""))
    return parts is not None and any(
        " ".join(m.group(0).split()) not in tags for t in parts[1] for m in _ANON_RECORD_RE.finditer(t)
    )


def _respell_qualified_pointers(api: ApiInfo, name: str, params: list[dict]) -> list[dict]:
    """
    `params` with each pointer to a qualified pointer spelled as the header declares it
    (`ApiInfo.qual_ptrs`): the model's `char **` for c-ares's `const char **name` is cast to
    `const char **`, and the object behind it declared `const char *` (`decl`). Passing a `char **`
    there discards a `const` in a nested pointer: clang warns, gcc 14 refuses the call. Only the
    spelling changes: `pointee` stays the model's, so the object is classified (zeroed, filled, a
    record) as before. A spelling with another pointer depth than the model's type (a typedef hiding
    a pointer) is not used: the object would not be the model's.
    """
    spelled = api.qual_ptrs.get(name)
    if not spelled:
        return params
    out: list[dict] = []
    for i, p in enumerate(params):
        s = spelled.get(i)
        if s is not None and p["kind"] == "ptr" and not p.get("anon_enum"):
            if _spelled(s["type"]).count("*") == _spelled(str(p["type"])).count("*"):
                p = {**p, "decl": s["pointee"], "type": s["type"]}
        out.append(p)
    return out


def _model_record(model: dict, dag_rec: dict, key: str) -> dict:
    functions = model.get("functions") or {}
    name = str(dag_rec.get("name") or key.split("#")[-1])
    for cand in (f"{dag_rec.get('file')}#{name}", key):
        if isinstance(functions.get(cand), dict):
            return functions[cand]
    return {}


def single_case(
    name: str,
    model_rec: dict,
    spare: int,
    api: ApiInfo | None = None,
    *,
    entry_trust: _EntryTrust | None = None,
    schema_bindings: dict[int, tuple[str, bool]] | None = None,
    builder_schema: dict[int, dict[str, Any]] | None = None,
) -> tuple[str | None, dict | None, str | None]:
    """(statements, layout, why not) of the case that calls one API function."""
    params, why = plan_params(str(model_rec.get("signature") or ""), model_rec.get("formals"))
    if params is None:
        return None, None, why
    case = _Case(spare, api, calls=1)
    try:
        call = _bind_call(
            case,
            0,
            name,
            params,
            list(model_rec.get("formals") or []),
            model_rec,
            entry_trust=entry_trust,
            schema_bindings=schema_bindings,
            builder_schema=builder_schema,
        )
    except _CaseError as e:
        return None, None, str(e)
    return case.statements([call]), case.layout("single", [name]), None


def _single_cases_for_entry(
    name: str,
    model_rec: dict,
    spare: int,
    api: ApiInfo,
    entry_trust: _EntryTrust | None = None,
) -> tuple[list[tuple[str, dict[str, Any]]], str | None, bool, set[str]]:
    """
    Build one or more single cases for an entry point under `FRAMAC_API_TRUST_SCHEMA`:
    returns `(made_cases, skip_reason, is_auto_exempt, used_schema_sources)`.
    When `api.trust_schema` is False, emits at most one case identically to `single_case`.
    When `api.trust_schema` is True, expands up to `MAX_SCHEMA_INSTANCES` cases per `(entry, instance)`
    for trusted schema parameters (S3) and schema-taking builders (S2/SD1b).
    """
    if not api.trust_schema:
        stmt, lay, why = single_case(name, model_rec, spare, api)
        return ([(stmt, lay)] if stmt is not None and lay is not None else []), why, False, set()

    params_raw, why = plan_params(str(model_rec.get("signature") or ""), model_rec.get("formals"))
    if params_raw is None:
        return [], why, False, set()
    formals = list(model_rec.get("formals") or [])
    try:
        params = _respell_anon_records(api, _respell_enum_pointers(api, name, params_raw))
        params = _respell_qualified_pointers(api, name, params)
    except _CaseError as exc:
        return [], str(exc), isinstance(exc, _AutoExempt), set()

    if _is_refcount_without_producer(name, params, api):
        return [], REFCOUNT_EXEMPT_REASON, True, set()

    roles = _param_roles(params, formals, model_rec, api, entry_trust) if entry_trust is not None else None
    handles = api.handles.get(name) or {}

    direct_schema_opts: dict[int, tuple[bool, str, str | None, list[dict[str, Any]]]] = {}
    builder_schema_opts: dict[int, tuple[str, list[dict[str, Any]]]] = {}

    for i, p in enumerate(params):
        role = roles[i] if roles is not None else None
        pname = _name(formals, i) or f"param{i}"
        if p["kind"] == "ptr":
            pointee = str(p.get("pointee") or "")
            decl = p.get("decl")
            htype = handles.get(i)
            is_handle = htype is not None and _constructible(api, htype) and _releasable(api, htype)
            own_init = name in api.candidates.get(pointee, set())
            has_builder = pointee in api.inits and not own_init
            if has_builder and api.inits[pointee] in api.schema_inits:
                _, s_pointee = api.schema_inits[api.inits[pointee]]
                insts = _lookup_schema_instances(api, s_pointee)
                if not insts:
                    return [], TRUSTED_PARAM_NO_INSTANCE_FMT.format(name=pname), True, set()
                builder_schema_opts[i] = (s_pointee, insts)
                continue
            if (
                role == "trusted"
                and not is_handle
                and not has_builder
                and _table_type(api, p) is None
                and not _is_nullable_allocator_param(pname, p)
                and not _is_trusted_cstring(params, formals, model_rec, i, roles)
            ):
                insts = _lookup_schema_instances(api, pointee, decl)
                if not insts:
                    return [], TRUSTED_PARAM_NO_INSTANCE_FMT.format(name=pname), True, set()
                direct_schema_opts[i] = (True, pointee, decl, insts)
        elif p["kind"] == "struct":
            ctype = str(p.get("ctype") or "")
            own_init = name in api.candidates.get(ctype, set())
            has_builder = ctype in api.inits and not own_init
            if has_builder and api.inits[ctype] in api.schema_inits:
                _, s_pointee = api.schema_inits[api.inits[ctype]]
                insts = _lookup_schema_instances(api, s_pointee)
                if not insts:
                    return [], TRUSTED_PARAM_NO_INSTANCE_FMT.format(name=pname), True, set()
                builder_schema_opts[i] = (s_pointee, insts)
                continue
            if role == "trusted" and not has_builder:
                # Caller-storage buffer structs have role == "caller_storage" (backed by fixed harness array).
                insts = _lookup_schema_instances(api, ctype, None)
                if not insts:
                    return [], TRUSTED_PARAM_NO_INSTANCE_FMT.format(name=pname), True, set()
                direct_schema_opts[i] = (False, ctype, None, insts)

    if not direct_schema_opts and not builder_schema_opts:
        case = _Case(spare, api, calls=1)
        try:
            call_stmt = _bind_call(case, 0, name, params_raw, formals, model_rec, entry_trust=entry_trust)
        except _AutoExempt as exc:
            return [], str(exc), True, set()
        except _CaseError as exc:
            return [], str(exc), False, set()
        return [(case.statements([call_stmt]), case.layout("single", [name]))], None, False, set()

    # Expand up to MAX_SCHEMA_INSTANCES along the primary schema parameter (direct trusted schema first).
    primary_direct = min(direct_schema_opts) if direct_schema_opts else None
    primary_builder = min(builder_schema_opts) if primary_direct is None and builder_schema_opts else None
    combos: list[
        tuple[dict[int, tuple[str, bool]], dict[int, dict[str, Any]], list[tuple[dict[str, Any], str, str | None]]]
    ] = []

    if primary_direct is not None:
        by_ref, p_pointee, p_decl, p_insts = direct_schema_opts[primary_direct]
        for inst in p_insts[:MAX_SCHEMA_INSTANCES]:
            sb: dict[int, tuple[str, bool]] = {primary_direct: (str(inst["name"]), by_ref)}
            used_meta: list[tuple[dict[str, Any], str, str | None]] = [(inst, p_pointee, p_decl)]
            for j, (j_ref, j_pointee, j_decl, j_insts) in direct_schema_opts.items():
                if j == primary_direct:
                    continue
                sb[j] = (str(j_insts[0]["name"]), j_ref)
                used_meta.append((j_insts[0], j_pointee, j_decl))
            bs = {j: j_insts[0] for j, (_, j_insts) in builder_schema_opts.items()}
            for _j, (j_sp, j_insts) in builder_schema_opts.items():
                used_meta.append((j_insts[0], j_sp, None))
            combos.append((sb, bs, used_meta))
    elif primary_builder is not None:
        p_sp, p_insts = builder_schema_opts[primary_builder]
        for inst in p_insts[:MAX_SCHEMA_INSTANCES]:
            bs = {primary_builder: inst}
            used_meta = [(inst, p_sp, None)]
            for j, (j_sp, j_insts) in builder_schema_opts.items():
                if j == primary_builder:
                    continue
                bs[j] = j_insts[0]
                used_meta.append((j_insts[0], j_sp, None))
            combos.append(({}, bs, used_meta))

    made: list[tuple[str, dict[str, Any]]] = []
    schema_sources: set[str] = set()
    last_err: str | None = None
    last_exempt = False
    for sb, bs, used_meta in combos:
        case = _Case(spare, api, calls=1)
        try:
            call_stmt = _bind_call(
                case,
                0,
                name,
                params_raw,
                formals,
                model_rec,
                entry_trust=entry_trust,
                schema_bindings=sb,
                builder_schema=bs,
            )
        except _AutoExempt as exc:
            last_err, last_exempt = str(exc), True
            continue
        except _CaseError as exc:
            last_err, last_exempt = str(exc), False
            continue
        for inst, pointee, decl in used_meta:
            _record_schema_extern(api, inst, pointee, decl)
            gfile = str(inst.get("file") or "")
            if gfile.endswith(".c"):
                schema_sources.add(gfile)
        made.append((case.statements([call_stmt]), case.layout("single", [name])))
    if not made:
        return [], last_err, last_exempt, set()
    return made, None, False, schema_sources


# --- variadic functions: one case per call site of the target's own programs -------------------------

_OBJECT_ARRAY_RE = re.compile(r"^(?P<elem>[^\[\]]+?)\s*(?P<dims>(?:\[\d+\])+)$")
_OBJECT_BASE_RE = re.compile(r"[A-Za-z_]\w*(?: [A-Za-z_]\w*)*")


def c_string_literal(data: bytes) -> str:
    """
    `data` as one C string literal on one line: printable ASCII as it is, every other byte, the
    quote, the backslash and `?` (no trigraph) as a three-digit octal escape, which never runs into
    the character after it.
    """
    out = ['"']
    for b in data:
        out.append(chr(b) if 0x20 <= b < 0x7F and chr(b) not in '"\\?' else f"\\{b:03o}")
    return "".join(out) + '"'


def _object_decl(ctype: str, var: str) -> tuple[str, bool] | None:
    """(`<type> var` for an object type of a call site (`struct tag`, `char[80]`), whether it is an array)."""
    t = " ".join(ctype.split())
    m = _OBJECT_ARRAY_RE.match(t)
    elem = m.group("elem").strip() if m else t
    if not _OBJECT_BASE_RE.fullmatch(elem):
        return None
    return f"{elem} {var}{m.group('dims') if m else ''}", m is not None


def variadic_case(
    name: str, model_rec: dict, site: dict, spare: int, api: ApiInfo | None = None
) -> tuple[str | None, dict | None, str | None]:
    """
    (statements, layout, why not) of the case that calls a variadic function as one call site of the
    target's own programs does (`site`: a case of scripts/variadic_calls.py). What the call site
    fixes stays fixed, so the case is a call the target itself makes, with another input:

      - the format (the last fixed parameter, `const char *`) is the call site's string literal. It
        is never read from the fuzz input: a fuzzed format would ask for objects the case does not
        pass, and every report would be the harness's own fault;
      - each argument after it is an object the case declares with exactly the call site's type
        (`char c0v0[80]`, `struct minmea_float c0v1`), zeroed, on the stack, passed as there (the
        array itself, or the object's address): a write past it is caught at its real size. No
        input byte goes into these objects, and none becomes a pointer;
      - the other fixed parameters follow the rules of every case, except that a `const` byte
        pointer among them keeps no size from the call sites (`param_sizes` there is the length of
        the literals the callers pass, not a contract): the first takes the rest of the input as a
        NUL-terminated string.

    The layout has kind `variadic` and records `format` (the literal's bytes as latin-1 text),
    `format_param` and `varargs` ({type, pass}), for the seed writer and for a reviewer.
    """
    sig = str(model_rec.get("signature") or "")
    parts = split_signature(sig)
    if parts is None or not is_variadic(sig, model_rec.get("formals")):
        return None, None, "not a variadic function"
    # A definition Frama-C translated lists the rest as one more parameter (`__va_params`).
    types = list(parts[1]) if parts[2] else list(parts[1])[:-1]
    params, why = _spell_params(types)
    if params is None:
        return None, None, why
    formals = [f for f in model_rec.get("formals") or [] if isinstance(f, dict)][: len(params)]
    fmt_at = len(params) - 1
    if fmt_at < 0 or site.get("format_param") != fmt_at:
        return None, None, "the call site's format is not the last fixed parameter of the model's signature"
    fmt_param = params[fmt_at]
    if fmt_param["kind"] != "ptr" or fmt_param.get("pointee") != "char" or not _is_input(formals, fmt_at):
        return None, None, "the last fixed parameter is not `const char *`: no format to fix"
    fmt = site.get("format")
    try:
        fmt_bytes = fmt.encode("latin-1") if isinstance(fmt, str) else None
    except UnicodeEncodeError:
        fmt_bytes = None
    if fmt_bytes is None:
        return None, None, "the call site has no format literal"
    case = _Case(spare, api, calls=1)
    extra: list[str] = []
    varargs: list[dict[str, str]] = []
    try:
        for j, va in enumerate(site.get("varargs") or []):
            ctype, how = (str(va.get("type") or ""), va.get("pass")) if isinstance(va, dict) else ("", None)
            v = case.declare(f"c0v{j}")
            decl = _object_decl(ctype, v)
            if decl is None or how not in ("addr", "array") or (how == "array" and not decl[1]):
                return None, None, f"variable argument {j}: an object of type {ctype!r} cannot be declared"
            case.decls.append(f"{decl[0]}; memset({v if decl[1] else '&' + v}, 0, sizeof({v}));")
            extra.append(v if how == "array" else f"&{v}")
            varargs.append({"type": " ".join(ctype.split()), "pass": str(how)})
            if (case.api.structs.get(ctype.split("[")[0].strip()) or {}).get("pointers"):
                case.note(0, fmt_at + 1 + j, f"{ctype}: holds pointers: the object is zeroed")
        sizes = {
            k: s
            for k, s in (model_rec.get("param_sizes") or {}).items()
            if not (k.isdigit() and int(k) < len(params) and _charlike(params[int(k)]) and _is_input(formals, int(k)))
        }
        rec = {**model_rec, "param_sizes": sizes}
        literal = c_string_literal(fmt_bytes)
        call = _bind_call(case, 0, name, params, formals, rec, {fmt_at: literal}, extra_args=extra)
    except _CaseError as e:
        return None, None, str(e)
    layout = case.layout(VARIADIC_KIND, [name])
    layout.update(format=fmt, format_param=fmt_at, varargs=varargs)
    return case.statements([call]), layout, None


def variadic_cases(
    key: str, name: str, model_rec: dict, sites: Sequence[dict], spare: int, api: ApiInfo | None = None
) -> tuple[list[tuple[str, dict]], list[dict]]:
    """
    The cases of one variadic entry point, one per distinct (format, objects) of its harvested call
    sites, at most MAX_VARIADIC_CASES: ((statements, layout) list, the call sites left out with
    `why`). Call sites that pass an array come first: a buffer whose size the callee cannot see is
    where an unchecked copy shows, so the cap never drops them for a scalar-only format.
    """
    made: list[tuple[str, dict]] = []
    dropped: list[dict] = []
    seen: set[str] = set()

    def arrays_first(item: tuple[int, dict]) -> tuple[bool, int]:
        vas = item[1].get("varargs") or []
        return (not any(isinstance(v, dict) and v.get("pass") == "array" for v in vas), item[0])

    for _, site in sorted(enumerate(s for s in sites if isinstance(s, dict)), key=arrays_first):
        ident = json.dumps([site.get("format"), site.get("varargs")], sort_keys=True, default=str)
        if ident in seen:
            continue
        seen.add(ident)
        left_out = {"entry": key, "format": str(site.get("format")), "varargs": site.get("varargs") or []}
        if len(made) >= MAX_VARIADIC_CASES:
            dropped.append({**left_out, "why": f"more than {MAX_VARIADIC_CASES} variadic cases of {name}"})
            continue
        stmt, layout, why = variadic_case(name, model_rec, site, spare, api)
        if stmt is None or layout is None:
            dropped.append({**left_out, "why": str(why)})
            continue
        made.append((stmt, {**layout, "entry": key}))
    return made, dropped


def still_skipped(layouts: Sequence[dict], skipped: dict[str, str]) -> dict[str, str]:
    """`skipped` without the entry points a case still calls (a variadic function has several cases)."""
    alive = {lay.get("entry") for lay in layouts if lay.get("entry")}
    return {k: v for k, v in skipped.items() if k not in alive}


def _is_path_name(name: str) -> bool:
    words = [w.lower() for w in _NAME_WORD_RE.findall(name)]
    pairs = zip(words, words[1:], strict=False)
    return any(w in _PATH_WORDS for w in words) or any(p in _PATH_WORD_PAIRS for p in pairs)


def path_parameter(rec: dict) -> str | None:
    """
    The name of the first byte-string parameter of a model record named like a file-system path
    (`filename`, `file_name`, `fname`, `path`, `filePath`, `dirname`), or None. Such a function opens,
    creates or lists what the string names (mpack's `mpack_writer_init_filename` fopen()s it for
    writing): fed input bytes, it would touch a file the fuzzer names on every execution.
    """
    params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
    formals = list(rec.get("formals") or [])
    for i, p in enumerate(params or []):
        name = _name(formals, i)
        if name and p["kind"] == "ptr" and p.get("pointee") in ("char", "signed char", "unsigned char"):
            if _is_path_name(name):
                return name
    return None


class _ClusterInitBudget:
    """
    Size budget for selecting cross-cluster struct initializers/destructors on a within-limit
    `address_flow` cluster (decision D2 / B7): prefer in-cluster candidates and reject any
    cross-cluster helper whose combined `flow_reach(anchors + [cand])` exceeds the split limits.
    """

    def __init__(self, dag: dict, sub: dict) -> None:
        import unit_split

        self._unit_split = unit_split
        self.dag_fns: dict[str, dict] = dag.get("functions") or {}
        self.dag_gvars: dict[str, dict] = dag.get("global_variables") or {}
        self.anchors: list[str] = list(sub.get("anchors") or [])
        self.sub_fns: set[str] = set(sub.get("functions") or [])
        self.sub_names: set[str] = {
            str((self.dag_fns.get(k) or {}).get("name") or k.split("#")[-1]) for k in self.sub_fns
        }
        own_keys, all_keys = unit_split.unit_closure_keys(dag, str(sub.get("unit") or ""))
        self.own_set: set[str] = set(own_keys)
        self.within_all: set[str] = set(all_keys)
        limits = dag.get("unit_split") or {}
        self.max_functions: int = int(limits.get("max_functions") or unit_split.MAX_FUNCTIONS)
        self.max_lines: int = int(limits.get("max_lines") or unit_split.MAX_LINES)
        self._keys_by_name: dict[str, list[str]] = {}
        for k in all_keys:
            rec = self.dag_fns.get(k) or {}
            if rec.get("is_static"):
                continue
            fn_name = str(rec.get("name") or k.split("#")[-1])
            self._keys_by_name.setdefault(fn_name, []).append(k)
        self._fits_cache: dict[str, bool] = {}

    def in_cluster(self, name: str) -> bool:
        return name in self.sub_names

    def fits(self, name: str) -> bool:
        if name in self.sub_names:
            return True
        if name in self._fits_cache:
            return self._fits_cache[name]
        cand_keys = self._keys_by_name.get(name) or []
        if not cand_keys:
            self._fits_cache[name] = True
            return True
        reached_all, _ = self._unit_split.flow_reach(
            self.dag_fns, self.dag_gvars, [*self.anchors, *cand_keys], self.within_all
        )
        n_fns, n_lines = self._unit_split.unit_size(self.dag_fns, reached_all & self.own_set)
        ok = n_fns <= self.max_functions and n_lines <= self.max_lines
        self._fits_cache[name] = ok
        return ok


def _flow_cluster_budget(dag: dict, module: str) -> _ClusterInitBudget | None:
    sub = (dag.get("submodules") or {}).get(module)
    if not isinstance(sub, dict) or sub.get("reach") != "address_flow" or "over_limit" in sub:
        return None
    return _ClusterInitBudget(dag, sub)


def struct_destructors(
    functions: dict[str, dict],
    visible: set[str] | None = None,
    *,
    cluster_budget: _ClusterInitBudget | None = None,
) -> tuple[dict[str, str], dict[str, set[str]]]:
    """
    Per struct type, the destructor that releases a struct object an initializer set up, and every
    function named like a destructor of it: named like a destructor (`*_destroy`, `*_free`, ...), one
    parameter, a non-const pointer to that struct (`mpack_error_t mpack_writer_destroy(mpack_writer_t
    *)`). `functions` are the model's records the harness links (the unit's); a header `static` one
    counts only when the layout probe saw it declared (`visible`), and with a probe every one must be.
    Several candidates: in-cluster first when `cluster_budget` is set (rejecting cross-cluster ones
    exceeding the cluster limit), else the first name.
    """
    names: dict[str, set[str]] = {}
    for key, rec in functions.items():
        if not isinstance(rec, dict):
            continue
        name = str(rec.get("name") or key.split("#")[-1])
        if not _DTOR_NAME_RE.search(name):
            continue
        if rec.get("static") and not rec.get("header"):
            continue
        if (rec.get("static") and visible is None) or (visible is not None and name not in visible):
            continue
        params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        if not params or len(params) != 1 or params[0]["kind"] != "ptr":
            continue
        if _is_input(list(rec.get("formals") or []), 0):
            continue
        pointee = str(params[0].get("pointee") or "")
        if _is_record(pointee) and "*" not in pointee:
            names.setdefault(pointee, set()).add(name)
    chosen: dict[str, str] = {}
    for t, ns in names.items():
        if cluster_budget is not None:
            fitting = [n for n in ns if cluster_budget.fits(n)]
            if fitting:
                chosen[t] = min(fitting, key=lambda n: (not cluster_budget.in_cluster(n), n))
        else:
            chosen[t] = min(ns)
    return chosen, names


def _byval_builder_target(rec: dict) -> str | None:
    """The struct type a by-value builder returns (`struct pb_istream_s`), or None."""
    ret = _norm_type(_return_type(rec))
    if not _is_record(ret) or "*" in ret or "(" in ret or "[" in ret:
        return None
    params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
    if params is None:
        return None
    # A function taking the same struct (by value or pointer) is a transformer/copy, not a builder from scratch.
    for p in params:
        if p["kind"] == "struct" and str(p.get("ctype") or "") == ret:
            return None
        if p["kind"] == "ptr" and str(p.get("pointee") or "") == ret:
            return None
    return ret


def _schema_builder_param(rec: dict, target_struct: str, is_byval: bool) -> tuple[int, str] | None:
    """
    For a schema-taking builder (`pb_field_iter_begin(iter, desc, msg)`, `mbedtls_cipher_setup(ctx, info)`),
    return `(param_index, schema_pointee)` of its `const` struct-pointer parameter, or None.
    """
    params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
    if not params:
        return None
    formals = list(rec.get("formals") or [])
    start = 0 if is_byval else 1
    for i in range(start, len(params)):
        p = params[i]
        if p["kind"] != "ptr" or not _is_input(formals, i):
            continue
        pointee = str(p.get("pointee") or "")
        if _is_record(pointee) and "*" not in pointee and pointee != target_struct:
            return i, pointee
    return None


def builder_metadata(
    chosen: dict[str, str],
    records: dict[str, dict],
) -> tuple[set[str], dict[str, tuple[int, str]]]:
    """
    Inspect `initializers(..., trust_schema=True)` outputs to identify:
      - `byval_inits`: builders returning their struct by value (`pb_istream_from_buffer`);
      - `schema_inits`: builders taking a trusted `const` struct schema pointer (`pb_field_iter_begin`).
    """
    byval: set[str] = set()
    schema_inits: dict[str, tuple[int, str]] = {}
    for target, fn in chosen.items():
        rec = records.get(fn)
        if not isinstance(rec, dict):
            continue
        is_byval = _byval_builder_target(rec) == target
        if is_byval:
            byval.add(fn)
        sp = _schema_builder_param(rec, target, is_byval)
        if sp is not None:
            schema_inits[fn] = sp
    return byval, schema_inits


def initializers(
    functions: dict[str, dict],
    traces: list[list[dict]] | None = None,
    visible: set[str] | None = None,
    *,
    cluster_budget: _ClusterInitBudget | None = None,
    skipped_notes: dict[str, list[str]] | None = None,
    trust_schema: bool = False,
    schema_globals: dict[str, list[dict[str, Any]]] | None = None,
    anon_tags: dict[str, str] | None = None,
) -> tuple[dict[str, str], dict[str, set[str]], dict[str, dict]]:
    """
    Per struct type, the initializer the harness calls on a pointer to it, and every candidate: a
    function named like an initializer whose first parameter is a non-const pointer to that struct.
    When `trust_schema=True` (`FRAMAC_API_TRUST_SCHEMA`, S2), also recognizes by-value struct
    builders (`*_from_*`, `*_init*`, `*_new*`, `*_create*`, `*_make*`, e.g. `pb_istream_from_buffer`)
    and schema-taking builders (`*_begin*`, `*_setup*`, e.g. `pb_field_iter_begin`).
    `functions` are the model's records (key -> record): `plan` passes the whole unit's, an
    initializer often lies in another cluster than the API it serves (mpack). A header `static`
    function counts only when the layout probe saw it declared in the harness (`visible`), every
    function then must be.

    An initializer that sets up a broken object is a candidate (its own case does not call another
    first) but never chosen (`_unusable_initializer`): one named for an error (`*_init_error`) or one
    taking a `FILE *`. When `cluster_budget` is set (a within-limit `address_flow` cluster),
    in-cluster candidates outrank cross-cluster ones, and cross-cluster candidates whose combined
    `flow_reach` exceeds the cluster limits are rejected (with notes recorded in `skipped_notes`).
    Among the others, the order is: a (buffer, length) pair the call only reads
    (`mpack_reader_init_data`: its bytes come from the input), then any (buffer, length) pair
    (`mpack_writer_init`: a spare buffer, rather than `*_init_growable`, whose buffer the caller must
    free), then the one the recorded traces call first, then the plainest name (`*_Init`/`*_init`),
    the fewest parameters, then the name.
    """
    cands: dict[str, set[str]] = {}
    records: dict[str, dict] = {}
    for key, rec in functions.items():
        if not isinstance(rec, dict):
            continue
        name = str(rec.get("name") or key.split("#")[-1])
        if rec.get("static") and not rec.get("header"):
            continue
        if (rec.get("static") and visible is None) or (visible is not None and name not in visible):
            continue
        if path_parameter(rec):
            continue  # it would open a file the input names (path_parameter)
        params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        formals = list(rec.get("formals") or [])
        matched_ptr = False
        if (
            (_SCHEMA_INIT_NAME_RE.search(name) if trust_schema else _INIT_NAME_RE.search(name))
            and not (trust_schema and _DTOR_NAME_RE.search(name))
            and params
            and params[0]["kind"] == "ptr"
            and not _is_input(formals, 0)
        ):
            pointee = str(params[0].get("pointee") or "")
            # A `struct tag **` first parameter is an out-parameter constructor (`outparam_constructors`),
            # not an initializer of a struct object.
            if _is_record(pointee) and "*" not in pointee:
                cands.setdefault(pointee, set()).add(name)
                records[name] = rec
                matched_ptr = True
        if (
            trust_schema
            and not matched_ptr
            and _BY_VAL_BUILDER_NAME_RE.search(name)
            and not _DTOR_NAME_RE.search(name)
            and params is not None
        ):
            target = _byval_builder_target(rec)
            if target is not None:
                cands.setdefault(target, set()).add(name)
                records[name] = rec
    traced: dict[str, int] = {}  # each function the traces call, by the order of its first call
    for trace in traces or []:
        for c in trace:
            fn = c.get("fn")
            if isinstance(fn, str):
                traced.setdefault(fn, len(traced))

    def rank(target: str, n: str) -> tuple[Any, ...]:
        rec = records[n]
        params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        formals = list(rec.get("formals") or [])
        is_byval = trust_schema and _byval_builder_target(rec) == target
        start = 0 if is_byval else 1
        pairs = [i for i in range(start, len(params or [])) if _is_pair(params or [], i, formals)]
        parts = split_signature(str(rec.get("signature") or ""))
        if not trust_schema:
            return (
                not cluster_budget.in_cluster(n) if cluster_budget is not None else False,
                not any(_is_input(formals, i) for i in pairs),
                not pairs,
                traced.get(n, len(traced)),
                not re.search(r"_[Ii]nit$", n),
                len(parts[1]) if parts else 99,
                n,
            )
        len_ptrs = [i for i in range(start, len(params or [])) if _len_ptr_params(params or [], i, formals, rec)]
        has_input_pair = any(_is_input(formals, i) for i in pairs) or bool(len_ptrs)
        has_any_pair = bool(pairs) or bool(len_ptrs)
        sp = _schema_builder_param(rec, target, is_byval)
        has_schema_inst = sp is not None and bool(
            _lookup_schema_instances_raw(schema_globals or {}, sp[1], None, anon_tags)
        )
        return (
            not cluster_budget.in_cluster(n) if cluster_budget is not None else False,
            not has_input_pair,
            not has_any_pair,
            not has_schema_inst,
            traced.get(n, len(traced)),
            not re.search(r"_(?:[Ii]nit|from_buffer|begin)$", n),
            len(parts[1]) if parts else 99,
            n,
        )

    chosen: dict[str, str] = {}
    for t, names in cands.items():
        usable = [n for n in names if not _unusable_initializer(n, records[n])]
        if cluster_budget is not None:
            fitting: list[str] = []
            for n in sorted(usable):
                if cluster_budget.fits(n):
                    fitting.append(n)
                elif skipped_notes is not None:
                    skipped_notes.setdefault(t, []).append(
                        f"initializer {n} skipped: cross-cluster reach exceeds cluster limit"
                    )
            usable = fitting
        if usable:
            chosen[t] = min(usable, key=lambda n: rank(t, n))  # noqa: B023
    return chosen, cands, records


_ERROR_WORD_RE = re.compile(r"(?:^|_)error(?:$|_)|Error(?=[A-Z0-9_]|$)")
_STDIO_FILE_RE = re.compile(r"\b(?:FILE|struct _IO_FILE)\b")


def _unusable_initializer(name: str, rec: dict) -> bool:
    """
    An initializer that leaves its object unusable for the call under test: one named for an error
    (`mpack_writer_init_error` flags the writer as failed, so every later call returns at once) or
    one that takes a `FILE *` (`mpack_writer_init_stdfile`: the harness has no stream to give it).
    """
    if _ERROR_WORD_RE.search(name):
        return True
    params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
    return any(_STDIO_FILE_RE.search(str(p.get("pointee") or p.get("type") or "")) for p in params or [])


def handle_functions(
    functions: dict[str, dict], visible: set[str] | None
) -> tuple[
    dict[str, dict[int, str]], dict[str, str], dict[str, str], dict[str, set[str]], dict[str, dict], dict[str, str]
]:
    """
    Opaque handles among `functions` (the model's records the harness may call): (per function, the
    parameters that are handles; per handle type its constructor, its destructor, every function named
    like a destructor of it; the records of the constructors; per function, the handle type it returns). The types come from the layout probe
    (`visible`, a `Declared`): the model's signatures have typedefs expanded, so `scmp_filter_ctx` and
    any other `void *` look alike there. Without a probe nothing is a handle.

    A constructor is named like an initializer (`_INIT_NAME_RE`: `*_new`, `*_new_<kind>`, `*_create`,
    `*_init`, ...), returns the handle type, takes no handle parameter and no file-system path
    (`path_parameter`); other parameters are allowed (the harness fills them from the input). The fewest
    parameters win, then the name. A destructor is named like one and takes the handle alone; one
    named for freeing (`_FREEING_DTOR_RE`: libmodbus's `modbus_free`) wins over `close`, `cleanup`,
    `deinit` or `fini` (`modbus_close` only closes the socket), then the name. A `close` of a handle
    whose destructor frees runs before it (`handle_closers`).
    """
    protos = getattr(visible, "prototypes", None) or {}
    by_name: dict[str, dict] = {}
    for key, rec in functions.items():
        if isinstance(rec, dict) and not (rec.get("static") and not rec.get("header")):
            by_name.setdefault(str(rec.get("name") or key.split("#")[-1]), rec)
    handles: dict[str, dict[int, str]] = {}
    ctor_cands: dict[str, list[str]] = {}
    dtor_cands: dict[str, set[str]] = {}
    returns: dict[str, str] = {}
    for name, rec in by_name.items():
        proto = protos.get(name)
        params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        # A variadic function has no case (plan_params refuses it), so it takes no part here: no
        # handle parameters, and it is no constructor or destructor. One the model does not show as
        # variadic (a record without its formals) still lists one parameter more than the header
        # declares, for the rest: its declared parameters keep their handle types.
        if not isinstance(proto, dict) or params is None or len(proto.get("params") or []) > len(params):
            continue
        mine = {i: t for i, t in enumerate(proto["params"]) if t and params[i]["kind"] == "ptr"}
        if mine:
            handles[name] = mine
        ret = proto.get("ret")
        if ret:
            returns[name] = ret
        if ret and not mine and _INIT_NAME_RE.search(name) and not path_parameter(rec):
            ctor_cands.setdefault(ret, []).append(name)
        if len(params) == 1 and mine and _DTOR_NAME_RE.search(name):
            dtor_cands.setdefault(mine[0], set()).add(name)
    ctors = {t: min(names, key=lambda n: (len(protos[n]["params"]), n)) for t, names in ctor_cands.items()}
    dtors = {t: min(names, key=_dtor_rank) for t, names in dtor_cands.items()}
    return handles, ctors, dtors, dtor_cands, {n: by_name[n] for n in ctors.values()}, returns


def handle_constructor_candidates(
    functions: dict[str, dict], visible: set[str] | None
) -> tuple[dict[str, list[str]], dict[str, dict]]:
    """
    All candidate handle constructors per handle type and their model records (for backend-matched
    constructor selection under `FRAMAC_API_TRUST_SCHEMA`, without altering `handle_functions`'s
    return tuple).
    """
    protos = getattr(visible, "prototypes", None) or {}
    by_name: dict[str, dict] = {}
    for key, rec in functions.items():
        if isinstance(rec, dict) and not (rec.get("static") and not rec.get("header")):
            by_name.setdefault(str(rec.get("name") or key.split("#")[-1]), rec)
    ctor_cands: dict[str, list[str]] = {}
    ctor_recs: dict[str, dict] = {}
    for name, rec in by_name.items():
        proto = protos.get(name)
        params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        if not isinstance(proto, dict) or params is None or len(proto.get("params") or []) > len(params):
            continue
        mine = {i: t for i, t in enumerate(proto["params"]) if t and params[i]["kind"] == "ptr"}
        ret = proto.get("ret")
        if ret and not mine and _INIT_NAME_RE.search(name) and not path_parameter(rec):
            ctor_cands.setdefault(ret, []).append(name)
            ctor_recs[name] = rec
    return {t: sorted(ns) for t, ns in ctor_cands.items()}, ctor_recs


def _dtor_rank(name: str) -> tuple[bool, str]:
    """A destructor named for freeing first (`modbus_free` over `modbus_close`), then the name."""
    return (not _FREEING_DTOR_RE.search(name), name)


def handle_closers(dtors: dict[str, str], dtor_names: dict[str, set[str]], model_functions: dict) -> dict[str, str]:
    """
    Per handle type whose destructor is named for freeing, the other destructor-named function named
    `close` that runs before it (libmodbus: `modbus_close(ctx); modbus_free(ctx);`, else the socket a
    connect or listen opened leaks once per execution). Name-only: one that reaches `free` through the
    model's direct call sites frees the handle itself and is no closer (a double free the harness
    would make); an indirect call (libmodbus's `ctx->backend->close`) is not followed.
    """
    freeing = _reaching(model_functions, frozenset({"free"}))
    out: dict[str, str] = {}
    for t, d in dtors.items():
        if not _FREEING_DTOR_RE.search(d):
            continue
        cands = sorted(
            n
            for n in dtor_names.get(t, set())
            if n != d and _CLOSE_DTOR_RE.search(n) and not _FREEING_DTOR_RE.search(n) and n not in freeing
        )
        if cands:
            out[t] = cands[0]
    return out


def struct_freers(struct_dtor_names: dict[str, set[str]]) -> dict[str, str]:
    """Per struct type, its destructor named for freeing (`modbus_mapping_free`), the first name; others have none."""
    out: dict[str, str] = {}
    for t, names in struct_dtor_names.items():
        freeing = sorted(n for n in names if _FREEING_DTOR_RE.search(n))
        if freeing:
            out[t] = freeing[0]
    return out


def _callable_records(functions: dict[str, dict], visible: set[str] | None) -> dict[str, dict]:
    """The records a case may call, by name: no file-local `static`, a header one only when the probe saw it declared."""
    out: dict[str, dict] = {}
    for key, rec in functions.items():
        if not isinstance(rec, dict):
            continue
        name = str(rec.get("name") or key.split("#")[-1])
        if rec.get("static") and not rec.get("header"):
            continue
        if (rec.get("static") and visible is None) or (visible is not None and name not in visible):
            continue
        out.setdefault(name, rec)
    return out


def struct_owners(
    functions: dict[str, dict], visible: set[str] | None, structs: dict[str, dict]
) -> tuple[dict[str, str], dict[str, set[str]], dict[str, set[str]]]:
    """
    Rule G: per struct type `S`, the destructors that free an object of it and also take tables of
    function pointers (`_vtable_layout`): named for freeing (`_FREEING_DTOR_RE`), a non-const `S *`
    first, then only pointers to such tables (protobuf-c's `void X__free_unpacked(X *message,
    ProtobufCAllocator *allocator)`). Returns (the chosen one per type, the first name; every one;
    the table types they take). A one-parameter destructor is `struct_destructors`' and
    `struct_freers`', as before.
    """
    names: dict[str, set[str]] = {}
    tables: dict[str, set[str]] = {}
    for name, rec in _callable_records(functions, visible).items():
        if not _FREEING_DTOR_RE.search(name):
            continue
        params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        if not params or len(params) < 2 or params[0]["kind"] != "ptr":
            continue
        if _is_input(list(rec.get("formals") or []), 0):
            continue
        made = str(params[0].get("pointee") or "")
        if not _is_record(made) or "*" in made:
            continue
        kinds = [str(p.get("pointee") or "") for p in params[1:]]
        if not all(
            p["kind"] == "ptr" and _vtable_layout(structs.get(t)) for p, t in zip(params[1:], kinds, strict=True)
        ):
            continue
        names.setdefault(made, set()).add(name)
        tables.setdefault(made, set()).update(kinds)
    return {t: min(ns) for t, ns in names.items()}, names, tables


def struct_producers(
    functions: dict[str, dict],
    visible: set[str] | None,
    owners: dict[str, str],
    owner_tables: dict[str, set[str]],
    structs: dict[str, dict],
    allocating: set[str],
    const_returns: set[str],
) -> dict[str, list[str]]:
    """
    Rule G: per struct type with a destructor that takes tables (`struct_owners`), the functions that
    make an object it may free, best first: returning `S *` (no `const` pointee in the header), taking
    no `S *`, no file-system path, named like a constructor, a parser or an unpacker
    (`_PRODUCER_NAME_RE`: `X__unpack`), and either reaching an allocator through the model's call
    sites or taking a table of a type the destructor takes (the allocation goes through it, an
    indirect call the model does not follow). The name that shares most words with the destructor's
    comes first (`alert_message__unpack` for `alert_message__free_unpacked`), then the fewest
    parameters, then the name.
    """
    out: dict[str, list[str]] = {}
    callable_recs = _callable_records(functions, visible)
    for name, rec in callable_recs.items():
        ret = _return_type(rec)
        if not ret.endswith("*"):
            continue
        made = ret[:-1].strip()
        if made not in owners or not _PRODUCER_NAME_RE.search(name) or name in const_returns or path_parameter(rec):
            continue
        params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        if params is None or any(p["kind"] == "ptr" and str(p.get("pointee") or "") == made for p in params):
            continue
        takes = {str(p.get("pointee") or "") for p in params if p["kind"] == "ptr"}
        if name not in allocating and not (takes & owner_tables.get(made, set())):
            continue
        out.setdefault(made, []).append(name)

    def rank(made: str, n: str) -> tuple[int, int, str]:
        common = 0
        for a, b in zip(_words(owners[made]), _words(n), strict=False):
            if a != b:
                break
            common += 1
        parts = split_signature(str(callable_recs[n].get("signature") or ""))
        return (-common, len(parts[1]) if parts else 99, n)

    return {made: sorted(ns, key=lambda n: rank(made, n)) for made, ns in out.items()}  # noqa: B023


@dataclass
class OutParamConstructors:
    """`outparam_constructors`: what `ApiInfo` takes (`outs`, `out_ctors`, `out_ctor_names`, `parents`) and the records."""

    outs: dict[str, dict[int, str]] = field(default_factory=dict)
    ctors: dict[str, tuple[str, int]] = field(default_factory=dict)
    names: dict[str, set[str]] = field(default_factory=dict)
    parents: dict[str, tuple[int, str]] = field(default_factory=dict)
    records: dict[str, dict] = field(default_factory=dict)


def outparam_constructors(
    functions: dict[str, dict],
    visible: set[str] | None,
    handles: dict[str, dict[int, str]],
    traces: list[list[dict]] | None = None,
) -> OutParamConstructors:
    """
    Constructors that write an opaque handle through an out-parameter (`H **`, the layout probe's
    `outs`, written by the call: a non-const pointer in the model's formals), as c-ares builds its
    handles: `ares_dns_record_create(ares_dns_record_t **, ...)`, `ares_init(ares_channel_t **)`,
    `ares_dns_parse(buf, len, flags, ares_dns_record_t **)`. A candidate is named like an initializer,
    a creator, a parser or an adder (`_OUT_CTOR_NAME_RE`), writes one handle, and takes at most one
    other handle, never one of the type it builds: that other handle is its parent, which owns the
    child (`ares_dns_record_rr_add(ares_dns_rr_t **, ares_dns_record_t *, ...)`). Per handle type the
    recorded traces decide (the candidate called first), else a candidate without a parent, the
    plainest name (an initializer's), the fewest parameters, then the name.
    """
    protos = getattr(visible, "prototypes", None) or {}
    out = OutParamConstructors()
    by_name: dict[str, dict] = {}
    for key, rec in functions.items():
        if isinstance(rec, dict) and not (rec.get("static") and not rec.get("header")):
            by_name.setdefault(str(rec.get("name") or key.split("#")[-1]), rec)
    cands: dict[str, list[str]] = {}
    for name, rec in by_name.items():
        proto = protos.get(name)
        params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        if not isinstance(proto, dict) or params is None or len(proto.get("params") or []) > len(params):
            continue
        formals = list(rec.get("formals") or [])
        written = {
            int(i): str(t)
            for i, t in (proto.get("outs") or {}).items()
            if t and int(i) < len(params) and params[int(i)]["kind"] == "ptr" and not _is_input(formals, int(i))
        }
        if not written:
            continue
        out.outs[name] = written
        takes = handles.get(name) or {}
        if len(written) != 1 or len(takes) > 1 or not _OUT_CTOR_NAME_RE.search(name):
            continue
        if path_parameter(rec):
            continue  # it would open a file the input names (path_parameter)
        ((_, htype),) = written.items()
        if htype in takes.values():
            continue  # a copy (`*_dup(dest, src)`) needs a handle of the type first
        cands.setdefault(htype, []).append(name)
        out.records[name] = rec

    def plainest(n: str) -> tuple[bool, bool, int, str]:
        parts = split_signature(str(by_name[n].get("signature") or ""))
        return (bool(handles.get(n)), not _INIT_NAME_RE.search(n), len(parts[1]) if parts else 99, n)

    chosen: dict[str, str] = {}
    for trace in traces or []:
        for c in trace:
            for htype, names in cands.items():
                if c.get("fn") in names and htype not in chosen:
                    chosen[htype] = str(c["fn"])
    for htype, names in cands.items():
        fn = chosen.get(htype) or min(names, key=plainest)
        out.ctors[htype] = (fn, next(iter(out.outs[fn])))
        out.names[htype] = set(names)
        takes = handles.get(fn) or {}
        if takes:
            out.parents[htype] = next(iter(takes.items()))
    out.records = {fn: out.records[fn] for fn, _ in out.ctors.values()}
    return out


def load_traces(path: Path = TRACES_JSONL) -> list[list[dict]]:
    """Recorded call sequences (seed_harvest.py record) of more than one call: one list per traced process."""
    from seed_harvest import load_traces as load_recorded

    traces = [[c for c in t if isinstance(c.get("fn"), str)] for t in load_recorded(path.parent)]
    return [t for t in traces if len(t) > 1]


def chains(trace: list[dict]) -> list[list[int]]:
    """
    The calls of one trace grouped by data flow: two calls are in one chain when they pass the same
    pointer (by address). Chains of one call are left out; the single cases cover them.
    """
    parent = list(range(len(trace)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    first_by_addr: dict[str, int] = {}
    for k, call in enumerate(trace):
        for addr in (call.get("addrs") or {}).values():
            if not isinstance(addr, str) or addr in ("0", "-"):
                continue
            if addr in first_by_addr:
                parent[find(k)] = find(first_by_addr[addr])
            else:
                first_by_addr[addr] = k
    groups: dict[int, list[int]] = {}
    for k in range(len(trace)):
        groups.setdefault(find(k), []).append(k)
    return [g for g in groups.values() if len(g) > 1]


def _shared_size(
    trace: list[dict],
    chain: list[int],
    records: dict[str, dict],
    addr: str,
    api: ApiInfo | None = None,
) -> int:
    """
    The size of a buffer shared by the calls of a chain: the largest the model gives any of its uses,
    0 (a spare buffer) when no use has one or a use is the lone output of a variable-length call. The
    bytes the trace recorded are not a size: they are what one run passed, often less than the object.
    """
    sizes: list[int] = []
    for j in chain:
        fn = trace[j]["fn"]
        rec = records.get(fn) or (api.records.get(fn) if api is not None and api.trust_schema else None) or {}
        params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        formals = list(rec.get("formals") or [])
        for i_s, a in (trace[j].get("addrs") or {}).items():
            if a != addr:
                continue
            i = int(i_s)
            if (
                params
                and i < len(params)
                and _lone_output(params, formals, i)
                and _variable_length(params, formals, rec, {})
            ):
                return 0
            sizes.append(param_size(rec, i) or 0)
    return max(sizes, default=0)


def _is_global_teardown_name(name: str) -> bool:
    return bool(set(_words(name)) & _GLOBAL_TEARDOWN_WORDS)


def _is_global_setup_name(name: str) -> bool:
    return not _is_global_teardown_name(name) and bool(set(_words(name)) & _GLOBAL_SETUP_WORDS)


def _is_global_init_name(name: str) -> bool:
    return not _is_global_teardown_name(name) and bool(set(_words(name)) & _GLOBAL_INIT_WORDS)


def _is_global_additive_name(name: str) -> bool:
    """Whether a global setup function appends/registers a table entry rather than overwriting a singleton config."""
    return not _is_global_teardown_name(name) and bool(set(_words(name)) & _GLOBAL_ADDITIVE_WORDS)


def _setup_call_arg_key(call: Mapping[str, Any]) -> tuple[tuple[str, tuple[tuple[str, int, str], ...]], ...]:
    """Canonical hashable key for a setup call's concrete recorded arguments."""
    args = call.get("args")
    if not isinstance(args, Mapping):
        return ()
    items: list[tuple[str, tuple[tuple[str, int, str], ...]]] = []
    for k in sorted(args, key=lambda x: (0, int(x)) if str(x).isdigit() else (1, str(x))):
        vals = args[k]
        if not isinstance(vals, list):
            continue
        entries = tuple((str(e[0]), int(e[1]), str(e[2])) for e in vals if isinstance(e, list) and len(e) == 3)
        if entries:
            items.append((str(k), entries))
    return tuple(items)


def _global_teardowns(
    callable_recs: Mapping[str, dict[str, Any]],
    traces: Sequence[Sequence[Mapping[str, Any]]] | None,
    trans_writes: Mapping[str, set[str]],
) -> dict[str, str]:
    """
    Map each global-state setup function to the best trace-observed 0-arg global teardown function
    writing overlapping globals (e.g. `Crypto_Config_MariaDB` / `Crypto_Init` -> `Crypto_Shutdown`).
    Only considers teardowns actually observed in recorded traces and callable in the harness.
    """
    if not trans_writes or not traces:
        return {}
    td_freq: dict[str, int] = {}
    for trace in traces:
        for call in trace:
            fn = call.get("fn")
            if not isinstance(fn, str) or fn not in callable_recs:
                continue
            if not _is_global_teardown_name(fn) or not trans_writes.get(fn):
                continue
            rec = callable_recs[fn]
            if path_parameter(rec):
                continue
            params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
            if params == []:
                td_freq[fn] = td_freq.get(fn, 0) + 1
    if not td_freq:
        return {}
    out: dict[str, str] = {}
    for fn in sorted(callable_recs):
        if not _is_global_setup_name(fn):
            continue
        sw = trans_writes.get(fn)
        if not sw:
            continue
        cands = [td for td in td_freq if td != fn and (trans_writes.get(td, set()) & sw)]
        if cands:
            out[fn] = min(cands, key=lambda td: (-len(trans_writes[td] & sw), -td_freq[td], td))
    return out


def _single_record_pointee(ctype: str) -> str | None:
    """For a single-level pointer-to-record type (`T *`, not `T **` / array / fn-ptr), return normalized `T`."""
    s = _spelled(ctype)
    if not s or "[" in s or "(" in s or s.count("*") != 1 or not s.endswith("*"):
        return None
    inner = _spelled(s[:-1])
    if not inner:
        return None
    # Reject primitive/void pointers; accept named `struct`/`union` tags and record typedefs.
    if inner in SCALAR_BYTES or inner in ("void", "char", "signed char", "unsigned char", "_Bool"):
        return None
    return inner


def _freeing_global_teardowns(
    callable_recs: Mapping[str, dict[str, Any]],
    merged_globals: Mapping[str, dict[str, Any]],
    trans_writes: Mapping[str, set[str]],
    freeing: Collection[str],
) -> dict[str, str]:
    """
    Fallback global teardown pairing when traces did not record a teardown: if a non-`const`
    pointer-to-record global is written by both a setup function `fn` and a 0-arg callable teardown
    `td` that reaches `free()`, pair `fn -> td` so `fn` heap-allocates the matching pointer argument
    and releases it through `td()` instead of leaving a dangling stack pointer for `td()` to free.
    """
    if not merged_globals or not trans_writes or not freeing:
        return {}
    ptr_gnames: set[str] = set()
    for gid, g in merged_globals.items():
        if not isinstance(g, dict) or g.get("const") is True:
            continue
        gname = str(g.get("name") or gid.split("#")[-1])
        if gname and any(_single_record_pointee(str(g.get(k) or "")) for k in ("type", "raw_type")):
            ptr_gnames.add(gname)
    if not ptr_gnames:
        return {}
    freeing_set = set(freeing)
    zero_arg_tds: list[str] = []
    for td, rec in sorted(callable_recs.items()):
        if td not in freeing_set or not _is_global_teardown_name(td):
            continue
        if not (trans_writes.get(td, set()) & ptr_gnames) or path_parameter(rec):
            continue
        params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        if params == []:
            zero_arg_tds.append(td)
    if not zero_arg_tds:
        return {}
    out: dict[str, str] = {}
    for fn in sorted(callable_recs):
        if _is_global_teardown_name(fn):
            continue
        sw = trans_writes.get(fn, set()) & ptr_gnames
        if not sw:
            continue
        cands = [td for td in zero_arg_tds if td != fn and (trans_writes.get(td, set()) & sw)]
        if cands:
            out[fn] = min(cands, key=lambda td: (-len(trans_writes[td] & sw), td))
    return out


def _global_pointer_ownership(
    merged_globals: Mapping[str, dict[str, Any]],
    trans_writes: Mapping[str, set[str]],
    global_td: Mapping[str, str],
    freeing: Collection[str],
    anon_tags: Mapping[str, str] | None = None,
) -> tuple[dict[str, set[str]], dict[str, set[str]], set[str]]:
    """
    Classify global pointer ownership for functions that write non-`const` global variables:
      - `freed_ptrs[fn]`: record pointee types of non-`const` pointer globals written by `fn` AND
        written by its global teardown `gtd = global_td[fn]` where `gtd in freeing`. Single cases
        allocate matching non-`const` record-pointer arguments with `calloc` so `gtd()` frees valid
        heap memory rather than a stack object (preventing both bad-free and cross-input
        stack-use-after-scope).
      - `retained_ptrs[fn]`: record pointee types of non-`const` pointer globals written by `fn`
        that are NOT cleared by `gtd` and NOT written by any freeing function; single cases use
        `static` storage so a stored pointer never dangles past function return.
      - `types_known`: functions in `global_td` for which `merged_globals` provides global variable
        type metadata, making single-case global teardown safe even with non-`const` record pointer
        parameters (because every retained freed pointer has been heap-allocated).
    """
    if not merged_globals or not trans_writes:
        return {}, {}, set()
    typedef_to_tags: dict[str, list[str]] = {}
    for tag, tdef in (anon_tags or {}).items():
        typedef_to_tags.setdefault(_spelled(tdef), []).append(_spelled(tag))
    all_global_names: set[str] = set()
    ptr_globals: dict[str, set[str]] = {}
    for gid, g in merged_globals.items():
        if not isinstance(g, dict):
            continue
        gname = str(g.get("name") or gid.split("#")[-1])
        if not gname:
            continue
        all_global_names.add(gname)
        if g.get("const") is True:
            continue
        keys: set[str] = set()
        for raw_t in (str(g.get("type") or ""), str(g.get("raw_type") or "")):
            pt = _single_record_pointee(raw_t)
            if not pt:
                continue
            keys.add(pt)
            if pt in (anon_tags or {}):
                keys.add(_spelled((anon_tags or {})[pt]))
            for tag in typedef_to_tags.get(pt, ()):
                keys.add(tag)
        if keys:
            ptr_globals.setdefault(gname, set()).update(keys)
    freeing_set = set(freeing)
    globals_written_by_freer: set[str] = set()
    for ffn, gset in trans_writes.items():
        if ffn in freeing_set:
            globals_written_by_freer.update(gset)
    freed_ptrs: dict[str, set[str]] = {}
    retained_ptrs: dict[str, set[str]] = {}
    types_known: set[str] = set()
    for fn, written in trans_writes.items():
        if not written:
            continue
        gtd = global_td.get(fn)
        if gtd is not None and (written & all_global_names):
            types_known.add(fn)
        td_writes = trans_writes.get(gtd, set()) if gtd else set()
        for gname in written:
            pt_types = ptr_globals.get(gname)
            if not pt_types:
                continue
            if gtd is not None and gname in td_writes and gtd in freeing_set:
                freed_ptrs.setdefault(fn, set()).update(pt_types)
            elif gtd is not None and gname in td_writes:
                # Teardown clears the global before the case returns without calling free(): stack is safe.
                continue
            elif gname not in globals_written_by_freer:
                retained_ptrs.setdefault(fn, set()).update(pt_types)
    return freed_ptrs, retained_ptrs, types_known


def _global_state_flow(model_functions: Mapping[str, Any]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    """
    Per function name in the Phase 0 model, the global variable names it transitively writes
    (`writes.globals`) and references (`global_refs` union `writes.globals`) across its call graph.
    Returns `({}, {})` when no function in the model records global writes.
    """
    direct_writes: dict[str, set[str]] = {}
    direct_refs: dict[str, set[str]] = {}
    has_writes = False
    for rec in model_functions.values():
        if not isinstance(rec, dict) or not isinstance(rec.get("name"), str):
            continue
        name = rec["name"]
        writes_obj = rec.get("writes")
        wg = {
            str(g)
            for g in ((writes_obj.get("globals") if isinstance(writes_obj, dict) else None) or [])
            if isinstance(g, str) and g
        }
        if wg:
            has_writes = True
        gr = {str(g).split("#")[-1] for g in (rec.get("global_refs") or []) if isinstance(g, str) and g}
        direct_writes.setdefault(name, set()).update(wg)
        direct_refs.setdefault(name, set()).update(gr | wg)
    if not has_writes:
        return {}, {}
    callees = _callee_names(dict(model_functions))
    trans_writes: dict[str, set[str]] = {}
    trans_refs: dict[str, set[str]] = {}
    for name in sorted(direct_refs):
        reached = {name} | _reach(callees, name)
        tw: set[str] = set()
        tr: set[str] = set()
        for fn in reached:
            tw.update(direct_writes.get(fn, ()))
            tr.update(direct_refs.get(fn, ()))
        trans_writes[name] = tw
        trans_refs[name] = tr
    return trans_writes, trans_refs


def _recorded_arg_bytes(call: Mapping[str, Any], idx: int, kind: str) -> bytes | None:
    """Recorded bytes of argument `idx` with record kind `kind` at offset 0, or None."""
    args = call.get("args")
    if not isinstance(args, dict):
        return None
    vals = args.get(str(idx))
    if not isinstance(vals, list):
        return None
    for val in vals:
        if isinstance(val, list) and len(val) == 3 and val[0] == kind and val[1] == 0:
            try:
                return bytes.fromhex(str(val[2]))
            except ValueError:
                return None
    return None


def _is_pointer_free_setup_struct(ctype: str, raw: bytes | None, api: ApiInfo | None) -> bool:
    """
    Whether a struct/union type `ctype` is proven pointer-free by clang's AST (either via a full
    layout in `api.structs` matching `len(raw)` or via `api.pointer_free_records` for packed or
    bit-field records whose exact `sizeof` is checked at C compile time).
    """
    if not raw or api is None:
        return False
    lay = api.structs.get(ctype)
    if lay is not None:
        return not lay.get("pointers") and int(lay.get("size") or 0) == len(raw)
    return ctype in api.pointer_free_records


def _can_bind_recorded_setup_call(call: Mapping[str, Any], params: list[dict[str, Any]], api: ApiInfo | None) -> bool:
    """
    Whether a global-state setup/teardown call has zero pointer parameters and every parameter can
    be materialized concretely from its recorded trace arguments (never reading fuzz bytes).
    """
    for i, p in enumerate(params):
        kind = p.get("kind")
        if kind == "int":
            raw = _recorded_arg_bytes(call, i, "i")
            if raw is None or not 0 < len(raw) <= 8:
                return False
        elif kind == "float":
            raw = _recorded_arg_bytes(call, i, "f")
            if raw is None or len(raw) not in (4, 8):
                return False
            fmt = "<f" if len(raw) == 4 else "<d"
            if not math.isfinite(struct.unpack(fmt, raw)[0]):
                return False
        elif kind == "struct":
            raw = _recorded_arg_bytes(call, i, "t")
            if not _is_pointer_free_setup_struct(str(p.get("ctype") or ""), raw, api):
                return False
        else:
            return False
    return True


def _bind_recorded_setup_call(
    case: _Case,
    call_pos: int,
    name: str,
    params: list[dict[str, Any]],
    call: Mapping[str, Any],
) -> str:
    """
    Emit a global-state setup or teardown call bound strictly to the concrete values recorded in
    the target's test traces: zero fuzz slots are consumed and `case.rest` stays free for the
    target entry point.
    """
    params = _respell_anon_records(case.api, _respell_enum_pointers(case.api, name, params))
    params = _respell_qualified_pointers(case.api, name, params)
    args: list[str] = []
    for i, p in enumerate(params):
        kind = p.get("kind")
        ctype = str(p["ctype"])
        v = f"c{call_pos}a{i}"
        if kind == "int":
            raw = _recorded_arg_bytes(call, i, "i")
            if raw is None or not 0 < len(raw) <= 8:
                raise _CaseError(f"{name}: missing recorded scalar for setup parameter {i}")
            val = int.from_bytes(raw, "little")
            if ctype == "_Bool":
                args.append(f"((_Bool){1 if val else 0})")
            else:
                signed = not (ctype.startswith(("unsigned", "enum", "_Bool")) or ctype in ("char", "size_t", "uint8_t"))
                if signed and val >= 1 << (8 * len(raw) - 1):
                    val -= 1 << (8 * len(raw))
                lit = f"{val}LL" if val < 0 else f"{val}ULL"
                args.append(f"(({ctype}){lit})")
            case.note(call_pos, i, "global setup call: recorded scalar value from seed traces; not read from input")
        elif kind == "float":
            raw = _recorded_arg_bytes(call, i, "f")
            if raw is None or len(raw) not in (4, 8):
                raise _CaseError(f"{name}: missing recorded float for setup parameter {i}")
            fmt = "<f" if len(raw) == 4 else "<d"
            if not math.isfinite(struct.unpack(fmt, raw)[0]):
                raise _CaseError(f"{name}: non-finite recorded float for setup parameter {i}")
            rec_var = case.declare(f"{v}_rec")
            hex_bytes = ", ".join(f"0x{b:02x}" for b in raw)
            case.decls.append(f"static const unsigned char {rec_var}[{len(raw)}] = {{ {hex_bytes} }};")
            case.decls.append(f"{ctype} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
            case.decls.append(f"if (sizeof({v}) == {len(raw)}U) {{ memcpy(&{v}, {rec_var}, {len(raw)}U); }}")
            args.append(v)
            case.note(call_pos, i, "global setup call: recorded float value from seed traces; not read from input")
        elif kind == "struct":
            raw = _recorded_arg_bytes(call, i, "t")
            if raw is None or not _is_pointer_free_setup_struct(ctype, raw, case.api):
                raise _CaseError(f"{name}: cannot concretely bind setup struct parameter {i} ({ctype})")
            rec_var = case.declare(f"{v}_rec")
            hex_bytes = ", ".join(f"0x{b:02x}" for b in raw)
            case.decls.append(f"static const unsigned char {rec_var}[{len(raw)}] = {{ {hex_bytes} }};")
            case.decls.append(f"{ctype} {case.declare(v)}; memset(&{v}, 0, sizeof({v}));")
            case.decls.append(
                f"if (sizeof({v}) == sizeof({rec_var})) {{ memcpy(&{v}, {rec_var}, sizeof({rec_var})); }}"
            )
            args.append(v)
            case.note(call_pos, i, "global setup call: recorded struct bytes from seed traces; not read from input")
        else:
            raise _CaseError(f"{name}: setup parameter {i} has unsupported kind {kind!r}")
    return f"(void){name}({', '.join(args)});"


def _global_setup_prefix(
    trace: list[dict],
    target_indices: list[int],
    records: Mapping[str, dict],
    api: ApiInfo,
    trans_writes: Mapping[str, set[str]],
    trans_refs: Mapping[str, set[str]],
) -> tuple[list[int], int | None]:
    """
    Backward-closed global-state setup calls preceding `target_indices` in `trace` (after the most
    recent teardown) whose transitively written globals feed `target_indices` (directly or through
    later setup calls such as `Crypto_Init`), plus an optional 0-arg trailing teardown call that
    resets those globals. Returns `([], None)` when no global setup applies.
    """
    if not target_indices or not trans_writes:
        return [], None
    first, last = target_indices[0], target_indices[-1]
    needed: set[str] = set()
    for idx in target_indices:
        needed.update(trans_refs.get(str(trace[idx]["fn"]), ()))
    if not needed:
        return [], None
    start = 0
    for k in range(first - 1, -1, -1):
        sfn = str(trace[k]["fn"])
        if _is_global_teardown_name(sfn) and trans_writes.get(sfn):
            start = k + 1
            break
    kept: list[int] = []
    for k in range(first - 1, start - 1, -1):
        sfn = str(trace[k]["fn"])
        if not _is_global_setup_name(sfn):
            continue
        sw = trans_writes.get(sfn)
        if not sw or not (sw & needed):
            continue
        srec = records.get(sfn) or api.records.get(sfn)
        if not srec or path_parameter(srec):
            continue
        params, _ = plan_params(str(srec.get("signature") or ""), srec.get("formals"))
        if params is None or not _can_bind_recorded_setup_call(trace[k], params, api):
            continue
        kept.append(k)
        needed.update(trans_refs.get(sfn, ()))
    if not kept:
        return [], None
    kept.reverse()
    # A sliding trace window without a teardown between two test cases may include an earlier init
    # before a fresh config+init block: keep only the final setup block leading into the last init.
    init_pos = [idx for idx, k in enumerate(kept) if _is_global_init_name(str(trace[k]["fn"]))]
    if len(init_pos) >= 2:
        kept = kept[init_pos[-2] + 1 :]
    # Deduplicate exact duplicate `(fn, args)` setup calls (keeping the first occurrence of additive
    # table registrations and the last occurrence of overwriting setters) without collapsing distinct
    # additive registrations (e.g. multiple GVCIDs for vcid 0, 1, 2, 3).
    exact_keep: dict[tuple[str, Any], int] = {}
    for k in kept:
        sfn = str(trace[k]["fn"])
        ekey = (sfn, _setup_call_arg_key(trace[k]))
        if _is_global_additive_name(sfn):
            exact_keep.setdefault(ekey, k)
        else:
            exact_keep[ekey] = k
    kept = [k for k in kept if exact_keep[(str(trace[k]["fn"]), _setup_call_arg_key(trace[k]))] == k]
    if len(kept) > GLOBAL_SETUP_MAX_PREFIX:
        # Collapse repeated non-additive setters (keeping their last call) before capping.
        last_non_add: dict[str, int] = {}
        for k in kept:
            sfn = str(trace[k]["fn"])
            if not _is_global_additive_name(sfn):
                last_non_add[sfn] = k
        kept = [
            k for k in kept if _is_global_additive_name(str(trace[k]["fn"])) or last_non_add[str(trace[k]["fn"])] == k
        ]
    if len(kept) > GLOBAL_SETUP_MAX_PREFIX:
        # Preserve all non-additive calls (e.g. Config_CryptoLib, Config_TC, Init) plus the earliest
        # distinct additive registrations up to the cap, never slicing off the initial configurator.
        non_add = [k for k in kept if not _is_global_additive_name(str(trace[k]["fn"]))]
        if len(non_add) >= GLOBAL_SETUP_MAX_PREFIX:
            kept = non_add[-GLOBAL_SETUP_MAX_PREFIX:]
        else:
            budget = GLOBAL_SETUP_MAX_PREFIX - len(non_add)
            add_list = [k for k in kept if _is_global_additive_name(str(trace[k]["fn"]))][:budget]
            keep_set = set(non_add) | set(add_list)
            kept = [k for k in kept if k in keep_set]
    setup_writes: set[str] = set()
    for k in kept:
        setup_writes.update(trans_writes.get(str(trace[k]["fn"]), ()))
    teardown: int | None = None
    for k in range(last + 1, min(len(trace), last + 5)):
        tfn = str(trace[k]["fn"])
        if _is_global_setup_name(tfn):
            break
        if _is_global_teardown_name(tfn) and (trans_writes.get(tfn, set()) & setup_writes):
            trec = records.get(tfn) or api.records.get(tfn)
            if not trec or path_parameter(trec):
                continue
            tparams, _ = plan_params(str(trec.get("signature") or ""), trec.get("formals"))
            if tparams == []:
                teardown = k
                break
    return kept, teardown


def _global_setup_plan(
    filtered_traces: list[list[dict]],
    records: Mapping[str, dict],
    singles: Mapping[str, dict],
    api: ApiInfo,
    trans_writes: Mapping[str, set[str]],
    trans_refs: Mapping[str, set[str]],
) -> list[dict[str, Any]]:
    """
    Best recorded global-state setup (+ optional teardown) per distinct non-setup API entry point
    in `records`, ranked to prefer complete setups with teardown, then most frequent concrete
    configuration (function names + recorded arguments) and concise recorded setup, ordered with
    input-reading entry points first.
    """
    if not trans_writes:
        return []
    freq: dict[tuple[str, tuple[str, ...], tuple[Any, ...], str | None], int] = {}
    total_freq: dict[str, int] = {}
    candidates: dict[str, list[dict[str, Any]]] = {}
    for trace in filtered_traces:
        for j, call in enumerate(trace):
            fn = str(call["fn"])
            if fn not in records or _is_global_setup_name(fn) or _is_global_teardown_name(fn):
                continue
            prefix, td = _global_setup_prefix(trace, [j], records, api, trans_writes, trans_refs)
            if not prefix:
                continue
            prefix_sig = tuple(str(trace[k]["fn"]) for k in prefix)
            prefix_args_sig = tuple(_setup_call_arg_key(trace[k]) for k in prefix)
            td_fn = str(trace[td]["fn"]) if td is not None else None
            key = (fn, prefix_sig, prefix_args_sig, td_fn)
            freq[key] = freq.get(key, 0) + 1
            total_freq[fn] = total_freq.get(fn, 0) + 1
            if freq[key] == 1:
                prefix_writes: set[str] = set()
                for k in prefix:
                    prefix_writes.update(trans_writes.get(str(trace[k]["fn"]), ()))
                coverage = len(prefix_writes & trans_refs.get(fn, set()))
                candidates.setdefault(fn, []).append(
                    {
                        "fn": fn,
                        "trace": trace,
                        "prefix": prefix,
                        "target": j,
                        "teardown": td,
                        "prefix_sig": prefix_sig,
                        "prefix_args_sig": prefix_args_sig,
                        "td_fn": td_fn,
                        "coverage": coverage,
                    }
                )
    chosen: list[dict[str, Any]] = []
    for fn, items in candidates.items():
        best = min(
            items,
            key=lambda it: (
                0 if it["teardown"] is not None else 1,
                -it["coverage"],
                -freq[(fn, it["prefix_sig"], it["prefix_args_sig"], it["td_fn"])],
                len(it["prefix"]),
                it["prefix_sig"],
                it["prefix_args_sig"],
                it["td_fn"] or "",
            ),
        )
        chosen.append(best)

    def _reads_input(fn: str) -> bool:
        lay = singles.get(fn)
        return bool(lay and (lay.get("slots") or lay.get("rest")))

    chosen.sort(
        key=lambda it: (
            0 if _reads_input(it["fn"]) else 1,
            -it["coverage"],
            -total_freq.get(it["fn"], 0),
            it["fn"],
        )
    )
    return chosen


def sequence_case(
    trace: list[dict],
    chain: list[int],
    records: dict[str, dict],
    spare: int,
    api: ApiInfo | None = None,
    trust: Mapping[str, _EntryTrust] | None = None,
    setup_positions: Collection[int] | None = None,
    trailing_teardown: str | None = None,
) -> tuple[str | None, dict | None, str | None]:
    """
    The case that replays one chain of a trace: one buffer per shared address (the largest size the
    model or the trace gives it), passed to every call that used that address; every other argument
    as in a single case. The layout's slots name the trace call (`call`, its position in the chain).
    A shared struct object whose first use is not one of its initializers gets the initializer first.
    `trust` gives each function's threat-model roles (by name), bound as in its single case: a trusted
    string is its literal, and a trusted scalar takes one of the values the traces recorded there
    (`_recorded_scalar_arg`), zero when none was. Under `FRAMAC_API_TRUST_SCHEMA`, optional
    `no-attacker-data` configurator/setup calls absent from `records` may be resolved from
    `api.records` (treating their non-shared parameters as trusted) as long as at least one call in
    `chain` is a real entry point in `records`. Positions listed in `setup_positions` are global-state
    setup or teardown calls bound strictly to their concrete recorded trace values (zero fuzz slots).
    `trailing_teardown`, when given, appends a 0-arg global teardown call after the chain.
    """
    try:
        return _sequence_case(trace, chain, records, spare, api, trust, setup_positions, trailing_teardown)
    except _CaseError as e:
        return None, None, str(e)


def _sequence_case(
    trace: list[dict],
    chain: list[int],
    records: dict[str, dict],
    spare: int,
    api: ApiInfo | None,
    trust: Mapping[str, _EntryTrust] | None = None,
    setup_positions: Collection[int] | None = None,
    trailing_teardown: str | None = None,
) -> tuple[str | None, dict | None, str | None]:
    case = _Case(spare, api, calls=len(chain))
    case.recorded_scalars = True
    buffers: dict[str, str] = {}
    calls: list[str] = []
    names: list[str] = []
    setup_pos = set(setup_positions or ())
    if not any(trace[k]["fn"] in records for pos, k in enumerate(chain) if pos not in setup_pos):
        return None, None, "sequence has no API entry point"
    seen_addr: dict[str, int] = {}
    for pos, k in enumerate(chain):
        if pos in setup_pos:
            continue
        call = trace[k]
        for addr in (call.get("addrs") or {}).values():
            if isinstance(addr, str) and addr not in ("0", "-"):
                seen_addr[addr] = seen_addr.get(addr, 0) + 1
    shared_addrs = {a for a, c in seen_addr.items() if c > 1}
    for pos, k in enumerate(chain):
        call = trace[k]
        name = call["fn"]
        rec = records.get(name)
        is_configurator = False
        if rec is None:
            if case.api.trust_schema and name in case.api.records:
                rec = case.api.records[name]
                is_configurator = True
            else:
                return None, None, f"{name} is not an API function of this module"
        params, why = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        if params is None:
            return None, None, f"{name}: {why}"
        if pos in setup_pos:
            calls.append(_bind_recorded_setup_call(case, pos, name, params, call))
            names.append(name)
            continue
        shared: dict[int, str] = {}
        before: list[str] = []
        for idx_s, addr in (call.get("addrs") or {}).items():
            if addr not in shared_addrs:
                continue
            idx = int(idx_s)
            if idx >= len(params) or params[idx]["kind"] != "ptr":
                continue
            if _table_type(case.api, params[idx]) is not None:
                # Rule G: a shared buffer would be a zeroed table; each call gets its own (NULL or harness
                # functions), the same for every call of the chain.
                continue
            if addr not in buffers:
                var = f"s{len(buffers)}"
                size = _shared_size(trace, chain, records, addr, case.api)
                pointee = str(params[idx].get("pointee") or "")
                is_record = _is_record(pointee)
                lay = case.api.structs.get(pointee) if is_record else None
                n_bytes = str(size or spare)
                if is_record:
                    # Room for the whole object, whatever size the call sites showed.
                    obj = _anon_record_spelling(case.api, pointee)
                    n_bytes = f"({n_bytes} > sizeof({obj}) ? {n_bytes} : sizeof({obj}))"
                case.decls.append(_byte_buffer(_storage(size or None), case.declare(var), n_bytes))
                # Filled from the input when its first use reads it, its size is known, and it holds
                # no pointer.
                raw_ok = not is_record or _raw_ok(lay)
                if not is_configurator and size and _is_input(list(rec.get("formals") or []), idx) and raw_ok:
                    case.slot(var, size, pos, idx, "bytes", addr=False)
                buffers[addr] = var
                own_init = idx == 0 and name in case.api.candidates.get(pointee, set())
                if pointee in case.api.inits and not own_init:
                    if case.api.trust_schema and case.api.inits[pointee] in case.api.byval_inits:
                        # QCBOR run-1: `s1 = UsefulBuf_FromSZ(...)` assigned a struct to the byte array, and
                        # the compile probe dropped the recorded encoder chain. Assign through the type.
                        obj = _anon_record_spelling(case.api, pointee)
                        before.append(_init_call(case, pointee, var, pos, idx, var=f"*({obj} *){var}"))
                    else:
                        before.append(_init_call(case, pointee, var, pos, idx))
                elif not own_init and pointee in case.api.init_skip_notes:
                    for note_msg in case.api.init_skip_notes[pointee]:
                        case.note(pos, idx, note_msg)
            shared[idx] = buffers[addr]
        if is_configurator:
            # W2-C: optional no-attacker-data configurator call in a recorded chain — treat all
            # non-shared parameters as trusted so caller-storage buffers get fixed harness arrays,
            # trusted C-strings get literals, and trusted scalars take recorded values or zero.
            et: _EntryTrust | None = _EntryTrust(input_role="entry", attacker_params=[])
        else:
            et = (trust or {}).get(name)
        bound = _bind_call(case, pos, name, params, list(rec.get("formals") or []), rec, shared, entry_trust=et)
        calls.append(" ".join([*before, bound]))
        names.append(name)
    if trailing_teardown and (not names or names[-1] != trailing_teardown):
        calls.append(f"(void){trailing_teardown}();")
        names.append(trailing_teardown)
        case.notes.append(f"call {len(names) - 1}: global state reset after setup with {trailing_teardown}")
    layout = case.layout("sequence", names)
    first_non_setup = next((pos for pos in range(len(chain)) if pos not in setup_pos), len(chain))
    if first_non_setup > 0:
        layout["setup_calls"] = list(names[:first_non_setup])
    return case.statements(calls), layout, None


def lifecycle_methods(htype: str, records: dict[str, dict], api: ApiInfo) -> list[str]:
    """
    The functions a lifecycle case of handle type `htype` may call on its handle: the API functions
    with a case (`records`) that take exactly one handle of that type, other than its constructor
    and the functions named like its destructor (the case releases the handle itself, last).
    """
    out: list[str] = []
    for name in sorted(records):
        if sum(1 for t in (api.handles.get(name) or {}).values() if t == htype) != 1:
            continue
        if name == api.ctors.get(htype) or name in api.dtor_names.get(htype, set()):
            continue
        if name == (api.out_ctors.get(htype) or ("", 0))[0]:
            continue
        out.append(name)
    return out[:LIFECYCLE_MAX_METHODS]


def lifecycle_case(
    htype: str,
    methods: list[str],
    records: dict[str, dict],
    spare: int,
    api: ApiInfo,
    max_calls: int = LIFECYCLE_MAX_CALLS,
) -> tuple[str | None, dict | None, str | None]:
    """
    A synthesized call sequence on one handle (H2): the constructor builds it (call 0, its arguments
    from the input as in any case, except that it never takes the rest of the input: an unsized input
    string is a `STRING_SLOT_BYTES` slot, NUL-terminated, and an unsized byte pair a zeroed spare
    buffer with a length read from the input and clamped to it), then while the input lasts, up to `max_calls` times, one input
    byte picks one of `methods` (call k + 1 for methods[k]), called on the handle with its other
    arguments read from the input at that point, then the destructor releases the handle (after its
    `close`, `handle_closers`; neither is a method, a release inside the loop would be a use after
    free the harness makes). Only the
    constructor's slots are fixed, so they are the layout's slots (seeds start from the constructor's
    recorded arguments); the method calls read their bytes in the loop. A NULL handle runs no method.
    """
    try:
        return _lifecycle_case(htype, methods, records, spare, api, max_calls)
    except _CaseError as e:
        return None, None, str(e)


def _lifecycle_case(
    htype: str, methods: list[str], records: dict[str, dict], spare: int, api: ApiInfo, max_calls: int
) -> tuple[str | None, dict | None, str | None]:
    ctor, dtor = api.ctors.get(htype), api.dtors.get(htype)
    out: int | None = None
    if ctor is None and htype in api.out_ctors:
        ctor, out = api.out_ctors[htype]
        if htype in api.parents:
            return None, None, f"{htype}: its constructor {ctor} needs a parent handle"
    if ctor is None or dtor is None:
        return None, None, f"{htype}: no constructor or destructor known"
    if not methods:
        return None, None, f"{htype}: no other function takes the handle"
    crec = api.records.get(ctor) or records.get(ctor) or {}
    cparams, why = plan_params(str(crec.get("signature") or ""), crec.get("formals"))
    if cparams is None:
        return None, None, f"{ctor}: {why}"
    ncalls = len(methods) + 2
    case = _Case(spare, api, calls=ncalls)
    formals = list(crec.get("formals") or [])
    # The method loop reads its op bytes and arguments after the constructor's slots: the constructor
    # never takes the rest of the input (the layout's `rest` is null), as in `_construct`.
    case.rest = _RESERVED_REST
    try:
        if out is None:
            make = _bind_call(case, 0, ctor, cparams, formals, crec, allow_init=False)
            # Without initializers the statement is the call alone: keep its result instead of dropping it.
            make = make.replace("(void)", f"{htype} {case.declare('fc_h')} = ", 1)
        else:
            # An out-parameter constructor writes the handle; one that fails leaves it NULL.
            make = _bind_call(case, 0, ctor, cparams, formals, crec, {out: "&fc_h"}, allow_init=False)
            make = f"{htype} {case.declare('fc_h')} = 0; {make}"
    finally:
        case.rest = None
    branches: list[str] = []
    for k, name in enumerate(methods):
        rec = records[name]
        params, why = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
        if params is None:
            return None, None, f"{name}: {why}"
        idx = next(i for i, t in (api.handles.get(name) or {}).items() if t == htype)
        sub = _Case(spare, api, calls=ncalls)
        call = _bind_call(sub, k + 1, name, params, list(rec.get("formals") or []), rec, {idx: "fc_h"})
        case.notes.extend(sub.notes)
        branches.append(f"if (fc_k == {k}U) {{ {' '.join([*sub.decls, *sub.post, call])} }}")
    closer = api.closers.get(htype)
    release = f"(void){closer}(fc_h); (void){dtor}(fc_h);" if closer else f"(void){dtor}(fc_h);"
    loop = (
        f"if (fc_h != 0) {{ for (unsigned int fc_i = 0; fc_i < {max_calls}U; fc_i++) {{ unsigned char fc_op = 0;"
        f" if (fuzz_len < fuzz_off + 1) {{ break; }} memcpy(&fc_op, {FUZZ_COPY}, 1); fuzz_off += 1;"
        f" unsigned int fc_k = (unsigned int)fc_op % {len(methods)}U; {' else '.join(branches)} }}"
        f" {release} }}"
    )
    layout = case.layout("lifecycle", [ctor, dtor])
    layout.update(handle=htype, methods=list(methods), max_calls=max_calls)
    # Rule F's outputs of the constructor (built with allow_init=False), freed after its destructor.
    frees, case.owned_frees = case.owned_frees, []
    return case.statements([make, loop, *frees]), layout, None


# --- stateful cases: the state an entry point needs before it does more than fail ------------------------
#
# QCBOR run-1 (2026-11-22): every single case calls its entry point once, right after the context's
# initializer. `QCBOREncode_CloseAndSortMap` then closes a map nobody opened, and the `*InMapSZ`
# accessors search a map nobody entered: both return an error on every input. A stateful case is a
# `sequence` case that leads up to such an entry point: the context's initializer, the calls that set
# up the state it needs, then the entry point.

STATE_MAX_CASES = 96  # stateful cases per harness, after the recorded sequences and lifecycle cases
STATE_MAX_PREFIX = 6  # calls before the entry point in a stateful case (its initializer not counted)
STATE_FEED_CALLS = 4  # data calls a model-built case makes on a context whose initializer reads no data
STATE_REACH_DEPTH = 8  # call-graph depth of `_reach`
_OPENER_WORDS = frozenset({"open", "enter", "begin", "start", "push"})
_CLOSER_WORDS = {"close": "open", "exit": "enter", "leave": "enter", "end": "begin", "stop": "start", "pop": "push"}
_CANCEL_WORDS = frozenset({"cancel", "abort"})  # undo an opener: a closer without a paired name
_SCOPE_WORDS = frozenset({"in", "from", "inside", "within"})


def _scope_noun(words: list[str]) -> str | None:
    """The noun of a scope an accessor works in (`get_int_in_map` -> `map`), or None."""
    for k, w in enumerate(words[:-1]):
        if w in _SCOPE_WORDS:
            return words[k + 1]
    return None


def _closer_word(words: list[str]) -> str | None:
    return next((w for w in words if w in _CLOSER_WORDS or w in _CANCEL_WORDS), None)


def _is_opener(words: list[str]) -> bool:
    return any(w in _OPENER_WORDS for w in words) and _closer_word(words) is None and _scope_noun(words) is None


def _reach(callees: Mapping[str, set[str]], name: str, depth: int = STATE_REACH_DEPTH) -> set[str]:
    """The functions `name` reaches through the model's direct call sites, within `depth` calls."""
    seen: set[str] = set()
    frontier = set(callees.get(name, ()))
    for _ in range(depth):
        frontier -= seen
        if not frontier:
            break
        seen |= frontier
        frontier = set().union(*(callees.get(f, set()) for f in frontier))
    return seen


def _context_type(rec: dict, api: ApiInfo) -> str | None:
    """The struct a function works on through its first parameter, when an initializer sets it up."""
    params, _ = plan_params(str(rec.get("signature") or ""), rec.get("formals"))
    if not params or params[0]["kind"] != "ptr":
        return None
    pointee = str(params[0].get("pointee") or "")
    return pointee if _is_record(pointee) and "*" not in pointee and pointee in api.inits else None


def _input_of(layout: dict) -> tuple[bool, bool]:
    """
    Of a single case: (whether the entry point's own call reads the input, whether the initializer of
    its context reads data, not only a size). An initializer or builder made for another argument of
    the call (`inits[].for.param` other than 0) feeds the call's own input.
    """
    ctx_inits = {
        int(i["call"])
        for i in layout.get("inits") or []
        if isinstance(i, dict) and (i.get("for") or {}).get("call") == 0 and (i.get("for") or {}).get("param") == 0
    }
    used = [*(layout.get("slots") or []), *([layout["rest"]] if layout.get("rest") else [])]
    own = any(int(s.get("call", 0)) not in ctx_inits for s in used)
    data = any(int(s.get("call", 0)) in ctx_inits and s.get("kind") not in ("int", "field_len") for s in used)
    return own, data


def _context_segments(traces: list[list[dict]] | None, init_names: set[str]) -> list[tuple[str, list[dict]]]:
    """
    The calls of the traces on one context object, with the initializer that set it up: from a call of
    an initializer on an address (its first argument) to the next one on that address, the initializer
    left out. Calls on an address no recorded initializer set up are in no segment.
    """
    out: list[tuple[str, list[dict]]] = []
    for trace in traces or []:
        open_seg: dict[str, list[dict]] = {}
        for call in trace:
            addr = (call.get("addrs") or {}).get("0")
            if not isinstance(addr, str) or addr in ("0", "-"):
                continue
            if call.get("fn") in init_names:
                open_seg[addr] = []
                out.append((str(call["fn"]), open_seg[addr]))
            elif addr in open_seg:
                open_seg[addr].append(call)
    return [(fn, s) for fn, s in out if s]


def _compress_prefix(pre: list[dict]) -> list[dict]:
    """
    At most `STATE_MAX_PREFIX` of a recorded prefix: the openers still open when the entry point ran,
    then the calls just before it, back to the last closer or the innermost of those openers.
    """
    if len(pre) <= STATE_MAX_PREFIX:
        return pre
    stack: list[int] = []
    for k, c in enumerate(pre):
        words = _words(str(c.get("fn")))
        if _closer_word(words) is not None:
            if stack:
                stack.pop()
        elif _is_opener(words):
            stack.append(k)
    keep = stack[-STATE_MAX_PREFIX:]
    lo = keep[-1] if keep else -1
    k = len(pre) - 1
    while len(keep) < STATE_MAX_PREFIX and k > lo:
        if _closer_word(_words(str(pre[k].get("fn")))) is not None:
            break
        keep.append(k)
        k -= 1
    return [pre[k] for k in sorted(set(keep))]


def _best_opener(
    cands: list[str], against: set[str], words: dict[str, list[str]], rank: dict[str, tuple[Any, ...]]
) -> str:
    """The opener sharing most words with `against` (open/close words aside), then the most recorded."""
    plain = against - _OPENER_WORDS - set(_CLOSER_WORDS) - _CANCEL_WORDS
    return min(cands, key=lambda o: (-len(plain & set(words[o])), *rank[o]))


def stateful_prefixes(
    records: dict[str, dict],
    singles: dict[str, dict],
    api: ApiInfo,
    model_functions: dict,
    traces: list[list[dict]] | None = None,
    configurators: Collection[str] | None = None,
) -> list[dict[str, Any]]:
    """
    The entry points whose single case can only reach an error path on a fresh context, each with the
    calls that set up the state it needs: [{entry, state, calls, why}], `calls` ending with the entry
    point. `records` are the entry points with a single case (`singles`: name -> its layout); the
    context of a function is the struct its first parameter points to, when an initializer sets it up.

    Which entry points (each rule names the opener it needs, if any):
      - a closer (`close`, `exit`, `end`, `leave`, `pop`, `cancel`, ...): the opener of the same name
        with the opening word (`close_nesting` -> `open_nesting`), its own or a direct callee's, else
        the opener sharing most words with it;
      - an accessor of a scope (`get_int_in_map`, `enter_array_from_map`): an opener whose name has the
        scope's noun (`enter_bounded_map`); and any other function of the context that reaches the
        functions all of those accessors reach and neither the opener nor the initializer does (QCBOR's
        `SeekToLabelN` reaches `MapSearch` as the `*InMap*` accessors do);
      - a function whose case reads no input of its own, on a context whose initializer reads no data
        (QCBOR's encoder: its only input was the storage size).
    The calls before it (at most `STATE_MAX_PREFIX`): (a) `recorded`, the calls the target's tests made
    on the same object before calling it (`_compress_prefix`), when a trace holds one with an opener
    (or any call, for the third rule); else (b) `model`, the opener, then `STATE_FEED_CALLS` calls of
    the context's most recorded data call when its initializer reads no data. Deterministic.
    """
    callees = _callee_names(model_functions)
    counts: dict[str, int] = {}
    for trace in traces or []:
        for call in trace:
            if isinstance(call.get("fn"), str):
                counts[call["fn"]] = counts.get(call["fn"], 0) + 1
    by_ctx: dict[str, list[str]] = {}
    for name in sorted(records):
        ctx = _context_type(records[name], api)
        if ctx is None or name == api.inits.get(ctx) or _INIT_NAME_RE.search(name) or name not in singles:
            continue
        by_ctx.setdefault(ctx, []).append(name)
    init_names = set(api.inits.values()) | {
        n for names in api.candidates.values() for n in names if _INIT_NAME_RE.search(n)
    }
    prefix_allowed = set(records) | (set(configurators) if configurators else set())
    segments = _context_segments(traces, init_names)

    def nparams(n: str) -> int:
        parts = split_signature(str(records[n].get("signature") or ""))
        return len(parts[1]) if parts else 99

    out: list[dict[str, Any]] = []
    for ctx, methods in sorted(by_ctx.items()):
        words = {m: _words(m) for m in methods}
        common = set.intersection(*(set(w) for w in words.values()))
        openers = [m for m in methods if _is_opener(words[m])]
        inputs = {m: _input_of(singles[m]) for m in methods}
        init_data = any(data for _own, data in inputs.values())
        rank = {o: (-counts.get(o, 0), nparams(o), o) for o in openers}
        needs: dict[str, tuple[str | None, str]] = {}
        groups: dict[str, list[str]] = {}  # per opener, the accessors of its scope
        for m in methods:
            if m in openers:
                pass
            elif (cw := _closer_word(words[m])) is not None:
                paired = None
                for callee in [m, *sorted(callees.get(m, ()))]:
                    c_words = _words(callee)
                    c_cw = _closer_word(c_words)
                    if c_cw in _CLOSER_WORDS:
                        want = [_CLOSER_WORDS[c_cw] if w == c_cw else w for w in c_words]
                        paired = next((o for o in openers if words[o] == want), None)
                        if paired is not None:
                            break
                if paired is None and openers:
                    paired = _best_opener(openers, set(words[m]) - common, words, rank)
                if paired is not None:
                    needs[m] = (paired, f"is a closer ({cw}): {paired} opens first")
                    continue
            elif (noun := _scope_noun(words[m])) is not None:
                scoped = [o for o in openers if noun in words[o]]
                if scoped:
                    entered = _best_opener(scoped, set(words[m]) - common, words, rank)
                    needs[m] = (entered, f"works in a {noun}: {entered} enters one first")
                    groups.setdefault(entered, []).append(m)
                    continue
            own, _data = inputs[m]
            # A destructor releases the object whatever it holds: no state to set up first.
            if not own and not init_data and m not in api.struct_dtor_names.get(ctx, set()):
                needs[m] = (None, "reads no input of its own, and the context's initializer reads no data")
        # The scope closure: what every accessor of one opener's scope reaches and the setup does not.
        init_reach = _reach(callees, api.inits[ctx]) | {api.inits[ctx]}
        for o, members in sorted(groups.items()):
            if len(members) < 2:
                continue
            guarded = set.intersection(*(_reach(callees, m) for m in members)) - _reach(callees, o) - init_reach
            guarded -= set(methods) | {o}
            # The entry points of that part of the call graph: functions of it no other one calls.
            tops = {g for g in guarded if not any(g in callees.get(h, set()) for h in guarded)}
            for m in methods:
                if m in needs or m in openers or not tops:
                    continue
                hit = sorted(_reach(callees, m) & tops)
                if hit:
                    needs[m] = (o, f"reaches {hit[0]} as the accessors of that scope do: {o} enters one first")
        feeders = [m for m in methods if m not in needs and m not in openers and inputs[m][0]]
        feeder = min(feeders, key=lambda f: (-counts.get(f, 0), nparams(f), f)) if feeders else None
        for m in sorted(needs):
            opener, why = needs[m]
            prefix: list[str] | None = None
            state = "model"
            for seg_init, seg in segments:
                if seg_init != api.inits[ctx] and seg_init not in api.candidates.get(ctx, set()):
                    continue  # another object at a reused address
                for j, c in enumerate(seg):
                    if c.get("fn") != m:
                        continue
                    pre = [x for x in seg[:j] if x.get("fn") in prefix_allowed]
                    if not pre or (opener is not None and not any(_is_opener(_words(str(x["fn"]))) for x in pre)):
                        continue
                    prefix = [str(x["fn"]) for x in _compress_prefix(pre)]
                    state = "recorded"
                    break
                if prefix is not None:
                    break
            if prefix is None:
                prefix = [opener] if opener is not None else []
                if not init_data and feeder is not None:
                    prefix += [feeder] * STATE_FEED_CALLS
            prefix = prefix[:STATE_MAX_PREFIX]
            if prefix:
                out.append({"entry": m, "state": state, "calls": [*prefix, m], "why": why})
    return out


# A function defined in a public header (static) has no symbol to link: a case calls the copy the
# harness compiles from the header, which the layout probe must have seen declared.
HEADER_NOT_VISIBLE = "static header function: the layout probe did not see the harness declare it"
HEADER_VARIADIC = "static header function, variadic: the generator takes no call site for it"


def _sequence_configurator_records(
    dag: dict,
    model: dict,
    module: str,
    mm: Any,
    records: dict[str, dict],
    api: ApiInfo,
    anon_tags: dict[str, str],
    visible: set[str] | None,
    tm_active: bool,
    entry_trust_map: Mapping[str, _EntryTrust],
    skipped: Mapping[str, str],
    cluster_budget: _ClusterInitBudget | None = None,
) -> dict[str, dict]:
    """
    W2-C: module-local, non-static, non-variadic, header-visible `no-attacker-data` configurator
    and setup calls (e.g., `QCBORDecode_SetMemPool`, `QCBOREncode_Init`, `UsefulOutBuf_Init`,
    `QCBORDecode_CompatibilityV1`) that may remain inside recorded trace segments alongside real
    entry points in `records`.

    Excludes `main`, static/header-inline functions, variadic functions, path-taking functions,
    trusted-only (`trusted_caller`) functions, already-skipped attacker-data entry points, freeing
    destructors, refcount helpers without a producer, and functions outside the module's scope.
    Disabled when `api.trust_schema` is False (`FRAMAC_API_TRUST_SCHEMA=off` rollback).
    """
    if not api.trust_schema:
        return {}
    functions = dag.get("functions") or {}
    scope_keys = list(mm.scope_functions(module))
    if not scope_keys:
        scope_keys = list((mm.unit_record(module)).get("functions") or [])
    scope_key_set = set(scope_keys) | set(mm.scope_entry_points(module))
    forbidden_dtors = (
        {n for ns in api.owner_names.values() for n in ns}
        | set(api.struct_freers.values())
        | {n for ns in api.dtor_names.values() for n in ns}
    )
    out: dict[str, dict] = {}
    for key in sorted(scope_key_set):
        drec = functions.get(key) or {}
        name = str(drec.get("name") or key.split("#")[-1])
        if not name or name == "main" or name in records or name in out or name in forbidden_dtors:
            continue
        if drec.get("is_static"):
            continue
        if tm_active:
            et = entry_trust_map.get(key) or _EntryTrust()
            if et.trusted_caller or et.input_role is not None:
                continue
        elif key in skipped:
            continue
        mrec = _model_record(model, drec, key)
        if not mrec or mrec.get("static"):
            continue
        if visible is not None and name not in visible:
            continue
        if _unspelled_anon_record(mrec, anon_tags):
            continue
        if is_variadic(str(mrec.get("signature") or ""), mrec.get("formals")):
            continue
        if path_parameter(mrec):
            continue
        if cluster_budget is not None and not cluster_budget.fits(name):
            continue
        params, _ = plan_params(str(mrec.get("signature") or ""), mrec.get("formals"))
        if params is None or _is_refcount_without_producer(name, params, api):
            continue
        out[name] = mrec
    return out


def plan(
    dag: dict,
    model: dict,
    module: str,
    unit: str | None,
    max_input_size: int,
    traces: list[list[dict]] | None = None,
    scope_files: list[str] | None = None,
    struct_layouts: dict[str, dict] | None = None,
    visible: set[str] | None = None,
    reserve: int = 0,
    callback_stubs: bool = True,
    variadic: dict[str, list[dict]] | None = None,
    *,
    global_variables: dict[str, dict] | None = None,
    trust: dict[str, Any] | None = None,
    trust_schema: bool | None = None,
) -> dict[str, Any]:
    """
    The cases of a module's API harness: {entries, cases, layouts, skipped, stubs, variadic_dropped}.
    `scope_files` (the sidecar's) give a sub-module that is neither a lexer module nor a cluster its
    scope. `struct_layouts` and `visible` come from `probe_layouts` (None: no probe ran). `reserve`
    selectors are left free for the hand-written cases `generate` appends. `stubs` maps each callback
    stub a case passes for a function pointer (`visible.callbacks`, unless `callback_stubs` is False)
    to its file-scope definition. `variadic` gives each variadic function's harvested call sites
    (`variadic_calls.load_cases`): its cases come after the single ones, and it is skipped only when
    it has none. `variadic_dropped` lists the call sites that made no case, with the reason.
    An entry point defined in a public header (`static`, `header`: the model's `header_api`) gets a
    single case when `visible` has it, after every other generated case but the stateful ones (so the
    cases of the global entry points keep their selectors, and these go over the case limit before
    them); without the probe it is skipped as `HEADER_NOT_VISIBLE`. The stateful cases
    (`stateful_prefixes`) come last and go over the case limit first: every entry point keeps its
    single case.
    """
    effective_trust_schema = api_trust_schema_enabled() if trust_schema is None else bool(trust_schema)
    max_cases = max(0, MAX_CASES - reserve)
    from module_map import ModuleMap

    sidecar: dict[str, Any] = {
        **({"unit": unit} if unit else {}),
        **({"scope_files": scope_files} if scope_files else {}),
    }
    mm = ModuleMap(dag, {module: sidecar} if sidecar else {})
    entries = mm.scope_entry_points(module)
    if not entries:
        info = (dag.get("modules") or {}).get(module) or {}
        entries = [e for e in info.get("candidate_entry_points") or [] if isinstance(e, str)]
    functions = dag.get("functions") or {}
    spare = spare_bytes(max_input_size)
    cases: list[str] = []
    layouts: list[dict] = []
    skipped: dict[str, str] = {}
    auto_exempt: dict[str, str] = {}
    schema_sources: set[str] = set()
    records: dict[str, dict] = {}
    names: list[str] = []
    variadic_made: list[tuple[str, dict]] = []
    dropped: list[dict] = []
    # Anonymous structs and unions the headers name by a typedef (nginx's `ngx_str_t`): a function
    # pointing to one no typedef names has no case, so it builds no object for another case either.
    anon_tags = anon_record_tags(model.get("functions") or {}, visible)
    # Initializers: the module's callable entry points, and header functions the harness sees.
    entry_names = {str((functions.get(k) or {}).get("name") or k.split("#")[-1]) for k in entries}
    init_pool = {
        k: rec
        for k, rec in (model.get("functions") or {}).items()
        if isinstance(rec, dict)
        and (str(rec.get("name") or k.split("#")[-1]) in entry_names or (rec.get("static") and rec.get("header")))
        and not _unspelled_anon_record(rec, anon_tags)
    }
    handles, ctors, dtors, dtor_names, ctor_records, returns = handle_functions(init_pool, visible)
    ctor_cands: dict[str, list[str]] = {}
    all_ctor_records: dict[str, dict] = {}
    if effective_trust_schema:
        ctor_cands, all_ctor_records = handle_constructor_candidates(init_pool, visible)
    outp = outparam_constructors(init_pool, visible, handles, traces)
    # Initializers and destructors of struct objects may lie outside the scope: mpack's
    # mpack_writer_init and mpack_writer_destroy are in other clusters than most of the writer API
    # (mpack run-3: every mpack_writer_2 case passed an all-zero writer). Any function of the unit
    # counts; the harness's sources take in the unit of every function a case names
    # (generate_harness._merge_dag_harness_sources).
    unit_rec = mm.unit_record(module)
    unit_names = {
        str((functions.get(k) or {}).get("name") or str(k).split("#")[-1]) for k in unit_rec.get("functions") or []
    } | entry_names
    unit_pool = {
        k: rec
        for k, rec in (model.get("functions") or {}).items()
        if isinstance(rec, dict)
        and (str(rec.get("name") or k.split("#")[-1]) in unit_names or (rec.get("static") and rec.get("header")))
        and not _unspelled_anon_record(rec, anon_tags)
    }
    resolved_unit = unit or (unit_rec.get("unit") if isinstance(unit_rec.get("unit"), str) else None)
    unit_links: list[str] = []
    if resolved_unit:
        u_model = (model.get("units") or {}).get(resolved_unit) or {}
        if isinstance(u_model, dict):
            unit_links = [str(x) for x in u_model.get("links") or [] if x]
    tm_active = False
    entry_trust_map: dict[str, _EntryTrust] = {}
    schema_globals: dict[str, list[dict[str, Any]]] = {}
    merged_globals: dict[str, dict[str, Any]] = {}
    if effective_trust_schema:
        tm_active, entry_trust_map = _resolve_threat_model(dag, model, trust=trust, unit=resolved_unit)
        merged_globals = _merge_global_variables(model, dag, global_variables)
        schema_globals = _schema_instances_index(
            merged_globals, unit=resolved_unit, unit_links=unit_links, anon_tags=anon_tags
        )
    cluster_budget = _flow_cluster_budget(dag, module)
    init_skip_notes: dict[str, list[str]] = {}
    inits, candidates, init_records = initializers(
        unit_pool,
        traces,
        visible,
        cluster_budget=cluster_budget,
        skipped_notes=init_skip_notes,
        trust_schema=effective_trust_schema,
        schema_globals=schema_globals if effective_trust_schema else None,
        anon_tags=anon_tags if effective_trust_schema else None,
    )
    byval_inits: set[str] = set()
    schema_inits: dict[str, tuple[int, str]] = {}
    if effective_trust_schema:
        byval_inits, schema_inits = builder_metadata(inits, init_records)
    struct_dtors, struct_dtor_names = struct_destructors(unit_pool, visible, cluster_budget=cluster_budget)
    freers = struct_freers(struct_dtor_names)
    if cluster_budget is not None:
        freers = {t: fn for t, fn in freers.items() if cluster_budget.fits(fn)}
    helper_pool = (set(inits.values()) | set(struct_dtors.values()) | set(freers.values())) - entry_names
    # A constructor that returns the handle keeps its place; out-parameter ones fill the other types.
    out_ctors = {t: c for t, c in outp.ctors.items() if t not in ctors}
    structs = dict(struct_layouts or {})
    # The typedef's layout under the model's tag too: a case looks an object up by the model's type.
    structs.update({tag: structs[n] for tag, n in anon_tags.items() if n in structs})
    # Rule G: destructors that take tables of function pointers, and the producers of what they free.
    allocating = allocating_functions(model.get("functions") or {})
    const_rets = set(getattr(visible, "const_returns", None) or ())
    owners, owner_names, owner_tables = struct_owners(unit_pool, visible, structs)
    producers = struct_producers(unit_pool, visible, owners, owner_tables, structs, allocating, const_rets)
    if cluster_budget is not None:
        # As the freers above: a helper from another cluster only within the cluster's limits. A
        # destructor whose producers all fall out is skipped; a producer whose destructor does is not freed.
        owners = {t: fn for t, fn in owners.items() if cluster_budget.fits(fn)}
        producers = {t: kept for t, ns in producers.items() if (kept := [n for n in ns if cluster_budget.fits(n)])}
    callable_recs = _callable_records(unit_pool, visible)
    g_names = set(owners.values()) | {ns[0] for ns in producers.values()}
    helper_pool |= g_names - entry_names
    model_fns = model.get("functions") or {}
    trans_writes: dict[str, set[str]] = {}
    trans_refs: dict[str, set[str]] = {}
    if effective_trust_schema and (traces or merged_globals):
        trans_writes, trans_refs = _global_state_flow(model_fns)
    global_td = (
        _global_teardowns(callable_recs, traces, trans_writes) if (effective_trust_schema and trans_writes) else {}
    )
    freeing_fns = _reaching(model_fns, frozenset({"free"}))
    if effective_trust_schema and trans_writes and merged_globals:
        for fn, td in _freeing_global_teardowns(callable_recs, merged_globals, trans_writes, freeing_fns).items():
            global_td.setdefault(fn, td)
    global_freed_ptrs, global_retained_ptrs, global_types_known = (
        _global_pointer_ownership(merged_globals, trans_writes, global_td, freeing_fns, anon_tags)
        if (effective_trust_schema and trans_writes)
        else ({}, {}, set())
    )
    helper_pool |= set(global_td.values()) - entry_names
    api = ApiInfo(
        structs=structs,
        probed=struct_layouts is not None,
        inits=inits,
        candidates=candidates,
        records={
            **{n: callable_recs[n] for n in g_names},
            **{n: callable_recs[n] for n in set(global_td.values()) if n in callable_recs},
            **init_records,
            **all_ctor_records,
            **ctor_records,
            **{c[0]: outp.records[c[0]] for c in out_ctors.values()},
        },
        handles=handles,
        ctors=ctors,
        dtors=dtors,
        dtor_names=dtor_names,
        closers=handle_closers(dtors, dtor_names, model_fns),
        returns=returns,
        outs=outp.outs,
        out_ctors=out_ctors,
        out_ctor_names=outp.names,
        parents={t: p for t, p in outp.parents.items() if t in out_ctors},
        callbacks=dict(getattr(visible, "callbacks", None) or {}) if callback_stubs else {},
        enum_ptrs=dict(getattr(visible, "enum_pointers", None) or {}),
        qual_ptrs=dict(getattr(visible, "qualified_pointers", None) or {}),
        anon_tags=anon_tags,
        struct_dtors=struct_dtors,
        struct_dtor_names=struct_dtor_names,
        struct_freers=freers,
        enum_params=dict(getattr(visible, "enum_params", None) or {}),
        const_returns=const_rets,
        allocating=allocating,
        limits=limit_parameters(model_fns),
        init_skip_notes=init_skip_notes,
        bounds=dict(getattr(visible, "bound_forwards", None) or {}),
        null_defaults=set(getattr(visible, "null_defaults", None) or ()),
        pointer_free_records=set(getattr(visible, "pointer_free_records", None) or ()),
        table_stubs=callback_stubs,
        owners=owners,
        owner_names=owner_names,
        owner_tables=owner_tables,
        producers=producers,
        trust_schema=effective_trust_schema,
        ctor_cands=ctor_cands,
        byval_inits=byval_inits,
        schema_inits=schema_inits,
        schema_globals=schema_globals,
        trusted_strings=recorded_strings(traces) if effective_trust_schema else {},
        trusted_scalars=recorded_scalars(traces) if effective_trust_schema else {},
        recorded_input_buffers=recorded_input_buffers(traces),
        heap_buffer_fns=_reaching(model_fns, _HEAP_SIZE_PROBERS),
        freeing=freeing_fns,
        global_teardown=global_td,
        global_freed_ptrs=global_freed_ptrs,
        global_retained_ptrs=global_retained_ptrs,
        global_types_known=global_types_known,
    )
    # Each function's threat-model roles by name, for the sequence cases (bound as in its single case).
    trust_by_name: dict[str, _EntryTrust] = {}
    singles: dict[str, dict] = {}
    header_entries: list[tuple[str, str]] = []
    for key in entries:
        drec = functions.get(key) or {}
        name = str(drec.get("name") or key.split("#")[-1])
        if name == "main":
            continue
        if effective_trust_schema and tm_active:
            et = entry_trust_map.get(key) or _EntryTrust()
            if et.trusted_caller or et.input_role is None:
                skipped[key] = NO_ATTACKER_DATA_REASON
                auto_exempt[key] = NO_ATTACKER_DATA_REASON
                continue
        else:
            et = None
        if drec.get("is_static") and drec.get("header"):
            # Defined in a public header (`header_api`): callable once the layout probe saw the
            # harness declare it. Its case comes after every other generated one (HD4).
            if visible is not None and name in visible:
                header_entries.append((key, name))
            else:
                skipped[key] = HEADER_NOT_VISIBLE
            continue
        if drec.get("is_static"):
            skipped[key] = STATIC_NOT_CALLABLE_REASON
            if effective_trust_schema:
                auto_exempt[key] = STATIC_NOT_CALLABLE_REASON
            continue
        mrec = _model_record(model, drec, key)
        if not mrec:
            skipped[key] = "not in the Phase 0 model"
            continue
        path = path_parameter(mrec)
        if path:
            skipped[key] = PATH_SKIP_REASON.format(name=path)
            continue
        if is_variadic(str(mrec.get("signature") or ""), mrec.get("formals")):
            # Not in `records`: a sequence or a lifecycle case builds its calls from the signature.
            made, left_out = variadic_cases(key, name, mrec, (variadic or {}).get(name) or [], spare, api)
            dropped += left_out
            if made:
                names.append(key)
                variadic_made += made
            else:
                skipped[key] = f"{NO_VARIADIC_SITE} ({left_out[0]['why']})" if left_out else NO_VARIADIC_SITE
            continue
        made_cases, why, is_exempt, used_srcs = _single_cases_for_entry(name, mrec, spare, api, et)
        if not made_cases:
            skipped[key] = str(why)
            if is_exempt:
                auto_exempt[key] = str(why)
            continue
        schema_sources.update(used_srcs)
        records[name] = mrec
        names.append(key)
        if et is not None:
            trust_by_name[name] = et
        singles[name] = made_cases[0][1]
        for c_stmt, c_layout in made_cases:
            cases.append(c_stmt)
            layouts.append({**c_layout, "entry": key})
    for v_stmt, v_layout in variadic_made:
        cases.append(v_stmt)
        layouts.append(v_layout)
    configurators = _sequence_configurator_records(
        dag,
        model,
        module,
        mm,
        records,
        api,
        anon_tags,
        visible,
        tm_active,
        entry_trust_map,
        skipped,
        cluster_budget,
    )
    for cname, crec in configurators.items():
        api.records.setdefault(cname, crec)
    seq_allowed = set(records) | set(configurators)
    seq_seen: set[tuple[str, ...]] = set()
    # Calls into other modules (an entropy source filling a nonce) are not replayed: what they
    # produced comes from the input instead, and the rest of the chain stays.
    filtered_traces = [[c for c in full if c.get("fn") in seq_allowed] for full in traces or []]
    global_setups: list[dict[str, Any]] = []
    if effective_trust_schema and filtered_traces and trans_writes:
        global_setups = _global_setup_plan(filtered_traces, records, singles, api, trans_writes, trans_refs)

    def _fallback_teardown(trace: list[dict], prefix: list[int]) -> str | None:
        for k in reversed(prefix):
            gtd = api.global_teardown.get(str(trace[k]["fn"]))
            if gtd:
                return gtd
        return None

    def _emit_sequence(
        trace: list[dict],
        chain: list[int],
        setup_positions: Collection[int] | None = None,
        trailing_teardown: str | None = None,
    ) -> None:
        setup_pos = set(setup_positions or ())
        if not any(trace[k]["fn"] in records for pos, k in enumerate(chain) if pos not in setup_pos):
            return
        sig = tuple(trace[k]["fn"] for k in chain) + ((trailing_teardown,) if trailing_teardown else ())
        if sig in seq_seen or len(seq_seen) >= MAX_SEQUENCE_CASES:
            return
        seq_stmt, seq_layout, _why = sequence_case(
            trace,
            chain,
            records,
            spare,
            api,
            trust_by_name,
            setup_positions=setup_pos or None,
            trailing_teardown=trailing_teardown,
        )
        if seq_stmt is None or seq_layout is None:
            if not setup_pos and any(trace[k]["fn"] not in records for k in chain):
                rec_trace = [trace[k] for k in chain if trace[k]["fn"] in records]
                for sub_chain in chains(rec_trace):
                    sub_sig = tuple(rec_trace[k]["fn"] for k in sub_chain)
                    if sub_sig in seq_seen or len(seq_seen) >= MAX_SEQUENCE_CASES:
                        continue
                    sub_stmt, sub_layout, _ = sequence_case(rec_trace, sub_chain, records, spare, api, trust_by_name)
                    if sub_stmt is None or sub_layout is None:
                        continue
                    seq_seen.add(sub_sig)
                    cases.append(sub_stmt)
                    layouts.append(sub_layout)
            return
        seq_seen.add(sig)
        cases.append(seq_stmt)
        layouts.append(seq_layout)

    if not global_setups:
        for trace in filtered_traces:
            for chain in chains(trace):
                _emit_sequence(trace, chain)
    else:
        global_targets = {item["fn"] for item in global_setups}
        multi_fn_chains: list[tuple[list[dict], list[int], set[int], str | None]] = []
        same_fn_chains: list[tuple[list[dict], list[int], set[int], str | None]] = []
        for trace in filtered_traces:
            for chain in chains(trace):
                if not any(trace[k]["fn"] in records for k in chain):
                    continue
                prefix, td = _global_setup_prefix(trace, chain, records, api, trans_writes, trans_refs)
                prefix = [k for k in prefix if k not in chain]
                if td is not None and td in chain:
                    td = None
                full_chain = [*prefix, *chain, *([td] if td is not None else [])]
                setup_pos = set(range(len(prefix))) | ({len(full_chain) - 1} if td is not None else set())
                needs_setup = any(trace[k]["fn"] in global_targets for k in chain)
                if needs_setup and not prefix:
                    continue
                fb_td = _fallback_teardown(trace, prefix) if (prefix and td is None) else None
                if len({trace[k]["fn"] for k in chain}) > 1:
                    multi_fn_chains.append((trace, full_chain, setup_pos, fb_td))
                else:
                    same_fn_chains.append((trace, full_chain, setup_pos, fb_td))
        for item in global_setups:
            prefix = list(item["prefix"])
            td = item["teardown"]
            full_chain = [*prefix, int(item["target"]), *([int(td)] if td is not None else [])]
            setup_pos = set(range(len(prefix))) | ({len(full_chain) - 1} if td is not None else set())
            fb_td = _fallback_teardown(item["trace"], prefix) if td is None else None
            _emit_sequence(item["trace"], full_chain, setup_pos, trailing_teardown=fb_td)
        for trace, full_chain, setup_pos, fb_td in multi_fn_chains:
            _emit_sequence(trace, full_chain, setup_pos, trailing_teardown=fb_td)
        for trace, full_chain, setup_pos, fb_td in same_fn_chains:
            _emit_sequence(trace, full_chain, setup_pos, trailing_teardown=fb_td)
    # Every handle type with a constructor and a destructor gets one synthesized lifecycle case, within
    # the same cap as the recorded sequences (which come first). A recorded chain does not cover the
    # type: sequence_case passes a shared handle as a zeroed buffer (an incomplete struct does not
    # even compile), never the constructor's result, which the traces do not record.
    n_seq = len(seq_seen)
    for htype in sorted((set(api.ctors) | set(api.out_ctors)) & set(api.dtors)):
        if n_seq >= MAX_SEQUENCE_CASES:
            break
        methods = lifecycle_methods(htype, records, api)
        lc_stmt, lc_layout, _why = lifecycle_case(htype, methods, records, spare, api)
        if lc_stmt is None or lc_layout is None:
            continue
        n_seq += 1
        cases.append(lc_stmt)
        layouts.append(lc_layout)
    # The functions defined in a public header, after the cases above: those keep their selectors,
    # and these go over the case limit before them (only the stateful cases below go first). They
    # stay out of `records`, which builds the sequence and lifecycle cases above, so those are the
    # same with or without them.
    for key, name in header_entries:
        mrec = _model_record(model, functions.get(key) or {}, key)
        if not mrec:
            skipped[key] = "not in the Phase 0 model"
            continue
        if is_variadic(str(mrec.get("signature") or ""), mrec.get("formals")):
            skipped[key] = HEADER_VARIADIC
            continue
        et = entry_trust_map.get(key) if (effective_trust_schema and tm_active) else None
        made_cases, why, is_exempt, used_srcs = _single_cases_for_entry(name, mrec, spare, api, et)
        if not made_cases:
            skipped[key] = str(why)
            if is_exempt:
                auto_exempt[key] = str(why)
            continue
        schema_sources.update(used_srcs)
        names.append(key)
        for stmt, layout in made_cases:
            cases.append(stmt)
            layouts.append({**layout, "entry": key})
    # Stateful cases, last: an entry point that fails on a fresh context, after the calls that set up
    # the state it needs (`stateful_prefixes`), within their own cap. Its single case stays, and over
    # the case limit these go first, so no entry point loses its single case to them.
    header_keys = {k for k, _ in header_entries}
    key_of = {str((functions.get(k) or {}).get("name") or k.split("#")[-1]): k for k in names if k not in header_keys}
    n_state = 0
    for plan_st in stateful_prefixes(
        records, singles, api, model.get("functions") or {}, traces, configurators=configurators
    ):
        sig = tuple(plan_st["calls"])
        if n_state >= STATE_MAX_CASES or sig in seq_seen:
            continue
        ctx_trace = [{"fn": fn, "args": {}, "addrs": {"0": "fc_ctx"}} for fn in plan_st["calls"]]
        st_stmt, st_layout, _why = sequence_case(
            ctx_trace, list(range(len(ctx_trace))), records, spare, api, trust_by_name
        )
        if st_stmt is None or st_layout is None:
            if any(fn not in records for fn in plan_st["calls"]):
                rec_calls = [fn for fn in plan_st["calls"] if fn in records]
                rec_sig = tuple(rec_calls)
                if len(rec_calls) > 1 and rec_sig not in seq_seen:
                    rec_trace = [{"fn": fn, "args": {}, "addrs": {"0": "fc_ctx"}} for fn in rec_calls]
                    st_stmt, st_layout, _why = sequence_case(
                        rec_trace, list(range(len(rec_trace))), records, spare, api, trust_by_name
                    )
                    if st_stmt is not None and st_layout is not None:
                        sig = rec_sig
            if st_stmt is None or st_layout is None:
                continue
        seq_seen.add(sig)
        n_state += 1
        st_layout["notes"] = [
            *(st_layout.get("notes") or []),
            f"stateful case ({plan_st['state']}): {plan_st['entry']} {plan_st['why']}",
        ]
        cases.append(st_stmt)
        layouts.append({**st_layout, "entry": key_of[plan_st["entry"]], "state": plan_st["state"]})
    if len(cases) > max_cases:
        for lay in layouts[max_cases:]:
            if lay.get("entry"):
                skipped[lay["entry"]] = f"more than {MAX_CASES} cases"
            if lay.get("kind") == VARIADIC_KIND:
                dropped.append(_dropped_variadic(lay, f"more than {MAX_CASES} cases"))
        cases, layouts = cases[:max_cases], layouts[:max_cases]
        skipped = still_skipped(layouts, skipped)
    auto_exempt = still_skipped(layouts, auto_exempt)
    for sel, lay in enumerate(layouts):
        lay["selector"] = sel
    return {
        "entries": names,
        "cases": cases,
        "layouts": layouts,
        "skipped": skipped,
        "auto_exempt": auto_exempt,
        "stubs": dict(api.stubs),
        "schema_externs": dict(api.schema_externs),
        "schema_sources": sorted(schema_sources),
        "variadic_dropped": dropped,
        "helpers": case_helpers(cases, layouts, helper_pool),
        "helper_pool": sorted(helper_pool),
    }


def case_helpers(cases: Sequence[str], layouts: Sequence[dict], pool: set[str] | Sequence[str]) -> list[str]:
    """
    The functions of `pool` (initializers and destructors from outside the module's scope) the cases
    call to set up or release an object: the sidecar's `api_helpers`. They run with arguments no case
    reads from the input, so the reach gate counts none of them as a root of the module
    (`harness_reach.check_module`).
    """
    names = set(pool)
    used = {str(i.get("fn")) for lay in layouts for i in lay.get("inits") or [] if isinstance(i, dict)}
    used |= {n for n in names if any(re.search(rf"\b{re.escape(n)}\s*\(", c) for c in cases)}
    return sorted(used & names)


_STUB_NAME_RE = re.compile(r"\bframac_cb_\w+")


def stubs_used(cases: list[str], stubs: dict[str, str]) -> list[str]:
    """The definitions of the callback stubs `cases` call, in name order (an unused one is left out)."""
    used = {m.group(0) for c in cases for m in _STUB_NAME_RE.finditer(c)}
    return [stubs[s] for s in sorted(used) if s in stubs]


def schema_externs_used(cases: list[str], externs: dict[str, str]) -> list[str]:
    """The `extern` declarations of S3 const schema globals `cases` reference, in name order."""
    if not externs:
        return []
    return [externs[g] for g in sorted(externs) if any(re.search(rf"\b{re.escape(g)}\b", c) for c in cases)]


SYNTH_PROTO_MARKER = "framac-api-synth-proto:"
_SYNTH_PROTO_LINE_RE = re.compile(r"/\*\s*framac-api-synth-proto:\s*([A-Za-z_]\w*)\s*\*/")
_UNDECLARED_FN_RE = re.compile(
    r"(?:call to undeclared function|implicit declaration of function)\s+['`\u2018]([A-Za-z_]\w*)['`\u2019]"
)
_TAG_USE_RE = re.compile(r"\b(struct|union)\s+([A-Za-z_]\w*)\b")


def _apply_const_pointee(ctype: str) -> str:
    """Restore `const` on the direct pointee of a CIL-canonical pointer type (`T *` -> `T const *`)."""
    s = _spelled(ctype)
    if "(" in s or "*" not in s:
        return s
    idx = s.rfind("*")
    head, tail = s[:idx].rstrip(), s[idx:]
    if re.search(r"\bconst\s*$", head):
        return s
    return f"{head} const {tail}"


def synthesize_extern_prototype(
    name: str,
    rec: Mapping[str, Any],
    anon_tags: Mapping[str, str] | None = None,
    known_structs: Collection[str] | None = None,
) -> tuple[str, str] | None:
    """
    Build a C `extern` prototype for an exported (non-`static`, non-variadic) function from its
    Phase 0 model signature when no included header declares it. Returns `(marked_line, clean_decl)`
    or `None` when the signature cannot be spelled safely in the harness's header scope (e.g.
    variadic, function-pointer return, or unresolved anonymous struct/union/enum tag).
    """
    if not _IDENT_RE.fullmatch(name) or rec.get("static"):
        return None
    sig = str(rec.get("signature") or "")
    formals = list(rec.get("formals") or [])
    if not sig or is_variadic(sig, formals):
        return None
    parts = split_signature(sig)
    if parts is None:
        return None
    ret_raw, param_raws, _ = parts
    if not ret_raw or "(" in ret_raw or "[" in ret_raw:
        return None
    tags = anon_tags or {}

    def _spell_type(t: str) -> str | None:
        def _rep(m: re.Match[str]) -> str:
            tag = " ".join(m.group(0).split())
            return tags.get(tag, m.group(0))

        spelled = _ANON_RECORD_RE.sub(_rep, _spelled(t))
        if _ANON_TAG_RE.search(spelled):
            return None
        return spelled

    ret = _spell_type(ret_raw)
    if ret is None:
        return None
    spelled_params: list[str] = []
    for k, raw_p in enumerate(param_raws):
        sp = _spell_type(raw_p)
        if sp is None:
            return None
        if k < len(formals) and isinstance(formals[k], Mapping) and formals[k].get("kind") == "const_pointer":
            sp = _apply_const_pointee(sp)
        spelled_params.append(sp)
    params_c = ", ".join(spelled_params) if spelled_params else "void"
    clean_decl = f"extern {ret} {name}({params_c});"
    known = set(known_structs or ())
    fwd_tags: set[tuple[str, str]] = set()
    for t in (ret, *spelled_params):
        if "*" not in t:
            continue
        for m in _TAG_USE_RE.finditer(t):
            kw, tag = m.group(1), m.group(2)
            if f"{kw} {tag}" not in known:
                fwd_tags.add((kw, tag))
    fwd_prefix = " ".join(f"{kw} {tag};" for kw, tag in sorted(fwd_tags))
    decl_line = f"{fwd_prefix} {clean_decl}" if fwd_prefix else clean_decl
    marked_line = f"{decl_line} /* {SYNTH_PROTO_MARKER} {name} */"
    return marked_line, clean_decl


def synth_protos_used(cases: Sequence[str], protos: Mapping[str, str]) -> list[str]:
    """The synthesized `extern` prototypes referenced by `cases`, in name order."""
    if not protos:
        return []
    return [protos[fn] for fn in sorted(protos) if any(re.search(rf"\b{re.escape(fn)}\s*\(", c) for c in cases)]


def _synth_proto_errors(harness_c: Path, errors: Sequence[str]) -> set[str] | None:
    """
    When every compile error outside the cases (`probe_cases`) lands on a synthesized `extern`
    prototype line, return the set of function names whose synthesized prototypes errored; else None.
    """
    try:
        lines = harness_c.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    bad_fns: set[str] = set()
    for err in errors:
        m = _ERR_LINE_RE.match(err)
        if not m or Path(m.group("file")).name != harness_c.name:
            return None
        no = int(m.group("line"))
        if not (0 < no <= len(lines)):
            return None
        pm = _SYNTH_PROTO_LINE_RE.search(lines[no - 1])
        if not pm:
            return None
        bad_fns.add(pm.group(1))
    return bad_fns or None


def _dropped_variadic(layout: dict, why: str) -> dict[str, Any]:
    """The `api_variadic_dropped` record of a variadic case that was planned and then left out."""
    return {
        "entry": str(layout.get("entry") or ""),
        "format": str(layout.get("format")),
        "varargs": list(layout.get("varargs") or []),
        "why": why,
    }


# --- struct layouts (clang's AST of the harness) ----------------------------------------------------

_CASE_LINE_RE = re.compile(r"\s*case (\d+)U: \{")
_ARRAY_RE = re.compile(r"^(?P<elem>.*\S)\s*\[(?P<n>\d+)\]$")
_POINTER_RE = re.compile(r"\*\s*(?:const|volatile|restrict|__restrict)?\s*$")
_RECORD_TYPE_RE = re.compile(r"^(struct|union|enum)\s+([A-Za-z_]\w*)$")
_UNSUPPORTED_ATTRS = {"PackedAttr", "AlignedAttr", "MaxFieldAlignmentAttr"}


def _walk_records(tree: dict) -> tuple[dict[str, dict], set[str]]:
    """Complete named struct/union definitions (`struct tag` -> AST node) and the declared function names."""
    records: dict[str, dict] = {}
    functions: set[str] = set()
    stack = [tree]
    while stack:
        node = stack.pop()
        kind = node.get("kind")
        if kind == "FunctionDecl":
            if isinstance(node.get("name"), str):
                functions.add(node["name"])
            continue  # bodies hold no type definitions the API uses
        if kind == "RecordDecl" and node.get("completeDefinition") and node.get("name"):
            records.setdefault(f"{node.get('tagUsed', 'struct')} {node['name']}", node)
        stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))
    return records, functions


# The spelling older clangs give an anonymous record (`struct (unnamed struct at x.h:2:9)`, `(anonymous
# union at ...)`); clang 19 spells a typedef's anonymous record by the typedef's name (`struct str_t`).
_UNNAMED_RECORD_RE = re.compile(r"\((?:unnamed|anonymous)\b[^()]*\)")


def _anon_record_nodes(tree: dict) -> dict[str, tuple[str, str, dict]]:
    """
    The typedef names of anonymous structs and unions (`typedef struct { size_t len; u_char *data; }
    ngx_str_t;`): name -> (struct or union, the record's AST id, its RecordDecl). A typedef names the
    record itself, never a pointer to it or an array of it (`typedef struct { ... } *p_t;` is left
    out); a typedef of such a typedef (`typedef str_t text_t;`) names the same record.
    """
    nameless: dict[str, tuple[str, dict]] = {}
    typedefs: list[dict] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        kind = node.get("kind")
        if kind == "FunctionDecl":
            continue
        if kind == "RecordDecl" and node.get("completeDefinition") and not node.get("name"):
            if isinstance(node.get("id"), str):
                nameless.setdefault(node["id"], (str(node.get("tagUsed") or "struct"), node))
        elif kind == "TypedefDecl" and isinstance(node.get("name"), str):
            typedefs.append(node)
        stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))
    out: dict[str, tuple[str, str, dict]] = {}
    for node in typedefs:
        qual = _UNNAMED_RECORD_RE.sub("X", str((node.get("type") or {}).get("qualType") or ""))
        if any(c in qual for c in "*[("):
            continue
        rid = _decl_ref(node, "RecordDecl")
        if rid in nameless:
            what, rec = nameless[rid]
            out.setdefault(node["name"], (what, rid, rec))
    grown = True
    while grown:
        grown = False
        for node in typedefs:
            target = _spelled(str((node.get("type") or {}).get("qualType") or ""))
            if node["name"] not in out and target in out:
                out[node["name"]] = out[target]
                grown = True
    return out


def anon_record_pointers(tree: dict, anon: Collection[str]) -> dict[str, dict[int, str]]:
    """
    Per declared function, the parameters (index) and the return (index -1) that point to an
    anonymous struct or union through one of its typedef names (`anon`), as the declaration writes
    them: `const ngx_str_t *s` gives "ngx_str_t". The model spells that pointer with Frama-C's tag
    (`struct __anonstruct_ngx_str_t_13 *`), which no header defines; `anon_record_tags` joins the two.
    """
    out: dict[str, dict[int, str]] = {}
    stack = [tree]
    while stack:
        node = stack.pop()
        if node.get("kind") != "FunctionDecl":
            stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))
            continue
        name = node.get("name")
        qual = str((node.get("type") or {}).get("qualType") or "")
        if not isinstance(name, str) or "(" not in qual:
            continue
        written = [(-1, qual[: qual.index("(")])]
        parms = [n for n in node.get("inner") or [] if isinstance(n, dict) and n.get("kind") == "ParmVarDecl"]
        written += [(i, str((p.get("type") or {}).get("qualType") or "")) for i, p in enumerate(parms)]
        for i, t in written:
            bare = _spelled(t)
            base = bare.rstrip("* ").strip()
            if bare.endswith("*") and base in anon:
                out.setdefault(name, {})[i] = base
    return out


class Declared(set):  # type: ignore[type-arg]
    """
    The function names a probe saw declared. `prototypes` gives, for each, the opaque handle types in
    its declaration as written: {name: {"ret": type or None, "params": [type or None, ...]}}.
    """

    prototypes: dict[str, dict[str, Any]]
    callbacks: dict[str, dict[int, dict[str, Any]]]
    enum_pointers: dict[str, dict[int, dict[str, str]]]
    qualified_pointers: dict[str, dict[int, dict[str, str]]]
    enum_params: dict[str, dict[int, list[str]]]
    const_returns: set[str]
    bound_forwards: dict[str, dict[int, tuple[str, str]]]
    anon_records: dict[str, dict[str, str]]
    anon_record_pointers: dict[str, dict[int, str]]
    null_defaults: set[str]
    pointer_free_records: set[str]

    def __init__(
        self,
        names: Any = (),
        prototypes: dict[str, dict[str, Any]] | None = None,
        callbacks: dict[str, dict[int, dict[str, Any]]] | None = None,
        enum_pointers: dict[str, dict[int, dict[str, str]]] | None = None,
        qualified_pointers: dict[str, dict[int, dict[str, str]]] | None = None,
        enum_params: dict[str, dict[int, list[str]]] | None = None,
        const_returns: set[str] | None = None,
        bound_forwards: dict[str, dict[int, tuple[str, str]]] | None = None,
        anon_records: dict[str, dict[str, str]] | None = None,
        anon_record_pointers: dict[str, dict[int, str]] | None = None,
        null_defaults: set[str] | None = None,
        pointer_free_records: set[str] | None = None,
    ) -> None:
        super().__init__(names)
        self.prototypes = prototypes or {}
        # `callback_prototypes`: per function, parameter index -> the callback's spelled prototype.
        self.callbacks = callbacks or {}
        # `enum_pointer_spellings`: per function, parameter index -> {type, pointee} of an enum pointer.
        self.enum_pointers = enum_pointers or {}
        # `qualified_pointer_spellings`: per function, parameter index -> {type, pointee} of a `T *const *`
        # or `const T **` parameter, as the header writes it.
        self.qualified_pointers = qualified_pointers or {}
        # `param_enums`: per function, parameter index -> the declared constants of an enum by value.
        self.enum_params = enum_params or {}
        # `const_returns`: the functions whose declaration returns a pointer to `const`.
        self.const_returns = set(const_returns or ())
        # `bound_forwards`: per function, parameter index -> (">=" or "<=", constant) of a lone range bound.
        self.bound_forwards = bound_forwards or {}
        # `_anon_record_nodes`: the typedef names of anonymous structs and unions -> {what, id}.
        self.anon_records = anon_records or {}
        # `anon_record_pointers`: per function, parameter index (-1: the return) -> the typedef name
        # through which it points to an anonymous struct or union.
        self.anon_record_pointers = anon_record_pointers or {}
        # `null_default_records`: the struct types a doc comment documents as NULL for a default.
        self.null_defaults = set(null_defaults or ())
        # Complete structs/unions (including packed or bit-field records) with no pointer fields.
        self.pointer_free_records = set(pointer_free_records or ())


def _spelled(t: str) -> str:
    return " ".join(_QUALIFIERS_RE.sub(" ", t).split())


_FN_POINTER_TYPE_RE = re.compile(r"^(?P<ret>[^()]+?)\s*\(\s*\*\s*\)\s*\((?P<params>.*)\)$")
_FN_TYPE_RE = re.compile(r"^(?P<ret>[^()]+?)\s*\((?P<params>.*)\)$")


def _split_top(text: str) -> list[str]:
    out: list[str] = []
    cur, depth = "", 0
    for ch in text:
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
            continue
        depth += ch in "([{"
        depth -= ch in ")]}"
        cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def _callback_prototype(written: str, typedefs: dict[str, str]) -> dict[str, Any] | None:
    """
    {"ret": type, "params": [type, ...]} of a function-pointer parameter whose declared type is
    `written` (clang's qualType), spelled with the names the headers use, or None when it is not a
    function pointer or a part cannot be spelled in C at file scope (an unnamed type, a nested function
    pointer, an array, a variadic list). Typedefs are followed one level at a time, never desugared, so
    `QCBORError` stays `QCBORError` where the model has `enum __anonenum_QCBORError_1`.
    """
    cur = " ".join(written.split())
    cur = re.sub(r"\s*\bconst\s*$", "", cur)
    fn: re.Match[str] | None = None
    for _ in range(8):
        fn = _FN_POINTER_TYPE_RE.match(cur)
        if fn:
            break
        if cur.endswith("*"):
            base = _spelled(cur[:-1])
            target = typedefs.get(base)
            fn = _FN_TYPE_RE.match(" ".join(target.split())) if target else None
            if fn:
                break
        nxt = typedefs.get(_spelled(cur))
        if nxt is None:
            return None
        cur = re.sub(r"\s*\bconst\s*$", "", " ".join(nxt.split()))
    if fn is None:
        return None
    ret = fn.group("ret").strip()
    params = _split_top(fn.group("params"))
    if params == ["void"]:
        params = []
    for t in [ret, *params]:
        if not t or any(bad in t for bad in ("(", "[", "...", "unnamed", "anonymous", "__anon")):
            return None
    return {"ret": ret, "params": params}


def callback_prototypes(tree: dict) -> dict[str, dict[int, dict[str, Any]]]:
    """Per declared function, its function-pointer parameters (index -> `_callback_prototype`)."""
    typedefs: dict[str, str] = {}
    decls: list[dict] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        kind = node.get("kind")
        if kind == "FunctionDecl":
            decls.append(node)
            continue
        if kind == "TypedefDecl" and isinstance(node.get("name"), str):
            typedefs.setdefault(node["name"], str((node.get("type") or {}).get("qualType") or ""))
        stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))
    out: dict[str, dict[int, dict[str, Any]]] = {}
    for node in decls:
        name = node.get("name")
        if not isinstance(name, str):
            continue
        parms = [n for n in node.get("inner") or [] if isinstance(n, dict) and n.get("kind") == "ParmVarDecl"]
        for i, parm in enumerate(parms):
            proto = _callback_prototype(str((parm.get("type") or {}).get("qualType") or ""), typedefs)
            if proto is not None:
                out.setdefault(name, {})[i] = proto
    return out


_TRAILING_QUALIFIER_RE = re.compile(r"\s*\b(?:const|volatile|restrict|__restrict)\s*$")


def enum_pointer_spellings(tree: dict) -> dict[str, dict[int, dict[str, str]]]:
    """
    Per declared function, its parameters that point to an enum through a typedef name, as the
    declaration writes them: index -> {"type": `cls_t *` (a `const` pointee kept, the parameter's own
    qualifier dropped), "pointee": `cls_t`}. c-ares's `typedef enum { ... } ares_dns_class_t;` is
    anonymous: the model names it `enum __anonenum_ares_dns_class_t_7`, which no header defines, so
    a case declares the object as `ares_dns_class_t`. Typedefs are followed only to learn that the
    name is an enum, never to spell it; a pointee that is not a plain typedef name is left out.
    """
    typedefs: dict[str, str] = {}
    decls: list[dict] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        kind = node.get("kind")
        if kind == "FunctionDecl":
            decls.append(node)
            continue
        if kind == "TypedefDecl" and isinstance(node.get("name"), str):
            typedefs.setdefault(node["name"], str((node.get("type") or {}).get("qualType") or ""))
        stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))

    def is_enum(name: str) -> bool:
        seen: set[str] = set()
        t = name
        while t in typedefs and t not in seen:
            seen.add(t)
            t = _spelled(typedefs[t])
        return t.startswith("enum ")

    out: dict[str, dict[int, dict[str, str]]] = {}
    for node in decls:
        name = node.get("name")
        if not isinstance(name, str):
            continue
        parms = [n for n in node.get("inner") or [] if isinstance(n, dict) and n.get("kind") == "ParmVarDecl"]
        for i, parm in enumerate(parms):
            qual = " ".join(str((parm.get("type") or {}).get("qualType") or "").split())
            written = _TRAILING_QUALIFIER_RE.sub("", qual)
            bare = _spelled(written)
            if not bare.endswith("*"):
                continue
            base = bare[:-1].strip()
            if not _IDENT_RE.fullmatch(base) or not is_enum(base):
                continue
            out.setdefault(name, {})[i] = {"type": written, "pointee": base}
    return out


_PLAIN_TYPE_RE = re.compile(r"[\w\s*]+")


def _drop_trailing_qualifiers(t: str) -> str:
    while True:
        s = _TRAILING_QUALIFIER_RE.sub("", t)
        if s == t:
            return t
        t = s


def qualified_pointer_spellings(tree: dict) -> dict[str, dict[int, dict[str, str]]]:
    """
    Per declared function, its parameters that point to a qualified pointer, as the declaration writes
    them: index -> {"type": `const char **` (the parameter's own qualifier dropped), "pointee": the
    object a case declares behind it, `const char *` (its own qualifier dropped too: `char *const *`
    gives `char *`, an object the case can zero and write)}. The model spells c-ares's
    `const char **name` as `char **`; a case that declares `char *` objects and casts to `char **`
    passes a pointer that discards the nested `const`, which gcc 14 refuses outright. Only plain
    spellings (identifiers, `*`, qualifiers) are kept: no function pointer, array, attribute, nor an
    anonymous type, whose tag no header defines.
    """
    out: dict[str, dict[int, dict[str, str]]] = {}
    stack = [tree]
    while stack:
        node = stack.pop()
        if node.get("kind") != "FunctionDecl":
            stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))
            continue
        name = node.get("name")
        if not isinstance(name, str):
            continue
        parms = [n for n in node.get("inner") or [] if isinstance(n, dict) and n.get("kind") == "ParmVarDecl"]
        for i, parm in enumerate(parms):
            written = _drop_trailing_qualifiers(" ".join(str((parm.get("type") or {}).get("qualType") or "").split()))
            if not _PLAIN_TYPE_RE.fullmatch(written) or "__anon" in written or not written.endswith("*"):
                continue
            pointee = written[:-1].strip()
            if not _spelled(pointee).endswith("*") or not _QUALIFIERS_RE.search(pointee):
                continue
            out.setdefault(name, {})[i] = {"type": written, "pointee": _drop_trailing_qualifiers(pointee)}
    return out


def _enum_ref(node: Any) -> str | None:
    """The id of the first EnumDecl a typedef's type nodes refer to (`ownedTagDecl`, `decl`), if any."""
    return _decl_ref(node, "EnumDecl")


def _decl_ref(node: Any, kind: str) -> str | None:
    """The id of the first declaration of `kind` (EnumDecl, RecordDecl) a typedef's type nodes refer to."""
    stack = [node]
    while stack:
        cur = stack.pop()
        if isinstance(cur, dict):
            if cur.get("kind") == kind and isinstance(cur.get("id"), str):
                return cur["id"]
            stack.extend(reversed([v for k, v in cur.items() if k in ("inner", "ownedTagDecl", "decl")]))
        elif isinstance(cur, list):
            stack.extend(reversed(cur))
    return None


def _flag_enum(values: list[int | None]) -> bool:
    """Constants a caller combines with `|`: at least three, every nonzero one a distinct power of two."""
    known = [v for v in values if v is not None]
    if len(known) != len(values):
        return False
    nonzero = [v for v in known if v]
    return len(nonzero) >= 3 and len(set(nonzero)) == len(nonzero) and all(v > 0 and v & (v - 1) == 0 for v in nonzero)


def param_enums(tree: dict) -> dict[str, dict[int, list[str]]]:
    """
    Per declared function, its enum parameters by value (index -> the enum's constant names, in
    declaration order), as the headers define the enum: through `enum tag` or through a typedef,
    an anonymous enum's included (`typedef enum { ... } t;`, followed by the typedef's own tag
    reference). A case maps an input value that is none of them onto one (rule D). A flag enum
    (`_flag_enum`) is left out: its callers pass combinations, which a single constant would hide.
    """
    consts: dict[str, list[tuple[str, int | None]]] = {}
    by_name: dict[str, str] = {}
    typedefs: dict[str, str] = {}
    typedef_enum: dict[str, str] = {}
    decls: list[dict] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        kind = node.get("kind")
        if kind == "FunctionDecl":
            decls.append(node)
            continue
        if kind == "EnumDecl" and isinstance(node.get("id"), str):
            items: list[tuple[str, int | None]] = []
            nxt: int | None = 0
            for c in node.get("inner") or []:
                if not isinstance(c, dict) or c.get("kind") != "EnumConstantDecl" or not isinstance(c.get("name"), str):
                    continue
                init = [x for x in c.get("inner") or [] if isinstance(x, dict)]
                if init:
                    try:
                        nxt = int(str(init[0].get("value")), 0)
                    except ValueError:
                        nxt = None
                items.append((c["name"], nxt))
                nxt = None if nxt is None else nxt + 1
            if items:
                consts[node["id"]] = items
                if isinstance(node.get("name"), str) and node["name"]:
                    by_name[node["name"]] = node["id"]
        if kind == "TypedefDecl" and isinstance(node.get("name"), str):
            qual = str((node.get("type") or {}).get("qualType") or "")
            typedefs.setdefault(node["name"], qual)
            ref = _enum_ref(node.get("inner"))
            if ref is not None and "*" not in qual and "(" not in qual:
                typedef_enum.setdefault(node["name"], ref)
        stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))

    def resolve(t: str) -> str | None:
        t = _spelled(t)
        for _ in range(8):
            if t.startswith("enum "):
                return by_name.get(t[5:].strip())
            if typedef_enum.get(t) in consts:
                return typedef_enum[t]
            if t not in typedefs:
                return None
            t = _spelled(typedefs[t])
        return None

    out: dict[str, dict[int, list[str]]] = {}
    for node in decls:
        name = node.get("name")
        if not isinstance(name, str):
            continue
        parms = [n for n in node.get("inner") or [] if isinstance(n, dict) and n.get("kind") == "ParmVarDecl"]
        for i, parm in enumerate(parms):
            qual = " ".join(str((parm.get("type") or {}).get("qualType") or "").split())
            if "*" in qual or "[" in qual or "(" in qual:
                continue
            ref = resolve(qual)
            if ref is None or _flag_enum([v for _, v in consts[ref]]):
                continue
            out.setdefault(name, {})[i] = [n for n, _ in consts[ref]]
    return out


def const_returns(tree: dict) -> set[str]:
    """The declared functions whose return type is a pointer to `const` (`const char *`), as written."""
    out: set[str] = set()
    stack = [tree]
    while stack:
        node = stack.pop()
        if node.get("kind") != "FunctionDecl":
            stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))
            continue
        fn = _FN_TYPE_RE.match(" ".join(str((node.get("type") or {}).get("qualType") or "").split()))
        ret = fn.group("ret") if fn else ""
        if isinstance(node.get("name"), str) and "*" in ret and re.search(r"\bconst\b", ret[: ret.rfind("*")]):
            out.add(node["name"])
    return out


_TRANSPARENT_EXPRS = frozenset({"ImplicitCastExpr", "ParenExpr", "ConstantExpr"})


def _strip_expr(node: Any) -> Any:
    """`node` without implicit casts and parentheses (an explicit cast stays: it may change the value)."""
    while isinstance(node, dict) and node.get("kind") in _TRANSPARENT_EXPRS and node.get("inner"):
        node = node["inner"][0]
    return node


def _literal(node: Any) -> str | None:
    """The text of an integer or floating literal, a negated one included (`-5`), else None."""
    node = _strip_expr(node)
    if not isinstance(node, dict):
        return None
    if node.get("kind") in ("IntegerLiteral", "FloatingLiteral") and isinstance(node.get("value"), str):
        return node["value"]
    if node.get("kind") == "UnaryOperator" and node.get("opcode") in ("-", "+") and node.get("inner"):
        inner = _literal(node["inner"][0])
        if inner is not None and not inner.startswith("-"):
            return inner if node["opcode"] == "+" else f"-{inner}"
    return None


def _number(text: str) -> float | None:
    try:
        return float(int(text, 0))
    except ValueError:
        try:
            return float(text)
        except ValueError:
            return None


def _param_ref(arg: Any, pids: list[str]) -> int | None:
    """The index of the parameter (by AST id) an argument passes unchanged but for implicit conversions."""
    a = _strip_expr(arg)
    decl = a.get("referencedDecl") if isinstance(a, dict) and a.get("kind") == "DeclRefExpr" else None
    if isinstance(decl, dict) and decl.get("kind") == "ParmVarDecl" and decl.get("id") in pids:
        return pids.index(decl["id"])
    return None


def bound_forwards(tree: dict) -> dict[str, dict[int, tuple[str, str]]]:
    """
    Per function with a body in the probe's AST (an inline function of a header), its lone range
    bounds (rule A'): parameter index -> (">=", constant) when it passes that parameter, unchanged
    but for implicit conversions, as the upper bound of a range-like callee (two parameters
    `_range_partner` pairs, `min_value`/`max_value`) and a literal constant as the lower bound
    (`mpack_expect_i8_max(reader, max_value)` returns `mpack_expect_i8_range(reader, 0, max_value)`),
    or ("<=", constant) for a lower bound under a constant upper one. The callee asserts
    `min <= max`, so a value past the constant is a precondition the wrapper passes on. With several
    such calls the strictest constant is kept. An explicit cast, an expression or a constant macro
    that is not a literal gives nothing.
    """
    names: dict[str, list[str]] = {}
    bodies: list[tuple[str, list[str], dict]] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        if node.get("kind") != "FunctionDecl":
            stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))
            continue
        name = node.get("name")
        if not isinstance(name, str):
            continue
        inner = [n for n in node.get("inner") or [] if isinstance(n, dict)]
        parms = [n for n in inner if n.get("kind") == "ParmVarDecl"]
        pnames = [str(p.get("name") or "") for p in parms]
        if all(pnames) and name not in names:
            names[name] = pnames
        body = next((n for n in inner if n.get("kind") == "CompoundStmt"), None)
        if body is not None:
            bodies.append((name, [str(p.get("id") or "") for p in parms], body))

    def ranges(callee: str) -> list[tuple[int, int]]:
        ps = names.get(callee) or []
        return [(i, j) for i in range(len(ps)) for j in range(i + 1, len(ps)) if _range_partner(ps[i], ps[j])]

    out: dict[str, dict[int, tuple[str, str]]] = {}
    for name, pids, body in bodies:
        calls: list[dict] = []
        walk: list[Any] = [body]
        while walk:
            cur = walk.pop()
            if isinstance(cur, dict):
                if cur.get("kind") == "CallExpr":
                    calls.append(cur)
                walk.extend(reversed(cur.get("inner") or []))
        for call in calls:
            parts = [n for n in call.get("inner") or [] if isinstance(n, dict)]
            if not parts:
                continue
            ref = _strip_expr(parts[0])
            callee = str(((ref or {}).get("referencedDecl") or {}).get("name") or "")
            args = parts[1:]
            for lo, hi in ranges(callee):
                if hi >= len(args):
                    continue
                for bound, const_at, op in ((hi, lo, ">="), (lo, hi, "<=")):
                    k, c = _param_ref(args[bound], pids), _literal(args[const_at])
                    if k is None or c is None or _number(c) is None:
                        continue
                    old = out.get(name, {}).get(k)
                    if old is not None:
                        if old[0] != op:
                            continue
                        prev, new = _number(old[1]), _number(c)
                        if prev is not None and new is not None and (new <= prev if op == ">=" else new >= prev):
                            continue
                    out.setdefault(name, {})[k] = (op, c)
    return out


def _callee_names(model_functions: dict) -> dict[str, set[str]]:
    """Per model function name, the names it calls directly (call sites and external calls)."""
    callees: dict[str, set[str]] = {}
    for key, rec in model_functions.items():
        if not isinstance(rec, dict):
            continue
        name = str(rec.get("name") or str(key).split("#")[-1])
        got = callees.setdefault(name, set())
        for c in [*(rec.get("call_sites") or []), *(rec.get("external_calls") or [])]:
            callee = c.get("callee") if isinstance(c, dict) else c
            if isinstance(callee, str):
                got.add(callee.split("#")[-1])
    return callees


def limit_parameters(model_functions: dict) -> dict[str, set[str]]:
    """
    Per function, the formal names of the limits rule B keeps at least 1: the `max_*` formals of a
    limit setter (`mpack_tree_set_limits(tree, max_message_size, max_message_nodes)`), and the formals
    of the same names of a function that calls one (`mpack_tree_init_stream`).
    """
    formals: dict[str, set[str]] = {}
    for key, rec in model_functions.items():
        if isinstance(rec, dict):
            name = str(rec.get("name") or str(key).split("#")[-1])
            formals[name] = {
                str(f.get("name")) for f in rec.get("formals") or [] if isinstance(f, dict) and f.get("name")
            }
    setters = {
        n: {f for f in fs if len(_words(f)) >= 2 and _words(f)[0] == "max"}
        for n, fs in formals.items()
        if _LIMIT_SETTER_RE.search(n)
    }
    out: dict[str, set[str]] = {n: fs for n, fs in setters.items() if fs}
    for name, cs in _callee_names(model_functions).items():
        got = set().union(*(setters[c] for c in cs if c in setters)) & formals.get(name, set())
        if got:
            out.setdefault(name, set()).update(got)
    return out


def allocating_functions(model_functions: dict) -> set[str]:
    """
    The functions of the model that reach an allocator (`ALLOCATORS`) through their call sites, by
    name: `mpack_expect_cstr_alloc` -> `mpack_expect_cstr_alloc_unchecked` ->
    `mpack_read_bytes_alloc_impl` -> `malloc`. Indirect calls are not followed.
    """
    return _reaching(model_functions, ALLOCATORS)


def _reaching(model_functions: dict, targets: frozenset[str]) -> set[str]:
    """The model's functions that reach one of `targets` through their direct call sites, by name."""
    callees = _callee_names(model_functions)
    out: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, cs in callees.items():
            if name not in out and cs & (targets | out):
                out.add(name)
                changed = True
    return out


CALLBACK_STUB_MARKER = "framac callback stub"


def callback_stub(stub: str, proto: dict[str, Any]) -> str:
    """
    A benign callback of prototype `proto`, defined at file scope on one line: it reads and writes
    nothing it is given, and returns the zero value of its type (`0`, a null pointer, a zeroed struct).
    """
    params = ", ".join(f"{t} fc_p{k}" for k, t in enumerate(proto["params"])) or "void"
    uses = " ".join(f"(void)fc_p{k};" for k in range(len(proto["params"])))
    ret = proto["ret"]
    local = _spelled(ret)  # no `const`: the zero value is written with memset
    body = uses if local == "void" else f"{uses} {local} fc_r; memset(&fc_r, 0, sizeof(fc_r)); return fc_r;"
    return f"static {ret} {stub}({params}) {{ {body.strip()} }} /* {CALLBACK_STUB_MARKER} */"


def handle_prototypes(tree: dict, complete: set[str], anon: Collection[str] = ()) -> dict[str, dict[str, Any]]:
    """
    Per declared function, where its declaration names an opaque handle type: a typedef that resolves
    to `void *`, or a pointer to a struct or union with no definition in the translation unit
    (`complete` holds the defined ones). A handle type is named as written when it is a typedef of
    `void *` (`scmp_filter_ctx`), else by the pointer type (`struct foo *`, also through a typedef).
    A plain `void *` is not a handle: nothing says what it points to. Nor is a pointer to an
    anonymous struct or union through its typedef name (`anon`, `_anon_record_nodes`): it is
    defined, though clang 19 writes the typedef's type as `struct ngx_str_t`, a tag no header defines.
    """
    typedefs: dict[str, str] = {}
    decls: list[dict] = []
    stack = [tree]
    while stack:
        node = stack.pop()
        kind = node.get("kind")
        if kind == "FunctionDecl":
            decls.append(node)
            continue
        if kind == "TypedefDecl" and isinstance(node.get("name"), str):
            typedefs.setdefault(node["name"], str((node.get("type") or {}).get("qualType") or ""))
        stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))

    def resolve(t: str) -> str:
        seen: set[str] = set()
        t = _spelled(t)
        while t in typedefs and t not in seen and t not in anon:
            seen.add(t)
            t = _spelled(typedefs[t])
        return t

    def handle(t: str) -> str | None:
        written = _spelled(t)
        full = resolve(written)
        if not full.endswith("*"):
            return None
        base = resolve(full[:-1])
        if "*" in base or "(" in base:
            return None
        if base == "void":
            return written if written in typedefs else None
        m = _RECORD_TYPE_RE.match(base)
        if m and m.group(1) != "enum" and base not in complete:
            return f"{base} *"
        return None

    def out_handle(t: str) -> str | None:
        """The handle type an `H **` parameter points to (`rec_t **` -> `struct rec *`), else None."""
        full = resolve(_spelled(t))
        return handle(full[:-1]) if full.endswith("*") else None

    out: dict[str, dict[str, Any]] = {}
    for node in decls:
        name = node.get("name")
        qual = str((node.get("type") or {}).get("qualType") or "")
        if not isinstance(name, str) or "(" not in qual:
            continue
        written = [
            str((n.get("type") or {}).get("qualType") or "")
            for n in node.get("inner") or []
            if isinstance(n, dict) and n.get("kind") == "ParmVarDecl"
        ]
        params = [handle(t) for t in written]
        outs = {i: h for i, t in enumerate(written) if (h := out_handle(t)) is not None}
        ret = handle(qual[: qual.index("(")])
        if ret or any(params) or outs:
            out.setdefault(name, {"ret": ret, "params": params, **({"outs": outs} if outs else {})})
    return out


def record_layouts(tree: dict) -> tuple[dict[str, dict], Declared]:
    """
    The layouts of every complete named struct and union of a clang JSON AST (x86_64 sizes and
    alignments), and the functions it declares. A layout: {what, size, align, pointers, fields: [{name,
    kind (int, float, enum, ptr, fnptr, array, record), off, size, ctype?, const?, what?, pointers?, bools?}],
    bools?}; `bools` marks a record or member holding a `_Bool`.
    A record with a bit-field, a packed or aligned attribute, an anonymous member or a type the
    generator does not know has no layout. The functions are a `Declared`, which also carries the
    opaque handle types of their declarations (`handle_prototypes`).

    An anonymous struct or union a typedef names (`typedef struct { size_t len; u_char *data; }
    ngx_str_t;`, `_anon_record_nodes`) is laid out under the typedef's name (`ngx_str_t`, no
    `struct ` before it: no header defines a tag for it), and a member of that type is a record of
    that name, so a named struct holding an `ngx_str_t` has a layout too.
    """
    raw, functions = _walk_records(tree)
    typedefs = _typedef_spellings(tree)
    anon_nodes = _anon_record_nodes(tree)
    for tname, (_, _, node) in anon_nodes.items():
        raw.setdefault(tname, node)
    memo: dict[str, dict | None] = {}

    def anon_name(t: str) -> str | None:
        """The typedef name of an anonymous record `t` spells (`const str_t`, `str_t [2]`), if any."""
        base = _spelled(re.sub(r"\s*\[\d*\]", "", t))
        return base if base in anon_nodes else None

    def type_info(t: str) -> dict | None:
        t = " ".join(t.split())
        if "unnamed" in t or "anonymous" in t:
            return {"kind": "enum", "size": 4, "align": 4, "pointers": False} if t.startswith("enum ") else None
        m = _ARRAY_RE.match(t)
        if m:
            elem = type_info(m.group("elem"))
            if elem is None:
                return None
            return {
                "kind": "array",
                "size": elem["size"] * int(m.group("n")),
                "align": elem["align"],
                "pointers": elem["pointers"],
                **({"bools": True} if elem.get("bools") else {}),
            }
        if "(" in t:
            if "(*)" not in t.replace(" ", ""):
                return None
            return {"kind": "fnptr", "size": POINTER_BYTES, "align": POINTER_BYTES, "pointers": True}
        if _POINTER_RE.search(t):
            base = t[: t.rfind("*")]
            return {
                "kind": "ptr",
                "size": POINTER_BYTES,
                "align": POINTER_BYTES,
                "pointers": True,
                "const": bool(re.search(r"\bconst\b", base)),
                # A byte pointer: a length beside it counts what it points to in bytes (`_len_ptr_pair`).
                **({"bytes": True} if _spelled(base) in _BYTE_POINTEES else {}),
            }
        n = " ".join(_QUALIFIERS_RE.sub(" ", t).split())
        if n in SCALAR_BYTES:
            size = SCALAR_BYTES[n]
            kind = "float" if n in ("float", "double", "long double") else "int"
            info = {"kind": kind, "size": size, "align": size, "pointers": False, "ctype": n}
            return {**info, "bools": True} if n == "_Bool" else info
        m = _RECORD_TYPE_RE.match(n)
        if n not in anon_nodes and not m:
            return None
        if m and m.group(1) == "enum":
            return {"kind": "enum", "size": 4, "align": 4, "pointers": False}
        sub = layout(n)
        if sub is None:
            return None
        return {
            "kind": "record",
            "size": sub["size"],
            "align": sub["align"],
            "pointers": sub["pointers"],
            "what": sub["what"],
            "ctype": n,
            **({"bools": True} if sub.get("bools") else {}),
        }

    def layout(key: str) -> dict | None:
        if key in memo:
            return memo[key]
        memo[key] = None  # a record that contains itself by value is not C; no layout
        node = raw.get(key)
        if node is None:
            return None
        inner = [n for n in node.get("inner") or [] if isinstance(n, dict)]
        if any(n.get("kind") in _UNSUPPORTED_ATTRS for n in inner):
            return None
        what = str(node.get("tagUsed") or "struct")
        fields: list[dict] = []
        off = size = 0
        align = 1
        for f in inner:
            if f.get("kind") != "FieldDecl":
                continue
            ftype = f.get("type") or {}
            name = f.get("name")
            if f.get("isBitfield") or not name:
                return None
            # A member written through the typedef of an anonymous record keeps that name: desugared,
            # an older clang spells it `struct (unnamed struct at ...)`, which has no layout.
            qual = str(ftype.get("qualType") or "")
            info = type_info(qual if anon_name(qual) else str(ftype.get("desugaredQualType") or qual))
            if info is None:
                return None
            if info["kind"] == "fnptr":
                # Rule G: a table's function pointers get harness functions of this prototype, spelled
                # as the header writes it (`_callback_prototype`); without it the field cannot be filled.
                proto = _callback_prototype(qual, typedefs)
                if proto is not None:
                    info["proto"] = proto
            a = int(info.pop("align"))
            align = max(align, a)
            here = 0 if what == "union" else (off + a - 1) // a * a
            fields.append({"name": name, "off": here, **info})
            off = here + info["size"]
            size = max(size, off)
        out = {
            "what": what,
            "size": (size + align - 1) // align * align,
            "align": align,
            "pointers": any(f["pointers"] for f in fields),
            "fields": fields,
        }
        if any(f.get("bools") for f in fields):
            out["bools"] = True  # a _Bool takes only 0 and 1: such a record is filled field by field
        memo[key] = out
        return out

    pf_memo: dict[str, bool] = {}

    def is_pf_type(t: str) -> bool:
        t = " ".join(t.split())
        if not t or _POINTER_RE.search(t):
            return False
        m = _ARRAY_RE.match(t)
        if m:
            return is_pf_type(m.group("elem"))
        if "unnamed" in t or "anonymous" in t:
            return t.startswith("enum ") and "(*" not in t
        if "(" in t:
            return False
        n = " ".join(_QUALIFIERS_RE.sub(" ", t).split())
        seen_td: set[str] = set()
        while n in typedefs and n not in seen_td:
            seen_td.add(n)
            n = _spelled(typedefs[n])
            if not n or _POINTER_RE.search(n):
                return False
            m = _ARRAY_RE.match(n)
            if m:
                return is_pf_type(m.group("elem"))
            if "unnamed" in n or "anonymous" in n:
                return n.startswith("enum ") and "(*" not in n
            if "(" in n:
                return False
        if n in SCALAR_BYTES:
            return True
        rm = _RECORD_TYPE_RE.match(n)
        if rm and rm.group(1) == "enum":
            return True
        if n in raw:
            return is_pf_record(n)
        return False

    def is_pf_record(key: str) -> bool:
        if key in pf_memo:
            return pf_memo[key]
        pf_memo[key] = False
        node = raw.get(key)
        if node is None:
            return False
        fields = [n for n in (node.get("inner") or []) if isinstance(n, dict) and n.get("kind") == "FieldDecl"]
        if not fields:
            return False
        for f in fields:
            ftype = f.get("type") or {}
            qual = str(ftype.get("qualType") or "")
            t = qual if anon_name(qual) else str(ftype.get("desugaredQualType") or qual)
            if not is_pf_type(t):
                return False
        pf_memo[key] = True
        return True

    layouts = {k: lay for k in raw if (lay := layout(k)) is not None}
    pf_records = {k for k in raw if is_pf_record(k)}
    return layouts, Declared(
        functions,
        handle_prototypes(tree, set(raw), set(anon_nodes)),
        callback_prototypes(tree),
        enum_pointer_spellings(tree),
        qualified_pointer_spellings(tree),
        param_enums(tree),
        const_returns(tree),
        bound_forwards(tree),
        {name: {"what": what, "id": rid} for name, (what, rid, _) in anon_nodes.items()},
        anon_record_pointers(tree, set(anon_nodes)),
        null_default_records(tree),
        pf_records,
    )


def _typedef_spellings(tree: dict) -> dict[str, str]:
    """Every typedef name of a clang JSON AST -> its type as written (function bodies left out)."""
    typedefs: dict[str, str] = {}
    stack = [tree]
    while stack:
        node = stack.pop()
        kind = node.get("kind")
        if kind == "FunctionDecl":
            continue
        if kind == "TypedefDecl" and isinstance(node.get("name"), str):
            typedefs.setdefault(node["name"], str((node.get("type") or {}).get("qualType") or ""))
        stack.extend(n for n in reversed(node.get("inner") or []) if isinstance(n, dict))
    return typedefs


def _comment_text(node: dict) -> str:
    """The text of a doc-comment node (clang's `FullComment` and its parts), joined."""
    parts: list[str] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if n.get("kind") == "TextComment" and isinstance(n.get("text"), str):
            parts.append(n["text"])
        stack.extend(c for c in reversed(n.get("inner") or []) if isinstance(c, dict))
    return " ".join(" ".join(parts).split())


def _says_null_default(text: str) -> bool:
    """
    Whether a doc comment says NULL selects a default (`May be NULL to specify the default allocator`).
    One that forbids NULL anywhere (`Must not be NULL; use the default ops`) never does.
    """
    if _NOT_NULL_RE.search(text):
        return False
    return bool(_NULL_WORD_RE.search(text) and _DEFAULT_WORD_RE.search(text))


def _pointed_record(decl: dict, typedefs: dict[str, str]) -> str | None:
    """
    The struct or union a declaration of type `T *` points to (`struct ProtobufCAllocator`), or None.
    clang writes `ProtobufCAllocator *` without a desugared form: the typedef name is followed.
    """
    t = str((decl.get("type") or {}).get("desugaredQualType") or (decl.get("type") or {}).get("qualType") or "")
    t = _TRAILING_QUALIFIER_RE.sub("", " ".join(t.split()))
    if not t.endswith("*") or t.count("*") != 1 or "(" in t:
        return None
    base = _spelled(t[:-1])
    seen: set[str] = set()
    while base in typedefs and base not in seen:
        seen.add(base)
        base = _spelled(typedefs[base])
    return base if _RECORD_TYPE_RE.match(base) and not base.startswith("enum ") else None


def null_default_records(tree: dict) -> set[str]:
    """
    Rule G: the struct types a doc comment of the headers documents as NULL for a default, from clang's
    JSON AST (doc comments, `/** ... */`, come as `FullComment` nodes): a function's `\\param` text,
    or a field's comment, that says NULL and a default (`_says_null_default`) on a declaration of type
    `T *`. protobuf-c.h: "`ProtobufCAllocator` to use for memory allocation. May be NULL to specify
    the default allocator." on `protobuf_c_message_unpack`'s `allocator`, and "Allocator to use. May
    be NULL to indicate the system allocator." on `ProtobufCBufferSimple`'s. The type is what the
    rule applies to, for every function that takes it: the generated `X__unpack` wrappers have no
    comment of their own.
    """
    out: set[str] = set()
    typedefs = _typedef_spellings(tree)
    stack = [tree]
    while stack:
        node = stack.pop()
        kind = node.get("kind")
        inner = [n for n in node.get("inner") or [] if isinstance(n, dict)]
        comments = [n for n in inner if n.get("kind") == "FullComment"]
        if kind == "FunctionDecl":
            parms = {n.get("name"): n for n in inner if n.get("kind") == "ParmVarDecl"}
            for full in comments:
                for pc in full.get("inner") or []:
                    if not isinstance(pc, dict) or pc.get("kind") != "ParamCommandComment":
                        continue
                    parm = parms.get(pc.get("param"))
                    t = _pointed_record(parm, typedefs) if parm is not None else None
                    if t is not None and _says_null_default(_comment_text(pc)):
                        out.add(t)
            continue  # a body holds no declaration the API documents
        if kind == "FieldDecl" and comments:
            t = _pointed_record(node, typedefs)
            if t is not None and any(_says_null_default(_comment_text(c)) for c in comments):
                out.add(t)
        stack.extend(reversed(inner))
    return out


def probe_layouts(
    harness_c: Path, cppflags: str, clang: str | None = None, runner: Callable[..., Any] = subprocess.run
) -> tuple[dict[str, dict], set[str]] | None:
    """
    The struct layouts and the functions declared where the harness is compiled: clang's JSON AST of a
    copy of the harness without its cases (they hold no definitions), with the harness's flags. None
    when clang is missing or its AST cannot be read.
    """
    import shlex

    from target_env import with_include_flags

    exe = clang or shutil.which("clang")
    if not exe:
        return None
    lines = harness_c.read_text(encoding="utf-8", errors="replace").splitlines()
    probe = harness_c.with_name(f".{harness_c.stem}.layout_probe.c")
    probe.write_text("\n".join("" if _CASE_LINE_RE.match(t) else t for t in lines) + "\n", encoding="utf-8")
    argv = [
        exe,
        "-fsyntax-only",
        "-w",
        "-x",
        "c",
        *shlex.split(with_include_flags(cppflags)),
        "-Xclang",
        "-ast-dump=json",
        str(probe),
    ]
    try:
        proc = runner(argv, capture_output=True, text=True, timeout=300, check=False)
        tree = json.loads(proc.stdout or "")
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    finally:
        probe.unlink(missing_ok=True)
    return record_layouts(tree) if isinstance(tree, dict) else None


# --- the compile probe ------------------------------------------------------------------------------

_ERR_LINE_RE = re.compile(
    r"^(?P<file>(?:[A-Za-z]:)?[^:\n]+):(?P<line>\d+):(?P<col>\d+):\s+(?:fatal\s+)?error:\s*(?P<msg>[^\n]*)$",
    re.MULTILINE,
)


def _no_error_limit(exe: str) -> str:
    """The option that lifts the compiler's error cap (clang stops at 20 errors, gcc has no cap by default)."""
    return "-ferror-limit=0" if "clang" in Path(exe).name else "-fmax-errors=0"


_ERROR_OPTION_RE = re.compile(r"-Werror(?:=|$)|-pedantic-errors$")
# The tag clang puts on the warning `_strict_case_flags` makes an error.
_PROMOTED_WARNING = "-Werror,-Wincompatible-pointer-types-discards-qualifiers]"


def _strict_case_flags(exe: str) -> list[str]:
    """
    The warning options of the compile probe, after the target's flags. Warnings are not errors (a
    `-Werror`, `-Werror=` or `-pedantic-errors` in the target's flags is dropped, `-w` used to hide
    them), except a pointer passed where its nested qualifiers
    are dropped (`char **` for `const char **`): gcc 14 refuses that call even under `-w`
    (`-Wincompatible-pointer-types` is an error there), while clang only warns, so a case the clang
    probe accepted broke a gcc build of the harness. clang's `-w` would silence the `-Werror=`
    option, and `-Wno-everything` the errors clang raises by default (`-Wint-conversion`): warnings
    stay on and only `error:` lines are read. gcc refuses it on its own.
    """
    if "clang" not in Path(exe).name:
        return ["-w"]
    return ["-Wno-error", "-Werror=incompatible-pointer-types-discards-qualifiers"]


def probe_cases(harness_c: Path, cppflags: str, clang: str | None = None) -> tuple[dict[int, str], list[str]] | None:
    """
    Compile the harness once: (the dispatch cases the compiler refuses, each with the compiler's first
    error on its line (`file:line: error: message`, trimmed); the errors on no case line), or None when
    no compiler ran. Each case is one line of the harness, so an error maps to its case by line. A case
    the target's headers cannot spell (an incomplete struct, a function the headers do not declare) is
    dropped instead of failing the whole harness. The error cap is lifted: every failing case is found
    in one compile. The compiler gets the run snapshot's include options (scripts/target_env.py), so
    the headers the build generated are found as in every other compile.
    """
    import shlex

    from target_env import with_include_flags

    exe = clang or shutil.which("clang") or shutil.which("gcc")
    if not exe:
        return None
    argv = [
        exe,
        "-fsyntax-only",
        _no_error_limit(exe),
        "-x",
        "c",
        *(t for t in shlex.split(with_include_flags(cppflags)) if not _ERROR_OPTION_RE.match(t)),
        *_strict_case_flags(exe),
        str(harness_c),
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode == 0:
        return {}, []
    lines = harness_c.read_text(encoding="utf-8", errors="replace").splitlines()
    case_of_line = {}
    for no, text in enumerate(lines, start=1):
        m = _CASE_LINE_RE.match(text)
        if m:
            case_of_line[no] = int(m.group(1))
    output = (proc.stdout or "") + (proc.stderr or "")
    bad: dict[int, str] = {}
    other: list[str] = []
    promoted = False
    for m in _ERR_LINE_RE.finditer(output):
        line = int(m.group("line"))
        if Path(m.group("file")).name == harness_c.name and line in case_of_line:
            diag = f"{harness_c.name}:{line}: error: {m.group('msg').strip()}"
            if len(diag) > MAX_DIAGNOSTIC_CHARS:
                diag = diag[: MAX_DIAGNOSTIC_CHARS - 3] + "..."
            bad.setdefault(case_of_line[line], diag)
        elif _PROMOTED_WARNING in m.group("msg"):
            # Only the cases are held to it: the target's own code (an inline function of its
            # headers, an included source) compiled under `-w` before and is not the harness's.
            promoted = True
        else:
            other.append(m.group(0).strip())
    if not bad and not other and promoted:
        unlocated = [t for t in output.splitlines() if "error:" in t and not _ERR_LINE_RE.match(t)]
        if not unlocated:
            return {}, []
        other.append(unlocated[0].strip())
    if not bad and not other:
        # A failed compile with no located error (a fatal one, a driver error): not a case's fault.
        other.append(output.strip().splitlines()[0] if output.strip() else f"exit code {proc.returncode}")
    return bad, other


def _stub_errors_only(harness_c: Path, errors: list[str]) -> bool:
    """Whether every compile error outside the cases (`probe_cases`) is on a callback stub's line."""
    try:
        lines = harness_c.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    found = False
    for err in errors:
        m = _ERR_LINE_RE.match(err)
        if not m or Path(m.group("file")).name != harness_c.name:
            return False
        no = int(m.group("line"))
        if not (0 < no <= len(lines) and CALLBACK_STUB_MARKER in lines[no - 1]):
            return False
        found = True
    return found


def case_diagnostics(harness_c: Path, cppflags: str, clang: str | None = None) -> dict[int, str] | None:
    """The dispatch cases the compiler refuses with their first error (`probe_cases`), or None when none
    is refused or no compiler ran."""
    probed = probe_cases(harness_c, cppflags, clang)
    return probed[0] or None if probed is not None else None


def failing_cases(harness_c: Path, cppflags: str, clang: str | None = None) -> set[int] | None:
    """Selectors of the dispatch cases the compiler refuses (`case_diagnostics` without the messages)."""
    diags = case_diagnostics(harness_c, cppflags, clang)
    return None if diags is None else set(diags)


def previous_custom_cases(sidecar: dict[str, Any]) -> list[str]:
    """The hand-written cases of an API harness's sidecar: the `dispatch_cases` its `custom` layouts select."""
    cases = sidecar.get("dispatch_cases")
    layouts = sidecar.get("api_cases")
    if not isinstance(cases, list) or not isinstance(layouts, list):
        return []
    out: list[str] = []
    for lay in layouts:
        sel = lay.get("selector") if isinstance(lay, dict) and lay.get("kind") == CUSTOM_KIND else None
        if isinstance(sel, int) and 0 <= sel < len(cases) and isinstance(cases[sel], str) and cases[sel].strip():
            out.append(cases[sel].strip())
    return out


def generate(
    module: str,
    header: str | None,
    max_input_size: int,
    cppflags: str,
    out_dir: Path,
    unit: str | None = None,
    ldflags: str = "",
    extra_includes: list[str] | None = None,
    reachability: str | None = None,
    auto_prelude: bool = True,
    probe: bool = True,
    dag_path: Path | None = None,
    model_path: Path = MODEL_JSON,
    traces_path: Path = TRACES_JSONL,
    scope_files: list[str] | None = None,
    struct_layouts: dict[str, dict] | None = None,
    visible: set[str] | None = None,
    dispatch_cases: list[str] | None = None,
    variadic: dict[str, list[dict]] | None = None,
    *,
    global_variables: dict[str, dict] | None = None,
    trust: dict[str, Any] | None = None,
    trust_schema: bool | None = None,
) -> dict[str, Any]:
    """
    Write harness_<module>.{c,json} for the module's whole API; the generate_harness result plus counts.
    `scope_files` (`--scope-file`) default to the previous sidecar's, and are kept in the new one.
    `struct_layouts`/`visible` replace the layout probe (`probe_layouts`), which runs with `probe`.

    `variadic` replaces the call sites of the variadic API (function -> cases). By default they are
    read from workspace/reports/variadic_calls.json next to the DAG, harvested first when that report
    is missing or was made from another model (`variadic_calls.ensure`). A call site whose case was
    left out (over a cap, or refused by the compiler) is listed in the sidecar's
    `api_variadic_dropped`; the function is in `api_skipped` only when none of its cases is left.

    `dispatch_cases` (`--dispatch-case`) are hand-written cases, for a function the generator cannot
    call: appended after the generated ones in the same switch (the next selectors), each with an
    `api_cases` layout of kind `custom` (no calls, no slots: the seed writers make nothing for it).
    None keeps the previous sidecar's custom cases; a list replaces them (an empty one drops them).
    One that does not compile fails the generation: it is never dropped silently.

    Without `header`, the headers come from the build capture (`header_attempts`): all chosen ones,
    then the public ones alone, then none (the harness as without a capture). An attempt whose
    harness does not compile outside its cases is abandoned for the next and recorded in the
    sidecar's `api_headers.fallbacks`; the automatic choice never fails the module. A given
    `header` fails it, as before.
    """
    from generate_harness import (
        _norm_scope_files,
        generate_module_harness,
        harness_files_kept_on_failure,
        previous_scope_files,
        write_sidecar,
    )

    dag_file = dag_path or (out_dir.parent / "reports" / "callgraph_dag.json")
    dag = load_json_optional(dag_file, None)
    if not isinstance(dag, dict):
        raise ApiHarnessError(f"--api needs the DAG ({dag_file})")
    model = load_json_optional(model_path, None)
    if not isinstance(model, dict) or model.get("status") != "ok":
        raise ApiHarnessError(f"--api needs the Phase 0 model ({model_path})")
    previous = load_json_optional(out_dir / f"harness_{module}.json", {})
    scope = (
        _norm_scope_files(scope_files)
        if scope_files is not None
        else previous_scope_files(previous if isinstance(previous, dict) else {})
    )
    custom = (
        previous_custom_cases(previous if isinstance(previous, dict) else {})
        if dispatch_cases is None
        else [c.strip() for c in dispatch_cases if isinstance(c, str) and c.strip()]
    )
    for n, text in enumerate(custom, start=1):
        if "\n" in text or "\r" in text:
            # The compile probe and the layout probe map a case to its one line of the harness.
            raise ApiHarnessError(f"module {module!r}: --dispatch-case {n} of {len(custom)} must be one line of C")
    if len(custom) >= MAX_CASES:
        raise ApiHarnessError(f"module {module!r}: {len(custom)} --dispatch-case cases, at most {MAX_CASES - 1}")

    def with_custom(planned: dict[str, Any]) -> tuple[list[str], list[dict], dict[str, str]]:
        """The planned cases followed by the hand-written ones, their layouts, and the skipped functions."""
        lays = [*planned["layouts"], *({"kind": CUSTOM_KIND, "calls": [], "slots": [], "rest": None} for _ in custom)]
        for sel, lay in enumerate(lays):
            lay["selector"] = sel
        return [*planned["cases"], *custom], lays, dict(planned["skipped"])

    warnings: list[str] = []
    capture_path = dag_file.parent / "build_capture.json"
    attempts = header_attempts(dag, module, unit, capture_path, scope, header, extra_includes)
    traces = load_traces(traces_path)
    if variadic is None:
        from variadic_calls import ensure

        reports = dag_file.parent
        variadic = ensure(reports / "variadic_calls.json", model_path, reports / "build_capture.json")
    effective_trust_schema = api_trust_schema_enabled() if trust_schema is None else bool(trust_schema)
    p = plan(
        dag,
        model,
        module,
        unit,
        max_input_size,
        traces,
        scope,
        struct_layouts,
        visible,
        reserve=len(custom),
        variadic=variadic,
        global_variables=global_variables,
        trust=trust,
        trust_schema=effective_trust_schema,
    )
    if not p["cases"]:
        raise ApiHarnessError(f"module {module!r}: no API entry point the generator can call: {p['skipped']}")
    functions = dag.get("functions") or {}
    dag_mod = (dag.get("modules") or {}).get(module) or {}
    req_sources = dag_mod.get("required_sources") or []
    # A `static` function defined in a public header (`header_api`) is compiled from the header the
    # harness includes, and fuzz_build names it for E-ACSL from the sidecar's cases
    # (`_harness_header_entries`): its file is no source. An exported function a header defines (mpack's
    # MPACK_INLINE) keeps its header here, where E-ACSL's function discovery and the module scope read
    # it; the clang builds leave it off their command line (framac_common.compile_inputs).
    sources = sorted(
        {
            str((functions.get(k) or {}).get("file"))
            for k in p["entries"]
            if (functions.get(k) or {}).get("file")
            and not ((functions.get(k) or {}).get("header") and (functions.get(k) or {}).get("is_static"))
        }
        | {str(s) for s in req_sources if s}
        | {str(s) for s in (p.get("schema_sources") or []) if s}
    )
    first = str((functions.get(p["entries"][0]) or {}).get("name") or p["entries"][0].split("#")[-1])
    planned = copy.deepcopy(p)  # header-free: every attempt at the headers starts from it
    exported_model_recs: dict[str, dict[str, Any]] = {}
    for _mk, _mrec in (model.get("functions") or {}).items():
        if not isinstance(_mrec, dict) or _mrec.get("static"):
            continue
        _mname = str(_mrec.get("name") or _mk.split("#")[-1])
        if _mname and _mname not in exported_model_recs:
            exported_model_recs[_mname] = _mrec

    def attempt(header: str | None, extra_includes: list[str] | None, more: bool) -> tuple[Any, ...]:
        """
        One harness with these headers: (p, cases, layouts, skipped, dropped, result, refused, synth_clean).
        With `more` (an automatic header choice that has a next step), a harness that does not compile
        outside its cases, or whose cases none compiles, raises `_HeadersBroken` instead of failing.
        """
        p = copy.deepcopy(planned)
        cases, layouts, skipped = with_custom(p)
        dropped: list[dict] = list(p["variadic_dropped"])
        # The sequence and lifecycle cases the compile probe refused: a stateful case's entry point keeps
        # its single case, and a recorded chain names none, so `api_skipped` would never show them.
        refused: list[dict[str, Any]] = []
        result: dict[str, Any] = {}
        # Synthesized `extern` prototypes for exported functions declared in no included header.
        synth_protos: dict[str, str] = {}
        synth_clean: dict[str, str] = {}
        synth_tried: set[str] = set()
        # Struct layouts come from the first harness written (its headers and prelude): the cases are
        # planned again with them before the compile probe. Each later round drops at least one case, so
        # the loop ends; the harness is written again after every drop, so the one left on disk is the one
        # whose cases the sidecar lists. Failed generation leaves the previous harness files as they were
        # (generate_harness.harness_files_kept_on_failure).
        need_layouts = probe and struct_layouts is None
        layouts_probed: tuple[dict[str, dict], set[str]] | None = (
            (struct_layouts, visible) if struct_layouts is not None and visible is not None else None
        )
        while True:
            # While the probe drops cases, a compile error is the probe's to judge; without the
            # probe, generate_module_harness fails on it itself.
            cur_sources = sorted(set(sources) | {str(s) for s in (p.get("schema_sources") or []) if s})
            file_scope_decls = [
                *synth_protos_used(cases, synth_protos),
                *schema_externs_used(cases, p.get("schema_externs") or {}),
                *stubs_used(cases, p.get("stubs") or {}),
            ]
            result = generate_module_harness(
                module_name=module,
                sources=cur_sources,
                header_include=header,
                entry_fn=first,
                max_input_size=max_input_size,
                cppflags=cppflags,
                out_dir=out_dir,
                reachability=reachability,
                entry_style="dispatch",
                dispatch_cases=cases,
                unit=unit,
                ldflags=ldflags,
                extra_includes=extra_includes,
                auto_prelude=auto_prelude,
                scope_files=scope,
                fail_on_compile_error=not probe,
                file_scope=file_scope_decls,
            )
            if not probe:
                break
            if need_layouts:
                need_layouts = False
                layouts_probed = probe_layouts(Path(result["harness_file"]), result["cppflags"])
                if layouts_probed is not None:
                    p = plan(
                        dag,
                        model,
                        module,
                        unit,
                        max_input_size,
                        traces,
                        scope,
                        *layouts_probed,
                        reserve=len(custom),
                        variadic=variadic,
                        global_variables=global_variables,
                        trust=trust,
                        trust_schema=effective_trust_schema,
                    )
                    if p["cases"]:
                        cases, layouts, skipped = with_custom(p)
                        dropped = list(p["variadic_dropped"])
                        continue
            probed = probe_cases(Path(result["harness_file"]), result["cppflags"])
            if probed is None:
                break  # no compiler: the cases stay unchecked
            bad, other = probed
            if other and synth_protos:
                bad_protos = _synth_proto_errors(Path(result["harness_file"]), other)
                if bad_protos:
                    for fn in bad_protos:
                        synth_protos.pop(fn, None)
                        synth_clean.pop(fn, None)
                    continue
            if other and layouts_probed is not None and _stub_errors_only(Path(result["harness_file"]), other):
                # A callback stub the headers cannot spell after all: plan again with NULL callbacks
                # (each case's notes say so), never fail the harness for a stub.
                p = plan(
                    dag,
                    model,
                    module,
                    unit,
                    max_input_size,
                    traces,
                    scope,
                    *layouts_probed,
                    reserve=len(custom),
                    variadic=variadic,
                    callback_stubs=False,
                    global_variables=global_variables,
                    trust=trust,
                    trust_schema=effective_trust_schema,
                )
                layouts_probed = None
                if p["cases"]:
                    cases, layouts, skipped = with_custom(p)
                    dropped = list(p["variadic_dropped"])
                    continue
            if other and more:
                raise _HeadersBroken(other[:3])
            if other:
                raise ApiHarnessError(
                    f"module {module!r}: the harness does not compile outside its cases: {'; '.join(other[:3])}"
                )
            if not bad:
                break
            added_proto = False
            cur_visible = layouts_probed[1] if layouts_probed is not None else visible
            cur_structs = layouts_probed[0] if layouts_probed is not None else (struct_layouts or {})
            cur_anon_tags: dict[str, str] | None = None
            for i, diag in sorted(bad.items()):
                if layouts[i]["kind"] == CUSTOM_KIND:
                    continue
                um = _UNDECLARED_FN_RE.search(diag)
                if not um:
                    continue
                ufn = um.group(1)
                if ufn in synth_tried or ufn not in exported_model_recs:
                    continue
                synth_tried.add(ufn)
                if cur_anon_tags is None:
                    cur_anon_tags = anon_record_tags(model.get("functions") or {}, cur_visible)
                built = synthesize_extern_prototype(
                    ufn, exported_model_recs[ufn], cur_anon_tags, known_structs=cur_structs
                )
                if built is not None:
                    synth_protos[ufn], synth_clean[ufn] = built
                    added_proto = True
            if added_proto:
                continue
            keep = [i for i in range(len(cases)) if i not in bad]
            for i, diag in sorted(bad.items()):
                if layouts[i]["kind"] == CUSTOM_KIND:
                    n = sum(1 for lay in layouts[: i + 1] if lay["kind"] == CUSTOM_KIND)
                    raise ApiHarnessError(
                        f"module {module!r}: --dispatch-case {n} of {len(custom)} does not compile "
                        f"with the target's headers: {diag}"
                    )
                if layouts[i].get("entry"):
                    skipped[layouts[i]["entry"]] = f"the case does not compile with the target's headers: {diag}"
                if layouts[i]["kind"] == VARIADIC_KIND:
                    why = f"the case does not compile with the target's headers: {diag}"
                    dropped.append(_dropped_variadic(layouts[i], why))
                if layouts[i]["kind"] in ("sequence", "lifecycle"):
                    gone = {"kind": layouts[i]["kind"], "calls": list(layouts[i].get("calls") or [])}
                    if layouts[i].get("entry"):
                        gone["entry"] = layouts[i]["entry"]
                    refused.append({**gone, "why": f"the case does not compile with the target's headers: {diag}"})
                    print(
                        f"api_harness: warning: dropped a {gone['kind']} case ({' -> '.join(gone['calls'][:4])}"
                        f"{' ...' if len(gone['calls']) > 4 else ''}): {diag}",
                        file=sys.stderr,
                    )
            if not keep and more:
                raise _HeadersBroken([bad[i] for i in sorted(bad)][:3])
            if not keep:
                raise ApiHarnessError(f"module {module!r}: no API case compiles: {sorted(skipped.items())}")
            cases = [cases[i] for i in keep]
            layouts = [layouts[i] for i in keep]
            for sel, lay in enumerate(layouts):
                lay["selector"] = sel
        used_synth = {
            fn: synth_clean[fn]
            for fn in sorted(synth_clean)
            if any(re.search(rf"\b{re.escape(fn)}\s*\(", c) for c in cases)
        }
        return p, cases, layouts, skipped, dropped, result, refused, used_synth

    # An automatic header choice degrades in steps and never fails the module for its own headers:
    # each abandoned attempt leaves the harness files as they were before it, and is recorded.
    fallbacks: list[dict[str, list[str]]] = []
    synthesized_protos: dict[str, str] = {}
    with harness_files_kept_on_failure(out_dir, module):
        for n, (hdr, extra, _, included) in enumerate(attempts):
            if hdr is None:
                # c-ares run-1: 18 of 19 cases dropped as `call to undeclared function`. Not a failure: a
                # header given through --extra-include, or a module of one function, still works.
                warnings.append(no_header_warning(capture_path))
                print(f"api_harness: warning: {warnings[-1]}", file=sys.stderr)
            try:
                with harness_files_kept_on_failure(out_dir, module):
                    p, cases, layouts, skipped, dropped, result, refused, synthesized_protos = attempt(
                        hdr, extra, n + 1 < len(attempts)
                    )
                api_headers = attempts[n][2]
                break
            except _HeadersBroken as exc:
                left = attempts[n + 1][3]
                fallbacks.append({"dropped": [h for h in included if h not in left], "errors": exc.errors})
                print(
                    f"api_harness: warning: the build capture's headers do not compile in the harness, "
                    f"dropping {', '.join(fallbacks[-1]['dropped'])}: {'; '.join(exc.errors)}",
                    file=sys.stderr,
                )
        if fallbacks:
            api_headers = {**api_headers, "fallbacks": fallbacks}
        if synthesized_protos:
            api_headers = {**api_headers, "synthesized_prototypes": synthesized_protos}
        sidecar_path = Path(result["harness_meta"])
        sidecar = load_json_optional(sidecar_path, {}) or {}
        sidecar["api_harness"] = True
        sidecar["dispatch_case_count"] = len(layouts)
        # A variadic function has one case per call site: it is skipped only when none is left.
        skipped = still_skipped(layouts, skipped)
        auto_exempt = still_skipped(layouts, dict(p.get("auto_exempt") or {}))
        sidecar["api_cases"] = layouts
        sidecar["api_skipped"] = skipped
        sidecar.pop("api_auto_exempt", None)
        if effective_trust_schema and auto_exempt:
            sidecar["api_auto_exempt"] = dict(sorted(auto_exempt.items()))
        sidecar["api_helpers"] = case_helpers(cases, layouts, p.get("helper_pool") or [])
        sidecar["api_headers"] = api_headers
        sidecar.pop("api_variadic_dropped", None)
        if dropped:
            sidecar["api_variadic_dropped"] = dropped
        write_sidecar(sidecar_path, sidecar)
    result.update(
        api_cases=len(layouts),
        api_entries=len({lay["entry"] for lay in layouts if lay.get("entry")}),
        api_variadic=sum(1 for lay in layouts if lay["kind"] == VARIADIC_KIND),
        api_variadic_dropped=dropped,
        api_sequences=sum(1 for lay in layouts if lay["kind"] == "sequence"),
        api_lifecycles=sum(1 for lay in layouts if lay["kind"] == "lifecycle"),
        api_custom=sum(1 for lay in layouts if lay["kind"] == CUSTOM_KIND),
        api_stateful=sum(1 for lay in layouts if lay.get("state")),
        api_dropped_cases=refused,
        api_skipped=skipped,
    )
    if effective_trust_schema and auto_exempt:
        result["api_auto_exempt"] = dict(sorted(auto_exempt.items()))
    if warnings:
        result["api_warnings"] = warnings
    return result


_ALIAS_DEFINE_RE = re.compile(r"(?m)^[ \t]*#[ \t]*define[ \t]+([A-Za-z_]\w*)[ \t]+([A-Za-z_]\w*)[ \t]*$")


def header_declares(path: Path, names: set[str]) -> set[str]:
    """
    The names of `names` the header at `path` declares, read from its text (no preprocessor). A name
    reached through a renaming macro counts: nettle's `aes-internal.h` writes `#define _aes_set_key
    _nettle_aes_set_key` and declares `void _aes_set_key(...)`, the model's `_nettle_aes_set_key`.
    An unreadable header declares nothing.
    """
    from build_capture import declared_names

    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return set()
    alias = {a: n for a, n in _ALIAS_DEFINE_RE.findall(text) if n in names}
    found = declared_names(text, names | set(alias))
    return {alias.get(n, n) for n in found}


def capture_headers(
    dag: dict,
    module: str,
    unit: str | None,
    capture_path: Path,
    scope_files: list[str] | None = None,
    public_only: bool = False,
) -> dict[str, Any]:
    """
    The headers an `--api` harness without `--header` includes, from the build capture (step O4 of
    docs/plans/open-topics-remediation-plan.md): {source, why, unit, public, internal, dropped,
    header, extra_includes}, the sidecar's `api_headers` plus the two include slots.

    - `public`: the capture's public headers (`public_headers.files`, an installed one mapped back
      to its tree header, `phase0_model.public_header_files`) that the unit's own compiles include
      (`compiles[].headers`);
    - `internal`: each other header those compiles include that declares an entry point of the
      module's scope no public header declares, with the names it declares;
    - `dropped`: a header whose file name another chosen header already has (the harness includes
      by file name, with `-I` on its directory, so the second would be the first again).

    `header` is the chosen header that declares the module's first entry point, else the first
    public one; the others are `extra_includes`, public before internal. The paths are rooted at
    the DAG's `target_dir` as its `cppflags` are (`workspace/work/<tree path>`). `source` is
    `capture` when a header was chosen, else `not_found`, with `why`: no capture, no record of the
    module's link unit in it, or none of its headers is public or declares an entry point.
    `scope_files` give a freely named sub-module its entry points, as in `plan`. `public_only`
    leaves the internal headers out (`generate`'s second attempt, when one of them breaks the harness).
    """
    from module_map import ModuleMap
    from phase0_model import public_header_files

    def not_found(why: str, **extra: Any) -> dict[str, Any]:
        return {"source": "not_found", "why": why, **extra, "header": None, "extra_includes": []}

    cap = load_json_optional(capture_path, None)
    if not isinstance(cap, dict):
        return not_found(f"no build capture ({capture_path.as_posix()})")
    sidecar = {**({"unit": unit} if unit else {}), **({"scope_files": scope_files} if scope_files else {})}
    mm = ModuleMap(dag, {module: sidecar} if sidecar else {})
    rec = mm.unit_record(module)
    cap_unit = rec.get("unit")
    cap_rec = (cap.get("units") or {}).get(cap_unit) if isinstance(cap_unit, str) else None
    compiles = [c for c in cap.get("compiles") or [] if isinstance(c, dict)]
    if not isinstance(cap_rec, dict) or not compiles:
        return not_found(f"the build capture has no compiles of the module's link unit ({cap_unit or 'unknown'})")
    objects = {str(o) for o in cap_rec.get("objects") or []}
    files = {str(f) for f in rec.get("files") or []}
    own = [c for c in compiles if str(c.get("object")) in objects] or [
        c for c in compiles if str(c.get("source")) in files
    ]
    unit_headers = sorted(
        {str(h) for c in own for h in c.get("headers") or [] if str(h).endswith(".h") and not str(h).startswith("/")}
    )
    if not unit_headers:
        return not_found(f"the compiles of link unit {cap_unit} include no project header", unit=cap_unit)
    every_header = {str(h) for c in compiles for h in c.get("headers") or [] if str(h).endswith(".h")}
    public = sorted(public_header_files(cap.get("public_headers"), every_header) & set(unit_headers))

    target = str(dag.get("target_dir") or "").replace("\\", "/")
    root = target[len("/framac-run/") :] if target.startswith("/framac-run/") else target

    def rooted(rel: str) -> str:
        return f"{root.rstrip('/')}/{rel}" if root else rel

    functions = dag.get("functions") or {}
    entries = mm.scope_entry_points(module) or list(
        ((dag.get("modules") or {}).get(module) or {}).get("candidate_entry_points") or []
    )
    names = [str((functions.get(k) or {}).get("name") or str(k).split("#")[-1]) for k in entries]
    wanted = {n for n in names if n != "main"}
    declares = {h: header_declares(Path(rooted(h)), wanted) for h in unit_headers}
    by_public = {n for h in public for n in declares[h]}
    internal = {h: sorted(declares[h] - by_public) for h in unit_headers if h not in public and declares[h] - by_public}
    if public_only:
        internal = {}
    chosen: list[str] = []
    dropped: list[dict[str, str]] = []
    for h in [*public, *internal]:
        same = next((c for c in chosen if PurePosixPath(c).name == PurePosixPath(h).name), None)
        if same is not None:
            dropped.append({"header": h, "why": f"same file name as {same}, which the harness includes"})
        else:
            chosen.append(h)
    kept = [{"header": h, "declares": d} for h, d in internal.items() if h in chosen]
    picked: dict[str, Any] = {
        "unit": cap_unit,
        "public": public,
        "internal": kept,
        **({"dropped": dropped} if dropped else {}),
    }
    if not chosen:
        return not_found(
            f"none of the {len(unit_headers)} headers link unit {cap_unit} includes is a public header "
            "or declares an entry point of the module",
            **picked,
        )
    first = next((n for n in names if n != "main"), None)
    main = next((h for h in chosen if first is not None and first in declares[h]), chosen[0])
    why = (
        f"--header not given: {len(public)} public header(s) of the build capture that link unit {cap_unit} "
        f"includes, and {len(kept)} internal header(s) declaring entry points the public ones "
        "do not declare"
    )
    if public_only:
        why = (
            f"--header not given: the {len(public)} public header(s) only of the build capture that link unit "
            f"{cap_unit} includes; the internal headers did not compile in the harness (`fallbacks`)"
        )
    return {
        "source": "capture",
        "why": why,
        **picked,
        "header": rooted(main),
        "extra_includes": [rooted(h) for h in chosen if h != main],
    }


class _HeadersBroken(ApiHarnessError):
    """An automatic header choice does not compile in the harness: `generate` tries the next one."""

    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = list(errors)


HeaderAttempt = tuple[str | None, list[str], dict[str, Any], list[str]]


def header_attempts(
    dag: dict,
    module: str,
    unit: str | None,
    capture_path: Path,
    scope_files: list[str] | None,
    header: str | None,
    extra_includes: list[str] | None,
) -> list[HeaderAttempt]:
    """
    The header sets `generate` tries in turn, each (header, extra includes, the sidecar's
    `api_headers`, the tree headers it includes). A given `--header` (or `none`) is the only one.
    Without it, from the build capture (`capture_headers`):

    1. every chosen header;
    2. only when internal headers were chosen: the public ones alone;
    3. no capture header (`source: capture_failed`): the harness as without a capture, with the
       caller's `--extra-include` and `no_header_warning`.

    `generate` moves on while a set does not compile outside the cases (or none of its cases
    compiles) and records each abandoned set in `api_headers.fallbacks`. Without a capture choice
    (`not_found`) there is one attempt, without a header. `public` and `internal` list what that
    attempt's harness includes.
    """
    given = list(extra_includes or [])
    if header is not None:
        none = header.strip().lower() == "none"
        return [(header, given, {"source": "none" if none else "given", "why": f"--header {header}"}, [])]

    def take(chosen: dict[str, Any]) -> HeaderAttempt:
        hdr = chosen.pop("header")
        extra = [*chosen.pop("extra_includes"), *given]
        included = [*chosen.get("public", []), *(i["header"] for i in chosen.get("internal", []))]
        return hdr, extra, chosen, included

    chosen = capture_headers(dag, module, unit, capture_path, scope_files)
    if chosen["source"] != "capture":
        return [take(chosen)]
    out = [take(chosen)]
    if chosen["internal"]:
        pub = capture_headers(dag, module, unit, capture_path, scope_files, public_only=True)
        if pub["source"] == "capture":
            out.append(take(pub))
    failed: dict[str, Any] = {
        "source": "capture_failed",
        "why": (
            "--header not given: none of the build capture's headers compiles in the harness (`fallbacks`), "
            "so it includes none of them, as without a capture"
        ),
        "unit": chosen.get("unit"),
        "public": [],
        "internal": [],
    }
    out.append((None, given, failed, []))
    return out


def no_header_warning(capture_path: Path) -> str:
    """
    Why an `--api` harness without `--header` loses its cases: the harness declares only the first
    entry point, so every other case calls an undeclared function and the compile probe drops it.
    Names the build capture's public headers (`public_headers.files`) when it has them. Given only when
    the capture gives the module no header (`capture_headers`).
    """
    cap = load_json_optional(capture_path, None)
    pub = cap.get("public_headers") if isinstance(cap, dict) else None
    files = pub.get("files") if isinstance(pub, dict) else None
    names = sorted({Path(str(f)).name for f in files or [] if f})
    hint = f" (the build capture's public headers: {', '.join(names)})" if names else ""
    return (
        "--api without --header: the harness includes no header of the target and declares only its first "
        "entry point, so the compile probe drops every other case as `call to undeclared function`; pass "
        f"--header <public header>{hint}"
    )
