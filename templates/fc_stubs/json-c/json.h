/*
 * Frama-C prototypes and ACSL contracts for <json-c/json.h> (json-c 0.18 API subset).
 *
 * No C bodies: Eva and WP use the contracts, which the ledger records as assumed
 * (STATUS_ASSUMED). Behaviour stated here is json-c 0.18's (json_object.c, json_tokener.c,
 * json_util.c): which functions accept NULL, which assert on it, what they return.
 *
 * Eva / WP (__fc_libc): handles come from ghost pools, as Frama-C's libc does for FILE
 * (`__fc_fopen`): a constructor returns NULL or an element of `__fc_json_pool`, so a target
 * that uses a handle without its NULL check gets an alarm. Returned strings point into the
 * ghost buffer `__fc_json_strbuf` and are valid strings of at most
 * __FC_JSON_STRBUF_SIZE - 1 bytes; its last byte is never written, every other byte is
 * unknown after a call that returns a string. The pools model neither reference counts nor
 * the free in json_object_put: a use after the last put is not an alarm.
 *
 * E-ACSL (__FRAMAC_EACSL__, the real json-c is linked): json-c allocates its objects and
 * strings itself, outside the instrumented code, so E-ACSL does not track them and
 * `\valid_read` is false on them. Handles are therefore only required non-NULL where json-c
 * asserts on NULL, and a string argument is checked only when it lies in tracked memory
 * (`__fc_json_string`). Postconditions on returned handles and strings are Eva / WP only
 * (the `__FC_JSON_*_RESULT` macros are `\true`); the others (return codes, enum ranges) hold for json-c
 * 0.18 and E-ACSL checks them. The pools are declared in both modes for typing. Under
 * Frama-C they carry libc's `__fc_stdlib_internal` attribute, so E-ACSL does not register
 * them as globals (they are never defined, and the binary would not link); a plain compiler
 * that reads this header (an uninstrumented build) sees no attribute.
 */

#ifndef FRAMAC_JSON_C_JSON_H
#define FRAMAC_JSON_C_JSON_H

#include <stddef.h>
#include <stdint.h>

typedef int json_bool;

#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif

typedef enum json_type {
    json_type_null = 0,
    json_type_boolean,
    json_type_double,
    json_type_int,
    json_type_object,
    json_type_array,
    json_type_string
} json_type;

enum json_tokener_error {
    json_tokener_success,
    json_tokener_continue,
    json_tokener_error_depth,
    json_tokener_error_parse_eof,
    json_tokener_error_parse_unexpected,
    json_tokener_error_parse_null,
    json_tokener_error_parse_boolean,
    json_tokener_error_parse_number,
    json_tokener_error_parse_array,
    json_tokener_error_parse_object_key_name,
    json_tokener_error_parse_object_key_sep,
    json_tokener_error_parse_object_value_sep,
    json_tokener_error_parse_string,
    json_tokener_error_parse_comment,
    json_tokener_error_parse_utf8_string,
    json_tokener_error_size,
    json_tokener_error_memory
};

/*
 * Opaque handles are complete (single dummy member) because E-ACSL emits
 * alignof/sizeof on pointed-to types. Target code must never dereference them;
 * json-c allocates and owns the real objects. json-c 0.18 still publishes the fields
 * of struct json_tokener (deprecated); code that reads them does not parse here.
 */
struct json_object { int _fc_opaque; };
struct json_tokener { int _fc_opaque; };
struct array_list { int _fc_opaque; };
struct lh_table { int _fc_opaque; };
typedef struct json_object json_object;
typedef struct json_tokener json_tokener;
typedef struct array_list array_list;
typedef struct lh_table lh_table;

#define JSON_C_TO_STRING_PLAIN      0
#define JSON_C_TO_STRING_SPACED     (1 << 0)
#define JSON_C_TO_STRING_PRETTY     (1 << 1)
#define JSON_C_TO_STRING_NOZERO     (1 << 2)
#define JSON_C_TO_STRING_PRETTY_TAB (1 << 3)
#define JSON_C_TO_STRING_NOSLASHESCAPE (1 << 4)
#define JSON_C_TO_STRING_COLOR      (1 << 5)

#define JSON_TOKENER_DEFAULT_DEPTH 32
#define JSON_TOKENER_STRICT 0x01
#define JSON_TOKENER_ALLOW_TRAILING_CHARS 0x02
#define JSON_TOKENER_VALIDATE_UTF8 0x10

/* Ghost state (never defined: Eva starts from unknown contents). */
#ifndef __FC_JSON_POOL_SIZE
#define __FC_JSON_POOL_SIZE 16
#endif
#ifndef __FC_JSON_TOKENER_POOL_SIZE
#define __FC_JSON_TOKENER_POOL_SIZE 4
#endif
#ifndef __FC_JSON_STRBUF_SIZE
#define __FC_JSON_STRBUF_SIZE 65536
#endif
#ifdef __FRAMAC__
#define __FC_JSON_GHOST __attribute__((__fc_stdlib_internal))
#else
#define __FC_JSON_GHOST
#endif
extern __FC_JSON_GHOST struct json_object __fc_json_pool[__FC_JSON_POOL_SIZE];
extern __FC_JSON_GHOST struct json_tokener __fc_json_tokener_pool[__FC_JSON_TOKENER_POOL_SIZE];
extern __FC_JSON_GHOST char __fc_json_strbuf[__FC_JSON_STRBUF_SIZE];

#if defined(__FRAMAC_EACSL__)

/*@
  predicate __fc_json_nul(char *s, integer i) = s[i] == '\0';
  // NUL-terminated inside its own block, when the block is tracked (see the header comment).
  predicate __fc_json_string(char *s) =
    \valid_read(s) ==>
      \exists integer i; 0 <= i < \block_length(s) - \offset(s) && __fc_json_nul(s, i);
  predicate __fc_json_readable(char *s, integer n) =
    \valid_read(s) ==> \valid_read(s + (0 .. n - 1));
  predicate __fc_json_handle(struct json_object *o) = o != \null;
  predicate __fc_json_handle_or_null(struct json_object *o) = \true;
  predicate __fc_json_tokener(struct json_tokener *t) = t != \null;
  predicate __fc_json_tokener_or_null(struct json_tokener *t) = \true;
*/

#define __FC_JSON_HANDLE_RESULT(r) \true
#define __FC_JSON_TOKENER_RESULT(r) \true
#define __FC_JSON_STRING_RESULT(r) \true
#define __FC_JSON_STRBUF_NUL \true

#else /* Eva / WP */

/*@
  predicate __fc_json_string(char *s) = valid_read_string(s);
  predicate __fc_json_readable(char *s, integer n) = \valid_read(s + (0 .. n - 1));
  predicate __fc_json_handle(struct json_object *o) = \valid_read(o);
  predicate __fc_json_handle_or_null(struct json_object *o) = o == \null || \valid_read(o);
  predicate __fc_json_tokener(struct json_tokener *t) = \valid(t);
  predicate __fc_json_tokener_or_null(struct json_tokener *t) = t == \null || \valid(t);
*/

/* Postconditions are macros, not predicates: Eva reduces a returned pointer by a \subset
 * written in the ensures clause, and keeps a garbled mix when the same \subset sits inside a
 * predicate. */
#define __FC_JSON_HANDLE_RESULT(r) \
  ((r) == \null || \subset((r), &__fc_json_pool[0 .. __FC_JSON_POOL_SIZE - 1]))
#define __FC_JSON_TOKENER_RESULT(r) \
  ((r) == \null || \subset((r), &__fc_json_tokener_pool[0 .. __FC_JSON_TOKENER_POOL_SIZE - 1]))
#define __FC_JSON_STRING_RESULT(r) \
  ((r) == \null || \
   (\subset((r), &__fc_json_strbuf[0 .. __FC_JSON_STRBUF_SIZE - 1]) && valid_read_string(r)))
#define __FC_JSON_STRBUF_NUL (__fc_json_strbuf[__FC_JSON_STRBUF_SIZE - 1] == '\0')

#endif /* __FRAMAC_EACSL__ */

/* ---- Tokener ---------------------------------------------------------------------------- */

/*@
  requires valid_str: __fc_json_string((char *)str);
  assigns \result \from &__fc_json_pool, indirect:str[0 ..];
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_tokener_parse(const char *str);

/*@
  requires valid_str: __fc_json_string((char *)str);
  requires valid_error: \valid(error);
  assigns *error \from indirect:str[0 ..];
  assigns \result \from &__fc_json_pool, indirect:str[0 ..];
  ensures error_set: json_tokener_success <= *error <= json_tokener_error_memory;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_tokener_parse_verbose(const char *str, enum json_tokener_error *error);

/*@
  assigns \result \from &__fc_json_tokener_pool;
  ensures null_or_tokener: __FC_JSON_TOKENER_RESULT(\result);
*/
json_tokener *json_tokener_new(void);

/*@
  assigns \result \from &__fc_json_tokener_pool, indirect:depth;
  ensures null_or_tokener: __FC_JSON_TOKENER_RESULT(\result);
*/
json_tokener *json_tokener_new_ex(int depth);

/*@
  requires valid_tok: __fc_json_tokener_or_null(tok);
  assigns \nothing;
*/
void json_tokener_free(json_tokener *tok);

/*@
  requires valid_tok: __fc_json_tokener_or_null(tok);
  assigns *tok \from indirect:tok;
*/
void json_tokener_reset(json_tokener *tok);

/*@
  requires valid_tok: __fc_json_tokener(tok);
  requires valid_str: len == -1 ==> __fc_json_string((char *)str);
  requires readable_str: len >= 0 ==> __fc_json_readable((char *)str, len);
  assigns *tok \from *tok, indirect:str[0 ..], indirect:len;
  assigns \result \from &__fc_json_pool, indirect:*tok, indirect:str[0 ..], indirect:len;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_tokener_parse_ex(json_tokener *tok, const char *str, int len);

/*@
  requires valid_tok: __fc_json_tokener(tok);
  assigns \result \from *tok;
  ensures known_error: json_tokener_success <= \result <= json_tokener_error_memory;
*/
enum json_tokener_error json_tokener_get_error(json_tokener *tok);

/*@
  assigns \result \from &__fc_json_strbuf, indirect:jerr;
  ensures valid_string: __FC_JSON_STRING_RESULT(\result);
  ensures nul_terminated: __FC_JSON_STRBUF_NUL;
  ensures not_null: \result != \null;
*/
const char *json_tokener_error_desc(enum json_tokener_error jerr);

/*@
  requires valid_tok: __fc_json_tokener(tok);
  assigns *tok \from *tok, indirect:flags;
*/
void json_tokener_set_flags(json_tokener *tok, int flags);

/*@
  requires valid_tok: __fc_json_tokener(tok);
  assigns \result \from *tok;
*/
size_t json_tokener_get_parse_end(json_tokener *tok);

/* ---- Files and serialisation ------------------------------------------------------------ */

/*@
  requires valid_filename: __fc_json_string((char *)filename);
  assigns \result \from &__fc_json_pool, indirect:filename[0 ..];
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_from_file(const char *filename);

/*@
  assigns \result \from &__fc_json_pool, indirect:fd;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_from_fd(int fd);

/*@
  requires valid_filename: __fc_json_string((char *)filename);
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:filename[0 ..], indirect:obj;
  ensures ok_or_error: \result == 0 || \result == -1;
*/
int json_object_to_file(const char *filename, json_object *obj);

/*@
  requires valid_filename: __fc_json_string((char *)filename);
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:filename[0 ..], indirect:obj, indirect:flags;
  ensures ok_or_error: \result == 0 || \result == -1;
*/
int json_object_to_file_ext(const char *filename, json_object *obj, int flags);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns __fc_json_strbuf[0 .. __FC_JSON_STRBUF_SIZE - 2] \from indirect:obj;
  assigns \result \from &__fc_json_strbuf, indirect:obj;
  ensures null_or_string: __FC_JSON_STRING_RESULT(\result);
  ensures nul_terminated: __FC_JSON_STRBUF_NUL;
*/
const char *json_object_to_json_string(json_object *obj);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns __fc_json_strbuf[0 .. __FC_JSON_STRBUF_SIZE - 2] \from indirect:obj, indirect:flags;
  assigns \result \from &__fc_json_strbuf, indirect:obj, indirect:flags;
  ensures null_or_string: __FC_JSON_STRING_RESULT(\result);
  ensures nul_terminated: __FC_JSON_STRBUF_NUL;
*/
const char *json_object_to_json_string_ext(json_object *obj, int flags);

/* ---- Reference counting and type -------------------------------------------------------- */

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from obj;
  ensures same_handle: \result == obj;
*/
json_object *json_object_get(json_object *obj);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:obj;
  ensures freed_or_not: \result == 0 || \result == 1;
*/
int json_object_put(json_object *obj);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:obj, indirect:type;
  ensures boolean: \result == 0 || \result == 1;
  ensures null_is_null_type: obj == \null ==> (\result == 1 <==> type == json_type_null);
*/
int json_object_is_type(const json_object *obj, enum json_type type);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:obj;
  ensures known_type: json_type_null <= \result <= json_type_string;
  ensures null_is_null_type: obj == \null ==> \result == json_type_null;
*/
enum json_type json_object_get_type(const json_object *obj);

/*@
  assigns \result \from &__fc_json_strbuf, indirect:o_type;
  ensures name: json_type_null <= o_type <= json_type_string ==>
    (\result != \null && __FC_JSON_STRING_RESULT(\result));
  ensures nul_terminated: __FC_JSON_STRBUF_NUL;
  ensures out_of_range: !(json_type_null <= o_type <= json_type_string) ==> \result == \null;
*/
const char *json_type_to_name(enum json_type o_type);

/* ---- Objects ---------------------------------------------------------------------------- */

/*@
  assigns \result \from &__fc_json_pool;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_new_object(void);

/*@
  requires valid_obj: __fc_json_handle(obj);
  assigns \result \from indirect:obj;
  ensures non_negative: \result >= 0;
*/
int json_object_object_length(const json_object *obj);

/*@
  requires valid_obj: __fc_json_handle(obj);
  requires valid_key: __fc_json_string((char *)key);
  requires valid_val: __fc_json_handle_or_null(val);
  assigns \result \from indirect:obj, indirect:key[0 ..], indirect:val;
  ensures ok_or_error: \result == 0 || \result == -1;
*/
int json_object_object_add(json_object *obj, const char *key, json_object *val);

/*@
  requires valid_obj: __fc_json_handle(obj);
  requires valid_key: __fc_json_string((char *)key);
  assigns \nothing;
*/
void json_object_object_del(json_object *obj, const char *key);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  requires valid_key: __fc_json_string((char *)key);
  assigns \result \from &__fc_json_pool, indirect:obj, indirect:key[0 ..];
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_object_get(const json_object *obj, const char *key);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  requires valid_key: __fc_json_string((char *)key);
  requires valid_value: value == \null || \valid(value);
  assigns *value, \result \from &__fc_json_pool, indirect:obj, indirect:key[0 ..];
  ensures boolean: \result == 0 || \result == 1;
  behavior with_value:
    assumes value != \null;
    assigns *value, \result \from &__fc_json_pool, indirect:obj, indirect:key[0 ..];
    ensures found_handle: __FC_JSON_HANDLE_RESULT(*value);
    ensures not_found_null: \result == 0 ==> *value == \null;
  behavior without_value:
    assumes value == \null;
    assigns \result \from indirect:obj, indirect:key[0 ..];
  complete behaviors;
  disjoint behaviors;
*/
json_bool json_object_object_get_ex(const json_object *obj, const char *key, json_object **value);

/* ---- Arrays ----------------------------------------------------------------------------- */

/*@
  assigns \result \from &__fc_json_pool;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_new_array(void);

/*@
  assigns \result \from &__fc_json_pool, indirect:initial_size;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_new_array_ext(int initial_size);

/*@
  requires valid_obj: __fc_json_handle(obj);
  assigns \result \from indirect:obj;
*/
size_t json_object_array_length(const json_object *obj);

/*@
  requires valid_obj: __fc_json_handle(obj);
  requires valid_val: __fc_json_handle_or_null(val);
  assigns \result \from indirect:obj, indirect:val;
  ensures ok_or_error: \result == 0 || \result == -1;
*/
int json_object_array_add(json_object *obj, json_object *val);

/*@
  requires valid_obj: __fc_json_handle(obj);
  requires valid_val: __fc_json_handle_or_null(val);
  assigns \result \from indirect:obj, indirect:idx, indirect:val;
  ensures ok_or_error: \result == 0 || \result == -1;
*/
int json_object_array_put_idx(json_object *obj, size_t idx, json_object *val);

/*@
  requires valid_obj: __fc_json_handle(obj);
  assigns \result \from &__fc_json_pool, indirect:obj, indirect:idx;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_array_get_idx(const json_object *obj, size_t idx);

/*@
  requires valid_obj: __fc_json_handle(obj);
  assigns \result \from indirect:obj, indirect:idx, indirect:count;
  ensures ok_or_error: \result == 0 || \result == -1;
*/
int json_object_array_del_idx(json_object *obj, size_t idx, size_t count);

/* ---- Scalars ---------------------------------------------------------------------------- */

/*@
  assigns \result \from &__fc_json_pool, indirect:b;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_new_boolean(json_bool b);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:obj;
  ensures null_is_false: obj == \null ==> \result == 0;
*/
json_bool json_object_get_boolean(const json_object *obj);

/*@
  assigns \result \from &__fc_json_pool, indirect:i;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_new_int(int32_t i);

/*@
  assigns \result \from &__fc_json_pool, indirect:i;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_new_int64(int64_t i);

/*@
  assigns \result \from &__fc_json_pool, indirect:i;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_new_uint64(uint64_t i);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:obj;
  ensures null_is_zero: obj == \null ==> \result == 0;
*/
int32_t json_object_get_int(const json_object *obj);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:obj;
  ensures null_is_zero: obj == \null ==> \result == 0;
*/
int64_t json_object_get_int64(const json_object *obj);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:obj;
  ensures null_is_zero: obj == \null ==> \result == 0;
*/
uint64_t json_object_get_uint64(const json_object *obj);

/*@
  assigns \result \from &__fc_json_pool, indirect:d;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_new_double(double d);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:obj;
*/
double json_object_get_double(const json_object *obj);

/* ---- Strings ---------------------------------------------------------------------------- */

/*@
  requires valid_s: __fc_json_string((char *)s);
  assigns \result \from &__fc_json_pool, indirect:s[0 ..];
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_new_string(const char *s);

/*@
  requires valid_len: len >= 0;
  requires readable_s: __fc_json_readable((char *)s, len);
  assigns \result \from &__fc_json_pool, indirect:s[0 .. len - 1], indirect:len;
  ensures null_or_handle: __FC_JSON_HANDLE_RESULT(\result);
*/
json_object *json_object_new_string_len(const char *s, const int len);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns __fc_json_strbuf[0 .. __FC_JSON_STRBUF_SIZE - 2] \from indirect:obj;
  assigns \result \from &__fc_json_strbuf, indirect:obj;
  ensures null_or_string: __FC_JSON_STRING_RESULT(\result);
  ensures nul_terminated: __FC_JSON_STRBUF_NUL;
  ensures null_for_null: obj == \null ==> \result == \null;
*/
const char *json_object_get_string(json_object *obj);

/*@
  requires valid_obj: __fc_json_handle_or_null(obj);
  assigns \result \from indirect:obj;
  ensures non_negative: \result >= 0;
  ensures null_is_zero: obj == \null ==> \result == 0;
*/
int json_object_get_string_len(const json_object *obj);

#endif /* FRAMAC_JSON_C_JSON_H */
