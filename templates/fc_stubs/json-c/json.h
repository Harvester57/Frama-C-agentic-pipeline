/*
 * Frama-C Bodyless Prototype Stub for <json-c/json.h>
 *
 * Provides opaque types and bodyless function prototypes for json-c so Frama-C
 * (Eva / WP) can typecheck and analyze modules that call json-c under -nostdinc,
 * recording external library specifications as Considered valid (STATUS_ASSUMED).
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

typedef struct json_object json_object;
typedef struct array_list array_list;
typedef struct lh_table lh_table;

#define JSON_C_TO_STRING_PLAIN      0
#define JSON_C_TO_STRING_SPACED     (1 << 0)
#define JSON_C_TO_STRING_PRETTY     (1 << 1)
#define JSON_C_TO_STRING_NOZERO     (1 << 2)
#define JSON_C_TO_STRING_PRETTY_TAB (1 << 3)
#define JSON_C_TO_STRING_NOSLASHESCAPE (1 << 4)

json_object *json_tokener_parse(const char *str);
json_object *json_object_from_file(const char *filename);
int json_object_to_file(const char *filename, json_object *obj);
int json_object_to_file_ext(const char *filename, json_object *obj, int flags);
const char *json_object_to_json_string(json_object *obj);
const char *json_object_to_json_string_ext(json_object *obj, int flags);

json_object *json_object_get(json_object *obj);
int json_object_put(json_object *obj);

int json_object_is_type(const json_object *obj, enum json_type type);
enum json_type json_object_get_type(const json_object *obj);

json_object *json_object_new_object(void);
int json_object_object_length(const json_object *obj);
int json_object_object_add(json_object *obj, const char *key, json_object *val);
void json_object_object_del(json_object *obj, const char *key);
json_object *json_object_object_get(const json_object *obj, const char *key);
json_bool json_object_object_get_ex(const json_object *obj, const char *key, json_object **value);

json_object *json_object_new_array(void);
json_object *json_object_new_array_ext(int initial_size);
size_t json_object_array_length(const json_object *obj);
int json_object_array_add(json_object *obj, json_object *val);
int json_object_array_put_idx(json_object *obj, size_t idx, json_object *val);
json_object *json_object_array_get_idx(const json_object *obj, size_t idx);

json_object *json_object_new_boolean(json_bool b);
json_bool json_object_get_boolean(const json_object *obj);

json_object *json_object_new_int(int32_t i);
json_object *json_object_new_int64(int64_t i);
json_object *json_object_new_uint64(uint64_t i);
int32_t json_object_get_int(const json_object *obj);
int64_t json_object_get_int64(const json_object *obj);
uint64_t json_object_get_uint64(const json_object *obj);

json_object *json_object_new_double(double d);
double json_object_get_double(const json_object *obj);

json_object *json_object_new_string(const char *s);
json_object *json_object_new_string_len(const char *s, const int len);
const char *json_object_get_string(json_object *obj);
int json_object_get_string_len(const json_object *obj);

#endif /* FRAMAC_JSON_C_JSON_H */
