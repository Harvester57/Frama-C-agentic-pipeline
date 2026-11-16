typedef struct json_object json_object;

/*@ requires obj == \null || \valid_read(obj); */
int is_set(const json_object *obj) {
  return obj != 0;
}

int main(void) {
  return is_set(0);
}
