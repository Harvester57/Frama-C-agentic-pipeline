typedef struct json_object json_object;

json_object *from_void(void *p) {
  return (json_object *)p;
}

int main(void) {
  return from_void(0) != 0;
}
