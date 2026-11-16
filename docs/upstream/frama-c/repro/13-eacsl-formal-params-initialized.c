struct S { const void *p; unsigned long len; };

/*@ requires \initialized(&s.len); */
int f_req(struct S s) { return s.len > 3; }

int main(void) {
  struct S full = { 0, 5 }; /* fully initialized */
  return f_req(full) - 1;
}
