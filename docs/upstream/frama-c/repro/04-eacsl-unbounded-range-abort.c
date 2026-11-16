/*@ requires \valid_read(p + (0..));
    requires n >= 0; */
int first(const char *p, int n) { return n > 0 ? p[0] : 0; }

int main(void) {
  char b[2] = "a";
  return first(b, -1);
}
