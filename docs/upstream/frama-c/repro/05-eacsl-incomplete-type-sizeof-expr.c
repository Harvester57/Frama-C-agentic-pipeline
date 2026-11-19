struct opaque;
extern struct opaque g;
extern int a[];

struct complete {
  int x;
};
struct complete complete_var;

void check_sizeof(void) {
  /*@ assert sizeof(g) > 0; */
  /*@ assert sizeof(a) > 0; */
  /*@ assert sizeof(complete_var) > 0; */
}

int main(void) {
  check_sizeof();
  return 0;
}
