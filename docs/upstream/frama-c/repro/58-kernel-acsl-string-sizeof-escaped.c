#define GREETING "hello\n"
char out[sizeof(GREETING)];

/*@ assigns \nothing;
    ensures len: \result == sizeof(GREETING); */
unsigned long greeting_size(void) { return sizeof(GREETING); }

/*@ requires room: \valid(buf + (0 .. sizeof(GREETING) - 1));
    assigns buf[0 .. sizeof(GREETING) - 1]; */
void greet(char *buf) { buf[0] = 'h'; }

int main(void) {
  //@ check c1: sizeof("\n") == 2;
  //@ check c2: sizeof("a\0b") == 4;
  //@ check c3: sizeof("\x41") == 2;
  //@ check c4: sizeof("\\") == 2;
  //@ check c5: sizeof(GREETING) == sizeof(out);
  greet(out);
  return 0;
}
