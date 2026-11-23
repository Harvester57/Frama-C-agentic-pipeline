int main(void) {
  //@ check oct_18: L"\18"[0] == 1 && L"\18"[1] == '8';
  //@ check oct_79: L"\79"[0] == 7 && L"\79"[1] == '9';
  //@ check oct_123: L"\123"[0] == 83;
  //@ check esc_v: L"\v"[0] == 11;
  return 0;
}
