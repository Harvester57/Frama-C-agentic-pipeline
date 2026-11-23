void main(void) {
  const char *a = "\x4" "1";
  const char *b = "\01" "2";
  /*@ check c1: ("\x4" "1")[0] == 4; */
  /*@ check c2: ("\01" "2")[0] == 1; */
  /*@ check c3: ("\\" "n")[0] == '\\'; */
  /*@ check c4: (L"\x4" "1")[0] == 4; */
  /*@ check c5: (L"\01" "2")[0] == 1; */
}
