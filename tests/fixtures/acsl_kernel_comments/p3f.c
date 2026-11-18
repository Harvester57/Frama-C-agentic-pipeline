/*@ requires s == "a // b" || b > 0;
*/
void string_with_slashes(const char *s, int b);

/*@ requires c == '/' || b > 0; // requires b > 1;
*/
void char_with_slash(char c, int b);
