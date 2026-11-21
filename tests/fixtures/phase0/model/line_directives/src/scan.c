#include <string.h>
#line 3 "scan.c"
int scan_global = 3;
#line 1 "scan.l"
#include "lexer.h"
#include <stdlib.h>
static int helper(int x) { return x + 1; }
int scan_entry(int x) { return helper(x) + lex_twice(x); }
#line 12 "scan.c"
int scan_len(const char *s)
{
  return (int)strlen(s) + scan_global;
}
int lex_peek(void) { return scan_global; }
int util_id(int v) { return v; }
