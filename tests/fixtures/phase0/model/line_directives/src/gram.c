#include <stdio.h>
#line 1 "gram.y"
#include "lexer.h"
#include "gen.h"
static int gram_state;
int parse(void)
{
  gram_state = lex_peek() + gen_twice(1);
  return gram_state;
}
