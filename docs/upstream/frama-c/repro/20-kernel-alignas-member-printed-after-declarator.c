/* Frama-C prints _Alignas inside or after the declarator for struct/union
   members and for pointer declarators, which is not valid C. */
#include <stdint.h>

union blk {
  _Alignas(16) uint64_t u64[2]; /* nettle's union nettle_block16 */
  uint8_t b[16];
};

struct s {
  char c;
  _Alignas(8) char d;
  _Alignas(16) int *p;
};

_Alignas(16) int *gp;          /* global pointer */
_Alignas(16) int (*gfp)(int);  /* global function pointer */
_Alignas(8) char *gap[2];      /* global array of pointers */
_Alignas(16) uint64_t ga[2];   /* global array: already printed validly */

int main(void)
{
  _Alignas(16) int *lp = 0;    /* local pointer */
  union blk u = { .b = { 0 } };
  struct s v = { 0 };
  return (int)u.u64[0] + v.c + (lp == 0) + (gp == 0) + (gfp == 0)
    + (gap[0] == 0) + (int)ga[0];
}
