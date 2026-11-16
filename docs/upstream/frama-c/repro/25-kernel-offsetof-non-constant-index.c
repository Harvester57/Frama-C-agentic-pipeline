/* offsetof with a non-constant array index in the member designator: a GCC
   (and Clang) extension, used for instance by libseccomp
   (offsetof(struct seccomp_data, args[x])). */
#include <stddef.h>

struct s {
  int hdr;
  struct { char c; long v[4]; } inner[3];
  unsigned long long args[6];
};

/*@ requires 0 <= i < 6;
    assigns \nothing;
    ensures \result == 128 + 8 * i; */
size_t arg_offset(int i)
{
  return offsetof(struct s, args[i]);
}

/*@ requires 0 <= i < 3 && 0 <= j < 4;
    assigns \nothing;
    ensures \result == 16 + 40 * i + 8 * j; */
size_t inner_offset(int i, int j)
{
  return offsetof(struct s, inner[i].v[j]);
}

int main(void)
{
  return (int)(arg_offset(2) + inner_offset(1, 3)) - 224;
}
