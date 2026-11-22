#include <stdio.h>

enum U { U_A = 0, U_B = 1 };
enum S { S_NEG = -1, S_POS = 1 };
enum L { L_BIG = 1ULL << 40 };
enum SL { SL_NEG = -1, SL_BIG = 1LL << 40 };
enum __attribute__((packed)) PU { PU_A = 0, PU_B = 1 };
enum __attribute__((packed)) PS { PS_NEG = -1, PS_POS = 1 };
typedef enum U u_t;
struct BF {
  enum U u : 3;
  enum S s : 3;
};

int main(void) {
#if defined(CASE_unsigned_enum)
  enum U u = U_B;
  printf("%u %x\n", u, u);
#elif defined(CASE_signed_enum)
  enum S s = S_NEG;
  printf("%d %i\n", s, s);
#elif defined(CASE_long_enum)
  enum L l = L_BIG;
  enum SL sl = SL_BIG;
  printf("%lu %ld\n", l, sl);
#elif defined(CASE_typedef_const_bf)
  const u_t cu = U_B;
  struct BF bf = {U_B, S_NEG};
  printf("%u %u %d\n", cu, bf.u, bf.s);
#elif defined(CASE_packed_enum)
  enum PS ps = PS_NEG;
  enum PU pu = PU_B;
  printf("%d %d %hhu\n", ps, pu, pu);
#elif defined(CASE_enum_ptr_n)
  enum S s = S_POS;
  printf("hi%n\n", &s);
  return s != 2;
#elif defined(CASE_snprintf_enum)
  enum S s = S_POS;
  char buf[16];
  snprintf(buf, sizeof buf, "%d", s);
#elif defined(CASE_enums_int)
  enum U u = U_B;
  printf("%d\n", u);
#elif defined(CASE_mismatch_str)
  enum S s = S_NEG;
  printf("%s\n", s);
#elif defined(CASE_mismatch_width)
  enum U u = U_B;
  printf("%lu\n", u);
#elif defined(CASE_mismatch_sign)
  enum U u = U_B;
  printf("%d\n", u);
#elif defined(CASE_mismatch_ptr_n)
  enum U u = U_B;
  printf("hi%n\n", &u);
#else
#error "define a CASE_* macro"
#endif
  return 0;
}
