/* Variants selected with -D; the default is the minimal failing case. */
union u { unsigned char b[16]; unsigned long w[2]; };
struct s { unsigned char b[16]; unsigned long w[2]; };

#if defined(LOCAL_STATIC)
int main(void) { static const union u zero_block; return zero_block.b[0]; }
#elif defined(INITIALIZED)
static const union u zero_block = { { 0 } };
int main(void) { return zero_block.b[0]; }
#elif defined(NON_STATIC)
const union u zero_block;
int main(void) { return zero_block.b[0]; }
#elif defined(CONST_STRUCT)
static const struct s zero_block;
int main(void) { return zero_block.b[0]; }
#elif defined(NON_CONST_UNION)
static union u zero_block;
int main(void) { return zero_block.b[0]; }
#else
static const union u zero_block;
int main(void) { return zero_block.b[0]; }
#endif
