/* GCC and Clang accept three spellings of the restrict qualifier: restrict,
   __restrict and __restrict__. R is the spelling, POS the position. No
   #include: a Frama-C libc header would rewrite the spelling (features.h). */
#if POS == 1 /* file scope */
int *R gp;
#elif POS == 2 /* struct member */
struct s { int *R m; } gs;
#elif POS == 3 /* named parameter of a prototype */
int get(int *R p);
int use(int *p) { return get(p); }
#elif POS == 4 /* parameter of a definition */
int get(int *R p) { return *p; }
#elif POS == 5 /* block scope */
int get(int *p) { int *R l = p; return *l; }
#elif POS == 6 /* cast */
int get(void *p) { return *(int *R)p; }
#endif
