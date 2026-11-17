/* An unnamed parameter qualified with __restrict__. GCC and Clang reject the
   body: __restrict__ is a keyword for them, not a name. */
int get(int *__restrict__) { return *__restrict__; }
