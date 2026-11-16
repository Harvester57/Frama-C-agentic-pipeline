#ifndef STUB_H
#define STUB_H
/* A spec-only stub whose assigns clause has no \from for its non-\result location. */
/*@ assigns *p, \result; */
int fill(int *p);
#endif
