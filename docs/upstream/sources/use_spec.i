/* run.config*
 EXIT: 1
   OPT: -eva-use-spec f,h -eva @EVA_OPTIONS@ -inout -calldeps
   OPT: -eva-use-spec f,h -eva @EVA_OPTIONS@ -inout -calldeps -show-indirect-deps
*/

void f(int *x) {
}

void g(int *y);

//@ assigns *z \from \nothing;
void h(int *z) {
}

//@ assigns *w \from \nothing;
void i(int *w);

int w, x, y, z;

void main() {
  f(&x);
  g(&y);
  h(&z);
  i(&w);
}
