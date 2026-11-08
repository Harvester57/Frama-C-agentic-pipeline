/* Alias narrowing (plan step I4): what Alias narrows, and where it is unsound. */
typedef int (*fn)(int);

int a(int x) { return x + 1; }
int b(int x) { return x + 2; }
int c(int x) { return x + 3; }

/* Flow-sensitive within a function: p may be a or c, never b. */
int pick(int k, int x)
{
    fn p = k ? a : c;
    return p(x);
}

/* g starts as a and set_g makes it b, but Alias analyses fire from the global initializers only:
   it answers {a} and the true edge fire -> b is lost. */
static fn g = a;
void set_g(void) { g = b; }
int fire(int x) { return g(x); }

/* A parameter: Alias has no target, the type match stays. */
int apply(fn f, int x) { return f(x); }