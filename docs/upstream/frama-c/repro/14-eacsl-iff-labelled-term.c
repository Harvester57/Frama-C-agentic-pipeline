struct s { int n; };

/* In a postcondition, the formal b stands for \old(b). */
/*@ requires \valid_read(b);
    assigns \nothing;
    ensures (\result != 0) <==> (b->n == 0); */
int f(struct s *b) { return b->n == 0; }

int main(void) { struct s x = { 0 }; return f(&x) - 1; }
