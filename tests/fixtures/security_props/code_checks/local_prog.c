/* L6_wiped, a secret held in a local array (plan step M6): wiped before every return in its scope. */
/*@ requires \valid(b + (0 .. 15));
    assigns b[0 .. 15]; */
void fill(unsigned char *b);

/*@ assigns \nothing; */
int consume(const unsigned char *b);

int derive(int n)
{
    if (n > 99)
        return -2;
    {
        unsigned char buf[16];
        fill(buf);
        int r = consume(buf);
        /*@ loop invariant 0 <= i <= 16;
            loop invariant \forall integer k; 0 <= k < i ==> buf[k] == 0;
            loop assigns i, buf[0 .. 15]; */
        for (int i = 0; i < 16; i++)
            buf[i] = 0;
#ifdef VIOLATE
        fill(buf); /* the secret is back before the return */
#endif
        if (r < 0)
            /*@ check L6_wiped_buf: \forall integer i; 0 <= i < sizeof(buf) / sizeof(buf[0]) ==> buf[i] == 0; */ return -1;
    /*@ check L6_wiped_buf: \forall integer i; 0 <= i < sizeof(buf) / sizeof(buf[0]) ==> buf[i] == 0; */ }
    return n;
}
