/* L4_call, a rule over a parameter of the callee: write_reg is called with idx < 8 only. */
/*@ assigns \nothing; */
void write_reg(unsigned idx, int v);

void poke(unsigned i, int v)
{
#ifndef VIOLATE
    if (i < 8)
#endif
        write_reg(i, v);
}
