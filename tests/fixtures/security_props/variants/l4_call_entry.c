/*
 * L4_call, entry: a callee the target defines and calls through a function pointer. The rule is its
 * precondition, which WP proves at the call (a \calling instance cannot name the arguments there).
 */
static int regs[8];

/*@ requires idx < 8; assigns regs[idx]; */
void write_reg(unsigned idx, int v)
{
    regs[idx] = v;
}

static void (*op)(unsigned, int) = write_reg;

/*@ requires op == &write_reg; */
void poke(unsigned i, int v)
{
#ifndef VIOLATE
    if (i >= 8)
        return;
#endif
    /*@ calls write_reg; */
    op(i, v);
}
