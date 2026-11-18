/* L4_call, a rule over globals: use_dev (declared only) is called only once ready is set. */
int ready;

/*@ assigns \nothing; */
void use_dev(int v);

void init_dev(void)
{
    ready = 1;
}

void work(int v)
{
#ifndef VIOLATE
    if (ready)
#endif
        use_dev(v);
}
