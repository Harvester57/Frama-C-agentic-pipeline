/* A declared callee whose `assigns` holds a set (package R of
 * docs/plans/metacsl-exploitation-plan.md): MetAcsl 0.12 stops on it in every function a \writing
 * property targets (meta_annotate.ml, line 675). `uses_two` calls it; `store` is another instance of
 * the same property, whose proof must still run.
 */
int auth_ok;
int other;

/*@ assigns \union(*a, *b); */
extern void two(int *a, int *b);

void login(void)
{
    auth_ok = 1;
}

/*@ requires auth_ok != 0; assigns \nothing; */
void admin(void)
{
}

void uses_two(void)
{
    int x = 0;
    two(&other, &x);
}

/*@ requires \valid(out) && \separated(out, &auth_ok);
    assigns *out; */
void store(int *out)
{
    *out = 1;
}
