/*
 * L6_no_leak, calling, global secret, decided statically: the satisfied version passes a string
 * literal, so the instance is obviously true and MetAcsl (-meta-simpl, its default) drops it: no goal
 * is left, and ledger.py ingest-wp credits the unit from the report's loaded properties. The literal
 * also decides L5_sanitized_log_line from the model (plan step M2), so the run has no meta goal at all.
 * The sink has a contract: a callee without one makes the WP run `unsound_proof`, never credited.
 */
/*@ assigns \nothing; */
void log_line(const char *msg);

static char key[16];

void set_key(const char *k)
{
    key[0] = k[0];
}

void show(void)
{
#ifdef VIOLATE
    log_line(key); /* leak */
#else
    log_line("banner");
#endif
}
