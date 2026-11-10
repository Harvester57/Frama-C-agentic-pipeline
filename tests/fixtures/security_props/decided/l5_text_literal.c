/*
 * L5_sanitized, text, decided from the model (plan step M2): every call of the log sink in `report`
 * passes a string literal. Satisfied: no CR or LF before the NUL (one after it does not count).
 * Violated (-DVIOLATE): a literal with LF, a log injection.
 */
void log_line(const char *msg);
void log_at(int level, const char *msg);

void report(int open)
{
    log_line("state:");
#ifdef VIOLATE
    log_at(1, open ? "up\n" : "down");
    log_line("injected\nline");
#else
    log_at(1, "up\0\n");
#endif
}
