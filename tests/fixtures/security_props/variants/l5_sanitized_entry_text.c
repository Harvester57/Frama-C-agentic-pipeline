/*
 * L5_sanitized, entry/text_formal: a log sink the target defines and calls through a function
 * pointer. The property is the sink's precondition, which WP proves at the call.
 */
static char last;

/*@ assigns last; */
void log_line(const char *msg)
{
    last = msg[0];
}

static void (*logger)(const char *) = log_line;

/*@ requires logger == &log_line; */
void report(int open)
{
    char line[3];
    line[0] = open ? 'u' : 'd';
#ifdef VIOLATE
    line[1] = '\n'; /* log injection */
#else
    line[1] = 'p';
#endif
    line[2] = '\0';
    /*@ calls log_line; */
    logger(line);
}
