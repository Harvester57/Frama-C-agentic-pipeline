/* L5_sanitized, emit/text: no CR or LF in a line handed to the log sink. */
void log_line(const char *msg);

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
    log_line(line);
}
