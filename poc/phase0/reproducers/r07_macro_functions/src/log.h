#ifndef REC_LOG_H
#define REC_LOG_H

/* Internal: report a decode failure and return -1. */
int rec_log_fail(const char *func, const char *what);

#define LOG_FAIL(what) rec_log_fail(__func__, (what))

#endif
