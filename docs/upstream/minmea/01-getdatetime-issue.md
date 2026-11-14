`minmea_parse_zda()` accepts any integer as day, month and year, and `minmea_getdatetime()` uses them without a range check. Two consequences on `master` (`c43c9e7`):

1. `tm->tm_mon = date->month - 1` (`minmea.c:656`) is a signed integer overflow when the month field is `-2147483648`.
2. Without any undefined behaviour, a month such as `13` or a day such as `99` returns success and is handed to `timegm()` by `minmea_gettime()`.

Neither is a memory-safety bug inside minmea. The point is that a caller who checks every return value still gets a "valid" `struct tm` or timestamp from a sentence that is not a date.

## Reproducer

```c
#include <stdio.h>
#include <time.h>
#include "minmea.h"

int main(void)
{
    struct minmea_sentence_zda zda;
    struct tm tm;

    if (!minmea_parse_zda(&zda, "$GPZDA,000000.00,01,-2147483648,2020,00,00"))
        return 2;
    int rc = minmea_getdatetime(&tm, &zda.date, &zda.time);
    printf("month INT_MIN: rc=%d tm_mon=%d\n", rc, rc == 0 ? tm.tm_mon : -1);

    if (!minmea_parse_zda(&zda, "$GPZDA,000000.00,01,13,2020,00,00"))
        return 3;
    rc = minmea_getdatetime(&tm, &zda.date, &zda.time);
    printf("month 13: rc=%d tm_mon=%d\n", rc, rc == 0 ? tm.tm_mon : -1);
    return 0;
}
```

```
$ gcc -g -O1 -fsanitize=undefined minmea.c repro.c -o repro && ./repro
minmea.c:656:30: runtime error: signed integer overflow: -2147483648 - 1 cannot be represented in type 'int'
month INT_MIN: rc=0 tm_mon=2147483647
month 13: rc=0 tm_mon=12
```

Both sentences pass `minmea_parse_zda()`. Their checksums are omitted here for readability; `minmea_parse_zda()` does not look at the checksum, and a sender can compute a valid one.

## Cause

`minmea_parse_zda()` validates `hour_offset` and `minute_offset` only. `minmea_getdatetime()` rejects the `-1` sentinel for the year and the hours, nothing else. The RMC path is narrower (the `D` specifier reads two digits per field), but it still lets months `13` to `99` through.

## Suggested fix

Reject a month outside `1..12` and a day outside `1..31` in `minmea_getdatetime()`, which covers every producer of a `struct minmea_date`. I am opening a pull request with that change and regression tests.

I left `minmea_parse_zda()` alone on purpose: an empty ZDA date field parses to `0`, and rejecting it there would change which sentences parse. Happy to add the check there too if you prefer.

## Related

This is separate from #106, which covers `abs(INT_MIN)` on `hour_offset` in the same function and the `scale *= 10` overflow in `minmea_scan()`.

Found with Frama-C (E-ACSL runtime checks) and libFuzzer in an LLM-assisted analysis pipeline. I reproduced it by hand with the program above.
