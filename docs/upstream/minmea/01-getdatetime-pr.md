Fixes #107.

`minmea_getdatetime()` used `date->month` and `date->day` without a range check. `minmea_parse_zda()` accepts any integer for both, so:

- a month of `-2147483648` overflows `date->month - 1` (undefined behaviour, reported by UBSan);
- a month such as `13` or a day such as `99` returned success and reached `timegm()` through `minmea_gettime()`.

## Change

- `minmea.c`: `minmea_getdatetime()` returns `-1` when the month is outside `1..12` or the day outside `1..31`. `minmea_gettime()` inherits the check.
- `minmea.h`: the comment of `minmea_getdatetime()` states when it returns `-1`.
- `tests.c`: `test_minmea_gettime` checks out-of-range months and days (including `INT_MIN` and `INT_MAX`), and a ZDA sentence with month `-2147483648` end to end.

`minmea_parse_zda()` is unchanged: an empty ZDA date field parses to `0`, and rejecting it there would change which sentences parse.

## Behaviour change

A date with month `0` or day `0` (for example from a ZDA sentence with empty date fields and a non-empty year) now makes `minmea_getdatetime()` fail. Before, it was passed on and `timegm()` normalized it to another date.

## Testing

- The new assertions fail on `master` (`tests.c`, `test_minmea_gettime`: `Assertion 'minmea_getdatetime(&tm, &d, &t) != 0' failed`) and pass with the fix.
- `gcc -g -O1 -fsanitize=undefined -fno-sanitize-recover=all -Wall -Wextra`: 38 checks, 0 failures, no new warning.
- `clang -O2`: 38 checks, 0 failures.

Tested on Debian x86-64 only, with a 64-bit `time_t`.

The change and tests were prepared with LLM assistance (Claude Code); I reviewed them and ran the tests above.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
