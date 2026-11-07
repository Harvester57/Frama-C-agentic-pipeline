#include <check.h>

#include "demo.h"

START_TEST(sum_saturates)
{
    unsigned char b[2] = {200, 100};
    ck_assert_int_eq(demo_sum(b, 2), 255);
}
END_TEST

int main(void)
{
    Suite *s = suite_create("demo");
    TCase *tc = tcase_create("core");
    tcase_add_test(tc, sum_saturates);
    suite_add_tcase(s, tc);
    SRunner *r = srunner_create(s);
    srunner_run_all(r, CK_NORMAL);
    int failed = srunner_ntests_failed(r);
    srunner_free(r);
    return failed != 0;
}
