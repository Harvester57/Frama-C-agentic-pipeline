#include <pwd.h>
#include <utmp.h>

int main(void) {
  struct passwd pw, *pw_res1 = 0, *pw_res2 = 0;
  char buf[256];
  int r1 = getpwnam_r("root", &pw, buf, sizeof(buf), &pw_res1);
  if (r1 == 0 && pw_res1 != 0) {
    //@ assert found_nam: pw_res1 == &pw;
  }
  int r2 = getpwuid_r(0, &pw, buf, sizeof(buf), &pw_res2);
  if (r2 == 0 && pw_res2 != 0) {
    //@ assert found_uid: pw_res2 == &pw;
  }

  struct utmp ub, ut_query = {0}, *ut_res1 = 0, *ut_res2 = 0, *ut_res3 = 0;
  if (getutent_r(&ub, &ut_res1) == 0 && ut_res1 == &ub) {
    //@ assert found_utent: \true;
  }
  if (getutid_r(&ut_query, &ub, &ut_res2) == 0 && ut_res2 == &ub) {
    //@ assert found_utid: \true;
  }
  if (getutline_r(&ut_query, &ub, &ut_res3) == 0 && ut_res3 == &ub) {
    //@ assert found_utline: \true;
  }

  return 0;
}
