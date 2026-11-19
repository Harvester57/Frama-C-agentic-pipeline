/* Issue 45: [MetAcsl] \result is refused in a \postcond property, although the
 * property becomes an ensures clause of the target function.
 *
 *   (default)   the property as one would write it
 *   -DGUARDED   the same predicate under \tguard
 *   -DBY_HAND   the clause written by hand as an ensures of login
 *   -DVIOLATE   login sets the state before its check: the property is false
 */
int auth_ok;

#ifdef BY_HAND
/*@ ensures unchanged_on_failure: \result != 0 ==> auth_ok == \old(auth_ok); */
#endif
int login(int pw)
{
#ifdef VIOLATE
  auth_ok = 1;
#endif
  if (pw != 42)
    return -1;
  auth_ok = 1;
  return 0;
}

#ifndef BY_HAND
#ifndef GUARDED
/*@ meta \prop, \name(unchanged_on_failure), \targets({login}), \context(\postcond),
      \result != 0 ==> auth_ok == \old(auth_ok);
*/
#else
/*@ meta \prop, \name(unchanged_on_failure), \targets({login}), \context(\postcond),
      \tguard(\result != 0 ==> auth_ok == \old(auth_ok));
*/
#endif
#endif
