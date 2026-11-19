/* Hand-written meta file for local_init.c: the templates of templates/metacsl/ with their
 * placeholders filled in, plus a \strong_invariant. It pins what MetAcsl itself does at a call in
 * an initializer (tests/test_security_props.py, test_metacsl_skips_calls_in_initializers_in_the_image),
 * independently of what scripts/security_props.py generates.
 */
/*@ meta \prop, \name(L5_sanitized_net_send), \targets(\ALL), \context(\calling),
      \tguard(\called == net_send ==> (\fguard(\initialized(\called_arg(buf) + (0 .. \called_arg(n) - 1)))));
*/
/*@ meta \prop, \name(L6_no_leak_key), \targets(\ALL), \context(\calling),
      \tguard(\called == net_send ==> \fguard(\separated(\called_arg(buf), &key)));
*/
/*@ meta \prop, \name(L4_auth_state_login), \targets(\diff(\ALL, {login})), \context(\writing),
      \separated(\written, &auth_ok);
*/
/*@ meta \prop, \name(L6_no_leak_read_key), \targets(\ALL), \context(\reading),
      \separated(\read, &key);
*/
/*@ meta \prop, \name(L4_invariant_auth_range), \targets(\diff(\ALL, {login})), \context(\strong_invariant),
      0 <= auth_ok <= 1;
*/
