/* Issue 48: [MetAcsl] -meta-fold drops the location of the folded instances.
 *
 * Two identical \writing properties: auth_folded is folded by -meta-fold,
 * auth_unfolded stays unfolded through \flags(fold:no). Both are violated:
 * "./prog folded" writes auth_ok through hack, "./prog" through bump.
 */
int auth_ok;

void hack(int *p)
{
  *p = 1;
}

void bump(int *p)
{
  *p = 1;
}

int main(int argc, char **argv)
{
  (void)argv;
  if (argc > 1)
    hack(&auth_ok);
  else
    bump(&auth_ok);
  return 0;
}

/*@ meta \prop, \name(auth_folded), \targets({hack}), \context(\writing),
      \separated(\written, &auth_ok);
*/

/*@ meta \prop, \name(auth_unfolded), \targets({bump}), \context(\writing),
      \flags(fold:no),
      \separated(\written, &auth_ok);
*/
