int g;
void ghost_nested(int a)
{
  /*@ ghost int x = a;
      //@ assert nested_in_ghost: x == a;
      x = 0; // plain comment: assert \false;
  */
  g = a;
}
