/*@ requires a > 0; // comment \
    requires b > 0;
    ensures \result == 0;
*/
int g2(int a, int b);

/*@ requires a > 0; // comment \
    requires b > 0
    ;
    ensures \result == 0;
*/
int g3(int a, int b);

/*@ requires a > 0; // comment \
    requires b > 0; //
    ensures \result == 0;
*/
int g4(int a, int b);
