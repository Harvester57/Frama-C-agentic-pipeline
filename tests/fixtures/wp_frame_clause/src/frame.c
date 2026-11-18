/* Shapes of a function contract with and without a frame (tests/test_wp_frame_clause.py). */
#include "frame.h"

int g;

/*@ assigns \nothing; */
int pure_ok(int x)
{
    return x;
}

/*@ requires \valid(p);
    assigns \nothing;
*/
void pure_broken(int *p)
{
    *p = 1;
}

/*@ requires \valid(p);
    ensures *p == 1;
*/
void post_only(int *p)
{
    *p = 1;
}

int bare(int x)
{
    return x;
}

void on_header(int *p)
{
    *p = 1;
}

void on_header_post_only(int *p)
{
    *p = 1;
}

/*@ behavior pos:
      assumes x > 0;
      assigns g;
      ensures g == x;
    behavior neg:
      assumes x <= 0;
      assigns \nothing;
    complete behaviors;
    disjoint behaviors;
*/
void guarded_all(int x)
{
    if (x > 0)
        g = x;
}

/*@ behavior pos:
      assumes x > 0;
      assigns g;
      ensures g == x;
*/
void guarded_some(int x)
{
    if (x > 0)
        g = x;
    else
        g = 0;
}

/*@ behavior pos:
      assumes x > 0;
      assigns g;
      ensures g == x;
    behavior neg:
      assumes x <= 0;
      ensures g == 0;
    complete behaviors;
    disjoint behaviors;
*/
void guarded_gap(int x)
{
    if (x > 0)
        g = x;
    else
        g = 0;
}

/*@ requires \valid(p);
    assigns *p;
    ensures *p == 1;
*/
void calls_post_only(int *p)
{
    post_only(p);
}
