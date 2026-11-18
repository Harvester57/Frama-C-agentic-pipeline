#ifndef FRAME_H
#define FRAME_H

extern int g;

/*@ requires \valid(p);
    assigns *p;
*/
void on_header(int *p);

/*@ requires \valid(p);
    ensures *p == 1;
*/
void on_header_post_only(int *p);

#endif
