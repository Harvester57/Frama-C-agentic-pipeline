/*
 * L5_sanitized, entry/object_formal: a sink without a length that the target defines and calls
 * through a function pointer. The property is the sink's precondition, which WP proves at the call.
 */
struct msg {
    int a;
    int b;
};

static int sent;

/*@ assigns sent; */
void send_msg(const struct msg *m)
{
    sent = m->a;
}

static void (*transmit)(const struct msg *) = send_msg;

/*@ requires transmit == &send_msg; */
void emit(int v)
{
    struct msg m;
    m.a = v;
#ifndef VIOLATE
    m.b = v; /* VIOLATE leaves m.b uninitialized */
#endif
    /*@ calls send_msg; */
    transmit(&m);
}
