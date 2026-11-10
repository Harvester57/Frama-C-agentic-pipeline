/* L5_sanitized, emit/object: the object handed to a sink without a length is initialized. */
struct msg {
    int a;
    int b;
};

void send_msg(const struct msg *m);

void emit(int v)
{
    struct msg m;
    m.a = v;
#ifndef VIOLATE
    m.b = v; /* VIOLATE leaves m.b uninitialized */
#endif
    send_msg(&m);
}
