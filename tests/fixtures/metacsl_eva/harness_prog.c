/* Eva harness of the metacsl_eva fixture: eva_main drives prog.c from unknown inputs.
 * -DHARNESS_DIRECT calls the protected function before the gate: a violation the harness induces. */
#include "__fc_builtin.h"
#include "prog.h"

/*@ assigns \nothing; */
void send_bytes(const unsigned char *buf, size_t n);

void eva_main(void)
{
#ifdef HARNESS_DIRECT
    admin(1);
#endif
    handle(Frama_C_interval(0, 100), Frama_C_interval(0, 1000));
    emit((unsigned char)Frama_C_interval(0, 255));
#ifdef VIOLATE
    backdoor();
#endif
}
