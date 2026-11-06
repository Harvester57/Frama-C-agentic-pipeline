/*  run.config*
    COMMENT: Test private array initialization
    STDOPT: +"-eva-auto-loop-unroll 5"
*/

extern int extern_data[5];

int __fc_private global_key[5] = { 0, 0, 0, 0, 0 };

int main(void) {
    int __fc_private local_key[5] = { 0, 0, 0, 0, 0 };

    for (int i = 0; i < 5; i++) {
        global_key[i] = extern_data[i];
        local_key[i] = extern_data[i];
    }

    /*@ assert security_status(global_key) == public; */
    /*@ assert security_status(local_key) == public; */

    return 0;
}
