/*
 * E-ACSL runtime initialization for libFuzzer targets.
 *
 * Linked as-is into every E-ACSL fuzz binary by run_eacsl_fuzz.py and
 * GNUmakefile.template (stage 2, `e-acsl-gcc -C`); it is never instrumented.
 *
 * E-ACSL inserts __e_acsl_memory_init / __e_acsl_globals_init at the top of
 * main(). A libFuzzer target has no main of its own (libFuzzer's main is not
 * instrumented), so the runtime would never be initialized: builds with
 * -e-acsl-full-mtracking then crash in shadow_alloca on every input
 * (E-ACSL manual §3.3.1). libFuzzer calls LLVMFuzzerInitialize once, with its
 * own argc/argv, before running any input. __e_acsl_memory_init runs once
 * even if called again. __e_acsl_globals_init is only generated when the slice
 * has tracked globals, hence the weak reference.
 */
#include <stddef.h>

void __e_acsl_memory_init(int *argc_ref, char ***argv_ref, size_t ptr_size);
void __e_acsl_globals_init(void) __attribute__((weak));

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    __e_acsl_memory_init(argc, argv, sizeof(void *));
    if (__e_acsl_globals_init)
        __e_acsl_globals_init();
    return 0;
}
