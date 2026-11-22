/*
 * E-ACSL runtime initialization for libFuzzer targets.
 *
 * Linked as-is into every E-ACSL fuzz binary by run_eacsl_fuzz.py (stage 2,
 * `e-acsl-gcc -C`), which every Make recipe calls; it is never instrumented.
 *
 * E-ACSL inserts __e_acsl_memory_init / __e_acsl_globals_init at the top of
 * main(). A libFuzzer target has no main of its own (libFuzzer's main is not
 * instrumented), so the runtime would never be initialized: builds with
 * -e-acsl-full-mtracking then crash in shadow_alloca on every input
 * (E-ACSL manual §3.3.1).
 *
 * Target code can also run before libFuzzer's main: its constructors
 * (sudo's noexec_ctor, sudo_interposer_init) and libc functions it replaces
 * that a shared library's constructor calls (sudo's getenv, called by
 * libcrypto's OPENSSL_cpuid_setup). Instrumented, that code registers its
 * locals in the shadow memory, which segfaults in shadow_alloca while the
 * runtime is not set up (sudo run-1). So the runtime is set up from the
 * executable's .preinit_array, which the dynamic loader runs before every
 * shared library's constructor and before the executable's own. Preinit
 * functions get (argc, argv, envp) on glibc.
 *
 * LLVMFuzzerInitialize, which libFuzzer calls once before any input, still
 * sets the runtime up when the preinit entry did not run (a loader that does
 * not pass argc/argv, or a link that drops the section); it does nothing
 * once the runtime is ready. __e_acsl_globals_init is only generated when
 * the slice has tracked globals, hence the weak reference.
 */
#include <stddef.h>

void __e_acsl_memory_init(int *argc_ref, char ***argv_ref, size_t ptr_size);
void __e_acsl_globals_init(void) __attribute__((weak));
void *__e_acsl_store_block(void *ptr, size_t size);
void __e_acsl_initialize(void *ptr, size_t size);
extern char **environ;

/*
 * Set once the runtime is initialized. The libc shim (eacsl_errno_shim.c,
 * eacsl_toolchain.EACSL_LIBC_EFFECTS) also wraps calls libFuzzer and the
 * runtime's own initialization make before the shadow memory is mapped; it
 * calls the runtime only once this is set.
 */
int __fc_eacsl_runtime_ready;

/*
 * The runtime registers *argc_ref and *argv_ref as blocks: at preinit they
 * live here, in tracked globals, not in the preinit function's frame.
 */
static int fc_eacsl_argc;
static char **fc_eacsl_argv;

static void fc_eacsl_runtime_init(int *argc, char ***argv)
{
    if (__fc_eacsl_runtime_ready)
        return;
    /* The runtime's argv_alloca advances `environ` to its end while it
     * registers the environment strings; getenv must still see them. The
     * environ_keep shim (-Wl,--wrap=__e_acsl_memory_init) does the same when
     * it is linked. */
    char **fc_env = environ;
    __e_acsl_memory_init(argc, argv, sizeof(void *));
    environ = fc_env;
    /* argv_alloca registers each environment string but not the array of
     * pointers to them, as it does for argv: target code walking `environ`
     * (or `*environ` read through `__environ`) failed \initialized on the
     * first element. The array is registered here, terminating NULL included. */
    if (fc_env) {
        size_t fc_env_count = 0;
        while (fc_env[fc_env_count])
            fc_env_count++;
        __e_acsl_store_block(fc_env, (fc_env_count + 1) * sizeof(char *));
        __e_acsl_initialize(fc_env, (fc_env_count + 1) * sizeof(char *));
    }
    if (__e_acsl_globals_init)
        __e_acsl_globals_init();
    __fc_eacsl_runtime_ready = 1;
}

static void fc_eacsl_preinit(int argc, char **argv, char **envp)
{
    if (argc <= 0 || !argv || !envp)
        return;
    fc_eacsl_argc = argc;
    fc_eacsl_argv = argv;
    /* libc sets `environ` in its own initializer, which runs after the
     * preinit array; the runtime reads the stack's end from it. */
    char **fc_libc_environ = environ;
    if (!environ)
        environ = envp;
    fc_eacsl_runtime_init(&fc_eacsl_argc, &fc_eacsl_argv);
    environ = fc_libc_environ;
}

__attribute__((section(".preinit_array"), used))
static void (*const fc_eacsl_preinit_entry)(int, char **, char **) = fc_eacsl_preinit;

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    fc_eacsl_runtime_init(argc, argv);
    return 0;
}

/*
 * Frama-C 33.0 E-ACSL runtime lacks __e_acsl_pthread_create when concurrency tracking is enabled.
 * Provide a self-contained weak alias forwarding to pthread_create if available without <pthread.h>.
 */
int pthread_create(void *thread, const void *attr, void *(*start_routine)(void *), void *arg) __attribute__((weak));

__attribute__((weak))
int __e_acsl_pthread_create(void *thread, const void *attr, void *(*start_routine)(void *), void *arg)
{
    if (pthread_create)
        return pthread_create(thread, attr, start_routine, arg);
    return -1;
}

