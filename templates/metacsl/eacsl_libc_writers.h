/* E-ACSL build only: the libc writers' assigns, from Frama-C's libc (share/libc/string.h).
 * e-acsl-gcc parses with the host headers (-no-frama-c-stdlib), where these functions have no
 * contract, and MetAcsl assumes a callee without one respects every \writing and \reading property:
 * a write through memcpy into a protected object went unchecked. scripts/fuzz_build.py appends this
 * text to the module's meta file after its last property (eacsl_toolchain.eacsl_meta_libc_text), so
 * the stage that runs MetAcsl sees the contracts; WP and Eva parse with Frama-C's libc and have them.
 * The formals keep glibc's names (__dest, __src, __n, __s, __c): MetAcsl instantiates the callee's
 * assigns at the call with the formals of the first declaration it meets, glibc's, and a contract
 * written with other names leaves those names in the generated check ("use of undeclared
 * identifier '__dest'" when clang compiles it).
 * Only what was checked in the image: strcpy's strlen-bounded assigns abort E-ACSL ("invalid label
 * 'Old' within statement annotation"), so strcpy, strcat and the other writers stay unchecked and
 * the build lists the calls it finds (security_props.libc_unchecked). Keep EACSL_META_LIBC_WRITERS
 * in scripts/eacsl_toolchain.py equal to the functions declared here. */
#include <string.h>
/*@ assigns ((char*)__dest)[0..__n - 1] \from ((char*)__src)[0..__n-1];
    assigns \result \from __dest; */
extern void *memcpy(void *restrict __dest, const void *restrict __src, size_t __n);
/*@ assigns ((char*)__dest)[0..__n - 1] \from ((char*)__src)[0..__n-1];
    assigns \result \from __dest; */
extern void *memmove(void *__dest, const void *__src, size_t __n);
/*@ assigns ((char*)__s)[0..__n - 1] \from __c;
    assigns \result \from __s; */
extern void *memset(void *__s, int __c, size_t __n);
/*@ assigns __dest[0..__n - 1] \from __src[0..__n-1];
    assigns \result \from __dest; */
extern char *strncpy(char *restrict __dest, const char *restrict __src, size_t __n);
