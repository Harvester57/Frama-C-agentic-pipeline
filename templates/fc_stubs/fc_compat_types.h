/*
 * Frama-C Compatibility Primitive Types (force-included by the pipeline)
 *
 * This header is a Frama-C parse aid only. It contains typedefs, includes,
 * keyword-spelling macros, contracted declarations and (E-ACSL branch only) weak definitions of __fc_libc's
 * model objects, never C function bodies, and it is EMPTY whenever __FRAMAC__ is undefined
 * (Clang compile of the self-contained E-ACSL output, sanitizer builds), so it
 * can never redefine types in code that already contains them.
 *
 *   __FRAMAC__ && __FRAMAC_EACSL__  (E-ACSL host-header mode, -no-frama-c-stdlib)
 *       Include host glibc <sys/types.h>: glibc itself is the only source of
 *       __int32_t, u_short, etc., so every alias is identical by construction.
 *
 *   __FRAMAC__ && !__FRAMAC_EACSL__ (Eva / WP with Frama-C's __fc_libc, -nostdinc)
 *       __fc_libc lacks the glibc-internal aliases (__int8_t .. __uint64_t) and
 *       some BSD aliases. Derive them from the compiler-predefined
 *       __INTn_TYPE__ / __UINTn_TYPE__ macros when available, which match the
 *       machdep ABI exactly (e.g. __int64_t is `long` on LP64), otherwise from
 *       <stdint.h>. Identical re-typedefs are valid C11.
 */

#ifndef FRAMAC_COMPAT_TYPES_H
#define FRAMAC_COMPAT_TYPES_H

#if defined(__FRAMAC__)

/* Machdep (plan step S9). The ioctl encoding, the x86_64 numbers of the typed syscall rewrites and the
 * `long` literals of the abs/labs contracts below assume x86_64 LP64. Another machdep stops here, at
 * parse time, instead of giving results computed on the wrong sizes. */
_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
               "fc_compat_types.h assumes an LP64 machdep (x86_64): run Frama-C with -machdep x86_64");

/* `offsetof` stays the libc's `__builtin_offsetof`, which the kernel folds to a constant. A
 * non-constant array index (`offsetof(T, m[i])`) is repaired in the preprocessed output by
 * scripts/fc_cpp_wrapper.py. Never redefine `offsetof` here: the null-pointer form
 * `&((T *)0)->m` is an invalid pointer for Eva (-warn-invalid-pointer) and no longer a constant. */

#ifndef _Float32
#define _Float32 float
#endif
#ifndef _Float64
#define _Float64 double
#endif
#ifndef _Float32x
#define _Float32x double
#endif
#ifndef _Float64x
#define _Float64x double
#endif
#ifndef _Float128
#define _Float128 double
#endif

/* Checked-arithmetic builtins (mpack run-3, 2026-11-17). Which ones Frama-C knows depends on the libc:
 * - Frama-C's own libc (Eva, WP, Phase 0) on a GCC machdep: the generated __fc_machdep.h includes
 *   FRAMAC_SHARE/libc/__fc_gcc_builtins.h, which declares the typed forms (__builtin_sadd_overflow ...
 *   __builtin_umulll_overflow) with contracts and defines the three generic forms as `_Generic` macros.
 *   They must not be redefined here: this header is force-included before that one, so a macro for a
 *   typed form expands inside its declaration and the parse fails (`__fc_gcc_builtins.h:37: syntax
 *   error`). Only the `_p` forms are missing there.
 * - The E-ACSL frontend (host glibc headers, -no-frama-c-stdlib): none of them. Frama-C calls each as
 *   an undeclared function with a prototype guessed from the first call, and prints that prototype into
 *   the instrumented C, which clang refuses ("cannot redeclare builtin function").
 * So the E-ACSL frontend gets all of them below, and both modes get the `_p` forms. Targets enable them
 * under `__has_builtin` or a GCC version test. They are GNU statement expressions with GCC's semantics: the operands' mathematical result, wrapped to
 * the type of `*res`, is stored, and the value is 1 when it does not fit. Each operand and `res` is
 * evaluated once, and no step wraps or converts out of range (no alarm under -warn-signed-downcast,
 * -warn-unsigned-overflow or -warn-unsigned-downcast at the target's line): 64-bit sums and products
 * are taken in 32-bit halves. LP64 (asserted above): operands and results are at most 64 bits wide.
 * WP proves the expansion's RTE goals with Alt-Ergo, Z3 and CVC5 together (Alt-Ergo alone leaves a few
 * products of halves). Not covered: a `_p` form whose third argument is a bit-field (`__typeof__` rejects
 * it) or is const-qualified. */
#ifndef __FC_OVF
#ifdef __CHAR_UNSIGNED__
#define __FC_OVF_CHAR_SIGNED 0
#else
#define __FC_OVF_CHAR_SIGNED 1
#endif
#define __FC_OVF_SIGNED(v) \
  _Generic((v), signed char: 1, short: 1, int: 1, long: 1, long long: 1, char: __FC_OVF_CHAR_SIGNED, default: 0)
/* 2^32. Halves are taken with `%` and `/` rather than masks and shifts, which WP's provers handle
 * poorly; the values are the same. */
#define __FC_OVF_K 4294967296ull
/* |x| as unsigned long long, without converting a negative value. */
#define __FC_OVF_MAG(x) ((x) < 0 ? (unsigned long long)(-((x) + 1)) + 1ull : (unsigned long long)(x))
/* (x - y) mod 2^64 for x >= y, in 32-bit halves: x + (2^64 - 1 - y) + 1, every partial sum below 2^34. */
#define __FC_OVF_DIFF(x, y, out)                                                                  \
  {                                                                                               \
    unsigned long long __fc_ovf_dl = (x) % __FC_OVF_K + (__FC_OVF_K - 1ull - (y) % __FC_OVF_K) + 1ull; \
    unsigned long long __fc_ovf_dh = (x) / __FC_OVF_K + (__FC_OVF_K - 1ull - (y) / __FC_OVF_K)    \
                                     + __fc_ovf_dl / __FC_OVF_K;                                  \
    (out) = __fc_ovf_dh % __FC_OVF_K * __FC_OVF_K + __fc_ovf_dl % __FC_OVF_K;                     \
  }
#define __FC_OVF(op, a, b, rp)                                                                    \
  ({                                                                                              \
    __typeof__((a) + 0) __fc_ovf_a = (a);                                                         \
    __typeof__((b) + 0) __fc_ovf_b = (b);                                                         \
    __typeof__(rp) __fc_ovf_r = (rp);                                                             \
    int __fc_ovf_na = __fc_ovf_a < 0;                                                             \
    int __fc_ovf_nb = __fc_ovf_b < 0;                                                             \
    unsigned long long __fc_ovf_ma = __FC_OVF_MAG(__fc_ovf_a);                                    \
    unsigned long long __fc_ovf_mb = __FC_OVF_MAG(__fc_ovf_b);                                    \
    unsigned long long __fc_ovf_m;                                                                \
    unsigned long long __fc_ovf_lo;                                                               \
    unsigned long long __fc_ovf_hi;                                                               \
    int __fc_ovf_neg;                                                                             \
    int __fc_ovf_big;                                                                             \
    if ((op) == 2) {                                                                              \
      __fc_ovf_neg = __fc_ovf_na != __fc_ovf_nb && __fc_ovf_ma != 0 && __fc_ovf_mb != 0;          \
      __fc_ovf_big = __fc_ovf_ma != 0 && __fc_ovf_mb > ~0ull / __fc_ovf_ma;                       \
      __fc_ovf_lo = __fc_ovf_ma % __FC_OVF_K * (__fc_ovf_mb % __FC_OVF_K);                        \
      __fc_ovf_hi = __fc_ovf_lo / __FC_OVF_K                                                      \
                    + (__fc_ovf_ma / __FC_OVF_K * (__fc_ovf_mb % __FC_OVF_K) % __FC_OVF_K         \
                       + __fc_ovf_ma % __FC_OVF_K * (__fc_ovf_mb / __FC_OVF_K) % __FC_OVF_K)      \
                          % __FC_OVF_K;                                                           \
      __fc_ovf_m = __fc_ovf_hi % __FC_OVF_K * __FC_OVF_K + __fc_ovf_lo % __FC_OVF_K;              \
    } else {                                                                                      \
      if ((op) == 1)                                                                              \
        __fc_ovf_nb = !__fc_ovf_nb && __fc_ovf_mb != 0;                                           \
      if (__fc_ovf_na == __fc_ovf_nb) {                                                           \
        __fc_ovf_neg = __fc_ovf_na;                                                               \
        __fc_ovf_lo = __fc_ovf_ma % __FC_OVF_K + __fc_ovf_mb % __FC_OVF_K;                        \
        __fc_ovf_hi = __fc_ovf_ma / __FC_OVF_K + __fc_ovf_mb / __FC_OVF_K + __fc_ovf_lo / __FC_OVF_K; \
        __fc_ovf_big = __fc_ovf_hi >= __FC_OVF_K;                                                 \
        __fc_ovf_m = __fc_ovf_hi % __FC_OVF_K * __FC_OVF_K + __fc_ovf_lo % __FC_OVF_K;            \
      } else if (__fc_ovf_ma >= __fc_ovf_mb) {                                                    \
        __fc_ovf_neg = __fc_ovf_na && __fc_ovf_ma != __fc_ovf_mb;                                 \
        __fc_ovf_big = 0;                                                                         \
        __FC_OVF_DIFF(__fc_ovf_ma, __fc_ovf_mb, __fc_ovf_m)                                       \
      } else {                                                                                    \
        __fc_ovf_neg = __fc_ovf_nb;                                                               \
        __fc_ovf_big = 0;                                                                         \
        __FC_OVF_DIFF(__fc_ovf_mb, __fc_ovf_ma, __fc_ovf_m)                                       \
      }                                                                                           \
    }                                                                                             \
    int __fc_ovf_s = __FC_OVF_SIGNED(*__fc_ovf_r);                                                \
    unsigned long long __fc_ovf_umax = sizeof(*__fc_ovf_r) == 1   ? 0xffull                       \
                                       : sizeof(*__fc_ovf_r) == 2 ? 0xffffull                     \
                                       : sizeof(*__fc_ovf_r) == 4 ? 0xffffffffull                 \
                                                                  : 0xffffffffffffffffull;        \
    unsigned long long __fc_ovf_max = __fc_ovf_s ? __fc_ovf_umax / 2ull : __fc_ovf_umax;          \
    int __fc_ovf_fits = !__fc_ovf_big                                                             \
                        && (__fc_ovf_neg ? __fc_ovf_m <= (__fc_ovf_s ? __fc_ovf_max + 1ull : 0ull) \
                                         : __fc_ovf_m <= __fc_ovf_max);                           \
    unsigned long long __fc_ovf_w =                                                               \
        __fc_ovf_neg && __fc_ovf_m != 0 ? 0xffffffffffffffffull - __fc_ovf_m + 1ull : __fc_ovf_m; \
    if (__fc_ovf_umax != 0xffffffffffffffffull)                                                   \
      __fc_ovf_w = __fc_ovf_w % (__fc_ovf_umax + 1ull);                                           \
    if (__fc_ovf_s && __fc_ovf_w > __fc_ovf_max)                                                  \
      *__fc_ovf_r = -(__typeof__(*__fc_ovf_r))(__fc_ovf_umax - __fc_ovf_w) - 1;                   \
    else                                                                                          \
      *__fc_ovf_r = (__typeof__(*__fc_ovf_r))__fc_ovf_w;                                          \
    !__fc_ovf_fits;                                                                               \
  })
#define __FC_OVF_P(op, a, b, c)                                                                   \
  ({                                                                                              \
    __typeof__(c) __fc_ovf_pv;                                                                    \
    __FC_OVF(op, a, b, &__fc_ovf_pv);                                                             \
  })
#define __builtin_add_overflow_p(a, b, c) __FC_OVF_P(0, a, b, c)
#define __builtin_sub_overflow_p(a, b, c) __FC_OVF_P(1, a, b, c)
#define __builtin_mul_overflow_p(a, b, c) __FC_OVF_P(2, a, b, c)
#if defined(__FRAMAC_EACSL__)
#define __builtin_add_overflow(a, b, res) __FC_OVF(0, a, b, res)
#define __builtin_sub_overflow(a, b, res) __FC_OVF(1, a, b, res)
#define __builtin_mul_overflow(a, b, res) __FC_OVF(2, a, b, res)
/* The typed forms convert their operands to the parameter type first, as a call would. */
#define __builtin_sadd_overflow(a, b, res) __FC_OVF(0, (int)(a), (int)(b), res)
#define __builtin_saddl_overflow(a, b, res) __FC_OVF(0, (long)(a), (long)(b), res)
#define __builtin_saddll_overflow(a, b, res) __FC_OVF(0, (long long)(a), (long long)(b), res)
#define __builtin_uadd_overflow(a, b, res) __FC_OVF(0, (unsigned)(a), (unsigned)(b), res)
#define __builtin_uaddl_overflow(a, b, res) __FC_OVF(0, (unsigned long)(a), (unsigned long)(b), res)
#define __builtin_uaddll_overflow(a, b, res) __FC_OVF(0, (unsigned long long)(a), (unsigned long long)(b), res)
#define __builtin_ssub_overflow(a, b, res) __FC_OVF(1, (int)(a), (int)(b), res)
#define __builtin_ssubl_overflow(a, b, res) __FC_OVF(1, (long)(a), (long)(b), res)
#define __builtin_ssubll_overflow(a, b, res) __FC_OVF(1, (long long)(a), (long long)(b), res)
#define __builtin_usub_overflow(a, b, res) __FC_OVF(1, (unsigned)(a), (unsigned)(b), res)
#define __builtin_usubl_overflow(a, b, res) __FC_OVF(1, (unsigned long)(a), (unsigned long)(b), res)
#define __builtin_usubll_overflow(a, b, res) __FC_OVF(1, (unsigned long long)(a), (unsigned long long)(b), res)
#define __builtin_smul_overflow(a, b, res) __FC_OVF(2, (int)(a), (int)(b), res)
#define __builtin_smull_overflow(a, b, res) __FC_OVF(2, (long)(a), (long)(b), res)
#define __builtin_smulll_overflow(a, b, res) __FC_OVF(2, (long long)(a), (long long)(b), res)
#define __builtin_umul_overflow(a, b, res) __FC_OVF(2, (unsigned)(a), (unsigned)(b), res)
#define __builtin_umull_overflow(a, b, res) __FC_OVF(2, (unsigned long)(a), (unsigned long)(b), res)
#define __builtin_umulll_overflow(a, b, res) __FC_OVF(2, (unsigned long long)(a), (unsigned long long)(b), res)
#endif /* __FRAMAC_EACSL__ */
#endif /* __FC_OVF */

#if defined(__FRAMAC_EACSL__)

/* GCC's `__restrict__` spelling (mpack's MPACK_RESTRICT under __GNUC__). Frama-C's parser knows
 * `restrict` and `__restrict` only; its own libc maps the GCC spelling (share/libc/features.h), but
 * the E-ACSL frontend parses with host glibc headers (-no-frama-c-stdlib), which do not. Ahead of
 * every include so a host header spelling it parses too. */
#ifndef __restrict__
#define __restrict__ __restrict
#endif

#include <stdint.h>
#include <sys/types.h>

/*@ requires abs_representable: j > (-2147483647 - 1);
  @ assigns \nothing;
  @*/
int abs(int j);

/*@ requires abs_representable: j > (-9223372036854775807L - 1L);
  @ assigns \nothing;
  @*/
long int labs(long int j);

/*@ requires abs_representable: j > (-9223372036854775807LL - 1LL);
  @ assigns \nothing;
  @*/
long long int llabs(long long int j);

/* The model objects of __fc_libc's descriptor, socket and termios contracts (libmodbus run-1,
 * 2026-11-18). WP proves `assigns __fc_sockfds[s]` on a caller of setsockopt, `assigns __fc_fds[fd]`
 * on a caller of close, `assigns Frama_C_entropy_source` on a caller of tcflush, because those are what
 * the libc contracts assign. Host glibc declares none of them, so the same contract stopped the E-ACSL
 * build with "unbound logic variable __fc_sockfds". Same names, types and sizes as __fc_libc
 * (__fc_builtin.h, __fc_define_fds.h, __fc_define_max_open_files.h, sys/socket.h, __fc_select.h).
 * E-ACSL does not check `assigns` / `\from`: the names only have to resolve. They are weak C definitions,
 * not `extern` declarations nor ghosts: full memory tracking registers every global the instrumented file
 * declares (`__e_acsl_store_block(&__fc_fds, ...)`), so an `extern` failed the link with "undefined
 * reference to `__fc_fds'", and a ghost would be printed as a comment, so a clause E-ACSL does execute
 * (`assumes Frama_C_entropy_source != 0`) would not compile. Weak, so a second definition (another
 * translation unit, a target defining one) links. Clang compiles without __FRAMAC__ never see them.
 * Only `assigns` / `\from` uses mean anything: glibc never writes these objects, so a clause E-ACSL executes
 * reads a zero that has nothing to do with WP's model (`Frama_C_entropy_source` is always 0). */
#ifndef __FC_MAX_OPEN_FILES
#define __FC_MAX_OPEN_FILES 1024
#endif
#ifndef __FC_MAX_OPEN_SOCKETS
#define __FC_MAX_OPEN_SOCKETS 1024
#endif
struct __fc_sockfds_type {
  int x;
};
volatile int Frama_C_entropy_source __attribute__((weak));
volatile int __fc_fds[__FC_MAX_OPEN_FILES] __attribute__((weak));
struct __fc_sockfds_type __fc_sockfds[__FC_MAX_OPEN_SOCKETS] __attribute__((weak));
int __fc_socket_counter __attribute__((weak));
volatile int __fc_fds_state __attribute__((weak));

#else /* Frama-C __fc_libc */

#include <stdint.h>
#include <sys/types.h>

/* Linux and glibc declarations __fc_libc lacks (found on libseccomp). E-ACSL builds take them from
 * glibc itself, so they live in this branch only. */

/* glibc <unistd.h>: `syscall`. The contract only says what ACSL can say about a variadic call: the
 * result depends on the number. It cannot state what the call writes through its arguments, so
 * Eva and WP assume a syscall writes no memory; buffers it fills stay as the caller left them. */
/*@ assigns \result \from number; */
long syscall(long number, ...);

/* Typed syscalls (plan step S6). scripts/fc_cpp_wrapper.py rewrites `syscall(<x86_64 number>, ...)` into
 * `__fc_syscall_<name>(...)` for the numbers below, which write memory, when this branch declares them.
 * Arguments as the kernel takes them; pointers are `void *` so any argument type converts as it does for
 * `syscall` (except `addrlen`, a socklen_t). The result is that of glibc's `syscall()`: -1 on error (errno is not modelled).
 * The unnamed postconditions hold on every call and are what WP uses: the first \result bytes are
 * initialized. Eva does not treat an `assigns` range as initialized and does not reduce that range on a
 * later test of the count, so, as in __fc_libc's read(), Frama_C_entropy_source splits a full transfer
 * (\result is the length) from a short one or an error; WP learns nothing from that volatile split.
 * No <sys/socket.h> here: the getsockopt block below must be the first to include it. No `\old` in an
 * `assigns`: WP 35 with -wp-check-memory-model crashed on `\old(*(unsigned int *)addrlen)` there
 * (Wp__NormAtLabels.LabelError). */
#include "__fc_builtin.h"

/* read(2), x86_64 number 0. */
/*@ requires buf_has_room: \valid((char *)buf + (0 .. count - 1));
  @ assigns \result, ((char *)buf)[0 .. count - 1]
  @   \from indirect:fd, indirect:count, indirect:Frama_C_entropy_source;
  @ ensures result_error_or_read_length: -1 <= \result <= count;
  @ ensures initialization: \initialized((char *)buf + (0 .. \result - 1));
  @ behavior full_read:
  @   assumes nondet_full: Frama_C_entropy_source != 0 && count <= 9223372036854775807;
  @   ensures result_full: \result == count;
  @ behavior partial_or_error:
  @   assumes nondet_partial: !(Frama_C_entropy_source != 0 && count <= 9223372036854775807);
  @   ensures result_short: \result < count;
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
long __fc_syscall_read(int fd, void *buf, size_t count);

/* recvfrom(2), x86_64 number 45. `addrlen` is a socklen_t, `unsigned int` on Linux. */
/*@ requires valid_buffer_length: \valid((char *)buf + (0 .. len - 1));
  @ requires valid_addrbuf_or_null:
  @   src_addr == \null
  @   || (\valid(addrlen) && \initialized(addrlen)
  @       && \valid((char *)src_addr + (0 .. *addrlen - 1)));
  @ assigns \result, ((char *)buf)[0 .. len - 1]
  @   \from indirect:sockfd, indirect:len, indirect:flags, indirect:Frama_C_entropy_source;
  @ assigns *addrlen \from indirect:sockfd, indirect:src_addr;
  @ assigns ((char *)src_addr)[0 .. *addrlen - 1] \from indirect:sockfd;
  @ ensures result_error_or_received_length: -1 <= \result <= len;
  @ ensures initialization:buf: \initialized((char *)buf + (0 .. \result - 1));
  @ ensures initialization:addrbuf:
  @   src_addr != \null ==> \initialized((char *)src_addr + (0 .. \old(*addrlen) - 1));
  @ behavior full_receive:
  @   assumes nondet_full: Frama_C_entropy_source != 0 && len <= 9223372036854775807;
  @   ensures result_full: \result == len;
  @ behavior partial_or_error:
  @   assumes nondet_partial: !(Frama_C_entropy_source != 0 && len <= 9223372036854775807);
  @   ensures result_short: \result < len;
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
long __fc_syscall_recvfrom(int sockfd, void *buf, size_t len, int flags, void *src_addr, unsigned int *addrlen);

/* getrandom(2), x86_64 number 318. Up to 256 bytes on an initialized pool fill the buffer, but a blocked call
 * can still fail (EINTR, EAGAIN with GRND_NONBLOCK, ENOSYS): the error branch stays reachable. */
/*@ requires valid_buf: \valid((char *)buf + (0 .. buflen - 1));
  @ assigns \result, ((char *)buf)[0 .. buflen - 1]
  @   \from indirect:buflen, indirect:flags, indirect:Frama_C_entropy_source;
  @ ensures result_error_or_length: -1 <= \result <= buflen;
  @ ensures initialization: \initialized((char *)buf + (0 .. \result - 1));
  @ behavior full:
  @   assumes nondet_full: Frama_C_entropy_source != 0 && buflen <= 9223372036854775807;
  @   ensures result_full: \result == buflen;
  @ behavior partial_or_error:
  @   assumes nondet_partial: !(Frama_C_entropy_source != 0 && buflen <= 9223372036854775807);
  @   ensures result_short: \result < buflen;
  @ complete behaviors;
  @ disjoint behaviors;
  @*/
long __fc_syscall_getrandom(void *buf, size_t buflen, unsigned int flags);

/* Wipes (plan step M6): explicit_bzero (glibc <string.h> since 2.25, the BSDs) and memset_s (C11 Annex K),
 * which __fc_libc lacks. The postconditions state the written range element by element, so a wipe
 * through them proves an L6 "wiped" property without a loop. Twice: through `char`, which WP Typed proves
 * for a `char` buffer (Typed reads `void *` as `char *`), and through `unsigned char`, which proves an
 * `unsigned char` / `uint8_t` buffer only under Typed+cast (Typed rejects the buffer's conversion to
 * `void *` at the call). `\subset` is the form Eva reduces. A target that defines its own explicit_bzero
 * or memset_s gets these contracts on its definition; define FC_STUBS_NO_WIPE_DECLS to drop them. */
#ifndef FC_STUBS_NO_WIPE_DECLS
/*@ requires valid_s: \valid((char *)s + (0 .. n - 1));
  @ assigns ((char *)s)[0 .. n - 1] \from \nothing;
  @ ensures zeroed: \forall integer k; 0 <= k < n ==> ((char *)s)[k] == 0;
  @ ensures zeroed_bytes: \forall integer k; 0 <= k < n ==> ((unsigned char *)s)[k] == 0;
  @ ensures zeroed_values: \subset(((char *)s)[0 .. n - 1], {0});
  @ ensures initialization: \initialized((char *)s + (0 .. n - 1));
  @*/
void explicit_bzero(void *s, size_t n);

/* errno_t and rsize_t are `int` and `size_t` (Annex K); the call sets min(n, smax) bytes and fails when
 * n > smax. */
/*@ requires valid_s: \valid((char *)s + (0 .. smax - 1));
  @ assigns ((char *)s)[0 .. (n <= smax ? n : smax) - 1] \from c, indirect:n, indirect:smax;
  @ assigns \result \from indirect:n, indirect:smax;
  @ ensures set: \forall integer k; 0 <= k < (n <= smax ? n : smax) ==> ((char *)s)[k] == (char)c;
  @ ensures set_bytes:
  @   \forall integer k; 0 <= k < (n <= smax ? n : smax) ==> ((unsigned char *)s)[k] == (unsigned char)c;
  @ ensures set_values: \subset(((char *)s)[0 .. (n <= smax ? n : smax) - 1], {(char)c});
  @ ensures initialization: \initialized((char *)s + (0 .. (n <= smax ? n : smax) - 1));
  @ ensures result: n <= smax ? \result == 0 : \result != 0;
  @*/
int memset_s(void *s, size_t smax, int c, size_t n);
#endif /* FC_STUBS_NO_WIPE_DECLS */

/* Linux <asm-generic/ioctl.h>: the ioctl request encoding (`_IOWR(magic, nr, struct foo)`), which
 * glibc's <sys/ioctl.h> provides and __fc_libc's does not. Without it the struct-type argument is a
 * syntax error. Values are those of x86_64 (and every architecture using the generic layout). */
#ifndef _IOC
#define _IOC_NRBITS 8
#define _IOC_TYPEBITS 8
#define _IOC_SIZEBITS 14
#define _IOC_DIRBITS 2
#define _IOC_NRSHIFT 0
#define _IOC_TYPESHIFT (_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT (_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT (_IOC_SIZESHIFT + _IOC_SIZEBITS)
#define _IOC_NONE 0U
#define _IOC_WRITE 1U
#define _IOC_READ 2U
#define _IOC(dir, type, nr, size) \
  (((dir) << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) | ((nr) << _IOC_NRSHIFT) | ((size) << _IOC_SIZESHIFT))
#define _IOC_TYPECHECK(t) (sizeof(t))
#define _IO(type, nr) _IOC(_IOC_NONE, (type), (nr), 0)
#define _IOR(type, nr, size) _IOC(_IOC_READ, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOW(type, nr, size) _IOC(_IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOWR(type, nr, size) _IOC(_IOC_READ | _IOC_WRITE, (type), (nr), (_IOC_TYPECHECK(size)))
#define _IOC_DIR(nr) (((nr) >> _IOC_DIRSHIFT) & ((1 << _IOC_DIRBITS) - 1))
#define _IOC_TYPE(nr) (((nr) >> _IOC_TYPESHIFT) & ((1 << _IOC_TYPEBITS) - 1))
#define _IOC_NR(nr) (((nr) >> _IOC_NRSHIFT) & ((1 << _IOC_NRBITS) - 1))
#define _IOC_SIZE(nr) (((nr) >> _IOC_SIZESHIFT) & ((1 << _IOC_SIZEBITS) - 1))
#endif

/* The modem-line bits of TIOCMGET / TIOCMBIS / TIOCMBIC / TIOCMSET: glibc's <sys/ioctl.h> defines
 * TIOCM_LE to TIOCM_RI in <bits/ioctl-types.h>, Linux <asm-generic/termios.h> all of them (with
 * TIOCM_OUT1, TIOCM_OUT2, TIOCM_LOOP), same values and spelling. __fc_libc's <sys/ioctl.h> defines
 * the four requests but none of the bits, so `flags |= TIOCM_RTS` is "Cannot resolve variable
 * TIOCM_RTS" (found on libmodbus, src/modbus-rtu.c). */
#ifndef TIOCM_LE
#define TIOCM_LE 0x001
#endif
#ifndef TIOCM_DTR
#define TIOCM_DTR 0x002
#endif
#ifndef TIOCM_RTS
#define TIOCM_RTS 0x004
#endif
#ifndef TIOCM_ST
#define TIOCM_ST 0x008
#endif
#ifndef TIOCM_SR
#define TIOCM_SR 0x010
#endif
#ifndef TIOCM_CTS
#define TIOCM_CTS 0x020
#endif
#ifndef TIOCM_CAR
#define TIOCM_CAR 0x040
#endif
#ifndef TIOCM_RNG
#define TIOCM_RNG 0x080
#endif
#ifndef TIOCM_DSR
#define TIOCM_DSR 0x100
#endif
#ifndef TIOCM_CD
#define TIOCM_CD TIOCM_CAR
#endif
#ifndef TIOCM_RI
#define TIOCM_RI TIOCM_RNG
#endif
#ifndef TIOCM_OUT1
#define TIOCM_OUT1 0x2000
#endif
#ifndef TIOCM_OUT2
#define TIOCM_OUT2 0x4000
#endif
#ifndef TIOCM_LOOP
#define TIOCM_LOOP 0x8000
#endif

/* Linux <asm-generic/ioctls.h> (glibc's <sys/ioctl.h> -> <bits/ioctls.h> -> <asm/ioctls.h>): the
 * termios2 requests, for a custom baud rate (`c_cflag |= BOTHER`). __fc_libc's <sys/ioctl.h> stops at
 * TCGETS / TCSETS, so with HAVE_STRUCT_TERMIOS2 libmodbus's src/modbus-rtu.c stops at "Cannot resolve
 * variable TCGETS2". `struct termios2` and BOTHER come from <asm/termbits.h>, which the target
 * includes itself (found through -idirafter). */
#ifndef TCGETS2
#define TCGETS2 _IOR('T', 0x2A, struct termios2)
#endif
#ifndef TCSETS2
#define TCSETS2 _IOW('T', 0x2B, struct termios2)
#endif
#ifndef TCSETSW2
#define TCSETSW2 _IOW('T', 0x2C, struct termios2)
#endif
#ifndef TCSETSF2
#define TCSETSF2 _IOW('T', 0x2D, struct termios2)
#endif

#ifndef __FC_COMPAT_INT_TYPES_DEFINED
#define __FC_COMPAT_INT_TYPES_DEFINED 1
#ifndef __GLIBC_INTERNAL_INT_TYPES_DEFINED
#define __GLIBC_INTERNAL_INT_TYPES_DEFINED 1
#endif
#if defined(__INT8_TYPE__) && defined(__UINT8_TYPE__) && defined(__INT16_TYPE__) && defined(__UINT16_TYPE__) \
    && defined(__INT32_TYPE__) && defined(__UINT32_TYPE__) && defined(__INT64_TYPE__) && defined(__UINT64_TYPE__)
typedef __INT8_TYPE__ __int8_t;
typedef __UINT8_TYPE__ __uint8_t;
typedef __INT16_TYPE__ __int16_t;
typedef __UINT16_TYPE__ __uint16_t;
typedef __INT32_TYPE__ __int32_t;
typedef __UINT32_TYPE__ __uint32_t;
typedef __INT64_TYPE__ __int64_t;
typedef __UINT64_TYPE__ __uint64_t;
#else
typedef int8_t __int8_t;
typedef uint8_t __uint8_t;
typedef int16_t __int16_t;
typedef uint16_t __uint16_t;
typedef int32_t __int32_t;
typedef uint32_t __uint32_t;
typedef int64_t __int64_t;
typedef uint64_t __uint64_t;
#endif
#endif /* __FC_COMPAT_INT_TYPES_DEFINED */

#ifndef __FC_COMPAT_BSD_ALIASES_DEFINED
#define __FC_COMPAT_BSD_ALIASES_DEFINED 1
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;
#endif /* __FC_COMPAT_BSD_ALIASES_DEFINED */

/*
 * getsockopt with a satisfiable contract. __fc_libc's behavior other_options requires
 * \valid(((char*)optval)+(0..)), an unbounded range no object satisfies, so Eva marks every
 * non-null call Invalid and the caller non-terminating. This header is force-included before
 * any other, so renaming the libc declaration here keeps its contract off the real name, whoever
 * includes <sys/socket.h> later. The replacement bounds optval by *optlen, as getsockopt(2)
 * writes at most *optlen bytes; a caller passing an *optlen larger than its buffer is still
 * flagged. Define FC_STUBS_KEEP_LIBC_GETSOCKOPT to keep __fc_libc's contract.
 */
#ifndef FC_STUBS_KEEP_LIBC_GETSOCKOPT
#define getsockopt __fc_libc_getsockopt_unbounded
#include <sys/socket.h>
#undef getsockopt
/*@
  requires valid_sockfd: 0 <= sockfd < __FC_MAX_OPEN_SOCKETS;
  requires valid_optlen: \valid(optlen);
  requires optval_null_or_valid: optval == \null || \valid((char *)optval + (0 .. *optlen - 1));
  assigns ((char *)optval)[0 .. *optlen - 1], *optlen, \result
          \from indirect:sockfd, indirect:level, indirect:optname, indirect:*optlen,
                indirect:__fc_sockfds[sockfd];
  ensures result_ok_or_error: \result == 0 || \result == -1;
*/
extern int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen);
#endif /* FC_STUBS_KEEP_LIBC_GETSOCKOPT */

/*
 * getopt, strlcpy and strlcat: libc contracts replaced, as for getsockopt (plan step S4).
 * The kernel merges two contracts of one function, so the libc declarations are renamed here,
 * before any target header includes <unistd.h> or <string.h>.
 *
 * getopt: __fc_libc's contract assigns `*optarg` (not `optarg`) and `optind` \from the argv
 * pointers, so Eva turns `optind` and `\result` into a garbled mix of addresses and `optarg`
 * and `argv + optind` are imprecise after the call (one strcmp Unknown per use on libseccomp's
 * tools). __fc_libc has a body in unistd.c, but the pipeline never parses it, so -eva-use-spec
 * changes nothing. The replacement keeps `optind` in [1 .. max(argc, 1)] and `optarg` NULL or
 * inside one of the argv strings. Eva cannot relate `optarg` to the option returned, so a use
 * of `optarg` as a string still has an Unknown for NULL; that one is real for an option
 * declared with an optional argument ("a::"). The precondition on `optind` is left out:
 * __fc_libc's `optind = 1` is in unistd.c, so Eva sees an unknown `optind` at the first call.
 *
 * strlcpy, strlcat: the contracts are in fc_strlcpy.h, shared with bsd/string.h.
 *
 * Define FC_STUBS_KEEP_LIBC_GETOPT or FC_STUBS_KEEP_LIBC_STRLCPY to keep __fc_libc's.
 */
#ifndef FC_STUBS_KEEP_LIBC_GETOPT
#define getopt __fc_libc_getopt_imprecise
#include <unistd.h>
#undef getopt
/*@
  requires valid_argv: \valid_read(argv + (0 .. argc - 1));
  requires valid_args: \forall integer i; 0 <= i < argc ==> valid_read_string(argv[i]);
  requires valid_optstring: valid_read_string(optstring);
  assigns \result \from indirect:argc, indirect:argv[0 .. argc - 1][0 ..],
                        indirect:optstring[0 ..], indirect:optind;
  assigns optind \from optind, indirect:argc, indirect:argv[0 .. argc - 1][0 ..],
                       indirect:optstring[0 ..];
  assigns optopt \from argv[0 .. argc - 1][0 ..], indirect:argc, indirect:optind,
                       indirect:optstring[0 ..];
  assigns optarg \from argv[0 .. argc - 1], indirect:argc, indirect:optind,
                       indirect:argv[0 .. argc - 1][0 ..], indirect:optstring[0 ..];
  ensures result_range: -128 <= \result <= 255;
  ensures optind_range: 1 <= optind <= \max(argc, 1);
  ensures optarg_in_argv: optarg == \null || \subset(optarg, argv[0 .. argc - 1] + (0 ..));
  ensures optarg_string: optarg == \null || valid_read_string(optarg);
*/
extern int getopt(int argc, char *const argv[], const char *optstring);
#endif /* FC_STUBS_KEEP_LIBC_GETOPT */

#ifndef FC_STUBS_KEEP_LIBC_STRLCPY
#define strlcpy __fc_libc_strlcpy
#define strlcat __fc_libc_strlcat
#include <string.h>
#undef strlcpy
#undef strlcat
#include "fc_strlcpy.h"
#endif /* FC_STUBS_KEEP_LIBC_STRLCPY */

/*
 * glibc names __fc_libc lacks, found on c-ares (run-2, 2026-11-18): pipe2, getservbyname_r,
 * getservbyport_r and the IN6_IS_ADDR_* macros. Frama-C read each use as a call to an undeclared
 * `int f()` ("Calling undeclared function pipe2. Old style K&R code?"), for the macros a function that
 * does not exist, and stub_gen.py listed them `undeclared`, which asks no stub author for a contract.
 * __fc_libc's directory comes before templates/fc_stubs on the include path, so <unistd.h>, <netdb.h>
 * and <netinet/in.h> cannot be shadowed there: the names are added here, after the libc headers that
 * define their types, and after the blocks above, which must be the first to include <sys/socket.h>,
 * <unistd.h> and <string.h>. E-ACSL builds take all of them from glibc.
 *
 * Each contract states its facts twice, as the typed syscalls above do: unconditionally, which is
 * what WP uses (it learns nothing from a split on the volatile Frama_C_entropy_source), and in two
 * behaviors, which is what lets Eva keep the success state apart from the failure state.
 *
 * Define FC_STUBS_NO_PIPE2_DECL or FC_STUBS_NO_NETDB_DECLS for a target whose own declarations clash
 * with these (the second also keeps <netdb.h> and <netinet/in.h> out of the force-include).
 */
#ifndef FC_STUBS_NO_PIPE2_DECL
#include <unistd.h>
/* pipe2(2), Linux and POSIX.1-2024. On error pipefd is left as it was, which pipe2(2) states and a
 * caller relies on when it presets both ends to -1 and closes what is not -1 (c-ares). __fc_libc's
 * pipe() says the opposite (both ends initialized and valid whatever the result); not copied.
 * Any `flags` is accepted: an unknown bit is an error result (EINVAL), not undefined behaviour. */
/*@
  requires valid_pipefd: \valid(pipefd + (0 .. 1));
  assigns pipefd[0 .. 1] \from indirect:flags, indirect:__fc_fds[0 ..], indirect:Frama_C_entropy_source;
  assigns \result \from indirect:flags, indirect:__fc_fds[0 ..], indirect:Frama_C_entropy_source;
  ensures result_ok_or_error: \result == 0 || \result == -1;
  ensures initialization:pipefd_on_success: \result == 0 ==> \initialized(&pipefd[0 .. 1]);
  ensures valid_fds_on_success:
    \result == 0 ==> 0 <= pipefd[0] < __FC_MAX_OPEN_FILES && 0 <= pipefd[1] < __FC_MAX_OPEN_FILES;
  ensures unchanged_on_error:
    \result == -1 ==> pipefd[0] == \old(pipefd[0]) && pipefd[1] == \old(pipefd[1]);
  behavior ok:
    assumes nondet_ok: Frama_C_entropy_source != 0;
    ensures result_ok: \result == 0;
    ensures initialization:pipefd: \initialized(&pipefd[0 .. 1]);
    ensures valid_fd0: 0 <= pipefd[0] < __FC_MAX_OPEN_FILES;
    ensures valid_fd1: 0 <= pipefd[1] < __FC_MAX_OPEN_FILES;
  behavior error:
    assumes nondet_error: Frama_C_entropy_source == 0;
    assigns \result \from indirect:flags, indirect:__fc_fds[0 ..], indirect:Frama_C_entropy_source;
    ensures result_error: \result == -1;
  complete behaviors;
  disjoint behaviors;
*/
extern int pipe2(int pipefd[2], int flags);
#endif /* FC_STUBS_NO_PIPE2_DECL */

#ifndef FC_STUBS_NO_NETDB_DECLS
#include <netdb.h>
#include <netinet/in.h>
/* getservbyname_r, getservbyport_r (glibc <netdb.h>, getservent_r(3)), the six-argument form.
 * The last parameter is glibc's `result`, named `res` here so that no clause reads like a `\result`
 * that lost its backslash (tools/check_generated_text.py).
 * The result is 0 or a positive error number (ERANGE when buf is too small). `*res` is result_buf
 * when an entry was found and NULL otherwise: not found is result 0 with a NULL `*res`, and every
 * error leaves `*res` NULL. A found entry's strings and alias vector lie in buf.
 * result_buf and buf may be written whatever the result (the lookup parses candidate lines into
 * them), so nothing is said about them unless an entry was found. The fields are named one by one:
 * the padding after s_port is not written, and with `assigns *result_buf \from buf` Eva made s_port
 * a garbled mix of buf's address.
 * `proto` may be NULL (any protocol). The written objects must not overlap (`restrict`).
 * `assigns *res \from result_buf`, as __fc_libc's getgrnam_r has it: with a \from that leaves the
 * caller's structure out (its getpwnam_r), Eva can only give a NULL `*res` and the found branch is dead. */
/*@
  requires valid_name: valid_read_string(name);
  requires valid_proto_or_null: proto == \null || valid_read_string(proto);
  requires valid_result_buf: \valid(result_buf);
  requires valid_buf: \valid(buf + (0 .. buflen - 1));
  requires valid_res: \valid(res);
  requires separation: \separated(result_buf, buf + (0 .. buflen - 1), res);
  //missing: every \from below also depends on the services database
  assigns \result \from indirect:name[0 ..], indirect:proto, indirect:buflen,
                        indirect:Frama_C_entropy_source;
  assigns result_buf->s_name, result_buf->s_aliases, result_buf->s_proto
    \from buf, indirect:name[0 ..], indirect:proto, indirect:buflen, indirect:Frama_C_entropy_source;
  assigns result_buf->s_port \from indirect:name[0 ..], indirect:proto, indirect:buflen,
                                   indirect:Frama_C_entropy_source;
  assigns buf[0 .. buflen - 1] \from indirect:name[0 ..], indirect:proto, indirect:buflen,
                                     indirect:Frama_C_entropy_source;
  assigns *res \from result_buf, indirect:name[0 ..], indirect:proto, indirect:buflen,
                        indirect:Frama_C_entropy_source;
  ensures result_zero_or_error_number: \result >= 0;
  ensures initialization:res: \initialized(res);
  ensures result_null_or_result_buf: *res == \null || *res == result_buf;
  ensures null_on_error: \result != 0 ==> *res == \null;
  ensures initialization:found_entry:
    *res != \null ==>
      \initialized(&result_buf->s_name) && \initialized(&result_buf->s_aliases)
      && \initialized(&result_buf->s_port) && \initialized(&result_buf->s_proto);
  ensures found_strings:
    *res != \null ==>
      valid_read_string(result_buf->s_name) && valid_read_string(result_buf->s_proto)
      && \valid_read(result_buf->s_aliases);
  behavior found:
    assumes nondet_found: Frama_C_entropy_source != 0;
    ensures result_found: \result == 0 && *res == result_buf;
    ensures initialization:entry:
      \initialized(&result_buf->s_name) && \initialized(&result_buf->s_aliases)
      && \initialized(&result_buf->s_port) && \initialized(&result_buf->s_proto);
    ensures name_in_buf: \subset(result_buf->s_name, buf + (0 .. buflen - 1));
    ensures proto_in_buf: \subset(result_buf->s_proto, buf + (0 .. buflen - 1));
    ensures aliases_in_buf: \subset((char *)result_buf->s_aliases, buf + (0 .. buflen - 1));
  behavior not_found_or_error:
    assumes nondet_none: Frama_C_entropy_source == 0;
    ensures result_none: *res == \null;
  complete behaviors;
  disjoint behaviors;
*/
extern int getservbyname_r(const char *name, const char *proto, struct servent *result_buf, char *buf,
                           size_t buflen, struct servent **res);

/* `port` is in network byte order; any value is accepted (an unknown port is "not found"). */
/*@
  requires valid_proto_or_null: proto == \null || valid_read_string(proto);
  requires valid_result_buf: \valid(result_buf);
  requires valid_buf: \valid(buf + (0 .. buflen - 1));
  requires valid_res: \valid(res);
  requires separation: \separated(result_buf, buf + (0 .. buflen - 1), res);
  //missing: every \from below also depends on the services database
  assigns \result \from indirect:port, indirect:proto, indirect:buflen, indirect:Frama_C_entropy_source;
  assigns result_buf->s_name, result_buf->s_aliases, result_buf->s_proto
    \from buf, indirect:port, indirect:proto, indirect:buflen, indirect:Frama_C_entropy_source;
  assigns result_buf->s_port \from port, indirect:proto, indirect:buflen, indirect:Frama_C_entropy_source;
  assigns buf[0 .. buflen - 1] \from indirect:port, indirect:proto, indirect:buflen,
                                     indirect:Frama_C_entropy_source;
  assigns *res \from result_buf, indirect:port, indirect:proto, indirect:buflen,
                        indirect:Frama_C_entropy_source;
  ensures result_zero_or_error_number: \result >= 0;
  ensures initialization:res: \initialized(res);
  ensures result_null_or_result_buf: *res == \null || *res == result_buf;
  ensures null_on_error: \result != 0 ==> *res == \null;
  ensures initialization:found_entry:
    *res != \null ==>
      \initialized(&result_buf->s_name) && \initialized(&result_buf->s_aliases)
      && \initialized(&result_buf->s_port) && \initialized(&result_buf->s_proto);
  ensures found_strings:
    *res != \null ==>
      valid_read_string(result_buf->s_name) && valid_read_string(result_buf->s_proto)
      && \valid_read(result_buf->s_aliases);
  ensures found_port: *res != \null ==> result_buf->s_port == port;
  behavior found:
    assumes nondet_found: Frama_C_entropy_source != 0;
    ensures result_found: \result == 0 && *res == result_buf;
    ensures initialization:entry:
      \initialized(&result_buf->s_name) && \initialized(&result_buf->s_aliases)
      && \initialized(&result_buf->s_port) && \initialized(&result_buf->s_proto);
    ensures name_in_buf: \subset(result_buf->s_name, buf + (0 .. buflen - 1));
    ensures proto_in_buf: \subset(result_buf->s_proto, buf + (0 .. buflen - 1));
    ensures aliases_in_buf: \subset((char *)result_buf->s_aliases, buf + (0 .. buflen - 1));
    ensures port_found: result_buf->s_port == port;
  behavior not_found_or_error:
    assumes nondet_none: Frama_C_entropy_source == 0;
    ensures result_none: *res == \null;
  complete behaviors;
  disjoint behaviors;
*/
extern int getservbyport_r(int port, const char *proto, struct servent *result_buf, char *buf,
                           size_t buflen, struct servent **res);

/* The IN6_IS_ADDR_* macros of <netinet/in.h> (POSIX), which __fc_libc's header does not define.
 * The whole POSIX family, not only the seven c-ares uses: one more is one more undeclared `int f()`.
 * Same values as glibc's on every address (compared in tests/test_fc_stub_repairs.py), read through
 * `s6_addr` bytes, the one member __fc_libc's struct in6_addr has, rather than glibc's 32-bit words,
 * so there is no pointer cast for WP's Typed model to refuse and no byte order in the expression.
 * The argument is evaluated once, as in glibc. */
#ifndef IN6_IS_ADDR_UNSPECIFIED
#define __FC_IN6_TEST(a, test)                                                                         \
  (__extension__({                                                                                     \
    const struct in6_addr *__fc_in6 = (const struct in6_addr *)(a);                                    \
    (test);                                                                                            \
  }))
#define __FC_IN6_ZERO4(i)                                                                              \
  (__fc_in6->s6_addr[(i)] == 0 && __fc_in6->s6_addr[(i) + 1] == 0 && __fc_in6->s6_addr[(i) + 2] == 0  \
   && __fc_in6->s6_addr[(i) + 3] == 0)
#define __FC_IN6_MC_SCOPE(a, scope)                                                                    \
  __FC_IN6_TEST(a, __fc_in6->s6_addr[0] == 0xff && (__fc_in6->s6_addr[1] & 0x0f) == (scope))
#define IN6_IS_ADDR_UNSPECIFIED(a)                                                                     \
  __FC_IN6_TEST(a, __FC_IN6_ZERO4(0) && __FC_IN6_ZERO4(4) && __FC_IN6_ZERO4(8) && __FC_IN6_ZERO4(12))
#define IN6_IS_ADDR_LOOPBACK(a)                                                                        \
  __FC_IN6_TEST(a, __FC_IN6_ZERO4(0) && __FC_IN6_ZERO4(4) && __FC_IN6_ZERO4(8)                         \
                     && __fc_in6->s6_addr[12] == 0 && __fc_in6->s6_addr[13] == 0                       \
                     && __fc_in6->s6_addr[14] == 0 && __fc_in6->s6_addr[15] == 1)
#define IN6_IS_ADDR_MULTICAST(a) __FC_IN6_TEST(a, __fc_in6->s6_addr[0] == 0xff)
#define IN6_IS_ADDR_LINKLOCAL(a)                                                                       \
  __FC_IN6_TEST(a, __fc_in6->s6_addr[0] == 0xfe && (__fc_in6->s6_addr[1] & 0xc0) == 0x80)
#define IN6_IS_ADDR_SITELOCAL(a)                                                                       \
  __FC_IN6_TEST(a, __fc_in6->s6_addr[0] == 0xfe && (__fc_in6->s6_addr[1] & 0xc0) == 0xc0)
#define IN6_IS_ADDR_V4MAPPED(a)                                                                        \
  __FC_IN6_TEST(a, __FC_IN6_ZERO4(0) && __FC_IN6_ZERO4(4) && __fc_in6->s6_addr[8] == 0                 \
                     && __fc_in6->s6_addr[9] == 0 && __fc_in6->s6_addr[10] == 0xff                     \
                     && __fc_in6->s6_addr[11] == 0xff)
/* glibc: the first 96 bits are zero and the last 32, as a host-order number, are greater than 1. */
#define IN6_IS_ADDR_V4COMPAT(a)                                                                        \
  __FC_IN6_TEST(a, __FC_IN6_ZERO4(0) && __FC_IN6_ZERO4(4) && __FC_IN6_ZERO4(8)                         \
                     && (__fc_in6->s6_addr[12] != 0 || __fc_in6->s6_addr[13] != 0                      \
                         || __fc_in6->s6_addr[14] != 0 || __fc_in6->s6_addr[15] > 1))
#define IN6_IS_ADDR_MC_NODELOCAL(a) __FC_IN6_MC_SCOPE(a, 0x1)
#define IN6_IS_ADDR_MC_LINKLOCAL(a) __FC_IN6_MC_SCOPE(a, 0x2)
#define IN6_IS_ADDR_MC_SITELOCAL(a) __FC_IN6_MC_SCOPE(a, 0x5)
#define IN6_IS_ADDR_MC_ORGLOCAL(a) __FC_IN6_MC_SCOPE(a, 0x8)
#define IN6_IS_ADDR_MC_GLOBAL(a) __FC_IN6_MC_SCOPE(a, 0xe)
#endif /* IN6_IS_ADDR_UNSPECIFIED */
#endif /* FC_STUBS_NO_NETDB_DECLS */

/*
 * glibc <sched.h> CPU affinity names __fc_libc's <sched.h> lacks (34.0~beta and 35.0~dev): cpu_set_t,
 * the CPU_* macros, sched_setaffinity and sched_getaffinity, found on nginx (run-1, 2026-11-19).
 * configure ran against glibc and set NGX_HAVE_SCHED_SETAFFINITY, so src/os/unix/ngx_setaffinity.h
 * stopped the parse of every nginx source at `typedef cpu_set_t ngx_cpuset_t;` ("syntax error").
 * glibc declares them under _GNU_SOURCE; here they are declared whatever the target defines, because
 * this header is read before the target's own `#define _GNU_SOURCE`.
 *
 * Layout as glibc x86_64: 1024 CPUs in sixteen unsigned longs, same names (`__cpu_mask`, `__bits`).
 * The macros keep glibc's semantics: each argument is evaluated once, and a CPU number at or past
 * setsize * 8 is ignored (CPU_SET and CPU_CLR write nothing and give 0, CPU_ISSET gives 0). They reach
 * a word through `&__bits[0]` (__FC_CPU_WORD), with no cast for WP's Typed model to refuse. In the
 * contracts below, `set->__bits[0 .. n - 1]` is what the logic typer makes of any spelling (it folds
 * `*(set->__bits + k)` back into `set->__bits[k]`): Eva and WP read it as the words at those offsets,
 * past word 15 too (Eva checked on a 32-word set), while E-ACSL checks `__bits[k]` as an index of the
 * sixteen-word member and stops ("index out of bounds") on a larger set. No E-ACSL build reads them.
 * CPU_COUNT calls glibc's own __sched_cpucount. glibc's CPU_ZERO and CPU_ZERO_S are a memset of the
 * set, which WP's Typed model refuses (the set converted to `void *`: "Cast with incompatible pointers
 * types"). CPU_ZERO, whose size is sizeof(cpu_set_t), is therefore an assignment of a zero cpu_set_t,
 * the same bytes, which both Eva and WP follow exactly; CPU_ZERO_S calls __fc_sched_cpuzero, a declared
 * model (below) that WP proves callers against but that Eva follows only as "initialized, any value"
 * (it reduces no form of its postcondition).
 * Not declared: CPU_EQUAL, CPU_AND, CPU_OR, CPU_XOR and their _S forms, CPU_ALLOC and CPU_FREE (glibc's
 * __sched_cpualloc / __sched_cpufree), sched_getcpu, getcpu, and <sched.h>'s clone, unshare and setns.
 *
 * Skipped when CPU_SETSIZE is already defined (a later libc that has them). Define
 * FC_STUBS_NO_SCHED_AFFINITY_DECLS for a target with its own cpu_set_t or CPU_* macros.
 */
#ifndef FC_STUBS_NO_SCHED_AFFINITY_DECLS
#include <sched.h>
#ifndef CPU_SETSIZE
typedef unsigned long int __cpu_mask;
#define __CPU_SETSIZE 1024
#define __NCPUBITS (8 * sizeof(__cpu_mask))
typedef struct {
  __cpu_mask __bits[__CPU_SETSIZE / __NCPUBITS];
} cpu_set_t;

#define CPU_SETSIZE __CPU_SETSIZE
#define __FC_CPU_ELT(cpu) ((cpu) / __NCPUBITS)
#define __FC_CPU_MASK(cpu) ((__cpu_mask)1 << ((cpu) % __NCPUBITS))
/* The word of `cpu`, through a pointer to the first word: a set of CPU_ALLOC_SIZE(n) bytes has more
 * words than the sixteen the member declares when n > 1024. glibc reaches it through a
 * `(__cpu_mask *)` cast, which Frama-C folds back into `__bits[i]`, an index of the sixteen-word
 * member (Eva: "accessing out of bounds index" from word 16 on); `*(&__bits[0] + i)` stays pointer
 * arithmetic, checked against the object the set lives in. */
#define __FC_CPU_WORD(cpusetp, cpu) ((&(cpusetp)->__bits[0])[__FC_CPU_ELT(cpu)])
#define CPU_SET_S(cpu, setsize, cpusetp)                                                               \
  (__extension__({                                                                                     \
    size_t __fc_cpu = (cpu);                                                                           \
    __fc_cpu / 8 < (setsize) ? (__FC_CPU_WORD(cpusetp, __fc_cpu) |= __FC_CPU_MASK(__fc_cpu)) : 0;      \
  }))
#define CPU_CLR_S(cpu, setsize, cpusetp)                                                               \
  (__extension__({                                                                                     \
    size_t __fc_cpu = (cpu);                                                                           \
    __fc_cpu / 8 < (setsize) ? (__FC_CPU_WORD(cpusetp, __fc_cpu) &= ~__FC_CPU_MASK(__fc_cpu)) : 0;     \
  }))
#define CPU_ISSET_S(cpu, setsize, cpusetp)                                                             \
  (__extension__({                                                                                     \
    size_t __fc_cpu = (cpu);                                                                           \
    __fc_cpu / 8 < (setsize) ? (__FC_CPU_WORD(cpusetp, __fc_cpu) & __FC_CPU_MASK(__fc_cpu)) != 0 : 0;  \
  }))
#define CPU_ZERO_S(setsize, cpusetp) __fc_sched_cpuzero((setsize), (cpusetp))
#define CPU_COUNT_S(setsize, cpusetp) __sched_cpucount((setsize), (cpusetp))
#define CPU_SET(cpu, cpusetp) CPU_SET_S(cpu, sizeof(cpu_set_t), cpusetp)
#define CPU_CLR(cpu, cpusetp) CPU_CLR_S(cpu, sizeof(cpu_set_t), cpusetp)
#define CPU_ISSET(cpu, cpusetp) CPU_ISSET_S(cpu, sizeof(cpu_set_t), cpusetp)
/* All sixteen words spelled out: WP proves nothing about the words a partial initializer (`{{0}}`)
 * leaves implicit. */
#define CPU_ZERO(cpusetp)                                                          \
  do {                                                                             \
    *(cpusetp) = (cpu_set_t){{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};   \
  } while (0)
#define CPU_COUNT(cpusetp) CPU_COUNT_S(sizeof(cpu_set_t), cpusetp)
#define CPU_ALLOC_SIZE(count) ((((count) + __NCPUBITS - 1) / __NCPUBITS) * sizeof(__cpu_mask))

/* glibc's CPU_COUNT_S: the bits set in the first setsize / sizeof(__cpu_mask) words (whole words only,
 * as glibc counts them). */
/*@
  requires valid_set: \valid_read(setp->__bits + (0 .. setsize / sizeof(__cpu_mask) - 1));
  requires initialized_set: \initialized(setp->__bits + (0 .. setsize / sizeof(__cpu_mask) - 1));
  assigns \result \from setp->__bits[0 .. setsize / sizeof(__cpu_mask) - 1], indirect:setsize;
  ensures count_range: 0 <= \result <= 8 * setsize;
*/
extern int __sched_cpucount(size_t setsize, const cpu_set_t *setp);

/* CPU_ZERO_S. glibc's is a memset of setsize bytes; this declared model zeroes the same words without
 * converting the set to memset's `void *` (with memset, WP left every caller's memset precondition and
 * assigns unproved). Whole words only, so that the assigns clause is exact: sizeof(cpu_set_t) and
 * CPU_ALLOC_SIZE are whole words, and sched_getaffinity refuses any other size. Eva reduces neither
 * postcondition on `unsigned long` words (nor through `(char *)`; checked 2026-11-19): after the call
 * the words are initialized with any value. */
/*@
  requires whole_words: setsize % sizeof(__cpu_mask) == 0;
  requires valid_set: \valid(setp->__bits + (0 .. setsize / sizeof(__cpu_mask) - 1));
  assigns setp->__bits[0 .. setsize / sizeof(__cpu_mask) - 1] \from \nothing;
  ensures zeroed: \forall integer k; 0 <= k < setsize / sizeof(__cpu_mask) ==> setp->__bits[k] == 0;
  ensures zeroed_values: \subset(setp->__bits[0 .. setsize / sizeof(__cpu_mask) - 1], {0});
  ensures initialized_set: \initialized(setp->__bits + (0 .. setsize / sizeof(__cpu_mask) - 1));
*/
extern void __fc_sched_cpuzero(size_t setsize, cpu_set_t *setp);

/* sched_setaffinity(2). The kernel reads cpusetsize bytes of the set (at most its own mask size);
 * the contract asks for whole words, cpusetsize rounded up, so an odd size over a buffer that ends
 * mid-word is a false alarm, never a missed one. 0 or -1 (EINVAL for a set with no online CPU, ESRCH,
 * EPERM). errno is not assigned, as in most of __fc_libc's <unistd.h>. */
/*@
  requires valid_mask:
    \valid_read(mask->__bits + (0 .. (cpusetsize + sizeof(__cpu_mask) - 1) / sizeof(__cpu_mask) - 1));
  requires initialized_mask:
    \initialized(mask->__bits + (0 .. (cpusetsize + sizeof(__cpu_mask) - 1) / sizeof(__cpu_mask) - 1));
  assigns \result \from indirect:pid, indirect:cpusetsize,
                        indirect:mask->__bits[0 .. (cpusetsize + sizeof(__cpu_mask) - 1) / sizeof(__cpu_mask) - 1],
                        indirect:Frama_C_entropy_source;
  ensures result_ok_or_error: \result == 0 || \result == -1;
*/
extern int sched_setaffinity(pid_t pid, size_t cpusetsize, const cpu_set_t *mask);

/* sched_getaffinity(2) through glibc 2.41: on success the whole set, cpusetsize bytes, is written (the
 * kernel's mask, then zeros); the kernel refuses (EINVAL) a size that is not whole words or holds fewer
 * bits than it has CPUs, and on any error nothing is written. Checked against glibc in the analysis
 * image. Stated twice, as pipe2 above: unconditionally for WP, in two behaviors for Eva. */
/*@
  requires valid_mask: \valid(mask->__bits + (0 .. cpusetsize / sizeof(__cpu_mask) - 1));
  assigns mask->__bits[0 .. cpusetsize / sizeof(__cpu_mask) - 1]
    \from indirect:pid, indirect:cpusetsize, indirect:Frama_C_entropy_source;
  assigns \result \from indirect:pid, indirect:cpusetsize, indirect:Frama_C_entropy_source;
  ensures result_ok_or_error: \result == 0 || \result == -1;
  ensures initialized_on_success:
    \result == 0 ==> \initialized(mask->__bits + (0 .. cpusetsize / sizeof(__cpu_mask) - 1));
  behavior ok:
    assumes nondet_ok: Frama_C_entropy_source != 0;
    ensures result_ok: \result == 0;
    ensures initialized_mask: \initialized(mask->__bits + (0 .. cpusetsize / sizeof(__cpu_mask) - 1));
  behavior error:
    assumes nondet_error: Frama_C_entropy_source == 0;
    assigns \result \from indirect:pid, indirect:cpusetsize, indirect:Frama_C_entropy_source;
    ensures result_error: \result == -1;
  complete behaviors;
  disjoint behaviors;
*/
extern int sched_getaffinity(pid_t pid, size_t cpusetsize, cpu_set_t *mask);
#endif /* CPU_SETSIZE */
#endif /* FC_STUBS_NO_SCHED_AFFINITY_DECLS */

/*
 * Linux names of glibc's <netinet/in.h> and <netinet/tcp.h> that __fc_libc's headers lack, found on nginx
 * (run-1, 2026-11-19): `struct in_pktinfo` (the IP_PKTINFO control message; __fc_libc has IP_PKTINFO and
 * struct in6_pktinfo), `struct tcp_info` (what TCP_INFO reads; __fc_libc has TCP_INFO), and every IP_,
 * IPV6_, TCP_ and TCPI_OPT_ constant of glibc 2.41's two headers that __fc_libc does not define, with
 * glibc's x86_64 values. nginx stopped on "field 'pkt' is declared with incomplete type 'struct
 * in_pktinfo'" (src/event/ngx_event_udp.h), "Cannot resolve variable IP_BIND_ADDRESS_NO_PORT"
 * (ngx_event_connect.c) and "sizeof on incomplete type 'struct tcp_info'" (ngx_http_variables.c).
 * Same layouts as glibc (checked against it by tests/test_fc_stub_repairs.py). Each constant steps aside
 * when already defined; the two structures cannot, so a later libc that adds one makes this header fail
 * with "redefinition of 'in_pktinfo'": drop it here then. Define FC_STUBS_NO_NETINET_LINUX_DECLS for a
 * target with its own (it also keeps <netinet/in.h> and <netinet/tcp.h> out of the force-include).
 * Not declared: IP_MSFILTER_SIZE (struct ip_msfilter), the MCAST_* requests, IN_CLASS*, and the AF_, SO_,
 * SOL_, SCM_ and MSG_ names of glibc's <sys/socket.h> that __fc_libc lacks.
 */
#ifndef FC_STUBS_NO_NETINET_LINUX_DECLS
#include <netinet/in.h>
#include <netinet/tcp.h>
struct in_pktinfo {
  int ipi_ifindex;
  struct in_addr ipi_spec_dst;
  struct in_addr ipi_addr;
};
struct tcp_info {
  uint8_t tcpi_state;
  uint8_t tcpi_ca_state;
  uint8_t tcpi_retransmits;
  uint8_t tcpi_probes;
  uint8_t tcpi_backoff;
  uint8_t tcpi_options;
  uint8_t tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
  uint32_t tcpi_rto;
  uint32_t tcpi_ato;
  uint32_t tcpi_snd_mss;
  uint32_t tcpi_rcv_mss;
  uint32_t tcpi_unacked;
  uint32_t tcpi_sacked;
  uint32_t tcpi_lost;
  uint32_t tcpi_retrans;
  uint32_t tcpi_fackets;
  uint32_t tcpi_last_data_sent;
  uint32_t tcpi_last_ack_sent;
  uint32_t tcpi_last_data_recv;
  uint32_t tcpi_last_ack_recv;
  uint32_t tcpi_pmtu;
  uint32_t tcpi_rcv_ssthresh;
  uint32_t tcpi_rtt;
  uint32_t tcpi_rttvar;
  uint32_t tcpi_snd_ssthresh;
  uint32_t tcpi_snd_cwnd;
  uint32_t tcpi_advmss;
  uint32_t tcpi_reordering;
  uint32_t tcpi_rcv_rtt;
  uint32_t tcpi_rcv_space;
  uint32_t tcpi_total_retrans;
};
/* <netinet/in.h> (glibc <bits/in.h>) */
#ifndef IP_NODEFRAG
#define IP_NODEFRAG 22
#endif
#ifndef IP_CHECKSUM
#define IP_CHECKSUM 23
#endif
#ifndef IP_BIND_ADDRESS_NO_PORT
#define IP_BIND_ADDRESS_NO_PORT 24
#endif
#ifndef IP_RECVFRAGSIZE
#define IP_RECVFRAGSIZE 25
#endif
#ifndef IP_RECVERR_RFC4884
#define IP_RECVERR_RFC4884 26
#endif
#ifndef IP_MULTICAST_ALL
#define IP_MULTICAST_ALL 49
#endif
#ifndef IP_UNICAST_IF
#define IP_UNICAST_IF 50
#endif
#ifndef IP_LOCAL_PORT_RANGE
#define IP_LOCAL_PORT_RANGE 51
#endif
#ifndef IP_PROTOCOL
#define IP_PROTOCOL 52
#endif
#ifndef IP_PMTUDISC_INTERFACE
#define IP_PMTUDISC_INTERFACE 4
#endif
#ifndef IP_PMTUDISC_OMIT
#define IP_PMTUDISC_OMIT 5
#endif
#ifndef IPV6_MULTICAST_ALL
#define IPV6_MULTICAST_ALL 29
#endif
#ifndef IPV6_ROUTER_ALERT_ISOLATE
#define IPV6_ROUTER_ALERT_ISOLATE 30
#endif
#ifndef IPV6_RECVERR_RFC4884
#define IPV6_RECVERR_RFC4884 31
#endif
#ifndef IPV6_HDRINCL
#define IPV6_HDRINCL 36
#endif
#ifndef IPV6_RECVPATHMTU
#define IPV6_RECVPATHMTU 60
#endif
#ifndef IPV6_PATHMTU
#define IPV6_PATHMTU 61
#endif
#ifndef IPV6_DONTFRAG
#define IPV6_DONTFRAG 62
#endif
#ifndef IPV6_AUTOFLOWLABEL
#define IPV6_AUTOFLOWLABEL 70
#endif
#ifndef IPV6_ADDR_PREFERENCES
#define IPV6_ADDR_PREFERENCES 72
#endif
#ifndef IPV6_MINHOPCOUNT
#define IPV6_MINHOPCOUNT 73
#endif
#ifndef IPV6_ORIGDSTADDR
#define IPV6_ORIGDSTADDR 74
#endif
#ifndef IPV6_RECVORIGDSTADDR
#define IPV6_RECVORIGDSTADDR IPV6_ORIGDSTADDR
#endif
#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT 75
#endif
#ifndef IPV6_UNICAST_IF
#define IPV6_UNICAST_IF 76
#endif
#ifndef IPV6_RECVFRAGSIZE
#define IPV6_RECVFRAGSIZE 77
#endif
#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif
#ifndef IPV6_PMTUDISC_INTERFACE
#define IPV6_PMTUDISC_INTERFACE 4
#endif
#ifndef IPV6_PMTUDISC_OMIT
#define IPV6_PMTUDISC_OMIT 5
#endif
/* <netinet/tcp.h> */
#ifndef TCP_MSS
#define TCP_MSS 512
#endif
#ifndef TCP_MAXWIN
#define TCP_MAXWIN 65535
#endif
#ifndef TCP_MAX_WINSHIFT
#define TCP_MAX_WINSHIFT 14
#endif
#ifndef TCP_REPAIR_WINDOW
#define TCP_REPAIR_WINDOW 29
#endif
#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT 30
#endif
#ifndef TCP_ULP
#define TCP_ULP 31
#endif
#ifndef TCP_MD5SIG_EXT
#define TCP_MD5SIG_EXT 32
#endif
#ifndef TCP_FASTOPEN_KEY
#define TCP_FASTOPEN_KEY 33
#endif
#ifndef TCP_FASTOPEN_NO_COOKIE
#define TCP_FASTOPEN_NO_COOKIE 34
#endif
#ifndef TCP_ZEROCOPY_RECEIVE
#define TCP_ZEROCOPY_RECEIVE 35
#endif
#ifndef TCP_INQ
#define TCP_INQ 36
#endif
#ifndef TCP_CM_INQ
#define TCP_CM_INQ TCP_INQ
#endif
#ifndef TCP_TX_DELAY
#define TCP_TX_DELAY 37
#endif
#ifndef TCP_REPAIR_ON
#define TCP_REPAIR_ON 1
#endif
#ifndef TCP_REPAIR_OFF
#define TCP_REPAIR_OFF 0
#endif
#ifndef TCP_REPAIR_OFF_NO_WP
#define TCP_REPAIR_OFF_NO_WP -1
#endif
#ifndef TCP_MD5SIG_FLAG_PREFIX
#define TCP_MD5SIG_FLAG_PREFIX 1
#endif
#ifndef TCP_MD5SIG_FLAG_IFINDEX
#define TCP_MD5SIG_FLAG_IFINDEX 2
#endif
#ifndef TCP_MD5SIG_MAXKEYLEN
#define TCP_MD5SIG_MAXKEYLEN 80
#endif
#ifndef TCP_COOKIE_MIN
#define TCP_COOKIE_MIN 8
#endif
#ifndef TCP_COOKIE_MAX
#define TCP_COOKIE_MAX 16
#endif
#ifndef TCP_COOKIE_PAIR_SIZE
#define TCP_COOKIE_PAIR_SIZE (2 * TCP_COOKIE_MAX)
#endif
#ifndef TCP_COOKIE_IN_ALWAYS
#define TCP_COOKIE_IN_ALWAYS (1 << 0)
#endif
#ifndef TCP_COOKIE_OUT_NEVER
#define TCP_COOKIE_OUT_NEVER (1 << 1)
#endif
#ifndef TCP_S_DATA_IN
#define TCP_S_DATA_IN (1 << 2)
#endif
#ifndef TCP_S_DATA_OUT
#define TCP_S_DATA_OUT (1 << 3)
#endif
#ifndef TCP_MSS_DEFAULT
#define TCP_MSS_DEFAULT 536U
#endif
#ifndef TCP_MSS_DESIRED
#define TCP_MSS_DESIRED 1220U
#endif
#ifndef TCPI_OPT_TIMESTAMPS
#define TCPI_OPT_TIMESTAMPS 1
#endif
#ifndef TCPI_OPT_SACK
#define TCPI_OPT_SACK 2
#endif
#ifndef TCPI_OPT_WSCALE
#define TCPI_OPT_WSCALE 4
#endif
#ifndef TCPI_OPT_ECN
#define TCPI_OPT_ECN 8
#endif
#ifndef TCPI_OPT_ECN_SEEN
#define TCPI_OPT_ECN_SEEN 16
#endif
#ifndef TCPI_OPT_SYN_DATA
#define TCPI_OPT_SYN_DATA 32
#endif
#endif /* FC_STUBS_NO_NETINET_LINUX_DECLS */

#endif /* __FRAMAC_EACSL__ */

/*
 * The string vocabulary (plan step S8). One name per notion, the names of __fc_libc's
 * __fc_string_axiomatic.h, which Eva and WP read (templates/acsl/acsl_vocabulary.h lists them):
 *
 *   valid_read_string(s)      s is readable up to and including its first NUL
 *   valid_string(s)           the same, writable
 *   valid_read_nstring(s, n)  n readable, initialized bytes, or a readable string (strnlen's domain)
 *   valid_string_or_null(s)   s == \null || valid_string(s)
 *   strlen(s)                 the length (a logic function, no backslash; `\strlen` does not exist)
 *
 * E-ACSL builds use the host's headers (-no-frama-c-stdlib), which do not define them, so this block
 * defines the same names with executable bodies. Differences an E-ACSL run can show:
 *   - valid_read_string and valid_string look for the NUL within 65536 bytes: a longer string fails;
 *   - on a buffer that is not a string they abort with an E-ACSL RTE inside the predicate
 *     (`\valid_read(s + i)`, E-ACSL checks the read before the validity guard next to it) rather than
 *     with the precondition: still a failure, reported at the predicate's line;
 *   - strlen is recursive: on a buffer that is not a string it aborts the same way.
 * These definitions must NOT reach the Eva/WP (__fc_libc) parse: a second definition of a libc
 * predicate aborts the kernel under annot-error=abort.
 */

#if defined(__FRAMAC_EACSL__)

/*@
  @ logic integer strlen(char *s) = s[0] == '\0' ? 0 : 1 + strlen(s + 1);
  @
  @ predicate __fc_eacsl_read_nul_at(char *s, integer i) = \valid_read(s + (0 .. i)) && s[i] == '\0';
  @
  @ predicate __fc_eacsl_nul_at(char *s, integer i) = \valid(s + (0 .. i)) && s[i] == '\0';
  @
  @ // One predicate call after the guard: E-ACSL 35 drops the first conjunct of
  @ // `\exists i; guard && P && Q` (troubleshooting, S4 entry).
  @ predicate valid_read_string(char *s) =
  @   \exists integer i; 0 <= i <= 65536 && __fc_eacsl_read_nul_at(s, i);
  @
  @ predicate valid_string(char *s) =
  @   \exists integer i; 0 <= i <= 65536 && __fc_eacsl_nul_at(s, i);
  @
  @ predicate valid_read_nstring(char *s, integer n) =
  @   (\valid_read(s + (0 .. n - 1)) && \initialized(s + (0 .. n - 1))) || valid_read_string(s);
  @
  @ predicate valid_string_or_null(char *s) = s == \null || valid_string(s);
  @*/

#endif /* __FRAMAC_EACSL__ */

#if defined(__has_include)
#if __has_include("../acsl/acsl_vocabulary.h")
#include "../acsl/acsl_vocabulary.h"
#elif __has_include(<acsl_vocabulary.h>)
#include <acsl_vocabulary.h>
#endif
#else
#include "../acsl/acsl_vocabulary.h"
#endif

#endif /* __FRAMAC__ */

#endif /* FRAMAC_COMPAT_TYPES_H */
