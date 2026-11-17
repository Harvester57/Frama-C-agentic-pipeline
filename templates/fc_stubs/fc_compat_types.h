/*
 * Frama-C Compatibility Primitive Types (force-included by the pipeline)
 *
 * This header is a Frama-C parse aid only. It contains typedefs, includes,
 * keyword-spelling macros and contracted declarations, never C function bodies, and it is EMPTY whenever __FRAMAC__ is undefined
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

/* Checked-arithmetic builtins (mpack run-3, 2026-11-17). Frama-C does not know __builtin_add_overflow,
 * __builtin_sub_overflow, __builtin_mul_overflow, their `_p` forms or the typed forms
 * (__builtin_sadd_overflow ... __builtin_umulll_overflow): it calls them as undeclared functions with a
 * prototype guessed from the first call, which converts the operands of later calls to that call's
 * types. Eva and WP use a generated `assigns` spec (any value in `*res` and in the result), and the
 * E-ACSL output redeclares the builtin, which clang refuses ("cannot redeclare builtin function"). Targets enable them under `__has_builtin` or a GCC version test, so both modes get them
 * here as GNU statement expressions with GCC's semantics: the operands' mathematical result, wrapped to
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
#define __builtin_add_overflow(a, b, res) __FC_OVF(0, a, b, res)
#define __builtin_sub_overflow(a, b, res) __FC_OVF(1, a, b, res)
#define __builtin_mul_overflow(a, b, res) __FC_OVF(2, a, b, res)
#define __builtin_add_overflow_p(a, b, c) __FC_OVF_P(0, a, b, c)
#define __builtin_sub_overflow_p(a, b, c) __FC_OVF_P(1, a, b, c)
#define __builtin_mul_overflow_p(a, b, c) __FC_OVF_P(2, a, b, c)
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
