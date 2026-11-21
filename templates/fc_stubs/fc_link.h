/*
 * The declarations of <link.h> for every Frama-C parse (Eva / WP, the model, the E-ACSL frontend),
 * included by templates/fc_stubs/link.h only; see there why glibc's header cannot be read.
 *
 * Same names, types and layouts as glibc 2.41 on x86_64 (compared with gcc by tests/test_fc_glibc_gaps.py),
 * declared whatever the target's feature-test macros, as glibc does under _GNU_SOURCE. Not declared: the
 * ld.so audit interface (la_version ... la_objclose, LAV_*, LA_*, the La_x86_64_* register types, whose
 * vector members Frama-C cannot represent).
 *
 * dl_iterate_phdr calls `callback` once per loaded object, with `data`; ACSL cannot state a call through a
 * function pointer, so Eva and WP never run the callback from here: its body is analysed only from its own
 * callers, and what it writes through `data` is not in the frame of dl_iterate_phdr. The result is the last
 * callback's result, or 0.
 */

#ifndef FC_STUBS_FC_LINK_H
#define FC_STUBS_FC_LINK_H

#include <elf.h>
#include <dlfcn.h>
#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>

#define __ELF_NATIVE_CLASS 64
#define ElfW(type) _ElfW(Elf, __ELF_NATIVE_CLASS, type)
#define _ElfW(e, w, t) _ElfW_1(e, w, _##t)
#define _ElfW_1(e, w, t) e##w##t

typedef uint32_t Elf_Symndx;

struct link_map;

/* The rendezvous structure of the dynamic linker (r_debug(3)). */
struct r_debug {
  int r_version;
  struct link_map *r_map;
  ElfW(Addr) r_brk;
  enum { RT_CONSISTENT, RT_ADD, RT_DELETE } r_state;
  ElfW(Addr) r_ldbase;
};

extern struct r_debug _r_debug;

struct r_debug_extended {
  struct r_debug base;
  struct r_debug_extended *r_next;
};

/* ElfW(Dyn), spelled out: tests/test_fc_stub_contracts.py reads `extern ElfW(...)` as a prototype of ElfW. */
extern Elf64_Dyn _DYNAMIC[];

struct link_map {
  ElfW(Addr) l_addr;
  char *l_name;
  ElfW(Dyn) *l_ld;
  struct link_map *l_next, *l_prev;
};

struct dl_phdr_info {
  ElfW(Addr) dlpi_addr;
  const char *dlpi_name;
  const ElfW(Phdr) *dlpi_phdr;
  ElfW(Half) dlpi_phnum;
  unsigned long long int dlpi_adds;
  unsigned long long int dlpi_subs;
  size_t dlpi_tls_modid;
  void *dlpi_tls_data;
};

/*@
  //missing: the calls of callback and what they write through data
  assigns \result \from indirect:callback, indirect:data;
*/
extern int dl_iterate_phdr(int (*callback)(struct dl_phdr_info *, size_t, void *), void *data);

#endif /* FC_STUBS_FC_LINK_H */
