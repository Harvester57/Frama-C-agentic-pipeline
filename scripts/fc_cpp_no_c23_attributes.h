/*
 * Forced first by scripts/fc_cpp_wrapper.py into every Frama-C preprocessing (Eva, WP, the Phase 0 model,
 * the kernel AST and the E-ACSL frontend). Frama-C 34 (34.0~beta) does not parse C23 attribute specifiers
 * (`[[__noreturn__]]`, `[[__fallthrough__]];`), but GCC 14's preprocessor answers `__has_c_attribute(...)`
 * with 202311 in every -std mode, so code that feature-tests it (sudo's config.h: sudo_noreturn,
 * FALLTHROUGH) hands Frama-C `[[...]]` and the parse stops with "syntax error ... before or at token: [".
 * Answering 0 makes such code take its own pre-C23 fallback (`__attribute__((__noreturn__))`, ...).
 *
 * A function-like macro, not `-U__has_c_attribute`: `#if defined(__has_c_attribute) && __has_c_attribute(x)`
 * is a cpp error once the name is undefined. In a system header so that redefining the built-in neither
 * warns nor fails a `-Werror` build. The wrapper blanks these lines out of the `-dD` output, so Frama-C's
 * annotation preprocessor (-pp-annot) does not replay them.
 */
#pragma GCC system_header
#undef __has_c_attribute
#define __has_c_attribute(__fc_c23_attribute) 0
