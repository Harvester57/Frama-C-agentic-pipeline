/*
 * Force-included for every CryptoLib module.
 *
 * CMake passes MC_LOG_PATH as `-DMC_LOG_PATH="log.txt"`. Carried through
 * -cpp-extra-args (Eva/WP/E-ACSL) the double quotes are stripped, which turns
 * the fopen() argument into the bare identifier `log.txt`. Defining the macro
 * in a header keeps the string literal intact for every front-end.
 */
#ifndef CRYPTOLIB_FC_MC_LOG_PATH_H
#define CRYPTOLIB_FC_MC_LOG_PATH_H

#ifndef MC_LOG_PATH
#define MC_LOG_PATH "log.txt"
#endif

#endif /* CRYPTOLIB_FC_MC_LOG_PATH_H */
