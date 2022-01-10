/* ws_attributes.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_ATTRIBUTES_H__
#define __WS_ATTRIBUTES_H__

#include "ws_compiler_tests.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * If we're running GCC or clang define _U_ to be "__attribute__((unused))"
 * so we can use _U_ to flag unused function parameters and not get warnings
 * about them. Otherwise, define _U_ to be an empty string so that _U_ used
 * to flag an unused function parameters will compile with other compilers.
 *
 * XXX - similar hints for other compilers?
 */
#if defined(__GNUC__)
  /* This includes clang */
  #define _U_ __attribute__((unused))
#elif defined(_MSC_VER)
  #define _U_ __pragma(warning(suppress:4100))
#else
  #define _U_
#endif

/*
 * WS_NORETURN, before a function declaration, means "this function
 * never returns".  (It must go before the function declaration, e.g.
 * "extern WS_NORETURN func(...)" rather than after the function
 * declaration, as the MSVC version has to go before the declaration.)
 */
#ifndef __cplusplus
  #define WS_NORETURN _Noreturn
#else /* __cplusplus */
#if __has_attribute(noreturn) \
    || WS_IS_AT_LEAST_GNUC_VERSION(2,5) \
    || WS_IS_AT_LEAST_SUNC_VERSION(5,9) \
    || WS_IS_AT_LEAST_XL_C_VERSION(10,1) \
    || WS_IS_AT_LEAST_HP_C_VERSION(6,10)
  /*
   * Compiler with support for __attribute__((noreturn)), or GCC 2.5 and
   * later, or Solaris Studio 12 (Sun C 5.9) and later, or IBM XL C 10.1
   * and later (do any earlier versions of XL C support this?), or
   * HP aCC A.06.10 and later.
   */
  #define WS_NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER)
  /*
   * MSVC.
   */
  #define WS_NORETURN __declspec(noreturn)
#else
  #define WS_NORETURN
#endif
#endif /* __cplusplus */

/*
 * WS_RETNONNULL, before a function declaration, means "this function
 * always returns a non-null pointer".
 */
#if __has_attribute(returns_nonnull) \
    || WS_IS_AT_LEAST_GNUC_VERSION(4,9)
  #define WS_RETNONNULL __attribute__((returns_nonnull))
#else
  #define WS_RETNONNULL
#endif

/*
 * WS_THREAD_LOCAL means "this variable should go in thread-local
 * storage.
 *
 * Based on
 *
 *   https://en.wikipedia.org/w/index.php?title=Thread-local_storage&oldid=1064900318#C_and_C++
 *
 * the major UN*X C compilers support __thread and the major Windows C
 * compilers support __declspec(thread).
 */
#ifdef _WIN32
  #define WS_THREAD_LOCAL __declspec(thread)
#else
  #define WS_THREAD_LOCAL __thread
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_ATTRIBUTES_H__ */
