/** @file
 * Compatibility definitions for using zlib and zlib-ng.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* The zlib-ng library inflates/deflates streams 40% faster
 * than the classic (and largely inactively maintained) zlib library.
 * The two libraries have different APIs, although zlib-ng may also
 * include a "compatibility mode" to offer the zlib API.
 * Not all distributions include this mode.
 *
 * This header aims to smooth the use of both libraries when the differences
 * don't matter, by using some strategic #defines and typedefs.
 * It builds on and generalizes the work started in !15815.
 *
 * Usage guidelines:
 * 1) unconditionally include this header instead of
 *    conditionally including either <zlib.h> or <zlib-ng.h>
 * 2) wrap zlib-dependent blocks in #ifdef USE_ZLIB_OR_ZLIBNG ... #endif
 * 2) use zlib_stream instead of either z_stream or zng_stream
 * 3) use zlib_streamp instead of either z_streamp or zng_streamp
 * 4) wrap the names of zlib functions in ZLIB_PREFIX()
 * 5a) If you need code specific to zlib or zlib-ng, then use this pattern
 *     to prevent the potentially-present compatibility mode from causing
 *     trouble:
 *
 *      #ifdef USE_ZLIB_OR_ZLIBNG
 *        #ifdef HAVE_ZLIBNG
 *          (zlib-ng specific code)
 *        #else
 *          (zlib specific code)
 *        #endif
 *      #endif
 *
 * 5b) ... but consider whether your use case is common enough that you could
 *     add an abstraction to this file instead.
 */

#ifndef __ZLIB_COMPAT_H__
#define __ZLIB_COMPAT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


#if defined(HAVE_ZLIB) && !defined(HAVE_ZLIBNG)
#define USE_ZLIB_OR_ZLIBNG
#define ZLIB_CONST
#define ZLIB_PREFIX(x) x
#include <zlib.h>
typedef z_stream zlib_stream;
typedef z_streamp zlib_streamp;
#endif /* defined(HAVE_ZLIB) && !defined(HAVE_ZLIBNG) */

#ifdef HAVE_ZLIBNG
#define USE_ZLIB_OR_ZLIBNG
#define HAVE_INFLATEPRIME 1
#define ZLIB_PREFIX(x) zng_ ## x
#include <zlib-ng.h>
typedef zng_stream zlib_stream;
typedef zng_streamp zlib_streamp;
#endif /* HAVE_ZLIBNG */


#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ZLIB_COMPAT_H__ */
