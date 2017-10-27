/* ws_diag_control.h
 * Turn compiler diagnostic messages on and off.
 *
 * From FreeRADIUS build.h.
 *
 * @copyright 2013 The FreeRADIUS server project
 *
 * That project is covered by the GPLv2, so:
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __WS_DIAG_CONTROL_H__
#define __WS_DIAG_CONTROL_H__

#include "ws_compiler_tests.h"

#ifdef __cplusplus
extern "C" {
#endif

#define XSTRINGIFY(x) #x

/*
 *	Macros for controlling warnings in GCC >= 4.2 and clang >= 2.8
 */
#define DIAG_JOINSTR(x,y) XSTRINGIFY(x ## y)
#define DIAG_DO_PRAGMA(x) _Pragma (#x)

#if defined(__clang__)
  /*
   * Clang, so we'd use _Pragma("clang diagnostic XXX"), if it's
   * supported.
   */
  #if WS_IS_AT_LEAST_CLANG_VERSION(2,8)
    /*
     * This is Clang 2.8 or later: we can use "clang diagnostic ignored -Wxxx"
     * and "clang diagnostic push/pop".
     */
    #define DIAG_PRAGMA(x) DIAG_DO_PRAGMA(clang diagnostic x)
    #define DIAG_OFF(x) DIAG_PRAGMA(push) DIAG_PRAGMA(ignored DIAG_JOINSTR(-W,x))
    #define DIAG_ON(x) DIAG_PRAGMA(pop)
  #endif
#elif defined(__GNUC__)
  /*
   * GCC, or a compiler (other than Clang) that claims to be GCC.
   * We assume that the compiler accepts _Pragma("GCC diagnostic xxx")
   * even if it's only claiming to be GCC.
   */
  #if WS_IS_AT_LEAST_GNUC_VERSION(4,8)
    /*
     * This is GCC 4.8 or later, or a compiler claiming to be that.
     * We can use "GCC diagnostic ignored -Wxxx" (introduced in 4.2)
     * and "GCC diagnostic push/pop" (introduced in 4.6), *and* gcc
     * supports "-Wpedantic" (introduced in 4.8), allowing us to
     * turn off pedantic warnings with DIAG_OFF().
     */
    #define DIAG_PRAGMA(x) DIAG_DO_PRAGMA(GCC diagnostic x)
    #define DIAG_OFF(x) DIAG_PRAGMA(push) DIAG_PRAGMA(ignored DIAG_JOINSTR(-W,x))
    #define DIAG_ON(x) DIAG_PRAGMA(pop)
  #endif
#endif

#ifndef DIAG_OFF
  /*
   * This is none of the above; we don't have any way to turn diagnostics
   * on or off.
   *
   * XXX - you can do that in MSVC, but it's done differently; we'd
   * have to have macros for *particular* diagnostics, using the
   * warning flag for GCC and Clang and the error number for MSVC.
   */
  #define DIAG_OFF(x)
  #define DIAG_ON(x)
#endif

/* Use for clang specific pragmas, so we can keep -Wpragmas enabled */
#ifdef __clang__
#  define DIAG_OFF_CLANG(x) DIAG_OFF(x)
#  define DIAG_ON_CLANG(x)  DIAG_ON(x)
#else
#  define DIAG_OFF_CLANG(x)
#  define DIAG_ON_CLANG(x)
#endif

/*
 *	For dealing with APIs which are only deprecated in macOS (like the
 *	OpenSSL and MIT/Heimdal Kerberos APIs).
 *
 *	Dear Apple: this is a cross-platform program, and we're not
 *	going to use your Shiny New Frameworks on macOS unless there's
 *	a sufficiently clear benefit to make it worth our while to have
 *	both macOS and non-macOS versions of the code.
 */
#ifdef __APPLE__
#  define USES_APPLE_DEPRECATED_API DIAG_OFF(deprecated-declarations)
#  define USES_APPLE_RST DIAG_ON(deprecated-declarations)
#else
#  define USES_APPLE_DEPRECATED_API
#  define USES_APPLE_RST
#endif

#ifdef __cplusplus
}
#endif
#endif /* __WS_DIAG_CONTROL_H__ */
