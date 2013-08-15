/*
 * Cross platform defines for exporting symbols from shared libraries
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Balint Reczey <balint@balintreczey.hu>
 * Copyright 2013 Balint Reczey
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

/** Reset symbol export behavior.
 * If you {un}define WS_BUILD_DLL on the fly you'll have to define this
 * as well.
 */
#ifdef RESET_SYMBOL_EXPORT

#ifdef SYMBOL_EXPORT_H
#undef SYMBOL_EXPORT_H
#endif

#ifdef WS_DLL_PUBLIC
#undef WS_DLL_PUBLIC
#endif

#ifdef WS_DLL_PUBLIC_NOEXTERN
#undef WS_DLL_PUBLIC_NOEXTERN
#endif

#ifdef WS_DLL_LOCAL
#undef WS_DLL_LOCAL
#endif

#endif /* RESET_SYMBOL_EXPORT */

#ifndef SYMBOL_EXPORT_H
#define SYMBOL_EXPORT_H

/* Originally copied from GCC Wiki at http://gcc.gnu.org/wiki/Visibility */
#if defined _WIN32 || defined __CYGWIN__
  #ifdef WS_BUILD_DLL
    #ifdef __GNUC__
#define WS_DLL_PUBLIC __attribute__ ((dllexport))
    #else /* ! __GNUC__ */
#define WS_DLL_PUBLIC __declspec(dllexport) /* Note: actually gcc seems to also support this syntax. */
    #endif /* __GNUC__ */
  #else
    #ifdef __GNUC__
#define WS_DLL_PUBLIC __attribute__ ((dllimport))
    #elif ! (defined ENABLE_STATIC) /* ! __GNUC__ */
#define WS_DLL_PUBLIC __declspec(dllimport) /* Note: actually gcc seems to also support this syntax. */
    #else /* ! __GNUC__  && ENABLE_STATIC */
#define WS_DLL_PUBLIC
    #endif /* __GNUC__ */
  #endif /* WS_BUILD_DLL */
  #define WS_DLL_PUBLIC_NOEXTERN WS_DLL_PUBLIC
  #define WS_DLL_LOCAL
#else
  #if __GNUC__ >= 4
#define WS_DLL_PUBLIC __attribute__ ((visibility ("default"))) extern
#define WS_DLL_PUBLIC_NOEXTERN __attribute__ ((visibility ("default")))
#define WS_DLL_LOCAL  __attribute__ ((visibility ("hidden")))
  #else /* ! __GNUC__ >= 4 */
    #define WS_DLL_PUBLIC
    #define WS_DLL_PUBLIC_NOEXTERN
    #define WS_DLL_LOCAL extern
  #endif /* __GNUC__ >= 4 */
#endif

#endif /* SYMBOL_EXPORT_H */
