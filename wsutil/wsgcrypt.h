/* wsgcrypt.h
 *
 * Wrapper around libgcrypt's include file gcrypt.h.
 * For libgcrypt 1.5.0, including gcrypt.h directly brings up lots of
 * compiler warnings about deprecated definitions.
 * Try to work around these warnings to ensure a clean build with -Werror.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
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

#ifndef __WSGCRYPT_H__
#define __WSGCRYPT_H__

#ifdef HAVE_LIBGCRYPT

#ifdef __CLANG__

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <gcrypt.h>
#pragma clang diagnostic pop

#else

#if defined(__GNUC__) && defined(__GNUC_MINOR__)
#define _GCC_VERSION (__GNUC__*100 + __GNUC_MINOR__*10)
#else
#define _GCC_VERSION 0
#endif

/* check the gcc version
   pragma GCC diagnostic error/warning was introduced in gcc 4.2.0
   pragma GCC diagnostic push/pop was introduced in gcc 4.6.0 */

#if _GCC_VERSION<420

/* no gcc or gcc version<4.2.0: we can't do anything */
#include <gcrypt.h>

#elif _GCC_VERSION<460

/* gcc version is between 4.2.0 and 4.6.0:
   diagnostic warning/error is supported, diagnostic push/pop is not supported */
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <gcrypt.h>
#pragma GCC diagnostic error "-Wdeprecated-declarations"

#else

/* gcc version is >= 4.6.0: we can use push/pop */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#include <gcrypt.h>
#pragma GCC diagnostic pop

#endif /* _GCC_VERSION */

#endif /* __CLANG__ */

#endif /* HAVE_LIBGCRYPT */

#endif /* __WSGCRYPT_H__ */
