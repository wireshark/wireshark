/* inet_addr-int.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifndef __WS_INET_ADDR_INT_H__
#define __WS_INET_ADDR_INT_H__

#include "config.h"

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>		/* needed to define AF_ values on UNIX */
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>	/* needed to define AF_ values on Windows */
#if _MSC_VER < 1600	/* errno.h defines EAFNOSUPPORT in Windows VC10 (and presumably eventually in VC11 ...) */
#define EAFNOSUPPORT    WSAEAFNOSUPPORT
#endif
#endif

/*
 * Versions of "inet_pton()" and "inet_ntop()", for the benefit of OSes that
 * don't have it.
 */
#ifndef HAVE_INET_PTON
extern int inet_pton(int af, const char *src, void *dst);
#endif

#ifndef HAVE_INET_NTOP
extern const char *inet_ntop(int af, const void *src, char *dst, size_t size);
#endif

/*
 * Those OSes may also not have AF_INET6, so declare it here if it's not
 * already declared, so that we can pass it to "inet_ntop()" and "inet_pton()".
 */
#ifndef AF_INET6
#define	AF_INET6	127	/* pick a value unlikely to duplicate an existing AF_ value */
#endif

#endif
