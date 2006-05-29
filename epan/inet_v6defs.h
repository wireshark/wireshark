/* inet_v6defs.h
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __INET_V6DEFS_H__
#define __INET_V6DEFS_H__

/*
 * Versions of "inet_pton()" and "inet_ntop()", for the benefit of OSes that
 * don't have it.
 */
extern int inet_pton(int af, const char *src, void *dst);
#ifndef HAVE_INET_NTOP_PROTO
extern const char *inet_ntop(int af, const void *src, char *dst,
    size_t size);
#endif

/*
 * Those OSes may also not have AF_INET6, so declare it here if it's not
 * already declared, so that we can pass it to "inet_ntop()" and "inet_pton()".
 */
#ifndef AF_INET6
#define	AF_INET6	127	/* pick a value unlikely to duplicate an existing AF_ value */
#endif

/*
 * And if __P isn't defined, define it here, so we can use it in
 * "inet_ntop.c" and "inet_pton.c" (rather than having to change them
 * not to use it).
 */
#ifndef __P
#define __P(args)	args
#endif

#endif
