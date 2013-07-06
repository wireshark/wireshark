/* moduleinfo.h
 *
 * Module info header for wireshark plugins.
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

/* Included *after* config.h, in order to re-define these macros */

#ifdef PACKAGE
#undef PACKAGE
#endif

/* Name of package */
#define PACKAGE "wimax"


#ifdef VERSION
#undef VERSION
#endif

/* Version number of package */

#define stringiz1(x) #x
#define stringize(x) stringiz1(x)

#ifndef BUILD_NUMBER
#define BUILD_NUMBER 0
#endif

#define VERSION "1.1." stringize(BUILD_NUMBER)

