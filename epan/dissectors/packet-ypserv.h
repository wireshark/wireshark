/* packet-ypserv.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef PACKET_YPSERV_H
#define PACKET_YPSERV_H

#define YPSERV_PROGRAM  100004

#define YPPROC_NULL 0
#define YPPROC_DOMAIN 1
#define YPPROC_DOMAIN_NONACK 2
#define YPPROC_MATCH 3
#define YPPROC_FIRST 4
#define YPPROC_NEXT 5
#define YPPROC_XFR 6
#define YPPROC_CLEAR 7
#define YPPROC_ALL 8
#define YPPROC_MASTER 9
#define YPPROC_ORDER 10
#define YPPROC_MAPLIST 11

#endif
