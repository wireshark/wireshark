/* packet-nisplus.h
 * 2001  Ronnie Sahlberg  <See AUTHORS for email>
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

#ifndef PACKET_NIS_H
#define PACKET_NIS_H

#define NISPROC_NULL		0
#define NISPROC_LOOKUP		1
#define NISPROC_ADD		2
#define NISPROC_MODIFY		3
#define NISPROC_REMOVE		4
#define NISPROC_IBLIST		5
#define NISPROC_IBADD		6
#define NISPROC_IBMODIFY	7
#define NISPROC_IBREMOVE	8
#define NISPROC_IBFIRST		9
#define NISPROC_IBNEXT		10

#define NISPROC_FINDDIRECTORY	12

#define NISPROC_STATUS		14
#define NISPROC_DUMPLOG		15
#define NISPROC_DUMP		16
#define NISPROC_CALLBACK	17
#define NISPROC_CPTIME		18
#define NISPROC_CHECKPOINT	19
#define NISPROC_PING		20
#define NISPROC_SERVSTATE	21
#define NISPROC_MKDIR		22
#define NISPROC_RMDIR		23
#define NISPROC_UPDKEYS		24

#define NIS_PROGRAM 100300


#define CBPROC_NULL		0
#define CBPROC_RECEIVE		1
#define CBPROC_FINISH		2
#define CBPROC_ERROR		3

#define CB_PROGRAM 100302

#endif
