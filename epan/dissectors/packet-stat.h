/* packet-stat.h
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_STAT_H
#define PACKET_STAT_H

#define STAT_PROGRAM  100024

#define STATPROC_NULL 0
#define STATPROC_STAT 1
#define STATPROC_MON 2
#define STATPROC_UNMON 3
#define STATPROC_UNMON_ALL 4
#define STATPROC_SIMU_CRASH 5
#define STATPROC_NOTIFY 6

#endif
