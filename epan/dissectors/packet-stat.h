/* packet-stat.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
