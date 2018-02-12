/* packet-nisplus.h
 * 2001  Ronnie Sahlberg  <See AUTHORS for email>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
