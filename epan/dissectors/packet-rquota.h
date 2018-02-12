/* packet-rquota.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RQUOTA_H
#define PACKET_RQUOTA_H

#define RQUOTAPROC_NULL 		0
#define RQUOTAPROC_GETQUOTA		1
#define RQUOTAPROC_GETACTIVEQUOTA	2
#define RQUOTAPROC_SETQUOTA		3
#define RQUOTAPROC_SETACTIVEQUOTA	4

#define RQUOTA_PROGRAM 100011

#endif
