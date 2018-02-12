/* packet-idmp.h
 * Routines for X.519 Internet Directly Mapped Protocol (IDMP) packet dissection
 * Graeme Lunt 2010
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_IDM_H
#define PACKET_IDM_H

#include <packet-ros.h>

void
register_idmp_protocol_info(const char *oid, const ros_info_t *rinfo, int proto _U_, const char *name);

#endif  /* PACKET_IDM_H */
