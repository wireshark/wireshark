/* packet-tn3270.h
 * Headers for tn3270.packet dissection
 *
 * Reference:
 * 3270 Information Display System: Data Stream Programmer's Reference
 *  GA23-0059-07
 *
 * Copyright 2009, Robert Hogan <robert@roberthogan.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TN3270_H_INCLUDED
#define TN3270_H_INCLUDED

void add_tn3270_conversation(packet_info *pinfo, int tn3270e, int model);
int find_tn3270_conversation(packet_info *pinfo);

#endif
