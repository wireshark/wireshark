/* packet-tn5250.h
 * Headers for tn5250.packet dissection
 *
 * Reference:
 *  5494 Remote Control Unit - Functions Reference
 *  Release 3.0 Document Number SC30-3533-04
 *  Chapters 12, 15, 16
 *
 * Copyright 2009, Robert Hogan <robert@roberthogan.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef TN5250_H_INCLUDED
#define TN5250_H_INCLUDED

void add_tn5250_conversation(packet_info *pinfo _U_, int tn5250e);
int find_tn5250_conversation(packet_info *pinfo _U_);
#endif
