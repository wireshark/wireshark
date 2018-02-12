/* packet-bfd.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_BFD_H
#define PACKET_BFD_H

void dissect_bfd_mep (tvbuff_t *tvb, proto_tree *tree, const int hfindex);

#endif
