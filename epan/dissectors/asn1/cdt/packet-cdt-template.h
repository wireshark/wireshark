/* packet-cdt.h
 *
 * Routines for Compressed Data Type packet dissection.
 *
 * Copyright 2005, Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CDT_H
#define PACKET_CDT_H

void dissect_cdt (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree);
#include "packet-cdt-exp.h"

#endif  /* PACKET_CDT_H */

