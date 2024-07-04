/* packet-t124.h
 * Routines for t124 packet dissection
 * Copyright 2010, Graeme Lunt
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_T124_H
#define PACKET_T124_H

#include <epan/packet_info.h>
#include "packet-per.h"

extern int dissect_DomainMCSPDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);
extern uint32_t t124_get_last_channelId(void);
extern void t124_set_top_tree(proto_tree *tree);

extern void register_t124_ns_dissector(const char *nsKey, dissector_t dissector, int proto);
extern void register_t124_sd_dissector(packet_info *pinfo, uint32_t channelId, dissector_t dissector, int proto);

#include "packet-t124-exp.h"

#endif  /* PACKET_T124_H */


