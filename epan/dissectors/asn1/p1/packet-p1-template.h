/* packet-p3.h
 * Routines for X.411 (X.400 Message Transfer) packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_P1_H
#define PACKET_P1_H

#include "packet-p1-val.h"

void p1_initialize_content_globals (asn1_ctx_t* actx, proto_tree *tree, gboolean report_unknown_cont_type);
const char* p1_get_last_oraddress(asn1_ctx_t* actx);
int dissect_p1_mts_apdu (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data);
#include "packet-p1-exp.h"

void proto_reg_handoff_p1(void);
void proto_register_p1(void);

#endif  /* PACKET_P1_H */
