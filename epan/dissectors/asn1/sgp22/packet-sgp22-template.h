/* packet-sgp22.h
 * Routines for SGP.22 packet dissection.
 *
 * Copyright 2025, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_SGP22_H
#define PACKET_SGP22_H

#include "packet-sgp22-val.h"

#include "packet-sgp22-exp.h"

unsigned get_rsp_tag(tvbuff_t *tvb, uint32_t *tag);
bool is_rsp_asn1_header(tvbuff_t *tvb, uint32_t *tag);

bool is_sgp22_request(tvbuff_t *tvb);
bool is_sgp22_response(tvbuff_t *tvb);

int dissect_sgp22_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);
int dissect_sgp22_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

#endif  /* PACKET_SGP22_H */
