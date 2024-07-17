/* packet-ncp-sss.h
 * Declarations of routines for Novell SecretStore Services
 * Greg Morris <gmorris@novell.com>
 * Copyright (c) Novell, Inc. 2002-2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NCP_SSS_H__
#define __PACKET_NCP_SSS_H__

void
dissect_sss_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ncp_tree, ncp_req_hash_value *request_value);

void
dissect_sss_reply(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ncp_tree, uint8_t subfunc, ncp_req_hash_value	*request_value);

#endif
