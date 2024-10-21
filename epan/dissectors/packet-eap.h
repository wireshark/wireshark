/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_EAP_H__
#define __PACKET_EAP_H__

extern bool dissect_eap_identity_3gpp(tvbuff_t *tvb, packet_info* pinfo, proto_tree* tree, int offset, int size);

#endif /* __PACKET_EAP_H__ */
