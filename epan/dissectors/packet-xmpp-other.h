/* xmpp-others.h
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef XMPP_OTHER_H
#define XMPP_OTHER_H

#include "packet-xmpp-utils.h"

extern void xmpp_iq_bind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_session(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_vcard(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

extern void xmpp_disco_items_query(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, xmpp_element_t *element);
extern void xmpp_roster_query(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo, xmpp_element_t *element);
extern void xmpp_disco_info_query(proto_tree *tree,  tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_bytestreams_query(proto_tree *tree,  tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

extern void xmpp_si(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);

extern void xmpp_feature_neg(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
extern void xmpp_x_data(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);

extern void xmpp_ibb_open(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_ibb_close(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_ibb_data(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

extern void xmpp_delay(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

extern void xmpp_presence_caps(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

extern void xmpp_vcard_x_update(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);

extern void xmpp_x_event(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

extern void xmpp_muc_x(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_muc_user_x(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_muc_owner_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_muc_admin_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

extern void xmpp_last_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_version_query(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

extern void xmpp_ping(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_hashes(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

extern void xmpp_jitsi_inputevt(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
#endif /* XMPP_OTHER_H */

