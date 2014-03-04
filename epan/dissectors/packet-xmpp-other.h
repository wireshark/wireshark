/* xmpp-others.h
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

