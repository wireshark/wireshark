/* xmpp-gtalk.h
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef XMPP_GTALK_H
#define XMPP_GTALK_H

#include "packet-xmpp-utils.h"

extern void xmpp_gtalk_session(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
extern void xmpp_gtalk_jingleinfo_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
extern void xmpp_gtalk_usersetting(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
extern void xmpp_gtalk_nosave_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
extern void xmpp_gtalk_nosave_x(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
extern void xmpp_gtalk_mail_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
extern void xmpp_gtalk_mail_mailbox(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
extern void xmpp_gtalk_mail_new_mail(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
extern void xmpp_gtalk_status_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
extern void xmpp_gtalk_transport_p2p(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, xmpp_element_t* element);
#endif /* XMPP_GTALK_H */

