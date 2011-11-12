/* xmpp-gtalk.h
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef XMPP_GTALK_H
#define XMPP_GTALK_H

extern void xmpp_gtalk_session(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_jingleinfo_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_usersetting(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_nosave_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_nosave_x(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_mail_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_mail_mailbox(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_mail_new_mail(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_status_query(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
extern void xmpp_gtalk_transport_p2p(proto_tree* tree, tvbuff_t* tvb, packet_info* pinfo, element_t* element);
#endif /* XMPP_GTALK_H */

