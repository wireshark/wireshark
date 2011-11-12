/* xmpp-core.h
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

#ifndef XMPP_CORE_H
#define XMPP_CORE_H

extern void xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
    packet_info *pinfo, element_t *packet, gint hf, gint ett, const char *col_info);
extern void xmpp_failure(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_xml_header(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_stream(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern gboolean xmpp_stream_close(proto_tree *tree, tvbuff_t *tvb, packet_info* pinfo);
extern void xmpp_features(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_starttls(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
extern void xmpp_proceed(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, element_t *packet);
#endif /* XMPP_CORE_H */

