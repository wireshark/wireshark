/* xmpp-core.h
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef XMPP_CORE_H
#define XMPP_CORE_H

#include "epan/tvbparse.h"

#include "packet-xmpp-utils.h"

extern void xmpp_init_parsers(void);
extern tvbparse_wanted_t *want_ignore;
extern tvbparse_wanted_t *want_stream_end_tag;
extern tvbparse_wanted_t *want_stream_end_with_ns;

extern void xmpp_iq(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        xmpp_element_t *packet);
extern void xmpp_presence(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        xmpp_element_t *packet);
extern void xmpp_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        xmpp_element_t *packet);
extern void xmpp_auth(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        xmpp_element_t *packet);
extern void xmpp_challenge_response_success(proto_tree *tree, tvbuff_t *tvb,
        packet_info *pinfo, xmpp_element_t *packet, expert_field* ei, gint ett,
        const char *col_info);
extern void xmpp_failure(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        xmpp_element_t *packet);
extern void xmpp_xml_header(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        xmpp_element_t *packet);
extern void xmpp_stream(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        xmpp_element_t *packet);
extern gboolean xmpp_stream_close(proto_tree *tree, tvbuff_t *tvb,
        packet_info* pinfo);
extern void xmpp_features(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        xmpp_element_t *packet);
extern void xmpp_starttls(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        xmpp_element_t *packet, xmpp_conv_info_t *xmpp_info);
extern void xmpp_proceed(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
        xmpp_element_t *packet, xmpp_conv_info_t *xmpp_info);
#endif /* XMPP_CORE_H */

