/* xmpp-jingle.h
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef XMPP_JINGLE_H
#define XMPP_JINGLE_H

#include "packet-xmpp-utils.h"

extern void xmpp_jingle(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_jinglenodes_services(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_jinglenodes_channel(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

#endif /* XMPP_JINGLE_H */

