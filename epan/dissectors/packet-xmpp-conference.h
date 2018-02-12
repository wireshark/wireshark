/* xmpp-conference.h
 *
 * Copyright 2011, Mariusz Okroj <okrojmariusz[]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef XMPP_CONFERENCE_H
#define XMPP_CONFERENCE_H

#include "packet-xmpp-utils.h"

extern void xmpp_conferece_info_advert(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);
extern void xmpp_conference_info(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, xmpp_element_t *element);

#endif /* XMPP_CONFERENCE_H */

