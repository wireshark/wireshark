/* packet-reload.h
 * RELOAD dissection utilities
 * Author: Stephane Bryant
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_RELOAD_H__
#define __PACKET_RELOAD_H__

extern int dissect_reload_messagecontents(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint16_t offset, uint16_t length);

#endif
