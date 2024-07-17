/* packet-mstp.h
 * Routines for BACnet MS/TP datalink dissection
 * Copyright 2008 Steve Karg <skarg@users.sourceforge.net> Alabama
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __MSTP_H__
#define __MSTP_H__

/**
 * Returns a value string for the BACnet MS/TP Frame Type.
 * @param val BACnet MS/TP Frame value
 * @return constant C String with MS/TP Frame Type
 */
const char *
mstp_frame_type_text(uint32_t val);

/**
 * Dissects the BACnet MS/TP packet after the preamble,
 * starting with the MS/TP Frame type octet.  Passes
 * the PDU, if there is one, to the BACnet dissector.
 * @param tvb the tv buffer of the current data
 * @param pinfo the packet info of the current data
 * @param tree the tree to append this item to
 * @param subtree the sub tree to append this item to
 * @param offset the offset in the tvb
 */
void
dissect_mstp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *subtree, int offset);

#endif /* __MSTP_H__ */


