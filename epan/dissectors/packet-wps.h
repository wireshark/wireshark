/* packet-wps.h
 *
 * Wifi Simple Config aka Wifi Protected Setup
 *
 * Written by Jens Braeuer using WiFi-Alliance Spec 1.0h and
 * parts of a patch by JP Jiang and Philippe Teuwen. November 2007
 *
 * Spec:
 * https://www.wi-fi.org/knowledge_center_overview.php?type=4
 * Patch:
 * http://wireshark.digimirror.nl/lists/wireshark-dev/200703/msg00121.html
 *
 * Copyright 2007 Jens Braeuer <jensb@cs.tu-berlin.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef _packet_wps_h_
#define _packet_wps_h_

 /* Vendor-Type and Vendor-id */
#define WFA_VENDOR_ID         0x00372A
#define WFA_SIMPLECONFIG_TYPE 0x1

void
dissect_wps_tlvs(proto_tree *eap_tree, tvbuff_t *tvb, int offset,
		 int size, packet_info* pinfo);

#endif
