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
 *
 */

#ifndef _packet_wps_h_
#define _packet_wps_h_

void
dissect_exteap_wps(proto_tree *eap_tree, tvbuff_t *tvb, int offset,
		   gint size, packet_info* pinfo);
void
dissect_wps_tlvs(proto_tree *eap_tree, tvbuff_t *tvb, int offset,
		 gint size, packet_info* pinfo);

#endif
