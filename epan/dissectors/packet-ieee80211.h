/* packet-ieee80211.h
 * Routines for Wireless LAN (IEEE 802.11) dissection
 *
 * Copyright 2000, Axis Communications AB
 * Inquiries/bugreports should be sent to Johan.Jorgensen@axis.com
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

void capture_ieee80211 (const guchar *, int, int, packet_counts *);
void capture_ieee80211_datapad (const guchar *, int, int, packet_counts *);
void capture_ieee80211_fixed (const guchar *, int, int, packet_counts *);

void ieee_80211_add_tagged_parameters (tvbuff_t * tvb, int offset,
       packet_info * pinfo, proto_tree * tree, int tagged_parameters_len);

typedef struct _wlan_hdr {
        address bssid;
        address src;
        address dst;
        guint16 type;
} wlan_hdr;
