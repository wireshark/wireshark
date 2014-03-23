/* packet-ieee80211.h
 * Routines for Wireless LAN (IEEE 802.11) dissection
 *
 * Copyright 2000, Axis Communications AB
 * Inquiries/bugreports should be sent to Johan.Jorgensen@axis.com
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "ws_symbol_export.h"

WS_DLL_PUBLIC
void capture_ieee80211 (const guchar *, int, int, packet_counts *);
void capture_ieee80211_datapad (const guchar *, int, int, packet_counts *);
void capture_ieee80211_fixed (const guchar *, int, int, packet_counts *);
void capture_ieee80211_ht (const guchar *, int, int, packet_counts *);

WS_DLL_PUBLIC
void capture_prism(const guchar *, int, int, packet_counts *);
WS_DLL_PUBLIC
void capture_wlancap(const guchar *, int, int, packet_counts *);

void dissect_wifi_p2p_ie(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
			 int offset, gint size);
int dissect_wifi_p2p_public_action(packet_info *pinfo, proto_tree *tree,
                                   tvbuff_t *tvb, int offset);
int dissect_wifi_p2p_action(proto_tree *tree, tvbuff_t *tvb, int offset);
void dissect_wifi_p2p_anqp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
			   int offset, gboolean request);

void dissect_wifi_display_ie(packet_info *pinfo, proto_tree *tree,
			     tvbuff_t *tvb, int offset, gint size);

#define MAX_SSID_LEN    32
#define MAX_PROTECT_LEN 10

struct _wlan_stats {
  guint8 channel;
  guint8 ssid_len;
  guchar ssid[MAX_SSID_LEN];
  gchar protection[MAX_PROTECT_LEN];
};

typedef struct _wlan_hdr {
        address bssid;
        address src;
        address dst;
        guint16 type;
        struct _wlan_stats stats;
} wlan_hdr;

#define WLANCAP_MAGIC_COOKIE_BASE 0x80211000
#define WLANCAP_MAGIC_COOKIE_V1 0x80211001
#define WLANCAP_MAGIC_COOKIE_V2 0x80211002

/* UAT entry structure. */
typedef struct {
    guint8    key;
    gchar    *string;
} uat_wep_key_record_t;
