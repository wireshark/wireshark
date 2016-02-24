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

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern
gboolean capture_ieee80211 (const guchar *, int, int, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header);
gboolean capture_ieee80211_datapad (const guchar *, int, int, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header);

extern
gboolean capture_wlancap(const guchar *, int, int, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header);

void dissect_wifi_p2p_ie(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                         int offset, gint size);
int dissect_wifi_p2p_public_action(packet_info *pinfo, proto_tree *tree,
                                   tvbuff_t *tvb, int offset);
int dissect_wifi_p2p_action(proto_tree *tree, tvbuff_t *tvb, int offset);
void dissect_wifi_p2p_anqp(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb,
                           int offset, gboolean request);

void dissect_wifi_display_ie(packet_info *pinfo, proto_tree *tree,
                             tvbuff_t *tvb, int offset, gint size);

int add_tagged_field(packet_info *pinfo, proto_tree *tree,
                            tvbuff_t *tvb, int offset, int ftype,
                            const guint8 *valid_element_ids,
                            guint valid_element_ids_count);

#define MAX_SSID_LEN    32
#define MAX_PROTECT_LEN 10

/*
 * Table of data rates, indexed by MCS index, bandwidth (0 for 20, 1 for 40),
 * amd guard interval (0 for long, 1 for short).
 */
#define MAX_MCS_INDEX 76

WS_DLL_PUBLIC const guint16 ieee80211_ht_Dbps[MAX_MCS_INDEX+1];
float ieee80211_htrate(int mcs_index, gboolean bandwidth, gboolean short_gi);

WS_DLL_PUBLIC value_string_ext ieee80211_supported_rates_vals_ext;

WS_DLL_PUBLIC
gboolean is_broadcast_bssid(const address *bssid);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*
 * Extract the protocol version from the frame control field
 */
#define FCF_PROT_VERSION(x)  ((x) & 0x3)

/*
 * Extract the frame type from the frame control field.
 */
#define FCF_FRAME_TYPE(x)    (((x) & 0xC) >> 2)

/*
 * Extract the frame subtype from the frame control field.
 */
#define FCF_FRAME_SUBTYPE(x) (((x) & 0xF0) >> 4)

/*
 * Extract the control frame extension from the frame control field.
 */
#define FCF_FRAME_EXTENSION(x) (((x) & 0xF00) >> 8)

/*
 * Checks if the frame is control frame extension.
 */
#define IS_FRAME_EXTENSION(x) ((FCF_FRAME_TYPE(x) == 0x1 && FCF_FRAME_SUBTYPE(x) == 0x6) ? 1 : 0)

/*
 * Convert the frame type and subtype from the frame control field into
 * one of the MGT_, CTRL_, or DATA_ values.
 * Now includes extension subtype in case present.
 */
#define COMPOSE_FRAME_TYPE(x) ((FCF_FRAME_TYPE(x) == 0x1 && FCF_FRAME_SUBTYPE(x) == 0x6) ? (((x & 0x0C)<< 6) + ((x) & 0xF0) + FCF_FRAME_EXTENSION(x)) : (((x & 0x0C)<< 2)+FCF_FRAME_SUBTYPE(x)))  /* Create key to (sub)type */

/*
 * The subtype field of a data frame is, in effect, composed of 4 flag
 * bits - CF-Ack, CF-Poll, Null (means the frame doesn't actually have
 * any data), and QoS.
 */
#define DATA_FRAME_IS_CF_ACK(x)  ((x) & 0x01)
#define DATA_FRAME_IS_CF_POLL(x) ((x) & 0x02)
#define DATA_FRAME_IS_NULL(x)    ((x) & 0x04)
#define DATA_FRAME_IS_QOS(x)     ((x) & 0x08)

/*
 * Extract the flags from the frame control field.
 * Now includes subset of flags when the subtype is control frame extension.
 */
#define FCF_FLAGS(x)           ((FCF_FRAME_TYPE(x) == 0x1 && FCF_FRAME_SUBTYPE(x) == 0x6) ? (((x) & 0xF000) >> 12) : (((x) & 0xFF00) >> 8))

/*
 * Bits from the flags field.
 */
#define FLAG_TO_DS            0x01
#define FLAG_FROM_DS          0x02
#define FLAG_MORE_FRAGMENTS   0x04
#define FLAG_RETRY            0x08
#define FLAG_POWER_MGT        0x10
#define FLAG_MORE_DATA        0x20
#define FLAG_PROTECTED        0x40
#define FLAG_ORDER            0x80    /* overloaded for "has HT control" */

/*
 * Test bits in the flags field.
 */
/*
 * XXX - Only HAVE_FRAGMENTS, IS_PROTECTED, and HAS_HT_CONTROL
 * are in use.  Should the rest be removed?
 */
#define IS_TO_DS(x)            ((x) & FLAG_TO_DS)
#define IS_FROM_DS(x)          ((x) & FLAG_FROM_DS)
#define HAVE_FRAGMENTS(x)      ((x) & FLAG_MORE_FRAGMENTS)
#define IS_RETRY(x)            ((x) & FLAG_RETRY)
#define POWER_MGT_STATUS(x)    ((x) & FLAG_POWER_MGT)
#define HAS_MORE_DATA(x)       ((x) & FLAG_MORE_DATA)
#define IS_PROTECTED(x)        ((x) & FLAG_PROTECTED)
#define IS_STRICTLY_ORDERED(x) ((x) & FLAG_ORDER)      /* for non-QoS data frames */
#define HAS_HT_CONTROL(x)      ((x) & FLAG_ORDER)      /* for management and QoS data frames */

/*
 * Extract subfields from the flags field.
 */
#define FLAGS_DS_STATUS(x)          ((x) & (FLAG_FROM_DS|FLAG_TO_DS))

/*
 * Extract an indication of the types of addresses in a data frame from
 * the frame control field.
 */
#define FCF_ADDR_SELECTOR(x) ((x) & ((FLAG_TO_DS|FLAG_FROM_DS) << 8))

#define DATA_ADDR_T1         0
#define DATA_ADDR_T2         (FLAG_FROM_DS << 8)
#define DATA_ADDR_T3         (FLAG_TO_DS << 8)
#define DATA_ADDR_T4         ((FLAG_TO_DS|FLAG_FROM_DS) << 8)

/*
 * COMPOSE_FRAME_TYPE() values for management frames.
 */
#define MGT_ASSOC_REQ          0x00  /* association request        */
#define MGT_ASSOC_RESP         0x01  /* association response       */
#define MGT_REASSOC_REQ        0x02  /* reassociation request      */
#define MGT_REASSOC_RESP       0x03  /* reassociation response     */
#define MGT_PROBE_REQ          0x04  /* Probe request              */
#define MGT_PROBE_RESP         0x05  /* Probe response             */
#define MGT_MEASUREMENT_PILOT  0x06  /* Measurement Pilot          */
#define MGT_BEACON             0x08  /* Beacon frame               */
#define MGT_ATIM               0x09  /* ATIM                       */
#define MGT_DISASS             0x0A  /* Disassociation             */
#define MGT_AUTHENTICATION     0x0B  /* Authentication             */
#define MGT_DEAUTHENTICATION   0x0C  /* Deauthentication           */
#define MGT_ACTION             0x0D  /* Action                     */
#define MGT_ACTION_NO_ACK      0x0E  /* Action No Ack              */
#define MGT_ARUBA_WLAN         0x0F  /* Aruba WLAN Specific        */

/*
 * COMPOSE_FRAME_TYPE() values for control frames.
 * 0x160 - 0x16A are for control frame extension where type = 1 and subtype =6.
 */
#define CTRL_BEAMFORM_RPT_POLL 0x14  /* Beamforming Report             */
#define CTRL_VHT_NDP_ANNC      0x15  /* VHT NDP Announcement           */
#define CTRL_POLL              0x162  /* Poll                          */
#define CTRL_SPR               0x163  /* Service Period Request        */
#define CTRL_GRANT             0x164  /* Grant                         */
#define CTRL_DMG_CTS           0x165  /* DMG Clear to Send             */
#define CTRL_DMG_DTS           0x166  /* DMG Denial to Send            */
#define CTRL_GRANT_ACK         0x167  /* Grant Acknowledgment          */
#define CTRL_SSW               0x168  /* Sector Sweep                  */
#define CTRL_SSW_FEEDBACK      0x169  /* Sector Sweep Feedback         */
#define CTRL_SSW_ACK           0x16A  /* Sector Sweep Acknowledgment   */
#define CTRL_CONTROL_WRAPPER   0x17  /* Control Wrapper                */
#define CTRL_BLOCK_ACK_REQ     0x18  /* Block ack Request              */
#define CTRL_BLOCK_ACK         0x19  /* Block ack                      */
#define CTRL_PS_POLL           0x1A  /* power-save poll                */
#define CTRL_RTS               0x1B  /* request to send                */
#define CTRL_CTS               0x1C  /* clear to send                  */
#define CTRL_ACKNOWLEDGEMENT   0x1D  /* acknowledgement                */
#define CTRL_CFP_END           0x1E  /* contention-free period end     */
#define CTRL_CFP_ENDACK        0x1F  /* contention-free period end/ack */

/*
 * COMPOSE_FRAME_TYPE() values for data frames.
 */
#define DATA                        0x20  /* Data                       */
#define DATA_CF_ACK                 0x21  /* Data + CF-Ack              */
#define DATA_CF_POLL                0x22  /* Data + CF-Poll             */
#define DATA_CF_ACK_POLL            0x23  /* Data + CF-Ack + CF-Poll    */
#define DATA_NULL_FUNCTION          0x24  /* Null function (no data)    */
#define DATA_CF_ACK_NOD             0x25  /* CF-Ack (no data)           */
#define DATA_CF_POLL_NOD            0x26  /* CF-Poll (No data)          */
#define DATA_CF_ACK_POLL_NOD        0x27  /* CF-Ack + CF-Poll (no data) */

#define DATA_QOS_DATA               0x28  /* QoS Data                   */
#define DATA_QOS_DATA_CF_ACK        0x29  /* QoS Data + CF-Ack        */
#define DATA_QOS_DATA_CF_POLL       0x2A  /* QoS Data + CF-Poll      */
#define DATA_QOS_DATA_CF_ACK_POLL   0x2B  /* QoS Data + CF-Ack + CF-Poll    */
#define DATA_QOS_NULL               0x2C  /* QoS Null        */
#define DATA_QOS_CF_POLL_NOD        0x2E  /* QoS CF-Poll (No Data)      */
#define DATA_QOS_CF_ACK_POLL_NOD    0x2F  /* QoS CF-Ack + CF-Poll (No Data) */

/*
 * COMPOSE_FRAME_TYPE() values for extension frames.
 */
#define EXTENSION_DMG_BEACON         0x30  /* Extension DMG beacon */

typedef struct _wlan_stats {
  guint8 channel;
  guint8 ssid_len;
  guchar ssid[MAX_SSID_LEN];
  gchar protection[MAX_PROTECT_LEN];
} wlan_stats_t;

typedef struct _wlan_hdr {
  address bssid;
  address src;
  address dst;
  guint16 type;
  struct _wlan_stats stats;
} wlan_hdr_t;

#define WLANCAP_MAGIC_COOKIE_BASE 0x80211000
#define WLANCAP_MAGIC_COOKIE_V1 0x80211001
#define WLANCAP_MAGIC_COOKIE_V2 0x80211002

/* UAT entry structure. */
typedef struct {
  guint8    key;
  gchar    *string;
} uat_wep_key_record_t;

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
