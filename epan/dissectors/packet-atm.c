/* packet-atm.c
 * Routines for ATM packet disassembly
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/oui.h>
#include <epan/addr_resolv.h>
#include <epan/ppptypes.h>

#include "packet-atm.h"
#include "packet-snmp.h"
#include "packet-eth.h"
#include "packet-tr.h"
#include "packet-llc.h"
#include <epan/prefs.h>
#include "packet-pw-atm.h"

static int proto_atm = -1;
static int hf_atm_aal = -1;
static int hf_atm_vpi = -1;
static int hf_atm_vci = -1;
static int hf_atm_cid = -1;
static int proto_atm_lane = -1;
static int proto_ilmi = -1;
static int proto_aal1 = -1;
static int proto_aal3_4 = -1;
static int proto_oamaal = -1;

static gint ett_atm = -1;
static gint ett_atm_lane = -1;
static gint ett_atm_lane_lc_lan_dest = -1;
static gint ett_atm_lane_lc_lan_dest_rd = -1;
static gint ett_atm_lane_lc_flags = -1;
static gint ett_atm_lane_lc_tlv = -1;
static gint ett_ilmi = -1;
static gint ett_aal1 = -1;
static gint ett_aal3_4 = -1;
static gint ett_oamaal = -1;

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t tr_handle;
static dissector_handle_t fr_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t sscop_handle;
static dissector_handle_t lane_handle;
static dissector_handle_t ilmi_handle;
static dissector_handle_t fp_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t eth_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t data_handle;
static dissector_handle_t gprs_ns_handle;

static gboolean dissect_lanesscop = FALSE;

static gint unknown_aal2_type = TRAF_UNKNOWN;

/*
 * See
 *
 *      http://www.atmforum.org/atmforum/specs/approved.html
 *
 * for a number of ATM Forum specifications, e.g. the LAN Emulation
 * over ATM 1.0 spec, whence I got most of this.
 */

/* LE Control opcodes */
#define LE_CONFIGURE_REQUEST    0x0001
#define LE_CONFIGURE_RESPONSE   0x0101
#define LE_JOIN_REQUEST         0x0002
#define LE_JOIN_RESPONSE        0x0102
#define READY_QUERY             0x0003
#define READY_IND               0x0103
#define LE_REGISTER_REQUEST     0x0004
#define LE_REGISTER_RESPONSE    0x0104
#define LE_UNREGISTER_REQUEST   0x0005
#define LE_UNREGISTER_RESPONSE  0x0105
#define LE_ARP_REQUEST          0x0006
#define LE_ARP_RESPONSE         0x0106
#define LE_FLUSH_REQUEST        0x0007
#define LE_FLUSH_RESPONSE       0x0107
#define LE_NARP_REQUEST         0x0008
#define LE_TOPOLOGY_REQUEST     0x0009
#define LE_VERIFY_REQUEST       0x000A
#define LE_VERIFY_RESPONSE      0x010A

static const value_string le_control_opcode_vals[] = {
  { LE_CONFIGURE_REQUEST,   "LE_CONFIGURE_REQUEST" },
  { LE_CONFIGURE_RESPONSE,  "LE_CONFIGURE_RESPONSE" },
  { LE_JOIN_REQUEST,        "LE_JOIN_REQUEST" },
  { LE_JOIN_RESPONSE,       "LE_JOIN_RESPONSE" },
  { READY_QUERY,            "READY_QUERY" },
  { READY_IND,              "READY_IND" },
  { LE_REGISTER_REQUEST,    "LE_REGISTER_REQUEST" },
  { LE_REGISTER_RESPONSE,   "LE_REGISTER_RESPONSE" },
  { LE_UNREGISTER_REQUEST,  "LE_UNREGISTER_REQUEST" },
  { LE_UNREGISTER_RESPONSE, "LE_UNREGISTER_RESPONSE" },
  { LE_ARP_REQUEST,         "LE_ARP_REQUEST" },
  { LE_ARP_RESPONSE,        "LE_ARP_RESPONSE" },
  { LE_FLUSH_REQUEST,       "LE_FLUSH_REQUEST" },
  { LE_FLUSH_RESPONSE,      "LE_FLUSH_RESPONSE" },
  { LE_NARP_REQUEST,        "LE_NARP_REQUEST" },
  { LE_TOPOLOGY_REQUEST,    "LE_TOPOLOGY_REQUEST" },
  { LE_VERIFY_REQUEST,      "LE_VERIFY_REQUEST" },
  { LE_VERIFY_RESPONSE,     "LE_VERIFY_RESPONSE" },
  { 0,                      NULL }
};

/* LE Control statuses */
static const value_string le_control_status_vals[] = {
  { 0,  "Success" },
  { 1,  "Version not supported" },
  { 2,  "Invalid request parameters" },
  { 4,  "Duplicate LAN destination registration" },
  { 5,  "Duplicate ATM address" },
  { 6,  "Insufficient resources to grant request" },
  { 7,  "Access denied" },
  { 8,  "Invalid REQUESTOR-ID" },
  { 9,  "Invalid LAN destination" },
  { 10, "Invalid ATM address" },
  { 20, "No configuration" },
  { 21, "LE_CONFIGURE error" },
  { 22, "Insufficient information" },
  { 24, "TLV not found" },
  { 0,  NULL }
};

/* LE Control LAN destination tags */
#define TAG_NOT_PRESENT         0x0000
#define TAG_MAC_ADDRESS         0x0001
#define TAG_ROUTE_DESCRIPTOR    0x0002

static const value_string le_control_landest_tag_vals[] = {
  { TAG_NOT_PRESENT,       "Not present" },
  { TAG_MAC_ADDRESS,       "MAC address" },
  { TAG_ROUTE_DESCRIPTOR,  "Route descriptor" },
  { 0,                     NULL }
};

/* LE Control LAN types */
#define LANT_UNSPEC     0x00
#define LANT_802_3      0x01
#define LANT_802_5      0x02

static const value_string le_control_lan_type_vals[] = {
  { LANT_UNSPEC, "Unspecified" },
  { LANT_802_3,  "Ethernet/802.3" },
  { LANT_802_5,  "802.5" },
  { 0,           NULL }
};

static const value_string le_control_frame_size_vals[] = {
  { 0x00, "Unspecified" },
  { 0x01, "1516/1528/1580/1592" },
  { 0x02, "4544/4556/1580/1592" },
  { 0x03, "9234/9246" },
  { 0x04, "18190/18202" },
  { 0,    NULL }
};

static void
dissect_le_client(tvbuff_t *tvb, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lane_tree;

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_atm_lane, tvb, 0, 2, "ATM LANE");
    lane_tree = proto_item_add_subtree(ti, ett_atm_lane);

    proto_tree_add_text(lane_tree, tvb, 0, 2, "LE Client: 0x%04X",
                        tvb_get_ntohs(tvb, 0));
  }
}

static void
dissect_lan_destination(tvbuff_t *tvb, int offset, const char *type, proto_tree *tree)
{
  proto_item *td;
  proto_tree *dest_tree;
  guint16 tag;
  proto_tree *rd_tree;
  guint16 route_descriptor;

  td = proto_tree_add_text(tree, tvb, offset, 8, "%s LAN destination",
                           type);
  dest_tree = proto_item_add_subtree(td, ett_atm_lane_lc_lan_dest);
  tag = tvb_get_ntohs(tvb, offset);
  proto_tree_add_text(dest_tree, tvb, offset, 2, "Tag: %s",
                      val_to_str(tag, le_control_landest_tag_vals,
                                 "Unknown (0x%04X)"));
  offset += 2;

  switch (tag) {

  case TAG_MAC_ADDRESS:
    proto_tree_add_text(dest_tree, tvb, offset, 6, "MAC address: %s",
                        tvb_ether_to_str(tvb, offset));
    break;

  case TAG_ROUTE_DESCRIPTOR:
    offset += 4;
    route_descriptor = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(dest_tree, tvb, offset, 2, "Route descriptor: 0x%02X",
                              route_descriptor);
    rd_tree = proto_item_add_subtree(td, ett_atm_lane_lc_lan_dest_rd);
    proto_tree_add_text(rd_tree, tvb, offset, 2, "%s",
                        decode_numeric_bitfield(route_descriptor, 0xFFF0, 2*8,
                                                "LAN ID = %u"));
    proto_tree_add_text(rd_tree, tvb, offset, 2, "%s",
                        decode_numeric_bitfield(route_descriptor, 0x000F, 2*8,
                                                "Bridge number = %u"));
    break;
  }
}

/*
 * TLV values in LE Control frames.
 */
#define TLV_TYPE(oui, ident)            (((oui) << 8) | (ident))

#define LE_CONTROL_TIMEOUT              TLV_TYPE(OUI_ATM_FORUM, 0x01)
#define LE_MAX_UNK_FRAME_COUNT          TLV_TYPE(OUI_ATM_FORUM, 0x02)
#define LE_MAX_UNK_FRAME_TIME           TLV_TYPE(OUI_ATM_FORUM, 0x03)
#define LE_VCC_TIMEOUT_PERIOD           TLV_TYPE(OUI_ATM_FORUM, 0x04)
#define LE_MAX_RETRY_COUNT              TLV_TYPE(OUI_ATM_FORUM, 0x05)
#define LE_AGING_TIME                   TLV_TYPE(OUI_ATM_FORUM, 0x06)
#define LE_FORWARD_DELAY_TIME           TLV_TYPE(OUI_ATM_FORUM, 0x07)
#define LE_EXPECTED_ARP_RESPONSE_TIME   TLV_TYPE(OUI_ATM_FORUM, 0x08)
#define LE_FLUSH_TIMEOUT                TLV_TYPE(OUI_ATM_FORUM, 0x09)
#define LE_PATH_SWITCHING_DELAY         TLV_TYPE(OUI_ATM_FORUM, 0x0A)
#define LE_LOCAL_SEGMENT_ID             TLV_TYPE(OUI_ATM_FORUM, 0x0B)
#define LE_MCAST_SEND_VCC_TYPE          TLV_TYPE(OUI_ATM_FORUM, 0x0C)
#define LE_MCAST_SEND_VCC_AVGRATE       TLV_TYPE(OUI_ATM_FORUM, 0x0D)
#define LE_MCAST_SEND_VCC_PEAKRATE      TLV_TYPE(OUI_ATM_FORUM, 0x0E)
#define LE_CONN_COMPLETION_TIMER        TLV_TYPE(OUI_ATM_FORUM, 0x0F)
#define LE_CONFIG_FRAG_INFO             TLV_TYPE(OUI_ATM_FORUM, 0x10)
#define LE_LAYER_3_ADDRESS              TLV_TYPE(OUI_ATM_FORUM, 0x11)
#define LE_ELAN_ID                      TLV_TYPE(OUI_ATM_FORUM, 0x12)
#define LE_SERVICE_CATEGORY             TLV_TYPE(OUI_ATM_FORUM, 0x13)
#define LE_LLC_MUXED_ATM_ADDRESS        TLV_TYPE(OUI_ATM_FORUM, 0x2B)
#define LE_X5_ADJUSTMENT                TLV_TYPE(OUI_ATM_FORUM, 0x2C)
#define LE_PREFERRED_LES                TLV_TYPE(OUI_ATM_FORUM, 0x2D)

static const value_string le_tlv_type_vals[] = {
  { LE_CONTROL_TIMEOUT,           "Control Time-out" },
  { LE_MAX_UNK_FRAME_COUNT,       "Maximum Unknown Frame Count" },
  { LE_MAX_UNK_FRAME_TIME,        "Maximum Unknown Frame Time" },
  { LE_VCC_TIMEOUT_PERIOD,        "VCC Time-out" },
  { LE_MAX_RETRY_COUNT,           "Maximum Retry Count" },
  { LE_AGING_TIME,                "Aging Time" },
  { LE_FORWARD_DELAY_TIME,        "Forwarding Delay Time" },
  { LE_EXPECTED_ARP_RESPONSE_TIME, "Expected LE_ARP Response Time" },
  { LE_FLUSH_TIMEOUT,             "Flush Time-out" },
  { LE_PATH_SWITCHING_DELAY,      "Path Switching Delay" },
  { LE_LOCAL_SEGMENT_ID,          "Local Segment ID" },
  { LE_MCAST_SEND_VCC_TYPE,       "Mcast Send VCC Type" },
  { LE_MCAST_SEND_VCC_AVGRATE,    "Mcast Send VCC AvgRate" },
  { LE_MCAST_SEND_VCC_PEAKRATE,   "Mcast Send VCC PeakRate" },
  { LE_CONN_COMPLETION_TIMER,     "Connection Completion Timer" },
  { LE_CONFIG_FRAG_INFO,          "Config Frag Info" },
  { LE_LAYER_3_ADDRESS,           "Layer 3 Address" },
  { LE_ELAN_ID,                   "ELAN ID" },
  { LE_SERVICE_CATEGORY,          "Service Category" },
  { LE_LLC_MUXED_ATM_ADDRESS,     "LLC-muxed ATM Address" },
  { LE_X5_ADJUSTMENT,             "X5 Adjustment" },
  { LE_PREFERRED_LES,             "Preferred LES" },
  { 0,                            NULL },
};

static void
dissect_le_control_tlvs(tvbuff_t *tvb, int offset, guint num_tlvs,
                        proto_tree *tree)
{
  guint32 tlv_type;
  guint8 tlv_length;
  proto_item *ttlv;
  proto_tree *tlv_tree;

  while (num_tlvs != 0) {
    tlv_type = tvb_get_ntohl(tvb, offset);
    tlv_length = tvb_get_guint8(tvb, offset+4);
    ttlv = proto_tree_add_text(tree, tvb, offset, 5+tlv_length, "TLV type: %s",
                               val_to_str(tlv_type, le_tlv_type_vals, "Unknown (0x%08x)"));
    tlv_tree = proto_item_add_subtree(ttlv, ett_atm_lane_lc_tlv);
    proto_tree_add_text(tlv_tree, tvb, offset, 4, "TLV Type: %s",
                        val_to_str(tlv_type, le_tlv_type_vals, "Unknown (0x%08x)"));
    proto_tree_add_text(tlv_tree, tvb, offset+4, 1, "TLV Length: %u", tlv_length);
    offset += 5+tlv_length;
    num_tlvs--;
  }
}

static void
dissect_le_configure_join_frame(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  guint8 num_tlvs;
  guint8 name_size;

  dissect_lan_destination(tvb, offset, "Source", tree);
  offset += 8;

  dissect_lan_destination(tvb, offset, "Target", tree);
  offset += 8;

  proto_tree_add_text(tree, tvb, offset, 20, "Source ATM Address: %s",
                      tvb_bytes_to_str(tvb, offset, 20));
  offset += 20;

  proto_tree_add_text(tree, tvb, offset, 1, "LAN type: %s",
                      val_to_str(tvb_get_guint8(tvb, offset), le_control_lan_type_vals,
                                 "Unknown (0x%02X)"));
  offset += 1;

  proto_tree_add_text(tree, tvb, offset, 1, "Maximum frame size: %s",
                      val_to_str(tvb_get_guint8(tvb, offset), le_control_frame_size_vals,
                                 "Unknown (0x%02X)"));
  offset += 1;

  num_tlvs = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1, "Number of TLVs: %u", num_tlvs);
  offset += 1;

  name_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1, "ELAN name size: %u", name_size);
  offset += 1;

  proto_tree_add_text(tree, tvb, offset, 20, "Target ATM Address: %s",
                      tvb_bytes_to_str(tvb, offset, 20));
  offset += 20;

  if (name_size > 32)
    name_size = 32;
  if (name_size != 0) {
    proto_tree_add_text(tree, tvb, offset, name_size, "ELAN name: %s",
                        tvb_bytes_to_str(tvb, offset, name_size));
  }
  offset += 32;

  dissect_le_control_tlvs(tvb, offset, num_tlvs, tree);
}

static void
dissect_le_registration_frame(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  guint8 num_tlvs;

  dissect_lan_destination(tvb, offset, "Source", tree);
  offset += 8;

  dissect_lan_destination(tvb, offset, "Target", tree);
  offset += 8;

  proto_tree_add_text(tree, tvb, offset, 20, "Source ATM Address: %s",
                      tvb_bytes_to_str(tvb, offset, 20));
  offset += 20;

  /* Reserved */
  offset += 2;

  num_tlvs = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1, "Number of TLVs: %u", num_tlvs);
  offset += 1;

  /* Reserved */
  offset += 53;

  dissect_le_control_tlvs(tvb, offset, num_tlvs, tree);
}

static void
dissect_le_arp_frame(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  guint8 num_tlvs;

  dissect_lan_destination(tvb, offset, "Source", tree);
  offset += 8;

  dissect_lan_destination(tvb, offset, "Target", tree);
  offset += 8;

  proto_tree_add_text(tree, tvb, offset, 20, "Source ATM Address: %s",
                      tvb_bytes_to_str(tvb, offset, 20));
  offset += 20;

  /* Reserved */
  offset += 2;

  num_tlvs = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1, "Number of TLVs: %u", num_tlvs);
  offset += 1;

  /* Reserved */
  offset += 1;

  proto_tree_add_text(tree, tvb, offset, 20, "Target ATM Address: %s",
                      tvb_bytes_to_str(tvb, offset, 20));
  offset += 20;

  /* Reserved */
  offset += 32;

  dissect_le_control_tlvs(tvb, offset, num_tlvs, tree);
}

static void
dissect_le_verify_frame(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  guint8 num_tlvs;

  /* Reserved */
  offset += 38;

  num_tlvs = tvb_get_guint8(tvb, offset);
  proto_tree_add_text(tree, tvb, offset, 1, "Number of TLVs: %u", num_tlvs);
  offset += 1;

  /* Reserved */
  offset += 1;

  proto_tree_add_text(tree, tvb, offset, 20, "Target ATM Address: %s",
                      tvb_bytes_to_str(tvb, offset, 20));
  offset += 20;

  /* Reserved */
  offset += 32;

  dissect_le_control_tlvs(tvb, offset, num_tlvs, tree);
}

static void
dissect_le_flush_frame(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  dissect_lan_destination(tvb, offset, "Source", tree);
  offset += 8;

  dissect_lan_destination(tvb, offset, "Target", tree);
  offset += 8;

  proto_tree_add_text(tree, tvb, offset, 20, "Source ATM Address: %s",
                      tvb_bytes_to_str(tvb, offset, 20));
  offset += 20;

  /* Reserved */
  offset += 4;

  proto_tree_add_text(tree, tvb, offset, 20, "Target ATM Address: %s",
                      tvb_bytes_to_str(tvb, offset, 20));
  offset += 20;

  /* Reserved */
  offset += 32;
}

static void
dissect_le_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lane_tree = NULL;
  int offset = 0;
  proto_item *tf;
  proto_tree *flags_tree;
  guint16 opcode;
  guint16 flags;

  col_set_str(pinfo->cinfo, COL_INFO, "LE Control");

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_atm_lane, tvb, offset, 108, "ATM LANE");
    lane_tree = proto_item_add_subtree(ti, ett_atm_lane);

    proto_tree_add_text(lane_tree, tvb, offset, 2, "Marker: 0x%04X",
                        tvb_get_ntohs(tvb, offset));
  }
  offset += 2;

  if (tree) {
    proto_tree_add_text(lane_tree, tvb, offset, 1, "Protocol: 0x%02X",
                        tvb_get_guint8(tvb, offset));
  }
  offset += 1;

  if (tree) {
    proto_tree_add_text(lane_tree, tvb, offset, 1, "Version: 0x%02X",
                        tvb_get_guint8(tvb, offset));
  }
  offset += 1;

  opcode = tvb_get_ntohs(tvb, offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                  val_to_str(opcode, le_control_opcode_vals,
                             "Unknown opcode (0x%04X)"));

  if (tree) {
    proto_tree_add_text(lane_tree, tvb, offset, 2, "Opcode: %s",
                        val_to_str(opcode, le_control_opcode_vals,
                                   "Unknown (0x%04X)"));
  }
  offset += 2;

  if (opcode == READY_QUERY || opcode == READY_IND) {
    /* There's nothing more in this packet. */
    return;
  }

  if (tree) {
    if (opcode & 0x0100) {
      /* Response; decode status. */
      proto_tree_add_text(lane_tree, tvb, offset, 2, "Status: %s",
                          val_to_str(tvb_get_ntohs(tvb, offset), le_control_status_vals,
                                     "Unknown (0x%04X)"));
    }
    offset += 2;

    proto_tree_add_text(lane_tree, tvb, offset, 4, "Transaction ID: 0x%08X",
                        tvb_get_ntohl(tvb, offset));
    offset += 4;

    proto_tree_add_text(lane_tree, tvb, offset, 2, "Requester LECID: 0x%04X",
                        tvb_get_ntohs(tvb, offset));
    offset += 2;

    flags = tvb_get_ntohs(tvb, offset);
    tf = proto_tree_add_text(lane_tree, tvb, offset, 2, "Flags: 0x%04X",
                             flags);
    flags_tree = proto_item_add_subtree(tf, ett_atm_lane_lc_flags);

    switch (opcode) {

    case LE_CONFIGURE_REQUEST:
    case LE_CONFIGURE_RESPONSE:
      proto_tree_add_text(flags_tree, tvb, offset, 2, "%s",
                          decode_boolean_bitfield(flags, 0x0002, 8*2,
                                                  "V2 capable", "Not V2 capable"));
      offset += 2;
      dissect_le_configure_join_frame(tvb, offset, lane_tree);
      break;

    case LE_JOIN_REQUEST:
    case LE_JOIN_RESPONSE:
      proto_tree_add_text(flags_tree, tvb, offset, 2, "%s",
                          decode_boolean_bitfield(flags, 0x0002, 8*2,
                                                  "V2 capable", "Not V2 capable"));
      if (opcode == LE_JOIN_REQUEST) {
        proto_tree_add_text(flags_tree, tvb, offset, 2, "%s",
                            decode_boolean_bitfield(flags, 0x0004, 8*2,
                                                    "Selective multicast", "No selective multicast"));
      } else {
        proto_tree_add_text(flags_tree, tvb, offset, 2, "%s",
                            decode_boolean_bitfield(flags, 0x0008, 8*2,
                                        "V2 required", "V2 not required"));
      }
      proto_tree_add_text(flags_tree, tvb, offset, 2, "%s",
        decode_boolean_bitfield(flags, 0x0080, 8*2,
                                "Proxy", "Not proxy"));
      proto_tree_add_text(flags_tree, tvb, offset, 2, "%s",
        decode_boolean_bitfield(flags, 0x0200, 8*2,
                                "Exclude explorer frames",
                                "Don't exclude explorer frames"));
      offset += 2;
      dissect_le_configure_join_frame(tvb, offset, lane_tree);
      break;

    case LE_REGISTER_REQUEST:
    case LE_REGISTER_RESPONSE:
    case LE_UNREGISTER_REQUEST:
    case LE_UNREGISTER_RESPONSE:
      offset += 2;
      dissect_le_registration_frame(tvb, offset, lane_tree);
      break;

    case LE_ARP_REQUEST:
    case LE_ARP_RESPONSE:
    case LE_NARP_REQUEST:
      if (opcode != LE_NARP_REQUEST) {
        proto_tree_add_text(flags_tree, tvb, offset, 2, "%s",
                            decode_boolean_bitfield(flags, 0x0001, 8*2,
                                                    "Remote address", "Local address"));
      }
      offset += 2;
      dissect_le_arp_frame(tvb, offset, lane_tree);
      break;

    case LE_TOPOLOGY_REQUEST:
      proto_tree_add_text(flags_tree, tvb, offset, 2, "%s",
                          decode_boolean_bitfield(flags, 0x0100, 8*2,
                                                  "Topology change", "No topology change"));
      offset += 2;
      /* 92 reserved bytes */
      break;

    case LE_VERIFY_REQUEST:
    case LE_VERIFY_RESPONSE:
      offset += 2;
      dissect_le_verify_frame(tvb, offset, lane_tree);
      break;

    case LE_FLUSH_REQUEST:
    case LE_FLUSH_RESPONSE:
      offset += 2;
      dissect_le_flush_frame(tvb, offset, lane_tree);
      break;
    }
  }
}

static void
capture_lane(const union wtap_pseudo_header *pseudo_header, const guchar *pd,
    int len, packet_counts *ld)
{
  /* Is it LE Control, 802.3, 802.5, or "none of the above"? */
  switch (pseudo_header->atm.subtype) {

  case TRAF_ST_LANE_802_3:
  case TRAF_ST_LANE_802_3_MC:
    /* Dissect as Ethernet */
    capture_eth(pd, 2, len, ld);
    break;

  case TRAF_ST_LANE_802_5:
  case TRAF_ST_LANE_802_5_MC:
    /* Dissect as Token-Ring */
    capture_tr(pd, 2, len, ld);
    break;

  default:
    ld->other++;
    break;
  }
}

static void
dissect_lane(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t *next_tvb;
  tvbuff_t *next_tvb_le_client;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATM LANE");

  /* Is it LE Control, 802.3, 802.5, or "none of the above"? */
  switch (pinfo->pseudo_header->atm.subtype) {

  case TRAF_ST_LANE_LE_CTRL:
    dissect_le_control(tvb, pinfo, tree);
    break;

  case TRAF_ST_LANE_802_3:
  case TRAF_ST_LANE_802_3_MC:
    col_set_str(pinfo->cinfo, COL_INFO, "LE Client - Ethernet/802.3");
    dissect_le_client(tvb, tree);

    /* Dissect as Ethernet */
    next_tvb_le_client  = tvb_new_subset_remaining(tvb, 2);
    call_dissector(eth_withoutfcs_handle, next_tvb_le_client, pinfo, tree);
    break;

  case TRAF_ST_LANE_802_5:
  case TRAF_ST_LANE_802_5_MC:
    col_set_str(pinfo->cinfo, COL_INFO, "LE Client - 802.5");
    dissect_le_client(tvb, tree);

    /* Dissect as Token-Ring */
    next_tvb_le_client  = tvb_new_subset_remaining(tvb, 2);
    call_dissector(tr_handle, next_tvb_le_client, pinfo, tree);
    break;

  default:
    /* Dump it as raw data. */
    col_set_str(pinfo->cinfo, COL_INFO, "Unknown LANE traffic type");
    next_tvb            = tvb_new_subset_remaining(tvb, 0);
    call_dissector(data_handle,next_tvb, pinfo, tree);
    break;
  }
}

static void
dissect_ilmi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_snmp_pdu(tvb, 0, pinfo, tree, proto_ilmi, ett_ilmi, ENC_BIG_ENDIAN);
}

/* AAL types */
static const value_string aal_vals[] = {
  { AAL_UNKNOWN,            "Unknown AAL" },
  { AAL_1,                  "AAL1" },
  { AAL_2,                  "AAL2" },
  { AAL_3_4,                "AAL3/4" },
  { AAL_5,                  "AAL5" },
  { AAL_USER,               "User AAL" },
  { AAL_SIGNALLING,         "Signalling AAL" },
  { AAL_OAMCELL,            "OAM cell" },
  { 0,              NULL }
};

/* AAL5 higher-level traffic types */
static const value_string aal5_hltype_vals[] = {
  { TRAF_UNKNOWN,           "Unknown traffic type" },
  { TRAF_LLCMX,             "LLC multiplexed" },
  { TRAF_VCMX,              "VC multiplexed" },
  { TRAF_LANE,              "LANE" },
  { TRAF_ILMI,              "ILMI" },
  { TRAF_FR,                "Frame Relay" },
  { TRAF_SPANS,             "FORE SPANS" },
  { TRAF_IPSILON,           "Ipsilon" },
  { TRAF_GPRS_NS,           "GPRS NS" },
  { 0,              NULL }
};

/* Traffic subtypes for VC multiplexed traffic */
static const value_string vcmx_type_vals[] = {
  { TRAF_ST_UNKNOWN,        "Unknown VC multiplexed traffic type" },
  { TRAF_ST_VCMX_802_3_FCS, "802.3 FCS" },
  { TRAF_ST_VCMX_802_4_FCS, "802.4 FCS" },
  { TRAF_ST_VCMX_802_5_FCS, "802.5 FCS" },
  { TRAF_ST_VCMX_FDDI_FCS,  "FDDI FCS" },
  { TRAF_ST_VCMX_802_6_FCS, "802.6 FCS" },
  { TRAF_ST_VCMX_802_3,     "802.3" },
  { TRAF_ST_VCMX_802_4,     "802.4" },
  { TRAF_ST_VCMX_802_5,     "802.5" },
  { TRAF_ST_VCMX_FDDI,      "FDDI" },
  { TRAF_ST_VCMX_802_6,     "802.6" },
  { TRAF_ST_VCMX_FRAGMENTS, "Fragments" },
  { TRAF_ST_VCMX_BPDU,      "BPDU" },
  { 0,                   NULL }
};

/* Traffic subtypes for LANE traffic */
static const value_string lane_type_vals[] = {
  { TRAF_ST_UNKNOWN,        "Unknown LANE traffic type" },
  { TRAF_ST_LANE_LE_CTRL,   "LE Control" },
  { TRAF_ST_LANE_802_3,     "802.3" },
  { TRAF_ST_LANE_802_5,     "802.5" },
  { TRAF_ST_LANE_802_3_MC,  "802.3 multicast" },
  { TRAF_ST_LANE_802_5_MC,  "802.5 multicast" },
  { 0,                     NULL }
};

/* Traffic subtypes for Ipsilon traffic */
static const value_string ipsilon_type_vals[] = {
  { TRAF_ST_UNKNOWN,        "Unknown Ipsilon traffic type" },
  { TRAF_ST_IPSILON_FT0,    "Flow type 0" },
  { TRAF_ST_IPSILON_FT1,    "Flow type 1" },
  { TRAF_ST_IPSILON_FT2,    "Flow type 2" },
  { 0,                NULL }
};

void
capture_atm(const union wtap_pseudo_header *pseudo_header, const guchar *pd,
    int len, packet_counts *ld)
{
  if (pseudo_header->atm.aal == AAL_5) {
    switch (pseudo_header->atm.type) {

    case TRAF_LLCMX:
      /* Dissect as WTAP_ENCAP_ATM_RFC1483 */
      /* The ATM iptrace capture that we have shows LLC at this point,
       * so that's what I'm calling */
      capture_llc(pd, 0, len, ld);
      break;

    case TRAF_LANE:
      capture_lane(pseudo_header, pd, len, ld);
      break;

    default:
      ld->other++;
      break;
    }
  } else
    ld->other++;
}

/*
 * Charles Michael Heard's CRC-32 code, from
 *
 *      http://www.cell-relay.com/cell-relay/publications/software/CRC/32bitCRC.c.html
 *
 * with the CRC table initialized with values computed by
 * his "gen_crc_table()" routine, rather than by calling that routine
 * at run time, and with various data type cleanups.
 */

/* crc32h.c -- package to compute 32-bit CRC one byte at a time using   */
/*             the high-bit first (Big-Endian) bit ordering convention  */
/*                                                                      */
/* Synopsis:                                                            */
/*  gen_crc_table() -- generates a 256-word table containing all CRC    */
/*                     remainders for every possible 8-bit byte.  It    */
/*                     must be executed (once) before any CRC updates.  */
/*                                                                      */
/*  unsigned update_crc(crc_accum, data_blk_ptr, data_blk_size)         */
/*           unsigned crc_accum; char *data_blk_ptr; int data_blk_size; */
/*           Returns the updated value of the CRC accumulator after     */
/*           processing each byte in the addressed block of data.       */
/*                                                                      */
/*  It is assumed that an unsigned long is at least 32 bits wide and    */
/*  that the predefined type char occupies one 8-bit byte of storage.   */
/*                                                                      */
/*  The generator polynomial used for this version of the package is    */
/*  x^32+x^26+x^23+x^22+x^16+x^12+x^11+x^10+x^8+x^7+x^5+x^4+x^2+x^1+x^0 */
/*  as specified in the Autodin/Ethernet/ADCCP protocol standards.      */
/*  Other degree 32 polynomials may be substituted by re-defining the   */
/*  symbol POLYNOMIAL below.  Lower degree polynomials must first be    */
/*  multiplied by an appropriate power of x.  The representation used   */
/*  is that the coefficient of x^0 is stored in the LSB of the 32-bit   */
/*  word and the coefficient of x^31 is stored in the most significant  */
/*  bit.  The CRC is to be appended to the data most significant byte   */
/*  first.  For those protocols in which bytes are transmitted MSB      */
/*  first and in the same order as they are encountered in the block    */
/*  this convention results in the CRC remainder being transmitted with */
/*  the coefficient of x^31 first and with that of x^0 last (just as    */
/*  would be done by a hardware shift register mechanization).          */
/*                                                                      */
/*  The table lookup technique was adapted from the algorithm described */
/*  by Avram Perez, Byte-wise CRC Calculations, IEEE Micro 3, 40 (1983).*/

static const guint32 crc_table[256] = {
  0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
  0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
  0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
  0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
  0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
  0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
  0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
  0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
  0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
  0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
  0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
  0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
  0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
  0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
  0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
  0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
  0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
  0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
  0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
  0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
  0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
  0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
  0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
  0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
  0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
  0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
  0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
  0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
  0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
  0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
  0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
  0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
  0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
  0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
  0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
  0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
  0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
  0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
  0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
  0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
  0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
  0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
  0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
  0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
  0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
  0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
  0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
  0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
  0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
  0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
  0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
  0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
  0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
  0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
  0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
  0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
  0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
  0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
  0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
  0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
  0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
  0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
  0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
  0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4,
};

static guint32
update_crc(guint32 crc_accum, const guint8 *data_blk_ptr, int data_blk_size)
{
  register int i, j;

  /* update the CRC on the data block one byte at a time */
  for (j = 0; j < data_blk_size;  j++) {
    i = ( (int) ( crc_accum >> 24) ^ *data_blk_ptr++ ) & 0xff;
    crc_accum = ( crc_accum << 8 ) ^ crc_table[i];
  }
  return crc_accum;
}

static void
dissect_reassembled_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_item *atm_ti,
    proto_tree *atm_tree, gboolean truncated)
{
  guint        length, reported_length;
  guint16      aal5_length;
  int          pad_length;
  tvbuff_t     *next_tvb;
  guint32      crc;
  guint32      calc_crc;
  gint         type;
  /*
   * ATM dissector is used as "sub-dissector" for ATM pseudowires.
   * In such cases, pinfo->private_data is used to pass info from/to
   * PW dissector to ATM dissector. For decoding normal ATM traffic
   * private_data should be NULL.
   */
  gboolean     pseudowire_mode = (NULL != pinfo->private_data);

  /*
   * This is reassembled traffic, so the cell headers are missing;
   * show the traffic type for AAL5 traffic, and the VPI and VCI,
   * from the pseudo-header.
   */
  if (pinfo->pseudo_header->atm.aal == AAL_5) {
    proto_tree_add_text(atm_tree, tvb, 0, 0, "Traffic type: %s",
                        val_to_str(pinfo->pseudo_header->atm.type, aal5_hltype_vals,
                                   "Unknown AAL5 traffic type (%u)"));
    switch (pinfo->pseudo_header->atm.type) {

    case TRAF_VCMX:
      proto_tree_add_text(atm_tree, tvb, 0, 0, "VC multiplexed traffic type: %s",
                          val_to_str(pinfo->pseudo_header->atm.subtype,
                                     vcmx_type_vals, "Unknown VCMX traffic type (%u)"));
      break;

    case TRAF_LANE:
      proto_tree_add_text(atm_tree, tvb, 0, 0, "LANE traffic type: %s",
                          val_to_str(pinfo->pseudo_header->atm.subtype,
                                     lane_type_vals, "Unknown LANE traffic type (%u)"));
      break;

    case TRAF_IPSILON:
      proto_tree_add_text(atm_tree, tvb, 0, 0, "Ipsilon traffic type: %s",
                          val_to_str(pinfo->pseudo_header->atm.subtype,
                                     ipsilon_type_vals, "Unknown Ipsilon traffic type (%u)"));
      break;
    }
  }
  if (!pseudowire_mode) {
    proto_tree_add_uint(atm_tree, hf_atm_vpi, tvb, 0, 0,
                        pinfo->pseudo_header->atm.vpi);
    proto_tree_add_uint(atm_tree, hf_atm_vci, tvb, 0, 0,
                        pinfo->pseudo_header->atm.vci);

    /* Also show vpi/vci in info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " VPI=%u, VCI=%u",
                    pinfo->pseudo_header->atm.vpi,
                    pinfo->pseudo_header->atm.vci);
  }

  next_tvb = tvb;
  if (truncated) {
    /*
     * The packet data does not include stuff such as the AAL5
     * trailer.
     */
    if (pinfo->pseudo_header->atm.cells != 0) {
      /*
       * If the cell count is 0, assume it means we don't know how
       * many cells it was.
       *
       * XXX - also assume it means we don't know what was in the AAL5
       * trailer.  We may, however, find some capture program that can
       * give us the AAL5 trailer information but not the cell count,
       * in which case we need some other way of indicating whether we
       * have the AAL5 trailer information.
       */
      if (tree) {
        proto_tree_add_text(atm_tree, tvb, 0, 0, "Cells: %u",
                            pinfo->pseudo_header->atm.cells);
        proto_tree_add_text(atm_tree, tvb, 0, 0, "AAL5 UU: 0x%02x",
                            pinfo->pseudo_header->atm.aal5t_u2u >> 8);
        proto_tree_add_text(atm_tree, tvb, 0, 0, "AAL5 CPI: 0x%02x",
                            pinfo->pseudo_header->atm.aal5t_u2u & 0xFF);
        proto_tree_add_text(atm_tree, tvb, 0, 0, "AAL5 len: %u",
                            pinfo->pseudo_header->atm.aal5t_len);
        proto_tree_add_text(atm_tree, tvb, 0, 0, "AAL5 CRC: 0x%08X",
                            pinfo->pseudo_header->atm.aal5t_chksum);
      }
    }
  } else {
    /*
     * The packet data includes stuff such as the AAL5 trailer, if
     * it wasn't cut off by the snapshot length.
     * Decode the trailer, if present, and then chop it off.
     */
    length = tvb_length(tvb);
    reported_length = tvb_reported_length(tvb);
    if ((reported_length % 48) == 0) {
      /*
       * Reported length is a multiple of 48, so we can presumably
       * divide it by 48 to get the number of cells.
       */
      proto_tree_add_text(atm_tree, tvb, 0, 0, "Cells: %u",
                          reported_length/48);
    }
    if ((pinfo->pseudo_header->atm.aal == AAL_5 ||
         pinfo->pseudo_header->atm.aal == AAL_SIGNALLING) &&
        length >= reported_length) {
      /*
       * XXX - what if the packet is truncated?  Can that happen?
       * What if you capture with Windows Sniffer on an ATM link
       * and tell it not to save the entire packet?  What happens
       * to the trailer?
       */
      aal5_length = tvb_get_ntohs(tvb, length - 6);

      /*
       * Check for sanity in the AAL5 length.  It must be > 0
       * and must be less than the amount of space left after
       * we remove the trailer.
       *
       * If it's not sane, assume we don't have a trailer.
       */
      if (aal5_length > 0 && aal5_length <= length - 8) {
        /*
         * How much padding is there?
         */
        pad_length = length - aal5_length - 8;

        /*
         * There is no reason for more than 47 bytes of padding.
         * The most padding you can have would be 7 bytes at the
         * end of the next-to-last cell (8 bytes after the end of
         * the data means you can fit the trailer in that cell),
         * plus 40 bytes in the last cell (with the last 8 bytes
         * being padding).
         *
         * If there's more than 47 bytes of padding, assume we don't
         * have a trailer.
         */
        if (pad_length <= 47) {
          if (tree) {
            if (pad_length > 0) {
              proto_tree_add_text(atm_tree, tvb, aal5_length, pad_length,
                                  "Padding");
            }
            proto_tree_add_text(atm_tree, tvb, length - 8, 1, "AAL5 UU: 0x%02x",
                                tvb_get_guint8(tvb, length - 8));
            proto_tree_add_text(atm_tree, tvb, length - 7, 1, "AAL5 CPI: 0x%02x",
                                tvb_get_guint8(tvb, length - 7));
            proto_tree_add_text(atm_tree, tvb, length - 6, 2, "AAL5 len: %u",
                                aal5_length);
            crc = tvb_get_ntohl(tvb, length - 4);
            calc_crc = update_crc(0xFFFFFFFF, tvb_get_ptr(tvb, 0, length),
                                  length);
            proto_tree_add_text(atm_tree, tvb, length - 4, 4,
                                "AAL5 CRC: 0x%08X (%s)", crc,
                                (calc_crc == 0xC704DD7B) ? "correct" : "incorrect");
          }
          next_tvb = tvb_new_subset(tvb, 0, aal5_length, aal5_length);
        }
      }
    }
  }

  switch (pinfo->pseudo_header->atm.aal) {

  case AAL_SIGNALLING:
    call_dissector(sscop_handle, next_tvb, pinfo, tree);
    break;

  case AAL_5:
    switch (pinfo->pseudo_header->atm.type) {

    case TRAF_FR:
      call_dissector(fr_handle, next_tvb, pinfo, tree);
      break;

    case TRAF_LLCMX:
      call_dissector(llc_handle, next_tvb, pinfo, tree);
      break;

    case TRAF_LANE:
      call_dissector(lane_handle, next_tvb, pinfo, tree);
      break;

    case TRAF_ILMI:
      call_dissector(ilmi_handle, next_tvb, pinfo, tree);
      break;

    case TRAF_GPRS_NS:
      call_dissector(gprs_ns_handle, next_tvb, pinfo, tree);
      break;

    default:
      {
        gboolean decoded = FALSE;

        if (tvb_length(next_tvb) > 7) /* sizeof(octet) */
        {
            guint8 octet[8];
            tvb_memcpy(next_tvb, octet, 0, sizeof(octet));

            decoded = TRUE;
            if (octet[0] == 0xaa
             && octet[1] == 0xaa
             && octet[2] == 0x03) /* LLC SNAP as per RFC2684 */
            {
                call_dissector(llc_handle, next_tvb, pinfo, tree);
            }
            else if ((pntohs(octet) & 0xff) == PPP_IP)
            {
                call_dissector(ppp_handle, next_tvb, pinfo, tree);
            }
            else if (pntohs(octet) == 0x00)
            {
                /* assume vc muxed bridged ethernet */
                proto_tree_add_text(tree, tvb, 0, 2, "Pad: 0x0000");
                next_tvb = tvb_new_subset_remaining(tvb, 2);
                call_dissector(eth_handle, next_tvb, pinfo, tree);
            }
            else if (octet[2] == 0x03    && /* NLPID */
                    ((octet[3] == 0xcc   || /* IPv4  */
                      octet[3] == 0x8e)  || /* IPv6  */
                     (octet[3] == 0x00   && /* Eth   */
                      octet[4] == 0x80)))   /* Eth   */
            {
                /* assume network interworking with FR 2 byte header */
                call_dissector(fr_handle, next_tvb, pinfo, tree);
            }
            else if (octet[4] == 0x03    && /* NLPID */
                    ((octet[5] == 0xcc   || /* IPv4  */
                      octet[5] == 0x8e)  || /* IPv6  */
                     (octet[5] == 0x00   && /* Eth   */
                      octet[6] == 0x80)))   /* Eth   */
            {
                /* assume network interworking with FR 4 byte header */
                call_dissector(fr_handle, next_tvb, pinfo, tree);
            }
            else if (((octet[0] & 0xf0)== 0x40) ||
                     ((octet[0] & 0xf0) == 0x60))
            {
                call_dissector(ip_handle, next_tvb, pinfo, tree);
            }
            else
            {
                decoded = FALSE;
            }
        }

        if (tree && !decoded) {
            /* Dump it as raw data. */
            call_dissector(data_handle, next_tvb, pinfo, tree);
        }
      }
      break;
    }
    break;

  case AAL_2:
    proto_tree_add_uint(atm_tree, hf_atm_cid, tvb, 0, 0,
                        pinfo->pseudo_header->atm.aal2_cid);
    proto_item_append_text(atm_ti, " (vpi=%u vci=%u cid=%u)",
                           pinfo->pseudo_header->atm.vpi,
                           pinfo->pseudo_header->atm.vci,
                           pinfo->pseudo_header->atm.aal2_cid);

    if (pinfo->pseudo_header->atm.flags & ATM_AAL2_NOPHDR) {
      next_tvb = tvb;
    } else {
          /* Skip first 4 bytes of message
             - side
             - length
             - UUI
             Ignoring for now... */
      next_tvb = tvb_new_subset_remaining(tvb, 4);
    }

    type = pinfo->pseudo_header->atm.type;
    if (type == TRAF_UNKNOWN) {
      type = unknown_aal2_type;
    }
    switch (type) {
      case TRAF_UMTS_FP:
          call_dissector(fp_handle, next_tvb, pinfo, tree);
          break;

      default:
        if (tree) {
          /* Dump it as raw data. */
          call_dissector(data_handle, next_tvb, pinfo, tree);
          break;
        }
    }
    break;

  default:
    if (tree) {
      /* Dump it as raw data. */
      call_dissector(data_handle, next_tvb, pinfo, tree);
    }
    break;
  }
}

/*
 * Charles Michael Heard's HEC code, from
 *
 *      http://www.cell-relay.com/cell-relay/publications/software/CRC/32bitCRC.tutorial.html
 *
 * with the syndrome and error position tables initialized with values
 * computed by his "gen_syndrome_table()" and "gen_err_posn_table()" routines,
 * rather than by calling those routines at run time, and with various data
 * type cleanups and changes not to correct the header if a correctible
 * error was detected.
 */
#define COSET_LEADER    0x055               /* x^6 + x^4 + x^2 + 1  */

static const guint8 syndrome_table[256] = {
  0x00, 0x07, 0x0e, 0x09, 0x1c, 0x1b, 0x12, 0x15,
  0x38, 0x3f, 0x36, 0x31, 0x24, 0x23, 0x2a, 0x2d,
  0x70, 0x77, 0x7e, 0x79, 0x6c, 0x6b, 0x62, 0x65,
  0x48, 0x4f, 0x46, 0x41, 0x54, 0x53, 0x5a, 0x5d,
  0xe0, 0xe7, 0xee, 0xe9, 0xfc, 0xfb, 0xf2, 0xf5,
  0xd8, 0xdf, 0xd6, 0xd1, 0xc4, 0xc3, 0xca, 0xcd,
  0x90, 0x97, 0x9e, 0x99, 0x8c, 0x8b, 0x82, 0x85,
  0xa8, 0xaf, 0xa6, 0xa1, 0xb4, 0xb3, 0xba, 0xbd,
  0xc7, 0xc0, 0xc9, 0xce, 0xdb, 0xdc, 0xd5, 0xd2,
  0xff, 0xf8, 0xf1, 0xf6, 0xe3, 0xe4, 0xed, 0xea,
  0xb7, 0xb0, 0xb9, 0xbe, 0xab, 0xac, 0xa5, 0xa2,
  0x8f, 0x88, 0x81, 0x86, 0x93, 0x94, 0x9d, 0x9a,
  0x27, 0x20, 0x29, 0x2e, 0x3b, 0x3c, 0x35, 0x32,
  0x1f, 0x18, 0x11, 0x16, 0x03, 0x04, 0x0d, 0x0a,
  0x57, 0x50, 0x59, 0x5e, 0x4b, 0x4c, 0x45, 0x42,
  0x6f, 0x68, 0x61, 0x66, 0x73, 0x74, 0x7d, 0x7a,
  0x89, 0x8e, 0x87, 0x80, 0x95, 0x92, 0x9b, 0x9c,
  0xb1, 0xb6, 0xbf, 0xb8, 0xad, 0xaa, 0xa3, 0xa4,
  0xf9, 0xfe, 0xf7, 0xf0, 0xe5, 0xe2, 0xeb, 0xec,
  0xc1, 0xc6, 0xcf, 0xc8, 0xdd, 0xda, 0xd3, 0xd4,
  0x69, 0x6e, 0x67, 0x60, 0x75, 0x72, 0x7b, 0x7c,
  0x51, 0x56, 0x5f, 0x58, 0x4d, 0x4a, 0x43, 0x44,
  0x19, 0x1e, 0x17, 0x10, 0x05, 0x02, 0x0b, 0x0c,
  0x21, 0x26, 0x2f, 0x28, 0x3d, 0x3a, 0x33, 0x34,
  0x4e, 0x49, 0x40, 0x47, 0x52, 0x55, 0x5c, 0x5b,
  0x76, 0x71, 0x78, 0x7f, 0x6a, 0x6d, 0x64, 0x63,
  0x3e, 0x39, 0x30, 0x37, 0x22, 0x25, 0x2c, 0x2b,
  0x06, 0x01, 0x08, 0x0f, 0x1a, 0x1d, 0x14, 0x13,
  0xae, 0xa9, 0xa0, 0xa7, 0xb2, 0xb5, 0xbc, 0xbb,
  0x96, 0x91, 0x98, 0x9f, 0x8a, 0x8d, 0x84, 0x83,
  0xde, 0xd9, 0xd0, 0xd7, 0xc2, 0xc5, 0xcc, 0xcb,
  0xe6, 0xe1, 0xe8, 0xef, 0xfa, 0xfd, 0xf4, 0xf3,
};

#define NO_ERROR_DETECTED   -128
#define UNCORRECTIBLE_ERROR  128

static const int err_posn_table[256] = {
  NO_ERROR_DETECTED,      39,
  38,                     UNCORRECTIBLE_ERROR,
  37,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    31,
  36,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    8,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  30,                     UNCORRECTIBLE_ERROR,
  35,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    23,
  7,                      UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  29,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  34,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  22,                     UNCORRECTIBLE_ERROR,
  6,                      UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    0,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  28,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  33,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    10,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    12,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  21,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    19,
  5,                      UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    17,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    3,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    15,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  27,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  32,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  9,                      UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    24,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    1,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  11,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  20,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    13,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  18,                     UNCORRECTIBLE_ERROR,
  4,                      UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  16,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    25,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  2,                      UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  14,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  26,                     UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
  UNCORRECTIBLE_ERROR,    UNCORRECTIBLE_ERROR,
};

/*
 * Return an indication of whether there was an error in the cell header
 * and, if so, where the error was, if it was correctable.
 */
static int
get_header_err(const guint8 *cell_header)
{
  register guint8 syndrome;
  register int i, err_posn;

  syndrome = 0;
  for (i = 0;  i < 4;  i++)
    syndrome = syndrome_table[syndrome ^ cell_header[i]];
  syndrome ^= cell_header[4] ^ COSET_LEADER;

  err_posn = err_posn_table [syndrome];

  if (err_posn < 0)
    return NO_ERROR_DETECTED;
  else if (err_posn < 40)
    return err_posn;
  else
    return UNCORRECTIBLE_ERROR;
}

const value_string atm_pt_vals[] = {
  { 0, "User data cell, congestion not experienced, SDU-type = 0" },
  { 1, "User data cell, congestion not experienced, SDU-type = 1" },
  { 2, "User data cell, congestion experienced, SDU-type = 0" },
  { 3, "User data cell, congestion experienced, SDU-type = 1" },
  { 4, "Segment OAM F5 flow related cell" },
  { 5, "End-to-end OAM F5 flow related cell" },
  { 6, "VC resource management cell" },
  { 0, NULL }
};

/*
 * Charles Michael Heard's CRC-10 code, from
 *
 *      http://www.cell-relay.com/cell-relay/publications/software/CRC/crc10.html
 *
 * with the CRC table initialized with values computed by
 * his "gen_byte_crc10_table()" routine, rather than by calling that
 * routine at run time, and with various data type cleanups.
 */
static const guint16 byte_crc10_table[256] = {
  0x0000, 0x0233, 0x0255, 0x0066, 0x0299, 0x00aa, 0x00cc, 0x02ff,
  0x0301, 0x0132, 0x0154, 0x0367, 0x0198, 0x03ab, 0x03cd, 0x01fe,
  0x0031, 0x0202, 0x0264, 0x0057, 0x02a8, 0x009b, 0x00fd, 0x02ce,
  0x0330, 0x0103, 0x0165, 0x0356, 0x01a9, 0x039a, 0x03fc, 0x01cf,
  0x0062, 0x0251, 0x0237, 0x0004, 0x02fb, 0x00c8, 0x00ae, 0x029d,
  0x0363, 0x0150, 0x0136, 0x0305, 0x01fa, 0x03c9, 0x03af, 0x019c,
  0x0053, 0x0260, 0x0206, 0x0035, 0x02ca, 0x00f9, 0x009f, 0x02ac,
  0x0352, 0x0161, 0x0107, 0x0334, 0x01cb, 0x03f8, 0x039e, 0x01ad,
  0x00c4, 0x02f7, 0x0291, 0x00a2, 0x025d, 0x006e, 0x0008, 0x023b,
  0x03c5, 0x01f6, 0x0190, 0x03a3, 0x015c, 0x036f, 0x0309, 0x013a,
  0x00f5, 0x02c6, 0x02a0, 0x0093, 0x026c, 0x005f, 0x0039, 0x020a,
  0x03f4, 0x01c7, 0x01a1, 0x0392, 0x016d, 0x035e, 0x0338, 0x010b,
  0x00a6, 0x0295, 0x02f3, 0x00c0, 0x023f, 0x000c, 0x006a, 0x0259,
  0x03a7, 0x0194, 0x01f2, 0x03c1, 0x013e, 0x030d, 0x036b, 0x0158,
  0x0097, 0x02a4, 0x02c2, 0x00f1, 0x020e, 0x003d, 0x005b, 0x0268,
  0x0396, 0x01a5, 0x01c3, 0x03f0, 0x010f, 0x033c, 0x035a, 0x0169,
  0x0188, 0x03bb, 0x03dd, 0x01ee, 0x0311, 0x0122, 0x0144, 0x0377,
  0x0289, 0x00ba, 0x00dc, 0x02ef, 0x0010, 0x0223, 0x0245, 0x0076,
  0x01b9, 0x038a, 0x03ec, 0x01df, 0x0320, 0x0113, 0x0175, 0x0346,
  0x02b8, 0x008b, 0x00ed, 0x02de, 0x0021, 0x0212, 0x0274, 0x0047,
  0x01ea, 0x03d9, 0x03bf, 0x018c, 0x0373, 0x0140, 0x0126, 0x0315,
  0x02eb, 0x00d8, 0x00be, 0x028d, 0x0072, 0x0241, 0x0227, 0x0014,
  0x01db, 0x03e8, 0x038e, 0x01bd, 0x0342, 0x0171, 0x0117, 0x0324,
  0x02da, 0x00e9, 0x008f, 0x02bc, 0x0043, 0x0270, 0x0216, 0x0025,
  0x014c, 0x037f, 0x0319, 0x012a, 0x03d5, 0x01e6, 0x0180, 0x03b3,
  0x024d, 0x007e, 0x0018, 0x022b, 0x00d4, 0x02e7, 0x0281, 0x00b2,
  0x017d, 0x034e, 0x0328, 0x011b, 0x03e4, 0x01d7, 0x01b1, 0x0382,
  0x027c, 0x004f, 0x0029, 0x021a, 0x00e5, 0x02d6, 0x02b0, 0x0083,
  0x012e, 0x031d, 0x037b, 0x0148, 0x03b7, 0x0184, 0x01e2, 0x03d1,
  0x022f, 0x001c, 0x007a, 0x0249, 0x00b6, 0x0285, 0x02e3, 0x00d0,
  0x011f, 0x032c, 0x034a, 0x0179, 0x0386, 0x01b5, 0x01d3, 0x03e0,
  0x021e, 0x002d, 0x004b, 0x0278, 0x0087, 0x02b4, 0x02d2, 0x00e1,
};

/* update the data block's CRC-10 remainder one byte at a time */
static guint16
update_crc10_by_bytes(guint16 crc10_accum, const guint8 *data_blk_ptr,
                      int data_blk_size)
{
  register int i;

  for (i = 0;  i < data_blk_size; i++) {
    crc10_accum = ((crc10_accum << 8) & 0x3ff)
      ^ byte_crc10_table[( crc10_accum >> 2) & 0xff]
      ^ *data_blk_ptr++;
  }
  return crc10_accum;
}

static const value_string st_vals[] = {
  { 2, "BOM" },
  { 0, "COM" },
  { 1, "EOM" },
  { 3, "SSM" },
  { 0, NULL }
};

#define OAM_TYPE_FM     1       /* Fault Management */
#define OAM_TYPE_PM     2       /* Performance Management */
#define OAM_TYPE_AD     8       /* Activation/Deactivation */

static const value_string oam_type_vals[] = {
  { OAM_TYPE_FM, "Fault Management" },
  { OAM_TYPE_PM, "Performance Management" },
  { OAM_TYPE_AD, "Activation/Deactivation" },
  { 0,           NULL }
};

static const value_string ft_fm_vals[] = {
  { 0, "Alarm Indication Signal" },
  { 1, "Far End Receive Failure" },
  { 8, "OAM Cell Loopback" },
  { 4, "Continuity Check" },
  { 0, NULL }
};

static const value_string ft_pm_vals[] = {
  { 0, "Forward Monitoring" },
  { 1, "Backward Reporting" },
  { 2, "Monitoring and Reporting" },
  { 0, NULL }
};

static const value_string ft_ad_vals[] = {
  { 0, "Performance Monitoring" },
  { 1, "Continuity Check" },
  { 0, NULL }
};


/*
 * Check for OAM cells.
 * OAM F4 is VCI 3 or 4 and PT 0X0.
 * OAM F5 is PT 10X.
 */
gboolean atm_is_oam_cell(const guint16 vci, const guint8 pt)
{
  return  (((vci == 3 || vci == 4) && ((pt & 0x5) == 0))
           || ((pt & 0x6) == 0x4));
}


static void
dissect_atm_cell(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 proto_tree *atm_tree, guint aal, gboolean nni,
                 gboolean crc_stripped)
{
  int          offset;
  proto_tree   *aal_tree;
  proto_item   *ti;
  guint8       octet;
  int          err;
  guint16      vpi;
  guint16      vci;
  guint8       pt;
  guint16      aal3_4_hdr, aal3_4_trlr;
  guint16      oam_crc;
  gint         length;
  guint16      crc10;
  tvbuff_t     *next_tvb;
  const pwatm_private_data_t * pwpd = pinfo->private_data;

  if (NULL == pwpd) {
    if (!nni) {
      /*
       * FF: ITU-T I.361 (Section 2.2) defines the cell header format
       * and encoding at UNI reference point as:
       *
       *  8 7 6 5 4 3 2 1
       * +-+-+-+-+-+-+-+-+
       * |  GFC  |  VPI  |
       * +-+-+-+-+-+-+-+-+
       * |  VPI  |  VCI  |
       * +-+-+-+-+-+-+-+-+
       * |      VCI      |
       * +-+-+-+-+-+-+-+-+
       * |  VCI  |  PT |C|
       * +-+-+-+-+-+-+-+-+
       * |   HEC (CRC)   |
       * +-+-+-+-+-+-+-+-+
       */
      octet = tvb_get_guint8(tvb, 0);
      proto_tree_add_text(atm_tree, tvb, 0, 1, "GFC: 0x%x", octet >> 4);
      vpi = (octet & 0xF) << 4;
      octet = tvb_get_guint8(tvb, 1);
      vpi |= octet >> 4;
      proto_tree_add_uint(atm_tree, hf_atm_vpi, tvb, 0, 2, vpi);
    } else {
      /*
       * FF: ITU-T I.361 (Section 2.3) defines the cell header format
       * and encoding at NNI reference point as:
       *
       *  8 7 6 5 4 3 2 1
       * +-+-+-+-+-+-+-+-+
       * |      VPI      |
       * +-+-+-+-+-+-+-+-+
       * |  VPI  |  VCI  |
       * +-+-+-+-+-+-+-+-+
       * |      VCI      |
       * +-+-+-+-+-+-+-+-+
       * |  VCI  |  PT |C|
       * +-+-+-+-+-+-+-+-+
       * |   HEC (CRC)   |
       * +-+-+-+-+-+-+-+-+
       */
      octet = tvb_get_guint8(tvb, 0);
      vpi = octet << 4;
      octet = tvb_get_guint8(tvb, 1);
      vpi |= (octet & 0xF0) >> 4;
      proto_tree_add_uint(atm_tree, hf_atm_vpi, tvb, 0, 2, vpi);
    }

    vci = (octet & 0x0F) << 12;
    octet = tvb_get_guint8(tvb, 2);
    vci |= octet << 4;
    octet = tvb_get_guint8(tvb, 3);
    vci |= octet >> 4;
    proto_tree_add_uint(atm_tree, hf_atm_vci, tvb, 1, 3, vci);
    pt = (octet >> 1) & 0x7;
    proto_tree_add_text(atm_tree, tvb, 3, 1, "Payload Type: %s",
                        val_to_str(pt, atm_pt_vals, "Unknown (%u)"));
    proto_tree_add_text(atm_tree, tvb, 3, 1, "Cell Loss Priority: %s",
                        (octet & 0x01) ? "Low priority" : "High priority");

    if (!crc_stripped) {
      /*
       * FF: parse the Header Error Check (HEC).
       */
      ti = proto_tree_add_text(atm_tree, tvb, 4, 1,
                               "Header Error Check: 0x%02x",
                               tvb_get_guint8(tvb, 4));
      err = get_header_err(tvb_get_ptr(tvb, 0, 5));
      if (err == NO_ERROR_DETECTED)
        proto_item_append_text(ti, " (correct)");
      else if (err == UNCORRECTIBLE_ERROR)
        proto_item_append_text(ti, " (uncorrectable error)");
      else
        proto_item_append_text(ti, " (error in bit %d)", err);
      offset = 5;
    } else {
      /*
       * FF: in some encapsulation modes (e.g. RFC 4717, ATM N-to-One
       * Cell Mode) the Header Error Check (HEC) field is stripped.
       * So we do nothing here.
       */
      offset = 4;
    }
  }
  else
  {
    offset = 0; /* For PWs. Header is decoded by PW dissector.*/
    pwpd = pinfo->private_data;
    vpi = pwpd->vpi;
    vci = pwpd->vci;
    pt  = pwpd->pti;
  }

  /*
   * Check for OAM cells.
   * XXX - do this for all AAL values, overriding whatever information
   * Wiretap got from the file?
   */
  if (aal == AAL_USER) {
    if (atm_is_oam_cell(vci,pt)) {
      aal = AAL_OAMCELL;
    }
  }

  switch (aal) {

  case AAL_1:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AAL1");
    col_clear(pinfo->cinfo, COL_INFO);
    ti = proto_tree_add_item(tree, proto_aal1, tvb, offset, -1, ENC_NA);
    aal_tree = proto_item_add_subtree(ti, ett_aal1);
    octet = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(aal_tree, tvb, offset, 1, "CSI: %u", octet >> 7);
    proto_tree_add_text(aal_tree, tvb, offset, 1, "Sequence Count: %u",
                        (octet >> 4) & 0x7);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Sequence count = %u",
                 (octet >> 4) & 0x7);
    proto_tree_add_text(aal_tree, tvb, offset, 1, "CRC: 0x%x",
                        (octet >> 1) & 0x7);
    proto_tree_add_text(aal_tree, tvb, offset, 1, "Parity: %u",
                        octet & 0x1);
    offset++;

    proto_tree_add_text(aal_tree, tvb, offset, 47, "Payload");
    break;

  case AAL_3_4:
    /*
     * XXX - or should this be the CS PDU?
     */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AAL3/4");
    col_clear(pinfo->cinfo, COL_INFO);
    ti = proto_tree_add_item(tree, proto_aal3_4, tvb, offset, -1, ENC_NA);
    aal_tree = proto_item_add_subtree(ti, ett_aal3_4);
    aal3_4_hdr = tvb_get_ntohs(tvb, offset);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s, sequence number = %u",
                 val_to_str(aal3_4_hdr >> 14, st_vals, "Unknown (%u)"),
                 (aal3_4_hdr >> 10) & 0xF);
    proto_tree_add_text(aal_tree, tvb, offset, 2, "Segment Type: %s",
                        val_to_str(aal3_4_hdr >> 14, st_vals, "Unknown (%u)"));
    proto_tree_add_text(aal_tree, tvb, offset, 2, "Sequence Number: %u",
                        (aal3_4_hdr >> 10) & 0xF);
    proto_tree_add_text(aal_tree, tvb, offset, 2, "Multiplex ID: %u",
                        aal3_4_hdr & 0x3FF);
    offset += 2;

    proto_tree_add_text(aal_tree, tvb, offset, 44, "Information");
    offset += 44;

    aal3_4_trlr = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(aal_tree, tvb, offset, 2, "Length Indicator: %u",
                        (aal3_4_trlr >> 10) & 0x3F);
    length = tvb_length_remaining(tvb, 5);
    crc10 = update_crc10_by_bytes(0, tvb_get_ptr(tvb, 5, length),
                                  length);
    proto_tree_add_text(aal_tree, tvb, offset, 2, "CRC: 0x%03x (%s)",
                        aal3_4_trlr & 0x3FF,
                        (crc10 == 0) ? "correct" : "incorrect");
    break;

  case AAL_OAMCELL:
    if (NULL == pwpd || pwpd->enable_fill_columns_by_atm_dissector)
    {
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "OAM AAL");
      col_clear(pinfo->cinfo, COL_INFO);
    }
    ti = proto_tree_add_item(tree, proto_oamaal, tvb, offset, -1, ENC_NA);
    aal_tree = proto_item_add_subtree(ti, ett_oamaal);
    octet = tvb_get_guint8(tvb, offset);
    if (NULL == pwpd || pwpd->enable_fill_columns_by_atm_dissector)
    {
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                   val_to_str(octet >> 4, oam_type_vals, "Unknown (%u)"));
    }
    proto_tree_add_text(aal_tree, tvb, offset, 1, "OAM Type: %s",
                        val_to_str(octet >> 4, oam_type_vals, "Unknown (%u)"));
    switch (octet >> 4) {

    case OAM_TYPE_FM:
      proto_tree_add_text(aal_tree, tvb, offset, 1, "Function Type: %s",
                          val_to_str(octet & 0x0F, ft_fm_vals, "Unknown (%u)"));
      break;

    case OAM_TYPE_PM:
      proto_tree_add_text(aal_tree, tvb, offset, 1, "Function Type: %s",
                          val_to_str(octet & 0x0F, ft_pm_vals, "Unknown (%u)"));
      break;

    case OAM_TYPE_AD:
      proto_tree_add_text(aal_tree, tvb, offset, 1, "Function Type: %s",
                          val_to_str(octet & 0x0F, ft_ad_vals, "Unknown (%u)"));
      break;

    default:
      proto_tree_add_text(aal_tree, tvb, offset, 1, "Function Type: %u",
                          octet & 0x0F);
      break;
    }
    offset += 1;

    proto_tree_add_text(aal_tree, tvb, offset, 45, "Function-specific information");
    offset += 45;

    length = tvb_length_remaining(tvb, 5);
    crc10 = update_crc10_by_bytes(0, tvb_get_ptr(tvb, 5, length),
                                  length);
    oam_crc = tvb_get_ntohs(tvb, offset);
    proto_tree_add_text(aal_tree, tvb, offset, 2, "CRC-10: 0x%03x (%s)",
                        oam_crc & 0x3FF,
                        (crc10 == 0) ? "correct" : "incorrect");
    break;

  default:
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(data_handle, next_tvb, pinfo, tree);
    break;
  }
}

static void
dissect_atm_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean truncated)
{
  proto_tree   *atm_tree = NULL;
  proto_item   *atm_ti = NULL;
  gboolean     pseudowire_mode = (NULL != pinfo->private_data);

  if ( pinfo->pseudo_header->atm.aal == AAL_5 &&
       pinfo->pseudo_header->atm.type == TRAF_LANE &&
       dissect_lanesscop ) {
    pinfo->pseudo_header->atm.aal = AAL_SIGNALLING;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATM");

  if (!pseudowire_mode) {
    switch (pinfo->pseudo_header->atm.channel) {

    case 0:
      /* Traffic from DTE to DCE. */
      col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DCE");
      col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DTE");
      break;

    case 1:
      /* Traffic from DCE to DTE. */
      col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DTE");
      col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DCE");
      break;
    }
  }

  if (pinfo->pseudo_header->atm.aal == AAL_5) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "AAL5 %s",
                 val_to_str(pinfo->pseudo_header->atm.type, aal5_hltype_vals,
                            "Unknown traffic type (%u)"));
  } else {
    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(pinfo->pseudo_header->atm.aal, aal_vals,
                           "Unknown AAL (%u)"));
  }

  if (tree) {
    atm_ti = proto_tree_add_item(tree, proto_atm, tvb, 0, -1, ENC_NA);
    atm_tree = proto_item_add_subtree(atm_ti, ett_atm);

    if (!pseudowire_mode) {
      switch (pinfo->pseudo_header->atm.channel) {

      case 0:
        /* Traffic from DTE to DCE. */
        proto_tree_add_text(atm_tree, tvb, 0, 0, "Channel: DTE->DCE");
        break;

      case 1:
        /* Traffic from DCE to DTE. */
        proto_tree_add_text(atm_tree, tvb, 0, 0, "Channel: DCE->DTE");
        break;

      default:
        /* Sniffers shouldn't provide anything other than 0 or 1. */
        proto_tree_add_text(atm_tree, tvb, 0, 0, "Channel: %u",
                            pinfo->pseudo_header->atm.channel);
        break;
      }
    }

    proto_tree_add_uint_format_value(atm_tree, hf_atm_aal, tvb, 0, 0,
                                     pinfo->pseudo_header->atm.aal,
                                     "%s",
                                     val_to_str(pinfo->pseudo_header->atm.aal, aal_vals,
                                                "Unknown AAL (%u)"));
  }
  if (pinfo->pseudo_header->atm.flags & ATM_RAW_CELL) {
    /* This is a single cell, with the cell header at the beginning. */
    if (pinfo->pseudo_header->atm.flags & ATM_NO_HEC) {
      proto_item_set_len(atm_ti, 4);
    } else {
      proto_item_set_len(atm_ti, 5);
    }
    dissect_atm_cell(tvb, pinfo, tree, atm_tree,
                     pinfo->pseudo_header->atm.aal, FALSE,
                     pinfo->pseudo_header->atm.flags & ATM_NO_HEC);
  } else {
    /* This is a reassembled PDU. */
    dissect_reassembled_pdu(tvb, pinfo, tree, atm_tree, atm_ti, truncated);
  }
}

static void
dissect_atm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_atm_common(tvb, pinfo, tree, TRUE);
}

static void
dissect_atm_untruncated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_atm_common(tvb, pinfo, tree, ENC_BIG_ENDIAN);
}

static void
dissect_atm_oam_cell(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree   *atm_tree = NULL;
  proto_item   *atm_ti = NULL;
  gboolean     pseudowire_mode = (NULL != pinfo->private_data);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATM");

  if (!pseudowire_mode) {
    if (tree) {
      atm_ti = proto_tree_add_protocol_format(tree, proto_atm, tvb, 0, 0, "ATM");
      atm_tree = proto_item_add_subtree(atm_ti, ett_atm);
    }
  }

  dissect_atm_cell(tvb, pinfo, tree, atm_tree, AAL_OAMCELL, FALSE, ENC_BIG_ENDIAN);
}


void
proto_register_atm(void)
{
  static hf_register_info hf[] = {
    { &hf_atm_aal,
      { "AAL",          "atm.aal", FT_UINT8, BASE_DEC, VALS(aal_vals), 0x0,
        NULL, HFILL }},

    { &hf_atm_vpi,
      { "VPI",          "atm.vpi", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_atm_vci,
      { "VCI",          "atm.vci", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

    { &hf_atm_cid,
      { "CID",          "atm.cid", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},

  };
  static gint *ett[] = {
    &ett_atm,
    &ett_ilmi,
    &ett_aal1,
    &ett_aal3_4,
    &ett_oamaal,
    &ett_atm_lane,
    &ett_atm_lane_lc_lan_dest,
    &ett_atm_lane_lc_lan_dest_rd,
    &ett_atm_lane_lc_flags,
    &ett_atm_lane_lc_tlv,
  };

  static enum_val_t unknown_aal2_options[] = {
    { "raw",     "Raw data", TRAF_UNKNOWN },
    { "umts_fp", "UMTS FP",  TRAF_UMTS_FP },
    { NULL, NULL, 0 }
  };

  module_t *atm_module;

  proto_atm = proto_register_protocol("Asynchronous Transfer Mode", "ATM", "atm");
  proto_aal1 = proto_register_protocol("ATM AAL1", "AAL1", "aal1");
  proto_aal3_4 = proto_register_protocol("ATM AAL3/4", "AAL3/4", "aal3_4");
  proto_oamaal = proto_register_protocol("ATM OAM AAL", "OAM AAL", "oamaal");
  proto_register_field_array(proto_atm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  proto_ilmi = proto_register_protocol("ILMI", "ILMI", "ilmi");

  register_dissector("ilmi", dissect_ilmi, proto_ilmi);

  proto_atm_lane = proto_register_protocol("ATM LAN Emulation",
                                           "ATM LANE", "lane");

  register_dissector("lane", dissect_lane, proto_atm_lane);
  register_dissector("atm_untruncated", dissect_atm_untruncated, proto_atm);
  register_dissector("atm_truncated", dissect_atm, proto_atm);
  register_dissector("atm_oam_cell", dissect_atm_oam_cell, proto_oamaal);

  atm_module = prefs_register_protocol ( proto_atm, NULL );
  prefs_register_bool_preference ( atm_module, "dissect_lane_as_sscop", "Dissect LANE as SSCOP",
                                   "Autodection between LANE and SSCOP is hard. As default LANE is preferred",
                                   &dissect_lanesscop);
  prefs_register_enum_preference ( atm_module, "unknown_aal2_type",
                                   "Decode unknown AAL2 traffic as",
                                   "Type used to dissect unknown AAL2 traffic",
                                   &unknown_aal2_type, unknown_aal2_options, ENC_BIG_ENDIAN);

}

void
proto_reg_handoff_atm(void)
{
  dissector_handle_t atm_handle, atm_untruncated_handle;

  /*
   * Get handles for the Ethernet, Token Ring, Frame Relay, LLC,
   * SSCOP, LANE, and ILMI dissectors.
   */
  eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
  tr_handle = find_dissector("tr");
  fr_handle = find_dissector("fr");
  llc_handle = find_dissector("llc");
  sscop_handle = find_dissector("sscop");
  lane_handle = find_dissector("lane");
  ilmi_handle = find_dissector("ilmi");
  ppp_handle = find_dissector("ppp");
  eth_handle = find_dissector("eth");
  ip_handle = find_dissector("ip");
  data_handle = find_dissector("data");
  fp_handle = find_dissector("fp");
  gprs_ns_handle = find_dissector("gprs_ns");

  atm_handle = create_dissector_handle(dissect_atm, proto_atm);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_ATM_PDUS, atm_handle);

  atm_untruncated_handle = create_dissector_handle(dissect_atm_untruncated,
                                                   proto_atm);
  dissector_add_uint("wtap_encap", WTAP_ENCAP_ATM_PDUS_UNTRUNCATED,
                atm_untruncated_handle);
}
