/* packet-atm.c
 * Routines for ATM packet disassembly
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
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <wsutil/pint.h>
#include <epan/oui.h>
#include <epan/addr_resolv.h>
#include <epan/ppptypes.h>
#include <epan/expert.h>
#include <epan/crc10-tvb.h>
#include <epan/crc32-tvb.h>
#include <epan/decode_as.h>

#include "packet-atm.h"
#include "packet-snmp.h"
#include "packet-eth.h"
#include "packet-tr.h"
#include "packet-llc.h"
#include <epan/prefs.h>
#include "packet-pw-atm.h"

void proto_register_atm(void);
void proto_reg_handoff_atm(void);

static int proto_atm = -1;
static int hf_atm_aal = -1;
static int hf_atm_gfc = -1;
static int hf_atm_vpi = -1;
static int hf_atm_vci = -1;
static int hf_atm_cid = -1;
static int hf_atm_reserved = -1;
static int proto_atm_lane = -1;
static int proto_ilmi = -1;
static int proto_aal1 = -1;
static int proto_aal3_4 = -1;
static int proto_oamaal = -1;

static int hf_atm_le_client_client = -1;
static int hf_atm_lan_destination_tag = -1;
static int hf_atm_lan_destination_mac = -1;
static int hf_atm_le_control_tlv_type = -1;
static int hf_atm_le_control_tlv_length = -1;
static int hf_atm_lan_destination_route_desc = -1;
static int hf_atm_lan_destination_lan_id = -1;
static int hf_atm_lan_destination_bridge_num = -1;
static int hf_atm_source_atm = -1;
static int hf_atm_target_atm = -1;
static int hf_atm_le_configure_join_frame_lan_type = -1;
static int hf_atm_le_configure_join_frame_max_frame_size = -1;
static int hf_atm_le_configure_join_frame_num_tlvs = -1;
static int hf_atm_le_configure_join_frame_elan_name_size = -1;
static int hf_atm_le_configure_join_frame_elan_name = -1;
static int hf_atm_le_registration_frame_num_tlvs = -1;
static int hf_atm_le_arp_frame_num_tlvs = -1;
static int hf_atm_le_verify_frame_num_tlvs = -1;
static int hf_atm_le_control_marker = -1;
static int hf_atm_le_control_protocol = -1;
static int hf_atm_le_control_version = -1;
static int hf_atm_le_control_opcode = -1;
static int hf_atm_le_control_status = -1;
static int hf_atm_le_control_transaction_id = -1;
static int hf_atm_le_control_requester_lecid = -1;
static int hf_atm_le_control_flags = -1;
static int hf_atm_le_control_flag_v2_capable = -1;
static int hf_atm_le_control_flag_selective_multicast = -1;
static int hf_atm_le_control_flag_v2_required = -1;
static int hf_atm_le_control_flag_proxy = -1;
static int hf_atm_le_control_flag_exclude_explorer_frames = -1;
static int hf_atm_le_control_flag_address = -1;
static int hf_atm_le_control_topology_change = -1;
static int hf_atm_traffic_type = -1;
static int hf_atm_traffic_vcmx = -1;
static int hf_atm_traffic_lane = -1;
static int hf_atm_traffic_ipsilon = -1;
static int hf_atm_cells = -1;
static int hf_atm_aal5_uu = -1;
static int hf_atm_aal5_cpi = -1;
static int hf_atm_aal5_len = -1;
static int hf_atm_aal5_crc = -1;
static int hf_atm_payload_type = -1;
static int hf_atm_cell_loss_priority = -1;
static int hf_atm_header_error_check = -1;
static int hf_atm_channel = -1;
static int hf_atm_aa1_csi = -1;
static int hf_atm_aa1_seq_count = -1;
static int hf_atm_aa1_crc = -1;
static int hf_atm_aa1_parity = -1;
static int hf_atm_aa1_payload = -1;
static int hf_atm_aal3_4_seg_type = -1;
static int hf_atm_aal3_4_seq_num = -1;
static int hf_atm_aal3_4_multiplex_id = -1;
static int hf_atm_aal3_4_information = -1;
static int hf_atm_aal3_4_length_indicator = -1;
static int hf_atm_aal3_4_crc = -1;
static int hf_atm_aal_oamcell_type = -1;
static int hf_atm_aal_oamcell_type_fm = -1;
static int hf_atm_aal_oamcell_type_pm = -1;
static int hf_atm_aal_oamcell_type_ad = -1;
static int hf_atm_aal_oamcell_type_ft = -1;
static int hf_atm_aal_oamcell_func_spec = -1;
static int hf_atm_aal_oamcell_crc = -1;
static int hf_atm_padding = -1;

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

static expert_field ei_atm_reassembly_failed = EI_INIT;

static dissector_handle_t atm_handle;
static dissector_handle_t atm_untruncated_handle;

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t tr_handle;
static dissector_handle_t fr_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t sscop_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t eth_maybefcs_handle;
static dissector_handle_t ip_handle;

static gboolean dissect_lanesscop = FALSE;

static dissector_table_t atm_type_aal2_table;
static dissector_table_t atm_type_aal5_table;

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

static const value_string atm_channel_vals[] = {
  { 0, "DTE->DCE" },
  { 1, "DCE->DTE" },
  { 0,    NULL }
};

static const true_false_string tfs_remote_local = { "Remote", "Local" };
static const true_false_string tfs_low_high_priority = { "Low priority", "High priority" };


static void
dissect_le_client(tvbuff_t *tvb, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lane_tree;

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_atm_lane, tvb, 0, 2, "ATM LANE");
    lane_tree = proto_item_add_subtree(ti, ett_atm_lane);

    proto_tree_add_item(lane_tree, hf_atm_le_client_client, tvb, 0, 2, ENC_BIG_ENDIAN );
  }
}

static void
dissect_lan_destination(tvbuff_t *tvb, int offset, const char *type, proto_tree *tree)
{
  proto_item *td;
  proto_tree *dest_tree;
  guint16     tag;
  proto_tree *rd_tree;

  dest_tree = proto_tree_add_subtree_format(tree, tvb, offset, 8,
                                    ett_atm_lane_lc_lan_dest, NULL, "%s LAN destination", type);
  tag = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(dest_tree, hf_atm_lan_destination_tag, tvb, offset, 2, ENC_BIG_ENDIAN );
  offset += 2;

  switch (tag) {

  case TAG_MAC_ADDRESS:
    proto_tree_add_item(dest_tree, hf_atm_lan_destination_mac, tvb, offset, 6, ENC_NA);
    break;

  case TAG_ROUTE_DESCRIPTOR:
    offset += 4;
    td = proto_tree_add_item(dest_tree, hf_atm_lan_destination_route_desc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    rd_tree = proto_item_add_subtree(td, ett_atm_lane_lc_lan_dest_rd);
    proto_tree_add_item(rd_tree, hf_atm_lan_destination_lan_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(rd_tree, hf_atm_lan_destination_bridge_num, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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
  guint32     tlv_type;
  guint8      tlv_length;
  proto_tree *tlv_tree;

  while (num_tlvs != 0) {
    tlv_type = tvb_get_ntohl(tvb, offset);
    tlv_length = tvb_get_guint8(tvb, offset+4);
    tlv_tree = proto_tree_add_subtree_format(tree, tvb, offset, 5+tlv_length, ett_atm_lane_lc_tlv, NULL,
                                                "TLV type: %s", val_to_str(tlv_type, le_tlv_type_vals, "Unknown (0x%08x)"));
    proto_tree_add_item(tlv_tree, hf_atm_le_control_tlv_type, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(tlv_tree, hf_atm_le_control_tlv_length, tvb, offset+4, 1, ENC_BIG_ENDIAN);
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

  proto_tree_add_item(tree, hf_atm_source_atm, tvb, offset, 20, ENC_NA);
  offset += 20;

  proto_tree_add_item(tree, hf_atm_le_configure_join_frame_lan_type, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_atm_le_configure_join_frame_max_frame_size, tvb, offset, 1, ENC_NA);
  offset += 1;

  num_tlvs = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_atm_le_configure_join_frame_num_tlvs, tvb, offset, 1, ENC_NA);
  offset += 1;

  name_size = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_atm_le_configure_join_frame_elan_name_size, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_atm_target_atm, tvb, offset, 20, ENC_NA);
  offset += 20;

  if (name_size > 32)
    name_size = 32;
  if (name_size != 0) {
    proto_tree_add_item(tree, hf_atm_le_configure_join_frame_elan_name, tvb, offset, name_size, ENC_NA);
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

  proto_tree_add_item(tree, hf_atm_source_atm, tvb, offset, 20, ENC_NA);
  offset += 20;

  proto_tree_add_item(tree, hf_atm_reserved, tvb, offset, 2, ENC_NA);
  offset += 2;

  num_tlvs = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_atm_le_registration_frame_num_tlvs, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_atm_reserved, tvb, offset, 53, ENC_NA);
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

  proto_tree_add_item(tree, hf_atm_source_atm, tvb, offset, 20, ENC_NA);
  offset += 20;

  proto_tree_add_item(tree, hf_atm_reserved, tvb, offset, 2, ENC_NA);
  offset += 2;

  num_tlvs = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_atm_le_arp_frame_num_tlvs, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_atm_reserved, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_atm_target_atm, tvb, offset, 20, ENC_NA);
  offset += 20;

  proto_tree_add_item(tree, hf_atm_reserved, tvb, offset, 32, ENC_NA);
  offset += 32;

  dissect_le_control_tlvs(tvb, offset, num_tlvs, tree);
}

static void
dissect_le_verify_frame(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  guint8 num_tlvs;

  proto_tree_add_item(tree, hf_atm_reserved, tvb, offset, 38, ENC_NA);
  offset += 38;

  num_tlvs = tvb_get_guint8(tvb, offset);
  proto_tree_add_item(tree, hf_atm_le_verify_frame_num_tlvs, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_atm_reserved, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_atm_target_atm, tvb, offset, 20, ENC_NA);
  offset += 20;

  proto_tree_add_item(tree, hf_atm_reserved, tvb, offset, 32, ENC_NA);
  offset += 32;

  dissect_le_control_tlvs(tvb, offset, num_tlvs, tree);
}

static int
dissect_le_flush_frame(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  dissect_lan_destination(tvb, offset, "Source", tree);
  offset += 8;

  dissect_lan_destination(tvb, offset, "Target", tree);
  offset += 8;

  proto_tree_add_item(tree, hf_atm_source_atm, tvb, offset, 20, ENC_NA);
  offset += 20;

  proto_tree_add_item(tree, hf_atm_reserved, tvb, offset, 4, ENC_NA);
  offset += 4;

  proto_tree_add_item(tree, hf_atm_target_atm, tvb, offset, 20, ENC_NA);
  offset += 20;

  proto_tree_add_item(tree, hf_atm_reserved, tvb, offset, 32, ENC_NA);
  offset += 32;

  return offset;
}

static void
dissect_le_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item *ti;
  proto_tree *lane_tree = NULL;
  int         offset    = 0;
  proto_item *tf;
  proto_tree *flags_tree;
  guint16     opcode;

  col_set_str(pinfo->cinfo, COL_INFO, "LE Control");

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_atm_lane, tvb, offset, 108, "ATM LANE");
    lane_tree = proto_item_add_subtree(ti, ett_atm_lane);

    proto_tree_add_item(lane_tree, hf_atm_le_control_marker, tvb, offset, 2, ENC_BIG_ENDIAN );
  }
  offset += 2;

  if (tree) {
    proto_tree_add_item(lane_tree, hf_atm_le_control_protocol, tvb, offset, 1, ENC_BIG_ENDIAN );

  }
  offset += 1;

  if (tree) {
    proto_tree_add_item(lane_tree, hf_atm_le_control_version, tvb, offset, 1, ENC_BIG_ENDIAN );
  }
  offset += 1;

  opcode = tvb_get_ntohs(tvb, offset);
  col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
                  val_to_str(opcode, le_control_opcode_vals,
                             "Unknown opcode (0x%04X)"));

  if (tree) {
    proto_tree_add_item(lane_tree, hf_atm_le_control_opcode, tvb, offset, 2, ENC_BIG_ENDIAN );
  }
  offset += 2;

  if (opcode == READY_QUERY || opcode == READY_IND) {
    /* There's nothing more in this packet. */
    return;
  }

  if (tree) {
    if (opcode & 0x0100) {
      /* Response; decode status. */
      proto_tree_add_item(lane_tree, hf_atm_le_control_status, tvb, offset, 2, ENC_BIG_ENDIAN );
    }
    offset += 2;

    proto_tree_add_item(lane_tree, hf_atm_le_control_transaction_id, tvb, offset, 4, ENC_BIG_ENDIAN );
    offset += 4;

    proto_tree_add_item(lane_tree, hf_atm_le_control_requester_lecid, tvb, offset, 2, ENC_BIG_ENDIAN );
    offset += 2;

    tf = proto_tree_add_item(lane_tree, hf_atm_le_control_flags, tvb, offset, 2, ENC_BIG_ENDIAN );
    flags_tree = proto_item_add_subtree(tf, ett_atm_lane_lc_flags);

    switch (opcode) {

    case LE_CONFIGURE_REQUEST:
    case LE_CONFIGURE_RESPONSE:
      proto_tree_add_item(flags_tree, hf_atm_le_control_flag_v2_capable, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      dissect_le_configure_join_frame(tvb, offset, lane_tree);
      break;

    case LE_JOIN_REQUEST:
    case LE_JOIN_RESPONSE:
      proto_tree_add_item(flags_tree, hf_atm_le_control_flag_v2_capable, tvb, offset, 2, ENC_BIG_ENDIAN);
      if (opcode == LE_JOIN_REQUEST) {
        proto_tree_add_item(flags_tree, hf_atm_le_control_flag_selective_multicast, tvb, offset, 2, ENC_BIG_ENDIAN);
      } else {
        proto_tree_add_item(flags_tree, hf_atm_le_control_flag_v2_required, tvb, offset, 2, ENC_BIG_ENDIAN);
      }

      proto_tree_add_item(flags_tree, hf_atm_le_control_flag_proxy, tvb, offset, 2, ENC_BIG_ENDIAN);
      proto_tree_add_item(flags_tree, hf_atm_le_control_flag_exclude_explorer_frames, tvb, offset, 2, ENC_BIG_ENDIAN);

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
        proto_tree_add_item(flags_tree, hf_atm_le_control_flag_address, tvb, offset, 2, ENC_BIG_ENDIAN);
      }
      offset += 2;
      dissect_le_arp_frame(tvb, offset, lane_tree);
      break;

    case LE_TOPOLOGY_REQUEST:
        proto_tree_add_item(flags_tree, hf_atm_le_control_topology_change, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(flags_tree, hf_atm_reserved, tvb, offset, 92, ENC_NA);
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

static gboolean
capture_lane(const guchar *pd, int offset _U_,
    int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
  /* Is it LE Control, 802.3, 802.5, or "none of the above"? */
  return try_capture_dissector("atm_lane", pseudo_header->atm.subtype, pd, 2, len, cpinfo, pseudo_header);
}

static int
dissect_lane(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct atm_phdr *atm_info = (struct atm_phdr *)data;
  tvbuff_t *next_tvb;
  tvbuff_t *next_tvb_le_client;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATM LANE");

  /* Is it LE Control, 802.3, 802.5, or "none of the above"? */
  switch (atm_info->subtype) {

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
    call_data_dissector(next_tvb, pinfo, tree);
    break;
  }
  return tvb_captured_length(tvb);
}

static int
dissect_ilmi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  return dissect_snmp_pdu(tvb, 0, pinfo, tree, proto_ilmi, ett_ilmi, FALSE);
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
  { TRAF_SSCOP,             "SSCOP" },
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

static gboolean
capture_atm(const guchar *pd, int offset,
    int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
  if (pseudo_header->atm.aal == AAL_5) {
    return try_capture_dissector("atm.aal5.type", pseudo_header->atm.type, pd, offset, len, cpinfo, pseudo_header);
  }
  return FALSE;
}

static void
dissect_reassembled_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_item *atm_ti, proto_tree *atm_tree, gboolean truncated,
    struct atm_phdr *atm_info, gboolean pseudowire_mode)
{
  guint     length, reported_length;
  guint16   aal5_length;
  int       pad_length;
  tvbuff_t *next_tvb;
  guint32   crc;
  guint32   calc_crc;
  gboolean  decoded;

  /*
   * This is reassembled traffic, so the cell headers are missing;
   * show the traffic type for AAL5 traffic, and the VPI and VCI,
   * from the pseudo-header.
   */
  if (atm_info->aal == AAL_5) {
    proto_tree_add_uint(atm_tree, hf_atm_traffic_type, tvb, 0, 0, atm_info->type);

    switch (atm_info->type) {

    case TRAF_VCMX:
      proto_tree_add_uint(atm_tree, hf_atm_traffic_vcmx, tvb, 0, 0, atm_info->subtype);
      break;

    case TRAF_LANE:
      proto_tree_add_uint(atm_tree, hf_atm_traffic_lane, tvb, 0, 0, atm_info->subtype);
      break;

    case TRAF_IPSILON:
      proto_tree_add_uint(atm_tree, hf_atm_traffic_ipsilon, tvb, 0, 0, atm_info->subtype);
      break;
    }
  }
  if (!pseudowire_mode) {
    proto_tree_add_uint(atm_tree, hf_atm_vpi, tvb, 0, 0, atm_info->vpi);
    proto_tree_add_uint(atm_tree, hf_atm_vci, tvb, 0, 0, atm_info->vci);

    /* Also show vpi/vci in info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, " VPI=%u, VCI=%u",
                    atm_info->vpi, atm_info->vci);
  }

  next_tvb = tvb;
  if (truncated || atm_info->flags & ATM_REASSEMBLY_ERROR) {
    /*
     * The packet data does not include stuff such as the AAL5
     * trailer, either because it was explicitly left out or because
     * reassembly failed.
     */
    if (atm_info->cells != 0) {
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
        proto_tree_add_uint(atm_tree, hf_atm_cells, tvb, 0, 0, atm_info->cells);
        proto_tree_add_uint(atm_tree, hf_atm_aal5_uu, tvb, 0, 0, atm_info->aal5t_u2u >> 8);
        proto_tree_add_uint(atm_tree, hf_atm_aal5_cpi, tvb, 0, 0, atm_info->aal5t_u2u & 0xFF);
        proto_tree_add_uint(atm_tree, hf_atm_aal5_len, tvb, 0, 0, atm_info->aal5t_len);
        proto_tree_add_uint(atm_tree, hf_atm_aal5_crc, tvb, 0, 0, atm_info->aal5t_chksum);
      }
    }
  } else {
    /*
     * The packet data includes stuff such as the AAL5 trailer, if
     * it wasn't cut off by the snapshot length, and ATM reassembly
     * succeeded.
     * Decode the trailer, if present, and then chop it off.
     */
    length = tvb_captured_length(tvb);
    reported_length = tvb_reported_length(tvb);
    if ((reported_length % 48) == 0) {
      /*
       * Reported length is a multiple of 48, so we can presumably
       * divide it by 48 to get the number of cells.
       */
      proto_tree_add_uint(atm_tree, hf_atm_cells, tvb, 0, 0, reported_length/48);
    }
    if ((atm_info->aal == AAL_5 || atm_info->aal == AAL_SIGNALLING) &&
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
            proto_item *ti;

            if (pad_length > 0) {
              proto_tree_add_item(atm_tree, hf_atm_padding, tvb, aal5_length, pad_length, ENC_NA);
            }

            proto_tree_add_item(atm_tree, hf_atm_aal5_uu, tvb, length - 8, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(atm_tree, hf_atm_aal5_cpi, tvb, length - 7, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(atm_tree, hf_atm_aal5_len, tvb, length - 6, 2, ENC_BIG_ENDIAN);

            crc = tvb_get_ntohl(tvb, length - 4);
            calc_crc = crc32_mpeg2_tvb(tvb, length);
            ti = proto_tree_add_uint(atm_tree, hf_atm_aal5_crc, tvb, length - 4, 4, crc);
            proto_item_append_text(ti, (calc_crc == 0xC704DD7B) ? " (correct)" : " (incorrect)");
          }
          next_tvb = tvb_new_subset_length(tvb, 0, aal5_length);
        }
      }
    }
  }

  decoded = FALSE;
  /*
   * Don't try to dissect the payload of PDUs with a reassembly
   * error.
   */
  switch (atm_info->aal) {

  case AAL_SIGNALLING:
    if (!(atm_info->flags & ATM_REASSEMBLY_ERROR)) {
      call_dissector(sscop_handle, next_tvb, pinfo, tree);
      decoded = TRUE;
    }
    break;

  case AAL_5:
    if (!(atm_info->flags & ATM_REASSEMBLY_ERROR)) {
      if (dissector_try_uint_new(atm_type_aal5_table, atm_info->type, next_tvb, pinfo, tree, TRUE, atm_info))
      {
        decoded = TRUE;
      }
      else
      {
        if (tvb_reported_length(next_tvb) > 7) /* sizeof(octet) */
        {
          guint8 octet[8];
          tvb_memcpy(next_tvb, octet, 0, sizeof(octet));

          if (octet[0] == 0xaa
           && octet[1] == 0xaa
           && octet[2] == 0x03) /* LLC SNAP as per RFC2684 */
          {
            call_dissector(llc_handle, next_tvb, pinfo, tree);
            decoded = TRUE;
          }
          else if ((pntoh16(octet) & 0xff) == PPP_IP)
          {
            call_dissector(ppp_handle, next_tvb, pinfo, tree);
            decoded = TRUE;
          }
          else if (pntoh16(octet) == 0x00)
          {
            /*
             * Assume VC multiplexed bridged Ethernet.
             * Whether there's an FCS is an option negotiated
             * over the VC, so we call the "do heuristic checks
             * to see if there's an FCS" version of the Ethernet
             * dissector.
             *
             * See RFC 2684 section 6.2 "VC Multiplexing of Bridged
             * Protocols".
             */
            proto_tree_add_item(tree, hf_atm_padding, tvb, 0, 2, ENC_NA);
            next_tvb = tvb_new_subset_remaining(tvb, 2);
            call_dissector(eth_maybefcs_handle, next_tvb, pinfo, tree);
            decoded = TRUE;
          }
          else if (octet[2] == 0x03    && /* NLPID */
                  ((octet[3] == 0xcc   || /* IPv4  */
                    octet[3] == 0x8e)  || /* IPv6  */
                   (octet[3] == 0x00   && /* Eth   */
                    octet[4] == 0x80)))   /* Eth   */
          {
            /* assume network interworking with FR 2 byte header */
            call_dissector(fr_handle, next_tvb, pinfo, tree);
            decoded = TRUE;
          }
          else if (octet[4] == 0x03    && /* NLPID */
                  ((octet[5] == 0xcc   || /* IPv4  */
                    octet[5] == 0x8e)  || /* IPv6  */
                   (octet[5] == 0x00   && /* Eth   */
                    octet[6] == 0x80)))   /* Eth   */
          {
            /* assume network interworking with FR 4 byte header */
            call_dissector(fr_handle, next_tvb, pinfo, tree);
            decoded = TRUE;
          }
          else if (((octet[0] & 0xf0)== 0x40) ||
                   ((octet[0] & 0xf0) == 0x60))
          {
            call_dissector(ip_handle, next_tvb, pinfo, tree);
            decoded = TRUE;
          }
        }
      }
      break;
    }
    break;

  case AAL_2:
    proto_tree_add_uint(atm_tree, hf_atm_cid, tvb, 0, 0,
                        atm_info->aal2_cid);
    proto_item_append_text(atm_ti, " (vpi=%u vci=%u cid=%u)",
                           atm_info->vpi,
                           atm_info->vci,
                           atm_info->aal2_cid);

    if (!(atm_info->flags & ATM_REASSEMBLY_ERROR)) {
      if (atm_info->flags & ATM_AAL2_NOPHDR) {
        next_tvb = tvb;
      } else {
        /* Skip first 4 bytes of message
           - side
           - length
           - UUI
           Ignoring for now... */
        next_tvb = tvb_new_subset_remaining(tvb, 4);
      }

      if (dissector_try_uint(atm_type_aal2_table, atm_info->type, next_tvb, pinfo, tree))
      {
        decoded = TRUE;
      }
    }
    break;

  default:
    /* Dump it as raw data. */
    break;
  }

  if (!decoded) {
    /* Dump it as raw data. */
    call_data_dissector(next_tvb, pinfo, tree);
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
  register int    i, err_posn;

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


static void
dissect_atm_cell_payload(tvbuff_t *tvb, int offset, packet_info *pinfo,
                         proto_tree *tree, guint aal, gboolean fill_columns)
{
  proto_tree *aal_tree;
  proto_item *ti;
  guint8      octet;
  gint        length;
  guint16     aal3_4_hdr, crc10;
  tvbuff_t   *next_tvb;

  switch (aal) {

  case AAL_1:
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AAL1");
    col_clear(pinfo->cinfo, COL_INFO);
    ti = proto_tree_add_item(tree, proto_aal1, tvb, offset, -1, ENC_NA);
    aal_tree = proto_item_add_subtree(ti, ett_aal1);
    octet = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(aal_tree, hf_atm_aa1_csi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(aal_tree, hf_atm_aa1_seq_count, tvb, offset, 1, ENC_BIG_ENDIAN);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Sequence count = %u",
                 (octet >> 4) & 0x7);
    proto_tree_add_item(aal_tree, hf_atm_aa1_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(aal_tree, hf_atm_aa1_parity, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(aal_tree, hf_atm_aa1_payload, tvb, offset, 47, ENC_NA);
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
    proto_tree_add_item(aal_tree, hf_atm_aal3_4_seg_type, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(aal_tree, hf_atm_aal3_4_seq_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(aal_tree, hf_atm_aal3_4_multiplex_id, tvb, offset, 2, ENC_BIG_ENDIAN);

    length = tvb_reported_length_remaining(tvb, offset);
    crc10 = update_crc10_by_bytes_tvb(0, tvb, offset, length);
    offset += 2;

    proto_tree_add_item(aal_tree, hf_atm_aal3_4_information, tvb, offset, 44, ENC_NA);
    offset += 44;

    proto_tree_add_item(aal_tree, hf_atm_aal3_4_length_indicator, tvb, offset, 2, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(aal_tree, hf_atm_aal3_4_crc, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, " (%s)", (crc10 == 0) ? " (correct)" : " (incorrect)");
    break;

  case AAL_OAMCELL:
    if (fill_columns)
    {
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "OAM AAL");
      col_clear(pinfo->cinfo, COL_INFO);
    }
    ti = proto_tree_add_item(tree, proto_oamaal, tvb, offset, -1, ENC_NA);
    aal_tree = proto_item_add_subtree(ti, ett_oamaal);
    octet = tvb_get_guint8(tvb, offset);
    if (fill_columns)
    {
      col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
                   val_to_str(octet >> 4, oam_type_vals, "Unknown (%u)"));
    }

    proto_tree_add_item(aal_tree, hf_atm_aal_oamcell_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    switch (octet >> 4) {

    case OAM_TYPE_FM:
      proto_tree_add_item(aal_tree, hf_atm_aal_oamcell_type_fm, tvb, offset, 1, ENC_BIG_ENDIAN);
      break;

    case OAM_TYPE_PM:
      proto_tree_add_item(aal_tree, hf_atm_aal_oamcell_type_pm, tvb, offset, 1, ENC_BIG_ENDIAN);
      break;

    case OAM_TYPE_AD:
      proto_tree_add_item(aal_tree, hf_atm_aal_oamcell_type_ad, tvb, offset, 1, ENC_BIG_ENDIAN);
      break;

    default:
      proto_tree_add_item(aal_tree, hf_atm_aal_oamcell_type_ft, tvb, offset, 1, ENC_BIG_ENDIAN);
      break;
    }
    length = tvb_reported_length_remaining(tvb, offset);
    crc10 = update_crc10_by_bytes_tvb(0, tvb, offset, length);
    offset += 1;

    proto_tree_add_item(aal_tree, hf_atm_aal_oamcell_func_spec, tvb, offset, 45, ENC_NA);
    offset += 45;

    ti = proto_tree_add_item(aal_tree, hf_atm_aal_oamcell_crc, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_item_append_text(ti, " (%s)", (crc10 == 0) ? " (correct)" : " (incorrect)");
    break;

  default:
    next_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(next_tvb, pinfo, tree);
    break;
  }
}

/*
 * Check for OAM cells.
 * OAM F4 is VCI 3 or 4 and PT 0X0.
 * OAM F5 is PT 10X.
 */
gboolean
atm_is_oam_cell(const guint16 vci, const guint8 pt)
{
  return  (((vci == 3 || vci == 4) && ((pt & 0x5) == 0))
           || ((pt & 0x6) == 0x4));
}


static void
dissect_atm_cell(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 proto_tree *atm_tree, guint aal, gboolean nni,
                 gboolean crc_stripped)
{
  int         offset;
  proto_item *ti;
  guint8      octet, pt;
  int         err;
  guint16     vpi, vci;

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
    proto_tree_add_item(atm_tree, hf_atm_gfc, tvb, 0, 1, ENC_NA);
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
  proto_tree_add_item(atm_tree, hf_atm_payload_type, tvb, 3, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(atm_tree, hf_atm_cell_loss_priority, tvb, 3, 1, ENC_BIG_ENDIAN);

  if (!crc_stripped) {
    /*
     * FF: parse the Header Error Check (HEC).
     */
    ti = proto_tree_add_item(atm_tree, hf_atm_header_error_check, tvb, 4, 1, ENC_BIG_ENDIAN);
    err = get_header_err((const guint8*)tvb_memdup(wmem_packet_scope(), tvb, 0, 5));
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

  /*
   * Check for OAM cells.
   * XXX - do this for all AAL values, overriding whatever information
   * Wiretap got from the file?
   */
  if (aal == AAL_USER || aal == AAL_UNKNOWN) {
    if (atm_is_oam_cell(vci,pt)) {
      aal = AAL_OAMCELL;
    }
  }

  dissect_atm_cell_payload(tvb, offset, pinfo, tree, aal, TRUE);
}

static int
dissect_atm_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gboolean truncated, struct atm_phdr *atm_info, gboolean pseudowire_mode)
{
  proto_tree *atm_tree        = NULL;
  proto_item *atm_ti          = NULL;

  if ( atm_info->aal == AAL_5 && atm_info->type == TRAF_LANE &&
       dissect_lanesscop ) {
    atm_info->aal = AAL_SIGNALLING;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATM");

  if (!pseudowire_mode) {
    switch (atm_info->channel) {

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

  if (atm_info->aal == AAL_5) {
    col_add_fstr(pinfo->cinfo, COL_INFO, "AAL5 %s",
                 val_to_str(atm_info->type, aal5_hltype_vals,
                            "Unknown traffic type (%u)"));
  } else {
    col_add_str(pinfo->cinfo, COL_INFO,
                val_to_str(atm_info->aal, aal_vals,
                           "Unknown AAL (%u)"));
  }

  if (tree) {
    atm_ti = proto_tree_add_item(tree, proto_atm, tvb, 0, -1, ENC_NA);
    atm_tree = proto_item_add_subtree(atm_ti, ett_atm);

    if (!pseudowire_mode) {
      proto_tree_add_uint(atm_tree, hf_atm_channel, tvb, 0, 0, atm_info->channel);
      if (atm_info->flags & ATM_REASSEMBLY_ERROR)
        expert_add_info(pinfo, atm_ti, &ei_atm_reassembly_failed);
    }

    proto_tree_add_uint_format_value(atm_tree, hf_atm_aal, tvb, 0, 0,
                                     atm_info->aal,
                                     "%s",
                                     val_to_str(atm_info->aal, aal_vals,
                                                "Unknown AAL (%u)"));
  }
  if (atm_info->flags & ATM_RAW_CELL) {
    /* This is a single cell, with the cell header at the beginning. */
    if (atm_info->flags & ATM_NO_HEC) {
      proto_item_set_len(atm_ti, 4);
    } else {
      proto_item_set_len(atm_ti, 5);
    }
    dissect_atm_cell(tvb, pinfo, tree, atm_tree,
                     atm_info->aal, FALSE,
                     atm_info->flags & ATM_NO_HEC);
  } else {
    /* This is a reassembled PDU. */

    /*
     * ATM dissector is used as "sub-dissector" for ATM pseudowires.
     * In such cases, the dissector data parameter is used to pass info from/to
     * PW dissector to ATM dissector. For decoding normal ATM traffic
     * data parameter should be NULL.
     */
    dissect_reassembled_pdu(tvb, pinfo, tree, atm_tree, atm_ti, truncated,
                            atm_info, pseudowire_mode);
  }

  return tvb_reported_length(tvb);
}

static int
dissect_atm_truncated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct atm_phdr *atm_info = (struct atm_phdr *)data;

  DISSECTOR_ASSERT(atm_info != NULL);

  return dissect_atm_common(tvb, pinfo, tree, TRUE, atm_info, FALSE);
}

static int
dissect_atm_pw_truncated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct atm_phdr *atm_info = (struct atm_phdr *)data;

  DISSECTOR_ASSERT(atm_info != NULL);

  return dissect_atm_common(tvb, pinfo, tree, TRUE, atm_info, TRUE);
}

static int
dissect_atm_untruncated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct atm_phdr *atm_info = (struct atm_phdr *)data;

  DISSECTOR_ASSERT(atm_info != NULL);

  return dissect_atm_common(tvb, pinfo, tree, FALSE, atm_info, FALSE);
}

static int
dissect_atm_pw_untruncated(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  struct atm_phdr *atm_info = (struct atm_phdr *)data;

  DISSECTOR_ASSERT(atm_info != NULL);

  return dissect_atm_common(tvb, pinfo, tree, FALSE, atm_info, TRUE);
}

static int
dissect_atm_oam_cell(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_tree *atm_tree;
  proto_item *atm_ti;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATM");

  atm_ti   = proto_tree_add_item(tree, proto_atm, tvb, 0, 0, ENC_NA);
  atm_tree = proto_item_add_subtree(atm_ti, ett_atm);

  dissect_atm_cell(tvb, pinfo, tree, atm_tree, AAL_OAMCELL, FALSE, FALSE);
  return tvb_reported_length(tvb);
}

static int
dissect_atm_pw_oam_cell(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  const pwatm_private_data_t *pwpd = (const pwatm_private_data_t *)data;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATM");

  dissect_atm_cell_payload(tvb, 0, pinfo, tree, AAL_OAMCELL,
                           pwpd->enable_fill_columns_by_atm_dissector);

  return tvb_reported_length(tvb);
}

static void atm_prompt(packet_info *pinfo _U_, gchar* result)
{
  g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Decode AAL2 traffic as");
}

static gpointer atm_value(packet_info *pinfo)
{
  return GUINT_TO_POINTER((guint)pinfo->pseudo_header->atm.type);
}

void
proto_register_atm(void)
{
  static hf_register_info hf[] = {
    { &hf_atm_aal,
      { "AAL",          "atm.aal", FT_UINT8, BASE_DEC, VALS(aal_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_gfc,
      { "GFC",          "atm.GFC", FT_UINT8, BASE_DEC, NULL, 0xF0,
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

    { &hf_atm_reserved,
      { "Reserved", "atm.reserved", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_atm_le_client_client,
      { "LE Client", "atm.le_client.client", FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_lan_destination_tag,
      { "Tag", "atm.lan_destination.tag", FT_UINT16, BASE_HEX, VALS(le_control_landest_tag_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_lan_destination_mac,
      { "MAC address", "atm.lan_destination.mac", FT_ETHER, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_tlv_type,
      { "TLV Type", "atm.le_control.tlv_type", FT_UINT32, BASE_HEX, VALS(le_tlv_type_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_tlv_length,
      { "TLV Length", "atm.le_control.tlv_length", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_lan_destination_route_desc,
      { "Route descriptor", "atm.lan_destination.route_desc", FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_lan_destination_lan_id,
      { "LAN ID", "atm.lan_destination.lan_id", FT_UINT16, BASE_DEC, NULL, 0xFFF0,
        NULL, HFILL }},
    { &hf_atm_lan_destination_bridge_num,
      { "Bridge number", "atm.lan_destination.bridge_num", FT_UINT16, BASE_DEC, NULL, 0x000F,
        NULL, HFILL }},
    { &hf_atm_source_atm,
      { "Source ATM address", "atm.source_atm", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_target_atm,
      { "Target ATM address", "atm.target_atm", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_configure_join_frame_lan_type,
      { "LAN type", "atm.le_configure_join_frame.lan_type", FT_UINT8, BASE_HEX, VALS(le_control_lan_type_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_le_configure_join_frame_max_frame_size,
      { "Maximum frame size", "atm.le_configure_join_frame.max_frame_size", FT_UINT8, BASE_HEX, VALS(le_control_frame_size_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_le_configure_join_frame_num_tlvs,
      { "Number of TLVs", "atm.le_configure_join_frame.num_tlvs", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_configure_join_frame_elan_name_size,
      { "ELAN name size", "atm.le_configure_join_frame.elan_name_size", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_registration_frame_num_tlvs,
      { "Number of TLVs", "atm.le_registration_frame.num_tlvs", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_arp_frame_num_tlvs,
      { "Number of TLVs", "atm.le_arp_frame.num_tlvs", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_verify_frame_num_tlvs,
      { "Number of TLVs", "atm.le_verify_frame.num_tlvs", FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_configure_join_frame_elan_name,
      { "ELAN name", "atm.le_configure_join_frame.elan_name", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_marker,
      { "Marker", "atm.le_control.marker", FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_protocol,
      { "Protocol", "atm.le_control.protocol", FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_version,
      { "Version", "atm.le_control.version", FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_opcode,
      { "Opcode", "atm.le_control.opcode", FT_UINT16, BASE_HEX, VALS(le_control_opcode_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_status,
      { "Status", "atm.le_control.status", FT_UINT16, BASE_HEX, VALS(le_control_status_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_transaction_id,
      { "Transaction ID", "atm.le_control.transaction_id", FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_requester_lecid,
      { "Requester LECID", "atm.le_control.requester_lecid", FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_flags,
      { "Flags", "atm.le_control.flag", FT_UINT16, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_le_control_flag_v2_capable,
      { "V2 capable", "atm.le_control.flag.v2_capable", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0002,
        NULL, HFILL }},
    { &hf_atm_le_control_flag_selective_multicast,
      { "Selective multicast", "atm.le_control.flag.selective_multicast", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0004,
        NULL, HFILL }},
    { &hf_atm_le_control_flag_v2_required,
      { "V2 required", "atm.le_control.flag.v2_required", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0008,
        NULL, HFILL }},
    { &hf_atm_le_control_flag_proxy,
      { "Proxy", "atm.le_control.flag.flag_proxy", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0080,
        NULL, HFILL }},
    { &hf_atm_le_control_flag_exclude_explorer_frames,
      { "Exclude explorer frames", "atm.le_control.flag.exclude_explorer_frames", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0200,
        NULL, HFILL }},
    { &hf_atm_le_control_flag_address,
      { "Address", "atm.le_control.flag.address", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0001,
        NULL, HFILL }},
    { &hf_atm_le_control_topology_change,
      { "Topology change", "atm.le_control.flag.topology_change", FT_BOOLEAN, 16, TFS(&tfs_remote_local), 0x0100,
        NULL, HFILL }},
    { &hf_atm_traffic_type,
      { "Traffic type", "atm.traffic_type", FT_UINT8, BASE_DEC, VALS(aal5_hltype_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_traffic_vcmx,
      { "VC multiplexed traffic type", "atm.traffic.vcmx", FT_UINT8, BASE_DEC, VALS(vcmx_type_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_traffic_lane,
      { "LANE traffic type", "atm.traffic.lane", FT_UINT8, BASE_DEC, VALS(lane_type_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_traffic_ipsilon,
      { "Ipsilon traffic type", "atm.traffic.ipsilon", FT_UINT8, BASE_DEC, VALS(ipsilon_type_vals), 0x0,
        NULL, HFILL }},
    { &hf_atm_cells,
      { "Cells", "atm.cells", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_aal5_uu,
      { "AAL5 UU", "atm.hf_atm.aal5t_uu", FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_aal5_cpi,
      { "AAL5 CPI", "atm.hf_atm.aal5t_cpi", FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_aal5_len,
      { "AAL5 len", "atm.aal5t_len", FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_aal5_crc,
      { "AAL5 CRC", "atm.aal5t_crc", FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_payload_type,
      { "Payload Type", "atm.payload_type", FT_UINT8, BASE_DEC, NULL, 0x0E,
        NULL, HFILL }},
    { &hf_atm_cell_loss_priority,
      { "Cell Loss Priority", "atm.cell_loss_priority", FT_BOOLEAN, 8, TFS(&tfs_low_high_priority), 0x01,
        NULL, HFILL }},
    { &hf_atm_header_error_check,
      { "Header Error Check", "atm.header_error_check", FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_atm_channel,
      { "Channel", "atm.channel", FT_UINT16, BASE_DEC, VALS(atm_channel_vals), 0,
        NULL, HFILL }},
    { &hf_atm_aa1_csi,
      { "CSI", "atm.aa1.csi", FT_UINT8, BASE_DEC, NULL, 0x80,
        NULL, HFILL }},
    { &hf_atm_aa1_seq_count,
      { "Sequence Count", "atm.aa1.seq_count", FT_UINT8, BASE_DEC, NULL, 0x70,
        NULL, HFILL }},
    { &hf_atm_aa1_crc,
      { "CRC", "atm.aa1.crc", FT_UINT8, BASE_DEC, NULL, 0x08,
        NULL, HFILL }},
    { &hf_atm_aa1_parity,
      { "Parity", "atm.aa1.parity", FT_UINT8, BASE_DEC, NULL, 0x07,
        NULL, HFILL }},
    { &hf_atm_aa1_payload,
      { "Payload", "atm.aa1.payload", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_aal3_4_seg_type,
      { "Segment Type", "atm.aal3_4.seg_type", FT_UINT16, BASE_DEC, VALS(st_vals), 0xC000,
        NULL, HFILL }},
    { &hf_atm_aal3_4_seq_num,
      { "Sequence Number", "atm.aal3_4.seq_num", FT_UINT16, BASE_DEC, NULL, 0x3C00,
        NULL, HFILL }},
    { &hf_atm_aal3_4_multiplex_id,
      { "Multiplex ID", "atm.aal3_4.multiplex_id", FT_UINT16, BASE_DEC, NULL, 0x03FF,
        NULL, HFILL }},
    { &hf_atm_aal3_4_information,
      { "Information", "atm.aal3_4.information", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_aal3_4_length_indicator,
      { "Length Indicator", "atm.aal3_4.length_indicator", FT_UINT16, BASE_DEC, VALS(st_vals), 0xFC00,
        NULL, HFILL }},
    { &hf_atm_aal3_4_crc,
      { "CRC", "atm.aal3_4.crc", FT_UINT16, BASE_DEC, NULL, 0x03FF,
        NULL, HFILL }},
    { &hf_atm_aal_oamcell_type,
      { "OAM Type", "atm.aal_oamcell.type", FT_UINT8, BASE_DEC, VALS(oam_type_vals), 0xF0,
        NULL, HFILL }},
    { &hf_atm_aal_oamcell_type_fm,
      { "Function Type", "atm.aal_oamcell.type.fm", FT_UINT8, BASE_DEC, VALS(ft_fm_vals), 0x0F,
        NULL, HFILL }},
    { &hf_atm_aal_oamcell_type_pm,
      { "Function Type", "atm.aal_oamcell.type.pm", FT_UINT8, BASE_DEC, VALS(ft_pm_vals), 0x0F,
        NULL, HFILL }},
    { &hf_atm_aal_oamcell_type_ad,
      { "Function Type", "atm.aal_oamcell.type.ad", FT_UINT8, BASE_DEC, VALS(ft_ad_vals), 0x0F,
        NULL, HFILL }},
    { &hf_atm_aal_oamcell_type_ft,
      { "Function Type", "atm.aal_oamcell.type.ft", FT_UINT8, BASE_DEC, NULL, 0x0F,
        NULL, HFILL }},
    { &hf_atm_aal_oamcell_func_spec,
      { "Function-specific information", "atm.aal_oamcell.func_spec", FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_atm_aal_oamcell_crc,
      { "CRC-10", "atm.aal_oamcell.crc", FT_UINT16, BASE_HEX, NULL, 0x3FF,
        NULL, HFILL }},
    { &hf_atm_padding,
      { "Padding", "atm.padding", FT_BYTES, BASE_NONE, NULL, 0x0,
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

  static ei_register_info ei[] = {
    { &ei_atm_reassembly_failed, { "atm.reassembly_failed", PI_REASSEMBLE, PI_ERROR, "PDU reassembly failed", EXPFILL }},
  };

  expert_module_t* expert_atm;
  module_t *atm_module;

  /* Decode As handling */
  static build_valid_func atm_da_build_value[1] = {atm_value};
  static decode_as_value_t atm_da_values = {atm_prompt, 1, atm_da_build_value};
  static decode_as_t atm_da = {"atm", "Network", "atm.aal2.type", 1, 0, &atm_da_values, NULL, NULL,
                                decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

  proto_atm    = proto_register_protocol("Asynchronous Transfer Mode", "ATM", "atm");
  proto_aal1   = proto_register_protocol("ATM AAL1", "AAL1", "aal1");
  proto_aal3_4 = proto_register_protocol("ATM AAL3/4", "AAL3/4", "aal3_4");
  proto_oamaal = proto_register_protocol("ATM OAM AAL", "OAM AAL", "oamaal");
  proto_register_field_array(proto_atm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_atm = expert_register_protocol(proto_atm);
  expert_register_field_array(expert_atm, ei, array_length(ei));

  proto_ilmi = proto_register_protocol("ILMI", "ILMI", "ilmi");

  proto_atm_lane = proto_register_protocol("ATM LAN Emulation", "ATM LANE", "lane");

  atm_type_aal2_table = register_dissector_table("atm.aal2.type", "ATM AAL_2 type subdissector", proto_atm, FT_UINT32, BASE_DEC);
  atm_type_aal5_table = register_dissector_table("atm.aal5.type", "ATM AAL_5 type subdissector", proto_atm, FT_UINT32, BASE_DEC);

  register_capture_dissector_table("atm.aal5.type", "ATM AAL_5");
  register_capture_dissector_table("atm_lane", "ATM LAN Emulation");

  atm_handle = register_dissector("atm_truncated", dissect_atm_truncated, proto_atm);
  register_dissector("atm_pw_truncated", dissect_atm_pw_truncated, proto_atm);
  atm_untruncated_handle = register_dissector("atm_untruncated", dissect_atm_untruncated, proto_atm);
  register_dissector("atm_pw_untruncated", dissect_atm_pw_untruncated, proto_atm);
  register_dissector("atm_oam_cell", dissect_atm_oam_cell, proto_oamaal);
  register_dissector("atm_pw_oam_cell", dissect_atm_pw_oam_cell, proto_oamaal);

  atm_module = prefs_register_protocol ( proto_atm, NULL );
  prefs_register_bool_preference(atm_module, "dissect_lane_as_sscop", "Dissect LANE as SSCOP",
                                 "Autodection between LANE and SSCOP is hard. As default LANE is preferred",
                                 &dissect_lanesscop);
  prefs_register_obsolete_preference(atm_module, "unknown_aal2_type");

  register_decode_as(&atm_da);
}

void
proto_reg_handoff_atm(void)
{
  /*
   * Get handles for the Ethernet, Token Ring, Frame Relay, LLC,
   * SSCOP, LANE, and ILMI dissectors.
   */
  eth_withoutfcs_handle = find_dissector_add_dependency("eth_withoutfcs", proto_atm_lane);
  tr_handle             = find_dissector_add_dependency("tr", proto_atm_lane);
  fr_handle             = find_dissector_add_dependency("fr", proto_atm);
  llc_handle            = find_dissector_add_dependency("llc", proto_atm);
  sscop_handle          = find_dissector_add_dependency("sscop", proto_atm);
  ppp_handle            = find_dissector_add_dependency("ppp", proto_atm);
  eth_maybefcs_handle   = find_dissector_add_dependency("eth_maybefcs", proto_atm);
  ip_handle             = find_dissector_add_dependency("ip", proto_atm);

  dissector_add_uint("wtap_encap", WTAP_ENCAP_ATM_PDUS, atm_handle);
  dissector_add_uint("atm.aal5.type", TRAF_LANE, create_dissector_handle(dissect_lane, proto_atm_lane));
  dissector_add_uint("atm.aal5.type", TRAF_ILMI, create_dissector_handle(dissect_ilmi, proto_ilmi));

  dissector_add_uint("wtap_encap", WTAP_ENCAP_ATM_PDUS_UNTRUNCATED,
                atm_untruncated_handle);
  register_capture_dissector("wtap_encap", WTAP_ENCAP_ATM_PDUS, capture_atm, proto_atm);
  register_capture_dissector("atm.aal5.type", TRAF_LANE, capture_lane, proto_atm_lane);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
