/* packet-atm.c
 * Routines for ATM packet disassembly
 *
 * $Id: packet-atm.c,v 1.45 2002/05/24 09:31:06 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include "oui.h"
#include <epan/resolv.h>

#include "packet-snmp.h"

static int proto_atm = -1;
static int hf_atm_vpi = -1;
static int hf_atm_vci = -1;
static int proto_atm_lane = -1;
static int proto_ilmi = -1;

static gint ett_atm = -1;
static gint ett_atm_lane = -1;
static gint ett_atm_lane_lc_lan_dest = -1;
static gint ett_atm_lane_lc_lan_dest_rd = -1;
static gint ett_atm_lane_lc_flags = -1;
static gint ett_atm_lane_lc_tlv = -1;
static gint ett_ilmi = -1;

static dissector_handle_t eth_handle;
static dissector_handle_t tr_handle;
static dissector_handle_t llc_handle;
static dissector_handle_t sscop_handle;
static dissector_handle_t lane_handle;
static dissector_handle_t ilmi_handle;
static dissector_handle_t data_handle;

/*
 * See
 *
 *	http://www.atmforum.org/atmforum/specs/approved.html
 *
 * for a number of ATM Forum specifications, e.g. the LAN Emulation
 * over ATM 1.0 spec, whence I got most of this.
 */

/* LE Control opcodes */
#define LE_CONFIGURE_REQUEST	0x0001
#define LE_CONFIGURE_RESPONSE	0x0101
#define LE_JOIN_REQUEST		0x0002
#define LE_JOIN_RESPONSE	0x0102
#define READY_QUERY		0x0003
#define READY_IND		0x0103
#define LE_REGISTER_REQUEST	0x0004
#define LE_REGISTER_RESPONSE	0x0104
#define LE_UNREGISTER_REQUEST	0x0005
#define LE_UNREGISTER_RESPONSE	0x0105
#define LE_ARP_REQUEST		0x0006
#define LE_ARP_RESPONSE		0x0106
#define LE_FLUSH_REQUEST	0x0007
#define LE_FLUSH_RESPONSE	0x0107
#define LE_NARP_REQUEST		0x0008
#define LE_TOPOLOGY_REQUEST	0x0009
#define LE_VERIFY_REQUEST	0x000A
#define LE_VERIFY_RESPONSE	0x010A

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
	{ 20, "No configuraton" },
	{ 21, "LE_CONFIGURE error" },
	{ 22, "Insufficient information" },
	{ 24, "TLV not found" },
	{ 0,  NULL }
};

/* LE Control LAN destination tags */
#define	TAG_NOT_PRESENT		0x0000
#define	TAG_MAC_ADDRESS		0x0001
#define	TAG_ROUTE_DESCRIPTOR	0x0002

static const value_string le_control_landest_tag_vals[] = {
	{ TAG_NOT_PRESENT,       "Not present" },
	{ TAG_MAC_ADDRESS,       "MAC address" },
	{ TAG_ROUTE_DESCRIPTOR,  "Route descriptor" },
	{ 0,                     NULL }
};

/* LE Control LAN types */
#define	LANT_UNSPEC	0x00
#define	LANT_802_3	0x01
#define	LANT_802_5	0x02

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
  proto_item *trd;
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
			ether_to_str(tvb_get_ptr(tvb, offset, 6)));
    break;

  case TAG_ROUTE_DESCRIPTOR:
    offset += 4;
    route_descriptor = tvb_get_ntohs(tvb, offset);
    trd = proto_tree_add_text(dest_tree, tvb, offset, 2, "Route descriptor: 0x%02X",
    			route_descriptor);
    rd_tree = proto_item_add_subtree(td, ett_atm_lane_lc_lan_dest_rd);
    proto_tree_add_text(rd_tree, tvb, offset, 2,
	    decode_numeric_bitfield(route_descriptor, 0xFFF0, 2*8,
			"LAN ID = %u"));
    proto_tree_add_text(rd_tree, tvb, offset, 2,
	    decode_numeric_bitfield(route_descriptor, 0x000F, 2*8,
			"Bridge number = %u"));
    break;
  }
}

/*
 * TLV values in LE Control frames.
 */
#define	TLV_TYPE(oui, ident)		(((oui) << 8) | (ident))

#define	LE_CONTROL_TIMEOUT		TLV_TYPE(OUI_ATM_FORUM, 0x01)
#define	LE_MAX_UNK_FRAME_COUNT		TLV_TYPE(OUI_ATM_FORUM, 0x02)
#define	LE_MAX_UNK_FRAME_TIME		TLV_TYPE(OUI_ATM_FORUM, 0x03)
#define	LE_VCC_TIMEOUT_PERIOD		TLV_TYPE(OUI_ATM_FORUM, 0x04)
#define	LE_MAX_RETRY_COUNT		TLV_TYPE(OUI_ATM_FORUM, 0x05)
#define	LE_AGING_TIME			TLV_TYPE(OUI_ATM_FORUM, 0x06)
#define	LE_FORWARD_DELAY_TIME		TLV_TYPE(OUI_ATM_FORUM, 0x07)
#define	LE_EXPECTED_ARP_RESPONSE_TIME	TLV_TYPE(OUI_ATM_FORUM, 0x08)
#define	LE_FLUSH_TIMEOUT		TLV_TYPE(OUI_ATM_FORUM, 0x09)
#define	LE_PATH_SWITCHING_DELAY		TLV_TYPE(OUI_ATM_FORUM, 0x0A)
#define	LE_LOCAL_SEGMENT_ID		TLV_TYPE(OUI_ATM_FORUM, 0x0B)
#define	LE_MCAST_SEND_VCC_TYPE		TLV_TYPE(OUI_ATM_FORUM, 0x0C)
#define	LE_MCAST_SEND_VCC_AVGRATE	TLV_TYPE(OUI_ATM_FORUM, 0x0D)
#define	LE_MCAST_SEND_VCC_PEAKRATE	TLV_TYPE(OUI_ATM_FORUM, 0x0E)
#define	LE_CONN_COMPLETION_TIMER	TLV_TYPE(OUI_ATM_FORUM, 0x0F)
#define	LE_CONFIG_FRAG_INFO		TLV_TYPE(OUI_ATM_FORUM, 0x10)
#define	LE_LAYER_3_ADDRESS		TLV_TYPE(OUI_ATM_FORUM, 0x11)
#define	LE_ELAN_ID			TLV_TYPE(OUI_ATM_FORUM, 0x12)
#define	LE_SERVICE_CATEGORY		TLV_TYPE(OUI_ATM_FORUM, 0x13)
#define	LE_LLC_MUXED_ATM_ADDRESS	TLV_TYPE(OUI_ATM_FORUM, 0x2B)
#define	LE_X5_ADJUSTMENT		TLV_TYPE(OUI_ATM_FORUM, 0x2C)
#define	LE_PREFERRED_LES		TLV_TYPE(OUI_ATM_FORUM, 0x2D)

static const value_string le_tlv_type_vals[] = {
	{ LE_CONTROL_TIMEOUT,		"Control Time-out" },
	{ LE_MAX_UNK_FRAME_COUNT,	"Maximum Unknown Frame Count" },
	{ LE_MAX_UNK_FRAME_TIME,	"Maximum Unknown Frame Time" },
	{ LE_VCC_TIMEOUT_PERIOD,	"VCC Time-out" },
	{ LE_MAX_RETRY_COUNT,		"Maximum Retry Count" },
	{ LE_AGING_TIME,		"Aging Time" },
	{ LE_FORWARD_DELAY_TIME,	"Forwarding Delay Time" },
	{ LE_EXPECTED_ARP_RESPONSE_TIME, "Expected LE_ARP Response Time" },
	{ LE_FLUSH_TIMEOUT,		"Flush Time-out" },
	{ LE_PATH_SWITCHING_DELAY,	"Path Switching Delay" },
	{ LE_LOCAL_SEGMENT_ID,		"Local Segment ID" },
	{ LE_MCAST_SEND_VCC_TYPE,	"Mcast Send VCC Type" },
	{ LE_MCAST_SEND_VCC_AVGRATE,	"Mcast Send VCC AvgRate" },
	{ LE_MCAST_SEND_VCC_PEAKRATE,	"Mcast Send VCC PeakRate" },
	{ LE_CONN_COMPLETION_TIMER,	"Connection Completion Timer" },
	{ LE_CONFIG_FRAG_INFO,		"Config Frag Info" },
	{ LE_LAYER_3_ADDRESS,		"Layer 3 Address" },
	{ LE_ELAN_ID,			"ELAN ID" },
	{ LE_SERVICE_CATEGORY,		"Service Category" },
	{ LE_LLC_MUXED_ATM_ADDRESS,	"LLC-muxed ATM Address" },
	{ LE_X5_ADJUSTMENT,		"X5 Adjustment" },
	{ LE_PREFERRED_LES,		"Preferred LES" },
	{ 0,				NULL },
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
dissect_le_topology_change_frame(tvbuff_t *tvb, int offset, proto_tree *tree)
{
  /* Reserved */
  offset += 92;
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

  if (check_col(pinfo->cinfo, COL_INFO))
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
  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_append_fstr(pinfo->cinfo, COL_INFO, ": %s",
	val_to_str(opcode, le_control_opcode_vals,
				"Unknown opcode (0x%04X)"));
  }
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
      dissect_le_topology_change_frame(tvb, offset, lane_tree);
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
dissect_lane(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  tvbuff_t	*next_tvb;
  tvbuff_t	*next_tvb_le_client;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATM LANE");

  /* Is it LE Control, 802.3, 802.5, or "none of the above"? */
  switch (pinfo->pseudo_header->atm.subtype) {

  case TRAF_ST_LANE_LE_CTRL:
    dissect_le_control(tvb, pinfo, tree);
    break;

  case TRAF_ST_LANE_802_3:
  case TRAF_ST_LANE_802_3_MC:
    if (check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "LE Client - Ethernet/802.3");
    dissect_le_client(tvb, tree);

    /* Dissect as Ethernet */
    next_tvb_le_client	= tvb_new_subset(tvb, 2, -1, -1);
    call_dissector(eth_handle, next_tvb_le_client, pinfo, tree);
    break;

  case TRAF_ST_LANE_802_5:
  case TRAF_ST_LANE_802_5_MC:
    if (check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "LE Client - 802.5");
    dissect_le_client(tvb, tree);

    /* Dissect as Token-Ring */
    next_tvb_le_client	= tvb_new_subset(tvb, 2, -1, -1);
    call_dissector(tr_handle, next_tvb_le_client, pinfo, tree);
    break;

  default:
    /* Dump it as raw data. */
    if (check_col(pinfo->cinfo, COL_INFO))
      col_set_str(pinfo->cinfo, COL_INFO, "Unknown LANE traffic type");
    next_tvb		= tvb_new_subset(tvb, 0, -1, -1);
    call_dissector(data_handle,next_tvb, pinfo, tree);
    break;
  }
}

static void
dissect_ilmi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  dissect_snmp_pdu(tvb, 0, pinfo, tree, "ILMI", proto_ilmi, ett_ilmi);
}

/* AAL types */
static const value_string aal_vals[] = {
	{ AAL_UNKNOWN,    "Unknown AAL" },
	{ AAL_1,          "AAL1" },
	{ AAL_2,          "AAL2" },
	{ AAL_3_4,        "AAL3/4" },
	{ AAL_5,          "AAL5" },
	{ AAL_USER,       "User AAL" },
	{ AAL_SIGNALLING, "Signalling AAL" },
	{ AAL_OAMCELL,    "OAM cell" },
	{ 0,              NULL }
};

/* AAL5 higher-level traffic types */
static const value_string aal5_hltype_vals[] = {
	{ TRAF_UNKNOWN, "Unknown traffic type" },
	{ TRAF_LLCMX,   "LLC multiplexed" },
	{ TRAF_VCMX,    "VC multiplexed" },
	{ TRAF_LANE,    "LANE" },
	{ TRAF_ILMI,    "ILMI" },
	{ TRAF_FR,      "Frame Relay" },
	{ TRAF_SPANS,   "FORE SPANS" },
	{ TRAF_IPSILON, "Ipsilon" },
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
	{ TRAF_ST_UNKNOWN,       "Unknown LANE traffic type" },
	{ TRAF_ST_LANE_LE_CTRL,  "LE Control" },
	{ TRAF_ST_LANE_802_3,    "802.3" },
	{ TRAF_ST_LANE_802_5,    "802.5" },
	{ TRAF_ST_LANE_802_3_MC, "802.3 multicast" },
	{ TRAF_ST_LANE_802_5_MC, "802.5 multicast" },
        { 0,                     NULL }
};

/* Traffic subtypes for Ipsilon traffic */
static const value_string ipsilon_type_vals[] = {
	{ TRAF_ST_UNKNOWN,     "Unknown Ipsilon traffic type" },
	{ TRAF_ST_IPSILON_FT0, "Flow type 0" },
	{ TRAF_ST_IPSILON_FT1, "Flow type 1" },
	{ TRAF_ST_IPSILON_FT2, "Flow type 2" },
	{ 0,                NULL }
};

static void
dissect_atm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree   *atm_tree;
  proto_item   *ti;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ATM");

  switch (pinfo->pseudo_header->atm.channel) {

  case 0:
    /* Traffic from DCE to DTE. */
    if (check_col(pinfo->cinfo, COL_RES_DL_DST))
      col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DTE");
    if (check_col(pinfo->cinfo, COL_RES_DL_SRC))
      col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DCE");
    break;

  case 1:
    /* Traffic from DTE to DCE. */
    if (check_col(pinfo->cinfo, COL_RES_DL_DST))
      col_set_str(pinfo->cinfo, COL_RES_DL_DST, "DCE");
    if (check_col(pinfo->cinfo, COL_RES_DL_SRC))
      col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "DTE");
    break;
  }

  if (check_col(pinfo->cinfo, COL_INFO)) {
    if (pinfo->pseudo_header->atm.aal == AAL_5) {
      col_add_fstr(pinfo->cinfo, COL_INFO, "AAL5 %s",
		val_to_str(pinfo->pseudo_header->atm.type, aal5_hltype_vals,
				"Unknown traffic type (%u)"));
    } else {
      col_add_str(pinfo->cinfo, COL_INFO,
		val_to_str(pinfo->pseudo_header->atm.aal, aal_vals,
			"Unknown AAL (%u)"));
    }
  }

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_atm, tvb, 0, 0, "ATM");
    atm_tree = proto_item_add_subtree(ti, ett_atm);

    proto_tree_add_text(atm_tree, tvb, 0, 0, "AAL: %s",
	val_to_str(pinfo->pseudo_header->atm.aal, aal_vals,
	"Unknown AAL (%u)"));
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
    proto_tree_add_uint(atm_tree, hf_atm_vpi, tvb, 0, 0,
    		pinfo->pseudo_header->atm.vpi);
    proto_tree_add_uint(atm_tree, hf_atm_vci, tvb, 0, 0,
		pinfo->pseudo_header->atm.vci);
    switch (pinfo->pseudo_header->atm.channel) {

    case 0:
      /* Traffic from DCE to DTE. */
      proto_tree_add_text(atm_tree, tvb, 0, 0, "Channel: DCE->DTE");
      break;

    case 1:
      /* Traffic from DTE to DCE. */
      proto_tree_add_text(atm_tree, tvb, 0, 0, "Channel: DTE->DCE");
      break;

    default:
      /* Sniffers shouldn't provide anything other than 0 or 1. */
      proto_tree_add_text(atm_tree, tvb, 0, 0, "Channel: %u",
 		pinfo->pseudo_header->atm.channel);
      break;
    }
    if (pinfo->pseudo_header->atm.cells != 0) {
      /*
       * If the cell count is 0, assume it means we don't know how
       * many cells it was.
       *
       * XXX - also, if this is AAL5 traffic, assume it means we don't
       * know what was in the AAL5 trailer.  We may, however, find
       * some capture program that can give us the AAL5 trailer
       * information but not the cell count, in which case we need
       * some other way of indicating whether we have the AAL5 trailer
       * information.
       */
      proto_tree_add_text(atm_tree, tvb, 0, 0, "Cells: %u",
		pinfo->pseudo_header->atm.cells);
      if (pinfo->pseudo_header->atm.aal == AAL_5) {
        proto_tree_add_text(atm_tree, tvb, 0, 0, "AAL5 U2U: %u",
		pinfo->pseudo_header->atm.aal5t_u2u);
        proto_tree_add_text(atm_tree, tvb, 0, 0, "AAL5 len: %u",
		pinfo->pseudo_header->atm.aal5t_len);
        proto_tree_add_text(atm_tree, tvb, 0, 0, "AAL5 checksum: 0x%08X",
		pinfo->pseudo_header->atm.aal5t_chksum);
      }
    }
  }

  switch (pinfo->pseudo_header->atm.aal) {

  case AAL_SIGNALLING:
    call_dissector(sscop_handle, tvb, pinfo, tree);
    break;

  case AAL_5:
    switch (pinfo->pseudo_header->atm.type) {

    case TRAF_LLCMX:
      /* Dissect as WTAP_ENCAP_ATM_RFC1483 */
      /* The ATM iptrace capture that we have shows LLC at this point,
       * so that's what I'm calling */
      call_dissector(llc_handle, tvb, pinfo, tree);
      break;

    case TRAF_LANE:
      call_dissector(lane_handle, tvb, pinfo, tree);
      break;

    case TRAF_ILMI:
      call_dissector(ilmi_handle, tvb, pinfo, tree);
      break;

    default:
      if (tree) {
        /* Dump it as raw data. */
        call_dissector(data_handle,tvb, pinfo, tree);
        break;
      }
    }
    break;

  default:
    if (tree) {
      /* Dump it as raw data.  (Is this a single cell?) */
      call_dissector(data_handle,tvb, pinfo, tree);
    }
    break;
  }
}

void
proto_register_atm(void)
{
	static hf_register_info hf[] = {
		{ &hf_atm_vpi,
		{ "VPI",		"atm.vpi", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},

		{ &hf_atm_vci,
		{ "VCI",		"atm.vci", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},
	};
	static gint *ett[] = {
		&ett_atm,
		&ett_ilmi,
		&ett_atm_lane,
		&ett_atm_lane_lc_lan_dest,
		&ett_atm_lane_lc_lan_dest_rd,
		&ett_atm_lane_lc_flags,
		&ett_atm_lane_lc_tlv,
	};
	proto_atm = proto_register_protocol("ATM", "ATM", "atm");
	proto_register_field_array(proto_atm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	proto_ilmi = proto_register_protocol("ILMI", "ILMI", "ilmi");

	register_dissector("ilmi", dissect_ilmi, proto_ilmi);

	proto_atm_lane = proto_register_protocol("ATM LAN Emulation",
	    "ATM LANE", "lane");

	register_dissector("lane", dissect_lane, proto_atm_lane);
}

void
proto_reg_handoff_atm(void)
{
	dissector_handle_t atm_handle;

	/*
	 * Get handles for the Ethernet, Token Ring, LLC, SSCOP, LANE,
	 * and ILMI dissectors.
	 */
	eth_handle = find_dissector("eth");
	tr_handle = find_dissector("tr");
	llc_handle = find_dissector("llc");
	sscop_handle = find_dissector("sscop");
	lane_handle = find_dissector("lane");
	ilmi_handle = find_dissector("ilmi");
	data_handle = find_dissector("data");

	atm_handle = create_dissector_handle(dissect_atm, proto_atm);

	dissector_add("wtap_encap", WTAP_ENCAP_ATM_SNIFFER, atm_handle);
}
