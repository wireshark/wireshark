/* packet-atm.c
 * Routines for ATM packet disassembly
 *
 * $Id: packet-atm.c,v 1.15 2000/05/11 22:04:15 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include "packet.h"
#include "oui.h"
#include "resolv.h"

#include "packet-eth.h"
#include "packet-llc.h"
#include "packet-snmp.h"
#include "packet-sscop.h"
#include "packet-tr.h"

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

static void
dissect_le_client(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
  proto_item *ti;
  proto_tree *lane_tree;

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_atm_lane, NullTVB, offset, 2, "ATM LANE");
    lane_tree = proto_item_add_subtree(ti, ett_atm_lane);

    proto_tree_add_text(lane_tree, NullTVB, offset, 2, "LE Client: 0x%04X",
			pntohs(&pd[offset]));
  }
}

static void
dissect_lan_destination(const u_char *pd, int offset, const char *type, proto_tree *tree) 
{
  proto_item *td;
  proto_tree *dest_tree;
  guint16 tag;
  proto_item *trd;
  proto_tree *rd_tree;
  guint16 route_descriptor;

  td = proto_tree_add_text(tree, NullTVB, offset, 8, "%s LAN destination",
    			type);
  dest_tree = proto_item_add_subtree(td, ett_atm_lane_lc_lan_dest);
  tag = pntohs(&pd[offset]);
  proto_tree_add_text(dest_tree, NullTVB, offset, 2, "Tag: %s",
	val_to_str(tag, le_control_landest_tag_vals,
				"Unknown (0x%04X)"));
  offset += 2;

  switch (tag) {

  case TAG_MAC_ADDRESS:
    proto_tree_add_text(dest_tree, NullTVB, offset, 6, "MAC address: %s",
			ether_to_str((u_char *)&pd[offset]));
    break;

  case TAG_ROUTE_DESCRIPTOR:
    offset += 4;
    route_descriptor = pntohs(&pd[offset]);
    trd = proto_tree_add_text(dest_tree, NullTVB, offset, 2, "Route descriptor: 0x%02X",
    			route_descriptor);
    rd_tree = proto_item_add_subtree(td, ett_atm_lane_lc_lan_dest_rd);
    proto_tree_add_text(rd_tree, NullTVB, offset, 2,
	    decode_numeric_bitfield(route_descriptor, 0xFFF0, 2*8,
			"LAN ID = %u"));
    proto_tree_add_text(rd_tree, NullTVB, offset, 2,
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
	{ 0,				NULL },
};

static void
dissect_le_control(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
  proto_item *ti;
  proto_tree *lane_tree;
  proto_item *tf;
  proto_tree *flags_tree;
  proto_item *ttlv;
  proto_tree *tlv_tree;
  guint16 opcode;
  guint16 flags;
  guint8 num_tlvs;
  guint32 tlv_type;
  guint8 tlv_length;

  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, "LE Control");

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_atm_lane, NullTVB, offset, 108, "ATM LANE");
    lane_tree = proto_item_add_subtree(ti, ett_atm_lane);

    proto_tree_add_text(lane_tree, NullTVB, offset, 2, "Marker: 0x%04X",
			pntohs(&pd[offset]));
    offset += 2;

    proto_tree_add_text(lane_tree, NullTVB, offset, 1, "Protocol: 0x%02X",
			pd[offset]);
    offset += 1;

    proto_tree_add_text(lane_tree, NullTVB, offset, 1, "Version: 0x%02X",
			pd[offset]);
    offset += 1;

    opcode = pntohs(&pd[offset]);
    proto_tree_add_text(lane_tree, NullTVB, offset, 2, "Opcode: %s",
	val_to_str(opcode, le_control_opcode_vals,
				"Unknown (0x%04X)"));
    offset += 2;

    if (opcode == READY_QUERY || opcode == READY_IND) {
      /* There's nothing more in this packet. */
      return;
    }

    if (opcode & 0x0100) {
      /* Response; decode status. */
      proto_tree_add_text(lane_tree, NullTVB, offset, 2, "Status: %s",
	val_to_str(pntohs(&pd[offset]), le_control_status_vals,
				"Unknown (0x%04X)"));
    }
    offset += 2;

    proto_tree_add_text(lane_tree, NullTVB, offset, 4, "Transaction ID: 0x%08X",
    			pntohl(&pd[offset]));
    offset += 4;

    proto_tree_add_text(lane_tree, NullTVB, offset, 2, "Requester LECID: 0x%04X",
    			pntohs(&pd[offset]));
    offset += 2;

    flags = pntohs(&pd[offset]);
    tf = proto_tree_add_text(lane_tree, NullTVB, offset, 2, "Flags: 0x%04X",
    			pntohs(&pd[offset]));
    flags_tree = proto_item_add_subtree(tf, ett_atm_lane_lc_flags);
    proto_tree_add_text(flags_tree, NullTVB, offset, 2, "%s",
	decode_boolean_bitfield(flags, 0x0001, 8*2,
				"Remote address", "Local address"));
    proto_tree_add_text(flags_tree, NullTVB, offset, 2, "%s",
	decode_boolean_bitfield(flags, 0x0080, 8*2,
				"Proxy", "Not proxy"));
    proto_tree_add_text(flags_tree, NullTVB, offset, 2, "%s",
	decode_boolean_bitfield(flags, 0x0100, 8*2,
				"Topology change", "No topology change"));
    offset += 2;

    dissect_lan_destination(pd, offset, "Source", lane_tree);
    offset += 8;

    dissect_lan_destination(pd, offset, "Target", lane_tree);
    offset += 8;

    proto_tree_add_text(lane_tree, NullTVB, offset, 20, "Source ATM Address: %s",
    			bytes_to_str(&pd[offset], 20));
    offset += 20;

    proto_tree_add_text(lane_tree, NullTVB, offset, 1, "LAN type: %s",
	val_to_str(pd[offset], le_control_lan_type_vals,
				"Unknown (0x%02X)"));
    offset += 1;

    proto_tree_add_text(lane_tree, NullTVB, offset, 1, "Maximum frame size: %u",
			pd[offset]);
    offset += 1;

    num_tlvs = pd[offset];
    proto_tree_add_text(lane_tree, NullTVB, offset, 1, "Number of TLVs: %u",
			num_tlvs);
    offset += 1;

    proto_tree_add_text(lane_tree, NullTVB, offset, 1, "ELAN name size: %u",
			pd[offset]);
    offset += 1;

    proto_tree_add_text(lane_tree, NullTVB, offset, 20, "Target ATM Address: %s",
    			bytes_to_str(&pd[offset], 20));
    offset += 20;

    proto_tree_add_text(lane_tree, NullTVB, offset, 32, "ELAN name: %s",
    			bytes_to_str(&pd[offset], 32));
    offset += 32;

    while (num_tlvs != 0) {
      tlv_type = pntohl(&pd[offset]);
      tlv_length = pd[offset+4];
      ttlv = proto_tree_add_text(lane_tree, NullTVB, offset, 5+tlv_length, "TLV type: %s",
	val_to_str(tlv_type, le_tlv_type_vals, "Unknown (0x%08x)"));
      tlv_tree = proto_item_add_subtree(ttlv, ett_atm_lane_lc_tlv);
      proto_tree_add_text(tlv_tree, NullTVB, offset, 4, "TLV Type: %s",
	val_to_str(tlv_type, le_tlv_type_vals, "Unknown (0x%08x)"));
      proto_tree_add_text(tlv_tree, NullTVB, offset+4, 1, "TLV Length: %u", tlv_length);
      offset += 5+tlv_length;
      num_tlvs--;
    }
  }
}

static void
dissect_lane(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "ATM LANE");
  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, "ATM LANE");

  /* Is it LE Control, 802.3, 802.5, or "none of the above"? */
  switch (fd->pseudo_header.ngsniffer_atm.AppHLType) {

  case AHLT_LANE_LE_CTRL:
    dissect_le_control(pd, offset, fd, tree);
    break;

  case AHLT_LANE_802_3:
  case AHLT_LANE_802_3_MC:
    dissect_le_client(pd, offset, fd, tree);
    offset += 2;

    /* Dissect as Ethernet */
    dissect_eth(pd, offset, fd, tree);
    break;

  case AHLT_LANE_802_5:
  case AHLT_LANE_802_5_MC:
    dissect_le_client(pd, offset, fd, tree);
    offset += 2;

    /* Dissect as Token-Ring */
    dissect_tr(pd, offset, fd, tree);
    break;

  default:
    /* Dump it as raw data. */
    dissect_data(pd, offset, fd, tree);
    break;
  }
}

/* AAL types */
static const value_string aal_vals[] = {
	{ ATT_AAL_UNKNOWN,    "Unknown AAL" },
	{ ATT_AAL1,           "AAL1" },
	{ ATT_AAL3_4,         "AAL3/4" },
	{ ATT_AAL5,           "AAL5" },
	{ ATT_AAL_USER,       "User AAL" },
	{ ATT_AAL_SIGNALLING, "Signalling AAL" },
	{ ATT_OAMCELL,        "OAM cell" },
	{ 0,                  NULL }
};

/* AAL5 higher-level traffic types */
static const value_string aal5_hltype_vals[] = {
	{ ATT_HL_UNKNOWN, "Unknown traffic type" },
	{ ATT_HL_LLCMX,   "LLC multiplexed" },
	{ ATT_HL_VCMX,    "VC multiplexed" },
	{ ATT_HL_LANE,    "LANE" },
	{ ATT_HL_ILMI,    "ILMI" },
	{ ATT_HL_FRMR,    "Frame Relay" },
	{ ATT_HL_SPANS,   "FORE SPANS" },
	{ ATT_HL_IPSILON, "Ipsilon" },
	{ 0,              NULL }
};

/* Traffic subtypes for VC multiplexed traffic */
static const value_string vcmx_type_vals[] = {
	{ AHLT_UNKNOWN,        "Unknown VC multiplexed traffic type" },
	{ AHLT_VCMX_802_3_FCS, "802.3 FCS" },
	{ AHLT_VCMX_802_4_FCS, "802.4 FCS" },
	{ AHLT_VCMX_802_5_FCS, "802.5 FCS" },
	{ AHLT_VCMX_FDDI_FCS,  "FDDI FCS" },
	{ AHLT_VCMX_802_6_FCS, "802.6 FCS" },
	{ AHLT_VCMX_802_3,     "802.3" },
	{ AHLT_VCMX_802_4,     "802.4" },
	{ AHLT_VCMX_802_5,     "802.5" },
	{ AHLT_VCMX_FDDI,      "FDDI" },
	{ AHLT_VCMX_802_6,     "802.6" },
	{ AHLT_VCMX_FRAGMENTS, "Fragments" },
	{ AHLT_VCMX_BPDU,      "BPDU" },
	{ 0,                   NULL }
};

/* Traffic subtypes for LANE traffic */
static const value_string lane_type_vals[] = {
	{ AHLT_UNKNOWN,       "Unknown LANE traffic type" },
	{ AHLT_LANE_LE_CTRL,  "LE Control" },
	{ AHLT_LANE_802_3,    "802.3" },
	{ AHLT_LANE_802_5,    "802.5" },
	{ AHLT_LANE_802_3_MC, "802.3 multicast" },
	{ AHLT_LANE_802_5_MC, "802.5 multicast" },
	{ 0,                  NULL }
};

/* Traffic subtypes for Ipsilon traffic */
static const value_string ipsilon_type_vals[] = {
	{ AHLT_UNKNOWN,     "Unknown Ipsilon traffic type" },
	{ AHLT_IPSILON_FT0, "Flow type 0" },
	{ AHLT_IPSILON_FT1, "Flow type 1" },
	{ AHLT_IPSILON_FT2, "Flow type 2" },
	{ 0,                NULL }
};

/*
 * We don't know what kind of traffic this is; try to guess.
 * We at least know it's AAL5....
 */
static void
atm_guess_content(const u_char *pd, frame_data *fd)
{
	if (fd->pseudo_header.ngsniffer_atm.Vpi == 0) {
		/*
		 * Traffic on some PVCs with a VPI of 0 and certain
		 * VCIs is of particular types.
		 */
		switch (fd->pseudo_header.ngsniffer_atm.Vci) {

		case 5:
			/*
			 * Signalling AAL.
			 */
			fd->pseudo_header.ngsniffer_atm.AppTrafType =
			    ATT_AAL_SIGNALLING;
			return;

		case 16:
			/*
			 * ILMI.
			 */
			fd->pseudo_header.ngsniffer_atm.AppTrafType |=
			    ATT_HL_ILMI;
			return;
		}
	}

	/*
	 * OK, we can't tell what it is based on the VPI/VCI; try
	 * guessing based on the contents.
	 */
	if (pd[0] == 0xaa && pd[1] == 0xaa && pd[2] == 0x03) {
		/*
		 * Looks like a SNAP header; assume it's LLC multiplexed
		 * RFC 1483 traffic.
		 */
		fd->pseudo_header.ngsniffer_atm.AppTrafType |= ATT_HL_LLCMX;
	} else {
		/*
		 * Assume it's LANE.
		 */
		fd->pseudo_header.ngsniffer_atm.AppTrafType |= ATT_HL_LANE;
		if (pd[0] == 0xff && pd[1] == 0x00) {
			/*
			 * Looks like LE Control traffic.
			 */
			fd->pseudo_header.ngsniffer_atm.AppHLType =
			    AHLT_LANE_LE_CTRL;
		} else {
			/*
			 * XXX - Ethernet, or Token Ring?
			 * Assume Ethernet for now; if we see earlier
			 * LANE traffic, we may be able to figure out
			 * the traffic type from that, but there may
			 * still be situations where the user has to
			 * tell us.
			 */
			fd->pseudo_header.ngsniffer_atm.AppHLType =
			    AHLT_LANE_802_3;
		}
	}
}

void
dissect_atm(const u_char *pd, frame_data *fd, proto_tree *tree) 
{
  int        offset = 0;
  proto_tree *atm_tree;
  proto_item *ti;
  guint       aal_type;
  guint       hl_type;
  tvbuff_t*   next_tvb;

  aal_type = fd->pseudo_header.ngsniffer_atm.AppTrafType & ATT_AALTYPE;
  hl_type = fd->pseudo_header.ngsniffer_atm.AppTrafType & ATT_HLTYPE;
  if (aal_type == ATT_AAL5) {
    if (hl_type == ATT_HL_UNKNOWN ||
	fd->pseudo_header.ngsniffer_atm.AppHLType == AHLT_UNKNOWN) {
      /*
       * The joys of a connection-oriented link layer; the type of
       * traffic may be implied by the connection on which it's
       * traveling, rather than being specified in the packet itself.
       *
       * For this packet, the program that captured the packet didn't
       * save the type of traffic, presumably because it didn't know
       * the traffic type (either it didn't see the connection setup
       * and wasn't running on one of the endpoints, and wasn't later
       * told, e.g. by the human running it, what type of traffic was
       * on that circuit, or was running on one of the endpoints but
       * was using, to capture the packets, a mechanism that either
       * doesn't have access to data saying what's going over the
       * connection or doesn't bother providing that information).
       *
       * For now, we try to guess the traffic type based on the VPI/VCI
       * or the packet header; later, we should provide a mechanism
       * by which the user can specify what sort of traffic is on a
       * particular circuit.
       */
      atm_guess_content(pd, fd);

      /*
       * OK, now get the AAL type and high-layer type again.
       */
      aal_type = fd->pseudo_header.ngsniffer_atm.AppTrafType & ATT_AALTYPE;
      hl_type = fd->pseudo_header.ngsniffer_atm.AppTrafType & ATT_HLTYPE;
    }
  }

  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "ATM");

  switch (fd->pseudo_header.ngsniffer_atm.channel) {

  case 0:
    /* Traffic from DCE to DTE. */
    if (check_col(fd, COL_RES_DL_DST))
      col_add_str(fd, COL_RES_DL_DST, "DTE");
    if (check_col(fd, COL_RES_DL_SRC))
      col_add_str(fd, COL_RES_DL_SRC, "DCE");
    break;

  case 1:
    /* Traffic from DTE to DCE. */
    if (check_col(fd, COL_RES_DL_DST))
      col_add_str(fd, COL_RES_DL_DST, "DCE");
    if (check_col(fd, COL_RES_DL_SRC))
      col_add_str(fd, COL_RES_DL_SRC, "DTE");
    break;
  }

  if (check_col(fd, COL_INFO)) {
    if (aal_type == ATT_AAL5) {
      col_add_fstr(fd, COL_INFO, "AAL5 %s",
		val_to_str(hl_type, aal5_hltype_vals,
				"Unknown traffic type (%x)"));
    } else {
      col_add_str(fd, COL_INFO,
		val_to_str(aal_type, aal_vals, "Unknown AAL (%x)"));
    }
  }

  if (tree) {
    ti = proto_tree_add_protocol_format(tree, proto_atm, NullTVB, 0, 0, "ATM");
    atm_tree = proto_item_add_subtree(ti, ett_atm);

    proto_tree_add_text(atm_tree, NullTVB, 0, 0, "AAL: %s",
	val_to_str(aal_type, aal_vals, "Unknown AAL (%x)"));
    if (aal_type == ATT_AAL5) {
      proto_tree_add_text(atm_tree, NullTVB, 0, 0, "Traffic type: %s",
	val_to_str(hl_type, aal5_hltype_vals, "Unknown AAL5 traffic type (%x)"));
      switch (hl_type) {

      case ATT_HL_LLCMX:
        proto_tree_add_text(atm_tree, NullTVB, 0, 0, "LLC multiplexed traffic");
        break;

      case ATT_HL_VCMX:
        proto_tree_add_text(atm_tree, NullTVB, 0, 0, "VC multiplexed traffic type: %s",
		val_to_str(fd->pseudo_header.ngsniffer_atm.AppHLType,
			vcmx_type_vals, "Unknown VCMX traffic type (%x)"));
        break;

      case ATT_HL_LANE:
        proto_tree_add_text(atm_tree, NullTVB, 0, 0, "LANE traffic type: %s",
		val_to_str(fd->pseudo_header.ngsniffer_atm.AppHLType,
			lane_type_vals, "Unknown LANE traffic type (%x)"));
        break;

      case ATT_HL_IPSILON:
        proto_tree_add_text(atm_tree, NullTVB, 0, 0, "Ipsilon traffic type: %s",
		val_to_str(fd->pseudo_header.ngsniffer_atm.AppHLType,
			ipsilon_type_vals, "Unknown Ipsilon traffic type (%x)"));
        break;
      }
    }
    proto_tree_add_item(atm_tree, hf_atm_vpi, NullTVB, 0, 0,
		fd->pseudo_header.ngsniffer_atm.Vpi);
    proto_tree_add_item(atm_tree, hf_atm_vci, NullTVB, 0, 0,
		fd->pseudo_header.ngsniffer_atm.Vci);
    switch (fd->pseudo_header.ngsniffer_atm.channel) {

    case 0:
      /* Traffic from DCE to DTE. */
      proto_tree_add_text(atm_tree, NullTVB, 0, 0, "Channel: DCE->DTE");
      break;

    case 1:
      /* Traffic from DTE to DCE. */
      proto_tree_add_text(atm_tree, NullTVB, 0, 0, "Channel: DTE->DCE");
      break;

    default:
      /* Sniffers shouldn't provide anything other than 0 or 1. */
      proto_tree_add_text(atm_tree, NullTVB, 0, 0, "Channel: %u",
 		fd->pseudo_header.ngsniffer_atm.channel);
      break;
    }
    if (fd->pseudo_header.ngsniffer_atm.cells != 0) {
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
      proto_tree_add_text(atm_tree, NullTVB, 0, 0, "Cells: %u",
		fd->pseudo_header.ngsniffer_atm.cells);
      if (aal_type == ATT_AAL5) {
        proto_tree_add_text(atm_tree, NullTVB, 0, 0, "AAL5 U2U: %u",
		fd->pseudo_header.ngsniffer_atm.aal5t_u2u);
        proto_tree_add_text(atm_tree, NullTVB, 0, 0, "AAL5 len: %u",
		fd->pseudo_header.ngsniffer_atm.aal5t_len);
        proto_tree_add_text(atm_tree, NullTVB, 0, 0, "AAL5 checksum: 0x%08X",
		fd->pseudo_header.ngsniffer_atm.aal5t_chksum);
      }
    }
  }

  switch (aal_type) {

  case ATT_AAL_SIGNALLING:
    dissect_sscop(pd, offset, fd, tree);
    break;

  case ATT_AAL5:
    switch (hl_type) {

    case ATT_HL_LLCMX:
      /* Dissect as WTAP_ENCAP_ATM_RFC1483 */
      /* The ATM iptrace capture that we have hows LLC at this point,
       * so that's what I'm calling */
      next_tvb = tvb_new_subset(pi.compat_top_tvb, offset, -1);
      dissect_llc(next_tvb, &pi, tree);
      break;

    case ATT_HL_LANE:
      dissect_lane(pd, offset, fd, tree);
      break;

    case ATT_HL_ILMI:
      dissect_snmp_pdu(pd, offset, fd, tree, "ILMI", proto_ilmi, ett_ilmi);
      break;

    default:
      if (tree) {
        /* Dump it as raw data. */
        dissect_data(pd, offset, fd, tree);
        break;
      }
    }
    break;

  default:
    if (tree) {
      /* Dump it as raw data.  (Is this a single cell?) */
      dissect_data(pd, offset, fd, tree);
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
			"" }},

		{ &hf_atm_vci,
		{ "VCI",		"atm.vci", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},
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
	proto_atm = proto_register_protocol("ATM", "atm");
	proto_register_field_array(proto_atm, hf, array_length(hf));
	proto_ilmi = proto_register_protocol("ILMI", "ilmi");
	proto_atm_lane = proto_register_protocol("ATM LANE", "lane");
	proto_register_subtree_array(ett, array_length(ett));
}
