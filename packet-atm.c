/* packet-atm.c
 * Routines for ATM packet disassembly
 *
 * $Id: packet-atm.c,v 1.5 1999/11/18 08:50:18 gram Exp $
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
#include "resolv.h"

#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
#include "packet-snmp.h"
#endif

static int proto_atm = -1;
static int proto_atm_lane = -1;
#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
static int proto_ilmi = -1;
#endif

static gint ett_atm = -1;
static gint ett_atm_lane = -1;
static gint ett_atm_lane_lc_lan_dest = -1;
static gint ett_atm_lane_lc_lan_dest_rd = -1;
static gint ett_atm_lane_lc_flags = -1;
#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
static gint ett_ilmi = -1;
#endif

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
    ti = proto_tree_add_item_format(tree, proto_atm_lane, offset, 2, NULL,
					    "ATM LANE");
    lane_tree = proto_item_add_subtree(ti, ett_atm_lane);

    proto_tree_add_text(lane_tree, offset, 2, "LE Client: 0x%04X",
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

  td = proto_tree_add_text(tree, offset, 8, "%s LAN destination",
    			type);
  dest_tree = proto_item_add_subtree(td, ett_atm_lane_lc_lan_dest);
  tag = pntohs(&pd[offset]);
  proto_tree_add_text(dest_tree, offset, 2, "Tag: %s",
	val_to_str(tag, le_control_landest_tag_vals,
				"Unknown (%x)"));
  offset += 2;

  switch (tag) {

  case TAG_MAC_ADDRESS:
    proto_tree_add_text(dest_tree, offset, 6, "MAC address: %s",
			ether_to_str((u_char *)&pd[offset]));
    break;

  case TAG_ROUTE_DESCRIPTOR:
    offset += 4;
    route_descriptor = pntohs(&pd[offset]);
    trd = proto_tree_add_text(dest_tree, offset, 2, "Route descriptor: 0x%02X",
    			route_descriptor);
    rd_tree = proto_item_add_subtree(td, ett_atm_lane_lc_lan_dest_rd);
    proto_tree_add_text(rd_tree, offset, 2,
	    decode_numeric_bitfield(route_descriptor, 0xFFF0, 2*8,
			"LAN ID = %u"));
    proto_tree_add_text(rd_tree, offset, 2,
	    decode_numeric_bitfield(route_descriptor, 0x000F, 2*8,
			"Bridge number = %u"));
    break;
  }
}

static void
dissect_le_control(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) 
{
  proto_item *ti;
  proto_tree *lane_tree;
  proto_item *tf;
  proto_tree *flags_tree;
  guint16 opcode;
  guint16 flags;

  if (check_col(fd, COL_INFO))
    col_add_str(fd, COL_INFO, "LE Control");

  if (tree) {
    ti = proto_tree_add_item_format(tree, proto_atm_lane, offset, 108, NULL,
					    "ATM LANE");
    lane_tree = proto_item_add_subtree(ti, ett_atm_lane);

    proto_tree_add_text(lane_tree, offset, 2, "Marker: 0x%04X",
			pntohs(&pd[offset]));
    offset += 2;

    proto_tree_add_text(lane_tree, offset, 1, "Protocol: 0x%02X",
			pd[offset]);
    offset += 1;

    proto_tree_add_text(lane_tree, offset, 1, "Version: 0x%02X",
			pd[offset]);
    offset += 1;

    opcode = pntohs(&pd[offset]);
    proto_tree_add_text(lane_tree, offset, 2, "Opcode: %s",
	val_to_str(opcode, le_control_opcode_vals,
				"Unknown (%x)"));
    offset += 2;

    if (opcode == READY_QUERY || opcode == READY_IND) {
      /* There's nothing more in this packet. */
      return;
    }

    if (opcode & 0x0100) {
      /* Response; decode status. */
      proto_tree_add_text(lane_tree, offset, 2, "Status: %s",
	val_to_str(pntohs(&pd[offset]), le_control_status_vals,
				"Unknown (%x)"));
    }
    offset += 2;

    proto_tree_add_text(lane_tree, offset, 4, "Transaction ID: 0x%08X",
    			pntohl(&pd[offset]));
    offset += 4;

    proto_tree_add_text(lane_tree, offset, 2, "Requester LECID: 0x%04X",
    			pntohs(&pd[offset]));
    offset += 2;

    flags = pntohs(&pd[offset]);
    tf = proto_tree_add_text(lane_tree, offset, 2, "Flags: 0x%04X",
    			pntohs(&pd[offset]));
    flags_tree = proto_item_add_subtree(tf, ett_atm_lane_lc_flags);
    proto_tree_add_text(flags_tree, offset, 2, "%s",
	decode_boolean_bitfield(flags, 0x0001, 8*2,
				"Remote address", "Local address"));
    proto_tree_add_text(flags_tree, offset, 2, "%s",
	decode_boolean_bitfield(flags, 0x0080, 8*2,
				"Proxy", "Not proxy"));
    proto_tree_add_text(flags_tree, offset, 2, "%s",
	decode_boolean_bitfield(flags, 0x0100, 8*2,
				"Topology change", "No topology change"));
    offset += 2;

    dissect_lan_destination(pd, offset, "Source", lane_tree);
    offset += 8;

    dissect_lan_destination(pd, offset, "Target", lane_tree);
    offset += 8;

    proto_tree_add_text(lane_tree, offset, 20, "Source ATM Address: %s",
    			bytes_to_str(&pd[offset], 20));
    offset += 20;

    proto_tree_add_text(lane_tree, offset, 1, "LAN type: %s",
	val_to_str(pd[offset], le_control_lan_type_vals,
				"Unknown (%x)"));
    offset += 1;

    proto_tree_add_text(lane_tree, offset, 1, "Maximum frame size: %u",
			pd[offset]);
    offset += 1;

    proto_tree_add_text(lane_tree, offset, 1, "Number of TLVs: %u",
			pd[offset]);
    offset += 1;

    proto_tree_add_text(lane_tree, offset, 1, "ELAN name size: %u",
			pd[offset]);
    offset += 1;

    proto_tree_add_text(lane_tree, offset, 20, "Target ATM Address: %s",
    			bytes_to_str(&pd[offset], 20));
    offset += 20;

    proto_tree_add_text(lane_tree, offset, 32, "ELAN name: %s",
    			bytes_to_str(&pd[offset], 32));
    offset += 32;
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

void
dissect_atm(const u_char *pd, frame_data *fd, proto_tree *tree) 
{
  int        offset = 0;
  proto_tree *atm_tree;
  proto_item *ti;
  guint       aal_type;
  guint       hl_type;

  aal_type = fd->pseudo_header.ngsniffer_atm.AppTrafType & ATT_AALTYPE;
  hl_type = fd->pseudo_header.ngsniffer_atm.AppHLType & ATT_HLTYPE;

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
    ti = proto_tree_add_item_format(tree, proto_atm, 0, 0, NULL,
					    "ATM");
    atm_tree = proto_item_add_subtree(ti, ett_atm);

    proto_tree_add_text(atm_tree, 0, 0, "AAL: %s",
	val_to_str(aal_type, aal_vals, "Unknown AAL (%x)"));
    if (aal_type == ATT_AAL5) {
      proto_tree_add_text(atm_tree, 0, 0, "Traffic type: %s",
	val_to_str(hl_type, aal5_hltype_vals, "Unknown AAL5 traffic type (%x)"));
    }
    if (aal_type == ATT_AAL5) {
      switch (hl_type) {

      case ATT_HL_LLCMX:
        proto_tree_add_text(atm_tree, 0, 0, "LLC multiplexed traffic");
        break;

      case ATT_HL_VCMX:
        proto_tree_add_text(atm_tree, 0, 0, "VC multiplexed traffic type: %s",
		val_to_str(fd->pseudo_header.ngsniffer_atm.AppHLType,
			vcmx_type_vals, "Unknown VCMX traffic type (%x)"));
        break;

      case ATT_HL_LANE:
        proto_tree_add_text(atm_tree, 0, 0, "LANE traffic type: %s",
		val_to_str(fd->pseudo_header.ngsniffer_atm.AppHLType,
			lane_type_vals, "Unknown LANE traffic type (%x)"));
        break;

      case ATT_HL_IPSILON:
        proto_tree_add_text(atm_tree, 0, 0, "Ipsilon traffic type: %s",
		val_to_str(fd->pseudo_header.ngsniffer_atm.AppHLType,
			ipsilon_type_vals, "Unknown Ipsilon traffic type (%x)"));
        break;
      }
    }
    proto_tree_add_text(atm_tree, 0, 0, "VPI: %u",
		fd->pseudo_header.ngsniffer_atm.Vpi);
    proto_tree_add_text(atm_tree, 0, 0, "VCI: %u",
		fd->pseudo_header.ngsniffer_atm.Vci);
    switch (fd->pseudo_header.ngsniffer_atm.channel) {

    case 0:
      /* Traffic from DCE to DTE. */
      proto_tree_add_text(atm_tree, 0, 0, "Channel: DCE->DTE");
      break;

    case 1:
      /* Traffic from DTE to DCE. */
      proto_tree_add_text(atm_tree, 0, 0, "Channel: DTE->DCE");
      break;

    default:
      /* Sniffers shouldn't provide anything other than 0 or 1. */
      proto_tree_add_text(atm_tree, 0, 0, "Channel: %u",
 		fd->pseudo_header.ngsniffer_atm.channel);
      break;
    }
    proto_tree_add_text(atm_tree, 0, 0, "Cells: %u",
		fd->pseudo_header.ngsniffer_atm.cells);
    if (aal_type == ATT_AAL5) {
      proto_tree_add_text(atm_tree, 0, 0, "AAL5 U2U: %u",
		fd->pseudo_header.ngsniffer_atm.aal5t_u2u);
      proto_tree_add_text(atm_tree, 0, 0, "AAL5 len: %u",
		fd->pseudo_header.ngsniffer_atm.aal5t_len);
      proto_tree_add_text(atm_tree, 0, 0, "AAL5 checksum: 0x%08X",
		fd->pseudo_header.ngsniffer_atm.aal5t_chksum);
    }
  }

  if (aal_type == ATT_AAL5) {
    switch (hl_type) {

    case ATT_HL_LLCMX:
      /* Dissect as WTAP_ENCAP_ATM_RFC1483 */
      /* The ATM iptrace capture that we have hows LLC at this point,
       * so that's what I'm calling */
      dissect_llc(pd, offset, fd, tree);
      break;

    case ATT_HL_LANE:
      dissect_lane(pd, offset, fd, tree);
      break;

#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
    case ATT_HL_ILMI:
      dissect_snmp_pdu(pd, offset, fd, tree, "ILMI", proto_ilmi, ett_ilmi);
      break;
#endif

    default:
      if (tree) {
        /* Dump it as raw data. */
        dissect_data(pd, offset, fd, tree);
        break;
      }
    }
  } else {
    if (tree) {
      /* Dump it as raw data.  (Is this a single cell?) */
      dissect_data(pd, offset, fd, tree);
    }
  }
}

void
proto_register_atm(void)
{
	static gint *ett[] = {
		&ett_atm,
		&ett_atm_lane,
		&ett_atm_lane_lc_lan_dest,
		&ett_atm_lane_lc_lan_dest_rd,
		&ett_atm_lane_lc_flags,
#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
		&ett_ilmi,
#endif
	};
	proto_atm = proto_register_protocol("ATM", "atm");
	proto_atm_lane = proto_register_protocol("ATM LANE", "lane");
#if defined(HAVE_UCD_SNMP_SNMP_H) || defined(HAVE_SNMP_SNMP_H)
	proto_ilmi = proto_register_protocol("ILMI", "ilmi");
#endif
	proto_register_subtree_array(ett, array_length(ett));
}
