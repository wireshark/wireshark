/* packet-extreme.c
 * Routines for the disassembly of Extreme Networks specific
 * protocols (EDP/ESRP)
 *
 * $Id$
 *
 * Copyright 2005 Joerg Mayer (see AUTJORS file)
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

/* Specs:
   EAPS v1 is specified in rfc 3619
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "packet-llc.h"
#include "oui.h"

static int hf_llc_extreme_pid = -1;

static int proto_edp = -1;
/* EDP header */
static int hf_edp_version = -1;
static int hf_edp_reserved = -1;
static int hf_edp_length = -1;
static int hf_edp_chksum = -1;
static int hf_edp_seqno = -1;
static int hf_edp_midtype = -1;
static int hf_edp_midmac = -1;
/* TLV header */
static int hf_edp_tlv_marker = -1;
static int hf_edp_tlv_type = -1;
static int hf_edp_tlv_length = -1;
/* Display string */
static int hf_edp_display = -1;
/* Info element */
static int hf_edp_info_slot = -1;
static int hf_edp_info_port = -1;
static int hf_edp_info_vchassid = -1;
static int hf_edp_info_reserved = -1;
static int hf_edp_info_version = -1;
static int hf_edp_info_vchassconn = -1;
/* Vlan element */
static int hf_edp_vlan_flags = -1;
static int hf_edp_vlan_reserved1 = -1;
static int hf_edp_vlan_id = -1;
static int hf_edp_vlan_reserved2 = -1;
static int hf_edp_vlan_ip = -1;
static int hf_edp_vlan_name = -1;
/* ESRP element */
static int hf_edp_esrp_proto = -1;
static int hf_edp_esrp_group = -1;
static int hf_edp_esrp_prio = -1;
static int hf_edp_esrp_state = -1;
static int hf_edp_esrp_ports = -1;
static int hf_edp_esrp_virtip = -1;
static int hf_edp_esrp_sysmac = -1;
static int hf_edp_esrp_hello = -1;
static int hf_edp_esrp_reserved = -1;
/* EAPS element */
static int hf_edp_eaps_ver = -1;
static int hf_edp_eaps_type = -1;
static int hf_edp_eaps_ctrlvlanid = -1;
static int hf_edp_eaps_reserved0 = -1;
static int hf_edp_eaps_sysmac = -1;
static int hf_edp_eaps_hello = -1;
static int hf_edp_eaps_fail = -1;
static int hf_edp_eaps_state = -1;
static int hf_edp_eaps_reserved1 = -1;
static int hf_edp_eaps_helloseq = -1;
static int hf_edp_eaps_reserved2 = -1;

static gint ett_edp = -1;
static gint ett_edp_tlv = -1;

#define PROTO_SHORT_NAME "EDP"
#define PROTO_LONG_NAME "Extreme Discovery Protocol"

static const value_string extreme_pid_vals[] = {
	{ 0x00bb,	"EDP" },

	{ 0,		NULL }
};

static const value_string esrp_proto_vals[] = {
	{ 0,	"IP" },
	{ 1,	"IPX" },
	{ 2,	"L2" },

	{ 0, NULL }
};

static const value_string esrp_state_vals[] = {
	{ 0,	"??" },
	{ 1,	"Master" },
	{ 2,	"Slave" },

	{ 0, NULL }
};

typedef enum {
	EDP_TYPE_NULL = 0,
	EDP_TYPE_DISPLAY,
	EDP_TYPE_INFO,
	EDP_TYPE_VLAN = 5,
	EDP_TYPE_ESRP = 8,
	EDP_TYPE_EAPS = 0xb
} edp_type_t;

static const value_string edp_type_vals[] = {
	{ EDP_TYPE_NULL,	"Null"},
	{ EDP_TYPE_DISPLAY,	"Display"},
	{ EDP_TYPE_INFO,	"System"},
	{ EDP_TYPE_VLAN,	"Vlan"},
	{ EDP_TYPE_ESRP,	"ESRP"},
	{ EDP_TYPE_EAPS,	"EAPS"},

	{ 0,	NULL }
};

static const value_string eaps_type_vals[] = {
	{ 5,	"Health" },
	{ 6,	"Ring up flush fdb" },
	{ 7,	"Ring down flush fdb" },
	{ 8,	"Link down" },

	{ 0,	NULL }
};

static const value_string eaps_state_vals[] = {
	{ 0,	"Idle" },
	{ 1,	"Complete" },
	{ 2,	"Failed" },
	{ 3,	"Links up" },
	{ 4,	"Links down" },
	{ 5,	"Pre Forwarding" },

	{ 0,	NULL }
};

static void
dissect_display_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int length, proto_tree *tree)
{
	/* FIXME: I don't think that this is the right solution but don't
	 	know what is */
        proto_tree_add_string(tree, hf_edp_display, tvb, offset, length,
                tvb_format_stringzpad(tvb, offset, length));
}

static void
dissect_info_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int length _U_, proto_tree *tree)
{
	proto_tree_add_uint(tree, hf_edp_info_slot, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_uint(tree, hf_edp_info_port, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_uint(tree, hf_edp_info_vchassid, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_bytes(tree, hf_edp_info_reserved, tvb, offset, 6,
		tvb_get_ptr(tvb, offset, 6));
	offset += 6;

	/* FIXME: Split into major.minor.patch.00 */
	proto_tree_add_uint(tree, hf_edp_info_version, tvb, offset, 4,
		tvb_get_ntohl(tvb, offset));
	offset += 4;

	proto_tree_add_bytes(tree, hf_edp_info_vchassconn, tvb, offset, 16,
		tvb_get_ptr(tvb, offset, 16));
	offset += 16;
}

static void
dissect_vlan_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, int length, proto_tree *tree)
{
	/* FIXME: properly decode the bit(s):
		bit 8 = 1 -> has ip interface  */
	proto_tree_add_uint(tree, hf_edp_vlan_flags, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	proto_tree_add_bytes(tree, hf_edp_vlan_reserved1, tvb, offset, 3,
		tvb_get_ptr(tvb, offset, 3));
	offset += 3;

	/* FIXME: Looks like the vlan number might be in the reserved2 part */
	proto_tree_add_uint(tree, hf_edp_vlan_id, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_bytes(tree, hf_edp_vlan_reserved2, tvb, offset, 2,
		tvb_get_ptr(tvb, offset, 2));
	offset += 2;

	proto_tree_add_ipv4(tree, hf_edp_vlan_ip, tvb, offset, 4,
		tvb_get_ntohl(tvb, offset));
	offset += 4;

	proto_tree_add_string(tree, hf_edp_vlan_name, tvb, offset, length - 12,
		tvb_format_stringzpad(tvb, offset, length - 12));
	offset += (length - 12);
}

static void
dissect_esrp_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length _U_, proto_tree *tree)
{
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "ESRP");

	proto_tree_add_uint(tree, hf_edp_esrp_proto, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	proto_tree_add_uint(tree, hf_edp_esrp_group, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	proto_tree_add_uint(tree, hf_edp_esrp_prio, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;
	
	proto_tree_add_uint(tree, hf_edp_esrp_state, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_uint(tree, hf_edp_esrp_ports, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_ipv4(tree, hf_edp_esrp_virtip, tvb, offset, 4,
		tvb_get_ntohl(tvb, offset));
	offset += 4;

	proto_tree_add_ether(tree, hf_edp_esrp_sysmac, tvb, offset, 6,
		tvb_get_ptr(tvb, offset, 6));
	offset += 6;

	proto_tree_add_uint(tree, hf_edp_esrp_hello, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_uint(tree, hf_edp_esrp_reserved, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;
}

static void
dissect_eaps_tlv(tvbuff_t *tvb, packet_info *pinfo, int offset, int length _U_, proto_tree *tree)
{
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAPS");

	proto_tree_add_uint(tree, hf_edp_eaps_ver, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	proto_tree_add_uint(tree, hf_edp_eaps_type, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	proto_tree_add_uint(tree, hf_edp_eaps_ctrlvlanid, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_bytes(tree, hf_edp_eaps_reserved0, tvb, offset, 4,
		tvb_get_ptr(tvb, offset, 4));
	offset += 4;

	proto_tree_add_ether(tree, hf_edp_eaps_sysmac, tvb, offset, 6,
		tvb_get_ptr(tvb, offset, 6));
	offset += 6;

	proto_tree_add_uint(tree, hf_edp_eaps_hello, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_uint(tree, hf_edp_eaps_fail, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_uint(tree, hf_edp_eaps_state, tvb, offset, 1,
		tvb_get_guint8(tvb, offset));
	offset += 1;

	proto_tree_add_bytes(tree, hf_edp_eaps_reserved1, tvb, offset, 1,
		tvb_get_ptr(tvb, offset, 1));
	offset += 1;

	proto_tree_add_uint(tree, hf_edp_eaps_helloseq, tvb, offset, 2,
		tvb_get_ntohs(tvb, offset));
	offset += 2;

	proto_tree_add_bytes(tree, hf_edp_eaps_reserved2, tvb, offset, 38,
		tvb_get_ptr(tvb, offset, 38));
	offset += 38;
}

static void
dissect_edp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_item *tlvi;
	proto_tree *tlv_tree;
	proto_tree *edp_tree = NULL;
	guint32 offset = 0;
	guint last = 0;
	guint8 tlv_marker;
	guint8 tlv_type;
	guint16 tlv_length;
	guint16 data_length;
	guint16 length_remaining;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, PROTO_SHORT_NAME ":");

	if (tree) {
		length_remaining = tvb_reported_length_remaining(tvb, offset);

		ti = proto_tree_add_item(tree, proto_edp, tvb, offset, -1,
		    FALSE);
		edp_tree = proto_item_add_subtree(ti, ett_edp);

		proto_tree_add_item(edp_tree, hf_edp_version, tvb, offset, 1,
		    TRUE);
		offset += 1;

		proto_tree_add_item(edp_tree, hf_edp_reserved, tvb, offset, 1,
			TRUE);
		offset += 1;

		data_length = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(edp_tree, hf_edp_length, tvb, offset, 2,
			data_length);
		offset += 2;

		proto_tree_add_uint(edp_tree, hf_edp_chksum, tvb, offset, 2,
			tvb_get_ntohs(tvb, offset));
		offset += 2;

		proto_tree_add_uint(edp_tree, hf_edp_seqno, tvb, offset, 2,
			tvb_get_ntohs(tvb, offset));
		offset += 2;

		/* Machine ID is 8 bytes, if it starts with 0000, the remaining
		   6 bytes are a MAC */
		proto_tree_add_uint(edp_tree, hf_edp_midtype, tvb, offset, 2,
			tvb_get_ntohs(tvb, offset));
		offset += 2;

		proto_tree_add_ether(edp_tree, hf_edp_midmac, tvb, offset, 6,
			tvb_get_ptr(tvb, offset, 6));
		offset += 6;

		/* Decode the individual TLVs */
		while (offset < data_length && last == 0) {
			if (data_length - offset < 4) {
	                	tlvi = proto_tree_add_text(edp_tree, tvb, offset, 4,
                    			"Too few bytes left for TLV: %u (< 4)",
					data_length - offset);
				offset += 4;
				break;
			}
			tlv_marker = tvb_get_guint8(tvb, offset);
			tlv_type = tvb_get_guint8(tvb, offset + 1);
			tlv_length = tvb_get_ntohs(tvb, offset + 2);

			if ((tlv_length < 4) || (tlv_length > (data_length - offset))) {
	                	tlvi = proto_tree_add_text(edp_tree, tvb, offset, 0,
                    			"TLV with invalid length: %u", tlv_length);
				last = 1;
				break;
			}
			tlvi = proto_tree_add_text(edp_tree, tvb, offset,
				tlv_length, "Type: %s, length: %d bytes",
				val_to_str(tlv_type, edp_type_vals, "Unknown (0x%02x)"),
				tlv_length);

			tlv_tree = proto_item_add_subtree(tlvi, ett_edp_tlv);
			proto_tree_add_uint(tlv_tree, hf_edp_tlv_marker, tvb, offset, 1,
				tlv_marker);
			offset += 1;

			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
					val_to_str(tlv_type, edp_type_vals, "[0x%02x]"));

			proto_tree_add_uint(tlv_tree, hf_edp_tlv_type, tvb, offset, 1,
				tlv_type);
			offset += 1;

			proto_tree_add_uint(tlv_tree, hf_edp_tlv_length, tvb, offset, 2,
				tlv_length);
			offset += 2;

			switch (tlv_type) {
			case EDP_TYPE_NULL: /* Last TLV */
				last = 1;
				break;
			case EDP_TYPE_DISPLAY: /* MIB II display string */
				dissect_display_tlv(tvb, pinfo, offset, tlv_length - 4, tlv_tree);
				break;
			case EDP_TYPE_INFO: /* Basic system information */
				dissect_info_tlv(tvb, pinfo, offset, tlv_length - 4, tlv_tree);
				break;
			case EDP_TYPE_VLAN: /* VLAN info */
				dissect_vlan_tlv(tvb, pinfo, offset, tlv_length - 4, tlv_tree);
				break;
			case EDP_TYPE_ESRP: /* Extreme Standby Router Protocol */
				dissect_esrp_tlv(tvb, pinfo, offset, tlv_length - 4, tlv_tree);
				break;
			case EDP_TYPE_EAPS: /* Ethernet Automatic Protection Swtiching */
				dissect_eaps_tlv(tvb, pinfo, offset, tlv_length - 4, tlv_tree);
				break;
			default:
				proto_tree_add_text(tlv_tree, tvb, offset,
					tlv_length - 4, "Unknown data");
				break;
			}
			offset += (tlv_length - 4);
		}

	}
}

void
proto_register_edp(void)
{
	static hf_register_info hf[] = {

	/* EDP header */
		{ &hf_edp_version,
		{ "Version",	"edp.version", FT_UINT8, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_reserved,
		{ "Reserved",	"edp.reserved", FT_UINT8, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_length,
		{ "Data length",	"edp.length", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_chksum,
		{ "Checksum",	"edp.checksum", FT_UINT16, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_seqno,
		{ "Sequence number",	"edp.seqno", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_midtype,
		{ "Machine ID type",	"edp.midtype", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_midmac,
		{ "Machine MAC",	"edp.midmac", FT_ETHER, BASE_NONE, NULL,
			0x0, "", HFILL }},

	/* TLV header */
		{ &hf_edp_tlv_marker,
		{ "TLV Marker",	"edp.tlv.marker", FT_UINT8, BASE_HEX, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_tlv_type,
		{ "TLV type",	"edp.tlv.type", FT_UINT8, BASE_DEC, VALS(edp_type_vals),
			0x0, "", HFILL }},

		{ &hf_edp_tlv_length,
		{ "TLV length",	"edp.tlv.length", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

	/* Display string */
		{ &hf_edp_display,
		{ "Display",	"edp.display", FT_STRING, BASE_NONE, NULL,
			0x0, "MIB II display string", HFILL }},

	/* Info element */
		{ &hf_edp_info_slot,
		{ "Slot",	"edp.info.slot", FT_UINT16, BASE_DEC, NULL,
			0x0, "Originating slot #", HFILL }},

		{ &hf_edp_info_port,
		{ "Port",	"edp.info.port", FT_UINT16, BASE_DEC, NULL,
			0x0, "Originating port #", HFILL }},

		{ &hf_edp_info_vchassid,
		{ "Virt chassis",	"edp.info.vchassid", FT_UINT16, BASE_DEC, NULL,
			0x0, "Virtual chassis ID", HFILL }},

		{ &hf_edp_info_reserved,
		{ "Reserved",	"edp.info.reserved", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

		/* FIXME: Split into major.minor.patch.00 */
		{ &hf_edp_info_version,
		{ "Version",	"edp.info.version", FT_UINT32, BASE_HEX, NULL,
			0x0, "Software version", HFILL }},

		{ &hf_edp_info_vchassconn,
		{ "Connections",	"edp.info.vchassconn", FT_BYTES, BASE_NONE, NULL,
			0x0, "Virtual chassis connections", HFILL }},

	/* Vlan element */
		/* FIXME: properly decode the bit(s) */
		{ &hf_edp_vlan_flags,
		{ "Flags",	"edp.vlan.flags", FT_UINT8, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_vlan_reserved1,
		{ "Reserved1",	"edp.vlan.reserved1", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_vlan_id,
		{ "Vlan ID",	"edp.vlan.id", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_vlan_reserved2,
		{ "Reserved2",	"edp.vlan.reserved2", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_vlan_ip,
		{ "IP addr",	"edp.vlan.ip", FT_IPv4, BASE_NONE, NULL,
			0x0, "VLAN IP address", HFILL }},

		{ &hf_edp_vlan_name,
		{ "Name",	"edp.vlan.name", FT_STRING, BASE_NONE, NULL,
			0x0, "VLAN name", HFILL }},

	/* ESRP element */
		{ &hf_edp_esrp_proto,
		{ "Protocol",	"edp.esrp.proto", FT_UINT8, BASE_DEC, VALS(esrp_proto_vals),
			0x0, "", HFILL }},

		{ &hf_edp_esrp_group,
		{ "Group",	"edp.esrp.group", FT_UINT8, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_esrp_prio,
		{ "Prio",	"edp.esrp.prio", FT_UINT16, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_esrp_state,
		{ "State",	"edp.esrp.state", FT_UINT16, BASE_DEC, VALS(esrp_state_vals),
			0x0, "", HFILL }},

		{ &hf_edp_esrp_ports,
		{ "Ports",	"edp.esrp.ports", FT_UINT16, BASE_DEC, NULL,
			0x0, "Number of active ports", HFILL }},

		{ &hf_edp_esrp_virtip,
		{ "VirtIP",	"edp.esrp.virtip", FT_IPv4, BASE_NONE, NULL,
			0x0, "Virtual IP address", HFILL }},

		{ &hf_edp_esrp_sysmac,
		{ "Sys MAC",	"edp.esrp.sysmac", FT_ETHER, BASE_NONE, NULL,
			0x0, "System MAC address", HFILL }},

		{ &hf_edp_esrp_hello,
		{ "Hello",	"edp.esrp.hello", FT_UINT16, BASE_DEC, NULL,
			0x0, "Hello timer", HFILL }},

		{ &hf_edp_esrp_reserved,
		{ "Reserved",	"edp.esrp.reserved", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

	/* EAPS element */
		{ &hf_edp_eaps_ver,
		{ "Version",	"edp.eaps.ver", FT_UINT8, BASE_DEC, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_eaps_type,
		{ "Type",	"edp.eaps.type", FT_UINT8, BASE_DEC, VALS(eaps_type_vals),
			0x0, "", HFILL }},

		{ &hf_edp_eaps_ctrlvlanid,
		{ "Vlan ID",	"edp.eaps.vlanid", FT_UINT16, BASE_DEC, NULL,
			0x0, "Control Vlan ID", HFILL }},

		{ &hf_edp_eaps_reserved0,
		{ "Reserved0",	"edp.eaps.reserved0", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_eaps_sysmac,
		{ "Sys MAC",	"edp.eaps.sysmac", FT_ETHER, BASE_NONE, NULL,
			0x0, "System MAC address", HFILL }},

		{ &hf_edp_eaps_hello,
		{ "Hello",	"edp.eaps.hello", FT_UINT16, BASE_DEC, NULL,
			0x0, "Hello timer", HFILL }},

		{ &hf_edp_eaps_fail,
		{ "Fail",	"edp.eaps.fail", FT_UINT16, BASE_DEC, NULL,
			0x0, "Fail timer", HFILL }},

		{ &hf_edp_eaps_state,
		{ "State",	"edp.eaps.state", FT_UINT8, BASE_DEC, VALS(eaps_state_vals),
			0x0, "", HFILL }},

		{ &hf_edp_eaps_reserved1,
		{ "Reserved1",	"edp.eaps.reserved1", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

		{ &hf_edp_eaps_helloseq,
		{ "Helloseq",	"edp.eaps.helloseq", FT_UINT16, BASE_DEC, NULL,
			0x0, "Hello sequence", HFILL }},

		{ &hf_edp_eaps_reserved2,
		{ "Reserved2",	"edp.eaps.reserved2", FT_BYTES, BASE_NONE, NULL,
			0x0, "", HFILL }},

        };
	static gint *ett[] = {
		&ett_edp,
		&ett_edp_tlv,
	};

        proto_edp = proto_register_protocol(PROTO_LONG_NAME,
	    PROTO_SHORT_NAME, "edp");
        proto_register_field_array(proto_edp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_edp(void)
{
	dissector_handle_t edp_handle;

	edp_handle = create_dissector_handle(dissect_edp, proto_edp);
	dissector_add("llc.extreme_pid", 0x00bb, edp_handle);
}

void
proto_register_extreme_oui(void)
{
	static hf_register_info hf = {
	    &hf_llc_extreme_pid,
		{ "PID",	"llc.extreme_pid",  FT_UINT16, BASE_HEX,
		  VALS(extreme_pid_vals), 0x0, "", HFILL },
	};

	llc_add_oui(OUI_EXTREME, "llc.extreme_pid", "Extreme OUI PID", &hf);
}

