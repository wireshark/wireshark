/* packet-ecp-oui.c
 * ECP/VDP dissector for wireshark (according to IEEE 802.1Qbg draft 0)
 * By Jens Osterkamp <jens at linux.vnet.ibm.com>
 *    Mijo Safradin <mijo at linux.vnet.ibm.com>
 * Copyright 2011,2012  IBM Corp.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/oui.h>
#include <epan/addr_resolv.h>

#include "packet-ieee802a.h"
#include "oui.h"

void proto_register_ecp_oui(void);
void proto_reg_handoff_ecp(void);

#define ECP_SUBTYPE		0x00

#define END_OF_VDPDU_TLV_TYPE	0x00	/* Mandatory */
#define VDP_TLV_TYPE		0x02
#define ORG_SPECIFIC_TLV_TYPE	0x7F

/* IEEE 802.1Qbg VDP filter info formats */
#define VDP_FIF_VID		0x01
#define VDP_FIF_MACVID		0x02
#define VDP_FIF_GROUPVID	0x03
#define VDP_FIF_GROUPVMACVID	0x04

/* Masks */
#define TLV_TYPE_MASK		0xFE00
#define TLV_TYPE(value)		(((value) & TLV_TYPE_MASK) >> 9)
#define TLV_INFO_LEN_MASK	0x01FF
#define TLV_INFO_LEN(value)	((value) & TLV_INFO_LEN_MASK)

static gint proto_ecp = -1;
static gint hf_ecp_pid = -1;
static gint hf_ecp_tlv_type = -1;
static gint hf_ecp_tlv_len = -1;
static gint hf_ecp_subtype = -1;
static gint hf_ecp_mode = -1;
static gint hf_ecp_sequence = -1;
/* static gint hf_ecp_vdp_oui = -1; */
static gint hf_ecp_vdp_mode = -1;
static gint hf_ecp_vdp_response = -1;
static gint hf_ecp_vdp_mgrid = -1;
static gint hf_ecp_vdp_vsitypeid = -1;
static gint hf_ecp_vdp_vsitypeidversion = -1;
static gint hf_ecp_vdp_instanceid = -1;
static gint hf_ecp_vdp_format = -1;
static gint hf_ecp_vdp_mac = -1;
static gint hf_ecp_vdp_vlan = -1;

static gint ett_ecp = -1;
static gint ett_end_of_vdpdu = -1;
static gint ett_802_1qbg_capabilities_flags = -1;

static const value_string ecp_pid_vals[] = {
	{ 0x0000,	"ECP draft 0" },
	{ 0,		NULL }
};

/* IEEE 802.1Qbg  ECP subtypes */
static const value_string ecp_subtypes[] = {
	{ 0x00,	"ECP default subtype" },
	{ 0, NULL }
};

/* IEEE 802.1Qbg ECP modes */
static const value_string ecp_modes[] = {
	{ 0x00,	"REQUEST" },
	{ 0x01,	"ACK" },
	{ 0, NULL }
};

/* IEEE 802.1Qbg VDP modes */
static const value_string ecp_vdp_modes[] = {
	{ 0x00,	"Pre-Associate" },
	{ 0x01,	"Pre-Associate with resource reservation" },
	{ 0x02,	"Associate" },
	{ 0x03,	"De-Associate" },
	{ 0, NULL }
};

/* IEEE 802.1Qbg VDP responses */
static const value_string ecp_vdp_responses[] = {
	{ 0x00, "success" },
	{ 0x01, "invalid format" },
	{ 0x02, "insufficient resources" },
	{ 0x03, "unused VTID" },
	{ 0x04, "VTID violation" },
	{ 0x05, "VTID version violation" },
	{ 0x06, "out of sync" },
	{ 0, NULL }
};

/* IEEE 802.1Qbg VDP filter info formats */
static const value_string ecp_vdp_formats[] = {
	{ VDP_FIF_VID, "VID values" },
	{ VDP_FIF_MACVID, "MAC/VID pairs" },
	{ VDP_FIF_GROUPVID, "GROUPID/VID pairs" },
	{ VDP_FIF_GROUPVMACVID, "GROUPID/MAC/VID triples" },
	{ 0, NULL }
};

/* IEEE 802.1Qbg Subtypes */
static const value_string ieee_802_1qbg_subtypes[] = {
	{ 0x00,	"EVB" },
	{ 0x01,	"CDCP" },
	{ 0x02,	"VDP" },
	{ 0, NULL }
};

/* Dissect Unknown TLV */
static gint32
dissect_ecp_unknown_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint16 tempLen;
	guint16 tempShort;

	proto_tree *ecp_unknown_tlv_tree = NULL;
	proto_item *ti = NULL;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	tempLen = TLV_INFO_LEN(tempShort);

	if (tree)
	{
		ti = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "Unknown TLV");
		ecp_unknown_tlv_tree = proto_item_add_subtree(ti, ett_ecp);
	}

	proto_tree_add_item(ecp_unknown_tlv_tree, hf_ecp_subtype, tvb, offset, 2, ENC_BIG_ENDIAN);

	return -1;
}

/* Dissect mac/vid pairs in VDP TLVs */
static gint32
dissect_vdp_fi_macvid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	gint i;
	guint16 entries;
	guint32 tempOffset = offset;
	const guint8 *mac_addr = NULL;

	proto_tree *ecp_vdp_tlv_fi_subtree = NULL;
	proto_item *ti = NULL;

	entries = tvb_get_ntohs(tvb, offset);

	if (tree)
	{
		ti = proto_tree_add_text(tree, tvb, tempOffset, 2, "%i MAC/VID pair%s",
		    entries, plurality((entries > 1), "s", ""));
		ecp_vdp_tlv_fi_subtree = proto_item_add_subtree(ti, ett_ecp);
	}

	tempOffset += 2;

	for (i=0; i < entries; i++) {
		mac_addr = tvb_get_ptr(tvb, tempOffset, 6);

		if (tree) {
			proto_tree_add_ether(ecp_vdp_tlv_fi_subtree, hf_ecp_vdp_mac, tvb, tempOffset, 6, mac_addr);
		}

		tempOffset += 6;

		proto_tree_add_item(ecp_vdp_tlv_fi_subtree, hf_ecp_vdp_vlan, tvb, tempOffset, 2, ENC_BIG_ENDIAN);

		tempOffset += 2;
	}

	return tempOffset-offset;
}

/* Dissect Organizationally Defined TLVs */
static gint32
dissect_vdp_org_specific_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint16 tempLen;
	guint16 len;
	guint16 tempShort;
	guint32 tempOffset = offset;
	guint32 oui;
	const char *ouiStr;
	guint8 subType, format;
	const char *subTypeStr;

	proto_tree	*ecp_vdp_tlv_subtree = NULL;
	proto_item	*ti = NULL;

	tempLen = 0;
	tempShort = tvb_get_ntohs(tvb, offset);
	len = TLV_INFO_LEN(tempShort);

	tempOffset += 2;

	oui = tvb_get_ntoh24(tvb, (tempOffset));
	/* maintain previous OUI names.  If not included, look in manuf database for OUI */
	ouiStr = val_to_str_const(oui, oui_vals, "Unknown");
	if (strcmp(ouiStr, "Unknown")==0) {
		ouiStr = uint_get_manuf_name_if_known(oui);
		if(ouiStr==NULL) ouiStr="Unknown";
	}

	tempOffset += 3;

	subType = tvb_get_guint8(tvb, tempOffset);

	switch(oui) {
	case OUI_IEEE_802_1QBG:
		subTypeStr = val_to_str(subType, ieee_802_1qbg_subtypes, "Unknown subtype 0x%x");
		break;
	default:
		subTypeStr = "Unknown";
		break;
	}

	if (tree) {
		ti = proto_tree_add_text(tree, tvb, offset, (len + 2), "%s - %s",
		    ouiStr, subTypeStr);
		ecp_vdp_tlv_subtree = proto_item_add_subtree(ti, ett_ecp);
	}

	tempOffset++;

	proto_tree_add_item(ecp_vdp_tlv_subtree, hf_ecp_vdp_mode, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
	tempOffset++;

	proto_tree_add_item(ecp_vdp_tlv_subtree, hf_ecp_vdp_response, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
	tempOffset++;

	proto_tree_add_item(ecp_vdp_tlv_subtree, hf_ecp_vdp_mgrid, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
	tempOffset++;

	proto_tree_add_item(ecp_vdp_tlv_subtree, hf_ecp_vdp_vsitypeid, tvb, tempOffset, 3, ENC_BIG_ENDIAN);
	tempOffset += 3;

	proto_tree_add_item(ecp_vdp_tlv_subtree, hf_ecp_vdp_vsitypeidversion, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
	tempOffset += 1;

	proto_tree_add_item(ecp_vdp_tlv_subtree, hf_ecp_vdp_instanceid, tvb, tempOffset, 16, ENC_NA);
	tempOffset += 16;

	format = tvb_get_guint8(tvb, tempOffset);
	proto_tree_add_item(ecp_vdp_tlv_subtree, hf_ecp_vdp_format, tvb, tempOffset, 1, ENC_BIG_ENDIAN);
	tempOffset++;

	switch (format) {
	case VDP_FIF_VID:
		/* place holder for future enablement */
		/* For compatibility of different implementations proceed to next entry */
	case VDP_FIF_MACVID:
		tempLen = dissect_vdp_fi_macvid(tvb, pinfo, ecp_vdp_tlv_subtree, tempOffset);
		break;
	case VDP_FIF_GROUPVID:
		/* place holder for future enablement */
		break;
	case VDP_FIF_GROUPVMACVID:
		/* place holder for future enablement */
		break;
	default:
		break;
	}

	tempOffset += tempLen;

	return tempOffset-offset;
}

/* Dissect End of VDP TLV (Mandatory) */
gint32
dissect_vdp_end_of_vdpdu_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint32 offset)
{
	guint16 tempLen;
	guint16 tempShort;

	proto_tree	*end_of_vdpdu_tree = NULL;
	proto_item	*tf = NULL;

	/* Get tlv type and length */
	tempShort = tvb_get_ntohs(tvb, offset);

	/* Get tlv length */
	tempLen = TLV_INFO_LEN(tempShort);

	if (tree)
	{
		/* Set port tree */
		tf = proto_tree_add_text(tree, tvb, offset, (tempLen + 2), "End of VDPDU");
		end_of_vdpdu_tree = proto_item_add_subtree(tf, ett_end_of_vdpdu);

		proto_tree_add_item(end_of_vdpdu_tree, hf_ecp_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(end_of_vdpdu_tree, hf_ecp_tlv_len, tvb, offset, 2, ENC_BIG_ENDIAN);
	}

	return -1;	/* Force the VDP dissector to terminate */
}

static void
dissect_ecp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *ecp_tree = NULL;
	proto_item *ti = NULL;
	gint32 tempLen = 0;
	guint32 offset = 0;
	guint16 tempShort;
	guint8 tempType;
	gboolean end = FALSE;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ECP");

	if (tree) {
	    ti = proto_tree_add_item(tree, proto_ecp, tvb, 0, -1, ENC_NA);
		ecp_tree = proto_item_add_subtree(ti, ett_ecp);
	}

	proto_tree_add_item(ecp_tree, hf_ecp_subtype, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ecp_tree, hf_ecp_mode, tvb, offset+1, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(ecp_tree, hf_ecp_sequence, tvb, offset+2, 2, ENC_BIG_ENDIAN);

	offset += 4;

	while (!end) {
		if (!tvb_bytes_exist(tvb, offset, 1))
			break;

		tempShort = tvb_get_ntohs(tvb, offset);
		tempType = TLV_TYPE(tempShort);

		switch (tempType) {
		case ORG_SPECIFIC_TLV_TYPE:
			tempLen = dissect_vdp_org_specific_tlv(tvb, pinfo, ecp_tree, offset);
			break;
		case END_OF_VDPDU_TLV_TYPE:
			tempLen = dissect_vdp_end_of_vdpdu_tlv(tvb, pinfo, ecp_tree, offset);
			break;
		default:
			tempLen = dissect_ecp_unknown_tlv(tvb, pinfo, ecp_tree, offset);
			break;
		}

		offset += tempLen;

		if (tempLen < 0)
			end = TRUE;
	}

}

void proto_register_ecp_oui(void)
{
	static hf_register_info hf_reg = {
		&hf_ecp_pid,
		{ "PID", "ieee802a.ecp_pid", FT_UINT16, BASE_HEX,
			VALS(ecp_pid_vals), 0x0, NULL, HFILL },
	};

	static hf_register_info hf[] = {
		{ &hf_ecp_tlv_type,
			{ "TLV Type", "ecp.tlv.type", FT_UINT16, BASE_DEC,
			NULL, TLV_TYPE_MASK, NULL, HFILL }
		},
		{ &hf_ecp_tlv_len,
			{ "TLV Length", "ecp.tlv.len", FT_UINT16, BASE_DEC,
			NULL, TLV_INFO_LEN_MASK, NULL, HFILL }
		},

		{ &hf_ecp_subtype,
			{ "subtype", "ecp.subtype", FT_UINT8, BASE_HEX,
				VALS(ecp_subtypes), 0x0, NULL, HFILL },
		},
		{ &hf_ecp_mode,
			{ "mode", "ecp.mode", FT_UINT8, BASE_HEX,
				VALS(ecp_modes), 0x0, NULL, HFILL },
		},
		{ &hf_ecp_sequence,
			{ "sequence number", "ecp.seq", FT_UINT16, BASE_HEX,
				NULL, 0x0, NULL, HFILL },
		},
#if 0
		{ &hf_ecp_vdp_oui,
			{ "Organization Unique Code",	"ecp.vdp.oui", FT_UINT24, BASE_HEX,
			VALS(oui_vals), 0x0, NULL, HFILL }
		},
#endif
		{ &hf_ecp_vdp_mode,
			{ "mode", "ecp.vdp.mode", FT_UINT8, BASE_HEX,
				VALS(ecp_vdp_modes), 0x0, NULL, HFILL },
		},
		{ &hf_ecp_vdp_response,
			{ "response", "ecp.vdp.response", FT_UINT8, BASE_HEX,
				VALS(ecp_vdp_responses), 0x0, NULL, HFILL },
		},
		{ &hf_ecp_vdp_mgrid,
			{ "Manager ID", "ecp.vdp.mgrid", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL },
		},
		{ &hf_ecp_vdp_vsitypeid,
			{ "VSI type ID", "ecp.vdp.vsitypeid", FT_UINT24, BASE_HEX,
				NULL, 0x0, NULL, HFILL },
		},
		{ &hf_ecp_vdp_vsitypeidversion,
			{ "VSI type ID version", "ecp.vdp.vsitypeidversion", FT_UINT8, BASE_HEX,
				NULL, 0x0, NULL, HFILL },
		},
		{ &hf_ecp_vdp_instanceid,
			{ "VSI Instance ID version", "ecp.vdp.instanceid", FT_BYTES, BASE_NONE,
				NULL, 0x0, NULL, HFILL },
		},
		{ &hf_ecp_vdp_format,
			{ "VSI filter info format", "ecp.vdp.format", FT_UINT8, BASE_HEX,
				VALS(ecp_vdp_formats), 0x0, NULL, HFILL },
		},
		{ &hf_ecp_vdp_mac,
			{ "VSI Mac Address", "ecp.vdp.mac", FT_ETHER, BASE_NONE,
				NULL, 0x0, NULL, HFILL }
		},
		{ &hf_ecp_vdp_vlan,
			{ "VSI VLAN ID", "ecp.vdp.vlan", FT_UINT16, BASE_DEC,
				NULL, 0x0, NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_ecp,
		&ett_end_of_vdpdu,
		&ett_802_1qbg_capabilities_flags,
	};

	ieee802a_add_oui(OUI_IEEE_802_1QBG, "ieee802a.ecp_pid",
		"IEEE802a ECP PID", &hf_reg);

	proto_ecp = proto_register_protocol("ECP Protocol", "ECP", "ecp");
	proto_register_field_array(proto_ecp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("ecp", dissect_ecp, proto_ecp);
}

void proto_reg_handoff_ecp(void)
{
	static dissector_handle_t ecp_handle;

	ecp_handle = find_dissector("ecp");
	dissector_add_uint("ieee802a.ecp_pid", 0x0000, ecp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
