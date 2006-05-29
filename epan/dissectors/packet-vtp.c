/* packet-vtp.c
 * Routines for the disassembly of Cisco's Virtual Trunking Protocol
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

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>

/*
 * See
 *
 *	http://www.cisco.com/univercd/cc/td/doc/product/lan/trsrb/frames.htm
 *
 * for some information on VTP.
 *
 * It's incomplete, and it appears to be inaccurate in a number of places,
 * but it's all I could find....
 */

static int proto_vtp = -1;
static int hf_vtp_version = -1;
static int hf_vtp_code = -1;
static int hf_vtp_followers = -1;
static int hf_vtp_md_len = -1;
static int hf_vtp_md = -1;
static int hf_vtp_conf_rev_num = -1;
static int hf_vtp_upd_id = -1;
static int hf_vtp_upd_ts = -1;
static int hf_vtp_md5_digest = -1;
static int hf_vtp_seq_num = -1;
static int hf_vtp_start_value = -1;
static int hf_vtp_vlan_info_len = -1;
static int hf_vtp_vlan_status_vlan_susp = -1;
static int hf_vtp_vlan_type = -1;
static int hf_vtp_vlan_name_len = -1;
static int hf_vtp_isl_vlan_id = -1;
static int hf_vtp_mtu_size = -1;
static int hf_vtp_802_10_index = -1;
static int hf_vtp_vlan_name = -1;
static int hf_vtp_vlan_tlvtype = -1;
static int hf_vtp_vlan_tlvlength = -1;

static gint ett_vtp = -1;
static gint ett_vtp_vlan_info = -1;
static gint ett_vtp_vlan_status = -1;
static gint ett_vtp_tlv = -1;

static int
dissect_vlan_info(tvbuff_t *tvb, int offset, proto_tree *tree);
static void
dissect_vlan_info_tlv(tvbuff_t *tvb, int offset, int length,
    proto_tree *tree, proto_item *ti, guint8 type);

#define SUMMARY_ADVERT		0x01
#define SUBSET_ADVERT		0x02
#define ADVERT_REQUEST		0x03

static const value_string type_vals[] = {
	{ SUMMARY_ADVERT, "Summary-Advert" },
	{ SUBSET_ADVERT,  "Subset-Advert" },
	{ ADVERT_REQUEST, "Advert-Request" },
	{ 0,              NULL },
};

static void
dissect_vtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *vtp_tree = NULL;
	int offset = 0;
	guint8 code;
	guint8 md_len;
	const guint8 *upd_timestamp;
	int vlan_info_len;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "VTP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Virtual Trunking Protocol");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vtp, tvb, offset, -1,
		    FALSE);
		vtp_tree = proto_item_add_subtree(ti, ett_vtp);

		proto_tree_add_item(vtp_tree, hf_vtp_version, tvb, offset, 1,
		    FALSE);
		offset += 1;

		code = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint(vtp_tree, hf_vtp_code, tvb, offset, 1,
		    code);
		offset += 1;

		switch (code) {

		case SUMMARY_ADVERT:
			proto_tree_add_item(vtp_tree, hf_vtp_followers, tvb, offset,
			    1, FALSE);
			offset += 1;

			md_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint(vtp_tree, hf_vtp_md_len, tvb, offset,
			    1, md_len);
			offset += 1;

			proto_tree_add_item(vtp_tree, hf_vtp_md, tvb, offset,
			    32, FALSE);
			offset += 32;

			proto_tree_add_item(vtp_tree, hf_vtp_conf_rev_num, tvb,
			    offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(vtp_tree, hf_vtp_upd_id, tvb,
			    offset, 4, FALSE);
			offset += 4;

			upd_timestamp = tvb_get_ptr(tvb, offset, 12);
			proto_tree_add_string_format(vtp_tree, hf_vtp_upd_ts, tvb,
			    offset, 12, upd_timestamp,
			    "Update Timestamp: %.2s-%.2s-%.2s %.2s:%.2s:%.2s",
			    &upd_timestamp[0], &upd_timestamp[2], &upd_timestamp[4],
			    &upd_timestamp[6], &upd_timestamp[8], &upd_timestamp[10]);
			offset += 12;

			proto_tree_add_item(vtp_tree, hf_vtp_md5_digest, tvb,
			    offset, 16, FALSE);
			break;

		case SUBSET_ADVERT:
			proto_tree_add_item(vtp_tree, hf_vtp_seq_num, tvb, offset,
			    1, FALSE);
			offset += 1;

			md_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint(vtp_tree, hf_vtp_md_len, tvb, offset,
			    1, md_len);
			offset += 1;

			proto_tree_add_item(vtp_tree, hf_vtp_md, tvb, offset,
			    32, FALSE);
			offset += 32;

			proto_tree_add_item(vtp_tree, hf_vtp_conf_rev_num, tvb,
			    offset, 4, FALSE);
			offset += 4;

			while (tvb_reported_length_remaining(tvb, offset) > 0) {
				vlan_info_len =
				    dissect_vlan_info(tvb, offset, vtp_tree);
				if (vlan_info_len < 0)
					break;
				offset += vlan_info_len;
			}
			break;

		case ADVERT_REQUEST:
			offset += 1;	/* skip reserved field */

			md_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint(vtp_tree, hf_vtp_md_len, tvb, offset,
			    1, md_len);
			offset += 1;

			proto_tree_add_item(vtp_tree, hf_vtp_start_value, tvb,
			    offset, 2, FALSE);
			break;

		case 0x04:
			/*
			 * Mysterious type, seen a lot.
			 * Is this some mutant variant of Advert-Request?
			 */
			offset += 1;	/* skip unknown field */

			md_len = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint(vtp_tree, hf_vtp_md_len, tvb, offset,
			    1, md_len);
			offset += 1;

			proto_tree_add_item(vtp_tree, hf_vtp_md, tvb, offset,
			    32, FALSE);
			offset += 32;

			offset += 2;	/* skip unknown field */

			proto_tree_add_text(vtp_tree, tvb, offset, 2,
			    "VLAN ID of some sort: 0x%04x",
			    tvb_get_ntohs(tvb, offset));
			offset += 2;
			break;
		}
	}
}

#define	VLAN_SUSPENDED	0x01

static const value_string vlan_type_vals[] = {
	{ 0x01, "Ethernet" },
	{ 0x02, "FDDI" },
	{ 0x03, "TrCRF" },
	{ 0x04, "FDDI-net" },
	{ 0x05, "TrBRF" },
	{ 0,    NULL },
};

#define	SR_RING_NUM		0x01
#define	SR_BRIDGE_NUM		0x02
#define	STP_TYPE		0x03
#define	PARENT_VLAN		0x04
#define	TR_BRIDGED_VLANS	0x05
#define	PRUNING			0x06
#define	BRIDGE_TYPE		0x07
#define	MAX_ARE_HOP_CNT		0x08
#define	MAX_STE_HOP_CNT		0x09
#define	BACKUP_CRF_MODE		0x0A

static const value_string vlan_tlv_type_vals[] = {
	{ SR_RING_NUM,      "Source-Routing Ring Number" },
	{ SR_BRIDGE_NUM,    "Source-Routing Bridge Number" },
	{ STP_TYPE,         "Spanning-Tree Protocol Type" },
	{ PARENT_VLAN,      "Parent VLAN" },
	{ TR_BRIDGED_VLANS, "Translationally Bridged VLANs" },
	{ PRUNING,          "Pruning" },
	{ BRIDGE_TYPE,      "Bridge Type" },
	{ MAX_ARE_HOP_CNT,  "Max ARE Hop Count" },
	{ MAX_STE_HOP_CNT,  "Max STE Hop Count" },
	{ BACKUP_CRF_MODE,  "Backup CRF Mode" },
	{ 0,                NULL },
};

static int
dissect_vlan_info(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *vlan_info_tree;
	proto_tree *status_tree;
	guint8 vlan_info_len;
	int vlan_info_left;
	guint8 status;
	guint8 vlan_name_len;
	guint8 type;
	int length;
	proto_tree *tlv_tree;

	vlan_info_len = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_text(tree, tvb, offset, vlan_info_len,
	    "VLAN Information");
	vlan_info_tree = proto_item_add_subtree(ti, ett_vtp_vlan_info);
	vlan_info_left = vlan_info_len;

	proto_tree_add_uint(vlan_info_tree, hf_vtp_vlan_info_len, tvb, offset, 1,
	    vlan_info_len);
	offset += 1;
	vlan_info_left -= 1;

	if (vlan_info_left < 1)
		return -1;
	status = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_text(vlan_info_tree, tvb, offset, 1,
	    "Status: 0x%02x%s", status,
	    (status & VLAN_SUSPENDED) ? "(VLAN suspended)" : "");
	status_tree = proto_item_add_subtree(ti, ett_vtp_vlan_status);
	proto_tree_add_boolean(status_tree, hf_vtp_vlan_status_vlan_susp, tvb, offset, 1,
	    status);
	offset += 1;
	vlan_info_left -= 1;

	if (vlan_info_left < 1)
		return -1;
	proto_tree_add_item(vlan_info_tree, hf_vtp_vlan_type, tvb, offset, 1,
	    FALSE);
	offset += 1;
	vlan_info_left -= 1;

	if (vlan_info_left < 1)
		return -1;
	vlan_name_len = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(vlan_info_tree, hf_vtp_vlan_name_len, tvb, offset, 1,
	    vlan_name_len);
	offset += 1;
	vlan_info_left -= 1;

	if (vlan_info_left < 2)
		return -1;
	proto_tree_add_item(vlan_info_tree, hf_vtp_isl_vlan_id, tvb, offset, 2,
	    FALSE);
	offset += 2;
	vlan_info_left -= 2;

	if (vlan_info_left < 2)
		return -1;
	proto_tree_add_item(vlan_info_tree, hf_vtp_mtu_size, tvb, offset, 2,
	    FALSE);
	offset += 2;
	vlan_info_left -= 2;

	if (vlan_info_left < 4)
		return -1;
	proto_tree_add_item(vlan_info_tree, hf_vtp_802_10_index, tvb, offset, 4,
	    FALSE);
	offset += 4;
	vlan_info_left -= 4;

	/* VLAN name length appears to be rounded up to a multiple of 4. */
	vlan_name_len = 4*((vlan_name_len + 3)/4);
	if (vlan_info_left < vlan_name_len)
		return -1;
	proto_tree_add_item(vlan_info_tree, hf_vtp_vlan_name, tvb, offset,
	    vlan_name_len, FALSE);
	offset += vlan_name_len;
	vlan_info_left -= vlan_name_len;

	while (vlan_info_left > 0) {
		type = tvb_get_guint8(tvb, offset + 0);
		length = tvb_get_guint8(tvb, offset + 1);

		ti = proto_tree_add_text(vlan_info_tree, tvb, offset,
		    2 + length*2, "%s",
		    val_to_str(type, vlan_tlv_type_vals,
		      "Unknown TLV type: 0x%02x"));
		tlv_tree = proto_item_add_subtree(ti, ett_vtp_tlv);
		proto_tree_add_uint(tlv_tree, hf_vtp_vlan_tlvtype, tvb, offset,
		    1, type);
		proto_tree_add_uint(tlv_tree, hf_vtp_vlan_tlvlength, tvb, offset+1,
		    1, length);
		offset += 2;
		vlan_info_left -= 2;
		if (length > 0) {
			dissect_vlan_info_tlv(tvb, offset, length*2, tlv_tree,
			    ti, type);
		}
		offset += length*2;
		vlan_info_left -= length*2;
	}

	return vlan_info_len;
}

static const value_string stp_type_vals[] = {
	{ 1, "SRT" },
	{ 2, "SRB" },
	{ 3, "Auto" },
	{ 0, NULL },
};

static const value_string pruning_vals[] = {
	{ 1, "Enabled" },
	{ 2, "Disabled" },
	{ 0, NULL },
};

static const value_string bridge_type_vals[] = {
	{ 1, "SRT" },
	{ 2, "SRB" },
	{ 0, NULL },
};

static const value_string backup_crf_mode_vals[] = {
	{ 1, "TrCRF is configured as a backup" },
	{ 2, "TrCRF is not configured as a backup" },
	{ 0, NULL },
};

static void
dissect_vlan_info_tlv(tvbuff_t *tvb, int offset, int length,
    proto_tree *tree, proto_item *ti, guint8 type)
{
	switch (type) {

	case SR_RING_NUM:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Source-Routing Ring Number: 0x%04x",
			    tvb_get_ntohs(tvb, offset));
			proto_tree_add_text(tree, tvb, offset, 2,
			    "Source-Routing Ring Number: 0x%04x",
			    tvb_get_ntohs(tvb, offset));
		} else {
			proto_item_set_text(ti,
			    "Source-Routing Ring Number: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Source-Routing Ring Number: Bad length %u",
			    length);
		}
		break;

	case SR_BRIDGE_NUM:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Source-Routing Bridge Number: 0x%04x",
			    tvb_get_ntohs(tvb, offset));
			proto_tree_add_text(tree, tvb, offset, 2,
			    "Source-Routing Bridge Number: 0x%04x",
			    tvb_get_ntohs(tvb, offset));
		} else {
			proto_item_set_text(ti,
			    "Source-Routing Bridge Number: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Source-Routing Bridge Number: Bad length %u",
			    length);
		}
		break;

	case STP_TYPE:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Spanning-Tree Protocol Type: %s",
			    val_to_str(tvb_get_ntohs(tvb, offset), stp_type_vals,
			      "Unknown (0x%04x)"));
			proto_tree_add_text(tree, tvb, offset, 2,
			    "Spanning-Tree Protocol Type: %s",
			    val_to_str(tvb_get_ntohs(tvb, offset), stp_type_vals,
			      "Unknown (0x%04x)"));
		} else {
			proto_item_set_text(ti,
			    "Spanning-Tree Protocol Type: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Spanning-Tree Protocol Type: Bad length %u",
			    length);
		}
		break;

	case PARENT_VLAN:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Parent VLAN: 0x%04x",
			    tvb_get_ntohs(tvb, offset));
			proto_tree_add_text(tree, tvb, offset, 2,
			    "Parent VLAN: 0x%04x",
			    tvb_get_ntohs(tvb, offset));
		} else {
			proto_item_set_text(ti,
			    "Parent VLAN: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Parent VLAN: Bad length %u",
			    length);
		}
		break;

	case TR_BRIDGED_VLANS:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Translationally Bridged VLANs: 0x%04x",
			    tvb_get_ntohs(tvb, offset));
			proto_tree_add_text(tree, tvb, offset, 2,
			    "Translationally Bridged VLANs: 0x%04x",
			    tvb_get_ntohs(tvb, offset));
		} else {
			proto_item_set_text(ti,
			    "Translationally Bridged VLANs: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Translationally Bridged VLANs: Bad length %u",
			    length);
		}
		break;

	case PRUNING:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Pruning: %s",
			    val_to_str(tvb_get_ntohs(tvb, offset), pruning_vals,
			      "Unknown (0x%04x)"));
			proto_tree_add_text(tree, tvb, offset, 2,
			    "Pruning: %s",
			    val_to_str(tvb_get_ntohs(tvb, offset), pruning_vals,
			      "Unknown (0x%04x)"));
		} else {
			proto_item_set_text(ti,
			    "Pruning: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Pruning: Bad length %u",
			    length);
		}
		break;

	case BRIDGE_TYPE:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Bridge Type: %s",
			    val_to_str(tvb_get_ntohs(tvb, offset), bridge_type_vals,
			      "Unknown (0x%04x)"));
			proto_tree_add_text(tree, tvb, offset, 2,
			    "Bridge Type: %s",
			    val_to_str(tvb_get_ntohs(tvb, offset), bridge_type_vals,
			      "Unknown (0x%04x)"));
		} else {
			proto_item_set_text(ti,
			    "Bridge Type: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Bridge Type: Bad length %u",
			    length);
		}
		break;

	case MAX_ARE_HOP_CNT:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Max ARE Hop Count: %u",
			    tvb_get_ntohs(tvb, offset));
			proto_tree_add_text(tree, tvb, offset, 2,
			    "Max ARE Hop Count: %u",
			    tvb_get_ntohs(tvb, offset));
		} else {
			proto_item_set_text(ti,
			    "Max ARE Hop Count: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Max ARE Hop Count: Bad length %u",
			    length);
		}
		break;

	case MAX_STE_HOP_CNT:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Max STE Hop Count: %u",
			    tvb_get_ntohs(tvb, offset));
			proto_tree_add_text(tree, tvb, offset, 2,
			    "Max STE Hop Count: %u",
			    tvb_get_ntohs(tvb, offset));
		} else {
			proto_item_set_text(ti,
			    "Max STE Hop Count: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Max STE Hop Count: Bad length %u",
			    length);
		}
		break;

	case BACKUP_CRF_MODE:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Backup CRF Mode: %s",
			    val_to_str(tvb_get_ntohs(tvb, offset), backup_crf_mode_vals,
			      "Unknown (0x%04x)"));
			proto_tree_add_text(tree, tvb, offset, 2,
			    "Backup CRF Mode: %s",
			    val_to_str(tvb_get_ntohs(tvb, offset), backup_crf_mode_vals,
			      "Unknown (0x%04x)"));
		} else {
			proto_item_set_text(ti,
			    "Backup CRF Mode: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Backup CRF Mode: Bad length %u",
			    length);
		}
		break;

	default:
		proto_tree_add_text(tree, tvb, offset, length, "Data");
		break;
	}
}

void
proto_register_vtp(void)
{
	static hf_register_info hf[] = {
		{ &hf_vtp_version,
		{ "Version",	"vtp.version", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_vtp_code,
		{ "Code",	"vtp.code", FT_UINT8, BASE_HEX, VALS(type_vals), 0x0,
			"", HFILL }},

		{ &hf_vtp_followers,
		{ "Followers",	"vtp.followers", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of following Subset-Advert messages", HFILL }},

		{ &hf_vtp_md_len,
		{ "Management Domain Length", "vtp.md_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Length of management domain string", HFILL }},

		{ &hf_vtp_md,
		{ "Management Domain", "vtp.md", FT_STRING, BASE_DEC, NULL, 0,
			"Management domain", HFILL }},

		{ &hf_vtp_conf_rev_num,
		{ "Configuration Revision Number", "vtp.conf_rev_num", FT_UINT32, BASE_DEC, NULL, 0x0,
			"Revision number of the configuration information", HFILL }},

		{ &hf_vtp_upd_id,
		{ "Updater Identity", "vtp.upd_id", FT_IPv4, BASE_NONE, NULL, 0x0,
			"IP address of the updater", HFILL }},

		{ &hf_vtp_upd_ts,
		{ "Update Timestamp", "vtp.upd_ts", FT_STRING, BASE_DEC, NULL, 0,
			"Time stamp of the current configuration revision", HFILL }},

		{ &hf_vtp_md5_digest,
		{ "MD5 Digest",	"vtp.md5_digest", FT_BYTES, BASE_HEX, NULL, 0x0,
			"", HFILL }},

		{ &hf_vtp_seq_num,
		{ "Sequence Number",	"vtp.seq_num", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Order of this frame in the sequence of Subset-Advert frames", HFILL }},

		{ &hf_vtp_start_value,
		{ "Start Value",	"vtp.start_value", FT_UINT16, BASE_HEX, NULL, 0x0,
			"Virtual LAN ID of first VLAN for which information is requested", HFILL }},

		{ &hf_vtp_vlan_info_len,
		{ "VLAN Information Length",	"vtp.vlan_info.len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Length of the VLAN information field", HFILL }},

		{ &hf_vtp_vlan_status_vlan_susp,
		{ "VLAN suspended",	"vtp.vlan_info.status.vlan_susp", FT_BOOLEAN, 8, NULL, VLAN_SUSPENDED,
			"VLAN suspended", HFILL }},

		{ &hf_vtp_vlan_type,
		{ "VLAN Type",	"vtp.vlan_info.vlan_type", FT_UINT8, BASE_HEX, VALS(vlan_type_vals), 0x0,
			"Type of VLAN", HFILL }},

		{ &hf_vtp_vlan_name_len,
		{ "VLAN Name Length", "vtp.vlan_info.vlan_name_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Length of VLAN name string", HFILL }},

		{ &hf_vtp_isl_vlan_id,
		{ "ISL VLAN ID",	"vtp.vlan_info.isl_vlan_id", FT_UINT16, BASE_HEX, NULL, 0x0,
			"ID of this VLAN on ISL trunks", HFILL }},

		{ &hf_vtp_mtu_size,
		{ "MTU Size",	"vtp.vlan_info.mtu_size", FT_UINT16, BASE_DEC, NULL, 0x0,
			"MTU for this VLAN", HFILL }},

		{ &hf_vtp_802_10_index,
		{ "802.10 Index", "vtp.vlan_info.802_10_index", FT_UINT32, BASE_HEX, NULL, 0x0,
			"IEEE 802.10 security association identifier for this VLAN", HFILL }},

		{ &hf_vtp_vlan_name,
		{ "VLAN Name", "vtp.vlan_info.vlan_name", FT_STRING, BASE_DEC, NULL, 0,
			"VLAN name", HFILL }},

		{ &hf_vtp_vlan_tlvtype,
		{ "Type",	"vtp.vlan_info.tlv_type", FT_UINT8, BASE_HEX, VALS(vlan_tlv_type_vals), 0x0,
			"", HFILL }},

		{ &hf_vtp_vlan_tlvlength,
		{ "Length",	"vtp.vlan_info.tlv_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }},
        };
	static gint *ett[] = {
		&ett_vtp,
		&ett_vtp_vlan_info,
		&ett_vtp_vlan_status,
		&ett_vtp_tlv,
	};

        proto_vtp = proto_register_protocol("Virtual Trunking Protocol",
	    "VTP", "vtp");
        proto_register_field_array(proto_vtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vtp(void)
{
	dissector_handle_t vtp_handle;

	vtp_handle = create_dissector_handle(dissect_vtp, proto_vtp);
	dissector_add("llc.cisco_pid", 0x2003, vtp_handle);
}
