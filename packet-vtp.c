/* packet-vtp.c
 * Routines for the disassembly of Cisco's Virtual Trunking Protocol
 *
 * $Id: packet-vtp.c,v 1.6 2000/08/13 14:09:08 deniel Exp $
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
 
#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "packet.h"

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
dissect_vlan_info(const u_char *pd, int offset, proto_tree *tree);
static void
dissect_vlan_info_tlv(const u_char *pd, int offset, int length,
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
	
void 
dissect_vtp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	proto_item *ti; 
	proto_tree *vtp_tree = NULL;
	guint8 code;
	guint8 md_len;
	int vlan_info_len;
	guint32 upd_id;

	OLD_CHECK_DISPLAY_AS_DATA(proto_vtp, pd, offset, fd, tree);

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "VTP");
	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, "Virtual Trunking Protocol"); 

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vtp, NullTVB, offset, END_OF_FRAME,
		    FALSE);
		vtp_tree = proto_item_add_subtree(ti, ett_vtp);

		proto_tree_add_uint(vtp_tree, hf_vtp_version, NullTVB, offset, 1,
		    pd[offset]);
		offset += 1;

		code = pd[offset];
		proto_tree_add_uint(vtp_tree, hf_vtp_code, NullTVB, offset, 1,
		    code);
		offset += 1;
		
		switch (code) {

		case SUMMARY_ADVERT:
			proto_tree_add_uint(vtp_tree, hf_vtp_followers, NullTVB, offset,
			    1, pd[offset]);
			offset += 1;

			md_len = pd[offset];
			proto_tree_add_uint(vtp_tree, hf_vtp_md_len, NullTVB, offset,
			    1, md_len);
			offset += 1;

			proto_tree_add_string_format(vtp_tree, hf_vtp_md, NullTVB, offset,
			    32, &pd[offset], "Management Domain: %.32s",
			    &pd[offset]);
			offset += 32;

			proto_tree_add_uint(vtp_tree, hf_vtp_conf_rev_num, NullTVB,
			    offset, 4, pntohl(&pd[offset]));
			offset += 4;

			memcpy(&upd_id, &pd[offset], sizeof upd_id);
			proto_tree_add_ipv4(vtp_tree, hf_vtp_upd_id, NullTVB,
			    offset, 4, upd_id);
			offset += 4;

			proto_tree_add_string_format(vtp_tree, hf_vtp_upd_ts, NullTVB,
			    offset, 12, &pd[offset],
			    "Update Timestamp: %.2s-%.2s-%.2s %.2s:%.2s:%.2s",
			    &pd[offset], &pd[offset+2], &pd[offset+4],
			    &pd[offset+6], &pd[offset+8], &pd[offset+10]);
			offset += 12;

			proto_tree_add_bytes(vtp_tree, hf_vtp_md5_digest, NullTVB,
			    offset, 16, &pd[offset]);
			break;

		case SUBSET_ADVERT:
			proto_tree_add_uint(vtp_tree, hf_vtp_seq_num, NullTVB, offset,
			    1, pd[offset]);
			offset += 1;

			md_len = pd[offset];
			proto_tree_add_uint(vtp_tree, hf_vtp_md_len, NullTVB, offset,
			    1, md_len);
			offset += 1;

			proto_tree_add_string_format(vtp_tree, hf_vtp_md, NullTVB, offset,
			    32, &pd[offset], "Management Domain: %.32s",
			    &pd[offset]);
			offset += 32;

			proto_tree_add_uint(vtp_tree, hf_vtp_conf_rev_num, NullTVB,
			    offset, 4, pntohl(&pd[offset]));
			offset += 4;

			for (;;) {
				vlan_info_len = 
				    dissect_vlan_info(pd, offset, vtp_tree);
				if (vlan_info_len < 0)
					break;
				offset += vlan_info_len;
			}
			break;

		case ADVERT_REQUEST:
			offset += 1;	/* skip reserved field */

			md_len = pd[offset];
			proto_tree_add_uint(vtp_tree, hf_vtp_md_len, NullTVB, offset,
			    1, md_len);
			offset += 1;

			proto_tree_add_uint(vtp_tree, hf_vtp_start_value, NullTVB,
			    offset, 2, pntohs(&pd[offset]));
			break;

		case 0x04:
			/*
			 * Mysterious type, seen a lot.
			 * Is this some mutant variant of Advert-Request?
			 */
			offset += 1;	/* skip unknown field */

			md_len = pd[offset];
			proto_tree_add_uint(vtp_tree, hf_vtp_md_len, NullTVB, offset,
			    1, md_len);
			offset += 1;

			proto_tree_add_string_format(vtp_tree, hf_vtp_md, NullTVB, offset,
			    32, &pd[offset], "Management Domain: %.32s",
			    &pd[offset]);
			offset += 32;

			offset += 2;	/* skip unknown field */

			proto_tree_add_text(vtp_tree, NullTVB, offset, 2,
			    "VLAN ID of some sort: 0x%04x",
			    pntohs(&pd[offset]));
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
dissect_vlan_info(const u_char *pd, int offset, proto_tree *tree)
{
	proto_item *ti; 
	proto_tree *vlan_info_tree;
	proto_tree *status_tree;
	guint8 vlan_info_len;
	int vlan_info_left;
	guint8 status;
	guint8 vlan_name_len;
	guint16 type;
	int length;
	char *type_str;
	proto_tree *tlv_tree;

	if (!BYTES_ARE_IN_FRAME(offset, 1))
		return -1;
	vlan_info_len = pd[offset];
	ti = proto_tree_add_text(tree, NullTVB, offset, vlan_info_len,
	    "VLAN Information");
	vlan_info_tree = proto_item_add_subtree(ti, ett_vtp_vlan_info);
	vlan_info_left = vlan_info_len;

	proto_tree_add_uint(vlan_info_tree, hf_vtp_vlan_info_len, NullTVB, offset, 1,
	    vlan_info_len);
	offset += 1;
	vlan_info_left -= 1;

	if (!BYTES_ARE_IN_FRAME(offset, 1) || vlan_info_left < 1)
		return -1;
	status = pd[offset];
	ti = proto_tree_add_text(vlan_info_tree, NullTVB, offset, 1,
	    "Status: 0x%02x%s", status,
	    (status & VLAN_SUSPENDED) ? "(VLAN suspended)" : "");
	status_tree = proto_item_add_subtree(ti, ett_vtp_vlan_status);
	proto_tree_add_boolean(status_tree, hf_vtp_vlan_status_vlan_susp, NullTVB, offset, 1,
	    status);
	offset += 1;
	vlan_info_left -= 1;

	if (!BYTES_ARE_IN_FRAME(offset, 1) || vlan_info_left < 1)
		return -1;
	proto_tree_add_uint(vlan_info_tree, hf_vtp_vlan_type, NullTVB, offset, 1,
	    pd[offset]);
	offset += 1;
	vlan_info_left -= 1;

	if (!BYTES_ARE_IN_FRAME(offset, 1) || vlan_info_left < 1)
		return -1;
	vlan_name_len = pd[offset];
	proto_tree_add_uint(vlan_info_tree, hf_vtp_vlan_name_len, NullTVB, offset, 1,
	    vlan_name_len);
	offset += 1;
	vlan_info_left -= 1;

	if (!BYTES_ARE_IN_FRAME(offset, 2) || vlan_info_left < 2)
		return -1;
	proto_tree_add_uint(vlan_info_tree, hf_vtp_isl_vlan_id, NullTVB, offset, 2,
	    pntohs(&pd[offset]));
	offset += 2;
	vlan_info_left -= 2;

	if (!BYTES_ARE_IN_FRAME(offset, 2) || vlan_info_left < 2)
		return -1;
	proto_tree_add_uint(vlan_info_tree, hf_vtp_mtu_size, NullTVB, offset, 2,
	    pntohs(&pd[offset]));
	offset += 2;
	vlan_info_left -= 2;

	if (!BYTES_ARE_IN_FRAME(offset, 4) || vlan_info_left < 4)
		return -1;
	proto_tree_add_uint(vlan_info_tree, hf_vtp_802_10_index, NullTVB, offset, 4,
	    pntohl(&pd[offset]));
	offset += 4;
	vlan_info_left -= 4;

	/* VLAN name length appears to be rounded up to a multiple of
	   4. */
	vlan_name_len = 4*((vlan_name_len + 3)/4);
	if (!BYTES_ARE_IN_FRAME(offset, vlan_name_len)
	    || vlan_info_left < vlan_name_len)
		return -1;
	proto_tree_add_string_format(vlan_info_tree, hf_vtp_vlan_name, NullTVB, offset,
	    vlan_name_len, &pd[offset], "VLAN Name: %.*s", vlan_name_len,
	    &pd[offset]);
	offset += vlan_name_len;
	vlan_info_left -= vlan_name_len;

	while (IS_DATA_IN_FRAME(offset) && vlan_info_left > 0) {
		type = pd[offset + 0];
		length = pd[offset + 1];
		type_str = val_to_str(type, vlan_tlv_type_vals,
		    "Unknown (0x%04x)");

		ti = proto_tree_add_notext(vlan_info_tree, NullTVB, offset,
		    2 + length*2);
		tlv_tree = proto_item_add_subtree(ti, ett_vtp_tlv);
		proto_tree_add_uint(tlv_tree, hf_vtp_vlan_tlvtype, NullTVB, offset,
		    1, type);
		proto_tree_add_uint(tlv_tree, hf_vtp_vlan_tlvlength, NullTVB, offset+1,
		    1, length);
		offset += 2;
		vlan_info_left -= 2;
		if (length > 0) {
			dissect_vlan_info_tlv(pd, offset, length*2, tlv_tree,
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
dissect_vlan_info_tlv(const u_char *pd, int offset, int length,
    proto_tree *tree, proto_item *ti, guint8 type)
{
	switch (type) {

	case SR_RING_NUM:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Source-Routing Ring Number: 0x%04x",
			    pntohs(&pd[offset]));
			proto_tree_add_text(tree, NullTVB, offset, 2,
			    "Source-Routing Ring Number: 0x%04x",
			    pntohs(&pd[offset]));
		} else {
			proto_item_set_text(ti,
			    "Source-Routing Ring Number: Bad length %u",
			    length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Source-Routing Ring Number: Bad length %u",
			    length);
		}
		break;

	case SR_BRIDGE_NUM:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Source-Routing Bridge Number: 0x%04x",
			    pntohs(&pd[offset]));
			proto_tree_add_text(tree, NullTVB, offset, 2,
			    "Source-Routing Bridge Number: 0x%04x",
			    pntohs(&pd[offset]));
		} else {
			proto_item_set_text(ti,
			    "Source-Routing Bridge Number: Bad length %u",
			    length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Source-Routing Bridge Number: Bad length %u",
			    length);
		}
		break;

	case STP_TYPE:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Spanning-Tree Protocol Type: %s",
			    val_to_str(pntohs(&pd[offset]), stp_type_vals,
			      "Unknown (0x%04x)"));
			proto_tree_add_text(tree, NullTVB, offset, 2,
			    "Spanning-Tree Protocol Type: %s",
			    val_to_str(pntohs(&pd[offset]), stp_type_vals,
			      "Unknown (0x%04x)"));
		} else {
			proto_item_set_text(ti,
			    "Spanning-Tree Protocol Type: Bad length %u",
			    length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Spanning-Tree Protocol Type: Bad length %u",
			    length);
		}
		break;

	case PARENT_VLAN:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Parent VLAN: 0x%04x",
			    pntohs(&pd[offset]));
			proto_tree_add_text(tree, NullTVB, offset, 2,
			    "Parent VLAN: 0x%04x",
			    pntohs(&pd[offset]));
		} else {
			proto_item_set_text(ti,
			    "Parent VLAN: Bad length %u",
			    length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Parent VLAN: Bad length %u",
			    length);
		}
		break;

	case TR_BRIDGED_VLANS:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Translationally Bridged VLANs: 0x%04x",
			    pntohs(&pd[offset]));
			proto_tree_add_text(tree, NullTVB, offset, 2,
			    "Translationally Bridged VLANs: 0x%04x",
			    pntohs(&pd[offset]));
		} else {
			proto_item_set_text(ti,
			    "Translationally Bridged VLANs: Bad length %u",
			    length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Translationally Bridged VLANs: Bad length %u",
			    length);
		}
		break;

	case PRUNING:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Pruning: %s",
			    val_to_str(pntohs(&pd[offset]), pruning_vals,
			      "Unknown (0x%04x)"));
			proto_tree_add_text(tree, NullTVB, offset, 2,
			    "Pruning: %s",
			    val_to_str(pntohs(&pd[offset]), pruning_vals,
			      "Unknown (0x%04x)"));
		} else {
			proto_item_set_text(ti,
			    "Pruning: Bad length %u",
			    length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Pruning: Bad length %u",
			    length);
		}
		break;

	case BRIDGE_TYPE:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Bridge Type: %s",
			    val_to_str(pntohs(&pd[offset]), bridge_type_vals,
			      "Unknown (0x%04x)"));
			proto_tree_add_text(tree, NullTVB, offset, 2,
			    "Bridge Type: %s",
			    val_to_str(pntohs(&pd[offset]), bridge_type_vals,
			      "Unknown (0x%04x)"));
		} else {
			proto_item_set_text(ti,
			    "Bridge Type: Bad length %u",
			    length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Bridge Type: Bad length %u",
			    length);
		}
		break;

	case MAX_ARE_HOP_CNT:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Max ARE Hop Count: %u",
			    pntohs(&pd[offset]));
			proto_tree_add_text(tree, NullTVB, offset, 2,
			    "Max ARE Hop Count: %u",
			    pntohs(&pd[offset]));
		} else {
			proto_item_set_text(ti,
			    "Max ARE Hop Count: Bad length %u",
			    length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Max ARE Hop Count: Bad length %u",
			    length);
		}
		break;

	case MAX_STE_HOP_CNT:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Max STE Hop Count: %u",
			    pntohs(&pd[offset]));
			proto_tree_add_text(tree, NullTVB, offset, 2,
			    "Max STE Hop Count: %u",
			    pntohs(&pd[offset]));
		} else {
			proto_item_set_text(ti,
			    "Max STE Hop Count: Bad length %u",
			    length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Max STE Hop Count: Bad length %u",
			    length);
		}
		break;

	case BACKUP_CRF_MODE:
		if (length == 2) {
			proto_item_set_text(ti,
			    "Backup CRF Mode: %s",
			    val_to_str(pntohs(&pd[offset]), backup_crf_mode_vals,
			      "Unknown (0x%04x)"));
			proto_tree_add_text(tree, NullTVB, offset, 2,
			    "Backup CRF Mode: %s",
			    val_to_str(pntohs(&pd[offset]), backup_crf_mode_vals,
			      "Unknown (0x%04x)"));
		} else {
			proto_item_set_text(ti,
			    "Backup CRF Mode: Bad length %u",
			    length);
			proto_tree_add_text(tree, NullTVB, offset, length,
			    "Backup CRF Mode: Bad length %u",
			    length);
		}
		break;

	default:
		proto_item_set_text(ti, "Unknown TLV type: 0x%02x", type);
		proto_tree_add_text(tree, NullTVB, offset, length, "Data");
		break;
	}
}

void
proto_register_vtp(void)
{
	static hf_register_info hf[] = {
		{ &hf_vtp_version,
		{ "Version",	"vtp.version", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_vtp_code,
		{ "Code",	"vtp.code", FT_UINT8, BASE_HEX, VALS(type_vals), 0x0,
			"" }},

		{ &hf_vtp_followers,
		{ "Followers",	"vtp.followers", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Number of following Subset-Advert messages" }},

		{ &hf_vtp_md_len,
		{ "Management Domain Length", "vtp.md_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Length of management domain string" }},

		{ &hf_vtp_md,
		{ "Management Domain", "vtp.md", FT_STRING, BASE_DEC, NULL, 0,
			"Management domain" }},

		{ &hf_vtp_conf_rev_num,
		{ "Configuration Revision Number", "vtp.conf_rev_num", FT_UINT32, BASE_DEC, NULL, 0x0,
			"Revision number of the configuration information" }},

		{ &hf_vtp_upd_id,
		{ "Updater Identity", "vtp.upd_id", FT_IPv4, BASE_NONE, NULL, 0x0,
			"IP address of the updater" }},

		{ &hf_vtp_upd_ts,
		{ "Update Timestamp", "vtp.upd_ts", FT_STRING, BASE_DEC, NULL, 0,
			"Time stamp of the current configuration revision" }},

		{ &hf_vtp_md5_digest,
		{ "MD5 Digest",	"vtp.md5_digest", FT_BYTES, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_vtp_seq_num,
		{ "Sequence Number",	"vtp.seq_num", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Order of this frame in the sequence of Subset-Advert frames" }},

		{ &hf_vtp_start_value,
		{ "Start Value",	"vtp.start_value", FT_UINT16, BASE_HEX, NULL, 0x0,
			"Virtual LAN ID of first VLAN for which information is requested" }},

		{ &hf_vtp_vlan_info_len,
		{ "VLAN Information Length",	"vtp.vlan_info.len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Length of the VLAN information field" }},

		{ &hf_vtp_vlan_status_vlan_susp,
		{ "VLAN suspended",	"vtp.vlan_info.status.vlan_susp", FT_BOOLEAN, 8, NULL, VLAN_SUSPENDED,
			"VLAN suspended" }},

		{ &hf_vtp_vlan_type,
		{ "VLAN Type",	"vtp.vlan_info.vlan_type", FT_UINT8, BASE_HEX, VALS(vlan_type_vals), 0x0,
			"Type of VLAN" }},

		{ &hf_vtp_vlan_name_len,
		{ "VLAN Name Length", "vtp.vlan_info.vlan_name_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"Length of VLAN name string" }},

		{ &hf_vtp_isl_vlan_id,
		{ "ISL VLAN ID",	"vtp.vlan_info.isl_vlan_id", FT_UINT16, BASE_HEX, NULL, 0x0,
			"ID of this VLAN on ISL trunks" }},

		{ &hf_vtp_mtu_size,
		{ "MTU Size",	"vtp.vlan_info.mtu_size", FT_UINT16, BASE_DEC, NULL, 0x0,
			"MTU for this VLAN" }},

		{ &hf_vtp_802_10_index,
		{ "802.10 Index", "vtp.vlan_info.802_10_index", FT_UINT32, BASE_HEX, NULL, 0x0,
			"IEEE 802.10 security association identifier for this VLAN" }},

		{ &hf_vtp_vlan_name,
		{ "VLAN Name", "vtp.vlan_info.vlan_name", FT_STRING, BASE_DEC, NULL, 0,
			"VLAN name" }},

		{ &hf_vtp_vlan_tlvtype,
		{ "Type",	"vtp.vlan_info.tlv_type", FT_UINT8, BASE_HEX, VALS(vlan_tlv_type_vals), 0x0,
			"" }},

		{ &hf_vtp_vlan_tlvlength,
		{ "Length",	"vtp.vlan_info.tlv_len", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},
        };
	static gint *ett[] = {
		&ett_vtp,
		&ett_vtp_vlan_info,
		&ett_vtp_vlan_status,
		&ett_vtp_tlv,
	};

        proto_vtp = proto_register_protocol("Virtual Trunking Protocol", "vtp");
        proto_register_field_array(proto_vtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
