/* packet-dtp.c
 * Routines for the disassembly for Cisco Dynamic Trunking Protocol
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * DTP support added by Charlie Lenahan <clenahan@fortresstech.com>
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
 *
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>

/*
 * It's incomplete, and it appears to be inaccurate in a number of places,
 * but it's all I could find....
 */

static int proto_dtp = -1;
static int hf_dtp_version = -1;
static int hf_dtp_tlvtype = -1;
static int hf_dtp_tlvlength = -1;
static int hf_dtp_some_mac = -1;


static gint ett_dtp = -1;
static gint ett_dtp_tlv = -1;

static void dissect_dtp_tlv(tvbuff_t *tvb, int offset, int length, proto_tree *tree, proto_item *ti, guint8 type);


#define	TYPE_DOMAIN		0x01
#define	TYPE_STATUS		0x02
#define	TYPE_DTPTYPE		0x03
#define	TYPE_NEIGHBOR		0x04


static const value_string dtp_tlv_type_vals[] = {
	{ TYPE_DOMAIN,		"Domain" },
	{ TYPE_STATUS,		"Status" },
	{ TYPE_DTPTYPE,		"Type" },
	{ TYPE_NEIGHBOR, 	"Neighbor" },

	{ 0,			NULL }
};


static void
dissect_dtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *dtp_tree = NULL;
	proto_tree *tlv_tree=NULL;
	int offset = 0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DTP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Dynamic Trunking Protocol");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_dtp, tvb, offset, -1, FALSE);
		dtp_tree = proto_item_add_subtree(ti, ett_dtp);
	}

        /* We assume version */
	proto_tree_add_item(dtp_tree, hf_dtp_version, tvb, offset, 1, FALSE);
	offset += 1;

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		int type, length, valuelength;

		type = tvb_get_ntohs(tvb, offset);
		length = tvb_get_ntohs(tvb, offset + 2);
		valuelength = (length-4);
    
		/* make sure still in valid tlv  */
		if ((valuelength < 1) || ( length > tvb_length_remaining(tvb, offset) ))
			break;

		ti = proto_tree_add_text(dtp_tree, tvb, offset, length, "%s", 
                    val_to_str(type, dtp_tlv_type_vals, "Unknown TLV type: 0x%02x"));

		tlv_tree = proto_item_add_subtree(ti, ett_dtp_tlv);
		proto_tree_add_uint(tlv_tree, hf_dtp_tlvtype, tvb, offset, 2, type);
		offset+=2;

		proto_tree_add_uint(tlv_tree, hf_dtp_tlvlength, tvb, offset, 2, length);
		offset+=2;


		if (valuelength > 0) {
			dissect_dtp_tlv(tvb, offset, valuelength, tlv_tree, ti, (guint8) type);
		}

		offset += valuelength;
        }
}

static void
dissect_dtp_tlv(tvbuff_t *tvb, int offset, int length,
    proto_tree *tree, proto_item *ti, guint8 type)
{
	switch (type) {

	case TYPE_DOMAIN:
		if (length > 0) {
			proto_item_set_text(ti, "Domain: %s", tvb_format_text(tvb, offset, length - 1));
			proto_tree_add_text(tree, tvb, offset, length, "Domain: %s", tvb_format_text(tvb, offset, length - 1));
		} else {
			proto_item_set_text(ti, "Domain: Bad length %u", length);
			proto_tree_add_text(tree, tvb, offset, length, "Domain: Bad length %u", length);
		}
		break;

	case TYPE_STATUS:
		if (length > 0) {
			proto_item_set_text(ti,
			    "Status: 0x%02x",
			    tvb_get_guint8(tvb, offset));
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Status: 0x%02x",
			    tvb_get_guint8(tvb, offset));
		} else {
			proto_item_set_text(ti,
			    "Status: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Status: Bad length %u",
			    length);
		}
		break;

	case TYPE_DTPTYPE:
		if (length > 0) {
			proto_item_set_text(ti,
			    "Dtptype: 0x%02x",
			    tvb_get_guint8(tvb, offset));
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Dtptype: 0x%02x",
			    tvb_get_guint8(tvb, offset));
		} else {
			proto_item_set_text(ti,
			    "Dtptype: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Dtptype: Bad length %u",
			    length);
		}
		break;


	case TYPE_NEIGHBOR:
		if (length == 6) {
	                const guint8 *macptr=tvb_get_ptr(tvb,offset,length);

			proto_item_set_text(ti, "Neighbor: %s",
				ether_to_str(macptr));	/* XXX - resolve? */
            		proto_tree_add_ether(tree, hf_dtp_some_mac, tvb, offset,length,macptr);
		} else {
			proto_item_set_text(ti,
			    "Neighbor: Bad length %u",
			    length);
			proto_tree_add_text(tree, tvb, offset, length,
			    "Neighbor: Bad length %u",
			    length);
		}
		break;

	default:
		proto_tree_add_text(tree, tvb, offset, length, "Data");
		break;
	}
}

void
proto_register_dtp(void)
{
	static hf_register_info hf[] = {
	{ &hf_dtp_version,
		{ "Version",	"dtp.version", FT_UINT8, BASE_HEX, 
		NULL, 0x0, "", HFILL }},

	{ &hf_dtp_tlvtype,
		{ "Type",	"dtp.tlv_type", FT_UINT16, BASE_HEX, 
		VALS(dtp_tlv_type_vals), 0x0, "", HFILL }},

	{ &hf_dtp_tlvlength,
		{ "Length",	"dtp.tlv_len", FT_UINT16, BASE_DEC, 
		NULL, 0x0, "", HFILL }},

	{ &hf_dtp_some_mac,
		{ "Neighbor", "vtp.neighbor", FT_ETHER, BASE_NONE, 
		NULL, 0x0, "MAC Address of neighbor", HFILL }},

        };

	static gint *ett[] = {
		&ett_dtp,
		&ett_dtp_tlv,
	};

	proto_dtp = proto_register_protocol("Dynamic Trunking Protocol", "DTP", "dtp");
	proto_register_field_array(proto_dtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dtp(void)
{
	dissector_handle_t dtp_handle;

	dtp_handle = create_dissector_handle(dissect_dtp, proto_dtp);
	dissector_add("llc.cisco_pid", 0x2004, dtp_handle);
}
