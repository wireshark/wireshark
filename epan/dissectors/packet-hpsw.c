/* packet-hpsw.c
 * Routines for HP Switch Config protocol
 * Charlie Lenahan <clenahan@fortresstech.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>

#include "packet-hpext.h"

static void dissect_hpsw_tlv(tvbuff_t *tvb, int offset, int length,
     proto_tree *tree, proto_item *ti, guint8 type);

static int proto_hpsw = -1;

static int hf_hpsw_version = -1;
static int hf_hpsw_type = -1;
static int hf_hpsw_tlvtype = -1;
static int hf_hpsw_tlvlength = -1;


static gint ett_hpsw = -1;
static gint ett_hpsw_tlv = -1;



#define HPFOO_DEVICE_NAME   0x1
#define HPFOO_DEVICE_VERSION 0x2
#define HPFOO_CONFIG_NAME 0x3
#define HPFOO_IP_ADDR 0x5
#define HPFOO_FIELD_7 0x7
#define HPFOO_FIELD_8 0x8
#define HPFOO_FIELD_9 0x9
#define HPFOO_FIELD_10 0xa
#define HPFOO_FIELD_12 0xc
#define HPFOO_DEVICE_ID 0xd /* Interpretation of this field is an educated guess */
#define HPFOO_MAC_ADDR 0xe

static const value_string hpsw_tlv_type_vals[] = {
	{ HPFOO_DEVICE_NAME,       "Device Name" },
	{ HPFOO_DEVICE_VERSION,     "Version" },
	{ HPFOO_CONFIG_NAME,     "Config" },
	{ HPFOO_IP_ADDR,     "IP Addr" },
	{ HPFOO_FIELD_7,     "Field 7" },
	{ HPFOO_FIELD_8,     "Field 8" },
	{ HPFOO_FIELD_9,     "Field 9" },
	{ HPFOO_FIELD_10,     "Field 10" },
	{ HPFOO_FIELD_12,     "Field 12" },
	{ HPFOO_DEVICE_ID,    "Device ID" },
	{ HPFOO_MAC_ADDR,     "MAC Addr" },
	{ 0x00,               NULL }
};


static void
dissect_hpsw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*hp_tree = NULL;
	proto_tree	*tlv_tree = NULL;
	proto_item	*ti = NULL;
	guint8		version;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "HP");

	col_set_str(pinfo->cinfo, COL_INFO, "HP Switch Protocol");

	version = tvb_get_guint8(tvb, 0);

	if (tree) {
		guint16 offset =0;

		ti = proto_tree_add_item(tree, proto_hpsw, tvb, 0, -1, ENC_NA);
		hp_tree = proto_item_add_subtree(ti, ett_hpsw);
		proto_tree_add_uint(hp_tree, hf_hpsw_version, tvb, 0, 1, version);
		offset++;

		proto_tree_add_item(hp_tree, hf_hpsw_type, tvb, 1, 1, ENC_BIG_ENDIAN);
		offset++;

		while ( tvb_reported_length_remaining(tvb, offset) > 0 )
		{
			guint8 type,length;

			type = tvb_get_guint8(tvb, offset);
			length = tvb_get_guint8(tvb, offset+1);

			/* make sure still in valid tlv */
			if (( length < 1 ) || ( length > tvb_length_remaining(tvb,offset+2)))
				break;

			ti = proto_tree_add_text(hp_tree,tvb,offset,length+2,"%s",
						val_to_str(type,hpsw_tlv_type_vals,"Unknown TLV type: 0x%02x"));

			tlv_tree=proto_item_add_subtree(ti,ett_hpsw_tlv);

			/* type */
			proto_tree_add_uint(tlv_tree, hf_hpsw_tlvtype, tvb, offset, 1, type);
			offset++;

			/* LENGTH (not inclusive of type and length bytes) */
			proto_tree_add_uint(tlv_tree, hf_hpsw_tlvlength, tvb, offset, 1, length);
			offset++;

			dissect_hpsw_tlv(tvb,offset,length,tlv_tree,ti,type);

			offset += length;

		}

	}
}

static void
dissect_hpsw_tlv(tvbuff_t *tvb, int offset, int length,
    proto_tree *tree, proto_item *ti, guint8 type)
{
    switch (type) {

    case HPFOO_DEVICE_NAME:
        if (length > 0) {
            proto_item_set_text(ti, "Device Name: %s", tvb_format_text(tvb, offset, length - 1));
            proto_tree_add_text(tree, tvb, offset, length, "Device Name: %s", tvb_format_text(tvb, offset, length - 1));
        } else {
            proto_item_set_text(ti, "Device Name: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "Device Name: Bad length %u", length);
        }
        break;

    case HPFOO_DEVICE_VERSION:
        if (length > 0) {
            proto_item_set_text(ti, "Version: %s", tvb_format_text(tvb, offset, length - 1));
            proto_tree_add_text(tree, tvb, offset, length, "Version: %s", tvb_format_text(tvb, offset, length - 1));
        } else {
            proto_item_set_text(ti, "Version: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "Version: Bad length %u", length);
        }
        break;

    case HPFOO_CONFIG_NAME:
        if (length > 0) {
            proto_item_set_text(ti, "Config: %s", tvb_format_text(tvb, offset, length - 1));
            proto_tree_add_text(tree, tvb, offset, length, "Config: %s", tvb_format_text(tvb, offset, length - 1));
        } else {
            proto_item_set_text(ti, "Config: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "Config: Bad length %u", length);
        }
        break;

    case HPFOO_IP_ADDR:
        if (length == 4) {
	    const char *ipstr = tvb_ip_to_str(tvb, offset);
            proto_item_set_text(ti, "IP Addr: %s", ipstr);
            proto_tree_add_text(tree, tvb, offset, length, "IP Addr: %s", ipstr);
        } else {
            proto_item_set_text(ti, "IP Addr: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "IP Addr: Bad length %u", length);
        }
        break;

    case HPFOO_FIELD_7:
        if (length == 1) {
            proto_item_set_text(ti, "Field 7: 0x%02x", tvb_get_guint8(tvb,offset));
            proto_tree_add_text(tree, tvb, offset, length, "Field 7: 0x%02x", tvb_get_guint8(tvb,offset));
        } else {
            proto_item_set_text(ti, "Field 7: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "Field 7: Bad length %u", length);
        }
        break;

    case HPFOO_FIELD_8:
        if (length == 2) {
            proto_item_set_text(ti, "Field 8: 0x%04x", tvb_get_ntohs(tvb,offset));
            proto_tree_add_text(tree, tvb, offset, length, "Field 8: 0x%04x", tvb_get_ntohs(tvb,offset));
        } else {
            proto_item_set_text(ti, "Field 8: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "Field 8: Bad length %u", length);
        }
        break;

    case HPFOO_FIELD_9:
        if (length == 2) {
            proto_item_set_text(ti, "Field 9: 0x%04x", tvb_get_ntohs(tvb,offset));
            proto_tree_add_text(tree, tvb, offset, length, "Field 9: 0x%04x", tvb_get_ntohs(tvb,offset));
        } else {
            proto_item_set_text(ti, "Field 9: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "Field 9: Bad length %u", length);
        }
        break;

    case HPFOO_FIELD_10:
        if (length == 4) {
            proto_item_set_text(ti, "Field 10: 0x%08x", tvb_get_ntohl(tvb,offset));
            proto_tree_add_text(tree, tvb, offset, length, "Field 10: 0x%08x", tvb_get_ntohl(tvb,offset));
        } else {
            proto_item_set_text(ti, "Field 10: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "Field 10: Bad length %u", length);
        }
        break;

    case HPFOO_FIELD_12:
        if (length == 1) {
            proto_item_set_text(ti, "Field 12: 0x%02x", tvb_get_guint8(tvb,offset));
            proto_tree_add_text(tree, tvb, offset, length, "Field 12: 0x%02x", tvb_get_guint8(tvb,offset));
        } else {
            proto_item_set_text(ti, "Field 12: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "Field 12: Bad length %u", length);
        }
        break;

    case HPFOO_DEVICE_ID:
        if (length == 10) {
	    const gchar *macstr = tvb_ether_to_str(tvb, offset);
            guint32 id=tvb_get_ntohl(tvb, offset+6);
            proto_item_set_text(ti, "Device ID: %s / %u", macstr, id);
            proto_tree_add_text(tree, tvb, offset, 10, "Device ID: %s / %u", macstr, id);
        } else {
            proto_item_set_text(ti, "Device ID: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "Device ID: Bad length %u", length);
        }
        break;

    case HPFOO_MAC_ADDR:
        if (length == 6) {
            const gchar *macstr = tvb_ether_to_str(tvb, offset);
            proto_item_set_text(ti, "MAC Addr: %s", macstr);
            proto_tree_add_text(tree, tvb, offset, length, "MAC Addr: %s", macstr);
        } else {
            proto_item_set_text(ti, "MAC Addr: Bad length %u", length);
            proto_tree_add_text(tree, tvb, offset, length, "MAC Addr: Bad length %u", length);
        }
        break;

    default:
        proto_tree_add_text(tree, tvb, offset, length, "Data");
        break;
    }
}




void
proto_register_hpsw(void)
{
	static hf_register_info hf[] = {
		{ &hf_hpsw_version,
		{ "Version", "hpsw.version", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_hpsw_type,
		{ "Type", "hpsw.type", FT_UINT8, BASE_HEX,
			NULL, 0x0, NULL, HFILL }},
		{ &hf_hpsw_tlvtype,
		{ "Type", "hpsw.tlv_type", FT_UINT8, BASE_HEX,
			VALS(hpsw_tlv_type_vals), 0x0, NULL, HFILL }},
		{ &hf_hpsw_tlvlength,
		{ "Length", "hpsw.tlv_len", FT_UINT8, BASE_DEC,
			NULL, 0x0, NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_hpsw,
		&ett_hpsw_tlv
	};

	proto_hpsw = proto_register_protocol( "HP Switch Protocol", "HPSW", "hpsw");
	proto_register_field_array(proto_hpsw, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("hpsw", dissect_hpsw, proto_hpsw);
}

void
proto_reg_handoff_hpsw(void)
{
	dissector_handle_t hpsw_handle;

	hpsw_handle = find_dissector("hpsw");

	dissector_add_uint("hpext.dxsap", HPEXT_HPSW, hpsw_handle);
}
