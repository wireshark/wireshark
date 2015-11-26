/* packet-wmx.c
 * WiMax Protocol and dissectors
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#include "config.h"

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include "wimax_tlv.h"
#include "wimax_utils.h"

void proto_register_wimax(void);

/* Global variables */
gint	proto_wimax = -1;
gint8	arq_enabled = 0;
gint	scheduling_service_type = 0;
gint	mac_sdu_length = 49; /* default SDU size is 49 bytes (11.13.16) */
extern	guint global_cid_max_basic;
extern	gboolean include_cor2_changes;

address bs_address = ADDRESS_INIT_NONE;


static int hf_tlv_type = -1;
static int hf_tlv_length = -1;
static int hf_tlv_length_size = -1;

#define MAX_NUM_TLVS	256
/* Global TLV array to retrieve unique subtree identifiers */
static gint ett_tlv[MAX_NUM_TLVS];

static const gchar tlv_val_1byte[] = "TLV value: %s (0x%02x)";
static const gchar tlv_val_2byte[] = "TLV value: %s (0x%04x)";
static const gchar tlv_val_3byte[] = "TLV value: %s (0x%06x)";
static const gchar tlv_val_4byte[] = "TLV value: %s (0x%08x)";
static const gchar tlv_val_5byte[] = "TLV value: %s (0x%08x...)";

/*************************************************************/
/* add_tlv_subtree()                                         */
/* Return a pointer to a proto_item of a TLV value that      */
/* already contains the type and length of the given TLV.    */
/*   tree          - the parent to which the new tree will   */
/*                   be attached                             */
/*   hfindex       - the index of the item to be attached    */
/*   tvb           - a pointer to the packet data            */
/*   start         - offset within the packet                */
/*   length        - length of this item                     */
/*   encoding      - encoding for proto_tree_add_item        */
/* return:                                                   */
/*   pointer to a proto_item                                 */
/*************************************************************/
proto_item *add_tlv_subtree(tlv_info_t *self, proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, const guint encoding)
{
	header_field_info *hf;
	proto_tree *tlv_tree;
	proto_item *tlv_item;
	gint tlv_value_length, tlv_val_offset;
	guint8 size_of_tlv_length_field;
	guint8 tlv_type;

	/* Make sure we're dealing with a valid TLV here */
	if (get_tlv_type(self) < 0)
		return tree;

	/* Retrieve the necessary TLV information */
	tlv_val_offset = get_tlv_value_offset(self);
	tlv_value_length = get_tlv_length(self);
	size_of_tlv_length_field = get_tlv_size_of_length(self);
	tlv_type = get_tlv_type(self);

	hf = proto_registrar_get_nth(hfindex);

	tlv_tree = proto_tree_add_subtree(tree, tvb, start, tlv_value_length+tlv_val_offset, ett_tlv[tlv_type], NULL, hf->name);

	proto_tree_add_uint(tlv_tree, hf_tlv_type, tvb, start, 1, tlv_type);
	if (size_of_tlv_length_field > 0) /* It is */
	{
		/* display the length of the length field TLV */
		proto_tree_add_uint(tlv_tree, hf_tlv_length_size, tvb, start+1, 1, size_of_tlv_length_field);
		/* display the TLV length */
		proto_tree_add_uint(tlv_tree, hf_tlv_length, tvb, start+2, size_of_tlv_length_field, tlv_value_length);
	} else { /* It is not */
		/* display the TLV length */
		proto_tree_add_uint(tlv_tree, hf_tlv_length, tvb, start+1, 1, tlv_value_length);
	}

	tlv_item = proto_tree_add_item(tlv_tree, hfindex, tvb, start+tlv_val_offset, tlv_value_length, encoding);

	/* Return a pointer to the value level */
	return tlv_item;
}

/*************************************************************/
/* add_tlv_subtree_no_item()                                 */
/* Return a pointer to a proto_tree of a TLV value that      */
/* already contains the type and length, but no value        */
/*   tree          - the parent to which the new tree will   */
/*                   be attached                             */
/*   hfindex       - the index of the item to be attached    */
/*   tvb           - a pointer to the packet data            */
/*   start         - offset within the packet                */
/*   length        - length of this item                     */
/* return:                                                   */
/*   pointer to a proto_tree (to then add value)             */
/*************************************************************/
proto_tree *add_tlv_subtree_no_item(tlv_info_t *self, proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start)
{
	header_field_info *hf;
	proto_tree *tlv_tree;
	gint tlv_value_length, tlv_val_offset;
	guint8 size_of_tlv_length_field;
	guint8 tlv_type;

	/* Make sure we're dealing with a valid TLV here */
	if (get_tlv_type(self) < 0)
		return tree;

	/* Retrieve the necessary TLV information */
	tlv_val_offset = get_tlv_value_offset(self);
	tlv_value_length = get_tlv_length(self);
	size_of_tlv_length_field = get_tlv_size_of_length(self);
	tlv_type = get_tlv_type(self);

	hf = proto_registrar_get_nth(hfindex);

	tlv_tree = proto_tree_add_subtree(tree, tvb, start, tlv_value_length+tlv_val_offset, ett_tlv[tlv_type], NULL, hf->name);

	proto_tree_add_uint(tlv_tree, hf_tlv_type, tvb, start, 1, tlv_type);
	if (size_of_tlv_length_field > 0) /* It is */
	{
		/* display the length of the length field TLV */
		proto_tree_add_uint(tlv_tree, hf_tlv_length_size, tvb, start+1, 1, size_of_tlv_length_field);
		/* display the TLV length */
		proto_tree_add_uint(tlv_tree, hf_tlv_length, tvb, start+2, size_of_tlv_length_field, tlv_value_length);
	} else { /* It is not */
		/* display the TLV length */
		proto_tree_add_uint(tlv_tree, hf_tlv_length, tvb, start+1, 1, tlv_value_length);
	}

	/* Return a pointer to the tree level (to manually add item) */
	return tlv_tree;
}

/*************************************************************/
/* add_protocol_subtree()                                    */
/* Return a pointer to a proto_tree that already contains    */
/* the type and length of a given TLV.                       */
/*   tree          - the parent to which the new tree will   */
/*                   be attached                             */
/*   hfindex       - the index of the item to be attached    */
/*   tvb           - a pointer to the packet data            */
/*   start         - offset within the packet                */
/*   length        - length of this item                     */
/*   format        - printf style formatting string          */
/*   ...	   - arguments to format                     */
/* return:                                                   */
/*   pointer to a proto_tree                                 */
/*************************************************************/
proto_tree *add_protocol_subtree(tlv_info_t *self, gint idx, proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length _U_, const char *label)
{
	/* Declare local variables */
	proto_tree *tlv_tree;
	proto_item *tlv_item;
	gint tlv_value_length, tlv_val_offset;
	guint8 size_of_tlv_length_field;
	guint8 tlv_type;
	guint32 tlv_value;
	const gchar *hex_fmt;

	/* Make sure we're dealing with a valid TLV here */
	if (get_tlv_type(self) < 0)
		return tree;

	/* Retrieve the necessary TLV information */
	tlv_val_offset = get_tlv_value_offset(self);
	tlv_value_length = get_tlv_length(self);
	size_of_tlv_length_field = get_tlv_size_of_length(self);
	tlv_type = get_tlv_type(self);

	/* display the TLV name and display the value in hex. Highlight type, length, and value. */
	tlv_item = proto_tree_add_protocol_format(tree, hfindex, tvb, start, tlv_value_length+tlv_val_offset, "%s (%u byte(s))", label, tlv_value_length);
	tlv_tree = proto_item_add_subtree(tlv_item, ett_tlv[tlv_type]);

	proto_tree_add_uint(tlv_tree, hf_tlv_type, tvb, start, 1, tlv_type);
	if (size_of_tlv_length_field > 0) /* It is */
	{
		/* display the length of the length field TLV */
		proto_tree_add_uint(tlv_tree, hf_tlv_length_size, tvb, start+1, 1, size_of_tlv_length_field);
		/* display the TLV length */
		proto_tree_add_uint(tlv_tree, hf_tlv_length, tvb, start+2, size_of_tlv_length_field, tlv_value_length);
	} else { /* It is not */
		/* display the TLV length */
		proto_tree_add_uint(tlv_tree, hf_tlv_length, tvb, start+1, 1, tlv_value_length);
	}

	/* display the TLV value and make it a subtree */
	switch (tlv_value_length)
	{
		case 1:
			tlv_value = tvb_get_guint8(tvb, start+tlv_val_offset);
			hex_fmt = tlv_val_1byte;
			break;
		case 2:
			tlv_value = tvb_get_ntohs(tvb, start+tlv_val_offset);
			hex_fmt = tlv_val_2byte;
			break;
		case 3:
			tlv_value = tvb_get_ntoh24(tvb, start+tlv_val_offset);
			hex_fmt = tlv_val_3byte;
			break;
		case 4:
			tlv_value = tvb_get_ntohl(tvb, start+tlv_val_offset);
			hex_fmt = tlv_val_4byte;
			break;
		default:
			tlv_value = tvb_get_ntohl(tvb, start+tlv_val_offset);
			hex_fmt = tlv_val_5byte;
			break;
	}
	/* Show "TLV value: " */
	tlv_tree = proto_tree_add_subtree_format(tlv_tree, tvb, start+tlv_val_offset, tlv_value_length, idx, NULL, hex_fmt, label, tlv_value);

	/* Return a pointer to the value level */
	return tlv_tree;
}



/* WiMax protocol dissector */
static int dissect_wimax(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree _U_, void* data _U_)
{
	/* display the WiMax protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WiMax");
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);

	return tvb_captured_length(tvb);
}

gboolean is_down_link(packet_info *pinfo)
{
	if (pinfo->p2p_dir == P2P_DIR_RECV)
		return TRUE;
	if (pinfo->p2p_dir == P2P_DIR_UNKNOWN)
		if(bs_address.len && !cmp_address(&bs_address, &pinfo->src))
			return TRUE;
	return FALSE;
}


/* Register Wimax Protocol */
void proto_register_wimax(void)
{
	int i;
	module_t *wimax_module;

	static hf_register_info hf[] = {
		{ &hf_tlv_type, { "TLV type", "wmx.tlv_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_tlv_length, { "TLV length", "wmx.tlv_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_tlv_length_size, { "Size of TLV length field", "wmx.tlv_length_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
	};

	gint *ett_reg[MAX_NUM_TLVS];

	/* Register the WiMax protocols here */
	proto_wimax = proto_register_protocol (
		"WiMax Protocol", /* name       */
		"WiMax (wmx)",    /* short name */
		"wmx"             /* abbrev     */
		);

	proto_register_field_array(proto_wimax, hf, array_length(hf));

	/* Register the ett TLV array to retrieve unique subtree identifiers */
	for (i = 0; i < MAX_NUM_TLVS; i++)
	{
		ett_tlv[i] = -1;
		ett_reg[i] = &ett_tlv[i];
	}

	proto_register_subtree_array(ett_reg, array_length(ett_reg));

	/* Register the WiMax dissector */
	register_dissector("wmx", dissect_wimax, proto_wimax);

	wimax_module = prefs_register_protocol(proto_wimax, NULL);

	prefs_register_uint_preference(wimax_module, "basic_cid_max",
				       "Maximum Basic CID",
				       "Set the maximum Basic CID"
				       " used in the Wimax decoder"
				       " (if other than the default of 320)."
				       "  Note: The maximum Primary CID is"
				       " double the maximum Basic CID.",
				       10, &global_cid_max_basic);

	prefs_register_bool_preference(wimax_module, "corrigendum_2_version",
				       "Corrigendum 2 Version",
				       "Set to TRUE to use the Corrigendum"
				       " 2 version of Wimax message decoding."
				       " Set to FALSE to use the 802.16e-2005"
				       "  version.",
				       &include_cor2_changes);
	prefs_register_obsolete_preference(wimax_module, "wimax.basic_cid_max");
	prefs_register_obsolete_preference(wimax_module, "wimax.corrigendum_2_version");
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
