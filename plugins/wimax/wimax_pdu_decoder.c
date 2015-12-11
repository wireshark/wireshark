/* wimax_pdu_decoder.c
 * WiMax PDU Burst decoder
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

#include <epan/packet.h>
#include "crc.h"
#include "wimax_utils.h"

extern gint proto_wimax;

void proto_register_wimax_pdu(void);
void proto_reg_handoff_wimax_pdu(void);

static dissector_handle_t mac_generic_decoder_handle = NULL;
static dissector_handle_t mac_header_type1_handle = NULL;
static dissector_handle_t mac_header_type2_handle = NULL;
static dissector_handle_t wimax_harq_map_handle = NULL;

#define WIMAX_PDU_PADDING_MASK           0xFF
#define WIMAX_INVALID_PDU_MASK           0xF0
#define WIMAX_MAP_TYPE_MASK              0xE0  /* 0b111 */
#define WIMAX_HARQ_MAP_MSG_IND           0xE0  /* 0b111 */
#define WIMAX_COMPRESSED_DL_MAP_IND      0xC0  /* 0b110 */
#define REDUCED_PRIVATE_MAP_MASK         0x0C  /* 0b11 */

#define WIMAX_MAC_HEADER_SIZE            6
#define WIMAX_MAC_HEADER_INFO_FIELDS     5
#define WIMAX_MAC_HEADER_HT_FIELD        0x80
#define WIMAX_MAC_HEADER_EC_FIELD        0x40
#define WIMAX_MAC_HEADER_LENGTH_MSB_MASK 0x07

#define WIMAX_HARQ_MAP_MSG_LENGTH_MASK1  0x07FC
/* Global Variables. */
gboolean first_gmh;

static gint proto_wimax_pdu_decoder = -1;
static gint ett_wimax_pdu_decoder = -1;

static int hf_wimax_value_bytes = -1;

static int dissect_wimax_pdu_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint offset;
	guint mac_ht, mac_ec;
	guint first_byte, length;
	guint mac_hcs, mac_hcs_calculated;
	proto_item *pdu_item = NULL;
	proto_tree *pdu_tree = NULL;

#ifndef STATIC_DATA
	/* generate the table of CRC32  remainders for all possible bytes */
	wimax_mac_gen_crc32_table();
	/* generate the table of CRC8 remainders for all possible bytes */
	wimax_mac_gen_crc8_table();
#endif

	/* parsing the PDU burst */
	for(offset = 0; offset < tvb_reported_length(tvb); )
	{
		if (offset == 0)
		{
			first_gmh = TRUE;
		}
		else
		{
			first_gmh = FALSE;
		}
		/* get the length of the remainder */
		length = tvb_reported_length_remaining(tvb, offset);
		/* get the first byte at offset */
		first_byte = tvb_get_guint8(tvb, offset);
		/* check for padding */
		if(first_byte == WIMAX_PDU_PADDING_MASK)
		{	/* Padding */
			/* display message */
			pdu_item = proto_tree_add_protocol_format(tree, proto_wimax_pdu_decoder, tvb, offset, length, "Padding (%u bytes)", length);
			/* add subtree */
			pdu_tree = proto_item_add_subtree(pdu_item, ett_wimax_pdu_decoder);
			/* display the padding in Hex */
			proto_tree_add_item(pdu_tree, hf_wimax_value_bytes, tvb, offset, length, ENC_NA);
			break;
		}
		else if((first_byte & WIMAX_MAP_TYPE_MASK) == WIMAX_HARQ_MAP_MSG_IND)
		{	/* HARQ MAP message (no mac header) */
			/* get the HARQ MAp Message Length */
			length = ((tvb_get_ntohs(tvb, offset) & WIMAX_HARQ_MAP_MSG_LENGTH_MASK1) >> 2);
			if (length == 0)
			{
				length = 3;	/* At least 3 bytes.  This prevents endless loop */
			}
			call_dissector(wimax_harq_map_handle, tvb_new_subset_length(tvb,offset,length), pinfo, tree);
			offset += length;
			continue;
		}
		else if((first_byte & WIMAX_MAP_TYPE_MASK) == WIMAX_COMPRESSED_DL_MAP_IND)
		{
			if(is_down_link(pinfo))
			{	/* decode compressed dl-map without mac header */
				if ((first_byte & REDUCED_PRIVATE_MAP_MASK) == REDUCED_PRIVATE_MAP_MASK)
				{
					length = wimax_decode_dlmap_reduced_aas(tvb, pinfo, tree);
				}
				else
				{
					length = wimax_decode_dlmapc(tvb, pinfo, tree);
				}
				offset += length;
				continue;
			}
		}
		else if((first_byte & WIMAX_INVALID_PDU_MASK) == WIMAX_INVALID_PDU_MASK)
		{	/* Invalid PDU */
			/* update the info column */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Invalid PDU");
			/* display message */
			pdu_item = proto_tree_add_protocol_format(tree, proto_wimax_pdu_decoder, tvb, offset, length, "Invalid PDU  (%u bytes)", length);
			/* add subtree */
			pdu_tree = proto_item_add_subtree(pdu_item, ett_wimax_pdu_decoder);
				/* display the invalid MAC Header in Hex */
			proto_tree_add_item(pdu_tree, hf_wimax_value_bytes, tvb, offset, length, ENC_NA);
			break;
		}
		/* calculate the MAC header HCS */
		mac_hcs_calculated = wimax_mac_calc_crc8(tvb_get_ptr(tvb, offset, WIMAX_MAC_HEADER_INFO_FIELDS), WIMAX_MAC_HEADER_INFO_FIELDS);
		/* get the Header Check Sequence (HCS) in the header */
		mac_hcs = tvb_get_guint8(tvb, offset + WIMAX_MAC_HEADER_SIZE - 1);
		/* verify the HCS */
		if(mac_hcs != mac_hcs_calculated)
		{
			/* update the info column */
			col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "MAC Header CRC error");
			/* display message */
			pdu_item = proto_tree_add_protocol_format(tree, proto_wimax_pdu_decoder, tvb, offset, WIMAX_MAC_HEADER_SIZE, "MAC Header CRC error %X (in header) and %X (calculated)", mac_hcs, mac_hcs_calculated);
			/* add subtree */
			pdu_tree = proto_item_add_subtree(pdu_item, ett_wimax_pdu_decoder);
			/* display the bad MAC Header in Hex */
			proto_tree_add_item(pdu_tree, hf_wimax_value_bytes, tvb, offset, length, ENC_NA);
			break;
		}
		/* get the Header Type (HT) */
		mac_ht = ((first_byte & WIMAX_MAC_HEADER_HT_FIELD)?1:0);
		/* get the Encryption Control (EC) */
		mac_ec = ((first_byte & WIMAX_MAC_HEADER_EC_FIELD)?1:0);
		/* update the MAC length for Generic MAC frame */
		if(!mac_ht)
		{	/* Generic MAC Header with payload */
			/* get the MAC length */
			length = (tvb_get_guint8(tvb, offset+1) & WIMAX_MAC_HEADER_LENGTH_MSB_MASK);
			length = ((length<<8) | tvb_get_guint8(tvb, offset+2));
		}
		else	/* MAC signaling Headers or Bandwidth Request Headers */
		{	/* set the mac length */
			length = WIMAX_MAC_HEADER_SIZE;
		}
		/* display PDU frame info */
		/*
		pdu_item = proto_tree_add_protocol_format(tree, proto_wimax_pdu_decoder, tvb, offset, length, "PDU Frame (%u bytes)", length);
		*/
		pdu_item = proto_tree_add_protocol_format(tree, proto_wimax_pdu_decoder, tvb, offset, length, "PDU (%u bytes)", length);
		/* add PDU subtree */
		pdu_tree = proto_item_add_subtree(pdu_item, ett_wimax_pdu_decoder);
		if (length == 0) {
			offset += 6;	/* Add header size. */
			/* Must skip the code below or tvb_new_subset_length()
			 * keeps allocating memory until it runs out. */
			continue;
		}
		/* process the valid MAC header */
		if(mac_ht)
		{	/* MAC signaling Headers or Bandwidth Request Headers */
			/* check the header type */
			if(mac_ec)
			{	/* MAC Signaling Header Type II Header */
				proto_item_append_text(pdu_item, " - Mac Type II Header: ");
				call_dissector(mac_header_type2_handle, tvb_new_subset_length(tvb,offset,length), pinfo, pdu_tree);
			}
			else
			{	/* MAC Signaling Header Type I Header */
				proto_item_append_text(pdu_item, " - Mac Type I Header: ");
				call_dissector(mac_header_type1_handle, tvb_new_subset_length(tvb,offset,length), pinfo, pdu_tree);
			}
		}
		else	/* Generic MAC Header with payload */
		{
			call_dissector(mac_generic_decoder_handle, tvb_new_subset_length(tvb,offset,length), pinfo, pdu_tree);
		}
		offset += length;
	}
	return tvb_captured_length(tvb);
}

/* Register Wimax PDU Burst Protocol */
void proto_register_wimax_pdu(void)
{
	/* PDU display */
	static hf_register_info hf[] =
	{
		{
			&hf_wimax_value_bytes,
			{
				"Values", "wmx.pdu.value",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] =
		{
			&ett_wimax_pdu_decoder,
		};

	proto_wimax_pdu_decoder = proto_wimax;

	register_dissector("wimax_pdu_burst_handler", dissect_wimax_pdu_decoder, -1);
	proto_register_field_array(proto_wimax_pdu_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_wimax_pdu(void)
{
	mac_generic_decoder_handle = find_dissector("mac_header_generic_handler");
	mac_header_type1_handle = find_dissector("mac_header_type_1_handler");
	mac_header_type2_handle = find_dissector("mac_header_type_2_handler");
	wimax_harq_map_handle = find_dissector("wimax_harq_map_handler");
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
