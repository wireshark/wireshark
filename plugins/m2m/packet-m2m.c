/* packet-m2m.c
 * Routines for WiMax MAC to MAC TLV packet disassembly
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <plugins/wimax/wimax_tlv.h>

/* forward reference */
void proto_reg_handoff_m2m(void);
void proto_register_m2m(void);
static void fch_burst_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo);
static void cdma_code_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo);
static void pdu_burst_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo, gint burst_number, gint frag_type, gint frag_number);
static void fast_feedback_burst_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo);
static void harq_ack_bursts_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo);
static void physical_attributes_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo);
static void extended_tlv_decoder(packet_info *pinfo);
void proto_tree_add_tlv(tlv_info_t *self, tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, gint hf, guint encoding);

/* Global variables */
static dissector_handle_t wimax_cdma_code_burst_handle;
static dissector_handle_t wimax_ffb_burst_handle;
static dissector_handle_t wimax_fch_burst_handle;
static dissector_handle_t wimax_hack_burst_handle;
static dissector_handle_t wimax_pdu_burst_handle;
static dissector_handle_t wimax_phy_attributes_burst_handle;

static reassembly_table pdu_reassembly_table;

static gint proto_m2m    = -1;

static gint ett_m2m      = -1;
static gint ett_m2m_tlv  = -1;
static gint ett_m2m_fch  = -1;
static gint ett_m2m_cdma = -1;
static gint ett_m2m_ffb  = -1;

/* TLV types (rev:0.2) */
#define TLV_PROTO_VER		1
#define TLV_FRAME_NUM		2
#define TLV_BURST_NUM		3
#define TLV_FRAG_TYPE		4
#define TLV_FRAG_NUM		5
#define TLV_CDMA_CODE		7
#define TLV_FCH_BURST		8
#define TLV_PDU_BURST		9
#define TLV_FAST_FB		10
#define TLV_CRC16_STATUS	11
#define TLV_BURST_POWER		12
#define TLV_BURST_CINR		13
#define TLV_PREAMBLE		14
#define TLV_HARQ_ACK_BURST	15
#define TLV_PHY_ATTRIBUTES	16
#define TLV_EXTENDED_TLV	255

/* TLV names */
static const value_string tlv_name[] =
{
	{ TLV_PROTO_VER, "Protocol Version" },
	{ TLV_FRAME_NUM, "Frame Number" },
	{ TLV_BURST_NUM, "Burst Number" },
	{ TLV_FRAG_TYPE, "Fragment Type" },
	{ TLV_FRAG_NUM, "Fragment Number" },
	{ TLV_CDMA_CODE, "CDMA Attribute" },
	{ TLV_FCH_BURST, "FCH Burst" },
	{ TLV_PDU_BURST, "PDU Burst" },
	{ TLV_FAST_FB, "Fast Feedback Burst" },
	{ TLV_CRC16_STATUS, "CRC16 Status" },
	{ TLV_BURST_POWER, " Burst Power" },
	{ TLV_BURST_CINR, "Burst CINR" },
	{ TLV_PREAMBLE, "Preamble" },
	{ TLV_HARQ_ACK_BURST, "HARQ ACK Bursts" },
	{ TLV_PHY_ATTRIBUTES, "PDU Burst Physical Attributes" },
	{ TLV_EXTENDED_TLV, "Extended TLV" },
	{ 0, NULL }
};

/* TLV Fragment types */
#define TLV_NO_FRAG     0
#define TLV_FIRST_FRAG  1
#define TLV_MIDDLE_FRAG 2
#define TLV_LAST_FRAG   3

/* TLV Fragment Type names */
static const value_string tlv_frag_type_name[] =
{
	{ TLV_NO_FRAG, "No TLV Fragment" },
	{ TLV_FIRST_FRAG, "First TLV Fragment" },
	{ TLV_MIDDLE_FRAG, "Middle TLV Fragment" },
	{ TLV_LAST_FRAG, "Last TLV Fragment" },
	{ 0, NULL }
};

/* TLV CRC16 Status */
static const value_string tlv_crc16_status[] =
{
	{ 0, "No CRC-16 in burst" },
	{ 1, "Good CRC-16 in burst" },
	{ 2, "Bad CRC-16 in burst" },
	{ 0, NULL }
};

static gint hf_m2m_sequence_number = -1;
static gint hf_m2m_frame_number = -1;
static gint hf_m2m_tlv_count = -1;

static gint hf_m2m_type = -1;
static gint hf_m2m_len = -1;
static gint hf_m2m_len_size = -1;
/* static gint hf_m2m_value_bytes = -1; */
static gint hf_wimax_invalid_tlv = -1;
static gint hf_m2m_value_protocol_vers_uint8 = -1;
static gint hf_m2m_value_burst_num_uint8 = -1;
static gint hf_m2m_value_frag_type_uint8 = -1;
static gint hf_m2m_value_frag_num_uint8 = -1;
static gint hf_m2m_value_pdu_burst = -1;
static gint hf_m2m_value_fast_fb = -1;
static gint hf_m2m_value_fch_burst_uint24 = -1;
static gint hf_m2m_value_cdma_code_uint24 = -1;
static gint hf_m2m_value_crc16_status_uint8 = -1;
static gint hf_m2m_value_burst_power_uint16 = -1;
static gint hf_m2m_value_burst_cinr_uint16 = -1;
static gint hf_m2m_value_preamble_uint16 = -1;
static gint hf_m2m_value_harq_ack_burst_bytes = -1;
static gint hf_m2m_phy_attributes = -1;

static expert_field ei_m2m_unexpected_length = EI_INIT;

/* Register M2M defrag table init routine. */
static void
m2m_defragment_init(void)
{
	reassembly_table_init(&pdu_reassembly_table,
	    &addresses_reassembly_table_functions);
}


/* WiMax MAC to MAC protocol dissector */
static void dissect_m2m(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti = NULL;
	proto_item *m2m_item = NULL;
	proto_tree *m2m_tree = NULL;
	proto_tree *tlv_tree = NULL;
	gint burst_number = 0;
	gint length, offset = 0;
	gint tlv_count;
	gint tlv_type, tlv_len, tlv_offset, tlv_value;
	gint tlv_frag_type = 0;
	gint tlv_frag_number = 0;
	tlv_info_t m2m_tlv_info;
	gint hf;
	guint encoding;
	guint frame_number;
	int expected_len;

	/* display the M2M protocol name */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WiMax");

	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo, COL_INFO);


	{	/* we are being asked for details */
		m2m_item = proto_tree_add_item(tree, proto_m2m, tvb, 0, -1, ENC_NA);
		m2m_tree = proto_item_add_subtree(m2m_item, ett_m2m);
		/* get the tvb reported length */
		length =  tvb_reported_length(tvb);
		/* add the size info */
        /*
		proto_item_append_text(m2m_item, " (%u bytes) - Packet Sequence Number,Number of TLVs", length);
        */
		proto_item_append_text(m2m_item, " (%u bytes)", length);
		/* display the sequence number */
		proto_tree_add_item(m2m_tree, hf_m2m_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		/* display the TLV count */
		proto_tree_add_item(m2m_tree, hf_m2m_tlv_count, tvb, offset, 2, ENC_BIG_ENDIAN);
		tlv_count = tvb_get_ntohs(tvb, offset);
		offset += 2;
		/* parses the TLVs within current packet */
		while ( tlv_count > 0)
		{	/* init MAC to MAC TLV information */
			init_tlv_info(&m2m_tlv_info, tvb, offset);
			/* get the TLV type */
			tlv_type = get_tlv_type(&m2m_tlv_info);
			/* get the TLV length */
			tlv_len = get_tlv_length(&m2m_tlv_info);
			if(tlv_type == -1 || tlv_len > 64000 || tlv_len < 1)
			{	/* invalid tlv info */
				col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "M2M TLV error");
				/* display the invalid TLV in HEX */
				proto_tree_add_item(m2m_tree, hf_wimax_invalid_tlv, tvb, offset, (length - offset), ENC_NA);
				break;
			}
			/* get the TLV value offset */
			tlv_offset = get_tlv_value_offset(&m2m_tlv_info);
			/* display TLV type */
			ti = proto_tree_add_protocol_format(m2m_tree, proto_m2m, tvb, offset, (tlv_len + tlv_offset), "%s", val_to_str(tlv_type, tlv_name, "Unknown TLV"));
			/* add TLV subtree */
			tlv_tree = proto_item_add_subtree(ti, ett_m2m_tlv);
			/* update the offset */
			offset += tlv_offset;
			/* add the size info */
			/* decode TLV content (TLV value) */
			expected_len = 0;
			hf = 0;
			encoding = ENC_NA;
			switch (tlv_type)
			{
				case TLV_PROTO_VER:
					/* get the protocol version */
					tlv_value = tvb_get_guint8( tvb, offset );
					/* add the description */
					proto_item_append_text(ti, ": %d", tlv_value);
					hf = hf_m2m_value_protocol_vers_uint8;
					encoding = ENC_BIG_ENDIAN;
					expected_len = 1;
				break;

				case TLV_BURST_NUM:
					/* get the burst number */
					burst_number = tvb_get_guint8( tvb, offset );
					/* add the description */
					proto_item_append_text(ti, ": %d", burst_number);
					hf = hf_m2m_value_burst_num_uint8;
					encoding = ENC_BIG_ENDIAN;
					expected_len = 1;
				break;

				case TLV_FRAG_TYPE:
					/* add the description */
					tlv_frag_type = tvb_get_guint8( tvb, offset );
					proto_item_append_text(ti, ": %s", val_to_str(tlv_frag_type, tlv_frag_type_name, "Unknown"));
					hf = hf_m2m_value_frag_type_uint8;
					encoding = ENC_BIG_ENDIAN;
					expected_len = 1;
				break;

				case TLV_FRAG_NUM:
					/* get the fragment number */
					tlv_frag_number = tvb_get_guint8( tvb, offset );
					/* add the description */
					proto_item_append_text(ti, ": %d", tlv_frag_number);
					hf = hf_m2m_value_frag_num_uint8;
					encoding = ENC_BIG_ENDIAN;
					expected_len = 1;
				break;

				case TLV_PDU_BURST:
					/* display PDU Burst length info */
					proto_item_append_text(ti, " (%u bytes)", tlv_len);
					/* decode and display the PDU Burst */
					pdu_burst_decoder(tree, tvb, offset, tlv_len, pinfo, burst_number, tlv_frag_type, tlv_frag_number);
					hf = hf_m2m_value_pdu_burst;
					encoding = ENC_NA;
				break;

				case TLV_FAST_FB:
					/* display the Fast Feedback Burst length info */
					proto_item_append_text(ti, " (%u bytes)", tlv_len);
					/* decode and display the Fast Feedback Burst */
					fast_feedback_burst_decoder(tree, tvb, offset, tlv_len, pinfo);
					hf = hf_m2m_value_fast_fb;
					encoding = ENC_NA;
				break;

				case TLV_FRAME_NUM:
					/* get the frame number */
					frame_number = tvb_get_ntoh24( tvb, offset );
					/* add the description */
					proto_tree_add_item(tlv_tree, hf_m2m_frame_number, tvb, offset, 3, ENC_BIG_ENDIAN);
					proto_item_append_text(ti, ": %d", frame_number);
				break;

				case TLV_FCH_BURST:
					/* add the description */
					tlv_value = tvb_get_ntoh24( tvb, offset );
					proto_item_append_text(ti, ": 0x%X", tlv_value);
					/* decode and display the TLV FCH burst */
					fch_burst_decoder(tree, tvb, offset, tlv_len, pinfo);
					hf = hf_m2m_value_fch_burst_uint24;
					encoding = ENC_BIG_ENDIAN;
					expected_len = 3;
				break;

				case TLV_CDMA_CODE:
					/* add the description */
					tlv_value = tvb_get_ntoh24( tvb, offset );
					proto_item_append_text(ti, ": 0x%X", tlv_value);
					/* decode and display the CDMA Code */
					cdma_code_decoder(tree, tvb, offset, tlv_len, pinfo);
					hf = hf_m2m_value_cdma_code_uint24;
					encoding = ENC_BIG_ENDIAN;
					expected_len = 3;
				break;

				case TLV_CRC16_STATUS:
					/* add the description */
					tlv_value = tvb_get_guint8( tvb, offset );
					proto_item_append_text(ti, ": %s", val_to_str(tlv_value, tlv_crc16_status, "Unknown"));
					hf = hf_m2m_value_crc16_status_uint8;
					encoding = ENC_BIG_ENDIAN;
					expected_len = 1;
				break;

				case TLV_BURST_POWER:
					/* add the description */
					tlv_value = tvb_get_ntohs( tvb, offset );
					proto_item_append_text(ti, ": %d", tlv_value);
					hf = hf_m2m_value_burst_power_uint16;
					encoding = ENC_BIG_ENDIAN;
					expected_len = 2;
				break;

				case TLV_BURST_CINR:
					/* add the description */
					tlv_value = tvb_get_ntohs( tvb, offset );
					proto_item_append_text(ti, ": 0x%X", tlv_value);
					hf = hf_m2m_value_burst_cinr_uint16;
					encoding = ENC_BIG_ENDIAN;
					expected_len = 2;
				break;

				case TLV_PREAMBLE:
					/* add the description */
					tlv_value = tvb_get_ntohs( tvb, offset );
					proto_item_append_text(ti, ": 0x%X", tlv_value);
					hf = hf_m2m_value_preamble_uint16;
					encoding = ENC_BIG_ENDIAN;
					expected_len = 2;
				break;

				case TLV_HARQ_ACK_BURST:
					/* display the Burst length info */
					proto_item_append_text(ti, " (%u bytes)", tlv_len);
					/* decode and display the HARQ ACK Bursts */
					harq_ack_bursts_decoder(tree, tvb, offset, tlv_len, pinfo);
					hf = hf_m2m_value_harq_ack_burst_bytes;
					encoding = ENC_NA;
				break;

				case TLV_PHY_ATTRIBUTES:
					/* display the Burst length info */
					proto_item_append_text(ti, " (%u bytes)", tlv_len);
					/* decode and display the PDU Burst Physical Attributes */
					physical_attributes_decoder(tree, tvb, offset, tlv_len, pinfo);
					hf = hf_m2m_phy_attributes;
					encoding = ENC_NA;
				break;

				case TLV_EXTENDED_TLV:
					/* display the Burst length info */
					proto_item_append_text(ti, " (%u bytes)", tlv_len);
					/* decode and display the Extended TLV */
					extended_tlv_decoder(pinfo);
				break;

				default:
					/* update the info column */
					col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Unknown TLV Type");
				break;
			}
			/* expand the TLV detail */
			if (hf) {
				if (offset - tlv_offset == expected_len) {
					proto_tree_add_tlv(&m2m_tlv_info, tvb, offset - tlv_offset, pinfo, tlv_tree, hf, encoding);
				} else {
					expert_add_info_format(pinfo, NULL, &ei_m2m_unexpected_length, "Expected length %d, got %d.", expected_len, offset - tlv_offset);
				}
			}
			offset += tlv_len;
			/* update tlv_count */
			tlv_count--;
		}
	}
}

/* Decode and display the FCH burst */
static void fch_burst_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo)
{
	if(wimax_fch_burst_handle)
	{	/* call FCH dissector */
		call_dissector(wimax_fch_burst_handle, tvb_new_subset_length(tvb, offset, length), pinfo, tree);
	}
	else	/* display FCH info */
	{	/* update the info column */
		col_append_str(pinfo->cinfo, COL_INFO, "FCH Burst: DL Frame Prefix");
	}
}

/* Decode and display the CDMA Code Attribute */
static void cdma_code_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo)
{
	if(wimax_cdma_code_burst_handle)
	{	/* call CDMA dissector */
		call_dissector(wimax_cdma_code_burst_handle, tvb_new_subset_length(tvb, offset, length), pinfo, tree);
	}
	else	/* display CDMA Code Attribute info */
	{	/* update the info column */
		col_append_str(pinfo->cinfo, COL_INFO, "CDMA Code Attribute");
	}
}

/* Decode and display the PDU Burst */
static void pdu_burst_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo, gint burst_number, gint frag_type, gint frag_number)
{
	fragment_head *pdu_frag;
	tvbuff_t *pdu_tvb = NULL;

	/* update the info column */
	switch (frag_type)
	{
		case TLV_FIRST_FRAG:
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "First TLV Fragment (%d)", frag_number);
		break;
		case TLV_LAST_FRAG:
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Last TLV Fragment (%d)", frag_number);
		break;
		case TLV_MIDDLE_FRAG:
			col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Middle TLV Fragment %d", frag_number);
		break;
	}
	if(frag_type == TLV_NO_FRAG)
	{	/* not fragmented PDU */
		pdu_tvb =  tvb_new_subset_length(tvb, offset, length);
	}
	else	/* fragmented PDU */
	{	/* add the fragment */
		pdu_frag = fragment_add_seq(&pdu_reassembly_table, tvb, offset, pinfo, burst_number, NULL, frag_number - 1, length, ((frag_type==TLV_LAST_FRAG)?0:1), 0);
		if(pdu_frag && frag_type == TLV_LAST_FRAG)
		{
			/* create the new tvb for defragmented frame */
			pdu_tvb = tvb_new_chain(tvb, pdu_frag->tvb_data);
			/* add the defragmented data to the data source list */
			add_new_data_source(pinfo, pdu_tvb, "Reassembled WiMax PDU Frame");
		}
		else
		{
			pdu_tvb = NULL;
			if(frag_type == TLV_LAST_FRAG)
			{	/* update the info column */
				col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Incomplete PDU frame");
			}
		}
	}
	/* process the defragmented PDU burst */
	if(pdu_tvb)
	{
		if(wimax_pdu_burst_handle)
		{/* decode and display PDU Burst */
			call_dissector(wimax_pdu_burst_handle, pdu_tvb, pinfo, tree);
		}
		else	/* display PDU Burst info */
		{	/* update the info column */
			col_append_str(pinfo->cinfo, COL_INFO, "PDU Burst");
		}
	}
}

/* Decode and display the Fast Feedback Burst */
static void fast_feedback_burst_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo)
{
	if(wimax_ffb_burst_handle)
	{	/* display the TLV Fast Feedback Burst dissector info */
		call_dissector(wimax_ffb_burst_handle, tvb_new_subset_length(tvb, offset, length), pinfo, tree);
	}
	else	/* display the Fast Feedback Burst info */
	{	/* update the info column */
		col_append_str(pinfo->cinfo, COL_INFO, "Fast Feedback Burst");
	}
}

static void harq_ack_bursts_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo)
{
	if(wimax_hack_burst_handle)
	{	/* call the TLV HARQ ACK Bursts dissector */
		call_dissector(wimax_hack_burst_handle, tvb_new_subset_length(tvb, offset, length), pinfo, tree);
	}
	else	/* display the TLV HARQ ACK Bursts info */
	{	/* update the info column */
		col_append_str(pinfo->cinfo, COL_INFO, "HARQ ACK Bursts");
	}
}

static void physical_attributes_decoder(proto_tree *tree, tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo)
{
	if(wimax_phy_attributes_burst_handle)
	{	/* call the TLV PDU Burst Physical Attributes dissector */
		call_dissector(wimax_phy_attributes_burst_handle, tvb_new_subset_length(tvb, offset, length), pinfo, tree);
	}
	else	/* display the TLV PDU Burst Physical Attributes info */
	{	/* update the info column */
		col_append_str(pinfo->cinfo, COL_INFO, "PHY-attr");
	}
}

static void extended_tlv_decoder(packet_info *pinfo)
{
	/* display the Extended TLV info */
	/* update the info column */
	col_append_str(pinfo->cinfo, COL_INFO, "Extended TLV");
}

/* Display the raw WiMax TLV */
void proto_tree_add_tlv(tlv_info_t *self, tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, gint hf, guint encoding)
{
	guint tlv_offset;
	gint tlv_type, tlv_len;

	/* make sure the TLV information is valid */
	if(!self->valid)
	{	/* invalid TLV info */
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Invalid TLV");
		return;
	}
	tlv_offset = offset;
	/* display TLV type */
	proto_tree_add_item(tree, hf_m2m_type, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
	tlv_offset++;
	/* check the TLV length type */
	if( self->length_type )
	{	/* multiple bytes TLV length */
		/* display the length of the TLV length with MSB */
		proto_tree_add_item(tree, hf_m2m_len_size, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);
		tlv_offset++;
		if(self->size_of_length)
			/* display the multiple byte TLV length */
			proto_tree_add_item(tree, hf_m2m_len, tvb, tlv_offset, self->size_of_length, ENC_BIG_ENDIAN);
		else
			return;
	}
	else	/* display the single byte TLV length */
		proto_tree_add_item(tree, hf_m2m_len, tvb, tlv_offset, 1, ENC_BIG_ENDIAN);

	tlv_type = get_tlv_type(self);
	/* Display Frame Number as special case for filter */
	if ( tlv_type == TLV_FRAME_NUM )
	{
		return;
	}

	/* get the TLV length */
	tlv_len = get_tlv_length(self);
	proto_tree_add_item(tree, hf, tvb, (offset + self->value_offset), tlv_len, encoding);
}

/* Register Wimax Mac to Mac Protocol */
void proto_register_m2m(void)
{
	/* M2M TLV display */
	static hf_register_info hf[] =
	{
		{
			&hf_m2m_sequence_number,
			{
				"Packet Sequence Number", "m2m.seq_number",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_frame_number,
			{
				"Value", "m2m.frame_number",
				FT_UINT24, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_tlv_count,
			{
				"Number of TLVs in the packet", "m2m.tlv_count",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		}
	};

	/* WiMax TLV display */
	static hf_register_info hf_tlv[] =
	{
		{
			&hf_m2m_type,
			{
				"Type", "m2m.tlv_type",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_len,
			{
				"Length", "m2m.tlv_len",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_len_size,
			{
				"Length Size", "m2m.tlv_len_size",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL
			}
		},
#if 0
		{
			&hf_m2m_value_bytes,
			{
				"Value (hex)", "m2m.multibyte_tlv_value",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
#endif
		{
			&hf_m2m_value_protocol_vers_uint8,
			{
				"Value", "m2m.protocol_vers_tlv_value",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_burst_num_uint8,
			{
				"Value", "m2m.burst_num_tlv_value",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_frag_type_uint8,
			{
				"Value", "m2m.frag_type_tlv_value",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_frag_num_uint8,
			{
				"Value", "m2m.frag_num_tlv_value",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_pdu_burst,
			{
				"Value (hex)", "m2m.pdu_burst_tlv_value",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_fast_fb,
			{
				"Value (hex)", "m2m.fast_fb_tlv_value",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_fch_burst_uint24,
			{
				"Value", "m2m.fch_burst_tlv_value",
				FT_UINT24, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_cdma_code_uint24,
			{
				"Value", "m2m.cdma_code_tlv_value",
				FT_UINT24, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_crc16_status_uint8,
			{
				"Value", "m2m.crc16_status_tlv_value",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_burst_power_uint16,
			{
				"Value", "m2m.burst_power_tlv_value",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_burst_cinr_uint16,
			{
				"Value", "m2m.burst_cinr_tlv_value",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_preamble_uint16,
			{
				"Value", "m2m.preamble_tlv_value",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_value_harq_ack_burst_bytes,
			{
				"Value (hex)", "m2m.harq_ack_burst_tlv_value",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_m2m_phy_attributes,
			{
				"Value (hex)", "m2m.phy_attributes",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		},
		{
			&hf_wimax_invalid_tlv,
			{
				"Invalid TLV (hex)", "m2m.invalid_tlv",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL
			}
		}
	};

	static gint *ett[] =
		{
			&ett_m2m,
			&ett_m2m_tlv,
			&ett_m2m_fch,
			&ett_m2m_cdma,
			&ett_m2m_ffb,
		};

	static ei_register_info ei[] = {
		{ &ei_m2m_unexpected_length, { "m2m.unexpected_length", PI_MALFORMED, PI_ERROR, "Unexpected length", EXPFILL }},
	};

	expert_module_t* expert_m2m;

    proto_m2m = proto_register_protocol (
		"WiMax Mac to Mac Packet", /* name       */
		"M2M  (m2m)",              /* short name */
		"m2m"                      /* abbrev     */
		);

	proto_register_field_array(proto_m2m, hf, array_length(hf));
	proto_register_field_array(proto_m2m, hf_tlv, array_length(hf_tlv));
	proto_register_subtree_array(ett, array_length(ett));
	expert_m2m = expert_register_protocol(proto_m2m);
	expert_register_field_array(expert_m2m, ei, array_length(ei));

	/* Register the PDU fragment table init routine */
	register_init_routine(m2m_defragment_init);
}

/* Register Wimax Mac to Mac Protocol handler */
void proto_reg_handoff_m2m(void)
{
	dissector_handle_t m2m_handle;

	m2m_handle = create_dissector_handle(dissect_m2m, proto_m2m);
	dissector_add_uint("ethertype", ETHERTYPE_WMX_M2M, m2m_handle);

	/* find the wimax handlers */
	wimax_cdma_code_burst_handle      = find_dissector("wimax_cdma_code_burst_handler");
	wimax_fch_burst_handle            = find_dissector("wimax_fch_burst_handler");
	wimax_ffb_burst_handle            = find_dissector("wimax_ffb_burst_handler");
	wimax_hack_burst_handle           = find_dissector("wimax_hack_burst_handler");
	wimax_pdu_burst_handle            = find_dissector("wimax_pdu_burst_handler");
	wimax_phy_attributes_burst_handle = find_dissector("wimax_phy_attributes_burst_handler");
}
