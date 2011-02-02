/* packet-tetra.c
 * Routines for TETRA packet dissection
 *
 * Copyright (c) 2007 - 2011 Professional Mobile Communication Research Group,
 *    Beijing Institute of Technology, China
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/asn1.h>
#include <epan/prefs.h>

#include <stdio.h>
#include <string.h>

#include <epan/dissectors/packet-per.h>
#include "packet-tetra.h"

#define PROTO_TAG_tetra	"TETRA"

/* Wireshark ID of the tetra protocol */
static int proto_tetra = -1;

/* These are the handles of our subdissectors */
static dissector_handle_t data_handle=NULL;

static dissector_handle_t tetra_handle;
void dissect_tetra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int global_tetra_port = 7074;

/* Whether the capture data include carrier numbers */
static gboolean include_carrier_number = TRUE;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_tetra()
*/
/** Kts attempt at defining the protocol */
static gint hf_tetra = -1;
static gint hf_tetra_header = -1;
static gint hf_tetra_channels = -1;
static gint hf_tetra_channel1 = -1;
static gint hf_tetra_channel2 = -1;
static gint hf_tetra_channel3 = -1;
static gint hf_tetra_txreg = -1;
static gint hf_tetra_timer = -1;
static gint hf_tetra_pdu = -1;
static gint hf_tetra_rvstr = -1;
static gint hf_tetra_carriernumber = -1;
static gint hf_tetra_rxchannel1 = -1;
static gint hf_tetra_rxchannel2 = -1;
static gint hf_tetra_crc = -1;
static gint hf_tetra_len0 = -1;
static gint hf_tetra_bits = -1;

#include "packet-tetra-hf.c"

/* Initialize the subtree pointers */
static int ett_umac = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_tetra = -1;
static gint ett_tetra_header = -1;
static gint ett_tetra_length = -1;
static gint ett_tetra_txreg = -1;
static gint ett_tetra_text = -1;

#include "packet-tetra-ett.c"

guint32
dissect_my_bit_string(tvbuff_t *tvb, guint32 offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index, int min_len, int max_len, gboolean has_extension, tvbuff_t **value_tvb)
{
	proto_item *tetra_sub_item = NULL;
	char s[256], s2[10];
	guint32 i, byte_len, byte_offset = offset >> 3;
	guint8 shift0, shift1, c;
	const guint8* p;

	max_len -= (offset - 104); // MAC-ACCESS only
  shift1 = offset & 0x07;
  shift0 = 8 - shift1;
	byte_len = (max_len + shift1) >> 3;
	if((max_len + shift1) & 0x07)
		byte_len++;
	p = tvb_get_ptr(tvb, byte_offset, byte_len);
	s[0] = 0;
	tetra_sub_item = proto_tree_add_item(tree, hf_index, tvb, offset >> 3, byte_len, 0);
	for(i = 0; i < byte_len; i++)
	{
		s2[0] = 0;
		c = (p[i] << shift1) | (p[i + 1] >> shift0);
		sprintf(s2, "%02x", c);
		strcat(s, s2);
	}
	proto_item_set_text(tetra_sub_item, "TM-SDU: %s", s);
	return(offset + max_len);
}

#include "packet-tetra-fn.c"

/*--- proto_register_tetra -------------------------------------------*/
void proto_reg_handoff_tetra(void)
{
	static gboolean initialized=FALSE;

	if (!initialized) {
		data_handle = find_dissector("data");
		tetra_handle = create_dissector_handle(dissect_tetra, proto_tetra);
		dissector_add("udp.port", global_tetra_port, tetra_handle);
	}

}

static const value_string channeltypenames[] = {
	{ 0, "Reserved" },
	{ 1, "AACH" },
	{ 2, "SCH/F" },
	{ 3, "SCH/HD" },
	{ 4, "Unknown" },
	{ 5, "BSCH" },
	{ 6, "BNCH" },
	{ 7, "TCH/F" },
	{ 8, "TCH/H" },
	{ 9, "TCH4.8"},
	{ 10, "TCH7.2"},
	{ 11, "STCH"},
	{ 0, NULL }
};

static const value_string recvchanneltypenames[] = {
	{ 0, "Reserved" },
	{ 1, "AACH" },
	{ 2, "SCH/F" },
	{ 3, "SCH/HD" },
	{ 4, "Unknown" },
	{ 5, "BSCH" },
	{ 6, "BNCH" },
	{ 7, "TCH/F" },
	{ 8, "TCH/H" },
	{ 9, "TCH4.8"},
	{ 10, "TCH7.2"},
	{ 11, "STCH"},
	{ 15, "SCH/HU"},
	{ 0, NULL }
};
void proto_register_tetra (void)
{
	/* A header field is something you can search/filter on.
	*
	* We create a structure to register our fields. It consists of an
	* array of hf_register_info structures, each of which are of the format
	* {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
	*/
	static hf_register_info hf[] = {
		{ &hf_tetra,
		{ "Data", "tetra.data", FT_NONE, BASE_NONE, NULL, 0x0,
		"tetra PDU", HFILL }},
		{ &hf_tetra_header,
		{ "Registers", "tetra.header", FT_NONE, BASE_NONE, NULL, 0x0,
		 "TETRA Registers", HFILL }},
		{ &hf_tetra_channels,
		{ "Logical Channels", "tetra.channels", FT_UINT8, BASE_DEC, NULL, 0x0,
		"The amount of logical channels", HFILL }},
		{ &hf_tetra_channel1,
		{ "Channel 1", "tetra.txchannel1", FT_UINT8, BASE_DEC, VALS(channeltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_channel2,
		{ "Channel 2", "tetra.txchannel2", FT_UINT8, BASE_DEC, VALS(channeltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_channel3,
		{ "Channel 3", "tetra.txchannel3", FT_UINT8, BASE_DEC, VALS(channeltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_txreg,
		{ "TxR", "tetra.txreg", FT_UINT16, BASE_HEX, NULL, 0x0,
		 "TX Register", HFILL }},
		{ &hf_tetra_rvstr,
		{ "RvSteR", "tetra.rvster", FT_UINT16, BASE_HEX, NULL, 0x0,
		 "Receive Status Register", HFILL }},
		{ &hf_tetra_carriernumber,
		{ "Carrier Number", "tetra.carrier", FT_UINT16, BASE_HEX, NULL, 0x0,
		 "Carrier Number", HFILL }},
		{ &hf_tetra_rxchannel1,
		{ "Channel 1", "tetra.rxchannel1", FT_UINT8, BASE_DEC, VALS(recvchanneltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_rxchannel2,
		{ "Channel 2", "tetra.rxchannel2", FT_UINT8, BASE_DEC, VALS(recvchanneltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_timer,
		{ "Timer", "tetra.timer", FT_UINT16, BASE_HEX, NULL, 0x0,
		 "Timer Register", HFILL }},
		{ &hf_tetra_crc,
		{ "CRC", "tetra.crc", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
		 "CRC result", HFILL }},
		{ &hf_tetra_len0,
		{ "Length", "tetra.len0", FT_UINT16, BASE_DEC, NULL, 0x0,
		 "Length of the PDU", HFILL }},
		{ &hf_tetra_pdu,
		{ "PDU", "tetra.pdu", FT_BYTES, BASE_HEX, NULL, 0x0,
		 "PDU", HFILL }} ,

#include "packet-tetra-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		&ett_tetra,
		&ett_tetra_header,
		&ett_tetra_length,
		&ett_tetra_txreg,
		&ett_tetra_text,
#include "packet-tetra-ettarr.c"
  };

  if (proto_tetra == -1)
  {  /* execute protocol initialization only once */
     module_t *per_module;

	   proto_tetra = proto_register_protocol ("TETRA Protocol", "tetra", "tetra");

	   proto_register_field_array (proto_tetra, hf, array_length (hf));
	   proto_register_subtree_array (ett, array_length (ett));
	   register_dissector("tetra", dissect_tetra, proto_tetra);

     per_module = prefs_register_protocol(proto_tetra, NULL);
	 prefs_register_bool_preference(per_module, "include_carrier_number",
			  "The data include carrier numbers",
			  "Whether the captured data include carrier number",
			  &include_carrier_number);
	}
}

// Get the length of received pdu
gint get_rx_pdu_length(guint32 channel_type)
{
	gint len = 0;

	switch(channel_type)
	{
	case 1: // AACH
		len = 14;
		break;
	case 2: // SCH/F
		len = 268;
		break;
	case 3: // SCH/HD
		len = 124; ;
		break;
	case 5: // BSCH
		len = 60;
		break;
	case 6:	// BNCH
		len = 124;
		break;
	case 7: // TCH/F
		len = 274;
		break;
	case 8: // TCH/H
		len = 137;
		break;
	case 9: // TCH2.4
		len = 144;
		break;
	case 10: // TCH4.8
		len = 288;
		break;
	case 11: //STCH
		len = 124;
		break;
	case 15: // SCH/HU
		len = 92;
		break;
	default:
		len = 0;
		break;
	}

	return len;
}

// Get the length of transmitted pdu
gint get_tx_pdu_length(guint32 channel_type)
{
	gint len = 0;

	switch(channel_type)
	{
	case 1: // AACH
		len = 14;
		break;
	case 2: // SCH/F
		len = 268;
		break;
	case 3: // SCH/HD
		len = 124;
		break;
	case 5: // BSCH
		len = 60;
		break;
	case 6:	// BNCH
		len = 124;
		break;
	case 7: // TCH/F
		len = 274;
		break;
	case 8: // TCH/H
		len = 137;
		break;
	case 9: // TCH/2.4
		len = 144;
		break;
	case 10: // TCH/4.8
		len = 288;
		break;
	case 11: // STCH
		len = 124;
		break;
	}

	return len;
}

void dissect_tetra_UNITDATA_IND(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tetra_tree, int offset)
{
	guint32 rxreg = 0;
	guint32 channels = 0, i;
	guint32 channel_type;
	gint pdu_offset = 0;
	proto_item *tetra_sub_item = NULL;
	proto_tree *tetra_header_tree = NULL, *tetra_sub_tree = NULL;
	const guint8* p;

	// Length
	tvb_memcpy(tvb, (guint8 *)&rxreg, offset, 4);
	tetra_sub_item = proto_tree_add_uint(tetra_tree, hf_tetra_len0, tvb, offset, 4, rxreg);

	// RvSteR
	offset += 4;
	tvb_memcpy(tvb, (guint8 *)&rxreg, offset, 4);
	tetra_sub_item = proto_tree_add_uint(tetra_tree, hf_tetra_rvstr, tvb, offset, 4, rxreg);

	// Logical channels
	channels = rxreg & 0x3;
	tetra_sub_item = proto_tree_add_uint( tetra_tree, hf_tetra_channels, tvb, offset, 4, channels );
	tetra_header_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);

	pdu_offset = offset + 4;
	for(i = 0; i < channels; i++)
	{
		gint hf_channel[] = {hf_tetra_rxchannel1, hf_tetra_rxchannel2};
		gint byte_len, bits_len, remaining_bits;

		// Channel type
		channel_type = (rxreg >> ((i + 1) * 4) ) & 0xf;
		proto_tree_add_uint( tetra_header_tree, hf_channel[i], tvb, offset, 4, channel_type);

		// CRC
		proto_tree_add_boolean( tetra_header_tree, hf_tetra_crc, tvb, offset, 4, !(rxreg >> (i + 2) & 0x01));

		// PDU
		bits_len = get_rx_pdu_length(channel_type);
		byte_len = bits_len >> 3;
		remaining_bits = bits_len % 8;
		if ((remaining_bits)!=0)
			byte_len++;
		tetra_sub_item = proto_tree_add_item( tetra_header_tree, hf_tetra_pdu, tvb, pdu_offset, byte_len, FALSE );
		if(!(rxreg >> (i + 2) & 0x01)) // CRC is true
		{
			tetra_sub_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);
			switch(channel_type)
			{
			case 15: // SCH/HU
				p = tvb_get_ptr(tvb, pdu_offset, 1);
				switch(p[0]>>7)
				{
				case 0: //MAC-ACCESS

					dissect_MAC_ACCESS_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree);
					break;
				case 1: //MAC-END-HU
					dissect_MAC_END_HU_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree);
					break;
				}
				break;
			case 2: // SCH/F
				p = tvb_get_ptr(tvb, pdu_offset, 1);
				switch(p[0] >> 6)
				{
				case 0: // MAC-DATA
					dissect_MAC_DATA_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree);
				case 1: // MAC-FRAG and MAC-END
					if((p[0] >> 5) == 3)
						dissect_MAC_END_UPLINK_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree);
					else
						dissect_MAC_FRAG_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree);
					break;
				}
				break;
			case 11: // STCH
				p = tvb_get_ptr(tvb, pdu_offset, 1);
				switch(p[0] >> 6)
				{
				case 0: // MAC-DATA
					dissect_MAC_DATA_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree);
					break;
				case 1: // MAC-FRAG and MAC-END
					if((p[0] >> 5) == 3)
						dissect_MAC_END_UP114_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree);

					else
						dissect_MAC_FRAG120_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree);
					break;
				}
				break;
			}
		} // if(!(rxreg >> (i + 2) & 0x01))

		if ((remaining_bits)!=0)
			byte_len--;
		pdu_offset += byte_len;
	}
}

void dissect_tetra_UNITDATA_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tetra_tree, int offset, gboolean dissect)
{
	guint32 txreg = 0;
	guint32 channels = 0, i;
	guint32 channel_type;
	gint pdu_offset = 0;
	proto_item *tetra_sub_item = NULL;
	proto_tree *tetra_header_tree = NULL, *tetra_sub_tree = NULL;
	const guint8* p;

	// TxR
	tvb_memcpy(tvb, (guint8 *)&txreg, offset, 4);
	tetra_sub_item = proto_tree_add_uint(tetra_tree, hf_tetra_txreg, tvb, offset, 4, txreg);

	// Logical channels
	channels = (txreg & 0x3) + 1;
	tetra_sub_item = proto_tree_add_uint( tetra_tree, hf_tetra_channels, tvb, offset, 4, channels );
	tetra_header_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);
	txreg >>= 2;
	// Skip 0000B
	if(channels == 2)
		txreg >>= 4;

	pdu_offset = offset + 4;
	for(i = 0; i < channels; i++)
	{
		gint hf_channel[] = {hf_tetra_channel1, hf_tetra_channel2, hf_tetra_channel3};
		gint byte_len, bits_len, remaining_bits;

		channel_type = txreg & 0xf;
		proto_tree_add_uint( tetra_header_tree, hf_channel[i], tvb, offset, 4, channel_type);
		txreg >>= 4;
		// PDU
		bits_len = get_tx_pdu_length(channel_type);
		byte_len = bits_len >> 3;
		remaining_bits = bits_len % 8;
		if ((remaining_bits)!=0)
				byte_len++;
		tetra_sub_item = proto_tree_add_item( tetra_header_tree, hf_tetra_pdu, tvb, pdu_offset, byte_len, FALSE );
		if(dissect)
		{
			tetra_sub_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);
			switch(channel_type)
			{
			case 1: // AACH
				dissect_AACH_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
				break;
			case 2: // SCH/F
				p = tvb_get_ptr(tvb, pdu_offset, 1);
				switch(p[0] >> 6)
				{
				case 0:
					dissect_MAC_RESOURCE_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					break;
				case 1: // MAC-FRAG or MAC-END
					if((p[0] >> 5) == 3)
						dissect_MAC_END_DOWNLINK_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					else
						dissect_MAC_FRAG_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					break;
				case 2:
					dissect_MAC_ACCESS_DEFINE_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					break;
				}
				break;
			case 3: // SCH/HD
				p = tvb_get_ptr(tvb, pdu_offset, 1);
				switch(p[0] >> 6)
				{
				case 0:
					dissect_MAC_RESOURCE_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					break;
				case 1: // MAC-FRAG or MAC-END
					if((p[0] >> 5) == 3)
						dissect_MAC_END_DOWN111_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					else
						dissect_MAC_FRAG120_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					break;
				case 2:
					dissect_MAC_ACCESS_DEFINE_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					break;
				}
				break;
			case 5: // BSCH
				dissect_BSCH_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
				break;
			case 6: // BNCH
				dissect_BNCH_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
				break;
			case 11: // STCH
				p = tvb_get_ptr(tvb, pdu_offset, 1);
				switch(p[0] >> 6)
				{
				case 0:
					dissect_MAC_RESOURCE_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					break;
				case 1: // MAC-FRAG or MAC-END
					if((p[0] >> 5) == 3)
						dissect_MAC_END_DOWN111_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					else
						dissect_MAC_FRAG120_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					break;
				case 2:
					dissect_MAC_ACCESS_DEFINE_PDU(tvb, pdu_offset << 3, pinfo, tetra_sub_tree );
					break;
				}
				break;
			}
		} // if(dissect)

		//if ((remaining_bits)!=0)
				//byte_len--;
		pdu_offset += byte_len;
	}
}

static void
dissect_tetra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	proto_item *tetra_item = NULL;
	proto_item *tetra_sub_item = NULL;
	proto_tree *tetra_tree = NULL;
	proto_tree *tetra_header_tree = NULL;
	guint16 type = 0;
	guint16 carriernumber = -1;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_tetra);
	/* Clear out stuff in the info column */
	if(check_col(pinfo->cinfo,COL_INFO)){
		col_clear(pinfo->cinfo,COL_INFO);
	}

	// This is not a good way of dissecting packets.  The tvb length should
	// be sanity checked so we aren't going past the actual size of the buffer.
//	type = tvb_get_guint8( tvb, 1 ); // Get the type byte
	tvb_memcpy(tvb, (guint8 *)&type, 0, 1);

	if(include_carrier_number)
		tvb_memcpy(tvb, (guint8 *)&carriernumber, 1, 1);


	if (check_col(pinfo->cinfo, COL_INFO)) {
		switch(type)
		{
		case 1:
			if(include_carrier_number)
				col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-REQ, Carrier: %d",
						pinfo->srcport, pinfo->destport, carriernumber);
			else
				col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-REQ",
						pinfo->srcport, pinfo->destport);
			break;
		case 2:
			if(include_carrier_number)
				col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-IND, Carrier: %d",
						pinfo->srcport, pinfo->destport, carriernumber);
			else
				col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-IND",
						pinfo->srcport, pinfo->destport);
			break;
		case 3:
			if(include_carrier_number)
				col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d MAC-Timer, Carrier: %d",
						pinfo->srcport, pinfo->destport, carriernumber);
			else
				col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d MAC-Timer",
						pinfo->srcport, pinfo->destport);
			break;
		case 127:
			if(include_carrier_number)
				col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-IND Done, Carrier: %d",
						pinfo->srcport, pinfo->destport, carriernumber);
			else
				col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-IND Done",
						pinfo->srcport, pinfo->destport);
			break;
		case 128:
			if(include_carrier_number)
				col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-REQ Done, Carrier: %d",
						pinfo->srcport, pinfo->destport, carriernumber);
		  else
				col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d tetra-UNITDATA-REQ Done",
						pinfo->srcport, pinfo->destport);
			break;
		default:
			col_add_fstr(pinfo->cinfo, COL_INFO, "%d > %d Unkown command: %d",
					pinfo->srcport, pinfo->destport, type);
			break;
		}
	}

	if (tree) { /* we are being asked for details */
		guint32 offset = 0;
		guint32 txtimer = 0;
		guint32 tslot = 0;

		tetra_item = proto_tree_add_item(tree, proto_tetra, tvb, 0, -1, FALSE);
		tetra_tree = proto_item_add_subtree(tetra_item, ett_tetra);
		tetra_header_tree = proto_item_add_subtree(tetra_item, ett_tetra);

		offset ++;

		// Carrier number
		if(include_carrier_number)
		{
			tetra_sub_item = proto_tree_add_uint(tetra_tree, hf_tetra_carriernumber, tvb, offset, 1, carriernumber);
			offset ++;
		}

		// Registers
		tetra_sub_item = proto_tree_add_item( tetra_tree, hf_tetra_header, tvb, offset, -1, FALSE );
		tetra_header_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);

		// Timer
		tvb_memcpy(tvb, (guint8 *)&txtimer, offset, 4);
		tetra_sub_item = proto_tree_add_item(tetra_header_tree, hf_tetra_timer, tvb, offset, 4, TRUE);
		tslot = ((txtimer & 0x7800) >> 11);
		if(tslot==4)
			tslot = 3;
		if(tslot==8)
			tslot = 4;
		proto_item_append_text(tetra_sub_item, " (Multiple frame: %d, Frame: %d, Slot: %d)",
													txtimer & 0x3F, (txtimer & 0x7c0) >> 6,
													tslot);

		offset += 4;

		switch(type)
		{
		case 1: // tetra-UNITDATA-REQ
		case 128: // tetra-UNITDATA-REQ Done
			dissect_tetra_UNITDATA_REQ(tvb, pinfo, tetra_header_tree, offset, 1);
			break;
		case 2: // tetra-UNITDATA-IND
		case 127: // tetra-UNITDATA-IND Done
			dissect_tetra_UNITDATA_IND(tvb, pinfo, tetra_header_tree, offset);
			break;
		case 3: // MAC-Timer
			break;
		default:
			break;
		}
	}
}
