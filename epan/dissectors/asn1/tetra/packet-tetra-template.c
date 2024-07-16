/* packet-tetra.c
 * Routines for TETRA packet dissection
 *
 * Copyright (c) 2007 - 2011 Professional Mobile Communication Research Group,
 *    Beijing Institute of Technology, China
 * Copyright (c) 2011 Holger Hans Peter Freyther
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * REF: ETSI EN 300 392-2 V3.2.1
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/conversation.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-tetra.h"

#define PROTO_TAG_tetra	"TETRA"

void proto_register_tetra(void);
void proto_reg_handoff_tetra(void);

/* Wireshark ID of the tetra protocol */
static int proto_tetra;

static dissector_handle_t tetra_handle;

#define TETRA_UDP_PORT  7074 /* Not IANA assigned */

/* Whether the capture data include carrier numbers */
static bool include_carrier_number = true;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_tetra()
*/
/** Kts attempt at defining the protocol */
static int hf_tetra;
static int hf_tetra_header;
static int hf_tetra_channels;
static int hf_tetra_channel1;
static int hf_tetra_channel2;
static int hf_tetra_channel3;
static int hf_tetra_txreg;
static int hf_tetra_timer;
static int hf_tetra_pdu;
static int hf_tetra_rvstr;
static int hf_tetra_carriernumber;
static int hf_tetra_rxchannel1;
static int hf_tetra_rxchannel2;
static int hf_tetra_rxchannel3;
static int hf_tetra_crc;
static int hf_tetra_len0;

#include "packet-tetra-hf.c"

/* Initialize the subtree pointers */
/* These are the ids of the subtrees that we may be creating */
static int ett_tetra;
static int ett_tetra_header;
static int ett_tetra_length;
static int ett_tetra_txreg;
static int ett_tetra_text;

#include "packet-tetra-ett.c"

static expert_field ei_tetra_channels_incorrect;

#include "packet-tetra-fn.c"

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

/* Get the length of received pdu */
static int get_rx_pdu_length(uint32_t channel_type)
{
	int len = 0;

	switch(channel_type) {
	case TETRA_CHAN_AACH:
		len = 14;
		break;
	case TETRA_CHAN_SCH_F:
		len = 268;
		break;
	case TETRA_CHAN_SCH_D:
		len = 124; ;
		break;
	case TETRA_CHAN_BSCH:
		len = 60;
		break;
	case TETRA_CHAN_BNCH:
		len = 124;
		break;
	case TETRA_CHAN_TCH_F:
		len = 274;
		break;
	case TETRA_CHAN_TCH_H:
		len = 137;
		break;
	case TETRA_CHAN_TCH_2_4:
		len = 144;
		break;
	case TETRA_CHAN_TCH_4_8:
		len = 288;
		break;
	case TETRA_CHAN_STCH:
		len = 124;
		break;
	case TETRA_CHAN_SCH_HU:
		len = 92;
		break;
	default:
		len = 0;
		break;
	}

	return len;
}

/* Get the length of transmitted pdu */
static int get_tx_pdu_length(uint32_t channel_type)
{
	int len = 0;

	switch(channel_type) {
	case TETRA_CHAN_AACH:
		len = 14;
		break;
	case TETRA_CHAN_SCH_F:
		len = 268;
		break;
	case TETRA_CHAN_SCH_D:
		len = 124;
		break;
	case TETRA_CHAN_BSCH:
		len = 60;
		break;
	case TETRA_CHAN_BNCH:
		len = 124;
		break;
	case TETRA_CHAN_TCH_F:
		len = 274;
		break;
	case TETRA_CHAN_TCH_H:
		len = 137;
		break;
	case TETRA_CHAN_TCH_2_4:
		len = 144;
		break;
	case TETRA_CHAN_TCH_4_8:
		len = 288;
		break;
	case TETRA_CHAN_STCH:
		len = 124;
		break;
	}

	return len;
}

void tetra_dissect_pdu(int channel_type, int dir, tvbuff_t *pdu, proto_tree *tree, packet_info *pinfo)
{
	proto_item *tetra_sub_item;
	proto_tree *tetra_sub_tree;
	uint8_t p;

	tetra_sub_item = proto_tree_add_item(tree, hf_tetra_pdu,
					     pdu, 0, tvb_captured_length(pdu), ENC_NA);

	tetra_sub_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);

	switch(channel_type) {
	case TETRA_CHAN_AACH:
		dissect_AACH_PDU(pdu, pinfo, tetra_sub_tree, NULL);
		break;
	case TETRA_CHAN_SCH_F:
		p = tvb_get_uint8(pdu, 0);
		switch(p >> 6) {
		case 0:
			if (dir == TETRA_DOWNLINK)
				dissect_MAC_RESOURCE_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			else
				dissect_MAC_DATA_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			break;
		case 1: /* MAC-FRAG or MAC-END */
			if((p >> 5) == 3) {
				if (dir == TETRA_DOWNLINK)
					dissect_MAC_END_DOWNLINK_PDU(pdu, pinfo, tetra_sub_tree, NULL);
				else
					dissect_MAC_END_UPLINK_PDU(pdu, pinfo, tetra_sub_tree, NULL);

			} else
				dissect_MAC_FRAG_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			break;
		case 2:
			dissect_MAC_ACCESS_DEFINE_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			break;
		}
		break;
	case TETRA_CHAN_SCH_D:
		p = tvb_get_uint8(pdu, 0);
		switch(p >> 6) {
		case 0:
			dissect_MAC_RESOURCE_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			break;
		case 1: /* MAC-FRAG or MAC-END */
			if((p >> 5) == 3)
				dissect_MAC_END_DOWN111_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			else
				dissect_MAC_FRAG120_PDU(pdu, pinfo, tetra_sub_tree, NULL);
		break;
		case 2:
			dissect_MAC_ACCESS_DEFINE_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			break;
		}
		break;
	case TETRA_CHAN_SCH_HU:
		p = tvb_get_uint8(pdu, 0);
		switch(p >> 7) {
		case 0: /* MAC-ACCESS */
			dissect_MAC_ACCESS_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			break;
		case 1: /* MAC-END-HU */
			dissect_MAC_END_HU_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			break;
		}
		break;
	case TETRA_CHAN_BSCH:
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "BSCH");
		dissect_BSCH_PDU(pdu, pinfo, tetra_sub_tree, NULL);
		break;
	case TETRA_CHAN_BNCH:
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "BNCH");
		dissect_BNCH_PDU(pdu, pinfo, tetra_sub_tree, NULL);
		break;
	case TETRA_CHAN_STCH:
		p = tvb_get_uint8(pdu, 0);
		switch(p >> 6) {
		case 0:
			dissect_MAC_RESOURCE_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			break;
		case 1: /* MAC-FRAG or MAC-END */
			if((p >> 5) == 3) {
				if (dir == TETRA_DOWNLINK)
					dissect_MAC_END_DOWN111_PDU(pdu, pinfo, tetra_sub_tree, NULL);
				else
					dissect_MAC_END_UP114_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			} else
				dissect_MAC_FRAG120_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			break;
		case 2:
			dissect_MAC_ACCESS_DEFINE_PDU(pdu, pinfo, tetra_sub_tree, NULL);
			break;
		}
		break;
	case TETRA_CHAN_TCH_F:
		col_append_sep_str(pinfo->cinfo, COL_INFO, NULL, "Voice");
		break;
	}
}

static void dissect_tetra_UNITDATA_IND(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tetra_tree, int offset)
{
	uint32_t rxreg = 0;
	uint32_t channels = 0, i;
	uint32_t channel_type;
	int pdu_offset = 0;
	proto_item *tetra_sub_item;
	proto_tree *tetra_header_tree = NULL;
	tvbuff_t *payload_tvb;

	/* Length */
	rxreg = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tetra_tree, hf_tetra_len0, tvb, offset, 4, rxreg);

	/* RvSteR */
	offset += 4;
	rxreg = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tetra_tree, hf_tetra_rvstr, tvb, offset, 4, rxreg);

	/* Logical channels */
	channels = rxreg & 0x3;
	tetra_sub_item = proto_tree_add_uint( tetra_tree, hf_tetra_channels, tvb, offset, 4, channels );
	tetra_header_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);
	if (channels > 3) {
		expert_add_info(pinfo, tetra_sub_item, &ei_tetra_channels_incorrect);
		channels = 3;
	}

	pdu_offset = offset + 4;
	for(i = 0; i < channels; i++) {
		int byte_len, bits_len, remaining_bits;
		int hf_channel[3];

		hf_channel[0] = hf_tetra_rxchannel1;
		hf_channel[1] = hf_tetra_rxchannel2;
		hf_channel[2] = hf_tetra_rxchannel3;

		/* Channel type */
		channel_type = (rxreg >> ((i + 1) * 4) ) & 0xf;
		proto_tree_add_uint( tetra_header_tree, hf_channel[i], tvb, offset, 4, channel_type);

		/* CRC */
		proto_tree_add_boolean( tetra_header_tree, hf_tetra_crc, tvb, offset, 4, !(rxreg >> (i + 2) & 0x01));

		/* PDU */
		bits_len = get_rx_pdu_length(channel_type);
		byte_len = bits_len >> 3;
		remaining_bits = bits_len % 8;
		if ((remaining_bits)!=0)
			byte_len++;

		payload_tvb = tvb_new_subset_length(tvb, pdu_offset, byte_len);
		tetra_dissect_pdu(channel_type, TETRA_UPLINK, payload_tvb, tetra_header_tree, pinfo);

		if ((remaining_bits)!=0)
			byte_len--;
		pdu_offset += byte_len;
	}
}

static void dissect_tetra_UNITDATA_REQ(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tetra_tree, int offset)
{
	uint32_t txreg = 0;
	uint32_t channels = 0, i;
	uint32_t channel_type;
	int pdu_offset = 0;
	proto_item *tetra_sub_item = NULL;
	proto_tree *tetra_header_tree = NULL;
	tvbuff_t *payload_tvb;

	/* TxR */
	txreg = tvb_get_letohl(tvb, offset);
	proto_tree_add_uint(tetra_tree, hf_tetra_txreg, tvb, offset, 4, txreg);

	/* Logical channels */
	channels = (txreg & 0x3) + 1;
	tetra_sub_item = proto_tree_add_uint( tetra_tree, hf_tetra_channels, tvb, offset, 4, channels );
	tetra_header_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);
	txreg >>= 2;
	/* Skip 0000B */
	if(channels == 2)
		txreg >>= 4;

	if (channels > 3) {
		expert_add_info(pinfo, tetra_sub_item, &ei_tetra_channels_incorrect);
		channels = 3;
	}

	pdu_offset = offset + 4;
	for(i = 0; i < channels; i++) {
		int byte_len, bits_len, remaining_bits;
		int hf_channel[3];

		hf_channel[0] = hf_tetra_channel1;
		hf_channel[1] = hf_tetra_channel2;
		hf_channel[2] = hf_tetra_channel3;

		channel_type = txreg & 0xf;
		proto_tree_add_uint( tetra_header_tree, hf_channel[i], tvb, offset, 4, channel_type);
		txreg >>= 4;
		/* PDU */
		bits_len = get_tx_pdu_length(channel_type);
		byte_len = bits_len >> 3;
		remaining_bits = bits_len % 8;
		if ((remaining_bits)!=0)
				byte_len++;

		payload_tvb = tvb_new_subset_length(tvb, pdu_offset, byte_len);
		tetra_dissect_pdu(channel_type, TETRA_DOWNLINK, payload_tvb, tetra_header_tree, pinfo);
		pdu_offset += byte_len;
	}
}

static int
dissect_tetra(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *tetra_item = NULL;
	proto_item *tetra_sub_item = NULL;
	proto_tree *tetra_tree = NULL;
	proto_tree *tetra_header_tree = NULL;
	uint16_t type = 0;
	uint8_t carriernumber = -1;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_tetra);
	/* Clear out stuff in the info column */
	col_clear(pinfo->cinfo,COL_INFO);

	/*
	 * This is not a good way of dissecting packets.  The tvb length should
	 * be sanity checked so we aren't going past the actual size of the buffer.
	 */
	type = tvb_get_uint8(tvb, 0);

	if(include_carrier_number) {
		carriernumber = tvb_get_uint8(tvb, 1);
	}


	switch(type) {
	case 1:
		if(include_carrier_number)
			col_add_fstr(pinfo->cinfo, COL_INFO, "Tetra-UNITDATA-REQ, Carrier: %d",
					carriernumber);
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "Tetra-UNITDATA-REQ");
		break;
	case 2:
		if(include_carrier_number)
			col_add_fstr(pinfo->cinfo, COL_INFO, "Tetra-UNITDATA-IND, Carrier: %d",
					carriernumber);
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "Tetra-UNITDATA-IND");
		break;
	case 3:
		if(include_carrier_number)
			col_add_fstr(pinfo->cinfo, COL_INFO, "MAC-Timer, Carrier: %d",
					carriernumber);
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "MAC-Timer");
		break;
	case 127:
		if(include_carrier_number)
			col_add_fstr(pinfo->cinfo, COL_INFO, "Tetra-UNITDATA-IND Done, Carrier: %d",
					carriernumber);
		else
			col_add_fstr(pinfo->cinfo, COL_INFO, "Tetra-UNITDATA-IND Done");
		break;
	case 128:
		if(include_carrier_number)
			col_add_fstr(pinfo->cinfo, COL_INFO, "Tetra-UNITDATA-REQ Done, Carrier: %d",
					carriernumber);
	  else
			col_add_fstr(pinfo->cinfo, COL_INFO, "Tetra-UNITDATA-REQ Done");
		break;
	default:
		col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown command: %d", type);
		break;
	}

	/* if (tree) */ { /* we are being asked for details */
		uint32_t offset = 0;
		uint32_t txtimer = 0;
		uint32_t tslot = 0;

		tetra_item = proto_tree_add_item(tree, proto_tetra, tvb, 0, -1, ENC_NA);
		tetra_tree = proto_item_add_subtree(tetra_item, ett_tetra);

		offset ++;

		/* Carrier number */
		if(include_carrier_number) {
			proto_tree_add_uint(tetra_tree, hf_tetra_carriernumber, tvb, offset, 1, carriernumber);
			offset ++;
		}

		/* Registers */
		tetra_sub_item = proto_tree_add_item( tetra_tree, hf_tetra_header, tvb, offset, -1, ENC_NA );
		tetra_header_tree = proto_item_add_subtree(tetra_sub_item, ett_tetra);

		/* Timer */
		txtimer = tvb_get_letohl(tvb, offset);
		tetra_sub_item = proto_tree_add_item(tetra_header_tree, hf_tetra_timer, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		tslot = ((txtimer & 0x7800) >> 11);
		if(tslot==4)
			tslot = 3;
		if(tslot==8)
			tslot = 4;
		proto_item_append_text(tetra_sub_item, " (Multiple frame: %d, Frame: %d, Slot: %d)",
													txtimer & 0x3F, (txtimer & 0x7c0) >> 6,
													tslot);

		offset += 4;

		switch(type) {
		case 1: /* tetra-UNITDATA-REQ */
		case 128: /* tetra-UNITDATA-REQ Done */
			dissect_tetra_UNITDATA_REQ(tvb, pinfo, tetra_header_tree, offset);
			break;
		case 2: /* tetra-UNITDATA-IND */
		case 127: /* tetra-UNITDATA-IND Done */
			dissect_tetra_UNITDATA_IND(tvb, pinfo, tetra_header_tree, offset);
			break;
		case 3: /* MAC-Timer */
			break;
		default:
			break;
		}
	}
	return tvb_captured_length(tvb);
}

void proto_reg_handoff_tetra(void)
{
	dissector_add_uint_with_preference("udp.port", TETRA_UDP_PORT, tetra_handle);
}


void proto_register_tetra (void)
{
	module_t *tetra_module;
	expert_module_t* expert_tetra;

	/*
	 * A header field is something you can search/filter on.
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
		{ "TxR", "tetra.txreg", FT_UINT32, BASE_HEX, NULL, 0x0,
		 "TX Register", HFILL }},
		{ &hf_tetra_rvstr,
		{ "RvSteR", "tetra.rvster", FT_UINT32, BASE_HEX, NULL, 0x0,
		 "Receive Status Register", HFILL }},
		{ &hf_tetra_carriernumber,
		{ "Carrier Number", "tetra.carrier", FT_UINT8, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},
		{ &hf_tetra_rxchannel1,
		{ "Channel 1", "tetra.rxchannel1", FT_UINT8, BASE_DEC, VALS(recvchanneltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_rxchannel2,
		{ "Channel 2", "tetra.rxchannel2", FT_UINT8, BASE_DEC, VALS(recvchanneltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_rxchannel3,
		{ "Channel 3", "tetra.rxchannel3", FT_UINT8, BASE_DEC, VALS(recvchanneltypenames), 0x0,
		"Logical channels type", HFILL }},
		{ &hf_tetra_timer,
		{ "Timer", "tetra.timer", FT_UINT32, BASE_HEX, NULL, 0x0,
		 "Timer Register", HFILL }},
		{ &hf_tetra_crc,
		{ "CRC", "tetra.crc", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		 "CRC result", HFILL }},
		{ &hf_tetra_len0,
		{ "Length", "tetra.len0", FT_UINT32, BASE_DEC, NULL, 0x0,
		 "Length of the PDU", HFILL }},
		{ &hf_tetra_pdu,
		{ "PDU", "tetra.pdu", FT_BYTES, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }} ,

#include "packet-tetra-hfarr.c"
 	};

	/* List of subtrees */
	static int *ett[] = {
		&ett_tetra,
		&ett_tetra_header,
		&ett_tetra_length,
		&ett_tetra_txreg,
		&ett_tetra_text,
#include "packet-tetra-ettarr.c"
	};

	static ei_register_info ei[] = {
		{ &ei_tetra_channels_incorrect, { "tetra.channels.incorrect", PI_MALFORMED, PI_WARN, "Channel count incorrect, must be <= 3", EXPFILL }},
	};

	proto_tetra = proto_register_protocol("TETRA Protocol", "TETRA", "tetra");
	proto_register_field_array (proto_tetra, hf, array_length (hf));
	proto_register_subtree_array (ett, array_length (ett));
	tetra_handle = register_dissector("tetra", dissect_tetra, proto_tetra);
	expert_tetra = expert_register_protocol(proto_tetra);
	expert_register_field_array(expert_tetra, ei, array_length(ei));

	tetra_module = prefs_register_protocol(proto_tetra, NULL);
	prefs_register_bool_preference(tetra_module, "include_carrier_number",
			"The data include carrier numbers",
			"Whether the captured data include carrier number",
			&include_carrier_number);
}
