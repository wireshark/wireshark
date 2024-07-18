/* Packet-rdp_snd.c
 * Routines for the audio output RDP channel
 * Copyright 2023, David Fort <contact@hardening-consulting.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * See: "[MS-RDPEA] "
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/value_string.h>

#include "packet-rdpudp.h"

#define PNAME  "RDP audio output virtual channel Protocol"
#define PSNAME "rdpsnd"
#define PFNAME "rdp_snd"

void proto_register_rdp_snd(void);
void proto_reg_handoff_rdp_snd(void);


static int proto_rdp_snd;

static int hf_snd_msgType;
static int hf_snd_bPad;
static int hf_snd_bodySize;

static int ett_rdp_snd;


enum {
	SNDC_CLOSE = 0x01,
	SNDC_WAVE = 0x02,
	SNDC_SETVOLUME = 0x03,
	SNDC_SETPITCH = 0x04,
	SNDC_WAVECONFIRM = 0x05,
	SNDC_TRAINING = 0x06,
	SNDC_FORMATS = 0x07,
	SNDC_CRYPTKEY = 0x08,
	SNDC_WAVEENCRYPT = 0x09,
	SNDC_UDPWAVE = 0x0A,
	SNDC_UDPWAVELAST = 0x0B,
	SNDC_QUALITYMODE = 0x0C,
	SNDC_WAVE2 = 0x0D,
};


static const value_string rdp_snd_order_vals[] = {
	{ SNDC_CLOSE, "Close"},
	{ SNDC_WAVE, "Wave"},
	{ SNDC_SETVOLUME, "Set volume"},
	{ SNDC_SETPITCH, "Set pitch"},
	{ SNDC_WAVECONFIRM, "Wave confirm"},
	{ SNDC_TRAINING, "Training"},
	{ SNDC_FORMATS, "Formats"},
	{ SNDC_CRYPTKEY, "Crypt key"},
	{ SNDC_WAVEENCRYPT, "Wave encrypt"},
	{ SNDC_UDPWAVE, "Udp wave"},
	{ SNDC_UDPWAVELAST, "Udp wave last"},
	{ SNDC_QUALITYMODE, "Quality mode"},
	{ SNDC_WAVE2, "Wave 2"},
	{ 0x0, NULL},
};


static int
dissect_rdp_snd(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *parent_tree _U_, void *data _U_)
{
	proto_item *item;
	int nextOffset, offset = 0;
	uint32_t cmdId = 0;
	uint32_t pduLength;
	proto_tree *tree;

	parent_tree = proto_tree_get_root(parent_tree);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDPSND");
	col_clear(pinfo->cinfo, COL_INFO);

	pduLength = tvb_get_uint32(tvb, offset + 2, ENC_LITTLE_ENDIAN) + 4;
	nextOffset = offset + pduLength;

	item = proto_tree_add_item(parent_tree, proto_rdp_snd, tvb, offset, pduLength, ENC_NA);
	tree = proto_item_add_subtree(item, ett_rdp_snd);

	proto_tree_add_item_ret_uint(tree, hf_snd_msgType, tvb, offset, 1, ENC_LITTLE_ENDIAN, &cmdId);
	offset += 1;

	proto_tree_add_item(tree, hf_snd_bPad, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_snd_bodySize, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	//offset += 2;

	col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const(cmdId, rdp_snd_order_vals, "Unknown rdpsnd command"));

	switch (cmdId) {
	case SNDC_CLOSE:
	case SNDC_WAVE:
	case SNDC_SETVOLUME:
	case SNDC_SETPITCH:
	case SNDC_WAVECONFIRM:
	case SNDC_TRAINING:
	case SNDC_FORMATS:
	case SNDC_CRYPTKEY:
	case SNDC_WAVEENCRYPT:
	case SNDC_UDPWAVE:
	case SNDC_UDPWAVELAST:
	case SNDC_QUALITYMODE:
	case SNDC_WAVE2:
	default:
		break;
	}

	offset = nextOffset;
	return offset;
}


void proto_register_rdp_snd(void) {
	static hf_register_info hf[] = {
		{ &hf_snd_msgType,
		  { "MsgrType", "rdp_snd.msgtype",
		    FT_UINT8, BASE_HEX, VALS(rdp_snd_order_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_snd_bPad,
		  { "bPad", "rdp_snd.bpad",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_snd_bodySize,
		  { "BodySize", "rdp_snd.bodysize",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_rdp_snd,
	};

	proto_rdp_snd = proto_register_protocol(PNAME, PSNAME, PFNAME);

	/* Register fields and subtrees */
	proto_register_field_array(proto_rdp_snd, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("rdp_snd", dissect_rdp_snd, proto_rdp_snd);
}

void proto_reg_handoff_rdp_snd(void) {
}
