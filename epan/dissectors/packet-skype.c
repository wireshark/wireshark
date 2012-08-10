/* packet-skype.c
 * Routines for the disassembly of Skype
 *
 * $Id$
 *
 * Copyright 2009 Joerg Mayer (see AUTHORS file)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * https://github.com/matthiasbock/OpenSkype/wiki/Skype's-UDP-Format

  TODO:
  - Authentication
  - TCP
  - Conversation stuff (to obtain external IPs for decryption)
  - Decryption (with given keys)
  - CRC check
  - Heuristics to reliably detect Skype traffic - most likely impossible
    to implement in Wireshark (see http://en.wikipedia.org/wiki/Skype)
  - Improve tests
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

/* protocol handles */
static int proto_skype = -1;

/* ett handles */
static int ett_skype = -1;

#define SKYPE_SOM_UNK_MASK	0xF0
#define SKYPE_SOM_TYPE_MASK	0x0F

/* hf elements */
/* Start of Message */
static int hf_skype_som_id = -1;
static int hf_skype_som_unk = -1;
static int hf_skype_som_type = -1;
/* Message body */
/* Unknown_0 */
static int hf_skype_unknown_0_unk1 = -1;
/* Payload */
static int hf_skype_payload_iv = -1;
static int hf_skype_payload_crc = -1;
static int hf_skype_payload_enc_data = -1;
/* Resend */
static int hf_skype_ffr_num = -1;
static int hf_skype_ffr_unk1 = -1;
static int hf_skype_ffr_iv = -1;
static int hf_skype_ffr_crc = -1;
static int hf_skype_ffr_enc_data = -1;
/* Nat info */
static int hf_skype_natinfo_srcip = -1;
static int hf_skype_natinfo_unk1 = -1;
/* Nat request */
static int hf_skype_natrequest_srcip = -1;
static int hf_skype_natrequest_unk1 = -1;
/* Audio */
static int hf_skype_audio_unk1 = -1;
/* Unknown_f */
static int hf_skype_unknown_f_unk1 = -1;


#define PROTO_SHORT_NAME "SKYPE"
#define PROTO_LONG_NAME "SKYPE"

#define PORT_SKYPE_UDP	0
#if 0
#define PORT_SKYPE_TCP	0
#endif

typedef enum {
	SKYPE_TYPE_UNKNOWN_0 = 0,
	SKYPE_TYPE_PAYLOAD = 2,
	SKYPE_TYPE_FFR = 3,
	SKYPE_TYPE_NAT_INFO = 5,
	SKYPE_TYPE_NAT_REPEAT = 7,
	SKYPE_TYPE_AUDIO = 0xd,
	SKYPE_TYPE_UNKNOWN_F = 0xf,
} skype_type_t;


static const value_string skype_type_vals[] = {
	{ SKYPE_TYPE_UNKNOWN_0,	"Unknown_0" },
	{ SKYPE_TYPE_PAYLOAD,	"Payload" },
	{ SKYPE_TYPE_FFR,	"Fragment/Forward/Resend" },
	{ SKYPE_TYPE_NAT_INFO ,	"NAT info" },
	{ SKYPE_TYPE_NAT_REPEAT,"NAT repeat" },
	{ SKYPE_TYPE_AUDIO,	"Audio" },
	{ SKYPE_TYPE_UNKNOWN_F,	"Unknown_F" },

	{ 0,	NULL }
};

static int
dissect_skype(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *skype_tree = NULL;
	guint32 offset = 0;
	guint32 packet_length;
	guint8 packet_type, packet_unk;

	packet_type = tvb_get_guint8(tvb, 2) & SKYPE_SOM_TYPE_MASK;
	packet_unk = (tvb_get_guint8(tvb, 2) & SKYPE_SOM_UNK_MASK) >> 4;

	packet_length = tvb_length(tvb);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(packet_type,
		skype_type_vals, "Type 0x%1x"));
	if (packet_unk) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " Unk: %1x", packet_unk);
	}

	if (tree) {
		/* Start of message dissection */
		ti = proto_tree_add_item(tree, proto_skype, tvb, offset, -1,
		    ENC_NA);
		skype_tree = proto_item_add_subtree(ti, ett_skype);

		proto_tree_add_item(skype_tree, hf_skype_som_id, tvb, offset, 2,
			ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(skype_tree, hf_skype_som_unk, tvb, offset, 1,
			ENC_NA);
		proto_tree_add_item(skype_tree, hf_skype_som_type, tvb, offset, 1,
			ENC_NA);
		offset += 1;

		/* Body dissection */
		switch (packet_type) {

		case SKYPE_TYPE_UNKNOWN_0:
			proto_tree_add_item(skype_tree, hf_skype_unknown_0_unk1, tvb, offset, -1,
				ENC_NA);
			offset = packet_length;
			break;
		case SKYPE_TYPE_PAYLOAD:
			proto_tree_add_item(skype_tree, hf_skype_payload_iv, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(skype_tree, hf_skype_payload_crc, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(skype_tree, hf_skype_payload_enc_data, tvb, offset, -1,
				ENC_NA);
			offset = packet_length;
			break;
		case SKYPE_TYPE_FFR:
			proto_tree_add_item(skype_tree, hf_skype_ffr_num, tvb, offset, 1,
				ENC_NA);
			offset += 1;
			proto_tree_add_item(skype_tree, hf_skype_ffr_unk1, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(skype_tree, hf_skype_ffr_iv, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(skype_tree, hf_skype_ffr_crc, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(skype_tree, hf_skype_ffr_enc_data, tvb, offset, -1,
				ENC_NA);
			offset = packet_length;
			break;
		case SKYPE_TYPE_NAT_INFO:
			proto_tree_add_item(skype_tree, hf_skype_natinfo_srcip, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(skype_tree, hf_skype_natinfo_unk1, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case SKYPE_TYPE_NAT_REPEAT:
			proto_tree_add_item(skype_tree, hf_skype_natrequest_srcip, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(skype_tree, hf_skype_natrequest_unk1, tvb, offset, 4,
				ENC_BIG_ENDIAN);
			offset += 4;
			break;
		case SKYPE_TYPE_AUDIO:
			proto_tree_add_item(skype_tree, hf_skype_audio_unk1, tvb, offset, -1,
				ENC_NA);
			offset = packet_length;
			break;
		case SKYPE_TYPE_UNKNOWN_F:
			proto_tree_add_item(skype_tree, hf_skype_unknown_f_unk1, tvb, offset, -1,
				ENC_NA);
			offset = packet_length;
			break;
		default:
			/* Should not happen: Unkown types filtered in test_skype */
			break;
		}
	}
	return offset;
}

static gboolean
test_skype(tvbuff_t *tvb)
{
	/* Minimum of 3 bytes, check for valid message type */
	guint length = tvb_length(tvb);
	guint8 type = tvb_get_guint8(tvb, 2) & 0xF;
	if ( length >= 3 &&
		    ( type == 0   ||
			/* FIXME: Extend this by minimum length per message type */
		      type == 2   ||
		      type == 3   ||
		      type == 5   ||
		      type == 7   ||
		      type == 0xd ||
		      type == 0xf
		    )
	) {
		return TRUE;
	}
	return FALSE;
}

#if 0
static gboolean
dissect_skype_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if ( !test_skype(tvb) ) {
		return FALSE;
	}
	dissect_skype(tvb, pinfo, tree);
	return TRUE;
}
#endif

static int
dissect_skype_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if ( !test_skype(tvb) ) {
		return 0;
	}
	return dissect_skype(tvb, pinfo, tree);
}

void
proto_register_skype(void)
{
	static hf_register_info hf[] = {

	/* Start of message fields */
		{ &hf_skype_som_id,
		{ "ID",	"skype.som.id", FT_UINT16, BASE_HEX, NULL,
			0x0, "Message ID", HFILL }},

		{ &hf_skype_som_unk,
		{ "Unknown",	"skype.som.unk", FT_UINT8, BASE_HEX, NULL,
			SKYPE_SOM_UNK_MASK, NULL, HFILL }},

		{ &hf_skype_som_type,
		{ "Type",	"skype.som.type", FT_UINT8, BASE_HEX, VALS(skype_type_vals),
			SKYPE_SOM_TYPE_MASK, "Message type", HFILL }},

	/* Message body */

	/* Unknown_0 */
		{ &hf_skype_unknown_0_unk1,
		{ "Unknown1",   "skype.unknown_0.unk1", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	/* Payload */
		{ &hf_skype_payload_iv,
		{ "IV",   "skype.payload.iv", FT_UINT32, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_skype_payload_crc,
		{ "CRC",   "skype.payload.crc", FT_UINT32, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_skype_payload_enc_data,
		{ "Enc Data",   "skype.payload.encdata", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	/* Resend */
		{ &hf_skype_ffr_num,
		{ "Num",   "skype.ffr.num", FT_UINT8, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_skype_ffr_unk1,
		{ "Unk1",   "skype.ffr.unk1", FT_UINT32, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_skype_ffr_iv,
		{ "IV",   "skype.ffr.iv", FT_UINT32, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_skype_ffr_crc,
		{ "CRC",   "skype.ffr.crc", FT_UINT32, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

		{ &hf_skype_ffr_enc_data,
		{ "Enc Data",   "skype.ffr.encdata", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	/* Nat info */
		{ &hf_skype_natinfo_srcip,
		{ "Src IP",   "skype.natinfo.srcip", FT_IPv4, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_skype_natinfo_unk1,
		{ "Unknown1",   "skype.natinfo.unk1", FT_UINT32, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

	/* Nat request */
		{ &hf_skype_natrequest_srcip,
		{ "Src IP",   "skype.natrequest.srcip", FT_IPv4, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

		{ &hf_skype_natrequest_unk1,
		{ "Unknown1",   "skype.natrequest.unk1", FT_UINT32, BASE_HEX, NULL,
			0x0, NULL, HFILL }},

	/* Audio */
		{ &hf_skype_audio_unk1,
		{ "Unknown1",   "skype.audio.unk1", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	/* Unknown_F */
		{ &hf_skype_unknown_f_unk1,
		{ "Unknown1",   "skype.unknown_f.unk1", FT_BYTES, BASE_NONE, NULL,
			0x0, NULL, HFILL }},

	};
	static gint *ett[] = {
		&ett_skype,
	};

	proto_skype = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "skype");
	proto_register_field_array(proto_skype, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_skype(void)
{
	dissector_handle_t skype_handle;

	skype_handle = new_create_dissector_handle(dissect_skype_static, proto_skype);
	dissector_add_uint("udp.port", PORT_SKYPE_UDP, skype_handle);
#if 0
	dissector_add_uint("tcp.port", PORT_SKYPE_TCP, skype_handle);
	heur_dissector_add("udp", dissect_skype_heur, proto_skype);
#endif

}

