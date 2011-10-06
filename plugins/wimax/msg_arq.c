/* msg_arq.c
 * WiMax MAC Management ARQ Feedback, Discard, Reset Message decoders
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: John R. Underwood <junderx@yahoo.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "moduleinfo.h"

#include <glib.h>
#include <epan/packet.h>
#include "crc.h"
#include "wimax_tlv.h"
#include "wimax_mac.h"

extern gint man_ofdma;

/* Forward reference */
void dissect_mac_mgmt_msg_arq_feedback_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_mac_mgmt_msg_arq_discard_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void dissect_mac_mgmt_msg_arq_reset_decoder(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gint proto_mac_mgmt_msg_arq_feedback_decoder = -1;
static gint proto_mac_mgmt_msg_arq_discard_decoder = -1;
static gint proto_mac_mgmt_msg_arq_reset_decoder = -1;

static gint ett_mac_mgmt_msg_arq_decoder = -1;

/* Setup protocol subtree array */
static gint *ett[] =
{
	&ett_mac_mgmt_msg_arq_decoder,
};


/* ARQ fields */
static gint hf_arq_cid			= -1;
static gint hf_arq_last			= -1;
static gint hf_arq_ack_type		= -1;
static gint hf_ack_type_reserved	= -1;
static gint hf_arq_bsn			= -1;
static gint hf_arq_num_ack_maps		= -1;
static gint hf_arq_selective_map	= -1;
static gint hf_arq_seq_format		= -1;
static gint hf_arq_0seq_ack_map		= -1;
static gint hf_arq_0seq1_len		= -1;
static gint hf_arq_0seq2_len		= -1;
static gint hf_arq_1seq_ack_map		= -1;
static gint hf_arq_1seq1_len		= -1;
static gint hf_arq_1seq2_len		= -1;
static gint hf_arq_1seq3_len		= -1;
static gint hf_arq_reserved		= -1;

static gint hf_arq_discard_cid		= -1;
static gint hf_arq_discard_reserved	= -1;
static gint hf_arq_discard_bsn		= -1;

static gint hf_arq_reset_cid		= -1;
static gint hf_arq_reset_type		= -1;
static gint hf_arq_reset_direction	= -1;
static gint hf_arq_reset_reserved	= -1;

static gint hf_arq_message_type = -1;

/* STRING RESOURCES */

static const true_false_string tfs_present = {
	"present",
	"absent"
};

static const true_false_string tfs_rng_req_aas_broadcast = {
	"SS cannot receive broadcast messages",
	"SS can receive broadcast messages"
};

static const true_false_string tfs_arq_last = {
	"Last ARQ feedback IE in the list",
	"More ARQ feedback IE in the list"
};

static const value_string vals_arq_ack_type[] = {
	{0,				"Selective ACK entry"},
	{1,				"Cumulative ACK entry"},
	{2,				"Cumulative with Selective ACK entry"},
	{3,				"Cumulative ACK with Block Sequence Ack entry"},
	{0,				NULL}
};

static const value_string vals_arq_reset_type[] = {
	{0,				"Original message from Initiator"},
	{1,				"Acknowledgment from Responder"},
	{2,				"Confirmation from Initiator"},
	{3,				"Reserved"},
	{0,				NULL}
};

static const value_string vals_arq_reset_direction[] = {
	{0,				"Uplink or downlink"},
	{1,				"Uplink"},
	{2,				"Downlink"},
	{3,				"Reserved"},
	{0,				NULL}
};

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_arq_feedback(void)
{
	/* ARQ fields display */
	static hf_register_info hf[] =
	{
		/* TODO: Make three separate arq message types */
		{
			&hf_arq_message_type,
			{
				"MAC Management Message Type", "wmx.macmgtmsgtype.arq",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_arq_ack_type,
			{
				"ACK Type", "wmx.arq.ack_type",
				FT_UINT8, BASE_DEC, VALS(vals_arq_ack_type), 0x60, NULL, HFILL
			}
		},
		{
			&hf_arq_bsn,
			{
				"BSN", "wmx.arq.bsn",
				FT_UINT16, BASE_DEC, NULL, 0x1FFC, NULL, HFILL
			}
		},
		{
			&hf_arq_cid,
			{
				"Connection ID", "wmx.arq.cid",
				FT_UINT16, BASE_DEC, NULL, 0x00, "The ID of the connection being referenced", HFILL
			}
		},
		{
			&hf_arq_discard_bsn,
			{
				"BSN", "wmx.arq.discard_bsn",
				FT_UINT16, BASE_DEC, NULL, 0x07FF, NULL, HFILL
			}
		},
		{
			&hf_arq_discard_cid,
			{
				"Connection ID", "wmx.arq.discard_cid",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_arq_discard_reserved,
			{
				"Reserved", "wmx.arq.discard_reserved",
				FT_UINT8, BASE_DEC, NULL, 0xF8, NULL, HFILL
			}
		},
		{
			&hf_arq_last,
			{
				"LAST", "wmx.arq.last",
				FT_BOOLEAN, 8, TFS(&tfs_arq_last), 0x80, NULL, HFILL
			}
		},
		{
			&hf_arq_num_ack_maps,
			{
				"Number of ACK Maps", "wmx.arq.num_maps",
				FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL
			}
		},
		{
			&hf_arq_reserved,
			{
				"Reserved", "wmx.arq.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL
			}
		},
		{
			&hf_arq_reset_cid,
			{
				"Connection ID", "wmx.arq.reset_cid",
				FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL
			}
		},
		{
			&hf_arq_reset_direction,
			{
				"Direction", "wmx.arq.reset_direction",
				FT_UINT8, BASE_DEC, VALS(vals_arq_reset_direction), 0x30, NULL, HFILL
			}
		},
		{
			&hf_arq_reset_reserved,
			{
				"Reserved", "wmx.arq.reset_reserved",
				FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL
			}
		},
		{
			&hf_arq_reset_type,
			{
				"Type", "wmx.arq.reset_type",
				FT_UINT8, BASE_DEC, VALS(vals_arq_reset_type), 0xC0, NULL, HFILL
			}
		},
		{
			&hf_arq_selective_map,
			{
				"Selective ACK Map", "wmx.arq.selective_map",
				FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_arq_0seq_ack_map,
			{
				"Sequence ACK Map", "wmx.arq.seq_ack_map",
				FT_UINT8, BASE_HEX, NULL, 0x60, NULL, HFILL
			}
		},
		{
			&hf_arq_1seq_ack_map,
			{
				"Sequence ACK Map", "wmx.arq.seq_ack_map",
				FT_UINT8, BASE_HEX, NULL, 0x70, NULL, HFILL
			}
		},
		{
			&hf_arq_seq_format,
			{
				"Sequence Format", "wmx.arq.seq_format",
				FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL
			}
		},
		{
			&hf_arq_0seq1_len,
			{
				"Sequence 1 Length", "wmx.arq.seq1_len",
				FT_UINT16, BASE_DEC, NULL, 0x1F80, NULL, HFILL
			}
		},
		{
			&hf_arq_0seq2_len,
			{
				"Sequence 2 Length", "wmx.arq.seq2_len",
				FT_UINT16, BASE_DEC, NULL, 0x007E, NULL, HFILL
			}
		},
		{
			&hf_arq_1seq1_len,
			{
				"Sequence 1 Length", "wmx.arq.seq1_len",
				FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL
			}
		},
		{
			&hf_arq_1seq2_len,
			{
				"Sequence 2 Length", "wmx.arq.seq2_len",
				FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL
			}
		},
		{
			&hf_arq_1seq3_len,
			{
				"Sequence 3 Length", "wmx.arq.seq3_len",
				FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL
			}
		},
		{
			&hf_ack_type_reserved,
			{
				"Reserved", "wmx.ack_type.reserved",
				FT_UINT8, BASE_DEC, NULL, 0x03, NULL, HFILL
			}
		}
	};

	proto_mac_mgmt_msg_arq_feedback_decoder = proto_register_protocol (
		"WiMax ARQ Feedback/Discard/Reset Messages", /* name */
		"WiMax ARQ Feedback/Discard/Reset (arq)", /* short name */
		"wmx.arq" /* abbrev */
		);

	proto_register_field_array(proto_mac_mgmt_msg_arq_feedback_decoder, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_arq_discard(void)
{
	proto_mac_mgmt_msg_arq_discard_decoder = proto_mac_mgmt_msg_arq_feedback_decoder;
}

/* Register Wimax Mac Payload Protocol and Dissector */
void proto_register_mac_mgmt_msg_arq_reset(void)
{
	proto_mac_mgmt_msg_arq_reset_decoder = proto_mac_mgmt_msg_arq_feedback_decoder;
}

/* Decode ARQ-Feedback messages. */
void dissect_mac_mgmt_msg_arq_feedback_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint offset = 0;
	guint arq_feedback_ie_count = 0;
	guint arq_cid;
	gboolean arq_last = FALSE;
	guint arq_ack_type;
	guint arq_bsn;
	guint arq_num_ack_maps;
	guint tvb_len, payload_type;
	proto_item *arq_feedback_item = NULL;
	proto_tree *arq_feedback_tree = NULL;
	proto_item *arq_fb_item = NULL;
	proto_tree *arq_fb_tree = NULL;
	proto_item *ti = NULL;
	guint i, seq_format;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, offset);
	if(payload_type != MAC_MGMT_MSG_ARQ_FEEDBACK)
	{
		return;
	}

	if (tree)
	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type ARQ-Feedback */
		arq_feedback_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_arq_feedback_decoder, tvb, offset, tvb_len, "MAC Management Message, ARQ-Feedback (33)");
		/* add MAC ARQ Feedback subtree */
		arq_feedback_tree = proto_item_add_subtree(arq_feedback_item, ett_mac_mgmt_msg_arq_decoder);
		/* display the Message Type */
		proto_tree_add_item(arq_feedback_tree, hf_arq_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset += 1;

		while(offset < tvb_len && !arq_last)
		{
			arq_feedback_ie_count++;
			arq_cid = tvb_get_ntohs(tvb, offset);
			arq_last = ((tvb_get_guint8(tvb, offset + 2) & 0x80) != 0);
			arq_ack_type = (tvb_get_guint8(tvb, offset + 2) & 0x60) >> 5;
			arq_bsn = (tvb_get_ntohs(tvb, offset + 2) & 0x1FFC) >> 2;
			arq_num_ack_maps = 1 + (tvb_get_guint8(tvb, offset + 3) & 0x03);

			arq_fb_item = proto_tree_add_protocol_format(arq_feedback_tree, proto_mac_mgmt_msg_arq_feedback_decoder, tvb, offset, tvb_len, "ARQ_Feedback_IE");
			proto_item_append_text(arq_fb_item, ", CID: %u, %s ARQ feedback IE, %s, BSN: %u",
				arq_cid, arq_last ? "Last" : "More", val_to_str(arq_ack_type, vals_arq_ack_type, ""), arq_bsn);
			if (arq_ack_type != ARQ_CUMULATIVE_ACK_ENTRY) {
				proto_item_append_text(arq_fb_item, ", %u ACK Map(s)", arq_num_ack_maps);
			}
			/* add ARQ Feedback IE subtree */
			arq_fb_tree = proto_item_add_subtree(arq_fb_item, ett_mac_mgmt_msg_arq_decoder);
			proto_tree_add_item(arq_fb_tree, hf_arq_cid, tvb, offset, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(arq_fb_tree, hf_arq_last, tvb, offset + 2, 1, FALSE);
			proto_tree_add_item(arq_fb_tree, hf_arq_ack_type, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(arq_fb_tree, hf_arq_bsn, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
			if (arq_ack_type != ARQ_CUMULATIVE_ACK_ENTRY) {
				ti = proto_tree_add_item(arq_fb_tree, hf_arq_num_ack_maps, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
				proto_item_append_text(ti, " (%d map(s))", arq_num_ack_maps);
				offset += 2;

				for (i = 0; i < arq_num_ack_maps; i++) {
					/* Each ACK Map is 16 bits. */
					offset += 2;
					if (arq_ack_type != 3) {
						proto_tree_add_item(arq_fb_tree, hf_arq_selective_map, tvb, offset, 2, ENC_BIG_ENDIAN);
					} else {
						proto_tree_add_item(arq_fb_tree, hf_arq_seq_format, tvb, offset, 1, ENC_BIG_ENDIAN);
						seq_format = (tvb_get_guint8(tvb, offset) & 0x80) >> 7;
						if (seq_format == 0) {
							proto_tree_add_item(arq_fb_tree, hf_arq_0seq_ack_map, tvb, offset, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(arq_fb_tree, hf_arq_0seq1_len, tvb, offset, 2, ENC_BIG_ENDIAN);
							proto_tree_add_item(arq_fb_tree, hf_arq_0seq2_len, tvb, offset, 2, ENC_BIG_ENDIAN);
							proto_tree_add_item(arq_fb_tree, hf_arq_reserved, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
						} else {
							proto_tree_add_item(arq_fb_tree, hf_arq_1seq_ack_map, tvb, offset, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(arq_fb_tree, hf_arq_1seq1_len, tvb, offset, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(arq_fb_tree, hf_arq_1seq2_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
							proto_tree_add_item(arq_fb_tree, hf_arq_1seq3_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
						}
					}
				}
			} else {
				/* Number of ACK Maps bits are reserved when ACK TYPE == 1 */
				proto_tree_add_item(arq_fb_tree, hf_ack_type_reserved, tvb, offset + 3, 1, ENC_BIG_ENDIAN);
				/* update the offset */
				offset += 2;
			}
			/* update the offset */
			offset += 2;
		}
		proto_item_append_text(arq_feedback_item, ", %u ARQ_feedback_IE(s)", arq_feedback_ie_count);
	}
}

/* Decode ARQ-Discard messages. */
void dissect_mac_mgmt_msg_arq_discard_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint tvb_len, payload_type;
	proto_item *arq_discard_item = NULL;
	proto_tree *arq_discard_tree = NULL;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, 0);
	if(payload_type != MAC_MGMT_MSG_ARQ_DISCARD)
	{
		return;
	}

	if (tree)
	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type ARQ-Discard */
		arq_discard_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_arq_discard_decoder, tvb, 0, tvb_len, "MAC Management Message, ARQ-Discard (34)");
		/* add MAC ARQ Discard subtree */
		arq_discard_tree = proto_item_add_subtree(arq_discard_item, ett_mac_mgmt_msg_arq_decoder);
		/* display the Message Type */
		proto_tree_add_item(arq_discard_tree, hf_arq_message_type, tvb, 0, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(arq_discard_tree, hf_arq_discard_cid, tvb, 1, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(arq_discard_tree, hf_arq_discard_reserved, tvb, 3, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(arq_discard_tree, hf_arq_discard_bsn, tvb, 3, 2, ENC_BIG_ENDIAN);
	}
}

/* Decode ARQ-Reset messages. */
void dissect_mac_mgmt_msg_arq_reset_decoder(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	guint tvb_len, payload_type;
	proto_item *arq_reset_item = NULL;
	proto_tree *arq_reset_tree = NULL;

	/* Ensure the right payload type */
	payload_type = tvb_get_guint8(tvb, 0);
	if(payload_type != MAC_MGMT_MSG_ARQ_RESET)
	{
		return;
	}

	if (tree)
	{	/* we are being asked for details */

		/* Get the tvb reported length */
		tvb_len =  tvb_reported_length(tvb);
		/* display MAC payload type ARQ-Reset */
		arq_reset_item = proto_tree_add_protocol_format(tree, proto_mac_mgmt_msg_arq_reset_decoder, tvb, 0, tvb_len, "MAC Management Message, ARQ-Reset (35)");
		/* add MAC ARQ Reset subtree */
		arq_reset_tree = proto_item_add_subtree(arq_reset_item, ett_mac_mgmt_msg_arq_decoder);
		/* display the Message Type */
		proto_tree_add_item(arq_reset_tree, hf_arq_message_type, tvb, 0, 1, ENC_BIG_ENDIAN);

		proto_tree_add_item(arq_reset_tree, hf_arq_reset_cid, tvb, 1, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(arq_reset_tree, hf_arq_reset_type, tvb, 3, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(arq_reset_tree, hf_arq_reset_direction, tvb, 3, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(arq_reset_tree, hf_arq_reset_reserved, tvb, 3, 1, ENC_BIG_ENDIAN);
	}
}

