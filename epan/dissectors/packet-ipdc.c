/* packet-ipdc.c
 * Routines for IP Device Control (SS7 over IP) dissection
 * Copyright Lucent Technologies 2004
 * Josh Bailey <joshbailey@lucent.com> and Ruud Linders <ruud@lucent.com>
 *
 * Using IPDC spec 0.20.2
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <math.h>

#include <epan/packet.h>
#include <epan/emem.h>
#include "packet-ipdc.h"
#include "packet-tcp.h"
#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/prefs.h>

static int proto_ipdc = -1;
static int hf_ipdc_nr = -1;
static int hf_ipdc_ns = -1;
static int hf_ipdc_payload_len = -1;
static int hf_ipdc_protocol_id = -1;
static int hf_ipdc_trans_id_size = -1;
static int hf_ipdc_trans_id = -1;
static int hf_ipdc_message_code = -1;

static gint ett_ipdc = -1;
static gint ett_ipdc_tag = -1;

static gboolean ipdc_desegment = TRUE;
static guint ipdc_port_pref = TCP_PORT_IPDC;
static gboolean new_packet = FALSE;

static dissector_handle_t q931_handle;

void proto_reg_handoff_ipdc(void);


static guint
get_ipdc_pdu_len(tvbuff_t *tvb, int offset)
{
        /* lower 10 bits only */
        guint raw_len = (tvb_get_ntohs(tvb,offset+2) & 0x03FF);
 
        return raw_len + 4;
}

static void
dissect_ipdc_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *ipdc_tree;
	proto_item *ipdc_tag;
	proto_tree *tag_tree;
	tvbuff_t *q931_tvb;

	const char *des;
	const char *enum_val = "";
	char tmp_tag_text[IPDC_STR_LEN + 1];
	const value_string *val_ptr;
	guint32	type;
	guint len;
	guint i;
	guint status;
	gshort tag;
	guint32 tmp_tag;

	gshort nr = tvb_get_guint8(tvb,0);
	gshort ns = tvb_get_guint8(tvb,1);
        guint payload_len = get_ipdc_pdu_len(tvb,0);

        gshort protocol_id;
        gshort trans_id_size;
        guint32 trans_id;
        guint16 message_code;
        guint16 offset;

        /* display IPDC protocol ID */
        if (check_col(pinfo->cinfo, COL_PROTOCOL))
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPDC");

	/* short frame... */
	if (payload_len < 4)
		return;

	/* clear info column and display send/receive sequence numbers */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (new_packet == TRUE) {
			col_clear(pinfo->cinfo, COL_INFO);
			new_packet = FALSE;
		}
		col_append_fstr(pinfo->cinfo, COL_INFO, "r=%u s=%u ",
		nr, ns);
	}

	if (payload_len == 4) {
		if (!tree)
			return;

	        ti = proto_tree_add_item(tree, proto_ipdc, tvb, 0, -1, FALSE);
       		ipdc_tree = proto_item_add_subtree(ti, ett_ipdc);
		proto_tree_add_item(ipdc_tree, hf_ipdc_nr, tvb, 0, 1, nr);
        	proto_tree_add_item(ipdc_tree, hf_ipdc_ns, tvb, 1, 1, ns);
        	proto_tree_add_uint(ipdc_tree, hf_ipdc_payload_len, tvb, 2, 2,
			payload_len);

		return;
	}

	/* IPDC tags present - display message code and trans. ID */
	protocol_id = tvb_get_guint8(tvb,4);
        trans_id_size = TRANS_ID_SIZE_IPDC; /* tvb_get_guint8(tvb,5); */
       	trans_id = tvb_get_ntohl(tvb,6);
       	message_code = tvb_get_ntohs(tvb,6+trans_id_size);
       	offset = 6 + trans_id_size + 2; /* past message_code */

	if (check_col(pinfo->cinfo, COL_INFO))
       		col_append_fstr(pinfo->cinfo, COL_INFO,
			"TID=%x %s ",
                        trans_id,
                        val_to_str(message_code, message_code_vals,
                        TEXT_UNDEFINED));

	if (!tree)
		return;

	ti = proto_tree_add_item(tree, proto_ipdc, tvb, 0, -1, FALSE);
	ipdc_tree = proto_item_add_subtree(ti, ett_ipdc);

	proto_tree_add_item(ipdc_tree, hf_ipdc_nr, tvb, 0, 1, nr);
	proto_tree_add_item(ipdc_tree, hf_ipdc_ns, tvb, 1, 1, ns);
	proto_tree_add_uint(ipdc_tree, hf_ipdc_payload_len, tvb,
		2, 2, payload_len);

	proto_tree_add_item(ipdc_tree, hf_ipdc_protocol_id, tvb,
		4, 1, protocol_id);
	proto_tree_add_item(ipdc_tree, hf_ipdc_trans_id_size, tvb,
		5, 1, trans_id_size);
	proto_tree_add_item(ipdc_tree, hf_ipdc_trans_id, tvb,
		6, trans_id_size, trans_id);
	proto_tree_add_item(ipdc_tree, hf_ipdc_message_code, tvb,
		6 + trans_id_size + 1, 1, message_code);

	ipdc_tag = proto_tree_add_text(ipdc_tree, tvb, offset,
	payload_len - offset, "IPDC tags");
	tag_tree = proto_item_add_subtree(ipdc_tag, ett_ipdc_tag);

	/* iterate through tags. first byte is tag, second is length,
           in bytes, following is tag data. tag of 0x0 should be
	   end of tags. */
	for (;;) {
		tag = tvb_get_guint8(tvb, offset);

		if (tag == 0x0) {
			if (offset == payload_len - 1) {
				proto_tree_add_text(tag_tree, tvb,
				offset, 1, "end of tags");
			} else {
				proto_tree_add_text(tag_tree, tvb,
				offset, 1, "data trailing end of tags");
			}

			break;
		}

		len = tvb_get_guint8(tvb,offset+1);
		des = val_to_str(tag, tag_description, TEXT_UNDEFINED);
		/* lookup tag type */
		for (i = 0; (ipdc_tag_types[i].tag != tag &&
			ipdc_tag_types[i].type != IPDC_UNKNOWN); i++)
		;
		type = ipdc_tag_types[i].type;

		tmp_tag = 0;

		switch (type) {
			/* simple IPDC_ASCII strings */
			case IPDC_ASCII:
				g_assert(len<=IPDC_STR_LEN);
				tvb_memcpy(tvb, tmp_tag_text, offset+2, len);
				tmp_tag_text[len] = 0;
				proto_tree_add_text(tag_tree, tvb, offset,
				len + 2, "0x%2.2x: %s: %s", tag, des,
				tmp_tag_text);
			break;

			/* unsigned integers, or bytes */
			case IPDC_UINT:
			case IPDC_BYTE:
				for (i = 0; i < len; i++) 
					tmp_tag += tvb_get_guint8(tvb,
						offset + 2 + i) * (guint32)
							pow(256, len - (i + 1));

				if (len == 1)
					enum_val =
						val_to_str(IPDC_TAG(tag) +
						tmp_tag,
						tag_enum_type, TEXT_UNDEFINED);

				if (len == 1 &&
					strcmp(enum_val, TEXT_UNDEFINED) != 0) {
					proto_tree_add_text(tag_tree, tvb,
						offset, len + 2,
						"0x%2.2x: %s: %s",
						tag, des, enum_val);
				} else {
					proto_tree_add_text(tag_tree, tvb,
						offset, len + 2,
						"0x%2.2x: %s: %u",
						tag, des, tmp_tag);
				}
			break;

			/* IP addresses */
			case IPDC_IPA:
				switch (len) {
					case 4:
						g_snprintf(tmp_tag_text,
						IPDC_STR_LEN,
						"%u.%u.%u.%u",
						tvb_get_guint8(tvb, offset + 2),
						tvb_get_guint8(tvb, offset + 3),
						tvb_get_guint8(tvb, offset + 4),
						tvb_get_guint8(tvb, offset + 5)
						);
					break;

					case 6:
						g_snprintf(tmp_tag_text,
						IPDC_STR_LEN,
						"%u.%u.%u.%u:%u",
						tvb_get_guint8(tvb, offset + 2),
						tvb_get_guint8(tvb, offset + 3),
						tvb_get_guint8(tvb, offset + 4),
						tvb_get_guint8(tvb, offset + 5),
						tvb_get_ntohs(tvb, offset + 6));
					break;

					default:
						g_snprintf(tmp_tag_text,
						IPDC_STR_LEN,
						"Invalid IP address length %u",
                                       		 len);
				}

				proto_tree_add_text(tag_tree, tvb,
					offset, len + 2,
					"0x%2.2x: %s: %s",
					tag, des, tmp_tag_text);
			break;

			/* Line status arrays */
			case IPDC_LINESTATUS:
			case IPDC_CHANNELSTATUS:
				proto_tree_add_text(tag_tree, tvb, offset,
				len + 2, "0x%2.2x: %s", tag, des);
				val_ptr = (type == IPDC_LINESTATUS) ?
					line_status_vals : channel_status_vals;

				for (i = 0; i < len; i++) {
					status = tvb_get_guint8(tvb,offset+2+i);

					proto_tree_add_text(tag_tree, tvb,
						offset + 2 + i, 1, 
						" %.2u: %.2x (%s)",
						i + 1, status,
						val_to_str(status,
						val_ptr,
						TEXT_UNDEFINED));
				}
			break;

			case IPDC_Q931:
				q931_tvb =
					tvb_new_subset(tvb, offset+2, len, len);
				call_dissector(q931_handle,q931_tvb,pinfo,tree);
			break;

			case IPDC_ENCTYPE:
				proto_tree_add_text(tag_tree, tvb,
					offset, len + 2,
					"0x%2.2x: %s: %s",
					tag, des, val_to_str(
					tvb_get_guint8(tvb,offset+2),
					encoding_type_vals,
					TEXT_UNDEFINED));

				if (len == 2) {
					proto_tree_add_text(tag_tree, tvb,
						offset, len + 2,
						"0x%2.2x: %s: %u",
						tag, des,
						tvb_get_guint8(tvb,offset+3));
				}
			break;
					
			/* default */
			default:
				proto_tree_add_text(tag_tree, tvb, offset,
				len + 2, "0x%2.2x: %s", tag, des);
		} /* switch */

		offset += len + 2;
	}
}

static void
dissect_ipdc_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_ipdc_common(tvb, pinfo, tree);
}

static void
dissect_ipdc_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	new_packet = TRUE;
	tcp_dissect_pdus(tvb, pinfo, tree, ipdc_desegment, 4,
		get_ipdc_pdu_len, dissect_ipdc_tcp_pdu);
}

void
proto_register_ipdc(void)
{                 

	static hf_register_info hf[] = {
		{ &hf_ipdc_nr,
			{ "N(r)",	"ipdc.nr",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Receive sequence number", HFILL }
		},

		{ &hf_ipdc_ns,
			{ "N(s)",	"ipdc.ns",
			FT_UINT8, BASE_DEC, NULL, 0x0, 
			"Transmit sequence number", HFILL }
		},

		{ &hf_ipdc_payload_len,
			{ "Payload length",	"ipdc.length",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Payload length", HFILL }
		},

		{ &hf_ipdc_protocol_id,
			{ "Protocol ID",	"ipdc.protocol_id",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Protocol ID", HFILL }
		},

		{ &hf_ipdc_trans_id_size,
			{ "Transaction ID size",	"ipdc.trans_id_size",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Transaction ID size", HFILL }
		},

		{ &hf_ipdc_trans_id,
			{ "Transaction ID",	"ipdc.trans_id",
			FT_BYTES, BASE_HEX, NULL, 0x0,
			"Transaction ID", HFILL }
		},

		{ &hf_ipdc_message_code,
			{ "Message code",	"ipdc.message_code",
			FT_UINT16, BASE_HEX, VALS(message_code_vals), 0x0,
			"Message Code", HFILL }
		},
	};

	static gint *ett[] = {
		&ett_ipdc,
		&ett_ipdc_tag,
	};

	module_t *ipdc_module;

	proto_ipdc = proto_register_protocol("IP Device Control (SS7 over IP)",
	    "IPDC", "ipdc");
	proto_register_field_array(proto_ipdc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	ipdc_module = prefs_register_protocol(proto_ipdc, proto_reg_handoff_ipdc);
	prefs_register_bool_preference(ipdc_module, "desegment_ipdc_messages",
		"Reassemble IPDC messages spanning multiple TCP segments",
		"Whether the IPDC dissector should reassemble messages spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&ipdc_desegment);
	prefs_register_uint_preference(ipdc_module, "tcp.port",
		"IPDC monitoring port",
		"Set the IPDC monitoring port", 10,
		&ipdc_port_pref);
}

void
proto_reg_handoff_ipdc(void)
{
	static guint last_ipdc_port_pref = 0;
	static dissector_handle_t ipdc_tcp_handle = NULL;

	if (ipdc_tcp_handle) {
		dissector_delete("tcp.port", last_ipdc_port_pref,
			ipdc_tcp_handle);
	} else {
		ipdc_tcp_handle = 
			create_dissector_handle(dissect_ipdc_tcp, proto_ipdc);
		q931_handle = find_dissector("q931");
	}

	last_ipdc_port_pref = ipdc_port_pref;
	dissector_add("tcp.port", ipdc_port_pref, ipdc_tcp_handle);
}
