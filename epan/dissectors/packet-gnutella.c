/* packet-gnutella.c
 * Routines for gnutella dissection
 * Copyright 2001, B. Johannessen <bob@havoq.com>
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
#include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>


#include <epan/packet.h>
#include "packet-gnutella.h"
#include "packet-tcp.h"

/*
 * See
 *
 *	http://rfc-gnutella.sourceforge.net/developer/index.html
 */

static int proto_gnutella = -1;

static int hf_gnutella_stream = -1;

static int hf_gnutella_header = -1;
static int hf_gnutella_header_id = -1;
static int hf_gnutella_header_payload = -1;
static int hf_gnutella_header_ttl = -1;
static int hf_gnutella_header_hops = -1;
static int hf_gnutella_header_size = -1;

static int hf_gnutella_pong_payload = -1;
static int hf_gnutella_pong_port = -1;
static int hf_gnutella_pong_ip = -1;
static int hf_gnutella_pong_files = -1;
static int hf_gnutella_pong_kbytes = -1;

static int hf_gnutella_query_payload = -1;
static int hf_gnutella_query_min_speed = -1;
static int hf_gnutella_query_search = -1;

static int hf_gnutella_queryhit_payload = -1;
static int hf_gnutella_queryhit_count = -1;
static int hf_gnutella_queryhit_port = -1;
static int hf_gnutella_queryhit_ip = -1;
static int hf_gnutella_queryhit_speed = -1;
static int hf_gnutella_queryhit_extra = -1;
static int hf_gnutella_queryhit_servent_id = -1;

static int hf_gnutella_queryhit_hit = -1;
static int hf_gnutella_queryhit_hit_index = -1;
static int hf_gnutella_queryhit_hit_size = -1;
static int hf_gnutella_queryhit_hit_name = -1;
static int hf_gnutella_queryhit_hit_extra = -1;

static int hf_gnutella_push_payload = -1;
static int hf_gnutella_push_servent_id = -1;
static int hf_gnutella_push_index = -1;
static int hf_gnutella_push_ip = -1;
static int hf_gnutella_push_port = -1;

static gint ett_gnutella = -1;

static void dissect_gnutella_pong(tvbuff_t *tvb, guint offset, proto_tree *tree) {

	proto_tree_add_item(tree,
		hf_gnutella_pong_port,
		tvb,
		offset + GNUTELLA_PONG_PORT_OFFSET,
		GNUTELLA_PORT_LENGTH,
		ENC_LITTLE_ENDIAN);

	proto_tree_add_item(tree,
		hf_gnutella_pong_ip,
		tvb,
		offset + GNUTELLA_PONG_IP_OFFSET,
		GNUTELLA_IP_LENGTH,
		ENC_BIG_ENDIAN);

	proto_tree_add_item(tree,
		hf_gnutella_pong_files,
		tvb,
		offset + GNUTELLA_PONG_FILES_OFFSET,
		GNUTELLA_LONG_LENGTH,
		ENC_LITTLE_ENDIAN);

	proto_tree_add_item(tree,
		hf_gnutella_pong_kbytes,
		tvb,
		offset + GNUTELLA_PONG_KBYTES_OFFSET,
		GNUTELLA_LONG_LENGTH,
		ENC_LITTLE_ENDIAN);

}

static void dissect_gnutella_query(tvbuff_t *tvb, guint offset, proto_tree *tree, guint size) {

	proto_tree_add_item(tree,
		hf_gnutella_query_min_speed,
		tvb,
		offset + GNUTELLA_QUERY_SPEED_OFFSET,
		GNUTELLA_SHORT_LENGTH,
		ENC_LITTLE_ENDIAN);

	if (size > GNUTELLA_SHORT_LENGTH) {
		proto_tree_add_item(tree,
			hf_gnutella_query_search,
			tvb,
			offset + GNUTELLA_QUERY_SEARCH_OFFSET,
			size - GNUTELLA_SHORT_LENGTH,
			ENC_ASCII|ENC_NA);
	}
	else {
		proto_tree_add_text(tree,
			tvb,
			offset + GNUTELLA_QUERY_SEARCH_OFFSET,
			0,
			"Missing data for Query Search.");
	}
}

static void dissect_gnutella_queryhit(tvbuff_t *tvb, guint offset, proto_tree *tree, guint size) {

	proto_tree *qhi, *hit_tree;
	int hit_count, i;
	int hit_offset;
	int name_length, extra_length;
	int idx_at_offset, size_at_offset;
	int servent_id_at_offset;
	int name_at_offset, extra_at_offset;
	int cur_char, remaining, used;

	hit_count = tvb_get_guint8(tvb, offset + GNUTELLA_QUERYHIT_COUNT_OFFSET);

	proto_tree_add_uint(tree,
		hf_gnutella_queryhit_count,
		tvb,
		offset + GNUTELLA_QUERYHIT_COUNT_OFFSET,
		GNUTELLA_BYTE_LENGTH,
		hit_count);

	proto_tree_add_item(tree,
		hf_gnutella_queryhit_port,
		tvb,
		offset + GNUTELLA_QUERYHIT_PORT_OFFSET,
		GNUTELLA_PORT_LENGTH,
		ENC_LITTLE_ENDIAN);

	proto_tree_add_item(tree,
		hf_gnutella_queryhit_ip,
		tvb,
		offset + GNUTELLA_QUERYHIT_IP_OFFSET,
		GNUTELLA_IP_LENGTH,
		ENC_BIG_ENDIAN);

	proto_tree_add_item(tree,
		hf_gnutella_queryhit_speed,
		tvb,
		offset + GNUTELLA_QUERYHIT_SPEED_OFFSET,
		GNUTELLA_LONG_LENGTH,
		ENC_LITTLE_ENDIAN);

	hit_offset = offset + GNUTELLA_QUERYHIT_FIRST_HIT_OFFSET;

	for(i = 0; i < hit_count; i++) {
		idx_at_offset  = hit_offset;
		size_at_offset = hit_offset + GNUTELLA_QUERYHIT_HIT_SIZE_OFFSET;

		hit_offset += (GNUTELLA_LONG_LENGTH * 2);

		name_length  = 0;
		extra_length = 0;

		name_at_offset = hit_offset;

		while(hit_offset - offset < size) {
			cur_char = tvb_get_guint8(tvb, hit_offset);
			if(cur_char == '\0')
				break;

			hit_offset++;
			name_length++;
		}

		hit_offset++;

		extra_at_offset = hit_offset;

		while(hit_offset - offset < size) {
			cur_char = tvb_get_guint8(tvb, hit_offset);
			if(cur_char == '\0')
				break;

			hit_offset++;
			extra_length++;
		}

		hit_offset++;

		qhi = proto_tree_add_item(tree,
			hf_gnutella_queryhit_hit,
			tvb,
			idx_at_offset,
			(GNUTELLA_LONG_LENGTH * 2) +
			name_length + extra_length +
			GNUTELLA_QUERYHIT_END_OF_STRING_LENGTH,
			ENC_NA);

		hit_tree = proto_item_add_subtree(qhi, ett_gnutella);

		proto_tree_add_item(hit_tree,
			hf_gnutella_queryhit_hit_index,
			tvb,
			idx_at_offset,
			GNUTELLA_LONG_LENGTH,
			ENC_LITTLE_ENDIAN);

		proto_tree_add_item(hit_tree,
			hf_gnutella_queryhit_hit_size,
			tvb,
			size_at_offset,
			GNUTELLA_LONG_LENGTH,
			ENC_LITTLE_ENDIAN);

		proto_tree_add_item(hit_tree,
			hf_gnutella_queryhit_hit_name,
			tvb,
			name_at_offset,
			name_length,
			ENC_ASCII|ENC_NA);

		if(extra_length) {
			proto_tree_add_item(hit_tree,
				hf_gnutella_queryhit_hit_extra,
				tvb,
				extra_at_offset,
				extra_length,
				ENC_NA);
		}
	}

	used = hit_offset - offset;
	remaining = size - used;

	if(remaining > GNUTELLA_SERVENT_ID_LENGTH) {
		servent_id_at_offset = hit_offset + remaining - GNUTELLA_SERVENT_ID_LENGTH;

		proto_tree_add_item(tree,
			hf_gnutella_queryhit_extra,
			tvb,
			hit_offset,
			servent_id_at_offset - hit_offset,
			ENC_NA);
	}
	else {
		servent_id_at_offset = hit_offset;
	}

	proto_tree_add_item(tree,
		hf_gnutella_queryhit_servent_id,
		tvb,
		servent_id_at_offset,
		GNUTELLA_SERVENT_ID_LENGTH,
		ENC_NA);

}

static void dissect_gnutella_push(tvbuff_t *tvb, guint offset, proto_tree *tree) {

	proto_tree_add_item(tree,
		hf_gnutella_push_servent_id,
		tvb,
		offset + GNUTELLA_PUSH_SERVENT_ID_OFFSET,
		GNUTELLA_SERVENT_ID_LENGTH,
		ENC_NA);

	proto_tree_add_item(tree,
		hf_gnutella_push_index,
		tvb,
		offset + GNUTELLA_PUSH_INDEX_OFFSET,
		GNUTELLA_LONG_LENGTH,
		ENC_LITTLE_ENDIAN);

	proto_tree_add_item(tree,
		hf_gnutella_push_ip,
		tvb,
		offset + GNUTELLA_PUSH_IP_OFFSET,
		GNUTELLA_IP_LENGTH,
		ENC_BIG_ENDIAN);

	proto_tree_add_item(tree,
		hf_gnutella_push_port,
		tvb,
		offset + GNUTELLA_PUSH_PORT_OFFSET,
		GNUTELLA_PORT_LENGTH,
		ENC_LITTLE_ENDIAN);

}

static guint
get_gnutella_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset) {
	guint32 size;

	size = tvb_get_letohl(
		tvb,
		offset + GNUTELLA_HEADER_SIZE_OFFSET);
	if (size > GNUTELLA_MAX_SNAP_SIZE) {
		/*
		 * XXX - arbitrary limit, preventing overflows and
		 * attempts to reassemble 4GB of data.
		 */
		size = GNUTELLA_MAX_SNAP_SIZE;
	}

	/* The size doesn't include the header */
	return GNUTELLA_HEADER_LENGTH + size;
}

static void dissect_gnutella_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	proto_item *ti, *hi, *pi;
	proto_tree *gnutella_tree = NULL;
	proto_tree *gnutella_header_tree, *gnutella_pong_tree;
	proto_tree *gnutella_queryhit_tree, *gnutella_push_tree;
	proto_tree *gnutella_query_tree;
	guint8 payload_descriptor;
	guint32 size = 0;
	const char *payload_descriptor_text;

	if (tree) {
		ti = proto_tree_add_item(tree,
			proto_gnutella,
			tvb,
			0,
			-1,
			ENC_NA);
		gnutella_tree = proto_item_add_subtree(ti, ett_gnutella);

		size = tvb_get_letohl(
			tvb,
			GNUTELLA_HEADER_SIZE_OFFSET);
	}

	payload_descriptor = tvb_get_guint8(
		tvb,
		GNUTELLA_HEADER_PAYLOAD_OFFSET);

	switch(payload_descriptor) {
		case GNUTELLA_PING:
			payload_descriptor_text = GNUTELLA_PING_NAME;
			break;
		case GNUTELLA_PONG:
			payload_descriptor_text = GNUTELLA_PONG_NAME;
			break;
		case GNUTELLA_PUSH:
			payload_descriptor_text = GNUTELLA_PUSH_NAME;
			break;
		case GNUTELLA_QUERY:
			payload_descriptor_text = GNUTELLA_QUERY_NAME;
			break;
		case GNUTELLA_QUERYHIT:
			payload_descriptor_text = GNUTELLA_QUERYHIT_NAME;
			break;
		default:
			payload_descriptor_text = GNUTELLA_UNKNOWN_NAME;
			break;
	}

	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
		    payload_descriptor_text);

	if (tree) {
		hi = proto_tree_add_item(gnutella_tree,
			hf_gnutella_header,
			tvb,
			0,
			GNUTELLA_HEADER_LENGTH,
			ENC_NA);
		gnutella_header_tree = proto_item_add_subtree(hi, ett_gnutella);

		proto_tree_add_item(gnutella_header_tree,
			hf_gnutella_header_id,
			tvb,
			GNUTELLA_HEADER_ID_OFFSET,
			GNUTELLA_SERVENT_ID_LENGTH,
			ENC_NA);

		proto_tree_add_uint_format(gnutella_header_tree,
			hf_gnutella_header_payload,
			tvb,
			GNUTELLA_HEADER_PAYLOAD_OFFSET,
			GNUTELLA_BYTE_LENGTH,
			payload_descriptor,
			"Payload: %i (%s)",
			payload_descriptor,
			payload_descriptor_text);

		proto_tree_add_item(gnutella_header_tree,
			hf_gnutella_header_ttl,
			tvb,
			GNUTELLA_HEADER_TTL_OFFSET,
			GNUTELLA_BYTE_LENGTH,
			ENC_BIG_ENDIAN);

		proto_tree_add_item(gnutella_header_tree,
			hf_gnutella_header_hops,
			tvb,
			GNUTELLA_HEADER_HOPS_OFFSET,
			GNUTELLA_BYTE_LENGTH,
			ENC_BIG_ENDIAN);

		proto_tree_add_uint(gnutella_header_tree,
			hf_gnutella_header_size,
			tvb,
			GNUTELLA_HEADER_SIZE_OFFSET,
			GNUTELLA_LONG_LENGTH,
			size);

		if (size > 0) {
			switch(payload_descriptor) {
			case GNUTELLA_PONG:
				pi = proto_tree_add_item(
					gnutella_header_tree,
					hf_gnutella_pong_payload,
					tvb,
					GNUTELLA_HEADER_LENGTH,
					size,
					ENC_NA);
				gnutella_pong_tree = proto_item_add_subtree(
					pi,
					ett_gnutella);
				dissect_gnutella_pong(
					tvb,
					GNUTELLA_HEADER_LENGTH,
					gnutella_pong_tree);
				break;
			case GNUTELLA_PUSH:
				pi = proto_tree_add_item(
					gnutella_header_tree,
					hf_gnutella_push_payload,
					tvb,
					GNUTELLA_HEADER_LENGTH,
					size,
					ENC_NA);
				gnutella_push_tree = proto_item_add_subtree(
					pi,
					ett_gnutella);
				dissect_gnutella_push(
					tvb,
					GNUTELLA_HEADER_LENGTH,
					gnutella_push_tree);
				break;
			case GNUTELLA_QUERY:
				pi = proto_tree_add_item(
					gnutella_header_tree,
					hf_gnutella_query_payload,
					tvb,
					GNUTELLA_HEADER_LENGTH,
					size,
					ENC_NA);
				gnutella_query_tree = proto_item_add_subtree(
					pi,
					ett_gnutella);
				dissect_gnutella_query(
					tvb,
					GNUTELLA_HEADER_LENGTH,
					gnutella_query_tree,
					size);
				break;
			case GNUTELLA_QUERYHIT:
				pi = proto_tree_add_item(
					gnutella_header_tree,
					hf_gnutella_queryhit_payload,
					tvb,
					GNUTELLA_HEADER_LENGTH,
					size,
					ENC_NA);
				gnutella_queryhit_tree = proto_item_add_subtree(
					pi,
					ett_gnutella);
				dissect_gnutella_queryhit(
					tvb,
					GNUTELLA_HEADER_LENGTH,
					gnutella_queryhit_tree,
					size);
				break;
			}
		}
	}

}


static void dissect_gnutella(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {

	proto_item *ti;
	proto_tree *gnutella_tree = NULL;
	guint32 size;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Gnutella");

	col_clear(pinfo->cinfo, COL_INFO);

	/*
	 * OK, do we have enough data to determine whether this
	 * is Gnutella messages or just a transfer stream?
	 */
	if (tvb_bytes_exist(tvb, GNUTELLA_HEADER_SIZE_OFFSET, 4)) {
		/*
		 * Yes - fetch the length and see if it's bigger
		 * than GNUTELLA_MAX_SNAP_SIZE; if it is, we assume
		 * it's a transfer stream.
		 *
		 * Should we also check the payload descriptor?
		 */
		size = tvb_get_letohl(
			tvb,
			GNUTELLA_HEADER_SIZE_OFFSET);
		if (size > GNUTELLA_MAX_SNAP_SIZE) {
			if (tree) {
				ti = proto_tree_add_item(tree,
					proto_gnutella,
					tvb,
					0,
					-1,
					ENC_NA);
				gnutella_tree = proto_item_add_subtree(ti,
					ett_gnutella);

				proto_tree_add_item(gnutella_tree,
					hf_gnutella_stream,
					tvb,
					0,
					-1,
					ENC_NA);
			}
			return;
		}
	}

	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, GNUTELLA_HEADER_SIZE_OFFSET+4,
	    get_gnutella_pdu_len, dissect_gnutella_pdu);
}

void proto_register_gnutella(void) {

	static hf_register_info hf[] = {
		{ &hf_gnutella_header,
			{ "Descriptor Header", "gnutella.header",
			FT_NONE, BASE_NONE, NULL, 0,
			"Gnutella Descriptor Header", HFILL }
		},
		{ &hf_gnutella_pong_payload,
			{ "Pong", "gnutella.pong.payload",
			FT_NONE, BASE_NONE, NULL, 0,
			"Gnutella Pong Payload", HFILL }
		},
		{ &hf_gnutella_push_payload,
			{ "Push", "gnutella.push.payload",
			FT_NONE, BASE_NONE, NULL, 0,
			"Gnutella Push Payload", HFILL }
		},
		{ &hf_gnutella_query_payload,
			{ "Query", "gnutella.query.payload",
			FT_NONE, BASE_NONE, NULL, 0,
			"Gnutella Query Payload", HFILL }
		},
		{ &hf_gnutella_queryhit_payload,
			{ "QueryHit", "gnutella.queryhit.payload",
			FT_NONE, BASE_NONE, NULL, 0,
			"Gnutella QueryHit Payload", HFILL }
		},
		{ &hf_gnutella_stream,
			{ "Gnutella Upload / Download Stream", "gnutella.stream",
			FT_NONE, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_gnutella_header_id,
			{ "ID", "gnutella.header.id",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Gnutella Descriptor ID", HFILL }
		},
		{ &hf_gnutella_header_payload,
			{ "Payload", "gnutella.header.payload",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Gnutella Descriptor Payload", HFILL }
		},
		{ &hf_gnutella_header_ttl,
			{ "TTL", "gnutella.header.ttl",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Gnutella Descriptor Time To Live", HFILL }
		},
		{ &hf_gnutella_header_hops,
			{ "Hops", "gnutella.header.hops",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Gnutella Descriptor Hop Count", HFILL }
		},
		{ &hf_gnutella_header_size,
			{ "Length", "gnutella.header.size",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Gnutella Descriptor Payload Length", HFILL }
		},
		{ &hf_gnutella_pong_port,
			{ "Port", "gnutella.pong.port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Gnutella Pong TCP Port", HFILL }
		},
		{ &hf_gnutella_pong_ip,
			{ "IP", "gnutella.pong.ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"Gnutella Pong IP Address", HFILL }
		},
		{ &hf_gnutella_pong_files,
			{ "Files Shared", "gnutella.pong.files",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Gnutella Pong Files Shared", HFILL }
		},
		{ &hf_gnutella_pong_kbytes,
			{ "KBytes Shared", "gnutella.pong.kbytes",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Gnutella Pong KBytes Shared", HFILL }
		},
		{ &hf_gnutella_query_min_speed,
			{ "Min Speed", "gnutella.query.min_speed",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Gnutella Query Minimum Speed", HFILL }
		},
		{ &hf_gnutella_query_search,
			{ "Search", "gnutella.query.search",
			FT_STRINGZ, BASE_NONE, NULL, 0,
			"Gnutella Query Search", HFILL }
		},
		{ &hf_gnutella_queryhit_hit,
			{ "Hit", "gnutella.queryhit.hit",
			FT_NONE, BASE_NONE, NULL, 0,
			"Gnutella QueryHit", HFILL }
		},
		{ &hf_gnutella_queryhit_hit_index,
			{ "Index", "gnutella.queryhit.hit.index",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Gnutella QueryHit Index", HFILL }
		},
		{ &hf_gnutella_queryhit_hit_size,
			{ "Size", "gnutella.queryhit.hit.size",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Gnutella QueryHit Size", HFILL }
		},
		{ &hf_gnutella_queryhit_hit_name,
			{ "Name", "gnutella.queryhit.hit.name",
			FT_STRING, BASE_NONE, NULL, 0,
			"Gnutella Query Name", HFILL }
		},
		{ &hf_gnutella_queryhit_hit_extra,
			{ "Extra", "gnutella.queryhit.hit.extra",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Gnutella Query Extra", HFILL }
		},
		{ &hf_gnutella_queryhit_count,
			{ "Count", "gnutella.queryhit.count",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Gnutella QueryHit Count", HFILL }
		},
		{ &hf_gnutella_queryhit_port,
			{ "Port", "gnutella.queryhit.port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Gnutella QueryHit Port", HFILL }
		},
		{ &hf_gnutella_queryhit_ip,
			{ "IP", "gnutella.queryhit.ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"Gnutella QueryHit IP Address", HFILL }
		},
		{ &hf_gnutella_queryhit_speed,
			{ "Speed", "gnutella.queryhit.speed",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Gnutella QueryHit Speed", HFILL }
		},
		{ &hf_gnutella_queryhit_extra,
			{ "Extra", "gnutella.queryhit.extra",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Gnutella QueryHit Extra", HFILL }
		},
		{ &hf_gnutella_queryhit_servent_id,
			{ "Servent ID", "gnutella.queryhit.servent_id",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Gnutella QueryHit Servent ID", HFILL }
		},
		{ &hf_gnutella_push_servent_id,
			{ "Servent ID", "gnutella.push.servent_id",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Gnutella Push Servent ID", HFILL }
		},
		{ &hf_gnutella_push_ip,
			{ "IP", "gnutella.push.ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"Gnutella Push IP Address", HFILL }
		},
		{ &hf_gnutella_push_index,
			{ "Index", "gnutella.push.index",
			FT_UINT32, BASE_DEC, NULL, 0,
			"Gnutella Push Index", HFILL }
		},
		{ &hf_gnutella_push_port,
			{ "Port", "gnutella.push.port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Gnutella Push Port", HFILL }
		},
	};

	static gint *ett[] = {
		&ett_gnutella,
	};

	proto_gnutella = proto_register_protocol("Gnutella Protocol",
	    					"GNUTELLA",
						"gnutella");

	proto_register_field_array(proto_gnutella, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_gnutella(void) {
	dissector_handle_t gnutella_handle;

	gnutella_handle = create_dissector_handle(dissect_gnutella,
			proto_gnutella);
	dissector_add_uint("tcp.port", GNUTELLA_TCP_PORT, gnutella_handle);
}
