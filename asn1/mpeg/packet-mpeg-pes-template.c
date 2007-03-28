/* MPEG Packetized Elementary Stream (PES) packet decoder.
 * Written by Shaun Jackman <sjackman@gmail.com>.
 * Copyright 2007 Shaun Jackman
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-per.h"

#include "packet-mpeg-pes-hf.c"
#include "packet-mpeg-pes-ett.c"
#include "packet-mpeg-pes-fn.c"

static int proto_mpeg = -1;
static int proto_mpeg_pes = -1;
static int hf_mpeg_pes_pack_header = -1;
static int hf_mpeg_pes_stuffing = -1;
static int hf_mpeg_pes_extension = -1;
static int hf_mpeg_pes_header_data = -1;
static int hf_mpeg_pes_padding = -1;

static int hf_mpeg_pes_data = -1;

static int hf_mpeg_video_sequence_header = -1;
static int hf_mpeg_video_sequence_extension = -1;
static int hf_mpeg_video_group_of_pictures = -1;
static int hf_mpeg_video_picture = -1;
static int hf_mpeg_video_quantization_matrix = -1;
static int hf_mpeg_video_data = -1;

enum { PES_PREFIX = 1 };
enum {
	STREAM_PICTURE = 0x00,
	STREAM_SEQUENCE = 0xb3,
	STREAM_SEQUENCE_EXTENSION = 0xb5,
	STREAM_GOP = 0xb8,
	STREAM_END = 0xb9,
	STREAM_PACK = 0xba,
	STREAM_SYSTEM = 0xbb,
	STREAM_PROGRAM = 0xbc,
	STREAM_PRIVATE1 = 0xbd,
	STREAM_PADDING = 0xbe,
	STREAM_PRIVATE2 = 0xbf,
	STREAM_AUDIO = 0xc0,
	STREAM_VIDEO = 0xe0
};

void
dissect_mpeg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gboolean
dissect_mpeg_pes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int prefix;
	int stream;
	asn1_ctx_t asn1_ctx;
	int offset = 0;

	if (!tvb_bytes_exist(tvb, 0, 3))
		return FALSE;	/* not enough bytes for a PES prefix */

	prefix = tvb_get_ntoh24(tvb, 0);
	if (prefix != PES_PREFIX)
		return FALSE;
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPEG PES");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	stream = tvb_get_guint8(tvb, 3);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		const char *s = match_strval(stream, mpeg_pes_T_stream_vals);
		if (s != NULL)
			col_set_str(pinfo->cinfo, COL_INFO, s);
	}

#if 0
	if (tree == NULL)
		return TRUE;
#endif
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
	offset = dissect_mpeg_pes_PES(tvb, offset, &asn1_ctx,
			tree, proto_mpeg_pes);

	if (stream == STREAM_PICTURE) {
		int frame_type;

		frame_type = tvb_get_guint8(tvb, 5) >> 3 & 0x07;
		if (check_col(pinfo->cinfo, COL_INFO)) {
			const char *s = match_strval(frame_type,
					mpeg_pes_T_frame_type_vals);
			if (s != NULL)
				col_set_str(pinfo->cinfo, COL_INFO, s);
		}

		offset = dissect_mpeg_pes_Picture(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_picture);
		proto_tree_add_item(tree, hf_mpeg_video_data, tvb,
				offset / 8, -1, FALSE);
	} else if (stream == STREAM_SEQUENCE) {
		tvbuff_t *es;

		offset = dissect_mpeg_pes_Sequence_header(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_sequence_header);

		proto_tree_add_item(tree, hf_mpeg_video_quantization_matrix, tvb,
				offset / 8, 64, FALSE);
		offset += 64 * 8;

		es = tvb_new_subset(tvb, offset / 8, -1, -1);
		dissect_mpeg_pes(es, pinfo, tree);
	} else if (stream == STREAM_SEQUENCE_EXTENSION) {
		tvbuff_t *es;

		offset = dissect_mpeg_pes_Sequence_extension(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_sequence_extension);

		es = tvb_new_subset(tvb, offset / 8, -1, -1);
		dissect_mpeg_pes(es, pinfo, tree);
	} else if (stream == STREAM_GOP) {
		tvbuff_t *es;

		offset = dissect_mpeg_pes_Group_of_pictures(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_group_of_pictures);

		es = tvb_new_subset(tvb, offset / 8, -1, -1);
		dissect_mpeg_pes(es, pinfo, tree);
	} else if (stream == STREAM_PACK) {
		int length;
		switch (tvb_get_guint8(tvb, 4) >> 6) {
			case 1:
				length = tvb_get_guint8(tvb, 13) & 0x07;
				offset = dissect_mpeg_pes_Pack(tvb, offset, &asn1_ctx,
						tree, hf_mpeg_pes_pack_header);
				if (length > 0)
					proto_tree_add_item(tree, hf_mpeg_pes_stuffing, tvb,
							offset / 8, length, FALSE);
				break;
			default:
				length = 8;
				proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
						offset / 8, length, FALSE);
		}
		offset += length * 8;
	} else if (stream == STREAM_SYSTEM) {
		offset = dissect_mpeg_pes_Stream(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_pes_extension);
		proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
				offset / 8, -1, FALSE);
	} else if (stream == STREAM_PADDING) {
		int padding_length;

		padding_length = tvb_get_ntohs(tvb, 4);
		proto_tree_add_item(tree, hf_mpeg_pes_length, tvb,
				offset / 8, 2, FALSE);
		offset += 2 * 8;

		proto_tree_add_item(tree, hf_mpeg_pes_padding, tvb,
				offset / 8, padding_length, FALSE);
	} else if (stream == STREAM_PRIVATE1
			|| stream >= STREAM_AUDIO) {
		int length;
		int header_length;
		tvbuff_t *es;

		length = tvb_get_ntohs(tvb, 4);

		offset = dissect_mpeg_pes_Stream(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_pes_extension);
		length -= 5 * 8;

		header_length = tvb_get_guint8(tvb, 8);
		if (header_length > 0) {
			proto_tree_add_item(tree, hf_mpeg_pes_header_data, tvb,
					offset / 8, header_length, FALSE);
			offset += header_length * 8;
			length -= header_length * 8;
		}

		es = tvb_new_subset(tvb, offset / 8, -1, length / 8);
		if (tvb_get_ntoh24(es, 0) == PES_PREFIX)
			dissect_mpeg_pes(es, pinfo, tree);
		else if (tvb_get_guint8(es, 0) == 0xff)
			dissect_mpeg(es, pinfo, tree);
		else
			proto_tree_add_item(tree, hf_mpeg_pes_data, es,
					0, -1, FALSE);
	} else {
		proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
				offset / 8, -1, FALSE);
	}
	return TRUE;
}

static heur_dissector_list_t heur_subdissector_list;

void
dissect_mpeg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree)) {
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
	    col_add_str(pinfo->cinfo, COL_PROTOCOL, "MPEG");
	if (check_col(pinfo->cinfo, COL_INFO))
	    col_clear(pinfo->cinfo, COL_INFO);
	if (tree)
	    proto_tree_add_item(tree, proto_mpeg, tvb, 0, -1, FALSE);
    }
}

void
proto_register_mpeg_pes(void)
{
	static hf_register_info hf[] = {
#include "packet-mpeg-pes-hfarr.c"
		{ &hf_mpeg_pes_pack_header,
			{ "Pack header", "mpeg-pes.pack",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_stuffing,
			{ "PES stuffing bytes", "mpeg-pes.stuffing",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_extension,
			{ "PES extension", "mpeg-pes.extension",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_header_data,
			{ "PES header data", "mpeg-pes.header-data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_padding,
			{ "PES padding", "mpeg-pes.padding",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_data,
			{ "PES data", "mpeg-pes.data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_sequence_header,
			{ "MPEG sequence header", "mpeg-video.sequence",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_sequence_extension,
			{ "MPEG sequence extension", "mpeg-video.sequence-ext",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_group_of_pictures,
			{ "MPEG group of pictures", "mpeg-video.gop",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_picture,
			{ "MPEG picture", "mpeg-video.picture",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_quantization_matrix,
			{ "MPEG quantization matrix", "mpeg-video.quant",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_video_data,
			{ "MPEG picture data", "mpeg-video.data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
	};

	static gint *ett[] = {
#include "packet-mpeg-pes-ettarr.c"
	};

	proto_mpeg = proto_register_protocol(
			"Moving Picture Experts Group", "MPEG", "mpeg");
	register_heur_dissector_list("mpeg", &heur_subdissector_list);

	if (proto_mpeg_pes != -1)
		return;

	proto_mpeg_pes = proto_register_protocol(
			"Packetized Elementary Stream", "MPEG PES", "mpeg-pes");
	proto_register_field_array(proto_mpeg_pes, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mpeg_pes(void)
{
	dissector_handle_t mpeg_handle = create_dissector_handle(
			dissect_mpeg, proto_mpeg);
	dissector_add("wtap_encap", WTAP_ENCAP_MPEG, mpeg_handle);

	heur_dissector_add("mpeg", dissect_mpeg_pes, proto_mpeg_pes);
}
