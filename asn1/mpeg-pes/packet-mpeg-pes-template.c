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
#include <epan/asn1.h>

#include "packet-per.h"

#include "packet-mpeg-pes-hf.c"
#include "packet-mpeg-pes-ett.c"
#include "packet-mpeg-pes-fn.c"

static int proto_mpeg = -1;
static int proto_mpeg_pes = -1;

static int ett_mpeg_pes_pack_header = -1;
static int ett_mpeg_pes_header_data = -1;

static int hf_mpeg_pes_pack_header = -1;
static int hf_mpeg_pes_scr = -1;
static int hf_mpeg_pes_program_mux_rate = -1;
static int hf_mpeg_pes_stuffing_length = -1;
static int hf_mpeg_pes_stuffing = -1;
static int hf_mpeg_pes_extension = -1;
static int hf_mpeg_pes_header_data = -1;
static int hf_mpeg_pes_pts = -1;
static int hf_mpeg_pes_dts = -1;
static int hf_mpeg_pes_escr = -1;
static int hf_mpeg_pes_es_rate = -1;
static int hf_mpeg_pes_copy_info = -1;
static int hf_mpeg_pes_crc = -1;
static int hf_mpeg_pes_extension_flags = -1;
static int hf_mpeg_pes_private_data = -1;
static int hf_mpeg_pes_pack_length = -1;
static int hf_mpeg_pes_sequence = -1;
static int hf_mpeg_pes_pstd_buffer = -1;
static int hf_mpeg_pes_extension2 = -1;
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

enum {
	PTS_FLAG = 0x80,
	DTS_FLAG = 0x40,
	ESCR_FLAG = 0x20,
	ES_RATE_FLAG = 0x10,
	DSM_TRICK_MODE_FLAG = 0x08,
	COPY_INFO_FLAG = 0x04,
	CRC_FLAG = 0x02,
	EXTENSION_FLAG = 0x01
};

enum {
	PRIVATE_DATA_FLAG = 0x80,
	PACK_LENGTH_FLAG = 0x40,
	SEQUENCE_FLAG = 0x20,
	PSTD_BUFFER_FLAG = 0x10,
	MUST_BE_ONES = 0x07,
	EXTENSION_FLAG2 = 0x01
};

static guint64 tvb_get_ntoh40(tvbuff_t *tvb, unsigned offset)
{
	return (guint64)tvb_get_guint8(tvb, offset) << 32
		| tvb_get_ntohl(tvb, offset + 1);
}

static guint64 tvb_get_ntoh48(tvbuff_t *tvb, unsigned offset)
{
	return (guint64)tvb_get_ntohs(tvb, offset) << 32
		| tvb_get_ntohl(tvb, offset + 2);
}

#define TSHZ 90000

static guint64 decode_time_stamp(tvbuff_t *tvb, unsigned offset, nstime_t *nst)
{
	guint64 bytes = tvb_get_ntoh40(tvb, offset);
	guint64 ts =
		(bytes >> 33 & 0x0007) << 30 |
		(bytes >> 17 & 0x7fff) << 15 |
		(bytes >>  1 & 0x7fff) << 0;
	unsigned rem = (unsigned)(ts % TSHZ);
	nst->secs = (time_t)(ts / TSHZ);
	nst->nsecs = (int)(G_GINT64_CONSTANT(1000000000) * rem / TSHZ);
	return ts;
}

#define SCRHZ 27000000

static guint64 decode_clock_reference(tvbuff_t *tvb, unsigned offset,
		nstime_t *nst)
{
	guint64 bytes = tvb_get_ntoh48(tvb, offset);
	guint64 ts =
		(bytes >> 43 & 0x0007) << 30 |
		(bytes >> 27 & 0x7fff) << 15 |
		(bytes >> 11 & 0x7fff) << 0;
	unsigned ext = (unsigned)((bytes >> 1) & 0x1ff);
	guint64 cr = 300 * ts + ext;
	unsigned rem = (unsigned)(cr % SCRHZ);
	nst->secs = (time_t)(cr / SCRHZ);
	nst->nsecs = (int)(G_GINT64_CONSTANT(1000000000) * rem / SCRHZ);
	return cr;
}

static void
dissect_mpeg_pes_header_data(tvbuff_t *tvb, packet_info *pinfo,
		proto_tree *root, unsigned flags)
{
	proto_item *item = proto_tree_add_item(root, hf_mpeg_pes_header_data, tvb,
			0, -1, FALSE);
	proto_tree *tree = proto_item_add_subtree(item, ett_mpeg_pes_header_data);

	unsigned offset = 0;
	if (flags & PTS_FLAG) {
		nstime_t nst;
		decode_time_stamp(tvb, offset, &nst);
		proto_tree_add_time(tree, hf_mpeg_pes_pts, tvb,
				offset, 5, &nst);
		offset += 5;

		if (check_col(pinfo->cinfo, COL_DEF_DST)) {
			SET_ADDRESS(&pinfo->dst, AT_NONE, 0, NULL);
			col_add_fstr(pinfo->cinfo, COL_DEF_DST,
					"PTS %ld.%09u",
					(long) nst.secs, nst.nsecs);
		}
	}
	if (flags & DTS_FLAG) {
		nstime_t nst;
		decode_time_stamp(tvb, offset, &nst);
		proto_tree_add_time(tree, hf_mpeg_pes_dts, tvb,
				offset, 5, &nst);
		offset += 5;

		if (check_col(pinfo->cinfo, COL_DEF_SRC)) {
			SET_ADDRESS(&pinfo->src, AT_NONE, 0, NULL);
			col_add_fstr(pinfo->cinfo, COL_DEF_SRC,
					"DTS %ld.%09u",
					(long) nst.secs, nst.nsecs);
		}
	}
	if (flags & ESCR_FLAG) {
		nstime_t nst;
		decode_clock_reference(tvb, offset, &nst);
		proto_tree_add_time(tree, hf_mpeg_pes_escr, tvb,
				offset, 6, &nst);
		offset += 6;
	}
	if (flags & ES_RATE_FLAG) {
		unsigned es_rate = (tvb_get_ntohs(tvb, offset) >> 1 & 0x3fff) * 50;
		proto_tree_add_uint(tree, hf_mpeg_pes_es_rate, tvb,
				offset, 3, es_rate);
		offset += 3;
	}
	if (flags & COPY_INFO_FLAG) {
		proto_tree_add_item(tree, hf_mpeg_pes_copy_info, tvb,
				offset, 1, FALSE);
		offset++;
	}
	if (flags & CRC_FLAG) {
		proto_tree_add_item(tree, hf_mpeg_pes_crc, tvb,
				offset, 2, FALSE);
		offset += 2;
	}

	if (flags & EXTENSION_FLAG) {
		int flags2 = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_mpeg_pes_extension_flags, tvb,
				offset, 1, FALSE);
		offset++;

		if (flags2 & PRIVATE_DATA_FLAG) {
			proto_tree_add_item(tree, hf_mpeg_pes_private_data, tvb,
					offset, 2, FALSE);
			offset += 2;
		}
		if (flags2 & PACK_LENGTH_FLAG) {
			proto_tree_add_item(tree, hf_mpeg_pes_pack_length, tvb,
					offset, 1, FALSE);
			offset++;
		}
		if (flags2 & SEQUENCE_FLAG) {
			proto_tree_add_item(tree, hf_mpeg_pes_sequence, tvb,
					offset, 2, FALSE);
			offset += 2;
		}
		if (flags2 & PSTD_BUFFER_FLAG) {
			unsigned pstd = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint(tree, hf_mpeg_pes_pstd_buffer, tvb,
					offset, 2, (pstd & 0x2000 ? 1024 : 128) * (pstd & 0x1ff));
			offset += 2;
		}
		if (flags2 & EXTENSION_FLAG2) {
			proto_tree_add_item(tree, hf_mpeg_pes_extension2, tvb,
					offset, 2, FALSE);
			offset += 2;
		}
	}
}

static unsigned
dissect_mpeg_pes_pack_header(tvbuff_t *tvb, unsigned offset,
		packet_info *pinfo, proto_tree *root)
{
	unsigned program_mux_rate, stuffing_length;

	proto_item *item = proto_tree_add_item(root, hf_mpeg_pes_pack_header, tvb,
			offset / 8, 10, FALSE);
	proto_tree *tree = proto_item_add_subtree(item, ett_mpeg_pes_pack_header);

	nstime_t nst;
	decode_clock_reference(tvb, offset / 8, &nst);
	proto_tree_add_time(tree, hf_mpeg_pes_scr, tvb, offset / 8, 6, &nst);
	offset += 6 * 8;

	program_mux_rate = (tvb_get_ntoh24(tvb, offset / 8) >> 2) * 50;
	proto_tree_add_uint(tree, hf_mpeg_pes_program_mux_rate, tvb, offset / 8, 3,
			program_mux_rate);
	offset += 3 * 8;

	if (check_col(pinfo->cinfo, COL_DEF_SRC)) {
		SET_ADDRESS(&pinfo->src, AT_NONE, 0, NULL);
		col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "%u B/s", program_mux_rate);
	}

	stuffing_length = tvb_get_guint8(tvb, offset / 8) & 0x07;
	proto_tree_add_item(tree, hf_mpeg_pes_stuffing_length, tvb,
			offset / 8, 1, FALSE);
	offset += 1 * 8;

	if (stuffing_length > 0) {
		proto_tree_add_item(tree, hf_mpeg_pes_stuffing, tvb,
				offset / 8, stuffing_length, FALSE);
		offset += stuffing_length * 8;
	}

	return offset;
}

static void
dissect_mpeg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static gboolean
dissect_mpeg_pes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int prefix;
	int stream;
	asn1_ctx_t asn1_ctx;
	unsigned offset = 0;

	if (!tvb_bytes_exist(tvb, 0, 3))
		return FALSE;	/* not enough bytes for a PES prefix */

	prefix = tvb_get_ntoh24(tvb, 0);
	if (prefix != PES_PREFIX)
		return FALSE;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPEG PES");
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
		if (tvb_get_guint8(tvb, offset / 8) >> 6 == 1) {
			offset = dissect_mpeg_pes_pack_header(tvb, offset, pinfo, tree);
		} else {
			proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
					offset / 8, 8, FALSE);
			offset += 8 * 8;
		}
	} else if (stream == STREAM_SYSTEM || stream == STREAM_PRIVATE2) {
		unsigned data_length = tvb_get_ntohs(tvb, offset / 8);
		proto_tree_add_item(tree, hf_mpeg_pes_length, tvb,
				offset / 8, 2, FALSE);
		offset += 2 * 8;

		proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
				offset / 8, data_length, FALSE);
	} else if (stream == STREAM_PADDING) {
		unsigned padding_length = tvb_get_ntohs(tvb, offset / 8);
		proto_tree_add_item(tree, hf_mpeg_pes_length, tvb,
				offset / 8, 2, FALSE);
		offset += 2 * 8;

		proto_tree_add_item(tree, hf_mpeg_pes_padding, tvb,
				offset / 8, padding_length, FALSE);
	} else if (stream == STREAM_PRIVATE1
			|| stream >= STREAM_AUDIO) {
		int length = tvb_get_ntohs(tvb, 4);

		if ((tvb_get_guint8(tvb, 6) & 0xc0) == 0x80) {
			int header_length;
			tvbuff_t *es;

			offset = dissect_mpeg_pes_Stream(tvb, offset, &asn1_ctx,
					tree, hf_mpeg_pes_extension);
			/* https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=2229 
			 * A value of 0 indicates that the PES packet length is neither specified nor 
			 * bounded and is allowed only in PES packets whose payload is a video elementary 
			 * stream contained in Transport Stream packets. 
			 * XXX Some one with access to the spec should check this 
			 */ 
			 if(length !=0 && stream != STREAM_VIDEO){
				 length -= 5 * 8;
			 }

			header_length = tvb_get_guint8(tvb, 8);
			if (header_length > 0) {
				int flags = tvb_get_guint8(tvb, 7);
				tvbuff_t *header_data = tvb_new_subset(tvb, offset / 8,
						header_length, header_length);
				dissect_mpeg_pes_header_data(header_data, pinfo, tree, flags);
				offset += header_length * 8;
				 /* lenght may be zero for Video stream */
				if(length !=0 && stream != STREAM_VIDEO){
					length -= header_length * 8;
				}
			}

			/* lenght may be zero for Video stream */ 
			if(length==0){ 
				proto_tree_add_item(tree, hf_mpeg_pes_data, tvb, (offset>>3),-1, FALSE);
				return TRUE;
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
			unsigned data_length = tvb_get_ntohs(tvb, offset / 8);
			proto_tree_add_item(tree, hf_mpeg_pes_length, tvb,
					offset / 8, 2, FALSE);
			offset += 2 * 8;

			proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
					offset / 8, data_length, FALSE);
		}
	} else {
		proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
				offset / 8, -1, FALSE);
	}
	return TRUE;
}

static heur_dissector_list_t heur_subdissector_list;

static void
dissect_mpeg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree)) {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPEG");
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
		{ &hf_mpeg_pes_scr,
			{ "system clock reference (SCR)", "mpeg-pes.scr",
				FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_program_mux_rate,
			{ "PES program mux rate", "mpeg-pes.program-mux-rate",
				FT_UINT24, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_stuffing_length,
			{ "PES stuffing length", "mpeg-pes.stuffing-length",
				FT_UINT8, BASE_DEC, NULL, 0x07, NULL, HFILL }},
		{ &hf_mpeg_pes_stuffing,
			{ "PES stuffing bytes", "mpeg-pes.stuffing",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_extension,
			{ "PES extension", "mpeg-pes.extension",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_header_data,
			{ "PES header data", "mpeg-pes.header-data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_pts,
			{ "presentation time stamp (PTS)", "mpeg-pes.pts",
				FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_dts,
			{ "decode time stamp (DTS)", "mpeg-pes.dts",
				FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_escr,
			{ "elementary stream clock reference (ESCR)", "mpeg-pes.escr",
				FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_es_rate,
			{ "elementary stream rate", "mpeg-pes.es-rate",
				FT_UINT24, BASE_DEC, NULL, 0x7ffe, NULL, HFILL }},
		{ &hf_mpeg_pes_copy_info,
			{ "copy info", "mpeg-pes.copy-info",
				FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL }},
		{ &hf_mpeg_pes_crc,
			{ "CRC", "mpeg-pes.crc",
				FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_extension_flags,
			{ "extension flags", "mpeg-pes.extension-flags",
				FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_private_data,
			{ "private data", "mpeg-pes.private-data",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_pack_length,
			{ "pack length", "mpeg-pes.pack-length",
				FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_sequence,
			{ "sequence", "mpeg-pes.sequence",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_pstd_buffer,
			{ "P-STD buffer size", "mpeg-pes.pstd-buffer",
				FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_extension2,
			{ "extension2", "mpeg-pes.extension2",
				FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }},
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
		&ett_mpeg_pes_pack_header,
		&ett_mpeg_pes_header_data,
	};

	proto_mpeg = proto_register_protocol(
			"Moving Picture Experts Group", "MPEG", "mpeg");
	register_dissector("mpeg", dissect_mpeg, proto_mpeg);
	register_heur_dissector_list("mpeg", &heur_subdissector_list);

	proto_mpeg_pes = proto_register_protocol(
			"Packetized Elementary Stream", "MPEG PES", "mpeg-pes");
	proto_register_field_array(proto_mpeg_pes, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	new_register_dissector("mpeg-pes", dissect_mpeg_pes, proto_mpeg_pes);
}

void
proto_reg_handoff_mpeg_pes(void)
{
	dissector_handle_t mpeg_handle = find_dissector("mpeg");

	dissector_add("wtap_encap", WTAP_ENCAP_MPEG, mpeg_handle);
	heur_dissector_add("mpeg", dissect_mpeg_pes, proto_mpeg_pes);
}
