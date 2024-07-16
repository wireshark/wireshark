/* MPEG Packetized Elementary Stream (PES) packet decoder.
 * Written by Shaun Jackman <sjackman@gmail.com>.
 * Copyright 2007 Shaun Jackman
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include <wiretap/wtap.h>

#include "packet-per.h"

#include "packet-mpeg-pes-hf.c"
#include "packet-mpeg-pes-ett.c"
#include "packet-mpeg-pes-fn.c"

void proto_register_mpeg_pes(void);
void proto_reg_handoff_mpeg_pes(void);

static int proto_mpeg;
static int proto_mpeg_pes;

static int ett_mpeg_pes_pack_header;
static int ett_mpeg_pes_header_data;
static int ett_mpeg_pes_trick_mode;

static int hf_mpeg_pes_pack_header;
static int hf_mpeg_pes_scr;
static int hf_mpeg_pes_program_mux_rate;
static int hf_mpeg_pes_stuffing_length;
static int hf_mpeg_pes_stuffing;
static int hf_mpeg_pes_extension;
static int hf_mpeg_pes_header_data;
static int hf_mpeg_pes_pts;
static int hf_mpeg_pes_dts;
static int hf_mpeg_pes_escr;
static int hf_mpeg_pes_es_rate;
static int hf_mpeg_pes_dsm_trick_mode;
static int hf_mpeg_pes_dsm_trick_mode_control;
static int hf_mpeg_pes_dsm_trick_mode_field_id;
static int hf_mpeg_pes_dsm_trick_mode_intra_slice_refresh;
static int hf_mpeg_pes_dsm_trick_mode_frequency_truncation;
static int hf_mpeg_pes_dsm_trick_mode_rep_cntrl;
static int hf_mpeg_pes_copy_info;
static int hf_mpeg_pes_crc;
static int hf_mpeg_pes_extension_flags;
static int hf_mpeg_pes_private_data;
static int hf_mpeg_pes_pack_length;
static int hf_mpeg_pes_sequence;
static int hf_mpeg_pes_pstd_buffer;
static int hf_mpeg_pes_extension2;
static int hf_mpeg_pes_padding;
static int hf_mpeg_pes_data;

static int hf_mpeg_video_sequence_header;
static int hf_mpeg_video_sequence_extension;
static int hf_mpeg_video_group_of_pictures;
static int hf_mpeg_video_picture;
static int hf_mpeg_video_quantization_matrix;
static int hf_mpeg_video_data;

static dissector_handle_t mpeg_handle;

static dissector_table_t stream_type_table;

enum { PES_PREFIX = 1 };

/*
 * MPEG uses 32-bit start codes that all begin with the three byte sequence
 * 00 00 01 (the start code prefix) for bit and byte alignment, among other
 * purposes.
 *
 * The values from 0xb9 through 0xff are "system start codes" and described in
 * ISO/IEC 13818-1:2019 / ITU-T H.222.0. The bulk of them, 0xbc through 0xff,
 * are stream_id values and documented in Table 2-22 "Stream_id assignments".
 * The remaining three are used by Program Streams and found as follows:
 * 0xb9, the MPEG_program_end_code, in 2.5.3.2 "Semantic definition of fields
 * in program stream"
 * 0xba, the pack_start_code, in 2.5.3.4 "Semantic definition of fields in
 * program stream pack"
 * 0xbb, the system_header_start_code, in 2.5.3.6 "Semantic definition of fields
 * in system header"
 *
 * The remaining 185 values from 0x00 to 0xb8 are used by MPEG-2 video
 * (backwards compatible with MPEG-1 video) and documented in ISO/IEC 13818-2 /
 * ITU-T H.262 (2000), in Table 6-1 "Start code values". These are not stream
 * id values and do not mark PES packets, but rather demarcate elements in the
 * coded MPEG-1/2 video bitstream, at a different hierarchical level than the
 * PES packets. The sets of values used for video start codes and for stream
 * ids are disjoint to avoid any ambiguity when resynchronizing. Note the
 * dissector currently conflates MPEG video with MPEG PES.
 *
 * Care is taken to ensure that the start code prefix 0x000001 does not occur
 * elsewhere in the structure (avoiding "emulation of start codes").
 *
 * The video can have other formats, given by the stream type, carried on
 * TS in the PMT and in PS from the similar Program Stream Map. AVC/H.264 and
 * HEVC/H.265 carried in PES also use the start code prefix, before each NAL,
 * and escape the raw byte sequence with bytes that prevent internal start code
 * prefixes. The byte following the prefix (the first byte of the NAL header)
 * has high bit zero, so the values of the NAL header are in the range used by
 * the MPEG-2 video bitstream, not the range used by stream ids, allowing for
 * synchronization in the same way. See Annex B "Byte Stream Format" of H.264
 * and H.265.
 */
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

enum {
	FAST_FORWARD_CONTROL = 0x00,
	SLOW_MOTION_CONTROL = 0x01,
	FREEZE_FRAME_CONTROL = 0x02,
	FAST_REVERSE_CONTROL = 0x03,
	SLOW_REVERSE_CONTROL = 0x04
};

static const value_string mpeg_pes_TrickModeControl_vals[] = {
  { FAST_FORWARD_CONTROL, "fast-forward" },
  { SLOW_MOTION_CONTROL,  "slow-motion" },
  { FREEZE_FRAME_CONTROL, "freeze-frame" },
  { FAST_REVERSE_CONTROL, "fast-reverse" },
  { SLOW_REVERSE_CONTROL, "slow-reverse" },
  {   5, "reserved" },
  {   6, "reserved" },
  {   7, "reserved" },
  {   0, NULL }
};

static const value_string mpeg_pes_TrickModeFieldId_vals[] = {
  {   0, "display-from-top-field-only" },
  {   1, "display-from-bottom-field-only" },
  {   2, "display-complete-frame" },
  {   3, "reserved" },
  {   0, NULL }
};

static const value_string mpeg_pes_TrickModeIntraSliceRefresh_vals[] = {
  {   0, "macroblocks-may-not-be-missing" },
  {   1, "macroblocks-may-be-missing" },
  {   0, NULL }
};

static const value_string mpeg_pes_TrickModeFrequencyTruncation_vals[] = {
  {   0, "only-DC-coefficients-are-non-zero" },
  {   1, "only-the-first-three-coefficients-are-non-zero" },
  {   2, "only-the-first-six-coefficients-are-non-zero" },
  {   3, "all-coefficients-may-be-non-zero" },
  {   0, NULL }
};

#define TSHZ 90000

static uint64_t decode_time_stamp(tvbuff_t *tvb, int offset, nstime_t *nst)
{
	uint64_t bytes = tvb_get_ntoh40(tvb, offset);
	uint64_t ts =
		(bytes >> 33 & 0x0007) << 30 |
		(bytes >> 17 & 0x7fff) << 15 |
		(bytes >>  1 & 0x7fff) << 0;
	unsigned int rem = (unsigned int)(ts % TSHZ);
	nst->secs = (time_t)(ts / TSHZ);
	nst->nsecs = (int)(INT64_C(1000000000) * rem / TSHZ);
	return ts;
}

#define SCRHZ 27000000

static uint64_t decode_clock_reference(tvbuff_t *tvb, int offset,
		nstime_t *nst)
{
	uint64_t bytes = tvb_get_ntoh48(tvb, offset);
	uint64_t ts =
		(bytes >> 43 & 0x0007) << 30 |
		(bytes >> 27 & 0x7fff) << 15 |
		(bytes >> 11 & 0x7fff) << 0;
	unsigned int ext = (unsigned int)((bytes >> 1) & 0x1ff);
	uint64_t cr = 300 * ts + ext;
	unsigned int rem = (unsigned int)(cr % SCRHZ);
	nst->secs = (time_t)(cr / SCRHZ);
	nst->nsecs = (int)(INT64_C(1000000000) * rem / SCRHZ);
	return cr;
}

static int
dissect_mpeg_pes_header_data(tvbuff_t *tvb, packet_info *pinfo _U_,
		proto_tree *root, unsigned int flags)
{
	proto_item *item = proto_tree_add_item(root, hf_mpeg_pes_header_data, tvb,
			0, -1, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_mpeg_pes_header_data);

	int offset = 0;
	if (flags & PTS_FLAG) {
		nstime_t nst;
		decode_time_stamp(tvb, offset, &nst);
		proto_tree_add_time(tree, hf_mpeg_pes_pts, tvb,
				offset, 5, &nst);
		offset += 5;
	}
	if (flags & DTS_FLAG) {
		nstime_t nst;
		decode_time_stamp(tvb, offset, &nst);
		proto_tree_add_time(tree, hf_mpeg_pes_dts, tvb,
				offset, 5, &nst);
		offset += 5;
	}
	if (flags & ESCR_FLAG) {
		nstime_t nst;
		decode_clock_reference(tvb, offset, &nst);
		proto_tree_add_time(tree, hf_mpeg_pes_escr, tvb,
				offset, 6, &nst);
		offset += 6;
	}
	if (flags & ES_RATE_FLAG) {
		unsigned int es_rate = (tvb_get_ntohs(tvb, offset) >> 1 & 0x3fff) * 50;
		proto_tree_add_uint(tree, hf_mpeg_pes_es_rate, tvb,
				offset, 3, es_rate);
		offset += 3;
	}
	if (flags & DSM_TRICK_MODE_FLAG)
	{
		uint8_t value = tvb_get_uint8(tvb, offset);
		uint8_t control;
		proto_tree *trick_tree;
		proto_item *trick_item;

		trick_item = proto_tree_add_item(item,
			hf_mpeg_pes_dsm_trick_mode, tvb,
				offset, 1, ENC_NA);

		trick_tree = proto_item_add_subtree(trick_item,
			ett_mpeg_pes_trick_mode);

		control = (value >> 5);
		proto_tree_add_uint(trick_tree,
			hf_mpeg_pes_dsm_trick_mode_control, tvb,
			offset, 1,
			control);

		if (control == FAST_FORWARD_CONTROL
			|| control == FAST_REVERSE_CONTROL)
		{
			proto_tree_add_uint(trick_tree,
				hf_mpeg_pes_dsm_trick_mode_field_id, tvb,
				offset, 1,
				(value & 0x18) >> 3);

			proto_tree_add_uint(trick_tree,
				hf_mpeg_pes_dsm_trick_mode_intra_slice_refresh, tvb,
				offset, 1,
				(value & 0x04) >> 2);

			proto_tree_add_uint(trick_tree,
				hf_mpeg_pes_dsm_trick_mode_frequency_truncation, tvb,
				offset, 1,
				(value & 0x03));
		}
		else if (control == SLOW_MOTION_CONTROL
			|| control == SLOW_REVERSE_CONTROL)
		{
			proto_tree_add_uint(trick_tree,
				hf_mpeg_pes_dsm_trick_mode_rep_cntrl, tvb,
				offset, 1,
				(value & 0x1F));
		}
		else if (control == FREEZE_FRAME_CONTROL)
		{
			proto_tree_add_uint(trick_tree,
				hf_mpeg_pes_dsm_trick_mode_field_id, tvb,
				offset, 1,
				(value & 0x18) >> 3);
		}

		offset += 1;
	}
	if (flags & COPY_INFO_FLAG) {
		proto_tree_add_item(tree, hf_mpeg_pes_copy_info, tvb,
				offset, 1, ENC_BIG_ENDIAN);
		offset++;
	}
	if (flags & CRC_FLAG) {
		proto_tree_add_item(tree, hf_mpeg_pes_crc, tvb,
				offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
	}

	if (flags & EXTENSION_FLAG) {
		int flags2 = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(tree, hf_mpeg_pes_extension_flags, tvb,
				offset, 1, ENC_BIG_ENDIAN);
		offset++;

		if (flags2 & PRIVATE_DATA_FLAG) {
			proto_tree_add_item(tree, hf_mpeg_pes_private_data, tvb,
					offset, 16, ENC_NA);
			offset += 16;
		}
		if (flags2 & PACK_LENGTH_FLAG) {
			proto_tree_add_item(tree, hf_mpeg_pes_pack_length, tvb,
					offset, 1, ENC_BIG_ENDIAN);
			offset++;
		}
		if (flags2 & SEQUENCE_FLAG) {
			proto_tree_add_item(tree, hf_mpeg_pes_sequence, tvb,
					offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		if (flags2 & PSTD_BUFFER_FLAG) {
			unsigned int pstd = tvb_get_ntohs(tvb, offset);
			proto_tree_add_uint(tree, hf_mpeg_pes_pstd_buffer, tvb,
					offset, 2, (pstd & 0x2000 ? 1024 : 128) * (pstd & 0x1ff));
			offset += 2;
		}
		if (flags2 & EXTENSION_FLAG2) {
			proto_tree_add_item(tree, hf_mpeg_pes_extension2, tvb,
					offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
	}
	return offset;
}

static int
dissect_mpeg_pes_pack_header(tvbuff_t *tvb, int offset,
		packet_info *pinfo _U_, proto_tree *root)
{
	unsigned int program_mux_rate, stuffing_length;

	proto_item *item = proto_tree_add_item(root, hf_mpeg_pes_pack_header, tvb,
			offset / 8, 10, ENC_NA);
	proto_tree *tree = proto_item_add_subtree(item, ett_mpeg_pes_pack_header);

	nstime_t nst;
	decode_clock_reference(tvb, offset / 8, &nst);
	proto_tree_add_time(tree, hf_mpeg_pes_scr, tvb, offset / 8, 6, &nst);
	offset += 6 * 8;

	program_mux_rate = (tvb_get_ntoh24(tvb, offset / 8) >> 2) * 50;
	proto_tree_add_uint(tree, hf_mpeg_pes_program_mux_rate, tvb, offset / 8, 3,
			program_mux_rate);
	offset += 3 * 8;

	stuffing_length = tvb_get_uint8(tvb, offset / 8) & 0x07;
	proto_tree_add_item(tree, hf_mpeg_pes_stuffing_length, tvb,
			offset / 8, 1, ENC_BIG_ENDIAN);
	offset += 1 * 8;

	if (stuffing_length > 0) {
		proto_tree_add_item(tree, hf_mpeg_pes_stuffing, tvb,
				offset / 8, stuffing_length, ENC_NA);
		offset += stuffing_length * 8;
	}

	return offset;
}

static int
dissect_mpeg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_mpeg_pes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	int prefix;
	int stream;
	asn1_ctx_t asn1_ctx;
	int offset = 0;
	uint8_t stream_type;

	if (!tvb_bytes_exist(tvb, 0, 3))
		return 0;	/* not enough bytes for a PES prefix */

	prefix = tvb_get_ntoh24(tvb, 0);
	if (prefix != PES_PREFIX)
		return 0;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPEG PES");
	col_clear(pinfo->cinfo, COL_INFO);

	stream = tvb_get_uint8(tvb, 3);
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(stream, mpeg_pes_T_stream_vals, "Unknown stream: %d"));

	/* Were we called from MP2T providing a stream type from a PMT? */
	stream_type = GPOINTER_TO_UINT(data);
	/* Luckily, stream_type 0 is reserved, so a null value is fine.
	 * XXX: Implement Program Stream Map for Program Stream (similar
	 * to PMT but maps stream_ids to stream_types instead of PIDs.)
	 */

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
	offset = dissect_mpeg_pes_PES(tvb, offset, &asn1_ctx,
			tree, proto_mpeg_pes);

	increment_dissection_depth(pinfo);
	if (stream == STREAM_PICTURE) {
		int frame_type;

		frame_type = tvb_get_uint8(tvb, 5) >> 3 & 0x07;
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(frame_type, mpeg_pes_T_frame_type_vals, "Unknown frame type: %d"));

		offset = dissect_mpeg_pes_Picture(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_picture);
		proto_tree_add_item(tree, hf_mpeg_video_data, tvb,
				offset / 8, -1, ENC_NA);
	} else if (stream == STREAM_SEQUENCE) {
		tvbuff_t *es;

		offset = dissect_mpeg_pes_Sequence_header(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_sequence_header);

		proto_tree_add_item(tree, hf_mpeg_video_quantization_matrix, tvb,
				offset / 8, 64, ENC_NA);
		offset += 64 * 8;

		es = tvb_new_subset_remaining(tvb, offset / 8);
		dissect_mpeg_pes(es, pinfo, tree, NULL);
	} else if (stream == STREAM_SEQUENCE_EXTENSION) {
		tvbuff_t *es;

		offset = dissect_mpeg_pes_Sequence_extension(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_sequence_extension);

		es = tvb_new_subset_remaining(tvb, offset / 8);
		dissect_mpeg_pes(es, pinfo, tree, NULL);
	} else if (stream == STREAM_GOP) {
		tvbuff_t *es;

		offset = dissect_mpeg_pes_Group_of_pictures(tvb, offset, &asn1_ctx,
				tree, hf_mpeg_video_group_of_pictures);

		es = tvb_new_subset_remaining(tvb, offset / 8);
		dissect_mpeg_pes(es, pinfo, tree, NULL);
	} else if (stream == STREAM_PACK) {
		if (tvb_get_uint8(tvb, offset / 8) >> 6 == 1) {
			dissect_mpeg_pes_pack_header(tvb, offset, pinfo, tree);
		} else {
			proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
					offset / 8, 8, ENC_NA);
		}
	} else if (stream == STREAM_SYSTEM || stream == STREAM_PRIVATE2) {
		unsigned int data_length = tvb_get_ntohs(tvb, offset / 8);
		proto_tree_add_item(tree, hf_mpeg_pes_length, tvb,
				offset / 8, 2, ENC_BIG_ENDIAN);
		offset += 2 * 8;

		proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
				offset / 8, data_length, ENC_NA);
	} else if (stream == STREAM_PADDING) {
		unsigned int padding_length = tvb_get_ntohs(tvb, offset / 8);
		proto_tree_add_item(tree, hf_mpeg_pes_length, tvb,
				offset / 8, 2, ENC_BIG_ENDIAN);
		offset += 2 * 8;

		proto_tree_add_item(tree, hf_mpeg_pes_padding, tvb,
				offset / 8, padding_length, ENC_NA);
	} else if (stream == STREAM_PRIVATE1
			|| stream >= STREAM_AUDIO) {
		int length = tvb_get_ntohs(tvb, 4);

		if ((tvb_get_uint8(tvb, 6) & 0xc0) == 0x80) {
			int header_length;
			tvbuff_t *es;
			int save_offset = offset;

			offset = dissect_mpeg_pes_Stream(tvb, offset, &asn1_ctx,
					tree, hf_mpeg_pes_extension);
			/* https://gitlab.com/wireshark/wireshark/-/issues/2229
			 * A value of 0 indicates that the PES packet length
			 * is neither specified nor bounded and is allowed
			 * only in PES packets whose payload is a video
			 * elementary stream contained in Transport Stream
			 * packets.
			 *
			 * See ISO/IEC 13818-1:2007, section 2.4.3.7
			 * "Semantic definition of fields in PES packet",
			 * which says of the PES_packet_length that "A value
			 * of 0 indicates that the PES packet length is
			 * neither specified nor bounded and is allowed only
			 * in PES packets whose payload consists of bytes
			 * from a video elementary stream contained in
			 * Transport Stream packets."
			 */
			if(length !=0 && stream != STREAM_VIDEO){
				/*
				 * XXX - note that ISO/IEC 13818-1:2007
				 * says that the length field is *not*
				 * part of the above extension.
				 *
				 * This means that the length of the length
				 * field itself should *not* be subtracted
				 * from the length field; ISO/IEC 13818-1:2007
				 * says that the PES_packet_length field is
				 * "A 16-bit field specifying the number of
				 * bytes in the PES packet following the
				 * last byte of the field."
				 *
				 * So we calculate the size of the extension,
				 * in bytes, by subtracting the saved bit
				 * offset value from the current bit offset
				 * value, divide by 8 to convert to a size
				 * in bytes, and then subtract 2 to remove
				 * the length field's length from the total
				 * length.
				 *
				 * (In addition, ISO/IEC 13818-1:2007
				 * suggests that the length field is
				 * always present, but this code, when
				 * processing some stream ID types, doesn't
				 * treat it as being present.  Where are
				 * the formats of those payloads specified?)
				 */
				length -= ((offset - save_offset) / 8) - 2;
			}

			header_length = tvb_get_uint8(tvb, 8);
			if (header_length > 0) {
				int flags = tvb_get_uint8(tvb, 7);
				tvbuff_t *header_data = tvb_new_subset_length(tvb, offset / 8,
						header_length);
				dissect_mpeg_pes_header_data(header_data, pinfo, tree, flags);
				offset += header_length * 8;
				 /* length may be zero for Video stream */
				if(length !=0 && stream != STREAM_VIDEO){
					length -= header_length;
				}
			}

			/* length may be zero for Video stream */
			if(length==0){
				es = tvb_new_subset_remaining(tvb, offset / 8);
			} else {
				es = tvb_new_subset_length_caplen(tvb, offset / 8, -1, length);
			}
			if (!dissector_try_uint_new(stream_type_table, stream_type, es, pinfo, tree, true, NULL)) {
				/* If we didn't get a stream type, then assume
				 * MPEG-1/2 Audio or Video.
				 */
				if (tvb_get_ntoh24(es, 0) == PES_PREFIX)
					dissect_mpeg_pes(es, pinfo, tree, NULL);
				else if (tvb_get_uint8(es, 0) == 0xff)
					dissect_mpeg(es, pinfo, tree, NULL);
				else
					proto_tree_add_item(tree, hf_mpeg_pes_data, es,
							0, -1, ENC_NA);
			}
		} else {
			unsigned int data_length = tvb_get_ntohs(tvb, offset / 8);
			proto_tree_add_item(tree, hf_mpeg_pes_length, tvb,
					offset / 8, 2, ENC_BIG_ENDIAN);
			offset += 2 * 8;

			proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
					offset / 8, data_length, ENC_NA);
		}
	} else if (stream != STREAM_END) {
		proto_tree_add_item(tree, hf_mpeg_pes_data, tvb,
				offset / 8, -1, ENC_NA);
	}
	decrement_dissection_depth(pinfo);
	return tvb_reported_length(tvb);
}

static heur_dissector_list_t heur_subdissector_list;

static int
dissect_mpeg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    heur_dtbl_entry_t *hdtbl_entry;

    if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &hdtbl_entry, NULL)) {
	    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPEG");
	    col_clear(pinfo->cinfo, COL_INFO);

	    proto_tree_add_item(tree, proto_mpeg, tvb, 0, -1, ENC_NA);
    }
	return tvb_captured_length(tvb);
}

static bool
dissect_mpeg_pes_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  return dissect_mpeg_pes(tvb, pinfo, tree, data) > 0;
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
		{ &hf_mpeg_pes_dsm_trick_mode,
			{ "Trick mode", "mpeg-pes.trick-mode",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode_control,
			{ "control", "mpeg-pes.trick-mode-control",
				FT_UINT8, BASE_HEX, VALS(mpeg_pes_TrickModeControl_vals), 0,
				"mpeg_pes trick mode control", HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode_field_id,
			{ "field id", "mpeg-pes.trick-mode-field-id",
				FT_UINT8, BASE_HEX, VALS(mpeg_pes_TrickModeFieldId_vals), 0,
				"mpeg_pes trick mode field id", HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode_intra_slice_refresh,
			{ "intra slice refresh", "mpeg-pes.trick-mode-intra-slice-refresh",
				FT_UINT8, BASE_HEX, VALS(mpeg_pes_TrickModeIntraSliceRefresh_vals), 0,
				"mpeg_pes trick mode intra slice refresh", HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode_frequency_truncation,
			{ "frequency truncation", "mpeg-pes.trick-mode-frequency-truncation",
				FT_UINT8, BASE_HEX, VALS(mpeg_pes_TrickModeFrequencyTruncation_vals), 0,
				"mpeg_pes trick mode frequency truncation", HFILL }},
		{ &hf_mpeg_pes_dsm_trick_mode_rep_cntrl,
			{ "rep cntrl", "mpeg-pes.trick-mode-rep-cntrl",
				FT_UINT8, BASE_HEX, NULL, 0, "mpeg_pes trick mode rep cntrl", HFILL }},
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
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
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

	static int *ett[] = {
#include "packet-mpeg-pes-ettarr.c"
		&ett_mpeg_pes_pack_header,
		&ett_mpeg_pes_header_data,
		&ett_mpeg_pes_trick_mode
	};

	proto_mpeg = proto_register_protocol("Moving Picture Experts Group", "MPEG", "mpeg");
	mpeg_handle = register_dissector("mpeg", dissect_mpeg, proto_mpeg);
	heur_subdissector_list = register_heur_dissector_list_with_description("mpeg", "MPEG payload", proto_mpeg);

	proto_mpeg_pes = proto_register_protocol("Packetized Elementary Stream", "MPEG PES", "mpeg-pes");
	proto_register_field_array(proto_mpeg_pes, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("mpeg-pes", dissect_mpeg_pes, proto_mpeg_pes);

	stream_type_table = register_dissector_table("mpeg-pes.stream", "MPEG PES stream type", proto_mpeg_pes, FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_mpeg_pes(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_MPEG, mpeg_handle);
	heur_dissector_add("mpeg", dissect_mpeg_pes_heur, "MPEG PES", "mpeg_pes", proto_mpeg_pes, HEURISTIC_ENABLE);

	dissector_add_uint("mpeg-pes.stream", 0x1B, find_dissector_add_dependency("h264_bytestream", proto_mpeg_pes));
	dissector_add_uint("mpeg-pes.stream", 0x24, find_dissector_add_dependency("h265_bytestream", proto_mpeg_pes));
}
