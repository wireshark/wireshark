/* MPEG audio packet decoder.
 * Written by Shaun Jackman <sjackman@gmail.com>.
 * Copyright 2007 Shaun Jackman
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include <wsutil/mpeg-audio.h>

#include "packet-per.h"

#include "packet-mpeg-audio-hf.c"
#include "packet-mpeg-audio-ett.c"
#include "packet-mpeg-audio-fn.c"

void proto_register_mpeg_audio(void);
void proto_reg_handoff_mpeg_audio(void);

dissector_handle_t mpeg_audio_handle;

static int proto_mpeg_audio;
static dissector_handle_t id3v2_handle;

static int hf_mpeg_audio_header;
static int hf_mpeg_audio_data;
static int hf_mpeg_audio_padbytes;
static int hf_id3v1;

static int ett_mpeg_audio;

static bool
test_mpeg_audio(tvbuff_t *tvb, int offset)
{
	uint32_t hdr;
	struct mpa mpa;

	if (!tvb_bytes_exist(tvb, offset, 4))
		return false;
	if (tvb_strneql(tvb, offset, "TAG", 3) == 0)
		return true;
	if (tvb_strneql(tvb, offset, "ID3", 3) == 0)
		return true;

	hdr = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
	MPA_UNMARSHAL(&mpa, hdr);
	return MPA_VALID(&mpa);
}

static int
mpeg_resync(tvbuff_t *tvb, int offset)
{
	uint32_t hdr;
	struct mpa mpa;

	/* This only looks to resync on another frame; it doesn't
	 * look for an ID3 tag.
	 */
	offset = tvb_find_guint8(tvb, offset, -1, '\xff');
	while (offset != -1 && tvb_bytes_exist(tvb, offset, 4)) {
		hdr = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
		MPA_UNMARSHAL(&mpa, hdr);
		if (MPA_VALID(&mpa)) {
			return offset;
		}
		offset = tvb_find_guint8(tvb, offset + 1, -1, '\xff');
	}
	return tvb_reported_length(tvb);
}

static int
dissect_mpeg_audio_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t h;
	struct mpa mpa;
	int data_size = 0;
	asn1_ctx_t asn1_ctx;
	int offset = 0;
	static const char *version_names[] = { "1", "2", "2.5" };

	if (!tvb_bytes_exist(tvb, 0, 4))
		return 0;

	h = tvb_get_ntohl(tvb, 0);
	MPA_UNMARSHAL(&mpa, h);
	if (!MPA_SYNC_VALID(&mpa) || !MPA_VERSION_VALID(&mpa) || !MPA_LAYER_VALID(&mpa)) {
		return 0;
	}

	col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
			"MPEG-%s", version_names[mpa_version(&mpa)]);
	col_add_fstr(pinfo->cinfo, COL_INFO,
				"Audio Layer %d", mpa_layer(&mpa) + 1);
	if (MPA_BITRATE_VALID(&mpa) && MPA_FREQUENCY_VALID(&mpa)) {
		data_size = (int)(MPA_DATA_BYTES(&mpa) - sizeof mpa);
		col_append_fstr(pinfo->cinfo, COL_INFO,
						", %d kb/s, %g kHz",
						mpa_bitrate(&mpa) / 1000,
						mpa_frequency(&mpa) / (float)1000);
	}

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
	offset = dissect_mpeg_audio_Audio(tvb, offset, &asn1_ctx,
			tree, hf_mpeg_audio_header);
	if (data_size > 0) {
		unsigned int padding;

		proto_tree_add_item(tree, hf_mpeg_audio_data, tvb,
				offset / 8, data_size, ENC_NA);
		offset += data_size * 8;
		padding = mpa_padding(&mpa);
		if (padding > 0) {
			proto_tree_add_item(tree, hf_mpeg_audio_padbytes, tvb,
					offset / 8, padding, ENC_NA);
			offset += padding * 8;
		}
	}
	return offset / 8;
}

static int
dissect_id3v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	asn1_ctx_t asn1_ctx;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ID3v1");
	col_clear(pinfo->cinfo, COL_INFO);
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
	return dissect_mpeg_audio_ID3v1(tvb, 0, &asn1_ctx,
			tree, hf_id3v1);
}

static int
dissect_mpeg_audio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *mpeg_audio_tree;

	int magic, offset = 0;
	uint32_t frame_len;
	tvbuff_t *next_tvb;

	ti = proto_tree_add_item(tree, proto_mpeg_audio, tvb, offset, -1, ENC_NA);
	mpeg_audio_tree = proto_item_add_subtree(ti, ett_mpeg_audio);
	while (tvb_reported_length_remaining(tvb, offset) >= 4) {
		next_tvb = tvb_new_subset_remaining(tvb, offset);
		magic = tvb_get_ntoh24(next_tvb, 0);
		switch (magic) {
			case 0x544147: /* TAG */
				offset += dissect_id3v1(next_tvb, pinfo, mpeg_audio_tree);
				break;
			case 0x494433: /* ID3 */
				offset += call_dissector(id3v2_handle, tvb, pinfo, mpeg_audio_tree);
				break;
			default:
				frame_len = dissect_mpeg_audio_frame(next_tvb, pinfo, mpeg_audio_tree);
				if (frame_len == 0) {
					frame_len = mpeg_resync(next_tvb, 0);
				}
				offset += frame_len;
		}
	}
	return tvb_reported_length(tvb);
}

static bool
dissect_mpeg_audio_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	if (!test_mpeg_audio(tvb, 0)) {
		return false;
	}
	dissect_mpeg_audio(tvb, pinfo, tree, data);
	return true;
}

void
proto_register_mpeg_audio(void)
{
	static hf_register_info hf[] = {
#include "packet-mpeg-audio-hfarr.c"
		{ &hf_mpeg_audio_header,
			{ "Frame Header", "mpeg-audio.header",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_audio_data,
			{ "Data", "mpeg-audio.data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_audio_padbytes,
			{ "Padding", "mpeg-audio.padbytes",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_id3v1,
			{ "ID3v1", "mpeg-audio.id3v1",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	};

	static int *ett[] = {
		&ett_mpeg_audio,
#include "packet-mpeg-audio-ettarr.c"
	};

	proto_mpeg_audio = proto_register_protocol("Moving Picture Experts Group Audio", "MPEG Audio", "mpeg-audio");
	proto_register_field_array(proto_mpeg_audio, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	mpeg_audio_handle = register_dissector("mpeg-audio", dissect_mpeg_audio, proto_mpeg_audio);
}

void
proto_reg_handoff_mpeg_audio(void)
{
	dissector_add_string("media_type", "audio/mpeg", mpeg_audio_handle);
	/* "audio/mp3" used by Chrome before 2020 */
	/* https://chromium.googlesource.com/chromium/src/+/842f46a95f49e24534ad35c7a71e5c425d426550 */
	dissector_add_string("media_type", "audio/mp3", mpeg_audio_handle);

	heur_dissector_add("mpeg", dissect_mpeg_audio_heur, "MPEG Audio", "mpeg_audio", proto_mpeg_audio, HEURISTIC_ENABLE);

	id3v2_handle = find_dissector("id3v2");
}
