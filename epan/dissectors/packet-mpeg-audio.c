/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-mpeg-audio.c                                                        */
/* asn2wrs.py -q -L -p mpeg-audio -c ./mpeg-audio.cnf -s ./packet-mpeg-audio-template -D . -O ../.. mpeg-audio.asn */

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

static int hf_mpeg_audio_sync;                    /* BIT_STRING_SIZE_11 */
static int hf_mpeg_audio_version;                 /* T_version */
static int hf_mpeg_audio_layer;                   /* T_layer */
static int hf_mpeg_audio_protection;              /* T_protection */
static int hf_mpeg_audio_bitrate;                 /* INTEGER_0_15 */
static int hf_mpeg_audio_frequency;               /* INTEGER_0_3 */
static int hf_mpeg_audio_padding;                 /* BOOLEAN */
static int hf_mpeg_audio_private;                 /* BOOLEAN */
static int hf_mpeg_audio_channel_mode;            /* T_channel_mode */
static int hf_mpeg_audio_mode_extension;          /* INTEGER_0_3 */
static int hf_mpeg_audio_copyright;               /* BOOLEAN */
static int hf_mpeg_audio_original;                /* BOOLEAN */
static int hf_mpeg_audio_emphasis;                /* T_emphasis */
static int hf_mpeg_audio_tag;                     /* OCTET_STRING_SIZE_3 */
static int hf_mpeg_audio_title;                   /* OCTET_STRING_SIZE_30 */
static int hf_mpeg_audio_artist;                  /* OCTET_STRING_SIZE_30 */
static int hf_mpeg_audio_album;                   /* OCTET_STRING_SIZE_30 */
static int hf_mpeg_audio_year;                    /* OCTET_STRING_SIZE_4 */
static int hf_mpeg_audio_comment;                 /* OCTET_STRING_SIZE_28 */
static int hf_mpeg_audio_must_be_zero;            /* INTEGER_0_255 */
static int hf_mpeg_audio_track;                   /* INTEGER_0_255 */
static int hf_mpeg_audio_genre;                   /* T_genre */
static int ett_mpeg_audio_Audio;
static int ett_mpeg_audio_ID3v1;


static int
dissect_mpeg_audio_BIT_STRING_SIZE_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     11, 11, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string mpeg_audio_T_version_vals[] = {
  {   0, "mpeg-2-5" },
  {   1, "reserved" },
  {   2, "mpeg-2" },
  {   3, "mpeg-1" },
  { 0, NULL }
};


static int
dissect_mpeg_audio_T_version(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}


static const value_string mpeg_audio_T_layer_vals[] = {
  {   0, "reserved" },
  {   1, "layer-3" },
  {   2, "layer-2" },
  {   3, "layer-1" },
  { 0, NULL }
};


static int
dissect_mpeg_audio_T_layer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}


static const value_string mpeg_audio_T_protection_vals[] = {
  {   0, "crc" },
  {   1, "none" },
  { 0, NULL }
};


static int
dissect_mpeg_audio_T_protection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_mpeg_audio_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}



static int
dissect_mpeg_audio_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}



static int
dissect_mpeg_audio_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string mpeg_audio_T_channel_mode_vals[] = {
  {   0, "stereo" },
  {   1, "joint-stereo" },
  {   2, "dual-channel" },
  {   3, "single-channel" },
  { 0, NULL }
};


static int
dissect_mpeg_audio_T_channel_mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}


static const value_string mpeg_audio_T_emphasis_vals[] = {
  {   0, "none" },
  {   1, "em-50-15-ms" },
  {   2, "reserved" },
  {   3, "ccit-j-17" },
  { 0, NULL }
};


static int
dissect_mpeg_audio_T_emphasis(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t Audio_sequence[] = {
  { &hf_mpeg_audio_sync     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_BIT_STRING_SIZE_11 },
  { &hf_mpeg_audio_version  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_T_version },
  { &hf_mpeg_audio_layer    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_T_layer },
  { &hf_mpeg_audio_protection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_T_protection },
  { &hf_mpeg_audio_bitrate  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_INTEGER_0_15 },
  { &hf_mpeg_audio_frequency, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_INTEGER_0_3 },
  { &hf_mpeg_audio_padding  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_BOOLEAN },
  { &hf_mpeg_audio_private  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_BOOLEAN },
  { &hf_mpeg_audio_channel_mode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_T_channel_mode },
  { &hf_mpeg_audio_mode_extension, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_INTEGER_0_3 },
  { &hf_mpeg_audio_copyright, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_BOOLEAN },
  { &hf_mpeg_audio_original , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_BOOLEAN },
  { &hf_mpeg_audio_emphasis , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_T_emphasis },
  { NULL, 0, 0, NULL }
};

static int
dissect_mpeg_audio_Audio(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_mpeg_audio_Audio, Audio_sequence);

  return offset;
}



static int
dissect_mpeg_audio_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}



static int
dissect_mpeg_audio_OCTET_STRING_SIZE_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       30, 30, false, NULL);

  return offset;
}



static int
dissect_mpeg_audio_OCTET_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}



static int
dissect_mpeg_audio_OCTET_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       28, 28, false, NULL);

  return offset;
}



static int
dissect_mpeg_audio_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const value_string mpeg_audio_T_genre_vals[] = {
  {   0, "blues" },
  {   1, "classic-rock" },
  {   2, "country" },
  {   3, "dance" },
  {   4, "disco" },
  {   5, "funk" },
  {   6, "grunge" },
  {   7, "hip-hop" },
  {   8, "jazz" },
  {   9, "metal" },
  {  10, "new-age" },
  {  11, "oldies" },
  {  12, "other" },
  {  13, "pop" },
  {  14, "r-and-b" },
  {  15, "rap" },
  {  16, "reggae" },
  {  17, "rock" },
  {  18, "techno" },
  {  19, "industrial" },
  {  20, "alternative" },
  {  21, "ska" },
  {  22, "death-metal" },
  {  23, "pranks" },
  {  24, "soundtrack" },
  {  25, "euro-techno" },
  {  26, "ambient" },
  {  27, "trip-hop" },
  {  28, "vocal" },
  {  29, "jazz-and-funk" },
  {  30, "fusion" },
  {  31, "trance" },
  {  32, "classical" },
  {  33, "instrumental" },
  {  34, "acid" },
  {  35, "house" },
  {  36, "game" },
  {  37, "sound-clip" },
  {  38, "gospel" },
  {  39, "noise" },
  {  40, "alternative-rock" },
  {  41, "bass" },
  {  42, "soul" },
  {  43, "punk" },
  {  44, "space" },
  {  45, "meditative" },
  {  46, "instrumental-pop" },
  {  47, "instrumental-rock" },
  {  48, "ethnic" },
  {  49, "gothic" },
  {  50, "darkwave" },
  {  51, "techno-industrial" },
  {  52, "electronic" },
  {  53, "pop-folk" },
  {  54, "eurodance" },
  {  55, "dream" },
  {  56, "southern-rock" },
  {  57, "comedy" },
  {  58, "cult" },
  {  59, "gangsta" },
  {  60, "top-40" },
  {  61, "christian-rap" },
  {  62, "pop-funk" },
  {  63, "jungle" },
  {  64, "native-american" },
  {  65, "cabaret" },
  {  66, "new-wave" },
  {  67, "psychedelic" },
  {  68, "rave" },
  {  69, "showtunes" },
  {  70, "trailer" },
  {  71, "lo-fi" },
  {  72, "tribal" },
  {  73, "acid-punk" },
  {  74, "acid-jazz" },
  {  75, "polka" },
  {  76, "retro" },
  {  77, "musical" },
  {  78, "rock-and-roll" },
  {  79, "hard-rock" },
  {  80, "folk" },
  {  81, "folk-rock" },
  {  82, "national-folk" },
  {  83, "swing" },
  {  84, "fast-fusion" },
  {  85, "bebob" },
  {  86, "latin" },
  {  87, "revival" },
  {  88, "celtic" },
  {  89, "bluegrass" },
  {  90, "avantgarde" },
  {  91, "gothic-rock" },
  {  92, "progressive-rock" },
  {  93, "psychedelic-rock" },
  {  94, "symphonic-rock" },
  {  95, "slow-rock" },
  {  96, "big-band" },
  {  97, "chorus" },
  {  98, "easy-listening" },
  {  99, "acoustic" },
  { 100, "humour" },
  { 101, "speech" },
  { 102, "chanson" },
  { 103, "opera" },
  { 104, "chamber-music" },
  { 105, "sonata" },
  { 106, "symphony" },
  { 107, "booty-bass" },
  { 108, "primus" },
  { 109, "porn-groove" },
  { 110, "satire" },
  { 111, "slow-jam" },
  { 112, "club" },
  { 113, "tango" },
  { 114, "samba" },
  { 115, "folklore" },
  { 116, "ballad" },
  { 117, "power-ballad" },
  { 118, "rhythmic-soul" },
  { 119, "freestyle" },
  { 120, "duet" },
  { 121, "punk-rock" },
  { 122, "drum-solo" },
  { 123, "a-cappella" },
  { 124, "euro-house" },
  { 125, "dance-hall" },
  { 0, NULL }
};


static int
dissect_mpeg_audio_T_genre(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t ID3v1_sequence[] = {
  { &hf_mpeg_audio_tag      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_OCTET_STRING_SIZE_3 },
  { &hf_mpeg_audio_title    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_OCTET_STRING_SIZE_30 },
  { &hf_mpeg_audio_artist   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_OCTET_STRING_SIZE_30 },
  { &hf_mpeg_audio_album    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_OCTET_STRING_SIZE_30 },
  { &hf_mpeg_audio_year     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_OCTET_STRING_SIZE_4 },
  { &hf_mpeg_audio_comment  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_OCTET_STRING_SIZE_28 },
  { &hf_mpeg_audio_must_be_zero, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_INTEGER_0_255 },
  { &hf_mpeg_audio_track    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_INTEGER_0_255 },
  { &hf_mpeg_audio_genre    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpeg_audio_T_genre },
  { NULL, 0, 0, NULL }
};

static int
dissect_mpeg_audio_ID3v1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_mpeg_audio_ID3v1, ID3v1_sequence);

  return offset;
}


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
    { &hf_mpeg_audio_sync,
      { "sync", "mpeg-audio.sync",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_11", HFILL }},
    { &hf_mpeg_audio_version,
      { "version", "mpeg-audio.version",
        FT_UINT32, BASE_DEC, VALS(mpeg_audio_T_version_vals), 0,
        NULL, HFILL }},
    { &hf_mpeg_audio_layer,
      { "layer", "mpeg-audio.layer",
        FT_UINT32, BASE_DEC, VALS(mpeg_audio_T_layer_vals), 0,
        NULL, HFILL }},
    { &hf_mpeg_audio_protection,
      { "protection", "mpeg-audio.protection",
        FT_UINT32, BASE_DEC, VALS(mpeg_audio_T_protection_vals), 0,
        NULL, HFILL }},
    { &hf_mpeg_audio_bitrate,
      { "bitrate", "mpeg-audio.bitrate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_mpeg_audio_frequency,
      { "frequency", "mpeg-audio.frequency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_mpeg_audio_padding,
      { "padding", "mpeg-audio.padding",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_audio_private,
      { "private", "mpeg-audio.private",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_audio_channel_mode,
      { "channel-mode", "mpeg-audio.channel_mode",
        FT_UINT32, BASE_DEC, VALS(mpeg_audio_T_channel_mode_vals), 0,
        NULL, HFILL }},
    { &hf_mpeg_audio_mode_extension,
      { "mode-extension", "mpeg-audio.mode_extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_mpeg_audio_copyright,
      { "copyright", "mpeg-audio.copyright",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_audio_original,
      { "original", "mpeg-audio.original",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mpeg_audio_emphasis,
      { "emphasis", "mpeg-audio.emphasis",
        FT_UINT32, BASE_DEC, VALS(mpeg_audio_T_emphasis_vals), 0,
        NULL, HFILL }},
    { &hf_mpeg_audio_tag,
      { "tag", "mpeg-audio.tag",
        FT_STRING, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_mpeg_audio_title,
      { "title", "mpeg-audio.title",
        FT_STRING, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_30", HFILL }},
    { &hf_mpeg_audio_artist,
      { "artist", "mpeg-audio.artist",
        FT_STRING, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_30", HFILL }},
    { &hf_mpeg_audio_album,
      { "album", "mpeg-audio.album",
        FT_STRING, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_30", HFILL }},
    { &hf_mpeg_audio_year,
      { "year", "mpeg-audio.year",
        FT_STRING, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_mpeg_audio_comment,
      { "comment", "mpeg-audio.comment",
        FT_STRING, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_28", HFILL }},
    { &hf_mpeg_audio_must_be_zero,
      { "must-be-zero", "mpeg-audio.must_be_zero",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_mpeg_audio_track,
      { "track", "mpeg-audio.track",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_mpeg_audio_genre,
      { "genre", "mpeg-audio.genre",
        FT_UINT32, BASE_DEC, VALS(mpeg_audio_T_genre_vals), 0,
        NULL, HFILL }},
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
    &ett_mpeg_audio_Audio,
    &ett_mpeg_audio_ID3v1,
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
