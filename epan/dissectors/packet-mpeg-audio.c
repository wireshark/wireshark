/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-mpeg-audio.c                                                        */
/* ../../tools/asn2wrs.py -p mpeg-audio -c ./mpeg-audio.cnf -s ./packet-mpeg-audio-template -D . mpeg-audio.asn */

/* Input file: packet-mpeg-audio-template.c */

#line 1 "../../asn1/mpeg-audio/packet-mpeg-audio-template.c"
/* MPEG audio packet decoder.
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/asn1.h>

#include <wsutil/mpeg-audio.h>

#include "packet-per.h"


/*--- Included file: packet-mpeg-audio-hf.c ---*/
#line 1 "../../asn1/mpeg-audio/packet-mpeg-audio-hf.c"
static int hf_mpeg_audio_sync = -1;               /* BIT_STRING_SIZE_11 */
static int hf_mpeg_audio_version = -1;            /* T_version */
static int hf_mpeg_audio_layer = -1;              /* T_layer */
static int hf_mpeg_audio_protection = -1;         /* T_protection */
static int hf_mpeg_audio_bitrate = -1;            /* INTEGER_0_15 */
static int hf_mpeg_audio_frequency = -1;          /* INTEGER_0_3 */
static int hf_mpeg_audio_padding = -1;            /* BOOLEAN */
static int hf_mpeg_audio_private = -1;            /* BOOLEAN */
static int hf_mpeg_audio_channel_mode = -1;       /* T_channel_mode */
static int hf_mpeg_audio_mode_extension = -1;     /* INTEGER_0_3 */
static int hf_mpeg_audio_copyright = -1;          /* BOOLEAN */
static int hf_mpeg_audio_original = -1;           /* BOOLEAN */
static int hf_mpeg_audio_emphasis = -1;           /* T_emphasis */
static int hf_mpeg_audio_tag = -1;                /* OCTET_STRING_SIZE_3 */
static int hf_mpeg_audio_title = -1;              /* OCTET_STRING_SIZE_30 */
static int hf_mpeg_audio_artist = -1;             /* OCTET_STRING_SIZE_30 */
static int hf_mpeg_audio_album = -1;              /* OCTET_STRING_SIZE_30 */
static int hf_mpeg_audio_year = -1;               /* OCTET_STRING_SIZE_4 */
static int hf_mpeg_audio_comment = -1;            /* OCTET_STRING_SIZE_28 */
static int hf_mpeg_audio_must_be_zero = -1;       /* INTEGER_0_255 */
static int hf_mpeg_audio_track = -1;              /* INTEGER_0_255 */
static int hf_mpeg_audio_genre = -1;              /* T_genre */

/*--- End of included file: packet-mpeg-audio-hf.c ---*/
#line 39 "../../asn1/mpeg-audio/packet-mpeg-audio-template.c"

/*--- Included file: packet-mpeg-audio-ett.c ---*/
#line 1 "../../asn1/mpeg-audio/packet-mpeg-audio-ett.c"
static gint ett_mpeg_audio_Audio = -1;
static gint ett_mpeg_audio_ID3v1 = -1;

/*--- End of included file: packet-mpeg-audio-ett.c ---*/
#line 40 "../../asn1/mpeg-audio/packet-mpeg-audio-template.c"

/*--- Included file: packet-mpeg-audio-fn.c ---*/
#line 1 "../../asn1/mpeg-audio/packet-mpeg-audio-fn.c"


static int
dissect_mpeg_audio_BIT_STRING_SIZE_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     11, 11, FALSE, NULL);

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
                                     4, NULL, FALSE, 0, NULL);

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
                                     4, NULL, FALSE, 0, NULL);

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
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_mpeg_audio_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_mpeg_audio_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

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
                                     4, NULL, FALSE, 0, NULL);

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
                                     4, NULL, FALSE, 0, NULL);

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
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_mpeg_audio_OCTET_STRING_SIZE_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       30, 30, FALSE, NULL);

  return offset;
}



static int
dissect_mpeg_audio_OCTET_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_mpeg_audio_OCTET_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       28, 28, FALSE, NULL);

  return offset;
}



static int
dissect_mpeg_audio_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

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
  {  67, "psychadelic" },
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
                                                            0U, 255U, NULL, FALSE);

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


/*--- End of included file: packet-mpeg-audio-fn.c ---*/
#line 41 "../../asn1/mpeg-audio/packet-mpeg-audio-template.c"

static int proto_mpeg_audio = -1;

static int hf_mpeg_audio_data = -1;
static int hf_mpeg_audio_padbytes = -1;
static int hf_id3v1 = -1;
static int hf_id3v2 = -1;

static gboolean
dissect_mpeg_audio_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint32 h;
	struct mpa mpa;
	int data_size = 0;
	asn1_ctx_t asn1_ctx;
	int offset = 0;
	static const char *version_names[] = { "1", "2", "2.5" };

	if (!tvb_bytes_exist(tvb, 0, 4))
		return FALSE;	/* not enough data for an MPEG audio frame */

	h = tvb_get_ntohl(tvb, 0);
	MPA_UNMARSHAL(&mpa, h);
	if (!MPA_SYNC_VALID(&mpa))
		return FALSE;
	if (!MPA_VERSION_VALID(&mpa))
		return FALSE;
	if (!MPA_LAYER_VALID(&mpa))
		return FALSE;
		
	col_add_fstr(pinfo->cinfo, COL_PROTOCOL,
			"MPEG-%s", version_names[mpa_version(&mpa)]);
	col_add_fstr(pinfo->cinfo, COL_INFO,
				"Audio Layer %d", mpa_layer(&mpa) + 1);
	if (MPA_BITRATE_VALID(&mpa) && MPA_FREQUENCY_VALID(&mpa)) {
		data_size = (int)(MPA_DATA_BYTES(&mpa) - sizeof mpa);
		if (check_col(pinfo->cinfo, COL_DEF_SRC)) {
			SET_ADDRESS(&pinfo->src, AT_NONE, 0, NULL);
			col_add_fstr(pinfo->cinfo, COL_DEF_SRC,
					"%d kb/s", mpa_bitrate(&mpa) / 1000);
		}
		if (check_col(pinfo->cinfo, COL_DEF_DST)) {
			SET_ADDRESS(&pinfo->dst, AT_NONE, 0, NULL);
			col_add_fstr(pinfo->cinfo, COL_DEF_DST,
					"%g kHz", mpa_frequency(&mpa) / (float)1000);
		}
	}

	if (tree == NULL)
		return TRUE;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
	offset = dissect_mpeg_audio_Audio(tvb, offset, &asn1_ctx,
			tree, proto_mpeg_audio);
	if (data_size > 0) {
		unsigned int padding;

		proto_tree_add_item(tree, hf_mpeg_audio_data, tvb,
				offset / 8, data_size, FALSE);
		offset += data_size * 8;
		padding = mpa_padding(&mpa);
		if (padding > 0) {
			proto_tree_add_item(tree, hf_mpeg_audio_padbytes, tvb,
					offset / 8, padding, FALSE);
			offset += padding * 8;
		}
	}
	return TRUE;
}

static void
dissect_id3v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	asn1_ctx_t asn1_ctx;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ID3v1");
	col_clear(pinfo->cinfo, COL_INFO);
	if (tree == NULL)
		return;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
	dissect_mpeg_audio_ID3v1(tvb, 0, &asn1_ctx,
			tree, hf_id3v1);
}

static void
dissect_id3v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ID3v2");
	col_clear(pinfo->cinfo, COL_INFO);
	proto_tree_add_item(tree, hf_id3v2, tvb,
			0, -1, FALSE);
}

static gboolean
dissect_mpeg_audio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int magic;

	if (!tvb_bytes_exist(tvb, 0, 3))
		return FALSE;	/* not enough data for an ID tag or audio frame */
	magic = tvb_get_ntoh24(tvb, 0);
	switch (magic) {
		case 0x544147: /* TAG */
			dissect_id3v1(tvb, pinfo, tree);
			return TRUE;
		case 0x494433: /* ID3 */
			dissect_id3v2(tvb, pinfo, tree);
			return TRUE;
		default:
			return dissect_mpeg_audio_frame(tvb, pinfo, tree);
	}
}

void
proto_register_mpeg_audio(void)
{
	static hf_register_info hf[] = {

/*--- Included file: packet-mpeg-audio-hfarr.c ---*/
#line 1 "../../asn1/mpeg-audio/packet-mpeg-audio-hfarr.c"
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

/*--- End of included file: packet-mpeg-audio-hfarr.c ---*/
#line 159 "../../asn1/mpeg-audio/packet-mpeg-audio-template.c"
		{ &hf_mpeg_audio_data,
			{ "Data", "mpeg.audio.data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_audio_padbytes,
			{ "Padding", "mpeg.audio.padbytes",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_id3v1,
			{ "ID3v1", "id3v1",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_id3v2,
			{ "ID3v2", "id3v2",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	};

	static gint *ett[] = {

/*--- Included file: packet-mpeg-audio-ettarr.c ---*/
#line 1 "../../asn1/mpeg-audio/packet-mpeg-audio-ettarr.c"
    &ett_mpeg_audio_Audio,
    &ett_mpeg_audio_ID3v1,

/*--- End of included file: packet-mpeg-audio-ettarr.c ---*/
#line 176 "../../asn1/mpeg-audio/packet-mpeg-audio-template.c"
	};

	proto_mpeg_audio = proto_register_protocol(
			"Moving Picture Experts Group Audio", "MPEG Audio", "mpeg.audio");
	proto_register_field_array(proto_mpeg_audio, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mpeg_audio(void)
{
	heur_dissector_add("mpeg", dissect_mpeg_audio, proto_mpeg_audio);
}
