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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/asn1.h>

#include <wsutil/mpeg-audio.h>

#include "packet-per.h"

#include "packet-mpeg-audio-hf.c"
#include "packet-mpeg-audio-ett.c"
#include "packet-mpeg-audio-fn.c"

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
				offset / 8, data_size, ENC_NA);
		offset += data_size * 8;
		padding = mpa_padding(&mpa);
		if (padding > 0) {
			proto_tree_add_item(tree, hf_mpeg_audio_padbytes, tvb,
					offset / 8, padding, ENC_NA);
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
			0, -1, ENC_NA);
}

static gboolean
dissect_mpeg_audio(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
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
#include "packet-mpeg-audio-hfarr.c"
		{ &hf_mpeg_audio_data,
			{ "Data", "mpeg-audio.data",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_mpeg_audio_padbytes,
			{ "Padding", "mpeg-audio.padbytes",
				FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

		{ &hf_id3v1,
			{ "ID3v1", "id3v1",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
		{ &hf_id3v2,
			{ "ID3v2", "id3v2",
				FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL }},
	};

	static gint *ett[] = {
#include "packet-mpeg-audio-ettarr.c"
	};

	proto_mpeg_audio = proto_register_protocol(
			"Moving Picture Experts Group Audio", "MPEG Audio", "mpeg-audio");
	proto_register_field_array(proto_mpeg_audio, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mpeg_audio(void)
{
	heur_dissector_add("mpeg", dissect_mpeg_audio, proto_mpeg_audio);
}
