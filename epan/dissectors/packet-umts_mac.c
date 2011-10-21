/* Routines for UMTS FP disassembly
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

#include "packet-umts_fp.h"
#include "packet-umts_mac.h"

int proto_umts_mac = -1;
extern int proto_fp;

/* dissector fields */
static int hf_mac_fach_fdd_tctf = -1;
static int hf_mac_rach_fdd_tctf = -1;
static int hf_mac_ct = -1;
static int hf_mac_ueid_type = -1;
static int hf_mac_crnti = -1;
static int hf_mac_urnti = -1;
static int hf_mac_channel = -1;

/* subtrees */
static int ett_mac = -1;
static int ett_mac_fach = -1;
static int ett_mac_rach = -1;
static int ett_mac_dch = -1;
static int ett_mac_pch = -1;
static int ett_mac_edch = -1;
static int ett_mac_hsdsch = -1;

static dissector_handle_t rlc_pcch_handle;
static dissector_handle_t rlc_ccch_handle;
static dissector_handle_t rlc_ctch_handle;
static dissector_handle_t rlc_dcch_handle;
static dissector_handle_t rlc_ps_dtch_handle;

static const value_string rach_fdd_tctf_vals[] = {
	{ TCTF_CCCH_RACH_FDD, "CCCH over RACH (FDD)" },
	{ TCTF_DCCH_DTCH_RACH_FDD, "DCCH/DTCH over RACH (FDD)" },
	{ 0, NULL }
};

static const value_string fach_fdd_tctf_vals[] = {
	{ TCTF_BCCH_FACH_FDD, "BCCH over FACH (FDD)" },
	{ TCTF_DCCH_DTCH_FACH_FDD, "DCCH/DTCH over FACH (FDD)" },
	{ TCTF_MTCH_FACH_FDD, "MTCH over FACH (FDD)" },
	{ TCTF_CCCH_FACH_FDD, "CCCH over FACH (FDD)" },
	{ TCTF_MCCH_FACH_FDD, "MCCH over FACH (FDD)" },
	{ TCTF_MSCH_FACH_FDD, "MSCH over FACH (FDD)" },
	{ TCTF_CTCH_FACH_FDD, "CTCH over FACH (FDD)" },
	{ 0, NULL }
};

static const value_string ueid_type_vals[] = {
	{ MAC_UEID_TYPE_URNTI,	"U-RNTI" },
	{ MAC_UEID_TYPE_CRNTI,	"C-RNTI" },
	{ 0, NULL }
};

#define MAC_PCCH	0
#define MAC_CCCH	1
#define MAC_CTCH	2
#define MAC_DCCH	3
#define MAC_DTCH	4
#define MAC_BCCH	5
#define MAC_MCCH	6
#define MAC_MSCH	7
#define MAC_MTCH	8
static const value_string mac_logical_channel_vals[] = {
	{ MAC_PCCH,	"PCCH" },
	{ MAC_CCCH, "CCCH" },
	{ MAC_CTCH,	"CTCH" },
	{ MAC_DCCH,	"DCCH" },
	{ MAC_DTCH,	"DTCH" },
	{ MAC_BCCH, "BCCH" },
	{ MAC_MCCH,	"MCCH" },
	{ MAC_MSCH,	"MSCH" },
	{ MAC_MTCH,	"MTCH" },
	{ 0, NULL }
};


static guint8 fach_fdd_tctf(guint8 hdr, guint16 *bit_offs)
{
	guint8 tctf;
	/* first, test for valid 2-bit combinations */
	tctf = hdr >> 6;
	switch (tctf) {
		case TCTF_BCCH_FACH_FDD:
		case TCTF_DCCH_DTCH_FACH_FDD:
			*bit_offs = 2;
			return tctf;
	}
	/* 4-bit combinations */
	tctf = hdr >> 4;
	switch (tctf) {
		case TCTF_MTCH_FACH_FDD:
			*bit_offs = 4;
			return tctf;
	}
	/* just return the 8-bit combination */
	*bit_offs = 8;
	tctf = hdr;
	switch (tctf) {
		case TCTF_CCCH_FACH_FDD:
		case TCTF_MCCH_FACH_FDD:
		case TCTF_MSCH_FACH_FDD:
		case TCTF_CTCH_FACH_FDD:
			return tctf;
		default:
			return tctf; /* TODO */
	}
}

static guint16 tree_add_common_dcch_dtch_fields(tvbuff_t *tvb, packet_info *pinfo _U_,
	proto_tree *tree, guint16 bitoffs, fp_info *fpinf, umts_mac_info *macinf)
{
	guint8 ueid_type;

	ueid_type = tvb_get_bits8(tvb, bitoffs, 2);
	proto_tree_add_bits_item(tree, hf_mac_ueid_type, tvb, bitoffs, 2, ENC_BIG_ENDIAN);
	bitoffs += 2;
	if (ueid_type == MAC_UEID_TYPE_URNTI) {
		proto_tree_add_bits_item(tree, hf_mac_urnti, tvb, bitoffs, 32, ENC_BIG_ENDIAN);
		bitoffs += 32;
	} else if (ueid_type == MAC_UEID_TYPE_CRNTI) {
		proto_tree_add_bits_item(tree, hf_mac_crnti, tvb, 4, 16, ENC_BIG_ENDIAN);
		bitoffs += 16;
	}

	if (macinf->ctmux[fpinf->cur_tb]) {
		proto_tree_add_bits_item(tree, hf_mac_ct, tvb, bitoffs, 4, ENC_BIG_ENDIAN);
		bitoffs += 4;
	}
	return bitoffs;
}

static void dissect_mac_fdd_pch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *pch_tree = NULL;
	proto_item *channel_type;
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");
	col_set_str(pinfo->cinfo, COL_INFO, "PCCH");

	if (tree) {
		proto_item *ti;
		ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
		pch_tree = proto_item_add_subtree(ti, ett_mac_pch);
		proto_item_append_text(ti, " (PCCH)");
		channel_type = proto_tree_add_uint(pch_tree, hf_mac_channel, tvb, 0, 0, MAC_PCCH);
		PROTO_ITEM_SET_GENERATED(channel_type);
	}
	call_dissector(rlc_pcch_handle, tvb, pinfo, tree);
}

static void dissect_mac_fdd_rach(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 tctf;
	guint8 chan;
	guint16 bitoffs = 0;
	tvbuff_t *next_tvb;
	proto_tree *rach_tree = NULL;
	proto_item *channel_type;
	umts_mac_info *macinf;
	fp_info *fpinf;
	proto_item *ti = NULL;

	/* RACH TCTF is always 2 bit */
	tctf = tvb_get_bits8(tvb, 0, 2);
	bitoffs += 2;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

	col_add_str(pinfo->cinfo, COL_INFO,
		val_to_str(tctf, rach_fdd_tctf_vals, "Unknown TCTF"));

	ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
	rach_tree = proto_item_add_subtree(ti, ett_mac_rach);

	macinf = p_get_proto_data(pinfo->fd, proto_umts_mac);
	fpinf = p_get_proto_data(pinfo->fd, proto_fp);
	if (!macinf || !fpinf) {
		proto_tree_add_text(rach_tree, tvb, 0, -1,
			"Cannot dissect MAC frame because per-frame info is missing");
		return;
	}

	proto_tree_add_bits_item(rach_tree, hf_mac_rach_fdd_tctf, tvb, 0, 2, ENC_BIG_ENDIAN);
	if (tctf == TCTF_DCCH_DTCH_RACH_FDD) {
		macinf->ctmux[fpinf->cur_tb] = 1; /* DCCH/DTCH on RACH *always* has a C/T */
		bitoffs = tree_add_common_dcch_dtch_fields(tvb, pinfo, rach_tree, bitoffs, fpinf, macinf);
	}

	chan = fpinf->cur_chan;
	/* handoff to next dissector */
	switch (tctf) {
		case TCTF_CCCH_RACH_FDD:
			proto_item_append_text(ti, " (CCCH)");
			channel_type = proto_tree_add_uint(rach_tree, hf_mac_channel, tvb, 0, 0, MAC_CCCH);
			PROTO_ITEM_SET_GENERATED(channel_type);
			next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[chan] - bitoffs);
			add_new_data_source(pinfo, next_tvb, "Octet-Aligned CCCH Data");
			call_dissector(rlc_ccch_handle, next_tvb, pinfo, tree);
			break;
		case TCTF_DCCH_DTCH_RACH_FDD:
			switch (macinf->content[chan]) {
				case MAC_CONTENT_DCCH:
					proto_item_append_text(ti, " (DCCH)");
					channel_type = proto_tree_add_uint(rach_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);
					PROTO_ITEM_SET_GENERATED(channel_type);
					next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[chan] - bitoffs);
					add_new_data_source(pinfo, next_tvb, "Octet-Aligned DCCH Data");
					call_dissector(rlc_dcch_handle, next_tvb, pinfo, tree);
					break;
				case MAC_CONTENT_PS_DTCH:
					proto_item_append_text(ti, " (PS DTCH)");
					channel_type = proto_tree_add_uint(rach_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);
					PROTO_ITEM_SET_GENERATED(channel_type);
					next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[chan] - bitoffs);
					add_new_data_source(pinfo, next_tvb, "Octet-Aligned DTCH Data");
					call_dissector(rlc_ps_dtch_handle, next_tvb, pinfo, tree);
					break;
				case MAC_CONTENT_CS_DTCH:
					proto_item_append_text(ti, " (CS DTCH)");
					/* TODO */
					break;
				default:
					proto_item_append_text(ti, " (Unknown RACH DCCH/DTCH Content)");
			}
			break;
		default:
			proto_item_append_text(ti, " (Unknown RACH TCTF)");
	}
}

static void dissect_mac_fdd_fach(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 hdr, tctf;
	guint16 bitoffs = 0;
	guint16 tctf_len, chan;
	proto_tree *fach_tree = NULL;
	proto_item *channel_type;
	umts_mac_info *macinf;
	fp_info *fpinf;
	proto_item *ti = NULL;

	hdr = tvb_get_guint8(tvb, 0);

	/* get target channel type field */
	tctf = fach_fdd_tctf(hdr, &bitoffs);
	tctf_len = bitoffs;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

	col_add_str(pinfo->cinfo, COL_INFO,
		val_to_str(tctf, fach_fdd_tctf_vals, "Unknown TCTF"));

	ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
	fach_tree = proto_item_add_subtree(ti, ett_mac_fach);

	macinf = p_get_proto_data(pinfo->fd, proto_umts_mac);
	fpinf = p_get_proto_data(pinfo->fd, proto_fp);
	if (!macinf || !fpinf) {
		proto_tree_add_text(fach_tree, tvb, 0, -1,
			"Cannot dissect MAC frame because per-frame info is missing");
		return;
	}

	proto_tree_add_bits_item(fach_tree, hf_mac_fach_fdd_tctf, tvb, 0, tctf_len, ENC_BIG_ENDIAN);
	if (tctf == TCTF_DCCH_DTCH_FACH_FDD) {
		macinf->ctmux[fpinf->cur_tb] = 1; /* DCCH/DTCH on FACH *always* has a C/T */
		bitoffs = tree_add_common_dcch_dtch_fields(tvb, pinfo, fach_tree, bitoffs, fpinf, macinf);
	}

	chan = fpinf->cur_chan;
	switch (tctf) {
		tvbuff_t *next_tvb;
		case TCTF_CCCH_FACH_FDD:
			proto_item_append_text(ti, " (CCCH)");
			channel_type = proto_tree_add_uint(fach_tree, hf_mac_channel, tvb, 0, 0, MAC_CCCH);
			PROTO_ITEM_SET_GENERATED(channel_type);
			/* CCCH over FACH is always octet aligned */
			next_tvb = tvb_new_subset(tvb, 1, tvb_length_remaining(tvb, 1), -1);
			call_dissector(rlc_ccch_handle, next_tvb, pinfo, tree);
			break;
		case TCTF_DCCH_DTCH_FACH_FDD:
			switch (macinf->content[fpinf->cur_tb]) {
				case MAC_CONTENT_DCCH:
					proto_item_append_text(ti, " (DCCH)");
					channel_type = proto_tree_add_uint(fach_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);
					PROTO_ITEM_SET_GENERATED(channel_type);
					next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[chan] - bitoffs);
					add_new_data_source(pinfo, next_tvb, "Octet-Aligned DCCH Data");
					call_dissector(rlc_dcch_handle, next_tvb, pinfo, tree);
					break;
				case MAC_CONTENT_PS_DTCH:
					proto_item_append_text(ti, " (PS DTCH)");
					channel_type = proto_tree_add_uint(fach_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);
					PROTO_ITEM_SET_GENERATED(channel_type);
					next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[chan] - bitoffs);
					add_new_data_source(pinfo, next_tvb, "Octet-Aligned DCCH Data");
					call_dissector(rlc_ps_dtch_handle, next_tvb, pinfo, tree);
					break;
				case MAC_CONTENT_CS_DTCH:
					proto_item_append_text(ti, " (CS DTCH)");
					/* TODO */
					break;
				default:
					proto_item_append_text(ti, " (Unknown FACH Content");
			}
			break;
        case TCTF_CTCH_FACH_FDD:
            proto_item_append_text(ti, " (CTCH)");
            channel_type = proto_tree_add_uint(fach_tree, hf_mac_channel, tvb, 0, 0, MAC_CTCH);
            PROTO_ITEM_SET_GENERATED(channel_type);
            /* CTCH over FACH is always octet aligned */
            next_tvb = tvb_new_subset(tvb, 1, tvb_length_remaining(tvb, 1), -1);
            call_dissector(rlc_ctch_handle, next_tvb, pinfo, tree);
            break;
		default:
            proto_item_append_text(ti, " (Unknown FACH Content)");
	}
}

static void dissect_mac_fdd_dch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint16 pos;
	guint8 bitoffs = 0;
	umts_mac_info *macinf;
	fp_info *fpinf;
	proto_tree *dch_tree = NULL;
	proto_item *channel_type;
	tvbuff_t *next_tvb;
	proto_item *ti = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

	ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
	dch_tree = proto_item_add_subtree(ti, ett_mac_dch);

	macinf = p_get_proto_data(pinfo->fd, proto_umts_mac);
	fpinf = p_get_proto_data(pinfo->fd, proto_fp);
	if (!macinf || !fpinf) {
		proto_tree_add_text(dch_tree, tvb, 0, -1,
			"Cannot dissect MAC frame because per-frame info is missing");
		return;
	}
	pos = fpinf->cur_tb;
	if (macinf->ctmux[pos]) {
		proto_tree_add_bits_item(dch_tree, hf_mac_ct, tvb, 0, 4, ENC_BIG_ENDIAN);
		bitoffs = 4;
	}

	if (bitoffs) {
		next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[pos] - bitoffs);
		add_new_data_source(pinfo, next_tvb, "Octet-Aligned DCCH Data");
	} else
		next_tvb = tvb;
	switch (macinf->content[pos]) {
		case MAC_CONTENT_DCCH:
			proto_item_append_text(ti, " (DCCH)");
			channel_type = proto_tree_add_uint(dch_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);
			PROTO_ITEM_SET_GENERATED(channel_type);
			call_dissector(rlc_dcch_handle, next_tvb, pinfo, tree);
			break;
		case MAC_CONTENT_PS_DTCH:
			proto_item_append_text(ti, " (PS DTCH)");
			channel_type = proto_tree_add_uint(dch_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);
			PROTO_ITEM_SET_GENERATED(channel_type);
			call_dissector(rlc_ps_dtch_handle, next_tvb, pinfo, tree);
			break;
		case MAC_CONTENT_CS_DTCH:
			proto_item_append_text(ti, " (CS DTCH)");
			/* TODO */
			break;
		default:
			proto_item_append_text(ti, " (Unknown DCH Content)");
			;
	}
}

static void dissect_mac_fdd_edch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *edch_tree = NULL;
	proto_item *channel_type;
	umts_mac_info *macinf;
	fp_info *fpinf;
	guint16 pos;
	proto_item *ti = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

	ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
	edch_tree = proto_item_add_subtree(ti, ett_mac_edch);

	fpinf = p_get_proto_data(pinfo->fd, proto_fp);
	macinf = p_get_proto_data(pinfo->fd, proto_umts_mac);
	pos = fpinf->cur_tb;
	if (!macinf) {
		proto_tree_add_text(edch_tree, tvb, 0, -1,
			"Cannot dissect MAC frame because per-frame info is missing");
		return;
	}

	switch (macinf->content[pos]) {
		case MAC_CONTENT_DCCH:
			proto_item_append_text(ti, " (DCCH)");
			channel_type = proto_tree_add_uint(edch_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);
			PROTO_ITEM_SET_GENERATED(channel_type);
			call_dissector(rlc_dcch_handle, tvb, pinfo, tree);
			break;
		case MAC_CONTENT_PS_DTCH:
			proto_item_append_text(ti, " (PS DTCH)");
			channel_type = proto_tree_add_uint(edch_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);
			PROTO_ITEM_SET_GENERATED(channel_type);
			call_dissector(rlc_ps_dtch_handle, tvb, pinfo, tree);
			break;
		case MAC_CONTENT_CS_DTCH:
			proto_item_append_text(ti, " (CS DTCH)");
			/* TODO */
			break;
		default:
			proto_item_append_text(ti, " (Unknown EDCH Content)");
	}
}

/* to avoid unnecessary re-alignment, the 4 bit padding prepended to the HSDSCH in FP
 * are handled in the MAC layer
 * If the C/T field is present, 'bitoffs' will be 8 (4 bit padding and 4 bit C/T) and
 * no re-alignment is necessary
 * If no C/T is present, the whole payload will be left-shifted by 4 bit
 */
static void dissect_mac_fdd_hsdsch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *hsdsch_tree = NULL;
	proto_item *channel_type;
	fp_info *fpinf;
	umts_mac_info *macinf;
	guint16 pos;
	guint8 bitoffs;
	tvbuff_t *next_tvb;
	proto_item *ti = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

	ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
	hsdsch_tree = proto_item_add_subtree(ti, ett_mac_hsdsch);

	fpinf = p_get_proto_data(pinfo->fd, proto_fp);
	macinf = p_get_proto_data(pinfo->fd, proto_umts_mac);
	pos = fpinf->cur_tb;
	bitoffs = fpinf->hsdsch_entity == ehs ? 0 : 4;

	if (!macinf) {
		proto_tree_add_text(hsdsch_tree, tvb, 0, -1,
			"Cannot dissect MAC frame because per-frame info is missing");
		return;
	}
	if (macinf->ctmux[pos]) {
		proto_tree_add_bits_item(hsdsch_tree, hf_mac_ct, tvb, 0, 4, ENC_BIG_ENDIAN);
		bitoffs += 4;
	}

	if ((bitoffs % 8) == 0) {
		next_tvb = tvb_new_subset(tvb, bitoffs/8, -1, -1);
	} else {
		next_tvb = tvb_new_octet_aligned(tvb, bitoffs, -1);
		add_new_data_source(pinfo, next_tvb, "Octet-Aligned HSDSCH Data");
	}
	switch (macinf->content[pos]) {
		case MAC_CONTENT_DCCH:
			proto_item_append_text(ti, " (DCCH)");
			channel_type = proto_tree_add_uint(hsdsch_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);
			PROTO_ITEM_SET_GENERATED(channel_type);
			call_dissector(rlc_dcch_handle, next_tvb, pinfo, tree);
			break;
		case MAC_CONTENT_PS_DTCH:
			proto_item_append_text(ti, " (PS DTCH)");
			channel_type = proto_tree_add_uint(hsdsch_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);
			PROTO_ITEM_SET_GENERATED(channel_type);
			call_dissector(rlc_ps_dtch_handle, next_tvb, pinfo, tree);
			break;
		case MAC_CONTENT_CS_DTCH:
			proto_item_append_text(ti, " (CS DTCH)");
			break;
		default:
			proto_item_append_text(ti, " (Unknown HSDSCH Content)");
	}
}

void
proto_register_umts_mac(void)
{
	static gint *ett[] = {
		&ett_mac,
		&ett_mac_fach,
		&ett_mac_rach,
		&ett_mac_dch,
		&ett_mac_pch,
		&ett_mac_edch,
		&ett_mac_hsdsch,
	};
        /** XX: Looks like some duplicate filter names ?? **/
	static hf_register_info hf[] = {
		{ &hf_mac_rach_fdd_tctf, { "Target Channel Type Field", "mac.tctf", FT_UINT8, BASE_HEX, VALS(rach_fdd_tctf_vals), 0, NULL, HFILL } },
		{ &hf_mac_fach_fdd_tctf, { "Target Channel Type Field", "mac.tctf", FT_UINT8, BASE_HEX, VALS(fach_fdd_tctf_vals), 0, NULL, HFILL } },
		{ &hf_mac_ct, { "C/T", "mac.ct", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_mac_ueid_type, { "UEID Type", "mac.ueid_type", FT_UINT8, BASE_DEC, VALS(ueid_type_vals), 0, NULL, HFILL } },
		{ &hf_mac_crnti, { "C-RNTI (UEID)", "mac.ueid", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_mac_urnti, { "U-RNTI (UEID)", "mac.ueid", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_mac_channel, { "Logical Channel", "mac.logical_channel", FT_UINT16, BASE_DEC, VALS(mac_logical_channel_vals), 0, NULL, HFILL } },
	};

	proto_umts_mac = proto_register_protocol("MAC", "MAC", "mac");
	proto_register_field_array(proto_umts_mac, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("mac.fdd.rach", dissect_mac_fdd_rach, proto_umts_mac);
	register_dissector("mac.fdd.fach", dissect_mac_fdd_fach, proto_umts_mac);
	register_dissector("mac.fdd.pch", dissect_mac_fdd_pch, proto_umts_mac);
	register_dissector("mac.fdd.dch", dissect_mac_fdd_dch, proto_umts_mac);
	register_dissector("mac.fdd.edch", dissect_mac_fdd_edch, proto_umts_mac);
	register_dissector("mac.fdd.hsdsch", dissect_mac_fdd_hsdsch, proto_umts_mac);
}

void
proto_reg_handoff_umts_mac(void)
{
	rlc_pcch_handle = find_dissector("rlc.pcch");
	rlc_ccch_handle = find_dissector("rlc.ccch");
	rlc_ctch_handle = find_dissector("rlc.ctch");
	rlc_dcch_handle = find_dissector("rlc.dcch");
	rlc_ps_dtch_handle = find_dissector("rlc.ps_dtch");
}

