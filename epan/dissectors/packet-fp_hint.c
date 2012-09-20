/* Routines for UMTS FP Hint protocol disassembly
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include "packet-umts_fp.h"
#include "packet-umts_mac.h"
#include "packet-rlc.h"

static int proto_fp_hint = -1;
extern int proto_fp;
extern int proto_umts_mac;
extern int proto_rlc;

static int ett_fph = -1;
static int ett_fph_rb = -1;
static int ett_fph_ddi_entry = -1;
static int ett_fph_tf = -1;

static int hf_fph_frametype = -1;
static int hf_fph_channeltype = -1;
static int hf_fph_chcnt = -1;
static int hf_fph_dchid = -1;
static int hf_fph_urnti = -1;
static int hf_fph_rlcmode = -1;
static int hf_fph_content = -1;
static int hf_fph_rbid = -1;
static int hf_fph_ctmux = -1;
static int hf_fph_ciphered = -1;
static int hf_fph_deciphered = -1;
static int hf_fph_macdflowid = -1;
static int hf_fph_macehs = -1;
static int hf_fph_rb = -1;
static int hf_fph_ddi_entry = -1;
static int hf_fph_ddi_size = -1;
static int hf_fph_ddi_logical = -1;
static int hf_fph_ddi_value = -1;
static int hf_fph_tf = -1;
static int hf_fph_tf_n = -1;
static int hf_fph_tf_size = -1;

static dissector_handle_t data_handle;
static dissector_handle_t ethwithfcs_handle;
static dissector_handle_t atm_untrunc_handle;

enum fph_ctype {
	FPH_CHANNEL_PCH,
	FPH_CHANNEL_RACH,
	FPH_CHANNEL_FACH,
	FPH_CHANNEL_DCH,
	FPH_CHANNEL_HSDSCH,
	FPH_CHANNEL_EDCH
};

enum fph_frame {
	FPH_FRAME_ATM_AAL2,
	FPH_FRAME_ETHERNET
};

enum fph_pich {
	FPH_PICH18,
	FPH_PICH36,
	FPH_PICH72,
	FPH_PICH144
};

enum fph_content {
	FPH_CONTENT_UNKNOWN,
	FPH_CONTENT_DCCH,
	FPH_CONTENT_PS_DTCH,
	FPH_CONTENT_CS_DTCH
};

static const value_string fph_frametype_vals[] = {
	{ FPH_FRAME_ATM_AAL2,	"ATM AAL2" },
	{ FPH_FRAME_ETHERNET,	"Ethernet" },
	{ 0, NULL }
};

static const value_string fph_channeltype_vals[] = {
	{ FPH_CHANNEL_PCH,		"PCH" },
	{ FPH_CHANNEL_RACH,		"RACH" },
	{ FPH_CHANNEL_FACH,		"FACH" },
	{ FPH_CHANNEL_DCH,		"DCH" },
	{ FPH_CHANNEL_HSDSCH,	"HSDSCH" },
	{ FPH_CHANNEL_EDCH,		"E-DCH" },
	{ 0, NULL }
};

static const value_string fph_rlcmode_vals[] = {
	{ RLC_TM,			"Transparent Mode" },
	{ RLC_UM,			"Unacknowledged Mode" },
	{ RLC_AM,			"Acknowledged Mode" },
	{ 0, NULL }
};

static const value_string fph_content_vals[] = {
	{ FPH_CONTENT_UNKNOWN,	"Unknown" },
	{ FPH_CONTENT_DCCH,		"DCCH" },
	{ FPH_CONTENT_PS_DTCH,	"PS DTCH" },
	{ FPH_CONTENT_CS_DTCH,	"PS DTCH" },
	{ 0, NULL }
};

static const true_false_string fph_ctmux_vals = {
	"C/T Mux field present", "C/T Mux field not present"
};

static const true_false_string fph_ciphered_vals = {
	"Ciphered", "Not ciphered"
};

static const true_false_string fph_deciphered_vals = {
	"Deciphered", "Not deciphered"
};

static guint16 assign_rb_info(tvbuff_t *tvb, packet_info *pinfo, guint16 offset, guint8 rbcnt, proto_tree *tree)
{
	guint8 i = 0, next_byte;
	guint8 rlc_mode, content, rb_id, ctmux, ciphered, deciphered;
	guint32 urnti;
	struct umts_mac_info *macinf;
	struct rlc_info *rlcinf;

	macinf = p_get_proto_data(pinfo->fd, proto_umts_mac);
	rlcinf = p_get_proto_data(pinfo->fd, proto_rlc);
	if (!macinf) {
		macinf = se_alloc0(sizeof(struct umts_mac_info));
		p_add_proto_data(pinfo->fd, proto_umts_mac, macinf);
	}
	if (!rlcinf) {
		rlcinf = se_alloc0(sizeof(struct rlc_info));
		p_add_proto_data(pinfo->fd, proto_rlc, rlcinf);
	}

	while (i < rbcnt) {
		urnti = tvb_get_letohl(tvb, offset);
		next_byte = tvb_get_guint8(tvb, offset + 4);
		rlc_mode = next_byte & 0x3;
		content = (next_byte >> 2) & 0x3;
		rb_id = next_byte >> 4;
		next_byte = tvb_get_guint8(tvb, offset + 5);
		rb_id |= (next_byte & 0x01) << 4;
		ctmux = (next_byte >> 1) & 0x1;
		ciphered = (next_byte >> 2) & 0x1;
		deciphered = (next_byte >> 3) & 0x1;

		if (i >= MAX_RLC_CHANS) {
			proto_tree_add_text(tree, tvb, offset, -1,
				"Frame contains more Radio Bearers than currently supported (%u present, %u supported)",
				rbcnt, MAX_RLC_CHANS);
			return -1;
		}
		if (i >= MAX_MAC_FRAMES) {
			proto_tree_add_text(tree, tvb, offset, -1,
				"Frame contains more MAC Frames than currently supported (%u present, %u supported)",
				rbcnt, MAX_MAC_FRAMES);
			return -1;
		}

		rlcinf->mode[i] = rlc_mode;
		rlcinf->rbid[i] = rb_id;
		rlcinf->urnti[i] = urnti;
		rlcinf->ciphered[i] = ciphered;
		rlcinf->deciphered[i] = deciphered;
		rlcinf->li_size[i] = RLC_LI_VARIABLE;

		macinf->ctmux[i] = ctmux ? TRUE : FALSE;
		switch (content) {
			case FPH_CONTENT_DCCH:
				macinf->content[i] = MAC_CONTENT_DCCH;
				break;
			case FPH_CONTENT_PS_DTCH:
				macinf->content[i] = MAC_CONTENT_PS_DTCH;
				break;
			case FPH_CONTENT_CS_DTCH:
				macinf->content[i] = MAC_CONTENT_CS_DTCH;
				break;
			default:
				macinf->content[i] = MAC_CONTENT_UNKNOWN;
		}

		if (tree) {
			proto_tree *subtree;
			proto_item *pi;

			pi = proto_tree_add_item(tree, hf_fph_rb, tvb, offset, 8, ENC_NA);
			subtree = proto_item_add_subtree(pi, ett_fph_rb);

			if (urnti)
				proto_tree_add_uint(subtree, hf_fph_urnti, tvb, offset, 4, urnti);
			proto_tree_add_bits_item(subtree, hf_fph_content, tvb, (offset+4)*8+4, 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_bits_item(subtree, hf_fph_rlcmode, tvb, (offset+4)*8+6, 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_item(subtree, hf_fph_rbid, tvb, (offset+4), 2, ENC_LITTLE_ENDIAN);
			proto_tree_add_boolean(subtree, hf_fph_ctmux, tvb, offset+5, 1, ctmux);
			proto_tree_add_boolean(subtree, hf_fph_ciphered, tvb, offset+5, 1, ciphered);
			proto_tree_add_boolean(subtree, hf_fph_deciphered, tvb, offset+5, 1, deciphered);
		}
		offset += 8;
		i++;
	}
	return offset;
}

static void assign_fph_pch(tvbuff_t *tvb, packet_info *pinfo _U_, guint16 offset, fp_info *fpi, proto_tree *tree _U_)
{
	guint8 pich;
	guint16 blkcnt, blksz;
	const guint8 *hdr;

	fpi->channel = CHANNEL_PCH;

	hdr = tvb_get_ptr(tvb, offset, 4);
	blkcnt = hdr[0] | ((hdr[1] & 0x01) << 8);
	blksz = (hdr[1] >> 1) | ((hdr[2] & 0x3f) << 7);
	pich = (hdr[2] >> 6) | ((hdr[3] & 0x01) << 2);

	switch (pich) {
		case FPH_PICH18:
			fpi->paging_indications = 18;
			break;
		case FPH_PICH36:
			fpi->paging_indications = 36;
			break;
		case FPH_PICH72:
			fpi->paging_indications = 72;
			break;
		case FPH_PICH144:
			fpi->paging_indications = 144;
			break;
		default:
			fpi->paging_indications = 0;
	}
	fpi->num_chans = 1;
	fpi->chan_tf_size[0] = blksz;
	fpi->chan_num_tbs[0] = blkcnt;
}

static void assign_fph_rach(tvbuff_t *tvb, packet_info *pinfo _U_, guint16 offset, fp_info *fpi, proto_tree *tree)
{
	const guint8 *hdr;
	guint8 rbcnt;
	guint16 blkcnt, blksz;

	fpi->channel = CHANNEL_RACH_FDD;

	hdr = tvb_get_ptr(tvb, offset, 4);
	blkcnt = hdr[0] | ((hdr[1] & 0x01) << 8);
	blksz = (hdr[1] >> 1) | ((hdr[2] & 0x3f) << 7);

	fpi->num_chans = 1;
	fpi->chan_tf_size[0] = blksz;
	fpi->chan_num_tbs[0] = blkcnt;

	offset += 4;
	rbcnt = tvb_get_guint8(tvb, offset); offset++;
	if (rbcnt > 0)
		offset = assign_rb_info(tvb, pinfo, offset, rbcnt, tree);
}

static void assign_fph_dch(tvbuff_t *tvb, packet_info *pinfo, guint16 offset, fp_info *fpi, proto_tree *tree)
{
	guint8 dch_id, rbcnt;
	guint16 N, size;
	guint32 cnt, i = 0;
	const guint8 *hdr;
	proto_tree *subtree;
	proto_item *pi;

	fpi->channel = CHANNEL_DCH;
	cnt = tvb_get_guint8(tvb, offset); offset++;

	if (tree)
		proto_tree_add_uint(tree, hf_fph_chcnt, tvb, offset-1, 1, cnt);

	fpi->num_chans = cnt;
	fpi->dch_crc_present = 1;
	while (i < cnt) {
		pi = proto_tree_add_item(tree, hf_fph_tf, tvb, offset, 4, ENC_NA);
		subtree = proto_item_add_subtree(pi, ett_fph_rb);
		hdr = tvb_get_ptr(tvb, offset, 4);
		dch_id = (hdr[0] & 0x1f) + 1;

		N = ((hdr[1] & 0x3f)<<3) | (hdr[0] >> 5);
		size = ((hdr[3] & 0x07)<<10) | (hdr[2] << 2) | ((hdr[1] & 0xc0)>>6);
		size = size == 0x1fff ? 0 : size;

		fpi->chan_tf_size[i] = size;
		fpi->chan_num_tbs[i] = N;

		if (subtree) {
			proto_tree_add_uint(subtree, hf_fph_dchid, tvb, offset, 1, dch_id);
			proto_tree_add_uint(subtree, hf_fph_tf_n, tvb, offset, 2, N);
			if (size)
				proto_tree_add_uint(subtree, hf_fph_tf_size, tvb, offset + 1, 3, size);
		}
		offset += 4;
		if (i > MAX_FP_CHANS) {
			proto_tree_add_text(tree, tvb, offset, -1,
				"Frame contains more FP channels than currently supported (%u supported)",
				MAX_FP_CHANS);
			return;
		}
		i++;
	}
	rbcnt = tvb_get_guint8(tvb, offset); offset++;
	if (rbcnt > 0)
		offset = assign_rb_info(tvb, pinfo, offset, rbcnt, tree);
}

static void assign_fph_fach(tvbuff_t *tvb, packet_info *pinfo, guint16 offset, fp_info *fpi, proto_tree *tree)
{
	const guint8 *hdr;
	guint8 rbcnt;
	guint16 blkcnt, blksz;

	fpi->channel = CHANNEL_FACH_FDD;

	hdr = tvb_get_ptr(tvb, offset, 4);
	blkcnt = hdr[0] | ((hdr[1] & 0x01) << 8);
	blksz = (hdr[1] >> 1) | ((hdr[2] & 0x3f) << 7);

	fpi->num_chans = 1;
	fpi->chan_tf_size[0] = blksz;
	fpi->chan_num_tbs[0] = blkcnt;

	offset += 4;
	rbcnt = tvb_get_guint8(tvb, offset); offset++;
	if (rbcnt > 0)
		offset = assign_rb_info(tvb, pinfo, offset, rbcnt, tree);
}

static void assign_fph_hsdsch(tvbuff_t *tvb, packet_info *pinfo, guint16 offset, fp_info *fpi, proto_tree *tree)
{
	guint8 rbcnt, hsdsch_info;

	hsdsch_info = tvb_get_guint8(tvb, offset);
	fpi->hsdsch_entity = hsdsch_info & 0x08 ? ehs : hs;
	fpi->channel = CHANNEL_HSDSCH;

	if (tree) {
		proto_tree_add_bits_item(tree, hf_fph_macehs, tvb,
			offset*8+4, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_bits_item(tree, hf_fph_macdflowid, tvb,
			offset*8+5, 3, ENC_LITTLE_ENDIAN);
	}

	offset++;
	rbcnt = tvb_get_guint8(tvb, offset); offset++;
	if (rbcnt > 0)
		offset = assign_rb_info(tvb, pinfo, offset, rbcnt, tree);
}

static void assign_fph_edch(tvbuff_t *tvb, packet_info *pinfo, guint16 offset, fp_info *fpi, proto_tree *tree)
{
	guint8 rbcnt, macdflow_id, maces_cnt, i = 0;
	guint8 logical, ddi;
	guint16 maces_size;
	proto_item *pi;
	proto_tree *subtree = NULL;

	fpi->channel = CHANNEL_EDCH;
	macdflow_id = tvb_get_guint8(tvb, offset);

	if (tree) {
		proto_tree_add_uint(tree, hf_fph_macdflowid, tvb, offset, 1, macdflow_id);
	}

	offset++;
	maces_cnt = tvb_get_guint8(tvb, offset); offset++;

	fpi->no_ddi_entries = maces_cnt;
	while (i < maces_cnt) {
		ddi = tvb_get_guint8(tvb, offset++);
		logical = tvb_get_guint8(tvb, offset++);
		maces_size = tvb_get_letohs(tvb, offset);
		offset += 2;
		fpi->edch_ddi[i] = ddi;
		fpi->edch_macd_pdu_size[i] = maces_size;
		if (tree) {
			pi = proto_tree_add_item(tree, hf_fph_ddi_entry, tvb, offset - 4, 4, ENC_NA);
			subtree = proto_item_add_subtree(pi, ett_fph_ddi_entry);
			proto_tree_add_uint(subtree, hf_fph_ddi_value, tvb, offset - 4, 1, ddi);
			proto_tree_add_uint(subtree, hf_fph_ddi_logical, tvb, offset - 3, 1, logical);
			proto_tree_add_uint(subtree, hf_fph_ddi_size, tvb, offset - 2, 2, maces_size);
		}
		i++;
		if (i >= MAX_EDCH_DDIS) {
			proto_tree_add_text(tree, tvb, offset, -1,
				"Frame contains more FP channels than currently supported (%u supported)",
				MAX_FP_CHANS);
			return;
		}
	}


	rbcnt = tvb_get_guint8(tvb, offset); offset++;
	if (rbcnt > 0)
		offset = assign_rb_info(tvb, pinfo, offset, rbcnt, tree);
}

static void attach_info(tvbuff_t *tvb, packet_info *pinfo, guint16 offset, guint8 channel_type, guint8 frame_type, proto_tree *tree)
{
	fp_info *fpi;

	fpi = p_get_proto_data(pinfo->fd, proto_fp);
	if (!fpi) {
		fpi = se_alloc0(sizeof(fp_info));
		p_add_proto_data(pinfo->fd, proto_fp, fpi);
	}

	fpi->is_uplink = pinfo->p2p_dir == P2P_DIR_RECV;
	/* TODO make this configurable */
	fpi->release = 7;
	fpi->release_year = 2008;
	fpi->release_month = 9;
	fpi->dch_crc_present = 1;

	switch (frame_type) {
		case FPH_FRAME_ATM_AAL2:
			fpi->link_type = FP_Link_ATM;
			break;
		case FPH_FRAME_ETHERNET:
			fpi->link_type = FP_Link_Ethernet;
			break;
		default:
			fpi->link_type = FP_Link_Unknown;
	}

	/* at the moment, only IuB is supported */
	fpi->iface_type = IuB_Interface;
	/* at the moment, only FDD is supported */
	fpi->division = Division_FDD;

	switch (channel_type) {
		case FPH_CHANNEL_PCH:
			assign_fph_pch(tvb, pinfo, offset, fpi, tree);
			break;
		case FPH_CHANNEL_RACH:
			assign_fph_rach(tvb, pinfo, offset, fpi, tree);
			break;
		case FPH_CHANNEL_FACH:
			assign_fph_fach(tvb, pinfo, offset, fpi, tree);
			break;
		case FPH_CHANNEL_DCH:
			assign_fph_dch(tvb, pinfo, offset, fpi, tree);
			break;
		case FPH_CHANNEL_HSDSCH:
			assign_fph_hsdsch(tvb, pinfo, offset, fpi, tree);
			break;
		case FPH_CHANNEL_EDCH:
			assign_fph_edch(tvb, pinfo, offset, fpi, tree);
			break;
		default:
			fpi->channel = 0;
	}
}

static void dissect_fp_hint(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 frame_type, channel_type;
	guint16 hdrlen;
	guint32 atm_hdr, aal2_ext;
	tvbuff_t *next_tvb;
	dissector_handle_t *next_dissector;
	proto_item *ti;
	proto_tree *fph_tree = NULL;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "FP Hint");

	hdrlen = tvb_get_letohs(tvb, 0);
	frame_type = tvb_get_guint8(tvb, 2);
	channel_type = tvb_get_guint8(tvb, 3);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_fp_hint, tvb, 0, hdrlen, ENC_NA);
		fph_tree = proto_item_add_subtree(ti, ett_fph);
		proto_tree_add_uint(fph_tree, hf_fph_frametype, tvb, 2, 1, frame_type);
		proto_tree_add_uint(fph_tree, hf_fph_channeltype, tvb, 3, 1, channel_type);
	}

	/* attach FP, MAC, RLC information */
	attach_info(tvb, pinfo, 4, channel_type, frame_type, fph_tree);
	switch (frame_type) {
		case FPH_FRAME_ATM_AAL2:
			aal2_ext = tvb_get_ntohl(tvb, hdrlen); hdrlen += 4;
			atm_hdr = tvb_get_ntohl(tvb, hdrlen); hdrlen += 4;
			memset(&pinfo->pseudo_header->atm, 0, sizeof(pinfo->pseudo_header->atm));
			pinfo->pseudo_header->atm.aal = AAL_2;
			/* pinfo->pseudo_header->atm.flags = pinfo->p2p_dir; */
			pinfo->pseudo_header->atm.flags = ATM_AAL2_NOPHDR;
			pinfo->pseudo_header->atm.vpi = ((atm_hdr & 0x0ff00000) >> 20);
			pinfo->pseudo_header->atm.vci = ((atm_hdr & 0x000ffff0) >>  4);
			pinfo->pseudo_header->atm.aal2_cid = aal2_ext & 0x000000ff;
			pinfo->pseudo_header->atm.type = TRAF_UMTS_FP;
			next_dissector = &atm_untrunc_handle;
			break;
		case FPH_FRAME_ETHERNET:
			next_dissector = &ethwithfcs_handle;
			break;
		default:
			next_dissector = &data_handle;
	}

	next_tvb = tvb_new_subset(tvb, hdrlen, -1, -1);
	call_dissector(*next_dissector, next_tvb, pinfo, tree);
}

void
proto_register_fp_hint(void)
{
	static hf_register_info hf[] = {
		{ &hf_fph_frametype, { "Frame Type", "fp_hint.frame_type", FT_UINT8, BASE_HEX, VALS(fph_frametype_vals), 0x0, NULL, HFILL } },
		{ &hf_fph_channeltype, { "Channel Type", "fp_hint.channel_type", FT_UINT8, BASE_HEX, VALS(fph_channeltype_vals), 0x0, NULL, HFILL } },
		{ &hf_fph_chcnt, { "Number of Channels", "fp_hint.num_chan", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_fph_dchid, { "DCH ID", "fp_hint.dchid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_fph_macdflowid, { "MACd Flow ID", "fp_hint.macdflowid", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_fph_macehs, { "MAC-ehs indicator", "fp_hint.mac_ehs", FT_BOOLEAN, BASE_NONE, NULL, 0, NULL, HFILL } },
		/* traffic format details */
		{ &hf_fph_tf, { "Traffic Format", "fp_hint.tf", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_fph_tf_n, { "N", "fp_hint.tf.n", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_fph_tf_size, { "Size", "fp_hint.tf.size", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
		/* DDI information for E-DCH */
		{ &hf_fph_ddi_entry, { "DDI Entry", "fp_hint.ddi", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_fph_ddi_value, { "DDI", "fp_hint.ddi.value", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_fph_ddi_logical, { "Logical Channel ID", "fp_hint.ddi.logical", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_fph_ddi_size, { "Size", "fp_hint.ddi.size", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		/* radio bearer details */
		{ &hf_fph_rb, { "Radio Bearer", "fp_hint.rb", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_fph_urnti, { "U-RNTI", "fp_hint.rb.urnti", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
		{ &hf_fph_content, { "Content", "fp_hint.rb.content", FT_UINT8, BASE_DEC, VALS(fph_content_vals), 0, NULL, HFILL } },
		{ &hf_fph_rlcmode, { "RLC Mode", "fp_hint.rb.rlc_mode", FT_UINT8, BASE_DEC, VALS(fph_rlcmode_vals), 0, NULL, HFILL } },
		{ &hf_fph_rbid, { "Radio Bearer ID", "fp_hint.rb.rbid", FT_UINT16, BASE_DEC, NULL, 0x01f0, NULL, HFILL } },
		{ &hf_fph_ctmux, { "C/T Mux", "fp_hint.rb.ctmux", FT_BOOLEAN, BASE_NONE, TFS(&fph_ctmux_vals), 0, "C/T Mux field", HFILL } },
		{ &hf_fph_ciphered, { "Ciphered", "fp_hint.rb.ciphered", FT_BOOLEAN, BASE_NONE, TFS(&fph_ciphered_vals), 0, "Ciphered flag", HFILL } },
		{ &hf_fph_deciphered, { "Deciphered", "fp_hint.rb.deciphered", FT_BOOLEAN, BASE_NONE, TFS(&fph_deciphered_vals), 0, "Deciphered flag", HFILL } }
	};

	static gint *ett[] = {
		&ett_fph,
		&ett_fph_rb,
		&ett_fph_ddi_entry,
		&ett_fph_tf
	};

	proto_fp_hint = proto_register_protocol("FP Hint", "FP Hint", "fp_hint");
	register_dissector("fp_hint", dissect_fp_hint, proto_fp_hint);

	proto_register_field_array(proto_fp_hint, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_fp_hint(void)
{
	atm_untrunc_handle = find_dissector("atm_untruncated");
	data_handle = find_dissector("data");
	ethwithfcs_handle = find_dissector("eth_withfcs");
}
