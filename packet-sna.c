/* packet-sna.c
 * Routines for SNA
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * $Id: packet-sna.c,v 1.35 2001/12/03 03:59:39 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include "packet.h"
#include "llcsaps.h"
#include "sna-utils.h"

/*
 * http://www.wanresources.com/snacell.html
 *
 */

static int proto_sna = -1;
static int hf_sna_th = -1;
static int hf_sna_th_0 = -1;
static int hf_sna_th_fid = -1;
static int hf_sna_th_mpf = -1;
static int hf_sna_th_odai = -1;
static int hf_sna_th_efi = -1;
static int hf_sna_th_daf = -1;
static int hf_sna_th_oaf = -1;
static int hf_sna_th_snf = -1;
static int hf_sna_th_dcf = -1;
static int hf_sna_th_lsid = -1;
static int hf_sna_th_tg_sweep = -1;
static int hf_sna_th_er_vr_supp_ind = -1;
static int hf_sna_th_vr_pac_cnt_ind = -1;
static int hf_sna_th_ntwk_prty = -1;
static int hf_sna_th_tgsf = -1;
static int hf_sna_th_mft = -1;
static int hf_sna_th_piubf = -1;
static int hf_sna_th_iern = -1;
static int hf_sna_th_nlpoi = -1;
static int hf_sna_th_nlp_cp = -1;
static int hf_sna_th_ern = -1;
static int hf_sna_th_vrn = -1;
static int hf_sna_th_tpf = -1;
static int hf_sna_th_vr_cwi = -1;
static int hf_sna_th_tg_nonfifo_ind = -1;
static int hf_sna_th_vr_sqti = -1;
static int hf_sna_th_tg_snf = -1;
static int hf_sna_th_vrprq = -1;
static int hf_sna_th_vrprs = -1;
static int hf_sna_th_vr_cwri = -1;
static int hf_sna_th_vr_rwi = -1;
static int hf_sna_th_vr_snf_send = -1;
static int hf_sna_th_dsaf = -1;
static int hf_sna_th_osaf = -1;
static int hf_sna_th_snai = -1;
static int hf_sna_th_def = -1;
static int hf_sna_th_oef = -1;
static int hf_sna_th_sa = -1;
static int hf_sna_th_cmd_fmt = -1;
static int hf_sna_th_cmd_type = -1;
static int hf_sna_th_cmd_sn = -1;

static int hf_sna_rh = -1;
static int hf_sna_rh_0 = -1;
static int hf_sna_rh_1 = -1;
static int hf_sna_rh_2 = -1;
static int hf_sna_rh_rri = -1;
static int hf_sna_rh_ru_category = -1;
static int hf_sna_rh_fi = -1;
static int hf_sna_rh_sdi = -1;
static int hf_sna_rh_bci = -1;
static int hf_sna_rh_eci = -1;
static int hf_sna_rh_dr1 = -1;
static int hf_sna_rh_lcci = -1;
static int hf_sna_rh_dr2 = -1;
static int hf_sna_rh_eri = -1;
static int hf_sna_rh_rti = -1;
static int hf_sna_rh_rlwi = -1;
static int hf_sna_rh_qri = -1;
static int hf_sna_rh_pi = -1;
static int hf_sna_rh_bbi = -1;
static int hf_sna_rh_ebi = -1;
static int hf_sna_rh_cdi = -1;
static int hf_sna_rh_csi = -1;
static int hf_sna_rh_edi = -1;
static int hf_sna_rh_pdi = -1;
static int hf_sna_rh_cebi = -1;
/*static int hf_sna_ru = -1;*/

static gint ett_sna = -1;
static gint ett_sna_th = -1;
static gint ett_sna_th_fid = -1;
static gint ett_sna_rh = -1;
static gint ett_sna_rh_0 = -1;
static gint ett_sna_rh_1 = -1;
static gint ett_sna_rh_2 = -1;

static dissector_handle_t data_handle;

/* Format Identifier */
static const value_string sna_th_fid_vals[] = {
	{ 0x0,	"SNA device <--> Non-SNA Device" },
	{ 0x1,	"Subarea Nodes, without ER or VR" },
	{ 0x2,	"Subarea Node <--> PU2" },
	{ 0x3,	"Subarea Node or SNA host <--> Subarea Node" },
	{ 0x4,	"Subarea Nodes, supporting ER and VR" },
	{ 0x5,	"HPR RTP endpoint nodes" },
	{ 0xf,	"Adjaced Subarea Nodes, supporting ER and VR" },
	{ 0x0,	NULL }
};

/* Mapping Field */
static const value_string sna_th_mpf_vals[] = {
	{ 0, "Middle segment of a BIU" },
	{ 1, "Last segment of a BIU" },
	{ 2, "First segment of a BIU" },
	{ 3 , "Whole BIU" },
	{ 0,   NULL }
};

/* Expedited Flow Indicator */
static const value_string sna_th_efi_vals[] = {
	{ 0, "Normal Flow" },
	{ 1, "Expedited Flow" },
	{ 0x0,	NULL }
};

/* Request/Response Indicator */
static const value_string sna_rh_rri_vals[] = {
	{ 0, "Request" },
	{ 1, "Response" },
	{ 0x0,	NULL }
};

/* Request/Response Unit Category */
static const value_string sna_rh_ru_category_vals[] = {
	{ 0, "Function Management Data (FMD)" },
	{ 1, "Network Control (NC)" },
	{ 2, "Data Flow Control (DFC)" },
	{ 3, "Session Control (SC)" },
	{ 0x0,	NULL }
};

/* Format Indicator */
static const true_false_string sna_rh_fi_truth =
	{ "FM Header", "No FM Header" };

/* Sense Data Included */
static const true_false_string sna_rh_sdi_truth =
	{ "Included", "Not Included" };

/* Begin Chain Indicator */
static const true_false_string sna_rh_bci_truth =
	{ "First in Chain", "Not First in Chain" };

/* End Chain Indicator */
static const true_false_string sna_rh_eci_truth =
	{ "Last in Chain", "Not Last in Chain" };

/* Lengith-Checked Compression Indicator */
static const true_false_string sna_rh_lcci_truth =
	{ "Compressed", "Not Compressed" };

/* Response Type Indicator */
static const true_false_string sna_rh_rti_truth =
	{ "Negative", "Positive" };

/* Exception Response Indicator */
static const true_false_string sna_rh_eri_truth =
	{ "Exception", "Definite" };

/* Queued Response Indicator */
static const true_false_string sna_rh_qri_truth =
	{ "Enqueue response in TC queues", "Response bypasses TC queues" };

/* Code Selection Indicator */
static const value_string sna_rh_csi_vals[] = {
	{ 0, "EBCDIC" },
	{ 1, "ASCII" },
	{ 0x0,	NULL }
};

/* TG Sweep */
static const value_string sna_th_tg_sweep_vals[] = {
	{ 0, "This PIU may overtake any PU ahead of it." },
	{ 1, "This PIU does not ovetake any PIU ahead of it." },
	{ 0x0,	NULL }
};

/* ER_VR_SUPP_IND */
static const value_string sna_th_er_vr_supp_ind_vals[] = {
	{ 0, "Each node supports ER and VR protocols" },
	{ 1, "Includes at least one node that does not support ER and VR protocols"  },
	{ 0x0,	NULL }
};

/* VR_PAC_CNT_IND */
static const value_string sna_th_vr_pac_cnt_ind_vals[] = {
	{ 0, "Pacing count on the VR has not reached 0" },
	{ 1, "Pacing count on the VR has reached 0" },
	{ 0x0,	NULL }
};

/* NTWK_PRTY */
static const value_string sna_th_ntwk_prty_vals[] = {
	{ 0, "PIU flows at a lower priority" },
	{ 1, "PIU flows at network priority (highest transmission priority)" },
	{ 0x0,	NULL }
};

/* TGSF */
static const value_string sna_th_tgsf_vals[] = {
	{ 0, "Not segmented" },
	{ 1, "Last segment" },
	{ 2, "First segment" },
	{ 3, "Middle segment" },
	{ 0x0,	NULL }
};

/* PIUBF */
static const value_string sna_th_piubf_vals[] = {
	{ 0, "Single PIU frame" },
	{ 1, "Last PIU of a multiple PIU frame" },
	{ 2, "First PIU of a multiple PIU frame" },
	{ 3, "Middle PIU of a multiple PIU frame" },
	{ 0x0,	NULL }
};

/* NLPOI */
static const value_string sna_th_nlpoi_vals[] = {
	{ 0, "NLP starts within this FID4 TH" },
	{ 1, "NLP byte 0 starts after RH byte 0 following NLP C/P pad" },
	{ 0x0,	NULL }
};

/* TPF */
static const value_string sna_th_tpf_vals[] = {
	{ 0, "Low Priority" },
	{ 1, "Medium Priority" },
	{ 2, "High Priority" },
	{ 0x0,	NULL }
};

/* VR_CWI */
static const value_string sna_th_vr_cwi_vals[] = {
	{ 0, "Increment window size" },
	{ 1, "Decrement window size" },
	{ 0x0,	NULL }
};

/* TG_NONFIFO_IND */
static const true_false_string sna_th_tg_nonfifo_ind_truth =
	{ "TG FIFO is not required", "TG FIFO is required" };

/* VR_SQTI */
static const value_string sna_th_vr_sqti_vals[] = {
	{ 0, "Non-sequenced, Non-supervisory" },
	{ 1, "Non-sequenced, Supervisory" },
	{ 2, "Singly-sequenced" },
	{ 0x0,	NULL }
};

/* VRPRQ */
static const true_false_string sna_th_vrprq_truth = {
	"VR pacing request is sent asking for a VR pacing response",
	"No VR pacing response is requested",
};

/* VRPRS */
static const true_false_string sna_th_vrprs_truth = {
	"VR pacing response is sent in response to a VRPRQ bit set",
	"No pacing response sent",
};

/* VR_CWRI */
static const value_string sna_th_vr_cwri_vals[] = {
	{ 0, "Increment window size by 1" },
	{ 1, "Decrement window size by 1" },
	{ 0x0,	NULL }
};

/* VR_RWI */
static const true_false_string sna_th_vr_rwi_truth = {
	"Reset window size to the minimum specified in NC_ACTVR",
	"Do not reset window size",
};

static int  dissect_fid0_1 (tvbuff_t*, packet_info*, proto_tree*);
static int  dissect_fid2 (tvbuff_t*, packet_info*, proto_tree*);
static int  dissect_fid3 (tvbuff_t*, proto_tree*);
static int  dissect_fid4 (tvbuff_t*, packet_info*, proto_tree*);
static int  dissect_fid5 (tvbuff_t*, proto_tree*);
static int  dissect_fidf (tvbuff_t*, proto_tree*);
static void dissect_rh (tvbuff_t*, int, proto_tree*);

static void
dissect_sna(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	proto_tree	*sna_tree = NULL, *th_tree = NULL, *rh_tree = NULL;
	proto_item	*sna_ti = NULL, *th_ti = NULL, *rh_ti = NULL;
	guint8		th_fid;
	int		sna_header_len = 0, th_header_len = 0;
	int		offset;

	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "SNA");
	if (check_col(pinfo->fd, COL_INFO))
		col_clear(pinfo->fd, COL_INFO);

	/* SNA data should be printed in EBCDIC, not ASCII */
	pinfo->fd->flags.encoding = CHAR_EBCDIC;

	/* Transmission Header Format Identifier */
	th_fid = hi_nibble(tvb_get_guint8(tvb, 0));

	/* Summary information */
	if (check_col(pinfo->fd, COL_INFO))
		col_add_str(pinfo->fd, COL_INFO,
				val_to_str(th_fid, sna_th_fid_vals, "Unknown FID: %01x"));

	if (tree) {

		/* Don't bother setting length. We'll set it later after we find
		 * the lengths of TH/RH/RU */
		sna_ti = proto_tree_add_item(tree, proto_sna, tvb, 0, 0, FALSE);
		sna_tree = proto_item_add_subtree(sna_ti, ett_sna);

		/* --- TH --- */
		/* Don't bother setting length. We'll set it later after we find
		 * the length of TH */
		th_ti = proto_tree_add_item(sna_tree, hf_sna_th, tvb,  0, 0, FALSE);
		th_tree = proto_item_add_subtree(th_ti, ett_sna_th);
	}

	/* Get size of TH */
	switch(th_fid) {
		case 0x0:
		case 0x1:
			th_header_len = dissect_fid0_1(tvb, pinfo, th_tree);
			break;
		case 0x2:
			th_header_len = dissect_fid2(tvb, pinfo, th_tree);
			break;
		case 0x3:
			th_header_len = dissect_fid3(tvb, th_tree);
			break;
		case 0x4:
			th_header_len = dissect_fid4(tvb, pinfo, th_tree);
			break;
		case 0x5:
			th_header_len = dissect_fid5(tvb, th_tree);
			break;
		case 0xf:
			th_header_len = dissect_fidf(tvb, th_tree);
			break;
		default:
			call_dissector(data_handle,tvb_new_subset(tvb, 1,-1,tvb_reported_length_remaining(tvb,1)), pinfo, tree);
	}

	sna_header_len += th_header_len;
	offset = th_header_len;

	if (tree) {
		proto_item_set_len(th_ti, th_header_len);

		/* --- RH --- */
		rh_ti = proto_tree_add_item(sna_tree, hf_sna_rh, tvb, offset, 3, FALSE);
		rh_tree = proto_item_add_subtree(rh_ti, ett_sna_rh);
		dissect_rh(tvb, offset, rh_tree);

		sna_header_len += 3;
		offset += 3;
		proto_item_set_len(sna_ti, sna_header_len);
	}
	else {
		sna_header_len += 3;
		offset += 3;
	}

	if (tvb_offset_exists(tvb, offset+1)) {
		call_dissector(data_handle,tvb_new_subset(tvb, offset, -1, tvb_reported_length_remaining(tvb,offset)),pinfo, tree);
	}
}

#define SNA_FID01_ADDR_LEN	2

/* FID Types 0 and 1 */
static int
dissect_fid0_1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0;
	const guint8	*ptr;

	const int bytes_in_header = 10;

	if (tree) {
		/* Byte 0 */
		th_0 = tvb_get_guint8(tvb, 0);
		bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, 0, 1, th_0);
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb, 0, 1, th_0);
		proto_tree_add_uint(bf_tree, hf_sna_th_mpf, tvb, 0, 1, th_0);
		proto_tree_add_uint(bf_tree, hf_sna_th_efi, tvb, 0, 1, th_0);

		/* Byte 1 */
		proto_tree_add_text(tree, tvb, 1, 1, "Reserved");

		/* Bytes 2-3 */
		proto_tree_add_item(tree, hf_sna_th_daf, tvb, 2, 2, FALSE);
	}

	/* Set DST addr */
	ptr = tvb_get_ptr(tvb, 2, SNA_FID01_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_dst, AT_SNA, SNA_FID01_ADDR_LEN, ptr);
	SET_ADDRESS(&pinfo->dst, AT_SNA, SNA_FID01_ADDR_LEN, ptr);

	if (tree) {
		proto_tree_add_item(tree, hf_sna_th_oaf, tvb, 4, 2, FALSE);
	}

	/* Set SRC addr */
	ptr = tvb_get_ptr(tvb, 4, SNA_FID01_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_src, AT_SNA, SNA_FID01_ADDR_LEN, ptr);
	SET_ADDRESS(&pinfo->src, AT_SNA, SNA_FID01_ADDR_LEN, ptr);

	/* If we're not filling a proto_tree, return now */
	if (tree) {
		return bytes_in_header;
	}

	proto_tree_add_item(tree, hf_sna_th_snf, tvb, 6, 2, FALSE);
	proto_tree_add_item(tree, hf_sna_th_dcf, tvb, 8, 2, FALSE);

	return bytes_in_header;
}

#define SNA_FID2_ADDR_LEN	1

/* FID Type 2 */
static int
dissect_fid2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0=0, daf=0, oaf=0;
	const guint8	*ptr;

	const int bytes_in_header = 6;

	if (tree) {
		th_0 = tvb_get_guint8(tvb, 0);
		daf = tvb_get_guint8(tvb, 2);
		oaf = tvb_get_guint8(tvb, 3);

		/* Byte 0 */
		bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, 0, 1, th_0);
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb, 0, 1, th_0);
		proto_tree_add_uint(bf_tree, hf_sna_th_mpf, tvb, 0, 1, th_0);
		proto_tree_add_uint(bf_tree, hf_sna_th_odai,tvb, 0, 1, th_0);
		proto_tree_add_uint(bf_tree, hf_sna_th_efi, tvb, 0, 1, th_0);

		/* Byte 1 */
		proto_tree_add_text(tree, tvb, 1, 1, "Reserved");

		/* Byte 2 */
		proto_tree_add_uint_format(tree, hf_sna_th_daf, tvb, 2, 1, daf,
				"Destination Address Field: 0x%02x", daf);
	}

	/* Set DST addr */
	ptr = tvb_get_ptr(tvb, 2, SNA_FID2_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_dst, AT_SNA, SNA_FID2_ADDR_LEN, ptr);
	SET_ADDRESS(&pinfo->dst, AT_SNA, SNA_FID2_ADDR_LEN, ptr);

	if (tree) {
		/* Byte 3 */
		proto_tree_add_uint_format(tree, hf_sna_th_oaf, tvb, 3, 1, oaf,
				"Origin Address Field: 0x%02x", oaf);
	}

	/* Set SRC addr */
	ptr = tvb_get_ptr(tvb, 3, SNA_FID2_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_src, AT_SNA, SNA_FID2_ADDR_LEN, ptr);
	SET_ADDRESS(&pinfo->src, AT_SNA, SNA_FID2_ADDR_LEN, ptr);

	if (tree) {
		proto_tree_add_item(tree, hf_sna_th_snf, tvb, 4, 2, FALSE);
	}

	return bytes_in_header;
}

/* FID Type 3 */
static int
dissect_fid3(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0;

	const int bytes_in_header = 2;

	/* If we're not filling a proto_tree, return now */
	if (!tree) {
		return bytes_in_header;
	}

	th_0 = tvb_get_guint8(tvb, 0);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, 0, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb, 0, 1, th_0);
	proto_tree_add_uint(bf_tree, hf_sna_th_mpf, tvb, 0, 1, th_0);
	proto_tree_add_uint(bf_tree, hf_sna_th_efi, tvb, 0, 1, th_0);

	proto_tree_add_item(tree, hf_sna_th_lsid, tvb, 1, 1, FALSE);

	return bytes_in_header;
}


static int
dissect_fid4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	int		offset = 0;
	guint8		th_byte, mft;
	guint16		th_word;
	guint16		def, oef;
	guint32		dsaf, osaf;
	static struct sna_fid_type_4_addr src, dst;

	const int bytes_in_header = 26;

	/* If we're not filling a proto_tree, return now */
	if (!tree) {
		return bytes_in_header;
	}

	if (tree) {
		th_byte = tvb_get_guint8(tvb, offset);

		/* Create the bitfield tree */
		bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, offset, 1, th_byte);
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		/* Byte 0 */
		proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb, offset, 1, th_byte);
		proto_tree_add_uint(bf_tree, hf_sna_th_tg_sweep, tvb, offset, 1, th_byte);
		proto_tree_add_uint(bf_tree, hf_sna_th_er_vr_supp_ind, tvb, offset, 1, th_byte);
		proto_tree_add_uint(bf_tree, hf_sna_th_vr_pac_cnt_ind, tvb, offset, 1, th_byte);
		proto_tree_add_uint(bf_tree, hf_sna_th_ntwk_prty, tvb, offset, 1, th_byte);

		offset += 1;
		th_byte = tvb_get_guint8(tvb, offset);

		/* Create the bitfield tree */
		bf_item = proto_tree_add_text(tree, tvb, offset, 1, "Transmision Header Byte 1");
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		/* Byte 1 */
		proto_tree_add_uint(bf_tree, hf_sna_th_tgsf, tvb, offset, 1, th_byte);
		proto_tree_add_boolean(bf_tree, hf_sna_th_mft, tvb, offset, 1, th_byte);
		proto_tree_add_uint(bf_tree, hf_sna_th_piubf, tvb, offset, 1, th_byte);

		mft = th_byte & 0x04;
		offset += 1;
		th_byte = tvb_get_guint8(tvb, offset);

		/* Create the bitfield tree */
		bf_item = proto_tree_add_text(tree, tvb, offset, 1, "Transmision Header Byte 2");
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		/* Byte 2 */
		if (mft) {
			proto_tree_add_uint(bf_tree, hf_sna_th_nlpoi, tvb, offset, 1, th_byte);
			proto_tree_add_uint(bf_tree, hf_sna_th_nlp_cp, tvb, offset, 1, th_byte);
		}
		else {
			proto_tree_add_uint(bf_tree, hf_sna_th_iern, tvb, offset, 1, th_byte);
		}
		proto_tree_add_uint(bf_tree, hf_sna_th_ern, tvb, offset, 1, th_byte);

		offset += 1;
		th_byte = tvb_get_guint8(tvb, offset);

		/* Create the bitfield tree */
		bf_item = proto_tree_add_text(tree, tvb, offset, 1, "Transmision Header Byte 3");
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		/* Byte 3 */
		proto_tree_add_uint(bf_tree, hf_sna_th_vrn, tvb, offset, 1, th_byte);
		proto_tree_add_uint(bf_tree, hf_sna_th_tpf, tvb, offset, 1, th_byte);

		offset += 1;
		th_word = tvb_get_ntohs(tvb, offset);

		/* Create the bitfield tree */
		bf_item = proto_tree_add_text(tree, tvb, offset, 2, "Transmision Header Bytes 4-5");
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		/* Bytes 4-5 */
		proto_tree_add_uint(bf_tree, hf_sna_th_vr_cwi, tvb, offset, 2, th_word);
		proto_tree_add_boolean(bf_tree, hf_sna_th_tg_nonfifo_ind, tvb, offset, 2, th_word);
		proto_tree_add_uint(bf_tree, hf_sna_th_vr_sqti, tvb, offset, 2, th_word);

		/* I'm not sure about byte-order on this one... */
		proto_tree_add_uint(bf_tree, hf_sna_th_tg_snf, tvb, offset, 2, th_word);

		offset += 2;
		th_word = tvb_get_ntohs(tvb, offset);

		/* Create the bitfield tree */
		bf_item = proto_tree_add_text(tree, tvb, offset, 2, "Transmision Header Bytes 6-7");
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		/* Bytes 6-7 */
		proto_tree_add_boolean(bf_tree, hf_sna_th_vrprq, tvb, offset, 2, th_word);
		proto_tree_add_boolean(bf_tree, hf_sna_th_vrprs, tvb, offset, 2, th_word);
		proto_tree_add_uint(bf_tree, hf_sna_th_vr_cwri, tvb, offset, 2, th_word);
		proto_tree_add_boolean(bf_tree, hf_sna_th_vr_rwi, tvb, offset, 2, th_word);

		/* I'm not sure about byte-order on this one... */
		proto_tree_add_uint(bf_tree, hf_sna_th_vr_snf_send, tvb, offset, 2, th_word);

		offset += 2;
	}

	dsaf = tvb_get_ntohl(tvb, 8);
	if (tree) {
		/* Bytes 8-11 */
		proto_tree_add_uint(tree, hf_sna_th_dsaf, tvb, offset, 4, dsaf);

		offset += 4;
	}

	osaf = tvb_get_ntohl(tvb, 12);
	if (tree) {
		/* Bytes 12-15 */
		proto_tree_add_uint(tree, hf_sna_th_osaf, tvb, offset, 4, osaf);

		offset += 4;
		th_byte = tvb_get_guint8(tvb, offset);

		/* Create the bitfield tree */
		bf_item = proto_tree_add_text(tree, tvb, offset, 2, "Transmision Header Byte 16");
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		/* Byte 16 */
		proto_tree_add_boolean(tree, hf_sna_th_snai, tvb, offset, 1, th_byte);

		/* We luck out here because in their infinite wisdom the SNA
		 * architects placed the MPF and EFI fields in the same bitfield
		 * locations, even though for FID4 they're not in byte 0.
		 * Thank you IBM! */
		proto_tree_add_uint(tree, hf_sna_th_mpf, tvb, offset, 1, th_byte);
		proto_tree_add_uint(tree, hf_sna_th_efi, tvb, offset, 1, th_byte);

		offset += 2; /* 1 for byte 16, 1 for byte 17 which is reserved */
	}


	def = tvb_get_ntohs(tvb, 18);
	if (tree) {
		/* Bytes 18-25 */
		proto_tree_add_uint(tree, hf_sna_th_def, tvb, offset, 2, def);
	}

	/* Addresses in FID 4 are discontiguous, sigh */
	dst.saf = dsaf;
	dst.ef = def;
	SET_ADDRESS(&pinfo->net_dst, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN, (guint8* )&dst);
	SET_ADDRESS(&pinfo->dst, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN, (guint8 *)&dst);


	oef = tvb_get_ntohs(tvb, 20);
	if (tree) {
		proto_tree_add_uint(tree, hf_sna_th_oef, tvb, offset+2, 2, oef);
	}

	/* Addresses in FID 4 are discontiguous, sigh */
	src.saf = osaf;
	src.ef = oef;
	SET_ADDRESS(&pinfo->net_src, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN, (guint8 *)&src);
	SET_ADDRESS(&pinfo->src, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN, (guint8 *)&src);

	if (tree) {
		proto_tree_add_item(tree, hf_sna_th_snf, tvb, offset+4, 2, FALSE);
		proto_tree_add_item(tree, hf_sna_th_dcf, tvb, offset+6, 2, FALSE);
	}

	return bytes_in_header;
}

/* FID Type 5 */
static int
dissect_fid5(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0;

	const int bytes_in_header = 12;

	/* If we're not filling a proto_tree, return now */
	if (!tree) {
		return bytes_in_header;
	}

	th_0 = tvb_get_guint8(tvb, 0);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, 0, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb, 0, 1, th_0);
	proto_tree_add_uint(bf_tree, hf_sna_th_mpf, tvb, 0, 1, th_0);
	proto_tree_add_uint(bf_tree, hf_sna_th_efi, tvb, 0, 1, th_0);

	proto_tree_add_text(tree, tvb, 1, 1, "Reserved");
	proto_tree_add_item(tree, hf_sna_th_snf, tvb, 2, 2, FALSE);

	proto_tree_add_item(tree, hf_sna_th_sa, tvb, 4, 8, FALSE);

	return bytes_in_header;

}

/* FID Type f */
static int
dissect_fidf(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0;
	
	const int bytes_in_header = 26;

	/* If we're not filling a proto_tree, return now */
	if (!tree) {
		return bytes_in_header;
	}

	th_0 = tvb_get_guint8(tvb, 0);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, 0, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb, 0, 1, th_0);
	proto_tree_add_text(tree, tvb, 1, 1, "Reserved");

	proto_tree_add_item(tree, hf_sna_th_cmd_fmt, tvb,  2, 1, FALSE);
	proto_tree_add_item(tree, hf_sna_th_cmd_type, tvb, 3, 1, FALSE);
	proto_tree_add_item(tree, hf_sna_th_cmd_sn, tvb,   4, 2, FALSE);

	/* Yup, bytes 6-23 are reserved! */
	proto_tree_add_text(tree, tvb, 6, 18, "Reserved");

	proto_tree_add_item(tree, hf_sna_th_dcf, tvb, 24, 2, FALSE);

	return bytes_in_header;
}


/* RH */
static void
dissect_rh(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	gboolean	is_response;
	guint8		rh_0, rh_1, rh_2;


	/* Create the bitfield tree for byte 0*/
	rh_0 = tvb_get_guint8(tvb, offset);
	is_response = (rh_0 & 0x80);

	bf_item = proto_tree_add_uint(tree, hf_sna_rh_0, tvb, offset, 1, rh_0);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_rh_0);

	proto_tree_add_uint(bf_tree, hf_sna_rh_rri, tvb, offset, 1, rh_0);
	proto_tree_add_uint(bf_tree, hf_sna_rh_ru_category, tvb, offset, 1, rh_0);
	proto_tree_add_boolean(bf_tree, hf_sna_rh_fi, tvb, offset, 1, rh_0);
	proto_tree_add_boolean(bf_tree, hf_sna_rh_sdi, tvb, offset, 1, rh_0);
	proto_tree_add_boolean(bf_tree, hf_sna_rh_bci, tvb, offset, 1, rh_0);
	proto_tree_add_boolean(bf_tree, hf_sna_rh_eci, tvb, offset, 1, rh_0);

	offset += 1;
	rh_1 = tvb_get_guint8(tvb, offset);

	/* Create the bitfield tree for byte 1*/
	bf_item = proto_tree_add_uint(tree, hf_sna_rh_1, tvb, offset, 1, rh_1);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_rh_1);

	proto_tree_add_boolean(bf_tree, hf_sna_rh_dr1, tvb,  offset, 1, rh_1);

	if (!is_response) {
		proto_tree_add_boolean(bf_tree, hf_sna_rh_lcci, tvb, offset, 1, rh_1);
	}

	proto_tree_add_boolean(bf_tree, hf_sna_rh_dr2, tvb,  offset, 1, rh_1);

	if (is_response) {
		proto_tree_add_boolean(bf_tree, hf_sna_rh_rti, tvb,  offset, 1, rh_1);
	}
	else {
		proto_tree_add_boolean(bf_tree, hf_sna_rh_eri, tvb,  offset, 1, rh_1);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_rlwi, tvb, offset, 1, rh_1);
	}

	proto_tree_add_boolean(bf_tree, hf_sna_rh_qri, tvb, offset, 1, rh_1);
	proto_tree_add_boolean(bf_tree, hf_sna_rh_pi, tvb,  offset, 1, rh_1);

	offset += 1;
	rh_2 = tvb_get_guint8(tvb, offset);

	/* Create the bitfield tree for byte 2*/
	bf_item = proto_tree_add_uint(tree, hf_sna_rh_2, tvb, offset, 1, rh_2);

	if (!is_response) {
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_rh_2);

		proto_tree_add_boolean(bf_tree, hf_sna_rh_bbi, tvb,  offset, 1, rh_2);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_ebi, tvb,  offset, 1, rh_2);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_cdi, tvb,  offset, 1, rh_2);
		proto_tree_add_uint(bf_tree, hf_sna_rh_csi, tvb,  offset, 1, rh_2);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_edi, tvb,  offset, 1, rh_2);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_pdi, tvb,  offset, 1, rh_2);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_cebi, tvb, offset, 1, rh_2);
	}

	/* XXX - check for sdi. If TRUE, the next 4 bytes will be sense data */
}

void
proto_register_sna(void)
{
        static hf_register_info hf[] = {
                { &hf_sna_th,
                { "Transmission Header",	"sna.th", FT_NONE, BASE_NONE, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_0,
                { "Transmission Header Byte 0",	"sna.th.0", FT_UINT8, BASE_HEX, NULL, 0x0,
			"Byte 0 of Tranmission Header contains FID, MPF, ODAI,"
			" and EFI as bitfields.", HFILL }},

                { &hf_sna_th_fid,
                { "Format Identifer",		"sna.th.fid", FT_UINT8, BASE_HEX, VALS(sna_th_fid_vals), 0xf0,
			"Format Identification", HFILL }},

                { &hf_sna_th_mpf,
                { "Mapping Field",		"sna.th.mpf", FT_UINT8, BASE_DEC, VALS(sna_th_mpf_vals), 0x0c,
			"The Mapping Field specifies whether the information field"
			" associated with the TH is a complete or partial BIU.", HFILL }},

		{ &hf_sna_th_odai,
		{ "ODAI Assignment Indicator",	"sna.th.odai", FT_UINT8, BASE_DEC, NULL, 0x02,
			"The ODAI indicates which node assigned the OAF'-DAF' values"
			" carried in the TH.", HFILL }},

                { &hf_sna_th_efi,
                { "Expedited Flow Indicator",	"sna.th.efi", FT_UINT8, BASE_DEC, VALS(sna_th_efi_vals), 0x01,
			"The EFI designates whether the PIU belongs to the normal"
			" or expedited flow.", HFILL }},

                { &hf_sna_th_daf,
                { "Destination Address Field",	"sna.th.daf", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_oaf,
                { "Origin Address Field",	"sna.th.oaf", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_snf,
                { "Sequence Number Field",	"sna.th.snf", FT_UINT16, BASE_DEC, NULL, 0x0,
			"The Sequence Number Field contains a numerical identifier for"
			" the associated BIU.", HFILL }},

                { &hf_sna_th_dcf,
                { "Data Count Field",	"sna.th.dcf", FT_UINT16, BASE_DEC, NULL, 0x0,
			"A binary count of the number of bytes in the BIU or BIU segment associated "
			"with the tranmission header. The count does not include any of the bytes "
			"in the transmission header.", HFILL }},

                { &hf_sna_th_lsid,
                { "Local Session Identification",	"sna.th.lsid", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_tg_sweep,
                { "Transmission Group Sweep",		"sna.th.tg_sweep", FT_UINT8, BASE_DEC,
			VALS(sna_th_tg_sweep_vals), 0x08,
			"", HFILL }},

                { &hf_sna_th_er_vr_supp_ind,
                { "ER and VR Support Indicator",	"sna.th.er_vr_supp_ind", FT_UINT8, BASE_DEC,
			VALS(sna_th_er_vr_supp_ind_vals), 0x04,
			"", HFILL }},

                { &hf_sna_th_vr_pac_cnt_ind,
                { "Virtual Route Pacing Count Indicator",	"sna.th.vr_pac_cnt_ind",
			FT_UINT8, BASE_DEC, VALS(sna_th_vr_pac_cnt_ind_vals), 0x02,
			"", HFILL }},

                { &hf_sna_th_ntwk_prty,
                { "Network Priority",	"sna.th.ntwk_prty",
			FT_UINT8, BASE_DEC, VALS(sna_th_ntwk_prty_vals), 0x01,
			"", HFILL }},

                { &hf_sna_th_tgsf,
                { "Transmission Group Segmenting Field",	"sna.th.tgsf",
			FT_UINT8, BASE_HEX, VALS(sna_th_tgsf_vals), 0xc0,
			"", HFILL }},

                { &hf_sna_th_mft,
                { "MPR FID4 Type",	"sna.th.mft", FT_BOOLEAN, BASE_NONE, NULL, 0x04,
			"", HFILL }},

                { &hf_sna_th_piubf,
                { "PIU Blocking Field",	"sna.th.piubf", FT_UINT8, BASE_HEX,
			VALS(sna_th_piubf_vals), 0x03,
			"Specifies whether this frame contains a single PIU or multiple PIUs.", HFILL }},

                { &hf_sna_th_iern,
                { "Initial Explicit Route Number",	"sna.th.iern", FT_UINT8, BASE_DEC, NULL, 0xf0,
			"", HFILL }},

                { &hf_sna_th_nlpoi,
                { "NLP Offset Indicator",	"sna.th.nlpoi", FT_UINT8, BASE_DEC,
			VALS(sna_th_nlpoi_vals), 0x80,
			"", HFILL }},

                { &hf_sna_th_nlp_cp,
                { "NLP Count or Padding",	"sna.th.nlp_cp", FT_UINT8, BASE_DEC, NULL, 0x70,
			"", HFILL }},

                { &hf_sna_th_ern,
                { "Explicit Route Number",	"sna.th.ern", FT_UINT8, BASE_DEC, NULL, 0x0f,
			"The ERN in a TH identifies an explicit route direction of flow.", HFILL }},

                { &hf_sna_th_vrn,
                { "Virtual Route Number",	"sna.th.vrn", FT_UINT8, BASE_DEC, NULL, 0xf0,
			"", HFILL }},

                { &hf_sna_th_tpf,
                { "Transmission Priority Field",	"sna.th.tpf", FT_UINT8, BASE_HEX,
			VALS(sna_th_tpf_vals), 0x03,
			"", HFILL }},

                { &hf_sna_th_vr_cwi,
                { "Virtual Route Change Window Indicator",	"sna.th.vr_cwi", FT_UINT16, BASE_DEC,
			VALS(sna_th_vr_cwi_vals), 0x8000,
			"Used to change the window size of the virtual route by 1.", HFILL }},

                { &hf_sna_th_tg_nonfifo_ind,
                { "Transmission Group Non-FIFO Indicator",	"sna.th.tg_nonfifo_ind", FT_BOOLEAN, 16,
			TFS(&sna_th_tg_nonfifo_ind_truth), 0x4000,
			"Indicates whether or not FIFO discipline is to enforced in "
			"transmitting PIUs through the tranmission groups to prevent the PIUs "
			"getting out of sequence during transmission over the TGs.", HFILL }},

                { &hf_sna_th_vr_sqti,
                { "Virtual Route Sequence and Type Indicator",	"sna.th.vr_sqti", FT_UINT16, BASE_HEX,
			VALS(sna_th_vr_sqti_vals), 0x3000,
			"Specifies the PIU type.", HFILL }},

                { &hf_sna_th_tg_snf,
                { "Transmission Group Sequence Number Field",	"sna.th.tg_snf", FT_UINT16, BASE_DEC,
			NULL, 0x0fff,
			"", HFILL }},

                { &hf_sna_th_vrprq,
                { "Virtual Route Pacing Request",	"sna.th.vrprq", FT_BOOLEAN, 16,
			TFS(&sna_th_vrprq_truth), 0x8000,
			"", HFILL }},

                { &hf_sna_th_vrprs,
                { "Virtual Route Pacing Response",	"sna.th.vrprs", FT_BOOLEAN, 16,
			TFS(&sna_th_vrprs_truth), 0x4000,
			"", HFILL }},

                { &hf_sna_th_vr_cwri,
                { "Virtual Route Change Window Reply Indicator",	"sna.th.vr_cwri", FT_UINT16, BASE_DEC,
			VALS(sna_th_vr_cwri_vals), 0x2000,
			"Permits changing of the window size by 1 for PIUs received by the "
			"sender of this bit.", HFILL }},

                { &hf_sna_th_vr_rwi,
                { "Virtual Route Reset Window Indicator",	"sna.th.vr_rwi", FT_BOOLEAN, 16,
			TFS(&sna_th_vr_rwi_truth), 0x1000,
			"Indicates severe congestion in a node on the virtual route.", HFILL }},

                { &hf_sna_th_vr_snf_send,
                { "Virtual Route Send Sequence Number Field",	"sna.th.vr_snf_send", FT_UINT16, BASE_DEC,
			NULL, 0x0fff,
			"", HFILL }},

                { &hf_sna_th_dsaf,
                { "Destination Subarea Address Field",	"sna.th.dsaf", FT_UINT32, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_osaf,
                { "Origin Subarea Address Field",	"sna.th.osaf", FT_UINT32, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_snai,
                { "SNA Indicator",	"sna.th.snai", FT_BOOLEAN, 8, NULL, 0x10,
			"Used to identify whether the PIU originated or is destined for "
			"an SNA or non-SNA device.", HFILL }},

                { &hf_sna_th_def,
                { "Destination Element Field",	"sna.th.def", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_oef,
                { "Origin Element Field",	"sna.th.oef", FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_sa,
                { "Session Address",	"sna.th.sa", FT_BYTES, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_cmd_fmt,
                { "Command Format",	"sna.th.cmd_fmt", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_cmd_type,
                { "Command Type",	"sna.th.cmd_type", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_th_cmd_sn,
                { "Command Sequence Number",	"sna.th.cmd_sn", FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }},


                { &hf_sna_rh,
                { "Request/Response Header",	"sna.rh", FT_NONE, BASE_NONE, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_rh_0,
                { "Request/Response Header Byte 0",	"sna.rh.0", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_rh_1,
                { "Request/Response Header Byte 1",	"sna.rh.1", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_rh_2,
                { "Request/Response Header Byte 2",	"sna.rh.2", FT_UINT8, BASE_HEX, NULL, 0x0,
			"", HFILL }},

                { &hf_sna_rh_rri,
                { "Request/Response Indicator",	"sna.rh.rri", FT_UINT8, BASE_DEC, VALS(sna_rh_rri_vals), 0x80,
			"Denotes whether this is a request or a response.", HFILL }},

                { &hf_sna_rh_ru_category,
                { "Request/Response Unit Category",	"sna.rh.ru_category", FT_UINT8, BASE_HEX,
			VALS(sna_rh_ru_category_vals), 0x60,
			"", HFILL }},

		{ &hf_sna_rh_fi,
		{ "Format Indicator",		"sna.rh.fi", FT_BOOLEAN, 8, TFS(&sna_rh_fi_truth), 0x08,
			"", HFILL }},

		{ &hf_sna_rh_sdi,
		{ "Sense Data Included",	"sna.rh.sdi", FT_BOOLEAN, 8, TFS(&sna_rh_sdi_truth), 0x04,
			"Indicates that a 4-byte sense data field is included in the associated RU.", HFILL }},

		{ &hf_sna_rh_bci,
		{ "Begin Chain Indicator",	"sna.rh.bci", FT_BOOLEAN, 8, TFS(&sna_rh_bci_truth), 0x02,
			"", HFILL }},

		{ &hf_sna_rh_eci,
		{ "End Chain Indicator",	"sna.rh.eci", FT_BOOLEAN, 8, TFS(&sna_rh_eci_truth), 0x01,
			"", HFILL }},

		{ &hf_sna_rh_dr1,
		{ "Definite Response 1 Indicator",	"sna.rh.dr1", FT_BOOLEAN, 8, NULL, 0x80,
			"", HFILL }},

		{ &hf_sna_rh_lcci,
		{ "Length-Checked Compression Indicator",	"sna.rh.lcci", FT_BOOLEAN, 8,
			TFS(&sna_rh_lcci_truth), 0x40,
			"", HFILL }},

		{ &hf_sna_rh_dr2,
		{ "Definite Response 2 Indicator",	"sna.rh.dr2", FT_BOOLEAN, 8, NULL, 0x20,
			"", HFILL }},

		{ &hf_sna_rh_eri,
		{ "Exception Response Indicator",	"sna.rh.eri", FT_BOOLEAN, 8, NULL, 0x10,
			"Used in conjunction with DR1I and DR2I to indicate, in a request, "
			"the form of response requested.", HFILL }},

		{ &hf_sna_rh_rti,
		{ "Response Type Indicator",	"sna.rh.rti", FT_BOOLEAN, 8, TFS(&sna_rh_rti_truth), 0x10,
			"", HFILL }},

		{ &hf_sna_rh_rlwi,
		{ "Request Larger Window Indicator",	"sna.rh.rlwi", FT_BOOLEAN, 8, NULL, 0x04,
			"Indicates whether a larger pacing window was requested.", HFILL }},

		{ &hf_sna_rh_qri,
		{ "Queued Response Indicator",	"sna.rh.qri", FT_BOOLEAN, 8, TFS(&sna_rh_qri_truth), 0x02,
			"", HFILL }},

		{ &hf_sna_rh_pi,
		{ "Pacing Indicator",	"sna.rh.pi", FT_BOOLEAN, 8, NULL, 0x01,
			"", HFILL }},

		{ &hf_sna_rh_bbi,
		{ "Begin Bracket Indicator",	"sna.rh.bbi", FT_BOOLEAN, 8, NULL, 0x80,
			"", HFILL }},

		{ &hf_sna_rh_ebi,
		{ "End Bracket Indicator",	"sna.rh.ebi", FT_BOOLEAN, 8, NULL, 0x40,
			"", HFILL }},

		{ &hf_sna_rh_cdi,
		{ "Change Direction Indicator",	"sna.rh.cdi", FT_BOOLEAN, 8, NULL, 0x20,
			"", HFILL }},

		{ &hf_sna_rh_csi,
		{ "Code Selection Indicator",	"sna.rh.csi", FT_UINT8, BASE_DEC, VALS(sna_rh_csi_vals), 0x08,
			"Specifies the encoding used for the associated FMD RU.", HFILL }},

		{ &hf_sna_rh_edi,
		{ "Enciphered Data Indicator",	"sna.rh.edi", FT_BOOLEAN, 8, NULL, 0x04,
			"Indicates that information in the associated RU is enciphered under "
			"session-level cryptography protocols.", HFILL }},

		{ &hf_sna_rh_pdi,
		{ "Padded Data Indicator",	"sna.rh.pdi", FT_BOOLEAN, 8, NULL, 0x02,
			"Indicates that the RU was padded at the end, before encipherment, to the next "
			"integral multiple of 8 bytes.", HFILL }},

		{ &hf_sna_rh_cebi,
		{ "Conditional End Bracket Indicator",	"sna.rh.cebi", FT_BOOLEAN, 8, NULL, 0x01,
			"Used to indicate the beginning or end of a group of exchanged "
			"requests and responses called a bracket. Only used on LU-LU sessions.", HFILL }},

/*                { &hf_sna_ru,
                { "Request/Response Unit",	"sna.ru", FT_NONE, BASE_NONE, NULL, 0x0,
			"", HFILL }},*/
        };
	static gint *ett[] = {
		&ett_sna,
		&ett_sna_th,
		&ett_sna_th_fid,
		&ett_sna_rh,
		&ett_sna_rh_0,
		&ett_sna_rh_1,
		&ett_sna_rh_2,
	};

        proto_sna = proto_register_protocol("Systems Network Architecture",
	    "SNA", "sna");
	proto_register_field_array(proto_sna, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("sna", dissect_sna, proto_sna);
}

void
proto_reg_handoff_sna(void)
{
	dissector_handle_t sna_handle;

	sna_handle = find_dissector("sna");
	dissector_add("llc.dsap", SAP_SNA_PATHCTRL, sna_handle);
	data_handle = find_dissector("data");
}
