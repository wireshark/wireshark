/* packet-sna.c
 * Routines for SNA
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-sna.c,v 1.8 1999/10/26 08:08:24 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
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
#include "packet-sna.h"

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
static int hf_sna_ru = -1;

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
	{ 1, "Expedited Flow" }
};

/* Request/Response Indicator */
static const value_string sna_rh_rri_vals[] = {
	{ 0, "Request" },
	{ 1, "Response" }
};

/* Request/Response Unit Category */
static const value_string sna_rh_ru_category_vals[] = {
	{ 0x00, "Function Management Data (FMD)" },
	{ 0x01, "Network Control (NC)" },
	{ 0x10, "Data Flow Control (DFC)" },
	{ 0x11, "Session Control (SC)" },
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
	{ 1, "ASCII" }
};

/* TG Sweep */
static const value_string sna_th_tg_sweep_vals[] = {
	{ 0, "This PIU may overtake any PU ahead of it." },
	{ 1, "This PIU does not ovetake any PIU ahead of it." }
};

/* ER_VR_SUPP_IND */
static const value_string sna_th_er_vr_supp_ind_vals[] = {
	{ 0, "Each node supports ER and VR protocols" },
	{ 1, "Includes at least one node that does not support ER and VR protocols"  }
};

/* VR_PAC_CNT_IND */
static const value_string sna_th_vr_pac_cnt_ind_vals[] = {
	{ 0, "Pacing count on the VR has not reached 0" },
	{ 1, "Pacing count on the VR has reached 0" }
};

/* NTWK_PRTY */
static const value_string sna_th_ntwk_prty_vals[] = {
	{ 0, "PIU flows at a lower priority" },
	{ 1, "PIU flows at network priority (highest transmission priority)" }
};

/* TGSF */
static const value_string sna_th_tgsf_vals[] = {
	{ 0x00, "Not segmented" },
	{ 0x01, "Last segment" },
	{ 0x10, "First segment" },
	{ 0x11, "Middle segment" }
};

/* PIUBF */
static const value_string sna_th_piubf_vals[] = {
	{ 0x00, "Single PIU frame" },
	{ 0x01, "Last PIU of a multiple PIU frame" },
	{ 0x10, "First PIU of a multiple PIU frame" },
	{ 0x11, "Middle PIU of a multiple PIU frame" }
};

/* NLPOI */
static const value_string sna_th_nlpoi_vals[] = {
	{ 0x0, "NLP starts within this FID4 TH" },
	{ 0x1, "NLP byte 0 starts after RH byte 0 following NLP C/P pad" },
};

/* TPF */
static const value_string sna_th_tpf_vals[] = {
	{ 0x00, "Low Priority" },
	{ 0x01, "Medium Priority" },
	{ 0x10, "High Priority" },
};

/* VR_CWI */
static const value_string sna_th_vr_cwi_vals[] = {
	{ 0x0, "Increment window size" },
	{ 0x1, "Decrement window size" },
};

/* TG_NONFIFO_IND */
static const true_false_string sna_th_tg_nonfifo_ind_truth =
	{ "TG FIFO is not required", "TG FIFO is required" };

/* VR_SQTI */
static const value_string sna_th_vr_sqti_vals[] = {
	{ 0x00, "Non-sequenced, Non-supervisory" },
	{ 0x01, "Non-sequenced, Supervisory" },
	{ 0x10, "Singly-sequenced" },
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
};

/* VR_RWI */
static const true_false_string sna_th_vr_rwi_truth = {
	"Reset window size to the minimum specified in NC_ACTVR",
	"Do not reset window size",
};

static int  dissect_fid0_1 (const u_char*, int, frame_data*, proto_tree*);
static int  dissect_fid2 (const u_char*, int, frame_data*, proto_tree*);
static int  dissect_fid3 (const u_char*, int, frame_data*, proto_tree*);
static int  dissect_fid4 (const u_char*, int, frame_data*, proto_tree*);
static int  dissect_fid5 (const u_char*, int, frame_data*, proto_tree*);
static int  dissect_fidf (const u_char*, int, frame_data*, proto_tree*);
static void dissect_rh (const u_char*, int, frame_data*, proto_tree*);

void
dissect_sna(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*sna_tree = NULL, *th_tree = NULL, *rh_tree = NULL;
	proto_item	*sna_ti = NULL, *th_ti = NULL, *rh_ti = NULL;
	guint8		th_fid;
	int		sna_header_len = 0, th_header_len = 0;

	if (IS_DATA_IN_FRAME(offset)) {
		/* Transmission Header Format Identifier */
		th_fid = hi_nibble(pd[offset]);
	}
	else {
		/* If our first byte isn't here, stop dissecting */
		return;
	}

	/* Summary information */
	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "SNA");
	if (check_col(fd, COL_INFO))
		col_add_str(fd, COL_INFO, val_to_str(th_fid, sna_th_fid_vals, "Unknown FID: %01x"));

	if (tree) {

		/* Don't bother setting length. We'll set it later after we find
		 * the lengths of TH/RH/RU */
		sna_ti = proto_tree_add_item(tree, proto_sna, offset, 0, NULL);
		sna_tree = proto_item_add_subtree(sna_ti, ETT_SNA);

		/* --- TH --- */
		/* Don't bother setting length. We'll set it later after we find
		 * the length of TH */
		th_ti = proto_tree_add_item(sna_tree, hf_sna_th,  offset, 0, NULL);
		th_tree = proto_item_add_subtree(th_ti, ETT_SNA_TH);
	}

	/* Get size of TH */
	switch(th_fid) {
		case 0x0:
		case 0x1:
			th_header_len = dissect_fid0_1(pd, offset, fd, th_tree);
			break;
		case 0x2:
			th_header_len = dissect_fid2(pd, offset, fd, th_tree);
			break;
		case 0x3:
			th_header_len = dissect_fid3(pd, offset, fd, th_tree);
			break;
		case 0x4:
			th_header_len = dissect_fid4(pd, offset, fd, th_tree);
			break;
		case 0x5:
			th_header_len = dissect_fid5(pd, offset, fd, th_tree);
			break;
		case 0xf:
			th_header_len = dissect_fidf(pd, offset, fd, th_tree);
			break;
		default:
			dissect_data(pd, offset+1, fd, tree);
	}

	sna_header_len += th_header_len;
	offset += th_header_len;

	if (tree) {
		proto_item_set_len(th_ti, th_header_len);

		/* --- RH --- */
		if (BYTES_ARE_IN_FRAME(offset, 3)) {
			rh_ti = proto_tree_add_item(sna_tree, hf_sna_rh, offset, 3, NULL);
			rh_tree = proto_item_add_subtree(rh_ti, ETT_SNA_RH);
			dissect_rh(pd, offset, fd, rh_tree);
			sna_header_len += 3;
			offset += 3;
		}
		else {
			/* If our first byte isn't here, stop dissecting */
			return;
		}

		proto_item_set_len(sna_ti, sna_header_len);
	}
	else {
		if (BYTES_ARE_IN_FRAME(offset, 3)) {
			sna_header_len += 3;
			offset += 3;
		}

	}

	if (IS_DATA_IN_FRAME(offset+1)) {
		dissect_data(pd, offset, fd, tree);
	}
}

/* FID Types 0 and 1 */
static int
dissect_fid0_1 (const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0;
	guint16		daf, oaf, snf, dcf;

	static int bytes_in_header = 10;

	if (!BYTES_ARE_IN_FRAME(offset, bytes_in_header)) {
		return 0;
	}

	th_0 = pd[offset+0];
	daf = pntohs(&pd[offset+2]);
	oaf = pntohs(&pd[offset+4]);
	snf = pntohs(&pd[offset+6]);
	dcf = pntohs(&pd[offset+8]);

	SET_ADDRESS(&pi.net_src, AT_SNA, 2, &pd[offset+4]);
	SET_ADDRESS(&pi.src, AT_SNA, 2, &pd[offset+4]);
	SET_ADDRESS(&pi.net_dst, AT_SNA, 2, &pd[offset+2]);
	SET_ADDRESS(&pi.dst, AT_SNA, 2, &pd[offset+2]);

	if (!tree) {
		return bytes_in_header;
	}

	/* Create the bitfield tree */
	bf_item = proto_tree_add_item(tree, hf_sna_th_0, offset, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	proto_tree_add_item(bf_tree, hf_sna_th_fid, offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_mpf, offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_efi ,offset, 1, th_0);

	proto_tree_add_text(tree, offset+1, 1, "Reserved");
	proto_tree_add_item(tree, hf_sna_th_daf ,offset+2, 1, daf);
	proto_tree_add_item(tree, hf_sna_th_oaf ,offset+4, 1, oaf);
	proto_tree_add_item(tree, hf_sna_th_snf ,offset+6, 2, snf);
	proto_tree_add_item(tree, hf_sna_th_dcf ,offset+8, 2, dcf);

	return bytes_in_header;

}


/* FID Type 2 */
static int
dissect_fid2 (const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0, daf, oaf;
	guint16		snf;

	static int bytes_in_header = 6;

	if (!BYTES_ARE_IN_FRAME(offset, bytes_in_header)) {
		return 0;
	}

	th_0 = pd[offset+0];
	daf = pd[offset+2];
	oaf = pd[offset+3];

	/* Addresses in FID 2 are FT_UINT8 */
	SET_ADDRESS(&pi.net_src, AT_SNA, 1, &pd[offset+3]);
	SET_ADDRESS(&pi.src, AT_SNA, 1, &pd[offset+3]);
	SET_ADDRESS(&pi.net_dst, AT_SNA, 1, &pd[offset+2]);
	SET_ADDRESS(&pi.dst, AT_SNA, 1, &pd[offset+2]);

	if (!tree) {
		return bytes_in_header;
	}

	snf = pntohs(&pd[offset+4]);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_item(tree, hf_sna_th_0, offset, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	proto_tree_add_item(bf_tree, hf_sna_th_fid, offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_mpf, offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_odai ,offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_efi ,offset, 1, th_0);

	/* Addresses in FID 2 are FT_UINT8 */
	proto_tree_add_text(tree, offset+1, 1, "Reserved");
	proto_tree_add_item_format(tree, hf_sna_th_daf ,offset+2, 1, daf,
			"Destination Address Field: 0x%02x", daf);
	proto_tree_add_item_format(tree, hf_sna_th_oaf ,offset+3, 1, oaf,
			"Origin Address Field: 0x%02x", oaf);
	proto_tree_add_item(tree, hf_sna_th_snf ,offset+4, 2, snf);

	return bytes_in_header;
}

/* FID Type 3 */
static int
dissect_fid3 (const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0;
	guint8		lsid;

	static int bytes_in_header = 2;

	if (!BYTES_ARE_IN_FRAME(offset, bytes_in_header)) {
		return 0;
	}

	if (!tree) {
		return bytes_in_header;
	}

	th_0 = pd[offset+0];
	lsid = pd[offset+1];

	/* Create the bitfield tree */
	bf_item = proto_tree_add_item(tree, hf_sna_th_0, offset, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	proto_tree_add_item(bf_tree, hf_sna_th_fid, offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_mpf, offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_efi ,offset, 1, th_0);

	proto_tree_add_item(tree, hf_sna_th_lsid ,offset+1, 1, lsid);

	return bytes_in_header;
}

/* FID Type 4 */

gchar *
sna_fid_type_4_addr_to_str(const struct sna_fid_type_4_addr *addrp)
{
  static gchar	str[3][14];
  static gchar	*cur;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else {
    cur = &str[0][0];
  }

  sprintf(cur, "%08X.%04X", addrp->saf, addrp->ef);
  return cur;
}

static int
dissect_fid4 (const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_byte, mft;
	guint16		th_word;
	guint16		def, oef, snf, dcf;
	guint32		dsaf, osaf;
	static struct sna_fid_type_4_addr src, dst;

	static int bytes_in_header = 26;

	if (!BYTES_ARE_IN_FRAME(offset, bytes_in_header)) {
		return 0;
	}

	dsaf = pntohl(&pd[offset+8]);
	osaf = pntohl(&pd[offset+12]);
	def = pntohs(&pd[offset+18]);
	oef = pntohs(&pd[offset+20]);
	snf = pntohs(&pd[offset+22]);
	dcf = pntohs(&pd[offset+24]);

	/* Addresses in FID 4 are discontiguous, sigh */
	src.saf = osaf;
	src.ef = oef;
	dst.saf = dsaf;
	dst.ef = def;
	SET_ADDRESS(&pi.net_src, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN,
	    (guint8 *)&src);
	SET_ADDRESS(&pi.src, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN,
	    (guint8 *)&src);
	SET_ADDRESS(&pi.net_dst, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN,
	    (guint8 *)&dst);
	SET_ADDRESS(&pi.dst, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN,
	    (guint8 *)&dst);

	if (!tree) {
		return bytes_in_header;
	}

	th_byte = pd[offset];

	/* Create the bitfield tree */
	bf_item = proto_tree_add_item(tree, hf_sna_th_0, offset, 1, th_byte);
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	/* Byte 0 */
	proto_tree_add_item(bf_tree, hf_sna_th_fid, offset, 1, th_byte);
	proto_tree_add_item(bf_tree, hf_sna_th_tg_sweep, offset, 1, th_byte);
	proto_tree_add_item(bf_tree, hf_sna_th_er_vr_supp_ind, offset, 1, th_byte);
	proto_tree_add_item(bf_tree, hf_sna_th_vr_pac_cnt_ind, offset, 1, th_byte);
	proto_tree_add_item(bf_tree, hf_sna_th_ntwk_prty, offset, 1, th_byte);

	offset += 1;
	th_byte = pd[offset];

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, offset, 1, "Transmision Header Byte 1");
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	/* Byte 1 */
	proto_tree_add_item(bf_tree, hf_sna_th_tgsf, offset, 1, th_byte);
	proto_tree_add_item(bf_tree, hf_sna_th_mft, offset, 1, th_byte);
	proto_tree_add_item(bf_tree, hf_sna_th_piubf, offset, 1, th_byte);

	mft = th_byte & 0x04;
	offset += 1;
	th_byte = pd[offset];

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, offset, 1, "Transmision Header Byte 2");
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	/* Byte 2 */
	if (mft) {
		proto_tree_add_item(bf_tree, hf_sna_th_nlpoi, offset, 1, th_byte);
		proto_tree_add_item(bf_tree, hf_sna_th_nlp_cp, offset, 1, th_byte);
	}
	else {
		proto_tree_add_item(bf_tree, hf_sna_th_iern, offset, 1, th_byte);
	}
	proto_tree_add_item(bf_tree, hf_sna_th_ern, offset, 1, th_byte);

	offset += 1;
	th_byte = pd[offset];

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, offset, 1, "Transmision Header Byte 3");
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	/* Byte 3 */
	proto_tree_add_item(bf_tree, hf_sna_th_vrn, offset, 1, th_byte);
	proto_tree_add_item(bf_tree, hf_sna_th_tpf, offset, 1, th_byte);

	offset += 1;
	th_word = pntohs(&pd[offset]);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, offset, 2, "Transmision Header Bytes 4-5");
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	/* Bytes 4-5 */
	proto_tree_add_item(bf_tree, hf_sna_th_vr_cwi, offset, 2, th_word);
	proto_tree_add_item(bf_tree, hf_sna_th_tg_nonfifo_ind, offset, 2, th_word);
	proto_tree_add_item(bf_tree, hf_sna_th_vr_sqti, offset, 2, th_word);

	/* I'm not sure about byte-order on this one... */
	proto_tree_add_item(bf_tree, hf_sna_th_tg_snf, offset, 2, th_word);

	offset += 2;
	th_word = pntohs(&pd[offset]);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, offset, 2, "Transmision Header Bytes 6-7");
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	/* Bytes 6-7 */
	proto_tree_add_item(bf_tree, hf_sna_th_vrprq, offset, 2, th_word);
	proto_tree_add_item(bf_tree, hf_sna_th_vrprs, offset, 2, th_word);
	proto_tree_add_item(bf_tree, hf_sna_th_vr_cwri, offset, 2, th_word);
	proto_tree_add_item(bf_tree, hf_sna_th_vr_rwi, offset, 2, th_word);

	/* I'm not sure about byte-order on this one... */
	proto_tree_add_item(bf_tree, hf_sna_th_vr_snf_send, offset, 2, th_word);

	offset += 2;

	/* Bytes 8-11 */
	proto_tree_add_item(tree, hf_sna_th_dsaf, offset, 4, dsaf);

	offset += 4;

	/* Bytes 12-15 */
	proto_tree_add_item(tree, hf_sna_th_osaf, offset, 4, osaf);

	offset += 4;
	th_byte = pd[offset];

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, offset, 2, "Transmision Header Byte 16");
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	/* Byte 16 */
	proto_tree_add_item(tree, hf_sna_th_snai, offset, 1, th_byte);

	/* We luck out here because in their infinite wisdom the SNA
	 * architects placed the MPF and EFI fields in the same bitfield
	 * locations, even though for FID4 they're not in byte 0.
	 * Thank you IBM! */
	proto_tree_add_item(tree, hf_sna_th_mpf, offset, 1, th_byte);
	proto_tree_add_item(tree, hf_sna_th_efi, offset, 1, th_byte);

	offset += 2; /* 1 for byte 16, 1 for byte 17 which is reserved */

	/* Bytes 18-25 */
	proto_tree_add_item(tree, hf_sna_th_def, offset+0, 2, def);
	proto_tree_add_item(tree, hf_sna_th_oef, offset+2, 2, oef);
	proto_tree_add_item(tree, hf_sna_th_snf, offset+4, 2, snf);
	proto_tree_add_item(tree, hf_sna_th_snf, offset+6, 2, dcf);

	return bytes_in_header;
}

/* FID Type 5 */
static int
dissect_fid5 (const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0;
	guint16		snf;

	static int bytes_in_header = 12;

	if (!BYTES_ARE_IN_FRAME(offset, bytes_in_header)) {
		return 0;
	}

	th_0 = pd[offset+0];
	snf = pntohs(&pd[offset+2]);

	if (!tree) {
		return bytes_in_header;
	}

	/* Create the bitfield tree */
	bf_item = proto_tree_add_item(tree, hf_sna_th_0, offset, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	proto_tree_add_item(bf_tree, hf_sna_th_fid, offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_mpf, offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_efi, offset, 1, th_0);

	proto_tree_add_text(tree, offset+1, 1, "Reserved");
	proto_tree_add_item(tree, hf_sna_th_snf, offset+2, 2, snf);

	proto_tree_add_item(tree, hf_sna_th_sa, offset+4, 8, &pd[offset+4]);

	return bytes_in_header;

}

/* FID Type f */
static int
dissect_fidf (const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0, cmd_fmt, cmd_type;
	guint16		cmd_sn, dcf;
	
	static int bytes_in_header = 26;

	if (!BYTES_ARE_IN_FRAME(offset, bytes_in_header)) {
		return 0;
	}

	th_0 = pd[offset+0];
	cmd_fmt = pd[offset+2];
	cmd_type = pd[offset+3];
	cmd_sn = pntohs(&pd[offset+4]);

	/* Yup, bytes 6-23 are reserved! */
	dcf = pntohs(&pd[offset+24]);

	if (!tree) {
		return bytes_in_header;
	}

	/* Create the bitfield tree */
	bf_item = proto_tree_add_item(tree, hf_sna_th_0, offset, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	proto_tree_add_item(bf_tree, hf_sna_th_fid, offset, 1, th_0);
	proto_tree_add_text(tree, offset+1, 1, "Reserved");

	proto_tree_add_item(tree, hf_sna_th_cmd_fmt,  offset+2, 1, cmd_fmt);
	proto_tree_add_item(tree, hf_sna_th_cmd_type, offset+3, 1, cmd_type);
	proto_tree_add_item(tree, hf_sna_th_cmd_sn,   offset+4, 2, cmd_sn);

	proto_tree_add_text(tree, offset+6, 18, "Reserved");

	proto_tree_add_item(tree, hf_sna_th_dcf, offset+24, 8, dcf);

	return bytes_in_header;
}


/* RH */
static void
dissect_rh (const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*bf_tree;
	proto_item	*bf_item;
	gboolean	is_response;
	guint8		rh_0, rh_1, rh_2;

	rh_0 = pd[offset+0];
	rh_1 = pd[offset+1];
	rh_2 = pd[offset+2];

	is_response = (rh_0 & 0x80);

	/* Create the bitfield tree for byte 0*/
	bf_item = proto_tree_add_item(tree, hf_sna_rh_0, offset, 1, rh_0);
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_RH_0);

	proto_tree_add_item(bf_tree, hf_sna_rh_rri, offset, 1, rh_0);
	proto_tree_add_item(bf_tree, hf_sna_rh_ru_category, offset, 1, rh_0);
	proto_tree_add_item(bf_tree, hf_sna_rh_fi, offset, 1, rh_0);
	proto_tree_add_item(bf_tree, hf_sna_rh_sdi, offset, 1, rh_0);
	proto_tree_add_item(bf_tree, hf_sna_rh_bci, offset, 1, rh_0);
	proto_tree_add_item(bf_tree, hf_sna_rh_eci, offset, 1, rh_0);

	offset += 1;

	/* Create the bitfield tree for byte 1*/
	bf_item = proto_tree_add_item(tree, hf_sna_rh_1, offset, 1, rh_1);
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_RH_1);

	proto_tree_add_item(bf_tree, hf_sna_rh_dr1,  offset, 1, rh_1);

	if (!is_response) {
		proto_tree_add_item(bf_tree, hf_sna_rh_lcci, offset, 1, rh_1);
	}

	proto_tree_add_item(bf_tree, hf_sna_rh_dr2,  offset, 1, rh_1);

	if (is_response) {
		proto_tree_add_item(bf_tree, hf_sna_rh_rti,  offset, 1, rh_1);
	}
	else {
		proto_tree_add_item(bf_tree, hf_sna_rh_eri,  offset, 1, rh_1);
		proto_tree_add_item(bf_tree, hf_sna_rh_rlwi, offset, 1, rh_1);
	}

	proto_tree_add_item(bf_tree, hf_sna_rh_qri, offset, 1, rh_1);
	proto_tree_add_item(bf_tree, hf_sna_rh_pi,  offset, 1, rh_1);

	offset += 1;

	/* Create the bitfield tree for byte 2*/
	bf_item = proto_tree_add_item(tree, hf_sna_rh_2, offset, 1, rh_2);

	if (!is_response) {
		bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_RH_2);

		proto_tree_add_item(bf_tree, hf_sna_rh_bbi,  offset, 1, rh_2);
		proto_tree_add_item(bf_tree, hf_sna_rh_ebi,  offset, 1, rh_2);
		proto_tree_add_item(bf_tree, hf_sna_rh_cdi,  offset, 1, rh_2);
		proto_tree_add_item(bf_tree, hf_sna_rh_csi,  offset, 1, rh_2);
		proto_tree_add_item(bf_tree, hf_sna_rh_edi,  offset, 1, rh_2);
		proto_tree_add_item(bf_tree, hf_sna_rh_pdi,  offset, 1, rh_2);
		proto_tree_add_item(bf_tree, hf_sna_rh_cebi, offset, 1, rh_2);
	}

	/* XXX - check for sdi. If TRUE, the next 4 bytes will be sense data */
}

void
proto_register_sna(void)
{
        static hf_register_info hf[] = {
                { &hf_sna_th,
                { "Transmission Header",	"sna.th", FT_NONE, BASE_NONE, NULL, 0x0,
			"" }},

                { &hf_sna_th_0,
                { "Transmission Header Byte 0",	"sna.th.0", FT_UINT8, BASE_HEX, NULL, 0x0,
			"Byte 0 of Tranmission Header contains FID, MPF, ODAI,"
			" and EFI as bitfields." }},

                { &hf_sna_th_fid,
                { "Format Identifer",		"sna.th.fid", FT_UINT8, BASE_HEX, VALS(sna_th_fid_vals), 0xf0,
			"Format Identification" }},

                { &hf_sna_th_mpf,
                { "Mapping Field",		"sna.th.mpf", FT_UINT8, BASE_NONE, VALS(sna_th_mpf_vals), 0x0c,
			"The Mapping Field specifies whether the information field"
			" associated with the TH is a complete or partial BIU." }},

		{ &hf_sna_th_odai,
		{ "ODAI Assignment Indicator",	"sna.th.odai", FT_UINT8, BASE_DEC, NULL, 0x02,
			"The ODAI indicates which node assigned the OAF'-DAF' values"
			" carried in the TH." }},

                { &hf_sna_th_efi,
                { "Expedited Flow Indicator",	"sna.th.efi", FT_UINT8, BASE_DEC, VALS(sna_th_efi_vals), 0x01,
			"The EFI designates whether the PIU belongs to the normal"
			" or expedited flow." }},

                { &hf_sna_th_daf,
                { "Destination Address Field",	"sna.th.daf", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_th_oaf,
                { "Origin Address Field",	"sna.th.oaf", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_th_snf,
                { "Sequence Number Field",	"sna.th.snf", FT_UINT16, BASE_NONE, NULL, 0x0,
			"The Sequence Number Field contains a numerical identifier for"
			" the associated BIU."}},

                { &hf_sna_th_dcf,
                { "Data Count Field",	"sna.th.dcf", FT_UINT16, BASE_DEC, NULL, 0x0,
			"A binary count of the number of bytes in the BIU or BIU segment associated "
			"with the tranmission header. The count does not include any of the bytes "
			"in the transmission header."}},

                { &hf_sna_th_lsid,
                { "Local Session Identification",	"sna.th.lsid", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_th_tg_sweep,
                { "Transmission Group Sweep",		"sna.th.tg_sweep", FT_UINT8, BASE_DEC,
			VALS(sna_th_tg_sweep_vals), 0x08,
			"" }},

                { &hf_sna_th_er_vr_supp_ind,
                { "ER and VR Support Indicator",	"sna.th.er_vr_supp_ind", FT_UINT8, BASE_DEC,
			VALS(sna_th_er_vr_supp_ind_vals), 0x04,
			"" }},

                { &hf_sna_th_vr_pac_cnt_ind,
                { "Virtual Route Pacing Count Indicator",	"sna.th.vr_pac_cnt_ind",
			FT_UINT8, BASE_DEC, VALS(sna_th_vr_pac_cnt_ind_vals), 0x02,
			"" }},

                { &hf_sna_th_ntwk_prty,
                { "Network Priority",	"sna.th.ntwk_prty",
			FT_UINT8, BASE_DEC, VALS(sna_th_ntwk_prty_vals), 0x01,
			"" }},

                { &hf_sna_th_tgsf,
                { "Transmission Group Segmenting Field",	"sna.th.tgsf",
			FT_UINT8, BASE_HEX, VALS(sna_th_tgsf_vals), 0xc0,
			"" }},

                { &hf_sna_th_mft,
                { "MPR FID4 Type",	"sna.th.mft", FT_BOOLEAN, BASE_NONE, NULL, 0x04,
			"" }},

                { &hf_sna_th_piubf,
                { "PIU Blocking Field",	"sna.th.piubf", FT_UINT8, BASE_HEX,
			VALS(sna_th_piubf_vals), 0x03,
			"Specifies whether this frame contains a single PIU or multiple PIUs." }},

                { &hf_sna_th_iern,
                { "Initial Explicit Route Number",	"sna.th.iern", FT_UINT8, BASE_DEC, NULL, 0xf0,
			"" }},

                { &hf_sna_th_nlpoi,
                { "NLP Offset Indicator",	"sna.th.nlpoi", FT_UINT8, BASE_DEC,
			VALS(sna_th_nlpoi_vals), 0x80,
			"" }},

                { &hf_sna_th_nlp_cp,
                { "NLP Count or Padding",	"sna.th.nlp_cp", FT_UINT8, BASE_DEC, NULL, 0x70,
			"" }},

                { &hf_sna_th_ern,
                { "Explicit Route Number",	"sna.th.ern", FT_UINT8, BASE_DEC, NULL, 0x0f,
			"The ERN in a TH identifies an explicit route direction of flow." }},

                { &hf_sna_th_vrn,
                { "Virtual Route Number",	"sna.th.vrn", FT_UINT8, BASE_DEC, NULL, 0xf0,
			"" }},

                { &hf_sna_th_tpf,
                { "Transmission Priority Field",	"sna.th.tpf", FT_UINT8, BASE_HEX,
			VALS(sna_th_tpf_vals), 0x03,
			"" }},

                { &hf_sna_th_vr_cwi,
                { "Virtual Route Change Window Indicator",	"sna.th.vr_cwi", FT_UINT16, BASE_DEC,
			VALS(sna_th_vr_cwi_vals), 0x8000,
			"Used to change the window size of the virtual route by 1." }},

                { &hf_sna_th_tg_nonfifo_ind,
                { "Transmission Group Non-FIFO Indicator",	"sna.th.tg_nonfifo_ind", FT_BOOLEAN, 16,
			TFS(&sna_th_tg_nonfifo_ind_truth), 0x4000,
			"Indicates whether or not FIFO discipline is to enforced in "
			"transmitting PIUs through the tranmission groups to prevent the PIUs "
			"getting out of sequence during transmission over the TGs." }},

                { &hf_sna_th_vr_sqti,
                { "Virtual Route Sequence and Type Indicator",	"sna.th.vr_sqti", FT_UINT16, BASE_HEX,
			VALS(sna_th_vr_sqti_vals), 0x3000,
			"Specifies the PIU type." }},

                { &hf_sna_th_tg_snf,
                { "Transmission Group Sequence Number Field",	"sna.th.tg_snf", FT_UINT16, BASE_DEC,
			NULL, 0x0fff,
			"" }},

                { &hf_sna_th_vrprq,
                { "Virtual Route Pacing Request",	"sna.th.vrprq", FT_BOOLEAN, 16,
			TFS(&sna_th_vrprq_truth), 0x8000,
			"" }},

                { &hf_sna_th_vrprs,
                { "Virtual Route Pacing Response",	"sna.th.vrprs", FT_BOOLEAN, 16,
			TFS(&sna_th_vrprs_truth), 0x4000,
			"" }},

                { &hf_sna_th_vr_cwri,
                { "Virtual Route Change Window Reply Indicator",	"sna.th.vr_cwri", FT_UINT16, BASE_DEC,
			VALS(sna_th_vr_cwri_vals), 0x2000,
			"Permits changing of the window size by 1 for PIUs received by the "
			"sender of this bit." }},

                { &hf_sna_th_vr_rwi,
                { "Virtual Route Reset Window Indicator",	"sna.th.vr_rwi", FT_BOOLEAN, 16,
			TFS(&sna_th_vr_rwi_truth), 0x1000,
			"Indicates severe congestion in a node on the virtual route." }},

                { &hf_sna_th_vr_snf_send,
                { "Virtual Route Send Sequence Number Field",	"sna.th.vr_snf_send", FT_UINT16, BASE_DEC,
			NULL, 0x0fff,
			"" }},

                { &hf_sna_th_dsaf,
                { "Destination Subarea Address Field",	"sna.th.dsaf", FT_UINT32, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_th_osaf,
                { "Origin Subarea Address Field",	"sna.th.osaf", FT_UINT32, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_th_snai,
                { "SNA Indicator",	"sna.th.snai", FT_BOOLEAN, 8, NULL, 0x10,
			"Used to identify whether the PIU originated or is destined for "
			"an SNA or non-SNA device." }},

                { &hf_sna_th_def,
                { "Destination Element Field",	"sna.th.def", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_th_oef,
                { "Origin Element Field",	"sna.th.oef", FT_UINT16, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_th_sa,
                { "Session Address",	"sna.th.sa", FT_BYTES, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_th_cmd_fmt,
                { "Command Format",	"sna.th.cmd_fmt", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_th_cmd_type,
                { "Command Type",	"sna.th.cmd_type", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_th_cmd_sn,
                { "Command Sequence Number",	"sna.th.cmd_sn", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},


                { &hf_sna_rh,
                { "Request/Response Header",	"sna.rh", FT_NONE, BASE_NONE, NULL, 0x0,
			"" }},

                { &hf_sna_rh_0,
                { "Request/Response Header Byte 0",	"sna.rh.0", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_rh_1,
                { "Request/Response Header Byte 1",	"sna.rh.1", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_rh_2,
                { "Request/Response Header Byte 2",	"sna.rh.2", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

                { &hf_sna_rh_rri,
                { "Request/Response Indicator",	"sna.rh.rri", FT_UINT8, BASE_DEC, VALS(sna_rh_rri_vals), 0x80,
			"Denotes whether this is a request or a response." }},

                { &hf_sna_rh_ru_category,
                { "Request/Response Unit Category",	"sna.rh.ru_category", FT_UINT8, BASE_HEX,
			VALS(sna_rh_ru_category_vals), 0x60,
			"" }},

		{ &hf_sna_rh_fi,
		{ "Format Indicator",		"sna.rh.fi", FT_BOOLEAN, 8, TFS(&sna_rh_fi_truth), 0x08,
			"" }},

		{ &hf_sna_rh_sdi,
		{ "Sense Data Included",	"sna.rh.sdi", FT_BOOLEAN, 8, TFS(&sna_rh_sdi_truth), 0x04,
			"Indicates that a 4-byte sense data field is included in the associated RU." }},

		{ &hf_sna_rh_bci,
		{ "Begin Chain Indicator",	"sna.rh.bci", FT_BOOLEAN, 8, TFS(&sna_rh_bci_truth), 0x02,
			"" }},

		{ &hf_sna_rh_eci,
		{ "End Chain Indicator",	"sna.rh.eci", FT_BOOLEAN, 8, TFS(&sna_rh_eci_truth), 0x01,
			"" }},

		{ &hf_sna_rh_dr1,
		{ "Definite Response 1 Indicator",	"sna.rh.dr1", FT_BOOLEAN, 8, NULL, 0x80,
			"" }},

		{ &hf_sna_rh_lcci,
		{ "Length-Checked Compression Indicator",	"sna.rh.lcci", FT_BOOLEAN, 8,
			TFS(&sna_rh_lcci_truth), 0x40,
			"" }},

		{ &hf_sna_rh_dr2,
		{ "Definite Response 2 Indicator",	"sna.rh.dr2", FT_BOOLEAN, 8, NULL, 0x20,
			"" }},

		{ &hf_sna_rh_eri,
		{ "Exception Response Indicator",	"sna.rh.eri", FT_BOOLEAN, 8, NULL, 0x10,
			"Used in conjunction with DR1I and DR2I to indicate, in a request, "
			"the form of response requested." }},

		{ &hf_sna_rh_rti,
		{ "Response Type Indicator",	"sna.rh.rti", FT_BOOLEAN, 8, TFS(&sna_rh_rti_truth), 0x10,
			"" }},

		{ &hf_sna_rh_rlwi,
		{ "Request Larger Window Indicator",	"sna.rh.rlwi", FT_BOOLEAN, 8, NULL, 0x04,
			"Indicates whether a larger pacing window was requested." }},

		{ &hf_sna_rh_qri,
		{ "Queued Response Indicator",	"sna.rh.qri", FT_BOOLEAN, 8, TFS(&sna_rh_qri_truth), 0x02,
			"" }},

		{ &hf_sna_rh_pi,
		{ "Pacing Indicator",	"sna.rh.pi", FT_BOOLEAN, 8, NULL, 0x01,
			"" }},

		{ &hf_sna_rh_bbi,
		{ "Begin Bracket Indicator",	"sna.rh.bbi", FT_BOOLEAN, 8, NULL, 0x80,
			"" }},

		{ &hf_sna_rh_ebi,
		{ "End Bracket Indicator",	"sna.rh.ebi", FT_BOOLEAN, 8, NULL, 0x40,
			"" }},

		{ &hf_sna_rh_cdi,
		{ "Change Direction Indicator",	"sna.rh.cdi", FT_BOOLEAN, 8, NULL, 0x20,
			"" }},

		{ &hf_sna_rh_csi,
		{ "Code Selection Indicator",	"sna.rh.csi", FT_BOOLEAN, 8, VALS(sna_rh_csi_vals), 0x08,
			"Specifies the encoding used for the associated FMD RU." }},

		{ &hf_sna_rh_edi,
		{ "Enciphered Data Indicator",	"sna.rh.edi", FT_BOOLEAN, 8, NULL, 0x04,
			"Indicates that information in the associated RU is enciphered under "
			"session-level cryptography protocols." }},

		{ &hf_sna_rh_pdi,
		{ "Padded Data Indicator",	"sna.rh.pdi", FT_BOOLEAN, 8, NULL, 0x02,
			"Indicates that the RU was padded at the end, before encipherment, to the next "
			"integral multiple of 8 bytes." }},

		{ &hf_sna_rh_cebi,
		{ "Conditional End Bracket Indicator",	"sna.rh.cebi", FT_BOOLEAN, 8, NULL, 0x01,
			"Used to indicate the beginning or end of a group of exchanged "
			"requests and responses called a bracket. Only used on LU-LU sessions." }},

                { &hf_sna_ru,
                { "Request/Response Unit",	"sna.ru", FT_NONE, BASE_NONE, NULL, 0x0,
			""}},
        };

        proto_sna = proto_register_protocol("Systems Network Architecture", "sna");
	proto_register_field_array(proto_sna, hf, array_length(hf));
}

