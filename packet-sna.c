/* packet-sna.c
 * Routines for SNA
 * Gilbert Ramirez <gram@xiexie.org>
 *
 * $Id: packet-sna.c,v 1.1 1999/10/12 06:20:17 gram Exp $
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
	{ 0x1,	"Subarea Node <--> Subarea Node" },
	{ 0x2,	"Subarea Node <--> PU2" },
	{ 0x3,	"Subarea Node or SNA host <--> Subarea Node" },
	{ 0x4,	"?" },
	{ 0x5,	"?" },
	{ 0xf,	"Adjaced Subarea Nodes" },
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

static int  dissect_fid0_1 (const u_char*, int, frame_data*, proto_tree*);
static int  dissect_fid2 (const u_char*, int, frame_data*, proto_tree*);
static int  dissect_fid3 (const u_char*, int, frame_data*, proto_tree*);
static void dissect_rh (const u_char*, int, frame_data*, proto_tree*);

void
dissect_sna(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	proto_tree	*sna_tree = NULL, *th_tree = NULL, *rh_tree = NULL;
	proto_item	*sna_ti, *th_ti, *rh_ti;
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
			default:
				dissect_data(pd, offset+1, fd, tree);
		}

		sna_header_len += th_header_len;
		offset += th_header_len;

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

	if (check_col(fd, COL_RES_DL_DST))
		col_add_fstr(fd, COL_RES_DL_DST, "%02X", daf);
	if (check_col(fd, COL_RES_DL_SRC))
		col_add_fstr(fd, COL_RES_DL_SRC, "%02X", oaf);

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

	snf = pntohs(&pd[offset+4]);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_item(tree, hf_sna_th_0, offset, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ETT_SNA_TH_FID);

	proto_tree_add_item(bf_tree, hf_sna_th_fid, offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_mpf, offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_odai ,offset, 1, th_0);
	proto_tree_add_item(bf_tree, hf_sna_th_efi ,offset, 1, th_0);

	proto_tree_add_text(tree, offset+1, 1, "Reserved");
	proto_tree_add_item(tree, hf_sna_th_daf ,offset+2, 1, daf);
	proto_tree_add_item(tree, hf_sna_th_oaf ,offset+3, 1, oaf);
	proto_tree_add_item(tree, hf_sna_th_snf ,offset+4, 2, snf);

	if (check_col(fd, COL_RES_DL_DST))
		col_add_fstr(fd, COL_RES_DL_DST, "%02X", daf);
	if (check_col(fd, COL_RES_DL_SRC))
		col_add_fstr(fd, COL_RES_DL_SRC, "%02X", oaf);

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
	if (is_response) {
		proto_tree_add_item(bf_tree, hf_sna_rh_bci, offset, 1, rh_0);
		proto_tree_add_item(bf_tree, hf_sna_rh_eci, offset, 1, rh_0);
	}

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

