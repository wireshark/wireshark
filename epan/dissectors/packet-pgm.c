/* packet-pgm.c
 * Routines for PGM packet disassembly, RFC 3208
 *
 * $Id$
 *
 * Copyright (c) 2000 by Talarian Corp
 * Rewritten by Jaap Keuter
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/afn.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/emem.h>
#include <epan/ptvcursor.h>

/*
 * Flag to control whether to check the PGM checksum.
 */
static gboolean pgm_check_checksum = TRUE;

void proto_reg_handoff_pgm(void);
static void proto_rereg_pgm(void);

/* constants for hdr types */
#define PGM_SPM_PCKT  0x00
#define PGM_ODATA_PCKT  0x04
#define PGM_RDATA_PCKT  0x05
#define PGM_NAK_PCKT  0x08
#define PGM_NNAK_PCKT  0x09
#define PGM_NCF_PCKT 0x0A
#define PGM_POLL_PCKT 0x01
#define PGM_POLR_PCKT 0x02
#define PGM_ACK_PCKT 0x0D

/* option flags (main PGM header) */
#define PGM_OPT 0x01
#define PGM_OPT_NETSIG 0x02
#define PGM_OPT_VAR_PKTLEN 0x40
#define PGM_OPT_PARITY 0x80

/* option types */
#define PGM_OPT_LENGTH 0x00
#define PGM_OPT_END 0x80
#define PGM_OPT_FRAGMENT 0x01
#define PGM_OPT_NAK_LIST 0x02
#define PGM_OPT_JOIN 0x03
#define PGM_OPT_REDIRECT 0x07
#define PGM_OPT_SYN 0x0D
#define PGM_OPT_FIN 0x0E
#define PGM_OPT_RST 0x0F
#define PGM_OPT_PARITY_PRM 0x08
#define PGM_OPT_PARITY_GRP 0x09
#define PGM_OPT_CURR_TGSIZE 0x0A
#define PGM_OPT_PGMCC_DATA  0x12
#define PGM_OPT_PGMCC_FEEDBACK  0x13
#define PGM_OPT_NAK_BO_IVL 0x04
#define PGM_OPT_NAK_BO_RNG 0x05

/* POLL subtypes */
#define PGM_POLL_GENERAL 0x0
#define PGM_POLL_DLR 0x1

/* OPX bit values */
#define PGM_OPX_IGNORE	0x00
#define PGM_OPX_INVAL	0x01
#define PGM_OPX_DISCARD	0x10

#define PGM_OPT_NAK_LIST_SIZE 4

/*
 * To squeeze the whole option into 255 bytes, we
 * can only have 62 in the list
 */
#define PGM_MAX_NAK_LIST_SZ (62)

#define PGM_OPT_JOIN_SIZE 8
#define PGM_OPT_PARITY_PRM_SIZE 8

/* OPT_PARITY_PRM P and O bits */
#define PGM_OPT_PARITY_PRM_PRO 0x2
#define PGM_OPT_PARITY_PRM_OND 0x1

#define PGM_OPT_PARITY_GRP_SIZE 8
#define PGM_OPT_CURR_TGSIZE_SIZE 8
#define PGM_OPT_PGMCC_DATA_SIZE 16
#define PGM_OPT_PGMCC_FEEDBACK_SIZE 16
#define PGM_OPT_NAK_BO_IVL_SIZE 12
#define PGM_OPT_NAK_BO_RNG_SIZE 12
#define PGM_OPT_REDIRECT_SIZE 12
#define PGM_OPT_FRAGMENT_SIZE 16

/*
 * Udp port for UDP encapsulation
 */
#define DEFAULT_UDP_ENCAP_UCAST_PORT 3055
#define DEFAULT_UDP_ENCAP_MCAST_PORT 3056

static guint udp_encap_ucast_port = 0;
static guint udp_encap_mcast_port = 0;
static guint old_encap_ucast_port = 0;
static guint old_encap_mcast_port = 0;

static int proto_pgm = -1;
static int ett_pgm = -1;
static int ett_pgm_optbits = -1;
static int ett_pgm_opts = -1;
static int ett_pgm_spm = -1;
static int ett_pgm_data = -1;
static int ett_pgm_nak = -1;
static int ett_pgm_poll = -1;
static int ett_pgm_polr = -1;
static int ett_pgm_ack = -1;
static int ett_pgm_opts_join = -1;
static int ett_pgm_opts_parityprm = -1;
static int ett_pgm_opts_paritygrp = -1;
static int ett_pgm_opts_naklist = -1;
static int ett_pgm_opts_ccdata = -1;
static int ett_pgm_opts_nak_bo_ivl = -1;
static int ett_pgm_opts_nak_bo_rng = -1;
static int ett_pgm_opts_redirect = -1;
static int ett_pgm_opts_fragment = -1;

static int hf_pgm_main_sport = -1;
static int hf_pgm_main_dport = -1;
static int hf_pgm_port = -1;
static int hf_pgm_main_type = -1;
static int hf_pgm_main_opts = -1;
static int hf_pgm_main_opts_opt = -1;
static int hf_pgm_main_opts_netsig = -1;
static int hf_pgm_main_opts_varlen = -1;
static int hf_pgm_main_opts_parity = -1;
static int hf_pgm_main_cksum = -1;
static int hf_pgm_main_cksum_bad = -1;
static int hf_pgm_main_gsi = -1;
static int hf_pgm_main_tsdulen = -1;
static int hf_pgm_spm_sqn = -1;
static int hf_pgm_spm_lead = -1;
static int hf_pgm_spm_trail = -1;
static int hf_pgm_spm_pathafi = -1;
static int hf_pgm_spm_res = -1;
static int hf_pgm_spm_path = -1;
static int hf_pgm_spm_path6 = -1;
static int hf_pgm_data_sqn = -1;
static int hf_pgm_data_trail = -1;
static int hf_pgm_nak_sqn = -1;
static int hf_pgm_nak_srcafi = -1;
static int hf_pgm_nak_srcres = -1;
static int hf_pgm_nak_src = -1;
static int hf_pgm_nak_src6 = -1;
static int hf_pgm_nak_grpafi = -1;
static int hf_pgm_nak_grpres = -1;
static int hf_pgm_nak_grp = -1;
static int hf_pgm_nak_grp6 = -1;
static int hf_pgm_poll_sqn = -1;
static int hf_pgm_poll_round = -1;
static int hf_pgm_poll_subtype = -1;
static int hf_pgm_poll_pathafi = -1;
static int hf_pgm_poll_res = -1;
static int hf_pgm_poll_path = -1;
static int hf_pgm_poll_path6 = -1;
static int hf_pgm_poll_backoff_ivl = -1;
static int hf_pgm_poll_rand_str = -1;
static int hf_pgm_poll_matching_bmask = -1;
static int hf_pgm_polr_sqn = -1;
static int hf_pgm_polr_round = -1;
static int hf_pgm_polr_res = -1;
static int hf_pgm_ack_sqn = -1;
static int hf_pgm_ack_bitmap = -1;

static int hf_pgm_opt_type = -1;
static int hf_pgm_opt_len = -1;
static int hf_pgm_opt_tlen = -1;

static int hf_pgm_genopt_type = -1;
static int hf_pgm_genopt_len = -1;
static int hf_pgm_genopt_opx = -1;

static int hf_pgm_opt_join_res = -1;
static int hf_pgm_opt_join_minjoin = -1;

static int hf_pgm_opt_parity_prm_po = -1;
static int hf_pgm_opt_parity_prm_prmtgsz = -1;

static int hf_pgm_opt_parity_grp_res = -1;
static int hf_pgm_opt_parity_grp_prmgrp = -1;

static int hf_pgm_opt_nak_res = -1;
static int hf_pgm_opt_nak_list = -1;

static int hf_pgm_opt_ccdata_res = -1;
static int hf_pgm_opt_ccdata_tsp = -1;
static int hf_pgm_opt_ccdata_afi = -1;
static int hf_pgm_opt_ccdata_res2 = -1;
static int hf_pgm_opt_ccdata_acker = -1;
static int hf_pgm_opt_ccdata_acker6 = -1;

static int hf_pgm_opt_ccfeedbk_res = -1;
static int hf_pgm_opt_ccfeedbk_tsp = -1;
static int hf_pgm_opt_ccfeedbk_afi = -1;
static int hf_pgm_opt_ccfeedbk_lossrate = -1;
static int hf_pgm_opt_ccfeedbk_acker = -1;
static int hf_pgm_opt_ccfeedbk_acker6 = -1;

static int hf_pgm_opt_nak_bo_ivl_res = -1;
static int hf_pgm_opt_nak_bo_ivl_bo_ivl = -1;
static int hf_pgm_opt_nak_bo_ivl_bo_ivl_sqn = -1;

static int hf_pgm_opt_nak_bo_rng_res = -1;
static int hf_pgm_opt_nak_bo_rng_min_bo_ivl = -1;
static int hf_pgm_opt_nak_bo_rng_max_bo_ivl = -1;

static int hf_pgm_opt_redirect_res = -1;
static int hf_pgm_opt_redirect_afi = -1;
static int hf_pgm_opt_redirect_res2 = -1;
static int hf_pgm_opt_redirect_dlr = -1;
static int hf_pgm_opt_redirect_dlr6 = -1;

static int hf_pgm_opt_fragment_res = -1;
static int hf_pgm_opt_fragment_first_sqn = -1;
static int hf_pgm_opt_fragment_offset = -1;
static int hf_pgm_opt_fragment_total_length = -1;

static dissector_table_t subdissector_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;


static const char *
optsstr(guint8 opts)
{
	char *msg;
	size_t returned_length, index = 0;
	const int MAX_STR_LEN = 256;

	if (opts == 0)
		return("");

	msg=ep_alloc(MAX_STR_LEN);
	if (opts & PGM_OPT){
		returned_length = g_snprintf(&msg[index], MAX_STR_LEN-index, "Present");
		index += MIN(returned_length, MAX_STR_LEN-index);
	}
	if (opts & PGM_OPT_NETSIG){
		returned_length = g_snprintf(&msg[index], MAX_STR_LEN-index, "%sNetSig", (!index)?"":",");
		index += MIN(returned_length, MAX_STR_LEN-index);
	}
	if (opts & PGM_OPT_VAR_PKTLEN){
		returned_length = g_snprintf(&msg[index], MAX_STR_LEN-index, "%sVarLen", (!index)?"":",");
		index += MIN(returned_length, MAX_STR_LEN-index);
	}
	if (opts & PGM_OPT_PARITY){
		returned_length = g_snprintf(&msg[index], MAX_STR_LEN-index, "%sParity", (!index)?"":",");
		index += MIN(returned_length, MAX_STR_LEN-index);
	}
	if (!index) {
		g_snprintf(&msg[index], MAX_STR_LEN-index, "0x%x", opts);
	}
	return(msg);
}
static const char *
paritystr(guint8 parity)
{
	char *msg;
	size_t returned_length, index = 0;
	const int MAX_STR_LEN = 256;

	if (parity == 0)
		return("");

	msg=ep_alloc(MAX_STR_LEN);
	if (parity & PGM_OPT_PARITY_PRM_PRO){
		returned_length = g_snprintf(&msg[index], MAX_STR_LEN-index, "Pro-active");
		index += MIN(returned_length, MAX_STR_LEN-index);
	}
	if (parity & PGM_OPT_PARITY_PRM_OND){
		returned_length = g_snprintf(&msg[index], MAX_STR_LEN-index, "%sOn-demand", (!index)?"":",");
		index += MIN(returned_length, MAX_STR_LEN-index);
	}
	if (!index) {
		g_snprintf(&msg[index], MAX_STR_LEN-index, "0x%x", parity);
	}
	return(msg);
}

static const value_string opt_vals[] = {
	{ PGM_OPT_LENGTH,      "Length" },
	{ PGM_OPT_END,         "End" },
	{ PGM_OPT_FRAGMENT,    "Fragment" },
	{ PGM_OPT_NAK_LIST,    "NakList" },
	{ PGM_OPT_JOIN,        "Join" },
	{ PGM_OPT_REDIRECT,    "ReDirect" },
	{ PGM_OPT_SYN,         "Syn" },
	{ PGM_OPT_FIN,         "Fin" },
	{ PGM_OPT_RST,         "Rst" },
	{ PGM_OPT_PARITY_PRM,  "ParityPrm" },
	{ PGM_OPT_PARITY_GRP,  "ParityGrp" },
	{ PGM_OPT_CURR_TGSIZE, "CurrTgsiz" },
	{ PGM_OPT_PGMCC_DATA,  "CcData" },
	{ PGM_OPT_PGMCC_FEEDBACK, "CcFeedBack" },
	{ PGM_OPT_NAK_BO_IVL,  "NakBackOffIvl" },
	{ PGM_OPT_NAK_BO_RNG,  "NakBackOffRng" },
	{ PGM_OPT_FRAGMENT,    "Fragment" },
	{ 0,                   NULL }
};

static const value_string opx_vals[] = {
	{ PGM_OPX_IGNORE,  "Ignore" },
	{ PGM_OPX_INVAL,   "Inval" },
	{ PGM_OPX_DISCARD, "DisCard" },
	{ 0,               NULL }
};

static const true_false_string opts_present = {
	"Present",
	"Not Present"
};

static void
dissect_pgmopts(ptvcursor_t* cursor, const char *pktname)
{
	proto_item *tf;
	proto_tree *opts_tree = NULL;
	proto_tree *opt_tree = NULL;
	tvbuff_t *tvb = ptvcursor_tvbuff(cursor);

	gboolean theend = FALSE;

	guint16 opts_total_len;
	guint8 genopts_type;
	guint8 genopts_len;
	guint8 opts_type = tvb_get_guint8(tvb, ptvcursor_current_offset(cursor));

	if (opts_type != PGM_OPT_LENGTH) {
		proto_tree_add_text(ptvcursor_tree(cursor), tvb, ptvcursor_current_offset(cursor), 1,
		    "%s Options - initial option is %s, should be %s",
		    pktname,
		    val_to_str(opts_type, opt_vals, "Unknown (0x%02x)"),
		    val_to_str(PGM_OPT_LENGTH, opt_vals, "Unknown (0x%02x)"));
		return;
	}

	opts_total_len = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor)+2);
	
	if (opts_total_len < 4) {
		proto_tree_add_text(opts_tree, tvb, ptvcursor_current_offset(cursor)+2, 2,
			"%s Options (Total Length %u - invalid, must be >= 4)",
			pktname, opts_total_len);
		return;
	}
	
	tf = proto_tree_add_text(ptvcursor_tree(cursor), tvb, ptvcursor_current_offset(cursor), opts_total_len,
		"%s Options (Total Length %d)", pktname, opts_total_len);
	opts_tree = proto_item_add_subtree(tf, ett_pgm_opts);
	ptvcursor_set_tree(cursor, opts_tree);
	ptvcursor_add(cursor, hf_pgm_opt_type, 1, FALSE);
	ptvcursor_add(cursor, hf_pgm_opt_len, 1, FALSE);
	ptvcursor_add(cursor, hf_pgm_opt_tlen, 2, FALSE);

	for (opts_total_len -= 4; !theend && opts_total_len != 0;){
		if (opts_total_len < 4) {
			proto_tree_add_text(opts_tree, tvb, ptvcursor_current_offset(cursor), opts_total_len,
			    "Remaining total options length doesn't have enough for an options header");
			break;
		}

		genopts_type = tvb_get_guint8(tvb, ptvcursor_current_offset(cursor));
		genopts_len = tvb_get_guint8(tvb, ptvcursor_current_offset(cursor)+1);

		if (genopts_type & PGM_OPT_END)  {
			genopts_type &= ~PGM_OPT_END;
			theend = TRUE;
		}
		if (genopts_len < 4) {
			proto_tree_add_text(opts_tree, tvb, ptvcursor_current_offset(cursor), genopts_len,
				"Option: %s, Length: %u (invalid, must be >= 4)",
				val_to_str(genopts_type, opt_vals, "Unknown (0x%02x)"),
				genopts_len);
			break;
		}
		if (opts_total_len < genopts_len) {
			proto_tree_add_text(opts_tree, tvb, ptvcursor_current_offset(cursor), genopts_len,
			    "Option: %s, Length: %u (> remaining total options length)",
			    val_to_str(genopts_type, opt_vals, "Unknown (0x%02x)"),
			    genopts_len);
			break;
		}
		tf = proto_tree_add_text(opts_tree, tvb, ptvcursor_current_offset(cursor), genopts_len,
			"Option: %s, Length: %u",
			val_to_str(genopts_type, opt_vals, "Unknown (0x%02x)"),
			genopts_len);

		switch(genopts_type) {
		case PGM_OPT_JOIN:{
			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_join);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, FALSE);

			if (genopts_len < PGM_OPT_JOIN_SIZE) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"Length: %u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_JOIN_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_join_res, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_join_minjoin, 4, FALSE);

			break;
		}
		case PGM_OPT_PARITY_PRM:{
			guint8 optdata_po;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_parityprm);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, FALSE);
			
			if (genopts_len < PGM_OPT_PARITY_PRM_SIZE) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, ptvcursor_tvbuff(cursor),
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"Length: %u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_PARITY_PRM_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, FALSE);
			optdata_po = tvb_get_guint8(tvb, ptvcursor_current_offset(cursor));
			proto_tree_add_uint_format(opt_tree, hf_pgm_opt_parity_prm_po, tvb,
				ptvcursor_current_offset(cursor), 1, optdata_po, "Parity Parameters: %s (0x%x)",
				paritystr(optdata_po), optdata_po);
			ptvcursor_advance(cursor, 1);

			ptvcursor_add(cursor, hf_pgm_opt_parity_prm_prmtgsz, 4, FALSE);

			break;
		}
		case PGM_OPT_PARITY_GRP:{
			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_paritygrp);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, FALSE);

			if (genopts_len < PGM_OPT_PARITY_GRP_SIZE) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"Length: %u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_PARITY_GRP_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_parity_grp_res, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_parity_grp_prmgrp, 4, FALSE);

			break;
		}
		case PGM_OPT_NAK_LIST:{
			guint8 optdata_len;
			guint32 naklist[PGM_MAX_NAK_LIST_SZ+1];
			unsigned char *nakbuf;
			gboolean firsttime;
			int i, j, naks, soffset;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_naklist);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, FALSE);
			
			if (genopts_len < PGM_OPT_NAK_LIST_SIZE) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"Length: %u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_NAK_LIST_SIZE);
				break;
			}
			optdata_len = tvb_get_guint8(tvb, ptvcursor_current_offset(cursor));
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_nak_res, 1, FALSE);
			
			optdata_len -= PGM_OPT_NAK_LIST_SIZE;
			tvb_memcpy(tvb, (guint8 *)naklist, ptvcursor_current_offset(cursor), optdata_len);
			firsttime = TRUE;
			soffset = 0;
			naks = (optdata_len/sizeof(guint32));
			nakbuf = ep_alloc(8192);
			j = 0;
			/*
			 * Print out 8 per line
			 */
			for (i=0; i < naks; i++) {
				soffset += MIN(8192-soffset,
					g_snprintf(nakbuf+soffset, 8192-soffset, "0x%lx ",
						(unsigned long)g_ntohl(naklist[i])));
				if ((++j % 8) == 0) {
					if (firsttime) {
						proto_tree_add_bytes_format(opt_tree,
							hf_pgm_opt_nak_list, tvb, ptvcursor_current_offset(cursor), j*4,
							nakbuf, "List(%d): %s", naks, nakbuf);
						soffset = 0;
						firsttime = FALSE;
					} else {
						proto_tree_add_bytes_format(opt_tree,
							hf_pgm_opt_nak_list, tvb, ptvcursor_current_offset(cursor), j*4,
							nakbuf, "List: %s", nakbuf);
						soffset = 0;
					}
					ptvcursor_advance(cursor, j*4);
					j = 0;
				}
			}
			if (j) {
				if (firsttime) {
					proto_tree_add_bytes_format(opt_tree,
						hf_pgm_opt_nak_list, tvb, ptvcursor_current_offset(cursor), j*4,
						nakbuf, "List(%d): %s", naks, nakbuf);
				} else {
					proto_tree_add_bytes_format(opt_tree,
						hf_pgm_opt_nak_list, tvb, ptvcursor_current_offset(cursor), j*4,
						nakbuf, "List: %s", nakbuf);
				}
				ptvcursor_advance(cursor, j*4);
			}
			break;
		}
		case PGM_OPT_PGMCC_DATA:{
			guint16 optdata_afi;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_ccdata);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, FALSE);

			if (genopts_len < PGM_OPT_PGMCC_DATA_SIZE) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"Length: %u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_PGMCC_DATA_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_ccdata_res, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_ccdata_tsp, 4, FALSE);
			optdata_afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
			ptvcursor_add(cursor, hf_pgm_opt_ccdata_afi, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_ccdata_res2, 1, FALSE);

			switch (optdata_afi) {

			case AFNUM_INET:
				ptvcursor_add(cursor, hf_pgm_opt_ccdata_acker, 4, FALSE);
				break;

			case AFNUM_INET6:
				ptvcursor_add(cursor, hf_pgm_opt_ccdata_acker6, 16, FALSE);
				break;

			default:
				proto_tree_add_text(opt_tree, tvb, ptvcursor_current_offset(cursor), -1, 
				    "Can't handle this address format");
				break;
			}

			break;
		}
		case PGM_OPT_PGMCC_FEEDBACK:{
			guint16 optdata_afi;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_ccdata);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, FALSE);

			if (genopts_len < PGM_OPT_PGMCC_FEEDBACK_SIZE) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"Length: %u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_PGMCC_FEEDBACK_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_res, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_tsp, 4, FALSE);
			optdata_afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
			ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_afi, 2, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_lossrate, 2, FALSE);

			switch (optdata_afi) {

			case AFNUM_INET:
				ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_acker, 4, FALSE);
				break;

			case AFNUM_INET6:
				ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_acker6, 16, FALSE);
				break;

			default:
				proto_tree_add_text(opt_tree, tvb, ptvcursor_current_offset(cursor), -1,
				    "Can't handle this address format");
				break;
			}

			break;
		}
		case PGM_OPT_NAK_BO_IVL:{
			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_nak_bo_ivl);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, FALSE);

			if (genopts_len < PGM_OPT_NAK_BO_IVL_SIZE) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"Length: %u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_NAK_BO_IVL_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_ivl_res, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_ivl_bo_ivl, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_ivl_bo_ivl_sqn, 1, FALSE);

			break;
		}
		case PGM_OPT_NAK_BO_RNG:{
			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_nak_bo_rng);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, FALSE);

			if (genopts_len < PGM_OPT_NAK_BO_RNG_SIZE) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"Length: %u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_NAK_BO_RNG_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_rng_res, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_rng_min_bo_ivl, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_rng_max_bo_ivl, 4, FALSE);

			break;
		}
		case PGM_OPT_REDIRECT:{
			guint16 optdata_afi;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_redirect);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, FALSE);

			if (genopts_len < PGM_OPT_REDIRECT_SIZE) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"Length: %u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_REDIRECT_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_redirect_res, 1, FALSE);
			optdata_afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
			ptvcursor_add(cursor, hf_pgm_opt_redirect_afi, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_redirect_res2, 1, FALSE);

			switch (optdata_afi) {

			case AFNUM_INET:
				ptvcursor_add(cursor, hf_pgm_opt_redirect_dlr, 4, FALSE);
				break;

			case AFNUM_INET6:
				ptvcursor_add(cursor, hf_pgm_opt_redirect_dlr6, 16, FALSE);
				break;

			default:
				proto_tree_add_text(opt_tree, tvb, ptvcursor_current_offset(cursor), -1, 
				    "Can't handle this address format");
				break;
			}

			break;
		}
		case PGM_OPT_FRAGMENT:{
			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_fragment);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, FALSE);

			if (genopts_len < PGM_OPT_FRAGMENT_SIZE) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"Length: %u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_FRAGMENT_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_fragment_res, 1, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_fragment_first_sqn, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_fragment_offset, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_opt_fragment_total_length, 4, FALSE);

			break;
		}
		}

		opts_total_len -= genopts_len;
	}
	return;
}

static const value_string type_vals[] = {
	{ PGM_SPM_PCKT,   "SPM" },
	{ PGM_RDATA_PCKT, "RDATA" },
	{ PGM_ODATA_PCKT, "ODATA" },
	{ PGM_NAK_PCKT,   "NAK" },
	{ PGM_NNAK_PCKT,  "NNAK" },
	{ PGM_NCF_PCKT,   "NCF" },
	{ PGM_POLL_PCKT,  "POLL" },
	{ PGM_POLR_PCKT,  "POLR" },
	{ PGM_ACK_PCKT,   "ACK" },
	{ 0,              NULL }
};

static const value_string poll_subtype_vals[] = {
	{ PGM_POLL_GENERAL,   "General" },
	{ PGM_POLL_DLR,       "DLR" },
	{ 0,                  NULL }
};

/* Determine if there is a sub-dissector and call it.  This has been */
/* separated into a stand alone routine to other protocol dissectors */
/* can call to it, ie. socks	*/

static void
decode_pgm_ports(tvbuff_t *tvb, int offset, packet_info *pinfo,
	proto_tree *tree, guint16 pgmhdr_sport, guint16 pgmhdr_dport)
{
  tvbuff_t *next_tvb;
  int found = 0;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);

  /* do lookup with the subdissector table */
  found = dissector_try_port(subdissector_table, pgmhdr_sport,
			next_tvb, pinfo, tree);
  if (found)
	return;

  found = dissector_try_port(subdissector_table, pgmhdr_dport,
			next_tvb, pinfo, tree);
  if (found)
	return;

  /* do lookup with the heuristic subdissector table */
  if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree))
	return;

  /* Oh, well, we don't know this; dissect it as data. */
  call_dissector(data_handle,next_tvb, pinfo, tree);
}

/*
 * dissect_pgm - The dissector for Pragmatic General Multicast
 */
static void
dissect_pgm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint16 pgmhdr_sport;
	guint16 pgmhdr_dport;
	guint8 pgmhdr_type;
	guint8 pgmhdr_opts;
	guint16 pgmhdr_cksum;
	guint16 pgmhdr_tsdulen;
	guint32 sqn;
	guint16 afi;

	guint plen = 0;
	proto_item *ti;
	const char *pktname;
	const char *pollstname;
	char *gsi;
	gboolean isdata = FALSE;
	guint pgmlen, reportedlen;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PGM");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		if (tvb_reported_length_remaining(tvb, 0) < 18) {
			col_set_str(pinfo->cinfo, COL_INFO,
				"Packet too small");
			return;
		}
	}

	pinfo->srcport = pgmhdr_sport = tvb_get_ntohs(tvb, 0);
	pinfo->destport = pgmhdr_dport = tvb_get_ntohs(tvb, 2);

	pgmhdr_type = tvb_get_guint8(tvb, 4);
	pktname = val_to_str(pgmhdr_type, type_vals, "Unknown (0x%02x)");

	pgmhdr_opts = tvb_get_guint8(tvb, 5);
	pgmhdr_cksum = tvb_get_ntohs(tvb, 6);
	gsi = tvb_bytes_to_str(tvb, 8, 6);
	pgmhdr_tsdulen = tvb_get_ntohs(tvb, 14);
	sqn = tvb_get_ntohl(tvb, 16);

	switch(pgmhdr_type) {
	case PGM_SPM_PCKT:
	case PGM_NAK_PCKT:
	case PGM_NNAK_PCKT:
	case PGM_NCF_PCKT:
	case PGM_POLR_PCKT:
	case PGM_ACK_PCKT:
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"%-5s sqn 0x%x gsi %s", pktname, sqn, gsi);
		}
		break;
	case PGM_RDATA_PCKT:
	case PGM_ODATA_PCKT:
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "%-5s sqn 0x%x gsi %s tsdulen %d", pktname, sqn, gsi,
			    pgmhdr_tsdulen);
		}
		isdata = TRUE;
		break;
	case PGM_POLL_PCKT: {
		guint16 poll_stype = tvb_get_ntohs(tvb, 22);
		pollstname = val_to_str(poll_stype, poll_subtype_vals, "Unknown (0x%02x)");

		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"%-5s sqn 0x%x gsi %s subtype %s", 
					pktname, sqn, gsi, pollstname);
		}
		}
		break;
	default:
		return;
	}

	{
		proto_tree *pgm_tree = NULL;
		proto_tree *opt_tree = NULL;
		proto_tree *type_tree = NULL;
		proto_item *tf;
		ptvcursor_t* cursor;

		ti = proto_tree_add_protocol_format(tree, proto_pgm,
			tvb, 0, -1,
			"Pragmatic General Multicast: Type %s"
			    " Src Port %u, Dst Port %u, GSI %s", pktname,
			pgmhdr_sport, pgmhdr_dport, gsi);

		pgm_tree = proto_item_add_subtree(ti, ett_pgm);

		cursor = ptvcursor_new(pgm_tree, tvb, 0);

		proto_tree_add_item_hidden(pgm_tree, hf_pgm_port, tvb, 0, 2, FALSE);
		proto_tree_add_item_hidden(pgm_tree, hf_pgm_port, tvb, 2, 2, FALSE);
		ptvcursor_add(cursor, hf_pgm_main_sport, 2, FALSE);
		ptvcursor_add(cursor, hf_pgm_main_dport, 2, FALSE);
		ptvcursor_add(cursor, hf_pgm_main_type, 1, FALSE);

		tf = proto_tree_add_uint_format(pgm_tree, hf_pgm_main_opts, tvb,
			ptvcursor_current_offset(cursor), 1, pgmhdr_opts, "Options: %s (0x%x)",
			optsstr(pgmhdr_opts), pgmhdr_opts);
		opt_tree = proto_item_add_subtree(tf, ett_pgm_optbits);
		ptvcursor_set_tree(cursor, opt_tree);

		ptvcursor_add_no_advance(cursor, hf_pgm_main_opts_opt, 1, FALSE);
		ptvcursor_add_no_advance(cursor, hf_pgm_main_opts_netsig, 1, FALSE);
		ptvcursor_add_no_advance(cursor, hf_pgm_main_opts_varlen, 1, FALSE);
		ptvcursor_add(cursor, hf_pgm_main_opts_parity, 1, FALSE);
		ptvcursor_set_tree(cursor, pgm_tree);

		/* Checksum may be 0 (not available), but not for DATA packets */
		if ((pgmhdr_type != PGM_RDATA_PCKT) && (pgmhdr_type != PGM_ODATA_PCKT) && 
		    (pgmhdr_cksum == 0))
		{
			proto_tree_add_uint_format(pgm_tree, hf_pgm_main_cksum, tvb,
				ptvcursor_current_offset(cursor), 2, pgmhdr_cksum, "Checksum: not available");
		} else {
			reportedlen = tvb_reported_length(tvb);
			pgmlen = tvb_length(tvb);
			if (pgm_check_checksum && pgmlen >= reportedlen) {
				vec_t cksum_vec[1];
				guint16 computed_cksum;

				cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, pgmlen);
				cksum_vec[0].len = pgmlen;
				computed_cksum = in_cksum(&cksum_vec[0], 1);
				if (computed_cksum == 0) {
					proto_tree_add_uint_format(pgm_tree, hf_pgm_main_cksum, tvb,
						ptvcursor_current_offset(cursor), 2, pgmhdr_cksum, "Checksum: 0x%04x [correct]", pgmhdr_cksum);
				} else {
					proto_tree_add_boolean_hidden(pgm_tree, hf_pgm_main_cksum_bad, tvb,
					    ptvcursor_current_offset(cursor), 2, TRUE);
					proto_tree_add_uint_format(pgm_tree, hf_pgm_main_cksum, tvb,
					    ptvcursor_current_offset(cursor), 2, pgmhdr_cksum, "Checksum: 0x%04x [incorrect, should be 0x%04x]",
						pgmhdr_cksum, in_cksum_shouldbe(pgmhdr_cksum, computed_cksum));
				}
			} else {
				ptvcursor_add_no_advance(cursor, hf_pgm_main_cksum, 2, FALSE);
			}
		}
		ptvcursor_advance(cursor, 2);

		ptvcursor_add(cursor, hf_pgm_main_gsi, 6, FALSE);
		ptvcursor_add(cursor, hf_pgm_main_tsdulen, 2, FALSE);

		tf = proto_tree_add_text(pgm_tree, tvb, ptvcursor_current_offset(cursor), plen, "%s Packet", pktname);
		switch(pgmhdr_type) {
		case PGM_SPM_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_spm);
			ptvcursor_set_tree(cursor, type_tree);

			ptvcursor_add(cursor, hf_pgm_spm_sqn, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_spm_trail, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_spm_lead, 4, FALSE);
			afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
			ptvcursor_add(cursor, hf_pgm_spm_pathafi, 2, FALSE);
			ptvcursor_add(cursor, hf_pgm_spm_res, 2, FALSE);

			switch (afi) {
			case AFNUM_INET:
				ptvcursor_add(cursor, hf_pgm_spm_path, 4, FALSE);
				break;

			case AFNUM_INET6:
				ptvcursor_add(cursor, hf_pgm_spm_path6, 16, FALSE);
				break;

			default:
				proto_tree_add_text(type_tree, tvb, ptvcursor_current_offset(cursor), -1, 
				    "Can't handle this address format");
				return;
			}
			break;
		case PGM_RDATA_PCKT:
		case PGM_ODATA_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_data);
			ptvcursor_set_tree(cursor, type_tree);

			ptvcursor_add(cursor, hf_pgm_spm_sqn, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_spm_trail, 4, FALSE);
			break;
		case PGM_NAK_PCKT:
		case PGM_NNAK_PCKT:
		case PGM_NCF_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_nak);
			ptvcursor_set_tree(cursor, type_tree);

			ptvcursor_add(cursor, hf_pgm_nak_sqn, 4, FALSE);
			afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
			ptvcursor_add(cursor, hf_pgm_nak_srcafi, 2, FALSE);
			ptvcursor_add(cursor, hf_pgm_nak_srcres, 2, FALSE);

			switch (afi) {
			case AFNUM_INET:
				ptvcursor_add(cursor, hf_pgm_nak_src, 4, FALSE);
				break;

			case AFNUM_INET6:
				ptvcursor_add(cursor, hf_pgm_nak_src6, 16, FALSE);
				break;

			default:
				proto_tree_add_text(type_tree, tvb, ptvcursor_current_offset(cursor), -1, 
				    "Can't handle this address format");
				break;
			}

			afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
			ptvcursor_add(cursor, hf_pgm_nak_grpafi, 2, FALSE);
			ptvcursor_add(cursor, hf_pgm_nak_grpres, 2, FALSE);

			switch (afi) {
			case AFNUM_INET:
				ptvcursor_add(cursor, hf_pgm_nak_grp, 4, FALSE);
				break;

			case AFNUM_INET6:
				ptvcursor_add(cursor, hf_pgm_nak_grp6, 16, FALSE);
				break;

			default:
				proto_tree_add_text(type_tree, tvb, ptvcursor_current_offset(cursor), -1, 
				    "Can't handle this address format");
				return;
			}
			break;
		case PGM_POLL_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_poll);
			ptvcursor_set_tree(cursor, type_tree);

			ptvcursor_add(cursor, hf_pgm_poll_sqn, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_poll_round, 2, FALSE);
			ptvcursor_add(cursor, hf_pgm_poll_subtype, 2, FALSE);
			afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
			ptvcursor_add(cursor, hf_pgm_poll_pathafi, 2, FALSE);
			ptvcursor_add(cursor, hf_pgm_poll_res, 2, FALSE);

			switch (afi) {
			case AFNUM_INET:
				ptvcursor_add(cursor, hf_pgm_poll_path, 4, FALSE);
				break;

			case AFNUM_INET6:
				ptvcursor_add(cursor, hf_pgm_poll_path6, 16, FALSE);
				break;

			default:
				proto_tree_add_text(type_tree, tvb, ptvcursor_current_offset(cursor), -1, 
				    "Can't handle this address format");
				break;
			}

			ptvcursor_add(cursor, hf_pgm_poll_backoff_ivl, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_poll_rand_str, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_poll_matching_bmask, 4, FALSE);
			break;
		case PGM_POLR_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_polr);
			ptvcursor_set_tree(cursor, type_tree);

			ptvcursor_add(cursor, hf_pgm_polr_sqn, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_polr_round, 2, FALSE);
			ptvcursor_add(cursor, hf_pgm_polr_res, 2, FALSE);
			break;
		case PGM_ACK_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_ack);
			ptvcursor_set_tree(cursor, type_tree);

			ptvcursor_add(cursor, hf_pgm_ack_sqn, 4, FALSE);
			ptvcursor_add(cursor, hf_pgm_ack_bitmap, 4, FALSE);
			break;
		}

		if (pgmhdr_opts & PGM_OPT)
			dissect_pgmopts(cursor, pktname);

		if (isdata) 
			decode_pgm_ports(tvb, ptvcursor_current_offset(cursor), pinfo, tree, pgmhdr_sport, pgmhdr_dport);
	}
}

/* Register all the bits needed with the filtering engine */
void
proto_register_pgm(void)
{
  static hf_register_info hf[] = {
    { &hf_pgm_main_sport,
      { "Source Port", "pgm.hdr.sport", FT_UINT16, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_main_dport,
      { "Destination Port", "pgm.hdr.dport", FT_UINT16, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_port,
      { "Port", "pgm.port", FT_UINT16, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_main_type,
      { "Type", "pgm.hdr.type", FT_UINT8, BASE_HEX,
	  VALS(type_vals), 0x0, "", HFILL }},
    { &hf_pgm_main_opts,
      { "Options", "pgm.hdr.opts", FT_UINT8, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_main_opts_opt,
      { "Options", "pgm.hdr.opts.opt", FT_BOOLEAN, 8,
	  TFS(&opts_present), PGM_OPT, "", HFILL }},
    { &hf_pgm_main_opts_netsig,
      { "Network Significant Options", "pgm.hdr.opts.netsig",
	  FT_BOOLEAN, 8,
	  TFS(&opts_present), PGM_OPT_NETSIG, "", HFILL }},
    { &hf_pgm_main_opts_varlen,
      { "Variable length Parity Packet Option", "pgm.hdr.opts.varlen",
	  FT_BOOLEAN, 8,
	  TFS(&opts_present), PGM_OPT_VAR_PKTLEN, "", HFILL }},
    { &hf_pgm_main_opts_parity,
      { "Parity", "pgm.hdr.opts.parity", FT_BOOLEAN, 8,
	  TFS(&opts_present), PGM_OPT_PARITY, "", HFILL }},
    { &hf_pgm_main_cksum,
      { "Checksum", "pgm.hdr.cksum", FT_UINT16, BASE_HEX,
        NULL, 0x0, "", HFILL }},
    { &hf_pgm_main_cksum_bad,
      { "Bad Checksum", "pgm.hdr.cksum_bad", FT_BOOLEAN, BASE_NONE,
        NULL, 0x0, "", HFILL }},
    { &hf_pgm_main_gsi,
      { "Global Source Identifier", "pgm.hdr.gsi", FT_BYTES, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_main_tsdulen,
      { "Transport Service Data Unit Length", "pgm.hdr.tsdulen", FT_UINT16,
	  BASE_DEC, NULL, 0x0, "", HFILL }},
    { &hf_pgm_spm_sqn,
      { "Sequence number", "pgm.spm.sqn", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_spm_trail,
      { "Trailing Edge Sequence Number", "pgm.spm.trail", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_spm_lead,
      { "Leading Edge Sequence Number", "pgm.spm.lead", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_spm_pathafi,
      { "Path NLA AFI", "pgm.spm.pathafi", FT_UINT16, BASE_DEC,
	  VALS(afn_vals), 0x0, "", HFILL }},
    { &hf_pgm_spm_res,
      { "Reserved", "pgm.spm.res", FT_UINT16, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_spm_path,
      { "Path NLA", "pgm.spm.path", FT_IPv4, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_spm_path6,
      { "Path NLA", "pgm.spm.path", FT_IPv6, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_data_sqn,
      { "Data Packet Sequence Number", "pgm.data.sqn", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_data_trail,
      { "Trailing Edge Sequence Number", "pgm.data.trail", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_nak_sqn,
      { "Requested Sequence Number", "pgm.nak.sqn", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_nak_srcafi,
      { "Source NLA AFI", "pgm.nak.srcafi", FT_UINT16, BASE_DEC,
	  VALS(afn_vals), 0x0, "", HFILL }},
    { &hf_pgm_nak_srcres,
      { "Reserved", "pgm.nak.srcres", FT_UINT16, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_nak_src,
      { "Source NLA", "pgm.nak.src", FT_IPv4, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_nak_src6,
      { "Source NLA", "pgm.nak.src", FT_IPv6, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_nak_grpafi,
      { "Multicast Group AFI", "pgm.nak.grpafi", FT_UINT16, BASE_DEC,
	  VALS(afn_vals), 0x0, "", HFILL }},
    { &hf_pgm_nak_grpres,
      { "Reserved", "pgm.nak.grpres", FT_UINT16, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_nak_grp,
      { "Multicast Group NLA", "pgm.nak.grp", FT_IPv4, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_nak_grp6,
      { "Multicast Group NLA", "pgm.nak.grp", FT_IPv6, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_poll_sqn,
      { "Sequence Number", "pgm.poll.sqn", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_poll_round,
      { "Round", "pgm.poll.round", FT_UINT16, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_poll_subtype,
      { "Subtype", "pgm.poll.subtype", FT_UINT16, BASE_HEX,
	  VALS(poll_subtype_vals), 0x0, "", HFILL }},
    { &hf_pgm_poll_pathafi,
      { "Path NLA AFI", "pgm.poll.pathafi", FT_UINT16, BASE_DEC,
	  VALS(afn_vals), 0x0, "", HFILL }},
    { &hf_pgm_poll_res,
      { "Reserved", "pgm.poll.res", FT_UINT16, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_poll_path,
      { "Path NLA", "pgm.poll.path", FT_IPv4, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_poll_path6,
      { "Path NLA", "pgm.poll.path", FT_IPv6, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_poll_backoff_ivl,
      { "Back-off Interval", "pgm.poll.backoff_ivl", FT_UINT32, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_poll_rand_str,
      { "Random String", "pgm.poll.rand_str", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_poll_matching_bmask,
      { "Matching Bitmask", "pgm.poll.matching_bmask", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_polr_sqn,
      { "Sequence Number", "pgm.polr.sqn", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_polr_round,
      { "Round", "pgm.polr.round", FT_UINT16, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_polr_res,
      { "Reserved", "pgm.polr.res", FT_UINT16, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_ack_sqn,
      { "Maximum Received Sequence Number", "pgm.ack.maxsqn", FT_UINT32,
	  BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pgm_ack_bitmap,
      { "Packet Bitmap", "pgm.ack.bitmap", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_type,
      { "Type", "pgm.opts.type", FT_UINT8, BASE_HEX,
          VALS(opt_vals), 0x0, "", HFILL }},
    { &hf_pgm_opt_len,
      { "Length", "pgm.opts.len", FT_UINT8, BASE_DEC,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_tlen,
      { "Total Length", "pgm.opts.tlen", FT_UINT16, BASE_DEC,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_genopt_type,
      { "Type", "pgm.genopts.type", FT_UINT8, BASE_HEX,
          VALS(opt_vals), 0x0, "", HFILL }},
    { &hf_pgm_genopt_len,
      { "Length", "pgm.genopts.len", FT_UINT8, BASE_DEC,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_genopt_opx,
      { "Option Extensibility Bits", "pgm.genopts.opx", FT_UINT8, BASE_HEX,
          VALS(opx_vals), 0x0, "", HFILL }},
    { &hf_pgm_opt_parity_prm_po,
      { "Parity Parameters", "pgm.opts.parity_prm.op", FT_UINT8, BASE_HEX,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_parity_prm_prmtgsz,
      { "Transmission Group Size", "pgm.opts.parity_prm.prm_grp",
          FT_UINT32, BASE_HEX,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_join_res,
      { "Reserved", "pgm.opts.join.res", FT_UINT8, BASE_HEX,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_join_minjoin,
      { "Minimum Sequence Number", "pgm.opts.join.min_join",
          FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_parity_grp_res,
      { "Reserved", "pgm.opts.parity_prm.op", FT_UINT8, BASE_HEX,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_parity_grp_prmgrp,
      { "Transmission Group Size", "pgm.opts.parity_prm.prm_grp",
          FT_UINT32, BASE_HEX,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_nak_res,
      { "Reserved", "pgm.opts.nak.op", FT_UINT8, BASE_HEX,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_nak_list,
      { "List", "pgm.opts.nak.list", FT_BYTES, BASE_NONE,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_ccdata_res,
      { "Reserved", "pgm.opts.ccdata.res", FT_UINT8, BASE_DEC,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_ccdata_tsp,
      { "Time Stamp", "pgm.opts.ccdata.tstamp", FT_UINT16, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_ccdata_afi,
      { "Acker AFI", "pgm.opts.ccdata.afi", FT_UINT16, BASE_DEC,
	  VALS(afn_vals), 0x0, "", HFILL }},
    { &hf_pgm_opt_ccdata_res2,
      { "Reserved", "pgm.opts.ccdata.res2", FT_UINT16, BASE_DEC,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_ccdata_acker,
      { "Acker", "pgm.opts.ccdata.acker", FT_IPv4, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_ccdata_acker6,
      { "Acker", "pgm.opts.ccdata.acker", FT_IPv6, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_ccfeedbk_res,
      { "Reserved", "pgm.opts.ccdata.res", FT_UINT8, BASE_DEC,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_ccfeedbk_tsp,
      { "Time Stamp", "pgm.opts.ccdata.tstamp", FT_UINT16, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_ccfeedbk_afi,
      { "Acker AFI", "pgm.opts.ccdata.afi", FT_UINT16, BASE_DEC,
	  VALS(afn_vals), 0x0, "", HFILL }},
    { &hf_pgm_opt_ccfeedbk_lossrate,
      { "Loss Rate", "pgm.opts.ccdata.lossrate", FT_UINT16, BASE_HEX,
          NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_ccfeedbk_acker,
      { "Acker", "pgm.opts.ccdata.acker", FT_IPv4, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_ccfeedbk_acker6,
      { "Acker", "pgm.opts.ccdata.acker", FT_IPv6, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_nak_bo_ivl_res,
      { "Reserved", "pgm.opts.nak_bo_ivl.res", FT_UINT8, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_nak_bo_ivl_bo_ivl,
      { "Back-off Interval", "pgm.opts.nak_bo_ivl.bo_ivl", FT_UINT32, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_nak_bo_ivl_bo_ivl_sqn,
      { "Back-off Interval Sequence Number", "pgm.opts.nak_bo_ivl.bo_ivl_sqn", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_nak_bo_rng_res,
      { "Reserved", "pgm.opts.nak_bo_rng.res", FT_UINT8, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_nak_bo_rng_min_bo_ivl,
      { "Min Back-off Interval", "pgm.opts.nak_bo_rng.min_bo_ivl", FT_UINT32, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_nak_bo_rng_max_bo_ivl,
      { "Max Back-off Interval", "pgm.opts.nak_bo_rng.max_bo_ivl", FT_UINT32, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_redirect_res,
      { "Reserved", "pgm.opts.redirect.res", FT_UINT8, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_redirect_afi,
      { "DLR AFI", "pgm.opts.redirect.afi", FT_UINT16, BASE_DEC,
	  VALS(afn_vals), 0x0, "", HFILL }},
    { &hf_pgm_opt_redirect_res2,
      { "Reserved", "pgm.opts.redirect.res2", FT_UINT16, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_redirect_dlr,
      { "DLR", "pgm.opts.redirect.dlr", FT_IPv4, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_redirect_dlr6,
      { "DLR", "pgm.opts.redirect.dlr", FT_IPv6, BASE_NONE,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_fragment_res,
      { "Reserved", "pgm.opts.fragment.res", FT_UINT8, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_fragment_first_sqn,
      { "First Sequence Number", "pgm.opts.fragment.first_sqn", FT_UINT32, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_fragment_offset,
      { "Fragment Offset", "pgm.opts.fragment.fragment_offset", FT_UINT32, BASE_DEC,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_opt_fragment_total_length,
      { "Total Length", "pgm.opts.fragment.total_length", FT_UINT32, BASE_DEC,
	  NULL, 0x0, "", HFILL }}
  };
  static gint *ett[] = {
	&ett_pgm,
	&ett_pgm_optbits,
	&ett_pgm_spm,
	&ett_pgm_data,
	&ett_pgm_nak,
	&ett_pgm_poll,
	&ett_pgm_polr,
	&ett_pgm_ack,
	&ett_pgm_opts,
	&ett_pgm_opts_join,
	&ett_pgm_opts_parityprm,
	&ett_pgm_opts_paritygrp,
	&ett_pgm_opts_naklist,
	&ett_pgm_opts_ccdata,
	&ett_pgm_opts_nak_bo_ivl,
	&ett_pgm_opts_nak_bo_rng,
	&ett_pgm_opts_redirect,
	&ett_pgm_opts_fragment
  };
  module_t *pgm_module;

  proto_pgm = proto_register_protocol("Pragmatic General Multicast",
				       "PGM", "pgm");

  proto_register_field_array(proto_pgm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
  subdissector_table = register_dissector_table("pgm.port",
		"PGM port", FT_UINT16, BASE_DEC);
  register_heur_dissector_list("pgm", &heur_subdissector_list);

  /*
   * Register configuration preferences for UDP encapsulation
   * (Note: Initially the ports are set to zero so the
   *        dissecting of PGM encapsulated in UPD packets
   *        is off by default)
   */
   pgm_module = prefs_register_protocol(proto_pgm, proto_rereg_pgm);

   prefs_register_bool_preference(pgm_module, "check_checksum",
	    "Check the validity of the PGM checksum when possible",
		"Whether to check the validity of the PGM checksum",
	    &pgm_check_checksum);

   prefs_register_uint_preference(pgm_module, "udp.encap_ucast_port",
		"PGM Encap Unicast Port (standard is 3055)",
		"PGM Encap is PGM packets encapsulated in UDP packets"
		" (Note: This option is off, i.e. port is 0, by default)",
		10, &udp_encap_ucast_port);
   old_encap_ucast_port = udp_encap_ucast_port;

   prefs_register_uint_preference(pgm_module, "udp.encap_mcast_port",
		"PGM Encap Multicast Port (standard is 3056)",
		"PGM Encap is PGM packets encapsulated in UDP packets"
		" (Note: This option is off, i.e. port is 0, by default)",
		10, &udp_encap_mcast_port);

   old_encap_mcast_port = udp_encap_mcast_port;
}

static dissector_handle_t pgm_handle;

/* The registration hand-off routine */
void
proto_reg_handoff_pgm(void)
{
  pgm_handle = create_dissector_handle(dissect_pgm, proto_pgm);

  /*
   * Set up PGM Encap dissecting, which is off by default
   */
  dissector_add("udp.port", udp_encap_ucast_port, pgm_handle);
  dissector_add("udp.port", udp_encap_mcast_port, pgm_handle);

  dissector_add("ip.proto", IP_PROTO_PGM, pgm_handle);

  data_handle = find_dissector("data");
}

static void
proto_rereg_pgm(void)
{
	/*
	 * Remove the old ones
	 */
	dissector_delete("udp.port", old_encap_ucast_port, pgm_handle);
	dissector_delete("udp.port", old_encap_mcast_port, pgm_handle);

	/*
	 * Set the new ones
	 */
	dissector_add("udp.port", udp_encap_ucast_port, pgm_handle);
	dissector_add("udp.port", udp_encap_mcast_port, pgm_handle);
}
