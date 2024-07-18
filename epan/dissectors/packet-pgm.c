/* packet-pgm.c
 * Routines for PGM packet disassembly, RFC 3208
 *
 * Copyright (c) 2000 by Talarian Corp
 * Rewritten by Jaap Keuter
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/afn.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/prefs.h>
#include <epan/ptvcursor.h>
#include <epan/expert.h>

/*
 * RFC 3208
 *
 * Plus https://dl.acm.org/doi/pdf/10.1145/347057.347390 for PGMCC,
 * whence the ACK packet type comes; there are some I-Ds for PGMCC,
 * draft-ietf-rmt-bb-pgmcc-00 through draft-ietf-rmt-bb-pgmcc-03,
 * but none of them give any description of the packet-level
 * changes to PGM, unlike the paper in question, which merely gives
 * an *insufficient* description of said changes.  In particular,
 * it doesn't indicate what the packet type code for ACK is.
 *
 * Luigi Rizzo's PGMCC code for FreeBSD, at
 *
 *     https://web.archive.org/web/20020302084503/http://info.iet.unipi.it/~luigi/pgm-code/
 *
 * uses 0x0b (11) for ACK, as does tcpdump's dissector.
 *
 * A capture file attached to
 *
 *     https://gitlab.com/wireshark/wireshark/-/issues/4798
 *
 * has packets that use 0x0d for ACK, as did this dissector, and
 * as does OpenPGM at https://github.com/steve-o/openpgm.  It may
 * be that some proprietary PGMCC implementations, such as SmartPGM,
 * do so as well.
 *
 * We use *both*, treating *either one* as a PGMCC ACK, pending
 * more information, such as an answer to
 *
 *    https://github.com/steve-o/openpgm/issues/75.
 */

void proto_register_pgm(void);
void proto_reg_handoff_pgm(void);

static dissector_handle_t pgm_handle;

/*
 * Flag to control whether to check the PGM checksum.
 */
static bool pgm_check_checksum = true;

/* constants for hdr types */
#define PGM_SPM_PCKT  0x00
#define PGM_ODATA_PCKT  0x04
#define PGM_RDATA_PCKT  0x05
#define PGM_NAK_PCKT  0x08
#define PGM_NNAK_PCKT  0x09
#define PGM_NCF_PCKT 0x0A
#define PGM_POLL_PCKT 0x01
#define PGM_POLR_PCKT 0x02

/*
 * See above comment for why there are two values for the PGMCC
 * ACK packet's packet type.
 */
#define PGM_ACK_PCKT 0x0B
#define PGM_ACK2_PCKT 0x0D

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

static int proto_pgm;
static int ett_pgm;
static int ett_pgm_optbits;
static int ett_pgm_opts;
static int ett_pgm_spm;
static int ett_pgm_data;
static int ett_pgm_nak;
static int ett_pgm_poll;
static int ett_pgm_polr;
static int ett_pgm_ack;
static int ett_pgm_opts_join;
static int ett_pgm_opts_parityprm;
static int ett_pgm_opts_paritygrp;
static int ett_pgm_opts_naklist;
static int ett_pgm_opts_ccdata;
static int ett_pgm_opts_nak_bo_ivl;
static int ett_pgm_opts_nak_bo_rng;
static int ett_pgm_opts_redirect;
static int ett_pgm_opts_fragment;

static int hf_pgm_main_sport;
static int hf_pgm_main_dport;
static int hf_pgm_port;
static int hf_pgm_main_type;
static int hf_pgm_main_opts;
static int hf_pgm_main_opts_opt;
static int hf_pgm_main_opts_netsig;
static int hf_pgm_main_opts_varlen;
static int hf_pgm_main_opts_parity;
static int hf_pgm_main_cksum;
static int hf_pgm_main_cksum_status;
static int hf_pgm_main_gsi;
static int hf_pgm_main_tsdulen;
static int hf_pgm_spm_sqn;
static int hf_pgm_spm_lead;
static int hf_pgm_spm_trail;
static int hf_pgm_spm_pathafi;
static int hf_pgm_spm_res;
static int hf_pgm_spm_path;
static int hf_pgm_spm_path6;
/* static int hf_pgm_data_sqn; */
/* static int hf_pgm_data_trail; */
static int hf_pgm_nak_sqn;
static int hf_pgm_nak_srcafi;
static int hf_pgm_nak_srcres;
static int hf_pgm_nak_src;
static int hf_pgm_nak_src6;
static int hf_pgm_nak_grpafi;
static int hf_pgm_nak_grpres;
static int hf_pgm_nak_grp;
static int hf_pgm_nak_grp6;
static int hf_pgm_poll_sqn;
static int hf_pgm_poll_round;
static int hf_pgm_poll_subtype;
static int hf_pgm_poll_pathafi;
static int hf_pgm_poll_res;
static int hf_pgm_poll_path;
static int hf_pgm_poll_path6;
static int hf_pgm_poll_backoff_ivl;
static int hf_pgm_poll_rand_str;
static int hf_pgm_poll_matching_bmask;
static int hf_pgm_polr_sqn;
static int hf_pgm_polr_round;
static int hf_pgm_polr_res;
static int hf_pgm_ack_sqn;
static int hf_pgm_ack_bitmap;

static int hf_pgm_opt_type;
static int hf_pgm_opt_len;
static int hf_pgm_opt_tlen;

static int hf_pgm_genopt_end;
static int hf_pgm_genopt_type;
static int hf_pgm_genopt_len;
static int hf_pgm_genopt_opx;

static int hf_pgm_opt_join_res;
static int hf_pgm_opt_join_minjoin;

static int hf_pgm_opt_parity_prm_po;
static int hf_pgm_opt_parity_prm_prmtgsz;

static int hf_pgm_opt_parity_grp_res;
static int hf_pgm_opt_parity_grp_prmgrp;

static int hf_pgm_opt_nak_res;
static int hf_pgm_opt_nak_list;

static int hf_pgm_opt_ccdata_res;
static int hf_pgm_opt_ccdata_tsp;
static int hf_pgm_opt_ccdata_afi;
static int hf_pgm_opt_ccdata_res2;
static int hf_pgm_opt_ccdata_acker;
static int hf_pgm_opt_ccdata_acker6;

static int hf_pgm_opt_ccfeedbk_res;
static int hf_pgm_opt_ccfeedbk_tsp;
static int hf_pgm_opt_ccfeedbk_afi;
static int hf_pgm_opt_ccfeedbk_lossrate;
static int hf_pgm_opt_ccfeedbk_acker;
static int hf_pgm_opt_ccfeedbk_acker6;

static int hf_pgm_opt_nak_bo_ivl_res;
static int hf_pgm_opt_nak_bo_ivl_bo_ivl;
static int hf_pgm_opt_nak_bo_ivl_bo_ivl_sqn;

static int hf_pgm_opt_nak_bo_rng_res;
static int hf_pgm_opt_nak_bo_rng_min_bo_ivl;
static int hf_pgm_opt_nak_bo_rng_max_bo_ivl;

static int hf_pgm_opt_redirect_res;
static int hf_pgm_opt_redirect_afi;
static int hf_pgm_opt_redirect_res2;
static int hf_pgm_opt_redirect_dlr;
static int hf_pgm_opt_redirect_dlr6;

static int hf_pgm_opt_fragment_res;
static int hf_pgm_opt_fragment_first_sqn;
static int hf_pgm_opt_fragment_offset;
static int hf_pgm_opt_fragment_total_length;

static expert_field ei_pgm_genopt_len;
static expert_field ei_pgm_opt_tlen;
static expert_field ei_pgm_opt_type;
static expert_field ei_address_format_invalid;
static expert_field ei_pgm_main_cksum;

static dissector_table_t subdissector_table;
static heur_dissector_list_t heur_subdissector_list;


static const char *
optsstr(wmem_allocator_t *pool, uint8_t opts)
{
	char *msg;
	int   returned_length, idx = 0;
	const int MAX_STR_LEN = 256;

	if (opts == 0)
		return "";

	msg=(char *)wmem_alloc(pool, MAX_STR_LEN);
	if (opts & PGM_OPT){
		returned_length = snprintf(&msg[idx], MAX_STR_LEN-idx, "Present");
		idx += MIN(returned_length, MAX_STR_LEN-idx);
	}
	if (opts & PGM_OPT_NETSIG){
		returned_length = snprintf(&msg[idx], MAX_STR_LEN-idx, "%sNetSig", (!idx)?"":",");
		idx += MIN(returned_length, MAX_STR_LEN-idx);
	}
	if (opts & PGM_OPT_VAR_PKTLEN){
		returned_length = snprintf(&msg[idx], MAX_STR_LEN-idx, "%sVarLen", (!idx)?"":",");
		idx += MIN(returned_length, MAX_STR_LEN-idx);
	}
	if (opts & PGM_OPT_PARITY){
		returned_length = snprintf(&msg[idx], MAX_STR_LEN-idx, "%sParity", (!idx)?"":",");
		idx += MIN(returned_length, MAX_STR_LEN-idx);
	}
	if (!idx) {
		snprintf(&msg[idx], MAX_STR_LEN-idx, "0x%x", opts);
	}
	return msg;
}
static const char *
paritystr(wmem_allocator_t *pool, uint8_t parity)
{
	char *msg;
	int returned_length, idx = 0;
	const int MAX_STR_LEN = 256;

	if (parity == 0)
		return "";

	msg=(char *)wmem_alloc(pool, MAX_STR_LEN);
	if (parity & PGM_OPT_PARITY_PRM_PRO){
		returned_length = snprintf(&msg[idx], MAX_STR_LEN-idx, "Pro-active");
		idx += MIN(returned_length, MAX_STR_LEN-idx);
	}
	if (parity & PGM_OPT_PARITY_PRM_OND){
		returned_length = snprintf(&msg[idx], MAX_STR_LEN-idx, "%sOn-demand", (!idx)?"":",");
		idx += MIN(returned_length, MAX_STR_LEN-idx);
	}
	if (!idx) {
		snprintf(&msg[idx], MAX_STR_LEN-idx, "0x%x", parity);
	}
	return msg;
}

static const value_string opt_vals[] = {
	{ PGM_OPT_LENGTH,	  "Length" },
	{ PGM_OPT_END,		  "End" },
	{ PGM_OPT_FRAGMENT,	  "Fragment" },
	{ PGM_OPT_NAK_LIST,	  "NakList" },
	{ PGM_OPT_JOIN,		  "Join" },
	{ PGM_OPT_REDIRECT,	  "ReDirect" },
	{ PGM_OPT_SYN,		  "Syn" },
	{ PGM_OPT_FIN,		  "Fin" },
	{ PGM_OPT_RST,		  "Rst" },
	{ PGM_OPT_PARITY_PRM,	  "ParityPrm" },
	{ PGM_OPT_PARITY_GRP,	  "ParityGrp" },
	{ PGM_OPT_CURR_TGSIZE,	  "CurrTgsiz" },
	{ PGM_OPT_PGMCC_DATA,	  "CcData" },
	{ PGM_OPT_PGMCC_FEEDBACK, "CcFeedBack" },
	{ PGM_OPT_NAK_BO_IVL,	  "NakBackOffIvl" },
	{ PGM_OPT_NAK_BO_RNG,	  "NakBackOffRng" },
	{ 0,                   NULL }
};

static const value_string opx_vals[] = {
	{ PGM_OPX_IGNORE,  "Ignore" },
	{ PGM_OPX_INVAL,   "Inval" },
	{ PGM_OPX_DISCARD, "DisCard" },
	{ 0,               NULL }
};

#define TLV_CHECK(ett) \
	opt_tree = proto_tree_add_subtree_format(opts_tree, tvb, ptvcursor_current_offset(cursor), genopts_len, \
						ett, &tf, "Option: %s, Length: %u", \
						val_to_str(genopts_type, opt_vals, "Unknown (0x%02x)"), genopts_len); \
	if (genopts_len < 4) { \
		expert_add_info_format(pinfo, tf, &ei_pgm_genopt_len, \
					"Length %u invalid, must be >= 4", genopts_len); \
		return; \
	} \
	if (opts_total_len < genopts_len) { \
		expert_add_info_format(pinfo, tf, &ei_pgm_genopt_len, \
					"Length %u > remaining total options length", genopts_len); \
		return; \
	} \


static void
dissect_pgmopts(ptvcursor_t* cursor, packet_info *pinfo, const char *pktname)
{
	proto_item *tf, *ti, *ti_len;
	proto_tree *opts_tree = NULL;
	proto_tree *opt_tree  = NULL;
	tvbuff_t   *tvb       = ptvcursor_tvbuff(cursor);

	bool theend = false;

	uint16_t opts_total_len;
	uint8_t genopts_type;
	uint8_t genopts_len;
	uint8_t opts_type;

	opts_tree = proto_tree_add_subtree_format(ptvcursor_tree(cursor), tvb, ptvcursor_current_offset(cursor), -1,
		ett_pgm_opts, &tf, "%s Options", pktname);
	ptvcursor_set_tree(cursor, opts_tree);
	opts_type = tvb_get_uint8(tvb, ptvcursor_current_offset(cursor));
	ti = ptvcursor_add(cursor, hf_pgm_opt_type, 1, ENC_BIG_ENDIAN);
	if (opts_type != PGM_OPT_LENGTH) {
		expert_add_info_format(pinfo, ti, &ei_pgm_opt_type,
		    "%s Options - initial option is %s, should be %s",
		    pktname,
		    val_to_str(opts_type, opt_vals, "Unknown (0x%02x)"),
		    val_to_str(PGM_OPT_LENGTH, opt_vals, "Unknown (0x%02x)"));
		return;
	}
	ptvcursor_add(cursor, hf_pgm_opt_len, 1, ENC_BIG_ENDIAN);
	opts_total_len = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
	proto_item_append_text(tf, " (Total Length %d)", opts_total_len);
	proto_item_set_len(tf, opts_total_len);
	ti_len = ptvcursor_add(cursor, hf_pgm_opt_tlen, 2, ENC_BIG_ENDIAN);
	if (opts_total_len < 4) {
		expert_add_info_format(pinfo, ti_len, &ei_pgm_opt_tlen,
			"%s Options (Total Length %u - invalid, must be >= 4)",
			pktname, opts_total_len);
		return;
	}

	for (opts_total_len -= 4; !theend && opts_total_len != 0;){
		if (opts_total_len < 4) {
			expert_add_info_format(pinfo, ti_len, &ei_pgm_opt_tlen,
				"Remaining total options length doesn't have enough for an options header");
			break;
		}

		genopts_type = tvb_get_uint8(tvb, ptvcursor_current_offset(cursor));
		genopts_len = tvb_get_uint8(tvb, ptvcursor_current_offset(cursor)+1);

		if (genopts_type & PGM_OPT_END)  {
			genopts_type &= ~PGM_OPT_END;
			theend = true;
		}

		switch(genopts_type) {
		case PGM_OPT_JOIN:{
			TLV_CHECK(ett_pgm_opts_join);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add_no_advance(cursor, hf_pgm_genopt_end, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, ENC_BIG_ENDIAN);

			if (genopts_len < PGM_OPT_JOIN_SIZE) {
				proto_tree_add_uint_format_value(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"%u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_JOIN_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_join_res, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_join_minjoin, 4, ENC_BIG_ENDIAN);

			break;
		}
		case PGM_OPT_PARITY_PRM:{
			uint8_t optdata_po;

			TLV_CHECK(ett_pgm_opts_parityprm);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add_no_advance(cursor, hf_pgm_genopt_end, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, ENC_BIG_ENDIAN);


			if (genopts_len < PGM_OPT_PARITY_PRM_SIZE) {
				proto_tree_add_uint_format_value(opt_tree, hf_pgm_genopt_len, ptvcursor_tvbuff(cursor),
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"%u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_PARITY_PRM_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, ENC_BIG_ENDIAN);
			optdata_po = tvb_get_uint8(tvb, ptvcursor_current_offset(cursor));
			proto_tree_add_uint_format_value(opt_tree, hf_pgm_opt_parity_prm_po, tvb,
				ptvcursor_current_offset(cursor), 1, optdata_po, "%s (0x%x)",
				paritystr(pinfo->pool, optdata_po), optdata_po);
			ptvcursor_advance(cursor, 1);

			ptvcursor_add(cursor, hf_pgm_opt_parity_prm_prmtgsz, 4, ENC_BIG_ENDIAN);

			break;
		}
		case PGM_OPT_PARITY_GRP:{
			TLV_CHECK(ett_pgm_opts_paritygrp);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add_no_advance(cursor, hf_pgm_genopt_end, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, ENC_BIG_ENDIAN);

			if (genopts_len < PGM_OPT_PARITY_GRP_SIZE) {
				proto_tree_add_uint_format_value(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"%u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_PARITY_GRP_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_parity_grp_res, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_parity_grp_prmgrp, 4, ENC_BIG_ENDIAN);

			break;
		}
		case PGM_OPT_NAK_LIST:{
			uint8_t optdata_len;
			uint32_t naklist[PGM_MAX_NAK_LIST_SZ+1];
			unsigned char *nakbuf;
			bool firsttime;
			int i, j, naks, soffset;

			TLV_CHECK(ett_pgm_opts_naklist);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add_no_advance(cursor, hf_pgm_genopt_end, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, ENC_BIG_ENDIAN);

			optdata_len = tvb_get_uint8(tvb, ptvcursor_current_offset(cursor));
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_nak_res, 1, ENC_BIG_ENDIAN);

			optdata_len -= PGM_OPT_NAK_LIST_SIZE;
			tvb_memcpy(tvb, (uint8_t *)naklist, ptvcursor_current_offset(cursor), optdata_len);
			firsttime = true;
			soffset = 0;
			naks = (int)(optdata_len/sizeof(uint32_t));
			nakbuf = (unsigned char *)wmem_alloc(pinfo->pool, 8192);
			j = 0;
			/*
			 * Print out 8 per line
			 */
			for (i=0; i < naks; i++) {
				soffset += MIN(8192-soffset,
					snprintf(nakbuf+soffset, 8192-soffset, "0x%lx ",
						(unsigned long)g_ntohl(naklist[i])));
				if ((++j % 8) == 0) {
					if (firsttime) {
						proto_tree_add_bytes_format(opt_tree,
							hf_pgm_opt_nak_list, tvb, ptvcursor_current_offset(cursor), j*4,
							nakbuf, "List(%d): %s", naks, nakbuf);
						soffset = 0;
						firsttime = false;
					} else {
						proto_tree_add_bytes_format_value(opt_tree,
							hf_pgm_opt_nak_list, tvb, ptvcursor_current_offset(cursor), j*4,
							nakbuf, "%s", nakbuf);
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
					proto_tree_add_bytes_format_value(opt_tree,
						hf_pgm_opt_nak_list, tvb, ptvcursor_current_offset(cursor), j*4,
						nakbuf, "%s", nakbuf);
				}
				ptvcursor_advance(cursor, j*4);
			}
			break;
		}
		case PGM_OPT_PGMCC_DATA:{
			uint16_t optdata_afi;

			TLV_CHECK(ett_pgm_opts_ccdata);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add_no_advance(cursor, hf_pgm_genopt_end, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, ENC_BIG_ENDIAN);

			if (genopts_len < PGM_OPT_PGMCC_DATA_SIZE) {
				proto_tree_add_uint_format_value(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"%u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_PGMCC_DATA_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_ccdata_res, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_ccdata_tsp, 4, ENC_BIG_ENDIAN);
			optdata_afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
			ti = ptvcursor_add(cursor, hf_pgm_opt_ccdata_afi, 2, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_ccdata_res2, 2, ENC_BIG_ENDIAN);

			switch (optdata_afi) {

			case AFNUM_INET:
				ptvcursor_add(cursor, hf_pgm_opt_ccdata_acker, 4, ENC_BIG_ENDIAN);
				break;

			case AFNUM_INET6:
				ptvcursor_add(cursor, hf_pgm_opt_ccdata_acker6, 16, ENC_NA);
				break;

			default:
				expert_add_info(pinfo, ti, &ei_address_format_invalid);
				break;
			}

			break;
		}
		case PGM_OPT_PGMCC_FEEDBACK:{
			uint16_t optdata_afi;

			TLV_CHECK(ett_pgm_opts_ccdata);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add_no_advance(cursor, hf_pgm_genopt_end, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, ENC_BIG_ENDIAN);

			if (genopts_len < PGM_OPT_PGMCC_FEEDBACK_SIZE) {
				proto_tree_add_uint_format_value(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"%u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_PGMCC_FEEDBACK_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_res, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_tsp, 4, ENC_BIG_ENDIAN);
			optdata_afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
			ti = ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_afi, 2, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_lossrate, 2, ENC_BIG_ENDIAN);

			switch (optdata_afi) {

			case AFNUM_INET:
				ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_acker, 4, ENC_BIG_ENDIAN);
				break;

			case AFNUM_INET6:
				ptvcursor_add(cursor, hf_pgm_opt_ccfeedbk_acker6, 16, ENC_NA);
				break;

			default:
				expert_add_info(pinfo, ti, &ei_address_format_invalid);
				break;
			}

			break;
		}
		case PGM_OPT_NAK_BO_IVL:{
			TLV_CHECK(ett_pgm_opts_nak_bo_ivl);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add_no_advance(cursor, hf_pgm_genopt_end, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, ENC_BIG_ENDIAN);

			if (genopts_len < PGM_OPT_NAK_BO_IVL_SIZE) {
				proto_tree_add_uint_format_value(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"%u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_NAK_BO_IVL_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_ivl_res, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_ivl_bo_ivl, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_ivl_bo_ivl_sqn, 4, ENC_BIG_ENDIAN);

			break;
		}
		case PGM_OPT_NAK_BO_RNG:{
			TLV_CHECK(ett_pgm_opts_nak_bo_rng);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add_no_advance(cursor, hf_pgm_genopt_end, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, ENC_BIG_ENDIAN);

			if (genopts_len < PGM_OPT_NAK_BO_RNG_SIZE) {
				proto_tree_add_uint_format_value(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"%u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_NAK_BO_RNG_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_rng_res, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_rng_min_bo_ivl, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_nak_bo_rng_max_bo_ivl, 4, ENC_BIG_ENDIAN);

			break;
		}
		case PGM_OPT_REDIRECT:{
			uint16_t optdata_afi;

			TLV_CHECK(ett_pgm_opts_redirect);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add_no_advance(cursor, hf_pgm_genopt_end, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, ENC_BIG_ENDIAN);

			if (genopts_len < PGM_OPT_REDIRECT_SIZE) {
				proto_tree_add_uint_format_value(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"%u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_REDIRECT_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_redirect_res, 1, ENC_BIG_ENDIAN);
			optdata_afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
			ti = ptvcursor_add(cursor, hf_pgm_opt_redirect_afi, 2, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_redirect_res2, 2, ENC_BIG_ENDIAN);

			switch (optdata_afi) {

			case AFNUM_INET:
				ptvcursor_add(cursor, hf_pgm_opt_redirect_dlr, 4, ENC_BIG_ENDIAN);
				break;

			case AFNUM_INET6:
				ptvcursor_add(cursor, hf_pgm_opt_redirect_dlr6, 16, ENC_NA);
				break;

			default:
				expert_add_info(pinfo, ti, &ei_address_format_invalid);
				break;
			}

			break;
		}
		case PGM_OPT_FRAGMENT:{
			TLV_CHECK(ett_pgm_opts_fragment);
			ptvcursor_set_tree(cursor, opt_tree);

			ptvcursor_add_no_advance(cursor, hf_pgm_genopt_end, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_type, 1, ENC_BIG_ENDIAN);

			if (genopts_len < PGM_OPT_FRAGMENT_SIZE) {
				proto_tree_add_uint_format_value(opt_tree, hf_pgm_genopt_len, tvb,
					ptvcursor_current_offset(cursor), 1, genopts_len,
					"%u (bogus, must be >= %u)",
					genopts_len, PGM_OPT_FRAGMENT_SIZE);
				break;
			}
			ptvcursor_add(cursor, hf_pgm_genopt_len, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_genopt_opx, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_fragment_res, 1, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_fragment_first_sqn, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_fragment_offset, 4, ENC_BIG_ENDIAN);
			ptvcursor_add(cursor, hf_pgm_opt_fragment_total_length, 4, ENC_BIG_ENDIAN);

			break;
		}
		default:{
			TLV_CHECK(ett_pgm_opts);
			ptvcursor_advance(cursor, genopts_len);
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
	{ PGM_ACK2_PCKT,  "ACK" },
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
		 proto_tree *tree, uint16_t pgmhdr_sport, uint16_t pgmhdr_dport)
{
	tvbuff_t *next_tvb;
	int       found = 0;
	heur_dtbl_entry_t *hdtbl_entry;

	next_tvb = tvb_new_subset_remaining(tvb, offset);

	/* do lookup with the subdissector table */
	found = dissector_try_uint(subdissector_table, pgmhdr_sport,
				   next_tvb, pinfo, tree);
	if (found)
		return;

	found = dissector_try_uint(subdissector_table, pgmhdr_dport,
				   next_tvb, pinfo, tree);
	if (found)
		return;

	/* do lookup with the heuristic subdissector table */
	if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL))
		return;

	/* Oh, well, we don't know this; dissect it as data. */
	call_data_dissector(next_tvb, pinfo, tree);
}

/*
 * dissect_pgm - The dissector for Pragmatic General Multicast
 */
static int
dissect_pgm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	uint32_t pgmhdr_sport;
	uint32_t pgmhdr_dport;
	uint32_t pgmhdr_type;
	uint8_t pgmhdr_opts;
	uint16_t pgmhdr_cksum;
	uint32_t pgmhdr_tsdulen;
	uint32_t sqn;
	uint16_t afi;

	proto_tree *pgm_tree = NULL;
	proto_tree *opt_tree = NULL;
	proto_tree *type_tree = NULL;
	proto_item *tf, *hidden_item;
	ptvcursor_t* cursor;

	unsigned    plen   = 0;
	proto_item *ti;
	const char *pktname;
	char       *gsi;
	bool        isdata = false;
	unsigned    pgmlen, reportedlen;

	if (tvb_reported_length_remaining(tvb, 0) < 18)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "PGM");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_protocol_format(tree, proto_pgm, tvb, 0, -1,
		"Pragmatic General Multicast");
	pgm_tree = proto_item_add_subtree(ti, ett_pgm);

	cursor = ptvcursor_new(pinfo->pool, pgm_tree, tvb, 0);

	hidden_item = proto_tree_add_item(pgm_tree, hf_pgm_port, tvb, 0, 2, ENC_BIG_ENDIAN);
	proto_item_set_hidden(hidden_item);
	hidden_item = proto_tree_add_item(pgm_tree, hf_pgm_port, tvb, 2, 2, ENC_BIG_ENDIAN);
	proto_item_set_hidden(hidden_item);
	ptvcursor_add_ret_uint(cursor, hf_pgm_main_sport, 2, ENC_BIG_ENDIAN, &pgmhdr_sport);
	pinfo->srcport = pgmhdr_sport;
	ptvcursor_add_ret_uint(cursor, hf_pgm_main_dport, 2, ENC_BIG_ENDIAN, &pgmhdr_dport);
	pinfo->destport = pgmhdr_dport;
	ptvcursor_add_ret_uint(cursor, hf_pgm_main_type, 1, ENC_BIG_ENDIAN, &pgmhdr_type);
	pktname = val_to_str(pgmhdr_type, type_vals, "Unknown (0x%02x)");
	proto_item_append_text(ti, ": Type %s Src Port %u, Dst Port %u",
	                       pktname, pgmhdr_sport, pgmhdr_dport);
	col_append_fstr(pinfo->cinfo, COL_INFO, "%-5s", pktname);

	pgmhdr_opts = tvb_get_uint8(tvb, 5);
	tf = proto_tree_add_uint_format_value(pgm_tree, hf_pgm_main_opts, tvb,
		ptvcursor_current_offset(cursor), 1, pgmhdr_opts, "%s (0x%x)",
		optsstr(pinfo->pool, pgmhdr_opts), pgmhdr_opts);
	opt_tree = proto_item_add_subtree(tf, ett_pgm_optbits);
	ptvcursor_set_tree(cursor, opt_tree);

	ptvcursor_add_no_advance(cursor, hf_pgm_main_opts_opt, 1, ENC_BIG_ENDIAN);
	ptvcursor_add_no_advance(cursor, hf_pgm_main_opts_netsig, 1, ENC_BIG_ENDIAN);
	ptvcursor_add_no_advance(cursor, hf_pgm_main_opts_varlen, 1, ENC_BIG_ENDIAN);
	ptvcursor_add(cursor, hf_pgm_main_opts_parity, 1, ENC_BIG_ENDIAN);
	ptvcursor_set_tree(cursor, pgm_tree);

	/* Checksum may be 0 (not available), but not for DATA packets */
	pgmhdr_cksum = tvb_get_ntohs(tvb, 6);
	if ((pgmhdr_type != PGM_RDATA_PCKT) && (pgmhdr_type != PGM_ODATA_PCKT) &&
	    (pgmhdr_cksum == 0))
	{
		proto_tree_add_checksum(pgm_tree, tvb, ptvcursor_current_offset(cursor), hf_pgm_main_cksum, hf_pgm_main_cksum_status, &ei_pgm_main_cksum,
								pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NOT_PRESENT);
	} else {
		reportedlen = tvb_reported_length(tvb);
		pgmlen = tvb_captured_length(tvb);
		if (pgm_check_checksum && pgmlen >= reportedlen) {
			vec_t cksum_vec[1];

			SET_CKSUM_VEC_TVB(cksum_vec[0], tvb, 0, pgmlen);
			proto_tree_add_checksum(pgm_tree, tvb, ptvcursor_current_offset(cursor), hf_pgm_main_cksum_status, hf_pgm_main_cksum_status, &ei_pgm_main_cksum,
									pinfo, in_cksum(&cksum_vec[0], 1), ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY|PROTO_CHECKSUM_IN_CKSUM);
		} else {
			proto_tree_add_checksum(pgm_tree, tvb, ptvcursor_current_offset(cursor), hf_pgm_main_cksum, hf_pgm_main_cksum_status, &ei_pgm_main_cksum,
									pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
		}
	}
	ptvcursor_advance(cursor, 2);

	gsi = tvb_bytes_to_str(pinfo->pool, tvb, 8, 6);
	ptvcursor_add(cursor, hf_pgm_main_gsi, 6, ENC_NA);
	proto_item_append_text(ti, ", GSI %s", gsi);
	ptvcursor_add_ret_uint(cursor, hf_pgm_main_tsdulen, 2, ENC_BIG_ENDIAN, &pgmhdr_tsdulen);
	sqn = tvb_get_ntohl(tvb, 16);
	col_append_fstr(pinfo->cinfo, COL_INFO,
		     " sqn 0x%x gsi %s", sqn, gsi);

	switch(pgmhdr_type) {
	case PGM_SPM_PCKT:
		type_tree = proto_tree_add_subtree_format(pgm_tree, tvb, ptvcursor_current_offset(cursor), plen,
											ett_pgm_spm, NULL, "%s Packet", pktname);
		ptvcursor_set_tree(cursor, type_tree);

		ptvcursor_add(cursor, hf_pgm_spm_sqn, 4, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_spm_trail, 4, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_spm_lead, 4, ENC_BIG_ENDIAN);
		afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
		ti = ptvcursor_add(cursor, hf_pgm_spm_pathafi, 2, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_spm_res, 2, ENC_BIG_ENDIAN);

		switch (afi) {
		case AFNUM_INET:
			ptvcursor_add(cursor, hf_pgm_spm_path, 4, ENC_BIG_ENDIAN);
			break;

		case AFNUM_INET6:
			ptvcursor_add(cursor, hf_pgm_spm_path6, 16, ENC_NA);
			break;

		default:
			expert_add_info(pinfo, ti, &ei_address_format_invalid);
			ptvcursor_free(cursor);
			return tvb_captured_length(tvb);
		}
		break;
	case PGM_RDATA_PCKT:
	case PGM_ODATA_PCKT:
		isdata = true;
		type_tree = proto_tree_add_subtree_format(pgm_tree, tvb, ptvcursor_current_offset(cursor), plen,
											ett_pgm_data, NULL, "%s Packet", pktname);
		ptvcursor_set_tree(cursor, type_tree);
		col_append_fstr(pinfo->cinfo, COL_INFO,
			    " tsdulen %d", pgmhdr_tsdulen);

		ptvcursor_add(cursor, hf_pgm_spm_sqn, 4, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_spm_trail, 4, ENC_BIG_ENDIAN);
		break;
	case PGM_NAK_PCKT:
	case PGM_NNAK_PCKT:
	case PGM_NCF_PCKT:
		type_tree = proto_tree_add_subtree_format(pgm_tree, tvb, ptvcursor_current_offset(cursor), plen,
											ett_pgm_nak, NULL, "%s Packet", pktname);
		ptvcursor_set_tree(cursor, type_tree);

		ptvcursor_add(cursor, hf_pgm_nak_sqn, 4, ENC_BIG_ENDIAN);
		afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
		ti = ptvcursor_add(cursor, hf_pgm_nak_srcafi, 2, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_nak_srcres, 2, ENC_BIG_ENDIAN);

		switch (afi) {
		case AFNUM_INET:
			ptvcursor_add(cursor, hf_pgm_nak_src, 4, ENC_BIG_ENDIAN);
			break;

		case AFNUM_INET6:
			ptvcursor_add(cursor, hf_pgm_nak_src6, 16, ENC_NA);
			break;

		default:
			expert_add_info(pinfo, ti, &ei_address_format_invalid);
			break;
		}

		afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
		ti = ptvcursor_add(cursor, hf_pgm_nak_grpafi, 2, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_nak_grpres, 2, ENC_BIG_ENDIAN);

		switch (afi) {
		case AFNUM_INET:
			ptvcursor_add(cursor, hf_pgm_nak_grp, 4, ENC_BIG_ENDIAN);
			break;

		case AFNUM_INET6:
			ptvcursor_add(cursor, hf_pgm_nak_grp6, 16, ENC_NA);
			break;

		default:
			expert_add_info(pinfo, ti, &ei_address_format_invalid);
			ptvcursor_free(cursor);
			return tvb_captured_length(tvb);
		}
		break;
	case PGM_POLL_PCKT: {
		uint32_t poll_stype;

		type_tree = proto_tree_add_subtree_format(pgm_tree, tvb, ptvcursor_current_offset(cursor), plen,
											ett_pgm_poll, NULL, "%s Packet", pktname);
		ptvcursor_set_tree(cursor, type_tree);

		ptvcursor_add(cursor, hf_pgm_poll_sqn, 4, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_poll_round, 2, ENC_BIG_ENDIAN);
		ptvcursor_add_ret_uint(cursor, hf_pgm_poll_subtype, 2, ENC_BIG_ENDIAN, &poll_stype);
		col_append_fstr(pinfo->cinfo, COL_INFO,
				" subtype %s",
				val_to_str(poll_stype, poll_subtype_vals, "Unknown (0x%02x)"));
		afi = tvb_get_ntohs(tvb, ptvcursor_current_offset(cursor));
		ti = ptvcursor_add(cursor, hf_pgm_poll_pathafi, 2, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_poll_res, 2, ENC_BIG_ENDIAN);

		switch (afi) {
		case AFNUM_INET:
			ptvcursor_add(cursor, hf_pgm_poll_path, 4, ENC_BIG_ENDIAN);
			break;

		case AFNUM_INET6:
			ptvcursor_add(cursor, hf_pgm_poll_path6, 16, ENC_NA);
			break;

		default:
			expert_add_info(pinfo, ti, &ei_address_format_invalid);
			break;
		}

		ptvcursor_add(cursor, hf_pgm_poll_backoff_ivl, 4, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_poll_rand_str, 4, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_poll_matching_bmask, 4, ENC_BIG_ENDIAN);
		break;
	}
	case PGM_POLR_PCKT:
		type_tree = proto_tree_add_subtree_format(pgm_tree, tvb, ptvcursor_current_offset(cursor), plen,
											ett_pgm_polr, NULL, "%s Packet", pktname);
		ptvcursor_set_tree(cursor, type_tree);

		ptvcursor_add(cursor, hf_pgm_polr_sqn, 4, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_polr_round, 2, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_polr_res, 2, ENC_BIG_ENDIAN);
		break;
	case PGM_ACK_PCKT:
	case PGM_ACK2_PCKT:
		type_tree = proto_tree_add_subtree_format(pgm_tree, tvb, ptvcursor_current_offset(cursor), plen,
											ett_pgm_ack, NULL, "%s Packet", pktname);
		ptvcursor_set_tree(cursor, type_tree);

		ptvcursor_add(cursor, hf_pgm_ack_sqn, 4, ENC_BIG_ENDIAN);
		ptvcursor_add(cursor, hf_pgm_ack_bitmap, 4, ENC_BIG_ENDIAN);
		break;
	}

	if (pgmhdr_opts & PGM_OPT)
		dissect_pgmopts(cursor, pinfo, pktname);

	if (isdata)
		decode_pgm_ports(tvb, ptvcursor_current_offset(cursor), pinfo, tree, pgmhdr_sport, pgmhdr_dport);

	ptvcursor_free(cursor);
	return tvb_captured_length(tvb);
}

/* Register all the bits needed with the filtering engine */
void
proto_register_pgm(void)
{
	static hf_register_info hf[] = {
		{ &hf_pgm_main_sport,
		  { "Source Port", "pgm.hdr.sport", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_main_dport,
		  { "Destination Port", "pgm.hdr.dport", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_port,
		  { "Port", "pgm.port", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_main_type,
		  { "Type", "pgm.hdr.type", FT_UINT8, BASE_HEX,
		    VALS(type_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_main_opts,
		  { "Options", "pgm.hdr.opts", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_main_opts_opt,
		  { "Options", "pgm.hdr.opts.opt", FT_BOOLEAN, 8,
		    TFS(&tfs_present_not_present), PGM_OPT, NULL, HFILL }},
		{ &hf_pgm_main_opts_netsig,
		  { "Network Significant Options", "pgm.hdr.opts.netsig",
		    FT_BOOLEAN, 8,
		    TFS(&tfs_present_not_present), PGM_OPT_NETSIG, NULL, HFILL }},
		{ &hf_pgm_main_opts_varlen,
		  { "Variable length Parity Packet Option", "pgm.hdr.opts.varlen",
		    FT_BOOLEAN, 8,
		    TFS(&tfs_present_not_present), PGM_OPT_VAR_PKTLEN, NULL, HFILL }},
		{ &hf_pgm_main_opts_parity,
		  { "Parity", "pgm.hdr.opts.parity", FT_BOOLEAN, 8,
		    TFS(&tfs_present_not_present), PGM_OPT_PARITY, NULL, HFILL }},
		{ &hf_pgm_main_cksum,
		  { "Checksum", "pgm.hdr.cksum", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_main_cksum_status,
		  { "Checksum Status", "pgm.hdr.cksum.status", FT_UINT8, BASE_NONE,
		    VALS(proto_checksum_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_main_gsi,
		  { "Global Source Identifier", "pgm.hdr.gsi", FT_BYTES, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_main_tsdulen,
		  { "Transport Service Data Unit Length", "pgm.hdr.tsdulen", FT_UINT16,
		    BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_spm_sqn,
		  { "Sequence number", "pgm.spm.sqn", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_spm_trail,
		  { "Trailing Edge Sequence Number", "pgm.spm.trail", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_spm_lead,
		  { "Leading Edge Sequence Number", "pgm.spm.lead", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_spm_pathafi,
		  { "Path NLA AFI", "pgm.spm.pathafi", FT_UINT16, BASE_DEC,
		    VALS(afn_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_spm_res,
		  { "Reserved", "pgm.spm.res", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_spm_path,
		  { "Path NLA", "pgm.spm.path.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_spm_path6,
		  { "Path NLA", "pgm.spm.path.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
#if 0
		{ &hf_pgm_data_sqn,
		  { "Data Packet Sequence Number", "pgm.data.sqn", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
#endif
#if 0
		{ &hf_pgm_data_trail,
		  { "Trailing Edge Sequence Number", "pgm.data.trail", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
#endif
		{ &hf_pgm_nak_sqn,
		  { "Requested Sequence Number", "pgm.nak.sqn", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_nak_srcafi,
		  { "Source NLA AFI", "pgm.nak.srcafi", FT_UINT16, BASE_DEC,
		    VALS(afn_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_nak_srcres,
		  { "Reserved", "pgm.nak.srcres", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_nak_src,
		  { "Source NLA", "pgm.nak.src.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_nak_src6,
		  { "Source NLA", "pgm.nak.src.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_nak_grpafi,
		  { "Multicast Group AFI", "pgm.nak.grpafi", FT_UINT16, BASE_DEC,
		    VALS(afn_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_nak_grpres,
		  { "Reserved", "pgm.nak.grpres", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_nak_grp,
		  { "Multicast Group NLA", "pgm.nak.grp.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_nak_grp6,
		  { "Multicast Group NLA", "pgm.nak.grp.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_poll_sqn,
		  { "Sequence Number", "pgm.poll.sqn", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_poll_round,
		  { "Round", "pgm.poll.round", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_poll_subtype,
		  { "Subtype", "pgm.poll.subtype", FT_UINT16, BASE_HEX,
		    VALS(poll_subtype_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_poll_pathafi,
		  { "Path NLA AFI", "pgm.poll.pathafi", FT_UINT16, BASE_DEC,
		    VALS(afn_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_poll_res,
		  { "Reserved", "pgm.poll.res", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_poll_path,
		  { "Path NLA", "pgm.poll.path.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_poll_path6,
		  { "Path NLA", "pgm.poll.path.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_poll_backoff_ivl,
		  { "Back-off Interval", "pgm.poll.backoff_ivl", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_poll_rand_str,
		  { "Random String", "pgm.poll.rand_str", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_poll_matching_bmask,
		  { "Matching Bitmask", "pgm.poll.matching_bmask", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_polr_sqn,
		  { "Sequence Number", "pgm.polr.sqn", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_polr_round,
		  { "Round", "pgm.polr.round", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_polr_res,
		  { "Reserved", "pgm.polr.res", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_ack_sqn,
		  { "Maximum Received Sequence Number", "pgm.ack.maxsqn", FT_UINT32,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_ack_bitmap,
		  { "Packet Bitmap", "pgm.ack.bitmap", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_type,
		  { "Type", "pgm.opts.type", FT_UINT8, BASE_HEX,
		    VALS(opt_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_len,
		  { "Length", "pgm.opts.len", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_tlen,
		  { "Total Length", "pgm.opts.tlen", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_genopt_end,
		  { "Option end", "pgm.genopts.end", FT_BOOLEAN, 8,
		    TFS(&tfs_yes_no), 0x80, NULL, HFILL }},
		{ &hf_pgm_genopt_type,
		  { "Type", "pgm.genopts.type", FT_UINT8, BASE_HEX,
		    VALS(opt_vals), 0x7f, NULL, HFILL }},
		{ &hf_pgm_genopt_len,
		  { "Length", "pgm.genopts.len", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_genopt_opx,
		  { "Option Extensibility Bits", "pgm.genopts.opx", FT_UINT8, BASE_HEX,
		    VALS(opx_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_parity_prm_po,
		  { "Parity Parameters", "pgm.opts.parity_prm.op", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_parity_prm_prmtgsz,
		  { "Transmission Group Size", "pgm.opts.parity_prm.prm_grp",
		    FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_join_res,
		  { "Reserved", "pgm.opts.join.res", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_join_minjoin,
		  { "Minimum Sequence Number", "pgm.opts.join.min_join",
		    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_parity_grp_res,
		  { "Reserved", "pgm.opts.parity_prm.reserved", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_parity_grp_prmgrp,
		  { "Transmission Group Size", "pgm.opts.parity_prm.prm_grp",
		    FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_nak_res,
		  { "Reserved", "pgm.opts.nak.op", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_nak_list,
		  { "List", "pgm.opts.nak.list", FT_BYTES, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccdata_res,
		  { "Reserved", "pgm.opts.ccdata.res", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccdata_tsp,
		  { "Time Stamp", "pgm.opts.ccdata.tstamp", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccdata_afi,
		  { "Acker AFI", "pgm.opts.ccdata.afi", FT_UINT16, BASE_DEC,
		    VALS(afn_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccdata_res2,
		  { "Reserved", "pgm.opts.ccdata.res2", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccdata_acker,
		  { "Acker", "pgm.opts.ccdata.acker.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccdata_acker6,
		  { "Acker", "pgm.opts.ccdata.acker.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccfeedbk_res,
		  { "Reserved", "pgm.opts.ccdata.res", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccfeedbk_tsp,
		  { "Time Stamp", "pgm.opts.ccdata.tstamp", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccfeedbk_afi,
		  { "Acker AFI", "pgm.opts.ccdata.afi", FT_UINT16, BASE_DEC,
		    VALS(afn_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccfeedbk_lossrate,
		  { "Loss Rate", "pgm.opts.ccdata.lossrate", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccfeedbk_acker,
		  { "Acker", "pgm.opts.ccdata.acker.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_ccfeedbk_acker6,
		  { "Acker", "pgm.opts.ccdata.acker.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_nak_bo_ivl_res,
		  { "Reserved", "pgm.opts.nak_bo_ivl.res", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_nak_bo_ivl_bo_ivl,
		  { "Back-off Interval", "pgm.opts.nak_bo_ivl.bo_ivl", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_nak_bo_ivl_bo_ivl_sqn,
		  { "Back-off Interval Sequence Number", "pgm.opts.nak_bo_ivl.bo_ivl_sqn", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_nak_bo_rng_res,
		  { "Reserved", "pgm.opts.nak_bo_rng.res", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_nak_bo_rng_min_bo_ivl,
		  { "Min Back-off Interval", "pgm.opts.nak_bo_rng.min_bo_ivl", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_nak_bo_rng_max_bo_ivl,
		  { "Max Back-off Interval", "pgm.opts.nak_bo_rng.max_bo_ivl", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_redirect_res,
		  { "Reserved", "pgm.opts.redirect.res", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_redirect_afi,
		  { "DLR AFI", "pgm.opts.redirect.afi", FT_UINT16, BASE_DEC,
		    VALS(afn_vals), 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_redirect_res2,
		  { "Reserved", "pgm.opts.redirect.res2", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_redirect_dlr,
		  { "DLR", "pgm.opts.redirect.dlr.ipv4", FT_IPv4, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_redirect_dlr6,
		  { "DLR", "pgm.opts.redirect.dlr.ipv6", FT_IPv6, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_fragment_res,
		  { "Reserved", "pgm.opts.fragment.res", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_fragment_first_sqn,
		  { "First Sequence Number", "pgm.opts.fragment.first_sqn", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_fragment_offset,
		  { "Fragment Offset", "pgm.opts.fragment.fragment_offset", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},
		{ &hf_pgm_opt_fragment_total_length,
		  { "Total Length", "pgm.opts.fragment.total_length", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }}
	};
	static int *ett[] = {
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
	static ei_register_info ei[] = {
		{ &ei_pgm_opt_type, { "pgm.opts.type.invalid", PI_PROTOCOL, PI_WARN, "Invalid option", EXPFILL }},
		{ &ei_pgm_opt_tlen, { "pgm.opts.tlen.invalid", PI_PROTOCOL, PI_WARN, "Total Length invalid", EXPFILL }},
		{ &ei_pgm_genopt_len, { "pgm.genopts.len.invalid", PI_PROTOCOL, PI_WARN, "Option length invalid", EXPFILL }},
		{ &ei_address_format_invalid, { "pgm.address_format_invalid", PI_PROTOCOL, PI_WARN, "Can't handle this address format", EXPFILL }},
		{ &ei_pgm_main_cksum, { "pgm.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
	};

	module_t *pgm_module;
	expert_module_t* expert_pgm;

	proto_pgm = proto_register_protocol("Pragmatic General Multicast", "PGM", "pgm");

	proto_register_field_array(proto_pgm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_pgm = expert_register_protocol(proto_pgm);
	expert_register_field_array(expert_pgm, ei, array_length(ei));

	/* subdissector code */
	pgm_handle = register_dissector("pgm", dissect_pgm, proto_pgm);
	subdissector_table = register_dissector_table("pgm.port",
						      "PGM port", proto_pgm, FT_UINT16, BASE_DEC);
	heur_subdissector_list = register_heur_dissector_list_with_description("pgm", "PGM data fallback", proto_pgm);

	/*
	 * Register configuration preferences for UDP encapsulation
	 * (Note: Initially the ports are set to zero and the ports
	 *        are not registered so the dissecting of PGM
	 *        encapsulated in UDP packets is off by default;
	 *        dissector_add_for_decode_as is called so that pgm
	 *        is available for 'decode-as'
	 */
	pgm_module = prefs_register_protocol(proto_pgm, NULL);

	prefs_register_bool_preference(pgm_module, "check_checksum",
				       "Check the validity of the PGM checksum when possible",
				       "Whether to check the validity of the PGM checksum",
				       &pgm_check_checksum);
}

/* The registration hand-off routine */
/*
 * Set up PGM Encap dissecting, which is off by default for UDP
 */

void
proto_reg_handoff_pgm(void)
{
	dissector_add_uint_range_with_preference("udp.port", "", pgm_handle);
	dissector_add_uint("ip.proto", IP_PROTO_PGM, pgm_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
