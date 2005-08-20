/* packet-pgm.c
 * Routines for PGM packet disassembly, RFC 3208
 *
 * $Id$
 *
 * Copyright (c) 2000 by Talarian Corp
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include "config.h"
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

/*
 * Flag to control whether to check the PGM checksum.
 */
static gboolean pgm_check_checksum = TRUE;

void proto_reg_handoff_pgm(void);
static void proto_rereg_pgm(void);

typedef guint8 nchar_t;
typedef guint16 nshort_t;
typedef guint32 nlong_t;

/* The PGM main header */
typedef struct {
	nshort_t sport;            /* source port */
	nshort_t dport;            /* destination port */
	nchar_t type;              /* PGM type */
	nchar_t opts;              /* options */
	nshort_t cksum;            /* checksum */
	nchar_t gsi[6];            /* Global Source ID */
	nshort_t tsdulen;          /* TSDU length */
} pgm_type;
#define pgmhdr_ntoh(_p) \
	(_p)->sport = g_ntohs((_p)->sport); \
	(_p)->dport = g_ntohs((_p)->dport); \
	(_p)->type = g_ntohs((_p)->type); \
	(_p)->opts = g_ntohs((_p)->opts); \
	(_p)->cksum = g_ntohs((_p)->cksum); \
	(_p)->tsdulen = g_ntohs((_p)->tsdulen)

/* The PGM SPM header */
typedef struct {
	nlong_t sqn;              /* SPM's sequence number */
	nlong_t trail;            /* Trailing edge sequence number */
	nlong_t lead;             /* Leading edge sequence number */
	nshort_t path_afi;        /* NLA AFI */
	nshort_t res;             /* reserved */
	nlong_t path;             /* Path NLA */
} pgm_spm_t;
#define spm_ntoh(_p) \
	(_p)->sqn = g_ntohl((_p)->sqn); \
	(_p)->trail = g_ntohl((_p)->trail); \
	(_p)->lead = g_ntohl((_p)->lead); \
	(_p)->path_afi = g_ntohs((_p)->path_afi); \
	(_p)->res = g_ntohs((_p)->res);

/* The PGM Data (ODATA/RDATA) header */
typedef struct {
	nlong_t sqn;              /* Data Packet sequence number */
	nlong_t trail;            /* Trailing edge sequence number */
} pgm_data_t;
#define data_ntoh(_p) \
	(_p)->sqn = g_ntohl((_p)->sqn); \
	(_p)->trail = g_ntohl((_p)->trail)

/* The PGM NAK (NAK/N-NAK/NCF) header */
typedef struct {
	nlong_t sqn;             /* Requested sequence number */
	nshort_t src_afi;        /* NLA AFI for source (IPv4 is set to 1) */
	nshort_t src_res;        /* reserved */
	nlong_t src;             /* Source NLA  */
	nshort_t grp_afi;        /* Multicast group AFI (IPv4 is set to 1) */
	nshort_t grp_res;        /* reserved */
	nlong_t grp;             /* Multicast group NLA */
} pgm_nak_t;
#define nak_ntoh(_p) \
	(_p)->sqn = g_ntohl((_p)->sqn); \
	(_p)->src_afi = g_ntohs((_p)->src_afi); \
	(_p)->src_res = g_ntohs((_p)->src_res); \
	(_p)->grp_afi = g_ntohs((_p)->grp_afi); \
	(_p)->grp_res = g_ntohs((_p)->grp_res)

/* The PGM POLL header */
typedef struct {
	nlong_t sqn;             /* POLL sequence number */
	nshort_t round;          /* POLL Round */
	nshort_t subtype;        /* POLL subtype */
	nshort_t path_afi;       /* NLA AFI for last hop router (IPv4 is set to 1) */
	nshort_t res;            /* reserved */
	nlong_t path;            /* Last hop router NLA  */
	nlong_t backoff_ivl;     /* POLL backoff interval */
	nlong_t rand_str;        /* POLL random string */
	nlong_t matching_bmask;  /* POLL matching bitmask */
} pgm_poll_t;
#define poll_ntoh(_p) \
	(_p)->sqn = g_ntohl((_p)->sqn); \
	(_p)->round = g_ntohs((_p)->round); \
	(_p)->subtype = g_ntohs((_p)->subtype); \
	(_p)->path_afi = g_ntohs((_p)->path_afi); \
	(_p)->res = g_ntohs((_p)->res); \
	(_p)->backoff_ivl = g_ntohl((_p)->backoff_ivl); \
	(_p)->rand_str = g_ntohl((_p)->rand_str); \
	(_p)->matching_bmask = g_ntohl((_p)->matching_bmask)

/* The PGM POLR header */
typedef struct {
	nlong_t sqn;             /* POLR sequence number */
	nshort_t round;          /* POLR Round */
	nshort_t res;            /* reserved */
} pgm_polr_t;
#define polr_ntoh(_p) \
	(_p)->sqn = g_ntohl((_p)->sqn); \
	(_p)->round = g_ntohs((_p)->round); \
	(_p)->res = g_ntohs((_p)->res)

/* The PGM ACK header (PGMCC) */
typedef struct {
	nlong_t rx_max_sqn;      /* RX_MAX sequence number */
	nlong_t bitmap;          /* Received Packet Bitmap */
} pgm_ack_t;
#define ack_ntoh(_p) \
	(_p)->rx_max_sqn = g_ntohl((_p)->rx_max_sqn); \
	(_p)->bitmap = g_ntohl((_p)->bitmap)

/* constants for hdr types */
#if defined(PGM_SPEC_01_PCKTS)
/* old spec-01 types */
#define PGM_SPM_PCKT  0x00
#define PGM_ODATA_PCKT  0x10
#define PGM_RDATA_PCKT  0x11
#define PGM_NAK_PCKT  0x20
#define PGM_NNAK_PCKT  0x21
#define PGM_NCF_PCKT 0x30
#else
/* spec-02 types (as well as spec-04+) */
#define PGM_SPM_PCKT  0x00
#define PGM_ODATA_PCKT  0x04
#define PGM_RDATA_PCKT  0x05
#define PGM_NAK_PCKT  0x08
#define PGM_NNAK_PCKT  0x09
#define PGM_NCF_PCKT 0x0A
#define PGM_POLL_PCKT 0x01
#define PGM_POLR_PCKT 0x02
#define PGM_ACK_PCKT 0x0D
#endif /* PGM_SPEC_01_PCKTS */

/* port swapping on NAK and NNAKs or not (default is to swap) */
/* PGM_NO_PORT_SWAP */

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

static const nchar_t PGM_OPT_INVALID = 0x7F;

/* OPX bit values */
#define PGM_OPX_IGNORE	0x00
#define PGM_OPX_INVAL	0x01
#define PGM_OPX_DISCARD	0x10

/* option formats */
typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
} pgm_opt_generic_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nshort_t total_len;
} pgm_opt_length_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
} pgm_opt_nak_list_t;

/*
 * To squeeze the whole option into 255 bytes, we
 * can only have 62 in the list
 */
#define PGM_MAX_NAK_LIST_SZ (62)

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t opt_join_min;
} pgm_opt_join_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t po;
	nlong_t prm_tgsz;
} pgm_opt_parity_prm_t;

/* OPT_PARITY_PRM P and O bits */
static const nchar_t PGM_OPT_PARITY_PRM_PRO = 0x2;
static const nchar_t PGM_OPT_PARITY_PRM_OND = 0x1;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t prm_grp;
} pgm_opt_parity_grp_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t prm_atgsz;
} pgm_opt_curr_tgsize_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t tsp;
	nshort_t acker_afi;
	nshort_t res2;
	nlong_t acker;
} pgm_opt_pgmcc_data_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t tsp;
	nshort_t acker_afi;
	nshort_t loss_rate;
	nlong_t acker;
} pgm_opt_pgmcc_feedback_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t bo_ivl;
	nlong_t bo_ivl_sqn;
} pgm_opt_nak_bo_ivl_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t min_bo_ivl;
	nlong_t max_bo_ivl;
} pgm_opt_nak_bo_rng_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nshort_t afi;
	nshort_t res2;
	nlong_t dlr;
} pgm_opt_redirect_t;

typedef struct {
	nchar_t type;
	nchar_t len;
	nchar_t opx;
	nchar_t res;
	nlong_t first_sqn;
	nlong_t offset;
	nlong_t total_length;
} pgm_opt_fragment_t;

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
static int hf_pgm_data_sqn = -1;
static int hf_pgm_data_trail = -1;
static int hf_pgm_nak_sqn = -1;
static int hf_pgm_nak_srcafi = -1;
static int hf_pgm_nak_srcres = -1;
static int hf_pgm_nak_src = -1;
static int hf_pgm_nak_grpafi = -1;
static int hf_pgm_nak_grpres = -1;
static int hf_pgm_nak_grp = -1;
static int hf_pgm_poll_sqn = -1;
static int hf_pgm_poll_round = -1;
static int hf_pgm_poll_subtype = -1;
static int hf_pgm_poll_pathafi = -1;
static int hf_pgm_poll_res = -1;
static int hf_pgm_poll_path = -1;
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

#ifdef PGM_UNUSED_HANDLES
static int hf_pgm_opt_curr_tgsize_type = -1;
static int hf_pgm_opt_curr_tgsize_len = -1;
static int hf_pgm_opt_curr_tgsize_opx = -1;
static int hf_pgm_opt_curr_tgsize_res = -1;
static int hf_pgm_opt_curr_tgsize_prmatgsz = -1;
#endif

static int hf_pgm_opt_nak_res = -1;
static int hf_pgm_opt_nak_list = -1;

static int hf_pgm_opt_ccdata_res = -1;
static int hf_pgm_opt_ccdata_tsp = -1;
static int hf_pgm_opt_ccdata_afi = -1;
static int hf_pgm_opt_ccdata_res2 = -1;
static int hf_pgm_opt_ccdata_acker = -1;

static int hf_pgm_opt_ccfeedbk_res = -1;
static int hf_pgm_opt_ccfeedbk_tsp = -1;
static int hf_pgm_opt_ccfeedbk_afi = -1;
static int hf_pgm_opt_ccfeedbk_lossrate = -1;
static int hf_pgm_opt_ccfeedbk_acker = -1;

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

static int hf_pgm_opt_fragment_res = -1;
static int hf_pgm_opt_fragment_first_sqn = -1;
static int hf_pgm_opt_fragment_offset = -1;
static int hf_pgm_opt_fragment_total_length = -1;

static dissector_table_t subdissector_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;

/*
 * As of the time this comment was typed
 *
 *	http://search.ietf.org/internet-drafts/draft-speakman-pgm-spec-06.txt
 *
 * was the URL for the PGM draft.
 */

static const char *
optsstr(nchar_t opts)
{
	char *msg;
	char *p;

	msg=ep_alloc(256);
	p=msg;
	if (opts == 0)
		return("");

	if (opts & PGM_OPT){
		p += g_snprintf(p, 256-(p-msg), "Present");
	}
	if (opts & PGM_OPT_NETSIG){
		p += g_snprintf(p, 256-(p-msg), "%sNetSig", (p==msg)?"":",");
	}
	if (opts & PGM_OPT_VAR_PKTLEN){
		p += g_snprintf(p, 256-(p-msg), "%sVarLen", (p==msg)?"":",");
	}
	if (opts & PGM_OPT_PARITY){
		p += g_snprintf(p, 256-(p-msg), "%sParity", (p==msg)?"":",");
	}
	if (p == msg) {
		p += g_snprintf(p, 256-(p-msg), "0x%x", opts);
	}
	return(msg);
}
static const char *
paritystr(nchar_t parity)
{
	char *msg;
	char *p;

	msg=ep_alloc(256);
	p=msg;
	if (parity == 0)
		return("");

	if (parity & PGM_OPT_PARITY_PRM_PRO){
		p += g_snprintf(p, 256-(p-msg), "Pro-active");
	}
	if (parity & PGM_OPT_PARITY_PRM_OND){
		p += g_snprintf(p, 256-(p-msg), "%sOn-demand", (p==msg)?"":",");
	}
	if (p == msg) {
		g_snprintf(p, 256-(p-msg), "%s0x%x", (p==msg)?"":" ", parity);
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

static void
dissect_pgmopts(tvbuff_t *tvb, int offset, proto_tree *tree,
    const char *pktname)
{
	proto_item *tf;
	proto_tree *opts_tree = NULL;
	proto_tree *opt_tree = NULL;
	pgm_opt_length_t opts;
	pgm_opt_generic_t genopts;
	gboolean theend = FALSE, firsttime = TRUE;

	tvb_memcpy(tvb, (guint8 *)&opts, offset, sizeof(opts));
	if (opts.type != PGM_OPT_LENGTH) {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "%s Options - initial option is %s, should be %s",
		    pktname,
		    val_to_str(opts.type, opt_vals, "Unknown (0x%02x)"),
		    val_to_str(PGM_OPT_LENGTH, opt_vals, "Unknown (0x%02x)"));
		return;
	}
	opts.total_len = g_ntohs(opts.total_len);

	if (opts.total_len < 4) {
		proto_tree_add_text(opts_tree, tvb, offset, 4,
			"%s Options (Total Length %u - invalid, must be >= 4)",
			pktname, opts.total_len);
		return;
	}
	tf = proto_tree_add_text(tree, tvb, offset,
		opts.total_len,
		"%s Options (Total Length %d)", pktname, opts.total_len);
	opts_tree = proto_item_add_subtree(tf, ett_pgm_opts);
	proto_tree_add_uint(opts_tree, hf_pgm_opt_type, tvb,
		offset, 1, opts.type);
	proto_tree_add_uint(opts_tree, hf_pgm_opt_len, tvb,
		offset+1, 1, opts.len);
	proto_tree_add_uint(opts_tree, hf_pgm_opt_tlen, tvb,
		offset+2, 2, opts.total_len);

	offset += 4;
	for (opts.total_len -= 4; !theend && opts.total_len != 0;){
		if (opts.total_len < 4) {
			proto_tree_add_text(opts_tree, tvb, offset, opts.total_len,
			    "Remaining total options length doesn't have enough for an options header");
			break;
		}
		tvb_memcpy(tvb, (guint8 *)&genopts, offset, sizeof(genopts));
		if (genopts.type & PGM_OPT_END)  {
			genopts.type &= ~PGM_OPT_END;
			theend = TRUE;
		}
		if (genopts.len < 4) {
			proto_tree_add_text(opts_tree, tvb, offset, genopts.len,
				"Option: %s, Length: %u (invalid, must be >= 4)",
				val_to_str(genopts.type, opt_vals, "Unknown (0x%02x)"),
				genopts.len);
			break;
		}
		if (opts.total_len < genopts.len) {
			proto_tree_add_text(opts_tree, tvb, offset, genopts.len,
			    "Option: %s, Length: %u (> remaining total options length)",
			    val_to_str(genopts.type, opt_vals, "Unknown (0x%02x)"),
			    genopts.len);
			break;
		}
		tf = proto_tree_add_text(opts_tree, tvb, offset, genopts.len,
			"Option: %s, Length: %u",
			val_to_str(genopts.type, opt_vals, "Unknown (0x%02x)"),
			genopts.len);

		switch(genopts.type) {
		case PGM_OPT_JOIN:{
			pgm_opt_join_t optdata;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_join);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_type,
				tvb, offset, 1, genopts.type);

			if (genopts.len < sizeof optdata) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					offset+1, 1, genopts.len,
					"Length: %u (bogus, must be >= %lu)",
					genopts.len,
					(unsigned long)sizeof optdata);
				break;
			}
			proto_tree_add_uint(opt_tree, hf_pgm_genopt_len, tvb,
				offset+1, 1, genopts.len);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_opx, tvb,
				offset+2, 1, genopts.opx);

			tvb_memcpy(tvb, (guint8 *)&optdata, offset, sizeof(optdata));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_join_res, tvb,
				offset+3, 1, optdata.res);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_join_minjoin, tvb,
				offset+4, 4, g_ntohl(optdata.opt_join_min));

			break;
		}
		case PGM_OPT_PARITY_PRM:{
			pgm_opt_parity_prm_t optdata;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_parityprm);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_type,
				tvb, offset, 1, genopts.type);

			if (genopts.len < sizeof optdata) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					offset+1, 1, genopts.len,
					"Length: %u (bogus, must be >= %lu)",
					genopts.len,
					(unsigned long) sizeof optdata);
				break;
			}
			proto_tree_add_uint(opt_tree, hf_pgm_genopt_len, tvb,
				offset+1, 1, genopts.len);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_opx,
				tvb, offset+2, 1, genopts.opx);

			tvb_memcpy(tvb, (guint8 *)&optdata, offset, sizeof(optdata));

			proto_tree_add_uint_format(opt_tree, hf_pgm_opt_parity_prm_po, tvb,
				offset+3, 1, optdata.po, "Parity Parameters: %s (0x%x)",
				paritystr(optdata.po), optdata.po);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_parity_prm_prmtgsz,
				tvb, offset+4, 4, g_ntohl(optdata.prm_tgsz));

			break;
		}
		case PGM_OPT_PARITY_GRP:{
			pgm_opt_parity_grp_t optdata;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_paritygrp);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_type,
				tvb, offset, 1, genopts.type);

			if (genopts.len < sizeof optdata) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					offset+1, 1, genopts.len,
					"Length: %u (bogus, must be >= %lu)",
					genopts.len,
					(unsigned long) sizeof optdata);
				break;
			}
			proto_tree_add_uint(opt_tree, hf_pgm_genopt_len, tvb,
				offset+1, 1, genopts.len);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_opx,
				tvb, offset+2, 1, genopts.opx);

			tvb_memcpy(tvb, (guint8 *)&optdata, offset, sizeof(optdata));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_parity_grp_res, tvb,
				offset+3, 1, optdata.res);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_parity_grp_prmgrp,
				tvb, offset+4, 4, g_ntohl(optdata.prm_grp));

			break;
		}
		case PGM_OPT_NAK_LIST:{
			pgm_opt_nak_list_t optdata;
			nlong_t naklist[PGM_MAX_NAK_LIST_SZ+1];
			char *nakbuf, *ptr;
			int i, j, naks, soffset = 0;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_naklist);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_type, tvb,
				offset, 1, genopts.type);

			if (genopts.len < sizeof optdata) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					offset+1, 1, genopts.len,
					"Length: %u (bogus, must be >= %lu)",
					genopts.len,
					(unsigned long) sizeof optdata);
				break;
			}
			proto_tree_add_uint(opt_tree, hf_pgm_genopt_len, tvb,
				offset+1, 1, genopts.len);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_opx,
				tvb, offset+2, 1, genopts.opx);

			tvb_memcpy(tvb, (guint8 *)&optdata, offset, sizeof(optdata));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_nak_res, tvb,
				offset+3, 1, optdata.res);

			optdata.len -= sizeof(pgm_opt_nak_list_t);
			tvb_memcpy(tvb, (guint8 *)naklist, offset+4, optdata.len);
			naks = (optdata.len/sizeof(nlong_t));
			nakbuf=ep_alloc(8192);
			nakbuf[0]=0;
			soffset=0;
			ptr = nakbuf;
			j = 0;
			/*
			 * Print out 8 per line
			 */
			for (i=0; i < naks; i++) {
				soffset += g_snprintf(nakbuf+soffset, 8192-soffset, "0x%lx ",
				    (unsigned long)g_ntohl(naklist[i]));
				if ((++j % 8) == 0) {
					if (firsttime) {
						proto_tree_add_bytes_format(opt_tree,
							hf_pgm_opt_nak_list, tvb, offset+4, optdata.len,
							nakbuf, "List(%d): %s", naks, nakbuf);
							soffset = 0;
					} else {
						proto_tree_add_bytes_format(opt_tree,
							hf_pgm_opt_nak_list, tvb, offset+4, optdata.len,
							nakbuf, "List: %s", nakbuf);
							soffset = 0;
					}
					firsttime = FALSE;
				}
			}
			if (soffset) {
				if (firsttime) {
					proto_tree_add_bytes_format(opt_tree,
						hf_pgm_opt_nak_list, tvb, offset+4, optdata.len,
						nakbuf, "List(%d): %s", naks, nakbuf);
						soffset = 0;
				} else {
					proto_tree_add_bytes_format(opt_tree,
						hf_pgm_opt_nak_list, tvb, offset+4, optdata.len,
						nakbuf, "List: %s", nakbuf);
						soffset = 0;
				}
			}
			break;
		}
		case PGM_OPT_PGMCC_DATA:{
			pgm_opt_pgmcc_data_t optdata;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_ccdata);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_type,
				tvb, offset, 1, genopts.type);

			if (genopts.len < sizeof optdata) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					offset+1, 1, genopts.len,
					"Length: %u (bogus, must be >= %lu)",
					genopts.len,
					(unsigned long) sizeof optdata);
				break;
			}
			proto_tree_add_uint(opt_tree, hf_pgm_genopt_len, tvb,
				offset+1, 1, genopts.len);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_opx,
				tvb, offset+2, 1, genopts.opx);

			tvb_memcpy(tvb, (guint8 *)&optdata, offset, sizeof(optdata));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_ccdata_res, tvb,
				offset+3, 1, optdata.res);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_ccdata_tsp, tvb,
				offset+4, 4, optdata.tsp);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_ccdata_afi, tvb,
				offset+8, 2, g_ntohs(optdata.acker_afi));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_ccdata_res2, tvb,
				offset+10, 2, g_ntohs(optdata.res2));

			switch (g_ntohs(optdata.acker_afi)) {

			case AFNUM_INET:
				proto_tree_add_ipv4(opt_tree, hf_pgm_opt_ccdata_acker,
				    tvb, offset+12, 4, optdata.acker);
				break;

			default:
				/*
				 * XXX - the header is variable-length,
				 * as the length of the NLA depends on
				 * its AFI.
				 *
				 * However, our structure for it is
				 * fixed-length, and assumes it's a 4-byte
				 * IPv4 address.
				 */
				break;
			}

			break;
		}
		case PGM_OPT_PGMCC_FEEDBACK:{
			pgm_opt_pgmcc_feedback_t optdata;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_ccdata);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_type,
				tvb, offset, 1, genopts.type);

			if (genopts.len < sizeof optdata) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					offset+1, 1, genopts.len,
					"Length: %u (bogus, must be >= %lu)",
					genopts.len,
					(unsigned long) sizeof optdata);
				break;
			}
			proto_tree_add_uint(opt_tree, hf_pgm_genopt_len, tvb,
				offset+1, 1, genopts.len);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_opx,
				tvb, offset+2, 1, genopts.opx);

			tvb_memcpy(tvb, (guint8 *)&optdata, offset, sizeof(optdata));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_ccfeedbk_res, tvb,
				offset+3, 1, optdata.res);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_ccfeedbk_tsp, tvb,
				offset+4, 4, optdata.tsp);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_ccfeedbk_afi, tvb,
				offset+8, 2, g_ntohs(optdata.acker_afi));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_ccfeedbk_lossrate, tvb,
				offset+10, 2, g_ntohs(optdata.loss_rate));

			switch (g_ntohs(optdata.acker_afi)) {

			case AFNUM_INET:
				proto_tree_add_ipv4(opt_tree, hf_pgm_opt_ccfeedbk_acker,
				    tvb, offset+12, 4, optdata.acker);
				break;

			default:
				/*
				 * XXX - the header is variable-length,
				 * as the length of the NLA depends on
				 * its AFI.
				 *
				 * However, our structure for it is
				 * fixed-length, and assumes it's a 4-byte
				 * IPv4 address.
				 */
				break;
			}

			break;
		}
		case PGM_OPT_NAK_BO_IVL:{
			pgm_opt_nak_bo_ivl_t optdata;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_nak_bo_ivl);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_type,
				tvb, offset, 1, genopts.type);

			if (genopts.len < sizeof optdata) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					offset+1, 1, genopts.len,
					"Length: %u (bogus, must be >= %lu)",
					genopts.len,
					(unsigned long) sizeof optdata);
				break;
			}
			proto_tree_add_uint(opt_tree, hf_pgm_genopt_len, tvb,
				offset+1, 1, genopts.len);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_opx, tvb,
				offset+2, 1, genopts.opx);

			tvb_memcpy(tvb, (guint8 *)&optdata, offset, sizeof(optdata));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_nak_bo_ivl_res, tvb,
				offset+3, 1, optdata.res);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_nak_bo_ivl_bo_ivl, tvb,
				offset+4, 4, g_ntohl(optdata.bo_ivl));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_nak_bo_ivl_bo_ivl_sqn, tvb,
				offset+8, 4, g_ntohl(optdata.bo_ivl_sqn));

			break;
		}
		case PGM_OPT_NAK_BO_RNG:{
			pgm_opt_nak_bo_rng_t optdata;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_nak_bo_rng);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_type,
				tvb, offset, 1, genopts.type);

			if (genopts.len < sizeof optdata) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					offset+1, 1, genopts.len,
					"Length: %u (bogus, must be >= %lu)",
					genopts.len,
					(unsigned long) sizeof optdata);
				break;
			}
			proto_tree_add_uint(opt_tree, hf_pgm_genopt_len, tvb,
				offset+1, 1, genopts.len);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_opx, tvb,
				offset+2, 1, genopts.opx);

			tvb_memcpy(tvb, (guint8 *)&optdata, offset, sizeof(optdata));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_nak_bo_rng_res, tvb,
				offset+3, 1, optdata.res);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_nak_bo_rng_min_bo_ivl, tvb,
				offset+4, 4, g_ntohl(optdata.min_bo_ivl));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_nak_bo_rng_max_bo_ivl, tvb,
				offset+8, 4, g_ntohl(optdata.max_bo_ivl));

			break;
		}
		case PGM_OPT_REDIRECT:{
			pgm_opt_redirect_t optdata;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_redirect);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_type,
				tvb, offset, 1, genopts.type);

			if (genopts.len < sizeof optdata) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					offset+1, 1, genopts.len,
					"Length: %u (bogus, must be >= %lu)",
					genopts.len,
					(unsigned long) sizeof optdata);
				break;
			}
			proto_tree_add_uint(opt_tree, hf_pgm_genopt_len, tvb,
				offset+1, 1, genopts.len);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_opx,
				tvb, offset+2, 1, genopts.opx);

			tvb_memcpy(tvb, (guint8 *)&optdata, offset, sizeof(optdata));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_redirect_res, tvb,
				offset+3, 1, optdata.res);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_redirect_afi, tvb,
				offset+4, 2, g_ntohs(optdata.afi));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_redirect_res2, tvb,
				offset+6, 2, g_ntohs(optdata.res2));

			switch (g_ntohs(optdata.afi)) {

			case AFNUM_INET:
				proto_tree_add_ipv4(opt_tree, hf_pgm_opt_redirect_dlr,
				    tvb, offset+8, 4, optdata.dlr);
				break;

			default:
				/*
				 * XXX - the header is variable-length,
				 * as the length of the NLA depends on
				 * its AFI.
				 *
				 * However, our structure for it is
				 * fixed-length, and assumes it's a 4-byte
				 * IPv4 address.
				 */
				break;
			}

			break;
		}
		case PGM_OPT_FRAGMENT:{
			pgm_opt_fragment_t optdata;

			opt_tree = proto_item_add_subtree(tf, ett_pgm_opts_fragment);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_type,
				tvb, offset, 1, genopts.type);

			if (genopts.len < sizeof optdata) {
				proto_tree_add_uint_format(opt_tree, hf_pgm_genopt_len, tvb,
					offset+1, 1, genopts.len,
					"Length: %u (bogus, must be >= %lu)",
					genopts.len,
					(unsigned long) sizeof optdata);
				break;
			}
			proto_tree_add_uint(opt_tree, hf_pgm_genopt_len, tvb,
				offset+1, 1, genopts.len);

			proto_tree_add_uint(opt_tree, hf_pgm_genopt_opx, tvb,
				offset+2, 1, genopts.opx);

			tvb_memcpy(tvb, (guint8 *)&optdata, offset, sizeof(optdata));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_fragment_res, tvb,
				offset+3, 1, optdata.res);

			proto_tree_add_uint(opt_tree, hf_pgm_opt_fragment_first_sqn, tvb,
				offset+4, 4, g_ntohl(optdata.first_sqn));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_fragment_offset, tvb,
				offset+8, 4, g_ntohl(optdata.offset));

			proto_tree_add_uint(opt_tree, hf_pgm_opt_fragment_total_length, tvb,
				offset+12, 4, g_ntohl(optdata.total_length));

			break;
		}
		}
		offset += genopts.len;
		opts.total_len -= genopts.len;

	}
	return ;
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
	proto_tree *tree, pgm_type *pgmhdr)
{
  tvbuff_t *next_tvb;
  int found = 0;

  next_tvb = tvb_new_subset(tvb, offset, -1, -1);

  /* do lookup with the subdissector table */
  found = dissector_try_port(subdissector_table, pgmhdr->sport,
			next_tvb, pinfo, tree);
  if (found)
	return;

  found = dissector_try_port(subdissector_table, pgmhdr->dport,
			next_tvb, pinfo, tree);
  if (found)
	return;

  /* do lookup with the heuristic subdissector table */
  if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree))
    return;

  /* Oh, well, we don't know this; dissect it as data. */
  call_dissector(data_handle,next_tvb, pinfo, tree);

}
static int
total_size(tvbuff_t *tvb, pgm_type *hdr)
{
	int bytes = sizeof(pgm_type);
	pgm_opt_length_t opts;

	switch(hdr->type) {
	case PGM_SPM_PCKT:
		bytes += sizeof(pgm_spm_t);
		break;

	case PGM_RDATA_PCKT:
	case PGM_ODATA_PCKT:
		bytes += sizeof(pgm_data_t);
		break;

	case PGM_NAK_PCKT:
	case PGM_NNAK_PCKT:
	case PGM_NCF_PCKT:
		bytes += sizeof(pgm_nak_t);
		break;
	case PGM_POLL_PCKT:
		bytes += sizeof(pgm_poll_t);
		break;
	case PGM_POLR_PCKT:
		bytes += sizeof(pgm_polr_t);
		break;
	case PGM_ACK_PCKT:
		bytes += sizeof(pgm_ack_t);
		break;
	}
	if ((hdr->opts & PGM_OPT)) {
		tvb_memcpy(tvb, (guint8 *)&opts, bytes, sizeof(opts));
		bytes += g_ntohs(opts.total_len);
	}
	return(bytes);
}
/*
 * dissect_pgm - The dissector for Pragmatic General Multicast
 */
static void
dissect_pgm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *pgm_tree = NULL;
	proto_tree *opt_tree = NULL;
	proto_tree *type_tree = NULL;
	proto_item *tf;
	pgm_type pgmhdr;
	pgm_spm_t spm;
	pgm_data_t data;
	pgm_nak_t nak;
	pgm_poll_t poll;
	pgm_polr_t polr;
	pgm_ack_t ack;
	int offset = 0;
	guint hlen, plen;
	proto_item *ti;
	const char *pktname;
	const char *pollstname;
	char *gsi;
	int isdata = 0;
	guint pgmlen, reportedlen;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PGM");

	/* Clear out the Info column. */
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	tvb_memcpy(tvb, (guint8 *)&pgmhdr, offset, sizeof(pgm_type));
	hlen = sizeof(pgm_type);
	pgmhdr.sport = g_ntohs(pgmhdr.sport);
	pgmhdr.dport = g_ntohs(pgmhdr.dport);
	pgmhdr.tsdulen = g_ntohs(pgmhdr.tsdulen);
	pgmhdr.cksum = g_ntohs(pgmhdr.cksum);

	pktname = val_to_str(pgmhdr.type, type_vals, "Unknown (0x%02x)");

	gsi = bytes_to_str(pgmhdr.gsi, 6);
	switch(pgmhdr.type) {
	case PGM_SPM_PCKT:
		plen = sizeof(pgm_spm_t);
		tvb_memcpy(tvb, (guint8 *)&spm, sizeof(pgm_type), plen);
		spm_ntoh(&spm);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"%-5s sqn 0x%x gsi %s", pktname, spm.sqn, gsi);
		}
		break;

	case PGM_RDATA_PCKT:
	case PGM_ODATA_PCKT:
		plen = sizeof(pgm_data_t);
		tvb_memcpy(tvb, (guint8 *)&data, sizeof(pgm_type), plen);
		data_ntoh(&data);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "%-5s sqn 0x%x gsi %s tsdulen %d", pktname, data.sqn, gsi,
			    pgmhdr.tsdulen);
		}
		isdata = 1;
		break;

	case PGM_NAK_PCKT:
	case PGM_NNAK_PCKT:
	case PGM_NCF_PCKT:
		plen = sizeof(pgm_nak_t);
		tvb_memcpy(tvb, (guint8 *)&nak, sizeof(pgm_type), plen);
		nak_ntoh(&nak);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"%-5s sqn 0x%x gsi %s", pktname, nak.sqn, gsi);
		}
		break;
	case PGM_POLL_PCKT:
		plen = sizeof(pgm_poll_t);
		tvb_memcpy(tvb, (guint8 *)&poll, sizeof(pgm_type), plen);
		poll_ntoh(&poll);
		pollstname = val_to_str(poll.subtype, poll_subtype_vals, "Unknown (0x%02x)");
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"%-5s sqn 0x%x gsi %s subtype %s", pktname, poll.sqn, gsi, pollstname);
		}
		break;
	case PGM_POLR_PCKT:
		plen = sizeof(pgm_polr_t);
		tvb_memcpy(tvb, (guint8 *)&polr, sizeof(pgm_type), plen);
		polr_ntoh(&polr);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				"%-5s sqn 0x%x gsi %s", pktname, polr.sqn, gsi);
		}
		break;
	case PGM_ACK_PCKT:
		plen = sizeof(pgm_ack_t);
		tvb_memcpy(tvb, (guint8 *)&ack, sizeof(pgm_type), plen);
		ack_ntoh(&ack);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "%-5s sqn 0x%x gsi %s", pktname, ack.rx_max_sqn, gsi);
		}
		break;

	default:
		return;
	}

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_pgm,
			tvb, offset, total_size(tvb, &pgmhdr),
			"Pragmatic General Multicast: Type %s"
			    " SrcPort %u, DstPort %u, GSI %s", pktname,
			pgmhdr.sport, pgmhdr.dport,
			bytes_to_str(pgmhdr.gsi, 6));

		pgm_tree = proto_item_add_subtree(ti, ett_pgm);
		proto_tree_add_uint(pgm_tree, hf_pgm_main_sport, tvb, offset, 2,
			pgmhdr.sport);
		proto_tree_add_uint_hidden(pgm_tree, hf_pgm_port, tvb, offset, 2,
			pgmhdr.sport);
		proto_tree_add_uint(pgm_tree, hf_pgm_main_dport, tvb, offset+2,
			2, pgmhdr.dport);
		proto_tree_add_uint_hidden(pgm_tree, hf_pgm_port, tvb, offset+2,
			2, pgmhdr.dport);
		
		proto_tree_add_uint(pgm_tree, hf_pgm_main_type, tvb,
			offset+4, 1, pgmhdr.type);

		tf = proto_tree_add_uint_format(pgm_tree, hf_pgm_main_opts, tvb,
			offset+5, 1, pgmhdr.opts, "Options: %s (0x%x)",
			optsstr(pgmhdr.opts), pgmhdr.opts);
		opt_tree = proto_item_add_subtree(tf, ett_pgm_optbits);

		proto_tree_add_boolean(opt_tree, hf_pgm_main_opts_opt, tvb,
			offset+5, 1, (pgmhdr.opts & PGM_OPT));
		proto_tree_add_boolean(opt_tree, hf_pgm_main_opts_netsig, tvb,
			offset+5, 1, (pgmhdr.opts & PGM_OPT_NETSIG));
		proto_tree_add_boolean(opt_tree, hf_pgm_main_opts_varlen, tvb,
			offset+5, 1, (pgmhdr.opts & PGM_OPT_VAR_PKTLEN));
		proto_tree_add_boolean(opt_tree, hf_pgm_main_opts_parity, tvb,
			offset+5, 1, (pgmhdr.opts & PGM_OPT_PARITY));

		reportedlen = tvb_reported_length(tvb);
		pgmlen = tvb_length(tvb);
		if (pgm_check_checksum && pgmlen >= reportedlen) {
			vec_t cksum_vec[1];
			guint16 computed_cksum;

			cksum_vec[0].ptr = tvb_get_ptr(tvb, offset, pgmlen);
			cksum_vec[0].len = pgmlen;
			computed_cksum = in_cksum(&cksum_vec[0], 1);
			if (computed_cksum == 0) {
				proto_tree_add_uint_format(pgm_tree, hf_pgm_main_cksum, tvb,
					offset+6, 2, pgmhdr.cksum, "Checksum: 0x%04x [correct]", pgmhdr.cksum);
			} else {
				proto_tree_add_boolean_hidden(pgm_tree, hf_pgm_main_cksum_bad, tvb,
				    offset+6, 2, TRUE);
				proto_tree_add_uint_format(pgm_tree, hf_pgm_main_cksum, tvb,
				    offset+6, 2, pgmhdr.cksum, "Checksum: 0x%04x [incorrect, should be 0x%04x]",
					pgmhdr.cksum, in_cksum_shouldbe(pgmhdr.cksum, computed_cksum));
			}
		} else {
			proto_tree_add_uint(pgm_tree, hf_pgm_main_cksum, tvb, offset+6,
				2, pgmhdr.cksum);
		}

		proto_tree_add_bytes(pgm_tree, hf_pgm_main_gsi, tvb, offset+8,
			6, pgmhdr.gsi);
		proto_tree_add_uint(pgm_tree, hf_pgm_main_tsdulen, tvb,
			offset+14, 2, pgmhdr.tsdulen);

		offset = sizeof(pgm_type);
		tf = proto_tree_add_text(pgm_tree, tvb, offset, plen, "%s Packet",
			pktname);
		switch(pgmhdr.type) {
		case PGM_SPM_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_spm);

			proto_tree_add_uint(type_tree, hf_pgm_spm_sqn, tvb,
				offset, 4, spm.sqn);
			proto_tree_add_uint(type_tree, hf_pgm_spm_trail, tvb,
				offset+4, 4, spm.trail);
			proto_tree_add_uint(type_tree, hf_pgm_spm_lead, tvb,
				offset+8, 4, spm.lead);
			proto_tree_add_uint(type_tree, hf_pgm_spm_pathafi, tvb,
				offset+12, 2, spm.path_afi);
			proto_tree_add_uint(type_tree, hf_pgm_spm_res, tvb,
				offset+14, 2, spm.res);
			switch (spm.path_afi) {

			case AFNUM_INET:
				proto_tree_add_ipv4(type_tree, hf_pgm_spm_path,
				    tvb, offset+16, 4, spm.path);
				break;

			default:
				/*
				 * XXX - the header is variable-length,
				 * as the length of the NLA depends on
				 * its AFI.
				 *
				 * However, our structure for it is
				 * fixed-length, and assumes it's a 4-byte
				 * IPv4 address.
				 */
				return;
			}

			if ((pgmhdr.opts & PGM_OPT) == FALSE)
				break;
			offset += plen;

			dissect_pgmopts(tvb, offset, type_tree, pktname);

			break;

		case PGM_RDATA_PCKT:
		case PGM_ODATA_PCKT: {
			type_tree = proto_item_add_subtree(tf, ett_pgm_data);

			proto_tree_add_uint(type_tree, hf_pgm_spm_sqn, tvb,
				offset, 4, data.sqn);
			proto_tree_add_uint(type_tree, hf_pgm_spm_trail, tvb,
				offset+4, 4, data.trail);

			if ((pgmhdr.opts & PGM_OPT) == FALSE)
				break;
			offset += plen;

			dissect_pgmopts(tvb, offset, type_tree, pktname);

			break;
		}


		case PGM_NAK_PCKT:
		case PGM_NNAK_PCKT:
		case PGM_NCF_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_nak);

			proto_tree_add_uint(type_tree, hf_pgm_nak_sqn, tvb,
				offset, 4, nak.sqn);
			proto_tree_add_uint(type_tree, hf_pgm_nak_srcafi, tvb,
				offset+4, 2, nak.src_afi);
			proto_tree_add_uint(type_tree, hf_pgm_nak_srcres, tvb,
				offset+6, 2, nak.src_res);

			switch (nak.src_afi) {

			case AFNUM_INET:
				proto_tree_add_ipv4(type_tree, hf_pgm_nak_src,
				    tvb, offset+8, 4, nak.src);
				break;

			default:
				/*
				 * XXX - the header is variable-length,
				 * as the length of the NLA depends on
				 * its AFI.
				 *
				 * However, our structure for it is
				 * fixed-length, and assumes it's a 4-byte
				 * IPv4 address.
				 */
				break;
			}

			proto_tree_add_uint(type_tree, hf_pgm_nak_grpafi, tvb,
				offset+12, 2, nak.grp_afi);
			proto_tree_add_uint(type_tree, hf_pgm_nak_grpres, tvb,
				offset+14, 2, nak.grp_res);

			switch (nak.grp_afi) {

			case AFNUM_INET:
				proto_tree_add_ipv4(type_tree, hf_pgm_nak_grp,
				    tvb, offset+16, 4, nak.grp);
				break;

			default:
				/*
				 * XXX - the header is variable-length,
				 * as the length of the NLA depends on
				 * its AFI.
				 *
				 * However, our structure for it is
				 * fixed-length, and assumes it's a 4-byte
				 * IPv4 address.
				 */
				return;
			}

			if ((pgmhdr.opts & PGM_OPT) == FALSE)
				break;
			offset += plen;

			dissect_pgmopts(tvb, offset, type_tree, pktname);

			break;
		case PGM_POLL_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_poll);

			proto_tree_add_uint(type_tree, hf_pgm_poll_sqn, tvb,
				offset, 4, poll.sqn);
			proto_tree_add_uint(type_tree, hf_pgm_poll_round, tvb,
				offset+4, 2, poll.round);
			proto_tree_add_uint(type_tree, hf_pgm_poll_subtype, tvb,
				offset+6, 2, poll.subtype);
			proto_tree_add_uint(type_tree, hf_pgm_poll_pathafi, tvb,
				offset+8, 2, poll.path_afi);
			proto_tree_add_uint(type_tree, hf_pgm_poll_res, tvb,
				offset+10, 2, poll.res);

			switch (poll.path_afi) {

			case AFNUM_INET:
				proto_tree_add_ipv4(type_tree, hf_pgm_poll_path,
				    tvb, offset+12, 4, poll.path);
				break;

			default:
				/*
				 * XXX - the header is variable-length,
				 * as the length of the NLA depends on
				 * its AFI.
				 *
				 * However, our structure for it is
				 * fixed-length, and assumes it's a 4-byte
				 * IPv4 address.
				 */
				break;
			}

			proto_tree_add_uint(type_tree, hf_pgm_poll_backoff_ivl, tvb,
				offset+16, 4, poll.backoff_ivl);
			proto_tree_add_uint(type_tree, hf_pgm_poll_rand_str, tvb,
				offset+20, 4, poll.rand_str);
			proto_tree_add_uint(type_tree, hf_pgm_poll_matching_bmask, tvb,
				offset+24, 4, poll.matching_bmask);

			if ((pgmhdr.opts & PGM_OPT) == FALSE)
				break;
			offset += plen;

			dissect_pgmopts(tvb, offset, type_tree, pktname);

			break;
		case PGM_POLR_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_polr);

			proto_tree_add_uint(type_tree, hf_pgm_polr_sqn, tvb,
				offset, 4, polr.sqn);
			proto_tree_add_uint(type_tree, hf_pgm_polr_round, tvb,
				offset+4, 2, polr.round);
			proto_tree_add_uint(type_tree, hf_pgm_polr_res, tvb,
				offset+6, 2, polr.res);

			if ((pgmhdr.opts & PGM_OPT) == FALSE)
				break;
			offset += plen;

			dissect_pgmopts(tvb, offset, type_tree, pktname);

			break;
		case PGM_ACK_PCKT:
			type_tree = proto_item_add_subtree(tf, ett_pgm_ack);

			proto_tree_add_uint(type_tree, hf_pgm_ack_sqn, tvb,
				offset, 4, ack.rx_max_sqn);
			proto_tree_add_uint(type_tree, hf_pgm_ack_bitmap, tvb,
				offset+4, 4, ack.bitmap);

			if ((pgmhdr.opts & PGM_OPT) == FALSE)
				break;
			offset += plen;

			dissect_pgmopts(tvb, offset, type_tree, pktname);

			break;
		}

	}
	if (isdata) {
		/*
		 * Now see if there are any sub-dissectors, if so call them
		 */
		offset = total_size(tvb, &pgmhdr);
		decode_pgm_ports(tvb, offset, pinfo, tree, &pgmhdr);
	}
	pktname = NULL;
}
static const true_false_string opts_present = {
	"Present",
	"Not Present"
};

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
      { "Options", "pgm.hdr.opts.opt", FT_BOOLEAN, BASE_NONE,
	  TFS(&opts_present), PGM_OPT, "", HFILL }},
    { &hf_pgm_main_opts_netsig,
      { "Network Significant Options", "pgm.hdr.opts.netsig",
	  FT_BOOLEAN, BASE_NONE,
	  TFS(&opts_present), PGM_OPT_NETSIG, "", HFILL }},
    { &hf_pgm_main_opts_varlen,
      { "Variable length Parity Packet Option", "pgm.hdr.opts.varlen",
	  FT_BOOLEAN, BASE_NONE,
	  TFS(&opts_present), PGM_OPT_VAR_PKTLEN, "", HFILL }},
    { &hf_pgm_main_opts_parity,
      { "Parity", "pgm.hdr.opts.parity", FT_BOOLEAN, BASE_NONE,
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
    { &hf_pgm_nak_grpafi,
      { "Multicast Group AFI", "pgm.nak.grpafi", FT_UINT16, BASE_DEC,
	  VALS(afn_vals), 0x0, "", HFILL }},
    { &hf_pgm_nak_grpres,
      { "Reserved", "pgm.nak.grpres", FT_UINT16, BASE_HEX,
	  NULL, 0x0, "", HFILL }},
    { &hf_pgm_nak_grp,
      { "Multicast Group NLA", "pgm.nak.grp", FT_IPv4, BASE_NONE,
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
	  NULL, 0x0, "", HFILL }},
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
	&ett_pgm_opts_fragment,
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
