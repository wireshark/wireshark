/* packet-ax25.c
 *
 * Routines for Amateur Packet Radio protocol dissection
 * AX.25 frames
 * Copyright 2005,2006,2007,2008,2009,2010,2012 R.W. Stearn <richard@rns-stearn.demon.co.uk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This dissector is for:
 * AX.25 Amateur Packet-Radio Link-Layer Protocol, Version 2.0, October 1984
 *
 * At the time of writing the specification could be found here:
 *   http://www.tapr.org/pub_ax25.html
 *
 * A newer version, Version 2.2, July 1998, can be found at
 *   http://www.ax25.net/AX25.2.2-Jul%2098-2.pdf
 *
 * The link tracking follows the Version 2.2 revision of September 2017
 * (referred to as "the spec" below; section numbers are from it).
 *
 * Inspiration on how to build the dissector drawn from
 *   packet-sdlc.c
 *   packet-x25.c
 *   packet-lapb.c
 *   packet-gprs-llc.c
 *   xdlc.c
 * with the base file built from README.developers.
 */

/*
 * Link tracking
 * -------------
 * Every frame belongs to a link, identified by the two station addresses,
 * the KISS port and the capture interface (see ax25_link_key()). A link is
 * a conversation; a new conversation starts at each connection attempt.
 * UI frames are connectionless (section 6.3.7): they are tracked with the
 * link (digipeated copies, segments), but they don't count as traffic of
 * the connection and get no ax25.stream index. A stream index is only
 * allocated when the first other frame shows up.
 *
 * State is only updated on the first pass, in frame order. Everything a
 * later pass needs is copied into a per-packet ax25_pkt_t, so the output
 * doesn't depend on -2 or on the order frames are dissected in later.
 * That also means nothing is decided retroactively: a frame is decoded
 * with what was known when it was first seen.
 *
 * The modulo (8 or 128) of I and S frames comes from the link: SABME
 * followed by a UA in the other direction sets 128, SABM followed by UA
 * sets 8, from the UA on. If the capture starts mid-session it is
 * inferred from the first decisive S frame, and assumed to be 8 until
 * then.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/to_str.h>
#include <epan/prefs.h>
#include <epan/tfs.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/unit_strings.h>
#include <wsutil/strtoi.h>
#include "packet-ax25.h"
#include "packet-xdlc.h"
#include <epan/iana-info.h>

#define STRLEN	80

#define AX25_HEADER_SIZE	15 /* length of src_addr + dst_addr + cntl */
#define AX25_MAX_DIGIS		 8

/* SSID octet: CRRSSSSx (destination/source), HRRSSSSx (repeater) */
#define AX25_SSID_CR		0x80	/* C bit (dst/src) or H bit (repeater) */
#define AX25_SSID_SSID		0x1E	/* the SSID itself */
#define AX25_SSID_EXT		0x01	/* HDLC address extension bit */

/*
 * Link key values used when the information isn't available. A frame
 * without a KISS port shares the value with KISS port 0; they can't be
 * confused, as KISS and other AX.25 encapsulations don't share a capture
 * interface, and the interface is part of the key.
 */
#define AX25_NO_PORT		0
#define AX25_NO_INTERFACE	0xFFFFFFFFU

/*
 * Direction of a frame on a link, relative to the canonical order of the
 * two masked addresses (see ax25_mask_address()).
 */
#define AX25_DIR_LO_HI		0	/* source is the lower address */
#define AX25_DIR_HI_LO		1	/* source is the higher address */

/* Bits 4-7 of the first octet of a modulo 128 S frame are always 0 (Figure 4.1b) */
#define AX25_S128_ZERO_BITS	0xF0

void proto_register_ax25(void);
void proto_reg_handoff_ax25(void);

/* Dissector table */
static dissector_table_t ax25_dissector_table;

static capture_dissector_handle_t ax25_cap_handle;

/* Initialize the protocol and registered fields */
static int proto_ax25;
static int hf_ax25_dst;
static int hf_ax25_src;
static int hf_ax25_via[ AX25_MAX_DIGIS ];

static int hf_ax25_ctl;
static int hf_ax25_ctl_ext;

static int hf_ax25_n_r;
static int hf_ax25_n_r_ext;
static int hf_ax25_n_s;
static int hf_ax25_n_s_ext;

static int hf_ax25_p;
static int hf_ax25_f;
static int hf_ax25_p_ext;
static int hf_ax25_f_ext;
static int hf_ax25_pf;
static int hf_ax25_pf_ext;

static int hf_ax25_ftype_s;
static int hf_ax25_ftype_s_ext;
static int hf_ax25_ftype_i;
static int hf_ax25_ftype_i_ext;
static int hf_ax25_ftype_su;
static int hf_ax25_ftype_su_ext;

static int hf_ax25_u_cmd;
static int hf_ax25_u_resp;

static int hf_ax25_pid;

static int hf_ax25_stream;
static int hf_ax25_version;
static int hf_ax25_cr;
static int hf_ax25_modulo;
static int hf_ax25_modulo_source;
static int hf_ax25_modulo_frame;
static int hf_ax25_link_state;
static int hf_ax25_link_state_frame;
static int hf_ax25_link_refused;
static int hf_ax25_link_fallback;
static int hf_ax25_link_frmr_xid;
static int hf_ax25_link_idle;
static int hf_ax25_dup_of;
static int hf_ax25_param_version;
static int hf_ax25_param_version_source;
static int hf_ax25_param_version_frame;
static int hf_ax25_param_t1;
static int hf_ax25_param_t1_source;
static int hf_ax25_param_t3;
static int hf_ax25_param_t3_source;
static int hf_ax25_param_n2;
static int hf_ax25_param_n2_source;
static int hf_ax25_param_n1;
static int hf_ax25_param_n1_source;
static int hf_ax25_param_k;
static int hf_ax25_param_k_source;
static int hf_ax25_param_xid_frame;
static int hf_ax25_xid;
static int hf_ax25_xidn_command_frame;
static int hf_ax25_xidn_duplex;
static int hf_ax25_xidn_reject;
static int hf_ax25_xidn_modulo;
static int hf_ax25_xidn_segmenter;
static int hf_ax25_xidn_t1;
static int hf_ax25_xidn_n2;
static int hf_ax25_xidn_n1;
static int hf_ax25_xidn_k;
static int hf_ax25_xidn_kept;
static int hf_ax25_xidn_v22;
static int hf_ax25_seg;
static int hf_ax25_seg_first;
static int hf_ax25_seg_remaining;
static int hf_ax25_seg_pid;
static int hf_ax25_seg_first_frame;
static int hf_ax25_seg_gap;
static int hf_ax25_xid_fi;
static int hf_ax25_xid_gi;
static int hf_ax25_xid_gl;
static int hf_ax25_xid_pi;
static int hf_ax25_xid_pl;
static int hf_ax25_xid_pv;
static int hf_ax25_xid_trailing;
static int hf_ax25_xid_cop;
static int hf_ax25_xid_hdlc;
static int hf_ax25_xid_n1_tx;
static int hf_ax25_xid_n1_rx;
static int hf_ax25_xid_k_tx;
static int hf_ax25_xid_k_rx;
static int hf_ax25_xid_t1;
static int hf_ax25_xid_n2;
static int hf_ax25_xid_cop_abm;
static int hf_ax25_xid_cop_nrm_pri;
static int hf_ax25_xid_cop_nrm_sec;
static int hf_ax25_xid_cop_arm_pri;
static int hf_ax25_xid_cop_arm_sec;
static int hf_ax25_xid_cop_half;
static int hf_ax25_xid_cop_full;
static int hf_ax25_xid_cop_reserved;
static int hf_ax25_xid_hdlc_reserved0;
static int hf_ax25_xid_hdlc_rej;
static int hf_ax25_xid_hdlc_srej;
static int hf_ax25_xid_hdlc_ui;
static int hf_ax25_xid_hdlc_sim_rim;
static int hf_ax25_xid_hdlc_up;
static int hf_ax25_xid_hdlc_basic_addr;
static int hf_ax25_xid_hdlc_ext_addr;
static int hf_ax25_xid_hdlc_del_i_resp;
static int hf_ax25_xid_hdlc_del_i_cmd;
static int hf_ax25_xid_hdlc_mod8;
static int hf_ax25_xid_hdlc_mod128;
static int hf_ax25_xid_hdlc_rset;
static int hf_ax25_xid_hdlc_test;
static int hf_ax25_xid_hdlc_rd;
static int hf_ax25_xid_hdlc_fcs16;
static int hf_ax25_xid_hdlc_fcs32;
static int hf_ax25_xid_hdlc_sync_tx;
static int hf_ax25_xid_hdlc_ss_tx;
static int hf_ax25_xid_hdlc_ss_flow;
static int hf_ax25_xid_hdlc_ss_octet;
static int hf_ax25_xid_hdlc_srej_multi;
static int hf_ax25_xid_hdlc_segmenter;
static int hf_ax25_xid_hdlc_reserved23;

static expert_field ei_ax25_modulo_assumed;
static expert_field ei_ax25_modulo_inferred;
static expert_field ei_ax25_modulo_no_ua;
static expert_field ei_ax25_s128_bits;
static expert_field ei_ax25_pre20_v22_feature;
static expert_field ei_ax25_cr_mixed;
static expert_field ei_ax25_after_disc;
static expert_field ei_ax25_after_dm;
static expert_field ei_ax25_after_frmr;
static expert_field ei_ax25_disconnecting;
static expert_field ei_ax25_after_idle;
static expert_field ei_ax25_capture_gap;
static expert_field ei_ax25_refused;
static expert_field ei_ax25_fallback;
static expert_field ei_ax25_frmr_xid;
static expert_field ei_ax25_dup;
static expert_field ei_ax25_n1_exceeded;
static expert_field ei_ax25_xid_rule;
static expert_field ei_ax25_sabm_xid;
static expert_field ei_ax25_xid_modulo;
static expert_field ei_ax25_xid_length;
static expert_field ei_ax25_seg_not_negotiated;
static expert_field ei_ax25_seg_neg_not_captured;
static expert_field ei_ax25_seg_missing_first;
static expert_field ei_ax25_seg_remaining;
static expert_field ei_ax25_seg_interleaved;
static expert_field ei_ax25_seg_too_long;
static expert_field ei_ax25_seg_tr210;

static const xdlc_cf_items ax25_cf_items = {
	&hf_ax25_n_r,
	&hf_ax25_n_s,
	&hf_ax25_p,
	&hf_ax25_f,
	&hf_ax25_ftype_s,
	&hf_ax25_u_cmd,
	&hf_ax25_u_resp,
	&hf_ax25_ftype_i,
	&hf_ax25_ftype_su
};

static const xdlc_cf_items ax25_cf_items_ext = {
	&hf_ax25_n_r_ext,
	&hf_ax25_n_s_ext,
	&hf_ax25_p_ext,
	&hf_ax25_f_ext,
	&hf_ax25_ftype_s_ext,
	&hf_ax25_u_cmd,
	&hf_ax25_u_resp,
	&hf_ax25_ftype_i_ext,
	&hf_ax25_ftype_su_ext
};

static const value_string pid_vals[] = {
	{ AX25_P_ROSE,	   "Rose" },
	{ AX25_P_RFC1144C, "RFC1144 (compressed)" },
	{ AX25_P_RFC1144,  "RFC1144 (uncompressed)" },
	{ AX25_P_SEGMENT,  "Segment" },
	{ AX25_P_TEXNET,   "Texnet" },
	{ AX25_P_LCP,	   "Link Quality protocol" },
	{ AX25_P_ATALK,	   "AppleTalk" },
	{ AX25_P_ATALKARP, "AppleTalk ARP" },
	{ AX25_P_IP,	   "IP" },
	{ AX25_P_ARP,	   "ARP" },
	{ AX25_P_FLEXNET,  "FlexNet" },
	{ AX25_P_NETROM,   "NetRom" },
	{ AX25_P_NO_L3,	   "No L3" },
	{ AX25_P_L3_ESC,   "L3 esc" },
	{ 0, NULL }
};

/* C/R bit interpretation (section 6.1.2, Figure 6.1) */
typedef enum {
	AX25_CR_COMMAND,
	AX25_CR_RESPONSE,
	AX25_CR_UNKNOWN
} ax25_cr_e;

static const value_string ax25_cr_vals[] = {
	{ AX25_CR_COMMAND,	"Command" },
	{ AX25_CR_RESPONSE,	"Response" },
	{ AX25_CR_UNKNOWN,	"Unknown" },
	{ 0, NULL }
};

/* Protocol version, as far as the C/R bits of a single frame tell */
typedef enum {
	AX25_VERSION_PRE20,	/* both C bits equal */
	AX25_VERSION_2X		/* exactly one C bit set */
} ax25_version_e;

static const value_string ax25_version_vals[] = {
	{ AX25_VERSION_PRE20,	"pre-2.0" },
	{ AX25_VERSION_2X,	"2.x" },
	{ 0, NULL }
};

/* Where the modulo in effect came from */
typedef enum {
	AX25_MODSRC_ASSUMED,	/* nothing known; using 8 */
	AX25_MODSRC_INFERRED,	/* from an S frame (mid-session start) */
	AX25_MODSRC_NO_UA,	/* from a SABM(E) whose UA wasn't captured */
	AX25_MODSRC_SABM_UA,	/* from a SABM(E) and its UA */
	AX25_MODSRC_XID		/* from an XID response after the UA */
} ax25_modsrc_e;

static const value_string ax25_modsrc_vals[] = {
	{ AX25_MODSRC_ASSUMED,	"Assumed (no SABM(E)/UA or decisive S frame seen yet)" },
	{ AX25_MODSRC_INFERRED,	"Inferred from an S frame" },
	{ AX25_MODSRC_NO_UA,	"SABM(E), UA not captured" },
	{ AX25_MODSRC_SABM_UA,	"SABM(E) and UA" },
	{ AX25_MODSRC_XID,	"XID" },
	{ 0, NULL }
};

/* Short U frame names, for frames whose C/R is unknown */
static const value_string ax25_u_short_vals[] = {
	{ XDLC_UI,	"UI" },
	{ XDLC_SABM,	"SABM" },
	{ XDLC_SABME,	"SABME" },
	{ XDLC_DISC,	"DISC" },
	{ XDLC_UA,	"UA" },
	{ XDLC_DM,	"DM" },
	{ XDLC_FRMR,	"FRMR" },
	{ XDLC_XID,	"XID" },
	{ XDLC_TEST,	"TEST" },
	{ 0, NULL }
};

static int ett_ax25;
static int ett_ax25_ctl;
static int ett_ax25_link;
static int ett_ax25_params;
static int ett_ax25_xid;
static int ett_ax25_xid_param;
static int ett_ax25_xid_bits;
static int ett_ax25_seg;
static int ett_ax25_xidn;

static int * const ax25_xid_cop_fields[] = {
	&hf_ax25_xid_cop_abm,
	&hf_ax25_xid_cop_nrm_pri,
	&hf_ax25_xid_cop_nrm_sec,
	&hf_ax25_xid_cop_arm_pri,
	&hf_ax25_xid_cop_arm_sec,
	&hf_ax25_xid_cop_half,
	&hf_ax25_xid_cop_full,
	&hf_ax25_xid_cop_reserved,
	NULL
};

static int * const ax25_xid_hdlc_fields[] = {
	&hf_ax25_xid_hdlc_reserved0,
	&hf_ax25_xid_hdlc_rej,
	&hf_ax25_xid_hdlc_srej,
	&hf_ax25_xid_hdlc_ui,
	&hf_ax25_xid_hdlc_sim_rim,
	&hf_ax25_xid_hdlc_up,
	&hf_ax25_xid_hdlc_basic_addr,
	&hf_ax25_xid_hdlc_ext_addr,
	&hf_ax25_xid_hdlc_del_i_resp,
	&hf_ax25_xid_hdlc_del_i_cmd,
	&hf_ax25_xid_hdlc_mod8,
	&hf_ax25_xid_hdlc_mod128,
	&hf_ax25_xid_hdlc_rset,
	&hf_ax25_xid_hdlc_test,
	&hf_ax25_xid_hdlc_rd,
	&hf_ax25_xid_hdlc_fcs16,
	&hf_ax25_xid_hdlc_fcs32,
	&hf_ax25_xid_hdlc_sync_tx,
	&hf_ax25_xid_hdlc_ss_tx,
	&hf_ax25_xid_hdlc_ss_flow,
	&hf_ax25_xid_hdlc_ss_octet,
	&hf_ax25_xid_hdlc_srej_multi,
	&hf_ax25_xid_hdlc_segmenter,
	&hf_ax25_xid_hdlc_reserved23,
	NULL
};


static dissector_handle_t ax25_handle;

/* Preferences; 0 means "not set" except where noted */
static unsigned ax25_pref_t3_s = 300;	/* T3; the spec gives no default, this is Linux's AX25_DEF_T3 */
static unsigned ax25_pref_t1_ms;
static unsigned ax25_pref_n2;
static unsigned ax25_pref_n1;
static unsigned ax25_pref_k;
/*
 * Spec default for k in modulo 8. The spec disagrees with itself: 7 in
 * section 6.3.2 (v2.0 defaults) and section 6.7.2.3, 4 in section
 * 4.3.3.7 (PI 8, which Direwolf follows). 7 until that is settled.
 */
static unsigned ax25_pref_k_mod8_default = 7;
/* TR210, next segment timer; the spec gives no value. 0: N2 x T1 of the sender */
static unsigned ax25_pref_tr210_s;

/* pinfo->pool key: the AX.25 snapshot, for the segment dissector */
#define AX25_PROTO_DATA_SEG_PKT	0x80000002U

/* Segment header (section 6.6, Figure 6.2) */
#define AX25_SEG_FIRST		0x80
#define AX25_SEG_REMAINING	0x7F

/* Segment expert infos */
#define AX25_SEGF_NOT_NEGOTIATED	0x0001
#define AX25_SEGF_NEG_NOT_CAPTURED	0x0002
#define AX25_SEGF_MISSING_FIRST		0x0004
#define AX25_SEGF_BAD_REMAINING		0x0008
#define AX25_SEGF_ABANDONED		0x0010	/* new first segment, previous one incomplete */
#define AX25_SEGF_INTERLEAVED		0x0020	/* another frame in the middle of a sequence */
#define AX25_SEGF_TR210			0x0040
#define AX25_SEGF_RETRANSMISSION	0x0080

/* Spec defaults (section 6.3.2; the same for v2.0 and v2.2 except k) */
#define AX25_SPEC_T1_MS		3000
#define AX25_SPEC_N2		10
#define AX25_SPEC_N1		256
#define AX25_SPEC_K_MOD128	32

/*
 * Per-station overrides (UAT), for parameters the capture doesn't show.
 */
#define AX25_UAT_VERSION_NONE	0
#define AX25_UAT_VERSION_20	20
#define AX25_UAT_VERSION_22	22

typedef struct _ax25_station_uat {
	char		*callsign;	/* CALL or CALL-SSID */
	uint32_t	t1_ms;
	uint32_t	t3_s;
	uint32_t	n2;
	uint32_t	n1;
	uint32_t	k;
	unsigned	version;	/* AX25_UAT_VERSION_xxx */
	uint8_t		masked[AX25_ADDR_LEN];	/* callsign, as ax25_mask_address() makes it */
} ax25_station_uat_t;

static ax25_station_uat_t *ax25_stations;
static unsigned ax25_num_stations;

static const value_string ax25_uat_version_vals[] = {
	{ AX25_UAT_VERSION_NONE,	"Unknown" },
	{ AX25_UAT_VERSION_20,		"2.0" },
	{ AX25_UAT_VERSION_22,		"2.2" },
	{ 0, NULL }
};

/* Where a link parameter value came from, in order of precedence */
typedef enum {
	AX25_PSRC_SPEC,		/* spec default for the version in effect */
	AX25_PSRC_PREF,		/* global preference */
	AX25_PSRC_UAT,		/* per-station override */
	AX25_PSRC_XID		/* negotiated (or notified) by XID */
} ax25_psrc_e;

static const value_string ax25_psrc_vals[] = {
	{ AX25_PSRC_SPEC,	"spec default" },
	{ AX25_PSRC_PREF,	"preference" },
	{ AX25_PSRC_UAT,	"station table" },
	{ AX25_PSRC_XID,	"XID" },
	{ 0, NULL }
};

typedef struct _ax25_param {
	uint32_t	value;
	ax25_psrc_e	src;
	uint32_t	frame;		/* the XID frame, for AX25_PSRC_XID */
} ax25_param_t;

/* Version whose defaults apply */
typedef enum {
	AX25_VEFF_20,
	AX25_VEFF_22
} ax25_veff_e;

typedef enum {
	AX25_VSRC_DEFAULT,	/* no evidence; v2.0 */
	AX25_VSRC_UAT,		/* station table hint */
	AX25_VSRC_EVIDENCE	/* seen in the capture */
} ax25_vsrc_e;

static const value_string ax25_veff_vals[] = {
	{ AX25_VEFF_20,		"2.0" },
	{ AX25_VEFF_22,		"2.2" },
	{ 0, NULL }
};

static const value_string ax25_vsrc_vals[] = {
	{ AX25_VSRC_DEFAULT,	"default (nothing seen)" },
	{ AX25_VSRC_UAT,	"station table" },
	{ AX25_VSRC_EVIDENCE,	"seen" },
	{ 0, NULL }
};

/* Parameters in effect for a frame, in the direction it was sent */
typedef struct _ax25_params {
	ax25_param_t	t1_ms;		/* acknowledgement timer */
	ax25_param_t	t3_s;		/* inactive link timer, of the sender */
	ax25_param_t	n2;		/* retries */
	ax25_param_t	n1;		/* longest I field the receiver accepts */
	ax25_param_t	k;		/* window the receiver accepts */
	ax25_veff_e	version;
	ax25_vsrc_e	version_src;
	uint32_t	version_frame;
} ax25_params_t;

/*
 * Contents of an XID information field (ISO 8885 general purpose XID,
 * parameter negotiation group), as far as AX.25 uses it.
 */
#define AX25_XID_FI		0x82
#define AX25_XID_GI		0x80

#define AX25_XID_PI_COP		2	/* Classes of Procedures */
#define AX25_XID_PI_HDLC	3	/* HDLC Optional Functions */
#define AX25_XID_PI_N1_TX	5	/* I field length Tx, bits */
#define AX25_XID_PI_N1_RX	6	/* I field length Rx, bits */
#define AX25_XID_PI_K_TX	7	/* window size Tx */
#define AX25_XID_PI_K_RX	8	/* window size Rx */
#define AX25_XID_PI_T1		9	/* acknowledge timer, ms */
#define AX25_XID_PI_N2		10	/* retries (labelled N1 in the spec) */

static const value_string ax25_xid_pi_vals[] = {
	{ AX25_XID_PI_COP,	"Classes of Procedures" },
	{ AX25_XID_PI_HDLC,	"HDLC Optional Functions" },
	{ AX25_XID_PI_N1_TX,	"I Field Length Tx" },
	{ AX25_XID_PI_N1_RX,	"I Field Length Rx" },
	{ AX25_XID_PI_K_TX,	"Window Size Tx" },
	{ AX25_XID_PI_K_RX,	"Window Size Rx" },
	{ AX25_XID_PI_T1,	"Acknowledge Timer" },
	{ AX25_XID_PI_N2,	"Retries" },
	{ 0, NULL }
};

/*
 * Bit fields (PI 2 and 3) are sent least significant octet first, so bit
 * n of Figure 4.5 is bit n%8 of octet n/8. Numeric fields are big-endian.
 * The text doesn't say; this is what Figure 4.6 shows for the numeric
 * fields and what Direwolf (xid.c) does for both. Figure 4.6 itself has
 * errata in the bit fields: its Classes of Procedures 0x22 0x00 sets bit
 * 1 (Unbalanced NRM primary) instead of bit 0 (Balanced ABM), and its
 * HDLC Optional Functions 0x82 0xA8 0x22 sets REJ and SREJ multiframe
 * (bit 21) while the text says SREJ/REJ; Direwolf's self-test corrects
 * them to 0x21 0x00 and 0x86 0xA8 0x02. Linux net/ax25 doesn't do XID.
 */
#define AX25_COP_ABM		0x0001
#define AX25_COP_NRM_PRI	0x0002
#define AX25_COP_NRM_SEC	0x0004
#define AX25_COP_ARM_PRI	0x0008
#define AX25_COP_ARM_SEC	0x0010
#define AX25_COP_HALF_DUPLEX	0x0020
#define AX25_COP_FULL_DUPLEX	0x0040
#define AX25_COP_RESERVED	0xFF80

#define AX25_HDLC_BIT(n)	(1U << (n))
#define AX25_HDLC_REJ		AX25_HDLC_BIT(1)
#define AX25_HDLC_SREJ		AX25_HDLC_BIT(2)
#define AX25_HDLC_MOD8		AX25_HDLC_BIT(10)
#define AX25_HDLC_MOD128	AX25_HDLC_BIT(11)
#define AX25_HDLC_SREJ_MULTI	AX25_HDLC_BIT(21)
#define AX25_HDLC_SEGMENTER	AX25_HDLC_BIT(22)

/* Selective reject levels, lowest first (section 6.3.2 ordering) */
#define AX25_REJ_NONE		0
#define AX25_REJ_REJ		1
#define AX25_REJ_SREJ		2

#define AX25_XID_HAS_DUPLEX	0x0001
#define AX25_XID_HAS_REJ	0x0002
#define AX25_XID_HAS_MODULO	0x0004
#define AX25_XID_HAS_SEGMENTER	0x0008
#define AX25_XID_HAS_N1_RX	0x0010
#define AX25_XID_HAS_K_RX	0x0020
#define AX25_XID_HAS_T1		0x0040
#define AX25_XID_HAS_N2		0x0080
/* the parameter was present with PL=0 (or GL=0): its default applies */
#define AX25_XID_DEF_SHIFT	8

typedef struct _ax25_xid {
	bool		valid;		/* FI/GI recognized */
	bool		gl_zero;	/* all defaults */
	unsigned	has;		/* AX25_XID_HAS_xxx, and << AX25_XID_DEF_SHIFT for defaults */
	bool		full_duplex;	/* highest offered */
	uint8_t		rej;		/* highest offered, AX25_REJ_xxx */
	uint8_t		modulo;		/* highest offered */
	bool		segmenter;
	uint32_t	n1_rx;		/* octets */
	uint32_t	k_rx;
	uint32_t	t1_ms;
	uint32_t	n2;
	uint32_t	cop;		/* PI 2 as received, for showing what was offered */
	uint32_t	hdlc;		/* PI 3 as received */
} ax25_xid_t;

/*
 * Negotiation as seen in one XID frame, for the tree: what a command
 * offers, or what a response selects and what results from it. Only
 * looks back, so a command can't point at the response that answers it:
 * that would need a second pass and break the output without -2.
 */
typedef struct _ax25_xid_neg {
	bool		response;
	ax25_xid_t	self;		/* this frame */
	uint32_t	cmd_frame;	/* response: the command it answers (0: not captured) */
	ax25_xid_t	cmd;		/* that command */
	uint8_t		modulo_before;	/* response: modulo in effect before it */
	bool		connected;	/* the link was connected */
	ax25_params_t	params[2];	/* parameters after this frame, per direction */
} ax25_xid_neg_t;

/* Things an XID response breaks in the section 6.3.2 negotiation rules */
#define AX25_XIDCHK_DUPLEX	0x01
#define AX25_XIDCHK_REJ		0x02
#define AX25_XIDCHK_MODULO	0x04
#define AX25_XIDCHK_T1		0x08
#define AX25_XIDCHK_N2		0x10

typedef struct _ax25_xid_check {
	uint32_t	cmd_frame;
	unsigned	flags;
	ax25_xid_t	cmd;
	ax25_xid_t	resp;
} ax25_xid_check_t;

/*
 * Frame types, classified from the first control octet only. The low two
 * bits tell I, S and U frames apart in both modulo 8 and modulo 128, the
 * S frame function is in bits 2-3 in both, and U frames are always one
 * octet, so this works before the modulo is known.
 */
typedef enum {
	AX25_FT_I,
	AX25_FT_RR,
	AX25_FT_RNR,
	AX25_FT_REJ,
	AX25_FT_SREJ,
	AX25_FT_SABM,
	AX25_FT_SABME,
	AX25_FT_DISC,
	AX25_FT_UA,
	AX25_FT_DM,
	AX25_FT_FRMR,
	AX25_FT_UI,
	AX25_FT_XID,
	AX25_FT_TEST,
	AX25_FT_U_OTHER,
	AX25_FT_NONE		/* no frame / nothing recorded */
} ax25_ftype_e;

static const value_string ax25_ftype_names[] = {
	{ AX25_FT_I,		"I" },
	{ AX25_FT_RR,		"RR" },
	{ AX25_FT_RNR,		"RNR" },
	{ AX25_FT_REJ,		"REJ" },
	{ AX25_FT_SREJ,		"SREJ" },
	{ AX25_FT_SABM,		"SABM" },
	{ AX25_FT_SABME,	"SABME" },
	{ AX25_FT_DISC,		"DISC" },
	{ AX25_FT_UA,		"UA" },
	{ AX25_FT_DM,		"DM" },
	{ AX25_FT_FRMR,		"FRMR" },
	{ AX25_FT_UI,		"UI" },
	{ AX25_FT_XID,		"XID" },
	{ AX25_FT_TEST,		"TEST" },
	{ AX25_FT_U_OTHER,	"U" },
	{ AX25_FT_NONE,		"none" },
	{ 0, NULL }
};

/* Link state (data-link state machine as seen from the channel) */
typedef enum {
	AX25_LINK_UNKNOWN,
	AX25_LINK_CONNECTING,		/* SABM(E) sent, not answered */
	AX25_LINK_CONNECTED,
	AX25_LINK_DISCONNECTING,	/* DISC sent, not answered */
	AX25_LINK_DISCONNECTED_DISC,	/* DISC answered by UA */
	AX25_LINK_DISCONNECTED_DM,	/* DM: refused, or link down */
	AX25_LINK_FRMR,			/* frame reject (pre-2.2 peer) */
	AX25_LINK_PRESUMED_DOWN		/* idle longer than T3 + N2 * T1 */
} ax25_link_state_e;

static const value_string ax25_link_state_vals[] = {
	{ AX25_LINK_UNKNOWN,		"Unknown" },
	{ AX25_LINK_CONNECTING,		"Connecting" },
	{ AX25_LINK_CONNECTED,		"Connected" },
	{ AX25_LINK_DISCONNECTING,	"Disconnecting" },
	{ AX25_LINK_DISCONNECTED_DISC,	"Disconnected (DISC/UA)" },
	{ AX25_LINK_DISCONNECTED_DM,	"Disconnected (DM)" },
	{ AX25_LINK_FRMR,		"Frame rejected (FRMR)" },
	{ AX25_LINK_PRESUMED_DOWN,	"Presumed down (idle timeout)" },
	{ 0, NULL }
};

/* Sequence expert infos, one per frame at most */
typedef enum {
	AX25_SEQ_NONE,
	AX25_SEQ_AFTER_DISC,
	AX25_SEQ_AFTER_DM,
	AX25_SEQ_AFTER_FRMR,
	AX25_SEQ_DISCONNECTING,
	AX25_SEQ_AFTER_IDLE,
	AX25_SEQ_CAPTURE_GAP
} ax25_seq_expert_e;

/* C/R encodings seen in one direction */
#define AX25_ENC_NONE		0
#define AX25_ENC_PRE20		1
#define AX25_ENC_2X		2

/*
 * Per-packet snapshot, computed on the first pass and attached to the
 * frame (file scope, keyed by layer number). Later passes, and frames
 * dissected out of order, only read it.
 */
typedef struct _ax25_pkt {
	bool		has_stream;	/* false for UI frames */
	uint32_t	stream;
	uint8_t		dir;

	uint8_t		modulo;
	ax25_modsrc_e	modulo_src;
	uint32_t	modulo_frame;

	uint32_t	pre20_frame;	/* a pre-2.0 frame was seen on the link before (or at) this one */
	uint32_t	cr_mixed_frame;	/* previous frame in this direction used the other C/R encoding */

	ax25_link_state_e state;	/* link state after this frame */
	ax25_seq_expert_e seq_expert;
	uint32_t	seq_frame;	/* frame that caused the state seq_expert is about */
	ax25_ftype_e	seq_ftype;	/* its type */
	nstime_t	idle_gap;	/* for AX25_SEQ_AFTER_IDLE / AX25_SEQ_CAPTURE_GAP */
	double		idle_limit_s;

	uint32_t	refused_frame;	/* this DM/FRMR refuses the SABM(E) in that frame */
	uint32_t	frmr_xid_frame;	/* this FRMR answers the XID command in that frame */
	uint32_t	fallback_frame;	/* this SABM retries after the DM/FRMR to SABME in that frame */
	uint32_t	dup_of;		/* this is a digipeated copy of that frame */

	ax25_params_t	params;		/* in effect for this frame's direction */
	ax25_xid_check_t *xid_check;	/* XID response breaking the negotiation rules */
	uint32_t	sabm_xid_frame;	/* SABM(E) disagrees with the modulo the XID in that frame negotiated */
	uint8_t		sabm_xid_modulo;
	uint8_t		xid_modulo_prev; /* this XID changed the modulo from that (0 = no change) */
	ax25_xid_neg_t	*xid_neg;	/* XID frames: negotiation details for the tree */

	/* Segmenter analysis */
	unsigned	seg_flags;	/* AX25_SEGF_xxx */
	uint32_t	seg_first_frame;	/* first segment of the sequence this frame is in (or breaks) */
	uint8_t		seg_expected;	/* remaining count expected, for AX25_SEGF_BAD_REMAINING */
	uint32_t	seg_xid_frame;	/* XID response that didn't negotiate the segmenter */
	nstime_t	seg_gap;	/* for AX25_SEGF_TR210 */
	double		seg_tr210_s;
} ax25_pkt_t;

/* Recent frames on a link, to recognize digipeated copies */
#define AX25_DUP_HISTORY	8

typedef struct _ax25_hist {
	uint32_t	frame;
	nstime_t	ts;
	unsigned	reported_len;
	unsigned	len;		/* captured octets in data */
	uint8_t		hbits;		/* H bit of each digipeater, bit n = digipeater n+1 */
	uint8_t		*data;		/* the frame with the H bits cleared */
	ax25_pkt_t	*pkt;
} ax25_hist_t;

/*
 * Per-link state, kept in the conversation and only touched on the first
 * pass. Everything a later pass needs is copied into ax25_pkt_t.
 */
typedef struct _ax25_conv {
	bool		has_stream;	/* stream allocated (a frame other than UI was seen) */
	uint32_t	stream;		/* ax25.stream */
	uint32_t	nframes;	/* frames other than UI seen so far on this stream */

	ax25_link_state_e state;
	uint32_t	state_frame;	/* frame that caused the state */
	ax25_ftype_e	state_ftype;	/* its type */

	/* AX25_LINK_CONNECTING */
	uint8_t		connect_dir;
	ax25_ftype_e	connect_type;	/* SABM or SABME */
	uint32_t	connect_frame;
	/* AX25_LINK_DISCONNECTING */
	uint8_t		disc_dir;
	/* A DM or FRMR answered a SABME: a SABM from the same side may follow
	 * (v2.2 -> v2.0 fallback, section 4.3.3.2) */
	bool		fallback_pending;
	uint8_t		fallback_dir;
	uint32_t	fallback_frame;

	/* Last command each side sent, to pair responses with */
	ax25_ftype_e	last_cmd[2];
	uint32_t	last_cmd_frame[2];

	/* Sequence numbers last seen from each side */
	uint8_t		last_ns[2];
	uint8_t		last_nr[2];
	bool		ns_valid[2];
	bool		nr_valid[2];

	/* Last frame on the link, either direction */
	uint32_t	last_frame;
	nstime_t	last_ts;
	/* AX25_LINK_PRESUMED_DOWN: the silence that caused it */
	nstime_t	idle_gap;
	double		idle_limit_s;

	/* Modulo in effect for I and S frames */
	uint8_t		modulo;		/* 8 or 128 */
	ax25_modsrc_e	modulo_src;
	uint32_t	modulo_frame;	/* frame that set it, 0 if assumed */

	/* Version evidence */
	uint32_t	pre20_frame;	/* first pre-2.0 frame on the link, 0 if none */
	uint8_t		last_enc[2];	/* AX25_ENC_xxx of the last frame, per direction */
	uint32_t	last_enc_frame[2];

	ax25_hist_t	hist[AX25_DUP_HISTORY];
	unsigned	hist_next;

	/* The station sending in each direction, and its station table entry */
	uint8_t		addr[2][AX25_ADDR_LEN];
	bool		has_uat[2];
	ax25_station_uat_t uat[2];	/* copy; callsign not kept */

	/* Version evidence: latest frame pointing at each version */
	uint32_t	v20_frame;
	uint32_t	v22_frame;
	/* Last frame that was about the connection itself (not XID/UI/TEST) */
	uint32_t	conn_activity_frame;

	/* XID: last command from each side, for checking the response */
	bool		xid_cmd_valid[2];
	uint32_t	xid_cmd_frame[2];
	ax25_xid_t	xid_cmd[2];
	/* XID: negotiated (from the response) for the whole link... */
	uint32_t	xid_neg_frame;		/* 0 = no XID response seen */
	uint32_t	xid_t1_frame;		/* PI 9 */
	bool		xid_t1_default;
	uint32_t	xid_t1_ms;
	uint32_t	xid_n2_frame;		/* PI 10 */
	bool		xid_n2_default;
	uint32_t	xid_n2;
	uint8_t		xid_modulo;		/* 0 = not negotiated */
	bool		xid_segmenter_known;
	bool		xid_segmenter;
	/* ...and notified by each station about what it can receive */
	uint32_t	xid_n1_frame[2];	/* PI 6 */
	bool		xid_n1_default[2];
	uint32_t	xid_n1[2];		/* octets */
	uint32_t	xid_k_frame[2];		/* PI 8 */
	bool		xid_k_default[2];
	uint32_t	xid_k[2];

	/* Segmenter: sequence in progress from each side */
	bool		seg_active[2];
	bool		seg_over_ui[2];
	uint8_t		seg_remaining[2];
	uint32_t	seg_first_frame[2];
	nstime_t	seg_last_ts[2];
	bool		seg_last_ns_valid[2];
	uint8_t		seg_last_ns[2];
	/*
	 * TODO: these sequences are what reassembly of segmented data
	 * units (section 6.6) would work from.
	 */

	/*
	 * TODO: the N(S)/N(R) tracking here would also support
	 * retransmission and window analysis (k), and the conversation
	 * could feed conversation/endpoint tables and Follow Stream.
	 */
} ax25_conv_t;

/* What the first pass needs to know about the frame being dissected */
typedef struct _ax25_frame {
	tvbuff_t	*tvb;
	int		ctl_offset;
	uint8_t		dir;
	ax25_ftype_e	ftype;
	ax25_cr_e	cr;
	ax25_version_e	version;
	uint8_t		c0;		/* first control octet */
	int		ctl_remaining;	/* octets from the control field to the end */
	unsigned	ndigis;
	int		digi_ssid_offset[AX25_MAX_DIGIS];
	uint8_t		hbits;
} ax25_frame_t;

static uint32_t ax25_stream_count;

static void ax25_set_modulo(ax25_conv_t *conv, uint8_t modulo, ax25_modsrc_e src, uint32_t frame);

static ax25_ftype_e
ax25_classify_control(uint8_t c0)
{
	if ((c0 & XDLC_I_MASK) == XDLC_I)
		return AX25_FT_I;

	if ((c0 & XDLC_S_U_MASK) == XDLC_S) {
		switch (c0 & XDLC_S_FTYPE_MASK) {
		case XDLC_RR:	return AX25_FT_RR;
		case XDLC_RNR:	return AX25_FT_RNR;
		case XDLC_REJ:	return AX25_FT_REJ;
		default:	return AX25_FT_SREJ;
		}
	}

	switch (c0 & XDLC_U_MODIFIER_MASK) {
	case XDLC_SABM:		return AX25_FT_SABM;
	case XDLC_SABME:	return AX25_FT_SABME;
	case XDLC_DISC:		return AX25_FT_DISC;
	case XDLC_UA:		return AX25_FT_UA;
	case XDLC_DM:		return AX25_FT_DM;
	case XDLC_FRMR:		return AX25_FT_FRMR;
	case XDLC_UI:		return AX25_FT_UI;
	case XDLC_XID:		return AX25_FT_XID;
	case XDLC_TEST:		return AX25_FT_TEST;
	default:		return AX25_FT_U_OTHER;
	}
}

static bool
ax25_ftype_is_sabm(ax25_ftype_e ft)
{
	return ft == AX25_FT_SABM || ft == AX25_FT_SABME;
}

static bool
ax25_ftype_is_s(ax25_ftype_e ft)
{
	return ft == AX25_FT_RR || ft == AX25_FT_RNR || ft == AX25_FT_REJ || ft == AX25_FT_SREJ;
}

/* I and S frames are the ones whose control field depends on the modulo */
static bool
ax25_ftype_is_numbered(ax25_ftype_e ft)
{
	return ft == AX25_FT_I || ax25_ftype_is_s(ft);
}

/*
 * Pre-2.0 stations set both C bits the same way, so the bits say nothing
 * about command or response. Use what the frame type implies (Figure 4.4
 * for U frames; I frames are always commands). S frames, XID and TEST can
 * be either.
 */
static ax25_cr_e
ax25_pre20_cr(ax25_ftype_e ft)
{
	switch (ft) {
	case AX25_FT_I:
	case AX25_FT_UI:
	case AX25_FT_SABM:
	case AX25_FT_SABME:
	case AX25_FT_DISC:
		return AX25_CR_COMMAND;
	case AX25_FT_UA:
	case AX25_FT_DM:
	case AX25_FT_FRMR:
		return AX25_CR_RESPONSE;
	default:
		return AX25_CR_UNKNOWN;
	}
}

/*
 * Reduce an address subfield to what identifies a station: the six
 * callsign octets and the SSID. The C/R (or H) bit, the two reserved
 * bits and the extension bit are dropped.
 */
static void
ax25_mask_address(tvbuff_t *tvb, int offset, uint8_t *masked)
{
	int i;

	for (i = 0; i < AX25_ADDR_LEN - 1; i++)
		masked[i] = tvb_get_uint8(tvb, offset + i) & 0xFE;
	masked[AX25_ADDR_LEN - 1] = tvb_get_uint8(tvb, offset + AX25_ADDR_LEN - 1) & AX25_SSID_SSID;
}

/*
 * Build the link key in pinfo->pool: the two masked addresses in canonical
 * order (lower first), each followed by the KISS port, then the capture
 * interface. That is the address/port/address/port layout other code
 * expects (e.g. conversation_key_addr2(), used by Lua's tostring() of a
 * conversation). Absent values use AX25_NO_PORT / AX25_NO_INTERFACE so
 * every key has the same shape. The digipeater path is deliberately not
 * part of the key: a link keeps its identity if the path changes, and
 * frames heard both before and after a digipeater belong to the same link.
 */
#define AX25_KEY_ADDR_LO	0
#define AX25_KEY_ADDR_HI	2

static conversation_element_t *
ax25_link_key(packet_info *pinfo, const uint8_t *lo, const uint8_t *hi,
		uint32_t port, uint32_t iface)
{
	conversation_element_t *key = wmem_alloc0_array(pinfo->pool, conversation_element_t, 6);

	key[AX25_KEY_ADDR_LO].type = CE_ADDRESS;
	set_address(&key[AX25_KEY_ADDR_LO].addr_val, AT_AX25, AX25_ADDR_LEN, lo);
	key[1].type = CE_PORT;
	key[1].port_val = port;
	key[AX25_KEY_ADDR_HI].type = CE_ADDRESS;
	set_address(&key[AX25_KEY_ADDR_HI].addr_val, AT_AX25, AX25_ADDR_LEN, hi);
	key[3].type = CE_PORT;
	key[3].port_val = port;
	key[4].type = CE_UINT;
	key[4].uint_val = iface;
	key[5].type = CE_CONVERSATION_TYPE;
	key[5].conversation_type_val = CONVERSATION_AX25;

	return key;
}

/*
 * Version whose defaults apply: what the capture showed last (SABME/UA
 * or an XID response for 2.2; a pre-2.0 frame, SABM/UA, FRMR to XID or
 * a fallback to SABM for 2.0), else the station table's hint (the lower
 * of the two), else 2.0.
 */
static void
ax25_version_in_effect(const ax25_conv_t *conv, ax25_params_t *p)
{
	uint8_t d;
	unsigned hint = AX25_UAT_VERSION_NONE;

	if (conv->v20_frame || conv->v22_frame) {
		p->version_src = AX25_VSRC_EVIDENCE;
		if (conv->v22_frame > conv->v20_frame) {
			p->version = AX25_VEFF_22;
			p->version_frame = conv->v22_frame;
		} else {
			p->version = AX25_VEFF_20;
			p->version_frame = conv->v20_frame;
		}
		return;
	}
	for (d = 0; d < 2; d++) {
		if (conv->has_uat[d] && conv->uat[d].version != AX25_UAT_VERSION_NONE &&
		    (hint == AX25_UAT_VERSION_NONE || conv->uat[d].version < hint))
			hint = conv->uat[d].version;
	}
	p->version_frame = 0;
	if (hint != AX25_UAT_VERSION_NONE) {
		p->version_src = AX25_VSRC_UAT;
		p->version = (hint == AX25_UAT_VERSION_22) ? AX25_VEFF_22 : AX25_VEFF_20;
	} else {
		p->version_src = AX25_VSRC_DEFAULT;
		p->version = AX25_VEFF_20;
	}
}

/*
 * One parameter, in order of precedence: XID, station table, preference,
 * spec default. 0 means "not set" in the station table and preferences.
 */
static void
ax25_resolve_param(ax25_param_t *out, uint32_t xid_frame, bool xid_default, uint32_t xid_value,
		bool has_uat, uint32_t uat_value, unsigned pref_value, uint32_t spec_value)
{
	out->frame = 0;
	if (xid_frame) {
		out->src = AX25_PSRC_XID;
		out->frame = xid_frame;
		out->value = xid_default ? spec_value : xid_value;
	} else if (has_uat && uat_value) {
		out->src = AX25_PSRC_UAT;
		out->value = uat_value;
	} else if (pref_value) {
		out->src = AX25_PSRC_PREF;
		out->value = pref_value;
	} else {
		out->src = AX25_PSRC_SPEC;
		out->value = spec_value;
	}
}

/*
 * Parameters for frames sent in direction dir. T1, N2 and T3 are the
 * sender's (T1 and N2 are negotiated for the whole link); N1 and k are
 * what the receiver notified it can take (section 6.3.2). The k default
 * follows the modulo in effect rather than the version: a v2.2 station
 * connected with SABM runs modulo 8.
 */
static void
ax25_resolve_params(const ax25_conv_t *conv, uint8_t dir, ax25_params_t *p)
{
	uint8_t rx = !dir;

	ax25_version_in_effect(conv, p);
	ax25_resolve_param(&p->t1_ms, conv->xid_t1_frame, conv->xid_t1_default, conv->xid_t1_ms,
			conv->has_uat[dir], conv->uat[dir].t1_ms, ax25_pref_t1_ms, AX25_SPEC_T1_MS);
	ax25_resolve_param(&p->n2, conv->xid_n2_frame, conv->xid_n2_default, conv->xid_n2,
			conv->has_uat[dir], conv->uat[dir].n2, ax25_pref_n2, AX25_SPEC_N2);
	/* T3 isn't negotiated and has no spec default; the preference always applies */
	ax25_resolve_param(&p->t3_s, 0, false, 0,
			conv->has_uat[dir], conv->uat[dir].t3_s, ax25_pref_t3_s, 0);
	ax25_resolve_param(&p->n1, conv->xid_n1_frame[rx], conv->xid_n1_default[rx], conv->xid_n1[rx],
			conv->has_uat[rx], conv->uat[rx].n1, ax25_pref_n1, AX25_SPEC_N1);
	ax25_resolve_param(&p->k, conv->xid_k_frame[rx], conv->xid_k_default[rx], conv->xid_k[rx],
			conv->has_uat[rx], conv->uat[rx].k, ax25_pref_k,
			conv->modulo == 128 ? AX25_SPEC_K_MOD128 : ax25_pref_k_mod8_default);
}

static double
ax25_param_t1_s(const ax25_conv_t *conv, uint8_t dir)
{
	ax25_params_t p;

	ax25_resolve_params(conv, dir, &p);
	return p.t1_ms.value / 1000.0;
}

static unsigned
ax25_param_n2(const ax25_conv_t *conv, uint8_t dir)
{
	ax25_params_t p;

	ax25_resolve_params(conv, dir, &p);
	return p.n2.value;
}

/* 0 disables the idle timeout */
static double
ax25_param_t3_s(const ax25_conv_t *conv, uint8_t dir)
{
	ax25_params_t p;

	ax25_resolve_params(conv, dir, &p);
	return (double)p.t3_s.value;
}

/* Station table lookup by masked address */
static const ax25_station_uat_t *
ax25_find_station(const uint8_t *masked)
{
	unsigned i;

	for (i = 0; i < ax25_num_stations; i++) {
		if (memcmp(ax25_stations[i].masked, masked, AX25_ADDR_LEN) == 0)
			return &ax25_stations[i];
	}
	return NULL;
}

/* XID integers: bit fields least significant octet first, numbers big-endian */
static uint32_t
ax25_xid_le(const uint8_t *pv, unsigned pl)
{
	uint32_t v = 0;
	unsigned i;

	for (i = 0; i < pl && i < 4; i++)
		v |= (uint32_t)pv[i] << (8 * i);
	return v;
}

static uint32_t
ax25_xid_be(const uint8_t *pv, unsigned pl)
{
	uint32_t v = 0;
	unsigned i;

	for (i = 0; i < pl && i < 4; i++)
		v = (v << 8) | pv[i];
	return v;
}

static uint8_t
ax25_xid_rej_level(uint32_t hdlc, bool highest)
{
	bool srej = (hdlc & (AX25_HDLC_SREJ | AX25_HDLC_SREJ_MULTI)) != 0;
	bool rej = (hdlc & AX25_HDLC_REJ) != 0;

	if (highest)
		return srej ? AX25_REJ_SREJ : (rej ? AX25_REJ_REJ : AX25_REJ_NONE);
	return rej ? AX25_REJ_REJ : (srej ? AX25_REJ_SREJ : AX25_REJ_NONE);
}

/*
 * Parse an XID information field (first pass; never throws). A command
 * offers a menu, so "highest" picks the best it offers; a response should
 * select one, and if it doesn't the lesser is taken.
 */
static void
ax25_parse_xid(tvbuff_t *tvb, int offset, bool highest, ax25_xid_t *x)
{
	const uint8_t *data;
	unsigned len, end, off, pl;
	uint8_t pi;
	uint32_t v;

	memset(x, 0, sizeof *x);
	len = tvb_captured_length_remaining(tvb, offset);
	if (len < 4)
		return;
	data = tvb_get_ptr(tvb, offset, len);
	if (data[0] != AX25_XID_FI || data[1] != AX25_XID_GI)
		return;
	x->valid = true;
	v = ((unsigned)data[2] << 8) | data[3];
	if (v == 0) {
		/* "all parameters assume their default values" */
		x->gl_zero = true;
		x->has = (AX25_XID_HAS_DUPLEX | AX25_XID_HAS_REJ | AX25_XID_HAS_MODULO |
			  AX25_XID_HAS_SEGMENTER | AX25_XID_HAS_N1_RX | AX25_XID_HAS_K_RX |
			  AX25_XID_HAS_T1 | AX25_XID_HAS_N2) << AX25_XID_DEF_SHIFT;
		return;
	}
	end = MIN(len, 4 + v);
	off = 4;
	while (off + 2 <= end) {
		pi = data[off];
		pl = data[off + 1];
		off += 2;
		if (off + pl > end)
			break;
		switch (pi) {
		case AX25_XID_PI_COP:
			if (pl == 0) {
				x->has |= AX25_XID_HAS_DUPLEX << AX25_XID_DEF_SHIFT;
				break;
			}
			v = ax25_xid_le(&data[off], pl);
			x->cop = v;
			x->has |= AX25_XID_HAS_DUPLEX;
			x->full_duplex = (v & AX25_COP_FULL_DUPLEX) &&
				(highest || !(v & AX25_COP_HALF_DUPLEX));
			break;
		case AX25_XID_PI_HDLC:
			if (pl == 0) {
				x->has |= (AX25_XID_HAS_REJ | AX25_XID_HAS_MODULO | AX25_XID_HAS_SEGMENTER)
					<< AX25_XID_DEF_SHIFT;
				break;
			}
			v = ax25_xid_le(&data[off], pl);
			x->hdlc = v;
			x->rej = ax25_xid_rej_level(v, highest);
			if (x->rej != AX25_REJ_NONE)
				x->has |= AX25_XID_HAS_REJ;
			if (v & (AX25_HDLC_MOD8 | AX25_HDLC_MOD128)) {
				x->has |= AX25_XID_HAS_MODULO;
				if ((v & AX25_HDLC_MOD128) && (highest || !(v & AX25_HDLC_MOD8)))
					x->modulo = 128;
				else
					x->modulo = 8;
			}
			x->has |= AX25_XID_HAS_SEGMENTER;
			x->segmenter = (v & AX25_HDLC_SEGMENTER) != 0;
			break;
		case AX25_XID_PI_N1_RX:
			if (pl == 0) {
				x->has |= AX25_XID_HAS_N1_RX << AX25_XID_DEF_SHIFT;
				break;
			}
			x->has |= AX25_XID_HAS_N1_RX;
			x->n1_rx = ax25_xid_be(&data[off], pl) / 8;
			break;
		case AX25_XID_PI_K_RX:
			if (pl == 0) {
				x->has |= AX25_XID_HAS_K_RX << AX25_XID_DEF_SHIFT;
				break;
			}
			x->has |= AX25_XID_HAS_K_RX;
			x->k_rx = ax25_xid_be(&data[off], pl);
			break;
		case AX25_XID_PI_T1:
			if (pl == 0) {
				x->has |= AX25_XID_HAS_T1 << AX25_XID_DEF_SHIFT;
				break;
			}
			x->has |= AX25_XID_HAS_T1;
			x->t1_ms = ax25_xid_be(&data[off], pl);
			break;
		case AX25_XID_PI_N2:
			if (pl == 0) {
				x->has |= AX25_XID_HAS_N2 << AX25_XID_DEF_SHIFT;
				break;
			}
			x->has |= AX25_XID_HAS_N2;
			x->n2 = ax25_xid_be(&data[off], pl);
			break;
		default:
			/* "A parameter field containing an unrecognized PI is ignored" */
			break;
		}
		off += pl;
	}
}

/* Has the XID got the parameter, or a default for it? */
static bool
ax25_xid_has(const ax25_xid_t *x, unsigned flag, bool *is_default)
{
	*is_default = (x->has & (flag << AX25_XID_DEF_SHIFT)) != 0;
	return (x->has & flag) || *is_default;
}

/*
 * What an XID command or response from direction d tells us. Each side
 * notifies what it can receive (N1 Rx, k Rx) in both; the response sets
 * the negotiated values for the link (section 6.3.2). An omitted PI keeps
 * the current value.
 */
static void
ax25_apply_xid_notifications(ax25_conv_t *conv, uint8_t d, const ax25_xid_t *x, uint32_t frame)
{
	bool def;

	if (ax25_xid_has(x, AX25_XID_HAS_N1_RX, &def)) {
		conv->xid_n1_frame[d] = frame;
		conv->xid_n1_default[d] = def;
		conv->xid_n1[d] = x->n1_rx;
	}
	if (ax25_xid_has(x, AX25_XID_HAS_K_RX, &def)) {
		conv->xid_k_frame[d] = frame;
		conv->xid_k_default[d] = def;
		conv->xid_k[d] = x->k_rx;
	}
}

static void
ax25_check_xid_response(ax25_pkt_t *pkt, const ax25_xid_t *cmd, uint32_t cmd_frame,
		const ax25_xid_t *resp)
{
	unsigned flags = 0;

	/* The lesser of what was offered and what was answered... */
	if ((cmd->has & resp->has & AX25_XID_HAS_DUPLEX) && resp->full_duplex && !cmd->full_duplex)
		flags |= AX25_XIDCHK_DUPLEX;
	if ((cmd->has & resp->has & AX25_XID_HAS_REJ) && resp->rej > cmd->rej)
		flags |= AX25_XIDCHK_REJ;
	if ((cmd->has & resp->has & AX25_XID_HAS_MODULO) && resp->modulo > cmd->modulo)
		flags |= AX25_XIDCHK_MODULO;
	/* ...but the greater for the timer and retries */
	if ((cmd->has & resp->has & AX25_XID_HAS_T1) && resp->t1_ms < cmd->t1_ms)
		flags |= AX25_XIDCHK_T1;
	if ((cmd->has & resp->has & AX25_XID_HAS_N2) && resp->n2 < cmd->n2)
		flags |= AX25_XIDCHK_N2;

	if (!flags)
		return;
	pkt->xid_check = wmem_new(wmem_file_scope(), ax25_xid_check_t);
	pkt->xid_check->cmd_frame = cmd_frame;
	pkt->xid_check->flags = flags;
	pkt->xid_check->cmd = *cmd;
	pkt->xid_check->resp = *resp;
}

/*
 * XID frames (first pass). Accepted before the SABM(E) (sections 4.3.3.7
 * and 6.3.2) as well as after the UA (Appendix C5.3; what Direwolf does).
 */
static void
ax25_handle_xid(ax25_conv_t *conv, ax25_pkt_t *pkt, packet_info *pinfo, const ax25_frame_t *f)
{
	ax25_xid_t x;
	bool def;
	uint8_t d = f->dir;

	ax25_xid_neg_t *neg;

	ax25_parse_xid(f->tvb, f->ctl_offset + 1, f->cr != AX25_CR_RESPONSE, &x);
	if (!x.valid)
		return;

	ax25_apply_xid_notifications(conv, d, &x, pinfo->num);

	if (f->cr != AX25_CR_UNKNOWN) {
		neg = wmem_new0(wmem_file_scope(), ax25_xid_neg_t);
		neg->response = (f->cr == AX25_CR_RESPONSE);
		neg->self = x;
		neg->modulo_before = conv->modulo;
		neg->connected = (conv->state == AX25_LINK_CONNECTED);
		if (neg->response && conv->xid_cmd_valid[!d]) {
			neg->cmd_frame = conv->xid_cmd_frame[!d];
			neg->cmd = conv->xid_cmd[!d];
		}
		pkt->xid_neg = neg;
	}

	if (f->cr == AX25_CR_COMMAND) {
		conv->xid_cmd_valid[d] = true;
		conv->xid_cmd_frame[d] = pinfo->num;
		conv->xid_cmd[d] = x;
		return;
	}
	if (f->cr != AX25_CR_RESPONSE)
		return;

	/* A response: both stations do v2.2 (section 6.3.2) */
	conv->v22_frame = pinfo->num;
	conv->xid_neg_frame = pinfo->num;
	if (conv->xid_cmd_valid[!d])
		ax25_check_xid_response(pkt, &conv->xid_cmd[!d], conv->xid_cmd_frame[!d], &x);
	conv->xid_cmd_valid[!d] = false;

	if (ax25_xid_has(&x, AX25_XID_HAS_T1, &def)) {
		conv->xid_t1_frame = pinfo->num;
		conv->xid_t1_default = def;
		conv->xid_t1_ms = x.t1_ms;
	}
	if (ax25_xid_has(&x, AX25_XID_HAS_N2, &def)) {
		conv->xid_n2_frame = pinfo->num;
		conv->xid_n2_default = def;
		conv->xid_n2 = x.n2;
	}
	if (x.has & AX25_XID_HAS_SEGMENTER) {
		conv->xid_segmenter_known = true;
		conv->xid_segmenter = x.segmenter;
	}
	/*
	 * The modulo only changes on an explicit selection, not on PL=0 or
	 * GL=0: switching a running link to a default it wasn't set up
	 * with would wreck the decoding.
	 */
	if (x.has & AX25_XID_HAS_MODULO) {
		conv->xid_modulo = x.modulo;
		if (conv->state == AX25_LINK_CONNECTED && x.modulo != conv->modulo) {
			pkt->xid_modulo_prev = conv->modulo;
			ax25_set_modulo(conv, x.modulo, AX25_MODSRC_XID, pinfo->num);
		}
	}
}

/*
 * How long a connected link can stay silent before it must be down: each
 * side polls after T3 and gives up after N2 tries of T1 (section 6.7.1.3).
 * Use the more patient side.
 */
static double
ax25_idle_limit_s(const ax25_conv_t *conv)
{
	double lim = 0, t3;
	uint8_t d;

	for (d = 0; d < 2; d++) {
		t3 = ax25_param_t3_s(conv, d);
		if (t3 <= 0)
			continue;	/* that side doesn't poll */
		lim = MAX(lim, t3 + ax25_param_n2(conv, d) * ax25_param_t1_s(conv, d));
	}
	return lim;	/* 0: disabled */
}

/* How long after a frame a digipeated copy of it may still be heard */
static double
ax25_dup_window_s(const ax25_conv_t *conv)
{
	return MAX(ax25_param_t1_s(conv, AX25_DIR_LO_HI), ax25_param_t1_s(conv, AX25_DIR_HI_LO));
}

/*
 * Does a SABM(E) start a new stream on this link (TCP-style reuse)?
 * Yes if anything at all has been seen on the current stream, except:
 * - while a connection attempt is unanswered, retries of the same
 *   SABM(E) from the same side, and the other side sending the same
 *   SABM(E) at the same time (a collision, section 6.3.6.2);
 * - a SABM from the side whose SABME was just answered by DM or FRMR:
 *   that is the same connection attempt falling back to v2.0
 *   (section 4.3.3.2).
 */
static bool
ax25_sabm_starts_stream(const ax25_conv_t *conv, const ax25_frame_t *f)
{
	if (conv->nframes == 0)
		return false;
	if (conv->state == AX25_LINK_CONNECTING && conv->connect_type == f->ftype)
		return false;
	if (conv->fallback_pending && f->ftype == AX25_FT_SABM && f->dir == conv->fallback_dir)
		return false;
	return true;
}

/*
 * Hearing only the responder: a UA nobody asked for while the link is
 * known to be down can only answer a SABM(E) we didn't hear (a DISC
 * while disconnected gets a DM, section 6.3.5), so it starts a stream.
 * Not on PRESUMED_DOWN, which is only inferred.
 */
static bool
ax25_ua_starts_stream(const ax25_conv_t *conv, const ax25_frame_t *f)
{
	if (f->ftype != AX25_FT_UA || conv->nframes == 0)
		return false;
	if (conv->last_cmd[!f->dir] != AX25_FT_NONE &&
	    conv->last_cmd_frame[!f->dir] > conv->state_frame)
		return false;	/* it answers something we heard */
	return conv->state == AX25_LINK_DISCONNECTED_DISC ||
	       conv->state == AX25_LINK_DISCONNECTED_DM ||
	       conv->state == AX25_LINK_FRMR;
}

/*
 * Start the state of a new stream. What we know about the stations
 * carries over from the previous stream on the same link: the modulo
 * stays in effect until the UA of the new connection, and version
 * evidence is about the stations, not the connection.
 */
static ax25_conv_t *
ax25_new_conv(conversation_t *conversation, const ax25_conv_t *prev,
		const conversation_element_t *key)
{
	ax25_conv_t *conv = wmem_new0(wmem_file_scope(), ax25_conv_t);
	const ax25_station_uat_t *st;
	uint8_t d;

	conv->state = AX25_LINK_UNKNOWN;
	conv->state_ftype = AX25_FT_NONE;
	conv->last_cmd[0] = conv->last_cmd[1] = AX25_FT_NONE;
	for (d = 0; d < 2; d++) {
		/* The lower address sends in AX25_DIR_LO_HI */
		memcpy(conv->addr[d],
		       key[d == AX25_DIR_LO_HI ? AX25_KEY_ADDR_LO : AX25_KEY_ADDR_HI].addr_val.data,
		       AX25_ADDR_LEN);
		st = ax25_find_station(conv->addr[d]);
		if (st) {
			conv->has_uat[d] = true;
			conv->uat[d] = *st;
			conv->uat[d].callsign = NULL;
		}
	}
	if (prev) {
		conv->v20_frame = prev->v20_frame;
		conv->v22_frame = prev->v22_frame;
		/*
		 * An XID exchange since the last connection activity is the
		 * parameter negotiation for this new connection (XID before
		 * SABM(E), section 6.3.2); keep it.
		 */
		if (prev->xid_neg_frame > prev->conn_activity_frame ||
		    prev->xid_n1_frame[0] > prev->conn_activity_frame ||
		    prev->xid_n1_frame[1] > prev->conn_activity_frame ||
		    prev->xid_k_frame[0] > prev->conn_activity_frame ||
		    prev->xid_k_frame[1] > prev->conn_activity_frame) {
			memcpy(conv->xid_cmd_valid, prev->xid_cmd_valid, sizeof conv->xid_cmd_valid);
			memcpy(conv->xid_cmd_frame, prev->xid_cmd_frame, sizeof conv->xid_cmd_frame);
			memcpy(conv->xid_cmd, prev->xid_cmd, sizeof conv->xid_cmd);
			conv->xid_neg_frame = prev->xid_neg_frame;
			conv->xid_t1_frame = prev->xid_t1_frame;
			conv->xid_t1_default = prev->xid_t1_default;
			conv->xid_t1_ms = prev->xid_t1_ms;
			conv->xid_n2_frame = prev->xid_n2_frame;
			conv->xid_n2_default = prev->xid_n2_default;
			conv->xid_n2 = prev->xid_n2;
			conv->xid_modulo = prev->xid_modulo;
			conv->xid_segmenter_known = prev->xid_segmenter_known;
			conv->xid_segmenter = prev->xid_segmenter;
			memcpy(conv->xid_n1_frame, prev->xid_n1_frame, sizeof conv->xid_n1_frame);
			memcpy(conv->xid_n1_default, prev->xid_n1_default, sizeof conv->xid_n1_default);
			memcpy(conv->xid_n1, prev->xid_n1, sizeof conv->xid_n1);
			memcpy(conv->xid_k_frame, prev->xid_k_frame, sizeof conv->xid_k_frame);
			memcpy(conv->xid_k_default, prev->xid_k_default, sizeof conv->xid_k_default);
			memcpy(conv->xid_k, prev->xid_k, sizeof conv->xid_k);
		}
		conv->modulo = prev->modulo;
		conv->modulo_src = prev->modulo_src;
		conv->modulo_frame = prev->modulo_frame;
		conv->pre20_frame = prev->pre20_frame;
		conv->last_enc[0] = prev->last_enc[0];
		conv->last_enc[1] = prev->last_enc[1];
		conv->last_enc_frame[0] = prev->last_enc_frame[0];
		conv->last_enc_frame[1] = prev->last_enc_frame[1];
		conv->fallback_pending = prev->fallback_pending;
		conv->fallback_dir = prev->fallback_dir;
		conv->fallback_frame = prev->fallback_frame;
	} else {
		conv->modulo = 8;
		conv->modulo_src = AX25_MODSRC_ASSUMED;
	}
	conversation_add_proto_data(conversation, proto_ax25, conv);
	return conv;
}

static void
ax25_set_modulo(ax25_conv_t *conv, uint8_t modulo, ax25_modsrc_e src, uint32_t frame)
{
	conv->modulo = modulo;
	conv->modulo_src = src;
	conv->modulo_frame = frame;
}

static void
ax25_set_state(ax25_conv_t *conv, ax25_link_state_e state, uint32_t frame, ax25_ftype_e ft)
{
	conv->state = state;
	conv->state_frame = frame;
	conv->state_ftype = ft;
}

/*
 * Mid-session start: try to tell the modulo from an S frame.
 *
 * - In modulo 128 bits 4-7 of the first octet are always 0 (Figure 4.1b),
 *   so any of them set proves modulo 8.
 * - Without anything after the control field, a modulo 8 S frame is one
 *   octet long and a modulo 128 one two octets. AX.25 has no information
 *   field in S frames, so a frame that ends right after one or two control
 *   octets is decisive. A trailing FCS doesn't fool this: it would make
 *   the frame at least three octets long, which isn't decisive.
 *
 * Returns 0 if the frame doesn't tell.
 */
static uint8_t
ax25_infer_modulo(const ax25_frame_t *f)
{
	if (!ax25_ftype_is_s(f->ftype))
		return 0;
	if (f->c0 & AX25_S128_ZERO_BITS)
		return 8;
	if (f->ctl_remaining == 1)
		return 8;
	if (f->ctl_remaining == 2)
		return 128;
	return 0;
}

/*
 * The modulo the control field of this frame is decoded with. Called on
 * the first pass before the frame is decoded.
 */
static void
ax25_update_modulo_before(ax25_conv_t *conv, packet_info *pinfo, const ax25_frame_t *f)
{
	uint8_t inferred;

	if (!ax25_ftype_is_numbered(f->ftype))
		return;

	/*
	 * I or S frames from the side that sent an unanswered SABM(E): that
	 * station only sends them once it has the UA (section 6.3.1), so
	 * the UA was missed (we may hear only one side). Use what the
	 * SABM(E) asked for. Frames from the other side between the SABM(E)
	 * and the UA keep the previous modulo.
	 */
	if (conv->state == AX25_LINK_CONNECTING) {
		if (f->dir == conv->connect_dir)
			ax25_set_modulo(conv, conv->connect_type == AX25_FT_SABME ? 128 : 8,
					AX25_MODSRC_NO_UA, conv->connect_frame);
		return;
	}

	if (conv->modulo_src == AX25_MODSRC_ASSUMED) {
		inferred = ax25_infer_modulo(f);
		if (inferred)
			ax25_set_modulo(conv, inferred, AX25_MODSRC_INFERRED, pinfo->num);
	}
}

/* N(S) and N(R) of an I or S frame, without throwing */
static bool
ax25_get_seq(const ax25_frame_t *f, uint8_t modulo, uint8_t *ns, uint8_t *nr)
{
	unsigned c;

	if (!ax25_ftype_is_numbered(f->ftype))
		return false;
	if (modulo == 128) {
		if (tvb_captured_length_remaining(f->tvb, f->ctl_offset) < 2)
			return false;
		c = tvb_get_letohs(f->tvb, f->ctl_offset);
		*nr = (uint8_t)((c & XDLC_N_R_EXT_MASK) >> XDLC_N_R_EXT_SHIFT);
		*ns = (uint8_t)((c & XDLC_N_S_EXT_MASK) >> XDLC_N_S_EXT_SHIFT);
	} else {
		c = f->c0;
		*nr = (uint8_t)((c & XDLC_N_R_MASK) >> XDLC_N_R_SHIFT);
		*ns = (uint8_t)((c & XDLC_N_S_MASK) >> XDLC_N_S_SHIFT);
	}
	return true;
}

/*
 * After an idle gap, does this frame carry on where the link left off?
 * An I frame continues if its N(S) follows (or repeats) the last N(S)
 * from the same side, or is what the other side last asked for in N(R).
 * An S frame continues if its N(R) repeats the last one from the same
 * side, or acknowledges the last I frame from the other side.
 */
static bool
ax25_seq_continues(const ax25_conv_t *conv, const ax25_frame_t *f, uint8_t modulo,
		uint8_t ns, uint8_t nr)
{
	uint8_t d = f->dir;

	if (f->ftype == AX25_FT_I) {
		if (conv->ns_valid[d] &&
		    (ns == conv->last_ns[d] || ns == (conv->last_ns[d] + 1) % modulo))
			return true;
		if (conv->nr_valid[!d] && ns == conv->last_nr[!d])
			return true;
		return false;
	}
	if (conv->nr_valid[d] && nr == conv->last_nr[d])
		return true;
	if (conv->ns_valid[!d] && nr == (conv->last_ns[!d] + 1) % modulo)
		return true;
	return false;
}

/*
 * Copy of the frame with the H bits of the digipeater path cleared, so
 * a digipeated copy compares equal to what it was copied from.
 */
static uint8_t *
ax25_dup_signature(const ax25_frame_t *f, unsigned *len)
{
	uint8_t *data;
	unsigned i;

	*len = tvb_captured_length(f->tvb);
	data = (uint8_t *)tvb_memdup(wmem_file_scope(), f->tvb, 0, *len);
	for (i = 0; i < f->ndigis; i++)
		data[f->digi_ssid_offset[i]] &= ~AX25_SSID_CR;
	return data;
}

/*
 * A digipeated copy matches a recent frame on the link except for the H
 * bits, and has the same H bits set plus at least one more. A frame
 * repeated with the same H bits is a retransmission, not a copy.
 */
static const ax25_hist_t *
ax25_find_dup(const ax25_conv_t *conv, packet_info *pinfo, const ax25_frame_t *f,
		const uint8_t *sig, unsigned len)
{
	const ax25_hist_t *h;
	nstime_t age;
	unsigned i, n;

	if (f->ndigis == 0)
		return NULL;

	for (n = 1; n <= AX25_DUP_HISTORY; n++) {
		i = (conv->hist_next + AX25_DUP_HISTORY - n) % AX25_DUP_HISTORY;
		h = &conv->hist[i];
		if (!h->data)
			break;
		if (h->reported_len != tvb_reported_length(f->tvb) || h->len != len ||
		    memcmp(h->data, sig, len) != 0)
			continue;
		/* The most recent frame with the same content decides */
		nstime_delta(&age, &pinfo->abs_ts, &h->ts);
		if (nstime_to_sec(&age) > ax25_dup_window_s(conv))
			return NULL;
		if (f->hbits != h->hbits && (f->hbits & h->hbits) == h->hbits)
			return h;
		return NULL;
	}
	return NULL;
}

static void
ax25_remember_frame(ax25_conv_t *conv, packet_info *pinfo, const ax25_frame_t *f,
		uint8_t *sig, unsigned len, ax25_pkt_t *pkt)
{
	ax25_hist_t *h;

	if (!sig)
		return;
	h = &conv->hist[conv->hist_next];
	if (h->data)
		wmem_free(wmem_file_scope(), h->data);
	h->frame = pinfo->num;
	h->ts = pinfo->abs_ts;
	h->reported_len = tvb_reported_length(f->tvb);
	h->len = len;
	h->hbits = f->hbits;
	h->data = sig;
	h->pkt = pkt;
	conv->hist_next = (conv->hist_next + 1) % AX25_DUP_HISTORY;
}

static void
ax25_seq_flag(ax25_pkt_t *pkt, const ax25_conv_t *conv, ax25_seq_expert_e e)
{
	pkt->seq_expert = e;
	pkt->seq_frame = conv->state_frame;
	pkt->seq_ftype = conv->state_ftype;
}

/*
 * The link state machine. Responses are paired with the last command
 * from the other side. It has to cope with hearing only one side of the
 * link, so missing frames are inferred where the protocol allows it.
 */
static void
ax25_update_state(ax25_conv_t *conv, ax25_pkt_t *pkt, packet_info *pinfo,
		const ax25_frame_t *f, uint8_t modulo)
{
	uint8_t d = f->dir;
	uint8_t ns = 0, nr = 0;
	bool have_seq;
	nstime_t gap;
	double limit;

	have_seq = ax25_get_seq(f, modulo, &ns, &nr);

	/* A connected link silent for longer than it can be is down */
	if (conv->state == AX25_LINK_CONNECTED && conv->nframes > 0) {
		nstime_delta(&gap, &pinfo->abs_ts, &conv->last_ts);
		limit = ax25_idle_limit_s(conv);
		if (limit > 0 && nstime_to_sec(&gap) > limit) {
			ax25_set_state(conv, AX25_LINK_PRESUMED_DOWN, conv->last_frame, AX25_FT_NONE);
			conv->idle_gap = gap;
			conv->idle_limit_s = limit;
		}
	}

	switch (f->ftype) {
	case AX25_FT_SABM:
	case AX25_FT_SABME:
		if (conv->fallback_pending && f->ftype == AX25_FT_SABM && d == conv->fallback_dir) {
			pkt->fallback_frame = conv->fallback_frame;
			conv->v20_frame = pinfo->num;
		}
		conv->fallback_pending = false;
		/* Connecting in a modulo other than the one just negotiated */
		if (conv->xid_neg_frame && conv->xid_modulo &&
		    conv->xid_modulo != (f->ftype == AX25_FT_SABME ? 128 : 8)) {
			pkt->sabm_xid_frame = conv->xid_neg_frame;
			pkt->sabm_xid_modulo = conv->xid_modulo;
		}
		if (conv->state != AX25_LINK_CONNECTING) {
			ax25_set_state(conv, AX25_LINK_CONNECTING, pinfo->num, f->ftype);
			conv->connect_dir = d;
			conv->connect_type = f->ftype;
			conv->connect_frame = pinfo->num;
		}
		break;

	case AX25_FT_DISC:
		ax25_set_state(conv, AX25_LINK_DISCONNECTING, pinfo->num, f->ftype);
		conv->disc_dir = d;
		break;

	case AX25_FT_UA:
		if (conv->state == AX25_LINK_CONNECTING && d != conv->connect_dir) {
			ax25_set_state(conv, AX25_LINK_CONNECTED, pinfo->num, f->ftype);
			ax25_set_modulo(conv, conv->connect_type == AX25_FT_SABME ? 128 : 8,
					AX25_MODSRC_SABM_UA, pinfo->num);
			/* SABME exists from v2.2 on; a SABM link is a v2.0 one */
			if (conv->connect_type == AX25_FT_SABME)
				conv->v22_frame = pinfo->num;
			else
				conv->v20_frame = pinfo->num;
			conv->ns_valid[0] = conv->ns_valid[1] = false;
			conv->nr_valid[0] = conv->nr_valid[1] = false;
		} else if (conv->state == AX25_LINK_DISCONNECTING && d != conv->disc_dir) {
			ax25_set_state(conv, AX25_LINK_DISCONNECTED_DISC, pinfo->num, f->ftype);
		}
		/* Otherwise we can't tell what it answers: a UA as the first
		 * frame stays UNKNOWN (see ax25_first_pass() for a UA that
		 * starts a stream). */
		break;

	case AX25_FT_DM:
		if (conv->state == AX25_LINK_CONNECTING && d != conv->connect_dir) {
			/* DM answering SABM(E): refused (section 6.3.1) */
			pkt->refused_frame = conv->connect_frame;
			if (conv->connect_type == AX25_FT_SABME) {
				conv->fallback_pending = true;
				conv->fallback_dir = conv->connect_dir;
				conv->fallback_frame = pinfo->num;
			}
		}
		/* Otherwise, answering I/S frames, a DISC, or unsolicited: down */
		ax25_set_state(conv, AX25_LINK_DISCONNECTED_DM, pinfo->num, f->ftype);
		break;

	case AX25_FT_FRMR:
		if (conv->last_cmd[!d] == AX25_FT_XID) {
			/* A pre-2.2 station rejecting XID (section 6.3.2): it
			 * uses v2.0 defaults. Not a link error. */
			pkt->frmr_xid_frame = conv->last_cmd_frame[!d];
			conv->v20_frame = pinfo->num;
			conv->xid_cmd_valid[!d] = false;
		} else if (conv->state == AX25_LINK_CONNECTING && d != conv->connect_dir &&
			   conv->connect_type == AX25_FT_SABME) {
			/* A pre-2.2 station rejecting SABME (section 4.3.3.2);
			 * expect a SABM. */
			pkt->refused_frame = conv->connect_frame;
			conv->fallback_pending = true;
			conv->fallback_dir = conv->connect_dir;
			conv->fallback_frame = pinfo->num;
			ax25_set_state(conv, AX25_LINK_DISCONNECTED_DM, pinfo->num, f->ftype);
		} else {
			ax25_set_state(conv, AX25_LINK_FRMR, pinfo->num, f->ftype);
		}
		break;

	case AX25_FT_I:
	case AX25_FT_RR:
	case AX25_FT_RNR:
	case AX25_FT_REJ:
	case AX25_FT_SREJ:
		/* Checked: I frames, and S frames sent as commands */
		if (f->ftype == AX25_FT_I || f->cr == AX25_CR_COMMAND) {
			switch (conv->state) {
			case AX25_LINK_DISCONNECTED_DISC:
				ax25_seq_flag(pkt, conv, AX25_SEQ_AFTER_DISC);
				break;
			case AX25_LINK_DISCONNECTED_DM:
				ax25_seq_flag(pkt, conv, AX25_SEQ_AFTER_DM);
				break;
			case AX25_LINK_FRMR:
				ax25_seq_flag(pkt, conv, AX25_SEQ_AFTER_FRMR);
				break;
			case AX25_LINK_DISCONNECTING:
				ax25_seq_flag(pkt, conv, AX25_SEQ_DISCONNECTING);
				break;
			default:
				break;
			}
		}
		switch (conv->state) {
		case AX25_LINK_UNKNOWN:
			/* Mid-session start: traffic means the link is up */
			ax25_set_state(conv, AX25_LINK_CONNECTED, pinfo->num, f->ftype);
			break;
		case AX25_LINK_CONNECTING:
			/* From the initiator, the UA was missed (see
			 * ax25_update_modulo_before()). From the other side
			 * these are left over from before the SABM(E). */
			if (d == conv->connect_dir)
				ax25_set_state(conv, AX25_LINK_CONNECTED, pinfo->num, f->ftype);
			break;
		case AX25_LINK_PRESUMED_DOWN:
			/* Traffic resumed after the gap. Only an inferred state,
			 * so it never splits the stream or changes the modulo. */
			if (f->ftype == AX25_FT_I || f->cr == AX25_CR_COMMAND) {
				ax25_seq_flag(pkt, conv,
					have_seq && ax25_seq_continues(conv, f, modulo, ns, nr) ?
					AX25_SEQ_CAPTURE_GAP : AX25_SEQ_AFTER_IDLE);
				pkt->idle_gap = conv->idle_gap;
				pkt->idle_limit_s = conv->idle_limit_s;
			}
			ax25_set_state(conv, AX25_LINK_CONNECTED, pinfo->num, f->ftype);
			break;
		default:
			break;
		}
		if (have_seq) {
			if (f->ftype == AX25_FT_I) {
				conv->last_ns[d] = ns;
				conv->ns_valid[d] = true;
			}
			conv->last_nr[d] = nr;
			conv->nr_valid[d] = true;
		}
		break;

	case AX25_FT_XID:
		/* Doesn't change the link state, but the parameters */
		ax25_handle_xid(conv, pkt, pinfo, f);
		break;

	default:
		/* UI and TEST don't change the link state */
		break;
	}

	switch (f->ftype) {
	case AX25_FT_UI:
	case AX25_FT_XID:
	case AX25_FT_TEST:
	case AX25_FT_U_OTHER:
		break;
	case AX25_FT_FRMR:
		if (pkt->frmr_xid_frame)
			break;
		/* FALLTHROUGH */
	default:
		conv->conn_activity_frame = pinfo->num;
		break;
	}

	if (f->cr == AX25_CR_COMMAND) {
		conv->last_cmd[d] = f->ftype;
		conv->last_cmd_frame[d] = pinfo->num;
	}
}

/* PID of an I or UI frame, without throwing */
static bool
ax25_get_pid(const ax25_frame_t *f, uint8_t modulo, int *pid_offset, uint8_t *pid)
{
	int off;

	if (f->ftype != AX25_FT_I && f->ftype != AX25_FT_UI)
		return false;
	off = f->ctl_offset + ((f->ftype == AX25_FT_I && modulo == 128) ? 2 : 1);
	if (tvb_captured_length_remaining(f->tvb, off) < 1)
		return false;
	*pid_offset = off;
	*pid = tvb_get_uint8(f->tvb, off);
	return true;
}

/* TR210: the preference, or how long the sender keeps trying (N2 x T1) */
static double
ax25_tr210_s(const ax25_pkt_t *pkt)
{
	if (ax25_pref_tr210_s)
		return (double)ax25_pref_tr210_s;
	return pkt->params.n2.value * (pkt->params.t1_ms.value / 1000.0);
}

/*
 * Segmenter analysis (section 6.6, Appendix C6), per direction, over I
 * and UI frames alike. No reassembly: just check that each sequence
 * starts with a first segment, that the remaining count goes down by one
 * each time, and that nothing else is sent in the middle of a sequence
 * (C6.3.2).
 */
static void
ax25_track_segments(ax25_conv_t *conv, ax25_pkt_t *pkt, packet_info *pinfo,
		const ax25_frame_t *f, uint8_t modulo)
{
	uint8_t d = f->dir;
	uint8_t pid, hdr, remaining, ns = 0, nr = 0;
	int pid_offset;
	bool first, have_ns, over_ui;
	nstime_t gap;

	if (!ax25_get_pid(f, modulo, &pid_offset, &pid))
		return;
	over_ui = (f->ftype == AX25_FT_UI);

	if (pid != AX25_P_SEGMENT) {
		/* Any other data from the same side breaks a sequence */
		if (conv->seg_active[d]) {
			pkt->seg_flags |= AX25_SEGF_INTERLEAVED;
			pkt->seg_first_frame = conv->seg_first_frame[d];
			conv->seg_active[d] = false;
		}
		return;
	}
	if (tvb_captured_length_remaining(f->tvb, pid_offset + 1) < 1)
		return;
	hdr = tvb_get_uint8(f->tvb, pid_offset + 1);
	first = (hdr & AX25_SEG_FIRST) != 0;
	remaining = hdr & AX25_SEG_REMAINING;
	have_ns = (f->ftype == AX25_FT_I) && ax25_get_seq(f, modulo, &ns, &nr);

	/* An I frame sent again (same N(S), same segment) isn't a new segment */
	if (have_ns && conv->seg_last_ns_valid[d] && ns == conv->seg_last_ns[d] &&
	    !conv->seg_over_ui[d] &&
	    (conv->seg_active[d] ? remaining == conv->seg_remaining[d] : remaining == 0)) {
		pkt->seg_flags |= AX25_SEGF_RETRANSMISSION;
		pkt->seg_first_frame = conv->seg_first_frame[d];
		return;
	}

	/* Did the stations agree to use the segmenter? */
	if (first || !conv->seg_active[d]) {
		if (!conv->xid_neg_frame) {
			pkt->seg_flags |= AX25_SEGF_NEG_NOT_CAPTURED;
		} else if (conv->xid_segmenter_known && !conv->xid_segmenter) {
			pkt->seg_flags |= AX25_SEGF_NOT_NEGOTIATED;
			pkt->seg_xid_frame = conv->xid_neg_frame;
		}
	}

	if (conv->seg_active[d]) {
		nstime_delta(&gap, &pinfo->abs_ts, &conv->seg_last_ts[d]);
		pkt->seg_tr210_s = ax25_tr210_s(pkt);
		if (pkt->seg_tr210_s > 0 && nstime_to_sec(&gap) > pkt->seg_tr210_s) {
			pkt->seg_flags |= AX25_SEGF_TR210;
			pkt->seg_gap = gap;
		}
		if (conv->seg_over_ui[d] != over_ui) {
			/* I and UI segments don't make one sequence */
			pkt->seg_flags |= AX25_SEGF_INTERLEAVED;
			pkt->seg_first_frame = conv->seg_first_frame[d];
			conv->seg_active[d] = false;
		}
	}

	if (first) {
		if (conv->seg_active[d]) {
			pkt->seg_flags |= AX25_SEGF_ABANDONED;
			pkt->seg_expected = conv->seg_remaining[d] - 1;
			pkt->seg_first_frame = conv->seg_first_frame[d];
		}
		conv->seg_first_frame[d] = pinfo->num;
		conv->seg_active[d] = (remaining > 0);
	} else if (!conv->seg_active[d]) {
		pkt->seg_flags |= AX25_SEGF_MISSING_FIRST;
		/* Follow what's left of the sequence anyway */
		conv->seg_first_frame[d] = 0;
		conv->seg_active[d] = (remaining > 0);
	} else {
		if (remaining != conv->seg_remaining[d] - 1) {
			pkt->seg_flags |= AX25_SEGF_BAD_REMAINING;
			pkt->seg_expected = conv->seg_remaining[d] - 1;
		}
		conv->seg_active[d] = (remaining > 0);
	}
	if (!pkt->seg_first_frame)
		pkt->seg_first_frame = conv->seg_first_frame[d];
	conv->seg_remaining[d] = remaining;
	conv->seg_over_ui[d] = over_ui;
	conv->seg_last_ts[d] = pinfo->abs_ts;
	conv->seg_last_ns_valid[d] = have_ns;
	conv->seg_last_ns[d] = ns;
}

/*
 * First pass: find (or start) the link this frame belongs to, update its
 * state and return the snapshot later passes will use.
 */
static ax25_pkt_t *
ax25_first_pass(packet_info *pinfo, conversation_element_t *key, const ax25_frame_t *f)
{
	conversation_t *conversation;
	ax25_conv_t *conv = NULL;
	ax25_pkt_t *pkt;
	const ax25_hist_t *orig;
	uint8_t *sig;
	unsigned sig_len = 0;
	uint8_t enc;

	conversation = find_conversation_full(pinfo->num, key);
	if (conversation)
		conv = (ax25_conv_t *)conversation_get_proto_data(conversation, proto_ax25);

	sig = f->ndigis ? ax25_dup_signature(f, &sig_len) : NULL;

	/* A digipeated copy is decoded like the original and changes nothing */
	if (conv && sig && (orig = ax25_find_dup(conv, pinfo, f, sig, sig_len)) != NULL) {
		pkt = wmem_new(wmem_file_scope(), ax25_pkt_t);
		*pkt = *orig->pkt;
		pkt->seq_expert = AX25_SEQ_NONE;
		pkt->cr_mixed_frame = 0;
		pkt->refused_frame = 0;
		pkt->frmr_xid_frame = 0;
		pkt->fallback_frame = 0;
		pkt->xid_check = NULL;
		pkt->sabm_xid_frame = 0;
		pkt->xid_modulo_prev = 0;
		pkt->xid_neg = NULL;
		pkt->seg_flags = 0;
		pkt->dup_of = orig->frame;
		wmem_free(wmem_file_scope(), sig);
		return pkt;
	}

	if (conv && ((ax25_ftype_is_sabm(f->ftype) && ax25_sabm_starts_stream(conv, f)) ||
		     ax25_ua_starts_stream(conv, f))) {
		conversation = conversation_new_full(pinfo->num, key);
		conv = ax25_new_conv(conversation, conv, key);
		if (f->ftype == AX25_FT_UA) {
			/* Hearing only the responder: it accepted a SABM(E)
			 * we didn't hear. Can't tell which, so the modulo is
			 * open again. */
			ax25_set_state(conv, AX25_LINK_CONNECTED, pinfo->num, f->ftype);
			conv->modulo_src = AX25_MODSRC_ASSUMED;
			conv->modulo_frame = 0;
		}
	}
	if (!conversation)
		conversation = conversation_new_full(pinfo->num, key);
	if (!conv)
		conv = ax25_new_conv(conversation, NULL, key);

	pkt = wmem_new0(wmem_file_scope(), ax25_pkt_t);

	/* Version evidence */
	enc = (f->version == AX25_VERSION_PRE20) ? AX25_ENC_PRE20 : AX25_ENC_2X;
	if (enc == AX25_ENC_PRE20) {
		if (conv->pre20_frame == 0)
			conv->pre20_frame = pinfo->num;
		/* "implies v2.0 defaults" */
		conv->v20_frame = pinfo->num;
	}
	if (conv->last_enc[f->dir] != AX25_ENC_NONE && conv->last_enc[f->dir] != enc)
		pkt->cr_mixed_frame = conv->last_enc_frame[f->dir];
	conv->last_enc[f->dir] = enc;
	conv->last_enc_frame[f->dir] = pinfo->num;

	/* Modulo this frame is decoded with */
	ax25_update_modulo_before(conv, pinfo, f);
	pkt->modulo = conv->modulo;
	pkt->modulo_src = conv->modulo_src;
	pkt->modulo_frame = conv->modulo_frame;

	ax25_update_state(conv, pkt, pinfo, f, pkt->modulo);
	if (f->ftype == AX25_FT_UA) {
		/* The UA is the frame the new modulo takes effect at */
		pkt->modulo = conv->modulo;
		pkt->modulo_src = conv->modulo_src;
		pkt->modulo_frame = conv->modulo_frame;
	}

	/* UI frames aren't part of the connection: no stream, and they
	 * neither count as traffic nor keep the link from being idle */
	if (f->ftype != AX25_FT_UI) {
		if (!conv->has_stream) {
			conv->has_stream = true;
			conv->stream = ax25_stream_count++;
		}
		pkt->has_stream = true;
		pkt->stream = conv->stream;
	}
	pkt->dir = f->dir;
	pkt->pre20_frame = conv->pre20_frame;
	pkt->state = conv->state;
	ax25_resolve_params(conv, f->dir, &pkt->params);
	if (pkt->xid_neg) {
		ax25_resolve_params(conv, AX25_DIR_LO_HI, &pkt->xid_neg->params[AX25_DIR_LO_HI]);
		ax25_resolve_params(conv, AX25_DIR_HI_LO, &pkt->xid_neg->params[AX25_DIR_HI_LO]);
	}
	ax25_track_segments(conv, pkt, pinfo, f, pkt->modulo);

	if (f->ftype != AX25_FT_UI) {
		conv->nframes++;
		conv->last_frame = pinfo->num;
		conv->last_ts = pinfo->abs_ts;
	}
	ax25_remember_frame(conv, pinfo, f, sig, sig_len, pkt);

	return pkt;
}

/*
 * Control field of an S or U frame whose C/R is unknown (pre-2.0 C/R
 * encoding). Same layout as dissect_xdlc_control(), but the P/F bit is
 * shown as "P/F" instead of being forced to Poll.
 */
static int
ax25_dissect_control_unknown_cr(tvbuff_t *tvb, int offset, packet_info *pinfo,
		proto_tree *tree, bool is_extended)
{
	proto_item *tc;
	proto_tree *control_tree;
	int control;
	int control_len;
	bool poll_final;
	char *info;
	const char *frame_type;

	if ((tvb_get_uint8(tvb, offset) & XDLC_S_U_MASK) == XDLC_S) {
		if (is_extended) {
			control = tvb_get_letohs(tvb, offset);
			control_len = 2;
			poll_final = (control & XDLC_P_F_EXT) != 0;
		} else {
			control = tvb_get_uint8(tvb, offset);
			control_len = 1;
			poll_final = (control & XDLC_P_F) != 0;
		}
		switch (control & XDLC_S_FTYPE_MASK) {
		case XDLC_RR:	frame_type = "RR"; break;
		case XDLC_RNR:	frame_type = "RNR"; break;
		case XDLC_REJ:	frame_type = "REJ"; break;
		default:	frame_type = "SREJ"; break;
		}
		info = wmem_strdup_printf(pinfo->pool, "S%s, func=%s, N(R)=%u",
				poll_final ? " P/F" : "", frame_type,
				is_extended ?
				    (unsigned)((control & XDLC_N_R_EXT_MASK) >> XDLC_N_R_EXT_SHIFT) :
				    (unsigned)((control & XDLC_N_R_MASK) >> XDLC_N_R_SHIFT));
		col_add_str(pinfo->cinfo, COL_INFO, info);
		tc = proto_tree_add_uint_format(tree, is_extended ? hf_ax25_ctl_ext : hf_ax25_ctl,
				tvb, offset, control_len, control,
				is_extended ? "Control field: %s (0x%04X)" : "Control field: %s (0x%02X)",
				info, control);
		control_tree = proto_item_add_subtree(tc, ett_ax25_ctl);
		proto_tree_add_uint(control_tree, is_extended ? hf_ax25_n_r_ext : hf_ax25_n_r,
				tvb, offset, control_len, control);
		if (poll_final)
			proto_tree_add_boolean(control_tree, is_extended ? hf_ax25_pf_ext : hf_ax25_pf,
					tvb, offset, control_len, control);
		proto_tree_add_uint(control_tree, is_extended ? hf_ax25_ftype_s_ext : hf_ax25_ftype_s,
				tvb, offset, control_len, control);
		proto_tree_add_uint(control_tree, is_extended ? hf_ax25_ftype_su_ext : hf_ax25_ftype_su,
				tvb, offset, control_len, control);
		return control;
	}

	/* U frame: always one octet */
	control = tvb_get_uint8(tvb, offset);
	poll_final = (control & XDLC_P_F) != 0;
	info = wmem_strdup_printf(pinfo->pool, "U%s, func=%s",
			poll_final ? " P/F" : "",
			val_to_str(pinfo->pool, control & XDLC_U_MODIFIER_MASK, ax25_u_short_vals, "Unknown"));
	col_add_str(pinfo->cinfo, COL_INFO, info);
	tc = proto_tree_add_uint_format(tree, hf_ax25_ctl, tvb, offset, 1, control,
			"Control field: %s (0x%02X)", info, control);
	control_tree = proto_item_add_subtree(tc, ett_ax25_ctl);
	if (poll_final)
		proto_tree_add_boolean(control_tree, hf_ax25_pf, tvb, offset, 1, control);
	proto_tree_add_uint(control_tree, hf_ax25_u_cmd, tvb, offset, 1, control);
	proto_tree_add_uint(control_tree, hf_ax25_ftype_su, tvb, offset, 1, control);
	return control;
}

/* Generated decode items (stream, modulo) and their expert infos */
static void
ax25_add_decode_items(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
		const ax25_pkt_t *pkt, const ax25_frame_t *f)
{
	proto_item *ti;

	if (pkt->has_stream) {
		ti = proto_tree_add_uint(tree, hf_ax25_stream, tvb, 0, 0, pkt->stream);
		proto_item_set_generated(ti);
	}

	if (!ax25_ftype_is_numbered(f->ftype))
		return;

	ti = proto_tree_add_uint(tree, hf_ax25_modulo, tvb, 0, 0, pkt->modulo);
	proto_item_set_generated(ti);
	ti = proto_tree_add_uint(tree, hf_ax25_modulo_source, tvb, 0, 0, pkt->modulo_src);
	proto_item_set_generated(ti);
	if (pkt->modulo_frame) {
		ti = proto_tree_add_uint(tree, hf_ax25_modulo_frame, tvb, 0, 0, pkt->modulo_frame);
		proto_item_set_generated(ti);
	}

	switch (pkt->modulo_src) {
	case AX25_MODSRC_ASSUMED:
		proto_tree_add_expert(tree, pinfo, &ei_ax25_modulo_assumed, tvb, 0, 0);
		break;
	case AX25_MODSRC_INFERRED:
		proto_tree_add_expert_format(tree, pinfo, &ei_ax25_modulo_inferred, tvb, 0, 0,
				"Modulo %u inferred from the S frame in frame %u",
				pkt->modulo, pkt->modulo_frame);
		break;
	case AX25_MODSRC_NO_UA:
		proto_tree_add_expert_format(tree, pinfo, &ei_ax25_modulo_no_ua, tvb, 0, 0,
				"Modulo %u taken from the SABM%s in frame %u; its UA was not captured",
				pkt->modulo, pkt->modulo == 128 ? "E" : "", pkt->modulo_frame);
		break;
	case AX25_MODSRC_SABM_UA:
	case AX25_MODSRC_XID:
		break;
	}
}

static void
ax25_add_param(proto_tree *tree, tvbuff_t *tvb, int hf, int hf_src, const ax25_param_t *p)
{
	proto_item *ti;
	proto_tree *pt;

	ti = proto_tree_add_uint(tree, hf, tvb, 0, 0, p->value);
	proto_item_set_generated(ti);
	if (p->src == AX25_PSRC_XID)
		proto_item_append_text(ti, " (XID, frame %u)", p->frame);
	else
		proto_item_append_text(ti, " (%s)", val_to_str_const(p->src, ax25_psrc_vals, "?"));
	pt = proto_item_add_subtree(ti, ett_ax25_params);
	ti = proto_tree_add_uint(pt, hf_src, tvb, 0, 0, p->src);
	proto_item_set_generated(ti);
	if (p->frame) {
		ti = proto_tree_add_uint(pt, hf_ax25_param_xid_frame, tvb, 0, 0, p->frame);
		proto_item_set_generated(ti);
	}
}

/* Parameters in effect for the direction of this frame, and their sources */
static void
ax25_add_params(proto_tree *tree, tvbuff_t *tvb, const ax25_params_t *p)
{
	proto_item *ti, *pi;
	proto_tree *pt;

	pt = proto_tree_add_subtree(tree, tvb, 0, 0, ett_ax25_params, &pi, "Parameters for this direction");
	proto_item_set_generated(pi);

	ti = proto_tree_add_uint(pt, hf_ax25_param_version, tvb, 0, 0, p->version);
	proto_item_set_generated(ti);
	proto_item_append_text(ti, " (%s)", val_to_str_const(p->version_src, ax25_vsrc_vals, "?"));
	ti = proto_tree_add_uint(pt, hf_ax25_param_version_source, tvb, 0, 0, p->version_src);
	proto_item_set_generated(ti);
	if (p->version_frame) {
		ti = proto_tree_add_uint(pt, hf_ax25_param_version_frame, tvb, 0, 0, p->version_frame);
		proto_item_set_generated(ti);
	}
	ax25_add_param(pt, tvb, hf_ax25_param_t1, hf_ax25_param_t1_source, &p->t1_ms);
	ax25_add_param(pt, tvb, hf_ax25_param_t3, hf_ax25_param_t3_source, &p->t3_s);
	ax25_add_param(pt, tvb, hf_ax25_param_n2, hf_ax25_param_n2_source, &p->n2);
	ax25_add_param(pt, tvb, hf_ax25_param_n1, hf_ax25_param_n1_source, &p->n1);
	ax25_add_param(pt, tvb, hf_ax25_param_k, hf_ax25_param_k_source, &p->k);
}

/* What an XID response did wrong (section 6.3.2) */
static void
ax25_add_xid_check(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, const ax25_xid_check_t *c)
{
	wmem_strbuf_t *why = wmem_strbuf_new(pinfo->pool, "");

	/* Kept short: expert messages are cut at ITEM_LABEL_LENGTH */
	if (c->flags & AX25_XIDCHK_DUPLEX)
		wmem_strbuf_append(why, "; full duplex, half offered");
	if (c->flags & AX25_XIDCHK_REJ)
		wmem_strbuf_append(why, "; SREJ, REJ offered");
	if (c->flags & AX25_XIDCHK_MODULO)
		wmem_strbuf_append(why, "; modulo 128, 8 offered");
	if (c->flags & AX25_XIDCHK_T1)
		wmem_strbuf_append_printf(why, "; T1 %u ms < %u ms offered",
				c->resp.t1_ms, c->cmd.t1_ms);
	if (c->flags & AX25_XIDCHK_N2)
		wmem_strbuf_append_printf(why, "; N2 %u < %u offered",
				c->resp.n2, c->cmd.n2);
	proto_tree_add_expert_format(tree, pinfo, &ei_ax25_xid_rule, tvb, 0, 0,
			"XID response to frame %u breaks section 6.3.2%s",
			c->cmd_frame, wmem_strbuf_get_str(why));
}

/* Link analysis subtree: state, sequence expert infos, digipeated copies */
static void
ax25_add_link_items(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
		const ax25_pkt_t *pkt, const ax25_frame_t *f)
{
	proto_item *ti, *li;
	proto_tree *link_tree;
	const char *what;
	expert_field *ei = NULL;

	/* Nothing to say about connectionless traffic (APRS and the like) */
	if (pkt->state == AX25_LINK_UNKNOWN && !pkt->dup_of &&
	    !(pkt->seg_flags & AX25_SEGF_INTERLEAVED) &&
	    (f->ftype == AX25_FT_UI || f->ftype == AX25_FT_TEST || f->ftype == AX25_FT_U_OTHER))
		return;

	link_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_ax25_link, &li, "Link analysis");
	proto_item_set_generated(li);

	if (pkt->dup_of) {
		ti = proto_tree_add_uint(link_tree, hf_ax25_dup_of, tvb, 0, 0, pkt->dup_of);
		proto_item_set_generated(ti);
		expert_add_info_format(pinfo, ti, &ei_ax25_dup,
				"Digipeated copy of frame %u (differs only in the H bits)", pkt->dup_of);
		proto_item_append_text(li, ": digipeated copy of frame %u", pkt->dup_of);
		return;
	}

	ti = proto_tree_add_uint(link_tree, hf_ax25_link_state, tvb, 0, 0, pkt->state);
	proto_item_set_generated(ti);
	proto_item_append_text(li, ": %s", val_to_str_const(pkt->state, ax25_link_state_vals, "Unknown"));

	if (pkt->refused_frame) {
		ti = proto_tree_add_uint(link_tree, hf_ax25_link_refused, tvb, 0, 0, pkt->refused_frame);
		proto_item_set_generated(ti);
		expert_add_info_format(pinfo, ti, &ei_ax25_refused,
				"Connection refused: %s answering the SABM(E) in frame %u",
				val_to_str_const(f->ftype, ax25_ftype_names, "?"), pkt->refused_frame);
	}
	if (pkt->fallback_frame) {
		ti = proto_tree_add_uint(link_tree, hf_ax25_link_fallback, tvb, 0, 0, pkt->fallback_frame);
		proto_item_set_generated(ti);
		expert_add_info_format(pinfo, ti, &ei_ax25_fallback,
				"SABM after the SABME was rejected in frame %u: falling back to v2.0",
				pkt->fallback_frame);
	}
	if (pkt->frmr_xid_frame) {
		ti = proto_tree_add_uint(link_tree, hf_ax25_link_frmr_xid, tvb, 0, 0, pkt->frmr_xid_frame);
		proto_item_set_generated(ti);
		expert_add_info_format(pinfo, ti, &ei_ax25_frmr_xid,
				"FRMR answering the XID in frame %u: the peer uses AX.25 v2.0 (not a link error)",
				pkt->frmr_xid_frame);
	}
	if (pkt->xid_check)
		ax25_add_xid_check(link_tree, tvb, pinfo, pkt->xid_check);
	if (pkt->sabm_xid_frame)
		proto_tree_add_expert_format(link_tree, pinfo, &ei_ax25_sabm_xid, tvb, 0, 0,
				"%s, but the XID in frame %u negotiated modulo %u",
				f->ftype == AX25_FT_SABME ? "SABME (modulo 128)" : "SABM (modulo 8)",
				pkt->sabm_xid_frame, pkt->sabm_xid_modulo);
	if (pkt->xid_modulo_prev)
		proto_tree_add_expert_format(link_tree, pinfo, &ei_ax25_xid_modulo, tvb, 0, 0,
				"XID after the UA changes the modulo from %u to %u from here on",
				pkt->xid_modulo_prev, pkt->xid_modulo_prev == 8 ? 128 : 8);

	if (pkt->seg_flags & AX25_SEGF_INTERLEAVED) {
		if (pkt->seg_first_frame) {
			ti = proto_tree_add_uint(link_tree, hf_ax25_seg_first_frame, tvb, 0, 0, pkt->seg_first_frame);
			proto_item_set_generated(ti);
			expert_add_info_format(pinfo, ti, &ei_ax25_seg_interleaved,
					"Frame sent in the middle of the segmented data unit that started in frame %u"
					" (Appendix C6.3.2 forbids it)", pkt->seg_first_frame);
		} else {
			proto_tree_add_expert_format(link_tree, pinfo, &ei_ax25_seg_interleaved, tvb, 0, 0,
					"Frame sent in the middle of a segmented data unit whose first segment wasn't seen"
					" (Appendix C6.3.2 forbids it)");
		}
	}

	ax25_add_params(link_tree, tvb, &pkt->params);

	if (pkt->seq_expert == AX25_SEQ_NONE)
		return;

	what = (f->ftype == AX25_FT_I) ? "I frame" :
		wmem_strdup_printf(pinfo->pool, "%s command",
				val_to_str_const(f->ftype, ax25_ftype_names, "?"));
	ti = proto_tree_add_uint(link_tree, hf_ax25_link_state_frame, tvb, 0, 0, pkt->seq_frame);
	proto_item_set_generated(ti);

	switch (pkt->seq_expert) {
	case AX25_SEQ_AFTER_DISC:
		expert_add_info_format(pinfo, ti, &ei_ax25_after_disc,
				"%s after the link was disconnected by DISC/UA (UA in frame %u)",
				what, pkt->seq_frame);
		break;
	case AX25_SEQ_AFTER_DM:
		expert_add_info_format(pinfo, ti, &ei_ax25_after_dm,
				"%s after %s in frame %u", what,
				val_to_str_const(pkt->seq_ftype, ax25_ftype_names, "DM"), pkt->seq_frame);
		break;
	case AX25_SEQ_AFTER_FRMR:
		expert_add_info_format(pinfo, ti, &ei_ax25_after_frmr,
				"%s after FRMR in frame %u", what, pkt->seq_frame);
		break;
	case AX25_SEQ_DISCONNECTING:
		expert_add_info_format(pinfo, ti, &ei_ax25_disconnecting,
				"%s while disconnecting (DISC in frame %u)", what, pkt->seq_frame);
		break;
	case AX25_SEQ_AFTER_IDLE:
		ei = &ei_ax25_after_idle;
		/* FALLTHROUGH */
	case AX25_SEQ_CAPTURE_GAP:
		if (!ei)
			ei = &ei_ax25_capture_gap;
		ti = proto_tree_add_time(link_tree, hf_ax25_link_idle, tvb, 0, 0, &pkt->idle_gap);
		proto_item_set_generated(ti);
		if (pkt->seq_expert == AX25_SEQ_AFTER_IDLE)
			expert_add_info_format(pinfo, ti, ei,
					"%s after %.1f s of silence since frame %u (more than T3 + N2 x T1 = %.1f s): the link was presumed down",
					what, nstime_to_sec(&pkt->idle_gap), pkt->seq_frame, pkt->idle_limit_s);
		else
			expert_add_info_format(pinfo, ti, ei,
					"%s continues the sequence numbers after %.1f s of silence since frame %u (more than T3 + N2 x T1 = %.1f s): possible capture gap",
					what, nstime_to_sec(&pkt->idle_gap), pkt->seq_frame, pkt->idle_limit_s);
		break;
	case AX25_SEQ_NONE:
		break;
	}
}

/* A numeric XID parameter (big-endian, up to four octets) */
static void
ax25_xid_number(proto_tree *tree, proto_item *pi, tvbuff_t *tvb, int offset, unsigned pl,
		int hf, const char *unit, unsigned divisor)
{
	proto_item *ti;
	uint32_t v;

	if (pl > 4) {
		proto_tree_add_item(tree, hf_ax25_xid_pv, tvb, offset, pl, ENC_NA);
		return;
	}
	v = (uint32_t)tvb_get_bits64(tvb, offset * 8, pl * 8, ENC_BIG_ENDIAN);
	ti = proto_tree_add_uint(tree, hf, tvb, offset, pl, v);
	if (divisor > 1) {
		proto_item_append_text(ti, " (%u %s)", v / divisor, unit);
		proto_item_append_text(pi, ": %u %s", v / divisor, unit);
	} else {
		proto_item_append_text(pi, ": %u%s%s", v, unit[0] ? " " : "", unit);
	}
}

/*
 * XID information field (section 4.3.3.7, ISO 8885): zero or more
 * information elements, each FI, GI, a two-octet big-endian GL and then
 * PI/PL/PV parameters. See the comment at AX25_COP_ABM for the encoding.
 */
static void
ax25_dissect_xid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	proto_item *xi, *gi, *pi, *ti;
	proto_tree *xt, *pt;
	uint8_t fi, gid, pid, pl;
	uint16_t gl;
	int end, off;

	unsigned avail, glen, plen;

	if (tvb_reported_length_remaining(tvb, offset) <= 0)
		return;

	xi = proto_tree_add_item(tree, hf_ax25_xid, tvb, offset, -1, ENC_NA);
	xt = proto_item_add_subtree(xi, ett_ax25_xid);

	/*
	 * Lengths that run past their group or the frame are flagged and
	 * clamped, so the rest of the field is still shown.
	 */
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		if (tvb_reported_length_remaining(tvb, offset) < 4) {
			pi = proto_tree_add_item(xt, hf_ax25_xid_trailing, tvb, offset, -1, ENC_NA);
			expert_add_info_format(pinfo, pi, &ei_ax25_xid_length,
					"Octets after the last information element, too short for another one");
			break;
		}
		proto_tree_add_item_ret_uint8(xt, hf_ax25_xid_fi, tvb, offset, 1, ENC_NA, &fi);
		proto_tree_add_item_ret_uint8(xt, hf_ax25_xid_gi, tvb, offset + 1, 1, ENC_NA, &gid);
		gi = proto_tree_add_item_ret_uint16(xt, hf_ax25_xid_gl, tvb, offset + 2, 2, ENC_BIG_ENDIAN, &gl);
		offset += 4;
		avail = tvb_reported_length_remaining(tvb, offset);
		glen = gl;
		if (glen > avail) {
			expert_add_info_format(pinfo, gi, &ei_ax25_xid_length,
					"Group length %u runs past the end of the frame (%u octets left)", gl, avail);
			glen = avail;
		}
		if (fi != AX25_XID_FI || gid != AX25_XID_GI) {
			/* Not the general purpose / parameter negotiation group */
			if (glen)
				proto_tree_add_item(xt, hf_ax25_xid_pv, tvb, offset, glen, ENC_NA);
			offset += glen;
			continue;
		}
		if (gl == 0) {
			proto_item_append_text(gi, " (all parameters take their default values)");
			continue;
		}
		end = offset + glen;
		off = offset;
		while (off < end) {
			pid = tvb_get_uint8(tvb, off);
			if (end - off < 2) {
				pi = proto_tree_add_uint(xt, hf_ax25_xid_pi, tvb, off, 1, pid);
				expert_add_info_format(pinfo, pi, &ei_ax25_xid_length,
						"Parameter identifier at the end of the group, without a length");
				break;
			}
			pl = tvb_get_uint8(tvb, off + 1);
			plen = MIN((unsigned)pl, (unsigned)(end - off - 2));
			pt = proto_tree_add_subtree(xt, tvb, off, 2 + plen, ett_ax25_xid_param, &pi,
					val_to_str(pinfo->pool, pid, ax25_xid_pi_vals, "Parameter %u"));
			proto_tree_add_uint(pt, hf_ax25_xid_pi, tvb, off, 1, pid);
			ti = proto_tree_add_uint(pt, hf_ax25_xid_pl, tvb, off + 1, 1, pl);
			off += 2;
			if (plen < pl) {
				expert_add_info_format(pinfo, ti, &ei_ax25_xid_length,
						"Parameter length %u runs past the group (%u octets left)", pl, plen);
				/* Don't decode a value that isn't all there */
				if (plen)
					proto_tree_add_item(pt, hf_ax25_xid_pv, tvb, off, plen, ENC_NA);
				off += plen;
				continue;
			}
			if (pl == 0) {
				proto_item_append_text(pi, ": default");
				continue;
			}
			switch (pid) {
			case AX25_XID_PI_COP:
				if (pl == 2)
					proto_tree_add_bitmask_with_flags(pt, tvb, off, hf_ax25_xid_cop,
						ett_ax25_xid_bits, ax25_xid_cop_fields, ENC_LITTLE_ENDIAN,
						BMT_NO_FALSE | BMT_NO_INT);
				else
					proto_tree_add_item(pt, hf_ax25_xid_pv, tvb, off, pl, ENC_NA);
				break;
			case AX25_XID_PI_HDLC:
				if (pl == 3)
					proto_tree_add_bitmask_with_flags(pt, tvb, off, hf_ax25_xid_hdlc,
						ett_ax25_xid_bits, ax25_xid_hdlc_fields, ENC_LITTLE_ENDIAN,
						BMT_NO_FALSE | BMT_NO_INT);
				else
					proto_tree_add_item(pt, hf_ax25_xid_pv, tvb, off, pl, ENC_NA);
				break;
			case AX25_XID_PI_N1_TX:
				ax25_xid_number(pt, pi, tvb, off, pl, hf_ax25_xid_n1_tx, "octets", 8);
				break;
			case AX25_XID_PI_N1_RX:
				ax25_xid_number(pt, pi, tvb, off, pl, hf_ax25_xid_n1_rx, "octets", 8);
				break;
			case AX25_XID_PI_K_TX:
				ax25_xid_number(pt, pi, tvb, off, pl, hf_ax25_xid_k_tx, "frames", 1);
				break;
			case AX25_XID_PI_K_RX:
				ax25_xid_number(pt, pi, tvb, off, pl, hf_ax25_xid_k_rx, "frames", 1);
				break;
			case AX25_XID_PI_T1:
				ax25_xid_number(pt, pi, tvb, off, pl, hf_ax25_xid_t1, "ms", 1);
				break;
			case AX25_XID_PI_N2:
				/* Figure 4.5 doesn't list PI 10 */
				ax25_xid_number(pt, pi, tvb, off, pl, hf_ax25_xid_n2, "", 1);
				break;
			default:
				proto_tree_add_item(pt, hf_ax25_xid_pv, tvb, off, pl, ENC_NA);
				break;
			}
			off += pl;
		}
		offset = end;
	}
}

/*
 * Segment (PID 0x08, section 6.6): a one-octet header (first flag,
 * number of segments remaining) and a piece of the data unit. Linux
 * (ax25_output()) and Direwolf both send the original PID as the first
 * octet of the first segment, so it is decoded as such.
 *
 * TODO: reassemble the data unit and hand it to the ax25.pid dissector
 * of the original PID.
 */
static int
dissect_ax25_segment( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
	proto_item *si, *ti;
	proto_tree *st;
	const ax25_pkt_t *pkt;
	uint8_t hdr;
	bool first;
	int offset = 0;

	pkt = (const ax25_pkt_t *)p_get_proto_data( pinfo->pool, pinfo, proto_ax25, AX25_PROTO_DATA_SEG_PKT );

	hdr = tvb_get_uint8( tvb, 0 );
	first = ( hdr & AX25_SEG_FIRST ) != 0;
	si = proto_tree_add_item( tree, hf_ax25_seg, tvb, 0, first ? 2 : 1, ENC_NA );
	st = proto_item_add_subtree( si, ett_ax25_seg );
	proto_tree_add_boolean( st, hf_ax25_seg_first, tvb, 0, 1, hdr );
	proto_tree_add_uint( st, hf_ax25_seg_remaining, tvb, 0, 1, hdr );
	proto_item_append_text( si, ": %s%u remaining", first ? "first, " : "", hdr & AX25_SEG_REMAINING );
	col_append_fstr( pinfo->cinfo, COL_INFO, " (%s%u remaining)", first ? "first, " : "",
			hdr & AX25_SEG_REMAINING );
	offset = 1;
	if ( first )
		{
		proto_tree_add_item( st, hf_ax25_seg_pid, tvb, 1, 1, ENC_NA );
		offset = 2;
		}

	if ( pkt )
		{
		if ( pkt->seg_first_frame && pkt->seg_first_frame != pinfo->num )
			{
			ti = proto_tree_add_uint( st, hf_ax25_seg_first_frame, tvb, 0, 0, pkt->seg_first_frame );
			proto_item_set_generated( ti );
			}
		if ( pkt->seg_flags & AX25_SEGF_RETRANSMISSION )
			proto_item_append_text( si, " [retransmission]" );
		if ( pkt->seg_flags & AX25_SEGF_NOT_NEGOTIATED )
			proto_tree_add_expert_format( st, pinfo, &ei_ax25_seg_not_negotiated, tvb, 0, 1,
				"Segment, but the XID response in frame %u didn't enable the segmenter",
				pkt->seg_xid_frame );
		if ( pkt->seg_flags & AX25_SEGF_NEG_NOT_CAPTURED )
			proto_tree_add_expert( st, pinfo, &ei_ax25_seg_neg_not_captured, tvb, 0, 1 );
		if ( pkt->seg_flags & AX25_SEGF_MISSING_FIRST )
			proto_tree_add_expert( st, pinfo, &ei_ax25_seg_missing_first, tvb, 0, 1 );
		if ( pkt->seg_flags & AX25_SEGF_BAD_REMAINING )
			proto_tree_add_expert_format( st, pinfo, &ei_ax25_seg_remaining, tvb, 0, 1,
				"%u segments remaining, expected %u (the count goes down by one per segment)",
				hdr & AX25_SEG_REMAINING, pkt->seg_expected );
		if ( pkt->seg_flags & AX25_SEGF_ABANDONED )
			{
			if ( pkt->seg_first_frame )
				proto_tree_add_expert_format( st, pinfo, &ei_ax25_seg_remaining, tvb, 0, 1,
					"First segment while the sequence from frame %u still had segments to come"
					" (expected %u remaining)", pkt->seg_first_frame, pkt->seg_expected );
			else
				proto_tree_add_expert_format( st, pinfo, &ei_ax25_seg_remaining, tvb, 0, 1,
					"First segment while the previous sequence still had segments to come"
					" (expected %u remaining)", pkt->seg_expected );
			}
		if ( pkt->seg_flags & AX25_SEGF_INTERLEAVED )
			proto_tree_add_expert( st, pinfo, &ei_ax25_seg_interleaved, tvb, 0, 1 );
		if ( pkt->seg_flags & AX25_SEGF_TR210 )
			{
			ti = proto_tree_add_time( st, hf_ax25_seg_gap, tvb, 0, 0, &pkt->seg_gap );
			proto_item_set_generated( ti );
			expert_add_info_format( pinfo, ti, &ei_ax25_seg_tr210,
				"%.1f s since the previous segment, more than TR210 (%.1f s)",
				nstime_to_sec( &pkt->seg_gap ), pkt->seg_tr210_s );
			}
		/* The I field (header included) of each segment is limited by N1 */
		if ( tvb_reported_length( tvb ) > pkt->params.n1.value )
			proto_tree_add_expert_format( st, pinfo, &ei_ax25_seg_too_long, tvb, 0, 1,
				"Segment of %u octets is longer than the receiver's N1 of %u",
				tvb_reported_length( tvb ), pkt->params.n1.value );
		}

	call_data_dissector( tvb_new_subset_remaining( tvb, offset ), pinfo, tree );
	return tvb_captured_length( tvb );
}

/* Negotiated values (section 6.3.2) */
#define AX25_XIDN_HALF		0
#define AX25_XIDN_FULL		1

static const value_string ax25_xidn_duplex_vals[] = {
	{ AX25_XIDN_HALF,	"Half duplex" },
	{ AX25_XIDN_FULL,	"Full duplex" },
	{ 0, NULL }
};

static const value_string ax25_xidn_reject_vals[] = {
	{ AX25_REJ_NONE,	"None" },
	{ AX25_REJ_REJ,		"Implicit reject (REJ)" },
	{ AX25_REJ_SREJ,	"Selective reject (SREJ)" },
	{ 0, NULL }
};

/* What a PI 2 offers, in words */
static const char *
ax25_xidn_duplex_set(const ax25_xid_t *x)
{
	bool half = (x->cop & AX25_COP_HALF_DUPLEX) != 0;
	bool full = (x->cop & AX25_COP_FULL_DUPLEX) != 0;

	if (half && full)
		return "half or full duplex";
	if (full)
		return "full duplex";
	if (half)
		return "half duplex";
	return "neither half nor full duplex";
}

/* What a PI 3 offers for reject, in words */
static const char *
ax25_xidn_reject_set(wmem_allocator_t *scope, const ax25_xid_t *x)
{
	wmem_strbuf_t *b = wmem_strbuf_new(scope, "");

	if (x->hdlc & AX25_HDLC_REJ)
		wmem_strbuf_append(b, "REJ");
	if (x->hdlc & AX25_HDLC_SREJ)
		wmem_strbuf_append_printf(b, "%sSREJ", wmem_strbuf_get_len(b) ? ", " : "");
	if (x->hdlc & AX25_HDLC_SREJ_MULTI)
		wmem_strbuf_append_printf(b, "%sSREJ multiframe", wmem_strbuf_get_len(b) ? ", " : "");
	if (!wmem_strbuf_get_len(b))
		wmem_strbuf_append(b, "neither REJ nor SREJ");
	return wmem_strbuf_get_str(b);
}

/* What a PI 3 offers for the modulo, in words */
static const char *
ax25_xidn_modulo_set(const ax25_xid_t *x)
{
	bool m8 = (x->hdlc & AX25_HDLC_MOD8) != 0;
	bool m128 = (x->hdlc & AX25_HDLC_MOD128) != 0;

	if (m8 && m128)
		return "modulo 8 or 128";
	if (m128)
		return "modulo 128";
	if (m8)
		return "modulo 8";
	return "no modulo";
}

#define AX25_XIDN_BREACH	" [breaks section 6.3.2]"

/* A response should select one option; several means it took the lesser */
static void
ax25_xidn_several(proto_item *ti, bool several)
{
	if (several)
		proto_item_append_text(ti, " [the response selects several; taking the lesser]");
}

/* Does the XID carry the parameter (PL=0 or GL=0 count, as defaults)? */
static bool
ax25_xidn_has(const ax25_xid_t *x, unsigned flag)
{
	bool def;

	return ax25_xid_has(x, flag, &def);
}

static bool
ax25_xidn_default(const ax25_xid_t *x, unsigned flag)
{
	return (x->has & (flag << AX25_XID_DEF_SHIFT)) != 0;
}

/*
 * One negotiated parameter on a response. If the response leaves it out
 * but the command offered it, the current value is kept (section 4.3.3.7).
 */
static proto_item *
ax25_xidn_kept(proto_tree *tree, tvbuff_t *tvb, const char *what)
{
	proto_item *ti;

	ti = proto_tree_add_none_format(tree, hf_ax25_xidn_kept, tvb, 0, 0,
			"%s: not in the response, the current value is kept", what);
	proto_item_set_generated(ti);
	return ti;
}

/*
 * "XID negotiation" subtree on XID frames: what a command offers, or what
 * a response selects, how that compares with the command, and the values
 * that result (section 6.3.2). The raw fields are in "XID information".
 */
static void
ax25_add_xid_negotiation(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
		const ax25_pkt_t *pkt, const ax25_frame_t *f)
{
	const ax25_xid_neg_t *neg = pkt->xid_neg;
	const ax25_xid_t *x, *c;
	const ax25_params_t *to_sender;
	proto_tree *nt;
	proto_item *ni, *ti;
	const char *src;
	bool have_cmd;

	if (!neg)
		return;
	x = &neg->self;
	c = &neg->cmd;
	have_cmd = neg->cmd_frame != 0;
	src = address_to_str(pinfo->pool, &pinfo->src);
	/* N1 and k of the station that sent this XID: they limit frames sent to it */
	to_sender = &neg->params[!f->dir];

	nt = proto_tree_add_subtree(tree, tvb, 0, 0, ett_ax25_xidn, &ni,
			neg->response ? "XID negotiation: result" : "XID negotiation: offer");
	proto_item_set_generated(ni);

	if (neg->response) {
		if (have_cmd) {
			ti = proto_tree_add_uint(nt, hf_ax25_xidn_command_frame, tvb, 0, 0, neg->cmd_frame);
			proto_item_set_generated(ti);
		} else {
			proto_item_append_text(ni, " (the XID command wasn't captured)");
		}
		/* "The receipt of an XID response ... establishes that both
		 * stations are using AX.25 version 2.2 or higher" */
		ti = proto_tree_add_item(nt, hf_ax25_xidn_v22, tvb, 0, 0, ENC_NA);
		proto_item_set_generated(ti);
	}
	if (x->gl_zero)
		proto_item_append_text(ni, ", all parameters take their default values (GL=0)");

	/* Classes of Procedures: half or full duplex, the lesser of the two */
	if (ax25_xidn_has(x, AX25_XID_HAS_DUPLEX)) {
		ti = proto_tree_add_uint(nt, hf_ax25_xidn_duplex, tvb, 0, 0,
				x->full_duplex ? AX25_XIDN_FULL : AX25_XIDN_HALF);
		proto_item_set_generated(ti);
		if (ax25_xidn_default(x, AX25_XID_HAS_DUPLEX))
			proto_item_append_text(ti, " (default)");
		else if (!neg->response)
			proto_item_append_text(ti, " (offers %s)", ax25_xidn_duplex_set(x));
		else {
			ax25_xidn_several(ti, (x->cop & AX25_COP_HALF_DUPLEX) && (x->cop & AX25_COP_FULL_DUPLEX));
			if (have_cmd && ax25_xidn_has(c, AX25_XID_HAS_DUPLEX))
				proto_item_append_text(ti, " (command offered %s; the lesser of the two applies)%s",
						ax25_xidn_duplex_set(c),
						(c->has & AX25_XID_HAS_DUPLEX) && x->full_duplex && !c->full_duplex ?
						    AX25_XIDN_BREACH : "");
		}
	} else if (neg->response && have_cmd && ax25_xidn_has(c, AX25_XID_HAS_DUPLEX)) {
		ax25_xidn_kept(nt, tvb, "Duplex");
	}

	/* HDLC Optional Functions: reject, the lesser of the two */
	if (ax25_xidn_has(x, AX25_XID_HAS_REJ)) {
		ti = proto_tree_add_uint(nt, hf_ax25_xidn_reject, tvb, 0, 0,
				ax25_xidn_default(x, AX25_XID_HAS_REJ) ? AX25_REJ_SREJ : x->rej);
		proto_item_set_generated(ti);
		if (ax25_xidn_default(x, AX25_XID_HAS_REJ))
			proto_item_append_text(ti, " (default)");
		else if (!neg->response)
			proto_item_append_text(ti, " (offers %s)", ax25_xidn_reject_set(pinfo->pool, x));
		else {
			ax25_xidn_several(ti, (x->hdlc & AX25_HDLC_REJ) &&
					(x->hdlc & (AX25_HDLC_SREJ | AX25_HDLC_SREJ_MULTI)));
			if (have_cmd && ax25_xidn_has(c, AX25_XID_HAS_REJ))
				proto_item_append_text(ti, " (command offered %s; the lesser of the two applies)%s",
						ax25_xidn_reject_set(pinfo->pool, c),
						(c->has & AX25_XID_HAS_REJ) && x->rej > c->rej ? AX25_XIDN_BREACH : "");
		}
	} else if (neg->response && have_cmd && ax25_xidn_has(c, AX25_XID_HAS_REJ)) {
		ax25_xidn_kept(nt, tvb, "Reject");
	}

	/*
	 * Modulo, the lesser of the two. A default (PL=0, GL=0) is shown but
	 * doesn't change a running link (see ax25_handle_xid()).
	 */
	if (ax25_xidn_has(x, AX25_XID_HAS_MODULO)) {
		ti = proto_tree_add_uint(nt, hf_ax25_xidn_modulo, tvb, 0, 0,
				ax25_xidn_default(x, AX25_XID_HAS_MODULO) ? 128 : x->modulo);
		proto_item_set_generated(ti);
		if (ax25_xidn_default(x, AX25_XID_HAS_MODULO) && neg->connected)
			proto_item_append_text(ti, " (default; the running link keeps modulo %u)",
					neg->modulo_before);
		else if (ax25_xidn_default(x, AX25_XID_HAS_MODULO))
			proto_item_append_text(ti, " (default)");
		else if (!neg->response)
			proto_item_append_text(ti, " (offers %s)", ax25_xidn_modulo_set(x));
		else {
			ax25_xidn_several(ti, (x->hdlc & AX25_HDLC_MOD8) && (x->hdlc & AX25_HDLC_MOD128));
			if (have_cmd && ax25_xidn_has(c, AX25_XID_HAS_MODULO))
				proto_item_append_text(ti, " (command offered %s; the lesser of the two applies)%s",
						ax25_xidn_modulo_set(c),
						(c->has & AX25_XID_HAS_MODULO) && x->modulo > c->modulo ?
						    AX25_XIDN_BREACH : "");
		}
	} else if (neg->response && have_cmd && ax25_xidn_has(c, AX25_XID_HAS_MODULO)) {
		ti = ax25_xidn_kept(nt, tvb, "Modulo");
		if (neg->connected)
			proto_item_append_text(ti, " (%u)", neg->modulo_before);
	}

	/* Segmenter/reassembler (section 6.6) */
	if (ax25_xidn_has(x, AX25_XID_HAS_SEGMENTER)) {
		ti = proto_tree_add_boolean(nt, hf_ax25_xidn_segmenter, tvb, 0, 0,
				!ax25_xidn_default(x, AX25_XID_HAS_SEGMENTER) && x->segmenter);
		proto_item_set_generated(ti);
		if (ax25_xidn_default(x, AX25_XID_HAS_SEGMENTER))
			proto_item_append_text(ti, " (default)");
		else if (neg->response && have_cmd && ax25_xidn_has(c, AX25_XID_HAS_SEGMENTER))
			proto_item_append_text(ti, " (command %s)", c->segmenter ? "offered it" : "didn't offer it");
	} else if (neg->response && have_cmd && ax25_xidn_has(c, AX25_XID_HAS_SEGMENTER)) {
		ax25_xidn_kept(nt, tvb, "Segmenter");
	}

	/* T1 and N2: the greater of the two, for the whole link */
	if (ax25_xidn_has(x, AX25_XID_HAS_T1)) {
		ti = proto_tree_add_uint(nt, hf_ax25_xidn_t1, tvb, 0, 0,
				ax25_xidn_default(x, AX25_XID_HAS_T1) ? AX25_SPEC_T1_MS : x->t1_ms);
		proto_item_set_generated(ti);
		if (ax25_xidn_default(x, AX25_XID_HAS_T1))
			proto_item_append_text(ti, " (default)");
		else if (neg->response && have_cmd && ax25_xidn_has(c, AX25_XID_HAS_T1))
			proto_item_append_text(ti, " (command offered %u ms; the greater of the two applies)%s",
					ax25_xidn_default(c, AX25_XID_HAS_T1) ? AX25_SPEC_T1_MS : c->t1_ms,
					(c->has & AX25_XID_HAS_T1) && x->t1_ms < c->t1_ms ? AX25_XIDN_BREACH : "");
	} else if (neg->response && have_cmd && ax25_xidn_has(c, AX25_XID_HAS_T1)) {
		ti = ax25_xidn_kept(nt, tvb, "T1");
		proto_item_append_text(ti, " (%u ms, %s)", neg->params[f->dir].t1_ms.value,
				val_to_str_const(neg->params[f->dir].t1_ms.src, ax25_psrc_vals, "?"));
	}
	if (ax25_xidn_has(x, AX25_XID_HAS_N2)) {
		ti = proto_tree_add_uint(nt, hf_ax25_xidn_n2, tvb, 0, 0,
				ax25_xidn_default(x, AX25_XID_HAS_N2) ? AX25_SPEC_N2 : x->n2);
		proto_item_set_generated(ti);
		if (ax25_xidn_default(x, AX25_XID_HAS_N2))
			proto_item_append_text(ti, " (default)");
		else if (neg->response && have_cmd && ax25_xidn_has(c, AX25_XID_HAS_N2))
			proto_item_append_text(ti, " (command offered %u; the greater of the two applies)%s",
					ax25_xidn_default(c, AX25_XID_HAS_N2) ? AX25_SPEC_N2 : c->n2,
					(c->has & AX25_XID_HAS_N2) && x->n2 < c->n2 ? AX25_XIDN_BREACH : "");
	} else if (neg->response && have_cmd && ax25_xidn_has(c, AX25_XID_HAS_N2)) {
		ti = ax25_xidn_kept(nt, tvb, "N2");
		proto_item_append_text(ti, " (%u, %s)", neg->params[f->dir].n2.value,
				val_to_str_const(neg->params[f->dir].n2.src, ax25_psrc_vals, "?"));
	}

	/*
	 * N1 and k are notifications, not negotiated: the sender of this XID
	 * says what it can receive, in a command as well as in a response.
	 */
	if (ax25_xidn_has(x, AX25_XID_HAS_N1_RX)) {
		ti = proto_tree_add_uint(nt, hf_ax25_xidn_n1, tvb, 0, 0, to_sender->n1.value);
		proto_item_set_generated(ti);
		proto_item_append_text(ti, " (%snotified by %s: frames sent to it must not exceed this)",
				ax25_xidn_default(x, AX25_XID_HAS_N1_RX) ? "default, " : "", src);
	}
	if (ax25_xidn_has(x, AX25_XID_HAS_K_RX)) {
		ti = proto_tree_add_uint(nt, hf_ax25_xidn_k, tvb, 0, 0, to_sender->k.value);
		proto_item_set_generated(ti);
		proto_item_append_text(ti, " (%snotified by %s: no more frames outstanding towards it)",
				ax25_xidn_default(x, AX25_XID_HAS_K_RX) ? "default, " : "", src);
	}
}

static int
dissect_ax25( tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_ )
{
	proto_item *ti;
	proto_item *gi;
	proto_tree *ax25_tree;
	int offset;
	int ctl_offset;
	int via_index;
	char *info_buffer;
	const char *ax25_version;
	int control;
	uint8_t pid = AX25_P_NO_L3;
	uint8_t src_ssid;
	uint8_t dst_ssid;
	tvbuff_t *next_tvb = NULL;
	uint8_t *dst_masked, *src_masked;
	const uint8_t *addr_lo, *addr_hi;
	uint32_t port = AX25_NO_PORT;
	uint32_t iface = AX25_NO_INTERFACE;
	void *port_data;
	unsigned trailer = 0;
	conversation_element_t *link_key;
	ax25_frame_t frame;
	ax25_pkt_t *pkt;
	bool is_extended;


	info_buffer = (char *)wmem_alloc( pinfo->pool, STRLEN );
	info_buffer[0] = '\0';

	col_set_str( pinfo->cinfo, COL_PROTOCOL, "AX.25" );
	col_clear( pinfo->cinfo, COL_INFO );

	/* The KISS port, if we came through KISS. Consume it so it doesn't
	 * leak into an AX.25 frame tunnelled further down. */
	port_data = p_get_proto_data( pinfo->pool, pinfo, proto_ax25, AX25_PROTO_DATA_PORT );
	if ( port_data )
		{
		port = GPOINTER_TO_UINT( port_data ) - 1;
		p_remove_proto_data( pinfo->pool, pinfo, proto_ax25, AX25_PROTO_DATA_PORT );
		}
	/* Octets at the end that aren't AX.25 (a KISS checksum) */
	port_data = p_get_proto_data( pinfo->pool, pinfo, proto_ax25, AX25_PROTO_DATA_TRAILER );
	if ( port_data )
		{
		trailer = GPOINTER_TO_UINT( port_data );
		p_remove_proto_data( pinfo->pool, pinfo, proto_ax25, AX25_PROTO_DATA_TRAILER );
		}
	if ( pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID )
		iface = pinfo->rec->rec_header.packet_header.interface_id;

	memset( &frame, 0, sizeof frame );
	frame.tvb = tvb;

	/* start at the dst addr */
	offset = 0;
	/* create display subtree for the protocol */
	ti = proto_tree_add_protocol_format( parent_tree, proto_ax25, tvb, offset, -1, "AX.25");
	ax25_tree = proto_item_add_subtree( ti, ett_ax25 );

	proto_tree_add_item( ax25_tree, hf_ax25_dst, tvb, offset, AX25_ADDR_LEN, ENC_NA);
	set_address_tvb(&pinfo->dl_dst, AT_AX25, AX25_ADDR_LEN, tvb, offset);
	copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
	dst_ssid = tvb_get_uint8(tvb, offset+6);
	dst_masked = (uint8_t *)wmem_alloc( pinfo->pool, AX25_ADDR_LEN );
	ax25_mask_address( tvb, offset, dst_masked );

	/* step over dst addr point at src addr */
	offset += AX25_ADDR_LEN;

	proto_tree_add_item( ax25_tree, hf_ax25_src, tvb, offset, AX25_ADDR_LEN, ENC_NA);
	set_address_tvb(&pinfo->dl_src, AT_AX25, AX25_ADDR_LEN, tvb, offset);
	copy_address_shallow(&pinfo->src, &pinfo->dl_src);
	src_ssid = tvb_get_uint8(tvb, offset+6);
	src_masked = (uint8_t *)wmem_alloc( pinfo->pool, AX25_ADDR_LEN );
	ax25_mask_address( tvb, offset, src_masked );

	/* step over src addr point at either 1st via addr or control byte */
	offset += AX25_ADDR_LEN;

	proto_item_append_text( ti, ", Src: %s, Dst: %s",
		address_to_str(pinfo->pool, &pinfo->src),
		address_to_str(pinfo->pool, &pinfo->dst));

	/* handle the vias, if any */
	via_index = 0;
	while ( ( tvb_get_uint8( tvb, offset - 1 ) & 0x01 ) == 0 )
		{
		if ( via_index < AX25_MAX_DIGIS )
			{
			proto_tree_add_item( ax25_tree, hf_ax25_via[ via_index ], tvb, offset, AX25_ADDR_LEN, ENC_NA);
			/* H bits, for recognizing digipeated copies */
			frame.digi_ssid_offset[ via_index ] = offset + AX25_ADDR_LEN - 1;
			if ( tvb_get_uint8( tvb, offset + AX25_ADDR_LEN - 1 ) & AX25_SSID_CR )
				frame.hbits |= 1U << via_index;
			via_index++;
			}
		/* step over a via addr */
		offset += AX25_ADDR_LEN;
		}
	frame.ndigis = via_index;
	ctl_offset = offset;

	/* What the frame is, before decoding the control field */
	frame.ctl_offset = ctl_offset;
	frame.c0 = tvb_get_uint8( tvb, ctl_offset );
	frame.ftype = ax25_classify_control( frame.c0 );
	frame.ctl_remaining = tvb_reported_length_remaining( tvb, ctl_offset ) - (int)trailer;

	/* decode the cmd/resp field (section 6.1.2, Figure 6.1) */
	switch ( ( (dst_ssid >> 6) & 0x02) | ( (src_ssid >> 7) & 0x01 ) )
		{
		case 1 : /* V2.0 Response */
			frame.version = AX25_VERSION_2X;
			frame.cr = AX25_CR_RESPONSE;
			ax25_version = "V2.0+";
			break;
		case 2 : /* V2.0 Command */
			frame.version = AX25_VERSION_2X;
			frame.cr = AX25_CR_COMMAND;
			ax25_version = "V2.0+";
			break;
		default : /* 00 or 11: a station older than 2.0 */
			frame.version = AX25_VERSION_PRE20;
			frame.cr = ax25_pre20_cr( frame.ftype );
			ax25_version = "pre-2.0";
			break;
		}
	proto_item_append_text( ti, ", Ver: %s", ax25_version );

	/* Link tracking. */
	if ( memcmp( src_masked, dst_masked, AX25_ADDR_LEN ) <= 0 )
		{
		addr_lo = src_masked;
		addr_hi = dst_masked;
		frame.dir = AX25_DIR_LO_HI;
		}
	else
		{
		addr_lo = dst_masked;
		addr_hi = src_masked;
		frame.dir = AX25_DIR_HI_LO;
		}
	link_key = ax25_link_key( pinfo, addr_lo, addr_hi, port, iface );

	if ( !PINFO_FD_VISITED( pinfo ) )
		{
		pkt = ax25_first_pass( pinfo, link_key, &frame );
		p_add_proto_data( wmem_file_scope(), pinfo, proto_ax25, pinfo->curr_layer_num, pkt );
		}
	else
		pkt = (ax25_pkt_t *)p_get_proto_data( wmem_file_scope(), pinfo, proto_ax25, pinfo->curr_layer_num );

	/* Let L3 dissectors find this link with find_conversation_pinfo() */
	pinfo->conv_elements = link_key;

	gi = proto_tree_add_uint( ax25_tree, hf_ax25_version, tvb, 0, 0, frame.version );
	proto_item_set_generated( gi );
	gi = proto_tree_add_uint( ax25_tree, hf_ax25_cr, tvb, 0, 0, frame.cr );
	proto_item_set_generated( gi );
	if ( pkt )
		{
		ax25_add_decode_items( ax25_tree, tvb, pinfo, pkt, &frame );
		if ( pkt->cr_mixed_frame )
			proto_tree_add_expert_format( ax25_tree, pinfo, &ei_ax25_cr_mixed, tvb, 0, 0,
				"C/R encoding is %s here but was %s in frame %u, in the same direction",
				frame.version == AX25_VERSION_PRE20 ? "pre-2.0" : "2.x",
				frame.version == AX25_VERSION_PRE20 ? "2.x" : "pre-2.0",
				pkt->cr_mixed_frame );
		if ( pkt->pre20_frame && ( frame.ftype == AX25_FT_SABME || frame.ftype == AX25_FT_XID ) )
			proto_tree_add_expert_format( ax25_tree, pinfo, &ei_ax25_pre20_v22_feature, tvb, ctl_offset, 1,
				"%s on a link where frame %u used pre-2.0 C/R encoding",
				frame.ftype == AX25_FT_SABME ? "SABME" : "XID", pkt->pre20_frame );
		ax25_add_link_items( ax25_tree, tvb, pinfo, pkt, &frame );
		}
	is_extended = pkt && pkt->modulo == 128 && ax25_ftype_is_numbered( frame.ftype );

	if ( frame.cr == AX25_CR_UNKNOWN )
		control = ax25_dissect_control_unknown_cr( tvb, ctl_offset, pinfo, ax25_tree, is_extended );
	else
		control = dissect_xdlc_control(	tvb,
						ctl_offset,
						pinfo,
						ax25_tree,
						is_extended ? hf_ax25_ctl_ext : hf_ax25_ctl,
						ett_ax25_ctl,
						&ax25_cf_items,
						&ax25_cf_items_ext,
						NULL,
						NULL,
						frame.cr == AX25_CR_RESPONSE,
						is_extended,
						false );
	offset = ctl_offset + XDLC_CONTROL_LEN(control, is_extended); /* step over control field */

	if ( is_extended && ax25_ftype_is_s( frame.ftype ) && ( frame.c0 & AX25_S128_ZERO_BITS ) )
		proto_tree_add_expert( ax25_tree, pinfo, &ei_ax25_s128_bits, tvb, ctl_offset, 1 );

	if ( frame.ftype == AX25_FT_XID )
		{
		ax25_dissect_xid( tvb, offset, pinfo, ax25_tree );
		if ( pkt )
			ax25_add_xid_negotiation( ax25_tree, tvb, pinfo, pkt, &frame );
		}

	/* I and UI frames carry a PID; UI may have P/F set (Figure 4.4) */
	if ( frame.ftype == AX25_FT_I || frame.ftype == AX25_FT_UI )
		{

		pid      = tvb_get_uint8( tvb, offset );
		col_append_fstr( pinfo->cinfo, COL_INFO, ", %s", val_to_str(pinfo->pool, pid, pid_vals, "Unknown (0x%02x)") );
		gi = proto_tree_add_uint( ax25_tree, hf_ax25_pid, tvb, offset, 1, pid );
		if ( pkt && pkt->pre20_frame && pid == AX25_P_SEGMENT )
			expert_add_info_format( pinfo, gi, &ei_ax25_pre20_v22_feature,
				"Segment on a link where frame %u used pre-2.0 C/R encoding", pkt->pre20_frame );

		/* Call sub-dissectors here */

		offset += 1; /* step over pid to the 1st byte of the payload */

		/* The PID isn't part of the I field (section 3.4) */
		if ( pkt && frame.ftype == AX25_FT_I && pid != AX25_P_SEGMENT &&
		     (unsigned)tvb_reported_length_remaining( tvb, offset ) > pkt->params.n1.value )
			proto_tree_add_expert_format( ax25_tree, pinfo, &ei_ax25_n1_exceeded, tvb, offset,
				tvb_captured_length_remaining( tvb, offset ),
				"I field of %u octets is longer than the receiver's N1 of %u (%s)",
				tvb_reported_length_remaining( tvb, offset ), pkt->params.n1.value,
				pkt->params.n1.src == AX25_PSRC_XID ?
				    wmem_strdup_printf( pinfo->pool, "XID, frame %u", pkt->params.n1.frame ) :
				    val_to_str_const( pkt->params.n1.src, ax25_psrc_vals, "?" ) );

		proto_item_set_end(ti, tvb, offset);

		next_tvb = tvb_new_subset_remaining(tvb, offset);

		/* The data pointer is the whole control field: one octet, or two
		 * (low octet first, as on the wire) for modulo 128 I frames. */
		if ( pkt )
			p_add_proto_data( pinfo->pool, pinfo, proto_ax25, AX25_PROTO_DATA_SEG_PKT, pkt );
		if (!dissector_try_uint_with_data(ax25_dissector_table, pid, next_tvb, pinfo, parent_tree, true, GINT_TO_POINTER(control)))
			{
			call_data_dissector(next_tvb, pinfo, parent_tree);
			}
		p_remove_proto_data( pinfo->pool, pinfo, proto_ax25, AX25_PROTO_DATA_SEG_PKT );
		}
	else
		proto_item_set_end(ti, tvb, offset);

	return tvb_captured_length(tvb);
}

/*
 * Capture dissectors are stateless, so this can't know the modulo of the
 * link.
 * XXX - in modulo 128 the control field of I frames is two octets, so the
 * PID offset computed here is one octet short and the PID read is the
 * second control octet. UI frames (one control octet in both modes) are
 * right.
 */
static bool
capture_ax25( const unsigned char *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
	uint8_t control;
	uint8_t pid;
	int l_offset;

	if ( ! BYTES_ARE_IN_FRAME( offset, len, AX25_HEADER_SIZE ) )
		return false;

	l_offset = offset;
	l_offset += AX25_ADDR_LEN; /* step over dst addr point at src addr */
	l_offset += AX25_ADDR_LEN; /* step over src addr point at either 1st via addr or control byte */
	while ( ( pd[ l_offset - 1 ] & 0x01 ) == 0 )
	{
		/* the via addr and the control byte after it must be in the frame */
		if ( ! BYTES_ARE_IN_FRAME( l_offset, len, AX25_ADDR_LEN + 1 ) )
			return false;
		l_offset += AX25_ADDR_LEN; /* step over a via addr */
	}

	control = pd[ l_offset ];

	/* decode the pid field (if appropriate) */
	if ( XDLC_IS_INFORMATION( control ) )
	{
		if ( ! BYTES_ARE_IN_FRAME( l_offset, len, 2 ) )
			return false;
		l_offset += 1; /* step over control byte point at pid */
		pid = pd[ l_offset ];

		l_offset += 1; /* step over the pid and point to the first byte of the payload */
		return try_capture_dissector("ax25.pid", pid & 0x0ff, pd, l_offset, len, cpinfo, pseudo_header);
	}
	return false;
}

/* Station table */
UAT_CSTRING_CB_DEF(ax25_stations, callsign, ax25_station_uat_t)
UAT_DEC_CB_DEF(ax25_stations, t1_ms, ax25_station_uat_t)
UAT_DEC_CB_DEF(ax25_stations, t3_s, ax25_station_uat_t)
UAT_DEC_CB_DEF(ax25_stations, n2, ax25_station_uat_t)
UAT_DEC_CB_DEF(ax25_stations, n1, ax25_station_uat_t)
UAT_DEC_CB_DEF(ax25_stations, k, ax25_station_uat_t)
UAT_VS_DEF(ax25_stations, version, ax25_station_uat_t, unsigned, AX25_UAT_VERSION_NONE, "Unknown")

/*
 * "CALL" or "CALL-SSID" to the address octets ax25_mask_address() makes:
 * up to six letters or digits shifted left one bit, padded with spaces,
 * then the SSID (0 if not given) in bits 1-4.
 */
static bool
ax25_callsign_to_masked(const char *str, uint8_t *masked, char **err)
{
	const char *p;
	unsigned i = 0;
	unsigned ssid = 0;
	char c;

	if (!str || !*str) {
		*err = g_strdup("A callsign is required");
		return false;
	}
	for (p = str; *p && *p != '-'; p++) {
		c = g_ascii_toupper(*p);
		if (i == AX25_ADDR_LEN - 1 || !(g_ascii_isupper(c) || g_ascii_isdigit(c))) {
			*err = ws_strdup_printf("\"%s\" isn't a callsign: up to six letters or digits", str);
			return false;
		}
		masked[i++] = (uint8_t)(c << 1);
	}
	if (i == 0) {
		*err = ws_strdup_printf("\"%s\" has no callsign before the SSID", str);
		return false;
	}
	for (; i < AX25_ADDR_LEN - 1; i++)
		masked[i] = ' ' << 1;
	if (*p == '-') {
		if (!ws_strtou32(p + 1, NULL, &ssid) || ssid > 15) {
			*err = ws_strdup_printf("\"%s\": the SSID must be 0 to 15", str);
			return false;
		}
	}
	masked[AX25_ADDR_LEN - 1] = (uint8_t)((ssid << 1) & AX25_SSID_SSID);
	return true;
}

static void *
ax25_stations_copy_cb(void *dest, const void *src, size_t len _U_)
{
	const ax25_station_uat_t *o = (const ax25_station_uat_t *)src;
	ax25_station_uat_t *d = (ax25_station_uat_t *)dest;

	*d = *o;
	d->callsign = g_strdup(o->callsign);
	return d;
}

static bool
ax25_stations_update_cb(void *r, char **err)
{
	ax25_station_uat_t *rec = (ax25_station_uat_t *)r;

	return ax25_callsign_to_masked(rec->callsign, rec->masked, err);
}

static void
ax25_stations_free_cb(void *r)
{
	ax25_station_uat_t *rec = (ax25_station_uat_t *)r;

	g_free(rec->callsign);
}

static void
ax25_init(void)
{
	ax25_stream_count = 0;
}

void
proto_register_ax25(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_ax25_dst,
			{ "Destination",		"ax25.dst",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Destination callsign", HFILL }
		},
		{ &hf_ax25_src,
			{ "Source",			"ax25.src",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Source callsign", HFILL }
		},
		{ &hf_ax25_via[ 0 ],
			{ "Via 1",			"ax25.via1",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 1", HFILL }
		},
		{ &hf_ax25_via[ 1 ],
			{ "Via 2",			"ax25.via2",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 2", HFILL }
		},
		{ &hf_ax25_via[ 2 ],
			{ "Via 3",			"ax25.via3",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 3", HFILL }
		},
		{ &hf_ax25_via[ 3 ],
			{ "Via 4",			"ax25.via4",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 4", HFILL }
		},
		{ &hf_ax25_via[ 4 ],
			{ "Via 5",			"ax25.via5",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 5", HFILL }
		},
		{ &hf_ax25_via[ 5 ],
			{ "Via 6",			"ax25.via6",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 6", HFILL }
		},
		{ &hf_ax25_via[ 6 ],
			{ "Via 7",			"ax25.via7",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 7", HFILL }
		},
		{ &hf_ax25_via[ 7 ],
			{ "Via 8",			"ax25.via8",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 8", HFILL }
		},
		{ &hf_ax25_ctl,
			{ "Control",			"ax25.ctl",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Control field", HFILL }
		},
		{ &hf_ax25_ctl_ext,
			{ "Control",			"ax25.ctl_ext",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Control field", HFILL }
		},
		{ &hf_ax25_n_r,
			{ "n(r)",			"ax25.ctl.n_r",
			FT_UINT8, BASE_DEC, NULL, XDLC_N_R_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_n_r_ext,
			{ "n(r) ext",			"ax25.ctl.n_r_ext",
			FT_UINT16, BASE_DEC, NULL, XDLC_N_R_EXT_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_n_s,
			{ "n(s)",			"ax25.ctl.n_s",
			FT_UINT8, BASE_DEC, NULL, XDLC_N_S_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_n_s_ext,
			{ "n(s) ext",			"ax25.ctl.n_s_ext",
			FT_UINT16, BASE_DEC, NULL, XDLC_N_S_EXT_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_p,
			{ "Poll",			"ax25.ctl.p",
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), XDLC_P_F,
			NULL, HFILL }
		},
		{ &hf_ax25_f_ext,
			{ "Final",			"ax25.ctl.f_ext",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), XDLC_P_F_EXT,
			NULL, HFILL }
		},
		{ &hf_ax25_p_ext,
			{ "Poll",			"ax25.ctl.p_ext",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), XDLC_P_F_EXT,
			NULL, HFILL }
		},
		{ &hf_ax25_f,
			{ "Final",			"ax25.ctl.f",
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), XDLC_P_F,
			NULL, HFILL }
		},
		{ &hf_ax25_pf,
			{ "Poll/Final",			"ax25.ctl.pf",
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), XDLC_P_F,
			"P/F bit of a frame whose C/R is unknown (pre-2.0 encoding)", HFILL }
		},
		{ &hf_ax25_pf_ext,
			{ "Poll/Final",			"ax25.ctl.pf_ext",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), XDLC_P_F_EXT,
			"P/F bit of a frame whose C/R is unknown (pre-2.0 encoding)", HFILL }
		},
		{ &hf_ax25_ftype_s,
			{ "Frame type",			"ax25.ctl.ftype_s",
			FT_UINT8, BASE_HEX, VALS(stype_vals), XDLC_S_FTYPE_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_ftype_s_ext,
			{ "Frame type",			"ax25.ctl.ftype_s_ext",
			FT_UINT16, BASE_HEX, VALS(stype_vals), XDLC_S_FTYPE_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_ftype_i,
			{ "Frame type",			"ax25.ctl.ftype_i",
			FT_UINT8, BASE_HEX, VALS(ftype_vals), XDLC_I_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_ftype_i_ext,
			{ "Frame type",			"ax25.ctl.ftype_i_ext",
			FT_UINT16, BASE_HEX, VALS(ftype_vals), XDLC_I_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_ftype_su,
			{ "Frame type",			"ax25.ctl.ftype_su",
			FT_UINT8, BASE_HEX, VALS(ftype_vals), XDLC_S_U_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_ftype_su_ext,
			{ "Frame type",			"ax25.ctl.ftype_su_ext",
			FT_UINT16, BASE_HEX, VALS(ftype_vals), XDLC_S_U_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_u_cmd,
			{ "Frame type",			"ax25.ctl.u_cmd",
			FT_UINT8, BASE_HEX, VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_u_resp,
			{ "Frame type",			"ax25.ctl.u_resp",
			FT_UINT8, BASE_HEX, VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_pid,
			{ "Protocol ID",		"ax25.pid",
			FT_UINT8, BASE_HEX, VALS(pid_vals), 0x0,
			"Protocol identifier", HFILL }
		},
		{ &hf_ax25_stream,
			{ "Stream index",		"ax25.stream",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Index of the AX.25 connection; a new stream starts at each connection attempt. UI frames have none", HFILL }
		},
		{ &hf_ax25_version,
			{ "Version",			"ax25.version",
			FT_UINT8, BASE_DEC, VALS(ax25_version_vals), 0x0,
			"Protocol version implied by the C/R bits (section 6.1.2)", HFILL }
		},
		{ &hf_ax25_cr,
			{ "Command/Response",		"ax25.cr",
			FT_UINT8, BASE_DEC, VALS(ax25_cr_vals), 0x0,
			"From the C/R bits, or from the frame type for pre-2.0 frames", HFILL }
		},
		{ &hf_ax25_modulo,
			{ "Modulo",			"ax25.modulo",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Sequence number modulo the control field was decoded with", HFILL }
		},
		{ &hf_ax25_modulo_source,
			{ "Modulo source",		"ax25.modulo.source",
			FT_UINT8, BASE_DEC, VALS(ax25_modsrc_vals), 0x0,
			"How the modulo in effect was determined", HFILL }
		},
		{ &hf_ax25_modulo_frame,
			{ "Modulo set in frame",	"ax25.modulo.frame",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"The frame the modulo in effect was determined from", HFILL }
		},
		{ &hf_ax25_link_state,
			{ "Link state",			"ax25.link.state",
			FT_UINT8, BASE_DEC, VALS(ax25_link_state_vals), 0x0,
			"State of the link after this frame", HFILL }
		},
		{ &hf_ax25_link_state_frame,
			{ "Link state set in frame",	"ax25.link.state_frame",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"The frame that caused the link state this frame is out of place in", HFILL }
		},
		{ &hf_ax25_link_refused,
			{ "Refused SABM(E) in frame",	"ax25.link.refused",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
			"The connection request this DM or FRMR refuses", HFILL }
		},
		{ &hf_ax25_link_fallback,
			{ "SABME rejected in frame",	"ax25.link.fallback",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"This SABM falls back to v2.0 after that frame rejected a SABME", HFILL }
		},
		{ &hf_ax25_link_frmr_xid,
			{ "Rejected XID in frame",	"ax25.link.frmr_xid",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
			"The XID command this FRMR answers", HFILL }
		},
		{ &hf_ax25_link_idle,
			{ "Idle time",			"ax25.link.idle",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
			"Silence on the link before this frame", HFILL }
		},
		{ &hf_ax25_dup_of,
			{ "Digipeated copy of frame",	"ax25.link.dup_of",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_DUP_ACK), 0x0,
			"This frame is a digipeated copy of that frame (only the H bits differ)", HFILL }
		},
		{ &hf_ax25_param_version,
			{ "Version in effect",		"ax25.param.version",
			FT_UINT8, BASE_DEC, VALS(ax25_veff_vals), 0x0,
			"AX.25 version whose defaults apply to this link (section 6.3.2)", HFILL }
		},
		{ &hf_ax25_param_version_source,
			{ "Version source",		"ax25.param.version.source",
			FT_UINT8, BASE_DEC, VALS(ax25_vsrc_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_param_version_frame,
			{ "Version seen in frame",	"ax25.param.version.frame",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"The latest frame that showed the version", HFILL }
		},
		{ &hf_ax25_param_t1,
			{ "T1",				"ax25.param.t1",
			FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
			"Acknowledgement timer of the sender", HFILL }
		},
		{ &hf_ax25_param_t1_source,
			{ "T1 source",			"ax25.param.t1.source",
			FT_UINT8, BASE_DEC, VALS(ax25_psrc_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_param_t3,
			{ "T3",				"ax25.param.t3",
			FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_seconds), 0x0,
			"Inactive link timer of the sender (0: idle timeout off)", HFILL }
		},
		{ &hf_ax25_param_t3_source,
			{ "T3 source",			"ax25.param.t3.source",
			FT_UINT8, BASE_DEC, VALS(ax25_psrc_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_param_n2,
			{ "N2",				"ax25.param.n2",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Maximum number of retries of the sender", HFILL }
		},
		{ &hf_ax25_param_n2_source,
			{ "N2 source",			"ax25.param.n2.source",
			FT_UINT8, BASE_DEC, VALS(ax25_psrc_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_param_n1,
			{ "N1",				"ax25.param.n1",
			FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_octet_octets), 0x0,
			"Longest I field the receiver accepts", HFILL }
		},
		{ &hf_ax25_param_n1_source,
			{ "N1 source",			"ax25.param.n1.source",
			FT_UINT8, BASE_DEC, VALS(ax25_psrc_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_param_k,
			{ "k",				"ax25.param.k",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Largest window the receiver accepts", HFILL }
		},
		{ &hf_ax25_param_k_source,
			{ "k source",			"ax25.param.k.source",
			FT_UINT8, BASE_DEC, VALS(ax25_psrc_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_param_xid_frame,
			{ "Set by XID in frame",	"ax25.param.xid_frame",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xidn_command_frame,
			{ "Answers the XID command in frame",	"ax25.xid.neg.command_frame",
			FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xidn_duplex,
			{ "Duplex",			"ax25.xid.neg.duplex",
			FT_UINT8, BASE_DEC, VALS(ax25_xidn_duplex_vals), 0x0,
			"Offered (command) or selected (response) by Classes of Procedures", HFILL }
		},
		{ &hf_ax25_xidn_reject,
			{ "Reject",			"ax25.xid.neg.reject",
			FT_UINT8, BASE_DEC, VALS(ax25_xidn_reject_vals), 0x0,
			"Highest offered (command) or selected (response) by HDLC Optional Functions", HFILL }
		},
		{ &hf_ax25_xidn_modulo,
			{ "Modulo",			"ax25.xid.neg.modulo",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Highest offered (command) or selected (response) by HDLC Optional Functions", HFILL }
		},
		{ &hf_ax25_xidn_segmenter,
			{ "Segmenter/reassembler",	"ax25.xid.neg.segmenter",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x0,
			"Offered (command) or selected (response) by HDLC Optional Functions", HFILL }
		},
		{ &hf_ax25_xidn_t1,
			{ "T1",				"ax25.xid.neg.t1",
			FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
			"Acknowledge timer offered (command) or selected (response)", HFILL }
		},
		{ &hf_ax25_xidn_n2,
			{ "N2",				"ax25.xid.neg.n2",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Retries offered (command) or selected (response)", HFILL }
		},
		{ &hf_ax25_xidn_n1,
			{ "N1",				"ax25.xid.neg.n1",
			FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_octet_octets), 0x0,
			"Longest I field the sender of this XID accepts (notification)", HFILL }
		},
		{ &hf_ax25_xidn_k,
			{ "k",				"ax25.xid.neg.k",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Largest window the sender of this XID accepts (notification)", HFILL }
		},
		{ &hf_ax25_xidn_kept,
			{ "Kept",			"ax25.xid.neg.kept",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"The command offered a parameter the response leaves out: its current value is kept", HFILL }
		},
		{ &hf_ax25_xidn_v22,
			{ "Both stations use AX.25 v2.2 or later",	"ax25.xid.neg.v22",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"An XID response establishes v2.2, with segmenter and selective reject (section 6.3.2)", HFILL }
		},
		{ &hf_ax25_seg,
			{ "Segment header",		"ax25.seg",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"Segmenter/reassembler header (section 6.6)", HFILL }
		},
		{ &hf_ax25_seg_first,
			{ "First segment",		"ax25.seg.first",
			FT_BOOLEAN, 8, TFS(&tfs_yes_no), AX25_SEG_FIRST,
			NULL, HFILL }
		},
		{ &hf_ax25_seg_remaining,
			{ "Segments remaining",		"ax25.seg.remaining",
			FT_UINT8, BASE_DEC, NULL, AX25_SEG_REMAINING,
			NULL, HFILL }
		},
		{ &hf_ax25_seg_pid,
			{ "Protocol ID",		"ax25.seg.pid",
			FT_UINT8, BASE_HEX, VALS(pid_vals), 0x0,
			"PID of the segmented data unit, in the first segment", HFILL }
		},
		{ &hf_ax25_seg_first_frame,
			{ "First segment in frame",	"ax25.seg.first_frame",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
			"First segment of the sequence", HFILL }
		},
		{ &hf_ax25_seg_gap,
			{ "Time since previous segment",	"ax25.seg.gap",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xid,
			{ "XID information",		"ax25.xid",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"ISO 8885 general purpose XID information field (section 4.3.3.7)", HFILL }
		},
		{ &hf_ax25_xid_fi,
			{ "Format identifier",		"ax25.xid.fi",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_gi,
			{ "Group identifier",		"ax25.xid.gi",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_gl,
			{ "Group length",		"ax25.xid.gl",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_pi,
			{ "Parameter identifier",	"ax25.xid.pi",
			FT_UINT8, BASE_DEC, VALS(ax25_xid_pi_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_pl,
			{ "Parameter length",		"ax25.xid.pl",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_pv,
			{ "Parameter value",		"ax25.xid.pv",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_trailing,
			{ "Trailing octets",		"ax25.xid.trailing",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_cop,
			{ "Classes of Procedures",	"ax25.xid.cop",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Bit field, least significant octet first", HFILL }
		},
		{ &hf_ax25_xid_hdlc,
			{ "HDLC Optional Functions",	"ax25.xid.hdlc",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			"Bit field, least significant octet first", HFILL }
		},
		{ &hf_ax25_xid_n1_tx,
			{ "I field length Tx",		"ax25.xid.n1_tx",
			FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_bit_bits), 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_n1_rx,
			{ "I field length Rx",		"ax25.xid.n1_rx",
			FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_bit_bits), 0x0,
			"Longest I field the sender of this XID accepts (N1 x 8)", HFILL }
		},
		{ &hf_ax25_xid_k_tx,
			{ "Window size Tx",		"ax25.xid.k_tx",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_k_rx,
			{ "Window size Rx",		"ax25.xid.k_rx",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Largest window the sender of this XID accepts", HFILL }
		},
		{ &hf_ax25_xid_t1,
			{ "Acknowledge timer",		"ax25.xid.t1",
			FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_milliseconds), 0x0,
			"T1", HFILL }
		},
		{ &hf_ax25_xid_n2,
			{ "Retries",			"ax25.xid.n2",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"N2 (the spec calls it N1 in sections 4.3.3.7 and 6.3.2)", HFILL }
		},
		{ &hf_ax25_xid_cop_abm,
			{ "Balanced ABM",			"ax25.xid.cop.abm",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), AX25_COP_ABM,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_cop_nrm_pri,
			{ "Unbalanced NRM primary",	"ax25.xid.cop.nrm_pri",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), AX25_COP_NRM_PRI,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_cop_nrm_sec,
			{ "Unbalanced NRM secondary",	"ax25.xid.cop.nrm_sec",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), AX25_COP_NRM_SEC,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_cop_arm_pri,
			{ "Unbalanced ARM primary",	"ax25.xid.cop.arm_pri",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), AX25_COP_ARM_PRI,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_cop_arm_sec,
			{ "Unbalanced ARM secondary",	"ax25.xid.cop.arm_sec",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), AX25_COP_ARM_SEC,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_cop_half,
			{ "Half duplex",			"ax25.xid.cop.half",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), AX25_COP_HALF_DUPLEX,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_cop_full,
			{ "Full duplex",			"ax25.xid.cop.full",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), AX25_COP_FULL_DUPLEX,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_cop_reserved,
			{ "Reserved",			"ax25.xid.cop.reserved",
			FT_BOOLEAN, 16, TFS(&tfs_set_notset), AX25_COP_RESERVED,
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_reserved0,
			{ "Reserved (bit 0)",		"ax25.xid.hdlc.reserved0",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(0),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_rej,
			{ "REJ command/response",		"ax25.xid.hdlc.rej",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(1),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_srej,
			{ "SREJ command/response",	"ax25.xid.hdlc.srej",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(2),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_ui,
			{ "UI command/response",		"ax25.xid.hdlc.ui",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(3),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_sim_rim,
			{ "SIM command/RIM response",	"ax25.xid.hdlc.sim_rim",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(4),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_up,
			{ "UP command",			"ax25.xid.hdlc.up",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(5),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_basic_addr,
			{ "Basic address",		"ax25.xid.hdlc.basic_addr",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(6),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_ext_addr,
			{ "Extended address",		"ax25.xid.hdlc.ext_addr",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(7),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_del_i_resp,
			{ "Delete I response",		"ax25.xid.hdlc.del_i_resp",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(8),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_del_i_cmd,
			{ "Delete I command",		"ax25.xid.hdlc.del_i_cmd",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(9),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_mod8,
			{ "Modulo 8",			"ax25.xid.hdlc.mod8",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(10),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_mod128,
			{ "Modulo 128",			"ax25.xid.hdlc.mod128",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(11),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_rset,
			{ "RSET command",			"ax25.xid.hdlc.rset",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(12),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_test,
			{ "TEST command/response",	"ax25.xid.hdlc.test",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(13),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_rd,
			{ "RD response",			"ax25.xid.hdlc.rd",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(14),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_fcs16,
			{ "16-bit FCS",			"ax25.xid.hdlc.fcs16",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(15),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_fcs32,
			{ "32-bit FCS",			"ax25.xid.hdlc.fcs32",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(16),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_sync_tx,
			{ "Synchronous transmit",		"ax25.xid.hdlc.sync_tx",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(17),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_ss_tx,
			{ "Start/stop transmission",	"ax25.xid.hdlc.ss_tx",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(18),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_ss_flow,
			{ "Start/stop basic flow control",	"ax25.xid.hdlc.ss_flow",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(19),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_ss_octet,
			{ "Start/stop octet transparency",	"ax25.xid.hdlc.ss_octet",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(20),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_srej_multi,
			{ "SREJ multiframe",		"ax25.xid.hdlc.srej_multi",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(21),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_segmenter,
			{ "Segmenter/reassembler",	"ax25.xid.hdlc.segmenter",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(22),
			NULL, HFILL }
		},
		{ &hf_ax25_xid_hdlc_reserved23,
			{ "Reserved (bit 23)",		"ax25.xid.hdlc.reserved23",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset), AX25_HDLC_BIT(23),
			NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_ax25,
		&ett_ax25_ctl,
		&ett_ax25_link,
		&ett_ax25_params,
		&ett_ax25_xid,
		&ett_ax25_xid_param,
		&ett_ax25_xid_bits,
		&ett_ax25_seg,
		&ett_ax25_xidn,
	};

	static ei_register_info ei[] = {
		{ &ei_ax25_modulo_assumed,
			{ "ax25.modulo.assumed", PI_ASSUMPTION, PI_NOTE,
			"Modulo not known yet (no SABM(E)/UA or decisive S frame seen); assuming 8", EXPFILL }
		},
		{ &ei_ax25_modulo_inferred,
			{ "ax25.modulo.inferred", PI_ASSUMPTION, PI_CHAT,
			"Modulo inferred from an S frame", EXPFILL }
		},
		{ &ei_ax25_modulo_no_ua,
			{ "ax25.modulo.no_ua", PI_ASSUMPTION, PI_NOTE,
			"Modulo taken from a SABM(E) whose UA was not captured", EXPFILL }
		},
		{ &ei_ax25_s128_bits,
			{ "ax25.ctl.s128_bits", PI_PROTOCOL, PI_WARN,
			"Bits 4-7 of a modulo 128 S frame must be zero (Figure 4.1b)", EXPFILL }
		},
		{ &ei_ax25_pre20_v22_feature,
			{ "ax25.pre20.v22_feature", PI_PROTOCOL, PI_WARN,
			"Version 2.2 feature on a link with a pre-2.0 station", EXPFILL }
		},
		{ &ei_ax25_cr_mixed,
			{ "ax25.cr.mixed", PI_PROTOCOL, PI_WARN,
			"Pre-2.0 and 2.x C/R encoding mixed in one direction", EXPFILL }
		},
		{ &ei_ax25_after_disc,
			{ "ax25.link.after_disc", PI_SEQUENCE, PI_WARN,
			"Frame after the link was disconnected by DISC/UA", EXPFILL }
		},
		{ &ei_ax25_after_dm,
			{ "ax25.link.after_dm", PI_SEQUENCE, PI_WARN,
			"Frame after DM", EXPFILL }
		},
		{ &ei_ax25_after_frmr,
			{ "ax25.link.after_frmr", PI_SEQUENCE, PI_WARN,
			"Frame after FRMR", EXPFILL }
		},
		{ &ei_ax25_disconnecting,
			{ "ax25.link.disconnecting", PI_SEQUENCE, PI_NOTE,
			"Frame while disconnecting", EXPFILL }
		},
		{ &ei_ax25_after_idle,
			{ "ax25.link.after_idle", PI_SEQUENCE, PI_NOTE,
			"Frame after the link was presumed down (idle timeout)", EXPFILL }
		},
		{ &ei_ax25_capture_gap,
			{ "ax25.link.capture_gap", PI_SEQUENCE, PI_CHAT,
			"Sequence numbers continue after an idle timeout: possible capture gap", EXPFILL }
		},
		{ &ei_ax25_refused,
			{ "ax25.link.refused.expert", PI_SEQUENCE, PI_NOTE,
			"Connection refused", EXPFILL }
		},
		{ &ei_ax25_fallback,
			{ "ax25.link.fallback.expert", PI_PROTOCOL, PI_NOTE,
			"SABM after a rejected SABME: falling back to v2.0", EXPFILL }
		},
		{ &ei_ax25_frmr_xid,
			{ "ax25.link.frmr_xid.expert", PI_PROTOCOL, PI_NOTE,
			"FRMR answering XID: the peer uses AX.25 v2.0", EXPFILL }
		},
		{ &ei_ax25_dup,
			{ "ax25.link.dup", PI_SEQUENCE, PI_NOTE,
			"Digipeated copy of an earlier frame", EXPFILL }
		},
		{ &ei_ax25_n1_exceeded,
			{ "ax25.param.n1.exceeded", PI_PROTOCOL, PI_WARN,
			"I field longer than the receiver's N1", EXPFILL }
		},
		{ &ei_ax25_xid_rule,
			{ "ax25.xid.negotiation", PI_PROTOCOL, PI_WARN,
			"XID response breaks section 6.3.2: the lesser of the two for duplex, reject and modulo, the greater for T1 and N2", EXPFILL }
		},
		{ &ei_ax25_sabm_xid,
			{ "ax25.xid.sabm_modulo", PI_PROTOCOL, PI_WARN,
			"SABM(E) asks for a modulo other than the one negotiated by XID", EXPFILL }
		},
		{ &ei_ax25_xid_modulo,
			{ "ax25.xid.modulo_change", PI_PROTOCOL, PI_NOTE,
			"XID after the UA changes the modulo", EXPFILL }
		},
		{ &ei_ax25_seg_not_negotiated,
			{ "ax25.seg.not_negotiated", PI_PROTOCOL, PI_WARN,
			"Segment on a link that didn't negotiate the segmenter", EXPFILL }
		},
		{ &ei_ax25_seg_neg_not_captured,
			{ "ax25.seg.negotiation_not_captured", PI_PROTOCOL, PI_NOTE,
			"Segment; the XID negotiation (if any) wasn't captured", EXPFILL }
		},
		{ &ei_ax25_seg_missing_first,
			{ "ax25.seg.missing_first", PI_SEQUENCE, PI_WARN,
			"Segment without a first segment before it", EXPFILL }
		},
		{ &ei_ax25_seg_remaining,
			{ "ax25.seg.remaining.bad", PI_SEQUENCE, PI_WARN,
			"Segments remaining doesn't go down by one", EXPFILL }
		},
		{ &ei_ax25_seg_interleaved,
			{ "ax25.seg.interleaved", PI_SEQUENCE, PI_WARN,
			"Frame in the middle of a segmented data unit", EXPFILL }
		},
		{ &ei_ax25_seg_too_long,
			{ "ax25.seg.too_long", PI_PROTOCOL, PI_WARN,
			"Segment longer than the receiver's N1", EXPFILL }
		},
		{ &ei_ax25_seg_tr210,
			{ "ax25.seg.tr210", PI_SEQUENCE, PI_NOTE,
			"Gap between segments longer than TR210", EXPFILL }
		},
		{ &ei_ax25_xid_length,
			{ "ax25.xid.length", PI_PROTOCOL, PI_WARN,
			"XID length runs past its group or the frame", EXPFILL }
		},
	};

	module_t *ax25_module;
	expert_module_t *expert_ax25;
	uat_t *stations_uat;

	static uat_field_t ax25_stations_fields[] = {
		UAT_FLD_CSTRING(ax25_stations, callsign, "Callsign",
			"CALL or CALL-SSID (without an SSID, SSID 0)"),
		UAT_FLD_DEC(ax25_stations, t1_ms, "T1 (ms)",
			"Acknowledgement timer of the station; 0: not set"),
		UAT_FLD_DEC(ax25_stations, t3_s, "T3 (s)",
			"Inactive link timer of the station; 0: not set"),
		UAT_FLD_DEC(ax25_stations, n2, "N2",
			"Maximum number of retries of the station; 0: not set"),
		UAT_FLD_DEC(ax25_stations, n1, "N1 (octets)",
			"Longest I field the station accepts; 0: not set"),
		UAT_FLD_DEC(ax25_stations, k, "k",
			"Largest window the station accepts; 0: not set"),
		UAT_FLD_VS(ax25_stations, version, "Version", ax25_uat_version_vals,
			"AX.25 version the station runs, for links where the capture doesn't show it"),
		UAT_END_FIELDS
	};

	/* Register the protocol name and description */
	proto_ax25 = proto_register_protocol("Amateur Radio AX.25", "AX.25", "ax25");
	ax25_module = prefs_register_protocol(proto_ax25, NULL);
	/* The modulo now comes from the link (SABM/SABME/UA, or inferred) */
	prefs_register_obsolete_preference(ax25_module, "extended");
	prefs_register_uint_preference(ax25_module, "t3",
		"Inactive link timer T3 (s)",
		"T3, used with T1 and N2 to decide when a silent link must be down"
		" (T3 + N2 x T1). The spec gives no default; 300 s is the Linux default.",
		10, &ax25_pref_t3_s);
	prefs_register_uint_preference(ax25_module, "t1",
		"Acknowledgement timer T1 (ms)",
		"T1 for links that didn't negotiate it with XID; 0: the spec default (3000 ms)",
		10, &ax25_pref_t1_ms);
	prefs_register_uint_preference(ax25_module, "n2",
		"Maximum number of retries N2",
		"N2 for links that didn't negotiate it with XID; 0: the spec default (10)",
		10, &ax25_pref_n2);
	prefs_register_uint_preference(ax25_module, "n1",
		"Maximum I field length N1 (octets)",
		"N1 for stations that didn't notify it with XID; 0: the spec default (256)",
		10, &ax25_pref_n1);
	prefs_register_uint_preference(ax25_module, "k",
		"Maximum window size k",
		"k for stations that didn't notify it with XID; 0: the spec default"
		" (see below for modulo 8, 32 for modulo 128)",
		10, &ax25_pref_k);
	prefs_register_uint_preference(ax25_module, "k_mod8_default",
		"Spec default window size k (modulo 8)",
		"The spec gives 7 in sections 6.3.2 and 6.7.2.3 but 4 in section 4.3.3.7",
		10, &ax25_pref_k_mod8_default);
	prefs_register_uint_preference(ax25_module, "tr210",
		"Next segment timer TR210 (s)",
		"Longest expected gap between two segments. The spec gives no value;"
		" 0: N2 x T1 of the sender",
		10, &ax25_pref_tr210_s);

	/*
	 * Per-station parameters, in between XID and the preferences above.
	 * Precedence: XID, this table, preferences, spec defaults.
	 */
	stations_uat = uat_new("AX.25 stations",
		sizeof(ax25_station_uat_t),
		"ax25_stations",
		true,
		&ax25_stations,
		&ax25_num_stations,
		UAT_AFFECTS_DISSECTION,
		NULL,
		ax25_stations_copy_cb,
		ax25_stations_update_cb,
		ax25_stations_free_cb,
		NULL,
		NULL,
		ax25_stations_fields);
	prefs_register_uat_preference(ax25_module, "stations",
		"Station parameters",
		"Link parameters of known stations, used when the capture doesn't show them",
		stations_uat);

	/* Register the dissector */
	ax25_handle = register_dissector( "ax25", dissect_ax25, proto_ax25 );

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array( proto_ax25, hf, array_length(hf ) );
	proto_register_subtree_array(ett, array_length(ett ) );
	expert_ax25 = expert_register_protocol( proto_ax25 );
	expert_register_field_array( expert_ax25, ei, array_length( ei ) );

	/* Register dissector table for protocol IDs */
	ax25_dissector_table = register_dissector_table("ax25.pid", "AX.25 protocol ID", proto_ax25, FT_UINT8, BASE_HEX);
	register_capture_dissector_table("ax25.pid", "AX.25");

	ax25_cap_handle = register_capture_dissector("ax25", capture_ax25, proto_ax25);

	register_init_routine( ax25_init );
}

void
proto_reg_handoff_ax25(void)
{
	dissector_add_uint("ax25.pid", AX25_P_SEGMENT,
			create_dissector_handle(dissect_ax25_segment, proto_ax25));
	dissector_add_uint("wtap_encap", WTAP_ENCAP_AX25, ax25_handle);
	dissector_add_uint("ip.proto", IP_PROTO_AX25, ax25_handle);

	capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_AX25, ax25_cap_handle);
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
