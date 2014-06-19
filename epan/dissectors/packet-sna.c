/* packet-sna.c
 * Routines for SNA
 * Gilbert Ramirez <gram@alumni.rice.edu>
 * Jochen Friedrich <jochen@scram.de>
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/llcsaps.h>
#include <epan/ppptypes.h>
#include <epan/sna-utils.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>

/*
 * http://www.wanresources.com/snacell.html
 * ftp://ftp.software.ibm.com/networking/pub/standards/aiw/formats/
 *
 */
void proto_register_sna(void);
void proto_reg_handoff_sna(void);

static int proto_sna = -1;
static int proto_sna_xid = -1;
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

static int hf_sna_nlp_nhdr = -1;
static int hf_sna_nlp_nhdr_0 = -1;
static int hf_sna_nlp_sm = -1;
static int hf_sna_nlp_tpf = -1;
static int hf_sna_nlp_nhdr_1 = -1;
static int hf_sna_nlp_ft = -1;
static int hf_sna_nlp_tspi = -1;
static int hf_sna_nlp_slowdn1 = -1;
static int hf_sna_nlp_slowdn2 = -1;
static int hf_sna_nlp_fra = -1;
static int hf_sna_nlp_anr = -1;
static int hf_sna_nlp_frh = -1;
static int hf_sna_nlp_thdr = -1;
static int hf_sna_nlp_tcid = -1;
static int hf_sna_nlp_thdr_8 = -1;
static int hf_sna_nlp_setupi = -1;
static int hf_sna_nlp_somi = -1;
static int hf_sna_nlp_eomi = -1;
static int hf_sna_nlp_sri = -1;
static int hf_sna_nlp_rasapi = -1;
static int hf_sna_nlp_retryi = -1;
static int hf_sna_nlp_thdr_9 = -1;
static int hf_sna_nlp_lmi = -1;
static int hf_sna_nlp_cqfi = -1;
static int hf_sna_nlp_osi = -1;
static int hf_sna_nlp_offset = -1;
static int hf_sna_nlp_dlf = -1;
static int hf_sna_nlp_bsn = -1;
static int hf_sna_nlp_opti_len = -1;
static int hf_sna_nlp_opti_type = -1;
static int hf_sna_nlp_opti_0d_version = -1;
static int hf_sna_nlp_opti_0d_4 = -1;
static int hf_sna_nlp_opti_0d_target = -1;
static int hf_sna_nlp_opti_0d_arb = -1;
static int hf_sna_nlp_opti_0d_reliable = -1;
static int hf_sna_nlp_opti_0d_dedicated = -1;
static int hf_sna_nlp_opti_0e_stat = -1;
static int hf_sna_nlp_opti_0e_gap = -1;
static int hf_sna_nlp_opti_0e_idle = -1;
static int hf_sna_nlp_opti_0e_nabsp = -1;
static int hf_sna_nlp_opti_0e_sync = -1;
static int hf_sna_nlp_opti_0e_echo = -1;
static int hf_sna_nlp_opti_0e_rseq = -1;
/* static int hf_sna_nlp_opti_0e_abspbeg = -1; */
/* static int hf_sna_nlp_opti_0e_abspend = -1; */
static int hf_sna_nlp_opti_0f_bits = -1;
static int hf_sna_nlp_opti_10_tcid = -1;
static int hf_sna_nlp_opti_12_sense = -1;
static int hf_sna_nlp_opti_14_si_len = -1;
static int hf_sna_nlp_opti_14_si_key = -1;
static int hf_sna_nlp_opti_14_si_2 = -1;
static int hf_sna_nlp_opti_14_si_refifo = -1;
static int hf_sna_nlp_opti_14_si_mobility = -1;
static int hf_sna_nlp_opti_14_si_dirsearch = -1;
static int hf_sna_nlp_opti_14_si_limitres = -1;
static int hf_sna_nlp_opti_14_si_ncescope = -1;
static int hf_sna_nlp_opti_14_si_mnpsrscv = -1;
static int hf_sna_nlp_opti_14_si_maxpsize = -1;
static int hf_sna_nlp_opti_14_si_switch = -1;
static int hf_sna_nlp_opti_14_si_alive = -1;
static int hf_sna_nlp_opti_14_rr_len = -1;
static int hf_sna_nlp_opti_14_rr_key = -1;
static int hf_sna_nlp_opti_14_rr_2 = -1;
static int hf_sna_nlp_opti_14_rr_bfe = -1;
static int hf_sna_nlp_opti_14_rr_num = -1;
static int hf_sna_nlp_opti_22_2 = -1;
static int hf_sna_nlp_opti_22_type = -1;
static int hf_sna_nlp_opti_22_raa = -1;
static int hf_sna_nlp_opti_22_parity = -1;
static int hf_sna_nlp_opti_22_arb = -1;
static int hf_sna_nlp_opti_22_3 = -1;
static int hf_sna_nlp_opti_22_ratereq = -1;
static int hf_sna_nlp_opti_22_raterep = -1;
static int hf_sna_nlp_opti_22_field1 = -1;
static int hf_sna_nlp_opti_22_field2 = -1;
static int hf_sna_nlp_opti_22_field3 = -1;
static int hf_sna_nlp_opti_22_field4 = -1;

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

static int hf_sna_gds = -1;
static int hf_sna_gds_len = -1;
static int hf_sna_gds_type = -1;
static int hf_sna_gds_cont = -1;

/* static int hf_sna_xid = -1; */
static int hf_sna_xid_0 = -1;
static int hf_sna_xid_id = -1;
static int hf_sna_xid_format = -1;
static int hf_sna_xid_type = -1;
static int hf_sna_xid_len = -1;
static int hf_sna_xid_idblock = -1;
static int hf_sna_xid_idnum = -1;
static int hf_sna_xid_3_8 = -1;
static int hf_sna_xid_3_init_self = -1;
static int hf_sna_xid_3_stand_bind = -1;
static int hf_sna_xid_3_gener_bind = -1;
static int hf_sna_xid_3_recve_bind = -1;
static int hf_sna_xid_3_actpu = -1;
static int hf_sna_xid_3_nwnode = -1;
static int hf_sna_xid_3_cp = -1;
static int hf_sna_xid_3_cpcp = -1;
static int hf_sna_xid_3_state = -1;
static int hf_sna_xid_3_nonact = -1;
static int hf_sna_xid_3_cpchange = -1;
static int hf_sna_xid_3_10 = -1;
static int hf_sna_xid_3_asend_bind = -1;
static int hf_sna_xid_3_arecv_bind = -1;
static int hf_sna_xid_3_quiesce = -1;
static int hf_sna_xid_3_pucap = -1;
static int hf_sna_xid_3_pbn = -1;
static int hf_sna_xid_3_pacing = -1;
static int hf_sna_xid_3_11 = -1;
static int hf_sna_xid_3_tgshare = -1;
static int hf_sna_xid_3_dedsvc = -1;
static int hf_sna_xid_3_12 = -1;
static int hf_sna_xid_3_negcsup = -1;
static int hf_sna_xid_3_negcomp = -1;
static int hf_sna_xid_3_15 = -1;
static int hf_sna_xid_3_partg = -1;
static int hf_sna_xid_3_dlur = -1;
static int hf_sna_xid_3_dlus = -1;
static int hf_sna_xid_3_exbn = -1;
static int hf_sna_xid_3_genodai = -1;
static int hf_sna_xid_3_branch = -1;
static int hf_sna_xid_3_brnn = -1;
static int hf_sna_xid_3_tg = -1;
static int hf_sna_xid_3_dlc = -1;
static int hf_sna_xid_3_dlen = -1;

static int hf_sna_control_len = -1;
static int hf_sna_control_key = -1;
static int hf_sna_control_hprkey = -1;
static int hf_sna_control_05_delay = -1;
static int hf_sna_control_05_type = -1;
static int hf_sna_control_05_ptp = -1;
static int hf_sna_control_0e_type = -1;
static int hf_sna_control_0e_value = -1;

static gint ett_sna = -1;
static gint ett_sna_th = -1;
static gint ett_sna_th_fid = -1;
static gint ett_sna_nlp_nhdr = -1;
static gint ett_sna_nlp_nhdr_0 = -1;
static gint ett_sna_nlp_nhdr_1 = -1;
static gint ett_sna_nlp_thdr = -1;
static gint ett_sna_nlp_thdr_8 = -1;
static gint ett_sna_nlp_thdr_9 = -1;
static gint ett_sna_nlp_opti_un = -1;
static gint ett_sna_nlp_opti_0d = -1;
static gint ett_sna_nlp_opti_0d_4 = -1;
static gint ett_sna_nlp_opti_0e = -1;
static gint ett_sna_nlp_opti_0e_stat = -1;
static gint ett_sna_nlp_opti_0e_absp = -1;
static gint ett_sna_nlp_opti_0f = -1;
static gint ett_sna_nlp_opti_10 = -1;
static gint ett_sna_nlp_opti_12 = -1;
static gint ett_sna_nlp_opti_14 = -1;
static gint ett_sna_nlp_opti_14_si = -1;
static gint ett_sna_nlp_opti_14_si_2 = -1;
static gint ett_sna_nlp_opti_14_rr = -1;
static gint ett_sna_nlp_opti_14_rr_2 = -1;
static gint ett_sna_nlp_opti_22 = -1;
static gint ett_sna_nlp_opti_22_2 = -1;
static gint ett_sna_nlp_opti_22_3 = -1;
static gint ett_sna_rh = -1;
static gint ett_sna_rh_0 = -1;
static gint ett_sna_rh_1 = -1;
static gint ett_sna_rh_2 = -1;
static gint ett_sna_gds = -1;
static gint ett_sna_xid_0 = -1;
static gint ett_sna_xid_id = -1;
static gint ett_sna_xid_3_8 = -1;
static gint ett_sna_xid_3_10 = -1;
static gint ett_sna_xid_3_11 = -1;
static gint ett_sna_xid_3_12 = -1;
static gint ett_sna_xid_3_15 = -1;
static gint ett_sna_control_un = -1;
static gint ett_sna_control_05 = -1;
static gint ett_sna_control_05hpr = -1;
static gint ett_sna_control_05hpr_type = -1;
static gint ett_sna_control_0e = -1;

static dissector_handle_t data_handle;

/* Defragment fragmented SNA BIUs*/
static gboolean sna_defragment = TRUE;
static reassembly_table sna_reassembly_table;

/* Format Identifier */
static const value_string sna_th_fid_vals[] = {
	{ 0x0,	"SNA device <--> Non-SNA Device" },
	{ 0x1,	"Subarea Nodes, without ER or VR" },
	{ 0x2,	"Subarea Node <--> PU2" },
	{ 0x3,	"Subarea Node or SNA host <--> Subarea Node" },
	{ 0x4,	"Subarea Nodes, supporting ER and VR" },
	{ 0x5,	"HPR RTP endpoint nodes" },
	{ 0xa,	"HPR NLP Frame Routing" },
	{ 0xb,	"HPR NLP Frame Routing" },
	{ 0xc,	"HPR NLP Automatic Network Routing" },
	{ 0xd,	"HPR NLP Automatic Network Routing" },
	{ 0xf,	"Adjacent Subarea Nodes, supporting ER and VR" },
	{ 0x0,	NULL }
};

/* Mapping Field */
#define MPF_MIDDLE_SEGMENT  0
#define MPF_LAST_SEGMENT    1
#define MPF_FIRST_SEGMENT   2
#define MPF_WHOLE_BIU       3

static const value_string sna_th_mpf_vals[] = {
	{ MPF_MIDDLE_SEGMENT,   "Middle segment of a BIU" },
	{ MPF_LAST_SEGMENT,     "Last segment of a BIU" },
	{ MPF_FIRST_SEGMENT,    "First segment of a BIU" },
	{ MPF_WHOLE_BIU,        "Whole BIU" },
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
	{ 1, "This PIU does not overtake any PIU ahead of it." },
	{ 0x0,	NULL }
};

/* ER_VR_SUPP_IND */
static const value_string sna_th_er_vr_supp_ind_vals[] = {
	{ 0, "Each node supports ER and VR protocols" },
	{ 1, "Includes at least one node that does not support ER and VR"
	    " protocols"  },
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
	{ 3, "Network Priority" },
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

/* Switching Mode */
static const value_string sna_nlp_sm_vals[] = {
	{ 5, "Function routing" },
	{ 6, "Automatic network routing" },
	{ 0x0,	NULL }
};

static const true_false_string sna_nlp_tspi_truth =
	{ "Time sensitive", "Not time sensitive" };

static const true_false_string sna_nlp_slowdn1_truth =
	{ "Minor congestion", "No minor congestion" };

static const true_false_string sna_nlp_slowdn2_truth =
	{ "Major congestion", "No major congestion" };

/* Function Type */
static const value_string sna_nlp_ft_vals[] = {
	{ 0x10, "LDLC" },
	{ 0x0,	NULL }
};

static const value_string sna_nlp_frh_vals[] = {
	{ 0x03, "XID complete request" },
	{ 0x04, "XID complete response" },
	{ 0x0,	NULL }
};

static const true_false_string sna_nlp_setupi_truth =
	{ "Connection setup segment present", "Connection setup segment not"
	    " present" };

static const true_false_string sna_nlp_somi_truth =
	{ "Start of message", "Not start of message" };

static const true_false_string sna_nlp_eomi_truth =
	{ "End of message", "Not end of message" };

static const true_false_string sna_nlp_sri_truth =
	{ "Status requested", "No status requested" };

static const true_false_string sna_nlp_rasapi_truth =
	{ "Reply as soon as possible", "No need to reply as soon as possible" };

static const true_false_string sna_nlp_retryi_truth =
	{ "Undefined", "Sender will retransmit" };

static const true_false_string sna_nlp_lmi_truth =
	{ "Last message", "Not last message" };

static const true_false_string sna_nlp_cqfi_truth =
	{ "CQFI included", "CQFI not included" };

static const true_false_string sna_nlp_osi_truth =
	{ "Optional segments present", "No optional segments present" };

static const value_string sna_xid_3_state_vals[] = {
	{ 0x00, "Exchange state indicators not supported" },
	{ 0x01, "Negotiation-proceeding exchange" },
	{ 0x02, "Prenegotiation exchange" },
	{ 0x03, "Nonactivation exchange" },
	{ 0x0, NULL }
};

static const value_string sna_xid_3_branch_vals[] = {
	{ 0x00, "Sender does not support branch extender" },
	{ 0x01, "TG is branch uplink" },
	{ 0x02, "TG is branch downlink" },
	{ 0x03, "TG is neither uplink nor downlink" },
	{ 0x0, NULL }
};

static const value_string sna_xid_type_vals[] = {
	{ 0x01, "T1 node" },
	{ 0x02, "T2.0 or T2.1 node" },
	{ 0x03, "Reserved" },
	{ 0x04, "T4 or T5 node" },
	{ 0x0, NULL }
};

static const value_string sna_nlp_opti_vals[] = {
	{ 0x0d, "Connection Setup Segment" },
	{ 0x0e, "Status Segment" },
	{ 0x0f, "Client Out Of Band Bits Segment" },
	{ 0x10, "Connection Identifier Exchange Segment" },
	{ 0x12, "Connection Fault Segment" },
	{ 0x14, "Switching Information Segment" },
	{ 0x22, "Adaptive Rate-Based Segment" },
	{ 0x0, NULL }
};

static const value_string sna_nlp_opti_0d_version_vals[] = {
	{ 0x0101, "Version 1.1" },
	{ 0x0, NULL }
};

static const value_string sna_nlp_opti_0f_bits_vals[] = {
	{ 0x0001, "Request Deactivation" },
	{ 0x8000, "Reply - OK" },
	{ 0x8004, "Reply - Reject" },
	{ 0x0, NULL }
};

static const value_string sna_nlp_opti_22_type_vals[] = {
	{ 0x00, "Setup" },
	{ 0x01, "Rate Reply" },
	{ 0x02, "Rate Request" },
	{ 0x03, "Rate Request/Rate Reply" },
	{ 0x0, NULL }
};

static const value_string sna_nlp_opti_22_raa_vals[] = {
	{ 0x00, "Normal" },
	{ 0x01, "Restraint" },
	{ 0x02, "Slowdown1" },
	{ 0x03, "Slowdown2" },
	{ 0x04, "Critical" },
	{ 0x0, NULL }
};

static const value_string sna_nlp_opti_22_arb_vals[] = {
	{ 0x00, "Base Mode ARB" },
	{ 0x01, "Responsive Mode ARB" },
	{ 0x0, NULL }
};

/* GDS Variable Type */
static const value_string sna_gds_var_vals[] = {
	{ 0x1210, "Change Number Of Sessions" },
	{ 0x1211, "Exchange Log Name" },
	{ 0x1212, "Control Point Management Services Unit" },
	{ 0x1213, "Compare States" },
	{ 0x1214, "LU Names Position" },
	{ 0x1215, "LU Name" },
	{ 0x1217, "Do Know" },
	{ 0x1218, "Partner Restart" },
	{ 0x1219, "Don't Know" },
	{ 0x1220, "Sign-Off" },
	{ 0x1221, "Sign-On" },
	{ 0x1222, "SNMP-over-SNA" },
	{ 0x1223, "Node Address Service" },
	{ 0x12C1, "CP Capabilities" },
	{ 0x12C2, "Topology Database Update" },
	{ 0x12C3, "Register Resource" },
	{ 0x12C4, "Locate" },
	{ 0x12C5, "Cross-Domain Initiate" },
	{ 0x12C9, "Delete Resource" },
	{ 0x12CA, "Find Resource" },
	{ 0x12CB, "Found Resource" },
	{ 0x12CC, "Notify" },
	{ 0x12CD, "Initiate-Other Cross-Domain" },
	{ 0x12CE, "Route Setup" },
	{ 0x12E1, "Error Log" },
	{ 0x12F1, "Null Data" },
	{ 0x12F2, "User Control Date" },
	{ 0x12F3, "Map Name" },
	{ 0x12F4, "Error Data" },
	{ 0x12F6, "Authentication Token Data" },
	{ 0x12F8, "Service Flow Authentication Token Data" },
	{ 0x12FF, "Application Data" },
	{ 0x1310, "MDS Message Unit" },
	{ 0x1311, "MDS Routing Information" },
	{ 0x1500, "FID2 Encapsulation" },
	{ 0x0,    NULL }
};

/* Control Vector Type */
static const value_string sna_control_vals[] = {
	{ 0x00,   "SSCP-LU Session Capabilities Control Vector" },
	{ 0x01,   "Date-Time Control Vector" },
	{ 0x02,   "Subarea Routing Control Vector" },
	{ 0x03,   "SDLC Secondary Station Control Vector" },
	{ 0x04,   "LU Control Vector" },
	{ 0x05,   "Channel Control Vector" },
	{ 0x06,   "Cross-Domain Resource Manager (CDRM) Control Vector" },
	{ 0x07,   "PU FMD-RU-Usage Control Vector" },
	{ 0x08,   "Intensive Mode Control Vector" },
	{ 0x09,   "Activation Request / Response Sequence Identifier Control"
	    " Vector" },
	{ 0x0a,   "User Request Correlator Control Vector" },
	{ 0x0b,   "SSCP-PU Session Capabilities Control Vector" },
	{ 0x0c,   "LU-LU Session Capabilities Control Vector" },
	{ 0x0d,   "Mode / Class-of-Service / Virtual-Route-Identifier List"
	    " Control Vector" },
	{ 0x0e,   "Network Name Control Vector" },
	{ 0x0f,   "Link Capabilities and Status Control Vector" },
	{ 0x10,   "Product Set ID Control Vector" },
	{ 0x11,   "Load Module Correlation Control Vector" },
	{ 0x12,   "Network Identifier Control Vector" },
	{ 0x13,   "Gateway Support Capabilities Control Vector" },
	{ 0x14,   "Session Initiation Control Vector" },
	{ 0x15,   "Network-Qualified Address Pair Control Vector" },
	{ 0x16,   "Names Substitution Control Vector" },
	{ 0x17,   "SSCP Identifier Control Vector" },
	{ 0x18,   "SSCP Name Control Vector" },
	{ 0x19,   "Resource Identifier Control Vector" },
	{ 0x1a,   "NAU Address Control Vector" },
	{ 0x1b,   "VRID List Control Vector" },
	{ 0x1c,   "Network-Qualified Name Pair Control Vector" },
	{ 0x1e,   "VR-ER Mapping Data Control Vector" },
	{ 0x1f,   "ER Configuration Control Vector" },
	{ 0x23,   "Local-Form Session Identifier Control Vector" },
	{ 0x24,   "IPL Load Module Request Control Vector" },
	{ 0x25,   "Security ID Control Control Vector" },
	{ 0x26,   "Network Connection Endpoint Identifier Control Vector" },
	{ 0x27,   "XRF Session Activation Control Vector" },
	{ 0x28,   "Related Session Identifier Control Vector" },
	{ 0x29,   "Session State Data Control Vector" },
	{ 0x2a,   "Session Information Control Vector" },
	{ 0x2b,   "Route Selection Control Vector" },
	{ 0x2c,   "COS/TPF Control Vector" },
	{ 0x2d,   "Mode Control Vector" },
	{ 0x2f,   "LU Definition Control Vector" },
	{ 0x30,   "Assign LU Characteristics Control Vector" },
	{ 0x31,   "BIND Image Control Vector" },
	{ 0x32,   "Short-Hold Mode Control Vector" },
	{ 0x33,   "ENCP Search Control Control Vector" },
	{ 0x34,   "LU Definition Override Control Vector" },
	{ 0x35,   "Extended Sense Data Control Vector" },
	{ 0x36,   "Directory Error Control Vector" },
	{ 0x37,   "Directory Entry Correlator Control Vector" },
	{ 0x38,   "Short-Hold Mode Emulation Control Vector" },
	{ 0x39,   "Network Connection Endpoint (NCE) Instance Identifier"
	    " Control Vector" },
	{ 0x3a,   "Route Status Data Control Vector" },
	{ 0x3b,   "VR Congestion Data Control Vector" },
	{ 0x3c,   "Associated Resource Entry Control Vector" },
	{ 0x3d,   "Directory Entry Control Vector" },
	{ 0x3e,   "Directory Entry Characteristic Control Vector" },
	{ 0x3f,   "SSCP (SLU) Capabilities Control Vector" },
	{ 0x40,   "Real Associated Resource Control Vector" },
	{ 0x41,   "Station Parameters Control Vector" },
	{ 0x42,   "Dynamic Path Update Data Control Vector" },
	{ 0x43,   "Extended SDLC Station Control Vector" },
	{ 0x44,   "Node Descriptor Control Vector" },
	{ 0x45,   "Node Characteristics Control Vector" },
	{ 0x46,   "TG Descriptor Control Vector" },
	{ 0x47,   "TG Characteristics Control Vector" },
	{ 0x48,   "Topology Resource Descriptor Control Vector" },
	{ 0x49,   "Multinode Persistent Sessions (MNPS) LU Names Control"
	    " Vector" },
	{ 0x4a,   "Real Owning Control Point Control Vector" },
	{ 0x4b,   "RTP Transport Connection Identifier Control Vector" },
	{ 0x51,   "DLUR/S Capabilities Control Vector" },
	{ 0x52,   "Primary Send Pacing Window Size Control Vector" },
	{ 0x56,   "Call Security Verification Control Vector" },
	{ 0x57,   "DLC Connection Data Control Vector" },
	{ 0x59,   "Installation-Defined CDINIT Data Control Vector" },
	{ 0x5a,   "Session Services Extension Support Control Vector" },
	{ 0x5b,   "Interchange Node Support Control Vector" },
	{ 0x5c,   "APPN Message Transport Control Vector" },
	{ 0x5d,   "Subarea Message Transport Control Vector" },
	{ 0x5e,   "Related Request Control Vector" },
	{ 0x5f,   "Extended Fully Qualified PCID Control Vector" },
	{ 0x60,   "Fully Qualified PCID Control Vector" },
	{ 0x61,   "HPR Capabilities Control Vector" },
	{ 0x62,   "Session Address Control Vector" },
	{ 0x63,   "Cryptographic Key Distribution Control Vector" },
	{ 0x64,   "TCP/IP Information Control Vector" },
	{ 0x65,   "Device Characteristics Control Vector" },
	{ 0x66,   "Length-Checked Compression Control Vector" },
	{ 0x67,   "Automatic Network Routing (ANR) Path Control Vector" },
	{ 0x68,   "XRF/Session Cryptography Control Vector" },
	{ 0x69,   "Switched Parameters Control Vector" },
	{ 0x6a,   "ER Congestion Data Control Vector" },
	{ 0x71,   "Triple DES Cryptography Key Continuation Control Vector" },
	{ 0xfe,   "Control Vector Keys Not Recognized" },
	{ 0x0,    NULL }
};

static const value_string sna_control_hpr_vals[] = {
	{ 0x00,   "Node Identifier Control Vector" },
	{ 0x03,   "Network ID Control Vector" },
	{ 0x05,   "Network Address Control Vector" },
	{ 0x0,    NULL }
};

static const value_string sna_control_0e_type_vals[] = {
	{ 0xF1,   "PU Name" },
	{ 0xF3,   "LU Name" },
	{ 0xF4,   "CP Name" },
	{ 0xF5,   "SSCP Name" },
	{ 0xF6,   "NNCP Name" },
	{ 0xF7,   "Link Station Name" },
	{ 0xF8,   "CP Name of CP(PLU)" },
	{ 0xF9,   "CP Name of CP(SLU)" },
	{ 0xFA,   "Generic Name" },
	{ 0x0,    NULL }
};

/* Values to direct the top-most dissector what to dissect
 * after the TH. */
enum next_dissection_enum {
    stop_here,
    rh_only,
    everything
};

enum parse {
    LT,
    KL
};

typedef enum next_dissection_enum next_dissection_t;

static void dissect_xid (tvbuff_t*, packet_info*, proto_tree*, proto_tree*);
static void dissect_fid (tvbuff_t*, packet_info*, proto_tree*, proto_tree*);
static void dissect_nlp (tvbuff_t*, packet_info*, proto_tree*, proto_tree*);
static void dissect_gds (tvbuff_t*, packet_info*, proto_tree*, proto_tree*);
static void dissect_rh (tvbuff_t*, int, proto_tree*);
static void dissect_control(tvbuff_t*, int, int, proto_tree*, int, enum parse);

/* --------------------------------------------------------------------
 * Chapter 2 High-Performance Routing (HPR) Headers
 * --------------------------------------------------------------------
 */

static void
dissect_optional_0d(tvbuff_t *tvb, proto_tree *tree)
{
	int		bits, offset, len, pad;
	proto_tree	*sub_tree;
	proto_item	*sub_ti = NULL;

	if (!tree)
		return;

	proto_tree_add_item(tree, hf_sna_nlp_opti_0d_version, tvb, 2, 2, ENC_BIG_ENDIAN);
	bits = tvb_get_guint8(tvb, 4);

	sub_ti = proto_tree_add_uint(tree, hf_sna_nlp_opti_0d_4,
	    tvb, 4, 1, bits);
	sub_tree = proto_item_add_subtree(sub_ti,
	    ett_sna_nlp_opti_0d_4);

	proto_tree_add_boolean(sub_tree, hf_sna_nlp_opti_0d_target,
	    tvb, 4, 1, bits);
	proto_tree_add_boolean(sub_tree, hf_sna_nlp_opti_0d_arb,
	    tvb, 4, 1, bits);
	proto_tree_add_boolean(sub_tree, hf_sna_nlp_opti_0d_reliable,
	    tvb, 4, 1, bits);
	proto_tree_add_boolean(sub_tree, hf_sna_nlp_opti_0d_dedicated,
	    tvb, 4, 1, bits);

	proto_tree_add_text(tree, tvb, 5, 3, "Reserved");

	offset = 8;

	while (tvb_offset_exists(tvb, offset)) {
		len = tvb_get_guint8(tvb, offset+0);
		if (len) {
			dissect_control(tvb, offset, len, tree, 1, LT);
			pad = (len+3) & 0xfffc;
			if (pad > len)
				proto_tree_add_text(tree, tvb, offset+len,
				    pad-len, "Padding");
			offset += pad;
		} else {
			/* Avoid endless loop */
			return;
		}
	}
}

static void
dissect_optional_0e(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int		bits, offset;
	proto_tree	*sub_tree;
	proto_item	*sub_ti = NULL;

	bits = tvb_get_guint8(tvb, 2);
	offset = 20;

	if (tree) {
		sub_ti = proto_tree_add_item(tree, hf_sna_nlp_opti_0e_stat,
		    tvb, 2, 1, ENC_BIG_ENDIAN);
		sub_tree = proto_item_add_subtree(sub_ti,
		    ett_sna_nlp_opti_0e_stat);

		proto_tree_add_boolean(sub_tree, hf_sna_nlp_opti_0e_gap,
		    tvb, 2, 1, bits);
		proto_tree_add_boolean(sub_tree, hf_sna_nlp_opti_0e_idle,
		    tvb, 2, 1, bits);
		proto_tree_add_item(tree, hf_sna_nlp_opti_0e_nabsp,
		    tvb, 3, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_sna_nlp_opti_0e_sync,
		    tvb, 4, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_sna_nlp_opti_0e_echo,
		    tvb, 6, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_sna_nlp_opti_0e_rseq,
		    tvb, 8, 4, ENC_BIG_ENDIAN);
		proto_tree_add_text(tree, tvb, 12, 8, "Reserved");

		if (tvb_offset_exists(tvb, offset))
			call_dissector(data_handle,
			    tvb_new_subset_remaining(tvb, 4), pinfo, tree);
	}
	if (bits & 0x40) {
		col_set_str(pinfo->cinfo, COL_INFO, "HPR Idle Message");
	} else {
		col_set_str(pinfo->cinfo, COL_INFO, "HPR Status Message");
	}
}

static void
dissect_optional_0f(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (!tree)
		return;

	proto_tree_add_item(tree, hf_sna_nlp_opti_0f_bits, tvb, 2, 2, ENC_BIG_ENDIAN);
	if (tvb_offset_exists(tvb, 4))
		call_dissector(data_handle,
		    tvb_new_subset_remaining(tvb, 4), pinfo, tree);
}

static void
dissect_optional_10(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (!tree)
		return;

	proto_tree_add_text(tree, tvb, 2, 2, "Reserved");
	proto_tree_add_item(tree, hf_sna_nlp_opti_10_tcid, tvb, 4, 8, ENC_NA);
	if (tvb_offset_exists(tvb, 12))
		call_dissector(data_handle,
		    tvb_new_subset_remaining(tvb, 12), pinfo, tree);
}

static void
dissect_optional_12(tvbuff_t *tvb, proto_tree *tree)
{
	if (!tree)
		return;

	proto_tree_add_text(tree, tvb, 2, 2, "Reserved");
	proto_tree_add_item(tree, hf_sna_nlp_opti_12_sense, tvb, 4, -1, ENC_NA);
}

static void
dissect_optional_14(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*sub_tree, *bf_tree;
	proto_item	*sub_item, *bf_item;
	int		len, pad, type, bits, offset, num, sublen;

	if (!tree)
		return;

	proto_tree_add_text(tree, tvb, 2, 2, "Reserved");

	offset = 4;

	len = tvb_get_guint8(tvb, offset);
	type = tvb_get_guint8(tvb, offset+1);

	if ((type != 0x83) || (len <= 16)) {
		/* Invalid */
		call_dissector(data_handle,
		    tvb_new_subset_remaining(tvb, offset), pinfo, tree);
		return;
	}
	sub_item = proto_tree_add_text(tree, tvb, offset, len,
	    "Switching Information Control Vector");
	sub_tree = proto_item_add_subtree(sub_item, ett_sna_nlp_opti_14_si);

	proto_tree_add_uint(sub_tree, hf_sna_nlp_opti_14_si_len,
	    tvb, offset, 1, len);
	proto_tree_add_uint(sub_tree, hf_sna_nlp_opti_14_si_key,
	    tvb, offset+1, 1, type);

	bits = tvb_get_guint8(tvb, offset+2);
	bf_item = proto_tree_add_uint(sub_tree, hf_sna_nlp_opti_14_si_2,
	    tvb, offset+2, 1, bits);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_nlp_opti_14_si_2);

	proto_tree_add_boolean(bf_tree, hf_sna_nlp_opti_14_si_refifo,
	    tvb, offset+2, 1, bits);
	proto_tree_add_boolean(bf_tree, hf_sna_nlp_opti_14_si_mobility,
	    tvb, offset+2, 1, bits);
	proto_tree_add_boolean(bf_tree, hf_sna_nlp_opti_14_si_dirsearch,
	    tvb, offset+2, 1, bits);
	proto_tree_add_boolean(bf_tree, hf_sna_nlp_opti_14_si_limitres,
	    tvb, offset+2, 1, bits);
	proto_tree_add_boolean(bf_tree, hf_sna_nlp_opti_14_si_ncescope,
	    tvb, offset+2, 1, bits);
	proto_tree_add_boolean(bf_tree, hf_sna_nlp_opti_14_si_mnpsrscv,
	    tvb, offset+2, 1, bits);

	proto_tree_add_text(sub_tree, tvb, offset+3, 1, "Reserved");
	proto_tree_add_item(sub_tree, hf_sna_nlp_opti_14_si_maxpsize,
	    tvb, offset+4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_sna_nlp_opti_14_si_switch,
	    tvb, offset+8, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_sna_nlp_opti_14_si_alive,
	    tvb, offset+12, 4, ENC_BIG_ENDIAN);

	dissect_control(tvb, offset+16, len-16, sub_tree, 1, LT);

	pad = (len+3) & 0xfffc;
	if (pad > len)
		proto_tree_add_text(sub_tree, tvb, offset+len, pad-len,
		    "Padding");
	offset += pad;

	len = tvb_get_guint8(tvb, offset);
	type = tvb_get_guint8(tvb, offset+1);

	if ((type != 0x85) || ( len < 4))  {
		/* Invalid */
		call_dissector(data_handle,
		    tvb_new_subset_remaining(tvb, offset), pinfo, tree);
		return;
	}
	sub_item = proto_tree_add_text(tree, tvb, offset, len,
	    "Return Route TG Descriptor Control Vector");
	sub_tree = proto_item_add_subtree(sub_item, ett_sna_nlp_opti_14_rr);

	proto_tree_add_uint(sub_tree, hf_sna_nlp_opti_14_rr_len,
	    tvb, offset, 1, len);
	proto_tree_add_uint(sub_tree, hf_sna_nlp_opti_14_rr_key,
	    tvb, offset+1, 1, type);

	bits = tvb_get_guint8(tvb, offset+2);
	bf_item = proto_tree_add_uint(sub_tree, hf_sna_nlp_opti_14_rr_2,
	    tvb, offset+2, 1, bits);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_nlp_opti_14_rr_2);

	proto_tree_add_boolean(bf_tree, hf_sna_nlp_opti_14_rr_bfe,
	    tvb, offset+2, 1, bits);

	num = tvb_get_guint8(tvb, offset+3);

	proto_tree_add_uint(sub_tree, hf_sna_nlp_opti_14_rr_num,
	    tvb, offset+3, 1, num);

	offset += 4;

	while (num) {
		sublen = tvb_get_guint8(tvb, offset);
		if (sublen) {
			dissect_control(tvb, offset, sublen, sub_tree, 1, LT);
		} else {
			/* Invalid */
			call_dissector(data_handle,
			    tvb_new_subset_remaining(tvb, offset), pinfo, tree);
			return;
		}
		/* No padding here */
		offset += sublen;
		num--;
	}
}

static void
dissect_optional_22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	int		bits, type;

	if (!tree)
		return;

	bits = tvb_get_guint8(tvb, 2);
	type = (bits & 0xc0) >> 6;

	bf_item = proto_tree_add_uint(tree, hf_sna_nlp_opti_22_2,
	    tvb, 2, 1, bits);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_nlp_opti_22_2);

	proto_tree_add_uint(bf_tree, hf_sna_nlp_opti_22_type,
	    tvb, 2, 1, bits);
	proto_tree_add_uint(bf_tree, hf_sna_nlp_opti_22_raa,
	    tvb, 2, 1, bits);
	proto_tree_add_boolean(bf_tree, hf_sna_nlp_opti_22_parity,
	    tvb, 2, 1, bits);
	proto_tree_add_uint(bf_tree, hf_sna_nlp_opti_22_arb,
	    tvb, 2, 1, bits);

	bits = tvb_get_guint8(tvb, 3);

	bf_item = proto_tree_add_uint(tree, hf_sna_nlp_opti_22_3,
	    tvb, 3, 1, bits);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_nlp_opti_22_3);

	proto_tree_add_uint(bf_tree, hf_sna_nlp_opti_22_ratereq,
	    tvb, 3, 1, bits);
	proto_tree_add_uint(bf_tree, hf_sna_nlp_opti_22_raterep,
	    tvb, 3, 1, bits);

	proto_tree_add_item(tree, hf_sna_nlp_opti_22_field1,
	    tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_sna_nlp_opti_22_field2,
	    tvb, 8, 4, ENC_BIG_ENDIAN);

	if (type == 0) {
		proto_tree_add_item(tree, hf_sna_nlp_opti_22_field3,
		    tvb, 12, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_sna_nlp_opti_22_field4,
		    tvb, 16, 4, ENC_BIG_ENDIAN);

		if (tvb_offset_exists(tvb, 20))
			call_dissector(data_handle,
			    tvb_new_subset_remaining(tvb, 20), pinfo, tree);
	} else {
		if (tvb_offset_exists(tvb, 12))
			call_dissector(data_handle,
			    tvb_new_subset_remaining(tvb, 12), pinfo, tree);
	}
}

static void
dissect_optional(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*sub_tree;
	proto_item	*sub_item;
	int		offset, type, len;
	gint		ett;

	sub_tree = NULL;

	offset = 0;

	while (tvb_offset_exists(tvb, offset)) {
		len = tvb_get_guint8(tvb, offset);
		type = tvb_get_guint8(tvb, offset+1);

		/* Prevent loop for invalid crap in packet */
		if (len == 0) {
			if (tree)
				call_dissector(data_handle,
				    tvb_new_subset_remaining(tvb, offset), pinfo, tree);
			return;
		}

		ett = ett_sna_nlp_opti_un;
		if(type == 0x0d) ett = ett_sna_nlp_opti_0d;
		if(type == 0x0e) ett = ett_sna_nlp_opti_0e;
		if(type == 0x0f) ett = ett_sna_nlp_opti_0f;
		if(type == 0x10) ett = ett_sna_nlp_opti_10;
		if(type == 0x12) ett = ett_sna_nlp_opti_12;
		if(type == 0x14) ett = ett_sna_nlp_opti_14;
		if(type == 0x22) ett = ett_sna_nlp_opti_22;
		if (tree) {
			sub_item = proto_tree_add_text(tree, tvb,
			    offset, len << 2, "%s",
			    val_to_str(type, sna_nlp_opti_vals,
			    "Unknown Segment Type"));
			sub_tree = proto_item_add_subtree(sub_item, ett);
			proto_tree_add_uint(sub_tree, hf_sna_nlp_opti_len,
			    tvb, offset, 1, len);
			proto_tree_add_uint(sub_tree, hf_sna_nlp_opti_type,
			    tvb, offset+1, 1, type);
		}
		switch(type) {
			case 0x0d:
				dissect_optional_0d(tvb_new_subset(tvb, offset,
				    len << 2, -1), sub_tree);
				break;
			case 0x0e:
				dissect_optional_0e(tvb_new_subset(tvb, offset,
				    len << 2, -1), pinfo, sub_tree);
				break;
			case 0x0f:
				dissect_optional_0f(tvb_new_subset(tvb, offset,
				    len << 2, -1), pinfo, sub_tree);
				break;
			case 0x10:
				dissect_optional_10(tvb_new_subset(tvb, offset,
				    len << 2, -1), pinfo, sub_tree);
				break;
			case 0x12:
				dissect_optional_12(tvb_new_subset(tvb, offset,
				    len << 2, -1), sub_tree);
				break;
			case 0x14:
				dissect_optional_14(tvb_new_subset(tvb, offset,
				    len << 2, -1), pinfo, sub_tree);
				break;
			case 0x22:
				dissect_optional_22(tvb_new_subset(tvb, offset,
				    len << 2, -1), pinfo, sub_tree);
				break;
			default:
				call_dissector(data_handle,
				    tvb_new_subset(tvb, offset,
				    len << 2, -1), pinfo, sub_tree);
		}
		offset += (len << 2);
	}
}

static void
dissect_nlp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_tree *parent_tree)
{
	proto_tree	*nlp_tree, *bf_tree;
	proto_item	*nlp_item, *bf_item;
	guint8		nhdr_0, nhdr_1, nhdr_x, thdr_8, thdr_9, fid;
	guint32		thdr_len, thdr_dlf;
	guint16		subindx;

	int indx = 0, counter = 0;

	nlp_tree = NULL;
	nlp_item = NULL;

	nhdr_0 = tvb_get_guint8(tvb, indx);
	nhdr_1 = tvb_get_guint8(tvb, indx+1);

	col_set_str(pinfo->cinfo, COL_INFO, "HPR NLP Packet");

	if (tree) {
		/* Don't bother setting length. We'll set it later after we
		 * find the lengths of NHDR */
		nlp_item = proto_tree_add_item(tree, hf_sna_nlp_nhdr, tvb,
		    indx, -1, ENC_NA);
		nlp_tree = proto_item_add_subtree(nlp_item, ett_sna_nlp_nhdr);

		bf_item = proto_tree_add_uint(nlp_tree, hf_sna_nlp_nhdr_0, tvb,
		    indx, 1, nhdr_0);
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_nlp_nhdr_0);

		proto_tree_add_uint(bf_tree, hf_sna_nlp_sm, tvb, indx, 1,
		    nhdr_0);
		proto_tree_add_uint(bf_tree, hf_sna_nlp_tpf, tvb, indx, 1,
		    nhdr_0);

		bf_item = proto_tree_add_uint(nlp_tree, hf_sna_nlp_nhdr_1, tvb,
		    indx+1, 1, nhdr_1);
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_nlp_nhdr_1);

		proto_tree_add_uint(bf_tree, hf_sna_nlp_ft, tvb,
		    indx+1, 1, nhdr_1);
		proto_tree_add_boolean(bf_tree, hf_sna_nlp_tspi, tvb,
		    indx+1, 1, nhdr_1);
		proto_tree_add_boolean(bf_tree, hf_sna_nlp_slowdn1, tvb,
		    indx+1, 1, nhdr_1);
		proto_tree_add_boolean(bf_tree, hf_sna_nlp_slowdn2, tvb,
		    indx+1, 1, nhdr_1);
	}
	/* ANR or FR lists */

	indx += 2;
	counter = 0;

	if ((nhdr_0 & 0xe0) == 0xa0) {
		do {
			nhdr_x = tvb_get_guint8(tvb, indx + counter);
			counter ++;
		} while (nhdr_x != 0xff);
		if (tree)
			proto_tree_add_item(nlp_tree,
			    hf_sna_nlp_fra, tvb, indx, counter, ENC_NA);
		indx += counter;
		if (tree)
			proto_tree_add_text(nlp_tree, tvb, indx, 1,
			    "Reserved");
		indx++;

		if (tree)
			proto_item_set_len(nlp_item, indx);

		if ((nhdr_1 & 0xf0) == 0x10) {
			nhdr_x = tvb_get_guint8(tvb, indx);
			if (tree)
				proto_tree_add_uint(tree, hf_sna_nlp_frh,
				    tvb, indx, 1, nhdr_x);
			indx ++;

			if (tvb_offset_exists(tvb, indx))
				call_dissector(data_handle,
					tvb_new_subset_remaining(tvb, indx),
					pinfo, parent_tree);
			return;
		}
	}
	if ((nhdr_0 & 0xe0) == 0xc0) {
		do {
			nhdr_x = tvb_get_guint8(tvb, indx + counter);
			counter ++;
		} while (nhdr_x != 0xff);
		if (tree)
			proto_tree_add_item(nlp_tree, hf_sna_nlp_anr,
			    tvb, indx, counter, ENC_NA);
		indx += counter;

		if (tree)
			proto_tree_add_text(nlp_tree, tvb, indx, 1,
			    "Reserved");
		indx++;

		if (tree)
			proto_item_set_len(nlp_item, indx);
	}

	thdr_8 = tvb_get_guint8(tvb, indx+8);
	thdr_9 = tvb_get_guint8(tvb, indx+9);
	thdr_len = tvb_get_ntohs(tvb, indx+10);
	thdr_dlf = tvb_get_ntohl(tvb, indx+12);

	if (tree) {
		nlp_item = proto_tree_add_item(tree, hf_sna_nlp_thdr, tvb,
		    indx, thdr_len << 2, ENC_NA);
		nlp_tree = proto_item_add_subtree(nlp_item, ett_sna_nlp_thdr);

		proto_tree_add_item(nlp_tree, hf_sna_nlp_tcid, tvb,
		    indx, 8, ENC_NA);
		bf_item = proto_tree_add_uint(nlp_tree, hf_sna_nlp_thdr_8, tvb,
		    indx+8, 1, thdr_8);
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_nlp_thdr_8);

		proto_tree_add_boolean(bf_tree, hf_sna_nlp_setupi, tvb,
		    indx+8, 1, thdr_8);
		proto_tree_add_boolean(bf_tree, hf_sna_nlp_somi, tvb, indx+8,
		    1, thdr_8);
		proto_tree_add_boolean(bf_tree, hf_sna_nlp_eomi, tvb, indx+8,
		    1, thdr_8);
		proto_tree_add_boolean(bf_tree, hf_sna_nlp_sri, tvb, indx+8,
		    1, thdr_8);
		proto_tree_add_boolean(bf_tree, hf_sna_nlp_rasapi, tvb,
		    indx+8, 1, thdr_8);
		proto_tree_add_boolean(bf_tree, hf_sna_nlp_retryi, tvb,
		    indx+8, 1, thdr_8);

		bf_item = proto_tree_add_uint(nlp_tree, hf_sna_nlp_thdr_9, tvb,
		    indx+9, 1, thdr_9);
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_nlp_thdr_9);

		proto_tree_add_boolean(bf_tree, hf_sna_nlp_lmi, tvb, indx+9,
		    1, thdr_9);
		proto_tree_add_boolean(bf_tree, hf_sna_nlp_cqfi, tvb, indx+9,
		    1, thdr_9);
		proto_tree_add_boolean(bf_tree, hf_sna_nlp_osi, tvb, indx+9,
		    1, thdr_9);

		proto_tree_add_uint(nlp_tree, hf_sna_nlp_offset, tvb, indx+10,
		    2, thdr_len);
		proto_tree_add_uint(nlp_tree, hf_sna_nlp_dlf, tvb, indx+12,
		    4, thdr_dlf);
		proto_tree_add_item(nlp_tree, hf_sna_nlp_bsn, tvb, indx+16,
		    4, ENC_BIG_ENDIAN);
	}
	subindx = 20;

	if (((thdr_9 & 0x18) == 0x08) && ((thdr_len << 2) > subindx)) {
		counter = tvb_get_guint8(tvb, indx + subindx);
		if (tvb_get_guint8(tvb, indx+subindx+1) == 5)
			dissect_control(tvb, indx + subindx, counter+2, nlp_tree, 1, LT);
		else
			call_dissector(data_handle,
			    tvb_new_subset(tvb, indx + subindx, counter+2,
			    -1), pinfo, nlp_tree);

		subindx += (counter+2);
	}
	if ((thdr_9 & 0x04) && ((thdr_len << 2) > subindx))
		dissect_optional(
		    tvb_new_subset(tvb, indx + subindx,
		    (thdr_len << 2) - subindx, -1),
		    pinfo, nlp_tree);

	indx += (thdr_len << 2);
	if (((thdr_8 & 0x20) == 0) && thdr_dlf) {
		col_set_str(pinfo->cinfo, COL_INFO, "HPR Fragment");
		if (tvb_offset_exists(tvb, indx)) {
			call_dissector(data_handle,
			    tvb_new_subset_remaining(tvb, indx), pinfo,
			    parent_tree);
		}
		return;
	}
	if (tvb_offset_exists(tvb, indx)) {
		/* Transmission Header Format Identifier */
		fid = hi_nibble(tvb_get_guint8(tvb, indx));
		if (fid == 5) /* Only FID5 allowed for HPR */
			dissect_fid(tvb_new_subset_remaining(tvb, indx), pinfo,
			    tree, parent_tree);
		else {
			if (tvb_get_ntohs(tvb, indx+2) == 0x12ce) {
				/* Route Setup */
				col_set_str(pinfo->cinfo, COL_INFO, "HPR Route Setup");
				dissect_gds(tvb_new_subset_remaining(tvb, indx),
				    pinfo, tree, parent_tree);
			} else
				call_dissector(data_handle,
				    tvb_new_subset_remaining(tvb, indx),
				    pinfo, parent_tree);
		}
	}
}

/* --------------------------------------------------------------------
 * Chapter 3 Exchange Identification (XID) Information Fields
 * --------------------------------------------------------------------
 */

static void
dissect_xid1(tvbuff_t *tvb, proto_tree *tree)
{
	if (!tree)
		return;

	proto_tree_add_text(tree, tvb, 0, 2, "Reserved");

}

static void
dissect_xid2(tvbuff_t *tvb, proto_tree *tree)
{
	guint		dlen, offset;

	if (!tree)
		return;

	dlen = tvb_get_guint8(tvb, 0);

	offset = dlen;

	while (tvb_offset_exists(tvb, offset)) {
		dlen = tvb_get_guint8(tvb, offset+1);
		dissect_control(tvb, offset, dlen+2, tree, 0, KL);
		offset += (dlen + 2);
	}
}

static void
dissect_xid3(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree	*sub_tree;
	proto_item	*sub_ti = NULL;
	guint		val, dlen, offset;

	if (!tree)
		return;

	proto_tree_add_text(tree, tvb, 0, 2, "Reserved");

	val = tvb_get_ntohs(tvb, 2);

	sub_ti = proto_tree_add_uint(tree, hf_sna_xid_3_8, tvb,
	    2, 2, val);
	sub_tree = proto_item_add_subtree(sub_ti, ett_sna_xid_3_8);

	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_init_self, tvb, 2, 2,
	    val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_stand_bind, tvb, 2, 2,
	    val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_gener_bind, tvb, 2, 2,
	    val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_recve_bind, tvb, 2, 2,
	    val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_actpu, tvb, 2, 2, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_nwnode, tvb, 2, 2, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_cp, tvb, 2, 2, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_cpcp, tvb, 2, 2, val);
	proto_tree_add_uint(sub_tree, hf_sna_xid_3_state, tvb, 2, 2, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_nonact, tvb, 2, 2, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_cpchange, tvb, 2, 2,
	    val);

	val = tvb_get_guint8(tvb, 4);

	sub_ti = proto_tree_add_uint(tree, hf_sna_xid_3_10, tvb,
	    4, 1, val);
	sub_tree = proto_item_add_subtree(sub_ti, ett_sna_xid_3_10);

	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_asend_bind, tvb, 4, 1,
	    val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_arecv_bind, tvb, 4, 1,
	    val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_quiesce, tvb, 4, 1, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_pucap, tvb, 4, 1, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_pbn, tvb, 4, 1, val);
	proto_tree_add_uint(sub_tree, hf_sna_xid_3_pacing, tvb, 4, 1, val);

	val = tvb_get_guint8(tvb, 5);

	sub_ti = proto_tree_add_uint(tree, hf_sna_xid_3_11, tvb,
	    5, 1, val);
	sub_tree = proto_item_add_subtree(sub_ti, ett_sna_xid_3_11);

	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_tgshare, tvb, 5, 1, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_dedsvc, tvb, 5, 1, val);

	val = tvb_get_guint8(tvb, 6);

	sub_ti = proto_tree_add_item(tree, hf_sna_xid_3_12, tvb,
	    6, 1, ENC_BIG_ENDIAN);
	sub_tree = proto_item_add_subtree(sub_ti, ett_sna_xid_3_12);

	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_negcsup, tvb, 6, 1, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_negcomp, tvb, 6, 1, val);

	proto_tree_add_text(tree, tvb, 7, 2, "Reserved");

	val = tvb_get_guint8(tvb, 9);

	sub_ti = proto_tree_add_item(tree, hf_sna_xid_3_15, tvb,
	    9, 1, ENC_BIG_ENDIAN);
	sub_tree = proto_item_add_subtree(sub_ti, ett_sna_xid_3_15);

	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_partg, tvb, 9, 1, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_dlur, tvb, 9, 1, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_dlus, tvb, 9, 1, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_exbn, tvb, 9, 1, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_genodai, tvb, 9, 1, val);
	proto_tree_add_uint(sub_tree, hf_sna_xid_3_branch, tvb, 9, 1, val);
	proto_tree_add_boolean(sub_tree, hf_sna_xid_3_brnn, tvb, 9, 1, val);

	proto_tree_add_item(tree, hf_sna_xid_3_tg, tvb, 10, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_sna_xid_3_dlc, tvb, 11, 1, ENC_BIG_ENDIAN);

	dlen = tvb_get_guint8(tvb, 12);

	proto_tree_add_uint(tree, hf_sna_xid_3_dlen, tvb, 12, 1, dlen);

	/* FIXME: DLC Dependent Data Go Here */

	offset = 12 + dlen;

	while (tvb_offset_exists(tvb, offset)) {
		dlen = tvb_get_guint8(tvb, offset+1);
		dissect_control(tvb, offset, dlen+2, tree, 0, KL);
		offset += (dlen+2);
	}
}

static void
dissect_xid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_tree *parent_tree)
{
	proto_tree	*sub_tree;
	proto_item	*sub_ti = NULL;
	int		format, type, len;
	guint32		id;

	len = tvb_get_guint8(tvb, 1);
	type = tvb_get_guint8(tvb, 0);
	id = tvb_get_ntohl(tvb, 2);
	format = hi_nibble(type);

	/* Summary information */
	col_add_fstr(pinfo->cinfo, COL_INFO,
		    "SNA XID Format:%d Type:%s", format,
		    val_to_str_const(lo_nibble(type), sna_xid_type_vals,
		    "Unknown Type"));

	if (tree) {
		sub_ti = proto_tree_add_item(tree, hf_sna_xid_0, tvb,
		    0, 1, ENC_BIG_ENDIAN);
		sub_tree = proto_item_add_subtree(sub_ti, ett_sna_xid_0);

		proto_tree_add_uint(sub_tree, hf_sna_xid_format, tvb, 0, 1,
		    type);
		proto_tree_add_uint(sub_tree, hf_sna_xid_type, tvb, 0, 1,
		    type);

		proto_tree_add_uint(tree, hf_sna_xid_len, tvb, 1, 1, len);

		sub_ti = proto_tree_add_item(tree, hf_sna_xid_id, tvb,
		    2, 4, ENC_BIG_ENDIAN);
		sub_tree = proto_item_add_subtree(sub_ti, ett_sna_xid_id);

		proto_tree_add_uint(sub_tree, hf_sna_xid_idblock, tvb, 2, 4,
		    id);
		proto_tree_add_uint(sub_tree, hf_sna_xid_idnum, tvb, 2, 4,
		    id);

		switch(format) {
			case 0:
				break;
			case 1:
				dissect_xid1(tvb_new_subset(tvb, 6, len-6, -1),
				    tree);
				break;
			case 2:
				dissect_xid2(tvb_new_subset(tvb, 6, len-6, -1),
				    tree);
				break;
			case 3:
				dissect_xid3(tvb_new_subset(tvb, 6, len-6, -1),
				    tree);
				break;
			default:
				/* external standards organizations */
				call_dissector(data_handle,
				    tvb_new_subset(tvb, 6, len-6, -1),
				    pinfo, tree);
		}
	}

	if (format == 0)
		len = 6;

	if (tvb_offset_exists(tvb, len))
		call_dissector(data_handle,
		    tvb_new_subset_remaining(tvb, len), pinfo, parent_tree);
}

/* --------------------------------------------------------------------
 * Chapter 4 Transmission Headers (THs)
 * --------------------------------------------------------------------
 */

#define RH_LEN	3

static unsigned int
mpf_value(guint8 th_byte)
{
	return (th_byte & 0x0c) >> 2;
}

#define FIRST_FRAG_NUMBER	0
#define MIDDLE_FRAG_NUMBER	1
#define LAST_FRAG_NUMBER	2

/* FID2 is defragged by sequence. The weird thing is that we have neither
 * absolute sequence numbers, nor byte offets. Other FIDs have byte offsets
 * (the DCF field), but not FID2. The only thing we have to go with is "FIRST",
 * "MIDDLE", or "LAST". If the BIU is split into 3 frames, then everything is
 * fine, * "FIRST", "MIDDLE", and "LAST" map nicely onto frag-number 0, 1,
 * and 2. However, if the BIU is split into 2 frames, then we only have
 * "FIRST" and "LAST", and the mapping *should* be frag-number 0 and 1,
 * *NOT* 0 and 2.
 *
 * The SNA docs say "FID2 PIUs cannot be blocked because there is no DCF in the
 * TH format for deblocking" (note on Figure 4-2 in the IBM SNA documention,
 * see the FTP URL in the comment near the top of this file). I *think*
 * this means that the fragmented frames cannot arrive out of order.
 * Well, I *want* it to mean this, because w/o this limitation, if you
 * get a "FIRST" frame and a "LAST" frame, how long should you wait to
 * see if a "MIDDLE" frame every arrives????? Thus, if frames *have* to
 * arrive in order, then we're saved.
 *
 * The problem then boils down to figuring out if "LAST" means frag-number 1
 * (in the case of a BIU split into 2 frames) or frag-number 2
 * (in the case of a BIU split into 3 frames).
 *
 * Assuming fragmented FID2 BIU frames *do* arrive in order, the obvious
 * way to handle the mapping of "LAST" to either frag-number 1 or
 * frag-number 2 is to keep a hash which tracks the frames seen, etc.
 * This consumes resources. A trickier way, but a way which works, is to
 * always map the "LAST" BIU segment to frag-number 2. Here's the trickery:
 * if we add frag-number 2, which we know to be the "LAST" BIU segment,
 * and the reassembly code tells us that the the BIU is still not reassmebled,
 * then, owing to the, ahem, /fact/, that fragmented BIU segments arrive
 * in order :), we know that 1) "FIRST" did come, and 2) there's no "MIDDLE",
 * because this BIU was fragmented into 2 frames, not 3. So, we'll be
 * tricky and add a zero-length "MIDDLE" BIU frame (i.e, frag-number 1)
 * to complete the reassembly.
 */
static tvbuff_t*
defragment_by_sequence(packet_info *pinfo, tvbuff_t *tvb, int offset, int mpf,
    int id)
{
	fragment_head *fd_head;
	int frag_number = -1;
	int more_frags = TRUE;
	tvbuff_t *rh_tvb = NULL;
	gint frag_len;

	/* Determine frag_number and more_frags */
	switch(mpf) {
		case MPF_WHOLE_BIU:
			/* nothing */
			break;
		case MPF_FIRST_SEGMENT:
			frag_number = FIRST_FRAG_NUMBER;
			break;
		case MPF_MIDDLE_SEGMENT:
			frag_number = MIDDLE_FRAG_NUMBER;
			break;
		case MPF_LAST_SEGMENT:
			frag_number = LAST_FRAG_NUMBER;
			more_frags = FALSE;
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
	}

	/* If sna_defragment is on, and this is a fragment.. */
	if (frag_number > -1) {
		/* XXX - check length ??? */
		frag_len = tvb_reported_length_remaining(tvb, offset);
		if (tvb_bytes_exist(tvb, offset, frag_len)) {
			fd_head = fragment_add_seq(&sna_reassembly_table,
			    tvb, offset, pinfo, id, NULL,
			    frag_number, frag_len, more_frags, 0);

			/* We added the LAST segment and reassembly didn't
			 * complete. Insert a zero-length MIDDLE segment to
			 * turn a 2-frame BIU-fragmentation into a 3-frame
			 * BIU-fragmentation (empty middle frag).
		         * See above long comment about this trickery. */

			if (mpf == MPF_LAST_SEGMENT && !fd_head) {
				fd_head = fragment_add_seq(&sna_reassembly_table,
				    tvb, offset, pinfo, id, NULL,
				    MIDDLE_FRAG_NUMBER, 0, TRUE, 0);
			}

			if (fd_head != NULL) {
				/* We have the complete reassembled payload. */
				rh_tvb = tvb_new_chain(tvb, fd_head->tvb_data);

				/* Add the defragmented data to the data
				 * source list. */
				add_new_data_source(pinfo, rh_tvb,
				    "Reassembled SNA BIU");
			}
		}
	}
	return rh_tvb;
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
		bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, 0, 1,
		    th_0);
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb, 0, 1, th_0);
		proto_tree_add_uint(bf_tree, hf_sna_th_mpf, tvb, 0, 1, th_0);
		proto_tree_add_uint(bf_tree, hf_sna_th_efi, tvb, 0, 1, th_0);

		/* Byte 1 */
		proto_tree_add_text(tree, tvb, 1, 1, "Reserved");

		/* Bytes 2-3 */
		proto_tree_add_item(tree, hf_sna_th_daf, tvb, 2, 2, ENC_BIG_ENDIAN);
	}

	/* Set DST addr */
	ptr = tvb_get_ptr(tvb, 2, SNA_FID01_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_dst, AT_SNA, SNA_FID01_ADDR_LEN, ptr);
	SET_ADDRESS(&pinfo->dst, AT_SNA, SNA_FID01_ADDR_LEN, ptr);

	if (tree)
		proto_tree_add_item(tree, hf_sna_th_oaf, tvb, 4, 2, ENC_BIG_ENDIAN);

	/* Set SRC addr */
	ptr = tvb_get_ptr(tvb, 4, SNA_FID01_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_src, AT_SNA, SNA_FID01_ADDR_LEN, ptr);
	SET_ADDRESS(&pinfo->src, AT_SNA, SNA_FID01_ADDR_LEN, ptr);

	/* If we're not filling a proto_tree, return now */
	if (tree)
		return bytes_in_header;

	proto_tree_add_item(tree, hf_sna_th_snf, tvb, 6, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_sna_th_dcf, tvb, 8, 2, ENC_BIG_ENDIAN);

	return bytes_in_header;
}

#define SNA_FID2_ADDR_LEN	1

/* FID Type 2 */
static int
dissect_fid2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        tvbuff_t **rh_tvb_ptr, next_dissection_t *continue_dissecting)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		th_0;
	const guint8	*ptr;
	unsigned int	mpf, id;

	const int bytes_in_header = 6;

	th_0 = tvb_get_guint8(tvb, 0);
	mpf = mpf_value(th_0);

	if (tree) {

		/* Byte 0 */
		bf_item = proto_tree_add_item(tree, hf_sna_th_0, tvb, 0, 1, ENC_NA);
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

		proto_tree_add_item(bf_tree, hf_sna_th_fid, tvb, 0, 1, ENC_NA);
		proto_tree_add_item(bf_tree, hf_sna_th_mpf, tvb, 0, 1, ENC_NA);
		proto_tree_add_item(bf_tree, hf_sna_th_odai,tvb, 0, 1, ENC_NA);
		proto_tree_add_item(bf_tree, hf_sna_th_efi, tvb, 0, 1, ENC_NA);


		/* Byte 1 */
		proto_tree_add_text(tree, tvb, 1, 1, "Reserved");

		/* Byte 2 */
		proto_tree_add_item(tree, hf_sna_th_daf, tvb, 2, 1, ENC_NA);
	}

	/* Set DST addr */
	ptr = tvb_get_ptr(tvb, 2, SNA_FID2_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_dst, AT_SNA, SNA_FID2_ADDR_LEN, ptr);
	SET_ADDRESS(&pinfo->dst, AT_SNA, SNA_FID2_ADDR_LEN, ptr);

	/* Byte 3 */
	proto_tree_add_item(tree, hf_sna_th_oaf, tvb, 3, 1, ENC_NA);

	/* Set SRC addr */
	ptr = tvb_get_ptr(tvb, 3, SNA_FID2_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_src, AT_SNA, SNA_FID2_ADDR_LEN, ptr);
	SET_ADDRESS(&pinfo->src, AT_SNA, SNA_FID2_ADDR_LEN, ptr);

	id = tvb_get_ntohs(tvb, 4);
	proto_tree_add_item(tree, hf_sna_th_snf, tvb, 4, 2, ENC_BIG_ENDIAN);

	if (mpf != MPF_WHOLE_BIU && !sna_defragment) {
		if (mpf == MPF_FIRST_SEGMENT) {
			*continue_dissecting = rh_only;
			} else {
			*continue_dissecting = stop_here;
			}

		}
	else if (sna_defragment) {
		*rh_tvb_ptr = defragment_by_sequence(pinfo, tvb,
		    bytes_in_header, mpf, id);
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
	if (!tree)
		return bytes_in_header;

	th_0 = tvb_get_guint8(tvb, 0);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, 0, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb, 0, 1, th_0);
	proto_tree_add_uint(bf_tree, hf_sna_th_mpf, tvb, 0, 1, th_0);
	proto_tree_add_uint(bf_tree, hf_sna_th_efi, tvb, 0, 1, th_0);

	proto_tree_add_item(tree, hf_sna_th_lsid, tvb, 1, 1, ENC_BIG_ENDIAN);

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
	static struct sna_fid_type_4_addr src, dst; /* has to be static due to SET_ADDRESS */

	const int bytes_in_header = 26;

	/* If we're not filling a proto_tree, return now */
	if (!tree)
		return bytes_in_header;

	th_byte = tvb_get_guint8(tvb, offset);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, offset,
	    1, th_byte);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	/* Byte 0 */
	proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb,
	    offset, 1, th_byte);
	proto_tree_add_uint(bf_tree, hf_sna_th_tg_sweep, tvb,
	    offset, 1, th_byte);
	proto_tree_add_uint(bf_tree, hf_sna_th_er_vr_supp_ind, tvb,
	    offset, 1, th_byte);
	proto_tree_add_uint(bf_tree, hf_sna_th_vr_pac_cnt_ind, tvb,
	    offset, 1, th_byte);
	proto_tree_add_uint(bf_tree, hf_sna_th_ntwk_prty, tvb,
	    offset, 1, th_byte);

	offset += 1;
	th_byte = tvb_get_guint8(tvb, offset);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, tvb, offset, 1,
	    "Transmission Header Byte 1");
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	/* Byte 1 */
	proto_tree_add_uint(bf_tree, hf_sna_th_tgsf, tvb, offset, 1,
	    th_byte);
	proto_tree_add_boolean(bf_tree, hf_sna_th_mft, tvb, offset, 1,
	    th_byte);
	proto_tree_add_uint(bf_tree, hf_sna_th_piubf, tvb, offset, 1,
	    th_byte);

	mft = th_byte & 0x04;
	offset += 1;
	th_byte = tvb_get_guint8(tvb, offset);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, tvb, offset, 1,
	    "Transmission Header Byte 2");
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	/* Byte 2 */
	if (mft) {
		proto_tree_add_uint(bf_tree, hf_sna_th_nlpoi, tvb,
		    offset, 1, th_byte);
		proto_tree_add_uint(bf_tree, hf_sna_th_nlp_cp, tvb,
		    offset, 1, th_byte);
	} else {
		proto_tree_add_uint(bf_tree, hf_sna_th_iern, tvb,
		    offset, 1, th_byte);
	}
	proto_tree_add_uint(bf_tree, hf_sna_th_ern, tvb, offset, 1,
	    th_byte);

	offset += 1;
	th_byte = tvb_get_guint8(tvb, offset);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, tvb, offset, 1,
	    "Transmission Header Byte 3");
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	/* Byte 3 */
	proto_tree_add_uint(bf_tree, hf_sna_th_vrn, tvb, offset, 1,
	    th_byte);
	proto_tree_add_uint(bf_tree, hf_sna_th_tpf, tvb, offset, 1,
	    th_byte);

	offset += 1;
	th_word = tvb_get_ntohs(tvb, offset);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, tvb, offset, 2,
	    "Transmission Header Bytes 4-5");
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	/* Bytes 4-5 */
	proto_tree_add_uint(bf_tree, hf_sna_th_vr_cwi, tvb,
	    offset, 2, th_word);
	proto_tree_add_boolean(bf_tree, hf_sna_th_tg_nonfifo_ind, tvb,
	    offset, 2, th_word);
	proto_tree_add_uint(bf_tree, hf_sna_th_vr_sqti, tvb,
	    offset, 2, th_word);

	/* I'm not sure about byte-order on this one... */
	proto_tree_add_uint(bf_tree, hf_sna_th_tg_snf, tvb,
	    offset, 2, th_word);

	offset += 2;
	th_word = tvb_get_ntohs(tvb, offset);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, tvb, offset, 2,
	    "Transmission Header Bytes 6-7");
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	/* Bytes 6-7 */
	proto_tree_add_boolean(bf_tree, hf_sna_th_vrprq, tvb, offset,
	    2, th_word);
	proto_tree_add_boolean(bf_tree, hf_sna_th_vrprs, tvb, offset,
	    2, th_word);
	proto_tree_add_uint(bf_tree, hf_sna_th_vr_cwri, tvb, offset,
	    2, th_word);
	proto_tree_add_boolean(bf_tree, hf_sna_th_vr_rwi, tvb, offset,
	    2, th_word);

	/* I'm not sure about byte-order on this one... */
	proto_tree_add_uint(bf_tree, hf_sna_th_vr_snf_send, tvb,
	    offset, 2, th_word);

	offset += 2;

	dsaf = tvb_get_ntohl(tvb, 8);
	/* Bytes 8-11 */
	proto_tree_add_uint(tree, hf_sna_th_dsaf, tvb, offset, 4, dsaf);

	offset += 4;

	osaf = tvb_get_ntohl(tvb, 12);
	/* Bytes 12-15 */
	proto_tree_add_uint(tree, hf_sna_th_osaf, tvb, offset, 4, osaf);

	offset += 4;
	th_byte = tvb_get_guint8(tvb, offset);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_text(tree, tvb, offset, 2,
	    "Transmission Header Byte 16");
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	/* Byte 16 */
	proto_tree_add_boolean(bf_tree, hf_sna_th_snai, tvb, offset, 1, th_byte);

	/* We luck out here because in their infinite wisdom the SNA
	 * architects placed the MPF and EFI fields in the same bitfield
	 * locations, even though for FID4 they're not in byte 0.
	 * Thank you IBM! */
	proto_tree_add_uint(bf_tree, hf_sna_th_mpf, tvb, offset, 1, th_byte);
	proto_tree_add_uint(bf_tree, hf_sna_th_efi, tvb, offset, 1, th_byte);

	offset += 2;
	/* 1 for byte 16, 1 for byte 17 which is reserved */

	def = tvb_get_ntohs(tvb, 18);
	/* Bytes 18-25 */
	proto_tree_add_uint(tree, hf_sna_th_def, tvb, offset, 2, def);

	/* Addresses in FID 4 are discontiguous, sigh */
	dst.saf = dsaf;
	dst.ef = def;
	SET_ADDRESS(&pinfo->net_dst, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN,
	    (guint8* )&dst);
	SET_ADDRESS(&pinfo->dst, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN,
	    (guint8 *)&dst);

	oef = tvb_get_ntohs(tvb, 20);
	proto_tree_add_uint(tree, hf_sna_th_oef, tvb, offset+2, 2, oef);

	/* Addresses in FID 4 are discontiguous, sigh */
	src.saf = osaf;
	src.ef = oef;
	SET_ADDRESS(&pinfo->net_src, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN,
	    (guint8 *)&src);
	SET_ADDRESS(&pinfo->src, AT_SNA, SNA_FID_TYPE_4_ADDR_LEN,
	    (guint8 *)&src);

	proto_tree_add_item(tree, hf_sna_th_snf, tvb, offset+4, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_sna_th_dcf, tvb, offset+6, 2, ENC_BIG_ENDIAN);

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
	if (!tree)
		return bytes_in_header;

	th_0 = tvb_get_guint8(tvb, 0);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, 0, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb, 0, 1, th_0);
	proto_tree_add_uint(bf_tree, hf_sna_th_mpf, tvb, 0, 1, th_0);
	proto_tree_add_uint(bf_tree, hf_sna_th_efi, tvb, 0, 1, th_0);

	proto_tree_add_text(tree, tvb, 1, 1, "Reserved");
	proto_tree_add_item(tree, hf_sna_th_snf, tvb, 2, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_sna_th_sa, tvb, 4, 8, ENC_NA);

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
	if (!tree)
		return bytes_in_header;

	th_0 = tvb_get_guint8(tvb, 0);

	/* Create the bitfield tree */
	bf_item = proto_tree_add_uint(tree, hf_sna_th_0, tvb, 0, 1, th_0);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_th_fid);

	proto_tree_add_uint(bf_tree, hf_sna_th_fid, tvb, 0, 1, th_0);
	proto_tree_add_text(tree, tvb, 1, 1, "Reserved");

	proto_tree_add_item(tree, hf_sna_th_cmd_fmt, tvb,  2, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_sna_th_cmd_type, tvb, 3, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_sna_th_cmd_sn, tvb,   4, 2, ENC_BIG_ENDIAN);

	/* Yup, bytes 6-23 are reserved! */
	proto_tree_add_text(tree, tvb, 6, 18, "Reserved");

	proto_tree_add_item(tree, hf_sna_th_dcf, tvb, 24, 2, ENC_BIG_ENDIAN);

	return bytes_in_header;
}

static void
dissect_fid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_tree *parent_tree)
{

	proto_tree	*th_tree = NULL, *rh_tree = NULL;
	proto_item	*th_ti = NULL, *rh_ti = NULL;
	guint8		th_fid;
	int		th_header_len = 0;
	int		offset, rh_offset;
	tvbuff_t	*rh_tvb = NULL;
	next_dissection_t continue_dissecting = everything;

	/* Transmission Header Format Identifier */
	th_fid = hi_nibble(tvb_get_guint8(tvb, 0));

	/* Summary information */
	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(th_fid, sna_th_fid_vals, "Unknown FID: %01x"));

	if (tree) {
		/* --- TH --- */
		/* Don't bother setting length. We'll set it later after we
		 * find the length of TH */
		th_ti = proto_tree_add_item(tree, hf_sna_th, tvb,  0, -1,
		    ENC_NA);
		th_tree = proto_item_add_subtree(th_ti, ett_sna_th);
	}

	/* Get size of TH */
	switch(th_fid) {
		case 0x0:
		case 0x1:
			th_header_len = dissect_fid0_1(tvb, pinfo, th_tree);
			break;
		case 0x2:
			th_header_len = dissect_fid2(tvb, pinfo, th_tree,
			    &rh_tvb, &continue_dissecting);
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
			call_dissector(data_handle,
			    tvb_new_subset_remaining(tvb, 1), pinfo, parent_tree);
			return;
	}

	offset = th_header_len;

	/* Short-circuit ? */
	if (continue_dissecting == stop_here) {
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, -1,
			    "BIU segment data");
		}
		return;
	}

	/* If the FID dissector function didn't create an rh_tvb, then we just
	 * use the rest of our tvbuff as the rh_tvb. */
	if (!rh_tvb)
		rh_tvb = tvb_new_subset_remaining(tvb, offset);
	rh_offset = 0;

	/* Process the rest of the SNA packet, starting with RH */
	if (tree) {
		proto_item_set_len(th_ti, th_header_len);

		/* --- RH --- */
		rh_ti = proto_tree_add_item(tree, hf_sna_rh, rh_tvb, rh_offset,
		    RH_LEN, ENC_NA);
		rh_tree = proto_item_add_subtree(rh_ti, ett_sna_rh);
		dissect_rh(rh_tvb, rh_offset, rh_tree);
	}

	rh_offset += RH_LEN;

	if (tvb_offset_exists(rh_tvb, rh_offset)) {
		/* Short-circuit ? */
		if (continue_dissecting == rh_only) {
			if (tree)
				proto_tree_add_text(tree, rh_tvb, rh_offset, -1,
				    "BIU segment data");
			return;
        	}

		call_dissector(data_handle,
		    tvb_new_subset_remaining(rh_tvb, rh_offset),
		    pinfo, parent_tree);
	}
}

/* --------------------------------------------------------------------
 * Chapter 5 Request/Response Headers (RHs)
 * --------------------------------------------------------------------
 */

static void
dissect_rh(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	gboolean	is_response;
	guint8		rh_0, rh_1, rh_2;

	if (!tree)
		return;

	/* Create the bitfield tree for byte 0*/
	rh_0 = tvb_get_guint8(tvb, offset);
	is_response = (rh_0 & 0x80);

	bf_item = proto_tree_add_uint(tree, hf_sna_rh_0, tvb, offset, 1, rh_0);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_rh_0);

	proto_tree_add_uint(bf_tree, hf_sna_rh_rri, tvb, offset, 1, rh_0);
	proto_tree_add_uint(bf_tree, hf_sna_rh_ru_category, tvb, offset, 1,
	    rh_0);
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

	if (!is_response)
		proto_tree_add_boolean(bf_tree, hf_sna_rh_lcci, tvb, offset, 1,
		    rh_1);

	proto_tree_add_boolean(bf_tree, hf_sna_rh_dr2, tvb,  offset, 1, rh_1);

	if (is_response) {
		proto_tree_add_boolean(bf_tree, hf_sna_rh_rti, tvb,  offset, 1,
		    rh_1);
	} else {
		proto_tree_add_boolean(bf_tree, hf_sna_rh_eri, tvb,  offset, 1,
		    rh_1);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_rlwi, tvb, offset, 1,
		    rh_1);
	}

	proto_tree_add_boolean(bf_tree, hf_sna_rh_qri, tvb, offset, 1, rh_1);
	proto_tree_add_boolean(bf_tree, hf_sna_rh_pi, tvb,  offset, 1, rh_1);

	offset += 1;
	rh_2 = tvb_get_guint8(tvb, offset);

	/* Create the bitfield tree for byte 2*/
	bf_item = proto_tree_add_uint(tree, hf_sna_rh_2, tvb, offset, 1, rh_2);

	if (!is_response) {
		bf_tree = proto_item_add_subtree(bf_item, ett_sna_rh_2);

		proto_tree_add_boolean(bf_tree, hf_sna_rh_bbi, tvb,  offset, 1,
		    rh_2);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_ebi, tvb,  offset, 1,
		    rh_2);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_cdi, tvb,  offset, 1,
		    rh_2);
		proto_tree_add_uint(bf_tree, hf_sna_rh_csi, tvb,  offset, 1,
		    rh_2);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_edi, tvb,  offset, 1,
		    rh_2);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_pdi, tvb,  offset, 1,
		    rh_2);
		proto_tree_add_boolean(bf_tree, hf_sna_rh_cebi, tvb, offset, 1,
		    rh_2);
	}

	/* XXX - check for sdi. If TRUE, the next 4 bytes will be sense data */
}

/* --------------------------------------------------------------------
 * Chapter 6 Request/Response Units (RUs)
 * --------------------------------------------------------------------
 */

/* --------------------------------------------------------------------
 * Chapter 9 Common Fields
 * --------------------------------------------------------------------
 */

static void
dissect_control_05hpr(tvbuff_t *tvb, proto_tree *tree, int hpr,
    enum parse parse)
{
	proto_tree	*bf_tree;
	proto_item	*bf_item;
	guint8		type;
	guint16		offset, len, pad;

	if (!tree)
		return;

	type = tvb_get_guint8(tvb, 2);

	bf_item = proto_tree_add_uint(tree, hf_sna_control_05_type, tvb,
	    2, 1, type);
	bf_tree = proto_item_add_subtree(bf_item, ett_sna_control_05hpr_type);

	proto_tree_add_boolean(bf_tree, hf_sna_control_05_ptp, tvb, 2, 1, type);
	proto_tree_add_text(tree, tvb, 3, 1, "Reserved");

	offset = 4;

	while (tvb_offset_exists(tvb, offset)) {
		if (parse == LT) {
			len = tvb_get_guint8(tvb, offset+0);
		} else {
			len = tvb_get_guint8(tvb, offset+1);
		}
		if (len) {
			dissect_control(tvb, offset, len, tree, hpr, parse);
			pad = (len+3) & 0xfffc;
            if (pad > len) {
                /* XXX - fix this, ensure tvb is large enough for pad */
                tvb_ensure_bytes_exist(tvb, offset+len, pad-len);
				proto_tree_add_text(tree, tvb, offset+len,
				    pad-len, "Padding");
            }
			offset += pad;
		} else {
			return;
		}
	}
}

static void
dissect_control_05(tvbuff_t *tvb, proto_tree *tree)
{
	if(!tree)
		return;

	proto_tree_add_item(tree, hf_sna_control_05_delay, tvb, 2, 2, ENC_BIG_ENDIAN);
}

static void
dissect_control_0e(tvbuff_t *tvb, proto_tree *tree)
{
	gint	len;

	if (!tree)
		return;

	proto_tree_add_item(tree, hf_sna_control_0e_type, tvb, 2, 1, ENC_BIG_ENDIAN);

	len = tvb_reported_length_remaining(tvb, 3);
	if (len <= 0)
		return;

	proto_tree_add_item(tree, hf_sna_control_0e_value, tvb, 3, len, ENC_EBCDIC|ENC_NA);
}

static void
dissect_control(tvbuff_t *parent_tvb, int offset, int control_len,
    proto_tree *tree, int hpr, enum parse parse)
{
	tvbuff_t	*tvb;
	gint		length, reported_length;
	proto_tree	*sub_tree;
	proto_item	*sub_item;
	int		len, key;
	gint		ett;

	length = tvb_length_remaining(parent_tvb, offset);
	reported_length = tvb_reported_length_remaining(parent_tvb, offset);
	if (control_len < length)
		length = control_len;
	if (control_len < reported_length)
		reported_length = control_len;
	tvb = tvb_new_subset(parent_tvb, offset, length, reported_length);

	sub_tree = NULL;

	if (parse == LT) {
		len = tvb_get_guint8(tvb, 0);
		key = tvb_get_guint8(tvb, 1);
	} else {
		key = tvb_get_guint8(tvb, 0);
		len = tvb_get_guint8(tvb, 1);
	}
	ett = ett_sna_control_un;

	if (tree) {
		if (key == 5) {
			 if (hpr) ett = ett_sna_control_05hpr;
			 else ett = ett_sna_control_05;
		}
		if (key == 0x0e) ett = ett_sna_control_0e;

		if (((key == 0) || (key == 3) || (key == 5)) && hpr)
			sub_item = proto_tree_add_text(tree, tvb, 0, -1, "%s",
			    val_to_str_const(key, sna_control_hpr_vals,
			    "Unknown Control Vector"));
		else
			sub_item = proto_tree_add_text(tree, tvb, 0, -1, "%s",
			    val_to_str_const(key, sna_control_vals,
			    "Unknown Control Vector"));
		sub_tree = proto_item_add_subtree(sub_item, ett);
		if (parse == LT) {
			proto_tree_add_uint(sub_tree, hf_sna_control_len,
			    tvb, 0, 1, len);
			if (((key == 0) || (key == 3) || (key == 5)) && hpr)
				proto_tree_add_uint(sub_tree,
				    hf_sna_control_hprkey, tvb, 1, 1, key);
			else
				proto_tree_add_uint(sub_tree,
				    hf_sna_control_key, tvb, 1, 1, key);
		} else {
			if (((key == 0) || (key == 3) || (key == 5)) && hpr)
				proto_tree_add_uint(sub_tree,
				    hf_sna_control_hprkey, tvb, 0, 1, key);
			else
				proto_tree_add_uint(sub_tree,
				    hf_sna_control_key, tvb, 0, 1, key);
			proto_tree_add_uint(sub_tree, hf_sna_control_len,
			    tvb, 1, 1, len);
		}
	}
	switch(key) {
		case 0x05:
			if (hpr)
				dissect_control_05hpr(tvb, sub_tree, hpr,
				    parse);
			else
				dissect_control_05(tvb, sub_tree);
			break;
		case 0x0e:
			dissect_control_0e(tvb, sub_tree);
			break;
	}
}

/* --------------------------------------------------------------------
 * Chapter 11 Function Management (FM) Headers
 * --------------------------------------------------------------------
 */

/* --------------------------------------------------------------------
 * Chapter 12 Presentation Services (PS) Headers
 * --------------------------------------------------------------------
 */

/* --------------------------------------------------------------------
 * Chapter 13 GDS Variables
 * --------------------------------------------------------------------
 */

static void
dissect_gds(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_tree *parent_tree)
{
	guint16		length;
	guint16		type;
	int		cont;
	int		offset = 0;
	proto_tree	*gds_tree;
	proto_item	*gds_item;

	do {
		length = tvb_get_ntohs(tvb, offset) & 0x7fff;
		cont   = (tvb_get_ntohs(tvb, offset) & 0x8000) ? 1 : 0;
		type   = tvb_get_ntohs(tvb, offset+2);

		if (length < 2 ) /* escape sequence ? */
			return;
		if (tree) {
			gds_item = proto_tree_add_item(tree, hf_sna_gds, tvb,
			    offset, length, ENC_NA);
			gds_tree = proto_item_add_subtree(gds_item,
			    ett_sna_gds);

			proto_tree_add_uint(gds_tree, hf_sna_gds_len, tvb,
			    offset, 2, length);
			proto_tree_add_boolean(gds_tree, hf_sna_gds_cont, tvb,
			    offset, 2, cont);
			proto_tree_add_uint(gds_tree, hf_sna_gds_type, tvb,
			    offset+2, 2, type);
		}
		offset += length;
	} while(cont);
	if (tvb_offset_exists(tvb, offset))
		call_dissector(data_handle,
		    tvb_new_subset_remaining(tvb, offset), pinfo, parent_tree);
}

/* --------------------------------------------------------------------
 * General stuff
 * --------------------------------------------------------------------
 */

static void
dissect_sna(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8		fid;
	proto_tree	*sna_tree = NULL;
	proto_item	*sna_ti = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SNA");
	col_clear(pinfo->cinfo, COL_INFO);

	/* SNA data should be printed in EBCDIC, not ASCII */
	pinfo->fd->flags.encoding = PACKET_CHAR_ENC_CHAR_EBCDIC;

	if (tree) {

		/* Don't bother setting length. We'll set it later after we find
		 * the lengths of TH/RH/RU */
		sna_ti = proto_tree_add_item(tree, proto_sna, tvb, 0, -1,
		    ENC_NA);
		sna_tree = proto_item_add_subtree(sna_ti, ett_sna);
	}

	/* Transmission Header Format Identifier */
	fid = hi_nibble(tvb_get_guint8(tvb, 0));
	switch(fid) {
		case 0xa:	/* HPR Network Layer Packet */
		case 0xb:
		case 0xc:
		case 0xd:
			dissect_nlp(tvb, pinfo, sna_tree, tree);
			break;
		default:
			dissect_fid(tvb, pinfo, sna_tree, tree);
	}
}

static void
dissect_sna_xid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*sna_tree = NULL;
	proto_item	*sna_ti = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SNA");
	col_clear(pinfo->cinfo, COL_INFO);

	/* SNA data should be printed in EBCDIC, not ASCII */
	pinfo->fd->flags.encoding = PACKET_CHAR_ENC_CHAR_EBCDIC;

	if (tree) {

		/* Don't bother setting length. We'll set it later after we find
		 * the lengths of XID */
		sna_ti = proto_tree_add_item(tree, proto_sna_xid, tvb, 0, -1,
		    ENC_NA);
		sna_tree = proto_item_add_subtree(sna_ti, ett_sna);
	}
	dissect_xid(tvb, pinfo, sna_tree, tree);
}

static void
sna_init(void)
{
	reassembly_table_init(&sna_reassembly_table,
	    &addresses_reassembly_table_functions);
}


void
proto_register_sna(void)
{
        static hf_register_info hf[] = {
                { &hf_sna_th,
                { "Transmission Header", "sna.th", FT_NONE, BASE_NONE,
		     NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_0,
                { "Transmission Header Byte 0", "sna.th.0", FT_UINT8, BASE_HEX,
		    NULL, 0x0,
		    "TH Byte 0", HFILL }},

                { &hf_sna_th_fid,
                { "Format Identifier", "sna.th.fid", FT_UINT8, BASE_HEX,
		    VALS(sna_th_fid_vals), 0xf0, NULL, HFILL }},

                { &hf_sna_th_mpf,
                { "Mapping Field", "sna.th.mpf", FT_UINT8,
		    BASE_DEC, VALS(sna_th_mpf_vals), 0x0c, NULL, HFILL }},

		{ &hf_sna_th_odai,
		{ "ODAI Assignment Indicator", "sna.th.odai", FT_UINT8,
		    BASE_DEC, NULL, 0x02, NULL, HFILL }},

                { &hf_sna_th_efi,
                { "Expedited Flow Indicator", "sna.th.efi", FT_UINT8,
		    BASE_DEC, VALS(sna_th_efi_vals), 0x01, NULL, HFILL }},

                { &hf_sna_th_daf,
                { "Destination Address Field", "sna.th.daf", FT_UINT16,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_oaf,
                { "Origin Address Field", "sna.th.oaf", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_snf,
                { "Sequence Number Field", "sna.th.snf", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_dcf,
                { "Data Count Field", "sna.th.dcf", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_lsid,
                { "Local Session Identification", "sna.th.lsid", FT_UINT8,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_tg_sweep,
                { "Transmission Group Sweep", "sna.th.tg_sweep", FT_UINT8,
		    BASE_DEC, VALS(sna_th_tg_sweep_vals), 0x08, NULL, HFILL }},

                { &hf_sna_th_er_vr_supp_ind,
                { "ER and VR Support Indicator", "sna.th.er_vr_supp_ind",
		    FT_UINT8, BASE_DEC, VALS(sna_th_er_vr_supp_ind_vals),
		    0x04, NULL, HFILL }},

                { &hf_sna_th_vr_pac_cnt_ind,
                { "Virtual Route Pacing Count Indicator",
		    "sna.th.vr_pac_cnt_ind", FT_UINT8, BASE_DEC,
		    VALS(sna_th_vr_pac_cnt_ind_vals), 0x02, NULL, HFILL }},

                { &hf_sna_th_ntwk_prty,
                { "Network Priority", "sna.th.ntwk_prty", FT_UINT8, BASE_DEC,
		    VALS(sna_th_ntwk_prty_vals), 0x01, NULL, HFILL }},

                { &hf_sna_th_tgsf,
                { "Transmission Group Segmenting Field", "sna.th.tgsf",
		    FT_UINT8, BASE_HEX, VALS(sna_th_tgsf_vals), 0xc0,
		    NULL, HFILL }},

                { &hf_sna_th_mft,
                { "MPR FID4 Type", "sna.th.mft", FT_BOOLEAN, 8,
		    NULL, 0x04, NULL, HFILL }},

                { &hf_sna_th_piubf,
                { "PIU Blocking Field", "sna.th.piubf", FT_UINT8, BASE_HEX,
		    VALS(sna_th_piubf_vals), 0x03, NULL, HFILL }},

                { &hf_sna_th_iern,
                { "Initial Explicit Route Number", "sna.th.iern", FT_UINT8,
		    BASE_DEC, NULL, 0xf0, NULL, HFILL }},

                { &hf_sna_th_nlpoi,
                { "NLP Offset Indicator", "sna.th.nlpoi", FT_UINT8, BASE_DEC,
		    VALS(sna_th_nlpoi_vals), 0x80, NULL, HFILL }},

                { &hf_sna_th_nlp_cp,
                { "NLP Count or Padding", "sna.th.nlp_cp", FT_UINT8, BASE_DEC,
		    NULL, 0x70, NULL, HFILL }},

                { &hf_sna_th_ern,
                { "Explicit Route Number", "sna.th.ern", FT_UINT8, BASE_DEC,
		    NULL, 0x0f, NULL, HFILL }},

                { &hf_sna_th_vrn,
                { "Virtual Route Number", "sna.th.vrn", FT_UINT8, BASE_DEC,
		    NULL, 0xf0, NULL, HFILL }},

                { &hf_sna_th_tpf,
                { "Transmission Priority Field", "sna.th.tpf", FT_UINT8,
		    BASE_HEX, VALS(sna_th_tpf_vals), 0x03, NULL, HFILL }},

                { &hf_sna_th_vr_cwi,
                { "Virtual Route Change Window Indicator", "sna.th.vr_cwi",
		    FT_UINT16, BASE_DEC, VALS(sna_th_vr_cwi_vals), 0x8000,
		    "Change Window Indicator", HFILL }},

                { &hf_sna_th_tg_nonfifo_ind,
                { "Transmission Group Non-FIFO Indicator",
		    "sna.th.tg_nonfifo_ind", FT_BOOLEAN, 16,
		    TFS(&sna_th_tg_nonfifo_ind_truth), 0x4000, NULL, HFILL }},

                { &hf_sna_th_vr_sqti,
                { "Virtual Route Sequence and Type Indicator", "sna.th.vr_sqti",
		    FT_UINT16, BASE_HEX, VALS(sna_th_vr_sqti_vals), 0x3000,
		    "Route Sequence and Type", HFILL }},

                { &hf_sna_th_tg_snf,
                { "Transmission Group Sequence Number Field", "sna.th.tg_snf",
		    FT_UINT16, BASE_DEC, NULL, 0x0fff, NULL, HFILL }},

                { &hf_sna_th_vrprq,
                { "Virtual Route Pacing Request", "sna.th.vrprq", FT_BOOLEAN,
		    16, TFS(&sna_th_vrprq_truth), 0x8000, NULL, HFILL }},

                { &hf_sna_th_vrprs,
                { "Virtual Route Pacing Response", "sna.th.vrprs", FT_BOOLEAN,
		    16, TFS(&sna_th_vrprs_truth), 0x4000, NULL, HFILL }},

                { &hf_sna_th_vr_cwri,
                { "Virtual Route Change Window Reply Indicator",
		    "sna.th.vr_cwri", FT_UINT16, BASE_DEC,
		    VALS(sna_th_vr_cwri_vals), 0x2000, NULL, HFILL }},

                { &hf_sna_th_vr_rwi,
                { "Virtual Route Reset Window Indicator", "sna.th.vr_rwi",
		    FT_BOOLEAN, 16, TFS(&sna_th_vr_rwi_truth), 0x1000,
		    NULL, HFILL }},

                { &hf_sna_th_vr_snf_send,
                { "Virtual Route Send Sequence Number Field",
		    "sna.th.vr_snf_send", FT_UINT16, BASE_DEC, NULL, 0x0fff,
		    "Send Sequence Number Field", HFILL }},

                { &hf_sna_th_dsaf,
                { "Destination Subarea Address Field", "sna.th.dsaf",
		    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_osaf,
                { "Origin Subarea Address Field", "sna.th.osaf", FT_UINT32,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_snai,
                { "SNA Indicator", "sna.th.snai", FT_BOOLEAN, 8, NULL, 0x10,
		    "Used to identify whether the PIU originated or is destined for an SNA or non-SNA device.", HFILL }},

                { &hf_sna_th_def,
                { "Destination Element Field", "sna.th.def", FT_UINT16,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_oef,
                { "Origin Element Field", "sna.th.oef", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_sa,
                { "Session Address", "sna.th.sa", FT_BYTES, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_cmd_fmt,
                { "Command Format", "sna.th.cmd_fmt", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_cmd_type,
                { "Command Type", "sna.th.cmd_type", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

                { &hf_sna_th_cmd_sn,
                { "Command Sequence Number", "sna.th.cmd_sn", FT_UINT16,
		    BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_nhdr,
                { "Network Layer Packet Header", "sna.nlp.nhdr", FT_NONE,
		    BASE_NONE, NULL, 0x0, "NHDR", HFILL }},

                { &hf_sna_nlp_nhdr_0,
                { "Network Layer Packet Header Byte 0",	"sna.nlp.nhdr.0",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_nhdr_1,
                { "Network Layer Packet Header Byte 1", "sna.nlp.nhdr.1",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_sm,
                { "Switching Mode Field", "sna.nlp.nhdr.sm", FT_UINT8,
		    BASE_HEX, VALS(sna_nlp_sm_vals), 0xe0, NULL, HFILL }},

                { &hf_sna_nlp_tpf,
                { "Transmission Priority Field", "sna.nlp.nhdr.tpf", FT_UINT8,
		    BASE_HEX, VALS(sna_th_tpf_vals), 0x06, NULL, HFILL }},

                { &hf_sna_nlp_ft,
                { "Function Type", "sna.nlp.nhdr.ft", FT_UINT8, BASE_HEX,
		    VALS(sna_nlp_ft_vals), 0xF0, NULL, HFILL }},

                { &hf_sna_nlp_tspi,
                { "Time Sensitive Packet Indicator", "sna.nlp.nhdr.tspi",
		    FT_BOOLEAN, 8, TFS(&sna_nlp_tspi_truth), 0x08, NULL, HFILL }},

                { &hf_sna_nlp_slowdn1,
                { "Slowdown 1", "sna.nlp.nhdr.slowdn1", FT_BOOLEAN, 8,
		    TFS(&sna_nlp_slowdn1_truth), 0x04, NULL, HFILL }},

                { &hf_sna_nlp_slowdn2,
                { "Slowdown 2", "sna.nlp.nhdr.slowdn2", FT_BOOLEAN, 8,
		    TFS(&sna_nlp_slowdn2_truth), 0x02, NULL, HFILL }},

                { &hf_sna_nlp_fra,
                { "Function Routing Address Entry", "sna.nlp.nhdr.fra",
		    FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

                { &hf_sna_nlp_anr,
                { "Automatic Network Routing Entry", "sna.nlp.nhdr.anr",
		    FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }},

                { &hf_sna_nlp_frh,
                { "Transmission Priority Field", "sna.nlp.frh", FT_UINT8,
		    BASE_HEX, VALS(sna_nlp_frh_vals), 0, NULL, HFILL }},

                { &hf_sna_nlp_thdr,
                { "RTP Transport Header", "sna.nlp.thdr", FT_NONE, BASE_NONE,
		    NULL, 0x0, "THDR", HFILL }},

                { &hf_sna_nlp_tcid,
                { "Transport Connection Identifier", "sna.nlp.thdr.tcid",
		    FT_BYTES, BASE_NONE, NULL, 0x0, "TCID", HFILL }},

                { &hf_sna_nlp_thdr_8,
                { "RTP Transport Packet Header Byte 8", "sna.nlp.thdr.8",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_setupi,
                { "Setup Indicator", "sna.nlp.thdr.setupi", FT_BOOLEAN, 8,
		    TFS(&sna_nlp_setupi_truth), 0x40, NULL, HFILL }},

                { &hf_sna_nlp_somi,
                { "Start Of Message Indicator", "sna.nlp.thdr.somi",
		    FT_BOOLEAN, 8, TFS(&sna_nlp_somi_truth), 0x20, NULL, HFILL }},

                { &hf_sna_nlp_eomi,
                { "End Of Message Indicator", "sna.nlp.thdr.eomi", FT_BOOLEAN,
		    8, TFS(&sna_nlp_eomi_truth), 0x10, NULL, HFILL }},

                { &hf_sna_nlp_sri,
                { "Session Request Indicator", "sna.nlp.thdr.sri", FT_BOOLEAN,
		    8, TFS(&sna_nlp_sri_truth), 0x08, NULL, HFILL }},

                { &hf_sna_nlp_rasapi,
                { "Reply ASAP Indicator", "sna.nlp.thdr.rasapi", FT_BOOLEAN,
		    8, TFS(&sna_nlp_rasapi_truth), 0x04, NULL, HFILL }},

                { &hf_sna_nlp_retryi,
                { "Retry Indicator", "sna.nlp.thdr.retryi", FT_BOOLEAN,
		    8, TFS(&sna_nlp_retryi_truth), 0x02, NULL, HFILL }},

                { &hf_sna_nlp_thdr_9,
                { "RTP Transport Packet Header Byte 9", "sna.nlp.thdr.9",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_lmi,
                { "Last Message Indicator", "sna.nlp.thdr.lmi", FT_BOOLEAN,
		    8, TFS(&sna_nlp_lmi_truth), 0x80, NULL, HFILL }},

                { &hf_sna_nlp_cqfi,
                { "Connection Qualifier Field Indicator", "sna.nlp.thdr.cqfi",
		    FT_BOOLEAN, 8, TFS(&sna_nlp_cqfi_truth), 0x08, NULL, HFILL }},

                { &hf_sna_nlp_osi,
                { "Optional Segments Present Indicator", "sna.nlp.thdr.osi",
		    FT_BOOLEAN, 8, TFS(&sna_nlp_osi_truth), 0x04, NULL, HFILL }},

                { &hf_sna_nlp_offset,
                { "Data Offset/4", "sna.nlp.thdr.offset", FT_UINT16, BASE_HEX,
		    NULL, 0x0, "Data Offset in Words", HFILL }},

                { &hf_sna_nlp_dlf,
                { "Data Length Field", "sna.nlp.thdr.dlf", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_bsn,
                { "Byte Sequence Number", "sna.nlp.thdr.bsn", FT_UINT32,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_len,
                { "Optional Segment Length/4", "sna.nlp.thdr.optional.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_type,
                { "Optional Segment Type", "sna.nlp.thdr.optional.type",
		    FT_UINT8, BASE_HEX, VALS(sna_nlp_opti_vals), 0x0, NULL,
		    HFILL }},

                { &hf_sna_nlp_opti_0d_version,
                { "Version", "sna.nlp.thdr.optional.0d.version",
		    FT_UINT16, BASE_HEX, VALS(sna_nlp_opti_0d_version_vals),
		    0, NULL, HFILL }},

                { &hf_sna_nlp_opti_0d_4,
                { "Connection Setup Byte 4", "sna.nlp.thdr.optional.0e.4",
		    FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

                { &hf_sna_nlp_opti_0d_target,
                { "Target Resource ID Present",
		    "sna.nlp.thdr.optional.0d.target",
		    FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

                { &hf_sna_nlp_opti_0d_arb,
                { "ARB Flow Control", "sna.nlp.thdr.optional.0d.arb",
		    FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},

                { &hf_sna_nlp_opti_0d_reliable,
                { "Reliable Connection", "sna.nlp.thdr.optional.0d.reliable",
		    FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},

                { &hf_sna_nlp_opti_0d_dedicated,
                { "Dedicated RTP Connection",
		    "sna.nlp.thdr.optional.0d.dedicated",
		    FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},

                { &hf_sna_nlp_opti_0e_stat,
                { "Status", "sna.nlp.thdr.optional.0e.stat",
		    FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }},

                { &hf_sna_nlp_opti_0e_gap,
                { "Gap Detected", "sna.nlp.thdr.optional.0e.gap",
		    FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

                { &hf_sna_nlp_opti_0e_idle,
                { "RTP Idle Packet", "sna.nlp.thdr.optional.0e.idle",
		    FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},

                { &hf_sna_nlp_opti_0e_nabsp,
                { "Number Of ABSP", "sna.nlp.thdr.optional.0e.nabsp",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_0e_sync,
                { "Status Report Number", "sna.nlp.thdr.optional.0e.sync",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_0e_echo,
                { "Status Acknowledge Number", "sna.nlp.thdr.optional.0e.echo",
		    FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_0e_rseq,
                { "Received Sequence Number", "sna.nlp.thdr.optional.0e.rseq",
		    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

#if 0
                { &hf_sna_nlp_opti_0e_abspbeg,
                { "ABSP Begin", "sna.nlp.thdr.optional.0e.abspbeg",
		    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
#endif

#if 0
                { &hf_sna_nlp_opti_0e_abspend,
                { "ABSP End", "sna.nlp.thdr.optional.0e.abspend",
		    FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
#endif

                { &hf_sna_nlp_opti_0f_bits,
                { "Client Bits", "sna.nlp.thdr.optional.0f.bits",
		    FT_UINT8, BASE_HEX, VALS(sna_nlp_opti_0f_bits_vals),
		    0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_10_tcid,
                { "Transport Connection Identifier",
		    "sna.nlp.thdr.optional.10.tcid",
		    FT_BYTES, BASE_NONE, NULL, 0x0, "TCID", HFILL }},

                { &hf_sna_nlp_opti_12_sense,
                { "Sense Data", "sna.nlp.thdr.optional.12.sense",
		    FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_len,
                { "Length", "sna.nlp.thdr.optional.14.si.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_key,
                { "Key", "sna.nlp.thdr.optional.14.si.key",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_2,
                { "Switching Information Byte 2",
		    "sna.nlp.thdr.optional.14.si.2",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_refifo,
                { "Resequencing (REFIFO) Indicator",
		    "sna.nlp.thdr.optional.14.si.refifo",
		    FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_mobility,
                { "Mobility Indicator",
		    "sna.nlp.thdr.optional.14.si.mobility",
		    FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_dirsearch,
                { "Directory Search Required on Path Switch Indicator",
		    "sna.nlp.thdr.optional.14.si.dirsearch",
		    FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_limitres,
                { "Limited Resource Link Indicator",
		    "sna.nlp.thdr.optional.14.si.limitres",
		    FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_ncescope,
                { "NCE Scope Indicator",
		    "sna.nlp.thdr.optional.14.si.ncescope",
		    FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_mnpsrscv,
                { "MNPS RSCV Retention Indicator",
		    "sna.nlp.thdr.optional.14.si.mnpsrscv",
		    FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_maxpsize,
                { "Maximum Packet Size On Return Path",
		    "sna.nlp.thdr.optional.14.si.maxpsize",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_switch,
                { "Path Switch Time", "sna.nlp.thdr.optional.14.si.switch",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_si_alive,
                { "RTP Alive Timer", "sna.nlp.thdr.optional.14.si.alive",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_rr_len,
                { "Length", "sna.nlp.thdr.optional.14.rr.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_rr_key,
                { "Key", "sna.nlp.thdr.optional.14.rr.key",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_rr_2,
                { "Return Route TG Descriptor Byte 2",
		    "sna.nlp.thdr.optional.14.rr.2",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_rr_bfe,
                { "BF Entry Indicator",
		    "sna.nlp.thdr.optional.14.rr.bfe",
		    FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

                { &hf_sna_nlp_opti_14_rr_num,
                { "Number Of TG Control Vectors",
		    "sna.nlp.thdr.optional.14.rr.num",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_2,
                { "Adaptive Rate Based Segment Byte 2",
		    "sna.nlp.thdr.optional.22.2",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_type,
                { "Message Type",
		    "sna.nlp.thdr.optional.22.type",
		    FT_UINT8, BASE_HEX,
		    VALS(sna_nlp_opti_22_type_vals), 0xc0, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_raa,
                { "Rate Adjustment Action",
		    "sna.nlp.thdr.optional.22.raa",
		    FT_UINT8, BASE_HEX,
		    VALS(sna_nlp_opti_22_raa_vals), 0x38, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_parity,
                { "Parity Indicator",
		    "sna.nlp.thdr.optional.22.parity",
		    FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_arb,
                { "ARB Mode",
		    "sna.nlp.thdr.optional.22.arb",
		    FT_UINT8, BASE_HEX,
		    VALS(sna_nlp_opti_22_arb_vals), 0x03, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_3,
                { "Adaptive Rate Based Segment Byte 3",
		    "sna.nlp.thdr.optional.22.3",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_ratereq,
                { "Rate Request Correlator",
		    "sna.nlp.thdr.optional.22.ratereq",
		    FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_raterep,
                { "Rate Reply Correlator",
		    "sna.nlp.thdr.optional.22.raterep",
		    FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_field1,
                { "Field 1", "sna.nlp.thdr.optional.22.field1",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_field2,
                { "Field 2", "sna.nlp.thdr.optional.22.field2",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_field3,
                { "Field 3", "sna.nlp.thdr.optional.22.field3",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_nlp_opti_22_field4,
                { "Field 4", "sna.nlp.thdr.optional.22.field4",
		    FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_rh,
                { "Request/Response Header", "sna.rh", FT_NONE, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

                { &hf_sna_rh_0,
                { "Request/Response Header Byte 0", "sna.rh.0", FT_UINT8,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_rh_1,
                { "Request/Response Header Byte 1", "sna.rh.1", FT_UINT8,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_rh_2,
                { "Request/Response Header Byte 2", "sna.rh.2", FT_UINT8,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_rh_rri,
                { "Request/Response Indicator", "sna.rh.rri", FT_UINT8,
		    BASE_DEC, VALS(sna_rh_rri_vals), 0x80, NULL, HFILL }},

                { &hf_sna_rh_ru_category,
                { "Request/Response Unit Category", "sna.rh.ru_category",
		    FT_UINT8, BASE_HEX, VALS(sna_rh_ru_category_vals), 0x60,
		    NULL, HFILL }},

		{ &hf_sna_rh_fi,
		{ "Format Indicator", "sna.rh.fi", FT_BOOLEAN, 8,
		    TFS(&sna_rh_fi_truth), 0x08, NULL, HFILL }},

		{ &hf_sna_rh_sdi,
		{ "Sense Data Included", "sna.rh.sdi", FT_BOOLEAN, 8,
		    TFS(&sna_rh_sdi_truth), 0x04, NULL, HFILL }},

		{ &hf_sna_rh_bci,
		{ "Begin Chain Indicator", "sna.rh.bci", FT_BOOLEAN, 8,
		    TFS(&sna_rh_bci_truth), 0x02, NULL, HFILL }},

		{ &hf_sna_rh_eci,
		{ "End Chain Indicator", "sna.rh.eci", FT_BOOLEAN, 8,
		    TFS(&sna_rh_eci_truth), 0x01, NULL, HFILL }},

		{ &hf_sna_rh_dr1,
		{ "Definite Response 1 Indicator", "sna.rh.dr1", FT_BOOLEAN,
		    8, NULL, 0x80, NULL, HFILL }},

		{ &hf_sna_rh_lcci,
		{ "Length-Checked Compression Indicator", "sna.rh.lcci",
		    FT_BOOLEAN, 8, TFS(&sna_rh_lcci_truth), 0x40, NULL, HFILL }},

		{ &hf_sna_rh_dr2,
		{ "Definite Response 2 Indicator", "sna.rh.dr2", FT_BOOLEAN,
		    8, NULL, 0x20, NULL, HFILL }},

		{ &hf_sna_rh_eri,
		{ "Exception Response Indicator", "sna.rh.eri", FT_BOOLEAN,
		    8, NULL, 0x10, NULL, HFILL }},

		{ &hf_sna_rh_rti,
		{ "Response Type Indicator", "sna.rh.rti", FT_BOOLEAN,
		    8, TFS(&sna_rh_rti_truth), 0x10, NULL, HFILL }},

		{ &hf_sna_rh_rlwi,
		{ "Request Larger Window Indicator", "sna.rh.rlwi", FT_BOOLEAN,
		    8, NULL, 0x04, NULL, HFILL }},

		{ &hf_sna_rh_qri,
		{ "Queued Response Indicator", "sna.rh.qri", FT_BOOLEAN,
		    8, TFS(&sna_rh_qri_truth), 0x02, NULL, HFILL }},

		{ &hf_sna_rh_pi,
		{ "Pacing Indicator", "sna.rh.pi", FT_BOOLEAN,
		    8, NULL, 0x01, NULL, HFILL }},

		{ &hf_sna_rh_bbi,
		{ "Begin Bracket Indicator", "sna.rh.bbi", FT_BOOLEAN,
		    8, NULL, 0x80, NULL, HFILL }},

		{ &hf_sna_rh_ebi,
		{ "End Bracket Indicator", "sna.rh.ebi", FT_BOOLEAN,
		    8, NULL, 0x40, NULL, HFILL }},

		{ &hf_sna_rh_cdi,
		{ "Change Direction Indicator", "sna.rh.cdi", FT_BOOLEAN,
		    8, NULL, 0x20, NULL, HFILL }},

		{ &hf_sna_rh_csi,
		{ "Code Selection Indicator", "sna.rh.csi", FT_UINT8, BASE_DEC,
		    VALS(sna_rh_csi_vals), 0x08, NULL, HFILL }},

		{ &hf_sna_rh_edi,
		{ "Enciphered Data Indicator", "sna.rh.edi", FT_BOOLEAN, 8,
		    NULL, 0x04, NULL, HFILL }},

		{ &hf_sna_rh_pdi,
		{ "Padded Data Indicator", "sna.rh.pdi", FT_BOOLEAN, 8, NULL,
		    0x02, NULL, HFILL }},

		{ &hf_sna_rh_cebi,
		{ "Conditional End Bracket Indicator", "sna.rh.cebi",
		    FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},

/*		{ &hf_sna_ru,
		{ "Request/Response Unit", "sna.ru", FT_NONE, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},*/

		{ &hf_sna_gds,
		{ "GDS Variable", "sna.gds", FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_sna_gds_len,
		{ "GDS Variable Length", "sna.gds.len", FT_UINT16, BASE_DEC,
		    NULL, 0x7fff, NULL, HFILL }},

		{ &hf_sna_gds_cont,
		{ "Continuation Flag", "sna.gds.cont", FT_BOOLEAN, 16, NULL,
		    0x8000, NULL, HFILL }},

		{ &hf_sna_gds_type,
		{ "Type of Variable", "sna.gds.type", FT_UINT16, BASE_HEX,
		    VALS(sna_gds_var_vals), 0x0, NULL, HFILL }},

#if 0
		{ &hf_sna_xid,
		{ "XID", "sna.xid", FT_NONE, BASE_NONE, NULL, 0x0,
		    "XID Frame", HFILL }},
#endif

		{ &hf_sna_xid_0,
		{ "XID Byte 0", "sna.xid.0", FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_sna_xid_format,
		{ "XID Format", "sna.xid.format", FT_UINT8, BASE_DEC, NULL,
		    0xf0, NULL, HFILL }},

		{ &hf_sna_xid_type,
		{ "XID Type", "sna.xid.type", FT_UINT8, BASE_DEC,
		    VALS(sna_xid_type_vals), 0x0f, NULL, HFILL }},

		{ &hf_sna_xid_len,
		{ "XID Length", "sna.xid.len", FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_sna_xid_id,
		{ "Node Identification", "sna.xid.id", FT_UINT32, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_sna_xid_idblock,
		{ "ID Block", "sna.xid.idblock", FT_UINT32, BASE_HEX, NULL,
		    0xfff00000, NULL, HFILL }},

		{ &hf_sna_xid_idnum,
		{ "ID Number", "sna.xid.idnum", FT_UINT32, BASE_HEX, NULL,
		    0x0fffff, NULL, HFILL }},

		{ &hf_sna_xid_3_8,
		{ "Characteristics of XID sender", "sna.xid.type3.8", FT_UINT16,
		    BASE_HEX, NULL, 0x0, NULL, HFILL }},

		{ &hf_sna_xid_3_init_self,
		{ "INIT-SELF support", "sna.xid.type3.initself",
		    FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }},

		{ &hf_sna_xid_3_stand_bind,
		{ "Stand-Alone BIND Support", "sna.xid.type3.stand_bind",
		    FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL }},

		{ &hf_sna_xid_3_gener_bind,
		{ "Whole BIND PIU generated indicator",
		    "sna.xid.type3.gener_bind", FT_BOOLEAN, 16, NULL, 0x2000,
		    "Whole BIND PIU generated", HFILL }},

		{ &hf_sna_xid_3_recve_bind,
		{ "Whole BIND PIU required indicator",
		    "sna.xid.type3.recve_bind", FT_BOOLEAN, 16, NULL, 0x1000,
		    "Whole BIND PIU required", HFILL }},

		{ &hf_sna_xid_3_actpu,
		{ "ACTPU suppression indicator", "sna.xid.type3.actpu",
		    FT_BOOLEAN, 16, NULL, 0x0080, NULL, HFILL }},

		{ &hf_sna_xid_3_nwnode,
		{ "Sender is network node", "sna.xid.type3.nwnode",
		    FT_BOOLEAN, 16, NULL, 0x0040, NULL, HFILL }},

		{ &hf_sna_xid_3_cp,
		{ "Control Point Services", "sna.xid.type3.cp",
		    FT_BOOLEAN, 16, NULL, 0x0020, NULL, HFILL }},

		{ &hf_sna_xid_3_cpcp,
		{ "CP-CP session support", "sna.xid.type3.cpcp",
		    FT_BOOLEAN, 16, NULL, 0x0010, NULL, HFILL }},

		{ &hf_sna_xid_3_state,
		{ "XID exchange state indicator", "sna.xid.type3.state",
		    FT_UINT16, BASE_HEX, VALS(sna_xid_3_state_vals),
		    0x000c, NULL, HFILL }},

		{ &hf_sna_xid_3_nonact,
		{ "Nonactivation Exchange", "sna.xid.type3.nonact",
		    FT_BOOLEAN, 16, NULL, 0x0002, NULL, HFILL }},

		{ &hf_sna_xid_3_cpchange,
		{ "CP name change support", "sna.xid.type3.cpchange",
		    FT_BOOLEAN, 16, NULL, 0x0001, NULL, HFILL }},

		{ &hf_sna_xid_3_10,
		{ "XID Type 3 Byte 10", "sna.xid.type3.10", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_sna_xid_3_asend_bind,
		{ "Adaptive BIND pacing support as sender",
		    "sna.xid.type3.asend_bind", FT_BOOLEAN, 8, NULL, 0x80,
		    "Pacing support as sender", HFILL }},

		{ &hf_sna_xid_3_arecv_bind,
		{ "Adaptive BIND pacing support as receiver",
		    "sna.xid.type3.asend_recv", FT_BOOLEAN, 8, NULL, 0x40,
		    "Pacing support as receive", HFILL }},

		{ &hf_sna_xid_3_quiesce,
		{ "Quiesce TG Request",
		    "sna.xid.type3.quiesce", FT_BOOLEAN, 8, NULL, 0x20,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_pucap,
		{ "PU Capabilities",
		    "sna.xid.type3.pucap", FT_BOOLEAN, 8, NULL, 0x10,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_pbn,
		{ "Peripheral Border Node",
		    "sna.xid.type3.pbn", FT_BOOLEAN, 8, NULL, 0x08,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_pacing,
		{ "Qualifier for adaptive BIND pacing support",
		    "sna.xid.type3.pacing", FT_UINT8, BASE_HEX, NULL, 0x03,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_11,
		{ "XID Type 3 Byte 11", "sna.xid.type3.11", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_sna_xid_3_tgshare,
		{ "TG Sharing Prohibited Indicator",
		    "sna.xid.type3.tgshare", FT_BOOLEAN, 8, NULL, 0x40,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_dedsvc,
		{ "Dedicated SVC Indicator",
		    "sna.xid.type3.dedsvc", FT_BOOLEAN, 8, NULL, 0x20,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_12,
		{ "XID Type 3 Byte 12", "sna.xid.type3.12", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_sna_xid_3_negcsup,
		{ "Negotiation Complete Supported",
		    "sna.xid.type3.negcsup", FT_BOOLEAN, 8, NULL, 0x80,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_negcomp,
		{ "Negotiation Complete",
		    "sna.xid.type3.negcomp", FT_BOOLEAN, 8, NULL, 0x40,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_15,
		{ "XID Type 3 Byte 15", "sna.xid.type3.15", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_sna_xid_3_partg,
		{ "Parallel TG Support",
		    "sna.xid.type3.partg", FT_BOOLEAN, 8, NULL, 0x80,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_dlur,
		{ "Dependent LU Requester Indicator",
		    "sna.xid.type3.dlur", FT_BOOLEAN, 8, NULL, 0x40,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_dlus,
		{ "DLUS Served LU Registration Indicator",
		    "sna.xid.type3.dlus", FT_BOOLEAN, 8, NULL, 0x20,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_exbn,
		{ "Extended HPR Border Node",
		    "sna.xid.type3.exbn", FT_BOOLEAN, 8, NULL, 0x10,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_genodai,
		{ "Generalized ODAI Usage Option",
		    "sna.xid.type3.genodai", FT_BOOLEAN, 8, NULL, 0x08,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_branch,
		{ "Branch Indicator", "sna.xid.type3.branch",
		    FT_UINT8, BASE_HEX, VALS(sna_xid_3_branch_vals),
		    0x06, NULL, HFILL }},

		{ &hf_sna_xid_3_brnn,
		{ "Option Set 1123 Indicator",
		    "sna.xid.type3.brnn", FT_BOOLEAN, 8, NULL, 0x01,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_tg,
		{ "XID TG", "sna.xid.type3.tg", FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_dlc,
		{ "XID DLC", "sna.xid.type3.dlc", FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_sna_xid_3_dlen,
		{ "DLC Dependent Section Length", "sna.xid.type3.dlen",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_control_len,
                { "Control Vector Length", "sna.control.len",
		    FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_control_key,
                { "Control Vector Key", "sna.control.key",
		    FT_UINT8, BASE_HEX, VALS(sna_control_vals), 0x0, NULL,
		    HFILL }},

                { &hf_sna_control_hprkey,
                { "Control Vector HPR Key", "sna.control.hprkey",
		    FT_UINT8, BASE_HEX, VALS(sna_control_hpr_vals), 0x0, NULL,
		    HFILL }},

                { &hf_sna_control_05_delay,
                { "Channel Delay", "sna.control.05.delay",
		    FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_control_05_type,
                { "Network Address Type", "sna.control.05.type",
		    FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

                { &hf_sna_control_05_ptp,
                { "Point-to-point", "sna.control.05.ptp",
		    FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},

                { &hf_sna_control_0e_type,
                { "Type", "sna.control.0e.type",
		    FT_UINT8, BASE_HEX, VALS(sna_control_0e_type_vals),
		    0, NULL, HFILL }},

                { &hf_sna_control_0e_value,
                { "Value", "sna.control.0e.value",
		    FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }},
        };
	static gint *ett[] = {
		&ett_sna,
		&ett_sna_th,
		&ett_sna_th_fid,
		&ett_sna_nlp_nhdr,
		&ett_sna_nlp_nhdr_0,
		&ett_sna_nlp_nhdr_1,
		&ett_sna_nlp_thdr,
		&ett_sna_nlp_thdr_8,
		&ett_sna_nlp_thdr_9,
		&ett_sna_nlp_opti_un,
		&ett_sna_nlp_opti_0d,
		&ett_sna_nlp_opti_0d_4,
		&ett_sna_nlp_opti_0e,
		&ett_sna_nlp_opti_0e_stat,
		&ett_sna_nlp_opti_0e_absp,
		&ett_sna_nlp_opti_0f,
		&ett_sna_nlp_opti_10,
		&ett_sna_nlp_opti_12,
		&ett_sna_nlp_opti_14,
		&ett_sna_nlp_opti_14_si,
		&ett_sna_nlp_opti_14_si_2,
		&ett_sna_nlp_opti_14_rr,
		&ett_sna_nlp_opti_14_rr_2,
		&ett_sna_nlp_opti_22,
		&ett_sna_nlp_opti_22_2,
		&ett_sna_nlp_opti_22_3,
		&ett_sna_rh,
		&ett_sna_rh_0,
		&ett_sna_rh_1,
		&ett_sna_rh_2,
		&ett_sna_gds,
		&ett_sna_xid_0,
		&ett_sna_xid_id,
		&ett_sna_xid_3_8,
		&ett_sna_xid_3_10,
		&ett_sna_xid_3_11,
		&ett_sna_xid_3_12,
		&ett_sna_xid_3_15,
		&ett_sna_control_un,
		&ett_sna_control_05,
		&ett_sna_control_05hpr,
		&ett_sna_control_05hpr_type,
		&ett_sna_control_0e,
	};
	module_t *sna_module;

	proto_sna = proto_register_protocol("Systems Network Architecture",
	    "SNA", "sna");
	proto_register_field_array(proto_sna, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("sna", dissect_sna, proto_sna);

	proto_sna_xid = proto_register_protocol(
	    "Systems Network Architecture XID", "SNA XID", "sna_xid");
	register_dissector("sna_xid", dissect_sna_xid, proto_sna_xid);

	/* Register configuration options */
	sna_module = prefs_register_protocol(proto_sna, NULL);
	prefs_register_bool_preference(sna_module, "defragment",
		"Reassemble fragmented BIUs",
		"Whether fragmented BIUs should be reassembled",
		&sna_defragment);

	register_init_routine(sna_init);
}

void
proto_reg_handoff_sna(void)
{
	dissector_handle_t sna_handle;
	dissector_handle_t sna_xid_handle;

	sna_handle = find_dissector("sna");
	sna_xid_handle = find_dissector("sna_xid");
	dissector_add_uint("llc.dsap", SAP_SNA_PATHCTRL, sna_handle);
	dissector_add_uint("llc.dsap", SAP_SNA1, sna_handle);
	dissector_add_uint("llc.dsap", SAP_SNA2, sna_handle);
	dissector_add_uint("llc.dsap", SAP_SNA3, sna_handle);
	dissector_add_uint("llc.xid_dsap", SAP_SNA_PATHCTRL, sna_xid_handle);
	dissector_add_uint("llc.xid_dsap", SAP_SNA1, sna_xid_handle);
	dissector_add_uint("llc.xid_dsap", SAP_SNA2, sna_xid_handle);
	dissector_add_uint("llc.xid_dsap", SAP_SNA3, sna_xid_handle);
	/* RFC 2043 */
	dissector_add_uint("ppp.protocol", PPP_SNA, sna_handle);
	data_handle = find_dissector("data");

}
