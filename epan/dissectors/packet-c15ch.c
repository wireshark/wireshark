/* packet-c15ch.c
 * Routines for C15 Call History Protocol dissection
 * Copyright 2015, Christopher Sheldahl for GENBAND <christopher.sheldahl@genband.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/wmem/wmem.h>

void proto_register_c15ch_hbeat(void);
void proto_register_c15ch(void);
void proto_reg_handoff_c15ch_hbeat(void);
void proto_reg_handoff_c15ch(void);

/* main C15 subtypes : int variable containing one of these values is passed along to second level dissector */
#define C15_CP_STATE_CH     1
#define C15_CP_EVENT        2
#define C15_ISUP            3
#define C15_NITN_XLATE      4
#define C15_SCCP            5
#define C15_CP_ORIG         6
#define C15_CONN            7
#define C15_NTWK_CONN       8
#define C15_MK_BRK          9
#define C15_PATH_FIND      10
#define C15_PATH_IDLE      11
#define C15_DEST_DIGITS    12
#define C15_TWC_RSWCH      13
#define C15_SRCE_DEST      14
#define C15_ROUTE          15
#define C15_INC_GWE        16
#define C15_OUT_GWE        17
#define C15_OUT_GWE_BC     18
#define C15_Q931           19
#define C15_AMA            20
#define C15_QOS            21
#define C15_ECHO_CANCEL    22
#define C15_TONE           23
#define C15_ENCAP_ISUP     24
#define C15_TCAP           25
#define C15_CLLI           26
#define C15_INFO           27

#define HEADER_SZ 36 /* length of complete c15ch header in bytes */
#define MAX_LEN_CONCAT_STRING 100
#define MAX_LEN_DESC_STRING 20
#define MAX_LEN_LOC_STRING 50 /* includes null char */

static const char * C15_LABEL = "C15";
/* Heartbeat Protocol : distinct from normal c15 type */
static int proto_c15ch_hbeat = -1;

/* Subtrees */
static gint ett_c15ch_hbeat = -1;

/* Fields */
static int hf_c15ch_hbeat_clli = -1;
static int hf_c15ch_hbeat_primary = -1;
static int hf_c15ch_hbeat_secondary = -1;
static int hf_c15ch_hbeat_interface = -1;

/* C15 base Protocol */
static int proto_c15ch = -1;

/* Dissector Table */
static dissector_table_t c15ch_dissector_table;

/* Fields */
static int hf_c15ch_version = -1;
static int hf_c15ch_msgtype = -1;
static int hf_c15ch_size = -1;
static int hf_c15ch_call_ref = -1;

static int hf_c15ch_srce_ni = -1;
static int hf_c15ch_srce_tn = -1;
static int hf_c15ch_dest_ni = -1;
static int hf_c15ch_dest_tn = -1;

static int hf_c15ch_srce_ni_tn = -1;
static int hf_c15ch_dest_ni_tn = -1;
static int hf_c15ch_realtime = -1;

/* Subtrees */
static gint ett_c15ch = -1;
static gint ett_src_ni_tn = -1;
static gint ett_dest_ni_tn = -1;

/* for msg_type field ...*/
static const value_string c15_msg_types[] = {
    { C15_CP_STATE_CH, "CP_STATE_CH" },
    { C15_CP_EVENT, "CP_EVENT" },
    { C15_ISUP, "ISUP" },
    { C15_NITN_XLATE, "NITN_XLATE" },
    { C15_SCCP, "SCCP" },
    { C15_CP_ORIG, "CP_ORIG" },
    { C15_CONN, "CONN" },
    { C15_NTWK_CONN, "NTWK_CONN" },
    { C15_MK_BRK, "MK_BRK" },
    { C15_PATH_FIND, "PATH_FIND" },
    { C15_PATH_IDLE, "PATH_IDLE" },
    { C15_DEST_DIGITS, "DEST_DIGITS" },
    { C15_TWC_RSWCH, "TWC_RSWCH" },
    { C15_SRCE_DEST, "SRCE_DEST" },
    { C15_ROUTE, "ROUTE" },
    { C15_INC_GWE, "INC_GWE" },
    { C15_OUT_GWE, "OUT_GWE" },
    { C15_OUT_GWE_BC, "OUT_GWE_BC" },
    { C15_Q931, "Q931" },
    { C15_AMA, "AMA" },
    { C15_QOS, "QOS" },
    { C15_ECHO_CANCEL, "ECHO_CANCEL" },
    { C15_TONE, "TONE" },
    { C15_ENCAP_ISUP, "ENCAP_ISUP" },
    { C15_TCAP, "TCAP" },
    { C15_CLLI, "CLLI" },
    { C15_INFO, "C15_INFO" },
    { 0, NULL }
};
static value_string_ext c15_msg_types_ext = VALUE_STRING_EXT_INIT(c15_msg_types);

/* Second Level */
static gint ett_c15ch_second_level = -1;
static gint ett_c15ch_second_level_sub1 = -1;
static gint ett_c15ch_second_level_sub2 = -1;
static gint ett_c15ch_second_level_sub3 = -1;
static gint ett_c15ch_second_level_sub4 = -1;
static int proto_c15ch_second_level = -1;

static dissector_handle_t general_sccp_handle  = NULL;
static dissector_handle_t general_isup_handle  = NULL;
static dissector_handle_t general_q931_handle  = NULL;
/* ama */

/* Fields */
static int hf_c15ch_ama = -1;
static int hf_c15ch_ama_call_code = -1;
static int hf_c15ch_ama_orig_digits = -1;
static int hf_c15ch_ama_num_dialed_digits = -1;
static int hf_c15ch_ama_br_prefix = -1;
static int hf_c15ch_ama_dialed_digits = -1;
static int hf_c15ch_ama_start_hour = -1;
static int hf_c15ch_ama_start_minute = -1;
static int hf_c15ch_ama_start_second = -1;
static int hf_c15ch_ama_start_tenth_second = -1;
static int hf_c15ch_ama_start_day = -1;
static int hf_c15ch_ama_start_month = -1;
static int hf_c15ch_ama_start_year = -1;
static int hf_c15ch_ama_answered = -1;
static int hf_c15ch_ama_elapsed_time = -1; /*elapsed time in millisec*/
static int hf_c15ch_ama_call_type = -1;


/* br_prefix labels */
static const value_string ama_br_prefix_types[] = {
    { 0, "PFX_NONE" },
    { 1, "PFX_1" },
    { 2, "PFX_0" },
    { 3, "PFX_01" },
    { 4, "PFX_011" },
    { 5, "PFX_ANY" },
    /* 6 is unused */
    { 7, "PFX_ANY" },
    { 0, NULL }
};

/* call_type labels */
static const value_string ama_call_types[] = {
    { 0, "NONE" },
    { 1, "FAIL" },
    { 2, "TEST" },
    { 3, "DDD" },
    { 4, "IDDD" },
    { 5, "EMERG" },
    { 6, "DA" },
    { 7, "LCDR" },
    { 8, "INWATS" },
    { 9, "OWATS" },
    { 10, "SLUS" },
    { 11, "TRAF" },
    { 12, "TMSG" },
    { 13, "UMSG" },
    { 14, "DAL" },
    { 15, "DAT" },
    { 16, "OFGA" },
    { 17, "TFGA" },
    { 18, "ILSP" },
    { 19, "ILOW" },
    { 20, "TLATA" },
    { 21, "CCSA" },
    { 22, "MISC" }, /* used for USCCF */
    { 23, "FREE" },
    { 24, "ICNS" },
    { 25, "TELC" },
    { 26, "ACB" },
    { 27, "AR" },
    { 28, "CNDB" },
    { 29, "SLE" },
    { 30, "COT" },
    { 31, "CLID" },
    { 32, "IPTS" },
    { 33, "CNAB" },
    { 34, "CIDS" },
    { 35, "ACR" },
    { 36, "SW56" },
    { 37, "ILSW56" },
    { 38, "TLSW56" },
    { 39, "CMCO" },
    { 40, "CMCT" },
    { 41, "TSLS" },
    { 42, "OFGB" },
    { 43, "TFGB" },
    { 44, "AIN" },
    { 45, "ISUS" },
    { 46, "ISTS" },
    { 47, "CNA" },
    { 48, "TGMO" },
    { 49, "TGMT" },
    { 0, NULL }
};
static value_string_ext ama_call_types_ext = VALUE_STRING_EXT_INIT(ama_call_types);
/* c15 info */
/* Fields */
static int hf_c15ch_c15_info = -1;
static int hf_c15ch_c15_info_code = -1;
static int hf_c15ch_c15_info_level = -1;
static int hf_c15ch_c15_info_text = -1;


/* labels for level */
static const value_string c15ch_c15_info_level_types[] = {
    { 0, "NONE" },
    { 1, "MIN" },
    { 2, "MAJ" },
    { 3, "CAT" },
    { 0, NULL }
};

/* clli */

/* Fields */
static int hf_c15ch_clli = -1;
static int hf_c15ch_clli_clli_string = -1;
static int hf_c15ch_clli_active_core = -1;
static int hf_c15ch_clli_inactive_core = -1;
static int hf_c15ch_clli_interface_string = -1;
static int hf_c15ch_clli_seconds = -1;
static int hf_c15ch_clli_microseconds = -1;


/* conn */

/* Fields */
static int hf_c15ch_conn = -1;
static int hf_c15ch_conn_connfrom = -1;
static int hf_c15ch_conn_conntype = -1;
static int hf_c15ch_conn_perphtype = -1;
static int hf_c15ch_conn_intra = -1;
static int hf_c15ch_conn_srceni = -1;
static int hf_c15ch_conn_srcenitn = -1;
static int hf_c15ch_conn_srcetn = -1;
static int hf_c15ch_conn_destni = -1;
static int hf_c15ch_conn_destnitn = -1;
static int hf_c15ch_conn_desttn = -1;
static int hf_c15ch_conn_interlinknum = -1;
static int hf_c15ch_conn_fromport = -1;
static int hf_c15ch_conn_fromslot = -1;
static int hf_c15ch_conn_toport = -1;
static int hf_c15ch_conn_toslot = -1;
static int hf_c15ch_conn_hubcallid = -1;

/* value_string arrays to label fields */
/* for connfrom field ...*/
static const value_string c15_conn_from_types[] = {
    { 1, "LOCAL_OTHER" },
    { 2, "LOCAL_RLCM" },
    { 3, "PATH_LOCAL_IDLE" },
    { 4, "PATH_SRCE_DEST" },
    { 0, NULL }
};

/* call proc state */


/* Fields */
static int hf_c15ch_cp_state_ch = -1;
static int hf_c15ch_cp_state_ch_oldpm = -1;
static int hf_c15ch_cp_state_ch_newpm = -1;
static int hf_c15ch_cp_state_ch_subpm = -1;
static int hf_c15ch_cp_state_ch_trkpm = -1;
static int hf_c15ch_cp_state_ch_slepm = -1;
static int hf_c15ch_cp_state_ch_flags = -1;
static int hf_c15ch_cp_state_ch_oldrtetype = -1;
static int hf_c15ch_cp_state_ch_oldrteidx = -1;
static int hf_c15ch_cp_state_ch_newrtetype = -1;
static int hf_c15ch_cp_state_ch_newrteidx = -1;

/* value_string arrays to label fields */
static const value_string c15_cp_state_pm_types[] = {
    { 0, "ORIG" },
    { 1, "DSTM" },
    { 2, "RVRT" },
    { 3, "ORDT" },
    { 4, "ORWS" },
    { 5, "ORDD" },
    { 6, "ORID" },
    { 7, "#TST" },
    { 8, "DLNG" },
    { 9, "RBLT" },
    { 10, "CFWR" },
    { 11, "RTE" },
    { 12, "RLIN" },
    { 13, "MTCE" },
    { 14, "AUXT" },
    { 15, "NOLR" },
    { 16, "ITTK" },
    { 17, "ALSD" },
    { 18, "ANSP" },
    { 19, "TRNK" },
    { 20, "LINE" },
    { 21, "NOCP" },
    { 22, "3WC" },
    { 23, "3WCH" },
    { 24, "CWT" },
    { 25, "CWTH" },
    { 26, "UPSC" },
    { 27, "ORSD" },
    { 28, "CFRT" },
    { 29, "CFWB" },
    { 30, "CFW" },
    { 31, "CFWD" },
    { 32, "RCFW" },
    { 33, "ROTL" },
    { 34, "CHDT" },
    { 35, "CHD" },
    { 36, "CHLD" },
    { 37, "3WCH" },
    { 38, "3WCW" },
    { 39, "CSLT" },
    { 40, "DGTX" },
    { 41, "NAIL" },
    { 42, "DCBI" },
    { 43, "RGCF" },
    { 44, "RGCP" },
    { 45, "E800" },
    { 46, "CFRA" },
    { 47, "MWID" },
    { 48, "ACCP" },
    { 49, "ACRR" },
    { 50, "ACAN" },
    { 51, "SLE" },
    { 52, "PCOT" },
    { 53, "CLID" },
    { 54, "XPML" },
    { 55, "MWIL" },
    { 56, "LDBS" },
    { 57, "ACR" },
    { 58, "CPRK" },
    { 59, "CRCL" },
    { 60, "CFF" },
    { 61, "BERT" },
    { 62, "AIN" },
    { 63, "ASIT" },
    { 64, "ARTG" },
    { 65, "BNAL" },
    { 66, "DNAL" },
    { 67, "TRVR" },
    { 68, "EKTS" },
    { 69, "ALT" },
    { 70, "CALE" },
    { 71, "SRNG" },
    { 72, "LTA" },
    { 73, "HGQ" },
    { 74, "IDLE" },
    { 75, "SIG" },
    { 76, "SIGD" },
    { 0, NULL }
};
static value_string_ext c15_cp_state_pm_types_ext = VALUE_STRING_EXT_INIT(c15_cp_state_pm_types);
/* dest digits */

/* Fields */
static int hf_c15ch_dest_digits = -1;
static int hf_c15ch_dest_digits_digits = -1;


/* echo cancel */

/* Fields */
static int hf_c15ch_echo_cancel = -1;
static int hf_c15ch_echo_cancel_ni = -1;
static int hf_c15ch_echo_cancel_tn = -1;
static int hf_c15ch_echo_cancel_ni_tn = -1;
static int hf_c15ch_echo_cancel_old_l2_mode = -1;
static int hf_c15ch_echo_cancel_old_channel_mode = -1;
static int hf_c15ch_echo_cancel_old_ecan_mode = -1;
static int hf_c15ch_echo_cancel_new_l2_mode = -1;
static int hf_c15ch_echo_cancel_new_channel_mode = -1;
static int hf_c15ch_echo_cancel_new_ecan_mode = -1;
static int hf_c15ch_echo_cancel_tone_id = -1;
static int hf_c15ch_echo_cancel_pm = -1;
static int hf_c15ch_echo_cancel_pc = -1;
static int hf_c15ch_echo_cancel_loop = -1;
static int hf_c15ch_echo_cancel_slot = -1;
static int hf_c15ch_echo_cancel_location = -1;



/* value_string arrays to label fields */
enum C15_EC_L2_MODE
{
    C15_EC_L2_MODE_VOICE,
    C15_EC_L2_MODE_VBD,
    C15_EC_L2_MODE_VBD_ECANOFF
};

static const value_string c15_echo_cancel_l2_mode_types[] = {
    {C15_EC_L2_MODE_VOICE, "L2_MODE_VOICE"},
    {C15_EC_L2_MODE_VBD, "L2_MODE_VBD"},
    {C15_EC_L2_MODE_VBD_ECANOFF, "L2_MODE_VBD_ECANOFF"},
    {0, NULL}
};

enum C15_EC_CHANNEL_MODE
{
    C15_EC_VOICE_CHANNEL_MODE,
    C15_EC_VBD_CHANNEL_MODE,
    C15_EC_CHANNEL_MODE_INVALID
};


static const value_string c15_echo_cancel_channel_mode_types[] = {
    {C15_EC_VOICE_CHANNEL_MODE, "VOICE"},
    {C15_EC_VBD_CHANNEL_MODE, "VBD"},
    {0, NULL}
};

enum C15_EC_ECAN_MODE
{
    C15_EC_OFF_ECAN_MODE,
    C15_EC_ON_ECAN_MODE,
    C15_EC_ECAN_MODE_INVALID
};

static const value_string c15_echo_cancel_ecan_mode_types[] = {
    {C15_EC_OFF_ECAN_MODE, "OFF"},
    {C15_EC_ON_ECAN_MODE, "ON"},
    {0, NULL}
};

/* encapsulated isup */

/* Fields */
static int hf_c15ch_encap_isup = -1;
static int hf_c15ch_encap_isup_direction = -1;
static int hf_c15ch_encap_isup_isup_msg_length = -1;


/* isup ( not encapsulated )*/

/* Fields */
static int hf_c15ch_isup = -1;
static int hf_c15ch_isup_direction = -1;
static int hf_c15ch_isup_msgtype = -1;
static int hf_c15ch_isup_cic = -1;
static int hf_c15ch_isup_opcmember = -1;
static int hf_c15ch_isup_opccluster = -1;
static int hf_c15ch_isup_opcnetwork = -1;
static int hf_c15ch_isup_dpcmember = -1;
static int hf_c15ch_isup_dpccluster = -1;
static int hf_c15ch_isup_dpcnetwork = -1;
static int hf_c15ch_isup_level3index = -1;
static int hf_c15ch_isup_ni = -1;
static int hf_c15ch_isup_tn = -1;
static int hf_c15ch_isup_ni_tn = -1;
static int hf_c15ch_isup_c15hdr = -1;
static int hf_c15ch_isup_layer2hdr = -1;
static int hf_c15ch_isup_layer3hdr = -1;
static int hf_c15ch_isup_iptime = -1;


/* value_string arrays to label fields */
/* labels for msgtype : non-contiguous integers*/
static const value_string c15_isup_types[] = {
    {1, "Initial Address"},
    {5, "Continuity"},
    {6, "Address Complete"},
    {9, "Answer"},
    {12, "Release"},
    {13, "Suspend"},
    {14, "Resume"},
    {16, "Release Complete"},
    {17, "Continuity Recheck Request"},
    {18, "Reset"},
    {19, "Blocking"},
    {20, "Unblocking"},
    {21, "Blocking Ack"},
    {22, "Unblocking Ack"},
    {23, "Group Reset"},
    {24, "Circuit Group Blocking"},
    {25, "Circuit Group Unblocking"},
    {26, "Circuit Group Blocking Ack"},
    {27, "Circuit Group Unblocking Ack"},
    {36, "Loop Back Ack"},
    {41, "Group Reset Ack"},
    {42, "Circuit Query"},
    {43, "Circuit Query Response"},
    {44, "Call Progress"},
    {46, "Unidentified Circuit ID Code"},
    {47, "Confusion"},
    {51, "Facility"},
    {233, "Circuit Reservation Ack"},
    {234, "Circuit Reservation"},
    {235, "Circuit Validation Response"},
    {236, "Circuit Validation Test"},
    {237, "Exit"},
    { 0, NULL}
};
static value_string_ext c15_isup_types_ext = VALUE_STRING_EXT_INIT(c15_isup_types);
static const value_string c15_isup_direction_types[] = {
    { 0, "Incoming" },
    { 1, "Outgoing" },
    { 0, NULL}
};

/* mkbrk */


/* Fields */
static int hf_c15ch_mkbrk = -1;
static int hf_c15ch_mkbrk_makebreak = -1;
static int hf_c15ch_mkbrk_nshlf = -1;
static int hf_c15ch_mkbrk_stm = -1;
static int hf_c15ch_mkbrk_caddr = -1;
static int hf_c15ch_mkbrk_cdata = -1;


/* nitn xlate */

/* Fields */
static int hf_c15ch_nitnxlate = -1;
static int hf_c15ch_nitnxlate_ni = -1;
static int hf_c15ch_nitnxlate_tn = -1;
static int hf_c15ch_nitnxlate_ni_tn = -1;
static int hf_c15ch_nitnxlate_equiptype = -1;
static int hf_c15ch_nitnxlate_concat_string = -1;
static int hf_c15ch_nitnxlate_sitestring = -1;
static int hf_c15ch_nitnxlate_subsitestring = -1;
static int hf_c15ch_nitnxlate_equipname = -1;
static int hf_c15ch_nitnxlate_gw_type = -1;
static int hf_c15ch_nitnxlate_parm_1 = -1;
static int hf_c15ch_nitnxlate_parm_2 = -1;
static int hf_c15ch_nitnxlate_parm_3 = -1;
static int hf_c15ch_nitnxlate_parm_4 = -1;
static int hf_c15ch_nitnxlate_key = -1;
static int hf_c15ch_nitnxlate_user_tid = -1;
static int hf_c15ch_nitnxlate_host = -1;
static int hf_c15ch_nitnxlate_tg_num = -1;
static int hf_c15ch_nitnxlate_mgcp_line_id = -1;
static int hf_c15ch_nitnxlate_gateway = -1;
static int hf_c15ch_nitnxlate_line = -1;
static int hf_c15ch_nitnxlate_bay = -1;
static int hf_c15ch_nitnxlate_shelf = -1;
static int hf_c15ch_nitnxlate_lsg = -1;
static int hf_c15ch_nitnxlate_idt_rdt = -1;
static int hf_c15ch_nitnxlate_pm = -1;
static int hf_c15ch_nitnxlate_channel = -1;
static int hf_c15ch_nitnxlate_ptrk = -1;
static int hf_c15ch_nitnxlate_pc_sts1 = -1;
static int hf_c15ch_nitnxlate_port_vt15 = -1;


static const value_string ett_c15ch_nitnxlate_gwe_types[] = {
    { 0, "NONE" },
    { 1, "H248_TRK" },
    { 2, "SIP_LN" },
    { 3, "MGCP_LN" },
    { 4, "H248_LN" },
    { 5, "NCS_LN" },
    { 0, NULL }
};

/* labels for equip (location) */
/* non-contiguous integers */
static const value_string ett_c15ch_nitnxlate_equip_types[] = {
    {   4, "UNIT" },
    {  57, "LCM_LINE" },
    {  78, "RSLM_UNIT" },
    {  79, "RSLM_LINE" },
    {  80, "4T12" },
    {  81, "RSLM_LSG" },
    {  82, "RSLM_DRAWER" },
    {  91, "ESA" },
    { 115, "RSCS_DTRK" },
    { 119, "DS1_CHANNEL" },
    { 122, "LOC_IDC" },
    { 131, "IDTL" },
    { 136, "HUB_LINE" },
    { 138, "UMP" },
    { 139, "HUB_DS1L" },
    { 145, "VLIN" },
    { 149, "GW_LINE" },
    { 151, "PTRK" },
    { 154, "GW_TRUNK" },
    { 155, "RDT" },
    { 0, NULL }
};
static value_string_ext ett_c15ch_nitnxlate_equip_types_ext = VALUE_STRING_EXT_INIT(ett_c15ch_nitnxlate_equip_types);
/* ntwk conn */

/* Fields */
static int hf_c15ch_ntwk_conn = -1;
static int hf_c15ch_ntwk_conn_pathtype = -1;
static int hf_c15ch_ntwk_conn_conntype = -1;
static int hf_c15ch_ntwk_conn_fromoptimized = -1;
static int hf_c15ch_ntwk_conn_fromsite = -1;
static int hf_c15ch_ntwk_conn_frompm = -1;
static int hf_c15ch_ntwk_conn_frompc = -1;
static int hf_c15ch_ntwk_conn_fromloop = -1;
static int hf_c15ch_ntwk_conn_fromslot = -1;
static int hf_c15ch_ntwk_conn_fromlocation = -1;
static int hf_c15ch_ntwk_conn_fromcnx = -1;
static int hf_c15ch_ntwk_conn_fromntwkni = -1;
static int hf_c15ch_ntwk_conn_fromntwktn = -1;
static int hf_c15ch_ntwk_conn_fromntwknitn = -1;
static int hf_c15ch_ntwk_conn_mbshold = -1;
static int hf_c15ch_ntwk_conn_tooptimized = -1;
static int hf_c15ch_ntwk_conn_tosite = -1;
static int hf_c15ch_ntwk_conn_topm = -1;
static int hf_c15ch_ntwk_conn_topc = -1;
static int hf_c15ch_ntwk_conn_toloop = -1;
static int hf_c15ch_ntwk_conn_toslot = -1;
static int hf_c15ch_ntwk_conn_tolocation = -1;
static int hf_c15ch_ntwk_conn_tocnx = -1;


static const value_string ett_c15ch_ntwk_conn_path_types[] = {
    { 0, "BRDCAST" },
    { 1, "1WAY" },
    { 2, "2WAY" },
    { 3, "BC_SPFC" },
    { 4, "1WAY_SPFC" },
    { 5, "BC_CMBND" },
    { 6, "1WAY_CMBND" },
    { 7, "NWLB" },
    { 8, "1WAY_2_UTR" },
    { 9, "2WAY_LB" },
    { 10, "2WAY_LSG" },
    { 0, NULL }
};

static const value_string ett_c15ch_ntwk_conn_conn_types[] = {
    { 0, "CONN_FULL" },
    { 1, "CONN_PRT_SRCE" },
    { 2, "CONN_PRT_DEST" },
    { 3, "CONN_PRT_SRDS" },
    { 4, "DISC_FULL" },
    { 5, "DISC_PRT_SRCE" },
    { 6, "DISC_PRT_DEST" },
    { 7, "DISC_PRT_SRDS" },
    { 0, NULL }
};

/* orig */

/* Fields */
static int hf_c15ch_orig = -1;
static int hf_c15ch_orig_tnblocktype = -1;
static int hf_c15ch_orig_ni = -1;
static int hf_c15ch_orig_tn = -1;
static int hf_c15ch_orig_ni_tn = -1;

static int hf_c15ch_orig_dndigits = -1;

static int hf_c15ch_orig_nidscrn = -1;
static int hf_c15ch_orig_nidaddrtype = -1;
static int hf_c15ch_orig_nidnmbrplan = -1;
static int hf_c15ch_orig_nidprivind = -1;
static int hf_c15ch_orig_upnsaved = -1;

static int hf_c15ch_orig_upndigits = -1;

static int hf_c15ch_orig_upnscrn = -1;
static int hf_c15ch_orig_upnaddrtype = -1;
static int hf_c15ch_orig_upnnmbrplan = -1;
static int hf_c15ch_orig_upnprivind = -1;
static int hf_c15ch_orig_rnpsaved = -1;

static int hf_c15ch_orig_rnpdigits = -1;

static int hf_c15ch_orig_rnpscrn = -1;
static int hf_c15ch_orig_rnpaddrtype = -1;
static int hf_c15ch_orig_rnpnmbrplan = -1;
static int hf_c15ch_orig_rnpprivind = -1;
static int hf_c15ch_orig_iptime = -1;


/* labels for blocktype */
static const value_string c15ch_orig_block_types[] = {
    {0, "CALL_REG_BUF"},
    {1, "MUX_LOOP"},
    {2, "DS30_LOOP"},
    {3, "DVCE_REG"},
    {4, "SHLF_BLOCK_DCM"},
    {5, "NSHLF_BLOCK"},
    {6, "DILOOP_BLOCK"},
    {7, "SHLF_BLOCK"},
    {8, "TIMER2_BLOCK"},
    {9, "DIGIT_BUFFER"},
    {10, "CARD_SPL"},
    {11, "CARD_8PL"},
    {12, "CARD_PPCL"},
    {13, "CARD_MISC"},
    {14, "CARD_2PL"},
    {15, "CARD_EMTRK"},
    {16, "CARD_DGT"},
    {17, "CARD_MF"},
    {18, "CARD_NOLLER"},
    {19, "CARD_PMA"},
    {20, "TRVR_REG"},
    {21, "CARD_TONE_TEST"},
    {22, "CARD_PC1"},
    {23, "CARD_EMTRK_2W"},
    {24, "CARD_ITTK"},
    {25, "CARD_LTT"},
    {26, "CARD_AUX_TONE"},
    {27, "MSG_BUF_REG"},
    {28, "TTY_PCB_REG"},
    {29, "TAPE_PCB_REG"},
    {30, "Q_INFO_BLOCK"},
    {31, "CARD_OTG_LPTRK"},
    {32, "CARD_MISC_LPTRK"},
    {33, "CARD_MF2PL"},
    {34, "CARD_CPSC"},
    {35, "CARD_PSC1"},
    {36, "CARD_ER2PL"},
    {37, "CARD_EMT_PAD_SW"},
    {38, "REM_BLOCK"},
    {39, "BR_BUFFER"},
    {40, "CARD_DTRK"},
    {41, "CARD_DMTC"},
    {42, "MTU_PCB_REG"},
    {43, "CARD_2PL_ZDB"},
    {44, "CARD_MISC_ZDB"},
    {45, "CARD_PPCL_ZDB"},
    {46, "CARD_PE_PROC"},
    {47, "CARD_SRL_ZDB"},
    {48, "CARD_ER8PL"},
    {49, "TWC_LINK_ORIG"},
    {50, "TWC_LINK_ADDED"},
    {51, "CWT_LINK_ORIG"},
    {52, "CWT_LINK_WTNG"},
    {53, "CARD_SPL_ZDB"},
    {54, "MAINT_REG"},
    {55, "CARD_MF4PL"},
    {56, "DAS_PCB_REG"},
    {57, "CARD_ESB_ZDB"},
    {58, "CARD_RCT_SPL"},
    {59, "CARD_RCT_UVSL"},
    {60, "CARD_RCT_FSR"},
    {61, "CARD_RCT_SIMP"},
    {62, "CARD_RCT_COIN"},
    {63, "SCM_BLOCK"},
    {64, "CARD_RMB_SHU"},
    {65, "CARD_ACT"},
    {66, "PMS"},
    {67, "CARD_8PL_ZDB"},
    {68, "TWC_LINK_HOLD"},
    {69, "CWT_LINK_HOLD"},
    {70, "XFER_LINK_ORIG"},
    {71, "XFER_LINK_ADDED"},
    {72, "CHD_LINK_HOLD"},
    {73, "CHD_LINK_ACT"},
    /* 74 IS UNUSED */
    {75, "TERM_IFACE"},
    {76, "SVCE_IFACE"},
    {77, "CONF_IFACE"},
    {78, "DRA_IFACE"},
    {79, "LCM_BLOCK"},
    {80, "CARD_LCML_A"},
    {81, "CARD_LCML_B"},
    {82, "LSG_BLOCK"},
    {83, "CARD_LCM_KEY"},
    {84, "CARD_LCM_ESB"},
    {85, "CARD_DRA_TRK"},
    {86, "IOID_IOBLOCK"},
    {87, "IOI_IOBLOCK"},
    {88, "UTR_BLOCK"},
    {89, "CARD_DLC_BRD"},
    {90, "DLC_PORT_REG"},
    {91, "DLC_BUF_REG"},
    {92, "AMA_RECORD_BUF"},
    {93, "SSO_BULK_BUF"},
    {94, "DLC_PORT_DBLK"},
    {95, "CARD_LCM_PWR"},
    {96, "SLC_BLOCK"},
    {97, "CARD_SLC_SPL"},
    {98, "CARD_SLC_SIMP"},
    {99, "CARD_SLC_COIN"},
    {100, "CARD_SLC_KEY"},
    {101, "CARD_SLC_PBX"},
    {102, "SLC_SHLF_BLOCK"},
    {103, "SCI_BLOCK"},
    {104, "DS1_LINK_BLOCK"},
    {105, "SRLK_IFACE_DBLK"},
    {106, "CARD_RLCM_LCT"},
    {107, "RMM_BLOCK"},
    {108, "CARD_RMPK"},
    {109, "BCU_BLOCK"},
    {110, "CARD_RSLM_RMP"},
    {111, "ESA_BLOCK"},
    {112, "CARD_RMP_ITTK"},
    {113, "SFTR_BUFFER"},
    {114, "LFTR_BUFFER"},
    {115, "LAN_LCI_BLOCK"},
    {116, "LAN_LSHF_BLOCK"},
    {117, "LAN_LSC_BLOCK"},
    {118, "LEVEL3_BLOCK"},
    {119, "LVL3_MTCE_REG"},
    {120, "CCS_SNLS_BLOCK"},
    {121, "CCS_SNL_BLOCK"},
    {122, "CCS_SNRS_BLOCK"},
    {123, "CCS_SNR_BLOCK"},
    {124, "CCS_MTCE_REG"},
    {125, "CARD_RMM_DTR"},
    {126, "SMDI_PCB_REG"},
    {127, "XLFTR_BUFFER"},
    {128, "CARD_RCU_POTS"},
    {129, "CARD_RCU_MF"},
    {130, "CARD_RCU_COIN"},
    {131, "CARD_RCU_FXB"},
    {132, "CARD_RCU_MP"},
    {133, "CARD_RCU_EPOT"},
    {134, "CARD_RCU_KEY"},
    {135, "CARD_RCU_EMF"},
    {136, "CARD_RCU_FX_KEY"},
    {137, "RCU_BLOCK"},
    {138, "CARD_RCU_ESB"},
    {139, "CARD_IBERT"},
    {140, "CARD_DPX" },
    {141, "CARD_LCML_C" },
    {142, "MBS_REG_BLK"},
    {143, "CARD_FXS"},
    {144, "CARD_FXo"},
    {145, "CARD_PBX_CELL"},
    {146, "RSCS_BLOCK"},
    {147, "RSC_D30L_BLOCK"},
    {148, "RSC_DS1_REM_BLK"},
    {149, "RSC_DS1_TRK_BLK"},
    {150, "CARD_RSCS_DTRK" },
    {151, "CARD_6X71_DATL"},
    {152, "LOOP_DS30_LBK"},
    {153, "LOOP_MLI_LBK"},
    {154, "CARD_BX27"},
    {155, "ISDN_REG_BLK"},
    {156, "IDC_BLOCK"},
    {157, "DS1_BLOCK"},
    {158, "VDS30_LOOP"},
    {159, "ISDN_PARDLD_BLK"},
    {160, "ISDN_BD_CH_BLK"},
    {161, "SMA_BLOCK"},
    {162, "IDT_BLOCK"},
    {163, "RDT_ISDN_CARD"},
    {164, "RDT_P_PHONE"},
    {165, "EDCH_BLOCK"},
    {166, "ESMA_DS1L_BLOCK"},
    {167, "TRANSACT_REG"},
    {168, "CARD_IDTL_SPL"},
    {169, "CARD_IDTL_SIMP"},
    {170, "CARD_IDTL_COIN"},
    {171, "CARD_IDTL_KEY"},
    {172, "CARD_IDTL_PBX"},
    {173, "TAFFI_DATA_BLK"},
    {174, "ISG_BLOCK"},
    {175, "ISG_DCH_BLOCK"},
    {176, "ISG_BCH_BLOCK"},
    {177, "TMC0_BLOCK"},
    {178, "EOC0_BLOCK"},
    {179, "TMC1_BLOCK"},
    {180, "EOC1_BLOCK"},
    {181, "HUB_BLOCK"},
    {182, "CARD_HUB_UMP"},
    {183, "CARD_UMP_ITTK"},
    {184, "CARD_UMP_TEST"},
    {185, "CARD_PRI_MTCE"},
    {186, "CARD_PRI_CHAN"},
    {187, "CARD_EX17_A"},
    {188, "RLD_BLOCK"},
    {189, "CARD_LMU_TEST"},
    {190, "HUB_DS1L_BLOCK"},
    {191, "PELP_BLOCK"},
    {192, "SIMRING_BLOCK"},
    {193, "CARD_VIRTUAL_LINE"},
    {194, "CARD_H248_SPL"},
    {195, "CARD_H248_COIN"},
    {196, "CARD_H248_PBX"},
    {197, "PGI_BLOCK"},
    {198, "GW1_BLOCK"},
    {199, "GW2_BLOCK"},
    {200, "GW_BLOCK"},
    {201, "CARD_SIP_SPL"},
    {202, "CARD_PTRK"},
    {203, "PTRK_IFACE_BLK"},
    {204, "PC_BLOCK"},
    {205, "CARD_H248_DTRK"},
    {206, "DS1_LOOP_BLK"},
    {207, "DS3_BLOCK"},
    {208, "RDT_BLOCK"},
    {209, "RDT_DS1L_BLOCK"},
    {210, "CARD_MGCP_SPL"},
    {211, "CARD_NCS_SPL"},
    {212, "SUBS_REG"},
    {213, "CARD_SIP_PBX"},
    {214, "OC3_BLOCK"},
    {215, "CCFN_LINK_BLK"},
    {216, "EMCC_BLOCK"},
    {217, "AGIF_BLOCK"},
    { 0, NULL}
};
static value_string_ext c15ch_orig_block_types_ext = VALUE_STRING_EXT_INIT(c15ch_orig_block_types);
/* out gwe bc */

/* Fields */
static int hf_c15ch_outgwebc = -1;
static int hf_c15ch_outgwebc_pbc_conn_ni = -1;
static int hf_c15ch_outgwebc_pbc_conn_tn = -1;
static int hf_c15ch_outgwebc_pbc_conn_ni_tn = -1;
static int hf_c15ch_outgwebc_pbc_conn_num = -1;
static int hf_c15ch_outgwebc_pbc_conn_type = -1;
static int hf_c15ch_outgwebc_bc_msg_type = -1;
static int hf_c15ch_outgwebc_op_bc_sdp_ip = -1;
static int hf_c15ch_outgwebc_op_bc_sdp_port = -1;
static int hf_c15ch_outgwebc_pbc_mdrp_mode = -1;
static int hf_c15ch_outgwebc_pbc_tst_flags = -1;


/* pathfind */
/* Fields */
static int hf_c15ch_pathfind = -1;
static int hf_c15ch_pathfind_vds30 = -1;

static int hf_c15ch_pathfind_fromgweni = -1;
static int hf_c15ch_pathfind_fromgwetn = -1;
static int hf_c15ch_pathfind_fromgwenitn = -1;
static int hf_c15ch_pathfind_fromoptimized = -1;
static int hf_c15ch_pathfind_fromsite = -1;
static int hf_c15ch_pathfind_frompm = -1;
static int hf_c15ch_pathfind_frompc = -1;
static int hf_c15ch_pathfind_fromloop = -1;
static int hf_c15ch_pathfind_fromslot = -1;
static int hf_c15ch_pathfind_fromcnx = -1;
static int hf_c15ch_pathfind_fromni = -1;
static int hf_c15ch_pathfind_fromtn = -1;
static int hf_c15ch_pathfind_fromnitn = -1;
static int hf_c15ch_pathfind_togweni = -1;
static int hf_c15ch_pathfind_togwetn = -1;
static int hf_c15ch_pathfind_togwenitn = -1;
static int hf_c15ch_pathfind_tooptimized = -1;
static int hf_c15ch_pathfind_tosite = -1;
static int hf_c15ch_pathfind_topm = -1;
static int hf_c15ch_pathfind_topc = -1;
static int hf_c15ch_pathfind_toloop = -1;
static int hf_c15ch_pathfind_toslot = -1;
static int hf_c15ch_pathfind_tocnx = -1;
static int hf_c15ch_pathfind_toni = -1;
static int hf_c15ch_pathfind_totn = -1;
static int hf_c15ch_pathfind_tonitn = -1;

/* value_string arrays to label fields */
/* for vds30 field ...*/
static const value_string c15ch_pathfind_vds30_types[] = {
    { 0, "NOT_VDS30" },
    { 1, "NEWSLOT_0" },
    { 2, "NEWSLOT_1_ADD_0" },
    { 3, "NEWSLOT_1_ADD_1" },
    { 4, "IDLE" },
    { 0, NULL }
};

/* pathidle */

/* Fields */
static int hf_c15ch_pathidle = -1;
static int hf_c15ch_pathidle_vds30 = -1;
static int hf_c15ch_pathidle_idlecode = -1;
static int hf_c15ch_pathidle_pathtype = -1;

static int hf_c15ch_pathidle_fromgweni = -1;
static int hf_c15ch_pathidle_fromgwenitn = -1;
static int hf_c15ch_pathidle_fromgwetn = -1;
static int hf_c15ch_pathidle_fromsite = -1;
static int hf_c15ch_pathidle_frompm = -1;
static int hf_c15ch_pathidle_frompc = -1;
static int hf_c15ch_pathidle_fromloop = -1;
static int hf_c15ch_pathidle_fromslot = -1;
static int hf_c15ch_pathidle_fromcnx = -1;
static int hf_c15ch_pathidle_fromni = -1;
static int hf_c15ch_pathidle_fromnitn = -1;
static int hf_c15ch_pathidle_fromtn = -1;

static int hf_c15ch_pathidle_togweni = -1;
static int hf_c15ch_pathidle_togwenitn = -1;
static int hf_c15ch_pathidle_togwetn = -1;
static int hf_c15ch_pathidle_tosite = -1;
static int hf_c15ch_pathidle_topm = -1;
static int hf_c15ch_pathidle_topc = -1;
static int hf_c15ch_pathidle_toloop = -1;
static int hf_c15ch_pathidle_toslot = -1;
static int hf_c15ch_pathidle_tocnx = -1;
static int hf_c15ch_pathidle_toni = -1;
static int hf_c15ch_pathidle_tonitn = -1;
static int hf_c15ch_pathidle_totn = -1;


/* for vds30 field */
static const value_string c15ch_pathidle_vds30_types[] = {
    { 0, "NOT_VDS30" },
    { 1, "NEWSLOT_0" },
    { 2, "NEWSLOT_1_ADD_0" },
    { 3, "NEWSLOT_1_ADD_1" },
    { 4, "IDLE" },
    { 0, NULL }
};

/* for pathtype field */
static const value_string c15ch_pathidle_path_types[] = {
    { 0, "BRDCST" },
    { 1, "1WAY" },
    { 2, "2WAY" },
    { 3, "BC_SPFC" },
    { 4, "1WAY_SPFC" },
    { 5, "BC_CMBND" },
    { 6, "1WAY_CMBND" },
    { 7, "NWLB" },
    { 8, "1WAY_2_UTR" },
    { 9, "2WAY_LB" },
    {10, "2WAY_LSG" },
    { 0, NULL }
};

/* for idlecode field */
static const value_string c15ch_pathidle_idle_types[] = {
    { 0, "FULL" },
    { 1, "PRT_SRCE" },
    { 2, "PRT_DEST" },
    { 3, "PRT_SRDS" },
    { 0, NULL }
};

/* q931 */

/* Fields */
static int hf_c15ch_q931 = -1;
static int hf_c15ch_q931_direction = -1;
static int hf_c15ch_q931_ni = -1;
static int hf_c15ch_q931_tn = -1;
static int hf_c15ch_q931_ni_tn = -1;
static int hf_c15ch_q931_msglength = -1;


/* value_string arrays to label fields */
/* for direction field */
static const value_string c15ch_q931_direction_types[] = {
    { 0, "Incoming" },
    { 1, "Outgoing" },
    { 0, NULL }
};

/* quality of service (qos) */

/* Fields */
static int hf_c15ch_qos = -1;
static int hf_c15ch_qos_ni = -1;
static int hf_c15ch_qos_tn = -1;
static int hf_c15ch_qos_ni_tn = -1;
static int hf_c15ch_qos_rtcp_call_id = -1;
static int hf_c15ch_qos_register_type = -1;
static int hf_c15ch_qos_tg_num = -1;
static int hf_c15ch_qos_trk_type = -1;
static int hf_c15ch_qos_status = -1;
static int hf_c15ch_qos_codec = -1;
static int hf_c15ch_qos_given_ip = -1;
static int hf_c15ch_qos_real_ip = -1;
static int hf_c15ch_qos_local_ip = -1;
static int hf_c15ch_qos_tx_pkts = -1;
static int hf_c15ch_qos_lost_pkts = -1;
static int hf_c15ch_qos_lost_pct = -1;
static int hf_c15ch_qos_jitter = -1;
static int hf_c15ch_qos_rtt = -1;
static int hf_c15ch_qos_avg_rtt = -1;
static int hf_c15ch_qos_duration = -1;
static int hf_c15ch_qos_mos = -1;
static int hf_c15ch_qos_ep_type = -1;
static int hf_c15ch_qos_dn_or_tg = -1;
static int hf_c15ch_qos_pm = -1;
static int hf_c15ch_qos_pc = -1;
static int hf_c15ch_qos_hour = -1;
static int hf_c15ch_qos_min = -1;
static int hf_c15ch_qos_sec = -1;
static int hf_c15ch_qos_tenth_sec = -1;
static int hf_c15ch_qos_year = -1;
static int hf_c15ch_qos_month = -1;
static int hf_c15ch_qos_day = -1;
static int hf_c15ch_qos_day_of_week = -1;


/* value_string arrays to label fields */
static const value_string ett_c15ch_qos_status_types[] = {
    { 1, "NO : No RTCP received from End" },
    { 2, "LO : Listener Only" },
    { 4, "CV : Conversation" },
    { 8, "NAT : NAT Connection" },
    { 16, "RTU : RTCP terminated by RTU" },
    { 32, "EPERR : Endpoint providing erroneous data" },
    { 64, "INACT : Inactive" },
    { 0, NULL }
};

/* route */

/* Fields */
static int hf_c15ch_route = -1;
static int hf_c15ch_route_number = -1;
static int hf_c15ch_route_type = -1;
static int hf_c15ch_route_subpm = -1;
static int hf_c15ch_route_trkpm = -1;
static int hf_c15ch_route_strtaindo = -1;
static int hf_c15ch_route_cr_rte_adv = -1;
static int hf_c15ch_route_cause = -1;


/* field labels */
/* for strtaindo field */
static const value_string c15_route_strt_ain_do_types[] = {
    { 0, "START" },
    { 1, "AIN" },
    { 2, "PROGRESS" },
    { 3, "RTADV" },
    { 0, NULL }
};

static const value_string c15_route_types[] = {
    { 0, "TONE" },
    { 1, "AUDICHRON" },
    { 2, "INTERCEPT" },
    { 3, "EAS" },
    { 4, "TIE_LINE" },
    { 5, "CAMA" },
    { 6, "CAMA_2" },
    { 7, "TSPS" },
    { 8, "AMR" },
    { 9, "STN_RING" },
    { 10, "VAXS" },
    { 11, "ROTL" },
    { 12, "TEST_LINE" },
    { 13, "ALM_CHK" },
    { 14, "DST" },
    { 15, "ESB" },
    { 16, "EQA" },
    { 17, "OS" },
    { 18, "LEAS" },
    { 19, "VDRA" },
    { 20, "ISUP" },
    { 21, "IDAL" },
    { 22, "EAOSS" },
    { 23, "LTRK" },
    { 24, "PRI" },
    { 25, "SIPT" },
    { 0, NULL }
};
static value_string_ext c15_route_types_ext = VALUE_STRING_EXT_INIT(c15_route_types);

/* Fields */
static int hf_c15ch_sccp = -1;
static int hf_c15ch_sccp_direction = -1;
static int hf_c15ch_sccp_msgtype = -1;
static int hf_c15ch_sccp_hopcount = -1;
static int hf_c15ch_sccp_transactionnum = -1;
static int hf_c15ch_sccp_opcmember = -1;
static int hf_c15ch_sccp_opccluster = -1;
static int hf_c15ch_sccp_opcnetwork = -1;
static int hf_c15ch_sccp_dpcmember = -1;
static int hf_c15ch_sccp_dpccluster = -1;
static int hf_c15ch_sccp_dpcnetwork = -1;
static int hf_c15ch_sccp_ni = -1;
static int hf_c15ch_sccp_ni_tn = -1;
static int hf_c15ch_sccp_tn = -1;
static int hf_c15ch_sccp_sls = -1;
static int hf_c15ch_sccp_iptime = -1;
static int hf_c15ch_sccp_level3index = -1;


static const value_string c15ch_sccp_direction_types[] = {
    { 0, "Incoming" },
    { 1, "Outgoing" },
    { 0, NULL }
};

static const value_string c15ch_sccp_msg_types[] = {
    { 9, "UDT" },
    { 10, "UDTS" },
    { 17, "XUDT" },
    { 18, "XUDTS" },
    { 0, NULL }
};

/* srcedest */

/* Fields */
static int hf_c15ch_srcedest = -1;
static int hf_c15ch_srcedest_conntype = -1;
static int hf_c15ch_srcedest_pathtype = -1;
static int hf_c15ch_srcedest_pathdirect = -1;


/* field labels */
/* for conntype field */
static const value_string c15_srcedest_conn_types[] = {
    { 0, "CONN_FULL" },
    { 1, "CONN_PRT_SRCE" },
    { 2, "CONN_PRT_DEST" },
    { 3, "CONN_PRT_SRDS" },
    { 4, "DISC_FULL" },
    { 5, "DISC_PRT_SRCE" },
    { 6, "DISC_PRT_DEST" },
    { 7, "DISC_PRT_SRDS" },
    { 0, NULL }
};


/* for pathtype field */
static const value_string c15_srcedest_path_types[] = {
    { 0, "BRDCST" },
    { 1, "1WAY" },
    { 2, "2WAY" },
    { 3, "BC_SPFC" },
    { 4, "1WAY_SPFC" },
    { 5, "BC_CMBND" },
    { 6, "1WAY_CMBND" },
    { 7, "NWLB" },
    { 8, "1WAY_2_UTR" },
    { 9, "2WAY_LB" },
    {10, "2WAY_LSG" },
    {11, NULL }
};

/* tcap */
/* Fields */
static int hf_c15ch_tcap = -1;
static int hf_c15ch_tcap_direction = -1;
static int hf_c15ch_tcap_action = -1;
static int hf_c15ch_tcap_package_type = -1;
static int hf_c15ch_tcap_ssn = -1;
static int hf_c15ch_tcap_local_ssn = -1;
static int hf_c15ch_tcap_result_err_code = -1;
static int hf_c15ch_tcap_return_reason = -1;
static int hf_c15ch_tcap_feat_id = -1;
static int hf_c15ch_tcap_feat_req = -1;
static int hf_c15ch_tcap_cl_comp_result = -1;
static int hf_c15ch_tcap_release_bit = -1;
static int hf_c15ch_tcap_term_cl_request = -1;
static int hf_c15ch_tcap_opc_index = -1;
static int hf_c15ch_tcap_dpc_mem = -1;
static int hf_c15ch_tcap_dpc_clus = -1;
static int hf_c15ch_tcap_dpc_net = -1;
static int hf_c15ch_tcap_cp_id = -1;

/* value strings */
static const value_string c15ch_tcap_action_types[] = {
    { 0, "Invalid" },
    { 1, "Output Msg" },
    { 2, "Abort Query" },
    { 3, "Timeout" },
    { 4, "Input Msg" },
    { 5, "Msg Ret on Err" },
    { 0, NULL }
};

static const value_string c15ch_tcap_package_types[] = {
    { 0, "Invalid" },
    { 1, "Unidirectional" },
    { 2, "Query W Perm" },
    { 3, "Query WO Perm" },
    { 4, "Response" },
    { 5, "Conv W Perm" },
    { 6, "Conv WO Perm" },
    { 16, "Abort Package" },
    { 0, NULL }
};

static const value_string c15ch_tcap_rel_bit_types[] = {
    { 0, "Hold Buffer" },
    { 1, "Release Buffer" },
    { 0, NULL }
};

static const value_string c15ch_tcap_ret_reason_types[] = {
    { 0, "GTT Trans" },
    { 1, "GTT Addr" },
    { 2, "Subsys Cong" },
    { 3, "Subsys Fail" },
    { 4, "Unequip User" },
    { 5, "Ntwk Fail" },
    { 6, "Ntwrk Cong" },
    { 0, NULL }
};

static const value_string c15ch_tcap_err_code_types[] = {
    { 0, "Class Succ" },
    { 1, "Cl Ret Err" },
    { 2, "T5 Timeout" },
    { 3, "SW Error" },
    { 4, "No Resource" },
    { 5, "CCS7 Unas" },
    { 6, "Acg Block" },
    { 7, "Abort Rcvd" },
    { 8, "Protocol" },
    { 9, "Application" },
    { 10, "T1 Timeout" },
    { 11, "Return Err" },
    { 12, "Reject" },
    { 13, "MWI T1 TO" },
    { 0, NULL }
};

static const value_string c15ch_tcap_feat_req_types[] = {
    { 0, "Invalid" },
    { 1, "Init Query" },
    { 2, "Send Notify" },
    { 3, "Busy Idle" },
    { 4, "Cancel" },
    { 5, "Dequeue" },
    { 6, "Abort" },
    { 7, "Report Err" },
    { 8, "Rsrc Clr" },
    { 9, "Update Data" },
    { 10, "EDP Cont" },
    { 11, "Term Notif" },
    { 12, "Update" },
    { 13, "Query Request" },
    { 0, NULL }
};

static const value_string c15ch_tcap_feat_id_types[] = {
    { 0, "Invalid" },
    { 1, "Acb Act" },
    { 2, "Ar 1Act" },
    { 3, "Ar 2Act 1st" },
    { 4, "Ar 2Act 2nd" },
    { 5, "Acb Deact" },
    { 6, "Ar Deact" },
    { 7, "SCREJ" },
    { 8, "SCFWD" },
    { 9, "SCACC" },
    { 10, "SC RNG CFWD" },
    { 11, "CNAM" },
    { 12, "AIN" },
    { 13, "MDSI" },
    { 0, NULL }
};


static const value_string c15ch_tcap_direction_types[] = {
    { 0, "In Orig" },
    { 1, "Out Orig" },
    { 2, "In Term" },
    { 3, "Out Term" },
    { 0, NULL }
};

static const value_string c15ch_tcap_local_ssn_types[] = {
    { 0, "NO_SUBSYSTEM" },
    { 1, "SCCP_NTWK" },
    { 2, "CLAS_SUBSYS" },
    { 3, "CNAM_SUBSYS" },
    { 4, "LDMG_SUBSYS" },
    /* 5 is unused */
    { 6, "E800_SUBSYS1" },
    { 7, "E800_SUBSYS2" },
    { 8, "E800_SUBSYS3" },
    { 9, "E800_SUBSYS4" },
    { 10, "E800_SUBSYS5" },
    { 11, "E800_SUBSYS6" },
    { 12, "E800_SUBSYS7" },
    { 13, "E800_SUBSYS8" },
    { 14, "AIN_SUBSYS" },
    { 15, "MDSI_SUBSYS" },
    { 0, NULL }
};

/* twc rswch */

/* Fields */
static int hf_c15ch_twc_rswch = -1;
static int hf_c15ch_twc_rswch_pm = -1;
static int hf_c15ch_twc_rswch_subpm = -1;
static int hf_c15ch_twc_rswch_trkpm = -1;
static int hf_c15ch_twc_rswch_devid = -1;
static int hf_c15ch_twc_rswch_event = -1;
static int hf_c15ch_twc_rswch_parm = -1;
static int hf_c15ch_twc_rswch_iptime = -1;


/* cp event */


/* Fields */
static int hf_c15ch_cp_event = -1;
static int hf_c15ch_cp_event_pm = -1;
static int hf_c15ch_cp_event_subpm = -1;
static int hf_c15ch_cp_event_trkpm = -1;
static int hf_c15ch_cp_event_dig_ckt_test_trkpm = -1;
static int hf_c15ch_cp_event_devid = -1;
static int hf_c15ch_cp_event_event = -1;
static int hf_c15ch_cp_event_parm = -1;
static int hf_c15ch_cp_event_iptime = -1;
static int hf_c15ch_cp_event_subpm_orig = -1;
static int hf_c15ch_cp_event_subpm_disc_time = -1;
static int hf_c15ch_cp_event_subpm_revert = -1;
static int hf_c15ch_cp_event_subpm_orig_dt = -1;
static int hf_c15ch_cp_event_subpm_orig_ws = -1;
static int hf_c15ch_cp_event_subpm_orig_dd = -1;
static int hf_c15ch_cp_event_subpm_orig_id = -1;
static int hf_c15ch_cp_event_subpm_no_test = -1;
static int hf_c15ch_cp_event_subpm_dialing = -1;
static int hf_c15ch_cp_event_subpm_rebuilt = -1;
static int hf_c15ch_cp_event_subpm_acfw_reac = -1;
static int hf_c15ch_cp_event_subpm_process_route = -1;
static int hf_c15ch_cp_event_subpm_rte_line = -1;
static int hf_c15ch_cp_event_subpm_mtce = -1;
static int hf_c15ch_cp_event_subpm_aux_tone = -1;
static int hf_c15ch_cp_event_subpm_noller = -1;
static int hf_c15ch_cp_event_subpm_ittk = -1;
static int hf_c15ch_cp_event_subpm_alm_send = -1;
static int hf_c15ch_cp_event_subpm_ani_spill = -1;
static int hf_c15ch_cp_event_subpm_trunk_term = -1;
static int hf_c15ch_cp_event_subpm_line_term = -1;
static int hf_c15ch_cp_event_subpm_non_cp = -1;
static int hf_c15ch_cp_event_subpm_3wc = -1;
static int hf_c15ch_cp_event_subpm_held_3wc = -1;
static int hf_c15ch_cp_event_subpm_cwt = -1;
static int hf_c15ch_cp_event_subpm_held_cwt = -1;
static int hf_c15ch_cp_event_subpm_update_sc = -1;
static int hf_c15ch_cp_event_subpm_orig_spdt = -1;
static int hf_c15ch_cp_event_subpm_acfw_retm = -1;
static int hf_c15ch_cp_event_subpm_cfw_busy = -1;
static int hf_c15ch_cp_event_subpm_cfw = -1;
static int hf_c15ch_cp_event_subpm_cfw_deact = -1;
static int hf_c15ch_cp_event_subpm_rcfw = -1;
static int hf_c15ch_cp_event_subpm_rotl_tp = -1;
static int hf_c15ch_cp_event_subpm_chdt = -1;
static int hf_c15ch_cp_event_subpm_chd = -1;
static int hf_c15ch_cp_event_subpm_cheld = -1;
static int hf_c15ch_cp_event_subpm_3wch = -1;
static int hf_c15ch_cp_event_subpm_3wcw = -1;
static int hf_c15ch_cp_event_subpm_cslt = -1;
static int hf_c15ch_cp_event_subpm_dig_ckt_test = -1;

static int hf_c15ch_cp_event_dig_ckt_test_subpm_sp = -1;
static int hf_c15ch_cp_event_dig_ckt_test_subpm_mp = -1;
static int hf_c15ch_cp_event_dig_ckt_test_subpm_coin = -1;
static int hf_c15ch_cp_event_dig_ckt_test_subpm_isdn = -1;
static int hf_c15ch_cp_event_dig_ckt_test_subpm_trc = -1;
static int hf_c15ch_cp_event_dig_ckt_test_subpm_disc = -1;

static int hf_c15ch_cp_event_subpm_nail = -1;
static int hf_c15ch_cp_event_subpm_dcbi = -1;
static int hf_c15ch_cp_event_subpm_rag_confirm = -1;
static int hf_c15ch_cp_event_subpm_rag_process = -1;
static int hf_c15ch_cp_event_subpm_e800 = -1;
static int hf_c15ch_cp_event_subpm_cfra = -1;
static int hf_c15ch_cp_event_subpm_mwi_deac = -1;
static int hf_c15ch_cp_event_subpm_acar_cp = -1;
static int hf_c15ch_cp_event_subpm_acar_rering = -1;
static int hf_c15ch_cp_event_subpm_acar_ann = -1;
static int hf_c15ch_cp_event_subpm_sle = -1;
static int hf_c15ch_cp_event_subpm_perform_cot = -1;
static int hf_c15ch_cp_event_subpm_clid = -1;
static int hf_c15ch_cp_event_subpm_xpm = -1;
static int hf_c15ch_cp_event_subpm_mwil = -1;
static int hf_c15ch_cp_event_subpm_ldbs = -1;
static int hf_c15ch_cp_event_subpm_acr = -1;
static int hf_c15ch_cp_event_subpm_call_park = -1;
static int hf_c15ch_cp_event_subpm_camp_on_recall = -1;
static int hf_c15ch_cp_event_subpm_cff = -1;
static int hf_c15ch_cp_event_subpm_ibert = -1;
static int hf_c15ch_cp_event_subpm_ain = -1;
static int hf_c15ch_cp_event_subpm_ain_sit = -1;
static int hf_c15ch_cp_event_subpm_ain_rtg = -1;
static int hf_c15ch_cp_event_subpm_nail_bcon = -1;
static int hf_c15ch_cp_event_subpm_nail_dcon = -1;
static int hf_c15ch_cp_event_subpm_qtrn_trvr = -1;
static int hf_c15ch_cp_event_subpm_ekts = -1;
static int hf_c15ch_cp_event_subpm_alt = -1;
static int hf_c15ch_cp_event_subpm_calea = -1;
static int hf_c15ch_cp_event_subpm_sim_ring = -1;
static int hf_c15ch_cp_event_subpm_lta = -1;
static int hf_c15ch_cp_event_subpm_hgq = -1;
static int hf_c15ch_cp_event_subpm_idle = -1;
static int hf_c15ch_cp_event_subpm_sig = -1;
static int hf_c15ch_cp_event_subpm_sig_dest = -1;
static int hf_c15ch_cp_event_subpm_agl_splrg = -1;


/*static const guint32 MIN_PM_VAL = 0; */
static const guint32 MAX_PM_VAL = 77;
static int * subpm_table[] = {
    /* one entry for each PM type */
    &hf_c15ch_cp_event_subpm_orig,            /* MIN_PM_VAL */
    &hf_c15ch_cp_event_subpm_disc_time,
    &hf_c15ch_cp_event_subpm_revert,
    &hf_c15ch_cp_event_subpm_orig_dt,
    &hf_c15ch_cp_event_subpm_orig_ws,
    &hf_c15ch_cp_event_subpm_orig_dd,
    &hf_c15ch_cp_event_subpm_orig_id,
    &hf_c15ch_cp_event_subpm_no_test,
    &hf_c15ch_cp_event_subpm_dialing,
    &hf_c15ch_cp_event_subpm_rebuilt,
    &hf_c15ch_cp_event_subpm_acfw_reac,
    &hf_c15ch_cp_event_subpm_process_route,
    &hf_c15ch_cp_event_subpm_rte_line,
    &hf_c15ch_cp_event_subpm_mtce,
    &hf_c15ch_cp_event_subpm_aux_tone,
    &hf_c15ch_cp_event_subpm_noller,
    &hf_c15ch_cp_event_subpm_ittk,
    &hf_c15ch_cp_event_subpm_alm_send,
    &hf_c15ch_cp_event_subpm_ani_spill,
    &hf_c15ch_cp_event_subpm_trunk_term,
    &hf_c15ch_cp_event_subpm_line_term,
    &hf_c15ch_cp_event_subpm_non_cp,
    &hf_c15ch_cp_event_subpm_3wc,
    &hf_c15ch_cp_event_subpm_held_3wc,
    &hf_c15ch_cp_event_subpm_cwt,
    &hf_c15ch_cp_event_subpm_held_cwt,
    &hf_c15ch_cp_event_subpm_update_sc,
    &hf_c15ch_cp_event_subpm_orig_spdt,
    &hf_c15ch_cp_event_subpm_acfw_retm,
    &hf_c15ch_cp_event_subpm_cfw_busy,
    &hf_c15ch_cp_event_subpm_cfw,
    &hf_c15ch_cp_event_subpm_cfw_deact,
    &hf_c15ch_cp_event_subpm_rcfw,
    &hf_c15ch_cp_event_subpm_rotl_tp,
    &hf_c15ch_cp_event_subpm_chdt,
    &hf_c15ch_cp_event_subpm_chd,
    &hf_c15ch_cp_event_subpm_cheld,
    &hf_c15ch_cp_event_subpm_3wch,
    &hf_c15ch_cp_event_subpm_3wcw,
    &hf_c15ch_cp_event_subpm_cslt,
    &hf_c15ch_cp_event_subpm_dig_ckt_test,    /* default variable for dig ckt pm*/
    &hf_c15ch_cp_event_subpm_nail,
    &hf_c15ch_cp_event_subpm_dcbi,
    &hf_c15ch_cp_event_subpm_rag_confirm,
    &hf_c15ch_cp_event_subpm_rag_process,
    &hf_c15ch_cp_event_subpm_e800,
    &hf_c15ch_cp_event_subpm_cfra,
    &hf_c15ch_cp_event_subpm_mwi_deac,
    &hf_c15ch_cp_event_subpm_acar_cp,
    &hf_c15ch_cp_event_subpm_acar_rering,
    &hf_c15ch_cp_event_subpm_acar_ann,
    &hf_c15ch_cp_event_subpm_sle,
    &hf_c15ch_cp_event_subpm_perform_cot,
    &hf_c15ch_cp_event_subpm_clid,
    &hf_c15ch_cp_event_subpm_xpm,
    &hf_c15ch_cp_event_subpm_mwil,
    &hf_c15ch_cp_event_subpm_ldbs,
    &hf_c15ch_cp_event_subpm_acr,
    &hf_c15ch_cp_event_subpm_call_park,
    &hf_c15ch_cp_event_subpm_camp_on_recall,
    &hf_c15ch_cp_event_subpm_cff,
    &hf_c15ch_cp_event_subpm_ibert,
    &hf_c15ch_cp_event_subpm_ain,
    &hf_c15ch_cp_event_subpm_ain_sit,
    &hf_c15ch_cp_event_subpm_ain_rtg,
    &hf_c15ch_cp_event_subpm_nail_bcon,
    &hf_c15ch_cp_event_subpm_nail_dcon,
    &hf_c15ch_cp_event_subpm_qtrn_trvr,
    &hf_c15ch_cp_event_subpm_ekts,
    &hf_c15ch_cp_event_subpm_alt,
    &hf_c15ch_cp_event_subpm_calea,
    &hf_c15ch_cp_event_subpm_sim_ring,
    &hf_c15ch_cp_event_subpm_lta,
    &hf_c15ch_cp_event_subpm_hgq,
    &hf_c15ch_cp_event_subpm_idle,
    &hf_c15ch_cp_event_subpm_sig,
    &hf_c15ch_cp_event_subpm_sig_dest,
    &hf_c15ch_cp_event_subpm_agl_splrg
    /* MAX_PM_VAL */
};
static const guint32 DIG_CKT_TEST_PM_VALUE = 40;

/* special table to look up subpm for pm_val = DIG_CKT_TEST__PM_VALUE */
/* this table is indexed by trunk pm numbers */
/*static const guint32 MIN_DIG_CKT_TEST_TRKPM_VAL = 0; */
static const guint32 MAX_DIG_CKT_TEST_TRKPM_VAL = 5;
static int * dig_ckt_test_subpm_table[] = {
    /* one entry for each TRKPM value in the expected range */
    &hf_c15ch_cp_event_dig_ckt_test_subpm_sp,            /* MIN_DIG_CKT_TEST_TRKPM_VAL */
    &hf_c15ch_cp_event_dig_ckt_test_subpm_mp,
    &hf_c15ch_cp_event_dig_ckt_test_subpm_coin,
    &hf_c15ch_cp_event_dig_ckt_test_subpm_isdn,
    &hf_c15ch_cp_event_dig_ckt_test_subpm_trc,
    &hf_c15ch_cp_event_dig_ckt_test_subpm_disc            /* MAX_DIG_CKT_TEST_TRKPM_VAL */
};

static const value_string dig_ckt_test_subpm_sp_types[] = {
/* a value_string_ext for this has not been defined because it is a member of array dig_ckt_test_subpm_name_tables
and the other members of that array all have less than 20 items */
    {0, "CRD_MSNG_TEST"},
    {1, "SET_UP"},
    {2, "HNDL_MODE_2"},
    {3, "WAIT_CTU_SCA"},
    {4, "WAIT_ACM_CON"},
    {5, "RDT_OFFHOOK"},
    {6, "SEND_ECHO_TONE"},
    {7, "ECHO_TONE_RESP"},
    {8, "SEND_ECHO_MEAS"},
    {9, "ECHO_MEAS_RESP"},
    {10, "SEND_STOP_ECHO_TONE"},
    {11, "STOP_ECHO_TONE_RESP"},
    {12, "RDT_ONHOOK"},
    {13, "RDT_SPRING"},
    {14, "POTS_OR_COIN"},
    {15, "RMOV_ASORB_P"},
    {16, "RFLEC_TERM"},
    {17, "SEND_LOSS_TONE"},
    {18, "LOSS_TONE_RESP"},
    {19, "SEND_LOSS_MEAS"},
    {20, "LOSS_MEAS_RESP"},
    {21, "SEND_QUIET_TONE"},
    {22, "QUIET_TONE_RESP"},
    {23, "SEND_IDLE_MEAS"},
    {24, "IDLE_MEAS_RESP"},
    {25, "RMOV_RFLC"},
    {0, NULL}
};

static const value_string dig_ckt_test_subpm_mp_types[] = {
    {0, "START_MP"},
    {1, "NEG_S_TONE"},
    {2, "NEG_S_MEAS"},
    {3, "ANI_RESP"},
    {4, "RMOV_NTPI"},
    {5, "ABSORB_TERM"},
    {6, "POS_S_TONE"},
    {7, "POS_S_MEAS"},
    {8, "POS_S_ANI"},
    {9, "ABSO_RMOV"},
    {10, "PTPI_TERM"},
    {11, "POS_T_TONE"},
    {12, "POS_T_MEAS"},
    {13, "RDT_NTPR"},
    {14, "RDT_PRPR"},
    {15, "RDT_PTPR"},
    {0, NULL}
};

static const value_string dig_ckt_test_subpm_coin_types[] = {
    {0, "START_COIN"},
    {1, "POS_C_TONE"},
    {2, "POS_C_MEAS"},
    {3, "COIN_PRES"},
    {4, "RMOV_PTPI"},
    {5, "RFL_NTPI_TRM"},
    {6, "NEG_C_TONE"},
    {7, "NEG_C_MEAS"},
    {8, "NEG_C_RSP"},
    {9, "RFL_NTPI_RMV"},
    {10, "POS_C_TERM"},
    {11, "POS_C_TONE2"},
    {12, "POS_C_MEAS2"},
    {13, "LOOP_DLY"},
    {14, "LOOP_MEAS"},
    {15, "RDT_C_CLCT"},
    {16, "RDT_C_RV_BT"},
    {17, "RDT_C_RET"},
    {0, NULL}
};

static const value_string dig_ckt_test_subpm_isdn_types[] = {
    {0, "CRD_MSNG_TEST"},
    {1, "SZ_LN_MTCE"},
    {2, "LC_RSTR_TEST"},
    {3, "U_CNT_TEST"},
    {4, "NT1_RSTR_TST"},
    {5, "NT1_STAT_TEST"},
    {6, "NEBE_TEST"},
    {7, "FEBE_TEST"},
    {8, "RLS_LN_MTCE"},
    {0, NULL}
};

static const value_string dig_ckt_test_subpm_trc_types[] = {
    {0, NULL}
};

static const value_string dig_ckt_test_subpm_disc_types[] = {
    {0, NULL}
};

static const value_string * dig_ckt_test_subpm_name_tables[] = {
    /* one entry for each TRKPM value in the expected range */
    dig_ckt_test_subpm_sp_types,
    dig_ckt_test_subpm_mp_types,
    dig_ckt_test_subpm_coin_types,
    dig_ckt_test_subpm_isdn_types,
    dig_ckt_test_subpm_trc_types,
    dig_ckt_test_subpm_disc_types
};

/* valid indexes run from MIN_DIG_CKT_TEST__TRKPM_VAL to MAX_DIG_CKT_TEST__TRKPM_VAL */
static const value_string trkpm_dig_ckt_test_types[] = {
    {0, "TEST_SP"},
    {1, "TEST_MP"},
    {2, "TEST_COIN"},
    {3, "TEST_ISDN"},
    {4, "WAIT_TRC_RESP"},
    {5, "WAIT_DISC_CONN"},
    {0, NULL}
};

/* various subpm tables */
static const value_string subpm_orig_types[] = {
    {0, "SET_UP"},
    {1, "SCM_CHANNEL"},
    {2, "P409_GRD_SRT"},
    {3, "ANI_TEST"},
    {4, "WAIT_RMB"},
    {5, "WAIT_FX_HIT"},
    {6, "WAIT_RSRC"},
    {7, "WAIT_ICOT_RSRC"},
    {8, "WAIT_LPA"},
    {9, "WAIT_COT_MSG"},
    {10, "WT_COT_RCHK"},
    {11, "WT_MADN_TONE"},
    {12, "MADN_TONE"},
    {13, "MADN_NOTONE"},
    {14, "FX_DIAL_DLAY"},
    {15, "WAIT_BD_RPY"},
    {16, "DELAY_IDTL_LKOT"},
    {17, "WT_H248_CTX1D"},
    {18, "WAIT_MSDN_PCA"},
    {19, "WT_H248_CTXAV"},
    {0, NULL}
};


static const value_string subpm_disc_time_types[] = {
    {0, "SET_UP"},
    {1, "WAIT_DISC"},
    {2, "HOLD_IDLE"},
    {3, "LOOP_DISC"},
    {4, "LOOP_TIME"},
    {5, "WAIT_FX0_DSC"},
    {0, NULL}
};

static const value_string subpm_revert_types[] = {
    {0, "SET_UP"},
    {1, "AWAIT_RSRC"},
    {2, "AWAIT_DIGIT"},
    {3, "BUSY_TONE"},
    {4, "INFORM_CLG"},
    {5, "WAIT_ONHK"},
    {6, "WAIT_TCAP"},
    {7, "RINGING"},
    {8, "INFORM_CLD"},
    {9, "TALKING"},
    {10, "RING_FAIL"},
    {11, "ANI_TEST"},
    {0, NULL}
};

static const value_string subpm_orig_dt_types[] = {
    {0, "SET_UP"},
    {1, "WAIT_DT"},
    {2, "DIAL_TONE"},
    {3, "FX_DIAL_DLAY"},
    {4, "WAIT_DT_PCA"},
    {0, NULL}
};

static const value_string subpm_orig_ws_types[] = {
    {0, "SET_UP"},
    {1, "WAIT_RCVR"},
    {2, "FX_DIAL_DLAY"},
    {0, NULL}
};

static const value_string subpm_orig_dd_types[] = {
    {0, "SET_UP"},
    {1, "WAIT_HIT_DELAY"},
    {2, "WAIT_FOR_RCVR"},
    {0, NULL}
};

static const value_string subpm_orig_id_types[] = {
    {0, "SET_UP"},
    {1, "WAIT_FOR_RCVR"},
    {0, NULL}
};

static const value_string subpm_no_test_types[] = {
    {0, NULL}
};

static const value_string subpm_dialing_types[] = {
    {0, "SET_UP"},
    {1, "DP_DGT_FIRST"},
    {2, "DP_DGT_DIAL"},
    {3, "WAIT_FOR_KP"},
    {4, "MF_DIALING"},
    {5, "COLL_GIC_DIG"},
    {6, "CPW_PROG_1ST"},
    {7, "CPW_PROG_NXT"},
    {8, "COLL_SC_INDX"},
    {9, "CONFIRM_TONE"},
    {10, "WAIT_CONFIRM"},
    {11, "FX_SND_DLNG"},
    {12, "AUD_PROG_1ST"},
    {13, "AUD_PROG_NXT"},
    {14, "ISDN_FA_DLNG"},
    {15, "ISDN_CFW_NXT"},
    {16, "CLD_SCFW_FA"},
    {17, "WAIT_CNFR_PCA"},
    {0, NULL}
};

static const value_string subpm_rebuilt_types[] = {
    {0, "REBILT_NORM"},
    {1, "REBILT_QUE"},
    {2, "REBILT_TIMIN"},
    {3, "REBILT_Q_T"},
    {0, NULL}
};

static const value_string subpm_acfw_reac_types[] = {
    {0, "REAC_SETUP"},
    {1, "WAIT_SPDT"},
    {2, "PROVIDE_SPDT"},
    {3, "COLLECT_DIGS"},
    {4, "WAIT_ACT_CFM"},
    {5, "PROV_ACT_CFM"},
    {0, NULL}
};

static const value_string subpm_process_route_types[] = {
    {0, NULL}
};

static const value_string subpm_rte_line_types[] = {
/* a value_string_ext has not been defined for this because it is a member of the array subpm_name_tables.
This is the longest member of that array.  There are also two members with 30-40 items. */
    {0, "SET_UP"},
    {1, "SRCE_CNTRL"},
    {2, "ANI_TEST"},
    {3, "CPSC_SELECT"},
    {4, "CPSC_TERM"},
    {5, "HUNT_SLICE"},
    {6, "SCM_CHNL"},
    {7, "PRERNG_TST"},
    {8, "SRCE_TEST"},
    {9, "RINGING_LINE"},
    {10, "DEST_TEST"},
    {11, "ANSWER_TIME"},
    {12, "WAIT_TIMING"},
    {13, "WAIT_INC_COT"},
    {14, "WAIT_LCM_CLI"},
    {15, "WAIT_CNAM_RS"},
    {16, "WAIT_ACR_RES"},
    {17, "DPX_SEIZE"},
    {18, "DPX_ANSWR"},
    {19, "MADN_SLICE"},
    {20, "LTRK_SELECT"},
    {21, "FXS_DIAL_OPL"},
    {22, "LTRK_OPL_DLY"},
    {23, "LTRK_OPLSING"},
    {24, "LTRK_WT_ANS"},
    {25, "ISDN_RT_BRK"},
    {26, "ISDN_PRESENT"},
    {27, "ISDN_PROCDG"},
    {28, "ISDN_ALERTING"},
    {29, "PROGRESS_CLR"},
    {30, "WAIT_SCP_RSP"},
    {31, "EKTS_SLICE"},
    {32, "EKTS_OFFERED"},
    {33, "TELE_WAIT_TCAP"},
    {34, "TELE_WAIT_COT_OR_TCAP"},
    {35, "TELE_TCAP_WAIT_COT"},
    {36, "TELE_WAIT_RCVR"},
    {37, "TELE_WAIT_ON_WINK"},
    {38, "TELE_WAIT_ON_COT"},
    {39, "TELE_VRDA_TRUNKS_BUSY"},
    {40, "TELE_OUTPULSE_BUSY"},
    {41, "TELE_WAIT_START"},
    {42, "TELE_COLLECT_DIG"},
    {43, "SRNG_NO_PDN"},
    {44, "WT_PKTCONN"},
    {45, "MADN_H248_WAIT_CNXID"},
    {46, "MADN_ANS_WAIT_PCA"},
    {47, "TELE_WAIT_RCVR_PCA"},
    {48, "WAIT_CTXID"},
    {0, NULL}
};

static const value_string subpm_mtce_types[] = {
    {27, "ISUP_MAINT"},
    {28, "QPL_MAINT"},
    {0, NULL}
};

static const value_string subpm_aux_tone_types[] = {
    {0, "SETUP"},
    {1, "SEIZED"},
    {2, "WAIT_FOR_TONE"},
    {3, "APPLY_TONE"},
    {0, NULL}
};

static const value_string subpm_noller_types[] = {
    {0, "SET_UP"},
    {1, "IDLE"},
    {2, "WAIT_MF_RCVR1"},
    {3, "DIALING_DN"},
    {4, "OVFLW_TONE"},
    {5, "VERIFY_CONN"},
    {6, "WAIT_MF_RCVR2"},
    {7, "DIALING_TC"},
    {8, "TEST_CONN"},
    {9, "WAIT_TIMING"},
    {0, NULL}
};

static const value_string subpm_ittk_types[] = {
    {0, "SET_UP"},
    {1, "WAIT_STRT_DLNG"},
    {2, "WAIT_FOR_RCVR"},
    {3, "TR_REV_DELAY"},
    {4, "WTBG_DIAL"},
    {5, "DN_DIALING"},
    {6, "DP_DIAL"},
    {7, "WAIT_END_DLNG"},
    {8, "NRML_SUPRVSN"},
    {9, "BUSY_MONITOR"},
    {10, "BM_TEMP"},
    {11, "NO_MONITOR"},
    {12, "NM_TEMP"},
    {13, "BUSY_TONE"},
    {14, "OUT_TEST"},
    {15, "IN_TEST__ID"},
    {16, "TT_TEST"},
    {17, "INTERCEPT_ID"},
    {18, "OVERFLOW"},
    {19, "CK_TRUE_DISC"},
    {20, "WAIT_BI_SET"},
    {21, "WAIT_BYPASS_CONN"},
    {22, "WAIT_BI_CLR"},
    {23, "SLC_OUT_TEST"},
    {24, "WAIT_BURSTS"},
    {25, "WAIT_TONE"},
    {26, "FIRST_TONE_ON"},
    {27, "FIRST_TONE_OFF"},
    {28, "SECOND_TONE_ON"},
    {29, "SECOND_TONE_OFF"},
    {30, "THIRD_TONE_ON"},
    {31, "WAIT_SLEEVE"},
    {32, "WAIT_VLCM"},
    {33, "WAIT_IDT/IDT_TO_MMB"},
    {34, "IDT_BYPASS"},
    {35, "WAIT_IDT_BPS"},
    {36, "TEST_IDT"},
    {0, NULL}
};

static const value_string subpm_alm_send_types[] = {
    {0, NULL}
};

static const value_string subpm_ani_spill_types[] = {
    {0, "SET_UP"},
    {1, "WAIT_MF_RCVR"},
    {2, "WAIT_ANI_KP"},
    {3, "WAIT_ANI_ID"},
    {4, "COLLECT_CLG_DIG"},
    {5, "WT_ONI_ANIF_ST"},
    {6, "ANI_TIMEOUT"},
    {7, "WAIT_DELAY"},
    {0, NULL}
};

static const value_string subpm_trunk_term_types[] = {
    {0, "SET_UP"},
    {1, "NORM_TALK"},
    {2, "DISC_TIMING"},
    {3, "COIN_COLLECT"},
    {4, "COIN_RETURN"},
    {5, "DEST_TONE"},
    {6, "WT_DEST_RCVR"},
    {7, "WT_SRCE_RCVR"},
    {8, "INBAND_DEST"},
    {9, "INBAND_SRCE"},
    {10, "HWL_INTR_RBK"},
    {11, "WT_HW_IT_RBK"},
    {12, "INTR_RGBK"},
    {13, "OS_FROM_DEST"},
    {14, "OS_FROM_SRCE"},
    {15, "TIME_CHG_CTL"},
    {16, "WAIT_CC_COL"},
    {17, "WAIT_CC_RET"},
    {18, "OVFL_RGBK"},
    {19, "WAIT_CC_MFST"},
    {20, "WAIT_CC_ENBL"},
    {21, "WAIT_CC_DSBL"},
    {22, "OS_HOLD"},
    {23, "CBARA_COL"},
    {24, "CBARA_RTN"},
    {25, "CBARA_RLSE"},
    {26, "WT_TLNK_HSHK"},
    {27, "WT_TLNK_SYNC"},
    {28, "WAIT_OUTPULSE_END"},
    {29, "WAIT_ALDP_TONE"},
    {30, "WAIT_OUTPULSE_DELAY"},
    {31, "WAIT_OSNC_CC"},
    {32, "WT_REPL_PCAV_TRK"},
    {0, NULL}
};

static const value_string subpm_line_term_types[] = {
    {0, "SET_UP"},
    {1, "NORM_TALKING"},
    {2, "DISC_TIMING"},
    {3, "COIN_COLLECT"},
    {4, "COIN_RETURN"},
    {5, "WAIT_RCVR"},
    {6, "INBAND_SIG"},
    {7, "HWL_INTR_RRG"},
    {8, "WT_HW_IT_RRG"},
    {9, "INTR_RERING"},
    {10, "SOURCE_TONE"},
    {11, "OVFL_RERING"},
    {12, "WAIT_BI_TONE"},
    {13, "BI_TONE_ON"},
    {14, "DCBI_3WC_Z"},
    {15, "TIME_CHG_CTL"},
    {16, "WAIT_DTR"},
    {17, "WT_TLNK_DLY"},
    {18, "WT_TLNK_HSHK"},
    {19, "WT_TLNK_SYNC"},
    {20, "WAIT_ALDP_TONE"},
    {21, "WT_PCAV_DCBI"},
    {22, "WT_REPL_PCAV"},
    {0, NULL}
};

static const value_string subpm_non_cp_types[] = {
    {0, "CR_SUB_PM_ZERO"},
    {1, "ONHK_TEST_PED"},
    {2, "ONHK_TEST_RES"},
    {3, "PEPR_MTCE_STATE"},
    {4, "GEN_TIMING_REG"},
    {5, "CPT_CONNECTION"},
    {6, "OFHK_TEST_PED"},
    {7, "OFHK_TEST_RES"},
    {8, "CR_TIMING_TEST"},
    {9, "CR_SUB_PM_INVLD"},
    {0, NULL}
};

static const value_string subpm_twc_types[] = {
    {0, "SET_UP"},
    {1, "CONN_ADDED"},
    {2, "TALK_3WAY"},
    {3, "RESW_Y_HELD"},
    {4, "RESW_Y_TALK"},
    {5, "RESW_ADDED"},
    {6, "CONNZ_YGONE"},
    {7, "CSLT_ORG"},
    {8, "CSLT_TALK_Y"},
    {9, "TRANSFER"},
    {10, "RESW_TRNSFER"},
    {11, "CSLT_XYGONE"},
    {12, "CSLT_XZGONE"},
    {13, "TALKY_XYGONE"},
    {14, "TALKY_XZGONE"},
    {15, "X_CLASS_ONLY"},
    {16, "RESW_XYGONE"},
    {0, NULL}
};

static const value_string subpm_held_3wc_types[] = {
    {0, "CR_SUB_PM_ZERO"},
    {1, "ONHK_TEST_PED"},
    {2, "ONHK_TEST_RES"},
    {3, "PEPR_MTCE_STATE"},
    {0, NULL}
};

static const value_string subpm_cwt_types[] = {
    {0, NULL}
};

static const value_string subpm_held_cwt_types[] = {
    {0, NULL}
};

static const value_string subpm_update_sc_types[] = {
    {0, "SETUP"},
    {1, "WAIT_SPDT"},
    {2, "HAVE_SPDT"},
    {3, "GET_INDEX"},
    {4, "GET_DIGITS"},
    {5, "WAIT_CONFRM"},
    {6, "HAVE_CONFRM"},
    {7, "WAIT_SPDT_PCA"},
    {8, "WAIT_CNFM_PCA"},
    {9, "WT_H248_CTXID"},
    {0, NULL}
};

static const value_string subpm_acfw_retm_types[] = {
    {0, "RETM_SETUP"},
    {1, "RETIMING"},
    {0, NULL}
};

static const value_string subpm_cfw_busy_types[] = {
    {0, "SETUP"},
    {1, "BUSY_TIMING"},
    {0, NULL}
};

static const value_string subpm_cfw_types[] = {
    {0, "SET_UP"},
    {1, "RT_BREAK"},
    {2, "REMIND_RING"},
    {3, "SCM_CHNL"},
    {0, NULL}
};

static const value_string subpm_cfw_deact_types[] = {
    {0, "DEACT_SETUP"},
    {1, "WAIT_DE_CPM"},
    {2, "PROV_DE_CPM"},    /* note that values are not continuous */
    {8, "WAIT_CNFR_PCA"},
    {0, NULL}
};

static const value_string subpm_rcfw_types[] = {
    {0, "SET_UP"},
    {1, "SRCE_CNTRL"},
    {2, "WAIT_COT"},
    {0, NULL}
};

static const value_string subpm_rotl_tp_types[] = {
    {0, "SET_UP"},
    {1, "FIRST_DIGIT"},
    {2, "SEC_DIGIT"},
    {3, "THIRD_DIGIT"},
    {4, "COL_TRK_INFO"},
    {5, "COL_DN_INFO"},
    {6, "END_OUTPULSE"},
    {7, "WAIT_COT"},
    {8, "WAIT_ACM"},
    {9, "WAIT_ANM"},
    {10, "ANS_SUPV"},
    {11, "LTBT_CONN"},
    {12, "TEST_CONN"},
    {13, "COL_ID_DIGIT"},
    {14, "WAIT_SIGNAL"},
    {15, "WAIT_ST_SIG"},
    {16, "WAIT_ANI_SIG"},
    {17, "END_ANI_SPILL"},
    {18, "ROTLTP_ONHK"},
    {19, "COL_TG_INFO"},
    {20, "WAIT_TO_SEND"},
    {21, "WAIT_CONN_APR"},
    {0, NULL}
};

static const value_string subpm_chdt_types[] = {
    {0, "SETUP"},
    {1, "WAIT_CFT"},
    {2, "CFT"},
    {3, "WAIT_DT"},
    {4, "DIAL_TONE"},
    {5, "WAIT_SPDT"},
    {6, "SPDT"},
    {0, NULL}
};

static const value_string subpm_chd_types[] = {
    {0, "SETUP"},
    {1, "CONN_ACT"},
    {2, "SRCE_RERING"},
    {3, "DEST_RERING"},
    {4, "SILENCE"},
    {5, "SIL_W_GONE"},
    {0, NULL}
};

static const value_string subpm_cheld_types[] = {
    {0, "SETUP"},
    {1, "NVP"},
    {0, NULL}
};

static const value_string subpm_dig_ckt_test_types[] = {
    {0, NULL}
};

static const value_string subpm_nail_types[] = {
    {0, NULL}
};

static const value_string subpm_dcbi_types[] = {
    {0, "DCBI_SETUP"},
    {1, "DCBI_CNTRL"},
    {2, "DCBI_RESW_XY"},
    {3, "DCBI_RESW_YZ"},
    {0, NULL}
};

static const value_string subpm_rag_confirm_types[] = {
    {0, "SETUP"},
    {1, "WAIT"},
    {2, "ON"},
    {0, NULL}
};

static const value_string subpm_rag_process_types[] = {
    {0, "SETUP"},
    {1, "SEARCH"},
    {2, "SCM_CHANNEL"},
    {3, "PRERNG_TEST"},
    {4, "WAIT_TCAP"},
    {5, "RERING"},
    {6, "MBS_RERING"},
    {7, "DELAY_CONN"},
    {8, "WT_H248_CTXID"},
    {0, NULL}
};

static const value_string subpm_e800_types[] = {
    {0, "SET_UP"},
    {1, "COLLECT_DIG"},
    {2, "WT_FGD_DIG"},
    {3, "WT_COR_RCVR"},
    {4, "WT_FGID_II"},
    {5, "WT_FGD_ANI"},
    {6, "WT_FGD_CLDKP"},
    {7, "WT_FGD_CLED"},
    {8, "WAIT_RESP"},
    {9, "CLCT_AT_DIG"},
    {10, "DLY_2ND_STG"},
    {11, "DLY_B4_ACK"},
    {0, NULL}
};

static const value_string subpm_cfra_types[] = {
    {0, "SET_UP"},
    {1, "SRCE_CNTRL"},
    {2, "WAIT_COT"},
    {3, "ANI_TEST"},
    {4, "CPSC_SELECT"},
    {5, "CAMA_OPR"},
    {6, "WAIT_RGBK"},
    {7, "RBT"},
    {8, "WAIT_TIMER"},
    {9, "WAIT_SPDT"},
    {10, "WAIT_ANS"},
    {11, "SPDT1"},
    {12, "DN_COLLECT"},
    {13, "PIN_COLLECT"},
    {14, "SPDT2"},
    {15, "ACT_DACT_COL"},
    {16, "SPDT3"},
    {17, "FWD_TO_COLL"},
    {18, "WT_DACT_CNFR"},
    {19, "WT_ACT_CNFR"},
    {20, "CNFR_TONE"},
    {0, NULL}
};

static const value_string subpm_mwi_deac_types[] = {
    {0, "SETUP_CONFRM"},
    {1, "WAIT_CONFRM"},
    {2, "HAVE_CONFRM"},
    {0, NULL}
};

static const value_string subpm_acar_cp_types[] = {
    {0, "SET_UP"},
    {1, "WAIT_I_BSP"},
    {2, "ACAR_CALL_PMS"},
    {0, NULL}
};

static const value_string subpm_acar_rering_types[] = {
    {0, "SET_UP"},
    {1, "SCM_CHANNEL"},
    {2, "WAIT_TCAP"},
    {3, "RERING_LOCL"},
    {4, "WAIT_FINAL_Q"},
    {5, "WT_H248_CTXID"},
    {0, NULL}
};

static const value_string subpm_acar_ann_types[] = {
    {0, "SET_UP"},
    {1, "DRA_BUSY"},
    {2, "DRA_WAIT"},
    {3, "DRA_MSG_BUSY"},
    {4, "DRA_MSG_WAIT"},
    {5, "DRA_MSG_ACT"},
    {6, "DRA_MSG_DIAL"},
    {7, "DRA_END_DLY"},
    {8, "WT_TCAP_RESP"},
    {9, "GET_CONF_DIG"},
    {10, "WAIT_RCVR_PCA"},
    {0, NULL}
};

static const value_string subpm_sle_types[] = {
    {0, "SETUP"},
    {1, "LIST_EDIT"},
    {2, "LIST_ADD"},
    {3, "LIST_DELETE"},
    {4, "LIST_REVIEW"},
    {5, "CHG_STATUS"},
    {6, "LISTEN_ERR"},
    {7, "EXIT"},
    {8, "DEL_ALL"},
    {9, "DEL_ALL_PRV"},
    {10, "REPEAT_ANNC"},
    {11, "LCP"},
    {12, "CA_FA_CNFRM"},
    {13, "INVALID_CMD"},
    {0, NULL}
};

static const value_string subpm_perform_cot_types[] = {
    {0, "SET_UP"},
    {1, "DRA_BUSY"},
    {2, "DRA_WAIT"},
    {3, "DRA_MSG_BUSY"},
    {4, "DRA_MSG_WAIT"},
    {5, "DRA_MSG_ACT"},
    {6, "DRA_MSG_DIAL"},
    {7, "DRA_END_DLY"},
    {8, "CMD_GET_DIG"},
    {9, "WAIT_RCVR"},
    {10, "WAIT_RCVR_PCA"},
    {0, NULL}
};

static const value_string subpm_clid_types[] = {
    {0, "SETUP"},
    {1, "TRK_RETRY"},
    {2, "WAIT_DRA"},
    {3, "WAIT_RSRC"},
    {4, "WAIT_ANNOC"},
    {5, "WAIT_END"},
    {6, "WAIT_CONFIRM"},
    {7, "WAIT_SRCE_DS"},
    {8, "WAIT_CNFR_PCA"},
    {0, NULL}
};

static const value_string subpm_xpm_types[] = {
    {0, NULL}
};

static const value_string subpm_mwil_types[] = {
    {0, "SETUP"},
    {1, "SEND"},
    {2, "WAIT"},
    {3, "CPM_CON"},
    {4, "CPM_WT"},
    {5, "BKGD"},
    {6, "WT_CNXID"},
    {7, "RDT_WAIT"},
    {0, NULL}
};

static const value_string subpm_ldbs_types[] = {
    {0, "SET_UP"},
    {1, "COLLECT_DIG"},
    {2, "WAIT_QUERY"},
    {3, "WAIT_DELAY"},
    {0, NULL}
};

static const value_string subpm_acr_types[] = {
    {0, "SETUP"},
    {1, "TRK_RETRY"},
    {2, "WAIT_DRA"},
    {3, "WAIT_RSRC"},
    {4, "WAIT_ANNOC"},
    {5, "WAIT_END"},
    {6, "WAIT_CONFIRM"},
    {7, "WAIT_SRCE_DS"},
    {0, NULL}
};

static const value_string subpm_call_park_types[] = {
    {0, "SET_UP"},
    {1, "COLL_1ST_DIG"},
    {2, "COLL_NTH_DIG"},
    {3, "X_WT_SPDT"},
    {4, "TONE_CONN_XY"},
    {5, "Y_PARKED"},
    {6, "YPARK_WT_RBK"},
    {7, "YPARK_XRERNG"},
    {8, "X_WT_CONFIRM"},
    {9, "X_CONFIRM"},
    {10, "DELAY_CONN"},
    {11, "ISDN_RERING"},
    {12, "WT_PCAV_CXID"},
    {0, NULL}
};

static const value_string subpm_camp_on_recall_types[] = {
    {0, NULL}
};

static const value_string subpm_cff_types[] = {
    {0, "SET_UP"},
    {1, "WAIT_CNFRM"},
    {2, "PROVIDE_CNFRM"},
    {3, "WAIT_CNFR_PCA"},
    {0, NULL}
};

static const value_string subpm_ibert_types[] = {
    {0, "SETUP"},
    {1, "WT_RESP_1"},
    {2, "WT_RESP_2"},
    {3, "CNT_CLR_ACK"},
    {4, "WT_STP_TEST"},
    {5, "RSET_CNT_ACK"},
    {6, "FND_PT_2_TST"},
    {7, "TEST_PATH"},
    {8, "WT_STAT_RSLT"},
    {9, "EFS_RSLT"},
    {10, "WAIT_DS1"},
    {11, "WT_RTS"},
    {12, "WT_TCM_SYNC"},
    {0, NULL}
};

static const value_string subpm_ain_types[] = {
    {0, "SET_UP"},
    {1, "WAIT_COT"},
    {2, "WAIT_SCP"},
    {3, "WAIT_DGT"},
    {4, "DRA_WAIT"},
    {5, "DRA_BUSY"},
    {6, "DRA_MSG_BUSY"},
    {7, "DRA_MSG_WAIT"},
    {8, "DRA_MSG_PLAY"},
    {9, "DRA_COL_DIGS"},
    {10, "WAIT_RCVR_PCA"},
    {0, NULL}
};

static const value_string subpm_ain_sit_types[] = {
    {0, "SET_UP"},
    {1, "DLY_B4_1ST_WINK"},
    {2, "WAIT_FOR_RCVR"},
    {3, "WAIT_FOR_1ST_KP"},
    {4, "WAIT_FOR_II"},
    {5, "WAIT_FOR_ANI"},
    {6, "WAIT_FOR_CLD_KP"},
    {7, "WAIT_FOR_CLD"},
    {8, "DLY_B4_2ND_WINK"},
    {0, NULL}
};

static const value_string subpm_ain_rtg_types[] = {
    {0, "SETUP"},
    {1, "REAL_TIME_BR"},
    {0, NULL}
};

static const value_string subpm_nail_bcon_types[] = {
    {0, "START_NAIL_CONN"},
    {1, "WAIT_SCM_RESP"},
    {2, "FINISH_NAIL_CONN"},
    {0, NULL}
};

static const value_string subpm_nail_dcon_types[] = {
    {0, "START_NAIL_CONN"},
    {1, "WAIT_SCM_RESP"},
    {2, "FINISH_NAIL_CONN"},
    {0, NULL}
};

static const value_string subpm_qtrn_trvr_types[] = {
    {0, NULL}
};

static const value_string subpm_ekts_types[] = {
    {0, "SET_UP"},
    {1, "KEY_SETUP"},
    {2, "PROGRESS"},
    {3, "RINGBACK"},
    {4, "CONNECT"},
    {5, "KEY_HOLD"},
    {6, "NOTIFY"},
    {7, "CLEARING"},
    {8, "FT_SEARCH"},
    {9, "FT_UPDATE"},
    {10, "REM_RING"},
    {11, "DNLD_REQ"},
    {12, "RETRIEVE"},
    {13, "DROP_EKTS"},
    {0, NULL}
};

static const value_string subpm_alt_types[] = {
    {0, "IDLE"},
    {1, "PERM"},
    {2, "BRIDGE"},
    {0, NULL}
};

static const value_string subpm_calea_types[] = {
    {0, NULL}
};

static const value_string subpm_sim_ring_types[] = {
    {0, "SET_UP"},
    {1, "GO_XLATE_NPMDN"},
    {2, "GO_DISC_NPMDN"},
    {0, NULL}
};

static const value_string subpm_lta_types[] = {
    {0, "SETUP"},
    {1, "WAIT_CONN_SLACC"},
    {2, "WAIT_MTA_CONN"},
    {3, "SEND_LOOPARND_RMV"},
    {4, "WAIT_MTA_LOOPARND_RMV"},
    {5, "MTA_ACCESS"},
    {6, "TL1_MSG_RSP_DLY"},
    {7, "CHG_DIR_RSP_DLY"},
    {8, "WAIT_MTA_DISC_RSP"},
    {9, "WAIT_MTA_REPSTAT_RPLY"},
    {10, "WAIT_BYPASS"},
    {11, "IDT_TO_MMB"},
    {12, "IDT_BYPASS"},
    {13, "WAIT_IDT_BPS"},
    {14, "TEST_IDT"},
    /* 15 is undefined */
    {16, "TL1_RESP_DELY"},
    {17, "WAIT_CU_TEST_FINISH"},
    {18, "WAIT_MTA_THEN_BREAK_CONN"},
    {19, "IDT_VIRT_WAIT_MMB"},
    {20, "IDT_VIRT_TRC_CONNECT"},
    {21, "IDT_VIRT_TRC_RSP_WAIT"},
    {22, "IDT_VIRT_TRC_DISC_WAIT"},
    {0, NULL}
};

static const value_string subpm_hgq_types[] = {
    {0, NULL}
};

static const value_string subpm_idle_types[] = {
    {0, NULL}
};

static const value_string subpm_sig_types[] = {
    {0, "SETUP"},
    {1, "PSIS_SETUP"},
    {2, "PSiM_SETUP"},
    {3, "WT_CNAM_RESP"},
    {4, "WT_DSIG_CONN"},
    {5, "WT_XMIT_TONE"},
    {6, "INTERCOM"},
    {7, "WT_DSIG_DISC"},
    {8, "WT_DISC"},
    {9, "WT_STD_RTE"},
    {0, NULL}
};

static const value_string subpm_sig_dest_types[] = {
    {0, "SETUP"},
    {1, "WT_RT_BREAK"},
    {2, "WT_PKT_CONN"},
    {3, "WT_DEST_CONN"},
    {4, "WT_DST_INTERCOM"},
    {5, "WT_DISC"},
    {0, NULL}
};

static const value_string subpm_agl_splrg_types[] = {
    {0, "SET_UP"},
    {1, "REMIND_RING"},
    {2, "WT_H248_CTXID"},
    {0, NULL}
};

static const value_string * subpm_name_tables[] = {
    subpm_orig_types,
    subpm_disc_time_types,
    subpm_revert_types,
    subpm_orig_dt_types,
    subpm_orig_ws_types,
    subpm_orig_dd_types,
    subpm_orig_id_types,
    subpm_no_test_types,
    subpm_dialing_types,
    subpm_rebuilt_types,
    subpm_acfw_reac_types,
    subpm_process_route_types,
    subpm_rte_line_types,
    subpm_mtce_types,
    subpm_aux_tone_types,
    subpm_noller_types,
    subpm_ittk_types,
    subpm_alm_send_types,
    subpm_ani_spill_types,
    subpm_trunk_term_types,
    subpm_line_term_types,
    subpm_non_cp_types,
    subpm_twc_types, /*index 22 : this is the same as at index 37 and index 38 */
    subpm_held_3wc_types, /*index 23 : this is the same as at index 39  */
    subpm_cwt_types,
    subpm_held_cwt_types,
    subpm_update_sc_types,
    subpm_orig_dt_types, /* index 27 : this is the same as at index 3 */
    subpm_acfw_retm_types,
    subpm_cfw_busy_types,
    subpm_cfw_types, /* index 30 */
    subpm_cfw_deact_types,
    subpm_rcfw_types,
    subpm_rotl_tp_types,
    subpm_chdt_types,
    subpm_chd_types,
    subpm_cheld_types,
    subpm_twc_types, /*index 37 : this is the same as at index 22 and index 38 */
    subpm_twc_types, /*index 38 : this is the same as at index 22 and index 37 */
    subpm_held_3wc_types, /*index 39 : this is the same as at index 23  */
    subpm_dig_ckt_test_types,    /* default for dig_ckt */
    subpm_nail_types,
    subpm_dcbi_types,
    subpm_rag_confirm_types,
    subpm_rag_process_types,
    subpm_e800_types,
    subpm_cfra_types,
    subpm_mwi_deac_types,
    subpm_acar_cp_types,
    subpm_acar_rering_types,
    subpm_acar_ann_types,    /* index 50 */
    subpm_sle_types,
    subpm_perform_cot_types,
    subpm_clid_types,
    subpm_xpm_types,
    subpm_mwil_types,
    subpm_ldbs_types,
    subpm_acr_types,
    subpm_call_park_types,
    subpm_camp_on_recall_types,
    subpm_cff_types,    /* index 60 */
    subpm_ibert_types,
    subpm_ain_types,
    subpm_ain_sit_types,
    subpm_ain_rtg_types,
    subpm_nail_bcon_types,
    subpm_nail_dcon_types,
    subpm_qtrn_trvr_types,
    subpm_ekts_types,
    subpm_alt_types,
    subpm_calea_types,    /* index 70 */
    subpm_sim_ring_types,
    subpm_lta_types,
    subpm_hgq_types,
    subpm_idle_types,
    subpm_sig_types,
    subpm_sig_dest_types,
    subpm_agl_splrg_types
};

/* for pm field ...*/
static const value_string c15_pm_types[] = {
    { 0, "ORIG" },
    { 1, "DSTM" },
    { 2, "RVRT" },
    { 3, "ORDT" },
    { 4, "ORWS" },
    { 5, "ORDD" },
    { 6, "ORID" },
    { 7, "#TST" },
    { 8, "DLNG" },
    { 9, "RBLT" },
    { 10, "CFWR" },
    { 11, "RTE" },
    { 12, "RLIN" },
    { 13, "MTCE" },
    { 14, "AUXT" },
    { 15, "NOLR" },
    { 16, "ITTK" },
    { 17, "ALSD" },
    { 18, "ANSP" },
    { 19, "TRNK" },
    { 20, "LINE" },
    { 21, "NOCP" },
    { 22, "3WC" },
    { 23, "3WCH" },
    { 24, "CWT" },
    { 25, "CWTH" },
    { 26, "UPSC" },
    { 27, "ORSD" },
    { 28, "CFRT" },
    { 29, "CFWB" },
    { 30, "CFW" },
    { 31, "CFWD" },
    { 32, "RCFW" },
    { 33, "ROTL" },
    { 34, "CHDT" },
    { 35, "CHD" },
    { 36, "CHLD" },
    { 37, "3WCH" },
    { 38, "3WCW" },
    { 39, "CSLT" },
    { 40, "DGTX" },
    { 41, "NAIL" },
    { 42, "DCBI" },
    { 43, "RGCF" },
    { 44, "RGCP" },
    { 45, "E800" },
    { 46, "CFRA" },
    { 47, "MWID" },
    { 48, "ACCP" },
    { 49, "ACRR" },
    { 50, "ACAN" },
    { 51, "SLE" },
    { 52, "PCOT" },
    { 53, "CLID" },
    { 54, "XPML" },
    { 55, "MWIL" },
    { 56, "LDBS" },
    { 57, "ACR" },
    { 58, "CPRK" },
    { 59, "CRCL" },
    { 60, "CFF" },
    { 61, "BERT" },
    { 62, "AIN" },
    { 63, "ASIT" },
    { 64, "ARTG" },
    { 65, "BNAL" },
    { 66, "DNAL" },
    { 67, "TRVR" },
    { 68, "EKTS" },
    { 69, "ALT" },
    { 70, "CALE" },
    { 71, "SRNG" },
    { 72, "LTA" },
    { 73, "HGQ" },
    { 74, "IDLE" },
    { 75, "SIG" },
    { 76, "SIGD" },
    { 77, "SPRG" },
    { 0, NULL }
};
static value_string_ext c15_pm_types_ext = VALUE_STRING_EXT_INIT(c15_pm_types);

static const value_string c15_dev_types[] = {
    { 0, "CR" },
    { 1, "SRCE" },
    { 2, "DEST" },
    { 3, "TS" },
    { 4, "RS" },
    { 5, "TD" },
    { 6, "RD" },
    { 7, "CLBF" },
    { 8, "TMP1" },
    { 9, "TMP2" },
    { 10, "PPS" },
    { 11, "PPD" },
    { 12, "BR1" },
    { 13, "BR2" },
    { 14, "BR3" },
    { 15, "BR4" },
    { 16, "BR5" },
    { 17, "BR6" },
    { 18, "ACFW" },
    { 19, "CATR" },
    { 20, "DATR" },
    { 21, "MR" },
    { 22, "TSMS" },
    { 23, "VFG" },
    { 24, "SFTR" },
    { 25, "ETOE" },
    { 26, "DST2" },
    { 27, "TD2" },
    { 28, "AINR" },
    { 29, "STRB" },
    { 30, "AXBF" },
    { 0, NULL }
};
static value_string_ext c15_dev_types_ext = VALUE_STRING_EXT_INIT(c15_dev_types);
static const value_string c15_event_types[] = {
    { 0, "DISC" },
    { 1, "CONN" },
    { 2, "DIGT" },
    { 3, "TO" },
    { 4, "RGFL" },
    { 5, "FLSH" },
    { 6, "WINK" },
    { 7, "NONE" },
    { 8, "COIN" },
    { 9, "ANI" },
    { 10, "OPLS" },
    { 11, "RSRC" },
    { 12, "PBLK" },
    { 13, "SOW" },
    { 14, "RGON" },
    { 15, "RGOF" },
    { 16, "LOW" },
    { 17, "LITTI" },
    { 18, "AUXT" },
    { 19, "NLRS" },
    { 20, "NLRE" },
    { 21, "ITTK" },
    { 22, "DSPL" },
    { 23, "MLWK" },
    { 24, "CONT" },
    { 25, "ROW" },
    { 26, "CPSC" },
    { 27, "PEPR" },
    { 28, "DST" },
    { 29, "PLSN" },
    { 30, "CHNL" },
    { 31, "HMPE" },
    { 32, "LTBT" },
    { 33, "MMB" },
    { 34, "FLTY" },
    { 35, "VAXS" },
    { 36, "MTCE" },
    { 37, "TSON" },
    { 38, "TSNO" },
    { 39, "TMAP" },
    { 40, "RMOV" },
    { 41, "CTU" },
    /* 42 unused */
    { 43, "COMP" },
    /* 44 unused */
    { 45, "TNPL" },
    { 46, "SCP" },
    { 47, "ACRT" },
    { 48, "CPST" },
    { 49, "ACM" },
    { 50, "ANM" },
    { 51, "BLO" },
    { 52, "CCRI" },
    { 53, "CCRO" },
    { 54, "COTP" },
    { 55, "COTF" },
    { 56, "COTT" },
    { 57, "CRA" },
    { 58, "CVR" },
    { 59, "EXM" },
    { 60, "IAM" },
    { 61, "LPA" },
    { 62, "REL" },
    { 63, "RES" },
    { 64, "RLC" },
    { 65, "RSC" },
    { 66, "SUS" },
    { 67, "UCIC" },
    { 68, "CLID" },
    { 69, "MONY" },
    { 70, "XPML" },
    { 71, "OVLT" },
    { 72, "SLET" },
    { 73, "CNAT" },
    { 74, "KEY" },
    { 75, "HOLD" },
    { 76, "RTRV" },
    { 77, "COT8" },
    { 78, "DATL" },
    { 79, "FKEY" },
    { 80, "ABRT" },
    { 81, "TCAP" },
    { 82, "SETP" },
    { 83, "FACT" },
    { 84, "PROC" },
    { 85, "ALRT" },
    { 86, "HDAK" },
    { 87, "HDRJ" },
    { 88, "KSAC" },
    { 89, "RTAK" },
    { 90, "RTRJ" },
    { 91, "STAT" },
    { 92, "ISFC" },
    { 93, "CPG" },
    { 94, "ALTW" },
    { 95, "ALTD" },
    { 96, "ALTN" },
    { 97, "ALTP" },
    { 98, "ALTQ" },
    { 99, "FACW" },
    { 100, "PROG" },
    { 101, "BRDG" },
    { 102, "AIU" },
    { 103, "FAC" },
    { 104, "SRNG" },
    { 105, "PCAV" },
    { 106, "CXID" },
    { 107, "INVT" },
    { 108, "REFR" },
    { 109, "SVND" },
    { 110, "TL1D" },
    { 111, "INDG" },
    { 112, "TL1M" },
    { 113, "INVR" },
    {   0, NULL}
};
static value_string_ext c15_event_types_ext = VALUE_STRING_EXT_INIT(c15_event_types);

#define C15_INC_GWE_NONE       0
#define C15_INC_GWE_REPLY      1
#define C15_INC_GWE_BC_PGI     2
#define C15_INC_GWE_MGCP_DLCX  3
#define C15_INC_GWE_H248_DIGIT    4
#define C15_INC_GWE_VOIP_COT      5
#define C15_INC_GWE_NOTIFY        6
#define C15_INC_GWE_ADMN_UPDT_REC 7
#define C15_INC_GWE_CL_SETUP      8
#define C15_INC_GWE_PTRK_SETUP    9
#define C15_INC_GWE_CL_PROG      10
#define C15_INC_GWE_CL_ANS       11
#define C15_INC_GWE_CL_REL       12
#define C15_INC_GWE_NTWK_MOD     13
#define C15_INC_GWE_RV_AVAIL     14
#define C15_INC_GWE_CL_REDIR     15
#define C15_INC_GWE_CL_REFER     16
#define C15_INC_GWE_CHG_HDL      17
#define C15_INC_GWE_SUBS_CHG_HDL 18
#define C15_INC_GWE_INFO         19
#define C15_INC_GWE_INV_REPL     20
#define C15_INC_GWE_ADMN_DN      21
#define C15_INC_GWE_SUA_REPLY    22
#define C15_INC_GWE_SUA_HNDL     23
#define C15_INC_GWE_SUA_TGH_STAT 24


/* Dissector Table */
static dissector_table_t c15ch_inc_gwe_dissector_table;

/* Fields */
static int hf_c15ch_inc_gwe = -1;
static int hf_c15ch_inc_gwe_ni = -1;
static int hf_c15ch_inc_gwe_tn = -1;
static int hf_c15ch_inc_gwe_ni_tn = -1;
static int hf_c15ch_inc_gwe_taskid = -1;
static int hf_c15ch_inc_gwe_fiatid_invalid = -1;
static int hf_c15ch_inc_gwe_fiatid_bc = -1;
static int hf_c15ch_inc_gwe_fiatid_mtce = -1;
static int hf_c15ch_inc_gwe_fiatid_om = -1;
static int hf_c15ch_inc_gwe_fiatid_h248 = -1;
static int hf_c15ch_inc_gwe_fiatid_sua = -1;
static int hf_c15ch_inc_gwe_fiatid_mgcp = -1;
static int hf_c15ch_inc_gwe_fiatid_sip_notify = -1;
static int hf_c15ch_inc_gwe_fiatid_admn = -1;
static int hf_c15ch_inc_gwe_datatype = -1;


/* labels */


static int * fiatid_table[] = {
    /* one entry for each Task type */
    &hf_c15ch_inc_gwe_fiatid_invalid,
    &hf_c15ch_inc_gwe_fiatid_bc,
    &hf_c15ch_inc_gwe_fiatid_mtce,
    &hf_c15ch_inc_gwe_fiatid_om,
    &hf_c15ch_inc_gwe_fiatid_h248,
    &hf_c15ch_inc_gwe_fiatid_sua,
    &hf_c15ch_inc_gwe_fiatid_mgcp,
    &hf_c15ch_inc_gwe_fiatid_sip_notify,
    &hf_c15ch_inc_gwe_fiatid_admn
};

/*static const guint8 FIRST_TASK_TYPE_INDEX = 0;*/
static const guint8  LAST_TASK_TYPE_INDEX = 8;


static const value_string c15inc_gwe_task_types[] = {
    { 0, "GWE_TK_INVALID" },
    { 1, "GWE_TK_BC" },
    { 2, "GWE_TK_MTCE" },
    { 3, "GWE_TK_OM" },
    { 4, "GWE_TK_H248" },
    { 5, "GWE_TK_SUA" },
    { 6, "GWE_TK_MGCP" },
    { 7, "GWE_TK_SIP_NOTIFY" },
    { 8, "GWE_TK_ADMN" },
    { 0, NULL }
};

#if 0
static const guint8 INVALID_TASK_TYPE_VAL = 0;
#endif

static const value_string c15inc_gwe_bc_fiat_types[] = {
    { 0, "GW_FT_INVALID" },
    { 1, "GWE_FT_REPLY" },
    { 2, "GWE_FT_BC_PGI" },
    { 3, "GWE_FT_MGCP_DLCX" },
    { 0, NULL }
};

static const value_string c15inc_gwe_mtce_fiat_types[] = {
    { 0, "GW_FT_INVALID" },
    { 1, "GWE_FT_REPLY" },
    { 2, "GWE_FT_GRACEFUL" },
    { 3, "GWE_FT_FORCED" },
    { 4, "GWE_FT_RESTART" },
    { 5, "GWE_FT_DISCNCT" },
    { 6, "GWE_FT_HANDOFF" },
    { 7, "GWE_FT_FAILOVER" },
    { 8, "GWE_FT_LN_DLCX" },
    { 9, "GWE_FT_LN_GRCFL" },
    { 10, "GWE_FT_LN_FRCD" },
    { 11, "GWE_FT_LN_RSTRT" },
    { 12, "GWE_FT_DS1_GRCFL" },
    { 13, "GWE_FT_DS1_FRCD" },
    { 14, "GWE_FT_DS1_RSTRT" },
    { 15, "GWE_FT_TRK_GRCFL" },
    { 16, "GWE_FT_TRK_FRCD" },
    { 17, "GWE_FT_TRK_RSTRT" },
    { 18, "GWE_FT_ALLDS1_GRCL" },
    { 19, "GWE_FT_ALLDS1_FRCD" },
    { 20, "GWE_FT_ALLDS1_GRCFL" },
    { 21, "GWE_FT_LN_DISCNCT" },
    { 0, NULL }
};

static const value_string c15inc_gwe_om_fiat_types[] = {
    { 0, "GW_FT_INVALID" },
    { 1, "GWE_FT_REPLY" },
    { 0, NULL }
};

static const value_string c15inc_gwe_h248_fiat_types[] = {
    { 0, "GW_FT_INVALID" },
    { 1, "GWE_FT_REPLY" },
    { 2, "GWE_FT_OFHK" },
    { 3, "GWE_FT_ONHK" },
    { 4, "GWE_FT_DIGIT" },
    { 5, "GWE_FT_FLASH" },
    { 6, "GWE_FT_COT" },
    { 7, "GWE_FT_FAX_NTFY" },
    { 8, "GWE_FT_MDM_NTFY" },
    { 0, NULL }
};

static const value_string c15inc_gwe_mgcp_fiat_types[] = {
    { 0, "GW_FT_INVALID" },
    { 1, "GWE_FT_REPLY" },
    { 2, "GWE_FT_OFHK" },
    { 3, "GWE_FT_ONHK" },
    { 4, "GWE_FT_DIGIT" },
    { 5, "GWE_FT_FLASH" },
    { 6, "GWE_FT_COT" },
    { 7, "GWE_FT_FAX_NTFY" },
    { 8, "GWE_FT_MDM_NTFY" },
    { 0, NULL }
};

static const value_string c15inc_gwe_sua_fiat_types[] = {
    { 0, "GW_FT_INVALID" },
    { 1, "GWE_FT_REPLY" },
    { 2, "GWE_FT_OFHK" },
    { 3, "GWE_FT_ONHK" },
    { 4, "GWE_FT_CL_SETUP" },
    { 5, "GWE_FT_CL_PROG" },
    { 6, "GWE_FT_CL_ANS" },
    { 7, "GWE_FT_CL_REL" },
    { 8, "GWE_FT_NTWK_MOD" },
    { 9, "GWE_FT_RV_AVAIL" },
    { 10, "GWE_FT_CL_REDIR" },
    { 11, "GWE_FT_CL_REFER" },
    { 12, "GWE_FT_PTRK_CL_SETUP" },
    { 13, "GWE_FT_CHG_HDL" },
    { 14, "GWE_FT_SUBS_CHG_HDL" },
    { 15, "GWE_FT_INFO" },
    { 16, "GWE_FT_INV_REPL" },
    { 17, "GWE_FT_TGH_STAT" },
    { 0, NULL }
};

static const value_string c15inc_gwe_sip_notify_fiat_types[] = {
    { 0, "GWE_FT_MWI_NOTIFY" },
    { 1, "GWE_FT_REMINDER_NOTIFY" },
    { 2, "GWE_FT_REFER_NOTIFY" },
    { 0, NULL }
};

static const value_string c15inc_gwe_admn_fiat_types[] = {
    { 0, "GWE_FT_INVALID" },
    { 1, "GWE_FT_ADMN_SUBS" },
    { 2, "GWE_FT_ADMN_UNSUBS" },
    { 3, "GWE_FT_ADMN_UPDT_REC_ADDR" },
    { 4, "GWE_FT_ADMN_UA_RESP" },
    { 0, NULL }
};

static const value_string * fiat_name_tables[] = {
    /* correspond to members of c15inc_gwe_task_types */
    NULL, /* corresponds to c15inc_gwe_task_types[0] i.e. GWE_TK_INVALID */
    c15inc_gwe_bc_fiat_types,
    c15inc_gwe_mtce_fiat_types,
    c15inc_gwe_om_fiat_types,
    c15inc_gwe_h248_fiat_types,
    c15inc_gwe_sua_fiat_types,
    c15inc_gwe_mgcp_fiat_types,
    c15inc_gwe_sip_notify_fiat_types,
    c15inc_gwe_admn_fiat_types
};
static const guint8 FIRST_FIAT_NAME_TABLE_INDEX  = 1;  /* First valid index. */
static const guint8 LAST_FIAT_NAME_TABLE_INDEX = 8;

static const value_string c15inc_gwe_types[] = {
    { C15_INC_GWE_NONE, "IN_DATA_NONE" },
    { C15_INC_GWE_REPLY, "REPLY" },
    { C15_INC_GWE_BC_PGI, "BC_PGI" },
    { C15_INC_GWE_MGCP_DLCX, "MGCP_DLCX" },
    { C15_INC_GWE_H248_DIGIT, "H248_DIGIT" },
    { C15_INC_GWE_VOIP_COT, "VOIP_COT" },
    { C15_INC_GWE_NOTIFY, "NOTIFY" },
    { C15_INC_GWE_ADMN_UPDT_REC, "ADMN_UPDT_REC" },
    { C15_INC_GWE_CL_SETUP, "CL_SETUP" },
    { C15_INC_GWE_PTRK_SETUP, "PTRK_SETUP" },
    { C15_INC_GWE_CL_PROG, "CL_PROG" },
    { C15_INC_GWE_CL_ANS, "CL_ANS" },
    { C15_INC_GWE_CL_REL, "CL_REL" },
    { C15_INC_GWE_NTWK_MOD, "NTWK_MOD" },
    { C15_INC_GWE_RV_AVAIL, "RV_AVAIL" },
    { C15_INC_GWE_CL_REDIR, "CL_REDIR" },
    { C15_INC_GWE_CL_REFER, "CL_REFER" },
    { C15_INC_GWE_CHG_HDL, "CHG_HDL" },
    { C15_INC_GWE_SUBS_CHG_HDL, "SUBS_CHG_HDL" },
    { C15_INC_GWE_INFO, "INFO" },
    { C15_INC_GWE_INV_REPL, "INV_REPL" },
    { C15_INC_GWE_ADMN_DN, "ADMN_DN" },
    { C15_INC_GWE_SUA_REPLY, "INC_SUA_REPLY" },
    { C15_INC_GWE_SUA_HNDL, "INC_SUA_HANDL" },
    { C15_INC_GWE_SUA_TGH_STAT, "INC_SUA_TGH_STAT" },
    { 0, NULL }
};
static value_string_ext c15inc_gwe_types_ext = VALUE_STRING_EXT_INIT(c15inc_gwe_types);

/* Protocol for all third-level Inc GWE dissection */
static int proto_c15ch_third_level_inc_gwe = -1;

static int ett_c15ch_third_level_inc_gwe = -1;
static int ett_c15ch_third_level_inc_gwe_sub1 = -1;


/* Fields */
static int hf_c15ch_inc_gwe_admn_dn = -1;
static int hf_c15ch_inc_gwe_admn_dn_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_admn_dn_ip_gwe_digits = -1;


/* Fields */
static int hf_c15ch_inc_gwe_admn_updt = -1;
static int hf_c15ch_inc_gwe_admn_updt_ip_gwe_med_ni = -1;
static int hf_c15ch_inc_gwe_admn_updt_ip_gwe_med_tn = -1;
static int hf_c15ch_inc_gwe_admn_updt_ip_gwe_med_ni_tn = -1;
static int hf_c15ch_inc_gwe_admn_updt_ip_ns_iface = -1;
static int hf_c15ch_inc_gwe_admn_updt_ip_ns_terminal = -1;
static int hf_c15ch_inc_gwe_admn_updt_ip_gwe_new_rec_addr = -1;

/* Fields */
static int hf_c15ch_inc_gwe_bc_pgi = -1;
static int hf_c15ch_inc_gwe_bc_pgi_pbc_conn_num = -1;
static int hf_c15ch_inc_gwe_bc_pgi_pbc_conn_type = -1;
static int hf_c15ch_inc_gwe_bc_pgi_pbc_msg_type = -1;
static int hf_c15ch_inc_gwe_bc_pgi_bc_mode = -1;
static int hf_c15ch_inc_gwe_bc_pgi_bc_pgi_sdp = -1;
static int hf_c15ch_inc_gwe_bc_pgi_bc_pgi_m_port = -1;
static int hf_c15ch_inc_gwe_bc_pgi_pbc_tst_flags = -1;

/* Field Labels */
static const value_string c15_inc_gwe_bc_pgi_pbc_conn_types[] = {
    { 1, "TDM Internetworking" },
    { 2, "Media Portal" },
    { 3, "Conference" },
    { 4, "Optimized Conn" },
    { 0, NULL }
};

/* Subtree */
#if 0
static gint ett_c15ch_inc_gwe_bc_pgi = -1;
#endif

/* Fields */
static int hf_c15ch_inc_gwe_chg_hndl = -1;
static int hf_c15ch_inc_gwe_chg_hndl_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_chg_hndl_ip_gwe_new_hndl = -1;


/* Fields */
static int hf_c15ch_inc_gwe_cl_ans = -1;
static int hf_c15ch_inc_gwe_cl_ans_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_cl_ans_ip_gwe_conn_num= -1;
static int hf_c15ch_inc_gwe_cl_ans_ip_cl_ans_lsdp = -1;
static int hf_c15ch_inc_gwe_cl_ans_ip_cl_ans_m_port = -1;
static int hf_c15ch_inc_gwe_cl_ans_encap_isup = -1;

/* Fields */
static int hf_c15ch_inc_gwe_cl_prog = -1;
static int hf_c15ch_inc_gwe_cl_prog_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_cl_prog_ip_gwe_conn_num= -1;
static int hf_c15ch_inc_gwe_cl_prog_ip_cl_prog_lsdp = -1;
static int hf_c15ch_inc_gwe_cl_prog_ip_cl_prog_m_port = -1;
static int hf_c15ch_inc_gwe_cl_prog_ip_gwe_stat_code = -1;
static int hf_c15ch_inc_gwe_cl_prog_encap_isup = -1;

/* Fields */
static int hf_c15ch_inc_gwe_cl_redir = -1;
static int hf_c15ch_inc_gwe_cl_redir_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_cl_redir_ip_gwe_conn_num = -1;
static int hf_c15ch_inc_gwe_cl_redir_ip_gwe_redir_digits = -1;


/* Fields */
static int hf_c15ch_inc_gwe_cl_refer = -1;
static int hf_c15ch_inc_gwe_cl_refer_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_cl_refer_ip_gwe_conn_num = -1;
static int hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_digits = -1;
static int hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_ni = -1;
static int hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_tn = -1;
static int hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_ni_tn = -1;


/* Fields */
static int hf_c15ch_inc_gwe_cl_rel = -1;
static int hf_c15ch_inc_gwe_cl_rel_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_cl_rel_ip_gwe_conn_num = -1;
static int hf_c15ch_inc_gwe_cl_rel_ip_gwe_stat_code = -1;
static int hf_c15ch_inc_gwe_cl_rel_encap_isup = -1;



/* Fields */
static int hf_c15ch_inc_gwe_cl_setup = -1;
static int hf_c15ch_inc_gwe_cl_setup_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_cl_setup_ip_gwe_cled_digits = -1;
static int hf_c15ch_inc_gwe_cl_setup_ip_cl_setup_lsdp = -1;
static int hf_c15ch_inc_gwe_cl_setup_ip_cl_setup_m_port = -1;


/* Fields */
static int hf_c15ch_inc_gwe_h248_digit = -1;
static int hf_c15ch_inc_gwe_h248_digit_ip_gwe_digit = -1;
static int hf_c15ch_inc_gwe_h248_digit_ip_gwe_digit_method = -1;


/* Fields */
static int hf_c15ch_inc_gwe_info = -1;
static int hf_c15ch_inc_gwe_info_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_info_ip_gwe_info_type = -1;
static int hf_c15ch_inc_gwe_info_ip_gwe_info_digit = -1;
static int hf_c15ch_inc_gwe_info_encap_isup_msg_type = -1;

/* value_string arrays to label fields */
/* These two encapsulated isup message types are the only valid ones for this field. */
static const value_string c15ch_inc_gwe_info_encap_isup_msg_types[] = {
    { 13, "Suspend Message" },
    { 14, "Resume Message" },
    { 0, NULL }
};

/* Fields */
static int hf_c15ch_inc_gwe_inv_repl = -1;
static int hf_c15ch_inc_gwe_inv_repl_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_inv_repl_ip_gwe_conn_num = -1;
static int hf_c15ch_inc_gwe_inv_repl_ip_inv_repl_rsdp_ip = -1;
static int hf_c15ch_inc_gwe_inv_repl_ip_inv_repl_rsdp_port = -1;

/* Fields */
static int hf_c15ch_inc_gwe_mgcp_dlcx = -1;
static int hf_c15ch_inc_gwe_mgcp_dlcx_err_code = -1;

/* Fields */
static int hf_c15ch_inc_gwe_notify = -1;
static int hf_c15ch_inc_gwe_notify_ip_gwe_mwi_stat = -1;
static int hf_c15ch_inc_gwe_notify_ip_gwe_digits = -1;

/* Fields */
static int hf_c15ch_inc_gwe_ntwk_mod  = -1;
static int hf_c15ch_inc_gwe_ntwk_mod_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_ntwk_mod_ip_gwe_conn_num= -1;
static int hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_lsdp = -1;
static int hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_l_m_port = -1;
static int hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_rsdp = -1;
static int hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_r_m_port = -1;
static int hf_c15ch_inc_gwe_ntwk_mod_ip_gwe_stat_code = -1;


/* Fields */
static int hf_c15ch_inc_gwe_ptrk_setup = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_cled_digits = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_cl_setup_lsdp = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_cl_setup_m_port = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clid_pri = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clng_digits = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clng_ton = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clng_np = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_alert_info = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_redir_digits = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_redir_ton = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_redir_np = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_ocn_digits = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_chrg_digits = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_chrg_noa = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_chrg_npi = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_npdi = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_rn_digits = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_cic_digits = -1;
static int hf_c15ch_inc_gwe_ptrk_setup_encap_isup = -1;

/* Fields */
static int hf_c15ch_inc_gwe_reply = -1;
static int hf_c15ch_inc_gwe_reply_ip_gwe_msg_type = -1;
static int hf_c15ch_inc_gwe_reply_ip_gwe_stat_code = -1;
static int hf_c15ch_inc_gwe_reply_ip_gwe_conn_num = -1;
static int hf_c15ch_inc_gwe_reply_nw_mdcn_lsdp_ip = -1;
static int hf_c15ch_inc_gwe_reply_nw_mdcn_lsdp_port = -1;
static int hf_c15ch_inc_gwe_reply_nw_mdcn_rsdp_ip = -1;
static int hf_c15ch_inc_gwe_reply_nw_mdcn_rsdp_port = -1;

/* Fields */
static int hf_c15ch_inc_gwe_rv_avail = -1;
static int hf_c15ch_inc_gwe_rv_avail_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_rv_avail_ip_gwe_conn_num = -1;
static int hf_c15ch_inc_gwe_rv_avail_ip_gwe_info_len = -1;

/* Fields */
static int hf_c15ch_inc_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_sua_hndl_ip_gwe_sua_hndl = -1;

/* Fields */
static int hf_c15ch_inc_gwe_sua_reply = -1;
static int hf_c15ch_inc_gwe_sua_reply_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_sua_reply_ip_gwe_msg_type = -1;
static int hf_c15ch_inc_gwe_sua_reply_ip_gwe_stat_code = -1;
static int hf_c15ch_inc_gwe_sua_reply_ip_gwe_conn_num = -1;
static int hf_c15ch_inc_gwe_sua_reply_nw_mdcn_lsdp_ip = -1;
static int hf_c15ch_inc_gwe_sua_reply_nw_mdcn_lsdp_port = -1;
static int hf_c15ch_inc_gwe_sua_reply_nw_mdcn_rsdp_ip = -1;
static int hf_c15ch_inc_gwe_sua_reply_nw_mdcn_rsdp_port = -1;

/* Fields */
static int hf_c15ch_inc_gwe_subs_chg_hndl = -1;
static int hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_new_hndl = -1;
static int hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_med_ni = -1;
static int hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_med_tn = -1;
static int hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_med_ni_tn = -1;

/* Fields */
static int hf_c15ch_inc_gwe_tgh_stat = -1;
static int hf_c15ch_inc_gwe_tgh_stat_ip_gwe_sua_hndl = -1;
static int hf_c15ch_inc_gwe_tgh_stat_ip_gwe_tgh_state = -1;

/* value_string arrays to label fields */

static const value_string tgh_state_types[] = {
    { 0, "In-Service" },
    { 1, "Acquiring" },
    { 2, "Out-of-Service" },
    { 0, NULL }
};

/* Fields */
static int hf_c15ch_inc_gwe_voip_cot = -1;
static int hf_c15ch_inc_gwe_voip_cot_ip_gwe_pass_code = -1;

/* Field Labels */
const true_false_string c15_inc_gwe_voip_cot_ip_gwe_pass_code_types = {
       "Success", /*string for 1*/
       "Failure"  /*string for 0*/
};

#if 0
/* Subtree */
static gint ett_c15ch_inc_gwe_voip_cot = -1;
#endif

/* out gwe */

#define C15_OUT_GWE_NONE       0
#define C15_OUT_GWE_DIGIT_SCAN 1
#define C15_OUT_GWE_CONN_NUM   2
#define C15_OUT_GWE_MK_CONN    3
#define C15_OUT_GWE_MD_CONN    4
#define C15_OUT_GWE_CALL_ANS   5
#define C15_OUT_GWE_CALL_SETUP 6
#define C15_OUT_GWE_CALL_PROG  7
#define C15_OUT_GWE_CALL_NOTIFY 8
#define C15_OUT_GWE_CALL_REL    9
#define C15_OUT_GWE_UPDT_NI_TN 10
#define C15_OUT_GWE_PCM_DATA   11
#define C15_OUT_GWE_BLF_DATA   12
#define C15_OUT_GWE_COT        13
#define C15_OUT_GWE_RING_LINE  14
#define C15_OUT_GWE_AUDIT_CONN 15
#define C15_OUT_GWE_SAC_SUB_VALID  16
#define C15_OUT_GWE_SAC_NOTIFY     17
#define C15_OUT_GWE_SAC_LIST_ENTRY 18
#define C15_OUT_GWE_RV_SUBS_DATA   19
#define C15_OUT_GWE_UPDT_REC_ADDR  20
#define C15_OUT_GWE_DEL_SUBS_UA    21
#define C15_OUT_GWE_LINE_SPRVSN    22
#define C15_OUT_GWE_SIP_INFO       23
#define C15_OUT_GWE_SIP_REFER      24

static int ett_c15ch_third_level_out_gwe = -1;
static int ett_c15ch_third_level_out_gwe_sub1 = -1;
static int ett_c15ch_third_level_out_gwe_sub2 = -1;

static int proto_c15ch_third_level_out_gwe = -1;

/* Dissector Table */
static dissector_table_t c15ch_out_gwe_dissector_table;

/* Fields */
static int hf_c15ch_out_gwe = -1;
static int hf_c15ch_out_gwe_ni = -1;
static int hf_c15ch_out_gwe_tn = -1;
static int hf_c15ch_out_gwe_ni_tn = -1;
static int hf_c15ch_out_gwe_op_gwe_msg_type = -1;
static int hf_c15ch_out_gwe_op_gwe_protocol = -1;
static int hf_c15ch_out_gwe_op_sua_hndl = -1;
static int hf_c15ch_out_gwe_gwe_data_type = -1;

#if 0
/* Subtree */
static gint ett_c15ch_out_gwe = -1;
static gint ett_c15ch_out_gwe_sub_ni_tn = -1;
#endif

/* value labels for fields*/
static const value_string c15_out_gwe_data_types[] = {
    { C15_OUT_GWE_NONE, "OUT_DATA_NONE" },
    { C15_OUT_GWE_DIGIT_SCAN, "DIGIT_SCAN" },
    { C15_OUT_GWE_CONN_NUM, "CONN_NUM" },
    { C15_OUT_GWE_MK_CONN, "MK_CONN" },
    { C15_OUT_GWE_MD_CONN, "MD_CONN" },
    { C15_OUT_GWE_CALL_ANS, "CALL_ANS" },
    { C15_OUT_GWE_CALL_SETUP, "CALL_SETUP" },
    { C15_OUT_GWE_CALL_PROG, "CALL_PROG" },
    { C15_OUT_GWE_CALL_NOTIFY, "CALL_NOTIFY" },
    { C15_OUT_GWE_CALL_REL, "CALL_REL" },
    { C15_OUT_GWE_UPDT_NI_TN, "UPDT_NI_TN" },
    { C15_OUT_GWE_PCM_DATA, "PCM_DATA" },
    { C15_OUT_GWE_BLF_DATA, "BLF_DATA" },
    { C15_OUT_GWE_COT, "GWE_OUT_COT" },
    { C15_OUT_GWE_RING_LINE, "RING_LINE" },
    { C15_OUT_GWE_AUDIT_CONN, "AUDIT_CONN" },
    { C15_OUT_GWE_SAC_SUB_VALID, "SAC_SUB_VALID" },
    { C15_OUT_GWE_SAC_NOTIFY, "SAC_NOTIFY" },
    { C15_OUT_GWE_SAC_LIST_ENTRY, "SAC_LIST_ENTRY" },
    { C15_OUT_GWE_RV_SUBS_DATA, "RV_SUBS_DATA" },
    { C15_OUT_GWE_UPDT_REC_ADDR, "UPDT_REC_ADDR" },
    { C15_OUT_GWE_DEL_SUBS_UA, "DEL_SUBS_UA" },
    { C15_OUT_GWE_LINE_SPRVSN, "LINE_SPRVSN" },
    { C15_OUT_GWE_SIP_INFO, "SIP_INFO" },
    { C15_OUT_GWE_SIP_REFER, "SIP_REFER" },
    { 0, NULL }
};
static value_string_ext c15_out_gwe_data_types_ext = VALUE_STRING_EXT_INIT(c15_out_gwe_data_types);

static const value_string c15_out_gwe_protocol_types[] = {
    { 0, "H248" },
    { 1, "SIP" },
    { 2, "MGCP" },
    { 3, "NCS" },
    { 0, NULL }
};

static const value_string c15_out_gwe_msg_types[] = {
    { 0, "GWE_MSG_INVALID" },
    { 1, "GWE_DIGIT_SCAN" },
    { 2, "GWE_RING_LINE" },
    { 3, "GWE_LINE_SPRVSN" },
    { 4, "GWE_APPLY_TONE" },
    { 5, "GWE_REMOVE_TONE" },
    { 6, "GWE_PHYS_MK_CONN" },
    { 7, "GWE_PHYS_BK_CONN" },
    { 8, "GWE_PHYS_MV_CONN" },
    { 9, "GWE_PHYS_MD_CONN" },
    { 10, "GWE_NTWK_MK_CONN" },
    { 11, "GWE_NTWK_BK_CONN" },
    { 12, "GWE_NTWK_MD_CONN" },
    { 13, "GWE_NODE_SVC_CHG" },
    { 14, "GWE_LINE_SVC_CHG" },
    { 15, "GWE_SEND_RESP" },
    { 16, "GWE_AUDIT_LINE" },
    { 17, "GWE_MSG_PASSTHRU" },
    { 18, "GWE_CALL_ANS" },
    { 19, "GWE_CALL_SETUP" },
    { 20, "GWE_CALL_PROG" },
    { 21, "GWE_CALL_REL" },
    { 22, "GWE_GET_RV_INFO" },
    { 23, "GWE_PUT_RV_INFO" },
    { 24, "GWE_CALL_NOTIFY" },
    { 25, "GWE_UPDT_NI_TN" },
    { 26, "GWE_UA_INFO_XFER" },
    { 27, "GWE_PUT_PCM_DATA" },
    { 28, "GWE_REBUILD_OK" },
    { 29, "GWE_TRK_SVC_CHG" },
    { 30, "GWE_STRT_COT" },
    { 31, "GWE_STOP_COT" },
    { 32, "GWE_RECV_COT" },
    { 33, "GWE_SUBTRACT_ALL" },
    { 34, "GWE_AUDIT_TRK" },
    { 35, "GWE_AUDIT_GW" },
    { 36, "GWE_AUDIT_ROOT" },
    { 37, "GWE_WC_LINE_OFHK" },
    { 38, "GWE_AUD_ROOT_CXTS" },
    { 39, "GWE_SUB_ALL_CXT" },
    { 40, "GWE_SAC_SUB_VALID" },
    { 41, "GWE_SAC_NOTIFY" },
    { 42, "GWE_DEL_NONE" },
    { 43, "GWE_AUDIT_CONN" },
    { 44, "GWE_SAC_LIST_ENTRY" },
    { 45, "GWE_PUT_BLF_DATA" },
    { 46, "GWE_PUT_RV_SUBS_DATA" },
    { 47, "GWE_GET_RV_SUBS_DATA" },
    { 48, "GWE_STORE_RV_SUBS_DATA" },
    { 49, "GWE_DEL_RV_SUBS_DATA" },
    { 50, "GWE_UPDT_REC_ADDR" },
    { 51, "GWE_MGCP_DLCX" },
    { 52, "GWE_DEL_SUBS_UA" },
    { 53, "GWE_SUBS_UA_QUE" },
    { 54, "GWE_SIP_INFO" },
    { 55, "GWE_SIP_REFER" },
    { 56, "GWE_UPDT_SDP" },
    { 0, NULL }
};
static value_string_ext c15_out_gwe_msg_types_ext = VALUE_STRING_EXT_INIT(c15_out_gwe_msg_types);

/* Fields */
static int hf_c15ch_out_gwe_audit_conn = -1;
static int hf_c15ch_out_gwe_audit_conn_ni = -1;
static int hf_c15ch_out_gwe_audit_conn_tn = -1;
static int hf_c15ch_out_gwe_audit_conn_ni_tn = -1;
static int hf_c15ch_out_gwe_audit_conn_context = -1;

/* Fields */
static int hf_c15ch_out_gwe_blf_data = -1;
static int hf_c15ch_out_gwe_blf_data_rb_ua_handle = -1;
static int hf_c15ch_out_gwe_blf_data_rb_type = -1;
static int hf_c15ch_out_gwe_blf_data_med_ni = -1;
static int hf_c15ch_out_gwe_blf_data_med_tn = -1;
static int hf_c15ch_out_gwe_blf_data_med_ni_tn = -1;
static int hf_c15ch_out_gwe_blf_data_rb_ni = -1;
static int hf_c15ch_out_gwe_blf_data_rb_tn = -1;
static int hf_c15ch_out_gwe_blf_data_rb_ni_tn = -1;


/* Fields */
static int hf_c15ch_out_gwe_call_ans = -1;
static int hf_c15ch_out_gwe_call_ans_conn_num = -1;
static int hf_c15ch_out_gwe_call_ans_op_cl_ans_rsdp_ip = -1;
static int hf_c15ch_out_gwe_call_ans_op_cl_ans_rsdp_port = -1;
static int hf_c15ch_out_gwe_call_ans_encap_isup = -1;

/* Fields */
static int hf_c15ch_out_gwe_call_notify = -1;
static int hf_c15ch_out_gwe_call_notify_op_gwe_mwi = -1;
static int hf_c15ch_out_gwe_call_notify_status_code = -1;


/* Fields */
static int hf_c15ch_out_gwe_call_prog = -1;
static int hf_c15ch_out_gwe_call_prog_conn_num = -1;
static int hf_c15ch_out_gwe_call_prog_op_gwe_stat_code = -1;
static int hf_c15ch_out_gwe_call_prog_encap_isup = -1;

/* Fields */
static int hf_c15ch_out_gwe_call_rel = -1;
static int hf_c15ch_out_gwe_call_rel_status_code = -1;
static int hf_c15ch_out_gwe_call_rel_encap_isup = -1;

/* Fields */
static int hf_c15ch_out_gwe_call_setup = -1;
static int hf_c15ch_out_gwe_call_setup_conn_num = -1;
static int hf_c15ch_out_gwe_call_setup_op_cl_ans_rsdp_ip = -1;
static int hf_c15ch_out_gwe_call_setup_op_cl_ans_rsdp_port = -1;

static int hf_c15ch_out_gwe_call_setup_op_gwe_redir_digits = -1;

static int hf_c15ch_out_gwe_call_setup_op_gwe_rdir_ton = -1;
static int hf_c15ch_out_gwe_call_setup_op_gwe_rdir_np = -1;

static int hf_c15ch_out_gwe_call_setup_op_gwe_ocn_digits = -1;

static int hf_c15ch_out_gwe_call_setup_op_gwe_chrg_digits = -1;

static int hf_c15ch_out_gwe_call_setup_op_gwe_chrg_noa = -1;
static int hf_c15ch_out_gwe_call_setup_op_gwe_chrg_npi = -1;

static int hf_c15ch_out_gwe_call_setup_encap_isup = -1;


/* Fields */
static int hf_c15ch_out_gwe_conn_num = -1;
static int hf_c15ch_out_gwe_conn_num_out_gwe_conn_num = -1;


/* Fields */
static int hf_c15ch_out_gwe_del_subs_ua = -1;
static int hf_c15ch_out_gwe_del_subs_ua_op_sip_ua_hndl = -1;


/* Fields */
static int hf_c15ch_out_gwe_digit_scan = -1;
static int hf_c15ch_out_gwe_digit_scan_voip_dgmp_override = -1;
static int hf_c15ch_out_gwe_digit_scan_actv_dgmp = -1;
static int hf_c15ch_out_gwe_digit_scan_op_gwe_digit_scan_tone = -1;
static int hf_c15ch_out_gwe_digit_scan_op_gwe_tone_type = -1;
static int hf_c15ch_out_gwe_digit_scan_op_gwe_tone_to = -1;
static int hf_c15ch_out_gwe_digit_scan_op_gwe_digit_flash = -1;

/* Fields */
static int hf_c15ch_out_gwe_line_sprvsn = -1;
static int hf_c15ch_out_gwe_line_sprvsn_op_gwe_ofhk_event = -1;
static int hf_c15ch_out_gwe_line_sprvsn_op_gwe_onhk_event = -1;
static int hf_c15ch_out_gwe_line_sprvsn_op_gwe_flhk_event = -1;


/* Fields */
static int hf_c15ch_out_gwe_md_conn = -1;
static int hf_c15ch_out_gwe_md_conn_conn_num = -1;
static int hf_c15ch_out_gwe_md_conn_status_code = -1;
static int hf_c15ch_out_gwe_md_conn_op_gwe_mode = -1;

/* Fields */
static int hf_c15ch_out_gwe_mk_conn = -1;
static int hf_c15ch_out_gwe_mk_conn_conn_num = -1;
static int hf_c15ch_out_gwe_mk_conn_op_mk_conn_rsdp_ip = -1;
static int hf_c15ch_out_gwe_mk_conn_op_mk_conn_rsdp_port = -1;

/* Fields */
static int hf_c15ch_out_gwe_out_cot = -1;
static int hf_c15ch_out_gwe_out_cot_ni = -1;
static int hf_c15ch_out_gwe_out_cot_tn = -1;
static int hf_c15ch_out_gwe_out_cot_ni_tn = -1;


/* Fields */
static int hf_c15ch_out_gwe_pcm_data = -1;
static int hf_c15ch_out_gwe_pcm_data_rb_ua_handle_near = -1;
static int hf_c15ch_out_gwe_pcm_data_rb_ua_handle_far  = -1;

/* Fields */
static int hf_c15ch_out_gwe_ring_line = -1;
static int hf_c15ch_out_gwe_ring_line_op_gwe_display = -1;
static int hf_c15ch_out_gwe_ring_line_op_gwe_display_chars = -1;


/* Fields */
static int hf_c15ch_out_gwe_rv_subs_data = -1;
static int hf_c15ch_out_gwe_rv_subs_data_rb_fe_ni = -1;
static int hf_c15ch_out_gwe_rv_subs_data_rb_fe_tn = -1;
static int hf_c15ch_out_gwe_rv_subs_data_rb_fe_ni_tn = -1;


/* Fields */
static int hf_c15ch_out_gwe_sac_list_entry = -1;
static int hf_c15ch_out_gwe_sac_list_entry_op_gwe_med_uri = -1;


/* Fields */
static int hf_c15ch_out_gwe_sac_notify = -1;
static int hf_c15ch_out_gwe_sac_notify_op_gwe_blf_state = -1;
static int hf_c15ch_out_gwe_sac_notify_op_gwe_subs_state = -1;


/* Fields */
static int hf_c15ch_out_gwe_sac_sub_valid = -1;
static int hf_c15ch_out_gwe_sac_sub_valid_op_gwe_subs_valid = -1;
static int hf_c15ch_out_gwe_sac_sub_valid_op_gwe_num_list_items = -1;


/* Fields */
static int hf_c15ch_out_gwe_sip_info = -1;
static int hf_c15ch_out_gwe_sip_info_op_gwe_sip_info = -1;
static int hf_c15ch_out_gwe_sip_info_op_gwe_sip_info_type = -1;

/* Fields */
static int hf_c15ch_out_gwe_sip_refer = -1;
static int hf_c15ch_out_gwe_sip_refer_op_gwe_refer_ua_hndl = -1;

/* Fields */
static int hf_c15ch_out_gwe_update_ni_tn = -1;
static int hf_c15ch_out_gwe_update_ni_tn_ni = -1;
static int hf_c15ch_out_gwe_update_ni_tn_tn = -1;
static int hf_c15ch_out_gwe_update_ni_tn_ni_tn = -1;


/* Fields */
static int hf_c15ch_out_gwe_update_rec_addr = -1;
static int hf_c15ch_out_gwe_update_rec_addr_op_new_rec_addr = -1;

/* tone */

#define C15_TONE_TONE_CONTROL 1
#define C15_TONE_GIVE_TONE    2
#define C15_TONE_OPLS         3
#define C15_TONE_COT          4
#define C15_TONE_CPM          5
#define C15_TONE_RCVR         6
#define C15_TONE_MADN_RING    7
#define C15_TONE_TIMEOUT      8

static const value_string tone_types[] = {
    { 0, "None" },
    { 1, "Rgbk" },
    { 2, "Ovflw" },
    { 3, "Dial" },
    { 4, "Howler/Rcvr Off Hook" },
    { 5, "Busy" },
    { 6, "Drop" },
    { 7, "COS_H" },
    { 8, "COS_L" },
    { 9, "Short Howl/Short Rcvr Off Hook" },
    { 10, "Con Rgbk" },
    { 11, "Low" },
    { 12, "High" },
    { 13, "Short Busy" },
    { 14, "Short Ovflw" },
    { 15, "Short Dial" },
    { 16, "Test 5 Sec" },
    { 17, "Test 9 Sec" },
    { 18, "Quiet" },
    { 19, "Quiet 1 Sec" },
    { 20, "Short Rgbk" },
    { 21, "Code2 Rgbk" },
    { 22, "Spec Dial" },
    { 23, "Confirmation" },
    { 24, "Call Waiting" },
    { 25, "1 Blip (Dial Speed Test)" },
    { 26, "2 Blips (Dial Speed Test)" },
    { 27, "3 Blips (Dial Speed Test)" },
    { 28, "ESB Ovflw" },
    { 29, "Src ROH" },
    { 30, "Con Busy" },
    { 31, "Con Rgbk" },
    { 32, "Short Rgbk" },
    { 33, "SWT" },
    { 34, "DWT" },
    { 35, "DROH" },
    { 36, "OPLSR" },
    { 37, "Barge-In" },
    { 38, "Stutter" },
    { 39, "CLID" },
    { 40, "NIC Dime A" },
    { 41, "QRT Doll A" },
    { 42, "NIC Dime B" },
    { 43, "QRT Doll B" },
    { 44, "DRCWT CAS" },
    { 45, "CWT CAS" },
    { 46, "Delay DT" },
    { 47, "P-Phone Norm Ring" },
    { 48, "P-Phone Distinct Ring" },
    { 49, "CWID QT" },
    { 50, "Teen CWT" },
    { 51, "TN2 CWT" },
    { 52, "SDR CWT" },
    { 53, "Teen CAS" },
    { 54, "TN2 CAS" },
    { 55, "SDR CAS" },
    { 56, "P-Phone Cont Ring (First Dnld Tone)" },
    { 57, "P-Phone DTMF Dig 1" },
    { 58, "P-Phone DTMF Dig 2" },
    { 59, "P-Phone DTMF Dig 3" },
    { 60, "P-Phone DTMF Dig 4" },
    { 61, "P-Phone DTMF Dig 5" },
    { 62, "P-Phone DTMF Dig 6" },
    { 63, "P-Phone DTMF Dig 7" },
    { 64, "P-Phone DTMF Dig 8" },
    { 65, "P-Phone DTMF Dig 9" },
    { 66, "P-Phone DTMF *" },
    { 67, "P-Phone DTMF Dig 0" },
    { 68, "P-Phone DTMF #" },
    { 69, "CAS" },
    { 70, "Cust (CTN1)" },
    { 71, "Cust (CTN2)" },
    { 72, "Cust (CTN3)" },
    { 73, "Cust (CTN4)" },
    { 74, "Cust (CTN5)" },
    { 0, NULL }
};
static value_string_ext tone_types_ext = VALUE_STRING_EXT_INIT(tone_types);


/* Dissector Table */
static dissector_table_t c15ch_tone_dissector_table;

/* Fields */
static int hf_c15ch_tone = -1;
static int hf_c15ch_tone_msg_type = -1;

/* Subtree */
static gint ett_c15ch_third_level_tone = -1; /* for third level dissection */
static gint ett_c15ch_third_level_tone_sub1 = -1;

/* Protocol */
static int proto_c15ch_third_level_tone = -1;
/* Fields */
static int hf_c15ch_tone_cot_control = -1;
static int hf_c15ch_tone_cot_control_device_id = -1;
static int hf_c15ch_tone_cot_control_cot_task = -1;
static int hf_c15ch_tone_cot_control_dest_h248 = -1;
static int hf_c15ch_tone_cot_control_srce_h248 = -1;
static int hf_c15ch_tone_cot_control_svc_channel = -1;

/* value labels for fields*/
static const value_string c15_tone_msg_types[] = {
    { C15_TONE_TONE_CONTROL, "TONE_CONTROL" },
    { C15_TONE_GIVE_TONE, "GIVE_TONE" },
    { C15_TONE_OPLS, "OPLS" },
    { C15_TONE_COT, "COT" },
    { C15_TONE_CPM, "CPM" },
    { C15_TONE_RCVR, "RCVR" },
    { C15_TONE_MADN_RING, "MADN_RING" },
    { C15_TONE_TIMEOUT, "TIMEOUT" },
    { 0, NULL }
};

/* Fields */
static int hf_c15ch_tone_cpm = -1;
static int hf_c15ch_tone_cpm_loop_type = -1;
static int hf_c15ch_tone_cpm_device_id = -1;
static int hf_c15ch_tone_cpm_tone_type = -1;


#if 0
/* Subtree */
static gint ett_c15ch_tone_cpm = -1;
#endif

/* labels for loop type */
static const value_string loop_types[] = {
    { 0, "INVALID" },
    { 1, "PE" },
    { 2, "REM" },
    { 3, "DCM" },
    { 4, "SCM" },
    { 5, "LCM" },
    { 6, "SCI" },
    { 7, "SCU" },
    { 8, "VDS30" },
    { 9, "RSCS" },
    { 10, "DS1" },
    { 11, "SMA" },
    { 12, "HUB" },
    { 13, "PRI" },
    { 14, "PGI" },
    { 15, "GWE" },
    { 0, NULL }
};

/* labels for device type */
static const value_string device_types[] = {
    { 0, "CALL_REG" },
    { 1, "SRCE" },
    { 2, "DEST" },
    { 3, "TONE_SRCE" },
    { 4, "RCVR_SRCE" },
    { 5, "TONE_DEST" },
    { 6, "RCVR_DEST" },
    { 7, "CLNG_NUM_BUF" },
    { 8, "TEMP_ID1" },
    { 9, "TEMP_ID2" },
    { 10, "PEPR_SRCE" },
    { 11, "PEPR_DEST" },
    { 12, "BILLING_REG_1" },
    { 13, "BILLING_REG_2" },
    { 14, "BILLING_REG_3" },
    { 15, "BILLING_REG_4" },
    { 16, "BILLING_REG_5" },
    { 17, "BILLING_REG_6" },
    { 18, "ACFW_DIG_BUFF" },
    { 19, "CR_ATR" },
    { 20, "DR_ATR" },
    { 21, "DEV_MAIN_REG" },
    { 22, "TSMS_BUFFER" },
    { 23, "VFG_REG" },
    { 24, "SFTR_BUFF" },
    { 25, "END_TO_END_DIG" },
    { 26, "DEST2" },
    { 27, "TONE_DEST2" },
    { 28, "AIN_REGISTER" },
    { 29, "AIN_STR_BUFFER" },
    { 30, "AUX_BUFF" },
    { 0, NULL },
};
static value_string_ext device_types_ext = VALUE_STRING_EXT_INIT(device_types);


/* Fields */
static int hf_c15ch_tone_give_tone = -1;
static int hf_c15ch_tone_give_tone_tone_id = -1;
static int hf_c15ch_tone_give_tone_tone_type = -1;

/* Fields */
static int hf_c15ch_tone_madn_ring = -1;
static int hf_c15ch_tone_madn_ring_device_id = -1;
static int hf_c15ch_tone_madn_ring_tone_type = -1;

/* Fields */
static int hf_c15ch_tone_opls = -1;
static int hf_c15ch_tone_opls_svce_from_ni = -1;
static int hf_c15ch_tone_opls_svce_to_ni = -1;
static int hf_c15ch_tone_opls_svce_to_ni_tn = -1;
static int hf_c15ch_tone_opls_svce_to_tn = -1;
static int hf_c15ch_tone_opls_digits = -1;


/* Fields */
static int hf_c15ch_tone_rcvr = -1;
static int hf_c15ch_tone_rcvr_rcvr_id = -1;
static int hf_c15ch_tone_rcvr_conn_to_ni = -1;
static int hf_c15ch_tone_rcvr_conn_to_ni_tn = -1;
static int hf_c15ch_tone_rcvr_conn_to_tn = -1;


/* Fields */
static int hf_c15ch_tone_timeout = -1;
static int hf_c15ch_tone_timeout_device_id = -1;
static int hf_c15ch_tone_timeout_service_pm = -1;
static int hf_c15ch_tone_timeout_service_ni = -1;
static int hf_c15ch_tone_timeout_service_ni_tn = -1;
static int hf_c15ch_tone_timeout_service_tn = -1;
static int hf_c15ch_tone_timeout_gw_provided = -1;
static int hf_c15ch_tone_timeout_gw_service_tone_type_or_from_ni = -1;


/* Fields */
static int hf_c15ch_tone_tone_control = -1;
static int hf_c15ch_tone_tone_control_device_id = -1;
static int hf_c15ch_tone_tone_control_tone_type = -1;


/* util functions */
/* static void add_digits_string(int hf, tvbuff_t *tvb, proto_tree *tree,
                    guint first_offset, guint num_digits, guint max_num_digits,
                    guint offset_from_digits_to_consume )
    Function: Add a string of telephony digits, read from a tvbuff_t as a field to a
              given proto_tree.
              The number of digits in the string is typically given in a number before the
              start of the digits.
    Parameters:
    hf is the field number of the proto_tree corresponding to storage for the digits.
    tvb is the tvbuff_t containing the data to be added.
    tree is the proto_tree to be modified.
    first_offset is the offset from the beginning of the tvbuff_t where the telephony digits
        actually begin.  If (first_offset >= tvb_length(tvb)) then the function does nothing.
    num_digits is the number of digits that were actually stored in the relevant part of tvb
       This value was probably determined by reading the field in the tvb just before where the
       string of digits begins.    This will be used to actually allocate storage for the string.
       max_num_digits is the maximum number of digits that the protocol indicates the
       string of digits could be.

      max_num_digits is used in a call to proto_tree_add_string().

    offset_from_digits_to_consume: This number is substracted from first_offset to give the location
        where the num_digits field was read e.g.
        offset_from_digits_to_consume == 1 if length is given in one byte just before digits
        offset_from_digits_to_consume == 4 if length is given in four bytes just before digits
        offset_from_digits_to_consume == 0 if no bytes before the digits are to be consumed
        Note that the offset_from_digits_to_consume method is used in order to properly indicate where
        the data came from that was used to determine the digits field.
        If (offset_from_digits_to_consume > first_offset), then the offset parameter is
        ignored and the display will indicate that the data used began at first_offset (equivalent
        to offset_from_digits_to_consume of 0).
*/
static void add_digits_string(int hf, tvbuff_t *tvb, proto_tree *tree,
                    guint first_offset, guint num_digits, guint max_num_digits, guint offset_from_digits_to_consume )
{
    char * ch_buff = NULL;
    guint curr_offset;
    guint buff_index;
    guint curr_digit;
    const char ZERO_C = '0';
    if (max_num_digits < num_digits)
    {
        return;
    }

    if (first_offset < offset_from_digits_to_consume)
    {
        offset_from_digits_to_consume = 0;
    }
    ch_buff = (char *) wmem_alloc(wmem_packet_scope(), num_digits + 1); /*include space for terminating null*/
    for ( curr_offset = first_offset, buff_index = 0; buff_index < num_digits; curr_offset++, buff_index++ )
    {
        curr_digit = tvb_get_guint8(tvb, curr_offset);

        if ( curr_digit < 10 )
        {
            /* decimal digit case */
            ch_buff[ buff_index ] = ZERO_C + curr_digit;
        }
        else
            {
                switch( curr_digit )
                {
                    case(10):
                        ch_buff[ buff_index ] = 'A';
                        break;
                    case(11):
                        ch_buff[ buff_index ] = '*';
                        break;
                    case(12):
                        ch_buff[ buff_index ] = '#';
                        break;
                    case(15):
                        ch_buff[ buff_index ] = 'D';
                        break;
                    default: /* includes 13 and 14 */
                        ch_buff[ buff_index ] = '?';
                }
            }
    }
    ch_buff[ num_digits ] = '\0';
    /* we are consuming all data from (first_offset - offset_from_start_to_consume) to (first_offset + max_num_digits) */

    proto_tree_add_string(tree, hf,
                tvb, first_offset - offset_from_digits_to_consume, max_num_digits + 1, ch_buff);
}


/* static void add_digits_string_info_col( tvbuff_t *tvb, guint first_offset,
                                    guint num_digits, packet_info *pinfo );
    Function: Append a string of telephony digits, read from a tvbuff_t, to the
              string displayed in COL_INFO, for pinfo.
    Parameters:
        tvb: tvbuff_t containing the digit data.
        first_offset: The offset from the beginning of the tvb where the digits begin.

        num_digits : number of digits to be read from tvb and put into the INFO column.



        pinfo : the packet_info structure containing the INFO column to be modified.
    */
static void add_digits_string_info_col(tvbuff_t *tvb,
                    guint first_offset, guint num_digits,
                    packet_info *pinfo)
{
    /* first_offset is where the list of digits actually begins in the packet */
    /* num_digits is the actual number of digits in the string */
    char * ch_buff;
    guint i;
    const char ZERO_C = '0';

    tvb_ensure_bytes_exist(tvb, first_offset, num_digits);
    ch_buff = (char *) wmem_alloc(wmem_packet_scope(), num_digits + 1); /*include space for terminating null*/
    for ( i = 0; i < num_digits; i++ )
    {
        guint curr_digit = tvb_get_guint8(tvb, i + first_offset);

        if ( curr_digit < 10 )
        {
            /* decimal digit case */
            ch_buff[ i ] = ZERO_C + curr_digit;
        }
        else
        {
            switch( curr_digit )
            {
                case(10):
                    ch_buff[ i ] = 'A';
                    break;
                case(11):
                    ch_buff[ i ] = '*';
                    break;
                case(12):
                    ch_buff[ i ] = '#';
                    break;
                case(15):
                    ch_buff[ i ] = 'D';
                    break;
                default: /* includes 13 and 14 */
                    ch_buff[ i ] = '?';
            }
        }
    }
    ch_buff[ num_digits ] = '\0';
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", ch_buff );
}

/* static void add_string_field( proto_tree * p_tree, tvbuff_t * tvb,
                                guint str_start, guint max_str_len,
                                int hf_num )

   Function: add an ascii string, read from a tvbuff_t, as a field to a given proto_tree

   Parameters:
   p_tree is the proto_tree to be added to

   tvb is the tvbuff_t containing the data to be placed into a string field of p_tree

   str_start is the position in tvb where the string data begins.




   hf_num is the field number for p_tree which is used for the string
*/
static void add_string_field( proto_tree * p_tree, tvbuff_t * tvb,
                                guint str_start, guint max_str_len,
                                int hf_num )
{
    guchar *field_stringz;
    guint len;

    if (max_str_len == 0)
    {
        max_str_len = 1;
    }


    field_stringz = tvb_get_stringz_enc(wmem_packet_scope(), tvb, str_start, &len, ENC_ASCII);
    if ( len <= 1 )
    {
        proto_tree_add_string(p_tree, hf_num,
            tvb, str_start, max_str_len, " ");
    }
    else
    {
        if ( len > max_str_len )
        {
            field_stringz[ max_str_len - 1 ] = '\0';
        }
        proto_tree_add_string(p_tree, hf_num,
                tvb, str_start, max_str_len, field_stringz);
    }
}

/* dissect functions */
/* heartbeat is its own distinct dissector with a distinct ethertype */
static int dissect_c15ch_hbeat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_hbeat_tree = NULL;
    col_clear(pinfo->cinfo, COL_INFO);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "C15CH_HBEAT");

    if (tree)
    {
        ti = proto_tree_add_item(tree, proto_c15ch_hbeat, tvb, 0, 62, ENC_NA);
        c15ch_hbeat_tree = proto_item_add_subtree(ti, ett_c15ch_hbeat);
        add_string_field( c15ch_hbeat_tree, tvb, 10, 25, hf_c15ch_hbeat_clli );
        proto_tree_add_item(c15ch_hbeat_tree, hf_c15ch_hbeat_primary,  tvb, 35, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_hbeat_tree, hf_c15ch_hbeat_secondary,  tvb, 36, 1, ENC_BIG_ENDIAN);
        add_string_field( c15ch_hbeat_tree, tvb, 37, 25, hf_c15ch_hbeat_interface );
    }

    /* Return the amount of data this dissector was able to dissect */
    return tvb_reported_length(tvb);
}

/* base dissector : first one called for all non-heartbeat packets */
/* These packets share a common ethertype */
static int dissect_c15ch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tree = NULL;
    proto_tree * src_ni_tn_tree = NULL;
    proto_tree * dest_ni_tn_tree = NULL;
    guint32 msg_type = 0;
    guint32 packet_length = 0;
    guint32 payload_length = 0;
    guint32 retv = 0;

    tvbuff_t * next_tvb;
    col_clear(pinfo->cinfo, COL_INFO);

    msg_type = tvb_get_ntohl(tvb, 4);
    packet_length = tvb_get_ntohl(tvb, 8);
    if (packet_length < HEADER_SZ)
    {
        return 0;
    }
    payload_length = packet_length - HEADER_SZ;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, C15_LABEL);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: %s",
        val_to_str_ext(msg_type, &c15_msg_types_ext, "Unknown Type: %d") );

    if (tree) /* we are being asked for details... */
    {
        ti = proto_tree_add_item(tree, proto_c15ch, tvb, 0, 36, ENC_NA);
        proto_item_append_text(ti, ", Type: %s",
            val_to_str_ext(msg_type, &c15_msg_types_ext, "Unknown Type: %d"));
        c15ch_tree = proto_item_add_subtree(ti, ett_c15ch);
        proto_tree_add_item(c15ch_tree, hf_c15ch_version,  tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tree, hf_c15ch_msgtype,  tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tree, hf_c15ch_size,     tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tree, hf_c15ch_call_ref, tvb, 12, 4, ENC_BIG_ENDIAN);
        /* src ni/tn */
        ti = proto_tree_add_item(c15ch_tree, hf_c15ch_srce_ni_tn, tvb, 16, 8, ENC_BIG_ENDIAN);
        src_ni_tn_tree = proto_item_add_subtree (ti, ett_src_ni_tn);

        proto_tree_add_item(src_ni_tn_tree, hf_c15ch_srce_ni, tvb, 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(src_ni_tn_tree, hf_c15ch_srce_tn, tvb, 20, 4, ENC_BIG_ENDIAN);

        /* dest ni/tn */
        ti = proto_tree_add_item(c15ch_tree, hf_c15ch_dest_ni_tn, tvb, 24, 8, ENC_BIG_ENDIAN);

        dest_ni_tn_tree = proto_item_add_subtree (ti, ett_dest_ni_tn);

        proto_tree_add_item(dest_ni_tn_tree, hf_c15ch_dest_ni, tvb, 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(dest_ni_tn_tree, hf_c15ch_dest_tn, tvb, 28, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_tree, hf_c15ch_realtime, tvb, 32, 4, ENC_BIG_ENDIAN);
    }

    next_tvb = tvb_new_subset(tvb, HEADER_SZ, -1, payload_length);
    /* call dissector to dissect the rest of the packet, based on msg_type */
    retv = HEADER_SZ + dissector_try_uint(c15ch_dissector_table, msg_type, next_tvb, pinfo, tree);
    return retv;
}


static int dissect_c15ch_ama(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_ama_tree = NULL;

    guint8 call_type_val = 0;
    guint8 dialed_num_digits;

    call_type_val = tvb_get_guint8(tvb, 40);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Call Type: %s",
        val_to_str_ext(call_type_val, &ama_call_types_ext, "Unknown %d") );
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_ama, tvb, 0, 41, ENC_NA);
        c15ch_ama_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        dialed_num_digits = tvb_get_guint8(tvb, 11);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_call_code,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_ama_orig_digits, tvb, c15ch_ama_tree,
                        1, 10, 10, 0);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_num_dialed_digits,
                            tvb, 11, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_br_prefix,
                            tvb, 12, 1, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_ama_dialed_digits, tvb, c15ch_ama_tree,
                        13, dialed_num_digits, 15, 0);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_start_hour,
                            tvb, 28, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_start_minute,
                            tvb, 29, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_start_second,
                            tvb, 30, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_start_tenth_second,
                            tvb, 31, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_start_day,
                            tvb, 32, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_start_month,
                            tvb, 33, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_start_year,
                            tvb, 34, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_answered,
                            tvb, 35, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_elapsed_time,
                            tvb, 36, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ama_tree, hf_c15ch_ama_call_type,
                            tvb, 40, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_c15_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_c15_info_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item( tree, hf_c15ch_c15_info, tvb, 0, 266, ENC_NA );
        c15ch_c15_info_tree = proto_item_add_subtree( ti, ett_c15ch_second_level );
        proto_tree_add_item( c15ch_c15_info_tree, hf_c15ch_c15_info_level, tvb, 0, 1, ENC_BIG_ENDIAN );
        add_string_field( c15ch_c15_info_tree, tvb, 1, 9, hf_c15ch_c15_info_code );
        add_string_field( c15ch_c15_info_tree, tvb, 10, 256, hf_c15ch_c15_info_text );
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_clli(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_clli_tree = NULL;

    gint clli_siz;
    guchar * clli_string;
    clli_string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, 0, &clli_siz, ENC_ASCII );
    if ( (clli_siz > 1) && (clli_siz <= 25 ) )
    {
        col_clear(pinfo->cinfo, COL_INFO);
        col_append_fstr( pinfo->cinfo, COL_INFO, "Type: CLLI, %s", clli_string );
    }
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_clli, tvb, 0, 60, ENC_NA);
        c15ch_clli_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        add_string_field( c15ch_clli_tree, tvb, 0, 25, hf_c15ch_clli_clli_string );
        proto_tree_add_item(c15ch_clli_tree, hf_c15ch_clli_active_core,  tvb, 25, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_clli_tree, hf_c15ch_clli_inactive_core,  tvb, 26, 1, ENC_BIG_ENDIAN);
        add_string_field( c15ch_clli_tree, tvb, 27, 25, hf_c15ch_clli_interface_string );
        proto_tree_add_item(c15ch_clli_tree, hf_c15ch_clli_seconds,  tvb, 52, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_clli_tree, hf_c15ch_clli_microseconds,  tvb, 56, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_conn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_conn_tree = NULL;
    proto_tree * srce_ni_tn_tree = NULL;
    proto_tree * dest_ni_tn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_conn, tvb, 0, 53, ENC_NA);
        c15ch_conn_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_connfrom,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_conntype,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_perphtype,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_intra,
                            tvb, 12, 1, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_srcenitn,
                            tvb, 13, 8, ENC_BIG_ENDIAN);
        srce_ni_tn_tree = proto_item_add_subtree(ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(srce_ni_tn_tree, hf_c15ch_conn_srceni,
                            tvb, 13, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(srce_ni_tn_tree, hf_c15ch_conn_srcetn,
                            tvb, 17, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_destnitn,
                            tvb, 21, 8, ENC_BIG_ENDIAN);
        dest_ni_tn_tree = proto_item_add_subtree(ti, ett_c15ch_second_level_sub2);
        proto_tree_add_item(dest_ni_tn_tree, hf_c15ch_conn_destni,
                            tvb, 21, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(dest_ni_tn_tree, hf_c15ch_conn_desttn,
                            tvb, 25, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_interlinknum,
                            tvb, 29, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_fromport,
                            tvb, 33, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_fromslot,
                            tvb, 37, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_toport,
                            tvb, 41, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_toslot,
                            tvb, 45, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_conn_tree, hf_c15ch_conn_hubcallid,
                            tvb, 49, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_cp_state_ch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    proto_item * ti = NULL;
    proto_tree * c15ch_cp_state_ch_tree = NULL;

    guint32 oldpm_value = 0;
    guint32 newpm_value = 0;
    col_clear(pinfo->cinfo, COL_INFO);
    oldpm_value = tvb_get_ntohl(tvb, 0);
    newpm_value = tvb_get_ntohl(tvb, 4);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: CP_STATE_CH, %s --> ",
        val_to_str_ext(oldpm_value, &c15_cp_state_pm_types_ext, "Unknown") );

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
        val_to_str_ext(newpm_value, &c15_cp_state_pm_types_ext, "Unknown") );

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_cp_state_ch, tvb, 0, 40, ENC_NA);
        proto_item_append_text(ti, ", Old PM Type: %s",
            val_to_str_ext(oldpm_value, &c15_cp_state_pm_types_ext, "Unknown"));
        proto_item_append_text(ti, ", New PM Type: %s",
            val_to_str_ext(newpm_value, &c15_cp_state_pm_types_ext, "Unknown"));

        c15ch_cp_state_ch_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_cp_state_ch_tree, hf_c15ch_cp_state_ch_oldpm,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_state_ch_tree, hf_c15ch_cp_state_ch_newpm,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_state_ch_tree, hf_c15ch_cp_state_ch_subpm,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_state_ch_tree, hf_c15ch_cp_state_ch_trkpm,
                            tvb, 12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_state_ch_tree, hf_c15ch_cp_state_ch_slepm,
                            tvb, 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_state_ch_tree, hf_c15ch_cp_state_ch_flags,
                            tvb, 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_state_ch_tree, hf_c15ch_cp_state_ch_oldrtetype,
                            tvb, 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_state_ch_tree, hf_c15ch_cp_state_ch_oldrteidx,
                            tvb, 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_state_ch_tree, hf_c15ch_cp_state_ch_newrtetype,
                            tvb, 32, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_state_ch_tree, hf_c15ch_cp_state_ch_newrteidx,
                            tvb, 36, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_dest_digits(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_dest_digits_tree = NULL;

    guint32 num_digits;
    num_digits = tvb_get_ntohl(tvb, 0);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", " );
    add_digits_string_info_col( tvb, 4, num_digits, pinfo);
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_dest_digits, tvb, 0, 36, ENC_NA);
        c15ch_dest_digits_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        add_digits_string(hf_c15ch_dest_digits_digits, tvb, c15ch_dest_digits_tree, 4, num_digits, 32, 4);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_echo_cancel(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_echo_cancel_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;
    proto_tree * loc_tree = NULL;
    proto_tree * old_tree = NULL;
    proto_tree * new_tree = NULL;

    guint8 valid_tone_id = 0;
    guint8 old_l2_mode_val, new_l2_mode_val;
    enum C15_EC_CHANNEL_MODE old_channel_mode, new_channel_mode;
    enum C15_EC_ECAN_MODE old_ecan_mode, new_ecan_mode;
    guint32 pm_val, pc_val, loop_val, slot_val;

    char * loc_string = NULL;


    old_l2_mode_val = tvb_get_guint8(tvb, 8);
    new_l2_mode_val = tvb_get_guint8(tvb, 9);

    switch( old_l2_mode_val )
    {
        case C15_EC_L2_MODE_VOICE:
            {
                old_channel_mode = C15_EC_VOICE_CHANNEL_MODE;
                old_ecan_mode = C15_EC_ON_ECAN_MODE;
            }
            break;
        case C15_EC_L2_MODE_VBD:
            {
                old_channel_mode = C15_EC_VBD_CHANNEL_MODE;
                old_ecan_mode = C15_EC_ON_ECAN_MODE;
            }
            break;
        case C15_EC_L2_MODE_VBD_ECANOFF:
            {
                old_channel_mode = C15_EC_VBD_CHANNEL_MODE;
                old_ecan_mode = C15_EC_OFF_ECAN_MODE;
            }
            break;
        default:
            {
                old_channel_mode = C15_EC_CHANNEL_MODE_INVALID;
                old_ecan_mode = C15_EC_ECAN_MODE_INVALID;
            }
            break;
    }

    switch( new_l2_mode_val )
    {
        case C15_EC_L2_MODE_VOICE:
            {
                new_channel_mode = C15_EC_VOICE_CHANNEL_MODE;
                new_ecan_mode = C15_EC_ON_ECAN_MODE;
            }
            break;
        case C15_EC_L2_MODE_VBD:
            {
                new_channel_mode = C15_EC_VBD_CHANNEL_MODE;
                new_ecan_mode = C15_EC_ON_ECAN_MODE;
            }
            break;
        case C15_EC_L2_MODE_VBD_ECANOFF:
            {
                new_channel_mode = C15_EC_VBD_CHANNEL_MODE;
                new_ecan_mode = C15_EC_OFF_ECAN_MODE;
            }
            break;
        default:
            {
                new_channel_mode = C15_EC_CHANNEL_MODE_INVALID;
                new_ecan_mode = C15_EC_ECAN_MODE_INVALID;
            }
            break;
    }

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_echo_cancel, tvb, 0, 31, ENC_NA);
        c15ch_echo_cancel_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        ti = proto_tree_add_item(c15ch_echo_cancel_tree, hf_c15ch_echo_cancel_ni_tn,
                            tvb, 0, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_echo_cancel_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_echo_cancel_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        valid_tone_id = tvb_get_guint8( tvb, 10 );
        if ( valid_tone_id )
        {
            proto_tree_add_item(c15ch_echo_cancel_tree, hf_c15ch_echo_cancel_tone_id, tvb, 11, 4, ENC_BIG_ENDIAN);
        }
        ti = proto_tree_add_item(c15ch_echo_cancel_tree, hf_c15ch_echo_cancel_old_l2_mode,
                            tvb, 8, 1, ENC_BIG_ENDIAN);
        old_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub2);
        proto_tree_add_uint(old_tree, hf_c15ch_echo_cancel_old_channel_mode, tvb, 8, 1, (guint32)old_channel_mode);
        proto_tree_add_uint(old_tree, hf_c15ch_echo_cancel_old_ecan_mode, tvb, 8, 1, (guint32)old_ecan_mode);

        ti = proto_tree_add_item(c15ch_echo_cancel_tree, hf_c15ch_echo_cancel_new_l2_mode,
                            tvb, 9, 1, ENC_BIG_ENDIAN);
        new_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub3);
        proto_tree_add_uint(new_tree, hf_c15ch_echo_cancel_new_channel_mode,
                            tvb, 9, 1, (guint32)new_channel_mode);
        proto_tree_add_uint(new_tree, hf_c15ch_echo_cancel_new_ecan_mode,
                            tvb, 9, 1, (guint32)new_ecan_mode);

        /* location : pm, pc, loop, slot */
        pm_val = tvb_get_ntohl( tvb, 15 );
        pc_val = tvb_get_ntohl( tvb, 19 );
        loop_val = tvb_get_ntohl( tvb, 23 );
        slot_val = tvb_get_ntohl( tvb, 27 );
        loc_string = (char *) wmem_alloc0(wmem_packet_scope(), MAX_LEN_LOC_STRING); /* init to all NULL */
        g_snprintf( loc_string, MAX_LEN_LOC_STRING, "%d  %d  %d  %d", pm_val, pc_val, loop_val, slot_val );
        ti = proto_tree_add_string(c15ch_echo_cancel_tree, hf_c15ch_echo_cancel_location, tvb, 15, (27 + 4 - 15) + 1, loc_string);
        loc_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub4);

        proto_tree_add_item(loc_tree, hf_c15ch_echo_cancel_pm, tvb, 15, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(loc_tree, hf_c15ch_echo_cancel_pc, tvb, 19, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(loc_tree, hf_c15ch_echo_cancel_loop, tvb, 23, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(loc_tree, hf_c15ch_echo_cancel_slot, tvb, 27, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_encap_isup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_encap_isup_tree = NULL;
    tvbuff_t * next_tvb;

    if (tree)
    {

        ti = proto_tree_add_item(tree, hf_c15ch_encap_isup, tvb, 0, 273, ENC_NA);
        c15ch_encap_isup_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_encap_isup_tree, hf_c15ch_encap_isup_direction,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_encap_isup_tree, hf_c15ch_encap_isup_isup_msg_length,
                            tvb, 1, 4, ENC_BIG_ENDIAN);

        /*length of ISUP portion == expected length == 268 */
        next_tvb = tvb_new_subset(tvb, 5, 268, 268);
        call_dissector(general_isup_handle, next_tvb, pinfo, tree);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, C15_LABEL);
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: ISUP");

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_isup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_isup_tree = NULL;
    proto_tree * c15ch_sub_hdr_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;
    guint8 msgtype_value = 0;
    tvbuff_t * next_tvb;

    msgtype_value = tvb_get_guint8(tvb, 1);

    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Msg Type: %s",
        val_to_str_ext(msgtype_value, &c15_isup_types_ext, "Unknown") );

    if (tree)
    {

        ti = proto_tree_add_item(tree, hf_c15ch_isup, tvb, 0, 324, ENC_NA);
        proto_item_append_text(ti, ", Msg Type: %s",
            val_to_str_ext(msgtype_value, &c15_isup_types_ext, "Unknown"));
        c15ch_isup_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_direction,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_msgtype,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_cic,
                            tvb, 2, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_opcmember,
                            tvb, 6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_opccluster,
                            tvb, 7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_opcnetwork,
                            tvb, 8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_dpcmember,
                            tvb, 9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_dpccluster,
                            tvb, 10, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_dpcnetwork,
                            tvb, 11, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_level3index,
                            tvb, 12, 1, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_ni_tn,
                            tvb, 13, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_isup_ni,
                            tvb, 13, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_isup_tn,
                            tvb, 17, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_isup_tree, hf_c15ch_isup_iptime,
                            tvb, 320, 4, ENC_BIG_ENDIAN);

        c15ch_sub_hdr_tree = proto_tree_add_subtree(c15ch_isup_tree,
                           tvb, 21, 28, ett_c15ch_second_level_sub2, NULL, "Raw Header Data");
        proto_tree_add_item(c15ch_sub_hdr_tree, hf_c15ch_isup_c15hdr,
                            tvb, 21, 18, ENC_NA);
        proto_tree_add_item(c15ch_sub_hdr_tree, hf_c15ch_isup_layer2hdr,
                            tvb, 39, 2, ENC_NA);
        proto_tree_add_item(c15ch_sub_hdr_tree, hf_c15ch_isup_layer3hdr,
                            tvb, 41, 8, ENC_NA);

        /*length of ISUP portion == expected length == 271 */
        next_tvb = tvb_new_subset(tvb, 49, 271, 271);
        call_dissector(general_isup_handle, next_tvb, pinfo, tree);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, C15_LABEL);
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: ISUP, Msg Type: %s",
        val_to_str_ext(msgtype_value, &c15_isup_types_ext, "Unknown Type") );

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_mkbrk(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_mkbrk_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_mkbrk, tvb, 0, 11, ENC_NA);
        c15ch_mkbrk_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_mkbrk_tree, hf_c15ch_mkbrk_makebreak,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_mkbrk_tree, hf_c15ch_mkbrk_nshlf,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_mkbrk_tree, hf_c15ch_mkbrk_stm,
                            tvb, 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_mkbrk_tree, hf_c15ch_mkbrk_caddr,
                            tvb, 3, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_mkbrk_tree, hf_c15ch_mkbrk_cdata,
                            tvb, 7, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_nitnxlate(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    proto_item * ti = NULL;
    proto_tree * c15ch_nitnxlate_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;
    proto_tree * concat_tree = NULL;
    char * concat_string = NULL;
    guchar * site_string;
    guchar * subsite_string;
    guchar * equipname_string;
    char * desc_string = NULL;
    gint str_start;
    gint max_str_len;
    gint site_str_len, subsite_str_len, equipname_str_len;
    guint32 gwtype_val;
    guint32 frame_val, shelf_val, lsg_val, unit_val;
    guint32 key_val;
    concat_string = (char *) wmem_alloc0(wmem_packet_scope(), MAX_LEN_CONCAT_STRING); /* init to all NULL */
    desc_string = (char *) wmem_alloc0(wmem_packet_scope(), MAX_LEN_DESC_STRING);
    /* sitestring */
    str_start = 12;
    max_str_len = 5;
    site_string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, str_start, &site_str_len, ENC_ASCII);
    if ( site_str_len > max_str_len )
    {
        site_string[ max_str_len - 1] = '\0';
    }

    /* subsitestring */
    str_start = 17;
    max_str_len = 5;
    subsite_string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, str_start, &subsite_str_len, ENC_ASCII);
    if ( subsite_str_len > max_str_len )
    {
        subsite_string[ max_str_len - 1] = '\0';
    }

    /* equipname */
    str_start = 22;
    max_str_len = 5;
    equipname_string = tvb_get_stringz_enc(wmem_packet_scope(), tvb, str_start, &equipname_str_len, ENC_ASCII);
    if ( equipname_str_len > max_str_len )
    {
        equipname_string[ max_str_len - 1] = '\0';
    }

    frame_val = tvb_get_ntohl( tvb, 31 );
    shelf_val = tvb_get_ntohl( tvb, 35 );
    lsg_val = tvb_get_ntohl( tvb, 39 );
    unit_val = tvb_get_ntohl( tvb, 43 );
    key_val = tvb_get_ntohl( tvb, 47 );
    /* desc_string contains for site, subsite, equip, any of which may be null */
    /* don't want to print "NULL" or similar in the output string on any platform */
    if ( ( site_str_len > 1 ) && ( subsite_str_len > 1 ) && ( equipname_str_len > 1 ) )
    {
        /* 1) none of site, subsite, or equip is null */
        g_snprintf( desc_string, MAX_LEN_DESC_STRING, "%s %s %s ", site_string, subsite_string, equipname_string );
    }
    else
        if ( ( site_str_len < 2 ) && ( subsite_str_len > 1 ) && ( equipname_str_len > 1 ) )
        {
            /* 2) only site is null */
            g_snprintf( desc_string, MAX_LEN_DESC_STRING, "%s %s ", subsite_string, equipname_string );
        }
        else
            if ( ( site_str_len > 1 ) && ( subsite_str_len < 2 ) && ( equipname_str_len > 1 ) )
            {
                /* 3) only subsite is null */
                g_snprintf( desc_string, MAX_LEN_DESC_STRING, "%s %s ", site_string, equipname_string);
            }
            else
                if ( ( site_str_len > 1 ) && ( subsite_str_len > 1 ) && ( equipname_str_len < 2 ) )
                {
                    /* 4) only equip is null */
                    g_snprintf( desc_string, MAX_LEN_DESC_STRING, "%s %s ", site_string, subsite_string);
                }
                else
                    if ( ( site_str_len < 2 ) && ( subsite_str_len < 2 ) && ( equipname_str_len > 1 ) )
                    {
                        /* 5) site and subsite are null but equip is non-null */
                        g_snprintf( desc_string, MAX_LEN_DESC_STRING, "%s ", equipname_string );
                    }
                    else
                        if ( ( site_str_len < 2 ) && ( subsite_str_len > 1 ) && ( equipname_str_len < 2 ) )
                        {
                            /* 6) site and equip are null but subsite is not-null */
                            g_snprintf( desc_string, MAX_LEN_DESC_STRING, "%s ", subsite_string );
                        }
                        else
                            if ( ( site_str_len > 1 ) && ( subsite_str_len < 2 ) && ( equipname_str_len < 2 ) )
                            {
                                /* 7) subsite and equip are null but site is not-null */
                                g_snprintf( desc_string, MAX_LEN_DESC_STRING, "%s ", site_string );
                            }
                            /* else site, subsite, equip are all null */
    if ( key_val )
    {
        if ( strlen( desc_string ) )
        {
            g_snprintf( concat_string, MAX_LEN_CONCAT_STRING, "%s%d %d %d %d %d",
                desc_string, frame_val, shelf_val, lsg_val, unit_val, key_val );
        }
        else
        {
            g_snprintf( concat_string, MAX_LEN_CONCAT_STRING, "%d %d %d %d %d",
                    frame_val, shelf_val, lsg_val, unit_val, key_val );
        }
    }
    else
    {
        if ( strlen( desc_string) )
        {
            if ( (g_strcmp0( "VLIN", equipname_string) == 0) ||
                 (g_strcmp0( "PTRK", equipname_string) == 0) )
            {
                g_snprintf( concat_string, MAX_LEN_CONCAT_STRING, "%s%d",
                        desc_string, frame_val );
            }
            else
                if ( (g_strcmp0( "GWE", equipname_string ) == 0) ||
                 (g_strcmp0( "IDE", equipname_string ) == 0) )
                {
                    g_snprintf( concat_string, MAX_LEN_CONCAT_STRING, "%s%d %d",
                        desc_string, frame_val, shelf_val );
                }
            else
                g_snprintf( concat_string, MAX_LEN_CONCAT_STRING, "%s%d %d %d %d",
                    desc_string, frame_val, shelf_val, lsg_val, unit_val);
        } /* if ( strlen( desc_string ) ) */
        else
        {
            g_snprintf( concat_string, MAX_LEN_CONCAT_STRING, "%d %d %d %d",
                    frame_val, shelf_val, lsg_val, unit_val);
        }
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", concat_string );
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_nitnxlate, tvb, 0, 190, ENC_NA);
        c15ch_nitnxlate_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);

        ti = proto_tree_add_item(c15ch_nitnxlate_tree, hf_c15ch_nitnxlate_ni_tn, tvb, 0, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_nitnxlate_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_nitnxlate_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        /* equiptype */
        proto_tree_add_item(c15ch_nitnxlate_tree, hf_c15ch_nitnxlate_equiptype,
                            tvb, 8, 4, ENC_BIG_ENDIAN);


        ti = proto_tree_add_string(c15ch_nitnxlate_tree, hf_c15ch_nitnxlate_concat_string, tvb, 12, 40 /*length*/,
                                concat_string);
        concat_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub2);
        if ( site_str_len > 1 )
        {
            str_start = 12;
            max_str_len = 5;
            add_string_field( concat_tree, tvb, str_start, max_str_len, hf_c15ch_nitnxlate_sitestring );
        }
        if ( subsite_str_len > 1 )
        {
            str_start = 17;
            max_str_len = 5;
            add_string_field( concat_tree, tvb, str_start, max_str_len, hf_c15ch_nitnxlate_subsitestring );
        }
        if ( equipname_str_len > 1 )
        {
            str_start = 22;
            max_str_len = 5;
            add_string_field( concat_tree, tvb, str_start, max_str_len, hf_c15ch_nitnxlate_equipname );
        }
        if ( g_strcmp0( "GWE", equipname_string) == 0 )
        {
            proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_gateway,
                            tvb, 31, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_line,
                            tvb, 35, 4, ENC_BIG_ENDIAN);
        }
        else
            if ( g_strcmp0( "IDE", equipname_string ) == 0 )
            {
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_idt_rdt,
                            tvb, 31, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_line,
                            tvb, 35, 4, ENC_BIG_ENDIAN);
            }
        else
            if ( g_strcmp0( "VLIN", equipname_string ) == 0 )
            {
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_line,
                            tvb, 31, 4, ENC_BIG_ENDIAN);
            }
        else
            if ( g_strcmp0( "PTRK", equipname_string ) == 0 )
            {
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_ptrk,
                            tvb, 31, 4, ENC_BIG_ENDIAN);
            }
        else
            if ( (g_strcmp0( "LCE", equipname_string ) == 0) ||
                 (g_strcmp0( "RSE", equipname_string ) == 0) ||
                 (g_strcmp0( "RSC", equipname_string ) == 0) ||
                 (g_strcmp0( "HUBE", equipname_string) == 0) )
            {
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_bay,
                            tvb, 31, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_shelf,
                            tvb, 35, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_lsg,
                            tvb, 39, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_line,
                            tvb, 43, 4, ENC_BIG_ENDIAN);
                if ( key_val )
                {
                    proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_key,
                            tvb, 47, 4, ENC_BIG_ENDIAN);
                }
            }
        else
            if (equipname_str_len <= 1)
            {
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_pm,
                            tvb, 31, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_pc_sts1,
                            tvb, 35, 4, ENC_BIG_ENDIAN); /* either pc or sts1 */
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_port_vt15,
                            tvb, 39, 4, ENC_BIG_ENDIAN); /* either port or vt15 */
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_channel,
                            tvb, 43, 4, ENC_BIG_ENDIAN);
            }
        else /* default case : label generically as parms  */
        {
            proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_parm_1,
                            tvb, 31, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_parm_2,
                            tvb, 35, 4, ENC_BIG_ENDIAN);

            proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_parm_3,
                            tvb, 39, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_parm_4,
                            tvb, 43, 4, ENC_BIG_ENDIAN);
            if ( key_val )
            {
                proto_tree_add_item(concat_tree, hf_c15ch_nitnxlate_key,
                            tvb, 47, 4, ENC_BIG_ENDIAN);
            }
        }
        /* gw type */
        proto_tree_add_item(c15ch_nitnxlate_tree, hf_c15ch_nitnxlate_gw_type,
                            tvb, 27, 4, ENC_BIG_ENDIAN);
        /* user_tid */
        if ( g_strcmp0( "GWE", equipname_string ) == 0 )
        {
            str_start = 51;
            max_str_len = 65;
            add_string_field( c15ch_nitnxlate_tree, tvb, str_start, max_str_len, hf_c15ch_nitnxlate_user_tid );
        }
        /* host */
        str_start = 116;
        max_str_len = 65;
        gwtype_val = tvb_get_ntohl( tvb, 27 );
        if ( gwtype_val )
        {
            add_string_field( c15ch_nitnxlate_tree, tvb, str_start, max_str_len, hf_c15ch_nitnxlate_host );
        }

        /* target group number */
        if ( g_strcmp0( "PTRK", equipname_string ) == 0 )
        {
            proto_tree_add_item(c15ch_nitnxlate_tree, hf_c15ch_nitnxlate_tg_num,
                            tvb, 181, 4, ENC_BIG_ENDIAN);
        }


         add_string_field( c15ch_nitnxlate_tree, tvb, 185, 5, hf_c15ch_nitnxlate_mgcp_line_id);

    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_ntwk_conn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_ntwk_conn_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;
    proto_tree * old_loc_tree = NULL;
    proto_tree * new_loc_tree = NULL;

    guint8 from_pm_val, from_pc_val, from_loop_val, from_slot_val;
    char * from_loc_string = NULL;

    guint8 to_pm_val, to_pc_val, to_loop_val, to_slot_val;
    char * to_loc_string = NULL;

    guint8 path_type_val = 0;
    guint8 conn_type_val = 0;
    path_type_val = tvb_get_guint8(tvb, 0);
    conn_type_val = tvb_get_guint8(tvb, 1);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Path Type: %s",
        val_to_str(path_type_val, ett_c15ch_ntwk_conn_path_types, "Unknown %d") );
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Conn Type: %s",
        val_to_str(conn_type_val, ett_c15ch_ntwk_conn_conn_types, "Unknown %d") );
    if (tree)
    {
        gint str_start;
        gint max_str_len;
        ti = proto_tree_add_item(tree, hf_c15ch_ntwk_conn, tvb, 0, 39, ENC_NA);
        c15ch_ntwk_conn_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);

        /* misc. fields */
        proto_tree_add_item(c15ch_ntwk_conn_tree, hf_c15ch_ntwk_conn_pathtype,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ntwk_conn_tree, hf_c15ch_ntwk_conn_conntype,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ntwk_conn_tree, hf_c15ch_ntwk_conn_fromoptimized,
                            tvb, 2, 1, ENC_BIG_ENDIAN);

        /* fromsite */
        str_start = 3;
        max_str_len = 5;
        add_string_field( c15ch_ntwk_conn_tree, tvb, str_start, max_str_len, hf_c15ch_ntwk_conn_fromsite );

        /* old location and pm, pc, slot, loop*/
        from_pm_val = tvb_get_guint8( tvb, 8 );
        from_pc_val = tvb_get_guint8( tvb, 9 );
        from_loop_val = tvb_get_guint8( tvb, 10 );
        from_slot_val = tvb_get_guint8( tvb, 11 );
        from_loc_string = (char *) wmem_alloc0(wmem_packet_scope(), MAX_LEN_LOC_STRING); /* init to all NULL */
        g_snprintf( from_loc_string, MAX_LEN_LOC_STRING, "%d  %d  %d  %d", from_pm_val, from_pc_val, from_loop_val, from_slot_val );
        ti = proto_tree_add_string(c15ch_ntwk_conn_tree, hf_c15ch_ntwk_conn_fromlocation, tvb, 8, (11 - 8) + 1,
                                from_loc_string);
        old_loc_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(old_loc_tree, hf_c15ch_ntwk_conn_frompm,
                            tvb, 8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(old_loc_tree, hf_c15ch_ntwk_conn_frompc,
                            tvb, 9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(old_loc_tree, hf_c15ch_ntwk_conn_fromloop,
                            tvb, 10, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(old_loc_tree, hf_c15ch_ntwk_conn_fromslot,
                            tvb, 11, 1, ENC_BIG_ENDIAN);

        /* misc. fields */
        proto_tree_add_item(c15ch_ntwk_conn_tree, hf_c15ch_ntwk_conn_fromcnx,
                            tvb, 12, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_ntwk_conn_tree, hf_c15ch_ntwk_conn_fromntwknitn,
                            tvb, 16, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti,ett_c15ch_second_level_sub2);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_ntwk_conn_fromntwkni,
                            tvb, 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_ntwk_conn_fromntwktn,
                            tvb, 20, 4, ENC_BIG_ENDIAN);


        proto_tree_add_item(c15ch_ntwk_conn_tree, hf_c15ch_ntwk_conn_mbshold,
                            tvb, 24, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ntwk_conn_tree, hf_c15ch_ntwk_conn_tooptimized,
                            tvb, 25, 1, ENC_BIG_ENDIAN);
        /* tosite */
        str_start = 26;
        max_str_len = 5;
        add_string_field( c15ch_ntwk_conn_tree, tvb, str_start, max_str_len, hf_c15ch_ntwk_conn_tosite );

        /* new location and pm, pc, slot, loop*/
        to_pm_val = tvb_get_guint8( tvb, 31 );
        to_pc_val = tvb_get_guint8( tvb, 32 );
        to_loop_val = tvb_get_guint8( tvb, 33 );
        to_slot_val = tvb_get_guint8( tvb, 34 );
        to_loc_string = (char *) wmem_alloc0(wmem_packet_scope(), MAX_LEN_LOC_STRING); /* init to all NULL */
        g_snprintf( to_loc_string, MAX_LEN_LOC_STRING, "%d  %d  %d  %d", to_pm_val, to_pc_val, to_loop_val, to_slot_val );
        ti = proto_tree_add_string(c15ch_ntwk_conn_tree, hf_c15ch_ntwk_conn_tolocation, tvb, 31, (34 - 31) + 1,
                                to_loc_string);
        new_loc_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub3);
        proto_tree_add_item(new_loc_tree, hf_c15ch_ntwk_conn_topm,
                            tvb, 31, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(new_loc_tree, hf_c15ch_ntwk_conn_topc,
                            tvb, 32, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(new_loc_tree, hf_c15ch_ntwk_conn_toloop,
                            tvb, 33, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(new_loc_tree, hf_c15ch_ntwk_conn_toslot,
                            tvb, 34, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_ntwk_conn_tree, hf_c15ch_ntwk_conn_tocnx,
                            tvb, 35, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_orig(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_orig_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;

    guint8 num_dn_digits;
    guint8 num_upn_digits;
    guint8 num_rnp_digits;

    num_dn_digits = tvb_get_guint8(tvb, 12);

    col_append_fstr(pinfo->cinfo, COL_INFO, ", DN: " );
    add_digits_string_info_col( tvb, 13, num_dn_digits, pinfo);

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_orig, tvb, 0, 73, ENC_NA);
        c15ch_orig_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        num_upn_digits = tvb_get_guint8(tvb, 28);
        num_rnp_digits = tvb_get_guint8(tvb, 49);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_tnblocktype,
                            tvb, 0, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_ni_tn, tvb, 4, 8, ENC_BIG_ENDIAN);

        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_orig_ni,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_orig_tn,
                            tvb, 8, 4, ENC_BIG_ENDIAN);

        add_digits_string(hf_c15ch_orig_dndigits,tvb,c15ch_orig_tree, 13, num_dn_digits, 10, 1);

        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_nidscrn,
                            tvb, 23, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_nidaddrtype,
                            tvb, 24, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_nidnmbrplan,
                            tvb, 25, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_nidprivind,
                            tvb, 26, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_upnsaved,
                            tvb, 27, 1, ENC_BIG_ENDIAN);

        add_digits_string(hf_c15ch_orig_upndigits,tvb,c15ch_orig_tree, 29, num_upn_digits, 15, 1);

        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_upnscrn,
                            tvb, 44, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_upnaddrtype,
                            tvb, 45, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_upnnmbrplan,
                            tvb, 46, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_upnprivind,
                            tvb, 47, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_rnpsaved,
                            tvb, 48, 1, ENC_BIG_ENDIAN);

        add_digits_string(hf_c15ch_orig_rnpdigits,tvb,c15ch_orig_tree, 50, num_rnp_digits, 15, 1);

        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_rnpscrn,
                            tvb, 65, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_rnpaddrtype,
                            tvb, 66, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_rnpnmbrplan,
                            tvb, 67, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_rnpprivind,
                            tvb, 68, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_orig_tree, hf_c15ch_orig_iptime,
                            tvb, 69, 4, ENC_BIG_ENDIAN);

    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_outgwebc(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_outgwebc_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;


    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_outgwebc, tvb, 0, 27, ENC_NA);
        c15ch_outgwebc_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);

        ti = proto_tree_add_item(c15ch_outgwebc_tree, hf_c15ch_outgwebc_pbc_conn_ni_tn,
                            tvb, 0, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);

        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_outgwebc_pbc_conn_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_outgwebc_pbc_conn_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_outgwebc_tree, hf_c15ch_outgwebc_pbc_conn_num,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_outgwebc_tree, hf_c15ch_outgwebc_pbc_conn_type,
                            tvb, 12, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_outgwebc_tree, hf_c15ch_outgwebc_bc_msg_type,
                            tvb, 13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_outgwebc_tree, hf_c15ch_outgwebc_op_bc_sdp_ip,
                            tvb, 14, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_outgwebc_tree, hf_c15ch_outgwebc_op_bc_sdp_port,
                            tvb, 18, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_outgwebc_tree, hf_c15ch_outgwebc_pbc_mdrp_mode,
                            tvb, 22, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_outgwebc_tree, hf_c15ch_outgwebc_pbc_tst_flags,
                            tvb, 23, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_pathfind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_pathfind_tree = NULL;
    proto_tree * fromgwe_ni_tn_tree = NULL;
    proto_tree * from_ni_tn_tree = NULL;
    proto_tree * togwe_ni_tn_tree = NULL;
    proto_tree * to_ni_tn_tree = NULL;
    gint str_start;
    gint max_str_len;

    if (tree)
    {
        ti = proto_tree_add_item(tree,  hf_c15ch_pathfind, tvb, 0, 73, ENC_NA);
        c15ch_pathfind_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_vds30,
                            tvb, 0, 1, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_fromgwenitn, tvb, 1, 8, ENC_BIG_ENDIAN);
        fromgwe_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(fromgwe_ni_tn_tree, hf_c15ch_pathfind_fromgweni,
                            tvb, 1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(fromgwe_ni_tn_tree, hf_c15ch_pathfind_fromgwetn,
                            tvb, 5, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_fromoptimized,
                            tvb, 9, 1, ENC_BIG_ENDIAN);
        /* fromsite */
        str_start = 10;
        max_str_len = 5;
        add_string_field( c15ch_pathfind_tree, tvb, str_start, max_str_len, hf_c15ch_pathfind_fromsite );

        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_frompm,
                            tvb, 15, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_frompc,
                            tvb, 16, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_fromloop,
                            tvb, 17, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_fromslot,
                            tvb, 21, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_fromcnx,
                            tvb, 25, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_fromnitn,
                            tvb, 29, 8, ENC_BIG_ENDIAN);
        from_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub2);
        proto_tree_add_item(from_ni_tn_tree, hf_c15ch_pathfind_fromni,
                            tvb, 29, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(from_ni_tn_tree, hf_c15ch_pathfind_fromtn,
                            tvb, 33, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_togwenitn,
                            tvb, 37, 8, ENC_BIG_ENDIAN);
        togwe_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub3);
        proto_tree_add_item(togwe_ni_tn_tree, hf_c15ch_pathfind_togweni,
                            tvb, 37, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(togwe_ni_tn_tree, hf_c15ch_pathfind_togwetn,
                            tvb, 41, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_tooptimized,
                            tvb, 45, 1, ENC_BIG_ENDIAN);
        /* tosite */
        str_start = 46;
        max_str_len = 5;
        add_string_field( c15ch_pathfind_tree, tvb, str_start, max_str_len, hf_c15ch_pathfind_tosite );

        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_topm,
                            tvb, 51, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_topc,
                            tvb, 52, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_toloop,
                            tvb, 53, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_toslot,
                            tvb, 57, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_tocnx,
                            tvb, 61, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_pathfind_tree, hf_c15ch_pathfind_tonitn,
                            tvb, 65, 8, ENC_BIG_ENDIAN);
        to_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub4);
        proto_tree_add_item(to_ni_tn_tree, hf_c15ch_pathfind_toni,
                            tvb, 65, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(to_ni_tn_tree, hf_c15ch_pathfind_totn,
                            tvb, 69, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_pathidle(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_pathidle_tree = NULL;
    proto_tree * fromgwe_ni_tn_tree = NULL;
    proto_tree * from_ni_tn_tree = NULL;
    proto_tree * togwe_ni_tn_tree = NULL;
    proto_tree * to_ni_tn_tree = NULL;
    gint str_start;
    gint max_str_len;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_pathidle, tvb, 0, 73, ENC_NA);
        c15ch_pathidle_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_vds30,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_idlecode,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_pathtype,
                            tvb, 2, 1, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_fromgwenitn,
                            tvb, 3, 8, ENC_BIG_ENDIAN);
        fromgwe_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(fromgwe_ni_tn_tree, hf_c15ch_pathidle_fromgweni,
                            tvb, 3, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(fromgwe_ni_tn_tree, hf_c15ch_pathidle_fromgwetn,
                            tvb, 7, 4, ENC_BIG_ENDIAN);
        /* fromsite */
        str_start = 11;
        max_str_len = 5;
        add_string_field( c15ch_pathidle_tree, tvb, str_start, max_str_len, hf_c15ch_pathidle_fromsite );

        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_frompm,
                            tvb, 16, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_frompc,
                            tvb, 17, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_fromloop,
                            tvb, 18, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_fromslot,
                            tvb, 22, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_fromcnx,
                            tvb, 26, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_fromnitn,
                            tvb, 30, 8, ENC_BIG_ENDIAN);
        from_ni_tn_tree = proto_item_add_subtree(ti, ett_c15ch_second_level_sub2);
        proto_tree_add_item(from_ni_tn_tree, hf_c15ch_pathidle_fromni,
                            tvb, 30, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(from_ni_tn_tree, hf_c15ch_pathidle_fromtn,
                            tvb, 34, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_togwenitn,
                            tvb, 38, 8, ENC_BIG_ENDIAN);
        togwe_ni_tn_tree = proto_item_add_subtree(ti, ett_c15ch_second_level_sub3);
        proto_tree_add_item(togwe_ni_tn_tree, hf_c15ch_pathidle_togweni,
                            tvb, 38, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(togwe_ni_tn_tree, hf_c15ch_pathidle_togwetn,
                            tvb, 42, 4, ENC_BIG_ENDIAN);
        /* tosite */
        str_start = 46;
        max_str_len = 5;
        add_string_field( c15ch_pathidle_tree, tvb, str_start, max_str_len, hf_c15ch_pathidle_tosite );

        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_topm,
                            tvb, 51, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_topc,
                            tvb, 52, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_toloop,
                            tvb, 53, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_toslot,
                            tvb, 57, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_tocnx,
                            tvb, 61, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_pathidle_tree, hf_c15ch_pathidle_tonitn, tvb, 65, 8, ENC_BIG_ENDIAN);
        to_ni_tn_tree = proto_item_add_subtree(ti, ett_c15ch_second_level_sub4);
        proto_tree_add_item(to_ni_tn_tree, hf_c15ch_pathidle_toni,
                            tvb, 65, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(to_ni_tn_tree, hf_c15ch_pathidle_totn,
                            tvb, 69, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_q931(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_q931_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;
    guint32 q931_msg_len;
    guint8 direction;
    tvbuff_t * next_tvb;
    guint8 bytes_to_skip;

    direction = tvb_get_guint8(tvb, 0);

    if (direction > 1)
    {
        bytes_to_skip = 0; /* signifies invalid direction: q931 dissector will not be called */
    }
    else
        if ( ! direction )
        {
            /* direction == 0 */
            bytes_to_skip = 13;
        }
        else
        {
            /* direction == 1 */
            bytes_to_skip = 10;
        }


    if (tree)
    {

        ti = proto_tree_add_item(tree, hf_c15ch_q931, tvb, 0, 13, ENC_NA);
        c15ch_q931_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_q931_tree, hf_c15ch_q931_direction,
                            tvb, 0, 1, ENC_BIG_ENDIAN);

        q931_msg_len = tvb_get_ntohl(tvb, 9);

        ti = proto_tree_add_item(c15ch_q931_tree, hf_c15ch_q931_ni_tn,
                            tvb, 1, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_q931_ni,
                            tvb, 1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_q931_tn,
                            tvb, 5, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_q931_tree, hf_c15ch_q931_msglength,
                            tvb, 9, 4, ENC_BIG_ENDIAN);
        if (q931_msg_len && bytes_to_skip)
        {
            next_tvb = tvb_new_subset(tvb, 13 + bytes_to_skip, q931_msg_len - bytes_to_skip, q931_msg_len - bytes_to_skip);
            call_dissector(general_q931_handle, next_tvb, pinfo, tree);
        }
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, C15_LABEL);
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: Q931, Direction: %s",
                val_to_str(direction, c15ch_q931_direction_types, "Unknown Direction Subtype: %d")  );

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_qos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_qos_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;

    guint32 year_val = (guint32)0;
    gfloat mos = (gfloat)0.0;

    mos = tvb_get_ntohl(tvb, 72) / (gfloat) (100.0);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", MOS: %.2f", mos );
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_qos, tvb, 0, 100, ENC_NA);
        c15ch_qos_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);

        ti = proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_ni_tn, tvb, 0, 8, ENC_BIG_ENDIAN);

        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_qos_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_qos_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_rtcp_call_id,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_register_type,
                            tvb, 12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_tg_num,
                            tvb, 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_trk_type,
                            tvb, 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_status,
                            tvb, 24, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_codec,
                            tvb, 28, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_given_ip,
                            tvb, 32, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_real_ip,
                            tvb, 36, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_local_ip,
                            tvb, 40, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_tx_pkts,
                            tvb, 44, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_lost_pkts,
                            tvb, 48, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_lost_pct,
                            tvb, 52, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_jitter,
                            tvb, 56, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_rtt,
                            tvb, 60, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_avg_rtt,
                            tvb, 64, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_duration,
                            tvb, 68, 4, ENC_BIG_ENDIAN);
        proto_tree_add_float(c15ch_qos_tree, hf_c15ch_qos_mos,
                            tvb, 72, 4, mos);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_ep_type,
                            tvb, 76, 1, ENC_BIG_ENDIAN);
        add_string_field( c15ch_qos_tree, tvb, 77, 13, hf_c15ch_qos_dn_or_tg );
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_pm,
                            tvb, 90, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_pc,
                            tvb, 91, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_hour,
                            tvb, 92, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_min,
                            tvb, 93, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_sec,
                            tvb, 94, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_tenth_sec,
                            tvb, 95, 1, ENC_BIG_ENDIAN);
        year_val = 2000 + ( (guint32) tvb_get_guint8( tvb, 96 ) ) ;
        proto_tree_add_uint(c15ch_qos_tree, hf_c15ch_qos_year, tvb, 96, 1, year_val);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_month,
                            tvb, 97, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_day,
                            tvb, 98, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_qos_tree, hf_c15ch_qos_day_of_week,
                            tvb, 99, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_route(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_route_tree = NULL;

    guint32 route_num_val = 0;

    route_num_val = tvb_get_ntohl(tvb, 0);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Route Number: %d",
        route_num_val );
    if (tree)
    {
        ti = proto_tree_add_item(tree,hf_c15ch_route, tvb, 0, 17, ENC_NA);
        c15ch_route_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_route_tree, hf_c15ch_route_number,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_route_tree, hf_c15ch_route_type,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_route_tree, hf_c15ch_route_subpm,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_route_tree, hf_c15ch_route_trkpm,
                            tvb, 12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_route_tree, hf_c15ch_route_strtaindo,
                            tvb, 16, 1, ENC_BIG_ENDIAN);
        if ( tvb_reported_length(tvb) >= 25 )
        {
            proto_tree_add_item(c15ch_route_tree, hf_c15ch_route_cr_rte_adv,
                            tvb, 17, 4, ENC_BIG_ENDIAN);
            proto_tree_add_item(c15ch_route_tree, hf_c15ch_route_cause,
                            tvb, 21, 4, ENC_BIG_ENDIAN);
        }
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_sccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    proto_item * ti = NULL;
    proto_tree * c15ch_sccp_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;
    guint8 direction;
    tvbuff_t * next_tvb;

    direction = tvb_get_guint8(tvb, 0);
    if (tree)
    {

        ti = proto_tree_add_item(tree, hf_c15ch_sccp, tvb, 0, 302, ENC_NA);
        c15ch_sccp_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_direction,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_msgtype,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_hopcount,
                            tvb, 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_transactionnum,
                            tvb, 3, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_opcmember,
                            tvb, 7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_opccluster,
                            tvb, 8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_opcnetwork,
                            tvb, 9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_dpcmember,
                            tvb, 10, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_dpccluster,
                            tvb, 11, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_dpcnetwork,
                            tvb, 12, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_level3index,
                            tvb, 13, 1, ENC_BIG_ENDIAN);
        /* NI/TN */
        ti = proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_ni_tn, tvb, 14, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_sccp_ni,
                            tvb, 14, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_sccp_tn,
                            tvb, 18, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_sls,
                            tvb, 22, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_sccp_tree, hf_c15ch_sccp_iptime,
                            tvb, 298, 4, ENC_BIG_ENDIAN);

        /* skip bytes to get to SCCP message type */
        next_tvb = tvb_new_subset(tvb, 23 + 2,
                                    275 - 2, 275 - 2);

        /* sccp dissector call */
        call_dissector(general_sccp_handle, next_tvb, pinfo, tree);
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, C15_LABEL);
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: SCCP, Direction: %s",
                val_to_str(direction, c15ch_sccp_direction_types, "Unknown Direction Subtype: %d")  );
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_srcedest(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_srcedest_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_srcedest, tvb, 0, 3, ENC_NA);
        c15ch_srcedest_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_srcedest_tree, hf_c15ch_srcedest_conntype,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_srcedest_tree, hf_c15ch_srcedest_pathtype,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_srcedest_tree, hf_c15ch_srcedest_pathdirect,
                            tvb, 2, 1, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tcap_tree = NULL;

    guint8 local_ssn_val = 0;

    local_ssn_val = tvb_get_guint8(tvb, 4);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Local SSN: %s",
        val_to_str(local_ssn_val, c15ch_tcap_local_ssn_types, "Unknown %d") );
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_tcap, tvb, 0, 20, ENC_NA);
        c15ch_tcap_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_direction,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_action,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_package_type,
                            tvb, 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_ssn,
                            tvb, 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_local_ssn,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_result_err_code,
                            tvb, 5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_return_reason,
                            tvb, 6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_feat_id,
                            tvb, 7, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_feat_req,
                            tvb, 8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_cl_comp_result,
                            tvb, 9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_release_bit,
                            tvb, 10, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_term_cl_request,
                            tvb, 11, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_opc_index,
                            tvb, 12, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_dpc_mem,
                            tvb, 13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_dpc_clus,
                            tvb, 14, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_dpc_net,
                            tvb, 15, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tcap_tree, hf_c15ch_tcap_cp_id,
                            tvb, 16, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_twc_rswch(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_twc_rswch_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_twc_rswch, tvb, 0, 28, ENC_NA);
        c15ch_twc_rswch_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_twc_rswch_tree, hf_c15ch_twc_rswch_pm,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_twc_rswch_tree, hf_c15ch_twc_rswch_subpm,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_twc_rswch_tree, hf_c15ch_twc_rswch_trkpm,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_twc_rswch_tree, hf_c15ch_twc_rswch_devid,
                            tvb, 12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_twc_rswch_tree, hf_c15ch_twc_rswch_event,
                            tvb, 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_twc_rswch_tree, hf_c15ch_twc_rswch_parm,
                            tvb, 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_twc_rswch_tree, hf_c15ch_twc_rswch_iptime,
                            tvb, 24, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_cp_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_cp_event_tree = NULL;

    guint32 pm_value = 0;
    guint32 event_value = 0;
    guint32 parm_value = 0;
    guint32 subpm_value = 0;
    guint32 trkpm_value = 0;
    if (tvb_reported_length(tvb) < 28)
    {
        return 0;
    }
    pm_value = tvb_get_ntohl(tvb, 0);
    subpm_value = tvb_get_ntohl(tvb, 4);
    trkpm_value = tvb_get_ntohl(tvb, 8);
    event_value = tvb_get_ntohl(tvb, 16);
    parm_value = tvb_get_ntohl(tvb, 20);
    col_clear(pinfo->cinfo, COL_INFO);

    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: CP_EVENT, PM Type: %s",
        val_to_str_ext(pm_value, &c15_pm_types_ext, "Unknown %d") );

    if ( ( pm_value <= MAX_PM_VAL ) && ( pm_value != DIG_CKT_TEST_PM_VALUE ) )
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Sub PM: %s",
                val_to_str(subpm_value, subpm_name_tables[ pm_value ], "%d") );
    }
    else
    {
        if ( pm_value == DIG_CKT_TEST_PM_VALUE )
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Trk PM: %s",
                    val_to_str(trkpm_value, trkpm_dig_ckt_test_types, "%d") );
            if ( trkpm_value > MAX_DIG_CKT_TEST_TRKPM_VAL  )
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Sub PM: %d", subpm_value);
            }
            else
            {
                col_append_fstr(pinfo->cinfo, COL_INFO, ", Sub PM: %s",
                    val_to_str(subpm_value, dig_ckt_test_subpm_name_tables[ trkpm_value ], "%d") );
            }
        }
        else    /* (pm_value < MIN_PM_VAL) || (pm_value > MAX_PM_VAL) */
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Sub PM: %d", subpm_value);
        }
    }

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Event Type: %s, Parm: %d",
        val_to_str_ext(event_value, &c15_event_types_ext, "Unknown %d"), parm_value );


    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_cp_event, tvb, 0, 28, ENC_NA);

        proto_item_append_text(ti, ", PM Type: %s",
            val_to_str_ext(pm_value, &c15_pm_types_ext, "Unknown"));
        proto_item_append_text(ti, ", Event Type: %s",
            val_to_str_ext(event_value, &c15_event_types_ext, "Unknown"));
        c15ch_cp_event_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);

        proto_tree_add_item(c15ch_cp_event_tree, hf_c15ch_cp_event_pm,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        if ( pm_value > MAX_PM_VAL )
        {
            /* Unknown Type */
            proto_tree_add_item(c15ch_cp_event_tree, hf_c15ch_cp_event_subpm,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        }
        else
        {
            /* pm_value is within expected range */
            if ( pm_value != DIG_CKT_TEST_PM_VALUE )
            {
                /*a normal pm type */
                proto_tree_add_item(c15ch_cp_event_tree, *(subpm_table[ pm_value ] ),
                            tvb, 4, 4, ENC_BIG_ENDIAN);
            }
            else
            {
                /* special case for labeling subpm values of dig_ckt pm type */
                if ( trkpm_value > MAX_DIG_CKT_TEST_TRKPM_VAL )
                {
                    /* this is a dig_ckt pm type, but the trkpm value is out of range */
                    /* use the default dig_ckt subpm field from the subpm_table */
                    proto_tree_add_item(c15ch_cp_event_tree, *(subpm_table[ pm_value ] ),
                            tvb, 4, 4, ENC_BIG_ENDIAN);
                }
                else
                {
                    /* dig_ckt pm type, with the trkpm value in the expected range */
                    proto_tree_add_item(c15ch_cp_event_tree, *(dig_ckt_test_subpm_table[ trkpm_value ] ),
                            tvb, 4, 4, ENC_BIG_ENDIAN);
                }
            }
        }

        if (pm_value !=  DIG_CKT_TEST_PM_VALUE)
        {
            proto_tree_add_item(c15ch_cp_event_tree, hf_c15ch_cp_event_trkpm,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        }
        else
        {
            proto_tree_add_item(c15ch_cp_event_tree, hf_c15ch_cp_event_dig_ckt_test_trkpm,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(c15ch_cp_event_tree, hf_c15ch_cp_event_devid,
                            tvb, 12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_event_tree, hf_c15ch_cp_event_event,
                            tvb, 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_event_tree, hf_c15ch_cp_event_parm,
                            tvb, 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_cp_event_tree, hf_c15ch_cp_event_iptime,
                            tvb, 24, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

/* second level dissection code : called after header is dissected */
static int dissect_c15ch_inc_gwe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;

    int retv = 0;
    guint8 task_num;
    guint8 type_num;
    guint8 fiat_num;
    tvbuff_t * next_tvb;
    gboolean task_in_range = TRUE;
    gboolean fiat_index_in_range = TRUE;

    task_num = tvb_get_guint8(tvb,  8);
    fiat_num = tvb_get_guint8(tvb,  9);
    type_num = tvb_get_guint8(tvb, 10);

    if ( task_num > LAST_TASK_TYPE_INDEX )
    {    /* this happens for unknown task types */
        task_in_range  = FALSE;
        fiat_index_in_range = FALSE; /* don't guess what the correct fiat table should be for unknown task */
    }

    if ( task_in_range )
    {
        if ( ( task_num < FIRST_FIAT_NAME_TABLE_INDEX ) || (task_num > LAST_FIAT_NAME_TABLE_INDEX ) )
        {
            fiat_index_in_range = FALSE; /* this happens for INVALID_TASK_TYPE_VAL */
        }
    }

    col_clear(pinfo->cinfo, COL_INFO);


    if (fiat_index_in_range)
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Type: INC_GWE, Task: %s, Fiat: %s",
                val_to_str( task_num, c15inc_gwe_task_types, "Unknown Task Type: %d" ),
                val_to_str( fiat_num, fiat_name_tables[ task_num ], "Unknown Fiat Type: %d") );
    }
    else /* either (task_num == INVALID_TASK_TYPE_VAL) or we have an unknown task */
    {
            col_add_fstr(pinfo->cinfo, COL_INFO, "Type: INC_GWE, Task: %s",
                val_to_str( task_num, c15inc_gwe_task_types, "Unknown Task Type: %d" ));
    }

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe, tvb, 0, 11, ENC_NA);
        /* note that defined INVALID_TASK_TYPE will be labeled as such, but task types that are out
        of range will be labeled as an Unknown Task Type */
        proto_item_append_text(ti, ", Task: %s",
                val_to_str( task_num, c15inc_gwe_task_types, "Unknown Task Type: %d" ) );


        if ( fiat_index_in_range) /* we can find a fiat name table: not defined Invalid task type and not unknown task */
        {
            proto_item_append_text( ti, ", Fiat: %s",
                val_to_str( fiat_num, fiat_name_tables[ task_num ], "Unknown Fiat Type: %d" ) );
        }
        c15ch_inc_gwe_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);

        ti = proto_tree_add_item(c15ch_inc_gwe_tree, hf_c15ch_inc_gwe_ni_tn,
                            tvb, 0, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);

        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_inc_gwe_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_inc_gwe_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_inc_gwe_tree, hf_c15ch_inc_gwe_taskid,
                            tvb, 8, 1, ENC_BIG_ENDIAN);
        if (task_in_range) /* can be of any defined task type including INVALID */
        {
            proto_tree_add_item(c15ch_inc_gwe_tree, *(fiatid_table[ task_num ] ),
                            tvb, 9, 1, ENC_BIG_ENDIAN);
        }
        proto_tree_add_item(c15ch_inc_gwe_tree, hf_c15ch_inc_gwe_datatype,
                            tvb, 10, 1, ENC_BIG_ENDIAN);
    }
    next_tvb = tvb_new_subset(tvb, 11, -1, -1);
    /*third level dissection*/
    retv = 11 + dissector_try_uint(c15ch_inc_gwe_dissector_table, type_num, next_tvb, pinfo, tree);
    return retv;
}

/* Third level dissection code : called after basic inc gwe header info is dissected */

static int dissect_c15ch_inc_gwe_admn_dn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_admn_dn_tree = NULL;

    guint8 num_digits;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_admn_dn, tvb, 0, 37, ENC_NA);
        c15ch_inc_gwe_admn_dn_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        num_digits = tvb_get_guint8(tvb, 4);
        proto_tree_add_item(c15ch_inc_gwe_admn_dn_tree, hf_c15ch_inc_gwe_admn_dn_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_inc_gwe_admn_dn_ip_gwe_digits, tvb, c15ch_inc_gwe_admn_dn_tree,
            5, num_digits, 32, 1);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_admn_updt(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_admn_updt_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_admn_updt, tvb, 0, 20, ENC_NA);
        c15ch_inc_gwe_admn_updt_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);

        ti = proto_tree_add_item(c15ch_inc_gwe_admn_updt_tree, hf_c15ch_inc_gwe_admn_updt_ip_gwe_med_ni_tn,
                            tvb, 0, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_third_level_inc_gwe_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_inc_gwe_admn_updt_ip_gwe_med_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_inc_gwe_admn_updt_ip_gwe_med_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_admn_updt_tree, hf_c15ch_inc_gwe_admn_updt_ip_ns_iface,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_admn_updt_tree, hf_c15ch_inc_gwe_admn_updt_ip_ns_terminal,
                            tvb, 12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_admn_updt_tree, hf_c15ch_inc_gwe_admn_updt_ip_gwe_new_rec_addr,
                            tvb, 16, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_bc_pgi(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_bc_pgi_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_bc_pgi, tvb, 0, 19, ENC_NA);
        c15ch_inc_gwe_bc_pgi_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_bc_pgi_tree, hf_c15ch_inc_gwe_bc_pgi_pbc_conn_num,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_bc_pgi_tree, hf_c15ch_inc_gwe_bc_pgi_pbc_conn_type,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_bc_pgi_tree, hf_c15ch_inc_gwe_bc_pgi_pbc_msg_type,
                            tvb, 5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_bc_pgi_tree, hf_c15ch_inc_gwe_bc_pgi_bc_mode,
                            tvb, 6, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_bc_pgi_tree, hf_c15ch_inc_gwe_bc_pgi_bc_pgi_sdp,
                            tvb, 7, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_bc_pgi_tree, hf_c15ch_inc_gwe_bc_pgi_bc_pgi_m_port,
                            tvb, 11, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_bc_pgi_tree, hf_c15ch_inc_gwe_bc_pgi_pbc_tst_flags,
                            tvb, 15, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_chg_hndl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_chg_hndl_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_chg_hndl, tvb, 0, 8, ENC_NA);
        c15ch_inc_gwe_chg_hndl_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_chg_hndl_tree, hf_c15ch_inc_gwe_chg_hndl_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_chg_hndl_tree, hf_c15ch_inc_gwe_chg_hndl_ip_gwe_new_hndl,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_cl_ans(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_cl_ans_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_cl_ans, tvb, 0, 14, ENC_NA);
        c15ch_inc_gwe_cl_ans_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_cl_ans_tree, hf_c15ch_inc_gwe_cl_ans_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_ans_tree, hf_c15ch_inc_gwe_cl_ans_ip_gwe_conn_num,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_ans_tree, hf_c15ch_inc_gwe_cl_ans_ip_cl_ans_lsdp,
                            tvb, 5, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_ans_tree, hf_c15ch_inc_gwe_cl_ans_ip_cl_ans_m_port,
                            tvb, 9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_ans_tree, hf_c15ch_inc_gwe_cl_ans_encap_isup,
                            tvb, 13, 1, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_cl_prog(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_cl_prog_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_cl_prog, tvb, 0, 15, ENC_NA);
        c15ch_inc_gwe_cl_prog_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_cl_prog_tree, hf_c15ch_inc_gwe_cl_prog_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_prog_tree, hf_c15ch_inc_gwe_cl_prog_ip_gwe_conn_num,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_prog_tree, hf_c15ch_inc_gwe_cl_prog_ip_cl_prog_lsdp,
                            tvb, 5, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_prog_tree, hf_c15ch_inc_gwe_cl_prog_ip_cl_prog_m_port,
                            tvb, 9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_prog_tree, hf_c15ch_inc_gwe_cl_prog_ip_gwe_stat_code,
                            tvb, 13, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_prog_tree, hf_c15ch_inc_gwe_cl_prog_encap_isup,
                            tvb, 14, 1, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_cl_redir(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_cl_redir_tree = NULL;


    guint8 redir_num_digits;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_cl_redir, tvb, 0, 24, ENC_NA);
        c15ch_inc_gwe_cl_redir_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        redir_num_digits = tvb_get_guint8(tvb, 8);
        proto_tree_add_item(c15ch_inc_gwe_cl_redir_tree, hf_c15ch_inc_gwe_cl_redir_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_redir_tree, hf_c15ch_inc_gwe_cl_redir_ip_gwe_conn_num,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_inc_gwe_cl_redir_ip_gwe_redir_digits, tvb,c15ch_inc_gwe_cl_redir_tree,
            9, redir_num_digits, 15, 1);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_cl_refer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_cl_refer_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;

    guint8 trgt_num_digits;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_cl_refer, tvb, 0, 49, ENC_NA);
        c15ch_inc_gwe_cl_refer_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        trgt_num_digits = tvb_get_guint8(tvb, 8);
        proto_tree_add_item(c15ch_inc_gwe_cl_refer_tree, hf_c15ch_inc_gwe_cl_refer_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_refer_tree, hf_c15ch_inc_gwe_cl_refer_ip_gwe_conn_num,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_digits, tvb, c15ch_inc_gwe_cl_refer_tree,
            9, trgt_num_digits, 32, 1);
        ti = proto_tree_add_item(c15ch_inc_gwe_cl_refer_tree, hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_ni_tn,
                            tvb, 41, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_third_level_inc_gwe_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_ni,
                            tvb, 41, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_tn,
                            tvb, 45, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_cl_rel(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_cl_rel_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_cl_rel, tvb, 0, 7, ENC_NA);
        c15ch_inc_gwe_cl_rel_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_cl_rel_tree, hf_c15ch_inc_gwe_cl_rel_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_rel_tree, hf_c15ch_inc_gwe_cl_rel_ip_gwe_conn_num,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_rel_tree, hf_c15ch_inc_gwe_cl_rel_ip_gwe_stat_code,
                            tvb, 5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_rel_tree, hf_c15ch_inc_gwe_cl_rel_encap_isup,
                            tvb, 6, 1, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_cl_setup(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_cl_setup_tree = NULL;


    guint8 num_digits;

    num_digits = tvb_get_guint8(tvb, 4);

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_cl_setup, tvb, 0, 45, ENC_NA);
        c15ch_inc_gwe_cl_setup_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_cl_setup_tree, hf_c15ch_inc_gwe_cl_setup_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_inc_gwe_cl_setup_ip_gwe_cled_digits,tvb,c15ch_inc_gwe_cl_setup_tree,
            5, num_digits, 32, 1);
        proto_tree_add_item(c15ch_inc_gwe_cl_setup_tree, hf_c15ch_inc_gwe_cl_setup_ip_cl_setup_lsdp,
                            tvb, 37, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_cl_setup_tree, hf_c15ch_inc_gwe_cl_setup_ip_cl_setup_m_port,
                            tvb, 41, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_h248_digit(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_h248_digit_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_h248_digit, tvb, 0, 2, ENC_NA);
        c15ch_inc_gwe_h248_digit_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_h248_digit_tree, hf_c15ch_inc_gwe_h248_digit_ip_gwe_digit,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_h248_digit_tree, hf_c15ch_inc_gwe_h248_digit_ip_gwe_digit_method,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_info_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_info, tvb, 0, 10, ENC_NA);
        c15ch_inc_gwe_info_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_info_tree, hf_c15ch_inc_gwe_info_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_info_tree, hf_c15ch_inc_gwe_info_ip_gwe_info_type,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_info_tree, hf_c15ch_inc_gwe_info_ip_gwe_info_digit,
                            tvb, 5, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_info_tree, hf_c15ch_inc_gwe_info_encap_isup_msg_type,
                            tvb, 9, 1, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_inv_repl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_inv_repl_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_inv_repl, tvb, 0, 16, ENC_NA);
        c15ch_inc_gwe_inv_repl_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_inv_repl_tree, hf_c15ch_inc_gwe_inv_repl_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_inv_repl_tree, hf_c15ch_inc_gwe_inv_repl_ip_gwe_conn_num,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_inv_repl_tree, hf_c15ch_inc_gwe_inv_repl_ip_inv_repl_rsdp_ip,
                            tvb, 8, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_inv_repl_tree, hf_c15ch_inc_gwe_inv_repl_ip_inv_repl_rsdp_port,
                            tvb, 12, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_mgcp_dlcx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_mgcp_dlcx_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_mgcp_dlcx, tvb, 0, 4, ENC_NA);
        c15ch_inc_gwe_mgcp_dlcx_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_mgcp_dlcx_tree, hf_c15ch_inc_gwe_mgcp_dlcx_err_code,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_notify(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_notify_tree = NULL;


    guint8 num_digits;

    num_digits = tvb_get_guint8(tvb, 4);

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_notify, tvb, 0, 37, ENC_NA);
        c15ch_inc_gwe_notify_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_notify_tree, hf_c15ch_inc_gwe_notify_ip_gwe_mwi_stat,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_inc_gwe_notify_ip_gwe_digits,tvb,c15ch_inc_gwe_notify_tree,
            5, num_digits, 32, 1);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_ntwk_mod(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_ntwk_mod_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_ntwk_mod, tvb, 0, 22, ENC_NA);
        c15ch_inc_gwe_ntwk_mod_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_ntwk_mod_tree, hf_c15ch_inc_gwe_ntwk_mod_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ntwk_mod_tree, hf_c15ch_inc_gwe_ntwk_mod_ip_gwe_conn_num,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ntwk_mod_tree, hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_lsdp,
                            tvb, 5, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ntwk_mod_tree, hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_l_m_port,
                            tvb, 9, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ntwk_mod_tree, hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_rsdp,
                            tvb, 13, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ntwk_mod_tree, hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_r_m_port,
                            tvb, 17, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ntwk_mod_tree, hf_c15ch_inc_gwe_ntwk_mod_ip_gwe_stat_code,
                            tvb, 21, 1, ENC_BIG_ENDIAN);

    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_ptrk_setup(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_ptrk_setup_tree = NULL;


    guint8 cled_num_digits, clng_num_digits, redir_num_digits, ocn_num_digits, chrg_num_digits,
        rn_num_digits, cic_num_digits;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_ptrk_setup, tvb, 0, 172, ENC_NA);
        c15ch_inc_gwe_ptrk_setup_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        /* CLED */
        cled_num_digits = tvb_get_guint8(tvb, 4);

        /* CLNG */
        clng_num_digits = tvb_get_guint8(tvb, 46);

        /* REDIR */
        redir_num_digits = tvb_get_guint8(tvb, 85);

        /* OCN */
        ocn_num_digits = tvb_get_guint8(tvb, 103);

        /* CHRG */
        chrg_num_digits = tvb_get_guint8(tvb, 119);

        /* RN */
        rn_num_digits = tvb_get_guint8(tvb, 133);

        /* CIC */
        cic_num_digits = tvb_get_guint8(tvb, 166);

        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_cled_digits,tvb,c15ch_inc_gwe_ptrk_setup_tree,
            5,cled_num_digits, 32, 1);
        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_cl_setup_lsdp,
                            tvb, 37, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_cl_setup_m_port,
                            tvb, 41, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clid_pri,
                            tvb, 45, 1, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clng_digits,tvb,c15ch_inc_gwe_ptrk_setup_tree,
            47,clng_num_digits, 32, 1);
        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clng_ton,
                            tvb, 79, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clng_np,
                            tvb, 80, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_alert_info,
                            tvb, 81, 4, ENC_BIG_ENDIAN);

        add_digits_string(hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_redir_digits,tvb,c15ch_inc_gwe_ptrk_setup_tree,
            86,redir_num_digits, 15, 1);
        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_redir_ton,
                            tvb, 101, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_redir_np,
                            tvb, 102, 1, ENC_BIG_ENDIAN);

        add_digits_string(hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_ocn_digits,tvb,c15ch_inc_gwe_ptrk_setup_tree,
            104,ocn_num_digits, 15, 1);

        add_digits_string(hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_chrg_digits,tvb,c15ch_inc_gwe_ptrk_setup_tree,
            120,chrg_num_digits, 10, 1);
        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_chrg_noa,
                            tvb, 130, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_chrg_npi,
                            tvb, 131, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_npdi,
                            tvb, 132, 1, ENC_BIG_ENDIAN);

        add_digits_string(hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_rn_digits,tvb,c15ch_inc_gwe_ptrk_setup_tree,
            134,rn_num_digits, 32, 1);

        add_digits_string(hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_cic_digits,tvb,c15ch_inc_gwe_ptrk_setup_tree,
            167,cic_num_digits, 4, 1);

        proto_tree_add_item(c15ch_inc_gwe_ptrk_setup_tree, hf_c15ch_inc_gwe_ptrk_setup_encap_isup,
                            tvb, 171, 1, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_reply_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree,  hf_c15ch_inc_gwe_reply, tvb, 0, 28, ENC_NA);
        c15ch_inc_gwe_reply_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_reply_tree, hf_c15ch_inc_gwe_reply_ip_gwe_msg_type,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_reply_tree, hf_c15ch_inc_gwe_reply_ip_gwe_stat_code,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_reply_tree, hf_c15ch_inc_gwe_reply_ip_gwe_conn_num,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_reply_tree, hf_c15ch_inc_gwe_reply_nw_mdcn_lsdp_ip,
                            tvb, 12, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_reply_tree, hf_c15ch_inc_gwe_reply_nw_mdcn_lsdp_port,
                            tvb, 16, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_reply_tree, hf_c15ch_inc_gwe_reply_nw_mdcn_rsdp_ip,
                            tvb, 20, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_reply_tree, hf_c15ch_inc_gwe_reply_nw_mdcn_rsdp_port,
                            tvb, 24, 4, ENC_BIG_ENDIAN);

    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_rv_avail(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_rv_avail_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_rv_avail, tvb, 0, 12, ENC_NA);
        c15ch_inc_gwe_rv_avail_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_rv_avail_tree, hf_c15ch_inc_gwe_rv_avail_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_rv_avail_tree, hf_c15ch_inc_gwe_rv_avail_ip_gwe_conn_num,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_rv_avail_tree, hf_c15ch_inc_gwe_rv_avail_ip_gwe_info_len,
                            tvb, 8, 4, ENC_BIG_ENDIAN);

    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_sua_reply(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_sua_reply_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_sua_reply, tvb, 0, 32, ENC_NA);
        c15ch_inc_gwe_sua_reply_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_sua_reply_tree, hf_c15ch_inc_gwe_sua_reply_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_sua_reply_tree, hf_c15ch_inc_gwe_sua_reply_ip_gwe_msg_type,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_sua_reply_tree, hf_c15ch_inc_gwe_sua_reply_ip_gwe_stat_code,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_sua_reply_tree, hf_c15ch_inc_gwe_sua_reply_ip_gwe_conn_num,
                            tvb, 12, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_sua_reply_tree, hf_c15ch_inc_gwe_sua_reply_nw_mdcn_lsdp_ip,
                            tvb, 16, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_sua_reply_tree, hf_c15ch_inc_gwe_sua_reply_nw_mdcn_lsdp_port,
                            tvb, 20, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_sua_reply_tree, hf_c15ch_inc_gwe_sua_reply_nw_mdcn_rsdp_ip,
                            tvb, 24, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_sua_reply_tree, hf_c15ch_inc_gwe_sua_reply_nw_mdcn_rsdp_port,
                            tvb, 28, 4, ENC_BIG_ENDIAN);

    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_subs_chg_hndl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_subs_chg_hndl_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_subs_chg_hndl, tvb, 0, 16, ENC_NA);
        c15ch_inc_gwe_subs_chg_hndl_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_subs_chg_hndl_tree, hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_subs_chg_hndl_tree, hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_new_hndl,
                            tvb, 4, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_inc_gwe_subs_chg_hndl_tree, hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_med_ni_tn,
                            tvb, 8, 16, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_third_level_inc_gwe_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_med_ni,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_med_tn,
                            tvb, 12, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_sua_hndl(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_sua_hndl_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_sua_hndl, tvb, 0, 4, ENC_NA);
        c15ch_inc_gwe_sua_hndl_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_sua_hndl_tree, hf_c15ch_inc_gwe_sua_hndl_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


static int dissect_c15ch_inc_gwe_tgh_stat(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_tgh_stat_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_tgh_stat, tvb, 0, 5, ENC_NA);
        c15ch_inc_gwe_tgh_stat_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_tgh_stat_tree, hf_c15ch_inc_gwe_tgh_stat_ip_gwe_sua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_inc_gwe_tgh_stat_tree, hf_c15ch_inc_gwe_tgh_stat_ip_gwe_tgh_state,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_inc_gwe_voip_cot(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_inc_gwe_voip_cot_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_inc_gwe_voip_cot, tvb, 0, 1, ENC_NA);
        c15ch_inc_gwe_voip_cot_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_inc_gwe);
        proto_tree_add_item(c15ch_inc_gwe_voip_cot_tree, hf_c15ch_inc_gwe_voip_cot_ip_gwe_pass_code,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}


/* second level dissection */
static int dissect_c15ch_out_gwe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;

    guint8 data_type;
    guint8 msg_type;
    tvbuff_t * next_tvb;

    msg_type = tvb_get_guint8(tvb, 8);
    data_type = tvb_get_guint8(tvb, 14);
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: OUT_GWE, Msg Subtype: %s",
        val_to_str_ext(msg_type, &c15_out_gwe_msg_types_ext, "Unknown Msg Subtype: %d") );
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe, tvb, 0, 15, ENC_NA);
        proto_item_append_text(ti, ", Msg Subtype: %s",
            val_to_str_ext(msg_type, &c15_out_gwe_msg_types_ext, "Unknown Msg Subtype: %d"));
        c15ch_out_gwe_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);

        ti = proto_tree_add_item(c15ch_out_gwe_tree, hf_c15ch_out_gwe_ni_tn,
                            tvb, 0, 8, ENC_BIG_ENDIAN);

        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_second_level_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_out_gwe_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_out_gwe_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);


        proto_tree_add_item(c15ch_out_gwe_tree, hf_c15ch_out_gwe_op_gwe_msg_type,
                            tvb, 8, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_tree, hf_c15ch_out_gwe_op_gwe_protocol,
                            tvb, 9, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_tree, hf_c15ch_out_gwe_op_sua_hndl,
                            tvb, 10, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_tree, hf_c15ch_out_gwe_gwe_data_type,
                            tvb, 14, 1, ENC_BIG_ENDIAN);
    }
    next_tvb = tvb_new_subset(tvb, 15, -1, -1);

    dissector_try_uint(c15ch_out_gwe_dissector_table, data_type, next_tvb, pinfo, tree);
    return tvb_reported_length(tvb);
}


/* third level dissection */
static int dissect_c15ch_out_gwe_audit_conn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_audit_conn_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_audit_conn, tvb, 0, 12, ENC_NA);
        c15ch_out_gwe_audit_conn_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        ti = proto_tree_add_item(c15ch_out_gwe_audit_conn_tree, hf_c15ch_out_gwe_audit_conn_ni_tn,
                            tvb, 0, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_third_level_out_gwe);

        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_out_gwe_audit_conn_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_out_gwe_audit_conn_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_audit_conn_tree, hf_c15ch_out_gwe_audit_conn_context,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_blf_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_blf_data_tree = NULL;
    proto_tree * sub_med_ni_tn_tree = NULL;
    proto_tree * sub_rb_ni_tn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_blf_data, tvb, 0, 21, ENC_NA);
        c15ch_out_gwe_blf_data_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_blf_data_tree, hf_c15ch_out_gwe_blf_data_rb_ua_handle,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_blf_data_tree, hf_c15ch_out_gwe_blf_data_rb_type,
                            tvb, 4, 1, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_out_gwe_blf_data_tree, hf_c15ch_out_gwe_blf_data_med_ni_tn,
                            tvb, 5, 8, ENC_BIG_ENDIAN);
        sub_med_ni_tn_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe_sub1);
        proto_tree_add_item(sub_med_ni_tn_tree, hf_c15ch_out_gwe_blf_data_med_ni,
                            tvb, 5, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_med_ni_tn_tree, hf_c15ch_out_gwe_blf_data_med_tn,
                            tvb, 9, 4, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_out_gwe_blf_data_tree, hf_c15ch_out_gwe_blf_data_rb_ni_tn,
                            tvb, 13, 8, ENC_BIG_ENDIAN);
        sub_rb_ni_tn_tree = proto_item_add_subtree(ti,  ett_c15ch_third_level_out_gwe_sub2);
        proto_tree_add_item(sub_rb_ni_tn_tree, hf_c15ch_out_gwe_blf_data_rb_ni,
                            tvb, 13, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_rb_ni_tn_tree, hf_c15ch_out_gwe_blf_data_rb_tn,
                            tvb, 17, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_call_ans(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_call_ans_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_call_ans, tvb, 0, 13, ENC_NA);
        c15ch_out_gwe_call_ans_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_call_ans_tree, hf_c15ch_out_gwe_call_ans_conn_num,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_ans_tree, hf_c15ch_out_gwe_call_ans_op_cl_ans_rsdp_ip,
                            tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_ans_tree, hf_c15ch_out_gwe_call_ans_op_cl_ans_rsdp_port,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_ans_tree, hf_c15ch_out_gwe_call_ans_encap_isup,
                            tvb, 12, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_call_notify(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_call_notify_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_call_notify, tvb, 0, 8, ENC_NA);
        c15ch_out_gwe_call_notify_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_call_notify_tree, hf_c15ch_out_gwe_call_notify_op_gwe_mwi,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_notify_tree, hf_c15ch_out_gwe_call_notify_status_code,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_call_prog(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_call_prog_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_call_prog, tvb, 0, 9, ENC_NA);
        c15ch_out_gwe_call_prog_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_call_prog_tree, hf_c15ch_out_gwe_call_prog_conn_num,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_prog_tree, hf_c15ch_out_gwe_call_prog_op_gwe_stat_code,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_prog_tree, hf_c15ch_out_gwe_call_prog_encap_isup,
                            tvb, 8, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_call_rel(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_call_rel_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_call_rel, tvb, 0, 5, ENC_NA);
        c15ch_out_gwe_call_rel_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_call_rel_tree, hf_c15ch_out_gwe_call_rel_status_code,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_rel_tree, hf_c15ch_out_gwe_call_rel_encap_isup,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_call_setup(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_call_setup_tree = NULL;

    guint8 redir_num_digits;
    guint8 ocn_num_digits;
    guint8 chrg_num_digits;

    if (tree)
    {
        ti = proto_tree_add_item(tree,  hf_c15ch_out_gwe_call_setup, tvb, 0, 60, ENC_NA);
        c15ch_out_gwe_call_setup_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        /* redir */
        redir_num_digits = tvb_get_guint8(tvb, 12);

        /* ocn  */
        ocn_num_digits = tvb_get_guint8(tvb, 30);

        /* chrg  */
        chrg_num_digits = tvb_get_guint8(tvb, 46);

        proto_tree_add_item(c15ch_out_gwe_call_setup_tree, hf_c15ch_out_gwe_call_setup_conn_num,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_setup_tree, hf_c15ch_out_gwe_call_setup_op_cl_ans_rsdp_ip,
                            tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_setup_tree, hf_c15ch_out_gwe_call_setup_op_cl_ans_rsdp_port,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_out_gwe_call_setup_op_gwe_redir_digits, tvb, c15ch_out_gwe_call_setup_tree,
            13, redir_num_digits, 15, 1);
        proto_tree_add_item(c15ch_out_gwe_call_setup_tree, hf_c15ch_out_gwe_call_setup_op_gwe_rdir_ton,
                            tvb, 28, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_setup_tree, hf_c15ch_out_gwe_call_setup_op_gwe_rdir_np,
                            tvb, 29, 1, ENC_BIG_ENDIAN);
        add_digits_string(hf_c15ch_out_gwe_call_setup_op_gwe_ocn_digits, tvb, c15ch_out_gwe_call_setup_tree,
            31, ocn_num_digits, 15, 1);
        add_digits_string(hf_c15ch_out_gwe_call_setup_op_gwe_chrg_digits, tvb, c15ch_out_gwe_call_setup_tree,
            47, chrg_num_digits, 10, 1);
        proto_tree_add_item(c15ch_out_gwe_call_setup_tree, hf_c15ch_out_gwe_call_setup_op_gwe_chrg_noa,
                            tvb, 57, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_setup_tree, hf_c15ch_out_gwe_call_setup_op_gwe_chrg_npi,
                            tvb, 58, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_call_setup_tree, hf_c15ch_out_gwe_call_setup_encap_isup,
                            tvb, 59, 1, ENC_BIG_ENDIAN);
    }
    return tvb_reported_length(tvb);
}

static int dissect_c15ch_out_gwe_conn_num(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_conn_num_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_conn_num, tvb, 0, 4, ENC_NA);
        c15ch_out_gwe_conn_num_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_conn_num_tree, hf_c15ch_out_gwe_conn_num_out_gwe_conn_num,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_out_gwe_del_subs_ua(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_del_subs_ua_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_del_subs_ua, tvb, 0, 4, ENC_NA);
        c15ch_out_gwe_del_subs_ua_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_del_subs_ua_tree, hf_c15ch_out_gwe_del_subs_ua_op_sip_ua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_digit_scan(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_digit_scan_tree = NULL;

    gint str_start;
    gint max_str_len;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_digit_scan, tvb, 0, 255, ENC_NA);
        c15ch_out_gwe_digit_scan_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_digit_scan_tree, hf_c15ch_out_gwe_digit_scan_voip_dgmp_override,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        str_start = 1;
        max_str_len = 250;
        add_string_field( c15ch_out_gwe_digit_scan_tree, tvb, str_start, max_str_len, hf_c15ch_out_gwe_digit_scan_actv_dgmp  );
        proto_tree_add_item(c15ch_out_gwe_digit_scan_tree, hf_c15ch_out_gwe_digit_scan_op_gwe_digit_scan_tone,
                            tvb, 251, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_digit_scan_tree, hf_c15ch_out_gwe_digit_scan_op_gwe_tone_type,
                            tvb, 252, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_digit_scan_tree, hf_c15ch_out_gwe_digit_scan_op_gwe_tone_to,
                            tvb, 253, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_digit_scan_tree, hf_c15ch_out_gwe_digit_scan_op_gwe_digit_flash,
                            tvb, 254, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_line_sprvsn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_line_sprvsn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree,  hf_c15ch_out_gwe_line_sprvsn, tvb, 0, 3, ENC_NA);
        c15ch_out_gwe_line_sprvsn_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_line_sprvsn_tree, hf_c15ch_out_gwe_line_sprvsn_op_gwe_ofhk_event,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_line_sprvsn_tree, hf_c15ch_out_gwe_line_sprvsn_op_gwe_onhk_event,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_line_sprvsn_tree, hf_c15ch_out_gwe_line_sprvsn_op_gwe_flhk_event,
                            tvb, 2, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_md_conn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_md_conn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_md_conn, tvb, 0, 6, ENC_NA);
        c15ch_out_gwe_md_conn_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_md_conn_tree, hf_c15ch_out_gwe_md_conn_conn_num,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_md_conn_tree, hf_c15ch_out_gwe_md_conn_status_code,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_md_conn_tree, hf_c15ch_out_gwe_md_conn_op_gwe_mode,
                            tvb, 5, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_out_cot(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_out_cot_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_out_cot, tvb, 0, 8, ENC_NA);
        c15ch_out_gwe_out_cot_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);

        ti = proto_tree_add_item(c15ch_out_gwe_out_cot_tree, hf_c15ch_out_gwe_out_cot_ni_tn,
                            tvb, 0, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_third_level_out_gwe_sub1);

        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_out_gwe_out_cot_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_out_gwe_out_cot_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_mk_conn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_mk_conn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_mk_conn, tvb, 0, 12, ENC_NA);
        c15ch_out_gwe_mk_conn_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_mk_conn_tree, hf_c15ch_out_gwe_mk_conn_conn_num,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_mk_conn_tree, hf_c15ch_out_gwe_mk_conn_op_mk_conn_rsdp_ip,
                            tvb, 4, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_mk_conn_tree, hf_c15ch_out_gwe_mk_conn_op_mk_conn_rsdp_port,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_out_gwe_pcm_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_pcm_data_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_pcm_data, tvb, 0, 8, ENC_NA);
        c15ch_out_gwe_pcm_data_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_pcm_data_tree, hf_c15ch_out_gwe_pcm_data_rb_ua_handle_near,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_pcm_data_tree, hf_c15ch_out_gwe_pcm_data_rb_ua_handle_far,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_out_gwe_ring_line(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_ring_line_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_ring_line, tvb, 0, 101, ENC_NA);
        c15ch_out_gwe_ring_line_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_ring_line_tree, hf_c15ch_out_gwe_ring_line_op_gwe_display,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        add_string_field( c15ch_out_gwe_ring_line_tree, tvb, 1, 100, hf_c15ch_out_gwe_ring_line_op_gwe_display_chars );
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_rv_subs_data(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_rv_subs_data_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_rv_subs_data, tvb, 0, 8, ENC_NA);
        c15ch_out_gwe_rv_subs_data_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);

        ti = proto_tree_add_item(c15ch_out_gwe_rv_subs_data_tree, hf_c15ch_out_gwe_rv_subs_data_rb_fe_ni_tn,
                            tvb, 0, 8, ENC_BIG_ENDIAN);
        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_third_level_out_gwe_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_out_gwe_rv_subs_data_rb_fe_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_out_gwe_rv_subs_data_rb_fe_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_out_gwe_sac_notify(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_sac_notify_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_sac_notify, tvb, 0, 2, ENC_NA);
        c15ch_out_gwe_sac_notify_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_sac_notify_tree, hf_c15ch_out_gwe_sac_notify_op_gwe_blf_state,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_sac_notify_tree, hf_c15ch_out_gwe_sac_notify_op_gwe_subs_state,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_sac_list_entry(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_sac_list_entry_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_sac_list_entry, tvb, 0, 72, ENC_NA);
        c15ch_out_gwe_sac_list_entry_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        add_string_field( c15ch_out_gwe_sac_list_entry_tree, tvb, 0,72,
                            hf_c15ch_out_gwe_sac_list_entry_op_gwe_med_uri );
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_sac_sub_valid(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_sac_sub_valid_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_sac_sub_valid, tvb, 0, 5, ENC_NA);
        c15ch_out_gwe_sac_sub_valid_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_sac_sub_valid_tree, hf_c15ch_out_gwe_sac_sub_valid_op_gwe_subs_valid,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_sac_sub_valid_tree, hf_c15ch_out_gwe_sac_sub_valid_op_gwe_num_list_items,
                            tvb, 1, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_sip_info(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_sip_info_tree = NULL;


    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_sip_info, tvb, 0, 5, ENC_NA);
        c15ch_out_gwe_sip_info_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_sip_info_tree, hf_c15ch_out_gwe_sip_info_op_gwe_sip_info_type,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_out_gwe_sip_info_tree, hf_c15ch_out_gwe_sip_info_op_gwe_sip_info,
                            tvb, 1, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_out_gwe_sip_refer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_sip_refer_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_sip_refer, tvb, 0, 4, ENC_NA);
        c15ch_out_gwe_sip_refer_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_sip_refer_tree, hf_c15ch_out_gwe_sip_refer_op_gwe_refer_ua_hndl,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_out_gwe_update_ni_tn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_update_ni_tn_tree = NULL;
    proto_tree * sub_ni_tn_tree = NULL;


    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_update_ni_tn, tvb, 0, 8, ENC_NA);
        c15ch_out_gwe_update_ni_tn_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);

        ti = proto_tree_add_item(c15ch_out_gwe_update_ni_tn_tree, hf_c15ch_out_gwe_update_ni_tn_ni_tn,
                            tvb, 0, 8, ENC_BIG_ENDIAN);

        sub_ni_tn_tree = proto_item_add_subtree (ti, ett_c15ch_third_level_out_gwe_sub1);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_out_gwe_update_ni_tn_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(sub_ni_tn_tree, hf_c15ch_out_gwe_update_ni_tn_tn,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_out_gwe_update_rec_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_out_gwe_update_rec_addr_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_out_gwe_update_rec_addr, tvb, 0, 4, ENC_NA);
        c15ch_out_gwe_update_rec_addr_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_out_gwe);
        proto_tree_add_item(c15ch_out_gwe_update_rec_addr_tree, hf_c15ch_out_gwe_update_rec_addr_op_new_rec_addr,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

/* tone */

static int dissect_c15ch_tone(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tone_tree = NULL;

    guint8 msg_type;
    tvbuff_t * next_tvb;
    guint32 retv = 0;

    msg_type = tvb_get_guint8(tvb, 0);
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type: TONE, Msg Subtype: %s",
        val_to_str(msg_type, c15_tone_msg_types, "Unknown Msg Subtype: %d") );
    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_tone, tvb, 0, 1, ENC_NA);
        proto_item_append_text(ti, ", Msg Subtype: %s",
            val_to_str(msg_type, c15_tone_msg_types, "Unknown Msg Subtype: %d"));
        c15ch_tone_tree = proto_item_add_subtree(ti, ett_c15ch_second_level);
        proto_tree_add_item(c15ch_tone_tree, hf_c15ch_tone_msg_type,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
    }
    next_tvb = tvb_new_subset(tvb, 1, -1, -1);
    retv = 1 + dissector_try_uint(c15ch_tone_dissector_table, msg_type, next_tvb, pinfo, tree);
    return retv;
}


static int dissect_c15ch_tone_cot_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tone_cot_control_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_tone_cot_control, tvb, 0, 5, ENC_NA);
        c15ch_tone_cot_control_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone);
        proto_tree_add_item(c15ch_tone_cot_control_tree, hf_c15ch_tone_cot_control_device_id,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_cot_control_tree, hf_c15ch_tone_cot_control_cot_task,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_cot_control_tree, hf_c15ch_tone_cot_control_dest_h248,
                            tvb, 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_cot_control_tree, hf_c15ch_tone_cot_control_srce_h248,
                            tvb, 3, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_cot_control_tree, hf_c15ch_tone_cot_control_svc_channel,
                            tvb, 4, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_tone_cpm(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tone_cpm_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_tone_cpm, tvb, 0, 3, ENC_NA);
        c15ch_tone_cpm_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone);
        proto_tree_add_item(c15ch_tone_cpm_tree, hf_c15ch_tone_cpm_loop_type,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_cpm_tree, hf_c15ch_tone_cpm_device_id,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_cpm_tree, hf_c15ch_tone_cpm_tone_type,
                            tvb, 2, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_tone_give_tone(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tone_give_tone_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_tone_give_tone, tvb, 0, 2, ENC_NA);
        c15ch_tone_give_tone_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone);
        proto_tree_add_item(c15ch_tone_give_tone_tree, hf_c15ch_tone_give_tone_tone_id,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_give_tone_tree, hf_c15ch_tone_give_tone_tone_type,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_tone_madn_ring(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tone_madn_ring_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_tone_madn_ring, tvb, 0, 2, ENC_NA);
        c15ch_tone_madn_ring_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone);
        proto_tree_add_item(c15ch_tone_madn_ring_tree, hf_c15ch_tone_madn_ring_device_id,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_madn_ring_tree, hf_c15ch_tone_madn_ring_tone_type,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_tone_opls(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tone_opls_tree = NULL;
    proto_tree * to_ni_tn_tree = NULL;

    guint8 num_digits;
    num_digits = tvb_get_guint8(tvb, 12);

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_tone_opls, tvb, 0, 67, ENC_NA);
        c15ch_tone_opls_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone);
        proto_tree_add_item(c15ch_tone_opls_tree, hf_c15ch_tone_opls_svce_from_ni,
                            tvb, 0, 4, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(c15ch_tone_opls_tree, hf_c15ch_tone_opls_svce_to_ni_tn,
                            tvb, 4, 8, ENC_BIG_ENDIAN);
        to_ni_tn_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone_sub1);
        proto_tree_add_item(to_ni_tn_tree, hf_c15ch_tone_opls_svce_to_ni,
                            tvb, 4, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(to_ni_tn_tree, hf_c15ch_tone_opls_svce_to_tn,
                            tvb, 8, 4, ENC_BIG_ENDIAN);
        /* digits */
        add_digits_string(hf_c15ch_tone_opls_digits, tvb, c15ch_tone_opls_tree,
                        13, num_digits, 54, 1);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_tone_rcvr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tone_rcvr_tree = NULL;
    proto_tree * ni_tn_tree = NULL;


    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_tone_rcvr, tvb, 0, 9, ENC_NA);
        c15ch_tone_rcvr_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone);
        proto_tree_add_item(c15ch_tone_rcvr_tree, hf_c15ch_tone_rcvr_rcvr_id,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(c15ch_tone_rcvr_tree, hf_c15ch_tone_rcvr_conn_to_ni_tn,
                            tvb, 1, 8, ENC_BIG_ENDIAN);
        ni_tn_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone_sub1);
        proto_tree_add_item(ni_tn_tree, hf_c15ch_tone_rcvr_conn_to_ni,
                            tvb, 1, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ni_tn_tree, hf_c15ch_tone_rcvr_conn_to_tn,
                            tvb, 5, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}


static int dissect_c15ch_tone_timeout(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tone_timeout_tree = NULL;
    proto_tree * ni_tn_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_tone_timeout, tvb, 0, 15, ENC_NA);
        c15ch_tone_timeout_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone);
        proto_tree_add_item(c15ch_tone_timeout_tree, hf_c15ch_tone_timeout_device_id,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_timeout_tree, hf_c15ch_tone_timeout_service_pm,
                            tvb, 1, 1, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(c15ch_tone_timeout_tree, hf_c15ch_tone_timeout_service_ni_tn,
                            tvb, 2, 8, ENC_BIG_ENDIAN);
        ni_tn_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone_sub1);
        proto_tree_add_item(ni_tn_tree, hf_c15ch_tone_timeout_service_ni,
                            tvb, 2, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item(ni_tn_tree, hf_c15ch_tone_timeout_service_tn,
                            tvb, 6, 4, ENC_BIG_ENDIAN);

        proto_tree_add_item(c15ch_tone_timeout_tree, hf_c15ch_tone_timeout_gw_provided,
                            tvb, 10, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_timeout_tree, hf_c15ch_tone_timeout_gw_service_tone_type_or_from_ni,
                            tvb, 11, 4, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

static int dissect_c15ch_tone_tone_control(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item * ti = NULL;
    proto_tree * c15ch_tone_tone_control_tree = NULL;

    if (tree)
    {
        ti = proto_tree_add_item(tree, hf_c15ch_tone_tone_control, tvb, 0, 2, ENC_NA);
        c15ch_tone_tone_control_tree = proto_item_add_subtree(ti, ett_c15ch_third_level_tone);
        proto_tree_add_item(c15ch_tone_tone_control_tree, hf_c15ch_tone_tone_control_device_id,
                            tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(c15ch_tone_tone_control_tree, hf_c15ch_tone_tone_control_tone_type,
                            tvb, 1, 1, ENC_BIG_ENDIAN);
    }

    return tvb_reported_length(tvb);
}

/* register functions */
/* fields for c15 heartbeat dissector */
void proto_register_c15ch_hbeat(void)
{
    static hf_register_info hf[] = {
            { &hf_c15ch_hbeat_clli,
                {"CLLI", "c15hbeat.clli",
                FT_STRINGZ, BASE_NONE,
                NULL,
                0x0, NULL, HFILL}
            },
            { &hf_c15ch_hbeat_primary,
                {"Primary", "c15hbeat.primary",
                FT_UINT8, BASE_DEC,
                NULL,
                0x0, NULL, HFILL}
            },
            { &hf_c15ch_hbeat_secondary,
                {"Secondary", "c15hbeat.secondary",
                FT_UINT8, BASE_DEC,
                NULL,
                0x0, NULL, HFILL}
            },
            {  &hf_c15ch_hbeat_interface,
                {"Interface", "c15hbeat.interface",
                FT_STRINGZ, BASE_NONE,
                NULL,
                0x0, NULL, HFILL}
            }
    }; /* close hf[] array declaration */

    /* Protocol subtree array */
    static gint *ett[] = {
        &ett_c15ch_hbeat
    };

    proto_c15ch_hbeat = proto_register_protocol(
        "C15 Call History Heartbeat Protocol", /* name */
        "C15HBEAT",         /* short name */
        "c15hbeat"            /* abbreviation */
        );
    proto_register_field_array(proto_c15ch_hbeat, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}



void proto_register_c15ch(void)
{
/* fields for C15 header : base c15 dissector for non-heartbeat packets */
/* first level of dissection */
 static hf_register_info hf[] = {
        { &hf_c15ch_version,
            {"Version", "c15.ch.version",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_msgtype,
            {"Message Type", "c15.ch.msgtype",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING,
            &c15_msg_types_ext,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_size,
            { "Size", "c15.ch.size",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_call_ref,
            {"Call Reference", "c15.ch.callref",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_srce_ni_tn,
            {"Source NI/TN", "c15.ch.srce_ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_dest_ni_tn,
            {"Destination NI/TN", "c15.ch.dest_ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_srce_ni,
            {"Source NI", "c15.ch.srce_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_srce_tn,
            {"Source TN", "c15.ch.srce_tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_dest_ni,
            {"Destination NI", "c15.ch.dest_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_dest_tn,
            {"Destination TN", "c15.ch.dest_tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_realtime,
            {"Real Time", "c15.ch.realtime",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        }
    };


    /* Protocol subtree array */
    static gint *ett[] = {
        &ett_c15ch,
        &ett_src_ni_tn,
        &ett_dest_ni_tn
    };


       static hf_register_info hf_second_level[] = {
        { &hf_c15ch_ama_call_code,
            { "Call Code", "c15.ama.call_code",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_orig_digits,
            { "Orig Digits", "c15.ama.orig_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_num_dialed_digits,
            { "Number of Dialed Digits", "c15.ama.num_dialed_digits",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_br_prefix,
            { "BR Prefix", "c15.ama.br_prefix",
            FT_UINT8, BASE_DEC,
            VALS( ama_br_prefix_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_dialed_digits,
            { "Dialed Digits", "c15.ama.dialed_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_start_hour,
            { "Start Hour", "c15.ama.start_hour",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_start_minute,
            { "Start Minute", "c15.ama.start_minute",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_start_second,
            { "Start Second", "c15.ama.start_second",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_start_tenth_second,
            { "Start Tenth of Second", "c15.ama.start_tenth_second",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_start_day,
            { "Start Day", "c15.ama.start_day",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_start_month,
            { "Start Month", "c15.ama.start_month",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_start_year,
            { "Start Year", "c15.ama.start_year",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_answered,
            { "Answered", "c15.ama.answered",
            FT_BOOLEAN, BASE_NONE,
            TFS(&tfs_yes_no),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_elapsed_time,
            { "Elapsed Time (Millisec)", "c15.ama.elapsed_time",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama_call_type,
            { "Call Type", "c15.ama.call_type",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &ama_call_types_ext,
            0x0, NULL, HFILL}
        },
           { &hf_c15ch_c15_info_text,
            {"C15 Info Text", "c15.info.text",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_c15_info_code,
            {"C15 Info Code", "c15.info.code",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_c15_info_level,
            {"C15 Info Level", "c15.info.level",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_c15_info_level_types ),
            0x0, NULL, HFILL}
        },

           { &hf_c15ch_clli_clli_string,
            {"CLLI", "c15.clli.clli",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_clli_active_core,
            {"Active Core", "c15.clli.active_core",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_clli_inactive_core,
            {"Inactive Core", "c15.clli.inactive_core",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_clli_interface_string,
            {"Interface", "c15.clli.interface",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_clli_seconds,
            {"Seconds", "c15.clli.seconds",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_clli_microseconds,
            {"Microseconds", "c15.clli.microseconds",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },

         { &hf_c15ch_conn_connfrom,
            { "Conn From", "c15.conn.connfrom",
            FT_UINT32, BASE_DEC,
            VALS( c15_conn_from_types),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_conntype,
            { "Conn Type", "c15.conn.conntype",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_conn_perphtype,
            { "Perph Type", "c15.conn.perphtype",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_intra,
            { "Intra", "c15.conn.intra",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_srceni,
            { "Source NI", "c15.conn.srceni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_srcetn,
            { "Source TN", "c15.conn.srcetn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_srcenitn,
            { "Source NI/TN", "c15.conn.srcenitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_destni,
            {"Destination NI", "c15.conn.destni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_desttn,
            { "Destination TN", "c15.conn.desttn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_destnitn,
            {"Destination NI/TN", "c15.conn.destnitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_interlinknum,
            { "Interlink Number", "c15.conn.interlinknum",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_fromport,
            { "From Port", "c15.conn.fromport",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_fromslot,
            { "From Slot", "c15.conn.fromslot",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_toport,
            { "From Port", "c15.conn.fromport",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_toslot,
            { "To Slot", "c15.conn.toslot",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn_hubcallid,
            { "Hub Call ID", "c15.conn.hubcallid",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },

           { &hf_c15ch_cp_state_ch_oldpm,
            {"Old Progress Mark", "c15.cpsc.oldpm",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING,
            &c15_cp_state_pm_types_ext,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_state_ch_newpm,
            {"New Progress Mark", "c15.cpsc.newpm",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING,
            &c15_cp_state_pm_types_ext,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_state_ch_subpm,
            {"Sub Progress Mark", "c15.cpsc.subpm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_state_ch_trkpm,
            {"Trunk Progress Mark", "c15.cpsc.trkpm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_state_ch_slepm,
            {"SLE Progress Mark", "c15.cpsc.slepm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_state_ch_flags,
            {"Flags", "c15.cpsc.flags",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_state_ch_oldrtetype,
            {"Old RTE Type", "c15.cpsc.oldrtetype",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_state_ch_oldrteidx,
            {"Old RTE Index", "c15.cpsc.oldrteidx",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_state_ch_newrtetype,
            {"New RTE Type", "c15.cpsc.newrtetype",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_cp_state_ch_newrteidx,
            {"New RTE Index", "c15.cpsc.newrteidx",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },

        { &hf_c15ch_dest_digits_digits,
            { "Digits", "c15.dest_digits.digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_echo_cancel_ni,
            {"NI", "c15.echo_cancel.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },

        { &hf_c15ch_echo_cancel_tn,
            {"TN", "c15.echo_cancel.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_ni_tn,
            {"NI/TN", "c15.echo_cancel.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_old_l2_mode,
            {"Old L2 Mode", "c15.echo_cancel.old_l2_mode",
            FT_UINT8, BASE_DEC,
            VALS( c15_echo_cancel_l2_mode_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_old_channel_mode,
            {"Old Channel Mode", "c15.echo_cancel.old_channel_mode",
            FT_UINT32, BASE_DEC,
            VALS( c15_echo_cancel_channel_mode_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_old_ecan_mode,
            {"Old Ecan Mode", "c15.echo_cancel.old_ecan_mode",
            FT_UINT32, BASE_DEC,
            VALS( c15_echo_cancel_ecan_mode_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_new_l2_mode,
            {"New L2 Mode", "c15.echo_cancel.new_l2_mode",
            FT_UINT8, BASE_DEC,
            VALS( c15_echo_cancel_l2_mode_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_new_channel_mode,
            {"New Channel Mode", "c15.echo_cancel.new_channel_mode",
            FT_UINT32, BASE_DEC,
            VALS( c15_echo_cancel_channel_mode_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_new_ecan_mode,
            {"New Ecan Mode", "c15.echo_cancel.new_ecan_mode",
            FT_UINT32, BASE_DEC,
            VALS( c15_echo_cancel_ecan_mode_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_tone_id,
            {"Tone ID", "c15.echo_cancel.tone_id",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_pm,
            {"PM", "c15.echo_cancel.pm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_pc,
            {"PC", "c15.echo_cancel.pc",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_loop,
            {"Loop", "c15.echo_cancel.loop",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_slot,
            {"Slot", "c15.echo_cancel.slot",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_echo_cancel_location,
            {"Location", "c15.echo_cancel.location",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL }
        },

        { &hf_c15ch_encap_isup_direction,
            {"Direction", "c15.encap_isup.direction",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_encap_isup_isup_msg_length,
            {"Message Type", "c15.encap_isup.isup_msg_length",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },

        { &hf_c15ch_isup_direction,
            {"Direction", "c15.isup.direction",
            FT_UINT8, BASE_DEC,
            VALS( c15_isup_direction_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_isup_msgtype,
            {"Message Type", "c15.isup.msgtype",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &c15_isup_types_ext,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_isup_cic,
            { "CIC", "c15.isup.cic",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_isup_opcmember,
            { "OPC Member", "c15.isup.opcmember",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_opccluster,
            { "OPC Cluster", "c15.isup.opccluster",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_opcnetwork,
            { "OPC Network", "c15.isup.opcnetwork",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_dpcmember,
            {"DPC Member", "c15.isup.dpcmember",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_isup_dpccluster,
            { "DPC Cluster", "c15.isup.dpccluster",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_dpcnetwork,
            { "DPC Network", "c15.isup.dpcnetwork",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_level3index,
            { "Level 3 Index", "c15.isup.level3index",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_ni,
            { "NI", "c15.isup.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_tn,
            { "TN", "c15.isup.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_ni_tn,
            {"NI/TN", "c15.isup.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_isup_c15hdr,
            { "C15 Header", "c15.isup.c15hdr",
            FT_BYTES, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_layer2hdr,
            { "Layer 2 Header", "c15.isup.layer2hdr",
            FT_BYTES, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_layer3hdr,
            { "Layer 3 Header", "c15.isup.layer3hdr",
            FT_BYTES, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup_iptime,
            {"IP Time", "c15.isup.iptime",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_mkbrk_makebreak,
            { "Make Break", "c15.mkbrk.makebreak",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_mkbrk_nshlf,
            { "Nshlf", "c15.mkbrk.nshlf",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_mkbrk_stm,
            { "Stm", "c15.mkbrk.stm",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_mkbrk_caddr,
            { "C Address", "c15.mkbrk.caddr",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_mkbrk_cdata,
            { "C Data", "c15.mkbrk.cdata",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_nitnxlate_ni,
            {"NI", "c15.nitnxlate.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_tn,
            { "TN", "c15.nitnxlate.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_nitnxlate_ni_tn,
            {"NI/TN", "c15.nitnxlate.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_nitnxlate_equiptype,
            { "Equipment Type", "c15.nitnxlate.equiptype",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING,
            &ett_c15ch_nitnxlate_equip_types_ext,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_sitestring,
            { "Site String", "c15.nitnxlate.sitestring",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_concat_string,
            { "ID String", "c15.nitnxlate.id_string",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_subsitestring,
            { "Subsite String", "c15.nitnxlate.subsitestring",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_equipname,
            { "Equipment Name", "c15.nitnxlate.equipname",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_gw_type,
            { "GW Type", "c15.nitnxlate.gw_type",
            FT_UINT32, BASE_DEC,
            VALS( ett_c15ch_nitnxlate_gwe_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_parm_1,
            { "Parm 1", "c15.nitnxlate.parm_1",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_parm_2,
            { "Parm 2", "c15.nitnxlate.parm_2",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_parm_3,
            { "Parm 3", "c15.nitnxlate.parm_3",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_parm_4,
            { "Parm 4", "c15.nitnxlate.parm_4",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_key,
            { "Key", "c15.nitnxlate.key",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_gateway,
            { "Gateway", "c15.nitnxlate.gateway",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_line,
            { "Line", "c15.nitnxlate.line",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_bay,
            { "Bay", "c15.nitnxlate.bay",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_shelf,
            { "Shelf", "c15.nitnxlate.shelf",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_lsg,
            { "LSG", "c15.nitnxlate.lsg",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_idt_rdt,
            { "IDT/RDT", "c15.nitnxlate.idt_rdt",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_pm,
            { "PM", "c15.nitnxlate.pm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_ptrk,
            { "Ptrk", "c15.nitnxlate.ptrk",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_channel,
            { "Channel", "c15.nitnxlate.channel",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_pc_sts1,
            { "PC or STS1", "c15.nitnxlate.pc_sts1",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_port_vt15,
            { "Port or VT15", "c15.nitnxlate.port_vt15",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_user_tid,
            { "User TID", "c15.nitnxlate.user_tid",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_host,
            { "Host", "c15.nitnxlate.host",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_tg_num,
            { "Target Group Num", "c15.nitnxlate.tg_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate_mgcp_line_id,
            { "MGCP Line ID", "c15.nitnxlate.mgcp_line_id",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_ntwk_conn_pathtype,
            { "Path Type", "c15.ntwkconn.pathtype",
            FT_UINT8, BASE_DEC,
            VALS( ett_c15ch_ntwk_conn_path_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_conntype,
            { "Conn Type", "c15.ntwkconn.conntype",
            FT_UINT8, BASE_DEC,
            VALS( ett_c15ch_ntwk_conn_conn_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_fromoptimized,
            { "From Optimized", "c15.ntwkconn.fromoptimized",
            FT_BOOLEAN, BASE_NONE,
            TFS(&tfs_yes_no),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_fromsite,
            { "From Site", "c15.ntwkconn.fromsite",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_frompm,
            { "From PM", "c15.ntwkconn.frompm",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_frompc,
            { "From PC", "c15.ntwkconn.frompc",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_fromloop,
            { "From Loop", "c15.ntwkconn.fromloop",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_fromslot,
            { "From Slot", "c15.ntwkconn.fromslot",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_fromlocation,
            { "From Location", "c15.ntwkconn.fromlocation",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_fromcnx,
            { "From CNX", "c15.ntwkconn.fromcnx",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_fromntwkni,
            { "From Ntwk NI", "c15.ntwkconn.fromntwkni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_fromntwktn,
            { "From Ntwk TN", "c15.ntwkconn.fromntwktn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_fromntwknitn,
            { "From Ntwk NI/TN", "c15.ntwkconn.fromntwknitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_mbshold,
            { "MBS Hold", "c15.ntwkconn.mbshold",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_tooptimized,
            { "To Optimized", "c15.ntwkconn.tooptimized",
            FT_BOOLEAN, BASE_NONE,
            TFS(&tfs_yes_no),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_tosite,
            { "To Site", "c15.ntwkconn.tosite",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_topm,
            { "To PM", "c15.ntwkconn.topm",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_topc,
            { "To PC", "c15.ntwkconn.topc",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_toloop,
            { "To Loop", "c15.ntwkconn.toloop",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_tolocation,
            { "To Location", "c15.ntwkconn.tolocation",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_toslot,
            { "To Slot", "c15.ntwkconn.toslot",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn_tocnx,
            { "To CNX", "c15.ntwkconn.tocnx",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_orig_tnblocktype,
            { "TN Block Type", "c15.orig.tnblocktype",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING,
            &c15ch_orig_block_types_ext,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_ni,
            { "NI", "c15.orig.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_tn,
            { "TN", "c15.orig.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_ni_tn,
            {"NI/TN", "c15.orig.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_orig_dndigits,
            { "DN Digits", "c15.orig.dndigits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_nidscrn,
            { "Nid Scrn", "c15.orig.nidscrn",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_nidaddrtype,
            { "Nid Address Type", "c15.orig.nidaddrtype",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_nidnmbrplan,
            { "Nid Number Plan", "c15.orig.nidnmbrplan",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_nidprivind,
            { "Nid Priv Ind", "c15.orig.nidprivind",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_upnsaved,
            { "UPN Saved", "c15.orig.upnsaved",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_upndigits,
            { "UPN Digits", "c15.orig.upndigits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_upnscrn,
            { "UPN Scrn", "c15.orig.upnscrn",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_upnaddrtype,
            { "UPN Address Type", "c15.orig.upnaddrtype",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_upnnmbrplan,
            { "UPN Nmbr Plan", "c15.orig.upnnmbrplan",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_upnprivind,
            { "UPN Priv Ind", "c15.orig.upnprivind",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_rnpsaved,
            { "RNP Saved", "c15.orig.rnpsaved",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_rnpdigits,
            { "RNP Digits", "c15.orig.rnpdigits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_rnpscrn,
            { "RNP Scrn", "c15.orig.rnpscrn",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_rnpaddrtype,
            { "RNP Address Type", "c15.orig.rnpaddrtype",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_rnpnmbrplan,
            { "RNP Number Plan", "c15.orig.rnpnmbrplan",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_rnpprivind,
            { "RNP Priv Ind", "c15.orig.rnpprivind",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig_iptime,
            { "IP Time", "c15.orig.iptime",
            FT_UINT8, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_outgwebc_pbc_conn_ni,
        { "PBC Conn NI", "c15.out_gwe_bc.pbc.conn.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_outgwebc_pbc_conn_tn,
            { "PBC Conn TN", "c15.out_gwe_bc.pbc_conn.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_outgwebc_pbc_conn_ni_tn,
            {"PBC Conn NI/TN", "c15.out_gwe_bc.pbc_conn.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_outgwebc_pbc_conn_num,
            { "PBC Conn Num", "c15.out_gwe_bc.pbc_conn.num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_outgwebc_pbc_conn_type,
            { "PBC Conn Type", "c15.out_gwe_bc.pbc_conn.type",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_outgwebc_bc_msg_type,
            { "BC Msg Type", "c15.out_gwe_bc.bc_msg_type",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_outgwebc_op_bc_sdp_ip,
            { "OP BC SDP IP", "c15.out_gwe_bc.op_bc_sdp.ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_outgwebc_op_bc_sdp_port,
            { "OP BC SDP Port", "c15.out_gwe_bc.op_bc_sdp.port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_outgwebc_pbc_mdrp_mode,
            { "PBC MDRP Mode", "c15.out_gwe_bc.pbc.mdrp_mode",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_outgwebc_pbc_tst_flags,
            { "PBC TST Flags", "c15.out_gwe_bc.pbc.tst_flags",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_pathfind_vds30,
            {"VDS30", "c15.pathfind.vds30",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_pathfind_vds30_types),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromgweni,
            { "From GWE NI", "c15.pathfind.fromgweni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromgwetn,
            { "From GWE TN", "c15.pathfind.fromgwetn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromgwenitn,
            { "From GWE NI/TN", "c15.pathfind.fromgwenitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromoptimized,
            { "From Optimized", "c15.pathfind.fromoptimized",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromsite,
            { "From Site", "c15.pathfind.fromsite",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_frompm,
            { "From Port Module", "c15.pathfind.frompm",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_frompc,
            { "From Port Controller", "c15.pathfind.frompc",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromloop,
            { "From Loop", "c15.pathfind.fromloop",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromslot,
            { "From Slot", "c15.pathfind.fromslot",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromcnx,
            { "From CNX", "c15.pathfind.fromcnx",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromni,
            { "From NI", "c15.pathfind.fromni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromtn,
            { "From TN", "c15.pathfind.fromtn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_fromnitn,
            { "From NI/TN", "c15.pathfind.fromnitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_togweni,
            { "To GWE NI", "c15.pathfind.togweni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_togwetn,
            { "To GWE TN", "c15.pathfind.togwetn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_togwenitn,
            { "To GWE TN", "c15.pathfind.togwenitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_tooptimized,
            { "To Optimized", "c15.pathfind.tooptimized",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_tosite,
            { "To Site", "c15.pathfind.tosite",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_topm,
            { "To Port Module", "c15.pathfind.topm",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_topc,
            { "To Port Controller", "c15.pathfind.topc",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_toloop,
            { "To Loop", "c15.pathfind.toloop",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_toslot,
            { "To Slot", "c15.pathfind.toslot",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_tocnx,
            { "To CNX", "c15.pathfind.tocnx",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_toni,
            { "To NI", "c15.pathfind.toni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_totn,
            { "To TN", "c15.pathfind.totn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind_tonitn,
            { "To NI/TN", "c15.pathfind.tonitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_pathidle_vds30,
            {"VDS30", "c15.pathidle.vds30",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_pathidle_vds30_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_idlecode,
            {"Idle Code", "c15.pathidle.idlecode",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_pathidle_idle_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_pathtype,
            { "Path Type", "c15.pathidle.pathtype",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_pathidle_path_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_fromgweni,
            { "From GWE NI", "c15.pathidle.fromgweni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_fromgwetn,
            { "From GWE TN", "c15.pathidle.fromgwetn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_fromgwenitn,
            { "From GWE NI/TN", "c15.pathidle.fromgwenitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_fromsite,
            { "From Site", "c15.pathidle.fromsite",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_frompm,
            { "From Port Module", "c15.pathidle.frompm",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_frompc,
            { "From Port Controller", "c15.pathidle.frompc",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_fromloop,
            { "From Loop", "c15.pathidle.fromloop",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_fromslot,
            { "From Slot", "c15.pathidle.fromslot",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_fromcnx,
            { "From CNX", "c15.pathidle.fromcnx",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_fromni,
            { "From NI", "c15.pathidle.fromni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_fromtn,
            { "From TN", "c15.pathidle.fromtn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_fromnitn,
            { "From NI/TN", "c15.pathidle.fromnitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_togweni,
            { "To GWE NI", "c15.pathidle.togweni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_togwenitn,
            { "To GWE NI/TN", "c15.pathidle.togwenitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_togwetn,
            { "To GWE TN", "c15.pathidle.togwetn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_tosite,
            { "To Site", "c15.pathidle.tosite",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_topm,
            { "To Port Module", "c15.pathidle.topm",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_topc,
            { "To Port Controller", "c15.pathidle.topc",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_toloop,
            { "To Loop", "c15.pathidle.toloop",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_toslot,
            { "To Slot", "c15.pathidle.toslot",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_tocnx,
            {"To CNX", "c15.pathidle.tocnx",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_toni,
            { "To NI", "c15.pathidle.toni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_totn,
            { "From TN", "c15.pathidle.totn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle_tonitn,
            { "To NI/TN", "c15.pathidle.tonitn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_q931_direction,
            { "Direction", "c15.q931.direction",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_q931_direction_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_q931_ni,
            { "NI", "c15.q931.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_q931_tn,
            { "TN", "c15.q931.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_q931_ni_tn,
            { "NI/TN", "c15.q931.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_q931_msglength,
            { "Message Length", "c15.q931.msglength",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_q931,
            { "C15 Q931", "c15.q931",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_ni,
            { "NI", "c15.qos.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_tn,
            { "TN", "c15.qos.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_ni_tn,
            { "NI/TN", "c15.qos.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_rtcp_call_id,
            { "RTCP Call ID", "c15.qos.rtcp_call_id",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_register_type,
            { "Register Type", "c15.qos.register_type",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_tg_num,
            { "TG Num", "c15.qos.tg_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_trk_type,
            { "Trunk Type", "c15.qos.trk_type",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_status,
            { "Status", "c15.qos.status",
            FT_UINT32, BASE_DEC,
            VALS( ett_c15ch_qos_status_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_codec,
            { "Codec", "c15.qos.codec",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_given_ip,
            { "Given IP", "c15.qos.given_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_real_ip,
            { "Real IP", "c15.qos.real_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_local_ip,
            { "Local IP", "c15.qos.local_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_tx_pkts,
            { "Tx Packets", "c15.qos.tx_pkts",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_lost_pkts,
            { "Lost Packets", "c15.qos.lost_pkts",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_lost_pct,
            { "Lost Percent", "c15.qos.lost_pct",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_jitter,
            { "Jitter", "c15.qos.jitter",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_rtt,
            { "Round Trip Time", "c15.qos.rtt",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_avg_rtt,
            { "Average Round Trip Time", "c15.qos.avg_rtt",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_duration,
            { "Duration", "c15.qos.duration",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_mos,
            { "MOS", "c15.qos.mos",
            FT_FLOAT, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_ep_type,
            { "EP Type", "c15.qos.ep_type",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_dn_or_tg,
            { "DN or TG", "c15.qos.dn_or_tg",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_pm,
            { "Port Module", "c15.qos.pm",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_pc,
            { "Port Controller", "c15.qos.pc",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_hour,
            { "Hour", "c15.qos.hour",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_min,
            { "Minutes", "c15.qos.min",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_sec,
            { "Seconds", "c15.qos.sec",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_tenth_sec,
            { "Tenths of Seconds", "c15.qos.tenth_sec",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_year,
            { "Year", "c15.qos.year",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_month,
            { "Month", "c15.qos.month",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_day,
            { "Day", "c15.qos.day",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos_day_of_week,
            { "Day of Week", "c15.qos.day_of_week",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_route_number,
            { "Number", "c15.route.number",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_route_type,
            { "Type", "c15.route.type",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING,
            &c15_route_types_ext,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_route_subpm,
            { "Sub Progress Mark", "c15.route.subpm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_route_trkpm,
            { "Trk Progress Mark", "c15.route.trkpm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_route_strtaindo,
            { "START AIN DO", "c15.route.strtaindo",
            FT_UINT8, BASE_DEC,
            VALS( c15_route_strt_ain_do_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_route_cr_rte_adv,
            { "CR RTE Adv", "c15.route.cr_rte_adv",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_route_cause,
            { "Cause", "c15.route.cause",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_sccp_direction,
            { "Direction", "c15.sccp.direction",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_sccp_direction_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_msgtype,
            { "Message Type", "c15.sccp.msgtype",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_sccp_msg_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_hopcount,
            { "Hop Count", "c15.sccp.hopcount",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_transactionnum,
            { "Transaction Number", "c15.sccp.transactionnum",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_opcmember,
            { "OPC Member", "c15.sccp.opcmember",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_opccluster,
            { "OPC Cluster", "c15.sccp.opccluster",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_opcnetwork,
            { "OPC Network", "c15.sccp.opcnetwork",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_dpcmember,
            { "DPC Member", "c15.sccp.opcmember",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_dpccluster,
            { "DPC Cluster", "c15.sccp.opccluster",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_dpcnetwork,
            { "DPC Network", "c15.sccp.opcnetwork",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_level3index,
            { "Level 3 Index", "c15.sccp.level3index",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_ni,
            { "NI", "c15.sccp.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_tn,
            { "TN", "c15.sccp.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_ni_tn,
            { "NI/TN", "c15.sccp.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_sls,
            { "SLS", "c15.sccp.sls",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp_iptime,
            { "IP Time", "c15.sccp.iptime",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_srcedest_conntype,
            { "Connection Type", "c15.srcedest.conntype",
            FT_UINT8, BASE_DEC,
            VALS( c15_srcedest_conn_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_srcedest_pathtype,
            { "Path Type", "c15.srcedest.pathtype",
            FT_UINT8, BASE_DEC,
            VALS( c15_srcedest_path_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_srcedest_pathdirect,
            { "Path Direction", "c15.srcedest.pathdirect",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_tcap_direction,
            { "Direction", "c15.tcap.direction",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_tcap_direction_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_action,
            { "Action", "c15.tcap.action",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_tcap_action_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_package_type,
            { "Package Type", "c15.tcap.package_type",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_tcap_package_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_ssn,
            { "SSN", "c15.tcap.ssn",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_local_ssn,
            { "Local SSN", "c15.tcap.local_ssn",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_tcap_local_ssn_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_result_err_code,
            { "Result Error Code", "c15.tcap.result_err_code",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_tcap_err_code_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_return_reason,
            { "Return Reason", "c15.tcap.return_reason",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_tcap_ret_reason_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_feat_id,
            { "Feat ID", "c15.tcap.feat_id",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_tcap_feat_id_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_feat_req,
            { "Feat Req", "c15.tcap.feat_req",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_tcap_feat_req_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_cl_comp_result,
            { "CL Comp Result", "c15.tcap.cl_comp_result",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_release_bit,
            { "Release Bit", "c15.tcap.release_bit",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_tcap_rel_bit_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_term_cl_request,
            { "Term CL Request", "c15.tcap.term_cl_request",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_opc_index,
            { "OPC Index", "c15.tcap.opc_index",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_dpc_mem,
            { "DPC Mem", "c15.tcap.dpc_mem",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_dpc_clus,
            { "DPC Clus", "c15.tcap.dpc_clus",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_dpc_net,
            { "DPC Net", "c15.tcap.dpc_net",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_tcap_cp_id,
            { "CP ID", "c15.tcap.cp_id",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },

        { &hf_c15ch_twc_rswch_pm,
            { "Progress Mark", "c15.twc_rswch.pm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_twc_rswch_subpm,
            { "Sub Progress Mark", "c15.twc_rswch.subpm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_twc_rswch_trkpm,
            { "Trunk Progress Mark", "c15.twc_rswch.trkpm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_twc_rswch_devid,
            { "Device ID", "c15.twc_rswch.devid",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_twc_rswch_event,
            { "Event", "c15.twc_rswch.event",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_twc_rswch_parm,
            { "Parameter", "c15.twc_rswch.parm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_twc_rswch_iptime,
            { "IP Time", "c15.twc_rswch.iptime",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_cp_event_pm,
            { "Progress Mark", "c15.cpe.pm",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING,
            &c15_pm_types_ext,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_cp_event_subpm,
            { "Sub Progress Mark", "c15.cpe.subpm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_orig,
            { "Sub Progress Mark (Orig)", "c15.cpe.subpm_orig",
            FT_UINT32, BASE_DEC,
            VALS( subpm_orig_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_disc_time,
            { "Sub Progress Mark (Disc Time)", "c15.cpe.subpm_disc_time",
            FT_UINT32, BASE_DEC,
            VALS( subpm_disc_time_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_revert,
            { "Sub Progress Mark (Revertive)", "c15.cpe.subpm_revert",
            FT_UINT32, BASE_DEC,
            VALS( subpm_revert_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_orig_dt,
            { "Sub Progress Mark (Orig DT)", "c15.cpe.subpm_orig_dt",
            FT_UINT32, BASE_DEC,
            VALS( subpm_orig_dt_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_orig_ws,
            { "Sub Progress Mark (Orig WS)", "c15.cpe.subpm_orig_ws",
            FT_UINT32, BASE_DEC,
            VALS( subpm_orig_ws_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_orig_dd,
            { "Sub Progress Mark (Orig DD)", "c15.cpe.subpm_orig_dd",
            FT_UINT32, BASE_DEC,
            VALS( subpm_orig_dd_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_orig_id,
            { "Sub Progress Mark (Orig ID)", "c15.cpe.subpm_orig_id",
            FT_UINT32, BASE_DEC,
            VALS( subpm_orig_id_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_no_test,
            { "Sub Progress Mark (No Test)", "c15.cpe.subpm_no_test",
            FT_UINT32, BASE_DEC,
            VALS( subpm_no_test_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_dialing,
            { "Sub Progress Mark (Dialing)", "c15.cpe.subpm_dialing",
            FT_UINT32, BASE_DEC,
            VALS( subpm_dialing_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_rebuilt,
            { "Sub Progress Mark (Rebuilt)", "c15.cpe.subpm_rebuilt",
            FT_UINT32, BASE_DEC,
            VALS( subpm_rebuilt_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_acfw_reac,
            { "Sub Progress Mark (ACFW Reac)", "c15.cpe.subpm_acfw_reac",
            FT_UINT32, BASE_DEC,
            VALS( subpm_acfw_reac_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_process_route,
            { "Sub Progress Mark (Process Route)", "c15.cpe.subpm_process_route",
            FT_UINT32, BASE_DEC,
            VALS( subpm_process_route_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_rte_line,
            { "Sub Progress Mark (Rte Line)", "c15.cpe.subpm_rte_line",
            FT_UINT32, BASE_DEC,
            VALS( subpm_rte_line_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_mtce,
            { "Sub Progress Mark (MTCE)", "c15.cpe.subpm_mtce",
            FT_UINT32, BASE_DEC,
            VALS( subpm_mtce_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_aux_tone,
            { "Sub Progress Mark (AUXT)", "c15.cpe.subpm_aux_tone",
            FT_UINT32, BASE_DEC,
            VALS( subpm_aux_tone_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_noller,
            { "Sub Progress Mark (NOLLER)", "c15.cpe.subpm_noller",
            FT_UINT32, BASE_DEC,
            VALS( subpm_noller_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_ittk,
            { "Sub Progress Mark (ITTK)", "c15.cpe.subpm_ittk",
            FT_UINT32, BASE_DEC,
            VALS( subpm_ittk_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_alm_send,
            { "Sub Progress Mark (Alarm Send)", "c15.cpe.subpm_alm_send",
            FT_UINT32, BASE_DEC,
            VALS( subpm_alm_send_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_ani_spill,
            { "Sub Progress Mark (ANI Spill)", "c15.cpe.subpm_ani_spill",
            FT_UINT32, BASE_DEC,
            VALS( subpm_ani_spill_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_trunk_term,
            { "Sub Progress Mark (Trunk Term)", "c15.cpe.subpm_trunk_term",
            FT_UINT32, BASE_DEC,
            VALS( subpm_trunk_term_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_line_term,
            { "Sub Progress Mark (Line Term)", "c15.cpe.subpm_line_term",
            FT_UINT32, BASE_DEC,
            VALS( subpm_line_term_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_non_cp,
            { "Sub Progress Mark (Non CP)", "c15.cpe.subpm_non_cp",
            FT_UINT32, BASE_DEC,
            VALS( subpm_non_cp_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_3wc,
            { "Sub Progress Mark (3wc)", "c15.cpe.subpm_3wc",
            FT_UINT32, BASE_DEC,
            VALS( subpm_twc_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_held_3wc,
            { "Sub Progress Mark (Held 3WC)", "c15.cpe.subpm_held_3wc",
            FT_UINT32, BASE_DEC,
            VALS( subpm_held_3wc_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_cwt,
            { "Sub Progress Mark (CWT)", "c15.cpe.subpm_cwt",
            FT_UINT32, BASE_DEC,
            VALS( subpm_cwt_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_held_cwt,
            { "Sub Progress Mark (Held CWT)", "c15.cpe.subpm_held_cwt",
            FT_UINT32, BASE_DEC,
            VALS( subpm_held_cwt_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_update_sc,
            { "Sub Progress Mark (Update SC)", "c15.cpe.subpm_update_sc",
            FT_UINT32, BASE_DEC,
            VALS( subpm_update_sc_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_orig_spdt,
            { "Sub Progress Mark (Orig SPDT)", "c15.cpe.subpm_orig_spdt",
            FT_UINT32, BASE_DEC,
            VALS( subpm_orig_dt_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_acfw_retm,
            { "Sub Progress Mark (ACFW RETM)", "c15.cpe.subpm_acfw_retm",
            FT_UINT32, BASE_DEC,
            VALS( subpm_acfw_retm_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_cfw_busy,
            { "Sub Progress Mark (CFW Busy)", "c15.cpe.subpm_cfw_busy",
            FT_UINT32, BASE_DEC,
            VALS( subpm_cfw_busy_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_cfw,
            { "Sub Progress Mark (CFW)", "c15.cpe.subpm_cfw",
            FT_UINT32, BASE_DEC,
            VALS( subpm_cfw_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_cfw_deact,
            { "Sub Progress Mark (CFW Deact)", "c15.cpe.subpm_cfw_deact",
            FT_UINT32, BASE_DEC,
            VALS( subpm_cfw_deact_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_rcfw,
            { "Sub Progress Mark (RCFW)", "c15.cpe.subpm_rcfw",
            FT_UINT32, BASE_DEC,
            VALS( subpm_rcfw_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_rotl_tp,
            { "Sub Progress Mark (ROTL TP)", "c15.cpe.subpm_rotl_tp",
            FT_UINT32, BASE_DEC,
            VALS( subpm_rotl_tp_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_chdt,
            { "Sub Progress Mark (CHD DT)", "c15.cpe.subpm_chdt",
            FT_UINT32, BASE_DEC,
            VALS( subpm_chdt_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_chd,
            { "Sub Progress Mark (Call Hold)", "c15.cpe.subpm_chd",
            FT_UINT32, BASE_DEC,
            VALS( subpm_chd_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_cheld,
            { "Sub Progress Mark (Call Held)", "c15.cpe.subpm_cheld",
            FT_UINT32, BASE_DEC,
            VALS( subpm_cheld_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_3wch,
            { "Sub Progress Mark (3WCH)", "c15.cpe.subpm_3wch",
            FT_UINT32, BASE_DEC,
            VALS( subpm_twc_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_3wcw,
            { "Sub Progress Mark (3WCW)", "c15.cpe.subpm_3wcw",
            FT_UINT32, BASE_DEC,
            VALS( subpm_twc_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_cslt,
            { "Sub Progress Mark (CSLT)", "c15.cpe.subpm_cslt",
            FT_UINT32, BASE_DEC,
            VALS( subpm_held_3wc_types ),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_dig_ckt_test,
            { "Sub Progress Mark (Dig CKT Test)", "c15.cpe.subpm_dig_ckt",
            FT_UINT32, BASE_DEC,
            VALS( subpm_dig_ckt_test_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_dig_ckt_test_subpm_sp,
            { "Sub Progress Mark (Dig CKT Test, Single Party)", "c15.cpe.dig_ckt_test_subpm_sp",
            FT_UINT32, BASE_DEC,
            VALS( dig_ckt_test_subpm_sp_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_dig_ckt_test_subpm_mp,
            { "Sub Progress Mark (Dig CKT Test, Multi Party)", "c15.cpe.dig_ckt_test_subpm_mp",
            FT_UINT32, BASE_DEC,
            VALS( dig_ckt_test_subpm_mp_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_dig_ckt_test_subpm_coin,
            { "Sub Progress Mark (Dig CKT Test, Coin)", "c15.cpe.dig_ckt_test_subpm_coin",
            FT_UINT32, BASE_DEC,
            VALS( dig_ckt_test_subpm_coin_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_dig_ckt_test_subpm_isdn,
            { "Sub Progress Mark (Dig CKT Test, ISDN)", "c15.cpe.dig_ckt_test_subpm_isdn",
            FT_UINT32, BASE_DEC,
            VALS( dig_ckt_test_subpm_isdn_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_dig_ckt_test_subpm_trc,
            { "Sub Progress Mark (Dig CKT Test, TRC)", "c15.cpe.dig_ckt_test_subpm_trc",
            FT_UINT32, BASE_DEC,
            VALS( dig_ckt_test_subpm_trc_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_dig_ckt_test_subpm_disc,
            { "Sub Progress Mark (Dig CKT Test, Disc)", "c15.cpe.dig_ckt_test_subpm_disc",
            FT_UINT32, BASE_DEC,
            VALS( dig_ckt_test_subpm_disc_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_nail,
            { "Sub Progress Mark (NAIL)", "c15.cpe.subpm_nail",
            FT_UINT32, BASE_DEC,
            VALS( subpm_nail_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_dcbi,
            { "Sub Progress Mark (DCBI)", "c15.cpe.subpm_dcbi",
            FT_UINT32, BASE_DEC,
            VALS( subpm_dcbi_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_rag_confirm,
            { "Sub Progress Mark (RAG Confirm)", "c15.cpe.subpm_rag_confirm",
            FT_UINT32, BASE_DEC,
            VALS( subpm_rag_confirm_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_rag_process,
            { "Sub Progress Mark (RAG Process)", "c15.cpe.subpm_rag_process",
            FT_UINT32, BASE_DEC,
            VALS( subpm_rag_process_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_e800,
            { "Sub Progress Mark (E800 Db)", "c15.cpe.subpm_e800",
            FT_UINT32, BASE_DEC,
            VALS( subpm_e800_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_cfra,
            { "Sub Progress Mark (CFRA)", "c15.cpe.subpm_cfra",
            FT_UINT32, BASE_DEC,
            VALS( subpm_cfra_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_mwi_deac,
            { "Sub Progress Mark (MWI Deac)", "c15.cpe.subpm_mwi_deac",
            FT_UINT32, BASE_DEC,
            VALS( subpm_mwi_deac_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_acar_cp,
            { "Sub Progress Mark (ACAR CP)", "c15.cpe.subpm_acar_cp",
            FT_UINT32, BASE_DEC,
            VALS( subpm_acar_cp_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_acar_rering,
            { "Sub Progress Mark (ACAR Rering)", "c15.cpe.subpm_acar_rering",
            FT_UINT32, BASE_DEC,
            VALS( subpm_acar_rering_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_acar_ann,
            { "Sub Progress Mark (ACAR Ann)", "c15.cpe.subpm_acar_ann",
            FT_UINT32, BASE_DEC,
            VALS( subpm_acar_ann_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_sle,
            { "Sub Progress Mark (CP SLE)", "c15.cpe.subpm_sle",
            FT_UINT32, BASE_DEC,
            VALS( subpm_sle_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_perform_cot,
            { "Sub Progress Mark (Perform COT)", "c15.cpe.subpm_perform_cot",
            FT_UINT32, BASE_DEC,
            VALS( subpm_perform_cot_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_clid,
            { "Sub Progress Mark (CLID)", "c15.cpe.subpm_clid",
            FT_UINT32, BASE_DEC,
            VALS( subpm_clid_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_xpm,
            { "Sub Progress Mark (XPM)", "c15.cpe.subpm_xpm",
            FT_UINT32, BASE_DEC,
            VALS( subpm_xpm_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_mwil,
            { "Sub Progress Mark (MWIL)", "c15.cpe.subpm_mwil",
            FT_UINT32, BASE_DEC,
            VALS( subpm_mwil_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_ldbs,
            { "Sub Progress Mark (LDBS)", "c15.cpe.subpm_ldbs",
            FT_UINT32, BASE_DEC,
            VALS( subpm_ldbs_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_acr,
            { "Sub Progress Mark (ACR)", "c15.cpe.subpm_acr",
            FT_UINT32, BASE_DEC,
            VALS( subpm_acr_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_call_park,
            { "Sub Progress Mark (Call Park)", "c15.cpe.subpm_call_park",
            FT_UINT32, BASE_DEC,
            VALS( subpm_call_park_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_camp_on_recall,
            { "Sub Progress Mark (Camp On Recall)", "c15.cpe.subpm_camp_on_recall",
            FT_UINT32, BASE_DEC,
            VALS( subpm_camp_on_recall_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_cff,
            { "Sub Progress Mark (Call Fwrd Fixed Dest)", "c15.cpe.subpm_cff",
            FT_UINT32, BASE_DEC,
            VALS( subpm_cff_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_ibert,
            { "Sub Progress Mark (IBERT)", "c15.cpe.subpm_ibert",
            FT_UINT32, BASE_DEC,
            VALS( subpm_ibert_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_ain,
            { "Sub Progress Mark (AIN)", "c15.cpe.subpm_ain",
            FT_UINT32, BASE_DEC,
            VALS( subpm_ain_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_ain_sit,
            { "Sub Progress Mark (AIN SIT)", "c15.cpe.subpm_ain_sit",
            FT_UINT32, BASE_DEC,
            VALS( subpm_ain_sit_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_ain_rtg,
            { "Sub Progress Mark (AIN RTG)", "c15.cpe.subpm_ain_rtg",
            FT_UINT32, BASE_DEC,
            VALS( subpm_ain_rtg_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_nail_bcon,
            { "Sub Progress Mark (NAIL BCON)", "c15.cpe.subpm_nail_bcon",
            FT_UINT32, BASE_DEC,
            VALS( subpm_nail_bcon_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_nail_dcon,
            { "Sub Progress Mark (NAIL DCON)", "c15.cpe.subpm_nail_dcon",
            FT_UINT32, BASE_DEC,
            VALS( subpm_nail_dcon_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_qtrn_trvr,
            { "Sub Progress Mark (QTRN TRVR)", "c15.cpe.subpm_qtrn_trvr",
            FT_UINT32, BASE_DEC,
            VALS( subpm_qtrn_trvr_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_ekts,
            { "Sub Progress Mark (EKTS)", "c15.cpe.subpm_ekts",
            FT_UINT32, BASE_DEC,
            VALS( subpm_ekts_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_alt,
            { "Sub Progress Mark (ALT)", "c15.cpe.subpm_alt",
            FT_UINT32, BASE_DEC,
            VALS( subpm_alt_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_calea,
            { "Sub Progress Mark (CALEA)", "c15.cpe.subpm_calea",
            FT_UINT32, BASE_DEC,
            VALS( subpm_calea_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_sim_ring,
            { "Sub Progress Mark (Sim Ring)", "c15.cpe.subpm_sim_ring",
            FT_UINT32, BASE_DEC,
            VALS( subpm_sim_ring_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_lta,
            { "Sub Progress Mark (LTA)", "c15.cpe.subpm_lta",
            FT_UINT32, BASE_DEC,
            VALS( subpm_lta_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_hgq,
            { "Sub Progress Mark (HGQ)", "c15.cpe.subpm_hgq",
            FT_UINT32, BASE_DEC,
            VALS( subpm_hgq_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_idle,
            { "Sub Progress Mark (Idle)", "c15.cpe.subpm_idle",
            FT_UINT32, BASE_DEC,
            VALS( subpm_idle_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_sig,
            { "Sub Progress Mark (Sig)", "c15.cpe.subpm_sig",
            FT_UINT32, BASE_DEC,
            VALS( subpm_sig_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_sig_dest,
            { "Sub Progress Mark (Sig Dest)", "c15.cpe.subpm_sig_dest",
            FT_UINT32, BASE_DEC,
            VALS( subpm_sig_dest_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_subpm_agl_splrg,
            { "Sub Progress Mark (AGL Splash Ring)", "c15.cpe.subpm_agl_splrg",
            FT_UINT32, BASE_DEC,
            VALS( subpm_agl_splrg_types),
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_cp_event_trkpm,
            { "Trunk Progress Mark", "c15.cpe.trkpm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_cp_event_dig_ckt_test_trkpm,
            { "Trunk Progress Mark (Dig CKT Test)", "c15.cpe.dig_ckt_test_trkpm",
            FT_UINT32, BASE_DEC,
            VALS( trkpm_dig_ckt_test_types),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_cp_event_devid,
            { "Device ID", "c15.cpe.devid",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING,
            &c15_dev_types_ext,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_cp_event_event,
            { "Event", "c15.cpe.event",
            FT_UINT32, BASE_DEC|BASE_EXT_STRING,
            &c15_event_types_ext,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_cp_event_parm,
            { "Parm", "c15.cpe.parm",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_cp_event_iptime,
            { "IP Time", "c15.cpe.iptime",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        } ,
         { &hf_c15ch_inc_gwe_ni,
            { "NI", "c15.inc_gwe.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_tn,
            { "TN", "c15.inc_gwe.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ni_tn,
            {"NI/TN", "c15.inc_gwe.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_inc_gwe_taskid,
            { "Task ID", "c15.inc_gwe.taskid",
            FT_UINT8, BASE_DEC,
            VALS( c15inc_gwe_task_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_fiatid_invalid,
            { "Fiat ID (Invalid)", "c15.inc_gwe.fiatid_invalid",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_fiatid_bc,
            { "Fiat ID (Bearer Control)", "c15.inc_gwe.fiatid_bc",
            FT_UINT8, BASE_DEC,
            VALS( c15inc_gwe_bc_fiat_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_fiatid_mtce,
            { "Fiat ID (MTCE)", "c15.inc_gwe.fiatid_mtce",
            FT_UINT8, BASE_DEC,
            VALS( c15inc_gwe_mtce_fiat_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_fiatid_om,
            { "Fiat ID (OM)", "c15.inc_gwe.fiatid_om",
            FT_UINT8, BASE_DEC,
            VALS( c15inc_gwe_om_fiat_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_fiatid_h248,
            { "Fiat ID (H248)", "c15.inc_gwe.fiatid_h248",
            FT_UINT8, BASE_DEC,
            VALS( c15inc_gwe_h248_fiat_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_fiatid_sua,
            { "Fiat ID (SUA)", "c15.inc_gwe.fiatid_sua",
            FT_UINT8, BASE_DEC,
            VALS( c15inc_gwe_sua_fiat_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_fiatid_mgcp,
            { "Fiat ID (MGCP)", "c15.inc_gwe.fiatid_mgcp",
            FT_UINT8, BASE_DEC,
            VALS( c15inc_gwe_mgcp_fiat_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_fiatid_sip_notify,
            { "Fiat ID (SIP Notify)", "c15.inc_gwe.fiatid_sip_notify",
            FT_UINT8, BASE_DEC,
            VALS( c15inc_gwe_sip_notify_fiat_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_fiatid_admn,
            { "Fiat ID (Admn)", "c15.inc_gwe.fiatid_admn",
            FT_UINT8, BASE_DEC,
            VALS( c15inc_gwe_admn_fiat_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_datatype,
            { "Datatype", "c15.inc_gwe.datatype",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &c15inc_gwe_types_ext,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_out_gwe_ni,
            { "NI", "c15.out_gwe.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_tn,
            { "TN", "c15.out_gwe.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_ni_tn,
            {"NI/TN", "c15.out_gwe.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_out_gwe_op_gwe_msg_type,
            { "OP GWE Msg Type", "c15.out_gwe.op_gwe_msg_type",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &c15_out_gwe_msg_types_ext,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_op_gwe_protocol,
            { "OP GWE Protocol", "c15.out_gwe.op_gwe_protocol",
            FT_UINT8, BASE_DEC,
            VALS( c15_out_gwe_protocol_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_op_sua_hndl,
            { "Sip User Agent Handle", "c15.out_gwe.sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_gwe_data_type,
            { "GWE Datatype", "c15.out_gwe.gwe_data_type",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &c15_out_gwe_data_types_ext,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_tone_msg_type,
            { "Msg Type", "c15.tone.msg_type",
            FT_UINT8, BASE_DEC,
            VALS( c15_tone_msg_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_cp_state_ch,
            { "C15 CP State Change", "c15.cpsc",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_cp_event,
            { "C15 CP Event", "c15.cpe",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_isup,
            { "C15 ISUP", "c15.isup",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_nitnxlate,
            { "C15 NITN Xlate", "c15.nitnxlate",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_sccp,
            { "C15 SCCP", "c15.sccp",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_orig,
            { "C15 CP Orig", "c15.orig",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_conn,
            { "C15 Conn", "c15.conn",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ntwk_conn,
            { "C15 Network Conn", "c15.ntwkconn",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_mkbrk,
            { "C15 Make Break", "c15.mkbrk",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathfind,
            { "C15 Path Find", "c15.pathfind",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_pathidle,
            { "C15 Path Idle", "c15.pathidle",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_dest_digits,
            { "C15 Destination Digits", "c15.dest_digits",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_twc_rswch,
            { "C15 TWC Rswch", "c15.twc_rswch",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_srcedest,
            { "C15 Source Destination", "c15.srcedest",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_route,
            { "C15 Route", "c15.route",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe,
            { "C15 Incoming GWE", "c15.inc_gwe",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe,
            { "C15 Outgoing GWE", "c15.out_gwe",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_outgwebc,
            { "C15 Out GWE Bearer Control", "c15.out_gwe_bc",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_ama,
            { "C15 AMA", "c15.ama",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_qos,
            { "C15 Quality of Service", "c15.qos",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_echo_cancel,
            { "C15 Echo Cancel", "c15.echo_cancel",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone,
            { "C15 Tone", "c15.tone",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_encap_isup,
            { "C15 Encapsulated ISUP", "c15.encap_isup",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tcap,
            { "C15 TCAP", "c15.tcap",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_clli,
            { "C15 CLLI", "c15.clli",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_c15_info,
            { "C15 Info", "c15.info",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        }
    };
    static gint *ett_second_level[] = {
        &ett_c15ch_second_level,
        &ett_c15ch_second_level_sub1,
        &ett_c15ch_second_level_sub2,
        &ett_c15ch_second_level_sub3,
        &ett_c15ch_second_level_sub4
    };
 /* third level */
 /* tone */

     static hf_register_info hf_third_level_tone[] = {
        { &hf_c15ch_tone_cot_control_device_id,
            { "Device ID", "c15.tone.cot_control.device_id",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_cot_control_cot_task,
            { "COT Task", "c15.tone.cot_control.cot_task",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_cot_control_dest_h248,
            { "Destination H248", "c15.tone.cot_control.dest_h248",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_cot_control_srce_h248,
            { "Source H248", "c15.tone.cot_control.srce_h248",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_cot_control_svc_channel,
            { "Svc Channel", "c15.tone.cot_control.svc_channel",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_give_tone_tone_id,
            { "Tone ID", "c15.tone.give_tone.tone_id",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_give_tone_tone_type,
            { "Tone Type", "c15.tone.give_tone.tone_type",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &tone_types_ext,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_tone_madn_ring_device_id,
            { "Device ID", "c15.tone.madn_ring.device_id",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_madn_ring_tone_type,
            { "Tone Type", "c15.tone.madn_ring.tone_type",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &tone_types_ext,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_opls_svce_from_ni,
            { "Svce From NI", "c15.tone.opls.svce_from_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_opls_svce_to_ni,
            { "Svce To NI", "c15.tone.opls.svce_to_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_opls_svce_to_tn,
            { "Svce To TN", "c15.tone.opls.svce_to_tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_opls_svce_to_ni_tn,
            { "Svce To NI/TN", "c15.tone.opls.svce_to_ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_opls_digits,
            { "Digits", "c15.tone.opls.digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_rcvr_rcvr_id,
            { "Receiver ID", "c15.tone.rcvr.rcvr_id",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_rcvr_conn_to_ni,
            { "Conn to NI", "c15.tone.rcvr.conn_to_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_rcvr_conn_to_tn,
            { "Conn to TN", "c15.tone.rcvr.conn_to_tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_rcvr_conn_to_ni_tn,
            { "Conn to NI/TN", "c15.tone.rcvr.conn_to_ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_timeout_device_id,
            { "Device ID", "c15.tone.timeout.device_id",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_timeout_service_pm,
            { "Service PM", "c15.tone.timeout.service_pm",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_timeout_service_ni,
            { "Service NI", "c15.tone.timeout.service_ni",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_timeout_service_tn,
            { "Service TN", "c15.tone.timeout.service_tn",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_timeout_service_ni_tn,
            { "Service NI/TN", "c15.tone.timeout.service_ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_timeout_gw_provided,
            { "GW Provided", "c15.tone.timeout.gw_provided",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_timeout_gw_service_tone_type_or_from_ni,
            { "GW Service Tone Type or From NI", "c15.tone.timeout.gw_service_tone_type_or_from_ni",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_tone_control_device_id,
            { "Device ID", "c15.tone.tone_control.device_id",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_tone_control_tone_type,
            { "Tone Type", "c15.tone.tone_control.tone_type",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &tone_types_ext,
            0x0, NULL, HFILL}
        },

        { &hf_c15ch_tone_cpm_loop_type,
            { "Loop Type", "c15.tone.cpm.loop_type",
            FT_UINT8, BASE_DEC,
            VALS( loop_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_cpm_device_id,
            { "Device ID", "c15.tone.cpm.device_id",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &device_types_ext,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_cpm_tone_type,
            { "Tone Type", "c15.tone.cpm.tone_type",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING,
            &tone_types_ext,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_tone_control,
            { "C15 Tone Control", "c15.tone.tone_control",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_give_tone,
            { "C15 Give Tone", "c15.tone.give_tone",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_opls,
            { "C15 Tone OPLS", "c15.tone.opls",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_cot_control,
            { "C15 Tone COT Control", "c15.tone.cot_control",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_cpm,
            { "C15 Tone CPM", "c15.tone.cpm",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_rcvr,
            { "C15 Tone Receiver", "c15.tone.rcvr",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_madn_ring,
            { "C15 Tone MADN Ring", "c15.tone.madn_ring",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_tone_timeout,
            { "C15 Tone Timeout", "c15.tone.timeout",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        }
    };


    static gint *ett_third_level_tone[] = {
        &ett_c15ch_third_level_tone,
        &ett_c15ch_third_level_tone_sub1
    };

       static hf_register_info hf_third_level_inc_gwe[] = {

        { &hf_c15ch_inc_gwe_reply_ip_gwe_msg_type,
            { "IP GWE Msg Type", "c15.inc_gwe.reply.ip_gwe_msg_type",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_reply_ip_gwe_stat_code,
            { "IP GWE Stat Code", "c15.inc_gwe.reply.ip_gwe_stat_code",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_reply_ip_gwe_conn_num,
            { "IP GWE Connection Number", "c15.inc_gwe.reply.ip_gwe_conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_reply_nw_mdcn_lsdp_ip,
            { "NW MDCN LSDP IP", "c15.inc_gwe.reply.nw_mdcn_lsdp_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_reply_nw_mdcn_lsdp_port,
            { "NW MDCN LSDP Port", "c15.inc_gwe.reply.nw_mdcn_lsdp_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_reply_nw_mdcn_rsdp_ip,
            { "NW MDCN RSDP IP", "c15.inc_gwe.reply.nw_mdcn_rsdp_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_reply_nw_mdcn_rsdp_port,
            { "NW MDCN RSDP Port", "c15.inc_gwe.reply.nw_mdcn_rsdp_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_bc_pgi_pbc_conn_num,
            { "PBC Connection Number", "c15.inc_gwe.bc_pgi.pbc_conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_bc_pgi_pbc_conn_type,
            { "PBC Connection Type", "c15.inc_gwe.bc_pgi.pbc_conn_type",
            FT_UINT8, BASE_DEC,
            VALS( c15_inc_gwe_bc_pgi_pbc_conn_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_bc_pgi_pbc_msg_type,
            { "PBC Message Type", "c15.inc_gwe.bc_pgi.pbc_msg_type",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_bc_pgi_bc_mode,
            { "BC Mode", "c15.inc_gwe.bc_pgi.bc_mode",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_bc_pgi_bc_pgi_sdp,
            { "BC PGI SDP", "c15.inc_gwe.bc_pgi.bc_pgi_sdp",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_bc_pgi_bc_pgi_m_port,
            { "BC PGI M Port", "c15.inc_gwe.bc_pgi.bc_pgi_m_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_bc_pgi_pbc_tst_flags,
            { "PBC TST Flags", "c15.inc_gwe.bc_pgi.pbc_tst_flags",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_mgcp_dlcx_err_code,
            { "Error Code", "c15.inc_gwe.mgcp_dlcx.err_code",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_h248_digit_ip_gwe_digit,
            { "IP GWE Digit", "c15.inc_gwe.h248_digit.ip_gwe_digit",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_h248_digit_ip_gwe_digit_method,
            { "IP GWE Digit Method", "c15.inc_gwe.h248_digit.ip_gwe_digit_method",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_voip_cot_ip_gwe_pass_code,
            { "IP GWE Digit", "c15.inc_gwe.voip_cot.ip_gwe_pass_code",
            FT_BOOLEAN, BASE_NONE,
            TFS( &c15_inc_gwe_voip_cot_ip_gwe_pass_code_types),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_notify_ip_gwe_mwi_stat,
            { "IP GWE Message Waiting Indicator Stat", "c15.inc_gwe.notify.ip_gwe_mwi_stat",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_notify_ip_gwe_digits,
            { "IP GWE Digits", "c15.inc_gwe.notify.ip_gwe_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_admn_updt_ip_gwe_med_ni,
            { "IP GWE Med NI", "c15.inc_gwe.admn_updt.ip_gwe_med_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_admn_updt_ip_gwe_med_tn,
            { "IP GWE Med TN", "c15.inc_gwe.admn_updt.ip_gwe_med_tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_admn_updt_ip_gwe_med_ni_tn,
            {"IP GWE Med NI/TN", "c15.inc_gwe.admn_updt.ip_gwe_med_ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_inc_gwe_admn_updt_ip_ns_iface,
            { "IP NS Interface", "c15.inc_gwe.admn_updt.ip_ns_iface",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_admn_updt_ip_ns_terminal,
            { "IP NS Terminal", "c15.inc_gwe.admn_updt.ip_ns_terminal",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_admn_updt_ip_gwe_new_rec_addr,
            { "IP GWE New Rec Addr", "c15.inc_gwe.admn_updt.ip_gwe_new_rec_addr",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_setup_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.cl_setup.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_setup_ip_gwe_cled_digits,
            { "IP GWE CLED Digits", "c15.inc_gwe.cl_setup.ip_gwe_cled_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_setup_ip_cl_setup_lsdp,
            { "IP CL Setup LSDP", "c15.inc_gwe.cl_setup.ip_cl_setup_lsdp",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_setup_ip_cl_setup_m_port,
            { "IP CL Setup M Port", "c15.inc_gwe.cl_setup.ip_cl_setup_m_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
                { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_sua_hndl,
            { "IP GWE SipUserAgent Handle", "c15.iinc_gwe.ptrk_setup.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_cled_digits,
            { "IP GWE CLED Digits", "c15.iinc_gwe.ptrk_setup.ip_gwe_cled_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_cl_setup_lsdp,
            { "IP CL SETUP LSDP", "c15.iinc_gwe.ptrk_setup.ip_cl_setup_lsdp",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_cl_setup_m_port,
            { "IP CL SETUP M Port", "c15.iinc_gwe.ptrk_setup.ip_cl_setup_m_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clid_pri,
            { "IP GWE CLID PRI", "c15.iinc_gwe.ptrk_setup.ip_gwe_clid_pri",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clng_digits,
            { "IP GWE CLNG Digits", "c15.iinc_gwe.ptrk_setup.ip_gwe_clng_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clng_ton,
            { "IP GWE CLNG TON", "c15.iinc_gwe.ptrk_setup.ip_gwe_clng_ton",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_clng_np,
            { "IP GWE CLNG NP", "c15.iinc_gwe.ptrk_setup.ip_gwe_clng_np",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_alert_info,
            { "IP GWE Alert Info", "c15.iinc_gwe.ptrk_setup.ip_gwe_alert_info",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_redir_digits,
            { "IP GWE REDIR Digits", "c15.iinc_gwe.ptrk_setup.ip_gwe_redir_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_redir_ton,
            { "IP GWE REDIR TON", "c15.iinc_gwe.ptrk_setup.ip_gwe_redir_ton",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_redir_np,
            { "IP GWE REDIR NP", "c15.iinc_gwe.ptrk_setup.ip_gwe_redir_np",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_ocn_digits,
            { "IP GWE OCN Digits", "c15.iinc_gwe.ptrk_setup.ip_gwe_ocn_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_chrg_digits,
            { "IP GWE CHRG Digits", "c15.iinc_gwe.ptrk_setup.ip_gwe_chrg_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_chrg_noa,
            { "IP GWE CHRG noa", "c15.iinc_gwe.ptrk_setup.ip_gwe_chrg_noa",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_chrg_npi,
            { "IP GWE CHRG NPI", "c15.iinc_gwe.ptrk_setup.ip_gwe_chrg_npi",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_npdi,
            { "IP GWE NPDI", "c15.iinc_gwe.ptrk_setup.ip_gwe_npdi",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_rn_digits,
            { "IP GWE RN Digits", "c15.iinc_gwe.ptrk_setup.ip_gwe_rn_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_ip_gwe_cic_digits,
            { "IP GWE CIC Digits", "c15.iinc_gwe.ptrk_setup.ip_gwe_cic_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup_encap_isup,
            { "Encapsulated ISUP", "c15.iinc_gwe.ptrk_setup.encap_isup",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_prog_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.cl_prog.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_prog_ip_gwe_conn_num,
            { "IP GWE Connection Number", "c15.inc_gwe.cl_prog.ip_gwe_conn_num",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_prog_ip_cl_prog_lsdp,
            { "IP CL Prog LSDP", "c15.inc_gwe.cl_prog.ip_cl_prog_lsdp",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_prog_ip_cl_prog_m_port,
            { "IP CL Prog M Port", "c15.inc_gwe.cl_prog.ip_cl_prog_m_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_prog_ip_gwe_stat_code,
            { "IP GWE Stat Code", "c15.inc_gwe.cl_prog.ip_gwe_stat_code",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_prog_encap_isup,
            { "Encapsulated ISUP", "c15.inc_gwe.cl_prog.encap_isup",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_reply,
            { "C15 Incoming GWE Reply", "c15.inc_gwe.reply",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_bc_pgi,
            { "C15 Incoming GWE Bearer Control PGI", "c15.inc_gwe.bc_pgi",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_mgcp_dlcx,
            { "C15 Incoming GWE MGCP DLCX", "c15.inc_gwe.mgcp_dlcx",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_h248_digit,
            { "C15 Incoming GWE H248 Digit", "c15.inc_gwe.h248_digit",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_voip_cot,
            { "C15 Incoming GWE VOIP COT", "c15.inc_gwe.voip_cot",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_notify,
            { "C15 Incoming GWE Notify", "c15.inc_gwe.notify",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_admn_updt,
            { "C15 Incoming GWE Admn Update", "c15.inc_gwe.admn_updt",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_setup,
            { "C15 Incoming GWE CL Setup", "c15.inc_gwe.cl_setup",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ptrk_setup,
            { "C15 Incoming GWE Packet Trunk Setup", "c15.inc_gwe.ptrk_setup",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_prog,
            { "C15 Incoming GWE CL Prog", "c15.inc_gwe.cl_prog",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_ans_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.cl_ans.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_ans_ip_gwe_conn_num,
            { "IP GWE Connection Number", "c15.inc_gwe.cl_ans.ip_gwe_conn_num",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_ans_ip_cl_ans_lsdp,
            { "IP CL Prog LSDP", "c15.inc_gwe.cl_ans.ip_cl_ans_lsdp",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_ans_ip_cl_ans_m_port,
            { "IP CL Prog M Port", "c15.inc_gwe.cl_ans.ip_cl_ans_m_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_ans_encap_isup,
            { "Encapsulated ISUP", "c15.inc_gwe.cl_ans.encap_isup",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL},
        },
        { &hf_c15ch_inc_gwe_cl_ans,
            { "C15 Incoming GWE CL Ans", "c15.inc_gwe.cl_ans",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL},
        },
        { &hf_c15ch_inc_gwe_cl_rel_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.cl_rel.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_rel_ip_gwe_conn_num,
            { "IP GWE Connection Number", "c15.inc_gwe.cl_rel.ip_gwe_conn_num",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_rel_ip_gwe_stat_code,
            { "IP GWE Stat Code", "c15.inc_gwe.cl_rel.ip_gwe_stat_code",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_rel_encap_isup,
            { "Encapsulated ISUP", "c15.inc_gwe.cl_rel.encap_isup",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL},
        },
        { &hf_c15ch_inc_gwe_cl_rel,
            { "C15 Incoming GWE CL Release", "c15.inc_gwe.cl_rel",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL},
        },
        { &hf_c15ch_inc_gwe_ntwk_mod_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.ntwk_mod.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ntwk_mod_ip_gwe_conn_num,
            { "IP GWE Connection Number", "c15.inc_gwe.ntwk_mod.ip_gwe_conn_num",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_lsdp,
            { "IP Network Mod LSDP", "c15.inc_gwe.ntwk_mod.ip_ntwk_mod_lsdp",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_l_m_port,
            { "IP Network Mod L M PORT", "c15.inc_gwe.ntwk_mod.ip_ntwk_mod_l_m_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_rsdp,
            { "IP Network Mod RSDP", "c15.inc_gwe.ntwk_mod.ip_ntwk_mod_rsdp",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ntwk_mod_ip_ntwk_mod_r_m_port,
            { "IP Network Mod R M PORT", "c15.inc_gwe.ntwk_mod.ip_ntwk_mod_r_m_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ntwk_mod_ip_gwe_stat_code,
            { "IP GWE Stat Code", "c15.inc_gwe.ntwk_mod.ip_gwe_stat_code",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_ntwk_mod,
            { "C15 Incoming GWE Network Mod", "c15.inc_gwe.ntwk_mod",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_rv_avail_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.rv_avail.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_rv_avail_ip_gwe_conn_num,
            { "IP GWE Connection Number", "c15.inc_gwe.rv_avail.ip_gwe_conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_rv_avail_ip_gwe_info_len,
            { "IP GWE Info Length", "c15.inc_gwe.rv_avail.ip_gwe_info_len",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_rv_avail,
            { "C15 Incoming GWE RV Avail", "c15.inc_gwe.rv_avail",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_redir_ip_gwe_sua_hndl,
            { "IP GWE SipUserAgent Handle", "c15.inc_gwe.cl_redir.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_redir_ip_gwe_conn_num,
            { "IP GWE Connection Number", "c15.inc_gwe.cl_redir.ip_gwe_conn_num",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_redir_ip_gwe_redir_digits,
            { "IP GWE Redir Digits", "c15.inc_gwe.cl_redir.ip_gwe_redir_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_redir,
            { "C15 Incoming GWE CL Redir", "c15.inc_gwe.cl_redir",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_refer_ip_gwe_sua_hndl,
            { "IP GWE SipUserAgent Handle", "c15.inc_gwe.cl_refer.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_refer_ip_gwe_conn_num,
            { "IP GWE Connection Number", "c15.inc_gwe.cl_refer.ip_gwe_conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_digits,
            { "IP GWE TRGT Digits", "c15.inc_gwe.cl_refer.ip_gwe_trgt_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_tn,
            { "IP GWE TRGT TN", "c15.inc_gwe.cl_refer.ip_gwe_trgt_tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_ni,
            { "IP GWE TRGT NI", "c15.inc_gwe.cl_refer.ip_gwe_trgt_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_cl_refer_ip_gwe_trgt_ni_tn,
            {"IP GWE TRGT NI/TN", "c15.inc_gwe.cl_refer.ip_gwe_trgt_tn_ni",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_inc_gwe_cl_refer,
            {"C15 Incoming GWE CL Refer", "c15.inc_gwe.cl_refer",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_inc_gwe_chg_hndl_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.chg_hndl.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_chg_hndl_ip_gwe_new_hndl,
            { "IP GWE Message New Sip User Agent Handle", "c15.inc_gwe.chg_hndl.ip_gwe_new_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_chg_hndl,
            { "C15 Incoming GWE Change Handle", "c15.inc_gwe.chg_hndl",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.subs_chg_hndl.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_new_hndl,
            { "IP GWE Message New Sip User Agent Handle", "c15.inc_gwe.subs_chg_hndl.ip_gwe_new_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_med_ni,
            { "IP GWE Med NI", "c15.inc_gwe.subs_chg_hndl.ip_gwe_med_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_med_tn,
            { "IP GWE Med TN", "c15.inc_gwe.subs_chg_hndl.ip_gwe_med_TN",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_subs_chg_hndl_ip_gwe_med_ni_tn,
            {"IP GWE Med NI/TN", "c15.inc_gwe.subs_chg_hndl.ip_gwe_med_ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_inc_gwe_subs_chg_hndl,
            {"C15 Incoming GWE Subscription Change Handle", "c15.inc_gwe.subs_chg_hndl",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_inc_gwe_info_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.info.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_info_ip_gwe_info_type,
            { "IP GWE Info Type", "c15.inc_gwe.info.ip_gwe_info_type",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_info_ip_gwe_info_digit,
            { "IP GWE Info Digit", "c15.inc_gwe.info.ip_gwe_info_digit",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_info_encap_isup_msg_type,
            { "IP GWE Encapsulated ISUP Message Type", "c15.inc_gwe.info.encap_isup_msg_type",
            FT_UINT8, BASE_DEC,
            VALS( c15ch_inc_gwe_info_encap_isup_msg_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_info,
            { "C15 Incoming GWE Info", "c15.inc_gwe.info",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_inv_repl_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.inv_repl.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_inv_repl_ip_gwe_conn_num,
            { "IP GWE Connection Number", "c15.inc_gwe.inv_repl.ip_gwe_conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_inv_repl_ip_inv_repl_rsdp_ip,
            { "IP Inv Repl RSDP IP", "c15.inc_gwe.inv_repl.ip_gwe_inv_repl_rsdp_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_inv_repl_ip_inv_repl_rsdp_port,
            { "IP Inv Repl RSDP Port", "c15.inc_gwe.inv_repl.ip_gwe_inv_repl_rsdp_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_inv_repl,
            { "C15 Incoming GWE Inv Repl", "c15.inc_gwe.inv_repl",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_admn_dn_ip_gwe_sua_hndl,
            { "IP GWE SipUserAgent Handle", "c15.inc_gwe.admn_dn.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_admn_dn_ip_gwe_digits,
            { "IP GWE Digits", "c15.inc_gwe.admn_dn.ip_gwe_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_admn_dn,
            { "C15 Incoming GWE Admn DN", "c15.inc_gwe.admn_dn",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_reply_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.sua_reply.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_reply_ip_gwe_msg_type,
            { "IP GWE Message Type", "c15.inc_gwe.sua_reply.ip_gwe_msg_type",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_reply_ip_gwe_stat_code,
            { "IP GWE Stat Code", "c15.inc_gwe.sua_reply.ip_gwe_stat_code",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_reply_ip_gwe_conn_num,
            { "IP GWE Connection Number", "c15.inc_gwe.sua_reply.ip_gwe_conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_reply_nw_mdcn_lsdp_ip,
            { "NW MDCN LSDP IP", "c15.inc_gwe.sua_reply.nw_mdcn_lsdp_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_reply_nw_mdcn_lsdp_port,
            { "NW MDCN LSDP Port", "c15.inc_gwe.sua_reply.nw_mdcn_lsdp_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_reply_nw_mdcn_rsdp_ip,
            { "NW MDCN RSDP IP", "c15.inc_gwe.sua_reply.nw_mdcn_rsdp_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_reply_nw_mdcn_rsdp_port,
            { "NW MDCN RSDP Port", "c15.inc_gwe.sua_reply.nw_mdcn_rsdp_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_reply,
            { "C15 Incoming GWE Sip User Agent Reply", "c15.inc_gwe.sua_reply",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_hndl_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.sua_hndl.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_sua_hndl,
            { "C15 Incoming GWE Sip User Agent Handle", "c15.inc_gwe.sua_hndl",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_tgh_stat_ip_gwe_sua_hndl,
            { "IP GWE Message Sip User Agent Handle", "c15.inc_gwe.sua_tgh_stat.ip_gwe_sua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_tgh_stat_ip_gwe_tgh_state,
            { "IP GWE TGH State", "c15.inc_gwe.sua_tgh_stat.ip_gwe_tgh_state",
            FT_UINT8, BASE_HEX,
            VALS( tgh_state_types ),
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_inc_gwe_tgh_stat,
            { "C15 Incoming GWE Sipu User Agent TGH State", "c15.inc_gwe.sua_tgh_stat",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        }
    };

    static gint *ett_third_level_inc_gwe[] = {
        &ett_c15ch_third_level_inc_gwe,
        &ett_c15ch_third_level_inc_gwe_sub1
    };

    static hf_register_info hf_third_level_out_gwe[] = {
       /* TODO */
        { &hf_c15ch_out_gwe_digit_scan_voip_dgmp_override,
            { "VOIP DGMP Override", "c15.out_gwe.digit_scan.voip_dgmp_override",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_digit_scan_actv_dgmp,
            { "Actv DGMP", "c15.out_gwe.digit_scan.actv_dgmp",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_digit_scan_op_gwe_digit_scan_tone,
            { "OP GWE Digit Scan Tone", "c15.out_gwe.digit_scan.op_gwe_digit_scan_tone",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_digit_scan_op_gwe_tone_type,
            { "OP GWE Digit Tone Type", "c15.out_gwe.digit_scan.op_gwe_digit_tone_type",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_digit_scan_op_gwe_tone_to,
            { "OP GWE Digit Tone To", "c15.out_gwe.digit_scan.op_gwe_digit_tone_to",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_digit_scan_op_gwe_digit_flash,
            { "OP GWE Digit Flash", "c15.out_gwe.digit_scan.op_gwe_digit_flash",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_digit_scan,
            { "C15 Outgoing GWE Digit Scan", "c15.out_gwe.digit_scan",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_conn_num_out_gwe_conn_num,
            { "Outgoing GWE Connection Number", "c15.out_gwe.conn_num.out_gwe_conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_conn_num,
            { "C15 Outgoing GWE Connection Number", "c15.out_gwe.conn_num",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_mk_conn_conn_num,
            { "Connection Number", "c15.out_gwe.mk_conn.conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_mk_conn_op_mk_conn_rsdp_ip,
            { "OP MK Conn RSDP IP", "c15.out_gwe.mk_conn.op_mk_conn_rsdp_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_mk_conn_op_mk_conn_rsdp_port,
            { "OP MK Conn RSDP Port", "c15.out_gwe.mk_conn.op_mk_conn_rsdp_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_mk_conn,
            { "C15 Outgoing GWE Mk Connection", "c15.out_gwe.mk_conn",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_md_conn_conn_num,
            { "Connection Number", "c15.out_gwe.md_conn.conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_md_conn_status_code,
            { "Status Code", "c15.out_gwe.md_conn.status_code",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_md_conn_op_gwe_mode,
            { "OP GWE Mode", "c15.out_gwe.md_conn.op_md_conn_op_gwe_mode",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_md_conn,
            { "C15 Outgoing GWE MD Connection", "c15.out_gwe.md_conn",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_ans_conn_num,
            { "Connection Number", "c15.out_gwe.call_ans.conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_ans_op_cl_ans_rsdp_ip,
            { "OP Call Answer RSDP IP", "c15.out_gwe.call_ans.op_cl_ans_rsdp_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_ans_op_cl_ans_rsdp_port,
            { "OP Call Answer RSDP Port", "c15.out_gwe.call_ans.op_cl_ans_rsdp_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_ans_encap_isup,
            { "Encapsulated ISUP", "c15.out_gwe.call_ans.encap_isup",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_ans,
            { "C15 Outgoing GWE Call Answer", "c15.out_gwe.call_ans",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_conn_num,
            { "Connection Number", "c15.out_gwe.call_setup.conn_num",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_op_cl_ans_rsdp_ip,
            { "OP Cl Ans RSDP IP", "c15.out_gwe.call_setup.op_cl_ans_rsdp_ip",
            FT_IPv4, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_op_cl_ans_rsdp_port,
            { "OP Cl Ans RSDP Port", "c15.out_gwe.call_setup.op_cl_ans_rsdp_port",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_op_gwe_redir_digits,
            { "OP GWE Redir Digits", "c15.out_gwe.call_setup.op_gwe_redir_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_op_gwe_rdir_ton,
            { "OP GWE Redirect TON", "c15.out_gwe.call_setup.op_gwe_rdir_ton",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_op_gwe_rdir_np,
            { "OP GWE Redirect NP", "c15.out_gwe.call_setup.op_gwe_rdir_np",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_op_gwe_ocn_digits,
            { "OP GWE OCN Digits", "c15.out_gwe.call_setup.op_gwe_ocn_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_op_gwe_chrg_digits,
            { "OP GWE CHRG Digits", "c15.out_gwe.call_setup.op_gwe_chrg_digits",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_op_gwe_chrg_noa,
            { "OP GWE CHRG NOA", "c15.out_gwe.call_setup.op_gwe_chrg_noa",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_op_gwe_chrg_npi,
            { "OP GWE CHRG NPI", "c15.out_gwe.call_setup.op_gwe_chrg_npi",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup_encap_isup,
            { "Encapsulated ISUP", "c15.out_gwe.call_setup.encap_isup",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_setup,
            { "C15 Outgoing GWE Call Setup", "c15.out_gwe.call_setup",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_prog_conn_num,
            { "Connection Number", "c15.out_gwe.call_prog.conn_num",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_prog_op_gwe_stat_code,
            { "OP GWE Stat Code", "c15.out_gwe.call_prog.op_gwe_stat_code",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_prog_encap_isup,
            { "Encapsulated ISUP", "c15.out_gwe.call_prog.encap_isup",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_prog,
            { "C15 Outgoing GWE Call Prog", "c15.out_gwe.call_prog",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_notify_op_gwe_mwi,
            { "OP GWE MWI", "c15.out_gwe.call_notify.op_gwe_mwi",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_notify_status_code,
            { "Status Code", "c15.out_gwe.call_notify.status_code",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_notify,
            { "C15 Outgoing GWE Call Notify", "c15.out_gwe.call_notify",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_rel_status_code,
            { "Status Code", "c15.out_gwe.call_rel.status_code",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_rel_encap_isup,
            { "Encapsulated ISUP", "c15.out_gwe.call_rel.encap_isup",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_call_rel,
            { "C15 Outgoing GWE Call Release", "c15.out_gwe.call_rel",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_update_ni_tn_ni,
            { "NI", "c15.out_gwe.update_ni_tn.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_update_ni_tn_tn,
            { "TN", "c15.out_gwe.update_ni_tn.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_update_ni_tn_ni_tn,
            { "TN", "c15.out_gwe.update_ni_tn.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_update_ni_tn,
            { "C15 Outgoing GWE Update NI and TN", "c15.out_gwe.update_ni_tn",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_pcm_data_rb_ua_handle_near,
            { "RB User Agent Handle (Near)", "c15.out_gwe.pcm_data.rb_ua_handle_near",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_pcm_data_rb_ua_handle_far,
            { "RB User Agent Handle (Far)", "c15.out_gwe.pcm_data.rb_ua_handle_far",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_pcm_data,
            { "C15 Outgoing GWE PCM Data", "c15.out_gwe.pcm_data",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_blf_data_rb_ua_handle,
            { "RB User Agent Handle", "c15.out_gwe.blf_data.rb_ua_handle",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_blf_data_rb_type,
            { "RB Type", "c15.out_gwe.blf_data.rb_type",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_blf_data_med_ni,
            { "Med NI", "c15.out_gwe.blf_data.med_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_blf_data_med_tn,
            { "Med TN", "c15.out_gwe.blf_data.med_tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_blf_data_med_ni_tn,
            {"Med NI/TN", "c15.out_gwe.blf_data.med_ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_out_gwe_blf_data_rb_ni,
            { "RB NI", "c15.out_gwe.blf_data.rb_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_blf_data_rb_tn,
            { "RB TN", "c15.out_gwe.blf_data.rb_tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_blf_data_rb_ni_tn,
            {"RB NI/TN", "c15.out_gwe.blf_data.rb_ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_out_gwe_blf_data,
            {"C15 Outgoing GWE BLF Data", "c15.out_gwe.blf_data",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL }
        },
       { &hf_c15ch_out_gwe_out_cot_ni,
            { "NI", "c15.out_gwe.out_cot.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_out_cot_tn,
            { "TN", "c15.out_gwe.out_cot.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_out_cot_ni_tn,
            {"NI/TN", "c15.out_gwe.out_cot.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_out_gwe_out_cot,
            {"C15 Outgoing GWE Out COT", "c15.out_gwe.out_cot",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_out_gwe_ring_line_op_gwe_display,
            { "OP GWE Display", "c15.out_gwe.ring_line.op_gwe_display",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_ring_line_op_gwe_display_chars,
            { "OP GWE Display Chars", "c15.out_gwe.ring_line.op_gwe_display_chars",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_ring_line,
            { "C15 Outgoing GWE Ring Line", "c15.out_gwe.ring_line",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_audit_conn_ni,
            { "NI", "c15.out_gwe.audit_conn.ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_audit_conn_tn,
            { "TN", "c15.out_gwe.audit_conn.tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_audit_conn_ni_tn,
            {"NI/TN", "c15.out_gwe.audit_conn.ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_out_gwe_audit_conn_context,
            { "Context", "c15.out_gwe.audit_conn.context",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_audit_conn,
            { "C15 Outgoing GWE Audit Connection", "c15.out_gwe.audit_conn",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sac_sub_valid_op_gwe_subs_valid,
            { "OP GWE Subs Valid", "c15.out_gwe.sac_sub_valid.op_gwe_subs_valid",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sac_sub_valid_op_gwe_num_list_items,
            { "OP GWE Num List Items", "c15.out_gwe.sac_sub_valid.op_gwe_num_list_items",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sac_sub_valid,
            { "C15 Outgoing GWE SAC Subscription Valid", "c15.out_gwe.sac_sub_valid",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sac_notify_op_gwe_blf_state,
            { "OP GWE BLF State", "c15.out_gwe.sac_notify.op_gwe_blf_state",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sac_notify_op_gwe_subs_state,
            { "OP GWE Subscription State", "c15.out_gwe.sac_notify.op_gwe_subs_state",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sac_notify,
            { "C15 Outgoing GWE SAC Notify", "c15.out_gwe.sac_notify",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sac_list_entry_op_gwe_med_uri,
            { "OP GWE Med URI", "c15.out_gwe.sac_list_entry.op_gwe_med_uri",
            FT_STRINGZ, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sac_list_entry,
            { "C15 Outgoing GWE SAC List Entry", "c15.out_gwe.sac_list_entry",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_rv_subs_data_rb_fe_ni,
            { "RB Fe NI", "c15.out_gwe.rv_subs_data.rb_fe_ni",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_rv_subs_data_rb_fe_tn,
            { "RB Fe TN", "c15.out_gwe.rv_subs_data.rb_fe_tn",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_rv_subs_data_rb_fe_ni_tn,
            {"Rb Fe NI/TN", "c15.out_gwe.rv_subs_data.rb_fe_ni_tn",
            FT_UINT64, BASE_HEX,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_out_gwe_rv_subs_data,
            {"C15 Outgoing GWE Radvision Subscription Data", "c15.out_gwe.rv_subs_data",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL }
        },
        { &hf_c15ch_out_gwe_update_rec_addr_op_new_rec_addr,
            { "OP New Rec Addr", "c15.out_gwe.update_rec_addr.op_new_rec_addr",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_update_rec_addr,
            { "C15 Outgoing GWE Update Rec Address", "c15.out_gwe.update_rec_addr",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_del_subs_ua_op_sip_ua_hndl,
            { "OP SIP UA Handle", "c15.out_gwe.del_subs_ua.op_sip_ua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_del_subs_ua,
            { "C15 Outgoing GWE Delete Subscription User Agent", "c15.out_gwe.del_subs_ua",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_line_sprvsn_op_gwe_ofhk_event,
            { "OP GWE Off-Hook Event", "c15.out_gwe.line_sprvsn.op_gwe_ofhk_event",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_line_sprvsn_op_gwe_onhk_event,
            { "OP GWE On-Hook Event", "c15.out_gwe.line_sprvsn.op_gwe_onhk_event",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_line_sprvsn_op_gwe_flhk_event,
            { "OP GWE Flash-Hook Event", "c15.out_gwe.line_sprvsn.op_gwe_flhk_event",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_line_sprvsn,
            { "C15 Outgoing GWE Line SPRVSN", "c15.out_gwe.line_sprvsn",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
       { &hf_c15ch_out_gwe_sip_info_op_gwe_sip_info_type,
            { "OP GWE SIP Info Type", "c15.out_gwe.sip_info.op_gwe_sip_info_type",
            FT_UINT8, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sip_info_op_gwe_sip_info,
            { "OP GWE SIP Info", "c15.out_gwe.sip_info.op_gwe_sip_info",
            FT_UINT32, BASE_DEC,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sip_info,
            { "C15 Outgoing GWE SIP Info", "c15.out_gwe.sip_info",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sip_refer_op_gwe_refer_ua_hndl,
            { "OP GWE Refer User Agent Handle", "c15.out_gwe.sip_refer.op_gwe_refer_ua_hndl",
            FT_UINT32, BASE_HEX,
            NULL,
            0x0, NULL, HFILL}
        },
        { &hf_c15ch_out_gwe_sip_refer,
            { "C15 Outgoing GWE SIP Refer", "c15.out_gwe.sip_refer",
            FT_PROTOCOL, BASE_NONE,
            NULL,
            0x0, NULL, HFILL}
        }
    };

    static gint *ett_third_level_out_gwe[] = {
        &ett_c15ch_third_level_out_gwe,
        &ett_c15ch_third_level_out_gwe_sub1,
        &ett_c15ch_third_level_out_gwe_sub2
    };
    /* protocols */

    /* first level: Call History Common Header */
    proto_c15ch = proto_register_protocol(
        "C15 Call History Common Header Protocol",
        "C15.ch",
        "c15.ch"
        );
    proto_register_field_array(proto_c15ch, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* second level dissector */
    proto_c15ch_second_level = proto_register_protocol(
        "C15 Call History Protocol",
        "C15",
        "c15"
        );
    proto_register_field_array(proto_c15ch_second_level, hf_second_level, array_length(hf_second_level));
    proto_register_subtree_array(ett_second_level, array_length(ett_second_level));
    c15ch_dissector_table = register_dissector_table("c15", "C15", proto_c15ch, FT_UINT32, BASE_DEC);

    /* third level */
    /* tone */
        proto_c15ch_third_level_tone = proto_register_protocol(
        "C15 Tone",
        "C15.TONE",
        "c15.tone"
        );
    proto_register_field_array(proto_c15ch_third_level_tone, hf_third_level_tone, array_length(hf_third_level_tone));
    proto_register_subtree_array(ett_third_level_tone, array_length(ett_third_level_tone));
    c15ch_tone_dissector_table = register_dissector_table("c15.tone", "C15.TONE", proto_c15ch_third_level_tone, FT_UINT32, BASE_DEC);

    /* inc gwe */
    proto_c15ch_third_level_inc_gwe = proto_register_protocol(
        "C15 Incoming GWE",
        "C15.INC_GWE",
        "c15.inc_gwe"
        );
    proto_register_field_array(proto_c15ch_third_level_inc_gwe, hf_third_level_inc_gwe, array_length(hf_third_level_inc_gwe));
    proto_register_subtree_array(ett_third_level_inc_gwe, array_length(ett_third_level_inc_gwe));
    c15ch_inc_gwe_dissector_table = register_dissector_table("c15.inc_gwe", "C15.INC_GWE", proto_c15ch_third_level_inc_gwe, FT_UINT32, BASE_DEC);

    /* out gwe */
    proto_c15ch_third_level_out_gwe = proto_register_protocol(
        "C15 Outgoing GWE",
        "C15.out_gwe",
        "c15.out_gwe"
        );
    proto_register_field_array(proto_c15ch_third_level_out_gwe, hf_third_level_out_gwe, array_length(hf_third_level_out_gwe));
    proto_register_subtree_array(ett_third_level_out_gwe, array_length(ett_third_level_out_gwe));
    c15ch_out_gwe_dissector_table = register_dissector_table("c15.out_gwe", "C15.out_gwe", proto_c15ch_third_level_out_gwe, FT_UINT32, BASE_DEC);
}


/* handoff */
/* heartbeat dissector */
void proto_reg_handoff_c15ch_hbeat(void)
{
    static dissector_handle_t c15ch_hbeat_handle;
    c15ch_hbeat_handle = create_dissector_handle(dissect_c15ch_hbeat, proto_c15ch_hbeat);
    dissector_add_uint("ethertype", ETHERTYPE_C15_HBEAT, c15ch_hbeat_handle);
}

/* c15 non-heartbeat dissectors : first-level, second-level, and third-level */
void proto_reg_handoff_c15ch(void)
{
    dissector_handle_t c15ch_handle;
    dissector_handle_t c15ch_second_level_handle;
    dissector_handle_t c15ch_third_level_handle;
    /* first level */
    c15ch_handle = create_dissector_handle(dissect_c15ch, proto_c15ch);
    dissector_add_uint("ethertype", ETHERTYPE_C15_CH, c15ch_handle);

    /* second_level */
    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_cp_state_ch, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_CP_STATE_CH, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_cp_event, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_CP_EVENT, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_isup, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_ISUP, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_nitnxlate, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_NITN_XLATE, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_route, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_ROUTE, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_sccp, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_SCCP, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_orig, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_CP_ORIG, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_conn, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_CONN, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_ntwk_conn, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_NTWK_CONN, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_mkbrk, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_MK_BRK, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_pathfind, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_PATH_FIND, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_pathidle, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_PATH_IDLE, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_dest_digits, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_DEST_DIGITS, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_twc_rswch, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_TWC_RSWCH, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_srcedest, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_SRCE_DEST, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_INC_GWE, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_out_gwe, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_OUT_GWE, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_outgwebc, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_OUT_GWE_BC, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_q931, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_Q931, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_ama, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_AMA, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_qos, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_QOS, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_echo_cancel, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_ECHO_CANCEL, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_tone, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_TONE, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_encap_isup, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_ENCAP_ISUP, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_tcap, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_TCAP, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_clli, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_CLLI, c15ch_second_level_handle);

    c15ch_second_level_handle = create_dissector_handle(dissect_c15ch_c15_info, proto_c15ch_second_level);
    dissector_add_uint("c15", C15_INFO, c15ch_second_level_handle);

    /* third level */
    /* tone */
    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_tone_cot_control, proto_c15ch_third_level_tone);
    dissector_add_uint("c15.tone", C15_TONE_COT, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_tone_cpm, proto_c15ch_third_level_tone);
    dissector_add_uint("c15.tone", C15_TONE_CPM, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_tone_give_tone, proto_c15ch_third_level_tone);
    dissector_add_uint("c15.tone", C15_TONE_GIVE_TONE, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_tone_madn_ring, proto_c15ch_third_level_tone);
    dissector_add_uint("c15.tone", C15_TONE_MADN_RING, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_tone_opls, proto_c15ch_third_level_tone);
    dissector_add_uint("c15.tone", C15_TONE_OPLS, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_tone_rcvr, proto_c15ch_third_level_tone);
    dissector_add_uint("c15.tone", C15_TONE_RCVR, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_tone_timeout, proto_c15ch_third_level_tone);
    dissector_add_uint("c15.tone", C15_TONE_TIMEOUT, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_tone_tone_control, proto_c15ch_third_level_tone);
    dissector_add_uint("c15.tone", C15_TONE_TONE_CONTROL, c15ch_third_level_handle);

    /* inc gwe */
    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_reply, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_REPLY, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_bc_pgi, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_BC_PGI, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_mgcp_dlcx, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_MGCP_DLCX, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_h248_digit, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_H248_DIGIT, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_voip_cot, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_VOIP_COT, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_notify, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_NOTIFY, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_admn_updt, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_ADMN_UPDT_REC, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_cl_setup, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_CL_SETUP, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_ptrk_setup, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_PTRK_SETUP, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_cl_prog, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_CL_PROG, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_cl_ans, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_CL_ANS, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_cl_rel, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_CL_REL, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_ntwk_mod, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_NTWK_MOD, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_rv_avail, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_RV_AVAIL, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_cl_redir, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_CL_REDIR, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_cl_refer, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_CL_REFER, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_chg_hndl, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_CHG_HDL, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_subs_chg_hndl, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_SUBS_CHG_HDL, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_info, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_INFO, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_inv_repl, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_INV_REPL, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_admn_dn, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_ADMN_DN, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_sua_reply, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_SUA_REPLY, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_sua_hndl, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_SUA_HNDL, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_inc_gwe_tgh_stat, proto_c15ch_third_level_inc_gwe);
    dissector_add_uint("c15.inc_gwe", C15_INC_GWE_SUA_TGH_STAT, c15ch_third_level_handle);

    /* out gwe */
    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_digit_scan, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_DIGIT_SCAN, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_conn_num, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_CONN_NUM, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_mk_conn, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_MK_CONN, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_md_conn, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_MD_CONN, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_call_ans, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_CALL_ANS, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_call_setup, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_CALL_SETUP, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_call_prog, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_CALL_PROG, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_call_notify, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_CALL_NOTIFY, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_call_rel, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_CALL_REL, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_update_ni_tn, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_UPDT_NI_TN, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_pcm_data, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_PCM_DATA, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_blf_data, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_BLF_DATA, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_out_cot, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_COT, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_ring_line, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_RING_LINE, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_audit_conn, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_AUDIT_CONN, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_sac_sub_valid, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_SAC_SUB_VALID, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_sac_notify, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_SAC_NOTIFY, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_sac_list_entry, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_SAC_LIST_ENTRY, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_rv_subs_data, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_RV_SUBS_DATA, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_update_rec_addr, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_UPDT_REC_ADDR, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_del_subs_ua, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_DEL_SUBS_UA, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_line_sprvsn, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_LINE_SPRVSN, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_sip_info, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_SIP_INFO, c15ch_third_level_handle);

    c15ch_third_level_handle = create_dissector_handle(dissect_c15ch_out_gwe_sip_refer, proto_c15ch_third_level_out_gwe);
    dissector_add_uint("c15.out_gwe", C15_OUT_GWE_SIP_REFER, c15ch_third_level_handle);

    /* find external dissectors */
    general_isup_handle = find_dissector_add_dependency("isup", proto_c15ch);
    general_sccp_handle = find_dissector_add_dependency("sccp", proto_c15ch);
    general_q931_handle = find_dissector_add_dependency("q931", proto_c15ch);

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
