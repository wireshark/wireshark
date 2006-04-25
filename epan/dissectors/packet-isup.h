/* packet-isup.h
 *
 * $Id$
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>,
 * In association with Telos Technology Inc.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define	ISUP_MAX_NUM_MESSAGE_TYPES	256

typedef struct _isup_tap_rec_t {
    guint8		message_type;
    /* added for VoIP calls analysis, see gtk/voip_calls.c*/
    gchar           *called_number;
    gchar           *calling_number;
    guint8			cause_value;
} isup_tap_rec_t;


/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a 
 * libethereal.dll, we need a special declaration.
 */
ETH_VAR_IMPORT const value_string isup_message_type_value[];
ETH_VAR_IMPORT const value_string isup_message_type_value_acro[];
ETH_VAR_IMPORT const value_string q850_cause_code_vals[];
/*
 * Export some definitions and value_string tables for other dissectors
 */

/* Definition of Parameter Types */
#define PARAM_TYPE_END_OF_OPT_PARAMS      0
#define PARAM_TYPE_CALL_REF               1
#define PARAM_TYPE_TRANSM_MEDIUM_REQU     2
#define PARAM_TYPE_ACC_TRANSP             3
#define PARAM_TYPE_CALLED_PARTY_NR        4
#define PARAM_TYPE_SUBSQT_NR              5
#define PARAM_TYPE_NATURE_OF_CONN_IND     6
#define PARAM_TYPE_FORW_CALL_IND          7
#define PARAM_TYPE_OPT_FORW_CALL_IND      8
#define PARAM_TYPE_CALLING_PRTY_CATEG     9
#define PARAM_TYPE_CALLING_PARTY_NR      10
#define PARAM_TYPE_REDIRECTING_NR        11
#define PARAM_TYPE_REDIRECTION_NR        12
#define PARAM_TYPE_CONNECTION_REQ        13
#define PARAM_TYPE_INFO_REQ_IND          14
#define PARAM_TYPE_INFO_IND              15
#define PARAM_TYPE_CONTINUITY_IND        16
#define PARAM_TYPE_BACKW_CALL_IND        17
#define PARAM_TYPE_CAUSE_INDICATORS      18
#define PARAM_TYPE_REDIRECTION_INFO      19
#define PARAM_TYPE_CIRC_GRP_SV_MSG_TYPE  21
#define PARAM_TYPE_RANGE_AND_STATUS      22
#define PARAM_TYPE_FACILITY_IND          24
#define PARAM_TYPE_CLSD_USR_GRP_ILOCK_CD 26
#define PARAM_TYPE_USER_SERVICE_INFO     29
#define PARAM_TYPE_SIGNALLING_POINT_CODE 30
#define PARAM_TYPE_USER_TO_USER_INFO     32
#define PARAM_TYPE_CONNECTED_NR          33
#define PARAM_TYPE_SUSP_RESUME_IND       34
#define PARAM_TYPE_TRANSIT_NETW_SELECT   35
#define PARAM_TYPE_EVENT_INFO            36
#define PARAM_TYPE_CIRC_ASSIGN_MAP       37
#define PARAM_TYPE_CIRC_STATE_IND        38
#define PARAM_TYPE_AUTO_CONG_LEVEL       39
#define PARAM_TYPE_ORIG_CALLED_NR        40
#define PARAM_TYPE_OPT_BACKW_CALL_IND    41
#define PARAM_TYPE_USER_TO_USER_IND      42
#define PARAM_TYPE_ORIG_ISC_POINT_CODE   43
#define PARAM_TYPE_GENERIC_NOTIF_IND     44
#define PARAM_TYPE_CALL_HIST_INFO        45
#define PARAM_TYPE_ACC_DELIV_INFO        46
#define PARAM_TYPE_NETW_SPECIFIC_FACLTY  47
#define PARAM_TYPE_USER_SERVICE_INFO_PR  48
#define PARAM_TYPE_PROPAG_DELAY_COUNTER  49
#define PARAM_TYPE_REMOTE_OPERATIONS     50
#define PARAM_TYPE_SERVICE_ACTIVATION    51
#define PARAM_TYPE_USER_TELESERV_INFO    52
#define PARAM_TYPE_TRANSM_MEDIUM_USED    53
#define PARAM_TYPE_CALL_DIV_INFO         54
#define PARAM_TYPE_ECHO_CTRL_INFO        55
#define PARAM_TYPE_MSG_COMPAT_INFO       56
#define PARAM_TYPE_PARAM_COMPAT_INFO     57
#define PARAM_TYPE_MLPP_PRECEDENCE       58
#define PARAM_TYPE_MCID_REQ_IND          59
#define PARAM_TYPE_MCID_RSP_IND          60
#define PARAM_TYPE_HOP_COUNTER           61
#define PARAM_TYPE_TRANSM_MEDIUM_RQUR_PR 62
#define PARAM_TYPE_LOCATION_NR           63
#define PARAM_TYPE_REDIR_NR_RSTRCT       64
#define PARAM_TYPE_CALL_TRANS_REF        67
#define PARAM_TYPE_LOOP_PREV_IND         68
#define PARAM_TYPE_CALL_TRANS_NR         69
#define PARAM_TYPE_CCSS                  75
#define PARAM_TYPE_FORW_GVNS             76
#define PARAM_TYPE_BACKW_GVNS            77
#define PARAM_TYPE_REDIRECT_CAPAB        78
#define PARAM_TYPE_NETW_MGMT_CTRL        91
#define PARAM_TYPE_CORRELATION_ID       101
#define PARAM_TYPE_SCF_ID               102
#define PARAM_TYPE_CALL_DIV_TREAT_IND   110
#define PARAM_TYPE_CALLED_IN_NR         111
#define PARAM_TYPE_CALL_OFF_TREAT_IND   112
#define PARAM_TYPE_CHARGED_PARTY_IDENT  113
#define PARAM_TYPE_CONF_TREAT_IND       114
#define PARAM_TYPE_DISPLAY_INFO         115
#define PARAM_TYPE_UID_ACTION_IND       116
#define PARAM_TYPE_UID_CAPAB_IND        117
#define PARAM_TYPE_REDIRECT_COUNTER     119
#define PARAM_TYPE_APPLICATON_TRANS		120
#define PARAM_TYPE_COLLECT_CALL_REQ     121
#define PARAM_TYPE_GENERIC_NR           192
#define PARAM_TYPE_GENERIC_DIGITS       193

#define ANSI_ISUP_PARAM_TYPE_OPER_SERV_INF	0xC2
#define ANSI_ISUP_PARAM_TYPE_EGRESS			0xC3
#define ANSI_ISUP_PARAM_TYPE_JURISDICTION	0xC4
#define ANSI_ISUP_PARAM_TYPE_CARRIER_ID		0xC5
#define ANSI_ISUP_PARAM_TYPE_BUSINESS_GRP	0xC6
#define ANSI_ISUP_PARAM_TYPE_GENERIC_NAME	0xC7
#define ANSI_ISUP_PARAM_TYPE_NOTIF_IND		0xE1

#define ANSI_ISUP_PARAM_TYPE_CG_CHAR_IND			229
#define ANSI_ISUP_PARAM_TYPE_CVR_RESP_IND			230
#define	ANSI_ISUP_PARAM_TYPE_OUT_TRK_GRP_NM			231	
#define ANSI_ISUP_PARAM_TYPE_CI_NAME_IND			232
#define ANSI_ISUP_PARAM_CLLI_CODE					233

#define ANSI_ISUP_PARAM_ORIG_LINE_INF				0xEA
#define ANSI_ISUP_PARAM_CHRG_NO						0xEB
#define ANSI_ISUP_PARAM_SERV_CODE_IND				0xEC
#define ANSI_ISUP_PARAM_SPEC_PROC_REQ				0xED
#define ANSI_ISUP_PARAM_CARRIER_SEL_INF				0xEE
#define ANSI_ISUP_PARAM_NET_TRANS					0xEF

extern const value_string isup_parameter_type_value[]; 
extern const value_string isup_transmission_medium_requirement_value[];
extern const value_string isup_calling_partys_category_value[];

/*
 * Export dissection of some parameters
 */
void dissect_nsap(tvbuff_t *parameter_tvb,gint offset,gint len, proto_tree *parameter_tree);
void dissect_isup_called_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item);
void dissect_isup_calling_party_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item);
void dissect_isup_cause_indicators_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item);
void dissect_isup_redirection_information_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item);
void dissect_isup_original_called_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item);
void dissect_isup_redirecting_number_parameter(tvbuff_t *parameter_tvb, proto_tree *parameter_tree, proto_item *parameter_item);

extern int dissect_codec_mode(proto_tree *tree, tvbuff_t *tvb, int offset, int len);
