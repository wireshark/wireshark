/* packet-gtp.c
 * 
 * Routines for GTP dissection
 * Copyright 2001, Michal Melerowicz <michal.melerowicz@nokia.com>
 *                 Nicolas Balkota <balkota@mac.com>
 *
 * $Id: packet-gtp.c,v 1.23 2002/01/31 10:11:32 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "packet-ipv6.h"
#include "prefs.h"

/* 
 * All data related to GTP v0 (GPRS) uses "gtpv0" or "GTPv0",
 * all data related to GTP v1 (UMTS) uses "gtpv1" or "GTPv1",
 * if there is any gtp alone statement it means that this data is common 
 * for both: GPRS and UMTS
 */

#define GTPv0_PORT 3386
#define GTPv1C_PORT 2123			/* 3G Control PDU */
#define GTPv1U_PORT 2152			/* 3G T-PDU */

#define GTPv0_HDR_LENGTH 20
#define GTPv1_HDR_LENGTH 12

/* for function checking compliance with ETSI  */
#define MANDATORY	1			
#define OPTIONAL	2 
#define CONDITIONAL	4

static int g_gtpv0_port			= GTPv0_PORT;
static int g_gtpv1c_port		= GTPv1C_PORT;
static int g_gtpv1u_port		= GTPv1U_PORT;

void proto_reg_handoff_gtp(void);

static int proto_gtpv0			= -1;
static int proto_gtpv1			= -1;

static int hf_gtpv0_flags			= -1;
static int hf_gtpv0_flags_ver		= -1;
static int hf_gtpv0_flags_pt		= -1;
static int hf_gtpv0_flags_spare		= -1;
static int hf_gtpv0_flags_e		= -1;
static int hf_gtpv0_flags_s		= -1;
static int hf_gtpv0_flags_pn		= -1;
static int hf_gtpv0_flags_snn		= -1;
static int hf_gtpv0_message_type		= -1;
static int hf_gtpv0_length		= -1;
static int hf_gtpv0_seq_number		= -1;
static int hf_gtpv0_flow_label		= -1;
static int hf_gtpv0_sndcp_number		= -1;
static int hf_gtpv0_npdu_number		= -1;
static int hf_gtpv0_tid			= -1;
static int hf_gtpv0_teid			= -1;
static int hf_gtpv0_next			= -1;
static int hf_gtpv0_cause			= -1;
static int hf_gtpv0_imsi			= -1;
static int hf_gtpv0_rai_mcc		= -1;
static int hf_gtpv0_rai_mnc		= -1;
static int hf_gtpv0_rai_rac		= -1;
static int hf_gtpv0_rai_lac		= -1;
static int hf_gtpv0_tlli			= -1;
static int hf_gtpv0_ptmsi			= -1;
static int hf_gtpv0_qos_spare1		= -1;
static int hf_gtpv0_qos_delay		= -1;
static int hf_gtpv0_qos_mean		= -1;
static int hf_gtpv0_qos_peak		= -1;
static int hf_gtpv0_qos_spare2		= -1;
static int hf_gtpv0_qos_precedence	= -1;
static int hf_gtpv0_qos_spare3		= -1;
static int hf_gtpv0_qos_reliability	= -1;
static int hf_gtpv0_reorder		= -1;
static int hf_gtpv0_map_cause		= -1;
static int hf_gtpv0_ptmsi_sig		= -1;
static int hf_gtpv0_ms_valid		= -1;
static int hf_gtpv0_recovery		= -1;
static int hf_gtpv0_sel_mode		= -1;
static int hf_gtpv0_ext_flow_label	= -1;
static int hf_gtpv0_teid_data		= -1;	/* 3G */
static int hf_gtpv0_flow_sig		= -1;
static int hf_gtpv0_teid_cp		= -1;	/* 3G */
static int hf_gtpv0_nsapi			= -1;
static int hf_gtpv0_flow_ii		= -1;
static int hf_gtpv0_teid_ii		= -1;	/* 3G */
static int hf_gtpv0_ms_reason		= -1;
static int hf_gtpv0_tear_ind		= -1;	/* 3G */
static int hf_gtpv0_ranap_cause		= -1;	/* 3G */
static int hf_gtpv0_rab_gtpu_dn		= -1;	/* 3G */
static int hf_gtpv0_rab_gtpu_up		= -1;	/* 3G */
static int hf_gtpv0_rab_pdu_dn		= -1;	/* 3G */
static int hf_gtpv0_rab_pdu_up		= -1;	/* 3G */
static int hf_gtpv0_rp_sms		= -1;	/* 3G */
static int hf_gtpv0_rp_spare		= -1;	/* 3G */
static int hf_gtpv0_rp_nsapi		= -1;	/* 3G */
static int hf_gtpv0_rp			= -1;	/* 3G */
static int hf_gtpv0_pkt_flow_id		= -1;	/* 3G */
static int hf_gtpv0_chrg_char_s		= -1;	/* 3G */
static int hf_gtpv0_chrg_char_n		= -1;	/* 3G */
static int hf_gtpv0_chrg_char_p		= -1;	/* 3G */
static int hf_gtpv0_chrg_char_f		= -1;	/* 3G */
static int hf_gtpv0_chrg_char_h		= -1;	/* 3G */
static int hf_gtpv0_chrg_char_r		= -1;	/* 3G */
static int hf_gtpv0_trace_ref		= -1;	/* 3G */
static int hf_gtpv0_trace_type		= -1;	/* 3G */
static int hf_gtpv0_tr_comm		= -1;	/* charging */
static int hf_gtpv0_chrg_id		= -1;
static int hf_gtpv0_user_ipv4		= -1;
static int hf_gtpv0_user_ipv6		= -1;
static int hf_gtpv0_user_addr_pdp_org	= -1;
static int hf_gtpv0_user_addr_pdp_type	= -1;
static int hf_gtpv0_apn			= -1;
static int hf_gtpv0_gsn_ipv4		= -1;
static int hf_gtpv0_gsn_ipv6		= -1;
static int hf_gtpv0_gsn_addr_type		= -1;
static int hf_gtpv0_gsn_addr_len		= -1;
static int hf_gtpv0_msisdn		= -1;
static int hf_gtpv0_qos_al_ret_priority	= -1;
static int hf_gtpv0_qos_traf_class	= -1;
static int hf_gtpv0_qos_del_order		= -1;
static int hf_gtpv0_qos_del_err_sdu	= -1;
static int hf_gtpv0_qos_max_sdu_size	= -1;
static int hf_gtpv0_qos_max_ul		= -1;
static int hf_gtpv0_qos_max_dl		= -1;
static int hf_gtpv0_qos_res_ber		= -1;
static int hf_gtpv0_qos_sdu_err_ratio	= -1;
static int hf_gtpv0_qos_trans_delay	= -1;
static int hf_gtpv0_qos_traf_handl_prio	= -1;
static int hf_gtpv0_qos_guar_ul		= -1;
static int hf_gtpv0_qos_guar_dl		= -1;
static int hf_gtpv0_rnc_ipv4		= -1;
static int hf_gtpv0_rnc_ipv6		= -1;
static int hf_gtpv0_chrg_ipv4		= -1;
static int hf_gtpv0_chrg_ipv6		= -1;
static int hf_gtpv0_node_ipv4		= -1;
static int hf_gtpv0_node_ipv6		= -1;
static int hf_gtpv0_ext_id		= -1;
static int hf_gtpv0_ext_val		= -1;
static int hf_gtpv0_unknown		= -1;

static int hf_gtpv1_flags			= -1;
static int hf_gtpv1_flags_ver		= -1;
static int hf_gtpv1_flags_pt		= -1;
static int hf_gtpv1_flags_spare		= -1;
static int hf_gtpv1_flags_e		= -1;
static int hf_gtpv1_flags_s		= -1;
static int hf_gtpv1_flags_pn		= -1;
static int hf_gtpv1_flags_snn		= -1;
static int hf_gtpv1_message_type		= -1;
static int hf_gtpv1_length		= -1;
static int hf_gtpv1_seq_number		= -1;
static int hf_gtpv1_flow_label		= -1;
static int hf_gtpv1_sndcp_number		= -1;
static int hf_gtpv1_npdu_number		= -1;
static int hf_gtpv1_tid			= -1;
static int hf_gtpv1_teid			= -1;
static int hf_gtpv1_next			= -1;
static int hf_gtpv1_cause			= -1;
static int hf_gtpv1_imsi			= -1;
static int hf_gtpv1_rai_mcc		= -1;
static int hf_gtpv1_rai_mnc		= -1;
static int hf_gtpv1_rai_rac		= -1;
static int hf_gtpv1_rai_lac		= -1;
static int hf_gtpv1_tlli			= -1;
static int hf_gtpv1_ptmsi			= -1;
static int hf_gtpv1_qos_spare1		= -1;
static int hf_gtpv1_qos_delay		= -1;
static int hf_gtpv1_qos_mean		= -1;
static int hf_gtpv1_qos_peak		= -1;
static int hf_gtpv1_qos_spare2		= -1;
static int hf_gtpv1_qos_precedence	= -1;
static int hf_gtpv1_qos_spare3		= -1;
static int hf_gtpv1_qos_reliability	= -1;
static int hf_gtpv1_reorder		= -1;
static int hf_gtpv1_map_cause		= -1;
static int hf_gtpv1_ptmsi_sig		= -1;
static int hf_gtpv1_ms_valid		= -1;
static int hf_gtpv1_recovery		= -1;
static int hf_gtpv1_sel_mode		= -1;
static int hf_gtpv1_ext_flow_label	= -1;
static int hf_gtpv1_teid_data		= -1;	/* 3G */
static int hf_gtpv1_flow_sig		= -1;
static int hf_gtpv1_teid_cp		= -1;	/* 3G */
static int hf_gtpv1_nsapi			= -1;
static int hf_gtpv1_flow_ii		= -1;
static int hf_gtpv1_teid_ii		= -1;	/* 3G */
static int hf_gtpv1_ms_reason		= -1;
static int hf_gtpv1_tear_ind		= -1;	/* 3G */
static int hf_gtpv1_ranap_cause		= -1;	/* 3G */
static int hf_gtpv1_rab_gtpu_dn		= -1;	/* 3G */
static int hf_gtpv1_rab_gtpu_up		= -1;	/* 3G */
static int hf_gtpv1_rab_pdu_dn		= -1;	/* 3G */
static int hf_gtpv1_rab_pdu_up		= -1;	/* 3G */
static int hf_gtpv1_rp_sms		= -1;	/* 3G */
static int hf_gtpv1_rp_spare		= -1;	/* 3G */
static int hf_gtpv1_rp_nsapi		= -1;	/* 3G */
static int hf_gtpv1_rp			= -1;	/* 3G */
static int hf_gtpv1_pkt_flow_id		= -1;	/* 3G */
static int hf_gtpv1_chrg_char_s		= -1;	/* 3G */
static int hf_gtpv1_chrg_char_n		= -1;	/* 3G */
static int hf_gtpv1_chrg_char_p		= -1;	/* 3G */
static int hf_gtpv1_chrg_char_f		= -1;	/* 3G */
static int hf_gtpv1_chrg_char_h		= -1;	/* 3G */
static int hf_gtpv1_chrg_char_r		= -1;	/* 3G */
static int hf_gtpv1_trace_ref		= -1;	/* 3G */
static int hf_gtpv1_trace_type		= -1;	/* 3G */
static int hf_gtpv1_tr_comm		= -1;	/* charging */
static int hf_gtpv1_chrg_id		= -1;
static int hf_gtpv1_user_ipv4		= -1;
static int hf_gtpv1_user_ipv6		= -1;
static int hf_gtpv1_user_addr_pdp_org	= -1;
static int hf_gtpv1_user_addr_pdp_type	= -1;
static int hf_gtpv1_apn			= -1;
static int hf_gtpv1_gsn_ipv4		= -1;
static int hf_gtpv1_gsn_ipv6		= -1;
static int hf_gtpv1_gsn_addr_type		= -1;
static int hf_gtpv1_gsn_addr_len		= -1;
static int hf_gtpv1_msisdn		= -1;
static int hf_gtpv1_qos_al_ret_priority	= -1;
static int hf_gtpv1_qos_traf_class	= -1;
static int hf_gtpv1_qos_del_order		= -1;
static int hf_gtpv1_qos_del_err_sdu	= -1;
static int hf_gtpv1_qos_max_sdu_size	= -1;
static int hf_gtpv1_qos_max_ul		= -1;
static int hf_gtpv1_qos_max_dl		= -1;
static int hf_gtpv1_qos_res_ber		= -1;
static int hf_gtpv1_qos_sdu_err_ratio	= -1;
static int hf_gtpv1_qos_trans_delay	= -1;
static int hf_gtpv1_qos_traf_handl_prio	= -1;
static int hf_gtpv1_qos_guar_ul		= -1;
static int hf_gtpv1_qos_guar_dl		= -1;
static int hf_gtpv1_rnc_ipv4		= -1;
static int hf_gtpv1_rnc_ipv6		= -1;
static int hf_gtpv1_chrg_ipv4		= -1;
static int hf_gtpv1_chrg_ipv6		= -1;
static int hf_gtpv1_node_ipv4		= -1;
static int hf_gtpv1_node_ipv6		= -1;
static int hf_gtpv1_ext_id		= -1;
static int hf_gtpv1_ext_val		= -1;
static int hf_gtpv1_unknown		= -1;

/* Initialize the subtree pointers */
static gint ett_gtp			= -1;
static gint ett_gtp_flags		= -1;
static gint ett_gtp_ext			= -1;
static gint ett_gtp_rai			= -1;
static gint ett_gtp_qos			= -1;
static gint ett_gtp_auth_tri		= -1;
static gint ett_gtp_flow_ii		= -1;
static gint ett_gtp_rab_cntxt		= -1;
static gint ett_gtp_rp			= -1;
static gint ett_gtp_pkt_flow_id		= -1;
static gint ett_gtp_chrg_char		= -1;
static gint ett_gtp_user		= -1;
static gint ett_gtp_mm			= -1;
static gint ett_gtp_trip		= -1;
static gint ett_gtp_quint		= -1;
static gint ett_gtp_pdp			= -1;
static gint ett_gtp_apn			= -1;
static gint ett_gtp_proto		= -1;
static gint ett_gtp_gsn_addr		= -1;
static gint ett_gtp_tft			= -1;
static gint ett_gtp_tft_pf		= -1;
static gint ett_gtp_rab_setup		= -1;
static gint ett_gtp_hdr_list		= -1;
static gint ett_gtp_chrg_addr		= -1;
static gint ett_gtp_node_addr		= -1;
static gint ett_gtp_rel_pack		= -1;
static gint ett_gtp_can_pack		= -1;
static gint ett_gtp_data_resp		= -1;
static gint ett_gtp_priv_ext		= -1;

/* Definition of user preferences panel fields */
#define DONT_DISSECT_CDRS	2

static gboolean	gtp_tpdu		= TRUE;
static gint 	gtpv0_cdr_as 		= DONT_DISSECT_CDRS;			/* 2 = do not dissect */
static gboolean	gtpv0_etsi_order	= FALSE;
static gboolean	gtpv1_etsi_order	= FALSE;
static int	gtpv0_port		= 0;
static int	gtpv1c_port		= 0;
static int	gtpv1u_port		= 0;
static gboolean ppp_reorder		= TRUE;

/* Definition of flags masks */
#define GTP_VER_MASK 0xE0

static const value_string ver_types[] = {
	{ 0, "GTP release 97/98 version" },
	{ 1, "GTP release 99 version" },
	{ 2, "None" },
	{ 3, "None" },
	{ 4, "None" },
	{ 5, "None" },
	{ 6, "None" },
	{ 7, "None" },
	{ 0, NULL }
};

#define GTP_PT_MASK		0x10
#define GTP_SPARE_MASK		0x0E
#define GTPv1_SPARE_MASK		0x08
#define GTPv1_E_MASK		0x04
#define GTPv1_S_MASK		0x02
#define GTP_SNN_MASK		0x01
#define GTPv1_PN_MASK		0x01

/* Definition of 3G charging characteristics masks */
#define GTP_MASK_CHRG_CHAR_S	0xF000
#define GTP_MASK_CHRG_CHAR_N	0x0800
#define GTP_MASK_CHRG_CHAR_P	0x0400
#define GTP_MASK_CHRG_CHAR_F	0x0200
#define GTP_MASK_CHRG_CHAR_H	0x0100
#define GTP_MASK_CHRG_CHAR_R	0x00FF


/* Definition of GSN Address masks */
#define GTP_EXT_GSN_ADDR_TYPE_MASK		0xC0
#define GTP_EXT_GSN_ADDR_LEN_MASK		0x3F

/* Definition of QoS masks */
#define GTP_EXT_QOS_SPARE1_MASK			0xC0
#define GTP_EXT_QOS_DELAY_MASK			0x38
#define GTP_EXT_QOS_RELIABILITY_MASK		0x07
#define GTP_EXT_QOS_PEAK_MASK			0xF0
#define GTP_EXT_QOS_SPARE2_MASK			0x08
#define GTP_EXT_QOS_PRECEDENCE_MASK		0x07
#define GTP_EXT_QOS_SPARE3_MASK			0xE0
#define GTP_EXT_QOS_MEAN_MASK			0x1F
#define GTP_EXT_QOS_TRAF_CLASS_MASK		0xE0
#define GTP_EXT_QOS_DEL_ORDER_MASK		0x18
#define GTP_EXT_QOS_DEL_ERR_SDU_MASK		0x07
#define GTP_EXT_QOS_RES_BER_MASK		0xF0
#define GTP_EXT_QOS_SDU_ERR_RATIO_MASK		0x0F
#define GTP_EXT_QOS_TRANS_DELAY_MASK		0xFC
#define GTP_EXT_QOS_TRAF_HANDL_PRIORITY_MASK	0x03

/* Definition of Radio Priority's masks */
#define GTPv1_EXT_RP_NSAPI_MASK			0xF0
#define GTPv1_EXT_RP_SPARE_MASK			0x08
#define GTPv1_EXT_RP_MASK			0x07

/* definitions of GTP messages */
#define GTP_MSG_UNKNOWN			0x00
#define GTP_MSG_ECHO_REQ		0x01
#define GTP_MSG_ECHO_RESP		0x02
#define GTP_MSG_VER_NOT_SUPP		0x03
#define GTP_MSG_NODE_ALIVE_REQ		0x04
#define GTP_MSG_NODE_ALIVE_RESP		0x05
#define GTP_MSG_REDIR_REQ		0x06
#define GTP_MSG_REDIR_RESP		0x07
#define GTP_MSG_CREATE_PDP_REQ		0x10
#define GTP_MSG_CREATE_PDP_RESP		0x11
#define GTP_MSG_UPDATE_PDP_REQ		0x12
#define GTP_MSG_UPDATE_PDP_RESP		0x13
#define GTP_MSG_DELETE_PDP_REQ		0x14
#define GTP_MSG_DELETE_PDP_RESP		0x15
#define GTP_MSG_CREATE_AA_PDP_REQ	0x16	/* 2G */
#define GTP_MSG_CREATE_AA_PDP_RESP	0x17	/* 2G */
#define GTP_MSG_DELETE_AA_PDP_REQ	0x18	/* 2G */
#define GTP_MSG_DELETE_AA_PDP_RESP	0x19	/* 2G */
#define GTP_MSG_ERR_IND			0x1A
#define GTP_MSG_PDU_NOTIFY_REQ		0x1B
#define GTP_MSG_PDU_NOTIFY_RESP		0x1C
#define GTP_MSG_PDU_NOTIFY_REJ_REQ	0x1D
#define GTP_MSG_PDU_NOTIFY_REJ_RESP	0x1E
#define GTP_MSG_SUPP_EXT_HDR		0x1F
#define GTP_MSG_SEND_ROUT_INFO_REQ	0x20
#define GTP_MSG_SEND_ROUT_INFO_RESP	0x21
#define GTP_MSG_FAIL_REP_REQ		0x22
#define GTP_MSG_FAIL_REP_RESP		0x23
#define GTP_MSG_MS_PRESENT_REQ		0x24
#define GTP_MSG_MS_PRESENT_RESP		0x25
#define GTP_MSG_IDENT_REQ		0x30
#define GTP_MSG_IDENT_RESP		0x31
#define GTP_MSG_SGSN_CNTXT_REQ		0x32
#define GTP_MSG_SGSN_CNTXT_RESP		0x33
#define GTP_MSG_SGSN_CNTXT_ACK		0x34
#define GTP_MSG_FORW_RELOC_REQ		0x35
#define GTP_MSG_FORW_RELOC_RESP		0x36
#define GTP_MSG_FORW_RELOC_COMP		0x37
#define GTP_MSG_RELOC_CANCEL_REQ	0x38
#define GTP_MSG_RELOC_CANCEL_RESP	0x39
#define GTP_MSG_FORW_SRNS_CNTXT		0x3A
#define GTP_MSG_FORW_RELOC_ACK		0x3B
#define GTP_MSG_FORW_SRNS_CNTXT_ACK	0x3C
#define GTP_MSG_DATA_TRANSF_REQ		0xF0
#define GTP_MSG_DATA_TRANSF_RESP	0xF1
#define GTP_MSG_TPDU			0xFF

static const value_string message_type[] = {
	{ GTP_MSG_UNKNOWN,		"For future use" },
	{ GTP_MSG_ECHO_REQ,		"Echo request" },
	{ GTP_MSG_ECHO_RESP,		"Echo response" },
	{ GTP_MSG_VER_NOT_SUPP,		"Version not supported" },
	{ GTP_MSG_NODE_ALIVE_REQ,	"Node alive request" },
	{ GTP_MSG_NODE_ALIVE_RESP,	"Node alive response" },
	{ GTP_MSG_REDIR_REQ,		"Redirection request" },
	{ GTP_MSG_REDIR_RESP,		"Redirection response" },
	{ GTP_MSG_CREATE_PDP_REQ,	"Create PDP context request" },
	{ GTP_MSG_CREATE_PDP_RESP,	"Create PDP context response" },
	{ GTP_MSG_UPDATE_PDP_REQ,	"Update PDP context request" },
	{ GTP_MSG_UPDATE_PDP_RESP,	"Update PDP context response" },
	{ GTP_MSG_DELETE_PDP_REQ,	"Delete PDP context request" },
	{ GTP_MSG_DELETE_PDP_RESP,	"Delete PDP context response" },
	{ GTP_MSG_CREATE_AA_PDP_REQ,	"Create AA PDP Context Request" },
	{ GTP_MSG_CREATE_AA_PDP_RESP,	"Create AA PDP Context Response" },
	{ GTP_MSG_DELETE_AA_PDP_REQ,	"Delete AA PDP Context Request" },
	{ GTP_MSG_DELETE_AA_PDP_RESP,	"Delete AA PDP Context Response" },
	{ GTP_MSG_ERR_IND,		"Error indication" },
	{ GTP_MSG_PDU_NOTIFY_REQ,	"PDU notification request" },
	{ GTP_MSG_PDU_NOTIFY_RESP,	"PDU notification response" },
	{ GTP_MSG_PDU_NOTIFY_REJ_REQ,	"PDU notification reject request" },
	{ GTP_MSG_PDU_NOTIFY_REJ_RESP,	"PDU notification reject response" },
	{ GTP_MSG_SUPP_EXT_HDR,		"Supported extension header notification" },
	{ GTP_MSG_SEND_ROUT_INFO_REQ,	"Send routing information for GPRS request" },
	{ GTP_MSG_SEND_ROUT_INFO_RESP,	"Send routing information for GPRS response" },
	{ GTP_MSG_FAIL_REP_REQ,		"Failure report request" },
	{ GTP_MSG_FAIL_REP_RESP,	"Failure report response" },
	{ GTP_MSG_MS_PRESENT_REQ,	"Note MS GPRS present request" },
	{ GTP_MSG_MS_PRESENT_RESP,	"Note MS GPRS present response" },
	{ GTP_MSG_IDENT_REQ,		"Identification request" },
	{ GTP_MSG_IDENT_RESP,		"Identification response" },
	{ GTP_MSG_SGSN_CNTXT_REQ,	"SGSN context request" },
	{ GTP_MSG_SGSN_CNTXT_RESP,	"SGSN context response" },
	{ GTP_MSG_SGSN_CNTXT_ACK,	"SGSN context acknowledgement" },
	{ GTP_MSG_FORW_RELOC_REQ,	"Forward relocation request" },
	{ GTP_MSG_FORW_RELOC_RESP,	"Forward relocation response" },
	{ GTP_MSG_FORW_RELOC_COMP,	"Forward relocation complete" },
	{ GTP_MSG_RELOC_CANCEL_REQ,	"Relocation cancel request" },
	{ GTP_MSG_RELOC_CANCEL_RESP,	"Relocation cancel response" },
	{ GTP_MSG_FORW_SRNS_CNTXT,	"Forward SRNS context" },
	{ GTP_MSG_FORW_RELOC_ACK,	"Forward relocation complete acknowledge" },
	{ GTP_MSG_FORW_SRNS_CNTXT_ACK,	"Forward SRNS context acknowledge" },
	{ GTP_MSG_DATA_TRANSF_REQ,	"Data record transfer request" },
	{ GTP_MSG_DATA_TRANSF_RESP,	"Data record transfer response" },
	{ GTP_MSG_TPDU,			"T-PDU" },
	{ 0, NULL }
};

/* definitions of fields in extension header */
#define GTP_EXT_CAUSE		0x01
#define GTP_EXT_IMSI		0x02
#define GTP_EXT_RAI		0x03
#define GTP_EXT_TLLI		0x04
#define GTP_EXT_PTMSI		0x05
#define GTP_EXT_QOS_GPRS	0x06
#define GTP_EXT_REORDER		0x08
#define GTP_EXT_AUTH_TRI	0x09
#define GTP_EXT_MAP_CAUSE	0x0B
#define GTP_EXT_PTMSI_SIG	0x0C
#define GTP_EXT_MS_VALID	0x0D
#define GTP_EXT_RECOVER		0x0E
#define GTP_EXT_SEL_MODE	0x0F

#define GTP_EXT_16		0x10
#define GTP_EXT_FLOW_LABEL	0x10	
#define GTP_EXT_TEID		0x10 	/* 0xFF10 3G */

#define GTP_EXT_17		0x11
#define GTP_EXT_FLOW_SIG	0x11	
#define GTP_EXT_TEID_CP		0x11	/* 0xFF11 3G */

#define GTP_EXT_18		0x12
#define GTP_EXT_FLOW_II		0x12	
#define GTP_EXT_TEID_II		0x12	/* 0xFF12 3G*/

#define GTP_EXT_19		0x13
#define GTP_EXT_MS_REASON	0x13	/* same as 0x1D GTPv1_EXT_MS_REASON */
#define GTP_EXT_TEAR_IND	0x13	/* 0xFF13 3G*/

#define GTP_EXT_NSAPI		0x14	/* 3G */
#define GTP_EXT_RANAP_CAUSE	0x15	/* 3G */
#define GTP_EXT_RAB_CNTXT	0x16	/* 3G */
#define GTP_EXT_RP_SMS		0x17	/* 3G */
#define GTP_EXT_RP		0x18	/* 3G */
#define GTP_EXT_PKT_FLOW_ID	0x19	/* 3G */
#define GTP_EXT_CHRG_CHAR	0x1A	/* 3G */
#define GTP_EXT_TRACE_REF	0x1B	/* 3G */
#define GTP_EXT_TRACE_TYPE	0x1C	/* 3G */
#define GTPv1_EXT_MS_REASON	0x1D	/* 3G */
#define GTP_EXT_TR_COMM		0x7E	/* charging */
#define GTP_EXT_CHRG_ID		0x7F
#define GTP_EXT_USER_ADDR	0x80
#define GTP_EXT_MM_CNTXT	0x81
#define GTP_EXT_PDP_CNTXT	0x82
#define GTP_EXT_APN		0x83
#define GTP_EXT_PROTO_CONF	0x84
#define GTP_EXT_GSN_ADDR	0x85
#define GTP_EXT_MSISDN		0x86
#define GTP_EXT_QOS_UMTS	0x87	/* 3G */
#define GTP_EXT_AUTH_QUI	0x88	/* 3G */
#define GTP_EXT_TFT		0x89	/* 3G */
#define GTP_EXT_TARGET_ID	0x8A	/* 3G */
#define GTP_EXT_UTRAN_CONT	0x8B	/* 3G */
#define GTP_EXT_RAB_SETUP	0x8C	/* 3G */
#define GTP_EXT_HDR_LIST	0x8D	/* 3G */
#define GTP_EXT_TRIGGER_ID	0x8E	/* 3G */
#define GTP_EXT_OMC_ID		0x8F	/* 3G */
#define GTP_EXT_REL_PACK	0xF9	/* charging */
#define GTP_EXT_CAN_PACK	0xFA	/* charging */
#define GTP_EXT_CHRG_ADDR	0xFB
#define GTP_EXT_DATA_REQ	0xFC	/* charging */
#define GTP_EXT_DATA_RESP	0xFD	/* charging */
#define GTP_EXT_NODE_ADDR	0xFE	/* charging */
#define GTP_EXT_PRIV_EXT	0xFF

static const value_string gtp_val[] = {
	{ GTP_EXT_CAUSE,	"Cause of operation" },
	{ GTP_EXT_IMSI,		"IMSI " },
	{ GTP_EXT_RAI,		"Routing Area Identity" },
	{ GTP_EXT_TLLI,		"Temporary Logical Link Identity" },
	{ GTP_EXT_PTMSI,	"Packet TMSI" },
	{ GTP_EXT_QOS_GPRS,	"Quality of Service" },
	{ GTP_EXT_REORDER,	"Reorder required" },
	{ GTP_EXT_AUTH_TRI,	"Authentication triplets" },
	{ GTP_EXT_MAP_CAUSE,	"MAP cause" },
	{ GTP_EXT_PTMSI_SIG,	"P-TMSI signature" },
	{ GTP_EXT_MS_VALID,	"MS validated" },
	{ GTP_EXT_RECOVER,	"Recovery" },
	{ GTP_EXT_SEL_MODE,	"Selection mode" },

	{ GTP_EXT_16,		"Flow label data I" },
	{ GTP_EXT_FLOW_LABEL,	"Flow label data I" },
	{ GTP_EXT_TEID,		"Tunnel Endpoint Identifier Data I" },		/* 3G */
	
	{ GTP_EXT_17,		"Flow label signalling" },
	{ GTP_EXT_FLOW_SIG,	"Flow label signalling" },
	{ GTP_EXT_TEID_CP,	"Tunnel Endpoint Identifier Data Control Plane" },	/* 3G */
	
	{ GTP_EXT_18,		"Flow label data II" },
	{ GTP_EXT_FLOW_II,	"Flow label data II" },
	{ GTP_EXT_TEID_II,	"Tunnel Endpoint Identifier Data II" },		/* 3G */
	
	{ GTP_EXT_19,		"MS not reachable reason" },
	{ GTP_EXT_MS_REASON,	"MS not reachable reason" },
	{ GTP_EXT_TEAR_IND,	"Teardown ID" },					/* 3G */
	
	{ GTP_EXT_NSAPI,	"NSAPI" },						/* 3G */
	{ GTP_EXT_RANAP_CAUSE,	"RANAP cause" },					/* 3G */
	{ GTP_EXT_RAB_CNTXT,	"RAB context" },					/* 3G */
	{ GTP_EXT_RP_SMS,	"Radio Priority for MO SMS" },			/* 3G */
	{ GTP_EXT_RP,		"Radio Priority" },					/* 3G */
	{ GTP_EXT_PKT_FLOW_ID,	"Packet Flow ID " },					/* 3G */
	{ GTP_EXT_CHRG_CHAR,	"Charging characteristics" },				/* 3G */
	{ GTP_EXT_TRACE_REF,	"Trace references" },					/* 3G */
	{ GTP_EXT_TRACE_TYPE,	"Trace type" },					/* 3G */
	{ GTPv1_EXT_MS_REASON,	"MS not reachable reason" },				/* 3G */
	{ GTP_EXT_TR_COMM,	"Packet transfer command" },				/* charging */
	{ GTP_EXT_CHRG_ID,	"Charging ID" },
	{ GTP_EXT_USER_ADDR,	"End user address " },
	{ GTP_EXT_MM_CNTXT,	"MM context" },
	{ GTP_EXT_PDP_CNTXT,	"PDP context" },
	{ GTP_EXT_APN,		"Access Point Name" },
	{ GTP_EXT_PROTO_CONF,	"Protocol configuration options" },
	{ GTP_EXT_GSN_ADDR,	"GSN address" },
	{ GTP_EXT_MSISDN,	"MS international PSTN/ISDN number" },
	{ GTP_EXT_QOS_UMTS,	"Quality of service (UMTS)" },			/* 3G */
	{ GTP_EXT_AUTH_QUI,	"Authentication quintuplets" },			/* 3G */
	{ GTP_EXT_TFT,		"Traffic Flow Template (TFT)" },			/* 3G */
	{ GTP_EXT_TARGET_ID,	"Target (RNC) identification" },			/* 3G */
	{ GTP_EXT_UTRAN_CONT,	"UTRAN transparent field" },				/* 3G */
	{ GTP_EXT_RAB_SETUP,	"RAB setup information" },				/* 3G */
	{ GTP_EXT_HDR_LIST,	"Extension Header Types List " },			/* 3G */
	{ GTP_EXT_TRIGGER_ID,	"Trigger Id " },					/* 3G */
	{ GTP_EXT_OMC_ID,	"OMC Identity " },					/* 3G */
	{ GTP_EXT_REL_PACK,	"Sequence numbers of released packets IE" },		/* charging */
	{ GTP_EXT_CAN_PACK,	"Sequence numbers of canceled packets IE" },		/* charging */
	{ GTP_EXT_CHRG_ADDR,	"Charging Gateway address" },
	{ GTP_EXT_DATA_REQ,	"Data record packet" },				/* charging */
	{ GTP_EXT_DATA_RESP,	"Requests responded" },				/* charging */
	{ GTP_EXT_NODE_ADDR,	"Address of recommended node" },			/* charging */
	{ GTP_EXT_PRIV_EXT, 	"Private Extension " },
	{ 0, NULL }
};

/* GPRS:	9.60 v7.6.0, page 37
 * UMTS:	29.060 v4.0, page 45 
 */
static const value_string cause_type[] = {
	{ 0,	"Request IMSI" },
	{ 1,	"Request IMEI" },
	{ 2,	"Request IMSI and IMEI" },
	{ 3,	"No identity needed" },
	{ 4,	"MS refuses" },
	{ 5,	"MS is not GPRS responding" },
	{ 59,	"System failure" },	/* charging */
	{ 60,	"The transmit buffers are becoming full" },	/* charging */
	{ 61,	"The receive buffers are becoming full" },	/* charging */
	{ 62,	"Another node is about to go down" },	/* charging */
	{ 63,	"This node is about to go down" },	/* charging */
	{ 128,	"Request accepted" },
	{ 192,	"Non-existent" },
	{ 193,	"Invalid message format" },
	{ 194,	"IMSI not known" },
	{ 195,	"MS is GPRS detached" },
	{ 196,	"MS is not GPRS responding" },
	{ 197,	"MS refuses" },
	{ 198,	"Version not supported" },
	{ 199,	"No resource available" },
	{ 200,	"Service not supported" },
	{ 201,	"Mandatory IE incorrect" },
	{ 202,	"Mandatory IE missing" },
	{ 203,	"Optional IE incorrect" },
	{ 204,	"System failure" },
	{ 205,	"Roaming restriction" },
	{ 206,	"P-TMSI signature mismatch" },
	{ 207,	"GPRS connection suspended" },
	{ 208,	"Authentication failure" },
	{ 209,	"User authentication failed" },
	{ 210,	"Context not found" },
	{ 211,	"All PDP dynamic addresses are occupied" },
	{ 212,	"No memory is available" },
	{ 213,	"Relocation failure" },
	{ 214,	"Unknown mandatory extension header" },
	{ 215,	"Semantic error in the TFT operation" },
	{ 216,	"Syntactic error in the TFT operation" },
	{ 217,	"Semantic errors in packet filter(s)" },
	{ 218,	"Syntactic errors in packet filter(s)" },
	{ 219,	"Missing or unknown APN" },
	{ 220,	"Unknown PDP address or PDP type" },
	{ 252,	"Request related to possibly duplicated packets already fulfilled" },	/* charging */
	{ 253,	"Request already fulfilled" },	/* charging */
	{ 254,	"Sequence numbers of released/cancelled packets IE incorrect" }, 	/* charging */
	{ 255,	"Request not fulfilled" },	/* charging */
	{ 0, NULL }
};

/* GPRS:	9.02 v7.7.0
 * UMTS:	29.002 v4.2.1, chapter 17.5, page 268
 * TODO: Check if all map_cause values are included
 */
static const value_string map_cause_type[] = {
	{ 1, "Unknown subscriber" },
	{ 8, "Roaming not allowed" },
	{ 10, "Bearer service not provisioned" },
	{ 11, "Teleservice not provisioned" },
	{ 13, "Call barred" },
	{ 21, "Facility not supported" },
	{ 23, "Update GPRS location" },
	{ 24, "Send routing info for GPRS" },
	{ 26, "Note MS present for GPRS" },
	{ 27, "Absent subscriber" },
	{ 34, "System failure" },
	{ 35, "Data missing" },
	{ 36, "Unexpected data value" },
	{ 44, "Number chenged" },
	{ 45, "Busy subscriber" },
	{ 46, "No subscriber reply" },
	{ 48, "Facility not allowed" },
	{ 0, NULL }
};

static const value_string gsn_addr_type[] = {
	{ 0x00, "IPv4" },
	{ 0x01, "IPv6" },
	{ 0, 	NULL },
};

static const value_string pdp_type[] = {
	{ 0x00, "X.25" },
	{ 0x01, "PPP" },
	{ 0x02, "OSP:IHOSS" },
	{ 0x21, "IPv4" },
	{ 0x57, "IPv6" },
	{ 0, NULL }
};

static const value_string pdp_org_type[] = {
	{ 0, "ETSI" },
	{ 1, "IETF" },
	{ 0, NULL }
};

static const value_string qos_delay_type[] = {
	{ 0x00, "Subsribed delay class (in MS to network direction)" },
	{ 0x01, "Delay class 1" },
	{ 0x02, "Delay class 2" },
	{ 0x03, "Delay class 3" },
	{ 0x04, "Delay class 4 (best effort)" },
	{ 0x07,	"Reserved" },
	{ 0, NULL }
};

static const value_string qos_reliability_type[] = {
	{ 0x00, "Subscribed reliability class (in MS to network direction)" },
	{ 0x01, "Ack GTP/LLC/RLC, Protected data" },
	{ 0x02, "Unack GTP, Ack LLC/RLC, Protected data" },
	{ 0x03, "Unack GTP/LLC, Ack RLC, Protected data" },
	{ 0x04, "Unack GTP/LLC/RLC, Protected data" },
	{ 0x05, "Unack GTP/LLC/RLC, Unprotected data" },
	{ 0x07, "Reserved" },
	{ 0, NULL }
};

static const value_string qos_peak_type[] = {
	{ 0x00, "Subscribed peak throughput (in MS to network direction)" },
	{ 0x01, "Up to 1 000 oct/s" },
	{ 0x02, "Up to 2 000 oct/s" },
	{ 0x03, "Up to 4 000 oct/s" },
	{ 0x04, "Up to 8 000 oct/s" },
	{ 0x05, "Up to 16 000 oct/s" },
	{ 0x06, "Up to 32 000 oct/s" },
	{ 0x07, "Up to 64 000 oct/s" },
	{ 0x08, "Up to 128 000 oct/s" },
	{ 0x09, "Up to 256 000 oct/s" },
/* QoS Peak throughput classes from 0x0A to 0x0F (from 10 to 15) are subscribed */ 
	{ 0x0A,	"Reserved" },
	{ 0x0B,	"Reserved" },
	{ 0x0C,	"Reserved" },
	{ 0x0D,	"Reserved" },
	{ 0x0E,	"Reserved" },
	{ 0x0F,	"Reserved" },
	{ 0, NULL }
};

static const value_string qos_precedence_type[] = {
	{ 0x00, "Subscribed precedence (in MS to network direction)" },
	{ 0x01, "High priority" },
	{ 0x02, "Normal priority" },
	{ 0x03, "Low priority" },
	{ 0x07, "Reserved" },
	{ 0, NULL }
};

static const value_string qos_mean_type[] = {
	{ 0x00, "Subscribed mean throughput (in MS to network direction)" },
	{ 0x01, "100 oct/h" },		/* Class 2 */
	{ 0x02, "200 oct/h" },		/* Class 3 */
	{ 0x03, "500 oct/h" },		/* Class 4 */
	{ 0x04, "1 000 oct/h" },	/* Class 5 */
	{ 0x05, "2 000 oct/h" },	/* Class 6 */
	{ 0x06, "5 000 oct/h" },	/* Class 7 */
	{ 0x07, "10 000 oct/h" },	/* Class 8 */
	{ 0x08, "20 000 oct/h" },	/* Class 9 */
	{ 0x09, "50 000 oct/h" },	/* Class 10 */
	{ 0x0A, "100 000 oct/h" },	/* Class 11 */
	{ 0x0B, "200 000 oct/h" },	/* Class 12 */
	{ 0x0C, "500 000 oct/h" },	/* Class 13 */
	{ 0x0D, "1 000 000 oct/h" },	/* Class 14 */
	{ 0x0E, "2 000 000 oct/h" },	/* Class 15 */
	{ 0x0F, "5 000 000 oct/h" },	/* Class 16 */
	{ 0x10, "10 000 000 oct/h" },	/* Class 17 */
	{ 0x11, "20 000 000 oct/h" },	/* Class 18 */
	{ 0x12, "50 000 000 oct/h" },	/* Class 19 */
/* QoS Mean throughput classes from 0x13 to 0x1E (from 19 to 30) are subscribed */
	{ 0x13, "Reserved" },
	{ 0x14, "Reserved" },
	{ 0x15, "Reserved" },
	{ 0x16, "Reserved" },
	{ 0x17, "Reserved" },
	{ 0x18, "Reserved" },
	{ 0x19, "Reserved" },
	{ 0x1A, "Reserved" },
	{ 0x1B, "Reserved" },
	{ 0x1C, "Reserved" },
	{ 0x1D, "Reserved" },
	{ 0x1E, "Reserved" },
	{ 0x1F, "Best effort" },	/* Class 1 */
	{ 0, NULL }
};

static const value_string qos_del_err_sdu[] = {
	{ 0x00, "Subscribed delivery of erroneous SDUs (in MS to network direction)" },
	{ 0x01, "No detect ('-')" },
	{ 0x02, "Erroneous SDUs are delivered ('yes')" },
	{ 0x03, "Erroneous SDUs are not delivered ('no')" },
	{ 0x07, "Reserved" },		/* All other values are reserved */
	{ 0, NULL }
};

static const value_string qos_del_order[] = {
	{ 0x00, "Subscribed delivery order (in MS to network direction)" },
	{ 0x01, "With delivery order ('yes')" },
	{ 0x02, "Without delivery order ('no')" },
	{ 0x03, "Reserved" },		/* All other values are reserved */
	{ 0, NULL }
};

static const value_string qos_traf_class[] = {
	{ 0x00, "Subscribed traffic class (in MS to network direction)" },
	{ 0x01, "Conversational class" },
	{ 0x02, "Streaming class" },
	{ 0x03, "Interactive class" },
	{ 0x04, "Background class" },
	{ 0x07, "Reserved" },		/* All other values are reserved */
	{ 0, NULL }
};

static const value_string qos_max_sdu_size[] = {
	{ 0x00, "Subscribed maximum SDU size (in MS to network direction" },
	/* For values from 0x01 to 0x96 (from 1 to 150), use a granularity of 10 octets */ 
	{ 0x97, "1502 octets" },
	{ 0x98, "1510 octets" },
	{ 0x99, "1520 octets" },
	{ 0, NULL }					/* All other values are reserved */
};

static const value_string qos_max_ul[] = {
	{ 0x00, "Subscribed maximum bit rate for uplink (in MS to network direction)" },
	/* For values from 0x01 to 0x3F (from 1 to 63), use a granularity of 1 kbps */
	/* For values from 0x40 to 0x7F, value = 64 kbps + (value - 0x40) * 8 kbps */
	/* For values from 0x80 to 0xFE, value = 576 kbps + (value - 0x80) * 64 kbps */
	{ 0xFF, "0 kbps" },
	{ 0, NULL }
};

static const value_string qos_max_dl[] = {
	{ 0x00, "Subscribed maximum bit rate for downlink (in MS to network direction)" },
	/* For values from 0x01 to 0x3F (from 1 to 63), use a granularity of 1 kbps */
	/* For values from 0x40 to 0x7F, value = 64 kbps + (value - 0x40) * 8 kbps */
	/* For values from 0x80 to 0xFE, value = 576 kbps + (value - 0x80) * 64 kbps */
	{ 0xFF, "0 kbps" },
	{ 0, NULL }
};

static const value_string qos_res_ber[] = {
	{ 0x00, "Subscribed residual BER (in MS to network direction)" },
	{ 0x01, "1/20 = 5x10^-2" },
	{ 0x02, "1/100 = 1x10^-2" },
	{ 0x03, "1/200 = 5x10^-3" },
	{ 0x04, "1/250 = 4x10^-3" },
	{ 0x05, "1/1 000 = 1x10^-3" },
	{ 0x06, "1/10 000 = 1x10^-4" },
	{ 0x07, "1/100 000 = 1x10^-5" },
	{ 0x08, "1/1 000 000 = 1x10^-6" },
	{ 0x09, "3/50 000 000 = 6x10^-8" },
	{ 0x0F, "Reserved" },		/* All other values are reserved */
	{ 0, NULL }
};

static const value_string qos_sdu_err_ratio[] = {
	{ 0x00, "Subscribed SDU error ratio (in MS to network direction)" },
	{ 0x01, "1/100 = 1x10^-2" },
	{ 0x02, "7/1000 = 7x10^-3" },
	{ 0x03, "1/1 000 = 1x10^-3" },
	{ 0x04, "1/10 000 = 1x10^-4" },
	{ 0x05, "1/100 000 = 1x10^-5" },
	{ 0x06, "1/1 000 000 = 1x10^-6" },
	{ 0x07, "1/10 = 1x10^-1" },
	{ 0x0F, "Reserved" },		/* All other values are reserved */
	{ 0, NULL }
}; 

static const value_string qos_traf_handl_prio[] = {
	{ 0x00, "Subscribed traffic handling priority (in MS to network direction)" },
	{ 0x01, "Priority level 1" },
	{ 0x02, "Priority level 2" },
	{ 0x03, "Priority level 3" },
	{ 0, NULL }
};

static const value_string qos_trans_delay[] = {
	{ 0x00, "Subscribed Transfer Delay (in MS to network direction)" },
	{ 0x01, "10 ms" },	/* Using a granularity of 10 ms */
	{ 0x02, "20 ms" },
	{ 0x03, "30 ms" },
	{ 0x04, "40 ms" },
	{ 0x05, "50 ms" },
	{ 0x06, "60 ms" },
	{ 0x07, "70 ms" },
	{ 0x08, "80 ms" },
	{ 0x09, "90 ms" },
	{ 0x0A, "100 ms" },
	{ 0x0B, "110 ms" },
	{ 0x0C, "120 ms" },
	{ 0x0D, "130 ms" },
	{ 0x0E, "140 ms" },
	{ 0x0F, "150 ms" },
	{ 0x10, "200 ms" },	/* (For values from 0x10 to 0x1F, value = 200 ms + (value - 0x10) * 50 ms */
	{ 0x11, "250 ms" },
	{ 0x12, "300 ms" },
	{ 0x13, "350 ms" },
	{ 0x14, "400 ms" },
	{ 0x15, "450 ms" },
	{ 0x16, "500 ms" },
	{ 0x17, "550 ms" },
	{ 0x18, "600 ms" },
	{ 0x19, "650 ms" },
	{ 0x1A, "700 ms" },
	{ 0x1B, "750 ms" },
	{ 0x1C, "800 ms" },
	{ 0x1D, "850 ms" },
	{ 0x1E, "900 ms" },
	{ 0x1F, "950 ms" },
	{ 0x20, "1000 ms" },	/* For values from 0x20 to 0x3E, value = 1000 ms + (value - 0x20) * 100 ms */
	{ 0x21, "1100 ms" },
	{ 0x22, "1200 ms" },
	{ 0x23, "1300 ms" },
	{ 0x24, "1400 ms" },
	{ 0x25, "1500 ms" },
	{ 0x26, "1600 ms" },
	{ 0x27, "1700 ms" },
	{ 0x28, "1800 ms" },
	{ 0x29, "1900 ms" },
	{ 0x2A, "2000 ms" },
	{ 0x2B, "2100 ms" },
	{ 0x2C, "2200 ms" },
	{ 0x2D, "2300 ms" },
	{ 0x2E, "2400 ms" },
	{ 0x2F, "2500 ms" },
	{ 0x30, "2600 ms" },
	{ 0x31, "2700 ms" },
	{ 0x32, "2800 ms" },
	{ 0x33, "2900 ms" },
	{ 0x34, "3000 ms" },
	{ 0x35, "3100 ms" },
	{ 0x36, "3200 ms" },
	{ 0x37, "3300 ms" },
	{ 0x38, "3400 ms" },
	{ 0x39, "3500 ms" },
	{ 0x3A, "3600 ms" },
	{ 0x3B, "3700 ms" },
	{ 0x3C, "3800 ms" },
	{ 0x3D, "3900 ms" },
	{ 0x3E, "4000 ms" },
	{ 0x3F, "Reserved"},
	{ 0, NULL }
};

static const value_string qos_guar_ul[] = {
	{ 0x00, "Subscribed guaranteed bit rate for uplink (in MS to network direction)" },
	/* For values from 0x01 to 0x3F (from 1 to 63), use a granularity of 1 kbps */
	/* For values from 0x40 to 0x7F, value = 64 kbps + (value - 0x40) * 8 kbps */
	/* For values from 0x80 to 0xFE, value = 576 kbps + (value - 0x80) * 64 kbps */
	{ 0xFF, "0 kbps" },
	{ 0, NULL }
};

static const value_string qos_guar_dl[] = {
	{ 0x00, "Subscribed guaranteed bit rate for downlink (in MS to network direction)" },
	/* For values from 0x01 to 0x3F (from 1 to 63), use a granularity of 1 kbps */
	/* For values from 0x40 to 0x7F, value = 64 kbps + (value - 0x40) * 8 kbps */
	/* For values from 0x80 to 0xFE, value = 576 kbps + (value - 0x80) * 64 kbps */
	{ 0xFF, "0 kbps" },
	{ 0, NULL }
};

static const value_string sel_mode_type[] = {
	{ 0,	"MS or network provided APN, subscriber verified" },
	{ 1,	"MS provided APN, subscription not verified" },
	{ 2,	"Network provided APN, subscription not verified" },
	{ 3,	"For future use (Network provided APN, subscription not verified" },/* Shall not be sent. If received, shall be sent as value 2 */
	{ 0, 	NULL }
};

static const value_string tr_comm_type[] = {
	{ 1,	"Send data record packet" },
	{ 2,	"Send possibly duplicated data record packet" },
	{ 3,	"Cancel data record packet" },
	{ 4,	"Release data record packet"},
	{ 0,	NULL }
};

/* TODO: CHeck if all ms_reasons are included */
static const value_string ms_not_reachable_type[] = {
	{ 0,	"No paging response via the MSC" },
	{ 1,	"IMSI detached" },
	{ 2,	"Roaming restriction" },
	{ 3,	"Deregistered in the HLR for non GPRS" },
	{ 4,	"MS purge for non GPRS" },
	{ 5,	"No paging response via the SGSN" },
	{ 6,	"GPRS detached" },
	{ 7,	"Deregistered in the HLR for non GPRS" },
	{ 8,	"MS purged for GPRS" },
	{ 9,	"Unidentified subscriber via the MSC" },
	{ 10,	"Unidentified subscriber via the SGSN" },
	{ 0,	NULL }
};

/* UMTS:	25.413 v3.4.0, chapter 9.2.1.4, page 80
 */
static const value_string ranap_cause_type[] = {
/* Radio Network Layer Cause (1-->64) */
	{ 1, "RAB preempted" },
	{ 2, "Trelocoverall Expiry" },
	{ 3, "Trelocprep Expiry" },
	{ 4, "Treloccomplete Expiry" },
	{ 5, "Tqueing Expiry" },
	{ 6, "Relocation Triggered" },
	{ 7, "TRELOCalloc Expiry" },
	{ 8, "Unable to Estabish During Relocation" },
	{ 9, "Unknown Target RNC" },
	{ 10, "Relocation Cancelled" },
	{ 11, "Successful Relocation" },
	{ 12, "Requested Ciphering and/or Integrity Protection Algorithms not Supported" },
	{ 13, "Change of Ciphering and/or Integrity Protection is not supported" },
	{ 14, "Failure in the Radio Interface Procedure" },
	{ 15, "Release due to UTRAN Generated Reason" },
	{ 16, "User Inactivity" },
	{ 17, "Time Critical Relocation" },
	{ 18, "Requested Traffic Class not Available" },
	{ 19, "Invalid RAB Parameters Value" },
	{ 20, "Requested Maximum Bit Rate not Available" },
	{ 21, "Requested Guaranteed Bit Rate not Available" },
	{ 22, "Requested Transfer Delay not Achievable" },
	{ 23, "Invalid RAB Parameters Combination" },
	{ 24, "Condition Violation for SDU Parameters" },
	{ 25, "Condition Violation for Traffic Handling Priority" },
	{ 26, "Condition Violation for Guaranteed Bit Rate" },
	{ 27, "User Plane Versions not Supported" },
	{ 28, "Iu UP Failure" },
	{ 29, "Relocation Failure in Target CN/RNC or Target System" },
	{ 30, "Invalid RAB ID" },
	{ 31, "No Remaining RAB" },
	{ 32, "Interaction with other procedure" },
	{ 33, "Requested Maximum Bit Rate for DL not Available" },
	{ 34, "Requested Maximum Bit Rate for UL not Available" },
	{ 35, "Requested Guaranteed Bit Rate for DL not Available" },
	{ 36, "Requested Guaranteed Bit Rate for UL not Available" },
	{ 37, "Repeated Integrity Checking Failure" },
	{ 38, "Requested Report Type not supported" },
	{ 39, "Request superseded" },
	{ 40, "Release due to UE generated signalling connection release" },
	{ 41, "Resource Optimisation Relocation" },
	{ 42, "Requested Information Not Available" },
	{ 43, "Relocation desirable for radio reasons" },
	{ 44, "Relocation not supported in Target RNC or Target System" },
	{ 45, "Directed Retry" },
	{ 46, "Radio Connection With UE Lost" },
/* Transport Layer Cause (65-->80) */
	{ 65, "Signalling Transport Resource Failure" },
	{ 66, "Iu Transport Connection Failed to Establish" },
/* NAS Cause (81-->96) */
	{ 81, "User Restriction Start Indication" },
	{ 82, "User Restriction End Indication" },
	{ 83, "Normal Release" },
/* Protocol Cause (97-->112) */
	{ 97, "Transfer Syntax Error" },
	{ 98, "Semantic Error" },
	{ 99, "Message not compatible with receiver state" },
	{ 100, "Abstract Syntax Error (Reject)" },
	{ 101, "Abstract Syntax Error (Ignore and Notify)" },
	{ 102, "Abstract Syntax Error (Falsely Constructed Message" },
/* Miscellaneous Cause (113-->128) */
	{ 113, "O & M Intervention" },
	{ 114, "No Resource Available" },
	{ 115, "Unspecified Failure" },
	{ 116, "Network Opimisation" },
/* Non-standard Cause (129-->255) */
	{ 0, NULL }
};

static const value_string mm_sec_modep[] = {
	{ 0,	"Used cipher value, UMTS keys and Quintuplets" },
	{ 1,	"GSM key and triplets" },
	{ 2,	"UMTS key and quintuplets" },
	{ 3,	"GSM key and quintuplets" },
	{ 0,	NULL }
};

static const value_string mm_proto_disc[] = {
	{ 0x00, "Group call control" },
	{ 0x01, "Broadcast call control" },
	{ 0x02, "PDSS1" },
	{ 0x03, "Call control; call related SS messages" },
	{ 0x04, "PDSS2" },
	{ 0x05, "Mobility Management messages for non-GPRS services" },
	{ 0x06, "Radio Resource management messages" },
	{ 0x08, "Mobility Management messages for GPRS services" },
	{ 0x09, "SMS" },
	{ 0x0A, "Session Management messages" },
	{ 0x0B, "Non-call related SS messages" },
	{ 0, NULL }
};

static const value_string mm_rr_mess[] = {
	{ 0x3C, "RR initialization request" },
	{ 0x3B, "Additional assignment" },
	{ 0x3F, "Immediate assignment" },
	{ 0x39, "Immediate assignment extended" },
	{ 0x3A, "Immediate assignment reject" },

	{ 0x35, "Ciphering mode command" },
	{ 0x32, "Ciphering mode complete" },

	{ 0x30, "Configuration change command" },
	{ 0x31, "Configuration change ack" },
	{ 0x33, "Configuration change reject" },
	
	{ 0x2E, "Assignment command" },
	{ 0x29, "Assignment complete" },
	{ 0x2F, "Assigment failure" },
	{ 0x2B, "Handover command" },
	{ 0x2C, "Handover complete" },
	{ 0x28, "Handover failure" },
	{ 0x2D, "Physical information" },

	{ 0x08, "RR-cell change order" },
	{ 0x23, "PDCH assignment command" },

	{ 0x0D, "Channel release" },
	{ 0x0A, "Partial release" },
	{ 0x0F, "PArtial release complete" },

	{ 0x21, "Paging request type 1" },
	{ 0x22, "Paging request type 2" },
	{ 0x24, "Paging request type 3" },
	{ 0x27, "Paging response" },
	{ 0x20, "Notification/NCH" },
	{ 0x25, "Notification/FACCH" },
	{ 0x26, "Reserved" },
	{ 0x0B, "Reserved" },

	{ 0x18, "System information type 8" },
	{ 0x19, "System information type 1" },
	{ 0x1A, "System information type 2" },
	{ 0x1B, "System information type 3" },
	{ 0x1C, "System information type 4" },
	{ 0x1D, "System information type 5" },
	{ 0x1E, "System information type 6" },
	{ 0x1F, "System information type 7" },

	{ 0x02, "System information type 2bis" },
	{ 0x03, "System information type 2ter" },
	{ 0x05, "System information type 5bis" },
	{ 0x06, "System information type 5ter" },
	{ 0x04, "System information 9" },
	{ 0x00, "System information 13" },
	{ 0x01, "System information 14" },

	{ 0x3D, "System information type 16" },
	{ 0x3E, "System information type 17" },

	{ 0x10, "Channel mode modify" },
	{ 0x12, "RR status" },
	{ 0x17, "Channel mode modify ack" },
	{ 0x14, "Frequency redefinition " },
	{ 0x15, "Measurement report" },
	{ 0x16, "Classmark change" },
	{ 0x13, "Classmark enquiry" },
	{ 0x36, "Extended measurement report" },
	{ 0x37, "Extended measurement order" },
	{ 0x34, "GPRS suspension request" },

	{ 0x09, "VGCS uplink grant" },
	{ 0x0E, "Uplink release" },
	{ 0x0C, "Uplink free" },
	{ 0x2A, "Uplink busy" },
	{ 0x11, "Talker indication" },

	{ 0, NULL }
};

static const value_string mm_mm_mess[] = {
	{ 0x01, "IMSI DETACH INDICATION" },
	{ 0x02, "LOCATION UPDATING ACCEPT" },
	{ 0x04, "LOCATION UPDATING REJECT" },
	{ 0x08, "LOCATION UPDATING REQUEST" },
	{ 0x11, "AUTHENTICATION REJECT" },
	{ 0x12, "AUTHENTICATION REQUEST" },
	{ 0x14, "AUTHENTICATION RESPONSE" },
	{ 0x18, "IDENTITY REQUEST" },
	{ 0x19, "IDENTITY RESPONSE" },
	{ 0x1A, "TMSI REALLOCATION COMMAND" },
	{ 0x1B, "TMSI REALLOCATION COMPLETE" },
	{ 0x21, "CM SERVICE ACCEPT" },
	{ 0x22, "CM SERVICE REJECT" },
	{ 0x23, "CM SERVICE ABORT" },
	{ 0x24, "CM SERVICE REQUEST" },
	{ 0x25, "CM SERVICE PROMPT" },
	{ 0x26, "NOTIFICATION RESPONSE" },
	{ 0x28, "CM RE-ESTABLISHMENT REQUEST" },
	{ 0x29, "ABORT" },
	{ 0x30, "MM NULL" },
	{ 0x31, "MM STATUS" },
	{ 0x32, "MM INFORMATION" },
	{ 0, NULL }
};

static const value_string mm_cc_mess[] = { 			
	{ 0x00, "escape to nationally specific" },
/*{ 0 x 0 0, "- - - Call establishment messages:" },*/
	{ 0x01, "ALERTING" },
	{ 0x08, "CALL CONFIRMED" },
	{ 0x02, "CALL PROCEEDING" },
	{ 0x07, "CONNECT" },
	{ 0x0F, "CONNECT ACKNOWLEDGE" },
	{ 0x0E, "EMERGENCY SETUP" },
	{ 0x03, "PROGRESS" },
	{ 0x04, "CC-ESTABLISHMENT" },
	{ 0x06, "CC-ESTABLISHMENT CONFIRMED" },
	{ 0x0B, "RECALL" },
	{ 0x09, "START CC" },
	{ 0x05, "SETUP" },
/*{ 0 x 0 1, "- - - Call information phase messages:" },*/
	{ 0x17, "MODIFY" },
	{ 0x1F, "MODIFY COMPLETE" },
	{ 0x13, "MODIFY REJECT" },
	{ 0x10, "USER INFORMATION" },
	{ 0x18, "HOLD" },
	{ 0x19, "HOLD ACKNOWLEDGE" },
	{ 0x1A, "HOLD REJECT" },
	{ 0x1C, "RETRIEVE" },
	{ 0x1D, "RETRIEVE ACKNOWLEDGE" },
	{ 0x1E, "RETRIEVE REJECT" },
/*{ 0 x 1 0, "- - - Call clearing messages:" },*/
	{ 0x25, "DISCONNECT" },
	{ 0x2D, "RELEASE" },
	{ 0x2A, "RELEASE COMPLETE" },
/*{ 0 x 1 1, "- - - Miscellaneous messages:" },*/
	{ 0x39, "CONGESTION CONTROL" },
	{ 0x3E, "NOTIFY" },
	{ 0x3D, "STATUS" },
	{ 0x34, "STATUS ENQUIRY" },
	{ 0x35, "START DTMF" },
	{ 0x31, "STOP DTMF" },
	{ 0x32, "STOP DTMF ACKNOWLEDGE" },
	{ 0x36, "START DTMF ACKNOWLEDGE" },
	{ 0x37, "START DTMF REJECT" },
	{ 0x3A, "FACILITY" },
	{ 0, NULL }
};

static const value_string mm_gprs_mess[] = {
	{ 0x01, "Attach request" },
	{ 0x02, "Attach accept" },
	{ 0x03, "Attach complete" },
	{ 0x04, "Attach reject" },
	{ 0x05, "Detach request" },
	{ 0x06, "Detach accept" },
	{ 0x08, "Routing area update request" },
	{ 0x09, "Routing area update accept" },
	{ 0x0A, "Routing area update complete" },
	{ 0x0B, "Routing area update reject" },
	{ 0x10, "P-TMSI reallocation command" },
	{ 0x11, "P-TMSI reallocation complete" },
	{ 0x12, "Authentication and ciphering req" },
	{ 0x13, "Authentication and ciphering resp" },
	{ 0x14, "Authentication and ciphering rej" },
	{ 0x15, "Identity request" },
	{ 0x16, "Identity response" },
	{ 0x20, "GMM status" },
	{ 0x21, "GMM information" },
	{ 0, NULL }
};

static const value_string tft_code_type[] = {
	{ 0, "Spare" },
	{ 1, "Create new TFT" },
	{ 2, "Delete existing TFT" },
	{ 3, "Add packet filters to existing TFT" },
	{ 4, "Replace packet filters in existing TFT" },
	{ 5, "Delete packet filters from existing TFT" },
	{ 6, "Reserved" },
	{ 7, "Reserved" },
	{ 0, NULL }
};

static const value_string cdr_close_type[] = {
	{ 0, "PDP release" },
	{ 1, "Volume limit" },
	{ 2, "Time limit" },
	{ 3, "SGSN change" },
	{ 4, "Max changes" },
	{ 6, "Management" },
	{ 7, "Abnormal" },
	{ 0, NULL }
};
			
static dissector_handle_t ip_handle;
static dissector_handle_t ppp_handle;

static int decode_gtp_cause		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_imsi		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_rai		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_tlli		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_ptmsi		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_qos_gprs		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_reorder		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_auth_tri		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_map_cause		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_ptmsi_sig		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_ms_valid		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_recovery		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_sel_mode		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_16		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_17		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_18		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_19		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_nsapi		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_ranap_cause	(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_rab_cntxt		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_rp_sms		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_rp		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_pkt_flow_id	(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_chrg_char		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_trace_ref		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_trace_type	(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_ms_reason		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_tr_comm		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_chrg_id		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_user_addr		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_mm_cntxt		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_pdp_cntxt		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_apn		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_gsn_addr		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_proto_conf	(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_msisdn		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_qos_umts		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_auth_qui		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_tft		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_target_id		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_utran_cont	(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_rab_setup		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_hdr_list		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_trigger_id	(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_omc_id		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_chrg_addr		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_rel_pack		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_can_pack		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_data_req		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_data_resp		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_node_addr		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_priv_ext		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_unknown		(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

typedef struct _gtp_opt {
	int   optcode; 
/*	char  *name; */
	int  (*decode)(tvbuff_t  *, int, packet_info *, proto_tree *);
} gtp_opt_t;

static const gtp_opt_t gtpopt[] = {
	{ GTP_EXT_CAUSE,	decode_gtp_cause },
	{ GTP_EXT_IMSI,		decode_gtp_imsi },
	{ GTP_EXT_RAI,		decode_gtp_rai },
	{ GTP_EXT_TLLI,		decode_gtp_tlli },
	{ GTP_EXT_PTMSI,	decode_gtp_ptmsi },
	{ GTP_EXT_QOS_GPRS,	decode_gtp_qos_gprs },
	{ GTP_EXT_REORDER,	decode_gtp_reorder },
	{ GTP_EXT_AUTH_TRI,	decode_gtp_auth_tri },
	{ GTP_EXT_MAP_CAUSE,	decode_gtp_map_cause },
	{ GTP_EXT_PTMSI_SIG,	decode_gtp_ptmsi_sig },
	{ GTP_EXT_MS_VALID,	decode_gtp_ms_valid },
	{ GTP_EXT_RECOVER,	decode_gtp_recovery },
	{ GTP_EXT_SEL_MODE,	decode_gtp_sel_mode },
	{ GTP_EXT_16,		decode_gtp_16 },
	{ GTP_EXT_17,		decode_gtp_17 },
	{ GTP_EXT_18,		decode_gtp_18 },
	{ GTP_EXT_19,		decode_gtp_19 },
	{ GTP_EXT_NSAPI,	decode_gtp_nsapi },
	{ GTP_EXT_RANAP_CAUSE,	decode_gtp_ranap_cause },
	{ GTP_EXT_RAB_CNTXT,	decode_gtp_rab_cntxt },
	{ GTP_EXT_RP_SMS,	decode_gtp_rp_sms },
	{ GTP_EXT_RP,		decode_gtp_rp },
	{ GTP_EXT_PKT_FLOW_ID,	decode_gtp_pkt_flow_id },
	{ GTP_EXT_CHRG_CHAR,	decode_gtp_chrg_char },
	{ GTP_EXT_TRACE_REF,	decode_gtp_trace_ref },
	{ GTP_EXT_TRACE_TYPE,	decode_gtp_trace_type },
	{ GTPv1_EXT_MS_REASON,	decode_gtp_ms_reason },
	{ GTP_EXT_TR_COMM,	decode_gtp_tr_comm },
	{ GTP_EXT_CHRG_ID,	decode_gtp_chrg_id },
	{ GTP_EXT_USER_ADDR,	decode_gtp_user_addr },
	{ GTP_EXT_MM_CNTXT,	decode_gtp_mm_cntxt },
	{ GTP_EXT_PDP_CNTXT,	decode_gtp_pdp_cntxt },
	{ GTP_EXT_APN,		decode_gtp_apn },
	{ GTP_EXT_PROTO_CONF,	decode_gtp_proto_conf },
	{ GTP_EXT_GSN_ADDR,	decode_gtp_gsn_addr },
	{ GTP_EXT_MSISDN,	decode_gtp_msisdn },
	{ GTP_EXT_QOS_UMTS,	decode_gtp_qos_umts },				/* 3G */
	{ GTP_EXT_AUTH_QUI,	decode_gtp_auth_qui },				/* 3G */
	{ GTP_EXT_TFT,		decode_gtp_tft },				/* 3G */
	{ GTP_EXT_TARGET_ID,	decode_gtp_target_id },			/* 3G */
	{ GTP_EXT_UTRAN_CONT,	decode_gtp_utran_cont },			/* 3G */
	{ GTP_EXT_RAB_SETUP,	decode_gtp_rab_setup },			/* 3G */
	{ GTP_EXT_HDR_LIST,	decode_gtp_hdr_list },				/* 3G */
	{ GTP_EXT_TRIGGER_ID,	decode_gtp_trigger_id },			/* 3G */
	{ GTP_EXT_OMC_ID,	decode_gtp_omc_id },				/* 3G */
	{ GTP_EXT_REL_PACK,	decode_gtp_rel_pack },				/* charging */
	{ GTP_EXT_CAN_PACK,	decode_gtp_can_pack }, 			/* charging */
	{ GTP_EXT_CHRG_ADDR,	decode_gtp_chrg_addr },
	{ GTP_EXT_DATA_REQ,	decode_gtp_data_req },				/* charging */
	{ GTP_EXT_DATA_RESP,	decode_gtp_data_resp },			/* charging */
	{ GTP_EXT_NODE_ADDR,	decode_gtp_node_addr },
	{ GTP_EXT_PRIV_EXT,	decode_gtp_priv_ext },
	{ 0, 			decode_gtp_unknown }
};

typedef struct {
	guint8		flags;
	guint8		message;
	guint16		length;
	guint16		seq_no;
	guint16		flow_label;
	guint8		sndcp_no;
	guint8		spare[3];
	guint8		tid[8];
} _gtpv0_hdr;

typedef struct {
	guint8		flags;
	guint8		message;
	guint16		length;
	guint32		teid;
} _gtpv1_hdr;

struct gcdr_ {					/* GCDR 118B */
	guint8		imsi[8];
	guint32		ggsnaddr;
	guint32		chrgid;
	guint32		sgsnaddr;
	gchar		apn[63];
	guint8		pdporg;
	guint8		pdptype;
	guint32		pdpaddr;
	guint8		addrflag;
	guint8		qos[3];
	guint32		uplink;
	guint32		downlink;
	guint32		timestamp;
	guint32		opening;
	guint32		duration;
	guint8		closecause;
	guint32		seqno;
	guint8		msisdn[9];
} gcdr;

typedef struct change_ {
	guint8		change;
	guint32		time1;
	guint32		time2;
	guint32		uplink;
	guint32		downlink;
	guint8		qos_req[3];
	guint8		qos_neg[3];
} change_t;

struct _scdr {					/* SCDR 277B */
	guint16		len;
	guint8		netini;
	guint8		anon;
	guint8		imsilen;
	guint8		imsi[8];
	guint8		imei[8];
	guint8		msisdnlen;
	guint8		msisdn[10];
	guint32		sgsnaddr;
	guint8		msclass_notused[12];
	guint8		msclass_caplen;
	guint8		msclass_cap;
	guint16		msclass_capomit;
	guint16		lac;
	guint8		rac;
	guint16		cid;
	guint32		chrgid;
	guint32		ggsnaddr;
	gchar		apn[64];
	guint8		pdporg;
	guint8		pdptype;
	guint32		pdpaddr;
	guint8		listind;
	change_t	change[5];
	guint32		timestamp;
	guint32		opening;
	guint32		duration;
	guint8		sgsnchange;
	guint8		closecause;
	guint8		diag1;
	guint8		diag2;
	guint8		diag3;
	guint8		diag4;
	guint32		diag5;
	guint32		seqno;
} scdr;

typedef struct mmchange_ {
	guint16		lac;
	guint8		rac;
	guint16		cid;
	guint8		omit[8];
} mmchange_t;

struct _mcdr {					/* MCDR 147B */
	guint16		len;
	guint8		imsilen;
	guint8		imsi[8];
	guint8		imei[8];
	guint8		msisdnlen;
	guint8		msisdn[10];
	guint32		sgsnaddr;
	guint8		msclass_notused[12];
	guint8		msclass_caplen;
	guint8		msclass_cap;
	guint16		msclass_capomit;
	guint16		lac;
	guint8		rac;
	guint16		cid;
	guint8		change_count;
	mmchange_t	change[5];
	guint32		timestamp;
	guint32		opening;
/*	guint8		opening[8]; */
	guint32		duration;
	guint8		sgsnchange;
	guint8		closecause;
	guint8		diag1;
	guint8		diag2;
	guint8		diag3;
	guint8		diag4;
	guint32		diag5;
	guint32		seqno;
} mcdr;

struct _socdr {						/* SOCDR 80B */
	guint16		len;
	guint8		imsilen;
	guint8		imsi[8];
	guint8		imei[8];
	guint8		msisdnlen;
	guint8		msisdn[10];
	guint8		msclass_notused[12];
	guint8		msclass_caplen;
	guint8		msclass_cap;
	guint16		msclass_capomit;
	guint8		serv_centr[9];
	guint8		rec_ent[9];
	guint16		lac;
	guint8		rac;
	guint16		cid;
	guint32		time1;
	guint32		time2;
	guint8		messref;
	guint16		smsres;
} socdr;


struct _stcdr {						/* STCDR 79B */
	guint16		len;
	guint8		imsilen;
	guint8		imsi[8];
	guint8		imei[8];
	guint8		msisdnlen;
	guint8		msisdn[10];
	guint8		msclass_notused[12];
	guint8		msclass_caplen;
	guint8		msclass_cap;
	guint16		msclass_capomit;
	guint8		serv_centr[9];
	guint8		rec_ent[9];
	guint16		lac;
	guint8		rac;
	guint16		cid;
	guint32		time1;
	guint32		time2;
	guint16		smsres;
} stcdr;
	
	guint8		gtp_version = 0;
	char		*yesno[] = { "False", "True" };
	
static void
col_append_str_gtp(column_info *cinfo, gint el, gchar *proto_name) {
	
	int	i;
	int	max_len;
	gchar	_tmp[COL_MAX_LEN];

	max_len = COL_MAX_LEN;

	for (i = 0; i < cinfo->num_cols; i++) {
		if (cinfo->fmt_matx[i][el]) {
			if (cinfo->col_data[i] != cinfo->col_buf[i]) {
				
    				strncpy(cinfo->col_buf[i], cinfo->col_data[i], max_len);
    				cinfo->col_buf[i][max_len - 1] = '\0';
      			}
	
			_tmp[0] = '\0';
			strcat(_tmp, proto_name);
			strcat(_tmp, " <");
			strcat(_tmp, cinfo->col_buf[i]);
			strcat(_tmp, ">");
			cinfo->col_buf[i][0] = '\0';
			strcat(cinfo->col_buf[i], _tmp);
			cinfo->col_data[i] = cinfo->col_buf[i];
		}
	}
}

static gchar *
id_to_str(const guint8 *ad) {
		
	static gchar	*str[17];
	gchar		*p;
	guint8		bits8to5, bits4to1, i;
	static const	gchar hex_digits[10] = "0123456789";

	p = (gchar *)&str[17];
	*--p = '\0';
	i = 7;
	for (;;) {
		bits8to5 = (ad[i] >> 4) & 0x0F;
		bits4to1 = ad[i] & 0x0F;
		if (bits8to5 < 0xA) *--p = hex_digits[bits8to5]; 
		if (bits4to1 < 0xA) *--p = hex_digits[bits4to1];
		if (i == 0) break;
		i--;
	}
	return p;
}

static gchar *
msisdn_to_str(const guint8 *ad, int len) {
		
	static gchar	*str[17];
	gchar		*p;
	guint8		bits8to5, bits4to1, i;
	static const	gchar hex_digits[16] = "0123456789      ";

	p = (gchar *)&str[0];
	*p = '+';
	i = 1;
	for (;;) {
		bits8to5 = (ad[i] >> 4) & 0x0F;
		bits4to1 = ad[i] & 0x0F;
		if (bits4to1 < 0xA) *++p = hex_digits[bits4to1];
		if (bits8to5 < 0xA) *++p = hex_digits[bits8to5];
		if (i == len-1) break;
		i++;
	}
	*++p = '\0';
	return (gchar *)&str[0];
}

gchar *
time_int_to_str (guint32 time)
{

	nstime_t	nstime;

	nstime.secs = time;
	nstime.nsecs = 0;

	return abs_time_to_str (&nstime);
}

gchar *
rel_time_int_to_str (guint32 time)
{

	nstime_t	nstime;

	nstime.secs = time;
	nstime.nsecs = 0;

	return rel_time_to_str (&nstime);
}

/* Next definitions and function check_field_presence checks if given field 
 * in GTP packet is compliant with ETSI 
 */
typedef struct _header {
	guint8		code;
	guint8		presence;
} ext_header;

typedef struct _message {
	guint8		code;
	ext_header	fields[32];
} _gtp_mess_items;

/* ---------------------
 * GPRS messages 
 * ---------------------*/
_gtp_mess_items gprs_mess_items[] = {

{
	GTP_MSG_ECHO_REQ, {					
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_ECHO_RESP, {
		{ GTP_EXT_RECOVER,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_VER_NOT_SUPP, {
		{ 0,			0 }
	}
},
{
	GTP_MSG_NODE_ALIVE_REQ, {
		{ GTP_EXT_NODE_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_NODE_ALIVE_RESP, {
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_REDIR_REQ, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_NODE_ADDR,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_REDIR_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{ 
	GTP_MSG_CREATE_PDP_REQ, {
		{ GTP_EXT_QOS_GPRS, 	MANDATORY },
		{ GTP_EXT_RECOVER, 	OPTIONAL },
		{ GTP_EXT_SEL_MODE, 	MANDATORY },
		{ GTP_EXT_FLOW_LABEL,	MANDATORY },
		{ GTP_EXT_FLOW_SIG,	MANDATORY },
		{ GTP_EXT_MSISDN,	MANDATORY },
		{ GTP_EXT_USER_ADDR,	MANDATORY },
		{ GTP_EXT_APN,		MANDATORY },
		{ GTP_EXT_PROTO_CONF,	OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0, 			0 }
	}
},
{ 
	GTP_MSG_CREATE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_QOS_GPRS,	CONDITIONAL },
		{ GTP_EXT_REORDER,	CONDITIONAL },
		{ GTP_EXT_RECOVER,	OPTIONAL },
		{ GTP_EXT_FLOW_LABEL,	CONDITIONAL },
		{ GTP_EXT_FLOW_SIG,	CONDITIONAL },
		{ GTP_EXT_CHRG_ID,	CONDITIONAL },
		{ GTP_EXT_USER_ADDR,	CONDITIONAL },
		{ GTP_EXT_PROTO_CONF,	OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_CHRG_ADDR,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0, 			0 }
	}
},
{	
	GTP_MSG_UPDATE_PDP_REQ, {
		{ GTP_EXT_QOS_GPRS,	MANDATORY },
		{ GTP_EXT_RECOVER,	OPTIONAL },
		{ GTP_EXT_FLOW_LABEL,	MANDATORY },
		{ GTP_EXT_FLOW_SIG,	MANDATORY },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0, 			0 },
	}
},
{
	GTP_MSG_UPDATE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_QOS_GPRS,	CONDITIONAL },
		{ GTP_EXT_RECOVER,	OPTIONAL },
		{ GTP_EXT_FLOW_LABEL,	CONDITIONAL },
		{ GTP_EXT_FLOW_SIG,	CONDITIONAL },
		{ GTP_EXT_CHRG_ID,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_CHRG_ADDR,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DELETE_PDP_REQ, {
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DELETE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 },
	}
},
{
	GTP_MSG_CREATE_AA_PDP_REQ, {
		{ GTP_EXT_QOS_GPRS, 	MANDATORY },
		{ GTP_EXT_RECOVER, 	OPTIONAL },
		{ GTP_EXT_SEL_MODE, 	MANDATORY },
		{ GTP_EXT_FLOW_LABEL,	MANDATORY },
		{ GTP_EXT_FLOW_SIG,	MANDATORY },
		{ GTP_EXT_USER_ADDR,	MANDATORY },
		{ GTP_EXT_APN,		MANDATORY },
		{ GTP_EXT_PROTO_CONF,	OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_CREATE_AA_PDP_RESP, {					
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_QOS_GPRS,	CONDITIONAL },
		{ GTP_EXT_REORDER,	CONDITIONAL },
		{ GTP_EXT_RECOVER,	OPTIONAL },
		{ GTP_EXT_FLOW_LABEL,	CONDITIONAL },
		{ GTP_EXT_FLOW_SIG,	CONDITIONAL },
		{ GTP_EXT_CHRG_ID,	CONDITIONAL },
		{ GTP_EXT_USER_ADDR,	CONDITIONAL },
		{ GTP_EXT_PROTO_CONF,	OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_CHRG_ADDR,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_DELETE_AA_PDP_REQ, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DELETE_AA_PDP_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_ERR_IND, {
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REQ, {
		{ GTP_EXT_USER_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{	
	GTP_MSG_PDU_NOTIFY_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REJ_REQ, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_USER_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REJ_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SEND_ROUT_INFO_REQ, {
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SEND_ROUT_INFO_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_MAP_CAUSE,	OPTIONAL },
		{ GTP_EXT_MS_REASON,	OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FAIL_REP_REQ, {
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FAIL_REP_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_MAP_CAUSE,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_MS_PRESENT_REQ, {
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_MS_PRESENT_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_IDENT_REQ, {
		{ GTP_EXT_RAI,		MANDATORY },
		{ GTP_EXT_PTMSI,	MANDATORY },
		{ GTP_EXT_PTMSI_SIG,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_IDENT_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_IMSI,		CONDITIONAL },
		{ GTP_EXT_AUTH_TRI,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_REQ, {
		{ GTP_EXT_IMSI,		CONDITIONAL },
		{ GTP_EXT_RAI,		MANDATORY },
		{ GTP_EXT_TLLI,		MANDATORY },
		{ GTP_EXT_PTMSI_SIG,	OPTIONAL },
		{ GTP_EXT_MS_VALID,	OPTIONAL },
		{ GTP_EXT_FLOW_SIG, 	MANDATORY },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_IMSI,		CONDITIONAL },
		{ GTP_EXT_FLOW_SIG,	CONDITIONAL },
		{ GTP_EXT_MM_CNTXT,	CONDITIONAL },
		{ GTP_EXT_PDP_CNTXT,	CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_ACK, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_FLOW_II,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DATA_TRANSF_REQ, {
		{ GTP_EXT_TR_COMM,	MANDATORY },
		{ GTP_EXT_DATA_REQ,	CONDITIONAL },
		{ GTP_EXT_REL_PACK,	CONDITIONAL },
		{ GTP_EXT_CAN_PACK,	CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DATA_TRANSF_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_DATA_RESP,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	0, {
		{ 0, 			0 }
	}
}
};

/* -----------------------------
 * UMTS messages 
 * -----------------------------*/
_gtp_mess_items umts_mess_items[] = {

{
	GTP_MSG_ECHO_REQ, {					
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_ECHO_RESP, {
		{ GTP_EXT_RECOVER,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_VER_NOT_SUPP, {
		{ 0,			0 }
	}
},
{
	GTP_MSG_NODE_ALIVE_REQ, {
		{ GTP_EXT_NODE_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_NODE_ALIVE_RESP, {
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_REDIR_REQ, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_NODE_ADDR,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_REDIR_REQ, {
		{ 0,			0 }
	}
},
{
	GTP_MSG_CREATE_PDP_REQ, {
		{ GTP_EXT_IMSI,		CONDITIONAL },
		{ GTP_EXT_RECOVER, 	OPTIONAL },
		{ GTP_EXT_SEL_MODE, 	CONDITIONAL },
		{ GTP_EXT_TEID,		MANDATORY },
		{ GTP_EXT_TEID_CP,	CONDITIONAL },
		{ GTP_EXT_NSAPI,	MANDATORY },
		{ GTP_EXT_NSAPI,	CONDITIONAL },
		{ GTP_EXT_CHRG_CHAR,	OPTIONAL },
		{ GTP_EXT_TRACE_REF,	OPTIONAL },
		{ GTP_EXT_TRACE_TYPE,	OPTIONAL },
		{ GTP_EXT_USER_ADDR,	CONDITIONAL },
		{ GTP_EXT_APN,		CONDITIONAL },
		{ GTP_EXT_PROTO_CONF,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_MSISDN,	CONDITIONAL },
		{ GTP_EXT_QOS_UMTS,	MANDATORY },
		{ GTP_EXT_TFT,		CONDITIONAL },
		{ GTP_EXT_TRIGGER_ID,	OPTIONAL },
		{ GTP_EXT_OMC_ID,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_CREATE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_REORDER,	CONDITIONAL },
		{ GTP_EXT_RECOVER,	OPTIONAL },
		{ GTP_EXT_TEID,		CONDITIONAL },
		{ GTP_EXT_TEID_CP,	CONDITIONAL },
		{ GTP_EXT_CHRG_ID,	CONDITIONAL },
		{ GTP_EXT_USER_ADDR,	CONDITIONAL },
		{ GTP_EXT_PROTO_CONF,	OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_QOS_UMTS,	CONDITIONAL },
		{ GTP_EXT_CHRG_ADDR,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{	/* checked, SGSN -> GGSN */
	GTP_MSG_UPDATE_PDP_REQ, {
		{ GTP_EXT_IMSI,		CONDITIONAL },
		{ GTP_EXT_RECOVER,	OPTIONAL },
		{ GTP_EXT_TEID,		MANDATORY },
		{ GTP_EXT_TEID_CP,	CONDITIONAL },
		{ GTP_EXT_NSAPI,	MANDATORY },
		{ GTP_EXT_TRACE_REF,	OPTIONAL },
		{ GTP_EXT_TRACE_TYPE,	OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_QOS_UMTS,	MANDATORY },
		{ GTP_EXT_TFT,		OPTIONAL },
		{ GTP_EXT_TRIGGER_ID,	OPTIONAL },
		{ GTP_EXT_OMC_ID,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{	/* checked, GGSN -> SGSN */
	GTP_MSG_UPDATE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_RECOVER,	OPTIONAL },
		{ GTP_EXT_TEID,		CONDITIONAL },
		{ GTP_EXT_TEID_CP,	CONDITIONAL },
		{ GTP_EXT_CHRG_ID,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_QOS_UMTS,	CONDITIONAL },
		{ GTP_EXT_CHRG_ADDR,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DELETE_PDP_REQ, {
		{ GTP_EXT_TEAR_IND,	CONDITIONAL },
		{ GTP_EXT_NSAPI,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DELETE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_ERR_IND, {
		{ GTP_EXT_TEID,		MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REQ, {
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_TEID_CP,	MANDATORY },
		{ GTP_EXT_USER_ADDR,	MANDATORY },
		{ GTP_EXT_APN,		MANDATORY },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REJ_REQ, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_TEID_CP,	MANDATORY },
		{ GTP_EXT_USER_ADDR,	MANDATORY },
		{ GTP_EXT_APN,		MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REJ_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SUPP_EXT_HDR, {
		{ GTP_EXT_HDR_LIST,	MANDATORY },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SEND_ROUT_INFO_REQ, {
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SEND_ROUT_INFO_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_MAP_CAUSE,	OPTIONAL },
		{ GTPv1_EXT_MS_REASON,	OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FAIL_REP_REQ, {
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FAIL_REP_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_MAP_CAUSE,	OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_MS_PRESENT_REQ, {
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_MS_PRESENT_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_IDENT_REQ, {
		{ GTP_EXT_RAI,		MANDATORY },
		{ GTP_EXT_PTMSI,	MANDATORY },
		{ GTP_EXT_PTMSI_SIG,	CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_IDENT_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_IMSI,		CONDITIONAL },
		{ GTP_EXT_AUTH_TRI,	CONDITIONAL },
		{ GTP_EXT_AUTH_QUI,	CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_REQ,	{
		{ GTP_EXT_IMSI,		CONDITIONAL },
		{ GTP_EXT_RAI,		MANDATORY },
		{ GTP_EXT_TLLI,		CONDITIONAL },
		{ GTP_EXT_PTMSI,	CONDITIONAL },
		{ GTP_EXT_PTMSI_SIG,	CONDITIONAL },
		{ GTP_EXT_MS_VALID,	OPTIONAL },
		{ GTP_EXT_TEID_CP,	MANDATORY },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_IMSI,		CONDITIONAL },
		{ GTP_EXT_TEID_CP,	CONDITIONAL },
		{ GTP_EXT_RP_SMS,	OPTIONAL },
		{ GTP_EXT_RP,		OPTIONAL },
		{ GTP_EXT_PKT_FLOW_ID,	OPTIONAL },
		{ GTP_EXT_MM_CNTXT,	CONDITIONAL },
		{ GTP_EXT_PDP_CNTXT,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_ACK, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_TEID_II,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_RELOC_REQ, {
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_TEID_CP,	MANDATORY },
		{ GTP_EXT_RANAP_CAUSE,	MANDATORY },
		{ GTP_EXT_MM_CNTXT,	MANDATORY },
		{ GTP_EXT_PDP_CNTXT,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	MANDATORY },
		{ GTP_EXT_TARGET_ID,	MANDATORY },
		{ GTP_EXT_UTRAN_CONT,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_RELOC_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_TEID_CP,	CONDITIONAL },
		{ GTP_EXT_RANAP_CAUSE,	CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	CONDITIONAL },
		{ GTP_EXT_UTRAN_CONT,	OPTIONAL },
		{ GTP_EXT_RAB_SETUP,	CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_RELOC_COMP, {
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_RELOC_CANCEL_REQ, {
		{ GTP_EXT_IMSI,		MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_RELOC_CANCEL_RESP, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_RELOC_ACK, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_SRNS_CNTXT, {
		{ GTP_EXT_RAB_CNTXT,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_SRNS_CNTXT_ACK, {
		{ GTP_EXT_CAUSE,	MANDATORY },
		{ GTP_EXT_PRIV_EXT,	OPTIONAL },
		{ 0,			0 }
	}
},
{
	0, {
		{ 0, 			0 }
	}
}
};

static int 
check_field_presence(guint8 message, guint8 field, int *position) {
	
	guint			i = 0;
	_gtp_mess_items		*mess_items;

	switch(gtp_version) {
		case 0: 
			mess_items = gprs_mess_items;
			break;
		case 1: 
			mess_items = umts_mess_items;
			break;
		default:
			return -2;
	}

	while (mess_items[i].code) {
		if (mess_items[i].code == message) {
			
			while (mess_items[i].fields[*position].code) {
				if (mess_items[i].fields[*position].code == field) {
					(*position)++;
					return 0;
				} else { 
				if (mess_items[i].fields[*position].presence == MANDATORY) {
					return mess_items[i].fields[(*position)++].code;
				} else {
					(*position)++;
				}}
			}
			return -1;
		}
		i++;
	}	

	return -2;
}

/* Decoders of fields in extension headers, each function returns no of bytes from field */

/* GPRS:	9.60 v7.6.0, chapter
 * UMTS:	29.060 v4.0, chapter
 */
static int
decode_gtp_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint8	cause;
	
	cause = tvb_get_guint8(tvb, offset+1);	
	
	proto_tree_add_uint(tree, gtp_version ? hf_gtpv1_cause : hf_gtpv0_cause, tvb, offset, 2, cause);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.2
 * UMTS:	29.060 v4.0, chapter 7.7.2
 */
static int 
decode_gtp_imsi(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	tid_val[8];
	gchar	*tid_str;

	tvb_memcpy(tvb, tid_val, offset+1, 8);
	tid_val[1] = tid_val[1] & 0x0F;
	tid_str = id_to_str(tid_val);
	
	proto_tree_add_string(tree, gtp_version ? hf_gtpv1_imsi : hf_gtpv0_imsi, tvb, offset, 9, tid_str);

	return 9;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.3
 * UMTS:	29.060 v4.0, chapter 7.7.3
 * TODO: Add details about MCC, MNC, LAC, RAC (show each digit) ?
 */
static int
decode_gtp_rai(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	proto_tree	*ext_tree_rai;
	proto_item	*te;
	guint8		byte[3];
	
	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_RAI, gtp_val, "Unknown message")); 
	ext_tree_rai = proto_item_add_subtree(te, ett_gtp_rai);
	
//	tvb_memcpy (tvb, (guint8 *)&byte, offset + 1, 3);
	byte[1] = tvb_get_guint8 (tvb, offset + 1);
	byte[2] = tvb_get_guint8 (tvb, offset + 2);
	byte[3] = tvb_get_guint8 (tvb, offset + 3);
	
	
	proto_tree_add_uint(ext_tree_rai, gtp_version ? hf_gtpv1_rai_mcc : hf_gtpv0_rai_mcc, tvb, offset+1, 2, (byte[1] & 0x0F) * 100 + ((byte[1] & 0xF0) >> 4) * 10  + (byte[2] & 0x0F ));
	proto_tree_add_uint(ext_tree_rai, gtp_version ? hf_gtpv1_rai_mnc : hf_gtpv0_rai_mnc, tvb, offset+2, 2, ((byte[3] & 0xF0) >> 4 ) * 10  + (byte[3] & 0x0F));
	proto_tree_add_uint(ext_tree_rai, gtp_version ? hf_gtpv1_rai_lac : hf_gtpv0_rai_lac, tvb, offset+4, 2, tvb_get_ntohs (tvb, offset+4));
	proto_tree_add_uint(ext_tree_rai, gtp_version ? hf_gtpv1_rai_rac : hf_gtpv0_rai_rac, tvb, offset+6, 1, tvb_get_guint8 (tvb, offset+6));

	return 7;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.4, page 39
 * UMTS:	29.060 v4.0, chapter 7.7.4, page 47
 */
static int
decode_gtp_tlli(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint32	tlli;
	
	tlli = tvb_get_ntohl(tvb, offset+1);	
	proto_tree_add_uint(tree, gtp_version ? hf_gtpv1_tlli : hf_gtpv0_tlli, tvb, offset, 5, tlli); 

	return 5;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.5, page 39
 * UMTS:	29.060 v4.0, chapter 7.7.5, page 47
 */
static int
decode_gtp_ptmsi(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint32	ptmsi;
	
	ptmsi = tvb_get_ntohl(tvb, offset);	
	proto_tree_add_uint(tree, gtp_version ? hf_gtpv1_ptmsi : hf_gtpv0_ptmsi, tvb, offset, 5, ptmsi);

	return 5;
}

/* adjust - how many bytes before offset should be highlighted 
 */
static int
decode_qos_gprs(tvbuff_t *tvb, int offset, proto_tree *tree, gchar* qos_str, guint8 adjust) {
	
	guint8		spare1, delay, reliability, peak, spare2,  precedence, spare3, mean;
	proto_tree	*ext_tree_qos;
	proto_item	*te;
	
	spare1 = tvb_get_guint8(tvb, offset) & 0xC0;
	delay = tvb_get_guint8(tvb, offset) & 0x38;
	reliability = tvb_get_guint8(tvb, offset) & 0x07;
	peak = tvb_get_guint8(tvb, offset+1) & 0xF0;
	spare2 = tvb_get_guint8(tvb, offset+1) & 0x08;
	precedence = tvb_get_guint8(tvb, offset+1) & 0x07;
	spare3 = tvb_get_guint8(tvb, offset+2) & 0xE0;
	mean = tvb_get_guint8(tvb, offset+2) & 0x1F;
	
	te = proto_tree_add_text(tree, tvb, offset-adjust, 3+adjust, "%s: delay: %u, reliability: %u, peak: %u, precedence: %u, mean: %u",
				                                        qos_str, delay, reliability, peak, precedence, mean);
	ext_tree_qos = proto_item_add_subtree(te, ett_gtp_qos);

	if (adjust != 0) {
		proto_tree_add_uint(ext_tree_qos, hf_gtpv0_qos_spare1, tvb, offset, 1, spare1);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv0_qos_delay, tvb, offset, 1, delay);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv0_qos_reliability, tvb, offset, 1, reliability);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv0_qos_peak, tvb, offset+1, 1, peak);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv0_qos_spare2, tvb, offset+1, 1, spare2);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv0_qos_precedence, tvb, offset+1, 1, precedence);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv0_qos_spare3, tvb, offset+2, 1, spare3);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv0_qos_mean, tvb, offset+2, 1, mean);
	}

	return 3; 
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.6, page 39
 * 		4.08
 * 		3.60
 * UMTS: 	not present
 * TODO:	check if length is included: ETSI 4.08 vs 9.60 
 */
static int
decode_gtp_qos_gprs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	return (1+decode_qos_gprs(tvb, offset+1, tree, "Quality of Service", 1));
	
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.7, page 39
 * UMTS:	29.060 v4.0, chapter 7.7.6, page 47
 */
static int
decode_gtp_reorder(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint8	reorder;
	
	reorder = tvb_get_guint8(tvb, offset+1) & 0x01;	
	proto_tree_add_boolean(tree, gtp_version ? hf_gtpv1_reorder : hf_gtpv0_reorder, tvb, offset, 2, reorder); 

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.8, page 40
 * 		4.08 v7.1.2, chapter 10.5.3.1+ 
 * UMTS:	29.060 v4.0, chapter 7.7.7
 * TODO: Add blurb support by registering items in the protocol registration
 */
static int
decode_gtp_auth_tri(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	proto_tree	*ext_tree_auth_tri;
	proto_item	*te;
	guint32		rand[4], sres, kc[2];
	
	tvb_memcpy(tvb, (guint8 *)&rand, offset+1, 16);
	sres = tvb_get_ntohl(tvb, offset+17);
	tvb_memcpy(tvb, (guint8 *)&kc, offset+21, 16);
	
	te = proto_tree_add_text(tree, tvb, offset, 29, val_to_str(GTP_EXT_AUTH_TRI, gtp_val, "Unknown message"));
	ext_tree_auth_tri = proto_item_add_subtree(tree, ett_gtp_auth_tri);
							
	proto_tree_add_text(ext_tree_auth_tri, tvb, offset+1, 16, "RAND: %x%x%x%x", rand[0], rand[1], rand[2], rand[3]);
	proto_tree_add_text(ext_tree_auth_tri, tvb, offset+17, 4, "SRES: %x", sres);
	proto_tree_add_text(ext_tree_auth_tri, tvb, offset+21, 8, "Kc: %x%x", kc[0], kc[1]);

	return 1+16+4+8;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.9, page 40
 * 		9.02 v7.7.0, page 1090
 * UMTS:	29.060 v4.0, chapter 7.7.8, page 48
 * 		29.002 v4.2.1, chapter 17.5, page 268
 */
static int
decode_gtp_map_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	map_cause;
	
	map_cause = tvb_get_guint8(tvb, offset+1);	
	proto_tree_add_uint(tree, gtp_version ? hf_gtpv1_map_cause : hf_gtpv0_map_cause, tvb, offset, 2, map_cause);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.10, page 41
 * UMTS:	29.060 v4.0, chapter 7.7.9, page 48
 */
static int
decode_gtp_ptmsi_sig(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint32	ptmsi_sig;
	
	ptmsi_sig = tvb_get_ntoh24(tvb, offset+1);	
	proto_tree_add_uint(tree, gtp_version ? hf_gtpv1_ptmsi_sig : hf_gtpv0_ptmsi_sig, tvb, offset, 4, ptmsi_sig);

	return 4;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.11, page 41
 * UMTS:	29.060 v4.0, chapter 7.7.10, page 49
 */
static int
decode_gtp_ms_valid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	ms_valid;
	
	ms_valid = tvb_get_guint8(tvb, offset+1) & 0x01;	
	proto_tree_add_boolean(tree, gtp_version ? hf_gtpv1_ms_valid : hf_gtpv0_ms_valid, tvb, offset, 2, ms_valid);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.12, page 41
 * UMTS:	29.060 v4.0, chapter 7.7.11, page 49
 */
static int
decode_gtp_recovery(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	recovery;
	
	recovery = tvb_get_guint8(tvb, offset+1);	
	proto_tree_add_uint(tree, gtp_version ? hf_gtpv1_recovery : hf_gtpv0_recovery, tvb, offset, 2, recovery);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.13, page 42
 * UMTS:	29.060 v4.0, chapter 7.7.12, page 49
 */
static int
decode_gtp_sel_mode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	sel_mode;
	
	sel_mode = tvb_get_guint8(tvb, offset+1) & 0x03;	
	proto_tree_add_uint(tree, gtp_version ? hf_gtpv1_sel_mode : hf_gtpv0_sel_mode, tvb, offset, 2, sel_mode);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.14, page 42
 * UMTS:	29.060 v4.0, chapter 7.7.13, page 50
 */
static int
decode_gtp_16(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16	ext_flow_label;	
	guint32	teid_data;

	switch (gtp_version) {
		case 0:
			ext_flow_label = tvb_get_ntohs(tvb, offset+1);	
			proto_tree_add_uint(tree, hf_gtpv0_ext_flow_label, tvb, offset, 3, ext_flow_label);
			
			return 3;
		case 1:
			teid_data = tvb_get_ntohl(tvb, offset+1);
			proto_tree_add_uint(tree, hf_gtpv1_teid_data, tvb, offset, 5, teid_data);

			return 5;
		default: 
			proto_tree_add_text(tree, tvb, offset, 1, "Flow label/TEID Data I : GTP version not supported");
			
			return 3;
	}
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.15, page 42
 * UMTS:	29.060 v4.0, chapter 7.7.14, page 42
 */
static int
decode_gtp_17(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16		flow_sig;
	guint32		teid_cp;

	switch (gtp_version) {
		case 0:
			flow_sig = tvb_get_ntohs(tvb, offset+1);	
			proto_tree_add_uint(tree, hf_gtpv0_flow_sig, tvb, offset, 3, flow_sig);
			
			return 3;
		case 1:
			teid_cp = tvb_get_ntohl(tvb, offset+1);
			proto_tree_add_uint(tree, hf_gtpv1_teid_cp, tvb, offset, 5, teid_cp);
			
			return 5;
		default:
			proto_tree_add_text(tree, tvb, offset, 1, "Flow label signalling/TEID control plane : GTP version not supported");
			
			return 3;
	}
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.16, page 42
 * UMTS:	29.060 v4.0, chapter 7.7.15, page 51
 */
static int
decode_gtp_18(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16		flow_ii;
	guint32		teid_ii;
	proto_tree	*ext_tree_flow_ii;
	proto_item	*te;

	switch (gtp_version) {
		case 0:
			te = proto_tree_add_text(tree, tvb, offset, 4, val_to_str(GTP_EXT_FLOW_II, gtp_val, "Unknown message"));
			ext_tree_flow_ii = proto_item_add_subtree(te, ett_gtp_flow_ii);
			
			proto_tree_add_uint(ext_tree_flow_ii, hf_gtpv0_nsapi, tvb, offset+1, 1, tvb_get_guint8(tvb, offset+1) & 0x0F);
			
			flow_ii = tvb_get_ntohs(tvb, offset+2);	
			proto_tree_add_uint(ext_tree_flow_ii, hf_gtpv0_flow_ii, tvb, offset+2, 2, flow_ii);
			
			return 4;
		case 1:	
			te = proto_tree_add_text(tree, tvb, offset, 6, val_to_str(GTP_EXT_TEID_II, gtp_val, "Unknown message"));
			ext_tree_flow_ii = proto_item_add_subtree(te, ett_gtp_flow_ii);
			
			proto_tree_add_uint(ext_tree_flow_ii, hf_gtpv1_nsapi, tvb, offset+1, 1, tvb_get_guint8(tvb, offset+1) & 0x0F);

			
			teid_ii = tvb_get_ntohl(tvb, offset+2);
			proto_tree_add_uint(ext_tree_flow_ii, hf_gtpv1_teid_ii, tvb, offset+2, 4, teid_ii);
			
			return 6;
		default:
			proto_tree_add_text(tree, tvb, offset, 1, "Flow data II/TEID Data II : GTP Version not supported");
			
			return 4;
	}
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.16A, page 43
 * UMTS:	29.060 v4.0, chapter 7.7.16, page 51
 * Check if all ms_reason types are included
 */
static int
decode_gtp_19(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8		field19;	
	
	field19 = tvb_get_guint8(tvb, offset+1);	
	
	switch (gtp_version) {
		case 0:	
			proto_tree_add_uint(tree, hf_gtpv0_ms_reason, tvb, offset, 2, field19);
			
			break;
		case 1:
			proto_tree_add_boolean(tree, hf_gtpv1_tear_ind, tvb, offset, 2, field19 & 0x01);
			
			break;
		default:
			proto_tree_add_text(tree, tvb, offset, 1, "Information Element Type = 19 : GTP Version not supported");

			break;
	}

	return 2;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.17, page 51
 */
static int
decode_gtp_nsapi(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8		nsapi;
	
	nsapi = tvb_get_guint8(tvb, offset+1) & 0x0F;	
	proto_tree_add_uint(tree, hf_gtpv1_nsapi, tvb, offset, 2, nsapi);

	return 2;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.18, page 52
 */
static int
decode_gtp_ranap_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8		ranap;
	
	ranap = tvb_get_guint8(tvb, offset+1);

	if(ranap > 0 && ranap <=64)
	proto_tree_add_uint_format(tree, hf_gtpv1_ranap_cause, tvb, offset, 2, ranap, "%s (Radio Network Layer Cause) : %s (%u)", val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	if(ranap > 64 && ranap <=80)
	proto_tree_add_uint_format(tree, hf_gtpv1_ranap_cause, tvb, offset, 2, ranap, "%s (Transport Layer Cause) : %s (%u)", val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	if(ranap > 80 && ranap <=96)
	proto_tree_add_uint_format(tree, hf_gtpv1_ranap_cause, tvb, offset, 2, ranap, "%s (NAS Cause) : %s (%u)", val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	if(ranap > 96 && ranap <=112)
	proto_tree_add_uint_format(tree, hf_gtpv1_ranap_cause, tvb, offset, 2, ranap, "%s (Protocol Cause) : %s (%u)", val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	if(ranap > 112 && ranap <=128)
	proto_tree_add_uint_format(tree, hf_gtpv1_ranap_cause, tvb, offset, 2, ranap, "%s (Miscellaneous Cause) : %s (%u)", val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	if(ranap > 128 && ranap <=255)
	proto_tree_add_uint_format(tree, hf_gtpv1_ranap_cause, tvb, offset, 2, ranap, "%s (Non-standard Cause) : %s (%u)", val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	return 2;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.19, page 52
 */
static int
decode_gtp_rab_cntxt(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8		nsapi, dl_pdcp_seq, ul_pdcp_seq;
	guint16		dl_gtpu_seq, ul_gtpu_seq;
	proto_tree	*ext_tree_rab_cntxt;
	proto_item	*te;
	
	te = proto_tree_add_text(tree, tvb, offset, 8, val_to_str(GTP_EXT_RAB_CNTXT, gtp_val, "Unknown message"));
	ext_tree_rab_cntxt = proto_item_add_subtree(te, ett_gtp_rab_cntxt);
	
	nsapi = tvb_get_guint8(tvb, offset+1) & 0x0F;	
	dl_gtpu_seq = tvb_get_ntohs(tvb, offset+2);
	ul_gtpu_seq = tvb_get_ntohs(tvb, offset+4);
	dl_pdcp_seq = tvb_get_guint8(tvb, offset+6);
	ul_pdcp_seq = tvb_get_guint8(tvb, offset+7);

	proto_tree_add_uint(ext_tree_rab_cntxt, hf_gtpv1_nsapi, tvb, offset+1, 1, nsapi);
	proto_tree_add_uint(ext_tree_rab_cntxt, hf_gtpv1_rab_gtpu_dn, tvb, offset+2, 2, dl_gtpu_seq);
	proto_tree_add_uint(ext_tree_rab_cntxt, hf_gtpv1_rab_gtpu_up, tvb, offset+4, 2, ul_gtpu_seq);
	proto_tree_add_uint(ext_tree_rab_cntxt, hf_gtpv1_rab_pdu_dn, tvb, offset+6, 1, dl_pdcp_seq);
	proto_tree_add_uint(ext_tree_rab_cntxt, hf_gtpv1_rab_pdu_up, tvb, offset+7, 1, ul_pdcp_seq);

	return 8;
}


/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.20, page 53
 */
static int
decode_gtp_rp_sms(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8		rp_sms;
	
	rp_sms = tvb_get_guint8(tvb, offset+1) & 0x07;	
	proto_tree_add_uint(tree, hf_gtpv1_rp_sms, tvb, offset, 2, rp_sms);

	return 2;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.21, page 53
 */
static int
decode_gtp_rp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	proto_tree	*ext_tree_rp;
	proto_item	*te;
	guint8 		nsapi, rp, spare;
	
	nsapi = tvb_get_guint8(tvb, offset+1) & 0xF0;
	spare = tvb_get_guint8(tvb, offset+1) & 0x08;
	rp = tvb_get_guint8(tvb, offset+1) & 0x07;

	te = proto_tree_add_uint_format(tree, hf_gtpv1_rp, tvb, offset, 2, rp, "Radio Priority for NSAPI(%u) : %u", nsapi, rp);
	ext_tree_rp = proto_item_add_subtree(tree, ett_gtp_rp);

	proto_tree_add_uint(ext_tree_rp, hf_gtpv1_rp_nsapi, tvb, offset+1, 1, nsapi);
	proto_tree_add_uint(ext_tree_rp, hf_gtpv1_rp_spare, tvb, offset+1, 1, spare);
	proto_tree_add_uint(ext_tree_rp, hf_gtpv1_rp, tvb, offset+1, 1, rp);

	return 2;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.22, page 53
 */
static int
decode_gtp_pkt_flow_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	proto_tree	*ext_tree_pkt_flow_id;
	proto_item	*te;
	guint8 		nsapi, pkt_flow_id;
	
	nsapi = tvb_get_guint8(tvb, offset+1) & 0x0F;
	pkt_flow_id = tvb_get_guint8(tvb, offset+2);

	te = proto_tree_add_uint_format(tree, hf_gtpv1_pkt_flow_id, tvb, offset, 3, pkt_flow_id, "Packet Flow ID for NSAPI(%u) : %u", nsapi, pkt_flow_id);
	ext_tree_pkt_flow_id = proto_item_add_subtree(tree, ett_gtp_pkt_flow_id);

	proto_tree_add_uint(ext_tree_pkt_flow_id, hf_gtpv1_nsapi, tvb, offset+1, 1, nsapi);
	proto_tree_add_uint_format(ext_tree_pkt_flow_id, hf_gtpv1_pkt_flow_id, tvb, offset+2, 1, pkt_flow_id, "%s : %u", val_to_str(GTP_EXT_PKT_FLOW_ID, gtp_val, "Unknown message"), pkt_flow_id);
	
	return 3;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.23, page 53
 * TODO: Differenciate these uints?
 */
static int
decode_gtp_chrg_char(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16		chrg_char;
	proto_item	*te;
	proto_tree	*ext_tree_chrg_char;
	
	chrg_char = tvb_get_ntohs(tvb, offset+1);
	
	te = proto_tree_add_text(tree, tvb, offset, 3, "%s: %x", val_to_str(GTP_EXT_CHRG_CHAR, gtp_val, "Unknown message"), chrg_char);
	ext_tree_chrg_char = proto_item_add_subtree(te, ett_gtp_chrg_char);
	
	proto_tree_add_uint(ext_tree_chrg_char, hf_gtpv1_chrg_char_s, tvb, offset+1, 2, chrg_char);
	proto_tree_add_uint(ext_tree_chrg_char, hf_gtpv1_chrg_char_n, tvb, offset+1, 2, chrg_char);
	proto_tree_add_uint(ext_tree_chrg_char, hf_gtpv1_chrg_char_p, tvb, offset+1, 2, chrg_char);
	proto_tree_add_uint(ext_tree_chrg_char, hf_gtpv1_chrg_char_f, tvb, offset+1, 2, chrg_char);
	proto_tree_add_uint(ext_tree_chrg_char, hf_gtpv1_chrg_char_h, tvb, offset+1, 2, chrg_char);
	proto_tree_add_uint(ext_tree_chrg_char, hf_gtpv1_chrg_char_r, tvb, offset+1, 2, chrg_char);
	
	return 3;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.24, page 
 */
static int
decode_gtp_trace_ref(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16		trace_ref;
	
	trace_ref = tvb_get_ntohs(tvb, offset+1);
	
	proto_tree_add_uint(tree, hf_gtpv1_trace_ref, tvb, offset, 3, trace_ref);

	return 3;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.25, page 
 */
static int
decode_gtp_trace_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16		trace_type;
	
	trace_type = tvb_get_ntohs(tvb, offset+1);
	
	proto_tree_add_uint(tree, hf_gtpv1_trace_type, tvb, offset, 3, trace_type);
	
	return 3;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.16A
 * UMTS:	29.060 v4.0, chapter 7.7.25A, page 
 */
static int
decode_gtp_ms_reason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8		reason;	
	
	reason = tvb_get_guint8(tvb, offset+1);	
	
	proto_tree_add_uint(tree, gtp_version ? hf_gtpv1_ms_reason : hf_gtpv0_ms_reason, tvb, offset, 2, reason);

	return 2;
}


/* GPRS:	12.15
 * UMTS:	33.015
 */
static int
decode_gtp_tr_comm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	tr_command;	
	
	tr_command = tvb_get_ntohl(tvb, offset+1);	
	
	proto_tree_add_uint(tree, gtp_version ? hf_gtpv1_tr_comm : hf_gtpv0_tr_comm, tvb, offset, 2, tr_command);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.17, page 43
 * UMTS:	29.060 v4.0, chapter 7.7.26, page 55
 */
static int
decode_gtp_chrg_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint32	chrg_id;	
	
	chrg_id = tvb_get_ntohl(tvb, offset+1);	
	proto_tree_add_uint(tree, gtp_version ? hf_gtpv1_chrg_id : hf_gtpv0_chrg_id, tvb, offset, 5, chrg_id);

	return 5;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.18, page 43
 * UMTS:	29.060 v4.0, chapter 7.7.27, page 55
 */
static int
decode_gtp_user_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16		length;
	guint8		pdp_typ, pdp_org;	
	guint32		addr_ipv4;
	struct		e_in6_addr addr_ipv6;
	proto_tree	*ext_tree_user;
	proto_item	*te;
	
	
    	length = tvb_get_ntohs(tvb, offset+1);
	pdp_org = tvb_get_guint8(tvb, offset+3) & 0x0F;
	pdp_typ = tvb_get_guint8(tvb, offset+4);

	te = proto_tree_add_text(tree, tvb, offset, 3+length, "%s (%s/%s)",
	    val_to_str(GTP_EXT_USER_ADDR, gtp_val, "Unknown message"),
	    val_to_str(pdp_org, pdp_org_type, "Unknown PDP Organization"),
	    val_to_str(pdp_typ, pdp_type, "Unknown PDP Type"));
	ext_tree_user = proto_item_add_subtree(te, ett_gtp_user);
	
	proto_tree_add_text(ext_tree_user, tvb, offset+1, 2, "Length : %u", length);
	proto_tree_add_uint(ext_tree_user, gtp_version ? hf_gtpv1_user_addr_pdp_org : hf_gtpv0_user_addr_pdp_org, tvb, offset+3, 1, pdp_org);
	proto_tree_add_uint(ext_tree_user, gtp_version ? hf_gtpv1_user_addr_pdp_type : hf_gtpv0_user_addr_pdp_type, tvb, offset+4, 1, pdp_typ);
	
	if (length == 2) {
		if (pdp_org == 0 && pdp_typ == 1)
			proto_item_append_text(te, " (Point to Point Protocol)");
		else if (pdp_typ == 2)
			proto_item_append_text(te, " (Octet Stream Protocol)");
	} else if (length > 2) {
		switch (pdp_typ) {
			case 0x21:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+5, sizeof addr_ipv4);
				proto_tree_add_ipv4(ext_tree_user, gtp_version ? hf_gtpv1_user_ipv4 : hf_gtpv0_user_ipv4, tvb, offset+5, 4, addr_ipv4);
				proto_item_append_text(te, " : %s", ip_to_str((guint8 *)&addr_ipv4));
				break;
			case 0x57:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+5, sizeof addr_ipv6);
				proto_tree_add_ipv6(ext_tree_user, gtp_version ? hf_gtpv1_user_ipv6 : hf_gtpv0_user_ipv6, tvb, offset+5, 16, (guint8 *)&addr_ipv6);
				proto_item_append_text(te, " : %s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
				break;
		}
	} else
		proto_item_append_text(te, " : empty PDP Address");
				
	return 3+length;
}

static int
decode_triplet(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 count) {
	
	proto_tree	*ext_tree_trip;
	proto_item	*te_trip;
	guint32		rand[4], sres, kc[2];
	guint16		i;
	
	for (i=0;i<count;i++) {
		
		tvb_memcpy(tvb, (guint8 *)&rand, offset+i*28, 16);
		sres = tvb_get_ntohl(tvb, offset+i*28+16);
		tvb_memcpy(tvb, (guint8 *)&kc, offset+i*28+20, 8);

		te_trip = proto_tree_add_text(tree, tvb, offset+i*28, 28, "Triplet no%x", i);
		ext_tree_trip = proto_item_add_subtree(te_trip, ett_gtp_trip);
							
		proto_tree_add_text(ext_tree_trip, tvb, offset+i*28, 16, "RAND: %x%x%x%x", rand[0], rand[1], rand[2], rand[3]);
		proto_tree_add_text(ext_tree_trip, tvb, offset+i*28+16, 4, "SRES: %x", sres);
		proto_tree_add_text(ext_tree_trip, tvb, offset+i*28+20, 8, "Kc: %x%x", kc[0], kc[1]);
	}
	
	return count*28;
}

/* adjust - how many bytes before quintuplet should be highlighted
 */
static int
decode_quintuplet(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 count, guint8 adjust) {
	
	proto_tree	*ext_tree_quint;
	proto_item	*te_quint;
	guint32		rand[4], q_ck[4], q_ik[4];
	guint16		q_len, xres_len, auth_len, q_offset, i;

	q_offset = 0;
	
	for (i=0;i<count;i++) {	
	
		offset = offset + q_offset;
		
		q_len = tvb_get_ntohs(tvb, offset);
		
		tvb_memcpy(tvb, (guint8 *)&rand, offset+2, 16);
		xres_len = tvb_get_ntohs(tvb, offset+18);
/*		xres = tvb_get_ptr(tvb, offset+20, xres_len);*/
		tvb_memcpy(tvb, (guint8 *)&q_ck, offset+20+xres_len, 16);
		tvb_memcpy(tvb, (guint8 *)&q_ik, offset+36+xres_len, 16);
		auth_len = tvb_get_ntohs(tvb, offset+52+xres_len);
/*		auth = tvb_get_ptr(tvb, offset+54+xres_len, auth_len);*/

		te_quint = proto_tree_add_text(tree, tvb, offset-adjust, q_len+adjust, "Quintuplet #%x", i);
		ext_tree_quint = proto_item_add_subtree(te_quint, ett_gtp_quint);
							
		proto_tree_add_text(ext_tree_quint, tvb, offset, 2, "Length: %x", q_len);
		proto_tree_add_text(ext_tree_quint, tvb, offset+2, 16, "RAND: %x%x%x%x", rand[0], rand[1], rand[2], rand[3]);
		proto_tree_add_text(ext_tree_quint, tvb, offset+18, 2, "XRES length: %x", xres_len);
		proto_tree_add_text(ext_tree_quint, tvb, offset+20, xres_len, "XRES");
		proto_tree_add_text(ext_tree_quint, tvb, offset+20+xres_len, 16, "Quintuplet ciphering key: %x%x%x%x", q_ck[0], q_ck[1], q_ck[2], q_ck[3]);
		proto_tree_add_text(ext_tree_quint, tvb, offset+36+xres_len, 16, "Quintuplet integrity key: %x%x%x%x", q_ik[0], q_ik[1], q_ik[2], q_ik[3]);
		proto_tree_add_text(ext_tree_quint, tvb, offset+52+xres_len, 2, "Authentication length: %x", auth_len);
		proto_tree_add_text(ext_tree_quint, tvb, offset+54+xres_len, auth_len, "AUTH");

		q_offset = q_offset + q_len + 2;
	}
	
	return q_offset;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.19 page 
 * UMTS:	29.060 v4.0, chapter 7.7.28 page 57
 * TODO:	- check if for quintuplets first 2 bytes are length, according to AuthQuint
 * 		- finish displaying last 3 parameters
 */
static int
decode_gtp_mm_cntxt(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16		length, quint_len, net_cap, con_len;	
	guint8		cksn, count, sec_mode, cipher, trans_id, proto_disc, message, drx_split, drx_len, drx_ccch, non_drx_timer;
	guint32		kc[4], ik[4];
	proto_tree	*ext_tree_mm;
	proto_item	*te;
	
	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_MM_CNTXT, gtp_val, "Unknown message"));
	ext_tree_mm = proto_item_add_subtree(te, ett_gtp_mm);
	
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < 1) return 3;
	
	cksn = tvb_get_guint8(tvb, offset+3) & 0x07;
	sec_mode = (tvb_get_guint8(tvb, offset+4) >> 6) & 0x03;
	count = (tvb_get_guint8(tvb, offset+4) >> 3) & 0x07;
	cipher = tvb_get_guint8(tvb, offset+4) & 0x07;
	
	proto_tree_add_text(ext_tree_mm, tvb, offset+1, 2, "Length: %x", length);
	proto_tree_add_text(ext_tree_mm, tvb, offset+3, 1, "Ciphering Key Sequence Number: %u", cksn);
	if (gtp_version != 0) {
		proto_tree_add_text(ext_tree_mm, tvb, offset+3, 1, "Security type: %u", sec_mode);
	} else {
		sec_mode = 1;
	}
	
	proto_tree_add_text(ext_tree_mm, tvb, offset+4, 1, "No of triplets: %u", count);

	switch (sec_mode) {
		case 0: 
			if (cipher == 0) {
				proto_tree_add_text(ext_tree_mm, tvb, offset+4, 1, "Ciphering: no ciphering");
			} else {
				proto_tree_add_text(ext_tree_mm, tvb, offset+4, 1, "Ciphering: GEA/%u", cipher);
			}
			tvb_memcpy(tvb, (guint8 *)&kc, offset+5, 16);
			proto_tree_add_text(ext_tree_mm, tvb, offset+5, 16, "Ciphering key CK: %x%x%x%x", kc[0], kc[1], kc[2], kc[3]);
			tvb_memcpy(tvb, (guint8 *)&ik, offset+21, 16);
			proto_tree_add_text(ext_tree_mm, tvb, offset+21, 16, "Integrity key CK: %x%x%x%x", ik[0], ik[1], ik[2], ik[3]);
			quint_len = tvb_get_ntohs(tvb, offset+37);
			proto_tree_add_text(ext_tree_mm, tvb, offset+37, 2, "Quintuplets length: %x", quint_len);

			offset = offset + decode_quintuplet(tvb, offset+39, ext_tree_mm, count, 0) + 39;
			
					
			break;
		case 1: 
			if (cipher == 0) {
				proto_tree_add_text(ext_tree_mm, tvb, offset+4, 1, "Ciphering: no ciphering");
			} else {
				proto_tree_add_text(ext_tree_mm, tvb, offset+4, 1, "Ciphering: GEA/%u", cipher);
			}
			tvb_memcpy(tvb, (guint8 *)&kc, offset+5, 8);
			proto_tree_add_text(ext_tree_mm, tvb, offset+5, 8, "Ciphering key Kc: %x%x", kc[0], kc[1]);

			offset = offset + decode_triplet(tvb, offset+13, ext_tree_mm, count) + 13;

			break;
		case 2: 
			tvb_memcpy(tvb, (guint8 *)&kc, offset+5, 16);
			proto_tree_add_text(ext_tree_mm, tvb, offset+5, 16, "Ciphering key CK: %x%x%x%x", kc[0], kc[1], kc[2], kc[3]);
			tvb_memcpy(tvb, (guint8 *)&ik, offset+21, 16);
			proto_tree_add_text(ext_tree_mm, tvb, offset+21, 16, "Integrity key CK: %x%x%x%x", ik[0], ik[1], ik[2], ik[3]);
			quint_len = tvb_get_ntohs(tvb, offset+37);
			proto_tree_add_text(ext_tree_mm, tvb, offset+37, 2, "Quintuplets length: %x", quint_len);
			
			offset = offset + decode_quintuplet(tvb, offset+39, ext_tree_mm, count, 0) + 39;
			
			break;
		case 3: 
			if (cipher == 0) {
				proto_tree_add_text(ext_tree_mm, tvb, offset+4, 1, "Ciphering: no ciphering");
			} else {
				proto_tree_add_text(ext_tree_mm, tvb, offset+4, 1, "Ciphering: GEA/%u", cipher);
			}
			tvb_memcpy(tvb, (guint8 *)&kc, offset+5, 8);
			proto_tree_add_text(ext_tree_mm, tvb, offset+5, 8, "Ciphering key Kc: %x%x", kc[0], kc[1]);
			quint_len = tvb_get_ntohs(tvb, offset+13);
			proto_tree_add_text(ext_tree_mm, tvb, offset+13, 2, "Quintuplets length: %x", quint_len);

			offset = offset + decode_quintuplet(tvb, offset+15, ext_tree_mm, count, 0) + 15;
			
			break;
		default:
			break;
	}
	
	
	drx_split = tvb_get_guint8(tvb, offset);
	drx_len = (tvb_get_guint8(tvb, offset+1) >> 4) & 0x0F;
	drx_ccch = (tvb_get_guint8(tvb, offset+1) >> 3) & 0x01;
	non_drx_timer = tvb_get_guint8(tvb, offset+1) & 0x07;

	net_cap	= tvb_get_ntohs(tvb, offset+2);
	con_len = tvb_get_ntohs(tvb, offset+4);
	
	proto_tree_add_text(ext_tree_mm, tvb, offset, 1, "DRX: split PG cycle code: %u", drx_split);
	proto_tree_add_text(ext_tree_mm, tvb, offset+1, 1, "DRX: CN specific DRX cycle length coefficient: %u", drx_len);
	proto_tree_add_text(ext_tree_mm, tvb, offset+1, 1, "DRX: split PG cycle on CCCH supported by MS: %s", yesno[drx_ccch]);
	if (non_drx_timer == 0) {
		proto_tree_add_text(ext_tree_mm, tvb, offset+1, 1, "DRX: no non-DRX mode after transfer state");
	} else {
		proto_tree_add_text(ext_tree_mm, tvb, offset+1, 1, "DRX: max sec non-DRX mode after transfer state:  2^%u", non_drx_timer-1);
	}
	
	proto_tree_add_text(ext_tree_mm, tvb, offset+2, 2, "MS network capability: %u", net_cap);
	proto_tree_add_text(ext_tree_mm, tvb, offset+4, 2, "Container length: %u", con_len);
	
	if (con_len > 0) {
		trans_id = (tvb_get_guint8(tvb, offset+6) >> 4) & 0x0F;
		proto_disc = tvb_get_guint8(tvb, offset+6) & 0x0F;
		message = tvb_get_guint8(tvb, offset+7);
	}

	return 3+length;
}

 /* WARNING : actually length is coded on 2 octets for QoS profile but on 1 octet for PDP Context!
  * so type means length of length :-)
 */
static int
decode_qos_umts(tvbuff_t *tvb, int offset, proto_tree *tree, gchar* qos_str, guint8 type) {

	guint8		length;
	guint8		al_ret_priority;
	guint8		delay, reliability, peak, precedence, mean, spare1, spare2, spare3;
	guint8		traf_class, del_order, del_err_sdu;
	guint8		max_sdu_size, max_ul, max_dl;
	guint8		res_ber, sdu_err_ratio;
	guint8		trans_delay, traf_handl_prio;
	guint8		guar_ul, guar_dl;
	proto_tree	*ext_tree_qos;
	proto_item	*te;
	int		mss, mu, md, gu, gd;

	switch (type) {
		case 1:
			length = tvb_get_guint8 (tvb, offset);
			te = proto_tree_add_text (tree, tvb, offset, length + 1, "%s", qos_str);
			ext_tree_qos = proto_item_add_subtree (te, ett_gtp_qos);
			proto_tree_add_text (ext_tree_qos, tvb, offset, 1, "Length: %u", length);
			break;
		case 2:
			length = tvb_get_ntohs (tvb, offset + 1);
			te = proto_tree_add_text(tree, tvb, offset, length + 3, "%s", qos_str);
			ext_tree_qos = proto_item_add_subtree (te, ett_gtp_qos);
			proto_tree_add_text (ext_tree_qos, tvb, offset + 1, 2, "Length: %u", length);
			type++;		/* +1 because of first 0x86 byte for UMTS QoS */
			break;
		default:
			/* XXX - what should we do with the length here? */
			length = 0;
			ext_tree_qos = NULL;
			break;
	}
	
	offset += type;
	
	al_ret_priority = tvb_get_guint8 (tvb, offset);

	spare1 = tvb_get_guint8(tvb, offset+1) & 0xC0;
	delay = tvb_get_guint8(tvb, offset+1) & 0x38;
	reliability = tvb_get_guint8(tvb, offset+1) & 0x07;
	peak = tvb_get_guint8(tvb, offset+2) & 0xF0;
	spare2 = tvb_get_guint8(tvb, offset+2) & 0x08;
	precedence = tvb_get_guint8(tvb, offset+2) & 0x07;
	spare3 = tvb_get_guint8(tvb, offset+3) & 0xE0;
	mean = tvb_get_guint8(tvb, offset+3) & 0x1F;

	proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_al_ret_priority, tvb, offset, 1, al_ret_priority);
	proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_spare1, tvb, offset+1, 1, spare1);
	proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_delay, tvb, offset+1, 1, delay);
	proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_reliability, tvb, offset+1, 1, reliability);
	proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_peak, tvb, offset+2, 1, peak);
	proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_spare2, tvb, offset+2, 1, spare2);
	proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_precedence, tvb, offset+2, 1, precedence);
	proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_spare3, tvb, offset+3, 1, spare3);
	proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_mean, tvb, offset+3, 1, mean);

	if (length > 4) {
		
		traf_class = tvb_get_guint8(tvb, offset+4) & 0xE0;
		del_order = tvb_get_guint8(tvb, offset+4) & 0x18;
		del_err_sdu = tvb_get_guint8(tvb, offset+4) & 0x07;
		max_sdu_size = tvb_get_guint8(tvb, offset+5);
		max_dl = tvb_get_guint8(tvb, offset+6);
		max_ul = tvb_get_guint8(tvb, offset+7);
		res_ber = tvb_get_guint8(tvb, offset+8) & 0xF0;
		sdu_err_ratio = tvb_get_guint8(tvb, offset+8) & 0x0F;
		trans_delay = tvb_get_guint8(tvb, offset+9) & 0xFC;
		traf_handl_prio = tvb_get_guint8(tvb, offset+9) & 0x03;
		guar_ul = tvb_get_guint8(tvb, offset+10);
		guar_dl = tvb_get_guint8(tvb, offset+11);
		
		proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_traf_class, tvb, offset+4, 1, traf_class);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_del_order, tvb, offset+4, 1, del_order);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_del_err_sdu, tvb, offset+4, 1, del_err_sdu);
		if (max_sdu_size == 0 || max_sdu_size > 150)
			proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_max_sdu_size, tvb, offset+5, 1, max_sdu_size);
		if (max_sdu_size > 0 && max_sdu_size <= 150) {
			mss = max_sdu_size*10;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_max_sdu_size, tvb, offset+5, 1, mss, "Maximum SDU size : %u octets", mss);
		}

		if(max_ul == 0 || max_ul == 255)
			proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_max_ul, tvb, offset+6, 1, max_ul);
		if(max_ul > 0 && max_ul <= 63)
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_max_ul, tvb, offset+6, 1, max_ul, "Maximum bit rate for uplink : %u kbps", max_ul);
		if(max_ul > 63 && max_ul <=127) {
			mu = 64 + ( max_ul - 64 ) * 8;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_max_ul, tvb, offset+6, 1, mu, "Maximum bit rate for uplink : %u kbps", mu);
		}
	
		if(max_ul > 127 && max_ul <=254) {
			mu = 576 + ( max_ul - 128 ) * 64;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_max_ul, tvb, offset+6, 1, mu, "Maximum bit rate for uplink : %u kbps", mu);
		}

		if(max_dl == 0 || max_dl == 255)
			proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_max_dl, tvb, offset+7, 1, max_dl);
		if(max_dl > 0 && max_dl <= 63)
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_max_dl, tvb, offset+7, 1, max_dl, "Maximum bit rate for downlink : %u kbps", max_dl);
		if(max_dl > 63 && max_dl <=127) {
			md = 64 + ( max_dl - 64 ) * 8;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_max_dl, tvb, offset+7, 1, md, "Maximum bit rate for downlink : %u kbps", md);
		}
		if(max_dl > 127 && max_dl <=254) {
			md = 576 + ( max_dl - 128 ) * 64;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_max_dl, tvb, offset+7, 1, md, "Maximum bit rate for downlink : %u kbps", md);
		}

		proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_res_ber, tvb, offset+8, 1, res_ber);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_sdu_err_ratio, tvb, offset+8, 1, sdu_err_ratio);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_trans_delay, tvb, offset+9, 1, trans_delay);
		proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_traf_handl_prio, tvb, offset+9, 1, traf_handl_prio);

		if(guar_ul == 0 || guar_ul == 255)
			proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_guar_ul, tvb, offset+10, 1, guar_ul);
		if(guar_ul > 0 && guar_ul <= 63)
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_guar_ul, tvb, offset+10, 1, guar_ul, "Guaranteed bit rate for uplink : %u kbps", guar_ul);
		if(guar_ul > 63 && guar_ul <=127) {
			gu = 64 + ( guar_ul - 64 ) * 8;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_guar_ul, tvb, offset+10, 1, gu, "Guaranteed bit rate for uplink : %u kbps", gu);
		}
		if(guar_ul > 127 && guar_ul <=254) {
			gu = 576 + ( guar_ul - 128 ) * 64;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_guar_ul, tvb, offset+10, 1, gu, "Guaranteed bit rate for uplink : %u kbps", gu);
		}

		if(guar_dl == 0 || guar_dl == 255)
			proto_tree_add_uint(ext_tree_qos, hf_gtpv1_qos_guar_dl, tvb, offset+11, 1, guar_dl);
		if(guar_dl > 0 && guar_dl <= 63)
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_guar_dl, tvb, offset+11, 1, guar_dl, "Guaranteed bit rate for downlink : %u kbps", guar_dl);
		if(guar_dl > 63 && guar_dl <=127) {
			gd = 64 + ( guar_dl - 64 ) * 8;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_guar_dl, tvb, offset+11, 1, gd, "Guaranteed bit rate for downlink : %u kbps", gd);
		}
		if(guar_dl > 127 && guar_dl <=254) {
			gd = 576 + ( guar_dl - 128 ) * 64;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtpv1_qos_guar_dl, tvb, offset+11, 1, gd, "Guaranteed bit rate for downlink : %u kbps", gd);
		}
	
	}
	
	return length + type;

}

static void
decode_apn(tvbuff_t *tvb, int offset, guint16 length, proto_tree *tree) {

	gchar	*apn = NULL;
	guint8	name_len, tmp;

	if (length > 0) {
		apn = g_malloc (length + 1);
		name_len = tvb_get_guint8 (tvb, offset);

		if (name_len < 0x20) {
			tvb_memcpy (tvb, apn, offset + 1, length);
			for (;;) {
				if (name_len >= length - 1) break;
				tmp = name_len;
				name_len = name_len + apn[tmp] + 1;
				apn[tmp] = '.';
			}
		} else {
			tvb_memcpy (tvb, apn, offset, length);
		}
		
		apn[length-1] = '\0';
		proto_tree_add_string(tree, gtp_version ? hf_gtpv1_apn : hf_gtpv0_apn, tvb, offset, length, apn);
		g_free(apn);
	}
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.20
 * UMTS:	29.060 v4.0, chapter 7.7.29
 * TODO:	unify addr functions 
 */
static int
decode_gtp_pdp_cntxt(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint8		ggsn_addr_len, apn_len, trans_id, vaa, order, nsapi, sapi, pdu_send_no, pdu_rec_no, pdp_cntxt_id,
			pdp_type_org, pdp_type_num, pdp_addr_len;
	guint16		length, sn_down, sn_up, up_flow;
	guint32 	addr_ipv4, up_teid, up_teid_cp;
	struct	e_in6_addr addr_ipv6;	
	proto_tree	*ext_tree_pdp;
	proto_item	*te;
	
	length = tvb_get_ntohs(tvb, offset+1);
	
	te = proto_tree_add_text(tree, tvb, offset, length+3, val_to_str(GTP_EXT_PDP_CNTXT, gtp_val, "Unknown message"));
	ext_tree_pdp = proto_item_add_subtree(te, ett_gtp_pdp);
	
	vaa = (tvb_get_guint8(tvb, offset+3) >> 6) & 0x01;
	order = (tvb_get_guint8(tvb, offset+3) >> 4) & 0x01;
	nsapi =  tvb_get_guint8(tvb, offset+3) & 0x0F;
	sapi = tvb_get_guint8(tvb, offset+4) & 0x0F;
	
	proto_tree_add_text(ext_tree_pdp, tvb, offset+3, 1, "VPLMN address allowed: %s", yesno[vaa]);
	proto_tree_add_text(ext_tree_pdp, tvb, offset+3, 1, "Reordering required: %s", yesno[order]);
	proto_tree_add_text(ext_tree_pdp, tvb, offset+3, 1, "NSAPI: %u", nsapi);
	proto_tree_add_text(ext_tree_pdp, tvb, offset+4, 1, "SAPI: %u", sapi);
	
	switch (gtp_version) {
		case 0:	
			decode_qos_gprs(tvb, offset+5, ext_tree_pdp, "QoS subscribed", 0);
			decode_qos_gprs(tvb, offset+8, ext_tree_pdp, "QoS requested", 0);
			decode_qos_gprs(tvb, offset+11, ext_tree_pdp, "QoS negotiated", 0);
			offset = offset + 14;
			break;
		case 1: 
			offset = offset + 5;
			offset = offset + decode_qos_umts(tvb, offset, ext_tree_pdp, "QoS subscribed", 1);
			offset = offset + decode_qos_umts(tvb, offset, ext_tree_pdp, "QoS requested", 1);
			offset = offset + decode_qos_umts(tvb, offset, ext_tree_pdp, "QoS negotiated", 1);
			break;
		default:
			break;
	}
	
	sn_down = tvb_get_ntohs(tvb, offset);
	sn_up = tvb_get_ntohs(tvb, offset+2);
	pdu_send_no = tvb_get_guint8(tvb, offset+4);
	pdu_rec_no = tvb_get_guint8(tvb, offset+5);
	
	proto_tree_add_text(ext_tree_pdp, tvb, offset, 2, "Sequence number down: %u", sn_down);
	proto_tree_add_text(ext_tree_pdp, tvb, offset+2, 2, "Sequence number up: %u", sn_up);
	proto_tree_add_text(ext_tree_pdp, tvb, offset+4, 1, "Send N-PDU number: %u", pdu_send_no);
	proto_tree_add_text(ext_tree_pdp, tvb, offset+5, 1, "Receive N-PDU number: %u", pdu_rec_no);
	
	switch (gtp_version) {
		case 0:
			up_flow = tvb_get_ntohs(tvb, offset+6);
			proto_tree_add_text(ext_tree_pdp, tvb, offset+6, 2, "Uplink flow label signalling: %u", up_flow);
			offset = offset + 8;
			break;
		case 1:
			up_teid = tvb_get_ntohl(tvb, offset+6);
			up_teid_cp = tvb_get_ntohl(tvb, offset+10);
			pdp_cntxt_id = tvb_get_guint8(tvb, offset+14);
			proto_tree_add_text(ext_tree_pdp, tvb, offset+6, 4, "Uplink TEID: %x", up_teid);
			proto_tree_add_text(ext_tree_pdp, tvb, offset+10, 4, "Uplink TEID control plane: %x", up_teid_cp);
			proto_tree_add_text(ext_tree_pdp, tvb, offset+14, 1, "PDP context identifier: %u", pdp_cntxt_id);
			offset = offset + 15;
			break;
		default:
			break;
	}

	pdp_type_org = tvb_get_guint8(tvb, offset) & 0x0F;
	pdp_type_num = tvb_get_guint8(tvb, offset+1);
	pdp_addr_len = tvb_get_guint8(tvb, offset+2);
	
	proto_tree_add_text(ext_tree_pdp, tvb, offset, 1, "PDP organization: %s", val_to_str(pdp_type_org, pdp_type, "Unknown PDP org"));
	proto_tree_add_text(ext_tree_pdp, tvb, offset+1, 1, "PDP type: %s", val_to_str(pdp_type_num, pdp_org_type, "Unknown PDP type"));
	proto_tree_add_text(ext_tree_pdp, tvb, offset+2, 1, "PDP address length: %u", pdp_addr_len);

	if (pdp_addr_len > 0) {
		switch (pdp_type_num) {
			case 0x21:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+3, sizeof addr_ipv4);
				proto_tree_add_text(ext_tree_pdp, tvb, offset+3, 4, "PDP address: %s", ip_to_str((guint8 *)&addr_ipv4));
				break;
			case 0x57:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+3, sizeof addr_ipv6);
				proto_tree_add_text(ext_tree_pdp, tvb, offset+3, 16, "PDP address: %s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
				break;
			default:
				break;
		}
	}
	
	offset = offset + 3 + pdp_addr_len;

	ggsn_addr_len = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(ext_tree_pdp, tvb, offset, 1, "GGSN address length: %u", ggsn_addr_len);
	
	switch (ggsn_addr_len) {
		case 4: 
			tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+1, sizeof addr_ipv4);
			proto_tree_add_text(ext_tree_pdp, tvb, offset+1, 4, "GGSN address: %s", ip_to_str((guint8 *)&addr_ipv4));
			break;
		case 16: 
			tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+1, sizeof addr_ipv6);
			proto_tree_add_text(ext_tree_pdp, tvb, offset+1, 16, "GGSN address: %s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
			break;
		default:
			break;
	}
	
	offset = offset + 1 + ggsn_addr_len;
	
	if (gtp_version == 1) {

		ggsn_addr_len = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(ext_tree_pdp, tvb, offset, 1, "GGSN 2 address length: %u", ggsn_addr_len);
		
		switch (ggsn_addr_len) {
			case 4: 
				tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+1, sizeof addr_ipv4);
				proto_tree_add_text(ext_tree_pdp, tvb, offset+1, 4, "GGSN 2 address: %s", ip_to_str((guint8 *)&addr_ipv4));
				break;
			case 16: 
				tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+1, sizeof addr_ipv6);
				proto_tree_add_text(ext_tree_pdp, tvb, offset+1, 16, "GGSN 2 address: %s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
				break;
			default:
				break;
		}
		offset = offset + 1 + ggsn_addr_len;
		
	}
	
	apn_len = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(ext_tree_pdp, tvb, offset, 1, "APN length: %u", apn_len);
	decode_apn(tvb, offset+1, apn_len, ext_tree_pdp);

	offset = offset + 1 + apn_len;
	
	trans_id = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(ext_tree_pdp, tvb, offset, 1, "Transaction identifier: %u", trans_id);

	return 3+length;
}

/* GPRS:	9.60, v7.6.0, chapter 7.9.21
 * UMTS:	29.060, v4.0, chapter 7.7.30
 */
static int
decode_gtp_apn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16		length;
	proto_tree	*ext_tree_apn;
	proto_item	*te;
	
	length = tvb_get_ntohs(tvb, offset+1);	

	te = proto_tree_add_text(tree, tvb, offset, length+3, val_to_str(GTP_EXT_APN, gtp_val, "Unknown field"));
	ext_tree_apn = proto_item_add_subtree(te, ett_gtp_apn);
	
	proto_tree_add_text(ext_tree_apn, tvb, offset+1, 2, "APN length : %u", length);
	decode_apn(tvb, offset+3, length, ext_tree_apn);

	return 3+length;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.22
 * 		4.08 v. 7.1.2, chapter 10.5.6.3 (p.580)
 * UMTS:	29.060 v4.0, chapter 7.7.31
 * 		24.008, v4.2, chapter 10.5.6.3
 * TODO:	check if length is 8 or 16 bits
 * 		- proto_conf in 3G */
int
decode_gtp_proto_conf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16         length, proto_offset;
	guint8          *ptr, conf, proto_len, tmp, msg;
	tvbuff_t        *next_tvb;
	proto_tree      *ext_tree_proto;
	proto_item      *te;

	length = tvb_get_ntohs(tvb, offset + 1);

	te = proto_tree_add_text(tree, tvb, offset, length + 3, val_to_str(GTP_EXT_PROTO_CONF, gtp_val, "Unknown message"));
	ext_tree_proto = proto_item_add_subtree(te, ett_gtp_proto);

	proto_tree_add_text(ext_tree_proto, tvb, offset + 1, 2, "Length: %u", length);

	if (length < 1) return 3;

	conf = tvb_get_guint8(tvb, offset + 3) & 0x07;
	proto_offset = 1;       /* ... 1st byte is conf */

	for (;;) {
		if (proto_offset >= length) break;
		proto_len = tvb_get_guint8(tvb, offset + 6); 
		proto_offset += proto_len + 3; 
			
		if ((proto_len > 0) && ppp_reorder) { 
			
			/* this part changes layout of GTP payload: 
			 * it swaps "length field" with "protocol header"  */ 
			
			ptr = (guint8 *)tvb_get_ptr(tvb, offset + 4, 3); 
			
			tmp = ptr[2]; 
			ptr[2] = ptr[1]; 
			ptr[1] = ptr[0]; 
			ptr[0] = tmp; 
				
			next_tvb = tvb_new_subset(tvb, offset + 5, proto_len + 2, proto_len + 2); 
			call_dissector(ppp_handle, next_tvb, pinfo, ext_tree_proto); 
				
			if (check_col(pinfo->cinfo, COL_PROTOCOL))
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTP"); 
				
			if (check_col(pinfo->cinfo, COL_INFO)) { 
					
				msg = tvb_get_guint8(tvb, 1); 
						
				col_set_str(pinfo->cinfo, COL_INFO, val_to_str(msg, message_type, "Unknown")); 
			} 
		} 
	}

	return 3 + length;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.23
 * UMTS:	29.060 v4.0, chapter 7.7.32
 */
static int
decode_gtp_gsn_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
	
	guint8		addr_type, addr_len;	
	guint16		length;	
	guint32		addr_ipv4;
	struct	e_in6_addr addr_ipv6;
	proto_tree	*ext_tree_gsn_addr;
	proto_item	*te;
	
	length = tvb_get_ntohs(tvb, offset+1);
	
	te = proto_tree_add_text(tree, tvb, offset, 3+length, "GSN address : ");
	ext_tree_gsn_addr = proto_item_add_subtree(te, ett_gtp_gsn_addr);
	
	switch (length) {
		case 4:
			proto_tree_add_text(ext_tree_gsn_addr, tvb, offset+1, 2, "GSN address length : %u", length);
			tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+3, sizeof addr_ipv4);
			proto_item_append_text(te, "%s", ip_to_str((guint8 *)&addr_ipv4));
			proto_tree_add_ipv4(ext_tree_gsn_addr, gtp_version ? hf_gtpv1_gsn_ipv4 : hf_gtpv0_gsn_ipv4, tvb, offset+3, 4, addr_ipv4);
			break;
		case 5:
			proto_tree_add_text(ext_tree_gsn_addr, tvb, offset+1, 2, "GSN address Information Element length : %u", length);
			addr_type = tvb_get_guint8(tvb, offset+3) & 0xC0;
			proto_tree_add_uint(ext_tree_gsn_addr, gtp_version ? hf_gtpv1_gsn_addr_type : hf_gtpv0_gsn_addr_type, tvb, offset+3, 1, addr_type);
			addr_len = tvb_get_guint8(tvb, offset+3) & 0x3F;
			proto_tree_add_uint(ext_tree_gsn_addr, gtp_version ? hf_gtpv1_gsn_addr_len : hf_gtpv0_gsn_addr_len, tvb, offset+3, 1, addr_len);
			tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+4, sizeof addr_ipv4);
			proto_item_append_text(te, "%s", ip_to_str((guint8 *)&addr_ipv4));
			proto_tree_add_ipv4(ext_tree_gsn_addr, gtp_version ? hf_gtpv1_gsn_ipv4 : hf_gtpv0_gsn_ipv4, tvb, offset+4, 4, addr_ipv4);
			break;
		case 16:
			proto_tree_add_text(ext_tree_gsn_addr, tvb, offset+1, 2, "GSN address length : %u", length); 
			tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+3, sizeof addr_ipv6);
			proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
			proto_tree_add_ipv6(ext_tree_gsn_addr, gtp_version ? hf_gtpv1_gsn_ipv6 : hf_gtpv0_gsn_ipv6, tvb, offset+3, 16, (guint8*)&addr_ipv6);
			break;
		case 17: 
			proto_tree_add_text(ext_tree_gsn_addr, tvb, offset+1, 2, "GSN address Information Element length : %u", length);
			addr_type = tvb_get_guint8(tvb, offset+3) & 0xC0;
			proto_tree_add_uint(ext_tree_gsn_addr, gtp_version ? hf_gtpv1_gsn_addr_type : hf_gtpv0_gsn_addr_type, tvb, offset+3, 1, addr_type);
			addr_len = tvb_get_guint8(tvb, offset+3) & 0x3F;
			proto_tree_add_uint(ext_tree_gsn_addr, gtp_version ? hf_gtpv1_gsn_addr_len : hf_gtpv0_gsn_addr_len, tvb, offset+3, 1, addr_len);
			tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+4, sizeof addr_ipv6);
			proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
			proto_tree_add_ipv6(ext_tree_gsn_addr, gtp_version ? hf_gtpv1_gsn_ipv6 : hf_gtpv0_gsn_ipv6, tvb, offset+4, 16, (guint8*)&addr_ipv6);
			break;
		default:
			proto_item_append_text(te, "unknown type or wrong length");
			break;
	}
	
	return 3+length;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.24
 * UMTS:	29.060 v4.0, chapter 7.7.33
 */
static int
decode_gtp_msisdn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	const guint8	*msisdn_val;
	gchar		*msisdn_str;
	guint16		length;
	
	length = tvb_get_ntohs(tvb, offset+1);
	
	if (length < 1) return 3;
	
	msisdn_val = tvb_get_ptr(tvb, offset+3, length);
	msisdn_str = msisdn_to_str(msisdn_val, length);
	
	proto_tree_add_string(tree, gtp_version ? hf_gtpv1_msisdn : hf_gtpv0_msisdn, tvb, offset, 3+length, msisdn_str);
	
	return 3+length;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.34
 * 		24.008 v4.2, chapter 10.5.6.5
 */
static int
decode_gtp_qos_umts(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	return decode_qos_umts(tvb, offset, tree, "Quality of Service", 2);
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.35
 */
static int
decode_gtp_auth_qui(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
	
	return (1 + decode_quintuplet(tvb, offset+1, tree, 1, 1));

}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.36
 * 		24.008 v4.2, chapter 10.5.6.12
 */
static int
decode_gtp_tft(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16		length, port1, port2, tos;
	guint8		tft_code, no_packet_filters, i, pf_id, pf_eval, pf_len, pf_content_id, pf_offset, proto;
	guint32		addr_ipv4, ipsec_id, label;
	struct	e_in6_addr addr_ipv6;
	proto_tree	*ext_tree_tft, *ext_tree_tft_pf;
	proto_item	*te, *tee;
	
	length = tvb_get_ntohs(tvb, offset+1);
	
	te = proto_tree_add_text(tree, tvb, offset, 3+length, "Traffic flow template");
	ext_tree_tft = proto_item_add_subtree(te, ett_gtp_tft);
	
	tft_code = (tvb_get_guint8(tvb, offset+3) >> 5) & 0x07;
	no_packet_filters = tvb_get_guint8(tvb, offset+3) & 0x0F;
	
	proto_tree_add_text(ext_tree_tft, tvb, offset+1, 2, "TFT length: %u", length);
	proto_tree_add_text(ext_tree_tft, tvb, offset+3, 1, "TFT operation code: %u", tft_code);
	proto_tree_add_text(ext_tree_tft, tvb, offset+3, 1, "Number of packet filters: %u", no_packet_filters);	

	offset = offset + 4;
	
	for (i=0;i<no_packet_filters;i++) {
		
		pf_id = tvb_get_guint8(tvb, offset);
		
		tee = proto_tree_add_text(ext_tree_tft, tvb, offset, 1, "Packet filter id: %u", pf_id);
		ext_tree_tft_pf = proto_item_add_subtree(tee, ett_gtp_tft_pf);
		
		if (tft_code != 2) {
			
			pf_eval = tvb_get_guint8(tvb, offset+1);
			pf_len = tvb_get_guint8(tvb, offset+2);
			
			proto_tree_add_text(ext_tree_tft_pf, tvb, offset+1, 1, "Evaluation precedence: %u", pf_eval);
			proto_tree_add_text(ext_tree_tft_pf, tvb, offset+2, 1, "Contents length: %u", pf_len);

			offset = offset + 3;
			pf_offset = 0;	
			
			while (pf_offset < pf_len) {	
				
				pf_content_id = tvb_get_guint8(tvb, offset + pf_offset);
				
				switch (pf_content_id) {
					/* address IPv4 and mask = 8 bytes*/
					case 0x10: 
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 1, "Address IPv4 and mask (0x10)");
						tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset + pf_offset + 1, sizeof addr_ipv4);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset + 1, 4, "\tAddress: %s", ip_to_str((guint8 *)&addr_ipv4));
						tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset + pf_offset + 5, sizeof addr_ipv4);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset + 5, 4, "\tNetmask: %s", ip_to_str((guint8 *)&addr_ipv4));
						pf_offset = pf_offset + 9;
						break;
					/* address IPv6 and mask = 32 bytes*/
					case 0x20: 
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset+pf_offset, 1, "Address IPv6 and mask (0x20)");
						tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+pf_offset+1, sizeof addr_ipv6);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset+offset+1, 16, "\tAddress: %s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
						tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+pf_offset+17, sizeof addr_ipv6);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset+offset+17, 16, "\tNetmask: %s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
						pf_offset = pf_offset + 33;
						break;
					/* protocol identifier/next header type = 1 byte*/
					case 0x30:
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 1, "IPv4 protocol identifier/IPv6 next header (0x30)");
						proto = tvb_get_guint8(tvb, offset + pf_offset + 1);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset + 1, 1, "\t%u", proto);
						pf_offset = pf_offset + 2;
						break;
					/* single destination port type = 2 bytes */
					case 0x40:
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset, 1, "Destination port (0x40)");
						port1 = tvb_get_ntohs(tvb, offset + pf_offset + 1);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset + 1, 2, "\t%u", port1);
						pf_offset = pf_offset + 3;
						break;
					/* destination port range type = 4 bytes */
					case 0x41:
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset+pf_offset, 1, "Destination port range (0x41)");
						port1 = tvb_get_ntohs(tvb, offset + pf_offset + 1);
						port2 = tvb_get_ntohs(tvb, offset + pf_offset + 3);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset + 1, 4, "\t%u-%u", port1, port2);
						pf_offset = pf_offset + 5;
						break;
					/* single source port type = 2 bytes */
					case 0x50:
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset+pf_offset, 1, "Source port (0x50)");
						port1 = tvb_get_ntohs(tvb, offset + pf_offset + 1);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset + 1, 2, "\t%u", port1);
						pf_offset = pf_offset + 3;
						break;
					/* source port range type = 4 bytes */
					case 0x51:
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset+pf_offset, 1, "Source port range (0x51)");
						port1 = tvb_get_ntohs(tvb, offset + pf_offset + 1);
						port2 = tvb_get_ntohs(tvb, offset + pf_offset + 3);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset + 1, 4, "\t%u-%u", port1, port2);
						pf_offset = pf_offset + 5;
						break;
					/* security parameter index type = 4 bytes */
					case 0x60:
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset+pf_offset, 1, "Security parameter index (0x60)");
						ipsec_id = tvb_get_ntohl(tvb, offset + pf_offset + 1);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset + 1, 4, "\t%x", ipsec_id);
						pf_offset = pf_offset + 5;
						break;
					/* type of service/traffic class type = 2 bytes */
					case 0x70:
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset+pf_offset, 1, "Type of Service/Traffic Class (0x70)");
						tos = tvb_get_ntohs(tvb, offset + pf_offset + 1);
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset + 1, 2, "\t%u", tos);
						pf_offset = pf_offset + 3;
						break;
					/* flow label type = 3 bytes */
					case 0x80:
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset+pf_offset, 1, "Flow label (0x80)");
						label = tvb_get_ntoh24(tvb, offset + pf_offset + 1) & 0x0FFFFF;;
						proto_tree_add_text(ext_tree_tft_pf, tvb, offset + pf_offset + 1, 3, "\t%x", label);
						pf_offset = pf_offset + 4;
						break;
					
					default: 
						break;
				}
			}
		}	
	}
	
	return 3 + length;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.37
 * 		25.413 v3.4, chapter ???
 */
static int
decode_gtp_target_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16		length;

	length = tvb_get_ntohs(tvb, offset + 1);

	proto_tree_add_text(tree, tvb, offset, 3 + length, "Targer Identification");
	
	return 3 + length;
}


/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.38
 */
static int
decode_gtp_utran_cont(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16		length;

	length = tvb_get_ntohs(tvb, offset + 1);

	proto_tree_add_text(tree, tvb, offset, 3 + length, "UTRAN transparent field");

	return 3 + length;

}
	

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.39
 */
static int
decode_gtp_rab_setup(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint32		teid, addr_ipv4;
	guint16		length;
	guint8		nsapi;
	struct	e_in6_addr addr_ipv6;
	proto_tree	*ext_tree_rab_setup;
	proto_item	*te;
	
	length = tvb_get_ntohs(tvb, offset + 1);
	nsapi = tvb_get_guint8(tvb, offset + 3) & 0x0F;

	te = proto_tree_add_text(tree, tvb, offset, 3+length, "Radio Access Bearer Setup Information");
	ext_tree_rab_setup = proto_item_add_subtree(te, ett_gtp_rab_setup);

	proto_tree_add_text(ext_tree_rab_setup, tvb, offset+1, 2, "RAB setup length : %u", length);
	proto_tree_add_uint(ext_tree_rab_setup, hf_gtpv1_nsapi, tvb, offset+3, 1, nsapi);

	if (length > 1) {
		
		teid = tvb_get_ntohl(tvb, offset + 4);

		proto_tree_add_uint(ext_tree_rab_setup, hf_gtpv1_teid_data, tvb, offset+4, 4, teid);
	
		switch (length) {
			case 12:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+8, sizeof addr_ipv4);
				proto_tree_add_ipv4(ext_tree_rab_setup, hf_gtpv1_rnc_ipv4, tvb, offset+8, 4, addr_ipv4);
				break;
			case 24: 
				tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+8, sizeof addr_ipv6);
				proto_tree_add_ipv6(ext_tree_rab_setup, hf_gtpv1_rnc_ipv6, tvb, offset+8, 16, (guint8 *)&addr_ipv6);
				break;
			default:
				break;
		}
	}

	return 3 + length;
}


/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.40
 */
static int
decode_gtp_hdr_list(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	int		i;
	guint8		length, hdr;
	proto_tree	*ext_tree_hdr_list;
	proto_item	*te;
	
	length = tvb_get_guint8(tvb, offset + 1);

	te = proto_tree_add_text(tree, tvb, offset, 2+length, "%s", val_to_str(GTP_EXT_HDR_LIST, gtp_val, "Unknown"));
	ext_tree_hdr_list = proto_item_add_subtree(te, ett_gtp_hdr_list);
	
	proto_tree_add_text(ext_tree_hdr_list, tvb, offset+1, 1, "Number of Extension Header Types in list (i.e., length) : %u", length);

	for(i=0 ; i<length ; i++) {
		hdr = tvb_get_guint8(tvb, offset+2+i);

		proto_tree_add_text(ext_tree_hdr_list, tvb, offset+2+i, 1, "No. %u --> Extension Header Type value : %s (%u)", i+1, val_to_str(hdr, gtp_val, "Unknown Extension Header Type"), hdr);
	}

	return 2 + length;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.41
 * TODO:	find TriggerID description
 */
static int
decode_gtp_trigger_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16		length;

	length = tvb_get_ntohs(tvb, offset + 1);

	proto_tree_add_text(tree, tvb, offset, 3+length, "%s length : %u", val_to_str(GTP_EXT_TRIGGER_ID, gtp_val, "Unknown"), length);

	return 3 + length;

}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.42
 * TODO:	find OMC-ID description
 */
static int
decode_gtp_omc_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16		length;

	length = tvb_get_ntohs(tvb, offset + 1);

	proto_tree_add_text(tree, tvb, offset, 3+length, "%s length : %u", val_to_str(GTP_EXT_OMC_ID, gtp_val, "Unknown"), length);

	return 3 + length;

}

/* GPRS:	9.60 v7.6.0, chapter 7.9.25
 * UMTS:	29.060 v4.0, chapter 7.7.43
 */
static int
decode_gtp_chrg_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16		length;	
	guint32		addr_ipv4;
	struct	e_in6_addr addr_ipv6;
	proto_tree	*ext_tree_chrg_addr;
	proto_item	*te;
	
	length = tvb_get_ntohs(tvb, offset+1);
	
	te = proto_tree_add_text(tree, tvb, offset, 3+length, "%s : ", val_to_str(GTP_EXT_CHRG_ADDR, gtp_val, "Unknown"));
	ext_tree_chrg_addr = proto_item_add_subtree(te, ett_gtp_chrg_addr);
	
	proto_tree_add_text(ext_tree_chrg_addr, tvb, offset+1, 2, "%s length : %u", val_to_str(GTP_EXT_CHRG_ADDR, gtp_val, "Unknown"), length);
	
	switch (length) {
		case 4:
			tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+3, sizeof addr_ipv4);
			proto_item_append_text(te, "%s", ip_to_str((guint8 *)&addr_ipv4));
			proto_tree_add_ipv4(ext_tree_chrg_addr, gtp_version ? hf_gtpv1_chrg_ipv4 : hf_gtpv0_chrg_ipv4, tvb, offset+3, 4, addr_ipv4);
			break;
		case 16: 
			tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+3, sizeof addr_ipv6);
			proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
			proto_tree_add_ipv6(ext_tree_chrg_addr, gtp_version ? hf_gtpv1_chrg_ipv6 : hf_gtpv0_chrg_ipv6, tvb, offset+3, 16, (guint8*)&addr_ipv6);
			break;
		default:
			proto_item_append_text(te, "unknown type or wrong length");
			break;
	}

	return 3 + length;
}

/* GPRS:	12.15
 * UMTS:	33.015
 */
static int
decode_gtp_rel_pack(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
	
	guint16		length, n, number;
	proto_tree	*ext_tree_rel_pack;
	proto_item	*te;

	length = tvb_get_ntohs(tvb, offset + 1);
	
	te = proto_tree_add_text(tree, tvb, offset, 3 + length, "Sequence numbers of released packets IE");
	ext_tree_rel_pack = proto_item_add_subtree(te, ett_gtp_rel_pack);
	
	n = 0;
	
	while (n < length) {

		number = tvb_get_ntohs(tvb, offset + 3 + n);
		proto_tree_add_text(ext_tree_rel_pack, tvb, offset + 3 + n, 2, "%u", number);
		n = n + 2;

	}
	
	return 3 + length;
}

/* GPRS:	12.15
 * UMTS:	33.015
 */
static int
decode_gtp_can_pack(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
	
	guint16		length, n, number;
	proto_tree	*ext_tree_can_pack;
	proto_item	*te;

	length = tvb_get_ntohs(tvb, offset + 1);
	
	te = proto_tree_add_text(tree, tvb, offset, 3 + length, "Sequence numbers of cancelled  packets IE");
	ext_tree_can_pack = proto_item_add_subtree(te, ett_gtp_can_pack);
	
	n = 0;
	
	while (n < length) {

		number = tvb_get_ntohs(tvb, offset + 3 + n);
		proto_tree_add_text(ext_tree_can_pack, tvb, offset + 3 + n, 2, "%u", number);
		n = n + 2;

	}
	
	return 3 + length;
}

/* CDRs dissector */
static int
decode_gtp_data_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
	
	guint16		length, format_ver, data_len, i, j;
	guint8		no, format, rectype;
	proto_tree	*ext_tree, *cdr_tree;
	proto_item	*te, *ce;

	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_DATA_REQ, gtp_val, "Unknown message"));
	ext_tree = proto_item_add_subtree(te, ett_gtp_ext);
	
	length = tvb_get_ntohs(tvb, offset + 1);
	no = tvb_get_guint8(tvb, offset + 3);
	format = tvb_get_guint8(tvb, offset + 4);
	format_ver = tvb_get_ntohs(tvb, offset + 5);
	
	proto_tree_add_text(ext_tree, tvb, offset+1, 2, "Length: %u", length);
	proto_tree_add_text(ext_tree, tvb, offset+3, 1, "Number of data records: %u", no);
	proto_tree_add_text(ext_tree, tvb, offset+4, 1, "Data record format: %u", format);
	proto_tree_add_text(ext_tree, tvb, offset+5, 2, "Data record format version: %u", format_ver);

	data_len = 0;
	offset = offset + 7;

	if (gtpv0_cdr_as != DONT_DISSECT_CDRS) {
	
	for (i = 0; i < no; i++) {
		data_len = tvb_get_ntohs(tvb, offset);
		rectype = tvb_get_guint8(tvb, offset+2);
		switch (rectype) {
			case 0x13:		/* GCDR */ 
				if (tvb_length_remaining(tvb, offset) < 3 + 118) {
					proto_tree_add_text(ext_tree, tvb, offset, tvb_length_remaining(tvb, offset), "GCDR fragmented, can't dissect");
					break;
				}
				
				tvb_memcpy(tvb, gcdr.imsi, offset+3, 8);	
				tvb_memcpy(tvb, (guint8 *)&gcdr.ggsnaddr, offset+11, sizeof gcdr.ggsnaddr);
				gcdr.chrgid = tvb_get_ntohl(tvb, offset+15);
				tvb_memcpy(tvb, (guint8 *)&gcdr.sgsnaddr, offset+19, sizeof gcdr.sgsnaddr);
				tvb_memcpy(tvb, gcdr.apn, offset+23, 63);
				gcdr.pdporg = tvb_get_guint8(tvb, offset+86);
				gcdr.pdptype = tvb_get_guint8(tvb, offset+87);
				tvb_memcpy(tvb, (guint8 *)&gcdr.pdpaddr, offset+88, sizeof gcdr.pdpaddr);
				gcdr.addrflag = tvb_get_guint8(tvb, offset+92);
				gcdr.uplink = tvb_get_ntohl(tvb, offset+96);
				gcdr.downlink = tvb_get_ntohl(tvb, offset+100);
				gcdr.timestamp = tvb_get_ntohl(tvb, offset+104);
				gcdr.opening = tvb_get_ntohl(tvb, offset+108);
				gcdr.duration = tvb_get_ntohl(tvb, offset+112);
				gcdr.closecause = tvb_get_guint8(tvb, offset+116);
				gcdr.seqno = tvb_get_ntohl(tvb, offset+117);
				
				ce = proto_tree_add_text(ext_tree, tvb, offset, data_len + 2, "GCDR (0x13), sequence number: %u", gcdr.seqno);
				cdr_tree = proto_item_add_subtree(ce, ett_gtp_ext);
				proto_tree_add_text(cdr_tree, tvb, offset, 2, "Length: %u", data_len);
				proto_tree_add_text(cdr_tree, tvb, offset+2, 1, "Type: %u (%x)", rectype, rectype);
				proto_tree_add_text(cdr_tree, tvb, offset+3, 8, "IMSI: %s", id_to_str(gcdr.imsi));
				proto_tree_add_text(cdr_tree, tvb, offset+11, 4, "GGSN address: %s", ip_to_str((guint8 *)&gcdr.ggsnaddr));
				proto_tree_add_text(cdr_tree, tvb, offset+15, 4, "Charging ID: %x", gcdr.chrgid);
				proto_tree_add_text(cdr_tree, tvb, offset+19, 4, "SGSN address: %s", ip_to_str((guint8 *)&gcdr.sgsnaddr));
				proto_tree_add_text(cdr_tree, tvb, offset+23, 63, "APN: %s", gcdr.apn);
				proto_tree_add_text(cdr_tree, tvb, offset+86, 1, "PDP org: %s", val_to_str(gcdr.pdporg, pdp_org_type, "Unknown PDP org"));
				proto_tree_add_text(cdr_tree, tvb, offset+87, 1, "PDP type: %s", val_to_str(gcdr.pdptype, pdp_type, "Unknown PDP type"));
				proto_tree_add_text(cdr_tree, tvb, offset+88, 4, "PDP address: %s", ip_to_str((guint8 *)&gcdr.pdpaddr));
				proto_tree_add_text(cdr_tree, tvb, offset+92, 1, "PDP address type: %u", gcdr.addrflag);
				decode_qos_gprs(tvb, offset+93, cdr_tree, "QoS", 0);
				proto_tree_add_text(cdr_tree, tvb, offset+96, 4, "Uplink volume: %u", gcdr.uplink);
				proto_tree_add_text(cdr_tree, tvb, offset+100, 4, "Downlink volume: %u", gcdr.downlink);
				proto_tree_add_text(cdr_tree, tvb, offset+104, 4, "Timestamp: %s", time_int_to_str(gcdr.timestamp));
				proto_tree_add_text(cdr_tree, tvb, offset+108, 4, "Record opening time: %s", time_int_to_str(gcdr.opening));
				proto_tree_add_text(cdr_tree, tvb, offset+112, 4, "Duration: %s", rel_time_int_to_str(gcdr.duration));
				proto_tree_add_text(cdr_tree, tvb, offset+116, 1, "Cause for close: %s (%u)", val_to_str(gcdr.closecause, cdr_close_type, "Unknown cause"), gcdr.closecause);
				proto_tree_add_text(cdr_tree, tvb, offset+117, 4, "Sequence number: %u", gcdr.seqno);
				
				if (data_len > 119) {
					tvb_memcpy (tvb, gcdr.msisdn, offset + 121, 9);
					proto_tree_add_text(cdr_tree, tvb, offset+121, 9, "MSISDN: %s", msisdn_to_str (gcdr.msisdn, 9));
				}
					
				break;

			case 0x12:		/* SCDR */
				if (tvb_length_remaining(tvb, offset) < 3 + 277) {
					proto_tree_add_text(ext_tree, tvb, offset, tvb_length_remaining(tvb, offset), "SCDR fragmented, can't dissect");
					break;
				}
				
				scdr.len = tvb_get_letohs(tvb, offset+3);
				scdr.netini = tvb_get_guint8(tvb, offset+5);
				scdr.anon = tvb_get_guint8(tvb, offset+6);
				scdr.imsilen = tvb_get_guint8(tvb, offset+7);
				tvb_memcpy(tvb, scdr.imsi, offset+8, 8);
				tvb_memcpy(tvb, scdr.imei, offset+16, 8);
				scdr.msisdnlen = tvb_get_guint8(tvb, offset+24);
				tvb_memcpy(tvb, scdr.msisdn, offset+25, 10);
				tvb_memcpy(tvb, (guint8 *)&scdr.sgsnaddr, offset+35, sizeof scdr.sgsnaddr);
				tvb_memcpy(tvb, scdr.msclass_notused, offset+39, 12);
				scdr.msclass_caplen = tvb_get_guint8(tvb, offset+51);
				scdr.msclass_cap = tvb_get_guint8(tvb, offset+52);
				scdr.msclass_capomit = tvb_get_ntohs(tvb, offset+53);
				scdr.lac = tvb_get_ntohs(tvb, offset+55);
				scdr.rac = tvb_get_guint8(tvb, offset+57);
				scdr.cid = tvb_get_ntohs(tvb, offset+58);
				scdr.chrgid = tvb_get_ntohl(tvb, offset+60);
				tvb_memcpy(tvb, (guint8 *)&scdr.ggsnaddr, offset+64, sizeof scdr.ggsnaddr);
				tvb_memcpy(tvb, scdr.apn, offset+68, 64);
				scdr.pdporg = tvb_get_guint8(tvb, offset+132);
				scdr.pdptype = tvb_get_guint8(tvb, offset+133);
				tvb_memcpy(tvb, (guint8 *)&scdr.pdpaddr, offset+134, sizeof scdr.pdpaddr);
				scdr.listind = tvb_get_guint8(tvb, offset+138);
				for (j=0;j<4;j++) {
					scdr.change[j].change = tvb_get_guint8(tvb, offset+139+23*j);
					scdr.change[j].time1 = tvb_get_ntohl(tvb, offset+140+23*j);
					scdr.change[j].time2 = tvb_get_ntohl(tvb, offset+144+23*j);
					scdr.change[j].uplink = tvb_get_ntohl(tvb, offset+148+23*j);
					scdr.change[j].downlink = tvb_get_ntohl(tvb, offset+152+23*j);
/*					tvb_memcpy(tvb, scdr.change[j].qos_req, offset+156+23*j, 3);
					tvb_memcpy(tvb, scdr.change[j].qos_neg, offset+159+23*j, 3);*/
				}
				scdr.timestamp = tvb_get_ntohl(tvb, offset+254);
				scdr.opening = tvb_get_ntohl(tvb, offset+258);
				scdr.duration = tvb_get_ntohl(tvb, offset+262);
				scdr.sgsnchange = tvb_get_guint8(tvb, offset+266);
				scdr.closecause = tvb_get_guint8(tvb, offset+267);
				scdr.diag1 = tvb_get_guint8(tvb, offset+268);
				scdr.diag2 = tvb_get_guint8(tvb, offset+269);
				scdr.diag3 = tvb_get_guint8(tvb, offset+270);
				scdr.diag4 = tvb_get_guint8(tvb, offset+271);
				scdr.diag5 = tvb_get_ntohl(tvb, offset+272);
				scdr.seqno = tvb_get_ntohl(tvb, offset+276);

				ce = proto_tree_add_text(ext_tree, tvb, offset, data_len + 2, "SCDR (type %x), sequence number: %u", rectype, scdr.seqno);
				cdr_tree = proto_item_add_subtree(ce, ett_gtp_ext);
				proto_tree_add_text(cdr_tree, tvb, offset, 2, "Length: %u", data_len);
				proto_tree_add_text(cdr_tree, tvb, offset+2, 1, "Type: %u (%x)", rectype, rectype);
				proto_tree_add_text(cdr_tree, tvb, offset+3, 2, "CDR length: %u", scdr.len);
				proto_tree_add_text(cdr_tree, tvb, offset+5, 1, "Network initiated PDP context: %s", yesno[scdr.netini]);
				proto_tree_add_text(cdr_tree, tvb, offset+6, 1, "Anonymous acces: %s", yesno[scdr.anon]);
				proto_tree_add_text(cdr_tree, tvb, offset+7, 1, "IMSI length: %u", scdr.imsilen);
				proto_tree_add_text(cdr_tree, tvb, offset+8, 8, "IMSI: %s", id_to_str(scdr.imsi));
				proto_tree_add_text(cdr_tree, tvb, offset+16, 8, "IMEI: %s", id_to_str(scdr.imei));
				proto_tree_add_text(cdr_tree, tvb, offset+24, 1, "MSISDN length: %u", scdr.msisdnlen);
				proto_tree_add_text(cdr_tree, tvb, offset+25, 10, "MSISDN: %s", msisdn_to_str(scdr.msisdn, 10));
				proto_tree_add_text(cdr_tree, tvb, offset+35, 4, "SGSN address: %s", ip_to_str((guint8 *)&scdr.sgsnaddr));
				proto_tree_add_text(cdr_tree, tvb, offset+39, 12, "(not used)");
				proto_tree_add_text(cdr_tree, tvb, offset+51, 1, "MS network capability length: %u", scdr.msclass_caplen);
				
/*				cap_id = proto_tree_add_text(cdr_tree, tvb, offset+52, 1, "MS network capability: %u", scdr.msclass_cap);
				cap_tree = proto_item_add_subtree(cap_id, ett_chrg_cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_gea, tvb, offset+52, 1, scdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_sm_gsm, tvb, offset+52, 1, scdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_sm_gprs, tvb, offset+52, 1, scdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_ucs2, tvb, offset+52, 1, scdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_ss, tvb, offset+52, 1, scdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_solsa, tvb, offset+52, 1, scdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_pad, tvb, offset+52, 1, scdr.cap);
*/

				proto_tree_add_text(cdr_tree, tvb, offset+53, 2, "MS network capability omitted: %u", scdr.msclass_capomit);
				proto_tree_add_text(cdr_tree, tvb, offset+55, 2, "LAC: %u", scdr.lac);
				proto_tree_add_text(cdr_tree, tvb, offset+57, 1, "RAC: %u", scdr.rac);
				proto_tree_add_text(cdr_tree, tvb, offset+58, 2, "Cell ID: %u", scdr.cid);
				proto_tree_add_text(cdr_tree, tvb, offset+60, 4, "Charging ID: %x", scdr.chrgid);
				proto_tree_add_text(cdr_tree, tvb, offset+64, 4, "GGSN address: %s", ip_to_str((guint8 *)&scdr.ggsnaddr));
				proto_tree_add_text(cdr_tree, tvb, offset+68, 64, "APN: %s", scdr.apn);
				proto_tree_add_text(cdr_tree, tvb, offset+132, 1, "PDP org: %s", val_to_str(scdr.pdporg, pdp_org_type, "Unknown PDP org"));
				proto_tree_add_text(cdr_tree, tvb, offset+133, 1, "PDP type: %s", val_to_str(scdr.pdptype, pdp_type, "Unknown PDP type"));
				proto_tree_add_text(cdr_tree, tvb, offset+134, 4, "PDP address: %s", ip_to_str((guint8 *)&scdr.pdpaddr));
				proto_tree_add_text(cdr_tree, tvb, offset+138, 1, "List of data volume index: %u", scdr.listind);
				for (j=0;j<4;j++) {
					proto_tree_add_text(cdr_tree, tvb, offset+139+23*j, 1, "List of data vol change condition: %u", scdr.change[j].change);
					proto_tree_add_text(cdr_tree, tvb, offset+140+23*j, 4, "Time1: %x", scdr.change[j].time1);
					proto_tree_add_text(cdr_tree, tvb, offset+144+23*j, 4, "Time2: %x", scdr.change[j].time2);
					proto_tree_add_text(cdr_tree, tvb, offset+148+23*j, 4, "Uplink: %x", scdr.change[j].uplink);
					proto_tree_add_text(cdr_tree, tvb, offset+152+23*j, 4, "Downlink: %x", scdr.change[j].downlink);
					decode_qos_gprs(tvb, offset+156, cdr_tree, "QoS requested", 0);
					decode_qos_gprs(tvb, offset+159, cdr_tree, "QoS negotiated", 0);
				}	
				proto_tree_add_text(cdr_tree, tvb, offset+254, 4, "Timestamp: %s", time_int_to_str(scdr.timestamp));
				proto_tree_add_text(cdr_tree, tvb, offset+258, 4, "Opening: %s", time_int_to_str(scdr.opening));
				proto_tree_add_text(cdr_tree, tvb, offset+262, 4, "Duration: %s", rel_time_int_to_str(scdr.duration));
				proto_tree_add_text(cdr_tree, tvb, offset+266, 1, "SGSN change: %u", scdr.sgsnchange);
				proto_tree_add_text(cdr_tree, tvb, offset+267, 1, "Cause for close: %s (%u)", val_to_str(scdr.closecause, cdr_close_type, "Unknown cause"), scdr.closecause);
				proto_tree_add_text(cdr_tree, tvb, offset+268, 1, "Diagnostics 1: %u", scdr.diag1);
				proto_tree_add_text(cdr_tree, tvb, offset+269, 1, "Diagnostics 2: %u", scdr.diag2);
				proto_tree_add_text(cdr_tree, tvb, offset+270, 1, "Diagnostics 3: %u", scdr.diag3);
				proto_tree_add_text(cdr_tree, tvb, offset+271, 1, "Diagnostics 4: %u", scdr.diag4);
				proto_tree_add_text(cdr_tree, tvb, offset+272, 4, "Diagnostics 5: %u", scdr.diag5);
				proto_tree_add_text(cdr_tree, tvb, offset+276, 4, "Sequence number: %u", scdr.seqno);
				break;
			case 0x14:		/* MCDR */
				if (tvb_length_remaining(tvb, offset) < 3 + 147) {
					proto_tree_add_text(ext_tree, tvb, offset, tvb_length_remaining(tvb, offset), "MCDR fragmented, can't dissect");
					break;
				}

				mcdr.len = tvb_get_ntohs(tvb, offset+3);
				mcdr.imsilen = tvb_get_guint8(tvb, offset+5);
				tvb_memcpy(tvb, mcdr.imsi, offset+6, 8);
				tvb_memcpy(tvb, mcdr.imei, offset+14, 8);
				mcdr.msisdnlen = tvb_get_guint8(tvb, offset+22);
				tvb_memcpy(tvb, mcdr.msisdn, offset+23, 10);
				tvb_memcpy(tvb, (guint8 *)&mcdr.sgsnaddr, offset+33, sizeof mcdr.sgsnaddr);
				tvb_memcpy(tvb, mcdr.msclass_notused, offset+37, 12);
				mcdr.msclass_caplen = tvb_get_guint8(tvb, offset+49);
				mcdr.msclass_cap = tvb_get_guint8(tvb, offset+50);
				mcdr.msclass_capomit = tvb_get_ntohs(tvb, offset+51);
				mcdr.lac = tvb_get_ntohs(tvb, offset+53);
				mcdr.rac = tvb_get_guint8(tvb, offset+55);
				mcdr.cid = tvb_get_ntohs(tvb, offset+56);
				mcdr.change_count = tvb_get_guint8(tvb, offset+58);
				for (j=0;j<4;j++) {
					mcdr.change[j].lac = tvb_get_ntohs(tvb, offset+59+13*j);
					mcdr.change[j].rac = tvb_get_guint8(tvb, offset+61+13*j);
					mcdr.change[j].cid = tvb_get_ntohs(tvb, offset+62+13*j);
					tvb_memcpy(tvb, mcdr.change[j].omit, offset+64+13*j, 8);
				}
				mcdr.timestamp = tvb_get_ntohl(tvb, offset+124);
				mcdr.opening = tvb_get_ntohl(tvb, offset+128);
				mcdr.duration = tvb_get_ntohl(tvb, offset+132);
				mcdr.sgsnchange = tvb_get_guint8(tvb, offset+136);
				mcdr.closecause = tvb_get_guint8(tvb, offset+137);
				mcdr.diag1 = tvb_get_guint8(tvb, offset+138);
				mcdr.diag2 = tvb_get_guint8(tvb, offset+139);
				mcdr.diag3 = tvb_get_guint8(tvb, offset+140);
				mcdr.diag4 = tvb_get_guint8(tvb, offset+141);
				mcdr.diag5 = tvb_get_ntohl(tvb, offset+142);
				mcdr.seqno = tvb_get_ntohl(tvb, offset+146);

				ce = proto_tree_add_text(ext_tree, tvb, offset, data_len + 2, "MCDR (0x14), sequence number: %u", mcdr.seqno);
				cdr_tree = proto_item_add_subtree(ce, ett_gtp_ext);
				proto_tree_add_text(cdr_tree, tvb, offset, 2, "Length: %u", data_len);
				proto_tree_add_text(cdr_tree, tvb, offset+2, 1, "Type: %u (%x)", rectype, rectype);
				proto_tree_add_text(cdr_tree, tvb, offset+3, 2, "MCDR length: %u", mcdr.len);
				proto_tree_add_text(cdr_tree, tvb, offset+5, 1, "IMSI length: %u", mcdr.imsilen);
				proto_tree_add_text(cdr_tree, tvb, offset+6, 8, "IMSI: %s", id_to_str(mcdr.imsi));
				proto_tree_add_text(cdr_tree, tvb, offset+14, 8, "IMEI: %s", id_to_str(mcdr.imei));
				proto_tree_add_text(cdr_tree, tvb, offset+22, 1, "MSISDN length: %u", mcdr.msisdnlen);
				proto_tree_add_text(cdr_tree, tvb, offset+23, 10, "MSISDN: %s", msisdn_to_str(mcdr.msisdn, 10));
				proto_tree_add_text(cdr_tree, tvb, offset+33, 4, "SGSN address: %s", ip_to_str((guint8 *)&mcdr.sgsnaddr));
				proto_tree_add_text(cdr_tree, tvb, offset+37, 12, "(not used)");
				proto_tree_add_text(cdr_tree, tvb, offset+49, 1, "MS network capability length: %u", mcdr.msclass_caplen);
				
/*				cap_id = proto_tree_add_text(cdr_tree, tvb, offset+50, 1, "MS network capability: %u", mcdr.msclass_cap);
				cap_tree = proto_item_add_subtree(cap_id, ett_chrg_cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_gea, tvb, offset+50, 1, mcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_sm_gsm, tvb, offset+50, 1, mcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_sm_gprs, tvb, offset+50, 1, mcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_ucs2, tvb, offset+50, 1, mcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_ss, tvb, offset+50, 1, mcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_solsa, tvb, offset+50, 1, mcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_pad, tvb, offset+50, 1, mcdr.cap);
*/
				proto_tree_add_text(cdr_tree, tvb, offset+51, 2, "MS network capability omitted: %u", mcdr.msclass_capomit);
				proto_tree_add_text(cdr_tree, tvb, offset+53, 2, "LAC: %u", mcdr.lac);
				proto_tree_add_text(cdr_tree, tvb, offset+55, 1, "RAC: %u", mcdr.rac);
				proto_tree_add_text(cdr_tree, tvb, offset+56, 2, "Cell ID: %u", mcdr.cid);
				proto_tree_add_text(cdr_tree, tvb, offset+58, 1, "List of data volume changes: %u", mcdr.change_count);
				for (j=0;j<4;j++) {
					proto_tree_add_text(cdr_tree, tvb, offset+59+13*j, 2, "LAC: %u", mcdr.change[j].lac);
					proto_tree_add_text(cdr_tree, tvb, offset+61+13*j, 1, "RAC: %u", mcdr.change[j].rac);
					proto_tree_add_text(cdr_tree, tvb, offset+62+13*j, 2, "CID: %u", mcdr.change[j].cid);
					proto_tree_add_text(cdr_tree, tvb, offset+64+13*j, 8, "(omitted)");
				}

				proto_tree_add_text(cdr_tree, tvb, offset+124, 4, "Timestamp: %s", time_int_to_str(mcdr.timestamp));
				proto_tree_add_text(cdr_tree, tvb, offset+128, 4, "Record opening time: %s", time_int_to_str(mcdr.opening));
				proto_tree_add_text(cdr_tree, tvb, offset+132, 4, "Duration: %s", rel_time_int_to_str(mcdr.duration));
				proto_tree_add_text(cdr_tree, tvb, offset+136, 1, "SGSN change: %u", mcdr.sgsnchange);
				proto_tree_add_text(cdr_tree, tvb, offset+137, 1, "Cause for close: %s (%u)", val_to_str(mcdr.closecause, cdr_close_type, "Unknown cause"), mcdr.closecause);
				proto_tree_add_text(cdr_tree, tvb, offset+138, 1, "Diagnostics 1: %u", mcdr.diag1);
				proto_tree_add_text(cdr_tree, tvb, offset+139, 1, "Diagnostics 2: %u", mcdr.diag2);
				proto_tree_add_text(cdr_tree, tvb, offset+140, 1, "Diagnostics 3: %u", mcdr.diag3);
				proto_tree_add_text(cdr_tree, tvb, offset+141, 1, "Diagnostics 4: %u", mcdr.diag4);
				proto_tree_add_text(cdr_tree, tvb, offset+142, 4, "Diagnostics 5: %u", mcdr.diag5);
				proto_tree_add_text(cdr_tree, tvb, offset+146, 4, "Sequence number: %u", mcdr.seqno);
				break;

			case 0x15:		/* SOCDR */
				if (tvb_length_remaining(tvb, offset) < 3 + 80) {
					proto_tree_add_text(ext_tree, tvb, offset, tvb_length_remaining(tvb, offset), "SOCDR fragmented, can't dissect");
					break;
				}

				socdr.len = tvb_get_ntohs(tvb, offset+3);
				socdr.imsilen = tvb_get_guint8(tvb, offset+5);
				tvb_memcpy(tvb, socdr.imsi, offset+6, 8);
				tvb_memcpy(tvb, socdr.imei, offset+14, 8);
				socdr.msisdnlen = tvb_get_guint8(tvb, offset+22);
				tvb_memcpy(tvb, socdr.msisdn, offset+23, 10);
				tvb_memcpy(tvb, socdr.msclass_notused, offset+33, 12);
				socdr.msclass_caplen = tvb_get_guint8(tvb, offset+45);
				socdr.msclass_cap = tvb_get_guint8(tvb, offset+46);
				socdr.msclass_capomit = tvb_get_ntohs(tvb, offset+47);
				tvb_memcpy(tvb, socdr.serv_centr, offset+49, 9);
				tvb_memcpy(tvb, socdr.rec_ent, offset+58, 9);
				socdr.lac = tvb_get_ntohs(tvb, offset+67);
				socdr.rac = tvb_get_guint8(tvb, offset+69);
				socdr.cid = tvb_get_ntohs(tvb, offset+70);
				socdr.time1 = tvb_get_ntohl(tvb, offset+72);
				socdr.time2 = tvb_get_ntohl(tvb, offset+76);
				socdr.messref = tvb_get_guint8(tvb, offset+80);
				socdr.smsres = tvb_get_ntohs(tvb, offset+81);

				ce = proto_tree_add_text(ext_tree, tvb, offset, data_len + 2, "SOCDR (0x15)");
				cdr_tree = proto_item_add_subtree(ce, ett_gtp_ext);
				proto_tree_add_text(cdr_tree, tvb, offset, 2, "Length: %u", data_len);
				proto_tree_add_text(cdr_tree, tvb, offset+2, 1, "Type: %u (%x)", rectype, rectype);
				proto_tree_add_text(cdr_tree, tvb, offset+3, 2, "MCDR length: %u", socdr.len);
				proto_tree_add_text(cdr_tree, tvb, offset+5, 1, "IMSI length: %u", socdr.imsilen);
				proto_tree_add_text(cdr_tree, tvb, offset+6, 8, "IMSI: %s", id_to_str(socdr.imsi));
				proto_tree_add_text(cdr_tree, tvb, offset+14, 8, "IMEI: %s", id_to_str(socdr.imei));
				proto_tree_add_text(cdr_tree, tvb, offset+22, 1, "MSISDN length: %u", socdr.msisdnlen);
				proto_tree_add_text(cdr_tree, tvb, offset+23, 10, "MSISDN: %s", msisdn_to_str(socdr.msisdn, 10));
				proto_tree_add_text(cdr_tree, tvb, offset+33, 12, "(not used)");
				proto_tree_add_text(cdr_tree, tvb, offset+45, 1, "MS network capability length: %u", socdr.msclass_caplen);
				
/*				cap_id = proto_tree_add_text(cdr_tree, tvb, offset+46, 1, "MS network capability: %u", socdr.msclass_cap);
				cap_tree = proto_item_add_subtree(cap_id, ett_chrg_cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_gea, tvb, offset+46, 1, socdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_sm_gsm, tvb, offset+46, 1, socdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_sm_gprs, tvb, offset+46, 1, socdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_ucs2, tvb, offset+46, 1, socdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_ss, tvb, offset+46, 1, socdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_solsa, tvb, offset+46, 1, socdr.cap);
*/
				proto_tree_add_text(cdr_tree, tvb, offset+47, 2, "MS network capability omitted: %u", stcdr.msclass_capomit);
				proto_tree_add_text(cdr_tree, tvb, offset+49, 9, "SMSC E.164 address: %s", msisdn_to_str(socdr.serv_centr, 9));
				proto_tree_add_text(cdr_tree, tvb, offset+58, 9, "SGSN E.164 address: %s", msisdn_to_str(socdr.rec_ent, 9));
				proto_tree_add_text(cdr_tree, tvb, offset+67, 2, "LAC: %u", socdr.lac);
				proto_tree_add_text(cdr_tree, tvb, offset+69, 1, "RAC: %u", socdr.rac);
				proto_tree_add_text(cdr_tree, tvb, offset+70, 2, "Cell ID: %u", socdr.cid);
				proto_tree_add_text(cdr_tree, tvb, offset+72, 4, "Time1: %s", time_int_to_str(socdr.time1));
				proto_tree_add_text(cdr_tree, tvb, offset+76, 4, "Time2: %s", time_int_to_str(socdr.time2));
				proto_tree_add_text(cdr_tree, tvb, offset+80, 1, "Message reference: %u", socdr.messref);
				proto_tree_add_text(cdr_tree, tvb, offset+81, 2, "Delivery result: %u", socdr.smsres);
				break;

			case 0x16:		/* STCDR */
				if (tvb_length_remaining(tvb, offset) < 3 + 79) {
					proto_tree_add_text(ext_tree, tvb, offset, tvb_length_remaining(tvb, offset), "STCDR fragmented, can't dissect");
					break;
				}

				stcdr.len = tvb_get_ntohs(tvb, offset+3);
				stcdr.imsilen = tvb_get_guint8(tvb, offset+5);
				tvb_memcpy(tvb, stcdr.imsi, offset+6, 8);
				tvb_memcpy(tvb, stcdr.imei, offset+14, 8);
				stcdr.msisdnlen = tvb_get_guint8(tvb, offset+22);
				tvb_memcpy(tvb, stcdr.msisdn, offset+23, 10);
				tvb_memcpy(tvb, stcdr.msclass_notused, offset+33, 12);
				stcdr.msclass_caplen = tvb_get_guint8(tvb, offset+45);
				stcdr.msclass_cap = tvb_get_guint8(tvb, offset+46);
				stcdr.msclass_capomit = tvb_get_ntohs(tvb, offset+47);
				tvb_memcpy(tvb, stcdr.serv_centr, offset+49, 9);
				tvb_memcpy(tvb, stcdr.rec_ent, offset+58, 9);
				stcdr.lac = tvb_get_ntohs(tvb, offset+67);
				stcdr.rac = tvb_get_guint8(tvb, offset+69);
				stcdr.cid = tvb_get_ntohs(tvb, offset+70);
				stcdr.time1 = tvb_get_ntohl(tvb, offset+72);
				stcdr.time2 = tvb_get_ntohl(tvb, offset+76);
				stcdr.smsres = tvb_get_ntohs(tvb, offset+80);

				ce = proto_tree_add_text(ext_tree, tvb, offset, data_len + 2, "STCDR (0x16)");
				cdr_tree = proto_item_add_subtree(ce, ett_gtp_ext);
				proto_tree_add_text(cdr_tree, tvb, offset, 2, "Length: %u", data_len);
				proto_tree_add_text(cdr_tree, tvb, offset+2, 1, "Type: %u (%x)", rectype, rectype);
				proto_tree_add_text(cdr_tree, tvb, offset+3, 2, "MCDR length: %u", stcdr.len);
				proto_tree_add_text(cdr_tree, tvb, offset+5, 1, "IMSI length: %u", stcdr.imsilen);
				proto_tree_add_text(cdr_tree, tvb, offset+6, 8, "IMSI: %s", id_to_str(stcdr.imsi));
				proto_tree_add_text(cdr_tree, tvb, offset+14, 8, "IMEI: %s", id_to_str(stcdr.imei));
				proto_tree_add_text(cdr_tree, tvb, offset+22, 1, "MSISDN length: %u", stcdr.msisdnlen);
				proto_tree_add_text(cdr_tree, tvb, offset+23, 10, "MSISDN: %s", msisdn_to_str(stcdr.msisdn, 10));
				proto_tree_add_text(cdr_tree, tvb, offset+33, 12, "(not used)");
				proto_tree_add_text(cdr_tree, tvb, offset+45, 1, "MS network capability length: %u", stcdr.msclass_caplen);
				
/*				cap_id = proto_tree_add_text(cdr_tree, tvb, offset+46, 1, "MS network capability: %u", stcdr.msclass_cap);
				cap_tree = proto_item_add_subtree(cap_id, ett_chrg_cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_gea, tvb, offset+46, 1, stcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_sm_gsm, tvb, offset+46, 1, stcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_sm_gprs, tvb, offset+46, 1, stcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_ucs2, tvb, offset+46, 1, stcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_ss, tvb, offset+46, 1, stcdr.cap);
				proto_tree_add_uint(cap_tree, hf_gtpv0_chrg_cap_solsa, tvb, offset+46, 1, stcdr.cap);
*/
				proto_tree_add_text(cdr_tree, tvb, offset+47, 2, "MS network capability omitted: %u", stcdr.msclass_capomit);
				proto_tree_add_text(cdr_tree, tvb, offset+49, 9, "SMSC E.164 address: %s", msisdn_to_str(stcdr.serv_centr, 9));
				proto_tree_add_text(cdr_tree, tvb, offset+58, 9, "SGSN E.164 address: %s", msisdn_to_str(stcdr.rec_ent, 9));
				proto_tree_add_text(cdr_tree, tvb, offset+67, 2, "LAC: %u", stcdr.lac);
				proto_tree_add_text(cdr_tree, tvb, offset+69, 1, "RAC: %u", stcdr.rac);
				proto_tree_add_text(cdr_tree, tvb, offset+70, 2, "Cell ID: %u", stcdr.cid);
				proto_tree_add_text(cdr_tree, tvb, offset+72, 4, "Time1: %s", time_int_to_str(stcdr.time1));
				proto_tree_add_text(cdr_tree, tvb, offset+76, 4, "Time2: %s", time_int_to_str(stcdr.time2));
				proto_tree_add_text(cdr_tree, tvb, offset+80, 2, "Delivery result: %u", stcdr.smsres);
				break;
		}
		offset = offset + 2 + data_len;
	}
	}
	return 3+length;
}

/* GPRS:	12.15
 * UMTS:	33.015
 */
static int
decode_gtp_data_resp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
	
	guint16		length, n, number;
	proto_tree	*ext_tree_data_resp;
	proto_item	*te;

	length = tvb_get_ntohs(tvb, offset + 1);
	
	te = proto_tree_add_text(tree, tvb, offset, 3 + length, "Requests responded");
	ext_tree_data_resp = proto_item_add_subtree(te, ett_gtp_data_resp);
	
	n = 0;
	
	while (n < length) {

		number = tvb_get_ntohs(tvb, offset + 3 + n);
		proto_tree_add_text(ext_tree_data_resp, tvb, offset + 3 + n, 2, "%u", number);
		n = n + 2;

	}

	return 3 + length;

}
	
/* GPRS:	12.15
 * UMTS:	33.015
 */
static int
decode_gtp_node_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16		length;	
	guint32		addr_ipv4;
	struct	e_in6_addr addr_ipv6;
	proto_tree	*ext_tree_node_addr;
	proto_item	*te;
	
	length = tvb_get_ntohs(tvb, offset+1);
	
	te = proto_tree_add_text(tree, tvb, offset, 3+length, "Node address: ");
	ext_tree_node_addr = proto_item_add_subtree(te, ett_gtp_node_addr);
	
	proto_tree_add_text(ext_tree_node_addr, tvb, offset+1, 2, "Node address length: %u", length);
	
	switch (length) {
		case 4:
			tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+3, sizeof addr_ipv4);
			proto_item_append_text(te, "%s", ip_to_str((guint8 *)&addr_ipv4));
			proto_tree_add_ipv4(ext_tree_node_addr, gtp_version ? hf_gtpv1_node_ipv4 : hf_gtpv0_node_ipv4, tvb, offset+3, 4, addr_ipv4);
			break;
		case 16: 
			tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+3, sizeof addr_ipv6);
			proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
			proto_tree_add_ipv6(ext_tree_node_addr, gtp_version ? hf_gtpv1_node_ipv6 : hf_gtpv0_node_ipv6, tvb, offset+3, 16, (guint8*)&addr_ipv6);
			break;
		default:
			proto_item_append_text(te, "unknown type or wrong length");
			break;
	}

	return 3 + length;

}

/* GPRS:	9.60 v7.6.0, chapter 7.9.26
 * UMTS:	29.060 v4.0, chapter 7.7.44
 */
static int
decode_gtp_priv_ext(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {	
		
	guint16		length, ext_id;	
	gchar		ext_val[64];
	proto_tree	*ext_tree_priv_ext;
	proto_item	*te;
	
	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_PRIV_EXT, gtp_val, "Unknown message"));
	ext_tree_priv_ext = proto_item_add_subtree(te, ett_gtp_ext);
	
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < 1) return 3+length;
	
	ext_id = tvb_get_ntohs(tvb, offset+3);	
	tvb_memcpy(tvb, ext_val, offset+5, length > 65 ? 63 : length-2);
	ext_val[length > 65 ? 64 : length-1] = '\0';
	proto_tree_add_uint(ext_tree_priv_ext, gtp_version ? hf_gtpv1_ext_id : hf_gtpv0_ext_id, tvb, offset+3, 2, ext_id);
	proto_tree_add_string(ext_tree_priv_ext, gtp_version ? hf_gtpv1_ext_val : hf_gtpv0_ext_val, tvb, offset+5, length-2, ext_val);
	
	return 3+length;
}

static int
decode_gtp_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	proto_tree_add_text(tree, tvb, offset, 1, "Unknown extension header");

	return tvb_length_remaining(tvb, offset);
}

static void
dissect_gtpv0(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	
	_gtpv0_hdr	gtpv0_hdr;
	proto_item	*ti, *tf;
	proto_tree	*gtpv0_tree, *flags_tree;
	guint8		ext_hdr_val;
	tvbuff_t	*next_tvb;
	const guint8	*tid_val;
	gchar		*tid_str;
	int		offset, length, i, mandatory, checked_field;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	tvb_memcpy(tvb, (guint8 *)&gtpv0_hdr, 0, 12); 
	tid_val = tvb_get_ptr(tvb, 12, 8);
	tid_str = id_to_str(tid_val);
	gtp_version = (gtpv0_hdr.flags >> 5) & 0x07;

	if (!((gtpv0_hdr.flags >> 4) & 1)) {
		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTP-CDR");
	} else {
		switch ((gtpv0_hdr.flags >> 5) & 0x07) {
		case 0: if (check_col(pinfo->cinfo, COL_PROTOCOL))
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTP");
			break;
		case 1: if (check_col(pinfo->cinfo, COL_PROTOCOL))
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTPv1");
		default: if (check_col(pinfo->cinfo, COL_PROTOCOL))
				col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTPv?");
			break;
		}
	}

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(gtpv0_hdr.message, message_type, "Unknown"));
	
	if (tree) {
			
		/* dissect GTP header */
		ti = proto_tree_add_item(tree, proto_gtpv0, tvb, 0, -1, FALSE);
		gtpv0_tree = proto_item_add_subtree(ti, ett_gtp);

		tf = proto_tree_add_uint(gtpv0_tree, hf_gtpv0_flags, tvb, 0, 1, gtpv0_hdr.flags);

		flags_tree = proto_item_add_subtree(tf, ett_gtp_flags);
		proto_tree_add_uint(flags_tree, hf_gtpv0_flags_ver, tvb, 0, 1, gtpv0_hdr.flags);
		proto_tree_add_uint(flags_tree, hf_gtpv0_flags_pt, tvb, 0, 1, gtpv0_hdr.flags);
		proto_tree_add_uint(flags_tree, hf_gtpv0_flags_spare, tvb, 0, 1, gtpv0_hdr.flags);
		proto_tree_add_boolean(flags_tree, hf_gtpv0_flags_snn, tvb, 0, 1, gtpv0_hdr.flags);
		
		gtpv0_hdr.length = ntohs(gtpv0_hdr.length);
		gtpv0_hdr.seq_no = ntohs(gtpv0_hdr.seq_no);
		proto_tree_add_uint(gtpv0_tree, hf_gtpv0_message_type, tvb, 1, 1, gtpv0_hdr.message);
		proto_tree_add_uint(gtpv0_tree, hf_gtpv0_length, tvb, 2, 2, gtpv0_hdr.length);
		proto_tree_add_uint(gtpv0_tree, hf_gtpv0_seq_number, tvb, 4, 2, gtpv0_hdr.seq_no);
		proto_tree_add_uint(gtpv0_tree, hf_gtpv0_flow_label, tvb, 6, 2, gtpv0_hdr.flow_label);
		proto_tree_add_uint(gtpv0_tree, hf_gtpv0_sndcp_number, tvb, 8, 1, gtpv0_hdr.sndcp_no);
		proto_tree_add_string(gtpv0_tree, hf_gtpv0_tid, tvb, 12, 8, tid_str);
	
		if (gtpv0_hdr.message != GTP_MSG_TPDU) {
				
			proto_tree_add_text(gtpv0_tree, tvb, 0, 0, "[--- end of GTPv0 header, beginning of extension headers ---]");
					
			offset = GTPv0_HDR_LENGTH;
			length = tvb_length(tvb);

			mandatory = 0;		/* check order of GTP fields against ETSI */
		
			for (;;) {
					
				if (offset >= length) break;
				ext_hdr_val = tvb_get_guint8(tvb, offset);
				
				if (gtpv0_etsi_order) {
					checked_field = check_field_presence (gtpv0_hdr.message, ext_hdr_val , (int *)&mandatory);
					switch (checked_field) {
						case -2: proto_tree_add_text(gtpv0_tree, tvb, 0, 0, "[WARNING] message not found");
							 break;
						case -1: proto_tree_add_text(gtpv0_tree, tvb, 0, 0, "[WARNING] field not present");
							 break;
						case 0:  break;
						default: proto_tree_add_text(gtpv0_tree, tvb, offset, 1, "[WARNING] wrong next field, should be: %s", val_to_str(checked_field, gtp_val, "Unknown extension field"));
					}
				}
				
				i = -1;
				while (gtpopt[++i].optcode) if (gtpopt[i].optcode == ext_hdr_val) break;
				offset = offset + (*gtpopt[i].decode)(tvb, offset, pinfo, gtpv0_tree);
			}
		}
	} 

/* next part dissects sublayers of GTP
 * right now it's only IP */
	
	if ((gtpv0_hdr.message == GTP_MSG_TPDU) && gtp_tpdu) {
		next_tvb = tvb_new_subset(tvb, 20, -1, -1);
		call_dissector(ip_handle, next_tvb, pinfo, tree);
		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_append_str_gtp(pinfo->cinfo, COL_PROTOCOL, "GTP");
	}
	
}

/* GTP v1 dissector */
static void
dissect_gtpv1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	
	_gtpv1_hdr	gtpv1_hdr;
	proto_item	*ti, *tf;
	proto_tree	*gtpv1_tree, *flags_tree;
	guint16		seq_no;
	guint8		ext_hdr_val, i, hdr_offset = 4, next_hdr, npdu_no, probe;
	tvbuff_t	*next_tvb;
	int		offset, length, mandatory, checked_field;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTP-C");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	tvb_memcpy(tvb, (guint8 *)&gtpv1_hdr, 0, 8);
	gtp_version = (gtpv1_hdr.flags >> 5) & 0x07;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(gtpv1_hdr.message, message_type, "Unknown"));

	if (tree) {
			
		ti = proto_tree_add_item(tree, proto_gtpv1, tvb, 0, -1, FALSE);
		gtpv1_tree = proto_item_add_subtree(ti, ett_gtp);

		tf = proto_tree_add_uint(gtpv1_tree, hf_gtpv1_flags, tvb, 0, 1, gtpv1_hdr.flags);
		flags_tree = proto_item_add_subtree(tf, ett_gtp_flags);
		
		proto_tree_add_uint(flags_tree, hf_gtpv1_flags_ver, tvb, 0, 1, gtpv1_hdr.flags);
		proto_tree_add_uint(flags_tree, hf_gtpv1_flags_pt, tvb, 0, 1, gtpv1_hdr.flags);
		proto_tree_add_uint(flags_tree, hf_gtpv1_flags_spare, tvb, 0, 1, gtpv1_hdr.flags);
		proto_tree_add_boolean(flags_tree, hf_gtpv1_flags_e, tvb, 0, 1, gtpv1_hdr.flags);
		proto_tree_add_boolean(flags_tree, hf_gtpv1_flags_s, tvb, 0, 1, gtpv1_hdr.flags);
		proto_tree_add_boolean(flags_tree, hf_gtpv1_flags_pn, tvb, 0, 1, gtpv1_hdr.flags);
		
		gtpv1_hdr.length = ntohs(gtpv1_hdr.length);
		gtpv1_hdr.teid = ntohl(gtpv1_hdr.teid);
		
		proto_tree_add_uint(gtpv1_tree, hf_gtpv1_message_type, tvb, 1, 1, gtpv1_hdr.message);
		proto_tree_add_uint(gtpv1_tree, hf_gtpv1_length, tvb, 2, 2, gtpv1_hdr.length);
		proto_tree_add_uint(gtpv1_tree, hf_gtpv1_teid, tvb, 4, 4, gtpv1_hdr.teid);

		if (gtpv1_hdr.flags & 0x07) {
			seq_no = tvb_get_ntohs (tvb, 8);
			proto_tree_add_uint (gtpv1_tree, hf_gtpv1_seq_number, tvb, 8, 2, seq_no);
			npdu_no = tvb_get_guint8 (tvb, 10);
			proto_tree_add_uint (gtpv1_tree, hf_gtpv1_npdu_number, tvb, 10, 1, npdu_no);
			next_hdr = tvb_get_guint8(tvb, 11);
			proto_tree_add_uint(gtpv1_tree, hf_gtpv1_next, tvb, 11, 1, next_hdr);
			hdr_offset = 0;
			
			if (next_hdr) hdr_offset = 1;
			else hdr_offset = 0;
		}
	
		if (gtpv1_hdr.message != GTP_MSG_TPDU) {

			proto_tree_add_text(gtpv1_tree, tvb, 0, 0, "[--- end of GTP v1 header, beginning of extension headers ---]");
				
			offset = GTPv1_HDR_LENGTH - hdr_offset;
			length = tvb_length(tvb);
		
			mandatory = 0;		/* check order of GTP fields against ETSI */
		
			for (;;) {
					
				if (offset >= length) break;
				ext_hdr_val = tvb_get_guint8(tvb, offset);
				
				if (gtpv1_etsi_order) {
					checked_field = check_field_presence (gtpv1_hdr.message, ext_hdr_val , (int *)&mandatory);
					switch (checked_field) {
						case -2: proto_tree_add_text(gtpv1_tree, tvb, 0, 0, "[WARNING] message not found");
							 break;
						case -1: proto_tree_add_text(gtpv1_tree, tvb, 0, 0, "[WARNING] field not present");
							 break;
						case 0:  break;
						default: proto_tree_add_text(gtpv1_tree, tvb, offset, 1, "[WARNING] wrong next field, should be: %s", val_to_str(checked_field, gtp_val, "Unknown extension field"));
					}
				}
				
				i = -1;
				while (gtpopt[++i].optcode) if (gtpopt[i].optcode == ext_hdr_val) break;
				offset = offset + (*gtpopt[i].decode)(tvb, offset, pinfo, gtpv1_tree);
			}
		} 
	}

	if (gtpv1_hdr.message == GTP_MSG_ERR_IND)
		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_add_str(pinfo->cinfo, COL_PROTOCOL, "GTP-U");


	if ((gtpv1_hdr.message == GTP_MSG_TPDU) && gtp_tpdu) {
	
		if (gtpv1_hdr.flags & 0x07) {	
			if (tvb_get_guint8 (tvb, 11)) hdr_offset = 1;		/* if next_hdr != 0 */
			else hdr_offset = 0;
		}
		
		next_tvb = tvb_new_subset(tvb, GTPv1_HDR_LENGTH - hdr_offset, -1, -1);
		call_dissector(ip_handle, next_tvb, pinfo, tree);
		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_append_str_gtp(pinfo->cinfo, COL_PROTOCOL, "GTP-U");
	}
}

static const true_false_string yes_no_tfs = { 
	"yes" ,
	"no"
};

void
proto_register_gtp(void)
{                 

	static hf_register_info hf_gtpv0[] = {

	{ &hf_gtpv0_flags,		{ "Flags", 		"gtpv0.flags", 			FT_UINT8, 	BASE_HEX, NULL, 0, "Ver/PT/Spare/SNN", HFILL }},
	{ &hf_gtpv0_flags_ver,		{ "Version",		"gtpv0.flags.version",		FT_UINT8,	BASE_DEC, VALS(ver_types), GTP_VER_MASK, "GTP Version", HFILL }},
	{ &hf_gtpv0_flags_pt,		{ "Protocol type",	"gtpv0.flags.payload",		FT_UINT8,	BASE_DEC, NULL, GTP_PT_MASK, "Protocol Type (1 = GTP, 0 = GTP' )", HFILL }},
	{ &hf_gtpv0_flags_spare,		{ "Reserved",		"gtpv0.flags.reserved",		FT_UINT8,	BASE_DEC, NULL, GTP_SPARE_MASK, "Reserved (shall be sent as '111' )", HFILL }},
	{ &hf_gtpv0_flags_snn,		{ "Is SNDCP N-PDU included?", "gtpv0.flags.snn",	FT_BOOLEAN, 	8, TFS(&yes_no_tfs), GTP_SNN_MASK, "Is SNDCP N-PDU LLC Number included? (1 = yes, 0 = no)", HFILL }},
	{ &hf_gtpv0_message_type,		{ "Message type",	"gtpv0.message",		FT_UINT8, 	BASE_HEX, VALS(message_type), 0x0, "GTP Message Type", HFILL }},
	{ &hf_gtpv0_length,		{ "Length", 		"gtpv0.length", 		FT_UINT16, 	BASE_DEC, NULL, 0, "Length (i.e. number of octets after TID or TEID)", HFILL }},
	{ &hf_gtpv0_seq_number,		{ "Sequence number", 	"gtpv0.seq_number",		FT_UINT16, 	BASE_HEX, NULL, 0, "Sequence Number", HFILL }},
	{ &hf_gtpv0_flow_label,		{ "Flow label", 	"gtpv0.flow_label",		FT_UINT16, 	BASE_HEX, NULL, 0, "Flow label", HFILL }},
	{ &hf_gtpv0_sndcp_number,		{ "SNDCP N-PDU LLC Number", "gtpv0.sndcp_number",		FT_UINT8, 	BASE_HEX, NULL, 0, "SNDCP N-PDU LLC Number", HFILL }},
	{ &hf_gtpv0_tid,			{ "TID", 		"gtpv0.tid", 			FT_STRING, 	BASE_DEC, NULL, 0, "Tunnel Identifier", HFILL }},
	{ &hf_gtpv0_cause,		{ "Cause",		"gtpv0.cause", 			FT_UINT8, 	BASE_DEC, VALS(cause_type), 0, "Cause of operation", HFILL }},
	{ &hf_gtpv0_imsi,			{ "IMSI", 		"gtpv0.imsi",	 		FT_STRING, 	BASE_DEC, NULL, 0, "International Mobile Subscriber Identity number", HFILL }},
	{ &hf_gtpv0_rai_mcc,		{ "MCC", 		"gtpv0.mcc",			FT_UINT16, 	BASE_DEC, NULL, 0, "Mobile Country Code", HFILL }},
	{ &hf_gtpv0_rai_mnc,		{ "MNC", 		"gtpv0.mnc", 			FT_UINT8, 	BASE_DEC, NULL, 0, "Mobile Network Code", HFILL }},
	{ &hf_gtpv0_rai_rac,		{ "RAC", 		"gtpv0.rac", 			FT_UINT8, 	BASE_DEC, NULL, 0, "Routing Area Code", HFILL }},
	{ &hf_gtpv0_rai_lac,		{ "LAC", 		"gtpv0.lac", 			FT_UINT16, 	BASE_DEC, NULL, 0, "Location Area Code", HFILL }},
	{ &hf_gtpv0_tlli,			{ "TLLI", 		"gtpv0.tlli",	 		FT_UINT32, 	BASE_HEX, NULL, 0, "Temporary Logical Link Identity", HFILL }},
	{ &hf_gtpv0_ptmsi,		{ "P-TMSI",		"gtpv0.ptmsi", 			FT_UINT32, 	BASE_HEX, NULL, 0, "Packet-Temporary Mobile Subscriber Identity", HFILL }},
	{ &hf_gtpv0_qos_spare1,		{ "Spare",		"gtpv0.qos_spare1", 		FT_UINT8, 	BASE_DEC, NULL, GTP_EXT_QOS_SPARE1_MASK, "Spare (shall be sent as '00' )", HFILL }},
	{ &hf_gtpv0_qos_delay,		{ "QoS delay",		"gtpv0.qos_delay", 		FT_UINT8, 	BASE_DEC, VALS(qos_delay_type), GTP_EXT_QOS_DELAY_MASK, "Quality of Service Delay Class", HFILL }},
	{ &hf_gtpv0_qos_reliability,	{ "QoS reliability",	"gtpv0.qos_reliabilty",	 	FT_UINT8, 	BASE_DEC, VALS(qos_reliability_type), GTP_EXT_QOS_RELIABILITY_MASK, "Quality of Service Reliability Class", HFILL }},
	{ &hf_gtpv0_qos_peak,		{ "QoS peak",		"gtpv0.qos_peak", 		FT_UINT8, 	BASE_DEC, VALS(qos_peak_type), GTP_EXT_QOS_PEAK_MASK, "Quality of Service Peak Throughput", HFILL }},
	{ &hf_gtpv0_qos_spare2,		{ "Spare",		"gtpv0.qos_spare2", 		FT_UINT8, 	BASE_DEC, NULL, GTP_EXT_QOS_SPARE2_MASK, "Spare (shall be sent as 0)", HFILL }},
	{ &hf_gtpv0_qos_precedence,	{ "QoS precedence",	"gtpv0.qos_precedence", 	FT_UINT8, 	BASE_DEC, VALS(qos_precedence_type), GTP_EXT_QOS_PRECEDENCE_MASK, "Quality of Service Precedence Class", HFILL }},
	{ &hf_gtpv0_qos_spare3,		{ "Spare",		"gtpv0.qos_spare3", 		FT_UINT8, 	BASE_DEC, NULL, GTP_EXT_QOS_SPARE3_MASK, "Spare (shall be sent as '000' )", HFILL }},
	{ &hf_gtpv0_qos_mean,		{ "QoS mean",		"gtpv0.qos_mean", 		FT_UINT8, 	BASE_DEC, VALS(qos_mean_type), GTP_EXT_QOS_MEAN_MASK, "Quality of Service Mean Throughput", HFILL }},
	{ &hf_gtpv0_reorder,		{ "Reordering required","gtpv0.reorder", 		FT_BOOLEAN,	BASE_NONE,NULL, 0, "Reordering required", HFILL }},
	{ &hf_gtpv0_map_cause,		{ "MAP cause",		"gtpv0.map_cause", 		FT_UINT8, 	BASE_DEC, VALS(map_cause_type), 0, "MAP cause", HFILL }},
	{ &hf_gtpv0_ptmsi_sig,		{ "P-TMSI signature",	"gtpv0.ptmsi_sig", 		FT_UINT24, 	BASE_HEX, NULL, 0, "P-TMSI Signature", HFILL }},
	{ &hf_gtpv0_ms_valid,		{ "MS validated",	"gtpv0.ms_valid", 		FT_BOOLEAN,	BASE_NONE,NULL, 0, "MS validated", HFILL }},
	{ &hf_gtpv0_recovery,		{ "Recovery",		"gtpv0.recovery", 		FT_UINT8, 	BASE_DEC, NULL, 0, "Restart counter", HFILL }},
	{ &hf_gtpv0_sel_mode,		{ "Selection mode", 	"gtpv0.sel_mode", 		FT_UINT8, 	BASE_DEC, VALS(sel_mode_type), 0, "Selection Mode", HFILL }},
	{ &hf_gtpv0_ext_flow_label,	{ "Flow Label Data I",	"gtpv0.ext_flow_label",		FT_UINT16, 	BASE_DEC, NULL, 0, "Flow label data", HFILL }},
	{ &hf_gtpv0_flow_sig,		{ "Flow label Signalling",	"gtpv0.flow_sig", 	FT_UINT16, 	BASE_DEC, NULL, 0, "Flow label signalling", HFILL }},
	{ &hf_gtpv0_nsapi,		{ "NSAPI ", 		"gtpv0.nsapi",			FT_UINT8, 	BASE_DEC, NULL, 0, "Network layer Service Access Point Identifier", HFILL }},
	{ &hf_gtpv0_flow_ii,		{ "Flow Label Data II ","gtpv0.flow_ii", 		FT_UINT16, 	BASE_DEC, NULL, 0, "Downlink flow label data", HFILL }},
	{ &hf_gtpv0_ms_reason,		{ "MS not reachable reason",	"gtpv0.ms_reason",	FT_UINT8,	BASE_DEC, VALS(ms_not_reachable_type), 0, "MS Not Reachable Reason", HFILL }},
	{ &hf_gtpv0_tr_comm,		{ "Packet transfer command",	"gtpv0.tr_comm", 	FT_UINT8, 	BASE_DEC, VALS(tr_comm_type), 0, "Packat transfer command", HFILL }},
	{ &hf_gtpv0_chrg_id,		{ "Charging ID ", 	"gtpv0.chrg_id", 		FT_UINT32, 	BASE_HEX, NULL, 0, "Charging ID", HFILL }},
	{ &hf_gtpv0_user_ipv4,		{ "End user address IPv4",	"gtpv0.user_ipv4",	FT_IPv4, 	BASE_DEC, NULL, 0, "End user address IPv4", HFILL }},
	{ &hf_gtpv0_user_ipv6,		{ "End user address IPv6",	"gtpv0.user_ipv6",	FT_IPv6, 	BASE_HEX, NULL, 0, "End user address IPv6", HFILL }},
	{ &hf_gtpv0_user_addr_pdp_org,	{ "PDP type organization",	"gtpv0.user_addr_pdp_org",	FT_UINT8, 	BASE_DEC, VALS(pdp_org_type), 0, "PDP type organization", HFILL }},
	{ &hf_gtpv0_user_addr_pdp_type,	{ "PDP type number",	"gtpv0.user_addr_pdp_type", 	FT_UINT8, 	BASE_HEX, VALS(pdp_type), 0, "PDP type", HFILL }},
	{ &hf_gtpv0_apn,			{ "APN", 		"gtpv0.apn", 			FT_STRING, 	BASE_DEC, NULL, 0, "Access Point Name", HFILL }},
	{ &hf_gtpv0_gsn_addr_type,	{ "GSN address type", 	"gtpv0.gsn_addr_type", 		FT_UINT8, 	BASE_DEC, VALS(gsn_addr_type), GTP_EXT_GSN_ADDR_TYPE_MASK, "GSN Address Type", HFILL }},
	{ &hf_gtpv0_gsn_addr_len,		{ "GSN address length", "gtpv0.gsn_addr_len", 		FT_UINT8, 	BASE_DEC, NULL, GTP_EXT_GSN_ADDR_LEN_MASK, "GSN Address Length", HFILL }},
	{ &hf_gtpv0_gsn_ipv4,		{ "GSN address IPv4", 	"gtpv0.gsn_ipv4", 		FT_IPv4, 	BASE_DEC, NULL, 0, "GSN address IPv4", HFILL }},
	{ &hf_gtpv0_gsn_ipv6,		{ "GSN address IPv6", 	"gtpv0.gsn_ipv6", 		FT_IPv6, 	BASE_DEC, NULL, 0, "GSN address IPv6", HFILL }},
	{ &hf_gtpv0_msisdn,		{ "MSISDN", 		"gtpv0.msisdn",	 		FT_STRING, 	BASE_DEC, NULL, 0, "MS international PSTN/ISDN number", HFILL }},
	{ &hf_gtpv0_chrg_ipv4,		{ "CG address IPv4", 	"gtpv0.chrg_ipv4", 		FT_IPv4, 	BASE_DEC, NULL, 0, "Charging Gateway address IPv4", HFILL }},
	{ &hf_gtpv0_chrg_ipv6,		{ "CG address IPv6", 	"gtpv0.chrg_ipv6", 		FT_IPv6, 	BASE_HEX, NULL, 0, "Charging Gateway address IPv6", HFILL }},
	{ &hf_gtpv0_node_ipv4,		{ "Node address IPv4", 	"gtpv0.node_ipv4", 		FT_IPv4, 	BASE_DEC, NULL, 0, "Recommended node address IPv4", HFILL }},
	{ &hf_gtpv0_node_ipv6,		{ "Node address IPv6", 	"gtpv0.node_ipv6", 		FT_IPv6, 	BASE_HEX, NULL, 0, "Recommended node address IPv6", HFILL }},
	{ &hf_gtpv0_ext_id,		{ "Extension identifier",	"gtpv0.ext_id", 	FT_UINT16, 	BASE_DEC, NULL, 0, "Extension Identifier", HFILL }},
	{ &hf_gtpv0_ext_val,		{ "Extension value", 		"gtpv0.ext_val", 	FT_STRING, 	BASE_DEC, NULL, 0, "Extension Value", HFILL }},
	{ &hf_gtpv0_unknown,		{ "Unknown data (length)",	"gtpv0.unknown", 	FT_UINT16, 	BASE_DEC, NULL, 0, "Unknown data", HFILL }},

	};

	
	static hf_register_info hf_gtpv1[] = {

	{ &hf_gtpv1_flags,		{ "Flags", 		"gtpv1.flags", 			FT_UINT8, 	BASE_HEX, NULL, 0, "Ver/PT/Spare/E/S/PN", HFILL }},
	{ &hf_gtpv1_flags_ver,		{ "Version",		"gtpv1.flags.version",		FT_UINT8,	BASE_DEC, VALS(ver_types), GTP_VER_MASK, "GTP Version", HFILL }},
	{ &hf_gtpv1_flags_pt,		{ "Protocol type",	"gtpv1.flags.payload_type",	FT_UINT8,	BASE_DEC, NULL, GTP_PT_MASK, "Protocol Type (1 = GTP, 0 = GPRS charging protocol : GTP' )", HFILL }},
	{ &hf_gtpv1_flags_spare,		{ "Spare bit", 		"gtpv1.flags.spare",		FT_UINT8, 	BASE_DEC, NULL, GTPv1_SPARE_MASK, "Spare bit (shall be sent as 0)", HFILL }},
	{ &hf_gtpv1_flags_e,		{ "Is Next Extension Header present?",	"gtpv1.flags.e",		FT_BOOLEAN, 	8, TFS(&yes_no_tfs), GTPv1_E_MASK, "Is Next Extension Header present? (1 = yes, 0 = no)", HFILL }},
	{ &hf_gtpv1_flags_s,		{ "Is Sequence Number present?",	"gtpv1.flags.s",		FT_BOOLEAN, 	8, TFS(&yes_no_tfs), GTPv1_S_MASK, "Is Sequence Number present? (1 = yes, 0 = no)", HFILL }},
	{ &hf_gtpv1_flags_pn,		{ "Is N-PDU number present?",	"gtpv1.flags.pn",		FT_BOOLEAN, 	8, TFS(&yes_no_tfs), GTPv1_PN_MASK, "Is N-PDU number present? (1 = yes, 0 = no)", HFILL }},
	{ &hf_gtpv1_message_type,		{ "Message Type",	"gtpv1.message",		FT_UINT8, 	BASE_HEX, VALS(message_type), 0x0, "GTP Message Type", HFILL }},
	{ &hf_gtpv1_length,		{ "Length", 		"gtpv1.length", 		FT_UINT16, 	BASE_DEC, NULL, 0, "Length (i.e. number of octets after TID or TEID)", HFILL }},
	{ &hf_gtpv1_seq_number,		{ "Sequence Number", 	"gtpv1.seq_number",		FT_UINT16, 	BASE_HEX, NULL, 0, "Sequence Number", HFILL }},
	{ &hf_gtpv1_teid,			{ "TEID", 		"gtpv1.teid", 			FT_UINT32, 	BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier", HFILL }},
	{ &hf_gtpv1_npdu_number,		{ "N-PDU Number", 	"gtpv1.npdu_number", 		FT_UINT8, 	BASE_HEX, NULL, 0, "N-PDU Number", HFILL }},
	{ &hf_gtpv1_next,			{ "Next extension header type",	"gtpv1.next", 		FT_UINT8, 	BASE_HEX, NULL, 0, "Next Extension Header Type", HFILL }},
	{ &hf_gtpv1_cause,		{ "Cause ", 		"gtpv1.cause", 			FT_UINT8, 	BASE_DEC, VALS(cause_type), 0, "Cause of operation", HFILL }},
	{ &hf_gtpv1_imsi,			{ "IMSI", 		"gtpv1.imsi", 			FT_STRING, 	BASE_DEC, NULL, 0, "International Mobile Subscriber Identity number", HFILL }},
	{ &hf_gtpv1_rai_mcc,		{ "MCC", 		"gtpv1.mcc",			FT_UINT16, 	BASE_DEC, NULL, 0, "Mobile Country Code", HFILL }},
	{ &hf_gtpv1_rai_mnc,		{ "MNC", 		"gtpv1.mnc", 			FT_UINT8, 	BASE_DEC, NULL, 0, "Mobile Network Code", HFILL }},
	{ &hf_gtpv1_rai_rac,		{ "RAC", 		"gtpv1.rac", 			FT_UINT8, 	BASE_DEC, NULL, 0, "Routing Area Code", HFILL }},
	{ &hf_gtpv1_rai_lac,		{ "LAC", 		"gtpv1.lac", 			FT_UINT16, 	BASE_DEC, NULL, 0, "Location Area Code", HFILL }},
	{ &hf_gtpv1_tlli,			{ "TLLI", 		"gtpv1.tlli", 			FT_UINT32, 	BASE_HEX, NULL, 0, "Temporary Logical Link Identity", HFILL }},
	{ &hf_gtpv1_ptmsi,		{ "P-TMSI",		"gtpv1.ptmsi", 			FT_UINT32, 	BASE_HEX, NULL, 0, "Packet-Temporary Mobile Subscriber Identity", HFILL }},
	{ &hf_gtpv1_qos_spare1,		{ "Spare",		"gtpv1.qos_spare1", 		FT_UINT8, 	BASE_DEC, NULL, GTP_EXT_QOS_SPARE1_MASK, "Spare (shall be sent as '00' )", HFILL }},
	{ &hf_gtpv1_qos_delay,		{ "QoS Delay",		"gtpv1.qos_delay", 		FT_UINT8, 	BASE_DEC, VALS(qos_delay_type), GTP_EXT_QOS_DELAY_MASK, "Quality of Service Delay Class", HFILL }},
	{ &hf_gtpv1_qos_reliability,	{ "QoS Reliability",	"gtpv1.qos_reliabilty", 	FT_UINT8, 	BASE_DEC, VALS(qos_reliability_type), GTP_EXT_QOS_RELIABILITY_MASK, "Quality of Service Reliability Class", HFILL }},
	{ &hf_gtpv1_qos_peak,		{ "QoS Peak",		"gtpv1.qos_peak", 		FT_UINT8, 	BASE_DEC, VALS(qos_peak_type), GTP_EXT_QOS_PEAK_MASK, "Quality of Service Peak Throughput", HFILL }},
	{ &hf_gtpv1_qos_spare2,		{ "Spare",		"gtpv1.qos_spare2", 		FT_UINT8, 	BASE_DEC, NULL, GTP_EXT_QOS_SPARE2_MASK, "Spare (shall be sent as 0)", HFILL }},
	{ &hf_gtpv1_qos_precedence,	{ "QoS Precedence",	"gtpv1.qos_precedence",	 	FT_UINT8, 	BASE_DEC, VALS(qos_precedence_type), GTP_EXT_QOS_PRECEDENCE_MASK, "Quality of Service Precedence Class", HFILL }},
	{ &hf_gtpv1_qos_spare3,		{ "Spare",		"gtpv1.qos_spare3", 		FT_UINT8, 	BASE_DEC, NULL, GTP_EXT_QOS_SPARE3_MASK, "Spare (shall be sent as '000' )", HFILL }},
	{ &hf_gtpv1_qos_mean,		{ "QoS Mean",		"gtpv1.qos_mean", 		FT_UINT8, 	BASE_DEC, VALS(qos_mean_type), GTP_EXT_QOS_MEAN_MASK, "Quality of Service Mean Throughput", HFILL }},
	{ &hf_gtpv1_reorder,		{ "Reordering required","gtpv1.reorder", 		FT_BOOLEAN,	BASE_NONE,NULL, 0, "Reordering required", HFILL }},
	{ &hf_gtpv1_map_cause,		{ "MAP cause",		"gtpv1.map_cause", 		FT_UINT8, 	BASE_DEC, VALS(map_cause_type), 0, "MAP cause", HFILL }},
	{ &hf_gtpv1_ptmsi_sig,		{ "P-TMSI Signature",	"gtpv1.ptmsi_sig", 		FT_UINT24, 	BASE_HEX, NULL, 0, "P-TMSI Signature", HFILL }},
	{ &hf_gtpv1_ms_valid,		{ "MS validated",	"gtpv1.ms_valid", 		FT_BOOLEAN,	BASE_NONE,NULL, 0, "MS validated", HFILL }},
	{ &hf_gtpv1_recovery,		{ "Recovery",		"gtpv1.recovery", 		FT_UINT8, 	BASE_DEC, NULL, 0, "Restart counter", HFILL }},
	{ &hf_gtpv1_sel_mode,		{ "Selection Mode", 	"gtpv1.sel_mode", 		FT_UINT8, 	BASE_DEC, VALS(sel_mode_type), 0, "Selection Mode", HFILL }},
	{ &hf_gtpv1_teid_data,		{ "TEID Data I",	"gtpv1.teid_data",		FT_UINT32,	BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier Data I", HFILL }},
	{ &hf_gtpv1_teid_cp,		{ "TEID Control Plane",	"gtpv1.teid_cp", 		FT_UINT32, 	BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier Control Plane", HFILL }},
	{ &hf_gtpv1_nsapi,		{ "NSAPI",		"gtpv1.nsapi",			FT_UINT8, 	BASE_DEC, NULL, 0, "Network layer Service Access Point Identifier", HFILL }},
	{ &hf_gtpv1_teid_ii,		{ "TEID Data II",	"gtpv1.teid_ii", 		FT_UINT32, 	BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier Data II", HFILL }},
	{ &hf_gtpv1_tear_ind,		{ "Teardown indication","gtpv1.tear_ind", 		FT_BOOLEAN, 	BASE_NONE,NULL, 0, "Teardown Indication", HFILL }},
	{ &hf_gtpv1_ranap_cause,		{ "RANAP cause",	"gtpv1.ranap_cause",		FT_UINT8, 	BASE_DEC, VALS(ranap_cause_type), 0, "RANAP cause", HFILL }},
	{ &hf_gtpv1_rab_gtpu_dn,		{ "Downlink GTP-U seq number",	"gtpv1.rab_gtp_dn",	FT_UINT16, 	BASE_DEC, NULL, 0, "Downlink GTP-U sequence number", HFILL }},
	{ &hf_gtpv1_rab_gtpu_up,		{ "Uplink GTP-U seq number",	"gtpv1.rab_gtp_up",	FT_UINT16, 	BASE_DEC, NULL, 0, "Uplink GTP-U sequence number", HFILL }},
	{ &hf_gtpv1_rab_pdu_dn,		{ "Downlink next PDCP-PDU seq number",	"gtpv1.rab_pdu_dn",		FT_UINT8, 	BASE_DEC, NULL, 0, "Downlink next PDCP-PDU sequence number", HFILL }},
	{ &hf_gtpv1_rab_pdu_up,		{ "Uplink next PDCP-PDU seq number",	"gtpv1.rab_pdu_up",		FT_UINT8, 	BASE_DEC, NULL, 0, "Uplink next PDCP-PDU sequence number", HFILL }},
	{ &hf_gtpv1_rp_sms,		{ "Radio Priority SMS",	"gtpv1.rp_sms",			FT_UINT8, 	BASE_DEC, NULL, 0, "Radio Priority for MO SMS", HFILL }},
	{ &hf_gtpv1_rp_nsapi, 		{ "NSAPI in Radio Priority",	"gtpv1.rp_nsapi",	FT_UINT8,	BASE_DEC, NULL, GTPv1_EXT_RP_NSAPI_MASK, "Network layer Service Access Point Identifier in Radio Priority", HFILL }},
	{ &hf_gtpv1_rp_spare,	 	{ "Reserved", 		"gtpv1.rp_spare", 		FT_UINT8,	BASE_DEC, NULL, GTPv1_EXT_RP_SPARE_MASK, "Spare bit", HFILL }},
	{ &hf_gtpv1_rp,			{ "Radio Priority", 	"gtpv1.rp", 			FT_UINT8, 	BASE_DEC, NULL, GTPv1_EXT_RP_MASK, "Radio Priority for uplink tx", HFILL }},
	{ &hf_gtpv1_pkt_flow_id,		{ "Packet Flow ID",	"gtpv1.pkt_flow_id",		FT_UINT8, 	BASE_DEC, NULL, 0, "Packet Flow ID", HFILL }},
	{ &hf_gtpv1_chrg_char_s,		{ "Spare", 		"gtpv1.chrg_char_s", 		FT_UINT8, 	BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_S, "Spare", HFILL }},
	{ &hf_gtpv1_chrg_char_n,		{ "Normal charging", 	"gtpv1.chrg_char_n", 		FT_UINT8, 	BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_N, "Normal charging", HFILL }},
	{ &hf_gtpv1_chrg_char_p,		{ "Prepaid charging", 	"gtpv1.chrg_char_p", 		FT_UINT8, 	BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_P, "Prepaid charging", HFILL }},
	{ &hf_gtpv1_chrg_char_f,		{ "Flat rate charging", "gtpv1.chrg_char_f", 		FT_UINT8, 	BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_F, "Flat rate charging", HFILL }},
	{ &hf_gtpv1_chrg_char_h,		{ "Hot billing charging",	"gtpv1.chrg_char_h", 	FT_UINT8, 	BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_H, "Hot billing charging", HFILL }},
	{ &hf_gtpv1_chrg_char_r,		{ "Reserved", 		"gtpv1.chrg_char_r", 		FT_UINT8, 	BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_R, "Reserved", HFILL }},
	{ &hf_gtpv1_trace_ref,		{ "Trace reference",	"gtpv1.trace_ref",		FT_UINT16, 	BASE_HEX, NULL, 0, "Trace reference", HFILL }},
	{ &hf_gtpv1_trace_type,		{ "Trace type",		"gtpv1.trace_type",		FT_UINT16, 	BASE_HEX, NULL, 0, "Trace type", HFILL }},
	{ &hf_gtpv1_ms_reason,		{ "MS not reachable reason",	"gtpv1.ms_reason",	FT_UINT8,	BASE_DEC, VALS(ms_not_reachable_type), 0, "MS not reachable reason", HFILL }},
	{ &hf_gtpv1_tr_comm,		{ "Packet transfer command", 	"gtpv1.tr_comm", 	FT_UINT8, 	BASE_DEC, VALS(tr_comm_type), 0, "Packat transfer command", HFILL }},
	{ &hf_gtpv1_chrg_id,		{ "Charging ID", 	"gtpv1.chrg_id", 		FT_UINT32, 	BASE_HEX, NULL, 0, "Charging ID", HFILL }},
	{ &hf_gtpv1_user_ipv4,		{ "End user address IPv4", 	"gtpv1.user_ipv4",	FT_IPv4, 	BASE_DEC, NULL, 0, "End user address IPv4", HFILL }},
	{ &hf_gtpv1_user_ipv6,		{ "End user address IPv6", 	"gtpv1.user_ipv6",	FT_IPv6, 	BASE_HEX, NULL, 0, "End user address IPv6", HFILL }},
	{ &hf_gtpv1_user_addr_pdp_org,	{ "PDP type organization",	"gtpv1.user_addr_pdp_org",	FT_UINT8, 	BASE_DEC, VALS(pdp_org_type), 0, "PDP type organization", HFILL }},
	{ &hf_gtpv1_user_addr_pdp_type,	{ "PDP type number",	"gtpv1.user_addr_pdp_type", 	FT_UINT8, 	BASE_HEX, VALS(pdp_type), 0, "PDP type", HFILL }},
	{ &hf_gtpv1_apn,			{ "APN", 		"gtpv1.apn", 			FT_STRING, 	BASE_DEC, NULL, 0, "Access Point Name", HFILL }},
	{ &hf_gtpv1_gsn_addr_type,	{ "GSN Address Type", 	"gtpv1.gsn_addr_type",		FT_UINT8, 	BASE_DEC, VALS(gsn_addr_type), GTP_EXT_GSN_ADDR_TYPE_MASK, "GSN Address Type", HFILL }},
	{ &hf_gtpv1_gsn_addr_len,		{ "GSN Address Length", "gtpv1.gsn_addr_len",		FT_UINT8, 	BASE_DEC, NULL, GTP_EXT_GSN_ADDR_LEN_MASK, "GSN Address Length", HFILL }},
	{ &hf_gtpv1_gsn_ipv4,		{ "GSN address IPv4", 	"gtpv1.gsn_ipv4", 		FT_IPv4, 	BASE_DEC, NULL, 0, "GSN address IPv4", HFILL }},
	{ &hf_gtpv1_gsn_ipv6,		{ "GSN address IPv6", 	"gtpv1.gsn_ipv6", 		FT_IPv6, 	BASE_DEC, NULL, 0, "GSN address IPv6", HFILL }},
	{ &hf_gtpv1_msisdn,		{ "MSISDN", 		"gtpv1.msisdn",			FT_STRING, 	BASE_DEC, NULL, 0, "MS international PSTN/ISDN number", HFILL }},
	{ &hf_gtpv1_qos_al_ret_priority,	{ "Allocation/Retention priority ","gtpv1.qos_al_ret_priority", 	FT_UINT8, 	BASE_DEC, NULL, 0, "Allocation/Retention Priority", HFILL }},
	{ &hf_gtpv1_qos_traf_class, 	{ "Traffic class",	"gtpv1.qos_traf_class", 	FT_UINT8, 	BASE_DEC, VALS(qos_traf_class), GTP_EXT_QOS_TRAF_CLASS_MASK, "Traffic Class", HFILL }},
	{ &hf_gtpv1_qos_del_order, 	{ "Delivery order",	"gtpv1.qos_del_order", 		FT_UINT8, 	BASE_DEC, VALS(qos_del_order), GTP_EXT_QOS_DEL_ORDER_MASK, "Delivery Order", HFILL }},
	{ &hf_gtpv1_qos_del_err_sdu, 	{ "Delivery of erroneous SDU",	"gtpv1.qos_del_err_sdu",	FT_UINT8,	BASE_DEC, VALS(qos_del_err_sdu), GTP_EXT_QOS_DEL_ERR_SDU_MASK, "Delivery of Erroneous SDU", HFILL }},
	{ &hf_gtpv1_qos_max_sdu_size,	{ "Maximum SDU size",	"gtpv1.qos_max_sdu_size", 	FT_UINT8,	BASE_DEC, VALS(qos_max_sdu_size), 0, "Maximum SDU size", HFILL }},
	{ &hf_gtpv1_qos_max_ul, 		{ "Maximum bit rate for uplink",	"gtpv1.qos_max_ul",	FT_UINT8,	BASE_DEC, VALS(qos_max_ul), 0, "Maximum bit rate for uplink", HFILL }},
	{ &hf_gtpv1_qos_max_dl, 		{ "Maximum bit rate for downlink",	"gtpv1.qos_max_dl",	FT_UINT8,	BASE_DEC, VALS(qos_max_dl), 0, "Maximum bit rate for downlink", HFILL }},
	{ &hf_gtpv1_qos_res_ber, 		{ "Residual BER",	"gtpv1.qos_res_ber",		FT_UINT8,	BASE_DEC, VALS(qos_res_ber), GTP_EXT_QOS_RES_BER_MASK, "Residual Bit Error Rate", HFILL }},
	{ &hf_gtpv1_qos_sdu_err_ratio,	{ "SDU Error ratio",	"gtpv1.qos_sdu_err_ratio",	FT_UINT8,	BASE_DEC, VALS(qos_sdu_err_ratio), GTP_EXT_QOS_SDU_ERR_RATIO_MASK, "SDU Error Ratio", HFILL }},
	{ &hf_gtpv1_qos_trans_delay, 	{ "Transfer delay",	"gtpv1.qos_trans_delay",	FT_UINT8,	BASE_DEC, VALS(qos_trans_delay), GTP_EXT_QOS_TRANS_DELAY_MASK, "Transfer Delay", HFILL }},
	{ &hf_gtpv1_qos_traf_handl_prio,	{ "Traffic handling priority",	"gtpv1.qos_traf_handl_prio",	FT_UINT8,	BASE_DEC, VALS(qos_traf_handl_prio), GTP_EXT_QOS_TRAF_HANDL_PRIORITY_MASK, "Traffic Handling Priority", HFILL }},
	{ &hf_gtpv1_qos_guar_ul,		{ "Guaranteed bit rate for uplink",	"gtpv1.qos_guar_ul",	FT_UINT8,	BASE_DEC, VALS(qos_guar_ul), 0, "Guaranteed bit rate for uplink", HFILL }},
	{ &hf_gtpv1_qos_guar_dl,		{ "Guaranteed bit rate for downlink",	"gtpv1.qos_guar_dl",	FT_UINT8,	BASE_DEC, VALS(qos_guar_dl), 0, "Guaranteed bit rate for downlink", HFILL }},
	{ &hf_gtpv1_rnc_ipv4,		{ "RNC address IPv4", 	"gtpv1.rnc_ipv4", 		FT_IPv4, 	BASE_DEC, NULL, 0, "Radio Network Controller address IPv4", HFILL }},
	{ &hf_gtpv1_rnc_ipv6,		{ "RNC address IPv6", 	"gtpv1.rnc_ipv6",	 	FT_IPv6, 	BASE_HEX, NULL, 0, "Radio Network Controller address IPv6", HFILL }},
	{ &hf_gtpv1_chrg_ipv4,		{ "CG address IPv4", 	"gtpv1.chrg_ipv4", 		FT_IPv4, 	BASE_DEC, NULL, 0, "Charging Gateway address IPv4", HFILL }},
	{ &hf_gtpv1_chrg_ipv6,		{ "CG address IPv6", 	"gtpv1.chrg_ipv6", 		FT_IPv6, 	BASE_HEX, NULL, 0, "Charging Gateway address IPv6", HFILL }},
	{ &hf_gtpv1_node_ipv4,		{ "Node address IPv4", 	"gtpv1.node_ipv4", 		FT_IPv4, 	BASE_DEC, NULL, 0, "Recommended node address IPv4", HFILL }},
	{ &hf_gtpv1_node_ipv6,		{ "Node address IPv6", 	"gtpv1.node_ipv6", 		FT_IPv6, 	BASE_HEX, NULL, 0, "Recommended node address IPv6", HFILL }},
	{ &hf_gtpv1_ext_id,		{ "Extensio Identifier","gtpv1.ext_id", 		FT_UINT16, 	BASE_DEC, NULL, 0, "Extension Identifier", HFILL }},
	{ &hf_gtpv1_ext_val,		{ "Extension Value", 	"gtpv1.ext_val", 		FT_STRING, 	BASE_DEC, NULL, 0, "Extension Value", HFILL }},
	{ &hf_gtpv1_unknown,		{ "Unknown data (length)",	"gtpv1.unknown", 	FT_UINT16, 	BASE_DEC, NULL, 0, "Unknown data", HFILL }},

	};

	static gint *ett_gtp_array[] = {
		&ett_gtp,
		&ett_gtp_flags,
		&ett_gtp_ext,
		&ett_gtp_rai,
		&ett_gtp_qos,
		&ett_gtp_auth_tri,
		&ett_gtp_flow_ii,
		&ett_gtp_rab_cntxt,
		&ett_gtp_rp,
		&ett_gtp_pkt_flow_id,
		&ett_gtp_chrg_char,
		&ett_gtp_user,
		&ett_gtp_mm,
		&ett_gtp_trip,
		&ett_gtp_quint,
		&ett_gtp_pdp,
		&ett_gtp_apn,
		&ett_gtp_proto,
		&ett_gtp_gsn_addr,
		&ett_gtp_tft,
		&ett_gtp_tft_pf,
		&ett_gtp_rab_setup,
		&ett_gtp_hdr_list,
		&ett_gtp_chrg_addr,
		&ett_gtp_node_addr,
		&ett_gtp_rel_pack,
		&ett_gtp_can_pack,
		&ett_gtp_data_resp,
		&ett_gtp_priv_ext,
	};

	module_t	*gtp_module;
	
	static enum_val_t gtpv0_cdr_options[] = {
		{ "GSM 12.15",	0 },
		{ "Nokia CDR", 	1 },
		{ "None",	2 },
		{ NULL, 	-1 }
	};

	proto_gtpv0 = proto_register_protocol("GPRS Tunnelling Protocol v0", "GTPv0", "gtpv0");
	proto_register_field_array(proto_gtpv0, hf_gtpv0, array_length(hf_gtpv0));
	proto_register_subtree_array(ett_gtp_array, array_length(ett_gtp_array));
	
	proto_gtpv1 = proto_register_protocol("GPRS Tunnelling Protocol v1", "GTPv1", "gtpv1");
	proto_register_field_array(proto_gtpv1, hf_gtpv1, array_length(hf_gtpv1));
	proto_register_subtree_array(ett_gtp_array, array_length(ett_gtp_array));
	
	gtp_module = prefs_register_protocol(proto_gtpv0, proto_reg_handoff_gtp);
	
	prefs_register_uint_preference(gtp_module, "gtpv0_port", "GTPv0 port ", "GTPv0 port (default 3386)", 10, &g_gtpv0_port);
	prefs_register_uint_preference(gtp_module, "gtpv1c_port", "GTPv1 control plane (GTP-C) port ", "GTPv1 control plane port (default 2123)", 10, &g_gtpv1c_port);
	prefs_register_uint_preference(gtp_module, "gtpv1u_port", "GTPv1 user plane (GTP-U) port ", "GTPv1 user plane port (default 2152)", 10, &g_gtpv1u_port);
	prefs_register_bool_preference(gtp_module, "gtp_dissect_tpdu", "Dissect T-PDU ", "Dissect T-PDU", &gtp_tpdu);
	prefs_register_enum_preference(gtp_module, "gtpv0_dissect_cdr_as", "Dissect GTP'v0 CDRs as ", "Dissect GTP'v0 CDRs as", &gtpv0_cdr_as, gtpv0_cdr_options, FALSE);
	prefs_register_bool_preference(gtp_module, "gtpv0_check_etsi", "Compare GTPv0 order with ETSI ", "GTPv0 ETSI order", &gtpv0_etsi_order);
	prefs_register_bool_preference(gtp_module, "gtpv1_check_etsi", "Compare GTPv1 order with ETSI ", "GTPv1 ETSI order", &gtpv1_etsi_order);
	prefs_register_bool_preference(gtp_module, "ppp_reorder", "Reorder & dissect PPP in Protocol conf. options", "PPP reorder & dissect", &ppp_reorder);
	
	register_dissector("gtpv0", dissect_gtpv0, proto_gtpv0);
	register_dissector("gtpv1", dissect_gtpv1, proto_gtpv1);

}

void
proto_reg_handoff_gtp(void)
{
	static int Initialized = FALSE;
	static dissector_handle_t gtpv0_handle;
	static dissector_handle_t gtpv1_handle;
	
	if (!Initialized) {
		
		gtpv0_handle = find_dissector("gtpv0");

		gtpv1_handle = find_dissector("gtpv1");

		Initialized = TRUE;
		
	} else {
		
		dissector_delete("udp.port", gtpv0_port, gtpv0_handle);
		dissector_delete("tcp.port", gtpv0_port, gtpv0_handle);

		dissector_delete("udp.port", gtpv1c_port, gtpv1_handle);
		dissector_delete("tcp.port", gtpv1c_port, gtpv1_handle);
		dissector_delete("udp.port", gtpv1u_port, gtpv1_handle);
		dissector_delete("tcp.port", gtpv1u_port, gtpv1_handle);
	}
		
	gtpv0_port = g_gtpv0_port;
	gtpv1c_port = g_gtpv1c_port;
	gtpv1u_port = g_gtpv1u_port;
	
	/* GTP v0 */
	
	dissector_add("udp.port", g_gtpv0_port, gtpv0_handle);
	dissector_add("tcp.port", g_gtpv0_port, gtpv0_handle);

	/* GTP v1 */
	
	dissector_add("udp.port", g_gtpv1c_port, gtpv1_handle);
	dissector_add("tcp.port", g_gtpv1c_port, gtpv1_handle);
	dissector_add("udp.port", g_gtpv1u_port, gtpv1_handle);
	dissector_add("tcp.port", g_gtpv1u_port, gtpv1_handle);
	
	ip_handle = find_dissector("ip");
	ppp_handle = find_dissector("ppp");
}
