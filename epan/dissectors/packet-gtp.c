/* packet-gtp.c
 *
 * Routines for GTP dissection
 * Copyright 2001, Michal Melerowicz <michal.melerowicz@nokia.com>
 *                 Nicolas Balkota <balkota@mac.com>
 *
 * $Id$
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-ipv6.h"
#include "packet-ppp.h"
#include "packet-radius.h"
#include "packet-bssap.h"
#include "packet-gsm_a.h"

static dissector_table_t ppp_subdissector_table;

#define GTPv0_PORT 3386
#define GTPv1C_PORT 2123			/* 3G Control PDU */
#define GTPv1U_PORT 2152			/* 3G T-PDU */

#define GTPv0_HDR_LENGTH 20
#define GTPv1_HDR_LENGTH 12
#define GTP_PRIME_HDR_LENGTH 6

/* to check compliance with ETSI  */
#define GTP_MANDATORY	1
#define GTP_OPTIONAL	2
#define GTP_CONDITIONAL	4

static guint g_gtpv0_port	= GTPv0_PORT;
static guint g_gtpv1c_port	= GTPv1C_PORT;
static guint g_gtpv1u_port	= GTPv1U_PORT;

void proto_reg_handoff_gtp(void);

static int proto_gtp		= -1;

static int hf_gtp_apn			= -1;
static int hf_gtp_cause			= -1;
static int hf_gtp_chrg_char		= -1;
static int hf_gtp_chrg_char_s		= -1;
static int hf_gtp_chrg_char_n		= -1;
static int hf_gtp_chrg_char_p		= -1;
static int hf_gtp_chrg_char_f		= -1;
static int hf_gtp_chrg_char_h		= -1;
static int hf_gtp_chrg_char_r		= -1;
static int hf_gtp_chrg_id		= -1;
static int hf_gtp_chrg_ipv4		= -1;
static int hf_gtp_chrg_ipv6		= -1;
static int hf_gtp_ext_flow_label	= -1;
static int hf_gtp_ext_id		= -1;
static int hf_gtp_ext_val		= -1;
static int hf_gtp_flags			= -1;
static int hf_gtp_flags_ver		= -1;
static int hf_gtp_flags_pt		= -1;
static int hf_gtp_flags_spare1		= -1;
static int hf_gtp_flags_snn		= -1;
static int hf_gtp_flags_spare2		= -1;
static int hf_gtp_flags_e		= -1;
static int hf_gtp_flags_s		= -1;
static int hf_gtp_flags_pn		= -1;
static int hf_gtp_flow_ii		= -1;
static int hf_gtp_flow_label		= -1;
static int hf_gtp_flow_sig		= -1;
static int hf_gtp_gsn_addr_len		= -1;
static int hf_gtp_gsn_addr_type		= -1;
static int hf_gtp_gsn_ipv4		= -1;
static int hf_gtp_gsn_ipv6		= -1;
static int hf_gtp_imsi			= -1;
static int hf_gtp_length		= -1;
static int hf_gtp_map_cause		= -1;
static int hf_gtp_message_type		= -1;
static int hf_gtp_ms_reason		= -1;
static int hf_gtp_ms_valid		= -1;
static int hf_gtp_msisdn		= -1;
static int hf_gtp_next			= -1;
static int hf_gtp_npdu_number		= -1;
static int hf_gtp_node_ipv4		= -1;
static int hf_gtp_node_ipv6		= -1;
static int hf_gtp_nsapi			= -1;
static int hf_gtp_ptmsi			= -1;
static int hf_gtp_ptmsi_sig		= -1;
static int hf_gtp_qos_version		= -1;
static int hf_gtp_qos_spare1		= -1;
static int hf_gtp_qos_delay		= -1;
static int hf_gtp_qos_mean		= -1;
static int hf_gtp_qos_peak		= -1;
static int hf_gtp_qos_spare2		= -1;
static int hf_gtp_qos_precedence	= -1;
static int hf_gtp_qos_spare3		= -1;
static int hf_gtp_qos_reliability	= -1;
static int hf_gtp_qos_al_ret_priority	= -1;
static int hf_gtp_qos_traf_class	= -1;
static int hf_gtp_qos_del_order		= -1;
static int hf_gtp_qos_del_err_sdu	= -1;
static int hf_gtp_qos_max_sdu_size	= -1;
static int hf_gtp_qos_max_ul		= -1;
static int hf_gtp_qos_max_dl		= -1;
static int hf_gtp_qos_res_ber		= -1;
static int hf_gtp_qos_sdu_err_ratio	= -1;
static int hf_gtp_qos_trans_delay	= -1;
static int hf_gtp_qos_traf_handl_prio	= -1;
static int hf_gtp_qos_guar_ul		= -1;
static int hf_gtp_qos_guar_dl		= -1;
static int hf_gtp_pkt_flow_id		= -1;
static int hf_gtp_rab_gtpu_dn		= -1;
static int hf_gtp_rab_gtpu_up		= -1;
static int hf_gtp_rab_pdu_dn		= -1;
static int hf_gtp_rab_pdu_up		= -1;
static int hf_gtp_rai_mcc		= -1;
static int hf_gtp_rai_mnc		= -1;
static int hf_gtp_rai_rac		= -1;
static int hf_gtp_rai_lac		= -1;
static int hf_gtp_ranap_cause		= -1;
static int hf_gtp_recovery		= -1;
static int hf_gtp_reorder		= -1;
static int hf_gtp_rnc_ipv4		= -1;
static int hf_gtp_rnc_ipv6		= -1;
static int hf_gtp_rp			= -1;
static int hf_gtp_rp_nsapi		= -1;
static int hf_gtp_rp_sms		= -1;
static int hf_gtp_rp_spare		= -1;
static int hf_gtp_sel_mode		= -1;
static int hf_gtp_seq_number		= -1;
static int hf_gtp_sndcp_number		= -1;
static int hf_gtp_tear_ind		= -1;
static int hf_gtp_teid			= -1;
static int hf_gtp_teid_cp		= -1;
static int hf_gtp_teid_data		= -1;
static int hf_gtp_teid_ii		= -1;
static int hf_gtp_tft_code		= -1;
static int hf_gtp_tft_spare		= -1;
static int hf_gtp_tft_number		= -1;
static int hf_gtp_tft_eval		= -1;
static int hf_gtp_tid			= -1;
static int hf_gtp_tlli			= -1;
static int hf_gtp_tr_comm		= -1;
static int hf_gtp_trace_ref		= -1;
static int hf_gtp_trace_type		= -1;
static int hf_gtp_unknown		= -1;
static int hf_gtp_user_addr_pdp_org	= -1;
static int hf_gtp_user_addr_pdp_type	= -1;
static int hf_gtp_user_ipv4		= -1;
static int hf_gtp_user_ipv6		= -1;
static int hf_gtp_security_mode = -1;
static int hf_gtp_no_of_vectors = -1;
static int hf_gtp_cipher_algorithm = -1;
static int hf_gtp_cksn_ksi = -1;
static int hf_gtp_cksn = -1;
static int hf_gtp_ksi = -1;


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
static gint ett_gtp_tft_flags		= -1;
static gint ett_gtp_rab_setup		= -1;
static gint ett_gtp_hdr_list		= -1;
static gint ett_gtp_chrg_addr		= -1;
static gint ett_gtp_node_addr		= -1;
static gint ett_gtp_rel_pack		= -1;
static gint ett_gtp_can_pack		= -1;
static gint ett_gtp_data_resp		= -1;
static gint ett_gtp_priv_ext		= -1;
static gint ett_gtp_net_cap			= -1;
	
static gboolean	gtp_tpdu		= TRUE;
static gboolean	gtp_over_tcp		= TRUE;
static gboolean	gtp_etsi_order		= FALSE;
static guint	gtpv0_port		= 0;
static guint	gtpv1c_port		= 0;
static guint	gtpv1u_port		= 0;

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
static const value_string pt_types[] = {
	{ 0, "GTP'" },
	{ 1, "GTP" },
	{ 0, NULL }
};

#define GTP_PT_MASK		0x10
#define GTP_SPARE1_MASK		0x0E
#define GTP_SPARE2_MASK		0x08
#define GTP_E_MASK		0x04
#define GTP_S_MASK		0x02
#define GTP_SNN_MASK		0x01
#define GTP_PN_MASK		0x01

/* Definition of 3G charging characteristics masks */
#define GTP_MASK_CHRG_CHAR_S	0xF000
#define GTP_MASK_CHRG_CHAR_N	0x0800
#define GTP_MASK_CHRG_CHAR_P	0x0400
#define GTP_MASK_CHRG_CHAR_F	0x0200
#define GTP_MASK_CHRG_CHAR_H	0x0100
#define GTP_MASK_CHRG_CHAR_R	0x00FF

/* Traffic Flow Templates  mask */
#define GTPv1_TFT_CODE_MASK	0xE0
#define GTPv1_TFT_SPARE_MASK	0x10
#define GTPv1_TFT_NUMBER_MASK	0x0F

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
#define GTP_EXT_C1		0xC1
#define GTP_EXT_C2		0xC2
#define GTP_EXT_REL_PACK	0xF9	/* charging */
#define GTP_EXT_CAN_PACK	0xFA	/* charging */
#define GTP_EXT_CHRG_ADDR	0xFB
#define GTP_EXT_DATA_REQ	0xFC	/* charging */
#define GTP_EXT_DATA_RESP	0xFD	/* charging */
#define GTP_EXT_NODE_ADDR	0xFE	/* charging */
#define GTP_EXT_PRIV_EXT	0xFF

static const value_string gtp_val[] = {
	{ GTP_EXT_CAUSE,	"Cause of operation" },
	{ GTP_EXT_IMSI,		"IMSI" },
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
	{ GTP_EXT_PKT_FLOW_ID,	"Packet Flow ID" },					/* 3G */
	{ GTP_EXT_CHRG_CHAR,	"Charging characteristics" },				/* 3G */
	{ GTP_EXT_TRACE_REF,	"Trace references" },					/* 3G */
	{ GTP_EXT_TRACE_TYPE,	"Trace type" },					/* 3G */
	{ GTPv1_EXT_MS_REASON,	"MS not reachable reason" },				/* 3G */
	{ GTP_EXT_TR_COMM,	"Packet transfer command" },				/* charging */
	{ GTP_EXT_CHRG_ID,	"Charging ID" },
	{ GTP_EXT_USER_ADDR,	"End user address" },
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
	{ GTP_EXT_HDR_LIST,	"Extension Header Types List" },			/* 3G */
	{ GTP_EXT_TRIGGER_ID,	"Trigger Id" },					/* 3G */
	{ GTP_EXT_OMC_ID,	"OMC Identity" },					/* 3G */
	{ GTP_EXT_REL_PACK,	"Sequence numbers of released packets IE" },		/* charging */
	{ GTP_EXT_CAN_PACK,	"Sequence numbers of canceled packets IE" },		/* charging */
	{ GTP_EXT_CHRG_ADDR,	"Charging Gateway address" },
	{ GTP_EXT_DATA_REQ,	"Data record packet" },				/* charging */
	{ GTP_EXT_DATA_RESP,	"Requests responded" },				/* charging */
	{ GTP_EXT_NODE_ADDR,	"Address of recommended node" },			/* charging */
	{ GTP_EXT_PRIV_EXT, 	"Private Extension" },
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
	{ 0,	"MS or network provided APN, subscribed verified" },
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

static const value_string gtp_cipher_algorithm[] = {
	{ 0, "No ciphering" },
	{ 1, "GEA/1" },
	{ 2, "GEA/2" },
	{ 3, "GEA/3" },
	{ 4, "GEA/4" },
	{ 5, "GEA/5" },
	{ 6, "GEA/6" },
	{ 7, "GEA/7" },
	{ 0, NULL }
};


#define MM_PROTO_GROUP_CALL_CONTROL	0x00
#define MM_PROTO_BROADCAST_CALL_CONTROL	0x01
#define MM_PROTO_PDSS1			0x02
#define MM_PROTO_CALL_CONTROL		0x03
#define MM_PROTO_PDSS2			0x04
#define MM_PROTO_MM_NON_GPRS		0x05
#define MM_PROTO_RR_MGMT		0x06
#define MM_PROTO_MM_GPRS		0x08
#define MM_PROTO_SMS			0x09
#define MM_PROTO_SESSION_MGMT		0x0A
#define MM_PROTO_NON_CALL_RELATED	0x0B

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


static dissector_handle_t ip_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t data_handle;
static dissector_handle_t gtpcdr_handle;
static dissector_table_t bssap_pdu_type_table=NULL;

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

struct _gtp_hdr {
	guint8		flags;
	guint8		message;
	guint16		length;
};

static	guint8		gtp_version = 0;
static	const char	*yesno[] = { "no", "yes" };

static void
col_append_str_gtp(column_info *cinfo, gint el, const gchar *proto_name) {

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

	static gchar	str[17] = "                ";
	guint8		bits8to5, bits4to1;
	int		i, j = 0;
	static const	gchar hex_digits[10] = "0123456789";

	for (i = 0; i < 8; i++) {
		bits8to5 = (ad[i] >> 4) & 0x0F;
		bits4to1 = ad[i] & 0x0F;
		if (bits4to1 < 0xA) 
			str[j++] = hex_digits[bits4to1];
		if (bits8to5 < 0xA) 
			str[j++] = hex_digits[bits8to5];
	}
	str[j] = '\0';
	return str;
}

static gchar *
imsi_to_str(const guint8 *ad) {

	static gchar	str[17] = "                ";
	int		i, j = 0;

	for (i = 0; i < 8; i++) {
		if ((ad[i] & 0x0F) <= 9) str[j++] = (ad[i] & 0x0F) + 0x30;
		if (((ad[i] >> 4) & 0x0F) <= 9) str[j++] = ((ad[i] >> 4) & 0x0F) + 0x30;
	}
	str[j] = '\0';

	return str;
}

static gchar *
msisdn_to_str(const guint8 *ad, int len) {

	static gchar	str[18] = "+                ";
	guint8		bits8to5, bits4to1;
	int		i, j = 1;
	static const	gchar hex_digits[10] = "0123456789";

	for (i = 1; i < len && i < 9; i++) {
		bits8to5 = (ad[i] >> 4) & 0x0F;
		bits4to1 = ad[i] & 0x0F;
		if (bits4to1 < 0xA) 
			str[j++] = hex_digits[bits4to1];
		if (bits8to5 < 0xA) 
			str[j++] = hex_digits[bits8to5];
	}
	str[j] = '\0';
	
	return str;
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
static _gtp_mess_items gprs_mess_items[] = {

{
	GTP_MSG_ECHO_REQ, {
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_ECHO_RESP, {
		{ GTP_EXT_RECOVER,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
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
		{ GTP_EXT_NODE_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_NODE_ALIVE_RESP, {
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_REDIR_REQ, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_NODE_ADDR,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_REDIR_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_CREATE_PDP_REQ, {
		{ GTP_EXT_QOS_GPRS, 	GTP_MANDATORY },
		{ GTP_EXT_RECOVER, 	GTP_OPTIONAL },
		{ GTP_EXT_SEL_MODE, 	GTP_MANDATORY },
		{ GTP_EXT_FLOW_LABEL,	GTP_MANDATORY },
		{ GTP_EXT_FLOW_SIG,	GTP_MANDATORY },
		{ GTP_EXT_MSISDN,	GTP_MANDATORY },
		{ GTP_EXT_USER_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_APN,		GTP_MANDATORY },
		{ GTP_EXT_PROTO_CONF,	GTP_OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_CREATE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_QOS_GPRS,	GTP_CONDITIONAL },
		{ GTP_EXT_REORDER,	GTP_CONDITIONAL },
		{ GTP_EXT_RECOVER,	GTP_OPTIONAL },
		{ GTP_EXT_FLOW_LABEL,	GTP_CONDITIONAL },
		{ GTP_EXT_FLOW_SIG,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_ID,	GTP_CONDITIONAL },
		{ GTP_EXT_USER_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_PROTO_CONF,	GTP_OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_ADDR,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_UPDATE_PDP_REQ, {
		{ GTP_EXT_QOS_GPRS,	GTP_MANDATORY },
		{ GTP_EXT_RECOVER,	GTP_OPTIONAL },
		{ GTP_EXT_FLOW_LABEL,	GTP_MANDATORY },
		{ GTP_EXT_FLOW_SIG,	GTP_MANDATORY },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0, 			0 },
	}
},
{
	GTP_MSG_UPDATE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_QOS_GPRS,	GTP_CONDITIONAL },
		{ GTP_EXT_RECOVER,	GTP_OPTIONAL },
		{ GTP_EXT_FLOW_LABEL,	GTP_CONDITIONAL },
		{ GTP_EXT_FLOW_SIG,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_ID,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_ADDR,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DELETE_PDP_REQ, {
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DELETE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 },
	}
},
{
	GTP_MSG_CREATE_AA_PDP_REQ, {
		{ GTP_EXT_QOS_GPRS, 	GTP_MANDATORY },
		{ GTP_EXT_RECOVER, 	GTP_OPTIONAL },
		{ GTP_EXT_SEL_MODE, 	GTP_MANDATORY },
		{ GTP_EXT_FLOW_LABEL,	GTP_MANDATORY },
		{ GTP_EXT_FLOW_SIG,	GTP_MANDATORY },
		{ GTP_EXT_USER_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_APN,		GTP_MANDATORY },
		{ GTP_EXT_PROTO_CONF,	GTP_OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_CREATE_AA_PDP_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_QOS_GPRS,	GTP_CONDITIONAL },
		{ GTP_EXT_REORDER,	GTP_CONDITIONAL },
		{ GTP_EXT_RECOVER,	GTP_OPTIONAL },
		{ GTP_EXT_FLOW_LABEL,	GTP_CONDITIONAL },
		{ GTP_EXT_FLOW_SIG,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_ID,	GTP_CONDITIONAL },
		{ GTP_EXT_USER_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_PROTO_CONF,	GTP_OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_ADDR,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_DELETE_AA_PDP_REQ, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DELETE_AA_PDP_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_ERR_IND, {
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REQ, {
		{ GTP_EXT_USER_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REJ_REQ, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_USER_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REJ_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SEND_ROUT_INFO_REQ, {
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SEND_ROUT_INFO_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_MAP_CAUSE,	GTP_OPTIONAL },
		{ GTP_EXT_MS_REASON,	GTP_OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FAIL_REP_REQ, {
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FAIL_REP_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_MAP_CAUSE,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_MS_PRESENT_REQ, {
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_MS_PRESENT_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_IDENT_REQ, {
		{ GTP_EXT_RAI,		GTP_MANDATORY },
		{ GTP_EXT_PTMSI,	GTP_MANDATORY },
		{ GTP_EXT_PTMSI_SIG,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_IDENT_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_IMSI,		GTP_CONDITIONAL },
		{ GTP_EXT_AUTH_TRI,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_REQ, {
		{ GTP_EXT_IMSI,		GTP_CONDITIONAL },
		{ GTP_EXT_RAI,		GTP_MANDATORY },
		{ GTP_EXT_TLLI,		GTP_MANDATORY },
		{ GTP_EXT_PTMSI_SIG,	GTP_OPTIONAL },
		{ GTP_EXT_MS_VALID,	GTP_OPTIONAL },
		{ GTP_EXT_FLOW_SIG, 	GTP_MANDATORY },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_IMSI,		GTP_CONDITIONAL },
		{ GTP_EXT_FLOW_SIG,	GTP_CONDITIONAL },
		{ GTP_EXT_MM_CNTXT,	GTP_CONDITIONAL },
		{ GTP_EXT_PDP_CNTXT,	GTP_CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_ACK, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_FLOW_II,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DATA_TRANSF_REQ, {
		{ GTP_EXT_TR_COMM,	GTP_MANDATORY },
		{ GTP_EXT_DATA_REQ,	GTP_CONDITIONAL },
		{ GTP_EXT_REL_PACK,	GTP_CONDITIONAL },
		{ GTP_EXT_CAN_PACK,	GTP_CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DATA_TRANSF_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_DATA_RESP,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
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
static _gtp_mess_items umts_mess_items[] = {

{
	GTP_MSG_ECHO_REQ, {
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_ECHO_RESP, {
		{ GTP_EXT_RECOVER,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
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
		{ GTP_EXT_NODE_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_NODE_ALIVE_RESP, {
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_REDIR_REQ, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_NODE_ADDR,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
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
		{ GTP_EXT_IMSI,		GTP_CONDITIONAL },
		{ GTP_EXT_RECOVER, 	GTP_OPTIONAL },
		{ GTP_EXT_SEL_MODE, 	GTP_CONDITIONAL },
		{ GTP_EXT_TEID,		GTP_MANDATORY },
		{ GTP_EXT_TEID_CP,	GTP_CONDITIONAL },
		{ GTP_EXT_NSAPI,	GTP_MANDATORY },
		{ GTP_EXT_NSAPI,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_CHAR,	GTP_OPTIONAL },
		{ GTP_EXT_TRACE_REF,	GTP_OPTIONAL },
		{ GTP_EXT_TRACE_TYPE,	GTP_OPTIONAL },
		{ GTP_EXT_USER_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_APN,		GTP_CONDITIONAL },
		{ GTP_EXT_PROTO_CONF,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_MSISDN,	GTP_CONDITIONAL },
		{ GTP_EXT_QOS_UMTS,	GTP_MANDATORY },
		{ GTP_EXT_TFT,		GTP_CONDITIONAL },
		{ GTP_EXT_TRIGGER_ID,	GTP_OPTIONAL },
		{ GTP_EXT_OMC_ID,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0, 			0 }
	}
},
{
	GTP_MSG_CREATE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_REORDER,	GTP_CONDITIONAL },
		{ GTP_EXT_RECOVER,	GTP_OPTIONAL },
		{ GTP_EXT_TEID,		GTP_CONDITIONAL },
		{ GTP_EXT_TEID_CP,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_ID,	GTP_CONDITIONAL },
		{ GTP_EXT_USER_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_PROTO_CONF,	GTP_OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_QOS_UMTS,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_ADDR,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{	/* checked, SGSN -> GGSN */
	GTP_MSG_UPDATE_PDP_REQ, {
		{ GTP_EXT_IMSI,		GTP_CONDITIONAL },
		{ GTP_EXT_RECOVER,	GTP_OPTIONAL },
		{ GTP_EXT_TEID,		GTP_MANDATORY },
		{ GTP_EXT_TEID_CP,	GTP_CONDITIONAL },
		{ GTP_EXT_NSAPI,	GTP_MANDATORY },
		{ GTP_EXT_TRACE_REF,	GTP_OPTIONAL },
		{ GTP_EXT_TRACE_TYPE,	GTP_OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_QOS_UMTS,	GTP_MANDATORY },
		{ GTP_EXT_TFT,		GTP_OPTIONAL },
		{ GTP_EXT_TRIGGER_ID,	GTP_OPTIONAL },
		{ GTP_EXT_OMC_ID,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{	/* checked, GGSN -> SGSN */
	GTP_MSG_UPDATE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_RECOVER,	GTP_OPTIONAL },
		{ GTP_EXT_TEID,		GTP_CONDITIONAL },
		{ GTP_EXT_TEID_CP,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_ID,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_QOS_UMTS,	GTP_CONDITIONAL },
		{ GTP_EXT_CHRG_ADDR,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DELETE_PDP_REQ, {
		{ GTP_EXT_TEAR_IND,	GTP_CONDITIONAL },
		{ GTP_EXT_NSAPI,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_DELETE_PDP_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_ERR_IND, {
		{ GTP_EXT_TEID,		GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REQ, {
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_TEID_CP,	GTP_MANDATORY },
		{ GTP_EXT_USER_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_APN,		GTP_MANDATORY },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REJ_REQ, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_TEID_CP,	GTP_MANDATORY },
		{ GTP_EXT_USER_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_APN,		GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_PDU_NOTIFY_REJ_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SUPP_EXT_HDR, {
		{ GTP_EXT_HDR_LIST,	GTP_MANDATORY },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SEND_ROUT_INFO_REQ, {
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SEND_ROUT_INFO_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_MAP_CAUSE,	GTP_OPTIONAL },
		{ GTPv1_EXT_MS_REASON,	GTP_OPTIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FAIL_REP_REQ, {
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FAIL_REP_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_MAP_CAUSE,	GTP_OPTIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_MS_PRESENT_REQ, {
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_MS_PRESENT_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_IDENT_REQ, {
		{ GTP_EXT_RAI,		GTP_MANDATORY },
		{ GTP_EXT_PTMSI,	GTP_MANDATORY },
		{ GTP_EXT_PTMSI_SIG,	GTP_CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_IDENT_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_IMSI,		GTP_CONDITIONAL },
		{ GTP_EXT_AUTH_TRI,	GTP_CONDITIONAL },
		{ GTP_EXT_AUTH_QUI,	GTP_CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_REQ,	{
		{ GTP_EXT_IMSI,		GTP_CONDITIONAL },
		{ GTP_EXT_RAI,		GTP_MANDATORY },
		{ GTP_EXT_TLLI,		GTP_CONDITIONAL },
		{ GTP_EXT_PTMSI,	GTP_CONDITIONAL },
		{ GTP_EXT_PTMSI_SIG,	GTP_CONDITIONAL },
		{ GTP_EXT_MS_VALID,	GTP_OPTIONAL },
		{ GTP_EXT_TEID_CP,	GTP_MANDATORY },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_IMSI,		GTP_CONDITIONAL },
		{ GTP_EXT_TEID_CP,	GTP_CONDITIONAL },
		{ GTP_EXT_RP_SMS,	GTP_OPTIONAL },
		{ GTP_EXT_RP,		GTP_OPTIONAL },
		{ GTP_EXT_PKT_FLOW_ID,	GTP_OPTIONAL },
		{ GTP_EXT_MM_CNTXT,	GTP_CONDITIONAL },
		{ GTP_EXT_PDP_CNTXT,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_SGSN_CNTXT_ACK, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_TEID_II,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_RELOC_REQ, {
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_TEID_CP,	GTP_MANDATORY },
		{ GTP_EXT_RANAP_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_MM_CNTXT,	GTP_MANDATORY },
		{ GTP_EXT_PDP_CNTXT,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_MANDATORY },
		{ GTP_EXT_TARGET_ID,	GTP_MANDATORY },
		{ GTP_EXT_UTRAN_CONT,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_RELOC_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_TEID_CP,	GTP_CONDITIONAL },
		{ GTP_EXT_RANAP_CAUSE,	GTP_CONDITIONAL },
		{ GTP_EXT_GSN_ADDR,	GTP_CONDITIONAL },
		{ GTP_EXT_UTRAN_CONT,	GTP_OPTIONAL },
		{ GTP_EXT_RAB_SETUP,	GTP_CONDITIONAL },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_RELOC_COMP, {
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_RELOC_CANCEL_REQ, {
		{ GTP_EXT_IMSI,		GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_RELOC_CANCEL_RESP, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_RELOC_ACK, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_SRNS_CNTXT, {
		{ GTP_EXT_RAB_CNTXT,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
		{ 0,			0 }
	}
},
{
	GTP_MSG_FORW_SRNS_CNTXT_ACK, {
		{ GTP_EXT_CAUSE,	GTP_MANDATORY },
		{ GTP_EXT_PRIV_EXT,	GTP_OPTIONAL },
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
				if (mess_items[i].fields[*position].presence == GTP_MANDATORY) {
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
decode_gtp_cause(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8	cause;

	cause = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint(tree, hf_gtp_cause, tvb, offset, 2, cause);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.2
 * UMTS:	29.060 v4.0, chapter 7.7.2
 */
static int
decode_gtp_imsi(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8	imsi_val[8];
	gchar	*imsi_str;

	tvb_memcpy(tvb, imsi_val, offset+1, 8);
	imsi_str = imsi_to_str (imsi_val);

	proto_tree_add_string (tree, hf_gtp_imsi, tvb, offset, 9, imsi_str);

	return 9;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.3
 * UMTS:	29.060 v4.0, chapter 7.7.3
 */
static int
decode_gtp_rai(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	proto_tree	*ext_tree_rai;
	proto_item	*te;
	guint8		byte[3];
	guint16		mnc, mcc;

	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_RAI, gtp_val, "Unknown message"));
	ext_tree_rai = proto_item_add_subtree(te, ett_gtp_rai);

	byte[0] = tvb_get_guint8 (tvb, offset + 1);
	byte[1] = tvb_get_guint8 (tvb, offset + 2);
	byte[2] = tvb_get_guint8 (tvb, offset + 3);
	mcc = (byte[0] & 0x0F) * 100 + ((byte[0] & 0xF0) >> 4) * 10  + (byte[1] & 0x0F );
	if ((byte[1] & 0xF0) == 0xF0)
		mnc = (byte[2] & 0x0F) * 10  + ((byte[2] & 0xF0) >> 4);
	else
		mnc = (byte[2] & 0x0F) * 100 + ((byte[2] & 0xF0) >> 4 ) * 10  + ((byte[1] & 0xF0) >> 4);

	proto_tree_add_uint(ext_tree_rai, hf_gtp_rai_mcc, tvb, offset+1, 2, mcc);
	proto_tree_add_uint(ext_tree_rai, hf_gtp_rai_mnc, tvb, offset+2, 2, mnc);
	proto_tree_add_uint(ext_tree_rai, hf_gtp_rai_lac, tvb, offset+4, 2, tvb_get_ntohs (tvb, offset+4));
	proto_tree_add_uint(ext_tree_rai, hf_gtp_rai_rac, tvb, offset+6, 1, tvb_get_guint8 (tvb, offset+6));

	return 7;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.4, page 39
 * UMTS:	29.060 v4.0, chapter 7.7.4, page 47
 */
static int
decode_gtp_tlli(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint32	tlli;

	tlli = tvb_get_ntohl(tvb, offset+1);
	proto_tree_add_uint(tree, hf_gtp_tlli, tvb, offset, 5, tlli);

	return 5;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.5, page 39
 * UMTS:	29.060 v4.0, chapter 7.7.5, page 47
 */
static int
decode_gtp_ptmsi(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint32	ptmsi;

	ptmsi = tvb_get_ntohl (tvb, offset+1);
	proto_tree_add_uint (tree, hf_gtp_ptmsi, tvb, offset, 5, ptmsi);

	return 5;
}

/* adjust - how many bytes before offset should be highlighted
 */
static int
decode_qos_gprs(tvbuff_t *tvb, int offset, proto_tree *tree, const gchar* qos_str, guint8 adjust) {

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
				                                        qos_str, (delay >> 3) & 0x07, reliability, (peak >> 4) & 0x0F, precedence, mean);
	ext_tree_qos = proto_item_add_subtree(te, ett_gtp_qos);

	if (adjust != 0) {
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare1, tvb, offset, 1, spare1);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_delay, tvb, offset, 1, delay);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_reliability, tvb, offset, 1, reliability);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_peak, tvb, offset+1, 1, peak);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare2, tvb, offset+1, 1, spare2);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_precedence, tvb, offset+1, 1, precedence);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare3, tvb, offset+2, 1, spare3);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_mean, tvb, offset+2, 1, mean);
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
decode_gtp_qos_gprs(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	return (1+decode_qos_gprs(tvb, offset+1, tree, "Quality of Service", 1));

}

/* GPRS:	9.60 v7.6.0, chapter 7.9.7, page 39
 * UMTS:	29.060 v4.0, chapter 7.7.6, page 47
 */
static int
decode_gtp_reorder(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8	reorder;

	reorder = tvb_get_guint8(tvb, offset+1) & 0x01;
	proto_tree_add_boolean(tree, hf_gtp_reorder, tvb, offset, 2, reorder);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.8, page 40
 * 		4.08 v7.1.2, chapter 10.5.3.1+
 * UMTS:	29.060 v4.0, chapter 7.7.7
 * TODO: Add blurb support by registering items in the protocol registration
 */
static int
decode_gtp_auth_tri(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	proto_tree	*ext_tree_auth_tri;
	proto_item	*te;

	te = proto_tree_add_text(tree, tvb, offset, 29, val_to_str(GTP_EXT_AUTH_TRI, gtp_val, "Unknown message"));
	ext_tree_auth_tri = proto_item_add_subtree(tree, ett_gtp_auth_tri);

	proto_tree_add_text(ext_tree_auth_tri, tvb, offset+1, 16, "RAND: %s", tvb_bytes_to_str(tvb, offset+1, 16));
	proto_tree_add_text(ext_tree_auth_tri, tvb, offset+17, 4, "SRES: %s", tvb_bytes_to_str(tvb, offset+17, 4));
	proto_tree_add_text(ext_tree_auth_tri, tvb, offset+21, 8, "Kc: %s", tvb_bytes_to_str(tvb, offset+21, 8));

	return 1+16+4+8;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.9, page 40
 * 		9.02 v7.7.0, page 1090
 * UMTS:	29.060 v4.0, chapter 7.7.8, page 48
 * 		29.002 v4.2.1, chapter 17.5, page 268
 */
static int
decode_gtp_map_cause(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8	map_cause;

	map_cause = tvb_get_guint8(tvb, offset+1);
	proto_tree_add_uint (tree, hf_gtp_map_cause, tvb, offset, 2, map_cause);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.10, page 41
 * UMTS:	29.060 v4.0, chapter 7.7.9, page 48
 */
static int
decode_gtp_ptmsi_sig(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint32	ptmsi_sig;

	ptmsi_sig = tvb_get_ntoh24(tvb, offset+1);
	proto_tree_add_uint(tree, hf_gtp_ptmsi_sig, tvb, offset, 4, ptmsi_sig);

	return 4;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.11, page 41
 * UMTS:	29.060 v4.0, chapter 7.7.10, page 49
 */
static int
decode_gtp_ms_valid(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8	ms_valid;

	ms_valid = tvb_get_guint8(tvb, offset+1) & 0x01;
	proto_tree_add_boolean (tree, hf_gtp_ms_valid, tvb, offset, 2, ms_valid);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.12, page 41
 * UMTS:	29.060 v4.0, chapter 7.7.11, page 49
 */
static int
decode_gtp_recovery(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8	recovery;

	recovery = tvb_get_guint8(tvb, offset+1);
	proto_tree_add_uint (tree, hf_gtp_recovery, tvb, offset, 2, recovery);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.13, page 42
 * UMTS:	29.060 v4.0, chapter 7.7.12, page 49
 */
static int
decode_gtp_sel_mode(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8	sel_mode;

	sel_mode = tvb_get_guint8(tvb, offset+1) & 0x03;
	proto_tree_add_uint(tree, hf_gtp_sel_mode, tvb, offset, 2, sel_mode);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.14, page 42
 * UMTS:	29.060 v4.0, chapter 7.7.13, page 50
 */
static int
decode_gtp_16(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16	ext_flow_label;
	guint32	teid_data;

	switch (gtp_version) {
		case 0:
			ext_flow_label = tvb_get_ntohs(tvb, offset+1);
			proto_tree_add_uint(tree, hf_gtp_ext_flow_label, tvb, offset, 3, ext_flow_label);

			return 3;
		case 1:
			teid_data = tvb_get_ntohl(tvb, offset+1);
			proto_tree_add_uint(tree, hf_gtp_teid_data, tvb, offset, 5, teid_data);

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
decode_gtp_17(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		flow_sig;
	guint32		teid_cp;

	switch (gtp_version) {
		case 0:
			flow_sig = tvb_get_ntohs(tvb, offset+1);
			proto_tree_add_uint (tree, hf_gtp_flow_sig, tvb, offset, 3, flow_sig);
			return 3;
		case 1:
			teid_cp = tvb_get_ntohl(tvb, offset+1);
			proto_tree_add_uint (tree, hf_gtp_teid_cp, tvb, offset, 5, teid_cp);
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
decode_gtp_18(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		flow_ii;
	guint32		teid_ii;
	proto_tree	*ext_tree_flow_ii;
	proto_item	*te;

	switch (gtp_version) {
		case 0:
			te = proto_tree_add_text(tree, tvb, offset, 4, val_to_str(GTP_EXT_FLOW_II, gtp_val, "Unknown message"));
			ext_tree_flow_ii = proto_item_add_subtree (te, ett_gtp_flow_ii);

			proto_tree_add_uint(ext_tree_flow_ii, hf_gtp_nsapi, tvb, offset+1, 1, tvb_get_guint8(tvb, offset+1) & 0x0F);

			flow_ii = tvb_get_ntohs(tvb, offset+2);
			proto_tree_add_uint(ext_tree_flow_ii, hf_gtp_flow_ii, tvb, offset+2, 2, flow_ii);

			return 4;
		case 1:
			te = proto_tree_add_text (tree, tvb, offset, 6, val_to_str(GTP_EXT_TEID_II, gtp_val, "Unknown message"));
			ext_tree_flow_ii = proto_item_add_subtree(te, ett_gtp_flow_ii);

			proto_tree_add_uint(ext_tree_flow_ii, hf_gtp_nsapi, tvb, offset+1, 1, tvb_get_guint8(tvb, offset+1) & 0x0F);


			teid_ii = tvb_get_ntohl(tvb, offset+2);
			proto_tree_add_uint(ext_tree_flow_ii, hf_gtp_teid_ii, tvb, offset+2, 4, teid_ii);

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
decode_gtp_19(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8		field19;

	field19 = tvb_get_guint8(tvb, offset+1);

	switch (gtp_version) {
		case 0:
			proto_tree_add_uint(tree, hf_gtp_ms_reason, tvb, offset, 2, field19);
			break;
		case 1:
			proto_tree_add_boolean(tree, hf_gtp_tear_ind, tvb, offset, 2, field19 & 0x01);
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
decode_gtp_nsapi(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8		nsapi;

	nsapi = tvb_get_guint8(tvb, offset+1) & 0x0F;
	proto_tree_add_uint(tree, hf_gtp_nsapi, tvb, offset, 2, nsapi);

	return 2;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.18, page 52
 */
static int
decode_gtp_ranap_cause(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8		ranap;

	ranap = tvb_get_guint8(tvb, offset+1);

	if(ranap > 0 && ranap <=64)
		proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, 
			ranap, "%s (Radio Network Layer Cause) : %s (%u)", 
			val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), 
			val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	if(ranap > 64 && ranap <=80)
		proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, 
			ranap, "%s (Transport Layer Cause) : %s (%u)", 
			val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), 
			val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	if(ranap > 80 && ranap <=96)
		proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, 
			ranap, "%s (NAS Cause) : %s (%u)", 
			val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), 
			val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	if(ranap > 96 && ranap <=112)
		proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, ranap, 
			"%s (Protocol Cause) : %s (%u)", 
			val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), 
			val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	if(ranap > 112 && ranap <=128)
		proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, ranap, 
			"%s (Miscellaneous Cause) : %s (%u)", 
			val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), 
			val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	if(ranap > 128 /* && ranap <=255 */)
		proto_tree_add_uint_format(tree, hf_gtp_ranap_cause, tvb, offset, 2, ranap, 
			"%s (Non-standard Cause) : %s (%u)", 
			val_to_str(GTP_EXT_RANAP_CAUSE, gtp_val, "Unknown"), 
			val_to_str(ranap, ranap_cause_type, "Unknown RANAP Cause"), ranap);

	return 2;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.19, page 52
 */
static int
decode_gtp_rab_cntxt(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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

	proto_tree_add_uint (ext_tree_rab_cntxt, hf_gtp_nsapi, tvb, offset+1, 1, nsapi);
	proto_tree_add_uint(ext_tree_rab_cntxt, hf_gtp_rab_gtpu_dn, tvb, offset+2, 2, dl_gtpu_seq);
	proto_tree_add_uint(ext_tree_rab_cntxt, hf_gtp_rab_gtpu_up, tvb, offset+4, 2, ul_gtpu_seq);
	proto_tree_add_uint(ext_tree_rab_cntxt, hf_gtp_rab_pdu_dn, tvb, offset+6, 1, dl_pdcp_seq);
	proto_tree_add_uint(ext_tree_rab_cntxt, hf_gtp_rab_pdu_up, tvb, offset+7, 1, ul_pdcp_seq);

	return 8;
}


/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.20, page 53
 */
static int
decode_gtp_rp_sms(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8		rp_sms;

	rp_sms = tvb_get_guint8(tvb, offset+1) & 0x07;
	proto_tree_add_uint(tree, hf_gtp_rp_sms, tvb, offset, 2, rp_sms);

	return 2;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.21, page 53
 */
static int
decode_gtp_rp(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	proto_tree	*ext_tree_rp;
	proto_item	*te;
	guint8 		nsapi, rp, spare;

	nsapi = tvb_get_guint8(tvb, offset+1) & 0xF0;
	spare = tvb_get_guint8(tvb, offset+1) & 0x08;
	rp = tvb_get_guint8(tvb, offset+1) & 0x07;

	te = proto_tree_add_uint_format(tree, hf_gtp_rp, tvb, offset, 2, rp, "Radio Priority for NSAPI(%u) : %u", nsapi, rp);
	ext_tree_rp = proto_item_add_subtree(tree, ett_gtp_rp);

	proto_tree_add_uint(ext_tree_rp, hf_gtp_rp_nsapi, tvb, offset+1, 1, nsapi);
	proto_tree_add_uint(ext_tree_rp, hf_gtp_rp_spare, tvb, offset+1, 1, spare);
	proto_tree_add_uint(ext_tree_rp, hf_gtp_rp, tvb, offset+1, 1, rp);

	return 2;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.22, page 53
 */
static int
decode_gtp_pkt_flow_id(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	proto_tree	*ext_tree_pkt_flow_id;
	proto_item	*te;
	guint8 		nsapi, pkt_flow_id;

	nsapi = tvb_get_guint8(tvb, offset+1) & 0x0F;
	pkt_flow_id = tvb_get_guint8(tvb, offset+2);

	te = proto_tree_add_uint_format (tree, hf_gtp_pkt_flow_id, tvb, offset, 
		3, pkt_flow_id, "Packet Flow ID for NSAPI(%u) : %u", nsapi, 
		pkt_flow_id);
	ext_tree_pkt_flow_id = proto_item_add_subtree(tree, ett_gtp_pkt_flow_id);

	proto_tree_add_uint(ext_tree_pkt_flow_id, hf_gtp_nsapi, tvb, offset+1, 1, nsapi);
	proto_tree_add_uint_format(ext_tree_pkt_flow_id, hf_gtp_pkt_flow_id, tvb, 
		offset+2, 1, pkt_flow_id, "%s : %u", 
		val_to_str(GTP_EXT_PKT_FLOW_ID, gtp_val, "Unknown message"), 
		pkt_flow_id);

	return 3;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.23, page 53
 * TODO: Differenciate these uints?
 */
static int
decode_gtp_chrg_char(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		chrg_char;
	proto_item	*te;
	proto_tree	*ext_tree_chrg_char;

	chrg_char = tvb_get_ntohs(tvb, offset+1);

	te = proto_tree_add_uint (tree, hf_gtp_chrg_char, tvb, offset, 3, chrg_char);
	/*"%s: %x", val_to_str (GTP_EXT_CHRG_CHAR, gtp_val, "Unknown message"), chrg_char);*/
	ext_tree_chrg_char = proto_item_add_subtree(te, ett_gtp_chrg_char);

	proto_tree_add_uint (ext_tree_chrg_char, hf_gtp_chrg_char_s, tvb, offset+1, 2, chrg_char);
	proto_tree_add_uint (ext_tree_chrg_char, hf_gtp_chrg_char_n, tvb, offset+1, 2, chrg_char);
	proto_tree_add_uint (ext_tree_chrg_char, hf_gtp_chrg_char_p, tvb, offset+1, 2, chrg_char);
	proto_tree_add_uint (ext_tree_chrg_char, hf_gtp_chrg_char_f, tvb, offset+1, 2, chrg_char);
	proto_tree_add_uint (ext_tree_chrg_char, hf_gtp_chrg_char_h, tvb, offset+1, 2, chrg_char);
	proto_tree_add_uint (ext_tree_chrg_char, hf_gtp_chrg_char_r, tvb, offset+1, 2, chrg_char);

	return 3;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.24, page
 */
static int
decode_gtp_trace_ref(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		trace_ref;

	trace_ref = tvb_get_ntohs(tvb, offset+1);

	proto_tree_add_uint (tree, hf_gtp_trace_ref, tvb, offset, 3, trace_ref);

	return 3;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.25, page
 */
static int
decode_gtp_trace_type(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		trace_type;

	trace_type = tvb_get_ntohs(tvb, offset+1);

	proto_tree_add_uint (tree, hf_gtp_trace_type, tvb, offset, 3, trace_type);

	return 3;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.16A
 * UMTS:	29.060 v4.0, chapter 7.7.25A, page
 */
static int
decode_gtp_ms_reason(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8		reason;

	reason = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint (tree, hf_gtp_ms_reason, tvb, offset, 2, reason);

	return 2;
}


/* GPRS:	12.15 v7.6.0, chapter 7.3.3, page 45
 * UMTS:	33.015
 */
static int
decode_gtp_tr_comm(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint8	tr_command;

	tr_command = tvb_get_guint8(tvb, offset+1);

	proto_tree_add_uint (tree, hf_gtp_tr_comm, tvb, offset, 2, tr_command);

	return 2;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.17, page 43
 * UMTS:	29.060 v4.0, chapter 7.7.26, page 55
 */
static int
decode_gtp_chrg_id(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint32	chrg_id;

	chrg_id = tvb_get_ntohl(tvb, offset+1);
	proto_tree_add_uint (tree, hf_gtp_chrg_id, tvb, offset, 5, chrg_id);

	return 5;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.18, page 43
 * UMTS:	29.060 v4.0, chapter 7.7.27, page 55
 */
static int
decode_gtp_user_addr(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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
	proto_tree_add_uint(ext_tree_user, hf_gtp_user_addr_pdp_org, tvb, offset+3, 1, pdp_org);
	proto_tree_add_uint(ext_tree_user, hf_gtp_user_addr_pdp_type, tvb, offset+4, 1, pdp_typ);

	if (length == 2) {
		if (pdp_org == 0 && pdp_typ == 1)
			proto_item_append_text(te, " (Point to Point Protocol)");
		else if (pdp_typ == 2)
			proto_item_append_text(te, " (Octet Stream Protocol)");
	} else if (length > 2) {
		switch (pdp_typ) {
			case 0x21:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+5, sizeof addr_ipv4);
				proto_tree_add_ipv4(ext_tree_user, hf_gtp_user_ipv4, tvb, offset+5, 4, addr_ipv4);
				proto_item_append_text(te, " : %s", ip_to_str((guint8 *)&addr_ipv4));
				break;
			case 0x57:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+5, sizeof addr_ipv6);
				proto_tree_add_ipv6 (ext_tree_user, hf_gtp_user_ipv6, tvb, offset+5, 16, (guint8 *)&addr_ipv6);
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
	guint16		i;

	for (i=0;i<count;i++) {
		te_trip = proto_tree_add_text(tree, tvb, offset+i*28, 28, "Triplet no%x", i);
		ext_tree_trip = proto_item_add_subtree(te_trip, ett_gtp_trip);

		proto_tree_add_text(ext_tree_trip, tvb, offset+i*28, 16, "RAND: %s", tvb_bytes_to_str(tvb, offset+i*28, 16));
		proto_tree_add_text(ext_tree_trip, tvb, offset+i*28+16, 4, "SRES: %s", tvb_bytes_to_str(tvb, offset+i*28+16, 4));
		proto_tree_add_text(ext_tree_trip, tvb, offset+i*28+20, 8, "Kc: %s", tvb_bytes_to_str(tvb, offset+i*28+20, 8));
	}

	return count*28;
}

/* adjust - how many bytes before quintuplet should be highlighted
 */
static int
decode_quintuplet(tvbuff_t *tvb, int offset, proto_tree *tree, guint16 count) {

	proto_tree	*ext_tree_quint;
	proto_item	*te_quint;
	guint16		q_offset, i;
	guint8          xres_len, auth_len;

	q_offset = 0;

	for (i=0;i<count;i++) {

		te_quint = proto_tree_add_text(tree, tvb, offset, -1, "Quintuplet #%x", i+1);
		ext_tree_quint = proto_item_add_subtree(te_quint, ett_gtp_quint);


		proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 16, "RAND: %s", tvb_bytes_to_str(tvb, offset, 16));
		q_offset = q_offset + 16;
		xres_len = tvb_get_guint8(tvb, offset+q_offset);
		proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 1, "XRES length: %u", xres_len);
		q_offset++;
		proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, xres_len, "XRES: %s", tvb_bytes_to_str(tvb, offset + q_offset, xres_len));
		q_offset = q_offset + xres_len;
		proto_tree_add_text(ext_tree_quint, tvb ,offset + q_offset, 16, "Quintuplet Ciphering Key: %s", tvb_bytes_to_str(tvb, offset + q_offset, 16));
		q_offset = q_offset + 16;
		proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 16, "Quintuplet Integrity Key: %s", tvb_bytes_to_str(tvb, offset + q_offset, 16));
		q_offset = q_offset +16;
		auth_len = tvb_get_guint8(tvb, offset + q_offset);
		proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 1, "Authentication length: %u", auth_len);
		q_offset++;
		proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, auth_len, "AUTH: %s", tvb_bytes_to_str(tvb, offset + q_offset, auth_len));

		q_offset = q_offset+auth_len;
		proto_item_set_end(te_quint, tvb, offset+q_offset);

	}

	return q_offset;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.19 page
 * UMTS:	29.060 v4.0, chapter 7.7.28 page 57
 * TODO:	- check if for quintuplets first 2 bytes are length, according to AuthQuint
 * 		- finish displaying last 3 parameters
 */
static int
decode_gtp_mm_cntxt(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		length, quint_len, con_len;
	guint8		cksn, count, sec_mode, len;
	proto_tree	*ext_tree_mm;
	proto_item	*te;
    proto_item  *tf = NULL;
    proto_tree  *tf_tree = NULL;
	tvbuff_t	*l3_tvb;


	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_MM_CNTXT, gtp_val, "Unknown message"));
	ext_tree_mm = proto_item_add_subtree(te, ett_gtp_mm);

	/* Octet 2 - 3 */
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < 1) return 3;

	/* Octet 4 */
	cksn = tvb_get_guint8(tvb, offset+3) & 0x07;
	/* Octet 5 */
	sec_mode = (tvb_get_guint8(tvb, offset+4) >> 6) & 0x03;
	count = (tvb_get_guint8(tvb, offset+4) >> 3) & 0x07;

	proto_tree_add_text(ext_tree_mm, tvb, offset+1, 2, "Length: %x", length);
	if (gtp_version == 0)
		sec_mode = 1;
	

	switch (sec_mode) {
		case 0:				/* Used cipher value, UMTS keys and Quintuplets */
			proto_tree_add_item(ext_tree_mm, hf_gtp_cksn_ksi, tvb, offset+3, 1, FALSE);
			proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode, tvb, offset+4, 1, FALSE);
			proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors, tvb, offset+4, 1, FALSE);
			proto_tree_add_item(ext_tree_mm, hf_gtp_cipher_algorithm, tvb, offset+4, 1, FALSE);
			proto_tree_add_text(ext_tree_mm, tvb, offset+5, 16, "Ciphering key CK: %s", tvb_bytes_to_str(tvb, offset+5, 16));
			proto_tree_add_text(ext_tree_mm, tvb, offset+21, 16, "Integrity key IK: %s", tvb_bytes_to_str(tvb, offset+21, 16));
			quint_len = tvb_get_ntohs(tvb, offset+37);
			proto_tree_add_text(ext_tree_mm, tvb, offset+37, 2, "Quintuplets length: 0x%x (%u)", quint_len, quint_len);

			offset = offset + decode_quintuplet(tvb, offset+39, ext_tree_mm, count) + 39;


			break;
		case 1:				/* GSM key and triplets */
			proto_tree_add_item(ext_tree_mm, hf_gtp_cksn, tvb, offset+3, 1, FALSE);
			if (gtp_version != 0) 
				proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode, tvb, offset+4, 1, FALSE);

			proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors, tvb, offset+4, 1, FALSE);
			proto_tree_add_item(ext_tree_mm, hf_gtp_cipher_algorithm, tvb, offset+4, 1, FALSE);
			proto_tree_add_text(ext_tree_mm, tvb, offset+5, 8, "Ciphering key Kc: %s", tvb_bytes_to_str(tvb, offset+5, 8));

			offset = offset + decode_triplet(tvb, offset+13, ext_tree_mm, count) + 14;

			break;
		case 2:				/* UMTS key and quintuplets */
			proto_tree_add_item(ext_tree_mm, hf_gtp_ksi, tvb, offset+3, 1, FALSE);
			proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode, tvb, offset+4, 1, FALSE);
			proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors, tvb, offset+4, 1, FALSE);
			proto_tree_add_text(ext_tree_mm, tvb, offset+5, 16, "Ciphering key CK: %s", tvb_bytes_to_str(tvb, offset+5, 16));
			proto_tree_add_text(ext_tree_mm, tvb, offset+21, 16, "Integrity key IK: %s", tvb_bytes_to_str(tvb, offset+21, 16));
			quint_len = tvb_get_ntohs(tvb, offset+37);
			proto_tree_add_text(ext_tree_mm, tvb, offset+37, 2, "Quintuplets length: 0x%x (%u)", quint_len, quint_len);

			offset = offset + decode_quintuplet(tvb, offset+39, ext_tree_mm, count) + 39;

			break;
		case 3:				/* GSM key and quintuplets */
			proto_tree_add_item(ext_tree_mm, hf_gtp_cksn, tvb, offset+3, 1, FALSE);
			proto_tree_add_item(ext_tree_mm, hf_gtp_security_mode, tvb, offset+4, 1, FALSE);
			proto_tree_add_item(ext_tree_mm, hf_gtp_no_of_vectors, tvb, offset+4, 1, FALSE);
			proto_tree_add_item(ext_tree_mm, hf_gtp_cipher_algorithm, tvb, offset+4, 1, FALSE);
			proto_tree_add_text(ext_tree_mm, tvb, offset+5, 8, "Ciphering key Kc: %s", tvb_bytes_to_str(tvb, offset+5, 8));
			quint_len = tvb_get_ntohs(tvb, offset+13);
			proto_tree_add_text(ext_tree_mm, tvb, offset+13, 2, "Quintuplets length: 0x%x (%u)", quint_len, quint_len);

			offset = offset + decode_quintuplet(tvb, offset+15, ext_tree_mm, count) + 15;

			break;
		default:
			break;
	}

/*
 * 3GPP TS 24.008 10.5.5.6 ( see packet-gsm_a.c )
 */
	de_gmm_drx_param(tvb, ext_tree_mm, offset, 2, NULL, 0);
	offset = offset +2;

	len	= tvb_get_guint8(tvb, offset);
    tf = proto_tree_add_text(ext_tree_mm,
    	tvb, offset, len+1,
    	"MS Network Capability");

    tf_tree = proto_item_add_subtree(tf, ett_gtp_net_cap);

	proto_tree_add_text(tf_tree, tvb, offset, 1, "Length of MS network capability contents: %u", len);

	offset++;
/*
 * GPP TS 24.008 10.5.5.12 ( see packet-gsm_a.c )
 */
	de_gmm_ms_net_cap(tvb, tf_tree, offset, len, NULL, 0);
	offset = offset +len;

/* Container contains one or several optional information elements as described in the clause 'Overview', 
 * from the clause 'General message format and information elements coding' in 3GPP TS 24.008. 
 * The IMEISV shall, if available, be included in the Container.
 */

	con_len = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(ext_tree_mm, tvb, offset, 2, "Container length: %u", con_len);
	offset = offset + 2;

	if (con_len > 0) {
		
		l3_tvb = tvb_new_subset(tvb, offset,con_len, con_len );
		if  (!dissector_try_port(bssap_pdu_type_table,BSSAP_PDU_TYPE_DTAP, l3_tvb, pinfo, ext_tree_mm))
		   		call_dissector(data_handle, l3_tvb, pinfo, ext_tree_mm);
	}

	return 3+length;
}

/* Function to extract the value of an hexadecimal octet. Only the lower
 * nybble will be non-zero in the output.
 * */
static guint8 hex2dec (guint8 x)
{
	if ((x >= 'a') && (x <= 'f'))
		x = x - 'a' + 10;
	else if ((x >= 'A') && (x <= 'F'))
		x = x - 'A' + 10;
	else if ((x >= '0') && (x <= '9'))
		x = x - '0';
	else
		x = 0;
	return x;
}

/* Wrapper function to add UTF-8 decoding for QoS attributes in
 * RADIUS messages.
 * */
static guint8 wrapped_tvb_get_guint8( tvbuff_t *tvb, int offset, int type)
{
	if (type == 2)
		return (hex2dec(tvb_get_guint8(tvb, offset)) << 4
					| hex2dec(tvb_get_guint8(tvb, offset + 1)));
	else
		return tvb_get_guint8(tvb, offset);
}

 /* WARNING : actually length is coded on 2 octets for QoS profile but on 1 octet for PDP Context!
  * so type means length of length :-)
  *
  * WARNING :) type does not mean length of length any more... see below for
  * type = 3!
 */
static int
decode_qos_umts(tvbuff_t *tvb, int offset, proto_tree *tree, const gchar* qos_str, guint8 type) {

	guint		length;
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

	/* Will keep if the input is UTF-8 encoded (as in RADIUS messages).
	 * If 1, input is *not* UTF-8 encoded (i.e. each input octet corresponds
	 * to one byte to be dissected).
	 * If 2, input is UTF-8 encoded (i.e. each *couple* of input octets
	 * corresponds to one byte to be dissected)
	 * */
	guint8      utf8_type = 1;

	/* In RADIUS messages the QoS has a version field of two octets prepended.
	 * As of 29.061 v.3.a.0, there is an hyphen between "Release Indicator" and
	 * <release specific QoS IE UTF-8 encoding>. Even if it sounds rather
	 * inconsistent and unuseful, I will check hyphen presence here and
	 * will signal its presence.
	 * */
	guint8      hyphen;

	/* Will keep the value that will be returned
	 * */
	int		retval = 0;

	switch (type) {
		case 1:
			length = tvb_get_guint8 (tvb, offset);
			te = proto_tree_add_text (tree, tvb, offset, length + 1, "%s", qos_str);
			ext_tree_qos = proto_item_add_subtree (te, ett_gtp_qos);
			proto_tree_add_text (ext_tree_qos, tvb, offset, 1, "Length: %u", length);
			offset++;
			retval = length + 1;
			break;
		case 2:
			length = tvb_get_ntohs (tvb, offset + 1);
			te = proto_tree_add_text(tree, tvb, offset, length + 3, "%s", qos_str);
			ext_tree_qos = proto_item_add_subtree (te, ett_gtp_qos);
			proto_tree_add_text (ext_tree_qos, tvb, offset + 1, 2, "Length: %u", length);
			offset += 3;		/* +1 because of first 0x86 byte for UMTS QoS */
			retval = length + 3;
			break;
		case 3:
			/* For QoS inside RADIUS Client messages from GGSN */
			utf8_type = 2;

			/* The field in the RADIUS message is the length of the tvb we were given */
			length = tvb_length(tvb);
			te = proto_tree_add_text (tree, tvb, offset, length, "%s", qos_str);

			ext_tree_qos = proto_item_add_subtree (te, ett_gtp_qos);
			
			proto_tree_add_item (ext_tree_qos, hf_gtp_qos_version, tvb, offset, 2, FALSE);

			/* Hyphen handling */
			hyphen = tvb_get_guint8(tvb, offset + 2);
			if (hyphen == ((guint8) '-'))
			{
				/* Hyphen is present, put in protocol tree */
				proto_tree_add_text (ext_tree_qos, tvb, offset + 2, 1, "Hyphen separator: -");
				offset++; /* "Get rid" of hyphen */
			}

			/* Now, we modify offset here and in order to use type later
			 * effectively.*/
			offset++;
			
			length -= offset;
			length /=2;
			
			retval = length + 2;      /* Actually, will be ignored. */
			break;
		default:
			/* XXX - what should we do with the length here? */
			length = 0;
			retval = 0;
			ext_tree_qos = NULL;
			break;
	}

	/* In RADIUS messages there is no allocation-retention priority
	 * so I don't need to wrap the following call to tvb_get_guint8
	 * */
	al_ret_priority = tvb_get_guint8 (tvb, offset);

	/* All calls are wrapped to take into account the possibility that the
	 * input is UTF-8 encoded. If utf8_type is equal to 1, the final value
	 * of the offset will be the same as in the previous version of this
	 * dissector, and the wrapped function will serve as a dumb wrapper;
	 * otherwise, if utf_8_type is 2, the offset is correctly shifted by
	 * two bytes for needed shift, and the wrapped function will unencode
	 * two values from the input.
	 * */
	spare1 = wrapped_tvb_get_guint8(tvb, offset+(1 - 1) * utf8_type + 1, utf8_type) & 0xC0;
	delay = wrapped_tvb_get_guint8(tvb, offset+(1 - 1) * utf8_type + 1, utf8_type) & 0x38;
	reliability = wrapped_tvb_get_guint8(tvb, offset+(1 - 1) * utf8_type + 1, utf8_type) & 0x07;
	peak = wrapped_tvb_get_guint8(tvb, offset+(2 - 1) * utf8_type + 1, utf8_type) & 0xF0;
	spare2 = wrapped_tvb_get_guint8(tvb, offset+(2 - 1) * utf8_type + 1, utf8_type) & 0x08;
	precedence = wrapped_tvb_get_guint8(tvb, offset+(2 - 1) * utf8_type + 1, utf8_type) & 0x07;
	spare3 = wrapped_tvb_get_guint8(tvb, offset+(3 - 1) * utf8_type + 1, utf8_type) & 0xE0;
	mean = wrapped_tvb_get_guint8(tvb, offset+(3 - 1) * utf8_type + 1, utf8_type) & 0x1F;

	/* In RADIUS messages there is no allocation-retention priority */
	if (type != 3)
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_al_ret_priority, tvb, offset, 1, al_ret_priority);

	/* All additions must take care of the fact that QoS fields in RADIUS
	 * messages are UTF-8 encoded, so we have to use the same trick as above.
	 * */
	proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare1, tvb, offset+(1 - 1) * utf8_type + 1, utf8_type, spare1);
	proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_delay, tvb, offset+(1 - 1) * utf8_type + 1, utf8_type, delay);
	proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_reliability, tvb, offset+(1 - 1) * utf8_type + 1, utf8_type, reliability);
	proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_peak, tvb, offset+(2 - 1) * utf8_type + 1, utf8_type, peak);
	proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare2, tvb, offset+(2 - 1) * utf8_type + 1, utf8_type, spare2);
	proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_precedence, tvb, offset+(2 - 1) * utf8_type + 1, utf8_type, precedence);
	proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_spare3, tvb, offset+(3 - 1) * utf8_type + 1, utf8_type, spare3);
	proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_mean, tvb, offset+(3 - 1) * utf8_type + 1, utf8_type, mean);

	if (length > 4) {

		/* See above for the need of wrapping
		 * */
		traf_class = wrapped_tvb_get_guint8(tvb, offset+(4 - 1) * utf8_type + 1, utf8_type) & 0xE0;
		del_order = wrapped_tvb_get_guint8(tvb, offset+(4 - 1) * utf8_type + 1, utf8_type) & 0x18;
		del_err_sdu = wrapped_tvb_get_guint8(tvb, offset+(4 - 1) * utf8_type + 1, utf8_type) & 0x07;
		max_sdu_size = wrapped_tvb_get_guint8(tvb, offset+(5 - 1) * utf8_type + 1, utf8_type);
		max_ul = wrapped_tvb_get_guint8(tvb, offset+(6 - 1) * utf8_type + 1, utf8_type);
		max_dl = wrapped_tvb_get_guint8(tvb, offset+(7 - 1) * utf8_type + 1, utf8_type);
		res_ber = wrapped_tvb_get_guint8(tvb, offset+(8 - 1) * utf8_type + 1, utf8_type) & 0xF0;
		sdu_err_ratio = wrapped_tvb_get_guint8(tvb, offset+(8 - 1) * utf8_type + 1, utf8_type) & 0x0F;
		trans_delay = wrapped_tvb_get_guint8(tvb, offset+(9 - 1) * utf8_type + 1, utf8_type) & 0xFC;
		traf_handl_prio = wrapped_tvb_get_guint8(tvb, offset+(9 - 1) * utf8_type + 1, utf8_type) & 0x03;
		guar_ul = wrapped_tvb_get_guint8(tvb, offset+(10 - 1) * utf8_type + 1, utf8_type);
		guar_dl = wrapped_tvb_get_guint8(tvb, offset+(11 - 1) * utf8_type + 1, utf8_type);

		/* See above comments for the changes
		 * */
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_traf_class, tvb, offset+(4 - 1) * utf8_type + 1, utf8_type, traf_class);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_del_order, tvb, offset+(4 - 1) * utf8_type + 1, utf8_type, del_order);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_del_err_sdu, tvb, offset+(4 - 1) * utf8_type + 1, utf8_type, del_err_sdu);
		if (max_sdu_size == 0 || max_sdu_size > 150)
			proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_max_sdu_size, tvb, offset+(5 - 1) * utf8_type + 1, utf8_type, max_sdu_size);
		if (max_sdu_size > 0 && max_sdu_size <= 150) {
			mss = max_sdu_size*10;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_sdu_size, tvb, offset+(5 - 1) * utf8_type + 1, utf8_type, mss, "Maximum SDU size : %u octets", mss);
		}

		if(max_ul == 0 || max_ul == 255)
			proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset+(6 - 1) * utf8_type + 1, utf8_type, max_ul);
		if(max_ul > 0 && max_ul <= 63)
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset+(6 - 1) * utf8_type + 1, utf8_type, max_ul, "Maximum bit rate for uplink : %u kbps", max_ul);
		if(max_ul > 63 && max_ul <=127) {
			mu = 64 + ( max_ul - 64 ) * 8;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset+(6 - 1) * utf8_type + 1, utf8_type, mu, "Maximum bit rate for uplink : %u kbps", mu);
		}

		if(max_ul > 127 && max_ul <=254) {
			mu = 576 + ( max_ul - 128 ) * 64;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_ul, tvb, offset+(6 - 1) * utf8_type + 1, utf8_type, mu, "Maximum bit rate for uplink : %u kbps", mu);
		}

		if(max_dl == 0 || max_dl == 255)
			proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset+(7 - 1) * utf8_type + 1, utf8_type, max_dl);
		if(max_dl > 0 && max_dl <= 63)
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset+(7 - 1) * utf8_type + 1, utf8_type, max_dl, "Maximum bit rate for downlink : %u kbps", max_dl);
		if(max_dl > 63 && max_dl <=127) {
			md = 64 + ( max_dl - 64 ) * 8;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset+(7 - 1) * utf8_type + 1, utf8_type, md, "Maximum bit rate for downlink : %u kbps", md);
		}
		if(max_dl > 127 && max_dl <=254) {
			md = 576 + ( max_dl - 128 ) * 64;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_max_dl, tvb, offset+(7 - 1) * utf8_type + 1, utf8_type, md, "Maximum bit rate for downlink : %u kbps", md);
		}

		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_res_ber, tvb, offset+(8 - 1) * utf8_type + 1, utf8_type, res_ber);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_sdu_err_ratio, tvb, offset+(8 - 1) * utf8_type + 1, utf8_type, sdu_err_ratio);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_trans_delay, tvb, offset+(9 - 1) * utf8_type + 1, utf8_type, trans_delay);
		proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_traf_handl_prio, tvb, offset+(9 - 1) * utf8_type + 1, utf8_type, traf_handl_prio);

		if(guar_ul == 0 || guar_ul == 255)
			proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset+(10 - 1) * utf8_type + 1, utf8_type, guar_ul);
		if(guar_ul > 0 && guar_ul <= 63)
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset+(10 - 1) * utf8_type + 1, utf8_type, guar_ul, "Guaranteed bit rate for uplink : %u kbps", guar_ul);
		if(guar_ul > 63 && guar_ul <=127) {
			gu = 64 + ( guar_ul - 64 ) * 8;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset+(10 - 1) * utf8_type + 1, utf8_type, gu, "Guaranteed bit rate for uplink : %u kbps", gu);
		}
		if(guar_ul > 127 && guar_ul <=254) {
			gu = 576 + ( guar_ul - 128 ) * 64;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_ul, tvb, offset+(10 - 1) * utf8_type + 1, utf8_type, gu, "Guaranteed bit rate for uplink : %u kbps", gu);
		}

		if(guar_dl == 0 || guar_dl == 255)
			proto_tree_add_uint(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset+(11 - 1) * utf8_type + 1, utf8_type, guar_dl);
		if(guar_dl > 0 && guar_dl <= 63)
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset+(11 - 1) * utf8_type + 1, utf8_type, guar_dl, "Guaranteed bit rate for downlink : %u kbps", guar_dl);
		if(guar_dl > 63 && guar_dl <=127) {
			gd = 64 + ( guar_dl - 64 ) * 8;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset+(11 - 1) * utf8_type + 1, utf8_type, gd, "Guaranteed bit rate for downlink : %u kbps", gd);
		}
		if(guar_dl > 127 && guar_dl <=254) {
			gd = 576 + ( guar_dl - 128 ) * 64;
			proto_tree_add_uint_format(ext_tree_qos, hf_gtp_qos_guar_dl, tvb, offset+(11 - 1) * utf8_type + 1, utf8_type, gd, "Guaranteed bit rate for downlink : %u kbps", gd);
		}

	}

	return retval;
}

static const gchar* dissect_radius_qos_umts(proto_tree *tree, tvbuff_t *tvb) {
	decode_qos_umts(tvb, 0, tree, "UMTS GTP QoS Profile", 3);
	return "UMTS GTP QoS Profile";
}

static void
decode_apn(tvbuff_t *tvb, int offset, guint16 length, proto_tree *tree) {

	gchar	*apn = NULL;
	guint8	name_len, tmp;

	if (length > 0) {
		name_len = tvb_get_guint8 (tvb, offset);

		if (name_len < 0x20) {
			apn = tvb_get_ephemeral_string(tvb, offset + 1, length - 1);
			for (;;) {
				if (name_len >= length - 1) break;
				tmp = name_len;
				name_len = name_len + apn[tmp] + 1;
				apn[tmp] = '.';
			}
		} else
			apn = tvb_get_ephemeral_string(tvb, offset, length);

		proto_tree_add_string (tree, hf_gtp_apn, tvb, offset, length, apn);
	}
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.20
 * UMTS:	29.060 v4.0, chapter 7.7.29
 * TODO:	unify addr functions
 */
static int
decode_gtp_pdp_cntxt(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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
decode_gtp_apn(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		length;
	proto_tree	*ext_tree_apn;
	proto_item	*te;

	length = tvb_get_ntohs(tvb, offset+1);

	te = proto_tree_add_text (tree, tvb, offset, length+3, val_to_str(GTP_EXT_APN, gtp_val, "Unknown field"));
	ext_tree_apn = proto_item_add_subtree(te, ett_gtp_apn);

	proto_tree_add_text (ext_tree_apn, tvb, offset+1, 2, "APN length : %u", length);
	decode_apn (tvb, offset+3, length, ext_tree_apn);

	return 3+length;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.22
 * 		4.08 v. 7.1.2, chapter 10.5.6.3 (p.580)
 * UMTS:	29.060 v4.0, chapter 7.7.31
 * 		24.008, v4.2, chapter 10.5.6.3
 */
int
decode_gtp_proto_conf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16         length, proto_offset;
	guint16		proto_id;
	guint8          conf, proto_len, cnt = 1;
	tvbuff_t        *next_tvb;
	proto_tree      *ext_tree_proto;
	proto_item      *te;
	gboolean	save_writable;

	length = tvb_get_ntohs(tvb, offset + 1);

	te = proto_tree_add_text(tree, tvb, offset, length + 3, val_to_str(GTP_EXT_PROTO_CONF, gtp_val, "Unknown message"));
	ext_tree_proto = proto_item_add_subtree(te, ett_gtp_proto);

	proto_tree_add_text(ext_tree_proto, tvb, offset + 1, 2, "Length: %u", length);

	if (length < 1) return 3;

	conf = tvb_get_guint8 (tvb, offset + 3) & 0x07;
	proto_tree_add_text (ext_tree_proto, tvb, offset + 3, 1, "Configuration protocol (00000xxx): %u", conf);

	proto_offset = 1;       /* ... 1st byte is conf */
	offset += 4;

	for (;;) {
		if (proto_offset >= length) break;
		proto_id = tvb_get_ntohs (tvb, offset);
		proto_len = tvb_get_guint8 (tvb, offset + 2);
		proto_offset += proto_len + 3;		/* 3 = proto id + length byte */

		if (proto_len > 0) {

			proto_tree_add_text (ext_tree_proto, tvb, offset, 2, "Protocol %u ID: %s (0x%04x)",
			    cnt, val_to_str(proto_id, ppp_vals, "Unknown"),
			    proto_id);
			proto_tree_add_text (ext_tree_proto, tvb, offset+2, 1, "Protocol %u length: %u", cnt, proto_len);

			/*
			 * Don't allow the dissector for the configuration
			 * protocol in question to update the columns - this
			 * is GTP, not PPP.
			 */
			save_writable = col_get_writable(pinfo->cinfo);
			col_set_writable(pinfo->cinfo, FALSE);

			/*
			 * XXX - should we have our own dissector table,
			 * solely for configuration protocols, so that bogus
			 * values don't cause us to dissect the protocol
			 * data as, for example, IP?
			 */
			next_tvb = tvb_new_subset (tvb, offset + 3, proto_len, proto_len);
			if (!dissector_try_port(ppp_subdissector_table,
			    proto_id, next_tvb, pinfo, ext_tree_proto)) {
				call_dissector(data_handle, next_tvb, pinfo,
				    ext_tree_proto);
			}

			col_set_writable(pinfo->cinfo, save_writable);
		}

		offset += proto_len + 3;
		cnt++;
	}

	return 3 + length;
}

/* GPRS:	9.60 v7.6.0, chapter 7.9.23
 * UMTS:	29.060 v4.0, chapter 7.7.32
 */
static int
decode_gtp_gsn_addr(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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
			proto_tree_add_ipv4(ext_tree_gsn_addr, hf_gtp_gsn_ipv4, tvb, offset+3, 4, addr_ipv4);
			break;
		case 5:
			proto_tree_add_text(ext_tree_gsn_addr, tvb, offset+1, 2, "GSN address Information Element length : %u", length);
			addr_type = tvb_get_guint8(tvb, offset+3) & 0xC0;
			proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_type, tvb, offset+3, 1, addr_type);
			addr_len = tvb_get_guint8(tvb, offset+3) & 0x3F;
			proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_len, tvb, offset+3, 1, addr_len);
			tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+4, sizeof addr_ipv4);
			proto_item_append_text(te, "%s", ip_to_str((guint8 *)&addr_ipv4));
			proto_tree_add_ipv4(ext_tree_gsn_addr, hf_gtp_gsn_ipv4, tvb, offset+4, 4, addr_ipv4);
			break;
		case 16:
			proto_tree_add_text(ext_tree_gsn_addr, tvb, offset+1, 2, "GSN address length : %u", length);
			tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+3, sizeof addr_ipv6);
			proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
			proto_tree_add_ipv6(ext_tree_gsn_addr, hf_gtp_gsn_ipv6, tvb, offset+3, 16, (guint8*)&addr_ipv6);
			break;
		case 17:
			proto_tree_add_text(ext_tree_gsn_addr, tvb, offset+1, 2, "GSN address Information Element length : %u", length);
			addr_type = tvb_get_guint8(tvb, offset+3) & 0xC0;
			proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_type, tvb, offset+3, 1, addr_type);
			addr_len = tvb_get_guint8(tvb, offset+3) & 0x3F;
			proto_tree_add_uint(ext_tree_gsn_addr, hf_gtp_gsn_addr_len, tvb, offset+3, 1, addr_len);
			tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+4, sizeof addr_ipv6);
			proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
			proto_tree_add_ipv6(ext_tree_gsn_addr, hf_gtp_gsn_ipv6, tvb, offset+4, 16, (guint8*)&addr_ipv6);
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
decode_gtp_msisdn(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	const guint8	*msisdn_val;
	gchar		*msisdn_str;
	guint16		length;

	length = tvb_get_ntohs(tvb, offset+1);

	if (length < 1) return 3;

	msisdn_val = tvb_get_ptr(tvb, offset+3, length);
	msisdn_str = msisdn_to_str(msisdn_val, length);

	proto_tree_add_string(tree, hf_gtp_msisdn, tvb, offset, 3+length, msisdn_str);

	return 3+length;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.34
 * 		24.008 v4.2, chapter 10.5.6.5
 */
static int
decode_gtp_qos_umts(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	return decode_qos_umts(tvb, offset, tree, "Quality of Service", 2);
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.35
 */
static int
decode_gtp_auth_qui(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	proto_tree	*ext_tree_quint;
	proto_item	*te_quint;
	guint16		q_offset, q_len;
	guint8      xres_len, auth_len;

	q_offset = 0;


	offset = offset + q_offset;

	q_len = tvb_get_ntohs(tvb, offset);

	te_quint = proto_tree_add_text(tree, tvb, offset+1, q_len, "Quintuplet");
	ext_tree_quint = proto_item_add_subtree(te_quint, ett_gtp_quint);

	proto_tree_add_text(ext_tree_quint, tvb, offset, 2, "Length: %x", q_len);
	q_offset = q_offset + 2;

	proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 16, "RAND: %s", tvb_bytes_to_str(tvb, offset, 16));
	q_offset = q_offset + 16;
	xres_len = tvb_get_guint8(tvb, offset+q_offset);
	proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 1, "XRES length: %u", xres_len);
	q_offset++;
	proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, xres_len, "XRES: %s", tvb_bytes_to_str(tvb, offset + q_offset, xres_len));
	q_offset = q_offset + xres_len;
	proto_tree_add_text(ext_tree_quint, tvb ,offset + q_offset, 16, "Quintuplet Ciphering Key: %s", tvb_bytes_to_str(tvb, offset + q_offset, 16));
	q_offset = q_offset + 16;
	proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 16, "Quintuplet Integrity Key: %s", tvb_bytes_to_str(tvb, offset + q_offset, 16));
	q_offset = q_offset +16;
	auth_len = tvb_get_guint8(tvb, offset + q_offset);
	proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, 1, "Authentication length: %u", auth_len);
	q_offset++;
	proto_tree_add_text(ext_tree_quint, tvb, offset + q_offset, auth_len, "AUTH: %s", tvb_bytes_to_str(tvb, offset + q_offset, auth_len));

	q_offset = q_offset+auth_len;

	return (1 + q_offset);

}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.36
 * 		24.008 v4.2, chapter 10.5.6.12
 */
static int
decode_gtp_tft(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		length, port1, port2, tos;
	guint8		tft_flags, tft_code, no_packet_filters, i, pf_id, pf_eval, pf_len, pf_content_id, proto, spare;
	guint		pf_offset;
	guint32		mask_ipv4, addr_ipv4, ipsec_id, label;
	struct	e_in6_addr addr_ipv6, mask_ipv6;
	proto_tree	*ext_tree_tft, *ext_tree_tft_pf, *ext_tree_tft_flags;
	proto_item	*te, *tee, *tef;

	length = tvb_get_ntohs(tvb, offset+1);

	te = proto_tree_add_text(tree, tvb, offset, 3+length, "Traffic flow template");
	ext_tree_tft = proto_item_add_subtree(te, ett_gtp_tft);

	tft_flags = tvb_get_guint8(tvb, offset+3);
	tft_code = (tft_flags >> 5) & 0x07;
	spare = (tft_flags >> 4) & 0x01;
	no_packet_filters = tft_flags & 0x0F;

	proto_tree_add_text(ext_tree_tft, tvb, offset+1, 2, "TFT length: %u", length);

	tef = proto_tree_add_text (ext_tree_tft, tvb, offset + 3, 1, "TFT flags");
	ext_tree_tft_flags = proto_item_add_subtree (tef, ett_gtp_tft_flags);
	proto_tree_add_uint (ext_tree_tft_flags, hf_gtp_tft_code, tvb, offset + 3, 1, tft_flags);
	proto_tree_add_uint (ext_tree_tft_flags, hf_gtp_tft_spare, tvb, offset + 3, 1, tft_flags);
	proto_tree_add_uint (ext_tree_tft_flags, hf_gtp_tft_number, tvb, offset + 3, 1, tft_flags);

	offset = offset + 4;

	for (i=0;i<no_packet_filters;i++) {

		pf_id = tvb_get_guint8(tvb, offset);

		tee = proto_tree_add_text (ext_tree_tft, tvb, offset, 1, "Packet filter id: %u", pf_id);
		ext_tree_tft_pf = proto_item_add_subtree (tee, ett_gtp_tft_pf);
		offset++;

		if (tft_code != 2) {

			pf_eval = tvb_get_guint8(tvb, offset);
			pf_len = tvb_get_guint8(tvb, offset + 1);

			proto_tree_add_uint (ext_tree_tft_pf, hf_gtp_tft_eval, tvb, offset, 1, pf_eval);
			proto_tree_add_text (ext_tree_tft_pf, tvb, offset+1, 1, "Content length: %u", pf_len);

			offset = offset + 2;
			pf_offset = 0;

			while (pf_offset < pf_len) {

				pf_content_id = tvb_get_guint8 (tvb, offset + pf_offset);

				switch (pf_content_id) {
					/* address IPv4 and mask = 8 bytes*/
					case 0x10:
						tvb_memcpy (tvb, (guint8 *)&addr_ipv4, offset + pf_offset + 1, sizeof addr_ipv4);
						tvb_memcpy (tvb, (guint8 *)&mask_ipv4, offset + pf_offset + 5, sizeof mask_ipv4);
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset + pf_offset, 9, "ID 0x10: IPv4/mask: %s/%s", ip_to_str ((guint8 *)&addr_ipv4), ip_to_str ((guint8 *)&mask_ipv4));
						pf_offset = pf_offset + 9;
						break;
					/* address IPv6 and mask = 32 bytes*/
					case 0x20:
						tvb_memcpy (tvb, (guint8 *)&addr_ipv6, offset+pf_offset+1, sizeof addr_ipv6);
						tvb_memcpy (tvb, (guint8 *)&mask_ipv6, offset+pf_offset+17, sizeof mask_ipv6);
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset+pf_offset, 33, "ID 0x20: IPv6/mask: %s/%s", ip6_to_str ((struct e_in6_addr*)&addr_ipv6), ip6_to_str ((struct e_in6_addr*)&mask_ipv6));
						pf_offset = pf_offset + 33;
						break;
					/* protocol identifier/next header type = 1 byte*/
					case 0x30:
						proto = tvb_get_guint8 (tvb, offset + pf_offset + 1);
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset + pf_offset, 2, "ID 0x30: IPv4 protocol identifier/IPv6 next header: %u (%x)", proto, proto);
						pf_offset = pf_offset + 2;
						break;
					/* single destination port type = 2 bytes */
					case 0x40:
						port1 = tvb_get_ntohs (tvb, offset + pf_offset + 1);
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset + pf_offset, 3, "ID 0x40: destination port: %u", port1);
						pf_offset = pf_offset + 3;
						break;
					/* destination port range type = 4 bytes */
					case 0x41:
						port1 = tvb_get_ntohs (tvb, offset + pf_offset + 1);
						port2 = tvb_get_ntohs (tvb, offset + pf_offset + 3);
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset + pf_offset, 5, "ID 0x41: destination port range: %u - %u", port1, port2);
						pf_offset = pf_offset + 5;
						break;
					/* single source port type = 2 bytes */
					case 0x50:
						port1 = tvb_get_ntohs (tvb, offset + pf_offset + 1);
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset + pf_offset, 3, "ID 0x50: source port: %u", port1);
						pf_offset = pf_offset + 3;
						break;
					/* source port range type = 4 bytes */
					case 0x51:
						port1 = tvb_get_ntohs (tvb, offset + pf_offset + 1);
						port2 = tvb_get_ntohs (tvb, offset + pf_offset + 3);
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset + pf_offset, 5, "ID 0x51: source port range: %u - %u", port1, port2);
						pf_offset = pf_offset + 5;
						break;
					/* security parameter index type = 4 bytes */
					case 0x60:
						ipsec_id = tvb_get_ntohl (tvb, offset + pf_offset + 1);
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset + pf_offset, 5, "ID 0x60: security parameter index: %x", ipsec_id);
						pf_offset = pf_offset + 5;
						break;
					/* type of service/traffic class type = 2 bytes */
					case 0x70:
						tos = tvb_get_ntohs (tvb, offset + pf_offset + 1);
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset + pf_offset, 2, "ID 0x70: Type of Service/Traffic Class: %u (%x)", tos, tos);
						pf_offset = pf_offset + 3;
						break;
					/* flow label type = 3 bytes */
					case 0x80:
						label = tvb_get_ntoh24(tvb, offset + pf_offset + 1) & 0x0FFFFF;
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset + pf_offset, 4, "ID 0x80: Flow Label: %u (%x)", label, label);
						pf_offset = pf_offset + 4;
						break;

					default:
						proto_tree_add_text (ext_tree_tft_pf, tvb, offset + pf_offset, 1, "Unknown value: %x ", pf_content_id);
						pf_offset++; /* to avoid infinite loop */
						break;
				}
			}

			offset = offset + pf_offset;
		}
	}

	return 3 + length;
}

/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.37
 * 		25.413 v3.4, chapter ???
 */
static int
decode_gtp_target_id(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		length;

	length = tvb_get_ntohs(tvb, offset + 1);

	proto_tree_add_text(tree, tvb, offset, 3 + length, "Targer Identification");

	return 3 + length;
}


/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.38
 */
static int
decode_gtp_utran_cont(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		length;

	length = tvb_get_ntohs(tvb, offset + 1);

	proto_tree_add_text(tree, tvb, offset, 3 + length, "UTRAN transparent field");

	return 3 + length;

}


/* GPRS:	not present
 * UMTS:	29.060 v4.0, chapter 7.7.39
 */
static int
decode_gtp_rab_setup(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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
	proto_tree_add_uint(ext_tree_rab_setup, hf_gtp_nsapi, tvb, offset+3, 1, nsapi);

	if (length > 1) {

		teid = tvb_get_ntohl(tvb, offset + 4);

		proto_tree_add_uint(ext_tree_rab_setup, hf_gtp_teid_data, tvb, offset+4, 4, teid);

		switch (length) {
			case 12:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+8, sizeof addr_ipv4);
				proto_tree_add_ipv4(ext_tree_rab_setup, hf_gtp_rnc_ipv4, tvb, offset+8, 4, addr_ipv4);
				break;
			case 24:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+8, sizeof addr_ipv6);
				proto_tree_add_ipv6(ext_tree_rab_setup, hf_gtp_rnc_ipv6, tvb, offset+8, 16, (guint8 *)&addr_ipv6);
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
decode_gtp_hdr_list(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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
decode_gtp_trigger_id(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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
decode_gtp_omc_id(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		length;

	length = tvb_get_ntohs(tvb, offset + 1);

	proto_tree_add_text(tree, tvb, offset, 3+length, "%s length : %u", val_to_str(GTP_EXT_OMC_ID, gtp_val, "Unknown"), length);

	return 3 + length;

}

/* GPRS:	9.60 v7.6.0, chapter 7.9.25
 * UMTS:	29.060 v4.0, chapter 7.7.43
 */
static int
decode_gtp_chrg_addr(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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
			proto_tree_add_ipv4 (ext_tree_chrg_addr, hf_gtp_chrg_ipv4, tvb, offset+3, 4, addr_ipv4);
			break;
		case 16:
			tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+3, sizeof addr_ipv6);
			proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
			proto_tree_add_ipv6 (ext_tree_chrg_addr, hf_gtp_chrg_ipv6, tvb, offset+3, 16, (guint8*)&addr_ipv6);
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
decode_gtp_rel_pack(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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
decode_gtp_can_pack(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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
decode_gtp_data_req(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		length, format_ver;
	guint8		no, format;
	proto_tree	*ext_tree;
	proto_item	*te;
	tvbuff_t	*next_tvb;

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
	
	if (gtpcdr_handle) {
		next_tvb = tvb_new_subset (tvb, offset, -1, -1);
		call_dissector (gtpcdr_handle, next_tvb, pinfo, tree);
	}
	else
		proto_tree_add_text (tree, tvb, offset, 0, "Data");

	return 3+length;
}

/* GPRS:	12.15
 * UMTS:	33.015
 */
static int
decode_gtp_data_resp(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

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
decode_gtp_node_addr(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		length;
	guint32		addr_ipv4;
	struct	e_in6_addr addr_ipv6;
	proto_tree	*ext_tree_node_addr;
	proto_item	*te;

	length = tvb_get_ntohs(tvb, offset+1);

	te = proto_tree_add_text(tree, tvb, offset, 3+length, "Node address: ");
	ext_tree_node_addr = proto_item_add_subtree(te, ett_gtp_node_addr);

	proto_tree_add_text (ext_tree_node_addr, tvb, offset+1, 2, "Node address length: %u", length);

	switch (length) {
		case 4:
			tvb_memcpy(tvb, (guint8 *)&addr_ipv4, offset+3, sizeof addr_ipv4);
			proto_item_append_text(te, "%s", ip_to_str((guint8 *)&addr_ipv4));
			proto_tree_add_ipv4 (ext_tree_node_addr, hf_gtp_node_ipv4, tvb, offset+3, 4, addr_ipv4);
			break;
		case 16:
			tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+3, sizeof addr_ipv6);
			proto_item_append_text(te, "%s", ip6_to_str((struct e_in6_addr*)&addr_ipv6));
			proto_tree_add_ipv6 (ext_tree_node_addr, hf_gtp_node_ipv6, tvb, offset+3, 16, (guint8*)&addr_ipv6);
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
decode_gtp_priv_ext(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	guint16		length, ext_id;
	proto_tree	*ext_tree_priv_ext;
	proto_item	*te;

	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_PRIV_EXT, gtp_val, "Unknown message"));
	ext_tree_priv_ext = proto_item_add_subtree(te, ett_gtp_ext);

	length = tvb_get_ntohs(tvb, offset+1);
	if (length >= 2) {
		ext_id = tvb_get_ntohs(tvb, offset+3);
		proto_tree_add_uint(ext_tree_priv_ext, hf_gtp_ext_id, tvb, offset+3, 2, ext_id);

		/*
		 * XXX - is this always a text string?  Or should it be
		 * displayed as hex data?
		 */
		if (length > 2)
			proto_tree_add_item(ext_tree_priv_ext, hf_gtp_ext_val, tvb, offset+5, length-2, FALSE);
	}

	return 3+length;
}

static int
decode_gtp_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree) {

	proto_tree_add_text(tree, tvb, offset, 1, "Unknown extension header");

	return tvb_length_remaining(tvb, offset);
}

static void
dissect_gtp (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	struct _gtp_hdr	gtp_hdr;
	proto_tree	*gtp_tree, *flags_tree;
	proto_item	*ti, *tf;
	int		i, offset, length, gtp_prime, checked_field, mandatory;
	int		seq_no, flow_label;
	guint8		pdu_no, next_hdr = 0, ext_hdr_val;
	const guint8	*tid_val;
	gchar		*tid_str;
	guint32		teid;
	tvbuff_t	*next_tvb;
	guint8		sub_proto, acfield_len = 0, control_field;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "GTP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);
	
	tvb_memcpy(tvb, (guint8 *)&gtp_hdr, 0, 4);
	
	if (!(gtp_hdr.flags & 0x10))
		gtp_prime = 1;
	else
		gtp_prime = 0;
	
	switch ((gtp_hdr.flags >> 5) & 0x07) {
		case 0: 
			gtp_version = 0;
			break;
		case 1: 
			gtp_version = 1;
			break;
		default: 
			gtp_version = 1;
			break;
	}

	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(gtp_hdr.message, message_type, "Unknown"));
	
	if (tree) {
		ti = proto_tree_add_item (tree, proto_gtp, tvb, 0, -1, FALSE);
		gtp_tree = proto_item_add_subtree(ti, ett_gtp);
		
		tf = proto_tree_add_uint (gtp_tree, hf_gtp_flags, tvb, 0, 1, gtp_hdr.flags);
		flags_tree = proto_item_add_subtree (tf, ett_gtp_flags);
		
		proto_tree_add_uint (flags_tree, hf_gtp_flags_ver, tvb, 0, 1, gtp_hdr.flags);
		proto_tree_add_uint (flags_tree, hf_gtp_flags_pt, tvb, 0, 1, gtp_hdr.flags);
		
		switch (gtp_version) {
			case 0:
				proto_tree_add_uint (flags_tree, hf_gtp_flags_spare1, tvb, 0, 1, gtp_hdr.flags);
				proto_tree_add_boolean (flags_tree, hf_gtp_flags_snn, tvb, 0, 1, gtp_hdr.flags);
				break;
			case 1:
				proto_tree_add_uint (flags_tree, hf_gtp_flags_spare2, tvb, 0, 1, gtp_hdr.flags);
				proto_tree_add_boolean (flags_tree, hf_gtp_flags_e, tvb, 0, 1, gtp_hdr.flags);
				proto_tree_add_boolean (flags_tree, hf_gtp_flags_s, tvb, 0, 1, gtp_hdr.flags);
				proto_tree_add_boolean (flags_tree, hf_gtp_flags_pn, tvb, 0, 1, gtp_hdr.flags);
				break;
			default:
				break;
		}
				
		proto_tree_add_uint (gtp_tree, hf_gtp_message_type, tvb, 1, 1, gtp_hdr.message);
		
		gtp_hdr.length = g_ntohs (gtp_hdr.length);
		proto_tree_add_uint (gtp_tree, hf_gtp_length, tvb, 2, 2, gtp_hdr.length);
		
		offset = 4;
		
		if (gtp_prime) {
			seq_no = tvb_get_ntohs (tvb, offset);
			proto_tree_add_uint (gtp_tree, hf_gtp_seq_number, tvb, offset, 2, seq_no);
			offset += 2;
		} else
		switch (gtp_version) {
			case 0:
				seq_no = tvb_get_ntohs (tvb, offset);
				proto_tree_add_uint (gtp_tree, hf_gtp_seq_number, tvb, offset, 2, seq_no);
				offset += 2;
			
				flow_label = tvb_get_ntohs (tvb, offset);
				proto_tree_add_uint (gtp_tree, hf_gtp_flow_label, tvb, offset, 2, flow_label);
				offset += 2;
			
				pdu_no = tvb_get_guint8 (tvb, offset);
				proto_tree_add_uint (gtp_tree, hf_gtp_sndcp_number, tvb, offset, 1, pdu_no);
				offset += 4;
				
				tid_val = tvb_get_ptr(tvb, offset, 8);
				tid_str = id_to_str (tid_val);
				proto_tree_add_string (gtp_tree, hf_gtp_tid, tvb, offset, 8, tid_str);
				offset += 8;
				break;			
			case 1:
				teid = tvb_get_ntohl (tvb, offset);
				proto_tree_add_uint (gtp_tree, hf_gtp_teid, tvb, offset, 4, teid);
				offset += 4;

				if (gtp_hdr.flags & 0x07) {
					seq_no = tvb_get_ntohs (tvb, offset);
					proto_tree_add_uint (gtp_tree, hf_gtp_seq_number, tvb, offset, 2, seq_no);
					offset += 2;
					
					pdu_no = tvb_get_guint8 (tvb, offset);
					proto_tree_add_uint (gtp_tree, hf_gtp_npdu_number, tvb, offset, 1, pdu_no);
					offset++;
					
					next_hdr = tvb_get_guint8 (tvb, offset);
					proto_tree_add_uint (gtp_tree, hf_gtp_next, tvb, offset, 1, next_hdr);
					if (!next_hdr)
						offset++;
				}
				break;
			default:
				break;
		}
		
		
		if (gtp_hdr.message != GTP_MSG_TPDU) {
			proto_tree_add_text(gtp_tree, tvb, 0, 0, "[--- end of GTP header, beginning of extension headers ---]");
			length = tvb_length (tvb);
			mandatory = 0;		/* check order of GTP fields against ETSI */
			for (;;) {
				if (offset >= length) 
					break;
				if (next_hdr) {
					ext_hdr_val = next_hdr;
					next_hdr = 0;
				}
				else
					ext_hdr_val = tvb_get_guint8 (tvb, offset);
				if (gtp_etsi_order) {
					checked_field = check_field_presence (gtp_hdr.message, ext_hdr_val , (int *)&mandatory);
					switch (checked_field) {
						case -2: proto_tree_add_text (gtp_tree, tvb, 0, 0, "[WARNING] message not found");
							 break;
						case -1: proto_tree_add_text (gtp_tree, tvb, 0, 0, "[WARNING] field not present");
							 break;
						case 0:  break;
						default: proto_tree_add_text (gtp_tree, tvb, offset, 1, "[WARNING] wrong next field, should be: %s", val_to_str(checked_field, gtp_val, "Unknown extension field"));
							 break;
					}
				}

				i = -1;
				while (gtpopt[++i].optcode) 
					if (gtpopt[i].optcode == ext_hdr_val) 
						break;
				offset = offset + (*gtpopt[i].decode)(tvb, offset, pinfo, gtp_tree);
			}
		}
	}
	
	if ((gtp_hdr.message == GTP_MSG_TPDU) && gtp_tpdu) {

		if (gtp_prime)
			offset = 6;
		else
		if (gtp_version == 1) {
			if (gtp_hdr.flags & 0x07)  {
				offset = 11;
				if (tvb_get_guint8 (tvb, offset) == 0)
					offset++;
			}
			else 
				offset = 8;
		}
		else
			offset = 20;

		sub_proto = tvb_get_guint8 (tvb, offset);

		if ((sub_proto >= 0x45) &&  (sub_proto <= 0x4e)) {
			/* this is most likely an IPv4 packet
			 * we can exclude 0x40 - 0x44 because the minimum header size is 20 octets
			 * 0x4f is excluded because PPP protocol type "IPv6 header compression"
			 * with protocol field compression is more likely than a plain IPv4 packet with 60 octet header size */
			
			next_tvb = tvb_new_subset (tvb, offset, -1, -1);
			call_dissector(ip_handle, next_tvb, pinfo, tree);
			
		} else
                if ((sub_proto & 0xf0) == 0x60){
			/* this is most likely an IPv6 packet */
			next_tvb = tvb_new_subset (tvb, offset, -1, -1);
			call_dissector (ipv6_handle, next_tvb, pinfo, tree);
		} else {
			/* this seems to be a PPP packet */

			if (sub_proto == 0xff) {
				/* this might be an address field, even it shouldn't be here */
				control_field = tvb_get_guint8 (tvb, offset + 1);
				if (control_field == 0x03)
					/* now we are pretty sure that address and control field are mistakenly inserted -> ignore it for PPP dissection */
					acfield_len = 2;
			}

			next_tvb = tvb_new_subset (tvb, offset + acfield_len, -1, -1);
			call_dissector (ppp_handle, next_tvb, pinfo, tree);
		}

		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_append_str_gtp(pinfo->cinfo, COL_PROTOCOL, "GTP");
	}
}

static const true_false_string yes_no_tfs = {
	"yes" ,
	"no"
};

void
proto_register_gtp(void)
{
	static hf_register_info hf_gtp[] = {
		{ &hf_gtp_apn, { "APN", "gtp.apn", FT_STRING, BASE_DEC, NULL, 0, "Access Point Name", HFILL }},
		{ &hf_gtp_cause, { "Cause ", "gtp.cause", FT_UINT8, BASE_DEC, VALS(cause_type), 0, "Cause of operation", HFILL }},
		{ &hf_gtp_chrg_char, { "Charging characteristics", "gtp.chrg_char", FT_UINT16, BASE_DEC, NULL, 0, "Charging characteristics", HFILL }},
		{ &hf_gtp_chrg_char_s, { "Spare", "gtp.chrg_char_s", FT_UINT16, 	BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_S, "Spare", HFILL }},
		{ &hf_gtp_chrg_char_n, { "Normal charging", "gtp.chrg_char_n", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_N, "Normal charging", HFILL }},
		{ &hf_gtp_chrg_char_p, { "Prepaid charging", "gtp.chrg_char_p", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_P, "Prepaid charging", HFILL }},
		{ &hf_gtp_chrg_char_f, { "Flat rate charging", "gtp.chrg_char_f", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_F, "Flat rate charging", HFILL }},
		{ &hf_gtp_chrg_char_h, { "Hot billing charging", "gtp.chrg_char_h", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_H, "Hot billing charging", HFILL }},
		{ &hf_gtp_chrg_char_r, { "Reserved", "gtp.chrg_char_r", FT_UINT16, BASE_DEC, NULL, GTP_MASK_CHRG_CHAR_R, "Reserved", HFILL }},
		{ &hf_gtp_chrg_id, { "Charging ID", "gtp.chrg_id", FT_UINT32, BASE_HEX, NULL, 0, "Charging ID", HFILL }},
		{ &hf_gtp_chrg_ipv4, { "CG address IPv4", "gtp.chrg_ipv4", FT_IPv4, BASE_DEC, NULL, 0, "Charging Gateway address IPv4", HFILL }},
		{ &hf_gtp_chrg_ipv6, { "CG address IPv6", "gtp.chrg_ipv6", FT_IPv6, BASE_HEX, NULL, 0, "Charging Gateway address IPv6", HFILL }},
		{ &hf_gtp_ext_flow_label, { "Flow Label Data I", "gtp.ext_flow_label", FT_UINT16, BASE_HEX, NULL, 0, "Flow label data", HFILL }},
		{ &hf_gtp_ext_id, { "Extension identifier", "gtp.ext_id", FT_UINT16, BASE_DEC, NULL, 0, "Extension Identifier", HFILL }},
		{ &hf_gtp_ext_val, { "Extension value", "gtp.ext_val", FT_STRING, BASE_DEC, NULL, 0, "Extension Value", HFILL }},
		{ &hf_gtp_flags, { "Flags", "gtp.flags", FT_UINT8, BASE_HEX, NULL, 0, "Ver/PT/Spare...", HFILL }},
		{ &hf_gtp_flags_ver, 
			{ "Version", "gtp.flags.version", 
			FT_UINT8, BASE_DEC, VALS(ver_types), GTP_VER_MASK, 
			"GTP Version", HFILL }
		},
		{ &hf_gtp_flags_pt, 
			{ "Protocol type",	"gtp.flags.payload", 
			FT_UINT8, BASE_DEC, VALS(pt_types), GTP_PT_MASK,
			"Protocol Type", HFILL }
		},
		{ &hf_gtp_flags_spare1,
			{ "Reserved", "gtp.flags.reserved", 
			FT_UINT8, BASE_DEC, NULL, GTP_SPARE1_MASK, 
			"Reserved (shall be sent as '111' )", HFILL }
		},
		{ &hf_gtp_flags_snn, { "Is SNDCP N-PDU included?", "gtp.flags.snn", FT_BOOLEAN, 8, TFS(&yes_no_tfs), GTP_SNN_MASK, "Is SNDCP N-PDU LLC Number included? (1 = yes, 0 = no)", HFILL }},
		{ &hf_gtp_flags_spare2,	{ "Reserved", "gtp.flags.reserved", FT_UINT8, BASE_DEC, NULL, GTP_SPARE2_MASK, "Reserved (shall be sent as '1' )", HFILL }},
		{ &hf_gtp_flags_e, { "Is Next Extension Header present?", "gtp.flags.e", FT_BOOLEAN, 8, TFS(&yes_no_tfs), GTP_E_MASK, "Is Next Extension Header present? (1 = yes, 0 = no)", HFILL }},
		{ &hf_gtp_flags_s, { "Is Sequence Number present?", "gtp.flags.s", FT_BOOLEAN, 8, TFS(&yes_no_tfs), GTP_S_MASK, "Is Sequence Number present? (1 = yes, 0 = no)", HFILL }},
		{ &hf_gtp_flags_pn, { "Is N-PDU number present?", "gtp.flags.pn", FT_BOOLEAN, 8, TFS(&yes_no_tfs), GTP_PN_MASK, "Is N-PDU number present? (1 = yes, 0 = no)", HFILL }},
		{ &hf_gtp_flow_ii, { "Flow Label Data II ", "gtp.flow_ii", FT_UINT16, BASE_DEC, NULL, 0, "Downlink flow label data", HFILL }},
		{ &hf_gtp_flow_label, { "Flow label", "gtp.flow_label", FT_UINT16, BASE_HEX, NULL, 0, "Flow label", HFILL }},
		{ &hf_gtp_flow_sig, { "Flow label Signalling", "gtp.flow_sig", FT_UINT16, BASE_HEX, NULL, 0, "Flow label signalling", HFILL }},
		{ &hf_gtp_gsn_addr_len,	{ "GSN Address Length", "gtp.gsn_addr_len", FT_UINT8, BASE_DEC, NULL, GTP_EXT_GSN_ADDR_LEN_MASK, "GSN Address Length", HFILL }},
		{ &hf_gtp_gsn_addr_type, { "GSN Address Type", "gtp.gsn_addr_type", FT_UINT8, BASE_DEC, VALS(gsn_addr_type), GTP_EXT_GSN_ADDR_TYPE_MASK, "GSN Address Type", HFILL }},
		{ &hf_gtp_gsn_ipv4, { "GSN address IPv4", "gtp.gsn_ipv4", FT_IPv4, BASE_DEC, NULL, 0, "GSN address IPv4", HFILL }},
		{ &hf_gtp_gsn_ipv6, { "GSN address IPv6", "gtp.gsn_ipv6", FT_IPv6, BASE_DEC, NULL, 0, "GSN address IPv6", HFILL }},	
		{ &hf_gtp_imsi, { "IMSI", "gtp.imsi", FT_STRING, BASE_DEC, NULL, 0, "International Mobile Subscriber Identity number", HFILL }},
		{ &hf_gtp_length, { "Length", "gtp.length", FT_UINT16, BASE_DEC, NULL, 0, "Length (i.e. number of octets after TID or TEID)", HFILL }},
		{ &hf_gtp_map_cause, { "MAP cause", "gtp.map_cause", FT_UINT8, BASE_DEC, VALS(map_cause_type), 0, "MAP cause", HFILL }},
		{ &hf_gtp_message_type, { "Message Type", "gtp.message", FT_UINT8, BASE_HEX, VALS(message_type), 0x0, "GTP Message Type", HFILL }},
		{ &hf_gtp_ms_reason, { "MS not reachable reason", "gtp.ms_reason", FT_UINT8, BASE_DEC, VALS(ms_not_reachable_type), 0, "MS Not Reachable Reason", HFILL }},
		{ &hf_gtp_ms_valid, { "MS validated", "gtp.ms_valid", FT_BOOLEAN, BASE_NONE,NULL, 0, "MS validated", HFILL }},
		{ &hf_gtp_msisdn, { "MSISDN", "gtp.msisdn", FT_STRING, BASE_DEC, NULL, 0, "MS international PSTN/ISDN number", HFILL }},
		{ &hf_gtp_next, { "Next extension header type",	"gtp.next", FT_UINT8, BASE_HEX, NULL, 0, "Next Extension Header Type", HFILL }},
		{ &hf_gtp_node_ipv4, { "Node address IPv4", "gtp.node_ipv4", FT_IPv4, BASE_DEC, NULL, 0, "Recommended node address IPv4", HFILL }},
		{ &hf_gtp_node_ipv6, { "Node address IPv6", "gtp.node_ipv6", FT_IPv6, BASE_HEX, NULL, 0, "Recommended node address IPv6", HFILL }},
		{ &hf_gtp_npdu_number, { "N-PDU Number", "gtp.npdu_number", FT_UINT8, BASE_HEX, NULL, 0, "N-PDU Number", HFILL }},
		{ &hf_gtp_nsapi, { "NSAPI", "gtp.nsapi", FT_UINT8, BASE_DEC, NULL, 0, "Network layer Service Access Point Identifier", HFILL }},
		{ &hf_gtp_qos_version, { "Version", "gtp.qos_version", FT_STRING, BASE_DEC, NULL, 0, "Version of the QoS Profile", HFILL }},
		{ &hf_gtp_qos_spare1, { "Spare", "gtp.qos_spare1", FT_UINT8, BASE_DEC, NULL, GTP_EXT_QOS_SPARE1_MASK, "Spare (shall be sent as '00' )", HFILL }},
		{ &hf_gtp_qos_delay, { "QoS delay", "gtp.qos_delay", FT_UINT8, BASE_DEC, VALS(qos_delay_type), GTP_EXT_QOS_DELAY_MASK, "Quality of Service Delay Class", HFILL }},
		{ &hf_gtp_qos_reliability, { "QoS reliability", "gtp.qos_reliabilty", FT_UINT8, BASE_DEC, VALS(qos_reliability_type), GTP_EXT_QOS_RELIABILITY_MASK, "Quality of Service Reliability Class", HFILL }},
		{ &hf_gtp_qos_peak, { "QoS peak", "gtp.qos_peak", FT_UINT8, BASE_DEC, VALS(qos_peak_type), GTP_EXT_QOS_PEAK_MASK, "Quality of Service Peak Throughput", HFILL }},
		{ &hf_gtp_qos_spare2, { "Spare", "gtp.qos_spare2",FT_UINT8, BASE_DEC, NULL, GTP_EXT_QOS_SPARE2_MASK, "Spare (shall be sent as 0)", HFILL }},
		{ &hf_gtp_qos_precedence, { "QoS precedence", "gtp.qos_precedence", FT_UINT8, BASE_DEC, VALS(qos_precedence_type), GTP_EXT_QOS_PRECEDENCE_MASK, "Quality of Service Precedence Class", HFILL }},
		{ &hf_gtp_qos_spare3, { "Spare", "gtp.qos_spare3", FT_UINT8, BASE_DEC, NULL, GTP_EXT_QOS_SPARE3_MASK, "Spare (shall be sent as '000' )", HFILL }},
		{ &hf_gtp_qos_mean, { "QoS mean", "gtp.qos_mean", FT_UINT8, BASE_DEC, VALS(qos_mean_type), GTP_EXT_QOS_MEAN_MASK, "Quality of Service Mean Throughput", HFILL }},
		{ &hf_gtp_qos_al_ret_priority, { "Allocation/Retention priority ","gtp.qos_al_ret_priority", FT_UINT8, BASE_DEC, NULL, 0, "Allocation/Retention Priority", HFILL }},
		{ &hf_gtp_qos_traf_class, { "Traffic class", "gtp.qos_traf_class", FT_UINT8, BASE_DEC, VALS(qos_traf_class), GTP_EXT_QOS_TRAF_CLASS_MASK, "Traffic Class", HFILL }},
		{ &hf_gtp_qos_del_order, { "Delivery order", "gtp.qos_del_order", FT_UINT8, BASE_DEC, VALS(qos_del_order), GTP_EXT_QOS_DEL_ORDER_MASK, "Delivery Order", HFILL }},
		{ &hf_gtp_qos_del_err_sdu, { "Delivery of erroneous SDU", "gtp.qos_del_err_sdu", FT_UINT8, BASE_DEC, VALS(qos_del_err_sdu), GTP_EXT_QOS_DEL_ERR_SDU_MASK, "Delivery of Erroneous SDU", HFILL }},
		{ &hf_gtp_qos_max_sdu_size, { "Maximum SDU size", "gtp.qos_max_sdu_size", FT_UINT8, BASE_DEC, VALS(qos_max_sdu_size), 0, "Maximum SDU size", HFILL }},
		{ &hf_gtp_qos_max_ul, { "Maximum bit rate for uplink",	"gtp.qos_max_ul", FT_UINT8, BASE_DEC, VALS(qos_max_ul), 0, "Maximum bit rate for uplink", HFILL }},
		{ &hf_gtp_qos_max_dl, { "Maximum bit rate for downlink", "gtp.qos_max_dl", FT_UINT8, BASE_DEC, VALS(qos_max_dl), 0, "Maximum bit rate for downlink", HFILL }},
		{ &hf_gtp_qos_res_ber, { "Residual BER", "gtp.qos_res_ber", FT_UINT8, BASE_DEC, VALS(qos_res_ber), GTP_EXT_QOS_RES_BER_MASK, "Residual Bit Error Rate", HFILL }},
		{ &hf_gtp_qos_sdu_err_ratio, { "SDU Error ratio", "gtp.qos_sdu_err_ratio", FT_UINT8, BASE_DEC, VALS(qos_sdu_err_ratio), GTP_EXT_QOS_SDU_ERR_RATIO_MASK, "SDU Error Ratio", HFILL }},
		{ &hf_gtp_qos_trans_delay, { "Transfer delay",	"gtp.qos_trans_delay", FT_UINT8, BASE_DEC, VALS(qos_trans_delay), GTP_EXT_QOS_TRANS_DELAY_MASK, "Transfer Delay", HFILL }},
		{ &hf_gtp_qos_traf_handl_prio, { "Traffic handling priority", "gtp.qos_traf_handl_prio", FT_UINT8, BASE_DEC, VALS(qos_traf_handl_prio), GTP_EXT_QOS_TRAF_HANDL_PRIORITY_MASK, "Traffic Handling Priority", HFILL }},
		{ &hf_gtp_qos_guar_ul, { "Guaranteed bit rate for uplink", "gtp.qos_guar_ul", FT_UINT8,	BASE_DEC, VALS(qos_guar_ul), 0, "Guaranteed bit rate for uplink", HFILL }},
		{ &hf_gtp_qos_guar_dl, { "Guaranteed bit rate for downlink", "gtp.qos_guar_dl",	FT_UINT8, BASE_DEC, VALS(qos_guar_dl), 0, "Guaranteed bit rate for downlink", HFILL }},
		{ &hf_gtp_pkt_flow_id, { "Packet Flow ID", "gtp.pkt_flow_id", FT_UINT8, BASE_DEC, NULL, 0, "Packet Flow ID", HFILL }},
		{ &hf_gtp_ptmsi, { "P-TMSI", "gtp.ptmsi", FT_UINT32, BASE_HEX, NULL, 0, "Packet-Temporary Mobile Subscriber Identity", HFILL }},
		{ &hf_gtp_ptmsi_sig, { "P-TMSI Signature", "gtp.ptmsi_sig", FT_UINT24, BASE_HEX, NULL, 0, "P-TMSI Signature", HFILL }},
		{ &hf_gtp_rab_gtpu_dn, { "Downlink GTP-U seq number", "gtp.rab_gtp_dn", FT_UINT16, BASE_DEC, NULL, 0, "Downlink GTP-U sequence number", HFILL }},
		{ &hf_gtp_rab_gtpu_up, { "Uplink GTP-U seq number", "gtp.rab_gtp_up", FT_UINT16, BASE_DEC, NULL, 0, "Uplink GTP-U sequence number", HFILL }},
		{ &hf_gtp_rab_pdu_dn, { "Downlink next PDCP-PDU seq number", "gtp.rab_pdu_dn", FT_UINT8, BASE_DEC, NULL, 0, "Downlink next PDCP-PDU sequence number", HFILL }},
		{ &hf_gtp_rab_pdu_up, { "Uplink next PDCP-PDU seq number", "gtp.rab_pdu_up", FT_UINT8, BASE_DEC, NULL, 0, "Uplink next PDCP-PDU sequence number", HFILL }},
		{ &hf_gtp_rai_mcc, { "MCC", "gtp.mcc", FT_UINT16, BASE_DEC, NULL, 0, "Mobile Country Code", HFILL }},
		{ &hf_gtp_rai_mnc, { "MNC", "gtp.mnc", FT_UINT8, BASE_DEC, NULL, 0, "Mobile Network Code", HFILL }},
		{ &hf_gtp_rai_rac, { "RAC", "gtp.rac", FT_UINT8, BASE_DEC, NULL, 0, "Routing Area Code", HFILL }},
		{ &hf_gtp_rai_lac, { "LAC", "gtp.lac", FT_UINT16, BASE_DEC, NULL, 0, "Location Area Code", HFILL }},
		{ &hf_gtp_ranap_cause, { "RANAP cause", "gtp.ranap_cause", FT_UINT8, BASE_DEC, VALS(ranap_cause_type), 0, "RANAP cause", HFILL }},
		{ &hf_gtp_recovery, { "Recovery", "gtp.recovery", FT_UINT8, BASE_DEC, NULL, 0, "Restart counter", HFILL }},
		{ &hf_gtp_reorder, { "Reordering required","gtp.reorder", FT_BOOLEAN, BASE_NONE,NULL, 0, "Reordering required", HFILL }},
		{ &hf_gtp_rnc_ipv4, { "RNC address IPv4", "gtp.rnc_ipv4", FT_IPv4, BASE_DEC, NULL, 0, "Radio Network Controller address IPv4", HFILL }},
		{ &hf_gtp_rnc_ipv6, { "RNC address IPv6", "gtp.rnc_ipv6", FT_IPv6, BASE_HEX, NULL, 0, "Radio Network Controller address IPv6", HFILL }},
		{ &hf_gtp_rp, { "Radio Priority", "gtp.rp", FT_UINT8, BASE_DEC, NULL, GTPv1_EXT_RP_MASK, "Radio Priority for uplink tx", HFILL }},
		{ &hf_gtp_rp_nsapi, { "NSAPI in Radio Priority", "gtp.rp_nsapi", FT_UINT8, BASE_DEC, NULL, GTPv1_EXT_RP_NSAPI_MASK, "Network layer Service Access Point Identifier in Radio Priority", HFILL }},
		{ &hf_gtp_rp_sms, { "Radio Priority SMS", "gtp.rp_sms",	FT_UINT8, BASE_DEC, NULL, 0, "Radio Priority for MO SMS", HFILL }},
		{ &hf_gtp_rp_spare, { "Reserved", "gtp.rp_spare", FT_UINT8, BASE_DEC, NULL, GTPv1_EXT_RP_SPARE_MASK, "Spare bit", HFILL }},		
		{ &hf_gtp_sel_mode, { "Selection mode", "gtp.sel_mode", FT_UINT8, BASE_DEC, VALS(sel_mode_type), 0, "Selection Mode", HFILL }},
		{ &hf_gtp_seq_number, { "Sequence number", "gtp.seq_number", FT_UINT16, BASE_HEX, NULL, 0, "Sequence Number", HFILL }},
		{ &hf_gtp_sndcp_number, { "SNDCP N-PDU LLC Number", "gtp.sndcp_number", FT_UINT8, BASE_HEX, NULL, 0, "SNDCP N-PDU LLC Number", HFILL }},
		{ &hf_gtp_tear_ind, { "Teardown Indicator", "gtp.tear_ind", FT_BOOLEAN, BASE_NONE,NULL, 0, "Teardown Indicator", HFILL }},
		{ &hf_gtp_teid, { "TEID", "gtp.teid", FT_UINT32, BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier", HFILL }},
		{ &hf_gtp_teid_cp, { "TEID Control Plane", "gtp.teid_cp", FT_UINT32, BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier Control Plane", HFILL }},
		{ &hf_gtp_teid_data, { "TEID Data I", "gtp.teid_data", FT_UINT32, BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier Data I", HFILL }},
		{ &hf_gtp_teid_ii, { "TEID Data II", "gtp.teid_ii", FT_UINT32, BASE_HEX, NULL, 0, "Tunnel Endpoint Identifier Data II", HFILL }},
		{ &hf_gtp_tft_code, { "TFT operation code", "gtp.tft_code", FT_UINT8, BASE_DEC, VALS (tft_code_type), GTPv1_TFT_CODE_MASK, "TFT operation code", HFILL }},
		{ &hf_gtp_tft_spare, { "TFT spare bit",	"gtp.tft_spare", FT_UINT8, BASE_DEC, NULL, GTPv1_TFT_SPARE_MASK, "TFT spare bit", HFILL }},
		{ &hf_gtp_tft_number, { "Number of packet filters", "gtp.tft_number", FT_UINT8, BASE_DEC, NULL, GTPv1_TFT_NUMBER_MASK, "Number of packet filters", HFILL }},
		{ &hf_gtp_tft_eval, { "Evaluation precedence", "gtp.tft_eval", FT_UINT8, BASE_DEC, NULL, 0, "Evaluation precedence", HFILL }},
		{ &hf_gtp_tid, { "TID", "gtp.tid", FT_STRING, BASE_DEC, NULL, 0, "Tunnel Identifier", HFILL }},
		{ &hf_gtp_tlli, { "TLLI", "gtp.tlli", FT_UINT32, BASE_HEX, NULL, 0, "Temporary Logical Link Identity", HFILL }},
		{ &hf_gtp_tr_comm, { "Packet transfer command",	"gtp.tr_comm", FT_UINT8, BASE_DEC, VALS (tr_comm_type), 0, "Packat transfer command", HFILL }},
		{ &hf_gtp_trace_ref, { "Trace reference", "gtp.trace_ref", FT_UINT16, BASE_HEX, NULL, 0, "Trace reference", HFILL }},
		{ &hf_gtp_trace_type, { "Trace type", "gtp.trace_type", FT_UINT16, BASE_HEX, NULL, 0, "Trace type", HFILL }},
		{ &hf_gtp_unknown, { "Unknown data (length)",	"gtp.unknown", FT_UINT16, BASE_DEC, NULL, 0, "Unknown data", HFILL }},
		{ &hf_gtp_user_addr_pdp_org, { "PDP type organization", "gtp.user_addr_pdp_org", FT_UINT8, BASE_DEC, VALS(pdp_org_type), 0, "PDP type organization", HFILL }},
		{ &hf_gtp_user_addr_pdp_type, { "PDP type number", "gtp.user_addr_pdp_type", FT_UINT8, BASE_HEX, VALS (pdp_type), 0, "PDP type", HFILL }},
		{ &hf_gtp_user_ipv4, { "End user address IPv4", "gtp.user_ipv4", FT_IPv4, BASE_DEC, NULL, 0, "End user address IPv4", HFILL }},
		{ &hf_gtp_user_ipv6, { "End user address IPv6", "gtp.user_ipv6", FT_IPv6, BASE_HEX, NULL, 0, "End user address IPv6", HFILL }},		
		{ &hf_gtp_security_mode, 
			{ "Security Mode", "gtp.security_mode", 
			FT_UINT8, BASE_DEC, VALS(mm_sec_modep), 0xc0, 
			"Security Mode", HFILL }
		},
		{ &hf_gtp_no_of_vectors,
			{ "No of Vectors", "gtp.no_of_vectors", 
			FT_UINT8, BASE_DEC, NULL, 0x38, 
			"No of Vectors", HFILL }
		},
		{ &hf_gtp_cipher_algorithm,
			{ "Cipher Algorithm", "gtp.no_of_vectors", 
			FT_UINT8, BASE_DEC, VALS(gtp_cipher_algorithm), 0x07, 
			"Cipher Algorithm", HFILL }
		},
		{ &hf_gtp_cksn_ksi,
			{ "Ciphering Key Sequence Number (CKSN)/Key Set Identifier (KSI)", "gtp.cksn_ksi", 
			FT_UINT8, BASE_DEC, NULL, 0x07, 
			"CKSN/KSI", HFILL }
		},
		{ &hf_gtp_cksn,
			{ "Ciphering Key Sequence Number (CKSN)", "gtp.cksn_ksi", 
			FT_UINT8, BASE_DEC, NULL, 0x07, 
			"CKSN", HFILL }
		},
		{ &hf_gtp_ksi,
			{ "Key Set Identifier (KSI)", "gtp.cksn_ksi", 
			FT_UINT8, BASE_DEC, NULL, 0x07, 
			"KSI", HFILL }
		},
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
		&ett_gtp_tft_flags,
		&ett_gtp_rab_setup,
		&ett_gtp_hdr_list,
		&ett_gtp_chrg_addr,
		&ett_gtp_node_addr,
		&ett_gtp_rel_pack,
		&ett_gtp_can_pack,
		&ett_gtp_data_resp,
		&ett_gtp_priv_ext,
		&ett_gtp_net_cap,
	};

	module_t	*gtp_module;

	proto_gtp = proto_register_protocol ("GPRS Tunneling Protocol", "GTP", "gtp");
	proto_register_field_array (proto_gtp, hf_gtp, array_length (hf_gtp));
	proto_register_subtree_array (ett_gtp_array, array_length (ett_gtp_array));
	
	gtp_module = prefs_register_protocol(proto_gtp, proto_reg_handoff_gtp);

	prefs_register_uint_preference(gtp_module, "v0_port", "GTPv0 port", "GTPv0 port (default 3386)", 10, &g_gtpv0_port);
	prefs_register_uint_preference(gtp_module, "v1c_port", "GTPv1 control plane (GTP-C) port", "GTPv1 control plane port (default 2123)", 10, &g_gtpv1c_port);
	prefs_register_uint_preference(gtp_module, "v1u_port", "GTPv1 user plane (GTP-U) port", "GTPv1 user plane port (default 2152)", 10, &g_gtpv1u_port);
	prefs_register_bool_preference(gtp_module, "dissect_tpdu", "Dissect T-PDU", "Dissect T-PDU", &gtp_tpdu);
	
	prefs_register_obsolete_preference (gtp_module, "v0_dissect_cdr_as");
	prefs_register_obsolete_preference (gtp_module, "v0_check_etsi");
	prefs_register_obsolete_preference (gtp_module, "v1_check_etsi");
	prefs_register_bool_preference (gtp_module, "check_etsi", "Compare GTP order with ETSI", "GTP ETSI order", &gtp_etsi_order);
	prefs_register_obsolete_preference(gtp_module, "ppp_reorder");
	
	/* This preference can be used to disable the dissection of GTP over TCP. Most of the Wireless operators uses GTP over UDP.
		 * The preference is set to TRUE by default forbackward compatibility
		 */
	prefs_register_bool_preference(gtp_module, "dissect_gtp_over_tcp", "Dissect GTP over TCP", "Dissect GTP over TCP", &gtp_over_tcp);

	register_dissector("gtp", dissect_gtp, proto_gtp);
}

void
proto_reg_handoff_gtp(void)
{
	static int Initialized = FALSE;
	static dissector_handle_t gtp_handle;

	
	if (!Initialized) {
		gtp_handle = find_dissector("gtp");
		ppp_subdissector_table = find_dissector_table("ppp.protocol");
		
		radius_register_avp_dissector(10415,5,dissect_radius_qos_umts);

		Initialized = TRUE;
	} else {
		dissector_delete ("udp.port", gtpv0_port, gtp_handle);
		dissector_delete ("udp.port", gtpv1c_port, gtp_handle);
		dissector_delete ("udp.port", gtpv1u_port, gtp_handle);
		
		if ( !gtp_over_tcp ) {
			dissector_delete ("tcp.port", gtpv0_port, gtp_handle);
			dissector_delete ("tcp.port", gtpv1c_port, gtp_handle);
			dissector_delete ("tcp.port", gtpv1u_port, gtp_handle);
		}
		
	}

	gtpv0_port = g_gtpv0_port;
	gtpv1c_port = g_gtpv1c_port;
	gtpv1u_port = g_gtpv1u_port;

	dissector_add ("udp.port", g_gtpv0_port, gtp_handle);
	dissector_add ("udp.port", g_gtpv1c_port, gtp_handle);
	dissector_add ("udp.port", g_gtpv1u_port, gtp_handle);

	
	if ( gtp_over_tcp ) {
		dissector_add ("tcp.port", g_gtpv0_port, gtp_handle);
		dissector_add ("tcp.port", g_gtpv1c_port, gtp_handle);
		dissector_add ("tcp.port", g_gtpv1u_port, gtp_handle);
	}
	
	ip_handle = find_dissector("ip");
	ipv6_handle = find_dissector("ipv6");
	ppp_handle = find_dissector("ppp");
	data_handle = find_dissector("data");
	gtpcdr_handle = find_dissector("gtpcdr");
	bssap_pdu_type_table = find_dissector_table("bssap.pdu_type");

}
