/* packet-gtp.c
 * Routines for GTP dissection
 * Copyright 2001, Michal Melerowicz <michal.melerowicz@nokia.com>
 *
 * $Id: packet-gtp.c,v 1.3 2001/04/10 19:10:09 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#include "packet.h"
#include "packet-ip.h"
#include "packet-ipv6.h"

#define UDP_PORT_GTP 3386
#define TCP_PORT_GTP 3386
#define UDP_PORT_GTP3C 2123		/* 3G Control PDU */
#define UDP_PORT_GTP3U 2152		/* 3G T-PDU */
#define TCP_PORT_GTP3C 2123		/* 3G Control PDU */
#define TCP_PORT_GTP3U 2152		/* 3G T-PDU */

#define GTP_HDR_LENGTH 20
#define GTP3_HDR_LENGTH 11

/* Initialize the protocol and registered fields */
static int proto_gtp			= -1;
static int hf_gtp_flags			= -1;
static int hf_gtp_flags_ver		= -1;
static int hf_gtp_flags_pt		= -1;
static int hf_gtp_flags_spare		= -1;
static int hf_gtp_flags_snn		= -1;
static int hf_gtp_message_type		= -1;
static int hf_gtp_length		= -1;
static int hf_gtp_seq_number		= -1;
static int hf_gtp_flow_label		= -1;
static int hf_gtp_sndcp_number		= -1;
static int hf_gtp_tid			= -1;
static int hf_gtp_ext			= -1;

static int hf_gtp_ext_cause		= -1;
static int hf_gtp_ext_imsi		= -1;
static int hf_gtp_ext_rai_mcc		= -1;
static int hf_gtp_ext_rai_mnc		= -1;
static int hf_gtp_ext_rai_rac		= -1;
static int hf_gtp_ext_rai_lac		= -1;
static int hf_gtp_ext_tlli		= -1;
static int hf_gtp_ext_ptmsi		= -1;
static int hf_gtp_ext_qos_delay		= -1;
static int hf_gtp_ext_qos_mean		= -1;
static int hf_gtp_ext_qos_peak		= -1;
static int hf_gtp_ext_qos_precedence	= -1;
static int hf_gtp_ext_qos_reliability	= -1;
static int hf_gtp_ext_reorder		= -1;
/*static int hf_gtp_ext_auth_rand	= -1;
static int hf_gtp_ext_auth_sres		= -1;
static int hf_gtp_ext_auth_kc		= -1;*/
static int hf_gtp_ext_map		= -1;
static int hf_gtp_ext_ptmsi_sig		= -1;
static int hf_gtp_ext_ms		= -1;
static int hf_gtp_ext_recover		= -1;
static int hf_gtp_ext_sel_mode		= -1;
static int hf_gtp_ext_flow_label	= -1;
static int hf_gtp_ext_flow_sig		= -1;
static int hf_gtp_ext_flow_ii_nsapi	= -1;
static int hf_gtp_ext_flow_ii		= -1;
static int hf_gtp_ext_tr_comm		= -1;
static int hf_gtp_ext_chrg_id		= -1;
static int hf_gtp_ext_user_addr		= -1;
static int hf_gtp_ext_user_addr_pdp_type	= -1;
static int hf_gtp_ext_user_addr_pdp_org	= -1;
static int hf_gtp_ext_apn		= -1;
static int hf_gtp_ext_proto_conf	= -1;
static int hf_gtp_ext_gsn_addr		= -1;
static int hf_gtp_ext_msisdn		= -1;
static int hf_gtp_ext_chrg_addr		= -1;
static int hf_gtp_ext_node_addr		= -1;
static int hf_gtp_ext_ext_id		= -1;
static int hf_gtp_ext_ext_val		= -1;

static int hf_gtp_ext_unknown		= -1;

/*static int gf_gtp_chrg_cap_gea	= -1;
static int gf_gtp_chrg_cap_sm_gsm	= -1;
static int gf_gtp_chrg_cap_sm_gprs	= -1;
static int gf_gtp_chrg_cap_ucs2		= -1;
static int gf_gtp_chrg_cap_ss		= -1;
static int gf_gtp_chrg_cap_solsa	= -1;
*/

/* Initialize the subtree pointers */
static gint ett_gtp			= -1;
static gint ett_gtp_flags		= -1;
static gint ett_gtp_ext			= -1;
static gint ett_gtp_qos			= -1;

#define GTP_VER_MASK 0xE0

static const value_string ver_types[] = {
	{ 0, "GTP version 1" },
	{ 1, "GTP 3G" },
	{ 2, "None" },
	{ 3, "None" },
	{ 4, "None" },
	{ 5, "None" },
	{ 6, "None" },
	{ 7, "None" },
	{ 0, NULL }
};

#define GTP_PT_MASK		0x10
#define GTP_SPARE_MASK	0x0E
#define GTP_SNN_MASK	0x01

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
#define GTP_MSG_CREATE_AA_PDP_REQ	0x16
#define GTP_MSG_CREATE_AA_PDP_RESP	0x17
#define GTP_MSG_DELETE_AA_PDP_REQ	0x18
#define GTP_MSG_DELETE_AA_PDP_RESP	0x19
#define GTP_MSG_ERR_IND			0x1A
#define GTP_MSG_PDU_NOTIFY_REQ		0x1B
#define GTP_MSG_PDU_NOTIFY_RESP		0x1C
#define GTP_MSG_PDU_NOTIFY_REJ_REQ	0x1D
#define GTP_MSG_PDU_NOTIFY_REJ_RESP	0x1E
#define GTP_MSG_SUPP_EXT_HDR_NOT	0x1F
#define GTP_MSG_SEND_ROUT_INFO_REQ	0x20
#define GTP_MSG_SEND_ROUT_INFO_RESP	0x21
#define GTP_MSG_FAIL_REP_REQ		0x22
#define GTP_MSG_FAIL_REP_RESP		0x23
#define GTP_MSG_MS_PRESENT_REQ		0x24
#define GTP_MSG_MS_PRESENT_RESP		0x25
#define GTP_MSG_IDENT_REQ		0x30
#define GTP_MSG_IDENT_RESP		0x31
#define GTP_MSG_SGSN_CNTX_REQ		0x32
#define GTP_MSG_SGSN_CNTX_RESP		0x33
#define GTP_MSG_SGSN_CNTX_ACK		0x34
#define GTP_MSG_FORW_RELOC_REQ		0x35
#define GTP_MSG_FORW_RELOC_RESP		0x36
#define GTP_MSG_FORW_RELOC_COMP		0x37
#define GTP_MSG_RELOC_CANCEL_REQ	0x38
#define GTP_MSG_RELOC_CANCEL_RESP	0x39
#define GTP_MSG_FORW_SRNS_CNTX		0x3A
#define GTP_MSG_FORW_RELOC_ACK		0x3B
#define GTP_MSG_FORW_SRNS_CNTX_ACK	0x3C
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
	{ GTP_MSG_DELETE_PDP_RESP,	"Delete PDP context respone" },
	{ GTP_MSG_CREATE_AA_PDP_REQ,	"Create AA PDP Context Request" },
	{ GTP_MSG_CREATE_AA_PDP_RESP,	"Create AA PDP Context Response" },
	{ GTP_MSG_DELETE_AA_PDP_REQ,	"Delete AA PDP Context Request" },
	{ GTP_MSG_DELETE_AA_PDP_RESP,	"Delete AA PDP Context Response" },
	{ GTP_MSG_ERR_IND,		"Error indication" },
	{ GTP_MSG_PDU_NOTIFY_REQ,	"PDU notification request" },
	{ GTP_MSG_PDU_NOTIFY_RESP,	"PDU notification response" },
	{ GTP_MSG_PDU_NOTIFY_REJ_REQ,	"PDU notification reject request" },
	{ GTP_MSG_PDU_NOTIFY_REJ_RESP,	"PDU notification reject response" },
	{ GTP_MSG_SUPP_EXT_HDR_NOT,	"Supported extension header notification" },
	{ GTP_MSG_SEND_ROUT_INFO_REQ,	"Send routing information for GPRS request" },
	{ GTP_MSG_SEND_ROUT_INFO_RESP,	"Send routing information for GPRS response" },
	{ GTP_MSG_FAIL_REP_REQ,		"Failure report request" },
	{ GTP_MSG_FAIL_REP_RESP,	"Failure report response" },
	{ GTP_MSG_MS_PRESENT_REQ,	"Note MS GPRS present request" },
	{ GTP_MSG_MS_PRESENT_RESP,	"Note MS GPRS present response" },
	{ GTP_MSG_IDENT_REQ,		"Identification request" },
	{ GTP_MSG_IDENT_RESP,		"Identification response" },
	{ GTP_MSG_SGSN_CNTX_REQ,	"SGSN context request" },
	{ GTP_MSG_SGSN_CNTX_RESP,	"SGSN context response" },
	{ GTP_MSG_SGSN_CNTX_ACK,	"SGSN context acknowledgement" },
	{ GTP_MSG_FORW_RELOC_REQ,	"Forward relocation request" },
	{ GTP_MSG_FORW_RELOC_RESP,	"Forward relocation response" },
	{ GTP_MSG_FORW_RELOC_COMP,	"Forward relocation complete" },
	{ GTP_MSG_RELOC_CANCEL_REQ,	"Relocation cancel request" },
	{ GTP_MSG_RELOC_CANCEL_RESP,	"Relocation cancel response" },
	{ GTP_MSG_FORW_SRNS_CNTX,	"Forward SRNS context" },
	{ GTP_MSG_FORW_RELOC_ACK,	"Forward relocation complete acknowledge" },
	{ GTP_MSG_FORW_SRNS_CNTX_ACK,	"Forward SRNS context acknowledge" },
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
#define GTP_EXT_QOS		0x06
#define GTP_EXT_REORDER		0x08
#define GTP_EXT_AUTH		0x09
#define GTP_EXT_MAP		0x0B
#define GTP_EXT_PTMSI_SIG	0x0C
#define GTP_EXT_MS		0x0D
#define GTP_EXT_RECOVER		0x0E
#define GTP_EXT_SEL_MODE	0x0F
#define	GTP_EXT_FLOW_LABEL	0x10	/* for 3G Tunnel Endpoint Id Data I */
#define GTP_EXT_FLOW_SIG	0x11	/* for 3G Tunnel Endpoint Id Control Plane */
#define GTP_EXT_FLOW_II		0x12	/* for 3G Tunnel Endpoint Id Data II */
#define GTP_EXT_TEARDOWN	0x13	/* 3G */
#define GTP_EXT_NSAPI		0x14	/* 3G */
#define GTP_EXT_RANAP_CAUSE	0x15	/* 3G */
#define GTP_EXT_RAB_CNTX	0x16	/* 3G */
#define GTP_EXT_RP_SMS		0x17	/* 3G */
#define GTP_EXT_RP		0x18	/* 3G */
#define GTP_EXT_PKT_FLOW_ID	0x19	/* 3G */
#define GTP_EXT_CHRG_CHAR	0x1A	/* 3G */
#define GTP_EXT_TRACE_REF	0x1B	/* 3G */
#define GTP_EXT_TRACE_TYPE	0x1C	/* 3G */
#define GTP_EXT_MS_REASON	0x1D	/* 3G */
#define GTP_EXT_TR_COMM		0x7E	/* charging */
#define GTP_EXT_CHRG_ID		0x7F
#define GTP_EXT_USER_ADDR	0x80
#define GTP_EXT_MM_CNTX		0x81
#define GTP_EXT_PDP_CNTX	0x82
#define GTP_EXT_APN		0x83
#define GTP_EXT_PROTO_CONF	0x84
#define GTP_EXT_GSN_ADDR	0x85
#define GTP_EXT_MSISDN		0x86
#define GTP_EXT_QOS_PROF	0x87	/* 3G */
#define GTP_EXT_AUTH_QUI	0x88	/* 3G */
#define GTP_EXT_TRAF_FLOW	0x89	/* 3G */
#define GTP_EXT_TARGET_ID	0x8A	/* 3G */
#define GTP_EXT_UTRAN_CONT	0x8B	/* 3G */
#define GTP_EXT_RAB_SETUP	0x8C	/* 3G */
#define GTP_EXT_HDR_LIST	0x8D	/* 3G */
#define GTP_EXT_TRIGGER_ID	0x8E	/* 3G */
#define GTP_EXT_OMC_IDEN	0x8F	/* 3G */
#define GTP_EXT_REL_PACK	0xF9	/* charging */
#define GTP_EXT_CANC_PACK	0xFA	/* charging */
#define GTP_EXT_CHRG_ADDR	0xFB
#define GTP_EXT_DATA_REC	0xFC	/* charging */
#define GTP_EXT_REQ_RESP	0xFD	/* charging */
#define GTP_EXT_NODE_ADDR	0xFE	/* charging */
#define GTP_EXT_PRIV_EXT	0xFF

static const value_string gtp_ext_val[] = {
	{ GTP_EXT_CAUSE,	"Cause of operation" },
	{ GTP_EXT_IMSI,		"IMSI" },
	{ GTP_EXT_RAI,		"Routeing Area Identity" },
	{ GTP_EXT_TLLI,		"Temporary Logical Link Identity" },
	{ GTP_EXT_PTMSI,	"Packet TMSI" },
	{ GTP_EXT_QOS,		"Quality of Service" },
	{ GTP_EXT_REORDER,	"Reorder required" },
	{ GTP_EXT_AUTH,		"Authentication triplets" },
	{ GTP_EXT_MAP,		"MAP cause" },
	{ GTP_EXT_PTMSI_SIG,	"P-TMSI signature" },
	{ GTP_EXT_MS,		"MS validated" },
	{ GTP_EXT_RECOVER,	"Recovery" },
	{ GTP_EXT_SEL_MODE,	"Selection mode" },
	{ GTP_EXT_FLOW_LABEL,	"Flow label data I" },
	{ GTP_EXT_FLOW_SIG,	"Flow label signalling" },
	{ GTP_EXT_FLOW_II,	"Flow label data II" },
	{ GTP_EXT_TR_COMM,	"Packet transfer command" },
	{ GTP_EXT_CHRG_ID,	"Charging ID" },
	{ GTP_EXT_USER_ADDR,	"End user address" },
	{ GTP_EXT_MM_CNTX,	"MM context" },
	{ GTP_EXT_PDP_CNTX,	"PDP context" },
	{ GTP_EXT_APN,		"Access point name" },
	{ GTP_EXT_PROTO_CONF,	"Protocol configuration options" },
	{ GTP_EXT_GSN_ADDR,	"GSN address" },
	{ GTP_EXT_MSISDN,	"MS international PSTN/ISDN number" },
	{ GTP_EXT_CHRG_ADDR,	"Charging gateway address" },
	{ GTP_EXT_DATA_REC,	"Data record packet" },
	{ GTP_EXT_NODE_ADDR,	"Address of recommended node" },
	{ GTP_EXT_PRIV_EXT, 	"Private extension" },
	{ 0, NULL }
};

static const value_string cause_type[] = {
	{ 0,	"Request IMSI" },
	{ 1,	"Request IMEI" },
	{ 2,	"Request IMSI and IMEI" },
	{ 3,	"No identity needed" },
	{ 4,	"MS refuses" },
	{ 5,	"MS is not GPRS responding" },
	{ 59,	"System failure" },							/* charging */
	{ 60,	"The transmit buffers are becoming full" },	/* charging */
	{ 61,	"The receive buffers are becoming full" },	/* charging */
	{ 62,	"Another node is about to go down" },		/* charging */
	{ 63,	"This node is about to go down" },			/* charging */
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
	{ 252,	"Request related to possibly duplicated packets already fulfilled" },	/* charging */
	{ 253,	"Request already fulfilled" },											/* charging */
	{ 254,	"Sequence numbers of released/cancelled packets IE incorrect" },		/* charging */
	{ 255,	"Request not fulfilled" },												/* charging */
	{ 0, NULL }
};
static const value_string map_cause_type[] = {
	{ 1, "Unknown subscriber" },
	{ 17, "User busy" },
	{ 18, "Absent subscriber" },
	{ 21, "Call barred/Forwarding violation" },
	{ 22, "Number changed" },
	{ 55, "CUG Reject" },
	{ 57, "Teleservice/Bearer Service not provisioned" },
	{ 69, "Facility not supported" },
	{ 111, "Data missing/Unexpected data value/System failure" },
	{ 0, NULL }
};

static const value_string pdp_type[] = {
	{ 0x00, "X.25" },
	{ 0x01, "PPP" },
	{ 0x02, "OSP:IHOSS" },
	{ 0x21, "IPv4" },
	{ 0x57, "IPv6" },
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
	{ 0x0F, "Reserved" },
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
	{ 0x01, "100 oct/h" },
	{ 0x02, "200 oct/h" },
	{ 0x03, "500 oct/h" },
	{ 0x04, "1 000 oct/h" },
	{ 0x05, "2 000 oct/h" },
	{ 0x06, "5 000 oct/h" },
	{ 0x07, "10 000 oct/h" },
	{ 0x08, "20 000 oct/h" },
	{ 0x09, "50 000 oct/h" },
	{ 0x0A, "100 000 oct/h" },
	{ 0x0B, "200 000 oct/h" },
	{ 0x0C, "500 000 oct/h" },
	{ 0x0D, "1 000 000 oct/h" },
	{ 0x0E, "2 000 000 oct/h" },
	{ 0x0F, "5 000 000 oct/h" },
	{ 0x10, "10 000 000 oct/h" },
	{ 0x11, "20 000 000 oct/h" },
	{ 0x12, "50 000 000 oct/h" },
	{ 0x1E, "Reserved" },
	{ 0x1F, "Best effort" },
	{ 0, NULL },
};

static const value_string sel_mode_type[] = {
	{ 0,	"MS or network provided APN, subscriber verified" },
	{ 1,	"MS provided APN, subscription not verified" },
	{ 2,	"Network provided APN, subscription not verified" },
	{ 3,	"For future use (Network provided APN, subscription not verified" },
	{ 0, 	NULL }
};
	
static const value_string tr_comm_type[] = {
	{ 1,	"Send data record packet" },
	{ 2,	"Send possibly duplicated data record packet" },
	{ 3,	"Cancel data record packet" },
	{ 4,	"Release data record packet"},
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

			
static dissector_handle_t ip_handle;
static dissector_handle_t ppp_handle;

static int decode_gtp_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_imsi(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_rai(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_tlli(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_ptmsi(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_qos(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_reorder(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_auth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_map(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_ptmsi_sig(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_ms(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_recover(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_sel_mode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_flow_label(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_flow_sig(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_flow_ii(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_tr_comm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_chrg_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_user_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_mm_cntx(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_pdp_cntx(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_apn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_gsn_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_proto_conf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static void free_tvb_data(void *tvb_data);
static int decode_gtp_msisdn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_chrg_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_data_rec(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_node_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_priv_ext(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int decode_gtp_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);

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
	{ GTP_EXT_QOS,		decode_gtp_qos },
	{ GTP_EXT_REORDER,	decode_gtp_reorder },
	{ GTP_EXT_AUTH,		decode_gtp_auth },
	{ GTP_EXT_MAP,		decode_gtp_map },
	{ GTP_EXT_PTMSI_SIG,decode_gtp_ptmsi_sig },
	{ GTP_EXT_MS,		decode_gtp_ms },
	{ GTP_EXT_RECOVER,	decode_gtp_recover },
	{ GTP_EXT_SEL_MODE,	decode_gtp_sel_mode },
	{ GTP_EXT_FLOW_LABEL,decode_gtp_flow_label },
	{ GTP_EXT_FLOW_SIG, decode_gtp_flow_sig },
	{ GTP_EXT_FLOW_II,	decode_gtp_flow_ii },
	{ GTP_EXT_TR_COMM,	decode_gtp_tr_comm },
	{ GTP_EXT_CHRG_ID,	decode_gtp_chrg_id },
	{ GTP_EXT_USER_ADDR,decode_gtp_user_addr },
	{ GTP_EXT_MM_CNTX,	decode_gtp_mm_cntx },
	{ GTP_EXT_PDP_CNTX,	decode_gtp_pdp_cntx },
	{ GTP_EXT_APN,		decode_gtp_apn },
	{ GTP_EXT_PROTO_CONF,decode_gtp_proto_conf },
	{ GTP_EXT_GSN_ADDR,	decode_gtp_gsn_addr },
	{ GTP_EXT_MSISDN,	decode_gtp_msisdn },
	{ GTP_EXT_CHRG_ADDR,decode_gtp_chrg_addr },
	{ GTP_EXT_DATA_REC, decode_gtp_data_rec },
	{ GTP_EXT_NODE_ADDR,decode_gtp_node_addr },
	{ GTP_EXT_PRIV_EXT, decode_gtp_priv_ext },
	{ 0, decode_gtp_unknown}
};

typedef struct _pdp {
	guint8		nsapi;
	guint8		sapi;
	guint8		qos_sub[3];
	guint8		qos_req[3];
	guint8		qos_neg[3];
	guint16		sn_down;
	guint16		sn_up;
	guint8		pdu_send_no;
	guint8		pdu_rec_no;
	guint16		up_flow;
	guint8		pdp_org;
	guint8		pdp_type;
	guint8		pdp_addr_len;
}	pdp_t;

struct _gtp_hdr {
	guint8		flags;
	guint8		message;
	guint16		length;
	guint16		seq_no;
	guint16		flow_label;
	guint8		npdu_no;
	guint8		spare[3];
	guint8		tid[8];
} gtp;

struct _gtp3_hdr {
	guint8		flags;
	guint8		message;
	guint16		length;
	guint32		teid;
	guint16		seq_no;
	guint8		npdu_no;
} gtp3_hdr;
	
struct _gtp {
	guint8		flags;
	guint8		message;
	guint16		length;
	union {
		struct {
			guint16		seq_no;
			guint16		flow_label;
			guint8		npdu_no;
			guint8		spare[3];
		} v1;
		struct {
			guint32		teid;
			guint16		seq_no;
			guint8		npdu_no;
			guint8		next;
		} v2;
	} v;
} gtp_g;

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
	guint16		ci;
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
	guint32		sgsnaddr;
	guint8		msclass_not_used[12];
	guint8		msclass_caplen;
	guint8		msclass_cap[3];
	guint8		serv_centr[9];
	guint8		rec_ent[9];
	guint16		lac;
	guint8		rac;
	guint16		ci;
	guint8		timestamp[8];
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
	guint32		sgsnaddr;
	guint8		msclass_not_used[12];
	guint8		msclass_caplen;
	guint8		msclass_cap[3];
	guint8		serv_centr[9];
	guint8		rec_ent[9];
	guint16		lac;
	guint8		rac;
	guint16		ci;
	guint8		timestamp[8];
	guint16		smsres;
} stcdr;
	
	guint8		gtp_version = 0;
	char		*yesno[] = { "False", "True" };
	
static void
col_append_str_gtp(frame_data *fd, gint el) {
	int		i;
	int		max_len;
	gchar	_tmp[COL_MAX_LEN];

	max_len = COL_MAX_LEN;

	for (i = 0; i < fd->cinfo->num_cols; i++) {
		if (fd->cinfo->fmt_matx[i][el]) {
			if (fd->cinfo->col_data[i] != fd->cinfo->col_buf[i]) {
    			strncpy(fd->cinfo->col_buf[i], fd->cinfo->col_data[i], max_len);
    			fd->cinfo->col_buf[i][max_len - 1] = '\0';
      		}
			_tmp[0] = '\0';
			strcat(_tmp, "GTP <");
			strcat(_tmp, fd->cinfo->col_buf[i]);
			strcat(_tmp, ">");
			fd->cinfo->col_buf[i][0] = '\0';
			strcat(fd->cinfo->col_buf[i], _tmp);
			fd->cinfo->col_data[i] = fd->cinfo->col_buf[i];
		}
	}
}

static gchar *
id_to_str(const guint8 *ad) {
		
	static gchar	*str[17];
	gchar			*p;
	guint8		octet, i;
	static const	gchar hex_digits[16] = "0123456789abcdef";

	p = (gchar *)&str[17];
	*--p = '\0';
	i = 7;
	for (;;) {
		octet = ad[i];
		*--p = hex_digits[(octet >> 4) & 0xF];
		*--p = hex_digits[octet&0xF];
		if (i == 0) break;
		i--;
	}
	return p;
}

static gchar *
msisdn_to_str(const guint8 *ad, int len) {
		
	static gchar	*str[17];
	gchar			*p;
	guint8		octet, i;
	static const	gchar hex_digits[16] = "0123456789      ";

	p = (gchar *)&str[0];
	*p = '+';
	i = 1;
	for (;;) {
		octet = ad[i];
		*++p = hex_digits[octet&0xF];
		*++p = hex_digits[(octet >> 4) &0xF];
		if (i == len-1) break;
		i++;
	}
	*++p = '\0';
	return (gchar *)&str[0];
}

/*
static gchar *
time_int_to_str(guint32 time)
{
	guint	hours, mins, secs, month, days;
	guint	mths_n[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	guint	mths_s[12] = {31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
	static gchar	*cur, *p, str[3][2+1+2+1+2+1+4+1+2+1+2+2];
	
	if (cur == &str[0][0]) {
		cur = &str[1][0];
	} else if (cur == &str[1][0]) {
		cur = &str[2][0];
	} else {
		cur = &str[0][0];
	}

	if (time == 0) {
		sprintf (cur, "00:00:00 1970-01-01");
		return cur;
	}
	
	secs = time % 60;
	time /= 60;
	mins = time % 60;
	time /= 60;
	hours = time % 24;
	time /= 24;
	
	days = time % 365;
	time /= 365;
	days -= time / 4 + 1;
	if (!(time / 4)) {
		for (month=0; month<12; month++)
			if (days > mths_n[month]) days -= mths_n[month];
				else break;
	} else {
		for (month=0; month<12; month++)
			if (days > mths_s[month]) days -= mths_s[month];
				else break;
	}
	month++;
	time += 1970;
	
	p = cur;
	sprintf (p, "%02d:%02d:%02d %u-%02d-%02d", hours, mins, secs, time, month, days);
	
	return 	cur;
}*/

/* Decoders of fields in extension headers, each function returns no of bytes from field */

/* ETSI 9.60 
 * 3G TS 29.060 v. 3.5.0, 7.7.1*/
static int
decode_gtp_cause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint8	cause;
	
	cause = tvb_get_guint8(tvb, offset+1);	
	proto_tree_add_uint_format(tree, hf_gtp_ext_cause, tvb, offset, 2, cause,  
					"%s: %u", val_to_str(GTP_EXT_CAUSE, gtp_ext_val, "Unknown message"), cause); 

	return 2;
}

static int 
decode_gtp_imsi(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	tid_val[8];
	gchar	*tid_str;

	tvb_memcpy(tvb, tid_val, offset+1, 8);
	tid_val[1] = tid_val[1] & 0x0F;
	tid_str = id_to_str(tid_val);
	
	proto_tree_add_string_format(tree, hf_gtp_ext_imsi, tvb, offset, 9, tid_str, 
					"%s: %s", val_to_str(GTP_EXT_IMSI, gtp_ext_val, "Unknown message"), tid_str);

	return 9;
}

static int
decode_gtp_rai(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	proto_tree	*ext_tree;
	proto_item	*te;
	
	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_RAI, gtp_ext_val, "Unknown message")); 
	ext_tree = proto_item_add_subtree(te, ett_gtp_ext);
	proto_tree_add_uint(ext_tree, hf_gtp_ext_rai_mcc, tvb, offset+1, 2, tvb_get_ntohs(tvb, offset+1) & 0xFF0F);
	proto_tree_add_uint(ext_tree, hf_gtp_ext_rai_mnc, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+3));
	proto_tree_add_uint(ext_tree, hf_gtp_ext_rai_lac, tvb, offset+4, 2, tvb_get_ntohs(tvb, offset+4));
	proto_tree_add_uint(ext_tree, hf_gtp_ext_rai_rac, tvb, offset+6, 1, tvb_get_guint8(tvb, offset+6));

	return 7;
}

static int
decode_gtp_tlli(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint32	tlli;
	
	tlli = tvb_get_ntohl(tvb, offset+1);	
	proto_tree_add_uint_format(tree, hf_gtp_ext_tlli, tvb, offset, 5, tlli, 
					"%s: %x", val_to_str(GTP_EXT_TLLI, gtp_ext_val, "Unknown message"), tlli);

	return 5;
}

static int
decode_gtp_ptmsi(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint32	ptmsi;
	
	ptmsi = tvb_get_ntohl(tvb, offset);	
	proto_tree_add_uint_format(tree, hf_gtp_ext_ptmsi, tvb, offset, 5, ptmsi, 
					"%s: %x", val_to_str(GTP_EXT_PTMSI, gtp_ext_val, "Unknown message"), ptmsi);

	return 5;
}

/* check if length is included: ETSI 4.08 vs 9.60 */
static int
decode_gtp_qos(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	delay, reliability, peak, precedence, mean;
	proto_tree	*ext_tree;
	proto_item	*te;
	
	delay = (tvb_get_guint8(tvb, offset+1) >> 3) & 0x07;
	reliability = tvb_get_guint8(tvb, offset+1) & 0x07;
	peak = (tvb_get_guint8(tvb, offset+2) >> 4) & 0xF;
	precedence = tvb_get_guint8(tvb, offset+2) & 0x07;
	mean = tvb_get_guint8(tvb, offset+3) & 0x1F;
	te = proto_tree_add_text(tree, tvb, offset, 4, "QoS: delay: %u, reliability: %u, peak: %u, precedence: %u, mean: %u", 
					delay, reliability, peak, precedence, mean);
	ext_tree = proto_item_add_subtree(te, ett_gtp_qos);
	
	proto_tree_add_text(ext_tree, tvb, offset+1, 1, val_to_str(delay, qos_delay_type, "Unknown"));
	proto_tree_add_text(ext_tree, tvb, offset+1, 1, val_to_str(reliability, qos_reliability_type, "Unknown"));
	proto_tree_add_text(ext_tree, tvb, offset+2, 1, val_to_str(peak, qos_peak_type, "Unknown"));
	proto_tree_add_text(ext_tree, tvb, offset+2, 1, val_to_str(precedence, qos_precedence_type, "Unknown"));
	proto_tree_add_text(ext_tree, tvb, offset+3, 1, val_to_str(mean, qos_mean_type, "Unknown"));

	proto_tree_add_uint_hidden(ext_tree, hf_gtp_ext_qos_delay, tvb, offset+1, 1, delay);
	proto_tree_add_uint_hidden(ext_tree, hf_gtp_ext_qos_reliability, tvb, offset+1, 1, reliability);
	proto_tree_add_uint_hidden(ext_tree, hf_gtp_ext_qos_peak, tvb, offset+2, 1, peak);
	proto_tree_add_uint_hidden(ext_tree, hf_gtp_ext_qos_precedence, tvb, offset+2, 1, precedence);
	proto_tree_add_uint_hidden(ext_tree, hf_gtp_ext_qos_mean, tvb, offset+3, 1, mean);

	return 4;
}

static int
decode_gtp_reorder(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint8	reorder;
	
	reorder = tvb_get_guint8(tvb, offset+1) & 0x01;	
	proto_tree_add_boolean_format(tree, hf_gtp_ext_reorder, tvb, offset, 2, reorder, 
					"%s: %s", val_to_str(GTP_EXT_REORDER, gtp_ext_val, "Unknown message"), yesno[reorder]);

	return 2;
}

/* ETSI 4.08 v. 7.1.2, 10.5.3.1+ 
 * 3G TS 29.060 v. 3.5.0, 7.7.7 
 * TODO - rand/sres/kc based search? */
static int
decode_gtp_auth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	proto_tree	*ext_tree;
	proto_item	*te;
	guint32		rand1, rand2, rand3, rand4, sres, kc1, kc2;
	
	rand1 = tvb_get_ntohl(tvb, offset+1);
	rand2 = tvb_get_ntohl(tvb, offset+5);
	rand3 = tvb_get_ntohl(tvb, offset+9);
	rand4 = tvb_get_ntohl(tvb, offset+13);
	sres = tvb_get_ntohl(tvb, offset+17);
	kc1 = tvb_get_ntohl(tvb, offset+21);
	kc2 = tvb_get_ntohl(tvb, offset+25);

	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_AUTH, gtp_ext_val, "Unknown message"));
	ext_tree = proto_item_add_subtree(tree, ett_gtp_ext);
							
	proto_tree_add_text(ext_tree, tvb, offset+1, 16, "RAND: %x%x%x%x", rand1, rand2, rand3, rand4);
	proto_tree_add_text(ext_tree, tvb, offset+17, 4, "SRES: %x", sres);
	proto_tree_add_text(ext_tree, tvb, offset+21, 8, "Kc: %x%x", kc1, kc2);

	return 1+16+4+8;
}

static int
decode_gtp_map(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	map;
	
	map = tvb_get_guint8(tvb, offset+1);	
	proto_tree_add_uint_format(tree, hf_gtp_ext_map, tvb, offset, 2, map, 
					"%s: %u", val_to_str(GTP_EXT_MAP, gtp_ext_val, "Unknown message"), map);

	return 2;
}

static int
decode_gtp_ptmsi_sig(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint32	ptmsi_sig;
	
	ptmsi_sig = tvb_get_ntoh24(tvb, offset+1);	
	proto_tree_add_uint_format(tree, hf_gtp_ext_ptmsi_sig, tvb, offset, 4, ptmsi_sig, 
					"%s: %x", val_to_str(GTP_EXT_PTMSI_SIG, gtp_ext_val, "Unknown message"), ptmsi_sig);

	return 4;
}

static int
decode_gtp_ms(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	ms;
	
	ms = tvb_get_guint8(tvb, offset+1) & 0x01;	
	proto_tree_add_boolean_format(tree, hf_gtp_ext_ms, tvb, offset, 2, ms, 
					"%s: %s", val_to_str(GTP_EXT_MS, gtp_ext_val, "Unknown message"), yesno[ms]);

	return 2;
}

static int
decode_gtp_recover(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	recover;
	
	recover = tvb_get_guint8(tvb, offset+1);	
	proto_tree_add_uint_format(tree, hf_gtp_ext_recover, tvb, offset, 2, recover,
					"%s: %u", val_to_str(GTP_EXT_RECOVER, gtp_ext_val, "Unknown message"), recover);

	return 2;
}

static int
decode_gtp_sel_mode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	sel_mode;
	
	sel_mode = tvb_get_guint8(tvb, offset+1) & 0x03;	
	proto_tree_add_uint_format(tree, hf_gtp_ext_sel_mode, tvb, offset, 2, sel_mode,
					"%s: %s", val_to_str(GTP_EXT_SEL_MODE, gtp_ext_val, "Unknown message"), 
					val_to_str(sel_mode, sel_mode_type, "Unknown selection mode"));

	return 2;
}

static int
decode_gtp_flow_label(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16	flow_label;	
	guint32	te_id_data;

	switch (gtp_version) {
		case 0:
		    flow_label = tvb_get_ntohs(tvb, offset+1);	
			proto_tree_add_uint_format(tree, hf_gtp_ext_flow_label, tvb, offset, 3, flow_label,
							"%s: %u", val_to_str(GTP_EXT_FLOW_LABEL, gtp_ext_val, "Unknown message"), flow_label);
			return 3;
		case 1:
			te_id_data = tvb_get_ntohl(tvb, offset+1);
/*			proto_tree_add_uint_format(tree, hf_gtp_te_id_data, tvb, offset, 5, te_id_data,
							"%s: %u", val_to_str(GTP_EXT_FLOW_LABEL, gtp_ext_val, "Unknown message"), te_id_data);
*/
			return 5;
		default: 
			proto_tree_add_text(tree, tvb, offset, 1, "Flow label/Tunnel end point: GTP version not supported");
			return 3;
	}
}

static int
decode_gtp_flow_sig(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16	flow_sig;
	guint32	te_id_sig;

	switch (gtp_version) {
		case 0:
		    flow_sig = tvb_get_ntohs(tvb, offset+1);	
			proto_tree_add_uint_format(tree, hf_gtp_ext_flow_sig, tvb, offset, 3, flow_sig,
							"%s: %u", val_to_str(GTP_EXT_FLOW_SIG, gtp_ext_val, "Unknown message"), flow_sig);
			return 3;
		case 1:
			te_id_sig = tvb_get_ntohl(tvb, offset+1);
/*			proto_tree_add_uint(tvb, hf_3g_gtp_ext_te_id_sig, tvb, offset, 5, te_id_sig,
							"%s: %u", val_to_str(GTP_EXT_TE_ID_SIG, gtp_ext_val, "Unknown message"), te_id_sig);
*/
			return 5;
		default:
			proto_tree_add_text(tree, tvb, offset, 0, "Flow sig/Tunnel end: GTP version not supported");
			return 3;
	}
}

static int
decode_gtp_flow_ii(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16		flow_ii;
	guint32		te_id_ii;
	proto_tree	*ext_tree;
	proto_item	*te;

	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_FLOW_II, gtp_ext_val, "Unknown message"));
	ext_tree = proto_item_add_subtree(te, ett_gtp_ext);
	
	proto_tree_add_uint(ext_tree, hf_gtp_ext_flow_ii_nsapi, tvb, offset+1, 1, tvb_get_guint8(tvb, offset+1) & 0x0F);

	switch (gtp_version) {
		case 0:
		    flow_ii = tvb_get_ntohs(tvb, offset+2);	
			proto_tree_add_uint(ext_tree, hf_gtp_ext_flow_ii, tvb, offset+2, 2, flow_ii);
			return 4;
		case 1:
			te_id_ii = tvb_get_ntohl(tvb, offset+2);
/*			proto_tree_add_uint(tree, hf_3g_gtp_ext_te_id_ii, tvb, offset+2, 4, te_id_ii);
*/
			return 6;
		default:
			proto_tree_add_text(ext_tree, tvb, offset, 1, "Flow data II/Tunnel end data II: GTP Version not supported");
			return 4;
	}
}

static int
decode_gtp_tr_comm(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint8	command;	
	
	command = tvb_get_guint8(tvb, offset+1);	
	proto_tree_add_uint_format(tree, hf_gtp_ext_tr_comm, tvb, offset, 2, command,
					"%s: %x", val_to_str(GTP_EXT_TR_COMM, gtp_ext_val, "Unknown message"), command);

	return 2;
}

static int
decode_gtp_chrg_id(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint32	chrg_id;	
	
	chrg_id = tvb_get_ntohl(tvb, offset+1);	
	proto_tree_add_uint_format(tree, hf_gtp_ext_chrg_id, tvb, offset, 5, chrg_id,
					"%s: %x", val_to_str(GTP_EXT_CHRG_ID, gtp_ext_val, "Unknown message"), chrg_id);

	return 5;
}

static int
decode_gtp_user_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16		length;
	guint8		pdp_type, pdp_org;	
	guint32		addr_ipv4;
	struct		e_in6_addr addr_ipv6;
	proto_tree	*ext_tree;
	proto_item	*te;
	
	
    length = tvb_get_ntohs(tvb, offset+1);
	pdp_org = tvb_get_guint8(tvb, offset+3) & 0x0F;
	pdp_type = tvb_get_guint8(tvb, offset+4);

	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_USER_ADDR, gtp_ext_val, "Unknown message"));
	ext_tree = proto_item_add_subtree(te, ett_gtp_ext);
	
	proto_tree_add_uint(ext_tree, hf_gtp_ext_user_addr_pdp_org, tvb, offset+3, 1, pdp_org);
	proto_tree_add_uint(ext_tree, hf_gtp_ext_user_addr_pdp_type, tvb, offset+4, 1, pdp_type);
	if (length > 2) {
		switch (pdp_type) {
				case 0x00: break;
			case 0x01: break;
			case 0x02: break;
			case 0x21:
				addr_ipv4 = tvb_get_letohl(tvb, offset+5);
				proto_tree_add_ipv4(ext_tree, hf_gtp_ext_user_addr, tvb, offset+5, 4, addr_ipv4);  
				break;
			case 0x57:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+5, sizeof addr_ipv6);
				proto_tree_add_ipv6(ext_tree, hf_gtp_ext_user_addr, tvb, offset+5, 16, (guint8 *)&addr_ipv6);
				break;
			default:
				; /* nothing */
		}
	}
				
	return 3+length;
}

static int
decode_gtp_mm_cntx(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16		length, drx, net_cap, con_len;	
	guint8		cksn, count, triplets[8], cipher, i, trans_id, proto_disc, message;
	gchar		kc[9];
	proto_tree	*ext_tree;
	proto_item	*te;
	
	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_MM_CNTX, gtp_ext_val, "Unknown message"));
	ext_tree = proto_item_add_subtree(te, ett_gtp_ext);
	
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < 1) return 3;
	
	cksn = tvb_get_guint8(tvb, offset+3) & 0x07;
	count = (tvb_get_guint8(tvb, offset+4) >> 3) & 0x07;
	cipher = tvb_get_guint8(tvb, offset+4) & 0x07;

	tvb_memcpy(tvb, kc, offset+5, 8);
	kc[8] = '\0';
	for(i=0; i < count; i++) triplets[i] = tvb_get_guint8(tvb, offset+13+i);
	drx = tvb_get_ntohs(tvb, offset+13+count);
	net_cap	= tvb_get_ntohs(tvb, offset+15+count);
	con_len = tvb_get_ntohs(tvb, offset+17+count);
	if (con_len > 0) {
		trans_id = (tvb_get_guint8(tvb, offset+18+count) >> 4) & 0x0F;
		proto_disc = tvb_get_guint8(tvb, offset+18+count) & 0x0F;
		message = tvb_get_guint8(tvb, offset+19+count);
	}

	proto_tree_add_text(ext_tree, tvb, offset+3, 1, "MM PDP CNTX - Ciphering Key Sequence Number: %u", cksn);
	proto_tree_add_text(ext_tree, tvb, offset+4, 1, "MM PDP CNTX - No of triplets: %u", count);
	proto_tree_add_text(ext_tree, tvb, offset+4, 1, "MM PDP CNTX - Ciphering: %u", cipher);
	proto_tree_add_text(ext_tree, tvb, offset+5, 8, "MM PDP CNTX - Kc: %s", kc);

	proto_tree_add_text(ext_tree, tvb, offset+13, 2, "MM PDP CNTX - DRX: %u", drx);
	proto_tree_add_text(ext_tree, tvb, offset+15, 2, "MM PDP CNTX - MS network capability: %u", net_cap);
	proto_tree_add_text(ext_tree, tvb, offset+17, 2, "MM PDP CNTX - Container length: %u", con_len);

	return 3+length;
}

static void
decode_qos(tvbuff_t *tvb, int offset, proto_tree *tree, guint8 qos[3], gchar* qos_str) {
	
	guint8	delay, reliability, peak, precedence, mean;
	
	delay = (qos[0] >> 3) & 0x07;
	reliability = qos[0] & 0x07;
	peak = (qos[1] >> 4) & 0xF;
	precedence = qos[1] & 0x07;
	mean = qos[2] & 0x1F;
	
	proto_tree_add_text(tree, tvb, offset, 3, "%s: delay: %u, reliability: %u, peak: %u, precedence: %u, mean: %u", 
					qos_str, delay, reliability, peak, precedence, mean);
}

/* insert info about PDP type, decode X.25 addr - unify qos/apn/addr functions */
static int
decode_gtp_pdp_cntx(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint8		ggsn_addr_len, apn_len, name_len, tmp, trans_id, vaa, order;
	guint16		length;
	guint32 	addr_ipv4;
	guint8		apn[100];
	pdp_t		pdp;
	struct		e_in6_addr addr_ipv6;	
	proto_tree	*ext_tree;
	proto_item	*te;
	
	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_PDP_CNTX, gtp_ext_val, "Unknown message"));
	ext_tree = proto_item_add_subtree(te, ett_gtp_ext);
	
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < sizeof(pdp_t)) return 3+length;
					
	tvb_memcpy(tvb, (guint8 *)&pdp, offset+3, sizeof(pdp_t));
    
	vaa = (pdp.nsapi >> 6) & 0x01;
	order = (pdp.nsapi >> 4) & 0x01;
	pdp.nsapi =  pdp.nsapi & 0x0F;
	pdp.sapi = pdp.sapi & 0x0F;
	

	proto_tree_add_text(ext_tree, tvb, offset+3, 1, "VPLMN address allowed: %s", yesno[vaa]);
	proto_tree_add_text(ext_tree, tvb, offset+3, 1, "Reordering required: %s", yesno[order]);
	
	proto_tree_add_text(ext_tree, tvb, offset+3, 1, "NSAPI: %u", pdp.nsapi);
	proto_tree_add_text(ext_tree, tvb, offset+4, 1, "SAPI: %u", pdp.sapi);
	
	decode_qos(tvb, offset+5, ext_tree, pdp.qos_sub, "QoS subscribed");
	decode_qos(tvb, offset+8, ext_tree, pdp.qos_req, "QoS requested");
	decode_qos(tvb, offset+11, ext_tree, pdp.qos_neg, "QoS negotiated");

	proto_tree_add_text(ext_tree, tvb, offset+14, 2, "Sequence number down: %u", pdp.sn_down);
	proto_tree_add_text(ext_tree, tvb, offset+16, 2, "Sequence number up: %u", pdp.sn_up);

	proto_tree_add_text(ext_tree, tvb, offset+18, 1, "Send N-PDU number: %u", pdp.pdu_send_no);
	proto_tree_add_text(ext_tree, tvb, offset+19, 1, "Receive N-PDU number: %u", pdp.pdu_rec_no);
	
	proto_tree_add_text(ext_tree, tvb, offset+20, 2, "Uplink flow label signalling: %u", pdp.up_flow);
	
	if (pdp.pdp_addr_len > 0) {
		switch (pdp.pdp_type) {
			case 0x00: break;
			case 0x01: break;
			case 0x02: break;
			case 0x21:
				addr_ipv4 = tvb_get_letohl(tvb, offset+25);
				proto_tree_add_ipv4(ext_tree, hf_gtp_ext_user_addr, tvb, offset+25, 4, addr_ipv4);  
				break;
			case 0x57:
				tvb_memcpy(tvb, (guint8 *)&addr_ipv6, offset+25, sizeof addr_ipv6);
				proto_tree_add_ipv6(ext_tree, hf_gtp_ext_user_addr, tvb, offset+25, 16, (guint8 *)&addr_ipv6);
				break;
			default:
				; /* nothing */
		}
	}
		
	ggsn_addr_len = tvb_get_guint8(tvb, offset+25+pdp.pdp_addr_len);
	addr_ipv4 = tvb_get_letohl(tvb, offset+26+pdp.pdp_addr_len);
	proto_tree_add_ipv4(ext_tree, hf_gtp_ext_gsn_addr, tvb, offset+26+pdp.pdp_addr_len, 4, addr_ipv4);
	
	apn_len = tvb_get_guint8(tvb, offset+26+pdp.pdp_addr_len+ggsn_addr_len);
	tvb_memcpy(tvb, apn, offset+27+pdp.pdp_addr_len+ggsn_addr_len, apn_len);
	name_len = 0;
	for (;;) {
		if (name_len >= apn_len) break;
		tmp = name_len;
		name_len = name_len + apn[name_len] + 1;
		apn[tmp] = '.';
	}
	apn[apn_len] = '\0';
	proto_tree_add_string(ext_tree, hf_gtp_ext_apn, tvb, offset+27+pdp.pdp_addr_len+ggsn_addr_len, apn_len, apn);
	
	trans_id = tvb_get_guint8(tvb, offset+27+pdp.pdp_addr_len+ggsn_addr_len+apn_len);
	proto_tree_add_text(ext_tree, tvb, offset+27+pdp.pdp_addr_len+ggsn_addr_len+apn_len, 1, "Transaction identifier: %u", trans_id);

	return 3+length;
}

static int
decode_gtp_apn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16	length, name_len, tmp;	
	guint8	apn[100];
	
	length = tvb_get_ntohs(tvb, offset+1);	
	if (length > 2) {
		name_len = tvb_get_guint8(tvb, offset+3);
		tvb_memcpy(tvb, apn, offset+4, length-1);
		for (;;) {
			if (name_len >= length-1) break;
			tmp = name_len;
			name_len = name_len + apn[tmp] + 1;
			apn[tmp] = '.';
		}
	}
	apn[length-1] = '\0';
	proto_tree_add_string_format(tree, hf_gtp_ext_apn, tvb, offset, length+3, apn,
					"%s: %s", val_to_str(GTP_EXT_APN, gtp_ext_val, "Unknown message"), apn);
	
	return 3+length;
}

/* ETSI 4.08 v. 7.1.2, 10.5.6.3 (p.580)
 * TODO	- check if length is 8 or 16 bits
 * 		- proto_conf in 3G */
static int
decode_gtp_proto_conf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	guint16		length, proto_id, raw_offset, proto_offset;	
	guint8		conf, proto_len;
	tvbuff_t	*next_tvb, *temp;
	guint8		*target;
	proto_tree	*ext_tree;
	proto_item	*te;
	packet_info	save_pi;

	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_PROTO_CONF, gtp_ext_val, "Unknown message"));
	ext_tree = proto_item_add_subtree(te, ett_gtp_ext);
	
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < 4) return 3+length;
	conf = tvb_get_guint8(tvb, offset+3) & 0x07;
	proto_offset = 1;	/* 1st byte is conf */
	
	for (;;) {	
		if (proto_offset >= length) break;
	
		proto_id = tvb_get_ntohs(tvb, offset+4);
		proto_len = tvb_get_guint8(tvb, offset+6);
	
		proto_offset += proto_len+3;
		
		if (proto_len > 0) {
		
			/* this part changes layout of GTP payload: 
			 * it removes "length field" from between protocol header and protocol payload */
	
			raw_offset = tvb_raw_offset(tvb);	
			target = g_malloc(tvb_length(tvb)+raw_offset);	
			tvb_memcpy(tvb, target+offset+4+raw_offset, offset+6, 1);
			tvb_memcpy(tvb, target+offset+5+raw_offset, offset+4, 2);
			tvb_memcpy(tvb, target+offset+7+raw_offset, offset+7, proto_len);
			temp = tvb_new_real_data(target,
			    tvb_length(tvb)+raw_offset,
			    tvb_length(tvb)+raw_offset,
			    "PPP payload");
			tvb_set_free_cb(temp, free_tvb_data);
			tvb_set_child_real_data_tvbuff(tvb, temp);
			next_tvb = tvb_new_subset(temp, offset+5+raw_offset, proto_len+2, proto_len+2);

			/* Save the current value of "pi", and adjust
			   certain fields to reflect the new top-level
			   tvbuff. */
			save_pi = pi;
			pi.compat_top_tvb = temp;
			pi.len = tvb_reported_length(temp);
			pi.captured_len = tvb_length(temp);

			call_dissector(ppp_handle, next_tvb, pinfo, ext_tree); 

			pi = save_pi;
		}
	}
	
	return 3+length;
}

static void
free_tvb_data(void *tvb_data)
{
	g_free(tvb_data);
}

static int
decode_gtp_gsn_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16	length, addr_len;	
	guint32	gsn_addr;
	
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < 1) return 3+length;
	gsn_addr = tvb_get_letohl(tvb, length > 4 ? offset+4 : offset+3);
	if (length > 4) addr_len = tvb_get_guint8(tvb, offset+3); else addr_len = 4;
	proto_tree_add_ipv4_format(tree, hf_gtp_ext_gsn_addr, tvb, offset, 3+length, gsn_addr,
					"%s: %s", val_to_str(GTP_EXT_GSN_ADDR, gtp_ext_val, "Unknown message"), 
					ip_to_str(tvb_get_ptr(tvb, length > 4 ? offset+4 : offset+3, 4)));
	
	return 3+length;
}

static int
decode_gtp_msisdn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	const guint8	*msisdn_val;
	gchar		*msisdn_str;
	guint16		length;
	
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < 1) return 3+length;
	
	msisdn_val = tvb_get_ptr(tvb, offset+3, length);
	msisdn_str = msisdn_to_str(msisdn_val, length);
	
	proto_tree_add_string_format(tree, hf_gtp_ext_msisdn, tvb, offset, 3+length, msisdn_str,
					"%s: %s", val_to_str(GTP_EXT_MSISDN, gtp_ext_val, "Unknown message"), msisdn_str);
	
	return 3+length;
}

static int
decode_gtp_chrg_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16 length, addr_len;
	guint32	chrg_addr;
	
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < 1) return 3+length;
	
	chrg_addr = tvb_get_letohl(tvb, length > 4 ? offset+4 : offset+3);
	if (length > 4) addr_len = tvb_get_guint8(tvb, offset+3); else addr_len = 4;
	proto_tree_add_ipv4_format(tree, hf_gtp_ext_chrg_addr, tvb, offset, 3+length, chrg_addr,
					"%s: %s", val_to_str(GTP_EXT_CHRG_ADDR, gtp_ext_val, "Unknown message"), 
					ip_to_str(tvb_get_ptr(tvb, length > 4 ? offset+4 : offset+3, 4)));
	
	return 3+length;
}

/* CDRs dissector */
static int
decode_gtp_data_rec(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
	
	guint16		length, format_ver, data_len, i;
	guint8		no, format, rectype;
	proto_tree	*ext_tree;
	proto_item	*te;

	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_DATA_REC, gtp_ext_val, "Unknown message"));
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
	for (i = 0; i < no; i++) {
		data_len = tvb_get_ntohs(tvb, offset);
		rectype = tvb_get_guint8(tvb, offset+2);
		switch (rectype) {
			case 0x13:		/* GCDR */ 
				proto_tree_add_text(ext_tree, tvb, offset, data_len + 2, "GCDR");
				break;
			case 0x12:		/* SCDR */
				proto_tree_add_text(ext_tree, tvb, offset, data_len + 2, "SCDR");
				break;
			case 0x14:		/* MCDR */
				proto_tree_add_text(ext_tree, tvb, offset, data_len + 2, "MCDR");
				break;
			case 0x15:		/* SOCDR */
				proto_tree_add_text(ext_tree, tvb, offset, data_len + 2, "SOCDR");
				break;
			case 0x16:		/* STCDR */
				proto_tree_add_text(ext_tree, tvb, offset, data_len + 2, "STCDR");
		}
		offset = offset + 2 + data_len;
	}

	return 3+length;
}
	
static int
decode_gtp_node_addr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
		
	guint16 length;
	guint32	node_addr;
	
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < 1) return 3+length;
	
	node_addr = tvb_get_letohl(tvb, offset+3);
	proto_tree_add_ipv4_format(tree, hf_gtp_ext_node_addr, tvb, offset, 3+length, node_addr,
					"%s: %s", val_to_str(GTP_EXT_NODE_ADDR, gtp_ext_val, "Unknown message"), 
					ip_to_str(tvb_get_ptr(tvb, offset+3, 4)));
	
	return 3+length;
}

static int
decode_gtp_priv_ext(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {	
		
	guint16		length, ext_id;	
	gchar		ext_val[64];
	proto_tree	*ext_tree;
	proto_item	*te;
	
	te = proto_tree_add_text(tree, tvb, offset, 1, val_to_str(GTP_EXT_PRIV_EXT, gtp_ext_val, "Unknown message"));
	ext_tree = proto_item_add_subtree(te, ett_gtp_ext);
	
	length = tvb_get_ntohs(tvb, offset+1);
	if (length < 1) return 3+length;
	
	ext_id = tvb_get_ntohs(tvb, offset+3);	
	tvb_memcpy(tvb, ext_val, offset+5, length > 65 ? 63 : length-2);
	ext_val[length > 65 ? 64 : length-1] = '\0';
	proto_tree_add_uint(ext_tree, hf_gtp_ext_ext_id, tvb, offset+3, 2, ext_id);
	proto_tree_add_string(ext_tree, hf_gtp_ext_ext_val, tvb, offset+5, length-2, ext_val);
	
	return 3+length;
}

static int
decode_gtp_unknown(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {

	return tvb_length_remaining(tvb, offset);
}

static void
dissect_gtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	
	proto_item	*ti, *tf;
	proto_tree	*gtp_tree, *flags_tree;
	guint8		ext_hdr_val;
	tvbuff_t	*next_tvb;
	const guint8	*tid_val;
	gchar		*tid_str;
	int		offset, length, i;
	
	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "GTP");
	if (check_col(pinfo->fd, COL_INFO))
		col_clear(pinfo->fd, COL_INFO);

	tvb_memcpy(tvb, (guint8 *)&gtp, 0, 12); 
	tid_val = tvb_get_ptr(tvb, 12, 8);
	tid_str = id_to_str(tid_val);
	gtp_version = (gtp.flags >> 5) & 0x07;

	if (!((gtp.flags >> 4) & 1)) {
		if (check_col(pinfo->fd, COL_PROTOCOL))
			col_set_str(pinfo->fd, COL_PROTOCOL, "GTP-CDR");
		if (check_col(pinfo->fd, COL_INFO))
			col_add_fstr(pinfo->fd, COL_INFO, "%s - tid: %s", val_to_str(gtp.message, message_type, "Unknown"), tid_str);
	} else {
		switch ((gtp.flags >> 5) & 0x07) {
		case 0:	
			if (check_col(pinfo->fd, COL_PROTOCOL))
				col_set_str(pinfo->fd, COL_PROTOCOL, "GTP");
			if (check_col(pinfo->fd, COL_INFO))
				col_add_fstr(pinfo->fd, COL_INFO, "%s - tid: %s", val_to_str(gtp.message, message_type, "Unknown"), tid_str);
			break;
		case 1: 
			if (check_col(pinfo->fd, COL_PROTOCOL))
				col_set_str(pinfo->fd, COL_PROTOCOL, "GTP3");
			if (check_col(pinfo->fd, COL_INFO))
				col_add_fstr(pinfo->fd, COL_INFO, "(version not supported yet) %s", val_to_str(gtp.message, message_type, "Unknown"));
			break;
		}
	}
	
	if (tree) {
			
		/* dissect GTP header */
		ti = proto_tree_add_item(tree, proto_gtp, tvb, 0, tvb_length(tvb), FALSE);

		gtp_tree = proto_item_add_subtree(ti, ett_gtp);

		tf = proto_tree_add_uint(gtp_tree, hf_gtp_flags, tvb, 0, 1, gtp.flags);

		flags_tree = proto_item_add_subtree(tf, ett_gtp_flags);
		proto_tree_add_uint(flags_tree, hf_gtp_flags_ver, tvb, 0, 1, gtp.flags);
		proto_tree_add_uint(flags_tree, hf_gtp_flags_pt, tvb, 0, 1, gtp.flags);
		proto_tree_add_uint(flags_tree, hf_gtp_flags_spare, tvb, 0, 1, gtp.flags);
		proto_tree_add_uint(flags_tree, hf_gtp_flags_snn, tvb, 0, 1, gtp.flags);
		
		gtp.length = ntohs(gtp.length);
		gtp.seq_no = ntohs(gtp.seq_no);
		proto_tree_add_uint(gtp_tree, hf_gtp_message_type, tvb, 1, 1, gtp.message);
		proto_tree_add_uint(gtp_tree, hf_gtp_length, tvb, 2, 2, gtp.length);
		proto_tree_add_uint(gtp_tree, hf_gtp_seq_number, tvb, 4, 2, gtp.seq_no);
		proto_tree_add_uint(gtp_tree, hf_gtp_flow_label, tvb, 6, 2, gtp.flow_label);
		proto_tree_add_uint(gtp_tree, hf_gtp_sndcp_number, tvb, 8, 1, gtp.npdu_no);
		proto_tree_add_string(gtp_tree, hf_gtp_tid, tvb, 12, 8, tid_str);
	
		if (gtp.message != GTP_MSG_TPDU) {
				
			offset = GTP_HDR_LENGTH;
			length = tvb_length(tvb);
		
			for (;;) {
					
				if (offset >= length) break;
				ext_hdr_val = tvb_get_guint8(tvb, offset);
				i = -1;
				while (gtpopt[++i].optcode) if (gtpopt[i].optcode == ext_hdr_val) break;
				offset = offset + (*gtpopt[i].decode)(tvb, offset, pinfo, gtp_tree);
			}
		}
	} 

	if (gtp.message == GTP_MSG_TPDU) {
		next_tvb = tvb_new_subset(tvb, 20, -1, -1);
		call_dissector(ip_handle, next_tvb, pinfo, tree);
		if (check_col(pinfo->fd, COL_PROTOCOL)) col_append_str_gtp(pinfo->fd, COL_PROTOCOL);
	}
	
}

/*
static void
dissect_gtp3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	
	proto_item	*ti, *tf;
	proto_tree	*gtp_tree, *flags_tree;
	guint8		int_val8, message_type_val, ext_hdr_val, i, gtp_version;
	guint16		int_val16;	
	tvbuff_t	*next_tvb;
	int			offset, length;
	int			(*decode)(tvbuff_t  *, int, packet_info *, proto_tree *);
	
	if (check_col(pinfo->fd, COL_PROTOCOL))
		col_set_str(pinfo->fd, COL_PROTOCOL, "GTP3");
	if (check_col(pinfo->fd, COL_INFO))
		col_clear(pinfo->fd, COL_INFO);

	tvb_memcpy(tvb, gtp3_hdr, 0, sizeof(gtp3_hdr));
	
	if (check_col(pinfo->fd, COL_INFO))
		col_add_str(pinfo->fd, COL_INFO, val_to_str(gtp3_hdr.message, message_type, "Unknown"));

	if (tree) {
			
		ti = proto_tree_add_item(tree, proto_gtp, tvb, 0, tvb_length(tvb), FALSE);

		gtp_tree = proto_item_add_subtree(ti, ett_gtp);

		int_val8 = tvb_get_guint8(tvb, 0);
		tf = proto_tree_add_uint(gtp_tree, hf_gtp_flags, tvb, 0, 1, int_val8);

		flags_tree = proto_item_add_subtree(tf, ett_gtp_flags);
		proto_tree_add_uint(flags_tree, hf_gtp_flags_ver, tvb, 0, 1, int_val8);
		proto_tree_add_uint(flags_tree, hf_gtp_flags_pt, tvb, 0, 1, int_val8);
		proto_tree_add_uint(flags_tree, hf_gtp_flags_spare, tvb, 0, 1, int_val8);
		proto_tree_add_uint(flags_tree, hf_gtp_flags_snn, tvb, 0, 1, int_val8);
	
		proto_tree_add_uint(gtp_tree, hf_gtp_message_type, tvb, 1, 1, message_type_val);

		int_val16 = tvb_get_ntohs(tvb, 2);
		proto_tree_add_uint(gtp_tree, hf_gtp_length, tvb, 2, 2, int_val16);
		
		int_val16 = tvb_get_ntohs(tvb, 4);
		proto_tree_add_uint(gtp_tree, hf_gtp_seq_number, tvb, 4, 2, int_val16);

		int_val16 = tvb_get_ntohs(tvb, 6);
		proto_tree_add_uint(gtp_tree, hf_gtp_flow_label, tvb, 6, 2, int_val16);

		int_val8 = tvb_get_guint8(tvb, 8);
		proto_tree_add_uint(gtp_tree, hf_gtp_sndcp_number, tvb, 8, 1, int_val8);

		proto_tree_add_string(gtp_tree, hf_gtp_tid, tvb, 12, 8, tid_str);
	

		if (message_type_val != GTP_MSG_TPDU) {
				
			offset = GTP_HDR_LENGTH;
			length = tvb_length(tvb);
		
			if (length > GTP_HDR_LENGTH) {
		
				int_val16 = 0;

				for (;;) {
	
					offset = offset + int_val16;	
					if (offset >= length) break;
					ext_hdr_val = tvb_get_guint8(tvb, offset);
	
					for (i = 0; i < 26; i++) if (gtpopt[i].optcode == ext_hdr_val) break;
					if (i < 26) {	
						decode = gtpopt[i].decode;
						int_val16 = (*decode)(tvb, offset, pinfo, gtp_tree);
					} else int_val16 = decode_gtp_unknown(tvb, offset, pinfo, gtp_tree);
				}
			}
		} 
	}

	int_val8 = tvb_get_guint8(tvb, 1);
	if (int_val8 == 0xff) {
		next_tvb = tvb_new_subset(tvb, 20, -1, -1);
		call_dissector(ip_handle, next_tvb, pinfo, tree);
		if (check_col(pinfo->fd, COL_PROTOCOL)) col_append_str_gtp(pinfo->fd, COL_PROTOCOL);
	}
	
}

*/

void
proto_register_gtp(void)
{                 

	static hf_register_info hf[] = {

		{ &hf_gtp_flags,		{ "Flags", 				"gtp.flags", 				FT_UINT8, 	BASE_HEX, NULL, 0, "Ver/PT/Res/E/S/PN" }},
		{ &hf_gtp_flags_ver,		{ "Version", 			"gtp.flags.version", 		FT_UINT8, 	BASE_DEC, VALS(ver_types), GTP_VER_MASK, "GTP version" }},
		{ &hf_gtp_flags_pt,		{ "Payload Type", 		"gtp.flags.payload_type", 	FT_UINT8, 	BASE_DEC, NULL, GTP_PT_MASK, "Payload types" }},
		{ &hf_gtp_flags_spare,		{ "Reserved", 			"gtp.flags.spare",			FT_UINT8, 	BASE_DEC, NULL, GTP_SPARE_MASK, "Reserved" }},
		{ &hf_gtp_flags_snn,		{ "Is seq number", 		"gtp.flags.snn",			FT_UINT8, 	BASE_DEC, NULL, GTP_SNN_MASK, "Is sequence number present" }},
		{ &hf_gtp_message_type,		{ "Message type", 		"gtp.message_type",			FT_UINT8, 	BASE_HEX, VALS(message_type), 0x0, "GTP message type" }},
		{ &hf_gtp_length,		{ "Length", 			"gtp.length", 				FT_UINT16, 	BASE_DEC, NULL, 0, "Length" }},
		{ &hf_gtp_seq_number,		{ "Sequence number", 	"gtp.seq_number",			FT_UINT16, 	BASE_HEX, NULL, 0, "Sequence number" }},
		{ &hf_gtp_flow_label,		{ "Flow label", 		"gtp.flow_label",			FT_UINT16, 	BASE_HEX, NULL, 0, "Flow label" }},
		{ &hf_gtp_sndcp_number,		{ "SNDCP N-PDU LLC Number", "gtp.sndcp_number",		FT_UINT8, 	BASE_HEX, NULL, 0, "SNDCP N-PDU LLC Number" }},
		{ &hf_gtp_tid,			{ "Tunnel ID", 			"gtp.tid", 					FT_STRING, 	BASE_DEC, NULL, 0, "Tunnel ID" }},
		{ &hf_gtp_ext,			{ "Extension header", 	"gtp.ext", 					FT_UINT8, 	BASE_HEX, NULL, 0, "Extension header" }},
		
		{ &hf_gtp_ext_cause,		{ "Cause", 				"gtp.ext.cause", 			FT_UINT8, 	BASE_DEC, VALS(cause_type), 0, "Cause of operation" }},
	
		{ &hf_gtp_ext_imsi,		{ "IMSI", 				"gtp.ext.imsi", 			FT_STRING, 	BASE_DEC, NULL, 0, "IMSI number" }},
	
		{ &hf_gtp_ext_rai_mcc,		{ "MCC", 				"gtp.ext.mcc",				FT_UINT16, 	BASE_DEC, NULL, 0, "Mobile Country Code" }},
		{ &hf_gtp_ext_rai_mnc,		{ "MNC", 				"gtp.ext.mnc", 				FT_UINT8, 	BASE_DEC, NULL, 0, "Mobile National Code" }},
		{ &hf_gtp_ext_rai_rac,		{ "RAC", 				"gtp.ext.rac", 				FT_UINT8, 	BASE_DEC, NULL, 0, "Routing Area" }},
		{ &hf_gtp_ext_rai_lac,		{ "LAC", 				"gtp.ext.lac", 				FT_UINT16, 	BASE_DEC, NULL, 0, "Location Area" }},
		
		{ &hf_gtp_ext_tlli,		{ "TLLI", 				"gtp.ext.tlli", 			FT_UINT32, 	BASE_HEX, NULL, 0, "Temporary Logical Link Identity" }},
		
		{ &hf_gtp_ext_ptmsi,		{ "P-TMSI",				"gtp.ext.ptmsi", 			FT_UINT32, 	BASE_HEX, NULL, 0, "Packet TMSI" }},
		
		{ &hf_gtp_ext_qos_delay,	{ "QoS delay",			"gtp.ext.qos_delay", 		FT_UINT8, 	BASE_DEC, VALS(qos_delay_type), 0, "QoS delay class" }},
		{ &hf_gtp_ext_qos_reliability,	{ "QoS reliability","gtp.ext.qos_reliabilty", 	FT_UINT8, 	BASE_DEC, VALS(qos_reliability_type), 0, "QoS reliability class" }},
		{ &hf_gtp_ext_qos_peak,		{ "QoS peak",			"gtp.ext.qos_peak", 		FT_UINT8, 	BASE_DEC, VALS(qos_peak_type), 0, "QoS peak throughput" }},
		{ &hf_gtp_ext_qos_precedence,	{ "QoS precedence",	"gtp.ext.qos_precedence", 	FT_UINT8, 	BASE_DEC, VALS(qos_precedence_type), 0, "QoS precedence class" }},
		{ &hf_gtp_ext_qos_mean,		{ "QoS mean",			"gtp.ext.qos_mean", 		FT_UINT8, 	BASE_DEC, VALS(qos_mean_type), 0, "QoS mean throughput" }},
		
		{ &hf_gtp_ext_reorder,		{ "Reordering required", "gtp.ext.reorder", 		FT_BOOLEAN, BASE_NONE, NULL, 0, "Reordering required" }},
		
/*		{ &hf_gtp_ext_auth_rand,	{ "Authentication RAND", "gtp.ext.auth_rand", 		FT_STRING, 	BASE_DEC, NULL, 0, "Authentication RAND" }},
		{ &hf_gtp_ext_auth_sres,	{ "Authentication SRES", "gtp.ext.auth_sres",		FT_STRING,	BASE_DEC, NULL, 0, "Authentication SRES" }},
		{ &hf_gtp_ext_auth_kc,		{ "Authentication Kc", 	"gtp.ext.auth_kc", 			FT_STRING, 	BASE_DEC, NULL, 0, "Authentication Kc" }},
*/		
		{ &hf_gtp_ext_map,		{ "Ext type",			"gtp.ext.map", 				FT_UINT8, 	BASE_DEC, VALS(map_cause_type), 0, "MAP cause" }},
		
		{ &hf_gtp_ext_ptmsi_sig,	{ "P-TMSI signature",	"gtp.ext.ptmsi_sig", 		FT_UINT24, 	BASE_HEX, NULL, 0, "P-TMSI signature" }},
		
		{ &hf_gtp_ext_ms,		{ "MS validated",		"gtp.ext.ms", 				FT_BOOLEAN,	BASE_NONE, NULL, 0, "MS validated" }},
		
		{ &hf_gtp_ext_recover,		{ "Restart counter",	"gtp.ext.recover", 			FT_UINT8, 	BASE_DEC, NULL, 0, "Restart counter" }},
		
		{ &hf_gtp_ext_sel_mode,		{ "Selection mode", 	"gtp.ext.sel_mode", 		FT_UINT8, 	BASE_DEC, VALS(sel_mode_type), 0, "Selection mode" }},
		
		{ &hf_gtp_ext_flow_label,	{ "Flow label", 		"gtp.ext.flow_label",		FT_UINT16, 	BASE_DEC, NULL, 0, "Flow label" }},
		
		{ &hf_gtp_ext_flow_sig,		{ "Flow label signature", "gtp.ext.flow_sig", 		FT_UINT16, 	BASE_DEC, NULL, 0, "Flow label signature" }},
		
		{ &hf_gtp_ext_flow_ii_nsapi,{ "NSAPI", 				"gtp.ext.flow_ii_nsapi", 	FT_UINT8, 	BASE_HEX, NULL, 0, "NSAPI" }},
		{ &hf_gtp_ext_flow_ii,		{ "Downlink flow label data", "gtp.ext.flow_ii", 	FT_UINT16, 	BASE_DEC, NULL, 0, "Downlink flow label data" }},
		
		{ &hf_gtp_ext_tr_comm,		{ "Transfer command",	"gtp.ext.tr_comm", 			FT_UINT8, 	BASE_DEC, VALS(tr_comm_type), 0, "Packet transfer command" }},
		{ &hf_gtp_ext_chrg_id,		{ "Charging ID", 		"gtp.ext.chrg_id", 			FT_UINT32, 	BASE_HEX, NULL, 0, "Charging ID" }},
		
		{ &hf_gtp_ext_user_addr,	{ "End user address", 	"gtp.ext.user_addr", 		FT_IPv4, 	BASE_DEC, NULL, 0, "End user address" }},
		{ &hf_gtp_ext_user_addr_pdp_type,	{ "PDP type", 	"gtp.ext.user_addr_pdp_type", 		FT_UINT8, 	BASE_HEX, VALS(pdp_type), 0, "PDP type" }},
		{ &hf_gtp_ext_user_addr_pdp_org,	{ "PDP type organization", 	"gtp.ext.user_addr_pdp_org", 		FT_UINT8, 	BASE_DEC, NULL, 0, "PDP type organization" }},
		
		{ &hf_gtp_ext_apn,		{ "APN", 				"gtp.ext.apn", 				FT_STRING, 	BASE_DEC, NULL, 0, "Access Point Name" }},
		
		{ &hf_gtp_ext_proto_conf,	{ "Protocol configuration", "gtp.ext.proto_conf",	FT_STRING, 	BASE_DEC, NULL, 0, "Protocol configuration" }},
		
		{ &hf_gtp_ext_gsn_addr,		{ "GSN address", 		"gtp.ext.gsn_addr", 		FT_IPv4, 	BASE_DEC, NULL, 0, "GSN address" }},
		
		{ &hf_gtp_ext_msisdn,		{ "MSISDN", 			"gtp.ext.msisdn", 			FT_STRING, 	BASE_DEC, NULL, 0, "MSISDN" }},

		{ &hf_gtp_ext_chrg_addr,	{ "CG address", 		"gtp.ext.chrg_addr", 		FT_IPv4, 	BASE_DEC, NULL, 0, "Charging gateway address" }},
		
		{ &hf_gtp_ext_node_addr,	{ "Node address", 		"gtp.ext.node_addr", 		FT_IPv4, 	BASE_DEC, NULL, 0, "Recommended node address" }},
		
		{ &hf_gtp_ext_ext_id,		{ "Ext id", 			"gtp.ext.ext_id", 			FT_UINT16, 	BASE_DEC, NULL, 0, "Extension id" }},
		{ &hf_gtp_ext_ext_val,		{ "Ext val", 			"gtp.ext.ext_val", 			FT_STRING, 	BASE_DEC, NULL, 0, "Extension value" }},
		
		{ &hf_gtp_ext_unknown,		{ "Unknown data (length)", "gtp.ext.unknown", 		FT_UINT16, 	BASE_DEC, NULL, 0, "Unknown data" }},

	};

	static gint *ett[] = {
		&ett_gtp,
		&ett_gtp_flags,
		&ett_gtp_ext,
		&ett_gtp_qos,
	};

	proto_gtp = proto_register_protocol("GPRS Tunneling Protocol", "GTP", "gtp");
	proto_register_field_array(proto_gtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gtp(void)
{
	dissector_add("udp.port", UDP_PORT_GTP, dissect_gtp, proto_gtp);
	dissector_add("tcp.port", TCP_PORT_GTP, dissect_gtp, proto_gtp);
/*	dissector_add("udp.port", UDP_PORT_GTP3C, dissect_gtp3, proto_gtp3);
	dissector_add("udp.port", UDP_PORT_GTP3U, dissect_gtp3, proto_gtp3);
	dissector_add("tcp.port", TCP_PORT_GTP3C, dissect_gtp3, proto_gtp3);
	dissector_add("tcp.port", TCP_PORT_GTP3U, dissect_gtp3, proto_gtp3);
*/
	
	ip_handle = find_dissector("ip");
	ppp_handle = find_dissector("ppp");
}
