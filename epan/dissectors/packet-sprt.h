/* packet-sprt.h
 *
 * Routines for SPRT dissection
 * SPRT = Simple Packet Relay Transport
 *
 * $Id$
 *
 * Written by Jamison Adcock <jamison.adcock@cobham.com>
 * for Sparta Inc., dba Cobham Analytic Solutions
 * This code is largely based on the RTP parsing code
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

#ifndef _PACKET_SPRT_H
#define _PACKET_SPRT_H


/* for some "range_string"s, there's only one value in the range  */
#define SPRT_VALUE_RANGE(a) a,a


/* TODO - conversation states */
#define SPRT_STATE_XXX_TODO 0


#define SPRT_CONV_MAX_SETUP_METHOD_SIZE	12

/* is DLCI field present in I_OCTET message?  See "DLCI enabled" in CONNECT message */
typedef enum {
	DLCI_UNKNOWN,
	DLCI_PRESENT,
	DLCI_ABSENT
} i_octet_dlci_status_t;



 /* Keep conversation info for one side of an SPRT conversation
  * TODO - this needs to be bidirectional
  */
struct _sprt_conversation_info
{
	gchar    method[SPRT_CONV_MAX_SETUP_METHOD_SIZE + 1];
	gboolean stream_started;
	guint32  frame_number;         /* the frame where this conversation is started */
	
	/* sequence numbers for each channel: */
	guint32 seqnum[4];
	
	/* are we using the DLCI field in I_OCTET messages?  See CONNECT message ("DLCI enabled") */
	i_octet_dlci_status_t i_octet_dlci_status;
	guint32 connect_frame_number; /* the CONNECT frame that tells us if the DLCI is enabled */

	/* TODO - maintain state */

};


void sprt_add_address(packet_info *pinfo,
					  address *addr,
					  int port,
					  int other_port,
					  const gchar *setup_method, 
					  guint32 setup_frame_number);



/* SPRT Message IDs: */
#define SPRT_MODEM_RELAY_MSG_ID_NULL			0
#define SPRT_MODEM_RELAY_MSG_ID_INIT			1
#define SPRT_MODEM_RELAY_MSG_ID_XID_XCHG		2
#define SPRT_MODEM_RELAY_MSG_ID_JM_INFO			3
#define SPRT_MODEM_RELAY_MSG_ID_START_JM		4
#define SPRT_MODEM_RELAY_MSG_ID_CONNECT			5
#define SPRT_MODEM_RELAY_MSG_ID_BREAK			6
#define SPRT_MODEM_RELAY_MSG_ID_BREAK_ACK		7
#define SPRT_MODEM_RELAY_MSG_ID_MR_EVENT		8
#define SPRT_MODEM_RELAY_MSG_ID_CLEARDOWN		9
#define SPRT_MODEM_RELAY_MSG_ID_PROF_XCHG		10
/* 11 -15 Reserved */
#define SPRT_MODEM_RELAY_MSG_ID_RESERVED1_START 11
#define SPRT_MODEM_RELAY_MSG_ID_RESERVED1_END	15
/* Data */
#define SPRT_MODEM_RELAY_MSG_ID_I_RAW_OCTET		16
#define SPRT_MODEM_RELAY_MSG_ID_I_RAW_BIT		17
#define SPRT_MODEM_RELAY_MSG_ID_I_OCTET			18
#define SPRT_MODEM_RELAY_MSG_ID_I_CHAR_STAT		19
#define SPRT_MODEM_RELAY_MSG_ID_I_CHAR_DYN		20
#define SPRT_MODEM_RELAY_MSG_ID_I_FRAME			21
#define SPRT_MODEM_RELAY_MSG_ID_I_OCTET_CS		22
#define SPRT_MODEM_RELAY_MSG_ID_I_CHAR_STAT_CS	23
#define SPRT_MODEM_RELAY_MSG_ID_I_CHAR_DYN_CS	24
/* 25 - 99 Reserved */
#define SPRT_MODEM_RELAY_MSG_ID_RESERVED2_START 25
#define SPRT_MODEM_RELAY_MSG_ID_RESERVED2_END	99
/* 100 - 127 Vendor-specific */
#define SPRT_MODEM_RELAY_MSG_ID_VENDOR_START	100
#define SPRT_MODEM_RELAY_MSG_ID_VENDOR_END		127


/* error correcting protocol in XID_XCHG message: */
#define SPRT_ECP_NO_LINK_LAYER_PROTO	0
#define SPRT_ECP_V42_LAPM				1
#define SPRT_ECP_ANNEX_AV42_1996		2
/* 3 - 25 Reserved for ITU-T */
#define SPRT_ECP_RESERVED_START			3
#define SPRT_ECP_RESERVED_END			25

	
/* category ID used in JM_INFO message: */
#define SPRT_JM_INFO_CAT_ID_CALL_FUNCT			0x8
#define SPRT_JM_INFO_CAT_ID_MOD_MODES			0xA
#define SPRT_JM_INFO_CAT_ID_PROTOCOLS			0x5
#define SPRT_JM_INFO_CAT_ID_PSTN_ACCESS			0xB
#define SPRT_JM_INFO_CAT_ID_PCM_MODEM_AVAIL		0xE
#define SPRT_JM_INFO_CAT_ID_CATEGORY_EXTENSION	0x0


#define SPRT_JMINFO_TBC_CALL_FUNCT_PSTN_MULTIMEDIA_TERM		0x4
#define SPRT_JMINFO_TBC_CALL_FUNCT_TEXTPHONE_ITU_T_REC_V18	0x2
#define SPRT_JMINFO_TBC_CALL_FUNCT_VIDEOTEXT_ITU_T_REC_T101 0x6				
#define SPRT_JMINFO_TBC_CALL_FUNCT_TRANS_FAX_ITU_T_REC_T30	0x1
#define SPRT_JMINFO_TBC_CALL_FUNCT_RECV_FAX_ITU_T_REC_T30	0x5
#define SPRT_JMINFO_TBC_CALL_FUNCT_DATA_V_SERIES_MODEM_REC	0x3


#define SPRT_JMINFO_TBC_PROTOCOL_LAPM_ITU_T_REC_V42		0x4


/* selected modulations in CONNECT message: */
#define SPRT_SELMOD_NULL		0
#define SPRT_SELMOD_V92			1
#define SPRT_SELMOD_V91			2
#define SPRT_SELMOD_V90			3
#define SPRT_SELMOD_V34			4
#define SPRT_SELMOD_V32_BIS		5
#define SPRT_SELMOD_V32			6
#define SPRT_SELMOD_V22_BIS		7
#define SPRT_SELMOD_V22			8
#define SPRT_SELMOD_V17			9
#define SPRT_SELMOD_V29			10
#define SPRT_SELMOD_V27_TER		11
#define SPRT_SELMOD_V26_TER		12
#define SPRT_SELMOD_V26_BIS		13
#define SPRT_SELMOD_V23			14
#define SPRT_SELMOD_V21			15
#define SPRT_SELMOD_BELL_212	16
#define SPRT_SELMOD_BELL_103	17
/* 18 - 30 Vendor-specific modulations */
#define SPRT_SELMOD_VENDOR_START	18
#define SPRT_SELMOD_VENDOR_END		30
/* 31 - 63 Reserved for ITU-T */
#define SPRT_SELMOD_RESERVED_START	31
#define SPRT_SELMOD_RESERVED_END	63


/* Compression direction in CONNECT message: */
#define SPRT_COMPR_DIR_NO_COMPRESSION	0
#define SPRT_COMPR_DIR_TRANSMIT			1
#define SPRT_COMPR_DIR_RECEIVE			2
#define SPRT_COMPR_DIR_BIDIRECTIONAL	3


/* Selected compression modes in CONNECT message: */
#define SPRT_SELECTED_COMPR_NONE			0
#define SPRT_SELECTED_COMPR_V42_BIS			1
#define SPRT_SELECTED_COMPR_V44				2
#define SPRT_SELECTED_COMPR_MNP5			3
/* 4 - 15 Reserved by ITU-T */
#define SPRT_SELECTED_COMPR_RESERVED_START	4
#define SPRT_SELECTED_COMPR_RESERVED_END	15


/* Selected error correction modes in CONNECT message: */
#define SPRT_SELECTED_ERR_CORR_V14_OR_NONE		0
#define SPRT_SELECTED_ERR_CORR_V42_LAPM			1
#define SPRT_SELECTED_ERR_CORR_ANNEX_AV42		2
/* 3 - 15 Reserved for ITU-T */
#define SPRT_SELECTED_ERR_CORR_RESERVED_START	3
#define SPRT_SELECTED_ERR_CORR_RESERVED_END		15


/* Break source protocol in BREAK message: */
#define SPRT_BREAK_SRC_PROTO_V42_LAPM			0
#define SPRT_BREAK_SRC_PROTO_ANNEX_AV42_1996	1
#define SPRT_BREAK_SRC_PROTO_V14				2
/* 3 - 15 Reserved for ITU-T */
#define SPRT_BREAK_SRC_PROTO_RESERVED_START		3
#define SPRT_BREAK_SRC_PROTO_RESERVED_END		15


#define SPRT_BREAK_TYPE_NOT_APPLICABLE					0
#define SPRT_BREAK_TYPE_DESTRUCTIVE_AND_EXPEDITED		1
#define SPRT_BREAK_TYPE_NONDESTRUCTIVE_AND_EXPEDITED	2
#define SPRT_BREAK_TYPE_NONDESTRUCTIVE_AND_NONEXPEDITED	3
/* 4 - 15 Reserved for ITU-T */
#define SPRT_BREAK_TYPE_RESERVED_START					4
#define SPRT_BREAK_TYPE_RESERVED_END					15


/* Modem relay info in MR_EVENT messages: */
#define SPRT_MREVT_EVENT_ID_NULL				0
#define SPRT_MREVT_EVENT_ID_RATE_RENEGOTIATION	1
#define SPRT_MREVT_EVENT_ID_RETRAIN				2
#define SPRT_MREVT_EVENT_ID_PHYSUP				3
/* 4 - 255 Reserved for ITU-T */
#define SPRT_MREVT_EVENT_ID_RESERVED_START		4
#define SPRT_MREVT_EVENT_ID_RESERVED_END		255


#define SPRT_MREVT_REASON_CODE_NULL				0
#define SPRT_MREVT_REASON_CODE_INIT				1
#define SPRT_MREVT_REASON_CODE_RESPONDING		2
/* 3 - 255 Undefined */
#define SPRT_MREVT_REASON_CODE_RESERVED_START	3
#define SPRT_MREVT_REASON_CODE_RESERVED_END		255


#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_NULL				0
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_600				1
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_1200				2
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_1600				3
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_2400				4
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_2743				5
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_3000				6
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_3200				7
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_3429				8
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_8000				9
/* 10 - 254 Reserved for ITU-T */
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_RESERVED_START	10
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_RESERVED_END		254
#define SPRT_MREVT_PHYS_LAYER_SYMBOL_RATE_UNSPECIFIED		255


/* Cleardown reason codes: */
#define SPRT_CLEARDOWN_RIC_UNKNOWN                     0
#define SPRT_CLEARDOWN_RIC_PHYSICAL_LAYER_RELEASE      1
#define SPRT_CLEARDOWN_RIC_LINK_LAYER_DISCONNECT       2
#define SPRT_CLEARDOWN_RIC_DATA_COMPRESSION_DISCONNECT 3
#define SPRT_CLEARDOWN_RIC_ABORT                       4
#define SPRT_CLEARDOWN_RIC_ON_HOOK                     5
#define SPRT_CLEARDOWN_RIC_NETWORK_LAYER_TERMINATION   6
#define SPRT_CLEARDOWN_RIC_ADMINISTRATIVE              7


/* PROF_XCHG messages (XID profile exchange for MR1): */
#define SPRT_PROF_XCHG_SUPPORT_NO		0
#define SPRT_PROF_XCHG_SUPPORT_YES		1
#define SPRT_PROF_XCHG_SUPPORT_UNKNOWN	2


/* DLCI field in I_OCTET: */
#define SPRT_PAYLOAD_DLCI1_DTE2DTE				0
#define SPRT_PAYLOAD_DLCI1_RESERVED_START		1
#define SPRT_PAYLOAD_DLCI1_RESERVED_END			31
#define SPRT_PAYLOAD_DLCI1_NOT_RESERVED_START	32
#define SPRT_PAYLOAD_DLCI1_NOT_RESERVED_END		62
#define SPRT_PAYLOAD_DLCI1_CTRLFN2CTRLFN		63

#define SPRT_PAYLOAD_DLCI2_START				0
#define SPRT_PAYLOAD_DLCI2_END					127

/* Payload fields for I_CHAR_STAT_CS, etc.: */
/* # of data bits */
#define SPRT_PAYLOAD_D_0		0
#define SPRT_PAYLOAD_D_1		1
#define SPRT_PAYLOAD_D_2		2
#define SPRT_PAYLOAD_D_3		3


/* parity */
#define SPRT_PAYLOAD_P_0	0
#define SPRT_PAYLOAD_P_1	1
#define SPRT_PAYLOAD_P_2	2
#define SPRT_PAYLOAD_P_3	3
#define SPRT_PAYLOAD_P_4	4
#define SPRT_PAYLOAD_P_5	5
#define SPRT_PAYLOAD_P_6	6
#define SPRT_PAYLOAD_P_7	7


/* # of stop bits */
#define SPRT_PAYLOAD_S_0	0
#define SPRT_PAYLOAD_S_1	1
#define SPRT_PAYLOAD_S_2	2
#define SPRT_PAYLOAD_S_3	3


/* data frame state */
#define SPRT_PAYLOAD_FR_0	0
#define SPRT_PAYLOAD_FR_1	1
#define SPRT_PAYLOAD_FR_2	2
#define SPRT_PAYLOAD_FR_3	3


#endif /* _PACKET_SPRT_H */
