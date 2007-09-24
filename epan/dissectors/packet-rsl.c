/* packet-rsl.c
 * Routines for Radio Signalling Link (RSL) dissection.
 *
 * Copyright 2007, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-cops.c
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
 *
 * REF: 3GPP TS 48.058 version 6.1.0 Release 6
 * http://www.3gpp.org/ftp/Specs/html-info/48058.htm
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/lapd_sapi.h>

#include "packet-gsm_a.h"

/* Initialize the protocol and registered fields */
static int proto_rsl		= -1;

static int hf_rsl_msg_type			= -1;
static int hf_rsl_T_bit				= -1;
static int hf_rsl_msg_dsc			= -1;
static int hf_rsl_ie_id				= -1;
static int hf_rsl_ie_length			= -1;
static int hf_rsl_ch_no_Cbits		= -1;
static int hf_rsl_ch_no_TN			= -1;

static int hf_rsl_acc_delay			= -1;
static int hf_rsl_req_ref_ra		= -1;
static int hf_rsl_req_ref_T1prim	= -1;
static int hf_rsl_req_ref_T3		= -1;
static int hf_rsl_req_ref_T2		= -1;
static int hf_rsl_ho_ref			= -1;
static int hf_rsl_ms_power_lev		= -1;
static int hf_rsl_ms_fpc			= -1;
static int hf_rsl_act_timing_adv	= -1;
static int hf_rsl_phy_ctx			= -1;
static int hf_rsl_na				= -1;
static int hf_rsl_ch_type			= -1;
static int hf_rsl_prio				= -1;
static int hf_rsl_sapi				= -1;
static int hf_rsl_rbit				= -1;
static int hf_rsl_a3a2				= -1;
static int hf_rsl_a1_0				= -1;
static int hf_rsl_a1_1				= -1;
static int hf_rsl_a1_2				= -1;
static int hf_rsl_epc_mode			= -1;
static int hf_rsl_fpc_epc_mode		= -1;
static int hf_rsl_bs_power			= -1;
static int hf_rsl_cm_dtxd			= -1;
static int hf_rsl_cm_dtxu			= -1;
static int hf_rsl_alg_id			= -1;
static int hf_rsl_key				= -1;
static int hf_rsl_cause				= -1;
static int hf_rsl_rel_mode			= -1;
static int hf_rsl_meas_res_no		= -1;
static int hf_rsl_extension_bit		= -1;
static int hf_rsl_dtxd				= -1;
static int hf_rsl_rxlev_full_up		= -1;
static int hf_rsl_rxlev_sub_up		= -1;
static int hf_rsl_rxqual_full_up	= -1;
static int hf_rsl_rxqual_sub_up		= -1;
static int hf_rsl_class				= -1;
static int hf_rsl_paging_grp		= -1;
static int hf_rsl_sys_info_type		= -1;
static int hf_rsl_timing_offset		= -1;
static int hf_rsl_ch_needed			= -1;
static int hf_rsl_emlpp_prio		= -1;

/* Initialize the subtree pointers */
static int ett_rsl = -1;
static int ett_ie_link_id = -1;
static int ett_ie_act_type = -1;
static int ett_ie_bs_power = -1;
static int ett_ie_ch_id = -1;
static int ett_ie_ch_mode = -1;
static int ett_ie_enc_inf = -1;
static int ett_ie_ch_no = -1;
static int ett_ie_frame_no = -1;
static int ett_ie_ho_ref = -1;
static int ett_ie_l1_inf = -1;
static int ett_ie_L3_inf = -1;
static int ett_ie_ms_id = -1;
static int ett_ie_phy_ctx = -1;
static int ett_ie_paging_grp = -1;
static int ett_ie_access_delay = -1;
static int ett_ie_req_ref = -1;
static int ett_ie_rel_mode = -1;
static int ett_ie_rlm_cause	=-1;
static int ett_ie_staring_time = -1;
static int ett_ie_uplik_meas = -1;
static int ett_ie_full_imm_ass_inf = -1;
static int ett_ie_ms_timing_offset = -1;
static int ett_ie_ch_needed = -1;
static int ett_ie_emlpp_prio = -1;
static int ett_ie_main_ch_ref = -1;
static int ett_ie_multirate_conf = -1;
static int ett_ie_cause = -1;
static int ett_ie_meas_res_no = -1;
static int ett_ie_message_id = -1;
static int ett_ie_sys_info_type = -1;

proto_tree *top_tree;
dissector_handle_t gsm_a_ccch_handle = NULL;
dissector_handle_t gsm_a_dtap_handle = NULL;

static const true_false_string rsl_t_bit_vals = {
  "Considered transparent by BTS",
  "Not considered transparent by BTS"
};

static const true_false_string rsl_na_vals = {
  "Not Applicable",
  "Applicable"
};

static const true_false_string rsl_extension_bit_value = {
  "Extension",
  "No Extension"
};

/*
 * 9.1 Message discriminator
 */
static const value_string rsl_msg_disc_vals[] = {
	{  0x00,		"Reserved" },
	{  0x01,		"Radio Link Layer Management messages" },
	{  0x04,		"Dedicated Channel Management messages" },
	{  0x06,		"Common Channel Management messages" },
	{  0x08,		"TRX Management messages" },
	{  0x16,		"Location Services messages" },
	{ 0,			NULL }
};
/*
 * 9.2 MESSAGE TYPE
 */
#define RSL_MSG_TYPE_DATA_REQ		1
#define RSL_MSG_TYPE_DATA_IND		2
#define RSL_MSG_TYPE_ERROR_IND		3
#define RSL_MSG_TYPE_EST_REQ		4
#define RSL_MSG_TYPE_EST_CONF		5
#define RSL_MSG_EST_IND				6
#define RSL_MSG_REL_REQ				7
#define RSL_MSG_REL_CONF			8
#define RSL_MSG_REL_IND				9
#define RSL_MSG_UNIT_DATA_REQ		10
/* Common Channel Management/TRX Management messages */
#define RSL_MSG_BCCH_INFO			17
#define RSL_MSG_CCCH_LOAD_IND		18
#define RSL_MSG_CHANRQD				19
#define RSL_MSG_DELETE_IND			20
#define RSL_MSG_PAGING_CMD			21
#define RSL_MSG_IMM_ASS_CMD			22
#define RSL_MSG_SMS_BC_REQ			23	/* 8.5.7 */
#define RSL_MSG_RF_RES_IND			24	/* 8.6.1 */
#define RSL_MSG_SACCH_FILL			25	/* 8.6.2 */

#define RSL_MSG_OVERLOAD			27	/* 8.6.3 */
#define RSL_MSG_ERROR_REPORT		28	/* 8.6.4 */
#define RSL_MSG_SMS_BC_CMD			29	/* 8.5.8 */
#define RSL_MSG_CBCH_LOAD_IND		30	/* 8.5.9 */
#define RSL_MSG_NOT_CMD				31	/* 8.5.10 */

/* 0 0 1 - - - - - Dedicated Channel Management messages: */
#define RSL_MSG_CHAN_ACTIV			33
#define RSL_MSG_CHAN_ACTIV_ACK		34
#define RSL_MSG_CHAN_ACTIV_N_ACK	35
#define RSL_MSG_CONN_FAIL			36
#define RSL_MSG_DEACTIVATE_SACCH	37
 
#define RSL_MSG_ENCR_CMD				38	/* 8.4.6 */
#define RSL_MSG_HANDODET				39	/* 8.4.7 */
#define RSL_MSG_MEAS_RES				40	/* 8.4.8 */
#define RSL_MSG_MODE_MODIFY_REQ			41	/* 8.4.9 */
#define RSL_MSG_MODE_MODIFY_ACK			42	/* 8.4.10 */
#define RSL_MSG_MODE_MODIFY_NACK		43	/* 8.4.11 */
#define RSL_MSG_PHY_CONTEXT_REQ			44	/* 8.4.12 */
#define RSL_MSG_PHY_CONTEXT_CONF		45	/* 8.4.13 */
#define RSL_MSG_RF_CHAN_REL				46	/* 8.4.14 */
#define RSL_MSG_MS_POWER_CONTROL		47	/* 8.4.15 */
#define RSL_MSG_BS_POWER_CONTROL		48	/* 8.4.16 */
#define RSL_MSG_PREPROC_CONFIG			49	/* 8.4.17 */
#define RSL_MSG_PREPROC_MEAS_RES		50	/* 8.4.18 */
#define RSL_MSG_RF_CHAN_REL_ACK			51	/* 8.4.19 */
#define RSL_MSG_SACCH_INFO_MODIFY		52	/* 8.4.20 */
#define RSL_MSG_TALKER_DET				53	/* 8.4.21 */
#define RSL_MSG_LISTENER_DET			54	/* 8.4.22 */
#define RSL_MSG_REMOTE_CODEC_CONF_REP	55	/* 8.4.23 */
#define RSL_MSG_R_T_D_REP				56	/* 8.4.24 */
#define RSL_MSG_PRE_HANDO_NOTIF			57	/* 8.4.25 */
#define RSL_MSG_MR_CODEC_MOD_REQ		58	/* 8.4.26 */
#define RSL_MSG_MR_CODEC_MOD_ACK		59	/* 8.4.27 */
#define RSL_MSG_MR_CODEC_MOD_NACK		60	/* 8.4.28 */
#define RSL_MSG_MR_CODEC_MOD_PER		61	/* 8.4.29 */
#define RSL_MSG_TFO_REP					62	/* 8.4.30 */
#define RSL_MSG_TFO_MOD_REQ				63	/* 8.4.31 */
	/* 	0 1 - - - - - - Location Services messages: */
#define RSL_MSG_LOC_INF					65	/* 8.7.1 */


static const value_string rsl_msg_type_vals[] = {
	  /* 	0 0 0 0 - - - - Radio Link Layer Management messages: */
	{  0x01,	"DATA REQuest" },								/* 8.3.1 */
	{  0x02,	"DATA INDication" },							/* 8.3.2 */
	{  0x03,	"ERROR INDication" },							/* 8.3.3 */
	{  0x04,	"ESTablish REQuest" },							/* 8.3.4 */
	{  0x05,	"ESTablish CONFirm" },							/* 8.3.5 */
	{  0x06,	"ESTablish INDication" },						/* 8.3.6 */
	{  0x07,	"RELease REQuest" },							/* 8.3.7 */
	{  0x08,	"RELease CONFirm" },							/* 8.3.8 */
	{  0x09,	"RELease INDication" },							/* 8.3.9 */
	{  0x0a,	"UNIT DATA REQuest" },							/* 8.3.10 */
	/* 0 0 0 1 - - - - Common Channel Management/TRX Management messages: */
	{  0x11,	"BCCH INFOrmation" },							/* 8.5.1 */
	{  0x12,	"CCCH LOAD INDication" },						/* 8.5.2 */
	{  0x13,	"CHANnel ReQuireD" },							/* 8.5.3 */
	{  0x14,	"DELETE INDication" },							/* 8.5.4 */
	{  0x15,	"PAGING CoMmanD" },								/* 8.5.5 */
	{  0x16,	"IMMEDIATE ASSIGN COMMAND" },					/* 8.5.6 */
	{  0x17,	"SMS BroadCast REQuest" },						/* 8.5.7 */
	{  0x18,	"RF RESource INDication" },						/* 8.6.1 */
	{  0x19,	"SACCH FILLing" },								/* 8.6.2 */
	{  0x1b,	"OVERLOAD" },									/* 8.6.3 */
	{  0x1c,	"ERROR REPORT" },								/* 8.6.4 */
	{  0x1d,	"SMS BroadCast CoMmanD" },						/* 8.5.8 */
	{  0x1e,	"CBCH LOAD INDication" },						/* 8.5.9 */
	{  0x1f,	"NOTification CoMmanD" },						/* 8.5.10 */
	/* 0 0 1 - - - - - Dedicated Channel Management messages: */
	{  0x21,	"CHANnel ACTIVation" },							/* 8.4.1 */
	{  0x22,	"CHANnel ACTIVation ACKnowledge" },				/* 8.4.2 */
	{  0x23,	"CHANnel ACTIVation Negative ACK" },			/* 8.4.3 */
	{  0x24,	"CONNection FAILure" },							/* 8.4.4 */
	{  0x25,	"DEACTIVATE SACCH" },							/* 8.4.5 */
	{  0x26,	"ENCRyption CoMmanD" },							/* 8.4.6 */
	{  0x27,	"HANDOver DETection" },							/* 8.4.7 */
	{  0x28,	"MEASurement RESult" },							/* 8.4.8 */
	{  0x29,	"MODE MODIFY REQuest" },						/* 8.4.9 */
	{  0x2a,	"MODE MODIFY ACKnowledge" },					/* 8.4.10 */
	{  0x2b,	"MODE MODIFY Negative ACKnowledge" },			/* 8.4.11 */
	{  0x2c,	"PHYsical CONTEXT REQuest" },					/* 8.4.12 */
	{  0x2d,	"PHYsical CONTEXT CONFirm" },					/* 8.4.13 */
	{  0x2e,	"RF CHANnel RELease" },							/* 8.4.14 */
	{  0x2f,	"MS POWER CONTROL" },							/* 8.4.15 */
	{  0x30,	"BS POWER CONTROL" },							/* 8.4.16 */
	{  0x31,	"PREPROCess CONFIGure" },						/* 8.4.17 */
	{  0x32,	"PREPROCessed MEASurement RESult" },			/* 8.4.18 */
	{  0x33,	"RF CHANnel RELease ACKnowledge" },				/* 8.4.19 */
	{  0x34,	"SACCH INFO MODIFY" },							/* 8.4.20 */
	{  0x35,	"TALKER DETection" },							/* 8.4.21 */
	{  0x36,	"LISTENER DETection" },							/* 8.4.22 */
	{  0x37,	"REMOTE CODEC CONFiguration REPort" },			/* 8.4.23 */
	{  0x38,	"Round Trip Delay REPort" },					/* 8.4.24 */
	{  0x39,	"PRE-HANDOver NOTIFication" },					/* 8.4.25 */
	{  0x3a,	"MultiRate CODEC MODification REQest" },		/* 8.4.26 */
	{  0x3b,	"MultiRate CODEC MOD ACKnowledge" },			/* 8.4.27 */
	{  0x3c,	"MultiRate CODEC MOD Negative ACKnowledge" },	/* 8.4.28 */
	{  0x3d,	"MultiRate CODEC MOD PERformed" },				/* 8.4.29 */
	{  0x3e,	"TFO REPort" },									/* 8.4.30 */
	{  0x3f,	"TFO MODification REQuest" },					/* 8.4.31 */
	/* 	0 1 - - - - - - Location Services messages: */
	{  0x41,	"Location Information" },						/* 8.7.1 */
	{ 0,		NULL }
};

#define RSL_IE_CH_NO			1
#define RSL_IE_LINK_ID			2

#define RSL_IE_BS_POW			4
#define RSL_IE_CH_ID			5
#define RSL_IE_CH_MODE			6

#define RSL_IE_FRAME_NO			8
#define RSL_IE_HO_REF			9
#define RSL_IE_L1_INF			10
#define RSL_IE_L3_INF			11
#define RSL_IE_MS_ID			12
#define RSL_IE_MS_POW			13
#define RSL_IE_PAGING_GRP		14

#define RSL_IE_PHY_CTX			16
#define RSL_IE_ACCESS_DELAY		17

#define RSL_IE_REQ_REF			19
#define RSL_IE_REL_MODE			20

#define RSL_IE_RLM_CAUSE		22
#define RSL_IE_STARTING_TIME	23

#define RSL_IE_UPLINK_MEAS		25
#define RSL_IE_CAUSE			26
#define RSL_IE_MEAS_RES_NO		27
#define RSL_IE_MESSAGE_ID		28

#define RSL_IE_SYS_INFO_TYPE	30




#define RSL_IE_FULL_IMM_ASS_INF 35

#define RSL_IE_FULL_MS_TIMING_OFFSET	37


#define RSL_IE_CH_NEEDED				40


#define RSL_IE_EMLPP_PRIO				51
#define RSL_IE_MAIN_CH_REF				53
#define RSL_IE_MULTIRATE_CONF			54
	
static const value_string rsl_ie_type_vals[] = {
	{  0x01,	"Channel Number" },				/*  9.3.1 */
	{  0x02,	"Link Identifier" },			/*  9.3.2 */
	{  0x03,	"Activation Type" },			/*  9.3.3 */
	{  0x04,	"BS Power" },					/*  9.3.4 */
	{  0x05,	"Channel Identification" },		/*  9.3.5 */
	{  0x06,	"Channel Mode" },				/*  9.3.6 */
	{  0x07,	"Encryption Information" },		/*  9.3.7 */
	{  0x08,	"Frame Number" },				/*  9.3.8 */
	{  0x09,	"Handover Reference" },			/*  9.3.9 */
	{  0x0a,	"L1 Information" },				/*  9.3.10 */
	{  0x0b,	"L3 Information" },				/*  9.3.11 */
	{  0x0c,	"MS Identity" },				/*  9.3.12 */
	{  0x0d,	"MS Power" },					/*  9.3.13 */
	{  0x0e,	"Paging Group" },				/*  9.3.14 */
	{  0x0f,	"Paging Load" },				/*  9.3.15 */
	{  0x10,	"Physical Context" },			/*  9.3.16 */
	{  0x11,	"Access Delay" },				/*  9.3.17 */
	{  0x12,	"RACH Load" },					/*  9.3.18 */
	{  0x13,	"Request Reference" },			/*  9.3.19 */
	{  0x14,	"Release Mode" },				/*  9.3.20 */
	{  0x15,	"Resource Information" },		/*  9.3.21 */
	{  0x16,	"RLM Cause" },					/*  9.3.22 */
	{  0x17,	"Starting Time" },				/*  9.3.23 */
	{  0x18,	"Timing Advance" },				/*  9.3.24 */
	{  0x19,	"Uplink Measurements" },		/*  9.3.25 */
	{  0x1a,	"Cause" },						/*  9.3.26 */
	{  0x1b,	"Measurement result number" },	/*  9.3.27 */
	{  0x1c,	"Message Identifier" },			/*  9.3.28 */
	{  0x1d,	"reserved" },					/*  */
	{  0x1e,	"System Info Type" },			/*  9.3.30 */
	{  0x1f,	"MS Power Parameters" },		/*  9.3.31 */
	{  0x20,	"BS Power Parameters" },		/*  9.3.32 */
	{  0x21,	"Pre-processing Parameters" },	/*  9.3.33 */
	{  0x22,	"Pre-processed Measurements" },	/*  9.3.34 */
	{  0x23,	"reserved" },					/*  */
	{  0x24,	"SMSCB Information" },			/*  9.3.36 */
	{  0x25,	"MS Timing Offset" },			/*  9.3.37 */
	{  0x26,	"Erroneous Message" },			/*  9.3.38 */
	{  0x27,	"Full BCCH Information" },		/*  9.3.39 */
	{  0x28,	"Channel Needed" },				/*  9.3.40 */
	{  0x29,	"CB Command type" },			/*  9.3.41 */
	{  0x2a,	"SMSCB message" },				/*  9.3.42 */
	{  0x2b,	"Full Immediate Assign Info" },	/*  9.3.35 */
	{  0x2c,	"SACCH Information" },			/*  9.3.29 */
	{  0x2d,	"CBCH Load Information" },		/*  9.3.43 */
	{  0x2e,	"SMSCB Channel Indicator" },	/*  9.3.44 */
	{  0x2f,	"Group call reference" },		/*  9.3.45 */
	{  0x30,	"Channel description" },		/*  9.3.46 */
	{  0x31,	"NCH DRX information" },		/*  9.3.47 */
	{  0x32,	"Command indicator" },			/*  9.3.48 */
	{  0x33,	"eMLPP Priority" },				/*  9.3.49 */
	{  0x34,	"UIC" },						/*  9.3.50 */
	{  0x35,	"Main channel reference" },		/*  9.3.51 */
	{  0x36,	"MultiRate configuration" },	/*  9.3.52 */
	{  0x37,	"MultiRate Control" },			/*  9.3.53 */
	{  0x38,	"Supported Codec Types" },		/*  9.3.54 */
	{  0x39,	"Codec Configuration" },		/*  9.3.55 */
	{  0x3a,	"Round Trip Delay" },			/*  9.3.56 */
	{  0x3b,	"TFO Status" },					/*  9.3.57 */
	{  0x3c,	"LLP APDU" },					/*  9.3.58 */
	{  0x3d,	"TFO transparent container" },	/*  9.3.59 */
	/*
			0 0 1 1 1 1 1 0
			to
			1 1 1 0 1 1 1 1
			Reserved for future use

			1 1 1 1 0 0 0 0
			to
			1 1 1 1 1 1 1 1
			Not used

	*/
	{ 0,			NULL }
};


/*
C5	C4	C3	C2	C1
0	0	0	0	1	Bm + ACCH's
0	0	0	1	T	Lm + ACCH's
0	0	1	T	T	SDCCH/4 + ACCH
0	1	T	T	T	SDCCH/8 + ACCH
1	0	0	0	0	BCCH
1	0	0	0	1	Uplink CCCH (RACH)
1	0	0	1	0	Downlink CCCH (PCH + AGCH)
*/
static const value_string rsl_ch_no_Cbits_vals[] = {
	{  0x01,	"Bm + ACCH's" },
	{  0x03,	"Lm + ACCH's" },
	{  0x03,	"Lm + ACCH's" },
	{  0x04,	"SDCCH/4 + ACCH" },
	{  0x05,	"SDCCH/4 + ACCH" },
	{  0x06,	"SDCCH/4 + ACCH" },
	{  0x07,	"SDCCH/4 + ACCH" },
	{  0x08,	"SDCCH/8 + ACCH" },
	{  0x09,	"SDCCH/8 + ACCH" },
	{  0x0a,	"SDCCH/8 + ACCH" },
	{  0x0b,	"SDCCH/8 + ACCH" },
	{  0x0c,	"SDCCH/8 + ACCH" },
	{  0x0d,	"SDCCH/8 + ACCH" },
	{  0x0e,	"SDCCH/8 + ACCH" },
	{  0x0f,	"SDCCH/8 + ACCH" },
	{  0x10,	"BCCH" },
	{  0x11,	"Uplink CCCH (RACH)" },
	{  0x12,	"Downlink CCCH (PCH + AGCH)" },
	{ 0,			NULL }
};

/* 9.3.1 Channel number			9.3.1	M TV 2 */
static int
dissect_rsl_ie_ch_no(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_CH_NO)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,2,"Channel number IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_ch_no);


	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* C-bits */
	proto_tree_add_item(ie_tree, hf_rsl_ch_no_Cbits, tvb, offset, 1, FALSE);
	/* TN is time slot number, binary represented as in 3GPP TS 45.002.
	 * 3 Bits
	 */
	proto_tree_add_item(ie_tree, hf_rsl_ch_no_TN, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}

static const value_string rsl_ch_type_vals[] = {
	{  0x00,	"Main signalling channel (FACCH or SDCCH)" },
	{  0x01,	"SACCH" },
	{ 0,			NULL }
};

static const value_string rsl_prio_vals[] = {
	{  0x00,	"Normal Priority" },
	{  0x01,	"High Priority" },
	{  0x02,	"Low Priority" },
	{ 0,			NULL }
};

/*
 * 9.3.2 Link Identifier M TV 2
 */
static int
dissect_rsl_ie_link_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 octet;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_LINK_ID)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,2,"Link Identifier IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_link_id);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	octet = tvb_get_guint8(tvb,offset);

	if((octet&0x20) == 0x20){
		/* Not applicable */
		proto_tree_add_item(ie_tree, hf_rsl_na, tvb, offset, 1, FALSE);
		return offset++;
	}
	/* channel type */
	proto_tree_add_item(ie_tree, hf_rsl_ch_type, tvb, offset, 1, FALSE);
	/* NA - Not applicable */
	proto_tree_add_item(ie_tree, hf_rsl_na, tvb, offset, 1, FALSE);
	/* Priority */
	proto_tree_add_item(ie_tree, hf_rsl_prio, tvb, offset, 1, FALSE);
	/* SAPI
	 * The SAPI field contains the SAPI value as defined in 3GPP TS 44.005.
	 */
	proto_tree_add_item(ie_tree, hf_rsl_sapi, tvb, offset, 1, FALSE);
	offset++;

	return offset;
}

/*
 * 9.3.3 Activation Type
 */
static const true_false_string rsl_rbit_vals = {
  "Reactivation",
  "Initial activation"
};

static const value_string rsl_a3a2_vals[] = {
	{  0x00,	"Activation related to intra-cell channel change" },
	{  0x01,	"Activation related to inter-cell channel change (handover)" },
	{  0x02,	"Activation related to secondary channels" },
	{ 0,			NULL }
};

static const true_false_string rsl_a1_0_vals = {
  "related to normal assignment procedure",
  "related to immediate assignment procedure"
};

static const true_false_string rsl_a1_1_vals = {
  "related to synchronous handover procedure",
  "related to asynchronous handover procedure"
};

static const true_false_string rsl_a1_2_vals = {
  "related to multislot configuration",
  "related to additional assignment procedure"
};

static int
dissect_rsl_ie_act_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;
	guint	octet;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_CH_NO)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,2,"Activation Type IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_act_type);


	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* The R bit indicates if the procedure is an initial activation or a reactivation. */
	proto_tree_add_item(ie_tree, hf_rsl_rbit, tvb, offset, 1, FALSE);

	/* The A-bits indicate the type of activation, which defines the access procedure 
	 * and the operation of the data link layer
	 */
	octet = (tvb_get_guint8(tvb,offset) & 0x06)>>1;
	proto_tree_add_item(ie_tree, hf_rsl_a3a2, tvb, offset, 1, FALSE);
	switch(octet){
	case 0:
		/* Activation related to intra-cell channel change */
		proto_tree_add_item(ie_tree, hf_rsl_a1_0, tvb, offset, 1, FALSE);
		break;
	case 1:
		/* Activation related to inter-cell channel change (handover) */
		proto_tree_add_item(ie_tree, hf_rsl_a1_1, tvb, offset, 1, FALSE);
		break;
	case 2:
		/* Activation related to secondary channels */
		proto_tree_add_item(ie_tree, hf_rsl_a1_2, tvb, offset, 1, FALSE);
		break;
	default:
		break;
	}
	offset++;

	return offset;
}
/*
 * 9.3.4 BS Power
 */

static const true_false_string rsl_epc_mode_vals = {
  "Channel in EPC mode",
  "Channel not in EPC mode"
};

static const true_false_string rsl_fpc_epc_mode_vals = {
  "Fast Power Control in use",
  "Fast Power Control not in use"
};

static const value_string rsl_rlm_bs_power_vals[] = {
	{  0x00,	"Pn" },
	{  0x01,	"Pn - 2 dB" },
	{  0x02,	"Pn - 4 dB" },
	{  0x03,	"Pn - 6 dB" },
	{  0x04,	"Pn - 8 dB" },
	{  0x05,	"Pn - 10 dB" },
	{  0x06,	"Pn - 12 dB" },
	{  0x07,	"Pn - 14 dB" },
	{  0x08,	"Pn - 16 dB" },
	{  0x09,	"Pn - 18 dB" },
	{  0x0a,	"Pn - 20 dB" },
	{  0x0b,	"Pn - 22 dB" },
	{  0x0c,	"Pn - 24 dB" },
	{  0x0d,	"Pn - 26 dB" },
	{  0x0e,	"Pn - 28 dB" },
	{  0x0f,	"Pn - 30 dB" },
	{ 0,			NULL }
};

static int
dissect_rsl_ie_bs_power(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_BS_POW)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,3,"BS Power IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_bs_power);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* EPC mode */
	proto_tree_add_item(ie_tree, hf_rsl_epc_mode, tvb, offset, 1, FALSE);
	/* FPC_EPC mode */
	proto_tree_add_item(ie_tree, hf_rsl_fpc_epc_mode, tvb, offset, 1, FALSE);

	/* The Power Level field (octet 2) indicates the number of 2 dB steps by 
	 * which the power shall be reduced from its nominal value, Pn, 
	 * set by the network operator to adjust the coverage. 
	 * Thus the Power Level values correspond to the following powers (relative to Pn):
	 */
	proto_tree_add_item(ie_tree, hf_rsl_bs_power, tvb, offset, 1, FALSE);
	offset++;

	return offset;
}
/*
 * 9.3.5 Channel Identification
 */
static int
dissect_rsl_ie_ch_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 length;
	int ie_offset;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_CH_ID)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Channel Identification IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_ch_id);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_guint8(tvb, offset);
	proto_item_set_len(ti, length+1);
	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);
 	offset++;

	ie_offset = offset;

	/* 3GPP TS 44.018 "Channel Description" */
	de_rr_ch_dsc(tvb, ie_tree, offset, length, NULL, 0);
	/*
	 * The 3GPP TS 24.008 "Mobile Allocation" shall for compatibility reasons be
	 * included but empty, i.e. the length shall be zero.
	 */
	return ie_offset + length;
}
/*
 * 9.3.6 Channel Mode
 */

static const true_false_string rsl_dtx_vals = {
  "DTX is applied",
  "DTX is not applied"
};

static int
dissect_rsl_ie_ch_mode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 length;
	int ie_offset;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_CH_MODE)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Channel Mode IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_ch_mode);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_guint8(tvb, offset);
	proto_item_set_len(ti, length+1);
	offset++;
	ie_offset = offset;
	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);
 	offset++;

	/* The DTX bits of octet 3 indicate whether DTX is applied
	 * DTXd indicates use of DTX in the downlink direction (BTS to MS) and 
	 * DTXu indicates use of DTX in the uplink direction (MS to BTS).
	 */
	proto_tree_add_item(ie_tree, hf_rsl_cm_dtxd, tvb, offset, 1, FALSE);
	proto_tree_add_item(ie_tree, hf_rsl_cm_dtxu, tvb, offset, 1, FALSE);
	offset++;
	/* The "Speech or data indicator" field (octet 4) */

	return ie_offset + length;

}

/*
 * 9.3.7 Encryption information
 */

/* The Algorithm Identifier field (octet 3) indicates the relevant ciphering algorithm. It is coded as: */
static const value_string rsl_algorithm_id_vals[] = {
	{  0x00,	"Pn" },
	{  0x00,	"Reserved" },
	{  0x01,	"No encryption shall be used" },
	{  0x02,	"GSM encryption algorithm version 1 (A5/1)" },
	{  0x03,	"GSM A5/2" },
	{  0x04,	"GSM A5/3" },
	{  0x05,	"GSM A5/4" },
	{  0x06,	"GSM A5/5" },
	{  0x07,	"GSM A5/6" },
	{  0x08,	"GSM A5/7" },
	{ 0,			NULL }
};

static int
dissect_rsl_ie_enc_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 length;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_L3_INF)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Encryption information IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_enc_inf);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_guint8(tvb, offset);
	proto_item_set_len(ti, length+1);
	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);
 	offset++;

	/* Algorithm Identifier field (octet 3) */

	proto_tree_add_item(ie_tree, hf_rsl_alg_id, tvb, offset, 1, FALSE);

	/* key */
	proto_tree_add_item(ie_tree, hf_rsl_key, tvb, offset+1, length -1, FALSE);

	return offset + length;

}
/*
 * 9.3.8 Frame Number
 */
static int
dissect_rsl_ie_frame_no(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_FRAME_NO)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Frame Number IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_frame_no);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	proto_tree_add_item(ie_tree, hf_rsl_req_ref_T1prim, tvb, offset, 1, FALSE);
	proto_tree_add_item(ie_tree, hf_rsl_req_ref_T3, tvb, offset, 2, FALSE);
	offset++;
	proto_tree_add_item(ie_tree, hf_rsl_req_ref_T2, tvb, offset, 1, FALSE);
	offset++;

	return offset;
}

/*
 * 9.3.9 Handover reference
 */
static int
dissect_rsl_ie_ho_ref(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_HO_REF)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Handover reference IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_ho_ref);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	
	/* Hand-over reference */
	proto_tree_add_item(ie_tree, hf_rsl_ho_ref, tvb, offset, 1, FALSE);
	offset++;

	return offset;
}

/*
 * 9.3.10 L1 Information
 */

static int
dissect_rsl_ie_l1_inf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_L1_INF)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset, 3,"L1 Information IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_l1_inf);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* Octets 2-3 contain the L1 header information of SACCH blocks.
	 * The information fields and codings are as defined in 3GPP TS 44.004.
	 */

	/* MS power level */
	proto_tree_add_item(ie_tree, hf_rsl_ms_power_lev, tvb, offset, 1, FALSE);
	/* FPC */
	proto_tree_add_item(ie_tree, hf_rsl_ms_fpc, tvb, offset, 1, FALSE);
	/* Reserved */
	offset++;
	/* Actual Timing Advance */
	proto_tree_add_item(ie_tree, hf_rsl_act_timing_adv, tvb, offset, 1, FALSE);
	offset++;

	return offset;
}

/*
 * 9.3.11 L3 Information			9.3.11	M TLV >=3
 *
 * This element contains a link layer service data unit (L3 message).
 * It is used to forward a complete L3 message as specified in
 * 3GPP TS 24.008 or 3GPP TS 44.018 between BTS and BSC.
 */
static int
dissect_rsl_ie_L3_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	tvbuff_t	*next_tvb;
	guint16 length;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_L3_INF)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"L3 Information IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_L3_inf);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_ntohs(tvb, offset);
	proto_item_set_len(ti, length+2);
	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 2, FALSE);
 	offset= offset +2;

	/* Link Layer Service Data Unit (i.e. a layer 3 message
	 * as defined in 3GPP TS 24.008 or 3GPP TS 44.018)
	 */

	proto_tree_add_text(ie_tree, tvb,offset,length,"Link Layer Service Data Unit ( L3 Message)");
	next_tvb = tvb_new_subset(tvb, offset, length, length);
	call_dissector(gsm_a_dtap_handle, next_tvb, pinfo, top_tree);

	offset = offset + length;

	return offset;
 }

/*
 * 9.3.12 MS Identity
 */
static int
dissect_rsl_ie_ms_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint length;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_MS_ID)
			return offset;
	}
	ti = proto_tree_add_text(tree, tvb,offset,0,"MS Identity IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_ms_id);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_guint8(tvb,offset);
	proto_item_set_len(ti, length+2);
	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);
	offset++;

	de_mid(tvb, ie_tree, offset, length, NULL, 0);

	offset = offset + length;

	return offset;
}
/*
 * 9.3.14 Paging Group M TV 2 2
 */
static int
dissect_rsl_ie_paging_grp(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_PAGING_GRP)
			return offset;
	}
	ti = proto_tree_add_text(tree, tvb,offset,0,"Paging Group IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_paging_grp);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* The Paging Group field (octet 2) contains the binary representation of the paging 
	 * group as defined in 3GPP TS 45.002.
	 */
	proto_tree_add_item(ie_tree, hf_rsl_paging_grp, tvb, offset, 1, FALSE);

	return offset;

}
/*
 * 9.3.16 Physical Context TLV
 */
static int
dissect_rsl_ie_phy_ctx(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint length;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_PHY_CTX)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Physical Context IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_phy_ctx);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_guint8(tvb,offset);
	proto_item_set_len(ti, length+2);
	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);
	offset++;

	/*
	 * Physical Context Information:
	 *	The Physical Context Information field is not specified.
	 *	This information should not be analysed by BSC, but merely
	 *	forwarded from one TRX/channel to another.
	 */
	proto_tree_add_item(ie_tree, hf_rsl_phy_ctx, tvb, offset, length, FALSE);
	offset = offset + length;

	return offset;
}
/*
 * 9.3.17 Access Delay M TV 2
 */
static int
dissect_rsl_ie_access_delay(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_ACCESS_DELAY)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,2,"Access Delay IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_access_delay);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(ie_tree, hf_rsl_acc_delay, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}
/*
 * 9.3.19 Request Reference M TV 4
 */
static int
dissect_rsl_ie_req_ref(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_REQ_REF)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,4,"Request Reference IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_req_ref);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(ie_tree, hf_rsl_req_ref_ra, tvb, offset, 1, FALSE);
	offset++;
	proto_tree_add_item(ie_tree, hf_rsl_req_ref_T1prim, tvb, offset, 1, FALSE);
	proto_tree_add_item(ie_tree, hf_rsl_req_ref_T3, tvb, offset, 2, FALSE);
	offset++;
	proto_tree_add_item(ie_tree, hf_rsl_req_ref_T2, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}

static const value_string rel_mode_vals[] = {
	{  0x00,	"Normal Release" },
	{  0x01,	"Local End Release" },
	{ 0,			NULL }
};

/*
 * 9.3.20 Release Mode				9.3.20	M TV 2
 */
static int
dissect_rsl_ie_rel_mode(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_REL_MODE)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,4,"Release Mode IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_rel_mode);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* 	The M bit is coded as follows:
	 * 0 normal release
	 * 1 local end release
	 */
	proto_tree_add_item(ie_tree, hf_rsl_rel_mode, tvb, offset, 1, FALSE);

	offset++;
	return offset;
}

static const value_string rsl_rlm_cause_vals[] = {
	{  0x00,	"reserved" },
	{  0x01,	"timer T200 expired (N200+1) times" },
	{  0x02,	"re-establishment request" },
	{  0x03,	"unsolicited UA response" },
	{  0x04,	"unsolicited DM response" },
	{  0x05,	"unsolicated DM response, multiple frame established state" },
	{  0x06,	"unsolicited supervisory response" },
	{  0x07,	"sequence error" },
	{  0x08,	"U-frame with incorrect parameters" },
	{  0x09,	"S-frame with incorrect parameters" },
	{  0x0a,	"I-frame with incorrect use of M bit" },
	{  0x0b,	"I-frame with incorrect length" },
	{  0x0c,	"frame not implemented" },
	{  0x0d,	"SABM command, multiple frame established state" },
	{  0x0e,	"SABM frame with information not allowed in this state" },
	{ 0,			NULL }
};


/*
 * 9.3.22 RLM Cause				9.3.22	M TLV 2-4
 */
static int
dissect_rsl_ie_rlm_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;

	guint		length;
	guint8		octet;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_RLM_CAUSE)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"RLM Cause IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_rlm_cause);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_guint8(tvb,offset);
	proto_item_set_len(ti, length+2);

	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);
	offset++;

	/* The Cause Value is a one octet field if the extension bit is set to 0.
	 * If the extension bit is set to 1, the Cause Value is a two octet field.
	 */
	octet = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(tree, hf_rsl_extension_bit, tvb, offset, 1, FALSE);
	proto_tree_add_item(ie_tree, hf_rsl_cause, tvb, offset, 1, FALSE);
	offset++;

	return offset;
}

/*
 * 9.3.23 Starting Time
 */
static int
dissect_rsl_ie_staring_time(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_STARTING_TIME)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,3,"Starting Time IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_staring_time);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	proto_tree_add_item(ie_tree, hf_rsl_req_ref_T1prim, tvb, offset, 1, FALSE);
	proto_tree_add_item(ie_tree, hf_rsl_req_ref_T3, tvb, offset, 2, FALSE);
	offset++;
	proto_tree_add_item(ie_tree, hf_rsl_req_ref_T2, tvb, offset, 1, FALSE);
	offset++;

	return offset;
}

/*
 * 9.3.25 Uplink Measurements
 */
static const true_false_string rsl_dtxd_vals = {
  "Employed",
  "Not employed"
};

static int
dissect_rsl_ie_uplik_meas(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint		length;
	int			ie_offset;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_UPLINK_MEAS)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Uplink Measurements IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_uplik_meas);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* Length */
	length = tvb_get_guint8(tvb,offset);
	proto_item_set_len(ti, length+2);

	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);
	offset++;
	ie_offset = offset;

	/* Octet 3
	 * 8	7	 6	5	4	3	2	1
	 * rfu	DTXd | RXLEV.FULL.up
	 */
	proto_tree_add_item(ie_tree, hf_rsl_dtxd, tvb, offset, 1, FALSE);
	proto_tree_add_item(ie_tree, hf_rsl_rxlev_full_up, tvb, offset, 1, FALSE);
	offset++;

	/* Octet4
	 * 8	7	6	5	4	3	2	1
	 * Reserved |  RXLEV.SUB.up 4
	 */
	proto_tree_add_item(ie_tree, hf_rsl_rxlev_sub_up, tvb, offset, 1, FALSE);
	offset++;
	/* Octet 5 
	 * 8	7	 6	5	4		  3	2	1
	 * Reserved | RXQUAL.FULL.up | RXQUAL.SUB.up
	 */
	proto_tree_add_item(ie_tree, hf_rsl_rxqual_full_up, tvb, offset, 1, FALSE);
	proto_tree_add_item(ie_tree, hf_rsl_rxqual_sub_up, tvb, offset, 1, FALSE);
	 offset++;
	/* Octet 6 - N
	 * Supplementary Measurement Information
	 */
	return ie_offset+length;
}


static const value_string rsl_class_vals[] = {
	{  0x00,	"Normal event" },
	{  0x01,	"Normal event" },
	{  0x02,	"Resource unavailable" },
	{  0x03,	"Service or option not available" },
	{  0x04,	"Service or option not implemented" },
	{  0x05,	"Invalid message (e.g. parameter out of range)" },
	{  0x06,	"Protocol error" },
	{  0x07,	"Interworking" },
	{ 0,			NULL }
};
	
 /*
  * 9.3.26 Cause
  */
static int
dissect_rsl_ie_cause(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint		length;
	guint8		octet;
	int			ie_offset;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_CAUSE)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Cause IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_cause);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_guint8(tvb,offset);
	proto_item_set_len(ti, length+2);
	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);
	offset++;
	ie_offset = offset;
	
	/* Cause Value */
	octet = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(tree, hf_rsl_extension_bit, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_rsl_class, tvb, offset, 1, FALSE);
	if ((octet & 0x80) == 80)
		offset++;
	
	/* Cause Extension*/
	/* Diagnostic(s) if any */
	return ie_offset+length;
}
/*
 * 9.3.27 Measurement result number
 */

static int
dissect_rsl_ie_meas_res_no(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_MEAS_RES_NO)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Measurement result number IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_meas_res_no);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* Measurement result number */
	proto_tree_add_item(ie_tree, hf_rsl_meas_res_no, tvb, offset, 1, FALSE);
	offset++;

	return offset;
}
/*
 * 9.3.28 Message Identifier
 */
static int
dissect_rsl_ie_message_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_MESSAGE_ID)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Message Identifier IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_message_id);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Message Type */
	proto_tree_add_item(tree, hf_rsl_msg_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}
/*
 * 9.3.30 System Info Type
 */
static const value_string rsl_sys_info_type_vals[] = {
	{  0x00,	"SYSTEM INFORMATION 8" },
	{  0x01,	"SYSTEM INFORMATION 1" },
	{  0x02,	"SYSTEM INFORMATION 2" },
	{  0x03,	"SYSTEM INFORMATION 3" },
	{  0x04,	"SYSTEM INFORMATION 4" },
	{  0x05,	"SYSTEM INFORMATION 5" },
	{  0x06,	"SYSTEM INFORMATION 6" },
	{  0x07,	"SYSTEM INFORMATION 7" },
	{  0x08,	"SYSTEM INFORMATION 16" },
	{  0x09,	"SYSTEM INFORMATION 17" },
	{  0x0a,	"SYSTEM INFORMATION 2bis" },
	{  0x0b,	"SYSTEM INFORMATION 2ter" },
	{  0x0d,	"SYSTEM INFORMATION 5bis" },
	{  0x0e,	"SYSTEM INFORMATION 5ter" },
	{  0x0f,	"SYSTEM INFORMATION 10" },
	{  0x47,	"EXTENDED MEASUREMENT ORDER" },
	{  0x48,	"MEASUREMENT INFORMATION" },
	{  0x28,	"SYSTEM INFORMATION 13" },
	{  0x29,	"SYSTEM INFORMATION 2quater" },
	{  0x2a,	"SYSTEM INFORMATION 9" },
	{  0x2b,	"SYSTEM INFORMATION 18" },
	{  0x2c,	"SYSTEM INFORMATION 19" },
	{  0x2d,	"SYSTEM INFORMATION 20" },
	{ 0,			NULL }
};


static int
dissect_rsl_ie_sys_info_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_SYS_INFO_TYPE)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,2,"System Info Type IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_sys_info_type);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Message Type */
	proto_tree_add_item(tree, hf_rsl_sys_info_type, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}
/*
 * 9.3.35 Full Immediate Assign Info TLV 25
 */
static int
dissect_rsl_ie_full_imm_ass_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;

	guint		length;
	tvbuff_t	*next_tvb;
	guint8		ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_FULL_IMM_ASS_INF)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Full Immediate Assign Info IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_full_imm_ass_inf);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_guint8(tvb,offset);
	proto_item_set_len(ti, length+2);

	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);
	offset++;
	/*	The Full Immediate Assign Info field (octets 3-25)
	 * contains a complete immediate assign message (IMMEDIATE ASSIGNMENT or
	 * IMMEDIATE ASSIGNMENT EXTENDED or IMMEDIATE ASSIGNMENT REJECT)
	 * as defined in 3GPP TS 44.018.
	 */
	proto_tree_add_text(ie_tree, tvb,offset,length,"Full Immediate Assign Info field");
	next_tvb = tvb_new_subset(tvb, offset, length, length);
	call_dissector(gsm_a_ccch_handle, next_tvb, pinfo, top_tree);

	offset = offset + length;

	return offset;
}

/*
 * 9.3.37 MS Timing Offset
 */

static int
dissect_rsl_ie_ms_timing_offset(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8		ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_FULL_MS_TIMING_OFFSET)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"MS Timing Offset IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_ms_timing_offset);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* Timing Offset 
	 * The meaning of the MS Timing Offset is as defined in 3GPP TS 45.010. 
	 * The value of MS Timing Offset is the binary value of the 8-bit Timing Offset field (octet 2) - 63.
	 * The range of MS Timing Offset is therefore -63 to 192.
	 */
	proto_tree_add_item(ie_tree, hf_rsl_timing_offset, tvb, offset, 1, FALSE);
	offset++;
	
	return offset;
}

/*
 * 9.3.40 Channel Needed
 */
static const value_string rsl_ch_needed_vals[] = {
	{  0x00,	"Any Channel" },
	{  0x01,	"SDCCH" },
	{  0x02,	"TCH/F (Full rate)" },
	{  0x03,	"TCH/F or TCH/H (Dual rate)" },
	{ 0,		NULL }
};

static int
dissect_rsl_ie_ch_needed(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8		ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_CH_NEEDED)
			return offset;
	}


	ti = proto_tree_add_text(tree, tvb,offset,0,"Channel Needed IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_ch_needed);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* Channel */
	proto_tree_add_item(ie_tree, hf_rsl_ch_needed, tvb, offset, 1, FALSE);
	offset++;
	
	return offset;
}

/*
 * 9.3.49 eMLPP Priority
 */
static const value_string rsl_emlpp_prio_vals[] = {
	{  0x00,	"no priority applied" },
	{  0x01,	"call priority level 4" },
	{  0x02,	"call priority level 3" },
	{  0x03,	"call priority level 2" },
	{  0x04,	"call priority level 1" },
	{  0x05,	"call priority level 0" },
	{  0x06,	"call priority level B" },
	{  0x07,	"call priority level A" },
	{ 0,			NULL }
};

static int
dissect_rsl_ie_emlpp_prio(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8		ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_EMLPP_PRIO)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"eMLPP Priority IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_emlpp_prio);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* The call priority field (bit 3 to 1 of octet 2) is coded in the same way
	 * as the call priority field (bit 3 to 1 of octet 5) in the 
	 * Descriptive group or broadcast call reference information element
	 * as defined in 3GPP TS 24.008. 
	 */
	proto_tree_add_item(ie_tree, hf_rsl_emlpp_prio, tvb, offset, 1, FALSE);
	offset++;

	return offset;
}

/*
 * 9.3.51 Main channel reference
 */

static int
dissect_rsl_ie_main_ch_ref(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8		ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_MAIN_CH_REF)
			return offset;
	}

	ti = proto_tree_add_text(tree, tvb,offset,0,"Main channel reference IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_main_ch_ref);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	/* TN is time slot number, binary represented as in 3GPP TS 45.002.
	 * 3 Bits
	 */
	proto_tree_add_item(ie_tree, hf_rsl_ch_no_TN, tvb, offset, 1, FALSE);
	offset++;
	return offset;
}

/*
 * 9.3.52 MultiRate configuration
 */

static int
dissect_rsl_ie_multirate_conf(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, gboolean is_mandatory)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint length;
	guint8 ie_id;

	if(is_mandatory == FALSE){
		ie_id = tvb_get_guint8(tvb,offset);
		if (ie_id != RSL_IE_MULTIRATE_CONF)
			return offset;
	}
	ti = proto_tree_add_text(tree, tvb,offset,0,"MultiRate configuration IE");
	ie_tree = proto_item_add_subtree(ti, ett_ie_multirate_conf);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_guint8(tvb,offset);
	proto_item_set_len(ti, length+2);
	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);
	offset++;

	/* Rest of element coded as in 3GPP TS 44.018 not including
	 * 3GPP TS 44.018 element identifier or 3GPP TS 44.018 octet length value
	 */

	de_rr_multirate_conf(tvb, ie_tree, offset, length, NULL, 0);

	offset = offset + length;

	return offset;
}

/*
 * 9.3.58 LLP APDU
 */

/* The rest of the information element contains the embedded message
 * that contains a Facility Information Element as defined in
 * 3GPP TS 44.071 excluding the Facility IEI and length of Facility IEI
 * octets defined in 3GPP TS 44.071.
 */

static int
dissct_rsl_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	guint8	msg_type;

	msg_type = tvb_get_guint8(tvb,offset)&0x7f;
	proto_tree_add_item(tree, hf_rsl_msg_type, tvb, offset, 1, FALSE);
	offset++;

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",val_to_str(msg_type, rsl_msg_type_vals,"unknown %u"));
	}


	switch (msg_type){
/* Radio Link Layer Management messages */
	/* 8.3.1 DATA REQUEST */
	case RSL_MSG_TYPE_DATA_REQ:
		/* Channel number			9.3.1	M TV 2		*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Link Identifier			9.3.2	M TV 2		*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		/* L3 Information			9.3.11	M TLV >=3	*/
		offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.3.2 DATA INDICATION */
	case RSL_MSG_TYPE_DATA_IND:
		/* Channel number			9.3.1	M TV 2		*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Link Identifier			9.3.2	M TV 2		*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		/* L3 Information			9.3.11	M TLV >=3	*/
		offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.3.3 ERROR INDICATION */
	case RSL_MSG_TYPE_ERROR_IND:
		/* Channel number			9.3.1	M TV 2		*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Link Identifier			9.3.2	M TV 2		*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		/* RLM Cause				9.3.22	M TLV 2-4	*/
		offset = dissect_rsl_ie_rlm_cause(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.3.4 ESTABLISH REQUEST */
	case RSL_MSG_TYPE_EST_REQ:
		/* Channel number			9.3.1	M TV 2		*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Link Identifier			9.3.2	M TV 2		*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.3.5 ESTABLISH CONFIRM */
	case RSL_MSG_TYPE_EST_CONF:
		/* Channel number			9.3.1	M TV 2		*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Link Identifier			9.3.2	M TV 2		*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.3.6 */
	case RSL_MSG_EST_IND:
		/* 	Channel number			9.3.1	M TV 2				 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* 	Link Identifier			9.3.2	M TV 2				 */
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		/* 	L3 Information			9.3.11	O (note 1) TLV 3-23	 */
		if(tvb_length_remaining(tvb,offset) >1)
			offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, FALSE);
		break;
	/* 8.3.7 RELEASE REQUEST */
	case RSL_MSG_REL_REQ:
		/* 	Channel number			9.3.1	M TV 2				 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* 	Link Identifier			9.3.2	M TV 2				 */
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		/* Release Mode				9.3.20	M TV 2				*/
		offset = dissect_rsl_ie_rel_mode(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.3.8 RELEASE CONFIRM */
	case RSL_MSG_REL_CONF:
		/* 	Channel number			9.3.1	M TV 2				 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* 	Link Identifier			9.3.2	M TV 2				 */
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.3.9 RELEASE INDICATION */
	case RSL_MSG_REL_IND:
		/* 	Channel number			9.3.1	M TV 2				 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* 	Link Identifier			9.3.2	M TV 2				 */
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.3.10 UNIT DATA REQUEST */
	case RSL_MSG_UNIT_DATA_REQ:
		/* 	Channel number			9.3.1	M TV 2				 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* 	Link Identifier			9.3.2	M TV 2				 */
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		/* 	L3 Information			9.3.11	O (note 1) TLV 3-23	 */
		offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, FALSE);
		break;

/* Common Channel Management/TRX Management messages: */
	/* 8.5.3 */
	case RSL_MSG_CHANRQD: /* 19 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Request Reference		9.3.19	M TV 4 */
		offset = dissect_rsl_ie_req_ref(tvb, pinfo, tree, offset, TRUE);
		/* Access Delay				9.3.17	M TV 2 */
		offset = dissect_rsl_ie_access_delay(tvb, pinfo, tree, offset, TRUE);
		/* Physical Context			9.3.16	O 1) TLV >=2 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_phy_ctx(tvb, pinfo, tree, offset, FALSE);
		break;
	/* 8.5.4 DELETE INDICATION */
	case RSL_MSG_DELETE_IND: /* 20 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Full Imm. Assign Info	9.3.35	M TLV 25 */
		offset = dissect_rsl_ie_full_imm_ass_inf(tvb, pinfo, tree, offset, TRUE);
		break;
	case RSL_MSG_PAGING_CMD:	/* 21 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Paging Group				9.3.14	M TV 2 2 */
		offset = dissect_rsl_ie_paging_grp(tvb, pinfo, tree, offset, TRUE);
		/* MS Identity				9.3.12	M TLV 2-10 2 */
		offset = dissect_rsl_ie_ms_id(tvb, pinfo, tree, offset, TRUE);
		/* Channel Needed			9.3.40	O 1) TV 2 2 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_ch_needed(tvb, pinfo, tree, offset, FALSE);
		/* eMLPP Priority			9.3.49	O 2) TV 2 2 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_emlpp_prio(tvb, pinfo, tree, offset, FALSE);
		break;
	/* 8.5.6 IMMEDIATE ASSIGN COMMAND */
	case RSL_MSG_IMM_ASS_CMD:	/* 22 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Full Imm. Assign Info	9.3.35	M TLV 25 */
		offset = dissect_rsl_ie_full_imm_ass_inf(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.5.7 SMS BROADCAST REQUEST */
	case RSL_MSG_SMS_BC_REQ:	/*	23	 8.5.7 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* SMSCB Information		9.3.36	M TV 24 */
		/* SMSCB Channel Indicator	9.3.44	O 1) TV 2 */
		break;
/* 8.6 TRX MANAGEMENT MESSAGES */
	/* 8.6.1 RF RESOURCE INDICATION */
	case RSL_MSG_RF_RES_IND:	/*	24	 8.6.1 */
		/* Resource Information		9.3.21	M TLV >=2 */
		break;
	/* 8.6.2 SACCH FILLING */
	case RSL_MSG_SACCH_FILL:	/*	25	 8.6.2 */
		/* System Info Type			9.3.30	M TV 2 */
		offset = dissect_rsl_ie_sys_info_type(tvb, pinfo, tree, offset, TRUE);
		/* L3 Info (SYS INFO)		9.3.11 O 1) TLV 22 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, FALSE);
		/* Starting Time			9.3.23 O 2) TV 3 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_staring_time(tvb, pinfo, tree, offset, FALSE);
		break;
	case RSL_MSG_OVERLOAD:		/*	27	 8.6.3 */
		/* Cause					9.3.26	M TLV >=3 */
		offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, TRUE);
		break;
	case RSL_MSG_ERROR_REPORT:	/*	28	 8.6.4 */
		/* Cause					9.3.26	M TLV >=3 */
		offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, TRUE);
		/* Message Identifier		9.3.28	O 1) TV 2 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_message_id(tvb, pinfo, tree, offset, FALSE);
		/* Channel Number			9.3.1	O 2) TV 2 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Link identifier			9.3.2	O 3) TV 2 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		/* Erroneous Message		9.3.38	O 4) TLV >=3 */
		break;
	/* 8.5.8 SMS BROADCAST COMMAND */
	case RSL_MSG_SMS_BC_CMD:	/*	29	 8.5.8 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* CB Command type			9.3.41	M TV 2 */
		/* SMSCB message			9.3.42	M TLV 2-90 */
		/* SMSCB Channel Indicator	9.3.44	O 1) TV 2 */
		break;
	case RSL_MSG_CBCH_LOAD_IND:	/*	30	 8.5.9 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* CBCH Load Information	9.3.43	M TV 2 */
		/* SMSCB Channel Indicator	9.3.44 O 1) TV 2 */
		break;
	case RSL_MSG_NOT_CMD:		/*	31	 8.5.10 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Command indicator		9.3.48 M 1) TLV 3-4 */
		/* Group call reference		9.3.45 O TLV 7 */
		/* Channel Description		9.3.46 O TLV 3-n */
		/* NCH DRX information		9.3.47 O TLV 3 */
		break;

/* Dedicated Channel Management messages: */
	/* 8.4.1 CHANNEL ACTIVATION 33*/
	case RSL_MSG_CHAN_ACTIV:
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Activation Type			9.3.3	M TV 2			*/
		offset = dissect_rsl_ie_act_type(tvb, pinfo, tree, offset, TRUE);
		/* Channel Mode				9.3.6	M TLV 8-9		*/
		offset = dissect_rsl_ie_ch_mode(tvb, pinfo, tree, offset, TRUE);
		/* Channel Identification	9.3.5	O 7) TLV 8		*/
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_ch_id(tvb, pinfo, tree, offset, FALSE);
		/* Encryption information	9.3.7	O 1) TLV >=3	*/
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_enc_inf(tvb, pinfo, tree, offset, FALSE);
		/* Handover Reference		9.3.9	C 2) TV 2		*/
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_ho_ref(tvb, pinfo, tree, offset, FALSE);
		/* BS Power					9.3.4	O 3) TV 2		*/
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_bs_power(tvb, pinfo, tree, offset, FALSE); 
		/* MS Power					9.3.13	O 3) TV 2		*/
		/* Timing Advance			9.3.24	C 3) 4) TV 2	*/
		/* BS Power Parameters		9.3.32	O 5) TLV >=2	*/
		/* MS Power Parameters		9.3.31	O 5) TLV >=2	*/
		/* Physical Context			9.3.16	O 6) TLV >=2	*/
		/* SACCH Information		9.3.29	O 8) TLV >=3	*/
		/* UIC						9.3.50	O 9) TLV 3		*/
		/* Main channel reference	9.3.51	O 10) TV 2		*
		offset = dissect_rsl_ie_main_ch_ref(tvb, pinfo, tree, offset, FALSE);
		/* MultiRate configuration	9.3.52	O 11) TLV >=4	*
		offset = dissect_rsl_ie_multirate_conf(tvb, pinfo, tree, offset, FALSE);
		/* MultiRate Control		9.3.53	O 12) TV 2		*/
		/* Supported Codec Types	9.3.54	O 12) TLV >=5	*/
		/* TFO transparent container 9.3.59 O 12) TLV >=3	*/
		break;

	/* 8.4.2 CHANNEL ACTIVATION ACKNOWLEDGE	34*/
	case RSL_MSG_CHAN_ACTIV_ACK:
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Frame number				9.3.8	M TV 3			*/
		offset = dissect_rsl_ie_frame_no(tvb, pinfo, tree, offset, TRUE);
		break;
	case RSL_MSG_CHAN_ACTIV_N_ACK:
	/* 8.4.3 CHANNEL ACTIVATION NEGATIVE ACKNOWLEDGE */
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Cause					9.3.26	M TLV >=3		*/
		offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.4 CONNECTION FAILURE INDICATION */
	case RSL_MSG_CONN_FAIL:
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Cause					9.3.26	M TLV >=3		*/
		offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.5 DEACTIVATE SACCH */
	case RSL_MSG_DEACTIVATE_SACCH:
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.6 ENCRYPTION COMMAND */
	case RSL_MSG_ENCR_CMD:			/*	38	 8.4.6 */
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Encryption information	9.3.7	M TLV >=3		*/
		offset = dissect_rsl_ie_enc_inf(tvb, pinfo, tree, offset, TRUE);
		/* Link Identifier			9.3.2	M TV 2			*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset, TRUE);
		/* L3 Info (CIPH MOD CMD)	9.3.11	M TLV 6			*/
		offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, TRUE); 
		break;
	/* 8.4.7 HANDOVER DETECTION */
	case RSL_MSG_HANDODET:			/*	39	 8.4.7 */
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Access Delay				9.3.17 O 1) TV 2		*/
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_access_delay(tvb, pinfo, tree, offset, FALSE);
		break;
	/* 8.4.8 MEASUREMENT RESULT 40 */
	case RSL_MSG_MEAS_RES:
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Measurement result number 9.3.27 M TV 2			*/
		offset = dissect_rsl_ie_meas_res_no(tvb, pinfo, tree, offset, TRUE);
		/* Uplink Measurements		9.3.25	M TLV >=5		*/
		offset = dissect_rsl_ie_uplik_meas(tvb, pinfo, tree, offset, TRUE);
		/* BS Power					9.3.4	M TV 2			*/
		offset = dissect_rsl_ie_bs_power(tvb, pinfo, tree, offset, TRUE);
		/* L1 Information			9.3.10 O 1) TV 3		*/
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_l1_inf(tvb, pinfo, tree, offset, FALSE);
		/* L3 Info (MEAS REP, EXT MEAS REP or ENH MEAS REP) 9.3.11 O 1) TLV 21 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, FALSE); 
		/* MS Timing Offset			9.3.37 O 2) TV 2		*/
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_ms_timing_offset(tvb, pinfo, tree, offset, FALSE); 
		break;
	/* 8.4.9 MODE MODIFY */
	case RSL_MSG_MODE_MODIFY_REQ:	/*	41	8.4.9 */
		/* Channel number			9.3.1 M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Channel Mode				9.3.6 M TLV 8-9 */
		offset = dissect_rsl_ie_ch_mode(tvb, pinfo, tree, offset, TRUE);
		/* Encryption information	9.3.7 O 1) TLV >=3 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_enc_inf(tvb, pinfo, tree, offset, FALSE); 
		/* Main channel reference	9.3.45 O 2) TV 2 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_main_ch_ref(tvb, pinfo, tree, offset, FALSE);
		/* MultiRate configuration	9.3.52 O 3) TLV >=3 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_multirate_conf(tvb, pinfo, tree, offset, FALSE);
		/* Multirate Control		9.3.53 O 4) TV 2 */
		/* Supported Codec Types	9.3.54 O 4) TLV >=5 */
		/* TFO transparent container 9.3.59 O 4) TLV */
		break;
	/* 8.4.10 MODE MODIFY ACKNOWLEDGE */
	case RSL_MSG_MODE_MODIFY_ACK:	/*	42	8.4.10 */
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.11 MODE MODIFY NEGATIVE ACKNOWLEDGE */
	case RSL_MSG_MODE_MODIFY_NACK:	/*	43	8.4.11 */
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Cause					9.3.26	M TLV >=3		*/
		offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.12 PHYSICAL CONTEXT REQUEST */
	case RSL_MSG_PHY_CONTEXT_REQ:	/*	44	8.4.12 */
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.13 PHYSICAL CONTEXT CONFIRM */
	case RSL_MSG_PHY_CONTEXT_CONF:	/*	45	8.4.13 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* BS Power					9.3.4	M TV 2 */
		offset = dissect_rsl_ie_bs_power(tvb, pinfo, tree, offset, TRUE);
		/* MS Power					9.3.13	M TV 2 */
		/* Timing Advance			9.3.24	M TV 2 */
		/* Physical Context			9.3.16	O 1) TLV */
		break;
	/* 8.4.14 RF CHANNEL RELEASE */
	case RSL_MSG_RF_CHAN_REL:		/*	46	8.4.14 */
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.15 MS POWER CONTROL */
	case RSL_MSG_MS_POWER_CONTROL:	/*	47	8.4.15 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* MS Power					9.3.13	M TV 2 */
		/* MS Power Parameters		9.3.31	O 1) TLV >=2 */
		break;
	/* 8.4.16 BS POWER CONTROL */
	case RSL_MSG_BS_POWER_CONTROL:	/*	48	8.4.16 */
		/* Channel number			9.3.1 M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* BS Power					9.3.4 M TV 2 */
		offset = dissect_rsl_ie_bs_power(tvb, pinfo, tree, offset, TRUE);
		/* BS Power Parameters		9.3.32 O 1) TLV >=2 */
		break;
	/* 8.4.17 PREPROCESS CONFIGURE */
	case RSL_MSG_PREPROC_CONFIG:		/*	49	8.4.17 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Preproc. Parameters		9.3.33	M TLV >=3 */
		break;
	/* 8.4.18 PREPROCESSED MEASUREMENT RESULT */
	case RSL_MSG_PREPROC_MEAS_RES:	/*	50	8.4.18 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Preproc. Measurements	9.3.34	M TLV >=2 */
		break;
	/* 8.4.19 RF CHANNEL RELEASE ACKNOWLEDGE */
	case RSL_MSG_RF_CHAN_REL_ACK:		/*	51	8.4.19 */
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.20 SACCH INFO MODIFY */
	case RSL_MSG_SACCH_INFO_MODIFY:	/*	52	8.4.20 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* System Info Type			9.3.30	M TV 2 */
		offset = dissect_rsl_ie_sys_info_type(tvb, pinfo, tree, offset, TRUE);
		/* L3 Info					9.3.11	O 1) TLV 22 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset, FALSE);
		/* Starting Time			9.3.23	O 2) TV 3 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_staring_time(tvb, pinfo, tree, offset, FALSE);
		break;
	/* 8.4.21 TALKER DETECTION */
	case RSL_MSG_TALKER_DET:			/*	53	8.4.21 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Access Delay				9.3.17	O 1) TV 2 */
		if(tvb_length_remaining(tvb,offset) > 0)
				offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.22 LISTENER DETECTION */
	case RSL_MSG_LISTENER_DET:		/*	54	8.4.22 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Access Delay				9.3.17	O 1) TV 2 */
		if(tvb_length_remaining(tvb,offset) > 0)
				offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.23 REMOTE CODEC CONFIGURATION REPORT */
	case RSL_MSG_REMOTE_CODEC_CONF_REP:/*	55	8.4.23 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Codec Configuration		9.3.55	M TLV >=3 */
		/* Supported Codec Types	9.3.54	M TLV >=5 */
		/* TFO transparent container 9.3.59 O 4) TLV >=3 */
		break;
	/* 8.4.24 ROUND TRIP DELAY REPORT */
	case RSL_MSG_R_T_D_REP:			/*	56	8.4.24 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Round Trip Delay			9.3.56	M TV 2 */
		break;
	/* 8.4.25 PRE-HANDOVER NOTIFICATION */
	case RSL_MSG_PRE_HANDO_NOTIF:		/*	57	8.4.25 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* MultiRateControl			9.3.53	M TV 2 */
		/* Codec Configuration		9.3.55	M TLV >=3 */
		/* TFO transparent container 9.3.59 O 4) TLV >=3 */
		break;
	/* 8.4.26 MULTIRATE CODEC MODIFICATION REQUEST */
	case RSL_MSG_MR_CODEC_MOD_REQ:	/*	58	8.4.26 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* MultiRate Configuration	9.3.52	O 1) TLV >=4 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_multirate_conf(tvb, pinfo, tree, offset, FALSE);
		break;
	/*  8.4.27 MULTIRATE CODEC MODIFICATION ACKNOWLEDGE */
	case RSL_MSG_MR_CODEC_MOD_ACK:	/*	59	8.4.27 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* MultiRate Configuration	9.3.52	O 1) TLV >=4 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_multirate_conf(tvb, pinfo, tree, offset, FALSE);
		break;
	/* 8.4.28 MULTIRATE CODEC MODIFICATION NEGATIVE ACKNOWLEDGE */
	case RSL_MSG_MR_CODEC_MOD_NACK:	/*	60	8.4.28 */
		/* Channel number			9.3.1	M TV 2			*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* Cause					9.3.26	M TLV >=3		*/
		offset = dissect_rsl_ie_cause(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.29 MULTIRATE CODEC MODIFICATION PERFORMED */
	case RSL_MSG_MR_CODEC_MOD_PER:	/*	61	8.4.29 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* MultiRate Configuration	9.3.52	M TLV >=4 */
		offset = dissect_rsl_ie_multirate_conf(tvb, pinfo, tree, offset, TRUE);
		break;
	/* 8.4.30 TFO REPORT */
	case RSL_MSG_TFO_REP:				/*	62	8.4.30 */
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* TFO Status				9.3.57	M TV 1 */
		break;
	/* 8.4.31 TFO MODIFICATION REQUEST */
	case RSL_MSG_TFO_MOD_REQ:			/*	63	8.4.31 */
		/* Channel number			9.3.1 M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset, TRUE);
		/* MultiRateControl			9.3.53 M TV 2 */
		/* Supported Codec Type		9.3.54 O 1) TLV >=5 */
		/* TFO transparent container 9.3.59 O 4) TLV >=3 */
		break;
	/* 	0 1 - - - - - - Location Services messages: */
	/* 8.7.1 LOCATION INFORMATION */
	case RSL_MSG_LOC_INF:				/*	65	8.7.1 */
		/* LLP APDU 9.3.58 M LV 2-N */
		break;
	default:
		break;
	}

	return offset;

}
static void
dissect_rsl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *rsl_tree;


	int offset = 0;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RSL");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	top_tree = tree;
	/*if (tree) {*/
		ti = proto_tree_add_item(tree, proto_rsl, tvb, 0, -1, FALSE);
		rsl_tree = proto_item_add_subtree(ti, ett_rsl);

		/* 9.1 Message discriminator */
		proto_tree_add_item(rsl_tree, hf_rsl_msg_dsc, tvb, offset, 1, FALSE);
		proto_tree_add_item(rsl_tree, hf_rsl_T_bit, tvb, offset, 1, FALSE);
		offset++;
		offset = dissct_rsl_msg(tvb, pinfo, rsl_tree, offset);

	/*}*/

}

void
proto_reg_handoff_rsl(void)
{
	dissector_handle_t rsl_handle;

	rsl_handle = create_dissector_handle(dissect_rsl, proto_rsl);
	dissector_add("lapd.gsm.sapi", LAPD_GSM_SAPI_RA_SIG_PROC, rsl_handle);

	gsm_a_ccch_handle = find_dissector("gsm_a_ccch");
	gsm_a_dtap_handle = find_dissector("gsm_a_dtap");
}

/* Register the protocol with Wireshark */
void proto_register_rsl(void)
{

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_rsl_msg_dsc,
			{ "Message discriminator",           "rsl.msg_dsc",
			FT_UINT8, BASE_DEC, VALS(rsl_msg_disc_vals), 0xfe,
			"Message discriminator", HFILL }
		},
		{ &hf_rsl_T_bit,
			{ "T bit",           "rsl.T_bit",
			FT_BOOLEAN, 8, TFS(&rsl_t_bit_vals), 0x01,
			"T bit", HFILL }
		},
		{ &hf_rsl_msg_type,
			{ "Message type",           "rsl.msg_type",
			FT_UINT8, BASE_HEX_DEC, VALS(rsl_msg_type_vals), 0x7f,
			"Message type", HFILL }
		},
		{ &hf_rsl_ie_id,
			{ "Element identifier",           "rsl.ie_id",
			FT_UINT8, BASE_HEX_DEC, VALS(rsl_ie_type_vals), 0x0,
			"Element identifier", HFILL }
		},
		{ &hf_rsl_ie_length,
			{ "Length",           "rsl.ie_length",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Length", HFILL }
		},
		{ &hf_rsl_ch_no_Cbits,
			{ "C-bits",           "rsl.ch_no_Cbits",
			FT_UINT8, BASE_DEC, VALS(rsl_ch_no_Cbits_vals), 0xf8,
			"C-bits", HFILL }
		},
		{ &hf_rsl_ch_no_TN,
			{ "Time slot number (TN)",  "rsl.ch_no_TN",
			FT_UINT8, BASE_DEC, NULL, 0x07,
			"Time slot number (TN)", HFILL }
		},
		{ &hf_rsl_req_ref_ra,
			{ "Random Access Information (RA)", "rsl.req_ref_ra",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Random Access Information (RA)", HFILL }
		},
		{ &hf_rsl_req_ref_T1prim,
			{ "T1'",           "rsl.req_ref_T1prim",
			FT_UINT8, BASE_DEC, NULL, 0xf8,
			"T1'", HFILL }
		},
		{ &hf_rsl_req_ref_T3,
			{ "T3",           "rsl.req_ref_T3",
			FT_UINT16, BASE_DEC, NULL, 0x07e0,
			"T3", HFILL }
		},
		{ &hf_rsl_req_ref_T2,
			{ "T2",           "rsl.req_ref_T2",
			FT_UINT8, BASE_DEC, NULL, 0x1f,
			"T2", HFILL }
		},
		{ &hf_rsl_ho_ref,
			{ "Hand-over reference",           "rsl.ho_ref",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Hand-over reference", HFILL }
		},
		{ &hf_rsl_ms_power_lev,
			{ "MS power level",           "rsl.s_power_lev",
			FT_UINT8, BASE_DEC, NULL, 0xf8,
			"MS power level", HFILL }
		},
		{ &hf_rsl_ms_fpc,
			{ "FPC",           "rsl.fpc",
			FT_BOOLEAN, 8, TFS(&rsl_fpc_epc_mode_vals), 0x04,
			"FPC", HFILL }
		},
		{ &hf_rsl_act_timing_adv,
			{ "Actual Timing Advance",           "rsl.act_timing_adv",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Actual Timing Advance", HFILL }
		},
		{ &hf_rsl_dtxd,
			{ "DTXd",           "rsl.dtxd",
			FT_BOOLEAN, 8, TFS(&rsl_dtxd_vals), 0x40,
			"DTXd", HFILL }
		},
		{ &hf_rsl_rxlev_full_up,
			{ "RXLEV.FULL.up",           "rsl.rxlev_full_up",
			FT_UINT8, BASE_DEC, NULL, 0x3f,
			"RXLEV.FULL.up", HFILL }
		},
		{ &hf_rsl_rxlev_sub_up,
			{ "RXLEV.SUB.up",           "rsl.rxlev_sub_up",
			FT_UINT8, BASE_DEC, NULL, 0x3f,
			"RXLEV.SUB.up", HFILL }
		},
		{ &hf_rsl_rxqual_full_up,
			{ "RXQUAL.FULL.up",           "rsl.rxqual_full_up",
			FT_UINT8, BASE_DEC, NULL, 0x38,
			"RXQUAL.FULL.up", HFILL }
		},
		{ &hf_rsl_rxqual_sub_up,
			{ "RXQUAL.SUB.up",           "rsl.rxqual_sub_up",
			FT_UINT8, BASE_DEC, NULL, 0x07,
			"RXQUAL.SUB.up", HFILL }
		},
		{ &hf_rsl_acc_delay,
			{ "Access Delay",           "rsl.acc_del",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Access Delay", HFILL }
		},
		{ &hf_rsl_phy_ctx,
			{ "Physical Context",           "rsl.phy_ctx",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Physical Context", HFILL }
		},
		{ &hf_rsl_na,
			{ "Not applicable (NA)",           "rsl.na",
			FT_BOOLEAN, 8, TFS(&rsl_na_vals), 0x20,
			"Not applicable (NA)", HFILL }
		},
		{ &hf_rsl_ch_type,
			{ "channel type",           "rsl.ch_type",
			FT_UINT8, BASE_DEC, VALS(rsl_ch_type_vals), 0xc0,
			"channel type", HFILL }
		},
		{ &hf_rsl_prio,
			{ "Priority",           "rsl.prio",
			FT_UINT8, BASE_DEC, VALS(rsl_prio_vals), 0x18,
			"Priority", HFILL }
		},
		{ &hf_rsl_sapi,
			{ "SAPI",           "rsl.sapi",
			FT_UINT8, BASE_DEC, NULL, 0x07,
			"SAPI", HFILL }
		},
		{ &hf_rsl_rbit,
			{ "R",           "rsl.rbit",
			FT_BOOLEAN, 8, TFS(&rsl_rbit_vals), 0x80,
			"R", HFILL }
		},
		{ &hf_rsl_a3a2,
			{ "A3A2",           "rsl.a3a2",
			FT_UINT8, BASE_DEC, VALS(rsl_a3a2_vals), 0x06,
			"A3A2", HFILL }
		},
		{ &hf_rsl_a1_0,
			{ "A1",           "rsl.a1_0",
			FT_BOOLEAN, 8, TFS(&rsl_a1_0_vals), 0x01,
			"A1", HFILL }
		},
		{ &hf_rsl_a1_1,
			{ "A1",           "rsl.a1_1",
			FT_BOOLEAN, 8, TFS(&rsl_a1_1_vals), 0x01,
			"A1", HFILL }
		},
		{ &hf_rsl_a1_2,
			{ "A1",           "rsl.a2_0",
			FT_BOOLEAN, 8, TFS(&rsl_a1_2_vals), 0x01,
			"A1", HFILL }
		},
		{ &hf_rsl_epc_mode,
			{ "EPC mode", "rsl.epc_mode",
			FT_BOOLEAN, 8, TFS(&rsl_epc_mode_vals), 0x20,
			"EPC mode", HFILL }
		},
		{ &hf_rsl_fpc_epc_mode,
			{ "FPC-EPC mode", "rsl.fpc_epc_mode",
			FT_BOOLEAN, 8, TFS(&rsl_fpc_epc_mode_vals), 0x10,
			"FPC-EPC mode", HFILL }
		},
		{ &hf_rsl_bs_power,
			{ "Power Level",           "rsl.bs_power",
			FT_UINT8, BASE_DEC, VALS(rsl_rlm_bs_power_vals), 0x0f,
			"Power Level", HFILL }
		},
		{ &hf_rsl_cm_dtxd,
			{ "DTXd", "rsl.cm_dtxd",
			FT_BOOLEAN, 8, TFS(&rsl_dtx_vals), 0x02,
			"DTXd", HFILL }
		},
		{ &hf_rsl_cm_dtxu,
			{ "DTXu", "rsl.cm_dtxu",
			FT_BOOLEAN, 8, TFS(&rsl_dtx_vals), 0x01,
			"DTXu", HFILL }
		},
		{ &hf_rsl_alg_id,
			{ "Algorithm Identifier",           "rsl.alg_id",
			FT_UINT8, BASE_DEC, VALS(rsl_algorithm_id_vals), 0x0,
			"Algorithm Identifier", HFILL }
		},
		{ &hf_rsl_key,
			{ "KEY",           "rsl.key",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"KEY", HFILL }
		},
		{ &hf_rsl_cause,
			{ "Cause",           "rsl.cause",
			FT_UINT8, BASE_DEC, VALS(rsl_rlm_cause_vals), 0x7f,
			"Cause", HFILL }
		},
		{ &hf_rsl_rel_mode,
			{ "Release Mode",           "rsl.rel_mode",
			FT_UINT8, BASE_DEC, VALS(rel_mode_vals), 0x01,
			"Relese Mode", HFILL }
		},
		{ &hf_rsl_meas_res_no,
			{ "Measurement result number",           "rsl.meas_res_no",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Measurement result number", HFILL }
		},
		{ &hf_rsl_extension_bit,
			{ "Extension", "rsl.extension_bit",
			FT_BOOLEAN, 8, TFS(&rsl_extension_bit_value), 0x80,
			"Extension", HFILL }},
		{ &hf_rsl_class,
			{ "Class",           "rsl.class",
			FT_UINT8, BASE_DEC, VALS(rsl_class_vals), 0x70,
			"Class", HFILL }
		},
		{ &hf_rsl_paging_grp,
			{ "Paging Group",           "rsl.paging_grp",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Paging Group", HFILL }
		},
		{ &hf_rsl_sys_info_type,
			{ "System Info Type",           "rsl.sys_info_type",
			FT_UINT8, BASE_DEC, VALS(rsl_sys_info_type_vals), 0x0,
			"System Info Type", HFILL }
		},
		{ &hf_rsl_timing_offset,
			{ "Timing Offset",           "rsl.timing_offset",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Timing Offset", HFILL }
		},
		{ &hf_rsl_ch_needed,
			{ "Channel Needed",           "rsl.ch_needed",
			FT_UINT8, BASE_DEC, VALS(rsl_ch_needed_vals), 0x03,
			"Channel Needed", HFILL }
		},
		{ &hf_rsl_emlpp_prio,
			{ "eMLPP Priority",           "rsl.emlpp_prio",
			FT_UINT8, BASE_DEC, VALS(rsl_emlpp_prio_vals), 0x03,
			"eMLPP Priority", HFILL }
		},
	};
	static gint *ett[] = {
		&ett_rsl,
		&ett_ie_link_id,
		&ett_ie_act_type,
		&ett_ie_bs_power,
		&ett_ie_ch_id,
		&ett_ie_ch_mode,
		&ett_ie_enc_inf,
		&ett_ie_ch_no,
		&ett_ie_frame_no,
		&ett_ie_ho_ref,
		&ett_ie_l1_inf,
		&ett_ie_L3_inf,
		&ett_ie_ms_id,
		&ett_ie_phy_ctx,
		&ett_ie_paging_grp,
		&ett_ie_access_delay,
		&ett_ie_req_ref,
		&ett_ie_rel_mode,
		&ett_ie_rlm_cause,
		&ett_ie_staring_time,
		&ett_ie_uplik_meas,
		&ett_ie_full_imm_ass_inf,
		&ett_ie_ms_timing_offset,
		&ett_ie_ch_needed,
		&ett_ie_emlpp_prio,
		&ett_ie_main_ch_ref,
		&ett_ie_multirate_conf,
		&ett_ie_cause,
		&ett_ie_meas_res_no,
		&ett_ie_message_id,
		&ett_ie_sys_info_type,
	};

	/* Register the protocol name and description */
	proto_rsl = proto_register_protocol("Radio Signalling Link (RSL)",
	                                    "RSL", "rsl");

	proto_register_field_array(proto_rsl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


}

