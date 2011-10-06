/* packet-gsm_bsslap.c
 * Routines for Location Services (LCS) Serving Mobile Location Centre - Base Station System (SMLC-BSS) dissection
 * Copyright 2008, Anders Broman <anders.broman[at]ericsson.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * References: 3GPP TS 48.071 version 7.2.0 Release 7
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>

#include "packet-gsm_a_common.h"

static dissector_handle_t bsslap_rrlp_handle = NULL;

/* Initialize the protocol and registered fields */
static int proto_gsm_bsslap			= -1;
static int hf_gsm_bsslap_msg_type	= -1;
int hf_gsm_a_bsslap_elem_id			= -1;
static int hf_gsm_bsslap_ta			= -1;
static int hf_gsm_bsslap_timer_value = -1;
static int hf_gsm_bsslap_ms_pow = -1;
static int hf_gsm_bsslap_cause = -1;
static int hf_gsm_bsslap_rrlp_flg = -1;
static int hf_gsm_bsslap_tfi = -1;
static int hf_gsm_bsslap_poll_rep = -1;
static int hf_gsm_bsslap_lac = -1;
static int hf_gsm_bsslap_cell_id_disc = -1;

/* Initialize the subtree pointers */
static int ett_gsm_bsslap = -1;
static int ett_bsslap_cell_list = -1;

/* Table 5.1: Element Indentifier codes */
#define BSSLAP_PARAM_TIMING_ADVANCE                  0x01
#define BSSLAP_PARAM_RESERVED_01                     0x08
#define BSSLAP_PARAM_CELL_IDENTITY                   0x09
#define BSSLAP_PARAM_RESERVED_02                     0x0A
#define BSSLAP_PARAM_RESERVED_03                     0x0B
#define BSSLAP_PARAM_RESERVED_04                     0x0C
#define BSSLAP_PARAM_CHANNEL_DESCRIPTION             0x10
#define BSSLAP_PARAM_RESERVED_05                     0x11
#define BSSLAP_PARAM_RESERVED_06                     0x12
#define BSSLAP_PARAM_RESERVED_07                     0x13
#define BSSLAP_PARAM_MEASUREMENT_REPORT              0x14
#define BSSLAP_PARAM_RESERVED_08                     0x15
#define BSSLAP_PARAM_CAUSE                           0x18
#define BSSLAP_PARAM_RRLP_FLAG                       0x19
#define BSSLAP_PARAM_RRLP_IE                         0x1B
#define BSSLAP_PARAM_CELL_IDENTITY_LIST              0x1C
#define BSSLAP_PARAM_ENHANCED_MEASUREMENT_REPORT     0x1D
#define BSSLAP_PARAM_LOCATION_AREA_CODE              0x1E
#define BSSLAP_PARAM_FREQUENCY_LIST                  0x21
#define BSSLAP_PARAM_MS_POWER                        0x22
#define BSSLAP_PARAM_DELTA_TIMER                     0x23
#define BSSLAP_PARAM_SERVING_CELL_IDENTIFIER         0x24
#define BSSLAP_PARAM_ENCRYPTION_KEY                  0x25
#define BSSLAP_PARAM_CIPHER_MODE_SETTING             0x26
#define BSSLAP_PARAM_CHANNEL_MODE                    0x27
#define BSSLAP_PARAM_MULTIRATE_CONFIGURATION         0x28
#define BSSLAP_PARAM_POLLING_REPETITION              0x29
#define BSSLAP_PARAM_PACKET_CHANNEL_DESCRIPTION      0x2A
#define BSSLAP_PARAM_TLLI                            0x2B
#define BSSLAP_PARAM_TFI                             0x2C
#define BSSLAP_PARAM_STARTING_TIME                   0x2D

const value_string gsm_bsslap_elem_strings[] = {
	{  0x00,								"Reserved" },
	{  BSSLAP_PARAM_TIMING_ADVANCE,			"Timing Advance" },
	{  BSSLAP_PARAM_RESERVED_01,			"Reserved" },			/* (note) */
	{  BSSLAP_PARAM_CELL_IDENTITY,			"Cell Identity" },
	{  BSSLAP_PARAM_RESERVED_02,			"Reserved" },			/* (note) */
	{  BSSLAP_PARAM_RESERVED_03,			"Reserved" },			/* (note) */
	{  BSSLAP_PARAM_RESERVED_04,			"Reserved" },			/* (note) */
	{  BSSLAP_PARAM_CHANNEL_DESCRIPTION,	"Channel Description" },
	{  BSSLAP_PARAM_RESERVED_05,			"Reserved" },			/* (note) */
	{  BSSLAP_PARAM_RESERVED_06,			"Reserved" },			/* (note) */
	{  BSSLAP_PARAM_RESERVED_07,			"Reserved" },			/* (note) */
	{  BSSLAP_PARAM_MEASUREMENT_REPORT,		"Measurement Report" },
	{  BSSLAP_PARAM_RESERVED_08,			"Reserved" },			/* (note) */
	{  BSSLAP_PARAM_CAUSE,					"Cause" },
	{  BSSLAP_PARAM_RRLP_FLAG,				"RRLP Flag" },
	{  BSSLAP_PARAM_RRLP_IE,				"RRLP IE" },
	{  BSSLAP_PARAM_CELL_IDENTITY_LIST,		"Cell Identity List" },
	{  BSSLAP_PARAM_ENHANCED_MEASUREMENT_REPORT,	"Enhanced Measurement Report" },
	{  BSSLAP_PARAM_LOCATION_AREA_CODE,				"Location Area Code" },
	{  BSSLAP_PARAM_FREQUENCY_LIST,					"Frequency List" },
	{  BSSLAP_PARAM_MS_POWER,						"MS Power" },
	{  BSSLAP_PARAM_DELTA_TIMER,					"Delta Timer" },
	{  BSSLAP_PARAM_SERVING_CELL_IDENTIFIER,		"Serving Cell Identifier" },
	{  BSSLAP_PARAM_ENCRYPTION_KEY,					"Encryption Key (Kc)" },
	{  BSSLAP_PARAM_CIPHER_MODE_SETTING,			"Cipher Mode Setting" },
	{  BSSLAP_PARAM_CHANNEL_MODE,					"Channel Mode" },
	{  BSSLAP_PARAM_MULTIRATE_CONFIGURATION,		"MultiRate Configuration" },
	{  BSSLAP_PARAM_POLLING_REPETITION,				"Polling Repetition" },
	{  BSSLAP_PARAM_PACKET_CHANNEL_DESCRIPTION,		"Packet Channel Description" },
	{  BSSLAP_PARAM_TLLI,							"TLLI" },
	{  BSSLAP_PARAM_TFI,							"TFI" },
	{  BSSLAP_PARAM_STARTING_TIME,					"Starting Time" },
	{ 0,		NULL },
};

/*
 *	NOTE: These values of the codepoints shall not be used as they were used in an earlier version of the
 *	protocol.
 *	All unassigned codes are spare.
 */


#define BSSLAP_TA_REQUEST	1
#define BSSLAP_TA_RESPONSE	2
#define BSSLAP_REJECT		10
#define BSSLAP_RESET		11
#define BSSLAP_ABORT		12
#define BSSLAP_TA_LAYER3	13
#define BSSLAP_MS_POS_CMD	15
#define BSSLAP_MS_POS_RES	16
#define BSSLAP_U_TDOA_REQ	17
#define BSSLAP_U_TDOA_RES	18

/* Table 5.1.1: Message Type codes */
static const value_string gsm_a_bsslap_msg_strings[] = {
	{  0x00,				"Reserved" },
	{  BSSLAP_TA_REQUEST,	"TA REQUEST" },
	{  BSSLAP_TA_RESPONSE,	"TA RESPONSE" },
	{  0x04,				"Reserved" },
	{  0x05,				"Reserved" },
	{  BSSLAP_REJECT,		"REJECT" },
	{  BSSLAP_RESET,		"RESET" },
	{  BSSLAP_ABORT,		"ABORT" },
	{  BSSLAP_TA_LAYER3,	"TA LAYER3" },
	{  BSSLAP_MS_POS_CMD,	"MS Position Command" },
	{  BSSLAP_MS_POS_RES,	"MS Position Response" },
	{  BSSLAP_U_TDOA_REQ,	"U-TDOA Request" },
	{  BSSLAP_U_TDOA_RES,	"U-TDOA Response" },
	{ 0,			NULL }
};

#define	NUM_GSM_BSSLAP_ELEM (sizeof(gsm_bsslap_elem_strings)/sizeof(value_string))
gint ett_gsm_bsslap_elem[NUM_GSM_BSSLAP_ELEM];

/*
 * 5.2 Timing Advance IE
 */
static guint16
de_ta(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_item(tree, hf_gsm_bsslap_ta, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset - offset);
}
/*
 * 5.12 Measurement Report IE
 */
#if 0
static guint16
de_meas_rep(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_text(tree,tvb, curr_offset, len,"Not decoded yet");


	return(len);
}
#endif
/*
 * 5.14 Cause IE
 */
static const value_string gsm_bsslap_cause_vals[] = {
	{ 0x00,	"Congestion" },
	{ 0x01,	"Channel Mode not supported" },
	{ 0x02,	"Positioning procedure not supported" },
	{ 0x03,	"Failure for other radio related events" },
	{ 0x04,	"Intra-BSS handover" },
	{ 0x05,	"Supervision Timer Expired" },
	{ 0x06,	"Inter-BSS handover" },
	{ 0x07,	"Loss of signalling connection to MS" },
	{ 0x08,	"Incorrect serving cell identity" },
	{ 0x09,	"BSSAP-LE Segmentation error" },
	{ 0,	NULL }
};

static guint16
de_bsslap_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_item(tree, hf_gsm_bsslap_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset - offset);
}
/*
 * 5.15 RRLP Flag IE
 */
static const true_false_string gsm_bsslap_rrlp_flg_vals = {
	"Not a Positioning Command or final response." ,
	"Position Command (SMLC to BSC) or final response (BSC to SMLC)"
};
static guint16
de_rrlp_flg(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_item(tree, hf_gsm_bsslap_rrlp_flg, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset - offset);
}
static guint16
de_rrlp_ie(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
   guint32 curr_offset;
   tvbuff_t *rrlp_tvb;
   guint16 length;

   length = tvb_get_ntohs(tvb, offset);

   curr_offset = offset + 2;
   if (length > 0)
   {
      rrlp_tvb = tvb_new_subset(tvb, curr_offset, length, length);
      if (bsslap_rrlp_handle)
         call_dissector(bsslap_rrlp_handle, rrlp_tvb, pinfo, tree);
   }

   curr_offset += length;
   return(curr_offset - offset);
}
/*
 * 5.17 Cell Identity List IE
 */
/*
 * The Cell identification discriminator i is coded as follows:
 */
static const value_string gsm_a_bsslap_cell_id_disc_vals[] = {
	{  0x0,				"The whole Cell Global Identification, CGI, is used to identify the 2G cells" },
	{  0x1,				"Location Area Code, LAC, and Cell Identify, CI, are used to identify the 2G cells" },
	{  0x2,				"3G Cell identification container 1" },
	{  0x3,				"3G Cell identification container 2" },
	{ 0,			NULL }
};



static guint16
de_cell_id_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8	consumed;
	guint8 cell_id_disc;
	guint8	num_cells;
	proto_item	*item = NULL;
	proto_tree	*subtree = NULL;

	curr_offset = offset;
	cell_id_disc = tvb_get_guint8(tvb,curr_offset);
	num_cells = 0;

	while(len>0){
		num_cells++;
		consumed = 0;
		item = proto_tree_add_text(tree, tvb, curr_offset, -1, "Cell %u", num_cells);
		subtree = proto_item_add_subtree(item, ett_bsslap_cell_list);

		if (add_string)
			add_string[0] = '\0';
		proto_tree_add_item(subtree, hf_gsm_bsslap_cell_id_disc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		curr_offset++;
		len--;
		switch(cell_id_disc){
			case 0:
				/* The whole Cell Global Identification, CGI, is used to identify the 2G cells. */
				consumed+= be_cell_id_aux(tvb, subtree, pinfo, curr_offset, len, NULL, 0, 0);
				break;
			case 1:
				/* Location Area Code, LAC, and Cell Identify, CI, are used to identify the 2G cells. */
				consumed+= be_cell_id_aux(tvb, subtree, pinfo, curr_offset, len, NULL, 0, 1);
				break;
			case 2:
				/* 3G Cell identification container 1 */
				/* fall trough */
			case 3:
				/* 3G Cell identification container 2 */
				/* fall trough */
			default:
				proto_tree_add_text(subtree,tvb, curr_offset, len,"Not decoded yet");
				consumed = len;
				break;
		}
		curr_offset += consumed;
		len-=consumed;
		/* lengt is "cell id" + discriminator */
		proto_item_set_len(item, consumed+1);
	}


	return(curr_offset - offset);
}
/*
 * 5.18 Enhanced Measurement Report IE
 * The Enhanced Measurement Results field is encoded as the contents of the
 * ENHANCED MEASUREMENT REPORT message in 3GPP TS 44.018 (excluding the fields:
 * "RR short PD", "Message type" and "Short layer 2 header")...
 */
static guint16
de_enh_meas_rep(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_text(tree,tvb, curr_offset, len,"Not decoded yet");


	return(len);
}
/*
 * 5.19 Location Area Code IE
 */
static guint16
de_lac(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_item(tree, hf_gsm_bsslap_lac, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset - offset);
}
/*
 * 5.21 MS Power IE
 */
static guint16
de_ms_pow(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_item(tree, hf_gsm_bsslap_ms_pow, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset - offset);
}

/*
 * 5.22 Delta Timer IE
 */
static guint16
de_delta_time(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_item(tree, hf_gsm_bsslap_timer_value, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset - offset);
}
/*
 * 5.23 Serving Cell Identifier IE
 * The Serving Cell Identifier IE is encoded as in 3GPP TS 48.008 (excluding IEI and length field).
 */
/*
 * 5.24 Encryption Key
 */
static guint16
de_blap_enc_key(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_text(tree,tvb, curr_offset, 8,"Encryption Key (Kc)");
	curr_offset = curr_offset + 8;

	return(curr_offset - offset);
}
/*
 * 5.25 Cipher Mode Setting IE
 * The Cipher Mode Setting information element is coded as defined in TS 44.018 (excluding IEI).
 */
/*
 * 5.26 Channel Mode IE
 * The Channel Mode information element is coded as defined in TS 44.018 (excluding IEI).
 */
/*
 * 5.27 MultiRate Configuration IE
 * The MultiRate Configuration information element is coded as defined in TS 44.018 (excluding IEI).
 */
/*
 * 5.28 Polling Repetition IE
 */
static guint16
de_poll_rep(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_item(tree, hf_gsm_bsslap_poll_rep, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset - offset);
}
/*
 * 5.29 Packet Channel Description IE
 * CSN.1 binary representation of the channel parameters as
 * described in TS 44.018 (CCCH) or TS 44.060 (PCCCH) plus
 * padding bits (binary 0) as required to achieve 4 complete octets
 */
static guint16
de_pkt_ch_desc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_text(tree,tvb, curr_offset, len,"Not decoded yet");


	return(len);
}
/*
 * 5.31 TFI IE
 * The TFI information element is coded as defined in TS 44.060 (excluding IEI).
 * 44.060:
 * UPLINK_TFI (5 bit field)
 * The Temporary Flow Identity field identifies an uplink Temporary Block Flow (TBF).
 * This field is encoded as a binary number. Range 0 to 31
 */
static guint16
de_tfi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	proto_tree_add_item(tree, hf_gsm_bsslap_tfi, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return(curr_offset - offset);
}

/*
This enum has been moved to packet-gsm_a_common to
make it possible to use element dissecton from this dissector
in other dissectors.
It is left here as a comment for easier reference.

Note this enum must be of the same size as the element decoding list

typedef enum
{
	/. BSS LAP Elements 5 ./
	DE_BLAP_RES1,			/. Reserved ./
	DE_BLAP_TA,				/. Timing Advance ./
	DE_BLAP_RES3,			/. Reserved ./			/. (note) ./
	DE_BLAP_RES4,			/. Cell Identity ./
	DE_BLAP_RES5,			/. Reserved ./			/. (note) ./
	DE_BLAP_RES6,			/. Reserved ./			/. (note) ./
	DE_BLAP_RES7,			/. Reserved ./			/. (note) ./
	DE_BLAP_CH_DESC,		/. Channel Description ./
	DE_BLAP_RES9,			/. Reserved ./			/. (note) ./
	DE_BLAP_RES10,			/. Reserved ./			/. (note) ./
	DE_BLAP_RES11,			/. Reserved ./			/. (note) ./
	DE_BLAP_MEAS_REP,		/. Measurement Report ./
	DE_BLAP_RES13,			/. Reserved ./			/. (note) ./
	DE_BLAP_CAUSE,			/. Cause ./
	DE_BLAP_RRLP_FLG,		/. RRLP Flag ./
	DE_BLAP_RRLP_IE,		/. RRLP IE ./
	DE_BLAP_CELL_ID_LIST,	/. Cell Identity List ./
	DE_BLAP_ENH_MEAS_REP,	/. Enhanced Measurement Report ./
	DE_BLAP_LAC,			/. Location Area Code ./
	DE_BLAP_FREQ_LIST,		/. Frequency List ./
	DE_BLAP_MS_POW,			/. MS Power ./
	DE_BLAP_DELTA_TIME,		/. Delta Timer ./
	DE_BLAP_SERV_CELL_ID,	/. Serving Cell Identifier ./
	DE_BLAP_ENC_KEY,		/. Encryption Key (Kc) ./
	DE_BLAP_CIP_M_SET,		/. Cipher Mode Setting ./
	DE_BLAP_CH_MODE,		/. Channel Mode ./
	DE_BLAP_POLL_REP,		/. Polling Repetition ./
	DE_BLAP_PKT_CH_DESC,	/. Packet Channel Description ./
	DE_BLAP_TLLI,			/. TLLI ./
	DE_BLAP_TFI,			/. TFI ./
	DE_BLAP_START_TIME,		/. Starting Time ./
	BSSLAP_NONE				/. NONE ./
}
bsslap_elem_idx_t;
*/
elem_fcn bsslap_elem_fcn[];

guint16 (*bsslap_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* BSS LAP Elements 5 */
	NULL,	/* Reserved */
	de_ta,	/* Timing Advance */
	NULL,	/* Reserved */			/* (note) */
	NULL,	/* "Cell Identity */
	NULL,	/* "Reserved */			/* (note) */
	NULL,	/* "Reserved */			/* (note) */
	NULL,	/* "Reserved */			/* (note) */
	NULL,	/* "Channel Description */
	NULL,	/* "Reserved */			/* (note) */
	NULL,	/* Reserved */			/* (note) */
	NULL,	/* Reserved */			/* (note) */
	de_rr_meas_res,	/* "Measurement Report */
	NULL,	/* "Reserved */			/* (note) */
	de_bsslap_cause,	/* "Cause */
	de_rrlp_flg,	/* "RRLP Flag */
	de_rrlp_ie,	/* "RRLP IE */
	de_cell_id_list,	/* "Cell Identity List */
	de_enh_meas_rep,	/* Enhanced Measurement Report */
	de_lac,	/* "Location Area Code */
	NULL,	/* "Frequency List */
	de_ms_pow,	/* MS Power */
	de_delta_time,	/* Delta Timer */
	NULL,	/* Serving Cell Identifier */
	de_blap_enc_key,	/* Encryption Key (Kc) */
	NULL,	/* Cipher Mode Setting */
	NULL,	/* Channel Mode */
	de_poll_rep,	/* Polling Repetition */
	de_pkt_ch_desc,	/* Packet Channel Description */
	NULL,	/* TLLI */
	de_tfi,	/* TFI */
	NULL,	/* Starting Time */
	NULL,	/* NONE */
};

#define	NUM_GSM_BSSLAP_MSG (sizeof(gsm_a_bsslap_msg_strings)/sizeof(value_string))
static gint ett_gsm_bsslap_msg[NUM_GSM_BSSLAP_MSG];

/* 4.2.2 TA Response ETSI TS 148 071 V7.2.0 (2007-06) */
static void
dissect_gsm_bsslap_ta_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = tvb_length_remaining(tvb,offset);

	/* Cell Identity IE / 5.4 M TV 3 */
	ELEM_MAND_TV(BSSLAP_PARAM_CELL_IDENTITY, GSM_A_PDU_TYPE_COMMON, DE_CELL_ID, "Serving Cell Identity");
	/* Timing Advance IE / 5.2 M TV 2 */
	ELEM_MAND_TV(BSSLAP_PARAM_TIMING_ADVANCE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_TA, NULL);
	/* Measurement Report IE / 5.12 O TLV 18 */
	ELEM_OPT_TLV(BSSLAP_PARAM_MEASUREMENT_REPORT, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_MEAS_REP, " BSSLAP");
	/* Enhanced Measurement Report IE / 5.18 O TLV 4-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_ENHANCED_MEASUREMENT_REPORT, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_ENH_MEAS_REP, NULL);
	/* Cell Identity List IE / 5.17 O TLV 6-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_CELL_IDENTITY_LIST, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_CELL_ID_LIST, "-Measured Cell");

	return;

}


/* 4.2.3 (void)   ETSI TS 148 071 V7.2.0 (2007-06) */
/* 4.2.4 (void)   ETSI TS 148 071 V7.2.0 (2007-06) */
/* 4.2.5 Reject   ETSI TS 148 071 V7.2.0 (2007-06) */
static void
dissect_gsm_bsslap_reject(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = tvb_length_remaining(tvb,offset);

	/* Cause IE / 5.14 M TV 2 */
	ELEM_MAND_TV(BSSLAP_PARAM_CAUSE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_CAUSE,NULL);

	return;
}

/* 4.2.6 Reset   ETSI TS 148 071 V7.2.0 (2007-06) */
static void
dissect_gsm_bsslap_reset(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = tvb_length_remaining(tvb,offset);

	/* Cell Identity IE / 5.4 M TV 3 */
	ELEM_MAND_TV(BSSLAP_PARAM_CELL_IDENTITY, GSM_A_PDU_TYPE_COMMON, DE_CELL_ID, NULL);
	/* Timing Advance IE / 5.2 M TV 2 */
	ELEM_MAND_TV(BSSLAP_PARAM_TIMING_ADVANCE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_TA, NULL);
	/* Channel Description IE / 5.8 M TV 4 */
	ELEM_MAND_TV(BSSLAP_PARAM_CHANNEL_DESCRIPTION,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC,NULL);
	/* Cause IE / 5.1 M TV 2 */
	ELEM_MAND_TV(BSSLAP_PARAM_CAUSE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_CAUSE,NULL);
	/* Measurement Report Measurement Report IE / 5.12 O TLV 18 */
	ELEM_OPT_TLV(BSSLAP_PARAM_MEASUREMENT_REPORT, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_MEAS_REP, " BSSLAP");
	/* Enhanced Measurement Report Enhanced Measurement Report IE / 5.18 O TLV 4-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_ENHANCED_MEASUREMENT_REPORT, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_ENH_MEAS_REP, NULL);
	/* Cell Identity List IE / 5.17 O TLV 6-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_CELL_IDENTITY_LIST, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_CELL_ID_LIST, "-Measured Cell");
	/* LAC Location Area Code IE / 5.19 O TV 3 */
	ELEM_OPT_TLV(BSSLAP_PARAM_LOCATION_AREA_CODE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_LAC, NULL);
	/* Frequency List Frequency List IE 5.20 C (note 1) TLV 3-n  */
	ELEM_OPT_TLV(BSSLAP_PARAM_FREQUENCY_LIST, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, NULL);
	/* Channel Mode IE 5.26 C (notes 2 & 4) TV 2 */
	ELEM_OPT_TV(BSSLAP_PARAM_CHANNEL_MODE, GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, NULL);
	/* MultiRate Configuration 5.27 C (notes 3 & 4) TLV 4-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_MULTIRATE_CONFIGURATION, GSM_A_PDU_TYPE_RR, DE_RR_MULTIRATE_CONF, NULL);
	/* Packet Channel Description Packet Channel Description IE 5.29 C (note 5) TV 4 */
	ELEM_OPT_TLV(BSSLAP_PARAM_PACKET_CHANNEL_DESCRIPTION, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_PKT_CH_DESC, NULL);
	/* TLLI IE 5.30 C (note 5) TV 5 */
	ELEM_OPT_TV(BSSLAP_PARAM_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI,NULL);
	/* TFI 5.31 C (note 5) TV 2 */
	ELEM_OPT_TV(BSSLAP_PARAM_TFI, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_TFI,NULL);
	/* Starting Time IE 5.32 C (note 5) TV 3 */
	ELEM_OPT_TV(BSSLAP_PARAM_STARTING_TIME, GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, "TBF Starting Time");
	/* Encryption Key IE 5.24 C (note 4) TV 9 */
	ELEM_OPT_TV(BSSLAP_PARAM_ENCRYPTION_KEY, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_ENC_KEY,NULL);
	/* Cipher Mode Setting IE 5.25 C (note 4) TV 2 */
	ELEM_OPT_TV(BSSLAP_PARAM_CIPHER_MODE_SETTING, GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_SET, NULL);
	return;
}

/* 4.2.7 Abort  ETSI TS 148 071 V7.2.0 (2007-06) */
static void
dissect_gsm_bsslap_abort(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = tvb_length_remaining(tvb,offset);

	/* Cause IE / 5.14 M TV 2 */
	ELEM_MAND_TV(BSSLAP_PARAM_CAUSE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_CAUSE,NULL);

	return;
}
/* 4.2.8 TA Layer3  ETSI TS 148 071 V7.2.0 (2007-06) */
static void
dissect_gsm_bsslap_ta_layer3(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = tvb_length_remaining(tvb,offset);

	/* Timing Advance IE / 5.2 M TV 2 */
	ELEM_MAND_TV(BSSLAP_PARAM_TIMING_ADVANCE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_TA, NULL);
	/* Measurement Report IE / 5.12 O TLV 18 */
	ELEM_OPT_TLV(BSSLAP_PARAM_MEASUREMENT_REPORT, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_MEAS_REP, " BSSLAP");
	/* Enhanced Measurement Report IE / 5.18 O TLV 4-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_ENHANCED_MEASUREMENT_REPORT, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_ENH_MEAS_REP, NULL);
	/*Cell Identity List IE / 5.17 O TLV 6-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_CELL_IDENTITY_LIST, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_CELL_ID_LIST, "-Measured Cell");
	return;
}
/* 4.2.9 MS Position Command  ETSI TS 148 071 V7.2.0 (2007-06) */
static void
dissect_gsm_bsslap_ms_pos_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = tvb_length_remaining(tvb,offset);

	/* RRLP flag IE / 5.15 M TV 2 */
	ELEM_MAND_TV(BSSLAP_PARAM_RRLP_FLAG, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_RRLP_FLG,"flag");
	/* RRLP IE / 5.16 M TLV 3-n */
	ELEM_MAND_TV(BSSLAP_PARAM_RRLP_IE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_RRLP_IE,"RRLP Info");
	return;
}
/* 4.2.10 MS Position Response   ETSI TS 148 071 V7.2.0 (2007-06) */
static void
dissect_gsm_bsslap_ms_pos_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = tvb_length_remaining(tvb,offset);

	/* flag RRLP flag IE / 5.15 M TV 2  */
	ELEM_MAND_TV(BSSLAP_PARAM_RRLP_FLAG, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_RRLP_FLG,"flag");
	/* RRLP Info RRLP IE / 5.16 M TLV 3-n */
	ELEM_MAND_TV(BSSLAP_PARAM_RRLP_IE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_RRLP_IE,"RRLP Info");
	/* Timing Advance IE / 5.2 O TV 2 */
	ELEM_OPT_TV(BSSLAP_PARAM_TIMING_ADVANCE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_TA, NULL);
	/* Measurement Report IE / 5.12 O TLV 18 */
	ELEM_OPT_TLV(BSSLAP_PARAM_MEASUREMENT_REPORT, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_MEAS_REP, " BSSLAP");
	/* Enhanced Measurement Report IE / 5.18 O TLV 4-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_ENHANCED_MEASUREMENT_REPORT, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_ENH_MEAS_REP, NULL);
	/* Cell Identity List IE / 5.17 O TLV 6-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_CELL_IDENTITY_LIST, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_CELL_ID_LIST, "-Measured Cell");
	return;
}
/* 4.2.11 U-TDOA Request   ETSI TS 148 071 V7.2.0 (2007-06) */
static void
dissect_gsm_bsslap_u_tdoa_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = tvb_length_remaining(tvb,offset);

	/* Delta Timer IE 5.22 O (note 1) TV 2 */
	ELEM_OPT_TV(BSSLAP_PARAM_DELTA_TIMER, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_DELTA_TIME, NULL);
	/* 	Polling Repitition IE 5.28 (note) C (note 2) TV 2 */
	ELEM_OPT_TV(BSSLAP_PARAM_POLLING_REPETITION, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_POLL_REP, NULL);

	return;
}
/* 4.2.12 U-TDOA Response  ETSI TS 148 071 V7.2.0 (2007-06) */
static void
dissect_gsm_bsslap_u_tdoa_res(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = tvb_length_remaining(tvb,offset);

	/* Channel Description IE 5.8 M TV 4 */
	ELEM_MAND_TV(BSSLAP_PARAM_CHANNEL_DESCRIPTION,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, NULL);
	/* Serving Cell Identifier Cell Identifier IE 5.23 M TLV 4-n */
	ELEM_MAND_TLV(BSSLAP_PARAM_SERVING_CELL_IDENTIFIER,GSM_A_PDU_TYPE_BSSMAP, BE_CELL_ID, NULL);
	/* Frequency List IE 5.20 C (note 3) TLV 3-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_FREQUENCY_LIST, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, NULL);
	/* Timing Advance IE 5.2 O TV 2 */
	ELEM_OPT_TV(BSSLAP_PARAM_TIMING_ADVANCE, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_TA, NULL);
	/* MS Power IE 5.21 O TV 2 */
	ELEM_OPT_TV(BSSLAP_PARAM_MS_POWER, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_MS_POW, NULL);
	/* Measurement Report IE 5.12 O TLV 18 */
	ELEM_OPT_TLV(BSSLAP_PARAM_MEASUREMENT_REPORT, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_MEAS_REP, " BSSLAP");
	/* Encryption Key IE 5.24 C (note 4) TV 9 */
	ELEM_OPT_TV(BSSLAP_PARAM_ENCRYPTION_KEY, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_ENC_KEY, NULL);
	/* Cipher Mode Setting IE 5.25 C (note 4) TV 2 */
	ELEM_OPT_TV(BSSLAP_PARAM_CIPHER_MODE_SETTING, GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_SET, NULL);
	/* Channel Mode IE 5.26 C (notes 1 & 4)TV 2 */
	ELEM_OPT_TV(BSSLAP_PARAM_CHANNEL_MODE, GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, NULL);
	/* MultiRate Configuration IE 5.27 C (notes 1 & 4)TLV 4-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_MULTIRATE_CONFIGURATION, GSM_A_PDU_TYPE_RR, DE_RR_MULTIRATE_CONF, NULL);
	/* Cell Identity List IE / 5.17 O TLV 6-n */
	ELEM_OPT_TLV(BSSLAP_PARAM_CELL_IDENTITY_LIST, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_CELL_ID_LIST, "-Measured Cell");
	/* Packet Channel Description IE 5.29 C (note 5) TV 4 */
	ELEM_OPT_TLV(BSSLAP_PARAM_PACKET_CHANNEL_DESCRIPTION, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_PKT_CH_DESC, NULL);
	/* TLLI IE 5.30 C (note 5) TV 5 */
	ELEM_OPT_TV(BSSLAP_PARAM_TLLI, GSM_A_PDU_TYPE_RR, DE_RR_TLLI, NULL);
	/* TFI IE 5.31 C (note 5) TV 2 BSSLAP_PARAM_TFI*/
	ELEM_OPT_TV(BSSLAP_PARAM_TFI, GSM_A_PDU_TYPE_BSSLAP, DE_BLAP_TFI, NULL);
	/* Starting Time IE 5.32 C (note 5) TV 3*/
	ELEM_OPT_TV(BSSLAP_PARAM_STARTING_TIME, GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, "TBF Starting Time");
	return;
}


static void
dissect_gsm_bsslap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *sub_tree;
	int	offset=0;
	guint8 octet;

/* Make entries in Protocol column and Info column on summary display */
	col_append_str(pinfo->cinfo, COL_PROTOCOL, "/BSSLAP");
	if (tree) {
		octet = tvb_get_guint8(tvb, offset);
		item = proto_tree_add_item(tree, proto_gsm_bsslap, tvb, 0, -1, FALSE);
		sub_tree = proto_item_add_subtree(item, ett_gsm_bsslap);

		/* Message Type IE / 5.1 M V 1 */
		proto_tree_add_item(sub_tree, hf_gsm_bsslap_msg_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		switch (octet){
		case BSSLAP_TA_REQUEST:
			/* Only message type IE */
			break;
		case BSSLAP_TA_RESPONSE:
			dissect_gsm_bsslap_ta_res(tvb, sub_tree, pinfo, offset);
			break;
		case BSSLAP_REJECT:
			dissect_gsm_bsslap_reject(tvb, sub_tree, pinfo, offset);
			break;
		case BSSLAP_RESET:
			dissect_gsm_bsslap_reset(tvb, sub_tree, pinfo, offset);
			break;
		case BSSLAP_ABORT:
			dissect_gsm_bsslap_abort(tvb, sub_tree, pinfo, offset);
			break;
		case BSSLAP_TA_LAYER3:
			dissect_gsm_bsslap_ta_layer3(tvb, sub_tree, pinfo, offset);
			break;
		case BSSLAP_MS_POS_CMD:
			dissect_gsm_bsslap_ms_pos_cmd(tvb, sub_tree, pinfo, offset);
			break;
		case BSSLAP_MS_POS_RES:
			dissect_gsm_bsslap_ms_pos_res(tvb, sub_tree, pinfo, offset);
			break;
		case BSSLAP_U_TDOA_REQ:
			dissect_gsm_bsslap_u_tdoa_req(tvb, sub_tree, pinfo, offset);
			break;
		case BSSLAP_U_TDOA_RES:
			dissect_gsm_bsslap_u_tdoa_res(tvb, sub_tree, pinfo, offset);
			break;
		default:
			break;
		}
	}


}

void
proto_reg_handoff_gsm_bsslap(void)
{
	bsslap_rrlp_handle = find_dissector("rrlp");
}

void
proto_register_gsm_bsslap(void)
{
	guint		i;
	guint		last_offset;


	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_gsm_bsslap_msg_type,
			{ "Message Type IE",           "gsm_bsslap.msg_type",
			FT_UINT8, BASE_DEC, VALS(gsm_a_bsslap_msg_strings), 0x0,
			NULL, HFILL }
		},
		{ &hf_gsm_a_bsslap_elem_id,
			{ "Element ID",	"gsm_bsslap.elem_id",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_gsm_bsslap_ta,
			{ "Timing Advance",           "gsm_bsslap.ta",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
        { &hf_gsm_bsslap_timer_value,
			{"Timer Value", "gsm_bsslap.timerValue",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},

        { &hf_gsm_bsslap_ms_pow,
			{"MS Power", "gsm_bsslap.MS_pow",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gsm_bsslap_cause,
			{"Cause", "gsm_bsslap.cause",
			FT_UINT8, BASE_DEC, VALS(gsm_bsslap_cause_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_gsm_bsslap_rrlp_flg,
			{"RRLP Flag", "gsm_bsslap.rrlp_flg",
			FT_UINT8, BASE_DEC, TFS(&gsm_bsslap_rrlp_flg_vals), 0x01,
			"Cause", HFILL }
		},
		{ &hf_gsm_bsslap_tfi,
			{"TFI", "gsm_bsslap.tfi",
			FT_UINT8, BASE_DEC, NULL, 0x1f,
			NULL, HFILL }
		},
		{ &hf_gsm_bsslap_poll_rep,
			{"Number of polling repetitions", "gsm_bsslap.poll_rep",
			FT_UINT8, BASE_DEC, NULL, 0x3F,
			NULL, HFILL }
		},
		{ &hf_gsm_bsslap_lac,
			{"Location Area Code", "gsm_bsslap.lac",
			FT_UINT8, BASE_DEC, NULL, 0x3f,
			NULL, HFILL }
		},
		{ &hf_gsm_bsslap_cell_id_disc,
			{"Cell identification Discriminator", "gsm_bsslap.cell_id_disc",
			FT_UINT8, BASE_DEC, VALS(gsm_a_bsslap_cell_id_disc_vals), 0xf,
			NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	2
	gint *ett[NUM_INDIVIDUAL_ELEMS + NUM_GSM_BSSLAP_MSG +
		  NUM_GSM_BSSLAP_ELEM];

	ett[0] = &ett_gsm_bsslap;
	ett[1] = &ett_bsslap_cell_list;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_GSM_BSSLAP_MSG; i++, last_offset++)
	{
		ett_gsm_bsslap_msg[i] = -1;
		ett[last_offset] = &ett_gsm_bsslap_msg[i];
	}

	for (i=0; i < NUM_GSM_BSSLAP_ELEM; i++, last_offset++)
	{
		ett_gsm_bsslap_elem[i] = -1;
		ett[last_offset] = &ett_gsm_bsslap_elem[i];
	}


/* Register the protocol name and description */
	proto_gsm_bsslap =
		proto_register_protocol("BSS LCS Assistance Protocol",
		"BSSLAP", "bsslap");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_gsm_bsslap, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("gsm_bsslap", dissect_gsm_bsslap, proto_gsm_bsslap);
}
