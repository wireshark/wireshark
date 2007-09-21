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
static int hf_rsl_phy_ctx			= -1;
static int hf_rsl_na				= -1;
static int hf_rsl_ch_type			= -1;
static int hf_rsl_prio				= -1;
static int hf_rsl_sapi				= -1;
static int hf_rsl_cause				= -1;
static int hf_rsl_rel_mode			= -1;

/* Initialize the subtree pointers */
static int ett_rsl = -1;
static int ett_ie_ch_no = -1;
static int ett_ie_phy_ctx = -1;
static int ett_ie_access_delay = -1;
static int ett_ie_req_ref = -1;
static int ett_ie_full_imm_ass_inf = -1;

proto_tree *top_tree;
dissector_handle_t gsm_a_ccch_handle = NULL;
dissector_handle_t gsm_a_dtap_handle = NULL;

static const true_false_string rsl_t_bit_vals = {
  "Considered transparent by BTS",
  "Not considered transparent by BTS"
};

static const true_false_string rsl_na_vals = {
  "Applicable",
  "Not Applicable"
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
#define RSL_MSG_TYPE_DATA_REQ	1
#define RSL_MSG_TYPE_DATA_IND	2
#define RSL_MSG_TYPE_ERROR_IND	3
#define RSL_MSG_TYPE_EST_REQ	4
#define RSL_MSG_TYPE_EST_CONF	5
#define RSL_MSG_EST_IND			6
#define RSL_MSG_REL_REQ			7
#define RSL_MSG_REL_CONF		8
#define RSL_MSG_REL_IND			9
#define RSL_MSG_UNIT_DATA_REQ	10

#define RSL_MSG_CHANRQD			19
#define RSL_MSG_IMM_ASS_CMD		22
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
dissect_rsl_ie_ch_no(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *ie_tree;

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
dissect_rsl_ie_link_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint8 octet;

	ti = proto_tree_add_text(tree, tvb,offset,2,"Link Identifier IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_phy_ctx);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;

	octet = tvb_get_guint8(tvb,offset);

	if(octet&0x20 == 0x20){
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
 * 9.3.11 L3 Information			9.3.11	M TLV >=3
 *
 * This element contains a link layer service data unit (L3 message).
 * It is used to forward a complete L3 message as specified in 
 * 3GPP TS 24.008 or 3GPP TS 44.018 between BTS and BSC.
 */
static int
dissect_rsl_ie_L3_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *ie_tree;
	tvbuff_t	*next_tvb;
	guint16 length;

	ti = proto_tree_add_text(tree, tvb,offset,0,"L3 Information ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_phy_ctx);

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
 * 9.3.16 Physical Context TLV
 */
static int
dissect_rsl_ie_phy_ctx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *ie_tree;
	guint length;

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
dissect_rsl_ie_access_delay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *ie_tree;

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
dissect_rsl_ie_req_ref(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *ie_tree;

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
dissect_rsl_ie_rel_mode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *ie_tree;

	ti = proto_tree_add_text(tree, tvb,offset,4,"Release Mode IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_req_ref);

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

static const value_string rsl_cause_vals[] = {
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
dissect_rsl_ie_rlm_cause(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *ie_tree;

	guint		length;

	ti = proto_tree_add_text(tree, tvb,offset,0,"RLM Cause IE ");
	ie_tree = proto_item_add_subtree(ti, ett_ie_full_imm_ass_inf);

	/* Element identifier */
	proto_tree_add_item(ie_tree, hf_rsl_ie_id, tvb, offset, 1, FALSE);
	offset++;
	/* Length */
	length = tvb_get_guint8(tvb,offset);
	proto_item_set_len(ti, length+2);

	proto_tree_add_item(ie_tree, hf_rsl_ie_length, tvb, offset, 1, FALSE);

	/* The Cause Value is a one octet field if the extension bit is set to 0. 
	 * If the extension bit is set to 1, the Cause Value is a two octet field.
	 */
	proto_tree_add_item(ie_tree, hf_rsl_cause, tvb, offset, 1, FALSE);
	offset++;
	offset = offset + length;

	return offset;
}

/*
 * 9.3.35 Full Immediate Assign Info TLV 25
 */
static int
dissect_rsl_ie_full_imm_ass_inf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	proto_item *ti;
	proto_tree *ie_tree;

	guint		length;
	tvbuff_t	*next_tvb;

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
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* Link Identifier			9.3.2	M TV 2		*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset);
		/* L3 Information			9.3.11	M TLV >=3	*/
		offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset);
		break;
	/* 8.3.2 DATA INDICATION */
	case RSL_MSG_TYPE_DATA_IND:
		/* Channel number			9.3.1	M TV 2		*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* Link Identifier			9.3.2	M TV 2		*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset);
		/* L3 Information			9.3.11	M TLV >=3	*/
		offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset);
		break;
	/* 8.3.3 ERROR INDICATION */
	case RSL_MSG_TYPE_ERROR_IND:
		/* Channel number			9.3.1	M TV 2		*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* Link Identifier			9.3.2	M TV 2		*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset);
		/* RLM Cause				9.3.22	M TLV 2-4	*/
		offset = dissect_rsl_ie_rlm_cause(tvb, pinfo, tree, offset);
		break;
	/* 8.3.4 ESTABLISH REQUEST */
	case RSL_MSG_TYPE_EST_REQ:
		/* Channel number			9.3.1	M TV 2		*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* Link Identifier			9.3.2	M TV 2		*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset);
		break;
	/* 8.3.5 ESTABLISH CONFIRM */
	case RSL_MSG_TYPE_EST_CONF:
		/* Channel number			9.3.1	M TV 2		*/
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* Link Identifier			9.3.2	M TV 2		*/
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset);
		break;
	/* 8.3.6 */
	case RSL_MSG_EST_IND:
		/* 	Channel number			9.3.1	M TV 2				 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* 	Link Identifier			9.3.2	M TV 2				 */
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset);
		/* 	L3 Information			9.3.11	O (note 1) TLV 3-23	 */
		if(tvb_length_remaining(tvb,offset) >1)
			offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset);
		break;
	/* 8.3.7 RELEASE REQUEST */
	case RSL_MSG_REL_REQ:
		/* 	Channel number			9.3.1	M TV 2				 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* 	Link Identifier			9.3.2	M TV 2				 */
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset);
		/* Release Mode				9.3.20	M TV 2				*/
		offset = dissect_rsl_ie_rel_mode(tvb, pinfo, tree, offset);
		break;
	/* 8.3.8 RELEASE CONFIRM */
	case RSL_MSG_REL_CONF:
		/* 	Channel number			9.3.1	M TV 2				 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* 	Link Identifier			9.3.2	M TV 2				 */
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset);
		break;
	/* 8.3.9 RELEASE INDICATION */
	case RSL_MSG_REL_IND:
		/* 	Channel number			9.3.1	M TV 2				 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* 	Link Identifier			9.3.2	M TV 2				 */
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset);
		break;
	/* 8.3.10 UNIT DATA REQUEST */
	case RSL_MSG_UNIT_DATA_REQ:
		/* 	Channel number			9.3.1	M TV 2				 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* 	Link Identifier			9.3.2	M TV 2				 */
		offset = dissect_rsl_ie_link_id(tvb, pinfo, tree, offset);
		/* 	L3 Information			9.3.11	O (note 1) TLV 3-23	 */
		offset = dissect_rsl_ie_L3_inf(tvb, pinfo, tree, offset);
		break;

/* Common Channel Management/TRX Management messages: */ 
	/* 8.5.3 */
	case RSL_MSG_CHANRQD:
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* Request Reference		9.3.19	M TV 4 */
		offset = dissect_rsl_ie_req_ref(tvb, pinfo, tree, offset);
		/* Access Delay				9.3.17	M TV 2 */
		offset = dissect_rsl_ie_access_delay(tvb, pinfo, tree, offset);
		/* Physical Context			9.3.16	O 1) TLV >=2 */
		if(tvb_length_remaining(tvb,offset) > 0)
			offset = dissect_rsl_ie_phy_ctx(tvb, pinfo, tree, offset);
		break;
	case RSL_MSG_IMM_ASS_CMD:
		/* Channel number			9.3.1	M TV 2 */
		offset = dissect_rsl_ie_ch_no(tvb, pinfo, tree, offset);
		/* Full Imm. Assign Info	9.3.35	M TLV 25 */
		offset = dissect_rsl_ie_full_imm_ass_inf(tvb, pinfo, tree, offset);
		break;
/* Dedicated Channel Management messages: */
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
		offset = dissct_rsl_msg(tvb, pinfo, rsl_tree, offset );
		
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
			FT_UINT8, BASE_DEC, NULL, 0x03,          
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
		{ &hf_rsl_cause,
			{ "Cause",           "rsl.cause",
			FT_UINT8, BASE_DEC, VALS(rsl_cause_vals), 0x7f,          
			"Cause", HFILL }
		},
		{ &hf_rsl_rel_mode,
			{ "Release Mode",           "rsl.rel_mode",
			FT_UINT8, BASE_DEC, VALS(rel_mode_vals), 0x01,          
			"Relese Mode", HFILL }
		},

	};
	static gint *ett[] = {
		&ett_rsl,
		&ett_ie_ch_no,
		&ett_ie_phy_ctx,
		&ett_ie_access_delay,
		&ett_ie_req_ref,
		&ett_ie_full_imm_ass_inf,
	};

	/* Register the protocol name and description */
	proto_rsl = proto_register_protocol("Radio Signalling Link (RSL)",
	                                    "RSL", "rsl");

	proto_register_field_array(proto_rsl, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));


}
