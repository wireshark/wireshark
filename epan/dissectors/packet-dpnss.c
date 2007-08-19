/* packet-dpnss_dass2.c
 * Routines for DPNNS/DASS2 dissection
 * Copyright 2007, Anders Broman <anders.broman[at]ericsson.com>
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
 * References:
 * ND1301:2001/03  http://www.nicc.org.uk/nicc-public/Public/interconnectstandards/dpnss/nd1301_2004_11.pdf
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/proto.h>

/* Initialize the protocol and registered fields */
static int proto_dpnss						= -1;
static int hf_dpnss_msg_grp_id				= -1;
static int hf_dpnss_cc_msg_type				= -1;
static int hf_dpnss_e2e_msg_type			= -1;
static int hf_dpnss_LbL_msg_type			= -1;
static int hf_dpnss_ext_bit					= -1;
static int hf_dpnss_ext_bit_notall			= -1;
static int hf_dpnss_sic_type				= -1;
static int hf_dpnss_sic_details_for_speech	= -1;
static int hf_dpnss_sic_details_for_data1	= -1;
static int hf_dpnss_sic_details_for_data2	= -1;
static int hf_dpnss_dest_addr				= -1;
static int hf_dpnss_sic_oct2_data_type		= -1;
static int hf_dpnss_sic_oct2_duplex			= -1;
static int hf_dpnss_sic_oct2_sync_data_format = -1;
static int hf_dpnss_sic_oct2_sync_byte_timing = -1;
static int hf_dpnss_sic_oct2_net_ind_clk	= -1;
static int hf_dpnss_sic_oct2_async_data		= -1;
static int hf_dpnss_sic_oct2_async_flow_ctrl = -1;
static int hf_dpnss_clearing_cause			= -1;
static int hf_dpnss_rejection_cause			= -1; 

#define DPNNS_MESSAGE_GROUP_CC			0
#define DPNNS_MESSAGE_GROUP_E2E			2
#define DPNNS_MESSAGE_GROUP_LbL			4

#define DPNSS_CC_MSG_ISRM_C				0
#define DPNSS_CC_MSG_ISRM_I				1
#define DPNSS_CC_MSG_RM_C				2
#define DPNSS_CC_MSG_RM_I				3
#define DPNSS_CC_MSG_CCM				5
#define DPNSS_CC_MSG_NIM				6
#define DPNSS_CC_MSG_CRM				8
#define DPNSS_CC_MSG_NAM				9
#define DPNSS_CC_MSG_RRM				10
#define DPNSS_CC_MSG_SSRM_I				11
#define DPNSS_CC_MSG_SSRM_C				12

/* Initialize the subtree pointers */
static int ett_dpnss			= -1;
static int ett_dpnss_sel_field	= -1;
static int ett_dpnss_sic_field	= -1;
static int ett_dpnss_ind_field	= -1;

static const value_string dpnss_msg_grp_id_vals[] = {
	{0,		"Call Control Message Group"}, 
	{2,		"End-to-End Message Group"}, 
	{4,		"Link-by-Link Message Group"},
	{0,	NULL }
};

static const value_string dpnss_cc_msg_type_vals[] = {
	{DPNSS_CC_MSG_ISRM_C,		"INITIAL SERVICE REQUEST Message (COMPLETE) - ISRM (C)"}, 
	{DPNSS_CC_MSG_ISRM_I,		"INITIAL SERVICE REQUEST Message (INCOMPLETE) - ISRM(I)"}, 
	{DPNSS_CC_MSG_RM_C,			"RECALL Message (COMPLETE) - RM(C)"},
	{DPNSS_CC_MSG_RM_I,			"RECALL Message (INCOMPLETE) - RM(I)"},
	{DPNSS_CC_MSG_CCM,			"CALL CONNECTED Message - CCM"},
	{DPNSS_CC_MSG_NIM,			"NETWORK INDICATION Message - NIM"},
	{DPNSS_CC_MSG_CRM,			"CLEAR REQUEST Message - CRM/CLEAR INDICATION Message - CIM"}, /* Humm chek 2.1.7/2.1.8 - depends on dir? */
	{DPNSS_CC_MSG_NAM,			"NUMBER ACKNOWLEDGE Message - NAM"},
	{DPNSS_CC_MSG_RRM,			"RECALL REJECTION Message - RRM"},
	{DPNSS_CC_MSG_SSRM_I,		"SUBSEQUENT SERVICE REQUEST Message (INCOMPLETE) - SSRM(I)"},
	{DPNSS_CC_MSG_SSRM_C,		"SUBSEQUENT SERVICE REQUEST Message (COMPLETE) - SSRM(C)"},
	{ 0,	NULL }
};


static const value_string dpnss_cc_msg_short_type_vals[] = {
	{DPNSS_CC_MSG_ISRM_C,		"ISRM (C)"}, 
	{DPNSS_CC_MSG_ISRM_I,		"ISRM(I)"}, 
	{DPNSS_CC_MSG_RM_C,			"RM(C)"},
	{DPNSS_CC_MSG_RM_I,			"RM(I)"},
	{DPNSS_CC_MSG_CCM,			"CCM"},
	{DPNSS_CC_MSG_NIM,			"NIM"},
	{DPNSS_CC_MSG_CRM,			"CRM/CIM"}, /* Humm chek 2.1.7/2.1.8 - depends on dir? */
	{DPNSS_CC_MSG_NAM,			"NAM"},
	{DPNSS_CC_MSG_RRM,			"RRM"},
	{DPNSS_CC_MSG_SSRM_I,		"SSRM(I)"},
	{DPNSS_CC_MSG_SSRM_C,		"SSRM(C)"},
	{0,	NULL }
};

/* 2.2 END-TO-END MESSAGE GROUP */
static const value_string dpnss_e2e_msg_type_vals[] = {
	{2,		"END-to-END Message (COMPLETE) - EEM(C)"},
	{3,		"END-to-END Message (INCOMPLETE) - EEM(I)"},
	{4,		"SINGLE-CHANNEL CLEAR REQUEST Message - SCRM"},
	{5,		"SINGLE-CHANNEL CLEAR INDICATION Message - SCIM"},
	{6,		"END-to-END RECALL Message (COMPLETE) - ERM(C)"},
	{7,		"END-to-END RECALL Message (INCOMPLETE) - ERM(I)"},
	{8,		"NON SPECIFIED INFORMATION Message - NSIM"}, 
	{ 0,	NULL }
};

static const value_string dpnss_e2e_msg_short_type_vals[] = {
	{2,		"EEM(C)"},
	{3,		"EEM(I)"},
	{4,		"SCRM"},
	{5,		"SCIM"},
	{6,		"ERM(C)"},
	{7,		"ERM(I)"},
	{8,		"NSIM"}, 
	{ 0,	NULL }
};

/* 2.3 LINK-BY-LINK MESSAGE GROUP */
static const value_string dpnss_LbL_msg_type_vals[] = {
	{0,		"LINK-by-LINK Message (COMPLETE) - LLM(C)"}, 
	{1,		"LINK-by-LINK Message (INCOMPLETE) - LLM(I)"}, 
	{2,		"LINK-by-LINK REJECT Message - LLRM"},
	{4,		"SWAP Message - SM"},
	{5,		"LINK MAINTENANCE Message - LMM"},
	{6,		"LINK MAINTENANCE REJECT Message - LMRM"},
	{ 0,	NULL }
};

static const value_string dpnss_LbL_msg_short_type_vals[] = {
	{0,		"LLM(C)"}, 
	{1,		"LLM(I)"}, 
	{2,		"LLRM"},
	{4,		"SM"},
	{5,		"LMM"},
	{6,		"LMRM"},
	{ 0,	NULL }
};

static const true_false_string dpnss_ext_bit_vals = {
  "further octet(s) follow",
  "no further octets"
};

static const true_false_string dpnss_ext_bit_no_ext_vals = {
  "no further octets",
  "Invalid"
};
/* SECTION 4 ANNEX 1 */
static const value_string dpnss_sic_type_type_vals[] = {
	{0,		"invalid"}, 
	{1,		"speech"}, 
	{2,		"data"},
	{3,		"data"},
	{4,		"interworking with DASS 2 - treat as data"},
	{5,		"interworking with DASS 2 - treat as data"},
	{6,		"interworking with DASS 2 - treat as data"},
	{7,		"interworking with DASS 2 - treat as data"},
	{ 0,	NULL }
};

static const value_string dpnss_sic_details_for_speech_vals[] = {
	{0,		"64 kbit/s PCM G.711 A-Law or analogue"}, 
	{1,		"32 kbit/s ADPCM G.721"}, 
	{2,		"64 kbit/s PCM G.711 u-Law or analogue"},
	{3,		"Invalid"},
	{4,		"Invalid"},
	{5,		"Invalid"},
	{6,		"Invalid"},
	{7,		"Invalid"},
	{8,		"Invalid"},
	{9,		"Invalid"},
	{10,	"Invalid"},
	{11,	"Invalid"},
	{12,	"Invalid"},
	{13,	"Invalid"},
	{14,	"Invalid"},
	{15,	"Invalid"},
	{ 0,	NULL }
};

static const value_string dpnss_sic_details_for_data_rates1_vals[] = {
	{0,		"64000 bit/s"}, 
	{1,		"56000 bit/s"}, 
	{2,		"48000 bit/s"},
	{3,		"32000 bit/s"},
	{4,		"19200 bit/s"},
	{5,		"16000 bit/s"},
	{6,		"14400 bit/s"},
	{7,		"12000 bit/s"},
	{8,		"9600 bit/s"},
	{9,		"8000 bit/s"},
	{10,	"7200 bit/s"},
	{11,	"4800 bit/s"},
	{12,	"3600 bit/s"},
	{13,	"2400 bit/s"},
	{14,	"1200 bit/s"},
	{15,	"600 bit/s"},
	{ 0,	NULL }
};

static const value_string dpnss_sic_details_for_data_rates2_vals[] = {
	{0,		"300 bit/s"}, 
	{1,		"200 bit/s"}, 
	{2,		"150 bit/s"},
	{3,		"134.5 bit/s"},
	{4,		"110 bit/s"},
	{5,		"100 bit/s"},
	{6,		"75 bit/s"},
	{7,		"50 bit/s"},
	{8,		"75/1200 bit/s"},
	{9,		"1200/75 bit/s"},
	{10,	"invalid"},
	{11,	"invalid"},
	{12,	"invalid"},
	{13,	"invalid"},
	{14,	"invalid"},
	{15,	"invalid"},
	{ 0,	NULL }
};
/* Octet 2 */

static const value_string dpnss_sic_oct2_data_type_vals[] = {
	{0,		"Invalid"},
	{1,		"Invalid"},
	{2,		"Invalid"},
	{3,		"Synchronous"},
	{4,		"Synchronous"},
	{5,		"Asynchronous"},
	{6,		"Asynchronous"},
	{7,		"Asynchronous"},
	{ 0,	NULL }
};

static const true_false_string dpnss_duplex_vals = {
  "Half Duplex (HDX)",
  "Full Duplex (FDX)"
};

static const true_false_string dpnss_sic_oct2_sync_data_format_vals = {
  "X.25 Packet Mode",
  "Anonymous or Unformatted"
};

static const true_false_string dpnss_sic_oct2_net_ind_clk_vals = {
  "Bits E4/E5/E6 indicate phase",
  "Clock Locked to Transmission"
};

static const true_false_string dpnss_provided_vals = {
  "Provided",
  "Not Provided"
};

static const value_string dpnss_sic_oct2_async_data_type_vals[] = {
	{0,		"Unspecified"},
	{1,		"5 data bits"},
	{2,		"7 data bits"},
	{3,		"8 data bits"},
	{ 0,	NULL }
};
static const true_false_string dpnss_flow_control_vals = {
  "TA has ESRA capability",
  "TA does not have ESRA capability"
};

/* SECTION 4 Global Issue 7 
 * ANNEX 3 CLEARING/REJECTION CAUSE CODES 
 */
static const value_string dpnss_clearing_cause_code_vals[] = {
	{0x29,		"Access Barred"},
	{0x14,		"Acknowledgement"},
	{0x01,		"Address Incomplete"},
	{0x08,		"Busy"},
	{0x23,		"Channel Out of Service"},
	{0x2d,		"DTE Controlled Not Ready"},
	{0x07,		"Congestion"},
	{0x30,		"Call Termination"},
	{0x18,		"Facility Not Registered"},
	{0x0a,		"Incoming Calls Barred"},
	{0x13,		"Service Incompatible"},
	{0x1a,		"Message Not Understood"},
	{0x1e,		"Network Address Extension-Error"},
	{0x02,		"Network Termination"},
	{0x00,		"Number Unobtainable"},
	{0x24,		"Priority Forced Release"},
	{0x19,		"Reject"},
	{0x1c,		"Route Out of Service"},
	{0x04,		"Subscriber Incompatible"},
	{0x15,		"Signal Not Understood"},
	{0x16,		"Signal Not Valid"},
	{0x09,		"Subscriber Out of Service"},
	{0x1b,		"Signalling System Incompatible"},
	{0x17,		"Service Temporarily Unavailable"},
	{0x03,		"Service Unavailable"},
	{0x1d,		"Transferred"},
	{0x2e,		"DTE Uncontrolled Not Ready"},
	{ 0,	NULL }
};
static int
dissect_dpnss_sic(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset)
{
	guint8 octet, type_of_data;

		octet = tvb_get_guint8(tvb,offset);
		type_of_data = (octet & 0x70)>>4;
		proto_tree_add_item(tree, hf_dpnss_ext_bit, tvb, offset, 1, FALSE);
		proto_tree_add_item(tree, hf_dpnss_sic_type, tvb, offset, 1, FALSE);
		switch(type_of_data){
		case 1:
			/* Type of Data (001) : Details for Speech */ 
			proto_tree_add_item(tree, hf_dpnss_sic_details_for_speech, tvb, offset, 1, FALSE);
			break;
		case 2:
			/* Type of Data (010) : Data Rates */
			proto_tree_add_item(tree, hf_dpnss_sic_details_for_data1, tvb, offset, 1, FALSE);
			break;
		case 3:
			/* Type of Data (011) : Data Rates */
			proto_tree_add_item(tree, hf_dpnss_sic_details_for_data2, tvb, offset, 1, FALSE);
			break;
		default:
			/* Illegal */
			break;
		}
		offset++;
		if((octet&0x80)==0x80){
			/* Extension bit set 
			 * Synch/Asynchronous Information
			 */
			octet = tvb_get_guint8(tvb,offset);
			type_of_data = octet&0x3;
			proto_tree_add_item(tree, hf_dpnss_ext_bit_notall, tvb, offset, 1, FALSE);
			switch(type_of_data){
			case 3:
				/* Synchronous */
			case 4:
				/* Synchronous */
				proto_tree_add_item(tree, hf_dpnss_sic_oct2_net_ind_clk, tvb, offset, 1, FALSE);
				proto_tree_add_item(tree, hf_dpnss_sic_oct2_sync_data_format, tvb, offset, 1, FALSE);
				proto_tree_add_item(tree, hf_dpnss_sic_oct2_sync_byte_timing, tvb, offset, 1, FALSE);
				break;
			case 5:
				/* Asynchronous */
			case 6:
				/* Asynchronous */
			case 7:
				/* Asynchronous */
				proto_tree_add_item(tree, hf_dpnss_sic_oct2_async_flow_ctrl, tvb, offset, 1, FALSE);
				proto_tree_add_item(tree, hf_dpnss_sic_oct2_async_data, tvb, offset, 1, FALSE);
				break;
			default:
				break;
			}
			proto_tree_add_item(tree, hf_dpnss_sic_oct2_duplex, tvb, offset, 1, FALSE);
			proto_tree_add_item(tree, hf_dpnss_sic_oct2_data_type, tvb, offset, 1, FALSE);
			offset++;
		}
		return offset;
}

/* 3.1 Supplementary Information Strings 
 * A Supplementary Information String comprises a Supplementary
 * Information Identifier which may be followed by one or more
 * Parameters. A Supplementary Information String starts with the
 * IA5 character * and ends with the IA5 character #. 
 * 
 *  When the Supplementary Information String includes Parameters
 * these are separated from the identifier and each other by a *.
 * eg * Supplementary Information Identifier code #
 * or * Supplementary Information Identifier code * Parameter #
 * or * Supplementary Information Identifier code * Parameter * Parameter #
 * A Supplementary Information String shall be wholly contained
 * within one Selection or Indication Field (ie it shall not be
 * split between messages).
 *
 * 3.2 Supplementary Information String Identifier
 * The identifier comprises one or more IA5 numerals 0-9 which may
 * be followed by a single IA5 alpha-character suffix in the range A-Z.
 * The numerals of the identifier indicate the main function of the
 * Supplementary Information String, eg "39F" indicates "Diverting
 * on No Reply". "F" is the suffix.
 * 
 * 3.5 Destination Address
 * The Destination Address comprises one or more IA5 numerals 0 to
 * 9, has no identifier code and is not prefixed by a * or
 * terminated by a #. The digits are always the last characters in
 * the Selection Block. The first Destination Address digit
 * immediately follows the # of the last Supplementary Information
 * String.
 */
static int
dissect_dpnss_sup_info_str(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset)
{
	gint		start_offset, hash_offset, tvb_end_offset;
	guint8		octet;
	gboolean	last_string = FALSE;

	tvb_end_offset = tvb_length(tvb);

	while((offset<tvb_end_offset)&&(last_string == FALSE)){
		octet = tvb_get_guint8(tvb,offset);
		if (octet == '*'){
			/* Supplementary Information String */
			start_offset = offset;
			hash_offset = tvb_find_guint8(tvb, offset, -1, '#');
			proto_tree_add_text(tree, tvb, offset, hash_offset-offset, "Supplementary Information: %s",tvb_format_text(tvb,offset,hash_offset-offset));

			offset = hash_offset+1;
		}else{
			last_string = TRUE;
			proto_tree_add_item(tree, hf_dpnss_dest_addr, tvb, offset, -1, FALSE);
		}
	}
	return offset;
}


static void
dissect_dpnss_LbL_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint8 octet;

	proto_tree_add_item(tree, hf_dpnss_LbL_msg_type, tvb, offset, 1, FALSE);
	octet = tvb_get_guint8(tvb,offset)&0x0f;
	offset++;
	if(check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(octet, dpnss_LbL_msg_short_type_vals, "Unknown (%d)" ));
	switch (octet){
	default:
		proto_tree_add_text(tree, tvb, offset, 1, "Dissection of this message not supported yet");
		break;
	}
}


static void
dissect_dpnss_e2e_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint8 octet;

	proto_tree_add_item(tree, hf_dpnss_e2e_msg_type, tvb, offset, 1, FALSE);
	octet = tvb_get_guint8(tvb,offset)&0x0f;
	offset++;
	if(check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(octet, dpnss_e2e_msg_short_type_vals, "Unknown (%d)" ));
	switch (octet){
	default:
		proto_tree_add_text(tree, tvb, offset, 1, "Dissection of this message not supported yet");
		break;
	}
}

static void
dissect_dpnss_cc_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *sel_field_item, *sic_field_item, *ind_field_item;
	proto_tree *sel_field_tree, *sic_field_tree, *ind_field_tree;
	int offset = 0;
	int tvb_end_offset;
	guint8 octet;	

	tvb_end_offset = tvb_length(tvb);
	proto_tree_add_item(tree, hf_dpnss_cc_msg_type, tvb, offset, 1, FALSE);
	octet = tvb_get_guint8(tvb,offset)&0x0f;
	offset++;
	if(check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(octet, dpnss_cc_msg_short_type_vals, "Unknown (%d)" ));

	if(tree){
		switch (octet){
		case DPNSS_CC_MSG_ISRM_C:
			/* 2.1.1 INITIAL SERVICE REQUEST Message (COMPLETE) - ISRM (C) */
			/* fall trough */
		case DPNSS_CC_MSG_ISRM_I:
			/* 2.1.2 INITIAL SERVICE REQUEST Message (INCOMPLETE) - ISRM(I) */
		case DPNSS_CC_MSG_RM_C:
			/* 2.1.3 RECALL Message (COMPLETE) - RM(C) */
			/* fall trough */
		case DPNSS_CC_MSG_RM_I:
			/* 2.1.4 RECALL Message (INCOMPLETE) - RM(I)*/
			/* fall trough */

			
			/* Service Indicator Code
			 * Note: On data calls the SIC may comprise more than one octet.
			 * The Service Indicator Code is coded in accordance with ANNEX 1.
			 */
			sic_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Service Indicator Code");
			sic_field_tree = proto_item_add_subtree(sic_field_item, ett_dpnss_sic_field);
			offset =dissect_dpnss_sic(tvb, pinfo, sic_field_tree, offset);
			/*
			 * Selection Field
			 * The Selection Field contains the selection information relating
			 * to a call set-up or Supplementary Service Request, and is
			 * structured as shown in Subsection 3.
			 */
			sel_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Selection Field: %s",tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
			sel_field_tree = proto_item_add_subtree(sel_field_item, ett_dpnss_sel_field);
			offset = dissect_dpnss_sup_info_str(tvb, pinfo, sel_field_tree, offset);
			break;
		case DPNSS_CC_MSG_CCM:
			/* 2.1.5 CALL CONNECTED Message - CCM */
			if(tvb_end_offset>offset){
				/* Indication Field (Optional) */
				ind_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Indication Field: %s",tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
				ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
				offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
			}
			break;
		case DPNSS_CC_MSG_NIM:
			/* 2.1.6 NETWORK INDICATION Message - NIM */
			/* fall trough */
		case DPNSS_CC_MSG_NAM:
			/* 2.1.9 NUMBER ACKNOWLEDGE Message - NAM */
				/* Indication Field */
			ind_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Indication Field: %s",tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
			ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
			offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
			break;
		case DPNSS_CC_MSG_CRM:
			/* 2.1.7 CLEAR REQUEST Message - CRM */
			/* 2.1.8 CLEAR INDICATION Message - CIM */
			/* Clearing Cause */
			proto_tree_add_item(tree, hf_dpnss_clearing_cause, tvb, offset, 1, FALSE);
			offset++;
			/* Indication Field (Optional) */
			if(tvb_end_offset>offset){
				ind_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Indication Field: %s",tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
				ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
				offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
			}
			break;
		case DPNSS_CC_MSG_RRM:
			/* 2.1.10 RECALL REJECTION Message - RRM */
			/* Rejection Cause */
			proto_tree_add_item(tree, hf_dpnss_rejection_cause, tvb, offset, 1, FALSE);
			/* Indication Field (Optional) */
			if(tvb_end_offset>offset){
				ind_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Indication Field: %s",tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
				ind_field_tree = proto_item_add_subtree(ind_field_item, ett_dpnss_ind_field);
				offset = dissect_dpnss_sup_info_str(tvb, pinfo, ind_field_tree, offset);
			}
			break;
		case DPNSS_CC_MSG_SSRM_I:
			/* 2.1.11 SUBSEQUENT SERVICE REQUEST Message (INCOMPLETE) - SSRM(I) */
			sel_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Selection Field: %s",tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
			sel_field_tree = proto_item_add_subtree(sel_field_item, ett_dpnss_sel_field);
			/* Selection Field */
			offset = dissect_dpnss_sup_info_str(tvb, pinfo, sel_field_tree, offset);
			break;
		case DPNSS_CC_MSG_SSRM_C:
			/* 2.1.12 SUBSEQUENT SERVICE REQUEST Message (COMPLETE) - SSRM(C) */
			/* Selection Field (Optional) */
			if(tvb_end_offset>offset){
				sel_field_item = proto_tree_add_text(tree, tvb, offset, -1, "Selection Field: %s",tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
				sel_field_tree = proto_item_add_subtree(sel_field_item, ett_dpnss_sel_field);
				offset = dissect_dpnss_sup_info_str(tvb, pinfo, sel_field_tree, offset);
			}
			break;
		default:
			proto_tree_add_text(tree, tvb, offset, 1, "Unknown or Dissection of this message not supported yet");
			break;
		}
	}
}
/* Code to actually dissect the packets */
static void
dissect_dpnss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_item *item;
	proto_tree *dpnss_tree;
	guint8 octet;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPNSS/DASS2");

	item = proto_tree_add_item(tree, proto_dpnss, tvb, 0, -1, FALSE);
	dpnss_tree = proto_item_add_subtree(item, ett_dpnss);
	proto_tree_add_item(dpnss_tree, hf_dpnss_msg_grp_id, tvb, offset, 1, FALSE);
	octet = tvb_get_guint8(tvb,offset)>>4;
	switch (octet){
	case DPNNS_MESSAGE_GROUP_CC:
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "CC MSG ");
		/* Call Control Message Group */
		dissect_dpnss_cc_msg(tvb, pinfo, dpnss_tree);
		break;
	case DPNNS_MESSAGE_GROUP_E2E:
		/* End-to-End Message Group */
		dissect_dpnss_e2e_msg(tvb, pinfo, dpnss_tree);
		break;
	case DPNNS_MESSAGE_GROUP_LbL:
		/* Link-by-Link Message Group */
		dissect_dpnss_LbL_msg(tvb, pinfo, dpnss_tree);
		break;
	default:
		proto_tree_add_text(tree, tvb, offset, 1, "Unknown Message Group");
		break;
	}
}


/* Register the protocol with Wireshark */
/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_dpnss(void)
{
	dissector_handle_t dpnss_handle;
	
	dpnss_handle = create_dissector_handle(dissect_dpnss, proto_dpnss);
}

void
proto_register_dpnss(void)
{                 


/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_dpnss_msg_grp_id,
			{ "Message Group Identifier",           "dpnss.msg_grp_id",
			FT_UINT8, BASE_DEC, VALS(dpnss_msg_grp_id_vals), 0xf0,          
			"Message Group Identifier", HFILL }
		},
		{ &hf_dpnss_cc_msg_type,
			{ "Call Control Message Type",           "dpnss.cc_msg_type",
			FT_UINT8, BASE_DEC, VALS(dpnss_cc_msg_type_vals), 0x0f,          
			"Call Control Message Type", HFILL }
		},
		{ &hf_dpnss_e2e_msg_type,
			{ "END-TO-END Message Type",           "dpnss.e2e_msg_type",
			FT_UINT8, BASE_DEC, VALS(dpnss_e2e_msg_type_vals), 0x0f,          
			"END-TO-END Message Type", HFILL }
		},
		{ &hf_dpnss_LbL_msg_type,
			{ "LINK-BY-LINK Message Type",           "dpnss.lbl_msg_type",
			FT_UINT8, BASE_DEC, VALS(dpnss_LbL_msg_type_vals), 0x0f,          
			"LINK-BY-LINK Message Type", HFILL }
		},
		{ &hf_dpnss_ext_bit,
			{ "Extension bit",           "dpnss.ext_bit",
			FT_BOOLEAN, 8, TFS(&dpnss_ext_bit_vals), 0x80,          
			"Extension bit", HFILL }
		},
		{ &hf_dpnss_ext_bit_notall,
			{ "Extension bit",           "dpnss.ext_bit_notall",
			FT_BOOLEAN, 8, TFS(&dpnss_ext_bit_no_ext_vals), 0x80,          
			"Extension bit", HFILL }
		},
		{ &hf_dpnss_sic_type,
			{ "Type of data",           "dpnss.sic_type",
			FT_UINT8, BASE_DEC, VALS(dpnss_sic_type_type_vals), 0x70,          
			"Type of data", HFILL }
		},
		{ &hf_dpnss_sic_details_for_speech,
			{ "Details for Speech",           "dpnss.sic_details_for_speech",
			FT_UINT8, BASE_DEC, VALS(dpnss_sic_details_for_speech_vals), 0x0f,          
			"Details for Speech", HFILL }
		},
		{ &hf_dpnss_sic_details_for_data1,
			{ "Data Rates",           "dpnss.sic_details_for_data1",
			FT_UINT8, BASE_DEC, VALS(dpnss_sic_details_for_data_rates1_vals), 0x0f,          
			"Type of Data (010) : Data Rates", HFILL }
		},
		{ &hf_dpnss_sic_details_for_data2,
			{ "Data Rates",           "dpnss.sic_details_data2",
			FT_UINT8, BASE_DEC, VALS(dpnss_sic_details_for_data_rates2_vals), 0x0f,          
			"Type of Data (011) : Data Rates", HFILL }
		},
		{ &hf_dpnss_dest_addr,
			{ "Destination Address",           "dpnss.dest_addr",
			FT_STRING, BASE_NONE, NULL, 0x0,          
			"Destination Address", HFILL }
		},
		{ &hf_dpnss_sic_oct2_data_type,
			{ "Data Type",           "dpnss.sic_oct2_data_type",
			FT_UINT8, BASE_DEC, VALS(dpnss_sic_oct2_data_type_vals), 0x03,          
			"Data Type", HFILL }
		},
		{ &hf_dpnss_sic_oct2_duplex,
			{ "Data Type",           "dpnss.sic_oct2_duplex",
			FT_BOOLEAN, 8, TFS(&dpnss_duplex_vals), 0x08,          
			"Data Type", HFILL }
		},
		{ &hf_dpnss_sic_oct2_net_ind_clk,
			{ "Network Independent Clock",           "dpnss.sic_oct2_sync_data_format",
			FT_BOOLEAN, 8, TFS(&dpnss_sic_oct2_net_ind_clk_vals), 0x40,          
			"Network Independent Clock", HFILL }
		},
		{ &hf_dpnss_sic_oct2_sync_data_format,
			{ "Data Format",           "dpnss.sic_oct2_sync_data_format",
			FT_BOOLEAN, 8, TFS(&dpnss_sic_oct2_sync_data_format_vals), 0x20,          
			"Data Format", HFILL }
		},
		{ &hf_dpnss_sic_oct2_sync_byte_timing,
			{ "Byte Timing",           "dpnss.sic_oct2_sync_byte_timing",
			FT_BOOLEAN, 8, TFS(&dpnss_provided_vals), 0x10,          
			"Byte Timing", HFILL }
		},
		{ &hf_dpnss_sic_oct2_async_data,
			{ "Data Format",           "dpnss.sic_oct2_async_data",
			FT_UINT8, BASE_DEC, VALS(dpnss_sic_oct2_async_data_type_vals), 0x30,          
			"Data Format", HFILL }
		},
		{ &hf_dpnss_sic_oct2_async_flow_ctrl,
			{ "Flow Control",           "dpnss.sic_oct2_async_flow_ctrl",
			FT_BOOLEAN, 8, TFS(&dpnss_flow_control_vals), 0x40,          
			"Flow Control", HFILL }
		},
		{ &hf_dpnss_clearing_cause,
			{ "Clearing Cause",           "dpnss.clearing_cause",
			FT_UINT8, BASE_DEC, VALS(dpnss_clearing_cause_code_vals), 0x0,          
			"Clearing Cause", HFILL }
		},
		{ &hf_dpnss_rejection_cause,
			{ "Rejection Cause",           "dpnss.rejection_cause",
			FT_UINT8, BASE_DEC, VALS(dpnss_clearing_cause_code_vals), 0x0,          
			"Rejection Cause", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_dpnss,
		&ett_dpnss_sel_field,
		&ett_dpnss_sic_field,
		&ett_dpnss_ind_field,
	};

/* Register the protocol name and description */
	proto_dpnss = proto_register_protocol("Digital Private Signalling System No 1","DPNSS", "dpnss");
	register_dissector("dpnss", dissect_dpnss, proto_dpnss);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_dpnss, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}
