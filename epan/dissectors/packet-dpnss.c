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
static int proto_dpnss		= -1;
static int hf_dpnss_msg_grp_id			= -1;
static int hf_dpnss_cc_msg_type			= -1;
static int hf_dpnss_e2e_msg_type		= -1;
static int hf_dpnss_LbL_msg_type		= -1;
static int hf_dpnss_ext_bit				= -1;
static int hf_dpnss_sic_type			= -1;
static int hf_dpnss_sic_details_for_speech = -1;
static int hf_dpnss_sic_details_for_data1 = -1;
static int hf_dpnss_sic_details_for_data2 = -1;

#define DPNNS_MESSAGE_GROUP_CC			0
#define DPNNS_MESSAGE_GROUP_E2E			2
#define DPNNS_MESSAGE_GROUP_LbL			4

#define DPNSS_CC_MDG_ISRMC				0
/* Initialize the subtree pointers */
static int ett_dpnss = -1;

static const value_string dpnss_msg_grp_id_vals[] = {
	{0,		"Call Control Message Group"}, 
	{2,		"End-to-End Message Group"}, 
	{4,		"Link-by-Link Message Group"},
	{0,	NULL }
};

static const value_string dpnss_cc_msg_type_vals[] = {
	{0,		"INITIAL SERVICE REQUEST Message (COMPLETE) - ISRM (C)"}, 
	{1,		"INITIAL SERVICE REQUEST Message (INCOMPLETE) - ISRM(I)"}, 
	{2,		"RECALL Message (COMPLETE) - RM(C)"},
	{3,		"RECALL Message (INCOMPLETE) - RM(I)"},
	{5,		"CALL CONNECTED Message - CCM"},
	{6,		"NETWORK INDICATION Message - NIM"},
	{8,		"CLEAR REQUEST Message - CRM/CLEAR INDICATION Message - CIM"}, /* Humm chek 2.1.7/2.1.8 - depends on dir? */
	{9,		"NUMBER ACKNOWLEDGE Message - NAM"},
	{10,	"RECALL REJECTION Message - RRM"},
	{11,	"SUBSEQUENT SERVICE REQUEST Message (INCOMPLETE) - SSRM(I)"},
	{12,	"SUBSEQUENT SERVICE REQUEST Message (COMPLETE) - SSRM(C)"},
	{ 0,	NULL }
};


static const value_string dpnss_cc_msg_short_type_vals[] = {
	{0,		"ISRM (C)"}, 
	{1,		"ISRM(I)"}, 
	{2,		"RM(C)"},
	{3,		"RM(I)"},
	{5,		"CCM"},
	{6,		"NIM"},
	{8,		"CRM/CIM"}, /* Humm chek 2.1.7/2.1.8 - depends on dir? */
	{9,		"NAM"},
	{10,	"RRM"},
	{11,	"SSRM(I)"},
	{12,	"SSRM(C)"},
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

static const value_string dpnss_sic_sic_details_for_speech_vals[] = {
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

static const value_string dpnss_sic_sic_details_for_data_rates1_vals[] = {
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

static const value_string dpnss_sic_sic_details_for_data_rates2_vals[] = {
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

/* A suplemetarry string 
 *
 */
static int
dissect_dpnss_sup_info_str(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, gint offset)
{
	guint hash_offset;

	hash_offset = tvb_find_guint8(tvb, offset, -1, '#');

	return offset;
}

static int
dissect_dpnss_LbL_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint8 octet;

	proto_tree_add_item(tree, hf_dpnss_LbL_msg_type, tvb, offset, 1, FALSE);
	octet = tvb_get_guint8(tvb,offset)&0x0f;
	offset++;
	if(check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(octet, dpnss_LbL_msg_short_type_vals, "Unknown (%d)" ));
	switch (octet){
	default:
		proto_tree_add_text(tree, tvb, offset, 1, "Dissection of this message not supported yet");
		break;
	}

	return offset;

}


static int
dissect_dpnss_e2e_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint8 octet;

	proto_tree_add_item(tree, hf_dpnss_e2e_msg_type, tvb, offset, 1, FALSE);
	octet = tvb_get_guint8(tvb,offset)&0x0f;
	offset++;
	if(check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(octet, dpnss_e2e_msg_short_type_vals, "Unknown (%d)" ));
	switch (octet){
	default:
		proto_tree_add_text(tree, tvb, offset, 1, "Dissection of this message not supported yet");
		break;
	}

	return offset;

}

static int
dissect_dpnss_cc_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	guint8 octet;	
	guint8 type_of_data;

	proto_tree_add_item(tree, hf_dpnss_cc_msg_type, tvb, offset, 1, FALSE);
	octet = tvb_get_guint8(tvb,offset)&0x0f;
	offset++;
	if(check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ",
			val_to_str(octet, dpnss_cc_msg_short_type_vals, "Unknown (%d)" ));

	switch (octet){
	case DPNSS_CC_MDG_ISRMC:
		/* 2.1.1 INITIAL SERVICE REQUEST Message (COMPLETE) - ISRM (C) */
		/* Service Indicator Code
		 * Note: On data calls the SIC may comprise more than one octet.
		 * The Service Indicator Code is coded in accordance with ANNEX 1.
		 */
		/* Routing Information */
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

			/* TODO add decoding here */
			offset++;
		}
		
		/*
		 * Selection Field
		 * 2 + n structured as shown in Subsection 3.
		 */
		proto_tree_add_text(tree, tvb, offset, -1, "Selection Field: %s",tvb_format_text(tvb,offset,tvb_length_remaining(tvb, offset)));
		offset = dissect_dpnss_sup_info_str(tvb, pinfo, tree, offset);
		break;
	default:
		proto_tree_add_text(tree, tvb, offset, 1, "Dissection of this message not supported yet");
		break;
	}

	return offset;

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

	if (tree) {
		item = proto_tree_add_item(tree, proto_dpnss, tvb, 0, -1, FALSE);
		dpnss_tree = proto_item_add_subtree(item, ett_dpnss);
		proto_tree_add_item(dpnss_tree, hf_dpnss_msg_grp_id, tvb, offset, 1, FALSE);
		octet = tvb_get_guint8(tvb,offset)>>4;
		switch (octet){
		case DPNNS_MESSAGE_GROUP_CC:
			/* Call Control Message Group */
			offset = dissect_dpnss_cc_msg(tvb, pinfo, dpnss_tree);
			break;
		case DPNNS_MESSAGE_GROUP_E2E:
			/* End-to-End Message Group */
			offset = dissect_dpnss_e2e_msg(tvb, pinfo, dpnss_tree);
			break;
		case DPNNS_MESSAGE_GROUP_LbL:
			/* Link-by-Link Message Group */
			offset = dissect_dpnss_LbL_msg(tvb, pinfo, dpnss_tree);
			break;
		default:
			proto_tree_add_text(tree, tvb, offset, 1, "Unknown Message Group");
			break;
		}
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
/** 	static int dpnss_prefs_initialized = FALSE; **/
	
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
		{ &hf_dpnss_sic_type,
			{ "Type of data",           "dpnss.sic_type",
			FT_UINT8, BASE_DEC, VALS(dpnss_sic_type_type_vals), 0x70,          
			"Type of data", HFILL }
		},
		{ &hf_dpnss_sic_details_for_speech,
			{ "Details for Speech",           "dpnss.sic_details_for_speech",
			FT_UINT8, BASE_DEC, VALS(dpnss_sic_sic_details_for_speech_vals), 0x0f,          
			"Details for Speech", HFILL }
		},
		{ &hf_dpnss_sic_details_for_data1,
			{ "Data Rates",           "dpnss.sic_details_for_data1",
			FT_UINT8, BASE_DEC, VALS(dpnss_sic_sic_details_for_data_rates1_vals), 0x0f,          
			"Type of Data (010) : Data Rates", HFILL }
		},
		{ &hf_dpnss_sic_details_for_data2,
			{ "Data Rates",           "dpnss.sic_details_data2",
			FT_UINT8, BASE_DEC, VALS(dpnss_sic_sic_details_for_data_rates2_vals), 0x0f,          
			"Type of Data (011) : Data Rates", HFILL }
		},

	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_dpnss,
	};

/* Register the protocol name and description */
	proto_dpnss = proto_register_protocol("Digital Private Signalling System No 1","DPNSS", "dpnss");
	register_dissector("dpnss", dissect_dpnss, proto_dpnss);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_dpnss, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}
