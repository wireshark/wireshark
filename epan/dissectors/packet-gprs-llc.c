/* packet-llcgprs.c
 * Routines for Logical Link Control GPRS dissection ETSI 4.64
 * Copyright 2000, Josef Korelus <jkor@quick.cz>
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "prefs.h"
/*
#include "packet-llcgprs.h"
*/
#define I_FORMAT	1
#define S_FORMAT	2
#define UI_FORMAT	3
#define U_FORMAT	4
#define I_SACK		5
#define S_SACK		6
#define UI_MASK_FMT    0xe000
#define UI_MASK_SPB    0x1800
#define UI_MASK_NU     0x07fc
#define UI_MASK_E      0x0002
#define UI_MASK_PM     0x0001

/* Initialize the protocol and registered fields */
static int proto_llcgprs       = -1;
static int hf_llcgprs_pd       = -1;
static int hf_llcgprs_cr       = -1;
static int hf_llcgprs_sapi     = -1;
static int hf_llcgprs_sapib    = -1;
static int hf_llcgprs_U_fmt    = -1;/* 3 upper bits in controlfield (UI format) */
static int hf_llcgprs_sp_bits  = -1; /*Spare bits in control field*/
static int hf_llcgprs_NU       = -1; /*Transmited unconfirmed sequence number*/
static int hf_llcgprs_E_bit    = -1;/* Encryption mode bit*/
static int hf_llcgprs_PM_bit   = -1;
static int hf_llcgprs_Un       = -1;
static int hf_llcgprs_As      = -1;
static int hf_llcgprs_ucom     = -1;
static int hf_llcgprs_PF	= -1;
static int hf_llcgprs_S_fmt	= -1;
static int hf_llcgprs_NR	= -1;
static int hf_llcgprs_sjsd	= -1;
/*static int hf_llcgprs_pd       = -1;
*/
/* Initialize the subtree pointers */
static gint ett_llcgprs = -1;
static gint ett_llcgprs_adf = -1;
static gint ett_llcgprs_ctrlf = -1;
static gint ett_ui = -1;
static gint ett_llcgprs_sframe = -1;

static dissector_handle_t data_handle;

static gboolean ignore_cipher_bit = FALSE;

static dissector_table_t llcgprs_subdissector_table;
static const value_string sapi_t[] = {
	{  0, "Reserved"},
	{  1, "GPRS Mobility Management" },
	{  2, "Tunnelling of messages 2" },
	{  3, "User data 3"},
	{  4, "Reserved" },
	{  5, "User data 5" },
	{  6, "Reserved" },
	{  7, "SMS" },
	{  8, "Tunneling of messages 8" },
	{  9, "User data 9" },
	{ 10, "Reserved" },
	{ 11, "User data 11" },
	{ 12, "Reserved" },
	{ 13, "Reserved" },
	{ 14, "Reserved" },
	{ 15, "Reserved" },
	{  0, NULL },
};

static const value_string sapi_abrv[] = {
	{  0, "0"},
	{  1, "LLGMM" },
	{  2, "TOM2" },
	{  3, "LL3"},
	{  4, "4" },
	{  5, "LL5" },
	{  6, "6" },
	{  7, "LLSMS" },
	{  8, "TOM8" },
	{  9, "LL9" },
	{ 10, "10" },
	{ 11, "LL11" },
	{ 12, "12" },
	{ 13, "13" },
	{ 14, "14" },
	{ 15, "15" },
	{  0, NULL },
};
static const true_false_string a_bit = {
	"To solicit an acknowledgement from the peer LLE. ",
	"The peer LLE is not requested to send an acknowledgment."
};

static const true_false_string pd_bit = {
	"Invalid frame PD=1",
	"OK"
};
static const true_false_string e_bit = {
	" encrypted frame",
	" non encrypted frame"	
};
static const true_false_string pm_bit = {
	"FCS covers the frame header and information fields",
	"FCS covers only the frame header and first N202 octets of the information field"
};
static const true_false_string cr_bit = {
	"DownLink/UpLink = Command/Response",
	"DownLink/UpLink = Response/Command"
};
/* bits are swaped comparing with "Table 3" in ETSI document*/
static const value_string pme[] = {
	{ 0, "unprotected,non-ciphered information" },
	{ 1, "protected, non-ciphered information" },
	{ 2, "unprotected,ciphered information"},
	{ 3, "protected, ciphered information" },
	{ 0, NULL},
};

static const value_string cr_formats_unnumb[]= {
	{  0x1, "DM-response" },
	{  0x4, "DISC-command" },
	{  0x6, "UA-response" },
	{  0x7, "SABM" },
	{  0x8, "FRMR" },
	{ 0xb, "XID" },
	{ 0, NULL },
};
static const value_string cr_formats_ipluss[] = {
	{ 0x0,"RR" },
	{ 0x1,"ACK" },
	{ 0x2,"RNR" },
	{ 0x3,"SACK" },
	{ 0, NULL },
};
/* Code to actually dissect the packets */
static void
dissect_llcgprs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
 guint8 addr_fld=0, sapi=0, ctrl_fld_fb=0, frame_format, tmp=0 ;
 guint16 offset=0 , epm = 0, nu=0,ctrl_fld_ui_s=0,crc_start=0 ;
 proto_item *ti, *addres_field_item, *ctrl_field_item, *ui_ti;
 proto_tree *llcgprs_tree=NULL , *ad_f_tree =NULL, *ctrl_f_tree=NULL, *ui_tree=NULL;
 tvbuff_t *next_tvb;
/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "GPRS-LLC");
	
        crc_start = tvb_length(tvb)-3;
        addr_fld = tvb_get_guint8(tvb,offset);
	offset++;
	if (addr_fld > 128 ) {
		if (check_col(pinfo->cinfo,COL_INFO))
		       col_add_str(pinfo->cinfo,COL_INFO,"Invalid packet - Protocol Discriminator bit is set to 1");
		return;
	}
 	sapi = addr_fld & 0xF;
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_add_fstr(pinfo->cinfo, COL_INFO, "SAPI: %s", match_strval(sapi,sapi_abrv));
	
	  		  
        
/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {

		ti = proto_tree_add_protocol_format(tree, proto_llcgprs, tvb, 0, -1,"MS-SGSN LLC (Mobile Station - Serving GPRS Support Node Logical Link Control)  SAPI: %s", match_strval(sapi,sapi_t));

		llcgprs_tree = proto_item_add_subtree(ti, ett_llcgprs);

/* add an item to the subtree, see section 1.6 for more information */
		proto_tree_add_text( llcgprs_tree, tvb, crc_start,3, "CRC of LLC layer" );
		addres_field_item = proto_tree_add_uint_format(llcgprs_tree,hf_llcgprs_sapi,
		     tvb, 0,1, sapi, "Address field  SAPI: %s", match_strval(sapi,sapi_abrv));
		ad_f_tree = proto_item_add_subtree(addres_field_item, ett_llcgprs_adf);
                proto_tree_add_boolean(ad_f_tree, hf_llcgprs_pd, tvb,0,1, addr_fld );
                proto_tree_add_boolean(ad_f_tree, hf_llcgprs_cr, tvb,0,1, addr_fld );
                proto_tree_add_uint(ad_f_tree, hf_llcgprs_sapib, tvb, 0, 1, addr_fld );
	}	

	ctrl_fld_fb = tvb_get_guint8(tvb,offset);
	if ( ctrl_fld_fb < 0xc0 ){
		frame_format = ( ctrl_fld_fb < 0x80)? I_FORMAT : S_FORMAT;
	}
	else {
               frame_format = ( ctrl_fld_fb < 0xe0 )? UI_FORMAT : U_FORMAT;
	}	  
	switch (frame_format){
		case I_FORMAT:
			if (check_col(pinfo->cinfo,COL_INFO)){
				col_append_str(pinfo->cinfo,COL_INFO, ", I");
			}
				
			break;
		case S_FORMAT:
		case UI_FORMAT:
			nu = ctrl_fld_ui_s = tvb_get_ntohs(tvb, offset);
			offset +=2;
			epm = ctrl_fld_ui_s & 0x3;
			nu = (nu >>2)&0x01FF;
			if (frame_format == S_FORMAT){
			  if (check_col(pinfo->cinfo, COL_INFO)){
				col_append_str(pinfo->cinfo, COL_INFO, ", S, ");
				col_append_str(pinfo->cinfo, COL_INFO, match_strval(epm,cr_formats_ipluss));
				col_append_fstr(pinfo->cinfo, COL_INFO, ", N(R) = %u", nu);
			  }
			  if (tree){
				ctrl_field_item = proto_tree_add_text(llcgprs_tree, tvb, offset-2,2,"Supervisory format: %s: N(R) = %u",match_strval(epm,cr_formats_ipluss), nu);
				ctrl_f_tree = proto_item_add_subtree( ctrl_field_item, ett_llcgprs_sframe);
				proto_tree_add_uint( ctrl_f_tree, hf_llcgprs_S_fmt, tvb, offset-2,2, ctrl_fld_ui_s );
				proto_tree_add_boolean( ctrl_f_tree, hf_llcgprs_As, tvb, offset-2, 2, ctrl_fld_ui_s );
				proto_tree_add_uint(ctrl_f_tree, hf_llcgprs_NR, tvb, offset-2, 2, ctrl_fld_ui_s );
				proto_tree_add_uint(ctrl_f_tree, hf_llcgprs_sjsd, tvb, offset-2, 2, ctrl_fld_ui_s );
			  }
			}else{
/*UI format*/
			  if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_str(pinfo->cinfo, COL_INFO, ", UI, ");
				col_append_str(pinfo->cinfo, COL_INFO, match_strval(epm, pme ));
				col_append_fstr(pinfo->cinfo,COL_INFO, ", N(U) = %u", nu);
			  }
		          if (tree){	
				ctrl_field_item = proto_tree_add_text(llcgprs_tree, tvb, offset-2, 2, "Unnumbered Information format - UI, N(U) = %u", nu);
				ctrl_f_tree = proto_item_add_subtree(ctrl_field_item, ett_llcgprs_ctrlf);
				proto_tree_add_uint( ctrl_f_tree, hf_llcgprs_U_fmt, tvb, offset-2, 2, ctrl_fld_ui_s);
				proto_tree_add_uint( ctrl_f_tree, hf_llcgprs_sp_bits, tvb, offset-2,2,ctrl_fld_ui_s);
				proto_tree_add_uint( ctrl_f_tree, hf_llcgprs_NU, tvb, offset-2, 2, ctrl_fld_ui_s);
				proto_tree_add_boolean( ctrl_f_tree, hf_llcgprs_E_bit, tvb, offset-2,2,ctrl_fld_ui_s);
				proto_tree_add_boolean( ctrl_f_tree, hf_llcgprs_PM_bit, tvb, offset-2,2,ctrl_fld_ui_s);
		     	  }

 		   	  next_tvb = tvb_new_subset(tvb, offset,crc_start-3, -1 );
		   	  if (ignore_cipher_bit || !(epm & 0x2)){
			  	/*
			  	 * Either we're ignoring the cipher bit
			  	 * (because the bit is set but the
			  	 * data is unciphered), or the cipher
			  	 * bit isn't set (indicating that the
			  	 * data is unciphered).  Try dissecting
			  	 * it with a subdissector.
			  	 */
		   	    if  (!dissector_try_port(llcgprs_subdissector_table,sapi, next_tvb, pinfo, tree))
		   		call_dissector(data_handle, next_tvb, pinfo, tree);
			  }
		          else	call_dissector(data_handle, next_tvb, pinfo, tree);
			}
			break;
		case U_FORMAT:
		     offset +=1;
		     tmp = 0;
		     tmp =  ctrl_fld_fb & 0xf;
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_str(pinfo->cinfo, COL_INFO, ", U, ");
				col_append_str(pinfo->cinfo, COL_INFO, val_to_str(tmp, cr_formats_unnumb,"Unknown/invalid code:%X"));
			}
			if(tree){
				ui_ti = proto_tree_add_text(llcgprs_tree,tvb,offset-1,crc_start-1,"Unnumbered frame: %s",val_to_str(tmp,cr_formats_unnumb,"Unknown/invalid code:%X"));
				ui_tree = proto_item_add_subtree( ui_ti, ett_ui);
				proto_tree_add_uint( ui_tree, hf_llcgprs_Un, tvb, offset-1, 1, ctrl_fld_fb);
				proto_tree_add_boolean( ui_tree, hf_llcgprs_PF, tvb, offset-1, 1, ctrl_fld_fb);
				proto_tree_add_uint( ui_tree, hf_llcgprs_ucom, tvb, offset-1, 1, ctrl_fld_fb);
			}
			break;
/*		case I_SACK:
			break;
		case S_SACK:
			break;	
*/
		}		
/*		proto_tree_add_item(llcgprs_tree,
		    hf_llcgprs_FIELDABBREV, tvb, offset, len, FALSE)
*/
/* Continue adding tree items to process the packet here */



/* If this protocol has a sub-dissector call it here, see section 1.8 */
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_llcgprs(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_llcgprs_sapi,
			{ "SAPI", "llcgprs.sapi", FT_UINT8, BASE_DEC, VALS(sapi_abrv), 0x0,"Service Access Point Identifier", HFILL }},
		{ &hf_llcgprs_pd, 
			{ "Protocol Discriminator_bit", "llcgprs.pd", FT_BOOLEAN,8, TFS(&pd_bit), 0x80, " Protocol Discriminator bit (should be 0)", HFILL }},
		{&hf_llcgprs_sjsd,
			{ "Supervisory function bits","llcgprs.s1s2", FT_UINT16, BASE_HEX, VALS(cr_formats_ipluss),0x3, "Supervisory functions bits",HFILL }},
		{ &hf_llcgprs_cr, 
			{ "Command/Response bit", "llcgprs.cr", FT_BOOLEAN, 8, TFS(&cr_bit), 0x40, " Command/Response bit", HFILL}},
		{ &hf_llcgprs_sapib,
			{ "SAPI", "llcgprs.sapib", FT_UINT8, BASE_DEC , VALS(sapi_t), 0xf, "Service Access Point Identifier ",HFILL }},	
		{ &hf_llcgprs_U_fmt,
			{ "UI format", "llcgprs.ui", FT_UINT16, BASE_HEX, NULL, UI_MASK_FMT, "UI frame format",HFILL}},
		{ &hf_llcgprs_Un,
			{ "U format", "llcgprs.u", FT_UINT8, BASE_DEC, NULL, 0xe0, " U frame format", HFILL}},
		{ &hf_llcgprs_sp_bits,
			{ "Spare bits", "llcgprs.ui_sp_bit", FT_UINT16, BASE_HEX, NULL, UI_MASK_SPB, "Spare bits", HFILL}},
		{ &hf_llcgprs_NU,
			{ "N(U)", "llcgprs.nu", FT_UINT16, BASE_DEC, NULL, UI_MASK_NU, "Transmited unconfirmed sequence number", HFILL}},
		{ &hf_llcgprs_E_bit,
			{ "E bit", "llcgprs.e", FT_BOOLEAN, 16, TFS(&e_bit), UI_MASK_E,"Encryption mode bit",HFILL }},
		{ &hf_llcgprs_PM_bit,
			{ "PM bit", "llcgprs.pm", FT_BOOLEAN, 16, TFS(&pm_bit), UI_MASK_PM, "Protected mode bit",HFILL}},
		{ &hf_llcgprs_As,
			{ "Ackn request bit", "llcgprs.as", FT_BOOLEAN, 16, TFS(&a_bit), 0x2000 ,"Acknowledgement request bit A", HFILL}},
		{ &hf_llcgprs_PF,
			{ "P/F bit", "llcgprs.pf", FT_BOOLEAN, 8, NULL, 0x10,"Poll /Finall bit", HFILL}},
		{ &hf_llcgprs_ucom,
			{ "Command/Response","llcgprs.ucom", FT_UINT8, BASE_HEX, VALS(cr_formats_unnumb),0xf,"Commands and Responses",HFILL }},	
		{ &hf_llcgprs_NR,
			{ "Receive sequence number", "llcgprs.nr",FT_UINT16, BASE_DEC, NULL, UI_MASK_NU,"Receive sequence number N(R)",HFILL }},
		{&hf_llcgprs_S_fmt,
			{ "S format", "llcgprs.s", FT_UINT16, BASE_DEC, NULL, 0xc000,"Supervisory format S", HFILL}}
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_llcgprs,
		&ett_llcgprs_adf,
		&ett_llcgprs_ctrlf,
		&ett_ui,
		&ett_llcgprs_sframe,
	};

	module_t *llcgprs_module;
	
/* Register the protocol name and description */
	proto_llcgprs = proto_register_protocol("Logical Link Control GPRS",
	    "GPRS-LLC", "llcgprs");
	llcgprs_subdissector_table = register_dissector_table("llcgprs.sapi","GPRS LLC SAPI", FT_UINT8,BASE_HEX);
/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_llcgprs, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector( "llcgprs", dissect_llcgprs, proto_llcgprs);
	
	llcgprs_module = prefs_register_protocol ( proto_llcgprs, NULL );
	prefs_register_bool_preference ( llcgprs_module, "ignore_cipher_bit",
	    "Ignore cipher bit", 
	    "Whether to ignore the cipher bit (because it might be set on unciphered data)",
	    &ignore_cipher_bit );
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_llcgprs(void)
{
	dissector_handle_t llcgprs_handle;

	llcgprs_handle = create_dissector_handle(dissect_llcgprs,
	    proto_llcgprs);
/*	dissector_add("PARENT_SUBFIELD", ID_VALUE, llcgprs_handle);
*/
	data_handle = find_dissector("data");
}
