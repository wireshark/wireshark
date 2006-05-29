/* packet-synergy.c
 * Routines for synergy dissection
 * Copyright 2005, Vasanth Manickam <vasanthm@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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



void proto_reg_handoff_synergy(void);


static int proto_synergy = -1;

static int hf_synergy_unknown = -1;
static int hf_synergy_handshake = -1;
static int hf_synergy_handshake_majorversion = -1;
static int hf_synergy_handshake_minorversion = -1;
static int hf_synergy_handshake_clientname = -1;

static int hf_synergy_cnop = -1;

static int hf_synergy_cbye = -1;

static int hf_synergy_cinn = -1;
static int hf_synergy_cinn_x = -1;
static int hf_synergy_cinn_y = -1;
static int hf_synergy_cinn_sequence = -1;
static int hf_synergy_cinn_modifiermask = -1;

static int hf_synergy_cout = -1;

static int hf_synergy_cclp = -1;
static int hf_synergy_cclp_clipboardidentifier = -1;
static int hf_synergy_cclp_sequencenumber = -1;

static int hf_synergy_csec = -1;

static int hf_synergy_crop = -1;

static int hf_synergy_ciak = -1;

static int hf_synergy_dkdn = -1;
static int hf_synergy_dkdn_keyid = -1;
static int hf_synergy_dkdn_keymodifiermask = -1;
static int hf_synergy_dkdn_keybutton = -1;

static int hf_synergy_dkrp = -1;
static int hf_synergy_dkrp_keyid = -1;
static int hf_synergy_dkrp_keymodifiermask = -1;
static int hf_synergy_dkrp_numberofrepeats = -1;
static int hf_synergy_dkrp_keybutton = -1;

static int hf_synergy_dkup = -1;
static int hf_synergy_dkup_keyid = -1;
static int hf_synergy_dkup_keymodifiermask = -1;
static int hf_synergy_dkup_keybutton = -1;

static int hf_synergy_dmdn = -1;
static int hf_synergy_dmup = -1;

static int hf_synergy_dmmv = -1;
static int hf_synergy_dmmv_x = -1;
static int hf_synergy_dmmv_y = -1;

static int hf_synergy_dmrm = -1;
static int hf_synergy_dmrm_x = -1;
static int hf_synergy_dmrm_y = -1;

static int hf_synergy_dmwm = -1;

static int hf_synergy_dclp = -1;
static int hf_synergy_dclp_clipboardidentifier = -1;
static int hf_synergy_dclp_sequencenumber = -1;
static int hf_synergy_dclp_clipboarddata = -1;

static int hf_synergy_dinf = -1;
static int hf_synergy_dinf_clp = -1;
static int hf_synergy_dinf_ctp= -1;
static int hf_synergy_dinf_wsp = -1;
static int hf_synergy_dinf_hsp = -1;
static int hf_synergy_dinf_swz = -1;
static int hf_synergy_dinf_x = -1;
static int hf_synergy_dinf_y = -1;

static int hf_synergy_dsop = -1;

static int hf_synergy_qinf = -1;

static int hf_synergy_eicv = -1;
static int hf_synergy_eicv_majorversion = -1;
static int hf_synergy_eicv_minorversion = -1;

static int hf_synergy_ebsy = -1;

static int hf_synergy_eunk = -1;

static int hf_synergy_ebad = -1;

/* Initialize the subtree pointers */
static gint ett_synergy = -1;

static void dissect_synergy_handshake(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);
static void dissect_synergy_cinn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);
static void dissect_synergy_cclp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);
static void dissect_synergy_dkdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);
static void dissect_synergy_dkrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);
static void dissect_synergy_dkup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);
static void dissect_synergy_dmmv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);
static void dissect_synergy_dmrm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);
static void dissect_synergy_dclp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);
static void dissect_synergy_dinf(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);
static void dissect_synergy_eicv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,gint offset);


/* Code to actually dissect the packets */
static void
dissect_synergy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

 if(check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "synergy");

	if (tree) {
		gint offset=0;
		char buffer[20];
		proto_item *ti = NULL;
		proto_tree *synergy_tree = NULL;
		ti = proto_tree_add_protocol_format(tree, proto_synergy, tvb, 0, -1,"Synergy Protocol");
		synergy_tree = proto_item_add_subtree(ti, ett_synergy);

		tvb_get_nstringz(tvb,offset+4,20,buffer);

		if(strncmp(buffer,"Synergy",7)==0)
			dissect_synergy_handshake(tvb,pinfo,synergy_tree,offset+4);
		else if(strncmp(buffer,"CNOP",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_cnop,tvb,offset+4,-1,FALSE);
		else if(strncmp(buffer,"CBYE",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_cbye,tvb,offset+4,-1,FALSE);
		else if(strncmp(buffer,"CINN",4)==0)
			dissect_synergy_cinn(tvb,pinfo,synergy_tree,offset+4);	
		else if(strncmp(buffer,"COUT",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_cout,tvb,offset+4,-1,FALSE);
		else if(strncmp(buffer,"CCLP",4)==0)
			dissect_synergy_cclp(tvb,pinfo,synergy_tree,offset+4);	
		else if(strncmp(buffer,"CSEC",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_csec,tvb,offset+4,1,FALSE);
		else if(strncmp(buffer,"CROP",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_crop,tvb,offset+4,-1,FALSE);
		else if(strncmp(buffer,"CIAK",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_ciak,tvb,offset+4,-1,FALSE);
		else if(strncmp(buffer,"DKDN",4)==0)
			dissect_synergy_dkdn(tvb,pinfo,synergy_tree,offset+4);
		else if(strncmp(buffer,"DKRP",4)==0)
			dissect_synergy_dkrp(tvb,pinfo,synergy_tree,offset+4);
		else if(strncmp(buffer,"DKUP",4)==0)
			dissect_synergy_dkup(tvb,pinfo,synergy_tree,offset+4);
		else if(strncmp(buffer,"DMDN",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_dmdn,tvb,offset+4,1,FALSE);
		else if(strncmp(buffer,"DMUP",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_dmup,tvb,offset+4,1,FALSE);
		else if(strncmp(buffer,"DMMV",4)==0)
			dissect_synergy_dmmv(tvb,pinfo,synergy_tree,offset+4);
		else if(strncmp(buffer,"DMRM",4)==0)
			dissect_synergy_dmrm(tvb,pinfo,synergy_tree,offset+4);
		else if(strncmp(buffer,"DMWM",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_dmwm,tvb,offset+4,2,FALSE);
		else if(strncmp(buffer,"DCLP",4)==0)
			dissect_synergy_dclp(tvb,pinfo,synergy_tree,offset+4);
		else if(strncmp(buffer,"DINF",4)==0)
			dissect_synergy_dinf(tvb,pinfo,synergy_tree,offset+4);
		else if(strncmp(buffer,"DSOP",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_dsop,tvb,offset+4,4,FALSE);
		else if(strncmp(buffer,"QINF",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_qinf,tvb,offset+4,-1,FALSE);
		else if(strncmp(buffer,"EICV",4)==0)
			dissect_synergy_eicv(tvb,pinfo,synergy_tree,offset+4);
		else if(strncmp(buffer,"EBSY",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_ebsy,tvb,offset+4,-1,FALSE);
		else if(strncmp(buffer,"EUNK",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_eunk,tvb,offset+4,-1,FALSE);
		else if(strncmp(buffer,"EBAD",4)==0)
			proto_tree_add_item(synergy_tree,hf_synergy_ebad,tvb,offset+4,-1,FALSE);
		else
			proto_tree_add_item(synergy_tree,hf_synergy_unknown,tvb,offset+4,-1,FALSE);
		}
}

static void dissect_synergy_handshake( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_handshake, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_handshake_majorversion, tvb, offset + 7, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_handshake_minorversion, tvb, offset + 9, 2, FALSE);
	
    if (tvb_length_remaining(tvb, offset + 11) != 0)
	{
        proto_tree_add_item(sub_tree, hf_synergy_unknown, tvb, offset + 11, 4, FALSE);
        proto_tree_add_item(sub_tree, hf_synergy_handshake_clientname, tvb, offset + 15, -1, FALSE);
	}
}

static void dissect_synergy_cinn( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_cinn, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_cinn_x, tvb, offset + 4, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_cinn_y, tvb, offset + 6, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_cinn_sequence, tvb, offset + 8, 4, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_cinn_modifiermask, tvb, offset + 12, 2, FALSE);
}

static void dissect_synergy_cclp( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_cclp, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_cclp_clipboardidentifier, tvb, offset + 4, 1, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_cclp_sequencenumber, tvb, offset + 5, 4, FALSE);
}

static void dissect_synergy_dkdn( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dkdn, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_dkdn_keyid, tvb, offset + 4, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dkdn_keymodifiermask, tvb, offset + 6, 2, FALSE);
	
    if (tvb_length_remaining(tvb, offset + 8) != 0)
        proto_tree_add_item(sub_tree, hf_synergy_dkdn_keybutton, tvb, offset + 8, 2, FALSE);
}

static void dissect_synergy_dkrp( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dkrp, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_dkrp_keyid, tvb, offset + 4, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dkrp_keymodifiermask, tvb, offset + 6, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dkrp_numberofrepeats, tvb, offset + 8, 2, FALSE);
	
    if (tvb_length_remaining(tvb, offset + 10) != 0)
        proto_tree_add_item(sub_tree, hf_synergy_dkrp_keybutton, tvb, offset + 10, 2, FALSE);
}

static void dissect_synergy_dkup( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dkup, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_dkup_keyid, tvb, offset + 4, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dkup_keymodifiermask, tvb, offset + 6, 2, FALSE);
	
    if (tvb_length_remaining(tvb, offset + 8) != 0)
        proto_tree_add_item(sub_tree, hf_synergy_dkup_keybutton, tvb, offset + 8, 2, FALSE);
}

static void dissect_synergy_dmmv( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dmmv, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_dmmv_x, tvb, offset + 4, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dmmv_y, tvb, offset + 6, 2, FALSE);
}

static void dissect_synergy_dmrm( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dmrm, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_dmrm_x, tvb, offset + 4, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dmrm_y, tvb, offset + 6, 2, FALSE);
}

static void dissect_synergy_dclp( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dclp, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_dclp_clipboardidentifier, tvb, offset + 4, 1, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dclp_sequencenumber, tvb, offset + 5, 4, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dclp_clipboarddata, tvb, offset + 9, -1, FALSE);
}

static void dissect_synergy_dinf( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_dinf, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_dinf_clp, tvb, offset + 4, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_ctp, tvb, offset + 6, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_wsp, tvb, offset + 8, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_hsp, tvb, offset + 10, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_swz, tvb, offset + 12, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_x, tvb, offset + 14, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_dinf_y, tvb, offset + 16, 2, FALSE);
}

static void dissect_synergy_eicv( tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset )
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    ti = proto_tree_add_item(tree, hf_synergy_eicv, tvb, offset, -1, FALSE);
    sub_tree = proto_item_add_subtree(ti, ett_synergy);
	
    proto_tree_add_item(sub_tree, hf_synergy_eicv_majorversion, tvb, offset + 4, 2, FALSE);
    proto_tree_add_item(sub_tree, hf_synergy_eicv_minorversion, tvb, offset + 6, 2, FALSE);
}


void
proto_register_synergy(void)
{                 
	static hf_register_info hf[] = {

		{ &hf_synergy_unknown,
			{ "unknown","synergy.unknown",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_handshake,
			{ "Handshake","synergy.handshake",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_handshake_majorversion,
			{ "Major Version","synergy.handshake.majorversion",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_handshake_minorversion,
			{ "Minor Version","synergy.handshake.minorversion",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_handshake_clientname,
			{ "Client Name","synergy.handshake.client",FT_STRING, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cnop,
			{ "No Operation","synergy.cnop",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cbye,
			{ "Close Connection","synergy.cbye",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cinn,
			{ "Enter Screen","synergy.cinn",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cinn_x,
			{ "Screen X","synergy.cinn.x",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cinn_y,
			{ "Screen Y","synergy.cinn.y",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cinn_sequence,
			{ "Sequence Number","synergy.cinn.sequence",FT_UINT32, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cinn_modifiermask,
			{ "Modifier Key Mask","synergy.cinn.mask",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cout,
			{ "Leave Screen","synergy.cout",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cclp,
			{ "Grab Clipboard","synergy.clipboard",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cclp_clipboardidentifier,
			{ "Identifier","synergy.clipboard.identifier",FT_UINT8, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_cclp_sequencenumber,
			{ "Sequence Number","synergy.clipboard.sequence",FT_UINT32, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_csec,
			{ "Screen Saver Change","synergy.screensaver",FT_BOOLEAN, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_crop,
			{ "Reset Options","synergy.resetoptions",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_ciak,
			{ "resolution change acknowledgment","synergy.ack",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkdn,
			{ "Key Pressed","synergy.keypressed",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkdn_keyid,
			{ "Key Id","synergy.keypressed.keyid",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkdn_keymodifiermask,
			{ "Key Modifier Mask","synergy.keypressed.mask",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkdn_keybutton,
			{ "Key Button","synergy.keypressed.key",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkrp,
			{ "key auto-repeat","synergy.keyautorepeat",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkrp_keyid,
			{ "Key ID","synergy.keyautorepeat.keyid",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkrp_keymodifiermask,
			{ "Key modifier Mask","synergy.keyautorepeat.mask",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkrp_numberofrepeats,
			{ "Number of Repeats","synergy.keyautorepeat.repeat",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkrp_keybutton,
			{ "Key Button","synergy.keyautorepeat.key",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkup,
			{ "key released","synergy.keyreleased",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkup_keyid,
			{ "Key Id","synergy.keyreleased.keyid",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkup_keymodifiermask,
			{ "Key Modifier Mask","synergykeyreleased.mask",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dkup_keybutton,
			{ "Key Button","synergy.keyreleased.key",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dmdn,
			{ "Mouse Button Pressed","synergy.mousebuttonpressed",FT_UINT8, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dmup,
			{ "Mouse Button Released","synergy.mousebuttonreleased",FT_UINT8, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dmmv,
			{ "Mouse Moved","synergy.mousemoved",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dmmv_x,
			{ "X Axis","synergy.mousemoved.x",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dmmv_y,
			{ "Y Axis","synergy.mousemoved.y",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dmrm,
			{ "Relative Mouse Move","synergy.relativemousemove",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dmrm_x,
			{ "X Axis","synergy.relativemousemove.x",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dmrm_y,
			{ "Y Axis","synergy.relativemousemove.y",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dmwm,
			{ "Mouse Button Pressed","synergy.mousebuttonpressed",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dclp,
			{ "Clipboard Data","synergy.clipboarddata",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dclp_clipboardidentifier,
			{ "Clipboard Identifier","synergy.clipboarddata.identifier",FT_UINT8, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dclp_sequencenumber,
			{ "Sequence Number","synergy.clipboarddata.sequence",FT_UINT32, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dclp_clipboarddata,
			{ "Clipboard Data","synergy.clipboarddata.data",FT_STRING, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dinf,
			{ "Client Data","synergy.clientdata",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dinf_clp,
			{ "coordinate of leftmost pixel on secondary screen","synergy.clps",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dinf_ctp,
			{ "coordinate of topmost pixel on secondary screen","synergy.clps.ctp",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dinf_wsp,
			{ "width of secondary screen in pixels","synergy.clps.wsp",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dinf_hsp,
			{ "height of secondary screen in pixels","synergy.clps.hsp",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dinf_swz,
			{ "size of warp zone","synergy.clps.swz",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dinf_x,
			{ "x position of the mouse on the secondary screen","synergy.clps.x",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dinf_y,
			{ "y position of the mouse on the secondary screen","synergy.clps.y",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_dsop,
			{ "Set Options","synergy.setoptions",FT_UINT32, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_qinf,
			{ "Query Screen Info","synergy.qinf",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_eicv,
			{ "incompatible versions","synergy.eicv",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_eicv_majorversion,
			{ "Major Version Number","synergy.eicv.major",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_eicv_minorversion,
			{ "Minor Version Number","synergy.eicv.minor",FT_UINT16, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_ebsy,
			{ "Connection Already in Use","synergy.ebsy",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_eunk,
			{ "Unknown Client","synergy.unknown",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
		{ &hf_synergy_ebad,
			{ "protocol violation","synergy.violation",FT_NONE, BASE_DEC, NULL, 0x0,"", HFILL }
		},
	};


/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_synergy,
	};

/* Register the protocol name and description */
	proto_synergy = proto_register_protocol("Synergy",
	    "Synergy", "synergy");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_synergy, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("synergy", dissect_synergy, proto_synergy);
	
}




void
proto_reg_handoff_synergy(void)
{

	dissector_handle_t synergy_handle;
	synergy_handle = find_dissector("synergy");
	dissector_add("tcp.port",24800, synergy_handle);
}
