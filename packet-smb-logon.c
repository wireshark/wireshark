/* packet-smb-logon.c
 * Routines for smb net logon packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-smb-logon.c,v 1.10 2000/11/19 08:54:06 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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
 */

#include "packet-smb-common.h"

static int proto_smb_logon = -1;

static int ett_smb_logon = -1;
static int ett_smb_account_flags = -1;


static void
dissect_account_control( const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree){
		
/* display the Allowable Account control bits */

	proto_tree  *flags_tree;
	proto_item  *ti;
	guint32  flags = GWORD( pd, offset);

	struct flag_array_type  flag_info[] = {
		{ 0x400, "User account ", "", "not ", "auto-locked"},
		{ 0x200, "User password will ", "not ", "", "expire"},
		{ 0x100, "", "", "Not a ", "Server Trust user account"},
		{ 0x080, "", "", "Not a ", "Workstation Trust user account"},
		{ 0x040, "", "", "Not an ", "Inter-domain Trust user account"},
		{ 0x020, "", "", "Not a ", "MNS Logon user account"},
		{ 0x010, "", "", "Not a ", "Normal user account"},
		{ 0x008, "", "", "Not a ", "temp duplicate user account"},
		{ 0x004, "", "No", "", "User password required"},
		{ 0x002, "", "No", "", "User home directory required"},
		{ 0x001, "User account ", "enabled", "disabled", ""},
		{ 0, "", "", "", ""}
	};


	ti = proto_tree_add_text( tree, NullTVB, offset, 4,
		"Account control  = 0x%04x", flags);
		
     	flags_tree = proto_item_add_subtree( ti, ett_smb_account_flags);

	display_flags( flag_info, 4, pd, offset, flags_tree);
}



static void
display_LM_token( const u_char *pd, int *offset, frame_data *fd,
	proto_tree *tree) {

/* decode and display the LanMan token */	

	guint16 Token;

	if (!BYTES_ARE_IN_FRAME(*offset, 2)) {
		proto_tree_add_text(tree, NullTVB, *offset, 0,"****FRAME TOO SHORT***");
		return;
	}

	Token = GSHORT( pd, *offset);
	
	if ( Token && 0x01) 
		proto_tree_add_text( tree, NullTVB, *offset, 2,
			"LM20 Token: 0x%x (LanMan 2.0 or higher)", Token);
	else
		proto_tree_add_text( tree, NullTVB, *offset, 2,
			"LM10 Token: 0x%x (WFW Networking)", Token);
	*offset += 2;
	
}

static void
display_NT_version( const u_char *pd, int *offset, frame_data *fd,
	proto_tree *tree, int length) {

/* display the NT version	*/	

	guint32 Version;
	
	if (!BYTES_ARE_IN_FRAME(*offset, length)) {
		proto_tree_add_text(tree, NullTVB, *offset, 0, "****FRAME TOO SHORT***");
		return;
	}

	if ( length == 2)
		Version = GSHORT( pd, *offset);
	else
		Version  = GWORD( pd, *offset);
	
	proto_tree_add_text( tree, NullTVB, *offset, length, "NT Version: 0x%x ",
		Version);

	*offset += length;
	
}



void dissect_smb_logon_request( const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree){

/*** 0x00 (LM1.0/LM2.0 LOGON Request) ***/
 
 	MoveAndCheckOffset( display_ms_string( "Computer Name", pd, offset, fd,
 		tree));
	
	MoveAndCheckOffset( display_ms_string( "User Name", pd, offset, fd,
		tree));

	MoveAndCheckOffset( display_ms_string( "Mailslot Name", pd, offset, fd,
		tree));

/*$$$$$ here add the Mailslot to the response list (if needed) */
	
	MoveAndCheckOffset( display_ms_value( "Request Count", 1, pd, offset,
		fd, tree));

	display_NT_version( pd, &offset, fd, tree,2);
	display_LM_token( pd, &offset, fd, tree);
}



static void
dissect_smb_logon_LM10_resp(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree){

/*** 0x01 LanMan 1.0 Logon response ***/

	MoveAndCheckOffset( display_ms_string( "User Name", pd, offset, fd,
		tree));
	MoveAndCheckOffset( display_ms_string( "Script Name", pd, offset, fd,
		tree));
}



void dissect_smb_logon_2(const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree) {

/*** 0x02  LM1.0 Query - Centralized Initialization ***/
/*** 0x03  LM1.0 Query - Distributed Initialization ***/
/*** 0x04  LM1.0 Query - Centralized Query Response ***/
/*** 0x04  LM1.0 Query - Distributed Query Response ***/

	MoveAndCheckOffset( display_ms_string( "Computer Name", pd, offset, fd, tree));

	MoveAndCheckOffset( display_ms_string( "Mailslot Name", pd, offset, fd, tree));

	display_NT_version( pd, &offset, fd, tree, 2);
	display_LM_token( pd, &offset, fd, tree);
}



void dissect_smb_logon_LM20_resp(const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree){

/*** 0x06 (LM2.0 LOGON Response)	***/

	++offset;		/* move to the server name */

	MoveAndCheckOffset( display_ms_string( "Logon Server Name", pd, offset,
		fd, tree));

	display_LM_token( pd, &offset, fd, tree);

}



static void
dissect_smb_pdc_query(const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree){

/*** 0x07 Query for Primary PDC  ***/

 
	MoveAndCheckOffset( display_ms_string( "Computer Name", pd, offset,
		fd, tree));

	MoveAndCheckOffset( display_ms_string( "Mailslot Name", pd, offset,
		fd, tree));

	MoveAndCheckOffset( display_ms_string( "OEM Computer Name", pd, offset,
		fd, tree));

	display_NT_version( pd, &offset, fd, tree, 4);

	proto_tree_add_text( tree, NullTVB, offset, 2, "LMNT Token: 0x%x",
		GWORD(pd, offset));
	MoveAndCheckOffset( 2);
	
	display_LM_token( pd, &offset, fd, tree);
}



void dissect_smb_pdc_startup(const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree){

/*** 0x08  Announce startup of PDC ***/
 
	MoveAndCheckOffset(
		display_ms_string( "PDC Name", pd, offset, fd, tree));

	/* A short Announce will not have the rest */

	if (END_OF_FRAME > 0) { 

	  if (offset % 2) offset++;      /* word align ... */

	  MoveAndCheckOffset(
		 display_unicode_string("Unicode PDC Name", pd, offset, fd, tree));

	  if (offset % 2) offset++;

	  MoveAndCheckOffset(
		 display_unicode_string("Unicode Domain Name", pd, offset, fd, tree));

	  display_NT_version( pd, &offset, fd, tree, 4);

	  display_LM_token( pd, &offset, fd, tree);
	}
}



static void
dissect_smb_pdc_failure( const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree){

/*** 0x09 Announce failure of the PDC ***/
/*** 0x0F LM2.0 Resp. during LOGON pause ***/
/*** 0x10 (LM 2.0 Unknown user response) ***/

	display_NT_version( pd, &offset, fd, tree, 4);
	display_LM_token( pd, &offset, fd, tree);
}


void dissect_announce_change( const u_char *pd, int offset,
	frame_data *fd,proto_tree *tree) {
	
/*** 0x0A ( Announce change to UAS or SAM ) ***/


	MoveAndCheckOffset( display_ms_value( "Low serial number", 4, pd,
		offset, fd, tree));
	MoveAndCheckOffset( display_ms_value( "Date/Time", 4, pd, offset, fd,
		tree));
	MoveAndCheckOffset(
		display_ms_value( "Pulse", 4, pd, offset, fd, tree));
	MoveAndCheckOffset(
		display_ms_value( "Random", 4, pd, offset, fd, tree));
	MoveAndCheckOffset(
		display_ms_string( "PDC Name", pd, offset, fd, tree));
	MoveAndCheckOffset(
		display_ms_string( "Domain Name", pd, offset, fd, tree));

/*???? is this needed ??? */
	if ( !( offset & 0x1))			/* add padding if needed */
		++offset;

	MoveAndCheckOffset( display_unicode_string( "Unicode PDC Name", pd,
		offset, fd, tree));

	MoveAndCheckOffset( display_unicode_string( "Unicode Domain Name", pd,
		offset, fd, tree));

	MoveAndCheckOffset( display_ms_value( "DB Count", 4, pd, offset, fd,
		tree));

	MoveAndCheckOffset( display_ms_value( "NT Version ", 4, pd, offset, fd,
		tree));

	MoveAndCheckOffset( display_ms_value( "LMNT Token ", 2, pd, offset, fd,
		tree));

	MoveAndCheckOffset( display_ms_value( "Unknown Token ", 2, pd, offset,
		fd, tree));
}


static void
dissect_smb_sam_logon_req(const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree){

/*** Netlogon command 0x12 - decode the SAM logon request from client ***/


	proto_tree_add_text( tree, NullTVB, offset, 2, "Request Count  = %x",
		GSHORT(pd, offset));

	MoveAndCheckOffset( 2);
	
	MoveAndCheckOffset( display_unicode_string( "Unicode Computer Name",
		pd, offset, fd, tree));
	
	MoveAndCheckOffset( display_unicode_string( "Unicode User Name",
		pd, offset, fd, tree));
	
	MoveAndCheckOffset( display_ms_string( "Mailslot Name", pd, offset, fd,
		tree));

	dissect_account_control( pd, offset, fd, tree);
		
	proto_tree_add_text( tree, NullTVB, offset, 2, "Domain SID Size = %x",
		GWORD(pd, offset));

}



static void
dissect_smb_no_user( const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree)

{/* 0x0B (Announce no user on machine) */

	display_ms_string( "Computer Name", pd, offset, fd, tree);
}



static void
dissect_smb_relogon_resp( const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree){

/*** 0x0d LanMan Response to relogon request ***/

	MoveAndCheckOffset( display_ms_value( "Workstation major version", 1,
		pd, offset, fd, tree));

	MoveAndCheckOffset( display_ms_value( "Workstation minor version", 1,
		pd, offset, fd, tree));

	MoveAndCheckOffset( display_ms_value( "Workstation OS version", 1,
		pd, offset, fd, tree));

	display_NT_version( pd, &offset, fd, tree, 4);

	display_LM_token( pd, &offset, fd, tree);
}



static void
dissect_smb_acc_update( const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree){

/*** 0x11  LM2.1 Announce Acc updates  ***/

	guint32 Temp1, Temp2;
	
	Temp1 = GWORD( pd, offset);

	Temp2 = GWORD( pd, offset + 4);
	
	proto_tree_add_text( tree, NullTVB, offset, 2, "Signature: 0x%04x%04x",
		Temp1, Temp2);

	MoveAndCheckOffset( 8);

	MoveAndCheckOffset( display_ms_value( "Time/Date:", 4,
		pd, offset, fd, tree));
	
	MoveAndCheckOffset( display_ms_string( "Computer name:", 
		pd, offset, fd, tree));

	MoveAndCheckOffset( display_ms_string( "User name:", 
		pd, offset, fd, tree));

	MoveAndCheckOffset( display_ms_value( "Update Type:", 2,
		pd, offset, fd, tree));

	display_NT_version( pd, &offset, fd, tree, 4);

	display_LM_token( pd, &offset, fd, tree);
}



static void
dissect_smb_inter_resp( const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree){

/* 0x0e LanMan Response to interrogate request */

	MoveAndCheckOffset( display_ms_value( "Workstation major version", 1,
		pd, offset, fd, tree));

	MoveAndCheckOffset( display_ms_value( "Workstation minor version", 1,
		pd, offset, fd, tree));

	MoveAndCheckOffset( display_ms_value( "Workstation OS version", 1, pd,
		offset, fd, tree));

	display_NT_version( pd, &offset, fd, tree, 4);

	MoveAndCheckOffset( display_ms_value( "LMNT Token ", 2, pd, offset, fd,
		tree));
}


void dissect_smb_sam_logon_resp(const u_char *pd, int offset, frame_data *fd,
		proto_tree *tree){

/* Netlogon command 0x13 - decode the SAM logon response from server */


	MoveAndCheckOffset( display_unicode_string( "Server Name", pd, offset,
		fd, tree));
	
	MoveAndCheckOffset( display_unicode_string( "User Name", pd, offset,
		fd, tree));
	
	MoveAndCheckOffset( display_unicode_string( "Domain Name", pd, offset,
		fd, tree));

	display_NT_version( pd, &offset, fd, tree, 4);

	proto_tree_add_text( tree, NullTVB, offset, 2, "LMNT Token: 0x%x",
		GSHORT(pd, offset));
	MoveAndCheckOffset( 2);

	display_LM_token( pd, &offset, fd, tree);
}


guint32 
dissect_smb_logon(const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, struct smb_info si,
	int max_data, int SMB_offset, int errcode, int dirn,
	const u_char *command, int DataOffset, int DataCount){


/* decode the Microsoft netlogon protocol */

static char* CommandName[] = {

	"LM1.0/LM2.0 LOGON Request",			/* 0x00 */
	"LM1.0 LOGON Response",				/* 0x01 */
	"LM1.0 Query - Centralized Initialization",	/* 0x02 */
	"LM1.0 Query - Distributed Initialization",	/* 0x03 */
	"LM1.0 Response - Centralized Query",		/* 0x04 */
	"LM1.0 Response - Distributed Initialization",	/* 0x05 */
	"LM2.0 Response to LOGON Request",		/* 0x06 */
	"Query for PDC",				/* 0x07 */
	"Announce Startup of PDC",			/* 0x08 */
	"Announce Failed PDC",				/* 0x09 */
	"Announce Change to UAS or SAM",		/* 0x0A */
	"Announce no user on machine",			/* 0x0B */
	"Response from PDC",				/* 0x0C */
	"LM1.0/LM2.0 Response to re-LOGON Request",	/* 0x0D */
	"LM1.0/LM2.0 Response to Interrogate Request",	/* 0x0E */
	"LM2.0 Response during LOGON pause",		/* 0x0F */
	"LM2.0 Response - user unknown",		/* 0x10 */
	"LM2.0 Announce account updates ",		/* 0x11 */
	"SAM LOGON request from client ",		/* 0x12 */
	"Response to SAM LOGON request",		/* 0x13 */
	"SAM Response during LOGON pause",		/* 0x14 */
	"SAM Response - user unknown",			/* 0x15 */
	"SAM Response to Interrogate Request",		/* 0x16 */
	"Unknown"					/* 0x17 */
	};

/* Array of functions to dissect the ms logon commands */
		
static void (*dissect_smb_logon_cmds[])(const u_char *, int, frame_data *,
	proto_tree *) = {

  dissect_smb_logon_request,    /* 0x00 (LM1.0/LM2.0 LOGON Request) 	*/
  dissect_smb_logon_LM10_resp, 	/* 0x01 (LM1.0 LOGON Response) 		*/
  dissect_smb_logon_2,	      	/* 0x02 (LM1.0 Query Centralized Init.)	*/
  dissect_smb_logon_2,	      	/* 0x03 (LM1.0 Query Distributed Init.)	*/
  dissect_smb_logon_2,	      	/* 0x04 (LM1.0 Centralized Query Resp.)	*/
  dissect_smb_logon_2,	      	/* 0x05 (LM1.0 Distributed Query Resp.) */
  dissect_smb_logon_LM20_resp, 	/* 0x06 (LM2.0 LOGON Response)		*/
  dissect_smb_pdc_query,	/* 0x07 (Query for PDC) 		*/
  dissect_smb_pdc_startup,	/* 0x08 (Announce PDC startup)		*/
  dissect_smb_pdc_failure,     	/* 0x09 (Announce Failed PDC)		*/
  dissect_announce_change,     	/* 0x0A (Announce change to UAS or SAM)	*/
  dissect_smb_no_user,	      	/* 0x0B (Announce no user on machine)	*/
  dissect_smb_pdc_startup,	/* 0x0C (Response from PDC)		*/
  dissect_smb_relogon_resp,	/* 0x0D (Relogon response) 		*/
  dissect_smb_inter_resp,      	/* 0x0E (Interrogate response) 		*/
  dissect_smb_pdc_failure,	/* 0x0F (LM2.0 Resp. during LOGON pause	*/
  dissect_smb_pdc_failure,    	/* 0x10 (LM 2.0 Unknown user response)	*/
  dissect_smb_acc_update,    	/* 0x11 (LM2.1 Announce Acc updates) 	*/
  dissect_smb_sam_logon_req,   	/* 0x12 (SAM LOGON request )		*/
  dissect_smb_sam_logon_resp,  	/* 0x13 (SAM LOGON response) 		*/
  dissect_smb_unknown,          /* 0x14 (SAM Response during LOGON Pause) */
  dissect_smb_unknown,          /* 0x15 (SAM Response User Unknown)      */
  dissect_smb_unknown,          /* 0x16 (SAM Response to Interrogate)   */
};



	guint8  cmd;
	proto_tree      *smb_logon_tree;
	proto_item      *ti;


	if (!proto_is_protocol_enabled(proto_smb_logon))
	  return 0;
					   /* get the Command field */
   	cmd = MIN(  GBYTE(pd, offset), array_length(dissect_smb_logon_cmds)-1);

	if (check_col(fd, COL_PROTOCOL))
		col_set_str(fd, COL_PROTOCOL, "NETLOGON");


	if (check_col(fd, COL_INFO))
		col_add_fstr(fd, COL_INFO, "%s", CommandName[ cmd]);

    	if (tree) {
		ti = proto_tree_add_item( parent, proto_smb_logon, NullTVB, offset,
			END_OF_FRAME, FALSE);
		smb_logon_tree = proto_item_add_subtree(ti, ett_smb_logon);

		proto_tree_add_text(smb_logon_tree, NullTVB, offset, 1,
			"Command: %u (%s)", cmd, CommandName[ cmd]);
			
		offset += 2;			/* skip to name field */

						/* vector to handle commands */
		(dissect_smb_logon_cmds[  cmd]) (pd, offset, fd,smb_logon_tree);

	}
   return 1;  
}



void
register_proto_smb_logon( void){

/*** Prep the logon protocol, for now, just register it	*/

	static gint *ett[] = {
		&ett_smb_logon,
		&ett_smb_account_flags
	};

   	proto_smb_logon = proto_register_protocol(
   		"Microsoft Windows Logon Protocol", "netlogon");

	proto_register_subtree_array(ett, array_length(ett));          
}





