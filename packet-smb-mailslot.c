/* packet-smb-mailslot.c
 * Routines for SMB mailslot packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-smb-mailslot.c,v 1.11 2001/03/18 03:34:22 guy Exp $
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
#include "packet-smb-mailslot.h"
#include "packet-smb-browse.h"
#include "packet-smb-logon.h"
#include "packet-smb-pipe.h"

static int proto_smb_msp = -1;

static int ett_smb_msp = -1;

gboolean
dissect_mailslot_smb(const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
	int SMB_offset, int errcode, int dirn, const u_char *command,
	int DataOffset, int DataCount, int ParameterOffset, int ParameterCount){


/* decode the SMB mail slot protocol */

   	proto_tree      *smb_msp_tree = 0;
   	proto_item      *ti;

   	guint16  Temp16; 
   	const char *StrPtr;

	if (!proto_is_protocol_enabled(proto_smb_msp))
		return FALSE;
   
	if (check_col(fd, COL_PROTOCOL))
		col_set_str(fd, COL_PROTOCOL, "SMB Mailslot");

	if (DataOffset < 0) {
		/* Interim reply */
		col_set_str(fd, COL_INFO, "Interim reply");
		return TRUE;
	}

 /* do the Op code field */
 
    	Temp16 = GSHORT(pd, offset);		/* get Op code */

	if (check_col(fd, COL_INFO))
		  col_set_str(fd, COL_INFO,
		      ( Temp16 == 1 ? "Write Mail slot" : "Unknown"));


    	if (tree) {
		ti = proto_tree_add_item( parent, proto_smb_msp, NullTVB, offset,
			END_OF_FRAME, FALSE);
		smb_msp_tree = proto_item_add_subtree(ti, ett_smb_msp);

 		proto_tree_add_text(smb_msp_tree, NullTVB, offset, 2, "Op code: %u (%s)",
 			Temp16, ( Temp16 == 1 ? "Write Mail slot" : "Unknown"));

	  	offset += 2;
 
   						/* do the Priority field */
     		Temp16 = GSHORT(pd, offset);
     		proto_tree_add_text(smb_msp_tree, NullTVB, offset, 2,
     			"Priority of transaction: %u", Temp16);
    	
   		offset += 2;

    						/* do the Class field */
      		Temp16 = GSHORT(pd, offset);
     
      		proto_tree_add_text(smb_msp_tree, NullTVB, offset, 2, "Class: %u (%s)",
      			Temp16, ( Temp16 == 1) ? "Reliable" : (( Temp16 == 2) ?
      			"Unreliable & Broadcast" : "Unknown"));
	
	   	offset += 2;

     			 			/* do the data size field */
     		Temp16 = GSHORT(pd, offset);
     		proto_tree_add_text(smb_msp_tree, NullTVB, offset, 2,
     			"Total size of mail data: %u", Temp16);

	   	offset += 2;
	}else {					/* no tree value adjust offset*/
		offset += 8;
	}	   	

    					/* Build display for: MailSlot Name */

    	StrPtr = &pd[offset];		/* load pointer to name	*/

 	if (smb_msp_tree) {
		proto_tree_add_text(smb_msp_tree, NullTVB, offset, strlen( StrPtr) + 1,
			"Mailslot Name: %s", StrPtr);
    	}

	offset += strlen( StrPtr) + 1;
 
/*** Decide what dissector to call based upon the command value ***/
 
  	if (command != NULL && strcmp(command, "BROWSE") == 0) { /* Decode a browse */

    		return dissect_mailslot_browse(pd, offset, fd, parent, tree,
    			si, max_data, SMB_offset, errcode, dirn, command,
    			DataOffset, DataCount);
  	}

  	else if (command != NULL && strcmp(command, "LANMAN") == 0) {

    		return dissect_pipe_lanman(pd, offset, fd, parent, tree, si,
    			max_data, SMB_offset, errcode, dirn, command,
    			DataOffset, DataCount, ParameterOffset, ParameterCount);
  	}

/* NOTE: use TEMP\\NETLOGON and MSSP because they seems very common,	*/
/* NOTE: may need a look up list to check for the mailslot names passed	*/
/*		by the logon request packet */
	
  	else if (((command != NULL) &&
		  strncmp(command, "NET", strlen("NET")) == 0) ||
		 (strcmp(command, "TEMP\\NETLOGON") == 0) ||
		 (strcmp(command, "MSSP") == 0)){

		return dissect_smb_logon(pd, DataOffset, fd, parent, tree,
			si, max_data, SMB_offset, errcode, dirn,
			command, DataOffset, DataCount);
		
	 }
  	return TRUE;
}


void
register_proto_smb_mailslot( void){


	static gint *ett[] = {
		&ett_smb_msp
	};

   	proto_smb_msp = proto_register_protocol(
   		"SMB MailSlot Protocol", "SMB Mailslot", "mailslot");

	proto_register_subtree_array(ett, array_length(ett));
}
