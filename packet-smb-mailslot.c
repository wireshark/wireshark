/* packet-smb-mailslot.c
 * Routines for smb mailslot packet dissection
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet-smb-mailslot.c,v 1.4 2000/05/11 08:15:45 gram Exp $
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

static int proto_smb_msp = -1;

static int ett_smb_msp = -1;


/***  External dissectors called from here	*/

extern guint32 
dissect_mailslot_browse(const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
	int SMB_offset, int errcode, int dirn, const u_char *command,
	int DataOffset, int DataCount);

extern guint32 
dissect_pipe_lanman(const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
	int SMB_offset, int errcode, int dirn, const u_char *command,
	int DataOffset, int DataCount, int ParameterOffset, int ParameterCount);

extern guint32 
dissect_smb_ntlogon(const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
	int SMB_offset, int errcode, int dirn, const u_char *command,
	int DataOffset, int DataCount);


extern guint32 
dissect_smb_logon(const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
	int SMB_offset, int errcode, int dirn, const u_char *command,
	int DataOffset, int DataCount);



guint32
dissect_mailslot_smb(const u_char *pd, int offset, frame_data *fd,
	proto_tree *parent, proto_tree *tree, struct smb_info si, int max_data,
	int SMB_offset, int errcode, int dirn, const u_char *command,
	int DataOffset, int DataCount, int ParameterOffset, int ParameterCount){


/* decode the SMB mail slot protocol */


   	proto_tree      *smb_msp_tree = 0;
   	proto_item      *ti;

   	guint16  Temp16; 
   	const char *StrPtr;
   
 /* do the Op code field */
 
    	Temp16 = GSHORT(pd, offset);		/* get Op code */

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "SMB Mailslot");

	if (check_col(fd, COL_INFO))
		  col_add_fstr(fd, COL_INFO, "%s",
		      ( Temp16 == 1 ? "Write Mail slot" : "Unknown"));


    	if (tree) {
		ti = proto_tree_add_item( parent, proto_smb_msp, NullTVB, offset,
			END_OF_FRAME, NULL);
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
 
  	if (strcmp(command, "BROWSE") == 0) { /* Decode a browse */

    		return dissect_mailslot_browse(pd, offset, fd, parent, tree,
    			si, max_data, SMB_offset, errcode, dirn, command,
    			DataOffset, DataCount);
  	}

  	else if (strcmp(command, "LANMAN") == 0) {

    		return dissect_pipe_lanman(pd, offset, fd, parent, tree, si,
    			max_data, SMB_offset, errcode, dirn, command,
    			DataOffset, DataCount, ParameterOffset, ParameterCount);
  	}

/* NOTE: use TEMP\\NETLOGON and MSSP because they seems very common,	*/
/* NOTE: may need a look up list to check for the mailslot names passed	*/
/*		by the logon request packet */
	
  	else if ((strncmp(command, "NET", strlen("NET")) == 0) 
			|| (strcmp(command, "TEMP\\NETLOGON") == 0)
			|| (strcmp(command, "MSSP") == 0)){

		return dissect_smb_logon(pd, DataOffset, fd, parent, tree,
			si, max_data, SMB_offset, errcode, dirn,
			command, DataOffset, DataCount);
		
	 }
  	return 1;
}


void
register_proto_smb_mailslot( void){


	static gint *ett[] = {
		&ett_smb_msp
	};

   	proto_smb_msp = proto_register_protocol(
   		"SMB MailSlot Protocol", "mailslot");

	proto_register_subtree_array(ett, array_length(ett));
}
