/* packet-netbios.c
 * Routines for NetBIOS protocol packet disassembly
 * Jeff Foster <foste@woodward.com>            
 * Copyright 1999 Jeffrey C. Foster
 * 
 * derived from the packet-nbns.c
 *
 * $Id: packet-netbios.c,v 1.4 1999/09/02 23:17:56 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <stdio.h>
#include <string.h>
#include <glib.h>
#include "packet.h"
#include "packet-dns.h"
#include "packet-netbios.h"
#include "util.h"

/* Netbios command numbers */
#define NB_ADD_GROUP		0x00
#define NB_ADD_NAME		0x01
#define NB_DATAGRAM		0x08
#define NB_NAME_QUERY		0x0a
#define NB_NAME_RESP 		0x0e
#define NB_DATA_ACK		0x14
#define NB_DATA_ONLY_LAST	0x16
#define NB_SESSION_CONFIRM	0x17	
#define NB_SESSION_INIT		0x19	
#define NB_KEEP_ALIVE		0x1f


/* Offsets of fields in the NetBIOS header. */
#define NB_LENGTH		0
#define	NB_DELIMITER		2
#define	NB_COMMAND		4
#define	NB_FLAGS		5
#define	NB_DATA1		5
#define	NB_RESYNC		6
#define	NB_DATA2		6
#define	NB_CALL_NAME_TYPE	7
#define	NB_XMIT_CORL		8
#define	NB_RESP_CORL		10
#define	NB_RMT_SES		12
#define	NB_LOCAL_SES		13
#define	NB_RECVER_NAME		12
#define	NB_SENDER_NAME		28




static int proto_netbios = -1;

/* a number to bit image table */

static char *bit_field_str[] = {
	"000",
	"001",
	"010",
	"011",
	"100",
	"101",
	"110",
	"111"};
	

/* the strings for the station type, used by get_netbios_name function */

char *name_type_str[] = {
	"Workstation/Redirector",	/* 0x00 */
	"Browser",			/* 0x01 */
	"Unknown",
	"Messenger service/Main name",	/* 0x03 */
	"Unknown",
	"Forwarded name",		/* 0x05 */
	"RAS Server service",		/* 0x06 */
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",			/* 0x10 */
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"Unknown",
	"PDC Domain name",		/* 0x1b */
	"BDC Domain name",		/* 0x1c */
	"Master Browser backup",	/* 0x1d */
	"Browser Election Service",	/* 0x1e */
	"Net DDE Service",		/* 0x1f */
	"Server service",		/* 0x20 */
	"RAS client service",		/* 0x21 */
	"Unknown",	/* need 'Unknown' as last entry (for limiting stuff) */
};

static int nb_name_type_max = (sizeof name_type_str / sizeof name_type_str[0]) - 1;

/* the strings for the command types  */

char *CommandName[] = {
		"Add Group Query",	/* 0x00 */
		"Add Name Query",	/* 0x01 */
		"Unknown",
		"Unknown",
		"Unknown",
		"Unknown",
		"Unknown",
		"Unknown",
		"Datagram",		/* 0x08 */
		"Unknown",
		"Name Query",		/* 0x0A */
		"Unknown",
		"Unknown",
		"Unknown",
		"Name Recognized",	/* 0x0E */
		"Unknown",
		"Unknown",
		"Unknown",
		"Unknown",
		"Unknown",
		"Data Ack",		/* 0x14 */
		"Unknown",
		"Data Only Last",	/* 0x16 */
		"Session Confirm",	/* 0x17	*/
		"Unknown",
		"Session Initialize",	/* 0x19	*/
		"Unknown",
		"Unknown",
		"Unknown",
		"Unknown",
		"Unknown",
		"Session Alive",	/* 0x1f */
	};

void capture_netbios(const u_char *pd, int offset, guint32 cap_len,
	packet_counts *ld)
{
	ld->netbios++;
}


static guint get_netbios_name(const u_char *data_ptr, int offset, char *name_ret)

{/*  Extract the name string and name type.  Return the name string in  */
 /* name_ret and return the name_type. */

	int i;
	char  name_type = *(data_ptr + offset + 15);
	const char *name_ptr = data_ptr + offset;

	for( i = 0; i <16; ++i){
		if ( 0x20 == (*name_ret++ = *name_ptr++)) 	/* exit if space */
			break;
	}

	*name_ret = 0;
	return (guint)name_type;
}


void netbios_add_name( char* label, const u_char *pd, int offset,
    int nb_offset, proto_tree *tree)

{/* add a name field display tree. Display the name and station type in sub-tree */
 /* NOTE: offset = offset to start of netbios header 	*/
 /*	  nb_offset = offset inside of netbios header	*/
 
	proto_tree *field_tree;
	proto_item *tf;
	char  name_str[ 17];
	int   name_type;

					/* decode the name field */
	name_type = get_netbios_name( pd, nb_offset, name_str);

	if ( nb_name_type_max < name_type)	/* limit type value */
		name_type = nb_name_type_max;
	
	tf = proto_tree_add_text( tree, offset + nb_offset, 16,
	    	"%s: %s (%s)", label, name_str, name_type_str[name_type]);

	field_tree = proto_item_add_subtree( tf, ETT_NETB_NAME);
	
	proto_tree_add_text( field_tree, offset + nb_offset, 15, "%s",
	    name_str);
	proto_tree_add_text( field_tree, offset + nb_offset + 15, 1,
	    "0x%0x (%s)", name_type, name_type_str[ name_type]);
}


static void netbios_add_flags( const u_char *pd, proto_tree *tree, int offset)

{

	proto_tree *field_tree;
	proto_item *tf;
	guint flags = *(pd + offset);
					/* decode the flag field */


	tf = proto_tree_add_text( tree, offset, 1,
			"Flags: 0x%02x", flags);
	field_tree = proto_item_add_subtree(tf, ETT_NETB_FLAGS);

	proto_tree_add_text( field_tree, offset, 1, "%s%s",
		decode_boolean_bitfield(flags, 0x80,
			8, "No", ""), " NO.ACK indicator");

	proto_tree_add_text(field_tree, offset, 1,
		 ".... %s. = Largest Frame Size = %d", 
		bit_field_str[(flags & 0x0e) >> 1], ((flags & 0x0e) >> 1));

	proto_tree_add_text(field_tree, offset, 1, "%s",
		decode_boolean_bitfield( flags, 0x01,
			8, "Version 2.0 or higher", "Pre version 2.0"));
}


static void netbios_add_ses_confirm_flags( const u_char *pd, proto_tree *tree,
	int offset)

{
	proto_tree *field_tree;
	proto_item *tf;
	guint flags = *(pd + offset);
					/* decode the flag field */


	tf = proto_tree_add_text( tree, offset, 1,
			"Flags: 0x%02x", flags);
	field_tree = proto_item_add_subtree( tf, ETT_NETB_FLAGS);

	proto_tree_add_text(field_tree, offset, 1, "%s%s",
			decode_boolean_bitfield(flags, 0x80,
				8, "No", ""), " NO.ACK indicator");

	proto_tree_add_text(field_tree, offset, 1, "%s",
			decode_boolean_bitfield(flags, 0x01,
				8, "Pre version 2.0", "Version 2.0 or higher"));
}


static void netbios_data_only_flags( const u_char *pd, proto_tree *tree,
    int offset)

{
	proto_tree *field_tree;
	proto_item *tf;
	guint flags = *(pd + offset);
					/* decode the flag field for data_only packet*/


	tf = proto_tree_add_text( tree, offset, 1,
			"Flags: 0x%02x", flags);
	field_tree = proto_item_add_subtree(tf, ETT_NETB_FLAGS);

	proto_tree_add_text(field_tree, offset, 1, "%s%s",
			decode_boolean_bitfield(flags, 0x08,
				8, "", "No "), "Acknowledge_Included");
	proto_tree_add_text(field_tree, offset, 1, "%s%s",
			decode_boolean_bitfield(flags, 0x04,
				8, "", "No "), "Ack_with_data_allowed");

	proto_tree_add_text(field_tree, offset, 1, "%s%s",
			decode_boolean_bitfield(flags, 0x02,
				8, "", "No "), "NO.ACK indicator");
}


/************************************************************************/
/*									*/
/*  The routines to display the netbios field values in the tree	*/
/*									*/
/************************************************************************/


static void nb_xmit_corrl(const u_char *data_ptr, int offset, proto_tree *tree)

{/* display the transmit correlator */

	proto_tree_add_text( tree, offset + NB_XMIT_CORL, 2,
  	    "Transmit Correlator: 0x%04x", pletohs( data_ptr + NB_XMIT_CORL));
}


static void nb_resp_corrl(const u_char *data_ptr, int offset, proto_tree *tree)

{/* display the response correlator */

	proto_tree_add_text( tree, offset + NB_RESP_CORL, 2,
  	    "Response Correlator: 0x%04x", pletohs( data_ptr + NB_RESP_CORL));
}


static void nb_call_name_type(const u_char *data_ptr, int offset,
    proto_tree *tree)

{/* display the call name type */

	int name_type_value = MIN(*(data_ptr + NB_CALL_NAME_TYPE),
		nb_name_type_max);
	
	proto_tree_add_text( tree, offset + NB_CALL_NAME_TYPE, 1,
  	    "Caller's Name Type.: 0x%02x (%s)",
  	    *(data_ptr + NB_CALL_NAME_TYPE),
  	    name_type_str[ name_type_value]);
}


static void nb_local_session(const u_char *data_ptr, int offset,
    proto_tree *tree)

{/* add the local session to tree */
			
	proto_tree_add_text( tree, offset +NB_LOCAL_SES, 1,
	    "Local Session No.: 0x%02d", *(data_ptr + NB_LOCAL_SES));
}


static void nb_remote_session(const u_char *data_ptr, int offset,
    proto_tree *tree)

{/* add the remote session to tree */
			
	proto_tree_add_text( tree, offset +NB_RMT_SES, 1,
	    "Remote Session No.: 0x%02d", *(data_ptr + NB_RMT_SES));
}


static void nb_data1( char *label, const u_char *data_ptr, int offset,
    proto_tree *tree)

{/* add the DATA1 to tree with format string = label */

	proto_tree_add_text( tree, offset + NB_DATA1, 1, label,
	    *(data_ptr + NB_DATA1));
}


static void nb_data2( char *label, int len, const u_char *data_ptr, int offset,
    proto_tree *tree)

{/* add the DATA2 to tree with format string = label and length of len */

	int value = (len == 1 ? *(data_ptr + NB_DATA2)
	   		: pletohs( data_ptr + NB_DATA2));
	
	proto_tree_add_text( tree, offset +NB_DATA2, len, label, value);
}

/************************************************************************/
/*									*/
/*  The routines called by the top level to handle individual commands  */
/*									*/
/************************************************************************/

static void  dissect_netb_unknown(const u_char *data_ptr, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle any unknow commands, do nothing */

//$$	dissect_data( data_ptr, offset + NB_COMMAND + 1, fd, tree);
}


static void  dissect_netb_add_group(const u_char *data_ptr, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the ADD GROUP command */

	nb_resp_corrl( data_ptr, offset, tree); 

	netbios_add_name( "Group to add", data_ptr, 
			    offset, NB_SENDER_NAME, tree);
}


static void  dissect_netb_add_name(const u_char *data_ptr, int offset, 
    frame_data *fd, proto_tree *tree)

{/* Handle the ADD NAME command */

	nb_resp_corrl( data_ptr, offset, tree); 

	netbios_add_name( "Name to add", data_ptr, 
			    offset, NB_SENDER_NAME, tree);
}


static void  dissect_netb_name_query(const u_char *data_ptr, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the NAME QUERY command */

	nb_data2( "Local Session No.: 0x%02x", 1, data_ptr, offset, tree); 
	nb_call_name_type( data_ptr, offset, tree); 
	netbios_add_name( "Query Name", data_ptr, offset, NB_RECVER_NAME, tree);
	netbios_add_name( "Sender's Name", data_ptr, offset, NB_SENDER_NAME,
	    tree);
}


static void  dissect_netb_name_resp(const u_char *data_ptr, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the NAME RESPONSE command */

	nb_data2( "Local Session No.: 0x%02x", 1, data_ptr, offset, tree); 

	nb_call_name_type( data_ptr, offset, tree); 
	nb_xmit_corrl( data_ptr, offset, tree); 
	nb_resp_corrl( data_ptr, offset, tree);
	netbios_add_name( "Receiver's Name", data_ptr, offset, NB_RECVER_NAME,
	    tree);
	netbios_add_name( "Sender's Name", data_ptr, offset, NB_SENDER_NAME,
	    tree);
}

static void  dissect_netb_session_init(const u_char *data_ptr, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the SESSION INITIATE command */

	netbios_add_flags( data_ptr, tree, offset + NB_FLAGS);

	nb_data2( "Max data recv size: %d", 2, data_ptr, offset, tree); 
	nb_resp_corrl( data_ptr, offset, tree);
	nb_xmit_corrl( data_ptr, offset, tree); 
	nb_remote_session( data_ptr, offset, tree); 
	nb_local_session( data_ptr, offset, tree); 
}


static void  dissect_netb_session_confirm(const u_char *data_ptr, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the SESSION CONFIRM command */

	netbios_add_ses_confirm_flags( data_ptr, tree, offset + NB_FLAGS);

	nb_data2( "Max data recv size: %d", 2, data_ptr, offset, tree); 
	nb_resp_corrl( data_ptr, offset, tree);
	nb_xmit_corrl( data_ptr, offset, tree); 
	nb_remote_session( data_ptr, offset, tree); 
	nb_local_session( data_ptr, offset, tree); 
}


static void  dissect_netb_data_only_last(const u_char *data_ptr, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the DATA ONLY LAST command */

	netbios_data_only_flags( data_ptr, tree, offset + NB_FLAGS);

	nb_data2( "Re-sync indicator: %d", 2, data_ptr, offset, tree); 
	nb_resp_corrl( data_ptr, offset, tree);
	nb_remote_session( data_ptr, offset, tree); 
	nb_local_session( data_ptr, offset, tree); 

}


static void  dissect_netb_datagram(const u_char *data_ptr, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the DATAGRAM command */

	nb_data1( "Data1: 0x%02x", data_ptr, offset, tree); 
	nb_data2( "Data2: 0x%04x", 2, data_ptr, offset, tree); 
	nb_xmit_corrl( data_ptr, offset, tree);
	nb_resp_corrl( data_ptr, offset, tree);
	netbios_add_name( "Receiver's Name", data_ptr, offset, NB_RECVER_NAME,
	    tree);
	netbios_add_name( "Sender's Name", data_ptr, offset, NB_SENDER_NAME,
	    tree);

}

static void  dissect_netb_data_ack(const u_char *data_ptr, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the DATA ACK command */

	netbios_data_only_flags( data_ptr, tree, offset + NB_FLAGS);


	nb_xmit_corrl( data_ptr, offset, tree);
	nb_remote_session( data_ptr, offset, tree); 
	nb_local_session( data_ptr, offset, tree); 

}


/************************************************************************/
/*									*/
/*  The table routines called by the top level to handle commands  	*/
/*									*/
/************************************************************************/


void (*dissect_netb[])(const u_char *, int, frame_data *, proto_tree *) = {

  dissect_netb_add_group,      	/* add_group 	0x00 */
  dissect_netb_add_name,      	/* add_name	0x01 */
  dissect_netb_unknown,		/* unknown 	0x02 */
  dissect_netb_unknown,		/* unknown 	0x03 */
  dissect_netb_unknown,		/* unknown 	0x04 */
  dissect_netb_unknown,		/* unknown 	0x05 */
  dissect_netb_unknown,		/* unknown 	0x06 */
  dissect_netb_unknown,		/* unknown 	0x07 */
  dissect_netb_datagram,	/* Datagram	0x08 */
  dissect_netb_unknown,		/* unknown 	0x09 */
  dissect_netb_name_query,	/* Name Query   0x0A */
  dissect_netb_unknown,		/* unknown 	0x0B */
  dissect_netb_unknown,		/* unknown 	0x0C */
  dissect_netb_unknown,		/* unknown 	0x0D */
  dissect_netb_name_resp,	/* Name Resp    0x0E */
  dissect_netb_unknown,		/* unknown 	0x0F */
  dissect_netb_unknown,		/* unknown 	0x10 */
  dissect_netb_unknown,		/* unknown 	0x11 */
  dissect_netb_unknown,		/* unknown 	0x12 */
  dissect_netb_unknown,		/* unknown 	0x13 */
  dissect_netb_data_ack,	/* Data Ack 	0x14 */
  dissect_netb_unknown,		/* unknown 	0x15 */
  dissect_netb_data_only_last,	/* Data Only Last 0x16 */
  dissect_netb_session_confirm,	/* Session Confirm 0x17	*/
  dissect_netb_unknown,		/* unknown 	0x18 */
  dissect_netb_session_init,	/* Session Initialize 0x19	*/
  dissect_netb_unknown,		/* unknown 	0x1A */
  dissect_netb_unknown,		/* unknown 	0x1B */
  dissect_netb_unknown,		/* unknown 	0x1C */
  dissect_netb_unknown,		/* unknown 	0x1D */
  dissect_netb_unknown,		/* unknown 	0x1E */

  dissect_netb_unknown,		/* Session Alive	0x1f (nothing to do) */
};


void dissect_netbios(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree)

{
	const u_char		*nb_data_ptr;
	proto_tree		*netb_tree;
	proto_item		*ti;
	guint16			hdr_len, command;
	char 			name[17];

	nb_data_ptr = &pd[offset];

/* Find NetBIOS marker EFFF, this is done because I have seen an extra LLC */
/* byte on our network. This only checks for one extra LLC byte. */

	if (( *(nb_data_ptr + 2) != 0xff) || ( *(nb_data_ptr + 3) != 0xef)){

		++nb_data_ptr;		/** marker not found shift one byte */
		++offset;
		if (( *(nb_data_ptr + 2) != 0xff)
		    || ( *(nb_data_ptr + 3) != 0xef)){
			if (check_col(fd, COL_PROTOCOL))
				col_add_str(fd, COL_PROTOCOL, "NetBIOS");	
	
			if (check_col(fd, COL_INFO)) 	/* print bad packet */
				col_add_str(fd, COL_INFO, "Bad packet");

			if (tree) {
				ti = proto_tree_add_item(tree, proto_netbios,
					offset, END_OF_FRAME, NULL);
				netb_tree = proto_item_add_subtree(ti, ETT_NETB);
				
				proto_tree_add_text( netb_tree, offset,
				    END_OF_FRAME, "Data (%u bytes)", 
				    END_OF_FRAME); 
			}	
			return;
		}
	}
	
	/* To do: check for runts, errs, etc. */

	hdr_len = pletohs( nb_data_ptr + NB_LENGTH);
	command = *(nb_data_ptr + NB_COMMAND);

	
 	if ( command == NB_NAME_QUERY ) {
		get_netbios_name( pd, offset + 12, name);
	}		

 	if ( command == NB_NAME_RESP ){
		get_netbios_name( pd, offset + 28, name);
	}		
	

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NetBIOS");

	if (check_col(fd, COL_INFO)) {			/* print command name */
		if ( command == NB_NAME_QUERY)
			col_add_fstr(fd, COL_INFO, "%s for %s",
			    CommandName[ command], name);

		else if ( command == NB_NAME_RESP)
			col_add_fstr(fd, COL_INFO, "%s - %s",
			    CommandName[ command], name);

		else
			col_add_fstr(fd, COL_INFO, "%s", CommandName[ command]);
	}


	if (tree) {
		ti = proto_tree_add_item(tree, proto_netbios, offset, END_OF_FRAME, NULL);

		netb_tree = proto_item_add_subtree(ti, ETT_NETB);

		proto_tree_add_text(netb_tree, offset, 2,
				"Header Length: %d", hdr_len);

		proto_tree_add_text(netb_tree, offset + 2, 2,
				"Delimiter: EFFF (NetBIOS)");

		proto_tree_add_text(netb_tree, offset + NB_COMMAND, 1,
  		    "Command: 0x%02x (%s)", command, CommandName[ command]);

						/* if command in table range */
		if ( command < sizeof( dissect_netb)/ sizeof(void *))

						/* branch to handle commands */
			(dissect_netb[ command])( nb_data_ptr, offset, fd,
				netb_tree);		
	}

							/* Test for SMB data */
	if ( (END_OF_FRAME) > ( hdr_len + 4)){		/* if enough data */

		nb_data_ptr += hdr_len;			/* move past header */

		if (( *nb_data_ptr == 0xff) &&		/* if SMB marker */
		    ( *(nb_data_ptr + 1) == 'S') &&
		    ( *(nb_data_ptr + 2) == 'M') &&
		    ( *(nb_data_ptr + 3) == 'B'))
							/* decode SMB */
			dissect_smb(pd, offset + hdr_len, fd, tree, 
				END_OF_FRAME - hdr_len);
	}

/*$$$$ somewhere around here need to check for frame padding */

}


void proto_register_netbios(void)
{

        proto_netbios = proto_register_protocol("NetBIOS", "netbios");
}
