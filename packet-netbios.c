/* packet-netbios.c
 * Routines for NetBIOS protocol packet disassembly
 * Jeff Foster <foste@woodward.com>            
 * Copyright 1999 Jeffrey C. Foster
 * 
 * derived from the packet-nbns.c
 *
 * $Id: packet-netbios.c,v 1.15 2000/02/15 21:02:40 gram Exp $
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
#include "packet-netbios.h"
#include "packet-smb.h"

/* Netbios command numbers */
#define NB_ADD_GROUP		0x00
#define NB_ADD_NAME		0x01
#define NB_NAME_IN_CONFLICT	0x02
#define NB_STATUS_QUERY		0x03
#define NB_TERMINATE_TRACE_R	0x07
#define NB_DATAGRAM		0x08
#define NB_DATAGRAM_BCAST	0x09
#define NB_NAME_QUERY		0x0a
#define NB_ADD_NAME_RESP	0x0d
#define NB_NAME_RESP 		0x0e
#define NB_STATUS_RESP 		0x0f
#define NB_TERMINATE_TRACE_LR	0x13
#define NB_DATA_ACK		0x14
#define NB_DATA_FIRST_MIDDLE	0x15
#define NB_DATA_ONLY_LAST	0x16
#define NB_SESSION_CONFIRM	0x17
#define NB_SESSION_END		0x18
#define NB_SESSION_INIT		0x19
#define NB_NO_RECEIVE		0x1a
#define NB_RECEIVE_OUTSTANDING	0x1b
#define NB_RECEIVE_CONTINUE	0x1c
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

static gint ett_netb = -1;
static gint ett_netb_name = -1;
static gint ett_netb_flags = -1;
static gint ett_netb_status = -1;

/* The strings for the station type, used by get_netbios_name function;
   many of them came from the file "NetBIOS.txt" in the Zip archive at

	http://www.net3group.com/ftp/browser.zip
 */

static const value_string name_type_vals[] = {
	{0x00,	"Workstation/Redirector"},
	{0x01,	"Browser"},
	{0x02,	"Workstation/Redirector"}, 
		/* not sure what 0x02 is, I'm seeing alot of them however */
		/* i'm seeing them with workstation/redirection host 
			announcements */
	{0x03,	"Messenger service/Main name"},
	{0x05,	"Forwarded name"},
	{0x06,	"RAS Server service"},
	{0x1b,	"PDC Domain name"},
	{0x1c,	"BDC Domain name"},
	{0x1d,	"Master Browser backup"},
	{0x1e,	"Browser Election Service"},
	{0x1f,	"Net DDE Service"},
	{0x20,	"Server service"},
	{0x21,	"RAS client service"},
	{0x22,	"Exchange Interchange (MSMail Connector)"},
	{0x23,	"Exchange Store"},
	{0x24,	"Exchange Directory"},
	{0x2b,	"Lotus Notes Server service"},
	{0x30,	"Modem sharing server service"},
	{0x31,	"Modem sharing client service"},
	{0x43,	"SMS Clients Remote Control"},
	{0x44,	"SMS Administrators Remote Control Tool"},
	{0x45,	"SMS Clients Remote Chat"},
	{0x46,	"SMS Clients Remote Transfer"},
	{0x4c,	"DEC Pathworks TCP/IP Service on Windows NT"},
	{0x52,	"DEC Pathworks TCP/IP Service on Windows NT"},
	{0x6a,	"Microsoft Exchange IMC"},
	{0x87,	"Microsoft Exchange MTA"},
	{0xbe,	"Network Monitor Agent"},
	{0xbf,	"Network Monitor Analyzer"},
	{0x00,	NULL}
};

/* See
   
	http://www.s390.ibm.com/bookmgr-cgi/bookmgr.cmd/BOOKS/BK8P7001/CCONTENTS

   and

	http://ourworld.compuserve.com/homepages/TimothyDEvans/contents.htm

   for information about the NetBIOS Frame Protocol (which is what this
   module dissects). */

/* the strings for the command types  */

static char *CommandName[] = {
	"Add Group Name Query",	/* 0x00 */
	"Add Name Query",	/* 0x01 */
	"Name In Conflict",	/* 0x02 */
	"Status Query",		/* 0x03 */
	"Unknown",
	"Unknown",
	"Unknown",
	"Terminate Trace",	/* 0x07 */
	"Datagram",		/* 0x08 */
	"Broadcast Datagram",	/* 0x09 */
	"Name Query",		/* 0x0A */
	"Unknown",
	"Unknown",
	"Add Name Response",	/* 0x0D */
	"Name Recognized",	/* 0x0E */
	"Status Response",	/* 0x0F */
	"Unknown",
	"Unknown",
	"Unknown",
	"Terminate Trace",	/* 0x13 */
	"Data Ack",		/* 0x14 */
	"Data First Middle",	/* 0x15 */
	"Data Only Last",	/* 0x16 */
	"Session Confirm",	/* 0x17	*/
	"Session End",		/* 0x18 */
	"Session Initialize",	/* 0x19	*/
	"No Receive",		/* 0x1a */
	"Receive Outstanding",	/* 0x1b */
	"Receive Continue",	/* 0x1c */
	"Unknown",
	"Unknown",
	"Session Alive",	/* 0x1f */
};

void capture_netbios(const u_char *pd, int offset, packet_counts *ld)
{
	ld->netbios++;
}


int
process_netbios_name(const u_char *name_ptr, char *name_ret)
{
	int i;
	int name_type = *(name_ptr + NETBIOS_NAME_LEN - 1);
	u_char name_char;
	static const char hex_digits[16] = "0123456789abcdef";

	for (i = 0; i < NETBIOS_NAME_LEN - 1; i++) {
		name_char = *name_ptr++;
		if (name_char >= ' ' && name_char <= '~')
			*name_ret++ = name_char;
		else {
			/* It's not printable; show it as <XX>, where
			   XX is the value in hex. */
			*name_ret++ = '<';
			*name_ret++ = hex_digits[(name_char >> 4)];
			*name_ret++ = hex_digits[(name_char & 0x0F)];
			*name_ret++ = '>';
		}
	}
	*name_ret = '\0';
	return name_type;
}

int get_netbios_name(const u_char *pd, int offset, char *name_ret)

{/*  Extract the name string and name type.  Return the name string in  */
 /* name_ret and return the name_type. */
	if (!BYTES_ARE_IN_FRAME(offset, NETBIOS_NAME_LEN)) {
		/*
		 * Name goes past end of captured data in packet.
		 */
		return -1;
	}
	return process_netbios_name(&pd[offset], name_ret);
}

/*
 * Get a string describing the type of a NetBIOS name.
 */
char *
netbios_name_type_descr(int name_type)
{
	return val_to_str(name_type, name_type_vals, "Unknown");
}

gboolean netbios_add_name(char* label, const u_char *pd, int offset,
    proto_tree *tree)

{/* add a name field display tree. Display the name and station type in sub-tree */
 
	proto_tree *field_tree;
	proto_item *tf;
	char  name_str[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int   name_type;
	char  *name_type_str;

					/* decode the name field */
	name_type = get_netbios_name(pd, offset, name_str);
	if (name_type < 0) {
		/*
		 * Name goes past end of captured data in packet.
		 */
		return FALSE;
	}

	name_type_str = netbios_name_type_descr(name_type);
	tf = proto_tree_add_text( tree, offset, NETBIOS_NAME_LEN,
	    	"%s: %s<%02x> (%s)", label, name_str, name_type, name_type_str);

	field_tree = proto_item_add_subtree( tf, ett_netb_name);
	
	proto_tree_add_text( field_tree, offset, 15, "%s",
	    name_str);
	proto_tree_add_text( field_tree, offset + 15, 1,
	    "0x%02x (%s)", name_type, name_type_str);
	return TRUE;
}


static void netbios_data_first_middle_flags(const u_char *pd, proto_tree *tree,
    int offset)

{
	proto_tree *field_tree;
	proto_item *tf;
	guint flags = pd[offset];
		/* decode the flag field for Data First Middle packet*/

	tf = proto_tree_add_text(tree, offset, 1,
			"Flags: 0x%02x", flags);
	field_tree = proto_item_add_subtree(tf, ett_netb_flags);

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_boolean_bitfield(flags, 0x08, 8,
		"Acknowledge_included", "No Acknowledge_included"));

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_boolean_bitfield(flags, 0x02, 8,
		"No acknowledgement expected", "Acknowledgement expected"));

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_boolean_bitfield(flags, 0x01, 8,
		"RECEIVE_CONTINUE requested", "RECEIVE_CONTINUE not requested"));
}


static void netbios_data_only_flags(const u_char *pd, proto_tree *tree,
    int offset)
{
	proto_tree *field_tree;
	proto_item *tf;
	guint flags = pd[offset];
		/* decode the flag field for Data Only Last packet*/

	tf = proto_tree_add_text(tree, offset, 1,
			"Flags: 0x%02x", flags);
	field_tree = proto_item_add_subtree(tf, ett_netb_flags);

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_boolean_bitfield(flags, 0x08, 8,
		"ACKNOWLEDGE_INCLUDED", "No ACKNOWLEDGE_INCLUDED"));

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_boolean_bitfield(flags, 0x04, 8,
		"ACKNOWLEDGE_WITH_DATA_ALLOWED", "No ACKNOWLEDGE_WITH_DATA_ALLOWED"));

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_boolean_bitfield(flags, 0x02, 8,
		"No acknowledgement expected", "Acknowledgement expected"));
}


static void netbios_add_ses_confirm_flags(const u_char *pd, proto_tree *tree,
	int offset)
{
	proto_tree *field_tree;
	proto_item *tf;
	guint flags = pd[offset];
		/* decode the flag field for Session Confirm packet */

	tf = proto_tree_add_text(tree, offset, 1,
			"Flags: 0x%02x", flags);
	field_tree = proto_item_add_subtree( tf, ett_netb_flags);

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_boolean_bitfield(flags, 0x80, 8,
		"Can handle SEND.NO.ACK", "Can't handle SEND.NO.ACK"));

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_boolean_bitfield(flags, 0x01, 8,
		"NetBIOS 2.00 or higher", "NetBIOS 1.xx"));
}


static void netbios_add_session_init_flags(const u_char *pd, proto_tree *tree,
	int offset)
{
	proto_tree *field_tree;
	proto_item *tf;
	guint flags = pd[offset];
		/* decode the flag field for Session Init packet */

	tf = proto_tree_add_text(tree, offset, 1,
			"Flags: 0x%02x", flags);
	field_tree = proto_item_add_subtree(tf, ett_netb_flags);

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_boolean_bitfield(flags, 0x80, 8,
		"Can handle SEND.NO.ACK", "Can't handle SEND.NO.ACK"));

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_numeric_bitfield(flags, 0x0E, 8,
		"Largest frame value = %u"));

	proto_tree_add_text(field_tree, offset, 1, "%s",
	    decode_boolean_bitfield(flags, 0x01, 8,
		"NetBIOS 2.00 or higher", "NetBIOS 1.xx"));
}


static void netbios_no_receive_flags(const u_char *pd, proto_tree *tree,
    int offset)

{
	proto_tree *field_tree;
	proto_item *tf;
	guint flags = pd[offset];
		/* decode the flag field for No Receive packet*/

	tf = proto_tree_add_text(tree, offset, 1,
			"Flags: 0x%02x", flags);

	if (flags & 0x02) {
		field_tree = proto_item_add_subtree(tf, ett_netb_flags);
		proto_tree_add_text(field_tree, offset, 1, "%s",
		    decode_boolean_bitfield(flags, 0x02, 8,
			"SEND.NO.ACK data not received", NULL));
	}
}


/************************************************************************/
/*									*/
/*  The routines to display the netbios field values in the tree	*/
/*									*/
/************************************************************************/


static void nb_xmit_corrl(const u_char *pd, int offset, proto_tree *tree)

{/* display the transmit correlator */

	proto_tree_add_text( tree, offset + NB_XMIT_CORL, 2,
  	    "Transmit Correlator: 0x%04x", pletohs(&pd[offset + NB_XMIT_CORL]));
}


static void nb_resp_corrl(const u_char *pd, int offset, proto_tree *tree)

{/* display the response correlator */

	proto_tree_add_text( tree, offset + NB_RESP_CORL, 2,
  	    "Response Correlator: 0x%04x", pletohs(&pd[offset + NB_RESP_CORL]));
}


static void nb_call_name_type(const u_char *pd, int offset,
    proto_tree *tree)

{/* display the call name type */

	int name_type_value = pd[offset + NB_CALL_NAME_TYPE];
	
	switch (name_type_value) {

	case 0x00:
		proto_tree_add_text( tree, offset + NB_CALL_NAME_TYPE, 1,
		    "Caller's Name Type: Unique name");
		break;

	case 0x01:
		proto_tree_add_text( tree, offset + NB_CALL_NAME_TYPE, 1,
		    "Caller's Name Type: Group name");
		break;

	default:
		proto_tree_add_text( tree, offset + NB_CALL_NAME_TYPE, 1,
		    "Caller's Name Type: 0x%02x (should be 0 or 1)",
		    name_type_value);
		break;
	}
}


static void nb_local_session(const u_char *pd, int offset,
    proto_tree *tree)

{/* add the local session to tree */
			
	proto_tree_add_text(tree, offset + NB_LOCAL_SES, 1,
	    "Local Session No.: 0x%02x", pd[offset + NB_LOCAL_SES]);
}


static void nb_remote_session(const u_char *pd, int offset,
    proto_tree *tree)

{/* add the remote session to tree */
			
	proto_tree_add_text(tree, offset + NB_RMT_SES, 1,
	    "Remote Session No.: 0x%02x", pd[offset + NB_RMT_SES]);
}


static void nb_data2(char *label, int len, const u_char *pd, int offset,
    proto_tree *tree)

{/* add the DATA2 to tree with format string = label and length of len */

	int value = (len == 1 ? pd[offset + NB_DATA2]
	   		: pletohs(&pd[offset + NB_DATA2]));
	
	proto_tree_add_text(tree, offset + NB_DATA2, len, label, value);
}

static void nb_resync_indicator(const u_char *pd, int offset,
    proto_tree *tree)
{
	guint16 resync_indicator = pletohs(&pd[offset + NB_DATA2]);

	switch (resync_indicator) {

	case 0x0000:
		proto_tree_add_text(tree, offset + NB_DATA2, 2,
		    "Re-sync indicator: Not first Data First Middle following Receive Outstanding");
		break;

	case 0x0001:
		proto_tree_add_text(tree, offset + NB_DATA2, 2,
		    "Re-sync indicator: First Data First Middle following Receive Outstanding");
		break;

	default:
		proto_tree_add_text(tree, offset + NB_DATA2, 2,
		    "Re-sync indicator: 0x%04x", resync_indicator);
		break;
	}
}

/************************************************************************/
/*									*/
/*  The routines called by the top level to handle individual commands  */
/*									*/
/************************************************************************/

static void  dissect_netb_unknown(const u_char *data_ptr, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle any unknow commands, do nothing */

/*	dissect_data( data_ptr, offset + NB_COMMAND + 1, fd, tree); */
}


static void  dissect_netb_add_group_name(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the ADD GROUP NAME QUERY command */

	nb_resp_corrl(pd, offset, tree); 

	netbios_add_name("Group name to add", pd, offset + NB_SENDER_NAME,
	    tree);
}


static void  dissect_netb_add_name(const u_char *pd, int offset, 
    frame_data *fd, proto_tree *tree)

{/* Handle the ADD NAME QUERY command */

	nb_resp_corrl(pd, offset, tree); 

	netbios_add_name("Name to add", pd, offset + NB_SENDER_NAME, tree);
}


static void  dissect_netb_name_in_conflict(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the NAME IN CONFLICT command */

	if (!netbios_add_name("Name In Conflict", pd, offset + NB_RECVER_NAME,
	    tree))
		return;
	netbios_add_name("Sender's Name", pd, offset + NB_SENDER_NAME,
	    tree);
}


static void  dissect_netb_status_query(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the STATUS QUERY command */
	guint8 status_request = pd[offset + NB_DATA1];

	switch (status_request) {

	case 0:
		proto_tree_add_text(tree, offset + NB_DATA1, 1,
		    "Status request: NetBIOS 1.x or 2.0");
		break;

	case 1:
		proto_tree_add_text(tree, offset + NB_DATA1, 1,
		    "Status request: NetBIOS 2.1, initial status request");
		break;

	default:
		proto_tree_add_text(tree, offset + NB_DATA1, 1,
		    "Status request: NetBIOS 2.1, %u names received so far",
		    status_request);
		break;
	}
	nb_data2("Length of status buffer: %u", 2, pd, offset, tree);
	nb_resp_corrl(pd, offset, tree); 
	if (!netbios_add_name("Receiver's Name", pd, offset + NB_RECVER_NAME,
	    tree))
		return;
	netbios_add_name("Sender's Name", pd, offset + NB_SENDER_NAME,
	    tree);
}


static u_char zeroes[10];

static void  dissect_netb_datagram(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the DATAGRAM command */

	if (!netbios_add_name("Receiver's Name", pd, offset + NB_RECVER_NAME,
	    tree))
		return;
	/* Weird.  In some datagrams, this is 10 octets of 0, followed
	   by a MAC address.... */
	if (memcmp(&pd[offset + NB_SENDER_NAME], zeroes, 10) == 0) {
		proto_tree_add_text( tree, offset + NB_SENDER_NAME + 10, 6,
		    "Sender's MAC Address: %s",
		    ether_to_str(&pd[offset + NB_SENDER_NAME + 10]));
	} else {
		netbios_add_name("Sender's Name", pd, offset + NB_SENDER_NAME,
		    tree);
	}
}


static void  dissect_netb_datagram_bcast(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the DATAGRAM BROADCAST command */

	/* We assume the same weirdness can happen here.... */
	if (memcmp(&pd[offset + NB_SENDER_NAME], zeroes, 10) == 0) {
		proto_tree_add_text( tree, offset + NB_SENDER_NAME + 10, 6,
		    "Sender's Node Address: %s",
		    ether_to_str(&pd[offset + NB_SENDER_NAME + 10]));
	} else {
		netbios_add_name("Sender's Name", pd, offset + NB_SENDER_NAME,
		    tree);
	}
}


static void  dissect_netb_name_query(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the NAME QUERY command */
	guint8 local_session_number = pd[offset + NB_DATA2];

	if (local_session_number == 0) {
		proto_tree_add_text( tree, offset + NB_DATA2, 1,
		    "Local Session No.: 0 (FIND.NAME request)");
	} else {
		proto_tree_add_text( tree, offset + NB_DATA2, 1,
		    "Local Session No.: 0x%02x", local_session_number);
	}
	nb_call_name_type(pd, offset, tree);
	nb_resp_corrl(pd, offset, tree);
	if (!netbios_add_name("Query Name", pd, offset + NB_RECVER_NAME, tree))
		return;
	if (local_session_number != 0) {
		netbios_add_name("Sender's Name", pd, offset + NB_SENDER_NAME,
		    tree);
	}
}


static void  dissect_netb_add_name_resp(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the ADD NAME RESPONSE command */
	guint8 status = pd[offset + NB_DATA1];
	guint16 name_type = pletohs(&pd[offset + NB_DATA2]);

	switch (status) {

	case 0:
		proto_tree_add_text( tree, offset + NB_DATA1, 1,
		    "Status: Add name not in process");
		break;

	case 1:
		proto_tree_add_text( tree, offset + NB_DATA1, 1,
		    "Status: Add name in process");
		break;

	default:
		proto_tree_add_text( tree, offset + NB_DATA1, 1,
		    "Status: 0x%02x (should be 0 or 1)", status);
		break;
	}

	switch (name_type) {

	case 0:
		proto_tree_add_text( tree, offset + NB_DATA2, 2,
		    "Name type: Unique name");
		break;

	case 1:
		proto_tree_add_text( tree, offset + NB_DATA2, 2,
		    "Name type: Group name");
		break;

	default:
		proto_tree_add_text( tree, offset + NB_DATA2, 2,
		    "Name type: 0x%04x (should be 0 or 1)", name_type);
		break;
	}

	nb_xmit_corrl(pd, offset, tree); 
	if (!netbios_add_name("Name to be added", pd, offset + NB_RECVER_NAME,
	    tree))
		return;
	netbios_add_name("Name to be added", pd, offset + NB_SENDER_NAME,
	    tree);
}


static void  dissect_netb_name_resp(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the NAME RECOGNIZED command */
	guint8 local_session_number = pd[offset + NB_DATA2];

	switch (local_session_number) {

	case 0x00:
		proto_tree_add_text( tree, offset + NB_DATA2, 1,
		    "State of name: No LISTEN pending, or FIND.NAME response");
		break;

	case 0xFF:
		proto_tree_add_text( tree, offset + NB_DATA2, 1,
		    "State of name: LISTEN pending, but insufficient resources to establish session");
		break;

	default:
		proto_tree_add_text( tree, offset + NB_DATA2, 1,
		    "Local Session No.: 0x%02x", local_session_number);
		break;
	}
	nb_call_name_type(pd, offset, tree);
	nb_xmit_corrl(pd, offset, tree);
	if (local_session_number != 0x00 && local_session_number != 0xFF)
		nb_resp_corrl(pd, offset, tree);
	if (!netbios_add_name("Receiver's Name", pd, offset + NB_RECVER_NAME,
	    tree))
		return;
	if (local_session_number != 0x00 && local_session_number != 0xFF) {
		netbios_add_name("Sender's Name", pd, offset + NB_SENDER_NAME,
		    tree);
	}
}


static void  dissect_netb_status_resp(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the STATUS RESPONSE command */
	guint8 status_response = pd[offset + NB_DATA1];
	proto_item *td2;
	proto_tree *data2_tree;
	guint16 data2;

	nb_call_name_type(pd, offset, tree);
	if (status_response == 0) {
		proto_tree_add_text(tree, offset + NB_DATA1, 1,
		    "Status response: NetBIOS 1.x or 2.0");
	} else {
		proto_tree_add_text(tree, offset + NB_DATA1, 1,
		    "Status response: NetBIOS 2.1, %u names sent so far",
		    status_response);
	}
	data2 = pletohs(&pd[offset + NB_DATA2]);
	td2 = proto_tree_add_text(tree, offset + NB_DATA2, 2, "Status: 0x04x",
	    data2);
	data2_tree = proto_item_add_subtree(td2, ett_netb_status);
	if (data2 & 0x8000) {
		proto_tree_add_text(data2_tree, offset, 2, "%s",
		    decode_boolean_bitfield(data2, 0x8000, 8*2,
			"Data length exceeds maximum frame size", NULL));
	}
	if (data2 & 0x4000) {
		proto_tree_add_text(data2_tree, offset, 2, "%s",
		    decode_boolean_bitfield(data2, 0x4000, 8*2,
			"Data length exceeds user's buffer", NULL));
	}
	proto_tree_add_text(data2_tree, offset, 2, "%s",
	    decode_numeric_bitfield(data2, 0x3FFF, 2*8,
			"Status data length = %u"));
	nb_xmit_corrl(pd, offset, tree); 
	if (!netbios_add_name("Receiver's Name", pd, offset + NB_RECVER_NAME,
	    tree))
		return;
	netbios_add_name("Sender's Name", pd, offset + NB_SENDER_NAME,
	    tree);
}


static void  dissect_netb_data_ack(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the DATA ACK command */

	nb_xmit_corrl(pd, offset, tree);
	nb_remote_session(pd, offset, tree);
	nb_local_session(pd, offset, tree);
}


static void  dissect_netb_data_first_middle(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the DATA FIRST MIDDLE command */

	netbios_data_first_middle_flags(pd, tree, offset + NB_FLAGS);

	nb_resync_indicator(pd, offset, tree);
	nb_xmit_corrl(pd, offset, tree);
	nb_resp_corrl(pd, offset, tree);
	nb_remote_session(pd, offset, tree);
	nb_local_session(pd, offset, tree);
}


static void  dissect_netb_data_only_last(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the DATA ONLY LAST command */

	netbios_data_only_flags(pd, tree, offset + NB_FLAGS);

	nb_resync_indicator(pd, offset, tree);
	nb_xmit_corrl(pd, offset, tree);
	nb_resp_corrl(pd, offset, tree);
	nb_remote_session(pd, offset, tree);
	nb_local_session(pd, offset, tree);
}


static void  dissect_netb_session_confirm(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the SESSION CONFIRM command */

	netbios_add_ses_confirm_flags(pd, tree, offset + NB_FLAGS);

	nb_data2("Max data recv size: %u", 2, pd, offset, tree);
	nb_xmit_corrl(pd, offset, tree);
	nb_resp_corrl(pd, offset, tree);
	nb_remote_session(pd, offset, tree);
	nb_local_session(pd, offset, tree);
}


static void  dissect_netb_session_end(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the SESSION END command */
	guint16 termination_indicator = pletohs(&pd[offset + NB_DATA2]);

	switch (termination_indicator) {

	case 0x0000:
		proto_tree_add_text( tree, offset + NB_DATA2, 2,
		    "Termination indicator: Normal session end");
		break;

	case 0x0001:
		proto_tree_add_text( tree, offset + NB_DATA2, 2,
		    "Termination indicator: Abormal session end");
		break;

	default:
		proto_tree_add_text( tree, offset + NB_DATA2, 2,
		    "Termination indicator: 0x%04x (should be 0x0000 or 0x0001)",
		    termination_indicator);
		break;
	}

	nb_remote_session(pd, offset, tree);
	nb_local_session(pd, offset, tree);
}


static void  dissect_netb_session_init(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the SESSION INITIALIZE command */

	netbios_add_session_init_flags(pd, tree, offset + NB_FLAGS);

	nb_data2("Max data recv size: %u", 2, pd, offset, tree);
	nb_resp_corrl(pd, offset, tree);
	nb_xmit_corrl(pd, offset, tree);
	nb_remote_session(pd, offset, tree);
	nb_local_session(pd, offset, tree);
}


static void  dissect_netb_no_receive(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the NO RECEIVE command */

	netbios_no_receive_flags(pd, tree, offset + NB_FLAGS);

	nb_data2("Number of data bytes accepted: %u", 2, pd, offset, tree);
	nb_remote_session(pd, offset, tree);
	nb_local_session(pd, offset, tree);
}


static void  dissect_netb_receive_outstanding(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the RECEIVE OUTSTANDING command */

	nb_data2("Number of data bytes accepted: %u", 2, pd, offset, tree);
	nb_remote_session(pd, offset, tree);
	nb_local_session(pd, offset, tree);
}


static void  dissect_netb_receive_continue(const u_char *pd, int offset,
    frame_data *fd, proto_tree *tree)

{/* Handle the RECEIVE CONTINUE command */

	nb_xmit_corrl(pd, offset, tree);
	nb_remote_session(pd, offset, tree);
	nb_local_session(pd, offset, tree);
}


/************************************************************************/
/*									*/
/*  The table routines called by the top level to handle commands  	*/
/*									*/
/************************************************************************/


void (*dissect_netb[])(const u_char *, int, frame_data *, proto_tree *) = {

  dissect_netb_add_group_name,	/* Add Group Name	0x00 */
  dissect_netb_add_name,      	/* Add Name		0x01 */
  dissect_netb_name_in_conflict,/* Name In Conflict 	0x02 */
  dissect_netb_status_query,	/* Status Query	 	0x03 */
  dissect_netb_unknown,		/* unknown 		0x04 */
  dissect_netb_unknown,		/* unknown	 	0x05 */
  dissect_netb_unknown,		/* unknown 		0x06 */
  dissect_netb_unknown,		/* Terminate Trace 	0x07 */
  dissect_netb_datagram,	/* Datagram		0x08 */
  dissect_netb_datagram_bcast,	/* Datagram Broadcast 	0x09 */
  dissect_netb_name_query,	/* Name Query   	0x0A */
  dissect_netb_unknown,		/* unknown	 	0x0B */
  dissect_netb_unknown,		/* unknown 		0x0C */
  dissect_netb_add_name_resp,	/* Add Name Response 	0x0D */
  dissect_netb_name_resp,	/* Name Recognized    	0x0E */
  dissect_netb_status_resp,	/* Status Response	0x0F */
  dissect_netb_unknown,		/* unknown	 	0x10 */
  dissect_netb_unknown,		/* unknown 		0x11 */
  dissect_netb_unknown,		/* unknown		0x12 */
  dissect_netb_unknown,		/* Terminate Trace	0x13 */
  dissect_netb_data_ack,	/* Data Ack 		0x14 */
  dissect_netb_data_first_middle,/* Data First Middle	0x15 */
  dissect_netb_data_only_last,	/* Data Only Last	0x16 */
  dissect_netb_session_confirm,	/* Session Confirm 	0x17 */
  dissect_netb_session_end,	/* Session End 		0x18 */
  dissect_netb_session_init,	/* Session Initialize	0x19 */
  dissect_netb_no_receive,	/* No Receive 		0x1A */
  dissect_netb_receive_outstanding,/* Receive Outstanding 0x1B */
  dissect_netb_receive_continue,/* Receive Continue	0x1C */
  dissect_netb_unknown,		/* unknown 		0x1D */
  dissect_netb_unknown,		/* unknown 		0x1E */

  dissect_netb_unknown,		/* Session Alive	0x1f (nothing to do) */
};


void dissect_netbios(const u_char *pd, int offset, frame_data *fd,
    proto_tree *tree)

{
	proto_tree		*netb_tree;
	proto_item		*ti;
	guint16			hdr_len, command;
	char 			name[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int			name_type;

/* Find NetBIOS marker EFFF, this is done because I have seen an extra LLC */
/* byte on our network. This only checks for one extra LLC byte. */

	if (( pd[offset + 2] != 0xff) || ( pd[offset + 3] != 0xef)){
		++offset;
		if (( pd[offset + 2] != 0xff)
		    || ( pd[offset + 3] != 0xef)){
			if (check_col(fd, COL_PROTOCOL))
				col_add_str(fd, COL_PROTOCOL, "NetBIOS");	
	
			if (check_col(fd, COL_INFO)) 	/* print bad packet */
				col_add_str(fd, COL_INFO, "Bad packet");

			if (tree) {
				ti = proto_tree_add_item(tree, proto_netbios,
					offset, END_OF_FRAME, NULL);
				netb_tree = proto_item_add_subtree(ti, ett_netb);
				
				proto_tree_add_text( netb_tree, offset,
				    END_OF_FRAME, "Data (%u bytes)", 
				    END_OF_FRAME); 
			}	
			return;
		}
	}
	
	/* To do: check for runts, errs, etc. */

	hdr_len = pletohs(&pd[offset + NB_LENGTH]);
	command = pd[offset + NB_COMMAND];
	
	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "NetBIOS");

	if (check_col(fd, COL_INFO)) {			/* print command name */
		switch ( command ) {
		case NB_NAME_QUERY:
			name_type = get_netbios_name( pd, offset + 12, name);
			col_add_fstr(fd, COL_INFO, "%s for %s<%02x>",
			    CommandName[ command], name, name_type);
			break;

		case NB_NAME_RESP:
			name_type = get_netbios_name( pd, offset + 28, name);
			col_add_fstr(fd, COL_INFO, "%s - %s<%02x>",
			    CommandName[ command], name, name_type);
			break;

		default:
			if ( command < sizeof( dissect_netb)/ sizeof(void *))
				col_add_fstr(fd, COL_INFO, "%s", CommandName[ command]);
			else
				col_add_fstr(fd, COL_INFO, "Unknown");
			break;
		}
	}


	if (tree) {
		ti = proto_tree_add_item(tree, proto_netbios, offset, END_OF_FRAME, NULL);

		netb_tree = proto_item_add_subtree(ti, ett_netb);

		proto_tree_add_text(netb_tree, offset, 2,
				"Header Length: %d", hdr_len);

		proto_tree_add_text(netb_tree, offset + 2, 2,
				"Delimiter: EFFF (NetBIOS)");

		proto_tree_add_text(netb_tree, offset + NB_COMMAND, 1,
  		    "Command: 0x%02x (%s)", command, CommandName[ command]);

						/* if command in table range */
		if ( command < sizeof( dissect_netb)/ sizeof(void *))

						/* branch to handle commands */
			(dissect_netb[ command])( pd, offset, fd,
				netb_tree);		
	}

							/* Test for SMB data */
	if ( (END_OF_FRAME) > ( hdr_len + 4)){		/* if enough data */

		offset += hdr_len;			/* move past header */

		if (( pd[offset + 0] == 0xff) &&	/* if SMB marker */
		    ( pd[offset + 1] == 'S') &&
		    ( pd[offset + 2] == 'M') &&
		    ( pd[offset + 3] == 'B'))
							/* decode SMB */
			dissect_smb(pd, offset, fd, tree, 
				END_OF_FRAME - hdr_len);
	}

/*$$$$ somewhere around here need to check for frame padding */

}


void proto_register_netbios(void)
{
	static gint *ett[] = {
		&ett_netb,
		&ett_netb_name,
		&ett_netb_flags,
		&ett_netb_status,
	};

        proto_netbios = proto_register_protocol("NetBIOS", "netbios");
	proto_register_subtree_array(ett, array_length(ett));
}
