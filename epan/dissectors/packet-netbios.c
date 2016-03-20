/* packet-netbios.c
 * Routines for NetBIOS protocol packet disassembly
 * Jeff Foster <jfoste@woodward.com>
 * Copyright 1999 Jeffrey C. Foster
 *
 * derived from the packet-nbns.c
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/llcsaps.h>
#include <epan/reassemble.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/capture_dissectors.h>
#include "packet-netbios.h"

void proto_register_netbios(void);
void proto_reg_handoff_netbios(void);

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
#define NB_LENGTH		 0
#define	NB_DELIMITER		 2
#define	NB_COMMAND		 4
#define	NB_FLAGS		 5
#define	NB_DATA1		 5
#define	NB_RESYNC		 6
#define	NB_DATA2		 6
#define	NB_CALL_NAME_TYPE	 7
#define	NB_XMIT_CORL		 8
#define	NB_RESP_CORL		10
#define	NB_RMT_SES		12
#define	NB_LOCAL_SES		13
#define	NB_RECVER_NAME		12
#define	NB_SENDER_NAME		28


static int proto_netbios = -1;
static int hf_netb_cmd = -1;
static int hf_netb_hdr_len = -1;
static int hf_netb_delimiter = -1;
static int hf_netb_xmit_corrl = -1;
static int hf_netb_resp_corrl = -1;
static int hf_netb_call_name_type = -1;
static int hf_netb_version = -1;
static int hf_netbios_no_receive_flags = -1;
static int hf_netbios_no_receive_flags_send_no_ack = -1;
static int hf_netb_largest_frame = -1;
static int hf_netb_nb_name = -1;
static int hf_netb_nb_name_type = -1;
static int hf_netb_status_buffer_len = -1;
static int hf_netb_status = -1;
static int hf_netb_name_type = -1;
static int hf_netb_max_data_recv_size = -1;
static int hf_netb_termination_indicator = -1;
static int hf_netb_num_data_bytes_accepted = -1;
static int hf_netb_local_ses_no = -1;
static int hf_netb_remote_ses_no = -1;
static int hf_netb_flags = -1;
static int hf_netb_flags_send_no_ack = -1;
static int hf_netb_flags_ack = -1;
static int hf_netb_flags_ack_with_data = -1;
static int hf_netb_flags_ack_expected = -1;
static int hf_netb_flags_recv_cont_req = -1;
static int hf_netb_data2 = -1;
static int hf_netb_data2_frame = -1;
static int hf_netb_data2_user = -1;
static int hf_netb_data2_status = -1;
static int hf_netb_datagram_mac = -1;
static int hf_netb_datagram_bcast_mac = -1;
static int hf_netb_resync_indicator = -1;
static int hf_netb_status_request = -1;
static int hf_netb_local_session_no = -1;
static int hf_netb_state_of_name = -1;
static int hf_netb_status_response = -1;
static int hf_netb_fragments = -1;
static int hf_netb_fragment = -1;
static int hf_netb_fragment_overlap = -1;
static int hf_netb_fragment_overlap_conflict = -1;
static int hf_netb_fragment_multiple_tails = -1;
static int hf_netb_fragment_too_long_fragment = -1;
static int hf_netb_fragment_error = -1;
static int hf_netb_fragment_count = -1;
static int hf_netb_reassembled_length = -1;

static gint ett_netb = -1;
static gint ett_netb_name = -1;
static gint ett_netb_flags = -1;
static gint ett_netb_status = -1;
static gint ett_netb_fragments = -1;
static gint ett_netb_fragment = -1;

static expert_field ei_netb_unknown_command_data = EI_INIT;

static const fragment_items netbios_frag_items = {
	&ett_netb_fragment,
	&ett_netb_fragments,
	&hf_netb_fragments,
	&hf_netb_fragment,
	&hf_netb_fragment_overlap,
	&hf_netb_fragment_overlap_conflict,
	&hf_netb_fragment_multiple_tails,
	&hf_netb_fragment_too_long_fragment,
	&hf_netb_fragment_error,
	&hf_netb_fragment_count,
	NULL,
	&hf_netb_reassembled_length,
	/* Reassembled data field */
	NULL,
	"fragments"
};

/* The strings for the station type, used by get_netbios_name function;
   many of them came from the file "NetBIOS.txt" in the Zip archive at

	http://www.net3group.com/ftp/browser.zip
 */

static const value_string nb_name_type_vals[] = {
	{0x00,	"Workstation/Redirector"},
	{0x01,	"Browser"},
	{0x02,	"Workstation/Redirector"},
		/* not sure what 0x02 is, I'm seeing a lot of them however */
		/* I'm seeing them with workstation/redirection host
			announcements */
	{0x03,	"Messenger service/Main name"},
	{0x05,	"Forwarded name"},
	{0x06,	"RAS Server service"},
	{0x1b,	"Domain Master Browser"},
	{0x1c,	"Domain Controllers"},
	{0x1d,	"Local Master Browser"},
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
static value_string_ext nb_name_type_vals_ext = VALUE_STRING_EXT_INIT(nb_name_type_vals);

/* Table for reassembly of fragments. */
static reassembly_table netbios_reassembly_table;

/* defragmentation of NetBIOS Frame */
static gboolean netbios_defragment = TRUE;

/* See

	http://publibz.boulder.ibm.com/cgi-bin/bookmgr_OS390/BOOKS/BK8P7001/CCONTENTS

   and

	http://ourworld.compuserve.com/homepages/TimothyDEvans/contents.htm

   for information about the NetBIOS Frame Protocol (which is what this
   module dissects). */

/* the strings for the command types  */

static const value_string cmd_vals[] = {
	{ NB_ADD_GROUP,			"Add Group Name Query" },
	{ NB_ADD_NAME,			"Add Name Query" },
	{ NB_NAME_IN_CONFLICT,		"Name In Conflict" },
	{ NB_STATUS_QUERY,		"Status Query" },
	{ NB_TERMINATE_TRACE_R,		"Terminate Trace" },
	{ NB_DATAGRAM,			"Datagram" },
	{ NB_DATAGRAM_BCAST,		"Broadcast Datagram" },
	{ NB_NAME_QUERY,		"Name Query" },
	{ NB_ADD_NAME_RESP,		"Add Name Response" },
	{ NB_NAME_RESP,			"Name Recognized" },
	{ NB_STATUS_RESP,		"Status Response" },
	{ NB_TERMINATE_TRACE_LR,	"Terminate Trace" },
	{ NB_DATA_ACK,			"Data Ack" },
	{ NB_DATA_FIRST_MIDDLE,		"Data First Middle" },
	{ NB_DATA_ONLY_LAST,		"Data Only Last" },
	{ NB_SESSION_CONFIRM,		"Session Confirm" },
	{ NB_SESSION_END,		"Session End" },
	{ NB_SESSION_INIT,		"Session Initialize" },
	{ NB_NO_RECEIVE,		"No Receive" },
	{ NB_RECEIVE_OUTSTANDING,	"Receive Outstanding" },
	{ NB_RECEIVE_CONTINUE,		"Receive Continue" },
	{ NB_KEEP_ALIVE,		"Session Alive" },
	{ 0,				NULL }
};
static value_string_ext cmd_vals_ext = VALUE_STRING_EXT_INIT(cmd_vals);

static const value_string name_types[] = {
	{ 0, "Unique name" },
	{ 1, "Group name" },
	{ 0, NULL }
};

static const true_false_string flags_allowed = {
	"Allowed",
	"Not allowed"
};

static const true_false_string netb_version_str = {
	"2.00 or higher",
	"1.xx"
};

static const value_string termination_indicator_vals[] = {
	{ 0x0000, "Normal session end" },
	{ 0x0001, "Abnormal session end" },
	{ 0,      NULL }
};

static const value_string status_vals[] = {
	{ 0, "Add name not in process" },
	{ 1, "Add name in process" },
	{ 0, NULL }
};

static const value_string max_frame_size_vals[] = {
	{ 0,	"516" },
	{ 1,	"1500" },
	{ 2,	"2052" },
	{ 3,	"4472" },
	{ 4,	"8144" },
	{ 5,	"11407" },
	{ 6,	"17800" },	/* 17800 in TR spec, 17749 in NBF spec */
	{ 7,	"65535" },
	{ 0,	NULL }
};


static gboolean
capture_netbios(const guchar *pd _U_, int offset _U_, int len _U_, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
	capture_dissector_increment_count(cpinfo, proto_netbios);
	return TRUE;
}


int
process_netbios_name(const guchar *name_ptr, char *name_ret, int name_ret_len)
{
	int    i;
	int    name_type = *(name_ptr + NETBIOS_NAME_LEN - 1);
	guchar name_char;
	static const char hex_digits[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

	for (i = 0; i < NETBIOS_NAME_LEN - 1; i++) {
		name_char = *name_ptr++;
		if (name_char >= ' ' && name_char <= '~') {
			if (--name_ret_len > 0)
				*name_ret++ = name_char;
		} else {
			/* It's not printable; show it as <XX>, where
			   XX is the value in hex. */
			if (--name_ret_len > 0)
				*name_ret++ = '<';
			if (--name_ret_len > 0)
				*name_ret++ = hex_digits[(name_char >> 4)];
			if (--name_ret_len > 0)
				*name_ret++ = hex_digits[(name_char & 0x0F)];
			if (--name_ret_len > 0)
				*name_ret++ = '>';
		}
	}
	*name_ret = '\0';

	/* Remove trailing space characters from name. */

	name_ret--;

	for (i = 0; i < NETBIOS_NAME_LEN - 1; i++) {
		if (*name_ret != ' ') {
			*(name_ret + 1) = 0;
			break;
		}
		name_ret--;
	}

	return name_type;
}


int
get_netbios_name( tvbuff_t *tvb, int offset, char *name_ret, int name_ret_len)

{/*  Extract the name string and name type.  Return the name string in  */
 /* name_ret and return the name_type. */

	return process_netbios_name( tvb_get_ptr( tvb, offset, NETBIOS_NAME_LEN ), name_ret, name_ret_len);
}


/*
 * Get a string describing the type of a NetBIOS name.
 */
const char *
netbios_name_type_descr(int name_type)

{
	return val_to_str_ext_const(name_type, &nb_name_type_vals_ext, "Unknown");
}

void
netbios_add_name(const char* label, tvbuff_t *tvb, int offset, proto_tree *tree)

{/* add a name field display tree. Display the name and station type in sub-tree */

	proto_tree *field_tree;
	char        name_str[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int         name_type;
	const char *name_type_str;

					/* decode the name field */
	name_type = get_netbios_name( tvb, offset, name_str, (NETBIOS_NAME_LEN - 1)*4 + 1);
	name_type_str = netbios_name_type_descr(name_type);
	field_tree = proto_tree_add_subtree_format( tree, tvb, offset, NETBIOS_NAME_LEN,
			ett_netb_name, NULL, "%s: %s<%02x> (%s)", label, name_str, name_type, name_type_str);

	proto_tree_add_string_format( field_tree, hf_netb_nb_name, tvb, offset,
		15, name_str, "%s", name_str);
	proto_tree_add_uint_format( field_tree, hf_netb_nb_name_type, tvb, offset + 15, 1, name_type,
		"0x%02x (%s)", name_type, name_type_str);
}


static void
netbios_data_first_middle_flags( tvbuff_t *tvb, proto_tree *tree, int offset)

{
	proto_tree *field_tree;
	proto_item *tf;

		/* decode the flag field for Data First Middle packet*/

	tf = proto_tree_add_item(tree, hf_netb_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	field_tree = proto_item_add_subtree(tf, ett_netb_flags);

	proto_tree_add_item( field_tree, hf_netb_flags_ack, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item( field_tree, hf_netb_flags_ack_expected, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item( field_tree, hf_netb_flags_recv_cont_req, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

static void
netbios_data_only_flags( tvbuff_t *tvb, proto_tree *tree, int offset)

{
	proto_tree *field_tree;
	proto_item *tf;

	/* decode the flag field for Data Only Last packet*/
	tf = proto_tree_add_item(tree, hf_netb_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	field_tree = proto_item_add_subtree(tf, ett_netb_flags);

	proto_tree_add_item( field_tree, hf_netb_flags_ack, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item( field_tree, hf_netb_flags_ack_with_data, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item( field_tree, hf_netb_flags_ack_expected, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}



static void
netbios_add_ses_confirm_flags( tvbuff_t *tvb, proto_tree *tree, int offset)

{
	proto_tree *field_tree;
	proto_item *tf;

	/* decode the flag field for Session Confirm packet */
	tf = proto_tree_add_item(tree, hf_netb_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	field_tree = proto_item_add_subtree( tf, ett_netb_flags);

	proto_tree_add_item( field_tree, hf_netb_flags_send_no_ack, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item( field_tree, hf_netb_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}


static void
netbios_add_session_init_flags( tvbuff_t *tvb, proto_tree *tree, int offset)

{
	proto_tree *field_tree;
	proto_item *tf;

	/* decode the flag field for Session Init packet */
	tf = proto_tree_add_item(tree, hf_netb_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	field_tree = proto_item_add_subtree(tf, ett_netb_flags);

	proto_tree_add_item( field_tree, hf_netb_flags_send_no_ack, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item( field_tree, hf_netb_largest_frame, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item( field_tree, hf_netb_version, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}


static void
netbios_no_receive_flags( tvbuff_t *tvb, proto_tree *tree, int offset)

{
	proto_tree *field_tree;
	proto_item *tf;

	/* decode the flag field for No Receive packet*/
	tf = proto_tree_add_item(tree, hf_netbios_no_receive_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	field_tree = proto_item_add_subtree(tf, ett_netb_flags);
	proto_tree_add_item(field_tree, hf_netbios_no_receive_flags_send_no_ack, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}


/************************************************************************/
/*									*/
/*  The routines to display the netbios field values in the tree	*/
/*									*/
/************************************************************************/


static void
nb_xmit_corrl( tvbuff_t *tvb, int offset, proto_tree *tree)

{/* display the transmit correlator */

	proto_tree_add_item( tree, hf_netb_xmit_corrl, tvb, offset + NB_XMIT_CORL,
		2, ENC_LITTLE_ENDIAN);
}


static void
nb_resp_corrl( tvbuff_t *tvb, int offset, proto_tree *tree)

{/* display the response correlator */

	proto_tree_add_item( tree, hf_netb_resp_corrl, tvb, offset + NB_RESP_CORL,
		2, ENC_LITTLE_ENDIAN);
}


static void
nb_call_name_type( tvbuff_t *tvb, int offset, proto_tree *tree)

{/* display the call name type */

	proto_tree_add_item( tree, hf_netb_call_name_type, tvb, offset + NB_CALL_NAME_TYPE,
		1, ENC_LITTLE_ENDIAN);

}


static guint8
nb_local_session( tvbuff_t *tvb, int offset, proto_tree *tree)

{/* add the local session to tree, and return its value */

	guint8 local_session = tvb_get_guint8( tvb, offset + NB_LOCAL_SES);

	proto_tree_add_uint( tree, hf_netb_local_ses_no, tvb, offset + NB_LOCAL_SES, 1,
		local_session);

	return local_session;
}


static guint8
nb_remote_session( tvbuff_t *tvb, int offset, proto_tree *tree)

{/* add the remote session to tree, and return its value */

	guint8 remote_session = tvb_get_guint8( tvb, offset + NB_RMT_SES);

	proto_tree_add_uint( tree, hf_netb_remote_ses_no, tvb, offset + NB_RMT_SES, 1,
		remote_session);

	return remote_session;
}


static void
nb_data1(int hf, tvbuff_t *tvb, int offset, proto_tree *tree)

{/* add the DATA1 to tree with specified hf_ value */

	proto_tree_add_item( tree, hf, tvb, offset + NB_DATA1, 1, ENC_LITTLE_ENDIAN);

}


static void
nb_data2(int hf, tvbuff_t *tvb, int offset, proto_tree *tree)

{/* add the DATA2 to tree with specified hf_ value */

	proto_tree_add_item( tree, hf, tvb, offset + NB_DATA2, 2, ENC_LITTLE_ENDIAN);

}


static void
nb_resync_indicator( tvbuff_t *tvb, int offset, proto_tree *tree, const char *cmd_str)

{
	guint16 resync_indicator = tvb_get_letohs( tvb, offset + NB_DATA2);


	switch (resync_indicator) {

	case 0x0000:
		proto_tree_add_uint_format_value(tree, hf_netb_resync_indicator, tvb, offset + NB_DATA2, 2,
		    resync_indicator, "No re-sync");
		break;

	case 0x0001:
		proto_tree_add_uint_format_value(tree, hf_netb_resync_indicator, tvb, offset + NB_DATA2, 2,
		    resync_indicator, "First '%s' following 'Receive Outstanding'", cmd_str);
		break;

	default:
		proto_tree_add_item(tree, hf_netb_resync_indicator, tvb, offset + NB_DATA2, 2, ENC_LITTLE_ENDIAN);
		break;
	}
}

/************************************************************************/
/*									*/
/*  The routines called by the top level to handle individual commands  */
/*									*/
/************************************************************************/

static guint32
dissect_netb_unknown( tvbuff_t *tvb, packet_info *pinfo, int offset, proto_tree *tree)

{/* Handle any unknown commands, do nothing */

	proto_tree_add_expert(tree, pinfo, &ei_netb_unknown_command_data, tvb, offset + NB_COMMAND + 1, -1);

	return 0;
}


static guint32
dissect_netb_add_group_name( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the ADD GROUP NAME QUERY command */

	nb_resp_corrl( tvb, offset, tree);

	netbios_add_name("Group name to add", tvb, offset + NB_SENDER_NAME,
	    tree);

	return 0;
}


static guint32
dissect_netb_add_name( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the ADD NAME QUERY command */

	nb_resp_corrl( tvb, offset, tree);

	netbios_add_name("Name to add", tvb, offset + NB_SENDER_NAME, tree);

	return 0;
}


static guint32
dissect_netb_name_in_conflict( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the NAME IN CONFLICT command */

	netbios_add_name("Name In Conflict", tvb, offset + NB_RECVER_NAME,
	    tree);
	netbios_add_name("Sender's Name", tvb, offset + NB_SENDER_NAME, tree);

	return 0;
}


static guint32
dissect_netb_status_query( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the STATUS QUERY command */
	guint8 status_request = tvb_get_guint8( tvb, offset + NB_DATA1);

	switch (status_request) {

	case 0:
		proto_tree_add_uint_format_value(tree, hf_netb_status_request, tvb, offset + NB_DATA1, 1,
		    status_request, "NetBIOS 1.x or 2.0");
		break;

	case 1:
		proto_tree_add_uint_format_value(tree, hf_netb_status_request, tvb, offset + NB_DATA1, 1,
		    status_request, "NetBIOS 2.1, initial status request");
		break;

	default:
		proto_tree_add_uint_format_value(tree, hf_netb_status_request, tvb, offset + NB_DATA1, 1,
		    status_request, "NetBIOS 2.1, %u names received so far",
		    status_request);
		break;
	}
	nb_data2( hf_netb_status_buffer_len, tvb, offset, tree);
	nb_resp_corrl( tvb, offset, tree);
	netbios_add_name("Receiver's Name", tvb, offset + NB_RECVER_NAME, tree);
	netbios_add_name("Sender's Name", tvb, offset + NB_SENDER_NAME, tree);

	return 0;
}


static guint32
dissect_netb_terminate_trace( tvbuff_t *tvb _U_, packet_info *pinfo _U_, int offset _U_, proto_tree *tree _U_)

{/* Handle the TERMINATE TRACE command */

	/*
	 * XXX - are any of the fields in this message significant?
	 * The IBM NetBIOS document shows them as "Reserved".
	 */

	return 0;
}


static const guchar zeroes[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static guint32
dissect_netb_datagram( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the DATAGRAM command */

	netbios_add_name("Receiver's Name", tvb, offset + NB_RECVER_NAME, tree);
	/* Weird.  In some datagrams, this is 10 octets of 0, followed
	   by a MAC address.... */

	if (tvb_memeql(tvb, offset + NB_SENDER_NAME, zeroes, 10) == 0) {
		proto_tree_add_item(tree, hf_netb_datagram_mac,
							tvb, offset + NB_SENDER_NAME + 10, 6, ENC_NA );
	} else {
		netbios_add_name("Sender's Name", tvb, offset + NB_SENDER_NAME,
		    tree);
	}

	return 0;
}


static guint32
dissect_netb_datagram_bcast( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the DATAGRAM BROADCAST command */

	/* We assume the same weirdness can happen here.... */
	if (tvb_memeql(tvb, offset + NB_SENDER_NAME, zeroes, 10) == 0) {
		proto_tree_add_item(tree, hf_netb_datagram_bcast_mac,
							tvb, offset + NB_SENDER_NAME + 10, 6, ENC_NA );
	} else {
		netbios_add_name("Sender's Name", tvb, offset + NB_SENDER_NAME,
		    tree);
	}

	return 0;
}


static guint32
dissect_netb_name_query( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the NAME QUERY command */
	guint8 local_session_number = tvb_get_guint8( tvb, offset + NB_DATA2);

	if (local_session_number == 0) {
		proto_tree_add_uint_format_value( tree, hf_netb_local_session_no, tvb, offset + NB_DATA2, 1,
		    local_session_number, "0 (FIND.NAME request)");
	} else {
		proto_tree_add_item( tree, hf_netb_local_session_no, tvb, offset + NB_DATA2, 1, ENC_LITTLE_ENDIAN);
	}
	nb_call_name_type( tvb, offset, tree);
	nb_resp_corrl( tvb, offset, tree);
	netbios_add_name("Query Name", tvb, offset + NB_RECVER_NAME, tree);
	if (local_session_number != 0) {
		netbios_add_name("Sender's Name", tvb, offset + NB_SENDER_NAME,
		    tree);
	}

	return 0;
}


static guint32
dissect_netb_add_name_resp( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the ADD NAME RESPONSE command */

	nb_data1( hf_netb_status, tvb, offset, tree);
	nb_data2( hf_netb_name_type, tvb, offset, tree);
	nb_xmit_corrl( tvb, offset, tree);
	netbios_add_name("Name to be added", tvb, offset + NB_RECVER_NAME,
	    tree);
	netbios_add_name("Name to be added", tvb, offset + NB_SENDER_NAME,
	    tree);

	return 0;
}


static guint32
dissect_netb_name_resp( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the NAME RECOGNIZED command */
	guint8 local_session_number = tvb_get_guint8( tvb, offset + NB_DATA2);

	switch (local_session_number) {

	case 0x00:
		proto_tree_add_uint_format_value( tree, hf_netb_state_of_name, tvb, offset + NB_DATA2, 1,
		    local_session_number, "No LISTEN pending, or FIND.NAME response");
		break;

	case 0xFF:
		proto_tree_add_uint_format_value( tree, hf_netb_state_of_name, tvb, offset + NB_DATA2, 1,
		    local_session_number, "LISTEN pending, but insufficient resources to establish session");
		break;

	default:
		proto_tree_add_item( tree, hf_netb_local_session_no, tvb, offset + NB_DATA2, 1, ENC_LITTLE_ENDIAN);
		break;
	}
	nb_call_name_type( tvb, offset, tree);
	nb_xmit_corrl( tvb, offset, tree);
	if (local_session_number != 0x00 && local_session_number != 0xFF)
		nb_resp_corrl(tvb, offset, tree);
	netbios_add_name("Receiver's Name", tvb, offset + NB_RECVER_NAME, tree);
	if (local_session_number != 0x00 && local_session_number != 0xFF) {
		netbios_add_name("Sender's Name", tvb, offset + NB_SENDER_NAME,
		    tree);
	}

	return 0;
}


static guint32
dissect_netb_status_resp( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the STATUS RESPONSE command */
	guint8	    status_response = tvb_get_guint8( tvb, offset + NB_DATA1);
	proto_item *td2;
	proto_tree *data2_tree;

	nb_call_name_type( tvb, offset, tree);
	if (status_response == 0) {
		proto_tree_add_uint_format_value(tree, hf_netb_status_response, tvb, offset + NB_DATA1, 1,
		    status_response, "NetBIOS 1.x or 2.0");
	} else {
		proto_tree_add_uint_format_value(tree, hf_netb_status_response, tvb, offset + NB_DATA1, 1,
		    status_response, "NetBIOS 2.1, %u names sent so far",
		    status_response);
	}

	td2 = proto_tree_add_item(tree, hf_netb_data2, tvb, offset + NB_DATA2, 2, ENC_LITTLE_ENDIAN);
	data2_tree = proto_item_add_subtree(td2, ett_netb_status);
	proto_tree_add_item(data2_tree, hf_netb_data2_frame, tvb, offset + NB_DATA2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(data2_tree, hf_netb_data2_user, tvb, offset + NB_DATA2, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(data2_tree, hf_netb_data2_status, tvb, offset + NB_DATA2, 2, ENC_LITTLE_ENDIAN);

	nb_xmit_corrl( tvb, offset, tree);
	netbios_add_name("Receiver's Name", tvb, offset + NB_RECVER_NAME, tree);
	netbios_add_name("Sender's Name", tvb, offset + NB_SENDER_NAME,
	    tree);

	return 0;
}


static guint32
dissect_netb_data_ack( tvbuff_t* tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the DATA ACK command */

	nb_xmit_corrl( tvb, offset, tree);
	nb_remote_session( tvb, offset, tree);
	nb_local_session( tvb, offset, tree);

	return 0;
}


static guint32
dissect_netb_data_first_middle( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the DATA FIRST MIDDLE command */

	guint8 remote_session, local_session;

	/*
	 * This is the first frame, or the middle frame, of a fragmented
	 * packet.
	 *
	 * XXX - there are no sequence numbers, so we have to assume
	 * that fragments arrive in order with no duplicates.
	 * In fact, 802.2 LLC is supposed to handle that, so we
	 * might have to have the LLC dissector do so (but the TCP
	 * dissector doesn't currently handle out-of-order or duplicate
	 * data, either).
	 */

	netbios_data_first_middle_flags( tvb, tree, offset + NB_FLAGS);

	nb_resync_indicator( tvb, offset, tree, "DATA FIRST MIDDLE");
	nb_xmit_corrl( tvb, offset, tree);
	nb_resp_corrl( tvb, offset, tree);
	remote_session = nb_remote_session( tvb, offset, tree);
	local_session = nb_local_session( tvb, offset, tree);

	/*
	 * Return a combination of the remote and local session numbers,
	 * for use when reassembling.
	 */
	return (remote_session << 8) + local_session;
}


static guint32
dissect_netb_data_only_last( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the DATA ONLY LAST command */

	guint8 remote_session, local_session;

	/*
	 * This is a complete packet, or the last frame of a fragmented
	 * packet.
	 */

	netbios_data_only_flags( tvb, tree, offset + NB_FLAGS);

	nb_resync_indicator( tvb, offset, tree, "DATA ONLY LAST");
	nb_xmit_corrl( tvb, offset, tree);
	nb_resp_corrl( tvb, offset, tree);
	remote_session = nb_remote_session( tvb, offset, tree);
	local_session = nb_local_session( tvb, offset, tree);

	/*
	 * Return a combination of the remote and local session numbers,
	 * for use when reassembling.
	 */
	return (remote_session << 8) + local_session;
}


static guint32
dissect_netb_session_confirm( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the SESSION CONFIRM command */

	netbios_add_ses_confirm_flags( tvb, tree, offset + NB_FLAGS);

	nb_data2( hf_netb_max_data_recv_size, tvb, offset, tree);
	nb_xmit_corrl( tvb, offset, tree);
	nb_resp_corrl( tvb, offset, tree);
	nb_remote_session( tvb, offset, tree);
	nb_local_session( tvb, offset, tree);

	return 0;
}


static guint32
dissect_netb_session_end( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the SESSION END command */

	nb_data2( hf_netb_termination_indicator, tvb, offset, tree);
	nb_remote_session( tvb, offset, tree);
	nb_local_session( tvb, offset, tree);

	return 0;
}


static guint32
dissect_netb_session_init( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the SESSION INITIALIZE command */

	netbios_add_session_init_flags( tvb, tree, offset + NB_FLAGS);

	nb_data2( hf_netb_max_data_recv_size, tvb, offset, tree);
	nb_resp_corrl( tvb, offset, tree);
	nb_xmit_corrl( tvb, offset, tree);
	nb_remote_session( tvb, offset, tree);
	nb_local_session( tvb, offset, tree);

	return 0;
}

static guint32
dissect_netb_no_receive( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the NO RECEIVE command */

	netbios_no_receive_flags( tvb, tree, offset + NB_FLAGS);

	nb_data2( hf_netb_num_data_bytes_accepted, tvb, offset, tree);
	nb_remote_session( tvb, offset, tree);
	nb_local_session( tvb, offset, tree);

	return 0;
}


static guint32
dissect_netb_receive_outstanding( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the RECEIVE OUTSTANDING command */

	nb_data2( hf_netb_num_data_bytes_accepted, tvb, offset, tree);
	nb_remote_session( tvb, offset, tree);
	nb_local_session( tvb, offset, tree);

	return 0;
}


static guint32
dissect_netb_receive_continue( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the RECEIVE CONTINUE command */

	nb_xmit_corrl( tvb, offset, tree);
	nb_remote_session( tvb, offset, tree);
	nb_local_session( tvb, offset, tree);

	return 0;
}


static guint32
dissect_netb_session_alive( tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree)

{/* Handle the SESSION ALIVE command */

	/*
	 * XXX - all the fields are claimed to be "Reserved", but
	 * the session numbers appear to be non-zero in at least
	 * one capture, and they do appear to match session numbers
	 * in other messages, and I'd expect that you had to identify
	 * sessions in this message in any case.
	 *
	 * We show only those fields.
	 */
	nb_remote_session( tvb, offset, tree);
	nb_local_session( tvb, offset, tree);

	return 0;
}


/************************************************************************/
/*									*/
/*  The table routines called by the top level to handle commands  	*/
/*									*/
/************************************************************************/

static guint32 (*const dissect_netb[])(tvbuff_t *, packet_info *, int, proto_tree *) = {

	dissect_netb_add_group_name,	  /* Add Group Name	 0x00 */
	dissect_netb_add_name,		  /* Add Name		 0x01 */
	dissect_netb_name_in_conflict,	  /* Name In Conflict	 0x02 */
	dissect_netb_status_query,	  /* Status Query	 0x03 */
	dissect_netb_unknown,		  /* unknown		 0x04 */
	dissect_netb_unknown,		  /* unknown		 0x05 */
	dissect_netb_unknown,		  /* unknown		 0x06 */
	dissect_netb_terminate_trace,	  /* Terminate Trace	 0x07 */
	dissect_netb_datagram,		  /* Datagram		 0x08 */
	dissect_netb_datagram_bcast,	  /* Datagram Broadcast	 0x09 */
	dissect_netb_name_query,	  /* Name Query		 0x0A */
	dissect_netb_unknown,		  /* unknown		 0x0B */
	dissect_netb_unknown,		  /* unknown		 0x0C */
	dissect_netb_add_name_resp,	  /* Add Name Response	 0x0D */
	dissect_netb_name_resp,		  /* Name Recognized	 0x0E */
	dissect_netb_status_resp,	  /* Status Response	 0x0F */
	dissect_netb_unknown,		  /* unknown		 0x10 */
	dissect_netb_unknown,		  /* unknown		 0x11 */
	dissect_netb_unknown,		  /* unknown		 0x12 */
	dissect_netb_terminate_trace,	  /* Terminate Trace	 0x13 */
	dissect_netb_data_ack,		  /* Data Ack		 0x14 */
	dissect_netb_data_first_middle,	  /* Data First Middle	 0x15 */
	dissect_netb_data_only_last,	  /* Data Only Last	 0x16 */
	dissect_netb_session_confirm,	  /* Session Confirm	 0x17 */
	dissect_netb_session_end,	  /* Session End	 0x18 */
	dissect_netb_session_init,	  /* Session Initialize	 0x19 */
	dissect_netb_no_receive,	  /* No Receive		 0x1A */
	dissect_netb_receive_outstanding, /* Receive Outstanding 0x1B */
	dissect_netb_receive_continue,	  /* Receive Continue	 0x1C */
	dissect_netb_unknown,		  /* unknown		 0x1D */
	dissect_netb_unknown,		  /* unknown		 0x1E */
	dissect_netb_session_alive,	  /* Session Alive	 0x1f */
	dissect_netb_unknown,
};

static heur_dissector_list_t netbios_heur_subdissector_list;

static void
dissect_netbios_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	heur_dtbl_entry_t *hdtbl_entry;

	/*
	 * Try the heuristic dissectors for NetBIOS; if none of them
	 * accept the packet, dissect it as data.
	 */
	if (!dissector_try_heuristic(netbios_heur_subdissector_list,
				    tvb, pinfo, tree, &hdtbl_entry, NULL))
		call_data_dissector(tvb, pinfo, tree);
}

static int
dissect_netbios(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree    *netb_tree = NULL;
	proto_item    *ti;
	guint16	       hdr_len, command;
	const char    *command_name;
	char 	       name[(NETBIOS_NAME_LEN - 1)*4 + 1];
	int	       name_type;
	guint16	       session_id;
	gboolean       save_fragmented;
	int	       len;
	fragment_head *fd_head;
	tvbuff_t      *next_tvb;

	int offset = 0;

					/* load the display labels 	*/
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetBIOS");


/* Find NetBIOS marker EFFF, this is done because I have seen an extra LLC */
/* byte on our network. This only checks for one extra LLC byte. */

	if ( 0xefff != tvb_get_letohs(tvb, 2)){
		++offset;
		if ( 0xefff != tvb_get_letohs(tvb, 3)){

			/* print bad packet */
			col_set_str( pinfo->cinfo, COL_INFO, "Bad packet, no 0xEFFF marker");

			return 3;		/* this is an unknown packet, no marker */
		}
	}


	hdr_len = tvb_get_letohs(tvb, offset + NB_LENGTH);
	command = tvb_get_guint8( tvb, offset + NB_COMMAND);
					/* limit command so no table overflows */
	command = MIN( command, sizeof( dissect_netb)/ sizeof(void *));

		/* print command name */
	command_name = val_to_str_ext(command, &cmd_vals_ext, "Unknown (0x%02x)");
	switch ( command ) {
		case NB_NAME_QUERY:
			name_type = get_netbios_name( tvb, offset + 12, name, (NETBIOS_NAME_LEN - 1)*4 + 1);
			col_add_fstr( pinfo->cinfo, COL_INFO, "%s for %s<%02x>", command_name, name, name_type);
			break;

		case NB_NAME_RESP:
		case NB_ADD_NAME:
		case NB_ADD_GROUP:
			name_type = get_netbios_name( tvb, offset + 28, name, (NETBIOS_NAME_LEN - 1)*4 + 1);
			col_add_fstr( pinfo->cinfo, COL_INFO, "%s - %s<%02x>", command_name, name, name_type);
		break;

		default:
			col_add_str( pinfo->cinfo, COL_INFO, command_name);
			break;
	}

	if ( tree) {
		ti = proto_tree_add_item(tree, proto_netbios, tvb, 0, hdr_len, ENC_NA);
		netb_tree = proto_item_add_subtree(ti, ett_netb);

		proto_tree_add_uint_format_value(netb_tree, hf_netb_hdr_len, tvb, offset, 2, hdr_len,
			"%d bytes", hdr_len);

		proto_tree_add_uint_format_value(netb_tree, hf_netb_delimiter, tvb, offset + 2, 2,
			tvb_get_letohs(tvb, offset + 2), "EFFF (NetBIOS)");

		proto_tree_add_uint(netb_tree, hf_netb_cmd, tvb, offset + NB_COMMAND, 1, command);
	}

					/* if command in table range */
	if ( command < sizeof( dissect_netb)/ sizeof(void *)) {

					/* branch to handle commands */
		session_id = (dissect_netb[ command])( tvb, pinfo, offset, netb_tree);

		offset += hdr_len;			/* move past header */

		save_fragmented = pinfo->fragmented;

		/*
		 * Process user data in frames that have it.
		 */
		switch (command) {

		case NB_DATAGRAM:
		case NB_DATAGRAM_BCAST:
			/*
			 * No fragmentation here.
			 */
			next_tvb = tvb_new_subset_remaining(tvb, offset);
			dissect_netbios_payload(next_tvb, pinfo, tree);
			break;

		case NB_DATA_FIRST_MIDDLE:
		case NB_DATA_ONLY_LAST:
			/*
			 * Possibly fragmented.
			 */
			len = tvb_reported_length_remaining(tvb, offset);
			if (netbios_defragment &&
			    tvb_bytes_exist(tvb, offset, len)) {
				fd_head = fragment_add_seq_next(&netbios_reassembly_table,
				    tvb, offset,
				    pinfo, session_id, NULL,
				    len, command == NB_DATA_FIRST_MIDDLE);
				if (fd_head != NULL) {
					if (fd_head->next != NULL) {
						next_tvb = tvb_new_chain(tvb, fd_head->tvb_data);
						add_new_data_source(pinfo,
						    next_tvb,
						    "Reassembled NetBIOS");
						/* Show all fragments. */
						if (tree) {
							proto_item *frag_tree_item;

							show_fragment_seq_tree(fd_head,
							    &netbios_frag_items,
							    netb_tree, pinfo,
							    next_tvb, &frag_tree_item);
						}
					} else {
						next_tvb = tvb_new_subset_remaining(tvb,
						    offset);
					}
				} else {
					next_tvb = NULL;
				}
			} else {
				/*
				 * Dissect this, regardless of whether
				 * it's NB_DATA_FIRST_MIDDLE or
				 * NB_DATA_ONLY_LAST.
				 *
				 * XXX - it'd be nice to show
				 * NB_DATA_FIRST_MIDDLE as a fragment
				 * if it's not the first fragment (i.e.,
				 * MIDDLE rather than FIRST), and show
				 * NB_DATA_ONLY_LAST as a fragment if
				 * it's part of a fragmented datagram
				 * (i.e, LAST rather than ONLY), but
				 * we'd have to do reassembly to
				 * be able to determine that.
				 */
				next_tvb = tvb_new_subset_remaining(tvb, offset);
			}
			if (next_tvb != NULL)
				dissect_netbios_payload(next_tvb, pinfo, tree);
			else {
				next_tvb = tvb_new_subset_remaining (tvb, offset);
				call_data_dissector(next_tvb, pinfo, tree);
			}
			break;
		}
		pinfo->fragmented = save_fragmented;
	}
	return tvb_captured_length(tvb);
}

static void
netbios_init(void)
{
	reassembly_table_init(&netbios_reassembly_table,
	    &addresses_reassembly_table_functions);
}

static void
netbios_cleanup(void)
{
	reassembly_table_destroy(&netbios_reassembly_table);
}

void
proto_register_netbios(void)
{
	static gint *ett[] = {
		&ett_netb,
		&ett_netb_name,
		&ett_netb_flags,
		&ett_netb_status,
		&ett_netb_fragments,
		&ett_netb_fragment,
	};

	static hf_register_info hf_netb[] = {
		{ &hf_netb_cmd,
		  { "Command", "netbios.command", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
		    &cmd_vals_ext, 0x0, NULL, HFILL }},

		{ &hf_netb_hdr_len,
		  { "Length", "netbios.hdr_len", FT_UINT16, BASE_DEC,
		    NULL, 0x0, "Header Length", HFILL }},

		{ &hf_netb_delimiter,
		  { "Delimiter", "netbios.delimiter", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_xmit_corrl,
		  { "Transmit Correlator", "netbios.xmit_corrl", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_resp_corrl,
		  { "Response Correlator", "netbios.resp_corrl", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_call_name_type,
		  { "Caller's Name Type", "netbios.call_name_type", FT_UINT8, BASE_HEX,
		    VALS(name_types), 0x0, NULL, HFILL }},

		{ &hf_netb_nb_name_type,
		  { "NetBIOS Name Type", "netbios.nb_name_type", FT_UINT8, BASE_HEX |BASE_EXT_STRING,
		    &nb_name_type_vals_ext, 0x0, NULL, HFILL }},

		{ &hf_netb_nb_name,
		  { "NetBIOS Name", "netbios.nb_name", FT_STRING, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_version,
		  { "NetBIOS Version", "netbios.version", FT_BOOLEAN,  8,
		    TFS( &netb_version_str), 0x01, NULL, HFILL }},

		{ &hf_netbios_no_receive_flags,
		  { "Flags", "netbios.no_receive_flags", FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_netbios_no_receive_flags_send_no_ack,
		  { "SEND.NO.ACK data received", "netbios.no_receive_flags.send_no_ack", FT_BOOLEAN,  8,
		    TFS( &tfs_no_yes), 0x02, NULL, HFILL }},

		{ &hf_netb_largest_frame,
		  { "Largest Frame", "netbios.largest_frame", FT_UINT8, BASE_DEC,
		    VALS(max_frame_size_vals), 0x0E, NULL, HFILL }},

		{ &hf_netb_status_buffer_len,
		  { "Length of status buffer", "netbios.status_buffer_len", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_status,
		  { "Status", "netbios.status", FT_UINT8, BASE_DEC,
		    VALS(status_vals), 0x0, NULL, HFILL }},

		{ &hf_netb_name_type,
		  { "Name type", "netbios.name_type", FT_UINT16, BASE_DEC,
		    VALS(name_types), 0x0, NULL, HFILL }},

		{ &hf_netb_max_data_recv_size,
		  { "Maximum data receive size", "netbios.max_data_recv_size", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_termination_indicator,
		  { "Termination indicator", "netbios.termination_indicator", FT_UINT16, BASE_HEX,
		    VALS(termination_indicator_vals), 0x0, NULL, HFILL }},

		{ &hf_netb_num_data_bytes_accepted,
		  { "Number of data bytes accepted", "netbios.num_data_bytes_accepted", FT_UINT16, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_local_ses_no,
		  { "Local Session No.", "netbios.local_session", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_remote_ses_no,
		  { "Remote Session No.", "netbios.remote_session", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_flags,
		  { "Flags", "netbios.flags", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_flags_send_no_ack,
		  { "Handle SEND.NO.ACK", "netbios.flags.send_no_ack", FT_BOOLEAN,  8,
		    TFS( &tfs_yes_no), 0x80, NULL, HFILL }},

		{ &hf_netb_flags_ack,
		  { "Acknowledge", "netbios.flags.ack", FT_BOOLEAN, 8,
		    TFS( &tfs_set_notset), 0x08, NULL, HFILL }},

		{ &hf_netb_flags_ack_with_data,
		  { "Acknowledge with data", "netbios.flags.ack_with_data", FT_BOOLEAN, 8,
		    TFS( &flags_allowed), 0x04, NULL, HFILL }},

		{ &hf_netb_flags_ack_expected,
		  { "Acknowledge expected", "netbios.flags.ack_expected", FT_BOOLEAN,  8,
		    TFS( &tfs_yes_no), 0x02, NULL, HFILL }},

		{ &hf_netb_flags_recv_cont_req,
		  { "RECEIVE_CONTINUE requested", "netbios.flags.recv_cont_req", FT_BOOLEAN,  8,
		    TFS( &tfs_yes_no), 0x01, NULL, HFILL }},

		{ &hf_netb_data2,
		  { "DATA2 value", "netbios.data2", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_data2_frame,
		  { "Data length exceeds maximum frame size", "netbios.data2.frame", FT_BOOLEAN, 16,
		    TFS(&tfs_yes_no), 0x8000, NULL, HFILL }},

		{ &hf_netb_data2_user,
		  { "Data length exceeds user's buffer", "netbios.data2.user", FT_BOOLEAN, 16,
		    TFS(&tfs_yes_no), 0x4000, NULL, HFILL }},

		{ &hf_netb_data2_status,
		  { "Status data length", "netbios.data2.status", FT_UINT16, BASE_DEC,
		    NULL, 0x3FFF, NULL, HFILL }},

		{ &hf_netb_datagram_mac,
		  { "Sender's MAC Address", "netbios.datagram_mac", FT_ETHER, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_datagram_bcast_mac,
		  { "Sender's Node Address",	"netbios.datagram_bcast_mac", FT_ETHER, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_resync_indicator,
		  { "Re-sync indicator", "netbios.resync_indicator", FT_UINT16, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_status_request,
		  { "Status request", "netbios.status_request", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_local_session_no,
		  { "Local Session No.", "netbios.local_session_no", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_state_of_name,
		  { "State of name", "netbios.state_of_name", FT_UINT8, BASE_HEX,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_status_response,
		  { "Status response", "netbios.status_response", FT_UINT8, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_fragment_overlap,
		  { "Fragment overlap",	"netbios.fragment.overlap", FT_BOOLEAN, BASE_NONE,
		    NULL, 0x0, "Fragment overlaps with other fragments", HFILL }},

		{ &hf_netb_fragment_overlap_conflict,
		  { "Conflicting data in fragment overlap", "netbios.fragment.overlap.conflict",
		    FT_BOOLEAN, BASE_NONE,
		    NULL, 0x0, "Overlapping fragments contained conflicting data", HFILL }},

		{ &hf_netb_fragment_multiple_tails,
		  { "Multiple tail fragments found", "netbios.fragment.multipletails",
		    FT_BOOLEAN, BASE_NONE,
		    NULL, 0x0, "Several tails were found when defragmenting the packet", HFILL }},

		{ &hf_netb_fragment_too_long_fragment,
		  { "Fragment too long",	"netbios.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE,
		    NULL, 0x0, "Fragment contained data past end of packet", HFILL }},

		{ &hf_netb_fragment_error,
		  { "Defragmentation error",	"netbios.fragment.error", FT_FRAMENUM, BASE_NONE,
		    NULL, 0x0, "Defragmentation error due to illegal fragments", HFILL }},

		{ &hf_netb_fragment_count,
		  { "Fragment count",	"netbios.fragment.count", FT_UINT32, BASE_DEC,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_fragment,
		  { "NetBIOS Fragment",		"netbios.fragment", FT_FRAMENUM, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_fragments,
		  { "NetBIOS Fragments",	"netbios.fragments", FT_NONE, BASE_NONE,
		    NULL, 0x0, NULL, HFILL }},

		{ &hf_netb_reassembled_length,
		  {"Reassembled NetBIOS length",	"netbios.reassembled.length", FT_UINT32, BASE_DEC,
		   NULL, 0x0, "The total length of the reassembled payload", HFILL }},
	};

	static ei_register_info ei[] = {
		{ &ei_netb_unknown_command_data, { "netbios.unknown_command_data", PI_UNDECODED, PI_WARN, "Unknown NetBIOS command data", EXPFILL }},
	};

	module_t *netbios_module;
	expert_module_t* expert_netbios;

	proto_netbios = proto_register_protocol("NetBIOS", "NetBIOS", "netbios");
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_field_array(proto_netbios, hf_netb, array_length(hf_netb));
	expert_netbios = expert_register_protocol(proto_netbios);
	expert_register_field_array(expert_netbios, ei, array_length(ei));


	netbios_heur_subdissector_list = register_heur_dissector_list("netbios", proto_netbios);

	netbios_module = prefs_register_protocol(proto_netbios, NULL);
	prefs_register_bool_preference(netbios_module, "defragment",
	    "Reassemble fragmented NetBIOS messages spanning multiple frames",
	    "Whether the NetBIOS dissector should defragment messages spanning multiple frames",
	    &netbios_defragment);

	register_init_routine(netbios_init);
	register_cleanup_routine(netbios_cleanup);
}

void
proto_reg_handoff_netbios(void)
{
	dissector_handle_t netbios_handle;

	netbios_handle = create_dissector_handle(dissect_netbios,
	    proto_netbios);
	dissector_add_uint("llc.dsap", SAP_NETBIOS, netbios_handle);
	register_capture_dissector("llc.dsap", SAP_NETBIOS, capture_netbios, proto_netbios);
}


/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
