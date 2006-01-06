/* packet-slsk.c
 * Routines for SoulSeek Protocol dissection
 * Copyright 2003, Christian Wagner <Christian.Wagner@stud.uni-karlsruhe.de>
 * Institute of Telematics - University of Karlsruhe
 * part of this work supported by
 *  Deutsche Forschungsgemeinschaft (DFG) Grant Number FU448/1
 *
 * SoulSeek Protocol dissector based on protocol descriptions from SoleSeek Project:
 * http://cvs.sourceforge.net/viewcvs.py/soleseek/SoleSeek/doc/protocol.html?rev=HEAD
 * Updated for SoulSeek client version 151
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

#include <epan/packet.h>
#include <epan/tvbuff.h>
#include "packet-tcp.h"
#include <epan/prefs.h>
#include <epan/strutil.h>

/* Initialize the protocol and registered fields */
static int proto_slsk = -1;

static int hf_slsk_integer = -1;
static int hf_slsk_string = -1;
static int hf_slsk_byte = -1;
static int hf_slsk_message_length = -1;
static int hf_slsk_message_code = -1;
static int hf_slsk_client_ip = -1;
static int hf_slsk_server_ip = -1;
static int hf_slsk_string_length = -1;
static int hf_slsk_username = -1;
static int hf_slsk_password = -1;
static int hf_slsk_version = -1;
static int hf_slsk_login_successful = -1;
static int hf_slsk_login_message = -1;
static int hf_slsk_port = -1;
static int hf_slsk_ip = -1;
static int hf_slsk_user_exists = -1;
static int hf_slsk_status_code = -1;
static int hf_slsk_room = -1;
static int hf_slsk_chat_message = -1;
static int hf_slsk_users_in_room = -1;
static int hf_slsk_token = -1;
static int hf_slsk_connection_type = -1;
static int hf_slsk_chat_message_id = -1;
static int hf_slsk_timestamp = -1;
static int hf_slsk_search_text = -1;
static int hf_slsk_folder_count = -1;
static int hf_slsk_file_count = -1;
static int hf_slsk_average_speed = -1;
static int hf_slsk_download_number = -1;
static int hf_slsk_files = -1;
static int hf_slsk_directories = -1;
static int hf_slsk_slotsfull = -1;
static int hf_slsk_place_in_queue = -1;
static int hf_slsk_number_of_rooms = -1;
static int hf_slsk_filename = -1;
static int hf_slsk_directory = -1;
static int hf_slsk_size = -1;
static int hf_slsk_checksum = -1;
static int hf_slsk_code = -1;
static int hf_slsk_number_of_users = -1;
static int hf_slsk_number_of_days = -1;
static int hf_slsk_transfer_direction = -1;
static int hf_slsk_user_description = -1;
static int hf_slsk_picture_exists = -1;
static int hf_slsk_picture = -1;
static int hf_slsk_user_uploads = -1;
static int hf_slsk_total_uploads = -1;
static int hf_slsk_queued_uploads = -1;
static int hf_slsk_slots_available = -1;
static int hf_slsk_allowed = -1;
static int hf_slsk_compr_packet = -1;
static int hf_slsk_parent_min_speed = -1;
static int hf_slsk_parent_speed_connection_ratio = -1;
static int hf_slsk_seconds_parent_inactivity_before_disconnect = -1;
static int hf_slsk_seconds_server_inactivity_before_disconnect = -1;
static int hf_slsk_nodes_in_cache_before_disconnect = -1;
static int hf_slsk_seconds_before_ping_children = -1;
static int hf_slsk_recommendation = -1;
static int hf_slsk_ranking = -1;


/* Initialize the subtree pointers */
static gint ett_slsk = -1;
static gint ett_slsk_compr_packet = -1;

#define TCP_PORT_SLSK_1 			2234
#define TCP_PORT_SLSK_2 			5534
#define TCP_PORT_SLSK_3 			2240


/* desegmentation of SoulSeek Message over TCP */
static gboolean slsk_desegment = TRUE;
#ifdef HAVE_LIBZ
static gboolean slsk_decompress = TRUE;
#else
static gboolean slsk_decompress = FALSE;
#endif

static const value_string slsk_tcp_msgs[] = {
	{ 1, "Login"},
	{ 2, "Set Wait Port"},
	{ 3, "Get Peer Address"},
	{ 4, "Get Shared File List"},
	{ 5, "User Exists / Shared File List"},
	{ 7, "Get User Status"},
	{ 9, "File Search Result"},
	{ 13, "Say ChatRoom"},
	{ 14, "Join Room"},
	{ 15, "Leave Room / User Info Request"},
	{ 16, "User Joined Room / User Info Reply"},
	{ 17, "User Left Room"},
	{ 18, "Connect To Peer"},
	{ 22, "Message User"},
	{ 23, "Message User Ack"},
	{ 26, "File Search"},
	{ 28, "Set Status"},
	{ 32, "Ping"},
	{ 34, "Update Upload Speed"},
	{ 35, "Shared Files & Folders"},
	{ 36, "Get User Stats / Folder Contents Request"},
	{ 37, "Folder Contents Response"},
	{ 40, "Queued Downloads / Transfer Request"},
	{ 41, "Transfer Response"},
	{ 42, "Placehold Upload"},
	{ 43, "Queue Upload"},
	{ 44, "Place In Queue"},
	{ 46, "Upload Failed"},
	{ 50, "Queue Failed / Own Recommendation"},
	{ 51, "Add Things I like / Place In Queue Request"},
	{ 52, "Remove Things I like"},
	{ 54, "Get Recommendations"},
	{ 55, "Type 55"},
	{ 56, "Get Global Rankings"},
	{ 57, "Get User Recommendations"},
	{ 58, "Admin Command"},
	{ 60, "Place In Line Response"},
	{ 62, "Room Added"},
	{ 63, "Room Removed"},
	{ 64, "Room List"},
	{ 65, "Exact File Search"},
	{ 66, "Admin Message"},
	{ 67, "Global User List"},
	{ 68, "Tunneled Message"},
	{ 69, "Privileged User List"},
	{ 71, "Get Parent List"},
	{ 73, "Type 73"},
	{ 83, "Parent Min Speed"},
	{ 84, "Parent Speed Connection Ratio"},
	{ 86, "Parent Inactivity Before Disconnect"},
	{ 87, "Server Inactivity Before Disconnect"},
	{ 88, "Nodes In Cache Before Disconnect"},
	{ 90, "Seconds Before Ping Children"},
	{ 91, "Add To Privileged"},
	{ 92, "Check Privileges"},
	{ 93, "Embedded Message"},
	{ 100, "Become Parent"},
	{ 102, "Random Parent Addresses"},
	{ 103, "Send Wishlist Entry"},
	{ 104, "Type 104"},
	{ 110, "Get Similar Users"},
	{ 111, "Get Recommendations for Item"},
	{ 112, "Get Similar Users for Item"},
	{ 1001, "Can't Connect To Peer"},
	{ 0, NULL }
};

static const value_string slsk_status_codes[] = {
	{ -1, "Unknown"},
	{ 0, "Offline"},
	{ 1, "Away"},
	{ 2, "Online"},
	{ 0, NULL }
};

static const value_string slsk_transfer_direction[] = {
	{ 0, "Download"},
	{ 1, "Upload"},
	{ 0, NULL }
};

static const value_string slsk_yes_no[] = {
	{ 0, "No"},
	{ 1, "Yes"},
	{ 0, NULL }
};

static const value_string slsk_attr_type[] = {
	{ 0, "Bitrate"},
	{ 1, "Length"},
	{ 2, "VBR"},
	{ 0, NULL }
};

static const char* connection_type(char con_type[]) {
	if (strlen(con_type) != 1) return "Unknown";
	if (con_type[0] == 'D') return "Distributed Search";
	if (con_type[0] == 'P') return "Peer Connection";		/* "File Search Result / User Info Request / Get Shared File List" */
	if (con_type[0] == 'F') return "File Transfer";
	return "Unknown";
}

static gboolean check_slsk_format(tvbuff_t *tvb, int offset, const char format[]){

	/*
	* Returns TRUE if tvbuff beginning at offset matches a certain format
	* The format is given by an array of characters standing for a special field type
	* 		i - integer	(4 bytes)
	* 		b - byte	(1 byte)
	*		s - string	(string_length + 4 bytes)
	*
	*		* - can be used at the end of a format to ignore any following bytes
	*/

	switch ( format[0] ) {
		case 'i':
			if (tvb_length_remaining(tvb, offset) < 4) return FALSE;
			offset += 4;
		break;
		case 'b':
			if (tvb_length_remaining(tvb, offset) < 1) return FALSE;
			offset += 1;
		break;
		case 's':
			if (tvb_length_remaining(tvb, offset) < 4) return FALSE;
			if (tvb_length_remaining(tvb, offset) < (int)tvb_get_letohl(tvb, offset)+4) return FALSE;
			offset += tvb_get_letohl(tvb, offset)+4;
		break;
		case '*':
			return TRUE;
		break;
		default:
			return FALSE;
		break;
	}

	if (format[1] == '\0' ) {
		if (tvb_length_remaining(tvb, offset) != 0) return FALSE;	/* Checks for additional bytes at the end */
			return TRUE;
	}
	return check_slsk_format(tvb, offset, &format[1]);

}

static const char* get_message_type(tvbuff_t *tvb) {
	/*
	* Checks if the Message Code is known.
	* If unknown checks if the Message Code is stored in a byte.
	* Returns the Message Type.
	*/
	int msg_code = tvb_get_letohl(tvb, 4);
	const gchar *message_type =  match_strval(msg_code, slsk_tcp_msgs);
	if (message_type == NULL) {
		if (check_slsk_format(tvb, 4, "bisis"))
			message_type = "Distributed Search";
		else if (check_slsk_format(tvb, 4, "bssi"))
			message_type = "Peer Init";
		else if (check_slsk_format(tvb, 4, "bi"))
			message_type = "Pierce Fw";
		else
			message_type = "Unknown";
	}
	return message_type;
}

static guint get_slsk_pdu_len(tvbuff_t *tvb, int offset)
{
	guint32 msg_len;
	msg_len = tvb_get_letohl(tvb, offset);
	/* That length doesn't include the length field itself; add that in. */
	msg_len += 4;
	return msg_len;
}

/* Code to actually dissect the packets */

static void dissect_slsk_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *slsk_tree;

	int offset, i, j;
	guint32 msg_len, msg_code;
	const gchar *message_type;
	guint8 *str;

	int comprlen = 0;
	int uncomprlen = 0;
	int uncompr_tvb_offset = 0;
	int i2 = 0;
	int j2 = 0;
	int i3 = 0;
	int j3 = 0;

	offset = 0;

	msg_len = tvb_get_letohl(tvb, offset);
	msg_code = tvb_get_letohl(tvb, offset+4);
	message_type =  get_message_type(tvb);

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "slsk");

/* This field shows up as the "Info" column in the display  */

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "SoulSeek Message");

	if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", message_type);
        }


	if (tree) {

/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_slsk, tvb, 0, -1, FALSE);
		slsk_tree = proto_item_add_subtree(ti, ett_slsk);

/* Continue adding tree items to process the packet here */

		proto_tree_add_uint(slsk_tree, hf_slsk_message_length, tvb, offset, 4, msg_len);
		offset += 4;

		switch (msg_code) {

			case  1:
				if (check_slsk_format(tvb, offset, "issi")) {
					/* Client-to-Server */
					message_type = "Login";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_password, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_version, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "ibs") || check_slsk_format(tvb, offset, "ibsi")) {
					/* Server-to-Client */
					message_type = "Login Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					i=tvb_get_guint8(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_login_successful, tvb, offset, 1, tvb_get_guint8(tvb, offset),
						"Login successful: %s (Byte: %d)", val_to_str(tvb_get_guint8(tvb, offset), slsk_yes_no, "Unknown"), tvb_get_guint8(tvb, offset));
					offset += 1;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_login_message, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					if (i == 1){
						proto_tree_add_ipv4(slsk_tree, hf_slsk_client_ip, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
						offset += 4;
					}
				}
			break;

			case  2:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Client-to-Server */
					message_type = "Set Wait Port";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_port, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case  3:
				if (check_slsk_format(tvb, offset, "isii")) {
					/* Server-to-Client */
					message_type = "Get Peer Address Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_ipv4(slsk_tree, hf_slsk_ip, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_port, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server */
					message_type = "Get Peer Address";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 4:
				if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Client */
					message_type = "Get Shared File List";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
			break;

			case  5:
				if (check_slsk_format(tvb, offset, "isb")) {
					/* Server-to-Client */
					message_type = "User Exists Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_user_exists, tvb, offset, 1, tvb_get_guint8(tvb, offset),
						"User exists: %s (Byte: %d)", val_to_str(tvb_get_guint8(tvb, offset), slsk_yes_no, "Unknown"), tvb_get_guint8(tvb, offset));
					offset += 1;
				}
				else if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server */
					message_type = "User Exists Request";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "i*")) {
					/* Client-to-Client */
					message_type = "Shared File List";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;

					/* [zlib compressed] */
					comprlen = tvb_length_remaining(tvb, offset);

					if (slsk_decompress == TRUE){

						tvbuff_t *uncompr_tvb = tvb_uncompress(tvb, offset, comprlen);

						if (uncompr_tvb == NULL) {
							proto_tree_add_text(slsk_tree, tvb, offset, -1,
								"[zlib compressed packet]");
							offset += tvb_length_remaining(tvb, offset);
							proto_tree_add_text(slsk_tree, tvb, 0, 0,
								"(uncompression failed !)");
						} else {

							proto_item *ti2 = proto_tree_add_item(slsk_tree, hf_slsk_compr_packet, tvb, offset, -1, FALSE);
							proto_tree *slsk_compr_packet_tree = proto_item_add_subtree(ti2, ett_slsk_compr_packet);

							proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
								"(  compressed packet length: %d)", comprlen);
							uncomprlen = tvb_reported_length_remaining(uncompr_tvb, 0);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
								"(uncompressed packet length: %d)", uncomprlen);

							/* Dissects the uncompressed tvbuffer */
							tvb_set_child_real_data_tvbuff(tvb, uncompr_tvb);
							add_new_data_source(pinfo, uncompr_tvb,
							    "Uncompressed SoulSeek data");
							uncompr_tvb_offset = 0;
							if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "i*")) {
								i=0;
								j = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
								proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb, uncompr_tvb_offset, 4, j,
									"Number of directories: %u", j);
								uncompr_tvb_offset += 4;
								while (i<j){
									if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "si*")) {
										guint32 len;

										len = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
										proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_string_length, uncompr_tvb,
											uncompr_tvb_offset, 4, len,
											"Directory #%d String Length: %u", i+1, len);
										proto_tree_add_text(slsk_compr_packet_tree, uncompr_tvb, uncompr_tvb_offset+4, len,
											"Directory #%d Name: %s", i+1,
											tvb_format_text(uncompr_tvb, uncompr_tvb_offset+4, len));
										uncompr_tvb_offset += 4+len;
										i2=0;
										j2 = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
										proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb,
											uncompr_tvb_offset, 4, j2,
											"Directory #%d Number of files: %u", i+1, j2);
										uncompr_tvb_offset += 4;
										while (i2<j2){
											if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "bsiisi*")) {
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_byte, uncompr_tvb,
													uncompr_tvb_offset, 1, tvb_get_guint8(uncompr_tvb, uncompr_tvb_offset),
													"Dir #%d File #%d Code: %d", i+1, i2+1, tvb_get_guint8(uncompr_tvb, uncompr_tvb_offset));
												uncompr_tvb_offset += 1;
												len = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_string_length,
													uncompr_tvb, uncompr_tvb_offset, 4, len,
													"Dir #%d File #%d String Length: %u", i+1, i2+1, len);
												proto_tree_add_text(slsk_compr_packet_tree, uncompr_tvb,
													uncompr_tvb_offset+4, len,
													"Dir #%d File #%d Filename: %s", i+1, i2+1,
													tvb_format_text(uncompr_tvb, uncompr_tvb_offset+4, len));
												uncompr_tvb_offset += 4+len;
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer,
													uncompr_tvb, uncompr_tvb_offset, 4,
													tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
													"Dir #%d File #%d Size1: %u", i+1, i2+1, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
												uncompr_tvb_offset += 4;
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer,
													uncompr_tvb, uncompr_tvb_offset, 4,
													tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
													"Dir #%d File #%d Size2: %d", i+1, i2+1, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
												uncompr_tvb_offset += 4;
												len = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_string_length,
													uncompr_tvb, uncompr_tvb_offset, 4, len,
													"Dir #%d File #%d String Length: %u", i+1, i2+1, len);
												proto_tree_add_text(slsk_compr_packet_tree, uncompr_tvb,
													uncompr_tvb_offset+4, len,
													"Dir #%d File #%d ext: %s", i+1, i2+1,
													tvb_format_text(uncompr_tvb, uncompr_tvb_offset+4, len));
												uncompr_tvb_offset += 4+len;
												i3=0;
												j3 = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer,
													uncompr_tvb, uncompr_tvb_offset, 4,
													tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
													"Dir #%d File #%d Number of attributes: %d", i+1, i2+1, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
												uncompr_tvb_offset += 4;
												while (i3<j3){
													if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "ii*")) {
														proto_tree_add_uint_format(slsk_compr_packet_tree,
															hf_slsk_integer, uncompr_tvb,
															uncompr_tvb_offset, 4,
															tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
															"Dir #%d File #%d Attr #%d type: %s (Code: %d)", i+1, i2+1, i3+1, val_to_str(tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset), slsk_attr_type, "Unknown"), tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
														uncompr_tvb_offset += 4;
														proto_tree_add_uint_format(slsk_compr_packet_tree,
															hf_slsk_integer, uncompr_tvb,
															uncompr_tvb_offset, 4,
															tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
															"Dir #%d File #%d Attr #%d value: %d", i+1, i2+1, i3+1, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
														uncompr_tvb_offset += 4;
														i3++;
													}
												}
											}
											i2++;
										}
									}
									i++;
								}
							}
						}
					}else {
						proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
							"[zlib compressed packet]");
						proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 0, 0,
							"(  compressed packet length: %d)", comprlen);
						offset += tvb_length_remaining(tvb, offset);
					}
				}
			break;

			case  7:
				if (check_slsk_format(tvb, offset, "isi")) {
					/* Server-to-Client */
					message_type = "Get User Status Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_status_code, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Status: %s (Code: %d)", val_to_str(tvb_get_letohl(tvb, offset), slsk_status_codes, "Unknown"), tvb_get_letohl(tvb, offset));
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server */
					message_type = "Get User Status";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 9:
				if (check_slsk_format(tvb, offset, "i*")) {
					/* Client-to-Client */
					message_type = "File Search Result";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;

					/* [zlib compressed] */
					comprlen = tvb_length_remaining(tvb, offset);

					if (slsk_decompress == TRUE){

						tvbuff_t *uncompr_tvb = tvb_uncompress(tvb, offset, comprlen);

						if (uncompr_tvb == NULL) {
							proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, tvb_length_remaining(tvb, offset), 0,
								"[zlib compressed packet]");
							offset += tvb_length_remaining(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, 0, 0, 0,
								"(uncompression failed !)");
						} else {

							proto_item *ti2 = proto_tree_add_item(slsk_tree, hf_slsk_compr_packet, tvb, offset, -1, FALSE);
							proto_tree *slsk_compr_packet_tree = proto_item_add_subtree(ti2, ett_slsk_compr_packet);

							proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
								"(  compressed packet length: %d)", comprlen);
							uncomprlen = tvb_length_remaining(uncompr_tvb, 0);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
								"(uncompressed packet length: %d)", uncomprlen);

							/* Dissects the uncompressed tvbuffer */
							tvb_set_child_real_data_tvbuff(tvb, uncompr_tvb);
							add_new_data_source(pinfo, uncompr_tvb,
							    "Uncompressed SoulSeek data");
							uncompr_tvb_offset = 0;
							if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "sii*")) {
								guint32 len;

								len = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
								proto_tree_add_uint(slsk_compr_packet_tree, hf_slsk_string_length, uncompr_tvb, uncompr_tvb_offset, 4, len);
								proto_tree_add_item(slsk_compr_packet_tree, hf_slsk_username, uncompr_tvb, uncompr_tvb_offset+4, len, TRUE);
								uncompr_tvb_offset += 4+len;
								proto_tree_add_item(slsk_compr_packet_tree, hf_slsk_token, uncompr_tvb, uncompr_tvb_offset, 4, TRUE);
								uncompr_tvb_offset += 4;
								i=0; j = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
								proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb, uncompr_tvb_offset, 4, j,
									"Number of files: %d", j);
								uncompr_tvb_offset += 4;
								while (i<j){
									if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "bsiisi*")) {
										proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_byte, uncompr_tvb, 0, 0, tvb_get_guint8(uncompr_tvb, uncompr_tvb_offset),
											"File #%d Code: %d", i+1, tvb_get_guint8(uncompr_tvb, uncompr_tvb_offset));
										uncompr_tvb_offset += 1;
										len = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
										proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_string_length, uncompr_tvb,
											uncompr_tvb_offset, 4, len,
											"File #%d String Length: %u", i+1, len);
										proto_tree_add_text(slsk_compr_packet_tree, uncompr_tvb, uncompr_tvb_offset+4, len,
											"File #%d Filename: %s", i+1,
											tvb_format_text(uncompr_tvb, uncompr_tvb_offset+4, len));
										uncompr_tvb_offset += 4+len;
										proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb,
											uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
											"File #%d Size1: %d", i+1, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
										uncompr_tvb_offset += 4;
										proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb,
											uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
											"File #%d Size2: %d", i+1, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
										uncompr_tvb_offset += 4;
										len = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
										proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_string_length, uncompr_tvb,
											uncompr_tvb_offset, 4, len,
											"File #%d String Length: %d", i+1, len);
										proto_tree_add_text(slsk_compr_packet_tree, uncompr_tvb, uncompr_tvb_offset+4, len,
											"File #%d ext: %s", i+1,
											tvb_format_text(uncompr_tvb, uncompr_tvb_offset+4, len));
										uncompr_tvb_offset += 4+len;
										i2=0;
										j2 = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
										proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb,
											uncompr_tvb_offset, 4, j,
											"File #%d Number of attributes: %d", i+1, j);
										uncompr_tvb_offset += 4;
										while (i2<j2){
											if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "ii*")) {
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer,
													uncompr_tvb, uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
													"File #%d Attr #%d type: %s (Code: %d)", i+1, i2+1, val_to_str(tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset), slsk_attr_type, "Unknown"), tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
												uncompr_tvb_offset += 4;
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer,
													uncompr_tvb, uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
													"File #%d Attr #%d value: %d", i+1, i2+1, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
												uncompr_tvb_offset += 4;
											}
											i2++;
										}
									}
									i++;
								}
								proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_byte, uncompr_tvb, uncompr_tvb_offset, 1, tvb_get_guint8(uncompr_tvb, uncompr_tvb_offset),
									"Free upload slots: %s (Byte: %d)", val_to_str(tvb_get_guint8(uncompr_tvb, uncompr_tvb_offset), slsk_yes_no, "Unknown"), tvb_get_guint8(uncompr_tvb, uncompr_tvb_offset));
								uncompr_tvb_offset += 1;
								proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb, uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
									"Upload speed: %d", tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
								uncompr_tvb_offset += 4;
								proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb, uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
									"In Queue: %d", tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
								uncompr_tvb_offset += 4;
							}
						}
					}else {
						proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
							"[zlib compressed packet]");
						proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
							"(  compressed packet length: %d)", comprlen);
						offset += tvb_length_remaining(tvb, offset);
					}
				}
			break;

			case 13:
				if (check_slsk_format(tvb, offset, "isss")) {
					/* Server-to-Client */
					message_type = "Say ChatRoom";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_room, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_chat_message, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "iss")) {
					/* Client-to-Server */
					message_type = "Say ChatRoom";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_room, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_chat_message, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 14:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server */
					message_type = "Join/Add Room";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_room, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "isi*")) {
					/* Server-to-Client */
					message_type = "Join Room User List";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_room, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "s*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"User #%d: %s", i+1, tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
						}
						i++;
					}
					if (check_slsk_format(tvb, offset, "i*")) {
						i=0; j = tvb_get_letohl(tvb, offset);
						proto_tree_add_uint(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
						while (i<j){
							if (check_slsk_format(tvb, offset, "i*")) {
								proto_tree_add_uint_format(slsk_tree, hf_slsk_status_code, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Status of User #%d: %s (Code: %d)", i+1, val_to_str(tvb_get_letohl(tvb, offset), slsk_status_codes, "Unknown"), tvb_get_letohl(tvb, offset));
								offset += 4;
							}
							i++;
						}
					}
					if (check_slsk_format(tvb, offset, "i*")) {
						i=0; j = tvb_get_letohl(tvb, offset);
						proto_tree_add_uint(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
						while (i<j){
							if (check_slsk_format(tvb, offset, "iiiii*")) {
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Average Speed of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Downloadnum of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Something of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Files of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Folders of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
							}
							i++;
						}
					}
					if (check_slsk_format(tvb, offset, "i*")) {
						i=0; j = tvb_get_letohl(tvb, offset);
						proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
							"Number of Slotsfull Records: %d", tvb_get_letohl(tvb, offset));
						offset += 4;
						while (i<j){
							if (check_slsk_format(tvb, offset, "i*")) {
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Slots full of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
							}
							i++;
						}
					}
				}
			break;

			case 15:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server & Server-to-Client */
					message_type = "Leave Room";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_room, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Client */
					message_type = "User Info Request";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
			break;

			case 16:
				if (check_slsk_format(tvb, offset, "issiiiiiii")) {
					/* Server-to-Client */
					message_type = "User Joined Room";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_room, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_total_uploads, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_average_speed, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_download_number, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_files, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_directories, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_slotsfull, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "isbiib") || check_slsk_format(tvb, offset, "isbsiib")) {
					/* Client-to-Client */
					message_type = "User Info Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_user_description, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_picture_exists, tvb, offset, 1, tvb_get_guint8(tvb, offset),
						"Picture exists: %s (Byte: %d)", val_to_str(tvb_get_guint8(tvb, offset), slsk_yes_no, "Unknown"), tvb_get_guint8(tvb, offset));
					offset += 1;
					if ( tvb_get_guint8(tvb, offset -1 ) == 1 ) {
						proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset),
							"Picture Size: %d", tvb_get_letohl(tvb, offset));
						proto_tree_add_item(slsk_tree, hf_slsk_picture, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
						offset += 4+tvb_get_letohl(tvb, offset);
					}
					proto_tree_add_uint(slsk_tree, hf_slsk_total_uploads, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_queued_uploads, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint_format(slsk_tree, hf_slsk_slots_available, tvb, offset, 1, tvb_get_guint8(tvb, offset),
						"Upload Slots available: %s (Byte: %d)", val_to_str(tvb_get_guint8(tvb, offset), slsk_yes_no, "Unknown"), tvb_get_guint8(tvb, offset));
					offset += 1;
				}
			break;

			case 17:
				if (check_slsk_format(tvb, offset, "iss")) {
					/* Server-to-Client */
					message_type = "User Left Room";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_room, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 18:
				if (check_slsk_format(tvb, offset, "iiss")) {
					/* Client-to-Server */
					guint32 len;

					message_type = "Connect To Peer";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, TRUE);
					offset += 4;
					len = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len);
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, len, FALSE);
					offset += 4+len;
					len = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len);
					str = tvb_get_ephemeral_string(tvb, offset+4, len);
					proto_tree_add_string_format(slsk_tree, hf_slsk_connection_type, tvb, offset+4, len, str,
						"Connection Type: %s (Char: %s)", connection_type(str),
						format_text(str, len));
					offset += 4+len;
				}
				else if (check_slsk_format(tvb, offset, "issiii")) {
					/* Server-to-Client */
					guint32 len;

					message_type = "Connect To Peer";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					len = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len);
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, len, FALSE);
					offset += 4+len;
					len = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len);
					str = tvb_get_ephemeral_string(tvb, offset+4, len);
					proto_tree_add_string_format(slsk_tree, hf_slsk_connection_type, tvb, offset+4, len, str,
						"Connection Type: %s (Char: %s)", connection_type(str),
						format_text(str, len));
					offset += 4+len;
					proto_tree_add_item(slsk_tree, hf_slsk_ip, tvb, offset, 4, FALSE);
					offset += 4;
					proto_tree_add_item(slsk_tree, hf_slsk_port, tvb, offset, 4, TRUE);
					offset += 4;
					proto_tree_add_item(slsk_tree, hf_slsk_token, tvb, offset, 4, TRUE);
					offset += 4;
				}
			break;

			case 22:
				if (check_slsk_format(tvb, offset, "iss")) {
					/* Client-to-Server */
					message_type = "Message User Send";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_chat_message, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "iiiss")) {
					/* Server-to-Client */
					message_type = "Message User Receive";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_chat_message_id, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_timestamp, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_chat_message, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 23:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Client-to-Server */
					message_type = "Message User Receive Ack";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_chat_message_id, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 26:
				if (check_slsk_format(tvb, offset, "iis")) {
					/* Client-to-Server */
					message_type = "File Search";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_search_text, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 28:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Client-to-Server */
					message_type = "Set Status";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint_format(slsk_tree, hf_slsk_status_code, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Status: %s (Code: %d)", val_to_str(tvb_get_letohl(tvb, offset), slsk_status_codes, "Unknown"), tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 32:
				if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Server */
					message_type = "Ping";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
			break;

			case 34:
				if (check_slsk_format(tvb, offset, "isi")) {
					/* Client-to-Server */
					message_type = "Update Upload Speed";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_average_speed, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 35:
				if (check_slsk_format(tvb, offset, "iii")) {
					/* Client-to-Server */
					message_type = "Shared Files & Folders ";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_folder_count, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_file_count, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 36:
				if (check_slsk_format(tvb, offset, "isiiiii")) {
					/* Server-to-Client */
					message_type = "Get User Stats Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_average_speed, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_download_number, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_files, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_directories, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Client */
					/* Client-to-Server: send after login successful */
					message_type = "Get User Stats";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "iis")) {
					/* Client-to-Client */
					message_type = "Folder Contents Request";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_directory, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 37:
				if (check_slsk_format(tvb, offset, "i*")) {
					/* Client-to-Client */
					message_type = "Folder Contents Response";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;

					/* [zlib compressed] */
					comprlen = tvb_length_remaining(tvb, offset);

					if (slsk_decompress == TRUE){

						tvbuff_t *uncompr_tvb = tvb_uncompress(tvb, offset, comprlen);

						if (uncompr_tvb == NULL) {
							proto_tree_add_text(slsk_tree, tvb, offset, -1,
								"[zlib compressed packet]");
							offset += tvb_length_remaining(tvb, offset);
							proto_tree_add_text(slsk_tree, tvb, 0, 0,
								"[uncompression failed !]");
						} else {

							proto_item *ti2 = proto_tree_add_item(slsk_tree, hf_slsk_compr_packet, tvb, offset, -1, FALSE);
							proto_tree *slsk_compr_packet_tree = proto_item_add_subtree(ti2, ett_slsk_compr_packet);

							proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
								"[compressed packet length: %d]", comprlen);
							uncomprlen = tvb_length_remaining(uncompr_tvb, 0);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
								"[uncompressed packet length: %d]", uncomprlen);

							/* Dissects the uncompressed tvbuffer */
							tvb_set_child_real_data_tvbuff(tvb, uncompr_tvb);
							add_new_data_source(pinfo, uncompr_tvb,
							    "Uncompressed SoulSeek data");
							uncompr_tvb_offset = 0;
							if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "isi*")) {
								guint32 len;

								proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb,
									uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
									"Token: %d", tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
								uncompr_tvb_offset += 4;
								len = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
								proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_string_length,
									uncompr_tvb, uncompr_tvb_offset, 4, len,
									"Directory Name String Length: %u", len);
								proto_tree_add_text(slsk_compr_packet_tree, uncompr_tvb, uncompr_tvb_offset+4, len,
									"Directory Name: %s", tvb_format_text(uncompr_tvb, uncompr_tvb_offset+4, len));
								uncompr_tvb_offset += 4+len;

								i=0; j = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
								proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb,
									uncompr_tvb_offset, 4, j,
									"Number of directories: %d", j);
								uncompr_tvb_offset += 4;
								while (i<j){
									if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "si*")) {
										len = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
										proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_string_length,
											uncompr_tvb, uncompr_tvb_offset, 4, len,
											"Directory #%d Name String Length: %u", i+1, len);
										proto_tree_add_text(slsk_compr_packet_tree, uncompr_tvb, uncompr_tvb_offset+4, len,
											"Directory #%d Name: %s", i+1,
											tvb_format_text(uncompr_tvb, uncompr_tvb_offset+4, len));
										uncompr_tvb_offset += 4+len;
										i2 = 0;
										j2 = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
										proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb,
											uncompr_tvb_offset, 4, j2,
											"Directory #%d Number of files: %d", i+1, j2);
										uncompr_tvb_offset += 4;
										while (i2<j2){
											if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "bsiisi*")) {
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_byte,
													uncompr_tvb, uncompr_tvb_offset, 1, tvb_get_guint8(uncompr_tvb, uncompr_tvb_offset),
													"Dir #%d File #%d Code: %d", i+1, i2+1, tvb_get_guint8(uncompr_tvb, uncompr_tvb_offset));
												uncompr_tvb_offset += 1;
												len = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_string_length,
													uncompr_tvb, uncompr_tvb_offset, 4, len,
													"Dir #%d File #%d String Length: %d", i+1, i2+1, len);
												proto_tree_add_text(slsk_compr_packet_tree, uncompr_tvb,
													uncompr_tvb_offset+4, len,
													"Dir #%d File #%d Filename: %s", i+1, i2+1,
													tvb_format_text(uncompr_tvb, uncompr_tvb_offset+4, len));
												uncompr_tvb_offset += 4+len;
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer,
													uncompr_tvb, uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
													"Dir #%d File #%d Size1: %d", i+1, i2+1, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
												uncompr_tvb_offset += 4;
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer,
													uncompr_tvb, uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
													"Dir #%d File #%d Size2: %d", i+1, i2+1, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
												uncompr_tvb_offset += 4;
												len = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_string_length,
													uncompr_tvb, uncompr_tvb_offset, 4, len,
													"Dir #%d File #%d String Length: %d", i+1, i2+1, len);
												proto_tree_add_text(slsk_compr_packet_tree, uncompr_tvb,
													uncompr_tvb_offset+4, len,
													"Dir #%d File #%d ext: %s", i+1, i2+1,
													tvb_format_text(uncompr_tvb, uncompr_tvb_offset+4, len));
												uncompr_tvb_offset += 4+len;
												i3 = 0;
												j3 = tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset);
												proto_tree_add_uint_format(slsk_compr_packet_tree, hf_slsk_integer, uncompr_tvb,
													uncompr_tvb_offset, 4, j3,
													"Dir #%d File #%d Number of attributes: %d", i+1, i2+1, j3);
												uncompr_tvb_offset += 4;
												while (i3<j3){
													if (check_slsk_format(uncompr_tvb, uncompr_tvb_offset, "ii*")) {
														proto_tree_add_uint_format(slsk_compr_packet_tree,
															hf_slsk_integer, uncompr_tvb,
															uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
															"Dir #%d File #%d Attr #%d type: %s (Code: %d)", i+1, i2+1, i3+1, val_to_str(tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset), slsk_attr_type, "Unknown"), tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
														uncompr_tvb_offset += 4;
														proto_tree_add_uint_format(slsk_compr_packet_tree,
															hf_slsk_integer, uncompr_tvb,
															uncompr_tvb_offset, 4, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset),
															"Dir #%d File #%d Attr #%d value: %d", i+1, i2+1, i3+1, tvb_get_letohl(uncompr_tvb, uncompr_tvb_offset));
														uncompr_tvb_offset += 4;
													}
													i3++;
												}
											}
											i2++;
										}
									}
									i++;
								}
							}
						}
					}else {
						proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
							"[zlib compressed packet]");
						proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, -1, 0,
							"(  compressed packet length: %d)", comprlen);
						offset += tvb_length_remaining(tvb, offset);
					}
				}
			break;

			case 40:
				if (check_slsk_format(tvb, offset, "isi")) {
					/* Server-to-Client */
					message_type = "Queued Downloads";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_slotsfull, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "iiis") || check_slsk_format(tvb, offset, "iiisii")) {
					/* Client-to-Client */
					message_type = "Transfer Request";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					i = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_transfer_direction, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Transfer Direction: %s (Code: %d)", val_to_str(tvb_get_letohl(tvb, offset), slsk_transfer_direction, "Unknown"), tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_filename, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					if (i == 1){
						proto_tree_add_uint(slsk_tree, hf_slsk_size, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
						proto_tree_add_uint(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
					}
				}

			break;

			case 41:
				if (check_slsk_format(tvb, offset, "iibs") || check_slsk_format(tvb, offset, "iibii") || check_slsk_format(tvb, offset, "iib")) {
					/* Client-to-Client */
					message_type = "Transfer Response";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					i = tvb_get_guint8(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_allowed, tvb, offset, 1, tvb_get_guint8(tvb, offset),
						"Download allowed: %s (Byte: %d)", val_to_str(tvb_get_guint8(tvb, offset), slsk_yes_no, "Unknown"), tvb_get_guint8(tvb, offset));
					offset += 1;
					if ( i == 1 ) {
						if ( tvb_length_remaining(tvb, offset) == 8 ) {
							proto_tree_add_uint(slsk_tree, hf_slsk_size, tvb, offset, 4, tvb_get_letohl(tvb, offset));
							offset += 4;
							proto_tree_add_uint(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset));
							offset += 4;
						}
					} else {
						proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						proto_tree_add_item(slsk_tree, hf_slsk_string, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
						offset += 4+tvb_get_letohl(tvb, offset);
					}
				}
			break;

			case 42:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Client */
					message_type = "Placehold Upload";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_filename, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 43:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Client */
					message_type = "Queue Upload";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_filename, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 44:
				if (check_slsk_format(tvb, offset, "isi")) {
					/* Client-to-Client */
					message_type = "Place In Queue";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_filename, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_place_in_queue, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 46:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Client */
					message_type = "Upload Failed";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_filename, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 50:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server */
					message_type = "Make Own Recommendation";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_recommendation, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "isi")) {
					/* Client-to-Server */
					message_type = "Remove Own Recommendation";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_recommendation, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_ranking, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "iss")) {
					/* Client-to-Client */
					message_type = "Queue Failed";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_filename, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_string, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 51:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server: "Add Things I like" */
					/* Client-to-Client:  "Place In Queue Request" */
					message_type = "Add Things I like / Place In Queue Request";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_filename, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 52:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server */
					message_type = "Remove Things I like";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_filename, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 54:
				if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Server */
					message_type = "Get Recommendations";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "ii*")) {
					/* Server-to-Client */
					message_type = "Get Recommendations Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Number of Recommendations: %d", tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "si*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"Recommendation #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
							proto_tree_add_uint_format(slsk_tree, hf_slsk_ranking, tvb, offset, 4, tvb_get_letohl(tvb, offset),
								"Ranking #%d: %d", i+1, tvb_get_letohl(tvb, offset));
							offset += 4;
						}
						i++;
					}
				}
			break;

			case 55:
				if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Server */
					message_type = "Type 55";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
			break;

			case 56:
				if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Server */
					message_type = "Get Global Rankings";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "ii*")) {
					/* Server-to-Client */
					message_type = "Get Global Rankings Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Number of Recommendations: %d", tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "si*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"Recommendation #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
							proto_tree_add_uint_format(slsk_tree, hf_slsk_ranking, tvb, offset, 4, tvb_get_letohl(tvb, offset),
								"Ranking #%d: %d", i+1, tvb_get_letohl(tvb, offset));
							offset += 4;
						}
						i++;
					}
				}
			break;

			case 57:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server */
					message_type = "Get User Recommendations";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "isi*")) {
					/* Server-to-Client */
					message_type = "Get User Recommendations Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Number of Recommendations: %d", tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "s*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"Recommendation #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
						}
						i++;
					}
				}
			break;

			case 58:
				if (check_slsk_format(tvb, offset, "isi*")) {
					/* Client-to-Server */
					message_type = "Admin Command";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_string, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_number_of_users, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Number of Strings: %d", tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "s*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"String #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
						}
						i++;
					}
				}
			break;

			case 60:
				if (check_slsk_format(tvb, offset, "isii")) {
					/* Client-to-Server & Server-to-Client */
					message_type = "Place In Line Response";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_place_in_queue, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 62:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Server-to-Client */
					message_type = "Room Added";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_room, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 63:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Server-to-Client */
					message_type = "Room Removed";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_room, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 64:
				if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Server */
					message_type = "Room List Request";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "ii*")) {
					/* Server-to-Client */
					message_type = "Room List";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_number_of_rooms, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "s*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"Room #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
						}
						i++;
					}
					if (check_slsk_format(tvb, offset, "i*")) {
						i=0;
						proto_tree_add_uint(slsk_tree, hf_slsk_number_of_rooms, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
						while (i<j){
							if (check_slsk_format(tvb, offset, "i*")) {
								proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Users in Room #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
							}
							i++;
						}
					}
				}
			break;

			case 65:
				if (check_slsk_format(tvb, offset, "isissiii")) {
					/* Server-to-Client */
					message_type = "Exact File Search";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_filename, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_directory, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 16, 0,
						"(+12 0 bytes)");
					offset += 12;
				}
				else if (check_slsk_format(tvb, offset, "iissiiib")) {
					/* Client-to-Server */
					message_type = "Exact File Search";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_filename, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_directory, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 13, 0,
						"(+13 0 bytes)");
					offset += 13;
				}
			break;

			case 66:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Server-to-Client */
					message_type = "Admin Message";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_chat_message, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 67:
				if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Server */
					message_type = "Global User List Request";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "isi*")) { 		/* same as case 14 */
					/* Server-to-Client */
					message_type = "Global User List";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_room, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "s*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"User #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
						}
						i++;
					}
					if (check_slsk_format(tvb, offset, "i*")) {
						i=0; j = tvb_get_letohl(tvb, offset);
						proto_tree_add_uint(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, j);
						offset += 4;
						while (i<j){
							if (check_slsk_format(tvb, offset, "i*")) {
								proto_tree_add_uint_format(slsk_tree, hf_slsk_status_code, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Status of User #%d: %s (Code: %d)", i+1, val_to_str(tvb_get_letohl(tvb, offset), slsk_status_codes, "Unknown"), tvb_get_letohl(tvb, offset));
								offset += 4;
							}
							i++;
						}
					}
					if (check_slsk_format(tvb, offset, "i*")) {
						i=0; j = tvb_get_letohl(tvb, offset);
						proto_tree_add_uint(slsk_tree, hf_slsk_users_in_room, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
						while (i<j){
							if (check_slsk_format(tvb, offset, "iiiii*")) {
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Average Speed of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Downloadnum of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Something of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Files of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Folders of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
							}
							i++;
						}
					}
					if (check_slsk_format(tvb, offset, "i*")) {
						i=0; j = tvb_get_letohl(tvb, offset);
						proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
							"Number of Slotsfull Records: %d", tvb_get_letohl(tvb, offset));
						offset += 4;
						while (i<j){
							if (check_slsk_format(tvb, offset, "i*")) {
								proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
									"Slots full of User #%d: %d", i+1, tvb_get_letohl(tvb, offset));
								offset += 4;
							}
							i++;
						}
					}
				}
			break;

			case 68:
				if (check_slsk_format(tvb, offset, "isiiiis")) {
					message_type = "Tunneled Message";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					proto_tree_add_uint(slsk_tree, hf_slsk_code, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_ipv4(slsk_tree, hf_slsk_ip, tvb, offset, 4, tvb_get_ntohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_port, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_chat_message, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 69:
				if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Server */
					message_type = "Privileged User List Request";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "ii*")) {
					/* Server-to-Client */
					message_type = "Privileged User List";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_number_of_users, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Number of Priviledged Users: %d", tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "s*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"User #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
						}
						i++;
					}
				}
			break;

			case 71:
				if (check_slsk_format(tvb, offset, "ib")) {
					/* Client-to-Server */
					message_type = "Get Parent List";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_byte, tvb, offset, 1, tvb_get_guint8(tvb, offset));
					offset += 1;
				}
			break;

			case 73:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Client-to-Server */
					message_type = "Type 73";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 83:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Server-to-Client */
					message_type = "Parent Min Speed";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_parent_min_speed, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 84:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Server-to-Client */
					message_type = "Parent Speed Connection Ratio";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_parent_speed_connection_ratio, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 86:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Server-to-Client */
					message_type = "Parent Inactivity Before Disconnect";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_seconds_parent_inactivity_before_disconnect, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 87:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Server-to-Client */
					message_type = "Server Inactivity Before Disconnect";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_seconds_server_inactivity_before_disconnect, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 88:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Server-to-Client */
					message_type = "Nodes In Cache Before Disconnect";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_nodes_in_cache_before_disconnect, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 90:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Server-to-Client */
					message_type = "Seconds Before Ping Children";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_seconds_before_ping_children, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 91:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Server-to-Client */
					message_type = "Add To Privileged";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 92:
				if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Server */
					message_type = "Check Privileges";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "ii")) {
					/* Server-to-Client */
					message_type = "Check Privileges Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_number_of_days, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 93:
				if (check_slsk_format(tvb, offset, "ibisis")) {
					/* Server-to-Client */
					message_type = "Embedded Message";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					if ( tvb_get_guint8(tvb, offset) == 3 ){
						/* Client-to-Client */
						message_type = "Distributed Search";
						proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 1, msg_code,
								       "Embedded Message Type: %s (Byte: %d)", message_type, 3);
						offset += 1;
						proto_tree_add_uint(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
						proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
						offset += 4+tvb_get_letohl(tvb, offset);
						proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
						proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						proto_tree_add_item(slsk_tree, hf_slsk_search_text, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
						offset += 4+tvb_get_letohl(tvb, offset);
					}
				}
			break;

			case 100:
				if (check_slsk_format(tvb, offset, "ib")) {
					/* Client-to-Server */
					message_type = "Become Parent";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_byte, tvb, offset, 1, tvb_get_guint8(tvb, offset));
					offset += 1;
				}
			break;

			case 102:
				if (check_slsk_format(tvb, offset, "ii*")) {
					/* Server-to-Client */
					message_type = "Random Parent Addresses";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_number_of_users, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Number of Parent Addresses: %d", tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "sii*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"User #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
							proto_tree_add_item(slsk_tree, hf_slsk_ip, tvb, offset, 4, FALSE);
							offset += 4;
							proto_tree_add_uint_format(slsk_tree, hf_slsk_port, tvb, offset, 4, tvb_get_letohl(tvb, offset),
								"Port Number #%d: %d", i+1, tvb_get_letohl(tvb, offset));
							offset += 4;
						}
						i++;
					}
				}
			break;

			case 103:
				if (check_slsk_format(tvb, offset, "iis")) {
					/* Server-to-Client */
					message_type = "Send Wishlist Entry";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_search_text, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
			break;

			case 104:
				if (check_slsk_format(tvb, offset, "ii")) {
					/* Server-to-Client */
					message_type = "Type 104";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			case 110:
				if (check_slsk_format(tvb, offset, "i")) {
					/* Client-to-Server */
					message_type = "Get Similar Users";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
				else if (check_slsk_format(tvb, offset, "ii*")) {
					/* Server-to-Client */
					message_type = "Get Similar Users Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_number_of_users, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Number of Users: %d", tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "si*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"User #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
							proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
								"Same Recommendations #%d: %d", i+1, tvb_get_letohl(tvb, offset));
							offset += 4;
						}
						i++;
					}
				}
			break;

			case 111:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server */
					message_type = "Get Recommendations for Item";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_recommendation, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "isi*")) {
					/* Server-to-Client */
					message_type = "Get Recommendations for Item Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_recommendation, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Number of Recommendations: %d", tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "si*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"Recommendation #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
							proto_tree_add_uint_format(slsk_tree, hf_slsk_ranking, tvb, offset, 4, tvb_get_letohl(tvb, offset),
								"Ranking #%d: %d", i+1, tvb_get_letohl(tvb, offset));
							offset += 4;
						}
						i++;
					}
				}
			break;

			case 112:
				if (check_slsk_format(tvb, offset, "is")) {
					/* Client-to-Server */
					message_type = "Get Similar Users for Item";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_recommendation, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "isi*")) {
					/* Server-to-Client */
					message_type = "Get Similar Users for Item Reply";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_recommendation, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
					i=0; j = tvb_get_letohl(tvb, offset);
					proto_tree_add_uint_format(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset),
						"Number of Recommendations: %d", tvb_get_letohl(tvb, offset));
					offset += 4;
					while (i<j){
						if (check_slsk_format(tvb, offset, "s*")) {
							guint32 len;

							len = tvb_get_letohl(tvb, offset);
							proto_tree_add_uint_format(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len,
								"String #%d Length: %d", i+1, len);
							proto_tree_add_text(slsk_tree, tvb, offset+4, len,
								"Username #%d: %s", i+1,
								tvb_format_text(tvb, offset+4, len));
							offset += 4+len;
						}
						i++;
					}
				}
			break;

			case 1001:
				if (check_slsk_format(tvb, offset, "iis")) {
					/* Client-to-Server */
					message_type = "Can't Connect To Peer";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
					offset += 4+tvb_get_letohl(tvb, offset);
				}
				else if (check_slsk_format(tvb, offset, "ii")) {
					/* Server-to-Client */
					message_type = "Can't Connect To Peer";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
					proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
					offset += 4;
				}
			break;

			default:
				if (check_slsk_format(tvb, offset, "bisis")) {
					if ( tvb_get_guint8(tvb, offset) == 3 ){
						/* Client-to-Client */
						message_type = "Distributed Search";
						proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 1, msg_code,
								       "Message Type: %s (Byte: %d)", message_type, 3);
						offset += 1;
						proto_tree_add_uint(slsk_tree, hf_slsk_integer, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
						proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
						offset += 4+tvb_get_letohl(tvb, offset);
						proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
						proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						proto_tree_add_item(slsk_tree, hf_slsk_search_text, tvb, offset+4, tvb_get_letohl(tvb, offset), FALSE);
						offset += 4+tvb_get_letohl(tvb, offset);
					}
				}
				else if (check_slsk_format(tvb, offset, "bssi")) {
					if ( tvb_get_guint8(tvb, offset) == 1 ){
						/* Client-to-Client */
						guint32 len;

						message_type = "Peer Init";
						proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 1, msg_code,
								       "Message Type: %s (Byte: %d)", message_type, 1);
						offset += 1;
						len = tvb_get_letohl(tvb, offset);
						proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len);
						proto_tree_add_item(slsk_tree, hf_slsk_username, tvb, offset+4, len, FALSE);
						offset += 4+len;
						len = tvb_get_letohl(tvb, offset);
						proto_tree_add_uint(slsk_tree, hf_slsk_string_length, tvb, offset, 4, len);
						str = tvb_get_ephemeral_string(tvb, offset+4, len);
						proto_tree_add_string_format(slsk_tree, hf_slsk_connection_type, tvb, offset+4, len, str,
							"Connection Type: %s (Char: %s)", connection_type(str),
							format_text(str, len));
						offset += 4+len;
						proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
					}
				}
				else if (check_slsk_format(tvb, offset, "bi")) {
					if ( tvb_get_guint8(tvb, offset) == 0 ){
						/* Client-to-Client */
						message_type = "Pierce Fw";
						proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 1, msg_code,
								       "Message Type: %s (Byte: %d)", message_type, 0);
						offset += 1;
						proto_tree_add_uint(slsk_tree, hf_slsk_token, tvb, offset, 4, tvb_get_letohl(tvb, offset));
						offset += 4;
					}
				}
				else {
					message_type = "Unknown";
					proto_tree_add_uint_format(slsk_tree, hf_slsk_message_code, tvb, offset, 4, msg_code,
							       "Message Type: %s (Code: %02d)", message_type, msg_code);
					offset += 4;
				}
			break;

		}

	}


}


static void dissect_slsk(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, slsk_desegment, 4, get_slsk_pdu_len, dissect_slsk_pdu);

}


/* Register the protocol with Ethereal */

void
proto_register_slsk(void)
{

/* Setup list of header fields  */
	static hf_register_info hf[] = {
		{ &hf_slsk_integer,
			{ "Integer", "slsk.integer",
			FT_UINT32, BASE_DEC, NULL, 0, "Integer", HFILL } },
		{ &hf_slsk_string,
			{ "String", "slsk.string",
			FT_STRING, BASE_NONE, NULL, 0, "String", HFILL } },
		{ &hf_slsk_byte,
			{ "Byte", "slsk.byte",
			FT_UINT8, BASE_DEC, NULL, 0, "Byte", HFILL } },
		{ &hf_slsk_message_length,
			{ "Message Length", "slsk.message.length",
			FT_UINT32, BASE_DEC, NULL, 0, "Message Length", HFILL } },
		{ &hf_slsk_message_code,
			{ "Message Code", "slsk.message.code",
			FT_UINT32, BASE_DEC, NULL, 0, "Message Code", HFILL } },
		{ &hf_slsk_client_ip,
			{ "Client IP", "slsk.server.ip",
			FT_IPv4, BASE_DEC, NULL, 0, "Client IP Address", HFILL } },
		{ &hf_slsk_server_ip,
			{ "SoulSeek Server IP", "slsk.server.ip",
			FT_UINT32, BASE_DEC, NULL, 0, "SoulSeek Server IP", HFILL } },
		{ &hf_slsk_string_length,
			{ "String Length", "slsk.string.length",
			FT_UINT32, BASE_DEC, NULL, 0, "String Length", HFILL } },
		{ &hf_slsk_username,
			{ "Username", "slsk.username",
			FT_STRING, BASE_NONE, NULL, 0, "Username", HFILL } },
		{ &hf_slsk_password,
			{ "Password", "slsk.password",
			FT_STRING, BASE_NONE, NULL, 0, "Password", HFILL } },
		{ &hf_slsk_version,
			{ "Version", "slsk.version",
			FT_UINT32, BASE_DEC, NULL, 0, "Version", HFILL } },
		{ &hf_slsk_login_successful,
			{ "Login successful", "slsk.login.successful",
			FT_UINT8, BASE_DEC, NULL, 0, "Login Successful", HFILL } },
		{ &hf_slsk_login_message,
			{ "Login Message", "slsk.login.message",
			FT_STRING, BASE_NONE, NULL, 0, "Login Message", HFILL } },
		{ &hf_slsk_port,
			{ "Port Number", "slsk.port.number",
			FT_UINT32, BASE_DEC, NULL, 0, "Port Number", HFILL } },
		{ &hf_slsk_ip,
			{ "IP Address", "slsk.ip.address",
			FT_IPv4, BASE_DEC, NULL, 0, "IP Address", HFILL } },
		{ &hf_slsk_user_exists,
			{ "user exists", "slsk.user.exists",
			FT_UINT8, BASE_DEC, NULL, 0, "User exists", HFILL } },
		{ &hf_slsk_status_code,
			{ "Status Code", "slsk.status.code",
			FT_UINT32, BASE_DEC, NULL, 0, "Status Code", HFILL } },
		{ &hf_slsk_room,
			{ "Room", "slsk.room",
			FT_STRING, BASE_NONE, NULL, 0, "Room", HFILL } },
		{ &hf_slsk_chat_message,
			{ "Chat Message", "slsk.chat.message",
			FT_STRING, BASE_NONE, NULL, 0, "Chat Message", HFILL } },
		{ &hf_slsk_users_in_room,
			{ "Users in Room", "slsk.room.users",
			FT_UINT32, BASE_DEC, NULL, 0, "Number of Users in Room", HFILL } },
		{ &hf_slsk_token,
			{ "Token", "slsk.token",
			FT_UINT32, BASE_DEC, NULL, 0, "Token", HFILL } },
		{ &hf_slsk_connection_type,
			{ "Connection Type", "slsk.connection.type",
			FT_STRING, BASE_NONE, NULL, 0, "Connection Type", HFILL } },
		{ &hf_slsk_chat_message_id,
			{ "Chat Message ID", "slsk.chat.message.id",
			FT_UINT32, BASE_DEC, NULL, 0, "Chat Message ID", HFILL } },
		{ &hf_slsk_timestamp,
			{ "Timestamp", "slsk.timestamp",
			FT_UINT32, BASE_DEC, NULL, 0, "Timestamp", HFILL } },
		{ &hf_slsk_search_text,
			{ "Search Text", "slsk.search.text",
			FT_STRING, BASE_NONE, NULL, 0, "Search Text", HFILL } },
		{ &hf_slsk_folder_count,
			{ "Folder Count", "slsk.folder.count",
			FT_UINT32, BASE_DEC, NULL, 0, "Folder Count", HFILL } },
		{ &hf_slsk_file_count,
			{ "File Count", "slsk.file.count",
			FT_UINT32, BASE_DEC, NULL, 0, "File Count", HFILL } },
		{ &hf_slsk_average_speed,
			{ "Average Speed", "slsk.average.speed",
			FT_UINT32, BASE_DEC, NULL, 0, "Average Speed", HFILL } },
		{ &hf_slsk_download_number,
			{ "Download Number", "slsk.download.number",
			FT_UINT32, BASE_DEC, NULL, 0, "Download Number", HFILL } },
		{ &hf_slsk_files,
			{ "Files", "slsk.files",
			FT_UINT32, BASE_DEC, NULL, 0, "Files", HFILL } },
		{ &hf_slsk_directories,
			{ "Directories", "slsk.directories",
			FT_UINT32, BASE_DEC, NULL, 0, "Directories", HFILL } },
		{ &hf_slsk_slotsfull,
			{ "Slots full", "slsk.slots.full",
			FT_UINT32, BASE_DEC, NULL, 0, "Upload Slots Full", HFILL } },
		{ &hf_slsk_place_in_queue,
			{ "Place in Queue", "slsk.queue.place",
			FT_UINT32, BASE_DEC, NULL, 0, "Place in Queue", HFILL } },
		{ &hf_slsk_number_of_rooms,
			{ "Number of Rooms", "slsk.room.count",
			FT_UINT32, BASE_DEC, NULL, 0, "Number of Rooms", HFILL } },
		{ &hf_slsk_filename,
			{ "Filename", "slsk.filename",
			FT_STRING, BASE_NONE, NULL, 0, "Filename", HFILL } },
		{ &hf_slsk_directory,
			{ "Directory", "slsk.directory",
			FT_STRING, BASE_NONE, NULL, 0, "Directory", HFILL } },
		{ &hf_slsk_size,
			{ "Size", "slsk.size",
			FT_UINT32, BASE_DEC, NULL, 0, "File Size", HFILL } },
		{ &hf_slsk_checksum,
			{ "Checksum", "slsk.checksum",
			FT_UINT32, BASE_DEC, NULL, 0, "Checksum", HFILL } },
		{ &hf_slsk_code,
			{ "Code", "slsk.code",
			FT_UINT32, BASE_DEC, NULL, 0, "Code", HFILL } },
		{ &hf_slsk_number_of_users,
			{ "Number of Users", "slsk.user.count",
			FT_UINT32, BASE_DEC, NULL, 0, "Number of Users", HFILL } },
		{ &hf_slsk_number_of_days,
			{ "Number of Days", "slsk.day.count",
			FT_UINT32, BASE_DEC, NULL, 0, "Number of Days", HFILL } },
		{ &hf_slsk_transfer_direction,
			{ "Transfer Direction", "slsk.transfer.direction",
			FT_UINT32, BASE_DEC, NULL, 0, "Transfer Direction", HFILL } },
		{ &hf_slsk_user_description,
			{ "User Description", "slsk.user.description",
			FT_STRING, BASE_NONE, NULL, 0, "User Description", HFILL } },
		{ &hf_slsk_picture_exists,
			{ "Picture exists", "slsk.user.picture.exists",
			FT_UINT8, BASE_DEC, NULL, 0, "User has a picture", HFILL } },
		{ &hf_slsk_picture,
			{ "Picture", "slsk.user.picture",
			FT_STRING, BASE_NONE, NULL, 0, "User Picture", HFILL } },
		{ &hf_slsk_user_uploads,
			{ "User uploads", "slsk.uploads.user",
			FT_UINT32, BASE_DEC, NULL, 0, "User uploads", HFILL } },
		{ &hf_slsk_total_uploads,
			{ "Total uploads allowed", "slsk.uploads.total",
			FT_UINT32, BASE_DEC, NULL, 0, "Total uploads allowed", HFILL } },
		{ &hf_slsk_queued_uploads,
			{ "Queued uploads", "slsk.uploads.queued",
			FT_UINT32, BASE_DEC, NULL, 0, "Queued uploads", HFILL } },
		{ &hf_slsk_slots_available,
			{ "Upload Slots available", "slsk.uploads.available",
			FT_UINT8, BASE_DEC, NULL, 0, "Upload Slots available", HFILL } },
		{ &hf_slsk_allowed,
			{ "Download allowed", "slsk.user.allowed",
			FT_UINT8, BASE_DEC, NULL, 0, "allowed", HFILL } },
		{ &hf_slsk_compr_packet,
			{ "[zlib compressed packet]", "slsk.compr.packet",
			FT_NONE, BASE_NONE, NULL, 0, "zlib compressed packet", HFILL } },
		{ &hf_slsk_parent_min_speed,
			{ "Parent Min Speed", "slsk.parent.min.speed",
			FT_UINT32, BASE_DEC, NULL, 0, "Parent Min Speed", HFILL } },
		{ &hf_slsk_parent_speed_connection_ratio,
			{ "Parent Speed Connection Ratio", "slsk.parent.speed.connection.ratio",
			FT_UINT32, BASE_DEC, NULL, 0, "Parent Speed Connection Ratio", HFILL } },
		{ &hf_slsk_seconds_parent_inactivity_before_disconnect,
			{ "Seconds Parent Inactivity Before Disconnect", "slsk.seconds.parent.inactivity.before.disconnect",
			FT_UINT32, BASE_DEC, NULL, 0, "Seconds Parent Inactivity Before Disconnect", HFILL } },
		{ &hf_slsk_seconds_server_inactivity_before_disconnect,
			{ "Seconds Server Inactivity Before Disconnect", "slsk.seconds.server.inactivity.before.disconnect",
			FT_UINT32, BASE_DEC, NULL, 0, "Seconds Server Inactivity Before Disconnect", HFILL } },
		{ &hf_slsk_nodes_in_cache_before_disconnect,
			{ "Nodes In Cache Before Disconnect", "slsk.nodes.in.cache.before.disconnect",
			FT_UINT32, BASE_DEC, NULL, 0, "Nodes In Cache Before Disconnect", HFILL } },
		{ &hf_slsk_seconds_before_ping_children,
			{ "Seconds Before Ping Children", "slsk.seconds.before.ping.children",
			FT_UINT32, BASE_DEC, NULL, 0, "Seconds Before Ping Children", HFILL } },
		{ &hf_slsk_recommendation,
			{ "Recommendation", "slsk.recommendation",
			FT_STRING, BASE_NONE, NULL, 0, "Recommendation", HFILL } },
		{ &hf_slsk_ranking,
			{ "Ranking", "slsk.ranking",
			FT_UINT32, BASE_DEC, NULL, 0, "Ranking", HFILL } },
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_slsk,
		&ett_slsk_compr_packet,
	};
	module_t *slsk_module;

/* Registers the protocol name and description */
	proto_slsk = proto_register_protocol("SoulSeek Protocol", "SoulSeek", "slsk");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_slsk, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	slsk_module = prefs_register_protocol(proto_slsk, NULL);

/* Registers the options in the menu preferences */
	prefs_register_bool_preference(slsk_module, "desegment",
	    "Reassemble SoulSeek messages spanning multiple TCP segments",
	    "Whether the SoulSeek dissector should reassemble messages spanning multiple TCP segments."
	    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &slsk_desegment);
#ifdef HAVE_LIBZ
	prefs_register_bool_preference(slsk_module, "decompress",
	    "Decompress zlib compressed packets inside SoulSeek messages",
	    "Whether the SoulSeek dissector should decompress all zlib compressed packets inside messages",
	    &slsk_decompress);
#endif

}


void
proto_reg_handoff_slsk(void)
{
	dissector_handle_t slsk_handle;

	slsk_handle = create_dissector_handle(dissect_slsk, proto_slsk);
	dissector_add("tcp.port", TCP_PORT_SLSK_1, slsk_handle);
	dissector_add("tcp.port", TCP_PORT_SLSK_2, slsk_handle);
	dissector_add("tcp.port", TCP_PORT_SLSK_3, slsk_handle);
}

