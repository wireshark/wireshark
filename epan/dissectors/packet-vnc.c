/* packet-vnc.c
 * Routines for VNC dissection (Virtual Network Computing)
 * Copyright 2005, Ulf Lamping <ulf.lamping@web.de>
 * Copyright 2006, Stephen Fisher <stephentfisher@yahoo.com>
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
 */

/* Dissection of the VNC (Virtual Network Computing) network traffic.
 *
 * Several VNC implementations available, see:
 * http://www.realvnc.com/
 * http://www.tightvnc.com/
 * http://ultravnc.sourceforge.net/
 * ...
 *
 * The protocol itself is known as RFB - Remote Frame Buffer Protocol.
 *
 * This code is based on the protocol specification:
 *   http://www.realvnc.com/docs/rfbproto.pdf
 *  and the RealVNC free edition source code
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-x11-keysym.h" /* This contains the X11 value_string "keysym_vals_source" that VNC uses */

static const value_string security_types_vs[] = {
	{ 0,  "Invalid" },
	{ 1,  "None"    },
	{ 2,  "VNC"     },
	{ 5,  "RA2"     },
	{ 6,  "RA2ne"   },
	{ 16, "Tight"   },
	{ 17, "Ultra"   },
	{ 18, "TLS"     },
	{ 0,  NULL      }
};

static const value_string auth_result_vs[] = {
	{ 0, "OK"     },
	{ 1, "Failed" },
	{ 0,  NULL    }
};

static const value_string yes_no_vs[] = {
	{ 0, "No"  },
	{ 1, "Yes" },
	{ 0,  NULL }
};

static const value_string client_message_types_vs[] = {
	{ 0, "Set Pixel Format"           },
	{ 2, "Set Encodings"              },
	{ 3, "Framebuffer Update Request" },
	{ 4, "Key Event"                  },
	{ 5, "Pointer Event"              },
	{ 6, "Cut Text"                   },
	{ 0,  NULL                        }
};

static const value_string server_message_types_vs[] = {
	{ 0, "Framebuffer Update"   },
	{ 1, "Set Colormap Entries" },
	{ 2, "Ring Bell"            },
	{ 3, "Cut Text"             },
	{ 0,  NULL                  }
};

static const value_string button_mask_vs[] = {
	{ 0, "Not pressed" },
	{ 1, "Pressed"     },
	{ 0,  NULL         }
};

static const value_string encoding_types_vs[] = {
	{ -239, "Cursor (pseudo)"      },
	{ -223, "DesktopSize (pseudo)" },
	{ 0,  "Raw"                    },
	{ 1,  "CopyRect"               },
	{ 2,  "RRE"                    },
	{ 4,  "CoRRE"                  },
	{ 5,  "Hextile"                },
	{ 16, "ZRLE"                   },
	{ 0,  NULL                     }
};


void proto_reg_handoff_vnc(void);

/* Variables for our preferences */
static guint vnc_preference_alternate_port = 0; /* An alternate port besides the default (5500, 5501, 5900, 5901) */

/* This is a behind the scenes variable that is not changed by the user.
 * This stores last setting of the vnc_preference_alternate_port.  Used to keep
 * track of when the user has changed the setting so that we can delete
 * and re-register with the new port number. */
static guint vnc_preference_alternate_port_last = 0;

/* Initialize the protocol and registered fields */
static int proto_vnc = -1; /* Protocol subtree */
static int hf_vnc_padding = -1;
static int hf_vnc_server_proto_ver = -1;
static int hf_vnc_client_proto_ver = -1;
static int hf_vnc_num_security_types = -1;
static int hf_vnc_security_type = -1;
static int hf_vnc_server_security_type = -1;
static int hf_vnc_client_security_type = -1;
static int hf_vnc_auth_challenge = -1;
static int hf_vnc_auth_response = -1;
static int hf_vnc_auth_result = -1;
static int hf_vnc_auth_error = -1;

static int hf_vnc_share_desktop_flag = -1;
static int hf_vnc_width = -1;
static int hf_vnc_height = -1;
static int hf_vnc_server_bits_per_pixel = -1;
static int hf_vnc_server_depth = -1;
static int hf_vnc_server_big_endian_flag = -1;
static int hf_vnc_server_true_color_flag = -1;
static int hf_vnc_server_red_max = -1;
static int hf_vnc_server_green_max = -1;
static int hf_vnc_server_blue_max = -1;
static int hf_vnc_server_red_shift = -1;
static int hf_vnc_server_green_shift = -1;
static int hf_vnc_server_blue_shift = -1;
static int hf_vnc_desktop_name = -1;
static int hf_vnc_desktop_name_len = -1;


/********** Client Message Types **********/

static int hf_vnc_client_message_type = -1; /* A subtree under VNC */
static int hf_vnc_client_bits_per_pixel = -1;
static int hf_vnc_client_depth = -1;
static int hf_vnc_client_big_endian_flag = -1;
static int hf_vnc_client_true_color_flag = -1;
static int hf_vnc_client_red_max = -1;
static int hf_vnc_client_green_max = -1;
static int hf_vnc_client_blue_max = -1;
static int hf_vnc_client_red_shift = -1;
static int hf_vnc_client_green_shift = -1;
static int hf_vnc_client_blue_shift = -1;

/* Client Key Event */
static int hf_vnc_key_down = -1;
static int hf_vnc_key = -1;

/* Client Pointer Event */
static int hf_vnc_button_1_pos = -1;
static int hf_vnc_button_2_pos = -1;
static int hf_vnc_button_3_pos = -1;
static int hf_vnc_button_4_pos = -1;
static int hf_vnc_button_5_pos = -1;
static int hf_vnc_button_6_pos = -1;
static int hf_vnc_button_7_pos = -1;
static int hf_vnc_button_8_pos = -1;
static int hf_vnc_pointer_x_pos = -1;
static int hf_vnc_pointer_y_pos = -1;

/* Client Framebuffer Update Request */
static int hf_vnc_update_req_incremental = -1;
static int hf_vnc_update_req_x_pos = -1;
static int hf_vnc_update_req_y_pos = -1;
static int hf_vnc_update_req_width = -1;
static int hf_vnc_update_req_height = -1;

/* Client Set Encodings */
static int hf_vnc_client_set_encodings_encoding_type = -1;

/* Client Cut Text */
static int hf_vnc_client_cut_text_len = -1;
static int hf_vnc_client_cut_text = -1;

/********** Server Message Types **********/

static int hf_vnc_server_message_type = -1; /* Subtree */

/* Server Set Colormap Entries */
static int hf_vnc_colormap_first_color = -1;
static int hf_vnc_colormap_num_colors = -1;
static int hf_vnc_colormap_red = -1;
static int hf_vnc_colormap_green = -1;
static int hf_vnc_colormap_blue = -1;

/* Server Cut Text */
static int hf_vnc_server_cut_text_len = -1;
static int hf_vnc_server_cut_text = -1;

/********** End of Server Message Types **********/

static gboolean vnc_preference_desegment = TRUE;

/* Initialize the subtree pointers */
static gint ett_vnc = -1;
static gint ett_vnc_client_message_type = -1;
static gint ett_vnc_server_message_type = -1;
static gint ett_vnc_colormap_num_groups = -1;
static gint ett_vnc_colormap_color_group = -1;

static dissector_handle_t vnc_handle;

/* Initialize the structure that will be tied to each conversation. */
typedef struct {
	/* Packet numbers for the first 9 packets of each conversation. */
	guint32 first_packet_number, second_packet_number, third_packet_number, forth_packet_number, fifth_packet_number,
		sixth_packet_number, seventh_packet_number, eighth_packet_number, ninth_packet_number;
	gdouble server_proto_ver, client_proto_ver;
} vnc_hash_entry_t;

/* Code to dissect the packets */
static void
dissect_vnc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 num_security_types, message_type;
	guint16 number_of_encodings = 0;     /* Part of: Client Set Encodings */
	guint16 number_of_colors;            /* Part of: Server Set Colormap Entries */
	guint32 text_len;                    /* Part of: Client Cut Text & Server Cut Text */
	guint32 auth_result, desktop_name_len;
	guint offset = 0, counter;

	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti=NULL;
	proto_tree *vnc_tree=NULL, *vnc_client_message_type_tree, *vnc_server_message_type_tree, *vnc_colormap_num_groups,
		*vnc_colormap_color_group;

	conversation_t *conversation;
	vnc_hash_entry_t *hash_info;

	conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, pinfo->ptype, pinfo->srcport, pinfo->destport, 0);

	if(!conversation) {  /* Conversation does not exist yet - create it */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst,
						pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	}

	/* Retrieve information from conversation
	 * or add it if it isn't there yet */
	hash_info = conversation_get_proto_data(conversation, proto_vnc);
	if(!hash_info) {
		hash_info = se_alloc(sizeof(vnc_hash_entry_t));

		/* We must be on the first packet now */
		hash_info->first_packet_number   = pinfo->fd->num;

		/* The rest of these values will be set as we come across each packet */
	      	hash_info->second_packet_number  = 0;
		hash_info->third_packet_number   = 0;
		hash_info->forth_packet_number   = 0;
		hash_info->fifth_packet_number   = 0;
		hash_info->sixth_packet_number   = 0;
		hash_info->seventh_packet_number = 0;
		hash_info->eighth_packet_number  = 0;
		hash_info->ninth_packet_number   = 0;

		hash_info->server_proto_ver = 0.0;
		hash_info->client_proto_ver = 0.0;

      		conversation_add_proto_data(conversation, proto_vnc, hash_info);
	}

	/* Store the number of the first nine packets of this conversation as we reach them for the first time.
	 * These are the packets that contain connection setup data and do not have a message type identifier.
	 * The packets after the ninth one do contain message type identifiers. */

	if(!hash_info->second_packet_number && pinfo->fd->num > hash_info->first_packet_number) {
		/* We're on the second packet of the conversation */
		hash_info->second_packet_number = pinfo->fd->num;

	} else if(hash_info->second_packet_number && !hash_info->third_packet_number && pinfo->fd->num > hash_info->second_packet_number) {
		/* We're on the third packet of the conversation */
		hash_info->third_packet_number = pinfo->fd->num;

	} else if(hash_info->third_packet_number && !hash_info->forth_packet_number && pinfo->fd->num > hash_info->third_packet_number) {
		/* We're on the forth packet of the conversation */
		hash_info->forth_packet_number = pinfo->fd->num;

	} else if(hash_info->forth_packet_number && !hash_info->fifth_packet_number && pinfo->fd->num > hash_info->forth_packet_number) {
		/* We're on the fifth packet of the conversation */
		hash_info->fifth_packet_number = pinfo->fd->num;

	} else if(hash_info->fifth_packet_number && !hash_info->sixth_packet_number && pinfo->fd->num > hash_info->fifth_packet_number) {
		/* We're on the sixth packet of the conversation */
		hash_info->sixth_packet_number = pinfo->fd->num;

	} else if(hash_info->sixth_packet_number && !hash_info->seventh_packet_number && pinfo->fd->num > hash_info->sixth_packet_number) {
		/* We're on the seventh packet of the conversation */
		hash_info->seventh_packet_number = pinfo->fd->num;

	} else if(hash_info->seventh_packet_number && !hash_info->eighth_packet_number && pinfo->fd->num > hash_info->seventh_packet_number)
		{
			/* We're on the eighth packet of the conversation */
			hash_info->eighth_packet_number = pinfo->fd->num;

		} else if(hash_info->eighth_packet_number && !hash_info->ninth_packet_number && pinfo->fd->num > hash_info->eighth_packet_number) {
		/* We're on the ninth packet of the conversation */
		hash_info->ninth_packet_number = pinfo->fd->num;
	}


	/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "VNC");

	/* First, clear the info column */
	if(check_col(pinfo->cinfo, COL_INFO))
                col_clear(pinfo->cinfo, COL_INFO);

	/* create display subtree for the protocol */
	if(tree) {
		ti = proto_tree_add_item(tree, proto_vnc, tvb, 0, -1, FALSE);
		vnc_tree = proto_item_add_subtree(ti, ett_vnc);
	}

	offset = 0; /* Start at the beginning of the VNC protocol data */

	/* Server Protocol Version */

	if(pinfo->fd->num == hash_info->first_packet_number) {
		proto_tree_add_item(vnc_tree, hf_vnc_server_proto_ver, tvb, 4, 7, FALSE);
		hash_info->server_proto_ver = g_strtod(tvb_get_ephemeral_string(tvb, 4, 7), NULL);

		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO, "Server protocol version: %s", tvb_format_text(tvb, 4, 7));
	}

	/* Second Packet = Client Protocol Version */
	else if(pinfo->fd->num == hash_info->second_packet_number) {
		proto_tree_add_item(vnc_tree, hf_vnc_client_proto_ver, tvb, 4, 7, FALSE);
		hash_info->client_proto_ver = g_strtod(tvb_get_ephemeral_string(tvb, 4, 7), NULL);

		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO, "Client protocol version: %s", tvb_format_text(tvb, 4, 7));

	}

	/* Security Types Supported */
	else if(pinfo->fd->num == hash_info->third_packet_number) {

		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Security types supported");

		/* We're checking against the client protocol version because the client is the final decider
		 * on which version to use after the server offers the version it supports. */

		if(hash_info->client_proto_ver >= 3.007) {
			proto_tree_add_item(vnc_tree, hf_vnc_num_security_types, tvb, offset, 1, FALSE);
			num_security_types = tvb_get_guint8(tvb, offset);

			for(offset = 1; offset <= num_security_types; offset++) {
				proto_tree_add_item(vnc_tree, hf_vnc_security_type, tvb, offset, 1, FALSE);
			}
		} else {
			/* Version < 3.007: The server decides the authentication time for us to use */
			proto_tree_add_item(vnc_tree, hf_vnc_server_security_type, tvb, offset, 4, FALSE);

		}

	}

	/* Authentication type selected by client */
	/* This field is skipped by versions < 3.007 so the packet number is off on each if statement below */
	else if(hash_info->client_proto_ver >= 3.007 && pinfo->fd->num == hash_info->forth_packet_number) {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Authentication type selected by client");

		proto_tree_add_item(vnc_tree, hf_vnc_client_security_type, tvb, offset, 1, FALSE);
	}

	/* Authentication challenge from server */
	else if((hash_info->client_proto_ver >= 3.007 && pinfo->fd->num == hash_info->fifth_packet_number) ||
		(hash_info->client_proto_ver  < 3.007 && pinfo->fd->num == hash_info->forth_packet_number)) {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Authentication challenge from server");

		proto_tree_add_item(vnc_tree, hf_vnc_auth_challenge, tvb, offset, 16, FALSE);
	}

	/* Authentication response from client */
	else if((hash_info->client_proto_ver >= 3.007 && pinfo->fd->num == hash_info->sixth_packet_number) ||
		(hash_info->client_proto_ver  < 3.007 && pinfo->fd->num == hash_info->fifth_packet_number)) {
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Authentication response from client");

		proto_tree_add_item(vnc_tree, hf_vnc_auth_response, tvb, offset, 16, FALSE);
	}

	/* Authentication result */
	else if((hash_info->client_proto_ver >= 3.007 && pinfo->fd->num == hash_info->seventh_packet_number) ||
		(hash_info->client_proto_ver  < 3.007 && pinfo->fd->num == hash_info->sixth_packet_number)) {

		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Authentication result");

		proto_tree_add_item(vnc_tree, hf_vnc_auth_result, tvb, offset, 4, FALSE);
		auth_result = tvb_get_ntohl(tvb, offset); /* 32-bit big endian accessor */
		offset += 4;

		if(hash_info->client_proto_ver >= 3.007 && auth_result == 1) { /* 1 = failed */
			text_len = tvb_get_ntohl(tvb, offset);
			proto_tree_add_text(vnc_tree, tvb, offset, 4, "Length of authentication error: %d", text_len);
			offset += 4;

			proto_tree_add_item(vnc_tree, hf_vnc_auth_error, tvb, offset, text_len, FALSE);
			offset += text_len;

		}
	}

	/* Share desktop */
	else if((hash_info->client_proto_ver >= 3.007 && pinfo->fd->num == hash_info->eighth_packet_number) ||
		(hash_info->client_proto_ver  < 3.007 && pinfo->fd->num == hash_info->seventh_packet_number)) {

		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Share desktop flag");

		proto_tree_add_item(vnc_tree, hf_vnc_share_desktop_flag, tvb, offset, 1, FALSE);
	}

	/* Various parameters for the frame buffer (screen) from the server */
	else if((hash_info->client_proto_ver >= 3.007 && pinfo->fd->num == hash_info->ninth_packet_number) ||
		(hash_info->client_proto_ver  < 3.007 && pinfo->fd->num == hash_info->eighth_packet_number)) {

		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Server framebuffer parameters");

		proto_tree_add_item(vnc_tree, hf_vnc_width, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(vnc_tree, hf_vnc_height, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(vnc_tree, hf_vnc_server_bits_per_pixel, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(vnc_tree, hf_vnc_server_depth, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(vnc_tree, hf_vnc_server_big_endian_flag, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(vnc_tree, hf_vnc_server_true_color_flag, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(vnc_tree, hf_vnc_server_red_max, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(vnc_tree, hf_vnc_server_green_max, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(vnc_tree, hf_vnc_server_blue_max, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(vnc_tree, hf_vnc_server_red_shift, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(vnc_tree, hf_vnc_server_green_shift, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(vnc_tree, hf_vnc_server_blue_shift, tvb, offset, 1, FALSE);
		offset += 1;

		proto_tree_add_item(vnc_tree, hf_vnc_padding, tvb, offset, 3, FALSE);
		offset += 3; /* Skip over 3 bytes of padding */

		if(tvb_length_remaining(tvb, offset) > 0) { /* Sometimes the desktop name & length is skipped */
			proto_tree_add_item(vnc_tree, hf_vnc_desktop_name_len, tvb, offset, 4, FALSE);
			desktop_name_len = tvb_get_ntohl(tvb, offset); /* 32-bit big endian accessor */
			offset += 4;

			proto_tree_add_item(vnc_tree, hf_vnc_desktop_name, tvb, offset, desktop_name_len, FALSE);
		}

	}

	/* All packets beyond #9 */
	else {
		if(pinfo->destport == 5500 || pinfo->destport == 5501 || pinfo->destport == 5900 ||
		   pinfo->destport == 5901 || pinfo->destport == vnc_preference_alternate_port) { /* From client to server */

			message_type = tvb_get_guint8(tvb, offset);

			switch(message_type) {

			case 0 : /* Client Set Pixel Format */
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_str(pinfo->cinfo, COL_INFO, "Client set pixel format");

				ti = proto_tree_add_item(vnc_tree, hf_vnc_client_message_type, tvb, offset, 1, FALSE);
				vnc_client_message_type_tree = proto_item_add_subtree(ti, ett_vnc_client_message_type);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_padding, tvb, offset, 3, FALSE);
				offset += 3; /* Skip over 3 bytes of padding */

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_bits_per_pixel, tvb, offset, 1,
						    FALSE);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_depth, tvb, offset, 1, FALSE);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_big_endian_flag, tvb, offset, 1,
						    FALSE);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_true_color_flag, tvb, offset, 1,
						    FALSE);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_red_max, tvb, offset, 2, FALSE);
				offset += 2;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_green_max, tvb, offset, 2, FALSE);
				offset += 2;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_blue_max, tvb, offset, 2, FALSE);
				offset += 2;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_red_shift, tvb, offset, 1, FALSE);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_green_shift, tvb, offset, 1, FALSE);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_blue_shift, tvb, offset, 1, FALSE);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_padding, tvb, offset, 3, FALSE);
				offset += 3; /* Skip over 3 bytes of padding */

				break;

			case 2 : /* Client Set Encodings */
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_str(pinfo->cinfo, COL_INFO, "Client set encodings");

				ti = proto_tree_add_item(vnc_tree, hf_vnc_client_message_type, tvb, offset, 1, FALSE);
				vnc_client_message_type_tree = proto_item_add_subtree(ti, ett_vnc_client_message_type);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_padding, tvb, offset, 1, FALSE);
				offset += 1; /* Skip over 1 byte of padding */

				number_of_encodings = tvb_get_ntohs(tvb, offset);

				proto_tree_add_text(vnc_client_message_type_tree, tvb, offset, 2,
						    "Number of encodings: %d", number_of_encodings);
				offset += 2;


				for(counter = 1; counter <= number_of_encodings; counter++) {
					proto_tree_add_item(vnc_client_message_type_tree,
							    hf_vnc_client_set_encodings_encoding_type, tvb, offset, 4, FALSE);
					offset += 4;
				}

				break;

			case 3 : /* Client Framebuffer Update Request */
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_str(pinfo->cinfo, COL_INFO, "Client framebuffer update request");

				ti = proto_tree_add_item(vnc_tree, hf_vnc_client_message_type, tvb, offset, 1, FALSE);
				vnc_client_message_type_tree = proto_item_add_subtree(ti, ett_vnc_client_message_type);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_update_req_incremental,
						    tvb, offset, 1, FALSE);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_update_req_x_pos,
						    tvb, offset, 2, FALSE);
				offset += 2;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_update_req_y_pos,
						    tvb, offset, 2, FALSE);
				offset += 2;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_update_req_width, tvb,
						    offset, 2, FALSE);
				offset += 2;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_update_req_height, tvb,
						    offset, 2, FALSE);
				offset += 2;

				break;

			case 4 : /* Client Key Event */
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_str(pinfo->cinfo, COL_INFO, "Client key event");

				ti = proto_tree_add_item(vnc_tree, hf_vnc_client_message_type, tvb, offset, 1, FALSE);
				vnc_client_message_type_tree = proto_item_add_subtree(ti, ett_vnc_client_message_type);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_key_down, tvb, offset, 1, FALSE);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_padding, tvb, offset, 2, FALSE);
				offset += 2; /* Skip over 2 bytes of padding */

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_key, tvb, offset, 4, FALSE);
				offset += 4;

				break;

			case 5: /* Client Pointer Event */
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_str(pinfo->cinfo, COL_INFO, "Client pointer event");

				ti = proto_tree_add_item(vnc_tree, hf_vnc_client_message_type, tvb, offset, 1, FALSE);
				vnc_client_message_type_tree = proto_item_add_subtree(ti, ett_vnc_client_message_type);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_button_1_pos, tvb,
						    offset, 1, FALSE);
				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_button_2_pos, tvb,
						    offset, 1, FALSE);
				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_button_3_pos, tvb,
						    offset, 1, FALSE);
				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_button_4_pos, tvb,
						    offset, 1, FALSE);
				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_button_5_pos, tvb,
						    offset, 1, FALSE);
				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_button_6_pos, tvb,
						    offset, 1, FALSE);
				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_button_7_pos, tvb,
						    offset, 1, FALSE);
				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_button_8_pos, tvb,
						    offset, 1, FALSE);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_pointer_x_pos, tvb,
						    offset, 2, FALSE);
				offset += 2;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_pointer_y_pos, tvb,
						    offset, 2, FALSE);
				offset += 2;

				break;

			case 6 : /* Client Cut Text */
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_str(pinfo->cinfo, COL_INFO, "Client cut text");

				ti = proto_tree_add_item(vnc_tree, hf_vnc_client_message_type, tvb, offset, 1, FALSE);
				vnc_client_message_type_tree = proto_item_add_subtree(ti, ett_vnc_client_message_type);
				offset += 1;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_padding, tvb, offset, 3, FALSE);
				offset += 3; /* Skip over 3 bytes of padding */

				text_len = tvb_get_ntohl(tvb, offset); /* 32-bit big endian accessor */
				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_cut_text_len, tvb, offset, 4,
						    FALSE);
				offset += 4;

				proto_tree_add_item(vnc_client_message_type_tree, hf_vnc_client_cut_text, tvb, offset, text_len,
						    FALSE);
				offset += text_len;

				break;

			default :
				if (check_col(pinfo->cinfo, COL_INFO))
					col_append_str(pinfo->cinfo, COL_INFO, "Unknown client message type");

				proto_tree_add_text(vnc_tree, tvb, 0, -1, "Unknown client message type");

				break;
			}

		} else { /* Packet is going from server to client */

			message_type = tvb_get_guint8(tvb, offset);

			switch(message_type) {

			case 0 : /* Server Framebuffer Update */

				/* XXX - This message type is not fully dissected yet */

				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_str(pinfo->cinfo, COL_INFO, "Server framebuffer update");

				ti = proto_tree_add_item(vnc_tree, hf_vnc_server_message_type, tvb, offset, 1, FALSE);
				vnc_server_message_type_tree = proto_item_add_subtree(ti, ett_vnc_server_message_type);
				offset += 1;

				proto_tree_add_text(vnc_server_message_type_tree, tvb, offset, -1,
						    "Data");

				break;

			case 1 : /* Server Set Colormap Entries */
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_str(pinfo->cinfo, COL_INFO, "Server set colormap entries");

				number_of_colors = tvb_get_ntohs(tvb, 4);
				if(vnc_preference_desegment && pinfo->can_desegment &&
				   tvb_length_remaining(tvb, offset) < (number_of_colors * 6) + 6) {
					pinfo->desegment_offset = 0;
					pinfo->desegment_len = (number_of_colors * 6) + 6 - tvb_length_remaining(tvb, offset);
					return;
				}

				ti = proto_tree_add_item(vnc_tree, hf_vnc_server_message_type, tvb, offset, 1, FALSE);
				vnc_server_message_type_tree = proto_item_add_subtree(ti, ett_vnc_server_message_type);
				offset += 1;

				proto_tree_add_item(vnc_server_message_type_tree, hf_vnc_padding, tvb, offset, 1, FALSE);
				offset += 1; /* Skip over 1 byte of padding */

				proto_tree_add_item(vnc_server_message_type_tree,
						    hf_vnc_colormap_first_color, tvb, offset, 2, FALSE);
				offset += 2;

				ti = proto_tree_add_item(vnc_server_message_type_tree, hf_vnc_colormap_num_colors, tvb,
							 offset, 2, FALSE);
				vnc_colormap_num_groups = proto_item_add_subtree(ti, ett_vnc_colormap_num_groups);

				offset += 2;

				for(counter = 1; counter <= number_of_colors; counter++) {
				      	ti = proto_tree_add_text(vnc_colormap_num_groups, tvb, offset, 6,
										"Color group #%d", counter);
					vnc_colormap_color_group = proto_item_add_subtree(ti, ett_vnc_colormap_color_group);

					proto_tree_add_item(vnc_colormap_color_group,
							    hf_vnc_colormap_red, tvb, offset, 2, FALSE);
					offset += 2;

					proto_tree_add_item(vnc_colormap_color_group,
							    hf_vnc_colormap_green, tvb, offset, 2, FALSE);
					offset += 2;

					proto_tree_add_item(vnc_colormap_color_group,
							    hf_vnc_colormap_blue, tvb, offset, 2, FALSE);
					offset += 2;
				}

				break;

			case 2 : /* Server Ring Bell (on client) */
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_str(pinfo->cinfo, COL_INFO, "Server ring bell on client");

				ti = proto_tree_add_item(vnc_tree, hf_vnc_server_message_type, tvb, offset, 1, FALSE);
				vnc_server_message_type_tree = proto_item_add_subtree(ti, ett_vnc_server_message_type);
				offset += 1;

				/* This message type has no payload... */

				break;

			case 3 : /* Server Cut Text */
				if (check_col(pinfo->cinfo, COL_INFO))
					col_set_str(pinfo->cinfo, COL_INFO, "Server cut text");

				ti = proto_tree_add_item(vnc_tree, hf_vnc_server_message_type, tvb, offset, 1, FALSE);
				vnc_server_message_type_tree = proto_item_add_subtree(ti, ett_vnc_server_message_type);
				offset += 1;

				proto_tree_add_item(vnc_server_message_type_tree, hf_vnc_padding, tvb, offset, 3, FALSE);
				offset += 3; /* Skip over 3 bytes of padding */

				text_len = tvb_get_ntohl(tvb, offset); /* 32-bit big endian accessor */
				proto_tree_add_item(vnc_server_message_type_tree, hf_vnc_server_cut_text_len, tvb, offset, 4,
						    FALSE);
				offset += 4;

				if(vnc_preference_desegment && pinfo->can_desegment &&
				   tvb_length_remaining(tvb, offset) < text_len) {
					pinfo->desegment_offset = 0;
					pinfo->desegment_len = text_len - tvb_length_remaining(tvb, offset);
					return;
				}
				proto_tree_add_item(vnc_server_message_type_tree, hf_vnc_server_cut_text, tvb, offset, text_len,
						    FALSE);
				offset += text_len;

				break;

			default :
				if (check_col(pinfo->cinfo, COL_INFO))
					col_append_str(pinfo->cinfo, COL_INFO, "Server framebuffer update (continuation)");

				proto_tree_add_text(vnc_tree, tvb, 0, -1, "Server framebuffer update data (continuation)");

				break;
			}

		}
	}
}


/* Register the protocol with Wireshark */
void
proto_register_vnc(void)
{
	module_t *vnc_module; /* To handle our preferences */

	/* Setup list of header fields */
        static hf_register_info hf[] = {
		{ &hf_vnc_padding,
		  { "Padding", "vnc.padding",
		    FT_NONE, BASE_NONE, NULL, 0x0,
		    "Unused space", HFILL }
		},

                { &hf_vnc_server_proto_ver,
		  { "Server protocol version", "vnc.server_proto_ver",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "VNC protocol version on server", HFILL }
                },
		{ &hf_vnc_client_proto_ver,
		  { "Client protocol version", "vnc.client_proto_ver",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "VNC protocol version on client", HFILL }
		},
		{ &hf_vnc_num_security_types,
		  { "Number of security types", "vnc.num_security_types",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of security (authentication) types supported by the server", HFILL }
		},
		{ &hf_vnc_security_type,
		  { "Security type", "vnc.security_type",
		    FT_UINT8, BASE_DEC, VALS(security_types_vs), 0x0,
		    "Security types offered by the server (VNC versions => 3.007", HFILL }
		},
		{ &hf_vnc_server_security_type,
		  { "Security type", "vnc.server_security_type",
		    FT_UINT32, BASE_DEC, VALS(security_types_vs), 0x0,
		    "Security type mandated by the server (VNC versions < 3.007)", HFILL }
		},
		{ &hf_vnc_client_security_type,
		  { "Security type selected", "vnc.security_type",
		    FT_UINT8, BASE_DEC, VALS(security_types_vs), 0x0,
		    "Security type selected by the client", HFILL }
		},
		{ &hf_vnc_auth_challenge,
		  { "Authentication challenge", "vnc.auth_challenge",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Random authentication challenge from server to client", HFILL }
		},
		{ &hf_vnc_auth_response,
		  { "Authentication response", "vnc.auth_response",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Client's encrypted response to the server's authentication challenge", HFILL }
		},
		{ &hf_vnc_auth_result,
		  { "Authentication result", "vnc.auth_result",
		    FT_UINT32, BASE_DEC, VALS(auth_result_vs), 0x0,
		    "Authentication result", HFILL }
		},
		{ &hf_vnc_auth_error,
		  { "Authentication error", "vnc.auth_error",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Authentication error (present only if the authentication result is fail", HFILL }
		},
		{ &hf_vnc_share_desktop_flag,
		  { "Share desktop flag", "vnc.share_desktop_flag",
		    FT_UINT8, BASE_DEC, VALS(yes_no_vs), 0x0,
		    "Client's desire to share the server's desktop with other clients", HFILL }
		},
		{ &hf_vnc_width,
		  { "Framebuffer width", "vnc.width",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Width of the framebuffer (screen) in pixels", HFILL }
		},
		{ &hf_vnc_height,
		  { "Framebuffer height", "vnc.width",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Height of the framebuffer (screen) in pixels", HFILL }
		},
		{ &hf_vnc_server_bits_per_pixel,
		  { "Bits per pixel", "vnc.server_bits_per_pixel",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of bits used by server for each pixel value on the wire from the server", HFILL }
		},
		{ &hf_vnc_server_depth,
		  { "Depth", "vnc.server_depth",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of useful bits in the pixel value on server", HFILL }
		},
		{ &hf_vnc_server_big_endian_flag,
		  { "Big endian flag", "vnc.server_big_endian_flag",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "True if multi-byte pixels are interpreted as big endian by server", HFILL }
		},
		{ &hf_vnc_server_true_color_flag,
		  { "True color flag", "vnc.server_true_color_flag",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "If true, then the next six items specify how to extract the red, green and blue intensities from the pixel value on the server.", HFILL }
		},
		{ &hf_vnc_server_red_max,
		  { "Red maximum", "vnc.server_red_max",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Maximum red value on server as n: 2^n - 1", HFILL }
		},
		{ &hf_vnc_server_green_max,
		  { "Green maximum", "vnc.server_green_max",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Maximum green value on server as n: 2^n - 1", HFILL }
		},
		{ &hf_vnc_server_blue_max,
		  { "Blue maximum", "vnc.server_blue_max",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Maximum blue value on server as n: 2^n - 1", HFILL }
		},
		{ &hf_vnc_server_red_shift,
		  { "Red shift", "vnc.server_red_shift",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of shifts needed to get the red value in a pixel to the least significant bit on the server", HFILL }
		},
		{ &hf_vnc_server_green_shift,
		  { "Green shift", "vnc.server_green_shift",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of shifts needed to get the green value in a pixel to the least significant bit on the server", HFILL }
		},
		{ &hf_vnc_server_blue_shift,
		  { "Blue shift", "vnc.server_blue_shift",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of shifts needed to get the blue value in a pixel to the least significant bit on the server", HFILL }
		},
		{ &hf_vnc_desktop_name_len,
		  { "Desktop name length", "vnc.desktop_name_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Length of desktop name in bytes", HFILL }
		},
		{ &hf_vnc_desktop_name,
		  { "Desktop name", "vnc.desktop_name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Name of the VNC desktop on the server", HFILL }
		},
		{ &hf_vnc_client_message_type,
		  { "Client Message Type", "vnc.client_message_type",
		    FT_UINT8, BASE_DEC, VALS(client_message_types_vs), 0x0,
		    "Message type from client", HFILL }
		},
		{ &hf_vnc_client_bits_per_pixel,
		  { "Bits per pixel", "vnc.client_bits_per_pixel",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of bits used by server for each pixel value on the wire from the client", HFILL }
		},
		{ &hf_vnc_client_depth,
		  { "Depth", "vnc.client_depth",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of useful bits in the pixel value on client", HFILL }
		},
		{ &hf_vnc_client_big_endian_flag,
		  { "Big endian flag", "vnc.client_big_endian_flag",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "True if multi-byte pixels are interpreted as big endian by client", HFILL }
		},
		{ &hf_vnc_client_true_color_flag,
		  { "True color flag", "vnc.client_true_color_flag",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "If true, then the next six items specify how to extract the red, green and blue intensities from the pixel value on the client.", HFILL }
		},
		{ &hf_vnc_client_red_max,
		  { "Red maximum", "vnc.client_red_max",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Maximum red value on client as n: 2^n - 1", HFILL }
		},
		{ &hf_vnc_client_green_max,
		  { "Green maximum", "vnc.client_green_max",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Maximum green value on client as n: 2^n - 1", HFILL }
		},
		{ &hf_vnc_client_blue_max,
		  { "Blue maximum", "vnc.client_blue_max",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Maximum blue value on client as n: 2^n - 1", HFILL }
		},
		{ &hf_vnc_client_red_shift,
		  { "Red shift", "vnc.client_red_shift",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of shifts needed to get the red value in a pixel to the least significant bit on the client", HFILL }
		},
		{ &hf_vnc_client_green_shift,
		  { "Green shift", "vnc.client_green_shift",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of shifts needed to get the green value in a pixel to the least significant bit on the client", HFILL }
		},
		{ &hf_vnc_client_blue_shift,
		  { "Blue shift", "vnc.client_blue_shift",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of shifts needed to get the blue value in a pixel to the least significant bit on the client", HFILL }
		},

		/* Client Key Event */
		{ &hf_vnc_key_down,
		  { "Key down", "vnc.key_down",
		    FT_UINT8, BASE_DEC, VALS(yes_no_vs), 0x0,
		    "Specifies whether the key is being pressed or not", HFILL }
		},
		{ &hf_vnc_key,
		  { "Key", "vnc.key",
		    FT_UINT32, BASE_HEX, VALS(keysym_vals_source), 0x0, /* keysym_vals_source is from packet-x11-keysym.h */
		    "Key being pressed/depressed", HFILL }
		},

		/* Client Pointer Event */
		{ &hf_vnc_button_1_pos,
		  { "Mouse button #1 position", "vnc.button_1_pos",
		    FT_UINT8, BASE_DEC, VALS(&button_mask_vs), 0x1,
		    "Whether mouse button #1 is being pressed or not", HFILL }
		},
		{ &hf_vnc_button_2_pos,
		  { "Mouse button #2 position", "vnc.button_2_pos",
		    FT_UINT8, BASE_DEC, VALS(&button_mask_vs), 0x2,
		    "Whether mouse button #2 is being pressed or not", HFILL }
		},
		{ &hf_vnc_button_3_pos,
		  { "Mouse button #3 position", "vnc.button_3_pos",
		    FT_UINT8, BASE_DEC, VALS(&button_mask_vs), 0x4,
		    "Whether mouse button #3 is being pressed or not", HFILL }
		},
		{ &hf_vnc_button_4_pos,
		  { "Mouse button #4 position", "vnc.button_4_pos",
		    FT_UINT8, BASE_DEC, VALS(&button_mask_vs), 0x8,
		    "Whether mouse button #4 is being pressed or not", HFILL }
		},
		{ &hf_vnc_button_5_pos,
		  { "Mouse button #5 position", "vnc.button_5_pos",
		    FT_UINT8, BASE_DEC, VALS(&button_mask_vs), 0x10,
		    "Whether mouse button #5 is being pressed or not", HFILL }
		},
		{ &hf_vnc_button_6_pos,
		  { "Mouse button #6 position", "vnc.button_6_pos",
		    FT_UINT8, BASE_DEC, VALS(&button_mask_vs), 0x20,
		    "Whether mouse button #6 is being pressed or not", HFILL }
		},
		{ &hf_vnc_button_7_pos,
		  { "Mouse button #7 position", "vnc.button_7_pos",
		    FT_UINT8, BASE_DEC, VALS(&button_mask_vs), 0x40,
		    "Whether mouse button #7 is being pressed or not", HFILL }
		},
		{ &hf_vnc_button_8_pos,
		  { "Mouse button #8 position", "vnc.button_8_pos",
		    FT_UINT8, BASE_DEC, VALS(&button_mask_vs), 0x80,
		    "Whether mouse button #8 is being pressed or not", HFILL }
		},
		{ &hf_vnc_pointer_x_pos,
		  { "X position", "vnc.pointer_x_pos",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Position of mouse cursor on the x-axis", HFILL }
		},
		{ &hf_vnc_pointer_y_pos,
		  { "Y position", "vnc.pointer_y_pos",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Position of mouse cursor on the y-axis", HFILL }
		},
		{ &hf_vnc_client_set_encodings_encoding_type,
		  { "Encoding type", "vnc.client_set_encodings_encoding_type",
		    FT_INT32, BASE_DEC, VALS(encoding_types_vs), 0x0,
		    "Type of encoding used to send pixel data from server to client", HFILL }
		},

		/* Client Framebuffer Update Request */
		{ &hf_vnc_update_req_incremental,
		  { "Incremental update", "vnc.update_req_incremental",
		    FT_BOOLEAN, BASE_DEC, NULL, 0x0,
		    "Specifies if the client wants an incremental update instead of a full one", HFILL }
		},
		{ &hf_vnc_update_req_x_pos,
		  { "X position", "vnc.update_req_x_pos",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "X position of framebuffer (screen) update requested", HFILL }
		},
		{ &hf_vnc_update_req_y_pos,
		  { "Y position", "vnc.update_req_y_pos",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Y position of framebuffer (screen) update request", HFILL }
		},
		{ &hf_vnc_update_req_width,
		  { "Width", "vnc.update_req_width",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Width of framebuffer (screen) update request", HFILL }
		},
		{ &hf_vnc_update_req_height,
		  { "Height", "vnc.update_req_height",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Height of framebuffer (screen) update request", HFILL }
		},
		{ &hf_vnc_client_cut_text_len,
		  { "Length", "vnc.client_cut_text_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Length of client's copy/cut text (clipboard) string in bytes", HFILL }
		},
		{ &hf_vnc_client_cut_text,
		  { "Text", "vnc.client_cut_text",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Text string in the client's copy/cut text (clipboard)", HFILL }
		},


		/********** Server Message Types **********/
		{ &hf_vnc_server_message_type,
		  { "Server Message Type", "vnc.server_message_type",
		    FT_UINT8, BASE_DEC, VALS(server_message_types_vs), 0x0,
		    "Message type from server", HFILL }
		},

		/* Server Set Colormap Entries */
		{ &hf_vnc_colormap_first_color,
		  { "First color", "vnc.colormap_first_color",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "First color that should be mapped to given RGB intensities", HFILL }
		},
		{ &hf_vnc_colormap_num_colors,
		  { "Number of color groups", "vnc.colormap_groups",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Number of red/green/blue color groups", HFILL }
		},
		{ &hf_vnc_colormap_red,
		  { "Red", "vnc.colormap_red",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Red intensity", HFILL }
		},
		{ &hf_vnc_colormap_green,
		  { "Green", "vnc.colormap_green",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Green intensity", HFILL }
		},
		{ &hf_vnc_colormap_blue,
		  { "Blue", "vnc.colormap_blue",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Blue intensity", HFILL }
		},

		/* Server Cut Text */
		{ &hf_vnc_server_cut_text_len,
		  { "Length", "vnc.server_cut_text_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Length of server's copy/cut text (clipboard) string in bytes", HFILL }
		},
		{ &hf_vnc_server_cut_text,
		  { "Text", "vnc.server_cut_text",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Text string in the server's copy/cut text (clipboard)", HFILL }
		},
	};

	/* Setup protocol subtree arrays */
	static gint *ett[] = {
		&ett_vnc,
		&ett_vnc_client_message_type,
		&ett_vnc_server_message_type,
		&ett_vnc_colormap_num_groups,
		&ett_vnc_colormap_color_group
	};

	/* Register the protocol name and description */
	proto_vnc = proto_register_protocol("Virtual Network Computing",
					    "VNC", "vnc");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_vnc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register our preferences module */
	vnc_module = prefs_register_protocol(proto_vnc, proto_reg_handoff_vnc);

	prefs_register_bool_preference(vnc_module, "desegment", "Reassemble VNC messages spanning multiple TCP segments.", "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.", &vnc_preference_desegment);

	prefs_register_uint_preference(vnc_module, "alternate_port", "Alternate TCP port",
				       "Decode this port's traffic as VNC in addition to the default ports (5500, 5501, 5900, 5901)",
				       10, &vnc_preference_alternate_port);

}

void
proto_reg_handoff_vnc(void)
{
        static gboolean inited = FALSE;

        if(!inited) {
		vnc_handle = create_dissector_handle(dissect_vnc,
						     proto_vnc);

		dissector_add("tcp.port", 5500, vnc_handle); /* First screen on listening vnc viewer */
		dissector_add("tcp.port", 5501, vnc_handle); /* Second screen on listening vnc viewer */
		dissector_add("tcp.port", 5900, vnc_handle); /* First screen on server */
		dissector_add("tcp.port", 5901, vnc_handle); /* Second screen on server */

		/* We don't register a port for the VNC HTTP server because that simply provides a java program
		 * for download via the normal HTTP protocol.  The java program then connects to a standard VNC port (above). */

		inited = TRUE;
	}

	if(vnc_preference_alternate_port != 5500 && vnc_preference_alternate_port != 5501 &&
	   vnc_preference_alternate_port != 5900 && vnc_preference_alternate_port != 5901 &&
	   vnc_preference_alternate_port != 0) {

		dissector_delete("tcp.port", vnc_preference_alternate_port_last, vnc_handle);
      		vnc_preference_alternate_port_last = vnc_preference_alternate_port;     /* Save this setting to see if has changed later */
       		dissector_add("tcp.port", vnc_preference_alternate_port, vnc_handle);   /* Register the new port setting */

	}

}
