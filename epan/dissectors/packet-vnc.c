/* packet-vnc.c
 * Routines for VNC dissection (Virtual Network Computing)
 * Copyright 2005, Ulf Lamping <ulf.lamping@web.de>
 * Copyright 2006-2007, Stephen Fisher <stephentfisher@yahoo.com>
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
 * All versions of RealVNC and TightVNC are supported.
 * Note: The addition of TightVNC support is not yet complete.
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
 *  and the RealVNC free edition & TightVNC source code
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <glib.h>

#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-x11-keysym.h" /* This contains the X11 value_string
				* "keysym_vals_source" that VNC also uses. */


static const value_string security_types_vs[] = {
	{ 0,  "Invalid"  },
	{ 1,  "None"     },
	{ 2,  "VNC"      },
	{ 5,  "RA2"      },
	{ 6,  "RA2ne"    },
	{ 16, "Tight"    },
	{ 17, "Ultra"    },
	{ 18, "TLS"      },
	{ 19, "VeNCrypt" },
	{ 0,  NULL       }
};

typedef enum {
	INVALID  = 0,
	NONE     = 1,
	VNC      = 2,
	RA2      = 5,
	RA2ne    = 6,
	TIGHT    = 16,
	ULTRA    = 17,
	TLS      = 18,
	VENCRYPT = 19
} security_types_e;

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
	{ 6,  "Zlib"                   },
	{ 7,  "Tight"                  },
	{ 8,  "ZlibHex"                },
	{ 16, "ZRLE"                   },
	{ 0,  NULL                     }
};

typedef enum {
	SERVER_VERSION,
	CLIENT_VERSION,

	SECURITY,
	SECURITY_TYPES,

	TIGHT_UNKNOWN_PACKET1,
	TIGHT_UNKNOWN_PACKET2,
	TIGHT_AUTH_TYPE_AND_VENDOR_CODE,
	TIGHT_UNKNOWN_PACKET3,

	VNC_AUTHENTICATION_CHALLENGE,
	VNC_AUTHENTICATION_RESPONSE,

	SECURITY_RESULT,

	CLIENT_INIT,
	SERVER_INIT,

	TIGHT_INTERACTION_CAPS,
	TIGHT_UNKNOWN_PACKET4,

	NORMAL_TRAFFIC
} vnc_session_state_e;

/* This structure will be tied to each conversation. */
typedef struct {
	guint8 security_type_selected;
	gdouble server_proto_ver, client_proto_ver;
	vnc_session_state_e vnc_next_state;
} vnc_conversation_t;

/* This structure will be tied to each packet */
typedef struct {
	guint8 bytes_per_pixel;
	vnc_session_state_e state;
} vnc_packet_t;

void proto_reg_handoff_vnc(void);

static gboolean vnc_startup_messages(tvbuff_t *tvb, packet_info *pinfo,
				     gint offset, proto_tree *tree,
				     vnc_conversation_t *per_conversation_info);
static void vnc_client_to_server(tvbuff_t *tvb, packet_info *pinfo,
				 gint *offset, proto_tree *tree);
static void vnc_server_to_client(tvbuff_t *tvb, packet_info *pinfo,
				 gint *offset, proto_tree *tree);
static void vnc_client_set_pixel_format(tvbuff_t *tvb, packet_info *pinfo,
					gint *offset, proto_tree *tree);
static void vnc_client_set_encodings(tvbuff_t *tvb, packet_info *pinfo,
				     gint *offset, proto_tree *tree);
static void vnc_client_framebuffer_update_request(tvbuff_t *tvb,
						  packet_info *pinfo,
						  gint *offset,
						  proto_tree *tree);
static void vnc_client_key_event(tvbuff_t *tvb, packet_info *pinfo,
				 gint *offset, proto_tree *tree);
static void vnc_client_pointer_event(tvbuff_t *tvb, packet_info *pinfo,
				     gint *offset, proto_tree *tree);
static void vnc_client_cut_text(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
				proto_tree *tree);

static guint vnc_server_framebuffer_update(tvbuff_t *tvb, packet_info *pinfo,
					   gint *offset, proto_tree *tree);
static guint vnc_raw_encoding(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
			      proto_tree *tree, guint16 width, guint16 height);
static guint vnc_copyrect_encoding(tvbuff_t *tvb, packet_info *pinfo,
				   gint *offset, proto_tree *tree,
				   guint16 width, guint16 height);
static guint vnc_rre_encoding(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
			      proto_tree *tree, guint16 width, guint16 height);
static guint vnc_hextile_encoding(tvbuff_t *tvb, packet_info *pinfo,
				  gint *offset, proto_tree *tree,
				  guint16 width, guint16 height);
static guint vnc_zrle_encoding(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
			       proto_tree *tree, guint16 width, guint16 height);
static guint vnc_cursor_encoding(tvbuff_t *tvb, packet_info *pinfo,
				 gint *offset, proto_tree *tree, guint16 width,
				 guint16 height);
static guint vnc_server_set_colormap_entries(tvbuff_t *tvb, packet_info *pinfo,
					     gint *offset, proto_tree *tree);
static void vnc_server_ring_bell(tvbuff_t *tvb, packet_info *pinfo,
				 gint *offset, proto_tree *tree);
static guint vnc_server_cut_text(tvbuff_t *tvb, packet_info *pinfo,
				 gint *offset, proto_tree *tree);
static void vnc_set_bytes_per_pixel(packet_info *pinfo, guint8 bytes_per_pixel);
static guint8 vnc_get_bytes_per_pixel(packet_info *pinfo);


#define DEST_PORT_VNC pinfo->destport == 5500 || pinfo->destport == 5501 || \
		pinfo->destport == 5900 || pinfo->destport == 5901 ||	\
		pinfo->destport == vnc_preference_alternate_port

#define VNC_BYTES_NEEDED(a)					\
	if(a > (guint)tvb_length_remaining(tvb, *offset))	\
		return a;


/* Variables for our preferences */
static guint vnc_preference_alternate_port = 0;

/* Initialize the protocol and registered fields */
static int proto_vnc = -1; /* Protocol subtree */
static int hf_vnc_padding = -1;
static int hf_vnc_server_proto_ver = -1;
static int hf_vnc_client_proto_ver = -1;
static int hf_vnc_num_security_types = -1;
static int hf_vnc_security_type = -1;
static int hf_vnc_server_security_type = -1;
static int hf_vnc_client_security_type = -1;
static int hf_vnc_vendor_code = -1;
static int hf_vnc_security_type_string = -1;
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

static int hf_vnc_num_server_message_types = -1;
static int hf_vnc_num_client_message_types = -1;
static int hf_vnc_num_encoding_types = -1;

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

/* Server Framebuffer Update */
static int hf_vnc_fb_update_x_pos = -1;
static int hf_vnc_fb_update_y_pos = -1;
static int hf_vnc_fb_update_width = -1;
static int hf_vnc_fb_update_height = -1;
static int hf_vnc_fb_update_encoding_type = -1;

/* Raw Encoding */
static int hf_vnc_raw_pixel_data = -1;

/* CopyRect Encoding */
static int hf_vnc_copyrect_src_x_pos = -1;
static int hf_vnc_copyrect_src_y_pos = -1;

/* RRE Encoding */
static int hf_vnc_rre_num_subrects = -1;
static int hf_vnc_rre_bg_pixel = -1;

static int hf_vnc_rre_subrect_pixel = -1;
static int hf_vnc_rre_subrect_x_pos = -1;
static int hf_vnc_rre_subrect_y_pos = -1;
static int hf_vnc_rre_subrect_width = -1;
static int hf_vnc_rre_subrect_height = -1;

/* Hextile Encoding */
static int hf_vnc_hextile_subencoding_mask = -1;
static int hf_vnc_hextile_raw = -1;
static int hf_vnc_hextile_raw_value = -1;
static int hf_vnc_hextile_bg = -1;
static int hf_vnc_hextile_bg_value = -1;
static int hf_vnc_hextile_fg = -1;
static int hf_vnc_hextile_fg_value = -1;
static int hf_vnc_hextile_anysubrects = -1;
static int hf_vnc_hextile_num_subrects = -1;
static int hf_vnc_hextile_subrectscolored = -1;
static int hf_vnc_hextile_subrect_pixel_value = -1;
static int hf_vnc_hextile_subrect_x_pos = -1;
static int hf_vnc_hextile_subrect_y_pos = -1;
static int hf_vnc_hextile_subrect_width = -1;
static int hf_vnc_hextile_subrect_height = -1;

/* ZRLE Encoding */
static int hf_vnc_zrle_len = -1;
static int hf_vnc_zrle_subencoding = -1;
static int hf_vnc_zrle_rle = -1;
static int hf_vnc_zrle_palette_size = -1;
static int hf_vnc_zrle_data = -1;
static int hf_vnc_zrle_raw = -1;
static int hf_vnc_zrle_palette = -1;

/* Cursor Encoding */
static int hf_vnc_cursor_encoding_pixels = -1;
static int hf_vnc_cursor_encoding_bitmask = -1;

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
static gint ett_vnc_rect = -1;
static gint ett_vnc_encoding_type = -1;
static gint ett_vnc_rre_subrect = -1;
static gint ett_vnc_hextile_subencoding_mask = -1;
static gint ett_vnc_hextile_num_subrects = -1;
static gint ett_vnc_hextile_subrect = -1;
static gint ett_vnc_zrle_subencoding = -1;
static gint ett_vnc_colormap_num_groups = -1;
static gint ett_vnc_colormap_color_group = -1;

guint8 vnc_bytes_per_pixel; /* Global so it keeps its value between packets */


/* Code to dissect the packets */
static void
dissect_vnc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gboolean ret;
	gint offset = 0;

	/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti=NULL;
	proto_tree *vnc_tree=NULL;

	conversation_t *conversation;
	vnc_conversation_t *per_conversation_info;

	conversation = find_conversation(pinfo->fd->num, &pinfo->src,
					 &pinfo->dst, pinfo->ptype,
					 pinfo->srcport, pinfo->destport, 0);

	if(!conversation) {  /* Conversation does not exist yet - create it */
		conversation = conversation_new(pinfo->fd->num, &pinfo->src,
						&pinfo->dst, pinfo->ptype,
						pinfo->srcport,
						pinfo->destport, 0);
	}

	/* Retrieve information from conversation, or add it if it isn't
	 * there yet */
	per_conversation_info = conversation_get_proto_data(conversation,
							    proto_vnc);
	if(!per_conversation_info) {
		per_conversation_info = se_alloc(sizeof(vnc_conversation_t));
		
		per_conversation_info->vnc_next_state = SERVER_VERSION;

      		conversation_add_proto_data(conversation, proto_vnc,
					    per_conversation_info);
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

	/* Dissect any remaining session startup messages */
	ret = vnc_startup_messages(tvb, pinfo, offset, vnc_tree,
				   per_conversation_info);

	vnc_set_bytes_per_pixel(pinfo, vnc_bytes_per_pixel);

	if(!ret) {	
		if(DEST_PORT_VNC)
			vnc_client_to_server(tvb, pinfo, &offset, vnc_tree);
		else
			vnc_server_to_client(tvb, pinfo, &offset, vnc_tree);
	}
}

/* Returns true if additional session startup messages follow */
static gboolean
vnc_startup_messages(tvbuff_t *tvb, packet_info *pinfo, gint offset,
		     proto_tree *tree, vnc_conversation_t
		     *per_conversation_info)
{
	guint8 num_security_types;
	gchar *vendor;
	guint32 desktop_name_len, auth_result, text_len;
	vnc_packet_t *per_packet_info;
	proto_item *ti;

	per_packet_info = p_get_proto_data(pinfo->fd, proto_vnc);

	if(!per_packet_info) {
		per_packet_info = se_alloc(sizeof(vnc_packet_t));

		per_packet_info->state = per_conversation_info->vnc_next_state;

		p_add_proto_data(pinfo->fd, proto_vnc, per_packet_info);
	} 
		
	/* Packet dissection follows */
	switch(per_packet_info->state) {

	case SERVER_VERSION :
		proto_tree_add_item(tree, hf_vnc_server_proto_ver, tvb, 4,
				    7, FALSE);

		per_conversation_info->server_proto_ver =
			g_strtod((char *)tvb_get_ephemeral_string(tvb, 4, 7),
				 NULL);
		
		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO,
				     "Server protocol version: %s",
				     tvb_format_text(tvb, 4, 7));
		
		per_conversation_info->vnc_next_state = CLIENT_VERSION;
		break;
		
	case CLIENT_VERSION :
		proto_tree_add_item(tree, hf_vnc_client_proto_ver, tvb,
				    4, 7, FALSE);

		per_conversation_info->client_proto_ver =
			g_strtod((char *)tvb_get_ephemeral_string(tvb, 4, 7),
				 NULL);
		
		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO,
				     "Client protocol version: %s",
				     tvb_format_text(tvb, 4, 7));
		
		per_conversation_info->vnc_next_state = SECURITY;
		break;

	case SECURITY :
                if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Security types supported");
		
                /* We're checking against the client protocol version because
                 * the client is the final decider on which version to use
                 * after the server offers the highest version it supports. */
		
                if(per_conversation_info->client_proto_ver >= 3.007) {
                        proto_tree_add_item(tree,
                                            hf_vnc_num_security_types, tvb,
                                            offset, 1, FALSE);
                        num_security_types = tvb_get_guint8(tvb, offset);
			
                        for(offset = 1; offset <= num_security_types; offset++){
                                proto_tree_add_item(tree,
                                                    hf_vnc_security_type, tvb,
                                                    offset, 1, FALSE);

                        }
                } else {
                        /* Version < 3.007: The server decides the
                         * authentication type for us to use */
                        proto_tree_add_item(tree,
                                            hf_vnc_server_security_type, tvb,
                                            offset, 4, FALSE);
		}

		per_conversation_info->vnc_next_state =	SECURITY_TYPES;
		break;

	case SECURITY_TYPES :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Authentication type selected by client");
		
                proto_tree_add_item(tree, hf_vnc_client_security_type, tvb,
                                    offset, 1, FALSE);
		per_conversation_info->security_type_selected =
			tvb_get_guint8(tvb, offset);
	
		switch(per_conversation_info->security_type_selected) {

		case 1 : /* None */
			if(per_conversation_info->client_proto_ver >= 3.008)
				per_conversation_info->vnc_next_state =
					SECURITY_RESULT;
			else
				per_conversation_info->vnc_next_state =
					CLIENT_INIT;

			break;

		case 2 : /* VNC */
			per_conversation_info->vnc_next_state =
				VNC_AUTHENTICATION_CHALLENGE;
			break;

		case 16 : /* Tight */
			per_conversation_info->vnc_next_state =
				TIGHT_UNKNOWN_PACKET1;
			
		default :
			/* Security type not supported by this dissector */
			break;
		}

		break;

	case TIGHT_UNKNOWN_PACKET1 :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Unknown packet (TightVNC)");

                proto_tree_add_text(tree, tvb, offset, -1,
				    "Unknown packet (TightVNC)");
		
		per_conversation_info->vnc_next_state =
			TIGHT_UNKNOWN_PACKET2;

		break;

	case TIGHT_UNKNOWN_PACKET2 :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Unknown packet (TightVNC)");

                proto_tree_add_text(tree, tvb, offset, -1,
				    "Unknown packet (TightVNC)");

		per_conversation_info->vnc_next_state =
			TIGHT_AUTH_TYPE_AND_VENDOR_CODE;
		
		break;

	case TIGHT_AUTH_TYPE_AND_VENDOR_CODE :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Authentication type / vendor code");

		proto_tree_add_item(tree, hf_vnc_server_security_type, tvb,
				    offset, 4, FALSE);		

		offset += 4;

		/* Display vendor code */		
		vendor = tvb_get_ephemeral_string(tvb, offset, 4);

		ti = proto_tree_add_string(tree, hf_vnc_vendor_code, tvb,
					   offset, 4, vendor);

		if(g_ascii_strcasecmp(vendor, "STDV") == 0)
			proto_item_append_text(ti, " (Standard VNC vendor)");

		else if(g_ascii_strcasecmp(vendor, "TRDV") == 0)
			proto_item_append_text(ti, " (Tridia VNC vendor)");

		else if(g_ascii_strcasecmp(vendor, "TGHT") == 0)
			proto_item_append_text(ti, " (Tight VNC vendor)");
			
		offset += 4;

		/* Display authentication method string */
		proto_tree_add_item(tree, hf_vnc_security_type_string, tvb,
				    offset, 8, FALSE);

		per_conversation_info->vnc_next_state =
			TIGHT_UNKNOWN_PACKET3;

		break;
		
	case TIGHT_UNKNOWN_PACKET3 :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Unknown packet (TightVNC)");
		
                proto_tree_add_text(tree, tvb, offset, -1,
				    "Unknown packet (TightVNC)");

		per_conversation_info->vnc_next_state =
			VNC_AUTHENTICATION_CHALLENGE;

		break;

	case VNC_AUTHENTICATION_CHALLENGE :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Authentication challenge from server");
                
                proto_tree_add_item(tree, hf_vnc_auth_challenge, tvb,
                                    offset, 16, FALSE);

		per_conversation_info->vnc_next_state =
			VNC_AUTHENTICATION_RESPONSE;
		break;

	case VNC_AUTHENTICATION_RESPONSE :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Authentication response from client");
		
                proto_tree_add_item(tree, hf_vnc_auth_response, tvb,
                                    offset, 16, FALSE);
		
		per_conversation_info->vnc_next_state = SECURITY_RESULT;
		break;

	case SECURITY_RESULT :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Authentication result");
		
                proto_tree_add_item(tree, hf_vnc_auth_result, tvb, offset,
                                    4, FALSE);
                auth_result = tvb_get_ntohl(tvb, offset);
                offset += 4;

		switch(auth_result) {

		case 0 : /* OK */
			per_conversation_info->vnc_next_state = CLIENT_INIT;
			break;

		case 1 : /* Failed */
			if(per_conversation_info->client_proto_ver >= 3.008) {
				text_len = tvb_get_ntohl(tvb, offset);
				proto_tree_add_text(tree, tvb, offset, 4, "Length of authentication error: %d", text_len);
				offset += 4;
				
				proto_tree_add_item(tree, hf_vnc_auth_error, tvb,
						    offset, text_len, FALSE);
				offset += text_len;
			}

			return TRUE; /* All versions: Do not continue
					processing VNC packets as connection
					will be	closed after this packet. */
			
			break;
		}

		break;

	case CLIENT_INIT :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Share desktop flag");

                proto_tree_add_item(tree, hf_vnc_share_desktop_flag, tvb,
                                    offset, 1, FALSE);
		
		per_conversation_info->vnc_next_state = SERVER_INIT;

		break;
		
	case SERVER_INIT :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Server framebuffer parameters");
	       
                proto_tree_add_item(tree, hf_vnc_width, tvb, offset, 2,
                                    FALSE);
                offset += 2;

                proto_tree_add_item(tree, hf_vnc_height, tvb, offset, 2,
                                    FALSE);
                offset += 2;

                proto_tree_add_item(tree, hf_vnc_server_bits_per_pixel,
                                    tvb, offset, 1, FALSE);
                vnc_bytes_per_pixel = tvb_get_guint8(tvb, offset)/8;
                vnc_set_bytes_per_pixel(pinfo, vnc_bytes_per_pixel);
                offset += 1;

                proto_tree_add_item(tree, hf_vnc_server_depth, tvb, offset,
                                    1, FALSE);
                offset += 1;

                proto_tree_add_item(tree, hf_vnc_server_big_endian_flag,
                                    tvb, offset, 1, FALSE);
                offset += 1;

                proto_tree_add_item(tree, hf_vnc_server_true_color_flag,
                                    tvb, offset, 1, FALSE);
                offset += 1;

                proto_tree_add_item(tree, hf_vnc_server_red_max,
                                    tvb, offset, 2, FALSE);
                offset += 2;

                proto_tree_add_item(tree, hf_vnc_server_green_max,
                                    tvb, offset, 2, FALSE);
                offset += 2;

                proto_tree_add_item(tree, hf_vnc_server_blue_max,
                                    tvb, offset, 2, FALSE);
                offset += 2;

                proto_tree_add_item(tree, hf_vnc_server_red_shift,
                                    tvb, offset, 1, FALSE);
                offset += 1;

                proto_tree_add_item(tree, hf_vnc_server_green_shift,
                                    tvb, offset, 1, FALSE);
                offset += 1;

                proto_tree_add_item(tree, hf_vnc_server_blue_shift,
                                    tvb, offset, 1, FALSE);
                offset += 1;

                proto_tree_add_item(tree, hf_vnc_padding,
                                    tvb, offset, 3, FALSE);
                offset += 3; /* Skip over 3 bytes of padding */
                
                if(tvb_length_remaining(tvb, offset) > 0) {
                        /* Sometimes the desktop name & length is skipped */
                        proto_tree_add_item(tree, hf_vnc_desktop_name_len,
                                            tvb, offset, 4, FALSE);
                        desktop_name_len = tvb_get_ntohl(tvb, offset);
                        offset += 4;

                        proto_tree_add_item(tree, hf_vnc_desktop_name,
                                            tvb, offset, desktop_name_len,
                                            FALSE);
                }

		if(per_conversation_info->security_type_selected == TIGHT)
			per_conversation_info->vnc_next_state =
				TIGHT_INTERACTION_CAPS;
		else
			per_conversation_info->vnc_next_state = NORMAL_TRAFFIC;
		break;
		
	case TIGHT_INTERACTION_CAPS :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Interaction Capabilities");

		proto_tree_add_item(tree, hf_vnc_num_server_message_types,
				    tvb, offset, 2, FALSE);

		offset += 2;

		proto_tree_add_item(tree, hf_vnc_num_client_message_types,
				    tvb, offset, 2, FALSE);

		offset += 2;

		proto_tree_add_item(tree, hf_vnc_num_encoding_types,
				    tvb, offset, 2, FALSE);

		offset += 2;

		proto_tree_add_item(tree, hf_vnc_padding, tvb, offset, 2,
				    FALSE);

		/* XXX - Display lists of server and client messages, the
		 * number of each in the packet is found above. */

		per_conversation_info->vnc_next_state = TIGHT_UNKNOWN_PACKET4;

		break;

	case TIGHT_UNKNOWN_PACKET4 :
		if (check_col(pinfo->cinfo, COL_INFO))
                        col_set_str(pinfo->cinfo, COL_INFO,
                                    "Unknown packet (TightVNC)");
		
                proto_tree_add_text(tree, tvb, offset, -1,
				    "Unknown packet (TightVNC)");
		
		per_conversation_info->vnc_next_state = NORMAL_TRAFFIC;
		
		break;

	case NORMAL_TRAFFIC :
		return FALSE;
	}

	return TRUE;
}


static void
vnc_client_to_server(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
		     proto_tree *tree)
{
	guint8 message_type;

	proto_item *ti=NULL;
	proto_tree *vnc_client_message_type_tree;

	message_type = tvb_get_guint8(tvb, *offset);

	ti = proto_tree_add_item(tree, hf_vnc_client_message_type, tvb,
				 *offset, 1, FALSE);

	vnc_client_message_type_tree =
		proto_item_add_subtree(ti, ett_vnc_client_message_type);

	*offset += 1;

	switch(message_type) {
		
	case 0 :
		vnc_client_set_pixel_format(tvb, pinfo, offset,
					    vnc_client_message_type_tree);
		break;

	case 2 :
		vnc_client_set_encodings(tvb, pinfo, offset,
					 vnc_client_message_type_tree);
		break;

	case 3 :
		vnc_client_framebuffer_update_request(tvb, pinfo, offset,
						      vnc_client_message_type_tree);
		break;

	case 4 :
		vnc_client_key_event(tvb, pinfo, offset,
				     vnc_client_message_type_tree);
		break;

	case 5:
		vnc_client_pointer_event(tvb, pinfo, offset,
					 vnc_client_message_type_tree);
		break;

	case 6 :
		vnc_client_cut_text(tvb, pinfo, offset,
				    vnc_client_message_type_tree);
		break;

	default :
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO,
					"Unknown client message type (%u)",
					message_type);
		break;
	}
}

static void
vnc_server_to_client(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
		     proto_tree *tree)
{
	guint8 message_type;
	gint bytes_needed = 0, length_remaining;
	
	proto_item *ti=NULL;
	proto_tree *vnc_server_message_type_tree;

	message_type = tvb_get_guint8(tvb, *offset);

	ti = proto_tree_add_item(tree, hf_vnc_server_message_type, tvb,
				 *offset, 1, FALSE);
	vnc_server_message_type_tree =
		proto_item_add_subtree(ti, ett_vnc_server_message_type);

	*offset += 1;

	switch(message_type) {

	case 0 :
		bytes_needed =
			vnc_server_framebuffer_update(tvb, pinfo, offset,
						      vnc_server_message_type_tree);
		break;

	case 1 :
		bytes_needed = vnc_server_set_colormap_entries(tvb, pinfo, offset, vnc_server_message_type_tree);
		break;

	case 2 :
		vnc_server_ring_bell(tvb, pinfo, offset,
				     vnc_server_message_type_tree);
		break;

	case 3 :
		bytes_needed = vnc_server_cut_text(tvb, pinfo, offset,
						   vnc_server_message_type_tree);
		break;

	default :
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_str(pinfo->cinfo, COL_INFO,
				       "Unknown server message type");
		break;
	}

	if(bytes_needed > 0 && vnc_preference_desegment &&
	   pinfo->can_desegment) {
		length_remaining = tvb_length_remaining(tvb, *offset);

		pinfo->desegment_offset = 0;
		pinfo->desegment_len = tvb_length(tvb) + bytes_needed -
			length_remaining;
		return;
	}
}


static void
vnc_client_set_pixel_format(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
			    proto_tree *tree)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Client set pixel format");
	
	proto_tree_add_item(tree, hf_vnc_padding, tvb, *offset,
			    3, FALSE);
	*offset += 3; /* Skip over 3 bytes of padding */
		
	proto_tree_add_item(tree, hf_vnc_client_bits_per_pixel, tvb, *offset,
			    1, FALSE);
	vnc_bytes_per_pixel = tvb_get_guint8(tvb, *offset)/8;
	vnc_set_bytes_per_pixel(pinfo, vnc_bytes_per_pixel);
	*offset += 1;

	proto_tree_add_item(tree, hf_vnc_client_depth, tvb, *offset,
			    1, FALSE);
	*offset += 1;

	proto_tree_add_item(tree, hf_vnc_client_big_endian_flag, tvb, *offset,
			    1, FALSE);
	*offset += 1;

	proto_tree_add_item(tree, hf_vnc_client_true_color_flag, tvb, *offset,
			    1, FALSE);
	*offset += 1;

	proto_tree_add_item(tree, hf_vnc_client_red_max, tvb, *offset,
			    2, FALSE);
	*offset += 2;

	proto_tree_add_item(tree, hf_vnc_client_green_max, tvb, *offset,
			    2, FALSE);
	*offset += 2;

	proto_tree_add_item(tree, hf_vnc_client_blue_max, tvb, *offset,
			    2, FALSE);
	*offset += 2;

	proto_tree_add_item(tree, hf_vnc_client_red_shift, tvb, *offset,
			    1, FALSE);
	*offset += 1;

	proto_tree_add_item(tree, hf_vnc_client_green_shift, tvb, *offset,
			    1, FALSE);
	*offset += 1;

	proto_tree_add_item(tree, hf_vnc_client_blue_shift, tvb, *offset,
			    1, FALSE);
	*offset += 1;

	proto_tree_add_item(tree, hf_vnc_padding, tvb, *offset,
			    3, FALSE);
	*offset += 3; /* Skip over 3 bytes of padding */
}


static void
vnc_client_set_encodings(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
			 proto_tree *tree)
{
	guint16 number_of_encodings;
	guint counter;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Client set encodings");

	proto_tree_add_item(tree, hf_vnc_padding,
			    tvb, *offset, 1, FALSE);
	*offset += 1; /* Skip over 1 byte of padding */

	number_of_encodings = tvb_get_ntohs(tvb, *offset);

	proto_tree_add_text(tree, tvb, *offset, 2,
			    "Number of encodings: %d", number_of_encodings);
	*offset += 2;

	for(counter = 1; counter <= number_of_encodings; counter++) {
		proto_tree_add_item(tree,
				    hf_vnc_client_set_encodings_encoding_type,
				    tvb, *offset, 4, FALSE);
		*offset += 4;
	}
}


static void
vnc_client_framebuffer_update_request(tvbuff_t *tvb, packet_info *pinfo,
				      gint *offset, proto_tree *tree)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO,
			    "Client framebuffer update request");

	proto_tree_add_item(tree, hf_vnc_update_req_incremental,
			    tvb, *offset, 1, FALSE);
	*offset += 1;

	proto_tree_add_item(tree, hf_vnc_update_req_x_pos,
			    tvb, *offset, 2, FALSE);
	*offset += 2;

	proto_tree_add_item(tree, hf_vnc_update_req_y_pos,
			    tvb, *offset, 2, FALSE);
	*offset += 2;

	proto_tree_add_item(tree, hf_vnc_update_req_width, tvb,
			    *offset, 2, FALSE);
	*offset += 2;

	proto_tree_add_item(tree, hf_vnc_update_req_height, tvb,
			    *offset, 2, FALSE);
	*offset += 2;
}


static void
vnc_client_key_event(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
		     proto_tree *tree)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Client key event");
	
	proto_tree_add_item(tree, hf_vnc_key_down, tvb, *offset, 1, FALSE);
	*offset += 1;
	
	proto_tree_add_item(tree, hf_vnc_padding, tvb, *offset, 2, FALSE);
	*offset += 2; /* Skip over 2 bytes of padding */
	
	proto_tree_add_item(tree, hf_vnc_key, tvb, *offset, 4, FALSE);
	*offset += 4;
}


static void
vnc_client_pointer_event(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
			 proto_tree *tree)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Client pointer event");
	
	proto_tree_add_item(tree, hf_vnc_button_1_pos, tvb, *offset, 1, FALSE);
	proto_tree_add_item(tree, hf_vnc_button_2_pos, tvb, *offset, 1, FALSE);
	proto_tree_add_item(tree, hf_vnc_button_3_pos, tvb, *offset, 1, FALSE);
	proto_tree_add_item(tree, hf_vnc_button_4_pos, tvb, *offset, 1, FALSE);
	proto_tree_add_item(tree, hf_vnc_button_5_pos, tvb, *offset, 1, FALSE);
	proto_tree_add_item(tree, hf_vnc_button_6_pos, tvb, *offset, 1, FALSE);
	proto_tree_add_item(tree, hf_vnc_button_7_pos, tvb, *offset, 1, FALSE);
	proto_tree_add_item(tree, hf_vnc_button_8_pos, tvb, *offset, 1, FALSE);
	*offset += 1;
	
	proto_tree_add_item(tree, hf_vnc_pointer_x_pos, tvb, *offset, 2, FALSE);
	*offset += 2;
	
	proto_tree_add_item(tree, hf_vnc_pointer_y_pos, tvb, *offset, 2, FALSE);
	*offset += 2;
}


static void
vnc_client_cut_text(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
		    proto_tree *tree)
{
	guint32 text_len;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Client cut text");

	proto_tree_add_item(tree, hf_vnc_padding, tvb, *offset, 3, FALSE);
	*offset += 3; /* Skip over 3 bytes of padding */

	text_len = tvb_get_ntohl(tvb, *offset);
	proto_tree_add_item(tree, hf_vnc_client_cut_text_len, tvb, *offset, 4,
			    FALSE);
	*offset += 4;

	proto_tree_add_item(tree, hf_vnc_client_cut_text, tvb, *offset,
			    text_len, FALSE);
	*offset += text_len;

}


static guint
vnc_server_framebuffer_update(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
			      proto_tree *tree)
{
	guint16 num_rects, i, width, height;
	guint bytes_needed = 0;
	gint32 encoding_type;
	proto_item *ti;
	proto_tree *vnc_rect_tree, *vnc_encoding_type_tree;
	
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO,
			    "Server framebuffer update");	

	proto_tree_add_item(tree, hf_vnc_padding, tvb, *offset, 1, FALSE);
	*offset += 1;
	
	num_rects = tvb_get_ntohs(tvb, *offset);
	proto_tree_add_text(tree, tvb, *offset, 2, "Number of rectangles: %d",
			    num_rects);
	*offset += 2;
	
	for(i = 1; i <= num_rects; i++) {

		VNC_BYTES_NEEDED(12);

		ti = proto_tree_add_text(tree, tvb, *offset, 12,
					 "Rectangle #%d", i);

		vnc_rect_tree =
			proto_item_add_subtree(ti, ett_vnc_rect);

		proto_tree_add_item(vnc_rect_tree, hf_vnc_fb_update_x_pos,
				    tvb, *offset, 2, FALSE);
		*offset += 2;
		
		proto_tree_add_item(vnc_rect_tree, hf_vnc_fb_update_y_pos,
				    tvb, *offset, 2, FALSE);
		*offset += 2;
		
		proto_tree_add_item(vnc_rect_tree, hf_vnc_fb_update_width,
				    tvb, *offset, 2, FALSE);
		width = tvb_get_ntohs(tvb, *offset);
		*offset += 2;
		
		proto_tree_add_item(vnc_rect_tree, hf_vnc_fb_update_height,
				    tvb, *offset, 2, FALSE);
		height = tvb_get_ntohs(tvb, *offset);
		*offset += 2;

		ti = proto_tree_add_item(vnc_rect_tree,
					 hf_vnc_fb_update_encoding_type,
					 tvb, *offset, 4, FALSE);
		
		vnc_encoding_type_tree =
			proto_item_add_subtree(ti, ett_vnc_encoding_type);

		encoding_type = tvb_get_ntohl(tvb, *offset);
		*offset += 4;

		switch(encoding_type) {
			
		case 0 :
			bytes_needed = vnc_raw_encoding(tvb, pinfo, offset,
							vnc_encoding_type_tree,
							width, height);
			break;
			
		case 1 :
			bytes_needed =
				vnc_copyrect_encoding(tvb, pinfo, offset,
						      vnc_encoding_type_tree,
						      width, height);
			break;
			
		case 2 :
			bytes_needed = 
				vnc_rre_encoding(tvb, pinfo, offset,
						 vnc_encoding_type_tree,
						 width, height);
			break;
			
		case 5 :
			bytes_needed =
				vnc_hextile_encoding(tvb, pinfo, offset,
						     vnc_encoding_type_tree,
						     width, height);
			break;
			
		case 16 :
			bytes_needed =
				vnc_zrle_encoding(tvb, pinfo, offset,
						  vnc_encoding_type_tree,
						  width, height);
			break;
			
		case -239 :
			bytes_needed =
				vnc_cursor_encoding(tvb, pinfo, offset,
						    vnc_encoding_type_tree,
						    width, height);
			break;
			
		case -223 : /* DesktopSize */

			/* There is no payload for this message type */

			bytes_needed = 0;
			break;

		}

		/* Check if the routines above requested more bytes to
		 * be desegmented. */
		if(bytes_needed > 0)
			return bytes_needed;
	}

	return 0;
}


static guint
vnc_raw_encoding(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
		 proto_tree *tree, guint16 width, guint16 height)
{
	guint8 bytes_per_pixel = vnc_get_bytes_per_pixel(pinfo);
	guint length;

	length = width * height * bytes_per_pixel;
	VNC_BYTES_NEEDED(length);

	proto_tree_add_item(tree, hf_vnc_raw_pixel_data, tvb, *offset, 
			    length, FALSE);
	*offset += length;

	return 0; /* bytes_needed */
}


static guint
vnc_copyrect_encoding(tvbuff_t *tvb, packet_info *pinfo _U_, gint *offset,
		      proto_tree *tree, guint16 width _U_, guint16 height _U_)
{
	proto_tree_add_item(tree, hf_vnc_copyrect_src_x_pos, tvb, *offset, 
			    2, FALSE);
	*offset += 2;

	proto_tree_add_item(tree, hf_vnc_copyrect_src_y_pos, tvb, *offset, 
			    2, FALSE);
	*offset += 2;

	return 0; /* bytes_needed */
}


static guint
vnc_rre_encoding(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
		 proto_tree *tree, guint16 width _U_, guint16 height _U_)
{
	guint8 bytes_per_pixel = vnc_get_bytes_per_pixel(pinfo);
	guint32 num_subrects, i;
	guint bytes_needed;
	proto_item *ti;
	proto_tree *subrect_tree;

	VNC_BYTES_NEEDED(4);
	proto_tree_add_item(tree, hf_vnc_rre_num_subrects, tvb, *offset, 
			    4, FALSE);
	num_subrects = tvb_get_ntohl(tvb, *offset);
	*offset += 4;

	VNC_BYTES_NEEDED(bytes_per_pixel);
	proto_tree_add_item(tree, hf_vnc_rre_bg_pixel, tvb, *offset, 
			    bytes_per_pixel, FALSE);
	*offset += bytes_per_pixel;

	for(i = 1; i <= num_subrects; i++) {
		bytes_needed = bytes_per_pixel + 8;
		VNC_BYTES_NEEDED(bytes_needed);

		ti = proto_tree_add_text(tree, tvb, *offset, bytes_per_pixel +
					 8, "Subrectangle #%d", i);
		subrect_tree =
			proto_item_add_subtree(ti, ett_vnc_rre_subrect);

		proto_tree_add_item(subrect_tree, hf_vnc_rre_subrect_pixel,
				    tvb, *offset, bytes_per_pixel, FALSE);
		*offset += bytes_per_pixel;

		proto_tree_add_item(subrect_tree, hf_vnc_rre_subrect_x_pos,
				    tvb, *offset, 2, FALSE);
		*offset += 2;

		proto_tree_add_item(subrect_tree, hf_vnc_rre_subrect_y_pos,
				    tvb, *offset, 2, FALSE);
		*offset += 2;

		proto_tree_add_item(subrect_tree, hf_vnc_rre_subrect_width,
				    tvb, *offset, 2, FALSE);
		*offset += 2;

		proto_tree_add_item(subrect_tree, hf_vnc_rre_subrect_height,
				    tvb, *offset, 2, FALSE);
		*offset += 2;
	}

	return 0; /* bytes_needed */
}


static guint
vnc_hextile_encoding(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
		     proto_tree *tree, guint16 width, guint16 height)
{
	guint8 bytes_per_pixel = vnc_get_bytes_per_pixel(pinfo);
	guint8 i, subencoding_mask, num_subrects, subrect_len;
	guint length;
	proto_tree *subencoding_mask_tree, *subrect_tree, *num_subrects_tree;
	proto_item *ti;

	VNC_BYTES_NEEDED(1);
	ti = proto_tree_add_item(tree, hf_vnc_hextile_subencoding_mask, tvb,
				 *offset, 1, FALSE);
	subencoding_mask = tvb_get_guint8(tvb, *offset);

	subencoding_mask_tree =
		proto_item_add_subtree(ti, ett_vnc_hextile_subencoding_mask);

	proto_tree_add_item(subencoding_mask_tree,
			    hf_vnc_hextile_raw, tvb, *offset, 1,
			    FALSE);
	proto_tree_add_item(subencoding_mask_tree,
			    hf_vnc_hextile_bg, tvb, *offset, 1,
			    FALSE);
	proto_tree_add_item(subencoding_mask_tree,
			    hf_vnc_hextile_fg, tvb, *offset, 1,
			    FALSE);
	proto_tree_add_item(subencoding_mask_tree,
			    hf_vnc_hextile_anysubrects, tvb, *offset, 1,
			    FALSE);
	proto_tree_add_item(subencoding_mask_tree,
			    hf_vnc_hextile_subrectscolored, tvb, *offset, 1,
			    FALSE);
	*offset += 1;
	
	if(subencoding_mask & 0x1) { /* Raw */
		length = width * height * bytes_per_pixel;

		VNC_BYTES_NEEDED(length);

		proto_tree_add_item(tree, hf_vnc_hextile_raw_value, tvb,
				    *offset, length, FALSE);
		*offset += length;
	} else { 
		if(subencoding_mask & 0x2) { /* Background Specified */
			proto_tree_add_item(tree, hf_vnc_hextile_bg_value,
					    tvb, *offset, bytes_per_pixel,
					    FALSE);
			*offset += bytes_per_pixel;
		}

		if(subencoding_mask & 0x4) { /* Foreground Specified */
			proto_tree_add_item(tree, hf_vnc_hextile_fg_value,
					    tvb, *offset, bytes_per_pixel,
					    FALSE);
			*offset += bytes_per_pixel;
		}

		if(subencoding_mask & 0x8) { /* Any Subrects */
			ti = proto_tree_add_item(tree,
						 hf_vnc_hextile_num_subrects,
						 tvb, *offset, 1,
						 FALSE);
			num_subrects = tvb_get_guint8(tvb, *offset);
			*offset += 1;
			
			num_subrects_tree =
				proto_item_add_subtree(ti, ett_vnc_hextile_num_subrects);

			for(i = 1; i <= num_subrects; i++) {

				if(subencoding_mask & 0x16) 
					subrect_len = bytes_per_pixel + 2;
				else
					subrect_len = 2;

				ti = proto_tree_add_text(num_subrects_tree, tvb,
							 *offset, subrect_len,
							 "Subrectangle #%d", i);

				subrect_tree = 
					proto_item_add_subtree(ti, ett_vnc_hextile_subrect);

				if(subencoding_mask & 0x16) {
					/* Subrects Colored */
					proto_tree_add_item(subrect_tree, hf_vnc_hextile_subrect_pixel_value, tvb, *offset, bytes_per_pixel, FALSE);
					
					*offset += bytes_per_pixel;
				}

				proto_tree_add_item(subrect_tree,
						    hf_vnc_hextile_subrect_x_pos, tvb, *offset, 1, FALSE);

				proto_tree_add_item(subrect_tree, hf_vnc_hextile_subrect_y_pos, tvb, *offset, 1, FALSE);

				*offset += 1;

				proto_tree_add_item(subrect_tree, hf_vnc_hextile_subrect_width, tvb, *offset, 1, FALSE);

				proto_tree_add_item(subrect_tree, hf_vnc_hextile_subrect_height, tvb, *offset, 1, FALSE);

				*offset += 1;
			}
		}
	}

	return 0; /* bytes_needed */
}

#ifdef HAVE_LIBZ
static guint
vnc_zrle_encoding(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
		  proto_tree *tree, guint16 width, guint16 height)
#else
static guint
vnc_zrle_encoding(tvbuff_t *tvb, packet_info *pinfo _U_, gint *offset,
		  proto_tree *tree, guint16 width _U_, guint16 height _U_)
#endif
{
	guint32 data_len;
#ifdef HAVE_LIBZ
	guint8 palette_size;
	guint8 bytes_per_cpixel = vnc_get_bytes_per_pixel(pinfo);
	gint uncomp_offset = 0;
	guint length;
	gint subencoding_type;
	tvbuff_t *uncomp_tvb = NULL;
	proto_tree *zrle_subencoding_tree;
	proto_item *ti;
#endif

	VNC_BYTES_NEEDED(4);
	proto_tree_add_item(tree, hf_vnc_zrle_len, tvb, *offset, 
			    4, FALSE);
	data_len = tvb_get_ntohl(tvb, *offset);

	*offset += 4;

	VNC_BYTES_NEEDED(data_len);

	proto_tree_add_item(tree, hf_vnc_zrle_data, tvb, *offset,
			    data_len, FALSE);

#ifdef HAVE_LIBZ
	uncomp_tvb = tvb_uncompress(tvb, *offset, data_len);

	if(uncomp_tvb != NULL) {
		tvb_set_child_real_data_tvbuff(tvb, uncomp_tvb);
		add_new_data_source(pinfo, uncomp_tvb,
				    "Uncompressed ZRLE data");

		ti = proto_tree_add_item(tree, hf_vnc_zrle_subencoding,
					 uncomp_tvb, uncomp_offset, 1, FALSE);
		zrle_subencoding_tree =
			proto_item_add_subtree(ti, ett_vnc_zrle_subencoding);

		proto_tree_add_item(zrle_subencoding_tree, hf_vnc_zrle_rle,
				    uncomp_tvb, uncomp_offset, 1, FALSE);

		proto_tree_add_item(zrle_subencoding_tree,
				    hf_vnc_zrle_palette_size, uncomp_tvb,
				    uncomp_offset, 1, FALSE);

		subencoding_type = tvb_get_guint8(uncomp_tvb, uncomp_offset);
		palette_size = subencoding_type & 0x7F;

		uncomp_offset += 1;

		if(subencoding_type == 0) { /* Raw */
			length = width * height * bytes_per_cpixel;
			VNC_BYTES_NEEDED(length);

			/* XXX - not working yet! */

			proto_tree_add_item(zrle_subencoding_tree,
					    hf_vnc_zrle_raw, uncomp_tvb,
					    uncomp_offset, length, FALSE);

		} else if(subencoding_type >= 130 && subencoding_type <= 255) {
			length = palette_size * bytes_per_cpixel;
			VNC_BYTES_NEEDED(length);

			proto_tree_add_item(zrle_subencoding_tree,
					    hf_vnc_zrle_palette, uncomp_tvb,
					    uncomp_offset, length, FALSE);
		
			/* XXX - Not complete! */
		}
			
	} else {
		proto_tree_add_text(tree, tvb, *offset, data_len,
				    "Decompression of ZRLE data failed");
	}
#endif /* HAVE_LIBZ */
	
	*offset += data_len;

	return 0; /* bytes_needed */
}


static guint
vnc_cursor_encoding(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
		    proto_tree *tree, guint16 width, guint16 height)
{
	guint8 bytes_per_pixel = vnc_get_bytes_per_pixel(pinfo);
	guint length;

	length = width * height * bytes_per_pixel;
	proto_tree_add_item(tree, hf_vnc_cursor_encoding_pixels, tvb, *offset, 
			    length, FALSE);
	*offset += length;

	length = (guint) (floor((width + 7)/8) * height);
	proto_tree_add_item(tree, hf_vnc_cursor_encoding_bitmask, tvb, *offset,
			    length, FALSE);
	*offset += length;

	return 0; /* bytes_needed */
}


static guint
vnc_server_set_colormap_entries(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
				proto_tree *tree)
{
	guint16 number_of_colors;
	guint counter, bytes_needed;
	proto_item *ti;
	proto_tree *vnc_colormap_num_groups, *vnc_colormap_color_group;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO,
			    "Server set colormap entries");

	number_of_colors = tvb_get_ntohs(tvb, 4);

	bytes_needed = (number_of_colors * 6) + 6;
	VNC_BYTES_NEEDED(bytes_needed);

	ti = proto_tree_add_item(tree, hf_vnc_server_message_type, tvb,
				 *offset, 1, FALSE);
	tree = proto_item_add_subtree(ti, ett_vnc_server_message_type);
	*offset += 1;

	proto_tree_add_item(tree, hf_vnc_padding, tvb, *offset, 1, FALSE);
	*offset += 1; /* Skip over 1 byte of padding */

	proto_tree_add_item(tree,
			    hf_vnc_colormap_first_color,
			    tvb, *offset, 2, FALSE);
	*offset += 2;

	ti = proto_tree_add_item(tree, hf_vnc_colormap_num_colors, tvb,
				 *offset, 2, FALSE);
	vnc_colormap_num_groups =
		proto_item_add_subtree(ti, ett_vnc_colormap_num_groups);

	*offset += 2;

	for(counter = 1; counter <= number_of_colors; counter++) {
		ti = proto_tree_add_text(vnc_colormap_num_groups, tvb,
					 *offset, 6,
					 "Color group #%d", counter);

		vnc_colormap_color_group =
			proto_item_add_subtree(ti,
					       ett_vnc_colormap_color_group);

		proto_tree_add_item(vnc_colormap_color_group,
				    hf_vnc_colormap_red, tvb,
				    *offset, 2, FALSE);
		*offset += 2;

		proto_tree_add_item(vnc_colormap_color_group,
				    hf_vnc_colormap_green, tvb,
				    *offset, 2, FALSE);
		*offset += 2;

		proto_tree_add_item(vnc_colormap_color_group,
				    hf_vnc_colormap_blue, tvb,
				    *offset, 2, FALSE);
		*offset += 2;
	}
	return *offset;
}


static void
vnc_server_ring_bell(tvbuff_t *tvb _U_, packet_info *pinfo, gint *offset _U_,
		     proto_tree *tree _U_)
{
	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO, "Server ring bell on client");
	/* This message type has no payload... */
}


static guint
vnc_server_cut_text(tvbuff_t *tvb, packet_info *pinfo, gint *offset,
		    proto_tree *tree)
{
	guint32 text_len;

	if (check_col(pinfo->cinfo, COL_INFO))
		col_set_str(pinfo->cinfo, COL_INFO,
			    "Server cut text");

	text_len = tvb_get_ntohl(tvb, *offset);
	proto_tree_add_item(tree,
			    hf_vnc_server_cut_text_len, tvb, *offset, 4,
			    FALSE);
	*offset += 4;
	
	VNC_BYTES_NEEDED(text_len);

	proto_tree_add_item(tree, hf_vnc_server_cut_text, tvb, *offset,
			    text_len, FALSE);
	*offset += text_len;

	return *offset;
}


static void
vnc_set_bytes_per_pixel(packet_info *pinfo, guint8 bytes_per_pixel)
{
	vnc_packet_t *per_packet_info;

	/* The per_packet_info has already been created by the
	 * vnc_startup_messages() routine. */
	per_packet_info = p_get_proto_data(pinfo->fd, proto_vnc);
	per_packet_info->bytes_per_pixel = bytes_per_pixel;
}


static guint8
vnc_get_bytes_per_pixel(packet_info *pinfo)
{
	vnc_packet_t *per_packet_info;

	/* The per_packet_info has already been created by the
	 * vnc_startup_messages() routine. */
	per_packet_info = p_get_proto_data(pinfo->fd, proto_vnc);
	return per_packet_info->bytes_per_pixel;
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
		    "Security type mandated by the server", HFILL }
		},
		{ &hf_vnc_client_security_type,
		  { "Security type selected", "vnc.security_type",
		    FT_UINT8, BASE_DEC, VALS(security_types_vs), 0x0,
		    "Security type selected by the client", HFILL }
		},
		{ &hf_vnc_vendor_code,
		  { "Vendor code", "vnc.vendor_code",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Identifies the VNC server software's vendor", HFILL }
		},
		{ &hf_vnc_security_type_string,
		  { "Security type string", "vnc.security_type_string",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Security type being used", HFILL }
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
		{ &hf_vnc_num_server_message_types,
		  { "Server message types", "vnc.num_server_message_types",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Unknown", HFILL } /* XXX - Needs description */
		},
		{ &hf_vnc_num_client_message_types,
		  { "Client message types", "vnc.num_client_message_types",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Unknown", HFILL } /* XXX - Needs description */
		},
		{ &hf_vnc_num_encoding_types,
		  { "Encoding types", "vnc.num_encoding_types",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Unknown", HFILL } /* XXX - Needs description */
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

		{ &hf_vnc_fb_update_x_pos,
		  { "X position", "vnc.fb_update_x_pos",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "X position of this server framebuffer update", HFILL }
		},

		{ &hf_vnc_fb_update_y_pos,
		  { "Y position", "vnc.fb_update_x_pos",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Y position of this server framebuffer update", HFILL }
		},

		{ &hf_vnc_fb_update_width,
		  { "Width", "vnc.fb_update_width",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Width of this server framebuffer update", HFILL }
		},

		{ &hf_vnc_fb_update_height,
		  { "Height", "vnc.fb_update_width",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Height of this server framebuffer update", HFILL }
		},

		{ &hf_vnc_fb_update_encoding_type,
		  { "Encoding type", "vnc.fb_update_encoding_type",
		    FT_INT32, BASE_DEC, VALS(encoding_types_vs), 0x0,
		    "Encoding type of this server framebuffer update", HFILL }
		},

		/* Cursor encoding */
		{ &hf_vnc_cursor_encoding_pixels,
		  { "Cursor encoding pixels", "vnc.cursor_encoding_pixels",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Cursor encoding pixel data", HFILL }
		},		

		{ &hf_vnc_cursor_encoding_bitmask,
		  { "Cursor encoding bitmask", "vnc.cursor_encoding_bitmask",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Cursor encoding pixel bitmask", HFILL }
		},		

		/* Raw Encoding */
		{ &hf_vnc_raw_pixel_data,
		  { "Pixel data", "vnc.raw_pixel_data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Raw pixel data.", HFILL }
		},		

		/* CopyRect Encoding*/
		{ &hf_vnc_copyrect_src_x_pos,
		  { "Source x position", "vnc.copyrect_src_x_pos",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "X position of the rectangle to copy from", HFILL }
		},		

		{ &hf_vnc_copyrect_src_y_pos,
		  { "Source y position", "vnc.copyrect_src_y_pos",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Y position of the rectangle to copy from", HFILL }
		},		

		/* RRE Encoding */
		{ &hf_vnc_rre_num_subrects,
		  { "Number of subrectangles", "vnc.rre_num_subrects",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Number of subrectangles contained in this encoding type", HFILL }
		},

		{ &hf_vnc_rre_bg_pixel,
		  { "Background pixel value", "vnc.rre_bg_pixel",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Background pixel value", HFILL }
		},

		{ &hf_vnc_rre_subrect_pixel,
		  { "Pixel value", "vnc.rre_subrect_pixel",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Subrectangle pixel value", HFILL }
		},

		{ &hf_vnc_rre_subrect_x_pos,
		  { "X position", "vnc.rre_subrect_x_pos",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Position of this subrectangle on the x axis", HFILL }
		},

		{ &hf_vnc_rre_subrect_y_pos,
		  { "Y position", "vnc.rre_subrect_y_pos",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Position of this subrectangle on the y axis", HFILL }
		},

		{ &hf_vnc_rre_subrect_width,
		  { "Width", "vnc.rre_subrect_width",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Width of this subrectangle", HFILL }
		},

		{ &hf_vnc_rre_subrect_height,
		  { "Height", "vnc.rre_subrect_height",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Height of this subrectangle", HFILL }
		},


		/* Hextile Encoding */
		{ &hf_vnc_hextile_subencoding_mask,
		  { "Subencoding type", "vnc.hextile_subencoding",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Hextile subencoding type.", HFILL }
		},		

		{ &hf_vnc_hextile_raw,
		  { "Raw", "vnc.hextile_raw",
		    FT_UINT8, BASE_DEC, VALS(yes_no_vs), 0x1,
		    "Raw subencoding is used in this tile", HFILL }
		},		

		{ &hf_vnc_hextile_raw_value,
		  { "Raw pixel values", "vnc.hextile_raw_value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Raw subencoding pixel values", HFILL }
		},		

		{ &hf_vnc_hextile_bg,
		  { "Background Specified", "vnc.hextile_bg",
		    FT_UINT8, BASE_DEC, VALS(yes_no_vs), 0x2,
		    "Background Specified subencoding is used in this tile", HFILL }
		},

		{ &hf_vnc_hextile_bg_value,
		  { "Background pixel value", "vnc.hextile_bg_value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Background color for this tile", HFILL }
		},

		{ &hf_vnc_hextile_fg,
		  { "Foreground Specified", "vnc.hextile_fg",
		    FT_UINT8, BASE_DEC, VALS(yes_no_vs), 0x4,
		    "Foreground Specified subencoding is used in this tile", HFILL }
		},		

		{ &hf_vnc_hextile_fg_value,
		  { "Foreground pixel value", "vnc.hextile_fg_value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Foreground color for this tile", HFILL }
		},

		{ &hf_vnc_hextile_anysubrects,
		  { "Any Subrects", "vnc.hextile_anysubrects",
		    FT_UINT8, BASE_DEC, VALS(yes_no_vs), 0x8,
		    "Any subrects subencoding is used in this tile", HFILL }
		},		

		{ &hf_vnc_hextile_num_subrects,
		  { "Number of subrectangles", "vnc.hextile_num_subrects",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Number of subrectangles that follow", HFILL }
		},		

		{ &hf_vnc_hextile_subrectscolored,
		  { "Subrects Colored", "vnc.hextile_subrectscolored",
		    FT_UINT8, BASE_DEC, VALS(yes_no_vs), 0x10,
		    "Subrects colored subencoding is used in this tile", HFILL }
		},		

		{ &hf_vnc_hextile_subrect_pixel_value,
		  { "Pixel value", "vnc.hextile_subrect_pixel_value",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Pixel value of this subrectangle", HFILL }
		},		

		{ &hf_vnc_hextile_subrect_x_pos,
		  { "X position", "vnc.hextile_subrect_x_pos",
		    FT_UINT8, BASE_DEC, NULL, 0xF0, /* Top 4 bits */
		    "X position of this subrectangle", HFILL }
		},		

		{ &hf_vnc_hextile_subrect_y_pos,
		  { "Y position", "vnc.hextile_subrect_y_pos",
		    FT_UINT8, BASE_DEC, NULL, 0xF, /* Bottom 4 bits */
		    "Y position of this subrectangle", HFILL }
		},		

		{ &hf_vnc_hextile_subrect_width,
		  { "Width", "vnc.hextile_subrect_width",
		    FT_UINT8, BASE_DEC, NULL, 0xF0, /* Top 4 bits */
		    "Subrectangle width minus one", HFILL }
		},		

		{ &hf_vnc_hextile_subrect_height,
		  { "Height", "vnc.hextile_subrect_height",
		    FT_UINT8, BASE_DEC, NULL, 0xF, /* Bottom 4 bits */
		    "Subrectangle height minus one", HFILL }
		},		


		/* ZRLE Encoding */
		{ &hf_vnc_zrle_len,
		  { "ZRLE compressed length", "vnc.zrle_len",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Length of compressed ZRLE data that follows", HFILL }
		},

		{ &hf_vnc_zrle_subencoding,
		  { "Subencoding type", "vnc.zrle_subencoding",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Subencoding type byte", HFILL }
		},

		{ &hf_vnc_zrle_rle,
		  { "RLE", "vnc.zrle_rle",
		    FT_UINT8, BASE_DEC, VALS(yes_no_vs), 0x80, /* Upper bit */
		    "Specifies that data is run-length encoded", HFILL }
		},

		{ &hf_vnc_zrle_palette_size,
		  { "Palette size", "vnc.zrle_palette_size",
		    FT_UINT8, BASE_DEC, NULL, 0x7F, /* Lower 7 bits */
		    "Palette size", HFILL }
		},

		{ &hf_vnc_zrle_data,
		  { "ZRLE compressed data", "vnc.zrle_data",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Compressed ZRLE data.  Compiling with zlib support will uncompress and dissect this data", HFILL }
		},

		{ &hf_vnc_zrle_raw,
		  { "Pixel values", "vnc.zrle_raw",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Raw pixel values for this tile", HFILL }
		},

		{ &hf_vnc_zrle_palette,
		  { "Palette", "vnc.zrle_palette",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Palette pixel values", HFILL }
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
		&ett_vnc_rect,
		&ett_vnc_encoding_type,
		&ett_vnc_rre_subrect,
		&ett_vnc_hextile_subencoding_mask,
		&ett_vnc_hextile_num_subrects,
		&ett_vnc_hextile_subrect,
		&ett_vnc_zrle_subencoding,
		&ett_vnc_colormap_num_groups,
		&ett_vnc_colormap_color_group
	};

	/* Register the protocol name and description */
	proto_vnc = proto_register_protocol("Virtual Network Computing",
					    "VNC", "vnc");

	/* Required function calls to register the header fields and subtrees */
	proto_register_field_array(proto_vnc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register our preferences module */
	vnc_module = prefs_register_protocol(proto_vnc, proto_reg_handoff_vnc);

	prefs_register_bool_preference(vnc_module, "desegment", "Reassemble VNC messages spanning multiple TCP segments.", "Whether the VNC dissector should reasss emble messages spanning multiple TCP segments.  To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.", &vnc_preference_desegment);

	prefs_register_uint_preference(vnc_module, "alternate_port", "Alternate TCP port", "Decode this port's traffic as VNC in addition to the default ports (5500, 5501, 5900, 5901)", 10, &vnc_preference_alternate_port);

}

void
proto_reg_handoff_vnc(void)
{
	static gboolean inited = FALSE;
	static dissector_handle_t vnc_handle;
	/* This is a behind the scenes variable that is not changed by the user.
	 * This stores last setting of the vnc_preference_alternate_port.  Used to keep
	 * track of when the user has changed the setting so that we can delete
	 * and re-register with the new port number. */
	static guint vnc_preference_alternate_port_last = 0;

	if(!inited) {
		vnc_handle = create_dissector_handle(dissect_vnc, proto_vnc);

		dissector_add("tcp.port", 5500, vnc_handle);
		dissector_add("tcp.port", 5501, vnc_handle);
		dissector_add("tcp.port", 5900, vnc_handle);
		dissector_add("tcp.port", 5901, vnc_handle);

		/* We don't register a port for the VNC HTTP server because
		 * that simply provides a java program for download via the
		 * HTTP protocol.  The java program then connects to a standard
		 * VNC port. */

		inited = TRUE;
	} else {  /* only after preferences have been read/changed */
		if(vnc_preference_alternate_port != vnc_preference_alternate_port_last &&
		   vnc_preference_alternate_port != 5500 &&
		   vnc_preference_alternate_port != 5501 &&
		   vnc_preference_alternate_port != 5900 &&
		   vnc_preference_alternate_port != 5901) {
			if (vnc_preference_alternate_port_last != 0) {
				dissector_delete("tcp.port",
						 vnc_preference_alternate_port_last,
						 vnc_handle);
			}
			/* Save this setting to see if has changed later */
	      		vnc_preference_alternate_port_last =
				vnc_preference_alternate_port;

			/* Register the new port setting */
			if (vnc_preference_alternate_port != 0) {
				dissector_add("tcp.port", 
					      vnc_preference_alternate_port,
					      vnc_handle);
			}
		}
	}
}
