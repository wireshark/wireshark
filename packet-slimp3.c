/* packet-slimp3.c
 * Routines for SliMP3 protocol dissection
 *
 * Ashok Narayanan <ashokn@cisco.com>
 *
 * Adds support for the data packet protocol for the SliMP3
 * See www.slimdevices.com for details.
 *
 * $Id: packet-slimp3.c,v 1.1 2001/12/27 05:24:20 ashokn Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include "packet.h"
#include "conversation.h"

static int proto_slimp3 = -1;
static int hf_slimp3_opcode = -1;
static int hf_slimp3_ir = -1;
static int hf_slimp3_display = -1;
static int hf_slimp3_control = -1;
static int hf_slimp3_hello = -1;
static int hf_slimp3_i2c = -1;
static int hf_slimp3_data_request = -1;
static int hf_slimp3_data = -1;
static int hf_slimp3_discover_request = -1;
static int hf_slimp3_discover_response = -1;

static gint ett_slimp3 = -1;

static dissector_handle_t slimp3_handle;

#define UDP_PORT_SLIMP3    1069

#define	SLIMP3_IR	'i'
#define	SLIMP3_CONTROL	's'
#define	SLIMP3_HELLO	'h'
#define	SLIMP3_DATA	'm'
#define	SLIMP3_DATA_REQ	'r'
#define	SLIMP3_DISPLAY	'l'
#define	SLIMP3_I2C 	'2'
#define	SLIMP3_DISC_REQ 'd'
#define	SLIMP3_DISC_RSP 'D'

static const value_string slimp3_opcode_vals[] = {
  { SLIMP3_IR,       "Infrared Remote Code" },
  { SLIMP3_CONTROL,  "Stream Control" },
  { SLIMP3_DATA,     "MPEG Data" },
  { SLIMP3_DATA_REQ, "Data Request" },
  { SLIMP3_HELLO,    "Hello" },
  { SLIMP3_DISPLAY,  "Display" },
  { SLIMP3_I2C,      "I2C" },
  { SLIMP3_DISC_REQ, "Discovery Request" },
  { SLIMP3_DISC_RSP, "Discovery Response" },
  { 0,               NULL }
};

static const value_string slimp3_ir_codes_jvc[] = {
    { 0xf786, "One" }, 
    { 0xf746, "Two" }, 
    { 0xf7c6, "Three" }, 
    { 0xf726, "Four" }, 
    { 0xf7a6, "Five" }, 
    { 0xf766, "Six" }, 
    { 0xf7e6, "Seven" }, 
    { 0xf716, "Eight" }, 
    { 0xf796, "Nine" }, 
    { 0xf776, "Ten" }, 

    { 0xf7f6, "Picture-In-Picture" }, 
    /* { 0xf7XX, "Enter" }, */
    { 0xf70e, "Back" }, 
    { 0xf732, "Play" }, 
    { 0xf76e, "Forward" }, 
    { 0xf743, "Record" }, 
    { 0xf7c2, "Stop" }, 
    { 0xf7b2, "Pause" }, 
    /* { 0xf7XX, "TV/Video" }, */
    { 0xf703, "Display" }, 
    { 0xf7b3, "Sleep" }, 
    { 0xf7b6, "Guide" }, 
    { 0xf70b, "Up" }, 
    { 0xf74b, "Left" }, 
    { 0xf7cb, "Right" }, 
    { 0xf78b, "Down" }, 
    { 0xf783, "Menu" }, 
    { 0xf72b, "OK" }, 
    { 0xf778, "Volume Up" }, 
    { 0xf7f8, "Volume Down" }, 
    { 0xf70d, "Channel Up" }, 
    { 0xf78d, "Channel Down" }, 
    /* { 0xf7XX, "Mute" },  */
    { 0xf7ab, "Recall" }, 
    { 0xf702, "Power" }, 
};

static const value_string slimp3_display_commands[] = {
    {  0x1, "Clear Display"},
    {  0x2, "Cursor to 1st Line Home"},

    {  0x4, "Mode: Decrement Address, Shift Cursor"},
    {  0x5, "Mode: Decrement Address, Shift Display"},
    {  0x6, "Mode: Increment Address, Shift Cursor"},
    {  0x7, "Mode: Increment Address, Shift Display"},
    
    {  0x8, "Display Off"},
    {  0xd, "Display On, With Blinking"},
    {  0xe, "Display On, With Cursor"},
    {  0xf, "Display On, With Cursor And Blinking"},

    { 0x10, "Move Cursor Left"},
    { 0x14, "Move Cursor Right"},
    { 0x18, "Shift Display Left"},
    { 0x1b, "Shift Display Right"},

    { 0x30, "Set (8-bit)"},
    { 0x20, "Set (4-bit)"},

    { 0xa0, "Cursor to Top Right"},
    { 0xc0, "Cursor to 2nd Line Home"},

    {    0, NULL},
};

static const value_string slimp3_display_fset8[] = {
    { 0x0, "Brightness 100%"},
    { 0x1, "Brightness 75%"},
    { 0x2, "Brightness 50%"},
    { 0x3, "Brightness 25%"},

    {   0, NULL },
};

static const value_string slimp3_stream_control[] = {
    { 1, "Reset buffer, Start New Stream"},
    { 2, "Pause Playback"},
    { 4, "Resume Playback"},
    {   0, NULL },
};

static void
dissect_slimp3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree	*slimp3_tree = NULL;
    proto_tree	*el_tree = NULL;
    proto_item	*ti = NULL;
    conversation_t  *conversation;
    gint		i1;
    gint		offset = 0;
    guint16		opcode;
    guint16         error;
    guint32      i;
    guint8       subcode;
    char addc_str[101];
    char *addc_strp;
    

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SliMP3");

    opcode = tvb_get_guint8(tvb, offset);

    if (check_col(pinfo->cinfo, COL_INFO)) {

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
		     val_to_str(opcode, slimp3_opcode_vals, "Unknown (%c)"));

    }

    addc_strp = addc_str;
    if (tree) {

	ti = proto_tree_add_item(tree, proto_slimp3, tvb, offset,
				 tvb_length_remaining(tvb, offset), FALSE);
	slimp3_tree = proto_item_add_subtree(ti, ett_slimp3);

	proto_tree_add_uint(slimp3_tree, hf_slimp3_opcode, tvb,
			    offset, 1, opcode);
    }
    switch (opcode) {

    case SLIMP3_IR:
	if (tree) {
	    proto_tree_add_item_hidden(slimp3_tree, hf_slimp3_ir, tvb, offset+8, 4, FALSE);

	    i1 = tvb_get_ntohl(tvb, offset+2);
	    proto_tree_add_text(slimp3_tree, tvb, offset+2, 4, "Uptime: %u sec (%u ticks)", 
				i1/625000, i1);
	    proto_tree_add_text(slimp3_tree, tvb, offset+6, 1, "Code identifier: 0x%0x: %s", 
				tvb_get_guint8(tvb, offset+6), 
				tvb_get_guint8(tvb, offset+6)==0xff ? "JVC DVD Player" : "Unknown");
	    proto_tree_add_text(slimp3_tree, tvb, offset+7, 1, "Code bits: %d",
				tvb_get_guint8(tvb, offset+7));

	    i1 = tvb_get_ntohl(tvb, offset+8);
	    /* Is this a standard JVC remote code? */
	    if (tvb_get_guint8(tvb, offset+6) == 0xff && 
		tvb_get_guint8(tvb, offset+7) == 16) {

		proto_tree_add_text(slimp3_tree, tvb, offset+8, 4, 
				    "Infrared Code: %s: 0x%0x", 
				    val_to_str(i1, slimp3_ir_codes_jvc, "Unknown"),
				    tvb_get_ntohl(tvb, offset+8));
	    } else {
		/* Unknown code; just write it */
		proto_tree_add_text(slimp3_tree, tvb, offset+8, 4, "Infrared Code: 0x%0x", 
				    tvb_get_ntohl(tvb, offset+8));
	    }
	}
	if (check_col(pinfo->cinfo, COL_INFO)) {
	    i1 = tvb_get_ntohl(tvb, offset+8);
	    if (tvb_get_guint8(tvb, offset+6) == 0xff && 
		tvb_get_guint8(tvb, offset+7) == 16) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", JVC: %s", 
				val_to_str(i1, slimp3_ir_codes_jvc, "Unknown (0x%0x)"));
	    } else {
		/* Unknown code; just write it */
		col_append_fstr(pinfo->cinfo, COL_INFO, ", 0x%0x", i1);
	    }
	}
	break;

    case SLIMP3_DISPLAY:
	if (tree) {
	    int in_str;

	    proto_tree_add_item_hidden(slimp3_tree, hf_slimp3_display,
				       tvb, offset, 1, FALSE);

	    /* Loop through the commands */
	    i1 = 18;
	    in_str = 0;
	    while (i1 < tvb_length_remaining(tvb, offset)) {
		switch(tvb_get_guint8(tvb, offset + i1)) {
		case 0:
		    in_str = 0; 
		    proto_tree_add_text(slimp3_tree, tvb, offset + i1, 2, 
					"Delay (%d ms)", tvb_get_guint8(tvb, offset + i1 + 1));
		    i1 += 2;
		    break;
		case 3:
		    if (ti && in_str) {
			proto_item_append_text(ti, "%c", 
					       tvb_get_guint8(tvb, offset + i1 + 1));
		    } else {
			ti = proto_tree_add_text(slimp3_tree, tvb, offset + i1, 2, 
						 "String: %c", 
						 tvb_get_guint8(tvb, offset + i1 + 1));
			in_str = 1;
		    }
		    i1 += 2;
		    break;

		case 2:
		    in_str = 0; 
		    ti = proto_tree_add_text(slimp3_tree, tvb, offset + i1, 2, 
					     "Command: %s", 
					     val_to_str(tvb_get_guint8(tvb, offset + i1 + 1), 
							slimp3_display_commands, 
							"Unknown (0x%0x)"));
		    if ((tvb_get_guint8(tvb, offset + i1 + 1) & 0xf0) == 0x30) { 
			proto_item_append_text(ti, ": %s", 
					       val_to_str(tvb_get_guint8(tvb, offset + i1 + 2),
							  slimp3_display_fset8, 
							  "Unknown (0x%0x)"));
			i1 += 2 ;
		    }
		    i1 += 2;
		    break;
			
		default:
		    proto_tree_add_text(slimp3_tree, tvb, offset + i1, 2, 
					"Unknown 0x%0x, 0x%0x", 
					tvb_get_guint8(tvb, offset + i1),
					tvb_get_guint8(tvb, offset + i1 + 1));
		    i1 += 2;
		    break;
		}
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    i1 = 18;
	    addc_strp = addc_str;
	    while (i1 < tvb_length_remaining(tvb, offset)) {
		switch(tvb_get_guint8(tvb, offset + i1)) {
		case 0: *addc_strp++ = '.'; break;
		case 2: *addc_strp++ = '|'; 
		    if ((tvb_get_guint8(tvb, offset + i1 + 1) & 0xf0) == 0x30) i1+=2;
		    break;
		case 3:
		    if (addc_strp==addc_str || 
			*(addc_strp-1)!=' ' ||
			tvb_get_guint8(tvb, offset + i1 + 1) != ' ')
			*addc_strp++ = tvb_get_guint8(tvb, offset + i1 + 1);
		}
		i1+=2;
	    }
	    *addc_strp = 0;
	    if (addc_strp - addc_str > 0)
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", addc_str);
	}

	break;

    case SLIMP3_CONTROL:
	if (tree) {
	    proto_tree_add_item_hidden(slimp3_tree, hf_slimp3_control,
				       tvb, offset+1, 1, FALSE);
	    proto_tree_add_text(slimp3_tree, tvb, offset+1, 1, "Command: %s",
				val_to_str(tvb_get_guint8(tvb, offset+1), 
					   slimp3_stream_control, "Unknown (0x%0x)"));
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", 
			    val_to_str(tvb_get_guint8(tvb, offset+1), 
				       slimp3_stream_control, "Unknown (0x%0x)"));
	}
	break;

    case SLIMP3_HELLO:
	if (tree) {
	    proto_tree_add_item_hidden(slimp3_tree, hf_slimp3_hello,
				       tvb, offset+1, 1, FALSE);
	    if (pinfo->destport == UDP_PORT_SLIMP3) {
		guint8 fw_ver = 0;
		/* Hello response; client->server */
		proto_tree_add_text(slimp3_tree, tvb, offset, 1, "Hello Response (Client --> Server)");
		proto_tree_add_text(slimp3_tree, tvb, offset+1, 1, "Device ID: %d", 
				    tvb_get_guint8(tvb, offset+1));
		fw_ver = tvb_get_guint8(tvb, offset+2);
		proto_tree_add_text(slimp3_tree, tvb, offset+2, 1, "Firmware Revision: %d.%d (0x%0x)", 
				    fw_ver>>4, fw_ver & 0xf, fw_ver);
	    } else {
		/* Hello request; server->client */
		proto_tree_add_text(slimp3_tree, tvb, offset, 1, "Hello Request (Server --> Client)");
	    }
	}
	break;

    case SLIMP3_I2C:
	if (tree) {
	    proto_tree_add_item_hidden(slimp3_tree, hf_slimp3_i2c,
				       tvb, offset, 1, FALSE);
	    if (pinfo->destport == UDP_PORT_SLIMP3) {
		/* Hello response; client->server */
		proto_tree_add_text(slimp3_tree, tvb, offset, tvb_length_remaining(tvb, offset), 
				    "I2C Response (Client --> Server)");
	    } else {
		/* Hello request; server->client */
		proto_tree_add_text(slimp3_tree, tvb, offset, tvb_length_remaining(tvb, offset), 
				    "I2C Request (Server --> Client)");
	    }
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    if (pinfo->destport == UDP_PORT_SLIMP3) {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Response");
	    } else {
		col_append_fstr(pinfo->cinfo, COL_INFO, ", Request");
	    }
	}
	break;

    case SLIMP3_DATA_REQ:
	if (tree) {
	    proto_tree_add_item_hidden(slimp3_tree, hf_slimp3_data_request,
				       tvb, offset, 1, FALSE);
	    proto_tree_add_text(slimp3_tree, tvb, offset+2, 2, 
				"Requested offset: %d bytes.", 
				tvb_get_ntohs(tvb, offset+2)*2);
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Offset: %d bytes",
			    tvb_get_ntohs(tvb, offset+2)*2);
	}
	break;

    case SLIMP3_DATA:
	if (tree) {
	    proto_tree_add_item_hidden(slimp3_tree, hf_slimp3_data,
				       tvb, offset, 1, FALSE);
	    proto_tree_add_text(slimp3_tree, tvb, offset, tvb_length_remaining(tvb, offset), 
				"Length: %d bytes", tvb_length_remaining(tvb, offset+18));
	    proto_tree_add_text(slimp3_tree, tvb, offset+2, 2, 
				"Buffer offset: %d bytes.", 
				tvb_get_ntohs(tvb, offset+2) * 2);
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Length: %d bytes, Offset: %d bytes.",
			    tvb_length_remaining(tvb, offset+18),
			    tvb_get_ntohs(tvb, offset+2) * 2);
	}
	break;

    case SLIMP3_DISC_REQ:
	if (tree) {
	    guint8 fw_ver;
	    proto_tree_add_item_hidden(slimp3_tree, hf_slimp3_discover_request,
				       tvb, offset, 1, FALSE);
	    proto_tree_add_text(slimp3_tree, tvb, offset+1, 1,
				"Device ID: %d.", tvb_get_guint8(tvb, offset+1));
	    fw_ver = tvb_get_guint8(tvb, offset+2);
	    proto_tree_add_text(slimp3_tree, tvb, offset+2, 1, "Firmware Revision: %d.%d (0x%0x)", 
				fw_ver>>4, fw_ver & 0xf, fw_ver);
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    guint8 fw_ver = tvb_get_guint8(tvb, offset+2);
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Device ID: %d. Firmware: %d.%d",
			    tvb_get_guint8(tvb, offset+1), fw_ver>>4, fw_ver & 0xf);
	}
	break;

    case SLIMP3_DISC_RSP:
	if (tree) {
	    guint8 fw_ver;
	    proto_tree_add_item_hidden(slimp3_tree, hf_slimp3_discover_response,
				       tvb, offset, 1, FALSE);
	    proto_tree_add_text(slimp3_tree, tvb, offset+2, 4,
				"Server Address: %s.", 
				ip_to_str(tvb_get_ptr(tvb, offset+2, 4)));
	    proto_tree_add_text(slimp3_tree, tvb, offset+6, 2, 
				"Server Port: %d", tvb_get_ntohs(tvb, offset + 6));
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
	    guint8 fw_ver = tvb_get_guint8(tvb, offset+2);
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Server Address: %s. Server Port: %d", 
			    ip_to_str(tvb_get_ptr(tvb, offset+2, 4)),
			    tvb_get_ntohs(tvb, offset + 6));
	}
	break;

    default:
	if (tree) {
	    proto_tree_add_text(slimp3_tree, tvb, offset, tvb_length_remaining(tvb, offset),
				"Data (%d bytes)", tvb_length_remaining(tvb, offset));
	}
	break;

    }
}

void
proto_register_slimp3(void)
{
  static hf_register_info hf[] = {
    { &hf_slimp3_opcode,
      { "Opcode",	      "slimp3.opcode",
	FT_UINT8, BASE_DEC, VALS(slimp3_opcode_vals), 0x0,
      	"SLIMP3 message type", HFILL }},

    { &hf_slimp3_ir,
      { "Infrared",	      "slimp3.ir",
	FT_UINT32, BASE_HEX, NULL, 0x0,
      	"SLIMP3 Infrared command", HFILL }},

    { &hf_slimp3_control,
      { "Control Packet",   "slimp3.control",
	FT_BOOLEAN, BASE_DEC, NULL, 0x0,
      	"SLIMP3 control", HFILL }},

    { &hf_slimp3_display,
      { "Display",	              "slimp3.display",
	FT_BOOLEAN, BASE_DEC, NULL, 0x0,
      	"SLIMP3 display", HFILL }},

    { &hf_slimp3_hello,
      { "Hello",	              "slimp3.hello",
	FT_BOOLEAN, BASE_DEC, NULL, 0x0,
      	"SLIMP3 hello", HFILL }},

    { &hf_slimp3_i2c,
      { "I2C",	              "slimp3.i2c",
	FT_BOOLEAN, BASE_DEC, NULL, 0x0,
      	"SLIMP3 I2C", HFILL }},

    { &hf_slimp3_data,
      { "Data",              "slimp3.data",
	FT_BOOLEAN, BASE_DEC, NULL, 0x0,
      	"SLIMP3 Data", HFILL }},

    { &hf_slimp3_data_request,
      { "Data Request",      "slimp3.data_req",
	FT_BOOLEAN, BASE_DEC, NULL, 0x0,
      	"SLIMP3 Data Request", HFILL }},

    { &hf_slimp3_discover_request,
      { "Discovery Request", "slimp3.discovery_req",
	FT_BOOLEAN, BASE_DEC, NULL, 0x0,
      	"SLIMP3 Discovery Request", HFILL }},

    { &hf_slimp3_discover_response,
      { "Discovery Response", "slimp3.discovery_response",
	FT_BOOLEAN, BASE_DEC, NULL, 0x0,
      	"SLIMP3 Discovery Response", HFILL }},

  };
  static gint *ett[] = {
    &ett_slimp3,
  };

  proto_slimp3 = proto_register_protocol("SliMP3 Communication Protocol",
				       "SliMP3", "slimp3");
  proto_register_field_array(proto_slimp3, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  slimp3_handle = create_dissector_handle(dissect_slimp3, proto_slimp3);
}

void
proto_reg_handoff_slimp3(void)
{
  dissector_add("udp.port", UDP_PORT_SLIMP3, slimp3_handle);
}
