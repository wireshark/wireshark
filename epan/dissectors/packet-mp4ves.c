/*
 * packet-mp4ves.c
 * Routines for MPEG4 dissection
 * Copyright 2007-2008, Anders Broman <anders.broman[at]ericsson.com>
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
 *
 * References:
 * http://www.ietf.org/rfc/rfc3016.txt?number=3016
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/proto.h>

#include "prefs.h"

/* Initialize the protocol and registered fields */
static int proto_mp4ves								= -1;

static int hf_mp4ves_config = -1;
static int hf_mp4ves_start_code_prefix = -1;
static int hf_mp4ves_start_code = -1;
static int hf_mp4ves_vop_coding_type = -1;

/* Initialize the subtree pointers */
static int ett_mp4ves = -1;
static int ett_mp4ves_config = -1;

/* The dynamic payload type which will be dissected as MP4V-ES */

static guint global_dynamic_payload_type = 0;


static const range_string mp4ves_startcode_vals[] = {
	{ 0,	0x1f, "video_object_start_code" },
	{ 0x20, 0x2f, "video_object_layer_start_code" },
	{ 0x30, 0xaf, "reserved" },
	{ 0xb0, 0xb0, "visual_object_sequence_start_code" },
	{ 0xb1, 0xb1, "visual_object_sequence_end_code" },
	{ 0xb2, 0xb2, "user_data_start_code" },
	{ 0xb3, 0xb3, "group_of_vop_start_code" },
	{ 0xb4, 0xb4, "video_session_error_code" },
	{ 0xb5, 0xb5, "visual_object_start_code" },
	{ 0xb6, 0xb6, "vop_start_code" },
	{ 0xb7, 0xb9, "reserved" },
	{ 0xba, 0xba, "fba_object_start_code" },
	{ 0xbb, 0xbb, "fba_object_plane_start_code" },
	{ 0xbc, 0xbc, "mesh_object_start_code" },
	{ 0xbd, 0xbd, "mesh_object_plane_start_code" },
	{ 0xbe, 0xbe, "still_texture_object_start_code" },
	{ 0xbf, 0xbf, "texture_spatial_layer_start_code" },
	{ 0xc0, 0xc0, "texture_snr_layer_start_code" },
	{ 0xc1, 0xc1, "texture_tile_start_code" },
	{ 0xc2, 0xc2, "texture_shape_layer_start_code" },
	{ 0xc3, 0xc3, "stuffing_start_code" },
	{ 0xc4, 0xc5, "reserved" },
	{ 0xc6, 0xcf, "System start codes" }, /* NOTE System start codes are defined in ISO/IEC 14496-1:1999 */
	{ 0,     0, NULL }
};

static const value_string mp4ves_vop_coding_type_vals[] = {
	{ 0,	"intra-coded (I)" },
	{ 1,	"predictive-coded (P)" },
	{ 2,	"bidirectionally-predictive-coded (B)" },
	{ 3,	"sprite (S)" },
	{ 0,	NULL }
};


#if 0
To be called from packet-sdp.c 
void 
dissect_mp4ves_config(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *mp4ves_tree;
	int bit_offset = 0;
	guint32 dword;

	item = proto_tree_add_item(tree, hf_mp4ves_config, tvb, 0, -1, FALSE);
	mp4ves_tree = proto_item_add_subtree(item, ett_mp4ves_config);

	/* Get start code prefix */
	dword = tvb_get_bits32(tvb,bit_offset, 24, FALSE);
	if (dword == 1){

	}else{
		/* No start code prefix */
		return;
	}

	proto_tree_add_bits_item(tree, hf_mp4ves_start_code_prefix, tvb, bit_offset, 24, FALSE);
	bit_offset = bit_offset+24;

	/* We are byte aligned no stuffing */
	dword = tvb_get_bits8(tvb,bit_offset, 8);
	proto_tree_add_bits_item(tree, hf_mp4ves_start_code, tvb, bit_offset, 8, FALSE);


}
#endif

void
dissect_mp4ves(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int bit_offset = 0;
	proto_item *item;
	proto_tree *mp4ves_tree;
	guint32 dword;

	/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "MP4V-ES");
	if (tree) {
		item = proto_tree_add_item(tree, proto_mp4ves, tvb, 0, -1, FALSE);
		mp4ves_tree = proto_item_add_subtree(item, ett_mp4ves);
	/*
	    +------+------+------+------+
	(a) | RTP  |  VS  |  VO  | VOL  |
	    |header|header|header|header|
	    +------+------+------+------+

	    +------+------+------+------+------------+
	(b) | RTP  |  VS  |  VO  | VOL  |Video Packet|
	    |header|header|header|header|            |
	    +------+------+------+------+------------+

	    +------+-----+------------------+
	(c) | RTP  | GOV |Video Object Plane|
	    |header|     |                  |
	    +------+-----+------------------+

	    +------+------+------------+  +------+------+------------+
	(d) | RTP  | VOP  |Video Packet|  | RTP  |  VP  |Video Packet|
	    |header|header|    (1)     |  |header|header|    (2)     |
	    +------+------+------------+  +------+------+------------+

	    +------+------+------------+------+------------+------+------------+
	(e) | RTP  |  VP  |Video Packet|  VP  |Video Packet|  VP  |Video Packet|
	    |header|header|     (1)    |header|    (2)     |header|    (3)     |
	    +------+------+------------+------+------------+------+------------+

	   +------+------+------------+  +------+------------+
	(f) | RTP  | VOP  |VOP fragment|  | RTP  |VOP fragment|
	    |header|header|    (1)     |  |header|    (2)     | ___
	    +------+------+------------+  +------+------------+

	     Figure 2 - Examples of RTP packetized MPEG-4 Visual bitstream

	So a valid packet should start with
	VS	- Visual Object Sequence Header
	GOV	- Group_of_VideoObjectPlane
	VOP	- Video Object Plane 
	VP	- Video Plane
	Otherwies it's a VOP fragment.

	visual_object_sequence_start_code: The visual_object_sequence_start_code is 
	the bit string '000001B0' in hexadecimal. It initiates a visual session.

	group_of_vop_start_code: The group_of_vop_start_code is the bit string '000001B3' in hexadecimal. It identifies 
	the beginning of a GOV header.

	vop_start_code: This is the bit string '000001B6' in hexadecimal.


	*/
		dword = tvb_get_bits32(tvb,bit_offset, 24, FALSE);
		if (dword != 1){
			/* if it's not 23 zeros followed by 1 it isn't a start code */
			proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "Data");
			return;
		}
		proto_tree_add_bits_item(tree, hf_mp4ves_start_code_prefix, tvb, bit_offset, 24, FALSE);
		bit_offset = bit_offset+24;
		dword = tvb_get_bits8(tvb,bit_offset, 8);
		proto_tree_add_bits_item(tree, hf_mp4ves_start_code, tvb, bit_offset, 8, FALSE);
		bit_offset = bit_offset+8;
		switch(dword){
		/* vop_start_code */
		case 0xb6:
			/* vop_coding_type 2 bits */
			proto_tree_add_bits_item(tree, hf_mp4ves_vop_coding_type, tvb, bit_offset, 2, FALSE);
			break;
		default:
			break;
		}
	}

}

void
proto_reg_handoff_mp4ves(void)
{
	static dissector_handle_t mp4ves_handle;
	static guint dynamic_payload_type;
	static gboolean mp4ves_prefs_initialized = FALSE;

	if (!mp4ves_prefs_initialized) {
		mp4ves_handle = find_dissector("mp4ves");
		dissector_add_string("rtp_dyn_payload_type","MP4V-ES", mp4ves_handle);
		mp4ves_prefs_initialized = TRUE;
	}else{
		if ( dynamic_payload_type > 95 )
			dissector_delete("rtp.pt", dynamic_payload_type, mp4ves_handle);
	}
	dynamic_payload_type = global_dynamic_payload_type;

	if ( dynamic_payload_type > 95 ){
		dissector_add("rtp.pt", dynamic_payload_type, mp4ves_handle);
	}
}

void
proto_register_mp4ves(void)
{                 


/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_mp4ves_config,
			{ "Configuration",        "mp4ves.configuration", 
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Configuration", HFILL }
		},
		{ &hf_mp4ves_start_code_prefix,
			{ "start code prefix",		"mp4ves.start_code_prefix", 
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"start code prefix", HFILL }
		},
		{ &hf_mp4ves_start_code,
			{ "Start code",		"mp4ves.start_code", 
			FT_UINT32, BASE_HEX, RVALS(&mp4ves_startcode_vals), 0x0,
			"Start code", HFILL }
		},
		{ &hf_mp4ves_vop_coding_type,
			{ "vop_coding_type",		"mp4ves.vop_coding_type", 
			FT_UINT8, BASE_DEC, VALS(mp4ves_vop_coding_type_vals), 0x0,
			"Start code", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_mp4ves,
		&ett_mp4ves_config,
	};

	module_t *mp4ves_module;

/* Register the protocol name and description */
	proto_mp4ves = proto_register_protocol("MP4V-ES","MP4V-ES", "mp4v-es");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_mp4ves, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	/* Register a configuration option for port */

	register_dissector("mp4ves", dissect_mp4ves, proto_mp4ves);

	/* Register a configuration option for port */	
	mp4ves_module = prefs_register_protocol(proto_mp4ves, proto_reg_handoff_mp4ves);

	prefs_register_uint_preference(mp4ves_module, "dynamic.payload.type",
								   "MP4V-ES dynamic payload type",
								   "The dynamic payload type which will be interpreted as MP4V-ES",
								   10,
								   &global_dynamic_payload_type);

}
