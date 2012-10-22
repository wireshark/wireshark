/* packet-aol.c
 *
 * Routines for dissecting the America Online protocol
 * Copyright (C) 2012 Tim Hentenaar <tim at hentenaar dot com>
 *
 * More information on the P3 frame protocol can be found on page 66 of:
 * http://koin.org/files/aol.aim/aol/fdo/manuals/WAOL.doc
 *
 * $Id$
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

#include <stdio.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-tcp.h"

/* AOL's port */
#define AOL_PORT 5190

/* Frame markers */
#define AOL_P3_FRAME_START 0x5a
#define AOL_P3_FRAME_END   0x0d

/* Frame types */
#define AOL_P3_TYPE_DATA      0x20
#define AOL_P3_TYPE_SS        0x21
#define AOL_P3_TYPE_SSR       0x22
#define AOL_P3_TYPE_INIT      0x23
#define AOL_P3_TYPE_ACK       0x24
#define AOL_P3_TYPE_NAK       0x25
#define AOL_P3_TYPE_HEARTBEAT 0x26

static const value_string aol_p3_types[] = {
	{ AOL_P3_TYPE_DATA,      "Data"        },
	{ AOL_P3_TYPE_SS,        "SS Request"  },
	{ AOL_P3_TYPE_SSR,       "SS Response" },
	{ AOL_P3_TYPE_INIT,      "Init"        },
	{ AOL_P3_TYPE_ACK,       "ACK"         },
	{ AOL_P3_TYPE_NAK,       "NAK"         },
	{ AOL_P3_TYPE_HEARTBEAT, "Heartbeat"   },
	{ 0,                     NULL          }
};

/* Platforms */
#define AOL_PLATFORM_WINDOWS 0x03
#define AOL_PLATFORM_MAC     0x0c

static const value_string aol_platforms[] = {
	{ AOL_PLATFORM_WINDOWS,  "Microsoft Windows" },
	{ AOL_PLATFORM_MAC,      "Macintosh"         },
	{ 0,                     NULL                }
};

/* Windows Memory Mode */
static const value_string aol_wmem_mode[] = {
	{ 0, "Standard" },
	{ 1, "Enhanced" },
	{ 0, NULL       }
};

/* Protocol */
static int proto_aol            = -1;

/* Special fields */
static int hf_aol_udata         = -1;
static int hf_aol_init          = -1;

/* Header fields */
static int hf_aol_start         = -1;
static int hf_aol_crc           = -1;
static int hf_aol_len           = -1;
static int hf_aol_tx_seq        = -1;
static int hf_aol_rx_seq        = -1;
static int hf_aol_type          = -1;
static int hf_aol_token         = -1;
static int hf_aol_data          = -1;
static int hf_aol_end           = -1;

/* 'INIT' PDU Fields */
static int hf_aol_platform      = -1;
static int hf_aol_version       = -1;
static int hf_aol_subversion    = -1;
static int hf_aol_unused        = -1;
static int hf_aol_machine_mem   = -1;
static int hf_aol_app_mem       = -1;
static int hf_aol_pc_type       = -1;
static int hf_aol_rel_month     = -1;
static int hf_aol_rel_day       = -1;
static int hf_aol_cust_class    = -1;
static int hf_aol_udo_timestamp = -1;
static int hf_aol_dos_ver       = -1;
static int hf_aol_sess_flags    = -1;
static int hf_aol_video_type    = -1;
static int hf_aol_cpu_type      = -1;
static int hf_aol_media_type    = -1;
static int hf_aol_win_ver       = -1;
static int hf_aol_wmem_mode     = -1;
static int hf_aol_horiz_res     = -1;
static int hf_aol_vert_res      = -1;
static int hf_aol_num_colors    = -1;
static int hf_aol_filler        = -1;
static int hf_aol_region        = -1;
static int hf_aol_lang          = -1;
static int hf_aol_conn_spd      = -1;

/* Subtrees */
static int ett_aol              = -1;
static int ett_aol_data         = -1;

/* Prefs */
static gboolean aol_desegment  = TRUE;

/**
 * Dissect the 'INIT' PDU.
 */
static guint dissect_aol_init(tvbuff_t *tvb, packet_info *pinfo _U_, guint offset, proto_tree *tree) {
	proto_item *data_item = NULL;
	proto_tree *data_tree = NULL;
	guint16     dos_ver   = 0;
	guint16     win_ver   = 0;

	/* Add the Data subtree */
	data_item = proto_tree_add_item(tree,hf_aol_init,tvb,offset,tvb_length_remaining(tvb,offset)-1,ENC_NA);
	data_tree = proto_item_add_subtree(data_item,ett_aol_data);

	/* Now, parse the structure */
	proto_tree_add_item(data_tree,hf_aol_platform,     tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_version,      tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_subversion,   tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_unused,       tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_machine_mem,  tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_app_mem,      tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_pc_type,      tvb,offset,2,ENC_LITTLE_ENDIAN); offset += 2;
	proto_tree_add_item(data_tree,hf_aol_rel_month,    tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_rel_day,      tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_cust_class,   tvb,offset,2,ENC_LITTLE_ENDIAN); offset += 2;
	proto_tree_add_item(data_tree,hf_aol_udo_timestamp,tvb,offset,4,ENC_LITTLE_ENDIAN); offset += 4;

	dos_ver = tvb_get_ntohs(tvb,offset);
	proto_tree_add_uint_format(data_tree,hf_aol_dos_ver,tvb,offset,2,dos_ver,"DOS Version: %d.%d",(dos_ver & 0xFF00) >> 8,dos_ver & 0xFF);
	offset += 2;

	proto_tree_add_item(data_tree,hf_aol_sess_flags,   tvb,offset,2,ENC_LITTLE_ENDIAN); offset += 2;
	proto_tree_add_item(data_tree,hf_aol_video_type,   tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_cpu_type,     tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_media_type,   tvb,offset,4,ENC_LITTLE_ENDIAN); offset += 4;

	/* Windows version is a 32-bit value, but only the lower 16 bits are populated */
	win_ver = tvb_get_ntohs(tvb,offset);
	proto_tree_add_uint_format(data_tree,hf_aol_win_ver,tvb,offset,2,dos_ver,"Windows Version: %d.%d",(win_ver & 0xFF00) >> 8,win_ver & 0xFF);
	offset += 4;

	proto_tree_add_item(data_tree,hf_aol_wmem_mode,    tvb,offset,1,ENC_NA);            offset += 1;
	proto_tree_add_item(data_tree,hf_aol_horiz_res,    tvb,offset,2,ENC_LITTLE_ENDIAN); offset += 2;
	proto_tree_add_item(data_tree,hf_aol_vert_res,     tvb,offset,2,ENC_LITTLE_ENDIAN); offset += 2;
	proto_tree_add_item(data_tree,hf_aol_num_colors,   tvb,offset,2,ENC_LITTLE_ENDIAN); offset += 2; /* 37b */

	/* WAOL 1.5 (48b), >= 2.5 (49b) */
	if (tvb_length_remaining(tvb,offset) <= 13) { /* WAOL 1.5 - 3.0 */
		if (tvb_length_remaining(tvb,offset) == 13) { /* WAOL > 1.5 */
			proto_tree_add_item(data_tree,hf_aol_filler,tvb,offset,1,ENC_BIG_ENDIAN); offset += 1;
		}

		proto_tree_add_item(data_tree,hf_aol_region,  tvb,offset,2,ENC_LITTLE_ENDIAN); offset += 2;
		proto_tree_add_item(data_tree,hf_aol_lang,    tvb,offset,8,ENC_LITTLE_ENDIAN); offset += 8;
		proto_tree_add_item(data_tree,hf_aol_conn_spd,tvb,offset,1,ENC_NA);            offset += 1;
	} else { /* WAOL >= 4.0 - ??? (52b) */
		;
	}

	return offset;
}

/**
 * Get the length of a particular PDU (+6 bytes for the frame)
 */
static guint get_aol_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset) {
	guint16 plen;

	/* Get the PDU length */
	plen = tvb_get_ntohs(tvb,offset+3);
	return plen + 6;
}

/**
 * Dissect a PDU
 */
static void dissect_aol_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	proto_item    *ti         = NULL;
	proto_tree    *aol_tree   = NULL;
	guint          offset     = 0;
	guint          old_offset = 0;
	guint16        token      = 0;
	guint16        pdu_len    = 0;
	guint8         pdu_type   = 0;

	/* Set the protocol name, and info column text. */
	col_set_str(pinfo->cinfo,COL_PROTOCOL,"AOL");
	col_set_str(pinfo->cinfo,COL_INFO,"America Online");

	/* Add our tree item, and tree */
	ti       = proto_tree_add_item(tree,proto_aol,tvb,0,-1,ENC_NA);
	aol_tree = proto_item_add_subtree(ti,ett_aol);
	pdu_len  = tvb_get_ntohs(tvb,3);

	/* Add the first few P3 fields */
	proto_tree_add_item(aol_tree,hf_aol_start,tvb,offset,1,ENC_NA);         offset += 1;
	proto_tree_add_item(aol_tree,hf_aol_crc,  tvb,offset,2,ENC_BIG_ENDIAN); offset += 2;
	proto_tree_add_item(aol_tree,hf_aol_len,  tvb,offset,2,ENC_BIG_ENDIAN); offset += 2;

	/* Add sequence fields */
	if (pdu_len >= 2) {
		proto_tree_add_item(aol_tree,hf_aol_tx_seq,tvb,offset,1,ENC_NA); offset += 1;
		proto_tree_add_item(aol_tree,hf_aol_rx_seq,tvb,offset,1,ENC_NA); offset += 1;
		pdu_len -= 2;
	}

	/* Add type (and add it to the tree item / info column) */
	if (pdu_len >= 1) {
		pdu_type = tvb_get_guint8(tvb,offset) & 0x3f;
		col_append_fstr(pinfo->cinfo,COL_INFO," [Type: %s]",val_to_str_const(pdu_type,aol_p3_types,"Unknown"));
		proto_item_append_text(ti," [Type: %s]",val_to_str_const(pdu_type,aol_p3_types,"Unknown"));
		proto_tree_add_uint(aol_tree,hf_aol_type,tvb,offset,1,pdu_type);
		offset += 1; pdu_len -= 1;
	}

	/* Now for the data... */
	if (pdu_len > 0) {
		old_offset = offset;

		if (tvb_length_remaining(tvb,offset) > pdu_len) {
			/* Init packets are a special case */
			if (pdu_type == AOL_P3_TYPE_INIT) {
				offset = dissect_aol_init(tvb,pinfo,offset,aol_tree);
			} else {
				if (pdu_len >= 2) {
					/* Get the token */
					token = tvb_get_ntohs(tvb,offset);

					/* Add it */
					col_append_fstr(pinfo->cinfo,COL_INFO," [Token: '%c%c']",(token & 0xFF00) >> 8,token & 0xFF);
					proto_item_append_text(ti," [Token: '%c%c']",(token & 0xFF00) >> 8,token & 0xFF);
					proto_tree_add_uint_format(aol_tree,hf_aol_token,tvb,offset,2,token,"Token: '%c%c'",(token & 0xFF00) >> 8,token & 0xFF);
					offset += 2; pdu_len -= 2;
				}

				/* Add the data */
				if (pdu_len > 0) {
					proto_tree_add_item(aol_tree,hf_aol_data,tvb,offset,pdu_len,ENC_NA);
					offset += pdu_len;
				}
			}

			if (offset < (old_offset + pdu_len)) {
				/* We didn't parse the entire pdu... */
				proto_tree_add_item(aol_tree,hf_aol_udata,tvb,offset,(old_offset+pdu_len)-offset,ENC_NA);
				offset = old_offset + pdu_len;
			}
		} else {
			/* Malformed packet */
			expert_add_info_format(pinfo,ti,PI_MALFORMED,PI_ERROR,"[Malformed Packet] pdu length > tvb length");
		}
	}

	/* End-of-Frame Marker */
	if (tvb_length_remaining(tvb,offset) >= 1) {
		proto_tree_add_item(aol_tree,hf_aol_end,tvb,offset,1,ENC_NA); offset += 1;
	} else {
		/* Malformed Packet */
		expert_add_info_format(pinfo,ti,PI_MALFORMED,PI_ERROR,"[Malformed Packet] End of frame marker expected");
	}

	return;
}

/**
 * Dissect a packet
 */
static int dissect_aol(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	/* Ensure this really is an AOL packet */
	if (tvb_length(tvb) >= 1 && tvb_get_guint8(tvb,0) != AOL_P3_FRAME_START) return 0;

	/* Dissect PDUs */
	tcp_dissect_pdus(tvb,pinfo,tree,aol_desegment,9,get_aol_pdu_len,dissect_aol_pdu);
	return tvb_length(tvb);
}

/**
 * Protocol Registration Routine
 *
 * Registers our protocol.
 */
void proto_register_aol(void) {
	/* Header fields */
	static hf_register_info hf[] = {
		/* Special Stuff */
		{ &hf_aol_udata, { "Unparsed Data",   "aol.udata",    FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
		{ &hf_aol_init,  { "AOL 'INIT' Data", "aol.init_data",FT_NONE,  BASE_NONE, NULL, 0x00, NULL, HFILL }},

		/* P3 Frame */
		{ &hf_aol_start,  { "Start of Frame", "aol.start",    FT_UINT8,  BASE_HEX,  NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_crc,    { "Checksum",       "aol.checksum", FT_UINT16, BASE_HEX,  NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_len,    { "Length",         "aol.len",      FT_UINT16, BASE_DEC,  NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_tx_seq, { "Tx Sequence",    "aol.tx_seq",   FT_UINT8,  BASE_HEX,  NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_rx_seq, { "Rx Sequence",    "aol.rx_seq",   FT_UINT8,  BASE_HEX,  NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_type,   { "Type",           "aol.type",     FT_UINT8,  BASE_HEX,  VALS(aol_p3_types), 0x00, NULL, HFILL }},
		{ &hf_aol_token,  { "Token",          "aol.token",    FT_UINT16, BASE_HEX,  NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_data,   { "Data",           "aol.data",     FT_BYTES,  BASE_NONE, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_end,    { "End of Frame",   "aol.end",      FT_UINT8,  BASE_HEX,  NULL,               0x00, NULL, HFILL }},

		/* Init packet */
		{ &hf_aol_platform,     { "Platform",         "aol.init.platform",   FT_UINT8,  BASE_HEX, VALS(aol_platforms),0x00, NULL, HFILL }},
		{ &hf_aol_version,      { "Client Version",   "aol.init.version",    FT_UINT8,  BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_subversion,   { "Client Subversion","aol.init.subversion", FT_UINT8,  BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_unused,       { "Unused",           "aol.init.unused",     FT_UINT8,  BASE_HEX, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_machine_mem,  { "Machine Memory",   "aol.init.memory",     FT_UINT8,  BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_app_mem,      { "App Memory",       "aol.init.app_memory", FT_UINT8,  BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_pc_type,      { "PC Type",          "aol.init.pc_type",    FT_UINT16, BASE_HEX, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_rel_month,    { "Release Month",    "aol.init.rel_month",  FT_UINT8,  BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_rel_day,      { "Release Day",      "aol.init.rel_day",    FT_UINT8,  BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_cust_class,   { "Customer Class",   "aol.init.cust_class", FT_UINT16, BASE_HEX, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_udo_timestamp,{ "UDO Timestamp",    "aol.init.udo_ts",     FT_UINT32, BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_dos_ver,      { "DOS Version",      "aol.init.dos_ver",    FT_UINT16, BASE_HEX, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_sess_flags,   { "Session Flags",    "aol.init.sess_flags", FT_UINT16, BASE_HEX, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_video_type,   { "Video Type",       "aol.init.video_type", FT_UINT8,  BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_cpu_type,     { "CPU Type",         "aol.init.cpu_type",   FT_UINT8,  BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_media_type,   { "Media Type",       "aol.init.media_type", FT_UINT32, BASE_HEX, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_win_ver,      { "Windows Version",  "aol.init.win_ver",    FT_UINT32, BASE_HEX, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_wmem_mode,    { "Windows Mem Type", "aol.init.wmem_mode",  FT_UINT8,  BASE_DEC, VALS(aol_wmem_mode),0x00, NULL, HFILL }},
		{ &hf_aol_horiz_res,    { "Horizontal Res",   "aol.init.horiz_res",  FT_UINT16, BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_vert_res,     { "Vertical Res",     "aol.init.vert_res",   FT_UINT16, BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_num_colors,   { "Colors",           "aol.init.colors",     FT_UINT16, BASE_DEC, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_filler,       { "Filler Byte",      "aol.init.filler",     FT_UINT8,  BASE_HEX, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_region,       { "AOL Region",       "aol.init.region",     FT_UINT16, BASE_HEX, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_lang,         { "AOL Language(s)",  "aol.init.langs",      FT_UINT64, BASE_HEX, NULL,               0x00, NULL, HFILL }},
		{ &hf_aol_conn_spd,     { "Connection Speed", "aol.init.conn_spd",   FT_UINT8,  BASE_HEX, NULL,               0x00, NULL, HFILL }},
	};

	/* Trees */
	static gint *ett[] = {
		&ett_aol,
		&ett_aol_data
	};

	/* Module (for prefs) */
	module_t *aol_module;

	/* Register the protocol and header fields */
	proto_aol = proto_register_protocol("America Online","AOL","aol");
	proto_register_field_array(proto_aol,hf,array_length(hf));
	proto_register_subtree_array(ett,array_length(ett));

	/* Register prefs */
	aol_module = prefs_register_protocol(proto_aol,NULL);
	prefs_register_bool_preference(aol_module,"desegment",
	    "Reassemble AOL messages spanning multiple TCP segments",
	    "Whether the AOL dissector should reassemble messages spanning multiple TCP segments. "
	    "To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" "
	    "in the TCP protocol settings.",&aol_desegment);
}

/**
 * Dissector Handoff Routine
 *
 * Initialize the dissector.
 */
void proto_reg_handoff_aol(void) {
	static dissector_handle_t aol_handle;

	aol_handle = new_create_dissector_handle(dissect_aol,proto_aol);
	dissector_add_uint("tcp.port",AOL_PORT,aol_handle);
}

/* vi:set ts=4: */
