/* packet-enttec.c
 * Routines for ENTTEC packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2003,2004 by Erwin Rol <erwin@erwinrol.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/strutil.h>

/*
 * See
 *
 *	http://www.enttec.com/docs/enttec_protocol.pdf
 */

/* Define UDP/TCP ports for ENTTEC */

#define UDP_PORT_ENTTEC 0x0D05
#define TCP_PORT_ENTTEC 0x0D05


#define ENTTEC_HEAD_ESPR 0x45535052
#define ENTTEC_HEAD_ESPP 0x45535050
#define ENTTEC_HEAD_ESAP 0x45534150
#define ENTTEC_HEAD_ESDD 0x45534444
#define ENTTEC_HEAD_ESNC 0x45534E43
#define ENTTEC_HEAD_ESZZ 0x45535A5A

static const value_string enttec_head_vals[] = {
	{ ENTTEC_HEAD_ESPR,	"Poll Reply" },
	{ ENTTEC_HEAD_ESPP,	"Poll" },
	{ ENTTEC_HEAD_ESAP,	"Ack/nAck" },
	{ ENTTEC_HEAD_ESDD,	"DMX Data" },
	{ ENTTEC_HEAD_ESNC,	"Config" },
	{ ENTTEC_HEAD_ESZZ,	"Reset" },
	{ 0,			NULL }
};

#define ENTTEC_DATA_TYPE_DMX		0x01
#define ENTTEC_DATA_TYPE_CHAN_VAL	0x02
#define ENTTEC_DATA_TYPE_RLE		0x04

static const value_string enttec_data_type_vals[] = {
	{ ENTTEC_DATA_TYPE_DMX,		"Uncompressed DMX" },
	{ ENTTEC_DATA_TYPE_CHAN_VAL,	"Channel+Value" },
	{ ENTTEC_DATA_TYPE_RLE,		"RLE Compressed DMX" },
	{ 0,				NULL }
};

void proto_reg_handoff_enttec(void);

/* Define the enttec proto */
static int proto_enttec = -1;

/* general */
static int hf_enttec_head = -1;

/* poll */
static int hf_enttec_poll_type = -1;

/* poll reply */
static int hf_enttec_poll_reply_mac = -1;
static int hf_enttec_poll_reply_node_type = -1;
static int hf_enttec_poll_reply_version = -1;
static int hf_enttec_poll_reply_switch = -1;
static int hf_enttec_poll_reply_name = -1;
static int hf_enttec_poll_reply_option = -1;
static int hf_enttec_poll_reply_tos = -1;
static int hf_enttec_poll_reply_ttl = -1;

/* dmx data */
static int hf_enttec_dmx_data_universe = -1;
static int hf_enttec_dmx_data_start_code = -1;
static int hf_enttec_dmx_data_type = -1;
static int hf_enttec_dmx_data_size = -1;
static int hf_enttec_dmx_data_data = -1;
static int hf_enttec_dmx_data_data_filter = -1;
static int hf_enttec_dmx_data_dmx_data = -1;

/* Define the tree for enttec */
static int ett_enttec = -1;

/*
 * Here are the global variables associated with the preferences
 * for enttec
 */

static guint global_udp_port_enttec = UDP_PORT_ENTTEC;
static guint global_tcp_port_enttec = TCP_PORT_ENTTEC;

static gint global_disp_chan_val_type = 0;
static gint global_disp_col_count = 16;
static gint global_disp_chan_nr_type = 0;

static gint
dissect_enttec_poll_reply(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_enttec_poll_reply_mac, tvb,
					offset, 6, FALSE);
	offset += 6;

	proto_tree_add_item(tree, hf_enttec_poll_reply_node_type, tvb,
					offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_enttec_poll_reply_version, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_enttec_poll_reply_switch, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	
	proto_tree_add_item(tree, hf_enttec_poll_reply_name, tvb,
					offset, 10, FALSE);
	offset += 10;

	proto_tree_add_item(tree, hf_enttec_poll_reply_option, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	
	proto_tree_add_item(tree, hf_enttec_poll_reply_tos, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	
	proto_tree_add_item(tree, hf_enttec_poll_reply_ttl, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* data */

	return offset;
}

static gint
dissect_enttec_poll(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_enttec_poll_type, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	return offset;
}

static gint
dissect_enttec_ack(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{

	return offset;
}

static gint
dissect_enttec_dmx_data(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
	const char* chan_format[] = {
		"%2u ",
		"%02x ",
		"%3u "
	};
	const char* string_format[] = {
		"%03x: %s",
		"%3u: %s"
	};

	guint8 *dmx_data = ep_alloc(512 * sizeof(guint8));
	guint16 *dmx_data_offset = ep_alloc(513 * sizeof(guint16)); /* 1 extra for last offset */
	emem_strbuf_t *dmx_epstr;

	proto_tree *hi,*si;
	proto_item *item;
	guint16 length,r,c,row_count;
	guint8 v,type,count;
	guint16 ci,ui,i,start_offset,end_offset;

	proto_tree_add_item(tree, hf_enttec_dmx_data_universe, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_enttec_dmx_data_start_code, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	type = tvb_get_guint8(tvb, offset);	
	proto_tree_add_item(tree, hf_enttec_dmx_data_type, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(tree, hf_enttec_dmx_data_size, tvb,
					offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/*
	 * XXX - we should handle a too-long length better.
	 */
	if (length > 512)
		length = 512;

	if (type == ENTTEC_DATA_TYPE_RLE) {
		/* uncompress the DMX data */
		ui = 0;
		ci = 0;
		while (ci < length && ui < 512) {
			v = tvb_get_guint8(tvb, offset+ci);
			if (v == 0xFE) {
				ci++;
				count = tvb_get_guint8(tvb, offset+ci);
				ci++;
				v = tvb_get_guint8(tvb, offset+ci);
				ci++;
				for (i=0;i < count && ui < 512;i++) {
					dmx_data[ui] = v;
					dmx_data_offset[ui] = ci-3;
					ui++;
				}
			} else if (v == 0xFD) {
				ci++;
				v = tvb_get_guint8(tvb, offset+ci);				
				dmx_data[ui] = v;
				dmx_data_offset[ui] = ci;
				ci++;
				ui++;
			} else {
				dmx_data[ui] = v;
				dmx_data_offset[ui] = ci;
				ui++;
				ci++;
			}
		}
		dmx_data_offset[ui] = ci;
	} else {
		for (ui=0; ui < length;ui++) {
			dmx_data[ui] =  tvb_get_guint8(tvb, offset+ui);
			dmx_data_offset[ui] = ui;
		}
		dmx_data_offset[ui] = ui;
	} 


	if ((type == ENTTEC_DATA_TYPE_DMX || type == ENTTEC_DATA_TYPE_RLE) && global_disp_col_count > 0) {
		hi = proto_tree_add_item(tree,
					hf_enttec_dmx_data_data,
					tvb,
					offset,
					length,
					ENC_NA);

		si = proto_item_add_subtree(hi, ett_enttec);
			
		row_count = (ui/global_disp_col_count) + ((ui%global_disp_col_count) == 0 ? 0 : 1);
		dmx_epstr = ep_strbuf_new_label(NULL);
		for (r=0; r < row_count;r++) {
			for (c=0;(c < global_disp_col_count) && (((r*global_disp_col_count)+c) < ui);c++) {
				if ((c % (global_disp_col_count/2)) == 0) {
					ep_strbuf_append_c(dmx_epstr, ' ');
				}
				v = dmx_data[(r*global_disp_col_count)+c];
				if (global_disp_chan_val_type == 0) {
					v = (v * 100) / 255;
					if (v == 100) {
						ep_strbuf_append(dmx_epstr, "FL ");
					} else {
						ep_strbuf_append_printf(dmx_epstr, chan_format[global_disp_chan_val_type], v);
					}
				} else {
					ep_strbuf_append_printf(dmx_epstr, chan_format[global_disp_chan_val_type], v);
				}
			}

			start_offset = dmx_data_offset[(r*global_disp_col_count)];
			end_offset = dmx_data_offset[(r*global_disp_col_count)+c];		

			proto_tree_add_none_format(si,hf_enttec_dmx_data_dmx_data, tvb,
						offset+start_offset, 
						end_offset-start_offset,
						string_format[global_disp_chan_nr_type], (r*global_disp_col_count)+1, dmx_epstr->str);
			ep_strbuf_truncate(dmx_epstr, 0);
		}
		
		item = proto_tree_add_item(si, hf_enttec_dmx_data_data_filter, tvb,
				offset, length, ENC_NA );
		PROTO_ITEM_SET_HIDDEN(item);
		
		offset += length;
	} else if (type == ENTTEC_DATA_TYPE_CHAN_VAL) {
		proto_tree_add_item(tree, hf_enttec_dmx_data_data_filter, tvb,
					offset, length, ENC_NA);
		offset += length;
	} else {
		proto_tree_add_item(tree, hf_enttec_dmx_data_data_filter, tvb,
					offset, length, ENC_NA);
		offset += length;
	}		

	
		
	return offset;
}

static gint
dissect_enttec_config(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{

	return offset;
}

static gint
dissect_enttec_reset(tvbuff_t *tvb _U_, guint offset, proto_tree *tree _U_)
{

	return offset;
}

static void
dissect_enttec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) 
{
	gint offset = 0;
	guint32 head = 0;
	proto_tree *ti,*enttec_tree=NULL;

	/* Set the protocol column */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENTTEC");

	head = tvb_get_ntohl(tvb, offset);

	/* Clear out stuff in the info column */
	if (check_col(pinfo->cinfo,COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
				val_to_str(head, enttec_head_vals, "Unknown (0x%08x)"));
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_enttec, tvb, offset, -1, FALSE);
		enttec_tree = proto_item_add_subtree(ti, ett_enttec);
	}

	if (enttec_tree) {
		proto_tree_add_item(enttec_tree, hf_enttec_head, tvb,
					offset, 4, ENC_BIG_ENDIAN );
		offset += 4;

		switch (head) {
			case ENTTEC_HEAD_ESPR:
				offset = dissect_enttec_poll_reply( tvb, offset, enttec_tree);
				break;

			case ENTTEC_HEAD_ESPP:
				offset = dissect_enttec_poll( tvb, offset, enttec_tree);
				break;

			case ENTTEC_HEAD_ESAP:
				offset = dissect_enttec_ack( tvb, offset, enttec_tree);
				break;

			case ENTTEC_HEAD_ESDD:
				offset = dissect_enttec_dmx_data( tvb, offset, enttec_tree);
				break;

			case ENTTEC_HEAD_ESNC:
				offset = dissect_enttec_config( tvb, offset, enttec_tree);
				break;

			case ENTTEC_HEAD_ESZZ:
				offset = dissect_enttec_reset( tvb, offset, enttec_tree);
				break;
		}

	}
}

void
proto_register_enttec(void) 
{
	static hf_register_info hf[] = {
		/* General */
		{ &hf_enttec_head,
			{ "Head", "enttec.head",
			  FT_UINT32, BASE_HEX, VALS(enttec_head_vals), 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_poll_reply_mac,
			{ "MAC", "enttec.poll_reply.mac",
			  FT_ETHER, BASE_NONE, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_poll_reply_node_type,
			{ "Node Type", "enttec.poll_reply.node_type",
			  FT_UINT16, BASE_HEX, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_poll_reply_version,
			{ "Version", "enttec.poll_reply.version",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_poll_reply_switch,
			{ "Switch settings", "enttec.poll_reply.switch_settings",
			  FT_UINT8, BASE_HEX, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_poll_reply_name,
			{ "Name", "enttec.poll_reply.name",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_poll_reply_option,
			{ "Option Field", "enttec.poll_reply.option_field",
			  FT_UINT8, BASE_HEX, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_poll_reply_tos,
			{ "TOS", "enttec.poll_reply.tos",
			  FT_UINT8, BASE_HEX, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_poll_reply_ttl,
			{ "TTL", "enttec.poll_reply.ttl",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_dmx_data_universe,
			{ "Universe", "enttec.dmx_data.universe",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_dmx_data_start_code,
			{ "Start Code", "enttec.dmx_data.start_code",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_dmx_data_type,
			{ "Data Type", "enttec.dmx_data.type",
			  FT_UINT8, BASE_HEX, VALS(enttec_data_type_vals), 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_dmx_data_size,
			{ "Data Size", "enttec.dmx_data.size",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_dmx_data_data,
			{ "DMX Data", "enttec.dmx_data.data",
			  FT_NONE, BASE_NONE, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_dmx_data_data_filter,
			{ "DMX Data", "enttec.dmx_data.data_filter",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_dmx_data_dmx_data,
			{ "DMX Data", "enttec.dmx_data.dmx_data",
			  FT_NONE, BASE_NONE, NULL, 0x0,
			  NULL, HFILL } },
		{ &hf_enttec_poll_type,
			{ "Reply Type", "enttec.poll.reply_type",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL } }
	};

	static gint *ett[] = {
		&ett_enttec,
	};

	module_t *enttec_module;

	static enum_val_t disp_chan_val_types[] = {
		{ "pro", "Percent", 0 },
		{ "hex", "Hexadecimal", 1 },
		{ "dec", "Decimal", 2 },
		{ NULL, NULL, 0 }
	};

	static enum_val_t disp_chan_nr_types[] = {
		{ "hex", "Hexadecimal", 0 },
		{ "dec", "Decimal", 1 },
		{ NULL, NULL, 0 }
	};

	static enum_val_t col_count[] = {
		{ "6", "6", 6 },
		{ "10", "10", 10 },
		{ "12", "12", 12 },
		{ "16", "16", 16 },
		{ "24", "24", 24 },
		{ NULL, NULL, 0 }
	};

	proto_enttec = proto_register_protocol("ENTTEC", "ENTTEC","enttec");
	proto_register_field_array(proto_enttec,hf,array_length(hf));
	proto_register_subtree_array(ett,array_length(ett));

	enttec_module = prefs_register_protocol(proto_enttec,
						proto_reg_handoff_enttec);
	prefs_register_uint_preference(enttec_module, "udp_port",
					"ENTTEC UDP Port",
					"The UDP port on which ENTTEC packets will be sent",
					10,&global_udp_port_enttec);

	prefs_register_uint_preference(enttec_module, "tcp_port",
					"ENTTEC TCP Port",
					"The TCP port on which ENTTEC packets will be sent",
					10,&global_tcp_port_enttec);

	prefs_register_enum_preference(enttec_module, "dmx_disp_chan_val_type",
				"DMX Display channel value type",
				"The way DMX values are displayed",
				&global_disp_chan_val_type,
				disp_chan_val_types, FALSE);

	prefs_register_enum_preference(enttec_module, "dmx_disp_chan_nr_type",
				"DMX Display channel nr. type",
				"The way DMX channel numbers are displayed",
				&global_disp_chan_nr_type,
				disp_chan_nr_types, FALSE);

	prefs_register_enum_preference(enttec_module, "dmx_disp_col_count",
				"DMX Display Column Count",
				"The number of columns for the DMX display",
				&global_disp_col_count,
				col_count, FALSE);
}

/* The registration hand-off routing */
void
proto_reg_handoff_enttec(void) {
	static gboolean enttec_initialized = FALSE;
	static dissector_handle_t enttec_handle;
	static guint udp_port_enttec;
	static guint tcp_port_enttec;

	if(!enttec_initialized) {
		enttec_handle = create_dissector_handle(dissect_enttec,proto_enttec);
		enttec_initialized = TRUE;
	} else {
		dissector_delete_uint("udp.port",udp_port_enttec,enttec_handle);
		dissector_delete_uint("tcp.port",tcp_port_enttec,enttec_handle);
	}

	udp_port_enttec = global_udp_port_enttec;
	tcp_port_enttec = global_tcp_port_enttec;  

	dissector_add_uint("udp.port",global_udp_port_enttec,enttec_handle);
	dissector_add_uint("tcp.port",global_tcp_port_enttec,enttec_handle);
}
