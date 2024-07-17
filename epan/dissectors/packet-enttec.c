/* packet-enttec.c
 * Routines for ENTTEC packet disassembly
 *
 * Copyright (c) 2003,2004 by Erwin Rol <erwin@erwinrol.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Include files */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
/*
 * See
 *
 *	http://www.enttec.com/docs/enttec_protocol.pdf
 */

/* Define UDP/TCP ports for ENTTEC */

#define UDP_PORT_ENTTEC 0x0D05 /* Not IANA registered */
#define TCP_PORT_ENTTEC 0x0D05 /* Not IANA registered */


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

void proto_register_enttec(void);
void proto_reg_handoff_enttec(void);

static dissector_handle_t enttec_udp_handle, enttec_tcp_handle;

/* Define the enttec proto */
static int proto_enttec;

/* general */
static int hf_enttec_head;

/* poll */
static int hf_enttec_poll_type;

/* poll reply */
static int hf_enttec_poll_reply_mac;
static int hf_enttec_poll_reply_node_type;
static int hf_enttec_poll_reply_version;
static int hf_enttec_poll_reply_switch;
static int hf_enttec_poll_reply_name;
static int hf_enttec_poll_reply_option;
static int hf_enttec_poll_reply_tos;
static int hf_enttec_poll_reply_ttl;

/* dmx data */
static int hf_enttec_dmx_data_universe;
static int hf_enttec_dmx_data_start_code;
static int hf_enttec_dmx_data_type;
static int hf_enttec_dmx_data_size;
static int hf_enttec_dmx_data_data;
static int hf_enttec_dmx_data_data_filter;
static int hf_enttec_dmx_data_dmx_data;

/* Define the tree for enttec */
static int ett_enttec;

/*
 * Here are the global variables associated with the preferences
 * for enttec
 */

static int global_disp_chan_val_type;
static int global_disp_col_count = 16;
static int global_disp_chan_nr_type;

static int
dissect_enttec_poll_reply(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_enttec_poll_reply_mac, tvb,
					offset, 6, ENC_NA);
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
					offset, 10, ENC_ASCII);
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

static int
dissect_enttec_poll(tvbuff_t *tvb, unsigned offset, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_enttec_poll_type, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	return offset;
}

static int
dissect_enttec_ack(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{

	return offset;
}

static int
dissect_enttec_dmx_data(tvbuff_t *tvb, packet_info *pinfo, unsigned offset, proto_tree *tree)
{
	static const char* chan_format[] = {
		"%2u ",
		"%02x ",
		"%3u "
	};
	static const char* string_format[] = {
		"%03x: %s",
		"%3u: %s"
	};

	uint8_t *dmx_data = (uint8_t *)wmem_alloc(pinfo->pool, 512 * sizeof(uint8_t));
	uint16_t *dmx_data_offset = (uint16_t *)wmem_alloc(pinfo->pool, 513 * sizeof(uint16_t)); /* 1 extra for last offset */
	wmem_strbuf_t *dmx_epstr;

	proto_tree *hi,*si;
	proto_item *item;
	uint16_t length,r,c,row_count;
	uint8_t v,type,count;
	uint16_t ci,ui,i,start_offset,end_offset;

	proto_tree_add_item(tree, hf_enttec_dmx_data_universe, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_enttec_dmx_data_start_code, tvb,
					offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	type = tvb_get_uint8(tvb, offset);
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
			v = tvb_get_uint8(tvb, offset+ci);
			if (v == 0xFE) {
				ci++;
				count = tvb_get_uint8(tvb, offset+ci);
				ci++;
				v = tvb_get_uint8(tvb, offset+ci);
				ci++;
				for (i=0;i < count && ui < 512;i++) {
					dmx_data[ui] = v;
					dmx_data_offset[ui] = ci-3;
					ui++;
				}
			} else if (v == 0xFD) {
				ci++;
				v = tvb_get_uint8(tvb, offset+ci);
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
			dmx_data[ui] =  tvb_get_uint8(tvb, offset+ui);
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
		dmx_epstr = wmem_strbuf_create(pinfo->pool);
		for (r=0; r < row_count;r++) {
			for (c=0;(c < global_disp_col_count) && (((r*global_disp_col_count)+c) < ui);c++) {
				if ((global_disp_col_count > 1) && (c % (global_disp_col_count/2)) == 0) {
					wmem_strbuf_append_c(dmx_epstr, ' ');
				}
				v = dmx_data[(r*global_disp_col_count)+c];
				if (global_disp_chan_val_type == 0) {
					v = (v * 100) / 255;
					if (v == 100) {
						wmem_strbuf_append(dmx_epstr, "FL ");
					} else {
						wmem_strbuf_append_printf(dmx_epstr, chan_format[global_disp_chan_val_type], v);
					}
				} else {
					wmem_strbuf_append_printf(dmx_epstr, chan_format[global_disp_chan_val_type], v);
				}
			}

			start_offset = dmx_data_offset[(r*global_disp_col_count)];
			end_offset = dmx_data_offset[(r*global_disp_col_count)+c];

			proto_tree_add_none_format(si,hf_enttec_dmx_data_dmx_data, tvb,
						offset+start_offset,
						end_offset-start_offset,
						string_format[global_disp_chan_nr_type], (r*global_disp_col_count)+1,
						wmem_strbuf_get_str(dmx_epstr));
			wmem_strbuf_truncate(dmx_epstr, 0);
		}

		item = proto_tree_add_item(si, hf_enttec_dmx_data_data_filter, tvb,
				offset, length, ENC_NA );
		proto_item_set_hidden(item);

		offset += length;
	}
	else {
		proto_tree_add_item(tree, hf_enttec_dmx_data_data_filter, tvb,
					offset, length, ENC_NA);
		offset += length;
	}



	return offset;
}

static int
dissect_enttec_reset(tvbuff_t *tvb _U_, unsigned offset, proto_tree *tree _U_)
{

	return offset;
}

static int
dissect_enttec_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int offset = 0;
	uint32_t head = 0;
	proto_tree *ti, *enttec_tree;

	/*
	 * If not enough bytes for the header word, not an ENTTEC packet.
	 */
	if (!tvb_bytes_exist(tvb, offset, 4))
		return 0;

	head = tvb_get_ntohl(tvb, offset);
	switch (head) {

	case ENTTEC_HEAD_ESPR:
	case ENTTEC_HEAD_ESPP:
	case ENTTEC_HEAD_ESAP:
	case ENTTEC_HEAD_ESDD:
	case ENTTEC_HEAD_ESZZ:
		/*
		 * Valid packet type.
		 */
		break;

	default:
		/*
		 * Not a known DMX-over-UDP packet type, so probably not ENTTEC.
		 */
		return 0;
	}

	/* Set the protocol column */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENTTEC");

	/* Clear out stuff in the info column */
	col_add_str(pinfo->cinfo, COL_INFO,
				val_to_str(head, enttec_head_vals, "Unknown (0x%08x)"));

	ti = proto_tree_add_item(tree, proto_enttec, tvb, offset, -1, ENC_NA);
	enttec_tree = proto_item_add_subtree(ti, ett_enttec);

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
			offset = dissect_enttec_dmx_data( tvb, pinfo, offset, enttec_tree);
			break;

		case ENTTEC_HEAD_ESZZ:
			offset = dissect_enttec_reset( tvb, offset, enttec_tree);
			break;
	}

	return offset;
}

static int
dissect_enttec_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int offset = 0;
	uint32_t head = 0;
	proto_tree *ti,*enttec_tree;

	/*
	 * If not enough bytes for the header word, don't try to
	 * reassemble to get 4 bytes of header word, as we don't
	 * know whether this will be an ENTTEC Config packet.
	 */
	if (!tvb_bytes_exist(tvb, offset, 4))
		return 0;

	head = tvb_get_ntohl(tvb, offset);
	if (head != ENTTEC_HEAD_ESNC) {
		/*
		 * Not a config packet, so probably not ENTTEC.
		 */
		return 0;
	}

	/* XXX - reassemble to end of connection? */

	/* Set the protocol column */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ENTTEC");

	/* Clear out stuff in the info column */
	col_add_str(pinfo->cinfo, COL_INFO,
				val_to_str(head, enttec_head_vals, "Unknown (0x%08x)"));

	ti = proto_tree_add_item(tree, proto_enttec, tvb, offset, -1, ENC_NA);
	enttec_tree = proto_item_add_subtree(ti, ett_enttec);

	proto_tree_add_item(enttec_tree, hf_enttec_head, tvb,
			offset, 4, ENC_BIG_ENDIAN );
	/* XXX - dissect the rest of the packet */

	return tvb_captured_length(tvb);
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

	static int *ett[] = {
		&ett_enttec,
	};

	module_t *enttec_module;

	static const enum_val_t disp_chan_val_types[] = {
		{ "pro", "Percent", 0 },
		{ "hex", "Hexadecimal", 1 },
		{ "dec", "Decimal", 2 },
		{ NULL, NULL, 0 }
	};

	static const enum_val_t disp_chan_nr_types[] = {
		{ "hex", "Hexadecimal", 0 },
		{ "dec", "Decimal", 1 },
		{ NULL, NULL, 0 }
	};

	static const enum_val_t col_count[] = {
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

	enttec_udp_handle = register_dissector("enttec.udp", dissect_enttec_udp,proto_enttec);
	enttec_tcp_handle = register_dissector("enttec.tcp", dissect_enttec_tcp,proto_enttec);

	enttec_module = prefs_register_protocol(proto_enttec, NULL);

	prefs_register_enum_preference(enttec_module, "dmx_disp_chan_val_type",
				"DMX Display channel value type",
				"The way DMX values are displayed",
				&global_disp_chan_val_type,
				disp_chan_val_types, false);

	prefs_register_enum_preference(enttec_module, "dmx_disp_chan_nr_type",
				"DMX Display channel nr. type",
				"The way DMX channel numbers are displayed",
				&global_disp_chan_nr_type,
				disp_chan_nr_types, false);

	prefs_register_enum_preference(enttec_module, "dmx_disp_col_count",
				"DMX Display Column Count",
				"The number of columns for the DMX display",
				&global_disp_col_count,
				col_count, false);
}

/* The registration hand-off routing */
void
proto_reg_handoff_enttec(void) {
	dissector_add_uint_with_preference("tcp.port",TCP_PORT_ENTTEC,enttec_tcp_handle);
	dissector_add_uint_with_preference("udp.port",UDP_PORT_ENTTEC,enttec_udp_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
