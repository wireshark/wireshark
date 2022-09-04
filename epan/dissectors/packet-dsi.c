/* packet-dsi.c
 * Routines for dsi packet dissection
 * Copyright 2001, Randy McEoin <rmceoin@pe.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-tcp.h"
#include "packet-afp.h"

/* The information in this module (DSI) comes from:

  AFP 2.1 & 2.2 documentation, in PDF form, at

http://developer.apple.com/DOCUMENTATION/macos8/pdf/ASAppleTalkFiling2.1_2.2.pdf

  The netatalk source code by Wesley Craig & Adrian Sun

  The Data Stream Interface description from
  http://developer.apple.com/documentation/Networking/Conceptual/AFPClient/AFPClient-6.html

(no longer available, apparently)

  Also, AFP 3.3 documents parts of DSI at:
  http://developer.apple.com/mac/library/documentation/Networking/Conceptual/AFP/Introduction/Introduction.html

 * What a Data Stream Interface packet looks like:
 * 0                               32
 * |-------------------------------|
 * |flags  |command| requestID     |
 * |-------------------------------|
 * |error code/enclosed data offset|
 * |-------------------------------|
 * |total data length              |
 * |-------------------------------|
 * |reserved field                 |
 * |-------------------------------|
 */

void proto_register_dsi(void);
void proto_reg_handoff_dsi(void);

static int proto_dsi = -1;
static int hf_dsi_flags = -1;
static int hf_dsi_command = -1;
static int hf_dsi_requestid = -1;
static int hf_dsi_offset = -1;
static int hf_dsi_error = -1;
static int hf_dsi_length = -1;
static int hf_dsi_reserved = -1;

static gint ett_dsi = -1;

static int hf_dsi_open_type     = -1;
static int hf_dsi_open_len      = -1;
static int hf_dsi_open_quantum  = -1;
static int hf_dsi_replay_cache_size = -1;
static int hf_dsi_open_option   = -1;

static int hf_dsi_attn_flag             = -1;
static int hf_dsi_attn_flag_shutdown    = -1;
static int hf_dsi_attn_flag_crash       = -1;
static int hf_dsi_attn_flag_msg         = -1;
static int hf_dsi_attn_flag_reconnect   = -1;
static int hf_dsi_attn_flag_time        = -1;
static int hf_dsi_attn_flag_bitmap      = -1;

static gint ett_dsi_open        = -1;
static gint ett_dsi_attn        = -1;
static gint ett_dsi_attn_flag   = -1;

static const value_string dsi_attn_flag_vals[] = {
	{0x0, "Reserved" },                                           /* 0000 */
	{0x1, "Reserved" },                                           /* 0001 */
	{0x2, "Server message" },                                     /* 0010 */
	{0x3, "Server notification, cf. extended bitmap" },           /* 0011 */
	{0x4, "Server is shutting down, internal error" },            /* 0100 */
	{0x8, "Server is shutting down" },                            /* 1000 */
	{0x9, "Server disconnects user" },                            /* 1001 */
	{0x10,"Server is shutting down, message" },                   /* 1010 */
	{0x11,"Server is shutting down, message,no reconnect"},       /* 1011 */
	{0,                   NULL } };
static value_string_ext dsi_attn_flag_vals_ext = VALUE_STRING_EXT_INIT(dsi_attn_flag_vals);

static const value_string dsi_open_type_vals[] = {
	{0,   "Server quantum" },
	{1,   "Attention quantum" },
	{2,   "Replay cache size" },
	{0,                   NULL } };

/* desegmentation of DSI */
static gboolean dsi_desegment = TRUE;

static dissector_handle_t afp_handle;
static dissector_handle_t afp_server_status_handle;

#define TCP_PORT_DSI      548 /* Not IANA registered */

#define DSI_BLOCKSIZ       16

/* DSI flags */
#define DSIFL_REQUEST    0x00
#define DSIFL_REPLY      0x01
#define DSIFL_MAX        0x01

/* DSI Commands */
#define DSIFUNC_CLOSE   1       /* DSICloseSession */
#define DSIFUNC_CMD     2       /* DSICommand */
#define DSIFUNC_STAT    3       /* DSIGetStatus */
#define DSIFUNC_OPEN    4       /* DSIOpenSession */
#define DSIFUNC_TICKLE  5       /* DSITickle */
#define DSIFUNC_WRITE   6       /* DSIWrite */
#define DSIFUNC_ATTN    8       /* DSIAttention */
#define DSIFUNC_MAX     8       /* largest command */

static const value_string flag_vals[] = {
	{DSIFL_REQUEST,       "Request" },
	{DSIFL_REPLY,         "Reply" },
	{0,                   NULL } };

static const value_string func_vals[] = {
	{DSIFUNC_CLOSE,       "CloseSession" },
	{DSIFUNC_CMD,         "Command" },
	{DSIFUNC_STAT,        "GetStatus" },
	{DSIFUNC_OPEN,        "OpenSession" },
	{DSIFUNC_TICKLE,      "Tickle" },
	{DSIFUNC_WRITE,       "Write" },
	{ 7,                  "Unknown" },
	{DSIFUNC_ATTN,        "Attention" },
	{0,                   NULL } };
static value_string_ext func_vals_ext = VALUE_STRING_EXT_INIT(func_vals);

static gint
dissect_dsi_open_session(tvbuff_t *tvb, proto_tree *dsi_tree, gint offset, gint dsi_length)
{
	proto_tree      *tree;
	guint8		type;
	guint8		len;

	tree = proto_tree_add_subtree(dsi_tree, tvb, offset, -1, ett_dsi_open, NULL, "Open Session");

	while( dsi_length >2 ) {

		type = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_dsi_open_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		len = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_dsi_open_len, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;
		switch (type) {
			case 0:
				proto_tree_add_item(tree, hf_dsi_open_quantum, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;
			case 1:
				proto_tree_add_item(tree, hf_dsi_open_quantum, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;
			case 2:
				proto_tree_add_item(tree, hf_dsi_replay_cache_size, tvb, offset, 4, ENC_BIG_ENDIAN);
				break;
			default:
				proto_tree_add_item(tree, hf_dsi_open_option, tvb, offset, len, ENC_NA);
		}

		dsi_length -= len + 2;

		offset += len;
	}
	return offset;
}

static gint
dissect_dsi_attention(tvbuff_t *tvb, proto_tree *dsi_tree, gint offset)
{
	proto_tree      *tree;
	proto_item	*ti;
	guint16		flag;

	if (!tvb_reported_length_remaining(tvb,offset))
		return offset;

	flag = tvb_get_ntohs(tvb, offset);
	tree = proto_tree_add_subtree(dsi_tree, tvb, offset, -1, ett_dsi_attn, NULL, "Attention");

	ti = proto_tree_add_item(tree, hf_dsi_attn_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
	tree = proto_item_add_subtree(ti, ett_dsi_attn_flag);
	proto_tree_add_item(tree, hf_dsi_attn_flag_shutdown, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsi_attn_flag_crash, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsi_attn_flag_msg, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_dsi_attn_flag_reconnect, tvb, offset, 2, ENC_BIG_ENDIAN);
	/* FIXME */
	if ((flag & 0xf000) != 0x3000)
		proto_tree_add_item(tree, hf_dsi_attn_flag_time, tvb, offset, 2, ENC_BIG_ENDIAN);
	else
		proto_tree_add_item(tree, hf_dsi_attn_flag_bitmap, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	return offset;
}

static int
dissect_dsi_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_tree      *dsi_tree;
	proto_item	*dsi_ti;
	guint8		dsi_flags,dsi_command;
	guint16		dsi_requestid;
	gint32		dsi_code;
	guint32		dsi_length;
	struct		atp_asp_dsi_info atp_asp_dsi_info;


	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSI");
	col_clear(pinfo->cinfo, COL_INFO);

	dsi_flags = tvb_get_guint8(tvb, 0);
	dsi_command = tvb_get_guint8(tvb, 1);
	dsi_requestid = tvb_get_ntohs(tvb, 2);
	dsi_code = tvb_get_ntohl(tvb, 4);
	dsi_length = tvb_get_ntohl(tvb, 8);

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s (%u)",
			val_to_str(dsi_flags, flag_vals,
				   "Unknown flag (0x%02x)"),
			val_to_str_ext(dsi_command, &func_vals_ext,
				   "Unknown function (0x%02x)"),
			dsi_requestid);

	dsi_ti = proto_tree_add_item(tree, proto_dsi, tvb, 0, -1, ENC_NA);
	dsi_tree = proto_item_add_subtree(dsi_ti, ett_dsi);

	if (tree) {
		proto_tree_add_uint(dsi_tree, hf_dsi_flags, tvb,
			0, 1, dsi_flags);
		proto_tree_add_uint(dsi_tree, hf_dsi_command, tvb,
			1, 1, dsi_command);
		proto_tree_add_uint(dsi_tree, hf_dsi_requestid, tvb,
			2, 2, dsi_requestid);
		switch (dsi_flags) {

		case DSIFL_REQUEST:
			proto_tree_add_int(dsi_tree, hf_dsi_offset, tvb,
				4, 4, dsi_code);
			break;

		case DSIFL_REPLY:
			proto_tree_add_int(dsi_tree, hf_dsi_error, tvb,
				4, 4, dsi_code);
			break;
		}
		proto_tree_add_item(dsi_tree, hf_dsi_length, tvb,
			8, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(dsi_tree, hf_dsi_reserved, tvb,
			12, 4, ENC_BIG_ENDIAN);
	}

	switch (dsi_command) {
	case DSIFUNC_OPEN:
		if (tree) {
			dissect_dsi_open_session(tvb, dsi_tree, DSI_BLOCKSIZ, dsi_length);
		}
		break;
	case DSIFUNC_ATTN:
		if (tree) {
			dissect_dsi_attention(tvb, dsi_tree, DSI_BLOCKSIZ);
		}
		break;
	case DSIFUNC_STAT:
		if (tree && (dsi_flags == DSIFL_REPLY)) {
			tvbuff_t   *new_tvb;

			/* XXX - assumes only AFP runs atop DSI */
			new_tvb = tvb_new_subset_remaining(tvb, DSI_BLOCKSIZ);
			call_dissector(afp_server_status_handle, new_tvb, pinfo, dsi_tree);
		}
		break;
	case DSIFUNC_CMD:
	case DSIFUNC_WRITE:
		{
			tvbuff_t   *new_tvb;

			atp_asp_dsi_info.reply = (dsi_flags == DSIFL_REPLY);
			atp_asp_dsi_info.command = dsi_command;
			atp_asp_dsi_info.tid = dsi_requestid;
			atp_asp_dsi_info.code = dsi_code;
			proto_item_set_len(dsi_ti, DSI_BLOCKSIZ);

			new_tvb = tvb_new_subset_remaining(tvb, DSI_BLOCKSIZ);
			call_dissector_with_data(afp_handle, new_tvb, pinfo, tree, &atp_asp_dsi_info);
		}
		break;
	default:
		call_data_dissector(tvb_new_subset_remaining(tvb, DSI_BLOCKSIZ),
						pinfo, dsi_tree);
		break;
	}

	return tvb_captured_length(tvb);
}

static guint
get_dsi_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
	guint32 plen;
	guint8	dsi_flags,dsi_command;

	dsi_flags = tvb_get_guint8(tvb, offset);
	dsi_command = tvb_get_guint8(tvb, offset+ 1);
	if ( dsi_flags > DSIFL_MAX || !dsi_command || dsi_command > DSIFUNC_MAX)
	{
	    /* it's not a known dsi pdu start sequence */
	    return tvb_captured_length_remaining(tvb, offset);
	}

	/*
	 * Get the length of the DSI packet.
	 */
	plen = tvb_get_ntohl(tvb, offset+8);

	/*
	 * That length doesn't include the length of the header itself;
	 * add that in.
	 */
	return plen + 16;
}

static int
dissect_dsi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, dsi_desegment, 12,
	    get_dsi_pdu_len, dissect_dsi_packet, data);

	return tvb_captured_length(tvb);
}

void
proto_register_dsi(void)
{

	static hf_register_info hf[] = {
		{ &hf_dsi_flags,
		  { "Flags",            "dsi.flags",
		    FT_UINT8, BASE_HEX, VALS(flag_vals), 0x0,
		    "Indicates request or reply.", HFILL }},

		{ &hf_dsi_command,
		  { "Command",          "dsi.command",
		    FT_UINT8, BASE_DEC|BASE_EXT_STRING, &func_vals_ext, 0x0,
		    "Represents a DSI command.", HFILL }},

		{ &hf_dsi_requestid,
		  { "Request ID",       "dsi.requestid",
		    FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Keeps track of which request this is.  Replies must match a Request.  IDs must be generated in sequential order.", HFILL }},

		{ &hf_dsi_offset,
		  { "Data offset",      "dsi.data_offset",
		    FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_dsi_error,
		  { "Error code",       "dsi.error_code",
		    FT_INT32, BASE_DEC|BASE_EXT_STRING, &asp_error_vals_ext, 0x0,
		    NULL, HFILL }},

		{ &hf_dsi_length,
		  { "Length",           "dsi.length",
		    FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
		    "Total length of the data that follows the DSI header.", HFILL }},

		{ &hf_dsi_reserved,
		  { "Reserved",         "dsi.reserved",
		    FT_UINT32, BASE_HEX, NULL, 0x0,
		    "Reserved for future use.  Should be set to zero.", HFILL }},

		{ &hf_dsi_open_type,
		  { "Option",          "dsi.open_type",
		    FT_UINT8, BASE_DEC, VALS(dsi_open_type_vals), 0x0,
		    "Open session option type.", HFILL }},

		{ &hf_dsi_open_len,
		  { "Length",          "dsi.open_len",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Open session option len", HFILL }},

		{ &hf_dsi_open_quantum,
		  { "Quantum",       "dsi.open_quantum",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Server/Attention quantum", HFILL }},

		{ &hf_dsi_replay_cache_size,
		  { "Replay",       "dsi.replay_cache",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Replay cache size", HFILL }},

		{ &hf_dsi_open_option,
		  { "Option",          "dsi.open_option",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Open session options (undecoded)", HFILL }},

		{ &hf_dsi_attn_flag,
		  { "Flags",          "dsi.attn_flag",
		    FT_UINT16, BASE_HEX|BASE_EXT_STRING, &dsi_attn_flag_vals_ext, 0xf000,
		    "Server attention flag", HFILL }},
		{ &hf_dsi_attn_flag_shutdown,
		  { "Shutdown",      "dsi.attn_flag.shutdown",
		    FT_BOOLEAN, 16, NULL, 1<<15,
		    "Attention flag, server is shutting down", HFILL }},
		{ &hf_dsi_attn_flag_crash,
		  { "Crash",      "dsi.attn_flag.crash",
		    FT_BOOLEAN, 16, NULL, 1<<14,
		    "Attention flag, server crash bit", HFILL }},
		{ &hf_dsi_attn_flag_msg,
		  { "Message",      "dsi.attn_flag.msg",
		    FT_BOOLEAN, 16, NULL, 1<<13,
		    "Attention flag, server message bit", HFILL }},
		{ &hf_dsi_attn_flag_reconnect,
		  { "Don't reconnect",      "dsi.attn_flag.reconnect",
		    FT_BOOLEAN, 16, NULL, 1<<12,
		    "Attention flag, don't reconnect bit", HFILL }},
		{ &hf_dsi_attn_flag_time,
		  { "Minutes",          "dsi.attn_flag.time",
		    FT_UINT16, BASE_DEC, NULL, 0xfff,
		    "Number of minutes", HFILL }},
		{ &hf_dsi_attn_flag_bitmap,
		  { "Bitmap",          "dsi.attn_flag.bitmap",
		    FT_UINT16, BASE_HEX, NULL, 0xfff,
		    "Attention extended bitmap", HFILL }},
	};

	static gint *ett[] = {
		&ett_dsi,
		&ett_dsi_open,
		&ett_dsi_attn,
		&ett_dsi_attn_flag
	};
	module_t *dsi_module;

	proto_dsi = proto_register_protocol("Data Stream Interface", "DSI", "dsi");
	proto_register_field_array(proto_dsi, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	dsi_module = prefs_register_protocol(proto_dsi, NULL);
	prefs_register_bool_preference(dsi_module, "desegment",
				       "Reassemble DSI messages spanning multiple TCP segments",
				       "Whether the DSI dissector should reassemble messages spanning multiple TCP segments."
				       " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				       &dsi_desegment);
}

void
proto_reg_handoff_dsi(void)
{
	dissector_handle_t dsi_handle;

	dsi_handle = create_dissector_handle(dissect_dsi, proto_dsi);
	dissector_add_uint_with_preference("tcp.port", TCP_PORT_DSI, dsi_handle);

	afp_handle = find_dissector_add_dependency("afp", proto_dsi);
	afp_server_status_handle = find_dissector_add_dependency("afp_server_status", proto_dsi);
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
