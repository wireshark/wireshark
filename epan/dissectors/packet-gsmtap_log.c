/* packet-gsmtap-log.c
 * Routines for GSMTAP logging packets
 *
 * (C) 2016 by Harald Welte <laforge@gnumonks.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-gsmtap.h"

void proto_register_gsmtap_log(void);
void proto_reg_handoff_gsmtap_log(void);

static int proto_gsmtap_log = -1;

static int hf_log_ident = -1;
static int hf_log_subsys = -1;
static int hf_log_file_name = -1;
static int hf_log_file_line = -1;
static int hf_log_ts = -1;
static int hf_log_pid = -1;
static int hf_log_level = -1;
static int hf_log_string = -1;

static int ett_gsmtap_log = -1;

/* from libosmocore include/osmocom/core/logging.h */
static const value_string gsmtap_log_levels[] = {
	{ 1,	"DEBUG" },
	{ 3,	"INFO" },
	{ 5,	"NOTICE" },
	{ 7,	"ERROR" },
	{ 8,	"FATAL" },
	{ 0, NULL }
};

/* dissect a GSMTAP header and hand payload off to respective dissector */
static int
dissect_gsmtap_log(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
	proto_item *ti;
	proto_tree *log_tree;
	gint offset = 0;
	gint log_str_len;
	guint log_pid, log_level, log_src_line;
	const char *log_str;
	const guint8 *log_ident, *log_subsys, *log_src_fname;

	ti = proto_tree_add_item(tree, proto_gsmtap_log, tvb, 0, -1, ENC_NA);
	log_tree = proto_item_add_subtree(ti, ett_gsmtap_log);

	proto_tree_add_item(log_tree, hf_log_ts, tvb, offset, 8, ENC_TIME_SECS_USECS|ENC_BIG_ENDIAN);
	offset += 8;
	proto_tree_add_item_ret_string(log_tree, hf_log_ident, tvb, offset, 16, ENC_NA, wmem_packet_scope(), &log_ident);
	offset += 16;
	proto_tree_add_item_ret_uint(log_tree, hf_log_pid, tvb, offset, 4, ENC_BIG_ENDIAN, &log_pid);
	offset += 4;
	proto_tree_add_item_ret_uint(log_tree, hf_log_level, tvb, offset++, 1, ENC_NA, &log_level);
	offset += 3; /* pad octets */
	proto_tree_add_item_ret_string(log_tree, hf_log_subsys, tvb, offset, 16, ENC_NA, wmem_packet_scope(), &log_subsys);
	offset += 16;
	proto_tree_add_item_ret_string(log_tree, hf_log_file_name, tvb, offset, 32, ENC_NA, wmem_packet_scope(), &log_src_fname);
	offset += 32;
	proto_tree_add_item_ret_uint(log_tree, hf_log_file_line, tvb, offset, 4, ENC_BIG_ENDIAN, &log_src_line);
	offset += 4;

	/* actual log message */
	log_str_len = tvb_captured_length_remaining(tvb, offset);
	proto_tree_add_item(log_tree, hf_log_string, tvb, offset, log_str_len, ENC_ASCII|ENC_NA);

	log_str = tvb_format_stringzpad_wsp(wmem_packet_scope(), tvb, offset, log_str_len);
	col_append_str(pinfo->cinfo, COL_INFO, log_str);

	proto_item_append_text(ti, " %s(%u): %s/%d: %s:%u %s",
			log_ident, log_pid, log_subsys, log_level,
			log_src_fname, log_src_line, log_str);
	return tvb_captured_length(tvb);
}

void
proto_register_gsmtap_log(void)
{
	static hf_register_info hf[] = {
		{ &hf_log_ident, { "Application", "gsmtap_log.ident",
		  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_log_subsys, { "Subsystem", "gsmtap_log.subsys",
		  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_log_file_name, { "Source File Name", "gsmtap_log.src_file.name",
		  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_log_file_line, { "Source File Line Number", "gsmtap_log.src_file.line_nr",
		  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_log_ts, { "Timestamp", "gsmtap_log.timestamp",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL } },
		{ &hf_log_pid, { "Process ID", "gsmtap_log.pid",
		  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_log_level, { "Log Level", "gsmtap_log.level",
		  FT_UINT8, BASE_DEC, VALS(gsmtap_log_levels), 0, NULL, HFILL } },
		{ &hf_log_string, { "String", "gsmtap_log.string",
		  FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
	};

	static gint *ett[] = {
		&ett_gsmtap_log,
	};

	proto_gsmtap_log = proto_register_protocol("GSMTAP libosmocore logging", "GSMTAP-LOG", "gsmtap_log");
	proto_register_field_array(proto_gsmtap_log, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gsmtap_log(void)
{
	dissector_handle_t gsmtap_log_handle;

	gsmtap_log_handle = create_dissector_handle(dissect_gsmtap_log, proto_gsmtap_log);
	dissector_add_uint("gsmtap.type", GSMTAP_TYPE_OSMOCORE_LOG, gsmtap_log_handle);
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
