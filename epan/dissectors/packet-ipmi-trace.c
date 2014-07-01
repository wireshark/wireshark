/* packet-hpm2-trace.c
 * Routines for HPM.2 Trace Data Block disassembly
 * By Dmitry Bazhenov <dima_b@pigeonpoint.com>
 * Copyright 2014 Pigeon Point Systems
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-ipmi.h>
#include <wiretap/wtap.h>

/*
 * See
 *
 * http://www.picmg.org/v2internal/resourcepage2.cfm?id=12
 */

/* Trace data block types. */
enum {
	HPM2_TRACE_PACKET_DATA	= 0,
	HPM2_CHN_STATE_NOTIFY	= 1,
	HPM2_EMBED_ASCII_MSG	= 2
};

/* Data directions. */
enum {
	HPM2_TRACE_DATA_OUT	= 0,	/* From IPM controller */
	HPM2_TRACE_DATA_IN	= 1		/* To IPM controller */
};

/* Redundant channel indicators. */
enum {
	HPM2_TRACE_1ST_CHN		= 0,
	HPM2_TRACE_2ND_CHN		= 1
};

/* IPMB local status values. */
enum {
	HPM2_IPMB_S_OK			= 0,
	HPM2_IPMB_S_ERR_SCL_HI	= 1,
	HPM2_IPMB_S_ERR_SDA_HI	= 2,
	HPM2_IPMB_S_ERR_SCL_LO	= 3,
	HPM2_IPMB_S_ERR_SDA_LO	= 4,
	HPM2_IPMB_S_SCL_TIMEOUT	= 5,
	HPM2_IPMB_S_UNDER_TEST	= 6,
	HPM2_IPMB_S_UNKNOWN_ERR	= 7
};

/* IPMI channel protocol types. */
enum {
	IPMI_PROTO_IPMB_1_0		= 0x01,
	IPMI_PROTO_ICMB_1_0		= 0x02,
	IPMI_PROTO_IPMI_SMBUS	= 0x04,
	IPMI_PROTO_KCS			= 0x05,
	IPMI_PROTO_SMIC			= 0x06,
	IPMI_PROTO_BT_10		= 0x07,
	IPMI_PROTO_BT_15		= 0x08,
	IPMI_PROTO_TMODE		= 0x09,
	IPMI_PROTO_OEM_1		= 0x1C,
	IPMI_PROTO_OEM_2		= 0x1D,
	IPMI_PROTO_OEM_3		= 0x1E,
	IPMI_PROTO_OEM_4		= 0x1F
};

/* IPMB override status values. */
enum {
	HPM2_IPMB_S_ISOLATED	= 0,
	HPM2_IPMB_S_LOCAL_CTRL	= 1
};

void proto_register_ipmi_trace(void);
void proto_reg_handoff_ipmi_trace(void);

static int proto_ipmi_trace = -1;

static dissector_handle_t data_dissector_handle;
static dissector_table_t proto_dissector_table;

static gint ett_ipmi_trace = -1;
static gint ett_trace_block_type = -1;
static gint ett_trace_timestamp = -1;
static gint ett_trace_protocol_data = -1;
static gint ett_trace_ipmb_state = -1;

static gint hf_trace_block_type = -1;
static gint hf_trace_channel_num = -1;
static gint hf_trace_packet_type = -1;
static gint hf_trace_timestamp = -1;
static gint hf_trace_timestamp_sec = -1;
static gint hf_trace_timestamp_msec = -1;
static gint hf_trace_data_type = -1;
static gint hf_trace_protocol_data = -1;
static gint hf_trace_dir = -1;
static gint hf_trace_ipmb_red_chn = -1;
static gint hf_trace_ipmb_link_num = -1;
static gint hf_trace_data_len = -1;
static gint hf_trace_notify_format = -1;
static gint hf_trace_ipmb_state = -1;
static gint hf_trace_ipmb_ovr_state = -1;
static gint hf_trace_ipmb_loc_state = -1;

static const value_string str_packet_types[] = {
	{ 0, "IPMI Trace Packet Data" },
	{ 1, "Channel State Change Notification" },
	{ 2, "Embedded ASCII message" },
	{ 0, NULL }
};

static const value_string str_protocol_types[] = {
	{ 0,	"n/a" },
	{ 1,	"IPMB-1.0" },
	{ 2,	"ICMB-1.0" },
	{ 4,	"IPMI-SMBus" },
	{ 5,	"KCS" },
	{ 6,	"SMIC" },
	{ 7,	"BT-10" },
	{ 8,	"BT-15" },
	{ 9,	"TMode" },
	{ 0x1C, "OEM Protocol 1" },
	{ 0x1D, "OEM Protocol 2" },
	{ 0x1E, "OEM Protocol 3" },
	{ 0x1F, "OEM Protocol 4" },
	{ 0, NULL }
};

static const value_string str_redund_chns[] = {
	{ 0, "First channel" },
	{ 1, "Second channel" },
	{ 0, NULL }
};

static const value_string str_trace_dirs[] = {
	{ 0, "From IPM Controller" },
	{ 1, "To IPM Controller" },
	{ 0, NULL }
};

static const value_string str_ipmb_notify_formats[] = {
	{ 0, "Derived from PICMG 3.0" },
	{ 0, NULL }
};

static const value_string str_ipmb_ovr_statuses[] = {
	{ 0, "Override status, bus isolated" },
	{ 1, "Local Control State" },
	{ 0, NULL }
};

static const value_string str_ipmb_loc_statuses[] = {
	{ 0, "No Failure" },
	{ 1, "Unable to drive clock HI" },
	{ 2, "Unable to drive data HI" },
	{ 3, "Unable to drive clock LO" },
	{ 4, "Unable to drive data LO" },
	{ 5, "Clock low timeout" },
	{ 6, "Under test" },
	{ 7, "Undiagnosed Communications Failure" },
	{ 0, NULL }
};

static const gint * bits_trace_block_type[] = {
	&hf_trace_channel_num,
	&hf_trace_packet_type,
	NULL
};

static const gint * bits_ipmb_protocol_data[] = {
	&hf_trace_ipmb_link_num,
	&hf_trace_ipmb_red_chn,
	&hf_trace_dir,
	NULL
};

static const gint * bits_host_protocol_data[] = {
	&hf_trace_dir,
	NULL
};

static const gint * bits_chn_state_info[] = {
	&hf_trace_ipmb_ovr_state,
	&hf_trace_ipmb_loc_state,
	NULL
};

/* HPM.2 Trace Collection tree indices. */
static gint * const ipmi_trace_ett[] = {
	&ett_ipmi_trace,
	&ett_trace_block_type,
	&ett_trace_timestamp,
	&ett_trace_protocol_data,
	&ett_trace_ipmb_state
};

/* HPM.2 Trace Collection header fields. */
static hf_register_info ipmi_trace_hf[] = {
	{	&hf_trace_block_type, {
			"Trace Data Block Type", "hpm2.trace.block.type",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
	{	&hf_trace_channel_num, {
			"IPMI Channel Number being traced", "hpm2.trace.chn.num",
			FT_UINT8, BASE_DEC_HEX, NULL, 0x0F, NULL, HFILL } },
	{	&hf_trace_packet_type, {
			"Packet Type", "hpm2.trace.packet.type",
			FT_UINT8, BASE_DEC, VALS(str_packet_types), 0x30, NULL, HFILL } },
	{	&hf_trace_timestamp, {
			"Timestamp", "hpm2.trace.stamp",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0, NULL, HFILL } },
	{	&hf_trace_timestamp_sec, {
			"Seconds part", "hpm2.trace.stamp.sec",
			FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
	{	&hf_trace_timestamp_msec, {
			"Milliseconds part", "hpm2.trace.stamp.msec",
			FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
	{	&hf_trace_data_type, {
			"Trace Data Type", "hpm2.trace.data.type",
			FT_UINT8, BASE_HEX, VALS(str_protocol_types), 0, NULL, HFILL } },
	{	&hf_trace_protocol_data, {
			"Additional protocol specific data", "hpm2.trace.proto.data",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
	{	&hf_trace_ipmb_link_num, {
			"Radial IPMB Link Number", "hpm2.trace.ipmb.link.num",
			FT_UINT16, BASE_DEC_HEX, NULL, 0x003F, NULL, HFILL } },
	{	&hf_trace_ipmb_red_chn, {
			"Redundant Channel Indicator", "hpm2.trace.ipmb.red.chn",
			FT_UINT16, BASE_DEC, VALS(str_redund_chns), 0x0040, NULL, HFILL } },
	{	&hf_trace_dir, {
			"Direction", "hpm2.trace.dir",
			FT_UINT16, BASE_DEC, VALS(str_trace_dirs), 0x0080, NULL, HFILL } },
	{	&hf_trace_data_len, {
			"Data length", "hpm2.trace.data.len",
			FT_UINT8, BASE_DEC_HEX, NULL, 0, NULL, HFILL } },
	{	&hf_trace_notify_format, {
			"Data format", "hpm2.trace.data.format",
			FT_UINT8, BASE_HEX, VALS(str_ipmb_notify_formats), 0, NULL, HFILL } },
	{	&hf_trace_ipmb_state, {
			"State Change Information", "hpm2.trace.ipmb.state",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
	{	&hf_trace_ipmb_ovr_state, {
			"IPMB Override status", "hpm2.trace.ipmb.state.ovr",
			FT_UINT8, BASE_DEC, VALS(str_ipmb_ovr_statuses), 0x8, NULL, HFILL } },
	{	&hf_trace_ipmb_loc_state, {
			"IPMB Local status", "hpm2.trace.ipmb.state.loc",
			FT_UINT8, BASE_DEC, VALS(str_ipmb_loc_statuses), 0x7, NULL, HFILL } },
};

static void
dissect_ipmb_state_notify(tvbuff_t * tvb, proto_tree * tree)
{
	/* add data format */
	proto_tree_add_item(tree, hf_trace_notify_format,
			tvb, 0, 1, ENC_LITTLE_ENDIAN);

	/* add host-specific data */
	proto_tree_add_bitmask(tree, tvb, 1,
			hf_trace_ipmb_state, ett_trace_ipmb_state,
			bits_chn_state_info, ENC_LITTLE_ENDIAN);
}

static void
dissect_ipmi_trace(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint block_type, chn_num, data_type, tmp;
	tvbuff_t * next_tvb;

	if (tvb_captured_length(tvb) < 11) {
		/* TODO: add expert info */
		call_dissector(data_dissector_handle, tvb, pinfo, tree);
		return;
	}

	/* get first byte */
	tmp = tvb_get_guint8(tvb, 0);

	/* get block type */
	block_type = (tmp >> 4) & 3;

	/* get channel number */
	chn_num = tmp & 0xF;

	/* get trace data type */
	data_type = tvb_get_guint8(tvb, 7);


	col_add_fstr(pinfo->cinfo, COL_DEF_SRC, "Channel %d", chn_num);
	col_set_str(pinfo->cinfo, COL_PROTOCOL,
			val_to_str(data_type, str_protocol_types,
					"Reserved (0x%02x)"));

	col_clear(pinfo->cinfo, COL_INFO);

	if (block_type == HPM2_TRACE_PACKET_DATA) {
		col_set_str(pinfo->cinfo, COL_INFO, "Trace Packet Data");
	} else if (block_type == HPM2_CHN_STATE_NOTIFY) {
		col_set_str(pinfo->cinfo, COL_INFO,
				"Channel State Change Notification");
	} else if (block_type == HPM2_EMBED_ASCII_MSG) {
		char str[257];

		/* get data length */
		guint str_len = tvb_get_guint8(tvb, 10);

		if (str_len) {
			/* copy string */
			tvb_memcpy(tvb, str, 11, str_len);

			/* pad with nul */
			str[str_len] = 0;

			/* print the string right inside the column */
			col_add_str(pinfo->cinfo, COL_INFO, str);
		}
	} else {
		col_set_str(pinfo->cinfo, COL_INFO, "Reserved");
	}


	if ( tree ) {
		proto_item * ti;
		proto_tree * trace_tree;
		proto_tree * stamp_tree;
		nstime_t timestamp;

		/* add protocol label */
		ti = proto_tree_add_item(tree, proto_ipmi_trace, tvb, 0, -1, ENC_NA);

		/* create protocol sub-tree */
		trace_tree = proto_item_add_subtree(ti, ett_ipmi_trace);

		/* add block type/channel bitmask */
		proto_tree_add_bitmask(trace_tree, tvb, 0, hf_trace_block_type,
				ett_trace_block_type, bits_trace_block_type,
				ENC_LITTLE_ENDIAN);

		/* get seconds part */
		timestamp.secs = tvb_get_letohl(tvb, 1);

		/* get milliseconds part */
		timestamp.nsecs = (int) tvb_get_letohs(tvb, 5) * 1000000;

		/* add timestamp */
		ti = proto_tree_add_time(trace_tree, hf_trace_timestamp, tvb, 1,
				6, &timestamp);

		/* create timestamp sub-tree */
		stamp_tree = proto_item_add_subtree(ti, ett_trace_timestamp);

		/* add seconds part */
		proto_tree_add_item(stamp_tree, hf_trace_timestamp_sec,
				tvb, 1, 4, ENC_LITTLE_ENDIAN);

		/* add milliseconds part */
		proto_tree_add_item(stamp_tree, hf_trace_timestamp_msec,
				tvb, 5, 2, ENC_LITTLE_ENDIAN);

		/* add trace data type */
		proto_tree_add_item(trace_tree, hf_trace_data_type,
				tvb, 7, 1, ENC_LITTLE_ENDIAN);

		if (data_type == IPMI_PROTO_IPMB_1_0) {
			/* add ipmb-specific data */
			proto_tree_add_bitmask(trace_tree, tvb, 8,
					hf_trace_protocol_data, ett_trace_protocol_data,
					bits_ipmb_protocol_data, ENC_LITTLE_ENDIAN);
		} else if (data_type == IPMI_PROTO_KCS
				|| data_type == IPMI_PROTO_SMIC
				|| data_type == IPMI_PROTO_BT_10
				|| data_type == IPMI_PROTO_BT_15) {
			/* add host-specific data */
			proto_tree_add_bitmask(trace_tree, tvb, 8,
					hf_trace_protocol_data, ett_trace_protocol_data,
					bits_host_protocol_data, ENC_LITTLE_ENDIAN);
		} else {
			/* add protocol specific data */
			proto_tree_add_item(trace_tree, hf_trace_protocol_data, tvb,
					8, 2, ENC_LITTLE_ENDIAN);
		}

		/* add data length*/
		proto_tree_add_item(trace_tree, hf_trace_data_len, tvb,
				10, 1, ENC_LITTLE_ENDIAN);
	}

	/* get pointer to remaining data buffer */
	next_tvb = tvb_new_subset_remaining(tvb, 11);

	if (block_type == HPM2_TRACE_PACKET_DATA) {
		ipmi_dissect_arg_t arg;

		/* setup IPMI protocol argument */
		arg.context = IPMI_E_NONE;
		arg.channel = chn_num;
		arg.flags	= tvb_get_guint8(tvb, 8);

		if (!dissector_try_uint_new(proto_dissector_table,
				data_type, next_tvb, pinfo, tree, TRUE, &arg)) {
			call_dissector(data_dissector_handle, next_tvb,
					pinfo, tree);
		}
	} else if (block_type == HPM2_CHN_STATE_NOTIFY
			&& data_type == IPMI_PROTO_IPMB_1_0) {
		dissect_ipmb_state_notify(next_tvb, tree);
	} else {
		call_dissector(data_dissector_handle, next_tvb, pinfo, tree);
	}
}

void
proto_register_ipmi_trace(void)
{
	/* register protocol for HPM.2 trace data block */
	proto_ipmi_trace = proto_register_protocol("IPMI Trace Data Collection",
			"ipmi-trace", "ipmi-trace");

	/* register HPM.2 header fields */
	proto_register_field_array(proto_ipmi_trace, ipmi_trace_hf,
			array_length(ipmi_trace_hf));

	/* register HPM.2 sub-tree indices */
	proto_register_subtree_array(ipmi_trace_ett,
			array_length(ipmi_trace_ett));

	/* register dissector table for IPMI messaging protocols */
	proto_dissector_table = register_dissector_table("ipmi.protocol",
			"IPMI Channel Protocol Type", FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_ipmi_trace(void)
{
	dissector_handle_t ipmi_trace_handle;

	ipmi_trace_handle = create_dissector_handle(dissect_ipmi_trace,
			proto_ipmi_trace);

	data_dissector_handle = find_dissector("data");

	dissector_add_uint("wtap_encap", WTAP_ENCAP_IPMI_TRACE, ipmi_trace_handle);

	dissector_add_uint("ipmi.protocol", IPMI_PROTO_IPMB_1_0,
			find_dissector("ipmb"));
	dissector_add_uint("ipmi.protocol", IPMI_PROTO_KCS,
			find_dissector("kcs"));
	dissector_add_uint("ipmi.protocol", IPMI_PROTO_TMODE,
			find_dissector("tmode"));
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
