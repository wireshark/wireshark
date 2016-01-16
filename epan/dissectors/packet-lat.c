/* packet-lat.c
 * Routines for the disassembly of DEC's LAT protocol
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

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "etypes.h"

void proto_register_lat(void);
void proto_reg_handoff_lat(void);

/*
 * Information on LAT taken from the Linux "latd" at
 *
 *	https://sourceforge.net/projects/linux-decnet/
 *
 * See also
 *
 *	http://www.bitsavers.org/pdf/dec/ethernet/lat/AA-NL26A-TE_LAT_Specification_Jun89.pdf
 */

static int proto_lat = -1;
static int hf_lat_rrf = -1;
static int hf_lat_master = -1;
static int hf_lat_cmd = -1;
static int hf_lat_num_slots = -1;
static int hf_lat_remote_connid = -1;
static int hf_lat_local_connid = -1;
static int hf_lat_seq_number = -1;
static int hf_lat_ack_number = -1;
static int hf_lat_slotcmd_local_session = -1;
static int hf_lat_slotcmd_remote_session = -1;
static int hf_lat_slotcmd_length = -1;
static int hf_lat_slotcmd_command = -1;
static int hf_lat_server_circuit_timer = -1;
static int hf_lat_high_prtcl_ver = -1;
static int hf_lat_low_prtcl_ver = -1;
static int hf_lat_cur_prtcl_ver = -1;
static int hf_lat_cur_prtcl_eco = -1;
static int hf_lat_msg_inc = -1;
static int hf_lat_change_flags = -1;
static int hf_lat_data_link_rcv_frame_size = -1;
static int hf_lat_node_multicast_timer = -1;
static int hf_lat_node_status = -1;
static int hf_lat_node_group_len = -1;
static int hf_lat_node_groups = -1;
static int hf_lat_node_name = -1;
static int hf_lat_node_description = -1;
static int hf_lat_service_name_count = -1;
static int hf_lat_service_rating = -1;
static int hf_lat_service_name = -1;
static int hf_lat_service_description = -1;
static int hf_lat_unknown_command_data = -1;

static gint ett_lat = -1;

static dissector_handle_t data_handle;

/* LAT commands. */
#define LAT_CCMD_RUN			0
#define LAT_CCMD_START			1
#define LAT_CCMD_STOP			2
#define LAT_CCMD_SERVICE_ANNOUNCEMENT	10
#define LAT_CCMD_COMMAND		12
#define LAT_CCMD_STATUS			13
#define LAT_CCMD_SOLICIT_INFORMATION	14
#define LAT_CCMD_RESPONSE_INFORMATION	15

static const value_string command_vals[] = {
	{ LAT_CCMD_RUN,                  "Run" },
	{ LAT_CCMD_START,                "Start" },
	{ LAT_CCMD_STOP,                 "Stop" },
	{ LAT_CCMD_SERVICE_ANNOUNCEMENT, "Service announcement" },
	{ LAT_CCMD_COMMAND,              "Command" },
	{ LAT_CCMD_STATUS,               "Status" },
	{ LAT_CCMD_SOLICIT_INFORMATION,  "Solicit information" },
	{ LAT_CCMD_RESPONSE_INFORMATION, "Response information" },
	{ 0,                             NULL },
};

static void dissect_lat_run(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_lat_start(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_lat_stop(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_lat_service_announcement(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_lat_command(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_lat_status(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_lat_solicit_information(tvbuff_t *tvb, int offset, proto_tree *tree);
static void dissect_lat_response_information(tvbuff_t *tvb, int offset, proto_tree *tree);

static int dissect_lat_string(tvbuff_t *tvb, int offset, int hf,
    proto_tree *tree);

static guint dissect_lat_header(tvbuff_t *tvb, int offset, proto_tree *tree);

static void dissect_lat_slots(tvbuff_t *tvb, int offset, guint num_slots,
    proto_tree *tree);

static int
dissect_lat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	int offset = 0;
	proto_item *ti;
	proto_tree *lat_tree = NULL;
	guint8 command;

	col_add_str(pinfo->cinfo, COL_PROTOCOL, "LAT");
	col_clear(pinfo->cinfo, COL_INFO);

	command = tvb_get_guint8(tvb, offset) >> 2;

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
	    val_to_str(command, command_vals, "Unknown command (%u)"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_lat, tvb, offset, -1,
		    ENC_NA);
		lat_tree = proto_item_add_subtree(ti, ett_lat);

		/* First byte of LAT header */
		proto_tree_add_item(lat_tree, hf_lat_rrf, tvb, offset, 1,
		    ENC_LITTLE_ENDIAN);
		proto_tree_add_item(lat_tree, hf_lat_master, tvb, offset, 1,
		    ENC_LITTLE_ENDIAN);
		proto_tree_add_item(lat_tree, hf_lat_cmd, tvb, offset, 1,
		    ENC_LITTLE_ENDIAN);
		offset += 1;

		switch (command) {

		case LAT_CCMD_RUN:
			dissect_lat_run(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_START:
			dissect_lat_start(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_STOP:
			dissect_lat_stop(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_SERVICE_ANNOUNCEMENT:
			dissect_lat_service_announcement(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_COMMAND:
			dissect_lat_command(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_STATUS:
			dissect_lat_status(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_SOLICIT_INFORMATION:
			dissect_lat_solicit_information(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_RESPONSE_INFORMATION:
			dissect_lat_response_information(tvb, offset, lat_tree);
			break;

		default:
			proto_tree_add_item(lat_tree, hf_lat_unknown_command_data,
			    tvb, offset, -1, ENC_NA);
			break;
		}

	}
	return tvb_captured_length(tvb);
}

static void
dissect_lat_run(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint8 num_slots;

	num_slots = dissect_lat_header(tvb, offset, tree);
	offset += 1 + 2 + 2 + 1 + 1;
	dissect_lat_slots(tvb, offset, num_slots, tree);
}

static void
dissect_lat_start(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	dissect_lat_header(tvb, offset, tree);
	/* XXX - dissect the rest of it */
}

static void
dissect_lat_stop(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	dissect_lat_header(tvb, offset, tree);
	/* XXX - dissect the rest of it */
}

static const value_string node_status_vals[] = {
	{ 2, "Accepting connections" },
	{ 3, "Not accepting connections" },
	{ 0, NULL },
};

static void
dissect_lat_service_announcement(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint8 timer;
	guint8 node_group_len;
	guint8 service_name_count;
	int i;

	timer = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format_value(tree, hf_lat_server_circuit_timer, tvb,
	    offset, 1, timer, "%u milliseconds", timer*10);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_high_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_low_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_ver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_cur_prtcl_eco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_msg_inc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_change_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_data_link_rcv_frame_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	timer = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format(tree, hf_lat_node_multicast_timer, tvb,
	    offset, 1, timer, "Multicast timer: %u seconds", timer);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_node_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	node_group_len = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_lat_node_group_len, tvb, offset, 1,
	    node_group_len);
	offset += 1;

	/* This is a bitmask */
	proto_tree_add_item(tree, hf_lat_node_groups, tvb, offset, node_group_len, ENC_NA);
	offset += node_group_len;

	offset = dissect_lat_string(tvb, offset, hf_lat_node_name, tree);

	offset = dissect_lat_string(tvb, offset, hf_lat_node_description, tree);

	service_name_count = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_lat_service_name_count, tvb, offset, 1,
	    service_name_count);
	offset += 1;

	for (i = 0; i < service_name_count; i++) {
		proto_tree_add_item(tree, hf_lat_service_rating, tvb,
		    offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		offset = dissect_lat_string(tvb, offset, hf_lat_service_name,
		    tree);
		offset = dissect_lat_string(tvb, offset, hf_lat_service_description,
		    tree);
	}
	/* XXX - more to dissect here */
}

static void
dissect_lat_command(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* XXX - dissect this */
	proto_tree_add_item(tree, hf_lat_unknown_command_data,
	    tvb, offset, -1, ENC_NA);
}

static void
dissect_lat_status(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* XXX - dissect this */
	proto_tree_add_item(tree, hf_lat_unknown_command_data,
	    tvb, offset, -1, ENC_NA);
}

static void
dissect_lat_solicit_information(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* XXX - dissect this */
	proto_tree_add_item(tree, hf_lat_unknown_command_data,
	    tvb, offset, -1, ENC_NA);
}

static void
dissect_lat_response_information(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	/* XXX - dissect this */
	proto_tree_add_item(tree, hf_lat_unknown_command_data,
	    tvb, offset, -1, ENC_NA);
}

static int
dissect_lat_string(tvbuff_t *tvb, int offset, int hf, proto_tree *tree)
{
	gint item_length;

	proto_tree_add_item_ret_length(tree, hf, tvb, offset, 1, ENC_LITTLE_ENDIAN, &item_length);
	return offset + item_length;
}

static guint
dissect_lat_header(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint8 num_slots;

	num_slots = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_lat_num_slots, tvb, offset, 1,
	    num_slots);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_remote_connid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_local_connid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lat_seq_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_ack_number, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	/*offset += 1;*/

	return num_slots;
}

static void
dissect_lat_slots(tvbuff_t *tvb, int offset, guint num_slots,
    proto_tree *tree)
{
	guint i;

	for (i = 0; i < num_slots; i++) {
		proto_tree_add_item(tree, hf_lat_slotcmd_local_session,
		    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(tree, hf_lat_slotcmd_remote_session,
		    tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(tree, hf_lat_slotcmd_length, tvb,
		    offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(tree, hf_lat_slotcmd_command, tvb,
		    offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
	}
}

void
proto_register_lat(void)
{
	static hf_register_info hf[] = {
	    { &hf_lat_rrf,
		{ "RRF", "lat.rrf", FT_BOOLEAN, 8,
		  NULL, 0x01, NULL, HFILL}},

	    { &hf_lat_master,
		{ "Master", "lat.master", FT_BOOLEAN, 8,
		  NULL, 0x02, NULL, HFILL}},

	    { &hf_lat_cmd,
		{ "Command", "lat.command", FT_UINT8, BASE_DEC,
		  VALS(command_vals), 0xFC, NULL, HFILL}},

	    { &hf_lat_num_slots,
		{ "Number of slots", "lat.num_slots", FT_UINT8, BASE_DEC,
		  NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_remote_connid,
		{ "Remote connection ID", "lat.remote_connid", FT_UINT16,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_local_connid,
		{ "Local connection ID", "lat.local_connid", FT_UINT16,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_seq_number,
		{ "Sequence number", "lat.seq_number", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_ack_number,
		{ "Ack number", "lat.ack_number", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_slotcmd_local_session,
		{ "Local session", "lat.slotcmd.local_session", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_slotcmd_remote_session,
		{ "Remote session", "lat.slotcmd.remote_session", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_slotcmd_length,
		{ "Length", "lat.slotcmd.length", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_slotcmd_command,
		{ "Command", "lat.slotcmd.command", FT_UINT8,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_server_circuit_timer,
		{ "Server circuit timer", "lat.server_circuit_timer", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_high_prtcl_ver,
		{ "Highest protocol version supported", "lat.high_prtcl_ver", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_low_prtcl_ver,
		{ "Lowest protocol version supported", "lat.low_prtcl_ver", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_cur_prtcl_ver,
		{ "Protocol version of this message", "lat.cur_prtcl_ver", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_cur_prtcl_eco,
		{ "ECO level of current protocol version", "lat.cur_prtcl_eco", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_msg_inc,
		{ "Message incarnation", "lat.msg_inc", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_change_flags,
		{ "Change flags", "lat.change_flags", FT_UINT8,
		  BASE_HEX, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_data_link_rcv_frame_size,
		{ "Maximum LAT message size", "lat.data_link_rcv_frame_size", FT_UINT16,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_multicast_timer,
		{ "Node multicast timer", "lat.node_multicast_timer", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_status,
		{ "Node status", "lat.node_status", FT_UINT8,
		  BASE_DEC, VALS(node_status_vals), 0x0, NULL, HFILL}},

	    { &hf_lat_node_group_len,
		{ "Node group length", "lat.node_group_len", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_groups,
		{ "Node groups", "lat.node_groups", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_name,
		{ "Node name", "lat.node_name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_node_description,
		{ "Node description", "lat.node_description", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_service_name_count,
		{ "Number of service names", "lat.service_name_count", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_service_rating,
		{ "Service rating", "lat.service.rating", FT_UINT8,
		  BASE_DEC, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_service_name,
		{ "Service name", "lat.service.name", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_service_description,
		{ "Service description", "lat.service.description", FT_UINT_STRING,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},

	    { &hf_lat_unknown_command_data,
		{ "Unknown command data", "lat.unknown_command_data", FT_BYTES,
		  BASE_NONE, NULL, 0x0, NULL, HFILL}},
	};
	static gint *ett[] = {
		&ett_lat,
	};

	proto_lat = proto_register_protocol("Local Area Transport",
	    "LAT", "lat");
	proto_register_field_array(proto_lat, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_lat(void)
{
	dissector_handle_t lat_handle;

	data_handle = find_dissector("data");
	lat_handle = create_dissector_handle(dissect_lat, proto_lat);
	dissector_add_uint("ethertype", ETHERTYPE_LAT, lat_handle);
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
