/* packet-lat.c
 * Routines for the disassembly of DEC's LAT protocol
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
 
#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include "etypes.h"

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
static int hf_lat_circuit_timer = -1;
static int hf_lat_hiver = -1;
static int hf_lat_lover = -1;
static int hf_lat_latver = -1;
static int hf_lat_latver_minor = -1;
static int hf_lat_incarnation = -1;
static int hf_lat_change_flags = -1;
static int hf_lat_mtu = -1;
static int hf_lat_multicast_timer = -1;
static int hf_lat_node_status = -1;
static int hf_lat_group_length = -1;
static int hf_lat_groups = -1;
static int hf_lat_nodename = -1;
static int hf_lat_greeting = -1;
static int hf_lat_num_services = -1;
static int hf_lat_service_rating = -1;
static int hf_lat_service_name = -1;
static int hf_lat_service_ident = -1;
static int hf_lat_unknown_command_data = -1;

static gint ett_lat = -1;

static dissector_handle_t data_handle;

/* LAT commands. */
#define LAT_CCMD_SREPLY		0x00 /* From Host */
#define LAT_CCMD_SDATA		0x01 /* From Host: Response required */
#define LAT_CCMD_SESSION	0x02 /* To Host */
#define LAT_CCMD_CONNECT	0x06
#define LAT_CCMD_CONREF		0x08 /* Connection Refused (I think) */
#define LAT_CCMD_CONACK		0x04
#define LAT_CCMD_DISCON		0x0A
#define LAT_CCMD_SERVICE	0x28
#define LAT_CCMD_ENQUIRE	0x38
#define LAT_CCMD_ENQREPLY	0x3C

static const value_string command_vals[] = {
	{ LAT_CCMD_SREPLY,   "Session reply" },
	{ LAT_CCMD_SDATA,    "Session data" },
	{ LAT_CCMD_SESSION,  "Session" },
	{ LAT_CCMD_CONNECT,  "Connect" },
	{ LAT_CCMD_CONREF,   "Connection refused" },
	{ LAT_CCMD_CONACK,   "Connection ACK" },
	{ LAT_CCMD_DISCON,   "Disconnect" },
	{ LAT_CCMD_SERVICE,  "Service" },
	{ LAT_CCMD_ENQUIRE,  "Enquire" },
	{ LAT_CCMD_ENQREPLY, "Enquire reply" },
	{ 0,                 NULL },
};

static void dissect_lat_sreply(tvbuff_t *tvb, int offset, proto_tree *tree);

static void dissect_lat_service(tvbuff_t *tvb, int offset, proto_tree *tree);

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

	command = tvb_get_guint8(tvb, offset);

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
	    val_to_str(command, command_vals, "Unknown command (%02x)"));

	if (tree) {
		ti = proto_tree_add_item(tree, proto_lat, tvb, offset, -1,
		    ENC_NA);
		lat_tree = proto_item_add_subtree(ti, ett_lat);

		/* LAT header */
		proto_tree_add_uint(lat_tree, hf_lat_cmd, tvb, offset, 1,
		    command);
		offset += 1;

		switch (command) {

		case LAT_CCMD_SREPLY:
			dissect_lat_sreply(tvb, offset, lat_tree);
			break;

#if 0
		case LAT_CCMD_SDATA:
			dissect_lat_header(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_SESSION:
			dissect_lat_header(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_CONNECT:
			dissect_lat_connect(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_CONREF:
			dissect_lat_conref(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_CONACK:
			dissect_lat_conack(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_DISCON:
			dissect_lat_discon(tvb, offset, lat_tree);
			break;
#endif

		case LAT_CCMD_SERVICE:
			dissect_lat_service(tvb, offset, lat_tree);
			break;

#if 0
		case LAT_CCMD_ENQUIRE:
			dissect_lat_enquire(tvb, offset, lat_tree);
			break;

		case LAT_CCMD_ENQREPLY:
			dissect_lat_enqreply(tvb, offset, lat_tree);
			break;
#endif

		default:
			proto_tree_add_item(lat_tree, hf_lat_unknown_command_data,
			    tvb, offset, -1, ENC_NA);
			break;
		}

	}
	return tvb_captured_length(tvb);
}

static void
dissect_lat_sreply(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint8 num_slots;

	num_slots = dissect_lat_header(tvb, offset, tree);
	offset += 1 + 2 + 2 + 1 + 1;
	dissect_lat_slots(tvb, offset, num_slots, tree);
}

static const value_string node_status_vals[] = {
	{ 2, "Accepting connections" },
	{ 3, "Not accepting connections" },
	{ 0, NULL },
};

static void
dissect_lat_service(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	guint8 timer;
	guint8 group_length;
	guint8 num_services;
	int i;

	timer = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format(tree, hf_lat_circuit_timer, tvb,
	    offset, 1, timer, "Circuit timer: %u milliseconds", timer*10);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_hiver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_lover, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_latver, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_latver_minor, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_incarnation, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_change_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	timer = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint_format(tree, hf_lat_multicast_timer, tvb,
	    offset, 1, timer, "Multicast timer: %u seconds", timer);
	offset += 1;

	proto_tree_add_item(tree, hf_lat_node_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	group_length = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_lat_group_length, tvb, offset, 1,
	    group_length);
	offset += 1;

	/* XXX - what are these? */
	proto_tree_add_item(tree, hf_lat_groups, tvb, offset, group_length, ENC_NA);
	offset += group_length;

	offset = dissect_lat_string(tvb, offset, hf_lat_nodename, tree);

	offset = dissect_lat_string(tvb, offset, hf_lat_greeting, tree);

	num_services = tvb_get_guint8(tvb, offset);
	proto_tree_add_uint(tree, hf_lat_num_services, tvb, offset, 1,
	    num_services);
	offset += 1;

	for (i = 0; i < num_services; i++) {
		proto_tree_add_item(tree, hf_lat_service_rating, tvb,
		    offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
		offset = dissect_lat_string(tvb, offset, hf_lat_service_name,
		    tree);
		offset = dissect_lat_string(tvb, offset, hf_lat_service_ident,
		    tree);
	}
}

static int
dissect_lat_string(tvbuff_t *tvb, int offset, int hf, proto_tree *tree)
{
	proto_item *ti;

	ti = proto_tree_add_item(tree, hf, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	return offset + proto_item_get_len(ti);
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
	offset += 1;

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
	    { &hf_lat_cmd,
		{ "Command", "lat.command", FT_UINT8, BASE_HEX,
		  VALS(command_vals), 0x0,
		  NULL, HFILL}},

	    { &hf_lat_num_slots,
		{ "Number of slots", "lat.num_slots", FT_UINT8, BASE_DEC,
		  NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_remote_connid,
		{ "Remote connection ID", "lat.remote_connid", FT_UINT16,
		  BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_local_connid,
		{ "Local connection ID", "lat.local_connid", FT_UINT16,
		  BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_seq_number,
		{ "Sequence number", "lat.seq_number", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_ack_number,
		{ "Ack number", "lat.ack_number", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_slotcmd_local_session,
		{ "Local session", "lat.slotcmd.local_session", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_slotcmd_remote_session,
		{ "Remote session", "lat.slotcmd.remote_session", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_slotcmd_length,
		{ "Length", "lat.slotcmd.length", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_slotcmd_command,
		{ "Command", "lat.slotcmd.command", FT_UINT8,
		  BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_circuit_timer,
		{ "Circuit timer", "lat.circuit_timer", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_hiver,
		{ "Highest protocol version acceptable", "lat.hiver", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_lover,
		{ "Lowest protocol version acceptable", "lat.lover", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_latver,
		{ "LAT version number", "lat.latver", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_latver_minor,
		{ "LAT minor version number (?)", "lat.latver_minor", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_incarnation,
		{ "Message incarnation (?)", "lat.incarnation", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_change_flags,
		{ "Change flags (?)", "lat.change_flags", FT_UINT8,
		  BASE_HEX, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_mtu,
		{ "MTU", "lat.mtu", FT_UINT16,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_multicast_timer,
		{ "Multicast timer", "lat.multicast_timer", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_node_status,
		{ "Node status", "lat.node_status", FT_UINT8,
		  BASE_DEC, VALS(node_status_vals), 0x0,
		  NULL, HFILL}},

	    { &hf_lat_group_length,
		{ "Group length", "lat.group_length", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_groups,
		{ "Groups", "lat.groups", FT_BYTES,
		  BASE_NONE, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_nodename,
		{ "Node name", "lat.nodename", FT_UINT_STRING,
		  0, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_greeting,
		{ "Greeting", "lat.greeting", FT_UINT_STRING,
		  0, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_num_services,
		{ "Number of services", "lat.num_services", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_service_rating,
		{ "Rating", "lat.service_rating", FT_UINT8,
		  BASE_DEC, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_service_name,
		{ "Service name", "lat.service.name", FT_UINT_STRING,
		  0, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_service_ident,
		{ "Service identification", "lat.service.ident", FT_UINT_STRING,
		  0, NULL, 0x0,
		  NULL, HFILL}},

	    { &hf_lat_unknown_command_data,
		{ "Unknown command data", "lat.unknown_command_data", FT_BYTES,
		  0, NULL, 0x0,
		  NULL, HFILL}},
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
