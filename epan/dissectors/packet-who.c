/* packet-who.c
 * Routines for who protocol (see man rwhod)
 * Gilbert Ramirez <gram@alumni.rice.edu>
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

#include <time.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/to_str.h>


/*
 *
RWHOD(8)                 UNIX System Manager's Manual                 RWHOD(8)


     The messages sent and received, are of the form:

           struct  outmp {
0                   char    out_line[8];             tty name
8                   char    out_name[8];             user id
16                   long    out_time;               time on
           };

           struct  whod {
 0                   char    wd_vers;
 1                   char    wd_type;
 2                   char    wd_fill[2];
 4                   int     wd_sendtime;
 8                   int     wd_recvtime;
12                   char    wd_hostname[32];
44                   int     wd_loadav[3];
56                   int     wd_boottime;
60                   struct  whoent {
                           struct  outmp we_utmp;
(20 each)                  int     we_idle;
                   } wd_we[1024 / sizeof (struct whoent)];
           };
 *
 */
 
void proto_register_who(void);
void proto_reg_handoff_who(void);

static int proto_who = -1;
static int hf_who_vers = -1;
static int hf_who_type = -1;
static int hf_who_sendtime = -1;
static int hf_who_recvtime = -1;
static int hf_who_hostname = -1;
static int hf_who_loadav_5 = -1;
static int hf_who_loadav_10 = -1;
static int hf_who_loadav_15 = -1;
static int hf_who_boottime = -1;
static int hf_who_whoent = -1;
static int hf_who_tty = -1;
static int hf_who_uid = -1;
static int hf_who_timeon = -1;
static int hf_who_idle = -1;

static gint ett_who = -1;
static gint ett_whoent = -1;

#define UDP_PORT_WHO    513

static void dissect_whoent(tvbuff_t *tvb, int offset, proto_tree *tree);

static void
dissect_who(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int		offset = 0;
	proto_tree	*who_tree = NULL;
	proto_item	*who_ti = NULL;
	guint8		*server_name;
	double		loadav_5 = 0.0, loadav_10 = 0.0, loadav_15 = 0.0;
	nstime_t	ts;

	/* Summary information */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WHO");
	col_clear(pinfo->cinfo, COL_INFO);

	ts.nsecs = 0;

	if (tree) {
		who_ti = proto_tree_add_item(tree, proto_who, tvb, offset, -1,
		    ENC_NA);
		who_tree = proto_item_add_subtree(who_ti, ett_who);
	}

	if (tree)
		proto_tree_add_item(who_tree, hf_who_vers, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	if (tree)
		proto_tree_add_item(who_tree, hf_who_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;

	/* 2 filler bytes */
	offset += 2;

	if (tree) {
		ts.secs = tvb_get_ntohl(tvb, offset);
		proto_tree_add_time(who_tree, hf_who_sendtime, tvb, offset, 4,
		    &ts);
	}
	offset += 4;

	if (tree) {
		ts.secs = tvb_get_ntohl(tvb, offset);
		proto_tree_add_time(who_tree, hf_who_recvtime, tvb, offset, 4,
		    &ts);
	}
	offset += 4;

	server_name = tvb_get_stringzpad(wmem_packet_scope(), tvb, offset, 32, ENC_ASCII|ENC_NA);
	if (tree)
		proto_tree_add_string(who_tree, hf_who_hostname, tvb, offset,
		    32, server_name);
	offset += 32;

	loadav_5  = (double) tvb_get_ntohl(tvb, offset) / 100.0;
	if (tree)
		proto_tree_add_double(who_tree, hf_who_loadav_5, tvb, offset,
		    4, loadav_5);
	offset += 4;

	loadav_10 = (double) tvb_get_ntohl(tvb, offset) / 100.0;
	if (tree)
		proto_tree_add_double(who_tree, hf_who_loadav_10, tvb, offset,
		    4, loadav_10);
	offset += 4;

	loadav_15 = (double) tvb_get_ntohl(tvb, offset) / 100.0;
	if (tree)
		proto_tree_add_double(who_tree, hf_who_loadav_15, tvb, offset,
		    4, loadav_15);
	offset += 4;

	/* Summary information */
	col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %.02f %.02f %.02f",
				server_name, loadav_5, loadav_10, loadav_15);

	if (tree) {
		ts.secs = tvb_get_ntohl(tvb, offset);
		proto_tree_add_time(who_tree, hf_who_boottime, tvb, offset, 4,
		    &ts);
		offset += 4;

		dissect_whoent(tvb, offset, who_tree);
	}
}

/* The man page says that (1024 / sizeof(struct whoent)) is the maximum number
 * of whoent structures in the packet. */
#define SIZE_OF_WHOENT	24
#define MAX_NUM_WHOENTS	(1024 / SIZE_OF_WHOENT)

static void
dissect_whoent(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	proto_tree	*whoent_tree = NULL;
	proto_item	*whoent_ti = NULL;
	int		line_offset = offset;
	guint8		*out_line;
	guint8		*out_name;
	nstime_t	ts;
	int		whoent_num = 0;
	guint32		idle_secs; /* say that out loud... */

	ts.nsecs = 0;

	while (tvb_reported_length_remaining(tvb, line_offset) > 0
	    && whoent_num < MAX_NUM_WHOENTS) {
		whoent_ti = proto_tree_add_item(tree, hf_who_whoent, tvb,
		    line_offset, SIZE_OF_WHOENT, ENC_NA);
		whoent_tree = proto_item_add_subtree(whoent_ti, ett_whoent);

		out_line = tvb_get_stringzpad(wmem_packet_scope(), tvb, line_offset, 8, ENC_ASCII|ENC_NA);
		proto_tree_add_string(whoent_tree, hf_who_tty, tvb, line_offset,
		    8, out_line);
		line_offset += 8;

		out_name = tvb_get_stringzpad(wmem_packet_scope(), tvb, line_offset, 8, ENC_ASCII|ENC_NA);
		proto_tree_add_string(whoent_tree, hf_who_uid, tvb, line_offset,
		    8, out_name);
		line_offset += 8;

		ts.secs = tvb_get_ntohl(tvb, line_offset);
		proto_tree_add_time(whoent_tree, hf_who_timeon, tvb,
		    line_offset, 4, &ts);
		line_offset += 4;

		idle_secs = tvb_get_ntohl(tvb, line_offset);
		proto_tree_add_uint_format(whoent_tree, hf_who_idle, tvb,
		    line_offset, 4, idle_secs, "Idle: %s",
		    time_secs_to_str(wmem_packet_scope(), idle_secs));
		line_offset += 4;

		whoent_num++;
	}
}

void
proto_register_who(void)
{
	static hf_register_info hf[] = {
		{ &hf_who_vers,
		{ "Version",	"who.vers", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_type,
		{ "Type",	"who.type", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_sendtime,
		{ "Send Time",	"who.sendtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_recvtime,
		{ "Receive Time", "who.recvtime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_hostname,
		{ "Hostname", "who.hostname", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_loadav_5,
		{ "Load Average Over Past  5 Minutes", "who.loadav_5", FT_DOUBLE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_loadav_10,
		{ "Load Average Over Past 10 Minutes", "who.loadav_10", FT_DOUBLE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_loadav_15,
		{ "Load Average Over Past 15 Minutes", "who.loadav_15", FT_DOUBLE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_boottime,
		{ "Boot Time", "who.boottime", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_whoent,
		{ "Who utmp Entry", "who.entry", FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_tty,
		{ "TTY Name", "who.tty", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_uid,
		{ "User ID", "who.uid", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_timeon,
		{ "Time On", "who.timeon", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
			NULL, HFILL }},

		{ &hf_who_idle,
		{ "Time Idle", "who.idle", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_who,
		&ett_whoent,
	};

	proto_who = proto_register_protocol("Who", "WHO", "who");
	proto_register_field_array(proto_who, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_who(void)
{
	dissector_handle_t who_handle;

	who_handle = create_dissector_handle(dissect_who, proto_who);
	dissector_add_uint("udp.port", UDP_PORT_WHO, who_handle);
}
