/* packet-sebek.c
 * Routines for Sebek - Kernel based data capture - packet dissection
 * Copyright 1999, Nathan Neulinger <nneul@umr.edu>
 *
 * See: http://project.honeynet.org/tools/sebek/ for more details
 *
 * $Id: packet-sebek.c,v 1.1 2003/11/19 22:13:29 nneul Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>

#include <string.h>
#include <time.h>
#include <math.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include <epan/resolv.h>

/*
        IP address:     32bit unsigned
        MAGIC Val:      32bit unsigned
        Sebek Ver:      16bit unsigned
        Type            16bit unsigned
        Counter:        32bit unsigned
        Time_sec:       32bit unsigned
        Time_usec:      32bit unsigned
        Proc ID:        32bit unsigned
        User ID:        32bit unsigned
        File Desc:      32bit unsigned
        Command:        12char array
        Length:         Data Length

        Data:           Variable Length data

 *
 */

/* By default, but can be completely different */
#define UDP_PORT_SEBEK	1101

static int proto_sebek = -1;

static int hf_sebek_magic = -1;
static int hf_sebek_version = -1;
static int hf_sebek_type = -1;
static int hf_sebek_counter = -1;
static int hf_sebek_time = -1;
static int hf_sebek_pid = -1;
static int hf_sebek_uid = -1;
static int hf_sebek_fd = -1;
static int hf_sebek_cmd = -1;
static int hf_sebek_len = -1;
static int hf_sebek_data = -1;

static gint ett_sebek = -1;

/* dissect_sebek - dissects sebek packet data
 * tvb - tvbuff for packet data (IN)
 * pinfo - packet info
 * proto_tree - resolved protocol tree
 */
static void
dissect_sebek(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree      *sebek_tree;
	proto_item	*ti;
	int offset = 0;
	int datalen = 0;
	nstime_t ts;
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SEBEK");

	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_clear(pinfo->cinfo, COL_INFO);
		col_set_str(pinfo->cinfo, COL_INFO, "SEBEK - ");
		col_append_fstr(pinfo->cinfo, COL_INFO, " pid(%d)", tvb_get_ntohl(tvb, 20));
		col_append_fstr(pinfo->cinfo, COL_INFO, " uid(%d)", tvb_get_ntohl(tvb, 24));
		col_append_fstr(pinfo->cinfo, COL_INFO, " fd(%d)", tvb_get_ntohl(tvb, 28));
		col_append_fstr(pinfo->cinfo, COL_INFO, " cmd: %s", tvb_get_string(tvb, 32, 12));
	}


	if (tree) {
		/* Adding NTP item and subtree */
		ti = proto_tree_add_item(tree, proto_sebek, tvb, 0, -1, FALSE);
		sebek_tree = proto_item_add_subtree(ti, ett_sebek);

		proto_tree_add_item(sebek_tree, hf_sebek_magic, tvb, offset, 4, FALSE);
		offset += 4;

		proto_tree_add_item(sebek_tree, hf_sebek_version, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(sebek_tree, hf_sebek_type, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(sebek_tree, hf_sebek_counter, tvb, offset, 4, FALSE);
		offset += 4;

        ts.secs = tvb_get_ntohl(tvb, offset);
        ts.nsecs = tvb_get_ntohl(tvb, offset+4);
        proto_tree_add_time(sebek_tree, hf_sebek_time, tvb, offset, 8, &ts);
        offset += 8; 

		proto_tree_add_item(sebek_tree, hf_sebek_pid, tvb, offset, 4, FALSE);
		offset += 4;

		proto_tree_add_item(sebek_tree, hf_sebek_uid, tvb, offset, 4, FALSE);
		offset += 4;

		proto_tree_add_item(sebek_tree, hf_sebek_fd, tvb, offset, 4, FALSE);
		offset += 4;

		proto_tree_add_item(sebek_tree, hf_sebek_cmd, tvb, offset, 12, FALSE);
		offset += 12;

		datalen = tvb_get_letohl(tvb, offset);
		proto_tree_add_item(sebek_tree, hf_sebek_len, tvb, offset, 4, FALSE);
		offset += 4;

		proto_tree_add_item(sebek_tree, hf_sebek_data, tvb, offset, -1, FALSE);
		
	}
}

void
proto_register_sebek(void)
{
	static hf_register_info hf[] = {
		{ &hf_sebek_magic, {
			"Magic", "sebek.magic", FT_UINT32, BASE_HEX,
			NULL, 0, "Magic Number", HFILL }},
		{ &hf_sebek_version, {
			"Version", "sebek.version", FT_UINT16, BASE_DEC,
			NULL, 0, "Version Number", HFILL }},
		{ &hf_sebek_type, {
			"Type", "sebek.type", FT_UINT16, BASE_DEC,
			NULL, 0, "Type", HFILL }},
		{ &hf_sebek_counter, {
			"Counter", "sebek.counter", FT_UINT32, BASE_DEC,
			NULL, 0, "Counter", HFILL }},
		{ &hf_sebek_time, {
			"Time", "sebek.time.sec", FT_ABSOLUTE_TIME, BASE_NONE,
			NULL, 0, "Time", HFILL }},
		{ &hf_sebek_pid, {
			"Process ID", "sebek.pid", FT_UINT32, BASE_DEC,
			NULL, 0, "Process ID", HFILL }},
		{ &hf_sebek_uid, {
			"User ID", "sebek.uid", FT_UINT32, BASE_DEC,
			NULL, 0, "User ID", HFILL }},
		{ &hf_sebek_fd, {
			"File Descriptor", "sebek.fd", FT_UINT32, BASE_DEC,
			NULL, 0, "File Descriptor Number", HFILL }},
		{ &hf_sebek_cmd, {
			"Command Name", "sebek.cmd", FT_STRING, 0,
			NULL, 0, "Command Name", HFILL }},
		{ &hf_sebek_len, {
			"Data Length", "sebek.len", FT_UINT32, BASE_DEC,
			NULL, 0, "Data Length", HFILL }},
		{ &hf_sebek_data, {
			"Data", "sebek.data", FT_STRING, 0,
			NULL, 0, "Data", HFILL }},
        };
	static gint *ett[] = {
		&ett_sebek,
	};

	proto_sebek = proto_register_protocol("SEBEK - Kernel Data Capture", "SEBEK",
	    "sebek");
	proto_register_field_array(proto_sebek, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_sebek(void)
{
	dissector_handle_t sebek_handle;

	sebek_handle = create_dissector_handle(dissect_sebek, proto_sebek);
	dissector_add("udp.port", UDP_PORT_SEBEK, sebek_handle);
}
