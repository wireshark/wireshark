/* packet-dhis.c
 * Routines for DHIS (Dynamic Host Information Services) packet disassembly
 * see http://dhis.sourceforge.net/
 * Olivier Abad <abad@daba.dhis.net>
 *
 * $Id: packet-dhis.c,v 1.3 2000/04/08 07:07:12 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 2000
 *
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
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

/*#include <string.h>
#include <ctype.h>
#include <time.h>*/

#include <glib.h>
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#include "packet.h"
#include "dfilter.h"
#include "packet-dhis.h"

static int proto_dhis = -1;
static int hf_dhis_version = -1;
static int hf_dhis_encrypt = -1;
static int hf_dhis_hostid = -1;
static int hf_dhis_msgtype = -1;
static int hf_dhis_opcode = -1;
static int hf_dhis_ipaddr = -1;
static int hf_dhis_status = -1;

static int ett_dhis = -1;

#define UDP_PORT_DHIS1	58800
#define UDP_PORT_DHIS2	58801

static const value_string vals_dhis_version[] = {
    { DHIS_VERSION_ERROR, "Protocol Error" },
    { DHIS_VERSION_4,     "4" },
    { DHIS_VERSION_5,     "5" },
    { 0, NULL}
};

static const value_string vals_dhis_encrypt[] = {
    { DHIS_ENCRYPT_ERROR,     "Encryption Error" },
    { DHIS_ENCRYPT_PLAINTEXT, "Plain text" },
    { DHIS_ENCRYPT_BLOWFISH,  "Blowfish" },
    { 0, NULL}
};

static const value_string vals_dhis_msgtype[] = {
    { DHIS_MESSAGE_ERROR, "Message Error" },
    { DHIS_UPDATE_QUERY,  "Update Query" },
    { DHIS_UPDATE_REPLY,  "Update Reply" },
    { DHIS_ALIVE_QUERY,   "Alive Query" },
    { DHIS_ALIVE_REPLY,   "Alive Reply" },
    { 0, NULL}
};

static const value_string vals_dhis_opcode[] = {
    { DHIS_MARK_ONLINE,  "Mark online" },
    { DHIS_MARK_OFFLINE, "Mark offline" },
    { 0, NULL}
};

static const value_string vals_dhis_status[] = {
    { DHIS_UPDATE_SUCCEEDED, "Update succeeded" },
    { DHIS_UPDATE_FAILED,    "Update failed" },
    { DHIS_INVALID_PASSWORD, "Invalid password" },
    { DHIS_INVALID_ACCOUNT,  "Invalid account" },
    { DHIS_INVALID_OPCODE,   "Invalid opcode" },
    { 0, NULL}
};

static void
dissect_dhis(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{

    proto_tree	    *dhis_tree;
    proto_item	    *ti;

    if (check_col(fd, COL_PROTOCOL)) {
	/*
	 * Indicate what kind of message this is.
	 */
    	col_add_str (fd, COL_PROTOCOL, "DHIS");
    }
    if (tree) {
	ti = proto_tree_add_item(tree, proto_dhis, offset,
		END_OF_FRAME - offset, NULL);
	dhis_tree = proto_item_add_subtree(ti, ett_dhis);

	if (!BYTES_ARE_IN_FRAME(offset, 4)) {
	    proto_tree_add_text(dhis_tree, offset, END_OF_FRAME-offset, "Frame too short");
	    return;
	}
	proto_tree_add_item(dhis_tree, hf_dhis_version, offset, 4, pntohl(pd+offset));
	offset += 4;
	if (!BYTES_ARE_IN_FRAME(offset, 4)) {
	    proto_tree_add_text(dhis_tree, offset, END_OF_FRAME-offset, "Frame too short");
	    return;
	}
	proto_tree_add_item(dhis_tree, hf_dhis_encrypt, offset, 4, pntohl(pd+offset));
	if (!BYTES_ARE_IN_FRAME(offset+4, 4)) {
	    proto_tree_add_text(dhis_tree, offset+4, END_OF_FRAME-offset-4, "Frame too short");
	    return;
	}
	proto_tree_add_item(dhis_tree, hf_dhis_hostid, offset+4, 4, pntohl(pd+offset+4));
	if (pntohl(pd+offset) == DHIS_ENCRYPT_PLAINTEXT) {
	    offset += 8;
	    if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		proto_tree_add_text(dhis_tree, offset, END_OF_FRAME-offset, "Frame too short");
		return;
	    }
	    proto_tree_add_item(dhis_tree, hf_dhis_msgtype, offset, 4, pntohl(pd+offset));
	    switch (pntohl(pd+offset)) {
	    case DHIS_MESSAGE_ERROR :
		offset += 4;
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Message Error");
		break;
	    case DHIS_UPDATE_QUERY :
		offset += 4;
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Update Query");
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(dhis_tree, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_item(dhis_tree, hf_dhis_opcode, offset, 4, pntohl(pd+offset));
		offset += 4;
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(dhis_tree, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_item(dhis_tree, hf_dhis_ipaddr, offset, 4, pntohl(pd+offset));
		break;
	    case DHIS_UPDATE_REPLY :
		offset += 4;
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Update Reply");
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(dhis_tree, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_item(dhis_tree, hf_dhis_status, offset, 4, pntohl(pd+offset));
		break;
	    case DHIS_ALIVE_QUERY :
		offset += 4;
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Alive Query");
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(dhis_tree, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_text(dhis_tree, offset, 4, "Dummy : %u", pntohl(pd+offset));
		break;
	    case DHIS_ALIVE_REPLY :
		offset += 4;
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Alive Reply");
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(dhis_tree, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_text(dhis_tree, offset, 4, "Dummy : %u", pntohl(pd+offset));
		break;
	    default :
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Unknwon type");
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(dhis_tree, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_text(dhis_tree, offset, 4, "Unknown type : %u", pntohl(pd+offset));
	    }
	}
   }
}

void
proto_register_dhis(void)
{
    static hf_register_info hf_dhis[] = {
	{ &hf_dhis_version,
	    { "Version", "dhis.version", FT_UINT32, BASE_DEC, VALS(vals_dhis_version), 0x0,
		"Version" } },
	{ &hf_dhis_encrypt,
	    { "Encryption", "dhis.encrypt", FT_UINT32, BASE_DEC, VALS(vals_dhis_encrypt), 0x0,
		"Encryption type" } },
	{ &hf_dhis_hostid,
	    { "Hostid", "dhis.hostid", FT_UINT32, BASE_DEC, NULL, 0x0,
		"Host ID" } },
	{ &hf_dhis_msgtype,
	    { "Message type", "dhis.msgtype", FT_UINT32, BASE_DEC, VALS(vals_dhis_msgtype), 0x0,
		"Message Type" } },
	{ &hf_dhis_opcode,
	    { "Opcode", "dhis.opcode", FT_UINT32, BASE_DEC, VALS(vals_dhis_opcode), 0x0,
		"Update query opcode" } },
	{ &hf_dhis_ipaddr,
	    { "IP addres", "dhis.ipaddr", FT_IPv4, BASE_NONE, NULL, 0x0,
		"IP address" } },
	{ &hf_dhis_status,
	    { "Status", "dhis.status", FT_UINT32, BASE_DEC, VALS(vals_dhis_status), 0x0,
		"Update reply status" } }
    };

    static gint *ett[] = { &ett_dhis };

    proto_dhis = proto_register_protocol("Dynamic Host Information Service", "dhis");
    proto_register_field_array(proto_dhis, hf_dhis, array_length(hf_dhis));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dhis(void)
{
    dissector_add("udp.port", UDP_PORT_DHIS1, dissect_dhis);
    dissector_add("udp.port", UDP_PORT_DHIS2, dissect_dhis);
}
