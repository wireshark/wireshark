/* packet-ddtp.c
 * Routines for DDTP (Dynamic DNS Tools Protocol) packet disassembly
 * see http://ddt.sourceforge.net/
 * Olivier Abad <abad@daba.dhis.net>
 *
 * $Id: packet-ddtp.c,v 1.3 2000/05/11 08:15:05 gram Exp $
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
#include "packet-ddtp.h"

static int proto_ddtp = -1;
static int hf_ddtp_version = -1;
static int hf_ddtp_encrypt = -1;
static int hf_ddtp_hostid = -1;
static int hf_ddtp_msgtype = -1;
static int hf_ddtp_opcode = -1;
static int hf_ddtp_ipaddr = -1;
static int hf_ddtp_status = -1;

static int ett_ddtp = -1;

#define UDP_PORT_DDTP1	58800
#define UDP_PORT_DDTP2	58801

static const value_string vals_ddtp_version[] = {
    { DDTP_VERSION_ERROR, "Protocol Error" },
    { DDTP_VERSION_4,     "4" },
    { DDTP_VERSION_5,     "5" },
    { 0, NULL}
};

static const value_string vals_ddtp_encrypt[] = {
    { DDTP_ENCRYPT_ERROR,     "Encryption Error" },
    { DDTP_ENCRYPT_PLAINTEXT, "Plain text" },
    { DDTP_ENCRYPT_BLOWFISH,  "Blowfish" },
    { 0, NULL}
};

static const value_string vals_ddtp_msgtype[] = {
    { DDTP_MESSAGE_ERROR, "Message Error" },
    { DDTP_UPDATE_QUERY,  "Update Query" },
    { DDTP_UPDATE_REPLY,  "Update Reply" },
    { DDTP_ALIVE_QUERY,   "Alive Query" },
    { DDTP_ALIVE_REPLY,   "Alive Reply" },
    { 0, NULL}
};

static const value_string vals_ddtp_opcode[] = {
    { DDTP_MARK_ONLINE,  "Mark online" },
    { DDTP_MARK_OFFLINE, "Mark offline" },
    { 0, NULL}
};

static const value_string vals_ddtp_status[] = {
    { DDTP_UPDATE_SUCCEEDED, "Update succeeded" },
    { DDTP_UPDATE_FAILED,    "Update failed" },
    { DDTP_INVALID_PASSWORD, "Invalid password" },
    { DDTP_INVALID_ACCOUNT,  "Invalid account" },
    { DDTP_INVALID_OPCODE,   "Invalid opcode" },
    { 0, NULL}
};

static void
dissect_ddtp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{

    proto_tree	    *ddtp_tree;
    proto_item	    *ti;

    if (check_col(fd, COL_PROTOCOL)) {
	/* Indicate what kind of message this is. */
    	col_add_str (fd, COL_PROTOCOL, "DDTP");
    }
    if (tree) {
	ti = proto_tree_add_item(tree, proto_ddtp, NullTVB, offset,
		END_OF_FRAME - offset, NULL);
	ddtp_tree = proto_item_add_subtree(ti, ett_ddtp);

	if (!BYTES_ARE_IN_FRAME(offset, 4)) {
	    proto_tree_add_text(ddtp_tree, NullTVB, offset, END_OF_FRAME-offset, "Frame too short");
	    return;
	}
	proto_tree_add_item(ddtp_tree, hf_ddtp_version, NullTVB, offset, 4, pntohl(pd+offset));
	offset += 4;
	if (!BYTES_ARE_IN_FRAME(offset, 4)) {
	    proto_tree_add_text(ddtp_tree, NullTVB, offset, END_OF_FRAME-offset, "Frame too short");
	    return;
	}
	proto_tree_add_item(ddtp_tree, hf_ddtp_encrypt, NullTVB, offset, 4, pntohl(pd+offset));
	if (!BYTES_ARE_IN_FRAME(offset+4, 4)) {
	    proto_tree_add_text(ddtp_tree, NullTVB, offset+4, END_OF_FRAME-offset-4, "Frame too short");
	    return;
	}
	proto_tree_add_item(ddtp_tree, hf_ddtp_hostid, NullTVB, offset+4, 4, pntohl(pd+offset+4));
	if (pntohl(pd+offset) == DDTP_ENCRYPT_PLAINTEXT) {
	    offset += 8;
	    if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		proto_tree_add_text(ddtp_tree, NullTVB, offset, END_OF_FRAME-offset, "Frame too short");
		return;
	    }
	    proto_tree_add_item(ddtp_tree, hf_ddtp_msgtype, NullTVB, offset, 4, pntohl(pd+offset));
	    switch (pntohl(pd+offset)) {
	    case DDTP_MESSAGE_ERROR :
		offset += 4;
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Message Error");
		break;
	    case DDTP_UPDATE_QUERY :
		offset += 4;
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Update Query");
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(ddtp_tree, NullTVB, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_item(ddtp_tree, hf_ddtp_opcode, NullTVB, offset, 4, pntohl(pd+offset));
		offset += 4;
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(ddtp_tree, NullTVB, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_item(ddtp_tree, hf_ddtp_ipaddr, NullTVB, offset, 4, pntohl(pd+offset));
		break;
	    case DDTP_UPDATE_REPLY :
		offset += 4;
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Update Reply");
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(ddtp_tree, NullTVB, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_item(ddtp_tree, hf_ddtp_status, NullTVB, offset, 4, pntohl(pd+offset));
		break;
	    case DDTP_ALIVE_QUERY :
		offset += 4;
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Alive Query");
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(ddtp_tree, NullTVB, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_text(ddtp_tree, NullTVB, offset, 4, "Dummy : %u", pntohl(pd+offset));
		break;
	    case DDTP_ALIVE_REPLY :
		offset += 4;
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Alive Reply");
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(ddtp_tree, NullTVB, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_text(ddtp_tree, NullTVB, offset, 4, "Dummy : %u", pntohl(pd+offset));
		break;
	    default :
		if (check_col(fd, COL_INFO)) col_add_str (fd, COL_INFO, "Unknwon type");
		if (!BYTES_ARE_IN_FRAME(offset, 4)) {
		    proto_tree_add_text(ddtp_tree, NullTVB, offset, END_OF_FRAME-offset, "Frame too short");
		    return;
		}
		proto_tree_add_text(ddtp_tree, NullTVB, offset, 4, "Unknown type : %u", pntohl(pd+offset));
	    }
	}
   }
}

void
proto_register_ddtp(void)
{
    static hf_register_info hf_ddtp[] = {
	{ &hf_ddtp_version,
	    { "Version", "ddtp.version", FT_UINT32, BASE_DEC, VALS(vals_ddtp_version), 0x0,
		"Version" } },
	{ &hf_ddtp_encrypt,
	    { "Encryption", "ddtp.encrypt", FT_UINT32, BASE_DEC, VALS(vals_ddtp_encrypt), 0x0,
		"Encryption type" } },
	{ &hf_ddtp_hostid,
	    { "Hostid", "ddtp.hostid", FT_UINT32, BASE_DEC, NULL, 0x0,
		"Host ID" } },
	{ &hf_ddtp_msgtype,
	    { "Message type", "ddtp.msgtype", FT_UINT32, BASE_DEC, VALS(vals_ddtp_msgtype), 0x0,
		"Message Type" } },
	{ &hf_ddtp_opcode,
	    { "Opcode", "ddtp.opcode", FT_UINT32, BASE_DEC, VALS(vals_ddtp_opcode), 0x0,
		"Update query opcode" } },
	{ &hf_ddtp_ipaddr,
	    { "IP addres", "ddtp.ipaddr", FT_IPv4, BASE_NONE, NULL, 0x0,
		"IP address" } },
	{ &hf_ddtp_status,
	    { "Status", "ddtp.status", FT_UINT32, BASE_DEC, VALS(vals_ddtp_status), 0x0,
		"Update reply status" } }
    };

    static gint *ett[] = { &ett_ddtp };

    proto_ddtp = proto_register_protocol("Dynamic DNS Tools Protocol", "ddtp");
    proto_register_field_array(proto_ddtp, hf_ddtp, array_length(hf_ddtp));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ddtp(void)
{
    dissector_add("udp.port", UDP_PORT_DDTP1, dissect_ddtp);
    dissector_add("udp.port", UDP_PORT_DDTP2, dissect_ddtp);
}
