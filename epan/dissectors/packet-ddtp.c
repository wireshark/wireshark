/* packet-ddtp.c
 * Routines for DDTP (Dynamic DNS Tools Protocol) packet disassembly
 * see http://ddt.sourceforge.net/
 * Olivier Abad <oabad@noos.fr>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2000
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
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
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

#define UDP_PORT_DDTP	1052

/*
 * XXX - is 0 an invalid value?  If so, should we remove it from this
 * list, so that putative DDNS packets with a version number of 0 are
 * rejected?
 */
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

static int
dissect_ddtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *ddtp_tree = NULL;
    proto_item *ti;

    /*
     * If we don't recognize the version number, don't dissect this.
     */
    if (tvb_length(tvb) >= 4) {
	if (match_strval(tvb_get_ntohl(tvb, 0), vals_ddtp_version) == NULL)
	    return 0;
    }

    /* Indicate what kind of message this is. */
    col_set_str (pinfo->cinfo, COL_PROTOCOL, "DDTP");
    /* In case we throw an exception below. */
    col_clear (pinfo->cinfo, COL_INFO);

    if (tree) {
	ti = proto_tree_add_item(tree, proto_ddtp, tvb, 0, -1, FALSE);
	ddtp_tree = proto_item_add_subtree(ti, ett_ddtp);

	proto_tree_add_item(ddtp_tree, hf_ddtp_version, tvb, 0, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(ddtp_tree, hf_ddtp_encrypt, tvb, 4, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(ddtp_tree, hf_ddtp_hostid, tvb, 8, 4, ENC_BIG_ENDIAN);
    }
    if (tvb_get_ntohl(tvb, 4) == DDTP_ENCRYPT_PLAINTEXT) {
	if (tree)
	    proto_tree_add_item(ddtp_tree, hf_ddtp_msgtype, tvb, 12, 4, ENC_BIG_ENDIAN);
	switch (tvb_get_ntohl(tvb, 12)) {
	case DDTP_MESSAGE_ERROR :
	    col_set_str(pinfo->cinfo, COL_INFO, "Message Error");
	    break;
	case DDTP_UPDATE_QUERY :
	    col_set_str(pinfo->cinfo, COL_INFO, "Update Query");
	    if (tree) {
		proto_tree_add_item(ddtp_tree, hf_ddtp_opcode, tvb, 16, 4,
			ENC_BIG_ENDIAN);
		proto_tree_add_item(ddtp_tree, hf_ddtp_ipaddr, tvb, 20, 4,
			ENC_BIG_ENDIAN);
	    }
	    break;
	case DDTP_UPDATE_REPLY :
	    col_set_str(pinfo->cinfo, COL_INFO, "Update Reply");
	    if (tree) {
		proto_tree_add_item(ddtp_tree, hf_ddtp_status, tvb, 16, 4,
			ENC_BIG_ENDIAN);
	    }
	    break;
	case DDTP_ALIVE_QUERY :
	    col_set_str(pinfo->cinfo, COL_INFO, "Alive Query");
	    if (tree) {
		proto_tree_add_text(ddtp_tree, tvb, 16, 4, "Dummy : %u",
			tvb_get_ntohl(tvb, 16));
	    }
	    break;
	case DDTP_ALIVE_REPLY :
	    col_set_str(pinfo->cinfo, COL_INFO, "Alive Reply");
	    if (tree) {
		proto_tree_add_text(ddtp_tree, tvb, 16, 4, "Dummy : %u",
			tvb_get_ntohl(tvb, 16));
	    }
	    break;
	default :
	    col_set_str(pinfo->cinfo, COL_INFO, "Unknown type");
	    if (tree) {
		proto_tree_add_text(ddtp_tree, tvb, 12, 4, "Unknown type : %u",
			tvb_get_ntohl(tvb, 12));
	    }
	}
    } else {
	col_set_str(pinfo->cinfo, COL_INFO, "Encrypted payload");
    }
    return tvb_length(tvb);
}

void
proto_register_ddtp(void)
{
    static hf_register_info hf_ddtp[] = {
	{ &hf_ddtp_version,
	    { "Version", "ddtp.version", FT_UINT32, BASE_DEC, VALS(vals_ddtp_version), 0x0,
		NULL, HFILL }},
	{ &hf_ddtp_encrypt,
	    { "Encryption", "ddtp.encrypt", FT_UINT32, BASE_DEC, VALS(vals_ddtp_encrypt), 0x0,
		"Encryption type", HFILL }},
	{ &hf_ddtp_hostid,
	    { "Hostid", "ddtp.hostid", FT_UINT32, BASE_DEC, NULL, 0x0,
		"Host ID", HFILL }},
	{ &hf_ddtp_msgtype,
	    { "Message type", "ddtp.msgtype", FT_UINT32, BASE_DEC, VALS(vals_ddtp_msgtype), 0x0,
		NULL, HFILL }},
	{ &hf_ddtp_opcode,
	    { "Opcode", "ddtp.opcode", FT_UINT32, BASE_DEC, VALS(vals_ddtp_opcode), 0x0,
		"Update query opcode", HFILL }},
	{ &hf_ddtp_ipaddr,
	    { "IP address", "ddtp.ipaddr", FT_IPv4, BASE_NONE, NULL, 0x0,
		NULL, HFILL }},
	{ &hf_ddtp_status,
	    { "Status", "ddtp.status", FT_UINT32, BASE_DEC, VALS(vals_ddtp_status), 0x0,
		"Update reply status", HFILL }}
    };

    static gint *ett[] = { &ett_ddtp };

    proto_ddtp = proto_register_protocol("Dynamic DNS Tools Protocol",
					 "DDTP", "ddtp");
    proto_register_field_array(proto_ddtp, hf_ddtp, array_length(hf_ddtp));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ddtp(void)
{
    dissector_handle_t ddtp_handle;

    ddtp_handle = new_create_dissector_handle(dissect_ddtp, proto_ddtp);
    dissector_add_uint("udp.port", UDP_PORT_DDTP, ddtp_handle);
}
