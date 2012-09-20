/* packet-igap.c
 * Routines for IGMP/IGAP packet disassembly
 * 2003, Endoh Akria (see AUTHORS for email)
 *
 * $Id$
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

/*
	IGAP "Internet Group membership Authentication Protocol"
	is defined in draft-hayashi-igap-03.txt.

	(Author's memo)
	 Type  Subtype  Message                     Msize
	-----------------------------------------------------
	 ----   0x02    User password               variable
	 ----   0x03    ----                        00
	 ----   0x04    Result of MD5 calculation   16
	 0x41   0x23    Challenge value             ??
	 0x41   0x24    Authentication result code   1
	 0x41   0x25    Accounting status code       1
	 ----   0x42    User password               variable
	 ----   0x43    ----                        00
	 ----   0x44    Result of MD5 calculation   16

*/

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include "packet-igmp.h"
#include "packet-igap.h"


static int proto_igap      = -1;
static int hf_type         = -1;
static int hf_max_resp     = -1;
static int hf_checksum     = -1;
static int hf_checksum_bad = -1;
static int hf_maddr        = -1;
static int hf_version      = -1;
static int hf_subtype      = -1;
static int hf_challengeid  = -1;
static int hf_asize        = -1;
static int hf_msize        = -1;
static int hf_account      = -1;

static int ett_igap = -1;


static const value_string igap_types[] = {
    {IGMP_IGAP_JOIN,  "Membership Report (Join)"},
    {IGMP_IGAP_QUERY, "Membership Query"},
    {IGMP_IGAP_LEAVE, "Leave Group"},
    {0, NULL}
};

#define IGAP_VERSION_1 0x10
static const value_string igap_version[] = {
    {IGAP_VERSION_1, "1"},
    {0, NULL}
};

#define IGAP_SUBTYPE_PASSWORD_JOIN            0x02
#define IGAP_SUBTYPE_CHALLENGE_REQUEST_JOIN   0x03
#define IGAP_SUBTYPE_CHALLENGE_RESPONSE_JOIN  0x04
#define IGAP_SUBTYPE_BASIC_QUERY              0x21
#define IGAP_SUBTYPE_CHALLENGE                0x23
#define IGAP_SUBTYPE_AUTH_MESSAGE             0x24
#define IGAP_SUBTYPE_ACCOUNTING_MESSAGE       0x25
#define IGAP_SUBTYPE_BASIC_LEAVE              0x41
#define IGAP_SUBTYPE_PASSWORD_LEAVE           0x42
#define IGAP_SUBTYPE_CHALLENGE_REQUEST_LEAVE  0x43
#define IGAP_SUBTYPE_CHALLENGE_RESPONSE_LEAVE 0x44
static const value_string igap_subtypes[] = {
    {IGAP_SUBTYPE_PASSWORD_JOIN,            "Password Mechanism Join (Password-Join)"},
    {IGAP_SUBTYPE_CHALLENGE_REQUEST_JOIN,   "Challenge-Response Mechanism Join Request (Challenge-Request-Join)"},
    {IGAP_SUBTYPE_CHALLENGE_RESPONSE_JOIN,  "Challenge-Response Mechanism Join Response (Challenge-Response-Join)"},
    {IGAP_SUBTYPE_BASIC_QUERY,              "Basic Query"},
    {IGAP_SUBTYPE_CHALLENGE,                "Challenge-Response Mechanism Challenge (Challenge)"},
    {IGAP_SUBTYPE_AUTH_MESSAGE,             "Authentication Message"},
    {IGAP_SUBTYPE_ACCOUNTING_MESSAGE,       "Accounting Message"},
    {IGAP_SUBTYPE_BASIC_LEAVE,              "Basic Leave"},
    {IGAP_SUBTYPE_PASSWORD_LEAVE,           "Password Mechanism Leave (Password-Leave)"},
    {IGAP_SUBTYPE_CHALLENGE_REQUEST_LEAVE,  "Challenge-Response Mechanism Leave Challenge Request (Challenge-Request-Leave)"},
    {IGAP_SUBTYPE_CHALLENGE_RESPONSE_LEAVE, "Challenge-Response Mechanism Response (Challenge-Response-Leave)"},
    {0, NULL}
};

#define IGAP_AUTH_SUCCESS 0x11
#define IGAP_AUTH_FAIL    0x21
static const value_string igap_auth_result[] = {
    {IGAP_AUTH_SUCCESS, "Authentication success"},
    {IGAP_AUTH_FAIL,    "Authentication failure"},
    {0, NULL}
};

#define IGAP_ACCOUNT_START 0x11
#define IGAP_ACCOUNT_STOP  0x21
static const value_string igap_account_status[] = {
    {IGAP_ACCOUNT_START, "Accounting start"},
    {IGAP_ACCOUNT_STOP,  "Accounting stop"},
    {0, NULL}
};

#define ACCOUNT_SIZE	16
#define MESSAGE_SIZE	64

/* This function is only called from the IGMP dissector */
int
dissect_igap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, int offset)
{
    proto_tree *tree;
    proto_item *item;
    guint8 type, tsecs, subtype, asize, msize;
    guchar account[ACCOUNT_SIZE+1], message[MESSAGE_SIZE+1];

    if (!proto_is_protocol_enabled(find_protocol_by_id(proto_igap))) {
	/* we are not enabled, skip entire packet to be nice
	   to the igmp layer. (so clicking on IGMP will display the data)
	   */
	return offset + tvb_length_remaining(tvb, offset);
    }

    item = proto_tree_add_item(parent_tree, proto_igap, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_igap);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IGAP");
    col_clear(pinfo->cinfo, COL_INFO);

    type = tvb_get_guint8(tvb, offset);
    if (check_col(pinfo->cinfo, COL_INFO)) {
	col_add_str(pinfo->cinfo, COL_INFO,
		     val_to_str(type, igap_types, "Unknown Type: 0x%02x"));
    }
    proto_tree_add_uint(tree, hf_type, tvb, offset, 1, type);
    offset += 1;

    tsecs = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint_format(tree, hf_max_resp, tvb, offset, 1, tsecs,
	"Max Response Time: %.1f sec (0x%02x)", tsecs * 0.1, tsecs);
    offset += 1;

    igmp_checksum(tree, tvb, hf_checksum, hf_checksum_bad, pinfo, 0);
    offset += 2;

    proto_tree_add_item(tree, hf_maddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_uint(tree, hf_version, tvb, offset, 1,
	tvb_get_guint8(tvb, offset));
    offset += 1;

    subtype = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_subtype, tvb, offset, 1, subtype);
    offset += 2;

    proto_tree_add_uint(tree, hf_challengeid, tvb, offset, 1,
	tvb_get_guint8(tvb, offset));
    offset += 1;

    asize = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_asize, tvb, offset, 1, asize);
    offset += 1;

    msize = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_msize, tvb, offset, 1, msize);
    offset += 3;

    if (asize > 0) {
    	if (asize > ACCOUNT_SIZE) {
    	    /* Bogus account size.
    	       XXX - flag this? */
    	    asize = ACCOUNT_SIZE;
    	}
	tvb_memcpy(tvb, account, offset, asize);
	account[asize] = '\0';
	proto_tree_add_string(tree, hf_account, tvb, offset, asize, account);
    }
    offset += ACCOUNT_SIZE;

    if (msize > 0) {
    	if (msize > MESSAGE_SIZE) {
    	    /* Bogus message size.
    	       XXX - flag this? */
    	    msize = MESSAGE_SIZE;
    	}
	tvb_memcpy(tvb, message, offset, msize);
	switch (subtype) {
	case IGAP_SUBTYPE_PASSWORD_JOIN:
	case IGAP_SUBTYPE_PASSWORD_LEAVE:
	    /* Challenge field is user's password */
	    message[msize] = '\0';
	    proto_tree_add_text(tree, tvb, offset, msize,
				"User password: %s", message);
	    break;
	case IGAP_SUBTYPE_CHALLENGE_RESPONSE_JOIN:
	case IGAP_SUBTYPE_CHALLENGE_RESPONSE_LEAVE:
	    /* Challenge field is the results of MD5 calculation */
	    proto_tree_add_text(tree, tvb, offset, msize,
				"Result of MD5 calculation: 0x%s",
				bytes_to_str(message, msize));
	    break;
	case IGAP_SUBTYPE_CHALLENGE:
	    /* Challenge field is the challenge value */
	    proto_tree_add_text(tree, tvb, offset, msize,
				"Challenge: 0x%s",
				bytes_to_str(message, msize));
	    break;
	case IGAP_SUBTYPE_AUTH_MESSAGE:
	    /* Challenge field indicates the result of the authenticaion */
	    proto_tree_add_text(tree, tvb, offset, msize,
				"Authentication result: %s (0x%x)",
				val_to_str_const(message[0], igap_auth_result, "Unknown"),
				message[0]);
	    break;
	case IGAP_SUBTYPE_ACCOUNTING_MESSAGE:
	    /* Challenge field indicates the accounting status */
	    proto_tree_add_text(tree, tvb, offset, msize,
				"Accounting status: %s (0x%x)",
				val_to_str_const(message[0], igap_account_status, "Unknown"),
				message[0]);
	    break;
	default:
	    proto_tree_add_text(tree, tvb, offset, msize,
				"Message: (Unknown)");
	}
    }
    offset += MESSAGE_SIZE;

    if (item) proto_item_set_len(item, offset);
    return offset;
}


void
proto_register_igap(void)
{
    static hf_register_info hf[] = {
	{ &hf_type,
	  { "Type", "igap.type", FT_UINT8, BASE_HEX,
	    VALS(igap_types), 0, "IGAP Packet Type", HFILL }
	},

	{ &hf_max_resp,
	  { "Max Resp Time", "igap.max_resp", FT_UINT8, BASE_DEC,
	    NULL, 0, "Max Response Time", HFILL }
	},

	{ &hf_checksum,
	  { "Checksum", "igap.checksum", FT_UINT16, BASE_HEX,
	    NULL, 0, NULL, HFILL }
	},

	{ &hf_checksum_bad,
	  { "Bad Checksum", "igap.checksum_bad", FT_BOOLEAN, BASE_NONE,
	    NULL, 0x0, NULL, HFILL }
	},

	{ &hf_maddr,
	  { "Multicast group address", "igap.maddr", FT_IPv4, BASE_NONE,
	    NULL, 0, NULL, HFILL }
	},

	{ &hf_version,
	  { "Version", "igap.version", FT_UINT8, BASE_HEX,
	    VALS(igap_version), 0, "IGAP protocol version", HFILL }
	},

	{ &hf_subtype,
	  { "Subtype", "igap.subtype", FT_UINT8, BASE_HEX,
	    VALS(igap_subtypes), 0, NULL, HFILL }
	},

	{ &hf_challengeid,
	  { "Challenge ID", "igap.challengeid", FT_UINT8, BASE_HEX,
	    NULL, 0, NULL, HFILL }
	},

	{ &hf_asize,
	  { "Account Size", "igap.asize", FT_UINT8, BASE_DEC,
	    NULL, 0, "Length of the User Account field", HFILL }
	},

	{ &hf_msize,
	  { "Message Size", "igap.msize", FT_UINT8, BASE_DEC,
	    NULL, 0, "Length of the Message field", HFILL }
	},

	{ &hf_account,
	  { "User Account", "igap.account", FT_STRING, BASE_NONE,
	    NULL, 0, NULL, HFILL }
	}
    };

    static gint *ett[] = {
	&ett_igap
    };

    proto_igap = proto_register_protocol
	("Internet Group membership Authentication Protocol",
	 "IGAP", "igap");
    proto_register_field_array(proto_igap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}
