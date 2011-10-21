/* packet-wow.c
 * Routines for World of Warcraft (WoW) protocol dissection
 * Copyright 2008-2009, Stephen Fisher (see AUTHORS file)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

/* This dissector is based on the MaNGOS project's source code, Stanford's
 * SRP protocol documents (http://srp.stanford.edu) and RFC 2945: "The SRP
 * Authentication and Key Exchange System." */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

typedef enum {
	AUTH_LOGON_CHALLENGE = 0x00,
	AUTH_LOGON_PROOF     = 0x01,
	REALM_LIST           = 0x10,
	XFER_INITIATE        = 0x30,
	XFER_DATA            = 0x31,
	XFER_ACCEPT          = 0x32,
	XFER_RESUME          = 0x33,
	XFER_CANCEL          = 0x34
} auth_cmd_e;

static const value_string cmd_vs[] = {
	{ AUTH_LOGON_CHALLENGE, "Authentication Logon Challenge" },
	{ AUTH_LOGON_PROOF,     "Authentication Logon Proof"     },
	{ REALM_LIST,           "Realm List"                     },
	{ XFER_INITIATE,        "Transfer Initiate"              },
	{ XFER_DATA,            "Transfer Data"                  },
	{ XFER_ACCEPT,          "Transfer Accept"                },
	{ XFER_RESUME,          "Transfer Resume"                },
	{ XFER_CANCEL,          "Transfer Cancel"                },
	{ 0, NULL                                                }
};

static const value_string account_type_vs[] = {
	{ 0, "Player"        },
	{ 1, "Moderator"     },
	{ 2, "Game master"   },
	{ 3, "Administrator" },
	{ 0, NULL            }
};

static const value_string realm_status_vs[] = {
	{ 0, "Online"  },
	{ 1, "Locked"  },
	{ 2, "Offline" },
	{ 0, NULL      }
};

static const value_string realm_type_vs[] = {
	{ 0, "Normal"                             },
	{ 1, "Player versus player"               },
	{ 4, "Normal (2)"                         },
	{ 6, "Role playing normal"                },
	{ 8, "Role playing player versus player)" },
	{ 0, NULL                                 }
};

#define WOW_PORT 3724

#define WOW_CLIENT_TO_SERVER pinfo->destport == WOW_PORT
#define WOW_SERVER_TO_CLIENT pinfo->srcport  == WOW_PORT

/* Initialize the protocol and registered fields */
static int proto_wow = -1;

static int hf_wow_command = -1;
static int hf_wow_error = -1;
static int hf_wow_pkt_size = -1;
static int hf_wow_gamename = -1;
static int hf_wow_version1 = -1;
static int hf_wow_version2 = -1;
static int hf_wow_version3 = -1;
static int hf_wow_build = -1;
static int hf_wow_platform = -1;
static int hf_wow_os = -1;
static int hf_wow_country = -1;
static int hf_wow_timezone_bias = -1;
static int hf_wow_ip = -1;
static int hf_wow_srp_i_len = -1;
static int hf_wow_srp_i = -1;

static int hf_wow_srp_b = -1;
static int hf_wow_srp_g_len = -1;
static int hf_wow_srp_g = -1;
static int hf_wow_srp_n_len = -1;
static int hf_wow_srp_n = -1;
static int hf_wow_srp_s = -1;

static int hf_wow_srp_a = -1;
static int hf_wow_srp_m1 = -1;
static int hf_wow_crc_hash = -1;
static int hf_wow_num_keys = -1;

static int hf_wow_srp_m2 = -1;

static int hf_wow_num_realms = -1;
static int hf_wow_realm_type = -1;
static int hf_wow_realm_status = -1;
static int hf_wow_realm_color = -1;
static int hf_wow_realm_name = -1;
static int hf_wow_realm_socket = -1;
static int hf_wow_realm_population_level = -1;
static int hf_wow_realm_num_characters = -1;
static int hf_wow_realm_timezone = -1;

static gboolean wow_preference_desegment = TRUE;

static gint ett_wow = -1;
static gint ett_wow_realms = -1;

static void dissect_wow_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static guint get_wow_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset);


static gboolean
dissect_wow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint8 size_field_offset = -1;
	guint8 cmd;

	cmd = tvb_get_guint8(tvb, 0);

	if(WOW_SERVER_TO_CLIENT && cmd == REALM_LIST)
		size_field_offset = 1;
	if(WOW_CLIENT_TO_SERVER && cmd == AUTH_LOGON_CHALLENGE)
		size_field_offset = 2;

	if(size_field_offset > -1) {
		tcp_dissect_pdus(tvb, pinfo, tree, wow_preference_desegment,
				 size_field_offset+2, get_wow_pdu_len,
				 dissect_wow_pdu);

	} else {
		/* Doesn't have a size field, so it cannot span multiple
		   segments.  Therefore, dissect this packet normally. */
		dissect_wow_pdu(tvb, pinfo, tree);
	}

	return TRUE;
}

static guint
get_wow_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset)
{
	gint8 size_field_offset = -1;
	guint8 cmd;
	guint16 pkt_len;

	cmd = tvb_get_guint8(tvb, offset);

	if(WOW_SERVER_TO_CLIENT && cmd == REALM_LIST)
		size_field_offset = 1;
	if(WOW_CLIENT_TO_SERVER && cmd == AUTH_LOGON_CHALLENGE)
		size_field_offset = 2;

	pkt_len = tvb_get_letohs(tvb, size_field_offset);

	return pkt_len + size_field_offset + 2;
}


static void
dissect_wow_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *wow_tree, *wow_realms_tree;

	gchar *string, *realm_name;
	guint8 cmd, srp_i_len, srp_g_len, srp_n_len;
	guint16 num_realms;
	guint32 offset = 0;
	gint len, i;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WOW");

	col_clear(pinfo->cinfo, COL_INFO);

	cmd = tvb_get_guint8(tvb, offset);

	if(check_col(pinfo->cinfo, COL_INFO)) {
		col_set_str(pinfo->cinfo, COL_INFO,
			    val_to_str_const(cmd, cmd_vs,
				       "Unrecognized packet type"));
	}

	if(tree) {
		ti = proto_tree_add_item(tree, proto_wow, tvb, 0, -1, ENC_NA);
		wow_tree = proto_item_add_subtree(ti, ett_wow);

		proto_tree_add_item(wow_tree, hf_wow_command, tvb, offset, 1,
				    ENC_LITTLE_ENDIAN);
		offset += 1;

		switch(cmd) {

		case AUTH_LOGON_CHALLENGE :

			if(WOW_CLIENT_TO_SERVER) {
				proto_tree_add_item(wow_tree, hf_wow_error, tvb,
						    offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;

				proto_tree_add_item(wow_tree, hf_wow_pkt_size,
						    tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;

				string = g_strreverse(tvb_get_ephemeral_string(tvb, offset, 4));
				proto_tree_add_string(wow_tree, hf_wow_gamename,
						      tvb, offset, 4, string);
				offset += 4;

				proto_tree_add_item(wow_tree, hf_wow_version1,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;

				proto_tree_add_item(wow_tree, hf_wow_version2,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;

				proto_tree_add_item(wow_tree, hf_wow_version3,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;

				proto_tree_add_item(wow_tree, hf_wow_build, tvb,
						    offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;

				string = g_strreverse(tvb_get_ephemeral_string(tvb, offset, 4));
				proto_tree_add_string(wow_tree, hf_wow_platform,
						      tvb, offset, 4, string);
				offset += 4;

				string = g_strreverse(tvb_get_ephemeral_string(tvb, offset, 4));
				proto_tree_add_string(wow_tree, hf_wow_os, tvb,
						      offset, 4, string);
				offset += 4;

				string = g_strreverse(tvb_get_ephemeral_string(tvb, offset, 4));
				proto_tree_add_string(wow_tree, hf_wow_country,
						      tvb, offset, 4, string);
				offset += 4;

				proto_tree_add_item(wow_tree,
						    hf_wow_timezone_bias,
						    tvb, offset, 4, ENC_LITTLE_ENDIAN);
				offset += 4;

				proto_tree_add_item(wow_tree, hf_wow_ip, tvb,
						    offset, 4, ENC_BIG_ENDIAN);
				offset += 4;

				proto_tree_add_item(wow_tree,
						    hf_wow_srp_i_len,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				srp_i_len = tvb_get_guint8(tvb, offset);
				offset += 1;

				proto_tree_add_item(wow_tree,
						    hf_wow_srp_i, tvb,
						    offset, srp_i_len,
						    ENC_ASCII|ENC_NA);
				offset += srp_i_len;


			} else if(WOW_SERVER_TO_CLIENT) {
				proto_tree_add_item(wow_tree, hf_wow_error, tvb,
						    offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;

				offset += 1; /* Unknown field */

				proto_tree_add_item(wow_tree, hf_wow_srp_b, tvb,
						    offset, 32, ENC_NA);
				offset += 32;

				proto_tree_add_item(wow_tree, hf_wow_srp_g_len,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				srp_g_len = tvb_get_guint8(tvb, offset);
				offset += 1;

				proto_tree_add_item(wow_tree, hf_wow_srp_g, tvb,
						    offset, srp_g_len, ENC_NA);
				offset += srp_g_len;

				proto_tree_add_item(wow_tree, hf_wow_srp_n_len,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				srp_n_len = tvb_get_guint8(tvb, offset);
				offset += 1;

				proto_tree_add_item(wow_tree, hf_wow_srp_n, tvb,
						    offset, srp_n_len, ENC_NA);
				offset += srp_n_len;

				proto_tree_add_item(wow_tree, hf_wow_srp_s, tvb,
						    offset, 32, ENC_NA);
				offset += 32;

				offset += 16; /* Unknown field */
			}

			break;

		case AUTH_LOGON_PROOF :

			if(WOW_CLIENT_TO_SERVER) {
				proto_tree_add_item(wow_tree, hf_wow_srp_a, tvb,
						    offset, 32, ENC_NA);
				offset += 32;

				proto_tree_add_item(wow_tree, hf_wow_srp_m1,
						    tvb, offset, 20, ENC_NA);
				offset += 20;

				proto_tree_add_item(wow_tree, hf_wow_crc_hash,
						    tvb, offset, 20, ENC_NA);
				offset += 20;

				proto_tree_add_item(wow_tree, hf_wow_num_keys,
						    tvb, offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;

				offset += 1; /* Unknown field */

			} else if(WOW_SERVER_TO_CLIENT) {
				proto_tree_add_item(wow_tree, hf_wow_error, tvb,
						    offset, 1, ENC_LITTLE_ENDIAN);
				offset += 1;

				proto_tree_add_item(wow_tree, hf_wow_srp_m2,
						    tvb, offset, 20, ENC_NA);
				offset += 20;

				offset += 4; /* Unknown field */

				offset += 2; /* Unknown field */
			}

			break;

		case REALM_LIST :

			if(WOW_CLIENT_TO_SERVER) {


			} else if(WOW_SERVER_TO_CLIENT) {

				proto_tree_add_item(wow_tree, hf_wow_pkt_size,
						    tvb, offset, 2, ENC_LITTLE_ENDIAN);
				offset += 2;

				offset += 4; /* Unknown field; always 0 */

				proto_tree_add_item(wow_tree, hf_wow_num_realms,
						    tvb, offset, 2, ENC_LITTLE_ENDIAN);
				num_realms = tvb_get_letohs(tvb, offset);
				offset += 2;

				for(i = 1; i <= num_realms; i++) {
					realm_name = tvb_get_ephemeral_stringz(tvb,
								     offset + 3,
								     &len);

					ti = proto_tree_add_text(wow_tree, tvb,
								 offset, 0,
								 "%s",
								 realm_name);

					wow_realms_tree = proto_item_add_subtree(ti, ett_wow_realms);
					proto_tree_add_item(wow_realms_tree, hf_wow_realm_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;

					proto_tree_add_item(wow_realms_tree, hf_wow_realm_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;

					proto_tree_add_item(wow_realms_tree, hf_wow_realm_color, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;

					proto_tree_add_string(wow_realms_tree, hf_wow_realm_name, tvb, offset, len, realm_name);
					offset += len;

					string = tvb_get_ephemeral_stringz(tvb, offset,
								 &len);
					proto_tree_add_string(wow_realms_tree, hf_wow_realm_socket, tvb, offset, len, string);
					offset += len;

					proto_tree_add_item(wow_realms_tree, hf_wow_realm_population_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
					offset += 4;

					proto_tree_add_item(wow_realms_tree, hf_wow_realm_num_characters, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;

					proto_tree_add_item(wow_realms_tree, hf_wow_realm_timezone, tvb, offset, 1, ENC_LITTLE_ENDIAN);
					offset += 1;

					offset += 1; /* Unknown field */
				}

				break;
			}
		}
	}
}


void
proto_register_wow(void)
{
	module_t *wow_module; /* For our preferences */

	static hf_register_info hf[] = {
		{ &hf_wow_command,
		  { "Command", "wow.cmd",
		    FT_UINT8, BASE_HEX, VALS(cmd_vs), 0,
		    "Type of packet", HFILL }
		},

		{ &hf_wow_error,
		  { "Error", "wow.error",
		    FT_UINT8, BASE_DEC, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_pkt_size,
		  { "Packet size", "wow.pkt_size",
		    FT_UINT16, BASE_DEC, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_gamename,
		  { "Game name", "wow.gamename",
		    FT_STRING, BASE_NONE, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_version1,
		  { "Version 1", "wow.version1",
		    FT_UINT8, BASE_DEC, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_version2,
		  { "Version 2", "wow.version2",
		    FT_UINT8, BASE_DEC, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_version3,
		  { "Version 3", "wow.version3",
		    FT_UINT8, BASE_DEC, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_build,
		  { "Build", "wow.build",
		    FT_UINT16, BASE_DEC, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_platform,
		  { "Platform", "wow.platform",
		    FT_STRING, BASE_NONE, 0, 0,
		    "CPU architecture of client system", HFILL }
		},
		{ &hf_wow_os,
		  { "Operating system", "wow.os",
		    FT_STRING, BASE_NONE, 0, 0,
		    "Operating system of client system", HFILL }
		},
		{ &hf_wow_country,
		  { "Country", "wow.country",
		    FT_STRING, BASE_NONE, 0, 0,
		    "Language and country of client system", HFILL }
		},
		{ &hf_wow_timezone_bias,
		  { "Timezone bias", "wow.timezone_bias",
		    FT_UINT32, BASE_DEC, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_ip,
		  { "IP address", "wow.ip",
		    FT_IPv4, BASE_NONE, 0, 0,
		    "Client's actual IP address", HFILL }
		},
		{ &hf_wow_srp_i_len,
		  { "SRP I length", "wow.srp.i_len",
		    FT_UINT8, BASE_DEC, 0, 0,
		    "Secure Remote Password protocol 'I' value length", HFILL }
		},
		{ &hf_wow_srp_i,
		  { "SRP I", "wow.srp.i",
		    FT_STRING, BASE_NONE, 0, 0,
		    "Secure Remote Password protocol 'I' value (username)", HFILL }
		},
		{ &hf_wow_srp_b,
		  { "SRP B", "wow.srp.b",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Secure Remote Password protocol 'B' value (one of the public ephemeral values)", HFILL }
		},
		{ &hf_wow_srp_g_len,
		  { "SRP g length", "wow.srp.g_len",
		    FT_UINT8, BASE_DEC, 0, 0,
		    "Secure Remote Password protocol 'g' value length",
		    HFILL }
		},
		{ &hf_wow_srp_g,
		  { "SRP g", "wow.srp.g",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Secure Remote Password protocol 'g' value", HFILL }
		},
		{ &hf_wow_srp_n_len,
		  { "SRP N length", "wow.srp.n_len",
		    FT_UINT8, BASE_DEC, 0, 0,
		    "Secure Remote Password protocol 'N' value length",
		    HFILL }
		},
		{ &hf_wow_srp_n,
		  { "SRP N", "wow.srp.n",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Secure Remote Password protocol 'N' value (a large safe prime)", HFILL }
		},
		{ &hf_wow_srp_s,
		  { "SRP s", "wow.srp.s",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Secure Remote Password protocol 's' (user's salt) value",
		    HFILL }
		},
		{ &hf_wow_srp_a,
		  { "SRP A", "wow.srp.a",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Secure Remote Password protocol 'A' value (one of the public ephemeral values)", HFILL }
		},
		{ &hf_wow_srp_m1,
		  { "SRP M1", "wow.srp.m1",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Secure Remote Password protocol 'M1' value", HFILL }
		},
		{ &hf_wow_crc_hash,
		  { "CRC hash", "wow.crc_hash",
		    FT_BYTES, BASE_NONE, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_num_keys,
		  { "Number of keys", "wow.num_keys",
		    FT_UINT8, BASE_DEC, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_srp_m2,
		  { "SRP M2", "wow.srp.m2",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Secure Remote Password protocol 'M2' value", HFILL }
		},
		{ &hf_wow_num_realms,
		  { "Number of realms", "wow.num_realms",
		    FT_UINT16, BASE_DEC, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_realm_type,
		  { "Type", "wow.realm_type",
		    FT_UINT8, BASE_DEC, VALS(realm_type_vs), 0,
		    "Also known as realm icon", HFILL }
		},
		{ &hf_wow_realm_status,
		  { "Status", "wow.realm_status",
		    FT_UINT8, BASE_DEC, VALS(realm_status_vs), 0,
		    NULL, HFILL }
		},
		{ &hf_wow_realm_color,
		  { "Color", "wow.realm_color",
		    FT_UINT8, BASE_DEC, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_realm_name,
		  { "Name", "wow.realm_name",
		    FT_STRINGZ, BASE_NONE, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_realm_socket,
		  { "Server socket", "wow.realm_socket",
		    FT_STRINGZ, BASE_NONE, 0, 0,
		    "IP address and port to connect to on the server to reach this realm", HFILL }
		},
		{ &hf_wow_realm_population_level,
		  { "Population level", "wow.realm_population_level",
		    FT_FLOAT, BASE_NONE, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_realm_num_characters,
		  { "Number of characters", "wow.realm_num_characters",
		    FT_UINT8, BASE_DEC, 0, 0,
		    "Number of characters the user has in this realm", HFILL }
		},
		{ &hf_wow_realm_timezone,
		  { "Timezone", "wow.realm_timezone",
		    FT_UINT8, BASE_DEC, 0, 0,
		    NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_wow,
		&ett_wow_realms
	};

	proto_wow = proto_register_protocol("World of Warcraft",
					    "WOW", "wow");

	proto_register_field_array(proto_wow, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	wow_module = prefs_register_protocol(proto_wow, NULL);

	prefs_register_bool_preference(wow_module, "desegment", "Reassemble wow messages spanning multiple TCP segments.", "Whether the wow dissector should reassemble messages spanning multiple TCP segments.  To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.", &wow_preference_desegment);

}

void
proto_reg_handoff_wow(void)
{
	dissector_handle_t wow_handle;

	wow_handle = new_create_dissector_handle(dissect_wow, proto_wow);
	dissector_add_uint("tcp.port", WOW_PORT, wow_handle);

}
