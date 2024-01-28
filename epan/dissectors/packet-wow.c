/* packet-wow.c
 * Routines for World of Warcraft (WoW) protocol dissection
 * Copyright 2008-2009, Stephen Fisher (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* This dissector is based on the MaNGOS project's source code, Stanford's
 * SRP protocol documents (http://srp.stanford.edu) and RFC 2945: "The SRP
 * Authentication and Key Exchange System." */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/charsets.h>
#include "packet-tcp.h"

void proto_register_wow(void);
void proto_reg_handoff_wow(void);

static dissector_handle_t wow_handle;

typedef enum {
	AUTH_LOGON_CHALLENGE       = 0x00,
	AUTH_LOGON_PROOF           = 0x01,
	AUTH_LOGON_RECONNECT       = 0x02,
	AUTH_LOGON_RECONNECT_PROOF = 0x03,
	REALM_LIST                 = 0x10,
	XFER_INITIATE              = 0x30,
	XFER_DATA                  = 0x31,
	XFER_ACCEPT                = 0x32,
	XFER_RESUME                = 0x33,
	XFER_CANCEL                = 0x34
} auth_cmd_e;

static const value_string cmd_vs[] = {
	{ AUTH_LOGON_CHALLENGE,       "Authentication Logon Challenge"     },
	{ AUTH_LOGON_PROOF,           "Authentication Logon Proof"         },
	{ AUTH_LOGON_RECONNECT,       "Authentication Reconnect Challenge" },
	{ AUTH_LOGON_RECONNECT_PROOF, "Authentication Reconnect Proof"     },
	{ REALM_LIST,                 "Realm List"                         },
	{ XFER_INITIATE,              "Transfer Initiate"                  },
	{ XFER_DATA,                  "Transfer Data"                      },
	{ XFER_ACCEPT,                "Transfer Accept"                    },
	{ XFER_RESUME,                "Transfer Resume"                    },
	{ XFER_CANCEL,                "Transfer Cancel"                    },
	{ 0, NULL                                                          }
};

typedef enum {
	SUCCESS                 = 0x00,
	FAIL_UNKNOWN0           = 0x01,
	FAIL_UNKNOWN1           = 0x02,
	FAIL_BANNED             = 0x03,
	FAIL_UNKNOWN_ACCOUNT    = 0x04,
	FAIL_INCORRECT_PASSWORD = 0x05,
	FAIL_ALREADY_ONLINE     = 0x06,
	FAIL_NO_TIME            = 0x07,
	FAIL_DB_BUSY            = 0x08,
	FAIL_VERSION_INVALID    = 0x09,
	FAIL_VERSION_UPDATE     = 0x0A,
	FAIL_INVALID_SERVER     = 0x0B,
	FAIL_SUSPENDED          = 0x0C,
	FAIL_NOACCESS           = 0x0D,
	SUCCESS_SURVEY          = 0x0E,
	FAIL_PARENTAL_CONTROL   = 0x0F
} auth_error_e;

static const value_string error_vs[] = {
	{ SUCCESS,                 "Success" },
	{ FAIL_UNKNOWN0,           "Unknown" },
	{ FAIL_UNKNOWN1,           "Unknown" },
	{ FAIL_BANNED,             "Account banned" },
	{ FAIL_UNKNOWN_ACCOUNT,    "Unknown account" },
	{ FAIL_INCORRECT_PASSWORD, "Incorrect password" },
	{ FAIL_ALREADY_ONLINE,     "Already online" },
	{ FAIL_NO_TIME,            "No game time on account" },
	{ FAIL_DB_BUSY,            "Database busy (could not log in)" },
	{ FAIL_VERSION_INVALID,    "Invalid game version" },
	{ FAIL_VERSION_UPDATE,     "Failed version update" },
	{ FAIL_INVALID_SERVER,     "Invalid server" },
	{ FAIL_SUSPENDED,          "Account suspended" },
	{ FAIL_NOACCESS,           "Unable to connect" },
	{ SUCCESS_SURVEY,          "Survey success" },
	{ FAIL_PARENTAL_CONTROL,   "Blocked by parental controls" },
	{ 0, NULL }
};

typedef enum {
    FLAG_NONE = 0x0,
    FLAG_INVALID = 0x1,
    FLAG_OFFLINE = 0x2,
    FLAG_SPECIFY_BUILD = 0x4,
    FLAG_UNK1 = 0x8,
    FLAG_UNK2 = 0x10,
    FLAG_FORCE_RECOMMENDED = 0x20,
    FLAG_FORCE_NEW_PLAYERS = 0x40,
    FLAG_FORCE_FULL = 0x80
} auth_realm_flag_e;

static const value_string realm_flags_vs[] = {
	{ FLAG_NONE, ""  },
	{ FLAG_INVALID, "Locked"  },
	{ FLAG_OFFLINE, "Offline" },
	{ FLAG_SPECIFY_BUILD, "Realm version info appended" },
	{ FLAG_UNK1, "Unknown" },
	{ FLAG_UNK2, "Unknown" },
	{ FLAG_FORCE_RECOMMENDED, "Realm status is 'Recommended' in blue text" },
	{ FLAG_FORCE_NEW_PLAYERS, "Realm status is 'Recommended' in green text" },
	{ FLAG_FORCE_FULL, "Realm status is 'Full' in red text" },
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
static int proto_wow;

/* More than 1 packet */
static int hf_wow_command;
static int hf_wow_error;
static int hf_wow_protocol_version;
static int hf_wow_pkt_size;
static int hf_wow_two_factor_pin_salt;
static int hf_wow_num_keys;
static int hf_wow_two_factor_enabled;
static int hf_wow_challenge_data;

/* Logon Challenge Client to Server */
static int hf_wow_gamename;
static int hf_wow_version1;
static int hf_wow_version2;
static int hf_wow_version3;
static int hf_wow_build;
static int hf_wow_platform;
static int hf_wow_os;
static int hf_wow_country;
static int hf_wow_timezone_bias;
static int hf_wow_ip;
static int hf_wow_srp_i_len;
static int hf_wow_srp_i;

/* Logon Challenge Server to Client */
static int hf_wow_srp_b;
static int hf_wow_srp_g_len;
static int hf_wow_srp_g;
static int hf_wow_srp_n_len;
static int hf_wow_srp_n;
static int hf_wow_srp_s;
static int hf_wow_crc_salt;
static int hf_wow_two_factor_pin_grid_seed;

/* Logon Proof Client to Server */
static int hf_wow_srp_a;
static int hf_wow_srp_m1;
static int hf_wow_crc_hash;
static int hf_wow_two_factor_pin_hash;

/* Logon Proof Server to Client */
static int hf_wow_srp_m2;
static int hf_wow_hardware_survey_id;
static int hf_wow_account_flags;
static int hf_wow_unknown_flags;

/* Reconnect Challenge Server to Client */
static int hf_wow_checksum_salt;

/* Reconnect Proof Client to Server */
static int hf_wow_client_proof;
static int hf_wow_client_checksum;

/* Realm List Server to Client */
static int hf_wow_num_realms;
static int hf_wow_realm_type;
static int hf_wow_realm_locked;
static int hf_wow_realm_flags;
static int hf_wow_realm_category;
static int hf_wow_realm_name;
static int hf_wow_realm_socket;
static int hf_wow_realm_population_level;
static int hf_wow_realm_num_characters;
static int hf_wow_realm_id;

static gboolean wow_preference_desegment = TRUE;

static gint ett_wow;
static gint ett_wow_realms;

struct game_version {
	gint8 major_version;
	gint8 minor_version;
	gint8 patch_version;
	gint16 revision;
};
static struct game_version client_game_version = { -1, -1, -1, -1 };

// WoW uses a kind of SemVer.
// So 1.0.0 is always greater than any 0.x.y, and
// 1.2.0 is always greater than any 1.1.y
static gboolean
version_is_at_or_above(int major, int minor, int patch)
{
	if (client_game_version.major_version > major) {
		return TRUE;
	}
	else if (client_game_version.major_version < major) {
		return FALSE;
	}
	// Major versions must be equal

	if (client_game_version.minor_version > minor) {
		return TRUE;
	}
	else if (client_game_version.minor_version < minor) {
		return FALSE;
	}
	// Both major and minor versions are equal

	if (client_game_version.patch_version > patch) {
		return TRUE;
	}
	else if (client_game_version.patch_version < patch) {
		return FALSE;
	}
	// All versions are identical

	return TRUE;
}
static void
parse_logon_proof_client_to_server(tvbuff_t *tvb, proto_tree *wow_tree, guint32 offset) {
	guint8 two_factor_enabled;

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

	if (!version_is_at_or_above(1, 12, 0)) {
		return;
	}
	two_factor_enabled = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(wow_tree, hf_wow_two_factor_enabled, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	if (!two_factor_enabled) {
		return;
	}

	proto_tree_add_item(wow_tree, hf_wow_two_factor_pin_salt, tvb,
			    offset, 16, ENC_NA);
	offset += 16;

	proto_tree_add_item(wow_tree, hf_wow_two_factor_pin_hash, tvb,
			    offset, 20, ENC_NA);


}


static void
parse_logon_proof_server_to_client(tvbuff_t *tvb, proto_tree *wow_tree, guint32 offset) {
	guint8 error;

	error = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(wow_tree, hf_wow_error, tvb,
			    offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	if (error != SUCCESS) {
		// Following fields are only present when not an error.
		return;
	}

	proto_tree_add_item(wow_tree, hf_wow_srp_m2,
			    tvb, offset, 20, ENC_NA);
	offset += 20;

	if (version_is_at_or_above(2, 4, 0)) {
		proto_tree_add_item(wow_tree, hf_wow_account_flags,
				    tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
	}

	proto_tree_add_item(wow_tree, hf_wow_hardware_survey_id,
			    tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	if (version_is_at_or_above(2, 0, 3)) {
		proto_tree_add_item(wow_tree, hf_wow_unknown_flags,
				    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	}
}
static void
parse_realm_list_server_to_client(packet_info *pinfo, tvbuff_t *tvb, proto_tree *wow_tree, guint32 offset) {
	guint8 num_realms, ii, number_of_realms_field_size, realm_name_offset, realm_type_field_size, realm_flags;
	gchar *string, *realm_name;
	gint len;
	proto_tree *wow_realms_tree;

	proto_tree_add_item(wow_tree, hf_wow_pkt_size,
			    tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	offset += 4; /* Unknown field; always 0 */

	if (version_is_at_or_above(2, 4, 3)) {
		/* Possibly valid for versions starting at 2.0.0 as well */
		number_of_realms_field_size = 2;
		realm_name_offset = 3;
		realm_type_field_size = 1;
	} else {
		number_of_realms_field_size = 1;
		realm_name_offset = 5;
		realm_type_field_size = 4;
	}

	proto_tree_add_item(wow_tree, hf_wow_num_realms,
			    tvb, offset, number_of_realms_field_size, ENC_LITTLE_ENDIAN);
	num_realms = tvb_get_guint8(tvb, offset);
	offset += number_of_realms_field_size;

	for(ii = 0; ii < num_realms; ii++) {
		realm_name = tvb_get_stringz_enc(pinfo->pool, tvb,
						 offset + realm_name_offset,
						 &len, ENC_UTF_8);

		wow_realms_tree = proto_tree_add_subtree(wow_tree, tvb,
							 offset, 0,
							 ett_wow_realms, NULL,
							 realm_name);

		proto_tree_add_item(wow_realms_tree, hf_wow_realm_type, tvb, offset, realm_type_field_size, ENC_LITTLE_ENDIAN);
		offset += realm_type_field_size;

		if (version_is_at_or_above(2, 4, 3)) {
			/* Possibly valid for versions starting at 2.0.0 as well */
			proto_tree_add_item(wow_realms_tree, hf_wow_realm_locked, tvb, offset, 1, ENC_NA);
			offset += 1;
		}

		realm_flags = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(wow_realms_tree, hf_wow_realm_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_string(wow_realms_tree, hf_wow_realm_name, tvb, offset, len, realm_name);
		offset += len;

		string = tvb_get_stringz_enc(pinfo->pool, tvb, offset,
					     &len, ENC_UTF_8);
		proto_tree_add_string(wow_realms_tree, hf_wow_realm_socket, tvb, offset, len, string);
		offset += len;

		proto_tree_add_item(wow_realms_tree, hf_wow_realm_population_level, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(wow_realms_tree, hf_wow_realm_num_characters, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(wow_realms_tree, hf_wow_realm_category, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		proto_tree_add_item(wow_realms_tree, hf_wow_realm_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;

		if (version_is_at_or_above(2, 4, 3) && (realm_flags & FLAG_SPECIFY_BUILD)) {
			proto_tree_add_item(wow_realms_tree, hf_wow_version1,
					    tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			proto_tree_add_item(wow_realms_tree, hf_wow_version2,
					    tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			proto_tree_add_item(wow_realms_tree, hf_wow_version3,
					    tvb, offset, 1, ENC_LITTLE_ENDIAN);
			offset += 1;

			proto_tree_add_item(wow_realms_tree, hf_wow_build, tvb,
					    offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
		}
	}
}

static void
parse_logon_reconnect_proof(tvbuff_t *tvb, packet_info *pinfo, proto_tree *wow_tree, guint32 offset) {
	if (WOW_CLIENT_TO_SERVER) {
		proto_tree_add_item(wow_tree, hf_wow_challenge_data, tvb,
				offset, 16, ENC_NA);
		offset += 16;

		proto_tree_add_item(wow_tree, hf_wow_client_proof, tvb,
				offset, 20, ENC_NA);
		offset += 20;

		proto_tree_add_item(wow_tree, hf_wow_client_checksum, tvb,
				offset, 20, ENC_NA);
		offset += 20;

		proto_tree_add_item(wow_tree, hf_wow_num_keys,
				tvb, offset, 1, ENC_LITTLE_ENDIAN);

	}
	else if (WOW_SERVER_TO_CLIENT) {
		proto_tree_add_item(wow_tree, hf_wow_error, tvb,
				offset, 1, ENC_LITTLE_ENDIAN);

	}

}

static void
parse_logon_reconnect_challenge_server_to_client(tvbuff_t *tvb, proto_tree *wow_tree, guint32 offset) {
	guint8 error = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(wow_tree, hf_wow_error, tvb,
			offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	if (error != SUCCESS) {
		// Following fields are only present when not an error.
		return;
	}

	proto_tree_add_item(wow_tree, hf_wow_challenge_data, tvb,
			offset, 16, ENC_NA);
	offset += 16;

	proto_tree_add_item(wow_tree, hf_wow_checksum_salt, tvb,
			offset, 16, ENC_NA);
}

static void
parse_logon_challenge_client_to_server(packet_info *pinfo, tvbuff_t *tvb, proto_tree *wow_tree, guint32 offset) {
	guint8 srp_i_len;
	gchar *string;

	proto_tree_add_item(wow_tree, hf_wow_protocol_version, tvb,
			offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(wow_tree, hf_wow_pkt_size,
			tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	string = tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII);
	/* g_utf8_strreverse handles the REPLACMENT CHARACTERs.
	 * It would handle embedded NULs correctly if we passed in the
	 * byte length after conversion, but we need to change the API
	 * to use counted strings in more places.
	 */
	string = g_utf8_strreverse(string, -1);
	proto_tree_add_string(wow_tree, hf_wow_gamename,
			tvb, offset, 4, string);
	g_free(string);
	offset += 4;


	client_game_version.major_version = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(wow_tree, hf_wow_version1,
			tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	client_game_version.minor_version = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(wow_tree, hf_wow_version2,
			tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	client_game_version.patch_version = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(wow_tree, hf_wow_version3,
			tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	client_game_version.revision = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(wow_tree, hf_wow_build, tvb,
			offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	string = tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII);
	string = g_utf8_strreverse(string, -1);
	proto_tree_add_string(wow_tree, hf_wow_platform,
			tvb, offset, 4, string);
	g_free(string);
	offset += 4;

	string = tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII);
	string = g_utf8_strreverse(string, -1);
	proto_tree_add_string(wow_tree, hf_wow_os, tvb,
			offset, 4, string);
	g_free(string);
	offset += 4;

	string = tvb_get_string_enc(pinfo->pool, tvb, offset, 4, ENC_ASCII);
	string = g_utf8_strreverse(string, -1);
	proto_tree_add_string(wow_tree, hf_wow_country,
			tvb, offset, 4, string);
	g_free(string);
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
			ENC_UTF_8);
}

static void
parse_logon_challenge_server_to_client(tvbuff_t *tvb, proto_tree *wow_tree, guint32 offset) {
    guint8 error, srp_g_len, srp_n_len, two_factor_enabled;

	proto_tree_add_item(wow_tree, hf_wow_protocol_version, tvb,
			offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	error = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(wow_tree, hf_wow_error, tvb,
			offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;
	if (error != SUCCESS) {
		// Following fields are only present when not an error.
		return;
	}

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

	proto_tree_add_item(wow_tree, hf_wow_crc_salt, tvb,
			offset, 16, ENC_NA);
	offset += 16;

	if (!version_is_at_or_above(1, 12, 0)) {
		/* The two factor fields were added in the 1.12 update. */
		return;
	}
	two_factor_enabled = tvb_get_guint8(tvb, offset);
	proto_tree_add_item(wow_tree, hf_wow_two_factor_enabled, tvb,
			offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	if (!two_factor_enabled) {
		return;
	}
	proto_tree_add_item(wow_tree, hf_wow_two_factor_pin_grid_seed, tvb,
			offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(wow_tree, hf_wow_two_factor_pin_salt, tvb,
			offset, 16, ENC_NA);

}

static guint
get_wow_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset, void *data _U_)
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

static int
dissect_wow_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *wow_tree;

	guint8 cmd;
	guint32 offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "WOW");

	col_clear(pinfo->cinfo, COL_INFO);

	cmd = tvb_get_guint8(tvb, offset);

	col_set_str(pinfo->cinfo, COL_INFO,
			    val_to_str_const(cmd, cmd_vs,
				       "Unrecognized packet type"));

	if(!tree) {
		return tvb_captured_length(tvb);
	}

	ti = proto_tree_add_item(tree, proto_wow, tvb, 0, -1, ENC_NA);
	wow_tree = proto_item_add_subtree(ti, ett_wow);

	proto_tree_add_item(wow_tree, hf_wow_command, tvb, offset, 1,
			ENC_LITTLE_ENDIAN);
	offset += 1;

	switch(cmd) {

		case AUTH_LOGON_RECONNECT_PROOF:
			parse_logon_reconnect_proof(tvb, pinfo, wow_tree, offset);

			break;

		case AUTH_LOGON_RECONNECT:
			if (WOW_SERVER_TO_CLIENT) {
				parse_logon_reconnect_challenge_server_to_client(tvb, wow_tree, offset);
			} else if (WOW_CLIENT_TO_SERVER) {
				parse_logon_challenge_client_to_server(pinfo, tvb, wow_tree, offset);
			}

			break;

		case AUTH_LOGON_CHALLENGE :
			if(WOW_CLIENT_TO_SERVER) {
				parse_logon_challenge_client_to_server(pinfo, tvb, wow_tree, offset);
			} else if(WOW_SERVER_TO_CLIENT) {
				parse_logon_challenge_server_to_client(tvb, wow_tree, offset);
			}

			break;

		case AUTH_LOGON_PROOF :
			if (WOW_CLIENT_TO_SERVER) {
				parse_logon_proof_client_to_server(tvb, wow_tree, offset);
			} else if (WOW_SERVER_TO_CLIENT) {
				parse_logon_proof_server_to_client(tvb, wow_tree, offset);
			}

			break;

		case REALM_LIST :
			if(WOW_CLIENT_TO_SERVER) {

			} else if(WOW_SERVER_TO_CLIENT) {
				parse_realm_list_server_to_client(pinfo, tvb, wow_tree, offset);

			}

			break;
	}

	return tvb_captured_length(tvb);
}


static gboolean
dissect_wow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
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
				 dissect_wow_pdu, data);

	} else {
		/* Doesn't have a size field, so it cannot span multiple
		   segments.  Therefore, dissect this packet normally. */
		dissect_wow_pdu(tvb, pinfo, tree, data);
	}

	return TRUE;
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
		{ &hf_wow_protocol_version,
		  { "Protocol version", "wow.protocol_version",
		    FT_UINT8, BASE_DEC, 0, 0,
		    "Version of packet", HFILL }
		},
		{ &hf_wow_error,
		  { "Error", "wow.error",
		    FT_UINT8, BASE_HEX, VALS(error_vs), 0,
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
		{ &hf_wow_crc_salt,
		  { "CRC salt", "wow.crc_salt",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Salt to be used for the hash in the reply packet",
		    HFILL }
		},
		{ &hf_wow_two_factor_enabled,
		  { "Two factor enabled", "wow.two_factor_enabled",
		    FT_BOOLEAN, BASE_NONE, 0, 0,
		    "Enables two factor authentication",
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
		{ &hf_wow_hardware_survey_id,
		  { "Hardware Survey ID", "wow.hardware_survey_id",
		    FT_UINT32, BASE_DEC, 0, 0,
		    "ID of a hardware survey that the client should run", HFILL }
		},
		{ &hf_wow_account_flags,
			{ "Account Flags", "wow.account_flags",
				FT_UINT32, BASE_HEX, 0, 0,
				NULL, HFILL }
		},
		{ &hf_wow_unknown_flags,
			{ "Unknown Flags", "wow.unknown_flags",
				FT_UINT16, BASE_HEX, 0, 0,
				NULL, HFILL }
		},
		{ &hf_wow_srp_m2,
		  { "SRP M2", "wow.srp.m2",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Secure Remote Password protocol 'M2' value", HFILL }
		},
		{ &hf_wow_challenge_data,
		  { "Reconnection Challenge Data", "wow.reconnect_challenge_data",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Random data used for reconnection calculation", HFILL }
		},
		{ &hf_wow_checksum_salt,
		  { "Reconnection Checksum Salt", "wow.reconnect_checksum_salt",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Unknown. Unused in 1.12", HFILL }
		},
		{ &hf_wow_client_proof,
		  { "Reconnection Client Proof", "wow.reconnect_proof",
		    FT_BYTES, BASE_NONE, 0, 0,
		    "Client proof of knowing session key based on challenge data", HFILL }
		},
		{ &hf_wow_client_checksum,
		  { "Reconnection Checksum", "wow.reconnect_checksum",
		    FT_BYTES, BASE_NONE, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_two_factor_pin_grid_seed,
		  { "Two Factor PIN Grid Seed", "wow.two_factor_pin_grid_seed",
		    FT_UINT32, BASE_HEX, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_two_factor_pin_salt,
		  { "Two Factor PIN Salt", "wow.two_factor_pin_salt",
		    FT_BYTES, BASE_NONE, 0, 0,
		    NULL, HFILL }
		},
		{ &hf_wow_two_factor_pin_hash,
		  { "Two Factor PIN Hash", "wow.two_factor_pin_hash",
		    FT_BYTES, BASE_NONE, 0, 0,
		    NULL, HFILL }
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
		{ &hf_wow_realm_locked,
			{ "Locked", "wow.realm_locked",
		    FT_BOOLEAN, BASE_NONE, 0, 0,
		    "Realm appears as locked in client", HFILL }
		},
		{ &hf_wow_realm_flags,
		  { "Flags", "wow.realm_flags",
		    FT_UINT8, BASE_DEC, VALS(realm_flags_vs), 0,
		    NULL, HFILL }
		},
		{ &hf_wow_realm_category,
		  { "Category", "wow.realm_category",
		    FT_UINT8, BASE_DEC, 0, 0,
		    "Language category the realm should be shown in", HFILL }
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
		{ &hf_wow_realm_id,
		  { "Realm id", "wow.realm_id",
		    FT_UINT8, BASE_DEC, 0, 0,
		    "Used for initial sorting the in client menu", HFILL }
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

	wow_handle = register_dissector("wow", dissect_wow, proto_wow);

	wow_module = prefs_register_protocol(proto_wow, NULL);

	prefs_register_bool_preference(wow_module, "desegment", "Reassemble wow messages spanning multiple TCP segments.", "Whether the wow dissector should reassemble messages spanning multiple TCP segments.  To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.", &wow_preference_desegment);

}

void
proto_reg_handoff_wow(void)
{
	dissector_add_uint_with_preference("tcp.port", WOW_PORT, wow_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
