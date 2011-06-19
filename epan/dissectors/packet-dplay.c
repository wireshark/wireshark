/* packet-dplay.c
 * This is a dissector for the DirectPlay protocol.
 * Copyright 2006 - 2008 by Kai Blin
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
 * USA.59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/aftypes.h>
#include <string.h>

/* function declarations */
static gboolean heur_dissect_dplay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void dissect_dplay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gint dissect_type1a_message(proto_tree *tree, tvbuff_t *tvb, gint offset);

static int proto_dplay = -1;

/* Common data fields */
static int hf_dplay_size = -1;              /* Size of the whole data */
static int hf_dplay_token = -1;
static int hf_dplay_saddr_af = -1;          /* WINSOCK_AF_INET, as this dissector does not handle IPX yet */
static int hf_dplay_saddr_port = -1;        /* port to use for the reply to this packet */
static int hf_dplay_saddr_ip = -1;          /* IP to use for the reply to this packet, or 0.0.0.0,
                                               then use the same IP as this packet used. */
static int hf_dplay_saddr_padding = -1;     /* null padding used in s_addr_in structures */
static int hf_dplay_play_str = -1;          /* always "play" without a null terminator */
static int hf_dplay_command = -1;           /* the dplay command this message contains*/
static int hf_dplay_proto_dialect = -1;     /* 0x0b00 for dplay7, 0x0e00 for dplay9 */
static int hf_dplay_play_str_2 = -1;        /* packet type 0x0015 encapsulates another packet */
static int hf_dplay_command_2 = -1;         /* that also has a "play" string, a command and a */
static int hf_dplay_proto_dialect_2 = -1;   /* protocol dialect, same as above */
static const int DPLAY_HEADER_OFFSET = 28;  /* The dplay header is 28 bytes in size */
static int hf_dplay_player_msg = -1;

/* The following fields are not part of the header, but hopefully have the same
 * meaning for all packets they show up in. */

static int hf_dplay_sess_desc_flags = -1; /* This is a 32bit field with some sort of a flag */
static int hf_dplay_flags_no_create_players = -1;
static int hf_dplay_flags_0002 = -1;
static int hf_dplay_flags_migrate_host = -1;
static int hf_dplay_flags_short_player_msg = -1;
static int hf_dplay_flags_ignored = -1;
static int hf_dplay_flags_can_join = -1;
static int hf_dplay_flags_use_ping = -1;
static int hf_dplay_flags_no_player_updates = -1;
static int hf_dplay_flags_use_auth = -1;
static int hf_dplay_flags_private_session = -1;
static int hf_dplay_flags_password_req = -1;
static int hf_dplay_flags_route = -1;
static int hf_dplay_flags_server_player_only = -1;
static int hf_dplay_flags_reliable = -1;
static int hf_dplay_flags_preserve_order = -1;
static int hf_dplay_flags_optimize_latency = -1;
static int hf_dplay_flags_acqire_voice = -1;
static int hf_dplay_flags_no_sess_desc_changes = -1;

#define DPLAY_FLAG_NO_CREATE_PLAYERS 0x0001
#define DPLAY_FLAG_0002 0x0002
#define DPLAY_FLAG_MIGRATE_HOST 0x0004
#define DPLAY_FLAG_SHORT_PLAYER_MSG 0x0008
#define DPLAY_FLAG_IGNORED 0x0010
#define DPLAY_FLAG_CAN_JOIN 0x0020
#define DPLAY_FLAG_USE_PING 0x0040
#define DPLAY_FLAG_NO_P_UPD 0x0080
#define DPLAY_FLAG_USE_AUTH 0x0100
#define DPLAY_FLAG_PRIV_SESS 0x0200
#define DPLAY_FLAG_PASS_REQ 0x0400
#define DPLAY_FLAG_ROUTE 0x0800
#define DPLAY_FLAG_SRV_ONLY 0x1000
#define DPLAY_FLAG_RELIABLE 0x2000
#define DPLAY_FLAG_ORDER 0x4000
#define DPLAY_FLAG_OPT_LAT 0x8000
#define DPLAY_FLAG_ACQ_VOICE 0x10000
#define DPLAY_FLAG_NO_SESS_DESC_CHANGES 0x20000

/* Session description structure fields */
static int hf_dplay_sess_desc_length = -1;
static int hf_dplay_game_guid = -1;
static int hf_dplay_instance_guid = -1;
static int hf_dplay_max_players = -1;
static int hf_dplay_curr_players = -1;
static int hf_dplay_sess_name_ptr = -1;
static int hf_dplay_passwd_ptr = -1;
static int hf_dplay_sess_desc_reserved_1 = -1;
static int hf_dplay_sess_desc_reserved_2 = -1;
static int hf_dplay_sess_desc_user_1 = -1;
static int hf_dplay_sess_desc_user_2 = -1;
static int hf_dplay_sess_desc_user_3 = -1;
static int hf_dplay_sess_desc_user_4 = -1;

/* PackedPlayer structure fields */
static int hf_dplay_pp_size = -1;
static int hf_dplay_pp_flags = -1;
static int hf_dplay_pp_flag_sysplayer = -1;
static int hf_dplay_pp_flag_nameserver = -1;
static int hf_dplay_pp_flag_in_group = -1;
static int hf_dplay_pp_flag_sending = -1;
static int hf_dplay_pp_id = -1;
static int hf_dplay_pp_short_name_len = -1;
static int hf_dplay_pp_long_name_len = -1;
static int hf_dplay_pp_sp_data_size = -1;
static int hf_dplay_pp_player_data_size = -1;
static int hf_dplay_pp_num_players = -1;
static int hf_dplay_pp_system_player = -1;
static int hf_dplay_pp_fixed_size = -1;
static int hf_dplay_pp_dialect = -1;
static int hf_dplay_pp_unknown_1 = -1;
static int hf_dplay_pp_short_name = -1;
static int hf_dplay_pp_long_name = -1;
static int hf_dplay_pp_sp_data = -1;
static int hf_dplay_pp_player_data = -1;
static int hf_dplay_pp_player_id = -1;
static int hf_dplay_pp_parent_id = -1;
#define DPLAY_PP_FLAG_SYSPLAYER 0x01
#define DPLAY_PP_FLAG_NAMESERVER 0x02
#define DPLAY_PP_FLAG_IN_GROUP 0x04
#define DPLAY_PP_FLAG_SENDING 0x08

/* SuperPackedPlayer structure fields */
static int hf_dplay_spp_size = -1;
static int hf_dplay_spp_flags = -1;
static int hf_dplay_spp_flags_sysplayer = -1;
static int hf_dplay_spp_flags_nameserver = -1;
static int hf_dplay_spp_flags_in_group = -1;
static int hf_dplay_spp_flags_sending = -1;
static int hf_dplay_spp_id = -1;
static int hf_dplay_spp_player_info_mask = -1;
static int hf_dplay_spp_have_short_name = -1;
static int hf_dplay_spp_have_long_name = -1;
static int hf_dplay_spp_sp_length_type = -1;
static int hf_dplay_spp_pd_length_type = -1;
static int hf_dplay_spp_player_count_type = -1;
static int hf_dplay_spp_have_parent_id = -1;
static int hf_dplay_spp_shortcut_count_type = -1;
static int hf_dplay_spp_dialect = -1;
static int hf_dplay_spp_sys_player_id = -1;
static int hf_dplay_spp_short_name = -1;
static int hf_dplay_spp_long_name = -1;
static int hf_dplay_spp_player_data_length = -1;
static int hf_dplay_spp_player_data = -1;
static int hf_dplay_spp_sp_data_length = -1;
static int hf_dplay_spp_sp_data = -1;
static int hf_dplay_spp_player_count = -1;
static int hf_dplay_spp_player_id = -1;
static int hf_dplay_spp_parent_id = -1;
static int hf_dplay_spp_shortcut_count = -1;
static int hf_dplay_spp_shortcut_id = -1;
#define DPLAY_SPP_FLAG_SYSPLAYER 0x01
#define DPLAY_SPP_FLAG_NAMESERVER 0x02
#define DPLAY_SPP_FLAG_IN_GROUP 0x04
#define DPLAY_SPP_FLAG_SENDING 0x08

/* SecurityDesc structure fields */
static int hf_dplay_sd_size = -1;
static int hf_dplay_sd_flags = -1;
static int hf_dplay_sd_sspi = -1;
static int hf_dplay_sd_capi = -1;
static int hf_dplay_sd_capi_type = -1;
static int hf_dplay_sd_enc_alg = -1;

/* Message Type 0x0001 data fields */
static int hf_dplay_type_01_name_offset = -1;
static int hf_dplay_type_01_game_name = -1;

/* Message Type 0x0002 data fields */
static int hf_dplay_type_02_game_guid = -1;
static int hf_dplay_type_02_password_offset = -1;
static int hf_dplay_type_02_flags = -1;
static int hf_dplay_type_02_password = -1;
static int hf_enum_sess_flag_join = -1;
static int hf_enum_sess_flag_all = -1;
static int hf_enum_sess_flag_passwd = -1;
#define DPLAY_ENUM_SESS_FLAG_JOIN 0x0001
#define DPLAY_ENUM_SESS_FLAG_ALL 0x0002
#define DPLAY_ENUM_SESS_FLAG_PASSWD 0x0040

/* Message Type 0x0005 data fields */
static int hf_dplay_type_05_flags = -1;
static int hf_dplay_type_05_system_player = -1;
static int hf_dplay_type_05_name_server = -1;
static int hf_dplay_type_05_local = -1;
static int hf_dplay_type_05_unknown = -1; /* unknown, but always set */
static int hf_dplay_type_05_secure = -1;
#define DPLAY_TYPE05_FLAG_SYSPLAYER 0x001
#define DPLAY_TYPE05_FLAG_NAMESERVER 0x002
#define DPLAY_TYPE05_FLAG_LOCAL 0x004
#define DPLAY_TYPE05_FLAG_UNKNOWN 0x008
#define DPLAY_TYPE05_FLAG_SECURE 0x200

/* Message Type 0x0007 data fields */
static int hf_dplay_type_07_dpid = -1;
static int hf_dplay_type_07_sspi_offset = -1;
static int hf_dplay_type_07_capi_offset = -1;
static int hf_dplay_type_07_hresult = -1;
static int hf_dplay_type_07_sspi = -1;
static int hf_dplay_type_07_capi = -1;

/* Data fields for message types 0x08, 0x09, 0x0b, 0x0c, 0x0d, 0x0e */
static int hf_dplay_multi_id_to = -1;
static int hf_dplay_multi_player_id = -1;
static int hf_dplay_multi_group_id = -1;
static int hf_dplay_multi_create_offset = -1;
static int hf_dplay_multi_password_offset = -1;
static int hf_dplay_multi_password = -1;

/* Message Type 0x000f data fields */
static int hf_dplay_type_0f_id_to = -1;
static int hf_dplay_type_0f_id = -1;
static int hf_dplay_type_0f_data_size = -1;
static int hf_dplay_type_0f_data_offset = -1;
static int hf_dplay_type_0f_data = -1;

/* Message Type 0x0013 data fields */
static int hf_dplay_type_13_id_to = -1;
static int hf_dplay_type_13_player_id = -1;
static int hf_dplay_type_13_group_id = -1;
static int hf_dplay_type_13_create_offset = -1;
static int hf_dplay_type_13_password_offset = -1;
static int hf_dplay_type_13_password = -1;
static int hf_dplay_type_13_tick_count = -1;

/* Message Type 0x0015 data fields */
static int hf_dplay_message_guid = -1;
static int hf_dplay_type_15_packet_idx = -1;
static int hf_dplay_type_15_data_size = -1;
static int hf_dplay_type_15_offset = -1;
static int hf_dplay_type_15_total_packets = -1;
static int hf_dplay_type_15_msg_size = -1;
static int hf_dplay_type_15_packet_offset = -1;

/* Message Type 0x0016 and 0x0017 data fields */
static int hf_dplay_ping_id_from = -1;
static int hf_dplay_ping_tick_count = -1;

/* Message Type 0x001a data fields */
static int hf_dplay_type_1a_id_to = -1;
static int hf_dplay_type_1a_sess_name_ofs = -1;
static int hf_dplay_type_1a_password_ofs = -1;
static int hf_dplay_type_1a_session_name = -1;
static int hf_dplay_type_1a_password = -1;

/* Message Type 0x0029 data fields */
static int hf_dplay_type_29_player_count = -1;
static int hf_dplay_type_29_group_count = -1;
static int hf_dplay_type_29_packed_offset = -1;
static int hf_dplay_type_29_shortcut_count = -1;
static int hf_dplay_type_29_description_offset = -1;
static int hf_dplay_type_29_name_offset = -1;
static int hf_dplay_type_29_password_offset = -1;
static int hf_dplay_type_29_game_name = -1;
static int hf_dplay_type_29_password = -1;

/* Message Type 0x002f data fields */
static int hf_dplay_type_2f_dpid = -1;

/* various */
static gint ett_dplay = -1;
static gint ett_dplay_header = -1;
static gint ett_dplay_sockaddr = -1;
static gint ett_dplay_data = -1;
static gint ett_dplay_enc_packet = -1;
static gint ett_dplay_flags = -1;
static gint ett_dplay_sess_desc_flags = -1;
static gint ett_dplay_pp_flags = -1;
static gint ett_dplay_spp_flags = -1;
static gint ett_dplay_spp_info_mask = -1;
static gint ett_dplay_type02_flags = -1;
static gint ett_dplay_type05_flags = -1;
static gint ett_dplay_type29_spp = -1;

static const value_string dplay_command_val[] = {
    { 0x0001, "Enum Sessions Reply" },
    { 0x0002, "Enum Sessions" },
    { 0x0003, "Enum Players Reply" },
    { 0x0004, "Enum Players" },
    { 0x0005, "Request Player ID" },
    { 0x0006, "Request Group ID" },
    { 0x0007, "Request Player Reply" },
    { 0x0008, "Create Player" },
    { 0x0009, "Create Group" },
    { 0x000a, "Player Message" },
    { 0x000b, "Delete Player" },
    { 0x000c, "Delete Group" },
    { 0x000d, "Add Player To Group" },
    { 0x000e, "Delete Player From Group" },
    { 0x000f, "Player Data Changed" },
    { 0x0010, "Player Name Changed" },
    { 0x0011, "Group Data Changed" },
    { 0x0012, "Group Name Changed" },
    { 0x0013, "Add Forward Request" },
    /* There is no command 0x0014 */
    { 0x0015, "Packet" },
    { 0x0016, "Ping" },
    { 0x0017, "Pong" },
    { 0x0018, "You Are Dead" },
    { 0x0019, "Player Wrapper" },
    { 0x001a, "Session Desc Changed" },
    { 0x001c, "Challenge" },
    { 0x001d, "Access Granted" },
    { 0x001e, "Logon Denied" },
    { 0x001f, "Auth Error" },
    { 0x0020, "Negotiate" },
    { 0x0021, "Challenge Response" },
    { 0x0022, "Signed"},
    /* There is no command 0x0023 */
    { 0x0024, "Add Forward Reply" },
    { 0x0025, "Ask For Multicast" },
    { 0x0026, "Ask For Multicast Guaranteed" },
    { 0x0027, "Add Shortcut To Group" },
    { 0x0028, "Delete Group From Group" },
    { 0x0029, "Super Enum Players Reply" },
    /* There is no command 0x002a */
    { 0x002b, "Key Exchange" },
    { 0x002c, "Key Exchange Reply" },
    { 0x002d, "Chat" },
    { 0x002e, "Add Forward" },
    { 0x002f, "Add Forward ACK" },
    { 0x0030, "Packet2 Data" },
    { 0x0031, "Packet2 ACK" },
    /* No commands 0x0032, 0x0033, 0x0034 */
    { 0x0035, "I Am Nameserver" },
    { 0x0036, "Voice" },
    { 0x0037, "Multicast Delivery" },
    { 0x0038, "Create Players Verify"},
    { 0     , NULL },
};

static const value_string dplay_af_val[] = {
    { WINSOCK_AF_INET, "AF_INET" },
    { WINSOCK_AF_IPX, "AF_IPX" },
    { 0     , NULL},
};

static const value_string dplay_proto_dialect_val[] = {
    { 0x0009, "dplay 6" },
    { 0x000a, "dplay 6.1" },
    { 0x000b, "dplay 6.1a" },
    { 0x000c, "dplay 7.1" },
    { 0x000d, "dplay 8" },
    { 0x000e, "dplay 9"},
    { 0     , NULL},
};

static const value_string dplay_token_val[] = {
    { 0xfab, "Remote Message" },
    { 0xcab, "Forwarded Message" },
    { 0xbab, "Server Message" },
    { 0    , NULL },
};

static const value_string dplay_spp_length_val[] = {
    { 0x0, "Not present" },
    { 0x1, "One byte" },
    { 0x2, "Two bytes" },
    { 0x3, "Four bytes" },
    { 0  , NULL},
};

static const value_string dplay_enc_alg_val[] = {
    { 0x0000, "Default" },
    { 0x6611, "AES" },
    { 0x6603, "3DES" },
    { 0x6601, "DES" },
    { 0x6602, "RC2" },
    { 0x6801, "RC4" },
    { 0     , NULL },
};

static const value_string yes_no_val[] = {
    { 0x0, "No" },
    { 0x1, "Yes" },
    { 0  , NULL },
};

static const true_false_string tfs_dplay_flag = {
    "present",
    "absent"
};

/* borrowed from epan/dissectors/packets-smb-common.c */
static gint display_unicode_string(proto_tree *tree, gint hf_index, tvbuff_t *tvb, gint offset)
{
    char *str, *p;
    gint len;
    gint charoffset;
    guint16 character;

    /* display a unicode string from the tree and return new offset */

    /*
     * Get the length of the string.
     * XXX - is it a bug or a feature that this will throw an exception
     * if we don't find the '\0'?  I think it's a feature.
     */
    len = 0;
    while (tvb_get_letohs(tvb, offset + len) != '\0')
        len += 2;
    len += 2;   /* count the '\0' too */

    /*
     * Allocate a buffer for the string; "len" is the length in
     * bytes, not the length in characters.
     */
    str = ep_alloc(len/2);

    /*
     * XXX - this assumes the string is just ISO 8859-1; we need
     * to better handle multiple character sets in Wireshark,
     * including Unicode/ISO 10646, and multiple encodings of
     * that character set (UCS-2, UTF-8, etc.).
     */
    charoffset = offset;
    p = str;
    while ((character = tvb_get_letohs(tvb, charoffset)) != '\0') {
        *p++ = (char) character;
        charoffset += 2;
    }
    *p = '\0';

    proto_tree_add_string(tree, hf_index, tvb, offset, len, str);

    return  offset+len;
}

static gint dissect_sockaddr_in(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    proto_item *sa_item = NULL;
    proto_tree *sa_tree = NULL;

    sa_item = proto_tree_add_text(tree, tvb, offset, 16,
            "DirectPlay sockaddr_in structure");
    sa_tree = proto_item_add_subtree(sa_item, ett_dplay_sockaddr);
    proto_tree_add_item(sa_tree, hf_dplay_saddr_af, tvb, offset, 2, TRUE); offset += 2;
    proto_tree_add_item(sa_tree, hf_dplay_saddr_port, tvb, offset, 2, FALSE); offset += 2;
    proto_tree_add_item(sa_tree, hf_dplay_saddr_ip, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(sa_tree, hf_dplay_saddr_padding, tvb, offset, 8, FALSE); offset += 8;
    return offset;
}

static gint dissect_session_desc(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 flags;
    proto_item *flags_item = NULL;
    proto_tree *flags_tree = NULL;

    flags = tvb_get_letohl(tvb, offset+4);

    proto_tree_add_item(tree, hf_dplay_sess_desc_length, tvb, offset, 4, TRUE); offset += 4;
    flags_item = proto_tree_add_item(tree, hf_dplay_sess_desc_flags, tvb, offset, 4, TRUE);
    flags_tree = proto_item_add_subtree(flags_item, ett_dplay_sess_desc_flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_no_sess_desc_changes, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_acqire_voice, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_optimize_latency, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_preserve_order, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_reliable, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_server_player_only, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_route, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_password_req, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_private_session, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_use_auth, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_no_player_updates, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_use_ping, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_can_join, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_ignored, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_short_player_msg, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_migrate_host, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_0002, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_flags_no_create_players, tvb, offset, 4, flags);
    offset += 4;

    proto_tree_add_item(tree, hf_dplay_instance_guid, tvb, offset, 16, FALSE); offset += 16;
    proto_tree_add_item(tree, hf_dplay_game_guid, tvb, offset, 16, FALSE); offset += 16;
    proto_tree_add_item(tree, hf_dplay_max_players, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_curr_players, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sess_name_ptr, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_passwd_ptr, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sess_desc_reserved_1, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sess_desc_reserved_2, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sess_desc_user_1, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sess_desc_user_2, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sess_desc_user_3, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sess_desc_user_4, tvb, offset, 4, FALSE); offset += 4;

    return offset;
}

static gint dissect_packed_player(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    proto_tree *flags_tree;
    proto_item *flags_item;
    guint32 flags, sn_len, ln_len, sd_len, pd_len, num_players, i;
    gint size;

    size = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_pp_size, tvb, offset, 4, TRUE); offset += 4;

    flags = tvb_get_letohl(tvb, offset);
    flags_item = proto_tree_add_item(tree, hf_dplay_pp_flags, tvb, offset, 4, TRUE);
    flags_tree = proto_item_add_subtree(flags_item, ett_dplay_pp_flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_pp_flag_sending, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_pp_flag_in_group, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_pp_flag_nameserver, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_pp_flag_sysplayer, tvb, offset, 4, flags);
    offset += 4;

    proto_tree_add_item(tree, hf_dplay_pp_id, tvb, offset, 4, FALSE); offset += 4;

    sn_len = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_pp_short_name_len, tvb, offset, 4, TRUE); offset += 4;
    ln_len = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_pp_long_name_len, tvb, offset, 4, TRUE); offset += 4;
    sd_len = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_pp_sp_data_size, tvb, offset, 4, TRUE); offset += 4;
    pd_len = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_pp_player_data_size, tvb, offset, 4, TRUE); offset += 4;
    num_players = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_pp_num_players, tvb, offset, 4, TRUE); offset += 4;

    proto_tree_add_item(tree, hf_dplay_pp_system_player, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_pp_fixed_size, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_pp_dialect, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_pp_unknown_1, tvb, offset, 4, FALSE); offset += 4;

    if (sn_len)
        offset = display_unicode_string(tree, hf_dplay_pp_short_name, tvb, offset);

    if (ln_len)
        offset = display_unicode_string(tree, hf_dplay_pp_long_name, tvb, offset);

    proto_tree_add_item(tree, hf_dplay_pp_sp_data, tvb, offset, sd_len, FALSE);
    offset += sd_len;

    if (pd_len) {
        proto_tree_add_item(tree, hf_dplay_pp_player_data, tvb, offset, pd_len, FALSE);
        offset += pd_len;
    }

    for (i=0; i < num_players; ++i) {
        proto_tree_add_item(tree, hf_dplay_pp_player_id, tvb, offset, 4, FALSE); offset += 4;
    }

    /* Size seems to miss the unknown empty dword */
    if (size + 4 > offset) {
        proto_tree_add_item(tree, hf_dplay_pp_parent_id, tvb, offset, 4, FALSE); offset += 4;
    }

    return offset;
}

static gint spp_get_value(guint32 length_type, tvbuff_t *tvb, gint offset, guint32 *value)
{
    gint len = 0;

    *value = 0;

    switch (length_type) {
        case 1:
            len = 1;
            *value = tvb_get_guint8(tvb, offset);
            break;
        case 2:
            len = 2;
            *value = tvb_get_letohs(tvb, offset);
            break;
        case 3:
            len = 4;
            *value = tvb_get_letohl(tvb, offset);
            break;
    }

    return len;
}

static gint dissect_dplay_super_packed_player(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 flags, is_sysplayer, info_mask;
    guint32 have_short_name, have_long_name, sp_length_type, pd_length_type;
    guint32 player_count_type, have_parent_id, shortcut_count_type;
    guint32 player_data_length, sp_data_length, player_count, shortcut_count;
    proto_item *flags_item = NULL, *im_item = NULL;
    proto_tree *flags_tree = NULL, *im_tree = NULL;
    gint len;

    proto_tree_add_item(tree, hf_dplay_spp_size, tvb, offset, 4, TRUE); offset += 4;

    flags = tvb_get_letohl(tvb, offset);
    is_sysplayer = flags & 0x00000001;
    flags_item = proto_tree_add_item(tree, hf_dplay_spp_flags, tvb, offset, 4, TRUE);
    flags_tree = proto_item_add_subtree(flags_item, ett_dplay_spp_flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_spp_flags_sending, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_spp_flags_in_group, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_spp_flags_nameserver, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_dplay_spp_flags_sysplayer, tvb, offset, 4, flags);
    offset += 4;
    proto_tree_add_item(tree, hf_dplay_spp_id, tvb, offset, 4, TRUE); offset += 4;

    info_mask = tvb_get_letohl(tvb, offset);

    have_short_name     =  info_mask & 0x00000001;
    have_long_name      = (info_mask & 0x00000002) >> 1;
    sp_length_type      = (info_mask & 0x0000000c) >> 2;
    pd_length_type      = (info_mask & 0x00000030) >> 4;
    player_count_type   = (info_mask & 0x000000c0) >> 6;
    have_parent_id      = (info_mask & 0x00000100) >> 8;
    shortcut_count_type = (info_mask & 0x00000600) >> 9;

    im_item = proto_tree_add_item(tree, hf_dplay_spp_player_info_mask, tvb, offset, 4, TRUE);

    im_tree = proto_item_add_subtree(im_item, ett_dplay_spp_info_mask);
    proto_tree_add_uint(im_tree, hf_dplay_spp_have_short_name, tvb, offset, 4, have_short_name);
    proto_tree_add_uint(im_tree, hf_dplay_spp_have_long_name, tvb, offset, 4, have_long_name);
    proto_tree_add_uint(im_tree, hf_dplay_spp_sp_length_type, tvb, offset, 4, sp_length_type);
    proto_tree_add_uint(im_tree, hf_dplay_spp_pd_length_type, tvb, offset, 4, pd_length_type);
    proto_tree_add_uint(im_tree, hf_dplay_spp_player_count_type, tvb, offset, 4, player_count_type);
    proto_tree_add_uint(im_tree, hf_dplay_spp_have_parent_id, tvb, offset, 4, have_parent_id);
    proto_tree_add_uint(im_tree, hf_dplay_spp_shortcut_count_type, tvb, offset, 4, shortcut_count_type);
    offset+=4;

    if (is_sysplayer) {
        proto_tree_add_item(tree, hf_dplay_spp_dialect, tvb, offset, 4, TRUE);
    } else {
        proto_tree_add_item(tree, hf_dplay_spp_sys_player_id, tvb, offset, 4, FALSE);
    }
    offset += 4;

    if (have_short_name) {
        offset = display_unicode_string(tree, hf_dplay_spp_short_name, tvb, offset);
    }

    if (have_long_name) {
        offset = display_unicode_string(tree, hf_dplay_spp_long_name, tvb, offset);
    }

    if (pd_length_type) {
        len = spp_get_value(pd_length_type, tvb, offset, &player_data_length);
        proto_tree_add_item(tree, hf_dplay_spp_player_data_length, tvb, offset, len, TRUE);
        offset += len;
        proto_tree_add_item(tree, hf_dplay_spp_player_data, tvb, offset, player_data_length, FALSE);
        offset += player_data_length;
    }

    if (sp_length_type) {
        len = spp_get_value(sp_length_type, tvb, offset, &sp_data_length);
        proto_tree_add_item(tree, hf_dplay_spp_sp_data_length, tvb, offset, len, TRUE);
        offset += len;
        proto_tree_add_item(tree, hf_dplay_spp_sp_data, tvb, offset, sp_data_length, FALSE);
        offset += sp_data_length;
    }

    if (player_count_type) {
        guint32 i;

        len = spp_get_value(player_count_type, tvb, offset, &player_count);
        proto_tree_add_item(tree, hf_dplay_spp_player_count, tvb, offset, len, TRUE);
        offset += len;
        for (i=0; i < player_count; ++i) {
            proto_tree_add_item(tree, hf_dplay_spp_player_id, tvb, offset, 4, FALSE); offset += 4;
        }
    }

    if (have_parent_id) {
        proto_tree_add_item(tree, hf_dplay_spp_parent_id, tvb, offset, 4, FALSE); offset += 4;
    }

    if (shortcut_count_type) {
        guint32 i;

        len = spp_get_value(shortcut_count_type, tvb, offset, &shortcut_count);
        proto_tree_add_item(tree, hf_dplay_spp_shortcut_count, tvb, offset, len, TRUE);
        offset += len;
        for (i=0; i < shortcut_count; ++i) {
            proto_tree_add_item(tree, hf_dplay_spp_shortcut_id, tvb, offset, 4, FALSE); offset += 4;
        }
    }

    return offset;
}

static gint dissect_security_desc(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    proto_tree_add_item(tree, hf_dplay_sd_size, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sd_flags, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sd_sspi, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sd_capi, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sd_capi_type, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_sd_enc_alg, tvb, offset, 4, TRUE); offset += 4;
    return offset;
}

static gint dissect_dplay_header(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 mixed, size, token;

    mixed = tvb_get_letohl(tvb, offset);
    size = mixed & 0x000FFFFF;
    token = (mixed & 0xFFF00000) >> 20;

    proto_tree_add_uint(tree, hf_dplay_size, tvb, offset, 4, size);
    proto_tree_add_uint(tree, hf_dplay_token, tvb, offset, 4, token);
    offset += 4;
    offset = dissect_sockaddr_in(tree, tvb, offset);
    proto_tree_add_item(tree, hf_dplay_play_str, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_command, tvb, offset, 2, TRUE); offset += 2;
    proto_tree_add_item(tree, hf_dplay_proto_dialect, tvb, offset, 2, TRUE); offset += 2;
    return offset;
}

static gint dissect_type01_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 name_offset;

    offset = dissect_session_desc(tree, tvb, offset);
    name_offset = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_01_name_offset, tvb, offset, 4, TRUE); offset += 4;

    if (name_offset != 0) {
        offset = display_unicode_string(tree, hf_dplay_type_01_game_name, tvb, offset);
    }
    return offset;
}

static gint dissect_type02_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 passwd_offset;
    guint32 flags;
    proto_item *flags_item = NULL;
    proto_tree *flags_tree = NULL;

    passwd_offset = tvb_get_letohl(tvb, offset + 16);
    flags = tvb_get_letohl(tvb, offset + 20);

    proto_tree_add_item(tree, hf_dplay_type_02_game_guid, tvb, offset, 16, FALSE); offset += 16;
    proto_tree_add_item(tree, hf_dplay_type_02_password_offset, tvb, offset, 4, TRUE); offset += 4;

    flags_item = proto_tree_add_item(tree, hf_dplay_type_02_flags, tvb, offset, 4, TRUE);
    flags_tree = proto_item_add_subtree(flags_item, ett_dplay_type02_flags);
    proto_tree_add_boolean(flags_tree, hf_enum_sess_flag_passwd, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_enum_sess_flag_all, tvb, offset, 4, flags);
    proto_tree_add_boolean(flags_tree, hf_enum_sess_flag_join, tvb, offset, 4, flags);
    offset += 4;

    if (passwd_offset != 0) {
        offset = display_unicode_string(tree, hf_dplay_type_02_password, tvb, offset);
    }
    return offset;
}

static gint dissect_type05_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    proto_item *flag_item;
    proto_item *flag_tree;
    guint32 flags;

    flags = tvb_get_letohl(tvb, offset);
    flag_item = proto_tree_add_item(tree, hf_dplay_type_05_flags, tvb, offset, 4, TRUE);
    flag_tree = proto_item_add_subtree(flag_item, ett_dplay_type05_flags);
    proto_tree_add_boolean(flag_tree, hf_dplay_type_05_secure, tvb, offset, 4, flags);
    proto_tree_add_boolean(flag_tree, hf_dplay_type_05_unknown, tvb, offset, 4, flags);
    proto_tree_add_boolean(flag_tree, hf_dplay_type_05_local, tvb, offset, 4, flags);
    proto_tree_add_boolean(flag_tree, hf_dplay_type_05_name_server, tvb, offset, 4, flags);
    proto_tree_add_boolean(flag_tree, hf_dplay_type_05_system_player, tvb, offset, 4, flags);
    offset += 4;
    return offset;
}

static gint dissect_type07_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 sspi_offset, capi_offset;

    proto_tree_add_item(tree, hf_dplay_type_07_dpid, tvb, offset, 4, FALSE); offset += 4;
    offset = dissect_security_desc(tree, tvb, offset);

    sspi_offset = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_07_sspi_offset, tvb, offset, 4, TRUE); offset += 4;

    capi_offset = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_07_capi_offset, tvb, offset, 4, TRUE); offset += 4;

    proto_tree_add_item(tree, hf_dplay_type_07_hresult, tvb, offset, 4, TRUE); offset += 4;

    if (sspi_offset) {
        offset = display_unicode_string(tree, hf_dplay_type_07_sspi, tvb, offset);
    }

    if (capi_offset) {
        offset = display_unicode_string(tree, hf_dplay_type_07_capi, tvb, offset);
    }
    return offset;
}

static gint dissect_player_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 pp_ofs;

    proto_tree_add_item(tree, hf_dplay_multi_id_to, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_multi_player_id, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_multi_group_id, tvb, offset, 4, FALSE); offset += 4;
    pp_ofs = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_multi_create_offset, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_multi_password_offset, tvb, offset, 4, TRUE); offset += 4;
    if (pp_ofs)
        offset = dissect_packed_player(tree, tvb, offset);
    if (tvb_bytes_exist(tvb, offset, 2))
        offset = display_unicode_string(tree, hf_dplay_multi_password, tvb, offset);
    return offset;
}

static gint dissect_type0f_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 data_size;

    proto_tree_add_item(tree, hf_dplay_type_0f_id_to, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_0f_id, tvb, offset, 4, FALSE); offset += 4;
    data_size = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_0f_data_size, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_0f_data_offset, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_0f_data, tvb, offset, data_size, FALSE);
    offset += data_size;

    return offset;
}

static gint dissect_type13_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 pp_ofs, pw_ofs;

    proto_tree_add_item(tree, hf_dplay_type_13_id_to, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_13_player_id, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_13_group_id, tvb, offset, 4, FALSE); offset += 4;
    pp_ofs = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_13_create_offset, tvb, offset, 4, TRUE); offset += 4;
    pw_ofs = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_13_password_offset, tvb, offset, 4, TRUE); offset += 4;
    if (pp_ofs)
        offset = dissect_packed_player(tree, tvb, offset);
    if (pw_ofs)
        offset = display_unicode_string(tree, hf_dplay_type_13_password, tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_13_tick_count, tvb, offset, 4, TRUE); offset += 4;

    return offset;
}

static gint dissect_type15_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint16 second_message_type;
    proto_item *enc_item = NULL;
    proto_tree *enc_tree = NULL;
    second_message_type = tvb_get_letohs(tvb, 72);

    proto_tree_add_item(tree, hf_dplay_message_guid, tvb, offset, 16, FALSE); offset += 16;
    proto_tree_add_item(tree, hf_dplay_type_15_packet_idx, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_15_data_size, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_15_offset, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_15_total_packets, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_15_msg_size, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_15_packet_offset, tvb, offset, 4, TRUE); offset += 4;

    enc_item = proto_tree_add_text(tree, tvb, offset, -1, "DirectPlay encapsulated packet");
    enc_tree = proto_item_add_subtree(enc_item, ett_dplay_enc_packet);

    proto_tree_add_item(enc_tree, hf_dplay_play_str_2, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(enc_tree, hf_dplay_command_2, tvb, offset, 2, TRUE); offset += 2;
    proto_tree_add_item(enc_tree, hf_dplay_proto_dialect_2, tvb, offset, 2, TRUE); offset += 2;

    switch(second_message_type)
    {
        case 0x0005:
            offset = dissect_type05_message(enc_tree, tvb, offset);
            break;
        case 0x0007:
            offset = dissect_type05_message(enc_tree, tvb, offset);
            break;
        case 0x0008:
        case 0x0009:
        case 0x000b:
        case 0x000c:
        case 0x000d:
        case 0x000e:
        case 0x002e:
            offset = dissect_player_message(enc_tree, tvb, offset);
            break;
        case 0x0013:
            offset = dissect_type13_message(enc_tree, tvb, offset);
            break;
        case 0x001a:
            offset = dissect_type1a_message(enc_tree, tvb, offset);
            break;
    }

    return offset;
}

static gint dissect_ping_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    proto_tree_add_item(tree, hf_dplay_ping_id_from, tvb, offset, 4, FALSE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_ping_tick_count, tvb, offset, 4, TRUE); offset += 4;

    return offset;
}

static gint dissect_type1a_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 sn_ofs, pw_ofs;

    proto_tree_add_item(tree, hf_dplay_type_1a_id_to, tvb, offset, 4, FALSE); offset += 4;
    sn_ofs = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_1a_sess_name_ofs, tvb, offset, 4, TRUE); offset += 4;
    pw_ofs = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_1a_password_ofs, tvb, offset, 4, TRUE); offset += 4;
    offset = dissect_session_desc(tree, tvb, offset);

    if (sn_ofs) {
        offset = display_unicode_string(tree, hf_dplay_type_1a_session_name, tvb, offset);
    }

    if (pw_ofs) {
        offset = display_unicode_string(tree, hf_dplay_type_1a_password, tvb, offset);
    }

    return offset;
}

static gint dissect_type29_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    guint32 password_offset = tvb_get_letohl(tvb, offset + 24);
    gint player_count, group_count, shortcut_count;
    gint i;

    player_count = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_29_player_count, tvb, offset, 4, TRUE); offset += 4;
    group_count = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_29_group_count, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_29_packed_offset, tvb, offset, 4, TRUE); offset += 4;
    shortcut_count = tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_dplay_type_29_shortcut_count, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_29_description_offset, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_29_name_offset, tvb, offset, 4, TRUE); offset += 4;
    proto_tree_add_item(tree, hf_dplay_type_29_password_offset, tvb, offset, 4, TRUE); offset += 4;
    offset = dissect_session_desc(tree, tvb, offset);
    offset = display_unicode_string(tree, hf_dplay_type_29_game_name, tvb, offset);

    if (password_offset != 0) {
        offset = display_unicode_string(tree, hf_dplay_type_29_password, tvb, offset);
    }

    for (i=0; i < player_count; ++i) {
        proto_item *spp_item;
        proto_tree *spp_tree;

        spp_item = proto_tree_add_text(tree, tvb, offset, 0, "Player %d", i);
        spp_tree = proto_item_add_subtree(spp_item, ett_dplay_type29_spp);
        offset = dissect_dplay_super_packed_player(spp_tree, tvb, offset);
    }

    for (i=0; i < group_count; ++i) {
        proto_item *spp_item;
        proto_tree *spp_tree;

        spp_item = proto_tree_add_text(tree, tvb, offset, 0, "Group %d", i);
        spp_tree = proto_item_add_subtree(spp_item, ett_dplay_type29_spp);
        offset = dissect_dplay_super_packed_player(spp_tree, tvb, offset);
    }

    for (i=0; i < shortcut_count; ++i) {
        proto_item *spp_item;
        proto_tree *spp_tree;

        spp_item = proto_tree_add_text(tree, tvb, offset, 0, "Shortcut %d", i);
        spp_tree = proto_item_add_subtree(spp_item, ett_dplay_type29_spp);
        offset = dissect_dplay_super_packed_player(spp_tree, tvb, offset);
    }

    return offset;
}

static gint dissect_type2f_message(proto_tree *tree, tvbuff_t *tvb, gint offset)
{
    proto_tree_add_item(tree, hf_dplay_type_2f_dpid, tvb, offset, 4, FALSE); offset += 4;
    return offset;
}

static void dissect_dplay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint16 message_type;
    guint16 second_message_type = G_MAXUINT16;
    guint16 proto_version;
    guint32 dplay_id;
    guint8 play_id[] = {'p','l','a','y'};

    dplay_id = tvb_get_letohl(tvb, 20);
    message_type = tvb_get_letohs(tvb, 24);
    proto_version = tvb_get_letohs(tvb, 26);

    if(memcmp(play_id, (guint8 *)&dplay_id, 4) != 0)
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPLAY");
        col_set_str(pinfo->cinfo,COL_INFO, "DPlay data packet");
        return;
    }

    if(message_type == 0x0015)
    {
        second_message_type = tvb_get_letohs(tvb, 72);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPLAY");

    if(check_col(pinfo->cinfo,COL_INFO))
    {
        if(message_type == 0x0015)
            col_add_fstr(pinfo->cinfo,COL_INFO, "%s: %s, holding a %s",
                val_to_str(proto_version, dplay_proto_dialect_val, "Unknown (0x%04x)"),
                val_to_str(message_type, dplay_command_val, "Unknown (0x%04x)"),
                val_to_str(second_message_type, dplay_command_val, "Unknown (0x%04x)"));
        else
            col_add_fstr(pinfo->cinfo,COL_INFO, "%s: %s",
                val_to_str(proto_version, dplay_proto_dialect_val, "Unknown (0x%04x)"),
                val_to_str(message_type, dplay_command_val, "Unknown (0x%04x)"));
    }

    if(tree)
    {
        proto_item *dplay_item = NULL;
        proto_item *header_item = NULL;
        proto_item *data_item = NULL;
        proto_tree *dplay_tree = NULL;
        proto_tree *dplay_header = NULL;
        proto_tree *dplay_data = NULL;
        gint offset = 0;

        dplay_item = proto_tree_add_item(tree, proto_dplay, tvb, 0, -1, FALSE);
        dplay_tree = proto_item_add_subtree(dplay_item, ett_dplay);
        header_item = proto_tree_add_text(dplay_tree, tvb, offset, DPLAY_HEADER_OFFSET, "DirectPlay header");
        dplay_header = proto_item_add_subtree(header_item, ett_dplay_header);

        offset = dissect_dplay_header(dplay_header, tvb, offset);

        /* Special handling for empty type 0x0004 packets */
        if(message_type == 0x0004)
            return;

        data_item = proto_tree_add_text(dplay_tree, tvb, offset, -1, "DirectPlay data");
        dplay_data = proto_item_add_subtree(data_item, ett_dplay_data);

        switch(message_type)
        {
            case 0x0001:
                offset = dissect_type01_message(dplay_data, tvb, offset);
                break;
            case 0x0002:
                offset = dissect_type02_message(dplay_data, tvb, offset);
                break;
            case 0x0004:
                /* We should not get here. */
                break;
            case 0x0005:
                offset = dissect_type05_message(dplay_data, tvb, offset);
                break;
            case 0x0007:
                offset = dissect_type07_message(dplay_data, tvb, offset);
                break;
            case 0x0008:
            case 0x0009:
            /* type 0a doesn't have a dplay header and is not handled here */
            case 0x000b:
            case 0x000c:
            case 0x000d:
            case 0x000e:
            case 0x002e:
            case 0x0038:
                offset = dissect_player_message(dplay_data, tvb, offset);
                break;
            case 0x000f:
                offset = dissect_type0f_message(dplay_data, tvb, offset);
                break;
            case 0x0013:
                offset = dissect_type13_message(dplay_data, tvb, offset);
                break;
            case 0x0015:
                offset = dissect_type15_message(dplay_data, tvb, offset);
                break;
            case 0x0016:
            case 0x0017:
                offset = dissect_ping_message(dplay_data, tvb, offset);
                break;
            case 0x001a:
                offset = dissect_type1a_message(dplay_data, tvb, offset);
                break;
            case 0x0029:
                offset = dissect_type29_message(dplay_data, tvb, offset);
                break;
            case 0x002f:
                offset = dissect_type2f_message(dplay_data, tvb, offset);
                break;
        }
    }

}

static void dissect_dplay_player_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint32 mixed, size, token;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPLAY");
    col_set_str(pinfo->cinfo,COL_INFO, "DPlay player to player message");

    if(tree)
    {
        proto_item *dplay_item = NULL;
        proto_item *data_item = NULL;
        proto_tree *dplay_tree = NULL;
        proto_tree *data_tree = NULL;
        gint offset = 0;

        dplay_item = proto_tree_add_item(tree, proto_dplay, tvb, offset, -1, FALSE);
        dplay_tree = proto_item_add_subtree(dplay_item, ett_dplay);
        data_item  = proto_tree_add_text(dplay_tree, tvb, offset, -1, "Message content");
        data_tree  = proto_item_add_subtree(data_item, ett_dplay_data);
        mixed = tvb_get_letohl(tvb, offset);
        size = mixed & 0x000FFFFF;
        token = (mixed & 0xFFF00000) >> 20;

        proto_tree_add_uint(data_tree, hf_dplay_size, tvb, offset, 4, size);
        proto_tree_add_uint(data_tree, hf_dplay_token, tvb, offset, 4, token);
        offset += 4;
        offset = dissect_sockaddr_in(data_tree, tvb, offset);
        /* Now there's two dplay IDs iff the session desc does not have the
         * "short player message" flag set */
        proto_tree_add_item(data_tree, hf_dplay_player_msg, tvb, offset, -1, FALSE);

    }
}
static gboolean heur_dissect_dplay(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8 signature[] = {'p','l','a','y'};
    guint32 dplay_id, token;

    if(!tvb_bytes_exist(tvb, 0, 24))
        return FALSE;

    dplay_id = tvb_get_letohl(tvb, 20);
    if( memcmp(signature, (guint8 *)&dplay_id, 4) == 0) {
        dissect_dplay(tvb, pinfo, tree);
        return TRUE;
    }

    /* There is a player to player message that does not contain "play" */
    token = tvb_get_letohl(tvb, 0);
    token = (token & 0xfff00000) >> 20;
    if (token == 0xfab || token == 0xbab || token == 0xcab) {
      /* Check the s_addr_in structure */
      if (tvb_get_letohs(tvb, 4) == WINSOCK_AF_INET) {
        int offset;
        for (offset = 12; offset <= 20; offset++)
          if (tvb_get_guint8(tvb, offset) != 0)
            return FALSE;

        dissect_dplay_player_msg(tvb, pinfo, tree);
        return TRUE;
      }
    }

    return FALSE;
}

void proto_register_dplay(void)
{
    static hf_register_info hf [] = {
    /* Common data fields */
    { &hf_dplay_size,
        { "DirectPlay package size", "dplay.size", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_token,
        { "DirectPlay token", "dplay.token", FT_UINT32, BASE_HEX,
        VALS(dplay_token_val), 0x0, NULL, HFILL}},
    { &hf_dplay_saddr_af,
        { "DirectPlay s_addr_in address family", "dplay.saddr.af", FT_UINT16, BASE_HEX,
        VALS(dplay_af_val), 0x0, NULL, HFILL}},
    { &hf_dplay_saddr_port,
        { "DirectPlay s_addr_in port", "dplay.saddr.port", FT_UINT16, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_saddr_ip,
        { "DirectPlay s_addr_in ip address", "dplay.saddr.ip", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_saddr_padding,
        { "DirectPlay s_addr_in null padding", "dplay.saddr.padding", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_play_str,
        { "DirectPlay action string", "dplay.dplay_str", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_command,
        { "DirectPlay command", "dplay.command", FT_UINT16, BASE_HEX,
        VALS(dplay_command_val), 0x0, NULL, HFILL}},
    { &hf_dplay_proto_dialect,
        { "DirectPlay dialect version", "dplay.dialect.version", FT_UINT16, BASE_HEX,
        VALS(dplay_proto_dialect_val), 0x0, NULL, HFILL}},
    { &hf_dplay_play_str_2,
        { "DirectPlay second action string", "dplay.dplay_str_2", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_command_2,
        { "DirectPlay second command", "dplay.command_2", FT_UINT16, BASE_HEX,
        VALS(dplay_command_val), 0x0, NULL, HFILL}},
    { &hf_dplay_proto_dialect_2,
        { "DirectPlay second dialect version", "dplay.dialect.version_2", FT_UINT16, BASE_HEX,
        VALS(dplay_proto_dialect_val), 0x0, NULL, HFILL}},
    { &hf_dplay_player_msg,
        { "DirectPlay Player to Player message", "dplay.player_msg", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* Session Desc structure fields */
    { &hf_dplay_sess_desc_flags,
        { "DirectPlay session desc flags", "dplay.flags", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_flags_no_create_players,
        { "no create players flag", "dplay.flags.no_create_players", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_NO_CREATE_PLAYERS, "No Create Players", HFILL}},
    { &hf_dplay_flags_0002,
        { "unused", "dplay.flags.unused", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_0002, NULL, HFILL}},
    { &hf_dplay_flags_migrate_host,
        { "migrate host flag", "dplay.flags.migrate_host", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_MIGRATE_HOST, "Migrate Host", HFILL}},
    { &hf_dplay_flags_short_player_msg,
        { "short player message", "dplay.flags.short_player_msg", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_SHORT_PLAYER_MSG, "Short Player Msg", HFILL}},
    { &hf_dplay_flags_ignored,
        { "ignored", "dplay.flags.ignored", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_IGNORED, NULL, HFILL}},
    { &hf_dplay_flags_can_join,
        { "can join", "dplay.flags.can_join", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_CAN_JOIN, NULL, HFILL}},
    { &hf_dplay_flags_use_ping,
        { "use ping", "dplay.flags.use_ping", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_USE_PING, NULL, HFILL}},
    { &hf_dplay_flags_no_player_updates,
        { "no player updates", "dplay.flags.no_player_updates", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_NO_P_UPD, NULL, HFILL}},
    { &hf_dplay_flags_use_auth,
        { "use authentication", "dplay.flags.use_auth", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_USE_AUTH, "Use Auth", HFILL}},
    { &hf_dplay_flags_private_session,
        { "private session", "dplay.flags.priv_sess", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_PRIV_SESS, "Priv Session", HFILL}},
    { &hf_dplay_flags_password_req,
        { "password required", "dplay.flags.pass_req", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_PASS_REQ, "Pass Req", HFILL}},
    { &hf_dplay_flags_route,
        { "route via game host", "dplay.flags.route", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_ROUTE, "Route", HFILL}},
    { &hf_dplay_flags_server_player_only,
        { "get server player only", "dplay.flags.srv_p_only", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_SRV_ONLY, "Svr Player Only", HFILL}},
    { &hf_dplay_flags_reliable,
        { "use reliable protocol", "dplay.flags.reliable", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_RELIABLE, "Reliable", HFILL}},
    { &hf_dplay_flags_preserve_order,
        { "preserve order", "dplay.flags.order", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_ORDER, "Order", HFILL}},
    { &hf_dplay_flags_optimize_latency,
        { "optimize for latency", "dplay.flags.opt_latency", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_OPT_LAT, "Opt Latency", HFILL}},
    { &hf_dplay_flags_acqire_voice,
        { "acquire voice", "dplay.flags.acq_voice", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_ACQ_VOICE, "Acq Voice", HFILL}},
    { &hf_dplay_flags_no_sess_desc_changes,
        { "no session desc changes", "dplay.flags.no_sess_desc", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_FLAG_NO_SESS_DESC_CHANGES, "No Sess Desc Changes", HFILL}},
    { &hf_dplay_instance_guid,
        { "DirectPlay instance guid", "dplay.instance.guid", FT_GUID, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_game_guid,
        { "DirectPlay game GUID", "dplay.game.guid", FT_GUID, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sess_desc_length,
        { "DirectPlay session desc length", "dplay.sess_desc.length", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_max_players,
        { "DirectPlay max players", "dplay.sess_desc.max_players", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_curr_players,
        { "DirectPlay current players", "dplay.sess_desc.curr_players", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sess_name_ptr,
        { "Session description name pointer placeholder", "dplay.sess_desc.name_ptr", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_passwd_ptr,
        { "Session description password pointer placeholder", "dplay.sess_desc.pw_ptr", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sess_desc_reserved_1,
        { "Session description reserved 1", "dplay.sess_desc.res_1", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sess_desc_reserved_2,
        { "Session description reserved 2", "dplay.sess_desc.res_2", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sess_desc_user_1,
        { "Session description user defined 1", "dplay.sess_desc.user_1", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sess_desc_user_2,
        { "Session description user defined 2", "dplay.sess_desc.user_2", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sess_desc_user_3,
        { "Session description user defined 3", "dplay.sess_desc.user_3", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sess_desc_user_4,
        { "Session description user defined 4", "dplay.sess_desc.user_4", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* PackedPlayer structure fields */
    { &hf_dplay_pp_size,
        { "PackedPlayer size", "dplay.pp.size", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_flags,
        { "PackedPlayer flags", "dplay.pp.flags", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_flag_sysplayer,
        { "is system player", "dplay.pp.flags.sysplayer", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_PP_FLAG_SYSPLAYER, NULL, HFILL}},
    { &hf_dplay_pp_flag_nameserver,
        { "is name server", "dplay.pp.flags.nameserver", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_PP_FLAG_NAMESERVER, NULL, HFILL}},
    { &hf_dplay_pp_flag_in_group,
        { "in group", "dplay.pp.flags.in_group", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_PP_FLAG_IN_GROUP, NULL, HFILL}},
    { &hf_dplay_pp_flag_sending,
        { "sending player on local machine", "dplay.pp.flags.sending", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_SPP_FLAG_SENDING, NULL, HFILL}},
    { &hf_dplay_pp_id,
        { "PackedPlayer ID", "dplay.pp.id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_short_name_len,
        { "PackedPlayer short name length", "dplay.pp.short_name_len", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_long_name_len,
        { "PackedPlayer long name length", "dplay.pp.long_name_len", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_sp_data_size,
        { "PackedPlayer service provider data size", "dplay.pp.sp_data_size", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_player_data_size,
        { "PackedPlayer player data size", "dplay.pp.player_data_size", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_num_players,
        { "PackedPlayer player count", "dplay.pp.player_count", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_system_player,
        { "PackedPlayer system player ID", "dplay.pp.sysplayer_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_fixed_size,
        { "PackedPlayer fixed size", "dplay.pp.fixed_size", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_dialect,
        { "PackedPlayer dialect version", "dplay.pp.dialect", FT_UINT32, BASE_HEX,
        VALS(dplay_proto_dialect_val), 0x0, NULL, HFILL}},
    { &hf_dplay_pp_unknown_1,
        { "PackedPlayer unknown 1", "dplay.pp.unknown_1", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_short_name,
        { "PackedPlayer short name", "dplay.pp.short_name", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_long_name,
        { "PackedPlayer long name", "dplay.pp.short_name", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_player_data,
        { "PackedPlayer player data", "dplay.pp.player_data", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_sp_data,
        { "PackedPlayer service provider data", "dplay.pp.sp_data", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_player_id,
        { "PackedPlayer player ID", "dplay.pp.player_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_pp_parent_id,
        { "PackedPlayer parent ID", "dplay.pp.parent_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* SuperPackedPlayer structure fields */
    { &hf_dplay_spp_size,
        { "SuperPackedPlayer size", "dplay.spp.size", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_flags,
        { "SuperPackedPlayer flags", "dplay.spp.flags", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_flags_sysplayer,
        { "is system player", "dplay.spp.flags.sysplayer", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_SPP_FLAG_SYSPLAYER, NULL, HFILL}},
    { &hf_dplay_spp_flags_nameserver,
        { "is name server", "dplay.spp.flags.nameserver", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_SPP_FLAG_NAMESERVER, NULL, HFILL}},
    { &hf_dplay_spp_flags_in_group,
        { "in group", "dplay.spp.flags.in_group", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_SPP_FLAG_IN_GROUP, NULL, HFILL}},
    { &hf_dplay_spp_flags_sending,
        { "sending player on local machine", "dplay.spp.flags.sending", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_SPP_FLAG_SENDING, NULL, HFILL}},
    { &hf_dplay_spp_id,
        { "SuperPackedPlayer ID", "dplay.spp.id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_player_info_mask,
        { "SuperPackedPlayer player info mask", "dplay.spp.pim", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_have_short_name,
        { "SuperPackedPlayer have short name", "dplay.spp.pim.short_name", FT_UINT32, BASE_HEX,
        VALS(yes_no_val), 0x0, NULL, HFILL}},
    { &hf_dplay_spp_have_long_name,
        { "SuperPackedPlayer have long name", "dplay.spp.pim.long_name", FT_UINT32, BASE_HEX,
        VALS(yes_no_val), 0x0, NULL, HFILL}},
    { &hf_dplay_spp_sp_length_type,
        { "SuperPackedPlayer service provider length info", "dplay.spp.pim.sp_length", FT_UINT32, BASE_HEX,
        VALS(dplay_spp_length_val), 0x0, NULL, HFILL}},
    { &hf_dplay_spp_pd_length_type,
        { "SuperPackedPlayer player data length info", "dplay.spp.pim.pd_length", FT_UINT32, BASE_HEX,
        VALS(dplay_spp_length_val), 0x0, NULL, HFILL}},
    { &hf_dplay_spp_player_count_type,
        { "SuperPackedPlayer player count info", "dplay.spp.pim.player_count", FT_UINT32, BASE_HEX,
        VALS(dplay_spp_length_val), 0x0, NULL, HFILL}},
    { &hf_dplay_spp_have_parent_id,
        { "SuperPackedPlayer have parent ID", "dplay.spp.pim.parent_id", FT_UINT32, BASE_HEX,
        VALS(yes_no_val), 0x0, NULL, HFILL}},
    { &hf_dplay_spp_shortcut_count_type,
        { "SuperPackedPlayer shortcut count info", "dplay.spp.pim.shortcut_count", FT_UINT32, BASE_HEX,
        VALS(dplay_spp_length_val), 0x0, NULL, HFILL}},
    { &hf_dplay_spp_dialect,
        { "SuperPackedPlayer dialect version", "dplay.spp.dialect", FT_UINT32, BASE_HEX,
        VALS(dplay_proto_dialect_val), 0x0, NULL, HFILL}},
    { &hf_dplay_spp_sys_player_id,
        { "SuperPackedPlayer system player ID", "dplay.spp.sysplayer_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_short_name,
        { "SuperPackedPlayer short name", "dplay.spp.short_name", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_long_name,
        { "SuperPackedPlayer long name", "dplay.spp.short_name", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_player_data_length,
        { "SuperPackedPlayer player data length", "dplay.spp.pd_length", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_player_data,
        { "SuperPackedPlayer player data", "dplay.spp.player_data", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_sp_data_length,
        { "SuperPackedPlayer service provider data length", "dplay.spp.sp_data_length", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_sp_data,
        { "SuperPackedPlayer service provider data", "dplay.spp.sp_data", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_player_count,
        { "SuperPackedPlayer player count", "dplay.spp.player_count", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_player_id,
        { "SuperPackedPlayer player ID", "dplay.spp.player_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_parent_id,
        { "SuperPackedPlayer parent ID", "dplay.spp.parent_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_shortcut_count,
        { "SuperPackedPlayer shortcut count", "dplay.spp.shortcut_count", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_spp_shortcut_id,
        { "SuperPackedPlayer shortcut ID", "dplay.spp.shortcut_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* Data fields for SecDesc struct */
    { &hf_dplay_sd_size,
        { "SecDesc struct size", "dplay.sd.size", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sd_flags,
        { "SecDesc flags", "dplay.sd.flags", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sd_sspi,
        { "SecDesc SSPI provider ptr", "dplay.sd.sspi", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sd_capi,
        { "SecDesc CAPI provider ptr", "dplay.sd.capi", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sd_capi_type,
        { "SecDesc CAPI provider type", "dplay.sd.capi_type", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_sd_enc_alg,
        { "SecDesc encryption algorithm" , "dplay.sd.enc_alg", FT_UINT32, BASE_HEX,
        VALS(dplay_enc_alg_val), 0x0, NULL, HFILL}},

    /* Data fields for message type 0x0001 */
    { &hf_dplay_type_01_name_offset,
        { "Enum Session Reply name offset", "dplay.type_01.name_offs", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_01_game_name,
        { "Enum Session Reply game name", "dplay.type_01.game_name", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* Data fields for message type 0x0002 */
    { &hf_dplay_type_02_game_guid,
        { "DirectPlay game GUID", "dplay.type02.game.guid", FT_GUID, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_02_password_offset,
        { "Enum Sessions password offset", "dplay.type02.password_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_02_flags,
        { "Enum Session flags", "dplay.type02.flags", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_02_password,
        { "Session password", "dplay.type02.password", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_enum_sess_flag_join,
        { "Enumerate joinable sessions", "dplay.type02.joinable", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_ENUM_SESS_FLAG_JOIN, "Joinable", HFILL}},
    { &hf_enum_sess_flag_all,
        { "Enumerate all sessions", "dplay.type02.all", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_ENUM_SESS_FLAG_ALL, "All", HFILL}},
    { &hf_enum_sess_flag_passwd,
        { "Enumerate sessions requiring a password", "dplay.type02.pw_req", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_ENUM_SESS_FLAG_PASSWD, "Password", HFILL}},

    /* Data fields for message type 0x0005 */
    { &hf_dplay_type_05_flags,
        { "Player ID request flags", "dplay.type_05.flags", FT_UINT32, BASE_HEX,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_05_system_player,
        { "is system player", "dplay.type_05.flags.sys_player", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_TYPE05_FLAG_SYSPLAYER, NULL, HFILL}},
    { &hf_dplay_type_05_name_server,
        { "is name server", "dplay.type_05.flags.name_server", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_TYPE05_FLAG_NAMESERVER, NULL, HFILL}},
    { &hf_dplay_type_05_local,
        { "is local player", "dplay.type_05.flags.local", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_TYPE05_FLAG_LOCAL, NULL, HFILL}},
    { &hf_dplay_type_05_unknown,
        { "unknown", "dplay.type_05.flags.unknown", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_TYPE05_FLAG_UNKNOWN, NULL, HFILL}},
    { &hf_dplay_type_05_secure,
        { "is secure session", "dplay.type_05.flags.secure", FT_BOOLEAN, 32,
        TFS(&tfs_dplay_flag), DPLAY_TYPE05_FLAG_SECURE, NULL, HFILL}},

    /* Data fields for message type 0x0007 */
    { &hf_dplay_type_07_dpid,
        { "DirectPlay ID", "dplay.type_07.dpid", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_07_sspi_offset,
        { "SSPI provider offset", "dplay.type_07.sspi_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_07_capi_offset,
        { "CAPI provider offset", "dplay.type_07.capi_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_07_hresult,
        { "Request player HRESULT", "dplay.type_07.hresult", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_07_sspi,
        { "SSPI provider", "dplay.type_07.sspi", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_07_capi,
        { "CAPI provider", "dplay.type_07.capi", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* Data fields for message type 0x0008, 0x0009, 0x000b, 0x000c, 0x000d,
     * 0x000e, 0x002e and 0x0038*/
    { &hf_dplay_multi_id_to,
        { "ID to", "dplay.multi.id_to", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_multi_player_id,
        { "Player ID", "dplay.multi.player_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_multi_group_id,
        { "Group ID", "dplay.multi.group_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_multi_create_offset,
        { "Offset to PackedPlayer struct", "dplay.multi.create_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_multi_password_offset,
        { "Offset to password", "dplay.multi.password_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_multi_password,
        { "Password", "dplay.multi.password", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* Data fields for message type 0x000f */
    { &hf_dplay_type_0f_id_to,
        { "ID to", "dplay.type_0f.id_to", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_0f_id,
        { "Player ID", "dplay.type_0f.player_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_0f_data_size,
        { "Data Size", "dplay.multi.group_id", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_0f_data_offset,
        { "Data Offset", "dplay.type_0f.data_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_0f_data,
        { "Player Data", "dplay.type_0f.player_data", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* Data fields for message type 0x0013 */
    { &hf_dplay_type_13_id_to,
        { "ID to", "dplay.type_13.id_to", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_13_player_id,
        { "Player ID", "dplay.type_13.player_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_13_group_id,
        { "Group ID", "dplay.type_13.group_id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_13_create_offset,
        { "Create Offset", "dplay.type_13.create_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_13_password_offset,
        { "Password Offset", "dplay.type_13.password_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_13_password,
        { "Password", "dplay.type_13.password", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_13_tick_count,
        { "Tick count? Looks like an ID", "dplay.type_13.tick_count", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* Data fields for message type 0x0015 */
    { &hf_dplay_message_guid,
        { "Message GUID", "dplay.message.guid", FT_GUID, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_15_packet_idx,
        { "Packet Index", "dplay.type_15.packet_idx", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_15_data_size,
        { "Data Size", "dplay.type_15.data_size", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_15_offset,
        { "Offset", "dplay.type_15.offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_15_total_packets,
        { "Total Packets", "dplay.type_15.total_packets", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_15_msg_size,
        { "Message size", "dplay.type_15.message.size", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_15_packet_offset,
        { "Packet offset", "dplay.type_15.packet_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},

    /* Data field for message type 0x0016 and 0x0017 */
    { &hf_dplay_ping_id_from,
        { "ID From", "dplay.ping.id_from", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_ping_tick_count,
        { "Tick Count", "dplay.ping.tick_count", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},

    /* Data fields for message type 0x001a */
    { &hf_dplay_type_1a_id_to,
        { "ID From", "dplay.type_1a.id_to", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_1a_sess_name_ofs,
        { "Session Name Offset", "dplay.type_1a.sess_name_ofs", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_1a_password_ofs,
        { "Password Offset", "dplay.type_1a.password_offset", FT_UINT32, BASE_DEC,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_1a_session_name,
        { "Session Name", "dplay.type_1a.session_name", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_1a_password,
        { "Password", "dplay.type_1a.password", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* Data fields for message type 0x0029 */
    { &hf_dplay_type_29_player_count,
        { "SuperEnumPlayers Reply player count", "dplay.type_29.player_count", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_29_group_count,
        { "SuperEnumPlayers Reply group count", "dplay.type_29.group_count", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_29_packed_offset,
        { "SuperEnumPlayers Reply packed offset", "dplay.type_29.packed_offset", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_29_shortcut_count,
        { "SuperEnumPlayers Reply shortcut count", "dplay.type_29.shortcut_count", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_29_description_offset,
        { "SuperEnumPlayers Reply description offset", "dplay.type_29.desc_offset", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_29_name_offset,
        { "SuperEnumPlayers Reply name offset", "dplay.type_29.name_offset", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_29_password_offset,
        { "SuperEnumPlayers Reply password offset", "dplay.type_29.pass_offset", FT_UINT32,
        BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_29_game_name,
        { "SuperEnumPlayers Reply game name", "dplay.type_29.game_name", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    { &hf_dplay_type_29_password,
        { "SuperEnumPlayers Reply Password", "dplay.type_29.password", FT_STRING, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},

    /* Data fields for message type 0x002f */
    { &hf_dplay_type_2f_dpid,
        { "ID of the forwarded player", "dplay.type_29.id", FT_BYTES, BASE_NONE,
        NULL, 0x0, NULL, HFILL}},
    };

    static gint *ett[] = {
        &ett_dplay,
        &ett_dplay_header,
        &ett_dplay_sockaddr,
        &ett_dplay_data,
        &ett_dplay_flags,
        &ett_dplay_enc_packet,
        &ett_dplay_sess_desc_flags,
        &ett_dplay_pp_flags,
        &ett_dplay_spp_flags,
        &ett_dplay_spp_info_mask,
        &ett_dplay_type02_flags,
        &ett_dplay_type05_flags,
        &ett_dplay_type29_spp,
    };

    proto_dplay = proto_register_protocol (
        "DirectPlay Protocol",
        "DPLAY",
        "dplay"
        );
    proto_register_field_array(proto_dplay, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_dplay(void)
{
    heur_dissector_add("udp", heur_dissect_dplay, proto_dplay);
    heur_dissector_add("tcp", heur_dissect_dplay, proto_dplay);
}

