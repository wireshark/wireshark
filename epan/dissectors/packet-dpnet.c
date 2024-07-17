/* packet-dpnet.c
 * This is a dissector for the DirectPlay 8 protocol.
 *
 * Copyright 2017 - Alistair Leslie-Hughes
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_dpnet(void);
void proto_reg_handoff_dpnet(void);

static dissector_handle_t dpnet_handle;

#define DPNET_PORT 6073

static int proto_dpnet;

static int hf_dpnet_lead;
static int hf_dpnet_command;
static int hf_dpnet_payload;
static int hf_dpnet_type;
static int hf_dpnet_application;
static int hf_dpnet_data;
static int hf_dpnet_reply_offset;
static int hf_dpnet_response_size;

static int hf_dpnet_desc_size;
static int hf_dpnet_desc_flags;
static int hf_dpnet_max_players;
static int hf_dpnet_current_players;
static int hf_dpnet_session_offset;
static int hf_dpnet_session_size;
static int hf_dpnet_session_name;
static int hf_dpnet_password_offset;
static int hf_dpnet_password_size;
static int hf_dpnet_reserved_offset;
static int hf_dpnet_reserved_size;
static int hf_dpnet_application_offset;
static int hf_dpnet_application_size;
static int hf_dpnet_application_data;
static int hf_dpnet_instance;
static int hf_dpnet_data_cframe_control;
static int hf_dpnet_data_cframe_msgid;
static int hf_dpnet_data_cframe_rspid;
static int hf_dpnet_data_cframe_protocol;
static int hf_dpnet_data_cframe_session;
static int hf_dpnet_data_cframe_timestamp;
static int hf_dpnet_data_cframe_padding;
static int hf_dpnet_data_cframe_flags;
static int hf_dpnet_data_cframe_retry;
static int hf_dpnet_data_cframe_nseq;
static int hf_dpnet_data_cframe_nrcv;
static int hf_dpnet_data_cframe_sack_mask1;
static int hf_dpnet_data_cframe_sack_mask2;
static int hf_dpnet_data_cframe_send_mask1;
static int hf_dpnet_data_cframe_send_mask2;
static int hf_dpnet_data_cframe_signature;
static int hf_dpnet_data_cframe_send_secret;
static int hf_dpnet_data_cframe_recv_secret;
static int hf_dpnet_data_cframe_signing_opts;
static int hf_dpnet_data_cframe_echo_time;
static int hf_dpnet_data_seq;
static int hf_dpnet_data_nseq;
static int hf_dpnet_data_command;
static int hf_dpnet_command_data;
static int hf_dpnet_command_reliable;
static int hf_dpnet_command_seq;
static int hf_dpnet_command_poll;
static int hf_dpnet_command_new_msg;
static int hf_dpnet_command_end_msg;
static int hf_dpnet_command_user1;
static int hf_dpnet_command_user2;
static int hf_dpnet_desc_client_server;
static int hf_dpnet_desc_migrate_host;
static int hf_dpnet_desc_nodpnsvr;
static int hf_dpnet_desc_req_password;
static int hf_dpnet_desc_no_enums;
static int hf_dpnet_desc_fast_signed;
static int hf_dpnet_desc_full_signed;

static int ett_dpnet;
static int ett_dpnet_command_flags;
static int ett_dpnet_desc_flags;

#define DPNET_QUERY_GUID     0x01

#define DPNET_ENUM_QUERY     0x02
#define DPNET_ENUM_RESPONSE  0x03

#define DPNET_COMMAND_DATA                   0x01
#define DPNET_COMMAND_RELIABLE               0x02
#define DPNET_COMMAND_SEQUENTIAL             0x04
#define DPNET_COMMAND_POLL                   0x08
#define DPNET_COMMAND_NEW_MSG                0x10
#define DPNET_COMMAND_END_MSG                0x20
#define DPNET_COMMAND_USER_1                 0x40
#define DPNET_COMMAND_CFRAME                 0x80

#define DN_MSG_INTERNAL_PLAYER_CONNECT_INFO  0x000000c1
#define DN_MSG_INTERNAL_SEND_CONNECT_INFO    0x000000c2
#define DN_MSG_INTERNAL_ACK_CONNECT_INFO     0x000000c3

#define FRAME_EXOPCODE_CONNECT               0x01
#define FRAME_EXOPCODE_CONNECTED             0x02
#define FRAME_EXOPCODE_CONNECTED_SIGNED      0x03
#define FRAME_EXOPCODE_HARD_DISCONNECT       0x04
#define FRAME_EXOPCODE_SACK                  0x06

#define PROTOCOL_VER_0                       0x00010000
#define PROTOCOL_VER_1                       0x00010001
#define PROTOCOL_VER_2                       0x00010002
#define PROTOCOL_VER_3                       0x00010003
#define PROTOCOL_VER_4                       0x00010004
#define PROTOCOL_VER_5                       0x00010005
#define PROTOCOL_VER_6                       0x00010006

#define SACK_FLAGS_RESPONSE                  0x01
#define SACK_FLAGS_SACK_MASK1                0x02
#define SACK_FLAGS_SACK_MASK2                0x04
#define SACK_FLAGS_SEND_MASK1                0x08
#define SACK_FLAGS_SEND_MASK2                0x10

#define PACKET_SIGNING_FAST                  0x01
#define PACKET_SIGNING_FULL                  0x02

#define SESSION_CLIENT_SERVER                0x0001
#define SESSION_MIGRATE_HOST                 0x0004
#define SESSION_NODPNSVR                     0x0040
#define SESSION_REQUIREPASSWORD              0x0080
#define SESSION_NOENUMS                      0x0100
#define SESSION_FAST_SIGNED                  0x0200
#define SESSION_FULL_SIGNED                  0x0400

static const value_string packetenumttypes[] = {
    { 1, "Application GUID" },
    { 2, "All Applications" },
    { 0, NULL }
};

static const value_string packetquerytype[] = {
    { 2, "Enumeration Query" },
    { 3, "Enumeration Response" },
    { 0, NULL }
};

static const value_string msg_cframe_control[] = {
    {FRAME_EXOPCODE_CONNECT,              "FRAME_EXOPCODE_CONNECT"},
    {FRAME_EXOPCODE_CONNECTED,            "FRAME_EXOPCODE_CONNECTED"},
    {FRAME_EXOPCODE_CONNECTED_SIGNED,     "FRAME_EXOPCODE_CONNECTED_SIGNED"},
    {FRAME_EXOPCODE_HARD_DISCONNECT,      "FRAME_EXOPCODE_HARD_DISCONNECT"},
    {FRAME_EXOPCODE_SACK,                 "FRAME_EXOPCODE_SACK"},
    {0, NULL }
};

static const value_string protocol_versions[] = {
    {PROTOCOL_VER_0,                      "Supports Base Features"},
    {PROTOCOL_VER_1,                      "Supports Base Features"},
    {PROTOCOL_VER_2,                      "Supports Base Features"},
    {PROTOCOL_VER_3,                      "Supports Base Features"},
    {PROTOCOL_VER_4,                      "Supports Base Features"},
    {PROTOCOL_VER_5,                      "Supports Coalescence"},
    {PROTOCOL_VER_6,                      "Supports Coalescence and Signing"},
    {0, NULL }
};

static const value_string sack_flags[] = {
    {SACK_FLAGS_RESPONSE,                  "Retry field is valid"},
    {SACK_FLAGS_SACK_MASK1,                "Low 32 bits of the SACK mask are present in sack.mask1"},
    {SACK_FLAGS_SACK_MASK2,                "High 32 bits of the SACK mask are present in sack.mask2"},
    {SACK_FLAGS_SEND_MASK1,                "Low 32 bits of the Send mask are present in send.mask1"},
    {SACK_FLAGS_SEND_MASK2,                "High 32 bits of the Send mask are present in send.mask2"},
    {0, NULL }
};

static const value_string signing_opts[] = {
    {PACKET_SIGNING_FAST,                "Fasting signing"},
    {PACKET_SIGNING_FULL,                "Full signing"},
    {0, NULL }
};

static const true_false_string tfs_flags_game_client = {
    "Client/Server session",
    "Peer session"
};

static const true_false_string tfs_flags_migrate = {
    "Host Migrating allowed",
    "Host Migrating NOT allowed"
};

static const true_false_string tfs_flags_dpnsvr = {
    "NOT using dpnsvr.exe",
    "Using dpnsvr.exe"
};

static const true_false_string tfs_flags_password_required = {
    "Password required",
    "NO password required"
};

static const true_false_string tfs_flags_enumeration = {
    "Enumeration NOT allowed",
    "Enumeration allowed"
};

static const true_false_string tfs_flags_fast = {
    "Using Fast signing",
    "NOT using Fast signing"
};

static const true_false_string tfs_flags_full = {
    "Using Full signing",
    "NOT using Full signing"
};


static int * const desc_flags[] = {
    &hf_dpnet_desc_client_server,
    &hf_dpnet_desc_migrate_host,
    &hf_dpnet_desc_nodpnsvr,
    &hf_dpnet_desc_req_password,
    &hf_dpnet_desc_no_enums,
    &hf_dpnet_desc_fast_signed,
    &hf_dpnet_desc_full_signed,
    NULL
};

static int * const command_flags[] = {
    &hf_dpnet_command_data,
    &hf_dpnet_command_reliable,
    &hf_dpnet_command_seq,
    &hf_dpnet_command_poll,
    &hf_dpnet_command_new_msg,
    &hf_dpnet_command_end_msg,
    &hf_dpnet_command_user1,
    &hf_dpnet_command_user2,
    NULL
};

static void process_dpnet_query(proto_tree *dpnet_tree, tvbuff_t *tvb, packet_info *pinfo)
{
    int offset = 0, data_tvb_len;
    uint8_t has_guid;
    uint8_t is_query;

    proto_tree_add_item(dpnet_tree, hf_dpnet_lead, tvb, 0, 1, ENC_BIG_ENDIAN); offset += 1;
    is_query = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(dpnet_tree, hf_dpnet_command, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;
    proto_tree_add_item(dpnet_tree, hf_dpnet_payload, tvb, offset, 2, ENC_LITTLE_ENDIAN); offset += 2;

    if(is_query == DPNET_ENUM_QUERY)
    {
        col_set_str(pinfo->cinfo, COL_INFO, "DPNET Enum Query");

        has_guid = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(dpnet_tree, hf_dpnet_type, tvb, offset, 1, ENC_BIG_ENDIAN); offset += 1;

        if (has_guid & DPNET_QUERY_GUID) {
            proto_tree_add_item(dpnet_tree, hf_dpnet_application, tvb, offset, 16, ENC_BIG_ENDIAN);
            offset += 16;
        }

        data_tvb_len = tvb_reported_length_remaining(tvb, offset);
        if(data_tvb_len)
            proto_tree_add_item(dpnet_tree, hf_dpnet_data, tvb, offset, data_tvb_len, ENC_NA);

    }
    else if(is_query == DPNET_ENUM_RESPONSE)
    {
        uint32_t session_offset, session_size;
        uint32_t application_offset, application_size;

        col_set_str(pinfo->cinfo, COL_INFO, "DPNET Enum Response");

        proto_tree_add_item(dpnet_tree, hf_dpnet_reply_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_response_size, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_desc_size, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_bitmask(dpnet_tree, tvb, offset, hf_dpnet_desc_flags, ett_dpnet_desc_flags, desc_flags, ENC_LITTLE_ENDIAN);
        offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_max_players, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_current_players, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item_ret_uint(dpnet_tree, hf_dpnet_session_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &session_offset); offset += 4;
        proto_tree_add_item_ret_uint(dpnet_tree, hf_dpnet_session_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &session_size); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_password_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_password_size, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_reserved_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_reserved_size, tvb, offset, 4, ENC_LITTLE_ENDIAN); offset += 4;
        proto_tree_add_item_ret_uint(dpnet_tree, hf_dpnet_application_offset, tvb, offset, 4, ENC_LITTLE_ENDIAN, &application_offset); offset += 4;
        proto_tree_add_item_ret_uint(dpnet_tree, hf_dpnet_application_size, tvb, offset, 4, ENC_LITTLE_ENDIAN, &application_size); offset += 4;
        proto_tree_add_item(dpnet_tree, hf_dpnet_instance, tvb, offset, 16, ENC_LITTLE_ENDIAN); offset += 16;
        proto_tree_add_item(dpnet_tree, hf_dpnet_application, tvb, offset, 16, ENC_LITTLE_ENDIAN);

        if(session_offset)
        {
            /* session_offset starts from the hf_dpnet_payload */
            proto_tree_add_item(dpnet_tree, hf_dpnet_session_name, tvb, session_offset + 4, session_size, ENC_UTF_16|ENC_LITTLE_ENDIAN);
        }

        if(application_offset)
        {
            /* application_offset starts from the hf_dpnet_payload */
            proto_tree_add_item(dpnet_tree, hf_dpnet_application_data, tvb, application_offset + 4, application_size, ENC_NA);
        }
    }
}

static void
dpnet_process_data_frame(proto_tree *dpnet_tree, tvbuff_t *tvb, packet_info *pinfo)
{
    int offset = 0;

    col_set_str(pinfo->cinfo, COL_INFO, "DPNET DFrame");

    proto_tree_add_bitmask(dpnet_tree, tvb, offset, hf_dpnet_data_command, ett_dpnet_command_flags, command_flags, ENC_BIG_ENDIAN);

    /* TODO */
}

static void
dpnet_process_control_frame(proto_tree *dpnet_tree, tvbuff_t *tvb, packet_info *pinfo)
{
    int offset = 0;
    int command;
    const char *command_str;
    int flag;
    uint32_t data_tvb_len;

    col_set_str(pinfo->cinfo, COL_INFO, "DPNET CFrame");

    proto_tree_add_bitmask(dpnet_tree, tvb, offset, hf_dpnet_data_command, ett_dpnet_command_flags, command_flags, ENC_BIG_ENDIAN);
    offset += 1;

    command = tvb_get_uint8(tvb, offset);
    command_str = val_to_str_const(command, msg_cframe_control, "Unknown Control (obsolete or malformed?)");
    col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", command_str);

    proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_control, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    switch(command)
    {
        case FRAME_EXOPCODE_CONNECT:
        case FRAME_EXOPCODE_CONNECTED:
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_msgid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_rspid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_protocol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_session, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case FRAME_EXOPCODE_CONNECTED_SIGNED:
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_msgid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_rspid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_protocol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_session, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_signature, tvb, offset, 8, ENC_NA);
            offset += 8;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_send_secret, tvb, offset, 8, ENC_NA);
            offset += 8;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_recv_secret, tvb, offset, 8, ENC_NA);
            offset += 8;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_signing_opts, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_echo_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            break;
        case FRAME_EXOPCODE_HARD_DISCONNECT:
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_msgid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_rspid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_protocol, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_session, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            data_tvb_len = tvb_reported_length_remaining(tvb, offset);
            if(data_tvb_len)
                proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_signature, tvb, offset, 8, ENC_NA);
            break;
        case FRAME_EXOPCODE_SACK:
            flag = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_retry, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_nseq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_nrcv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_padding, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset += 2;
            proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_timestamp, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset += 4;

            if(flag & SACK_FLAGS_SACK_MASK1)
            {
                proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_sack_mask1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }
            if(flag & SACK_FLAGS_SACK_MASK2)
            {
                proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_sack_mask2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }
            if(flag & SACK_FLAGS_SEND_MASK1)
            {
                proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_send_mask1, tvb, offset, 4, ENC_LITTLE_ENDIAN);
                offset += 4;
            }
            if(flag & SACK_FLAGS_SEND_MASK2)
            {
                proto_tree_add_item(dpnet_tree, hf_dpnet_data_cframe_send_mask2, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            }
            break;
        default:
            break;
    }
}

static int
dissect_dpnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint8_t lead;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPNET");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_dpnet, tvb, 0, -1, ENC_NA);
    proto_tree *dpnet_tree = proto_item_add_subtree(ti, ett_dpnet);

    lead = tvb_get_uint8(tvb, 0);
    if(lead == 0)
    {
        process_dpnet_query(dpnet_tree, tvb, pinfo);
    }
    else
    {
        if(lead & DPNET_COMMAND_DATA)
            dpnet_process_data_frame(dpnet_tree, tvb, pinfo);
        else
            dpnet_process_control_frame(dpnet_tree, tvb, pinfo);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_dpnet(void)
{
    static hf_register_info hf[] = {
        { &hf_dpnet_lead,
            { "Lead", "dpnet.lead",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_command,
            { "Command", "dpnet.command",
            FT_UINT8, BASE_HEX,
            VALS(packetquerytype), 0,
            NULL, HFILL }
        },
        { &hf_dpnet_payload,
            { "Payload", "dpnet.payload",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_type,
            { "Type", "dpnet.type",
            FT_UINT8, BASE_DEC,
            VALS(packetenumttypes), 0,
            NULL, HFILL }
        },
        { &hf_dpnet_application,
            { "Application GUID", "dpnet.application",
            FT_GUID, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data,
            { "Data", "dpnet.data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_reply_offset,
            { "Reply Offset", "dpnet.reply_offset",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_response_size,
            { "Response Size", "dpnet.response_size",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_desc_size,
            { "Description Size", "dpnet.desc_size",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_desc_flags,
            { "Description Flags", "dpnet.desc_flags",
            FT_UINT16, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_max_players,
            { "Max Players", "dpnet.max_players",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_current_players,
            { "Current Players", "dpnet.current_players",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_session_offset,
            { "Session Offset", "dpnet.session_offset",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_session_size,
            { "Session Size", "dpnet.session_size",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_session_name,
            { "Session name", "dpnet.session_name",
            FT_STRING, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_password_offset,
            { "Password Offset", "dpnet.password_offset",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_password_size,
            { "Password Size", "dpnet.password_size",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_reserved_offset,
            { "Reserved Offset", "dpnet.reserved_offset",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_reserved_size,
            { "Reserved Size", "dpnet.reserved_size",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_application_offset,
            { "Application Offset", "dpnet.application_offset",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_application_size,
            { "Application Size", "dpnet.application_size",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_application_data,
            { "Application data", "dpnet.application_data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_instance,
            { "Instance GUID", "dpnet.instance",
            FT_GUID, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_command,
            { "Command", "dpnet.command",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_control,
            { "Control", "dpnet.cframe.control",
            FT_UINT8, BASE_HEX,
            VALS(msg_cframe_control), 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_msgid,
            { "Message ID", "dpnet.cframe.msg_id",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_rspid,
            { "Response ID", "dpnet.cframe.rsp_id",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_protocol,
            { "Protocol", "dpnet.cframe.protocol",
            FT_UINT32, BASE_HEX,
            VALS(protocol_versions), 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_session,
            { "Session", "dpnet.cframe.session",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_timestamp,
            { "Timestamp", "dpnet.cframe.timestamp",
            FT_UINT32, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_padding,
            { "Padding", "dpnet.cframe.padding",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_flags,
            { "Flags", "dpnet.cframe.flags",
            FT_UINT8, BASE_HEX,
            VALS(sack_flags), 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_retry,
            { "Retry", "dpnet.cframe.retry",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_nseq,
            { "Next Sequence", "dpnet.cframe.nseq",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_nrcv,
            { "Received", "dpnet.cframe.nrcv",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_sack_mask1,
            { "SACK Mask1", "dpnet.cframe.sack.mask1",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_sack_mask2,
            { "SACK Mask2", "dpnet.cframe.sack.mask2",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_send_mask1,
            { "Send Mask1", "dpnet.cframe.send.mask1",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_send_mask2,
            { "Send Mask2", "dpnet.cframe.send.mask2",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_signature,
            { "Signature", "dpnet.cframe.signature",
            FT_UINT64, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_send_secret,
            { "Sender Secret", "dpnet.cframe.sender_secret",
            FT_UINT64, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_recv_secret,
            { "Receiver Secret", "dpnet.cframe.receiver_secret",
            FT_UINT64, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_signing_opts,
            { "Signing Options", "dpnet.cframe.sign_opt",
            FT_UINT32, BASE_HEX,
            VALS(signing_opts), 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_cframe_echo_time,
            { "Signing Options", "dpnet.cframe.echo_time",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_seq,
            { "Sequence", "dpnet.sequence",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_dpnet_data_nseq,
            { "Next Sequence", "dpnet.next",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        {&hf_dpnet_command_data,
            {"Control Data", "dpnet.control.data",
            FT_BOOLEAN, 8,
            NULL, DPNET_COMMAND_DATA,
            NULL, HFILL}
        },
        {&hf_dpnet_command_reliable,
            {"Reliable", "dpnet.control.reliable",
            FT_BOOLEAN, 8,
            NULL, DPNET_COMMAND_RELIABLE,
            NULL, HFILL}
        },
        {&hf_dpnet_command_seq,
            {"Sequential", "dpnet.control.sequential",
            FT_BOOLEAN, 8,
            NULL, DPNET_COMMAND_SEQUENTIAL,
            NULL, HFILL}
        },
        {&hf_dpnet_command_poll,
            {"Poll", "dpnet.control.poll",
            FT_BOOLEAN, 8,
            NULL, DPNET_COMMAND_POLL,
            NULL, HFILL}
        },
        {&hf_dpnet_command_new_msg,
            {"New Message", "dpnet.control.new_msg",
            FT_BOOLEAN, 8,
            NULL, DPNET_COMMAND_NEW_MSG,
            NULL, HFILL}
        },
        {&hf_dpnet_command_end_msg,
            {"End Message", "dpnet.control.end_msg",
            FT_BOOLEAN, 8,
            NULL, DPNET_COMMAND_END_MSG,
            NULL, HFILL}
        },
        {&hf_dpnet_command_user1,
            {"User 1", "dpnet.control.user1",
            FT_BOOLEAN, 8,
            NULL, DPNET_COMMAND_USER_1,
            NULL, HFILL}
        },
        {&hf_dpnet_command_user2,
            {"CFrame", "dpnet.control.cframe",
            FT_BOOLEAN, 8,
            NULL, DPNET_COMMAND_CFRAME,
            NULL, HFILL}
        },
        {&hf_dpnet_desc_client_server,
            {"Client", "dpnet.session.client",
            FT_BOOLEAN, 16,
            TFS(&tfs_flags_game_client), SESSION_CLIENT_SERVER,
            NULL, HFILL}
        },
        {&hf_dpnet_desc_migrate_host,
            {"Migrate", "dpnet.session.migrate",
            FT_BOOLEAN, 16,
            TFS(&tfs_flags_migrate), SESSION_MIGRATE_HOST,
            NULL, HFILL}
        },
        {&hf_dpnet_desc_nodpnsvr,
            {"dpnsvr", "dpnet.session.dpnsvr",
            FT_BOOLEAN, 16,
            TFS(&tfs_flags_dpnsvr), SESSION_NODPNSVR,
            NULL, HFILL}
        },
        {&hf_dpnet_desc_req_password,
            {"Password", "dpnet.session.password",
            FT_BOOLEAN, 16,
            TFS(&tfs_flags_password_required), SESSION_REQUIREPASSWORD,
            NULL, HFILL}
        },
        {&hf_dpnet_desc_no_enums,
            {"Enumeration", "dpnet.session.enumeration",
            FT_BOOLEAN, 16,
            TFS(&tfs_flags_enumeration), SESSION_NOENUMS,
            NULL, HFILL}
        },
        {&hf_dpnet_desc_fast_signed,
            {"Fast signing", "dpnet.session.fast_sign",
            FT_BOOLEAN, 16,
            TFS(&tfs_flags_fast), SESSION_FAST_SIGNED,
            NULL, HFILL}
        },
        {&hf_dpnet_desc_full_signed,
            {"Full signing", "dpnet.session.full_sign",
            FT_BOOLEAN, 16,
            TFS(&tfs_flags_full), SESSION_FULL_SIGNED,
            NULL, HFILL}
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_dpnet,
        &ett_dpnet_command_flags,
        &ett_dpnet_desc_flags
    };


    proto_dpnet = proto_register_protocol ("DirectPlay 8 protocol", "DPNET", "dpnet");

    proto_register_field_array(proto_dpnet, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    dpnet_handle = register_dissector("dpnet", dissect_dpnet, proto_dpnet);
}

void
proto_reg_handoff_dpnet(void)
{
    dissector_add_uint("udp.port", DPNET_PORT, dpnet_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
