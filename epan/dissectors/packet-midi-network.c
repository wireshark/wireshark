/* packet-midi-network.c
 * Network MIDI 2.0 dissector
 *
 * Copyright (c) 2026 by Matt Morris <mattm.dev.1[AT]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include "packet-midi.h"

#define NMP_IDENTIFIER ((const uint8_t*)"MIDI")
#define NMP_IDENTIFIER_LEN (4)

/* protocols and header fields */
static int proto_nmp;

static dissector_handle_t nmp_handle;

static int ett_nmp;
static int ett_nmp_command;
static int ett_nmp_invitation_capabilities;
static int ett_nmp_nak_header;

static int hf_nmp_signature;
static int hf_nmp_command;
static int hf_nmp_command_code;
static int hf_nmp_payload_length;
static int hf_nmp_command_specific_data;
static int hf_nmp_reserved;

static int hf_nmp_sequence_number;

static int hf_nmp_invitation_capabilities;
static int hf_nmp_invitation_capabilities_auth;
static int hf_nmp_invitation_capabilities_user_auth;
static int hf_nmp_invitation_endpoint_name_len;
static int hf_nmp_invitation_endpoint_name;
static int hf_nmp_invitation_product_instance_id;
static int hf_nmp_invitation_auth_digest;
static int hf_nmp_invitation_user_name;
static int hf_nmp_invitation_auth_state;
static int hf_nmp_invitation_crypto_nonce;

static int hf_nmp_ping_id;
static int hf_nmp_retransmit_command_count;
static int hf_nmp_retransmit_error;
static int hf_nmp_bye_reason;
static int hf_nmp_bye_message;

static int hf_nmp_nak_reason;
static int hf_nmp_nak_header;
static int hf_nmp_nak_message;

static int hf_nmp_ping_response_in;
static int hf_nmp_ping_response_to;
static int hf_nmp_ping_response_time;

typedef struct _nmp_ping_transaction_t {
    uint32_t req_frame;
    uint32_t rep_frame;
    nstime_t req_time;
} nmp_ping_transaction_t;
typedef struct _nmp_conv_info_t {
    /* Map from (uint32_t ping_id) to (nmp_ping_transaction_t) */
    wmem_map_t *ping_pdus;
} nmp_conv_info_t;

#define NMP_COMMAND_UMP_DATA                       0xFF
#define NMP_COMMAND_INVITATION                     0x01
#define NMP_COMMAND_INVITATION_AUTH                0x02
#define NMP_COMMAND_INVITATION_USER_AUTH           0x03
#define NMP_COMMAND_INVITATION_REPLY_ACCEPT        0x10
#define NMP_COMMAND_INVITATION_REPLY_PENDING       0x11
#define NMP_COMMAND_INVITATION_REPLY_AUTH_REQ      0x12
#define NMP_COMMAND_INVITATION_REPLY_USER_AUTH_REQ 0x13
#define NMP_COMMAND_PING                           0x20
#define NMP_COMMAND_PING_REPLY                     0x21
#define NMP_COMMAND_RETRANSMIT_REQ                 0x80
#define NMP_COMMAND_RETRANSMIT_ERROR               0x81
#define NMP_COMMAND_SESSION_RESET                  0x82
#define NMP_COMMAND_SESSION_RESET_REPLY            0x83
#define NMP_COMMAND_NAK                            0x8F
#define NMP_COMMAND_BYE                            0xF0
#define NMP_COMMAND_BYE_REPLY                      0xF1
static const value_string nmp_command_names[] = {
    { NMP_COMMAND_INVITATION,                     "Invitation" },
    { NMP_COMMAND_INVITATION_AUTH,                "Invitation with Authentication" },
    { NMP_COMMAND_INVITATION_USER_AUTH,           "Invitation with User Authentication" },
    { NMP_COMMAND_INVITATION_REPLY_ACCEPT,        "Invitation Reply: Accepted" },
    { NMP_COMMAND_INVITATION_REPLY_PENDING,       "Invitation Reply: Pending" },
    { NMP_COMMAND_INVITATION_REPLY_AUTH_REQ,      "Invitation Reply: Authentication Required" },
    { NMP_COMMAND_INVITATION_REPLY_USER_AUTH_REQ, "Invitation Reply: User Authentication Required" },
    { NMP_COMMAND_PING,                           "Ping" },
    { NMP_COMMAND_PING_REPLY,                     "Ping Reply" },
    { NMP_COMMAND_RETRANSMIT_REQ,                 "Retransmit Request" },
    { NMP_COMMAND_RETRANSMIT_ERROR,               "Retransmit Error" },
    { NMP_COMMAND_SESSION_RESET,                  "Session Reset" },
    { NMP_COMMAND_SESSION_RESET_REPLY,            "Session Reset Reply" },
    { NMP_COMMAND_NAK,                            "NAK" },
    { NMP_COMMAND_BYE,                            "Bye" },
    { NMP_COMMAND_BYE_REPLY,                      "Bye Reply" },
    { NMP_COMMAND_UMP_DATA,                       "UMP Data" },
    { 0, NULL }
};

static const value_string nmp_invitation_auth_state[] = {
    { 0x00, "First request" },
    { 0x01, "Digest incorrect" },
    { 0x02, "Username not found" },
    { 0, NULL }
};

static const value_string nmp_retransmit_error[] = {
    { 0x00, "Unknown" },
    { 0x01, "Not in Transmit Buffer" },
    { 0, NULL }
};

static const value_string nmp_bye_reason[] = {
    { 0x00, "Unknown or Undefined" },
    { 0x01, "User terminated session" },
    { 0x02, "Power Down" },
    { 0x03, "Too Many Missing Packets" },
    { 0x04, "Timeout" },
    { 0x05, "Session Not Established" },
    { 0x06, "No Pending Session" },
    { 0x07, "Protocol Error" },
    { 0x40, "Invitation Failed: too many sessions" },
    { 0x41, "Auth Rejected: missing prior unauthenticated invitation" },
    { 0x42, "Invitation Rejected: user did not accept session" },
    { 0x43, "Invitation Rejected: authentication failed" },
    { 0x44, "Invitation Rejected: username not found" },
    { 0x45, "No Matching Authentication Method" },
    { 0x80, "Invitation Canceled" },
    { 0, NULL }
};

static const value_string nmp_nak_reason[] = {
    { 0x00, "Other" },
    { 0x01, "Command Not Supported" },
    { 0x02, "Command Not Expected" },
    { 0x03, "Command Malformed" },
    { 0x20, "Bad Ping Reply" },
    { 0, NULL }
};

static int* const nmp_invitation_capabilities[] = {
    &hf_nmp_invitation_capabilities_auth,
    &hf_nmp_invitation_capabilities_user_auth,
    NULL
};

static void
dissect_nmp_ump_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned offset, unsigned end_offset, proto_item* parent) {
    uint16_t seq;
    int ump_count = 0;
    proto_tree_add_item_ret_uint16(tree, hf_nmp_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN, &seq);
    offset += 2;

    while (end_offset > offset) {
        unsigned new_offset = dissect_midi_ump_message(tvb, pinfo, tree, offset, ENC_BIG_ENDIAN);
        if (new_offset <= offset)
        break;
        offset = new_offset;
        ump_count += 1;
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, " (seq=%d, count=%d)", seq, ump_count);
    proto_item_append_text(parent, ", %d UMPs", ump_count);
}

static void
dissect_nmp_invitation(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned offset, unsigned end_offset, uint8_t command_code) {
    if (command_code == NMP_COMMAND_INVITATION) {
        uint8_t ep_name_len;
        proto_tree_add_item_ret_uint8(tree, hf_nmp_invitation_endpoint_name_len, tvb, offset, 1, ENC_NA, &ep_name_len);
        offset += 1;

        proto_tree_add_bitmask(tree, tvb, offset, hf_nmp_invitation_capabilities,
            ett_nmp_invitation_capabilities, nmp_invitation_capabilities, ENC_NA);
        offset += 1;

        const uint8_t* ep_name;
        proto_tree_add_item_ret_string(tree, hf_nmp_invitation_endpoint_name, tvb, offset, ep_name_len*4, ENC_UTF_8, pinfo->pool, &ep_name);
        offset += ep_name_len * 4;
        proto_tree_add_item(tree, hf_nmp_invitation_product_instance_id, tvb, offset, end_offset-offset, ENC_UTF_8);

        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", ep_name);
    } else {
        proto_tree_add_item(tree, hf_nmp_reserved, tvb, offset, 2, ENC_NA);
        offset += 2;

        proto_tree_add_item(tree, hf_nmp_invitation_auth_digest, tvb, offset, 32, ENC_NA);
        offset += 32;

        if (command_code == NMP_COMMAND_INVITATION_USER_AUTH) {
            proto_tree_add_item(tree, hf_nmp_invitation_user_name, tvb, offset, end_offset-offset, ENC_UTF_8);
        }
    }
}

static void
dissect_nmp_invitation_reply(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, unsigned offset, unsigned end_offset, uint8_t command_code) {
    uint8_t ep_name_len;
    proto_tree_add_item_ret_uint8(tree, hf_nmp_invitation_endpoint_name_len, tvb, offset, 1, ENC_NA, &ep_name_len);
    offset += 1;

    if (command_code==NMP_COMMAND_INVITATION_REPLY_AUTH_REQ || command_code==NMP_COMMAND_INVITATION_REPLY_USER_AUTH_REQ) {
        proto_tree_add_item(tree, hf_nmp_invitation_auth_state, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(tree, hf_nmp_invitation_crypto_nonce, tvb, offset, 16, ENC_ASCII);
        offset += 16;
    } else {
        proto_tree_add_item(tree, hf_nmp_reserved, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    const uint8_t* ep_name;
    proto_tree_add_item_ret_string(tree, hf_nmp_invitation_endpoint_name, tvb, offset, ep_name_len*4, ENC_UTF_8, pinfo->pool, &ep_name);
    offset += ep_name_len * 4;

    proto_tree_add_item(tree, hf_nmp_invitation_product_instance_id, tvb, offset, end_offset-offset, ENC_UTF_8);

    col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", ep_name);
}

static void
dissect_nmp_nak(tvbuff_t* tvb, proto_tree* tree, unsigned offset, unsigned end_offset) {
    proto_tree_add_item(tree, hf_nmp_nak_reason, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_nmp_reserved, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_item* pi = proto_tree_add_item(tree, hf_nmp_nak_header, tvb, offset, 4, ENC_NA);
    proto_tree* tr = proto_item_add_subtree(pi, ett_nmp_nak_header);
    {
        uint8_t cc;
        proto_tree_add_item_ret_uint8(tr, hf_nmp_command_code, tvb, offset, 1, ENC_NA, &cc);
        offset += 1;
        proto_tree_add_item(tr, hf_nmp_payload_length, tvb, offset, 1, ENC_NA);
        offset += 1;
        switch(cc) {
            case NMP_COMMAND_UMP_DATA:
                proto_tree_add_item(tr, hf_nmp_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case NMP_COMMAND_INVITATION:
                proto_tree_add_item(tr, hf_nmp_invitation_endpoint_name_len, tvb, offset, 1, ENC_NA);
                proto_tree_add_bitmask(tr, tvb, offset+1, hf_nmp_invitation_capabilities,
                    ett_nmp_invitation_capabilities, nmp_invitation_capabilities, ENC_NA);
                break;
            case NMP_COMMAND_INVITATION_REPLY_ACCEPT:
            case NMP_COMMAND_INVITATION_REPLY_PENDING:
                proto_tree_add_item(tr, hf_nmp_invitation_endpoint_name_len, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(tr, hf_nmp_reserved, tvb, offset+1, 1, ENC_NA);
                break;
            case NMP_COMMAND_INVITATION_REPLY_AUTH_REQ:
            case NMP_COMMAND_INVITATION_REPLY_USER_AUTH_REQ:
                proto_tree_add_item(tr, hf_nmp_invitation_endpoint_name_len, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(tr, hf_nmp_invitation_auth_state, tvb, offset+1, 1, ENC_NA);
                break;
            case NMP_COMMAND_RETRANSMIT_REQ:
                proto_tree_add_item(tr, hf_nmp_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case NMP_COMMAND_RETRANSMIT_ERROR:
                proto_tree_add_item(tr, hf_nmp_retransmit_error, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(tr, hf_nmp_reserved, tvb, offset+1, 1, ENC_NA);
                break;
            case NMP_COMMAND_NAK:
                proto_tree_add_item(tr, hf_nmp_nak_reason, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(tr, hf_nmp_reserved, tvb, offset+1, 1, ENC_NA);
                break;
            case NMP_COMMAND_BYE:
                proto_tree_add_item(tr, hf_nmp_bye_reason, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(tr, hf_nmp_reserved, tvb, offset+1, 1, ENC_NA);
                break;
            case NMP_COMMAND_INVITATION_AUTH:
            case NMP_COMMAND_INVITATION_USER_AUTH:
            case NMP_COMMAND_PING:
            case NMP_COMMAND_PING_REPLY:
            case NMP_COMMAND_SESSION_RESET:
            case NMP_COMMAND_SESSION_RESET_REPLY:
            case NMP_COMMAND_BYE_REPLY:
                proto_tree_add_item(tr, hf_nmp_reserved, tvb, offset, 2, ENC_NA);
                break;
            default:
                proto_tree_add_item(tr, hf_nmp_command_specific_data, tvb, offset, 2, ENC_NA);
                break;
        }
        offset += 2;
    }

    if (end_offset-offset)
        proto_tree_add_item(tree, hf_nmp_nak_message, tvb, offset, end_offset-offset, ENC_UTF_8);
}

static int
dissect_nmp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* parent_tree, void* data _U_)
{
    if (tvb_memeql(tvb, 0, NMP_IDENTIFIER, NMP_IDENTIFIER_LEN) != 0) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NetMIDI2");
    col_clear(pinfo->cinfo, COL_INFO);

    unsigned int offset = 0;
    proto_item *ti = proto_tree_add_protocol_format(parent_tree, proto_nmp, tvb, offset, -1, "Network MIDI 2.0");
    proto_tree *tree = proto_item_add_subtree(ti, ett_nmp);

    proto_tree_add_item(tree, hf_nmp_signature, tvb, offset, 4, ENC_ASCII);
    offset += 4;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        uint8_t command_code, payload_length;
        proto_item* comm = proto_tree_add_item(tree, hf_nmp_command, tvb, offset, 4, ENC_NA);
        proto_tree* comm_tree = proto_item_add_subtree(comm, ett_nmp_command);

        proto_tree_add_item_ret_uint8(comm_tree, hf_nmp_command_code, tvb, offset, 1, ENC_NA, &command_code);
        offset += 1;
        proto_tree_add_item_ret_uint8(comm_tree, hf_nmp_payload_length, tvb, offset, 1, ENC_NA, &payload_length);
        offset += 1;

        const char* command_str = val_to_str(pinfo->pool, command_code, nmp_command_names, "Unknown %d");
        proto_item_append_text(comm, ": %s", command_str);
        if (offset > 6)
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", command_str);
        else
            col_append_str(pinfo->cinfo, COL_INFO, command_str);


        proto_item_set_len(comm, 4 + payload_length*4);
        unsigned end_offset = offset + 2 + payload_length*4;

        switch(command_code) {
            case NMP_COMMAND_UMP_DATA:
                dissect_nmp_ump_data(tvb, pinfo, comm_tree, offset, end_offset, comm);
                break;
            case NMP_COMMAND_INVITATION:
            case NMP_COMMAND_INVITATION_AUTH:
            case NMP_COMMAND_INVITATION_USER_AUTH:
                dissect_nmp_invitation(tvb, pinfo, comm_tree, offset, end_offset, command_code);
                break;
            case NMP_COMMAND_INVITATION_REPLY_ACCEPT:
            case NMP_COMMAND_INVITATION_REPLY_PENDING:
            case NMP_COMMAND_INVITATION_REPLY_AUTH_REQ:
            case NMP_COMMAND_INVITATION_REPLY_USER_AUTH_REQ:
                dissect_nmp_invitation_reply(tvb, pinfo, comm_tree, offset, end_offset, command_code);
                break;
            case NMP_COMMAND_PING:
            case NMP_COMMAND_PING_REPLY: {
                proto_tree_add_item(comm_tree, hf_nmp_reserved, tvb, offset, 2, ENC_NA);
                offset += 2;
                uint32_t ping_id;
                proto_tree_add_item_ret_uint32(comm_tree, hf_nmp_ping_id, tvb, offset, 4, ENC_BIG_ENDIAN, &ping_id);
                col_append_fstr(pinfo->cinfo, COL_INFO, " (id=%08x)", ping_id);

                /* 'Request/response' tracking for pings so that we can estimate the latency */
                conversation_t* conversation = find_or_create_conversation(pinfo);
                nmp_conv_info_t* nmp_info = conversation_get_proto_data(conversation, proto_nmp);;
                if (nmp_info == NULL) {
                    nmp_info = wmem_new(wmem_file_scope(), nmp_conv_info_t);
                    nmp_info->ping_pdus = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

                    conversation_add_proto_data(conversation, proto_nmp, nmp_info);
                }
                nmp_ping_transaction_t *ping_trans;
                if (!PINFO_FD_VISITED(pinfo)) {
                    if (command_code == NMP_COMMAND_PING) {
                        /* This is a request */
                        ping_trans = wmem_new(wmem_file_scope(), nmp_ping_transaction_t);
                        ping_trans->req_frame = pinfo->num;
                        ping_trans->rep_frame = 0;
                        ping_trans->req_time = pinfo->fd->abs_ts;
                        wmem_map_insert(nmp_info->ping_pdus, GUINT_TO_POINTER(ping_id), (void *)ping_trans);
                    } else {
                        ping_trans = wmem_map_lookup(nmp_info->ping_pdus, GUINT_TO_POINTER(ping_id));
                        if (ping_trans) {
                            ping_trans->rep_frame = pinfo->num;
                        }
                    }
                } else {
                    ping_trans = wmem_map_lookup(nmp_info->ping_pdus, GUINT_TO_POINTER(ping_id));
                }
                if (ping_trans) {
                    if (command_code == NMP_COMMAND_PING) {
                        if (ping_trans->rep_frame) {
                            proto_item_set_generated(proto_tree_add_uint(
                                comm_tree, hf_nmp_ping_response_in,
                                tvb, 0, 0, ping_trans->rep_frame
                            ));
                        }
                    } else {
                        if (ping_trans->req_frame) {
                            proto_item_set_generated(proto_tree_add_uint(
                                comm_tree, hf_nmp_ping_response_to,
                                tvb, 0, 0, ping_trans->req_frame
                            ));
                            nstime_t ns;
                            nstime_delta(&ns, &pinfo->fd->abs_ts, &ping_trans->req_time);
                            proto_item_set_generated(proto_tree_add_time(
                                comm_tree, hf_nmp_ping_response_time,
                                tvb, 0, 0, &ns
                            ));
                        }
                    }
                }

                break;
            }
            case NMP_COMMAND_RETRANSMIT_REQ:
                proto_tree_add_item(comm_tree, hf_nmp_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(comm_tree, hf_nmp_retransmit_command_count, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(comm_tree, hf_nmp_reserved, tvb, offset, 2, ENC_NA);
                break;
            case NMP_COMMAND_RETRANSMIT_ERROR:
                proto_tree_add_item(comm_tree, hf_nmp_retransmit_error, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(comm_tree, hf_nmp_reserved, tvb, offset, 1, ENC_NA);
                offset += 1;
                proto_tree_add_item(comm_tree, hf_nmp_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(comm_tree, hf_nmp_reserved, tvb, offset, 2, ENC_NA);
                break;
            case NMP_COMMAND_SESSION_RESET:
            case NMP_COMMAND_SESSION_RESET_REPLY:
                proto_tree_add_item(comm_tree, hf_nmp_reserved, tvb, offset, 2, ENC_NA);
                break;
            case NMP_COMMAND_NAK:
                dissect_nmp_nak(tvb, comm_tree, offset, end_offset);
                break;
            case NMP_COMMAND_BYE: {
                uint8_t bye_val;
                proto_tree_add_item_ret_uint8(comm_tree, hf_nmp_bye_reason, tvb, offset, 1, ENC_NA, &bye_val);
                offset += 1;
                proto_tree_add_item(comm_tree, hf_nmp_reserved, tvb, offset, 1, ENC_NA);
                offset += 1;
                if (payload_length)
                    proto_tree_add_item(comm_tree, hf_nmp_bye_message, tvb, offset, payload_length*4, ENC_UTF_8);

                const char* bye_str = val_to_str(pinfo->pool, bye_val, nmp_bye_reason, "reason=0x%02X");
                col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", bye_str);
                break;
            }
            case NMP_COMMAND_BYE_REPLY:
                proto_tree_add_item(comm_tree, hf_nmp_reserved, tvb, offset, 2, ENC_NA);
                break;
            default:
                proto_tree_add_item(comm_tree, hf_nmp_command_specific_data, tvb, offset, 2, ENC_NA);
                break;
        }

        offset = end_offset;
    }

    return offset;
}

static bool
dissect_nmp_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    if (tvb_captured_length(tvb) < 8) {
        return false;
    }

    /* Check signature */
    if (tvb_memeql(tvb, 0, NMP_IDENTIFIER, NMP_IDENTIFIER_LEN) != 0) {
        return false;
    }

    /* Check it is a known command
     * could fail on some packets, but likely to succeed on at least
     * one packet in a given connection
     */
    uint8_t v = tvb_get_uint8(tvb, 4);
    if (try_val_to_str(v, nmp_command_names) == NULL) {
        return false;
    }

    conversation_t* conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, nmp_handle);

    dissect_nmp(tvb, pinfo, tree, data);

    return true;
}

void
proto_register_midi_network(void)
{
    static hf_register_info hf[] = {
        { &hf_nmp_signature,
            { "Signature", "nmp.signature",
            FT_STRING, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_command,
            { "Command", "nmp.command",
            FT_NONE, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_command_code,
            { "Command Code", "nmp.command_code",
            FT_UINT8, BASE_HEX,
            VALS(nmp_command_names), 0,
            NULL, HFILL }
        },
        { &hf_nmp_payload_length,
            { "Payload Length (words)", "nmp.payload_length",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_command_specific_data,
            { "Command Specific Data", "nmp.command_specific_data",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_reserved,
            { "Reserved", "nmp.reserved",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_nmp_sequence_number,
            { "Sequence Number", "nmp.sequence_number",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_nmp_invitation_capabilities,
            { "Capabilities", "nmp.invitation.capabilities",
            FT_UINT8, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_invitation_capabilities_auth,
            { "Auth", "nmp.invitation.capabilities.auth",
            FT_BOOLEAN, 8,
            NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_nmp_invitation_capabilities_user_auth,
            { "User Auth", "nmp.invitation.capabilities.user_auth",
            FT_BOOLEAN, 8,
            NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_nmp_invitation_endpoint_name_len,
            { "Name Length", "nmp.invitation.endpoint_name_len",
            FT_UINT8, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_invitation_endpoint_name,
            { "Endpoint Name", "nmp.invitation.endpoint_name",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_invitation_product_instance_id,
            { "Product Instance Id", "nmp.invitation.product_instance_id",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_invitation_auth_digest,
            { "Auth Digest", "nmp.invitation.auth_digest",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_invitation_user_name,
            { "User Name", "nmp.invitation.user_name",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_invitation_auth_state,
            { "Auth State", "nmp.invitation.auth_state",
            FT_UINT8, BASE_HEX,
            VALS(nmp_invitation_auth_state), 0,
            NULL, HFILL }
        },
        { &hf_nmp_invitation_crypto_nonce,
            { "Crypto Nonce", "nmp.invitation.crypto_nonce",
            FT_STRING, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },

        { &hf_nmp_ping_id,
            { "Ping Id", "nmp.ping.id",
            FT_UINT32, BASE_HEX,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_retransmit_command_count,
            { "Retransmit Count", "nmp.retransmit.command_count",
            FT_UINT16, BASE_DEC,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_retransmit_error,
            { "Error", "nmp.retransmit.error",
            FT_UINT8, BASE_HEX,
            VALS(nmp_retransmit_error), 0,
            NULL, HFILL }
        },
        { &hf_nmp_bye_reason,
            { "Bye Reason", "nmp.bye.reason",
            FT_UINT8, BASE_HEX,
            VALS(nmp_bye_reason), 0,
            NULL, HFILL }
        },
        { &hf_nmp_bye_message,
            { "Bye Message", "nmp.bye.message",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_nak_reason,
            { "Nak Reason", "nmp.nak.reason",
            FT_UINT8, BASE_HEX,
            VALS(nmp_nak_reason), 0,
            NULL, HFILL }
        },
        { &hf_nmp_nak_header,
            { "Nak Message Header", "nmp.nak.header",
            FT_BYTES, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_nak_message,
            { "Nak Message", "nmp.nak.message",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0,
            NULL, HFILL }
        },
        { &hf_nmp_ping_response_in,
            { "Ping Reply In", "nmp.ping.response_in",
            FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            NULL, HFILL }
        },
        { &hf_nmp_ping_response_to,
            { "Ping In", "nmp.ping.response_to",
            FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL }
        },
        { &hf_nmp_ping_response_time,
            { "Latency", "nmp.ping.latency",
            FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_nmp,
        &ett_nmp_command,
        &ett_nmp_invitation_capabilities,
        &ett_nmp_nak_header,
    };

    proto_nmp = proto_register_protocol("Network MIDI 2.0", "NetMIDI", "nmp");
    proto_register_field_array(proto_nmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    nmp_handle = register_dissector("net_midi2", dissect_nmp, proto_nmp);
}

void
proto_reg_handoff_midi_network(void)
{
    dissector_add_for_decode_as_with_preference("udp.port", nmp_handle);
    heur_dissector_add("udp", dissect_nmp_heur, "Network MIDI 2.0", "nmp", proto_nmp, HEURISTIC_ENABLE);
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
