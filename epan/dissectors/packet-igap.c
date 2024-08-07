/* packet-igap.c
 * Routines for IGMP/IGAP packet disassembly
 * 2003, Endoh Akria (see AUTHORS for email)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include <epan/packet.h>
#include <epan/expert.h>
#include "packet-igmp.h"

void proto_register_igap(void);
void proto_reg_handoff_igap(void);

static dissector_handle_t igap_handle;

static int proto_igap;
static int hf_type;
static int hf_max_resp;
static int hf_checksum;
static int hf_checksum_status;
static int hf_maddr;
static int hf_version;
static int hf_subtype;
static int hf_challengeid;
static int hf_asize;
static int hf_msize;
static int hf_account;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_igap_challenge;
static int hf_igap_user_password;
static int hf_igap_authentication_result;
static int hf_igap_result_of_md5_calculation;
static int hf_igap_accounting_status;
static int hf_igap_unknown_message;

static int ett_igap;

static expert_field ei_checksum;

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

#define ACCOUNT_SIZE    16
#define MESSAGE_SIZE    64

/* This function is only called from the IGMP dissector */
static int
dissect_igap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    proto_tree *tree;
    proto_item *item;
    uint8_t type, tsecs, subtype, asize, msize;
    uint8_t authentication_result, accounting_status;
    int offset = 0;

    item = proto_tree_add_item(parent_tree, proto_igap, tvb, offset, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_igap);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IGAP");
    col_clear(pinfo->cinfo, COL_INFO);

    type = tvb_get_uint8(tvb, offset);
        col_add_str(pinfo->cinfo, COL_INFO,
                     val_to_str(type, igap_types, "Unknown Type: 0x%02x"));
    proto_tree_add_uint(tree, hf_type, tvb, offset, 1, type);
    offset += 1;

    tsecs = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint_format_value(tree, hf_max_resp, tvb, offset, 1, tsecs,
        "%.1f sec (0x%02x)", tsecs * 0.1, tsecs);
    offset += 1;

    igmp_checksum(tree, tvb, hf_checksum, hf_checksum_status, &ei_checksum, pinfo, 0);
    offset += 2;

    proto_tree_add_item(tree, hf_maddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    proto_tree_add_item(tree, hf_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    subtype = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_subtype, tvb, offset, 1, subtype);
    offset += 2;

    proto_tree_add_item(tree, hf_challengeid, tvb, offset, 1, ENC_NA);
    offset += 1;

    asize = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_asize, tvb, offset, 1, asize);
    offset += 1;

    msize = tvb_get_uint8(tvb, offset);
    proto_tree_add_uint(tree, hf_msize, tvb, offset, 1, msize);
    offset += 3;

    if (asize > 0) {
        if (asize > ACCOUNT_SIZE) {
            /* Bogus account size.
               XXX - flag this? */
            asize = ACCOUNT_SIZE;
        }
        /* XXX - encoding? */
        proto_tree_add_item(tree, hf_account, tvb, offset, asize, ENC_ASCII);
    }
    offset += ACCOUNT_SIZE;

    if (msize > 0) {
        if (msize > MESSAGE_SIZE) {
            /* Bogus message size.
               XXX - flag this? */
            msize = MESSAGE_SIZE;
        }
        switch (subtype) {
        case IGAP_SUBTYPE_PASSWORD_JOIN:
        case IGAP_SUBTYPE_PASSWORD_LEAVE:
            /* Challenge field is user's password */
            /* XXX - encoding? */
            proto_tree_add_item(tree, hf_igap_user_password, tvb, offset, msize, ENC_ASCII);
            break;
        case IGAP_SUBTYPE_CHALLENGE_RESPONSE_JOIN:
        case IGAP_SUBTYPE_CHALLENGE_RESPONSE_LEAVE:
            /* Challenge field is the results of MD5 calculation */
            proto_tree_add_item(tree, hf_igap_result_of_md5_calculation, tvb, offset, msize, ENC_NA);
            break;
        case IGAP_SUBTYPE_CHALLENGE:
            /* Challenge field is the challenge value */
            proto_tree_add_item(tree, hf_igap_challenge, tvb, offset, msize, ENC_NA);
            break;
        case IGAP_SUBTYPE_AUTH_MESSAGE:
            /* Challenge field indicates the result of the authentication */
            /* XXX - what if the length isn't 1? */
            authentication_result = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint(tree, hf_igap_authentication_result, tvb, offset, msize, authentication_result);
            break;
        case IGAP_SUBTYPE_ACCOUNTING_MESSAGE:
            /* Challenge field indicates the accounting status */
            /* XXX - what if the length isn't 1? */
            accounting_status = tvb_get_uint8(tvb, offset);
            proto_tree_add_uint(tree, hf_igap_accounting_status, tvb, offset, msize, accounting_status);
            break;
        default:
            proto_tree_add_item(tree, hf_igap_unknown_message, tvb, offset, msize, ENC_NA);
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
          { "Type", "igap.type",
            FT_UINT8, BASE_HEX, VALS(igap_types), 0,
            "IGAP Packet Type", HFILL }
        },
        { &hf_max_resp,
          { "Max Response Time", "igap.max_resp",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_checksum,
          { "Checksum", "igap.checksum",
            FT_UINT16, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_checksum_status,
          { "Checksum Status", "igap.checksum.status",
            FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_maddr,
          { "Multicast group address", "igap.maddr",
            FT_IPv4, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_version,
          { "Version", "igap.version",
            FT_UINT8, BASE_HEX, VALS(igap_version), 0,
            "IGAP protocol version", HFILL }
        },
        { &hf_subtype,
          { "Subtype", "igap.subtype",
            FT_UINT8, BASE_HEX, VALS(igap_subtypes), 0,
            NULL, HFILL }
        },
        { &hf_challengeid,
          { "Challenge ID", "igap.challengeid",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_asize,
          { "Account Size", "igap.asize",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Length of the User Account field", HFILL }
        },
        { &hf_msize,
          { "Message Size", "igap.msize",
            FT_UINT8, BASE_DEC, NULL, 0,
            "Length of the Message field", HFILL }
        },
        { &hf_account,
          { "User Account", "igap.account",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },

        /* Generated from convert_proto_tree_add_text.pl */
        { &hf_igap_user_password,
          { "User password", "igap.user_password",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_igap_result_of_md5_calculation,
          { "Result of MD5 calculation", "igap.result_of_md5_calculation",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_igap_challenge,
          { "Challenge", "igap.challenge",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_igap_authentication_result,
          { "Authentication result", "igap.authentication_result",
            FT_UINT8, BASE_HEX, VALS(igap_auth_result), 0x0,
            NULL, HFILL }
        },
        { &hf_igap_accounting_status,
          { "Accounting status", "igap.accounting_status",
            FT_UINT8, BASE_HEX, VALS(igap_account_status), 0x0,
            NULL, HFILL }
        },
        { &hf_igap_unknown_message,
          { "Unknown message", "igap.unknown_message",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static ei_register_info ei[] = {
        { &ei_checksum, { "igap.bad_checksum", PI_CHECKSUM, PI_ERROR, "Bad checksum", EXPFILL }},
    };

    expert_module_t* expert_igap;

    static int *ett[] = {
        &ett_igap
    };

    proto_igap = proto_register_protocol("Internet Group membership Authentication Protocol", "IGAP", "igap");
    proto_register_field_array(proto_igap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_igap = expert_register_protocol(proto_igap);
    expert_register_field_array(expert_igap, ei, array_length(ei));

    igap_handle = register_dissector("igap", dissect_igap, proto_igap);
}

void
proto_reg_handoff_igap(void)
{
    dissector_add_uint("igmp.type", IGMP_IGAP_JOIN, igap_handle);
    dissector_add_uint("igmp.type", IGMP_IGAP_QUERY, igap_handle);
    dissector_add_uint("igmp.type", IGMP_IGAP_LEAVE, igap_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
