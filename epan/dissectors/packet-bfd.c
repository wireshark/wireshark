/* packet-bfd.c
 * Routines for Bidirectional Forwarding Detection (BFD) message dissection
 * RFCs
 *   5880: Bidirectional Forwarding Detection (BFD)
 *   5881: Bidirectional Forwarding Detection (BFD) for IPv4 and IPv6 (Single Hop)
 *   5882: Generic Application of Bidirectional Forwarding Detection (BFD)
 *   5883: Bidirectional Forwarding Detection (BFD) for Multihop Paths
 *   5884: Bidirectional Forwarding Detection (BFD) for MPLS Label Switched Paths (LSPs)
 *   5885: Bidirectional Forwarding Detection (BFD) for the Pseudowire Virtual Circuit Connectivity Verification (VCCV)
 *   7130: Bidirectional Forwarding Detection (BFD) on Link Aggregation Group (LAG) Interfaces
 *   7881: Seamless Bidirectional Forwarding Detection (S-BFD) for IPv4, IPv6, and MPLS
 * (and https://tools.ietf.org/html/draft-ietf-bfd-base-01 for version 0)
 *
 * Copyright 2003, Hannes Gredler <hannes@juniper.net>
 * Copyright 2006, Balint Reczey <Balint.Reczey@ericsson.com>
 * Copyright 2007, Todd J Martin <todd.martin@acm.org>
 *
 * Copyright 2011, Jaihari Kalijanakiraman <jaiharik@ipinfusion.com>
 *                 Krishnamurthy Mayya <krishnamurthy.mayya@ipinfusion.com>
 *                 Nikitha Malgi       <malgi.nikitha@ipinfusion.com>
 *                  - support for MPLS-TP BFD Proactive CV Message Format as per RFC 6428
 *                  - includes decoding support for Section MEP-ID, LSP MEP-ID, PW MEP-ID
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-bfd.h"
#include "packet-mpls.h"

void proto_register_bfd(void);
void proto_reg_handoff_bfd(void);

static dissector_handle_t bfd_control_handle;
static dissector_handle_t bfd_echo_handle;

/* 3784: BFD control, 3785: BFD echo, 4784: BFD multi hop control */
/* 6784: BFD on LAG, 7784: seamless BFD */
/* https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml?search=bfd */
#define UDP_PORT_RANGE_BFD_CTRL  "3784,4784,6784,7784"
#define UDP_PORT_BFD_ECHO  3785

/* As per RFC 6428 : https://tools.ietf.org/html/rfc6428
   Section: 3.5 */
#define TLV_TYPE_MPLSTP_SECTION_MEP   0
#define TLV_TYPE_MPLSTP_LSP_MEP       1
#define TLV_TYPE_MPLSTP_PW_MEP        2

static const value_string mplstp_mep_tlv_type_values [] = {
    { TLV_TYPE_MPLSTP_SECTION_MEP, "Section MEP-ID" },
    { TLV_TYPE_MPLSTP_LSP_MEP,     "LSP MEP-ID" },
    { TLV_TYPE_MPLSTP_PW_MEP,      "PW MEP-ID" },
    { 0, NULL}
};
static const value_string bfd_control_v0_diag_values[] = {
    { 0, "No Diagnostic" },
    { 1, "Control Detection Time Expired" },
    { 2, "Echo Function Failed" },
    { 3, "Neighbor Signaled Session Down" },
    { 4, "Forwarding Plane Reset" },
    { 5, "Path Down" },
    { 6, "Concatenated Path Down" },
    { 7, "Administratively Down" },
    { 0, NULL }
};

static const value_string bfd_control_v1_diag_values[] = {
    { 0, "No Diagnostic" },
    { 1, "Control Detection Time Expired" },
    { 2, "Echo Function Failed" },
    { 3, "Neighbor Signaled Session Down" },
    { 4, "Forwarding Plane Reset" },
    { 5, "Path Down" },
    { 6, "Concatenated Path Down" },
    { 7, "Administratively Down" },
    { 8, "Reverse Concatenated Path Down" },
    { 9, "Mis-Connectivity Defect" },
    { 0, NULL }
};

static const value_string bfd_control_sta_values[] = {
    { 0, "AdminDown" },
    { 1, "Down" },
    { 2, "Init" },
    { 3, "Up" },
    { 0, NULL }
};

#define BFD_AUTH_SIMPLE    1
#define BFD_AUTH_MD5       2
#define BFD_AUTH_MET_MD5   3
#define BFD_AUTH_SHA1      4
#define BFD_AUTH_MET_SHA1  5
static const value_string bfd_control_auth_type_values[] = {
    { BFD_AUTH_SIMPLE      , "Simple Password" },
    { BFD_AUTH_MD5         , "Keyed MD5" },
    { BFD_AUTH_MET_MD5     , "Meticulous Keyed MD5" },
    { BFD_AUTH_SHA1        , "Keyed SHA1" },
    { BFD_AUTH_MET_SHA1    , "Meticulous Keyed SHA1" },
    { 0, NULL }
};
/* Per the standard, the simple password must by 1-16 bytes in length */
#define MAX_PASSWORD_LEN 16
/* Per the standard, the length of the MD5 authentication packets must be 24
 * bytes and the checksum is 16 bytes */
#define MD5_AUTH_LEN 24
#define MD5_CHECKSUM_LEN 16
/* Per the standard, the length of the SHA1 authentication packets must be 28
 * bytes and the checksum is 20 bytes */
#define SHA1_AUTH_LEN 28
#define SHA1_CHECKSUM_LEN 20

static int proto_bfd;
static int proto_bfd_echo;

static int hf_bfd_version;
static int hf_bfd_diag;
static int hf_bfd_sta;
static int hf_bfd_flags;
static int hf_bfd_flags_h;
static int hf_bfd_flags_p;
static int hf_bfd_flags_f;
static int hf_bfd_flags_c;
static int hf_bfd_flags_a;
static int hf_bfd_flags_d;
static int hf_bfd_flags_m;
static int hf_bfd_flags_d_v0;
static int hf_bfd_flags_p_v0;
static int hf_bfd_flags_f_v0;
static int hf_bfd_detect_time_multiplier;
static int hf_bfd_message_length;
static int hf_bfd_my_discriminator;
static int hf_bfd_your_discriminator;
static int hf_bfd_desired_min_tx_interval;
static int hf_bfd_required_min_rx_interval;
static int hf_bfd_required_min_echo_interval;
static int hf_bfd_checksum;

static int hf_bfd_auth_type;
static int hf_bfd_auth_len;
static int hf_bfd_auth_key;
static int hf_bfd_auth_password;
static int hf_bfd_auth_seq_num;

static int hf_bfd_echo;

static int ett_bfd;
static int ett_bfd_flags;
static int ett_bfd_auth;

static int ett_bfd_echo;

static expert_field ei_bfd_auth_len_invalid;
static expert_field ei_bfd_auth_no_data;

static int hf_mep_type;
static int hf_mep_len;
static int hf_mep_global_id;
static int hf_mep_node_id;
/* static int hf_mep_interface_no; */
static int hf_mep_tunnel_no;
static int hf_mep_lsp_no;
static int hf_mep_ac_id;
static int hf_mep_agi_type;
static int hf_mep_agi_len;
static int hf_mep_agi_val;
static int hf_section_interface_no;
/*
 * Control packet version 0, draft-katz-ward-bfd-01.txt
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Vers |  Diag   |H|D|P|F| Rsvd  |  Detect Mult  |    Length     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                       My Discriminator                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                      Your Discriminator                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                    Desired Min TX Interval                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                   Required Min RX Interval                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                 Required Min Echo RX Interval                 |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

/*
 * Control packet version 1, RFC 5880
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Vers |  Diag   |Sta|P|F|C|A|D|M|  Detect Mult  |    Length     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                       My Discriminator                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                      Your Discriminator                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                    Desired Min TX Interval                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                   Required Min RX Interval                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                 Required Min Echo RX Interval                 |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    An optional Authentication Section may be present:
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Auth Type   |   Auth Len    |    Authentication Data...     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    There are 5 types of authentication defined:
 *      1 - Simple Password
 *      2 - Keyed MD5
 *      3 - Meticulous Keyed MD5
 *      4 - Keyed SHA1
 *      5 - Meticulous Keyed SHA1
 *
 *     The format for Simple Password authentication is:
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Auth Type   |   Auth Len    |  Auth Key ID  |  Password...  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                              ...                              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    The format for Keyed MD5 and Meticulous Keyed MD5 authentication is:
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        Sequence Number                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                     Auth Key/Checksum...                      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                              ...                              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    The format for Keyed SHA1 and Meticulous Keyed SHA1 authentication is:
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   Auth Type   |   Auth Len    |  Auth Key ID  |   Reserved    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        Sequence Number                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                     Auth Key/Checksum...                      |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                              ...                              |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *
 */


/* Given the type of authentication being used, return the required length of
 * the authentication header
 */
static uint8_t
get_bfd_required_auth_len(uint8_t auth_type)
{
    uint8_t auth_len = 0;

    switch (auth_type) {
        case BFD_AUTH_MD5:
        case BFD_AUTH_MET_MD5:
            auth_len = MD5_AUTH_LEN;
            break;
        case BFD_AUTH_SHA1:
        case BFD_AUTH_MET_SHA1:
            auth_len = SHA1_AUTH_LEN;
            break;
        default:
            break;
    }
    return auth_len;
}

/* Given the type of authentication being used, return the length of
 * checksum field
 */
static uint8_t
get_bfd_checksum_len(uint8_t auth_type)
{
    uint8_t checksum_len = 0;
    switch (auth_type) {
        case BFD_AUTH_MD5:
        case BFD_AUTH_MET_MD5:
            checksum_len = MD5_CHECKSUM_LEN;
            break;
        case BFD_AUTH_SHA1:
        case BFD_AUTH_MET_SHA1:
            checksum_len = SHA1_CHECKSUM_LEN;
            break;
        default:
            break;
    }
    return checksum_len;
}

static void
dissect_bfd_authentication(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int           offset    = 24;
    uint8_t       auth_type;
    uint8_t       auth_len;
    proto_item   *auth_item = NULL;
    proto_tree   *auth_tree = NULL;
    const uint8_t *password;

    auth_type = tvb_get_uint8(tvb, offset);
    auth_len  = tvb_get_uint8(tvb, offset + 1);

    if (tree) {
        auth_tree = proto_tree_add_subtree_format(tree, tvb, offset, auth_len,
                                        ett_bfd_auth, NULL, "Authentication: %s",
                                        val_to_str(auth_type,
                                                   bfd_control_auth_type_values,
                                                   "Unknown Authentication Type (%d)") );

        proto_tree_add_item(auth_tree, hf_bfd_auth_type, tvb, offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(auth_tree, hf_bfd_auth_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(auth_tree, hf_bfd_auth_key, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    }

    switch (auth_type) {
        case BFD_AUTH_SIMPLE:
            proto_tree_add_item_ret_string(auth_tree, hf_bfd_auth_password, tvb, offset+3,
                                    auth_len-3, ENC_ASCII|ENC_NA, pinfo->pool, &password);
            proto_item_append_text(auth_item, ": %s", password);
            break;
        case BFD_AUTH_MD5:
        case BFD_AUTH_MET_MD5:
        case BFD_AUTH_SHA1:
        case BFD_AUTH_MET_SHA1:
            if (auth_len != get_bfd_required_auth_len(auth_type)) {
                proto_tree_add_expert_format(auth_tree, pinfo, &ei_bfd_auth_len_invalid, tvb, offset, auth_len,
                        "Length of authentication section (%d) is invalid for Authentication Type: %s",
                        auth_len, val_to_str(auth_type, bfd_control_auth_type_values, "Unknown Authentication Type (%d)") );

                proto_item_append_text(auth_item, ": Invalid Authentication Section");
            }

            if (tree) {
                proto_tree_add_item(auth_tree, hf_bfd_auth_seq_num, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(auth_tree, hf_bfd_checksum, tvb, offset+8, get_bfd_checksum_len(auth_type), ENC_NA);
            }
            break;
        default:
            break;
    }
}

static int
dissect_bfd_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree *bfd_tree = NULL;
    unsigned bfd_length = tvb_reported_length_remaining(tvb, 0);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BFD Echo");
    /* XXX Add direction */
    col_set_str(pinfo->cinfo, COL_INFO, "Originator specific content");

    if (tree) {
        proto_item *ti;

        ti = proto_tree_add_protocol_format(tree, proto_bfd_echo, tvb, 0, bfd_length,
                                            "BFD Echo message");

        bfd_tree = proto_item_add_subtree(ti, ett_bfd_echo);

        proto_tree_add_item(bfd_tree, hf_bfd_echo, tvb, 0, bfd_length, ENC_NA);
    }

    return bfd_length;
}

static int
dissect_bfd_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    unsigned flags;
    unsigned bfd_version;
    unsigned bfd_diag;
    unsigned bfd_sta        = 0;
    unsigned bfd_flags;
    unsigned bfd_flags_a    = 0;
    unsigned bfd_detect_time_multiplier;
    unsigned bfd_length;
    unsigned bfd_my_discriminator;
    unsigned bfd_your_discriminator;
    unsigned bfd_desired_min_tx_interval;
    unsigned bfd_required_min_rx_interval;
    unsigned bfd_required_min_echo_interval;
    proto_tree *bfd_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BFD Control");
    col_clear(pinfo->cinfo, COL_INFO);

    bfd_version = (tvb_get_uint8(tvb, 0) & 0xe0) >> 5;
    bfd_diag    = (tvb_get_uint8(tvb, 0) & 0x1f);
    flags       = tvb_get_uint8(tvb, 1);
    switch (bfd_version) {
        case 0:
            bfd_flags      = flags;
            break;
        case 1:
        default:
            bfd_sta        = flags & 0xc0;
            bfd_flags      = flags & 0x3e;
            bfd_flags_a    = flags & 0x04;
            break;
    }

    bfd_detect_time_multiplier     = tvb_get_uint8(tvb, 2);
    bfd_length                     = tvb_get_uint8(tvb, 3);
    bfd_my_discriminator           = tvb_get_ntohl(tvb, 4);
    bfd_your_discriminator         = tvb_get_ntohl(tvb, 8);
    bfd_desired_min_tx_interval    = tvb_get_ntohl(tvb, 12);
    bfd_required_min_rx_interval   = tvb_get_ntohl(tvb, 16);
    bfd_required_min_echo_interval = tvb_get_ntohl(tvb, 20);

    switch (bfd_version) {
        case 0:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Diag: %s, Flags: 0x%02x",
                         val_to_str_const(bfd_diag, bfd_control_v0_diag_values, "Unknown"),
                         bfd_flags);
            break;
        case 1:
        default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Diag: %s, State: %s, Flags: 0x%02x",
                         val_to_str_const(bfd_diag, bfd_control_v1_diag_values, "Unknown"),
                         val_to_str_const(bfd_sta >> 6 , bfd_control_sta_values, "Unknown"),
                         bfd_flags);
            break;
    }

    if (tree) {
        proto_item *ti;

        ti = proto_tree_add_protocol_format(tree, proto_bfd, tvb, 0, bfd_length,
                                            "BFD Control message");

        bfd_tree = proto_item_add_subtree(ti, ett_bfd);

        proto_tree_add_uint(bfd_tree, hf_bfd_version, tvb, 0,
                                 1, bfd_version << 5);

        proto_tree_add_uint(bfd_tree, hf_bfd_diag, tvb, 0,
                                 1, bfd_diag);

        switch (bfd_version) {
            case 0:
                break;
            case 1:
            default:
                proto_tree_add_uint(bfd_tree, hf_bfd_sta, tvb, 1,
                                    1, bfd_sta);

                break;
        }
        switch (bfd_version) {
            case 0:
                {
                static int * const bfd_message_flags[] = {
                    &hf_bfd_flags_h,
                    &hf_bfd_flags_d_v0,
                    &hf_bfd_flags_p_v0,
                    &hf_bfd_flags_f_v0,
                    NULL
                };
                proto_tree_add_bitmask_with_flags(bfd_tree, tvb, 1, hf_bfd_flags, ett_bfd_flags, bfd_message_flags, ENC_NA, BMT_NO_FALSE);
                }
                break;
            case 1:
            default:
                {
                static int * const bfd_message_flags[] = {
                    &hf_bfd_flags_p,
                    &hf_bfd_flags_f,
                    &hf_bfd_flags_c,
                    &hf_bfd_flags_a,
                    &hf_bfd_flags_d,
                    &hf_bfd_flags_m,
                    NULL
                };
                proto_tree_add_bitmask_with_flags(bfd_tree, tvb, 1, hf_bfd_flags, ett_bfd_flags, bfd_message_flags, ENC_NA, BMT_NO_FALSE);
                }
                break;
        }

        proto_tree_add_uint_format_value(bfd_tree, hf_bfd_detect_time_multiplier, tvb, 2,
                                         1, bfd_detect_time_multiplier,
                                         "%u (= %u ms Detection time)",
                                         bfd_detect_time_multiplier,
                                         bfd_detect_time_multiplier * (bfd_desired_min_tx_interval/1000));

        proto_tree_add_uint(bfd_tree, hf_bfd_message_length, tvb, 3, 1, bfd_length);

        proto_tree_add_uint(bfd_tree, hf_bfd_my_discriminator, tvb, 4,
                                 4, bfd_my_discriminator);

        proto_tree_add_uint(bfd_tree, hf_bfd_your_discriminator, tvb, 8,
                                 4, bfd_your_discriminator);

        proto_tree_add_uint_format_value(bfd_tree, hf_bfd_desired_min_tx_interval, tvb, 12,
                                              4, bfd_desired_min_tx_interval,
                                              "%4u ms (%u us)",
                                              bfd_desired_min_tx_interval/1000,
                                              bfd_desired_min_tx_interval);

        proto_tree_add_uint_format_value(bfd_tree, hf_bfd_required_min_rx_interval, tvb, 16,
                                              4, bfd_required_min_rx_interval,
                                              "%4u ms (%u us)",
                                              bfd_required_min_rx_interval/1000,
                                              bfd_required_min_rx_interval);

        proto_tree_add_uint_format_value(bfd_tree, hf_bfd_required_min_echo_interval, tvb, 20,
                                              4, bfd_required_min_echo_interval,
                                              "%4u ms (%u us)",
                                              bfd_required_min_echo_interval/1000,
                                              bfd_required_min_echo_interval);
    } /* if (tree) */

    /* Dissect the authentication fields if the Authentication flag has
     * been set
     */
    if (bfd_version && bfd_flags_a) {
        if (bfd_length >= 28) {
            dissect_bfd_authentication(tvb, pinfo, bfd_tree);
        } else {
            proto_tree_add_expert_format(bfd_tree, pinfo, &ei_bfd_auth_no_data, tvb, 24, bfd_length-24,
                                         "Authentication: Length of the BFD frame is invalid (%d)", bfd_length);
        }
    }

    return tvb_captured_length(tvb);
}

/* BFD CV Source MEP-ID TLV Decoder,
   As per RFC 6428 : https://tools.ietf.org/html/rfc6428
   sections - 3.5.1, 3.5.2, 3.5.3 */
void
dissect_bfd_mep (tvbuff_t *tvb, proto_tree *tree, const int hfindex)
{
    proto_item *ti;
    proto_tree *bfd_tree;
    int         offset = 0;
    int         mep_type;
    int         mep_len;
    int         mep_agi_len;

    if (!tree)
        return;

    /* Fetch the BFD control message length and move the offset
       to point to the data portion after the control message */

    /* The parameter hfindex is used for determining the tree under which MEP-ID TLV
       has to be determined. Since according to RFC 6428, MEP-ID TLV can be used by any
       OAM function, if hfindex is 0, as per this function the MEP-TLV is a part of
       BFD-CV payload. If a non-zero hfindex comes, then tht TLV info will be displayed
       under a particular protocol-tree. */
    if (!hfindex)
      {
        offset   = tvb_get_uint8(tvb, 3);
        mep_type = tvb_get_ntohs (tvb, offset);
        mep_len  = tvb_get_ntohs (tvb, (offset + 2));
        ti       = proto_tree_add_protocol_format (tree, proto_bfd, tvb, offset, (mep_len + 4),
                                                   "MPLS-TP SOURCE MEP-ID TLV");
      }
    else
      {
        mep_type = tvb_get_ntohs (tvb, offset);
        mep_len  = tvb_get_ntohs (tvb, (offset + 2));
        ti       = proto_tree_add_protocol_format (tree, hfindex, tvb, offset, (mep_len + 4),
                                                   "MPLS-TP SOURCE MEP-ID TLV");
      }

    switch (mep_type) {
        case TLV_TYPE_MPLSTP_SECTION_MEP:

            bfd_tree = proto_item_add_subtree (ti, ett_bfd);
            proto_tree_add_uint (bfd_tree, hf_mep_type , tvb, offset,
                                 2, mep_type);
            proto_tree_add_uint (bfd_tree, hf_mep_len, tvb, (offset + 2),
                                 2, mep_len);
            proto_tree_add_item (bfd_tree, hf_mep_global_id, tvb, (offset + 4),
                                 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (bfd_tree, hf_mep_node_id, tvb, (offset + 8),
                                 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (bfd_tree, hf_section_interface_no, tvb, (offset + 12),
                                 4, ENC_BIG_ENDIAN);

            break;

        case TLV_TYPE_MPLSTP_LSP_MEP:

            bfd_tree = proto_item_add_subtree (ti, ett_bfd);
            proto_tree_add_uint (bfd_tree, hf_mep_type , tvb, offset,
                                 2, mep_type);
            proto_tree_add_uint (bfd_tree, hf_mep_len, tvb, (offset + 2),
                                 2, mep_len);
            proto_tree_add_item (bfd_tree, hf_mep_global_id, tvb, (offset + 4),
                                 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (bfd_tree, hf_mep_node_id, tvb, (offset + 8),
                                 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (bfd_tree, hf_mep_tunnel_no, tvb, (offset + 12),
                                 2, ENC_BIG_ENDIAN);
            proto_tree_add_item (bfd_tree, hf_mep_lsp_no, tvb, (offset + 14),
                                 2, ENC_BIG_ENDIAN);

            break;

        case TLV_TYPE_MPLSTP_PW_MEP:

            mep_agi_len   = tvb_get_uint8 (tvb, (offset + 17));
            bfd_tree = proto_item_add_subtree (ti, ett_bfd);
            proto_tree_add_uint (bfd_tree, hf_mep_type, tvb, offset,
                                 2, (mep_type));
            proto_tree_add_uint (bfd_tree, hf_mep_len, tvb, (offset + 2),
                                 2, mep_len);
            proto_tree_add_item (bfd_tree, hf_mep_global_id, tvb, (offset + 4),
                                 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (bfd_tree, hf_mep_node_id, tvb, (offset + 8),
                                 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (bfd_tree, hf_mep_ac_id, tvb, (offset + 12),
                                 4, ENC_BIG_ENDIAN);
            proto_tree_add_item (bfd_tree, hf_mep_agi_type, tvb, (offset + 16),
                                 1, ENC_BIG_ENDIAN);
            proto_tree_add_uint (bfd_tree, hf_mep_agi_len, tvb, (offset + 17),
                                 1, mep_agi_len);
            proto_tree_add_item (bfd_tree, hf_mep_agi_val, tvb, (offset + 18),
                                 mep_agi_len, ENC_ASCII);

            break;

        default:
            break;
    }
    return;
}

/* Register the protocol with Wireshark */
void
proto_register_bfd(void)
{

    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_bfd_version,
          { "Protocol Version", "bfd.version",
            FT_UINT8, BASE_DEC, NULL , 0xe0,
            "The version number of the BFD protocol", HFILL }
        },
        { &hf_bfd_diag,
          { "Diagnostic Code", "bfd.diag",
            FT_UINT8, BASE_HEX, VALS(bfd_control_v1_diag_values), 0x1f,
            "This field give the reason for a BFD session failure", HFILL }
        },
        { &hf_bfd_sta,
          { "Session State", "bfd.sta",
            FT_UINT8, BASE_HEX, VALS(bfd_control_sta_values), 0xc0,
            "The BFD state as seen by the transmitting system", HFILL }
        },
        { &hf_bfd_flags,
          { "Message Flags", "bfd.flags",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bfd_flags_h,
          { "I hear you", "bfd.flags.h",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x80,
            NULL, HFILL }
        },
        { &hf_bfd_flags_d_v0,
          { "Demand", "bfd.flags.d",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            NULL, HFILL }
        },
        { &hf_bfd_flags_p_v0,
          { "Poll", "bfd.flags.p",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x20,
            NULL, HFILL }
        },
        { &hf_bfd_flags_f_v0,
          { "Final", "bfd.flags.f",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x10,
            NULL, HFILL }
        },
        { &hf_bfd_flags_p,
          { "Poll", "bfd.flags.p",
            FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x20, /* 6 flag bits; Sta is shown separately */
            "If set, the transmitting system is expecting a packet with the Final (F) bit in reply",
            HFILL }
        },
        { &hf_bfd_flags_f,
          { "Final", "bfd.flags.f",
            FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x10, /* 6 flag bits; Sta is shown separately */
            "If set, the transmitting system is replying to a packet with the Poll (P) bit set",
            HFILL }
        },
        { &hf_bfd_flags_c,
          { "Control Plane Independent", "bfd.flags.c",
            FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x08, /* 6 flag bits; Sta is shown separately */
            "If set, the BFD implementation is implemented in the forwarding plane", HFILL }
        },
        { &hf_bfd_flags_a,
          { "Authentication Present", "bfd.flags.a",
            FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x04, /* 6 flag bits; Sta is shown separately */
            "The Authentication Section is present", HFILL }
        },
        { &hf_bfd_flags_d,
          { "Demand", "bfd.flags.d",
            FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x02, /* 6 flag bits; Sta is shown separately */
            "If set, Demand mode is active in the transmitting system", HFILL }
        },
        { &hf_bfd_flags_m,
          { "Multipoint", "bfd.flags.m",
            FT_BOOLEAN, 6, TFS(&tfs_set_notset), 0x01, /* 6 flag bits; Sta is shown separately */
            "Reserved for future point-to-multipoint extensions", HFILL }
        },
        { &hf_bfd_detect_time_multiplier,
          { "Detect Time Multiplier", "bfd.detect_time_multiplier",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "The transmit interval multiplied by this value is the failure detection time", HFILL }
        },
        { &hf_bfd_message_length,
          { "Message Length", "bfd.message_length",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
            "Length of the BFD Control packet, in bytes", HFILL }
        },
        { &hf_bfd_my_discriminator,
          { "My Discriminator", "bfd.my_discriminator",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bfd_your_discriminator,
          { "Your Discriminator", "bfd.your_discriminator",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bfd_desired_min_tx_interval,
          { "Desired Min TX Interval", "bfd.desired_min_tx_interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The minimum interval to use when transmitting BFD Control packets", HFILL }
        },
        { &hf_bfd_required_min_rx_interval,
          { "Required Min RX Interval", "bfd.required_min_rx_interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The minimum interval between received BFD Control packets that this system can support", HFILL }
        },
        { &hf_bfd_required_min_echo_interval,
          { "Required Min Echo Interval", "bfd.required_min_echo_interval",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            "The minimum interval between received BFD Echo packets that this system can support", HFILL }
        },
        { &hf_bfd_checksum,
          { "Checksum", "bfd.checksum",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_bfd_auth_type,
          { "Authentication Type", "bfd.auth.type",
            FT_UINT8, BASE_DEC, VALS(bfd_control_auth_type_values), 0x0,
            "The type of authentication in use on this session", HFILL }
        },
        { &hf_bfd_auth_len,
          { "Authentication Length", "bfd.auth.len",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x0,
            "The length, in bytes, of the authentication section", HFILL }
        },
        { &hf_bfd_auth_key,
          { "Authentication Key ID", "bfd.auth.key",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "The Authentication Key ID, identifies which password is in use for this packet", HFILL }
        },
        { &hf_bfd_auth_password,
          { "Password", "bfd.auth.password",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "The simple password in use on this session", HFILL }
        },
        { &hf_bfd_auth_seq_num,
          { "Sequence Number", "bfd.auth.seq_num",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "The Sequence Number is periodically incremented to prevent replay attacks", HFILL }
          },
         { &hf_mep_type,
          { "Type", "bfd.mep.type",
            FT_UINT16, BASE_DEC, VALS(mplstp_mep_tlv_type_values), 0x0,
            "The type of the MEP Id", HFILL }
        },
        { &hf_mep_len,
          { "Length", "bfd.mep.len",
            FT_UINT16, BASE_DEC, NULL , 0x0,
            "The length of the MEP Id", HFILL }
        },
        { &hf_mep_global_id,
          { "Global Id", "bfd.mep.global.id",
            FT_UINT32, BASE_DEC, NULL , 0x0,
            "MPLS-TP  Global  MEP Id", HFILL }
        },
        { &hf_mep_node_id,
          { "Node Id", "bfd.mep.node.id",
            FT_IPv4, BASE_NONE, NULL , 0x0,
            "MPLS-TP Node Identifier", HFILL }
        },
#if 0
        { &hf_mep_interface_no,
          { "Interface  Number", "bfd.mep.interface.no",
            FT_UINT32, BASE_DEC, NULL , 0x0,
            "MPLS-TP Interface Number", HFILL }
        },
#endif
        { &hf_mep_tunnel_no,
          { "Tunnel Number", "bfd.mep.tunnel.no",
            FT_UINT16, BASE_DEC, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mep_lsp_no,
          { "LSP Number", "bfd.mep.lsp.no",
            FT_UINT16, BASE_DEC, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mep_ac_id,
          { "AC Id", "bfd.mep.ac.id",
            FT_UINT32, BASE_DEC, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mep_agi_type,
          { "AGI TYPE", "bfd.mep.agi.type",
            FT_UINT8, BASE_DEC, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mep_agi_len,
          { "AGI Length", "bfd.mep.agi.len",
            FT_UINT8, BASE_DEC, NULL , 0x0,
            NULL, HFILL }
        },
        { &hf_mep_agi_val,
           { "AGI value", "bfd.mep.agi.val",
             FT_STRING, BASE_NONE, NULL , 0x0,
             NULL, HFILL }
        },
        { &hf_section_interface_no,
          { "Interface Number", "bfd.mep.interface.no",
            FT_UINT32, BASE_DEC, NULL , 0x0,
            "MPLS-TP Interface Number", HFILL }
        }
    };
    /* BFD Echo */
    static hf_register_info hf_echo[] = {
        { &hf_bfd_echo,
          { "Echo", "bfd_echo.packet",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Originator specific echo packet", HFILL }
        }
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_bfd,
        &ett_bfd_flags,
        &ett_bfd_auth,
        &ett_bfd_echo
    };

    static ei_register_info ei[] = {
        { &ei_bfd_auth_len_invalid, { "bfd.auth.len.invalid", PI_MALFORMED, PI_WARN, "Length of authentication section is invalid", EXPFILL }},
        { &ei_bfd_auth_no_data, { "bfd.auth.no_data", PI_MALFORMED, PI_WARN, "Authentication flag is set in a BFD packet, but no authentication data is present", EXPFILL }},
    };

    expert_module_t* expert_bfd;

    /* Register the protocol name and description */
    proto_bfd = proto_register_protocol("Bidirectional Forwarding Detection Control Message",
                                        "BFD Control",
                                        "bfd");
    proto_bfd_echo = proto_register_protocol("Bidirectional Forwarding Detection Echo Packet",
                                        "BFD Echo",
                                        "bfd_echo");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bfd, hf, array_length(hf));
    proto_register_field_array(proto_bfd_echo, hf_echo, array_length(hf_echo));
    proto_register_subtree_array(ett, array_length(ett));
    expert_bfd = expert_register_protocol(proto_bfd);
    expert_register_field_array(expert_bfd, ei, array_length(ei));

    /* Register dissectors */
    bfd_control_handle = register_dissector("bfd", dissect_bfd_control, proto_bfd);
    bfd_echo_handle = register_dissector("bfd_echo", dissect_bfd_echo, proto_bfd_echo);
}

void
proto_reg_handoff_bfd(void)
{
    dissector_add_uint_range_with_preference("udp.port", UDP_PORT_RANGE_BFD_CTRL, bfd_control_handle);
    dissector_add_uint("udp.port", UDP_PORT_BFD_ECHO, bfd_echo_handle);

    dissector_add_uint("pwach.channel_type", PW_ACH_TYPE_BFD_CC, bfd_control_handle);
    dissector_add_uint("pwach.channel_type", PW_ACH_TYPE_BFD_CV, bfd_control_handle);
    dissector_add_uint("pwach.channel_type", PW_ACH_TYPE_BFD, bfd_control_handle);
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
