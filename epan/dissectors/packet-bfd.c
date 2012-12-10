/* packet-bfd.c
 * Routines for Bidirectional Forwarding Detection (BFD) message dissection
 * RFCs 5880, 5881, 5882, 5883, 5884, 5885
 * (and http://tools.ietf.org/html/draft-ietf-bfd-base-01 for version 0)
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

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-bfd.h"

#define UDP_PORT_BFD_1HOP_CONTROL 3784 /* draft-katz-ward-bfd-v4v6-1hop-00.txt */
#define UDP_PORT_BFD_MULTIHOP_CONTROL 4784 /* draft-ietf-bfd-multihop-05.txt */

/* As per RFC 6428 : http://tools.ietf.org/html/rfc6428
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

#define APPEND_BOOLEAN_FLAG(flag, item, string) \
    if(flag){                            \
        if(item)                        \
            proto_item_append_text(item, string, sep);    \
        sep = cont_sep;                        \
    }
static const char *const initial_sep = " (";
static const char *const cont_sep = ", ";

static gint proto_bfd = -1;

static gint hf_bfd_version = -1;
static gint hf_bfd_diag = -1;
static gint hf_bfd_sta = -1;
static gint hf_bfd_flags = -1;
static gint hf_bfd_flags_h = -1;
static gint hf_bfd_flags_p = -1;
static gint hf_bfd_flags_f = -1;
static gint hf_bfd_flags_c = -1;
static gint hf_bfd_flags_a = -1;
static gint hf_bfd_flags_d = -1;
static gint hf_bfd_flags_m = -1;
static gint hf_bfd_flags_d_v0 = -1;
static gint hf_bfd_flags_p_v0 = -1;
static gint hf_bfd_flags_f_v0 = -1;
static gint hf_bfd_detect_time_multiplier = -1;
static gint hf_bfd_message_length = -1;
static gint hf_bfd_my_discriminator = -1;
static gint hf_bfd_your_discriminator = -1;
static gint hf_bfd_desired_min_tx_interval = -1;
static gint hf_bfd_required_min_rx_interval = -1;
static gint hf_bfd_required_min_echo_interval = -1;

static gint hf_bfd_auth_type = -1;
static gint hf_bfd_auth_len = -1;
static gint hf_bfd_auth_key = -1;
static gint hf_bfd_auth_password = -1;
static gint hf_bfd_auth_seq_num = -1;

static gint ett_bfd = -1;
static gint ett_bfd_flags = -1;
static gint ett_bfd_auth = -1;

static gint hf_mep_type = -1;
static gint hf_mep_len = -1;
static gint hf_mep_global_id = -1;
static gint hf_mep_node_id = -1;
static gint hf_mep_interface_no = -1;
static gint hf_mep_tunnel_no = -1;
static gint hf_mep_lsp_no = -1;
static gint hf_mep_ac_id = -1;
static gint hf_mep_agi_type = -1;
static gint hf_mep_agi_len = -1;
static gint hf_mep_agi_val = -1;
static gint hf_section_interface_no = -1;
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
 * Control packet version 1, draft-ietf-bfd-base-04.txt
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Vers |  Diag   |Sta|P|F|C|A|D|R|  Detect Mult  |    Length     |
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
static guint8
get_bfd_required_auth_len(guint8 auth_type)
{
    guint8 auth_len = 0;

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
static guint8
get_bfd_checksum_len(guint8 auth_type)
{
    guint8 checksum_len = 0;
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
    int         offset    = 24;
    guint8      auth_type;
    guint8      auth_len;
    proto_item *ti        = NULL;
    proto_item *auth_item = NULL;
    proto_tree *auth_tree = NULL;
    guint8     *password;

    auth_type = tvb_get_guint8(tvb, offset);
    auth_len  = tvb_get_guint8(tvb, offset + 1);

    if (tree) {
        auth_item = proto_tree_add_text(tree, tvb, offset, auth_len, "Authentication: %s",
                                        val_to_str(auth_type,
                                                   bfd_control_auth_type_values,
                                                   "Unknown Authentication Type (%d)") );
        auth_tree = proto_item_add_subtree(auth_item, ett_bfd_auth);

        proto_tree_add_item(auth_tree, hf_bfd_auth_type, tvb, offset, 1, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(auth_tree, hf_bfd_auth_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti, " bytes");

        proto_tree_add_item(auth_tree, hf_bfd_auth_key, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    }

    switch (auth_type) {
        case BFD_AUTH_SIMPLE:
            if (tree) {
                password = tvb_get_ephemeral_string(tvb, offset+3, auth_len-3);
                proto_tree_add_string(auth_tree, hf_bfd_auth_password, tvb, offset+3,
                                      auth_len-3, password);
                proto_item_append_text(auth_item, ": %s", password);
            }
            break;
        case BFD_AUTH_MD5:
        case BFD_AUTH_MET_MD5:
        case BFD_AUTH_SHA1:
        case BFD_AUTH_MET_SHA1:
            if (auth_len != get_bfd_required_auth_len(auth_type)) {
                if (tree) {
                    ti = proto_tree_add_text(auth_tree, tvb, offset, auth_len,
                                             "Length of authentication is invalid (%d)", auth_len);
                    proto_item_append_text(auth_item, ": Invalid Authentication Section");
                }
                expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_WARN,
                        "Length of authentication section is invalid for Authentication Type: %s",
                        val_to_str(auth_type, bfd_control_auth_type_values, "Unknown Authentication Type (%d)") );
            }

            if (tree) {
                proto_tree_add_item(auth_tree, hf_bfd_auth_seq_num, tvb, offset+4, 4, ENC_BIG_ENDIAN);

                proto_tree_add_text(auth_tree, tvb, offset+8, get_bfd_checksum_len(auth_type), "Checksum: 0x%s",
                                    tvb_bytes_to_str(tvb, offset+8, get_bfd_checksum_len(auth_type)) );
            }
            break;
        default:
            break;
    }
}


static void
dissect_bfd_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint flags;
    guint bfd_version;
    guint bfd_diag;
    guint bfd_sta        = 0;
    guint bfd_flags;
    guint bfd_flags_h    = 0;
    guint bfd_flags_p    = 0;
    guint bfd_flags_f    = 0;
    guint bfd_flags_c    = 0;
    guint bfd_flags_a    = 0;
    guint bfd_flags_d    = 0;
    guint bfd_flags_m    = 0;
    guint bfd_flags_d_v0 = 0;
    guint bfd_flags_p_v0 = 0;
    guint bfd_flags_f_v0 = 0;
    guint bfd_detect_time_multiplier;
    guint bfd_length;
    guint bfd_my_discriminator;
    guint bfd_your_discriminator;
    guint bfd_desired_min_tx_interval;
    guint bfd_required_min_rx_interval;
    guint bfd_required_min_echo_interval;
    proto_tree *bfd_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BFD Control");
    col_clear(pinfo->cinfo, COL_INFO);

    bfd_version = (tvb_get_guint8(tvb, 0) & 0xe0) >> 5;
    bfd_diag    = (tvb_get_guint8(tvb, 0) & 0x1f);
    flags       = tvb_get_guint8(tvb, 1);
    switch (bfd_version) {
        case 0:
            bfd_flags      = flags;
            bfd_flags_h    = flags & 0x80;
            bfd_flags_d_v0 = flags & 0x40;
            bfd_flags_p_v0 = flags & 0x20;
            bfd_flags_f_v0 = flags & 0x10;
            break;
        case 1:
        default:
            bfd_sta        = flags & 0xc0;
            bfd_flags      = flags & 0x3e;
            bfd_flags_p    = flags & 0x20;
            bfd_flags_f    = flags & 0x10;
            bfd_flags_c    = flags & 0x08;
            bfd_flags_a    = flags & 0x04;
            bfd_flags_d    = flags & 0x02;
            bfd_flags_m    = flags & 0x01;
            break;
    }

    bfd_detect_time_multiplier     = tvb_get_guint8(tvb, 2);
    bfd_length                     = tvb_get_guint8(tvb, 3);
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
        proto_tree *bfd_flags_tree;
        const char *sep;

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
                ti = proto_tree_add_text ( bfd_tree, tvb, 1, 1, "Message Flags: 0x%02x",
                                           bfd_flags);
                bfd_flags_tree = proto_item_add_subtree(ti, ett_bfd_flags);
                proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_h,    tvb, 1, 1, bfd_flags_h);
                proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_d_v0, tvb, 1, 1, bfd_flags_d_v0);
                proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_p_v0, tvb, 1, 1, bfd_flags_p_v0);
                proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_f_v0, tvb, 1, 1, bfd_flags_f_v0);

                sep = initial_sep;
                APPEND_BOOLEAN_FLAG(bfd_flags_h,    ti, "%sH");
                APPEND_BOOLEAN_FLAG(bfd_flags_d_v0, ti, "%sD");
                APPEND_BOOLEAN_FLAG(bfd_flags_p_v0, ti, "%sP");
                APPEND_BOOLEAN_FLAG(bfd_flags_f_v0, ti, "%sF");
                if (sep != initial_sep) {
                    proto_item_append_text (ti, ")");
                }
                break;
            case 1:
            default:
                ti = proto_tree_add_text ( bfd_tree, tvb, 1, 1, "Message Flags: 0x%02x",
                                           bfd_flags);
                bfd_flags_tree = proto_item_add_subtree(ti, ett_bfd_flags);
                proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_p, tvb, 1, 1, bfd_flags_p);
                proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_f, tvb, 1, 1, bfd_flags_f);
                proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_c, tvb, 1, 1, bfd_flags_c);
                proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_a, tvb, 1, 1, bfd_flags_a);
                proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_d, tvb, 1, 1, bfd_flags_d);
                proto_tree_add_boolean(bfd_flags_tree, hf_bfd_flags_m, tvb, 1, 1, bfd_flags_m);

                sep = initial_sep;
                APPEND_BOOLEAN_FLAG(bfd_flags_p, ti, "%sP");
                APPEND_BOOLEAN_FLAG(bfd_flags_f, ti, "%sF");
                APPEND_BOOLEAN_FLAG(bfd_flags_c, ti, "%sC");
                APPEND_BOOLEAN_FLAG(bfd_flags_a, ti, "%sA");
                APPEND_BOOLEAN_FLAG(bfd_flags_d, ti, "%sD");
                APPEND_BOOLEAN_FLAG(bfd_flags_m, ti, "%sM");
                if (sep != initial_sep) {
                    proto_item_append_text (ti, ")");
                }
                break;
        }

        proto_tree_add_uint_format_value(bfd_tree, hf_bfd_detect_time_multiplier, tvb, 2,
                                         1, bfd_detect_time_multiplier,
                                         "%u (= %u ms Detection time)",
                                         bfd_detect_time_multiplier,
                                         bfd_detect_time_multiplier * (bfd_desired_min_tx_interval/1000));

        proto_tree_add_uint_format_value(bfd_tree, hf_bfd_message_length, tvb, 3, 1, bfd_length,
                "%u bytes", bfd_length);

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
            proto_item *ti = NULL;
            if (tree) {
                ti = proto_tree_add_text(bfd_tree, tvb, 24, bfd_length-24,
                                         "Authentication: Length of the BFD frame is invalid (%d)", bfd_length);
            }
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_WARN,
                                   "Authentication flag is set in a BFD packet, but no authentication data is present");
        }
    }

    return;
}

/* BFD CV Source MEP-ID TLV Decoder,
   As per RFC 6428 : http://tools.ietf.org/html/rfc6428
   sections - 3.5.1, 3.5.2, 3.5.3 */
void
dissect_bfd_mep (tvbuff_t *tvb, proto_tree *tree, const int hfindex)
{
    proto_item *ti;
    proto_tree *bfd_tree;
    gint        offset = 0;
    gint        mep_type;
    gint        mep_len;
    gint        mep_agi_len;

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
        offset   = tvb_get_guint8(tvb, 3);
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

            mep_agi_len   = tvb_get_guint8 (tvb, (offset + 17));
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
                                 mep_agi_len, ENC_ASCII|ENC_NA);

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
            FT_UINT8, BASE_HEX, NULL, 0xf0,
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
            FT_UINT8, BASE_DEC, NULL, 0x0,
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
        { &hf_bfd_auth_type,
          { "Authentication Type", "bfd.auth.type",
            FT_UINT8, BASE_DEC, VALS(bfd_control_auth_type_values), 0x0,
            "The type of authentication in use on this session", HFILL }
        },
        { &hf_bfd_auth_len,
          { "Authentication Length", "bfd.auth.len",
            FT_UINT8, BASE_DEC, NULL, 0x0,
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
        { &hf_mep_interface_no,
          { "Interface  Number", "bfd.mep.interface.no",
            FT_UINT32, BASE_DEC, NULL , 0x0,
            "MPLS-TP Interface Number", HFILL }
        },
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

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_bfd,
        &ett_bfd_flags,
        &ett_bfd_auth
    };

    /* Register the protocol name and description */
    proto_bfd = proto_register_protocol("Bidirectional Forwarding Detection Control Message",
                                        "BFD Control",
                                        "bfd");
    register_dissector("bfd", dissect_bfd_control, proto_bfd);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bfd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bfd(void)
{
    dissector_handle_t bfd_control_handle;

    bfd_control_handle = find_dissector("bfd");
    dissector_add_uint("udp.port", UDP_PORT_BFD_1HOP_CONTROL,     bfd_control_handle);
    dissector_add_uint("udp.port", UDP_PORT_BFD_MULTIHOP_CONTROL, bfd_control_handle);
}
