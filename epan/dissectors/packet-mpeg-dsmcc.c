/* packet-dsmcc.c
 *
 * Routines for ISO/IEC 13818-6 DSM-CC
 * Copyright 2012, Weston Schmidt <weston_schmidt@alumni.purdue.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/crc32-tvb.h>
#include "packet-mpeg-sect.h"

void proto_register_dsmcc(void);
void proto_reg_handoff_dsmcc(void);

/* NOTE: Please try to keep this status comment up to date until the spec is
 * completely implemented - there are a large number of tables in the spec.
 *
 * 13818-6 Table status:
 *
 * Missing tables:
 * 3-1 3-2 3-3 3-4 3-6 3-7 3-8 3-9
 * 4-1 4-7 4-8 4-9 4-10 4-11 4-12 4-13 4-14 4-15 4-*
 * 5-*
 * 6-4
 * 7-5 7-8 7-10 7-12
 * 8-2 8-3 8-4 8-6
 * 9-5 9-6
 * 10-*
 * 11-*
 * 12-*
 *
 * Dissected tables:
 * 2-1 2-4 2-6 2-7
 * 4-6 4-16 4-17 4-34 4-35 (partly)
 * 6-1
 * 7-6 7-7
 * 9-2
 *
 * Validated (all parameters are checked) tables:
 */


static int proto_dsmcc = -1;
static gboolean dsmcc_sect_check_crc = FALSE;

/* NOTE: Please add values numerically according to 13818-6 so it is easier to
 * keep track of what parameters/tables are associated with each other.
 */

/* table 2-1 dsmccMessageHeader - start */
static int hf_dsmcc_protocol_discriminator = -1;
static int hf_dsmcc_type = -1;
static int hf_dsmcc_message_id = -1;
static int hf_dsmcc_transaction_id = -1;
static int hf_dsmcc_header_reserved = -1;
static int hf_dsmcc_adaptation_length = -1;
static int hf_dsmcc_message_length = -1;
/* table 2-1 dsmccMessageHeader - end */

/* table 2-4 dsmccAdaptationHeader - start */
static int hf_dsmcc_adaptation_type = -1;
/* table 2-4 dsmccAdaptationHeader - end */

/* table 2-6 dsmccConditionalAccess - start */
static int hf_dsmcc_adaptation_ca_reserved = -1;
static int hf_dsmcc_adaptation_ca_system_id = -1;
static int hf_dsmcc_adaptation_ca_length = -1;
/* table 2-6 dsmccConditionalAccess - end */

/* table 2-7 dsmccUserId - start */
static int hf_dsmcc_adaptation_user_id_reserved = -1;
/* table 2-7 dsmccUserId - end */

/* table 4-6 U-N user data format - start */
static int hf_dsmcc_un_sess_uu_data_len = -1;
static int hf_dsmcc_un_sess_uu_data = -1;
static int hf_dsmcc_un_sess_priv_data_len = -1;
static int hf_dsmcc_un_sess_priv_data = -1;
/* table 4-6 U-N user data format - end */

/* other tables in section 4.2 - start */
static int hf_dsmcc_un_sess_id = -1;
static int hf_dsmcc_un_sess_response = -1;
static int hf_dsmcc_un_sess_reason = -1;
/* other tables in section 4.2 - end */

/* table 6-1 compatabilityDescriptor - start */
static int hf_compat_desc_length = -1;
static int hf_compat_desc_count = -1;
static int hf_desc_type = -1;
static int hf_desc_length = -1;
static int hf_desc_spec_type = -1;
static int hf_desc_spec_data = -1;
static int hf_desc_model = -1;
static int hf_desc_version = -1;
static int hf_desc_sub_desc_count = -1;
static int hf_desc_sub_desc_type = -1;
static int hf_desc_sub_desc_len = -1;
/* table 6-1 compatabilityDescriptor - end */

/* table 7-3 dsmccDownloadDataHeader - start */
static int hf_dsmcc_dd_download_id = -1;
static int hf_dsmcc_dd_message_id = -1;
/* table 7-3 dsmccDownloadDataHeader - end */

/* table 7-6 dsmccDownloadInfoIndication/InfoResponse - start */
static int hf_dsmcc_dii_download_id = -1;
static int hf_dsmcc_dii_block_size = -1;
static int hf_dsmcc_dii_window_size = -1;
static int hf_dsmcc_dii_ack_period = -1;
static int hf_dsmcc_dii_t_c_download_window = -1;
static int hf_dsmcc_dii_t_c_download_scenario = -1;
static int hf_dsmcc_dii_number_of_modules = -1;
static int hf_dsmcc_dii_module_id = -1;
static int hf_dsmcc_dii_module_size = -1;
static int hf_dsmcc_dii_module_version = -1;
static int hf_dsmcc_dii_module_info_length = -1;
static int hf_dsmcc_dii_private_data_length = -1;
/* table 7-6 dsmccDownloadInfoIndication/InfoResponse - end */

/* table 7-7 dsmccDownloadDataBlock - start */
static int hf_dsmcc_ddb_module_id = -1;
static int hf_dsmcc_ddb_version = -1;
static int hf_dsmcc_ddb_reserved = -1;
static int hf_dsmcc_ddb_block_number = -1;
/* table 7-7 dsmccDownloadDataBlock - end */

/* table 9-2 dsmccSection - start */
static int hf_dsmcc_table_id = -1;
static int hf_dsmcc_section_syntax_indicator = -1;
static int hf_dsmcc_private_indicator = -1;
static int hf_dsmcc_reserved = -1;
static int hf_dsmcc_section_length = -1;
static int hf_dsmcc_table_id_extension = -1;
static int hf_dsmcc_reserved2 = -1;
static int hf_dsmcc_version_number = -1;
static int hf_dsmcc_current_next_indicator = -1;
static int hf_dsmcc_section_number = -1;
static int hf_dsmcc_last_section_number = -1;
static int hf_dsmcc_crc = -1;
static int hf_dsmcc_checksum = -1;
/* table 9-2 dsmccSection - end */

/* TODO: this should really live in the ETV dissector, but I'm not sure how
 * to make the functionality work exactly right yet.  Will work on a patch
 * for this next.
 */
static int hf_etv_module_abs_path = -1;
static int hf_etv_dii_authority = -1;

static gint ett_dsmcc = -1;
static gint ett_dsmcc_payload = -1;
static gint ett_dsmcc_header = -1;
static gint ett_dsmcc_adaptation_header = -1;
static gint ett_dsmcc_compat = -1;
static gint ett_dsmcc_compat_sub_desc = -1;
static gint ett_dsmcc_dii_module = -1;

static expert_field ei_dsmcc_invalid_value = EI_INIT;
static expert_field ei_dsmcc_crc_invalid = EI_INIT;

#define DSMCC_TCP_PORT            13819

/* DSM-CC protocol discriminator, (table 2-1) */
#define DSMCC_PROT_DISC         0x11

#define DSMCC_SSI_MASK          0x8000
#define DSMCC_PRIVATE_MASK      0x4000
#define DSMCC_RESERVED_MASK     0x3000
#define DSMCC_LENGTH_MASK       0x0fff

#define DSMCC_RESERVED2_MASK                    0xc0
#define DSMCC_VERSION_NUMBER_MASK               0x3e
#define DSMCC_CURRENT_NEXT_INDICATOR_MASK       0x01

#define DSMCC_UN_SESS_SRV_SESS_REL_REQ 0x8020
#define DSMCC_UN_SESS_SRV_SESS_REL_CNF 0x8021
#define DSMCC_UN_SESS_SRV_STAT_REQ     0x8060
#define DSMCC_UN_SESS_SRV_STAT_CNF     0x8061

static const range_string dsmcc_header_type_vals[] = {
    {    0,    0, "ISO/IEC 13818-6 Reserved" },
    { 0x01, 0x01, "ISO/IEC 13818-6 User-to-Network Configuration Message" },
    { 0x02, 0x02, "ISO/IEC 13818-6 User-to-Network Session Message" },
    { 0x03, 0x03, "ISO/IEC 13818-6 Download Message" },
    { 0x04, 0x04, "ISO/IEC 13818-6 SDB Channel Change Protocol Message" },
    { 0x05, 0x05, "ISO/IEC 13818-6 User-to-Network Pass-Thru Message" },
    { 0x06, 0x7f, "ISO/IEC 13818-6 Reserved" },
    { 0x80, 0xff, "User Defined Message Type" },
    {    0,    0, NULL }
};

static const range_string dsmcc_adaptation_header_vals[] = {
    {    0,    0, "ISO/IEC 13818-6 Reserved" },
    { 0x01, 0x01, "DSM-CC Conditional Access Adaptation Format" },
    { 0x02, 0x02, "DSM-CC User ID Adaptation Format" },
    { 0x03, 0x7f, "ISO/IEC 13818-6 Reserved" },
    { 0x80, 0xff, "User Defined Adaptation Type" },
    {    0,    0, NULL }
};

static const value_string dsmcc_payload_name_vals[] = {
    { DSMCC_TID_LLCSNAP,   "LLCSNAP" },
    { DSMCC_TID_UN_MSG,    "User Network Message" },
    { DSMCC_TID_DD_MSG,    "Download Data Message" },
    { DSMCC_TID_DESC_LIST, "Descriptor List" },
    { DSMCC_TID_PRIVATE,   "Private" },
    {                 0,   NULL }
};

static const value_string dsmcc_dd_message_id_vals[] = {
    { 0x1001,   "Download Info Request" },
    { 0x1002,   "Download Info Indication" },
    { 0x1003,   "Download Data Block" },
    { 0x1004,   "Download Data Request" },
    { 0x1005,   "Download Data Cancel" },
    { 0x1006,   "Download Server Initiate" },
    {      0,   NULL }
};

static const value_string dsmcc_un_sess_message_id_vals[] = {
    { DSMCC_UN_SESS_SRV_SESS_REL_REQ, "Server Session Release Request" },
    { DSMCC_UN_SESS_SRV_SESS_REL_CNF, "Server Session Release Confirm" },
    { DSMCC_UN_SESS_SRV_STAT_REQ,     "Server Status Request" },
    { DSMCC_UN_SESS_SRV_STAT_CNF,     "Server Status Confirm" },
    {      0,   NULL }
};

static void
dissect_dsmcc_adaptation_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t   *sub_tvb;
    guint       offset = 0;
    proto_item *pi;
    proto_tree *sub_tree;
    guint8      type, tmp;
    guint16     ca_len;

    type = tvb_get_guint8(tvb, offset);

    if (1 == type) {
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dsmcc_adaptation_header, NULL, "Adaptation Header");
        proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_type, tvb,
            offset, 1, ENC_BIG_ENDIAN);
        offset +=1;
        tmp = tvb_get_guint8(tvb, offset);
        pi = proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_ca_reserved, tvb,
            offset, 1, ENC_BIG_ENDIAN);
        if (0xff != tmp) {
            expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value,
                        "Invalid value - should be 0xff");
        }
        offset +=1;
        proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_ca_system_id, tvb,
            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        ca_len = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_ca_length, tvb,
            offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        sub_tvb = tvb_new_subset_length(tvb, offset, ca_len);
        call_data_dissector(sub_tvb, pinfo, tree);
    } else if (2 == type) {
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dsmcc_adaptation_header, NULL, "Adaptation Header");
        proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_type, tvb,
            offset, 1, ENC_BIG_ENDIAN);
        offset +=1;
        tmp = tvb_get_guint8(tvb, offset);
        pi = proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_user_id_reserved, tvb,
            offset, 1, ENC_BIG_ENDIAN);
        if (0xff != tmp) {
            expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value,
                        "Invalid value - should be 0xff");
        }
        /*offset +=1;*/
        /* TODO: handle the userId */
    } else {
        sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_dsmcc_adaptation_header, NULL, "Unknown Adaptation Header");
        proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_type, tvb,
            offset, 1, ENC_BIG_ENDIAN);
    }
}

static guint
dissect_dsmcc_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint offset,
            gboolean download_header)
{
    tvbuff_t   *sub_tvb;
    proto_item *pi;
    proto_tree *sub_tree;
    guint8      prot_disc;
    guint       reserved;
    guint8      adaptation_len;
    guint       offset_start;
    int         msg_id, tx_id;

    offset_start = offset;

    prot_disc = tvb_get_guint8(tvb, offset);
    reserved = tvb_get_guint8(tvb, 8+offset);
    adaptation_len = tvb_get_guint8(tvb, 9+offset);

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, 12+adaptation_len, ett_dsmcc_header, NULL, "DSM-CC Header");
    pi = proto_tree_add_item(sub_tree, hf_dsmcc_protocol_discriminator, tvb,
                 offset, 1, ENC_BIG_ENDIAN);
    if (DSMCC_PROT_DISC != prot_disc) {
        expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value,
                    "Invalid value - should be 0x11");
    }
    offset +=1;
    proto_tree_add_item(sub_tree, hf_dsmcc_type, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    if (TRUE == download_header) {
        msg_id = hf_dsmcc_dd_message_id;
        tx_id = hf_dsmcc_dd_download_id;
    } else {
        msg_id = hf_dsmcc_message_id;
        tx_id = hf_dsmcc_transaction_id;
    }
    proto_tree_add_item(sub_tree, msg_id, tvb,
        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(sub_tree, tx_id, tvb,
        offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    pi = proto_tree_add_item(sub_tree, hf_dsmcc_header_reserved, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    if (0xff != reserved) {
        expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value,
                    "Invalid value - should be 0xff");
    }
    offset +=1;

    proto_tree_add_item(sub_tree, hf_dsmcc_adaptation_length, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    proto_tree_add_item(sub_tree, hf_dsmcc_message_length, tvb,
        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (0 < adaptation_len) {
        sub_tvb = tvb_new_subset_length(tvb, offset, adaptation_len);
        dissect_dsmcc_adaptation_header(sub_tvb, pinfo, sub_tree);
        offset += adaptation_len;
    }

    return offset-offset_start;
}


static guint
dissect_dsmcc_dii_compat_desc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                guint offset)
{
    gint        i, j;
    guint8      sub_count, sub_len;
    guint16     len, count;
    proto_tree *compat_tree;
    proto_tree *desc_sub_tree;

    len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_compat_desc_length, tvb, offset,
                2, ENC_BIG_ENDIAN);
    offset += 2;

    if (0 < len) {
        count = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_compat_desc_count, tvb, offset,
                    2, ENC_BIG_ENDIAN);
        offset += 2;

        for (i = 0; i < count; i++) {
            compat_tree = proto_tree_add_subtree(tree, tvb, offset, len, ett_dsmcc_compat, NULL, "Compatibility Descriptor");
            proto_tree_add_item(compat_tree, hf_desc_type, tvb, offset,
                        1, ENC_BIG_ENDIAN);
            offset +=1;
            proto_tree_add_item(compat_tree, hf_desc_length, tvb, offset,
                        1, ENC_BIG_ENDIAN);
            offset +=1;
            proto_tree_add_item(compat_tree, hf_desc_spec_type, tvb, offset,
                        1, ENC_BIG_ENDIAN);
            offset +=1;
            proto_tree_add_item(compat_tree, hf_desc_spec_data, tvb, offset,
                        3, ENC_BIG_ENDIAN);
            offset += 3;
            proto_tree_add_item(compat_tree, hf_desc_model, tvb, offset,
                        2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(compat_tree, hf_desc_version, tvb, offset,
                        2, ENC_BIG_ENDIAN);
            offset += 2;

            sub_count = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(compat_tree, hf_desc_sub_desc_count, tvb, offset,
                        1, ENC_BIG_ENDIAN);
            offset +=1;

            for (j = 0; j < sub_count; j++) {
                sub_len = tvb_get_guint8(tvb, offset+1);

                desc_sub_tree = proto_tree_add_subtree(compat_tree, tvb, offset, sub_len+2,
                                            ett_dsmcc_compat_sub_desc, NULL, "Sub Descriptor");
                proto_tree_add_item(desc_sub_tree, hf_desc_sub_desc_type, tvb, offset,
                            1, ENC_BIG_ENDIAN);
                offset +=1;
                proto_tree_add_item(desc_sub_tree, hf_desc_sub_desc_len, tvb, offset,
                            1, ENC_BIG_ENDIAN);
                offset +=1;

                offset += sub_len;
            }
        }

        if( 1000 == offset ) {
            expert_add_info( pinfo, NULL, &ei_dsmcc_crc_invalid);
        }
    }

    return 2 + len;
}

static void
dissect_dsmcc_dii(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        guint offset)
{
    guint8      module_info_len;
    guint16     modules, private_data_len;
    guint16     module_id;
    guint8      module_version;
    guint       module_size;
    guint       i;
    proto_tree *mod_tree;

    proto_tree_add_item(tree, hf_dsmcc_dii_download_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_dsmcc_dii_block_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_dsmcc_dii_window_size, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    proto_tree_add_item(tree, hf_dsmcc_dii_ack_period, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    proto_tree_add_item(tree, hf_dsmcc_dii_t_c_download_window, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_dsmcc_dii_t_c_download_scenario, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    offset += dissect_dsmcc_dii_compat_desc(tvb, pinfo, tree, offset);
    proto_tree_add_item(tree, hf_dsmcc_dii_number_of_modules, tvb, offset, 2, ENC_BIG_ENDIAN);
    modules = tvb_get_ntohs(tvb, offset);
    offset += 2;

    for (i = 0; i < modules; i++ ) {
        module_id = tvb_get_ntohs(tvb, offset);
        module_size = tvb_get_ntohl(tvb, 2+offset);
        module_version = tvb_get_guint8(tvb, 6+offset);

        mod_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
                ett_dsmcc_dii_module, NULL, "Module Id: 0x%x, Version: %u, Size: %u",
                module_id, module_version, module_size);
        proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset +=1;

        module_info_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(mod_tree, hf_dsmcc_dii_module_info_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset +=1;
        if (0 < module_info_len) {
            proto_tree_add_item(mod_tree, hf_etv_module_abs_path, tvb, offset, 1,
                ENC_ASCII|ENC_BIG_ENDIAN);
            offset += module_info_len;
        }
    }

    private_data_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_dsmcc_dii_private_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (0 < private_data_len) {
        proto_tree_add_item(tree, hf_etv_dii_authority, tvb, offset, 1,
            ENC_ASCII|ENC_BIG_ENDIAN);
        /*offset += private_data_len;*/
    }
}


static void
dissect_dsmcc_ddb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
            proto_tree *top_tree, guint offset)
{
    tvbuff_t   *sub_tvb;
    proto_item *pi;
    guint8      reserved;

    proto_tree_add_item(tree, hf_dsmcc_ddb_module_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_dsmcc_ddb_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    reserved = tvb_get_guint8(tvb, offset);
    pi = proto_tree_add_item(tree, hf_dsmcc_ddb_reserved, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    if (0xff != reserved) {
        expert_add_info_format(pinfo, pi, &ei_dsmcc_invalid_value,
                    "Invalid value - should be 0xff");
    }
    offset +=1;
    proto_tree_add_item(tree, hf_dsmcc_ddb_block_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    sub_tvb = tvb_new_subset_remaining(tvb, offset);
    call_data_dissector(sub_tvb, pinfo, top_tree);
}


static void
dissect_dsmcc_un_download(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                proto_tree *top_tree)
{
    proto_tree *sub_tree;
    guint16     msg_id;
    guint       offset = 0;

    msg_id = tvb_get_ntohs(tvb, offset+2);

    sub_tree = proto_tree_add_subtree_format(tree, tvb, 0, -1, ett_dsmcc_payload, NULL,
            "User Network Message - %s", val_to_str(msg_id, dsmcc_dd_message_id_vals, "%u"));

    switch (msg_id) {
        case 0x1001:
        case 0x1002:
            offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, FALSE);
            dissect_dsmcc_dii(tvb, pinfo, sub_tree, offset);
            break;
        case 0x1003:
            offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, TRUE);
            dissect_dsmcc_ddb(tvb, pinfo, sub_tree, top_tree, offset);
            break;
        case 0x1004:
            /* TODO: Add support */
            break;
        case 0x1005:
            /* TODO: Add support */
            break;
        case 0x1006:
            /* TODO: Add support */
            break;
        default:
            break;
    }
}

static guint dissect_dsmcc_un_session_user_data(
        tvbuff_t *tvb, guint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint offset_start;
    guint16 uu_len, priv_len;

    offset_start = offset;

    uu_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_dsmcc_un_sess_uu_data_len,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (uu_len>0) {
        proto_tree_add_item(tree, hf_dsmcc_un_sess_uu_data,
                tvb, offset, uu_len, ENC_NA);
        offset += uu_len;
    }

    priv_len = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_dsmcc_un_sess_priv_data_len,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (priv_len>0) {
        proto_tree_add_item(tree, hf_dsmcc_un_sess_priv_data,
                tvb, offset, priv_len, ENC_NA);
        offset += priv_len;
    }

    return offset-offset_start;
}


static void
dissect_dsmcc_un_session(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, proto_tree *top_tree _U_)
{
    proto_item *pi;
    proto_tree *sub_tree;
    guint16     msg_id;
    guint       offset = 0;

    msg_id = tvb_get_ntohs(tvb, offset+2);

    sub_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1,
            ett_dsmcc_payload, &pi, "User Network Message (Session) - %s",
            val_to_str(msg_id, dsmcc_un_sess_message_id_vals, "0x%x"));
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "%s",
            val_to_str(msg_id, dsmcc_un_sess_message_id_vals, "0x%x"));

    switch (msg_id) {
        case DSMCC_UN_SESS_SRV_SESS_REL_REQ:
            offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, FALSE);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_id,
                tvb, offset, 10, ENC_NA);
            offset += 10;
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason,
                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            offset += dissect_dsmcc_un_session_user_data(
                    tvb, offset, pinfo, sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_SESS_REL_CNF:
            offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, FALSE);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_id,
                tvb, offset, 10, ENC_NA);
            offset += 10;
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response,
                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            offset += dissect_dsmcc_un_session_user_data(
                    tvb, offset, pinfo, sub_tree);
            break;
        case DSMCC_UN_SESS_SRV_STAT_REQ:
            offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, FALSE);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_reason,
                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* TODO: add server id, status type, status count */
            offset += 20;
            /* TODO: skip status bytes */
            break;
        case DSMCC_UN_SESS_SRV_STAT_CNF:
            offset += dissect_dsmcc_header(tvb, pinfo, sub_tree, offset, FALSE);
            proto_tree_add_item(sub_tree, hf_dsmcc_un_sess_response,
                tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            /* TODO: add status type, status count */
            offset += 4;
            /* TODO: skip status bytes */
            break;
        default:
            break;
    }
    proto_item_set_len(pi, offset);
}


static void
dissect_dsmcc_un(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
            proto_tree *top_tree)
{
    guint8 type;

    /* dsmccMessageHeader.dsmccType */
    type = tvb_get_guint8(tvb, 1);

    switch (type) {
        case 1: /* user-to-network configuration */
            /* TODO: Add support */
            break;
        case 2: /* user-to-network session */
            dissect_dsmcc_un_session(tvb, pinfo, tree, top_tree);
            break;
        case 3: /* user-to-network download */
            dissect_dsmcc_un_download(tvb, pinfo, tree, top_tree);
            break;
        case 4: /* sdb channel change protocol */
            /* TODO: Add support */
            break;
        case 5: /* user-to-network pass-thru */
            /* TODO: Add support */
            break;
        default:
            break;
    }
}

static int
dissect_dsmcc_ts(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree_in, void *data _U_)
{
    proto_item *pi;
    proto_tree *tree;
    guint       crc_len;
    guint8      tid;
    guint16     sect_len;
    guint32     crc, calculated_crc;
    const char *label;
    tvbuff_t   *sub_tvb;
    guint16     ssi;
    guint       offset = 0;

    pi = proto_tree_add_item(tree_in, proto_dsmcc, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(pi, ett_dsmcc);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSM-CC");

    tid = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_dsmcc_table_id, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    ssi = tvb_get_ntohs(tvb, offset);
    ssi &= DSMCC_SSI_MASK;
    proto_tree_add_item(tree, hf_dsmcc_section_syntax_indicator, tvb,
        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dsmcc_private_indicator, tvb,
        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dsmcc_reserved, tvb,
        offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dsmcc_section_length, tvb,
        offset, 2, ENC_BIG_ENDIAN);
    sect_len = tvb_get_ntohs(tvb, offset);
    sect_len &= DSMCC_LENGTH_MASK;
    offset += 2;

    proto_tree_add_item(tree, hf_dsmcc_table_id_extension, tvb,
        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_dsmcc_reserved2, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dsmcc_version_number, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dsmcc_current_next_indicator, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    proto_tree_add_item(tree, hf_dsmcc_section_number, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset +=1;
    proto_tree_add_item(tree, hf_dsmcc_last_section_number, tvb,
        offset, 1, ENC_BIG_ENDIAN);
    offset +=1;

    sub_tvb = tvb_new_subset_length(tvb, offset, sect_len-9);
    switch (tid) {
        case DSMCC_TID_LLCSNAP:
            /* TODO: Add support */
            break;
        case DSMCC_TID_UN_MSG:
        case DSMCC_TID_DD_MSG:
            dissect_dsmcc_un(sub_tvb, pinfo, tree, tree_in);
            break;
        case DSMCC_TID_DESC_LIST:
            /* TODO: Add support */
            break;
        case DSMCC_TID_PRIVATE:
            /* TODO: Add support */
            break;
        default:
            break;
    }

    crc_len = 3 + sect_len - 4; /* Add the header, remove the crc */
    if (ssi) {
        crc = tvb_get_ntohl(tvb, crc_len);

        calculated_crc = crc;
        label = "Unverified";
        if (dsmcc_sect_check_crc) {
            label = "Verified";
            calculated_crc = crc32_mpeg2_tvb_offset(tvb, 0, crc_len);
        }

        if (calculated_crc == crc) {
            proto_tree_add_uint_format( tree, hf_dsmcc_crc, tvb,
                crc_len, 4, crc, "CRC: 0x%08x [%s]", crc, label);
        } else {
            proto_item *msg_error;

            msg_error = proto_tree_add_uint_format( tree, hf_dsmcc_crc, tvb,
                                crc_len, 4, crc,
                                "CRC: 0x%08x [Failed Verification (Calculated: 0x%08x)]",
                                crc, calculated_crc );
            PROTO_ITEM_SET_GENERATED(msg_error);
            expert_add_info( pinfo, msg_error, &ei_dsmcc_crc_invalid);
        }
    } else {
        /* TODO: actually check the checksum */
        proto_tree_add_checksum(tree, tvb, crc_len, hf_dsmcc_checksum,
            -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);
    }

    return tvb_reported_length(tvb);
}


static int dissect_dsmcc_tcp(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data _U_)
{
    proto_item *pi;
    proto_tree *sub_tree;

    if (tvb_get_guint8(tvb, 0) != DSMCC_PROT_DISC)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DSM-CC");
    col_clear(pinfo->cinfo, COL_INFO);

    pi = proto_tree_add_item(tree, proto_dsmcc, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree(pi, ett_dsmcc);

    dissect_dsmcc_un(tvb, pinfo, sub_tree, tree);

    return tvb_reported_length(tvb);
}


void
proto_register_dsmcc(void)
{
    /* NOTE: Please add tables numerically according to 13818-6 so it is
     * easier to keep track of what parameters/tables are associated with
     * each other.
     */
    static hf_register_info hf[] = {
        /* table 2-1 dsmccMessageHeader - start */
        { &hf_dsmcc_protocol_discriminator, {
            "Protocol Discriminator", "mpeg_dsmcc.protocol",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_type, {
            "Type", "mpeg_dsmcc.type",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(dsmcc_header_type_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_message_id, {
            "Message ID", "mpeg_dsmcc.message_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_transaction_id, {
            "Transaction ID", "mpeg_dsmcc.transaction_id",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_header_reserved, {
            "Reserved", "mpeg_dsmcc.header_reserved",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_adaptation_length, {
            "Adaptation Length", "mpeg_dsmcc.adaptation_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_message_length, {
            "Message Length", "mpeg_dsmcc.message_length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 2-1 dsmccMessageHeader - end */


        /* table 2-4 dsmccAdaptationHeader - start */
        { &hf_dsmcc_adaptation_type, {
            "Adaptation Type", "mpeg_dsmcc.adaptation_header.type",
            FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(dsmcc_adaptation_header_vals), 0, NULL, HFILL
        } },
        /* table 2-4 dsmccAdaptationHeader - end */

        /* table 2-6 dsmccConditionalAccess - start */
        { &hf_dsmcc_adaptation_ca_reserved, {
            "Reserved", "mpeg_dsmcc.adaptation_header.ca.reserved",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_adaptation_ca_system_id, {
            "System ID", "mpeg_dsmcc.adaptation_header.ca.system_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_adaptation_ca_length, {
            "System ID", "mpeg_dsmcc.adaptation_header.ca.length",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 2-6 dsmccConditionalAccess - end */


        /* table 2-7 dsmccUserId - start */
        { &hf_dsmcc_adaptation_user_id_reserved, {
            "Reserved", "mpeg_dsmcc.adaptation_header.uid.reserved",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 2-7 dsmccUserId - start */

        /* table 4-6 U-N user data format - start */
        { &hf_dsmcc_un_sess_uu_data_len, {
            "User data length", "mpeg_dsmcc.un_sess.uu_data_len",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_uu_data, {
            "User data", "mpeg_dsmcc.un_sess.uu_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_priv_data_len, {
            "Private data length", "mpeg_dsmcc.un_sess.priv_data_len",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_priv_data, {
            "Private data", "mpeg_dsmcc.un_sess.priv_data",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },
        /* table 4-6 U-N user data format - end */

        /* other tables in section 4.2 - start */
        { &hf_dsmcc_un_sess_id, {
            "Session ID", "mpeg_dsmcc.un_sess.session_id",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_response, {
            "Response", "mpeg_dsmcc.un_sess.response",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_un_sess_reason, {
            "Reason", "mpeg_dsmcc.un_sess.reason",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        /* other tables in section 4.2 - end */

        /* table 6-1 compatabilityDescriptor - start */
        { &hf_compat_desc_length, {
            "Compatibility Descriptor Length", "mpeg_dsmcc.dii.compat_desc_len",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_compat_desc_count, {
            "Descriptor Length", "mpeg_dsmcc.dii.compat_desc_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_type, {
            "Descriptor Type", "mpeg_dsmcc.dii.compat.type",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_length, {
            "Descriptor Length", "mpeg_dsmcc.dii.compat.length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_spec_type, {
            "Specifier Type", "mpeg_dsmcc.dii.compat.spec_type",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_spec_data, {
            "Specifier Data", "mpeg_dsmcc.dii.compat.spec_data",
            FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_model, {
            "Model", "mpeg_dsmcc.dii.compat.model",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_version, {
            "Version", "mpeg_dsmcc.dii.compat.version",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_sub_desc_count, {
            "Version", "mpeg_dsmcc.dii.compat.sub_count",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_sub_desc_type, {
            "Type", "mpeg_dsmcc.dii.compat.sub_type",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_desc_sub_desc_len, {
            "Length", "mpeg_dsmcc.dii.compat.sub_len",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 6-1 compatabilityDescriptor - end */


        /* table 7-3 dsmccDownloadDataHeader - start */
        { &hf_dsmcc_dd_download_id, {
            "Download ID", "mpeg_dsmcc.download_id",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dd_message_id, {
            "Message ID", "mpeg_dsmcc.message_id",
            FT_UINT16, BASE_HEX, VALS(dsmcc_dd_message_id_vals), 0, NULL, HFILL
        } },
        /* table 7-3 dsmccDownloadDataHeader - end */


        /* table 7-6 downloadInfoIndication - start */
        { &hf_dsmcc_dii_download_id, {
            "Download ID", "mpeg_dsmcc.dii.download_id",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_block_size, {
            "Block Size", "mpeg_dsmcc.dii.block_size",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_window_size, {
            "Window Size", "mpeg_dsmcc.dii.window_size",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_ack_period, {
            "ACK Period", "mpeg_dsmcc.dii.ack_period",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_t_c_download_window, {
            "Carousel Download Window", "mpeg_dsmcc.dii.carousel_download_window",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_t_c_download_scenario, {
            "Carousel Download Scenario", "mpeg_dsmcc.dii.carousel_download_scenario",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_number_of_modules, {
            "Number of Modules", "mpeg_dsmcc.dii.module_count",
            FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_module_id, {
            "Module ID", "mpeg_dsmcc.dii.module_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_module_size, {
            "Module Size", "mpeg_dsmcc.dii.module_size",
            FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_module_version, {
            "Module Version", "mpeg_dsmcc.dii.module_version",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_module_info_length, {
            "Module Info Length", "mpeg_dsmcc.dii.module_info_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_dii_private_data_length, {
            "Private Data Length", "mpeg_dsmcc.dii.private_data_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },
        /* table 7-6 downloadInfoIndication - end */


        /* table 7-7 dsmccDownloadDataBlock - start */
        { &hf_dsmcc_ddb_module_id, {
            "Module ID", "mpeg_dsmcc.ddb.module_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_ddb_version, {
            "Version", "mpeg_dsmcc.ddb.version",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_ddb_reserved, {
            "Reserved", "mpeg_dsmcc.ddb.reserved",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_ddb_block_number, {
            "Block Number", "mpeg_dsmcc.ddb.block_num",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        /* table 7-7 dsmccDownloadDataBlock - end */


        /* table 9-2 - start */
        { &hf_dsmcc_table_id, {
            "Table ID", "mpeg_sect.table_id",
            FT_UINT8, BASE_HEX, VALS(dsmcc_payload_name_vals), 0, NULL, HFILL
        } },

        { &hf_dsmcc_section_syntax_indicator, {
            "Session Syntax Indicator", "mpeg_sect.ssi",
            FT_UINT16, BASE_DEC, NULL, DSMCC_SSI_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_private_indicator, {
            "Private Indicator", "mpeg_dsmcc.private_indicator",
            FT_UINT16, BASE_DEC, NULL, DSMCC_PRIVATE_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_reserved, {
            "Reserved", "mpeg_sect.reserved",
            FT_UINT16, BASE_HEX, NULL, DSMCC_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_section_length, {
            "Length", "mpeg_sect.section_length",
            FT_UINT16, BASE_DEC, NULL, DSMCC_LENGTH_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_table_id_extension, {
            "Table ID Extension", "mpeg_dsmcc.table_id_extension",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_reserved2, {
            "Reserved", "mpeg_dsmcc.reserved2",
            FT_UINT8, BASE_HEX, NULL, DSMCC_RESERVED2_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_version_number, {
            "Version Number", "mpeg_dsmcc.version_number",
            FT_UINT8, BASE_DEC, NULL, DSMCC_VERSION_NUMBER_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_current_next_indicator, {
            "Current Next Indicator", "mpeg_dsmcc.current_next_indicator",
            FT_UINT8, BASE_DEC, NULL, DSMCC_CURRENT_NEXT_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_dsmcc_section_number, {
            "Section Number", "mpeg_dsmcc.section_number",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_last_section_number, {
            "Last Section Number", "mpeg_dsmcc.last_section_number",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_crc, {
            "CRC 32", "mpeg_sect.crc",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dsmcc_checksum, {
            "Checksum", "mpeg_dsmcc.checksum",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } },
        /* table 9-2 - end */


        { &hf_etv_module_abs_path, {
            "Module Absolute Path", "etv.dsmcc.dii.module_abs_path",
            FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_etv_dii_authority, {
            "Authority", "etv.dsmcc.dii.authority",
            FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL
        } }
    };

    static gint *ett[] = {
        &ett_dsmcc,
        &ett_dsmcc_payload,
        &ett_dsmcc_adaptation_header,
        &ett_dsmcc_header,
        &ett_dsmcc_compat,
        &ett_dsmcc_compat_sub_desc,
        &ett_dsmcc_dii_module
    };
    static ei_register_info ei[] = {
        { &ei_dsmcc_invalid_value, { "mpeg_dsmcc.invalid_value", PI_PROTOCOL, PI_WARN, "Invalid value", EXPFILL }},
        { &ei_dsmcc_crc_invalid, { "mpeg_sect.crc.invalid", PI_CHECKSUM, PI_WARN, "Invalid CRC", EXPFILL }},
    };

    module_t *dsmcc_module;
    expert_module_t* expert_dsmcc;

    proto_dsmcc = proto_register_protocol("MPEG DSM-CC", "MPEG DSM-CC", "mpeg_dsmcc");

    proto_register_field_array(proto_dsmcc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_dsmcc = expert_register_protocol(proto_dsmcc);
    expert_register_field_array(expert_dsmcc, ei, array_length(ei));
    register_dissector("mp2t-dsmcc", dissect_dsmcc_ts, proto_dsmcc);

    dsmcc_module = prefs_register_protocol(proto_dsmcc, NULL);

    prefs_register_bool_preference(dsmcc_module, "verify_crc",
        "Verify the section CRC or checksum",
        "Whether the section dissector should verify the CRC or checksum",
        &dsmcc_sect_check_crc);
}


void
proto_reg_handoff_dsmcc(void)
{
    dissector_handle_t dsmcc_ts_handle, dsmcc_tcp_handle;

    dsmcc_ts_handle = create_dissector_handle(dissect_dsmcc_ts, proto_dsmcc);
    dsmcc_tcp_handle = create_dissector_handle(dissect_dsmcc_tcp, proto_dsmcc);

    dissector_add_uint("mpeg_sect.tid", DSMCC_TID_LLCSNAP, dsmcc_ts_handle);
    dissector_add_uint("mpeg_sect.tid", DSMCC_TID_UN_MSG, dsmcc_ts_handle);
    dissector_add_uint("mpeg_sect.tid", DSMCC_TID_DD_MSG, dsmcc_ts_handle);
    dissector_add_uint("mpeg_sect.tid", DSMCC_TID_DESC_LIST, dsmcc_ts_handle);
    dissector_add_uint("mpeg_sect.tid", DSMCC_TID_PRIVATE, dsmcc_ts_handle);

    dissector_add_uint("tcp.port", DSMCC_TCP_PORT, dsmcc_tcp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
