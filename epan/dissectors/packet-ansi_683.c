/* packet-ansi_683.c
 * Routines for ANSI IS-683 (OTA (Mobile)) dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 * Copyright 2008, Michael Lum <mglum [AT] shaw.ca>
 * In association with Global Star Solutions, ULC.
 *
 * Last Updated to:
 * http://www.3gpp2.org/Public_html/specs/C.S0016-C_v2.0_081031.pdf
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

#include <string.h>

#include <epan/packet.h>
#include <epan/to_str.h>

void proto_register_ansi_683(void);
void proto_reg_handoff_ansi_683(void);


static const char *ansi_proto_name = "ANSI IS-683 (OTA (Mobile))";
static const char *ansi_proto_name_short = "IS-683";

#define ANSI_683_FORWARD        0
#define ANSI_683_REVERSE        1


/* Initialize the subtree pointers */
static gint ett_ansi_683 = -1;
static gint ett_for_nam_block = -1;
static gint ett_for_sspr_block = -1;
static gint ett_rev_sspr_block = -1;
static gint ett_rev_nam_block = -1;
static gint ett_key_p = -1;
static gint ett_key_g = -1;
static gint ett_rev_feat = -1;
static gint ett_for_val_block = -1;
static gint ett_band_cap = -1;
static gint ett_scm = -1;
static gint ett_for_puzl_block = -1;
static gint ett_rev_puzl_block = -1;
static gint ett_for_3gpd_block = -1;
static gint ett_rev_3gpd_block = -1;
static gint ett_for_mmd_block = -1;
static gint ett_rev_mmd_block = -1;
static gint ett_for_mms_block = -1;
static gint ett_rev_mms_block = -1;
static gint ett_rev_cap = -1;
static gint ett_segment = -1;

/* Initialize the protocol and registered fields */
static int proto_ansi_683 = -1;
static int hf_ansi_683_none = -1;
static int hf_ansi_683_for_msg_type = -1;
static int hf_ansi_683_rev_msg_type = -1;
static int hf_ansi_683_length = -1;

static char bigbuf[1024];

static const char dtmf_digits[16] = {'?','1','2','3','4','5','6','7','8','9','0','?','?','?','?','?'};
static const char bcd_digits[16]  = {'0','1','2','3','4','5','6','7','8','9','?','?','?','?','?','?'};

/* FUNCTIONS */

/* PARAM FUNCTIONS */

#define EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
        proto_tree_add_none_format(tree, hf_ansi_683_none, tvb, \
            offset, (edc_len) - (edc_max_len), "Extraneous Data"); \
    }

#define SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
        proto_tree_add_none_format(tree, hf_ansi_683_none, tvb, \
            offset, (sdc_len), "Short Data (?)"); \
        return; \
    }

#define EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
        proto_tree_add_none_format(tree, hf_ansi_683_none, tvb, \
            offset, (edc_len), "Unexpected Data Length"); \
        return; \
    }

static guint32
fresh_handler(tvbuff_t *tvb, proto_tree *tree, guint len _U_, guint32 offset)
{
    guint32     value;
    guint8      oct;

    oct = tvb_get_guint8(tvb, offset);

    if (oct & 0x80)
    {
        value = tvb_get_ntohs(tvb, offset);

        other_decode_bitfield_value(bigbuf, value, 0x8000, 16);
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 2,
            "%s :  FRESH_INCL : TRUE",
            bigbuf);

        other_decode_bitfield_value(bigbuf, value, 0x7fff, 16);
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 2,
            "%s :  FRESH",
            bigbuf);

        return(2);
    }

    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  FRESH_INCL : FALSE",
        bigbuf);

    other_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Reserved",
        bigbuf);

    return(1);
}

/*
 * Table 3.5.1.2-1 Result Codes
 */
static const gchar *
rev_res_code_type(guint8 res_code)
{
    const gchar *str;

    switch (res_code)
    {
    case 0: str = "Accepted - Operation successful"; break;
    case 1: str = "Rejected - Unknown reason"; break;
    case 2: str = "Rejected - Data size mismatch"; break;
    case 3: str = "Rejected - Protocol version mismatch"; break;
    case 4: str = "Rejected - Invalid parameter"; break;
    case 5: str = "Rejected - SID/NID length mismatch"; break;
    case 6: str = "Rejected - Message not expected in this mode"; break;
    case 7: str = "Rejected - BLOCK_ID value not supported"; break;
    case 8: str = "Rejected - Preferred roaming list length mismatch"; break;
    case 9: str = "Rejected - CRC error"; break;
    case 10: str = "Rejected - Mobile station locked"; break;
    case 11: str = "Rejected - Invalid SPC"; break;
    case 12: str = "Rejected - SPC change denied by the user"; break;
    case 13: str = "Rejected - Invalid SPASM"; break;
    case 14: str = "Rejected - BLOCK_ID not expected in this mode"; break;
    case 15: str = "Rejected - User Zone already in PUZL"; break;
    case 16: str = " Rejected - User Zone not in PUZL"; break;
    case 17: str = " Rejected - No entries in PUZL"; break;
    case 18: str = "Rejected - Operation Mode mismatch"; break;
    case 19: str = "Rejected - SimpleIP MAX_NUM_NAI mismatch"; break;
    case 20: str = "Rejected - SimpleIP MAX_NAI_LENGTH mismatch"; break;
    case 21: str = "Rejected - MobileIP MAX_NUM_NAI mismatch"; break;
    case 22: str = "Rejected - MobileIP MAX_NAI_LENGTH mismatch"; break;
    case 23: str = "Rejected - SimpleIP PAP MAX_SS_LENGTH mismatch"; break;
    case 24: str = "Rejected - SimpleIP CHAP MAX_SS_LENGTH mismatch"; break;
    case 25: str = "Rejected - MobileIP MAX_MNAAA_SS_LENGTH mismatch"; break;
    case 26: str = "Rejected - MobileIP MAX_MN-HA_SS_LENGTH mismatch"; break;
    case 27: str = "Rejected - MobileIP MN-AAA_AUTH_ALGORITHM mismatch"; break;
    case 28: str = "Rejected - MobileIP MN-HA_AUTH_ALGORITHM mismatch"; break;
    case 29: str = "Rejected - SimpleIP ACT_NAI_ENTRY_INDEX mismatch"; break;
    case 30: str = "Rejected - MobileIP ACT_NAI_ENTRY_INDEX mismatch"; break;
    case 31: str = "Rejected - SimpleIP PAP NAI_ENTRY_INDEX mismatch"; break;
    case 32: str = "Rejected - SimpleIP CHAP NAI_ENTRY_INDEX mismatch"; break;
    case 33: str = "Rejected - MobileIP NAI_ENTRY_INDEX mismatch"; break;
    case 34: str = "Rejected - Unexpected PRL_BLOCK_ID change"; break;
    case 35: str = "Rejected - PRL format mismatch"; break;
    case 36: str = "Rejected - HRPD Access Authentication MAX_NAI_LENGTH mismatch"; break;
    case 37: str = "Rejected - HRPD Access Authentication CHAP MAX_SS_LENGTH mismatch"; break;
    case 38: str = " Rejected - MMD MAX_NUM_IMPU mismatch"; break;
    case 39: str = " Rejected - MMD MAX_IMPU_LENGTH mismatch"; break;
    case 40: str = " Rejected - MMD MAX_NUM_P-CSCF mismatch"; break;
    case 41: str = " Rejected - MMD MAX_P-CSCF_LENGTH mismatch"; break;
    case 42: str = " Rejected - Unexpected System Tag BLOCK_ID Change"; break;
    case 43: str = " Rejected - System Tag Format mismatch"; break;
    case 44: str = " Rejected - NUM_MMS_URI mismatch"; break;
    case 45: str = " Rejected - MMS_URI _LENGTH mismatch"; break;
    case 46: str = " Rejected - Invalid MMS_URI"; break;
    default:
        if ((res_code >= 47) && (res_code <= 127)) { str = "Reserved for future standardization"; break; }
        else if ((res_code >= 128) && (res_code <= 254)) { str = "Available for manufacturer-specific Result Code definitions"; break; }
        else { str = "Reserved"; break; }
    }

    return(str);
}

/*
 * Table 3.5.1.7-1 Feature Identifier
 */
static const gchar *
rev_feat_id_type(guint8 feat_id)
{
    const gchar *str;

    switch (feat_id)
    {
    case 0: str = "NAM Download (DATA_P_REV)"; break;
    case 1: str = "Key Exchange (A_KEY_P_REV)"; break;
    case 2: str = "System Selection for Preferred Roaming (SSPR_P_REV)"; break;
    case 3: str = "Service Programming Lock (SPL_P_REV)"; break;
    case 4: str = "Over-The-Air Parameter Administration (OTAPA_P_REV)"; break;
    case 5: str = "Preferred User Zone List (PUZL_P_REV)"; break;
    case 6: str = "3G Packet Data (3GPD)"; break;
    case 7: str = "Secure MODE (SECURE_MODE_P_REV)"; break;
    case 8: str = "Multimedia Domain (MMD)"; break;
    case 9: str = "System Tag Download (TAG_P_REV)"; break;
    case 10: str = "Multimedia Messaging Service (MMS)"; break;
    default:
        if ((feat_id >= 11) && (feat_id <= 191)) { str = "Reserved for future standardization"; break; }
        else if ((feat_id >= 192) && (feat_id <= 254)) { str = "Available for manufacturer-specific features"; break; }
        else { str = "Reserved"; break; }
    }

    return(str);
}

#define REV_TYPE_CAP_INFO_OP_MODE       0
#define REV_TYPE_CAP_INFO_CDMA_BAND     1
#define REV_TYPE_CAP_INFO_MEID          2
#define REV_TYPE_CAP_INFO_ICCID         3
#define REV_TYPE_CAP_INFO_EXT_UIM_ID    4
#define REV_TYPE_CAP_INFO_MEID_ME       5

/*
 * Table 3.5.1.17.1-1 Capability Information Record Types
 */
static const gchar *
rev_cap_info_record_type(guint8 rec_type)
{
    const gchar *str;

    switch (rec_type)
    {
    case 0: str = "Operating Mode Information"; break;
    case 1: str = "CDMA Band Class Information"; break;
    case 2: str = "MEID"; break;
    case 3: str = "ICCID"; break;
    case 4: str = "EXT_UIM_ID"; break;
    case 5: str = "MEID_ME"; break;
    default:
        str = "Reserved"; break;
    }

    return(str);
}

#define FOR_BLOCK_VAL_VERIFY_SPC                0
#define FOR_BLOCK_VAL_CHANGE_SPC                1
#define FOR_BLOCK_VAL_VALDATE_SPASM             2

/*
 * Table 4.5.4-1 Validation Parameter Block Types
 */
static const gchar *
for_param_block_val(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "Verify SPC"; break;
    case 1: str = "Change SPC"; break;
    case 2: str = "Validate SPASM"; break;
    default:
        if ((block_type >= 3) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
        else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
        else { str = "Reserved"; break; }
    }

    return(str);
}

#define REV_BLOCK_SSPR_PRL_DIM          0
#define REV_BLOCK_SSPR_PRL              1
#define REV_BLOCK_SSPR_EXT_PRL_DIM      2

/*
 * Table 3.5.3-1 SSPR Parameter Block Types
 */
static const gchar *
rev_param_block_sspr(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "Preferred Roaming List Dimensions"; break;
    case 1: str = "Preferred Roaming List"; break;
    case 2: str = "Extended Preferred Roaming List Dimensions"; break;
    default:
        if ((block_type >= 3) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
        else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
        else { str = "Reserved"; break; }
    }

    return(str);
}

#define FOR_BLOCK_SSPR_PRL              0
#define FOR_BLOCK_SSPR_EXT_PRL          1

/*
 * Table 4.5.3-1 SSPR Parameter Block Types
 */
static const gchar *
for_param_block_sspr(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "Preferred Roaming List"; break;
    case 1: str = "Extended Preferred Roaming List with SSPR_P_REV greater than 00000001"; break;
    default:
        if ((block_type >= 2) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
        else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
        else { str = "Reserved"; break; }
    }

    return(str);
}

#define REV_BLOCK_NAM_CDMA_ANALOG       0
#define REV_BLOCK_NAM_MDN               1
#define REV_BLOCK_NAM_CDMA              2
#define REV_BLOCK_NAM_IMSI_T            3

/*
 * Table 3.5.2-1 NAM Parameter Block Types
 */
static const gchar *
rev_param_block_nam(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "CDMA/Analog NAM"; break;
    case 1: str = "Mobile Directory Number"; break;
    case 2: str = "CDMA NAM"; break;
    case 3: str = "IMSI_T"; break;
    default:
        if ((block_type >= 4) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
        else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
        else { str = "Reserved"; break; }
    }

    return(str);
}

#define FOR_BLOCK_NAM_CDMA_ANALOG       0
#define FOR_BLOCK_NAM_MDN               1
#define FOR_BLOCK_NAM_CDMA              2
#define FOR_BLOCK_NAM_IMSI_T            3

/*
 * Table 4.5.2-1 NAM Parameter Block Types
 */
static const gchar *
for_param_block_nam(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "CDMA/Analog NAM Download"; break;
    case 1: str = "Mobile Directory Number"; break;
    case 2: str = "CDMA NAM Download"; break;
    case 3: str = "IMSI_T"; break;
    default:
        if ((block_type >= 4) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
        else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
        else { str = "Reserved"; break; }
    }

    return(str);
}

/*
 * Table 3.5.6-1 PUZL Parameter Block Types
 */
static const gchar *
rev_param_block_puzl(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "PUZL Dimensions"; break;
    case 1: str = "PUZL Priorities"; break;
    case 2: str = "User Zone"; break;
    case 3: str = "Preferred User Zone List"; break;
    default:
        if ((block_type >= 4) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
        else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
        else { str = "Reserved"; break; }
    }

    return(str);
}

#define FOR_BLOCK_PUZL_UZ_INS                   0
#define FOR_BLOCK_PUZL_UZ_UPD                   1
#define FOR_BLOCK_PUZL_UZ_DEL                   2
#define FOR_BLOCK_PUZL_UZ_PRI_CHANGE            3
#define FOR_BLOCK_PUZL_FLAGS                    4

/*
 * Table 4.5.6-1 PUZL Parameter Block Types
 */
static const gchar *
for_param_block_puzl(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "User Zone Insert"; break;
    case 1: str = "User Zone Update"; break;
    case 2: str = "User Zone Delete"; break;
    case 3: str = "User Zone Priority Change"; break;
    case 4: str = "PUZL Flags"; break;
    default:
        if ((block_type >= 5) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
        else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
        else { str = "Reserved"; break; }
    }

    return(str);
}

#define REV_BLOCK_3GPD_OP_CAP                   0
#define REV_BLOCK_3GPD_OP_MODE                  1
#define REV_BLOCK_3GPD_SIP_CAP                  2
#define REV_BLOCK_3GPD_MIP_CAP                  3
#define REV_BLOCK_3GPD_SIP_USER_PRO             4
#define REV_BLOCK_3GPD_MIP_USER_PRO             5
#define REV_BLOCK_3GPD_SIP_STATUS               6
#define REV_BLOCK_3GPD_MIP_STATUS               7
#define REV_BLOCK_3GPD_SIP_PAP_SS               8
#define REV_BLOCK_3GPD_SIP_CHAP_SS              9
#define REV_BLOCK_3GPD_MIP_SS                   10
#define REV_BLOCK_3GPD_HRPD_ACC_AUTH_CAP        11
#define REV_BLOCK_3GPD_HRPD_ACC_AUTH_USER       12
#define REV_BLOCK_3GPD_HRPD_ACC_AUTH_CHAP_SS    13

/*
 * Table 3.5.8-1 3GPD Parameter Block Types
 */
static const gchar *
rev_param_block_3gpd(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "3GPD Operation Capability Parameters"; break;
    case 1: str = "3GPD Operation Mode Parameters"; break;
    case 2: str = "SimpleIP Capability Parameters"; break;
    case 3: str = "MobileIP Capability Parameters"; break;
    case 4: str = "SimpleIP User Profile Parameters"; break;
    case 5: str = "Mobile IP User Profile Parameters"; break;
    case 6: str = "SimpleIP Status Parameters"; break;
    case 7: str = "MobileIP Status Parameters"; break;
    case 8: str = "SimpleIP PAP SS Parameters"; break;
    case 9: str = "SimpleIP CHAP SS Parameters"; break;
    case 10: str = "MobileIP SS Parameters"; break;
    case 11: str = "HRPD Access Authentication Capability Parameters"; break;
    case 12: str = "HRPD Access Authentication User Profile Parameters"; break;
    case 13: str = "HRPD Access Authentication CHAP SS Parameters"; break;
    default:
        str = "Reserved"; break;
    }

    return(str);
}

#define FOR_BLOCK_3GPD_OP_MODE                  0
#define FOR_BLOCK_3GPD_SIP_USER_PRO             1
#define FOR_BLOCK_3GPD_MIP_USER_PRO             2
#define FOR_BLOCK_3GPD_SIP_STATUS               6
#define FOR_BLOCK_3GPD_MIP_STATUS               7
#define FOR_BLOCK_3GPD_SIP_PAP_SS               8
#define FOR_BLOCK_3GPD_SIP_CHAP_SS              9
#define FOR_BLOCK_3GPD_MIP_SS                   10
#define FOR_BLOCK_3GPD_HRPD_ACC_AUTH_USER       11
#define FOR_BLOCK_3GPD_HRPD_ACC_AUTH_CHAP_SS    12

/*
 * Table 4.5.7-1 3GPD Parameter Block Types
 */
static const gchar *
for_param_block_3gpd(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "3GPD Operation Mode Parameters"; break;
    case 1: str = "SimpleIP User Profile Parameters"; break;
    case 2: str = "Mobile IP User Profile Parameters"; break;
    case 6: str = "SimpleIP Status Parameters"; break;
    case 7: str = "MobileIP Status Parameters"; break;
    case 8: str = "SimpleIP PAP SS Parameters"; break;
    case 9: str = "SimpleIP CHAP SS Parameters"; break;
    case 10: str = "MobileIP SS Parameters"; break;
    case 11: str = "HRPD Access Authentication User Profile Parameters"; break;
    case 12: str = "HRPD Access Authentication CHAP SS Parameters"; break;
    default:
        str = "Reserved"; break;
    }

    return(str);
}

#define REV_BLOCK_MMD_APP               0

/*
 * Table 3.5.9-1 MMD Parameter Block Types
 */
static const gchar *
rev_param_block_mmd(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "MMD Application Parameters"; break;
    default:
        str = "Reserved"; break;
    }

    return(str);
}

#define FOR_BLOCK_MMD_APP               0

/*
 * Table 4.5.8-1 MMD Parameter Block Types
 */
static const gchar *
for_param_block_mmd(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "MMD Application Parameters"; break;
    default:
        str = "Reserved"; break;
    }

    return(str);
}

#define REV_BLOCK_SYSTAG_HOME_SYSTAG            0
#define REV_BLOCK_SYSTAG_GROUP_TAG_LIST_DIM     1
#define REV_BLOCK_SYSTAG_GROUP_TAG_LIST         2
#define REV_BLOCK_SYSTAG_SPEC_TAG_LIST_DIM      3
#define REV_BLOCK_SYSTAG_SPEC_TAG_LIST          4
#define REV_BLOCK_SYSTAG_CALL_PROMPT_LIST_DIM   5
#define REV_BLOCK_SYSTAG_CALL_PROMPT_LIST       6

/*
 * Table 3.5.10-1 System Tag Parameter Block Types
 */
static const gchar *
rev_param_block_systag(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "Home System Tag"; break;
    case 1: str = "Group Tag List Dimensions"; break;
    case 2: str = "Group Tag List"; break;
    case 3: str = "Specific Tag List Dimensions"; break;
    case 4: str = "Specific Tag List"; break;
    case 5: str = "Call Prompt List Dimensions"; break;
    case 6: str = "Call Prompt List"; break;
    default:
        str = "Reserved"; break;
    }

    return(str);
}

/*
 * Table 4.5.9-1 System Tag Parameter Block Types
 */
static const gchar *
for_param_block_systag(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "Home System Tag"; break;
    case 1: str = "Group Tag List"; break;
    case 2: str = "Specific Tag List"; break;
    case 3: str = "Call Prompt List"; break;
    default:
        if ((block_type >= 4) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
        else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
        else { str = "Reserved"; break; }
    }

    return(str);
}

#define REV_BLOCK_MMS_URI               0
#define REV_BLOCK_MMS_URI_CAP           1

/*
 * Table 3.5.12-1 MMS Parameter Block Types
 */
static const gchar *
rev_param_block_mms(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "MMS URI Parameters"; break;
    case 1: str = "MMS URI Capability Parameters"; break;
    default:
        str = "Reserved"; break;
    }

    return(str);
}

#define FOR_BLOCK_MMS_URI               0

/*
 * Table 4.5.10-1 MMS Parameter Block Types
 */
static const gchar *
for_param_block_mms(guint8 block_type)
{
    const gchar *str;

    switch (block_type)
    {
    case 0: str = "MMS URI Parameters"; break;
    default:
        str = "Reserved"; break;
    }

    return(str);
}

/* PARAMETER BLOCK DISSECTION */

/*
 * 3.5.2.1
 */
static void
rev_param_block_nam_cdma_analog(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;
    guint32     count;
    proto_tree  *subtree;
    proto_item  *item;
    const gchar *str = NULL;

    saved_offset = offset;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xffe0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  First paging channel (FIRSTCHP) used in the home system (%u)",
        bigbuf,
        (value & 0xffe0) >> 5);

    offset++;

    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x1fffc0, 24);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 3,
        "%s :  Home system identification (HOME_SID) (%u)",
        bigbuf,
        (value & 0x1fffc0) >> 6);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset + 2, 1,
        "%s :  Extended address indicator (EX)",
        bigbuf);

    offset += 2;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x1fe0, 16);
    item =
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 2,
            "%s :  Station class mark (SCM) (%u)",
            bigbuf,
            (value & 0x1fe0) >> 5);

    /*
     * following SCM decode is from:
     *  3GPP2 C.S0005-0 section 2.3.3
     *  3GPP2 C.S0072-0 section 2.1.2
     */
    subtree = proto_item_add_subtree(item, ett_scm);

    other_decode_bitfield_value(bigbuf, value, 0x1000, 16);
    proto_tree_add_none_format(subtree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Extended SCM Indicator: %s",
        bigbuf,
        (value & 0x1000) ? "Band Classes 1,4" : "Other bands");

    other_decode_bitfield_value(bigbuf, value, 0x0800, 16);
    proto_tree_add_none_format(subtree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  %s",
        bigbuf,
        (value & 0x0800) ? "Dual Mode" : "CDMA Only");

    other_decode_bitfield_value(bigbuf, value, 0x0400, 16);
    proto_tree_add_none_format(subtree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  %s",
        bigbuf,
        (value & 0x0400) ? "Slotted" : "Non-Slotted");

    if (value & 0x0200)
    {
        str = "";
        proto_item_append_text(item, "%s", " (MEID configured)");
    }
    else
    {
        str = "not ";
    }

    other_decode_bitfield_value(bigbuf, value, 0x0200, 16);
    proto_tree_add_none_format(subtree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  MEID %sconfigured",
        bigbuf,
        str);

    other_decode_bitfield_value(bigbuf, value, 0x0100, 16);
    proto_tree_add_none_format(subtree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  25 MHz Bandwidth",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0080, 16);
    proto_tree_add_none_format(subtree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  %s Transmission",
        bigbuf,
        (value & 0x0080) ? "Discontinuous" : "Continuous");

    switch ((value & 0x0060) >> 5)
    {
    case 0x00: str = "Class I"; break;
    case 0x01: str = "Class II"; break;
    case 0x02: str = "Class III"; break;
    case 0x03: str = "Reserved"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x0060, 16);
    proto_tree_add_none_format(subtree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Power Class for Band Class 0 Analog Operation: %s",
        bigbuf,
        str);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x1fe0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Mobile station protocol revision number (MOB_P_REV) (%u)",
        bigbuf,
        (value & 0x1fe0) >> 5);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset + 1, 1,
        "%s :  IMSI_M Class assignment of the mobile station (IMSI_M_CLASS), Class %u",
        bigbuf,
        (value & 0x10) >> 4);

    other_decode_bitfield_value(bigbuf, value, 0x0e, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset + 1, 1,
        "%s :  Number of IMSI_M address digits (IMSI_M_ADDR_NUM) (%u), %u digits in NMSI",
        bigbuf,
        (value & 0x0e) >> 1,
        (value & 0x10) ? ((value & 0x0e) >> 1) + 4 : 0);

    offset++;

    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x01ff80, 24);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 3,
        "%s :  Mobile country code (MCC_M)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x7f, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset + 2, 1,
        "%s :  11th and 12th digits of the IMSI_M (IMSI__M_11_12)",
        bigbuf);

    offset += 3;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 5,
        "The least significant 10 digits of the IMSI_M (IMSI_M_S) (34 bits)");

    offset += 4;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x3c, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Access overload class (ACCOLC) (%u)",
        bigbuf,
        (value & 0x3c) >> 2);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Local control status (LOCAL_CONTROL)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Termination indicator for the home system (MOB_TERM_HOME)",
        bigbuf);

    offset++;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Termination indicator for SID roaming (MOB_TERM_FOR_SID)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Termination indicator for NID roaming (MOB_TERM_FOR_NID)",
        bigbuf);

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x3fc0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Maximum stored SID/NID pairs (MAX_SID_NID) (%u)",
        bigbuf,
        (value & 0x3fc0) >> 6);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    count = (value & 0x3fc0) >> 6;

    other_decode_bitfield_value(bigbuf, value, 0x3fc0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Number of stored SID/NID pairs (STORED_SID_NID) (%u)",
        bigbuf,
        count);

    other_decode_bitfield_value(bigbuf, value, 0x003f, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  SID/NID pairs (MSB)",
        bigbuf);

    offset += 2;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, len - (offset - saved_offset),
        "SID/NID pairs, Reserved");
}

/*
 * 3.5.2.2
 * 4.5.2.2
 */
static void
param_block_nam_mdn(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value, count, i;

    saved_offset = offset;

    value = tvb_get_guint8(tvb, offset);

    count = (value & 0xf0) >> 4;

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Number of digits (N_DIGITS) (%u)",
        bigbuf,
        count);

    for (i=0; i < count; i++)
    {
        bigbuf[i] = dtmf_digits[(value & 0x0f)];

        if ((i + 1) < count)
        {
            offset++;
            value = tvb_get_guint8(tvb, offset);
            bigbuf[i+1] = dtmf_digits[(value & 0xf0) >> 4];
            i++;
        }
    }
    bigbuf[i] = '\0';

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, saved_offset, len,
        "Mobile directory number, %s",
        bigbuf);

    if (!(count & 0x01))
    {
        other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s :  Reserved",
            bigbuf);
    }
}

/*
 * 3.5.2.3
 */
static void
rev_param_block_nam_cdma(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;
    guint32     count;

    saved_offset = offset;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Reserved",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Slotted Mode",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Reserved",
        bigbuf);

    offset++;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Mobile station protocol revision number (MOB_P_REV) (%u)",
        bigbuf,
        value);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x8000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  IMSI_M Class assignment of the mobile station (IMSI_M_CLASS), Class %u",
        bigbuf,
        (value & 0x8000) >> 15);

    other_decode_bitfield_value(bigbuf, value, 0x7000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Number of IMSI_M address digits (IMSI_M_ADDR_NUM) (%u), %u digits in NMSI",
        bigbuf,
        (value & 0x7000) >> 12,
        (value & 0x8000) ? ((value & 0x7000) >> 12) + 4 : 0);

    other_decode_bitfield_value(bigbuf, value, 0x0ffc, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Mobile country code (MCC_M)",
        bigbuf);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x3f80, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  11th and 12th digits of the IMSI_M (IMSI__M_11_12)",
        bigbuf);

    offset++;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 5,
        "The least significant 10 digits of the IMSI_M (IMSI_M_S) (34 bits)");

    offset += 4;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x01e0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Access overload class (ACCOLC) (%u)",
        bigbuf,
        (value & 0x01e0) >> 5);

    other_decode_bitfield_value(bigbuf, value, 0x0010, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Local control status (LOCAL_CONTROL)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0008, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Termination indicator for the home system (MOB_TERM_HOME)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0004, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Termination indicator for SID roaming (MOB_TERM_FOR_SID)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0002, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Termination indicator for NID roaming (MOB_TERM_FOR_NID)",
        bigbuf);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x01fe, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Maximum stored SID/NID pairs (MAX_SID_NID) (%u)",
        bigbuf,
        (value & 0x01fe) >> 1);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    count = (value & 0x01fe) >> 1;

    other_decode_bitfield_value(bigbuf, value, 0x01fe, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Number of stored SID/NID pairs (STORED_SID_NID) (%u)",
        bigbuf,
        count);

    other_decode_bitfield_value(bigbuf, value, 0x0001, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  SID/NID pairs (MSB)",
        bigbuf);

    offset += 2;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, len - (offset - saved_offset),
        "SID/NID pairs, Reserved");
}

/*
 * 3.5.2.4
 * 4.5.2.4
 */
static void
param_block_nam_imsi_t(tvbuff_t *tvb, proto_tree *tree, guint len _U_, guint32 offset)
{
    guint32     value;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  IMSI_T Class assignment of the mobile station (IMSI_T_CLASS), Class %u",
        bigbuf,
        (value & 0x80) >> 7);

    other_decode_bitfield_value(bigbuf, value, 0x70, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Number of IMSI_T address digits (IMSI_T_ADDR_NUM ) (%u), %u digits in NMSI",
        bigbuf,
        (value & 0x70) >> 4,
        (value & 0x80) ? ((value & 0x70) >> 4) + 4 : 0);

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x0ffc, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Mobile country code (MCC_T)",
        bigbuf);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x03f8, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  11th and 12th digits of the IMSI_T (IMSI__T_11_12)",
        bigbuf);

    offset++;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 5,
        "The least significant 10 digits of the IMSI_T (IMSI_T_S) (34 bits)");

    offset += 4;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Reserved",
        bigbuf);
}

/*
 * 4.5.2.1
 */
static void
for_param_block_nam_cdma_analog(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;
    guint32     count;

    saved_offset = offset;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xffe0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  First paging channel (FIRSTCHP) used in the home system (%u)",
        bigbuf,
        (value & 0xffe0) >> 5);

    offset++;

    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x1fffc0, 24);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 3,
        "%s :  Home system identification (HOME_SID) (%u)",
        bigbuf,
        (value & 0x1fffc0) >> 6);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset + 2, 1,
        "%s :  Extended address indicator (EX)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset + 2, 1,
        "%s :  IMSI_M Class assignment of the mobile station (IMSI_M_CLASS), Class %u",
        bigbuf,
        (value & 0x10) >> 4);

    other_decode_bitfield_value(bigbuf, value, 0x0e, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset + 2, 1,
        "%s :  Number of IMSI_M address digits (IMSI_M_ADDR_NUM) (%u), %u digits in NMSI",
        bigbuf,
        (value & 0x0e) >> 1,
        (value & 0x10) ? ((value & 0x0e) >> 1) + 4 : 0);

    offset += 2;

    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x01ff80, 24);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 3,
        "%s :  Mobile country code (MCC_M)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x7f, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset + 2, 1,
        "%s :  11th and 12th digits of the IMSI_M (IMSI__M_11_12)",
        bigbuf);

    offset += 3;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 5,
        "The least significant 10 digits of the IMSI_M (IMSI_M_S) (34 bits)");

    offset += 4;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x3c, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Access overload class (ACCOLC) (%u)",
        bigbuf,
        (value & 0x3c) >> 2);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Local control status (LOCAL_CONTROL)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Termination indicator for the home system (MOB_TERM_HOME)",
        bigbuf);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x8000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Termination indicator for SID roaming (MOB_TERM_FOR_SID)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x4000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Termination indicator for NID roaming (MOB_TERM_FOR_NID)",
        bigbuf);

    count = (value & 0x3fc0) >> 6;

    other_decode_bitfield_value(bigbuf, value, 0x3fc0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Number of SID/NID pairs (N_SID_NID) (%u)",
        bigbuf,
        count);

    other_decode_bitfield_value(bigbuf, value, 0x003f, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  SID/NID pairs (MSB)",
        bigbuf);

    offset += 2;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, len - (offset - saved_offset),
        "SID/NID pairs, Reserved");
}

/*
 * 4.5.2.2
 * see param_block_nam_mdn()
 */

/*
 * 4.5.2.3
 */
static void
for_param_block_nam_cdma(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;
    guint32     count;

    saved_offset = offset;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x8000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  IMSI_M Class assignment of the mobile station (IMSI_M_CLASS), Class %u",
        bigbuf,
        (value & 0x8000) >> 15);

    other_decode_bitfield_value(bigbuf, value, 0x7000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Number of IMSI_M address digits (IMSI_M_ADDR_NUM) (%u), %u digits in NMSI",
        bigbuf,
        (value & 0x7000) >> 12,
        (value & 0x8000) ? ((value & 0x7000) >> 12) + 4 : 0);

    other_decode_bitfield_value(bigbuf, value, 0x0ffc, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Mobile country code (MCC_M)",
        bigbuf);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x3f80, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  11th and 12th digits of the IMSI_M (IMSI__M_11_12)",
        bigbuf);

    offset++;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 5,
        "The least significant 10 digits of the IMSI_M (IMSI_M_S) (34 bits)");

    offset += 4;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x01e0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Access overload class (ACCOLC) (%u)",
        bigbuf,
        (value & 0x01e0) >> 5);

    other_decode_bitfield_value(bigbuf, value, 0x0010, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Local control status (LOCAL_CONTROL)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0008, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Termination indicator for the home system (MOB_TERM_HOME)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0004, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Termination indicator for SID roaming (MOB_TERM_FOR_SID)",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0002, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Termination indicator for NID roaming (MOB_TERM_FOR_NID)",
        bigbuf);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    count = (value & 0x01fe) >> 1;

    other_decode_bitfield_value(bigbuf, value, 0x01fe, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Number of SID/NID pairs (N_SID_NID) (%u)",
        bigbuf,
        count);

    other_decode_bitfield_value(bigbuf, value, 0x0001, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  SID/NID pairs (MSB)",
        bigbuf);

    offset += 2;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, len - (offset - saved_offset),
        "SID/NID pairs, Reserved");
}

/*
 * 4.5.2.4
 * see param_block_nam_imsi_t()
 */

/*
 * 4.5.4.1
 * 4.5.4.2
 */
static void
for_param_block_val_spc(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;

    EXACT_DATA_CHECK(len, 3);

    saved_offset = offset;

    value = tvb_get_guint8(tvb, offset++);
    bigbuf[0] = bcd_digits[(value & 0x0f)];
    bigbuf[1] = bcd_digits[(value & 0xf0) >> 4];

    value = tvb_get_guint8(tvb, offset++);
    bigbuf[2] = bcd_digits[(value & 0x0f)];
    bigbuf[3] = bcd_digits[(value & 0xf0) >> 4];

    value = tvb_get_guint8(tvb, offset++);
    bigbuf[4] = bcd_digits[(value & 0x0f)];
    bigbuf[5] = bcd_digits[(value & 0xf0) >> 4];
    bigbuf[6] = '\0';

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, saved_offset, len,
        "Service programming code: %s",
        bigbuf);
}

/*
 * 4.5.4.3
 */
static void
for_param_block_val_spasm(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32     value;

    if (len == 1)
    {
        value = tvb_get_guint8(tvb, offset);

        other_decode_bitfield_value(bigbuf, value, 0x80, 8);
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s :  OTAPA SPASM validation signature %sincluded indicator",
            bigbuf,
            (value & 0x80) ? "" : "not ");

        other_decode_bitfield_value(bigbuf, value, 0x40, 8);
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s :  %s SPASM protection for the active NAM",
            bigbuf,
            (value & 0x40) ? "Activate" : "Do not activate");

        other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s :  Reserved",
            bigbuf);
    }
    else
    {
        EXACT_DATA_CHECK(len, 3);

        value = tvb_get_ntoh24(tvb, offset);

        other_decode_bitfield_value(bigbuf, value, 0x800000, 24);
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 3,
            "%s :  OTAPA SPASM validation signature %sincluded indicator",
            bigbuf,
            (value & 0x800000) ? "" : "not ");

        other_decode_bitfield_value(bigbuf, value, 0x7fffe0, 24);
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 3,
            "%s :  OTAPA SPASM validation signature (0x%x)",
            bigbuf,
            (value & 0x7fffe0) >> 5);

        other_decode_bitfield_value(bigbuf, value, 0x000010, 24);
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 3,
            "%s :  %s SPASM protection for the active NAM",
            bigbuf,
            (value & 0x000010) ? "Activate" : "Do not activate");

        other_decode_bitfield_value(bigbuf, value, 0x00000f, 24);
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 3,
            "%s :  Reserved",
            bigbuf);
    }
}

/* FORWARD MESSAGES */

/*
 * 4.5.1.1
 */
static void
msg_config_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    const gchar *str = NULL;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_blocks);

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = rev_param_block_nam(oct);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "[%u]:  %s (%u)",
            i+1,
            str,
            oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.2
 */
static void
msg_download_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    const gchar *str = NULL;
    proto_tree  *subtree;
    proto_item  *item;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = for_param_block_nam(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_for_nam_block);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
            case FOR_BLOCK_NAM_CDMA_ANALOG:
                for_param_block_nam_cdma_analog(tvb, subtree, block_len, offset);
                break;

            case FOR_BLOCK_NAM_MDN:
                param_block_nam_mdn(tvb, subtree, block_len, offset);
                break;

            case FOR_BLOCK_NAM_CDMA:
                for_param_block_nam_cdma(tvb, subtree, block_len, offset);
                break;

            case FOR_BLOCK_NAM_IMSI_T:
                param_block_nam_imsi_t(tvb, subtree, block_len, offset);
                break;

            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Block Data");
                break;
            }

            offset += block_len;
        }
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.3
 */
static void
msg_ms_key_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      akey_prev, param_len;
    proto_tree  *subtree;
    proto_item  *item;
    guint32     saved_offset;
    const gchar *str = NULL;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    akey_prev = tvb_get_guint8(tvb, offset);

    switch (akey_prev)
    {
    case 0x02: str = "2G A-key generation"; break;
    case 0x03: str = "2G A-key and 3G Root Key generation"; break;
    case 0x04: str = "3G Root Key generation"; break;
    case 0x05: str = "Enhanced 3G Root Key generation"; break;
    default: str = "Unknown"; break;
    }

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "A-Key Protocol Revision (%u):  %s",
        akey_prev,
        str);
    offset++;

    if (akey_prev < 0x03)
    {
        param_len = tvb_get_guint8(tvb, offset);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, param_len + 1,
                "Key exchange parameter P");
        subtree = proto_item_add_subtree(item, ett_key_p);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, param_len);
        offset++;

        if (param_len > 0)
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none,
                tvb, offset, param_len,
                "Parameter P");
            offset += param_len;
        }

        param_len = tvb_get_guint8(tvb, offset);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, param_len + 1,
                "Key exchange parameter G");
        subtree = proto_item_add_subtree(item, ett_key_g);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, param_len);
        offset++;

        if (param_len > 0)
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none,
                tvb, offset, param_len,
                "Parameter G");
            offset += param_len;
        }
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.4
 */
static void
msg_key_gen_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      param_len;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    param_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, param_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), param_len);

    if (param_len > 0)
    {
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, param_len,
            "Base Station Calculation Result");
        offset += param_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.5
 */
static void
msg_reauth_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{

    EXACT_DATA_CHECK(len, 4);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 4,
        "Random Challenge value");
}

/*
 * 4.5.1.6
 * Commit Request (no data associated)
 */

/*
 * 4.5.1.7
 */
static void
msg_protocap_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32     i, saved_offset;
    guint8      oct, num_cap;
    const gchar *str = NULL;

    if (len == 0)
    {
        /*
         * if the base station did not request new cap info OR
         * this is an earlier release
         */
        return;
    }

    saved_offset = offset;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "OTASP protocol revision");

    offset++;

    num_cap = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of Capability Records (%u)",
        num_cap);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_cap);

    for (i=0; i < num_cap; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = rev_cap_info_record_type(oct);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "[%u]:  %s (%u)",
            i+1,
            str,
            oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.8
 */
static void
msg_sspr_config_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    const gchar *str = NULL;
    guint32     saved_offset;
    guint32     value;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_param_block_sspr(oct);

    item =
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

    offset++;

    if (oct == REV_BLOCK_SSPR_PRL)
    {
        subtree = proto_item_add_subtree(item, ett_rev_sspr_block);

        if ((len - (offset - saved_offset)) < 3)
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        value = tvb_get_ntohs(tvb, offset);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 2,
            "Segment offset (%u)",
            value);
        offset += 2;

        oct = tvb_get_guint8(tvb, offset);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "Maximum segment size (%u)",
            oct);
        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.9
 */
static void
msg_sspr_download_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_len;
    const gchar *str = NULL;
    guint32     saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = for_param_block_sspr(oct);

    item =
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

    subtree = proto_item_add_subtree(item, ett_for_sspr_block);
    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(subtree, hf_ansi_683_length,
        tvb, offset, 1, block_len);
    offset++;

    if (block_len > (len - (offset - saved_offset)))
    {
        proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
            offset, len - (offset - saved_offset), "Short Data (?)");
        return;
    }

    if (block_len > 0)
    {
        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, block_len, "Block Data");
        offset += block_len;
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.10
 */
static void
msg_validate_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    const gchar *str = NULL;
    proto_tree  *subtree;
    proto_item  *item;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = for_param_block_val(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_for_val_block);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);

        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
            case FOR_BLOCK_VAL_VERIFY_SPC:
            case FOR_BLOCK_VAL_CHANGE_SPC:
                for_param_block_val_spc(tvb, subtree, block_len, offset);
                break;

            case FOR_BLOCK_VAL_VALDATE_SPASM:
                for_param_block_val_spasm(tvb, subtree, block_len, offset);
                break;

            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Block Data");
                break;
            }

            offset += block_len;
        }
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.11
 */
static void
msg_otapa_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  %s OTAPA session",
        bigbuf,
        (oct & 0x80) ? "Start" : "Stop");

    other_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Reserved",
        bigbuf);

    offset++;
}

/*
 * 4.5.1.12
 */
static void
msg_puzl_config_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_len;
    const gchar *str = NULL;
    guint32     saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_param_block_puzl(oct);

    item =
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

    block_len = len - (offset - saved_offset);

    if (block_len > 0)
    {
        subtree = proto_item_add_subtree(item, ett_rev_puzl_block);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, block_len, "Block Data");
        offset += block_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.13
 */
static void
msg_puzl_download_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    const gchar *str = NULL;
    proto_tree  *subtree;
    proto_item  *item;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = for_param_block_puzl(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_for_puzl_block);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
            case FOR_BLOCK_PUZL_UZ_INS:
            case FOR_BLOCK_PUZL_UZ_UPD:
            case FOR_BLOCK_PUZL_UZ_DEL:
            case FOR_BLOCK_PUZL_UZ_PRI_CHANGE:
            case FOR_BLOCK_PUZL_FLAGS:
            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Block Data");
                break;
            }

            offset += block_len;
        }
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.14
 */
static void
msg_3gpd_config_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    const gchar *str = NULL;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_blocks);

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = rev_param_block_3gpd(oct);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "[%u]:  %s (%u)",
            i+1,
            str,
            oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.15
 */
static void
msg_3gpd_download_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    const gchar *str = NULL;
    proto_tree  *subtree;
    proto_item  *item;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = for_param_block_3gpd(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_for_3gpd_block);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
            case FOR_BLOCK_3GPD_OP_MODE:
            case FOR_BLOCK_3GPD_SIP_USER_PRO:
            case FOR_BLOCK_3GPD_MIP_USER_PRO:
            case FOR_BLOCK_3GPD_SIP_STATUS:
            case FOR_BLOCK_3GPD_MIP_STATUS:
            case FOR_BLOCK_3GPD_SIP_PAP_SS:
            case FOR_BLOCK_3GPD_SIP_CHAP_SS:
            case FOR_BLOCK_3GPD_MIP_SS:
            case FOR_BLOCK_3GPD_HRPD_ACC_AUTH_USER:
            case FOR_BLOCK_3GPD_HRPD_ACC_AUTH_CHAP_SS:
            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Block Data");
                break;
            }

            offset += block_len;
        }
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.16
 */
static void
msg_secure_mode_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    const gchar *str = NULL;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  %s Secure Mode",
        bigbuf,
        (oct & 0x80) ? "Start" : "Stop");

    if (oct & 0x80)
    {
        switch ((oct & 0x78) >> 3)
        {
        case 0x0: str = "SMCK generation using SSD_A and SSD_B"; break;
        case 0x1: str = "SMCK generation using 3G Root Key"; break;
        default: str = "Key in use indicator"; break;
        }
    }
    else
    {
        str = "Key in use indicator";
    }

    other_decode_bitfield_value(bigbuf, oct, 0x78, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  %s",
        bigbuf,
        str);

    other_decode_bitfield_value(bigbuf, oct, 0x07, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Reserved",
        bigbuf);

    offset++;

    if (oct & 0x80)
    {
        SHORT_DATA_CHECK(len, 8);

        proto_tree_add_text(tree,
            tvb, offset, 8,
            "Random Number used for SMCK generation");

        offset += 8;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.17
 * Reserved
 */

/*
 * 4.5.1.18
 */
static void
msg_mmd_config_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    const gchar *str = NULL;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_blocks);

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = rev_param_block_mmd(oct);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "[%u]:  %s (%u)",
            i+1,
            str,
            oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.19
 */
static void
msg_mmd_download_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    const gchar *str = NULL;
    proto_tree  *subtree;
    proto_item  *item;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = for_param_block_mmd(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_for_mmd_block);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
            case FOR_BLOCK_MMD_APP:
            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Block Data");
                break;
            }

            offset += block_len;
        }
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.20
 */
static void
msg_systag_config_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    const gchar *str = NULL;
    guint32     saved_offset;
    guint32     value;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_param_block_systag(oct);

    item =
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

    offset++;

    /*
     * possible values, but unclear in spec
     *  REV_BLOCK_SYSTAG_HOME_SYSTAG
     *  REV_BLOCK_SYSTAG_GROUP_TAG_LIST_DIM
     *  REV_BLOCK_SYSTAG_GROUP_TAG_LIST
     *  REV_BLOCK_SYSTAG_SPEC_TAG_LIST_DIM
     *  REV_BLOCK_SYSTAG_SPEC_TAG_LIST
     *  REV_BLOCK_SYSTAG_CALL_PROMPT_LIST_DIM
     *  REV_BLOCK_SYSTAG_CALL_PROMPT_LIST
     */
    if (len > (offset - saved_offset))
    {
        SHORT_DATA_CHECK(len, 3);

        subtree = proto_item_add_subtree(item, ett_segment);

        value = tvb_get_ntohs(tvb, offset);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 2,
            "Segment offset (%u)",
            value);
        offset += 2;

        oct = tvb_get_guint8(tvb, offset);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "Maximum segment size (%u)",
            oct);
        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.21
 */
static void
msg_systag_download_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_len;
    const gchar *str = NULL;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = for_param_block_systag(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s (%u)",
        str,
        oct);

    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, block_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), block_len);

    if (block_len > 0)
    {
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, block_len, "Block Data");
        offset += block_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}


/*
 * 4.5.1.22
 */
static void
msg_srvckey_gen_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x8000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Key ID: IMS Root Key",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x4000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Key ID: BCMCS Root Key",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x2000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Key ID: WLAN Root Key",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x1ff0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Key ID: Reserved",
        bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x000f, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Reserved",
        bigbuf);

    offset += 2;

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.23
 */
static void
msg_mms_config_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    const gchar *str = NULL;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_blocks);

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = rev_param_block_mms(oct);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "[%u]:  %s (%u)",
            i+1,
            str,
            oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.24
 */
static void
msg_mms_download_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    const gchar *str = NULL;
    proto_tree  *subtree;
    proto_item  *item;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = for_param_block_mms(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_for_mms_block);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
            case FOR_BLOCK_MMS_URI:
            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Block Data");
                break;
            }

            offset += block_len;
        }
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/* REVERSE MESSAGES */

/*
 * 3.5.1.1
 */
static void
msg_config_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id, num_blocks, block_len;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = rev_param_block_nam(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_rev_nam_block);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
            case REV_BLOCK_NAM_CDMA_ANALOG:
                rev_param_block_nam_cdma_analog(tvb, subtree, block_len, offset);
                break;

            case REV_BLOCK_NAM_MDN:
                param_block_nam_mdn(tvb, subtree, block_len, offset);
                break;

            case REV_BLOCK_NAM_CDMA:
                rev_param_block_nam_cdma(tvb, subtree, block_len, offset);
                break;

            case REV_BLOCK_NAM_IMSI_T:
                param_block_nam_imsi_t(tvb, subtree, block_len, offset);
                break;

            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Block Data");
                break;
            }

            offset += block_len;
        }
    }

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_blocks);

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = rev_res_code_type(oct);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "[%u]:  %s (%u)",
            i+1,
            str,
            oct);

        offset++;
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.2
 */
static void
msg_download_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = for_param_block_nam(oct);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                oct);

        subtree = proto_item_add_subtree(item, ett_for_nam_block);
        offset++;

        oct = tvb_get_guint8(tvb, offset);

        str = rev_res_code_type(oct);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.3
 */
static void
msg_ms_key_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Key exchange result code, %s (%u)",
        str,
        oct);

    offset++;
}

/*
 * 3.5.1.4
 */
static void
msg_key_gen_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, result_len;
    const gchar *str = NULL;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Key exchange result code, %s (%u)",
        str,
        oct);

    offset++;

    result_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, result_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), result_len);

    if (result_len > 0)
    {
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, result_len, "Mobile station calculation result");
        offset += result_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.5
 */
static void
msg_reauth_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32     value;

    EXACT_DATA_CHECK(len, 7);

    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xffffc0, 24);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 3,
        "%s :  Authentication signature data (AUTHR) (%u)",
        bigbuf,
        (value & 0xffffc0) >> 6);

    offset += 2;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x3fc0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "%s :  Random challenge value (RANDC) (%u)",
        bigbuf,
        (value & 0x3fc0) >> 6);

    other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset + 1, 1,
        "%s :  Call history parameter (COUNT) (%u)",
        bigbuf,
        value & 0x3f);

    offset += 2;

    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xffffff, 24);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 3,
        "%s :  Authentication Data input parameter (AUTH_DATA) (%u)",
        bigbuf,
        value);
}

/*
 * 3.5.1.6
 */
static void
msg_commit_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Data commit result code, %s (%u)",
        str,
        oct);

    offset++;
}

/*
 * 3.5.1.7
 */
static void
msg_protocap_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_feat, add_len;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    guint32     value;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 5);

    saved_offset = offset;

    value = tvb_get_ntohs(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "Mobile station firmware revision number (%u)",
        value);

    offset += 2;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Mobile station manufacturer's model number (%u)",
        oct);

    offset++;

    num_feat = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of features (%u)",
        num_feat);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_feat * 2));

    for (i=0; i < num_feat; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = rev_feat_id_type(oct);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  Feature ID, %s (%u)",
                i+1,
                str,
                oct);

        subtree = proto_item_add_subtree(item, ett_rev_feat);
        offset++;

        oct = tvb_get_guint8(tvb, offset);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "Feature protocol version (%u)",
            oct);

        offset++;
    }

    add_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, add_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), add_len);

    if (add_len > 0)
    {
        oct = tvb_get_guint8(tvb, offset);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "Band/Mode Capability Information");

        subtree = proto_item_add_subtree(item, ett_band_cap);

        other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s :  Band Class 0 Analog",
            bigbuf);

        other_decode_bitfield_value(bigbuf, oct, 0x40, 8);
        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s :  Band Class 0 CDMA",
            bigbuf);

        other_decode_bitfield_value(bigbuf, oct, 0x20, 8);
        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s :  Band Class 1 CDMA",
            bigbuf);

        other_decode_bitfield_value(bigbuf, oct, 0x10, 8);
        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s :  Band Class 3 CDMA",
            bigbuf);

        other_decode_bitfield_value(bigbuf, oct, 0x08, 8);
        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s :  Band Class 6 CDMA",
            bigbuf);

        other_decode_bitfield_value(bigbuf, oct, 0x07, 8);
        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s :  Reserved",
            bigbuf);

        offset++;

        if (add_len > 1)
        {
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, add_len - 1,
                "More Additional Fields");
            offset += (add_len - 1);
        }
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.8
 */
static void
msg_sspr_config_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_len;
    const gchar *str = NULL;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_param_block_sspr(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s (%u)",
        str,
        oct);

    offset++;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "SSPR Configuration result code, %s (%u)",
        str,
        oct);

    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, block_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), block_len);

    if (block_len > 0)
    {
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, block_len, "Block Data");
        offset += block_len;
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.9
 */
static void
msg_sspr_download_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id;
    const gchar *str = NULL;
    guint32     value;

    EXACT_DATA_CHECK(len, 5);

    block_id = tvb_get_guint8(tvb, offset);

    str = for_param_block_sspr(block_id);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s (%u)",
        str,
        block_id);

    offset++;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "SSPR Download result code, %s (%u)",
        str,
        oct);

    offset++;

    switch (block_id)
    {
    case FOR_BLOCK_SSPR_PRL:
    case FOR_BLOCK_SSPR_EXT_PRL:
        value = tvb_get_ntohs(tvb, offset);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 2,
            "Segment offset (%u)",
            value);
        offset += 2;

        oct = tvb_get_guint8(tvb, offset);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "Maximum segment size (%u)",
            oct);
        offset++;
        break;
    }
}

/*
 * 3.5.1.10
 */
static void
msg_validate_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id, num_blocks;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = for_param_block_val(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_for_val_block);
        offset++;

        oct = tvb_get_guint8(tvb, offset);

        str = rev_res_code_type(oct);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.11
 */
static void
msg_otapa_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    const gchar *str = NULL;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s (%d)",
        str,
        oct);

    offset++;

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, oct, 0xfe, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  Reserved",
        bigbuf);

    other_decode_bitfield_value(bigbuf, oct, 0x01, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s :  NAM_LOCK indicator",
        bigbuf);

    offset++;

    if (oct & 0x01)
    {
        SHORT_DATA_CHECK((len - (offset - saved_offset)), 4);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 4,
            "SPASM random challenge");
        offset += 4;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.12
 */
static void
msg_puzl_config_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_len;
    const gchar *str = NULL;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_param_block_puzl(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s (%u)",
        str,
        oct);

    offset++;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "PUZL Configuration result code, %s (%u)",
        str,
        oct);

    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, block_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), block_len);

    if (block_len > 0)
    {
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, block_len, "Block Data");
        offset += block_len;
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.13
 */
static void
msg_puzl_download_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id, num_blocks;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;
    guint32     value, temp_value;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    /* minimum required length */
    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 3));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = for_param_block_puzl(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_for_puzl_block);
        offset++;

        oct = tvb_get_guint8(tvb, offset);

        str = rev_res_code_type(oct);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

        offset++;

        oct = tvb_get_guint8(tvb, offset);

        if (oct & 0x80)
        {
            SHORT_DATA_CHECK(len, 4);

            value = tvb_get_ntohs(tvb, offset);

            other_decode_bitfield_value(bigbuf, value, 0x8000, 16);
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 2,
                "%s :  Identifiers present",
                bigbuf);

            other_decode_bitfield_value(bigbuf, value, 0x7fff, 16);
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 2,
                "%s :  User Zone ID (MSB)",
                bigbuf);

            offset += 2;

            temp_value = (value & 0x7fff) << 1;
            value = tvb_get_ntohs(tvb, offset);

            other_decode_bitfield_value(bigbuf, value, 0x8000, 16);
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 2,
                "%s :  User Zone ID (%u)",
                bigbuf,
                temp_value + ((value & 0x8000) >> 15));

            other_decode_bitfield_value(bigbuf, value, 0x7fff, 16);
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 2,
                "%s :  User Zone SID (%u)",
                bigbuf,
                (value & 0x7fff));

            offset += 2;
        }
        else
        {
            other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "%s :  Identifiers not present",
                bigbuf);

            other_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "%s :  Reserved",
                bigbuf);

            offset++;
        }
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.14
 */
static void
msg_3gpd_config_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id, num_blocks, block_len;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    /* minimum required length */
    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 3));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = rev_param_block_3gpd(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_rev_3gpd_block);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
            case REV_BLOCK_3GPD_OP_CAP:
            case REV_BLOCK_3GPD_OP_MODE:
            case REV_BLOCK_3GPD_SIP_CAP:
            case REV_BLOCK_3GPD_MIP_CAP:
            case REV_BLOCK_3GPD_SIP_USER_PRO:
            case REV_BLOCK_3GPD_MIP_USER_PRO:
            case REV_BLOCK_3GPD_SIP_STATUS:
            case REV_BLOCK_3GPD_MIP_STATUS:
            case REV_BLOCK_3GPD_SIP_PAP_SS:
            case REV_BLOCK_3GPD_SIP_CHAP_SS:
            case REV_BLOCK_3GPD_MIP_SS:
            case REV_BLOCK_3GPD_HRPD_ACC_AUTH_CAP:
            case REV_BLOCK_3GPD_HRPD_ACC_AUTH_USER:
            case REV_BLOCK_3GPD_HRPD_ACC_AUTH_CHAP_SS:
            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Block Data");
                break;
            }

            offset += block_len;
        }

        SHORT_DATA_CHECK(len, 1);

        oct = tvb_get_guint8(tvb, offset);

        str = rev_res_code_type(oct);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

        offset++;
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.15
 */
static void
msg_3gpd_download_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = for_param_block_3gpd(oct);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                oct);

        subtree = proto_item_add_subtree(item, ett_for_3gpd_block);
        offset++;

        oct = tvb_get_guint8(tvb, offset);

        str = rev_res_code_type(oct);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.16
 */
static void
msg_secure_mode_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Secure Mode result code, %s (%u)",
        str,
        oct);

    offset++;
}

/*
 * 3.5.1.17
 */
static void
msg_ext_protocap_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id, num_recs, block_len;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    guint32     value;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 6);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "OTASP Mobile Protocol Revision (%u)",
        oct);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 2,
        "Mobile station firmware revision number (%u)",
        value);

    offset += 2;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Mobile station manufacturer's model number (%u)",
        oct);

    offset++;

    num_recs = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of features (%u)",
        num_recs);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_recs * 2));

    for (i=0; i < num_recs; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = rev_feat_id_type(oct);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  Feature ID, %s (%u)",
                i+1,
                str,
                oct);

        subtree = proto_item_add_subtree(item, ett_rev_feat);
        offset++;

        oct = tvb_get_guint8(tvb, offset);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "Feature protocol version (%u)",
            oct);

        offset++;
    }

    SHORT_DATA_CHECK((len - (offset - saved_offset)), 1);

    num_recs = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of Capability Records (%u)",
        num_recs);

    offset++;

    /* minimum required length */
    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_recs * 2));

    for (i=0; i < num_recs; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = rev_cap_info_record_type(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_rev_cap);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
#ifdef MLUM
            case REV_TYPE_CAP_INFO_OP_MODE:
            case REV_TYPE_CAP_INFO_CDMA_BAND:
            case REV_TYPE_CAP_INFO_MEID:
            case REV_TYPE_CAP_INFO_ICCID:
            case REV_TYPE_CAP_INFO_EXT_UIM_ID:
                rev_param_block_mmd_app(tvb, subtree, block_len, offset);
                break;
#endif

            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Capability Data");
                break;
            }

            offset += block_len;
        }
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.18
 */
static void
msg_mmd_config_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id, num_blocks, block_len;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    /* minimum required length */
    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 3));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = rev_param_block_mmd(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_rev_mmd_block);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
#ifdef MLUM
            case REV_BLOCK_MMD_APP:
                rev_param_block_mmd_app(tvb, subtree, block_len, offset);
                break;
#endif

            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Block Data");
                break;
            }

            offset += block_len;
        }

        SHORT_DATA_CHECK(len, 1);

        oct = tvb_get_guint8(tvb, offset);

        str = rev_res_code_type(oct);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

        offset++;
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.19
 */
static void
msg_mmd_download_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = for_param_block_mmd(oct);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                oct);

        subtree = proto_item_add_subtree(item, ett_for_mmd_block);
        offset++;

        oct = tvb_get_guint8(tvb, offset);

        str = rev_res_code_type(oct);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.20
 */
static void
msg_systag_config_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_len;
    const gchar *str = NULL;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_param_block_systag(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s (%u)",
        str,
        oct);

    offset++;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "System Tag result code, %s (%u)",
        str,
        oct);

    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, block_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), block_len);

    if (block_len > 0)
    {
        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, block_len, "Block Data");
        offset += block_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.21
 */
static void
msg_systag_download_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id;
    const gchar *str = NULL;
    guint32     saved_offset;
    guint32     value;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    block_id = tvb_get_guint8(tvb, offset);

    str = for_param_block_systag(block_id);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "%s (%u)",
        str,
        block_id);

    offset++;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "System Tag Download result code, %s (%u)",
        str,
        oct);

    offset++;

    switch (block_id)
    {
    case 0x01:          /* Group Tag List Parameter */
    case 0x02:          /* Specific Tag List Parameter */
    case 0x03:          /* Call Prompt List Parameter */
        SHORT_DATA_CHECK(len, 3);

        value = tvb_get_ntohs(tvb, offset);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 2,
            "Segment offset (%u)",
            value);
        offset += 2;

        oct = tvb_get_guint8(tvb, offset);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "Segment size (%u)",
            oct);
        offset++;
        break;

    default:
        break;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.22
 */
static void
msg_srvckey_gen_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    const gchar *str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Service Key Generation result code, %s (%u)",
        str,
        oct);

    offset++;
}

/*
 * 3.5.1.23
 */
static void
msg_mms_config_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id, num_blocks, block_len;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    /* minimum required length */
    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 3));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        str = rev_param_block_mms(block_id);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                block_id);

        subtree = proto_item_add_subtree(item, ett_rev_mms_block);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
                offset, len - (offset - saved_offset), "Short Data (?)");
            return;
        }

        if (block_len > 0)
        {
            switch (block_id)
            {
#ifdef MLUM
            case REV_BLOCK_MMS_URI:
                rev_param_block_mms_uri(tvb, subtree, block_len, offset);
                break;

            case REV_BLOCK_MMS_URI_CAP:
                rev_param_block_mms_uri_cap(tvb, subtree, block_len, offset);
                break;
#endif

            default:
                proto_tree_add_none_format(subtree, hf_ansi_683_none,
                    tvb, offset, block_len, "Block Data");
                break;
            }

            offset += block_len;
        }

        SHORT_DATA_CHECK(len, 1);

        oct = tvb_get_guint8(tvb, offset);

        str = rev_res_code_type(oct);

        proto_tree_add_none_format(tree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

        offset++;
    }

    if (len > (offset - saved_offset))
    {
        offset +=
            fresh_handler(tvb, tree, len - (offset - saved_offset), offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.24
 */
static void
msg_mms_download_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    const gchar *str = NULL;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
        tvb, offset, 1,
        "Number of parameter blocks (%u)",
        num_blocks);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        str = for_param_block_mms(oct);

        item =
            proto_tree_add_none_format(tree, hf_ansi_683_none,
                tvb, offset, 1,
                "[%u]:  %s (%u)",
                i+1,
                str,
                oct);

        subtree = proto_item_add_subtree(item, ett_for_mms_block);
        offset++;

        oct = tvb_get_guint8(tvb, offset);

        str = rev_res_code_type(oct);

        proto_tree_add_none_format(subtree, hf_ansi_683_none,
            tvb, offset, 1,
            "%s (%u)",
            str,
            oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static const value_string for_msg_type_strings[] = {
    { 0,        "Configuration Request" },
    { 1,        "Download Request" },
    { 2,        "MS Key Request" },
    { 3,        "Key Generation Request" },
    { 4,        "Re-Authenticate Request" },
    { 5,        "Commit Request" },
    { 6,        "Protocol Capability Request" },
    { 7,        "SSPR Configuration Request" },
    { 8,        "SSPR Download Request" },
    { 9,        "Validation Request" },
    { 10,       "OTAPA Request" },
    { 11,       "PUZL Configuration Request" },
    { 12,       "PUZL Download Request" },
    { 13,       "3GPD Configuration Request" },
    { 14,       "3GPD Download Request" },
    { 15,       "Secure Mode Request" },
    { 16,       "Reserved" },
    { 17,       "MMD Configuration Request" },
    { 18,       "MMD Download Request" },
    { 19,       "System Tag Configuration Request" },
    { 20,       "System Tag Download Request" },
    { 21,       "Service Key Generation Request" },
    { 22,       "MMS Configuration Request" },
    { 23,       "MMS Download Request" },
    { 0, NULL }
};
#define NUM_FOR_MSGS (sizeof(for_msg_type_strings)/sizeof(value_string))
static void (*ansi_683_for_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    msg_config_req,             /* Configuration Request */
    msg_download_req,           /* Download Request */
    msg_ms_key_req,             /* MS Key Request */
    msg_key_gen_req,            /* Key Generation Request */
    msg_reauth_req,             /* Re-Authenticate Request */
    NULL         /* No data */, /* Commit Request */
    msg_protocap_req,           /* Protocol Capability Request */
    msg_sspr_config_req,        /* SSPR Configuration Request */
    msg_sspr_download_req,      /* SSPR Download Request */
    msg_validate_req,           /* Validation Request */
    msg_otapa_req,              /* OTAPA Request */
    msg_puzl_config_req,        /* PUZL Configuration Request */
    msg_puzl_download_req,      /* PUZL Download Request */
    msg_3gpd_config_req,        /* 3GPD Configuration Request */
    msg_3gpd_download_req,      /* 3GPD Download Request */
    msg_secure_mode_req,        /* Secure Mode Request */
    NULL,               /* Reserved */
    msg_mmd_config_req,         /* MMD Configuration Request */
    msg_mmd_download_req,       /* MMD Download Request */
    msg_systag_config_req,      /* System Tag Configuration Request */
    msg_systag_download_req,    /* System Tag Download Request */
    msg_srvckey_gen_req,        /* Service Key Generation Request */
    msg_mms_config_req,         /* MMS Configuration Request */
    msg_mms_download_req,       /* MMS Download Request */
    NULL        /* NONE */
};

static const value_string rev_msg_type_strings[] = {
    { 0,        "Configuration Response" },
    { 1,        "Download Response" },
    { 2,        "MS Key Response" },
    { 3,        "Key Generation Response" },
    { 4,        "Re-Authenticate Response" },
    { 5,        "Commit Response" },
    { 6,        "Protocol Capability Response" },
    { 7,        "SSPR Configuration Response" },
    { 8,        "SSPR Download Response" },
    { 9,        "Validation Response" },
    { 10,       "OTAPA Response" },
    { 11,       "PUZL Configuration Response" },
    { 12,       "PUZL Download Response" },
    { 13,       "3GPD Configuration Response" },
    { 14,       "3GPD Download Response" },
    { 15,       "Secure Mode Response" },
    { 16,       "Extended Protocol Capability Response" },
    { 17,       "MMD Configuration Response" },
    { 18,       "MMD Download Response" },
    { 19,       "System Tag Configuration Response" },
    { 20,       "System Tag Download Response" },
    { 21,       "Service Key Generation Response" },
    { 22,       "MMS Configuration Response" },
    { 23,       "MMS Download Response" },
    { 0, NULL }
};
#define NUM_REV_MSGS (sizeof(rev_msg_type_strings)/sizeof(value_string))
static void (*ansi_683_rev_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    msg_config_rsp,             /* Configuration Response */
    msg_download_rsp,           /* Download Response */
    msg_ms_key_rsp,             /* MS Key Response */
    msg_key_gen_rsp,            /* Key Generation Response */
    msg_reauth_rsp,             /* Re-Authenticate Response */
    msg_commit_rsp,             /* Commit Response */
    msg_protocap_rsp,           /* Protocol Capability Response */
    msg_sspr_config_rsp,        /* SSPR Configuration Response */
    msg_sspr_download_rsp,      /* SSPR Download Response */
    msg_validate_rsp,           /* Validation Response */
    msg_otapa_rsp,              /* OTAPA Response */
    msg_puzl_config_rsp,        /* PUZL Configuration Response */
    msg_puzl_download_rsp,      /* PUZL Download Response */
    msg_3gpd_config_rsp,        /* 3GPD Configuration Response */
    msg_3gpd_download_rsp,      /* 3GPD Download Response */
    msg_secure_mode_rsp,        /* Secure Mode Response */
    msg_ext_protocap_rsp,       /* Extended Protocol Capability Response */
    msg_mmd_config_rsp,         /* MMD Configuration Response */
    msg_mmd_download_rsp,       /* MMD Download Response */
    msg_systag_config_rsp,      /* System Tag Configuration Response */
    msg_systag_download_rsp,    /* System Tag Download Response */
    msg_srvckey_gen_rsp,        /* Service Key Generation Response */
    msg_mms_config_rsp,         /* MMS Configuration Response */
    msg_mms_download_rsp,       /* MMS Download Response */
    NULL        /* NONE */
};


static void
dissect_ansi_683_for_message(tvbuff_t *tvb, proto_tree *ansi_683_tree)
{
    guint8      msg_type;
    gint        idx;
    const gchar *str = NULL;


    msg_type = tvb_get_guint8(tvb, 0);

    str = try_val_to_str_idx(msg_type, for_msg_type_strings, &idx);

    if (str == NULL)
    {
        return;
    }

    /*
     * No Information column data
     */

    proto_tree_add_uint(ansi_683_tree, hf_ansi_683_for_msg_type,
        tvb, 0, 1, msg_type);

    if (ansi_683_for_msg_fcn[idx] != NULL)
    {
        (*ansi_683_for_msg_fcn[idx])(tvb, ansi_683_tree, tvb_length(tvb) - 1, 1);
    }
}

static void
dissect_ansi_683_rev_message(tvbuff_t *tvb, proto_tree *ansi_683_tree)
{
    guint8      msg_type;
    gint        idx;
    const gchar *str = NULL;


    msg_type = tvb_get_guint8(tvb, 0);

    str = try_val_to_str_idx(msg_type, rev_msg_type_strings, &idx);

    if (str == NULL)
    {
        return;
    }

    /*
     * No Information column data
     */

    proto_tree_add_uint(ansi_683_tree, hf_ansi_683_rev_msg_type,
        tvb, 0, 1, msg_type);

    (*ansi_683_rev_msg_fcn[idx])(tvb, ansi_683_tree, tvb_length(tvb) - 1, 1);
}

static void
dissect_ansi_683(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *ansi_683_item;
    proto_tree  *ansi_683_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, ansi_proto_name_short);

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree)
    {
        /*
         * create the ansi_683 protocol tree
         */
        ansi_683_item =
            proto_tree_add_protocol_format(tree, proto_ansi_683, tvb, 0, -1,
                "%s %s Link",
                ansi_proto_name,
                (pinfo->match_uint == ANSI_683_FORWARD) ? "Forward" : "Reverse");

        ansi_683_tree =
            proto_item_add_subtree(ansi_683_item, ett_ansi_683);

        if (pinfo->match_uint == ANSI_683_FORWARD)
        {
            dissect_ansi_683_for_message(tvb, ansi_683_tree);
        }
        else
        {
            dissect_ansi_683_rev_message(tvb, ansi_683_tree);
        }
    }
}


/* Register the protocol with Wireshark */
void
proto_register_ansi_683(void)
{

    /* Setup list of header fields */
    static hf_register_info hf[] =
    {
        { &hf_ansi_683_for_msg_type,
          { "Forward Link Message Type",
            "ansi_683.for_msg_type",
            FT_UINT8, BASE_DEC, VALS(for_msg_type_strings), 0,
            NULL, HFILL }},
        { &hf_ansi_683_rev_msg_type,
          { "Reverse Link Message Type",
            "ansi_683.rev_msg_type",
            FT_UINT8, BASE_DEC, VALS(rev_msg_type_strings), 0,
            NULL, HFILL }},
        { &hf_ansi_683_length,
            { "Length",         "ansi_683.len",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_683_none,
            { "Sub tree",       "ansi_683.none",
            FT_NONE, BASE_NONE, 0, 0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_PARAMS   21
    static gint *ett[NUM_INDIVIDUAL_PARAMS];

    memset((void *) ett, 0, sizeof(ett));

    ett[0] = &ett_ansi_683;
    ett[1] = &ett_for_nam_block;
    ett[2] = &ett_rev_nam_block;
    ett[3] = &ett_key_p;
    ett[4] = &ett_key_g;
    ett[5] = &ett_rev_feat;
    ett[6] = &ett_for_val_block;
    ett[7] = &ett_for_sspr_block;
    ett[8] = &ett_band_cap;
    ett[9] = &ett_rev_sspr_block;
    ett[10] = &ett_scm;
    ett[11] = &ett_for_puzl_block;
    ett[12] = &ett_rev_puzl_block;
    ett[13] = &ett_for_3gpd_block;
    ett[14] = &ett_rev_3gpd_block;
    ett[15] = &ett_for_mmd_block;
    ett[16] = &ett_rev_mmd_block;
    ett[17] = &ett_for_mms_block;
    ett[18] = &ett_rev_mms_block;
    ett[19] = &ett_rev_cap;
    ett[20] = &ett_segment;

    /* Register the protocol name and description */
    proto_ansi_683 =
        proto_register_protocol(ansi_proto_name, "ANSI IS-683 (OTA (Mobile))", "ansi_683");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_683, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_ansi_683(void)
{
    dissector_handle_t  ansi_683_handle;

    ansi_683_handle = create_dissector_handle(dissect_ansi_683, proto_ansi_683);

    dissector_add_uint("ansi_map.ota", ANSI_683_FORWARD, ansi_683_handle);
    dissector_add_uint("ansi_map.ota", ANSI_683_REVERSE, ansi_683_handle);
    dissector_add_uint("ansi_a.ota", ANSI_683_FORWARD, ansi_683_handle);
    dissector_add_uint("ansi_a.ota", ANSI_683_REVERSE, ansi_683_handle);
}
