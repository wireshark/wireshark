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


#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_ansi_683(void);
void proto_reg_handoff_ansi_683(void);


static const char *ansi_proto_name = "ANSI IS-683 (OTA (Mobile))";

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
static int hf_ansi_683_for_msg_type = -1;
static int hf_ansi_683_rev_msg_type = -1;
static int hf_ansi_683_length = -1;
static int hf_ansi_683_reserved8 = -1;
static int hf_ansi_683_reserved16_f = -1;
static int hf_ansi_683_reserved24_f = -1;
static int hf_ansi_683_reserved_bytes = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_ansi_683_spasm_protection_for_the_active_nam_000010 = -1;
static int hf_ansi_683_imsi_t_11_12 = -1;
static int hf_ansi_683_otapa_spasm_validation_signature_indicator_800000 = -1;
static int hf_ansi_683_accolc_3c = -1;
static int hf_ansi_683_otapa_spasm_validation_signature = -1;
static int hf_ansi_683_mcc_m_0ffc = -1;
static int hf_ansi_683_home_sid = -1;
static int hf_ansi_683_sid_nid_pairs_3fff = -1;
static int hf_ansi_683_identifiers_present8 = -1;
static int hf_ansi_683_authentication_data_input_parameter = -1;
static int hf_ansi_683_feature_protocol_version = -1;
static int hf_ansi_683_parameter_p = -1;
static int hf_ansi_683_key_id_reserved = -1;
static int hf_ansi_683_local_control_status_0010 = -1;
static int hf_ansi_683_mob_term_for_nid_0002 = -1;
static int hf_ansi_683_mob_term_for_nid_40 = -1;
static int hf_ansi_683_power_class = -1;
static int hf_ansi_683_mobile_station_fw_rev = -1;
static int hf_ansi_683_fresh_incl8 = -1;
static int hf_ansi_683_random_number_smck_generation = -1;
static int hf_ansi_683_key_id_ims_root_key = -1;
static int hf_ansi_683_num_sid_nid_01fe = -1;
static int hf_ansi_683_n_digits = -1;
static int hf_ansi_683_stored_sid_nid_3fc0 = -1;
static int hf_ansi_683_mob_term_for_sid_0004 = -1;
static int hf_ansi_683_capability_data = -1;
static int hf_ansi_683_mobile_station_calculation_result = -1;
static int hf_ansi_683_maximum_segment_size = -1;
static int hf_ansi_683_otasp_mobile_protocol_revision = -1;
static int hf_ansi_683_otasp_protocol_revision = -1;
static int hf_ansi_683_start_secure_mode = -1;
static int hf_ansi_683_security = -1;
static int hf_ansi_683_imsi_t_10 = -1;
static int hf_ansi_683_meid = -1;
static int hf_ansi_683_nam_lock_indicator = -1;
static int hf_ansi_683_start_otapa_session = -1;
static int hf_ansi_683_band_class_1_cdma = -1;
static int hf_ansi_683_segment_offset = -1;
static int hf_ansi_683_identifiers_present16 = -1;
static int hf_ansi_683_user_zone_id = -1;
static int hf_ansi_683_mcc_m_01ff80 = -1;
static int hf_ansi_683_max_sid_nid_3fc0 = -1;
static int hf_ansi_683_segment_size = -1;
static int hf_ansi_683_imsi_m_class8000 = -1;
static int hf_ansi_683_local_control_status_02 = -1;
static int hf_ansi_683_transmission = -1;
static int hf_ansi_683_max_sid_nid_01fe = -1;
static int hf_ansi_683_spasm_random_challenge = -1;
static int hf_ansi_683_extended_scm_indicator = -1;
static int hf_ansi_683_a_key_protocol_revision = -1;
static int hf_ansi_683_cdma_analog_mode = -1;
static int hf_ansi_683_mob_term_home_08 = -1;
static int hf_ansi_683_imsi_m_11_12_3f80 = -1;
static int hf_ansi_683_user_zone_sid = -1;
static int hf_ansi_683_fresh_incl16 = -1;
static int hf_ansi_683_sid_nid_pairs_01ff = -1;
static int hf_ansi_683_imsi_t_addr_num = -1;
static int hf_ansi_683_slotted_mode = -1;
static int hf_ansi_683_imsi_m_class10 = -1;
static int hf_ansi_683_secure_mode_result_code = -1;
static int hf_ansi_683_ismi_m_addr_num_e = -1;
static int hf_ansi_683_mob_term_for_nid_4000 = -1;
static int hf_ansi_683_station_class_mark = -1;
static int hf_ansi_683_otapa_spasm_validation_signature_indicator_80 = -1;
static int hf_ansi_683_mob_term_for_sid_8000 = -1;
static int hf_ansi_683_imsi_m_11_12_7f = -1;
static int hf_ansi_683_sspr_configuration_result_code = -1;
static int hf_ansi_683_mob_p_rev_1fe0 = -1;
static int hf_ansi_683_puzl_configuration_result_code = -1;
static int hf_ansi_683_key_id_wlan_root_key = -1;
static int hf_ansi_683_firstchp = -1;
static int hf_ansi_683_key_id_bcmcs_root_key = -1;
static int hf_ansi_683_band_class_0_cdma = -1;
static int hf_ansi_683_fresh = -1;
static int hf_ansi_683_extended_address_indicator = -1;
static int hf_ansi_683_mob_term_home_01 = -1;
static int hf_ansi_683_imsi_t_class = -1;
static int hf_ansi_683_system_tag_download_result_code = -1;
static int hf_ansi_683_band_class_0_analog = -1;
static int hf_ansi_683_service_key_generation_result_code = -1;
static int hf_ansi_683_sspr_download_result_code = -1;
static int hf_ansi_683_band_class_6_cdma = -1;
static int hf_ansi_683_data_commit_result_code = -1;
static int hf_ansi_683_mob_p_rev_ff = -1;
static int hf_ansi_683_number_of_capability_records = -1;
static int hf_ansi_683_system_tag_result_code = -1;
static int hf_ansi_683_mcc_t = -1;
static int hf_ansi_683_call_history_parameter = -1;
static int hf_ansi_683_randc = -1;
static int hf_ansi_683_mob_term_for_sid_80 = -1;
static int hf_ansi_683_parameter_g = -1;
static int hf_ansi_683_num_features = -1;
static int hf_ansi_683_cdma_analog_slotted = -1;
static int hf_ansi_683_spasm_protection_for_the_active_nam_40 = -1;
static int hf_ansi_683_25mhz_bandwidth = -1;
static int hf_ansi_683_base_station_calculation_result = -1;
static int hf_ansi_683_key_exchange_result_code = -1;
static int hf_ansi_683_mobile_station_manuf_model_number = -1;
static int hf_ansi_683_random_challenge_value = -1;
static int hf_ansi_683_imsi_m_10 = -1;
static int hf_ansi_683_stored_sid_nid_01fe = -1;
static int hf_ansi_683_number_of_parameter_blocks = -1;
static int hf_ansi_683_imsi_m_addr_num_7000 = -1;
static int hf_ansi_683_block_data = -1;
static int hf_ansi_683_feature_id = -1;
static int hf_ansi_683_num_sid_nid_3fc0 = -1;
static int hf_ansi_683_more_additional_fields = -1;
static int hf_ansi_683_band_class_3_cdma = -1;
static int hf_ansi_683_authr = -1;
static int hf_ansi_683_accolc_01e0 = -1;
static int hf_ansi_683_result_code = -1;
static int hf_ansi_683_cap_info_record_type = -1;
static int hf_ansi_683_param_block_val = -1;
static int hf_ansi_683_rev_param_block_sspr = -1;
static int hf_ansi_683_for_param_block_sspr = -1;
static int hf_ansi_683_rev_param_block_nam = -1;
static int hf_ansi_683_for_param_block_nam = -1;
static int hf_ansi_683_rev_param_block_puzl = -1;
static int hf_ansi_683_for_param_block_puzl = -1;
static int hf_ansi_683_rev_param_block_3gpd = -1;
static int hf_ansi_683_for_param_block_3gpd = -1;
static int hf_ansi_683_rev_param_block_mmd = -1;
static int hf_ansi_683_for_param_block_mmd = -1;
static int hf_ansi_683_rev_param_block_systag = -1;
static int hf_ansi_683_for_param_block_systag = -1;
static int hf_ansi_683_rev_param_block_mms = -1;
static int hf_ansi_683_for_param_block_mms = -1;
static int hf_ansi_683_mobile_directory_number = -1;
static int hf_ansi_683_service_programming_code = -1;

static expert_field ei_ansi_683_extraneous_data = EI_INIT;
static expert_field ei_ansi_683_short_data = EI_INIT;
static expert_field ei_ansi_683_data_length = EI_INIT;

static const char dtmf_digits[16] = {'?','1','2','3','4','5','6','7','8','9','0','?','?','?','?','?'};

/* FUNCTIONS */

/* PARAM FUNCTIONS */

#define EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, &ei_ansi_683_extraneous_data, tvb, \
            offset, (edc_len) - (edc_max_len)); \
    }

#define SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, &ei_ansi_683_short_data, tvb, \
            offset, (sdc_len)); \
        return; \
    }

#define EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
        proto_tree_add_expert(tree, pinfo, &ei_ansi_683_data_length, tvb, \
            offset, (edc_len)); \
        return; \
    }

static guint32
fresh_handler(tvbuff_t *tvb, proto_tree *tree, guint len _U_, guint32 offset)
{
    guint8      oct;

    oct = tvb_get_guint8(tvb, offset);

    if (oct & 0x80)
    {
        proto_tree_add_item(tree, hf_ansi_683_fresh_incl16, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_683_fresh, tvb, offset, 2, ENC_BIG_ENDIAN);
        return(2);
    }

    proto_tree_add_item(tree, hf_ansi_683_fresh_incl8, tvb, offset, 1, ENC_NA);
    proto_tree_add_bits_item(tree, hf_ansi_683_reserved8, tvb, offset<<3, 7, ENC_NA);

    return(1);
}

/*
 * Table 3.5.1.2-1 Result Codes
 */
static const range_string result_codes_rvals[] = {
    { 0,    0,  "Accepted - Operation successful" },
    { 1,    1,  "Rejected - Unknown reason" },
    { 2,    2,  "Rejected - Data size mismatch" },
    { 3,    3,  "Rejected - Protocol version mismatch" },
    { 4,    4,  "Rejected - Invalid parameter" },
    { 5,    5,  "Rejected - SID/NID length mismatch" },
    { 6,    6,  "Rejected - Message not expected in this mode" },
    { 7,    7,  "Rejected - BLOCK_ID value not supported" },
    { 8,    8,  "Rejected - Preferred roaming list length mismatch" },
    { 9,    9,  "Rejected - CRC error" },
    { 10,  10,  "Rejected - Mobile station locked" },
    { 11,  11,  "Rejected - Invalid SPC" },
    { 12,  12,  "Rejected - SPC change denied by the user" },
    { 13,  13,  "Rejected - Invalid SPASM" },
    { 14,  14,  "Rejected - BLOCK_ID not expected in this mode" },
    { 15,  15,  "Rejected - User Zone already in PUZL" },
    { 16,  16,  "Rejected - User Zone not in PUZL" },
    { 17,  17,  "Rejected - No entries in PUZL" },
    { 18,  18,  "Rejected - Operation Mode mismatch" },
    { 19,  19,  "Rejected - SimpleIP MAX_NUM_NAI mismatch" },
    { 20,  20,  "Rejected - SimpleIP MAX_NAI_LENGTH mismatch" },
    { 21,  21,  "Rejected - MobileIP MAX_NUM_NAI mismatch" },
    { 22,  22,  "Rejected - MobileIP MAX_NAI_LENGTH mismatch" },
    { 23,  23,  "Rejected - SimpleIP PAP MAX_SS_LENGTH mismatch" },
    { 24,  24,  "Rejected - SimpleIP CHAP MAX_SS_LENGTH mismatch" },
    { 25,  25,  "Rejected - MobileIP MAX_MNAAA_SS_LENGTH mismatch" },
    { 26,  26,  "Rejected - MobileIP MAX_MN-HA_SS_LENGTH mismatch" },
    { 27,  27,  "Rejected - MobileIP MN-AAA_AUTH_ALGORITHM mismatch" },
    { 28,  28,  "Rejected - MobileIP MN-HA_AUTH_ALGORITHM mismatch" },
    { 29,  29,  "Rejected - SimpleIP ACT_NAI_ENTRY_INDEX mismatch" },
    { 30,  30,  "Rejected - MobileIP ACT_NAI_ENTRY_INDEX mismatch" },
    { 31,  31,  "Rejected - SimpleIP PAP NAI_ENTRY_INDEX mismatch" },
    { 32,  32,  "Rejected - SimpleIP CHAP NAI_ENTRY_INDEX mismatch" },
    { 33,  33,  "Rejected - MobileIP NAI_ENTRY_INDEX mismatch" },
    { 34,  34,  "Rejected - Unexpected PRL_BLOCK_ID change" },
    { 35,  35,  "Rejected - PRL format mismatch" },
    { 36,  36,  "Rejected - HRPD Access Authentication MAX_NAI_LENGTH mismatch" },
    { 37,  37,  "Rejected - HRPD Access Authentication CHAP MAX_SS_LENGTH mismatch" },
    { 38,  38,  "Rejected - MMD MAX_NUM_IMPU mismatch" },
    { 39,  39,  "Rejected - MMD MAX_IMPU_LENGTH mismatch" },
    { 40,  40,  "Rejected - MMD MAX_NUM_P-CSCF mismatch" },
    { 41,  41,  "Rejected - MMD MAX_P-CSCF_LENGTH mismatch" },
    { 42,  42,  "Rejected - Unexpected System Tag BLOCK_ID Change" },
    { 43,  43,  "Rejected - System Tag Format mismatch" },
    { 44,  44,  "Rejected - NUM_MMS_URI mismatch" },
    { 45,  45,  "Rejected - MMS_URI _LENGTH mismatch" },
    { 46,  46,  "Rejected - Invalid MMS_URI" },
    { 47,  127,  "Reserved for future standardization" },
    { 128, 254,  "Available for manufacturer-specific Result Code definitions" },
    { 255, 255,  "Reserved" },

    { 0x00, 0x00,  NULL },
};

/*
 * Table 3.5.1.7-1 Feature Identifier
 */
static const range_string feat_id_type_rvals[] = {
    { 0,    0,  "NAM Download (DATA_P_REV)" },
    { 1,    1,  "Key Exchange (A_KEY_P_REV)" },
    { 2,    2,  "System Selection for Preferred Roaming (SSPR_P_REV)" },
    { 3,    3,  "Service Programming Lock (SPL_P_REV)" },
    { 4,    4,  "Over-The-Air Parameter Administration (OTAPA_P_REV)" },
    { 5,    5,  "Preferred User Zone List (PUZL_P_REV)" },
    { 6,    6,  "3G Packet Data (3GPD)" },
    { 7,    7,  "Secure MODE (SECURE_MODE_P_REV)" },
    { 8,    8,  "Multimedia Domain (MMD)" },
    { 9,    9,  "System Tag Download (TAG_P_REV)" },
    { 10,  10,  "Multimedia Messaging Service (MMS)" },
    { 11,  191,  "Reserved for future standardization" },
    { 192, 254,  "Available for manufacturer-specific features" },
    { 255, 255,  "Reserved" },

    { 0x00, 0x00,  NULL },
};

#define REV_TYPE_CAP_INFO_OP_MODE       0
#define REV_TYPE_CAP_INFO_CDMA_BAND     1
#define REV_TYPE_CAP_INFO_MEID          2
#define REV_TYPE_CAP_INFO_ICCID         3
#define REV_TYPE_CAP_INFO_EXT_UIM_ID    4
#define REV_TYPE_CAP_INFO_MEID_ME       5

/*
 * Table 3.5.1.17.1-1 Capability Information Record Types
 */
static const range_string rev_cap_info_record_type_rvals[] = {
    { REV_TYPE_CAP_INFO_OP_MODE,     REV_TYPE_CAP_INFO_OP_MODE,  "Operating Mode Information" },
    { REV_TYPE_CAP_INFO_CDMA_BAND,   REV_TYPE_CAP_INFO_CDMA_BAND,  "CDMA Band Class Information" },
    { REV_TYPE_CAP_INFO_MEID,        REV_TYPE_CAP_INFO_MEID,  "MEID" },
    { REV_TYPE_CAP_INFO_ICCID,       REV_TYPE_CAP_INFO_ICCID,  "ICCID" },
    { REV_TYPE_CAP_INFO_EXT_UIM_ID,  REV_TYPE_CAP_INFO_EXT_UIM_ID,  "EXT_UIM_ID" },
    { REV_TYPE_CAP_INFO_MEID_ME,     REV_TYPE_CAP_INFO_MEID_ME,  "MEID_ME" },
    { 6,    255, "Reserved" },

    { 0x00, 0x00,  NULL },
};

#define FOR_BLOCK_VAL_VERIFY_SPC                0
#define FOR_BLOCK_VAL_CHANGE_SPC                1
#define FOR_BLOCK_VAL_VALDATE_SPASM             2

/*
 * Table 4.5.4-1 Validation Parameter Block Types
 */
static const range_string for_param_block_rvals[] = {
    { FOR_BLOCK_VAL_VERIFY_SPC,     FOR_BLOCK_VAL_VERIFY_SPC,  "Verify SPC" },
    { FOR_BLOCK_VAL_CHANGE_SPC,     FOR_BLOCK_VAL_CHANGE_SPC, "Change SPC" },
    { FOR_BLOCK_VAL_VALDATE_SPASM,  FOR_BLOCK_VAL_VALDATE_SPASM,  "Validate SPASM" },
    { 3,    127, "Reserved for future standardization" },
    { 128,  254, "Available for manufacturer-specific parameter block definitions" },
    { 255,  255, "Reserved" },

    { 0x00, 0x00,  NULL },
};

#define REV_BLOCK_SSPR_PRL_DIM          0
#define REV_BLOCK_SSPR_PRL              1
#define REV_BLOCK_SSPR_EXT_PRL_DIM      2

/*
 * Table 3.5.3-1 SSPR Parameter Block Types
 */
static const range_string rev_param_block_sspr_rvals[] = {
    { REV_BLOCK_SSPR_PRL_DIM,     REV_BLOCK_SSPR_PRL_DIM,  "Preferred Roaming List Dimensions" },
    { REV_BLOCK_SSPR_PRL,         REV_BLOCK_SSPR_PRL, "Preferred Roaming List" },
    { REV_BLOCK_SSPR_EXT_PRL_DIM, REV_BLOCK_SSPR_EXT_PRL_DIM,  "Extended Preferred Roaming List Dimensions" },
    { 3,    127, "Reserved for future standardization" },
    { 128,  254, "Available for manufacturer-specific parameter block definitions" },
    { 255,  255, "Reserved" },

    { 0x00, 0x00,  NULL },
};

#define FOR_BLOCK_SSPR_PRL              0
#define FOR_BLOCK_SSPR_EXT_PRL          1

/*
 * Table 4.5.3-1 SSPR Parameter Block Types
 */
static const range_string for_param_block_sspr_rvals[] = {
    { FOR_BLOCK_SSPR_PRL,     FOR_BLOCK_SSPR_PRL,  "Preferred Roaming List" },
    { FOR_BLOCK_SSPR_EXT_PRL, FOR_BLOCK_SSPR_EXT_PRL, "Extended Preferred Roaming List with SSPR_P_REV greater than 00000001" },
    { 2,    127, "Reserved for future standardization" },
    { 128,  254, "Available for manufacturer-specific parameter block definitions" },
    { 255,  255, "Reserved" },

    { 0x00, 0x00,  NULL },
};

#define REV_BLOCK_NAM_CDMA_ANALOG       0
#define REV_BLOCK_NAM_MDN               1
#define REV_BLOCK_NAM_CDMA              2
#define REV_BLOCK_NAM_IMSI_T            3

/*
 * Table 3.5.2-1 NAM Parameter Block Types
 */
static const range_string rev_param_block_nam_rvals[] = {
    { REV_BLOCK_NAM_CDMA_ANALOG, REV_BLOCK_NAM_CDMA_ANALOG,  "CDMA/Analog NAM" },
    { REV_BLOCK_NAM_MDN,         REV_BLOCK_NAM_MDN, "Mobile Directory Number" },
    { REV_BLOCK_NAM_CDMA,        REV_BLOCK_NAM_CDMA,  "CDMA NAM" },
    { REV_BLOCK_NAM_IMSI_T,      REV_BLOCK_NAM_IMSI_T, "IMSI_T" },
    { 4,    127, "Reserved for future standardization" },
    { 128,  254, "Available for manufacturer-specific parameter block definitions" },
    { 255,  255, "Reserved" },

    { 0x00, 0x00,  NULL },
};


#define FOR_BLOCK_NAM_CDMA_ANALOG       0
#define FOR_BLOCK_NAM_MDN               1
#define FOR_BLOCK_NAM_CDMA              2
#define FOR_BLOCK_NAM_IMSI_T            3

/*
 * Table 4.5.2-1 NAM Parameter Block Types
 */
static const range_string for_param_block_nam_rvals[] = {
    { FOR_BLOCK_NAM_CDMA_ANALOG, FOR_BLOCK_NAM_CDMA_ANALOG,  "CDMA/Analog NAM Download" },
    { FOR_BLOCK_NAM_MDN,         FOR_BLOCK_NAM_MDN, "Mobile Directory Number" },
    { FOR_BLOCK_NAM_CDMA,        FOR_BLOCK_NAM_CDMA,  "CDMA NAM Download" },
    { FOR_BLOCK_NAM_IMSI_T,      FOR_BLOCK_NAM_IMSI_T, "IMSI_T" },
    { 4,    127, "Reserved for future standardization" },
    { 128,  254, "Available for manufacturer-specific parameter block definitions" },
    { 255,  255, "Reserved" },

    { 0x00, 0x00,  NULL },
};

/*
 * Table 3.5.6-1 PUZL Parameter Block Types
 */
static const range_string rev_param_block_puzl_rvals[] = {
    { 0,    0,   "PUZL Dimensions" },
    { 1,    1,   "PUZL Priorities" },
    { 2,    2,   "User Zone" },
    { 3,    3,   "Preferred User Zone List" },
    { 4,    127, "Reserved for future standardization" },
    { 128,  254, "Available for manufacturer-specific parameter block definitions" },
    { 255,  255, "Reserved" },

    { 0x00, 0x00,  NULL },
};

#define FOR_BLOCK_PUZL_UZ_INS                   0
#define FOR_BLOCK_PUZL_UZ_UPD                   1
#define FOR_BLOCK_PUZL_UZ_DEL                   2
#define FOR_BLOCK_PUZL_UZ_PRI_CHANGE            3
#define FOR_BLOCK_PUZL_FLAGS                    4

/*
 * Table 4.5.6-1 PUZL Parameter Block Types
 */
static const range_string for_param_block_puzl_rvals[] = {
    { FOR_BLOCK_PUZL_UZ_INS,    FOR_BLOCK_PUZL_UZ_INS,   "User Zone Insert" },
    { FOR_BLOCK_PUZL_UZ_UPD,    FOR_BLOCK_PUZL_UZ_UPD,   "User Zone Update" },
    { FOR_BLOCK_PUZL_UZ_DEL,    FOR_BLOCK_PUZL_UZ_DEL,   "User Zone Delete" },
    { FOR_BLOCK_PUZL_UZ_PRI_CHANGE,    FOR_BLOCK_PUZL_UZ_PRI_CHANGE,   "User Zone Priority Change" },
    { FOR_BLOCK_PUZL_FLAGS,    FOR_BLOCK_PUZL_FLAGS,   "PUZL Flags" },
    { 5,    127, "Reserved for future standardization" },
    { 128,  254, "Available for manufacturer-specific parameter block definitions" },
    { 255,  255, "Reserved" },

    { 0x00, 0x00,  NULL },
};

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
static const value_string rev_param_block_3gpd_vals[] = {
  { REV_BLOCK_3GPD_OP_CAP,        "3GPD Operation Capability Parameters" },
  { REV_BLOCK_3GPD_OP_MODE,        "3GPD Operation Mode Parameters" },
  { REV_BLOCK_3GPD_SIP_CAP,        "SimpleIP Capability Parameters" },
  { REV_BLOCK_3GPD_MIP_CAP,        "MobileIP Capability Parameters" },
  { REV_BLOCK_3GPD_SIP_USER_PRO,        "SimpleIP User Profile Parameters" },
  { REV_BLOCK_3GPD_MIP_USER_PRO,        "Mobile IP User Profile Parameters" },
  { REV_BLOCK_3GPD_SIP_STATUS,        "SimpleIP Status Parameters" },
  { REV_BLOCK_3GPD_MIP_STATUS,        "MobileIP Status Parameters" },
  { REV_BLOCK_3GPD_SIP_PAP_SS,        "SimpleIP PAP SS Parameters" },
  { REV_BLOCK_3GPD_SIP_CHAP_SS,        "SimpleIP CHAP SS Parameters" },
  { REV_BLOCK_3GPD_MIP_SS,       "MobileIP SS Parameters" },
  { REV_BLOCK_3GPD_HRPD_ACC_AUTH_CAP,       "HRPD Access Authentication Capability Parameters" },
  { REV_BLOCK_3GPD_HRPD_ACC_AUTH_USER,       "HRPD Access Authentication User Profile Parameters" },
  { REV_BLOCK_3GPD_HRPD_ACC_AUTH_CHAP_SS,       "HRPD Access Authentication CHAP SS Parameters" },
  { 0,        NULL }
};

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
static const value_string for_param_block_3gpd_vals[] = {
  { FOR_BLOCK_3GPD_OP_MODE,             "3GPD Operation Mode Parameters" },
  { FOR_BLOCK_3GPD_SIP_USER_PRO,        "SimpleIP User Profile Parameters" },
  { FOR_BLOCK_3GPD_MIP_USER_PRO,        "Mobile IP User Profile Parameters" },
  { FOR_BLOCK_3GPD_SIP_STATUS,          "SimpleIP Status Parameters" },
  { FOR_BLOCK_3GPD_MIP_STATUS,          "MobileIP Status Parameters" },
  { FOR_BLOCK_3GPD_SIP_PAP_SS,          "SimpleIP PAP SS Parameters" },
  { FOR_BLOCK_3GPD_SIP_CHAP_SS,         "SimpleIP CHAP SS Parameters" },
  { FOR_BLOCK_3GPD_MIP_SS,              "MobileIP SS Parameters" },
  { FOR_BLOCK_3GPD_HRPD_ACC_AUTH_USER,      "HRPD Access Authentication User Profile Parameters" },
  { FOR_BLOCK_3GPD_HRPD_ACC_AUTH_CHAP_SS,   "HRPD Access Authentication CHAP SS Parameters" },
  { 0,        NULL }
};


#define REV_BLOCK_MMD_APP               0

/*
 * Table 3.5.9-1 MMD Parameter Block Types
 */
static const value_string param_block_mmd_vals[] = {
  { 0,        "MMD Application Parameters" },
  { 0,        NULL }
};

/*
 * Table 4.5.8-1 MMD Parameter Block Types
 */
#define FOR_BLOCK_MMD_APP               0


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
static const value_string rev_param_block_systag_vals[] = {
  { REV_BLOCK_SYSTAG_HOME_SYSTAG,        "Home System Tag" },
  { REV_BLOCK_SYSTAG_GROUP_TAG_LIST_DIM,        "Group Tag List Dimensions" },
  { REV_BLOCK_SYSTAG_GROUP_TAG_LIST,        "Group Tag List" },
  { REV_BLOCK_SYSTAG_SPEC_TAG_LIST_DIM,        "Specific Tag List Dimensions" },
  { REV_BLOCK_SYSTAG_SPEC_TAG_LIST,        "Specific Tag List" },
  { REV_BLOCK_SYSTAG_CALL_PROMPT_LIST_DIM,        "Call Prompt List Dimensions" },
  { REV_BLOCK_SYSTAG_CALL_PROMPT_LIST,        "Call Prompt List" },
  { 0,        NULL }
};

/*
 * Table 4.5.9-1 System Tag Parameter Block Types
 */
static const range_string for_param_block_systag_rvals[] = {
    { 0,    0,   "Home System Tag" },
    { 1,    1,   "Group Tag List" },
    { 2,    2,   "Specific Tag List" },
    { 3,    3,   "Call Prompt List" },
    { 4,    127, "Reserved for future standardization" },
    { 128,  254, "Available for manufacturer-specific parameter block definitions" },
    { 255,  255, "Reserved" },

    { 0x00, 0x00,  NULL },
};

#define REV_BLOCK_MMS_URI               0
#define REV_BLOCK_MMS_URI_CAP           1

/*
 * Table 3.5.12-1 MMS Parameter Block Types
 */
static const range_string rev_param_block_mms_rvals[] = {
    { REV_BLOCK_MMS_URI,    REV_BLOCK_MMS_URI,   "MMS URI Parameters" },
    { REV_BLOCK_MMS_URI_CAP,    REV_BLOCK_MMS_URI_CAP,   "MMS URI Capability Parameters" },
    { 2,  255, "Reserved" },

    { 0x00, 0x00,  NULL },
};

#define FOR_BLOCK_MMS_URI               0

/*
 * Table 4.5.10-1 MMS Parameter Block Types
 */
static const range_string for_param_block_mms_rvals[] = {
    { FOR_BLOCK_MMS_URI,    FOR_BLOCK_MMS_URI,   "MMS URI Parameters" },
    { 1,  255, "Reserved" },

    { 0x00, 0x00,  NULL },
};

/* PARAMETER BLOCK DISSECTION */

/*
 * 3.5.2.1
 */
static const value_string power_class_vals[] = {
  { 0x00,        "Class I" },
  { 0x01,        "Class II" },
  { 0x02,        "Class III" },
  { 0x03,        "Reserved" },
  { 0,           NULL }
};

static const true_false_string tfs_extended_scm_indicator = { "Band Classes 1,4", "Other bands" };
static const true_false_string tfs_cdma_analog_mode = { "Dual Mode", "CDMA Only" };
static const true_false_string tfs_configured_not_configured = { "Configured", "Not configured" };
static const true_false_string tfs_discontinuous_continous = { "Discontinuous", "Continuous" };

static void
rev_param_block_nam_cdma_analog(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;
    proto_tree  *subtree;
    proto_item  *item;

    saved_offset = offset;

    proto_tree_add_item(tree, hf_ansi_683_firstchp, tvb, offset, 2, ENC_BIG_ENDIAN);

    offset++;

    proto_tree_add_item(tree, hf_ansi_683_home_sid, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_extended_address_indicator, tvb, offset + 2, 1, ENC_BIG_ENDIAN);

    offset += 2;

    value = tvb_get_ntohs(tvb, offset);

    item = proto_tree_add_item(tree, hf_ansi_683_station_class_mark, tvb, offset, 2, ENC_BIG_ENDIAN);

    /*
     * following SCM decode is from:
     *  3GPP2 C.S0005-0 section 2.3.3
     *  3GPP2 C.S0072-0 section 2.1.2
     */
    subtree = proto_item_add_subtree(item, ett_scm);

    proto_tree_add_item(subtree, hf_ansi_683_extended_scm_indicator, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_683_cdma_analog_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_683_cdma_analog_slotted, tvb, offset, 2, ENC_BIG_ENDIAN);

    if (value & 0x0200)
        proto_item_append_text(item, "%s", " (MEID configured)");

    proto_tree_add_item(subtree, hf_ansi_683_meid, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_683_25mhz_bandwidth, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_683_transmission, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ansi_683_power_class, tvb, offset, 2, ENC_BIG_ENDIAN);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_mob_p_rev_1fe0, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_imsi_m_class10, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format_value(tree, hf_ansi_683_ismi_m_addr_num_e, tvb, offset + 1, 1, value,
            "%u, %u digits in NMSI", (value & 0x0e) >> 1,
            (value & 0x10) ? ((value & 0x0e) >> 1) + 4 : 0);

    offset++;

    proto_tree_add_item(tree, hf_ansi_683_mcc_m_01ff80, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_imsi_m_11_12_7f, tvb, offset, 3, ENC_BIG_ENDIAN);

    offset += 3;

    proto_tree_add_item(tree, hf_ansi_683_imsi_m_10, tvb, offset, 5, ENC_NA);

    offset += 4;

    proto_tree_add_item(tree, hf_ansi_683_accolc_3c, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_local_control_status_02, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_mob_term_home_01, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_mob_term_for_sid_80, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_mob_term_for_nid_40, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_max_sid_nid_3fc0, tvb, offset, 2, ENC_BIG_ENDIAN);

    offset++;

    proto_tree_add_item(tree, hf_ansi_683_stored_sid_nid_3fc0, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_sid_nid_pairs_3fff, tvb, offset+1, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ansi_683_reserved_bytes,
        tvb, offset, len - (offset - saved_offset), ENC_NA);
}

/*
 * 3.5.2.2
 * 4.5.2.2
 */
static void
param_block_nam_mdn(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value, count, i;
    char        str[17];

    saved_offset = offset;

    value = tvb_get_guint8(tvb, offset);

    count = (value & 0xf0) >> 4;

    proto_tree_add_item(tree, hf_ansi_683_n_digits, tvb, offset, 1, ENC_BIG_ENDIAN);

    for (i=0; i < count; i++)
    {
        str[i] = dtmf_digits[(value & 0x0f)];

        if ((i + 1) < count)
        {
            offset++;
            value = tvb_get_guint8(tvb, offset);
            str[i+1] = dtmf_digits[(value & 0xf0) >> 4];
            i++;
        }
    }
    str[i] = '\0';

    proto_tree_add_string(tree, hf_ansi_683_mobile_directory_number,
        tvb, saved_offset, len, str);

    if (!(count & 0x01))
    {
        proto_tree_add_bits_item(tree, hf_ansi_683_reserved8, tvb, offset<<3, 4, ENC_NA);
    }
}

/*
 * 3.5.2.3
 */
static void
rev_param_block_nam_cdma(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;

    saved_offset = offset;

    proto_tree_add_bits_item(tree, hf_ansi_683_reserved8, tvb, (offset<<3)+6, 2, ENC_NA);
    proto_tree_add_item(tree, hf_ansi_683_slotted_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_bits_item(tree, hf_ansi_683_reserved8, tvb, offset<<3, 5, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_mob_p_rev_ff, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    value = tvb_get_ntohs(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_imsi_m_class8000, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format_value(tree, hf_ansi_683_imsi_m_addr_num_7000, tvb, offset, 2, value,
            "%u, %u digits in NMSI", (value & 0x7000) >> 12,
            (value & 0x8000) ? ((value & 0x7000) >> 12) + 4 : 0);

    proto_tree_add_item(tree, hf_ansi_683_mcc_m_0ffc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_imsi_m_11_12_3f80, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_imsi_m_10, tvb, offset, 5, ENC_NA);
    offset += 4;

    proto_tree_add_item(tree, hf_ansi_683_accolc_01e0, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_local_control_status_0010, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_mob_term_home_08, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_mob_term_for_sid_0004, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_mob_term_for_nid_0002, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_max_sid_nid_01fe, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_stored_sid_nid_01fe, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_sid_nid_pairs_01ff, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ansi_683_reserved_bytes,
        tvb, offset, len - (offset - saved_offset), ENC_NA);
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

    proto_tree_add_item(tree, hf_ansi_683_imsi_t_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format_value(tree, hf_ansi_683_imsi_t_addr_num, tvb, offset, 1, value,
            "%u, %u digits in NMSI", (value & 0x70) >> 4,
            (value & 0x80) ? ((value & 0x70) >> 4) + 4 : 0);

    proto_tree_add_item(tree, hf_ansi_683_mcc_t, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_imsi_t_11_12, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_imsi_t_10, tvb, offset, 5, ENC_NA);
    offset += 4;

    proto_tree_add_bits_item(tree, hf_ansi_683_reserved8, tvb, offset<<3, 1, ENC_NA);
}

/*
 * 4.5.2.1
 */
static void
for_param_block_nam_cdma_analog(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;

    saved_offset = offset;

    proto_tree_add_item(tree, hf_ansi_683_firstchp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    value = tvb_get_ntoh24(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_home_sid, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_extended_address_indicator, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_imsi_m_class10, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format_value(tree, hf_ansi_683_ismi_m_addr_num_e, tvb, offset + 2, 1, value,
            "%u, %u digits in NMSI", (value & 0x0e) >> 1,
            (value & 0x10) ? ((value & 0x0e) >> 1) + 4 : 0);

    offset += 2;

    proto_tree_add_item(tree, hf_ansi_683_mcc_m_01ff80, tvb, offset, 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_imsi_m_11_12_7f, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
    offset += 3;

    proto_tree_add_item(tree, hf_ansi_683_imsi_m_10, tvb, offset, 5, ENC_NA);
    offset += 4;

    proto_tree_add_item(tree, hf_ansi_683_accolc_3c, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_local_control_status_02, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_mob_term_home_01, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_mob_term_for_sid_8000, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_mob_term_for_nid_4000, tvb, offset, 2, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_ansi_683_num_sid_nid_3fc0, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_sid_nid_pairs_3fff, tvb, offset+1, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ansi_683_reserved_bytes,
        tvb, offset, len - (offset - saved_offset), ENC_NA);
}

/*
 * 4.5.2.2
 * see param_block_nam_mdn()
 */

/*
 * 4.5.2.3
 */
static void
for_param_block_nam_cdma(tvbuff_t *tvb, packet_info* pinfo _U_, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;

    saved_offset = offset;

    value = tvb_get_ntohs(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_imsi_m_class8000, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_uint_format_value(tree, hf_ansi_683_imsi_m_addr_num_7000, tvb, offset, 2, value,
            "%u, %u digits in NMSI", (value & 0x7000) >> 12,
            (value & 0x8000) ? ((value & 0x7000) >> 12) + 4 : 0);

    proto_tree_add_item(tree, hf_ansi_683_mcc_m_0ffc, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_imsi_m_11_12_3f80, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_imsi_m_10, tvb, offset, 5, ENC_NA);
    offset += 4;

    proto_tree_add_item(tree, hf_ansi_683_accolc_01e0, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_local_control_status_0010, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_mob_term_home_08, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_mob_term_for_sid_0004, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_mob_term_for_nid_0002, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_num_sid_nid_01fe, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_sid_nid_pairs_01ff, tvb, offset+1, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ansi_683_reserved_bytes,
        tvb, offset, len - (offset - saved_offset), ENC_NA);
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
for_param_block_val_spc(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    EXACT_DATA_CHECK(len, 3);

    proto_tree_add_string(tree, hf_ansi_683_service_programming_code,
        tvb, offset, len, tvb_bcd_dig_to_wmem_packet_str(tvb, offset, 3, NULL, FALSE));
}

/*
 * 4.5.4.3
 */
static const true_false_string tfs_activate_do_not_activate = { "Activate", "Do not activate" };

static void
for_param_block_val_spasm(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    if (len == 1)
    {
        proto_tree_add_item(tree, hf_ansi_683_otapa_spasm_validation_signature_indicator_80, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_ansi_683_spasm_protection_for_the_active_nam_40, tvb, offset, 1, ENC_NA);
        proto_tree_add_bits_item(tree, hf_ansi_683_reserved8, tvb, offset<<3, 6, ENC_NA);
    }
    else
    {
        EXACT_DATA_CHECK(len, 3);

        proto_tree_add_item(tree, hf_ansi_683_otapa_spasm_validation_signature_indicator_800000, tvb, offset, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_683_otapa_spasm_validation_signature, tvb, offset, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_683_spasm_protection_for_the_active_nam_000010, tvb, offset, 3, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_683_reserved24_f, tvb, offset, 3, ENC_BIG_ENDIAN);
    }
}

/* FORWARD MESSAGES */

/*
 * 4.5.1.1
 */
static void
msg_config_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_blocks);

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format(tree, hf_ansi_683_rev_param_block_nam, tvb, offset, 1,
            oct, "NAM Parameter Block Type #%u:  %s (%u)", i+1,
            rval_to_str_const(oct, rev_param_block_nam_rvals, "Reserved"), oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.2
 */
static void
msg_download_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    proto_tree  *subtree;
    proto_item  *item;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_for_nam_block, &item,
                "Block #%u", i+1);

        proto_tree_add_uint(subtree, hf_ansi_683_for_param_block_nam,
            tvb, offset, 1, block_id);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }
        proto_item_set_len(item, block_len+1);

        if (block_len > 0)
        {
            switch (block_id)
            {
            case FOR_BLOCK_NAM_CDMA_ANALOG:
                for_param_block_nam_cdma_analog(tvb, pinfo, subtree, block_len, offset);
                break;

            case FOR_BLOCK_NAM_MDN:
                param_block_nam_mdn(tvb, pinfo, subtree, block_len, offset);
                break;

            case FOR_BLOCK_NAM_CDMA:
                for_param_block_nam_cdma(tvb, pinfo, subtree, block_len, offset);
                break;

            case FOR_BLOCK_NAM_IMSI_T:
                param_block_nam_imsi_t(tvb, subtree, block_len, offset);
                break;

            default:
                proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
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
static const value_string akey_protocol_revision_vals[] = {
    { 0x02,     "2G A-key generation" },
    { 0x03,     "2G A-key and 3G Root Key generation" },
    { 0x04,     "3G Root Key generation" },
    { 0x05,     "Enhanced 3G Root Key generation" },
    { 0, NULL },
};

static void
msg_ms_key_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      akey_prev, param_len;
    proto_tree  *subtree;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    akey_prev = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_a_key_protocol_revision, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (akey_prev < 0x03)
    {
        param_len = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree(tree,
                tvb, offset, param_len + 1,
                ett_key_p, NULL, "Key exchange parameter P");

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, param_len);
        offset++;

        if (param_len > 0)
        {
            proto_tree_add_item(subtree, hf_ansi_683_parameter_p, tvb, offset, param_len, ENC_NA);
            offset += param_len;
        }

        param_len = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree(tree,
                tvb, offset, param_len + 1,
                ett_key_g, NULL, "Key exchange parameter G");

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, param_len);
        offset++;

        if (param_len > 0)
        {
            proto_tree_add_item(subtree, hf_ansi_683_parameter_g, tvb, offset, param_len, ENC_NA);
            offset += param_len;
        }
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.4
 */
static void
msg_key_gen_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
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
        proto_tree_add_item(tree, hf_ansi_683_base_station_calculation_result, tvb, offset, param_len, ENC_NA);
        offset += param_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.5
 */
static void
msg_reauth_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{

    EXACT_DATA_CHECK(len, 4);

    proto_tree_add_item(tree, hf_ansi_683_random_challenge_value, tvb, offset, 4, ENC_NA);
}

/*
 * 4.5.1.6
 * Commit Request (no data associated)
 */

/*
 * 4.5.1.7
 */
static void
msg_protocap_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint32     i, saved_offset;
    guint8      oct, num_cap;

    if (len == 0)
    {
        /*
         * if the base station did not request new cap info OR
         * this is an earlier release
         */
        return;
    }

    saved_offset = offset;

    proto_tree_add_item(tree, hf_ansi_683_otasp_protocol_revision, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    num_cap = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_capability_records, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_cap);

    for (i=0; i < num_cap; i++)
    {
        oct = tvb_get_guint8(tvb, offset);
        proto_tree_add_uint_format(tree, hf_ansi_683_cap_info_record_type, tvb, offset, 1, oct,
            "Record Type #%u: %s (%u)", i+1, rval_to_str_const(oct, rev_cap_info_record_type_rvals, "Reserved"), oct);
        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.8
 */
static void
msg_sspr_config_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    guint32     saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_item(tree, hf_ansi_683_rev_param_block_sspr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (oct == REV_BLOCK_SSPR_PRL)
    {
        subtree = proto_item_add_subtree(item, ett_rev_sspr_block);

        if ((len - (offset - saved_offset)) < 3)
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }

        proto_tree_add_item(subtree, hf_ansi_683_segment_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(subtree, hf_ansi_683_maximum_segment_size, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.9
 */
static void
msg_sspr_download_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_len;
    guint32     saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    item = proto_tree_add_item(tree, hf_ansi_683_for_param_block_sspr, tvb, offset, 1, ENC_BIG_ENDIAN);
    subtree = proto_item_add_subtree(item, ett_for_sspr_block);
    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(subtree, hf_ansi_683_length,
        tvb, offset, 1, block_len);
    offset++;

    if (block_len > (len - (offset - saved_offset)))
    {
        proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
        return;
    }

    if (block_len > 0)
    {
        proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
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
msg_validate_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    proto_tree  *subtree;
    proto_item  *item;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_for_val_block, &item,
                "Block #%u", i+1);

        proto_tree_add_item(subtree, hf_ansi_683_param_block_val, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);

        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }
        proto_item_set_len(item, block_len+1);

        if (block_len > 0)
        {
            switch (block_id)
            {
            case FOR_BLOCK_VAL_VERIFY_SPC:
            case FOR_BLOCK_VAL_CHANGE_SPC:
                for_param_block_val_spc(tvb, pinfo, subtree, block_len, offset);
                break;

            case FOR_BLOCK_VAL_VALDATE_SPASM:
                for_param_block_val_spasm(tvb, pinfo, subtree, block_len, offset);
                break;

            default:
                proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
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
static const true_false_string tfs_start_stop = { "Start", "Stop" };

static void
msg_otapa_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_683_start_otapa_session, tvb, offset, 1, ENC_NA);
    proto_tree_add_bits_item(tree, hf_ansi_683_reserved8, tvb, offset<<3, 7, ENC_NA);
}

/*
 * 4.5.1.12
 */
static void
msg_puzl_config_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_len;
    guint32     saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    item = proto_tree_add_item(tree, hf_ansi_683_rev_param_block_puzl, tvb, offset, 1, ENC_BIG_ENDIAN);
    block_len = len - (offset - saved_offset);

    if (block_len > 0)
    {
        subtree = proto_item_add_subtree(item, ett_rev_puzl_block);

        proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
        offset += block_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.13
 */
static void
msg_puzl_download_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    proto_item  *item;
    proto_tree  *subtree;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_for_puzl_block, &item,
                "Block #%u", i+1);

        proto_tree_add_uint(subtree, hf_ansi_683_for_param_block_puzl,
            tvb, offset, 1, block_id);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }
        proto_item_set_len(item, block_len+1);

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
                proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
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
msg_3gpd_config_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_blocks);

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint_format(tree, hf_ansi_683_rev_param_block_3gpd,
            tvb, offset, 1, oct,
            "3GPD Parameter Block %u:  %s (%u)",
            i+1, val_to_str_const(oct, rev_param_block_3gpd_vals, "Reserved"), oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.15
 */
static void
msg_3gpd_download_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    proto_item  *item;
    proto_tree  *subtree;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_for_3gpd_block, &item,
                "Block #%u", i+1);
        proto_tree_add_uint(subtree, hf_ansi_683_for_param_block_3gpd, tvb, offset, 1, block_id);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }
        proto_item_set_len(item, block_len+1);

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
                proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
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
msg_secure_mode_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    const gchar *str = NULL;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_start_secure_mode, tvb, offset, 1, ENC_NA);

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

    proto_tree_add_uint_format_value(tree, hf_ansi_683_security,
        tvb, offset, 1, oct, "%s", str);

    proto_tree_add_bits_item(tree, hf_ansi_683_reserved8, tvb, offset<<3, 3, ENC_NA);
    offset++;

    if (oct & 0x80)
    {
        SHORT_DATA_CHECK(len, 8);

        proto_tree_add_item(tree, hf_ansi_683_random_number_smck_generation, tvb, offset, 8, ENC_BIG_ENDIAN);

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
msg_mmd_config_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_blocks);

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint_format(tree, hf_ansi_683_rev_param_block_mmd,
            tvb, offset, 1, oct,
            "MMD Parameter Block #%u:  %s (%u)",
            i+1, val_to_str_const(oct, param_block_mmd_vals, "Reserved"), oct);

        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.19
 */
static void
msg_mmd_download_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    proto_item  *item;
    proto_tree  *subtree;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_for_mmd_block, &item,
                "Block #%u", i+1);

        proto_tree_add_uint(subtree, hf_ansi_683_for_param_block_mmd,
            tvb, offset, 1, block_id);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }

        proto_item_set_len(item, block_len+1);

        if (block_len > 0)
        {
            switch (block_id)
            {
            case FOR_BLOCK_MMD_APP:
            default:
                proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
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
msg_systag_config_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    item = proto_tree_add_item(tree, hf_ansi_683_rev_param_block_systag,
            tvb, offset, 1, ENC_BIG_ENDIAN);
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

        proto_tree_add_item(subtree, hf_ansi_683_segment_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(subtree, hf_ansi_683_maximum_segment_size, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.21
 */
static void
msg_systag_download_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_len;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    proto_tree_add_item(tree, hf_ansi_683_for_param_block_systag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, block_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), block_len);

    if (block_len > 0)
    {
        proto_tree_add_item(tree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
        offset += block_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}


/*
 * 4.5.1.22
 */
static void
msg_srvckey_gen_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint32     saved_offset;
    guint32     value;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    value = tvb_get_ntohs(tvb, offset);

    proto_tree_add_boolean_format_value(tree, hf_ansi_683_key_id_ims_root_key, tvb, offset, 2, value, "IMS Root Key");
    proto_tree_add_boolean_format_value(tree, hf_ansi_683_key_id_bcmcs_root_key, tvb, offset, 2, value, "BCMCS Root Key");
    proto_tree_add_boolean_format_value(tree, hf_ansi_683_key_id_wlan_root_key, tvb, offset, 2, value, "WLAN Root Key");
    proto_tree_add_uint_format_value(tree, hf_ansi_683_key_id_reserved, tvb, offset, 2, value, "Reserved");

    proto_tree_add_item(tree, hf_ansi_683_reserved16_f,
        tvb, offset, 2, ENC_BIG_ENDIAN);

    offset += 2;

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.23
 */
static void
msg_mms_config_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_blocks);

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint_format(tree, hf_ansi_683_rev_param_block_mms,
            tvb, offset, 1, oct,
            "MMS Parameter Block #%u:  %s (%u)",
            i+1, rval_to_str_const(oct, rev_param_block_mms_rvals, "Reserved"), oct);
        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 4.5.1.24
 */
static void
msg_mms_download_req(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    proto_item  *item;
    proto_tree  *subtree;
    guint32     i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_for_mms_block, &item,
                "Block #%u", i+1);

        proto_tree_add_uint(subtree, hf_ansi_683_for_param_block_mms, tvb, offset, 1, block_id);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }
        proto_item_set_len(item, block_len+1);

        if (block_len > 0)
        {
            switch (block_id)
            {
            case FOR_BLOCK_MMS_URI:
            default:
                proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
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
msg_config_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id, num_blocks, block_len;
    guint32     i, saved_offset;
    proto_item  *item;
    proto_tree  *subtree;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_rev_nam_block, &item,
                "Block #%u", i+1);
        proto_tree_add_uint(subtree, hf_ansi_683_rev_param_block_nam,
            tvb, offset, 1, block_id);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }
        proto_item_set_len(item, block_len+1);

        if (block_len > 0)
        {
            switch (block_id)
            {
            case REV_BLOCK_NAM_CDMA_ANALOG:
                rev_param_block_nam_cdma_analog(tvb, pinfo, subtree, block_len, offset);
                break;

            case REV_BLOCK_NAM_MDN:
                param_block_nam_mdn(tvb, pinfo, subtree, block_len, offset);
                break;

            case REV_BLOCK_NAM_CDMA:
                rev_param_block_nam_cdma(tvb, pinfo, subtree, block_len, offset);
                break;

            case REV_BLOCK_NAM_IMSI_T:
                param_block_nam_imsi_t(tvb, subtree, block_len, offset);
                break;

            default:
                proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
                break;
            }

            offset += block_len;
        }
    }

    SHORT_DATA_CHECK((len - (offset - saved_offset)), num_blocks);

    for (i=0; i < num_blocks; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint_format(tree, hf_ansi_683_result_code,
            tvb, offset, 1, oct, "Block #%u result code: %s (%u)",
            i+1, rval_to_str_const(oct, result_codes_rvals, "Reserved"), oct);

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
msg_download_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      num_blocks;
    guint32     i, saved_offset;
    proto_tree  *subtree;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 2, ett_for_nam_block, NULL,
                "Block #%u", i+1);
        proto_tree_add_item(subtree, hf_ansi_683_for_param_block_nam,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(subtree, hf_ansi_683_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.3
 */
static void
msg_ms_key_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_683_key_exchange_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/*
 * 3.5.1.4
 */
static void
msg_key_gen_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      result_len;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    proto_tree_add_item(tree, hf_ansi_683_key_exchange_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    result_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, result_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), result_len);

    if (result_len > 0)
    {
        proto_tree_add_item(tree, hf_ansi_683_mobile_station_calculation_result, tvb, offset, result_len, ENC_NA);
        offset += result_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.5
 */
static void
msg_reauth_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    EXACT_DATA_CHECK(len, 7);

    proto_tree_add_item(tree, hf_ansi_683_authr, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ansi_683_randc, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_ansi_683_call_history_parameter, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ansi_683_authentication_data_input_parameter, tvb, offset, 3, ENC_BIG_ENDIAN);
}

/*
 * 3.5.1.6
 */
static void
msg_commit_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_683_data_commit_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/*
 * 3.5.1.7
 */
static void
msg_protocap_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_feat, add_len;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item;

    SHORT_DATA_CHECK(len, 5);

    saved_offset = offset;

    proto_tree_add_item(tree, hf_ansi_683_mobile_station_fw_rev, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ansi_683_mobile_station_manuf_model_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    num_feat = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_num_features, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_feat * 2));

    for (i=0; i < num_feat; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        item = proto_tree_add_uint_format(tree, hf_ansi_683_feature_id,
                tvb, offset, 1, oct,
                "Feature ID #%u: %s (%u)",
                i+1, rval_to_str_const(oct, feat_id_type_rvals, "Reserved"), oct);

        subtree = proto_item_add_subtree(item, ett_rev_feat);
        offset++;

        proto_tree_add_item(subtree, hf_ansi_683_feature_protocol_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    add_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, add_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), add_len);

    if (add_len > 0)
    {
        subtree = proto_tree_add_subtree(tree,
                tvb, offset, 1, ett_band_cap, NULL,
                "Band/Mode Capability Information");

        proto_tree_add_item(subtree, hf_ansi_683_band_class_0_analog, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_ansi_683_band_class_0_cdma, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_ansi_683_band_class_1_cdma, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_ansi_683_band_class_3_cdma, tvb, offset, 1, ENC_NA);
        proto_tree_add_item(subtree, hf_ansi_683_band_class_6_cdma, tvb, offset, 1, ENC_NA);
        proto_tree_add_bits_item(subtree, hf_ansi_683_reserved8, tvb, offset<<3, 3, ENC_NA);
        offset++;

        if (add_len > 1)
        {
            proto_tree_add_item(tree, hf_ansi_683_more_additional_fields, tvb, offset, add_len - 1, ENC_NA);
            offset += (add_len - 1);
        }
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.8
 */
static void
msg_sspr_config_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_len;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = offset;

    proto_tree_add_item(tree, hf_ansi_683_rev_param_block_sspr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_sspr_configuration_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, block_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), block_len);

    if (block_len > 0)
    {
        proto_tree_add_item(tree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
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
msg_sspr_download_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id;

    EXACT_DATA_CHECK(len, 5);

    block_id = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_for_param_block_sspr, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_sspr_download_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    switch (block_id)
    {
    case FOR_BLOCK_SSPR_PRL:
    case FOR_BLOCK_SSPR_EXT_PRL:
        proto_tree_add_item(tree, hf_ansi_683_segment_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_ansi_683_maximum_segment_size, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        break;
    }
}

/*
 * 3.5.1.10
 */
static void
msg_validate_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      num_blocks;
    guint32     i, saved_offset;
    proto_tree  *subtree;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 2, ett_for_val_block, NULL,
                "Block ID #%u", i+1);

        proto_tree_add_item(subtree, hf_ansi_683_param_block_val, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(subtree, hf_ansi_683_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.11
 */
static void
msg_otapa_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint_format(tree, hf_ansi_683_result_code,
        tvb, offset, 1, oct, "OTAPA result code: %s (%u)",
        rval_to_str_const(oct, result_codes_rvals, "Reserved"), oct);

    offset++;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_bits_item(tree, hf_ansi_683_reserved8, tvb, (offset<<3)+1, 7, ENC_NA);

    proto_tree_add_item(tree, hf_ansi_683_nam_lock_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (oct & 0x01)
    {
        SHORT_DATA_CHECK((len - (offset - saved_offset)), 4);

        proto_tree_add_item(tree, hf_ansi_683_spasm_random_challenge, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.12
 */
static void
msg_puzl_config_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_len;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = offset;

    proto_tree_add_item(tree, hf_ansi_683_rev_param_block_puzl, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_puzl_configuration_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, block_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), block_len);

    if (block_len > 0)
    {
        proto_tree_add_item(tree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
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
msg_puzl_download_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, num_blocks;
    guint32     i, saved_offset, block_offset;
    proto_item  *item;
    proto_tree  *subtree;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    /* minimum required length */
    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 3));

    for (i=0; i < num_blocks; i++)
    {
        block_offset = offset;

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_for_puzl_block, &item,
                "Block #%u", i+1);

        proto_tree_add_item(subtree, hf_ansi_683_for_param_block_puzl, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(subtree, hf_ansi_683_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        oct = tvb_get_guint8(tvb, offset);

        if (oct & 0x80)
        {
            SHORT_DATA_CHECK(len, 4);

            proto_tree_add_item(tree, hf_ansi_683_identifiers_present16, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_ansi_683_user_zone_id, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(tree, hf_ansi_683_user_zone_sid, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        else
        {
            proto_tree_add_item(tree, hf_ansi_683_identifiers_present8, tvb, offset, 1, ENC_NA);
            proto_tree_add_bits_item(tree, hf_ansi_683_reserved8, tvb, offset<<3, 7, ENC_NA);
            offset++;
        }

        proto_item_set_len(item, offset - block_offset);
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.14
 */
static void
msg_3gpd_config_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    guint32     i, saved_offset;
    proto_item  *item;
    proto_tree  *subtree;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    /* minimum required length */
    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 3));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_rev_3gpd_block, &item,
                "Block #%u", i+1);

        proto_tree_add_uint(subtree, hf_ansi_683_rev_param_block_3gpd,
            tvb, offset, 1, block_id);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }
        proto_item_set_len(item, block_len+1);

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
                proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
                break;
            }

            offset += block_len;
        }

        SHORT_DATA_CHECK(len, 1);

        proto_tree_add_item(tree, hf_ansi_683_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
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
msg_3gpd_download_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      num_blocks;
    guint32     i, saved_offset;
    proto_tree  *subtree;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 2, ett_for_3gpd_block, NULL,
                "Block #%u", i+1);
        proto_tree_add_item(subtree, hf_ansi_683_for_param_block_3gpd, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(subtree, hf_ansi_683_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.16
 */
static void
msg_secure_mode_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_683_secure_mode_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/*
 * 3.5.1.17
 */
static void
msg_ext_protocap_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      oct, block_id, num_recs, block_len;
    guint32     i, saved_offset;
    proto_tree  *subtree;
    proto_item  *item, *len_item;

    SHORT_DATA_CHECK(len, 6);

    saved_offset = offset;

    proto_tree_add_item(tree, hf_ansi_683_otasp_mobile_protocol_revision, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_mobile_station_fw_rev, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(tree, hf_ansi_683_mobile_station_manuf_model_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    num_recs = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ansi_683_num_features, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_recs * 2));

    for (i=0; i < num_recs; i++)
    {
        oct = tvb_get_guint8(tvb, offset);

        item = proto_tree_add_uint_format(tree, hf_ansi_683_feature_id,
                tvb, offset, 1, oct,
                "Feature ID #%u: %s (%u)",
                i+1, rval_to_str_const(oct, feat_id_type_rvals, "Reserved"), oct);

        subtree = proto_item_add_subtree(item, ett_rev_feat);
        offset++;

        proto_tree_add_item(subtree, hf_ansi_683_feature_protocol_version, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    SHORT_DATA_CHECK((len - (offset - saved_offset)), 1);

    num_recs = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_capability_records, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /* minimum required length */
    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_recs * 2));

    for (i=0; i < num_recs; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_rev_cap, &item,
                "Block ID #%u", i+1);
        proto_tree_add_item(subtree, hf_ansi_683_cap_info_record_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        len_item = proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            expert_add_info(pinfo, len_item, &ei_ansi_683_short_data);
            return;
        }
        proto_item_set_len(item, block_len+1);

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
                proto_tree_add_item(subtree, hf_ansi_683_capability_data, tvb, offset, block_len, ENC_NA);
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
msg_mmd_config_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    guint32     i, saved_offset;
    proto_item  *item;
    proto_tree  *subtree;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    /* minimum required length */
    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 3));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_rev_mmd_block, &item,
                "Block #%u", i+1);

        proto_tree_add_uint(subtree, hf_ansi_683_rev_param_block_mmd,
            tvb, offset, 1, block_id);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }

        proto_item_set_len(item, block_len+1);

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
                proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
                break;
            }

            offset += block_len;
        }

        SHORT_DATA_CHECK(len, 1);

        proto_tree_add_item(tree, hf_ansi_683_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
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
msg_mmd_download_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      num_blocks;
    guint32     i, saved_offset;
    proto_tree  *subtree;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 2, ett_for_mmd_block, NULL,
                "Block #%u", i+1);

        proto_tree_add_item(subtree, hf_ansi_683_for_param_block_mmd, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(subtree, hf_ansi_683_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.20
 */
static void
msg_systag_config_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_len;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = offset;

    proto_tree_add_item(tree, hf_ansi_683_rev_param_block_systag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_system_tag_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
        tvb, offset, 1, block_len);
    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), block_len);

    if (block_len > 0)
    {
        proto_tree_add_item(tree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
        offset += block_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * 3.5.1.21
 */
static void
msg_systag_download_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id;
    guint32     saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    block_id = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_ansi_683_for_param_block_systag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_ansi_683_system_tag_download_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    switch (block_id)
    {
    case 0x01:          /* Group Tag List Parameter */
    case 0x02:          /* Specific Tag List Parameter */
    case 0x03:          /* Call Prompt List Parameter */
        SHORT_DATA_CHECK(len, 3);

        proto_tree_add_item(tree, hf_ansi_683_segment_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_ansi_683_segment_size, tvb, offset, 1, ENC_BIG_ENDIAN);
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
msg_srvckey_gen_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    EXACT_DATA_CHECK(len, 1);

    proto_tree_add_item(tree, hf_ansi_683_service_key_generation_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
}

/*
 * 3.5.1.23
 */
static void
msg_mms_config_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      block_id, num_blocks, block_len;
    guint32     i, saved_offset;
    proto_tree  *item;
    proto_tree  *subtree;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    /* minimum required length */
    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 3));

    for (i=0; i < num_blocks; i++)
    {
        block_id = tvb_get_guint8(tvb, offset);

        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_rev_mms_block, &item,
                "Block #%u", i+1);

        proto_tree_add_item(subtree, hf_ansi_683_rev_param_block_mms, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        block_len = tvb_get_guint8(tvb, offset);

        proto_tree_add_uint(subtree, hf_ansi_683_length,
            tvb, offset, 1, block_len);
        offset++;

        if (block_len > (len - (offset - saved_offset)))
        {
            proto_tree_add_expert(subtree, pinfo, &ei_ansi_683_short_data, tvb, offset, len - (offset - saved_offset));
            return;
        }
        proto_item_set_len(item, block_len+1);

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
                proto_tree_add_item(subtree, hf_ansi_683_block_data, tvb, offset, block_len, ENC_NA);
                break;
            }

            offset += block_len;
        }

        SHORT_DATA_CHECK(len, 1);

        proto_tree_add_item(subtree, hf_ansi_683_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
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
msg_mms_download_rsp(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset)
{
    guint8      num_blocks;
    guint32     i, saved_offset;
    proto_tree  *subtree;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_ansi_683_number_of_parameter_blocks, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    SHORT_DATA_CHECK((len - (offset - saved_offset)), (guint32)(num_blocks * 2));

    for (i=0; i < num_blocks; i++)
    {
        subtree = proto_tree_add_subtree_format(tree,
                tvb, offset, 1, ett_for_mms_block, NULL,
                "Block #%u", i+1);

        proto_tree_add_item(subtree, hf_ansi_683_for_param_block_mms, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        proto_tree_add_item(subtree, hf_ansi_683_result_code, tvb, offset, 1, ENC_BIG_ENDIAN);
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
static void (*ansi_683_for_msg_fcn[])(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset) = {
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
static void (*ansi_683_rev_msg_fcn[])(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, guint len, guint32 offset) = {
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
dissect_ansi_683_for_message(tvbuff_t *tvb, packet_info* pinfo, proto_tree *ansi_683_tree)
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
        (*ansi_683_for_msg_fcn[idx])(tvb, pinfo, ansi_683_tree, tvb_reported_length(tvb) - 1, 1);
    }
}

static void
dissect_ansi_683_rev_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *ansi_683_tree)
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

    (*ansi_683_rev_msg_fcn[idx])(tvb, pinfo, ansi_683_tree, tvb_reported_length(tvb) - 1, 1);
}

static int
dissect_ansi_683(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item  *ansi_683_item;
    proto_tree  *ansi_683_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IS-683");

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
        dissect_ansi_683_for_message(tvb, pinfo, ansi_683_tree);
    }
    else
    {
        dissect_ansi_683_rev_message(tvb, pinfo, ansi_683_tree);
    }
    return tvb_captured_length(tvb);
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
        { &hf_ansi_683_reserved8,
            { "Reserved",         "ansi_683.reserved",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_683_reserved16_f,
            { "Reserved",         "ansi_683.reserved",
            FT_UINT16, BASE_HEX, NULL, 0x000f,
            NULL, HFILL }
        },
        { &hf_ansi_683_reserved24_f,
            { "Reserved",         "ansi_683.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x00000f,
            NULL, HFILL }
        },
        { &hf_ansi_683_reserved_bytes,
            { "Reserved",   "ansi_683.reserved_bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_ansi_683_fresh_incl16, { "FRESH_INCL", "ansi_683.fresh_incl", FT_BOOLEAN, 16, TFS(&tfs_true_false), 0x8000, NULL, HFILL }},
      { &hf_ansi_683_fresh, { "FRESH", "ansi_683.fresh", FT_UINT16, BASE_DEC, NULL, 0x7fff, NULL, HFILL }},
      { &hf_ansi_683_fresh_incl8, { "FRESH_INCL", "ansi_683.fresh_incl", FT_BOOLEAN, 8, TFS(&tfs_true_false), 0x80, NULL, HFILL }},
      { &hf_ansi_683_firstchp, { "First paging channel (FIRSTCHP) used in the home system", "ansi_683.firstchp", FT_UINT16, BASE_DEC, NULL, 0xffe0, NULL, HFILL }},
      { &hf_ansi_683_home_sid, { "Home system identification (HOME_SID)", "ansi_683.home_sid", FT_UINT24, BASE_DEC, NULL, 0x1fffc0, NULL, HFILL }},
      { &hf_ansi_683_extended_address_indicator, { "Extended address indicator (EX)", "ansi_683.extended_address_indicator", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
      { &hf_ansi_683_station_class_mark, { "Station class mark (SCM)", "ansi_683.station_class_mark", FT_UINT16, BASE_DEC, NULL, 0x1fe0, NULL, HFILL }},
      { &hf_ansi_683_extended_scm_indicator, { "Extended SCM Indicator", "ansi_683.extended_scm_indicator", FT_BOOLEAN, 16, TFS(&tfs_extended_scm_indicator), 0x1000, NULL, HFILL }},
      { &hf_ansi_683_cdma_analog_mode, { "Mode", "ansi_683.cdma_analog_mode", FT_BOOLEAN, 16, TFS(&tfs_cdma_analog_mode), 0x0800, NULL, HFILL }},
      { &hf_ansi_683_cdma_analog_slotted, { "Slotted", "ansi_683.cdma_analog_slotted", FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0400, NULL, HFILL }},
      { &hf_ansi_683_meid, { "MEID", "ansi_683.meid", FT_BOOLEAN, 16, TFS(&tfs_configured_not_configured), 0x0200, NULL, HFILL }},
      { &hf_ansi_683_25mhz_bandwidth, { "25 MHz Bandwidth", "ansi_683.25mhz_bandwidth", FT_BOOLEAN, 16, NULL, 0x0100, NULL, HFILL }},
      { &hf_ansi_683_transmission, { "Transmission", "ansi_683.transmission", FT_BOOLEAN, 16, TFS(&tfs_discontinuous_continous), 0x0080, NULL, HFILL }},
      { &hf_ansi_683_power_class, { "Power Class for Band Class 0 Analog Operation", "ansi_683.power_class", FT_UINT16, BASE_DEC, VALS(power_class_vals), 0x0060, NULL, HFILL }},
      { &hf_ansi_683_mob_p_rev_1fe0, { "Mobile station protocol revision number (MOB_P_REV)", "ansi_683.mob_p_rev", FT_UINT16, BASE_DEC, NULL, 0x1fe0, NULL, HFILL }},
      { &hf_ansi_683_imsi_m_class10, { "IMSI_M Class assignment of the mobile station (IMSI_M_CLASS)", "ansi_683.imsi_m_class", FT_UINT16, BASE_DEC, NULL, 0x10, NULL, HFILL }},
      { &hf_ansi_683_ismi_m_addr_num_e, { "Number of IMSI_M address digits (IMSI_M_ADDR_NUM)", "ansi_683.ismi_m_addr_num", FT_UINT16, BASE_DEC, NULL, 0x0e, NULL, HFILL }},
      { &hf_ansi_683_mcc_m_01ff80, { "Mobile country code (MCC_M)", "ansi_683.mcc_m", FT_UINT24, BASE_DEC, NULL, 0x01ff80, NULL, HFILL }},
      { &hf_ansi_683_imsi_m_11_12_7f, { "11th and 12th digits of the IMSI_M (IMSI__M_11_12)", "ansi_683.imsi_m_11_12", FT_UINT24, BASE_HEX, NULL, 0x00007f, NULL, HFILL }},
      { &hf_ansi_683_imsi_m_10, { "The least significant 10 digits of the IMSI_M (IMSI_M_S) (34 bits)", "ansi_683.imsi_m_10", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_accolc_3c, { "Access overload class (ACCOLC)", "ansi_683.accolc", FT_UINT8, BASE_DEC, NULL, 0x3c, NULL, HFILL }},
      { &hf_ansi_683_local_control_status_02, { "Local control status (LOCAL_CONTROL)", "ansi_683.local_control_status", FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL }},
      { &hf_ansi_683_mob_term_home_01, { "Termination indicator for the home system (MOB_TERM_HOME)", "ansi_683.mob_term_home", FT_UINT8, BASE_DEC, NULL, 0x1, NULL, HFILL }},
      { &hf_ansi_683_mob_term_for_sid_80, { "Termination indicator for SID roaming (MOB_TERM_FOR_SID)", "ansi_683.mob_term_for_sid", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
      { &hf_ansi_683_mob_term_for_nid_40, { "Termination indicator for NID roaming (MOB_TERM_FOR_NID)", "ansi_683.mob_term_for_nid", FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL }},
      { &hf_ansi_683_max_sid_nid_3fc0, { "Maximum stored SID/NID pairs (MAX_SID_NID)", "ansi_683.max_sid_nid", FT_UINT16, BASE_DEC, NULL, 0x3fc0, NULL, HFILL }},
      { &hf_ansi_683_stored_sid_nid_3fc0, { "Number of stored SID/NID pairs (STORED_SID_NID)", "ansi_683.stored_sid_nid", FT_UINT16, BASE_DEC, NULL, 0x3fc0, NULL, HFILL }},
      { &hf_ansi_683_sid_nid_pairs_3fff, { "SID/NID pairs", "ansi_683.sid_nid_pairs", FT_UINT16, BASE_DEC, NULL, 0x3fff, NULL, HFILL }},
      { &hf_ansi_683_n_digits, { "Number of digits (N_DIGITS)", "ansi_683.n_digits", FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
      { &hf_ansi_683_slotted_mode, { "Slotted Mode", "ansi_683.slotted_mode", FT_UINT8, BASE_DEC, NULL, 0x20, NULL, HFILL }},
      { &hf_ansi_683_mob_p_rev_ff, { "Mobile station protocol revision number (MOB_P_REV)", "ansi_683.mob_p_rev", FT_UINT8, BASE_DEC, NULL, 0xFF, NULL, HFILL }},
      { &hf_ansi_683_imsi_m_class8000, { "IMSI_M Class assignment of the mobile station (IMSI_M_CLASS)", "ansi_683.imsi_m_class", FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL }},
      { &hf_ansi_683_imsi_m_addr_num_7000, { "Number of IMSI_M address digits (IMSI_M_ADDR_NUM)", "ansi_683.imsi_m_addr_num", FT_UINT16, BASE_DEC, NULL, 0x7000, NULL, HFILL }},
      { &hf_ansi_683_mcc_m_0ffc, { "Mobile country code (MCC_M)", "ansi_683.mcc_m", FT_UINT16, BASE_DEC, NULL, 0x0ffc, NULL, HFILL }},
      { &hf_ansi_683_imsi_m_11_12_3f80, { "11th and 12th digits of the IMSI_M (IMSI__M_11_12)", "ansi_683.imsi_m_11_12", FT_UINT16, BASE_DEC, NULL, 0x3f80, NULL, HFILL }},
      { &hf_ansi_683_accolc_01e0, { "Access overload class (ACCOLC)", "ansi_683.accolc", FT_UINT16, BASE_DEC, NULL, 0x01e0, NULL, HFILL }},
      { &hf_ansi_683_local_control_status_0010, { "Local control status (LOCAL_CONTROL)", "ansi_683.local_control_status", FT_UINT16, BASE_DEC, NULL, 0x0010, NULL, HFILL }},
      { &hf_ansi_683_mob_term_home_08, { "Termination indicator for the home system (MOB_TERM_HOME)", "ansi_683.mob_term_home", FT_UINT16, BASE_DEC, NULL, 0x0008, NULL, HFILL }},
      { &hf_ansi_683_mob_term_for_sid_0004, { "Termination indicator for SID roaming (MOB_TERM_FOR_SID)", "ansi_683.mob_term_for_sid", FT_UINT16, BASE_DEC, NULL, 0x0004, NULL, HFILL }},
      { &hf_ansi_683_mob_term_for_nid_0002, { "Termination indicator for NID roaming (MOB_TERM_FOR_NID)", "ansi_683.mob_term_for_nid", FT_UINT16, BASE_DEC, NULL, 0x0002, NULL, HFILL }},
      { &hf_ansi_683_max_sid_nid_01fe, { "Maximum stored SID/NID pairs (MAX_SID_NID)", "ansi_683.max_sid_nid", FT_UINT16, BASE_DEC, NULL, 0x01fe, NULL, HFILL }},
      { &hf_ansi_683_stored_sid_nid_01fe, { "Number of stored SID/NID pairs (STORED_SID_NID)", "ansi_683.stored_sid_nid", FT_UINT16, BASE_DEC, NULL, 0x01fe, NULL, HFILL }},
      { &hf_ansi_683_sid_nid_pairs_01ff, { "SID/NID pairs", "ansi_683.sid_nid_pairs", FT_UINT16, BASE_DEC, NULL, 0x01ff, NULL, HFILL }},
      { &hf_ansi_683_imsi_t_class, { "IMSI_T Class assignment of the mobile station (IMSI_T_CLASS)", "ansi_683.imsi_t_class", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
      { &hf_ansi_683_imsi_t_addr_num, { "Number of IMSI_T address digits (IMSI_T_ADDR_NUM )", "ansi_683.imsi_t_addr_num", FT_UINT8, BASE_DEC, NULL, 0x70, NULL, HFILL }},
      { &hf_ansi_683_mcc_t, { "Mobile country code (MCC_T)", "ansi_683.mcc_t", FT_UINT16, BASE_DEC, NULL, 0x0ffc, NULL, HFILL }},
      { &hf_ansi_683_imsi_t_11_12, { "11th and 12th digits of the IMSI_T (IMSI__T_11_12)", "ansi_683.imsi_t_11_12", FT_UINT16, BASE_DEC, NULL, 0x03f8, NULL, HFILL }},
      { &hf_ansi_683_imsi_t_10, { "The least significant 10 digits of the IMSI_T (IMSI_T_S) (34 bits)", "ansi_683.imsi_t_10", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_mob_term_for_sid_8000, { "Termination indicator for SID roaming (MOB_TERM_FOR_SID)", "ansi_683.mob_term_for_sid", FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL }},
      { &hf_ansi_683_mob_term_for_nid_4000, { "Termination indicator for NID roaming (MOB_TERM_FOR_NID)", "ansi_683.mob_term_for_nid", FT_UINT16, BASE_DEC, NULL, 0x4000, NULL, HFILL }},
      { &hf_ansi_683_num_sid_nid_3fc0, { "Number of SID/NID pairs (N_SID_NID)", "ansi_683.num_sid_nid", FT_UINT16, BASE_DEC, NULL, 0x3fc0, NULL, HFILL }},
      { &hf_ansi_683_num_sid_nid_01fe, { "Number of SID/NID pairs (N_SID_NID)", "ansi_683.num_sid_nid", FT_UINT16, BASE_DEC, NULL, 0x01fe, NULL, HFILL }},
      { &hf_ansi_683_otapa_spasm_validation_signature_indicator_80, { "OTAPA SPASM validation signature indicator", "ansi_683.otapa_spasm_validation_signature_indicator", FT_BOOLEAN, 8, TFS(&tfs_included_not_included), 0x80, NULL, HFILL }},
      { &hf_ansi_683_spasm_protection_for_the_active_nam_40, { "SPASM protection for the active NAM", "ansi_683.spasm_protection_for_the_active_nam", FT_BOOLEAN, 8, TFS(&tfs_activate_do_not_activate), 0x40, NULL, HFILL }},
      { &hf_ansi_683_otapa_spasm_validation_signature_indicator_800000, { "OTAPA SPASM validation signature indicator", "ansi_683.otapa_spasm_validation_signature_indicator", FT_BOOLEAN, 24, TFS(&tfs_included_not_included), 0x800000, NULL, HFILL }},
      { &hf_ansi_683_otapa_spasm_validation_signature, { "OTAPA SPASM validation signature", "ansi_683.otapa_spasm_validation_signature", FT_UINT24, BASE_HEX, NULL, 0x7fffe0, NULL, HFILL }},
      { &hf_ansi_683_spasm_protection_for_the_active_nam_000010, { "SPASM protection for the active NAM", "ansi_683.spasm_protection_for_the_active_nam", FT_BOOLEAN, 24, TFS(&tfs_activate_do_not_activate), 0x000010, NULL, HFILL }},
      { &hf_ansi_683_number_of_parameter_blocks, { "Number of parameter blocks", "ansi_683.number_of_parameter_blocks", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_block_data, { "Block Data", "ansi_683.block_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_a_key_protocol_revision, { "A-Key Protocol Revision", "ansi_683.a_key_protocol_revision", FT_UINT8, BASE_DEC, VALS(akey_protocol_revision_vals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_parameter_p, { "Parameter P", "ansi_683.parameter_p", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_parameter_g, { "Parameter G", "ansi_683.parameter_g", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_base_station_calculation_result, { "Base Station Calculation Result", "ansi_683.base_station_calculation_result", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_random_challenge_value, { "Random Challenge value", "ansi_683.random_challenge_value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_otasp_protocol_revision, { "OTASP protocol revision", "ansi_683.otasp_protocol_revision", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_number_of_capability_records, { "Number of Capability Records", "ansi_683.number_of_capability_records", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_segment_offset, { "Segment offset", "ansi_683.segment_offset", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_maximum_segment_size, { "Maximum segment size", "ansi_683.maximum_segment_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_start_otapa_session, { "OTAPA session", "ansi_683.otapa_session", FT_BOOLEAN, 8, TFS(&tfs_start_stop), 0x80, NULL, HFILL }},
      { &hf_ansi_683_start_secure_mode, { "Secure Mode", "ansi_683.secure_mode", FT_BOOLEAN, 8, TFS(&tfs_start_stop), 0x80, NULL, HFILL }},
      { &hf_ansi_683_security, { "Security", "ansi_683.security", FT_UINT8, BASE_DEC, NULL, 0x78, NULL, HFILL }},
      { &hf_ansi_683_random_number_smck_generation, { "Random Number used for SMCK generation", "ansi_683.random_number_smck_generation", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_key_id_ims_root_key, { "Key ID", "ansi_683.key_id.ims_root_key", FT_BOOLEAN, 16, NULL, 0x8000, NULL, HFILL }},
      { &hf_ansi_683_key_id_bcmcs_root_key, { "Key ID", "ansi_683.key_id.bcmcs_root_key", FT_BOOLEAN, 16, NULL, 0x4000, NULL, HFILL }},
      { &hf_ansi_683_key_id_wlan_root_key, { "Key ID", "ansi_683.key_id.wlan_root_key", FT_BOOLEAN, 16, NULL, 0x2000, NULL, HFILL }},
      { &hf_ansi_683_key_id_reserved, { "Key ID", "ansi_683.key_id.reserved", FT_UINT16, BASE_HEX, NULL, 0x1ff0, NULL, HFILL }},
      { &hf_ansi_683_key_exchange_result_code, { "Key exchange result code", "ansi_683.key_exchange_result_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(result_codes_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_mobile_station_calculation_result, { "Mobile station calculation result", "ansi_683.mobile_station_calculation_result", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_authr, { "Authentication signature data (AUTHR)", "ansi_683.authr", FT_UINT24, BASE_DEC, NULL, 0xffffc0, NULL, HFILL }},
      { &hf_ansi_683_randc, { "Random challenge value (RANDC)", "ansi_683.randc", FT_UINT16, BASE_DEC, NULL, 0x3fc0, NULL, HFILL }},
      { &hf_ansi_683_call_history_parameter, { "Call history parameter (COUNT)", "ansi_683.call_history_parameter", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
      { &hf_ansi_683_authentication_data_input_parameter, { "Authentication Data input parameter (AUTH_DATA)", "ansi_683.authentication_data_input_parameter", FT_UINT24, BASE_DEC, NULL, 0xffffff, NULL, HFILL }},
      { &hf_ansi_683_data_commit_result_code, { "Data commit result code", "ansi_683.data_commit_result_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(result_codes_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_mobile_station_fw_rev, { "Mobile station firmware revision number", "ansi_683.mobile_station_fw_rev", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_mobile_station_manuf_model_number, { "Mobile station manufacturer's model number", "ansi_683.mobile_station_manuf_model_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_num_features, { "Number of features", "ansi_683.num_features", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_feature_id, { "Feature ID", "ansi_683.feature_id", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(feat_id_type_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_feature_protocol_version, { "Feature protocol version", "ansi_683.feature_protocol_version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_band_class_0_analog, { "Band Class 0 Analog", "ansi_683.band_class_0_analog", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_ansi_683_band_class_0_cdma, { "Band Class 0 CDMA", "ansi_683.band_class_0_cdma", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_ansi_683_band_class_1_cdma, { "Band Class 1 CDMA", "ansi_683.band_class_1_cdma", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_ansi_683_band_class_3_cdma, { "Band Class 3 CDMA", "ansi_683.band_class_3_cdma", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_ansi_683_band_class_6_cdma, { "Band Class 6 CDMA", "ansi_683.band_class_6_cdma", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_ansi_683_more_additional_fields, { "More Additional Fields", "ansi_683.more_additional_fields", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_sspr_configuration_result_code, { "SSPR Configuration result code", "ansi_683.sspr_configuration_result_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(result_codes_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_sspr_download_result_code, { "SSPR Download result code", "ansi_683.sspr_download_result_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(result_codes_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_nam_lock_indicator, { "NAM_LOCK indicator", "ansi_683.nam_lock_indicator", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
      { &hf_ansi_683_spasm_random_challenge, { "SPASM random challenge", "ansi_683.spasm_random_challenge", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_puzl_configuration_result_code, { "PUZL Configuration result code", "ansi_683.puzl_configuration_result_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(result_codes_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_identifiers_present16, { "Identifiers", "ansi_683.identifiers.present", FT_BOOLEAN, 16, TFS(&tfs_present_not_present), 0x8000, NULL, HFILL }},
      { &hf_ansi_683_user_zone_id, { "User Zone ID", "ansi_683.user_zone_id", FT_UINT24, BASE_DEC, NULL, 0x7fff80, NULL, HFILL }},
      { &hf_ansi_683_user_zone_sid, { "User Zone SID", "ansi_683.user_zone_sid", FT_UINT16, BASE_DEC, NULL, 0x7fff, NULL, HFILL }},
      { &hf_ansi_683_identifiers_present8, { "Identifiers", "ansi_683.identifiers.present", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x80, NULL, HFILL }},
      { &hf_ansi_683_secure_mode_result_code, { "Secure Mode result code", "ansi_683.secure_mode_result_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(result_codes_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_otasp_mobile_protocol_revision, { "OTASP Mobile Protocol Revision", "ansi_683.otasp_mobile_protocol_revision", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_capability_data, { "Capability Data", "ansi_683.capability_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_system_tag_result_code, { "System Tag result code", "ansi_683.system_tag_result_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(result_codes_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_system_tag_download_result_code, { "System Tag Download result code", "ansi_683.system_tag_download_result_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(result_codes_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_segment_size, { "Segment size", "ansi_683.segment_size", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_service_key_generation_result_code, { "Service Key Generation result code", "ansi_683.service_key_generation_result_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(result_codes_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_result_code, { "Result Code", "ansi_683.result_code", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(result_codes_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_cap_info_record_type, { "Capability Record Type", "ansi_683.cap_info_record_type", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(rev_cap_info_record_type_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_param_block_val, { "Parameter Block Value", "ansi_683.param_block_val", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(for_param_block_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_rev_param_block_sspr, { "Parameter Block SSPR", "ansi_683.param_block_sspr", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(rev_param_block_sspr_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_for_param_block_sspr, { "Parameter Block SSPR", "ansi_683.param_block_sspr", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(for_param_block_sspr_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_rev_param_block_nam, { "NAM Parameter Block Type", "ansi_683.param_block_nam", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(rev_param_block_nam_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_for_param_block_nam, { "NAM Parameter Block Type", "ansi_683.param_block_nam", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(for_param_block_nam_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_rev_param_block_puzl, { "PUZL Parameter Block Type", "ansi_683.param_block_puzl", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(rev_param_block_puzl_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_for_param_block_puzl, { "PUZL Parameter Block Type", "ansi_683.param_block_puzl", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(for_param_block_puzl_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_rev_param_block_3gpd, { "3GPD Parameter Block Type", "ansi_683.param_block_3gpd", FT_UINT8, BASE_DEC, VALS(rev_param_block_3gpd_vals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_for_param_block_3gpd, { "3GPD Parameter Block Type", "ansi_683.param_block_3gpd", FT_UINT8, BASE_DEC, VALS(for_param_block_3gpd_vals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_rev_param_block_mmd, { "MMD Parameter Block Type", "ansi_683.param_block_mmd", FT_UINT8, BASE_DEC, VALS(param_block_mmd_vals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_for_param_block_mmd, { "MMD Parameter Block Type", "ansi_683.param_block_mmd", FT_UINT8, BASE_DEC, VALS(param_block_mmd_vals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_rev_param_block_systag, { "System Tag Parameter Block Type", "ansi_683.param_block_systag", FT_UINT8, BASE_DEC, VALS(rev_param_block_systag_vals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_for_param_block_systag, { "System Tag Parameter Block Type", "ansi_683.param_block_systag", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(for_param_block_systag_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_rev_param_block_mms, { "MMS Parameter Block Type", "ansi_683.param_block_mms", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(rev_param_block_mms_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_for_param_block_mms, { "MMS Parameter Block Type", "ansi_683.param_block_mms", FT_UINT8, BASE_DEC|BASE_RANGE_STRING, RVALS(for_param_block_mms_rvals), 0x0, NULL, HFILL }},
      { &hf_ansi_683_mobile_directory_number, { "Modbile directory number", "ansi_683.mobile_directory_number", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_683_service_programming_code, { "Service programming code", "ansi_683.service_programming_code", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_ansi_683,
        &ett_for_nam_block,
        &ett_rev_nam_block,
        &ett_key_p,
        &ett_key_g,
        &ett_rev_feat,
        &ett_for_val_block,
        &ett_for_sspr_block,
        &ett_band_cap,
        &ett_rev_sspr_block,
        &ett_scm,
        &ett_for_puzl_block,
        &ett_rev_puzl_block,
        &ett_for_3gpd_block,
        &ett_rev_3gpd_block,
        &ett_for_mmd_block,
        &ett_rev_mmd_block,
        &ett_for_mms_block,
        &ett_rev_mms_block,
        &ett_rev_cap,
        &ett_segment,
    };

    static ei_register_info ei[] = {
        { &ei_ansi_683_extraneous_data, { "ansi_683.extraneous_data", PI_PROTOCOL, PI_WARN, "Extraneous Data", EXPFILL }},
        { &ei_ansi_683_short_data, { "ansi_683.short_data", PI_MALFORMED, PI_ERROR, "Short Data (?)", EXPFILL }},
        { &ei_ansi_683_data_length, { "ansi_683.data_length.invalid", PI_PROTOCOL, PI_WARN, "Unexpected Data Length", EXPFILL }},
    };

    expert_module_t* expert_ansi_683;

    /* Register the protocol name and description */
    proto_ansi_683 =
        proto_register_protocol(ansi_proto_name, "ANSI IS-683 (OTA (Mobile))", "ansi_683");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_683, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ansi_683 = expert_register_protocol(proto_ansi_683);
    expert_register_field_array(expert_ansi_683, ei, array_length(ei));
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
