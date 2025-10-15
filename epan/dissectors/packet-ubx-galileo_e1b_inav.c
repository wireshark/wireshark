/* packet-ubx-galileo_e1b_inav.c
 * Dissection of Galileo E1-B I/NAV navigation messages
 * (as provided by UBX-RXM-SFRBX).
 *
 * By Timo Warns <timo.warns@gmail.com>
 * Copyright 2023 Timo Warns
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/tfs.h>
#include <epan/unit_strings.h>
#include <proto.h>
#include <wmem_scopes.h>
#include <wsutil/array.h>
#include <wsutil/pint.h>
#include <wsutil/utf8_entities.h>

#include "packet-ubx.h"
#include "wsutil/wmem/wmem_core.h"

/*
 * Dissects Galileo E1-B I/NAV navigation messages
 * as encoded by UBX (in UBX-RXM-SFRBX messages).
 * Based on Galileo OS SIS ICD Issue 2.1
 */

const value_string DAY_NUMBER[] = {
    {0, "not defined"},
    {1, "Sunday"},
    {2, "Monday"},
    {3, "Tuesday"},
    {4, "Wednesday"},
    {5, "Thursday"},
    {6, "Friday"},
    {7, "Saturday"},
    {0, NULL},
};

static const value_string GAL_OSNMA_NMAS_CODE[] = {
    { 0, "Reserved"},
    { 1, "Test"},
    { 2, "Operational"},
    { 3, "Don't use"},
    { 0, NULL},
};

static const value_string GAL_OSNMA_CPKS_CODE[] = {
    { 0, "Reserved"},
    { 1, "Nominal"},
    { 2, "End of Chain (EOC)"},
    { 3, "Chain Revoked (CREV)"},
    { 4, "New Public Key (NPK)"},
    { 5, "Public Key Revoked (PKREV)"},
    { 6, "New Merkle Tree (NMT)"},
    { 7, "Alert Message (AM)"},
    { 0, NULL},
};

static const value_string GAL_OSNMA_NB_DP_CODE[] = {
    { 0, "Reserved"},
    { 1, "Reserved"},
    { 2, "Reserved"},
    { 3, "Reserved"},
    { 4, "Reserved"},
    { 5, "Reserved"},
    { 6, "Reserved"},
    { 7, "13"},
    { 8, "14"},
    { 9, "15"},
    {10, "16"},
    {11, "Reserved"},
    {12, "Reserved"},
    {13, "Reserved"},
    {14, "Reserved"},
    {15, "Reserved"},
    { 0, NULL},
};

static const value_string GAL_OSNMA_NB_DK_CODE[] = {
    { 0, "Reserved"},
    { 1, "7"},
    { 2, "8"},
    { 3, "9"},
    { 4, "10"},
    { 5, "11"},
    { 6, "12"},
    { 7, "13"},
    { 8, "14"},
    { 9, "Reserved"},
    {10, "Reserved"},
    {11, "Reserved"},
    {12, "Reserved"},
    {13, "Reserved"},
    {14, "Reserved"},
    {15, "Reserved"},
    { 0, NULL},
};

static const value_string GAL_OSNMA_NPKT_CODE[] = {
    { 0, "Reserved"},
    { 1, "ECDSA P-256"},
    { 2, "Reserved"},
    { 3, "ECDSA P-521"},
    { 4, "OSNMA Alert Message (OAM)"},
    { 5, "Reserved"},
    { 6, "Reserved"},
    { 7, "Reserved"},
    { 8, "Reserved"},
    { 9, "Reserved"},
    {10, "Reserved"},
    {11, "Reserved"},
    {12, "Reserved"},
    {13, "Reserved"},
    {14, "Reserved"},
    {15, "Reserved"},
    { 0, NULL},
};

static const value_string GAL_OSNMA_HF_CODE[] = {
    { 0, "SHA-256"},
    { 1, "Reserved"},
    { 2, "SHA3-256"},
    { 3, "Reserved"},
    { 0, NULL},
};

static const value_string GAL_OSNMA_MF_CODE[] = {
    { 0, "HMAC-SHA-256"},
    { 1, "CMAC-AES"},
    { 2, "Reserved"},
    { 3, "Reserved"},
    { 0, NULL},
};

static const value_string GAL_OSNMA_KS_CODE[] = {
    { 0, "96 bits"},
    { 1, "104 bits"},
    { 2, "112 bits"},
    { 3, "120 bits"},
    { 4, "128 bits"},
    { 5, "160 bits"},
    { 6, "192 bits"},
    { 7, "224 bits"},
    { 8, "256 bits"},
    { 9, "Reserved"},
    {10, "Reserved"},
    {11, "Reserved"},
    {12, "Reserved"},
    {13, "Reserved"},
    {14, "Reserved"},
    {15, "Reserved"},
    { 0, NULL},
};
static uint32_t ks2len(uint32_t ks) {
    if (ks <= 4) {
        return 12 + ks;
    }
    else if (ks <= 8) {
        return 20 + (ks-5) * 4;
    }
    else {
        return 0;
    }
}

static const value_string GAL_OSNMA_TS_CODE[] = {
    { 0, "Reserved"},
    { 1, "Reserved"},
    { 2, "Reserved"},
    { 3, "Reserved"},
    { 4, "Reserved"},
    { 5, "20 bits"},
    { 6, "24 bits"},
    { 7, "28 bits"},
    { 8, "32 bits"},
    { 9, "40 bits"},
    {10, "Reserved"},
    {11, "Reserved"},
    {12, "Reserved"},
    {13, "Reserved"},
    {14, "Reserved"},
    {15, "Reserved"},
    { 0, NULL},
};

static const value_string GAL_SAR_SHORT_RLM_MSG_CODE[] = {
    { 0, "Spare"},
    { 1, "Acknowledgement Service"},
    { 2, "Spare"},
    { 3, "Spare"},
    { 4, "Spare"},
    { 5, "Spare"},
    { 6, "Spare"},
    { 7, "Spare"},
    { 8, "Spare"},
    { 9, "Spare"},
    {10, "Spare"},
    {11, "Spare"},
    {12, "Spare"},
    {13, "Spare"},
    {14, "Spare"},
    {15, "Test Service"},
    { 0, NULL},
};

#define CONVERSATION_SAR_RLM 1
#define CONVERSATION_OSNMA_HKROOT 2
#define CONVERSATION_OSNMA_DSM 3

// Initialize the protocol and registered fields
static int proto_ubx_gal_inav;

static int hf_ubx_gal_inav_even_odd;
static int hf_ubx_gal_inav_page_type;
static int hf_ubx_gal_inav_type;
static int hf_ubx_gal_inav_data_122_67;
static int hf_ubx_gal_inav_data_66_17;
static int hf_ubx_gal_inav_data_16_1;

static int hf_ubx_gal_inav_osnma_hkroot;
static int hf_ubx_gal_inav_osnma_mack;
static int hf_ubx_gal_inav_osnma_nmas;
static int hf_ubx_gal_inav_osnma_cid;
static int hf_ubx_gal_inav_osnma_cpks;
static int hf_ubx_gal_inav_osnma_reserved;
static int hf_ubx_gal_inav_osnma_dsm_id;
static int hf_ubx_gal_inav_osnma_dsm_blk_id;
static int hf_ubx_gal_inav_osnma_dsm_blk;
static int hf_ubx_gal_inav_osnma_dsm_nb_dk;
static int hf_ubx_gal_inav_osnma_dsm_pkid;
static int hf_ubx_gal_inav_osnma_dsm_cidkr;
static int hf_ubx_gal_inav_osnma_dsm_reserved1;
static int hf_ubx_gal_inav_osnma_dsm_hf;
static int hf_ubx_gal_inav_osnma_dsm_mf;
static int hf_ubx_gal_inav_osnma_dsm_ks;
static int hf_ubx_gal_inav_osnma_dsm_ts;
static int hf_ubx_gal_inav_osnma_dsm_maclt;
static int hf_ubx_gal_inav_osnma_dsm_reserved2;
static int hf_ubx_gal_inav_osnma_dsm_wn_k;
static int hf_ubx_gal_inav_osnma_dsm_towh_k;
static int hf_ubx_gal_inav_osnma_dsm_alpha;
static int hf_ubx_gal_inav_osnma_dsm_kroot;
static int hf_ubx_gal_inav_osnma_dsm_ds;
static int hf_ubx_gal_inav_osnma_dsm_p_dk;
static int hf_ubx_gal_inav_osnma_dsm_nb_dp;
static int hf_ubx_gal_inav_osnma_dsm_mid;
static int hf_ubx_gal_inav_osnma_dsm_x_0_0;
static int hf_ubx_gal_inav_osnma_dsm_x_0_1;
static int hf_ubx_gal_inav_osnma_dsm_x_0_2;
static int hf_ubx_gal_inav_osnma_dsm_x_0_3;
static int hf_ubx_gal_inav_osnma_dsm_x_0_4;
static int hf_ubx_gal_inav_osnma_dsm_x_0_5;
static int hf_ubx_gal_inav_osnma_dsm_x_0_6;
static int hf_ubx_gal_inav_osnma_dsm_x_0_7;
static int hf_ubx_gal_inav_osnma_dsm_x_0_8;
static int hf_ubx_gal_inav_osnma_dsm_x_0_9;
static int hf_ubx_gal_inav_osnma_dsm_x_0_10;
static int hf_ubx_gal_inav_osnma_dsm_x_0_11;
static int hf_ubx_gal_inav_osnma_dsm_x_0_12;
static int hf_ubx_gal_inav_osnma_dsm_x_0_13;
static int hf_ubx_gal_inav_osnma_dsm_x_0_14;
static int hf_ubx_gal_inav_osnma_dsm_x_0_15;
static int hf_ubx_gal_inav_osnma_dsm_x_1_0;
static int hf_ubx_gal_inav_osnma_dsm_x_1_1;
static int hf_ubx_gal_inav_osnma_dsm_x_1_2;
static int hf_ubx_gal_inav_osnma_dsm_x_1_3;
static int hf_ubx_gal_inav_osnma_dsm_x_1_4;
static int hf_ubx_gal_inav_osnma_dsm_x_1_5;
static int hf_ubx_gal_inav_osnma_dsm_x_1_6;
static int hf_ubx_gal_inav_osnma_dsm_x_1_7;
static int hf_ubx_gal_inav_osnma_dsm_x_2_0;
static int hf_ubx_gal_inav_osnma_dsm_x_2_1;
static int hf_ubx_gal_inav_osnma_dsm_x_2_2;
static int hf_ubx_gal_inav_osnma_dsm_x_2_3;
static int hf_ubx_gal_inav_osnma_dsm_x_3_0;
static int hf_ubx_gal_inav_osnma_dsm_x_3_1;
static int hf_ubx_gal_inav_osnma_dsm_npkt;
static int hf_ubx_gal_inav_osnma_dsm_npkid;
static int hf_ubx_gal_inav_osnma_dsm_npk;
static int hf_ubx_gal_inav_osnma_dsm_p_dp;

static int hf_ubx_gal_inav_sar_start_bit;
static int hf_ubx_gal_inav_sar_long_rlm;
static int hf_ubx_gal_inav_sar_rlm_data;
static int hf_ubx_gal_inav_sar_beacon_id;
static int hf_ubx_gal_inav_sar_msg_code;

static int hf_ubx_gal_inav_spare;
static int hf_ubx_gal_inav_ssp;
static int hf_ubx_gal_inav_crc;
static int hf_ubx_gal_inav_tail;
static int hf_ubx_gal_inav_pad;
static int hf_ubx_gal_inav_reserved_1;

static int hf_ubx_gal_inav_word_type;

static int hf_ubx_gal_inav_word0;
static int hf_ubx_gal_inav_word0_time;
static int hf_ubx_gal_inav_word0_spare;
static int hf_ubx_gal_inav_word0_wn;
static int hf_ubx_gal_inav_word0_tow;

static int hf_ubx_gal_inav_word1;
static int hf_ubx_gal_inav_word1_iodnav;
static int hf_ubx_gal_inav_word1_t0e;
static int hf_ubx_gal_inav_word1_m0;
static int hf_ubx_gal_inav_word1_e;
static int hf_ubx_gal_inav_word1_sqrta;
static int hf_ubx_gal_inav_word1_reserved;

static int hf_ubx_gal_inav_word2;
static int hf_ubx_gal_inav_word2_iodnav;
static int hf_ubx_gal_inav_word2_omega0;
static int hf_ubx_gal_inav_word2_i0;
static int hf_ubx_gal_inav_word2_omega;
static int hf_ubx_gal_inav_word2_incl_angle_rate;
static int hf_ubx_gal_inav_word2_reserved;

static int hf_ubx_gal_inav_word3;
static int hf_ubx_gal_inav_word3_iodnav;
static int hf_ubx_gal_inav_word3_omega_rate;
static int hf_ubx_gal_inav_word3_delta_n;
static int hf_ubx_gal_inav_word3_c_uc;
static int hf_ubx_gal_inav_word3_c_us;
static int hf_ubx_gal_inav_word3_c_rc;
static int hf_ubx_gal_inav_word3_c_rs;
static int hf_ubx_gal_inav_word3_sisa_e1_e5b;

static int hf_ubx_gal_inav_word4;
static int hf_ubx_gal_inav_word4_iodnav;
static int hf_ubx_gal_inav_word4_svid;
static int hf_ubx_gal_inav_word4_c_ic;
static int hf_ubx_gal_inav_word4_c_is;
static int hf_ubx_gal_inav_word4_t_0c;
static int hf_ubx_gal_inav_word4_a_f0;
static int hf_ubx_gal_inav_word4_a_f1;
static int hf_ubx_gal_inav_word4_a_f2;
static int hf_ubx_gal_inav_word4_spare;

static int hf_ubx_gal_inav_word6;
static int hf_ubx_gal_inav_word6_a0;
static int hf_ubx_gal_inav_word6_a1;
static int hf_ubx_gal_inav_word6_delta_t_ls;
static int hf_ubx_gal_inav_word6_t_0t;
static int hf_ubx_gal_inav_word6_wn_0t;
static int hf_ubx_gal_inav_word6_wn_lsf;
static int hf_ubx_gal_inav_word6_dn;
static int hf_ubx_gal_inav_word6_delta_t_lsf;
static int hf_ubx_gal_inav_word6_tow;
static int hf_ubx_gal_inav_word6_spare;

static dissector_table_t ubx_gal_inav_word_dissector_table;

static int ett_ubx_gal_inav;
static int ett_ubx_gal_inav_word0;
static int ett_ubx_gal_inav_word1;
static int ett_ubx_gal_inav_word2;
static int ett_ubx_gal_inav_word3;
static int ett_ubx_gal_inav_word4;
static int ett_ubx_gal_inav_word6;
static int ett_ubx_gal_inav_osnma;
static int ett_ubx_gal_inav_osnma_hkroot_msg;
static int ett_ubx_gal_inav_osnma_dsm;
static int ett_ubx_gal_inav_sar;
static int ett_ubx_gal_inav_sar_rlm;

static const value_string GAL_PAGE_TYPE[] = {
    {0, "nominal"},
    {1, "alert"},
    {0, NULL},
};

static const value_string GAL_SSP[] = {
    {0x04, "SSP 1"},
    {0x2b, "SSP 2"},
    {0x2f, "SSP 3"},
    {0, NULL},
};

#define OSNMA_HKROOT_MSG_PARTS_NUM 15
#define OSNMA_HKROOT_MSG_LENGTH OSNMA_HKROOT_MSG_PARTS_NUM * 8 / 8

typedef struct osnma_hkroot_msg_part {
    uint32_t frame;
    uint8_t hkroot;
} osnma_hkroot_msg_part;

#define OSNMA_DSM_BLK_LENGTH 13
#define OSNMA_DSM_BLK_NUM 15

typedef struct osnma_dsm_blk {
    bool set;
    uint8_t blk[OSNMA_DSM_BLK_LENGTH];
} osnma_dsm_blk;

#define SAR_LONG_RLM_PARTS_NUM 8
#define SAR_LONG_RLM_LENGTH (SAR_LONG_RLM_PARTS_NUM * 20 / 8)
#define SAR_SHORT_RLM_PARTS_NUM 4
#define SAR_SHORT_RLM_LENGTH (SAR_SHORT_RLM_PARTS_NUM * 20 / 8)

typedef struct sar_rlm_part {
    uint32_t frame;
    bool long_rlm;
    uint32_t rlm_data;
} sar_rlm_part;

/* Format A_0 for GST-UTC Conversion with 2^-30s resolution */
void fmt_a0(char *label, int64_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%" PRId64 " * 2^-30s", c);
}

/* Format A_1 for GST-UTC Conversion with 2^-50s/s resolution */
void fmt_a1(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-50s/s", c);
}

/* Format t_0t for GST-UTC Conversion with 3600s resolution */
static void fmt_t_0t(char *label, uint32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%us", c * 3600);
}

/* Format clock correction (with scale factor 60) for
 * t_0c
 */
static void fmt_clk_correction(char *label, uint32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%u s", 60 * c);
}

/* Format radians (with 2^-29 scale factor) for
 * amplitude of harmonic correction terms
 */
void fmt_lat_correction(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-29 radians", c);
}

/* Format meters (with 2^-5 scale factor) for
 * amplitude of orbit correction terms
 */
static void fmt_orbit_correction(char *label, int16_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-5 m", c);
}

/* Format semi-circles (with 2^-31 scale factor) for
 * - mean anomaly at reference time
 * - longitude of ascending node of orbital plane at weekly epoch
 * - inclination angle at reference time
 * - argument of perigee
 */
static void fmt_semi_circles(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-31 semi-circles", c);
}

/* Format rate of semi-circles (with 2^-43 scale factor) for
 * - inclination angle
 * - right ascension
 * - mean motion difference
 */
void fmt_semi_circles_rate(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-43 semi-circles/s", c);
}

/* Format SISA */
static void fmt_sisa(char *label, uint8_t i) {
    if (i <= 49) {
        // 0 cm to 49 cm with 1 cm resolution
        snprintf(label, ITEM_LABEL_LENGTH, "%u cm", i);
    }
    else if (i <= 74) {
        // 50 cm to 98 cm with 2 cm resolution
        snprintf(label, ITEM_LABEL_LENGTH, "%u cm", 50 + ((i - 50) * 2));
    }
    else if (i <= 99) {
        // 100 cm to 196 cm with 4 cm resolution
        snprintf(label, ITEM_LABEL_LENGTH, "%u cm", 100 + ((i - 75) * 4));
    }
    else if (i <= 125) {
        // 200 cm to 600 cm with 16 cm resolution
        snprintf(label, ITEM_LABEL_LENGTH, "%u cm", 200 + ((i - 100) * 16));
    }
    else if (i <= 254) {
        // Spare
        snprintf(label, ITEM_LABEL_LENGTH, "Spare");
    }
    else { // i == 255
        snprintf(label, ITEM_LABEL_LENGTH, "No Accuracy Prediction Available (NAPA)");
    }
}

/* Format SV clock bias (with 2^-34 scale factor) for
 * a_f0
 */
static void fmt_sv_clk_bias(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-34 s", c);
}

/* Format SV clock drift (with 2^-46 scale factor) for
 * a_f1
 */
static void fmt_sv_clk_drift(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-46 s/s", c);
}

/* Format SV clock drift rate (with 2^-59 scale factor) for
 * a_f1
 */
static void fmt_sv_clk_drift_rate(char *label, int32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%d * 2^-59 s/s" UTF8_SUPERSCRIPT_TWO, c);
}

/* Format eccentricity */
static void fmt_e(char *label, uint64_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%" PRIu64 " * 2^-33", c);
}

/* Format square root of the semi-major axis */
static void fmt_sqrt_a(char *label, uint64_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%" PRIu64 " * 2^-19 " UTF8_SQUARE_ROOT "m", c);
}

/* Format ephemeris reference time */
static void fmt_t0e(char *label, uint32_t c) {
    c = c * 60;
    snprintf(label, ITEM_LABEL_LENGTH, "%ds", c);
}

/* Dissect Galileo E1-B I/NAV navigation message */
static int dissect_ubx_gal_inav(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    tvbuff_t *next_tvb;

    bool complete_hkroot = false;
    bool sar_start, sar_long_rlm;
    uint32_t inav_type = 0, even_page_type, odd_page_type, hkroot, sar_rlm_data;
    uint32_t dsm_id, dsm_blk_id, dsm_ks;
    uint64_t data_122_67 = 0, data_66_17 = 0, data_16_1 = 0;
    uint8_t *word, *hkroot_msg, *dsm_buf;
    osnma_hkroot_msg_part *osnma_hkroot_msg_parts = NULL;
    osnma_dsm_blk *osnma_dsm_blks = NULL;
    sar_rlm_part *sar_rlm_parts = NULL;
    int i;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Galileo E1-B I/NAV");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_tree *gal_inav_tree = proto_tree_add_subtree(tree, tvb, 0, 32, ett_ubx_gal_inav, NULL, "Galileo E1-B I/NAV");

    // even page
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_even_odd, tvb, 0, 1, ENC_NA);
    proto_tree_add_item_ret_uint(gal_inav_tree, hf_ubx_gal_inav_page_type, tvb, 0, 1, ENC_NA, &even_page_type);

    if (even_page_type == 1) { // alert page
        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_reserved_1,  tvb, 0, 15, ENC_NA);
    }
    else if (even_page_type == 0) { // nominal page
        proto_tree_add_item_ret_uint(gal_inav_tree,   hf_ubx_gal_inav_type,        tvb, 0,  1, ENC_NA,         &inav_type);
        proto_tree_add_item_ret_uint64(gal_inav_tree, hf_ubx_gal_inav_data_122_67, tvb, 0,  8, ENC_BIG_ENDIAN, &data_122_67);
        proto_tree_add_item_ret_uint64(gal_inav_tree, hf_ubx_gal_inav_data_66_17,  tvb, 8,  8, ENC_BIG_ENDIAN, &data_66_17);
    }

    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_tail,            tvb, 14, 1, ENC_NA);
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_pad,             tvb, 15, 1, ENC_NA);


    // odd page
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_even_odd, tvb, 16, 1, ENC_NA);
    proto_tree_add_item_ret_uint(gal_inav_tree, hf_ubx_gal_inav_page_type, tvb, 16, 1, ENC_NA, &odd_page_type);

    if (odd_page_type == 1) { // alert page
        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_reserved_1,  tvb, 16, 11, ENC_NA);
    }
    else if (odd_page_type == 0) { // nominal page
        uint8_t *svid = (uint8_t *) data;

        proto_tree_add_item_ret_uint64(gal_inav_tree, hf_ubx_gal_inav_data_16_1,   tvb, 16, 8, ENC_BIG_ENDIAN, &data_16_1);

        proto_tree *osnma_tree = proto_tree_add_subtree(gal_inav_tree, tvb, 18, 6, ett_ubx_gal_inav_osnma, NULL, "OSNMA");
        proto_tree_add_item_ret_uint(osnma_tree, hf_ubx_gal_inav_osnma_hkroot,  tvb, 18, 4, ENC_BIG_ENDIAN, &hkroot);
        proto_tree_add_item(osnma_tree, hf_ubx_gal_inav_osnma_mack,             tvb, 18, 8, ENC_BIG_ENDIAN);

        // manage OSNMA HKROOT message via conversations
        if (svid != NULL && even_page_type == 0) {
            // try to find already existing conversation
            conversation_element_t constellation = {.type = CE_INT, .int_val = GNSS_ID_GALILEO};
            conversation_element_t type = {.type = CE_INT, .int_val = CONVERSATION_OSNMA_HKROOT};
            conversation_element_t prn = {.type = CE_INT, .int_val = *svid};
            conversation_element_t end = {.type = CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_GNSS};
            conversation_element_t ce[4] = {constellation, type, prn, end};
            conversation_t *c = find_conversation_full(pinfo->num, ce);

            if (c == NULL && inav_type == 2) {
                // No conversation found, but the current Word Type is 2.
                // As Word Type 2 nominally starts a sub-frame, start a new conversation.
                // TODO: Detect a new sub-frame based on GST (or, at least, cross-check against GST).
                c = conversation_new_full(pinfo->num, ce);

                osnma_hkroot_msg_parts = (osnma_hkroot_msg_part *) wmem_alloc0_array(wmem_file_scope(), osnma_hkroot_msg_part, OSNMA_HKROOT_MSG_PARTS_NUM);

                osnma_hkroot_msg_parts[0].frame = pinfo->num;
                osnma_hkroot_msg_parts[0].hkroot = hkroot;

                conversation_add_proto_data(c, proto_ubx_gal_inav, osnma_hkroot_msg_parts);
            }
            else if (c != NULL && inav_type == 2) {
                // Check whether the conversation found starts at the current frame.
                // (If not, a new conversation needs to be created as the Word Type is 2, which nominally indicates a new sub-frame.)
                // TODO: Detect a new sub-frame based on GST (or, at least, cross-check against GST).
                osnma_hkroot_msg_parts = (osnma_hkroot_msg_part *) conversation_get_proto_data(c, proto_ubx_gal_inav);

                if (osnma_hkroot_msg_parts != NULL && osnma_hkroot_msg_parts[0].frame != pinfo->num) {
                    // Separate conversation found, start a new one.
                    c = conversation_new_full(pinfo->num, ce);

                    osnma_hkroot_msg_parts = (osnma_hkroot_msg_part *) wmem_alloc0_array(wmem_file_scope(), osnma_hkroot_msg_part, OSNMA_HKROOT_MSG_PARTS_NUM);

                    osnma_hkroot_msg_parts[0].frame = pinfo->num;
                    osnma_hkroot_msg_parts[0].hkroot = hkroot;

                    conversation_add_proto_data(c, proto_ubx_gal_inav, osnma_hkroot_msg_parts);
                }
            }
            else if (c != NULL) {
                // Check whether packet data still needs to be added to the conversation.
                osnma_hkroot_msg_parts = (osnma_hkroot_msg_part *) conversation_get_proto_data(c, proto_ubx_gal_inav);

                if (osnma_hkroot_msg_parts) {
                    // TODO: Detecting the slot of the HKROOT part should be based on GST.
                    // TODO: Cross-check whether identified slot matches nominal Word Type schedule.
                    for (i = 0; i < OSNMA_HKROOT_MSG_PARTS_NUM; i++) {
                        if (osnma_hkroot_msg_parts[i].frame == 0) {
                            osnma_hkroot_msg_parts[i].frame = pinfo->num;
                            osnma_hkroot_msg_parts[i].hkroot = hkroot;
                            break;
                        }
                        else if (osnma_hkroot_msg_parts[i].frame == pinfo->num) {
                            break;
                        }
                    }
                }
            }

            // display OSNMA HKROOT message if all parts are available
            if (c != NULL && osnma_hkroot_msg_parts != NULL) {
                for (i = 0; i < OSNMA_HKROOT_MSG_PARTS_NUM; i++) {
                    if (osnma_hkroot_msg_parts[i].frame == 0) {
                        break;
                    }
                }

                if (i == OSNMA_HKROOT_MSG_PARTS_NUM) {
                    // All parts of an OSNMA HKROOT message are available in the conversation.
                    complete_hkroot = true;

                    // Now dissect it.

                    // reserve buffer for OSNMA HKROOT message
                    hkroot_msg = wmem_alloc(pinfo->pool, OSNMA_HKROOT_MSG_LENGTH);

                    // fill buffer with OSNMA HKROOT parts
                    for (i = 0; i < OSNMA_HKROOT_MSG_PARTS_NUM; i++) {
                        hkroot_msg[i] = osnma_hkroot_msg_parts[i].hkroot;
                    }

                    tvbuff_t *osnma_hkroot_msg_tvb = tvb_new_child_real_data(tvb, (uint8_t *)hkroot_msg, OSNMA_HKROOT_MSG_LENGTH, OSNMA_HKROOT_MSG_LENGTH);
                    add_new_data_source(pinfo, osnma_hkroot_msg_tvb, "Galileo E1-B I/NAV OSNMA HKROOT Message");

                    // dissect OSNMA HKROOT message
                    proto_tree *osnma_hkroot_msg_tree = proto_tree_add_subtree(osnma_tree, osnma_hkroot_msg_tvb, 0, OSNMA_HKROOT_MSG_LENGTH, ett_ubx_gal_inav_osnma_hkroot_msg, NULL, "HKROOT Message (re-assembled)");

                    proto_tree_add_item(osnma_hkroot_msg_tree, hf_ubx_gal_inav_osnma_nmas,                osnma_hkroot_msg_tvb, 0, 1,  ENC_NA);
                    proto_tree_add_item(osnma_hkroot_msg_tree, hf_ubx_gal_inav_osnma_cid,                 osnma_hkroot_msg_tvb, 0, 1,  ENC_NA);
                    proto_tree_add_item(osnma_hkroot_msg_tree, hf_ubx_gal_inav_osnma_cpks,                osnma_hkroot_msg_tvb, 0, 1,  ENC_NA);
                    proto_tree_add_item(osnma_hkroot_msg_tree, hf_ubx_gal_inav_osnma_reserved,            osnma_hkroot_msg_tvb, 0, 1,  ENC_NA);
                    proto_tree_add_item_ret_uint(osnma_hkroot_msg_tree, hf_ubx_gal_inav_osnma_dsm_id,     osnma_hkroot_msg_tvb, 1, 1,  ENC_NA, &dsm_id);
                    proto_tree_add_item_ret_uint(osnma_hkroot_msg_tree, hf_ubx_gal_inav_osnma_dsm_blk_id, osnma_hkroot_msg_tvb, 1, 1,  ENC_NA, &dsm_blk_id);
                    proto_tree_add_item(osnma_hkroot_msg_tree, hf_ubx_gal_inav_osnma_dsm_blk,             osnma_hkroot_msg_tvb, 2, 13, ENC_NA);

                }
            }
        }

        // manage OSNMA DSM via conversations (if a HKROOT message was re-assembled)
        if (complete_hkroot) {
            // try to find already existing conversation
            conversation_element_t constellation = {.type = CE_INT, .int_val = GNSS_ID_GALILEO};
            conversation_element_t type = {.type = CE_INT, .int_val = CONVERSATION_OSNMA_DSM};
            conversation_element_t dsm = {.type = CE_INT, .int_val = dsm_id};
            conversation_element_t end = {.type = CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_GNSS};
            conversation_element_t ce[4] = {constellation, type, dsm, end};
            conversation_t *c = find_conversation_full(pinfo->num, ce);

            // TODO: Add logic to detect and manage DSM ID roll-over
            if (c == NULL) {
                // No conversation found. Start a new one.
                c = conversation_new_full(pinfo->num, ce);

                osnma_dsm_blks = (osnma_dsm_blk *) wmem_alloc0_array(wmem_file_scope(), osnma_dsm_blk, OSNMA_DSM_BLK_NUM);

                conversation_add_proto_data(c, proto_ubx_gal_inav, osnma_dsm_blks);
            }
            else {
                osnma_dsm_blks = (osnma_dsm_blk *) conversation_get_proto_data(c, proto_ubx_gal_inav);
            }

            if (osnma_dsm_blks != NULL) {

                // store block
                osnma_dsm_blks[dsm_blk_id].set = true;
                memcpy(osnma_dsm_blks[dsm_blk_id].blk, &hkroot_msg[2], OSNMA_DSM_BLK_LENGTH);

                // If first block of a DSM has been received, continue processing.
                if (osnma_dsm_blks[0].set && 0 < osnma_dsm_blks[0].blk[0]) {

                    // Count the number of sequential blocks received.
                    uint8_t dsm_blk_count = 0;
                    for (i = 0; i < OSNMA_DSM_BLK_NUM; i++) {
                        if (osnma_dsm_blks[i].set) {
                            dsm_blk_count++;
                        }
                        else {
                            break;
                        }
                    }

                    // Compare number of received blocks against NB_DP / NB_DK in block 0.
                    if (dsm_blk_count == (osnma_dsm_blks[0].blk[0] >> 4) + 6) {
                        // All blocks for a DSM have been received.
                        // Now dissect it.

                        dsm_buf = wmem_alloc(pinfo->pool, dsm_blk_count * OSNMA_DSM_BLK_LENGTH);
                        for (i = 0; i < dsm_blk_count; i++) {
                            memcpy(&dsm_buf[i * OSNMA_DSM_BLK_LENGTH], osnma_dsm_blks[i].blk, OSNMA_DSM_BLK_LENGTH);
                        }
                        tvbuff_t *osnma_dsm_tvb = tvb_new_child_real_data(tvb, (uint8_t *)dsm_buf, dsm_blk_count * OSNMA_DSM_BLK_LENGTH, dsm_blk_count * OSNMA_DSM_BLK_LENGTH);
                        add_new_data_source(pinfo, osnma_dsm_tvb, "Galileo E1-B I/NAV OSNMA DSM");


                        if (dsm_id < 12) {
                            // dissect DSM-KROOT
                            uint32_t dk_len = dsm_blk_count * OSNMA_DSM_BLK_LENGTH;

                            proto_tree *osnma_dsm_tree = proto_tree_add_subtree(osnma_tree, osnma_dsm_tvb, 0, dk_len, ett_ubx_gal_inav_osnma_dsm, NULL, "DSM-KROOT (re-assembled)");
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_nb_dk,     osnma_dsm_tvb,  0,  1, ENC_NA);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_pkid,      osnma_dsm_tvb,  0,  1, ENC_NA);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_cidkr,     osnma_dsm_tvb,  1,  1, ENC_NA);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_reserved1, osnma_dsm_tvb,  1,  1, ENC_NA);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_hf,        osnma_dsm_tvb,  1,  1, ENC_NA);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_mf,        osnma_dsm_tvb,  1,  1, ENC_NA);
                            proto_tree_add_item_ret_uint(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_ks, osnma_dsm_tvb, 2, 1, ENC_NA, &dsm_ks);
                            uint32_t ks_len = ks2len(dsm_ks);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_ts,        osnma_dsm_tvb,  2,  1, ENC_NA);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_maclt,     osnma_dsm_tvb,  3,  1, ENC_NA);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_reserved2, osnma_dsm_tvb,  4,  1, ENC_NA);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_wn_k,      osnma_dsm_tvb,  4,  2, ENC_BIG_ENDIAN);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_towh_k,    osnma_dsm_tvb,  6,  1, ENC_NA);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_alpha,     osnma_dsm_tvb,  7,  6, ENC_NA);
                            if (ks_len > 0) {
                                // TODO: The length of the digital signature should be derived from the DSM-PKR NPKT with matching PKID.
                                uint32_t ds_len = 64;
                                uint32_t p_dk_len = dk_len - 13 - ks_len - ds_len;

                                proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_kroot, osnma_dsm_tvb, 13,                   ks_len,   ENC_NA);
                                proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_ds,    osnma_dsm_tvb, 13 + ks_len,          ds_len,   ENC_NA);
                                proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_p_dk,  osnma_dsm_tvb, 13 + ks_len + ds_len, p_dk_len, ENC_NA);
                            }
                        }
                        else {
                            // dissect DSM-PKR
                            uint32_t dsm_nb_dp, dsm_mid, dsm_npkt, l_npk, l_pdp;

                            proto_tree *osnma_dsm_tree = proto_tree_add_subtree(osnma_tree, osnma_dsm_tvb, 0, dsm_blk_count * OSNMA_DSM_BLK_LENGTH, ett_ubx_gal_inav_osnma_dsm, NULL, "DSM-PKR (re-assembled)");
                            proto_tree_add_item_ret_uint(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_nb_dp, osnma_dsm_tvb, 0, 1, ENC_NA, &dsm_nb_dp);
                            proto_tree_add_item_ret_uint(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_mid,   osnma_dsm_tvb, 0, 1, ENC_NA, &dsm_mid);

                            switch (dsm_mid) {
                                case 0:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_1,  osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_1,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_1,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_1,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 1:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_0,  osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_1,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_1,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_1,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 2:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_3,  osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_0,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_1,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_1,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 3:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_2,  osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_0,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_1,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_1,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 4:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_5,  osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_3,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_0,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_1,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 5:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_4,  osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_3,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_0,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_1,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 6:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_7,  osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_2,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_0,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_1,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 7:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_6,  osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_2,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_0,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_1,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 8:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_9,  osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_5,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_3,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_0,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 9:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_8,  osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_5,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_3,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_0,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 10:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_11, osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_4,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_3,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_0,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 11:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_10, osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_4,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_3,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_0,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 12:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_13, osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_7,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_2,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_0,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 13:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_12, osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_7,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_2,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_0,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 14:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_15, osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_6,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_2,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_0,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                case 15:
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_0_14, osnma_dsm_tvb,  1, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_1_6,  osnma_dsm_tvb, 33, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_2_2,  osnma_dsm_tvb, 65, 32, ENC_NA);
                                    proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_x_3_0,  osnma_dsm_tvb, 97, 32, ENC_NA);
                                    break;
                                default:
                                    break;
                            }

                            proto_tree_add_item_ret_uint(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_npkt,  osnma_dsm_tvb, 129, 1, ENC_NA, &dsm_npkt);
                            proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_npkid, osnma_dsm_tvb, 129, 1, ENC_NA);

                            // compute field lengths
                            if (7 <= dsm_nb_dp && dsm_nb_dp <= 10 && (dsm_npkt == 1 || dsm_npkt == 3 || dsm_npkt == 4)) {
                                if (dsm_npkt == 1) { // ECDSA P-256
                                    l_npk = 264;
                                }
                                else if (dsm_npkt == 4) { // ECDSA P-521
                                    l_npk = 536;
                                }
                                else { // OSNMA Alert Message
                                    l_npk = ((dsm_nb_dp + 6) * 104) - 1040; // = l_PK_OAM
                                }

                                l_pdp = ((dsm_nb_dp + 6) * 104) - 1040 - l_npk;

                                proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_npk,  osnma_dsm_tvb, 130,               l_npk / 8, ENC_NA);
                                proto_tree_add_item(osnma_dsm_tree, hf_ubx_gal_inav_osnma_dsm_p_dp, osnma_dsm_tvb, 130 + (l_npk / 8), l_pdp / 8, ENC_NA);
                            }
                        }
                    }
                }
            }
        }

        proto_tree *sar_tree = proto_tree_add_subtree(gal_inav_tree, tvb, 23, 4, ett_ubx_gal_inav_sar, NULL, "SAR");
        proto_tree_add_item_ret_boolean(sar_tree, hf_ubx_gal_inav_sar_start_bit, tvb, 23, 4, ENC_BIG_ENDIAN, &sar_start);
        proto_tree_add_item_ret_boolean(sar_tree, hf_ubx_gal_inav_sar_long_rlm,  tvb, 23, 4, ENC_BIG_ENDIAN, &sar_long_rlm);
        proto_tree_add_item_ret_uint(sar_tree, hf_ubx_gal_inav_sar_rlm_data,     tvb, 23, 4, ENC_BIG_ENDIAN, &sar_rlm_data);

        // manage SAR RLM parts via conversations
        if (svid != NULL) {

            // try to find already existing conversation
            conversation_element_t constellation = {.type = CE_INT, .int_val = GNSS_ID_GALILEO};
            conversation_element_t type = {.type = CE_INT, .int_val = CONVERSATION_SAR_RLM};
            conversation_element_t prn = {.type = CE_INT, .int_val = *svid};
            conversation_element_t end = {.type = CE_CONVERSATION_TYPE, .conversation_type_val = CONVERSATION_GNSS};
            conversation_element_t ce[4] = {constellation, type, prn, end};
            conversation_t *c = find_conversation_full(pinfo->num, ce);

            if (c == NULL && sar_start) {
                // No conversation found. As the start bit is set, start a new one.
                c = conversation_new_full(pinfo->num, ce);

                sar_rlm_parts = (sar_rlm_part *) wmem_alloc0_array(wmem_file_scope(), sar_rlm_part, sar_long_rlm ? SAR_LONG_RLM_PARTS_NUM : SAR_SHORT_RLM_PARTS_NUM);

                sar_rlm_parts[0].frame = pinfo->num;
                sar_rlm_parts[0].long_rlm = sar_long_rlm;
                sar_rlm_parts[0].rlm_data = sar_rlm_data;

                conversation_add_proto_data(c, proto_ubx_gal_inav, sar_rlm_parts);
            }
            else if (c != NULL && sar_start) {
                // Check whether the conversation found starts at the
                // current frame. (If not, a new conversation needs to be
                // created as the start bit is set.
                sar_rlm_parts = (sar_rlm_part *) conversation_get_proto_data(c, proto_ubx_gal_inav);

                if (sar_rlm_parts != NULL && sar_rlm_parts[0].frame != pinfo->num) {
                    // Separate conversation found, start a new one.
                    c = conversation_new_full(pinfo->num, ce);

                    sar_rlm_parts = (sar_rlm_part *) wmem_alloc0_array(wmem_file_scope(), sar_rlm_part, sar_long_rlm ? SAR_LONG_RLM_PARTS_NUM : SAR_SHORT_RLM_PARTS_NUM);

                    sar_rlm_parts[0].frame = pinfo->num;
                    sar_rlm_parts[0].long_rlm = sar_long_rlm;
                    sar_rlm_parts[0].rlm_data = sar_rlm_data;

                    conversation_add_proto_data(c, proto_ubx_gal_inav, sar_rlm_parts);
                }

            }
            else if (c != NULL) {
                // Check whether packet data still needs to be added to the conversation.
                sar_rlm_parts = (sar_rlm_part *) conversation_get_proto_data(c, proto_ubx_gal_inav);

                if (sar_rlm_parts != NULL && sar_rlm_parts[0].long_rlm == sar_long_rlm) {
                    for (i = 0; i < (sar_long_rlm ? SAR_LONG_RLM_PARTS_NUM : SAR_SHORT_RLM_PARTS_NUM); i++) {
                        if (sar_rlm_parts[i].frame == 0) {
                            sar_rlm_parts[i].frame = pinfo->num;
                            sar_rlm_parts[i].long_rlm = sar_long_rlm;
                            sar_rlm_parts[i].rlm_data = sar_rlm_data;
                            break;
                        }
                        else if (sar_rlm_parts[i].frame == pinfo->num) {
                            break;
                        }
                    }
                }
            }

            // display SAR RLM if all parts are available
            if (c != NULL && sar_rlm_parts != NULL) {
                for (i = 0; i < (sar_long_rlm ? SAR_LONG_RLM_PARTS_NUM : SAR_SHORT_RLM_PARTS_NUM); i++) {
                    if (sar_rlm_parts[i].frame == 0) {
                        break;
                    }
                }

                if (!sar_long_rlm && i == SAR_SHORT_RLM_PARTS_NUM) {
                    // All parts of a Short-RLM are available in the conversation.
                    // Now dissect it.

                    // reserve buffer for short RLM
                    uint8_t *buf = wmem_alloc(pinfo->pool, SAR_SHORT_RLM_LENGTH);

                    // fill buffer with RLM parts
                    phtonu32(buf, (sar_rlm_parts[0].rlm_data << 12) | (sar_rlm_parts[1].rlm_data >> 8));
                    phtonu32(buf + 4, (sar_rlm_parts[1].rlm_data << 24) | (sar_rlm_parts[2].rlm_data << 4) | (sar_rlm_parts[3].rlm_data >> 16));
                    phtonu16(buf + 8, (sar_rlm_parts[3].rlm_data & 0xffff));

                    tvbuff_t *rlm_tvb = tvb_new_child_real_data(tvb, (uint8_t *)buf, SAR_SHORT_RLM_LENGTH, SAR_SHORT_RLM_LENGTH);
                    add_new_data_source(pinfo, rlm_tvb, "Galileo E1-B I/NAV SAR Short-RLM");

                    // dissect RLM
                    proto_tree *sar_rlm_tree = proto_tree_add_subtree(sar_tree, rlm_tvb, 0, SAR_SHORT_RLM_LENGTH, ett_ubx_gal_inav_sar_rlm, NULL, "Short-RLM (re-assembled)");

                    proto_tree_add_item(sar_rlm_tree, hf_ubx_gal_inav_sar_beacon_id, rlm_tvb, 0, 8, ENC_BIG_ENDIAN);
                    proto_tree_add_item(sar_rlm_tree, hf_ubx_gal_inav_sar_msg_code,  rlm_tvb, 6, 4, ENC_BIG_ENDIAN);
                }
                else if (sar_long_rlm && i == SAR_LONG_RLM_PARTS_NUM) {
                    // All parts of a Long-RLM are available in the conversation.
                    // TODO: Now dissect it.
                }
            }
        }

        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_spare,       tvb, 26, 1, ENC_NA);
    }

    // TODO: check CRC
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_crc,           tvb, 26, 4, ENC_BIG_ENDIAN);

    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_ssp,           tvb, 28, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_tail,          tvb, 30, 1, ENC_NA);
    proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_pad,           tvb, 31, 1, ENC_NA);

    // handoff the data word of a nominal page
    if (even_page_type == 0 && odd_page_type == 0) {
        // create new tvb with the data word
        word = wmem_alloc(pinfo->pool, 16);
        phtonu16(word + 14, (uint16_t)data_16_1);
        phtonu64(word + 6, data_66_17);
        phtonu64(word, (((uint64_t) inav_type) << 58) | (data_122_67 << 2) | (data_66_17 >> 48));

        next_tvb = tvb_new_child_real_data(tvb, (uint8_t *)word, 16, 16);
        add_new_data_source(pinfo, next_tvb, "Galileo I/NAV Word");

        // handoff to appropriate dissector
        if (!dissector_try_uint(ubx_gal_inav_word_dissector_table, inav_type, next_tvb, pinfo, tree)) {
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }

    return tvb_captured_length(tvb);
}

/* Dissect word 0 - I/NAV Spare Word */
static int dissect_ubx_gal_inav_word0(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    col_append_str(pinfo->cinfo, COL_INFO, "Word 0 (Spare Word)");

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_gal_inav_word0, tvb, 0, 16, ENC_NA);
    proto_tree *word_tree = proto_item_add_subtree(ti, ett_ubx_gal_inav_word0);

    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word_type,   tvb,  0,  1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word0_time,  tvb,  0,  1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word0_spare, tvb,  1, 11, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word0_wn,    tvb, 12,  4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word0_tow,   tvb, 12,  4, ENC_BIG_ENDIAN);

    return tvb_captured_length(tvb);
}

/* Dissect word 1 - Ephemeris (1/4) */
static int dissect_ubx_gal_inav_word1(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    col_append_str(pinfo->cinfo, COL_INFO, "Word 1 (Ephemeris (1/4))");

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_gal_inav_word1, tvb, 0, 16, ENC_NA);
    proto_tree *word_tree = proto_item_add_subtree(ti, ett_ubx_gal_inav_word1);

    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word_type,      tvb,  0, 1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_iodnav,   tvb,  0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_t0e,      tvb,  2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_m0,       tvb,  3, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_e,        tvb,  7, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_sqrta,    tvb,  8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word1_reserved, tvb, 15, 1, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Dissect word 2 - Ephemeris (2/4) */
static int dissect_ubx_gal_inav_word2(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    col_append_str(pinfo->cinfo, COL_INFO, "Word 2 (Ephemeris (2/4))");

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_gal_inav_word2, tvb, 0, 16, ENC_NA);
    proto_tree *word_tree = proto_item_add_subtree(ti, ett_ubx_gal_inav_word2);

    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word_type,             tvb,  0, 1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word2_iodnav,          tvb,  0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word2_omega0,          tvb,  2, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word2_i0,              tvb,  6, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word2_omega,           tvb, 10, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word2_incl_angle_rate, tvb, 14, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word2_reserved,        tvb, 15, 1, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Dissect word 3 - Ephemeris (3/4) */
static int dissect_ubx_gal_inav_word3(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    col_append_str(pinfo->cinfo, COL_INFO, "Word 3 (Ephemeris (3/4))");

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_gal_inav_word3, tvb, 0, 16, ENC_NA);
    proto_tree *word_tree = proto_item_add_subtree(ti, ett_ubx_gal_inav_word3);

    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word_type,         tvb,  0, 1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word3_iodnav,      tvb,  0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word3_omega_rate,  tvb,  2, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word3_delta_n,     tvb,  5, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word3_c_uc,        tvb,  7, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word3_c_us,        tvb,  9, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word3_c_rc,        tvb, 11, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word3_c_rs,        tvb, 13, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word3_sisa_e1_e5b, tvb, 15, 1, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Dissect word 4 - Ephemeris (4/4) */
static int dissect_ubx_gal_inav_word4(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    col_append_str(pinfo->cinfo, COL_INFO, "Word 4 (Ephemeris (4/4))");

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_gal_inav_word4, tvb, 0, 16, ENC_NA);
    proto_tree *word_tree = proto_item_add_subtree(ti, ett_ubx_gal_inav_word4);

    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word_type,    tvb,  0, 1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word4_iodnav, tvb,  0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word4_svid,   tvb,  2, 1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word4_c_ic,   tvb,  2, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word4_c_is,   tvb,  4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word4_t_0c,   tvb,  6, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word4_a_f0,   tvb,  8, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word4_a_f1,   tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word4_a_f2,   tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word4_spare,  tvb, 15, 1, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Dissect word 6 - GST-UTC conversion parameters */
static int dissect_ubx_gal_inav_word6(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_) {
    col_append_str(pinfo->cinfo, COL_INFO, "Word 6 (GST-UTC conversion parameters)");

    proto_item *ti = proto_tree_add_item(tree, hf_ubx_gal_inav_word6, tvb, 0, 16, ENC_NA);
    proto_tree *word_tree = proto_item_add_subtree(ti, ett_ubx_gal_inav_word6);

    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word_type,         tvb,  0, 1, ENC_NA);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word6_a0,          tvb,  0, 8, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word6_a1,          tvb,  4, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word6_delta_t_ls,  tvb,  7, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word6_t_0t,        tvb,  8, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word6_wn_0t,       tvb,  9, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word6_wn_lsf,      tvb, 10, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word6_dn,          tvb, 11, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word6_delta_t_lsf, tvb, 12, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word6_tow,         tvb, 12, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(word_tree, hf_ubx_gal_inav_word6_spare,       tvb, 15, 1, ENC_NA);

    return tvb_captured_length(tvb);
}

void proto_register_ubx_gal_inav(void) {

    static hf_register_info hf[] = {
        {&hf_ubx_gal_inav_even_odd,      {"Even/Odd",      "gal_inav.even_odd",    FT_BOOLEAN, 8,         TFS(&tfs_odd_even),  0x80,               NULL, HFILL}},
        {&hf_ubx_gal_inav_page_type,     {"Page Type",     "gal_inav.page_type",   FT_UINT8,   BASE_DEC,  VALS(GAL_PAGE_TYPE), 0x40,               NULL, HFILL}},
        {&hf_ubx_gal_inav_type,          {"Type",          "gal_inav.type",        FT_UINT8,   BASE_DEC,  NULL,                0x3f,               NULL, HFILL}},
        {&hf_ubx_gal_inav_data_122_67,   {"Data (122-67)", "gal_inav.data_122_67", FT_UINT64,  BASE_HEX,  NULL,                0x00ffffffffffffff, NULL, HFILL}},
        {&hf_ubx_gal_inav_data_66_17,    {"Data (66-17)",  "gal_inav.data_66_17",  FT_UINT64,  BASE_HEX,  NULL,                0xffffffffffffc000, NULL, HFILL}},
        {&hf_ubx_gal_inav_data_16_1,     {"Data (16-1)",   "gal_inav.data_16_1",   FT_UINT64,  BASE_HEX,  NULL,                0x3fffc00000000000, NULL, HFILL}},

        // OSNMA
        {&hf_ubx_gal_inav_osnma_hkroot,        {"HKROOT",                             "gal_inav.osnma.hkroot",         FT_UINT32,     BASE_HEX,                  NULL,                       0x3fc00000,         NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_mack,          {"MACK",                               "gal_inav.osnma.mack",           FT_UINT64,     BASE_HEX,                  NULL,                       0x003fffffffc00000, NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_nmas,          {"NMA Status (NMAS)",                  "gal_inav.osnma.nmas",           FT_UINT8,      BASE_HEX,                  VALS(GAL_OSNMA_NMAS_CODE),  0xc0,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_cid,           {"Chain ID (CID)",                     "gal_inav.osnma.cid",            FT_UINT8,      BASE_DEC,                  NULL,                       0x30,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_cpks,          {"Chain and Public Key Status (CPKS)", "gal_inav.osnma.cpks",           FT_UINT8,      BASE_DEC,                  VALS(GAL_OSNMA_CPKS_CODE),  0x0e,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_reserved,      {"Reserved",                           "gal_inav.osnma.reserved",       FT_UINT8,      BASE_HEX,                  NULL,                       0x01,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_id,        {"DSM ID",                             "gal_inav.osnma.dsm_id",         FT_UINT8,      BASE_DEC,                  NULL,                       0xf0,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_blk_id,    {"DSM Block ID",                       "gal_inav.osnma.dsm_blk_id",     FT_UINT8,      BASE_DEC,                  NULL,                       0x0f,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_blk,       {"DSM Block",                          "gal_inav.osnma.dsm_blk",        FT_BYTES, BASE_NONE|SEP_COLON,            NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_nb_dk,     {"Number of DSM-KROOT Blocks (NB_DK)", "gal_inav.osnma.dsm.nb_dk",      FT_UINT8,      BASE_DEC,                  VALS(GAL_OSNMA_NB_DK_CODE), 0xf0,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_pkid,      {"Public Key ID (PKID)",               "gal_inav.osnma.dsm.pkid",       FT_UINT8,      BASE_DEC,                  NULL,                       0x0f,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_cidkr,     {"KROOT Chain ID (CIDKR)",             "gal_inav.osnma.dsm.cidkr",      FT_UINT8,      BASE_DEC,                  NULL,                       0xc0,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_reserved1, {"Reserved 1",                         "gal_inav.osnma.dsm.reserved1",  FT_UINT8,      BASE_HEX,                  NULL,                       0x30,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_hf,        {"Hash Function (HF)",                 "gal_inav.osnma.dsm.hf",         FT_UINT8,      BASE_DEC,                  VALS(GAL_OSNMA_HF_CODE),    0x0c,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_mf,        {"MAC Function (MF)",                  "gal_inav.osnma.dsm.mf",         FT_UINT8,      BASE_DEC,                  VALS(GAL_OSNMA_MF_CODE),    0x03,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_ks,        {"Key Size (KS)",                      "gal_inav.osnma.dsm.ks",         FT_UINT8,      BASE_DEC,                  VALS(GAL_OSNMA_KS_CODE),    0xf0,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_ts,        {"Tag Size (TS)",                      "gal_inav.osnma.dsm.ts",         FT_UINT8,      BASE_DEC,                  VALS(GAL_OSNMA_TS_CODE),    0x0f,               NULL, HFILL}},
        // TODO: show the meaning of MACLT entries
        {&hf_ubx_gal_inav_osnma_dsm_maclt,     {"MAC Look-up Table (MACLT)",          "gal_inav.osnma.dsm.maclt",      FT_UINT8,      BASE_DEC,                  NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_reserved2, {"Reserved 2",                         "gal_inav.osnma.dsm.reserved2",  FT_UINT8,      BASE_HEX,                  NULL,                       0xf0,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_wn_k,      {"KROOT Week Number (WN_K)",           "gal_inav.osnma.dsm.wn_k",       FT_UINT16,     BASE_DEC,                  NULL,                       0x0fff,             NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_towh_k,    {"KROOT Time of Week (TOWH_K)",        "gal_inav.osnma.dsm.towh_k",     FT_UINT8,      BASE_DEC|BASE_UNIT_STRING, UNS(&units_hours),          0xff,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_alpha,     {"Random Pattern (α)",                 "gal_inav.osnma.dsm.alpha",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_kroot,     {"KROOT",                              "gal_inav.osnma.dsm.kroot",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_ds,        {"Digital Signature (DS)",             "gal_inav.osnma.dsm.ds",         FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_p_dk,      {"DSM-KROOT Padding (P_DK)",           "gal_inav.osnma.dsm.p_dk",       FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_nb_dp,     {"Number of DSM-PKR Blocks (NB_DP)",   "gal_inav.osnma.dsm.nb_dp",      FT_UINT8,      BASE_DEC,                  VALS(GAL_OSNMA_NB_DP_CODE), 0xf0,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_mid,       {"Message ID (MID)",                   "gal_inav.osnma.dsm.mid",        FT_UINT8,      BASE_DEC,                  NULL,                       0x0f,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_0,     {"x_0_0",                              "gal_inav.osnma.dsm.x_0_0",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_1,     {"x_0_1",                              "gal_inav.osnma.dsm.x_0_1",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_2,     {"x_0_2",                              "gal_inav.osnma.dsm.x_0_2",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_3,     {"x_0_3",                              "gal_inav.osnma.dsm.x_0_3",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_4,     {"x_0_4",                              "gal_inav.osnma.dsm.x_0_4",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_5,     {"x_0_5",                              "gal_inav.osnma.dsm.x_0_5",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_6,     {"x_0_6",                              "gal_inav.osnma.dsm.x_0_6",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_7,     {"x_0_7",                              "gal_inav.osnma.dsm.x_0_7",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_8,     {"x_0_8",                              "gal_inav.osnma.dsm.x_0_8",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_9,     {"x_0_9",                              "gal_inav.osnma.dsm.x_0_9",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_10,    {"x_0_10",                             "gal_inav.osnma.dsm.x_0_10",     FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_11,    {"x_0_11",                             "gal_inav.osnma.dsm.x_0_11",     FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_12,    {"x_0_12",                             "gal_inav.osnma.dsm.x_0_12",     FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_13,    {"x_0_13",                             "gal_inav.osnma.dsm.x_0_13",     FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_14,    {"x_0_14",                             "gal_inav.osnma.dsm.x_0_14",     FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_0_15,    {"x_0_15",                             "gal_inav.osnma.dsm.x_0_15",     FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_1_0,     {"x_1_0",                              "gal_inav.osnma.dsm.x_1_0",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_1_1,     {"x_1_1",                              "gal_inav.osnma.dsm.x_1_1",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_1_2,     {"x_1_2",                              "gal_inav.osnma.dsm.x_1_2",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_1_3,     {"x_1_3",                              "gal_inav.osnma.dsm.x_1_3",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_1_4,     {"x_1_4",                              "gal_inav.osnma.dsm.x_1_4",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_1_5,     {"x_1_5",                              "gal_inav.osnma.dsm.x_1_5",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_1_6,     {"x_1_6",                              "gal_inav.osnma.dsm.x_1_6",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_1_7,     {"x_1_7",                              "gal_inav.osnma.dsm.x_1_7",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_2_0,     {"x_2_0",                              "gal_inav.osnma.dsm.x_2_0",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_2_1,     {"x_2_1",                              "gal_inav.osnma.dsm.x_2_1",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_2_2,     {"x_2_2",                              "gal_inav.osnma.dsm.x_2_2",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_2_3,     {"x_2_3",                              "gal_inav.osnma.dsm.x_2_3",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_3_0,     {"x_3_0",                              "gal_inav.osnma.dsm.x_3_0",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_x_3_1,     {"x_3_1",                              "gal_inav.osnma.dsm.x_3_1",      FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_npkt,      {"New Public Key Type (NPKT)",         "gal_inav.osnma.dsm.npkt",       FT_UINT8,      BASE_DEC,                  VALS(GAL_OSNMA_NPKT_CODE),  0xf0,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_npkid,     {"New Public Key ID (NPKID)",          "gal_inav.osnma.dsm.npkid",      FT_UINT8,      BASE_DEC,                  NULL,                       0x0f,               NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_npk,       {"New Public Key (NPK)",               "gal_inav.osnma.dsm.npk",        FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma_dsm_p_dp,      {"DSM-PKR Padding (P_DP)",             "gal_inav.osnma.dsm.p_dp",       FT_BYTES,      BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},

        // SAR
        {&hf_ubx_gal_inav_sar_start_bit, {"Start bit",                          "gal_inav.sar.start_bit", FT_BOOLEAN, 32,        NULL,                             0x20000000,         NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_long_rlm,  {"Long RLM",                           "gal_inav.sar.long_rlm",  FT_BOOLEAN, 32,        NULL,                             0x10000000,         NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_rlm_data,  {"RLM data",                           "gal_inav.sar.rlm_data",  FT_UINT32,  BASE_HEX,  NULL,                             0x0fffff00,         NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_beacon_id, {"Beacon ID",                          "gal_inav.sar.beacon_id", FT_UINT64,  BASE_HEX,  NULL,                             0xfffffffffffffff0, NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_msg_code,  {"Message code",                       "gal_inav.sar.msg_code",  FT_UINT32,  BASE_HEX,  VALS(GAL_SAR_SHORT_RLM_MSG_CODE), 0x000f0000,         NULL, HFILL}},

        {&hf_ubx_gal_inav_spare,      {"Spare",      "gal_inav.spare",      FT_UINT8,  BASE_HEX,  NULL,          0xc0,       NULL, HFILL}},
        {&hf_ubx_gal_inav_reserved_1, {"Reserved 1", "gal_inav.reserved_1", FT_NONE,   BASE_NONE, NULL,          0x0,        NULL, HFILL}},
        {&hf_ubx_gal_inav_crc,        {"CRC",        "gal_inav.crc",        FT_UINT32, BASE_HEX,  NULL,          0x3fffffc0, NULL, HFILL}},
        {&hf_ubx_gal_inav_ssp,        {"SSP",        "gal_inav.ssp",        FT_UINT32, BASE_HEX,  VALS(GAL_SSP), 0x003fc000, NULL, HFILL}},
        {&hf_ubx_gal_inav_tail,       {"Tail",       "gal_inav.tail",       FT_UINT8,  BASE_HEX,  NULL,          0x3f,       NULL, HFILL}},
        {&hf_ubx_gal_inav_pad,        {"Pad",        "gal_inav.pad",        FT_UINT8,  BASE_HEX,  NULL,          0x0,        NULL, HFILL}},

        // Data words
        {&hf_ubx_gal_inav_word_type,     {"Type",                "gal_inav.word.type",     FT_UINT8,      BASE_DEC,  NULL, 0xfc, NULL, HFILL}},

        // Word 0
        {&hf_ubx_gal_inav_word0,         {"Word 0 (Spare Word)", "gal_inav.word0",         FT_NONE,       BASE_NONE, NULL, 0x0,  NULL, HFILL}},
        {&hf_ubx_gal_inav_word0_time,    {"Time",                "gal_inav.word0.time",    FT_UINT8,      BASE_HEX,  NULL, 0x03, NULL, HFILL}},
        {&hf_ubx_gal_inav_word0_spare,   {"Spare",               "gal_inav.word0.spare",   FT_BYTES,      BASE_NONE|SEP_SPACE, NULL, 0x0,  NULL, HFILL}},
        {&hf_ubx_gal_inav_word0_wn,      {"Week Number",         "gal_inav.word0.wn",      FT_UINT32,     BASE_DEC,  NULL, 0xfff00000,  NULL, HFILL}},
        {&hf_ubx_gal_inav_word0_tow,     {"Time of Week",        "gal_inav.word0.tow",     FT_UINT32,     BASE_DEC,  NULL, 0x000fffff,  NULL, HFILL}},

        // Word 1
        {&hf_ubx_gal_inav_word1,         {"Word 1 (Ephemeris (1/4))",                                   "gal_inav.word1",          FT_NONE,   BASE_NONE,   NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_iodnav,  {"IOD_nav",                                                    "gal_inav.word1.iod_nav",  FT_UINT16, BASE_DEC,    NULL,                       0x03ff,             NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_t0e,     {"Ephemeris reference time (t_0e)",                            "gal_inav.word1.t_0e",     FT_UINT16, BASE_CUSTOM, CF_FUNC(&fmt_t0e),          0xfffc,             NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_m0,      {"Mean anomaly at reference time (M" UTF8_SUBSCRIPT_ZERO ")",  "gal_inav.word1.m_0",      FT_INT64,  BASE_CUSTOM, CF_FUNC(&fmt_semi_circles), 0x03fffffffc000000, NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_e,       {"Eccentricity (e)",                                           "gal_inav.word1.e",        FT_UINT64, BASE_CUSTOM, CF_FUNC(&fmt_e),            0x03fffffffc000000, NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_sqrta,   {"Square root of the semi-major axis (" UTF8_SQUARE_ROOT "a)", "gal_inav.word1.sqrt_a",   FT_UINT64, BASE_CUSTOM, CF_FUNC(&fmt_sqrt_a),       0x00000003fffffffc, NULL, HFILL}},
        {&hf_ubx_gal_inav_word1_reserved,{"Reserved",                                                   "gal_inav.word1.reserved", FT_UINT8,  BASE_HEX,    NULL,                       0x03,               NULL, HFILL}},

        // Word 2
        {&hf_ubx_gal_inav_word2,                 {"Word 2 (Ephemeris (2/4))",                                                                                  "gal_inav.word2",          FT_NONE,   BASE_NONE,   NULL,                            0x0,        NULL, HFILL}},
        {&hf_ubx_gal_inav_word2_iodnav,          {"IOD_nav",                                                                                                   "gal_inav.word2.iod_nav",  FT_UINT16, BASE_DEC,    NULL,                            0x03ff,     NULL, HFILL}},
        {&hf_ubx_gal_inav_word2_omega0,          {"Longitude of ascending node of orbital plane at weekly epoch (" UTF8_CAPITAL_OMEGA UTF8_SUBSCRIPT_ZERO ")", "gal_inav.word2.omega_0",  FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_semi_circles),      0xffffffff, NULL, HFILL}},
        {&hf_ubx_gal_inav_word2_i0,              {"Inclination angle at reference time (i" UTF8_SUBSCRIPT_ZERO ")",                                            "gal_inav.word2.i_0",      FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_semi_circles),      0xffffffff, NULL, HFILL}},
        {&hf_ubx_gal_inav_word2_omega,           {"Argument of perigee (" UTF8_OMEGA ")",                                                                      "gal_inav.word2.omega",    FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_semi_circles),      0xffffffff, NULL, HFILL}},
        {&hf_ubx_gal_inav_word2_incl_angle_rate, {"Rate of change of inclination angle (di)",                                                                  "gal_inav.word2.di",       FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_semi_circles_rate), 0xfffc,     NULL, HFILL}},
        {&hf_ubx_gal_inav_word2_reserved,        {"Reserved",                                                                                                  "gal_inav.word2.reserved", FT_UINT8,  BASE_HEX,    NULL,                            0x03,       NULL, HFILL}},

        // Word 3
        {&hf_ubx_gal_inav_word3,             {"Word 3 (Ephemeris (3/4))",                                                            "gal_inav.word3",             FT_NONE,   BASE_NONE,   NULL,                            0x0,        NULL, HFILL}},
        {&hf_ubx_gal_inav_word3_iodnav,      {"IOD_nav",                                                                             "gal_inav.word3.iod_nav",     FT_UINT16, BASE_DEC,    NULL,                            0x03ff,     NULL, HFILL}},
        {&hf_ubx_gal_inav_word3_omega_rate,  {"Rate of change of right ascension (dot " UTF8_CAPITAL_OMEGA ")",                      "gal_inav.word3.omega_rate",  FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_semi_circles_rate), 0xffffff00, NULL, HFILL}},
        {&hf_ubx_gal_inav_word3_delta_n,     {"Mean motion difference from computed value (" UTF8_CAPITAL_DELTA "n)",                "gal_inav.word3.delta_n",     FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_semi_circles_rate), 0xffff,     NULL, HFILL}},
        {&hf_ubx_gal_inav_word3_c_uc,        {"Amplitude of the cosine harmonic correction term to the argument of latitude (C_UC)", "gal_inav.word3.c_uc",        FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_lat_correction),    0xffff,     NULL, HFILL}},
        {&hf_ubx_gal_inav_word3_c_us,        {"Amplitude of the sine harmonic correction term to the argument of latitude (C_US)",   "gal_inav.word3.c_us",        FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_lat_correction),    0xffff,     NULL, HFILL}},
        {&hf_ubx_gal_inav_word3_c_rc,        {"Amplitude of the cosine harmonic correction term to the orbit radius (C_RC)",         "gal_inav.word3.c_rc",        FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_orbit_correction),  0xffff,     NULL, HFILL}},
        {&hf_ubx_gal_inav_word3_c_rs,        {"Amplitude of the sine harmonic correction term to the orbit radius (C_RS)",           "gal_inav.word3.c_rs",        FT_INT16,  BASE_CUSTOM, CF_FUNC(&fmt_orbit_correction),  0xffff,     NULL, HFILL}},
        {&hf_ubx_gal_inav_word3_sisa_e1_e5b, {"Signal-in-Space Accuracy (SISA(E1,E5b))",                                             "gal_inav.word3.sisa_e1_e5b", FT_UINT8,  BASE_CUSTOM, CF_FUNC(&fmt_sisa),              0xff,       NULL, HFILL}},

        // Word 4
        {&hf_ubx_gal_inav_word4,             {"Word 4 (Ephemeris (4/4))",                                                            "gal_inav.word4",             FT_NONE,   BASE_NONE,   NULL,                            0x0,        NULL, HFILL}},
        {&hf_ubx_gal_inav_word4_iodnav,      {"IOD_nav",                                                                             "gal_inav.word4.iod_nav",     FT_UINT16, BASE_DEC,    NULL,                            0x03ff,     NULL, HFILL}},
        {&hf_ubx_gal_inav_word4_svid,        {"SVID",                                                                                "gal_inav.word4.svid",        FT_UINT8,  BASE_DEC,    NULL,                            0xfc,       NULL, HFILL}},
        {&hf_ubx_gal_inav_word4_c_ic,        {"Amplitude of the cosine harmonic correction term to the angle of inclination (C_IC)", "gal_inav.word4.c_ic",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_lat_correction),    0x03fffc00, NULL, HFILL}},
        {&hf_ubx_gal_inav_word4_c_is,        {"Amplitude of the sine harmonic correction term to the angle of inclination (C_IS)",   "gal_inav.word4.c_is",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_lat_correction),    0x03fffc00, NULL, HFILL}},
        {&hf_ubx_gal_inav_word4_t_0c,        {"Clock correction data reference Time of Week (t_0c)",                                 "gal_inav.word4.t_0c",        FT_UINT32, BASE_CUSTOM, CF_FUNC(&fmt_clk_correction),    0x03fff000, NULL, HFILL}},
        {&hf_ubx_gal_inav_word4_a_f0,        {"SV clock bias correction coefficient (a_f0)",                                         "gal_inav.word4.a_f0",        FT_INT64,  BASE_CUSTOM, CF_FUNC(&fmt_sv_clk_bias),       0x0fffffffe0000000, NULL, HFILL}},
        {&hf_ubx_gal_inav_word4_a_f1,        {"SV clock drift correction coefficient (a_f1)",                                        "gal_inav.word4.a_f1",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_sv_clk_drift),      0x1fffff00, NULL, HFILL}},
        {&hf_ubx_gal_inav_word4_a_f2,        {"SV clock drift rate correction coefficient (a_f2)",                                   "gal_inav.word4.a_f2",        FT_INT32,  BASE_CUSTOM, CF_FUNC(&fmt_sv_clk_drift_rate), 0x000000fc, NULL, HFILL}},
        {&hf_ubx_gal_inav_word4_spare,       {"Spare",                                                                               "gal_inav.word4.spare",       FT_UINT8,  BASE_HEX,    NULL,                            0x03,       NULL, HFILL}},

        // Word 6
        {&hf_ubx_gal_inav_word6,             {"Word 6 (GST-UTC conversion parameters)",                                         "gal_inav.word6",             FT_NONE,   BASE_NONE,                 NULL,                       0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_word6_a0,          {"Constant term of polynomial (A_0)",                                              "gal_inav.word6.a_0",         FT_INT64,  BASE_CUSTOM,               CF_FUNC(&fmt_a0),           0x03fffffffc000000, NULL, HFILL}},
        {&hf_ubx_gal_inav_word6_a1,          {"1st order term of polynomial (A_1)",                                             "gal_inav.word6.a_1",         FT_INT32,  BASE_CUSTOM,               CF_FUNC(&fmt_a1),           0x03fffffc,         NULL, HFILL}},
        {&hf_ubx_gal_inav_word6_delta_t_ls,  {"Leap Second count before leap second adjustment (" UTF8_CAPITAL_DELTA "t_LS)",   "gal_inav.word6.delta_t_ls",  FT_INT16,  BASE_DEC|BASE_UNIT_STRING, UNS(&units_second_seconds), 0x03fc,             NULL, HFILL}},
        {&hf_ubx_gal_inav_word6_t_0t,        {"UTC data reference Time of Week (t_0t)",                                         "gal_inav.word6.t_0t",        FT_UINT16, BASE_CUSTOM,               CF_FUNC(&fmt_t_0t),         0x03fc,             NULL, HFILL}},
        {&hf_ubx_gal_inav_word6_wn_0t,       {"UTC data reference Week Number (WN_0t)",                                         "gal_inav.word6.wn_0t",       FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_week_weeks),     0x03fc,             NULL, HFILL}},
        {&hf_ubx_gal_inav_word6_wn_lsf,      {"Week Number of leap second adjustment (WN_LSF)",                                 "gal_inav.word6.wn_lsf",      FT_UINT16, BASE_DEC|BASE_UNIT_STRING, UNS(&units_week_weeks),     0x03fc,             NULL, HFILL}},
        {&hf_ubx_gal_inav_word6_dn,          {"Day Number at the end of which a leap second adjustment becomes effective (DN)", "gal_inav.word6.dn",          FT_UINT16, BASE_DEC, VALS(DAY_NUMBER),                            0x0380,             NULL, HFILL}},
        {&hf_ubx_gal_inav_word6_delta_t_lsf, {"Leap Second count after leap second adjustment (" UTF8_CAPITAL_DELTA "t_LSF)",   "gal_inav.word6.delta_t_lsf", FT_INT16,  BASE_DEC|BASE_UNIT_STRING, UNS(&units_second_seconds), 0x7f80,             NULL, HFILL}},
        {&hf_ubx_gal_inav_word6_tow,         {"Time of Week (TOW)",                                                             "gal_inav.word6.tow",         FT_UINT32, BASE_DEC|BASE_UNIT_STRING, UNS(&units_second_seconds), 0x007ffff8,         NULL, HFILL}},
        {&hf_ubx_gal_inav_word6_spare,       {"Spare",                                                                          "gal_inav.word6.spare",       FT_UINT8,  BASE_HEX,                  NULL,                       0x07,               NULL, HFILL}},
    };

    static int *ett[] = {
        &ett_ubx_gal_inav,
        &ett_ubx_gal_inav_word0,
        &ett_ubx_gal_inav_word1,
        &ett_ubx_gal_inav_word2,
        &ett_ubx_gal_inav_word3,
        &ett_ubx_gal_inav_word4,
        &ett_ubx_gal_inav_word6,
        &ett_ubx_gal_inav_osnma,
        &ett_ubx_gal_inav_osnma_hkroot_msg,
        &ett_ubx_gal_inav_osnma_dsm,
        &ett_ubx_gal_inav_sar,
        &ett_ubx_gal_inav_sar_rlm,
    };

    proto_ubx_gal_inav = proto_register_protocol("Galileo E1-B I/NAV Navigation Message", "Galileo I/NAV", "gal_inav");

    proto_register_field_array(proto_ubx_gal_inav, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("ubx_gal_inav", dissect_ubx_gal_inav, proto_ubx_gal_inav);

    ubx_gal_inav_word_dissector_table = register_dissector_table("ubx.rxm.sfrbx.gal_inav.word",
            "Galileo I/NAV Word", proto_ubx_gal_inav, FT_UINT8, BASE_DEC);
}

void proto_reg_handoff_ubx_gal_inav(void) {
    dissector_add_uint("ubx.rxm.sfrbx.gnssid", GNSS_ID_GALILEO, create_dissector_handle(dissect_ubx_gal_inav, proto_ubx_gal_inav));

    dissector_add_uint("ubx.rxm.sfrbx.gal_inav.word", 0, create_dissector_handle(dissect_ubx_gal_inav_word0, proto_ubx_gal_inav));
    dissector_add_uint("ubx.rxm.sfrbx.gal_inav.word", 1, create_dissector_handle(dissect_ubx_gal_inav_word1, proto_ubx_gal_inav));
    dissector_add_uint("ubx.rxm.sfrbx.gal_inav.word", 2, create_dissector_handle(dissect_ubx_gal_inav_word2, proto_ubx_gal_inav));
    dissector_add_uint("ubx.rxm.sfrbx.gal_inav.word", 3, create_dissector_handle(dissect_ubx_gal_inav_word3, proto_ubx_gal_inav));
    dissector_add_uint("ubx.rxm.sfrbx.gal_inav.word", 4, create_dissector_handle(dissect_ubx_gal_inav_word4, proto_ubx_gal_inav));
    dissector_add_uint("ubx.rxm.sfrbx.gal_inav.word", 6, create_dissector_handle(dissect_ubx_gal_inav_word6, proto_ubx_gal_inav));
}
