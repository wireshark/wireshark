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

#include <epan/packet.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <wsutil/pint.h>
#include <wsutil/utf8_entities.h>

#include "packet-ubx.h"

/*
 * Dissects Galileo E1-B I/NAV navigation messages
 * as encoded by UBX (in UBX-RXM-SFRBX messages).
 * Based on Galileo OS SIS ICD Issue 2.1
 */

// Initialize the protocol and registered fields
static int proto_ubx_gal_inav;

static int hf_ubx_gal_inav_even_odd;
static int hf_ubx_gal_inav_page_type;
static int hf_ubx_gal_inav_type;
static int hf_ubx_gal_inav_data_122_67;
static int hf_ubx_gal_inav_data_66_17;
static int hf_ubx_gal_inav_data_16_1;
static int hf_ubx_gal_inav_osnma;
static int hf_ubx_gal_inav_sar_start_bit;
static int hf_ubx_gal_inav_sar_long_rlm;
static int hf_ubx_gal_inav_sar_beacon_1;
static int hf_ubx_gal_inav_sar_rlm_data;
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

static dissector_table_t ubx_gal_inav_word_dissector_table;

static int ett_ubx_gal_inav;
static int ett_ubx_gal_inav_word0;
static int ett_ubx_gal_inav_word1;
static int ett_ubx_gal_inav_word2;
static int ett_ubx_gal_inav_word3;
static int ett_ubx_gal_inav_word4;
static int ett_ubx_gal_inav_sar;

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

/* Format clock correction (with scale factor 60) for
 * t_0c
 */
static void fmt_clk_correction(char *label, uint32_t c) {
    snprintf(label, ITEM_LABEL_LENGTH, "%u s", 60 * c);
}

/* Format radians (with 2^-29 scale factor) for
 * amplitude of harmonic correction terms
 */
static void fmt_lat_correction(char *label, int16_t c) {
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
static void fmt_semi_circles_rate(char *label, int16_t c) {
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
static int dissect_ubx_gal_inav(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    tvbuff_t *next_tvb;

    bool sar_start, sar_long_rlm;
    uint32_t inav_type = 0, even_page_type, odd_page_type;
    uint64_t data_122_67 = 0, data_66_17 = 0, data_16_1 = 0;
    uint8_t *word;

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
        proto_tree_add_item_ret_uint64(gal_inav_tree, hf_ubx_gal_inav_data_16_1,   tvb, 16, 8, ENC_BIG_ENDIAN, &data_16_1);
        proto_tree_add_item(gal_inav_tree, hf_ubx_gal_inav_osnma,       tvb, 16, 8, ENC_BIG_ENDIAN);

        proto_tree *sar_tree = proto_tree_add_subtree(gal_inav_tree, tvb, 23, 4, ett_ubx_gal_inav_sar, NULL, "SAR");
        proto_tree_add_item_ret_boolean(sar_tree, hf_ubx_gal_inav_sar_start_bit, tvb, 23, 4, ENC_BIG_ENDIAN, &sar_start);
        proto_tree_add_item_ret_boolean(sar_tree, hf_ubx_gal_inav_sar_long_rlm,  tvb, 23, 4, ENC_BIG_ENDIAN, &sar_long_rlm);
        if (sar_start) {
            proto_tree_add_item(sar_tree, hf_ubx_gal_inav_sar_beacon_1, tvb, 23, 4, ENC_BIG_ENDIAN);
        }
        else {
            // TODO: add more elaborate dissection for subsequent RLM data (requiring state tracking)
            proto_tree_add_item(sar_tree, hf_ubx_gal_inav_sar_rlm_data, tvb, 23, 4, ENC_BIG_ENDIAN);
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
        phton16(word + 14, (uint16_t)data_16_1);
        phton64(word + 6, data_66_17);
        phton64(word, (((uint64_t) inav_type) << 58) | (data_122_67 << 2) | (data_66_17 >> 48));

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

void proto_register_ubx_gal_inav(void) {

    static hf_register_info hf[] = {
        {&hf_ubx_gal_inav_even_odd,      {"Even/Odd",      "gal_inav.even_odd",      FT_BOOLEAN, 8,         TFS(&tfs_odd_even),  0x80,               NULL, HFILL}},
        {&hf_ubx_gal_inav_page_type,     {"Page Type",     "gal_inav.page_type",     FT_UINT8,   BASE_DEC,  VALS(GAL_PAGE_TYPE), 0x40,               NULL, HFILL}},
        {&hf_ubx_gal_inav_type,          {"Type",          "gal_inav.type",          FT_UINT8,   BASE_DEC,  NULL,                0x3f,               NULL, HFILL}},
        {&hf_ubx_gal_inav_data_122_67,   {"Data (122-67)", "gal_inav.data_122_67",   FT_UINT64,  BASE_HEX,  NULL,                0x00ffffffffffffff, NULL, HFILL}},
        {&hf_ubx_gal_inav_data_66_17,    {"Data (66-17)",  "gal_inav.data_66_17",    FT_UINT64,  BASE_HEX,  NULL,                0xffffffffffffc000, NULL, HFILL}},
        {&hf_ubx_gal_inav_data_16_1,     {"Data (16-1)",   "gal_inav.data_16_1",     FT_UINT64,  BASE_HEX,  NULL,                0x3fffc00000000000, NULL, HFILL}},
        {&hf_ubx_gal_inav_osnma,         {"OSNMA",         "gal_inav.osnma",         FT_UINT64,  BASE_HEX,  NULL,                0x00003fffffffffc0, NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_start_bit, {"Start bit",     "gal_inav.sar.start_bit", FT_BOOLEAN, 32,        NULL,                0x20000000,         NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_long_rlm,  {"Long RLM",      "gal_inav.sar.long_rlm",  FT_BOOLEAN, 32,        NULL,                0x10000000,         NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_beacon_1,  {"Beacon (1/3)",  "gal_inav.sar.beacon_1",  FT_UINT32,  BASE_HEX,  NULL,                0x0fffff00,         NULL, HFILL}},
        {&hf_ubx_gal_inav_sar_rlm_data,  {"RLM data",      "gal_inav.sar.rlm_data",  FT_UINT32,  BASE_HEX,  NULL,                0x0fffff00,         NULL, HFILL}},
        {&hf_ubx_gal_inav_spare,         {"Spare",         "gal_inav.spare",         FT_UINT8,   BASE_HEX,  NULL,                0xc0,               NULL, HFILL}},
        {&hf_ubx_gal_inav_reserved_1,    {"Reserved 1",    "gal_inav.reserved_1",    FT_NONE,    BASE_NONE, NULL,                0x0,                NULL, HFILL}},
        {&hf_ubx_gal_inav_crc,           {"CRC",           "gal_inav.crc",           FT_UINT32,  BASE_HEX,  NULL,                0x3fffffc0,         NULL, HFILL}},
        {&hf_ubx_gal_inav_ssp,           {"SSP",           "gal_inav.ssp",           FT_UINT32,  BASE_HEX,  VALS(GAL_SSP),       0x003fc000,         NULL, HFILL}},
        {&hf_ubx_gal_inav_tail,          {"Tail",          "gal_inav.tail",          FT_UINT8,   BASE_HEX,  NULL,                0x3f,               NULL, HFILL}},
        {&hf_ubx_gal_inav_pad,           {"Pad",           "gal_inav.pad",           FT_UINT8,   BASE_HEX,  NULL,                0x0,                NULL, HFILL}},

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
    };

    static int *ett[] = {
        &ett_ubx_gal_inav,
        &ett_ubx_gal_inav_word0,
        &ett_ubx_gal_inav_word1,
        &ett_ubx_gal_inav_word2,
        &ett_ubx_gal_inav_word3,
        &ett_ubx_gal_inav_word4,
        &ett_ubx_gal_inav_sar,
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
}
