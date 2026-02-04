/* packet-homeplug-av-vendor-vertexcom.c
 * Routines for HomePlug AV VertexCom MME dissection
 * Copyright 2026, ShanTon Tu <shanton.tu@vertexcom.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * HomePlug AV VertexCom MME dissector
 */

#include "config.h"
#define WS_LOG_DOMAIN "homeplug-av-vendor-vertexcom"

#include <epan/etypes.h>
#include <epan/packet.h>
#include <epan/tfs.h>

#include "packet-homeplug-av-vendor-vertexcom.h"

/* Prototypes */
/* (Required to prevent [-Wmissing-prototypes] warnings */
void proto_reg_handoff_homeplug_av_vendor_vertexcom(void);
void proto_register_homeplug_av_vendor_vertexcom(void);

typedef struct homeplug_av_vertexcom_context {
    uint8_t mmver;
    uint16_t mmtype;
} homeplug_av_vertexcom_context_t;

/* VertexCom VS_* MMEs */
typedef enum {
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_VERSION_REQ = 0XA000,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_VERSION_CNF = 0XA001,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_RESET_REQ = 0XA008,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_RESET_CNF = 0XA009,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_TONEMASK_REQ = 0XA01C,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_TONEMASK_CNF = 0XA01D,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_ETH_PHY_REQ = 0XA020,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_ETH_PHY_CNF = 0XA021,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_ETH_STATS_REQ = 0XA024,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_ETH_STATS_CNF = 0XA025,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_STATUS_REQ = 0XA030,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_STATUS_CNF = 0XA031,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_TONEMAP_REQ = 0XA034,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_TONEMAP_CNF = 0XA035,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_SNR_REQ = 0XA038,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_SNR_CNF = 0XA039,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_SPECTRUM_REQ = 0XA03C,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_SPECTRUM_CNF = 0XA03D,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_LINK_STATS_REQ = 0XA040,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_LINK_STATS_CNF = 0XA041,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_AMP_MAP_REQ = 0XA044,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_AMP_MAP_CNF = 0XA045,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NW_INFO_REQ = 0XA0FC,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NW_INFO_CNF = 0XA0FD,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_CAPTURE_STATE_REQ = 0XA100,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_CAPTURE_STATE_CNF = 0XA101,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_NVRAM_REQ = 0XA104,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_NVRAM_CNF = 0XA105,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NVRAM_REQ = 0XA108,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NVRAM_CNF = 0XA109,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_STATS_REQ = 0XA10C,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_STATS_CNF = 0XA10D,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_STATS_IND = 0XA10E,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_CONF_REQ = 0XA110,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_CONF_CNF = 0XA111,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_PWM_CONF_REQ = 0XA114,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_PWM_CONF_CNF = 0XA115,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_PWM_GENERATION_REQ = 0XA118,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_PWM_GENERATION_CNF = 0XA119,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SPI_STATS_REQ = 0XA11C,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SPI_STATS_CNF = 0XA11D,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_DSP_RECORD_STATE_REQ = 0XA120,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_DSP_RECORD_STATE_CNF = 0XA121,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_DSP_RECORD_STATUS_REQ = 0XA124,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_DSP_RECORD_STATUS_CNF = 0XA125,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_TX_CAL_REQ = 0XA128,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_TX_CAL_CNF = 0XA129,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SNIFFER_MODE_REQ = 0XA138,
    // HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SNIFFER_MODE_CNF = 0XA139,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_REMOTE_ACCESS_REQ = 0XA13C,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_REMOTE_ACCESS_CNF = 0XA13D,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_REMOTE_ACCESS_REQ = 0XA140,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_REMOTE_ACCESS_CNF = 0XA141,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_FILE_ACCESS_REQ = 0XA4FC,
    HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_FILE_ACCESS_CNF = 0XA4FD,
} homeplug_av_mmetypes_vertexcom_vs_type;

static int proto_homeplug_av;

static int hf_homeplug_av_mmhdr_mmtype_vertexcom;

static heur_dissector_list_t vertexcom_mmtype_vs_heur_dissector_list;

static const value_string homeplug_av_mmtype_vertexcom_vals[] = {
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_VERSION_REQ, "VS_GET_VERSION.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_VERSION_CNF, "VS_GET_VERSION.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_RESET_REQ, "VS_RESET.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_RESET_CNF, "VS_RESET.CNF"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_TONEMASK_REQ,
    // "VS_GET_TONEMASK.REQ"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_TONEMASK_CNF,
    // "VS_GET_TONEMASK.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_ETH_PHY_REQ, "VS_GET_ETH_PHY.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_ETH_PHY_CNF, "VS_GET_ETH_PHY.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_ETH_STATS_REQ, "VS_ETH_STATS.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_ETH_STATS_CNF, "VS_ETH_STATS.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_STATUS_REQ, "VS_GET_STATUS.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_STATUS_CNF, "VS_GET_STATUS.CNF"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_TONEMAP_REQ, "VS_GET_TONEMAP.REQ"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_TONEMAP_CNF, "VS_GET_TONEMAP.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_SNR_REQ, "VS_GET_SNR.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_SNR_CNF, "VS_GET_SNR.CNF"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_SPECTRUM_REQ,
    // "VS_GET_SPECTRUM.REQ"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_SPECTRUM_CNF,
    // "VS_GET_SPECTRUM.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_LINK_STATS_REQ, "VS_GET_LINK_STATS.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_LINK_STATS_CNF, "VS_GET_LINK_STATS.CNF"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_AMP_MAP_REQ, "VS_GET_AMP_MAP.REQ"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_AMP_MAP_CNF, "VS_GET_AMP_MAP.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NW_INFO_REQ, "VS_GET_NW_INFO.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NW_INFO_CNF, "VS_GET_NW_INFO.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_CAPTURE_STATE_REQ,
     "VS_SET_CAPTURE_STATE.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_CAPTURE_STATE_CNF,
     "VS_SET_CAPTURE_STATE.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_NVRAM_REQ, "VS_SET_NVRAM.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_NVRAM_CNF, "VS_SET_NVRAM.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NVRAM_REQ, "VS_GET_NVRAM.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NVRAM_CNF, "VS_GET_NVRAM.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_STATS_REQ, "VS_GET_PWM_STATS.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_STATS_CNF, "VS_GET_PWM_STATS.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_STATS_IND, "VS_GET_PWM_STATS.IND"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_CONF_REQ, "VS_GET_PWM_CONF.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_CONF_CNF, "VS_GET_PWM_CONF.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_PWM_CONF_REQ, "VS_SET_PWM_CONF.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_PWM_CONF_CNF, "VS_SET_PWM_CONF.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_PWM_GENERATION_REQ, "VS_PWM_GENERATION.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_PWM_GENERATION_CNF, "VS_PWM_GENERATION.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SPI_STATS_REQ, "VS_SPI_STATS.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SPI_STATS_CNF, "VS_SPI_STATS.CNF"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_DSP_RECORD_STATE_REQ,
    // "VS_SET_DSP_RECORD_STATE.REQ"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_DSP_RECORD_STATE_CNF,
    // "VS_SET_DSP_RECORD_STATE.CNF"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_DSP_RECORD_STATUS_REQ,
    // "VS_GET_DSP_RECORD_STATUS.REQ"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_DSP_RECORD_STATUS_CNF,
    // "VS_GET_DSP_RECORD_STATUS.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_TX_CAL_REQ, "VS_SET_TX_CAL.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_TX_CAL_CNF, "VS_SET_TX_CAL.CNF"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SNIFFER_MODE_REQ,
    // "VS_SNIFFER_MODE.REQ"},
    // {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SNIFFER_MODE_CNF,
    // "VS_SNIFFER_MODE.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_REMOTE_ACCESS_REQ,
     "VS_SET_REMOTE_ACCESS.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_REMOTE_ACCESS_CNF,
     "VS_SET_REMOTE_ACCESS.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_REMOTE_ACCESS_REQ,
     "VS_GET_REMOTE_ACCESS.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_REMOTE_ACCESS_CNF,
     "VS_GET_REMOTE_ACCESS.CNF"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_FILE_ACCESS_REQ, "VS_FILE_ACCESS.REQ"},
    {HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_FILE_ACCESS_CNF, "VS_FILE_ACCESS.CNF"},
    {0, NULL},  // must be add this at end
};

static value_string_ext homeplug_av_mmtype_vertexcom_vals_ext =
    VALUE_STRING_EXT_INIT(homeplug_av_mmtype_vertexcom_vals);

// #################### Common Vlues ####################
static const value_string vertexcom_val_str_operation_result[] = {
    {0x00, "Success"},
    {0x01, "Failure"},
    {0xff, "Operation is prohibited"},
    {0, NULL},
};

static const value_string vertexcom_val_str_stats_command[] = {
    {0x00, "Get statistics"},
    {0x01, "Reset statistics"},
    {0, NULL},
};

static const value_string vertexcom_val_str_pwm_conf_pwm_measurement_method[] = {
    {0x00, "Poll"},
    {0x01, "Push"},
    {0, NULL},
};

// #################### VS_GET_VERSION ####################

static int ett_vs_get_version_cnf;
static int hf_vs_get_version_cnf;
static int hf_vs_get_version_cnf_result;
static int hf_vs_get_version_cnf_deviceid;
static int hf_vs_get_version_cnf_imgidx;
static int hf_vs_get_version_cnf_appversion;
static int hf_vs_get_version_cnf_avstackversion;
static int hf_vs_get_version_cnf_appalternate;
static int hf_vs_get_version_cnf_bootloaderversion;

static const value_string vertexcom_val_str_deviceid[] = {
    {0, "DEVICEID_MSE1000"},
    {1, "DEVICEID_SPC300"},
    {0, NULL},
};

static bool dissect_vs_get_version_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                       proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_VERSION_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_version_cnf, -1, 0x00000000,
                               ett_vs_get_version_cnf);
    ptvcursor_add(cursor, hf_vs_get_version_cnf_result, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_version_cnf_deviceid, 2, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_version_cnf_imgidx, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_version_cnf_appversion, 16, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_version_cnf_avstackversion, 64, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_version_cnf_appalternate, 16, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_version_cnf_bootloaderversion, 64, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_get_version(int proto) {
    static hf_register_info hf[] = {
        // VS_GET_VERSION.CNF
        {&hf_vs_get_version_cnf,
         {"MMENTRY (VS_GET_VERSION.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.get_version_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_version_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.get_version_cnf.result",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_fail_success), 0x0, NULL, HFILL}},
        {&hf_vs_get_version_cnf_deviceid,
         {"Device ID", "homeplug_av.mmtype.vertexcom.vs.get_version_cnf.deviceid",
          FT_UINT16, BASE_HEX, VALS(vertexcom_val_str_deviceid), 0x0, NULL, HFILL}},
        {&hf_vs_get_version_cnf_imgidx,
         {"Image Index", "homeplug_av.mmtype.vertexcom.vs.get_version_cnf.imgidx",
          FT_UINT8, BASE_DEC, NULL, 0x0, "Current image index", HFILL}},
        {&hf_vs_get_version_cnf_appversion,
         {"Applicative Version",
          "homeplug_av.mmtype.vertexcom.vs.get_version_cnf.appversion", FT_STRING,
          BASE_NONE, NULL, 0x0, "Current applicative layer version", HFILL}},
        {&hf_vs_get_version_cnf_avstackversion,
         {"AV Stack Version",
          "homeplug_av.mmtype.vertexcom.vs.get_version_cnf.avstackversion",
          FT_STRING, BASE_NONE, NULL, 0x0, "Current AV stack version", HFILL}},
        {&hf_vs_get_version_cnf_appalternate,
         {"Applicative Alternate",
          "homeplug_av.mmtype.vertexcom.vs.get_version_cnf.appalternate", FT_STRING,
          BASE_NONE, NULL, 0x0, "Alternate applicative layer version", HFILL}},
        {&hf_vs_get_version_cnf_bootloaderversion,
         {"Bootloader Version",
          "homeplug_av.mmtype.vertexcom.vs.get_version_cnf.bootloaderversion",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };
    static int* ett[] = {&ett_vs_get_version_cnf};

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_get_version_cnf, "VertexCom VS_GET_VERSION.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.get_version_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_RESET ####################
static int ett_vs_reset_cnf;
static int hf_vs_reset_cnf;
static int hf_vs_reset_cnf_result;

static bool dissect_vs_reset_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                 proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_RESET_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_reset_cnf, -1, 0x00000000,
                               ett_vs_reset_cnf);
    ptvcursor_add(cursor, hf_vs_reset_cnf_result, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_reset(int proto) {
    static hf_register_info hf[] = {
        // VS_RESET.CNF
        {&hf_vs_reset_cnf,
         {"MMENTRY (VS_RESET.CNF)", "homeplug_av.mmtype.vertexcom.vs.reset_cnf",
          FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_reset_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.reset_cnf.result", FT_BOOLEAN,
          BASE_NONE, TFS(&tfs_fail_success), 0x0, NULL, HFILL}},
    };
    proto_register_field_array(proto, hf, array_length(hf));

    static int* ett[] = {&ett_vs_reset_cnf};
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_reset_cnf,
                       "VertexCom VS_RESET.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.reset_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_GET_ETH_PHY ####################
static int ett_vs_get_eth_phy_cnf;
static int hf_vs_get_eth_phy_cnf;
static int hf_vs_get_eth_phy_cnf_result;
static int hf_vs_get_eth_phy_cnf_link;
static int hf_vs_get_eth_phy_cnf_speed;
static int hf_vs_get_eth_phy_cnf_duplex;
static int hf_vs_get_eth_phy_cnf_phy_address;

static const value_string vertexcom_val_str_link[] = {
    {0x00, "LINK_DISCONNECTED"},
    {0x01, "LINK_CONNECTED"},
    {0x02, "LINK_UNKNOWN"},
    {0, NULL},
};

static const value_string vertexcom_val_str_speed[] = {
    {0x00, "SPEED_10MBPS"},
    {0x01, "SPEED_100MBPS"},
    {0x02, "SPEED_1000MBPS"},
    {0, NULL},
};

static const range_string vertexcom_rval_str_phy_address[] = {
    {0x00, 0x1f, "PHY_ADDR"},
    {0x20, 0xff, "PHY_ADDR_RESERVED"},
    {0, 0, NULL},
};

static bool dissect_vs_get_eth_phy_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                       proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_ETH_PHY_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_eth_phy_cnf, -1, 0x00000000,
                               ett_vs_get_eth_phy_cnf);
    ptvcursor_add(cursor, hf_vs_get_eth_phy_cnf_result, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_eth_phy_cnf_link, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_eth_phy_cnf_speed, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_eth_phy_cnf_duplex, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_eth_phy_cnf_phy_address, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_get_eth_phy(int proto) {
    static hf_register_info hf[] = {
        // VS_GET_ETH_PHY.CNF
        {&hf_vs_get_eth_phy_cnf,
         {"MMENTRY (VS_GET_ETH_PHY.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.get_eth_phy_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_eth_phy_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.get_eth_phy_cnf.result",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_fail_success), 0x0, NULL, HFILL}},
        {&hf_vs_get_eth_phy_cnf_link,
         {"Link", "homeplug_av.mmtype.vertexcom.vs.get_eth_phy_cnf.link", FT_UINT8,
          BASE_HEX, VALS(vertexcom_val_str_link), 0x0, NULL, HFILL}},
        {&hf_vs_get_eth_phy_cnf_speed,
         {"Speed", "homeplug_av.mmtype.vertexcom.vs.get_eth_phy_cnf.speed",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_speed), 0x0, NULL, HFILL}},
        {&hf_vs_get_eth_phy_cnf_duplex,
         {"Duplex", "homeplug_av.mmtype.vertexcom.vs.get_eth_phy_cnf.duplex",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_full_half), 0x0, NULL, HFILL}},
        {&hf_vs_get_eth_phy_cnf_phy_address,
         {"PHY Address",
          "homeplug_av.mmtype.vertexcom.vs.get_eth_phy_cnf.phy_address", FT_UINT8,
          BASE_HEX | BASE_RANGE_STRING, RVALS(vertexcom_rval_str_phy_address), 0x0,
          NULL, HFILL}},
    };

    static int* ett[] = {&ett_vs_get_eth_phy_cnf};

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_get_eth_phy_cnf, "VertexCom VS_GET_ETH_PHY.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.get_eth_phy_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_ETH_STATS ####################
static int ett_vs_eth_stats_req;
static int hf_vs_eth_stats_req;
static int hf_vs_eth_stats_req_command;

static int ett_vs_eth_stats_cnf;
static int hf_vs_eth_stats_cnf;
static int hf_vs_eth_stats_cnf_result;
static int hf_vs_eth_stats_cnf_rx_packets;
static int hf_vs_eth_stats_cnf_rx_good_packets;
static int hf_vs_eth_stats_cnf_rx_unicast;
static int hf_vs_eth_stats_cnf_rx_multicast;
static int hf_vs_eth_stats_cnf_rx_broadcast;
static int hf_vs_eth_stats_cnf_rx_errors;
static int hf_vs_eth_stats_cnf_rx_fifo_overflow;
static int hf_vs_eth_stats_cnf_tx_packets;
static int hf_vs_eth_stats_cnf_tx_good_packets;
static int hf_vs_eth_stats_cnf_tx_unicast;
static int hf_vs_eth_stats_cnf_tx_multicast;
static int hf_vs_eth_stats_cnf_tx_broadcast;
static int hf_vs_eth_stats_cnf_tx_errors;
static int hf_vs_eth_stats_cnf_tx_fifo_underflow;
static int hf_vs_eth_stats_cnf_tx_collisions;
static int hf_vs_eth_stats_cnf_tx_carrier_errors;

static bool dissect_vs_eth_stats_req(tvbuff_t* tvb, packet_info* pinfo,
                                     proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_ETH_STATS_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_eth_stats_req, -1, 0x00000000,
                               ett_vs_eth_stats_req);
    ptvcursor_add(cursor, hf_vs_eth_stats_req_command, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_eth_stats_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                     proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_ETH_STATS_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_eth_stats_cnf, -1, 0x00000000,
                               ett_vs_eth_stats_cnf);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_result, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_rx_packets, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_rx_good_packets, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_rx_unicast, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_rx_multicast, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_rx_broadcast, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_rx_errors, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_rx_fifo_overflow, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_tx_packets, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_tx_good_packets, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_tx_unicast, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_tx_multicast, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_tx_broadcast, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_tx_errors, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_tx_fifo_underflow, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_tx_collisions, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_eth_stats_cnf_tx_carrier_errors, 4, 0x80000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_eth_stats(int proto) {
    static hf_register_info hf[] = {
        // VS_ETH_STATS.REQ
        {&hf_vs_eth_stats_req,
         {"MMENTRY (VS_ETH_STATS.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_req", FT_NONE, BASE_NONE, NULL,
          0x0, NULL, HFILL}},
        {&hf_vs_eth_stats_req_command,
         {"Command", "homeplug_av.mmtype.vertexcom.vs.eth_stats_req.command",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_stats_command), 0x0, NULL,
          HFILL}},
        // VS_ETH_STATS.CNF
        {&hf_vs_eth_stats_cnf,
         {"MMENTRY (VS_ETH_STATS.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf", FT_NONE, BASE_NONE, NULL,
          0x0, NULL, HFILL}},
        {&hf_vs_eth_stats_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.result",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_fail_success), 0x0, NULL, HFILL}},
        {&hf_vs_eth_stats_cnf_rx_packets,
         {"Rx Packets", "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.rx_packets",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Rx packets", HFILL}},
        {&hf_vs_eth_stats_cnf_rx_good_packets,
         {"Rx Good Packets",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.rx_good_packets",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Rx good packets", HFILL}},
        {&hf_vs_eth_stats_cnf_rx_unicast,
         {"Rx Unicast", "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.rx_unicast",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Rx unicast", HFILL}},
        {&hf_vs_eth_stats_cnf_rx_multicast,
         {"Rx Multicast",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.rx_multicast", FT_UINT32,
          BASE_DEC, NULL, 0x0, "Number of Rx multicast", HFILL}},
        {&hf_vs_eth_stats_cnf_rx_broadcast,
         {"Rx Broadcast",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.rx_broadcast", FT_UINT32,
          BASE_DEC, NULL, 0x0, "Number of Rx broadcast", HFILL}},
        {&hf_vs_eth_stats_cnf_rx_errors,
         {"Rx Errors", "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.rx_errors",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Rx errors", HFILL}},
        {&hf_vs_eth_stats_cnf_rx_fifo_overflow,
         {"Rx FIFO Overflow",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.rx_fifo_overflow",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Rx FIFO overflow", HFILL}},
        {&hf_vs_eth_stats_cnf_tx_packets,
         {"Tx Packets", "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.tx_packets",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Tx packets", HFILL}},
        {&hf_vs_eth_stats_cnf_tx_good_packets,
         {"Tx Good Packets",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.tx_good_packets",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Tx good packets", HFILL}},
        {&hf_vs_eth_stats_cnf_tx_unicast,
         {"Tx Unicast", "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.tx_unicast",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Tx unicast", HFILL}},
        {&hf_vs_eth_stats_cnf_tx_multicast,
         {"Tx Multicast",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.tx_multicast", FT_UINT32,
          BASE_DEC, NULL, 0x0, "Number of Tx multicast", HFILL}},
        {&hf_vs_eth_stats_cnf_tx_broadcast,
         {"Tx Broadcast",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.tx_broadcast", FT_UINT32,
          BASE_DEC, NULL, 0x0, "Number of Tx broadcast", HFILL}},
        {&hf_vs_eth_stats_cnf_tx_errors,
         {"Tx Errors", "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.tx_errors",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Tx errors", HFILL}},
        {&hf_vs_eth_stats_cnf_tx_fifo_underflow,
         {"Tx FIFO Underflow",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.tx_fifo_underflow",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Tx FIFO underflow", HFILL}},
        {&hf_vs_eth_stats_cnf_tx_collisions,
         {"Tx Collisions",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.tx_collisions", FT_UINT32,
          BASE_DEC, NULL, 0x0, "Number of Tx collisions", HFILL}},
        {&hf_vs_eth_stats_cnf_tx_carrier_errors,
         {"Tx Carrier Errors",
          "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf.tx_carrier_errors",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Tx carrier errors", HFILL}}};

    static int* ett[] = {&ett_vs_eth_stats_req, &ett_vs_eth_stats_cnf};

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_eth_stats_req,
                       "VertexCom VS_ETH_STATS.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.eth_stats_req", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_eth_stats_cnf,
                       "VertexCom VS_ETH_STATS.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.eth_stats_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_GET_STATUS ####################
static int ett_vs_get_status_cnf;
static int hf_vs_get_status_cnf;
static int hf_vs_get_status_cnf_result;
static int hf_vs_get_status_cnf_status;
static int hf_vs_get_status_cnf_cco;
static int hf_vs_get_status_cnf_preferred_cco;
static int hf_vs_get_status_cnf_backup_cco;
static int hf_vs_get_status_cnf_proxy_cco;
static int hf_vs_get_status_cnf_simple_connect;
static int hf_vs_get_status_cnf_link_state;
static int hf_vs_get_status_cnf_ready_for_plc;
static int hf_vs_get_status_cnf_frequency_error;
static int hf_vs_get_status_cnf_frequency_offset;
static int hf_vs_get_status_cnf_uptime;
static int hf_vs_get_status_cnf_authenticated_time;
static int hf_vs_get_status_cnf_authenticated_count;

static const value_string vertexcom_val_str_status[] = {
    {0x00, "Unassociated"},
    {0x01, "Associated"},
    {0x02, "Authenticated"},
    {0, NULL},
};

static const value_string vertexcom_val_str_cco[] = {
    {0x00, "Not CCO"},
    {0x01, "CCO"},
    {0, NULL},
};

static const value_string vertexcom_val_str_preferred_cco[] = {
    {0x00, "Not Preferred CCO"},
    {0x01, "Preferred CCO"},
    {0, NULL},
};

static const value_string vertexcom_val_str_backup_cco[] = {
    {0x00, "Not Backup CCO"},
    {0x01, "Backup CCO"},
    {0, NULL},
};

static const value_string vertexcom_val_str_proxy_cco[] = {
    {0x00, "Not Proxy CCO"},
    {0x01, "Proxy CCO"},
    {0, NULL},
};

static const value_string vertexcom_val_str_simple_connect[] = {
    {0x00, "Not Support Simple Connect"},
    {0x01, "Support Simple Connect"},
    {0, NULL},
};

static const value_string vertexcom_val_str_link_state[] = {
    {0x00, "Disconnected"},
    {0x01, "Connected"},
    {0x02, "Ready to Connect"},
    {0, NULL},
};

static const value_string vertexcom_val_str_ready_for_plc[] = {
    {0x00, "Not Ready"},
    {0x01, "Ready"},
    {0, NULL},
};

static bool dissect_vs_get_status_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                      proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_STATUS_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_status_cnf, -1, 0x00000000,
                               ett_vs_get_status_cnf);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_result, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_status, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_cco, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_preferred_cco, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_backup_cco, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_proxy_cco, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_simple_connect, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_link_state, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_ready_for_plc, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_frequency_error, 8, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_frequency_offset, 8, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_uptime, 8, 0x80000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_authenticated_time, 8, 0x80000000);
    ptvcursor_add(cursor, hf_vs_get_status_cnf_authenticated_count, 2, 0x80000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_get_status(int proto) {
    static hf_register_info hf[] = {
        // VS_GET_STATUS.CNF
        {&hf_vs_get_status_cnf,
         {"MMENTRY (VS_GET_STATUS.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.get_status_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.result",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_fail_success), 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_status,
         {"Status", "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.status",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_status), 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_cco,
         {"CCO", "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.cco", FT_UINT8,
          BASE_HEX, VALS(vertexcom_val_str_cco), 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_preferred_cco,
         {"Preferred CCO",
          "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.preferred_cco", FT_UINT8,
          BASE_HEX, VALS(vertexcom_val_str_preferred_cco), 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_backup_cco,
         {"Backup CCO", "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.backup_cco",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_backup_cco), 0x0, NULL,
          HFILL}},
        {&hf_vs_get_status_cnf_proxy_cco,
         {"Proxy CCO", "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.proxy_cco",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_proxy_cco), 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_simple_connect,
         {"Simple Connect",
          "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.simple_connect", FT_UINT8,
          BASE_HEX, VALS(vertexcom_val_str_simple_connect), 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_link_state,
         {"Link State", "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.link_state",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_link_state), 0x0, NULL,
          HFILL}},
        {&hf_vs_get_status_cnf_ready_for_plc,
         {"Ready for PLC operation",
          "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.ready_for_plc", FT_UINT8,
          BASE_HEX, VALS(vertexcom_val_str_ready_for_plc), 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_frequency_error,
         {"Frequency Error (mppm)",
          "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.frequency_error",
          FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_frequency_offset,
         {"Frequency Offset",
          "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.frequency_offset",
          FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_uptime,
         {"Uptime (Second)",
          "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.uptime", FT_UINT64,
          BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_authenticated_time,
         {"Authenticated Time (Second)",
          "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.authenticated_time",
          FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_status_cnf_authenticated_count,
         {"Authenticated Count",
          "homeplug_av.mmtype.vertexcom.vs.get_status_cnf.authenticated_count",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    };

    static int* ett[] = {
        &ett_vs_get_status_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_get_status_cnf,
                       "VertexCom VS_GET_STATUS.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.get_status_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_GET_SNR ####################
static int ett_vs_get_snr_req;
static int hf_vs_get_snr_req;
static int hf_vs_get_snr_req_station_address;
static int hf_vs_get_snr_req_interval_index;
static int hf_vs_get_snr_req_interval_id;
static int hf_vs_get_snr_req_carrier_group;

static int ett_vs_get_snr_cnf;
static int hf_vs_get_snr_cnf;
static int hf_vs_get_snr_cnf_result;
static int hf_vs_get_snr_cnf_interval_id;
static int hf_vs_get_snr_cnf_interval_list_length;
static int hf_vs_get_snr_cnf_interval_list;
static int hf_vs_get_snr_cnf_interval_list_end_time;
static int hf_vs_get_snr_cnf_tm_ber;
static int hf_vs_get_snr_cnf_carrier_group;
static int hf_vs_get_snr_cnf_snr_list;
static int hf_vs_get_snr_cnf_snr_list_carrier_snr;

static int ett_vs_get_snr_cnf_interval_list;
static int ett_vs_get_snr_cnf_snr_list;

static const range_string vertexcom_rval_str_snr_interval[] = {
    {0x00, 0x1f, "Tonemap interval index"},
    {0x20, 0xfd, "Reserved"},
    {0xfe, 0xfe, "No negotiated tonemap"},
    {0xff, 0xff, "To get current intervals lists"},
    {0, 0, NULL},
};

static const range_string vertexcom_rval_string_snr_carrier_group[] = {
    {0x00, 0x00, "Carrier group 0"}, {0x01, 0x01, "Carrier group 1"},
    {0x02, 0x02, "Carrier group 2"}, {0x03, 0x03, "Carrier group 3"},
    {0x04, 0xff, "Reserved"},        {0, 0, NULL},
};

static const value_string vertexcom_val_str_snr_result[] = {
    {0x00, "Success"},
    {0x01, "Failure"},
    {0x02, "Bad tonemap interval list identifier"},
    {0x03, "No negotiated tonemap"},
    {0, NULL},
};

static bool dissect_vs_get_snr_req(tvbuff_t* tvb, packet_info* pinfo,
                                   proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_SNR_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_snr_req, -1, 0x00000000,
                               ett_vs_get_snr_req);
    ptvcursor_add(cursor, hf_vs_get_snr_req_station_address, 6, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_snr_req_interval_index, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_snr_req_interval_id, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_snr_req_carrier_group, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_get_snr_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                   proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_SNR_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    proto_item* it = NULL;
    uint32_t ret_interval_list_length = 0;
    uint32_t ret_inverval_list_end_time = 0;
    uint32_t ret_carrier_group = 0;
    int32_t ret_snr = 0;
    uint32_t snr_index = 0;
    double end_time_us = 0.0;
    double end_time_ms = 0.0;

    ptvcursor_add_with_subtree(cursor, hf_vs_get_snr_cnf, -1, 0x00000000,
                               ett_vs_get_snr_cnf);
    ptvcursor_add(cursor, hf_vs_get_snr_cnf_result, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_snr_cnf_interval_id, 1, 0x00000000);
    ptvcursor_add_ret_uint(cursor, hf_vs_get_snr_cnf_interval_list_length, 1,
                           0x00000000, &ret_interval_list_length);
    if (ret_interval_list_length > 0) {
        ptvcursor_add_with_subtree(cursor, hf_vs_get_snr_cnf_interval_list, -1,
                                   0x00000000, ett_vs_get_snr_cnf_interval_list);
        for (uint32_t i = 0; i < ret_interval_list_length; i++) {
            it = ptvcursor_add_ret_uint(cursor,
                                        hf_vs_get_snr_cnf_interval_list_end_time, 2,
                                        0x80000000, &ret_inverval_list_end_time);
            proto_item_set_text(it, "EndTime#%d : %d", i,
                                ret_inverval_list_end_time);
            end_time_us = (double)ret_inverval_list_end_time * 10.24;
            if (end_time_us > 1e3) {
                end_time_ms = (double)(end_time_us / 1e3);
                proto_item_append_text(it, " (%lf ms)", end_time_ms);
            } else {
                proto_item_append_text(it, " (%lf us)", end_time_us);
            }
        }
        ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_add(cursor, hf_vs_get_snr_cnf_tm_ber, 2, 0x80000000);
    ptvcursor_add_ret_uint(cursor, hf_vs_get_snr_cnf_carrier_group, 1, 0x00000000,
                           &ret_carrier_group);
    if (ret_carrier_group <= 0x03) {
        ptvcursor_add_with_subtree(cursor, hf_vs_get_snr_cnf_snr_list, -1,
                                   0x00000000, ett_vs_get_snr_cnf_snr_list);
        for (uint32_t i = 0; i < 1024; i++) {
            snr_index = i * 4 + ret_carrier_group;
            it = ptvcursor_add_ret_int(cursor,
                                       hf_vs_get_snr_cnf_snr_list_carrier_snr, 1,
                                       0x00000000, &ret_snr);
            proto_item_set_text(it, "Carrier %d SNR: %d dB", snr_index,
                                (int8_t)ret_snr);
        }
        ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_get_snr(int proto) {
    static hf_register_info hf[] = {
        // VS_GET_SNR.REQ
        {&hf_vs_get_snr_req,
         {"MMENTRY (VS_GET_SNR.REQ)", "homeplug_av.mmtype.vertexcom.vs.get_snr_req",
          FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_snr_req_station_address,
         {"Station_address",
          "homeplug_av.mmtype.vertexcom.vs.get_snr_req.station_address", FT_ETHER,
          BASE_NONE, NULL, 0x0, "MAC address of the remote peer station", HFILL}},
        {&hf_vs_get_snr_req_interval_index,
         {"Interval index",
          "homeplug_av.mmtype.vertexcom.vs.get_snr_req.interval_index", FT_UINT8,
          BASE_HEX | BASE_RANGE_STRING, RVALS(vertexcom_rval_str_snr_interval), 0x0,
          "Tonemap interval index", HFILL}},
        {&hf_vs_get_snr_req_interval_id,
         {"Interval ID", "homeplug_av.mmtype.vertexcom.vs.get_snr_req.interval_id",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          "Current tonemap interval list identifier (No meaning if INT=0xff)",
          HFILL}},
        {&hf_vs_get_snr_req_carrier_group,
         {"Carrier_group",
          "homeplug_av.mmtype.vertexcom.vs.get_snr_req.carrier_group", FT_UINT8,
          BASE_HEX | BASE_RANGE_STRING,
          RVALS(vertexcom_rval_string_snr_carrier_group), 0x00,
          "Carrier group modulo 4", HFILL}},
        // VS_GET_SNR.CNF
        {&hf_vs_get_snr_cnf,
         {"MMENTRY (VS_GET_SNR.CNF)", "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf",
          FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_snr_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf.result", FT_UINT8,
          BASE_HEX, VALS(vertexcom_val_str_snr_result), 0x0, NULL, HFILL}},
        {&hf_vs_get_snr_cnf_interval_id,
         {"Interval ID", "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf.interval_id",
          FT_UINT8, BASE_HEX, NULL, 0x0,
          "Current tonemap interval list identifier (No meaning if INT=0xff)",
          HFILL}},
        {&hf_vs_get_snr_cnf_interval_list_length,
         {"Interval list length",
          "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf.interval_list_length",
          FT_UINT8, BASE_DEC, NULL, 0x0, "Length of the interval list", HFILL}},
        // VS_GET_SNR.CNF - Interval list >>
        {&hf_vs_get_snr_cnf_interval_list,
         {"Interval list",
          "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf.interval_list", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_snr_cnf_interval_list_end_time,
         {"Interval end time",
          "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf.interval_list.end_time",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "End time of interval in allocation time unit (10.24us)", HFILL}},
        // << VS_GET_SNR.CNF - Interval list
        {&hf_vs_get_snr_cnf_tm_ber,
         {"TM_BER", "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf.tm_ber", FT_UINT16,
          BASE_DEC, NULL, 0x0, "Average Bit Error Rate", HFILL}},
        {&hf_vs_get_snr_cnf_carrier_group,
         {"Carrier_group",
          "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf.carrier_group", FT_UINT8,
          BASE_HEX | BASE_RANGE_STRING,
          RVALS(vertexcom_rval_string_snr_carrier_group), 0x00,
          "Carrier group modulo 4", HFILL}},
        // VS_GET_SNR.CNF - SNR list >>
        {&hf_vs_get_snr_cnf_snr_list,
         {"SNR list", "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf.snr_list",
          FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_snr_cnf_snr_list_carrier_snr,
         {"Carrier SNR",
          "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf.snr_list.carrier_snr",
          FT_INT8, BASE_DEC, NULL, 0x0, "SNR of Carrier", HFILL}}};

    static int* ett[] = {
        &ett_vs_get_snr_req,
        &ett_vs_get_snr_cnf,
        &ett_vs_get_snr_cnf_interval_list,
        &ett_vs_get_snr_cnf_snr_list,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_get_snr_req,
                       "VertexCom VS_GET_SNR.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.get_snr_req", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_get_snr_cnf,
                       "VertexCom VS_GET_SNR.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.get_snr_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_GET_LINK_STATS ####################
static int ett_vs_get_link_stats_req;
static int hf_vs_get_link_stats_req;

static int hf_vs_get_link_stats_req_reqtype;
static int hf_vs_get_link_stats_req_reqid;
static int hf_vs_get_link_stats_req_lid;
static int hf_vs_get_link_stats_req_tlflag;
static int hf_vs_get_link_stats_req_mgmt_flag;
static int hf_vs_get_link_stats_req_dasa;

static int ett_vs_get_link_stats_cnf;
static int hf_vs_get_link_stats_cnf;
static int hf_vs_get_link_stats_cnf_reqid;
static int hf_vs_get_link_stats_cnf_result;

static int ett_vs_get_link_stats_cnf_tx;
static int hf_vs_get_link_stats_cnf_tx;
static int hf_vs_get_link_stats_cnf_tx_msdu_seg_success;
static int hf_vs_get_link_stats_cnf_tx_mpdu;
static int hf_vs_get_link_stats_cnf_tx_mpdu_burst;
static int hf_vs_get_link_stats_cnf_tx_mpdu_acked;
static int hf_vs_get_link_stats_cnf_tx_mpdu_coll;
static int hf_vs_get_link_stats_cnf_tx_mpdu_fail;
static int hf_vs_get_link_stats_cnf_tx_pb_success;
static int hf_vs_get_link_stats_cnf_tx_pb_dropped;
static int hf_vs_get_link_stats_cnf_tx_pb_crc_fail;
static int hf_vs_get_link_stats_cnf_tx_buf_shortage_drop;

static int ett_vs_get_link_stats_cnf_rx;
static int hf_vs_get_link_stats_cnf_rx;
static int hf_vs_get_link_stats_cnf_rx_msdu_success;
static int hf_vs_get_link_stats_cnf_rx_mpdu_received;
static int hf_vs_get_link_stats_cnf_rx_burst_mpdu_received;
static int hf_vs_get_link_stats_cnf_rx_mpdu_acked;
static int hf_vs_get_link_stats_cnf_rx_mpdu_fail;
static int hf_vs_get_link_stats_cnf_rx_mpdu_icv_fail;
static int hf_vs_get_link_stats_cnf_rx_pbs;
static int hf_vs_get_link_stats_cnf_rx_pbs_success;
static int hf_vs_get_link_stats_cnf_rx_pbs_duplicated;
static int hf_vs_get_link_stats_cnf_rx_pbs_crc_fail;
static int hf_vs_get_link_stats_cnf_rx_sum_of_ber_in_pbs_success;
static int hf_vs_get_link_stats_cnf_rx_ssn_under_min;
static int hf_vs_get_link_stats_cnf_rx_ssn_over_max;
static int hf_vs_get_link_stats_cnf_rx_pbs_missed;

static const value_string vertexcom_val_str_link_stats_reqtype[] = {
    {0x00, "Reset statistics for the corresponding Link"},
    {0x01, "Get statistics for the corresponding Link"},
    {0x02, "Get and reset statistics for the corresponding Link"},
    {0, NULL},
};

static const value_string vertexcom_val_str_link_stats_tlflag[] = {
    {0x00, "Transmit Link"},
    {0x01, "Receive Link"},
    {0, NULL},
};

static const value_string vertexcom_val_str_link_stats_mgmt_flag[] = {
    {0x00, "Not Management Link"},
    {0x01, "Management Link"},
    {0, NULL},
};

uint32_t ret_tlflag = 0xff;

static bool dissect_vs_get_link_stats_req(tvbuff_t* tvb, packet_info* pinfo,
                                          proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_LINK_STATS_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    proto_item* it = NULL;

    ptvcursor_add_with_subtree(cursor, hf_vs_get_link_stats_req, -1, 0x00000000,
                               ett_vs_get_link_stats_req);
    ptvcursor_add(cursor, hf_vs_get_link_stats_req_reqtype, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_link_stats_req_reqid, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_link_stats_req_lid, 1, 0x00000000);
    ptvcursor_add_ret_uint(cursor, hf_vs_get_link_stats_req_tlflag, 1, 0x00000000,
                           &ret_tlflag);
    ptvcursor_add(cursor, hf_vs_get_link_stats_req_mgmt_flag, 1, 0x00000000);
    it = ptvcursor_add(cursor, hf_vs_get_link_stats_req_dasa, 6, 0x00000000);
    if (ret_tlflag == 0) {  // transmit link
        proto_item_append_text(it, " ((Destination MAC)");
    } else if (ret_tlflag == 1) {  // receive link
        proto_item_append_text(it, " (Source MAC)");
    }
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_get_link_stats_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                          proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_LINK_STATS_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_link_stats_cnf, -1, 0x00000000,
                               ett_vs_get_link_stats_cnf);
    ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_reqid, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_result, 1, 0x00000000);
    if (ret_tlflag == 0) {  // transmit Link
        ptvcursor_add_with_subtree(cursor, hf_vs_get_link_stats_cnf_tx, -1,
                                   0x00000000, ett_vs_get_link_stats_cnf_tx);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_tx_msdu_seg_success, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_tx_mpdu, 4, 0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_tx_mpdu_burst, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_tx_mpdu_acked, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_tx_mpdu_coll, 4, 0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_tx_mpdu_fail, 4, 0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_tx_pb_success, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_tx_pb_dropped, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_tx_pb_crc_fail, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_tx_buf_shortage_drop, 4,
                      0x80000000);
        ptvcursor_pop_subtree(cursor);
    } else if (ret_tlflag == 1) {  // receive Link
        ptvcursor_add_with_subtree(cursor, hf_vs_get_link_stats_cnf_rx, -1,
                                   0x00000000, ett_vs_get_link_stats_cnf_rx);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_msdu_success, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_mpdu_received, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_burst_mpdu_received, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_mpdu_acked, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_mpdu_fail, 4, 0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_mpdu_icv_fail, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_pbs, 4, 0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_pbs_success, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_pbs_duplicated, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_pbs_crc_fail, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_sum_of_ber_in_pbs_success,
                      8, 0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_ssn_under_min, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_ssn_over_max, 4,
                      0x80000000);
        ptvcursor_add(cursor, hf_vs_get_link_stats_cnf_rx_pbs_missed, 4,
                      0x80000000);
        ptvcursor_pop_subtree(cursor);
    }
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_get_link_stats(int proto) {
    static hf_register_info hf[] = {
        // VS_GET_LINK_STATS.REQ
        {&hf_vs_get_link_stats_req,
         {"MMENTRY (VS_GET_LINK_STATS.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_req", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_link_stats_req_reqtype,
         {"ReqType", "homeplug_av.mmtype.vertexcom.vs.get_link_stats_req.reqtype",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_link_stats_reqtype), 0x0,
          "Request Type", HFILL}},
        {&hf_vs_get_link_stats_req_reqid,
         {"ReqID", "homeplug_av.mmtype.vertexcom.vs.get_link_stats_req.reqid",
          FT_UINT8, BASE_HEX, NULL, 0x0, "Request Identifier", HFILL}},
        {&hf_vs_get_link_stats_req_lid,
         {"LID", "homeplug_av.mmtype.vertexcom.vs.get_link_stats_req.lid", FT_UINT8,
          BASE_HEX, NULL, 0x0,
          "Link Identifier (valid only when the Mgmt_Flag is set to 0x00)", HFILL}},
        {&hf_vs_get_link_stats_req_tlflag,
         {"TLFlag", "homeplug_av.mmtype.vertexcom.vs.get_link_stats_req.tlflag",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_link_stats_tlflag), 0x0,
          "Transmit Link Flag", HFILL}},
        {&hf_vs_get_link_stats_req_mgmt_flag,
         {"MgmtFlag",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_req.mgmt_flag", FT_UINT8,
          BASE_HEX, VALS(vertexcom_val_str_link_stats_mgmt_flag), 0x0,
          "Management Link flag", HFILL}},
        {&hf_vs_get_link_stats_req_dasa,
         {"DA/SA", "homeplug_av.mmtype.vertexcom.vs.get_link_stats_req.dasa",
          FT_ETHER, BASE_NONE, NULL, 0x0,
          "Indicate the Destination or Source MAC Address depending on TLFlag",
          HFILL}},
        // VS_GET_LINK_STATS.CNF
        {&hf_vs_get_link_stats_cnf,
         {"MMENTRY (VS_GET_LINK_STATS.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_link_stats_cnf_reqid,
         {"ReqID", "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.reqid",
          FT_UINT8, BASE_HEX, NULL, 0x0, "Request Identifier", HFILL}},
        {&hf_vs_get_link_stats_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.result",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_fail_success), 0x0, NULL, HFILL}},
        // VS_GET_LINK_STATS.CNF - TX Link Statistics >>
        {&hf_vs_get_link_stats_cnf_tx,
         {"TX Link Statistics",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_link_stats_cnf_tx_msdu_seg_success,
         {"Tx_MSDU_seg_success",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx.msdu_seg_success",
          FT_UINT32, BASE_DEC, NULL, 0x0, "MSDU segmentation success", HFILL}},
        {&hf_vs_get_link_stats_cnf_tx_mpdu,
         {"Tx_MPDU", "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx.mpdu",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of MPDUs transmitted", HFILL}},
        {&hf_vs_get_link_stats_cnf_tx_mpdu_burst,
         {"Tx_MPDU_burst",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx.mpdu_burst",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of MPDU bursts transmitted",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_tx_mpdu_acked,
         {"Tx_MPDU_acked",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx.mpdu_acked",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of MPDUs transmitted and acked",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_tx_mpdu_coll,
         {"Tx_MPDU_coll",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx.mpdu_coll",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of transmitted with collision",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_tx_mpdu_fail,
         {"Tx_MPDU_fail",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx.mpdu_fail",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of MPDUs transmitted but failed",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_tx_pb_success,
         {"Tx_PB_success",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx.pb_success",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of PBs transmitted and succeeded",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_tx_pb_dropped,
         {"Tx_PB_dropped",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx.pb_dropped",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of PBs transmitted but dropped",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_tx_pb_crc_fail,
         {"Tx_PB_CRC_fail",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx.pb_crc_fail",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of PBs transmitted with CRC error", HFILL}},
        {&hf_vs_get_link_stats_cnf_tx_buf_shortage_drop,
         {"Tx_BUF_shortage_drop",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.tx.buf_shortage_drop",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of buffer shortage events",
          HFILL}},
        // VS_GET_LINK_STATS.CNF - RX Link Statistics >>
        {&hf_vs_get_link_stats_cnf_rx,
         {"RX Link Statistics",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_msdu_success,
         {"Rx_MSDU_success",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.msdu_success",
          FT_UINT32, BASE_DEC, NULL, 0x0, "MSDU re-assembly successful", HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_mpdu_received,
         {"Rx_MPDU_received",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.mpdu_received",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of MPDUs received", HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_burst_mpdu_received,
         {"Rx_Burst_MPDU_received",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.burst_mpdu_"
          "received",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of burst MPDUs received", HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_mpdu_acked,
         {"Rx_MPDU_acked",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.mpdu_acked",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of MPDUs received and acked",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_mpdu_fail,
         {"Rx_MPDU_fail",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.mpdu_fail",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of MPDUs received and failed",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_mpdu_icv_fail,
         {"Rx_MPDU_ICV_fail",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.mpdu_icv_fail",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of MPDUs received with ICV failure", HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_pbs,
         {"Rx_PBs", "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.pbs",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of PBs received", HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_pbs_success,
         {"Rx_PBs_success",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.pbs_success",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of PBs received for re-assembly",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_pbs_duplicated,
         {"Rx_PBs_duplicated",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.pbs_duplicated",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of PBs received but duplicated",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_pbs_crc_fail,
         {"Rx_PBs_crc_fail",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.pbs_crc_fail",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of PBs received with CRC error",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_sum_of_ber_in_pbs_success,
         {"Rx_sum_of_BER_in_PBs_success",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.sum_of_ber_in_pbs_"
          "success",
          FT_UINT64, BASE_DEC, NULL, 0x0, "Sum of BER in PBs successfully received",
          HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_ssn_under_min,
         {"Rx_SSN_under_MIN",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.ssn_under_min",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of SSN under MIN", HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_ssn_over_max,
         {"Rx_SSN_over_MAX",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.ssn_over_max",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of SSN over MAX", HFILL}},
        {&hf_vs_get_link_stats_cnf_rx_pbs_missed,
         {"Rx_PBs_missed",
          "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf.rx.pbs_missed",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of PBs  missed", HFILL}},
    };

    static int* ett[] = {
        &ett_vs_get_link_stats_req,
        &ett_vs_get_link_stats_cnf,
        &ett_vs_get_link_stats_cnf_tx,
        &ett_vs_get_link_stats_cnf_rx,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_get_link_stats_req,
                       "VertexCom VS_GET_LINK_STATS.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.get_link_stats_req", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_get_link_stats_cnf,
                       "VertexCom VS_GET_LINK_STATS.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.get_link_stats_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_GET_NW_INFO ####################
static int ett_vs_get_nw_info_cnf;
static int hf_vs_get_nw_info_cnf;
static int hf_vs_get_nw_info_cnf_nid;
static int hf_vs_get_nw_info_cnf_snid;
static int hf_vs_get_nw_info_cnf_cco_tei;
static int hf_vs_get_nw_info_cnf_cco_macaddr;
static int hf_vs_get_nw_info_cnf_numstas;

static int ett_vs_get_nw_info_cnf_sta_list;
static int hf_vs_get_nw_info_cnf_sta_list;

static int ett_vs_get_nw_info_cnf_sta_list_sta;
static int hf_vs_get_nw_info_cnf_sta_list_sta;
static int hf_vs_get_nw_info_cnf_sta_list_sta_tei;
static int hf_vs_get_nw_info_cnf_sta_list_sta_macaddr;
static int hf_vs_get_nw_info_cnf_sta_list_sta_phy_tx_coded;
static int hf_vs_get_nw_info_cnf_sta_list_sta_phy_tx_raw;
static int hf_vs_get_nw_info_cnf_sta_list_sta_phy_rx_coded;
static int hf_vs_get_nw_info_cnf_sta_list_sta_phy_rx_raw;
static int hf_vs_get_nw_info_cnf_sta_list_sta_agc_gain;

static const range_string vertexcom_rval_str_nw_info_tei[] = {
    {0, 0, "TEI_NOT_YET_ASSIGNED"},
    {1, 0xFE, "TEI_WITHIN_THE_AVLNS"},
    {0xFF, 0xFF, "TEI_BROADCAST_TEI"},
    {0, 0, NULL},
};

static bool dissect_vs_get_nw_info_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                       proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NW_INFO_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    proto_item* it = NULL;
    uint32_t ret_numstas = 0;

    ptvcursor_add_with_subtree(cursor, hf_vs_get_nw_info_cnf, -1, 0x00000000,
                               ett_vs_get_nw_info_cnf);
    ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_nid, 7, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_snid, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_cco_tei, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_cco_macaddr, 6, 0x00000000);
    ptvcursor_add_ret_uint(cursor, hf_vs_get_nw_info_cnf_numstas, 1, 0x00000000,
                           &ret_numstas);

    if (ret_numstas > 0) {
        ptvcursor_add_with_subtree(cursor, hf_vs_get_nw_info_cnf_sta_list, -1,
                                   0x00000000, ett_vs_get_nw_info_cnf_sta_list);
        for (uint32_t i = 0; i < ret_numstas; i++) {
            it = ptvcursor_add_no_advance(cursor, hf_vs_get_nw_info_cnf_sta_list,
                                          16, ENC_NA);
            ptvcursor_push_subtree(cursor, it, ett_vs_get_nw_info_cnf_sta_list_sta);
            proto_item_set_text(it, "STA#%d", i);

            ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_sta_list_sta_tei, 1,
                          0x00000000);
            ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_sta_list_sta_macaddr, 6,
                          0x00000000);
            ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_sta_list_sta_phy_tx_coded,
                          2, 0x80000000);
            ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_sta_list_sta_phy_tx_raw, 2,
                          0x80000000);
            ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_sta_list_sta_phy_rx_coded,
                          2, 0x80000000);
            ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_sta_list_sta_phy_rx_raw, 2,
                          0x80000000);
            ptvcursor_add(cursor, hf_vs_get_nw_info_cnf_sta_list_sta_agc_gain, 1,
                          0x00000000);

            ptvcursor_pop_subtree(cursor);
        }
    }
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_get_nw_info(int proto) {
    static hf_register_info hf[] = {
        // VS_GET_NW_INFO.CNF
        {&hf_vs_get_nw_info_cnf,
         {"MMENTRY (VS_GET_NW_INFO.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_nw_info_cnf_nid,
         {"NID", "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.nid", FT_BYTES,
          SEP_DASH, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_nw_info_cnf_snid,
         {"SNID", "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.snid", FT_UINT8,
          BASE_HEX, NULL, 0xF, NULL, HFILL}},
        {&hf_vs_get_nw_info_cnf_cco_tei,
         {"CCO TEI", "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.cco_tei",
          FT_UINT8, BASE_HEX | BASE_RANGE_STRING,
          RVALS(vertexcom_rval_str_nw_info_tei), 0x0, NULL, HFILL}},
        {&hf_vs_get_nw_info_cnf_cco_macaddr,
         {"CCO MACAddr",
          "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.cco_macaddr", FT_ETHER,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_nw_info_cnf_numstas,
         {"NUM_STAs", "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.numstas",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        // VS_GET_NW_INFO.CNF - STA List >>
        {&hf_vs_get_nw_info_cnf_sta_list,
         {"STA List", "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.sta_list",
          FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_nw_info_cnf_sta_list_sta,
         {"STA", "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.sta_list.sta",
          FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_nw_info_cnf_sta_list_sta_tei,
         {"STA TEI",
          "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.sta_list.sta.tei",
          FT_UINT8, BASE_HEX, NULL, 0x0, "Terminal Equipment Identifier of STA#",
          HFILL}},
        {&hf_vs_get_nw_info_cnf_sta_list_sta_macaddr,
         {"STA MACAddr",
          "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.sta_list.sta.macaddr",
          FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_nw_info_cnf_sta_list_sta_phy_tx_coded,
         {"STA PHY TX Coded (Mbps)",
          "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.sta_list.sta.phy_tx_"
          "coded",
          FT_UINT16, BASE_DEC, NULL, 0x0, "Coded TX PHY rate (Mbps) of STA#",
          HFILL}},
        {&hf_vs_get_nw_info_cnf_sta_list_sta_phy_tx_raw,
         {"STA PHY TX Raw (Mbps)",
          "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.sta_list.sta.phy_tx_raw",
          FT_UINT16, BASE_DEC, NULL, 0x0, "Raw TX PHY rate (Mbps) of STA#", HFILL}},
        {&hf_vs_get_nw_info_cnf_sta_list_sta_phy_rx_coded,
         {"STA PHY RX Coded (Mbps)",
          "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.sta_list.sta.phy_rx_"
          "coded",
          FT_UINT16, BASE_DEC, NULL, 0x0, "Coded RX PHY rate (Mbps) of STA#",
          HFILL}},
        {&hf_vs_get_nw_info_cnf_sta_list_sta_phy_rx_raw,
         {"STA PHY RX Raw (Mbps)",
          "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.sta_list.sta.phy_rx_raw",
          FT_UINT16, BASE_DEC, NULL, 0x0, "Raw RX PHY rate (Mbps) of STA#", HFILL}},
        {&hf_vs_get_nw_info_cnf_sta_list_sta_agc_gain,
         {"STA AGC Gain",
          "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf.sta_list.sta.agc_gain",
          FT_UINT8, BASE_DEC, NULL, 0x0, "Rx AGC gain of STA#", HFILL}},
    };

    static int* ett[] = {
        &ett_vs_get_nw_info_cnf,
        &ett_vs_get_nw_info_cnf_sta_list,
        &ett_vs_get_nw_info_cnf_sta_list_sta,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_get_nw_info_cnf, "VertexCom VS_GET_NW_INFO.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.get_nw_info_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_SET_CAPTURE_STATE ####################
static int ett_vs_set_capture_state_req;
static int hf_vs_set_capture_state_req;
static int hf_vs_set_capture_state_req_station_address;
static int hf_vs_set_capture_state_req_state;
static int hf_vs_set_capture_state_req_captured;
static int hf_vs_set_capture_state_req_captured_source;

static int ett_vs_set_capture_state_cnf;
static int hf_vs_set_capture_state_cnf;
static int hf_vs_set_capture_state_cnf_result;

static const value_string vertexcom_val_str_capture_state[] = {
    {0x00, "Stop capture"},
    {0x01, "Start capture"},
    {0, NULL},
};

static const value_string vertexcom_val_str_captured[] = {
    {0x00, "to measure SNR"},
    {0, NULL},
};

static const value_string vertexcom_val_str_captured_source[] = {
    {0x00, "only based on MME frames"},
    {0x01, "only based on DATA frames"},
    {0x02, "based on both MME and DATA"},
    {0, NULL},
};

static const value_string vertexcom_val_str_capture_state_result[] = {
    {0x00, "Success"},
    {0x01, "Resource occupied"},
    {0x02, "No peer station"},
    {0x03, "Wrong state"},
    {0x04, "Not supported capture type"},
    {0x05, "Not supported capture source"},
    {0xff, "Operation is prohibited"},
    {0, NULL},
};

static bool dissect_vs_set_capture_state_req(tvbuff_t* tvb, packet_info* pinfo,
                                             proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_CAPTURE_STATE_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_set_capture_state_req, -1, 0x00000000,
                               ett_vs_set_capture_state_req);
    ptvcursor_add(cursor, hf_vs_set_capture_state_req_station_address, 6,
                  0x00000000);
    ptvcursor_add(cursor, hf_vs_set_capture_state_req_state, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_set_capture_state_req_captured, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_set_capture_state_req_captured_source, 1,
                  0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_set_capture_state_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                             proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_CAPTURE_STATE_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_set_capture_state_cnf, -1, 0x00000000,
                               ett_vs_set_capture_state_cnf);
    ptvcursor_add(cursor, hf_vs_set_capture_state_cnf_result, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_set_capture_state(int proto) {
    static hf_register_info hf[] = {
        // VS_SET_CAPTURE_STATE.REQ
        {&hf_vs_set_capture_state_req,
         {"MMENTRY (VS_SET_CAPTURE_STATE.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.set_capture_state_req", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_set_capture_state_req_station_address,
         {"Station_address",
          "homeplug_av.mmtype.vertexcom.vs.set_capture_state_req.station_address",
          FT_ETHER, BASE_NONE, NULL, 0x0, "MAC address of the remote peer station",
          HFILL}},
        {&hf_vs_set_capture_state_req_state,
         {"State", "homeplug_av.mmtype.vertexcom.vs.set_capture_state_req.state",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_capture_state), 0x0,
          "Capture state", HFILL}},
        {&hf_vs_set_capture_state_req_captured,
         {"Captured",
          "homeplug_av.mmtype.vertexcom.vs.set_capture_state_req.captured",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_captured), 0x0, NULL, HFILL}},
        {&hf_vs_set_capture_state_req_captured_source,
         {"Captured_source",
          "homeplug_av.mmtype.vertexcom.vs.set_capture_state_req.captured_source",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_captured_source), 0x0, NULL,
          HFILL}},
        // VS_SET_CAPTURE_STATE.CNF
        {&hf_vs_set_capture_state_cnf,
         {"MMENTRY (VS_SET_CAPTURE_STATE.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.set_capture_state_cnf", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_set_capture_state_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.set_capture_state_cnf.result",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_capture_state_result), 0x0,
          NULL, HFILL}},
    };

    static int* ett[] = {
        &ett_vs_set_capture_state_req,
        &ett_vs_set_capture_state_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_set_capture_state_req,
                       "VertexCom VS_SET_CAPTURE_STATE.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.set_capture_state_req",
                       proto, HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_set_capture_state_cnf,
                       "VertexCom VS_SET_CAPTURE_STATE.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.set_capture_state_cnf",
                       proto, HEURISTIC_ENABLE);
}

// #################### VS_SET_NVRAM ####################
static int ett_vs_set_nvram_req;
static int hf_vs_set_nvram_req;
static int hf_vs_set_nvram_req_block_index;
static int hf_vs_set_nvram_req_nvram_size;
static int hf_vs_set_nvram_req_checksum;
static int hf_vs_set_nvram_req_block_data;

static int ett_vs_set_nvram_cnf;
static int hf_vs_set_nvram_cnf;
static int hf_vs_set_nvram_cnf_result;

static const value_string vertexcom_val_str_set_nvram_result[] = {
    {0x00, "Success"},
    {0x01, "Read MME error"},
    {0x02, "Checksum error"},
    {0x03, "Write data into temp file error"},
    {0x04, "Write NVRAM into flash error"},
    {0x05, "Read data from temp file error"},
    {0xff, "Operation is prohibited"},
    {0, NULL},
};

static bool dissect_vs_set_nvram_req(tvbuff_t* tvb, packet_info* pinfo,
                                     proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_NVRAM_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_set_nvram_req, -1, 0x00000000,
                               ett_vs_set_nvram_req);
    ptvcursor_add(cursor, hf_vs_set_nvram_req_block_index, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_set_nvram_req_nvram_size, 2, 0x80000000);
    ptvcursor_add(cursor, hf_vs_set_nvram_req_checksum, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_set_nvram_req_block_data, 1024, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_set_nvram_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                     proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_NVRAM_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_set_nvram_cnf, -1, 0x00000000,
                               ett_vs_set_nvram_cnf);
    ptvcursor_add(cursor, hf_vs_set_nvram_cnf_result, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_set_nvram(int proto) {
    static hf_register_info hf[] = {
        // VS_SET_NVRAM.REQ
        {&hf_vs_set_nvram_req,
         {"MMENTRY (VS_SET_NVRAM.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.set_nvram_req", FT_NONE, BASE_NONE, NULL,
          0x0, NULL, HFILL}},
        {&hf_vs_set_nvram_req_block_index,
         {"Block index",
          "homeplug_av.mmtype.vertexcom.vs.set_nvram_req.block_index", FT_UINT8,
          BASE_DEC, NULL, 0x0, "Block index of NVRAM", HFILL}},
        {&hf_vs_set_nvram_req_nvram_size,
         {"NVRAM size", "homeplug_av.mmtype.vertexcom.vs.set_nvram_req.nvram_size",
          FT_UINT16, BASE_DEC, NULL, 0x0, "All NVRAM size", HFILL}},
        {&hf_vs_set_nvram_req_checksum,
         {"Checksum", "homeplug_av.mmtype.vertexcom.vs.set_nvram_req.checksum",
          FT_UINT32, BASE_HEX, NULL, 0x0, "Checksum of each block", HFILL}},
        {&hf_vs_set_nvram_req_block_data,
         {"Data", "homeplug_av.mmtype.vertexcom.vs.set_nvram_req.block_data",
          FT_NONE, BASE_NONE, NULL, 0x0, "Data of each block", HFILL}},
        // VS_SET_NVRAM.CNF
        {&hf_vs_set_nvram_cnf,
         {"MMENTRY (VS_SET_NVRAM.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.set_nvram_cnf", FT_NONE, BASE_NONE, NULL,
          0x0, NULL, HFILL}},
        {&hf_vs_set_nvram_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.set_nvram_cnf.result",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_set_nvram_result), 0x0, NULL,
          HFILL}},
    };

    static int* ett[] = {
        &ett_vs_set_nvram_req,
        &ett_vs_set_nvram_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_set_nvram_req,
                       "VertexCom VS_SET_NVRAM.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.set_nvram_req", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_set_nvram_cnf,
                       "VertexCom VS_SET_NVRAM.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.set_nvram_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_GET_NVRAM ####################
static int ett_vs_get_nvram_req;
static int hf_vs_get_nvram_req;
static int hf_vs_get_nvram_req_block_index;

static int ett_vs_get_nvram_cnf;
static int hf_vs_get_nvram_cnf;
static int hf_vs_get_nvram_cnf_result;
static int hf_vs_get_nvram_cnf_block_index;
static int hf_vs_get_nvram_cnf_nvram_size;
static int hf_vs_get_nvram_cnf_block_data;

static const value_string vertexcom_val_str_get_nvram_result[] = {
    {0x00, "Success"},
    {0x01, "Read MME error"},
    {0x02, "Bad block index"},
    {0x03, "NVRAM is invalid"},
    {0, NULL},
};

static bool dissect_vs_get_nvram_req(tvbuff_t* tvb, packet_info* pinfo,
                                     proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NVRAM_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_nvram_req, -1, 0x00000000,
                               ett_vs_get_nvram_req);
    ptvcursor_add(cursor, hf_vs_get_nvram_req_block_index, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_get_nvram_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                     proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_NVRAM_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_nvram_cnf, -1, 0x00000000,
                               ett_vs_get_nvram_cnf);
    ptvcursor_add(cursor, hf_vs_get_nvram_cnf_result, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_nvram_cnf_block_index, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_nvram_cnf_nvram_size, 2, 0x80000000);
    ptvcursor_add(cursor, hf_vs_get_nvram_cnf_block_data, 1024, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_get_nvram(int proto) {
    static hf_register_info hf[] = {
        // VS_GET_NVRAM.REQ
        {&hf_vs_get_nvram_req,
         {"MMENTRY (VS_GET_NVRAM.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.get_nvram_req", FT_NONE, BASE_NONE, NULL,
          0x0, NULL, HFILL}},
        {&hf_vs_get_nvram_req_block_index,
         {"Block index",
          "homeplug_av.mmtype.vertexcom.vs.get_nvram_req.block_index", FT_UINT8,
          BASE_DEC, NULL, 0x0, "Block index of NVRAM", HFILL}},
        // VS_GET_NVRAM.CNF
        {&hf_vs_get_nvram_cnf,
         {"MMENTRY (VS_GET_NVRAM.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.get_nvram_cnf", FT_NONE, BASE_NONE, NULL,
          0x0, NULL, HFILL}},
        {&hf_vs_get_nvram_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.get_nvram_cnf.result",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_get_nvram_result), 0x0, NULL,
          HFILL}},
        {&hf_vs_get_nvram_cnf_block_index,
         {"Block index",
          "homeplug_av.mmtype.vertexcom.vs.get_nvram_cnf.block_index", FT_UINT8,
          BASE_DEC, NULL, 0x0, "Block index of NVRAM", HFILL}},
        {&hf_vs_get_nvram_cnf_nvram_size,
         {"NVRAM size", "homeplug_av.mmtype.vertexcom.vs.get_nvram_cnf.nvram_size",
          FT_UINT16, BASE_DEC, NULL, 0x0, "Size of NVRAM", HFILL}},
        {&hf_vs_get_nvram_cnf_block_data,
         {"Data", "homeplug_av.mmtype.vertexcom.vs.get_nvram_cnf.block_data",
          FT_NONE, BASE_NONE, NULL, 0x0, "Data of each block", HFILL}},
    };

    static int* ett[] = {
        &ett_vs_get_nvram_req,
        &ett_vs_get_nvram_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_get_nvram_req,
                       "VertexCom VS_GET_NVRAM.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.get_nvram_req", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_get_nvram_cnf,
                       "VertexCom VS_GET_NVRAM.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.get_nvram_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_GET_PWM_STATS ####################
static int ett_vs_get_pwm_stats_cnf;
static int hf_vs_get_pwm_stats_cnf;
static int hf_vs_get_pwm_stats_cnf_result;
static int hf_vs_get_pwm_stats_cnf_frequency;
static int hf_vs_get_pwm_stats_cnf_duty_cycle;
static int hf_vs_get_pwm_stats_cnf_voltage;
static int hf_vs_get_pwm_stats_cnf_saradc;

static int ett_vs_get_pwm_stats_ind;
static int hf_vs_get_pwm_stats_ind;
static int hf_vs_get_pwm_stats_ind_result;
static int hf_vs_get_pwm_stats_ind_frequency;
static int hf_vs_get_pwm_stats_ind_duty_cycle;
static int hf_vs_get_pwm_stats_ind_voltage;

static const value_string vertexcom_val_str_pwm_stats_cnf_result[] = {
    {0x00, "Success"},
    {0x01, "PWM monitor disabled"},
    {0x02, "No PWM signal"},
    {0, NULL},
};

static const value_string vertexcom_val_str_pwm_stats_ind_result[] = {
    {0x00, "Initial results"},
    {0x01, "Frequency change over the threshold"},
    {0x02, "Duty cycle change over the threshold"},
    {0x03, "Frequency and Duty cycle change over the thresholds"},
    {0x04, "Voltage change over the threshold"},
    {0x05, "Frequency and Voltage change over the thresholds"},
    {0x06, "Duty cycle and Voltage change over the thresholds"},
    {0x07, "Frequency, Duty cycle and Voltage change over the thresholds"},
    {0, NULL},
};

static bool dissect_vs_get_pwm_stats_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                         proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_STATS_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_pwm_stats_cnf, -1, 0x00000000,
                               ett_vs_get_pwm_stats_cnf);
    ptvcursor_add(cursor, hf_vs_get_pwm_stats_cnf_result, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_stats_cnf_frequency, 2, 0x80000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_stats_cnf_duty_cycle, 2, 0x80000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_stats_cnf_voltage, 2, 0x80000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_stats_cnf_saradc, 2, 0x80000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_get_pwm_stats_ind(tvbuff_t* tvb, packet_info* pinfo,
                                         proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_STATS_IND) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_pwm_stats_ind, -1, 0x00000000,
                               ett_vs_get_pwm_stats_ind);
    ptvcursor_add(cursor, hf_vs_get_pwm_stats_ind_result, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_stats_ind_frequency, 2, 0x80000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_stats_ind_duty_cycle, 2, 0x80000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_stats_ind_voltage, 2, 0x80000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_get_pwm_stats(int proto) {
    static hf_register_info hf[] = {
        // VS_GET_PWM_STATS.CNF
        {&hf_vs_get_pwm_stats_cnf,
         {"MMENTRY (VS_GET_PWM_STATS.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_pwm_stats_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_cnf.result",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_pwm_stats_cnf_result), 0x0,
          NULL, HFILL}},
        {&hf_vs_get_pwm_stats_cnf_frequency,
         {"Frequency (Hz)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_cnf.frequency", FT_UINT16,
          BASE_DEC, NULL, 0x0, "unit: Hz", HFILL}},
        {&hf_vs_get_pwm_stats_cnf_duty_cycle,
         {"Duty Cycle (0.1%)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_cnf.duty_cycle", FT_UINT16,
          BASE_DEC, NULL, 0x0, "unit: 0.1%", HFILL}},
        {&hf_vs_get_pwm_stats_cnf_voltage,
         {"Voltage (LSB or mV)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_cnf.voltage", FT_UINT16,
          BASE_DEC, NULL, 0x0, "unit: ADC LSB (0 ~ 1023) or mV", HFILL}},
        {&hf_vs_get_pwm_stats_cnf_saradc,
         {"SARADC (LSB)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_cnf.saradc", FT_UINT16,
          BASE_DEC, NULL, 0x0, "unit: SARADC LSB (0 ~ 1023)", HFILL}},
        // VS_GET_PWM_STATS.IND
        {&hf_vs_get_pwm_stats_ind,
         {"MMENTRY (VS_GET_PWM_STATS.IND)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_ind", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_pwm_stats_ind_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_ind.result",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_pwm_stats_ind_result), 0x0,
          NULL, HFILL}},
        {&hf_vs_get_pwm_stats_ind_frequency,
         {"Frequency (Hz)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_ind.frequency", FT_UINT16,
          BASE_DEC, NULL, 0x0, "unit: Hz", HFILL}},
        {&hf_vs_get_pwm_stats_ind_duty_cycle,
         {"Duty Cycle (0.1%)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_ind.duty_cycle", FT_UINT16,
          BASE_DEC, NULL, 0x0, "unit: 0.1%", HFILL}},
        {&hf_vs_get_pwm_stats_ind_voltage,
         {"Voltage (LSB or mV)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_ind.voltage", FT_UINT16,
          BASE_DEC, NULL, 0x0, "unit: ADC LSB (0 ~ 1023) or mV", HFILL}},
    };

    static int* ett[] = {
        &ett_vs_get_pwm_stats_cnf,
        &ett_vs_get_pwm_stats_ind,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_get_pwm_stats_cnf,
                       "VertexCom VS_GET_PWM_STATS.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_cnf", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_get_pwm_stats_ind,
                       "VertexCom VS_GET_PWM_STATS.IND",
                       "homeplug_av.mmtype.vertexcom.vs.get_pwm_stats_ind", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_GET_PWM_CONF ####################
static int ett_vs_get_pwm_conf_cnf;
static int hf_vs_get_pwm_conf_cnf;
static int hf_vs_get_pwm_conf_cnf_pwm_mode;
static int hf_vs_get_pwm_conf_cnf_pwm_measurement_method;
static int hf_vs_get_pwm_conf_cnf_frequency_change_threshold;
static int hf_vs_get_pwm_conf_cnf_duty_cycle_change_threshold;
static int hf_vs_get_pwm_conf_cnf_voltage_change_threshold;
static int hf_vs_get_pwm_conf_cnf_pwm_voltage_calibration_slope;
static int hf_vs_get_pwm_conf_cnf_pwm_voltage_calibration_bias;

static bool dissect_vs_get_pwm_conf_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                        proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_PWM_CONF_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_pwm_conf_cnf, -1, 0x00000000,
                               ett_vs_get_pwm_conf_cnf);
    ptvcursor_add(cursor, hf_vs_get_pwm_conf_cnf_pwm_mode, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_conf_cnf_pwm_measurement_method, 1,
                  0x00000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_conf_cnf_frequency_change_threshold, 2,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_conf_cnf_duty_cycle_change_threshold, 2,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_conf_cnf_voltage_change_threshold, 2,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_conf_cnf_pwm_voltage_calibration_slope, 2,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_get_pwm_conf_cnf_pwm_voltage_calibration_bias, 2,
                  0x80000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_get_pwm_conf(int proto) {
    static hf_register_info hf[] = {
        // VS_GET_PWM_CONF.CNF
        {&hf_vs_get_pwm_conf_cnf,
         {"MMENTRY (VS_GET_PWM_CONF.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_conf_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_pwm_conf_cnf_pwm_mode,
         {"PWM Mode", "homeplug_av.mmtype.vertexcom.vs.get_pwm_conf_cnf.pwm_mode",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x0, NULL, HFILL}},
        {&hf_vs_get_pwm_conf_cnf_pwm_measurement_method,
         {"PWM Measurement Method",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_conf_cnf.pwm_measurement_method",
          FT_UINT8, BASE_HEX,
          VALS(vertexcom_val_str_pwm_conf_pwm_measurement_method), 0x0, NULL,
          HFILL}},
        {&hf_vs_get_pwm_conf_cnf_frequency_change_threshold,
         {"Frequency Change Threshold (Hz)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_conf_cnf.frequency_change_"
          "threshold",
          FT_UINT16, BASE_DEC, NULL, 0x0, "unit: Hz", HFILL}},
        {&hf_vs_get_pwm_conf_cnf_duty_cycle_change_threshold,
         {"Duty Cycle Change Threshold (0.1%)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_conf_cnf.duty_cycle_change_"
          "threshold",
          FT_UINT16, BASE_DEC, NULL, 0x0, "unit: 0.1%", HFILL}},
        {&hf_vs_get_pwm_conf_cnf_voltage_change_threshold,
         {"Voltage Change Threshold (LSB or mV)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_conf_cnf.voltage_change_"
          "threshold",
          FT_UINT16, BASE_DEC, NULL, 0x0, "unit: ADC LSB (0 ~ 1023) or mV", HFILL}},
        {&hf_vs_get_pwm_conf_cnf_pwm_voltage_calibration_slope,
         {"PWM Voltage Calibration Slope",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_conf_cnf.pwm_voltage_"
          "calibration_slope",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "generated by companion calibration algorithm", HFILL}},
        {&hf_vs_get_pwm_conf_cnf_pwm_voltage_calibration_bias,
         {"PWM Voltage Calibration Bias (mV)",
          "homeplug_av.mmtype.vertexcom.vs.get_pwm_conf_cnf.pwm_voltage_"
          "calibration_bias",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "generated by companion calibration algorithm", HFILL}},
    };

    static int* ett[] = {
        &ett_vs_get_pwm_conf_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_get_pwm_conf_cnf, "VertexCom VS_GET_PWM_CONF.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.get_pwm_conf_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_SET_PWM_CONF ####################
static int ett_vs_set_pwm_conf_req;
static int hf_vs_set_pwm_conf_req;
static int hf_vs_set_pwm_conf_req_op_code;
static int hf_vs_set_pwm_conf_req_pwm_mode;
static int hf_vs_set_pwm_conf_req_pwm_measurement_method;
static int hf_vs_set_pwm_conf_req_pwm_measurement_period;
static int hf_vs_set_pwm_conf_req_frequency_change_threshold;
static int hf_vs_set_pwm_conf_req_duty_cycle_change_threshold;
static int hf_vs_set_pwm_conf_req_voltage_change_threshold;
static int hf_vs_set_pwm_conf_req_pwm_voltage_calibration_slope;
static int hf_vs_set_pwm_conf_req_pwm_voltage_calibration_bias;

static int ett_vs_set_pwm_conf_cnf;
static int hf_vs_set_pwm_conf_cnf;
static int hf_vs_set_pwm_conf_cnf_result;

static const value_string vertexcom_val_str_pwm_conf_op_code[] = {
    {0x01, "PWM mode"},
    {0x02, "PWM measurement method"},
    {0x04, "PWM measurement period"},
    {0x08, "Frequency change threshold"},
    {0x10, "Duty cycle change threshold"},
    {0x20, "Voltage change threshold"},
    {0x40, "Voltage calibration"},
    {0, NULL},
};

static bool dissect_vs_set_pwm_conf_req(tvbuff_t* tvb, packet_info* pinfo,
                                        proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_PWM_CONF_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_set_pwm_conf_req, -1, 0x00000000,
                               ett_vs_set_pwm_conf_req);
    ptvcursor_add(cursor, hf_vs_set_pwm_conf_req_op_code, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_set_pwm_conf_req_pwm_mode, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_set_pwm_conf_req_pwm_measurement_method, 1,
                  0x00000000);
    ptvcursor_add(cursor, hf_vs_set_pwm_conf_req_pwm_measurement_period, 2,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_set_pwm_conf_req_frequency_change_threshold, 2,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_set_pwm_conf_req_duty_cycle_change_threshold, 2,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_set_pwm_conf_req_voltage_change_threshold, 2,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_set_pwm_conf_req_pwm_voltage_calibration_slope, 2,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_set_pwm_conf_req_pwm_voltage_calibration_bias, 2,
                  0x80000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_set_pwm_conf_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                        proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_PWM_CONF_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_set_pwm_conf_cnf, -1, 0x00000000,
                               ett_vs_set_pwm_conf_cnf);
    ptvcursor_add(cursor, hf_vs_set_pwm_conf_cnf_result, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_set_pwm_conf(int proto) {
    static hf_register_info hf[] = {
        // VS_SET_PWM_CONF.REQ
        {&hf_vs_set_pwm_conf_req,
         {"MMENTRY (VS_SET_PWM_CONF.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_set_pwm_conf_req_op_code,
         {"Op Code", "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req.op_code",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_pwm_conf_op_code), 0x0, NULL,
          HFILL}},
        {&hf_vs_set_pwm_conf_req_pwm_mode,
         {"PWM Mode", "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req.pwm_mode",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x0, NULL, HFILL}},
        {&hf_vs_set_pwm_conf_req_pwm_measurement_method,
         {"PWM Measurement Method",
          "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req.pwm_measurement_method",
          FT_UINT8, BASE_HEX,
          VALS(vertexcom_val_str_pwm_conf_pwm_measurement_method), 0x0, NULL,
          HFILL}},
        {&hf_vs_set_pwm_conf_req_pwm_measurement_period,
         {"PWM Measurement Period (ms)",
          "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req.pwm_measurement_period",
          FT_UINT16, BASE_DEC, NULL, 0x0, "unit: ms", HFILL}},
        {&hf_vs_set_pwm_conf_req_frequency_change_threshold,
         {"Frequency Change Threshold (Hz)",
          "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req.frequency_change_"
          "threshold",
          FT_UINT16, BASE_DEC, NULL, 0x0, "unit: Hz", HFILL}},
        {&hf_vs_set_pwm_conf_req_duty_cycle_change_threshold,
         {"Duty Cycle Change Threshold (0.1%)",
          "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req.duty_cycle_change_"
          "threshold",
          FT_UINT16, BASE_DEC, NULL, 0x0, "unit: 0.1%", HFILL}},
        {&hf_vs_set_pwm_conf_req_voltage_change_threshold,
         {"Voltage Change Threshold (LSB or mV)",
          "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req.voltage_change_"
          "threshold",
          FT_UINT16, BASE_DEC, NULL, 0x0, "unit: ADC LSB 0 ~ 1023 or mV", HFILL}},
        {&hf_vs_set_pwm_conf_req_pwm_voltage_calibration_slope,
         {"PWM Voltage Calibration Slope",
          "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req.pwm_voltage_"
          "calibration_slope",
          FT_UINT16, BASE_DEC, NULL, 0x0, "generated by companion calibration",
          HFILL}},
        {&hf_vs_set_pwm_conf_req_pwm_voltage_calibration_bias,
         {"PWM Voltage Calibration Bias (mV)",
          "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req.pwm_voltage_"
          "calibration_bias",
          FT_UINT16, BASE_DEC, NULL, 0x0, "generated by companion calibration",
          HFILL}},
        // VS_SET_PWM_CONF.CNF
        {&hf_vs_set_pwm_conf_cnf,
         {"MMENTRY (VS_SET_PWM_CONF.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_set_pwm_conf_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_cnf.result",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_operation_result), 0x0, NULL,
          HFILL}},
    };

    static int* ett[] = {
        &ett_vs_set_pwm_conf_req,
        &ett_vs_set_pwm_conf_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_set_pwm_conf_req, "VertexCom VS_SET_PWM_CONF.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_req", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_set_pwm_conf_cnf, "VertexCom VS_SET_PWM_CONF.CN",
                       "homeplug_av.mmtype.vertexcom.vs.set_pwm_conf_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_PWM_GENERATION ####################
static int ett_vs_pwm_generation_req;
static int hf_vs_pwm_generation_req;
static int hf_vs_pwm_generation_req_pwm_mode;
static int hf_vs_pwm_generation_req_frequency;
static int hf_vs_pwm_generation_req_duty_cycle;

static int ett_vs_pwm_generation_cnf;
static int hf_vs_pwm_generation_cnf;
static int hf_vs_pwm_generation_cnf_result;

static bool dissect_vs_pwm_generation_req(tvbuff_t* tvb, packet_info* pinfo,
                                          proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_PWM_GENERATION_REQ) {
        return false;
    }

    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_pwm_generation_req, -1, 0x00000000,
                               ett_vs_pwm_generation_req);
    ptvcursor_add(cursor, hf_vs_pwm_generation_req_pwm_mode, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_pwm_generation_req_frequency, 2, 0x80000000);
    ptvcursor_add(cursor, hf_vs_pwm_generation_req_duty_cycle, 2, 0x80000000);

    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_pwm_generation_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                          proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_PWM_GENERATION_CNF) {
        return false;
    }

    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_pwm_generation_cnf, -1, 0x00000000,
                               ett_vs_pwm_generation_cnf);
    ptvcursor_add(cursor, hf_vs_pwm_generation_cnf_result, 1, 0x00000000);

    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_pwm_generation(int proto) {
    static hf_register_info hf[] = {
        // VS_PWM_GENERATION.REQ
        {&hf_vs_pwm_generation_req,
         {"MMENTRY (VS_PWM_GENERATION.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.pwm_generation_req", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_pwm_generation_req_pwm_mode,
         {"PWM Mode", "homeplug_av.mmtype.vertexcom.vs.pwm_generation_req.pwm_mode",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x0, NULL, HFILL}},
        {&hf_vs_pwm_generation_req_frequency,
         {"Frequency (kHz)",
          "homeplug_av.mmtype.vertexcom.vs.pwm_generation_req.frequency", FT_UINT16,
          BASE_DEC, NULL, 0x0, "unit: kHz", HFILL}},
        {&hf_vs_pwm_generation_req_duty_cycle,
         {"Duty Cycle (%)",
          "homeplug_av.mmtype.vertexcom.vs.pwm_generation_req.duty_cycle",
          FT_UINT16, BASE_DEC, NULL, 0x0, "unit: 1%", HFILL}},
        // VS_PWM_GENERATION.CNF
        {&hf_vs_pwm_generation_cnf,
         {"MMENTRY (VS_PWM_GENERATION.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.pwm_generation_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_pwm_generation_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.pwm_generation_cnf.result",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_operation_result), 0x0, NULL,
          HFILL}},
    };

    static int* ett[] = {
        &ett_vs_pwm_generation_req,
        &ett_vs_pwm_generation_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_pwm_generation_req,
                       "VertexCom VS_PWM_GENERATION.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.pwm_generation_req", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_pwm_generation_cnf,
                       "VertexCom VS_PWM_GENERATION.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.pwm_generation_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_SPI_STATS ####################
static int ett_vs_spi_stats_req;
static int hf_vs_spi_stats_req;
static int hf_vs_spi_stats_req_command;

static int ett_vs_spi_stats_cnf;
static int hf_vs_spi_stats_cnf;
static int hf_vs_spi_stats_cnf_result;
static int hf_vs_spi_stats_cnf_rx_packets;
static int hf_vs_spi_stats_cnf_rx_unicast;
static int hf_vs_spi_stats_cnf_rx_cmd_rts;
static int hf_vs_spi_stats_cnf_rx_cmd_rts_error;
static int hf_vs_spi_stats_cnf_rx_cmd_rts_wrong_length;
static int hf_vs_spi_stats_cnf_rx_data_error;
static int hf_vs_spi_stats_cnf_rx_abort_due_to_queue_full;
static int hf_vs_spi_stats_cnf_rx_wait_re_assembled_fragment_length;
static int hf_vs_spi_stats_cnf_tx_packets;
static int hf_vs_spi_stats_cnf_tx_unicast;
static int hf_vs_spi_stats_cnf_tx_cmd_rts;
static int hf_vs_spi_stats_cnf_tx_cmd_ctr;
static int hf_vs_spi_stats_cnf_tx_cmd_rts_timeout_abort;
static int hf_vs_spi_stats_cnf_tx_cmd_ctr_timeout_abort;
static int hf_vs_spi_stats_cnf_tx_packets_drop_due_to_queue_full;
static int hf_vs_spi_stats_cnf_fragment_expire_happen;
static int hf_vs_spi_stats_cnf_rx_cmd_ctr;
static int hf_vs_spi_stats_cnf_rx_command_error;
static int hf_vs_spi_stats_cnf_rx_command_fail;
static int hf_vs_spi_stats_cnf_rx_unknown_command;
static int hf_vs_spi_stats_cnf_rx_data_dft_error;
static int hf_vs_spi_stats_cnf_tx_cmd_rts_fail;
static int hf_vs_spi_stats_cnf_tx_cmd_ctr_fail;
static int hf_vs_spi_stats_cnf_tx_data_error;

static bool dissect_vs_spi_stats_req(tvbuff_t* tvb, packet_info* pinfo,
                                     proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SPI_STATS_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_spi_stats_req, -1, 0x00000000,
                               ett_vs_spi_stats_req);
    ptvcursor_add(cursor, hf_vs_spi_stats_req_command, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_spi_stats_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                     proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SPI_STATS_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_spi_stats_cnf, -1, 0x00000000,
                               ett_vs_spi_stats_cnf);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_result, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_packets, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_unicast, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_cmd_rts, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_cmd_rts_error, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_cmd_rts_wrong_length, 4,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_data_error, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_abort_due_to_queue_full, 4,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_wait_re_assembled_fragment_length,
                  2, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_tx_packets, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_tx_unicast, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_tx_cmd_rts, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_tx_cmd_ctr, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_tx_cmd_rts_timeout_abort, 4,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_tx_cmd_ctr_timeout_abort, 4,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_tx_packets_drop_due_to_queue_full, 4,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_fragment_expire_happen, 4,
                  0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_cmd_ctr, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_command_error, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_command_fail, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_unknown_command, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_rx_data_dft_error, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_tx_cmd_rts_fail, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_tx_cmd_ctr_fail, 4, 0x80000000);
    ptvcursor_add(cursor, hf_vs_spi_stats_cnf_tx_data_error, 4, 0x80000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_spi_stats(int proto) {
    static hf_register_info hf[] = {
        // VS_SPI_STATS.REQ
        {&hf_vs_spi_stats_req,
         {"MMENTRY (VS_SPI_STATS.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_req", FT_NONE, BASE_NONE, NULL,
          0x0, NULL, HFILL}},
        {&hf_vs_spi_stats_req_command,
         {"Command", "homeplug_av.mmtype.vertexcom.vs.spi_stats_req.command",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_stats_command), 0x0, NULL,
          HFILL}},
        // VS_SPI_STATS.CNF
        {&hf_vs_spi_stats_cnf,
         {"MMENTRY (VS_SPI_STATS.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf", FT_NONE, BASE_NONE, NULL,
          0x0, NULL, HFILL}},
        {&hf_vs_spi_stats_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.result",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_fail_success), 0x0, NULL, HFILL}},
        {&hf_vs_spi_stats_cnf_rx_packets,
         {"Rx Packets", "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_packets",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Rx packets", HFILL}},
        {&hf_vs_spi_stats_cnf_rx_unicast,
         {"Rx Unicast", "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_unicast",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Rx unicast", HFILL}},
        {&hf_vs_spi_stats_cnf_rx_cmd_rts,
         {"Rx CMD_RTS", "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_cmd_rts",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of CMD_RTS correctly received",
          HFILL}},
        {&hf_vs_spi_stats_cnf_rx_cmd_rts_error,
         {"Rx CMD_RTS Error",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_cmd_rts_error",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of CMD_RTS received with wrong delimiter or wrong command type",
          HFILL}},
        {&hf_vs_spi_stats_cnf_rx_cmd_rts_wrong_length,
         {"Rx CMD_RTS Wrong Length",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_cmd_rts_wrong_length",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of CMD_RTS received with wrong data length", HFILL}},
        {&hf_vs_spi_stats_cnf_rx_data_error,
         {"Rx Data Error",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_data_error", FT_UINT32,
          BASE_DEC, NULL, 0x0,
          "Number of data packets received without SOF delimiter", HFILL}},
        {&hf_vs_spi_stats_cnf_rx_abort_due_to_queue_full,
         {"Rx Abort Due to Queue Full",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_abort_due_to_queue_"
          "full",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of RX action aborted due to SPI RX queue full", HFILL}},
        {&hf_vs_spi_stats_cnf_rx_wait_re_assembled_fragment_length,
         {"Rx Wait Re-Assembled Fragment Length",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_wait_re_assembled_"
          "fragment_length",
          FT_UINT16, BASE_DEC, NULL, 0x0,
          "Total length of received fragments which are waiting to be re-assembled",
          HFILL}},
        {&hf_vs_spi_stats_cnf_tx_packets,
         {"Tx Packets", "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.tx_packets",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Tx packets", HFILL}},
        {&hf_vs_spi_stats_cnf_tx_unicast,
         {"Tx Unicast", "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.tx_unicast",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of Tx unicast", HFILL}},
        {&hf_vs_spi_stats_cnf_tx_cmd_rts,
         {"Tx CMD_RTS", "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.tx_cmd_rts",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of CMD_RTS transmitted", HFILL}},
        {&hf_vs_spi_stats_cnf_tx_cmd_ctr,
         {"Tx CMD_CTR", "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.tx_cmd_ctr",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of CMD_CTR transmitted", HFILL}},
        {&hf_vs_spi_stats_cnf_tx_cmd_rts_timeout_abort,
         {"Tx CMD_RTS Timeout Abort",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.tx_cmd_rts_timeout_abort",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of CMD_RTS timeout abort",
          HFILL}},
        {&hf_vs_spi_stats_cnf_tx_cmd_ctr_timeout_abort,
         {"Tx CMD_CTR Timeout Abort",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.tx_cmd_ctr_timeout_abort",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of CMD_CTR timeout abort",
          HFILL}},
        {&hf_vs_spi_stats_cnf_tx_packets_drop_due_to_queue_full,
         {"Tx Packets Drop Due to Queue Full",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.tx_packets_drop_due_to_"
          "queue_full",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of packets from PLC dropped due to SPI TX queue full", HFILL}},
        {&hf_vs_spi_stats_cnf_fragment_expire_happen,
         {"Fragment Expire Happen",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.fragment_expire_happen",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of timeout-to-received fragment data", HFILL}},
        {&hf_vs_spi_stats_cnf_rx_cmd_ctr,
         {"Rx CMD_CTR", "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_cmd_ctr",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of CMD_CTR commands received",
          HFILL}},
        {&hf_vs_spi_stats_cnf_rx_command_error,
         {"Rx Command Error",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_command_error",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of received commands not started with DET_CMD", HFILL}},
        {&hf_vs_spi_stats_cnf_rx_command_fail,
         {"Rx Command Fail",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_command_fail",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of fail-to-received commands",
          HFILL}},
        {&hf_vs_spi_stats_cnf_rx_unknown_command,
         {"Rx Unknown Command",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_unknown_command",
          FT_UINT32, BASE_DEC, NULL, 0x0, "Number of received unknown commands",
          HFILL}},
        {&hf_vs_spi_stats_cnf_rx_data_dft_error,
         {"Rx Data DFT Error",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.rx_data_dft_error",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of received data packets whose DFT is invalid", HFILL}},
        {&hf_vs_spi_stats_cnf_tx_cmd_rts_fail,
         {"Tx CMD_RTS Fail",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.tx_cmd_rts_fail",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of failed transmissions of CMD_RTS command", HFILL}},
        {&hf_vs_spi_stats_cnf_tx_cmd_ctr_fail,
         {"Tx CMD_CTR Fail",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.tx_cmd_ctr_fail",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Number of failed transmissions of CMD_CTR command", HFILL}},
        {&hf_vs_spi_stats_cnf_tx_data_error,
         {"Tx Data Error",
          "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf.tx_data_error", FT_UINT32,
          BASE_DEC, NULL, 0x0, "Number of failed transmissions of data packets",
          HFILL}},
    };

    static int* ett[] = {
        &ett_vs_spi_stats_req,
        &ett_vs_spi_stats_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_spi_stats_req,
                       "VertexCom VS_SPI_STATS.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.spi_stats_req", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_spi_stats_cnf,
                       "VertexCom VS_SPI_STATS.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.spi_stats_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_SET_TX_CAL ####################
static int ett_vs_set_tx_cal_req;
static int hf_vs_set_tx_cal_req;
static int hf_vs_set_tx_cal_req_enable;

static int ett_vs_set_tx_cal_cnf;
static int hf_vs_set_tx_cal_cnf;
static int hf_vs_set_tx_cal_cnf_result;

static bool dissect_vs_set_tx_cal_req(tvbuff_t* tvb, packet_info* pinfo,
                                      proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_TX_CAL_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_set_tx_cal_req, -1, 0x00000000,
                               ett_vs_set_tx_cal_req);
    ptvcursor_add(cursor, hf_vs_set_tx_cal_req_enable, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_set_tx_cal_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                      proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_TX_CAL_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_set_tx_cal_cnf, -1, 0x00000000,
                               ett_vs_set_tx_cal_cnf);
    ptvcursor_add(cursor, hf_vs_set_tx_cal_cnf_result, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_set_tx_cal(int proto) {
    static hf_register_info hf[] = {
        // VS_SET_TX_CAL.REQ
        {&hf_vs_set_tx_cal_req,
         {"MMENTRY (VS_SET_TX_CAL.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.set_tx_cal_req", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_set_tx_cal_req_enable,
         {"Enable", "homeplug_av.mmtype.vertexcom.vs.set_tx_cal_req.enable",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_enabled_disabled), 0x0,
          "Disable/Enable transmission PSD calibration feature", HFILL}},
        // VS_SET_TX_CAL.CNF
        {&hf_vs_set_tx_cal_cnf,
         {"MMENTRY (VS_SET_TX_CAL.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.set_tx_cal_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_set_tx_cal_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.set_tx_cal_cnf.result",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_operation_result), 0x0, NULL,
          HFILL}},
    };

    static int* ett[] = {
        &ett_vs_set_tx_cal_req,
        &ett_vs_set_tx_cal_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_set_tx_cal_req,
                       "VertexCom VS_SET_TX_CAL.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.set_tx_cal_req", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs", dissect_vs_set_tx_cal_cnf,
                       "VertexCom VS_SET_TX_CAL.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.set_tx_cal_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_FILE_ACCESS ####################
static int ett_vs_file_access_req;
static int hf_vs_file_access_req;
static int hf_vs_file_access_req_opcode;
static int hf_vs_file_access_req_filetype;
static int hf_vs_file_access_req_parameter;
static int hf_vs_file_access_req_total_fragments;
static int hf_vs_file_access_req_fragment_sequence_number;
static int hf_vs_file_access_req_offset;
static int hf_vs_file_access_req_checksum;
static int hf_vs_file_access_req_length;
static int hf_vs_file_access_req_fragment_data;

static int ett_vs_file_access_cnf;
static int hf_vs_file_access_cnf;
static int hf_vs_file_access_cnf_status;
static int hf_vs_file_access_cnf_opcode;
static int hf_vs_file_access_cnf_filetype;
static int hf_vs_file_access_cnf_parameter;
static int hf_vs_file_access_cnf_total_fragments;
static int hf_vs_file_access_cnf_fragment_sequence_number;
static int hf_vs_file_access_cnf_offset;
static int hf_vs_file_access_cnf_length;
static int hf_vs_file_access_cnf_fragment_data;

static const value_string vertexcom_val_str_file_access_opcode[] = {
    {0x00, "Write"},          {0x01, "Read"},
    {0x02, "Delete"},         {0x03, "List directory"},
    {0x04, "Make directory"}, {0x05, "Delete directory"},
    {0x06, "Format flash"},   {0x07, "Save"},
    {0x08, "Scan STA"},       {0, NULL},
};

static const value_string vertexcom_val_str_file_access_filetype[] = {
    {0x00, "Bootloader"},  {0x01, "Simage"}, {0x02, "All other files"},
    {0x03, "Debug trace"}, {0, NULL},
};

static bool dissect_vs_file_access_req(tvbuff_t* tvb, packet_info* pinfo,
                                       proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_FILE_ACCESS_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_file_access_req, -1, 0x00000000,
                               ett_vs_file_access_req);
    ptvcursor_add(cursor, hf_vs_file_access_req_opcode, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_req_filetype, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_req_parameter, 32, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_req_total_fragments, 2, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_req_fragment_sequence_number, 2,
                  0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_req_offset, 4, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_req_checksum, 4, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_req_length, 2, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_req_fragment_data, -1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_file_access_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                       proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_FILE_ACCESS_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_file_access_cnf, -1, 0x00000000,
                               ett_vs_file_access_cnf);
    ptvcursor_add(cursor, hf_vs_file_access_cnf_status, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_cnf_opcode, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_cnf_filetype, 1, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_cnf_parameter, 32, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_cnf_total_fragments, 2, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_cnf_fragment_sequence_number, 2,
                  0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_cnf_offset, 4, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_cnf_length, 2, 0x00000000);
    ptvcursor_add(cursor, hf_vs_file_access_cnf_fragment_data, -1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_file_access(int proto) {
    static hf_register_info hf[] = {
        // VS_FILE_ACCESS.REQ
        {&hf_vs_file_access_req,
         {"MMENTRY (VS_FILE_ACCESS.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.file_access_req", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_file_access_req_opcode,
         {"OPcode", "homeplug_av.mmtype.vertexcom.vs.file_access_req.opcode",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_file_access_opcode), 0x0,
          "Operation code", HFILL}},
        {&hf_vs_file_access_req_filetype,
         {"FileType", "homeplug_av.mmtype.vertexcom.vs.file_access_req.filetype",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_file_access_filetype), 0x0,
          "File type", HFILL}},
        {&hf_vs_file_access_req_parameter,
         {"Parameter", "homeplug_av.mmtype.vertexcom.vs.file_access_req.parameter",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "ASCII string of filename and path in file system", HFILL}},
        {&hf_vs_file_access_req_total_fragments,
         {"Total_Fragments",
          "homeplug_av.mmtype.vertexcom.vs.file_access_req.total_fragments",
          FT_UINT16, BASE_DEC, NULL, 0x0, "Number of total fragments", HFILL}},
        {&hf_vs_file_access_req_fragment_sequence_number,
         {"Fragment_Sequence_Number",
          "homeplug_av.mmtype.vertexcom.vs.file_access_req.fragment_sequence_"
          "number",
          FT_UINT16, BASE_DEC, NULL, 0x0, "Sequence number of this fragment",
          HFILL}},
        {&hf_vs_file_access_req_offset,
         {"Offset", "homeplug_av.mmtype.vertexcom.vs.file_access_req.offset",
          FT_UINT32, BASE_DEC, NULL, 0x0, "The byte offset from start of the file",
          HFILL}},
        {&hf_vs_file_access_req_checksum,
         {"Checksum", "homeplug_av.mmtype.vertexcom.vs.file_access_req.checksum",
          FT_UINT32, BASE_HEX, NULL, 0x0, "Checksum value to verify data integrity",
          HFILL}},
        {&hf_vs_file_access_req_length,
         {"Length", "homeplug_av.mmtype.vertexcom.vs.file_access_req.length",
          FT_UINT16, BASE_DEC, NULL, 0x0, "The byte length of the fragment",
          HFILL}},
        {&hf_vs_file_access_req_fragment_data,
         {"Data", "homeplug_av.mmtype.vertexcom.vs.file_access_req.fragment_data",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        // VS_FILE_ACCESS.CNF
        {&hf_vs_file_access_cnf,
         {"MMENTRY (VS_FILE_ACCESS.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.file_access_cnf", FT_NONE, BASE_NONE,
          NULL, 0x0, NULL, HFILL}},
        {&hf_vs_file_access_cnf_status,
         {"Status", "homeplug_av.mmtype.vertexcom.vs.file_access_cnf.status",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_operation_result), 0x0, NULL,
          HFILL}},
        {&hf_vs_file_access_cnf_opcode,
         {"OPcode", "homeplug_av.mmtype.vertexcom.vs.file_access_cnf.opcode",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_file_access_opcode), 0x0,
          "Operation code", HFILL}},
        {&hf_vs_file_access_cnf_filetype,
         {"FileType", "homeplug_av.mmtype.vertexcom.vs.file_access_cnf.filetype",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_file_access_filetype), 0x0,
          "File type", HFILL}},
        {&hf_vs_file_access_cnf_parameter,
         {"Parameter", "homeplug_av.mmtype.vertexcom.vs.file_access_cnf.parameter",
          FT_STRING, BASE_NONE, NULL, 0x0,
          "ASCII string of filename and path in file system", HFILL}},
        {&hf_vs_file_access_cnf_total_fragments,
         {"Total_Fragments",
          "homeplug_av.mmtype.vertexcom.vs.file_access_cnf.total_fragments",
          FT_UINT16, BASE_DEC, NULL, 0x0, "Number of total fragments", HFILL}},
        {&hf_vs_file_access_cnf_fragment_sequence_number,
         {"Fragment_Sequence_Number",
          "homeplug_av.mmtype.vertexcom.vs.file_access_cnf.fragment_sequence_"
          "number",
          FT_UINT16, BASE_DEC, NULL, 0x0, "Sequence number of this fragment",
          HFILL}},
        {&hf_vs_file_access_cnf_offset,
         {"Offset", "homeplug_av.mmtype.vertexcom.vs.file_access_cnf.offset",
          FT_UINT32, BASE_DEC, NULL, 0x0, "The byte offset from start of the file",
          HFILL}},
        {&hf_vs_file_access_cnf_length,
         {"Length", "homeplug_av.mmtype.vertexcom.vs.file_access_cnf.length",
          FT_UINT16, BASE_DEC, NULL, 0x0, "The byte length of the fragment",
          HFILL}},
        {&hf_vs_file_access_cnf_fragment_data,
         {"Data", "homeplug_av.mmtype.vertexcom.vs.file_access_cnf.fragment_data",
          FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    };

    static int* ett[] = {
        &ett_vs_file_access_req,
        &ett_vs_file_access_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_file_access_req, "VertexCom VS_FILE_ACCESS.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.file_access_req", proto,
                       HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_file_access_cnf, "VertexCom VS_FILE_ACCESS.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.file_access_cnf", proto,
                       HEURISTIC_ENABLE);
}

// #################### VS_SET_REMOTE_ACCESS ####################
static int ett_vs_set_remote_access_req;
static int hf_vs_set_remote_access_req;
static int hf_vs_set_remote_access_req_mode;

static int ett_vs_set_remote_access_cnf;
static int hf_vs_set_remote_access_cnf;
static int hf_vs_set_remote_access_cnf_result;

static bool dissect_vs_set_remote_access_req(tvbuff_t* tvb, packet_info* pinfo,
                                             proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_REMOTE_ACCESS_REQ) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_set_remote_access_req, -1, 0x00000000,
                               ett_vs_set_remote_access_req);
    ptvcursor_add(cursor, hf_vs_set_remote_access_req_mode, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static bool dissect_vs_set_remote_access_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                             proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_SET_REMOTE_ACCESS_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_set_remote_access_cnf, -1, 0x00000000,
                               ett_vs_set_remote_access_cnf);
    ptvcursor_add(cursor, hf_vs_set_remote_access_cnf_result, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_set_remote_access(int proto) {
    static hf_register_info hf[] = {
        // VS_SET_REMOTE_ACCESS.REQ
        {&hf_vs_set_remote_access_req,
         {"MMENTRY (VS_SET_REMOTE_ACCESS.REQ)",
          "homeplug_av.mmtype.vertexcom.vs.set_remote_access_req", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_set_remote_access_req_mode,
         {"Mode", "homeplug_av.mmtype.vertexcom.vs.set_remote_access_req.mode",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_not_allowed_allowed), 0x0,
          "Remote access mode", HFILL}},
        // VS_SET_REMOTE_ACCESS.CNF
        {&hf_vs_set_remote_access_cnf,
         {"MMENTRY (VS_SET_REMOTE_ACCESS.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.set_remote_access_cnf", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_set_remote_access_cnf_result,
         {"Result", "homeplug_av.mmtype.vertexcom.vs.set_remote_access_cnf.result",
          FT_UINT8, BASE_HEX, VALS(vertexcom_val_str_operation_result), 0x0, NULL,
          HFILL}},
    };

    static int* ett[] = {
        &ett_vs_set_remote_access_req,
        &ett_vs_set_remote_access_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_set_remote_access_req,
                       "VertexCom VS_SET_REMOTE_ACCESS.REQ",
                       "homeplug_av.mmtype.vertexcom.vs.set_remote_access_req",
                       proto, HEURISTIC_ENABLE);
    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_set_remote_access_cnf,
                       "VertexCom VS_SET_REMOTE_ACCESS.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.set_remote_access_cnf",
                       proto, HEURISTIC_ENABLE);
}

// #################### VS_GET_REMOTE_ACCESS ####################
static int ett_vs_get_remote_access_cnf;
static int hf_vs_get_remote_access_cnf;
static int hf_vs_get_remote_access_cnf_status;

static bool dissect_vs_get_remote_access_cnf(tvbuff_t* tvb, packet_info* pinfo,
                                             proto_tree* tree, void* data) {
    DISSECTOR_ASSERT(data);
    homeplug_av_vertexcom_context_t* ctx = (homeplug_av_vertexcom_context_t*)data;
    if (ctx->mmtype != HOMEPLUG_AV_MMTYPE_VERTEXCOM_VS_GET_REMOTE_ACCESS_CNF) {
        return false;
    }
    //  shift cusor after `OUI` field
    ptvcursor_t* cursor = ptvcursor_new(pinfo->pool, tree, tvb, 0);
    ptvcursor_advance(cursor, 3);

    ptvcursor_add_with_subtree(cursor, hf_vs_get_remote_access_cnf, -1, 0x00000000,
                               ett_vs_get_remote_access_cnf);
    ptvcursor_add(cursor, hf_vs_get_remote_access_cnf_status, 1, 0x00000000);
    ptvcursor_pop_subtree(cursor);

    return true;
}

static inline void register_vertexcom_mmtype_vs_get_remote_access(int proto) {
    static hf_register_info hf[] = {
        // VS_GET_REMOTE_ACCESS.CNF
        {&hf_vs_get_remote_access_cnf,
         {"MMENTRY (VS_GET_REMOTE_ACCESS.CNF)",
          "homeplug_av.mmtype.vertexcom.vs.get_remote_access_cnf", FT_NONE,
          BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_vs_get_remote_access_cnf_status,
         {"Status", "homeplug_av.mmtype.vertexcom.vs.get_remote_access_cnf.status",
          FT_BOOLEAN, BASE_NONE, TFS(&tfs_not_allowed_allowed), 0x0,
          "Remote access status", HFILL}},
    };

    static int* ett[] = {
        &ett_vs_get_remote_access_cnf,
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    heur_dissector_add("homeplug_av.mmtype.vertexcom.vs",
                       dissect_vs_get_remote_access_cnf,
                       "VertexCom VS_GET_REMOTE_ACCESS.CNF",
                       "homeplug_av.mmtype.vertexcom.vs.get_remote_access_cnf",
                       proto, HEURISTIC_ENABLE);
}

/* Register VS_* MMEs dissectors */
static void register_vertexcom_mmtype_vs_process(int proto) {
    vertexcom_mmtype_vs_heur_dissector_list =
        register_heur_dissector_list("homeplug_av.mmtype.vertexcom.vs", proto);
    register_vertexcom_mmtype_vs_get_version(proto);
    register_vertexcom_mmtype_vs_reset(proto);
    register_vertexcom_mmtype_vs_get_eth_phy(proto);
    register_vertexcom_mmtype_vs_eth_stats(proto);
    register_vertexcom_mmtype_vs_get_status(proto);
    register_vertexcom_mmtype_vs_get_snr(proto);
    register_vertexcom_mmtype_vs_get_link_stats(proto);
    register_vertexcom_mmtype_vs_get_nw_info(proto);
    register_vertexcom_mmtype_vs_set_capture_state(proto);
    register_vertexcom_mmtype_vs_set_nvram(proto);
    register_vertexcom_mmtype_vs_get_nvram(proto);
    register_vertexcom_mmtype_vs_get_pwm_stats(proto);
    register_vertexcom_mmtype_vs_get_pwm_conf(proto);
    register_vertexcom_mmtype_vs_set_pwm_conf(proto);
    register_vertexcom_mmtype_vs_pwm_generation(proto);
    register_vertexcom_mmtype_vs_spi_stats(proto);
    register_vertexcom_mmtype_vs_set_tx_cal(proto);
    register_vertexcom_mmtype_vs_file_access(proto);
    register_vertexcom_mmtype_vs_set_remote_access(proto);
    register_vertexcom_mmtype_vs_get_remote_access(proto);
}

/* Heuristic dissector for Vertexcom VS_* MMEs */
static void dissect_vertexcom_mmtype_vs(tvbuff_t* vendor_tvb, packet_info* pinfo,
                                        proto_tree* vendor_tree,
                                        homeplug_av_vertexcom_context_t* context) {
    heur_dtbl_entry_t* hdtbl_entry = NULL;
    dissector_try_heuristic(vertexcom_mmtype_vs_heur_dissector_list, vendor_tvb,
                            pinfo, vendor_tree, &hdtbl_entry, context);
}

/* Register HomePlug AV Vertexcom MME dissectors */
static void homeplug_av_vertexcom_register_process(int proto) {
    static hf_register_info hf[] = {
        {
            &hf_homeplug_av_mmhdr_mmtype_vertexcom,
            {"Type", "homeplug_av.mmhdr.mmtype.vertexcom", FT_UINT16,
             BASE_HEX | BASE_EXT_STRING, &homeplug_av_mmtype_vertexcom_vals_ext,
             0x0, NULL, HFILL},
        },
    };

    proto_register_field_array(proto, hf, array_length(hf));
    register_external_value_string_ext("homeplug_av_mmtype_vertexcom_vals_ext",
                                       &homeplug_av_mmtype_vertexcom_vals_ext);

    register_vertexcom_mmtype_vs_process(proto);
}

void dissect_homeplug_av_mme_vertexcom(ptvcursor_t* cursor,
                                       uint8_t homeplug_av_mmver,
                                       uint16_t homeplug_av_mmtype,
                                       packet_info* pinfo,
                                       proto_tree* vendor_tree) {
    tvbuff_t* tvb = ptvcursor_tvbuff(cursor);
    proto_tree* tree = ptvcursor_tree(cursor);
    unsigned int cursor_offset = ptvcursor_current_offset(cursor);
    unsigned int tvb_remaining_len =
        tvb_reported_length_remaining(tvb, cursor_offset);
    if (tree == NULL || vendor_tree == NULL || tvb_remaining_len < 38) {
        return;
    }

    // get subset of `homeplug_av.vendor` tree, -3 to include OUI field
    tvbuff_t* vendor_tvb = tvb_new_subset_remaining(tvb, cursor_offset - 3);
    homeplug_av_vertexcom_context_t ctx = {
        .mmver = homeplug_av_mmver,
        .mmtype = homeplug_av_mmtype,
    };
    dissect_vertexcom_mmtype_vs(vendor_tvb, pinfo, vendor_tree, &ctx);
}

proto_tree* dissect_homeplug_av_mmhdr_mmtype_vertexcom(ptvcursor_t* cursor) {
    return ptvcursor_add_no_advance(cursor, hf_homeplug_av_mmhdr_mmtype_vertexcom,
                                    2, ENC_LITTLE_ENDIAN);
}

void homeplug_av_mmtype_column_vertexcom(packet_info* pinfo,
                                         uint16_t homeplug_av_mmtype) {
    col_append_sep_str(
        pinfo->cinfo, COL_INFO, ", ",
        val_to_str_ext(pinfo->pool, homeplug_av_mmtype,
                       &homeplug_av_mmtype_vertexcom_vals_ext, "Unknown 0x%x"));
}

void proto_register_homeplug_av_vendor_vertexcom(void) {
    proto_homeplug_av = proto_get_id_by_filter_name("homeplug-av");
}

void proto_reg_handoff_homeplug_av_vendor_vertexcom(void) {
    if (proto_homeplug_av != -1) {
        homeplug_av_vertexcom_register_process(proto_homeplug_av);
    }
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
