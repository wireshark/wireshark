/* packet-oran.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Section types from Table 7.3.1-1 */
enum section_c_types {
    SEC_C_UNUSED_RB = 0,
    SEC_C_NORMAL = 1,
    SEC_C_RSVD2 = 2,
    SEC_C_PRACH = 3,
    SEC_C_SLOT_CONTROL = 4,
    SEC_C_UE_SCHED = 5,
    SEC_C_CH_INFO = 6,
    SEC_C_LAA = 7,
    SEC_C_ACK_NACK_FEEDBACK = 8,
    SEC_C_SINR_REPORTING = 9,
    SEC_C_RRM_MEAS_REPORTS = 10,
    SEC_C_REQUEST_RRM_MEAS = 11,
    SEC_C_MAX_INDEX				/* used to size array below */
};

#define HIGHEST_EXTTYPE 29  /* Highest supported exttype */
#define MAX_SECTION_IDs 32  /* i.e. how many may be reported from one frame */
#define MAX_BEAMS_IN_FRAME 32

/* 8.3.3.15 Compression schemes */
#define COMP_NONE                             0
#define COMP_BLOCK_FP                         1
#define COMP_BLOCK_SCALE                      2
#define COMP_U_LAW                            3
#define COMP_MODULATION                       4
#define BFP_AND_SELECTIVE_RE                  5
#define MOD_COMPR_AND_SELECTIVE_RE            6
#define BFP_AND_SELECTIVE_RE_WITH_MASKS       7
#define MOD_COMPR_AND_SELECTIVE_RE_WITH_MASKS 8


typedef struct oran_tap_info {
    /* Key info */
    bool     userplane;
    uint16_t eaxc;
    bool     uplink;
    /* Timing info */
    uint8_t frame;
    uint8_t slot;
    /* Missing SNs */
    uint32_t missing_sns;
    /* TODO: repeated SNs? */
    /* Accumulated state */
    uint32_t pdu_size;
    bool     section_types[SEC_C_MAX_INDEX];
    uint16_t section_ids[MAX_SECTION_IDs+1];
    uint8_t  num_section_ids;
    bool     extensions[HIGHEST_EXTTYPE+1];    /* wasting first entry */

    /* U-Plane stats */
    uint32_t num_prbs;
    uint32_t num_res;
    bool     non_zero_re_in_current_prb;
    uint32_t num_prbs_zero;
    uint32_t num_res_zero;

    uint32_t ul_delay_in_us;
    uint32_t ul_delay_configured_max;
    /* TODO: compression/bitwidth, beams? */
    /* N.B. bitwidth, method, but each section could potentially have different udcompHdr.. */

    uint32_t compression_methods;
    uint32_t compression_width;      /* TODO: support multiple widths? */

    /* (DL) beamIds */
    uint8_t  num_beams;
    uint16_t beams[MAX_BEAMS_IN_FRAME];

} oran_tap_info;

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
