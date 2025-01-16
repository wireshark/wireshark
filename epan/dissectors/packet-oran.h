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
    SEC_C_MAX_INDEX
};

#define HIGHEST_EXTTYPE 27

typedef struct oran_tap_info {
    /* Key info */
    bool     userplane;
    uint16_t eaxc;
    bool     uplink;
    /* TODO: Timing info */
    uint8_t slot;
    /* Missing SNs */
    uint32_t missing_sns;
    /* TODO: repeated SNs? */
    /* Accumulated state */
    uint32_t pdu_size;
    bool     section_types[SEC_C_MAX_INDEX];
    bool     extensions[HIGHEST_EXTTYPE+1];    /* wasting first entry */

    /* TODO: compression/bitwidth, mu/scs, slots, Section IDs, beams? */
    /* N.B. bitwidth, method, but each section could potentially have different udcompHdr.. */
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
