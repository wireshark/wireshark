/* packet-mac-common.h
 *
 * Common tap definitions for LTE and NR MAC protocols
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "ws_symbol_export.h"


 /* For LTE, mapped to 0 to 10 and 32 to 38 */
#define MAC_3GPP_DATA_LCID_COUNT_MAX 33

#define MAC_RAT_LTE 0
#define MAC_RAT_NR  1

typedef struct mac_3gpp_tap_info {
    /* version */
    uint8_t  rat;

    /* Info from context */
    uint16_t rnti;
    uint16_t ueid;
    uint8_t  rntiType;
    uint8_t  isPredefinedData;
    bool crcStatusValid;
    int      crcStatus;  // mac_lte_crc_status
    uint8_t  direction;

    uint8_t  isPHYRetx;
    uint16_t ueInTTI;
    nstime_t mac_time;

    /* Number of bytes (which part is used depends upon context settings) */
    uint32_t single_number_of_bytes;
    uint32_t bytes_for_lcid[MAC_3GPP_DATA_LCID_COUNT_MAX];
    uint32_t sdus_for_lcid[MAC_3GPP_DATA_LCID_COUNT_MAX];
    uint8_t  number_of_rars;
    uint8_t  number_of_paging_ids;

    /* Number of padding bytes includes padding subheaders and trailing padding */
    uint16_t padding_bytes;
    uint16_t raw_length;
} mac_3gpp_tap_info;

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
