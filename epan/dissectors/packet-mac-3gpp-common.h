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
    guint16  rnti;
    guint16  ueid;
    guint8   rntiType;
    guint8   isPredefinedData;
    gboolean crcStatusValid;
    int      crcStatus;  // mac_lte_crc_status
    guint8   direction;

    guint8   isPHYRetx;
    guint16  ueInTTI;
    nstime_t mac_time;

    /* Number of bytes (which part is used depends upon context settings) */
    guint32  single_number_of_bytes;
    guint32  bytes_for_lcid[MAC_3GPP_DATA_LCID_COUNT_MAX];
    guint32  sdus_for_lcid[MAC_3GPP_DATA_LCID_COUNT_MAX];
    guint8   number_of_rars;
    guint8   number_of_paging_ids;

    /* Number of padding bytes includes padding subheaders and trailing padding */
    guint16  padding_bytes;
    guint16  raw_length;
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
