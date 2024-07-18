/* packet-rlc-common.h
 *
 * Martin Mathieson
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RLC_COMMON_H
#define PACKET_RLC_COMMON_H


#define RLC_RAT_LTE 0
#define RLC_RAT_NR  1

typedef struct rlc_3gpp_tap_info {
    /* version */
    uint8_t         rat;

    /* Info from context */
    uint8_t         rlcMode;
    uint8_t         direction;
    uint8_t         priority;
    uint16_t        ueid;
    uint16_t        channelType;
    uint16_t        channelId;
    uint16_t        pduLength;
    uint8_t         sequenceNumberLength;

    nstime_t        rlc_time;
    uint8_t         loggedInMACFrame;

    bool            sequenceNumberGiven;  // absent for NR UM if not segmented
    uint32_t        sequenceNumber;
    uint8_t         isResegmented;        // LTE only..
    uint8_t         isControlPDU;
    uint32_t        ACKNo;
    #define MAX_NACKs 512
    uint16_t        noOfNACKs;
    uint32_t        NACKs[MAX_NACKs];

    uint16_t        missingSNs;
} rlc_3gpp_tap_info;

#endif


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
