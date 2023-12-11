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
    guint8          rlcMode;
    guint8          direction;
    guint8          priority;
    guint16         ueid;
    guint16         channelType;
    guint16         channelId;
    guint16         pduLength;
    guint8          sequenceNumberLength;

    nstime_t        rlc_time;
    guint8          loggedInMACFrame;

    gboolean        sequenceNumberGiven;  // absent for NR UM if not segmented
    guint32         sequenceNumber;
    guint8          isResegmented;        // LTE only..
    guint8          isControlPDU;
    guint32         ACKNo;
    #define MAX_NACKs 512
    guint16         noOfNACKs;
    guint32         NACKs[MAX_NACKs];

    guint16         missingSNs;
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
