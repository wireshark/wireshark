/* packet-btle.h
 * Structures for determining the dissection context for BTLE.
 *
 * Copyright 2014, Christopher D. Kilgour, techie at whiterocker dot com
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __PACKET_BTLE_H__
#define __PACKET_BTLE_H__

#include "packet-bluetooth.h"

/*
 * These structures are meant to support the provision of contextual
 * metadata to the BTLE dissector.
 */
typedef struct {
    guint64 InitA;
    guint64 AdvA;
    guint32 LinkAA;
    guint32 CRCInit;
    guint8  WinSize;
    guint16 WinOffset;
    guint16 Interval;
    guint16 Latency;
    guint16 Timeout;
    guint64 ChM;
    guint8  Hop;
    guint8  SCA;
} btle_CONNECT_REQ_t;

typedef enum {
    E_AA_NO_COMMENT = 0,
    E_AA_MATCHED,
    E_AA_BIT_ERRORS,
    E_AA_ILLEGAL
} btle_AA_category_t;

#define BTLE_DIR_UNKNOWN 0
#define BTLE_DIR_MASTER_SLAVE 1
#define BTLE_DIR_SLAVE_MASTER 2

#define BTLE_PDU_TYPE_UNKNOWN     0 /* Unknown physical channel PDU */
#define BTLE_PDU_TYPE_ADVERTISING 1 /* Advertising physical channel PDU */
#define BTLE_PDU_TYPE_DATA        2 /* Data physical channel PDU */

#define LE_1M_PHY     0
#define LE_2M_PHY     1
#define LE_CODED_PHY  2

typedef struct {
    btle_AA_category_t aa_category;
    btle_CONNECT_REQ_t connection_info;
    guint connection_info_valid: 1;
    guint crc_checked_at_capture: 1;
    guint crc_valid_at_capture: 1;
    guint mic_checked_at_capture: 1;
    guint mic_valid_at_capture: 1;
    guint direction: 2; /* 0 Unknown, 1 Master -> Slave, 2 Slave -> Master */
    guint aux_pdu_type_valid: 1;
    guint8 pdu_type;
    guint8 aux_pdu_type;
    guint8 channel;
    guint8 phy;

    union {
        void              *data;
        bluetooth_data_t  *bluetooth_data;
    } previous_protocol_data;
} btle_context_t;

#endif /* __PACKET_BTLE_H__ */

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
