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

typedef enum {
    E_AA_NO_COMMENT = 0,
    E_AA_MATCHED,
    E_AA_BIT_ERRORS,
    E_AA_ILLEGAL
} btle_AA_category_t;

#define BTLE_DIR_UNKNOWN 0
#define BTLE_DIR_CENTRAL_PERIPHERAL 1
#define BTLE_DIR_PERIPHERAL_CENTRAL 2

#define BTLE_PDU_TYPE_UNKNOWN       0 /* Unknown physical channel PDU */
#define BTLE_PDU_TYPE_ADVERTISING   1 /* Advertising physical channel PDU */
#define BTLE_PDU_TYPE_DATA          2 /* Data physical channel PDU */
#define BTLE_PDU_TYPE_CONNECTEDISO  3 /* Connected isochronous physical channel PDU */
#define BTLE_PDU_TYPE_BROADCASTISO  4 /* Broadcast isochronous physical channel PDU */

#define LE_1M_PHY     0
#define LE_2M_PHY     1
#define LE_CODED_PHY  2

typedef struct {
    btle_AA_category_t aa_category;
    unsigned crc_checked_at_capture: 1;
    unsigned crc_valid_at_capture: 1;
    unsigned mic_checked_at_capture: 1;
    unsigned mic_valid_at_capture: 1;
    unsigned direction: 2; /* 0 Unknown, 1 Central -> Peripheral, 2 Peripheral -> Central */
    unsigned aux_pdu_type_valid: 1;
    unsigned event_counter_valid: 1;
    uint8_t pdu_type;
    uint8_t aux_pdu_type;
    uint8_t channel;
    uint8_t phy;
    uint16_t event_counter;

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
