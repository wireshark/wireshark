/* packet-lin.h
 *
 * Definitions for LIN
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de> / <lars.voelker@bmw.de>
 * Copyright 2021-2023 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_LIN_H__
#define __PACKET_LIN_H__

#define LIN_PAYLOAD_LENGTH_MASK                         0xf0

#define LIN_MSG_TYPE_MASK                               0x0c
#define LIN_MSG_TYPE_FRAME                              0
#define LIN_MSG_TYPE_EVENT                              3

#define LIN_CHECKSUM_TYPE_MASK                          0x03

#define LIN_FRAME_ID_MASK                               0x3f

#define LIN_EVENT_TYPE_GO_TO_SLEEP_EVENT_BY_GO_TO_SLEEP 0xB0B00001
#define LIN_EVENT_TYPE_GO_TO_SLEEP_EVENT_BY_INACTIVITY  0xB0B00002
#define LIN_EVENT_TYPE_WAKE_UP_BY_WAKE_UP_SIGNAL        0xB0B00004

#define LIN_ERROR_NO_SLAVE_RESPONSE                     0x01
#define LIN_ERROR_FRAMING_ERROR                         0x02
#define LIN_ERROR_PARITY_ERROR                          0x04
#define LIN_ERROR_CHECKSUM_ERROR                        0x08
#define LIN_ERROR_INVALID_ID_ERROR                      0x10
#define LIN_ERROR_OVERFLOW_ERROR                        0x20


#define LIN_DIAG_MASTER_REQUEST_FRAME                   0x3c
#define LIN_DIAG_SLAVE_RESPONSE_FRAME                   0x3d
#define LIN_ID_MASK                                     0x3f

/* bus_id 0 means ANY Bus */
struct lin_info {
    uint32_t id;
    uint16_t bus_id;
    uint16_t len;
};

typedef struct lin_info lin_info_t;

bool lin_set_source_and_destination_columns(packet_info* pinfo, lin_info_t *lininfo);

int dissect_lin_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, lin_info_t *lininfo);

#endif /* __PACKET_LIN_H__ */

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
