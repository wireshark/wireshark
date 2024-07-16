/* packet-dlt.c
 * DLT Dissector (Header file)
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2013-2022 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_DLT_H__
#define __PACKET_DLT_H__

typedef struct dlt_info {
    const char     *ecu_id;
    uint32_t        message_id;
    bool            little_endian;
    uint8_t         message_type;
    uint8_t         message_type_info_comb;
} dlt_info_t;

#define DLT_MSG_TYPE_LOG_MSG                            0x0
#define DLT_MSG_TYPE_TRACE_MSG                          0x1
#define DLT_MSG_TYPE_NETWORK_MSG                        0x2
#define DLT_MSG_TYPE_CTRL_MSG                           0x3

#define DLT_MSG_TYPE_INFO_LOG_FATAL                     0x10
#define DLT_MSG_TYPE_INFO_LOG_ERROR                     0x20
#define DLT_MSG_TYPE_INFO_LOG_WARN                      0x30
#define DLT_MSG_TYPE_INFO_LOG_INFO                      0x40
#define DLT_MSG_TYPE_INFO_LOG_DEBUG                     0x50
#define DLT_MSG_TYPE_INFO_LOG_VERBOSE                   0x60
#define DLT_MSG_TYPE_INFO_TRACE_VAR                     0x12
#define DLT_MSG_TYPE_INFO_TRACE_FUNC_IN                 0x22
#define DLT_MSG_TYPE_INFO_TRACE_FUNC_OUT                0x32
#define DLT_MSG_TYPE_INFO_TRACE_STATE                   0x42
#define DLT_MSG_TYPE_INFO_TRACE_VFB                     0x52
#define DLT_MSG_TYPE_INFO_NET_IPC                       0x14
#define DLT_MSG_TYPE_INFO_NET_CAN                       0x24
#define DLT_MSG_TYPE_INFO_NET_FLEXRAY                   0x34
#define DLT_MSG_TYPE_INFO_NET_MOST                      0x46
#define DLT_MSG_TYPE_INFO_CTRL_REQ                      0x16
#define DLT_MSG_TYPE_INFO_CTRL_RES                      0x26
#define DLT_MSG_TYPE_INFO_CTRL_TIME                     0x36

int32_t
dlt_ecu_id_to_gint32(const char *ecu_id);

#endif /* __PACKET_DLT_H__ */
