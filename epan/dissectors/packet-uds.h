/* packet-uds.h
 * ISO 14229-2 ISO UDS
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2021-2021 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_UDS_H__
#define __PACKET_UDS_H__

#define UDS_SID_MASK    0xBF
#define UDS_REPLY_MASK  0x40

#define UDS_SERVICES_DSC     0x10
#define UDS_SERVICES_ER      0x11
#define UDS_SERVICES_CDTCI   0x14
#define UDS_SERVICES_RDTCI   0x19
#define UDS_SERVICES_RDBI    0x22
#define UDS_SERVICES_RMBA    0x23
#define UDS_SERVICES_RSDBI   0x24
#define UDS_SERVICES_SA      0x27
#define UDS_SERVICES_CC      0x28
#define UDS_SERVICES_ARS     0x29
#define UDS_SERVICES_RDBPI   0x2A
#define UDS_SERVICES_DDDI    0x2C
#define UDS_SERVICES_WDBI    0x2E
#define UDS_SERVICES_IOCBI   0x2F
#define UDS_SERVICES_RC      0x31
#define UDS_SERVICES_RD      0x34
#define UDS_SERVICES_RU      0x35
#define UDS_SERVICES_TD      0x36
#define UDS_SERVICES_RTE     0x37
#define UDS_SERVICES_RFT     0x38
#define UDS_SERVICES_WMBA    0x3D
#define UDS_SERVICES_TP      0x3E
#define UDS_SERVICES_ERR     0x3F
#define UDS_SERVICES_SDT     0x84
#define UDS_SERVICES_CDTCS   0x85
#define UDS_SERVICES_ROE     0x86
#define UDS_SERVICES_LC      0x87

typedef struct uds_info {
    guint32  id;
    guint32  uds_address;
    gboolean reply;
    guint8   service;
} uds_info_t;

#endif /* __PACKET_UDS_H__ */

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
