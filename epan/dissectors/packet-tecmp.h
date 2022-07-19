 /* packet-tecmp.h
  *
  * Definitions for TECMP
  * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
  * Copyright 2022-2022 Dr. Lars Voelker
  *
  * Wireshark - Network traffic analyzer
  * By Gerald Combs <gerald@wireshark.org>
  * Copyright 1998 Gerald Combs
  *
  * SPDX-License-Identifier: GPL-2.0-or-later
  */

#ifndef __PACKET_TECMP_H__
#define __PACKET_TECMP_H__

#define TECMP_PAYLOAD_INTERFACE_ID "tecmp.payload.interface_id"

typedef struct tecmp_info {
    guint32 interface_id;
    guint16 device_id;
    guint16 data_type;
    guint8  msg_type;
} tecmp_info_t;

#endif /* __PACKET_TECMP_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
