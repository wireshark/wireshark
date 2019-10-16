/* packet-btavctp.h
 * Headers for AVCTP
 *
 * Copyright 2012, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BTAVCTP_H__
#define __PACKET_BTAVCTP_H__

typedef struct _btavctp_data_t {
    guint32   interface_id;
    guint32   adapter_id;
    guint16   chandle;  /* only low 12 bits used */
    guint16   psm;
    guint8    cr;
} btavctp_data_t;

extern int proto_btavctp;

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
