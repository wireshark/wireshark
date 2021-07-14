/* packet-iso15765.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ISO15765_H__
#define __PACKET_ISO15765_H__

#define ISO15765_TYPE_NONE    0
#define ISO15765_TYPE_CAN     1
#define ISO15765_TYPE_CAN_FD  2
#define ISO15765_TYPE_LIN     3

struct iso15765_info {
    guint32 bus_type;
    guint32 id;
    guint32 len;
};

typedef struct iso15765_info iso15765_info_t;

#endif /* __PACKET_ISO15765_H__ */

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
