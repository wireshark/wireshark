/* packet-usbip.h
 * Definitions for USBIP dissection
 * Copyright 2016, Christian Lamparter <chunkeey@googlemail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_USBIP_H__
#define __PACKET_USBIP_H__

#define USBIP_HEADER_WITH_SETUP_LEN 0x28
#define USBIP_HEADER_LEN 0x30

#define USBIP_DIR_OUT 0x00
#define USBIP_DIR_IN 0x01

struct usbip_header {
    guint8 devid;
    guint8 busid;
    guint32 ep;
    guint32 dir;
};

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
