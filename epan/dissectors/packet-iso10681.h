/* packet-iso10681.h
 * ISO 10681-2 ISO FlexRay TP
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2021-2021 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ISO10681_H__
#define __PACKET_ISO10681_H__

typedef struct iso10681_info {
    guint32 id;
    guint32 len;
    guint16 target_address;
    guint16 source_address;
} iso10681_info_t;

#endif /* __PACKET_ISO10681_H__ */

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
