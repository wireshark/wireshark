/* packet-hsfz.h
 * HSFZ Dissector
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2013-2019 BMW Group, Dr. Lars Voelker
 * Copyright 2020-2023 Technica Engineering, Dr. Lars Voelker
 * Copyright 2023-2023 BMW Group, Hermann Leinsle
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_HSFZ_H__
#define __PACKET_HSFZ_H__

typedef struct hsfz_info {
    uint8_t target_address;
    uint8_t source_address;
} hsfz_info_t;

#endif /* __PACKET_HSFZ_H__ */

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
