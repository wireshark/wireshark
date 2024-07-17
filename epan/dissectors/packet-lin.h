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

#define LIN_DIAG_MASTER_REQUEST_FRAME 0x3c
#define LIN_DIAG_SLAVE_RESPONSE_FRAME 0x3d
#define LIN_ID_MASK                   0x3f

/* bus_id 0 means ANY Bus */
struct lin_info {
    uint32_t id;
    uint16_t bus_id;
    uint16_t len;
};

typedef struct lin_info lin_info_t;

bool lin_set_source_and_destination_columns(packet_info* pinfo, lin_info_t *lininfo);

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
