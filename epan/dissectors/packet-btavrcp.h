/* packet-btavrcp.h
 * Headers for AVRCP
 *
 * Copyright 2014, Michal Labedzki for Tieto Corporation
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BTAVRCP_H__
#define __PACKET_BTAVRCP_H__

extern wmem_tree_t *btavrcp_song_positions;

typedef struct _btavrcp_song_position_data_t {
    guint32   song_position;
    guint32   used_in_frame;
} btavrcp_song_position_data_t;

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
