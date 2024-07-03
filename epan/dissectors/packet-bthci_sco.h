/* packet-bthci_sco.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BTHCI_SCO_H__
#define __PACKET_BTHCI_SCO_H__

extern wmem_tree_t *bthci_sco_stream_numbers;

typedef struct _bthci_sco_stream_number_t {
    uint32_t stream_number;
} bthci_sco_stream_number_t;

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
