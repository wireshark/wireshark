/* packet-btrfcomm.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BTRFCOMM_H__
#define __PACKET_BTRFCOMM_H__

typedef struct _btrfcomm_data_t {
    uint32_t  interface_id;
    uint32_t  adapter_id;
    uint16_t  chandle;  /* only low 12 bits used */
    uint16_t  cid;
    bool      is_local_psm; /* otherwise it is PSM in remote device */
    uint8_t   dlci;
    uint32_t  remote_bd_addr_oui;
    uint32_t  remote_bd_addr_id;
} btrfcomm_data_t;

extern int proto_btrfcomm;

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
