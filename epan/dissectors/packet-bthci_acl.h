/* packet-bthci_acl.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BTHCI_ACL_H__
#define __PACKET_BTHCI_ACL_H__

typedef struct _bthci_acl_data_t {
    guint32   interface_id;
    guint32   adapter_id;
    guint32  *adapter_disconnect_in_frame;
    guint16   chandle;  /* only low 12 bits used */
    guint32  *disconnect_in_frame;

    guint32 remote_bd_addr_oui;
    guint32 remote_bd_addr_id;
    gboolean is_btle;
    gboolean is_btle_retransmit;
} bthci_acl_data_t;

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
