/* packet-bacnet.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BACNET_H__
#define __PACKET_BACNET_H__

extern int
bacnet_dissect_sec_wrapper(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    gint offset, gboolean *pis_net_msg_flg);

#endif /* __PACKET_BACNET_H__ */

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
