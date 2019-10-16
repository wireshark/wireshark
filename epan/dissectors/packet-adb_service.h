/* packet-adb_service.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ADB_SERVICE_H__
#define __PACKET_ADB_SERVICE_H__

gint dissect_ascii_uint32(proto_tree *tree, gint hf_hex_ascii, gint ett_hex_ascii,
        gint hf_value, tvbuff_t *tvb, gint offset, guint32 *value);

typedef struct {
    guint32        session_key_length;
    guint32       *session_key;

    const gchar   *service;
    gint           direction;
} adb_service_data_t;

#endif /* __PACKET_ADB_SERVICE_H__ */

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
