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

int dissect_ascii_uint32(proto_tree *tree, int hf_hex_ascii, int ett_hex_ascii,
        int hf_value, tvbuff_t *tvb, int offset, uint32_t *value);

typedef struct {
    uint32_t       session_key_length;
    uint32_t      *session_key;

    const char    *service;
    int            direction;
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
