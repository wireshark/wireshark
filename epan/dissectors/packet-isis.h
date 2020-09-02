/* packet-isis.h
 * Defines and such for core isis protcol decode.
 *
 * Stuart Stanley <stuarts@mxmail.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _PACKET_ISIS_H
#define _PACKET_ISIS_H

/*
 * The version we support is 1
 */
#define ISIS_REQUIRED_VERSION 1

/*
 * ISIS type field values
 */
#define ISIS_TYPE_L1_HELLO  15
#define ISIS_TYPE_L2_HELLO  16
#define ISIS_TYPE_PTP_HELLO 17
#define ISIS_TYPE_L1_LSP    18
#define ISIS_TYPE_L2_LSP    20
#define ISIS_TYPE_L1_CSNP   24
#define ISIS_TYPE_L2_CSNP   25
#define ISIS_TYPE_L1_PSNP   26
#define ISIS_TYPE_L2_PSNP   27

#define ISIS_TYPE_MASK             0x1f
#define ISIS_TYPE_RESERVED_MASK 0xe0

/*
 * Data given to subdissectors
 */
typedef struct isis_data {
    guint8 header_length;
    guint8 system_id_len;
    guint16 pdu_length;
    proto_item *header_length_item;
    expert_field *ei_bad_header_length;
} isis_data_t;

extern int hf_isis_clv_key_id;

#endif /* _PACKET_ISIS_H */

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
