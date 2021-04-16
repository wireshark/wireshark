/* packet-btbredr_rf.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

typedef struct _reassembly_t {
    guint   segment_len_rem;
    guint32 l2cap_index;
    guint   seqn : 1;
} reassembly_t;

typedef struct _connection_info_t {
    reassembly_t reassembly[2];
    nstime_t     timestamp;
    guint32      btclock;
    guint32      interface_id;
    guint32      adapter_id;
    guint16      escosize[2];
    guint8       bd_addr[2][6];
    guint8       lt_addr;
    guint8       escohandle;
    guint8       esco : 1;
} connection_info_t;

connection_info_t *
btbredr_rf_add_esco_link(connection_info_t *cinfo, packet_info *pinfo, guint8 handle, guint32 ltaddr, guint16 pktszms, guint16 pktszsm);

void
btbredr_rf_remove_esco_link(connection_info_t *cinfo, packet_info *pinfo, guint8 handle);
