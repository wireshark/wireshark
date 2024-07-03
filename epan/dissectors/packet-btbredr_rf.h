/* packet-btbredr_rf.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

typedef struct _reassembly_t {
    unsigned   segment_len_rem;
    uint32_t l2cap_index;
    unsigned   seqn : 1;
} reassembly_t;

typedef struct _connection_info_t {
    reassembly_t reassembly[2];
    nstime_t     timestamp;
    uint32_t     btclock;
    uint32_t     interface_id;
    uint32_t     adapter_id;
    uint16_t     escosize[2];
    uint8_t      bd_addr[2][6];
    uint8_t      lt_addr;
    uint8_t      escohandle;
    uint8_t      esco : 1;
} connection_info_t;

connection_info_t *
btbredr_rf_add_esco_link(connection_info_t *cinfo, packet_info *pinfo, uint8_t handle, uint32_t ltaddr, uint16_t pktszms, uint16_t pktszsm);

void
btbredr_rf_remove_esco_link(connection_info_t *cinfo, packet_info *pinfo, uint8_t handle);
