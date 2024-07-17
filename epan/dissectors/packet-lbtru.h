/* packet-lbtru.h
 * Routines for LBT-RU Packet dissection
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LBTRU_H_INCLUDED
#define PACKET_LBTRU_H_INCLUDED

typedef struct
{
    address source_address;
    uint16_t source_port;
    uint32_t session_id;
    uint64_t channel;
    uint32_t next_client_id;
    wmem_list_t * client_list;
} lbtru_transport_t;

typedef struct
{
    address receiver_address;
    uint16_t receiver_port;
    uint32_t id;
    lbtru_transport_t * transport;
    wmem_tree_t * frame;
    lbm_transport_frame_t * last_frame;
    lbm_transport_frame_t * last_data_frame;
    lbm_transport_frame_t * last_sm_frame;
    lbm_transport_frame_t * last_nak_frame;
    lbm_transport_frame_t * last_ncf_frame;
    lbm_transport_frame_t * last_ack_frame;
    lbm_transport_frame_t * last_creq_frame;
    lbm_transport_frame_t * last_rst_frame;
    wmem_tree_t * data_sqn;
    wmem_tree_t * sm_sqn;
    uint32_t data_high_sqn;
    uint32_t sm_high_sqn;
} lbtru_client_transport_t;

lbtru_transport_t * lbtru_transport_add(const address * source_address, uint16_t source_port, uint32_t session_id, uint32_t frame);
char * lbtru_transport_source_string(const address * source_address, uint16_t source_port, uint32_t session_id);

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
