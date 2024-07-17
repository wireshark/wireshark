/* packet-lbttcp.h
 * Routines for LBM TCP Packet dissection
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LBTTCP_H_INCLUDED
#define PACKET_LBTTCP_H_INCLUDED

typedef struct
{
    address source_address;
    uint16_t source_port;
    uint32_t session_id;
    uint64_t channel;
    uint32_t next_client_id;
    wmem_list_t * client_list;
} lbttcp_transport_t;

typedef struct
{
    address receiver_address;
    uint16_t receiver_port;
    uint32_t id;
    lbttcp_transport_t * transport;
} lbttcp_client_transport_t;

lbttcp_transport_t * lbttcp_transport_find(const address * source_address, uint16_t source_port, uint32_t session_id, uint32_t frame);
lbttcp_transport_t * lbttcp_transport_add(const address * source_address, uint16_t source_port, uint32_t session_id, uint32_t frame);
char * lbttcp_transport_source_string(const address * source_address, uint16_t source_port, uint32_t session_id);
bool lbttcp_transport_sid_find(const address * source_address, uint16_t source_port, uint32_t frame, uint32_t * session_id);
void lbttcp_transport_sid_add(const address * source_address, uint16_t source_port, uint32_t frame, uint32_t session_id);

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
