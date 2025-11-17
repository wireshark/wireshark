/* packet-nats.h
 *
 * Routines for NATS Client Protocol dissection
 * https://docs.nats.io/reference/reference-protocols/nats-protocol
 *
 * Copyright 2025, Max Dmitrichenko <dmitrmax@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_NATS_H__
#define __PACKET_NATS_H__

#include <wsutil/wmem/wmem_map.h>

typedef struct nats_data
{
    const char* subject;
    const char* reply_to;
    const char* in_reply_to;

    wmem_map_t* headers_map;
} nats_data_t;

#endif //NATS_NATS_H
