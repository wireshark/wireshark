/* preferences.h
 * Header file for the TRANSUM response time analyzer post-dissector
 * By Paul Offord <paul.offord@advance7.com>
 * Copyright 2016 Advance Seven Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>

#define RTE_TIME_SEC 1
#define RTE_TIME_MSEC 1000
#define RTE_TIME_USEC 1000000

#define TRACE_CAP_CLIENT 1
#define TRACE_CAP_INTERMEDIATE 2
#define TRACE_CAP_SERVICE 3

/* Add entries to the service port table for packets to be treated as services
* This is populated with preferences "service ports" data */
typedef struct _TSUM_PREFERENCES
{
    int      capture_position;
    gboolean reassembly;
    wmem_map_t *tcp_svc_ports;
    wmem_map_t *udp_svc_ports;
    gboolean orphan_ka_discard;
    int      time_multiplier;
    gboolean rte_on_first_req;
    gboolean rte_on_last_req;
    gboolean rte_on_first_rsp;
    gboolean rte_on_last_rsp;
    gboolean summarisers_enabled;
    gboolean summarise_tds;
    gboolean summarisers_escape_quotes;
    gboolean debug_enabled;
} TSUM_PREFERENCES;
