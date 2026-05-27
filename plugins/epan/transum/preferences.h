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
#include <epan/packet.h>
#include <epan/prefs.h>

#define RTE_TIME_SEC 1
#define RTE_TIME_MSEC 1000
#define RTE_TIME_USEC 1000000

#define TRACE_CAP_CLIENT 1
#define TRACE_CAP_INTERMEDIATE 2
#define TRACE_CAP_SERVICE 3

/**
 * @brief Holds all user-configurable preferences governing traffic summarisation, service port classification, and RTE annotation behaviour.
 */
typedef struct _TSUM_PREFERENCES
{
    int        capture_position;          /**< Indicates whether this Wireshark node is positioned at the client or service side of the capture, affecting RR direction logic. */
    bool       reassembly;                /**< True if TCP stream reassembly should be performed before RR pair detection. */
    wmem_map_t *tcp_svc_ports;            /**< Map of TCP port numbers that should be treated as service (server) ports for RR pair detection; populated from the "service ports" preference. */
    wmem_map_t *udp_svc_ports;            /**< Map of UDP port numbers that should be treated as service (server) ports for RR pair detection; populated from the "service ports" preference. */
    bool       orphan_ka_discard;         /**< True if TCP keep-alive packets that cannot be associated with an RR pair should be silently discarded rather than reported. */
    int        time_multiplier;           /**< Scaling factor applied to raw timestamps when computing response-time metrics, allowing unit conversion. */
    bool       rte_on_first_req;          /**< True if an RTE (Response Time Entry) annotation should be added to the first frame of the request APDU. */
    bool       rte_on_last_req;           /**< True if an RTE annotation should be added to the last frame of the request APDU. */
    bool       rte_on_first_rsp;          /**< True if an RTE annotation should be added to the first frame of the response APDU. */
    bool       rte_on_last_rsp;           /**< True if an RTE annotation should be added to the last frame of the response APDU. */
    bool       summarisers_enabled;       /**< True if the summariser output stage is active; when false no summary records are emitted regardless of other settings. */
    bool       summarise_tds;             /**< True if TDS (Tabular Data Stream / SQL Server) conversations should be included in summary output. */
    bool       summarisers_escape_quotes; /**< True if quote characters in summariser output fields should be escaped, e.g. for CSV-safe output. */
    bool       debug_enabled;             /**< True if verbose debug logging is enabled for the TSUM dissector. */
} TSUM_PREFERENCES;

extern TSUM_PREFERENCES preferences;
