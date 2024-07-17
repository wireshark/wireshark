/* packet-icmp.h
 * Definitions for ICMP: http://tools.ietf.org/html/rfc792.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ICMP_H__
#define __PACKET_ICMP_H__

/* ICMP echo request/reply transaction statistics ... used by ICMP tap(s) */
typedef struct _icmp_transaction_t {
    uint32_t rqst_frame;
    uint32_t resp_frame;
    nstime_t rqst_time;
    nstime_t resp_time;
} icmp_transaction_t;

/* ICMP info ... used by sequence analysis tap and stored in pinfo with p_add_proto_data */
typedef struct {
    uint8_t type;
    uint8_t code;
} icmp_info_t;

int get_best_guess_timestamp(tvbuff_t *tvb, int offset, nstime_t *comp_ts, nstime_t *out_ts);

#endif
