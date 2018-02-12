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
    guint32 rqst_frame;
    guint32 resp_frame;
    nstime_t rqst_time;
    nstime_t resp_time;
} icmp_transaction_t;

/* ICMP info ... used by sequence analysis tap and stored in pinfo with p_add_proto_data */
typedef struct {
    guint8 type;
    guint8 code;
} icmp_info_t;

#endif
