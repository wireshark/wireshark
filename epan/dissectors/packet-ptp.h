/* packet-ptp.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_PTP_H__
#define __PACKET_PTP_H__

extern value_string_ext ptp_v2_clockAccuracy_vals_ext;
extern value_string_ext ptp_v2_timeSource_vals_ext;
extern value_string_ext ptp_v2_portState_vals_ext;
extern const value_string ptp_v2_delayMechanism_vals[];

void dissect_ptp_v2_timeInterval(tvbuff_t *tvb, int *cur_offset, proto_tree *tree,
                                 const char* name,
                                 int hf_ptp_v2_timeInterval_ns, int hf_ptp_v2_timeInterval_subns,
                                 proto_tree **tree_out, int64_t *ns_out);


#endif /* packet-ptp.h */
