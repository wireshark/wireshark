/* packet-gmr1_rr.h
 *
 * Exported routines for GMR-1 Radio Resource dissection in wireshark.
 * Copyright (c) 2011 Sylvain Munaut <tnt@246tNt.com>
 *
 * References:
 *  [1] ETSI TS 101 376-4-8 V1.3.1 - GMR-1 04.008
 *  [2] ETSI TS 101 376-4-8 V2.2.1 - GMPRS-1 04.008
 *  [3] ETSI TS 101 376-4-8 V3.1.1 - GMR-1 3G 44.008
 *  [4] ETSI TS 100 940 V7.21.0 - GSM 04.08
 *  [5] ETSI TS 101 376-4-12 V3.2.1 - GMR-1 3G 44.060
 *  [6] ETSI TS 101 376-5-6 V1.3.1 - GMR-1 05.008
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_GMR1_RR_H__
#define __PACKET_GMR1_RR_H__

extern void
gmr1_get_msg_rr_params(guint8 oct, int dcch, const gchar **msg_str,
                       int *ett_tree, int *hf_idx, gmr1_msg_func_t *msg_func_p);

#endif /* __PACKET_GMR1_RR_H__ */
