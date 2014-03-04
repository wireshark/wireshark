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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __PACKET_GMR1_RR_H__
#define __PACKET_GMR1_RR_H__

extern void
gmr1_get_msg_rr_params(guint8 oct, int dcch, const gchar **msg_str,
                       int *ett_tree, int *hf_idx, gmr1_msg_func_t *msg_func_p);

#endif /* __PACKET_GMR1_RR_H__ */
