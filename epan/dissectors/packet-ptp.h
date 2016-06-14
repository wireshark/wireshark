/* packet-ptp.h
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

#ifndef __PACKET_PTP_H__
#define __PACKET_PTP_H__

extern value_string_ext ptp_v2_networkProtocol_vals_ext;
extern value_string_ext ptp_v2_clockAccuracy_vals_ext;
extern value_string_ext ptp_v2_timeSource_vals_ext;
extern value_string_ext ptp_v2_portState_vals_ext;
extern const value_string ptp_v2_delayMechanism_vals[];

#endif /* packet-ptp.h */
