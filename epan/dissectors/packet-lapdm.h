/* packet-lapdm.h
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

#ifndef __PACKET_BTL2CAP_H__
#define __PACKET_BTL2CAP_H__

/* See GSM TS 04.06 */
enum lapdm_hdr_type {
    LAPDM_HDR_FMT_A,
    LAPDM_HDR_FMT_B,
    LAPDM_HDR_FMT_Bter,
    LAPDM_HDR_FMT_B4,
    LAPDM_HDR_FMT_C,
};

typedef struct _lapdm_data_t {
    enum lapdm_hdr_type hdr_type;
} lapdm_data_t;

#endif
