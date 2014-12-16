/* packet-rdm.h
 * Declarations for dissecting RDM PIDs
 * Copyright 2014, Claudius Zingerli <czingerl@gmail.com>
 *
 * RDM Parameter IDs (PIDs) are used in
 *   - packet-rdm.c (Ansi E1.20,E1.33 (ACN))
 *   - packet-artnet.c (Art-Net3)
 * -> Declarations remain in packet-rdm.c
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

#ifndef __PACKET_RDM_H__
#define __PACKET_RDM_H__

extern value_string_ext rdm_param_id_vals_ext;


#endif /* #ifndef __PACKET_RDM_H__ */
