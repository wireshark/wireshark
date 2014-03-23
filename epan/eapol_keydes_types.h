/* eapol_keydes_types.h
 * Declarations of EAPOL Key Descriptor types
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

#ifndef __EAPOL_KEYDES_TYPES_H__
#define __EAPOL_KEYDES_TYPES_H__

#define EAPOL_RC4_KEY           1 /* RC4 - deprecated */
#define EAPOL_RSN_KEY           2 /* 802.11i - "work in progress" */
#define EAPOL_WPA_KEY           254

#endif /* __EAPOL_KEYDES_TYPES_H__ */
