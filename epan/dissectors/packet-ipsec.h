/* packet-ipsec.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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

#ifndef __PACKET_IPSEC_H__
#define __PACKET_IPSEC_H__


/* Configure a new SA (programmatically, most likely from a private dissector).
   The arugments here are deliberately in the same string formats as the UAT fields
   in order to keep code paths common.
   Note that an attempt to match with these entries will be made *before* entries
   added through the UAT entry interface/file. */
WS_DLL_PUBLIC void esp_sa_record_add_from_dissector(guint8 protocol, const gchar *srcIP, const char *dstIP,
                                                    gchar *spi,
                                                    guint8 encryption_algo, const gchar *encryption_key,
                                                    guint8 authentication_algo, const gchar *authentication_key);

#endif
