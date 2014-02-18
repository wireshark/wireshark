/* packet-pkcs12.h
 * Routines for PKCS#12 Personal Information Exchange packet dissection
 * Graeme Lunt 2006
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

#ifndef PACKET_PKCS12_H
#define PACKET_PKCS12_H

void PBE_reset_parameters(void);
int PBE_decrypt_data(const char *object_identifier_id, tvbuff_t *encrypted_tvb, asn1_ctx_t *actx, proto_item *item);

#endif  /* PACKET_PKCS12_H */

