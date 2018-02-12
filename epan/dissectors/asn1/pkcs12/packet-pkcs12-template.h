/* packet-pkcs12.h
 * Routines for PKCS#12 Personal Information Exchange packet dissection
 * Graeme Lunt 2006
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PKCS12_H
#define PACKET_PKCS12_H

void PBE_reset_parameters(void);
int PBE_decrypt_data(const char *object_identifier_id, tvbuff_t *encrypted_tvb, packet_info *pinfo, asn1_ctx_t *actx, proto_item *item);

#endif  /* PACKET_PKCS12_H */

