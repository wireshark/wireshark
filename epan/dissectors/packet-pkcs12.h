/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkcs12.h                                                            */
/* asn2wrs.py -b -p pkcs12 -c ./pkcs12.cnf -s ./packet-pkcs12-template -D . -O ../.. pkcs12.asn */

/* Input file: packet-pkcs12-template.h */

#line 1 "./asn1/pkcs12/packet-pkcs12-template.h"
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

