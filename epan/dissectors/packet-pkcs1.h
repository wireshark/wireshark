/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkcs1.h                                                             */
/* asn2wrs.py -b -p pkcs1 -c ./pkcs1.cnf -s ./packet-pkcs1-template -D . -O ../.. PKIXAlgs-2009.asn */

/* Input file: packet-pkcs1-template.h */

#line 1 "./asn1/pkcs1/packet-pkcs1-template.h"
/* packet-pkcs1.h
 * Routines for PKCS#1/RFC2313 packet dissection
 *  Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PKCS1_H
#define PACKET_PKCS1_H


/*--- Included file: packet-pkcs1-exp.h ---*/
#line 1 "./asn1/pkcs1/packet-pkcs1-exp.h"
int dissect_pkcs1_RSAPublicKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_pkcs1_DigestInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-pkcs1-exp.h ---*/
#line 16 "./asn1/pkcs1/packet-pkcs1-template.h"

#endif  /* PACKET_PKCS1_H */

