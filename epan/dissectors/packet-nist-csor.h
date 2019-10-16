/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-nist-csor.h                                                         */
/* asn2wrs.py -b -p nist-csor -c ./nist-csor.cnf -s ./packet-nist-csor-template -D . -O ../.. aes1.asn */

/* Input file: packet-nist-csor-template.h */

#line 1 "./asn1/nist-csor/packet-nist-csor-template.h"
/* packet-nist-csor.h
 * Routines for NIST CSOR
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_NIST_CSOR_H
#define PACKET_NIST_CSOR_H


/*--- Included file: packet-nist-csor-exp.h ---*/
#line 1 "./asn1/nist-csor/packet-nist-csor-exp.h"
int dissect_nist_csor_CFBParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_nist_csor_AES_IV(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_nist_csor_NumberOfBits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_nist_csor_ShakeOutputLen(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-nist-csor-exp.h ---*/
#line 15 "./asn1/nist-csor/packet-nist-csor-template.h"

#endif  /* PACKET_NIST_CSOR_H */
