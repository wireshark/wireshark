/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkix1implicit.h                                                     */
/* asn2wrs.py -b -p pkix1implicit -c ./pkix1implicit.cnf -s ./packet-pkix1implicit-template -D . -O ../.. PKIX1IMPLICIT93.asn */

/* Input file: packet-pkix1implicit-template.h */

#line 1 "./asn1/pkix1implicit/packet-pkix1implicit-template.h"
/* packet-pkix1implicit.h
 * Routines for PKIX1Implicit packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PKIX1IMPLICIT_H
#define PACKET_PKIX1IMPLICIT_H

int dissect_pkix1implicit_GeneralName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
int dissect_pkix1implicit_ReasonFlags(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);


/*--- Included file: packet-pkix1implicit-exp.h ---*/
#line 1 "./asn1/pkix1implicit/packet-pkix1implicit-exp.h"
int dissect_pkix1implicit_KeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_pkix1implicit_AuthorityInfoAccessSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_pkix1implicit_UserNotice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-pkix1implicit-exp.h ---*/
#line 18 "./asn1/pkix1implicit/packet-pkix1implicit-template.h"

#endif  /* PACKET_PKIX1IMPLICIT_H */

