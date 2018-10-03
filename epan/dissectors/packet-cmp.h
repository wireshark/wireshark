/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-cmp.h                                                               */
/* asn2wrs.py -b -p cmp -c ./cmp.cnf -s ./packet-cmp-template -D . -O ../.. CMP.asn */

/* Input file: packet-cmp-template.h */

#line 1 "./asn1/cmp/packet-cmp-template.h"
/* packet-cmp.h
 * Routines for RFC2510 Certificate Management Protocol packet dissection
 *   Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CMP_H
#define PACKET_CMP_H

void proto_reg_handoff_cmp(void);


/*--- Included file: packet-cmp-exp.h ---*/
#line 1 "./asn1/cmp/packet-cmp-exp.h"
int dissect_cmp_PKIMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_cmp_ProtectedPart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_cmp_OOBCert(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_cmp_OOBCertHash(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-cmp-exp.h ---*/
#line 18 "./asn1/cmp/packet-cmp-template.h"

#endif  /* PACKET_CMP_H */

