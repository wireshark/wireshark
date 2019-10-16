/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-crmf.h                                                              */
/* asn2wrs.py -b -p crmf -c ./crmf.cnf -s ./packet-crmf-template -D . -O ../.. CRMF.asn */

/* Input file: packet-crmf-template.h */

#line 1 "./asn1/crmf/packet-crmf-template.h"
/* packet-crmf.h
 * Routines for RFC2511 Certificate Request Message Format packet dissection
 *   Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_CRMF_H
#define PACKET_CRMF_H


/*--- Included file: packet-crmf-exp.h ---*/
#line 1 "./asn1/crmf/packet-crmf-exp.h"
int dissect_crmf_CertReqMessages(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_crmf_CertTemplate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_crmf_AttributeTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_crmf_PKIPublicationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_crmf_EncryptedValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_crmf_CertId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-crmf-exp.h ---*/
#line 16 "./asn1/crmf/packet-crmf-template.h"

#endif  /* PACKET_CRMF_H */

