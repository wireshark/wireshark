/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkinit.h                                                            */
/* asn2wrs.py -b -p pkinit -c ./pkinit.cnf -s ./packet-pkinit-template -D . -O ../.. PKINIT.asn */

/* Input file: packet-pkinit-template.h */

#line 1 "./asn1/pkinit/packet-pkinit-template.h"
/* packet-pkinit.h
 * Routines for PKINIT packet dissection
 *  Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_PKINIT_H
#define PACKET_PKINIT_H

int dissect_pkinit_PA_PK_AS_REQ(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
int dissect_pkinit_PA_PK_AS_REP(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);


/*--- Included file: packet-pkinit-exp.h ---*/
#line 1 "./asn1/pkinit/packet-pkinit-exp.h"
extern const value_string pkinit_PaPkAsRep_vals[];
int dissect_pkinit_PaPkAsReq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_pkinit_PaPkAsRep(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_pkinit_PA_PK_AS_REQ_Win2k(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_pkinit_PA_PK_AS_REP_Win2k(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-pkinit-exp.h ---*/
#line 19 "./asn1/pkinit/packet-pkinit-template.h"

#endif  /* PACKET_PKINIT_H */

