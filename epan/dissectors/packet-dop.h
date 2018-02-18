/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-dop.h                                                               */
/* asn2wrs.py -b -p dop -c ./dop.cnf -s ./packet-dop-template -D . -O ../.. dop.asn */

/* Input file: packet-dop-template.h */

#line 1 "./asn1/dop/packet-dop-template.h"
/* packet-x501.h
 * Routines for X.501 (DSA Operational Attributes) packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_X501_H
#define PACKET_X501_H


/*--- Included file: packet-dop-exp.h ---*/
#line 1 "./asn1/dop/packet-dop-exp.h"
int dissect_dop_DSEType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_dop_SupplierAndConsumers(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_dop_OperationalBindingID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-dop-exp.h ---*/
#line 16 "./asn1/dop/packet-dop-template.h"

#endif  /* PACKET_X501_H */
