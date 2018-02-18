/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-h235.h                                                              */
/* asn2wrs.py -p h235 -c ./h235.cnf -s ./packet-h235-template -D . -O ../.. H235-SECURITY-MESSAGES.asn H235-SRTP.asn */

/* Input file: packet-h235-template.h */

#line 1 "./asn1/h235/packet-h235-template.h"
/* packet-h235.h
 * Routines for H.235 packet dissection
 * 2004  Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_H235_H
#define PACKET_H235_H


/*--- Included file: packet-h235-exp.h ---*/
#line 1 "./asn1/h235/packet-h235-exp.h"
extern const value_string h235_AuthenticationMechanism_vals[];
extern const value_string h235_CryptoToken_vals[];
int dissect_h235_TimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h235_AuthenticationMechanism(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h235_ClearToken(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h235_SIGNED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h235_ENCRYPTED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h235_HASHED(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h235_CryptoToken(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_h235_SrtpKeys(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-h235-exp.h ---*/
#line 16 "./asn1/h235/packet-h235-template.h"

#endif  /* PACKET_H235_H */

