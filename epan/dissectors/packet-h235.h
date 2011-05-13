/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-h235.h                                                              */
/* ../../tools/asn2wrs.py -e -p h235 -c ./h235.cnf -s ./packet-h235-template -D . H235-SECURITY-MESSAGES.asn H235-SRTP.asn */

/* Input file: packet-h235-template.h */

#line 1 "../../asn1/h235/packet-h235-template.h"
/* packet-h235.h
 * Routines for H.235 packet dissection
 * 2004  Tomas Kukosa
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_H235_H
#define PACKET_H235_H


/*--- Included file: packet-h235-exp.h ---*/
#line 1 "../../asn1/h235/packet-h235-exp.h"
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
#line 30 "../../asn1/h235/packet-h235-template.h"

#endif  /* PACKET_H235_H */

