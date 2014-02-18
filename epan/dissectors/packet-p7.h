/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-p7.h                                                                */
/* ../../tools/asn2wrs.py -b -L -C -p p7 -c ./p7.cnf -s ./packet-p7-template -D . -O ../../epan/dissectors MSAbstractService.asn MSGeneralAttributeTypes.asn MSAccessProtocol.asn MSUpperBounds.asn */

/* Input file: packet-p7-template.h */

#line 1 "../../asn1/p7/packet-p7-template.h"
/* packet-p7.h
 * Routines for X.413 (P7) packet dissection
 * Graeme Lunt 2007
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef PACKET_P7_H
#define PACKET_P7_H


/*--- Included file: packet-p7-exp.h ---*/
#line 1 "../../asn1/p7/packet-p7-exp.h"
extern const value_string p7_SignatureStatus_vals[];
int dissect_p7_SequenceNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p7_SignatureStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-p7-exp.h ---*/
#line 28 "../../asn1/p7/packet-p7-template.h"

#endif  /* PACKET_P7_H */
