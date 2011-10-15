/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-p22.h                                                               */
/* ../../tools/asn2wrs.py -b -C -p p22 -c ./p22.cnf -s ./packet-p22-template -D . -O ../../epan/dissectors IPMSInformationObjects.asn IPMSHeadingExtensions.asn IPMSExtendedBodyPartTypes2.asn IPMSFileTransferBodyPartType.asn IPMSExtendedVoiceBodyPartType.asn IPMSForwardedContentBodyPartType.asn IPMSMessageStoreAttributes.asn IPMSSecurityExtensions.asn IPMSObjectIdentifiers.asn IPMSUpperBounds.asn */

/* Input file: packet-p22-template.h */

#line 1 "../../asn1/p22/packet-p22-template.h"
/* packet-p22.h
 * Routines for X.420 (X.400 Message Transfer) packet dissection
 * Graeme Lunt 2005
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

#ifndef PACKET_P22_H
#define PACKET_P22_H


/*--- Included file: packet-p22-exp.h ---*/
#line 1 "../../asn1/p22/packet-p22-exp.h"
extern const value_string p22_InformationObject_vals[];
extern const value_string p22_NonReceiptReasonField_vals[];
extern const value_string p22_DiscardReasonField_vals[];
int dissect_p22_InformationObject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p22_IPM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p22_ORDescriptor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p22_ExtensionsField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p22_MessageParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p22_IPN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p22_NonReceiptReasonField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p22_DiscardReasonField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_p22_ReceiptTimeField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/*--- End of included file: packet-p22-exp.h ---*/
#line 30 "../../asn1/p22/packet-p22-template.h"

void proto_reg_handoff_p22(void);
void proto_register_p22(void);

#endif  /* PACKET_P22_H */
