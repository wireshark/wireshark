/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-s1ap.h                                                              */
/* ../../tools/asn2wrs.py -p s1ap -c ./s1ap.cnf -s ./packet-s1ap-template -D . -O ../../epan/dissectors S1AP-CommonDataTypes.asn S1AP-Constants.asn S1AP-Containers.asn S1AP-IEs.asn S1AP-PDU-Contents.asn S1AP-PDU-Descriptions.asn S1AP-SonTransfer-IEs.asn */

/* Input file: packet-s1ap-template.h */

#line 1 "../../asn1/s1ap/packet-s1ap-template.h"
/* packet-s1ap.h
 * Routines for E-UTRAN S1 Application Protocol (S1AP) packet dissection
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

#ifndef PACKET_S1AP_H
#define PACKET_S1AP_H


/*--- Included file: packet-s1ap-exp.h ---*/
#line 1 "../../asn1/s1ap/packet-s1ap-exp.h"
WS_DLL_PUBLIC const value_string s1ap_CauseMisc_vals[];
WS_DLL_PUBLIC const value_string s1ap_CauseProtocol_vals[];
WS_DLL_PUBLIC const value_string s1ap_CauseRadioNetwork_vals[];
WS_DLL_PUBLIC const value_string s1ap_CauseTransport_vals[];
WS_DLL_PUBLIC const value_string s1ap_CauseNas_vals[];
extern const value_string s1ap_SONtransferRequestContainer_vals[];
extern const value_string s1ap_SONtransferResponseContainer_vals[];
int dissect_s1ap_Global_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_s1ap_SONtransferRequestContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_s1ap_SONtransferResponseContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_s1ap_Global_ENB_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_s1ap_ENB_StatusTransfer_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_s1ap_SONtransferApplicationIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_s1ap_SONtransferRequestContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_s1ap_SONtransferResponseContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_s1ap_SONtransferCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-s1ap-exp.h ---*/
#line 27 "../../asn1/s1ap/packet-s1ap-template.h"

#endif  /* PACKET_S1AP_H */
