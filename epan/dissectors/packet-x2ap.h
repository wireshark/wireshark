/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-x2ap.h                                                              */
/* asn2wrs.py -p x2ap -c ./x2ap.cnf -s ./packet-x2ap-template -D . -O ../.. X2AP-CommonDataTypes.asn X2AP-Constants.asn X2AP-Containers.asn X2AP-IEs.asn X2AP-PDU-Contents.asn X2AP-PDU-Descriptions.asn */

/* Input file: packet-x2ap-template.h */

#line 1 "./asn1/x2ap/packet-x2ap-template.h"
/* packet-x2ap.h
 * Routines for E-UTRAN X2 Application Protocol (S1AP) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_X2AP_H
#define PACKET_X2AP_H


/*--- Included file: packet-x2ap-exp.h ---*/
#line 1 "./asn1/x2ap/packet-x2ap-exp.h"
int dissect_x2ap_MeNBResourceCoordinationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_x2ap_ProtectedEUTRAResourceIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_x2ap_SgNBResourceCoordinationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_x2ap_EUTRANRCellResourceCoordinationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_x2ap_EUTRANRCellResourceCoordinationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-x2ap-exp.h ---*/
#line 15 "./asn1/x2ap/packet-x2ap-template.h"

#endif  /* PACKET_X2AP_H */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
