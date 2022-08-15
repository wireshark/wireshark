/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ngap.h                                                              */
/* asn2wrs.py -p ngap -c ./ngap.cnf -s ./packet-ngap-template -D . -O ../.. NGAP-CommonDataTypes.asn NGAP-Constants.asn NGAP-Containers.asn NGAP-IEs.asn NGAP-PDU-Contents.asn NGAP-PDU-Descriptions.asn */

/* Input file: packet-ngap-template.h */

#line 1 "./asn1/ngap/packet-ngap-template.h"
/* packet-ngap.h
 * Routines for NG-RAN NG Application Protocol (NGAP) packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_NGAP_H
#define PACKET_NGAP_H


/*--- Included file: packet-ngap-exp.h ---*/
#line 1 "./asn1/ngap/packet-ngap-exp.h"
int dissect_ngap_SecondaryRATDataUsageReportTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_ngap_LastVisitedNGRANCellInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_ngap_LastVisitedPSCellInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_ngap_MobilityRestrictionList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_ngap_MDT_Configuration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_ngap_NGRAN_CGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_ngap_SONConfigurationTransfer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_ngap_SourceNGRANNode_ToTargetNGRANNode_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_ngap_TargetNGRANNode_ToSourceNGRANNode_TransparentContainer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-ngap-exp.h ---*/
#line 15 "./asn1/ngap/packet-ngap-template.h"

#endif  /* PACKET_NGAP_H */

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
