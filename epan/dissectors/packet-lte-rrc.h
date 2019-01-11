/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lte-rrc.h                                                           */
/* asn2wrs.py -L -p lte-rrc -c ./lte-rrc.cnf -s ./packet-lte-rrc-template -D . -O ../.. EUTRA-InterNodeDefinitions.asn EUTRA-RRC-Definitions.asn EUTRA-Sidelink-Preconf.asn EUTRA-UE-Variables.asn PC5-RRC-Definitions.asn NBIOT-InterNodeDefinitions.asn NBIOT-RRC-Definitions.asn NBIOT-UE-Variables.asn */

/* Input file: packet-lte-rrc-template.h */

#line 1 "./asn1/lte-rrc/packet-lte-rrc-template.h"
/* packet-lte-rrc-template.h
 * Copyright 2009, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_LTE_RRC_H
#define PACKET_LTE_RRC_H

extern value_string_ext lte_rrc_messageIdentifier_vals_ext;


/*--- Included file: packet-lte-rrc-exp.h ---*/
#line 1 "./asn1/lte-rrc/packet-lte-rrc-exp.h"
int dissect_lte_rrc_HandoverCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_HandoverPreparationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_SCG_Config_r12_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_SCG_ConfigInfo_r12_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_UEPagingCoverageInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_RRCConnectionReconfigurationComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_RLF_Report_r9_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_RLF_Report_v9e0_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_UE_EUTRA_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_VisitedCellInfoList_r12_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_VisitedCellInfo_r12_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_HandoverPreparationInformation_NB_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lte_rrc_UEPagingCoverageInformation_NB_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-lte-rrc-exp.h ---*/
#line 17 "./asn1/lte-rrc/packet-lte-rrc-template.h"

#endif  /* PACKET_LTE_RRC_H */
