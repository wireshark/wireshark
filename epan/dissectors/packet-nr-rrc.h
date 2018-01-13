/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-nr-rrc.h                                                            */
/* asn2wrs.py -L -p nr-rrc -c ./nr-rrc.cnf -s ./packet-nr-rrc-template -D . -O ../.. NR-InterNodeDefinitions.asn NR-RRC-Definitions.asn */

/* Input file: packet-nr-rrc-template.h */

#line 1 "./asn1/nr-rrc/packet-nr-rrc-template.h"
/* packet-nr-rrc-template.h
 * Copyright 2018, Pascal Quantin
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef PACKET_NR_RRC_H
#define PACKET_NR_RRC_H


/*--- Included file: packet-nr-rrc-exp.h ---*/
#line 1 "./asn1/nr-rrc/packet-nr-rrc-exp.h"
int dissect_nr_rrc_SCG_ConfigInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_nr_rrc_UL_DCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_nr_rrc_RRCReconfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_nr_rrc_RRCReconfigurationComplete_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_nr_rrc_MeasResults_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_nr_rrc_RadioBearerConfig_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_nr_rrc_UE_MRDC_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_nr_rrc_UE_NR_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-nr-rrc-exp.h ---*/
#line 15 "./asn1/nr-rrc/packet-nr-rrc-template.h"

#endif  /* PACKET_NR_RRC_H */
