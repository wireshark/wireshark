/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-rrc.h                                                               */
/* asn2wrs.py -p rrc -c ./rrc.cnf -s ./packet-rrc-template -D . -O ../.. Class-definitions.asn PDU-definitions.asn InformationElements.asn Constant-definitions.asn Internode-definitions.asn */

/* Input file: packet-rrc-template.h */

#line 1 "./asn1/rrc/packet-rrc-template.h"
/* packet-rrc-template.h
 * Copyright 2009, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RRC_H
#define PACKET_RRC_H

#include <epan/asn1.h>    /* Needed for non asn1 dissectors?*/

extern int proto_rrc;

/*--- Included file: packet-rrc-exp.h ---*/
#line 1 "./asn1/rrc/packet-rrc-exp.h"
int dissect_rrc_InterRATHandoverInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_rrc_HandoverToUTRANCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_InterRATHandoverInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_MeasurementReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_MasterInformationBlock_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType4_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType5_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType6_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType7_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType11_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType12_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType13_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType13_1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType13_2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType13_3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType13_4_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType14_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType15_1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType15_2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType15_3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType15_4_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType16_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType17_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType18_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoType19_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoTypeSB1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_SysInfoTypeSB2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_ToTargetRNC_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_rrc_TargetRNC_ToSourceRNC_Container_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-rrc-exp.h ---*/
#line 18 "./asn1/rrc/packet-rrc-template.h"

enum rrc_message_type {
  RRC_MESSAGE_TYPE_INVALID    = 0,
  RRC_MESSAGE_TYPE_PCCH        = 1,
  RRC_MESSAGE_TYPE_UL_CCCH,
  RRC_MESSAGE_TYPE_DL_CCCH,
  RRC_MESSAGE_TYPE_UL_DCCH,
  RRC_MESSAGE_TYPE_DL_DCCH,
  RRC_MESSAGE_TYPE_BCCH_FACH
};

enum nas_sys_info_gsm_map {
  RRC_NAS_SYS_UNKNOWN = 0,
  RRC_NAS_SYS_INFO_CS,
  RRC_NAS_SYS_INFO_PS,
  RRC_NAS_SYS_INFO_CN_COMMON
};

enum rrc_ue_state {
  RRC_UE_STATE_UNKNOWN = 0,
  RRC_UE_STATE_CELL_DCH,
  RRC_UE_STATE_CELL_FACH,
  RRC_UE_STATE_CELL_PCH,
  RRC_UE_STATE_URA_PCH
};

#define MAX_RRC_FRAMES    64
typedef struct rrc_info
{
  enum rrc_message_type msgtype[MAX_RRC_FRAMES];
  guint16 hrnti[MAX_RRC_FRAMES];
} rrc_info;

/*Struct for storing ciphering information*/
typedef struct rrc_ciphering_info
{
  int seq_no[31][2];    /*Indicates for each Rbid when ciphering starts - Indexers are [BearerID][Direction]*/
  GTree * /*guint32*/ start_cs;    /*Start value for CS counter*/
  GTree * /*guint32*/ start_ps;    /*Start value for PS counter*/
  gint32 ciphering_algorithm;    /*Indicates which type of ciphering algorithm used*/
  gint32 integrity_algorithm;    /*Indicates which type of integrity algorithm used*/
  guint32 setup_frame[2];    /*Store which frame contained this information - Indexer is [Direction]*/
  guint32 ps_conf_counters[31][2];    /*This should also be made for CS*/

} rrc_ciphering_info;

extern GTree * hsdsch_muxed_flows;
extern GTree * rrc_ciph_info_tree;
extern wmem_tree_t* rrc_global_urnti_crnti_map;

#endif  /* PACKET_RRC_H */
