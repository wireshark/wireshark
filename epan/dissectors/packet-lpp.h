/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lpp.h                                                               */
/* asn2wrs.py -p lpp -c ./lpp.cnf -s ./packet-lpp-template -D . -O ../.. LPP-PDU-Definitions.asn LPP-Broadcast-Definitions.asn */

/* Input file: packet-lpp-template.h */

#line 1 "./asn1/lpp/packet-lpp-template.h"
/* packet-lpp.h
 * Routines for 3GPP LTE Positioning Protocol (LPP) packet dissection
 * Copyright 2011-2022 Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#ifndef PACKET_LPP_H
#define PACKET_LPP_H

typedef enum {
    LPP_POS_SIB_TYPE_UNKNOWN,
    LPP_POS_SIB_TYPE_1_1,
    LPP_POS_SIB_TYPE_1_2,
    LPP_POS_SIB_TYPE_1_3,
    LPP_POS_SIB_TYPE_1_4,
    LPP_POS_SIB_TYPE_1_5,
    LPP_POS_SIB_TYPE_1_6,
    LPP_POS_SIB_TYPE_1_7,
    LPP_POS_SIB_TYPE_1_8,
    LPP_POS_SIB_TYPE_1_9,
    LPP_POS_SIB_TYPE_1_10,
    LPP_POS_SIB_TYPE_2_1,
    LPP_POS_SIB_TYPE_2_2,
    LPP_POS_SIB_TYPE_2_3,
    LPP_POS_SIB_TYPE_2_4,
    LPP_POS_SIB_TYPE_2_5,
    LPP_POS_SIB_TYPE_2_6,
    LPP_POS_SIB_TYPE_2_7,
    LPP_POS_SIB_TYPE_2_8,
    LPP_POS_SIB_TYPE_2_9,
    LPP_POS_SIB_TYPE_2_10,
    LPP_POS_SIB_TYPE_2_11,
    LPP_POS_SIB_TYPE_2_12,
    LPP_POS_SIB_TYPE_2_13,
    LPP_POS_SIB_TYPE_2_14,
    LPP_POS_SIB_TYPE_2_15,
    LPP_POS_SIB_TYPE_2_16,
    LPP_POS_SIB_TYPE_2_17,
    LPP_POS_SIB_TYPE_2_18,
    LPP_POS_SIB_TYPE_2_19,
    LPP_POS_SIB_TYPE_2_20,
    LPP_POS_SIB_TYPE_2_21,
    LPP_POS_SIB_TYPE_2_22,
    LPP_POS_SIB_TYPE_2_23,
    LPP_POS_SIB_TYPE_2_24,
    LPP_POS_SIB_TYPE_2_25,
    LPP_POS_SIB_TYPE_3_1,
    LPP_POS_SIB_TYPE_4_1,
    LPP_POS_SIB_TYPE_5_1,
    LPP_POS_SIB_TYPE_6_1,
    LPP_POS_SIB_TYPE_6_2,
    LPP_POS_SIB_TYPE_6_3,
    LPP_POS_SIB_TYPE_6_4,
    LPP_POS_SIB_TYPE_6_5,
    LPP_POS_SIB_TYPE_6_6,
} lpp_pos_sib_type_t;

int dissect_lpp_AssistanceDataSIBelement_r15_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, lpp_pos_sib_type_t pos_sib_type);


/*--- Included file: packet-lpp-exp.h ---*/
#line 1 "./asn1/lpp/packet-lpp-exp.h"
extern const value_string lpp_Velocity_vals[];
int dissect_lpp_ARFCN_ValueEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_ARFCN_ValueEUTRA_v9a0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_ARFCN_ValueUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_CellGlobalIdEUTRA_AndUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_CellGlobalIdGERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_Ellipsoid_Point(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_EllipsoidPointWithAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_EllipsoidPointWithAltitudeAndUncertaintyEllipsoid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_Velocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_OTDOA_ReferenceCellInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_OTDOA_NeighbourCellInfoElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_GNSS_SystemTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_NetworkTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_GNSS_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_GNSS_ID_Bitmap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_GNSS_SignalID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_GNSS_SignalIDs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_SV_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_ECID_SignalMeasurementInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
int dissect_lpp_Ellipsoid_Point_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_Ellipsoid_PointWithUncertaintyCircle_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_EllipsoidPointWithUncertaintyEllipse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_EllipsoidPointWithAltitude_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_EllipsoidPointWithAltitudeAndUncertaintyEllipsoid_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_EllipsoidArc_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_HorizontalVelocity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_HorizontalWithVerticalVelocity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_HorizontalVelocityWithUncertainty_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_Polygon_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_LocationCoordinates_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_Velocity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_LocationError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_LocationSource_r13_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_Sensor_MeasurementInformation_r13_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_Sensor_MotionInformation_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
int dissect_lpp_DisplacementTimeStamp_r15_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

/*--- End of included file: packet-lpp-exp.h ---*/
#line 67 "./asn1/lpp/packet-lpp-template.h"

#endif  /* PACKET_LPP_H */
