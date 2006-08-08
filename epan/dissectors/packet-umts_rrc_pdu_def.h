/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-umts_rrc_pdu_def.h                                                */
/* ../../tools/asn2wrs.py -u -e -p umts_rrc_pdu_def -c umts_rrc_pdu_def.cnf -s packet-umts_rrc_pdu_def-template umts_rrc_PDU-definitions.asn */

/* Input file: packet-umts_rrc_pdu_def-template.h */

#line 1 "packet-umts_rrc_pdu_def-template.h"
/* packet-umts_rrc_pdu_def.h
 * Routines for Universal Mobile Telecommunications System (UMTS);
 * Radio Resource Control (RRC) protocol specification 	
 * (3GPP TS 25.331 version 6.7.0 Release 6) chapter 11.2	PDU definitions
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef PACKET_UMTS_RRC_PDU_DEF_H
#define PACKET_UMTS_RRC_PDU_DEF_H




/*--- Included file: packet-umts_rrc_pdu_def-exp.h ---*/
#line 1 "packet-umts_rrc_pdu_def-exp.h"
extern const value_string umts_rrc_pdu_def_ActiveSetUpdate_vals[];
extern const value_string umts_rrc_pdu_def_AssistanceDataDelivery_vals[];
extern const value_string umts_rrc_pdu_def_CellChangeOrderFromUTRAN_vals[];
extern const value_string umts_rrc_pdu_def_CellChangeOrderFromUTRANFailure_vals[];
extern const value_string umts_rrc_pdu_def_CellUpdateConfirm_vals[];
extern const value_string umts_rrc_pdu_def_CellUpdateConfirm_CCCH_vals[];
extern const value_string umts_rrc_pdu_def_CounterCheck_vals[];
extern const value_string umts_rrc_pdu_def_DownlinkDirectTransfer_vals[];
extern const value_string umts_rrc_pdu_def_HandoverFromUTRANCommand_GSM_vals[];
extern const value_string umts_rrc_pdu_def_HandoverFromUTRANCommand_CDMA2000_vals[];
extern const value_string umts_rrc_pdu_def_MeasurementControl_vals[];
extern const value_string umts_rrc_pdu_def_PhysicalChannelReconfiguration_vals[];
extern const value_string umts_rrc_pdu_def_PhysicalSharedChannelAllocation_vals[];
extern const value_string umts_rrc_pdu_def_RadioBearerReconfiguration_vals[];
extern const value_string umts_rrc_pdu_def_RadioBearerRelease_vals[];
extern const value_string umts_rrc_pdu_def_RadioBearerSetup_vals[];
extern const value_string umts_rrc_pdu_def_RRCConnectionReject_vals[];
extern const value_string umts_rrc_pdu_def_RRCConnectionRelease_vals[];
extern const value_string umts_rrc_pdu_def_RRCConnectionRelease_CCCH_vals[];
extern const value_string umts_rrc_pdu_def_RRCConnectionSetup_vals[];
extern const value_string umts_rrc_pdu_def_SecurityModeCommand_vals[];
extern const value_string umts_rrc_pdu_def_SignallingConnectionRelease_vals[];
extern const value_string umts_rrc_pdu_def_TransportChannelReconfiguration_vals[];
extern const value_string umts_rrc_pdu_def_UECapabilityEnquiry_vals[];
extern const value_string umts_rrc_pdu_def_UECapabilityInformationConfirm_vals[];
extern const value_string umts_rrc_pdu_def_UplinkPhysicalChannelControl_vals[];
extern const value_string umts_rrc_pdu_def_URAUpdateConfirm_vals[];
extern const value_string umts_rrc_pdu_def_URAUpdateConfirm_CCCH_vals[];
extern const value_string umts_rrc_pdu_def_UTRANMobilityInformation_vals[];
int dissect_umts_rrc_pdu_def_ActiveSetUpdate(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_ActiveSetUpdateComplete(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_ActiveSetUpdateFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_AssistanceDataDelivery(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_CellChangeOrderFromUTRAN(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_CellChangeOrderFromUTRANFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_CellUpdate(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_CellUpdateConfirm(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_CellUpdateConfirm_CCCH(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_CounterCheck(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_CounterCheckResponse(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_DownlinkDirectTransfer(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_HandoverToUTRANComplete(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_InitialDirectTransfer(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_HandoverFromUTRANCommand_GSM(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_HandoverFromUTRANCommand_GERANIu(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_HandoverFromUTRANCommand_CDMA2000(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_HandoverFromUTRANFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MeasurementControl(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MeasurementControlFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MeasurementReport(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_PagingType1(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_PagingType2(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_PhysicalChannelReconfiguration(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_PhysicalChannelReconfigurationComplete(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_PhysicalChannelReconfigurationFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_PhysicalSharedChannelAllocation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_PUSCHCapacityRequest(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RadioBearerReconfiguration(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RadioBearerReconfigurationComplete(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RadioBearerReconfigurationFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RadioBearerRelease(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RadioBearerReleaseComplete(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RadioBearerReleaseFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RadioBearerSetup(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RadioBearerSetupComplete(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RadioBearerSetupFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RRCConnectionReject(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RRCConnectionRelease(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RRCConnectionRelease_CCCH(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RRCConnectionReleaseComplete(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RRCConnectionRequest(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RRCConnectionSetup(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RRCConnectionSetupComplete(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_RRCStatus(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_SecurityModeCommand(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_SecurityModeComplete(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_SecurityModeFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_SignallingConnectionRelease(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_SignallingConnectionReleaseIndication(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_SystemInformation_BCH(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_SystemInformation_FACH(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_SystemInformationChangeIndication(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_TransportChannelReconfiguration(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_TransportChannelReconfigurationComplete(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_TransportChannelReconfigurationFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_TransportFormatCombinationControl(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_TransportFormatCombinationControlFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_UECapabilityEnquiry(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_UECapabilityInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_UECapabilityInformationConfirm(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_UplinkDirectTransfer(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_UplinkPhysicalChannelControl(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_URAUpdate(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_URAUpdateConfirm(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_URAUpdateConfirm_CCCH(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_UTRANMobilityInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_UTRANMobilityInformationConfirm(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_UTRANMobilityInformationFailure(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MBMSAccessInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MBMSCommonPTMRBInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MBMSCurrentCellPTMRBInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MBMSGeneralInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MBMSModificationRequest(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MBMSModifiedServicesInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MBMSNeighbouringCellPTMRBInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MBMSSchedulingInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);
int dissect_umts_rrc_pdu_def_MBMSUnmodifiedServicesInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index);

/*--- End of included file: packet-umts_rrc_pdu_def-exp.h ---*/
#line 34 "packet-umts_rrc_pdu_def-template.h"

#endif  /* PACKET_UMTS_RRC_PDU_DEF_H */


