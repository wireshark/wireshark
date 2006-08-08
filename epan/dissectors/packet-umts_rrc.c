/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-umts_rrc.c                                                        */
/* ../../tools/asn2wrs.py -u -e -p umts_rrc -c umts_rrc.cnf -s packet-umts_rrc-template umts_rrc_Class-definitions.asn */

/* Input file: packet-umts_rrc-template.c */

#line 1 "packet-umts_rrc-template.c"
/* packet-umts_rrc.c
 * Routines for Universal Mobile Telecommunications System (UMTS);
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 25.331 version 6.7.0 Release 6) packet dissection
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
 *
 * Ref: 3GPP TS 25.423 version 6.7.0 Release 6
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-umts_rrc.h"
#include "packet-umts_rrc_ies.h"
#include "packet-umts_rrc_pdu_def.h"

#define PNAME  "Universal Mobile Telecommunications System (UMTS) Radio Resource Control (RRC) protocol"
#define PSNAME "UMTS_RRC"
#define PFNAME "umts_rrc"

static dissector_handle_t umts_rrc_handle=NULL;

/* Include constants */
/*#include "packet-umts_rrc-val.h"*/

/* Initialize the protocol and registered fields */
static int proto_umts_rrc = -1;



/*--- Included file: packet-umts_rrc-hf.c ---*/
#line 1 "packet-umts_rrc-hf.c"
static int hf_umts_rrc_DL_DCCH_Message_PDU = -1;  /* DL_DCCH_Message */
static int hf_umts_rrc_integrityCheckInfo = -1;   /* IntegrityCheckInfo */
static int hf_umts_rrc_message = -1;              /* DL_DCCH_MessageType */
static int hf_umts_rrc_activeSetUpdate = -1;      /* ActiveSetUpdate */
static int hf_umts_rrc_assistanceDataDelivery = -1;  /* AssistanceDataDelivery */
static int hf_umts_rrc_cellChangeOrderFromUTRAN = -1;  /* CellChangeOrderFromUTRAN */
static int hf_umts_rrc_cellUpdateConfirm = -1;    /* CellUpdateConfirm */
static int hf_umts_rrc_counterCheck = -1;         /* CounterCheck */
static int hf_umts_rrc_downlinkDirectTransfer = -1;  /* DownlinkDirectTransfer */
static int hf_umts_rrc_handoverFromUTRANCommand_GSM = -1;  /* HandoverFromUTRANCommand_GSM */
static int hf_umts_rrc_handoverFromUTRANCommand_CDMA2000 = -1;  /* HandoverFromUTRANCommand_CDMA2000 */
static int hf_umts_rrc_measurementControl = -1;   /* MeasurementControl */
static int hf_umts_rrc_pagingType2 = -1;          /* PagingType2 */
static int hf_umts_rrc_physicalChannelReconfiguration = -1;  /* PhysicalChannelReconfiguration */
static int hf_umts_rrc_physicalSharedChannelAllocation = -1;  /* PhysicalSharedChannelAllocation */
static int hf_umts_rrc_radioBearerReconfiguration = -1;  /* RadioBearerReconfiguration */
static int hf_umts_rrc_radioBearerRelease = -1;   /* RadioBearerRelease */
static int hf_umts_rrc_radioBearerSetup = -1;     /* RadioBearerSetup */
static int hf_umts_rrc_rrcConnectionRelease = -1;  /* RRCConnectionRelease */
static int hf_umts_rrc_securityModeCommand = -1;  /* SecurityModeCommand */
static int hf_umts_rrc_signallingConnectionRelease = -1;  /* SignallingConnectionRelease */
static int hf_umts_rrc_transportChannelReconfiguration = -1;  /* TransportChannelReconfiguration */
static int hf_umts_rrc_transportFormatCombinationControl = -1;  /* TransportFormatCombinationControl */
static int hf_umts_rrc_ueCapabilityEnquiry = -1;  /* UECapabilityEnquiry */
static int hf_umts_rrc_ueCapabilityInformationConfirm = -1;  /* UECapabilityInformationConfirm */
static int hf_umts_rrc_uplinkPhysicalChannelControl = -1;  /* UplinkPhysicalChannelControl */
static int hf_umts_rrc_uraUpdateConfirm = -1;     /* URAUpdateConfirm */
static int hf_umts_rrc_utranMobilityInformation = -1;  /* UTRANMobilityInformation */
static int hf_umts_rrc_handoverFromUTRANCommand_GERANIu = -1;  /* HandoverFromUTRANCommand_GERANIu */
static int hf_umts_rrc_mbmsModifiedServicesInformation = -1;  /* MBMSModifiedServicesInformation */
static int hf_umts_rrc_spare5 = -1;               /* NULL */
static int hf_umts_rrc_spare4 = -1;               /* NULL */
static int hf_umts_rrc_spare3 = -1;               /* NULL */
static int hf_umts_rrc_spare2 = -1;               /* NULL */
static int hf_umts_rrc_spare1 = -1;               /* NULL */
static int hf_umts_rrc_message1 = -1;             /* UL_DCCH_MessageType */
static int hf_umts_rrc_activeSetUpdateComplete = -1;  /* ActiveSetUpdateComplete */
static int hf_umts_rrc_activeSetUpdateFailure = -1;  /* ActiveSetUpdateFailure */
static int hf_umts_rrc_cellChangeOrderFromUTRANFailure = -1;  /* CellChangeOrderFromUTRANFailure */
static int hf_umts_rrc_counterCheckResponse = -1;  /* CounterCheckResponse */
static int hf_umts_rrc_handoverToUTRANComplete = -1;  /* HandoverToUTRANComplete */
static int hf_umts_rrc_initialDirectTransfer = -1;  /* InitialDirectTransfer */
static int hf_umts_rrc_handoverFromUTRANFailure = -1;  /* HandoverFromUTRANFailure */
static int hf_umts_rrc_measurementControlFailure = -1;  /* MeasurementControlFailure */
static int hf_umts_rrc_measurementReport = -1;    /* MeasurementReport */
static int hf_umts_rrc_physicalChannelReconfigurationComplete = -1;  /* PhysicalChannelReconfigurationComplete */
static int hf_umts_rrc_physicalChannelReconfigurationFailure = -1;  /* PhysicalChannelReconfigurationFailure */
static int hf_umts_rrc_radioBearerReconfigurationComplete = -1;  /* RadioBearerReconfigurationComplete */
static int hf_umts_rrc_radioBearerReconfigurationFailure = -1;  /* RadioBearerReconfigurationFailure */
static int hf_umts_rrc_radioBearerReleaseComplete = -1;  /* RadioBearerReleaseComplete */
static int hf_umts_rrc_radioBearerReleaseFailure = -1;  /* RadioBearerReleaseFailure */
static int hf_umts_rrc_radioBearerSetupComplete = -1;  /* RadioBearerSetupComplete */
static int hf_umts_rrc_radioBearerSetupFailure = -1;  /* RadioBearerSetupFailure */
static int hf_umts_rrc_rrcConnectionReleaseComplete = -1;  /* RRCConnectionReleaseComplete */
static int hf_umts_rrc_rrcConnectionSetupComplete = -1;  /* RRCConnectionSetupComplete */
static int hf_umts_rrc_rrcStatus = -1;            /* RRCStatus */
static int hf_umts_rrc_securityModeComplete = -1;  /* SecurityModeComplete */
static int hf_umts_rrc_securityModeFailure = -1;  /* SecurityModeFailure */
static int hf_umts_rrc_signallingConnectionReleaseIndication = -1;  /* SignallingConnectionReleaseIndication */
static int hf_umts_rrc_transportChannelReconfigurationComplete = -1;  /* TransportChannelReconfigurationComplete */
static int hf_umts_rrc_transportChannelReconfigurationFailure = -1;  /* TransportChannelReconfigurationFailure */
static int hf_umts_rrc_transportFormatCombinationControlFailure = -1;  /* TransportFormatCombinationControlFailure */
static int hf_umts_rrc_ueCapabilityInformation = -1;  /* UECapabilityInformation */
static int hf_umts_rrc_uplinkDirectTransfer = -1;  /* UplinkDirectTransfer */
static int hf_umts_rrc_utranMobilityInformationConfirm = -1;  /* UTRANMobilityInformationConfirm */
static int hf_umts_rrc_utranMobilityInformationFailure = -1;  /* UTRANMobilityInformationFailure */
static int hf_umts_rrc_mbmsModificationRequest = -1;  /* MBMSModificationRequest */
static int hf_umts_rrc_message2 = -1;             /* DL_CCCH_MessageType */
static int hf_umts_rrc_cellUpdateConfirm1 = -1;   /* CellUpdateConfirm_CCCH */
static int hf_umts_rrc_rrcConnectionReject = -1;  /* RRCConnectionReject */
static int hf_umts_rrc_rrcConnectionRelease1 = -1;  /* RRCConnectionRelease_CCCH */
static int hf_umts_rrc_rrcConnectionSetup = -1;   /* RRCConnectionSetup */
static int hf_umts_rrc_uraUpdateConfirm1 = -1;    /* URAUpdateConfirm_CCCH */
static int hf_umts_rrc_message3 = -1;             /* UL_CCCH_MessageType */
static int hf_umts_rrc_cellUpdate = -1;           /* CellUpdate */
static int hf_umts_rrc_rrcConnectionRequest = -1;  /* RRCConnectionRequest */
static int hf_umts_rrc_uraUpdate = -1;            /* URAUpdate */
static int hf_umts_rrc_spare = -1;                /* NULL */
static int hf_umts_rrc_message4 = -1;             /* PCCH_MessageType */
static int hf_umts_rrc_pagingType1 = -1;          /* PagingType1 */
static int hf_umts_rrc_message5 = -1;             /* DL_SHCCH_MessageType */
static int hf_umts_rrc_message6 = -1;             /* UL_SHCCH_MessageType */
static int hf_umts_rrc_puschCapacityRequest = -1;  /* PUSCHCapacityRequest */
static int hf_umts_rrc_message7 = -1;             /* BCCH_FACH_MessageType */
static int hf_umts_rrc_systemInformation = -1;    /* SystemInformation_FACH */
static int hf_umts_rrc_systemInformationChangeIndication = -1;  /* SystemInformationChangeIndication */
static int hf_umts_rrc_message8 = -1;             /* SystemInformation_BCH */
static int hf_umts_rrc_message9 = -1;             /* MCCH_MessageType */
static int hf_umts_rrc_mbmsAccessInformation = -1;  /* MBMSAccessInformation */
static int hf_umts_rrc_mbmsCommonPTMRBInformation = -1;  /* MBMSCommonPTMRBInformation */
static int hf_umts_rrc_mbmsCurrentCellPTMRBInformation = -1;  /* MBMSCurrentCellPTMRBInformation */
static int hf_umts_rrc_mbmsGeneralInformation = -1;  /* MBMSGeneralInformation */
static int hf_umts_rrc_mbmsNeighbouringCellPTMRBInformation = -1;  /* MBMSNeighbouringCellPTMRBInformation */
static int hf_umts_rrc_mbmsUnmodifiedServicesInformation = -1;  /* MBMSUnmodifiedServicesInformation */
static int hf_umts_rrc_spare9 = -1;               /* NULL */
static int hf_umts_rrc_spare8 = -1;               /* NULL */
static int hf_umts_rrc_spare7 = -1;               /* NULL */
static int hf_umts_rrc_spare6 = -1;               /* NULL */
static int hf_umts_rrc_message10 = -1;            /* MSCH_MessageType */
static int hf_umts_rrc_mbmsSchedulingInformation = -1;  /* MBMSSchedulingInformation */

/*--- End of included file: packet-umts_rrc-hf.c ---*/
#line 61 "packet-umts_rrc-template.c"

/* Initialize the subtree pointers */
static int ett_umts_rrc = -1;


/*--- Included file: packet-umts_rrc-ett.c ---*/
#line 1 "packet-umts_rrc-ett.c"
static gint ett_umts_rrc_DL_DCCH_Message = -1;
static gint ett_umts_rrc_DL_DCCH_MessageType = -1;
static gint ett_umts_rrc_UL_DCCH_Message = -1;
static gint ett_umts_rrc_UL_DCCH_MessageType = -1;
static gint ett_umts_rrc_DL_CCCH_Message = -1;
static gint ett_umts_rrc_DL_CCCH_MessageType = -1;
static gint ett_umts_rrc_UL_CCCH_Message = -1;
static gint ett_umts_rrc_UL_CCCH_MessageType = -1;
static gint ett_umts_rrc_PCCH_Message = -1;
static gint ett_umts_rrc_PCCH_MessageType = -1;
static gint ett_umts_rrc_DL_SHCCH_Message = -1;
static gint ett_umts_rrc_DL_SHCCH_MessageType = -1;
static gint ett_umts_rrc_UL_SHCCH_Message = -1;
static gint ett_umts_rrc_UL_SHCCH_MessageType = -1;
static gint ett_umts_rrc_BCCH_FACH_Message = -1;
static gint ett_umts_rrc_BCCH_FACH_MessageType = -1;
static gint ett_umts_rrc_BCCH_BCH_Message = -1;
static gint ett_umts_rrc_MCCH_Message = -1;
static gint ett_umts_rrc_MCCH_MessageType = -1;
static gint ett_umts_rrc_MSCH_Message = -1;
static gint ett_umts_rrc_MSCH_MessageType = -1;

/*--- End of included file: packet-umts_rrc-ett.c ---*/
#line 66 "packet-umts_rrc-template.c"

/* Global variables */
static proto_tree *top_tree;


/*--- Included file: packet-umts_rrc-fn.c ---*/
#line 1 "packet-umts_rrc-fn.c"


static int
dissect_umts_rrc_NULL(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string umts_rrc_DL_DCCH_MessageType_vals[] = {
  {   0, "activeSetUpdate" },
  {   1, "assistanceDataDelivery" },
  {   2, "cellChangeOrderFromUTRAN" },
  {   3, "cellUpdateConfirm" },
  {   4, "counterCheck" },
  {   5, "downlinkDirectTransfer" },
  {   6, "handoverFromUTRANCommand-GSM" },
  {   7, "handoverFromUTRANCommand-CDMA2000" },
  {   8, "measurementControl" },
  {   9, "pagingType2" },
  {  10, "physicalChannelReconfiguration" },
  {  11, "physicalSharedChannelAllocation" },
  {  12, "radioBearerReconfiguration" },
  {  13, "radioBearerRelease" },
  {  14, "radioBearerSetup" },
  {  15, "rrcConnectionRelease" },
  {  16, "securityModeCommand" },
  {  17, "signallingConnectionRelease" },
  {  18, "transportChannelReconfiguration" },
  {  19, "transportFormatCombinationControl" },
  {  20, "ueCapabilityEnquiry" },
  {  21, "ueCapabilityInformationConfirm" },
  {  22, "uplinkPhysicalChannelControl" },
  {  23, "uraUpdateConfirm" },
  {  24, "utranMobilityInformation" },
  {  25, "handoverFromUTRANCommand-GERANIu" },
  {  26, "mbmsModifiedServicesInformation" },
  {  27, "spare5" },
  {  28, "spare4" },
  {  29, "spare3" },
  {  30, "spare2" },
  {  31, "spare1" },
  { 0, NULL }
};

static const per_choice_t DL_DCCH_MessageType_choice[] = {
  {   0, &hf_umts_rrc_activeSetUpdate, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_ActiveSetUpdate },
  {   1, &hf_umts_rrc_assistanceDataDelivery, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_AssistanceDataDelivery },
  {   2, &hf_umts_rrc_cellChangeOrderFromUTRAN, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_CellChangeOrderFromUTRAN },
  {   3, &hf_umts_rrc_cellUpdateConfirm, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_CellUpdateConfirm },
  {   4, &hf_umts_rrc_counterCheck, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_CounterCheck },
  {   5, &hf_umts_rrc_downlinkDirectTransfer, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_DownlinkDirectTransfer },
  {   6, &hf_umts_rrc_handoverFromUTRANCommand_GSM, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_HandoverFromUTRANCommand_GSM },
  {   7, &hf_umts_rrc_handoverFromUTRANCommand_CDMA2000, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_HandoverFromUTRANCommand_CDMA2000 },
  {   8, &hf_umts_rrc_measurementControl, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MeasurementControl },
  {   9, &hf_umts_rrc_pagingType2, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_PagingType2 },
  {  10, &hf_umts_rrc_physicalChannelReconfiguration, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_PhysicalChannelReconfiguration },
  {  11, &hf_umts_rrc_physicalSharedChannelAllocation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_PhysicalSharedChannelAllocation },
  {  12, &hf_umts_rrc_radioBearerReconfiguration, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RadioBearerReconfiguration },
  {  13, &hf_umts_rrc_radioBearerRelease, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RadioBearerRelease },
  {  14, &hf_umts_rrc_radioBearerSetup, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RadioBearerSetup },
  {  15, &hf_umts_rrc_rrcConnectionRelease, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RRCConnectionRelease },
  {  16, &hf_umts_rrc_securityModeCommand, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_SecurityModeCommand },
  {  17, &hf_umts_rrc_signallingConnectionRelease, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_SignallingConnectionRelease },
  {  18, &hf_umts_rrc_transportChannelReconfiguration, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_TransportChannelReconfiguration },
  {  19, &hf_umts_rrc_transportFormatCombinationControl, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_TransportFormatCombinationControl },
  {  20, &hf_umts_rrc_ueCapabilityEnquiry, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_UECapabilityEnquiry },
  {  21, &hf_umts_rrc_ueCapabilityInformationConfirm, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_UECapabilityInformationConfirm },
  {  22, &hf_umts_rrc_uplinkPhysicalChannelControl, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_UplinkPhysicalChannelControl },
  {  23, &hf_umts_rrc_uraUpdateConfirm, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_URAUpdateConfirm },
  {  24, &hf_umts_rrc_utranMobilityInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_UTRANMobilityInformation },
  {  25, &hf_umts_rrc_handoverFromUTRANCommand_GERANIu, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_HandoverFromUTRANCommand_GERANIu },
  {  26, &hf_umts_rrc_mbmsModifiedServicesInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MBMSModifiedServicesInformation },
  {  27, &hf_umts_rrc_spare5     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {  28, &hf_umts_rrc_spare4     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {  29, &hf_umts_rrc_spare3     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {  30, &hf_umts_rrc_spare2     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {  31, &hf_umts_rrc_spare1     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_umts_rrc_DL_DCCH_MessageType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_umts_rrc_DL_DCCH_MessageType, DL_DCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DL_DCCH_Message_sequence[] = {
  { &hf_umts_rrc_integrityCheckInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_umts_rrc_ies_IntegrityCheckInfo },
  { &hf_umts_rrc_message    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_DL_DCCH_MessageType },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_DL_DCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_DL_DCCH_Message, DL_DCCH_Message_sequence);

  return offset;
}


static const value_string umts_rrc_UL_DCCH_MessageType_vals[] = {
  {   0, "activeSetUpdateComplete" },
  {   1, "activeSetUpdateFailure" },
  {   2, "cellChangeOrderFromUTRANFailure" },
  {   3, "counterCheckResponse" },
  {   4, "handoverToUTRANComplete" },
  {   5, "initialDirectTransfer" },
  {   6, "handoverFromUTRANFailure" },
  {   7, "measurementControlFailure" },
  {   8, "measurementReport" },
  {   9, "physicalChannelReconfigurationComplete" },
  {  10, "physicalChannelReconfigurationFailure" },
  {  11, "radioBearerReconfigurationComplete" },
  {  12, "radioBearerReconfigurationFailure" },
  {  13, "radioBearerReleaseComplete" },
  {  14, "radioBearerReleaseFailure" },
  {  15, "radioBearerSetupComplete" },
  {  16, "radioBearerSetupFailure" },
  {  17, "rrcConnectionReleaseComplete" },
  {  18, "rrcConnectionSetupComplete" },
  {  19, "rrcStatus" },
  {  20, "securityModeComplete" },
  {  21, "securityModeFailure" },
  {  22, "signallingConnectionReleaseIndication" },
  {  23, "transportChannelReconfigurationComplete" },
  {  24, "transportChannelReconfigurationFailure" },
  {  25, "transportFormatCombinationControlFailure" },
  {  26, "ueCapabilityInformation" },
  {  27, "uplinkDirectTransfer" },
  {  28, "utranMobilityInformationConfirm" },
  {  29, "utranMobilityInformationFailure" },
  {  30, "mbmsModificationRequest" },
  {  31, "spare1" },
  { 0, NULL }
};

static const per_choice_t UL_DCCH_MessageType_choice[] = {
  {   0, &hf_umts_rrc_activeSetUpdateComplete, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_ActiveSetUpdateComplete },
  {   1, &hf_umts_rrc_activeSetUpdateFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_ActiveSetUpdateFailure },
  {   2, &hf_umts_rrc_cellChangeOrderFromUTRANFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_CellChangeOrderFromUTRANFailure },
  {   3, &hf_umts_rrc_counterCheckResponse, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_CounterCheckResponse },
  {   4, &hf_umts_rrc_handoverToUTRANComplete, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_HandoverToUTRANComplete },
  {   5, &hf_umts_rrc_initialDirectTransfer, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_InitialDirectTransfer },
  {   6, &hf_umts_rrc_handoverFromUTRANFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_HandoverFromUTRANFailure },
  {   7, &hf_umts_rrc_measurementControlFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MeasurementControlFailure },
  {   8, &hf_umts_rrc_measurementReport, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MeasurementReport },
  {   9, &hf_umts_rrc_physicalChannelReconfigurationComplete, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_PhysicalChannelReconfigurationComplete },
  {  10, &hf_umts_rrc_physicalChannelReconfigurationFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_PhysicalChannelReconfigurationFailure },
  {  11, &hf_umts_rrc_radioBearerReconfigurationComplete, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RadioBearerReconfigurationComplete },
  {  12, &hf_umts_rrc_radioBearerReconfigurationFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RadioBearerReconfigurationFailure },
  {  13, &hf_umts_rrc_radioBearerReleaseComplete, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RadioBearerReleaseComplete },
  {  14, &hf_umts_rrc_radioBearerReleaseFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RadioBearerReleaseFailure },
  {  15, &hf_umts_rrc_radioBearerSetupComplete, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RadioBearerSetupComplete },
  {  16, &hf_umts_rrc_radioBearerSetupFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RadioBearerSetupFailure },
  {  17, &hf_umts_rrc_rrcConnectionReleaseComplete, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RRCConnectionReleaseComplete },
  {  18, &hf_umts_rrc_rrcConnectionSetupComplete, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RRCConnectionSetupComplete },
  {  19, &hf_umts_rrc_rrcStatus  , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RRCStatus },
  {  20, &hf_umts_rrc_securityModeComplete, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_SecurityModeComplete },
  {  21, &hf_umts_rrc_securityModeFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_SecurityModeFailure },
  {  22, &hf_umts_rrc_signallingConnectionReleaseIndication, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_SignallingConnectionReleaseIndication },
  {  23, &hf_umts_rrc_transportChannelReconfigurationComplete, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_TransportChannelReconfigurationComplete },
  {  24, &hf_umts_rrc_transportChannelReconfigurationFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_TransportChannelReconfigurationFailure },
  {  25, &hf_umts_rrc_transportFormatCombinationControlFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_TransportFormatCombinationControlFailure },
  {  26, &hf_umts_rrc_ueCapabilityInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_UECapabilityInformation },
  {  27, &hf_umts_rrc_uplinkDirectTransfer, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_UplinkDirectTransfer },
  {  28, &hf_umts_rrc_utranMobilityInformationConfirm, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_UTRANMobilityInformationConfirm },
  {  29, &hf_umts_rrc_utranMobilityInformationFailure, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_UTRANMobilityInformationFailure },
  {  30, &hf_umts_rrc_mbmsModificationRequest, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MBMSModificationRequest },
  {  31, &hf_umts_rrc_spare1     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_umts_rrc_UL_DCCH_MessageType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_umts_rrc_UL_DCCH_MessageType, UL_DCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UL_DCCH_Message_sequence[] = {
  { &hf_umts_rrc_integrityCheckInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_umts_rrc_ies_IntegrityCheckInfo },
  { &hf_umts_rrc_message1   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_UL_DCCH_MessageType },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_UL_DCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_UL_DCCH_Message, UL_DCCH_Message_sequence);

  return offset;
}


static const value_string umts_rrc_DL_CCCH_MessageType_vals[] = {
  {   0, "cellUpdateConfirm" },
  {   1, "rrcConnectionReject" },
  {   2, "rrcConnectionRelease" },
  {   3, "rrcConnectionSetup" },
  {   4, "uraUpdateConfirm" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t DL_CCCH_MessageType_choice[] = {
  {   0, &hf_umts_rrc_cellUpdateConfirm1, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_CellUpdateConfirm_CCCH },
  {   1, &hf_umts_rrc_rrcConnectionReject, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RRCConnectionReject },
  {   2, &hf_umts_rrc_rrcConnectionRelease1, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RRCConnectionRelease_CCCH },
  {   3, &hf_umts_rrc_rrcConnectionSetup, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RRCConnectionSetup },
  {   4, &hf_umts_rrc_uraUpdateConfirm1, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_URAUpdateConfirm_CCCH },
  {   5, &hf_umts_rrc_spare3     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {   6, &hf_umts_rrc_spare2     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {   7, &hf_umts_rrc_spare1     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_umts_rrc_DL_CCCH_MessageType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_umts_rrc_DL_CCCH_MessageType, DL_CCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DL_CCCH_Message_sequence[] = {
  { &hf_umts_rrc_integrityCheckInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_umts_rrc_ies_IntegrityCheckInfo },
  { &hf_umts_rrc_message2   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_DL_CCCH_MessageType },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_DL_CCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_DL_CCCH_Message, DL_CCCH_Message_sequence);

  return offset;
}


static const value_string umts_rrc_UL_CCCH_MessageType_vals[] = {
  {   0, "cellUpdate" },
  {   1, "rrcConnectionRequest" },
  {   2, "uraUpdate" },
  {   3, "spare" },
  { 0, NULL }
};

static const per_choice_t UL_CCCH_MessageType_choice[] = {
  {   0, &hf_umts_rrc_cellUpdate , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_CellUpdate },
  {   1, &hf_umts_rrc_rrcConnectionRequest, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_RRCConnectionRequest },
  {   2, &hf_umts_rrc_uraUpdate  , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_URAUpdate },
  {   3, &hf_umts_rrc_spare      , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_umts_rrc_UL_CCCH_MessageType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_umts_rrc_UL_CCCH_MessageType, UL_CCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UL_CCCH_Message_sequence[] = {
  { &hf_umts_rrc_integrityCheckInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_umts_rrc_ies_IntegrityCheckInfo },
  { &hf_umts_rrc_message3   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_UL_CCCH_MessageType },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_UL_CCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_UL_CCCH_Message, UL_CCCH_Message_sequence);

  return offset;
}


static const value_string umts_rrc_PCCH_MessageType_vals[] = {
  {   0, "pagingType1" },
  {   1, "spare" },
  { 0, NULL }
};

static const per_choice_t PCCH_MessageType_choice[] = {
  {   0, &hf_umts_rrc_pagingType1, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_PagingType1 },
  {   1, &hf_umts_rrc_spare      , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_umts_rrc_PCCH_MessageType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_umts_rrc_PCCH_MessageType, PCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PCCH_Message_sequence[] = {
  { &hf_umts_rrc_message4   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_PCCH_MessageType },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_PCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_PCCH_Message, PCCH_Message_sequence);

  return offset;
}


static const value_string umts_rrc_DL_SHCCH_MessageType_vals[] = {
  {   0, "physicalSharedChannelAllocation" },
  {   1, "spare" },
  { 0, NULL }
};

static const per_choice_t DL_SHCCH_MessageType_choice[] = {
  {   0, &hf_umts_rrc_physicalSharedChannelAllocation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_PhysicalSharedChannelAllocation },
  {   1, &hf_umts_rrc_spare      , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_umts_rrc_DL_SHCCH_MessageType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_umts_rrc_DL_SHCCH_MessageType, DL_SHCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DL_SHCCH_Message_sequence[] = {
  { &hf_umts_rrc_message5   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_DL_SHCCH_MessageType },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_DL_SHCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_DL_SHCCH_Message, DL_SHCCH_Message_sequence);

  return offset;
}


static const value_string umts_rrc_UL_SHCCH_MessageType_vals[] = {
  {   0, "puschCapacityRequest" },
  {   1, "spare" },
  { 0, NULL }
};

static const per_choice_t UL_SHCCH_MessageType_choice[] = {
  {   0, &hf_umts_rrc_puschCapacityRequest, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_PUSCHCapacityRequest },
  {   1, &hf_umts_rrc_spare      , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_umts_rrc_UL_SHCCH_MessageType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_umts_rrc_UL_SHCCH_MessageType, UL_SHCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UL_SHCCH_Message_sequence[] = {
  { &hf_umts_rrc_message6   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_UL_SHCCH_MessageType },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_UL_SHCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_UL_SHCCH_Message, UL_SHCCH_Message_sequence);

  return offset;
}


static const value_string umts_rrc_BCCH_FACH_MessageType_vals[] = {
  {   0, "systemInformation" },
  {   1, "systemInformationChangeIndication" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t BCCH_FACH_MessageType_choice[] = {
  {   0, &hf_umts_rrc_systemInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_SystemInformation_FACH },
  {   1, &hf_umts_rrc_systemInformationChangeIndication, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_SystemInformationChangeIndication },
  {   2, &hf_umts_rrc_spare2     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {   3, &hf_umts_rrc_spare1     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_umts_rrc_BCCH_FACH_MessageType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_umts_rrc_BCCH_FACH_MessageType, BCCH_FACH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BCCH_FACH_Message_sequence[] = {
  { &hf_umts_rrc_message7   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_BCCH_FACH_MessageType },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_BCCH_FACH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_BCCH_FACH_Message, BCCH_FACH_Message_sequence);

  return offset;
}


static const per_sequence_t BCCH_BCH_Message_sequence[] = {
  { &hf_umts_rrc_message8   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_pdu_def_SystemInformation_BCH },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_BCCH_BCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_BCCH_BCH_Message, BCCH_BCH_Message_sequence);

  return offset;
}


static const value_string umts_rrc_MCCH_MessageType_vals[] = {
  {   0, "mbmsAccessInformation" },
  {   1, "mbmsCommonPTMRBInformation" },
  {   2, "mbmsCurrentCellPTMRBInformation" },
  {   3, "mbmsGeneralInformation" },
  {   4, "mbmsModifiedServicesInformation" },
  {   5, "mbmsNeighbouringCellPTMRBInformation" },
  {   6, "mbmsUnmodifiedServicesInformation" },
  {   7, "spare9" },
  {   8, "spare8" },
  {   9, "spare7" },
  {  10, "spare6" },
  {  11, "spare5" },
  {  12, "spare4" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};

static const per_choice_t MCCH_MessageType_choice[] = {
  {   0, &hf_umts_rrc_mbmsAccessInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MBMSAccessInformation },
  {   1, &hf_umts_rrc_mbmsCommonPTMRBInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MBMSCommonPTMRBInformation },
  {   2, &hf_umts_rrc_mbmsCurrentCellPTMRBInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MBMSCurrentCellPTMRBInformation },
  {   3, &hf_umts_rrc_mbmsGeneralInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MBMSGeneralInformation },
  {   4, &hf_umts_rrc_mbmsModifiedServicesInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MBMSModifiedServicesInformation },
  {   5, &hf_umts_rrc_mbmsNeighbouringCellPTMRBInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MBMSNeighbouringCellPTMRBInformation },
  {   6, &hf_umts_rrc_mbmsUnmodifiedServicesInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MBMSUnmodifiedServicesInformation },
  {   7, &hf_umts_rrc_spare9     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {   8, &hf_umts_rrc_spare8     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {   9, &hf_umts_rrc_spare7     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {  10, &hf_umts_rrc_spare6     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {  11, &hf_umts_rrc_spare5     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {  12, &hf_umts_rrc_spare4     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {  13, &hf_umts_rrc_spare3     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {  14, &hf_umts_rrc_spare2     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {  15, &hf_umts_rrc_spare1     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_umts_rrc_MCCH_MessageType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_umts_rrc_MCCH_MessageType, MCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MCCH_Message_sequence[] = {
  { &hf_umts_rrc_message9   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_MCCH_MessageType },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_MCCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_MCCH_Message, MCCH_Message_sequence);

  return offset;
}


static const value_string umts_rrc_MSCH_MessageType_vals[] = {
  {   0, "mbmsSchedulingInformation" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t MSCH_MessageType_choice[] = {
  {   0, &hf_umts_rrc_mbmsSchedulingInformation, ASN1_NO_EXTENSIONS     , dissect_umts_rrc_pdu_def_MBMSSchedulingInformation },
  {   1, &hf_umts_rrc_spare3     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {   2, &hf_umts_rrc_spare2     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  {   3, &hf_umts_rrc_spare1     , ASN1_NO_EXTENSIONS     , dissect_umts_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_umts_rrc_MSCH_MessageType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_umts_rrc_MSCH_MessageType, MSCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MSCH_Message_sequence[] = {
  { &hf_umts_rrc_message10  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_umts_rrc_MSCH_MessageType },
  { NULL, 0, 0, NULL }
};

int
dissect_umts_rrc_MSCH_Message(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_umts_rrc_MSCH_Message, MSCH_Message_sequence);

  return offset;
}

/*--- PDUs ---*/

static void dissect_DL_DCCH_Message_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_umts_rrc_DL_DCCH_Message(tvb, 0, &asn1_ctx, tree, hf_umts_rrc_DL_DCCH_Message_PDU);
}


/*--- End of included file: packet-umts_rrc-fn.c ---*/
#line 71 "packet-umts_rrc-template.c"


static void
dissect_umts_rrc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* FIX ME Currently don't know the 'starting point' of this protocol
	 * exported DL-DCCH-Message is the entry point.
	 */
	proto_item	*umts_rrc_item = NULL;
	proto_tree	*umts_rrc_tree = NULL;
	int			offset = 0;

	top_tree = tree;

	/* make entry in the Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "UMTS_RRC");

    /* create the umts_rrc protocol tree */
    umts_rrc_item = proto_tree_add_item(tree, proto_umts_rrc, tvb, 0, -1, FALSE);
    umts_rrc_tree = proto_item_add_subtree(umts_rrc_item, ett_umts_rrc);

}
/*--- proto_register_umts_rrc -------------------------------------------*/
void proto_register_umts_rrc(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-umts_rrc-hfarr.c ---*/
#line 1 "packet-umts_rrc-hfarr.c"
    { &hf_umts_rrc_DL_DCCH_Message_PDU,
      { "DL-DCCH-Message", "umts_rrc.DL_DCCH_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "DL-DCCH-Message", HFILL }},
    { &hf_umts_rrc_integrityCheckInfo,
      { "integrityCheckInfo", "umts_rrc.integrityCheckInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_umts_rrc_message,
      { "message", "umts_rrc.message",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_DL_DCCH_MessageType_vals), 0,
        "DL-DCCH-Message/message", HFILL }},
    { &hf_umts_rrc_activeSetUpdate,
      { "activeSetUpdate", "umts_rrc.activeSetUpdate",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_ActiveSetUpdate_vals), 0,
        "DL-DCCH-MessageType/activeSetUpdate", HFILL }},
    { &hf_umts_rrc_assistanceDataDelivery,
      { "assistanceDataDelivery", "umts_rrc.assistanceDataDelivery",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_AssistanceDataDelivery_vals), 0,
        "DL-DCCH-MessageType/assistanceDataDelivery", HFILL }},
    { &hf_umts_rrc_cellChangeOrderFromUTRAN,
      { "cellChangeOrderFromUTRAN", "umts_rrc.cellChangeOrderFromUTRAN",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_CellChangeOrderFromUTRAN_vals), 0,
        "DL-DCCH-MessageType/cellChangeOrderFromUTRAN", HFILL }},
    { &hf_umts_rrc_cellUpdateConfirm,
      { "cellUpdateConfirm", "umts_rrc.cellUpdateConfirm",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_CellUpdateConfirm_vals), 0,
        "DL-DCCH-MessageType/cellUpdateConfirm", HFILL }},
    { &hf_umts_rrc_counterCheck,
      { "counterCheck", "umts_rrc.counterCheck",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_CounterCheck_vals), 0,
        "DL-DCCH-MessageType/counterCheck", HFILL }},
    { &hf_umts_rrc_downlinkDirectTransfer,
      { "downlinkDirectTransfer", "umts_rrc.downlinkDirectTransfer",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_DownlinkDirectTransfer_vals), 0,
        "DL-DCCH-MessageType/downlinkDirectTransfer", HFILL }},
    { &hf_umts_rrc_handoverFromUTRANCommand_GSM,
      { "handoverFromUTRANCommand-GSM", "umts_rrc.handoverFromUTRANCommand_GSM",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_HandoverFromUTRANCommand_GSM_vals), 0,
        "DL-DCCH-MessageType/handoverFromUTRANCommand-GSM", HFILL }},
    { &hf_umts_rrc_handoverFromUTRANCommand_CDMA2000,
      { "handoverFromUTRANCommand-CDMA2000", "umts_rrc.handoverFromUTRANCommand_CDMA2000",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_HandoverFromUTRANCommand_CDMA2000_vals), 0,
        "DL-DCCH-MessageType/handoverFromUTRANCommand-CDMA2000", HFILL }},
    { &hf_umts_rrc_measurementControl,
      { "measurementControl", "umts_rrc.measurementControl",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_MeasurementControl_vals), 0,
        "DL-DCCH-MessageType/measurementControl", HFILL }},
    { &hf_umts_rrc_pagingType2,
      { "pagingType2", "umts_rrc.pagingType2",
        FT_NONE, BASE_NONE, NULL, 0,
        "DL-DCCH-MessageType/pagingType2", HFILL }},
    { &hf_umts_rrc_physicalChannelReconfiguration,
      { "physicalChannelReconfiguration", "umts_rrc.physicalChannelReconfiguration",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_PhysicalChannelReconfiguration_vals), 0,
        "DL-DCCH-MessageType/physicalChannelReconfiguration", HFILL }},
    { &hf_umts_rrc_physicalSharedChannelAllocation,
      { "physicalSharedChannelAllocation", "umts_rrc.physicalSharedChannelAllocation",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_PhysicalSharedChannelAllocation_vals), 0,
        "", HFILL }},
    { &hf_umts_rrc_radioBearerReconfiguration,
      { "radioBearerReconfiguration", "umts_rrc.radioBearerReconfiguration",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_RadioBearerReconfiguration_vals), 0,
        "DL-DCCH-MessageType/radioBearerReconfiguration", HFILL }},
    { &hf_umts_rrc_radioBearerRelease,
      { "radioBearerRelease", "umts_rrc.radioBearerRelease",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_RadioBearerRelease_vals), 0,
        "DL-DCCH-MessageType/radioBearerRelease", HFILL }},
    { &hf_umts_rrc_radioBearerSetup,
      { "radioBearerSetup", "umts_rrc.radioBearerSetup",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_RadioBearerSetup_vals), 0,
        "DL-DCCH-MessageType/radioBearerSetup", HFILL }},
    { &hf_umts_rrc_rrcConnectionRelease,
      { "rrcConnectionRelease", "umts_rrc.rrcConnectionRelease",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_RRCConnectionRelease_vals), 0,
        "DL-DCCH-MessageType/rrcConnectionRelease", HFILL }},
    { &hf_umts_rrc_securityModeCommand,
      { "securityModeCommand", "umts_rrc.securityModeCommand",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_SecurityModeCommand_vals), 0,
        "DL-DCCH-MessageType/securityModeCommand", HFILL }},
    { &hf_umts_rrc_signallingConnectionRelease,
      { "signallingConnectionRelease", "umts_rrc.signallingConnectionRelease",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_SignallingConnectionRelease_vals), 0,
        "DL-DCCH-MessageType/signallingConnectionRelease", HFILL }},
    { &hf_umts_rrc_transportChannelReconfiguration,
      { "transportChannelReconfiguration", "umts_rrc.transportChannelReconfiguration",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_TransportChannelReconfiguration_vals), 0,
        "DL-DCCH-MessageType/transportChannelReconfiguration", HFILL }},
    { &hf_umts_rrc_transportFormatCombinationControl,
      { "transportFormatCombinationControl", "umts_rrc.transportFormatCombinationControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "DL-DCCH-MessageType/transportFormatCombinationControl", HFILL }},
    { &hf_umts_rrc_ueCapabilityEnquiry,
      { "ueCapabilityEnquiry", "umts_rrc.ueCapabilityEnquiry",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_UECapabilityEnquiry_vals), 0,
        "DL-DCCH-MessageType/ueCapabilityEnquiry", HFILL }},
    { &hf_umts_rrc_ueCapabilityInformationConfirm,
      { "ueCapabilityInformationConfirm", "umts_rrc.ueCapabilityInformationConfirm",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_UECapabilityInformationConfirm_vals), 0,
        "DL-DCCH-MessageType/ueCapabilityInformationConfirm", HFILL }},
    { &hf_umts_rrc_uplinkPhysicalChannelControl,
      { "uplinkPhysicalChannelControl", "umts_rrc.uplinkPhysicalChannelControl",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_UplinkPhysicalChannelControl_vals), 0,
        "DL-DCCH-MessageType/uplinkPhysicalChannelControl", HFILL }},
    { &hf_umts_rrc_uraUpdateConfirm,
      { "uraUpdateConfirm", "umts_rrc.uraUpdateConfirm",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_URAUpdateConfirm_vals), 0,
        "DL-DCCH-MessageType/uraUpdateConfirm", HFILL }},
    { &hf_umts_rrc_utranMobilityInformation,
      { "utranMobilityInformation", "umts_rrc.utranMobilityInformation",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_UTRANMobilityInformation_vals), 0,
        "DL-DCCH-MessageType/utranMobilityInformation", HFILL }},
    { &hf_umts_rrc_handoverFromUTRANCommand_GERANIu,
      { "handoverFromUTRANCommand-GERANIu", "umts_rrc.handoverFromUTRANCommand_GERANIu",
        FT_NONE, BASE_NONE, NULL, 0,
        "DL-DCCH-MessageType/handoverFromUTRANCommand-GERANIu", HFILL }},
    { &hf_umts_rrc_mbmsModifiedServicesInformation,
      { "mbmsModifiedServicesInformation", "umts_rrc.mbmsModifiedServicesInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_umts_rrc_spare5,
      { "spare5", "umts_rrc.spare5",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_umts_rrc_spare4,
      { "spare4", "umts_rrc.spare4",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_umts_rrc_spare3,
      { "spare3", "umts_rrc.spare3",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_umts_rrc_spare2,
      { "spare2", "umts_rrc.spare2",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_umts_rrc_spare1,
      { "spare1", "umts_rrc.spare1",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_umts_rrc_message1,
      { "message", "umts_rrc.message",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_UL_DCCH_MessageType_vals), 0,
        "UL-DCCH-Message/message", HFILL }},
    { &hf_umts_rrc_activeSetUpdateComplete,
      { "activeSetUpdateComplete", "umts_rrc.activeSetUpdateComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/activeSetUpdateComplete", HFILL }},
    { &hf_umts_rrc_activeSetUpdateFailure,
      { "activeSetUpdateFailure", "umts_rrc.activeSetUpdateFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/activeSetUpdateFailure", HFILL }},
    { &hf_umts_rrc_cellChangeOrderFromUTRANFailure,
      { "cellChangeOrderFromUTRANFailure", "umts_rrc.cellChangeOrderFromUTRANFailure",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_CellChangeOrderFromUTRANFailure_vals), 0,
        "UL-DCCH-MessageType/cellChangeOrderFromUTRANFailure", HFILL }},
    { &hf_umts_rrc_counterCheckResponse,
      { "counterCheckResponse", "umts_rrc.counterCheckResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/counterCheckResponse", HFILL }},
    { &hf_umts_rrc_handoverToUTRANComplete,
      { "handoverToUTRANComplete", "umts_rrc.handoverToUTRANComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/handoverToUTRANComplete", HFILL }},
    { &hf_umts_rrc_initialDirectTransfer,
      { "initialDirectTransfer", "umts_rrc.initialDirectTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/initialDirectTransfer", HFILL }},
    { &hf_umts_rrc_handoverFromUTRANFailure,
      { "handoverFromUTRANFailure", "umts_rrc.handoverFromUTRANFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/handoverFromUTRANFailure", HFILL }},
    { &hf_umts_rrc_measurementControlFailure,
      { "measurementControlFailure", "umts_rrc.measurementControlFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/measurementControlFailure", HFILL }},
    { &hf_umts_rrc_measurementReport,
      { "measurementReport", "umts_rrc.measurementReport",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/measurementReport", HFILL }},
    { &hf_umts_rrc_physicalChannelReconfigurationComplete,
      { "physicalChannelReconfigurationComplete", "umts_rrc.physicalChannelReconfigurationComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/physicalChannelReconfigurationComplete", HFILL }},
    { &hf_umts_rrc_physicalChannelReconfigurationFailure,
      { "physicalChannelReconfigurationFailure", "umts_rrc.physicalChannelReconfigurationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/physicalChannelReconfigurationFailure", HFILL }},
    { &hf_umts_rrc_radioBearerReconfigurationComplete,
      { "radioBearerReconfigurationComplete", "umts_rrc.radioBearerReconfigurationComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/radioBearerReconfigurationComplete", HFILL }},
    { &hf_umts_rrc_radioBearerReconfigurationFailure,
      { "radioBearerReconfigurationFailure", "umts_rrc.radioBearerReconfigurationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/radioBearerReconfigurationFailure", HFILL }},
    { &hf_umts_rrc_radioBearerReleaseComplete,
      { "radioBearerReleaseComplete", "umts_rrc.radioBearerReleaseComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/radioBearerReleaseComplete", HFILL }},
    { &hf_umts_rrc_radioBearerReleaseFailure,
      { "radioBearerReleaseFailure", "umts_rrc.radioBearerReleaseFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/radioBearerReleaseFailure", HFILL }},
    { &hf_umts_rrc_radioBearerSetupComplete,
      { "radioBearerSetupComplete", "umts_rrc.radioBearerSetupComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/radioBearerSetupComplete", HFILL }},
    { &hf_umts_rrc_radioBearerSetupFailure,
      { "radioBearerSetupFailure", "umts_rrc.radioBearerSetupFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/radioBearerSetupFailure", HFILL }},
    { &hf_umts_rrc_rrcConnectionReleaseComplete,
      { "rrcConnectionReleaseComplete", "umts_rrc.rrcConnectionReleaseComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/rrcConnectionReleaseComplete", HFILL }},
    { &hf_umts_rrc_rrcConnectionSetupComplete,
      { "rrcConnectionSetupComplete", "umts_rrc.rrcConnectionSetupComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/rrcConnectionSetupComplete", HFILL }},
    { &hf_umts_rrc_rrcStatus,
      { "rrcStatus", "umts_rrc.rrcStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/rrcStatus", HFILL }},
    { &hf_umts_rrc_securityModeComplete,
      { "securityModeComplete", "umts_rrc.securityModeComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/securityModeComplete", HFILL }},
    { &hf_umts_rrc_securityModeFailure,
      { "securityModeFailure", "umts_rrc.securityModeFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/securityModeFailure", HFILL }},
    { &hf_umts_rrc_signallingConnectionReleaseIndication,
      { "signallingConnectionReleaseIndication", "umts_rrc.signallingConnectionReleaseIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/signallingConnectionReleaseIndication", HFILL }},
    { &hf_umts_rrc_transportChannelReconfigurationComplete,
      { "transportChannelReconfigurationComplete", "umts_rrc.transportChannelReconfigurationComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/transportChannelReconfigurationComplete", HFILL }},
    { &hf_umts_rrc_transportChannelReconfigurationFailure,
      { "transportChannelReconfigurationFailure", "umts_rrc.transportChannelReconfigurationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/transportChannelReconfigurationFailure", HFILL }},
    { &hf_umts_rrc_transportFormatCombinationControlFailure,
      { "transportFormatCombinationControlFailure", "umts_rrc.transportFormatCombinationControlFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/transportFormatCombinationControlFailure", HFILL }},
    { &hf_umts_rrc_ueCapabilityInformation,
      { "ueCapabilityInformation", "umts_rrc.ueCapabilityInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/ueCapabilityInformation", HFILL }},
    { &hf_umts_rrc_uplinkDirectTransfer,
      { "uplinkDirectTransfer", "umts_rrc.uplinkDirectTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/uplinkDirectTransfer", HFILL }},
    { &hf_umts_rrc_utranMobilityInformationConfirm,
      { "utranMobilityInformationConfirm", "umts_rrc.utranMobilityInformationConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/utranMobilityInformationConfirm", HFILL }},
    { &hf_umts_rrc_utranMobilityInformationFailure,
      { "utranMobilityInformationFailure", "umts_rrc.utranMobilityInformationFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/utranMobilityInformationFailure", HFILL }},
    { &hf_umts_rrc_mbmsModificationRequest,
      { "mbmsModificationRequest", "umts_rrc.mbmsModificationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-DCCH-MessageType/mbmsModificationRequest", HFILL }},
    { &hf_umts_rrc_message2,
      { "message", "umts_rrc.message",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_DL_CCCH_MessageType_vals), 0,
        "DL-CCCH-Message/message", HFILL }},
    { &hf_umts_rrc_cellUpdateConfirm1,
      { "cellUpdateConfirm", "umts_rrc.cellUpdateConfirm",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_CellUpdateConfirm_CCCH_vals), 0,
        "DL-CCCH-MessageType/cellUpdateConfirm", HFILL }},
    { &hf_umts_rrc_rrcConnectionReject,
      { "rrcConnectionReject", "umts_rrc.rrcConnectionReject",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_RRCConnectionReject_vals), 0,
        "DL-CCCH-MessageType/rrcConnectionReject", HFILL }},
    { &hf_umts_rrc_rrcConnectionRelease1,
      { "rrcConnectionRelease", "umts_rrc.rrcConnectionRelease",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_RRCConnectionRelease_CCCH_vals), 0,
        "DL-CCCH-MessageType/rrcConnectionRelease", HFILL }},
    { &hf_umts_rrc_rrcConnectionSetup,
      { "rrcConnectionSetup", "umts_rrc.rrcConnectionSetup",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_RRCConnectionSetup_vals), 0,
        "DL-CCCH-MessageType/rrcConnectionSetup", HFILL }},
    { &hf_umts_rrc_uraUpdateConfirm1,
      { "uraUpdateConfirm", "umts_rrc.uraUpdateConfirm",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_pdu_def_URAUpdateConfirm_CCCH_vals), 0,
        "DL-CCCH-MessageType/uraUpdateConfirm", HFILL }},
    { &hf_umts_rrc_message3,
      { "message", "umts_rrc.message",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_UL_CCCH_MessageType_vals), 0,
        "UL-CCCH-Message/message", HFILL }},
    { &hf_umts_rrc_cellUpdate,
      { "cellUpdate", "umts_rrc.cellUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-CCCH-MessageType/cellUpdate", HFILL }},
    { &hf_umts_rrc_rrcConnectionRequest,
      { "rrcConnectionRequest", "umts_rrc.rrcConnectionRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-CCCH-MessageType/rrcConnectionRequest", HFILL }},
    { &hf_umts_rrc_uraUpdate,
      { "uraUpdate", "umts_rrc.uraUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-CCCH-MessageType/uraUpdate", HFILL }},
    { &hf_umts_rrc_spare,
      { "spare", "umts_rrc.spare",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_umts_rrc_message4,
      { "message", "umts_rrc.message",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_PCCH_MessageType_vals), 0,
        "PCCH-Message/message", HFILL }},
    { &hf_umts_rrc_pagingType1,
      { "pagingType1", "umts_rrc.pagingType1",
        FT_NONE, BASE_NONE, NULL, 0,
        "PCCH-MessageType/pagingType1", HFILL }},
    { &hf_umts_rrc_message5,
      { "message", "umts_rrc.message",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_DL_SHCCH_MessageType_vals), 0,
        "DL-SHCCH-Message/message", HFILL }},
    { &hf_umts_rrc_message6,
      { "message", "umts_rrc.message",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_UL_SHCCH_MessageType_vals), 0,
        "UL-SHCCH-Message/message", HFILL }},
    { &hf_umts_rrc_puschCapacityRequest,
      { "puschCapacityRequest", "umts_rrc.puschCapacityRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL-SHCCH-MessageType/puschCapacityRequest", HFILL }},
    { &hf_umts_rrc_message7,
      { "message", "umts_rrc.message",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_BCCH_FACH_MessageType_vals), 0,
        "BCCH-FACH-Message/message", HFILL }},
    { &hf_umts_rrc_systemInformation,
      { "systemInformation", "umts_rrc.systemInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "BCCH-FACH-MessageType/systemInformation", HFILL }},
    { &hf_umts_rrc_systemInformationChangeIndication,
      { "systemInformationChangeIndication", "umts_rrc.systemInformationChangeIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "BCCH-FACH-MessageType/systemInformationChangeIndication", HFILL }},
    { &hf_umts_rrc_message8,
      { "message", "umts_rrc.message",
        FT_NONE, BASE_NONE, NULL, 0,
        "BCCH-BCH-Message/message", HFILL }},
    { &hf_umts_rrc_message9,
      { "message", "umts_rrc.message",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_MCCH_MessageType_vals), 0,
        "MCCH-Message/message", HFILL }},
    { &hf_umts_rrc_mbmsAccessInformation,
      { "mbmsAccessInformation", "umts_rrc.mbmsAccessInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCCH-MessageType/mbmsAccessInformation", HFILL }},
    { &hf_umts_rrc_mbmsCommonPTMRBInformation,
      { "mbmsCommonPTMRBInformation", "umts_rrc.mbmsCommonPTMRBInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCCH-MessageType/mbmsCommonPTMRBInformation", HFILL }},
    { &hf_umts_rrc_mbmsCurrentCellPTMRBInformation,
      { "mbmsCurrentCellPTMRBInformation", "umts_rrc.mbmsCurrentCellPTMRBInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCCH-MessageType/mbmsCurrentCellPTMRBInformation", HFILL }},
    { &hf_umts_rrc_mbmsGeneralInformation,
      { "mbmsGeneralInformation", "umts_rrc.mbmsGeneralInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCCH-MessageType/mbmsGeneralInformation", HFILL }},
    { &hf_umts_rrc_mbmsNeighbouringCellPTMRBInformation,
      { "mbmsNeighbouringCellPTMRBInformation", "umts_rrc.mbmsNeighbouringCellPTMRBInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCCH-MessageType/mbmsNeighbouringCellPTMRBInformation", HFILL }},
    { &hf_umts_rrc_mbmsUnmodifiedServicesInformation,
      { "mbmsUnmodifiedServicesInformation", "umts_rrc.mbmsUnmodifiedServicesInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCCH-MessageType/mbmsUnmodifiedServicesInformation", HFILL }},
    { &hf_umts_rrc_spare9,
      { "spare9", "umts_rrc.spare9",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCCH-MessageType/spare9", HFILL }},
    { &hf_umts_rrc_spare8,
      { "spare8", "umts_rrc.spare8",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCCH-MessageType/spare8", HFILL }},
    { &hf_umts_rrc_spare7,
      { "spare7", "umts_rrc.spare7",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCCH-MessageType/spare7", HFILL }},
    { &hf_umts_rrc_spare6,
      { "spare6", "umts_rrc.spare6",
        FT_NONE, BASE_NONE, NULL, 0,
        "MCCH-MessageType/spare6", HFILL }},
    { &hf_umts_rrc_message10,
      { "message", "umts_rrc.message",
        FT_UINT32, BASE_DEC, VALS(umts_rrc_MSCH_MessageType_vals), 0,
        "MSCH-Message/message", HFILL }},
    { &hf_umts_rrc_mbmsSchedulingInformation,
      { "mbmsSchedulingInformation", "umts_rrc.mbmsSchedulingInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "MSCH-MessageType/mbmsSchedulingInformation", HFILL }},

/*--- End of included file: packet-umts_rrc-hfarr.c ---*/
#line 101 "packet-umts_rrc-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_umts_rrc,

/*--- Included file: packet-umts_rrc-ettarr.c ---*/
#line 1 "packet-umts_rrc-ettarr.c"
    &ett_umts_rrc_DL_DCCH_Message,
    &ett_umts_rrc_DL_DCCH_MessageType,
    &ett_umts_rrc_UL_DCCH_Message,
    &ett_umts_rrc_UL_DCCH_MessageType,
    &ett_umts_rrc_DL_CCCH_Message,
    &ett_umts_rrc_DL_CCCH_MessageType,
    &ett_umts_rrc_UL_CCCH_Message,
    &ett_umts_rrc_UL_CCCH_MessageType,
    &ett_umts_rrc_PCCH_Message,
    &ett_umts_rrc_PCCH_MessageType,
    &ett_umts_rrc_DL_SHCCH_Message,
    &ett_umts_rrc_DL_SHCCH_MessageType,
    &ett_umts_rrc_UL_SHCCH_Message,
    &ett_umts_rrc_UL_SHCCH_MessageType,
    &ett_umts_rrc_BCCH_FACH_Message,
    &ett_umts_rrc_BCCH_FACH_MessageType,
    &ett_umts_rrc_BCCH_BCH_Message,
    &ett_umts_rrc_MCCH_Message,
    &ett_umts_rrc_MCCH_MessageType,
    &ett_umts_rrc_MSCH_Message,
    &ett_umts_rrc_MSCH_MessageType,

/*--- End of included file: packet-umts_rrc-ettarr.c ---*/
#line 107 "packet-umts_rrc-template.c"
  };


  /* Register protocol */
  proto_umts_rrc = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_umts_rrc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

 
  register_dissector("umts_rrc", dissect_umts_rrc, proto_umts_rrc);


}


/*--- proto_reg_handoff_umts_rrc ---------------------------------------*/
void
proto_reg_handoff_umts_rrc(void)
{

	umts_rrc_handle = find_dissector("umts_rrc");

}


