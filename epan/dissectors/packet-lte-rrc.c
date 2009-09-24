/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-lte-rrc.c                                                           */
/* ../../tools/asn2wrs.py -L -p lte-rrc -c ./lte-rrc.cnf -s ./packet-lte-rrc-template -D . EUTRA-RRC-Definitions.asn EUTRA-UE-Variables.asn EUTRA-InterNodeDefinitions.asn */

/* Input file: packet-lte-rrc-template.c */

#line 1 "packet-lte-rrc-template.c"
/* packet-lte-rrc-template.c
 * Routines for Evolved Universal Terrestrial Radio Access (E-UTRA);
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 36.331 V8.3.0 Release 8) packet dissection
 * Copyright 2008, Vincent Helfre
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-per.h"


#define PNAME  "LTE Radio Resource Control (RRC) protocol"
#define PSNAME "LTE RRC"
#define PFNAME "lte_rrc"

static dissector_handle_t nas_eps_handle = NULL;

/* Include constants */

/*--- Included file: packet-lte-rrc-val.h ---*/
#line 1 "packet-lte-rrc-val.h"
#define maxAC                          5
#define maxBands                       64
#define maxCDMA_BandClass              31
#define maxCellBlack                   16
#define maxCellInter                   16
#define maxCellIntra                   16
#define maxCellMeas                    32
#define maxCellReport                  8
#define maxDRB                         11
#define maxEARFCN                      65535
#define maxFreq                        8
#define maxGERAN_Carrier               32
#define maxGERAN_SI                    10
#define maxGNFG                        16
#define maxMBSFN_Allocations           8
#define maxMCS_1                       16
#define maxMeasId                      32
#define maxObjectId                    32
#define maxPageRec                     16
#define maxPNOffset                    511
#define maxRAT_Capabilities            8
#define maxReportConfigId              32
#define maxSIB                         32
#define maxSIB_1                       31
#define maxSI_Message                  32
#define maxUTRA_FDD_Carrier            16
#define maxUTRA_TDD_Carrier            16
#define maxReestabInfo                 32

/*--- End of included file: packet-lte-rrc-val.h ---*/
#line 52 "packet-lte-rrc-template.c"

/* Initialize the protocol and registered fields */
static int proto_lte_rrc = -1;


/*--- Included file: packet-lte-rrc-hf.c ---*/
#line 1 "packet-lte-rrc-hf.c"
static int hf_lte_rrc_BCCH_BCH_Message_PDU = -1;  /* BCCH_BCH_Message */
static int hf_lte_rrc_BCCH_DL_SCH_Message_PDU = -1;  /* BCCH_DL_SCH_Message */
static int hf_lte_rrc_PCCH_Message_PDU = -1;      /* PCCH_Message */
static int hf_lte_rrc_DL_CCCH_Message_PDU = -1;   /* DL_CCCH_Message */
static int hf_lte_rrc_DL_DCCH_Message_PDU = -1;   /* DL_DCCH_Message */
static int hf_lte_rrc_UL_CCCH_Message_PDU = -1;   /* UL_CCCH_Message */
static int hf_lte_rrc_UL_DCCH_Message_PDU = -1;   /* UL_DCCH_Message */
static int hf_lte_rrc_UECapabilityInformation_PDU = -1;  /* UECapabilityInformation */
static int hf_lte_rrc_message = -1;               /* BCCH_BCH_MessageType */
static int hf_lte_rrc_message_01 = -1;            /* BCCH_DL_SCH_MessageType */
static int hf_lte_rrc_c1 = -1;                    /* T_c1 */
static int hf_lte_rrc_systemInformation = -1;     /* SystemInformation */
static int hf_lte_rrc_systemInformationBlockType1 = -1;  /* SystemInformationBlockType1 */
static int hf_lte_rrc_messageClassExtension = -1;  /* T_messageClassExtension */
static int hf_lte_rrc_message_02 = -1;            /* PCCH_MessageType */
static int hf_lte_rrc_c1_01 = -1;                 /* T_c1_01 */
static int hf_lte_rrc_paging = -1;                /* Paging */
static int hf_lte_rrc_messageClassExtension_01 = -1;  /* T_messageClassExtension_01 */
static int hf_lte_rrc_message_03 = -1;            /* DL_CCCH_MessageType */
static int hf_lte_rrc_c1_02 = -1;                 /* T_c1_02 */
static int hf_lte_rrc_rrcConnectionReestablishment = -1;  /* RRCConnectionReestablishment */
static int hf_lte_rrc_rrcConnectionReestablishmentReject = -1;  /* RRCConnectionReestablishmentReject */
static int hf_lte_rrc_rrcConnectionReject = -1;   /* RRCConnectionReject */
static int hf_lte_rrc_rrcConnectionSetup = -1;    /* RRCConnectionSetup */
static int hf_lte_rrc_messageClassExtension_02 = -1;  /* T_messageClassExtension_02 */
static int hf_lte_rrc_message_04 = -1;            /* DL_DCCH_MessageType */
static int hf_lte_rrc_c1_03 = -1;                 /* T_c1_03 */
static int hf_lte_rrc_cdma2000_CSFBParametersResponse = -1;  /* CDMA2000_CSFBParametersResponse */
static int hf_lte_rrc_dlInformationTransfer = -1;  /* DLInformationTransfer */
static int hf_lte_rrc_handoverFromEUTRAPreparationRequest = -1;  /* HandoverFromEUTRAPreparationRequest */
static int hf_lte_rrc_mobilityFromEUTRACommand = -1;  /* MobilityFromEUTRACommand */
static int hf_lte_rrc_rrcConnectionReconfiguration = -1;  /* RRCConnectionReconfiguration */
static int hf_lte_rrc_rrcConnectionRelease = -1;  /* RRCConnectionRelease */
static int hf_lte_rrc_securityModeCommand = -1;   /* SecurityModeCommand */
static int hf_lte_rrc_ueCapabilityEnquiry = -1;   /* UECapabilityEnquiry */
static int hf_lte_rrc_counterCheck = -1;          /* CounterCheck */
static int hf_lte_rrc_spare7 = -1;                /* NULL */
static int hf_lte_rrc_spare6 = -1;                /* NULL */
static int hf_lte_rrc_spare5 = -1;                /* NULL */
static int hf_lte_rrc_spare4 = -1;                /* NULL */
static int hf_lte_rrc_spare3 = -1;                /* NULL */
static int hf_lte_rrc_spare2 = -1;                /* NULL */
static int hf_lte_rrc_spare1 = -1;                /* NULL */
static int hf_lte_rrc_messageClassExtension_03 = -1;  /* T_messageClassExtension_03 */
static int hf_lte_rrc_message_05 = -1;            /* UL_CCCH_MessageType */
static int hf_lte_rrc_c1_04 = -1;                 /* T_c1_04 */
static int hf_lte_rrc_rrcConnectionReestablishmentRequest = -1;  /* RRCConnectionReestablishmentRequest */
static int hf_lte_rrc_rrcConnectionRequest = -1;  /* RRCConnectionRequest */
static int hf_lte_rrc_messageClassExtension_04 = -1;  /* T_messageClassExtension_04 */
static int hf_lte_rrc_message_06 = -1;            /* UL_DCCH_MessageType */
static int hf_lte_rrc_c1_05 = -1;                 /* T_c1_05 */
static int hf_lte_rrc_cdma2000_CSFBParametersRequest = -1;  /* CDMA2000_CSFBParametersRequest */
static int hf_lte_rrc_measurementReport = -1;     /* MeasurementReport */
static int hf_lte_rrc_rrcConnectionReconfigurationComplete = -1;  /* RRCConnectionReconfigurationComplete */
static int hf_lte_rrc_rrcConnectionReestablishmentComplete = -1;  /* RRCConnectionReestablishmentComplete */
static int hf_lte_rrc_rrcConnectionSetupComplete = -1;  /* RRCConnectionSetupComplete */
static int hf_lte_rrc_securityModeComplete = -1;  /* SecurityModeComplete */
static int hf_lte_rrc_securityModeFailure = -1;   /* SecurityModeFailure */
static int hf_lte_rrc_ueCapabilityInformation = -1;  /* UECapabilityInformation */
static int hf_lte_rrc_ulHandoverPreparationTransfer = -1;  /* ULHandoverPreparationTransfer */
static int hf_lte_rrc_ulInformationTransfer = -1;  /* ULInformationTransfer */
static int hf_lte_rrc_counterCheckResponse = -1;  /* CounterCheckResponse */
static int hf_lte_rrc_messageClassExtension_05 = -1;  /* T_messageClassExtension_05 */
static int hf_lte_rrc_rrc_TransactionIdentifier = -1;  /* RRC_TransactionIdentifier */
static int hf_lte_rrc_criticalExtensions = -1;    /* T_criticalExtensions */
static int hf_lte_rrc_cdma2000_CSFBParametersRequest_r8 = -1;  /* CDMA2000_CSFBParametersRequest_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture = -1;  /* T_criticalExtensionsFuture */
static int hf_lte_rrc_nonCriticalExtension = -1;  /* T_nonCriticalExtension */
static int hf_lte_rrc_criticalExtensions_01 = -1;  /* T_criticalExtensions_01 */
static int hf_lte_rrc_cdma2000_1xParametersForCSFB_r8 = -1;  /* CDMA2000_CSFBParametersResponse_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_01 = -1;  /* T_criticalExtensionsFuture_01 */
static int hf_lte_rrc_cdma2000_RAND = -1;         /* CDMA2000_RAND */
static int hf_lte_rrc_cdma2000_MobilityParameters = -1;  /* CDMA2000_MobilityParameters */
static int hf_lte_rrc_nonCriticalExtension_01 = -1;  /* T_nonCriticalExtension_01 */
static int hf_lte_rrc_criticalExtensions_02 = -1;  /* T_criticalExtensions_02 */
static int hf_lte_rrc_c1_06 = -1;                 /* T_c1_06 */
static int hf_lte_rrc_counterCheck_r8 = -1;       /* CounterCheck_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_02 = -1;  /* T_criticalExtensionsFuture_02 */
static int hf_lte_rrc_drb_CountMSB_InfoList = -1;  /* DRB_CountMSB_InfoList */
static int hf_lte_rrc_nonCriticalExtension_02 = -1;  /* T_nonCriticalExtension_02 */
static int hf_lte_rrc_DRB_CountMSB_InfoList_item = -1;  /* DRB_CountMSB_InfoList_item */
static int hf_lte_rrc_drb_Identity = -1;          /* INTEGER_1_32 */
static int hf_lte_rrc_countMSB_Uplink = -1;       /* INTEGER_0_33554431 */
static int hf_lte_rrc_countMSB_Downlink = -1;     /* INTEGER_0_33554431 */
static int hf_lte_rrc_criticalExtensions_03 = -1;  /* T_criticalExtensions_03 */
static int hf_lte_rrc_counterCheckResponse_r8 = -1;  /* CounterCheckResponse_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_03 = -1;  /* T_criticalExtensionsFuture_03 */
static int hf_lte_rrc_drb_CountInfoList = -1;     /* DRB_CountInfoList */
static int hf_lte_rrc_nonCriticalExtension_03 = -1;  /* T_nonCriticalExtension_03 */
static int hf_lte_rrc_DRB_CountInfoList_item = -1;  /* DRB_CountInfoList_item */
static int hf_lte_rrc_count_Uplink = -1;          /* INTEGER_0_4294967295 */
static int hf_lte_rrc_count_Downlink = -1;        /* INTEGER_0_4294967295 */
static int hf_lte_rrc_criticalExtensions_04 = -1;  /* T_criticalExtensions_04 */
static int hf_lte_rrc_c1_07 = -1;                 /* T_c1_07 */
static int hf_lte_rrc_dlInformationTransfer_r8 = -1;  /* DLInformationTransfer_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_04 = -1;  /* T_criticalExtensionsFuture_04 */
static int hf_lte_rrc_informationType = -1;       /* T_informationType */
static int hf_lte_rrc_nas3GPP = -1;               /* NAS_DedicatedInformation */
static int hf_lte_rrc_cdma2000 = -1;              /* T_cdma2000 */
static int hf_lte_rrc_cdma2000_Type = -1;         /* CDMA2000_Type */
static int hf_lte_rrc_cdma2000_DedicatedInfo = -1;  /* CDMA2000_DedicatedInfo */
static int hf_lte_rrc_nonCriticalExtension_04 = -1;  /* T_nonCriticalExtension_04 */
static int hf_lte_rrc_criticalExtensions_05 = -1;  /* T_criticalExtensions_05 */
static int hf_lte_rrc_c1_08 = -1;                 /* T_c1_08 */
static int hf_lte_rrc_handoverFromEUTRAPreparationRequest_r8 = -1;  /* HandoverFromEUTRAPreparationRequest_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_05 = -1;  /* T_criticalExtensionsFuture_05 */
static int hf_lte_rrc_nonCriticalExtension_05 = -1;  /* T_nonCriticalExtension_05 */
static int hf_lte_rrc_dl_Bandwidth = -1;          /* T_dl_Bandwidth */
static int hf_lte_rrc_phich_Configuration = -1;   /* PHICH_Configuration */
static int hf_lte_rrc_systemFrameNumber = -1;     /* BIT_STRING_SIZE_8 */
static int hf_lte_rrc_spare = -1;                 /* BIT_STRING_SIZE_10 */
static int hf_lte_rrc_criticalExtensions_06 = -1;  /* T_criticalExtensions_06 */
static int hf_lte_rrc_c1_09 = -1;                 /* T_c1_09 */
static int hf_lte_rrc_measurementReport_r8 = -1;  /* MeasurementReport_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_06 = -1;  /* T_criticalExtensionsFuture_06 */
static int hf_lte_rrc_measuredResults = -1;       /* MeasuredResults */
static int hf_lte_rrc_nonCriticalExtension_06 = -1;  /* T_nonCriticalExtension_06 */
static int hf_lte_rrc_criticalExtensions_07 = -1;  /* T_criticalExtensions_07 */
static int hf_lte_rrc_c1_10 = -1;                 /* T_c1_10 */
static int hf_lte_rrc_mobilityFromEUTRACommand_r8 = -1;  /* MobilityFromEUTRACommand_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_07 = -1;  /* T_criticalExtensionsFuture_07 */
static int hf_lte_rrc_csFallbackIndicator = -1;   /* T_csFallbackIndicator */
static int hf_lte_rrc_purpose = -1;               /* T_purpose */
static int hf_lte_rrc_handover = -1;              /* Handover */
static int hf_lte_rrc_cellChangeOrder = -1;       /* CellChangeOrder */
static int hf_lte_rrc_nonCriticalExtension_07 = -1;  /* T_nonCriticalExtension_07 */
static int hf_lte_rrc_targetRAT_Type = -1;        /* T_targetRAT_Type */
static int hf_lte_rrc_targetRAT_MessageContainer = -1;  /* OCTET_STRING */
static int hf_lte_rrc_nas_SecurityParamFromEUTRA = -1;  /* OCTET_STRING */
static int hf_lte_rrc_t304 = -1;                  /* T_t304 */
static int hf_lte_rrc_targetRAT_Type_01 = -1;     /* T_targetRAT_Type_01 */
static int hf_lte_rrc_geran = -1;                 /* T_geran */
static int hf_lte_rrc_bsic = -1;                  /* GERAN_CellIdentity */
static int hf_lte_rrc_geran_CarrierFreq = -1;     /* GERAN_CarrierFreq */
static int hf_lte_rrc_networkControlOrder = -1;   /* BIT_STRING_SIZE_2 */
static int hf_lte_rrc_geran_SystemInformation = -1;  /* T_geran_SystemInformation */
static int hf_lte_rrc_si = -1;                    /* GERAN_SystemInformation */
static int hf_lte_rrc_psi = -1;                   /* GERAN_SystemInformation */
static int hf_lte_rrc_GERAN_SystemInformation_item = -1;  /* OCTET_STRING_SIZE_1_23 */
static int hf_lte_rrc_pagingRecordList = -1;      /* PagingRecordList */
static int hf_lte_rrc_systemInfoModification = -1;  /* T_systemInfoModification */
static int hf_lte_rrc_etws_Indication = -1;       /* T_etws_Indication */
static int hf_lte_rrc_nonCriticalExtension_08 = -1;  /* T_nonCriticalExtension_08 */
static int hf_lte_rrc_PagingRecordList_item = -1;  /* PagingRecord */
static int hf_lte_rrc_ue_Identity = -1;           /* PagingUE_Identity */
static int hf_lte_rrc_cn_Domain = -1;             /* T_cn_Domain */
static int hf_lte_rrc_s_TMSI = -1;                /* S_TMSI */
static int hf_lte_rrc_imsi = -1;                  /* IMSI */
static int hf_lte_rrc_criticalExtensions_08 = -1;  /* T_criticalExtensions_08 */
static int hf_lte_rrc_c1_11 = -1;                 /* T_c1_11 */
static int hf_lte_rrc_rrcConnectionReconfiguration_r8 = -1;  /* RRCConnectionReconfiguration_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_08 = -1;  /* T_criticalExtensionsFuture_08 */
static int hf_lte_rrc_measurementConfiguration = -1;  /* MeasurementConfiguration */
static int hf_lte_rrc_mobilityControlInformation = -1;  /* MobilityControlInformation */
static int hf_lte_rrc_nas_DedicatedInformationList = -1;  /* SEQUENCE_SIZE_1_maxDRB_OF_NAS_DedicatedInformation */
static int hf_lte_rrc_nas_DedicatedInformationList_item = -1;  /* NAS_DedicatedInformation */
static int hf_lte_rrc_radioResourceConfiguration = -1;  /* RadioResourceConfigDedicated */
static int hf_lte_rrc_securityConfiguration = -1;  /* SecurityConfiguration */
static int hf_lte_rrc_nas_SecurityParamToEUTRA = -1;  /* OCTET_STRING_SIZE_6 */
static int hf_lte_rrc_nonCriticalExtension_09 = -1;  /* T_nonCriticalExtension_09 */
static int hf_lte_rrc_criticalExtensions_09 = -1;  /* T_criticalExtensions_09 */
static int hf_lte_rrc_rrcConnectionReconfigurationComplete_r8 = -1;  /* RRCConnectionReconfigurationComplete_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_09 = -1;  /* T_criticalExtensionsFuture_09 */
static int hf_lte_rrc_nonCriticalExtension_10 = -1;  /* T_nonCriticalExtension_10 */
static int hf_lte_rrc_criticalExtensions_10 = -1;  /* T_criticalExtensions_10 */
static int hf_lte_rrc_c1_12 = -1;                 /* T_c1_12 */
static int hf_lte_rrc_rrcConnectionReestablishment_r8 = -1;  /* RRCConnectionReestablishment_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_10 = -1;  /* T_criticalExtensionsFuture_10 */
static int hf_lte_rrc_nextHopChainingCount = -1;  /* NextHopChainingCount */
static int hf_lte_rrc_nonCriticalExtension_11 = -1;  /* T_nonCriticalExtension_11 */
static int hf_lte_rrc_criticalExtensions_11 = -1;  /* T_criticalExtensions_11 */
static int hf_lte_rrc_rrcConnectionReestablishmentComplete_r8 = -1;  /* RRCConnectionReestablishmentComplete_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_11 = -1;  /* T_criticalExtensionsFuture_11 */
static int hf_lte_rrc_nonCriticalExtension_12 = -1;  /* T_nonCriticalExtension_12 */
static int hf_lte_rrc_criticalExtensions_12 = -1;  /* T_criticalExtensions_12 */
static int hf_lte_rrc_rrcConnectionReestablishmentReject_r8 = -1;  /* RRCConnectionReestablishmentReject_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_12 = -1;  /* T_criticalExtensionsFuture_12 */
static int hf_lte_rrc_nonCriticalExtension_13 = -1;  /* T_nonCriticalExtension_13 */
static int hf_lte_rrc_criticalExtensions_13 = -1;  /* T_criticalExtensions_13 */
static int hf_lte_rrc_rrcConnectionReestablishmentRequest_r8 = -1;  /* RRCConnectionReestablishmentRequest_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_13 = -1;  /* T_criticalExtensionsFuture_13 */
static int hf_lte_rrc_ue_Identity_01 = -1;        /* ReestabUE_Identity */
static int hf_lte_rrc_reestablishmentCause = -1;  /* ReestablishmentCause */
static int hf_lte_rrc_spare_01 = -1;              /* BIT_STRING_SIZE_2 */
static int hf_lte_rrc_c_RNTI = -1;                /* C_RNTI */
static int hf_lte_rrc_physCellIdentity = -1;      /* PhysicalCellIdentity */
static int hf_lte_rrc_shortMAC_I = -1;            /* ShortMAC_I */
static int hf_lte_rrc_criticalExtensions_14 = -1;  /* T_criticalExtensions_14 */
static int hf_lte_rrc_c1_13 = -1;                 /* T_c1_13 */
static int hf_lte_rrc_rrcConnectionReject_r8 = -1;  /* RRCConnectionReject_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_14 = -1;  /* T_criticalExtensionsFuture_14 */
static int hf_lte_rrc_waitTime = -1;              /* INTEGER_1_16 */
static int hf_lte_rrc_nonCriticalExtension_14 = -1;  /* T_nonCriticalExtension_14 */
static int hf_lte_rrc_criticalExtensions_15 = -1;  /* T_criticalExtensions_15 */
static int hf_lte_rrc_c1_14 = -1;                 /* T_c1_14 */
static int hf_lte_rrc_rrcConnectionRelease_r8 = -1;  /* RRCConnectionRelease_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_15 = -1;  /* T_criticalExtensionsFuture_15 */
static int hf_lte_rrc_releaseCause = -1;          /* ReleaseCause */
static int hf_lte_rrc_redirectionInformation = -1;  /* RedirectionInformation */
static int hf_lte_rrc_idleModeMobilityControlInfo = -1;  /* IdleModeMobilityControlInfo */
static int hf_lte_rrc_nonCriticalExtension_15 = -1;  /* T_nonCriticalExtension_15 */
static int hf_lte_rrc_eutra_CarrierFreq = -1;     /* EUTRA_DL_CarrierFreq */
static int hf_lte_rrc_interRAT_target = -1;       /* T_interRAT_target */
static int hf_lte_rrc_geran_01 = -1;              /* GERAN_CarrierFreq */
static int hf_lte_rrc_utra_FDD = -1;              /* UTRA_DL_CarrierFreq */
static int hf_lte_rrc_utra_TDD = -1;              /* UTRA_DL_CarrierFreq */
static int hf_lte_rrc_cdma2000_HRPD = -1;         /* CDMA2000_CarrierInfo */
static int hf_lte_rrc_cdma2000_1xRTT = -1;        /* CDMA2000_CarrierInfo */
static int hf_lte_rrc_interFreqPriorityList = -1;  /* InterFreqPriorityList */
static int hf_lte_rrc_geran_FreqPriorityList = -1;  /* GERAN_FreqPriorityList */
static int hf_lte_rrc_utra_FDD_FreqPriorityList = -1;  /* UTRA_FDD_FreqPriorityList */
static int hf_lte_rrc_utra_TDD_FreqPriorityList = -1;  /* UTRA_TDD_FreqPriorityList */
static int hf_lte_rrc_hrpd_BandClassPriorityList = -1;  /* HRPD_BandClassPriorityList */
static int hf_lte_rrc_oneXRTT_BandClassPriorityList = -1;  /* OneXRTT_BandClassPriorityList */
static int hf_lte_rrc_t320 = -1;                  /* T_t320 */
static int hf_lte_rrc_InterFreqPriorityList_item = -1;  /* InterFreqPriorityList_item */
static int hf_lte_rrc_cellReselectionPriority = -1;  /* INTEGER_0_7 */
static int hf_lte_rrc_GERAN_FreqPriorityList_item = -1;  /* GERAN_FreqPriorityList_item */
static int hf_lte_rrc_geran_BCCH_FrequencyGroup = -1;  /* GERAN_CarrierFreqList */
static int hf_lte_rrc_geran_CellReselectionPriority = -1;  /* INTEGER_0_7 */
static int hf_lte_rrc_UTRA_FDD_FreqPriorityList_item = -1;  /* UTRA_FDD_FreqPriorityList_item */
static int hf_lte_rrc_utra_CarrierFreq = -1;      /* UTRA_DL_CarrierFreq */
static int hf_lte_rrc_utra_CellReselectionPriority = -1;  /* INTEGER_0_7 */
static int hf_lte_rrc_UTRA_TDD_FreqPriorityList_item = -1;  /* UTRA_TDD_FreqPriorityList_item */
static int hf_lte_rrc_HRPD_BandClassPriorityList_item = -1;  /* HRPD_BandClassPriorityList_item */
static int hf_lte_rrc_hrpd_bandClass = -1;        /* CDMA2000_Bandclass */
static int hf_lte_rrc_hrpd_CellReselectionPriority = -1;  /* INTEGER_0_7 */
static int hf_lte_rrc_OneXRTT_BandClassPriorityList_item = -1;  /* OneXRTT_BandClassPriorityList_item */
static int hf_lte_rrc_oneXRTT_bandClass = -1;     /* CDMA2000_Bandclass */
static int hf_lte_rrc_oneXRTT_CellReselectionPriority = -1;  /* INTEGER_0_7 */
static int hf_lte_rrc_criticalExtensions_16 = -1;  /* T_criticalExtensions_16 */
static int hf_lte_rrc_rrcConnectionRequest_r8 = -1;  /* RRCConnectionRequest_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_16 = -1;  /* T_criticalExtensionsFuture_16 */
static int hf_lte_rrc_ue_Identity_02 = -1;        /* InitialUE_Identity */
static int hf_lte_rrc_establishmentCause = -1;    /* EstablishmentCause */
static int hf_lte_rrc_spare_02 = -1;              /* BIT_STRING_SIZE_1 */
static int hf_lte_rrc_randomValue = -1;           /* BIT_STRING_SIZE_40 */
static int hf_lte_rrc_criticalExtensions_17 = -1;  /* T_criticalExtensions_17 */
static int hf_lte_rrc_c1_15 = -1;                 /* T_c1_15 */
static int hf_lte_rrc_rrcConnectionSetup_r8 = -1;  /* RRCConnectionSetup_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_17 = -1;  /* T_criticalExtensionsFuture_17 */
static int hf_lte_rrc_nonCriticalExtension_16 = -1;  /* T_nonCriticalExtension_16 */
static int hf_lte_rrc_criticalExtensions_18 = -1;  /* T_criticalExtensions_18 */
static int hf_lte_rrc_c1_16 = -1;                 /* T_c1_16 */
static int hf_lte_rrc_rrcConnectionSetupComplete_r8 = -1;  /* RRCConnectionSetupComplete_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_18 = -1;  /* T_criticalExtensionsFuture_18 */
static int hf_lte_rrc_selectedPLMN_Identity = -1;  /* INTEGER_1_6 */
static int hf_lte_rrc_registeredMME = -1;         /* RegisteredMME */
static int hf_lte_rrc_nas_DedicatedInformation = -1;  /* NAS_DedicatedInformation */
static int hf_lte_rrc_nonCriticalExtension_17 = -1;  /* T_nonCriticalExtension_17 */
static int hf_lte_rrc_plmn_Identity = -1;         /* PLMN_Identity */
static int hf_lte_rrc_mmegi = -1;                 /* BIT_STRING_SIZE_16 */
static int hf_lte_rrc_mmec = -1;                  /* MMEC */
static int hf_lte_rrc_criticalExtensions_19 = -1;  /* T_criticalExtensions_19 */
static int hf_lte_rrc_c1_17 = -1;                 /* T_c1_17 */
static int hf_lte_rrc_securityModeCommand_r8 = -1;  /* SecurityModeCommand_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_19 = -1;  /* T_criticalExtensionsFuture_19 */
static int hf_lte_rrc_nonCriticalExtension_18 = -1;  /* T_nonCriticalExtension_18 */
static int hf_lte_rrc_criticalExtensions_20 = -1;  /* T_criticalExtensions_20 */
static int hf_lte_rrc_securityModeComplete_r8 = -1;  /* SecurityModeComplete_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_20 = -1;  /* T_criticalExtensionsFuture_20 */
static int hf_lte_rrc_nonCriticalExtension_19 = -1;  /* T_nonCriticalExtension_19 */
static int hf_lte_rrc_criticalExtensions_21 = -1;  /* T_criticalExtensions_21 */
static int hf_lte_rrc_securityModeFailure_r8 = -1;  /* SecurityModeFailure_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_21 = -1;  /* T_criticalExtensionsFuture_21 */
static int hf_lte_rrc_nonCriticalExtension_20 = -1;  /* T_nonCriticalExtension_20 */
static int hf_lte_rrc_criticalExtensions_22 = -1;  /* T_criticalExtensions_22 */
static int hf_lte_rrc_systemInformation_r8 = -1;  /* SystemInformation_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_22 = -1;  /* T_criticalExtensionsFuture_22 */
static int hf_lte_rrc_sib_TypeAndInfo = -1;       /* T_sib_TypeAndInfo */
static int hf_lte_rrc_sib_TypeAndInfo_item = -1;  /* T_sib_TypeAndInfo_item */
static int hf_lte_rrc_sib2 = -1;                  /* SystemInformationBlockType2 */
static int hf_lte_rrc_sib3 = -1;                  /* SystemInformationBlockType3 */
static int hf_lte_rrc_sib4 = -1;                  /* SystemInformationBlockType4 */
static int hf_lte_rrc_sib5 = -1;                  /* SystemInformationBlockType5 */
static int hf_lte_rrc_sib6 = -1;                  /* SystemInformationBlockType6 */
static int hf_lte_rrc_sib7 = -1;                  /* SystemInformationBlockType7 */
static int hf_lte_rrc_sib8 = -1;                  /* SystemInformationBlockType8 */
static int hf_lte_rrc_sib9 = -1;                  /* SystemInformationBlockType9 */
static int hf_lte_rrc_sib10 = -1;                 /* SystemInformationBlockType10 */
static int hf_lte_rrc_sib11 = -1;                 /* SystemInformationBlockType11 */
static int hf_lte_rrc_nonCriticalExtension_21 = -1;  /* T_nonCriticalExtension_21 */
static int hf_lte_rrc_cellAccessRelatedInformation = -1;  /* T_cellAccessRelatedInformation */
static int hf_lte_rrc_plmn_IdentityList = -1;     /* PLMN_IdentityList */
static int hf_lte_rrc_trackingAreaCode = -1;      /* TrackingAreaCode */
static int hf_lte_rrc_cellIdentity = -1;          /* CellIdentity */
static int hf_lte_rrc_cellBarred = -1;            /* T_cellBarred */
static int hf_lte_rrc_intraFrequencyReselection = -1;  /* T_intraFrequencyReselection */
static int hf_lte_rrc_csg_Indication = -1;        /* BOOLEAN */
static int hf_lte_rrc_csg_Identity = -1;          /* BIT_STRING_SIZE_27 */
static int hf_lte_rrc_cellSelectionInfo = -1;     /* T_cellSelectionInfo */
static int hf_lte_rrc_q_RxLevMin = -1;            /* INTEGER_M70_M22 */
static int hf_lte_rrc_q_RxLevMinOffset = -1;      /* INTEGER_1_8 */
static int hf_lte_rrc_p_Max = -1;                 /* P_Max */
static int hf_lte_rrc_frequencyBandIndicator = -1;  /* INTEGER_1_64 */
static int hf_lte_rrc_schedulingInformation = -1;  /* SchedulingInformation */
static int hf_lte_rrc_tdd_Configuration = -1;     /* TDD_Configuration */
static int hf_lte_rrc_si_WindowLength = -1;       /* T_si_WindowLength */
static int hf_lte_rrc_systemInformationValueTag = -1;  /* INTEGER_0_31 */
static int hf_lte_rrc_nonCriticalExtension_22 = -1;  /* T_nonCriticalExtension_22 */
static int hf_lte_rrc_PLMN_IdentityList_item = -1;  /* PLMN_IdentityList_item */
static int hf_lte_rrc_cellReservedForOperatorUse = -1;  /* T_cellReservedForOperatorUse */
static int hf_lte_rrc_SchedulingInformation_item = -1;  /* SchedulingInformation_item */
static int hf_lte_rrc_si_Periodicity = -1;        /* T_si_Periodicity */
static int hf_lte_rrc_sib_MappingInfo = -1;       /* SIB_MappingInfo */
static int hf_lte_rrc_SIB_MappingInfo_item = -1;  /* SIB_Type */
static int hf_lte_rrc_criticalExtensions_23 = -1;  /* T_criticalExtensions_23 */
static int hf_lte_rrc_c1_18 = -1;                 /* T_c1_18 */
static int hf_lte_rrc_ueCapabilityEnquiry_r8 = -1;  /* UECapabilityEnquiry_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_23 = -1;  /* T_criticalExtensionsFuture_23 */
static int hf_lte_rrc_ue_RadioAccessCapRequest = -1;  /* UE_RadioAccessCapRequest */
static int hf_lte_rrc_nonCriticalExtension_23 = -1;  /* T_nonCriticalExtension_23 */
static int hf_lte_rrc_UE_RadioAccessCapRequest_item = -1;  /* RAT_Type */
static int hf_lte_rrc_criticalExtensions_24 = -1;  /* T_criticalExtensions_24 */
static int hf_lte_rrc_c1_19 = -1;                 /* T_c1_19 */
static int hf_lte_rrc_ueCapabilityInformation_r8 = -1;  /* UECapabilityInformation_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_24 = -1;  /* T_criticalExtensionsFuture_24 */
static int hf_lte_rrc_UECapabilityInformation_r8_IEs_item = -1;  /* UECapabilityInformation_r8_IEs_item */
static int hf_lte_rrc_rat_Type = -1;              /* RAT_Type */
static int hf_lte_rrc_ueCapabilitiesRAT_Container = -1;  /* OCTET_STRING */
static int hf_lte_rrc_nonCriticalExtension_24 = -1;  /* T_nonCriticalExtension_24 */
static int hf_lte_rrc_criticalExtensions_25 = -1;  /* T_criticalExtensions_25 */
static int hf_lte_rrc_c1_20 = -1;                 /* T_c1_20 */
static int hf_lte_rrc_ulHandoverPreparationTransfer_r8 = -1;  /* ULHandoverPreparationTransfer_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_25 = -1;  /* T_criticalExtensionsFuture_25 */
static int hf_lte_rrc_cdma2000_MEID = -1;         /* BIT_STRING_SIZE_56 */
static int hf_lte_rrc_nonCriticalExtension_25 = -1;  /* T_nonCriticalExtension_25 */
static int hf_lte_rrc_criticalExtensions_26 = -1;  /* T_criticalExtensions_26 */
static int hf_lte_rrc_c1_21 = -1;                 /* T_c1_21 */
static int hf_lte_rrc_ulInformationTransfer_r8 = -1;  /* ULInformationTransfer_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_26 = -1;  /* T_criticalExtensionsFuture_26 */
static int hf_lte_rrc_informationType_01 = -1;    /* T_informationType_01 */
static int hf_lte_rrc_cdma2000_01 = -1;           /* T_cdma2000_01 */
static int hf_lte_rrc_nonCriticalExtension_26 = -1;  /* T_nonCriticalExtension_26 */
static int hf_lte_rrc_accessBarringInformation = -1;  /* T_accessBarringInformation */
static int hf_lte_rrc_accessBarringForEmergencyCalls = -1;  /* BOOLEAN */
static int hf_lte_rrc_accessBarringForSignalling = -1;  /* AccessClassBarringInformation */
static int hf_lte_rrc_accessBarringForOriginatingCalls = -1;  /* AccessClassBarringInformation */
static int hf_lte_rrc_radioResourceConfigCommon = -1;  /* RadioResourceConfigCommonSIB */
static int hf_lte_rrc_ue_TimersAndConstants = -1;  /* UE_TimersAndConstants */
static int hf_lte_rrc_frequencyInformation = -1;  /* T_frequencyInformation */
static int hf_lte_rrc_ul_EARFCN = -1;             /* INTEGER_0_maxEARFCN */
static int hf_lte_rrc_ul_Bandwidth = -1;          /* T_ul_Bandwidth */
static int hf_lte_rrc_additionalSpectrumEmission = -1;  /* INTEGER_0_31 */
static int hf_lte_rrc_mbsfn_SubframeConfiguration = -1;  /* MBSFN_SubframeConfiguration */
static int hf_lte_rrc_timeAlignmentTimerCommon = -1;  /* TimeAlignmentTimer */
static int hf_lte_rrc_accessProbabilityFactor = -1;  /* T_accessProbabilityFactor */
static int hf_lte_rrc_accessBarringTime = -1;     /* T_accessBarringTime */
static int hf_lte_rrc_accessClassBarringList = -1;  /* AccessClassBarringList */
static int hf_lte_rrc_AccessClassBarringList_item = -1;  /* AccessClassBarringList_item */
static int hf_lte_rrc_accessClassBarring = -1;    /* BOOLEAN */
static int hf_lte_rrc_MBSFN_SubframeConfiguration_item = -1;  /* MBSFN_SubframeConfiguration_item */
static int hf_lte_rrc_radioframeAllocationPeriod = -1;  /* T_radioframeAllocationPeriod */
static int hf_lte_rrc_radioframeAllocationOffset = -1;  /* INTEGER_0_7 */
static int hf_lte_rrc_subframeAllocation = -1;    /* T_subframeAllocation */
static int hf_lte_rrc_oneFrame = -1;              /* BIT_STRING_SIZE_6 */
static int hf_lte_rrc_fourFrames = -1;            /* BIT_STRING_SIZE_24 */
static int hf_lte_rrc_cellReselectionInfoCommon = -1;  /* T_cellReselectionInfoCommon */
static int hf_lte_rrc_q_Hyst = -1;                /* T_q_Hyst */
static int hf_lte_rrc_speedDependentReselection = -1;  /* T_speedDependentReselection */
static int hf_lte_rrc_mobilityStateParameters = -1;  /* MobilityStateParameters */
static int hf_lte_rrc_speedDependentScalingParametersHyst = -1;  /* T_speedDependentScalingParametersHyst */
static int hf_lte_rrc_q_HystSF_Medium = -1;       /* T_q_HystSF_Medium */
static int hf_lte_rrc_q_HystSF_High = -1;         /* T_q_HystSF_High */
static int hf_lte_rrc_sameRefSignalsInNeighbour = -1;  /* BOOLEAN */
static int hf_lte_rrc_cellReselectionServingFreqInfo = -1;  /* T_cellReselectionServingFreqInfo */
static int hf_lte_rrc_s_NonIntraSearch = -1;      /* ReselectionThreshold */
static int hf_lte_rrc_threshServingLow = -1;      /* ReselectionThreshold */
static int hf_lte_rrc_intraFreqCellReselectionInfo = -1;  /* T_intraFreqCellReselectionInfo */
static int hf_lte_rrc_s_IntraSearch = -1;         /* ReselectionThreshold */
static int hf_lte_rrc_measurementBandwidth = -1;  /* MeasurementBandwidth */
static int hf_lte_rrc_neighbourCellConfiguration = -1;  /* NeighbourCellConfiguration */
static int hf_lte_rrc_t_ReselectionEUTRAN = -1;   /* INTEGER_0_7 */
static int hf_lte_rrc_speedDependentScalingParameters = -1;  /* T_speedDependentScalingParameters */
static int hf_lte_rrc_t_ReselectionEUTRAN_SF_Medium = -1;  /* T_t_ReselectionEUTRAN_SF_Medium */
static int hf_lte_rrc_t_ReselectionEUTRAN_SF_High = -1;  /* T_t_ReselectionEUTRAN_SF_High */
static int hf_lte_rrc_intraFreqNeighbouringCellList = -1;  /* IntraFreqNeighbouringCellList */
static int hf_lte_rrc_intraFreqBlacklistedCellList = -1;  /* IntraFreqBlacklistedCellList */
static int hf_lte_rrc_csg_PCI_Range = -1;         /* PhysicalCellIdentityAndRange */
static int hf_lte_rrc_IntraFreqNeighbouringCellList_item = -1;  /* IntraFreqNeighbouringCellList_item */
static int hf_lte_rrc_physicalCellIdentity = -1;  /* PhysicalCellIdentity */
static int hf_lte_rrc_q_OffsetCell = -1;          /* T_q_OffsetCell */
static int hf_lte_rrc_IntraFreqBlacklistedCellList_item = -1;  /* IntraFreqBlacklistedCellList_item */
static int hf_lte_rrc_physicalCellIdentityAndRange = -1;  /* PhysicalCellIdentityAndRange */
static int hf_lte_rrc_interFreqCarrierFreqList = -1;  /* InterFreqCarrierFreqList */
static int hf_lte_rrc_InterFreqCarrierFreqList_item = -1;  /* InterFreqCarrierFreqList_item */
static int hf_lte_rrc_speedDependentScalingParameters_01 = -1;  /* T_speedDependentScalingParameters_01 */
static int hf_lte_rrc_t_ReselectionEUTRAN_SF_Medium_01 = -1;  /* T_t_ReselectionEUTRAN_SF_Medium_01 */
static int hf_lte_rrc_t_ReselectionEUTRAN_SF_High_01 = -1;  /* T_t_ReselectionEUTRAN_SF_High_01 */
static int hf_lte_rrc_threshX_High = -1;          /* ReselectionThreshold */
static int hf_lte_rrc_threshX_Low = -1;           /* ReselectionThreshold */
static int hf_lte_rrc_q_OffsetFreq = -1;          /* T_q_OffsetFreq */
static int hf_lte_rrc_interFreqNeighbouringCellList = -1;  /* InterFreqNeighbouringCellList */
static int hf_lte_rrc_interFreqBlacklistedCellList = -1;  /* InterFreqBlacklistedCellList */
static int hf_lte_rrc_InterFreqNeighbouringCellList_item = -1;  /* InterFreqNeighbouringCellList_item */
static int hf_lte_rrc_q_OffsetCell_01 = -1;       /* T_q_OffsetCell_01 */
static int hf_lte_rrc_InterFreqBlacklistedCellList_item = -1;  /* InterFreqBlacklistedCellList_item */
static int hf_lte_rrc_utra_FDD_CarrierFreqList = -1;  /* UTRA_FDD_CarrierFreqList */
static int hf_lte_rrc_utra_TDD_CarrierFreqList = -1;  /* UTRA_TDD_CarrierFreqList */
static int hf_lte_rrc_t_ReselectionUTRA = -1;     /* INTEGER_0_7 */
static int hf_lte_rrc_speedDependentScalingParameters_02 = -1;  /* T_speedDependentScalingParameters_02 */
static int hf_lte_rrc_t_ReselectionUTRA_SF_Medium = -1;  /* T_t_ReselectionUTRA_SF_Medium */
static int hf_lte_rrc_t_ReselectionUTRA_SF_High = -1;  /* T_t_ReselectionUTRA_SF_High */
static int hf_lte_rrc_UTRA_FDD_CarrierFreqList_item = -1;  /* UTRA_FDD_CarrierFreqList_item */
static int hf_lte_rrc_maxAllowedTxPower = -1;     /* INTEGER_M50_33 */
static int hf_lte_rrc_q_QualMin = -1;             /* INTEGER_M24_0 */
static int hf_lte_rrc_UTRA_TDD_CarrierFreqList_item = -1;  /* UTRA_TDD_CarrierFreqList_item */
static int hf_lte_rrc_t_ReselectionGERAN = -1;    /* INTEGER_0_7 */
static int hf_lte_rrc_speedDependentScalingParameters_03 = -1;  /* T_speedDependentScalingParameters_03 */
static int hf_lte_rrc_t_ReselectionGERAN_SF_Medium = -1;  /* T_t_ReselectionGERAN_SF_Medium */
static int hf_lte_rrc_t_ReselectionGERAN_SF_High = -1;  /* T_t_ReselectionGERAN_SF_High */
static int hf_lte_rrc_geran_NeigbourFreqList = -1;  /* GERAN_NeigbourFreqList */
static int hf_lte_rrc_GERAN_NeigbourFreqList_item = -1;  /* GERAN_BCCH_Group */
static int hf_lte_rrc_geran_BCCH_Configuration = -1;  /* T_geran_BCCH_Configuration */
static int hf_lte_rrc_ncc_Permitted = -1;         /* BIT_STRING_SIZE_8 */
static int hf_lte_rrc_q_RxLevMin_01 = -1;         /* INTEGER_0_31 */
static int hf_lte_rrc_p_MaxGERAN = -1;            /* INTEGER_0_39 */
static int hf_lte_rrc_cdma2000_SystemTimeInfo = -1;  /* CDMA2000_SystemTimeInfo */
static int hf_lte_rrc_searchWindowSize = -1;      /* INTEGER_0_15 */
static int hf_lte_rrc_hrpd_Parameters = -1;       /* T_hrpd_Parameters */
static int hf_lte_rrc_hrpd_PreRegistrationInfo = -1;  /* HRPD_PreRegistrationInfo */
static int hf_lte_rrc_hrpd_CellReselectionParameters = -1;  /* T_hrpd_CellReselectionParameters */
static int hf_lte_rrc_hrpd_BandClassList = -1;    /* HRPD_BandClassList */
static int hf_lte_rrc_hrpd_NeighborCellList = -1;  /* CDMA2000_NeighbourCellList */
static int hf_lte_rrc_t_ReselectionCDMA_HRPD = -1;  /* INTEGER_0_7 */
static int hf_lte_rrc_speedDependentScalingParameters_04 = -1;  /* T_speedDependentScalingParameters_04 */
static int hf_lte_rrc_t_ReselectionCDMA_HRPD_SF_Medium = -1;  /* T_t_ReselectionCDMA_HRPD_SF_Medium */
static int hf_lte_rrc_t_ReselectionCDMA_HRPD_SF_High = -1;  /* T_t_ReselectionCDMA_HRPD_SF_High */
static int hf_lte_rrc_oneXRTT_Parameters = -1;    /* T_oneXRTT_Parameters */
static int hf_lte_rrc_oneXRTT_CSFB_RegistrationInfo = -1;  /* OneXRTT_CSFB_RegistrationInfo */
static int hf_lte_rrc_oneXRTT_LongCodeState = -1;  /* BIT_STRING_SIZE_42 */
static int hf_lte_rrc_oneXRTT_CellReselectionParameters = -1;  /* T_oneXRTT_CellReselectionParameters */
static int hf_lte_rrc_oneXRTT_BandClassList = -1;  /* OneXRTT_BandClassList */
static int hf_lte_rrc_oneXRTT_NeighborCellList = -1;  /* CDMA2000_NeighbourCellList */
static int hf_lte_rrc_t_ReselectionCDMA_OneXRTT = -1;  /* INTEGER_0_7 */
static int hf_lte_rrc_speedDependentScalingParameters_05 = -1;  /* T_speedDependentScalingParameters_05 */
static int hf_lte_rrc_t_ReselectionCDMA_OneXRTT_SF_Medium = -1;  /* T_t_ReselectionCDMA_OneXRTT_SF_Medium */
static int hf_lte_rrc_t_ReselectionCDMA_OneXRTT_SF_High = -1;  /* T_t_ReselectionCDMA_OneXRTT_SF_High */
static int hf_lte_rrc_CDMA2000_NeighbourCellList_item = -1;  /* CDMA2000_NeighbourCellList_item */
static int hf_lte_rrc_bandClass = -1;             /* CDMA2000_Bandclass */
static int hf_lte_rrc_frequencyList = -1;         /* CDMA2000_NeighbourCellsPerBandclass */
static int hf_lte_rrc_CDMA2000_NeighbourCellsPerBandclass_item = -1;  /* CDMA2000_NeighbourCellsPerBandclass_item */
static int hf_lte_rrc_frequency = -1;             /* INTEGER_0_2047 */
static int hf_lte_rrc_cellIdList = -1;            /* CDMA2000_CellIdList */
static int hf_lte_rrc_CDMA2000_CellIdList_item = -1;  /* CDMA2000_CellIdentity */
static int hf_lte_rrc_HRPD_BandClassList_item = -1;  /* HRPD_BandClassList_item */
static int hf_lte_rrc_hrpd_BandClass = -1;        /* CDMA2000_Bandclass */
static int hf_lte_rrc_threshX_High_01 = -1;       /* INTEGER_0_63 */
static int hf_lte_rrc_threshX_Low_01 = -1;        /* INTEGER_0_63 */
static int hf_lte_rrc_OneXRTT_BandClassList_item = -1;  /* OneXRTT_BandClassList_item */
static int hf_lte_rrc_oneXRTT_BandClass = -1;     /* CDMA2000_Bandclass */
static int hf_lte_rrc_hnbid = -1;                 /* OCTET_STRING_SIZE_1_48 */
static int hf_lte_rrc_messageIdentifier = -1;     /* BIT_STRING_SIZE_16 */
static int hf_lte_rrc_serialNumber = -1;          /* BIT_STRING_SIZE_16 */
static int hf_lte_rrc_warningType = -1;           /* OCTET_STRING_SIZE_2 */
static int hf_lte_rrc_warningSecurityInformation = -1;  /* OCTET_STRING_SIZE_50 */
static int hf_lte_rrc_warningMessageSegmentType = -1;  /* T_warningMessageSegmentType */
static int hf_lte_rrc_warningMessageSegmentNumber = -1;  /* INTEGER_0_63 */
static int hf_lte_rrc_warningMessageSegment = -1;  /* OCTET_STRING */
static int hf_lte_rrc_dataCodingScheme = -1;      /* OCTET_STRING_SIZE_1 */
static int hf_lte_rrc_antennaPortsCount = -1;     /* T_antennaPortsCount */
static int hf_lte_rrc_transmissionMode = -1;      /* T_transmissionMode */
static int hf_lte_rrc_codebookSubsetRestriction = -1;  /* T_codebookSubsetRestriction */
static int hf_lte_rrc_n2TxAntenna_tm3 = -1;       /* BIT_STRING_SIZE_2 */
static int hf_lte_rrc_n4TxAntenna_tm3 = -1;       /* BIT_STRING_SIZE_4 */
static int hf_lte_rrc_n2TxAntenna_tm4 = -1;       /* BIT_STRING_SIZE_6 */
static int hf_lte_rrc_n4TxAntenna_tm4 = -1;       /* BIT_STRING_SIZE_64 */
static int hf_lte_rrc_n2TxAntenna_tm5 = -1;       /* BIT_STRING_SIZE_4 */
static int hf_lte_rrc_n4TxAntenna_tm5 = -1;       /* BIT_STRING_SIZE_16 */
static int hf_lte_rrc_n2TxAntenna_tm6 = -1;       /* BIT_STRING_SIZE_4 */
static int hf_lte_rrc_n4TxAntenna_tm6 = -1;       /* BIT_STRING_SIZE_16 */
static int hf_lte_rrc_ue_TransmitAntennaSelection = -1;  /* T_ue_TransmitAntennaSelection */
static int hf_lte_rrc_disable = -1;               /* NULL */
static int hf_lte_rrc_enable = -1;                /* T_enable */
static int hf_lte_rrc_cqi_ReportingModeAperiodic = -1;  /* T_cqi_ReportingModeAperiodic */
static int hf_lte_rrc_nomPDSCH_RS_EPRE_Offset = -1;  /* INTEGER_M1_6 */
static int hf_lte_rrc_cqi_ReportingPeriodic = -1;  /* CQI_ReportingPeriodic */
static int hf_lte_rrc_enable_01 = -1;             /* T_enable_01 */
static int hf_lte_rrc_cqi_PUCCH_ResourceIndex = -1;  /* INTEGER_0_767 */
static int hf_lte_rrc_cqi_pmi_ConfigIndex = -1;   /* INTEGER_0_511 */
static int hf_lte_rrc_cqi_FormatIndicatorPeriodic = -1;  /* T_cqi_FormatIndicatorPeriodic */
static int hf_lte_rrc_widebandCQI = -1;           /* NULL */
static int hf_lte_rrc_subbandCQI = -1;            /* T_subbandCQI */
static int hf_lte_rrc_k = -1;                     /* INTEGER_1_4 */
static int hf_lte_rrc_ri_ConfigIndex = -1;        /* INTEGER_0_1023 */
static int hf_lte_rrc_simultaneousAckNackAndCQI = -1;  /* BOOLEAN */
static int hf_lte_rrc_ul_SpecificParameters = -1;  /* T_ul_SpecificParameters */
static int hf_lte_rrc_priority = -1;              /* INTEGER_1_16 */
static int hf_lte_rrc_prioritizedBitRate = -1;    /* T_prioritizedBitRate */
static int hf_lte_rrc_bucketSizeDuration = -1;    /* T_bucketSizeDuration */
static int hf_lte_rrc_logicalChannelGroup = -1;   /* INTEGER_0_3 */
static int hf_lte_rrc_dl_SCH_Configuration = -1;  /* T_dl_SCH_Configuration */
static int hf_lte_rrc_ul_SCH_Configuration = -1;  /* T_ul_SCH_Configuration */
static int hf_lte_rrc_maxHARQ_Tx = -1;            /* T_maxHARQ_Tx */
static int hf_lte_rrc_periodicBSR_Timer = -1;     /* T_periodicBSR_Timer */
static int hf_lte_rrc_retxBSR_Timer = -1;         /* T_retxBSR_Timer */
static int hf_lte_rrc_ttiBundling = -1;           /* BOOLEAN */
static int hf_lte_rrc_drx_Configuration = -1;     /* T_drx_Configuration */
static int hf_lte_rrc_enable_02 = -1;             /* T_enable_02 */
static int hf_lte_rrc_onDurationTimer = -1;       /* T_onDurationTimer */
static int hf_lte_rrc_drx_InactivityTimer = -1;   /* T_drx_InactivityTimer */
static int hf_lte_rrc_drx_RetransmissionTimer = -1;  /* T_drx_RetransmissionTimer */
static int hf_lte_rrc_longDRX_CycleStartOffset = -1;  /* T_longDRX_CycleStartOffset */
static int hf_lte_rrc_sf10 = -1;                  /* INTEGER_0_9 */
static int hf_lte_rrc_sf20 = -1;                  /* INTEGER_0_19 */
static int hf_lte_rrc_sf32 = -1;                  /* INTEGER_0_31 */
static int hf_lte_rrc_sf40 = -1;                  /* INTEGER_0_39 */
static int hf_lte_rrc_sf64 = -1;                  /* INTEGER_0_63 */
static int hf_lte_rrc_sf80 = -1;                  /* INTEGER_0_79 */
static int hf_lte_rrc_sf128 = -1;                 /* INTEGER_0_127 */
static int hf_lte_rrc_sf160 = -1;                 /* INTEGER_0_159 */
static int hf_lte_rrc_sf256 = -1;                 /* INTEGER_0_255 */
static int hf_lte_rrc_sf320 = -1;                 /* INTEGER_0_319 */
static int hf_lte_rrc_sf512 = -1;                 /* INTEGER_0_511 */
static int hf_lte_rrc_sf640 = -1;                 /* INTEGER_0_639 */
static int hf_lte_rrc_sf1024 = -1;                /* INTEGER_0_1023 */
static int hf_lte_rrc_sf1280 = -1;                /* INTEGER_0_1279 */
static int hf_lte_rrc_sf2048 = -1;                /* INTEGER_0_2047 */
static int hf_lte_rrc_sf2560 = -1;                /* INTEGER_0_2559 */
static int hf_lte_rrc_shortDRX = -1;              /* T_shortDRX */
static int hf_lte_rrc_enable_03 = -1;             /* T_enable_03 */
static int hf_lte_rrc_shortDRX_Cycle = -1;        /* T_shortDRX_Cycle */
static int hf_lte_rrc_drxShortCycleTimer = -1;    /* INTEGER_1_16 */
static int hf_lte_rrc_timeAlignmentTimerDedicated = -1;  /* TimeAlignmentTimer */
static int hf_lte_rrc_phr_Configuration = -1;     /* T_phr_Configuration */
static int hf_lte_rrc_enable_04 = -1;             /* T_enable_04 */
static int hf_lte_rrc_periodicPHR_Timer = -1;     /* T_periodicPHR_Timer */
static int hf_lte_rrc_prohibitPHR_Timer = -1;     /* T_prohibitPHR_Timer */
static int hf_lte_rrc_dl_PathlossChange = -1;     /* T_dl_PathlossChange */
static int hf_lte_rrc_discardTimer = -1;          /* T_discardTimer */
static int hf_lte_rrc_rlc_AM = -1;                /* T_rlc_AM */
static int hf_lte_rrc_statusReportRequired = -1;  /* BOOLEAN */
static int hf_lte_rrc_rlc_UM = -1;                /* T_rlc_UM */
static int hf_lte_rrc_pdcp_SN_Size = -1;          /* T_pdcp_SN_Size */
static int hf_lte_rrc_headerCompression = -1;     /* T_headerCompression */
static int hf_lte_rrc_notUsed = -1;               /* NULL */
static int hf_lte_rrc_rohc = -1;                  /* T_rohc */
static int hf_lte_rrc_maxCID = -1;                /* INTEGER_1_16383 */
static int hf_lte_rrc_profiles = -1;              /* T_profiles */
static int hf_lte_rrc_profile0x0001 = -1;         /* BOOLEAN */
static int hf_lte_rrc_profile0x0002 = -1;         /* BOOLEAN */
static int hf_lte_rrc_profile0x0003 = -1;         /* BOOLEAN */
static int hf_lte_rrc_profile0x0004 = -1;         /* BOOLEAN */
static int hf_lte_rrc_profile0x0006 = -1;         /* BOOLEAN */
static int hf_lte_rrc_profile0x0101 = -1;         /* BOOLEAN */
static int hf_lte_rrc_profile0x0102 = -1;         /* BOOLEAN */
static int hf_lte_rrc_profile0x0103 = -1;         /* BOOLEAN */
static int hf_lte_rrc_profile0x0104 = -1;         /* BOOLEAN */
static int hf_lte_rrc_referenceSignalPower = -1;  /* INTEGER_M60_50 */
static int hf_lte_rrc_p_b = -1;                   /* T_p_b */
static int hf_lte_rrc_p_a = -1;                   /* T_p_a */
static int hf_lte_rrc_phich_Duration = -1;        /* T_phich_Duration */
static int hf_lte_rrc_phich_Resource = -1;        /* T_phich_Resource */
static int hf_lte_rrc_pdsch_Configuration = -1;   /* PDSCH_ConfigDedicated */
static int hf_lte_rrc_pucch_Configuration = -1;   /* PUCCH_ConfigDedicated */
static int hf_lte_rrc_pusch_Configuration = -1;   /* PUSCH_ConfigDedicated */
static int hf_lte_rrc_uplinkPowerControl = -1;    /* UplinkPowerControlDedicated */
static int hf_lte_rrc_tpc_PDCCH_ConfigPUCCH = -1;  /* TPC_PDCCH_Configuration */
static int hf_lte_rrc_tpc_PDCCH_ConfigPUSCH = -1;  /* TPC_PDCCH_Configuration */
static int hf_lte_rrc_cqi_Reporting = -1;         /* CQI_Reporting */
static int hf_lte_rrc_soundingRsUl_Config = -1;   /* SoundingRsUl_ConfigDedicated */
static int hf_lte_rrc_antennaInformation = -1;    /* T_antennaInformation */
static int hf_lte_rrc_explicitValue = -1;         /* AntennaInformationDedicated */
static int hf_lte_rrc_defaultValue = -1;          /* NULL */
static int hf_lte_rrc_schedulingRequestConfig = -1;  /* SchedulingRequest_Configuration */
static int hf_lte_rrc_rootSequenceIndex = -1;     /* INTEGER_0_837 */
static int hf_lte_rrc_prach_ConfigInfo = -1;      /* PRACH_ConfigInfo */
static int hf_lte_rrc_prach_ConfigurationIndex = -1;  /* INTEGER_0_63 */
static int hf_lte_rrc_highSpeedFlag = -1;         /* BOOLEAN */
static int hf_lte_rrc_zeroCorrelationZoneConfig = -1;  /* INTEGER_0_15 */
static int hf_lte_rrc_prach_FrequencyOffset = -1;  /* INTEGER_0_104 */
static int hf_lte_rrc_deltaPUCCH_Shift = -1;      /* T_deltaPUCCH_Shift */
static int hf_lte_rrc_nRB_CQI = -1;               /* INTEGER_0_63 */
static int hf_lte_rrc_nCS_AN = -1;                /* INTEGER_0_7 */
static int hf_lte_rrc_n1PUCCH_AN = -1;            /* INTEGER_0_2047 */
static int hf_lte_rrc_ackNackRepetition = -1;     /* T_ackNackRepetition */
static int hf_lte_rrc_enable_05 = -1;             /* T_enable_05 */
static int hf_lte_rrc_repetitionFactor = -1;      /* T_repetitionFactor */
static int hf_lte_rrc_tddAckNackFeedbackMode = -1;  /* T_tddAckNackFeedbackMode */
static int hf_lte_rrc_pusch_ConfigBasic = -1;     /* T_pusch_ConfigBasic */
static int hf_lte_rrc_n_SB = -1;                  /* T_n_SB */
static int hf_lte_rrc_hoppingMode = -1;           /* T_hoppingMode */
static int hf_lte_rrc_pusch_HoppingOffset = -1;   /* INTEGER_0_63 */
static int hf_lte_rrc_enable64Qam = -1;           /* BOOLEAN */
static int hf_lte_rrc_ul_ReferenceSignalsPUSCH = -1;  /* UL_ReferenceSignalsPUSCH */
static int hf_lte_rrc_deltaOffset_ACK_Index = -1;  /* INTEGER_0_15 */
static int hf_lte_rrc_deltaOffset_RI_Index = -1;  /* INTEGER_0_15 */
static int hf_lte_rrc_deltaOffset_CQI_Index = -1;  /* INTEGER_0_15 */
static int hf_lte_rrc_ra_PreambleIndex = -1;      /* INTEGER_1_64 */
static int hf_lte_rrc_ra_PRACH_MaskIndex = -1;    /* INTEGER_0_15 */
static int hf_lte_rrc_preambleInformation = -1;   /* T_preambleInformation */
static int hf_lte_rrc_numberOfRA_Preambles = -1;  /* T_numberOfRA_Preambles */
static int hf_lte_rrc_preamblesGroupAConfig = -1;  /* T_preamblesGroupAConfig */
static int hf_lte_rrc_sizeOfRA_PreamblesGroupA = -1;  /* T_sizeOfRA_PreamblesGroupA */
static int hf_lte_rrc_messageSizeGroupA = -1;     /* T_messageSizeGroupA */
static int hf_lte_rrc_messagePowerOffsetGroupB = -1;  /* T_messagePowerOffsetGroupB */
static int hf_lte_rrc_powerRampingParameters = -1;  /* T_powerRampingParameters */
static int hf_lte_rrc_powerRampingStep = -1;      /* T_powerRampingStep */
static int hf_lte_rrc_preambleInitialReceivedTargetPower = -1;  /* T_preambleInitialReceivedTargetPower */
static int hf_lte_rrc_ra_SupervisionInformation = -1;  /* T_ra_SupervisionInformation */
static int hf_lte_rrc_preambleTransMax = -1;      /* T_preambleTransMax */
static int hf_lte_rrc_ra_ResponseWindowSize = -1;  /* T_ra_ResponseWindowSize */
static int hf_lte_rrc_mac_ContentionResolutionTimer = -1;  /* T_mac_ContentionResolutionTimer */
static int hf_lte_rrc_maxHARQ_Msg3Tx = -1;        /* INTEGER_1_8 */
static int hf_lte_rrc_rach_Configuration = -1;    /* RACH_ConfigCommon */
static int hf_lte_rrc_bcch_Configuration = -1;    /* BCCH_Configuration */
static int hf_lte_rrc_pcch_Configuration = -1;    /* PCCH_Configuration */
static int hf_lte_rrc_prach_Configuration = -1;   /* PRACH_ConfigurationSIB */
static int hf_lte_rrc_pdsch_Configuration_01 = -1;  /* PDSCH_ConfigCommon */
static int hf_lte_rrc_pusch_Configuration_01 = -1;  /* PUSCH_ConfigCommon */
static int hf_lte_rrc_pucch_Configuration_01 = -1;  /* PUCCH_ConfigCommon */
static int hf_lte_rrc_soundingRsUl_Config_01 = -1;  /* SoundingRsUl_ConfigCommon */
static int hf_lte_rrc_uplinkPowerControl_01 = -1;  /* UplinkPowerControlCommon */
static int hf_lte_rrc_ul_CyclicPrefixLength = -1;  /* UL_CyclicPrefixLength */
static int hf_lte_rrc_prach_Configuration_01 = -1;  /* PRACH_Configuration */
static int hf_lte_rrc_antennaInformationCommon = -1;  /* AntennaInformationCommon */
static int hf_lte_rrc_modificationPeriodCoeff = -1;  /* T_modificationPeriodCoeff */
static int hf_lte_rrc_defaultPagingCycle = -1;    /* T_defaultPagingCycle */
static int hf_lte_rrc_nB = -1;                    /* T_nB */
static int hf_lte_rrc_srb_ToAddModifyList = -1;   /* SRB_ToAddModifyList */
static int hf_lte_rrc_drb_ToAddModifyList = -1;   /* DRB_ToAddModifyList */
static int hf_lte_rrc_drb_ToReleaseList = -1;     /* DRB_ToReleaseList */
static int hf_lte_rrc_mac_MainConfig = -1;        /* T_mac_MainConfig */
static int hf_lte_rrc_explicitValue_01 = -1;      /* MAC_MainConfiguration */
static int hf_lte_rrc_sps_Configuration = -1;     /* SPS_Configuration */
static int hf_lte_rrc_physicalConfigDedicated = -1;  /* PhysicalConfigDedicated */
static int hf_lte_rrc_SRB_ToAddModifyList_item = -1;  /* SRB_ToAddModifyList_item */
static int hf_lte_rrc_srb_Identity = -1;          /* INTEGER_1_2 */
static int hf_lte_rrc_rlc_Configuration = -1;     /* T_rlc_Configuration */
static int hf_lte_rrc_explicitValue_02 = -1;      /* RLC_Configuration */
static int hf_lte_rrc_logicalChannelConfig = -1;  /* T_logicalChannelConfig */
static int hf_lte_rrc_explicitValue_03 = -1;      /* LogicalChannelConfig */
static int hf_lte_rrc_DRB_ToAddModifyList_item = -1;  /* DRB_ToAddModifyList_item */
static int hf_lte_rrc_eps_BearerIdentity = -1;    /* INTEGER_0_15 */
static int hf_lte_rrc_pdcp_Configuration = -1;    /* PDCP_Configuration */
static int hf_lte_rrc_rlc_Configuration_01 = -1;  /* RLC_Configuration */
static int hf_lte_rrc_logicalChannelIdentity = -1;  /* INTEGER_3_10 */
static int hf_lte_rrc_logicalChannelConfig_01 = -1;  /* LogicalChannelConfig */
static int hf_lte_rrc_DRB_ToReleaseList_item = -1;  /* DRB_ToReleaseList_item */
static int hf_lte_rrc_am = -1;                    /* T_am */
static int hf_lte_rrc_ul_AM_RLC = -1;             /* UL_AM_RLC */
static int hf_lte_rrc_dl_AM_RLC = -1;             /* DL_AM_RLC */
static int hf_lte_rrc_um_Bi_Directional = -1;     /* T_um_Bi_Directional */
static int hf_lte_rrc_ul_UM_RLC = -1;             /* UL_UM_RLC */
static int hf_lte_rrc_dl_UM_RLC = -1;             /* DL_UM_RLC */
static int hf_lte_rrc_um_Uni_Directional_UL = -1;  /* T_um_Uni_Directional_UL */
static int hf_lte_rrc_um_Uni_Directional_DL = -1;  /* T_um_Uni_Directional_DL */
static int hf_lte_rrc_t_PollRetransmit = -1;      /* T_PollRetransmit */
static int hf_lte_rrc_pollPDU = -1;               /* PollPDU */
static int hf_lte_rrc_pollByte = -1;              /* PollByte */
static int hf_lte_rrc_maxRetxThreshold = -1;      /* T_maxRetxThreshold */
static int hf_lte_rrc_t_Reordering = -1;          /* T_Reordering */
static int hf_lte_rrc_t_StatusProhibit = -1;      /* T_StatusProhibit */
static int hf_lte_rrc_sn_FieldLength = -1;        /* SN_FieldLength */
static int hf_lte_rrc_enable_06 = -1;             /* T_enable_06 */
static int hf_lte_rrc_sr_PUCCH_ResourceIndex = -1;  /* INTEGER_0_2047 */
static int hf_lte_rrc_sr_ConfigurationIndex = -1;  /* INTEGER_0_155 */
static int hf_lte_rrc_dsr_TransMax = -1;          /* T_dsr_TransMax */
static int hf_lte_rrc_srsBandwidthConfiguration = -1;  /* T_srsBandwidthConfiguration */
static int hf_lte_rrc_srsSubframeConfiguration = -1;  /* T_srsSubframeConfiguration */
static int hf_lte_rrc_ackNackSrsSimultaneousTransmission = -1;  /* BOOLEAN */
static int hf_lte_rrc_srsMaxUpPts = -1;           /* BOOLEAN */
static int hf_lte_rrc_enable_07 = -1;             /* T_enable_07 */
static int hf_lte_rrc_srsBandwidth = -1;          /* T_srsBandwidth */
static int hf_lte_rrc_srsHoppingBandwidth = -1;   /* T_srsHoppingBandwidth */
static int hf_lte_rrc_frequencyDomainPosition = -1;  /* INTEGER_0_23 */
static int hf_lte_rrc_duration = -1;              /* BOOLEAN */
static int hf_lte_rrc_srs_ConfigurationIndex = -1;  /* INTEGER_0_1023 */
static int hf_lte_rrc_transmissionComb = -1;      /* INTEGER_0_1 */
static int hf_lte_rrc_cyclicShift = -1;           /* T_cyclicShift */
static int hf_lte_rrc_semiPersistSchedC_RNTI = -1;  /* C_RNTI */
static int hf_lte_rrc_sps_ConfigurationDL = -1;   /* SPS_ConfigurationDL */
static int hf_lte_rrc_sps_ConfigurationUL = -1;   /* SPS_ConfigurationUL */
static int hf_lte_rrc_enable_08 = -1;             /* T_enable_08 */
static int hf_lte_rrc_semiPersistSchedIntervalDL = -1;  /* T_semiPersistSchedIntervalDL */
static int hf_lte_rrc_numberOfConfSPS_Processes = -1;  /* INTEGER_1_8 */
static int hf_lte_rrc_n1Pucch_AN_Persistent = -1;  /* INTEGER_0_2047 */
static int hf_lte_rrc_enable_09 = -1;             /* T_enable_09 */
static int hf_lte_rrc_semiPersistSchedIntervalUL = -1;  /* T_semiPersistSchedIntervalUL */
static int hf_lte_rrc_implicitReleaseAfter = -1;  /* T_implicitReleaseAfter */
static int hf_lte_rrc_p0_Persistent = -1;         /* T_p0_Persistent */
static int hf_lte_rrc_p0_NominalPUSCH_Persistent = -1;  /* INTEGER_M126_24 */
static int hf_lte_rrc_p0_UePUSCH_Persistent = -1;  /* INTEGER_M8_7 */
static int hf_lte_rrc_subframeAssignment = -1;    /* T_subframeAssignment */
static int hf_lte_rrc_specialSubframePatterns = -1;  /* T_specialSubframePatterns */
static int hf_lte_rrc_indexOfFormat3 = -1;        /* INTEGER_1_15 */
static int hf_lte_rrc_indexOfFormat3A = -1;       /* INTEGER_1_31 */
static int hf_lte_rrc_enable_10 = -1;             /* T_enable_10 */
static int hf_lte_rrc_tpc_RNTI = -1;              /* BIT_STRING_SIZE_16 */
static int hf_lte_rrc_tpc_Index = -1;             /* TPC_Index */
static int hf_lte_rrc_groupHoppingEnabled = -1;   /* BOOLEAN */
static int hf_lte_rrc_groupAssignmentPUSCH = -1;  /* INTEGER_0_29 */
static int hf_lte_rrc_sequenceHoppingEnabled = -1;  /* BOOLEAN */
static int hf_lte_rrc_cyclicShift_01 = -1;        /* INTEGER_0_7 */
static int hf_lte_rrc_p0_NominalPUSCH = -1;       /* INTEGER_M126_24 */
static int hf_lte_rrc_alpha = -1;                 /* T_alpha */
static int hf_lte_rrc_p0_NominalPUCCH = -1;       /* INTEGER_M127_M96 */
static int hf_lte_rrc_deltaFList_PUCCH = -1;      /* DeltaFList_PUCCH */
static int hf_lte_rrc_deltaPreambleMsg3 = -1;     /* INTEGER_M1_6 */
static int hf_lte_rrc_p0_UePUSCH = -1;            /* INTEGER_M8_7 */
static int hf_lte_rrc_deltaMCS_Enabled = -1;      /* T_deltaMCS_Enabled */
static int hf_lte_rrc_accumulationEnabled = -1;   /* BOOLEAN */
static int hf_lte_rrc_p0_uePUCCH = -1;            /* INTEGER_M8_7 */
static int hf_lte_rrc_pSRS_Offset = -1;           /* INTEGER_0_15 */
static int hf_lte_rrc_deltaF_PUCCH_Format1 = -1;  /* T_deltaF_PUCCH_Format1 */
static int hf_lte_rrc_deltaF_PUCCH_Format1b = -1;  /* T_deltaF_PUCCH_Format1b */
static int hf_lte_rrc_deltaF_PUCCH_Format2 = -1;  /* T_deltaF_PUCCH_Format2 */
static int hf_lte_rrc_deltaF_PUCCH_Format2a = -1;  /* T_deltaF_PUCCH_Format2a */
static int hf_lte_rrc_deltaF_PUCCH_Format2b = -1;  /* T_deltaF_PUCCH_Format2b */
static int hf_lte_rrc_integrityProtAlgorithm = -1;  /* IntegrityProtAlgorithm */
static int hf_lte_rrc_cipheringAlgorithm = -1;    /* CipheringAlgorithm */
static int hf_lte_rrc_keyChangeIndicator = -1;    /* BOOLEAN */
static int hf_lte_rrc_cdma2000_CarrierInfo = -1;  /* CDMA2000_CarrierInfo */
static int hf_lte_rrc_pnOffset = -1;              /* CDMA2000_CellIdentity */
static int hf_lte_rrc_cdma_EUTRA_Synchronisation = -1;  /* BOOLEAN */
static int hf_lte_rrc_cdma_SystemTime = -1;       /* T_cdma_SystemTime */
static int hf_lte_rrc_cdma_SynchronousSystemTime = -1;  /* BIT_STRING_SIZE_39 */
static int hf_lte_rrc_cdma_AsynchronousSystemTime = -1;  /* BIT_STRING_SIZE_49 */
static int hf_lte_rrc_CellIndexList_item = -1;    /* CellIndexList_item */
static int hf_lte_rrc_cellIndex = -1;             /* INTEGER_1_maxCellMeas */
static int hf_lte_rrc_timeToTriggerSF_Medium = -1;  /* T_timeToTriggerSF_Medium */
static int hf_lte_rrc_timeToTriggerSF_High = -1;  /* T_timeToTriggerSF_High */
static int hf_lte_rrc_earfcn_DL = -1;             /* INTEGER_0_maxEARFCN */
static int hf_lte_rrc_earfcn_UL = -1;             /* EUTRA_DL_CarrierFreq */
static int hf_lte_rrc_arfcn = -1;                 /* GERAN_ARFCN_Value */
static int hf_lte_rrc_bandIndicator = -1;         /* GERAN_BandIndicator */
static int hf_lte_rrc_startingARFCN = -1;         /* GERAN_ARFCN_Value */
static int hf_lte_rrc_followingARFCNs = -1;       /* T_followingARFCNs */
static int hf_lte_rrc_explicitListOfARFCNs = -1;  /* ExplicitListOfARFCNs */
static int hf_lte_rrc_equallySpacedARFCNs = -1;   /* T_equallySpacedARFCNs */
static int hf_lte_rrc_arfcn_Spacing = -1;         /* INTEGER_1_8 */
static int hf_lte_rrc_numberOfFollowingARFCNs = -1;  /* INTEGER_0_31 */
static int hf_lte_rrc_variableBitMapOfARFCNs = -1;  /* OCTET_STRING_SIZE_1_16 */
static int hf_lte_rrc_ExplicitListOfARFCNs_item = -1;  /* GERAN_ARFCN_Value */
static int hf_lte_rrc_networkColourCode = -1;     /* BIT_STRING_SIZE_3 */
static int hf_lte_rrc_baseStationColourCode = -1;  /* BIT_STRING_SIZE_3 */
static int hf_lte_rrc_utra_CellIdentity = -1;     /* BIT_STRING_SIZE_28 */
static int hf_lte_rrc_locationAreaCode = -1;      /* BIT_STRING_SIZE_16 */
static int hf_lte_rrc_geran_CellIdentity = -1;    /* BIT_STRING_SIZE_16 */
static int hf_lte_rrc_globalCellId_oneXRTT = -1;  /* BIT_STRING_SIZE_47 */
static int hf_lte_rrc_globalCellId_HRPD = -1;     /* BIT_STRING_SIZE_128 */
static int hf_lte_rrc_hrpd_PreRegistrationAllowed = -1;  /* BOOLEAN */
static int hf_lte_rrc_hrpd_PreRegistrationZoneId = -1;  /* INTEGER_0_255 */
static int hf_lte_rrc_hrpd_SecondaryPreRegistrationZoneIdList = -1;  /* HRPD_SecondaryPreRegistrationZoneIdList */
static int hf_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList_item = -1;  /* HRPD_SecondaryPreRegistrationZoneIdList_item */
static int hf_lte_rrc_hrpd_SecondaryPreRegistrationZoneId = -1;  /* INTEGER_0_255 */
static int hf_lte_rrc_targetCellIdentity = -1;    /* PhysicalCellIdentity */
static int hf_lte_rrc_eutra_CarrierFreq_01 = -1;  /* EUTRA_CarrierFreq */
static int hf_lte_rrc_eutra_CarrierBandwidth = -1;  /* EUTRA_CarrierBandwidth */
static int hf_lte_rrc_t304_01 = -1;               /* T_t304_01 */
static int hf_lte_rrc_newUE_Identity = -1;        /* C_RNTI */
static int hf_lte_rrc_radioResourceConfigCommon_01 = -1;  /* RadioResourceConfigCommon */
static int hf_lte_rrc_rach_ConfigDedicated = -1;  /* RACH_ConfigDedicated */
static int hf_lte_rrc_dl_Bandwidth_01 = -1;       /* T_dl_Bandwidth_01 */
static int hf_lte_rrc_ul_Bandwidth_01 = -1;       /* T_ul_Bandwidth_01 */
static int hf_lte_rrc_t_Evalulation = -1;         /* T_t_Evalulation */
static int hf_lte_rrc_t_HystNormal = -1;          /* T_t_HystNormal */
static int hf_lte_rrc_n_CellChangeMedium = -1;    /* INTEGER_1_16 */
static int hf_lte_rrc_n_CellChangeHigh = -1;      /* INTEGER_1_16 */
static int hf_lte_rrc_oneXRTT_CSFB_RegistrationAllowed = -1;  /* BOOLEAN */
static int hf_lte_rrc_oneXRTT_RegistrationParameters = -1;  /* OneXRTT_RegistrationParameters */
static int hf_lte_rrc_oneXRTT_SID = -1;           /* BIT_STRING_SIZE_15 */
static int hf_lte_rrc_oneXRTT_NID = -1;           /* BIT_STRING_SIZE_16 */
static int hf_lte_rrc_oneXRTT_MultipleSID = -1;   /* BOOLEAN */
static int hf_lte_rrc_oneXRTT_MultipleNID = -1;   /* BOOLEAN */
static int hf_lte_rrc_oneXRTT_HomeReg = -1;       /* BOOLEAN */
static int hf_lte_rrc_oneXRTT_ForeignSIDReg = -1;  /* BOOLEAN */
static int hf_lte_rrc_oneXRTT_ForeignNIDReg = -1;  /* BOOLEAN */
static int hf_lte_rrc_oneXRTT_ParameterReg = -1;  /* BOOLEAN */
static int hf_lte_rrc_oneXRTT_RegistrationPeriod = -1;  /* BIT_STRING_SIZE_7 */
static int hf_lte_rrc_oneXRTT_RegistrationZone = -1;  /* BIT_STRING_SIZE_12 */
static int hf_lte_rrc_oneXRTT_TotalZone = -1;     /* BIT_STRING_SIZE_3 */
static int hf_lte_rrc_oneXRTT_ZoneTimer = -1;     /* BIT_STRING_SIZE_3 */
static int hf_lte_rrc_singlePCI = -1;             /* PhysicalCellIdentity */
static int hf_lte_rrc_rangeOfPCI = -1;            /* T_rangeOfPCI */
static int hf_lte_rrc_startPCI = -1;              /* PhysicalCellIdentity */
static int hf_lte_rrc_rangePCI = -1;              /* T_rangePCI */
static int hf_lte_rrc_mcc = -1;                   /* MCC */
static int hf_lte_rrc_mnc = -1;                   /* MNC */
static int hf_lte_rrc_MCC_item = -1;              /* MCC_MNC_Digit */
static int hf_lte_rrc_MNC_item = -1;              /* MCC_MNC_Digit */
static int hf_lte_rrc_primaryScramblingCode = -1;  /* INTEGER_0_511 */
static int hf_lte_rrc_cellParametersID = -1;      /* INTEGER_0_127 */
static int hf_lte_rrc_uarfcn_DL = -1;             /* INTEGER_0_16383 */
static int hf_lte_rrc_gapActivation = -1;         /* T_gapActivation */
static int hf_lte_rrc_activate = -1;              /* T_activate */
static int hf_lte_rrc_gapPattern = -1;            /* T_gapPattern */
static int hf_lte_rrc_gp1 = -1;                   /* T_gp1 */
static int hf_lte_rrc_gapOffset = -1;             /* INTEGER_0_39 */
static int hf_lte_rrc_gp2 = -1;                   /* T_gp2 */
static int hf_lte_rrc_gapOffset_01 = -1;          /* INTEGER_0_79 */
static int hf_lte_rrc_deactivate = -1;            /* NULL */
static int hf_lte_rrc_cdma2000_SearchWindowSize = -1;  /* INTEGER_0_15 */
static int hf_lte_rrc_offsetFreq = -1;            /* T_offsetFreq */
static int hf_lte_rrc_cellsToRemoveList = -1;     /* CellIndexList */
static int hf_lte_rrc_cellsToAddModifyList = -1;  /* CDMA2000_CellsToAddModifyList */
static int hf_lte_rrc_cellForWhichToReportCGI = -1;  /* CDMA2000_CellIdentity */
static int hf_lte_rrc_CDMA2000_CellsToAddModifyList_item = -1;  /* CDMA2000_CellsToAddModifyList_item */
static int hf_lte_rrc_cellIdentity_01 = -1;       /* CDMA2000_CellIdentity */
static int hf_lte_rrc_eutra_CarrierInfo = -1;     /* EUTRA_DL_CarrierFreq */
static int hf_lte_rrc_offsetFreq_01 = -1;         /* T_offsetFreq_01 */
static int hf_lte_rrc_cellsToAddModifyList_01 = -1;  /* NeighCellsToAddModifyList */
static int hf_lte_rrc_blackListedCellsToRemoveList = -1;  /* CellIndexList */
static int hf_lte_rrc_blackListedCellsToAddModifyList = -1;  /* BlackListedCellsToAddModifyList */
static int hf_lte_rrc_cellForWhichToReportCGI_01 = -1;  /* PhysicalCellIdentity */
static int hf_lte_rrc_NeighCellsToAddModifyList_item = -1;  /* NeighCellsToAddModifyList_item */
static int hf_lte_rrc_cellIdentity_02 = -1;       /* PhysicalCellIdentity */
static int hf_lte_rrc_cellIndividualOffset = -1;  /* T_cellIndividualOffset */
static int hf_lte_rrc_BlackListedCellsToAddModifyList_item = -1;  /* BlackListedCellsToAddModifyList_item */
static int hf_lte_rrc_cellIdentityAndRange = -1;  /* PhysicalCellIdentityAndRange */
static int hf_lte_rrc_geran_MeasFrequencyList = -1;  /* GERAN_MeasFrequencyList */
static int hf_lte_rrc_offsetFreq_02 = -1;         /* INTEGER_M15_15 */
static int hf_lte_rrc_cellForWhichToReportCGI_02 = -1;  /* GERAN_CellIdentity */
static int hf_lte_rrc_GERAN_MeasFrequencyList_item = -1;  /* GERAN_CarrierFreqList */
static int hf_lte_rrc_cellsToAddModifyList_02 = -1;  /* T_cellsToAddModifyList */
static int hf_lte_rrc_cellsToAddModifyListUTRA_FDD = -1;  /* UTRA_FDD_CellsToAddModifyList */
static int hf_lte_rrc_cellsToAddModifyListUTRA_TDD = -1;  /* UTRA_TDD_CellsToAddModifyList */
static int hf_lte_rrc_cellForWhichToReportCGI_03 = -1;  /* T_cellForWhichToReportCGI */
static int hf_lte_rrc_utra_FDD_01 = -1;           /* UTRA_FDD_CellIdentity */
static int hf_lte_rrc_utra_TDD_01 = -1;           /* UTRA_TDD_CellIdentity */
static int hf_lte_rrc_UTRA_FDD_CellsToAddModifyList_item = -1;  /* UTRA_FDD_CellsToAddModifyList_item */
static int hf_lte_rrc_utra_FDD_CellIdentity = -1;  /* UTRA_FDD_CellIdentity */
static int hf_lte_rrc_UTRA_TDD_CellsToAddModifyList_item = -1;  /* UTRA_TDD_CellsToAddModifyList_item */
static int hf_lte_rrc_utra_TDD_CellIdentity = -1;  /* UTRA_TDD_CellIdentity */
static int hf_lte_rrc_measId = -1;                /* MeasId */
static int hf_lte_rrc_measResultServing = -1;     /* T_measResultServing */
static int hf_lte_rrc_rsrpResult = -1;            /* RSRP_Range */
static int hf_lte_rrc_rsrqResult = -1;            /* RSRQ_Range */
static int hf_lte_rrc_neighbouringMeasResults = -1;  /* T_neighbouringMeasResults */
static int hf_lte_rrc_measResultListEUTRA = -1;   /* MeasResultListEUTRA */
static int hf_lte_rrc_measResultListUTRA = -1;    /* MeasResultListUTRA */
static int hf_lte_rrc_measResultListGERAN = -1;   /* MeasResultListGERAN */
static int hf_lte_rrc_measResultsCDMA2000 = -1;   /* MeasResultsCDMA2000 */
static int hf_lte_rrc_MeasResultListEUTRA_item = -1;  /* MeasResultListEUTRA_item */
static int hf_lte_rrc_globalCellIdentity = -1;    /* T_globalCellIdentity */
static int hf_lte_rrc_globalCellID_EUTRA = -1;    /* GlobalCellId_EUTRA */
static int hf_lte_rrc_tac_ID = -1;                /* TrackingAreaCode */
static int hf_lte_rrc_plmn_IdentityList_01 = -1;  /* PLMN_IdentityList2 */
static int hf_lte_rrc_measResult = -1;            /* T_measResult */
static int hf_lte_rrc_MeasResultListUTRA_item = -1;  /* MeasResultListUTRA_item */
static int hf_lte_rrc_physicalCellIdentity_01 = -1;  /* T_physicalCellIdentity */
static int hf_lte_rrc_cellIentityFDD = -1;        /* UTRA_FDD_CellIdentity */
static int hf_lte_rrc_cellIentityTDD = -1;        /* UTRA_TDD_CellIdentity */
static int hf_lte_rrc_globalCellIdentity_01 = -1;  /* T_globalCellIdentity_01 */
static int hf_lte_rrc_globalcellID_UTRA = -1;     /* GlobalCellId_UTRA */
static int hf_lte_rrc_lac_Id = -1;                /* BIT_STRING_SIZE_16 */
static int hf_lte_rrc_rac_Id = -1;                /* BIT_STRING_SIZE_8 */
static int hf_lte_rrc_measResult_01 = -1;         /* T_measResult_01 */
static int hf_lte_rrc_mode = -1;                  /* T_mode */
static int hf_lte_rrc_fdd = -1;                   /* T_fdd */
static int hf_lte_rrc_cpich_RSCP = -1;            /* INTEGER_M5_91 */
static int hf_lte_rrc_cpich_EcN0 = -1;            /* INTEGER_0_49 */
static int hf_lte_rrc_tdd = -1;                   /* T_tdd */
static int hf_lte_rrc_pccpch_RSCP = -1;           /* INTEGER_M5_91 */
static int hf_lte_rrc_MeasResultListGERAN_item = -1;  /* MeasResultListGERAN_item */
static int hf_lte_rrc_physicalCellIdentity_02 = -1;  /* T_physicalCellIdentity_01 */
static int hf_lte_rrc_geran_CellIdentity_01 = -1;  /* GERAN_CellIdentity */
static int hf_lte_rrc_globalCellIdentity_02 = -1;  /* T_globalCellIdentity_02 */
static int hf_lte_rrc_globalcellID_GERAN = -1;    /* GlobalCellId_GERAN */
static int hf_lte_rrc_measResult_02 = -1;         /* T_measResult_02 */
static int hf_lte_rrc_rssi = -1;                  /* BIT_STRING_SIZE_6 */
static int hf_lte_rrc_hrpdPreRegistrationStatus = -1;  /* BOOLEAN */
static int hf_lte_rrc_measResultListCDMA2000 = -1;  /* MeasResultListCDMA2000 */
static int hf_lte_rrc_MeasResultListCDMA2000_item = -1;  /* MeasResultListCDMA2000_item */
static int hf_lte_rrc_physicalCellIdentity_03 = -1;  /* CDMA2000_CellIdentity */
static int hf_lte_rrc_globalCellIdentity_03 = -1;  /* GlobalCellId_CDMA2000 */
static int hf_lte_rrc_measResult_03 = -1;         /* T_measResult_03 */
static int hf_lte_rrc_pilotPnPhase = -1;          /* INTEGER_0_32767 */
static int hf_lte_rrc_pilotStrength = -1;         /* INTEGER_0_63 */
static int hf_lte_rrc_PLMN_IdentityList2_item = -1;  /* PLMN_IdentityList2_item */
static int hf_lte_rrc_measObjectToRemoveList = -1;  /* MeasObjectToRemoveList */
static int hf_lte_rrc_measObjectToAddModifyList = -1;  /* MeasObjectToAddModifyList */
static int hf_lte_rrc_reportConfigToRemoveList = -1;  /* ReportConfigToRemoveList */
static int hf_lte_rrc_reportConfigToAddModifyList = -1;  /* ReportConfigToAddModifyList */
static int hf_lte_rrc_measIdToRemoveList = -1;    /* MeasIdToRemoveList */
static int hf_lte_rrc_measIdToAddModifyList = -1;  /* MeasIdToAddModifyList */
static int hf_lte_rrc_quantityConfig = -1;        /* QuantityConfig */
static int hf_lte_rrc_measGapConfig = -1;         /* MeasGapConfig */
static int hf_lte_rrc_s_Measure = -1;             /* RSRP_Range */
static int hf_lte_rrc_speedDependentParameters = -1;  /* T_speedDependentParameters */
static int hf_lte_rrc_enable_11 = -1;             /* T_enable_11 */
static int hf_lte_rrc_speedDependentScalingParameters_06 = -1;  /* ConnectedModeSpeedDependentScalingParameters */
static int hf_lte_rrc_MeasIdToRemoveList_item = -1;  /* MeasIdToRemoveList_item */
static int hf_lte_rrc_MeasIdToAddModifyList_item = -1;  /* MeasIdToAddModifyList_item */
static int hf_lte_rrc_measObjectId = -1;          /* MeasObjectId */
static int hf_lte_rrc_reportConfigId = -1;        /* ReportConfigId */
static int hf_lte_rrc_MeasObjectToRemoveList_item = -1;  /* MeasObjectToRemoveList_item */
static int hf_lte_rrc_MeasObjectToAddModifyList_item = -1;  /* MeasObjectToAddModifyList_item */
static int hf_lte_rrc_measObject = -1;            /* T_measObject */
static int hf_lte_rrc_measObjectEUTRA = -1;       /* MeasObjectEUTRA */
static int hf_lte_rrc_measObjectUTRA = -1;        /* MeasObjectUTRA */
static int hf_lte_rrc_measObjectGERAN = -1;       /* MeasObjectGERAN */
static int hf_lte_rrc_measObjectCDMA2000 = -1;    /* MeasObjectCDMA2000 */
static int hf_lte_rrc_ReportConfigToRemoveList_item = -1;  /* ReportConfigToRemoveList_item */
static int hf_lte_rrc_ReportConfigToAddModifyList_item = -1;  /* ReportConfigToAddModifyList_item */
static int hf_lte_rrc_reportConfig = -1;          /* T_reportConfig */
static int hf_lte_rrc_reportConfigEUTRA = -1;     /* ReportConfigEUTRA */
static int hf_lte_rrc_reportConfigInterRAT = -1;  /* ReportConfigInterRAT */
static int hf_lte_rrc_quantityConfigEUTRA = -1;   /* QuantityConfigEUTRA */
static int hf_lte_rrc_quantityConfigUTRA = -1;    /* QuantityConfigUTRA */
static int hf_lte_rrc_quantityConfigGERAN = -1;   /* QuantityConfigGERAN */
static int hf_lte_rrc_quantityConfigCDMA2000 = -1;  /* QuantityConfigCDMA2000 */
static int hf_lte_rrc_filterCoefficientRSRP = -1;  /* FilterCoefficient */
static int hf_lte_rrc_filterCoefficientRSRQ = -1;  /* FilterCoefficient */
static int hf_lte_rrc_measQuantityUTRA_FDD = -1;  /* T_measQuantityUTRA_FDD */
static int hf_lte_rrc_measQuantityUTRA_TDD = -1;  /* T_measQuantityUTRA_TDD */
static int hf_lte_rrc_filterCoefficient = -1;     /* FilterCoefficient */
static int hf_lte_rrc_measQuantityGERAN = -1;     /* T_measQuantityGERAN */
static int hf_lte_rrc_measQuantityCDMA2000 = -1;  /* T_measQuantityCDMA2000 */
static int hf_lte_rrc_triggerType = -1;           /* T_triggerType */
static int hf_lte_rrc_event = -1;                 /* T_event */
static int hf_lte_rrc_eventId = -1;               /* T_eventId */
static int hf_lte_rrc_eventA1 = -1;               /* T_eventA1 */
static int hf_lte_rrc_a1_Threshold = -1;          /* ThresholdEUTRA */
static int hf_lte_rrc_eventA2 = -1;               /* T_eventA2 */
static int hf_lte_rrc_a2_Threshold = -1;          /* ThresholdEUTRA */
static int hf_lte_rrc_eventA3 = -1;               /* T_eventA3 */
static int hf_lte_rrc_a3_Offset = -1;             /* INTEGER_M30_30 */
static int hf_lte_rrc_reportOnLeave = -1;         /* BOOLEAN */
static int hf_lte_rrc_eventA4 = -1;               /* T_eventA4 */
static int hf_lte_rrc_a4_Threshold = -1;          /* ThresholdEUTRA */
static int hf_lte_rrc_eventA5 = -1;               /* T_eventA5 */
static int hf_lte_rrc_a5_Threshold1 = -1;         /* ThresholdEUTRA */
static int hf_lte_rrc_a5_Threshold2 = -1;         /* ThresholdEUTRA */
static int hf_lte_rrc_hysteresis = -1;            /* INTEGER_0_30 */
static int hf_lte_rrc_timeToTrigger = -1;         /* TimeToTrigger */
static int hf_lte_rrc_periodical = -1;            /* T_periodical */
static int hf_lte_rrc_purpose_01 = -1;            /* T_purpose_01 */
static int hf_lte_rrc_reportStrongestCells = -1;  /* NULL */
static int hf_lte_rrc_reportCGI = -1;             /* NULL */
static int hf_lte_rrc_triggerQuantity = -1;       /* T_triggerQuantity */
static int hf_lte_rrc_reportQuantity = -1;        /* T_reportQuantity */
static int hf_lte_rrc_maxReportCells = -1;        /* INTEGER_1_maxCellReport */
static int hf_lte_rrc_reportInterval = -1;        /* ReportInterval */
static int hf_lte_rrc_reportAmount = -1;          /* T_reportAmount */
static int hf_lte_rrc_threshold_RSRP = -1;        /* RSRP_Range */
static int hf_lte_rrc_threshold_RSRQ = -1;        /* RSRQ_Range */
static int hf_lte_rrc_triggerType_01 = -1;        /* T_triggerType_01 */
static int hf_lte_rrc_event_01 = -1;              /* T_event_01 */
static int hf_lte_rrc_eventId_01 = -1;            /* T_eventId_01 */
static int hf_lte_rrc_eventB1 = -1;               /* T_eventB1 */
static int hf_lte_rrc_b1_Threshold = -1;          /* T_b1_Threshold */
static int hf_lte_rrc_b1_Threshold_CDMA2000 = -1;  /* INTEGER_0_63 */
static int hf_lte_rrc_b1_Threshold_UTRA = -1;     /* ThresholdUTRA */
static int hf_lte_rrc_b1_Threshold_GERAN = -1;    /* ThresholdGERAN */
static int hf_lte_rrc_eventB2 = -1;               /* T_eventB2 */
static int hf_lte_rrc_b2_Threshold1 = -1;         /* ThresholdEUTRA */
static int hf_lte_rrc_b2_Threshold2 = -1;         /* T_b2_Threshold2 */
static int hf_lte_rrc_b2_Threshold2_CDMA2000 = -1;  /* INTEGER_0_63 */
static int hf_lte_rrc_b2_Threshold2_UTRA = -1;    /* ThresholdUTRA */
static int hf_lte_rrc_b2_Threshold2_GERAN = -1;   /* ThresholdGERAN */
static int hf_lte_rrc_periodical_01 = -1;         /* T_periodical_01 */
static int hf_lte_rrc_purpose_02 = -1;            /* T_purpose_02 */
static int hf_lte_rrc_reportStrongestCellsForSON = -1;  /* NULL */
static int hf_lte_rrc_reportAmount_01 = -1;       /* T_reportAmount_01 */
static int hf_lte_rrc_thresholdUTRA_RSCP = -1;    /* INTEGER_M5_91 */
static int hf_lte_rrc_thresholdUTRA_EcNO = -1;    /* INTEGER_0_49 */
static int hf_lte_rrc_IMSI_item = -1;             /* IMSI_Digit */
static int hf_lte_rrc_m_TMSI = -1;                /* BIT_STRING_SIZE_32 */
static int hf_lte_rrc_accessStratumRelease = -1;  /* AccessStratumRelease */
static int hf_lte_rrc_ue_Category = -1;           /* INTEGER_1_16 */
static int hf_lte_rrc_pdcp_Parameters = -1;       /* PDCP_Parameters */
static int hf_lte_rrc_phyLayerParameters = -1;    /* PhyLayerParameters */
static int hf_lte_rrc_rf_Parameters = -1;         /* RF_Parameters */
static int hf_lte_rrc_measurementParameters = -1;  /* MeasurementParameters */
static int hf_lte_rrc_interRAT_Parameters = -1;   /* T_interRAT_Parameters */
static int hf_lte_rrc_utraFDD = -1;               /* IRAT_UTRA_FDD_Parameters */
static int hf_lte_rrc_utraTDD128 = -1;            /* IRAT_UTRA_TDD128_Parameters */
static int hf_lte_rrc_utraTDD384 = -1;            /* IRAT_UTRA_TDD384_Parameters */
static int hf_lte_rrc_utraTDD768 = -1;            /* IRAT_UTRA_TDD768_Parameters */
static int hf_lte_rrc_geran_02 = -1;              /* IRAT_GERAN_Parameters */
static int hf_lte_rrc_cdma2000_HRPD_01 = -1;      /* IRAT_CDMA2000_HRPD_Parameters */
static int hf_lte_rrc_cdma2000_1xRTT_01 = -1;     /* IRAT_CDMA2000_1xRTT_Parameters */
static int hf_lte_rrc_nonCriticalExtension_27 = -1;  /* T_nonCriticalExtension_27 */
static int hf_lte_rrc_supportedROHCprofiles = -1;  /* T_supportedROHCprofiles */
static int hf_lte_rrc_maxNumberROHC_ContextSessions = -1;  /* T_maxNumberROHC_ContextSessions */
static int hf_lte_rrc_ue_TxAntennaSelectionSupported = -1;  /* BOOLEAN */
static int hf_lte_rrc_ue_SpecificRefSigsSupported = -1;  /* BOOLEAN */
static int hf_lte_rrc_supportedEUTRA_BandList = -1;  /* SupportedEUTRA_BandList */
static int hf_lte_rrc_SupportedEUTRA_BandList_item = -1;  /* SupportedEUTRA_BandList_item */
static int hf_lte_rrc_eutra_Band = -1;            /* INTEGER_1_64 */
static int hf_lte_rrc_halfDuplex = -1;            /* BOOLEAN */
static int hf_lte_rrc_eutra_BandList = -1;        /* EUTRA_BandList */
static int hf_lte_rrc_EUTRA_BandList_item = -1;   /* EUTRA_BandList_item */
static int hf_lte_rrc_interFreqEUTRA_BandList = -1;  /* InterFreqEUTRA_BandList */
static int hf_lte_rrc_interRAT_BandList = -1;     /* InterRAT_BandList */
static int hf_lte_rrc_InterFreqEUTRA_BandList_item = -1;  /* InterFreqEUTRA_BandList_item */
static int hf_lte_rrc_interFreqNeedForGaps = -1;  /* BOOLEAN */
static int hf_lte_rrc_InterRAT_BandList_item = -1;  /* InterRAT_BandList_item */
static int hf_lte_rrc_interRAT_NeedForGaps = -1;  /* BOOLEAN */
static int hf_lte_rrc_supportedUTRA_FDD_BandList = -1;  /* SupportedUTRA_FDD_BandList */
static int hf_lte_rrc_SupportedUTRA_FDD_BandList_item = -1;  /* SupportedUTRA_FDD_BandList_item */
static int hf_lte_rrc_utra_FDD_Band = -1;         /* T_utra_FDD_Band */
static int hf_lte_rrc_supportedUTRA_TDD128BandList = -1;  /* SupportedUTRA_TDD128BandList */
static int hf_lte_rrc_SupportedUTRA_TDD128BandList_item = -1;  /* SupportedUTRA_TDD128BandList_item */
static int hf_lte_rrc_utra_TDD128Band = -1;       /* T_utra_TDD128Band */
static int hf_lte_rrc_supportedUTRA_TDD384BandList = -1;  /* SupportedUTRA_TDD384BandList */
static int hf_lte_rrc_SupportedUTRA_TDD384BandList_item = -1;  /* SupportedUTRA_TDD384BandList_item */
static int hf_lte_rrc_utra_TDD384Band = -1;       /* T_utra_TDD384Band */
static int hf_lte_rrc_supportedUTRA_TDD768BandList = -1;  /* SupportedUTRA_TDD768BandList */
static int hf_lte_rrc_SupportedUTRA_TDD768BandList_item = -1;  /* SupportedUTRA_TDD768BandList_item */
static int hf_lte_rrc_utra_TDD768Band = -1;       /* T_utra_TDD768Band */
static int hf_lte_rrc_supportedGERAN_BandList = -1;  /* SupportedGERAN_BandList */
static int hf_lte_rrc_interRAT_PS_HO_ToGERAN = -1;  /* BOOLEAN */
static int hf_lte_rrc_SupportedGERAN_BandList_item = -1;  /* SupportedGERAN_BandList_item */
static int hf_lte_rrc_geran_Band = -1;            /* T_geran_Band */
static int hf_lte_rrc_supportedHRPD_BandList = -1;  /* SupportedHRPD_BandList */
static int hf_lte_rrc_cdma2000_HRPD_TxConfig = -1;  /* T_cdma2000_HRPD_TxConfig */
static int hf_lte_rrc_cdma2000_HRPD_RxConfig = -1;  /* T_cdma2000_HRPD_RxConfig */
static int hf_lte_rrc_SupportedHRPD_BandList_item = -1;  /* SupportedHRPD_BandList_item */
static int hf_lte_rrc_cdma2000_HRPD_Band = -1;    /* CDMA2000_Bandclass */
static int hf_lte_rrc_supported1xRTT_BandList = -1;  /* Supported1xRTT_BandList */
static int hf_lte_rrc_cdma2000_1xRTT_TxConfig = -1;  /* T_cdma2000_1xRTT_TxConfig */
static int hf_lte_rrc_cdma2000_1xRTT_RxConfig = -1;  /* T_cdma2000_1xRTT_RxConfig */
static int hf_lte_rrc_Supported1xRTT_BandList_item = -1;  /* Supported1xRTT_BandList_item */
static int hf_lte_rrc_cdma2000_1xRTT_Band = -1;   /* CDMA2000_Bandclass */
static int hf_lte_rrc_t300 = -1;                  /* T_t300 */
static int hf_lte_rrc_t301 = -1;                  /* T_t301 */
static int hf_lte_rrc_t310 = -1;                  /* T_t310 */
static int hf_lte_rrc_n310 = -1;                  /* T_n310 */
static int hf_lte_rrc_t311 = -1;                  /* T_t311 */
static int hf_lte_rrc_n311 = -1;                  /* T_n311 */
static int hf_lte_rrc_measIdList = -1;            /* MeasIdToAddModifyList */
static int hf_lte_rrc_measObjectList = -1;        /* MeasObjectToAddModifyList */
static int hf_lte_rrc_reportConfigList = -1;      /* ReportConfigToAddModifyList */
static int hf_lte_rrc_speedDependentParameters_01 = -1;  /* T_speedDependentParameters_01 */
static int hf_lte_rrc_VarMeasurementReports_item = -1;  /* VarMeasurementReports_item */
static int hf_lte_rrc_cellsTriggeredList = -1;    /* CellsTriggeredList */
static int hf_lte_rrc_numberOfReportsSent = -1;   /* INTEGER */
static int hf_lte_rrc_CellsTriggeredList_item = -1;  /* CellsTriggeredList_item */
static int hf_lte_rrc_message_07 = -1;            /* InterNode_MessageType */
static int hf_lte_rrc_c1_22 = -1;                 /* T_c1_22 */
static int hf_lte_rrc_interRAT_Message = -1;      /* InterRAT_Message */
static int hf_lte_rrc_handoverCommand = -1;       /* HandoverCommand */
static int hf_lte_rrc_handoverPreparationInformation = -1;  /* HandoverPreparationInformation */
static int hf_lte_rrc_ueRadioAccessCapabilityInformation = -1;  /* UERadioAccessCapabilityInformation */
static int hf_lte_rrc_messageClassExtension_06 = -1;  /* T_messageClassExtension_06 */
static int hf_lte_rrc_criticalExtensions_27 = -1;  /* T_criticalExtensions_27 */
static int hf_lte_rrc_c1_23 = -1;                 /* T_c1_23 */
static int hf_lte_rrc_interRAT_Message_r8 = -1;   /* InterRAT_Message_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_27 = -1;  /* T_criticalExtensionsFuture_27 */
static int hf_lte_rrc_interRAT_Message_01 = -1;   /* OCTET_STRING */
static int hf_lte_rrc_nonCriticalExtension_28 = -1;  /* T_nonCriticalExtension_28 */
static int hf_lte_rrc_criticalExtensions_28 = -1;  /* T_criticalExtensions_28 */
static int hf_lte_rrc_c1_24 = -1;                 /* T_c1_24 */
static int hf_lte_rrc_handoverCommand_r8 = -1;    /* HandoverCommand_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_28 = -1;  /* T_criticalExtensionsFuture_28 */
static int hf_lte_rrc_handoverCommandMessage = -1;  /* T_handoverCommandMessage */
static int hf_lte_rrc_nonCriticalExtension_29 = -1;  /* T_nonCriticalExtension_29 */
static int hf_lte_rrc_criticalExtensions_29 = -1;  /* T_criticalExtensions_29 */
static int hf_lte_rrc_c1_25 = -1;                 /* T_c1_25 */
static int hf_lte_rrc_handoverPreparationInformation_r8 = -1;  /* HandoverPreparationInformation_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_29 = -1;  /* T_criticalExtensionsFuture_29 */
static int hf_lte_rrc_as_Configuration = -1;      /* AS_Configuration */
static int hf_lte_rrc_rrm_Configuration = -1;     /* RRM_Configuration */
static int hf_lte_rrc_as_Context = -1;            /* AS_Context */
static int hf_lte_rrc_nonCriticalExtension_30 = -1;  /* T_nonCriticalExtension_30 */
static int hf_lte_rrc_criticalExtensions_30 = -1;  /* T_criticalExtensions_30 */
static int hf_lte_rrc_c1_26 = -1;                 /* T_c1_26 */
static int hf_lte_rrc_ueRadioAccessCapabilityInformation_r8 = -1;  /* UERadioAccessCapabilityInformation_r8_IEs */
static int hf_lte_rrc_criticalExtensionsFuture_30 = -1;  /* T_criticalExtensionsFuture_30 */
static int hf_lte_rrc_ue_RadioAccessCapabilityInfo = -1;  /* T_ue_RadioAccessCapabilityInfo */
static int hf_lte_rrc_nonCriticalExtension_31 = -1;  /* T_nonCriticalExtension_31 */
static int hf_lte_rrc_sourceMeasurementConfiguration = -1;  /* MeasurementConfiguration */
static int hf_lte_rrc_sourceRadioResourceConfiguration = -1;  /* RadioResourceConfigDedicated */
static int hf_lte_rrc_sourceSecurityConfiguration = -1;  /* SecurityConfiguration */
static int hf_lte_rrc_sourceUE_Identity = -1;     /* C_RNTI */
static int hf_lte_rrc_sourceMasterInformationBlock = -1;  /* MasterInformationBlock */
static int hf_lte_rrc_sourceSystemInformationBlockType1 = -1;  /* SystemInformationBlockType1 */
static int hf_lte_rrc_sourceSystemInformationBlockType2 = -1;  /* SystemInformationBlockType2 */
static int hf_lte_rrc_ue_RadioAccessCapabilityInfo_01 = -1;  /* T_ue_RadioAccessCapabilityInfo_01 */
static int hf_lte_rrc_ue_SecurityCapabilityInfo = -1;  /* OCTET_STRING */
static int hf_lte_rrc_reestablishmentInfo = -1;   /* ReestablishmentInfo */
static int hf_lte_rrc_sourcePhysicalCellIdentity = -1;  /* PhysicalCellIdentity */
static int hf_lte_rrc_targetCellShortMAC_I = -1;  /* ShortMAC_I */
static int hf_lte_rrc_additionalReestabInfoList = -1;  /* AdditionalReestabInfoList */
static int hf_lte_rrc_AdditionalReestabInfoList_item = -1;  /* AdditionalReestabInfoList_item */
static int hf_lte_rrc_key_eNodeB_Star = -1;       /* Key_eNodeB_Star */
static int hf_lte_rrc_ue_InactiveTime = -1;       /* T_ue_InactiveTime */

/*--- End of included file: packet-lte-rrc-hf.c ---*/
#line 57 "packet-lte-rrc-template.c"

/* Initialize the subtree pointers */
static int ett_lte_rrc = -1;


/*--- Included file: packet-lte-rrc-ett.c ---*/
#line 1 "packet-lte-rrc-ett.c"
static gint ett_lte_rrc_BCCH_BCH_Message = -1;
static gint ett_lte_rrc_BCCH_DL_SCH_Message = -1;
static gint ett_lte_rrc_BCCH_DL_SCH_MessageType = -1;
static gint ett_lte_rrc_T_c1 = -1;
static gint ett_lte_rrc_T_messageClassExtension = -1;
static gint ett_lte_rrc_PCCH_Message = -1;
static gint ett_lte_rrc_PCCH_MessageType = -1;
static gint ett_lte_rrc_T_c1_01 = -1;
static gint ett_lte_rrc_T_messageClassExtension_01 = -1;
static gint ett_lte_rrc_DL_CCCH_Message = -1;
static gint ett_lte_rrc_DL_CCCH_MessageType = -1;
static gint ett_lte_rrc_T_c1_02 = -1;
static gint ett_lte_rrc_T_messageClassExtension_02 = -1;
static gint ett_lte_rrc_DL_DCCH_Message = -1;
static gint ett_lte_rrc_DL_DCCH_MessageType = -1;
static gint ett_lte_rrc_T_c1_03 = -1;
static gint ett_lte_rrc_T_messageClassExtension_03 = -1;
static gint ett_lte_rrc_UL_CCCH_Message = -1;
static gint ett_lte_rrc_UL_CCCH_MessageType = -1;
static gint ett_lte_rrc_T_c1_04 = -1;
static gint ett_lte_rrc_T_messageClassExtension_04 = -1;
static gint ett_lte_rrc_UL_DCCH_Message = -1;
static gint ett_lte_rrc_UL_DCCH_MessageType = -1;
static gint ett_lte_rrc_T_c1_05 = -1;
static gint ett_lte_rrc_T_messageClassExtension_05 = -1;
static gint ett_lte_rrc_CDMA2000_CSFBParametersRequest = -1;
static gint ett_lte_rrc_T_criticalExtensions = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture = -1;
static gint ett_lte_rrc_CDMA2000_CSFBParametersRequest_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension = -1;
static gint ett_lte_rrc_CDMA2000_CSFBParametersResponse = -1;
static gint ett_lte_rrc_T_criticalExtensions_01 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_01 = -1;
static gint ett_lte_rrc_CDMA2000_CSFBParametersResponse_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_01 = -1;
static gint ett_lte_rrc_CounterCheck = -1;
static gint ett_lte_rrc_T_criticalExtensions_02 = -1;
static gint ett_lte_rrc_T_c1_06 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_02 = -1;
static gint ett_lte_rrc_CounterCheck_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_02 = -1;
static gint ett_lte_rrc_DRB_CountMSB_InfoList = -1;
static gint ett_lte_rrc_DRB_CountMSB_InfoList_item = -1;
static gint ett_lte_rrc_CounterCheckResponse = -1;
static gint ett_lte_rrc_T_criticalExtensions_03 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_03 = -1;
static gint ett_lte_rrc_CounterCheckResponse_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_03 = -1;
static gint ett_lte_rrc_DRB_CountInfoList = -1;
static gint ett_lte_rrc_DRB_CountInfoList_item = -1;
static gint ett_lte_rrc_DLInformationTransfer = -1;
static gint ett_lte_rrc_T_criticalExtensions_04 = -1;
static gint ett_lte_rrc_T_c1_07 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_04 = -1;
static gint ett_lte_rrc_DLInformationTransfer_r8_IEs = -1;
static gint ett_lte_rrc_T_informationType = -1;
static gint ett_lte_rrc_T_cdma2000 = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_04 = -1;
static gint ett_lte_rrc_HandoverFromEUTRAPreparationRequest = -1;
static gint ett_lte_rrc_T_criticalExtensions_05 = -1;
static gint ett_lte_rrc_T_c1_08 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_05 = -1;
static gint ett_lte_rrc_HandoverFromEUTRAPreparationRequest_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_05 = -1;
static gint ett_lte_rrc_MasterInformationBlock = -1;
static gint ett_lte_rrc_MeasurementReport = -1;
static gint ett_lte_rrc_T_criticalExtensions_06 = -1;
static gint ett_lte_rrc_T_c1_09 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_06 = -1;
static gint ett_lte_rrc_MeasurementReport_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_06 = -1;
static gint ett_lte_rrc_MobilityFromEUTRACommand = -1;
static gint ett_lte_rrc_T_criticalExtensions_07 = -1;
static gint ett_lte_rrc_T_c1_10 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_07 = -1;
static gint ett_lte_rrc_MobilityFromEUTRACommand_r8_IEs = -1;
static gint ett_lte_rrc_T_purpose = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_07 = -1;
static gint ett_lte_rrc_Handover = -1;
static gint ett_lte_rrc_CellChangeOrder = -1;
static gint ett_lte_rrc_T_targetRAT_Type_01 = -1;
static gint ett_lte_rrc_T_geran = -1;
static gint ett_lte_rrc_T_geran_SystemInformation = -1;
static gint ett_lte_rrc_GERAN_SystemInformation = -1;
static gint ett_lte_rrc_Paging = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_08 = -1;
static gint ett_lte_rrc_PagingRecordList = -1;
static gint ett_lte_rrc_PagingRecord = -1;
static gint ett_lte_rrc_PagingUE_Identity = -1;
static gint ett_lte_rrc_RRCConnectionReconfiguration = -1;
static gint ett_lte_rrc_T_criticalExtensions_08 = -1;
static gint ett_lte_rrc_T_c1_11 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_08 = -1;
static gint ett_lte_rrc_RRCConnectionReconfiguration_r8_IEs = -1;
static gint ett_lte_rrc_SEQUENCE_SIZE_1_maxDRB_OF_NAS_DedicatedInformation = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_09 = -1;
static gint ett_lte_rrc_RRCConnectionReconfigurationComplete = -1;
static gint ett_lte_rrc_T_criticalExtensions_09 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_09 = -1;
static gint ett_lte_rrc_RRCConnectionReconfigurationComplete_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_10 = -1;
static gint ett_lte_rrc_RRCConnectionReestablishment = -1;
static gint ett_lte_rrc_T_criticalExtensions_10 = -1;
static gint ett_lte_rrc_T_c1_12 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_10 = -1;
static gint ett_lte_rrc_RRCConnectionReestablishment_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_11 = -1;
static gint ett_lte_rrc_RRCConnectionReestablishmentComplete = -1;
static gint ett_lte_rrc_T_criticalExtensions_11 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_11 = -1;
static gint ett_lte_rrc_RRCConnectionReestablishmentComplete_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_12 = -1;
static gint ett_lte_rrc_RRCConnectionReestablishmentReject = -1;
static gint ett_lte_rrc_T_criticalExtensions_12 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_12 = -1;
static gint ett_lte_rrc_RRCConnectionReestablishmentReject_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_13 = -1;
static gint ett_lte_rrc_RRCConnectionReestablishmentRequest = -1;
static gint ett_lte_rrc_T_criticalExtensions_13 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_13 = -1;
static gint ett_lte_rrc_RRCConnectionReestablishmentRequest_r8_IEs = -1;
static gint ett_lte_rrc_ReestabUE_Identity = -1;
static gint ett_lte_rrc_RRCConnectionReject = -1;
static gint ett_lte_rrc_T_criticalExtensions_14 = -1;
static gint ett_lte_rrc_T_c1_13 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_14 = -1;
static gint ett_lte_rrc_RRCConnectionReject_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_14 = -1;
static gint ett_lte_rrc_RRCConnectionRelease = -1;
static gint ett_lte_rrc_T_criticalExtensions_15 = -1;
static gint ett_lte_rrc_T_c1_14 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_15 = -1;
static gint ett_lte_rrc_RRCConnectionRelease_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_15 = -1;
static gint ett_lte_rrc_RedirectionInformation = -1;
static gint ett_lte_rrc_T_interRAT_target = -1;
static gint ett_lte_rrc_IdleModeMobilityControlInfo = -1;
static gint ett_lte_rrc_InterFreqPriorityList = -1;
static gint ett_lte_rrc_InterFreqPriorityList_item = -1;
static gint ett_lte_rrc_GERAN_FreqPriorityList = -1;
static gint ett_lte_rrc_GERAN_FreqPriorityList_item = -1;
static gint ett_lte_rrc_UTRA_FDD_FreqPriorityList = -1;
static gint ett_lte_rrc_UTRA_FDD_FreqPriorityList_item = -1;
static gint ett_lte_rrc_UTRA_TDD_FreqPriorityList = -1;
static gint ett_lte_rrc_UTRA_TDD_FreqPriorityList_item = -1;
static gint ett_lte_rrc_HRPD_BandClassPriorityList = -1;
static gint ett_lte_rrc_HRPD_BandClassPriorityList_item = -1;
static gint ett_lte_rrc_OneXRTT_BandClassPriorityList = -1;
static gint ett_lte_rrc_OneXRTT_BandClassPriorityList_item = -1;
static gint ett_lte_rrc_RRCConnectionRequest = -1;
static gint ett_lte_rrc_T_criticalExtensions_16 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_16 = -1;
static gint ett_lte_rrc_RRCConnectionRequest_r8_IEs = -1;
static gint ett_lte_rrc_InitialUE_Identity = -1;
static gint ett_lte_rrc_RRCConnectionSetup = -1;
static gint ett_lte_rrc_T_criticalExtensions_17 = -1;
static gint ett_lte_rrc_T_c1_15 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_17 = -1;
static gint ett_lte_rrc_RRCConnectionSetup_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_16 = -1;
static gint ett_lte_rrc_RRCConnectionSetupComplete = -1;
static gint ett_lte_rrc_T_criticalExtensions_18 = -1;
static gint ett_lte_rrc_T_c1_16 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_18 = -1;
static gint ett_lte_rrc_RRCConnectionSetupComplete_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_17 = -1;
static gint ett_lte_rrc_RegisteredMME = -1;
static gint ett_lte_rrc_SecurityModeCommand = -1;
static gint ett_lte_rrc_T_criticalExtensions_19 = -1;
static gint ett_lte_rrc_T_c1_17 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_19 = -1;
static gint ett_lte_rrc_SecurityModeCommand_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_18 = -1;
static gint ett_lte_rrc_SecurityModeComplete = -1;
static gint ett_lte_rrc_T_criticalExtensions_20 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_20 = -1;
static gint ett_lte_rrc_SecurityModeComplete_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_19 = -1;
static gint ett_lte_rrc_SecurityModeFailure = -1;
static gint ett_lte_rrc_T_criticalExtensions_21 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_21 = -1;
static gint ett_lte_rrc_SecurityModeFailure_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_20 = -1;
static gint ett_lte_rrc_SystemInformation = -1;
static gint ett_lte_rrc_T_criticalExtensions_22 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_22 = -1;
static gint ett_lte_rrc_SystemInformation_r8_IEs = -1;
static gint ett_lte_rrc_T_sib_TypeAndInfo = -1;
static gint ett_lte_rrc_T_sib_TypeAndInfo_item = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_21 = -1;
static gint ett_lte_rrc_SystemInformationBlockType1 = -1;
static gint ett_lte_rrc_T_cellAccessRelatedInformation = -1;
static gint ett_lte_rrc_T_cellSelectionInfo = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_22 = -1;
static gint ett_lte_rrc_PLMN_IdentityList = -1;
static gint ett_lte_rrc_PLMN_IdentityList_item = -1;
static gint ett_lte_rrc_SchedulingInformation = -1;
static gint ett_lte_rrc_SchedulingInformation_item = -1;
static gint ett_lte_rrc_SIB_MappingInfo = -1;
static gint ett_lte_rrc_UECapabilityEnquiry = -1;
static gint ett_lte_rrc_T_criticalExtensions_23 = -1;
static gint ett_lte_rrc_T_c1_18 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_23 = -1;
static gint ett_lte_rrc_UECapabilityEnquiry_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_23 = -1;
static gint ett_lte_rrc_UE_RadioAccessCapRequest = -1;
static gint ett_lte_rrc_UECapabilityInformation = -1;
static gint ett_lte_rrc_T_criticalExtensions_24 = -1;
static gint ett_lte_rrc_T_c1_19 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_24 = -1;
static gint ett_lte_rrc_UECapabilityInformation_r8_IEs = -1;
static gint ett_lte_rrc_UECapabilityInformation_r8_IEs_item = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_24 = -1;
static gint ett_lte_rrc_ULHandoverPreparationTransfer = -1;
static gint ett_lte_rrc_T_criticalExtensions_25 = -1;
static gint ett_lte_rrc_T_c1_20 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_25 = -1;
static gint ett_lte_rrc_ULHandoverPreparationTransfer_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_25 = -1;
static gint ett_lte_rrc_ULInformationTransfer = -1;
static gint ett_lte_rrc_T_criticalExtensions_26 = -1;
static gint ett_lte_rrc_T_c1_21 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_26 = -1;
static gint ett_lte_rrc_ULInformationTransfer_r8_IEs = -1;
static gint ett_lte_rrc_T_informationType_01 = -1;
static gint ett_lte_rrc_T_cdma2000_01 = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_26 = -1;
static gint ett_lte_rrc_SystemInformationBlockType2 = -1;
static gint ett_lte_rrc_T_accessBarringInformation = -1;
static gint ett_lte_rrc_T_frequencyInformation = -1;
static gint ett_lte_rrc_AccessClassBarringInformation = -1;
static gint ett_lte_rrc_AccessClassBarringList = -1;
static gint ett_lte_rrc_AccessClassBarringList_item = -1;
static gint ett_lte_rrc_MBSFN_SubframeConfiguration = -1;
static gint ett_lte_rrc_MBSFN_SubframeConfiguration_item = -1;
static gint ett_lte_rrc_T_subframeAllocation = -1;
static gint ett_lte_rrc_SystemInformationBlockType3 = -1;
static gint ett_lte_rrc_T_cellReselectionInfoCommon = -1;
static gint ett_lte_rrc_T_speedDependentReselection = -1;
static gint ett_lte_rrc_T_speedDependentScalingParametersHyst = -1;
static gint ett_lte_rrc_T_cellReselectionServingFreqInfo = -1;
static gint ett_lte_rrc_T_intraFreqCellReselectionInfo = -1;
static gint ett_lte_rrc_T_speedDependentScalingParameters = -1;
static gint ett_lte_rrc_SystemInformationBlockType4 = -1;
static gint ett_lte_rrc_IntraFreqNeighbouringCellList = -1;
static gint ett_lte_rrc_IntraFreqNeighbouringCellList_item = -1;
static gint ett_lte_rrc_IntraFreqBlacklistedCellList = -1;
static gint ett_lte_rrc_IntraFreqBlacklistedCellList_item = -1;
static gint ett_lte_rrc_SystemInformationBlockType5 = -1;
static gint ett_lte_rrc_InterFreqCarrierFreqList = -1;
static gint ett_lte_rrc_InterFreqCarrierFreqList_item = -1;
static gint ett_lte_rrc_T_speedDependentScalingParameters_01 = -1;
static gint ett_lte_rrc_InterFreqNeighbouringCellList = -1;
static gint ett_lte_rrc_InterFreqNeighbouringCellList_item = -1;
static gint ett_lte_rrc_InterFreqBlacklistedCellList = -1;
static gint ett_lte_rrc_InterFreqBlacklistedCellList_item = -1;
static gint ett_lte_rrc_SystemInformationBlockType6 = -1;
static gint ett_lte_rrc_T_speedDependentScalingParameters_02 = -1;
static gint ett_lte_rrc_UTRA_FDD_CarrierFreqList = -1;
static gint ett_lte_rrc_UTRA_FDD_CarrierFreqList_item = -1;
static gint ett_lte_rrc_UTRA_TDD_CarrierFreqList = -1;
static gint ett_lte_rrc_UTRA_TDD_CarrierFreqList_item = -1;
static gint ett_lte_rrc_SystemInformationBlockType7 = -1;
static gint ett_lte_rrc_T_speedDependentScalingParameters_03 = -1;
static gint ett_lte_rrc_GERAN_NeigbourFreqList = -1;
static gint ett_lte_rrc_GERAN_BCCH_Group = -1;
static gint ett_lte_rrc_T_geran_BCCH_Configuration = -1;
static gint ett_lte_rrc_SystemInformationBlockType8 = -1;
static gint ett_lte_rrc_T_hrpd_Parameters = -1;
static gint ett_lte_rrc_T_hrpd_CellReselectionParameters = -1;
static gint ett_lte_rrc_T_speedDependentScalingParameters_04 = -1;
static gint ett_lte_rrc_T_oneXRTT_Parameters = -1;
static gint ett_lte_rrc_T_oneXRTT_CellReselectionParameters = -1;
static gint ett_lte_rrc_T_speedDependentScalingParameters_05 = -1;
static gint ett_lte_rrc_CDMA2000_NeighbourCellList = -1;
static gint ett_lte_rrc_CDMA2000_NeighbourCellList_item = -1;
static gint ett_lte_rrc_CDMA2000_NeighbourCellsPerBandclass = -1;
static gint ett_lte_rrc_CDMA2000_NeighbourCellsPerBandclass_item = -1;
static gint ett_lte_rrc_CDMA2000_CellIdList = -1;
static gint ett_lte_rrc_HRPD_BandClassList = -1;
static gint ett_lte_rrc_HRPD_BandClassList_item = -1;
static gint ett_lte_rrc_OneXRTT_BandClassList = -1;
static gint ett_lte_rrc_OneXRTT_BandClassList_item = -1;
static gint ett_lte_rrc_SystemInformationBlockType9 = -1;
static gint ett_lte_rrc_SystemInformationBlockType10 = -1;
static gint ett_lte_rrc_SystemInformationBlockType11 = -1;
static gint ett_lte_rrc_AntennaInformationCommon = -1;
static gint ett_lte_rrc_AntennaInformationDedicated = -1;
static gint ett_lte_rrc_T_codebookSubsetRestriction = -1;
static gint ett_lte_rrc_T_ue_TransmitAntennaSelection = -1;
static gint ett_lte_rrc_CQI_Reporting = -1;
static gint ett_lte_rrc_CQI_ReportingPeriodic = -1;
static gint ett_lte_rrc_T_enable_01 = -1;
static gint ett_lte_rrc_T_cqi_FormatIndicatorPeriodic = -1;
static gint ett_lte_rrc_T_subbandCQI = -1;
static gint ett_lte_rrc_LogicalChannelConfig = -1;
static gint ett_lte_rrc_T_ul_SpecificParameters = -1;
static gint ett_lte_rrc_MAC_MainConfiguration = -1;
static gint ett_lte_rrc_T_dl_SCH_Configuration = -1;
static gint ett_lte_rrc_T_ul_SCH_Configuration = -1;
static gint ett_lte_rrc_T_drx_Configuration = -1;
static gint ett_lte_rrc_T_enable_02 = -1;
static gint ett_lte_rrc_T_longDRX_CycleStartOffset = -1;
static gint ett_lte_rrc_T_shortDRX = -1;
static gint ett_lte_rrc_T_enable_03 = -1;
static gint ett_lte_rrc_T_phr_Configuration = -1;
static gint ett_lte_rrc_T_enable_04 = -1;
static gint ett_lte_rrc_PDCP_Configuration = -1;
static gint ett_lte_rrc_T_rlc_AM = -1;
static gint ett_lte_rrc_T_rlc_UM = -1;
static gint ett_lte_rrc_T_headerCompression = -1;
static gint ett_lte_rrc_T_rohc = -1;
static gint ett_lte_rrc_T_profiles = -1;
static gint ett_lte_rrc_PDSCH_ConfigCommon = -1;
static gint ett_lte_rrc_PDSCH_ConfigDedicated = -1;
static gint ett_lte_rrc_PHICH_Configuration = -1;
static gint ett_lte_rrc_PhysicalConfigDedicated = -1;
static gint ett_lte_rrc_T_antennaInformation = -1;
static gint ett_lte_rrc_PRACH_ConfigurationSIB = -1;
static gint ett_lte_rrc_PRACH_Configuration = -1;
static gint ett_lte_rrc_PRACH_ConfigInfo = -1;
static gint ett_lte_rrc_PUCCH_ConfigCommon = -1;
static gint ett_lte_rrc_PUCCH_ConfigDedicated = -1;
static gint ett_lte_rrc_T_ackNackRepetition = -1;
static gint ett_lte_rrc_T_enable_05 = -1;
static gint ett_lte_rrc_PUSCH_ConfigCommon = -1;
static gint ett_lte_rrc_T_pusch_ConfigBasic = -1;
static gint ett_lte_rrc_PUSCH_ConfigDedicated = -1;
static gint ett_lte_rrc_RACH_ConfigDedicated = -1;
static gint ett_lte_rrc_RACH_ConfigCommon = -1;
static gint ett_lte_rrc_T_preambleInformation = -1;
static gint ett_lte_rrc_T_preamblesGroupAConfig = -1;
static gint ett_lte_rrc_T_powerRampingParameters = -1;
static gint ett_lte_rrc_T_ra_SupervisionInformation = -1;
static gint ett_lte_rrc_RadioResourceConfigCommonSIB = -1;
static gint ett_lte_rrc_RadioResourceConfigCommon = -1;
static gint ett_lte_rrc_BCCH_Configuration = -1;
static gint ett_lte_rrc_PCCH_Configuration = -1;
static gint ett_lte_rrc_RadioResourceConfigDedicated = -1;
static gint ett_lte_rrc_T_mac_MainConfig = -1;
static gint ett_lte_rrc_SRB_ToAddModifyList = -1;
static gint ett_lte_rrc_SRB_ToAddModifyList_item = -1;
static gint ett_lte_rrc_T_rlc_Configuration = -1;
static gint ett_lte_rrc_T_logicalChannelConfig = -1;
static gint ett_lte_rrc_DRB_ToAddModifyList = -1;
static gint ett_lte_rrc_DRB_ToAddModifyList_item = -1;
static gint ett_lte_rrc_DRB_ToReleaseList = -1;
static gint ett_lte_rrc_DRB_ToReleaseList_item = -1;
static gint ett_lte_rrc_RLC_Configuration = -1;
static gint ett_lte_rrc_T_am = -1;
static gint ett_lte_rrc_T_um_Bi_Directional = -1;
static gint ett_lte_rrc_T_um_Uni_Directional_UL = -1;
static gint ett_lte_rrc_T_um_Uni_Directional_DL = -1;
static gint ett_lte_rrc_UL_AM_RLC = -1;
static gint ett_lte_rrc_DL_AM_RLC = -1;
static gint ett_lte_rrc_UL_UM_RLC = -1;
static gint ett_lte_rrc_DL_UM_RLC = -1;
static gint ett_lte_rrc_SchedulingRequest_Configuration = -1;
static gint ett_lte_rrc_T_enable_06 = -1;
static gint ett_lte_rrc_SoundingRsUl_ConfigCommon = -1;
static gint ett_lte_rrc_SoundingRsUl_ConfigDedicated = -1;
static gint ett_lte_rrc_T_enable_07 = -1;
static gint ett_lte_rrc_SPS_Configuration = -1;
static gint ett_lte_rrc_SPS_ConfigurationDL = -1;
static gint ett_lte_rrc_T_enable_08 = -1;
static gint ett_lte_rrc_SPS_ConfigurationUL = -1;
static gint ett_lte_rrc_T_enable_09 = -1;
static gint ett_lte_rrc_T_p0_Persistent = -1;
static gint ett_lte_rrc_TDD_Configuration = -1;
static gint ett_lte_rrc_TPC_Index = -1;
static gint ett_lte_rrc_TPC_PDCCH_Configuration = -1;
static gint ett_lte_rrc_T_enable_10 = -1;
static gint ett_lte_rrc_UL_ReferenceSignalsPUSCH = -1;
static gint ett_lte_rrc_UplinkPowerControlCommon = -1;
static gint ett_lte_rrc_UplinkPowerControlDedicated = -1;
static gint ett_lte_rrc_DeltaFList_PUCCH = -1;
static gint ett_lte_rrc_SecurityConfiguration = -1;
static gint ett_lte_rrc_CDMA2000_CarrierInfo = -1;
static gint ett_lte_rrc_CDMA2000_NeighbourCellInformation = -1;
static gint ett_lte_rrc_CDMA2000_SystemTimeInfo = -1;
static gint ett_lte_rrc_T_cdma_SystemTime = -1;
static gint ett_lte_rrc_CellIndexList = -1;
static gint ett_lte_rrc_CellIndexList_item = -1;
static gint ett_lte_rrc_ConnectedModeSpeedDependentScalingParameters = -1;
static gint ett_lte_rrc_EUTRA_CarrierFreq = -1;
static gint ett_lte_rrc_GERAN_CarrierFreq = -1;
static gint ett_lte_rrc_GERAN_CarrierFreqList = -1;
static gint ett_lte_rrc_T_followingARFCNs = -1;
static gint ett_lte_rrc_T_equallySpacedARFCNs = -1;
static gint ett_lte_rrc_ExplicitListOfARFCNs = -1;
static gint ett_lte_rrc_GERAN_CellIdentity = -1;
static gint ett_lte_rrc_GlobalCellId_EUTRA = -1;
static gint ett_lte_rrc_GlobalCellId_UTRA = -1;
static gint ett_lte_rrc_GlobalCellId_GERAN = -1;
static gint ett_lte_rrc_GlobalCellId_CDMA2000 = -1;
static gint ett_lte_rrc_HRPD_PreRegistrationInfo = -1;
static gint ett_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList = -1;
static gint ett_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList_item = -1;
static gint ett_lte_rrc_MobilityControlInformation = -1;
static gint ett_lte_rrc_EUTRA_CarrierBandwidth = -1;
static gint ett_lte_rrc_MobilityStateParameters = -1;
static gint ett_lte_rrc_OneXRTT_CSFB_RegistrationInfo = -1;
static gint ett_lte_rrc_OneXRTT_RegistrationParameters = -1;
static gint ett_lte_rrc_PhysicalCellIdentityAndRange = -1;
static gint ett_lte_rrc_T_rangeOfPCI = -1;
static gint ett_lte_rrc_PLMN_Identity = -1;
static gint ett_lte_rrc_MCC = -1;
static gint ett_lte_rrc_MNC = -1;
static gint ett_lte_rrc_UTRA_FDD_CellIdentity = -1;
static gint ett_lte_rrc_UTRA_TDD_CellIdentity = -1;
static gint ett_lte_rrc_UTRA_DL_CarrierFreq = -1;
static gint ett_lte_rrc_MeasGapConfig = -1;
static gint ett_lte_rrc_T_gapActivation = -1;
static gint ett_lte_rrc_T_activate = -1;
static gint ett_lte_rrc_T_gapPattern = -1;
static gint ett_lte_rrc_T_gp1 = -1;
static gint ett_lte_rrc_T_gp2 = -1;
static gint ett_lte_rrc_MeasObjectCDMA2000 = -1;
static gint ett_lte_rrc_CDMA2000_CellsToAddModifyList = -1;
static gint ett_lte_rrc_CDMA2000_CellsToAddModifyList_item = -1;
static gint ett_lte_rrc_MeasObjectEUTRA = -1;
static gint ett_lte_rrc_NeighCellsToAddModifyList = -1;
static gint ett_lte_rrc_NeighCellsToAddModifyList_item = -1;
static gint ett_lte_rrc_BlackListedCellsToAddModifyList = -1;
static gint ett_lte_rrc_BlackListedCellsToAddModifyList_item = -1;
static gint ett_lte_rrc_MeasObjectGERAN = -1;
static gint ett_lte_rrc_GERAN_MeasFrequencyList = -1;
static gint ett_lte_rrc_MeasObjectUTRA = -1;
static gint ett_lte_rrc_T_cellsToAddModifyList = -1;
static gint ett_lte_rrc_T_cellForWhichToReportCGI = -1;
static gint ett_lte_rrc_UTRA_FDD_CellsToAddModifyList = -1;
static gint ett_lte_rrc_UTRA_FDD_CellsToAddModifyList_item = -1;
static gint ett_lte_rrc_UTRA_TDD_CellsToAddModifyList = -1;
static gint ett_lte_rrc_UTRA_TDD_CellsToAddModifyList_item = -1;
static gint ett_lte_rrc_MeasuredResults = -1;
static gint ett_lte_rrc_T_measResultServing = -1;
static gint ett_lte_rrc_T_neighbouringMeasResults = -1;
static gint ett_lte_rrc_MeasResultListEUTRA = -1;
static gint ett_lte_rrc_MeasResultListEUTRA_item = -1;
static gint ett_lte_rrc_T_globalCellIdentity = -1;
static gint ett_lte_rrc_T_measResult = -1;
static gint ett_lte_rrc_MeasResultListUTRA = -1;
static gint ett_lte_rrc_MeasResultListUTRA_item = -1;
static gint ett_lte_rrc_T_physicalCellIdentity = -1;
static gint ett_lte_rrc_T_globalCellIdentity_01 = -1;
static gint ett_lte_rrc_T_measResult_01 = -1;
static gint ett_lte_rrc_T_mode = -1;
static gint ett_lte_rrc_T_fdd = -1;
static gint ett_lte_rrc_T_tdd = -1;
static gint ett_lte_rrc_MeasResultListGERAN = -1;
static gint ett_lte_rrc_MeasResultListGERAN_item = -1;
static gint ett_lte_rrc_T_physicalCellIdentity_01 = -1;
static gint ett_lte_rrc_T_globalCellIdentity_02 = -1;
static gint ett_lte_rrc_T_measResult_02 = -1;
static gint ett_lte_rrc_MeasResultsCDMA2000 = -1;
static gint ett_lte_rrc_MeasResultListCDMA2000 = -1;
static gint ett_lte_rrc_MeasResultListCDMA2000_item = -1;
static gint ett_lte_rrc_T_measResult_03 = -1;
static gint ett_lte_rrc_PLMN_IdentityList2 = -1;
static gint ett_lte_rrc_PLMN_IdentityList2_item = -1;
static gint ett_lte_rrc_MeasurementConfiguration = -1;
static gint ett_lte_rrc_T_speedDependentParameters = -1;
static gint ett_lte_rrc_T_enable_11 = -1;
static gint ett_lte_rrc_MeasIdToRemoveList = -1;
static gint ett_lte_rrc_MeasIdToRemoveList_item = -1;
static gint ett_lte_rrc_MeasIdToAddModifyList = -1;
static gint ett_lte_rrc_MeasIdToAddModifyList_item = -1;
static gint ett_lte_rrc_MeasObjectToRemoveList = -1;
static gint ett_lte_rrc_MeasObjectToRemoveList_item = -1;
static gint ett_lte_rrc_MeasObjectToAddModifyList = -1;
static gint ett_lte_rrc_MeasObjectToAddModifyList_item = -1;
static gint ett_lte_rrc_T_measObject = -1;
static gint ett_lte_rrc_ReportConfigToRemoveList = -1;
static gint ett_lte_rrc_ReportConfigToRemoveList_item = -1;
static gint ett_lte_rrc_ReportConfigToAddModifyList = -1;
static gint ett_lte_rrc_ReportConfigToAddModifyList_item = -1;
static gint ett_lte_rrc_T_reportConfig = -1;
static gint ett_lte_rrc_QuantityConfig = -1;
static gint ett_lte_rrc_QuantityConfigEUTRA = -1;
static gint ett_lte_rrc_QuantityConfigUTRA = -1;
static gint ett_lte_rrc_QuantityConfigGERAN = -1;
static gint ett_lte_rrc_QuantityConfigCDMA2000 = -1;
static gint ett_lte_rrc_ReportConfigEUTRA = -1;
static gint ett_lte_rrc_T_triggerType = -1;
static gint ett_lte_rrc_T_event = -1;
static gint ett_lte_rrc_T_eventId = -1;
static gint ett_lte_rrc_T_eventA1 = -1;
static gint ett_lte_rrc_T_eventA2 = -1;
static gint ett_lte_rrc_T_eventA3 = -1;
static gint ett_lte_rrc_T_eventA4 = -1;
static gint ett_lte_rrc_T_eventA5 = -1;
static gint ett_lte_rrc_T_periodical = -1;
static gint ett_lte_rrc_T_purpose_01 = -1;
static gint ett_lte_rrc_ThresholdEUTRA = -1;
static gint ett_lte_rrc_ReportConfigInterRAT = -1;
static gint ett_lte_rrc_T_triggerType_01 = -1;
static gint ett_lte_rrc_T_event_01 = -1;
static gint ett_lte_rrc_T_eventId_01 = -1;
static gint ett_lte_rrc_T_eventB1 = -1;
static gint ett_lte_rrc_T_b1_Threshold = -1;
static gint ett_lte_rrc_T_eventB2 = -1;
static gint ett_lte_rrc_T_b2_Threshold2 = -1;
static gint ett_lte_rrc_T_periodical_01 = -1;
static gint ett_lte_rrc_T_purpose_02 = -1;
static gint ett_lte_rrc_ThresholdUTRA = -1;
static gint ett_lte_rrc_IMSI = -1;
static gint ett_lte_rrc_S_TMSI = -1;
static gint ett_lte_rrc_UE_EUTRA_Capability = -1;
static gint ett_lte_rrc_T_interRAT_Parameters = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_27 = -1;
static gint ett_lte_rrc_PDCP_Parameters = -1;
static gint ett_lte_rrc_T_supportedROHCprofiles = -1;
static gint ett_lte_rrc_PhyLayerParameters = -1;
static gint ett_lte_rrc_RF_Parameters = -1;
static gint ett_lte_rrc_SupportedEUTRA_BandList = -1;
static gint ett_lte_rrc_SupportedEUTRA_BandList_item = -1;
static gint ett_lte_rrc_MeasurementParameters = -1;
static gint ett_lte_rrc_EUTRA_BandList = -1;
static gint ett_lte_rrc_EUTRA_BandList_item = -1;
static gint ett_lte_rrc_InterFreqEUTRA_BandList = -1;
static gint ett_lte_rrc_InterFreqEUTRA_BandList_item = -1;
static gint ett_lte_rrc_InterRAT_BandList = -1;
static gint ett_lte_rrc_InterRAT_BandList_item = -1;
static gint ett_lte_rrc_IRAT_UTRA_FDD_Parameters = -1;
static gint ett_lte_rrc_SupportedUTRA_FDD_BandList = -1;
static gint ett_lte_rrc_SupportedUTRA_FDD_BandList_item = -1;
static gint ett_lte_rrc_IRAT_UTRA_TDD128_Parameters = -1;
static gint ett_lte_rrc_SupportedUTRA_TDD128BandList = -1;
static gint ett_lte_rrc_SupportedUTRA_TDD128BandList_item = -1;
static gint ett_lte_rrc_IRAT_UTRA_TDD384_Parameters = -1;
static gint ett_lte_rrc_SupportedUTRA_TDD384BandList = -1;
static gint ett_lte_rrc_SupportedUTRA_TDD384BandList_item = -1;
static gint ett_lte_rrc_IRAT_UTRA_TDD768_Parameters = -1;
static gint ett_lte_rrc_SupportedUTRA_TDD768BandList = -1;
static gint ett_lte_rrc_SupportedUTRA_TDD768BandList_item = -1;
static gint ett_lte_rrc_IRAT_GERAN_Parameters = -1;
static gint ett_lte_rrc_SupportedGERAN_BandList = -1;
static gint ett_lte_rrc_SupportedGERAN_BandList_item = -1;
static gint ett_lte_rrc_IRAT_CDMA2000_HRPD_Parameters = -1;
static gint ett_lte_rrc_SupportedHRPD_BandList = -1;
static gint ett_lte_rrc_SupportedHRPD_BandList_item = -1;
static gint ett_lte_rrc_IRAT_CDMA2000_1xRTT_Parameters = -1;
static gint ett_lte_rrc_Supported1xRTT_BandList = -1;
static gint ett_lte_rrc_Supported1xRTT_BandList_item = -1;
static gint ett_lte_rrc_UE_TimersAndConstants = -1;
static gint ett_lte_rrc_VarMeasurementConfiguration = -1;
static gint ett_lte_rrc_T_speedDependentParameters_01 = -1;
static gint ett_lte_rrc_VarMeasurementReports = -1;
static gint ett_lte_rrc_VarMeasurementReports_item = -1;
static gint ett_lte_rrc_CellsTriggeredList = -1;
static gint ett_lte_rrc_CellsTriggeredList_item = -1;
static gint ett_lte_rrc_VarShortMAC_Input = -1;
static gint ett_lte_rrc_InterNode_Message = -1;
static gint ett_lte_rrc_InterNode_MessageType = -1;
static gint ett_lte_rrc_T_c1_22 = -1;
static gint ett_lte_rrc_T_messageClassExtension_06 = -1;
static gint ett_lte_rrc_InterRAT_Message = -1;
static gint ett_lte_rrc_T_criticalExtensions_27 = -1;
static gint ett_lte_rrc_T_c1_23 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_27 = -1;
static gint ett_lte_rrc_InterRAT_Message_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_28 = -1;
static gint ett_lte_rrc_HandoverCommand = -1;
static gint ett_lte_rrc_T_criticalExtensions_28 = -1;
static gint ett_lte_rrc_T_c1_24 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_28 = -1;
static gint ett_lte_rrc_HandoverCommand_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_29 = -1;
static gint ett_lte_rrc_HandoverPreparationInformation = -1;
static gint ett_lte_rrc_T_criticalExtensions_29 = -1;
static gint ett_lte_rrc_T_c1_25 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_29 = -1;
static gint ett_lte_rrc_HandoverPreparationInformation_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_30 = -1;
static gint ett_lte_rrc_UERadioAccessCapabilityInformation = -1;
static gint ett_lte_rrc_T_criticalExtensions_30 = -1;
static gint ett_lte_rrc_T_c1_26 = -1;
static gint ett_lte_rrc_T_criticalExtensionsFuture_30 = -1;
static gint ett_lte_rrc_UERadioAccessCapabilityInformation_r8_IEs = -1;
static gint ett_lte_rrc_T_nonCriticalExtension_31 = -1;
static gint ett_lte_rrc_AS_Configuration = -1;
static gint ett_lte_rrc_AS_Context = -1;
static gint ett_lte_rrc_ReestablishmentInfo = -1;
static gint ett_lte_rrc_AdditionalReestabInfoList = -1;
static gint ett_lte_rrc_AdditionalReestabInfoList_item = -1;
static gint ett_lte_rrc_RRM_Configuration = -1;

/*--- End of included file: packet-lte-rrc-ett.c ---*/
#line 62 "packet-lte-rrc-template.c"

/* Forward declarations */
static int dissect_DL_DCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);

/*--- Included file: packet-lte-rrc-fn.c ---*/
#line 1 "packet-lte-rrc-fn.c"
/*--- PDUs declarations ---*/
static int dissect_UECapabilityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);


static const value_string lte_rrc_T_dl_Bandwidth_vals[] = {
  {   0, "n6" },
  {   1, "n15" },
  {   2, "n25" },
  {   3, "n50" },
  {   4, "n75" },
  {   5, "n100" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_dl_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_phich_Duration_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_phich_Duration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_phich_Resource_vals[] = {
  {   0, "oneSixth" },
  {   1, "half" },
  {   2, "one" },
  {   3, "two" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_phich_Resource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PHICH_Configuration_sequence[] = {
  { &hf_lte_rrc_phich_Duration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_phich_Duration },
  { &hf_lte_rrc_phich_Resource, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_phich_Resource },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PHICH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PHICH_Configuration, PHICH_Configuration_sequence);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL);

  return offset;
}


static const per_sequence_t MasterInformationBlock_sequence[] = {
  { &hf_lte_rrc_dl_Bandwidth, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_dl_Bandwidth },
  { &hf_lte_rrc_phich_Configuration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PHICH_Configuration },
  { &hf_lte_rrc_systemFrameNumber, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_8 },
  { &hf_lte_rrc_spare       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_10 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MasterInformationBlock(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "MasterInformationBlock");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MasterInformationBlock, MasterInformationBlock_sequence);

  return offset;
}



static int
dissect_lte_rrc_BCCH_BCH_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_lte_rrc_MasterInformationBlock(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t BCCH_BCH_Message_sequence[] = {
  { &hf_lte_rrc_message     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BCCH_BCH_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_BCCH_BCH_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_BCCH_BCH_Message, BCCH_BCH_Message_sequence);

  return offset;
}



static int
dissect_lte_rrc_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string lte_rrc_T_accessProbabilityFactor_vals[] = {
  {   0, "p00" },
  {   1, "p05" },
  {   2, "p10" },
  {   3, "p15" },
  {   4, "p20" },
  {   5, "p25" },
  {   6, "p30" },
  {   7, "p40" },
  {   8, "p50" },
  {   9, "p60" },
  {  10, "p70" },
  {  11, "p75" },
  {  12, "p80" },
  {  13, "p85" },
  {  14, "p90" },
  {  15, "p95" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_accessProbabilityFactor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_accessBarringTime_vals[] = {
  {   0, "s4" },
  {   1, "s8" },
  {   2, "s16" },
  {   3, "s32" },
  {   4, "s64" },
  {   5, "s128" },
  {   6, "s256" },
  {   7, "s512" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_accessBarringTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AccessClassBarringList_item_sequence[] = {
  { &hf_lte_rrc_accessClassBarring, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_AccessClassBarringList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_AccessClassBarringList_item, AccessClassBarringList_item_sequence);

  return offset;
}


static const per_sequence_t AccessClassBarringList_sequence_of[1] = {
  { &hf_lte_rrc_AccessClassBarringList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_AccessClassBarringList_item },
};

static int
dissect_lte_rrc_AccessClassBarringList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_AccessClassBarringList, AccessClassBarringList_sequence_of,
                                                  maxAC, maxAC, FALSE);

  return offset;
}


static const per_sequence_t AccessClassBarringInformation_sequence[] = {
  { &hf_lte_rrc_accessProbabilityFactor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_accessProbabilityFactor },
  { &hf_lte_rrc_accessBarringTime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_accessBarringTime },
  { &hf_lte_rrc_accessClassBarringList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_AccessClassBarringList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_AccessClassBarringInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_AccessClassBarringInformation, AccessClassBarringInformation_sequence);

  return offset;
}


static const per_sequence_t T_accessBarringInformation_sequence[] = {
  { &hf_lte_rrc_accessBarringForEmergencyCalls, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_accessBarringForSignalling, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_AccessClassBarringInformation },
  { &hf_lte_rrc_accessBarringForOriginatingCalls, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_AccessClassBarringInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_accessBarringInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_accessBarringInformation, T_accessBarringInformation_sequence);

  return offset;
}


static const value_string lte_rrc_T_numberOfRA_Preambles_vals[] = {
  {   0, "n4" },
  {   1, "n8" },
  {   2, "n12" },
  {   3, "n16" },
  {   4, "n20" },
  {   5, "n24" },
  {   6, "n28" },
  {   7, "n32" },
  {   8, "n36" },
  {   9, "n40" },
  {  10, "n44" },
  {  11, "n48" },
  {  12, "n52" },
  {  13, "n56" },
  {  14, "n60" },
  {  15, "n64" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_numberOfRA_Preambles(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_sizeOfRA_PreamblesGroupA_vals[] = {
  {   0, "n4" },
  {   1, "n8" },
  {   2, "n12" },
  {   3, "n16" },
  {   4, "n20" },
  {   5, "n24" },
  {   6, "n28" },
  {   7, "n32" },
  {   8, "n36" },
  {   9, "n40" },
  {  10, "n44" },
  {  11, "n48" },
  {  12, "n52" },
  {  13, "n56" },
  {  14, "n60" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_sizeOfRA_PreamblesGroupA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_messageSizeGroupA_vals[] = {
  {   0, "b56" },
  {   1, "b144" },
  {   2, "b208" },
  {   3, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_messageSizeGroupA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_messagePowerOffsetGroupB_vals[] = {
  {   0, "minusinfinity" },
  {   1, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_messagePowerOffsetGroupB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_preamblesGroupAConfig_sequence[] = {
  { &hf_lte_rrc_sizeOfRA_PreamblesGroupA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_sizeOfRA_PreamblesGroupA },
  { &hf_lte_rrc_messageSizeGroupA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_messageSizeGroupA },
  { &hf_lte_rrc_messagePowerOffsetGroupB, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_messagePowerOffsetGroupB },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_preamblesGroupAConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_preamblesGroupAConfig, T_preamblesGroupAConfig_sequence);

  return offset;
}


static const per_sequence_t T_preambleInformation_sequence[] = {
  { &hf_lte_rrc_numberOfRA_Preambles, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_numberOfRA_Preambles },
  { &hf_lte_rrc_preamblesGroupAConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_preamblesGroupAConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_preambleInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_preambleInformation, T_preambleInformation_sequence);

  return offset;
}


static const value_string lte_rrc_T_powerRampingStep_vals[] = {
  {   0, "dB0" },
  {   1, "dB2" },
  {   2, "dB4" },
  {   3, "dB6" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_powerRampingStep(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_preambleInitialReceivedTargetPower_vals[] = {
  {   0, "dBm-120" },
  {   1, "dBm-118" },
  {   2, "dBm-116" },
  {   3, "dBm-114" },
  {   4, "dBm-112" },
  {   5, "dBm-110" },
  {   6, "dBm-108" },
  {   7, "dBm-106" },
  {   8, "dBm-104" },
  {   9, "dBm-102" },
  {  10, "dBm-100" },
  {  11, "dBm-98" },
  {  12, "dBm-96" },
  {  13, "dBm-94" },
  {  14, "dBm-92" },
  {  15, "dBm-90" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_preambleInitialReceivedTargetPower(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_powerRampingParameters_sequence[] = {
  { &hf_lte_rrc_powerRampingStep, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_powerRampingStep },
  { &hf_lte_rrc_preambleInitialReceivedTargetPower, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_preambleInitialReceivedTargetPower },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_powerRampingParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_powerRampingParameters, T_powerRampingParameters_sequence);

  return offset;
}


static const value_string lte_rrc_T_preambleTransMax_vals[] = {
  {   0, "n3" },
  {   1, "n4" },
  {   2, "n5" },
  {   3, "n6" },
  {   4, "n7" },
  {   5, "n8" },
  {   6, "n10" },
  {   7, "n20" },
  {   8, "n50" },
  {   9, "n100" },
  {  10, "n200" },
  {  11, "spare5" },
  {  12, "spare4" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_preambleTransMax(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_ra_ResponseWindowSize_vals[] = {
  {   0, "sf2" },
  {   1, "sf3" },
  {   2, "sf4" },
  {   3, "sf5" },
  {   4, "sf6" },
  {   5, "sf7" },
  {   6, "sf8" },
  {   7, "sf10" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_ra_ResponseWindowSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_mac_ContentionResolutionTimer_vals[] = {
  {   0, "sf8" },
  {   1, "sf16" },
  {   2, "sf24" },
  {   3, "sf32" },
  {   4, "sf40" },
  {   5, "sf48" },
  {   6, "sf56" },
  {   7, "sf64" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_mac_ContentionResolutionTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_ra_SupervisionInformation_sequence[] = {
  { &hf_lte_rrc_preambleTransMax, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_preambleTransMax },
  { &hf_lte_rrc_ra_ResponseWindowSize, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_ra_ResponseWindowSize },
  { &hf_lte_rrc_mac_ContentionResolutionTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_mac_ContentionResolutionTimer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_ra_SupervisionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_ra_SupervisionInformation, T_ra_SupervisionInformation_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RACH_ConfigCommon_sequence[] = {
  { &hf_lte_rrc_preambleInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_preambleInformation },
  { &hf_lte_rrc_powerRampingParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_powerRampingParameters },
  { &hf_lte_rrc_ra_SupervisionInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_ra_SupervisionInformation },
  { &hf_lte_rrc_maxHARQ_Msg3Tx, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RACH_ConfigCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RACH_ConfigCommon, RACH_ConfigCommon_sequence);

  return offset;
}


static const value_string lte_rrc_T_modificationPeriodCoeff_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  {   2, "n8" },
  {   3, "spare" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_modificationPeriodCoeff(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t BCCH_Configuration_sequence[] = {
  { &hf_lte_rrc_modificationPeriodCoeff, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_modificationPeriodCoeff },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_BCCH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_BCCH_Configuration, BCCH_Configuration_sequence);

  return offset;
}


static const value_string lte_rrc_T_defaultPagingCycle_vals[] = {
  {   0, "rf32" },
  {   1, "rf64" },
  {   2, "rf128" },
  {   3, "rf256" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_defaultPagingCycle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_nB_vals[] = {
  {   0, "fourT" },
  {   1, "twoT" },
  {   2, "oneT" },
  {   3, "halfT" },
  {   4, "quarterT" },
  {   5, "oneEightT" },
  {   6, "onSixteenthT" },
  {   7, "oneThirtySecondT" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_nB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PCCH_Configuration_sequence[] = {
  { &hf_lte_rrc_defaultPagingCycle, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_defaultPagingCycle },
  { &hf_lte_rrc_nB          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_nB },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PCCH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PCCH_Configuration, PCCH_Configuration_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_837(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 837U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_104(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 104U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PRACH_ConfigInfo_sequence[] = {
  { &hf_lte_rrc_prach_ConfigurationIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_63 },
  { &hf_lte_rrc_highSpeedFlag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_zeroCorrelationZoneConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_15 },
  { &hf_lte_rrc_prach_FrequencyOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_104 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PRACH_ConfigInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PRACH_ConfigInfo, PRACH_ConfigInfo_sequence);

  return offset;
}


static const per_sequence_t PRACH_ConfigurationSIB_sequence[] = {
  { &hf_lte_rrc_rootSequenceIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_837 },
  { &hf_lte_rrc_prach_ConfigInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PRACH_ConfigInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PRACH_ConfigurationSIB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PRACH_ConfigurationSIB, PRACH_ConfigurationSIB_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M60_50(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -60, 50U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_p_b_vals[] = {
  {   0, "pb0" },
  {   1, "pb1" },
  {   2, "pb2" },
  {   3, "pb3" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_p_b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PDSCH_ConfigCommon_sequence[] = {
  { &hf_lte_rrc_referenceSignalPower, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M60_50 },
  { &hf_lte_rrc_p_b         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_p_b },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PDSCH_ConfigCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PDSCH_ConfigCommon, PDSCH_ConfigCommon_sequence);

  return offset;
}


static const value_string lte_rrc_T_n_SB_vals[] = {
  {   0, "nsb1" },
  {   1, "nsb2" },
  {   2, "nsb3" },
  {   3, "nsb4" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_n_SB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_hoppingMode_vals[] = {
  {   0, "interSubFrame" },
  {   1, "intraAndInterSubFrame" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_hoppingMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_pusch_ConfigBasic_sequence[] = {
  { &hf_lte_rrc_n_SB        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_n_SB },
  { &hf_lte_rrc_hoppingMode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_hoppingMode },
  { &hf_lte_rrc_pusch_HoppingOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_63 },
  { &hf_lte_rrc_enable64Qam , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_pusch_ConfigBasic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_pusch_ConfigBasic, T_pusch_ConfigBasic_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_29(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 29U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t UL_ReferenceSignalsPUSCH_sequence[] = {
  { &hf_lte_rrc_groupHoppingEnabled, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_groupAssignmentPUSCH, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_29 },
  { &hf_lte_rrc_sequenceHoppingEnabled, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_cyclicShift_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UL_ReferenceSignalsPUSCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UL_ReferenceSignalsPUSCH, UL_ReferenceSignalsPUSCH_sequence);

  return offset;
}


static const per_sequence_t PUSCH_ConfigCommon_sequence[] = {
  { &hf_lte_rrc_pusch_ConfigBasic, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_pusch_ConfigBasic },
  { &hf_lte_rrc_ul_ReferenceSignalsPUSCH, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UL_ReferenceSignalsPUSCH },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PUSCH_ConfigCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PUSCH_ConfigCommon, PUSCH_ConfigCommon_sequence);

  return offset;
}


static const value_string lte_rrc_T_deltaPUCCH_Shift_vals[] = {
  {   0, "ds1" },
  {   1, "ds2" },
  {   2, "ds3" },
  {   3, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_deltaPUCCH_Shift(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PUCCH_ConfigCommon_sequence[] = {
  { &hf_lte_rrc_deltaPUCCH_Shift, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_deltaPUCCH_Shift },
  { &hf_lte_rrc_nRB_CQI     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_63 },
  { &hf_lte_rrc_nCS_AN      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_n1PUCCH_AN  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_2047 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PUCCH_ConfigCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PUCCH_ConfigCommon, PUCCH_ConfigCommon_sequence);

  return offset;
}


static const value_string lte_rrc_T_srsBandwidthConfiguration_vals[] = {
  {   0, "bw0" },
  {   1, "bw1" },
  {   2, "bw2" },
  {   3, "bw3" },
  {   4, "bw4" },
  {   5, "bw5" },
  {   6, "bw6" },
  {   7, "bw7" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_srsBandwidthConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_srsSubframeConfiguration_vals[] = {
  {   0, "sc0" },
  {   1, "sc1" },
  {   2, "sc2" },
  {   3, "sc3" },
  {   4, "sc4" },
  {   5, "sc5" },
  {   6, "sc6" },
  {   7, "sc7" },
  {   8, "sc8" },
  {   9, "sc9" },
  {  10, "sc10" },
  {  11, "sc11" },
  {  12, "sc12" },
  {  13, "sc13" },
  {  14, "sc14" },
  {  15, "sc15" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_srsSubframeConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t SoundingRsUl_ConfigCommon_sequence[] = {
  { &hf_lte_rrc_srsBandwidthConfiguration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_srsBandwidthConfiguration },
  { &hf_lte_rrc_srsSubframeConfiguration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_srsSubframeConfiguration },
  { &hf_lte_rrc_ackNackSrsSimultaneousTransmission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_srsMaxUpPts , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SoundingRsUl_ConfigCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SoundingRsUl_ConfigCommon, SoundingRsUl_ConfigCommon_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M126_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -126, 24U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_alpha_vals[] = {
  {   0, "al0" },
  {   1, "al04" },
  {   2, "al05" },
  {   3, "al06" },
  {   4, "al07" },
  {   5, "al08" },
  {   6, "al09" },
  {   7, "al1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_alpha(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M127_M96(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, -96, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_deltaF_PUCCH_Format1_vals[] = {
  {   0, "deltaF-2" },
  {   1, "deltaF0" },
  {   2, "deltaF2" },
  {   3, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_deltaF_PUCCH_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_deltaF_PUCCH_Format1b_vals[] = {
  {   0, "deltaF1" },
  {   1, "deltaF3" },
  {   2, "deltaF5" },
  {   3, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_deltaF_PUCCH_Format1b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_deltaF_PUCCH_Format2_vals[] = {
  {   0, "deltaF-2" },
  {   1, "deltaF0" },
  {   2, "deltaF1" },
  {   3, "deltaF2" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_deltaF_PUCCH_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_deltaF_PUCCH_Format2a_vals[] = {
  {   0, "deltaF-2" },
  {   1, "deltaF0" },
  {   2, "deltaF2" },
  {   3, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_deltaF_PUCCH_Format2a(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_deltaF_PUCCH_Format2b_vals[] = {
  {   0, "deltaF-2" },
  {   1, "deltaF0" },
  {   2, "deltaF2" },
  {   3, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_deltaF_PUCCH_Format2b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t DeltaFList_PUCCH_sequence[] = {
  { &hf_lte_rrc_deltaF_PUCCH_Format1, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_deltaF_PUCCH_Format1 },
  { &hf_lte_rrc_deltaF_PUCCH_Format1b, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_deltaF_PUCCH_Format1b },
  { &hf_lte_rrc_deltaF_PUCCH_Format2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_deltaF_PUCCH_Format2 },
  { &hf_lte_rrc_deltaF_PUCCH_Format2a, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_deltaF_PUCCH_Format2a },
  { &hf_lte_rrc_deltaF_PUCCH_Format2b, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_deltaF_PUCCH_Format2b },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DeltaFList_PUCCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DeltaFList_PUCCH, DeltaFList_PUCCH_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M1_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1, 6U, NULL, FALSE);

  return offset;
}


static const per_sequence_t UplinkPowerControlCommon_sequence[] = {
  { &hf_lte_rrc_p0_NominalPUSCH, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M126_24 },
  { &hf_lte_rrc_alpha       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_alpha },
  { &hf_lte_rrc_p0_NominalPUCCH, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M127_M96 },
  { &hf_lte_rrc_deltaFList_PUCCH, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DeltaFList_PUCCH },
  { &hf_lte_rrc_deltaPreambleMsg3, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M1_6 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UplinkPowerControlCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UplinkPowerControlCommon, UplinkPowerControlCommon_sequence);

  return offset;
}


static const value_string lte_rrc_UL_CyclicPrefixLength_vals[] = {
  {   0, "len1" },
  {   1, "len2" },
  { 0, NULL }
};


static int
dissect_lte_rrc_UL_CyclicPrefixLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t RadioResourceConfigCommonSIB_sequence[] = {
  { &hf_lte_rrc_rach_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RACH_ConfigCommon },
  { &hf_lte_rrc_bcch_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BCCH_Configuration },
  { &hf_lte_rrc_pcch_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PCCH_Configuration },
  { &hf_lte_rrc_prach_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PRACH_ConfigurationSIB },
  { &hf_lte_rrc_pdsch_Configuration_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PDSCH_ConfigCommon },
  { &hf_lte_rrc_pusch_Configuration_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PUSCH_ConfigCommon },
  { &hf_lte_rrc_pucch_Configuration_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PUCCH_ConfigCommon },
  { &hf_lte_rrc_soundingRsUl_Config_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_SoundingRsUl_ConfigCommon },
  { &hf_lte_rrc_uplinkPowerControl_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UplinkPowerControlCommon },
  { &hf_lte_rrc_ul_CyclicPrefixLength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UL_CyclicPrefixLength },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RadioResourceConfigCommonSIB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RadioResourceConfigCommonSIB, RadioResourceConfigCommonSIB_sequence);

  return offset;
}


static const value_string lte_rrc_T_t300_vals[] = {
  {   0, "ms100" },
  {   1, "ms200" },
  {   2, "ms400" },
  {   3, "ms600" },
  {   4, "ms1000" },
  {   5, "ms1500" },
  {   6, "ms2000" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t300(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t301_vals[] = {
  {   0, "ms100" },
  {   1, "ms200" },
  {   2, "ms400" },
  {   3, "ms600" },
  {   4, "ms1000" },
  {   5, "ms1500" },
  {   6, "ms2000" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t301(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t310_vals[] = {
  {   0, "ms0" },
  {   1, "ms50" },
  {   2, "ms100" },
  {   3, "ms200" },
  {   4, "ms500" },
  {   5, "ms1000" },
  {   6, "ms2000" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t310(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_n310_vals[] = {
  {   0, "spare7" },
  {   1, "spare6" },
  {   2, "spare5" },
  {   3, "spare4" },
  {   4, "spare3" },
  {   5, "spare2" },
  {   6, "spare1" },
  {   7, "spare0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_n310(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t311_vals[] = {
  {   0, "ms1000" },
  {   1, "ms3000" },
  {   2, "ms5000" },
  {   3, "ms10000" },
  {   4, "ms15000" },
  {   5, "ms20000" },
  {   6, "ms30000" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t311(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_n311_vals[] = {
  {   0, "spare7" },
  {   1, "spare6" },
  {   2, "spare5" },
  {   3, "spare4" },
  {   4, "spare3" },
  {   5, "spare2" },
  {   6, "spare1" },
  {   7, "spare0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_n311(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t UE_TimersAndConstants_sequence[] = {
  { &hf_lte_rrc_t300        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t300 },
  { &hf_lte_rrc_t301        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t301 },
  { &hf_lte_rrc_t310        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t310 },
  { &hf_lte_rrc_n310        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_n310 },
  { &hf_lte_rrc_t311        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t311 },
  { &hf_lte_rrc_n311        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_n311 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UE_TimersAndConstants(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UE_TimersAndConstants, UE_TimersAndConstants_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_maxEARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxEARFCN, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_ul_Bandwidth_vals[] = {
  {   0, "n6" },
  {   1, "n15" },
  {   2, "n25" },
  {   3, "n50" },
  {   4, "n75" },
  {   5, "n100" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_ul_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_frequencyInformation_sequence[] = {
  { &hf_lte_rrc_ul_EARFCN   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_maxEARFCN },
  { &hf_lte_rrc_ul_Bandwidth, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_ul_Bandwidth },
  { &hf_lte_rrc_additionalSpectrumEmission, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_31 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_frequencyInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_frequencyInformation, T_frequencyInformation_sequence);

  return offset;
}


static const value_string lte_rrc_T_radioframeAllocationPeriod_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  {   4, "n16" },
  {   5, "n32" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_radioframeAllocationPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL);

  return offset;
}


static const value_string lte_rrc_T_subframeAllocation_vals[] = {
  {   0, "oneFrame" },
  {   1, "fourFrames" },
  { 0, NULL }
};

static const per_choice_t T_subframeAllocation_choice[] = {
  {   0, &hf_lte_rrc_oneFrame    , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_BIT_STRING_SIZE_6 },
  {   1, &hf_lte_rrc_fourFrames  , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_BIT_STRING_SIZE_24 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_subframeAllocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_subframeAllocation, T_subframeAllocation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MBSFN_SubframeConfiguration_item_sequence[] = {
  { &hf_lte_rrc_radioframeAllocationPeriod, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_radioframeAllocationPeriod },
  { &hf_lte_rrc_radioframeAllocationOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_subframeAllocation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_subframeAllocation },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MBSFN_SubframeConfiguration_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MBSFN_SubframeConfiguration_item, MBSFN_SubframeConfiguration_item_sequence);

  return offset;
}


static const per_sequence_t MBSFN_SubframeConfiguration_sequence_of[1] = {
  { &hf_lte_rrc_MBSFN_SubframeConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MBSFN_SubframeConfiguration_item },
};

static int
dissect_lte_rrc_MBSFN_SubframeConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MBSFN_SubframeConfiguration, MBSFN_SubframeConfiguration_sequence_of,
                                                  1, maxMBSFN_Allocations, FALSE);

  return offset;
}


static const value_string lte_rrc_TimeAlignmentTimer_vals[] = {
  {   0, "sf500" },
  {   1, "sf750" },
  {   2, "sf1280" },
  {   3, "sf1920" },
  {   4, "sf2560" },
  {   5, "sf5120" },
  {   6, "sf10240" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_lte_rrc_TimeAlignmentTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t SystemInformationBlockType2_sequence[] = {
  { &hf_lte_rrc_accessBarringInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_accessBarringInformation },
  { &hf_lte_rrc_radioResourceConfigCommon, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RadioResourceConfigCommonSIB },
  { &hf_lte_rrc_ue_TimersAndConstants, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UE_TimersAndConstants },
  { &hf_lte_rrc_frequencyInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_frequencyInformation },
  { &hf_lte_rrc_mbsfn_SubframeConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_MBSFN_SubframeConfiguration },
  { &hf_lte_rrc_timeAlignmentTimerCommon, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_TimeAlignmentTimer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType2, SystemInformationBlockType2_sequence);

  return offset;
}


static const value_string lte_rrc_T_q_Hyst_vals[] = {
  {   0, "dB0" },
  {   1, "dB1" },
  {   2, "dB2" },
  {   3, "dB3" },
  {   4, "dB4" },
  {   5, "dB5" },
  {   6, "dB6" },
  {   7, "dB8" },
  {   8, "dB10" },
  {   9, "dB12" },
  {  10, "dB14" },
  {  11, "dB16" },
  {  12, "dB18" },
  {  13, "dB20" },
  {  14, "dB22" },
  {  15, "dB24" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_q_Hyst(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t_Evalulation_vals[] = {
  {   0, "s30" },
  {   1, "s60" },
  {   2, "s120" },
  {   3, "s180" },
  {   4, "s240" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_Evalulation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t_HystNormal_vals[] = {
  {   0, "s30" },
  {   1, "s60" },
  {   2, "s120" },
  {   3, "s180" },
  {   4, "s240" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_HystNormal(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MobilityStateParameters_sequence[] = {
  { &hf_lte_rrc_t_Evalulation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_Evalulation },
  { &hf_lte_rrc_t_HystNormal, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_HystNormal },
  { &hf_lte_rrc_n_CellChangeMedium, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_16 },
  { &hf_lte_rrc_n_CellChangeHigh, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MobilityStateParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MobilityStateParameters, MobilityStateParameters_sequence);

  return offset;
}


static const value_string lte_rrc_T_q_HystSF_Medium_vals[] = {
  {   0, "db-6" },
  {   1, "dB-4" },
  {   2, "db-2" },
  {   3, "db0" },
  {   4, "db2" },
  {   5, "db4" },
  {   6, "db6" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_q_HystSF_Medium(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_q_HystSF_High_vals[] = {
  {   0, "db-6" },
  {   1, "dB-4" },
  {   2, "db-2" },
  {   3, "db0" },
  {   4, "db2" },
  {   5, "db4" },
  {   6, "db6" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_q_HystSF_High(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_speedDependentScalingParametersHyst_sequence[] = {
  { &hf_lte_rrc_q_HystSF_Medium, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_q_HystSF_Medium },
  { &hf_lte_rrc_q_HystSF_High, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_q_HystSF_High },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_speedDependentScalingParametersHyst(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_speedDependentScalingParametersHyst, T_speedDependentScalingParametersHyst_sequence);

  return offset;
}


static const per_sequence_t T_speedDependentReselection_sequence[] = {
  { &hf_lte_rrc_mobilityStateParameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MobilityStateParameters },
  { &hf_lte_rrc_speedDependentScalingParametersHyst, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_speedDependentScalingParametersHyst },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_speedDependentReselection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_speedDependentReselection, T_speedDependentReselection_sequence);

  return offset;
}


static const per_sequence_t T_cellReselectionInfoCommon_sequence[] = {
  { &hf_lte_rrc_q_Hyst      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_q_Hyst },
  { &hf_lte_rrc_speedDependentReselection, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_speedDependentReselection },
  { &hf_lte_rrc_sameRefSignalsInNeighbour, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_cellReselectionInfoCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_cellReselectionInfoCommon, T_cellReselectionInfoCommon_sequence);

  return offset;
}



static int
dissect_lte_rrc_ReselectionThreshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_cellReselectionServingFreqInfo_sequence[] = {
  { &hf_lte_rrc_s_NonIntraSearch, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_ReselectionThreshold },
  { &hf_lte_rrc_threshServingLow, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReselectionThreshold },
  { &hf_lte_rrc_cellReselectionPriority, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_cellReselectionServingFreqInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_cellReselectionServingFreqInfo, T_cellReselectionServingFreqInfo_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M70_M22(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -70, -22, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_P_Max(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -30, 33U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_MeasurementBandwidth_vals[] = {
  {   0, "mbw6" },
  {   1, "mbw15" },
  {   2, "mbw25" },
  {   3, "mbw50" },
  {   4, "mbw75" },
  {   5, "mbw100" },
  { 0, NULL }
};


static int
dissect_lte_rrc_MeasurementBandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_NeighbourCellConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionEUTRAN_SF_Medium_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionEUTRAN_SF_Medium(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionEUTRAN_SF_High_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionEUTRAN_SF_High(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_speedDependentScalingParameters_sequence[] = {
  { &hf_lte_rrc_t_ReselectionEUTRAN_SF_Medium, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionEUTRAN_SF_Medium },
  { &hf_lte_rrc_t_ReselectionEUTRAN_SF_High, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionEUTRAN_SF_High },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_speedDependentScalingParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_speedDependentScalingParameters, T_speedDependentScalingParameters_sequence);

  return offset;
}


static const per_sequence_t T_intraFreqCellReselectionInfo_sequence[] = {
  { &hf_lte_rrc_q_RxLevMin  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M70_M22 },
  { &hf_lte_rrc_p_Max       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_P_Max },
  { &hf_lte_rrc_s_IntraSearch, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_ReselectionThreshold },
  { &hf_lte_rrc_measurementBandwidth, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_MeasurementBandwidth },
  { &hf_lte_rrc_neighbourCellConfiguration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_NeighbourCellConfiguration },
  { &hf_lte_rrc_t_ReselectionEUTRAN, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_speedDependentScalingParameters, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_speedDependentScalingParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_intraFreqCellReselectionInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_intraFreqCellReselectionInfo, T_intraFreqCellReselectionInfo_sequence);

  return offset;
}


static const per_sequence_t SystemInformationBlockType3_sequence[] = {
  { &hf_lte_rrc_cellReselectionInfoCommon, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cellReselectionInfoCommon },
  { &hf_lte_rrc_cellReselectionServingFreqInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cellReselectionServingFreqInfo },
  { &hf_lte_rrc_intraFreqCellReselectionInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_intraFreqCellReselectionInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType3, SystemInformationBlockType3_sequence);

  return offset;
}



static int
dissect_lte_rrc_PhysicalCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_q_OffsetCell_vals[] = {
  {   0, "dB-24" },
  {   1, "dB-22" },
  {   2, "dB-20" },
  {   3, "dB-18" },
  {   4, "dB-16" },
  {   5, "dB-14" },
  {   6, "dB-12" },
  {   7, "dB-10" },
  {   8, "dB-8" },
  {   9, "dB-6" },
  {  10, "dB-5" },
  {  11, "dB-4" },
  {  12, "dB-3" },
  {  13, "dB-2" },
  {  14, "dB-1" },
  {  15, "dB0" },
  {  16, "dB1" },
  {  17, "dB2" },
  {  18, "dB3" },
  {  19, "dB4" },
  {  20, "dB5" },
  {  21, "dB6" },
  {  22, "dB8" },
  {  23, "dB10" },
  {  24, "dB12" },
  {  25, "dB14" },
  {  26, "dB16" },
  {  27, "dB18" },
  {  28, "dB20" },
  {  29, "dB22" },
  {  30, "dB24" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_q_OffsetCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     31, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t IntraFreqNeighbouringCellList_item_sequence[] = {
  { &hf_lte_rrc_physicalCellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentity },
  { &hf_lte_rrc_q_OffsetCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_q_OffsetCell },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_IntraFreqNeighbouringCellList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_IntraFreqNeighbouringCellList_item, IntraFreqNeighbouringCellList_item_sequence);

  return offset;
}


static const per_sequence_t IntraFreqNeighbouringCellList_sequence_of[1] = {
  { &hf_lte_rrc_IntraFreqNeighbouringCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_IntraFreqNeighbouringCellList_item },
};

static int
dissect_lte_rrc_IntraFreqNeighbouringCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_IntraFreqNeighbouringCellList, IntraFreqNeighbouringCellList_sequence_of,
                                                  1, maxCellIntra, FALSE);

  return offset;
}


static const value_string lte_rrc_T_rangePCI_vals[] = {
  {   0, "n5" },
  {   1, "n10" },
  {   2, "n15" },
  {   3, "n20" },
  {   4, "n25" },
  {   5, "n30" },
  {   6, "n40" },
  {   7, "n50" },
  {   8, "n64" },
  {   9, "n84" },
  {  10, "n100" },
  {  11, "n168" },
  {  12, "n252" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_rangePCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_rangeOfPCI_sequence[] = {
  { &hf_lte_rrc_startPCI    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentity },
  { &hf_lte_rrc_rangePCI    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_rangePCI },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_rangeOfPCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_rangeOfPCI, T_rangeOfPCI_sequence);

  return offset;
}


static const value_string lte_rrc_PhysicalCellIdentityAndRange_vals[] = {
  {   0, "singlePCI" },
  {   1, "rangeOfPCI" },
  { 0, NULL }
};

static const per_choice_t PhysicalCellIdentityAndRange_choice[] = {
  {   0, &hf_lte_rrc_singlePCI   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_PhysicalCellIdentity },
  {   1, &hf_lte_rrc_rangeOfPCI  , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_rangeOfPCI },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_PhysicalCellIdentityAndRange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_PhysicalCellIdentityAndRange, PhysicalCellIdentityAndRange_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t IntraFreqBlacklistedCellList_item_sequence[] = {
  { &hf_lte_rrc_physicalCellIdentityAndRange, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentityAndRange },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_IntraFreqBlacklistedCellList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_IntraFreqBlacklistedCellList_item, IntraFreqBlacklistedCellList_item_sequence);

  return offset;
}


static const per_sequence_t IntraFreqBlacklistedCellList_sequence_of[1] = {
  { &hf_lte_rrc_IntraFreqBlacklistedCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_IntraFreqBlacklistedCellList_item },
};

static int
dissect_lte_rrc_IntraFreqBlacklistedCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_IntraFreqBlacklistedCellList, IntraFreqBlacklistedCellList_sequence_of,
                                                  1, maxCellBlack, FALSE);

  return offset;
}


static const per_sequence_t SystemInformationBlockType4_sequence[] = {
  { &hf_lte_rrc_intraFreqNeighbouringCellList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_IntraFreqNeighbouringCellList },
  { &hf_lte_rrc_intraFreqBlacklistedCellList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_IntraFreqBlacklistedCellList },
  { &hf_lte_rrc_csg_PCI_Range, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_PhysicalCellIdentityAndRange },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType4, SystemInformationBlockType4_sequence);

  return offset;
}



static int
dissect_lte_rrc_EUTRA_DL_CarrierFreq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxEARFCN, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionEUTRAN_SF_Medium_01_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionEUTRAN_SF_Medium_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionEUTRAN_SF_High_01_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionEUTRAN_SF_High_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_speedDependentScalingParameters_01_sequence[] = {
  { &hf_lte_rrc_t_ReselectionEUTRAN_SF_Medium_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionEUTRAN_SF_Medium_01 },
  { &hf_lte_rrc_t_ReselectionEUTRAN_SF_High_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionEUTRAN_SF_High_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_speedDependentScalingParameters_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_speedDependentScalingParameters_01, T_speedDependentScalingParameters_01_sequence);

  return offset;
}


static const value_string lte_rrc_T_q_OffsetFreq_vals[] = {
  {   0, "dB-24" },
  {   1, "dB-22" },
  {   2, "dB-20" },
  {   3, "dB-18" },
  {   4, "dB-16" },
  {   5, "dB-14" },
  {   6, "dB-12" },
  {   7, "dB-10" },
  {   8, "dB-8" },
  {   9, "dB-6" },
  {  10, "dB-5" },
  {  11, "dB-4" },
  {  12, "dB-3" },
  {  13, "dB-2" },
  {  14, "dB-1" },
  {  15, "dB0" },
  {  16, "dB1" },
  {  17, "dB2" },
  {  18, "dB3" },
  {  19, "dB4" },
  {  20, "dB5" },
  {  21, "dB6" },
  {  22, "dB8" },
  {  23, "dB10" },
  {  24, "dB12" },
  {  25, "dB14" },
  {  26, "dB16" },
  {  27, "dB18" },
  {  28, "dB20" },
  {  29, "dB22" },
  {  30, "dB24" },
  {  31, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_q_OffsetFreq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_q_OffsetCell_01_vals[] = {
  {   0, "dB-24" },
  {   1, "dB-22" },
  {   2, "dB-20" },
  {   3, "dB-18" },
  {   4, "dB-16" },
  {   5, "dB-14" },
  {   6, "dB-12" },
  {   7, "dB-10" },
  {   8, "dB-8" },
  {   9, "dB-6" },
  {  10, "dB-5" },
  {  11, "dB-4" },
  {  12, "dB-3" },
  {  13, "dB-2" },
  {  14, "dB-1" },
  {  15, "dB0" },
  {  16, "dB1" },
  {  17, "dB2" },
  {  18, "dB3" },
  {  19, "dB4" },
  {  20, "dB5" },
  {  21, "dB6" },
  {  22, "dB8" },
  {  23, "dB10" },
  {  24, "dB12" },
  {  25, "dB14" },
  {  26, "dB16" },
  {  27, "dB18" },
  {  28, "dB20" },
  {  29, "dB22" },
  {  30, "dB24" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_q_OffsetCell_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     31, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t InterFreqNeighbouringCellList_item_sequence[] = {
  { &hf_lte_rrc_physicalCellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentity },
  { &hf_lte_rrc_q_OffsetCell_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_q_OffsetCell_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_InterFreqNeighbouringCellList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_InterFreqNeighbouringCellList_item, InterFreqNeighbouringCellList_item_sequence);

  return offset;
}


static const per_sequence_t InterFreqNeighbouringCellList_sequence_of[1] = {
  { &hf_lte_rrc_InterFreqNeighbouringCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_InterFreqNeighbouringCellList_item },
};

static int
dissect_lte_rrc_InterFreqNeighbouringCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_InterFreqNeighbouringCellList, InterFreqNeighbouringCellList_sequence_of,
                                                  1, maxCellInter, FALSE);

  return offset;
}


static const per_sequence_t InterFreqBlacklistedCellList_item_sequence[] = {
  { &hf_lte_rrc_physicalCellIdentityAndRange, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentityAndRange },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_InterFreqBlacklistedCellList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_InterFreqBlacklistedCellList_item, InterFreqBlacklistedCellList_item_sequence);

  return offset;
}


static const per_sequence_t InterFreqBlacklistedCellList_sequence_of[1] = {
  { &hf_lte_rrc_InterFreqBlacklistedCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_InterFreqBlacklistedCellList_item },
};

static int
dissect_lte_rrc_InterFreqBlacklistedCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_InterFreqBlacklistedCellList, InterFreqBlacklistedCellList_sequence_of,
                                                  1, maxCellBlack, FALSE);

  return offset;
}


static const per_sequence_t InterFreqCarrierFreqList_item_sequence[] = {
  { &hf_lte_rrc_eutra_CarrierFreq, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_EUTRA_DL_CarrierFreq },
  { &hf_lte_rrc_q_RxLevMin  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M70_M22 },
  { &hf_lte_rrc_p_Max       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_P_Max },
  { &hf_lte_rrc_t_ReselectionEUTRAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_speedDependentScalingParameters_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_speedDependentScalingParameters_01 },
  { &hf_lte_rrc_threshX_High, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReselectionThreshold },
  { &hf_lte_rrc_threshX_Low , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReselectionThreshold },
  { &hf_lte_rrc_measurementBandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasurementBandwidth },
  { &hf_lte_rrc_cellReselectionPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_q_OffsetFreq, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_q_OffsetFreq },
  { &hf_lte_rrc_interFreqNeighbouringCellList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_InterFreqNeighbouringCellList },
  { &hf_lte_rrc_interFreqBlacklistedCellList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_InterFreqBlacklistedCellList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_InterFreqCarrierFreqList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_InterFreqCarrierFreqList_item, InterFreqCarrierFreqList_item_sequence);

  return offset;
}


static const per_sequence_t InterFreqCarrierFreqList_sequence_of[1] = {
  { &hf_lte_rrc_InterFreqCarrierFreqList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_InterFreqCarrierFreqList_item },
};

static int
dissect_lte_rrc_InterFreqCarrierFreqList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_InterFreqCarrierFreqList, InterFreqCarrierFreqList_sequence_of,
                                                  1, maxFreq, FALSE);

  return offset;
}


static const per_sequence_t SystemInformationBlockType5_sequence[] = {
  { &hf_lte_rrc_interFreqCarrierFreqList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_InterFreqCarrierFreqList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType5, SystemInformationBlockType5_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}


static const per_sequence_t UTRA_DL_CarrierFreq_sequence[] = {
  { &hf_lte_rrc_uarfcn_DL   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_16383 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UTRA_DL_CarrierFreq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UTRA_DL_CarrierFreq, UTRA_DL_CarrierFreq_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M50_33(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -50, 33U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M24_0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -24, 0U, NULL, FALSE);

  return offset;
}


static const per_sequence_t UTRA_FDD_CarrierFreqList_item_sequence[] = {
  { &hf_lte_rrc_utra_CarrierFreq, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_DL_CarrierFreq },
  { &hf_lte_rrc_utra_CellReselectionPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_threshX_High, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReselectionThreshold },
  { &hf_lte_rrc_threshX_Low , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReselectionThreshold },
  { &hf_lte_rrc_q_RxLevMin  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M70_M22 },
  { &hf_lte_rrc_maxAllowedTxPower, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M50_33 },
  { &hf_lte_rrc_q_QualMin   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M24_0 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UTRA_FDD_CarrierFreqList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UTRA_FDD_CarrierFreqList_item, UTRA_FDD_CarrierFreqList_item_sequence);

  return offset;
}


static const per_sequence_t UTRA_FDD_CarrierFreqList_sequence_of[1] = {
  { &hf_lte_rrc_UTRA_FDD_CarrierFreqList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_FDD_CarrierFreqList_item },
};

static int
dissect_lte_rrc_UTRA_FDD_CarrierFreqList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_UTRA_FDD_CarrierFreqList, UTRA_FDD_CarrierFreqList_sequence_of,
                                                  1, maxUTRA_FDD_Carrier, FALSE);

  return offset;
}


static const per_sequence_t UTRA_TDD_CarrierFreqList_item_sequence[] = {
  { &hf_lte_rrc_utra_CarrierFreq, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_DL_CarrierFreq },
  { &hf_lte_rrc_utra_CellReselectionPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_threshX_High, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReselectionThreshold },
  { &hf_lte_rrc_threshX_Low , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReselectionThreshold },
  { &hf_lte_rrc_q_RxLevMin  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M70_M22 },
  { &hf_lte_rrc_maxAllowedTxPower, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M50_33 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UTRA_TDD_CarrierFreqList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UTRA_TDD_CarrierFreqList_item, UTRA_TDD_CarrierFreqList_item_sequence);

  return offset;
}


static const per_sequence_t UTRA_TDD_CarrierFreqList_sequence_of[1] = {
  { &hf_lte_rrc_UTRA_TDD_CarrierFreqList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_TDD_CarrierFreqList_item },
};

static int
dissect_lte_rrc_UTRA_TDD_CarrierFreqList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_UTRA_TDD_CarrierFreqList, UTRA_TDD_CarrierFreqList_sequence_of,
                                                  1, maxUTRA_TDD_Carrier, FALSE);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionUTRA_SF_Medium_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionUTRA_SF_Medium(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionUTRA_SF_High_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionUTRA_SF_High(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_speedDependentScalingParameters_02_sequence[] = {
  { &hf_lte_rrc_t_ReselectionUTRA_SF_Medium, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionUTRA_SF_Medium },
  { &hf_lte_rrc_t_ReselectionUTRA_SF_High, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionUTRA_SF_High },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_speedDependentScalingParameters_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_speedDependentScalingParameters_02, T_speedDependentScalingParameters_02_sequence);

  return offset;
}


static const per_sequence_t SystemInformationBlockType6_sequence[] = {
  { &hf_lte_rrc_utra_FDD_CarrierFreqList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_UTRA_FDD_CarrierFreqList },
  { &hf_lte_rrc_utra_TDD_CarrierFreqList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_UTRA_TDD_CarrierFreqList },
  { &hf_lte_rrc_t_ReselectionUTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_speedDependentScalingParameters_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_speedDependentScalingParameters_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType6, SystemInformationBlockType6_sequence);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionGERAN_SF_Medium_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionGERAN_SF_Medium(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionGERAN_SF_High_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionGERAN_SF_High(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_speedDependentScalingParameters_03_sequence[] = {
  { &hf_lte_rrc_t_ReselectionGERAN_SF_Medium, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionGERAN_SF_Medium },
  { &hf_lte_rrc_t_ReselectionGERAN_SF_High, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionGERAN_SF_High },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_speedDependentScalingParameters_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_speedDependentScalingParameters_03, T_speedDependentScalingParameters_03_sequence);

  return offset;
}



static int
dissect_lte_rrc_GERAN_ARFCN_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_GERAN_BandIndicator_vals[] = {
  {   0, "dcs1800" },
  {   1, "pcs1900" },
  { 0, NULL }
};


static int
dissect_lte_rrc_GERAN_BandIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ExplicitListOfARFCNs_sequence_of[1] = {
  { &hf_lte_rrc_ExplicitListOfARFCNs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_ARFCN_Value },
};

static int
dissect_lte_rrc_ExplicitListOfARFCNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_ExplicitListOfARFCNs, ExplicitListOfARFCNs_sequence_of,
                                                  0, 31, FALSE);

  return offset;
}


static const per_sequence_t T_equallySpacedARFCNs_sequence[] = {
  { &hf_lte_rrc_arfcn_Spacing, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_8 },
  { &hf_lte_rrc_numberOfFollowingARFCNs, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_31 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_equallySpacedARFCNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_equallySpacedARFCNs, T_equallySpacedARFCNs_sequence);

  return offset;
}



static int
dissect_lte_rrc_OCTET_STRING_SIZE_1_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 16, FALSE, NULL);

  return offset;
}


static const value_string lte_rrc_T_followingARFCNs_vals[] = {
  {   0, "explicitListOfARFCNs" },
  {   1, "equallySpacedARFCNs" },
  {   2, "variableBitMapOfARFCNs" },
  { 0, NULL }
};

static const per_choice_t T_followingARFCNs_choice[] = {
  {   0, &hf_lte_rrc_explicitListOfARFCNs, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ExplicitListOfARFCNs },
  {   1, &hf_lte_rrc_equallySpacedARFCNs, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_equallySpacedARFCNs },
  {   2, &hf_lte_rrc_variableBitMapOfARFCNs, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_OCTET_STRING_SIZE_1_16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_followingARFCNs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_followingARFCNs, T_followingARFCNs_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GERAN_CarrierFreqList_sequence[] = {
  { &hf_lte_rrc_startingARFCN, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_ARFCN_Value },
  { &hf_lte_rrc_bandIndicator, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_BandIndicator },
  { &hf_lte_rrc_followingARFCNs, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_followingARFCNs },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_GERAN_CarrierFreqList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_GERAN_CarrierFreqList, GERAN_CarrierFreqList_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_39(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 39U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_geran_BCCH_Configuration_sequence[] = {
  { &hf_lte_rrc_geran_CellReselectionPriority, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_ncc_Permitted, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_8 },
  { &hf_lte_rrc_q_RxLevMin_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_31 },
  { &hf_lte_rrc_p_MaxGERAN  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_39 },
  { &hf_lte_rrc_threshX_High, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReselectionThreshold },
  { &hf_lte_rrc_threshX_Low , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReselectionThreshold },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_geran_BCCH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_geran_BCCH_Configuration, T_geran_BCCH_Configuration_sequence);

  return offset;
}


static const per_sequence_t GERAN_BCCH_Group_sequence[] = {
  { &hf_lte_rrc_geran_BCCH_FrequencyGroup, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_CarrierFreqList },
  { &hf_lte_rrc_geran_BCCH_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_geran_BCCH_Configuration },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_GERAN_BCCH_Group(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_GERAN_BCCH_Group, GERAN_BCCH_Group_sequence);

  return offset;
}


static const per_sequence_t GERAN_NeigbourFreqList_sequence_of[1] = {
  { &hf_lte_rrc_GERAN_NeigbourFreqList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_BCCH_Group },
};

static int
dissect_lte_rrc_GERAN_NeigbourFreqList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_GERAN_NeigbourFreqList, GERAN_NeigbourFreqList_sequence_of,
                                                  1, maxGNFG, FALSE);

  return offset;
}


static const per_sequence_t SystemInformationBlockType7_sequence[] = {
  { &hf_lte_rrc_t_ReselectionGERAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_speedDependentScalingParameters_03, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_speedDependentScalingParameters_03 },
  { &hf_lte_rrc_geran_NeigbourFreqList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_GERAN_NeigbourFreqList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType7, SystemInformationBlockType7_sequence);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_39(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     39, 39, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_49(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     49, 49, FALSE, NULL);

  return offset;
}


static const value_string lte_rrc_T_cdma_SystemTime_vals[] = {
  {   0, "cdma-SynchronousSystemTime" },
  {   1, "cdma-AsynchronousSystemTime" },
  { 0, NULL }
};

static const per_choice_t T_cdma_SystemTime_choice[] = {
  {   0, &hf_lte_rrc_cdma_SynchronousSystemTime, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_BIT_STRING_SIZE_39 },
  {   1, &hf_lte_rrc_cdma_AsynchronousSystemTime, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_BIT_STRING_SIZE_49 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_cdma_SystemTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_cdma_SystemTime, T_cdma_SystemTime_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CDMA2000_SystemTimeInfo_sequence[] = {
  { &hf_lte_rrc_cdma_EUTRA_Synchronisation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_cdma_SystemTime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cdma_SystemTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CDMA2000_SystemTimeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CDMA2000_SystemTimeInfo, CDMA2000_SystemTimeInfo_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t HRPD_SecondaryPreRegistrationZoneIdList_item_sequence[] = {
  { &hf_lte_rrc_hrpd_SecondaryPreRegistrationZoneId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList_item, HRPD_SecondaryPreRegistrationZoneIdList_item_sequence);

  return offset;
}


static const per_sequence_t HRPD_SecondaryPreRegistrationZoneIdList_sequence_of[1] = {
  { &hf_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList_item },
};

static int
dissect_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList, HRPD_SecondaryPreRegistrationZoneIdList_sequence_of,
                                                  1, 2, FALSE);

  return offset;
}


static const per_sequence_t HRPD_PreRegistrationInfo_sequence[] = {
  { &hf_lte_rrc_hrpd_PreRegistrationAllowed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_hrpd_PreRegistrationZoneId, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_255 },
  { &hf_lte_rrc_hrpd_SecondaryPreRegistrationZoneIdList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_HRPD_PreRegistrationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_HRPD_PreRegistrationInfo, HRPD_PreRegistrationInfo_sequence);

  return offset;
}


static const value_string lte_rrc_CDMA2000_Bandclass_vals[] = {
  {   0, "bc0" },
  {   1, "bc1" },
  {   2, "bc2" },
  {   3, "bc3" },
  {   4, "bc4" },
  {   5, "bc5" },
  {   6, "bc6" },
  {   7, "bc7" },
  {   8, "bc8" },
  {   9, "bc9" },
  {  10, "bc10" },
  {  11, "bc11" },
  {  12, "bc12" },
  {  13, "bc13" },
  {  14, "bc14" },
  {  15, "bc15" },
  {  16, "bc16" },
  {  17, "bc17" },
  {  18, "spare14" },
  {  19, "spare13" },
  {  20, "spare12" },
  {  21, "spare11" },
  {  22, "spare10" },
  {  23, "spare9" },
  {  24, "spare8" },
  {  25, "spare7" },
  {  26, "spare6" },
  {  27, "spare5" },
  {  28, "spare4" },
  {  29, "spare3" },
  {  30, "spare2" },
  {  31, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_CDMA2000_Bandclass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t HRPD_BandClassList_item_sequence[] = {
  { &hf_lte_rrc_hrpd_BandClass, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Bandclass },
  { &hf_lte_rrc_hrpd_CellReselectionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_threshX_High_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_63 },
  { &hf_lte_rrc_threshX_Low_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_HRPD_BandClassList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_HRPD_BandClassList_item, HRPD_BandClassList_item_sequence);

  return offset;
}


static const per_sequence_t HRPD_BandClassList_sequence_of[1] = {
  { &hf_lte_rrc_HRPD_BandClassList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_HRPD_BandClassList_item },
};

static int
dissect_lte_rrc_HRPD_BandClassList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_HRPD_BandClassList, HRPD_BandClassList_sequence_of,
                                                  1, maxCDMA_BandClass, FALSE);

  return offset;
}



static int
dissect_lte_rrc_CDMA2000_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxPNOffset, NULL, FALSE);

  return offset;
}


static const per_sequence_t CDMA2000_CellIdList_sequence_of[1] = {
  { &hf_lte_rrc_CDMA2000_CellIdList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_CellIdentity },
};

static int
dissect_lte_rrc_CDMA2000_CellIdList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_CDMA2000_CellIdList, CDMA2000_CellIdList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t CDMA2000_NeighbourCellsPerBandclass_item_sequence[] = {
  { &hf_lte_rrc_frequency   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_2047 },
  { &hf_lte_rrc_cellIdList  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_CellIdList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CDMA2000_NeighbourCellsPerBandclass_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CDMA2000_NeighbourCellsPerBandclass_item, CDMA2000_NeighbourCellsPerBandclass_item_sequence);

  return offset;
}


static const per_sequence_t CDMA2000_NeighbourCellsPerBandclass_sequence_of[1] = {
  { &hf_lte_rrc_CDMA2000_NeighbourCellsPerBandclass_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_NeighbourCellsPerBandclass_item },
};

static int
dissect_lte_rrc_CDMA2000_NeighbourCellsPerBandclass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_CDMA2000_NeighbourCellsPerBandclass, CDMA2000_NeighbourCellsPerBandclass_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t CDMA2000_NeighbourCellList_item_sequence[] = {
  { &hf_lte_rrc_bandClass   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Bandclass },
  { &hf_lte_rrc_frequencyList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_NeighbourCellsPerBandclass },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CDMA2000_NeighbourCellList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CDMA2000_NeighbourCellList_item, CDMA2000_NeighbourCellList_item_sequence);

  return offset;
}


static const per_sequence_t CDMA2000_NeighbourCellList_sequence_of[1] = {
  { &hf_lte_rrc_CDMA2000_NeighbourCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_NeighbourCellList_item },
};

static int
dissect_lte_rrc_CDMA2000_NeighbourCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_CDMA2000_NeighbourCellList, CDMA2000_NeighbourCellList_sequence_of,
                                                  1, 16, FALSE);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionCDMA_HRPD_SF_Medium_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionCDMA_HRPD_SF_Medium(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionCDMA_HRPD_SF_High_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionCDMA_HRPD_SF_High(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_speedDependentScalingParameters_04_sequence[] = {
  { &hf_lte_rrc_t_ReselectionCDMA_HRPD_SF_Medium, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionCDMA_HRPD_SF_Medium },
  { &hf_lte_rrc_t_ReselectionCDMA_HRPD_SF_High, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionCDMA_HRPD_SF_High },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_speedDependentScalingParameters_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_speedDependentScalingParameters_04, T_speedDependentScalingParameters_04_sequence);

  return offset;
}


static const per_sequence_t T_hrpd_CellReselectionParameters_sequence[] = {
  { &hf_lte_rrc_hrpd_BandClassList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_HRPD_BandClassList },
  { &hf_lte_rrc_hrpd_NeighborCellList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_NeighbourCellList },
  { &hf_lte_rrc_t_ReselectionCDMA_HRPD, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_speedDependentScalingParameters_04, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_speedDependentScalingParameters_04 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_hrpd_CellReselectionParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_hrpd_CellReselectionParameters, T_hrpd_CellReselectionParameters_sequence);

  return offset;
}


static const per_sequence_t T_hrpd_Parameters_sequence[] = {
  { &hf_lte_rrc_hrpd_PreRegistrationInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_HRPD_PreRegistrationInfo },
  { &hf_lte_rrc_hrpd_CellReselectionParameters, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_hrpd_CellReselectionParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_hrpd_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_hrpd_Parameters, T_hrpd_Parameters_sequence);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     15, 15, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     7, 7, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     12, 12, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     3, 3, FALSE, NULL);

  return offset;
}


static const per_sequence_t OneXRTT_RegistrationParameters_sequence[] = {
  { &hf_lte_rrc_oneXRTT_SID , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_15 },
  { &hf_lte_rrc_oneXRTT_NID , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { &hf_lte_rrc_oneXRTT_MultipleSID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_oneXRTT_MultipleNID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_oneXRTT_HomeReg, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_oneXRTT_ForeignSIDReg, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_oneXRTT_ForeignNIDReg, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_oneXRTT_ParameterReg, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_oneXRTT_RegistrationPeriod, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_7 },
  { &hf_lte_rrc_oneXRTT_RegistrationZone, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_12 },
  { &hf_lte_rrc_oneXRTT_TotalZone, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_3 },
  { &hf_lte_rrc_oneXRTT_ZoneTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_OneXRTT_RegistrationParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_OneXRTT_RegistrationParameters, OneXRTT_RegistrationParameters_sequence);

  return offset;
}


static const per_sequence_t OneXRTT_CSFB_RegistrationInfo_sequence[] = {
  { &hf_lte_rrc_oneXRTT_CSFB_RegistrationAllowed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_oneXRTT_RegistrationParameters, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_OneXRTT_RegistrationParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_OneXRTT_CSFB_RegistrationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_OneXRTT_CSFB_RegistrationInfo, OneXRTT_CSFB_RegistrationInfo_sequence);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_42(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     42, 42, FALSE, NULL);

  return offset;
}


static const per_sequence_t OneXRTT_BandClassList_item_sequence[] = {
  { &hf_lte_rrc_oneXRTT_BandClass, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Bandclass },
  { &hf_lte_rrc_oneXRTT_CellReselectionPriority, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_threshX_High_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_63 },
  { &hf_lte_rrc_threshX_Low_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_OneXRTT_BandClassList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_OneXRTT_BandClassList_item, OneXRTT_BandClassList_item_sequence);

  return offset;
}


static const per_sequence_t OneXRTT_BandClassList_sequence_of[1] = {
  { &hf_lte_rrc_OneXRTT_BandClassList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OneXRTT_BandClassList_item },
};

static int
dissect_lte_rrc_OneXRTT_BandClassList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_OneXRTT_BandClassList, OneXRTT_BandClassList_sequence_of,
                                                  1, maxCDMA_BandClass, FALSE);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionCDMA_OneXRTT_SF_Medium_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionCDMA_OneXRTT_SF_Medium(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_t_ReselectionCDMA_OneXRTT_SF_High_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t_ReselectionCDMA_OneXRTT_SF_High(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_speedDependentScalingParameters_05_sequence[] = {
  { &hf_lte_rrc_t_ReselectionCDMA_OneXRTT_SF_Medium, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionCDMA_OneXRTT_SF_Medium },
  { &hf_lte_rrc_t_ReselectionCDMA_OneXRTT_SF_High, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t_ReselectionCDMA_OneXRTT_SF_High },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_speedDependentScalingParameters_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_speedDependentScalingParameters_05, T_speedDependentScalingParameters_05_sequence);

  return offset;
}


static const per_sequence_t T_oneXRTT_CellReselectionParameters_sequence[] = {
  { &hf_lte_rrc_oneXRTT_BandClassList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OneXRTT_BandClassList },
  { &hf_lte_rrc_oneXRTT_NeighborCellList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_NeighbourCellList },
  { &hf_lte_rrc_t_ReselectionCDMA_OneXRTT, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { &hf_lte_rrc_speedDependentScalingParameters_05, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_speedDependentScalingParameters_05 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_oneXRTT_CellReselectionParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_oneXRTT_CellReselectionParameters, T_oneXRTT_CellReselectionParameters_sequence);

  return offset;
}


static const per_sequence_t T_oneXRTT_Parameters_sequence[] = {
  { &hf_lte_rrc_oneXRTT_CSFB_RegistrationInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_OneXRTT_CSFB_RegistrationInfo },
  { &hf_lte_rrc_oneXRTT_LongCodeState, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_BIT_STRING_SIZE_42 },
  { &hf_lte_rrc_oneXRTT_CellReselectionParameters, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_oneXRTT_CellReselectionParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_oneXRTT_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_oneXRTT_Parameters, T_oneXRTT_Parameters_sequence);

  return offset;
}


static const per_sequence_t SystemInformationBlockType8_sequence[] = {
  { &hf_lte_rrc_cdma2000_SystemTimeInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_CDMA2000_SystemTimeInfo },
  { &hf_lte_rrc_searchWindowSize, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_15 },
  { &hf_lte_rrc_hrpd_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_hrpd_Parameters },
  { &hf_lte_rrc_oneXRTT_Parameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_oneXRTT_Parameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType8, SystemInformationBlockType8_sequence);

  return offset;
}



static int
dissect_lte_rrc_OCTET_STRING_SIZE_1_48(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 48, FALSE, NULL);

  return offset;
}


static const per_sequence_t SystemInformationBlockType9_sequence[] = {
  { &hf_lte_rrc_hnbid       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OCTET_STRING_SIZE_1_48 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType9, SystemInformationBlockType9_sequence);

  return offset;
}



static int
dissect_lte_rrc_OCTET_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_OCTET_STRING_SIZE_50(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       50, 50, FALSE, NULL);

  return offset;
}


static const per_sequence_t SystemInformationBlockType10_sequence[] = {
  { &hf_lte_rrc_messageIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { &hf_lte_rrc_serialNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { &hf_lte_rrc_warningType , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OCTET_STRING_SIZE_2 },
  { &hf_lte_rrc_warningSecurityInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_OCTET_STRING_SIZE_50 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType10, SystemInformationBlockType10_sequence);

  return offset;
}


static const value_string lte_rrc_T_warningMessageSegmentType_vals[] = {
  {   0, "notLastSegment" },
  {   1, "lastSegment" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_warningMessageSegmentType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_OCTET_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t SystemInformationBlockType11_sequence[] = {
  { &hf_lte_rrc_messageIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { &hf_lte_rrc_serialNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { &hf_lte_rrc_warningMessageSegmentType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_warningMessageSegmentType },
  { &hf_lte_rrc_warningMessageSegmentNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_63 },
  { &hf_lte_rrc_warningMessageSegment, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OCTET_STRING },
  { &hf_lte_rrc_dataCodingScheme, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OCTET_STRING_SIZE_1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType11, SystemInformationBlockType11_sequence);

  return offset;
}


static const value_string lte_rrc_T_sib_TypeAndInfo_item_vals[] = {
  {   0, "sib2" },
  {   1, "sib3" },
  {   2, "sib4" },
  {   3, "sib5" },
  {   4, "sib6" },
  {   5, "sib7" },
  {   6, "sib8" },
  {   7, "sib9" },
  {   8, "sib10" },
  {   9, "sib11" },
  { 0, NULL }
};

static const per_choice_t T_sib_TypeAndInfo_item_choice[] = {
  {   0, &hf_lte_rrc_sib2        , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_SystemInformationBlockType2 },
  {   1, &hf_lte_rrc_sib3        , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_SystemInformationBlockType3 },
  {   2, &hf_lte_rrc_sib4        , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_SystemInformationBlockType4 },
  {   3, &hf_lte_rrc_sib5        , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_SystemInformationBlockType5 },
  {   4, &hf_lte_rrc_sib6        , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_SystemInformationBlockType6 },
  {   5, &hf_lte_rrc_sib7        , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_SystemInformationBlockType7 },
  {   6, &hf_lte_rrc_sib8        , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_SystemInformationBlockType8 },
  {   7, &hf_lte_rrc_sib9        , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_SystemInformationBlockType9 },
  {   8, &hf_lte_rrc_sib10       , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_SystemInformationBlockType10 },
  {   9, &hf_lte_rrc_sib11       , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_SystemInformationBlockType11 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_sib_TypeAndInfo_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_sib_TypeAndInfo_item, T_sib_TypeAndInfo_item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_sib_TypeAndInfo_sequence_of[1] = {
  { &hf_lte_rrc_sib_TypeAndInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_sib_TypeAndInfo_item },
};

static int
dissect_lte_rrc_T_sib_TypeAndInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_T_sib_TypeAndInfo, T_sib_TypeAndInfo_sequence_of,
                                                  1, maxSIB, FALSE);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_21_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_21, T_nonCriticalExtension_21_sequence);

  return offset;
}


static const per_sequence_t SystemInformation_r8_IEs_sequence[] = {
  { &hf_lte_rrc_sib_TypeAndInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_sib_TypeAndInfo },
  { &hf_lte_rrc_nonCriticalExtension_21, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_21 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformation_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformation_r8_IEs, SystemInformation_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_22_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_22(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_22, T_criticalExtensionsFuture_22_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_22_vals[] = {
  {   0, "systemInformation-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_22_choice[] = {
  {   0, &hf_lte_rrc_systemInformation_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_SystemInformation_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_22, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_22 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_22(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_22, T_criticalExtensions_22_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SystemInformation_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_22, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_22 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "SystemInformation");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformation, SystemInformation_sequence);

  return offset;
}



static int
dissect_lte_rrc_MCC_MNC_Digit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MCC_sequence_of[1] = {
  { &hf_lte_rrc_MCC_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MCC_MNC_Digit },
};

static int
dissect_lte_rrc_MCC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MCC, MCC_sequence_of,
                                                  3, 3, FALSE);

  return offset;
}


static const per_sequence_t MNC_sequence_of[1] = {
  { &hf_lte_rrc_MNC_item    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MCC_MNC_Digit },
};

static int
dissect_lte_rrc_MNC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MNC, MNC_sequence_of,
                                                  2, 3, FALSE);

  return offset;
}


static const per_sequence_t PLMN_Identity_sequence[] = {
  { &hf_lte_rrc_mcc         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_MCC },
  { &hf_lte_rrc_mnc         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MNC },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PLMN_Identity, PLMN_Identity_sequence);

  return offset;
}


static const value_string lte_rrc_T_cellReservedForOperatorUse_vals[] = {
  {   0, "reserved" },
  {   1, "notReserved" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_cellReservedForOperatorUse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PLMN_IdentityList_item_sequence[] = {
  { &hf_lte_rrc_plmn_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PLMN_Identity },
  { &hf_lte_rrc_cellReservedForOperatorUse, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cellReservedForOperatorUse },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PLMN_IdentityList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PLMN_IdentityList_item, PLMN_IdentityList_item_sequence);

  return offset;
}


static const per_sequence_t PLMN_IdentityList_sequence_of[1] = {
  { &hf_lte_rrc_PLMN_IdentityList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PLMN_IdentityList_item },
};

static int
dissect_lte_rrc_PLMN_IdentityList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_PLMN_IdentityList, PLMN_IdentityList_sequence_of,
                                                  1, 6, FALSE);

  return offset;
}



static int
dissect_lte_rrc_TrackingAreaCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL);

  return offset;
}


static const value_string lte_rrc_T_cellBarred_vals[] = {
  {   0, "barred" },
  {   1, "notBarred" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_cellBarred(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_intraFrequencyReselection_vals[] = {
  {   0, "allowed" },
  {   1, "notAllowed" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_intraFrequencyReselection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_27(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     27, 27, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_cellAccessRelatedInformation_sequence[] = {
  { &hf_lte_rrc_plmn_IdentityList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PLMN_IdentityList },
  { &hf_lte_rrc_trackingAreaCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_TrackingAreaCode },
  { &hf_lte_rrc_cellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CellIdentity },
  { &hf_lte_rrc_cellBarred  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cellBarred },
  { &hf_lte_rrc_intraFrequencyReselection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_intraFrequencyReselection },
  { &hf_lte_rrc_csg_Indication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_csg_Identity, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_BIT_STRING_SIZE_27 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_cellAccessRelatedInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_cellAccessRelatedInformation, T_cellAccessRelatedInformation_sequence);

  return offset;
}


static const per_sequence_t T_cellSelectionInfo_sequence[] = {
  { &hf_lte_rrc_q_RxLevMin  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M70_M22 },
  { &hf_lte_rrc_q_RxLevMinOffset, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_1_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_cellSelectionInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_cellSelectionInfo, T_cellSelectionInfo_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 64U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_si_Periodicity_vals[] = {
  {   0, "rf8" },
  {   1, "rf16" },
  {   2, "rf32" },
  {   3, "rf64" },
  {   4, "rf128" },
  {   5, "rf256" },
  {   6, "rf512" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_si_Periodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_SIB_Type_vals[] = {
  {   0, "sibType3" },
  {   1, "sibType4" },
  {   2, "sibType5" },
  {   3, "sibType6" },
  {   4, "sibType7" },
  {   5, "sibType8" },
  {   6, "sibType9" },
  {   7, "sibType10" },
  {   8, "sibType11" },
  {   9, "spare7" },
  {  10, "spare6" },
  {  11, "spare5" },
  {  12, "spare4" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_SIB_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SIB_MappingInfo_sequence_of[1] = {
  { &hf_lte_rrc_SIB_MappingInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SIB_Type },
};

static int
dissect_lte_rrc_SIB_MappingInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SIB_MappingInfo, SIB_MappingInfo_sequence_of,
                                                  0, maxSIB_1, FALSE);

  return offset;
}


static const per_sequence_t SchedulingInformation_item_sequence[] = {
  { &hf_lte_rrc_si_Periodicity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_si_Periodicity },
  { &hf_lte_rrc_sib_MappingInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SIB_MappingInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SchedulingInformation_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SchedulingInformation_item, SchedulingInformation_item_sequence);

  return offset;
}


static const per_sequence_t SchedulingInformation_sequence_of[1] = {
  { &hf_lte_rrc_SchedulingInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SchedulingInformation_item },
};

static int
dissect_lte_rrc_SchedulingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SchedulingInformation, SchedulingInformation_sequence_of,
                                                  1, maxSI_Message, FALSE);

  return offset;
}


static const value_string lte_rrc_T_subframeAssignment_vals[] = {
  {   0, "sa0" },
  {   1, "sa1" },
  {   2, "sa2" },
  {   3, "sa3" },
  {   4, "sa4" },
  {   5, "sa5" },
  {   6, "sa6" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_subframeAssignment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_specialSubframePatterns_vals[] = {
  {   0, "ssp0" },
  {   1, "ssp1" },
  {   2, "ssp2" },
  {   3, "ssp3" },
  {   4, "ssp4" },
  {   5, "ssp5" },
  {   6, "ssp6" },
  {   7, "ssp7" },
  {   8, "ssp8" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_specialSubframePatterns(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t TDD_Configuration_sequence[] = {
  { &hf_lte_rrc_subframeAssignment, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_subframeAssignment },
  { &hf_lte_rrc_specialSubframePatterns, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_specialSubframePatterns },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_TDD_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_TDD_Configuration, TDD_Configuration_sequence);

  return offset;
}


static const value_string lte_rrc_T_si_WindowLength_vals[] = {
  {   0, "ms1" },
  {   1, "ms2" },
  {   2, "ms5" },
  {   3, "ms10" },
  {   4, "ms15" },
  {   5, "ms20" },
  {   6, "ms40" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_si_WindowLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_22_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_22(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_22, T_nonCriticalExtension_22_sequence);

  return offset;
}


static const per_sequence_t SystemInformationBlockType1_sequence[] = {
  { &hf_lte_rrc_cellAccessRelatedInformation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cellAccessRelatedInformation },
  { &hf_lte_rrc_cellSelectionInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cellSelectionInfo },
  { &hf_lte_rrc_p_Max       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_P_Max },
  { &hf_lte_rrc_frequencyBandIndicator, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_64 },
  { &hf_lte_rrc_schedulingInformation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SchedulingInformation },
  { &hf_lte_rrc_tdd_Configuration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_TDD_Configuration },
  { &hf_lte_rrc_si_WindowLength, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_si_WindowLength },
  { &hf_lte_rrc_systemInformationValueTag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_31 },
  { &hf_lte_rrc_nonCriticalExtension_22, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_22 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SystemInformationBlockType1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "SystemInformationBlockType1");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SystemInformationBlockType1, SystemInformationBlockType1_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_vals[] = {
  {   0, "systemInformation" },
  {   1, "systemInformationBlockType1" },
  { 0, NULL }
};

static const per_choice_t T_c1_choice[] = {
  {   0, &hf_lte_rrc_systemInformation, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_SystemInformation },
  {   1, &hf_lte_rrc_systemInformationBlockType1, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_SystemInformationBlockType1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1, T_c1_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_messageClassExtension_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_messageClassExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_messageClassExtension, T_messageClassExtension_sequence);

  return offset;
}


static const value_string lte_rrc_BCCH_DL_SCH_MessageType_vals[] = {
  {   0, "c1" },
  {   1, "messageClassExtension" },
  { 0, NULL }
};

static const per_choice_t BCCH_DL_SCH_MessageType_choice[] = {
  {   0, &hf_lte_rrc_c1          , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1 },
  {   1, &hf_lte_rrc_messageClassExtension, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_messageClassExtension },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_BCCH_DL_SCH_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_BCCH_DL_SCH_MessageType, BCCH_DL_SCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BCCH_DL_SCH_Message_sequence[] = {
  { &hf_lte_rrc_message_01  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BCCH_DL_SCH_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_BCCH_DL_SCH_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_BCCH_DL_SCH_Message, BCCH_DL_SCH_Message_sequence);

  return offset;
}



static int
dissect_lte_rrc_MMEC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, NULL);

  return offset;
}


static const per_sequence_t S_TMSI_sequence[] = {
  { &hf_lte_rrc_mmec        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MMEC },
  { &hf_lte_rrc_m_TMSI      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_S_TMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_S_TMSI, S_TMSI_sequence);

  return offset;
}



static int
dissect_lte_rrc_IMSI_Digit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, FALSE);

  return offset;
}


static const per_sequence_t IMSI_sequence_of[1] = {
  { &hf_lte_rrc_IMSI_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_IMSI_Digit },
};

static int
dissect_lte_rrc_IMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_IMSI, IMSI_sequence_of,
                                                  6, 21, FALSE);

  return offset;
}


static const value_string lte_rrc_PagingUE_Identity_vals[] = {
  {   0, "s-TMSI" },
  {   1, "imsi" },
  { 0, NULL }
};

static const per_choice_t PagingUE_Identity_choice[] = {
  {   0, &hf_lte_rrc_s_TMSI      , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_S_TMSI },
  {   1, &hf_lte_rrc_imsi        , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_IMSI },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_PagingUE_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_PagingUE_Identity, PagingUE_Identity_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_cn_Domain_vals[] = {
  {   0, "ps" },
  {   1, "cs" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_cn_Domain(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PagingRecord_sequence[] = {
  { &hf_lte_rrc_ue_Identity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PagingUE_Identity },
  { &hf_lte_rrc_cn_Domain   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cn_Domain },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PagingRecord(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PagingRecord, PagingRecord_sequence);

  return offset;
}


static const per_sequence_t PagingRecordList_sequence_of[1] = {
  { &hf_lte_rrc_PagingRecordList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PagingRecord },
};

static int
dissect_lte_rrc_PagingRecordList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_PagingRecordList, PagingRecordList_sequence_of,
                                                  1, maxPageRec, FALSE);

  return offset;
}


static const value_string lte_rrc_T_systemInfoModification_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_systemInfoModification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_etws_Indication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_etws_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_08_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_08, T_nonCriticalExtension_08_sequence);

  return offset;
}


static const per_sequence_t Paging_sequence[] = {
  { &hf_lte_rrc_pagingRecordList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_PagingRecordList },
  { &hf_lte_rrc_systemInfoModification, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_systemInfoModification },
  { &hf_lte_rrc_etws_Indication, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_etws_Indication },
  { &hf_lte_rrc_nonCriticalExtension_08, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_08 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_Paging(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "Paging");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_Paging, Paging_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_01_vals[] = {
  {   0, "paging" },
  { 0, NULL }
};

static const per_choice_t T_c1_01_choice[] = {
  {   0, &hf_lte_rrc_paging      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_Paging },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_01, T_c1_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_messageClassExtension_01_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_messageClassExtension_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_messageClassExtension_01, T_messageClassExtension_01_sequence);

  return offset;
}


static const value_string lte_rrc_PCCH_MessageType_vals[] = {
  {   0, "c1" },
  {   1, "messageClassExtension" },
  { 0, NULL }
};

static const per_choice_t PCCH_MessageType_choice[] = {
  {   0, &hf_lte_rrc_c1_01       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_01 },
  {   1, &hf_lte_rrc_messageClassExtension_01, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_messageClassExtension_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_PCCH_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_PCCH_MessageType, PCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PCCH_Message_sequence[] = {
  { &hf_lte_rrc_message_02  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PCCH_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PCCH_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PCCH_Message, PCCH_Message_sequence);

  return offset;
}



static int
dissect_lte_rrc_RRC_TransactionIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 2U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_PollRetransmit_vals[] = {
  {   0, "ms5" },
  {   1, "ms10" },
  {   2, "ms15" },
  {   3, "ms20" },
  {   4, "ms25" },
  {   5, "ms30" },
  {   6, "ms35" },
  {   7, "ms40" },
  {   8, "ms45" },
  {   9, "ms50" },
  {  10, "ms55" },
  {  11, "ms60" },
  {  12, "ms65" },
  {  13, "ms70" },
  {  14, "ms75" },
  {  15, "ms80" },
  {  16, "ms85" },
  {  17, "ms90" },
  {  18, "ms95" },
  {  19, "ms100" },
  {  20, "ms105" },
  {  21, "ms110" },
  {  22, "ms115" },
  {  23, "ms120" },
  {  24, "ms125" },
  {  25, "ms130" },
  {  26, "ms135" },
  {  27, "ms140" },
  {  28, "ms145" },
  {  29, "ms150" },
  {  30, "ms155" },
  {  31, "ms160" },
  {  32, "ms165" },
  {  33, "ms170" },
  {  34, "ms175" },
  {  35, "ms180" },
  {  36, "ms185" },
  {  37, "ms190" },
  {  38, "ms195" },
  {  39, "ms200" },
  {  40, "ms205" },
  {  41, "ms210" },
  {  42, "ms215" },
  {  43, "ms220" },
  {  44, "ms225" },
  {  45, "ms230" },
  {  46, "ms235" },
  {  47, "ms240" },
  {  48, "ms245" },
  {  49, "ms250" },
  {  50, "ms300" },
  {  51, "ms350" },
  {  52, "ms400" },
  {  53, "ms450" },
  {  54, "ms500" },
  {  55, "spare9" },
  {  56, "spare8" },
  {  57, "spare7" },
  {  58, "spare6" },
  {  59, "spare5" },
  {  60, "spare4" },
  {  61, "spare3" },
  {  62, "spare2" },
  {  63, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_PollRetransmit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_PollPDU_vals[] = {
  {   0, "p4" },
  {   1, "p8" },
  {   2, "p16" },
  {   3, "p32" },
  {   4, "p64" },
  {   5, "p128" },
  {   6, "p256" },
  {   7, "pInfinity" },
  { 0, NULL }
};


static int
dissect_lte_rrc_PollPDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_PollByte_vals[] = {
  {   0, "kB25" },
  {   1, "kB50" },
  {   2, "kB75" },
  {   3, "kB100" },
  {   4, "kB125" },
  {   5, "kB250" },
  {   6, "kB375" },
  {   7, "kB500" },
  {   8, "kB750" },
  {   9, "kB1000" },
  {  10, "kB1250" },
  {  11, "kB1500" },
  {  12, "kB2000" },
  {  13, "kB3000" },
  {  14, "kBinfinity" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_PollByte(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_maxRetxThreshold_vals[] = {
  {   0, "t1" },
  {   1, "t2" },
  {   2, "t3" },
  {   3, "t4" },
  {   4, "t6" },
  {   5, "t8" },
  {   6, "t16" },
  {   7, "t32" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_maxRetxThreshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t UL_AM_RLC_sequence[] = {
  { &hf_lte_rrc_t_PollRetransmit, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_PollRetransmit },
  { &hf_lte_rrc_pollPDU     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PollPDU },
  { &hf_lte_rrc_pollByte    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PollByte },
  { &hf_lte_rrc_maxRetxThreshold, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_maxRetxThreshold },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UL_AM_RLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UL_AM_RLC, UL_AM_RLC_sequence);

  return offset;
}


static const value_string lte_rrc_T_Reordering_vals[] = {
  {   0, "ms0" },
  {   1, "ms5" },
  {   2, "ms10" },
  {   3, "ms15" },
  {   4, "ms20" },
  {   5, "ms25" },
  {   6, "ms30" },
  {   7, "ms35" },
  {   8, "ms40" },
  {   9, "ms45" },
  {  10, "ms50" },
  {  11, "ms55" },
  {  12, "ms60" },
  {  13, "ms65" },
  {  14, "ms70" },
  {  15, "ms75" },
  {  16, "ms80" },
  {  17, "ms85" },
  {  18, "ms90" },
  {  19, "ms95" },
  {  20, "ms100" },
  {  21, "ms110" },
  {  22, "ms120" },
  {  23, "ms130" },
  {  24, "ms140" },
  {  25, "ms150" },
  {  26, "ms160" },
  {  27, "ms170" },
  {  28, "ms180" },
  {  29, "ms190" },
  {  30, "ms200" },
  {  31, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_Reordering(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_StatusProhibit_vals[] = {
  {   0, "ms0" },
  {   1, "ms5" },
  {   2, "ms10" },
  {   3, "ms15" },
  {   4, "ms20" },
  {   5, "ms25" },
  {   6, "ms30" },
  {   7, "ms35" },
  {   8, "ms40" },
  {   9, "ms45" },
  {  10, "ms50" },
  {  11, "ms55" },
  {  12, "ms60" },
  {  13, "ms65" },
  {  14, "ms70" },
  {  15, "ms75" },
  {  16, "ms80" },
  {  17, "ms85" },
  {  18, "ms90" },
  {  19, "ms95" },
  {  20, "ms100" },
  {  21, "ms105" },
  {  22, "ms110" },
  {  23, "ms115" },
  {  24, "ms120" },
  {  25, "ms125" },
  {  26, "ms130" },
  {  27, "ms135" },
  {  28, "ms140" },
  {  29, "ms145" },
  {  30, "ms150" },
  {  31, "ms155" },
  {  32, "ms160" },
  {  33, "ms165" },
  {  34, "ms170" },
  {  35, "ms175" },
  {  36, "ms180" },
  {  37, "ms185" },
  {  38, "ms190" },
  {  39, "ms195" },
  {  40, "ms200" },
  {  41, "ms205" },
  {  42, "ms210" },
  {  43, "ms215" },
  {  44, "ms220" },
  {  45, "ms225" },
  {  46, "ms230" },
  {  47, "ms235" },
  {  48, "ms240" },
  {  49, "ms245" },
  {  50, "ms250" },
  {  51, "ms300" },
  {  52, "ms350" },
  {  53, "ms400" },
  {  54, "ms450" },
  {  55, "ms500" },
  {  56, "spare8" },
  {  57, "spare7" },
  {  58, "spare6" },
  {  59, "spare5" },
  {  60, "spare4" },
  {  61, "spare3" },
  {  62, "spare2" },
  {  63, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_StatusProhibit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t DL_AM_RLC_sequence[] = {
  { &hf_lte_rrc_t_Reordering, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_Reordering },
  { &hf_lte_rrc_t_StatusProhibit, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_StatusProhibit },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DL_AM_RLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DL_AM_RLC, DL_AM_RLC_sequence);

  return offset;
}


static const per_sequence_t T_am_sequence[] = {
  { &hf_lte_rrc_ul_AM_RLC   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UL_AM_RLC },
  { &hf_lte_rrc_dl_AM_RLC   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DL_AM_RLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_am(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_am, T_am_sequence);

  return offset;
}


static const value_string lte_rrc_SN_FieldLength_vals[] = {
  {   0, "size5" },
  {   1, "size10" },
  { 0, NULL }
};


static int
dissect_lte_rrc_SN_FieldLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t UL_UM_RLC_sequence[] = {
  { &hf_lte_rrc_sn_FieldLength, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SN_FieldLength },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UL_UM_RLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UL_UM_RLC, UL_UM_RLC_sequence);

  return offset;
}


static const per_sequence_t DL_UM_RLC_sequence[] = {
  { &hf_lte_rrc_sn_FieldLength, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SN_FieldLength },
  { &hf_lte_rrc_t_Reordering, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_Reordering },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DL_UM_RLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DL_UM_RLC, DL_UM_RLC_sequence);

  return offset;
}


static const per_sequence_t T_um_Bi_Directional_sequence[] = {
  { &hf_lte_rrc_ul_UM_RLC   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UL_UM_RLC },
  { &hf_lte_rrc_dl_UM_RLC   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DL_UM_RLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_um_Bi_Directional(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_um_Bi_Directional, T_um_Bi_Directional_sequence);

  return offset;
}


static const per_sequence_t T_um_Uni_Directional_UL_sequence[] = {
  { &hf_lte_rrc_ul_UM_RLC   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UL_UM_RLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_um_Uni_Directional_UL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_um_Uni_Directional_UL, T_um_Uni_Directional_UL_sequence);

  return offset;
}


static const per_sequence_t T_um_Uni_Directional_DL_sequence[] = {
  { &hf_lte_rrc_dl_UM_RLC   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DL_UM_RLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_um_Uni_Directional_DL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_um_Uni_Directional_DL, T_um_Uni_Directional_DL_sequence);

  return offset;
}


static const value_string lte_rrc_RLC_Configuration_vals[] = {
  {   0, "am" },
  {   1, "um-Bi-Directional" },
  {   2, "um-Uni-Directional-UL" },
  {   3, "um-Uni-Directional-DL" },
  { 0, NULL }
};

static const per_choice_t RLC_Configuration_choice[] = {
  {   0, &hf_lte_rrc_am          , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_am },
  {   1, &hf_lte_rrc_um_Bi_Directional, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_um_Bi_Directional },
  {   2, &hf_lte_rrc_um_Uni_Directional_UL, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_um_Uni_Directional_UL },
  {   3, &hf_lte_rrc_um_Uni_Directional_DL, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_um_Uni_Directional_DL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_RLC_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_RLC_Configuration, RLC_Configuration_choice,
                                 NULL);

  return offset;
}



static int
dissect_lte_rrc_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string lte_rrc_T_rlc_Configuration_vals[] = {
  {   0, "explicitValue" },
  {   1, "defaultValue" },
  { 0, NULL }
};

static const per_choice_t T_rlc_Configuration_choice[] = {
  {   0, &hf_lte_rrc_explicitValue_02, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RLC_Configuration },
  {   1, &hf_lte_rrc_defaultValue, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_rlc_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_rlc_Configuration, T_rlc_Configuration_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_prioritizedBitRate_vals[] = {
  {   0, "kBps0" },
  {   1, "kBps8" },
  {   2, "kBps16" },
  {   3, "kBps32" },
  {   4, "kBps64" },
  {   5, "kBps128" },
  {   6, "kBps256" },
  {   7, "infinity" },
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


static int
dissect_lte_rrc_T_prioritizedBitRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_bucketSizeDuration_vals[] = {
  {   0, "ms50" },
  {   1, "ms100" },
  {   2, "ms150" },
  {   3, "ms300" },
  {   4, "ms500" },
  {   5, "ms1000" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_bucketSizeDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_ul_SpecificParameters_sequence[] = {
  { &hf_lte_rrc_priority    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_16 },
  { &hf_lte_rrc_prioritizedBitRate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_prioritizedBitRate },
  { &hf_lte_rrc_bucketSizeDuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_bucketSizeDuration },
  { &hf_lte_rrc_logicalChannelGroup, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_ul_SpecificParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_ul_SpecificParameters, T_ul_SpecificParameters_sequence);

  return offset;
}


static const per_sequence_t LogicalChannelConfig_sequence[] = {
  { &hf_lte_rrc_ul_SpecificParameters, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_ul_SpecificParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_LogicalChannelConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_LogicalChannelConfig, LogicalChannelConfig_sequence);

  return offset;
}


static const value_string lte_rrc_T_logicalChannelConfig_vals[] = {
  {   0, "explicitValue" },
  {   1, "defaultValue" },
  { 0, NULL }
};

static const per_choice_t T_logicalChannelConfig_choice[] = {
  {   0, &hf_lte_rrc_explicitValue_03, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_LogicalChannelConfig },
  {   1, &hf_lte_rrc_defaultValue, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_logicalChannelConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_logicalChannelConfig, T_logicalChannelConfig_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SRB_ToAddModifyList_item_sequence[] = {
  { &hf_lte_rrc_srb_Identity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_2 },
  { &hf_lte_rrc_rlc_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_rlc_Configuration },
  { &hf_lte_rrc_logicalChannelConfig, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_logicalChannelConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SRB_ToAddModifyList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SRB_ToAddModifyList_item, SRB_ToAddModifyList_item_sequence);

  return offset;
}


static const per_sequence_t SRB_ToAddModifyList_sequence_of[1] = {
  { &hf_lte_rrc_SRB_ToAddModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SRB_ToAddModifyList_item },
};

static int
dissect_lte_rrc_SRB_ToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SRB_ToAddModifyList, SRB_ToAddModifyList_sequence_of,
                                                  1, 2, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_discardTimer_vals[] = {
  {   0, "ms50" },
  {   1, "ms100" },
  {   2, "ms150" },
  {   3, "ms300" },
  {   4, "ms500" },
  {   5, "ms750" },
  {   6, "ms1500" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_discardTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_rlc_AM_sequence[] = {
  { &hf_lte_rrc_statusReportRequired, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_rlc_AM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_rlc_AM, T_rlc_AM_sequence);

  return offset;
}


static const value_string lte_rrc_T_pdcp_SN_Size_vals[] = {
  {   0, "len7bits" },
  {   1, "len12bits" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_pdcp_SN_Size(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_rlc_UM_sequence[] = {
  { &hf_lte_rrc_pdcp_SN_Size, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_pdcp_SN_Size },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_rlc_UM(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_rlc_UM, T_rlc_UM_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16383U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_profiles_sequence[] = {
  { &hf_lte_rrc_profile0x0001, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0002, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0003, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0004, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0006, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0101, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0102, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0103, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0104, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_profiles(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_profiles, T_profiles_sequence);

  return offset;
}


static const per_sequence_t T_rohc_sequence[] = {
  { &hf_lte_rrc_maxCID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_1_16383 },
  { &hf_lte_rrc_profiles    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_profiles },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_rohc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_rohc, T_rohc_sequence);

  return offset;
}


static const value_string lte_rrc_T_headerCompression_vals[] = {
  {   0, "notUsed" },
  {   1, "rohc" },
  { 0, NULL }
};

static const per_choice_t T_headerCompression_choice[] = {
  {   0, &hf_lte_rrc_notUsed     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_rohc        , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_rohc },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_headerCompression(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_headerCompression, T_headerCompression_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PDCP_Configuration_sequence[] = {
  { &hf_lte_rrc_discardTimer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_discardTimer },
  { &hf_lte_rrc_rlc_AM      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_rlc_AM },
  { &hf_lte_rrc_rlc_UM      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_rlc_UM },
  { &hf_lte_rrc_headerCompression, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_headerCompression },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PDCP_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PDCP_Configuration, PDCP_Configuration_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_3_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            3U, 10U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DRB_ToAddModifyList_item_sequence[] = {
  { &hf_lte_rrc_eps_BearerIdentity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_15 },
  { &hf_lte_rrc_drb_Identity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_32 },
  { &hf_lte_rrc_pdcp_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_PDCP_Configuration },
  { &hf_lte_rrc_rlc_Configuration_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_RLC_Configuration },
  { &hf_lte_rrc_logicalChannelIdentity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_3_10 },
  { &hf_lte_rrc_logicalChannelConfig_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_LogicalChannelConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DRB_ToAddModifyList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DRB_ToAddModifyList_item, DRB_ToAddModifyList_item_sequence);

  return offset;
}


static const per_sequence_t DRB_ToAddModifyList_sequence_of[1] = {
  { &hf_lte_rrc_DRB_ToAddModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DRB_ToAddModifyList_item },
};

static int
dissect_lte_rrc_DRB_ToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_DRB_ToAddModifyList, DRB_ToAddModifyList_sequence_of,
                                                  1, maxDRB, FALSE);

  return offset;
}


static const per_sequence_t DRB_ToReleaseList_item_sequence[] = {
  { &hf_lte_rrc_drb_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DRB_ToReleaseList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DRB_ToReleaseList_item, DRB_ToReleaseList_item_sequence);

  return offset;
}


static const per_sequence_t DRB_ToReleaseList_sequence_of[1] = {
  { &hf_lte_rrc_DRB_ToReleaseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DRB_ToReleaseList_item },
};

static int
dissect_lte_rrc_DRB_ToReleaseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_DRB_ToReleaseList, DRB_ToReleaseList_sequence_of,
                                                  1, maxDRB, FALSE);

  return offset;
}


static const per_sequence_t T_dl_SCH_Configuration_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_dl_SCH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_dl_SCH_Configuration, T_dl_SCH_Configuration_sequence);

  return offset;
}


static const value_string lte_rrc_T_maxHARQ_Tx_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n3" },
  {   3, "n4" },
  {   4, "n5" },
  {   5, "n6" },
  {   6, "n7" },
  {   7, "n8" },
  {   8, "n10" },
  {   9, "n12" },
  {  10, "n16" },
  {  11, "n20" },
  {  12, "n24" },
  {  13, "n28" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_maxHARQ_Tx(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_periodicBSR_Timer_vals[] = {
  {   0, "sf5" },
  {   1, "sf10" },
  {   2, "sf16" },
  {   3, "sf20" },
  {   4, "sf32" },
  {   5, "sf40" },
  {   6, "sf64" },
  {   7, "sf80" },
  {   8, "sf128" },
  {   9, "sf160" },
  {  10, "sf320" },
  {  11, "sf640" },
  {  12, "sf1280" },
  {  13, "sf2560" },
  {  14, "infinity" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_periodicBSR_Timer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_retxBSR_Timer_vals[] = {
  {   0, "sf320" },
  {   1, "sf640" },
  {   2, "sf1280" },
  {   3, "sf2560" },
  {   4, "sf5120" },
  {   5, "sf10240" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_retxBSR_Timer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_ul_SCH_Configuration_sequence[] = {
  { &hf_lte_rrc_maxHARQ_Tx  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_maxHARQ_Tx },
  { &hf_lte_rrc_periodicBSR_Timer, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_periodicBSR_Timer },
  { &hf_lte_rrc_retxBSR_Timer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_retxBSR_Timer },
  { &hf_lte_rrc_ttiBundling , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_ul_SCH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_ul_SCH_Configuration, T_ul_SCH_Configuration_sequence);

  return offset;
}


static const value_string lte_rrc_T_onDurationTimer_vals[] = {
  {   0, "psf1" },
  {   1, "psf2" },
  {   2, "psf3" },
  {   3, "psf4" },
  {   4, "psf5" },
  {   5, "psf6" },
  {   6, "psf8" },
  {   7, "psf10" },
  {   8, "psf20" },
  {   9, "psf30" },
  {  10, "psf40" },
  {  11, "psf50" },
  {  12, "psf60" },
  {  13, "psf80" },
  {  14, "psf100" },
  {  15, "psf200" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_onDurationTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_drx_InactivityTimer_vals[] = {
  {   0, "psf1" },
  {   1, "psf2" },
  {   2, "psf3" },
  {   3, "psf4" },
  {   4, "psf5" },
  {   5, "psf6" },
  {   6, "psf8" },
  {   7, "psf10" },
  {   8, "psf20" },
  {   9, "psf30" },
  {  10, "psf40" },
  {  11, "psf50" },
  {  12, "psf60" },
  {  13, "psf80" },
  {  14, "psf100" },
  {  15, "psf200" },
  {  16, "psf300" },
  {  17, "psf500" },
  {  18, "psf750" },
  {  19, "psf1280" },
  {  20, "psf1920" },
  {  21, "psf2560" },
  {  22, "spare10" },
  {  23, "spare9" },
  {  24, "spare8" },
  {  25, "spare7" },
  {  26, "spare6" },
  {  27, "spare5" },
  {  28, "spare4" },
  {  29, "spare3" },
  {  30, "spare2" },
  {  31, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_drx_InactivityTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_drx_RetransmissionTimer_vals[] = {
  {   0, "sf1" },
  {   1, "sf2" },
  {   2, "sf4" },
  {   3, "sf6" },
  {   4, "sf8" },
  {   5, "sf16" },
  {   6, "sf24" },
  {   7, "sf33" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_drx_RetransmissionTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 19U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_79(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 79U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_159(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 159U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_319(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 319U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_639(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 639U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_1279(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1279U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_2559(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2559U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_longDRX_CycleStartOffset_vals[] = {
  {   0, "sf10" },
  {   1, "sf20" },
  {   2, "sf32" },
  {   3, "sf40" },
  {   4, "sf64" },
  {   5, "sf80" },
  {   6, "sf128" },
  {   7, "sf160" },
  {   8, "sf256" },
  {   9, "sf320" },
  {  10, "sf512" },
  {  11, "sf640" },
  {  12, "sf1024" },
  {  13, "sf1280" },
  {  14, "sf2048" },
  {  15, "sf2560" },
  { 0, NULL }
};

static const per_choice_t T_longDRX_CycleStartOffset_choice[] = {
  {   0, &hf_lte_rrc_sf10        , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_9 },
  {   1, &hf_lte_rrc_sf20        , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_19 },
  {   2, &hf_lte_rrc_sf32        , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_31 },
  {   3, &hf_lte_rrc_sf40        , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_39 },
  {   4, &hf_lte_rrc_sf64        , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_63 },
  {   5, &hf_lte_rrc_sf80        , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_79 },
  {   6, &hf_lte_rrc_sf128       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_127 },
  {   7, &hf_lte_rrc_sf160       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_159 },
  {   8, &hf_lte_rrc_sf256       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_255 },
  {   9, &hf_lte_rrc_sf320       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_319 },
  {  10, &hf_lte_rrc_sf512       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_511 },
  {  11, &hf_lte_rrc_sf640       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_639 },
  {  12, &hf_lte_rrc_sf1024      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_1023 },
  {  13, &hf_lte_rrc_sf1280      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_1279 },
  {  14, &hf_lte_rrc_sf2048      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_2047 },
  {  15, &hf_lte_rrc_sf2560      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_2559 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_longDRX_CycleStartOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_longDRX_CycleStartOffset, T_longDRX_CycleStartOffset_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_shortDRX_Cycle_vals[] = {
  {   0, "sf2" },
  {   1, "sf5" },
  {   2, "sf8" },
  {   3, "sf10" },
  {   4, "sf16" },
  {   5, "sf20" },
  {   6, "sf32" },
  {   7, "sf40" },
  {   8, "sf64" },
  {   9, "sf80" },
  {  10, "sf128" },
  {  11, "sf160" },
  {  12, "sf256" },
  {  13, "sf320" },
  {  14, "sf512" },
  {  15, "sf640" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_shortDRX_Cycle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_enable_03_sequence[] = {
  { &hf_lte_rrc_shortDRX_Cycle, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_shortDRX_Cycle },
  { &hf_lte_rrc_drxShortCycleTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_03, T_enable_03_sequence);

  return offset;
}


static const value_string lte_rrc_T_shortDRX_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t T_shortDRX_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_03   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_shortDRX(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_shortDRX, T_shortDRX_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_enable_02_sequence[] = {
  { &hf_lte_rrc_onDurationTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_onDurationTimer },
  { &hf_lte_rrc_drx_InactivityTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_drx_InactivityTimer },
  { &hf_lte_rrc_drx_RetransmissionTimer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_drx_RetransmissionTimer },
  { &hf_lte_rrc_longDRX_CycleStartOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_longDRX_CycleStartOffset },
  { &hf_lte_rrc_shortDRX    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_shortDRX },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_02, T_enable_02_sequence);

  return offset;
}


static const value_string lte_rrc_T_drx_Configuration_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t T_drx_Configuration_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_02   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_drx_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_drx_Configuration, T_drx_Configuration_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_periodicPHR_Timer_vals[] = {
  {   0, "sf10" },
  {   1, "sf20" },
  {   2, "sf50" },
  {   3, "sf100" },
  {   4, "sf200" },
  {   5, "sf500" },
  {   6, "sf1000" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_periodicPHR_Timer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_prohibitPHR_Timer_vals[] = {
  {   0, "sf0" },
  {   1, "sf10" },
  {   2, "sf20" },
  {   3, "sf50" },
  {   4, "sf100" },
  {   5, "sf200" },
  {   6, "sf500" },
  {   7, "sf1000" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_prohibitPHR_Timer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_dl_PathlossChange_vals[] = {
  {   0, "dB1" },
  {   1, "dB3" },
  {   2, "dB6" },
  {   3, "infinity" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_dl_PathlossChange(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_enable_04_sequence[] = {
  { &hf_lte_rrc_periodicPHR_Timer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_periodicPHR_Timer },
  { &hf_lte_rrc_prohibitPHR_Timer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_prohibitPHR_Timer },
  { &hf_lte_rrc_dl_PathlossChange, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_dl_PathlossChange },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_04, T_enable_04_sequence);

  return offset;
}


static const value_string lte_rrc_T_phr_Configuration_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t T_phr_Configuration_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_04   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_04 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_phr_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_phr_Configuration, T_phr_Configuration_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MAC_MainConfiguration_sequence[] = {
  { &hf_lte_rrc_dl_SCH_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_dl_SCH_Configuration },
  { &hf_lte_rrc_ul_SCH_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_ul_SCH_Configuration },
  { &hf_lte_rrc_drx_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_drx_Configuration },
  { &hf_lte_rrc_timeAlignmentTimerDedicated, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_TimeAlignmentTimer },
  { &hf_lte_rrc_phr_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_phr_Configuration },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MAC_MainConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MAC_MainConfiguration, MAC_MainConfiguration_sequence);

  return offset;
}


static const value_string lte_rrc_T_mac_MainConfig_vals[] = {
  {   0, "explicitValue" },
  {   1, "defaultValue" },
  { 0, NULL }
};

static const per_choice_t T_mac_MainConfig_choice[] = {
  {   0, &hf_lte_rrc_explicitValue_01, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_MAC_MainConfiguration },
  {   1, &hf_lte_rrc_defaultValue, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_mac_MainConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_mac_MainConfig, T_mac_MainConfig_choice,
                                 NULL);

  return offset;
}



static int
dissect_lte_rrc_C_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL);

  return offset;
}


static const value_string lte_rrc_T_semiPersistSchedIntervalDL_vals[] = {
  {   0, "sf10" },
  {   1, "sf20" },
  {   2, "sf32" },
  {   3, "sf40" },
  {   4, "sf64" },
  {   5, "sf80" },
  {   6, "sf128" },
  {   7, "sf160" },
  {   8, "sf320" },
  {   9, "sf640" },
  {  10, "spare6" },
  {  11, "spare5" },
  {  12, "spare4" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_semiPersistSchedIntervalDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_enable_08_sequence[] = {
  { &hf_lte_rrc_semiPersistSchedIntervalDL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_semiPersistSchedIntervalDL },
  { &hf_lte_rrc_numberOfConfSPS_Processes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_8 },
  { &hf_lte_rrc_n1Pucch_AN_Persistent, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_2047 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_08, T_enable_08_sequence);

  return offset;
}


static const value_string lte_rrc_SPS_ConfigurationDL_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t SPS_ConfigurationDL_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_08   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_08 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_SPS_ConfigurationDL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_SPS_ConfigurationDL, SPS_ConfigurationDL_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_semiPersistSchedIntervalUL_vals[] = {
  {   0, "sf10" },
  {   1, "sf20" },
  {   2, "sf32" },
  {   3, "sf40" },
  {   4, "sf64" },
  {   5, "sf80" },
  {   6, "sf128" },
  {   7, "sf160" },
  {   8, "sf320" },
  {   9, "sf640" },
  {  10, "spare6" },
  {  11, "spare5" },
  {  12, "spare4" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_semiPersistSchedIntervalUL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_implicitReleaseAfter_vals[] = {
  {   0, "e2" },
  {   1, "e3" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_implicitReleaseAfter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M8_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_p0_Persistent_sequence[] = {
  { &hf_lte_rrc_p0_NominalPUSCH_Persistent, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M126_24 },
  { &hf_lte_rrc_p0_UePUSCH_Persistent, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M8_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_p0_Persistent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_p0_Persistent, T_p0_Persistent_sequence);

  return offset;
}


static const per_sequence_t T_enable_09_sequence[] = {
  { &hf_lte_rrc_semiPersistSchedIntervalUL, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_semiPersistSchedIntervalUL },
  { &hf_lte_rrc_implicitReleaseAfter, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_implicitReleaseAfter },
  { &hf_lte_rrc_p0_Persistent, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_p0_Persistent },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_09, T_enable_09_sequence);

  return offset;
}


static const value_string lte_rrc_SPS_ConfigurationUL_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t SPS_ConfigurationUL_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_09   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_09 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_SPS_ConfigurationUL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_SPS_ConfigurationUL, SPS_ConfigurationUL_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SPS_Configuration_sequence[] = {
  { &hf_lte_rrc_semiPersistSchedC_RNTI, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_C_RNTI },
  { &hf_lte_rrc_sps_ConfigurationDL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_SPS_ConfigurationDL },
  { &hf_lte_rrc_sps_ConfigurationUL, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_SPS_ConfigurationUL },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SPS_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SPS_Configuration, SPS_Configuration_sequence);

  return offset;
}


static const value_string lte_rrc_T_p_a_vals[] = {
  {   0, "dB-6" },
  {   1, "dB-4dot77" },
  {   2, "dB-3" },
  {   3, "dB-1dot77" },
  {   4, "dB0" },
  {   5, "dB1" },
  {   6, "dB2" },
  {   7, "dB3" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_p_a(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PDSCH_ConfigDedicated_sequence[] = {
  { &hf_lte_rrc_p_a         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_p_a },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PDSCH_ConfigDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PDSCH_ConfigDedicated, PDSCH_ConfigDedicated_sequence);

  return offset;
}


static const value_string lte_rrc_T_repetitionFactor_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  {   2, "n6" },
  {   3, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_repetitionFactor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_enable_05_sequence[] = {
  { &hf_lte_rrc_repetitionFactor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_repetitionFactor },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_05, T_enable_05_sequence);

  return offset;
}


static const value_string lte_rrc_T_ackNackRepetition_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t T_ackNackRepetition_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_05   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_05 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_ackNackRepetition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_ackNackRepetition, T_ackNackRepetition_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_tddAckNackFeedbackMode_vals[] = {
  {   0, "bundling" },
  {   1, "multiplexing" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_tddAckNackFeedbackMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PUCCH_ConfigDedicated_sequence[] = {
  { &hf_lte_rrc_ackNackRepetition, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_ackNackRepetition },
  { &hf_lte_rrc_tddAckNackFeedbackMode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_tddAckNackFeedbackMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PUCCH_ConfigDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PUCCH_ConfigDedicated, PUCCH_ConfigDedicated_sequence);

  return offset;
}


static const per_sequence_t PUSCH_ConfigDedicated_sequence[] = {
  { &hf_lte_rrc_deltaOffset_ACK_Index, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_15 },
  { &hf_lte_rrc_deltaOffset_RI_Index, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_15 },
  { &hf_lte_rrc_deltaOffset_CQI_Index, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PUSCH_ConfigDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PUSCH_ConfigDedicated, PUSCH_ConfigDedicated_sequence);

  return offset;
}


static const value_string lte_rrc_T_deltaMCS_Enabled_vals[] = {
  {   0, "en0" },
  {   1, "en1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_deltaMCS_Enabled(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t UplinkPowerControlDedicated_sequence[] = {
  { &hf_lte_rrc_p0_UePUSCH  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M8_7 },
  { &hf_lte_rrc_deltaMCS_Enabled, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_deltaMCS_Enabled },
  { &hf_lte_rrc_accumulationEnabled, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_p0_uePUCCH  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M8_7 },
  { &hf_lte_rrc_pSRS_Offset , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UplinkPowerControlDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UplinkPowerControlDedicated, UplinkPowerControlDedicated_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 31U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_TPC_Index_vals[] = {
  {   0, "indexOfFormat3" },
  {   1, "indexOfFormat3A" },
  { 0, NULL }
};

static const per_choice_t TPC_Index_choice[] = {
  {   0, &hf_lte_rrc_indexOfFormat3, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_1_15 },
  {   1, &hf_lte_rrc_indexOfFormat3A, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_1_31 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_TPC_Index(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_TPC_Index, TPC_Index_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_enable_10_sequence[] = {
  { &hf_lte_rrc_tpc_RNTI    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { &hf_lte_rrc_tpc_Index   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_TPC_Index },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_10, T_enable_10_sequence);

  return offset;
}


static const value_string lte_rrc_TPC_PDCCH_Configuration_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t TPC_PDCCH_Configuration_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_10   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_10 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_TPC_PDCCH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_TPC_PDCCH_Configuration, TPC_PDCCH_Configuration_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_cqi_ReportingModeAperiodic_vals[] = {
  {   0, "rm12" },
  {   1, "rm20" },
  {   2, "rm22" },
  {   3, "rm30" },
  {   4, "rm31" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_cqi_ReportingModeAperiodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 767U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_subbandCQI_sequence[] = {
  { &hf_lte_rrc_k           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_subbandCQI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_subbandCQI, T_subbandCQI_sequence);

  return offset;
}


static const value_string lte_rrc_T_cqi_FormatIndicatorPeriodic_vals[] = {
  {   0, "widebandCQI" },
  {   1, "subbandCQI" },
  { 0, NULL }
};

static const per_choice_t T_cqi_FormatIndicatorPeriodic_choice[] = {
  {   0, &hf_lte_rrc_widebandCQI , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_subbandCQI  , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_subbandCQI },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_cqi_FormatIndicatorPeriodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_cqi_FormatIndicatorPeriodic, T_cqi_FormatIndicatorPeriodic_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_enable_01_sequence[] = {
  { &hf_lte_rrc_cqi_PUCCH_ResourceIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_767 },
  { &hf_lte_rrc_cqi_pmi_ConfigIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_511 },
  { &hf_lte_rrc_cqi_FormatIndicatorPeriodic, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cqi_FormatIndicatorPeriodic },
  { &hf_lte_rrc_ri_ConfigIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_1023 },
  { &hf_lte_rrc_simultaneousAckNackAndCQI, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_01, T_enable_01_sequence);

  return offset;
}


static const value_string lte_rrc_CQI_ReportingPeriodic_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t CQI_ReportingPeriodic_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_01   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_CQI_ReportingPeriodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_CQI_ReportingPeriodic, CQI_ReportingPeriodic_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CQI_Reporting_sequence[] = {
  { &hf_lte_rrc_cqi_ReportingModeAperiodic, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cqi_ReportingModeAperiodic },
  { &hf_lte_rrc_nomPDSCH_RS_EPRE_Offset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M1_6 },
  { &hf_lte_rrc_cqi_ReportingPeriodic, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_CQI_ReportingPeriodic },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CQI_Reporting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CQI_Reporting, CQI_Reporting_sequence);

  return offset;
}


static const value_string lte_rrc_T_srsBandwidth_vals[] = {
  {   0, "bw0" },
  {   1, "bw1" },
  {   2, "bw2" },
  {   3, "bw3" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_srsBandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_srsHoppingBandwidth_vals[] = {
  {   0, "hbw0" },
  {   1, "hbw1" },
  {   2, "hbw2" },
  {   3, "hbw3" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_srsHoppingBandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 23U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_cyclicShift_vals[] = {
  {   0, "cs0" },
  {   1, "cs1" },
  {   2, "cs2" },
  {   3, "cs3" },
  {   4, "cs4" },
  {   5, "cs5" },
  {   6, "cs6" },
  {   7, "cs7" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_cyclicShift(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_enable_07_sequence[] = {
  { &hf_lte_rrc_srsBandwidth, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_srsBandwidth },
  { &hf_lte_rrc_srsHoppingBandwidth, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_srsHoppingBandwidth },
  { &hf_lte_rrc_frequencyDomainPosition, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_23 },
  { &hf_lte_rrc_duration    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_srs_ConfigurationIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_1023 },
  { &hf_lte_rrc_transmissionComb, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_1 },
  { &hf_lte_rrc_cyclicShift , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cyclicShift },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_07, T_enable_07_sequence);

  return offset;
}


static const value_string lte_rrc_SoundingRsUl_ConfigDedicated_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t SoundingRsUl_ConfigDedicated_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_07   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_07 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_SoundingRsUl_ConfigDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_SoundingRsUl_ConfigDedicated, SoundingRsUl_ConfigDedicated_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_transmissionMode_vals[] = {
  {   0, "tm1" },
  {   1, "tm2" },
  {   2, "tm3" },
  {   3, "tm4" },
  {   4, "tm5" },
  {   5, "tm6" },
  {   6, "tm7" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_transmissionMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL);

  return offset;
}


static const value_string lte_rrc_T_codebookSubsetRestriction_vals[] = {
  {   0, "n2TxAntenna-tm3" },
  {   1, "n4TxAntenna-tm3" },
  {   2, "n2TxAntenna-tm4" },
  {   3, "n4TxAntenna-tm4" },
  {   4, "n2TxAntenna-tm5" },
  {   5, "n4TxAntenna-tm5" },
  {   6, "n2TxAntenna-tm6" },
  {   7, "n4TxAntenna-tm6" },
  { 0, NULL }
};

static const per_choice_t T_codebookSubsetRestriction_choice[] = {
  {   0, &hf_lte_rrc_n2TxAntenna_tm3, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_BIT_STRING_SIZE_2 },
  {   1, &hf_lte_rrc_n4TxAntenna_tm3, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_BIT_STRING_SIZE_4 },
  {   2, &hf_lte_rrc_n2TxAntenna_tm4, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_BIT_STRING_SIZE_6 },
  {   3, &hf_lte_rrc_n4TxAntenna_tm4, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_BIT_STRING_SIZE_64 },
  {   4, &hf_lte_rrc_n2TxAntenna_tm5, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_BIT_STRING_SIZE_4 },
  {   5, &hf_lte_rrc_n4TxAntenna_tm5, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_BIT_STRING_SIZE_16 },
  {   6, &hf_lte_rrc_n2TxAntenna_tm6, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_BIT_STRING_SIZE_4 },
  {   7, &hf_lte_rrc_n4TxAntenna_tm6, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_codebookSubsetRestriction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_codebookSubsetRestriction, T_codebookSubsetRestriction_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_enable_vals[] = {
  {   0, "closedLoop" },
  {   1, "openLoop" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_enable(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_ue_TransmitAntennaSelection_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t T_ue_TransmitAntennaSelection_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_ue_TransmitAntennaSelection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_ue_TransmitAntennaSelection, T_ue_TransmitAntennaSelection_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AntennaInformationDedicated_sequence[] = {
  { &hf_lte_rrc_transmissionMode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_transmissionMode },
  { &hf_lte_rrc_codebookSubsetRestriction, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_codebookSubsetRestriction },
  { &hf_lte_rrc_ue_TransmitAntennaSelection, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_ue_TransmitAntennaSelection },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_AntennaInformationDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_AntennaInformationDedicated, AntennaInformationDedicated_sequence);

  return offset;
}


static const value_string lte_rrc_T_antennaInformation_vals[] = {
  {   0, "explicitValue" },
  {   1, "defaultValue" },
  { 0, NULL }
};

static const per_choice_t T_antennaInformation_choice[] = {
  {   0, &hf_lte_rrc_explicitValue, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_AntennaInformationDedicated },
  {   1, &hf_lte_rrc_defaultValue, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_antennaInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_antennaInformation, T_antennaInformation_choice,
                                 NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_155(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 155U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_dsr_TransMax_vals[] = {
  {   0, "n4" },
  {   1, "n8" },
  {   2, "n16" },
  {   3, "n32" },
  {   4, "n64" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_dsr_TransMax(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_enable_06_sequence[] = {
  { &hf_lte_rrc_sr_PUCCH_ResourceIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_2047 },
  { &hf_lte_rrc_sr_ConfigurationIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_155 },
  { &hf_lte_rrc_dsr_TransMax, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_dsr_TransMax },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_06, T_enable_06_sequence);

  return offset;
}


static const value_string lte_rrc_SchedulingRequest_Configuration_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t SchedulingRequest_Configuration_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_06   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_06 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_SchedulingRequest_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_SchedulingRequest_Configuration, SchedulingRequest_Configuration_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PhysicalConfigDedicated_sequence[] = {
  { &hf_lte_rrc_pdsch_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_PDSCH_ConfigDedicated },
  { &hf_lte_rrc_pucch_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_PUCCH_ConfigDedicated },
  { &hf_lte_rrc_pusch_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_PUSCH_ConfigDedicated },
  { &hf_lte_rrc_uplinkPowerControl, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_UplinkPowerControlDedicated },
  { &hf_lte_rrc_tpc_PDCCH_ConfigPUCCH, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_TPC_PDCCH_Configuration },
  { &hf_lte_rrc_tpc_PDCCH_ConfigPUSCH, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_TPC_PDCCH_Configuration },
  { &hf_lte_rrc_cqi_Reporting, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_CQI_Reporting },
  { &hf_lte_rrc_soundingRsUl_Config, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_SoundingRsUl_ConfigDedicated },
  { &hf_lte_rrc_antennaInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_antennaInformation },
  { &hf_lte_rrc_schedulingRequestConfig, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_SchedulingRequest_Configuration },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PhysicalConfigDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PhysicalConfigDedicated, PhysicalConfigDedicated_sequence);

  return offset;
}


static const per_sequence_t RadioResourceConfigDedicated_sequence[] = {
  { &hf_lte_rrc_srb_ToAddModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_SRB_ToAddModifyList },
  { &hf_lte_rrc_drb_ToAddModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_DRB_ToAddModifyList },
  { &hf_lte_rrc_drb_ToReleaseList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_DRB_ToReleaseList },
  { &hf_lte_rrc_mac_MainConfig, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_mac_MainConfig },
  { &hf_lte_rrc_sps_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_SPS_Configuration },
  { &hf_lte_rrc_physicalConfigDedicated, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_PhysicalConfigDedicated },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RadioResourceConfigDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RadioResourceConfigDedicated, RadioResourceConfigDedicated_sequence);

  return offset;
}



static int
dissect_lte_rrc_NextHopChainingCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_11_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_11, T_nonCriticalExtension_11_sequence);

  return offset;
}


static const per_sequence_t RRCConnectionReestablishment_r8_IEs_sequence[] = {
  { &hf_lte_rrc_radioResourceConfiguration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RadioResourceConfigDedicated },
  { &hf_lte_rrc_nextHopChainingCount, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_NextHopChainingCount },
  { &hf_lte_rrc_nonCriticalExtension_11, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_11 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReestablishment_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReestablishment_r8_IEs, RRCConnectionReestablishment_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_12_vals[] = {
  {   0, "rrcConnectionReestablishment-r8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_12_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionReestablishment_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReestablishment_r8_IEs },
  {   1, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   4, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   5, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   6, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   7, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_12, T_c1_12_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_10_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_10, T_criticalExtensionsFuture_10_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_10_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_10_choice[] = {
  {   0, &hf_lte_rrc_c1_12       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_12 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_10, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_10 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_10, T_criticalExtensions_10_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionReestablishment_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_10, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_10 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReestablishment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionReestablishment");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReestablishment, RRCConnectionReestablishment_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_13_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_13, T_nonCriticalExtension_13_sequence);

  return offset;
}


static const per_sequence_t RRCConnectionReestablishmentReject_r8_IEs_sequence[] = {
  { &hf_lte_rrc_nonCriticalExtension_13, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_13 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReestablishmentReject_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReestablishmentReject_r8_IEs, RRCConnectionReestablishmentReject_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_12_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_12, T_criticalExtensionsFuture_12_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_12_vals[] = {
  {   0, "rrcConnectionReestablishmentReject-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_12_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionReestablishmentReject_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReestablishmentReject_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_12, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_12 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_12, T_criticalExtensions_12_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionReestablishmentReject_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_12, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_12 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReestablishmentReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionReestablishmentReject");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReestablishmentReject, RRCConnectionReestablishmentReject_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_14_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_14, T_nonCriticalExtension_14_sequence);

  return offset;
}


static const per_sequence_t RRCConnectionReject_r8_IEs_sequence[] = {
  { &hf_lte_rrc_waitTime    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_16 },
  { &hf_lte_rrc_nonCriticalExtension_14, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_14 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReject_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReject_r8_IEs, RRCConnectionReject_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_13_vals[] = {
  {   0, "rrcConnectionReject-r8" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_13_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionReject_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReject_r8_IEs },
  {   1, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_13, T_c1_13_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_14_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_14, T_criticalExtensionsFuture_14_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_14_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_14_choice[] = {
  {   0, &hf_lte_rrc_c1_13       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_13 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_14, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_14 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_14, T_criticalExtensions_14_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionReject_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_14, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_14 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionReject");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReject, RRCConnectionReject_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_16_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_16, T_nonCriticalExtension_16_sequence);

  return offset;
}


static const per_sequence_t RRCConnectionSetup_r8_IEs_sequence[] = {
  { &hf_lte_rrc_radioResourceConfiguration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RadioResourceConfigDedicated },
  { &hf_lte_rrc_nonCriticalExtension_16, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionSetup_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionSetup_r8_IEs, RRCConnectionSetup_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_15_vals[] = {
  {   0, "rrcConnectionSetup-r8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_15_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionSetup_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionSetup_r8_IEs },
  {   1, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   4, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   5, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   6, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   7, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_15, T_c1_15_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_17_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_17(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_17, T_criticalExtensionsFuture_17_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_17_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_17_choice[] = {
  {   0, &hf_lte_rrc_c1_15       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_15 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_17, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_17 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_17(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_17, T_criticalExtensions_17_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionSetup_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_17, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_17 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionSetup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionSetup");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionSetup, RRCConnectionSetup_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_02_vals[] = {
  {   0, "rrcConnectionReestablishment" },
  {   1, "rrcConnectionReestablishmentReject" },
  {   2, "rrcConnectionReject" },
  {   3, "rrcConnectionSetup" },
  { 0, NULL }
};

static const per_choice_t T_c1_02_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionReestablishment, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReestablishment },
  {   1, &hf_lte_rrc_rrcConnectionReestablishmentReject, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReestablishmentReject },
  {   2, &hf_lte_rrc_rrcConnectionReject, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReject },
  {   3, &hf_lte_rrc_rrcConnectionSetup, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionSetup },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_02, T_c1_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_messageClassExtension_02_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_messageClassExtension_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_messageClassExtension_02, T_messageClassExtension_02_sequence);

  return offset;
}


static const value_string lte_rrc_DL_CCCH_MessageType_vals[] = {
  {   0, "c1" },
  {   1, "messageClassExtension" },
  { 0, NULL }
};

static const per_choice_t DL_CCCH_MessageType_choice[] = {
  {   0, &hf_lte_rrc_c1_02       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_02 },
  {   1, &hf_lte_rrc_messageClassExtension_02, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_messageClassExtension_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_DL_CCCH_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_DL_CCCH_MessageType, DL_CCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DL_CCCH_Message_sequence[] = {
  { &hf_lte_rrc_message_03  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DL_CCCH_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DL_CCCH_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DL_CCCH_Message, DL_CCCH_Message_sequence);

  return offset;
}



static int
dissect_lte_rrc_CDMA2000_RAND(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_CDMA2000_MobilityParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_01_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_01, T_nonCriticalExtension_01_sequence);

  return offset;
}


static const per_sequence_t CDMA2000_CSFBParametersResponse_r8_IEs_sequence[] = {
  { &hf_lte_rrc_cdma2000_RAND, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_RAND },
  { &hf_lte_rrc_cdma2000_MobilityParameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_MobilityParameters },
  { &hf_lte_rrc_nonCriticalExtension_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CDMA2000_CSFBParametersResponse_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CDMA2000_CSFBParametersResponse_r8_IEs, CDMA2000_CSFBParametersResponse_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_01_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_01, T_criticalExtensionsFuture_01_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_01_vals[] = {
  {   0, "cdma2000-1xParametersForCSFB-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_01_choice[] = {
  {   0, &hf_lte_rrc_cdma2000_1xParametersForCSFB_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_CDMA2000_CSFBParametersResponse_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_01, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_01, T_criticalExtensions_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CDMA2000_CSFBParametersResponse_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CDMA2000_CSFBParametersResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "CDMA2000-CSFBParametersResponse");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CDMA2000_CSFBParametersResponse, CDMA2000_CSFBParametersResponse_sequence);

  return offset;
}



static int
dissect_lte_rrc_NAS_DedicatedInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *nas_eps_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, &nas_eps_tvb);


	if ((nas_eps_tvb)&&(nas_eps_handle))
		call_dissector(nas_eps_handle,nas_eps_tvb,actx->pinfo, tree);


  return offset;
}


static const value_string lte_rrc_CDMA2000_Type_vals[] = {
  {   0, "type1XRTT" },
  {   1, "typeHRPD" },
  { 0, NULL }
};


static int
dissect_lte_rrc_CDMA2000_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_CDMA2000_DedicatedInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_cdma2000_sequence[] = {
  { &hf_lte_rrc_cdma2000_Type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Type },
  { &hf_lte_rrc_cdma2000_DedicatedInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_DedicatedInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_cdma2000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_cdma2000, T_cdma2000_sequence);

  return offset;
}


static const value_string lte_rrc_T_informationType_vals[] = {
  {   0, "nas3GPP" },
  {   1, "cdma2000" },
  { 0, NULL }
};

static const per_choice_t T_informationType_choice[] = {
  {   0, &hf_lte_rrc_nas3GPP     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NAS_DedicatedInformation },
  {   1, &hf_lte_rrc_cdma2000    , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_cdma2000 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_informationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_informationType, T_informationType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_04_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_04, T_nonCriticalExtension_04_sequence);

  return offset;
}


static const per_sequence_t DLInformationTransfer_r8_IEs_sequence[] = {
  { &hf_lte_rrc_informationType, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_informationType },
  { &hf_lte_rrc_nonCriticalExtension_04, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_04 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DLInformationTransfer_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DLInformationTransfer_r8_IEs, DLInformationTransfer_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_07_vals[] = {
  {   0, "dlInformationTransfer-r8" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_07_choice[] = {
  {   0, &hf_lte_rrc_dlInformationTransfer_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_DLInformationTransfer_r8_IEs },
  {   1, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_07, T_c1_07_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_04_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_04, T_criticalExtensionsFuture_04_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_04_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_04_choice[] = {
  {   0, &hf_lte_rrc_c1_07       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_07 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_04, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_04 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_04, T_criticalExtensions_04_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DLInformationTransfer_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_04, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_04 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DLInformationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "DLInformationTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DLInformationTransfer, DLInformationTransfer_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_05_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_05, T_nonCriticalExtension_05_sequence);

  return offset;
}


static const per_sequence_t HandoverFromEUTRAPreparationRequest_r8_IEs_sequence[] = {
  { &hf_lte_rrc_cdma2000_Type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Type },
  { &hf_lte_rrc_cdma2000_RAND, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_CDMA2000_RAND },
  { &hf_lte_rrc_cdma2000_MobilityParameters, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_CDMA2000_MobilityParameters },
  { &hf_lte_rrc_nonCriticalExtension_05, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_05 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_HandoverFromEUTRAPreparationRequest_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_HandoverFromEUTRAPreparationRequest_r8_IEs, HandoverFromEUTRAPreparationRequest_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_08_vals[] = {
  {   0, "handoverFromEUTRAPreparationRequest-r8" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_08_choice[] = {
  {   0, &hf_lte_rrc_handoverFromEUTRAPreparationRequest_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_HandoverFromEUTRAPreparationRequest_r8_IEs },
  {   1, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_08, T_c1_08_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_05_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_05, T_criticalExtensionsFuture_05_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_05_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_05_choice[] = {
  {   0, &hf_lte_rrc_c1_08       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_08 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_05, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_05 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_05, T_criticalExtensions_05_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t HandoverFromEUTRAPreparationRequest_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_05, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_05 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_HandoverFromEUTRAPreparationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "HandoverFromEUTRAPreparationRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_HandoverFromEUTRAPreparationRequest, HandoverFromEUTRAPreparationRequest_sequence);

  return offset;
}


static const value_string lte_rrc_T_csFallbackIndicator_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_csFallbackIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_targetRAT_Type_vals[] = {
  {   0, "utran" },
  {   1, "geran" },
  {   2, "cdma2000-1XRTT" },
  {   3, "cdma2000-HRPD" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_targetRAT_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t Handover_sequence[] = {
  { &hf_lte_rrc_targetRAT_Type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_targetRAT_Type },
  { &hf_lte_rrc_targetRAT_MessageContainer, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OCTET_STRING },
  { &hf_lte_rrc_nas_SecurityParamFromEUTRA, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_Handover(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_Handover, Handover_sequence);

  return offset;
}


static const value_string lte_rrc_T_t304_vals[] = {
  {   0, "ms100" },
  {   1, "ms200" },
  {   2, "ms500" },
  {   3, "ms1000" },
  {   4, "ms2000" },
  {   5, "ms4000" },
  {   6, "ms8000" },
  {   7, "spare" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t304(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t GERAN_CellIdentity_sequence[] = {
  { &hf_lte_rrc_networkColourCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_3 },
  { &hf_lte_rrc_baseStationColourCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_GERAN_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_GERAN_CellIdentity, GERAN_CellIdentity_sequence);

  return offset;
}


static const per_sequence_t GERAN_CarrierFreq_sequence[] = {
  { &hf_lte_rrc_arfcn       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_ARFCN_Value },
  { &hf_lte_rrc_bandIndicator, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_BandIndicator },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_GERAN_CarrierFreq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_GERAN_CarrierFreq, GERAN_CarrierFreq_sequence);

  return offset;
}



static int
dissect_lte_rrc_OCTET_STRING_SIZE_1_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 23, FALSE, NULL);

  return offset;
}


static const per_sequence_t GERAN_SystemInformation_sequence_of[1] = {
  { &hf_lte_rrc_GERAN_SystemInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OCTET_STRING_SIZE_1_23 },
};

static int
dissect_lte_rrc_GERAN_SystemInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_GERAN_SystemInformation, GERAN_SystemInformation_sequence_of,
                                                  1, maxGERAN_SI, FALSE);

  return offset;
}


static const value_string lte_rrc_T_geran_SystemInformation_vals[] = {
  {   0, "si" },
  {   1, "psi" },
  { 0, NULL }
};

static const per_choice_t T_geran_SystemInformation_choice[] = {
  {   0, &hf_lte_rrc_si          , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_GERAN_SystemInformation },
  {   1, &hf_lte_rrc_psi         , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_GERAN_SystemInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_geran_SystemInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_geran_SystemInformation, T_geran_SystemInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_geran_sequence[] = {
  { &hf_lte_rrc_bsic        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_CellIdentity },
  { &hf_lte_rrc_geran_CarrierFreq, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_CarrierFreq },
  { &hf_lte_rrc_networkControlOrder, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_BIT_STRING_SIZE_2 },
  { &hf_lte_rrc_geran_SystemInformation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_geran_SystemInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_geran(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_geran, T_geran_sequence);

  return offset;
}


static const value_string lte_rrc_T_targetRAT_Type_01_vals[] = {
  {   0, "geran" },
  { 0, NULL }
};

static const per_choice_t T_targetRAT_Type_01_choice[] = {
  {   0, &hf_lte_rrc_geran       , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_geran },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_targetRAT_Type_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_targetRAT_Type_01, T_targetRAT_Type_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellChangeOrder_sequence[] = {
  { &hf_lte_rrc_t304        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t304 },
  { &hf_lte_rrc_targetRAT_Type_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_targetRAT_Type_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CellChangeOrder(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CellChangeOrder, CellChangeOrder_sequence);

  return offset;
}


static const value_string lte_rrc_T_purpose_vals[] = {
  {   0, "handover" },
  {   1, "cellChangeOrder" },
  { 0, NULL }
};

static const per_choice_t T_purpose_choice[] = {
  {   0, &hf_lte_rrc_handover    , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_Handover },
  {   1, &hf_lte_rrc_cellChangeOrder, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_CellChangeOrder },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_purpose(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_purpose, T_purpose_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_07_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_07, T_nonCriticalExtension_07_sequence);

  return offset;
}


static const per_sequence_t MobilityFromEUTRACommand_r8_IEs_sequence[] = {
  { &hf_lte_rrc_csFallbackIndicator, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_csFallbackIndicator },
  { &hf_lte_rrc_purpose     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_purpose },
  { &hf_lte_rrc_nonCriticalExtension_07, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_07 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MobilityFromEUTRACommand_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MobilityFromEUTRACommand_r8_IEs, MobilityFromEUTRACommand_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_10_vals[] = {
  {   0, "mobilityFromEUTRACommand-r8" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_10_choice[] = {
  {   0, &hf_lte_rrc_mobilityFromEUTRACommand_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_MobilityFromEUTRACommand_r8_IEs },
  {   1, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_10, T_c1_10_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_07_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_07, T_criticalExtensionsFuture_07_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_07_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_07_choice[] = {
  {   0, &hf_lte_rrc_c1_10       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_10 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_07, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_07 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_07(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_07, T_criticalExtensions_07_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MobilityFromEUTRACommand_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_07, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_07 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MobilityFromEUTRACommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "MobilityFromEUTRACommand");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MobilityFromEUTRACommand, MobilityFromEUTRACommand_sequence);

  return offset;
}



static int
dissect_lte_rrc_MeasObjectId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxObjectId, NULL, FALSE);

  return offset;
}


static const per_sequence_t MeasObjectToRemoveList_item_sequence[] = {
  { &hf_lte_rrc_measObjectId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasObjectId },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasObjectToRemoveList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasObjectToRemoveList_item, MeasObjectToRemoveList_item_sequence);

  return offset;
}


static const per_sequence_t MeasObjectToRemoveList_sequence_of[1] = {
  { &hf_lte_rrc_MeasObjectToRemoveList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasObjectToRemoveList_item },
};

static int
dissect_lte_rrc_MeasObjectToRemoveList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MeasObjectToRemoveList, MeasObjectToRemoveList_sequence_of,
                                                  1, maxObjectId, FALSE);

  return offset;
}


static const value_string lte_rrc_T_offsetFreq_01_vals[] = {
  {   0, "dB-24" },
  {   1, "dB-22" },
  {   2, "dB-20" },
  {   3, "dB-18" },
  {   4, "dB-16" },
  {   5, "dB-14" },
  {   6, "dB-12" },
  {   7, "dB-10" },
  {   8, "dB-8" },
  {   9, "dB-6" },
  {  10, "dB-5" },
  {  11, "dB-4" },
  {  12, "dB-3" },
  {  13, "dB-2" },
  {  14, "dB-1" },
  {  15, "dB0" },
  {  16, "dB1" },
  {  17, "dB2" },
  {  18, "dB3" },
  {  19, "dB4" },
  {  20, "dB5" },
  {  21, "dB6" },
  {  22, "dB8" },
  {  23, "dB10" },
  {  24, "dB12" },
  {  25, "dB14" },
  {  26, "dB16" },
  {  27, "dB18" },
  {  28, "dB20" },
  {  29, "dB22" },
  {  30, "dB24" },
  {  31, "spare" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_offsetFreq_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_maxCellMeas(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxCellMeas, NULL, FALSE);

  return offset;
}


static const per_sequence_t CellIndexList_item_sequence[] = {
  { &hf_lte_rrc_cellIndex   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_maxCellMeas },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CellIndexList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CellIndexList_item, CellIndexList_item_sequence);

  return offset;
}


static const per_sequence_t CellIndexList_sequence_of[1] = {
  { &hf_lte_rrc_CellIndexList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CellIndexList_item },
};

static int
dissect_lte_rrc_CellIndexList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_CellIndexList, CellIndexList_sequence_of,
                                                  1, maxCellMeas, FALSE);

  return offset;
}


static const value_string lte_rrc_T_cellIndividualOffset_vals[] = {
  {   0, "dB-24" },
  {   1, "dB-22" },
  {   2, "dB-20" },
  {   3, "dB-18" },
  {   4, "dB-16" },
  {   5, "dB-14" },
  {   6, "dB-12" },
  {   7, "dB-10" },
  {   8, "dB-8" },
  {   9, "dB-6" },
  {  10, "dB-5" },
  {  11, "dB-4" },
  {  12, "dB-3" },
  {  13, "dB-2" },
  {  14, "dB-1" },
  {  15, "dB0" },
  {  16, "dB1" },
  {  17, "dB2" },
  {  18, "dB3" },
  {  19, "dB4" },
  {  20, "dB5" },
  {  21, "dB6" },
  {  22, "dB8" },
  {  23, "dB10" },
  {  24, "dB12" },
  {  25, "dB14" },
  {  26, "dB16" },
  {  27, "dB18" },
  {  28, "dB20" },
  {  29, "dB22" },
  {  30, "dB24" },
  {  31, "spare" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_cellIndividualOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t NeighCellsToAddModifyList_item_sequence[] = {
  { &hf_lte_rrc_cellIndex   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_maxCellMeas },
  { &hf_lte_rrc_cellIdentity_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentity },
  { &hf_lte_rrc_cellIndividualOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cellIndividualOffset },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_NeighCellsToAddModifyList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_NeighCellsToAddModifyList_item, NeighCellsToAddModifyList_item_sequence);

  return offset;
}


static const per_sequence_t NeighCellsToAddModifyList_sequence_of[1] = {
  { &hf_lte_rrc_NeighCellsToAddModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_NeighCellsToAddModifyList_item },
};

static int
dissect_lte_rrc_NeighCellsToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_NeighCellsToAddModifyList, NeighCellsToAddModifyList_sequence_of,
                                                  1, maxCellMeas, FALSE);

  return offset;
}


static const per_sequence_t BlackListedCellsToAddModifyList_item_sequence[] = {
  { &hf_lte_rrc_cellIndex   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_maxCellMeas },
  { &hf_lte_rrc_cellIdentityAndRange, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentityAndRange },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_BlackListedCellsToAddModifyList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_BlackListedCellsToAddModifyList_item, BlackListedCellsToAddModifyList_item_sequence);

  return offset;
}


static const per_sequence_t BlackListedCellsToAddModifyList_sequence_of[1] = {
  { &hf_lte_rrc_BlackListedCellsToAddModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BlackListedCellsToAddModifyList_item },
};

static int
dissect_lte_rrc_BlackListedCellsToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_BlackListedCellsToAddModifyList, BlackListedCellsToAddModifyList_sequence_of,
                                                  1, maxCellMeas, FALSE);

  return offset;
}


static const per_sequence_t MeasObjectEUTRA_sequence[] = {
  { &hf_lte_rrc_eutra_CarrierInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_EUTRA_DL_CarrierFreq },
  { &hf_lte_rrc_measurementBandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasurementBandwidth },
  { &hf_lte_rrc_offsetFreq_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_offsetFreq_01 },
  { &hf_lte_rrc_cellsToRemoveList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_CellIndexList },
  { &hf_lte_rrc_cellsToAddModifyList_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_NeighCellsToAddModifyList },
  { &hf_lte_rrc_blackListedCellsToRemoveList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_CellIndexList },
  { &hf_lte_rrc_blackListedCellsToAddModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_BlackListedCellsToAddModifyList },
  { &hf_lte_rrc_cellForWhichToReportCGI_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_PhysicalCellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasObjectEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasObjectEUTRA, MeasObjectEUTRA_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M15_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -15, 15U, NULL, FALSE);

  return offset;
}


static const per_sequence_t UTRA_FDD_CellIdentity_sequence[] = {
  { &hf_lte_rrc_primaryScramblingCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_511 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UTRA_FDD_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UTRA_FDD_CellIdentity, UTRA_FDD_CellIdentity_sequence);

  return offset;
}


static const per_sequence_t UTRA_FDD_CellsToAddModifyList_item_sequence[] = {
  { &hf_lte_rrc_cellIndex   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_maxCellMeas },
  { &hf_lte_rrc_utra_FDD_CellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_FDD_CellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UTRA_FDD_CellsToAddModifyList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UTRA_FDD_CellsToAddModifyList_item, UTRA_FDD_CellsToAddModifyList_item_sequence);

  return offset;
}


static const per_sequence_t UTRA_FDD_CellsToAddModifyList_sequence_of[1] = {
  { &hf_lte_rrc_UTRA_FDD_CellsToAddModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_FDD_CellsToAddModifyList_item },
};

static int
dissect_lte_rrc_UTRA_FDD_CellsToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_UTRA_FDD_CellsToAddModifyList, UTRA_FDD_CellsToAddModifyList_sequence_of,
                                                  1, maxCellMeas, FALSE);

  return offset;
}


static const per_sequence_t UTRA_TDD_CellIdentity_sequence[] = {
  { &hf_lte_rrc_cellParametersID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UTRA_TDD_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UTRA_TDD_CellIdentity, UTRA_TDD_CellIdentity_sequence);

  return offset;
}


static const per_sequence_t UTRA_TDD_CellsToAddModifyList_item_sequence[] = {
  { &hf_lte_rrc_cellIndex   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_maxCellMeas },
  { &hf_lte_rrc_utra_TDD_CellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_TDD_CellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UTRA_TDD_CellsToAddModifyList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UTRA_TDD_CellsToAddModifyList_item, UTRA_TDD_CellsToAddModifyList_item_sequence);

  return offset;
}


static const per_sequence_t UTRA_TDD_CellsToAddModifyList_sequence_of[1] = {
  { &hf_lte_rrc_UTRA_TDD_CellsToAddModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_TDD_CellsToAddModifyList_item },
};

static int
dissect_lte_rrc_UTRA_TDD_CellsToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_UTRA_TDD_CellsToAddModifyList, UTRA_TDD_CellsToAddModifyList_sequence_of,
                                                  1, maxCellMeas, FALSE);

  return offset;
}


static const value_string lte_rrc_T_cellsToAddModifyList_vals[] = {
  {   0, "cellsToAddModifyListUTRA-FDD" },
  {   1, "cellsToAddModifyListUTRA-TDD" },
  { 0, NULL }
};

static const per_choice_t T_cellsToAddModifyList_choice[] = {
  {   0, &hf_lte_rrc_cellsToAddModifyListUTRA_FDD, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UTRA_FDD_CellsToAddModifyList },
  {   1, &hf_lte_rrc_cellsToAddModifyListUTRA_TDD, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UTRA_TDD_CellsToAddModifyList },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_cellsToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_cellsToAddModifyList, T_cellsToAddModifyList_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_cellForWhichToReportCGI_vals[] = {
  {   0, "utra-FDD" },
  {   1, "utra-TDD" },
  { 0, NULL }
};

static const per_choice_t T_cellForWhichToReportCGI_choice[] = {
  {   0, &hf_lte_rrc_utra_FDD_01 , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UTRA_FDD_CellIdentity },
  {   1, &hf_lte_rrc_utra_TDD_01 , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UTRA_TDD_CellIdentity },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_cellForWhichToReportCGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_cellForWhichToReportCGI, T_cellForWhichToReportCGI_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasObjectUTRA_sequence[] = {
  { &hf_lte_rrc_utra_CarrierFreq, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_DL_CarrierFreq },
  { &hf_lte_rrc_offsetFreq_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_M15_15 },
  { &hf_lte_rrc_cellsToRemoveList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_CellIndexList },
  { &hf_lte_rrc_cellsToAddModifyList_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_cellsToAddModifyList },
  { &hf_lte_rrc_cellForWhichToReportCGI_03, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_cellForWhichToReportCGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasObjectUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasObjectUTRA, MeasObjectUTRA_sequence);

  return offset;
}


static const per_sequence_t GERAN_MeasFrequencyList_sequence_of[1] = {
  { &hf_lte_rrc_GERAN_MeasFrequencyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_CarrierFreqList },
};

static int
dissect_lte_rrc_GERAN_MeasFrequencyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_GERAN_MeasFrequencyList, GERAN_MeasFrequencyList_sequence_of,
                                                  1, maxGNFG, FALSE);

  return offset;
}


static const per_sequence_t MeasObjectGERAN_sequence[] = {
  { &hf_lte_rrc_geran_MeasFrequencyList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_MeasFrequencyList },
  { &hf_lte_rrc_offsetFreq_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_M15_15 },
  { &hf_lte_rrc_ncc_Permitted, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_BIT_STRING_SIZE_8 },
  { &hf_lte_rrc_cellForWhichToReportCGI_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_GERAN_CellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasObjectGERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasObjectGERAN, MeasObjectGERAN_sequence);

  return offset;
}


static const per_sequence_t CDMA2000_CarrierInfo_sequence[] = {
  { &hf_lte_rrc_bandClass   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Bandclass },
  { &hf_lte_rrc_frequency   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_2047 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CDMA2000_CarrierInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CDMA2000_CarrierInfo, CDMA2000_CarrierInfo_sequence);

  return offset;
}


static const value_string lte_rrc_T_offsetFreq_vals[] = {
  {   0, "db-15" },
  {   1, "dB-14" },
  {   2, "db-13" },
  {   3, "dB-12" },
  {   4, "dB-11" },
  {   5, "dB-10" },
  {   6, "db-9" },
  {   7, "dB-8" },
  {   8, "dB-7" },
  {   9, "dB-6" },
  {  10, "dB-5" },
  {  11, "dB-4" },
  {  12, "dB-3" },
  {  13, "dB-2" },
  {  14, "dB-1" },
  {  15, "dB0" },
  {  16, "dB1" },
  {  17, "dB2" },
  {  18, "dB3" },
  {  19, "dB4" },
  {  20, "dB5" },
  {  21, "dB6" },
  {  22, "db7" },
  {  23, "dB8" },
  {  24, "dB9" },
  {  25, "dB10" },
  {  26, "dB11" },
  {  27, "dB12" },
  {  28, "dB13" },
  {  29, "dB14" },
  {  30, "dB15" },
  {  31, "spare" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_offsetFreq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     32, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t CDMA2000_CellsToAddModifyList_item_sequence[] = {
  { &hf_lte_rrc_cellIndex   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_maxCellMeas },
  { &hf_lte_rrc_cellIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_CellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CDMA2000_CellsToAddModifyList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CDMA2000_CellsToAddModifyList_item, CDMA2000_CellsToAddModifyList_item_sequence);

  return offset;
}


static const per_sequence_t CDMA2000_CellsToAddModifyList_sequence_of[1] = {
  { &hf_lte_rrc_CDMA2000_CellsToAddModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_CellsToAddModifyList_item },
};

static int
dissect_lte_rrc_CDMA2000_CellsToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_CDMA2000_CellsToAddModifyList, CDMA2000_CellsToAddModifyList_sequence_of,
                                                  1, maxCellMeas, FALSE);

  return offset;
}


static const per_sequence_t MeasObjectCDMA2000_sequence[] = {
  { &hf_lte_rrc_cdma2000_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Type },
  { &hf_lte_rrc_cdma2000_CarrierInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_CarrierInfo },
  { &hf_lte_rrc_cdma2000_SearchWindowSize, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_15 },
  { &hf_lte_rrc_offsetFreq  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_offsetFreq },
  { &hf_lte_rrc_cellsToRemoveList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_CellIndexList },
  { &hf_lte_rrc_cellsToAddModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_CDMA2000_CellsToAddModifyList },
  { &hf_lte_rrc_cellForWhichToReportCGI, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_CDMA2000_CellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasObjectCDMA2000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasObjectCDMA2000, MeasObjectCDMA2000_sequence);

  return offset;
}


static const value_string lte_rrc_T_measObject_vals[] = {
  {   0, "measObjectEUTRA" },
  {   1, "measObjectUTRA" },
  {   2, "measObjectGERAN" },
  {   3, "measObjectCDMA2000" },
  { 0, NULL }
};

static const per_choice_t T_measObject_choice[] = {
  {   0, &hf_lte_rrc_measObjectEUTRA, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_MeasObjectEUTRA },
  {   1, &hf_lte_rrc_measObjectUTRA, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_MeasObjectUTRA },
  {   2, &hf_lte_rrc_measObjectGERAN, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_MeasObjectGERAN },
  {   3, &hf_lte_rrc_measObjectCDMA2000, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_MeasObjectCDMA2000 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_measObject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_measObject, T_measObject_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasObjectToAddModifyList_item_sequence[] = {
  { &hf_lte_rrc_measObjectId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasObjectId },
  { &hf_lte_rrc_measObject  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_measObject },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasObjectToAddModifyList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasObjectToAddModifyList_item, MeasObjectToAddModifyList_item_sequence);

  return offset;
}


static const per_sequence_t MeasObjectToAddModifyList_sequence_of[1] = {
  { &hf_lte_rrc_MeasObjectToAddModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasObjectToAddModifyList_item },
};

static int
dissect_lte_rrc_MeasObjectToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MeasObjectToAddModifyList, MeasObjectToAddModifyList_sequence_of,
                                                  1, maxObjectId, FALSE);

  return offset;
}



static int
dissect_lte_rrc_ReportConfigId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxReportConfigId, NULL, FALSE);

  return offset;
}


static const per_sequence_t ReportConfigToRemoveList_item_sequence[] = {
  { &hf_lte_rrc_reportConfigId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReportConfigId },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ReportConfigToRemoveList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ReportConfigToRemoveList_item, ReportConfigToRemoveList_item_sequence);

  return offset;
}


static const per_sequence_t ReportConfigToRemoveList_sequence_of[1] = {
  { &hf_lte_rrc_ReportConfigToRemoveList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReportConfigToRemoveList_item },
};

static int
dissect_lte_rrc_ReportConfigToRemoveList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_ReportConfigToRemoveList, ReportConfigToRemoveList_sequence_of,
                                                  1, maxReportConfigId, FALSE);

  return offset;
}



static int
dissect_lte_rrc_RSRP_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_RSRQ_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_ThresholdEUTRA_vals[] = {
  {   0, "threshold-RSRP" },
  {   1, "threshold-RSRQ" },
  { 0, NULL }
};

static const per_choice_t ThresholdEUTRA_choice[] = {
  {   0, &hf_lte_rrc_threshold_RSRP, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RSRP_Range },
  {   1, &hf_lte_rrc_threshold_RSRQ, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RSRQ_Range },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_ThresholdEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_ThresholdEUTRA, ThresholdEUTRA_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_eventA1_sequence[] = {
  { &hf_lte_rrc_a1_Threshold, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ThresholdEUTRA },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_eventA1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_eventA1, T_eventA1_sequence);

  return offset;
}


static const per_sequence_t T_eventA2_sequence[] = {
  { &hf_lte_rrc_a2_Threshold, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ThresholdEUTRA },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_eventA2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_eventA2, T_eventA2_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M30_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -30, 30U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_eventA3_sequence[] = {
  { &hf_lte_rrc_a3_Offset   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M30_30 },
  { &hf_lte_rrc_reportOnLeave, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_eventA3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_eventA3, T_eventA3_sequence);

  return offset;
}


static const per_sequence_t T_eventA4_sequence[] = {
  { &hf_lte_rrc_a4_Threshold, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ThresholdEUTRA },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_eventA4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_eventA4, T_eventA4_sequence);

  return offset;
}


static const per_sequence_t T_eventA5_sequence[] = {
  { &hf_lte_rrc_a5_Threshold1, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ThresholdEUTRA },
  { &hf_lte_rrc_a5_Threshold2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ThresholdEUTRA },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_eventA5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_eventA5, T_eventA5_sequence);

  return offset;
}


static const value_string lte_rrc_T_eventId_vals[] = {
  {   0, "eventA1" },
  {   1, "eventA2" },
  {   2, "eventA3" },
  {   3, "eventA4" },
  {   4, "eventA5" },
  { 0, NULL }
};

static const per_choice_t T_eventId_choice[] = {
  {   0, &hf_lte_rrc_eventA1     , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_eventA1 },
  {   1, &hf_lte_rrc_eventA2     , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_eventA2 },
  {   2, &hf_lte_rrc_eventA3     , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_eventA3 },
  {   3, &hf_lte_rrc_eventA4     , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_eventA4 },
  {   4, &hf_lte_rrc_eventA5     , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_eventA5 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_eventId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_eventId, T_eventId_choice,
                                 NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 30U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_TimeToTrigger_vals[] = {
  {   0, "ms0" },
  {   1, "ms10" },
  {   2, "ms20" },
  {   3, "ms40" },
  {   4, "ms64" },
  {   5, "ms80" },
  {   6, "ms100" },
  {   7, "ms128" },
  {   8, "ms160" },
  {   9, "ms200" },
  {  10, "ms256" },
  {  11, "ms320" },
  {  12, "ms640" },
  {  13, "ms1280" },
  {  14, "ms2560" },
  {  15, "ms5120" },
  { 0, NULL }
};


static int
dissect_lte_rrc_TimeToTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t T_event_sequence[] = {
  { &hf_lte_rrc_eventId     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_eventId },
  { &hf_lte_rrc_hysteresis  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_30 },
  { &hf_lte_rrc_timeToTrigger, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_TimeToTrigger },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_event(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_event, T_event_sequence);

  return offset;
}


static const value_string lte_rrc_T_purpose_01_vals[] = {
  {   0, "reportStrongestCells" },
  {   1, "reportCGI" },
  { 0, NULL }
};

static const per_choice_t T_purpose_01_choice[] = {
  {   0, &hf_lte_rrc_reportStrongestCells, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_reportCGI   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_purpose_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_purpose_01, T_purpose_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_periodical_sequence[] = {
  { &hf_lte_rrc_purpose_01  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_purpose_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_periodical(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_periodical, T_periodical_sequence);

  return offset;
}


static const value_string lte_rrc_T_triggerType_vals[] = {
  {   0, "event" },
  {   1, "periodical" },
  { 0, NULL }
};

static const per_choice_t T_triggerType_choice[] = {
  {   0, &hf_lte_rrc_event       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_event },
  {   1, &hf_lte_rrc_periodical  , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_periodical },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_triggerType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_triggerType, T_triggerType_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_triggerQuantity_vals[] = {
  {   0, "rsrp" },
  {   1, "rsrq" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_triggerQuantity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_reportQuantity_vals[] = {
  {   0, "sameAsTriggerQuantity" },
  {   1, "both" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_reportQuantity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_maxCellReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxCellReport, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_ReportInterval_vals[] = {
  {   0, "ms120" },
  {   1, "ms240" },
  {   2, "ms480" },
  {   3, "ms640" },
  {   4, "ms1024" },
  {   5, "ms2048" },
  {   6, "ms5120" },
  {   7, "ms10240" },
  {   8, "min1" },
  {   9, "min6" },
  {  10, "min12" },
  {  11, "min30" },
  {  12, "min60" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_ReportInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_reportAmount_vals[] = {
  {   0, "r1" },
  {   1, "r2" },
  {   2, "r4" },
  {   3, "r8" },
  {   4, "r16" },
  {   5, "r32" },
  {   6, "r64" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_reportAmount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ReportConfigEUTRA_sequence[] = {
  { &hf_lte_rrc_triggerType , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_triggerType },
  { &hf_lte_rrc_triggerQuantity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_triggerQuantity },
  { &hf_lte_rrc_reportQuantity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_reportQuantity },
  { &hf_lte_rrc_maxReportCells, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_maxCellReport },
  { &hf_lte_rrc_reportInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReportInterval },
  { &hf_lte_rrc_reportAmount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_reportAmount },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ReportConfigEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ReportConfigEUTRA, ReportConfigEUTRA_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_M5_91(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -5, 91U, NULL, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_49(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 49U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_ThresholdUTRA_vals[] = {
  {   0, "thresholdUTRA-RSCP" },
  {   1, "thresholdUTRA-EcNO" },
  { 0, NULL }
};

static const per_choice_t ThresholdUTRA_choice[] = {
  {   0, &hf_lte_rrc_thresholdUTRA_RSCP, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_M5_91 },
  {   1, &hf_lte_rrc_thresholdUTRA_EcNO, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_49 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_ThresholdUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_ThresholdUTRA, ThresholdUTRA_choice,
                                 NULL);

  return offset;
}



static int
dissect_lte_rrc_ThresholdGERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const value_string lte_rrc_T_b1_Threshold_vals[] = {
  {   0, "b1-Threshold-CDMA2000" },
  {   1, "b1-Threshold-UTRA" },
  {   2, "b1-Threshold-GERAN" },
  { 0, NULL }
};

static const per_choice_t T_b1_Threshold_choice[] = {
  {   0, &hf_lte_rrc_b1_Threshold_CDMA2000, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_63 },
  {   1, &hf_lte_rrc_b1_Threshold_UTRA, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ThresholdUTRA },
  {   2, &hf_lte_rrc_b1_Threshold_GERAN, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ThresholdGERAN },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_b1_Threshold(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_b1_Threshold, T_b1_Threshold_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_eventB1_sequence[] = {
  { &hf_lte_rrc_b1_Threshold, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_b1_Threshold },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_eventB1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_eventB1, T_eventB1_sequence);

  return offset;
}


static const value_string lte_rrc_T_b2_Threshold2_vals[] = {
  {   0, "b2-Threshold2-CDMA2000" },
  {   1, "b2-Threshold2-UTRA" },
  {   2, "b2-Threshold2-GERAN" },
  { 0, NULL }
};

static const per_choice_t T_b2_Threshold2_choice[] = {
  {   0, &hf_lte_rrc_b2_Threshold2_CDMA2000, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_INTEGER_0_63 },
  {   1, &hf_lte_rrc_b2_Threshold2_UTRA, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ThresholdUTRA },
  {   2, &hf_lte_rrc_b2_Threshold2_GERAN, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ThresholdGERAN },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_b2_Threshold2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_b2_Threshold2, T_b2_Threshold2_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_eventB2_sequence[] = {
  { &hf_lte_rrc_b2_Threshold1, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ThresholdEUTRA },
  { &hf_lte_rrc_b2_Threshold2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_b2_Threshold2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_eventB2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_eventB2, T_eventB2_sequence);

  return offset;
}


static const value_string lte_rrc_T_eventId_01_vals[] = {
  {   0, "eventB1" },
  {   1, "eventB2" },
  { 0, NULL }
};

static const per_choice_t T_eventId_01_choice[] = {
  {   0, &hf_lte_rrc_eventB1     , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_eventB1 },
  {   1, &hf_lte_rrc_eventB2     , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_eventB2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_eventId_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_eventId_01, T_eventId_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_event_01_sequence[] = {
  { &hf_lte_rrc_eventId_01  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_eventId_01 },
  { &hf_lte_rrc_hysteresis  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_30 },
  { &hf_lte_rrc_timeToTrigger, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_TimeToTrigger },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_event_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_event_01, T_event_01_sequence);

  return offset;
}


static const value_string lte_rrc_T_purpose_02_vals[] = {
  {   0, "reportStrongestCells" },
  {   1, "reportStrongestCellsForSON" },
  {   2, "reportCGI" },
  { 0, NULL }
};

static const per_choice_t T_purpose_02_choice[] = {
  {   0, &hf_lte_rrc_reportStrongestCells, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_reportStrongestCellsForSON, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_reportCGI   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_purpose_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_purpose_02, T_purpose_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_periodical_01_sequence[] = {
  { &hf_lte_rrc_purpose_02  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_purpose_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_periodical_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_periodical_01, T_periodical_01_sequence);

  return offset;
}


static const value_string lte_rrc_T_triggerType_01_vals[] = {
  {   0, "event" },
  {   1, "periodical" },
  { 0, NULL }
};

static const per_choice_t T_triggerType_01_choice[] = {
  {   0, &hf_lte_rrc_event_01    , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_event_01 },
  {   1, &hf_lte_rrc_periodical_01, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_periodical_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_triggerType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_triggerType_01, T_triggerType_01_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_T_reportAmount_01_vals[] = {
  {   0, "r1" },
  {   1, "r2" },
  {   2, "r4" },
  {   3, "r8" },
  {   4, "r16" },
  {   5, "r32" },
  {   6, "r64" },
  {   7, "infinity" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_reportAmount_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ReportConfigInterRAT_sequence[] = {
  { &hf_lte_rrc_triggerType_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_triggerType_01 },
  { &hf_lte_rrc_maxReportCells, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_maxCellReport },
  { &hf_lte_rrc_reportInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReportInterval },
  { &hf_lte_rrc_reportAmount_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_reportAmount_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ReportConfigInterRAT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ReportConfigInterRAT, ReportConfigInterRAT_sequence);

  return offset;
}


static const value_string lte_rrc_T_reportConfig_vals[] = {
  {   0, "reportConfigEUTRA" },
  {   1, "reportConfigInterRAT" },
  { 0, NULL }
};

static const per_choice_t T_reportConfig_choice[] = {
  {   0, &hf_lte_rrc_reportConfigEUTRA, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ReportConfigEUTRA },
  {   1, &hf_lte_rrc_reportConfigInterRAT, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ReportConfigInterRAT },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_reportConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_reportConfig, T_reportConfig_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ReportConfigToAddModifyList_item_sequence[] = {
  { &hf_lte_rrc_reportConfigId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReportConfigId },
  { &hf_lte_rrc_reportConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_reportConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ReportConfigToAddModifyList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ReportConfigToAddModifyList_item, ReportConfigToAddModifyList_item_sequence);

  return offset;
}


static const per_sequence_t ReportConfigToAddModifyList_sequence_of[1] = {
  { &hf_lte_rrc_ReportConfigToAddModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReportConfigToAddModifyList_item },
};

static int
dissect_lte_rrc_ReportConfigToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_ReportConfigToAddModifyList, ReportConfigToAddModifyList_sequence_of,
                                                  1, maxReportConfigId, FALSE);

  return offset;
}



static int
dissect_lte_rrc_MeasId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxMeasId, NULL, FALSE);

  return offset;
}


static const per_sequence_t MeasIdToRemoveList_item_sequence[] = {
  { &hf_lte_rrc_measId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasId },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasIdToRemoveList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasIdToRemoveList_item, MeasIdToRemoveList_item_sequence);

  return offset;
}


static const per_sequence_t MeasIdToRemoveList_sequence_of[1] = {
  { &hf_lte_rrc_MeasIdToRemoveList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasIdToRemoveList_item },
};

static int
dissect_lte_rrc_MeasIdToRemoveList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MeasIdToRemoveList, MeasIdToRemoveList_sequence_of,
                                                  1, maxMeasId, FALSE);

  return offset;
}


static const per_sequence_t MeasIdToAddModifyList_item_sequence[] = {
  { &hf_lte_rrc_measId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasId },
  { &hf_lte_rrc_measObjectId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasObjectId },
  { &hf_lte_rrc_reportConfigId, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReportConfigId },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasIdToAddModifyList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasIdToAddModifyList_item, MeasIdToAddModifyList_item_sequence);

  return offset;
}


static const per_sequence_t MeasIdToAddModifyList_sequence_of[1] = {
  { &hf_lte_rrc_MeasIdToAddModifyList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasIdToAddModifyList_item },
};

static int
dissect_lte_rrc_MeasIdToAddModifyList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MeasIdToAddModifyList, MeasIdToAddModifyList_sequence_of,
                                                  1, maxMeasId, FALSE);

  return offset;
}


static const value_string lte_rrc_FilterCoefficient_vals[] = {
  {   0, "fc0" },
  {   1, "fc1" },
  {   2, "fc2" },
  {   3, "fc3" },
  {   4, "fc4" },
  {   5, "fc5" },
  {   6, "fc6" },
  {   7, "fc7" },
  {   8, "fc8" },
  {   9, "fc9" },
  {  10, "fc11" },
  {  11, "fc13" },
  {  12, "fc15" },
  {  13, "fc17" },
  {  14, "fc19" },
  {  15, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_FilterCoefficient(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t QuantityConfigEUTRA_sequence[] = {
  { &hf_lte_rrc_filterCoefficientRSRP, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_FilterCoefficient },
  { &hf_lte_rrc_filterCoefficientRSRQ, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_FilterCoefficient },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_QuantityConfigEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_QuantityConfigEUTRA, QuantityConfigEUTRA_sequence);

  return offset;
}


static const value_string lte_rrc_T_measQuantityUTRA_FDD_vals[] = {
  {   0, "cpich-RSCP" },
  {   1, "cpich-EcN0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_measQuantityUTRA_FDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_measQuantityUTRA_TDD_vals[] = {
  {   0, "pccpch-RSCP" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_measQuantityUTRA_TDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t QuantityConfigUTRA_sequence[] = {
  { &hf_lte_rrc_measQuantityUTRA_FDD, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_measQuantityUTRA_FDD },
  { &hf_lte_rrc_measQuantityUTRA_TDD, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_measQuantityUTRA_TDD },
  { &hf_lte_rrc_filterCoefficient, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_FilterCoefficient },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_QuantityConfigUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_QuantityConfigUTRA, QuantityConfigUTRA_sequence);

  return offset;
}


static const value_string lte_rrc_T_measQuantityGERAN_vals[] = {
  {   0, "rssi" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_measQuantityGERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t QuantityConfigGERAN_sequence[] = {
  { &hf_lte_rrc_measQuantityGERAN, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_measQuantityGERAN },
  { &hf_lte_rrc_filterCoefficient, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_FilterCoefficient },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_QuantityConfigGERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_QuantityConfigGERAN, QuantityConfigGERAN_sequence);

  return offset;
}


static const value_string lte_rrc_T_measQuantityCDMA2000_vals[] = {
  {   0, "pilotStrength" },
  {   1, "pilotPnPhaseAndPilotStrength" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_measQuantityCDMA2000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t QuantityConfigCDMA2000_sequence[] = {
  { &hf_lte_rrc_measQuantityCDMA2000, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_measQuantityCDMA2000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_QuantityConfigCDMA2000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_QuantityConfigCDMA2000, QuantityConfigCDMA2000_sequence);

  return offset;
}


static const per_sequence_t QuantityConfig_sequence[] = {
  { &hf_lte_rrc_quantityConfigEUTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_QuantityConfigEUTRA },
  { &hf_lte_rrc_quantityConfigUTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_QuantityConfigUTRA },
  { &hf_lte_rrc_quantityConfigGERAN, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_QuantityConfigGERAN },
  { &hf_lte_rrc_quantityConfigCDMA2000, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_QuantityConfigCDMA2000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_QuantityConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_QuantityConfig, QuantityConfig_sequence);

  return offset;
}


static const per_sequence_t T_gp1_sequence[] = {
  { &hf_lte_rrc_gapOffset   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_39 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_gp1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_gp1, T_gp1_sequence);

  return offset;
}


static const per_sequence_t T_gp2_sequence[] = {
  { &hf_lte_rrc_gapOffset_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_79 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_gp2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_gp2, T_gp2_sequence);

  return offset;
}


static const value_string lte_rrc_T_gapPattern_vals[] = {
  {   0, "gp1" },
  {   1, "gp2" },
  { 0, NULL }
};

static const per_choice_t T_gapPattern_choice[] = {
  {   0, &hf_lte_rrc_gp1         , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_gp1 },
  {   1, &hf_lte_rrc_gp2         , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_T_gp2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_gapPattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_gapPattern, T_gapPattern_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_activate_sequence[] = {
  { &hf_lte_rrc_gapPattern  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_gapPattern },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_activate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_activate, T_activate_sequence);

  return offset;
}


static const value_string lte_rrc_T_gapActivation_vals[] = {
  {   0, "activate" },
  {   1, "deactivate" },
  { 0, NULL }
};

static const per_choice_t T_gapActivation_choice[] = {
  {   0, &hf_lte_rrc_activate    , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_activate },
  {   1, &hf_lte_rrc_deactivate  , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_gapActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_gapActivation, T_gapActivation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasGapConfig_sequence[] = {
  { &hf_lte_rrc_gapActivation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_gapActivation },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasGapConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasGapConfig, MeasGapConfig_sequence);

  return offset;
}


static const value_string lte_rrc_T_timeToTriggerSF_Medium_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_timeToTriggerSF_Medium(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_timeToTriggerSF_High_vals[] = {
  {   0, "oDot25" },
  {   1, "oDot5" },
  {   2, "oDot75" },
  {   3, "lDot0" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_timeToTriggerSF_High(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t ConnectedModeSpeedDependentScalingParameters_sequence[] = {
  { &hf_lte_rrc_timeToTriggerSF_Medium, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_timeToTriggerSF_Medium },
  { &hf_lte_rrc_timeToTriggerSF_High, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_timeToTriggerSF_High },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ConnectedModeSpeedDependentScalingParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ConnectedModeSpeedDependentScalingParameters, ConnectedModeSpeedDependentScalingParameters_sequence);

  return offset;
}


static const per_sequence_t T_enable_11_sequence[] = {
  { &hf_lte_rrc_mobilityStateParameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MobilityStateParameters },
  { &hf_lte_rrc_speedDependentScalingParameters_06, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ConnectedModeSpeedDependentScalingParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_enable_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_enable_11, T_enable_11_sequence);

  return offset;
}


static const value_string lte_rrc_T_speedDependentParameters_vals[] = {
  {   0, "disable" },
  {   1, "enable" },
  { 0, NULL }
};

static const per_choice_t T_speedDependentParameters_choice[] = {
  {   0, &hf_lte_rrc_disable     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   1, &hf_lte_rrc_enable_11   , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_enable_11 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_speedDependentParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_speedDependentParameters, T_speedDependentParameters_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasurementConfiguration_sequence[] = {
  { &hf_lte_rrc_measObjectToRemoveList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_MeasObjectToRemoveList },
  { &hf_lte_rrc_measObjectToAddModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_MeasObjectToAddModifyList },
  { &hf_lte_rrc_reportConfigToRemoveList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_ReportConfigToRemoveList },
  { &hf_lte_rrc_reportConfigToAddModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_ReportConfigToAddModifyList },
  { &hf_lte_rrc_measIdToRemoveList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_MeasIdToRemoveList },
  { &hf_lte_rrc_measIdToAddModifyList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_MeasIdToAddModifyList },
  { &hf_lte_rrc_quantityConfig, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_QuantityConfig },
  { &hf_lte_rrc_measGapConfig, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_MeasGapConfig },
  { &hf_lte_rrc_s_Measure   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_RSRP_Range },
  { &hf_lte_rrc_hrpd_PreRegistrationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_HRPD_PreRegistrationInfo },
  { &hf_lte_rrc_neighbourCellConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_NeighbourCellConfiguration },
  { &hf_lte_rrc_speedDependentParameters, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_speedDependentParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasurementConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasurementConfiguration, MeasurementConfiguration_sequence);

  return offset;
}


static const per_sequence_t EUTRA_CarrierFreq_sequence[] = {
  { &hf_lte_rrc_earfcn_DL   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_maxEARFCN },
  { &hf_lte_rrc_earfcn_UL   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_EUTRA_DL_CarrierFreq },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_EUTRA_CarrierFreq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_EUTRA_CarrierFreq, EUTRA_CarrierFreq_sequence);

  return offset;
}


static const value_string lte_rrc_T_dl_Bandwidth_01_vals[] = {
  {   0, "n6" },
  {   1, "n15" },
  {   2, "n25" },
  {   3, "n50" },
  {   4, "n75" },
  {   5, "n100" },
  {   6, "spare10" },
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


static int
dissect_lte_rrc_T_dl_Bandwidth_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_ul_Bandwidth_01_vals[] = {
  {   0, "n6" },
  {   1, "n15" },
  {   2, "n25" },
  {   3, "n50" },
  {   4, "n75" },
  {   5, "n100" },
  {   6, "spare10" },
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


static int
dissect_lte_rrc_T_ul_Bandwidth_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t EUTRA_CarrierBandwidth_sequence[] = {
  { &hf_lte_rrc_dl_Bandwidth_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_dl_Bandwidth_01 },
  { &hf_lte_rrc_ul_Bandwidth_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_ul_Bandwidth_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_EUTRA_CarrierBandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_EUTRA_CarrierBandwidth, EUTRA_CarrierBandwidth_sequence);

  return offset;
}


static const value_string lte_rrc_T_t304_01_vals[] = {
  {   0, "ms50" },
  {   1, "ms100" },
  {   2, "ms150" },
  {   3, "ms200" },
  {   4, "ms500" },
  {   5, "ms1000" },
  {   6, "ms2000" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t304_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PRACH_Configuration_sequence[] = {
  { &hf_lte_rrc_rootSequenceIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_837 },
  { &hf_lte_rrc_prach_ConfigInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_PRACH_ConfigInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PRACH_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PRACH_Configuration, PRACH_Configuration_sequence);

  return offset;
}


static const value_string lte_rrc_T_antennaPortsCount_vals[] = {
  {   0, "an1" },
  {   1, "an2" },
  {   2, "an4" },
  {   3, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_antennaPortsCount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AntennaInformationCommon_sequence[] = {
  { &hf_lte_rrc_antennaPortsCount, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_antennaPortsCount },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_AntennaInformationCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_AntennaInformationCommon, AntennaInformationCommon_sequence);

  return offset;
}


static const per_sequence_t RadioResourceConfigCommon_sequence[] = {
  { &hf_lte_rrc_rach_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_RACH_ConfigCommon },
  { &hf_lte_rrc_prach_Configuration_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PRACH_Configuration },
  { &hf_lte_rrc_pdsch_Configuration_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_PDSCH_ConfigCommon },
  { &hf_lte_rrc_pusch_Configuration_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PUSCH_ConfigCommon },
  { &hf_lte_rrc_phich_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_PHICH_Configuration },
  { &hf_lte_rrc_pucch_Configuration_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_PUCCH_ConfigCommon },
  { &hf_lte_rrc_soundingRsUl_Config_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_SoundingRsUl_ConfigCommon },
  { &hf_lte_rrc_uplinkPowerControl_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_UplinkPowerControlCommon },
  { &hf_lte_rrc_antennaInformationCommon, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_AntennaInformationCommon },
  { &hf_lte_rrc_tdd_Configuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_TDD_Configuration },
  { &hf_lte_rrc_ul_CyclicPrefixLength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UL_CyclicPrefixLength },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RadioResourceConfigCommon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RadioResourceConfigCommon, RadioResourceConfigCommon_sequence);

  return offset;
}


static const per_sequence_t RACH_ConfigDedicated_sequence[] = {
  { &hf_lte_rrc_ra_PreambleIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_64 },
  { &hf_lte_rrc_ra_PRACH_MaskIndex, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RACH_ConfigDedicated(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RACH_ConfigDedicated, RACH_ConfigDedicated_sequence);

  return offset;
}


static const per_sequence_t MobilityControlInformation_sequence[] = {
  { &hf_lte_rrc_targetCellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentity },
  { &hf_lte_rrc_eutra_CarrierFreq_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_EUTRA_CarrierFreq },
  { &hf_lte_rrc_eutra_CarrierBandwidth, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_EUTRA_CarrierBandwidth },
  { &hf_lte_rrc_additionalSpectrumEmission, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_31 },
  { &hf_lte_rrc_p_Max       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_P_Max },
  { &hf_lte_rrc_t304_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_t304_01 },
  { &hf_lte_rrc_newUE_Identity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_C_RNTI },
  { &hf_lte_rrc_radioResourceConfigCommon_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RadioResourceConfigCommon },
  { &hf_lte_rrc_rach_ConfigDedicated, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_RACH_ConfigDedicated },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MobilityControlInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MobilityControlInformation, MobilityControlInformation_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxDRB_OF_NAS_DedicatedInformation_sequence_of[1] = {
  { &hf_lte_rrc_nas_DedicatedInformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_NAS_DedicatedInformation },
};

static int
dissect_lte_rrc_SEQUENCE_SIZE_1_maxDRB_OF_NAS_DedicatedInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SEQUENCE_SIZE_1_maxDRB_OF_NAS_DedicatedInformation, SEQUENCE_SIZE_1_maxDRB_OF_NAS_DedicatedInformation_sequence_of,
                                                  1, maxDRB, FALSE);

  return offset;
}


static const value_string lte_rrc_IntegrityProtAlgorithm_vals[] = {
  {   0, "eia1" },
  {   1, "eia2" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_IntegrityProtAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_CipheringAlgorithm_vals[] = {
  {   0, "eea0" },
  {   1, "eea1" },
  {   2, "eea2" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_CipheringAlgorithm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SecurityConfiguration_sequence[] = {
  { &hf_lte_rrc_integrityProtAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_IntegrityProtAlgorithm },
  { &hf_lte_rrc_cipheringAlgorithm, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_CipheringAlgorithm },
  { &hf_lte_rrc_keyChangeIndicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_nextHopChainingCount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_NextHopChainingCount },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SecurityConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SecurityConfiguration, SecurityConfiguration_sequence);

  return offset;
}



static int
dissect_lte_rrc_OCTET_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_09_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_09, T_nonCriticalExtension_09_sequence);

  return offset;
}


static const per_sequence_t RRCConnectionReconfiguration_r8_IEs_sequence[] = {
  { &hf_lte_rrc_measurementConfiguration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_MeasurementConfiguration },
  { &hf_lte_rrc_mobilityControlInformation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_MobilityControlInformation },
  { &hf_lte_rrc_nas_DedicatedInformationList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_SEQUENCE_SIZE_1_maxDRB_OF_NAS_DedicatedInformation },
  { &hf_lte_rrc_radioResourceConfiguration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_RadioResourceConfigDedicated },
  { &hf_lte_rrc_securityConfiguration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_SecurityConfiguration },
  { &hf_lte_rrc_nas_SecurityParamToEUTRA, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_OCTET_STRING_SIZE_6 },
  { &hf_lte_rrc_nonCriticalExtension_09, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_09 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReconfiguration_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReconfiguration_r8_IEs, RRCConnectionReconfiguration_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_11_vals[] = {
  {   0, "rrcConnectionReconfiguration-r8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_11_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionReconfiguration_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReconfiguration_r8_IEs },
  {   1, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   4, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   5, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   6, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   7, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_11, T_c1_11_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_08_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_08, T_criticalExtensionsFuture_08_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_08_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_08_choice[] = {
  {   0, &hf_lte_rrc_c1_11       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_11 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_08, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_08 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_08(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_08, T_criticalExtensions_08_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionReconfiguration_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_08, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_08 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReconfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionReconfiguration");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReconfiguration, RRCConnectionReconfiguration_sequence);

  return offset;
}


static const value_string lte_rrc_ReleaseCause_vals[] = {
  {   0, "loadBalancingTAUrequired" },
  {   1, "other" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_ReleaseCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_interRAT_target_vals[] = {
  {   0, "geran" },
  {   1, "utra-FDD" },
  {   2, "utra-TDD" },
  {   3, "cdma2000-HRPD" },
  {   4, "cdma2000-1xRTT" },
  { 0, NULL }
};

static const per_choice_t T_interRAT_target_choice[] = {
  {   0, &hf_lte_rrc_geran_01    , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_GERAN_CarrierFreq },
  {   1, &hf_lte_rrc_utra_FDD    , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_UTRA_DL_CarrierFreq },
  {   2, &hf_lte_rrc_utra_TDD    , ASN1_EXTENSION_ROOT    , dissect_lte_rrc_UTRA_DL_CarrierFreq },
  {   3, &hf_lte_rrc_cdma2000_HRPD, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_CDMA2000_CarrierInfo },
  {   4, &hf_lte_rrc_cdma2000_1xRTT, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_CDMA2000_CarrierInfo },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_interRAT_target(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_interRAT_target, T_interRAT_target_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_RedirectionInformation_vals[] = {
  {   0, "eutra-CarrierFreq" },
  {   1, "interRAT-target" },
  { 0, NULL }
};

static const per_choice_t RedirectionInformation_choice[] = {
  {   0, &hf_lte_rrc_eutra_CarrierFreq, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_EUTRA_DL_CarrierFreq },
  {   1, &hf_lte_rrc_interRAT_target, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_interRAT_target },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_RedirectionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_RedirectionInformation, RedirectionInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InterFreqPriorityList_item_sequence[] = {
  { &hf_lte_rrc_eutra_CarrierFreq, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_EUTRA_DL_CarrierFreq },
  { &hf_lte_rrc_cellReselectionPriority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_InterFreqPriorityList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_InterFreqPriorityList_item, InterFreqPriorityList_item_sequence);

  return offset;
}


static const per_sequence_t InterFreqPriorityList_sequence_of[1] = {
  { &hf_lte_rrc_InterFreqPriorityList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_InterFreqPriorityList_item },
};

static int
dissect_lte_rrc_InterFreqPriorityList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_InterFreqPriorityList, InterFreqPriorityList_sequence_of,
                                                  1, maxFreq, FALSE);

  return offset;
}


static const per_sequence_t GERAN_FreqPriorityList_item_sequence[] = {
  { &hf_lte_rrc_geran_BCCH_FrequencyGroup, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_CarrierFreqList },
  { &hf_lte_rrc_geran_CellReselectionPriority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_GERAN_FreqPriorityList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_GERAN_FreqPriorityList_item, GERAN_FreqPriorityList_item_sequence);

  return offset;
}


static const per_sequence_t GERAN_FreqPriorityList_sequence_of[1] = {
  { &hf_lte_rrc_GERAN_FreqPriorityList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_FreqPriorityList_item },
};

static int
dissect_lte_rrc_GERAN_FreqPriorityList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_GERAN_FreqPriorityList, GERAN_FreqPriorityList_sequence_of,
                                                  1, maxGNFG, FALSE);

  return offset;
}


static const per_sequence_t UTRA_FDD_FreqPriorityList_item_sequence[] = {
  { &hf_lte_rrc_utra_CarrierFreq, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_DL_CarrierFreq },
  { &hf_lte_rrc_utra_CellReselectionPriority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UTRA_FDD_FreqPriorityList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UTRA_FDD_FreqPriorityList_item, UTRA_FDD_FreqPriorityList_item_sequence);

  return offset;
}


static const per_sequence_t UTRA_FDD_FreqPriorityList_sequence_of[1] = {
  { &hf_lte_rrc_UTRA_FDD_FreqPriorityList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_FDD_FreqPriorityList_item },
};

static int
dissect_lte_rrc_UTRA_FDD_FreqPriorityList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_UTRA_FDD_FreqPriorityList, UTRA_FDD_FreqPriorityList_sequence_of,
                                                  1, maxUTRA_FDD_Carrier, FALSE);

  return offset;
}


static const per_sequence_t UTRA_TDD_FreqPriorityList_item_sequence[] = {
  { &hf_lte_rrc_utra_CarrierFreq, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_DL_CarrierFreq },
  { &hf_lte_rrc_utra_CellReselectionPriority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UTRA_TDD_FreqPriorityList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UTRA_TDD_FreqPriorityList_item, UTRA_TDD_FreqPriorityList_item_sequence);

  return offset;
}


static const per_sequence_t UTRA_TDD_FreqPriorityList_sequence_of[1] = {
  { &hf_lte_rrc_UTRA_TDD_FreqPriorityList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UTRA_TDD_FreqPriorityList_item },
};

static int
dissect_lte_rrc_UTRA_TDD_FreqPriorityList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_UTRA_TDD_FreqPriorityList, UTRA_TDD_FreqPriorityList_sequence_of,
                                                  1, maxUTRA_TDD_Carrier, FALSE);

  return offset;
}


static const per_sequence_t HRPD_BandClassPriorityList_item_sequence[] = {
  { &hf_lte_rrc_hrpd_bandClass, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Bandclass },
  { &hf_lte_rrc_hrpd_CellReselectionPriority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_HRPD_BandClassPriorityList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_HRPD_BandClassPriorityList_item, HRPD_BandClassPriorityList_item_sequence);

  return offset;
}


static const per_sequence_t HRPD_BandClassPriorityList_sequence_of[1] = {
  { &hf_lte_rrc_HRPD_BandClassPriorityList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_HRPD_BandClassPriorityList_item },
};

static int
dissect_lte_rrc_HRPD_BandClassPriorityList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_HRPD_BandClassPriorityList, HRPD_BandClassPriorityList_sequence_of,
                                                  1, maxCDMA_BandClass, FALSE);

  return offset;
}


static const per_sequence_t OneXRTT_BandClassPriorityList_item_sequence[] = {
  { &hf_lte_rrc_oneXRTT_bandClass, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Bandclass },
  { &hf_lte_rrc_oneXRTT_CellReselectionPriority, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_OneXRTT_BandClassPriorityList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_OneXRTT_BandClassPriorityList_item, OneXRTT_BandClassPriorityList_item_sequence);

  return offset;
}


static const per_sequence_t OneXRTT_BandClassPriorityList_sequence_of[1] = {
  { &hf_lte_rrc_OneXRTT_BandClassPriorityList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OneXRTT_BandClassPriorityList_item },
};

static int
dissect_lte_rrc_OneXRTT_BandClassPriorityList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_OneXRTT_BandClassPriorityList, OneXRTT_BandClassPriorityList_sequence_of,
                                                  1, maxCDMA_BandClass, FALSE);

  return offset;
}


static const value_string lte_rrc_T_t320_vals[] = {
  {   0, "min5" },
  {   1, "min10" },
  {   2, "min20" },
  {   3, "min30" },
  {   4, "min60" },
  {   5, "min120" },
  {   6, "min180" },
  {   7, "spare" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_t320(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t IdleModeMobilityControlInfo_sequence[] = {
  { &hf_lte_rrc_interFreqPriorityList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_InterFreqPriorityList },
  { &hf_lte_rrc_geran_FreqPriorityList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_GERAN_FreqPriorityList },
  { &hf_lte_rrc_utra_FDD_FreqPriorityList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_UTRA_FDD_FreqPriorityList },
  { &hf_lte_rrc_utra_TDD_FreqPriorityList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_UTRA_TDD_FreqPriorityList },
  { &hf_lte_rrc_hrpd_BandClassPriorityList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_HRPD_BandClassPriorityList },
  { &hf_lte_rrc_oneXRTT_BandClassPriorityList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_OneXRTT_BandClassPriorityList },
  { &hf_lte_rrc_t320        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_t320 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_IdleModeMobilityControlInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_IdleModeMobilityControlInfo, IdleModeMobilityControlInfo_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_15_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_15, T_nonCriticalExtension_15_sequence);

  return offset;
}


static const per_sequence_t RRCConnectionRelease_r8_IEs_sequence[] = {
  { &hf_lte_rrc_releaseCause, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReleaseCause },
  { &hf_lte_rrc_redirectionInformation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_RedirectionInformation },
  { &hf_lte_rrc_idleModeMobilityControlInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_IdleModeMobilityControlInfo },
  { &hf_lte_rrc_nonCriticalExtension_15, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionRelease_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionRelease_r8_IEs, RRCConnectionRelease_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_14_vals[] = {
  {   0, "rrcConnectionRelease-r8" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_14_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionRelease_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionRelease_r8_IEs },
  {   1, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_14, T_c1_14_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_15_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_15, T_criticalExtensionsFuture_15_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_15_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_15_choice[] = {
  {   0, &hf_lte_rrc_c1_14       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_14 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_15, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_15 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_15, T_criticalExtensions_15_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionRelease_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_15, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionRelease");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionRelease, RRCConnectionRelease_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_18_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_18, T_nonCriticalExtension_18_sequence);

  return offset;
}


static const per_sequence_t SecurityModeCommand_r8_IEs_sequence[] = {
  { &hf_lte_rrc_securityConfiguration, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SecurityConfiguration },
  { &hf_lte_rrc_nonCriticalExtension_18, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_18 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SecurityModeCommand_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SecurityModeCommand_r8_IEs, SecurityModeCommand_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_17_vals[] = {
  {   0, "securityModeCommand-r8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_17_choice[] = {
  {   0, &hf_lte_rrc_securityModeCommand_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_SecurityModeCommand_r8_IEs },
  {   1, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   4, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   5, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   6, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   7, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_17(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_17, T_c1_17_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_19_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_19, T_criticalExtensionsFuture_19_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_19_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_19_choice[] = {
  {   0, &hf_lte_rrc_c1_17       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_17 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_19, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_19 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_19, T_criticalExtensions_19_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SecurityModeCommand_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_19, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_19 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SecurityModeCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "SecurityModeCommand");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SecurityModeCommand, SecurityModeCommand_sequence);

  return offset;
}


static const value_string lte_rrc_RAT_Type_vals[] = {
  {   0, "eutra" },
  {   1, "utran" },
  {   2, "geran" },
  {   3, "cdma2000-1xrttBandClass" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_RAT_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t UE_RadioAccessCapRequest_sequence_of[1] = {
  { &hf_lte_rrc_UE_RadioAccessCapRequest_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RAT_Type },
};

static int
dissect_lte_rrc_UE_RadioAccessCapRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_UE_RadioAccessCapRequest, UE_RadioAccessCapRequest_sequence_of,
                                                  1, maxRAT_Capabilities, FALSE);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_23_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_23, T_nonCriticalExtension_23_sequence);

  return offset;
}


static const per_sequence_t UECapabilityEnquiry_r8_IEs_sequence[] = {
  { &hf_lte_rrc_ue_RadioAccessCapRequest, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UE_RadioAccessCapRequest },
  { &hf_lte_rrc_nonCriticalExtension_23, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_23 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UECapabilityEnquiry_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UECapabilityEnquiry_r8_IEs, UECapabilityEnquiry_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_18_vals[] = {
  {   0, "ueCapabilityEnquiry-r8" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_18_choice[] = {
  {   0, &hf_lte_rrc_ueCapabilityEnquiry_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UECapabilityEnquiry_r8_IEs },
  {   1, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_18, T_c1_18_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_23_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_23, T_criticalExtensionsFuture_23_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_23_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_23_choice[] = {
  {   0, &hf_lte_rrc_c1_18       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_18 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_23, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_23 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_23, T_criticalExtensions_23_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UECapabilityEnquiry_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_23, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_23 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UECapabilityEnquiry(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "UECapabilityEnquiry");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UECapabilityEnquiry, UECapabilityEnquiry_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_33554431(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 33554431U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DRB_CountMSB_InfoList_item_sequence[] = {
  { &hf_lte_rrc_drb_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_32 },
  { &hf_lte_rrc_countMSB_Uplink, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_33554431 },
  { &hf_lte_rrc_countMSB_Downlink, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_33554431 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DRB_CountMSB_InfoList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DRB_CountMSB_InfoList_item, DRB_CountMSB_InfoList_item_sequence);

  return offset;
}


static const per_sequence_t DRB_CountMSB_InfoList_sequence_of[1] = {
  { &hf_lte_rrc_DRB_CountMSB_InfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DRB_CountMSB_InfoList_item },
};

static int
dissect_lte_rrc_DRB_CountMSB_InfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_DRB_CountMSB_InfoList, DRB_CountMSB_InfoList_sequence_of,
                                                  1, maxDRB, FALSE);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_02_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_02, T_nonCriticalExtension_02_sequence);

  return offset;
}


static const per_sequence_t CounterCheck_r8_IEs_sequence[] = {
  { &hf_lte_rrc_drb_CountMSB_InfoList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DRB_CountMSB_InfoList },
  { &hf_lte_rrc_nonCriticalExtension_02, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CounterCheck_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CounterCheck_r8_IEs, CounterCheck_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_06_vals[] = {
  {   0, "counterCheck-r8" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_06_choice[] = {
  {   0, &hf_lte_rrc_counterCheck_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_CounterCheck_r8_IEs },
  {   1, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_06, T_c1_06_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_02_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_02, T_criticalExtensionsFuture_02_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_02_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_02_choice[] = {
  {   0, &hf_lte_rrc_c1_06       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_06 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_02, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_02, T_criticalExtensions_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CounterCheck_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CounterCheck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CounterCheck, CounterCheck_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_03_vals[] = {
  {   0, "cdma2000-CSFBParametersResponse" },
  {   1, "dlInformationTransfer" },
  {   2, "handoverFromEUTRAPreparationRequest" },
  {   3, "mobilityFromEUTRACommand" },
  {   4, "rrcConnectionReconfiguration" },
  {   5, "rrcConnectionRelease" },
  {   6, "securityModeCommand" },
  {   7, "ueCapabilityEnquiry" },
  {   8, "counterCheck" },
  {   9, "spare7" },
  {  10, "spare6" },
  {  11, "spare5" },
  {  12, "spare4" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_03_choice[] = {
  {   0, &hf_lte_rrc_cdma2000_CSFBParametersResponse, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_CDMA2000_CSFBParametersResponse },
  {   1, &hf_lte_rrc_dlInformationTransfer, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_DLInformationTransfer },
  {   2, &hf_lte_rrc_handoverFromEUTRAPreparationRequest, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_HandoverFromEUTRAPreparationRequest },
  {   3, &hf_lte_rrc_mobilityFromEUTRACommand, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_MobilityFromEUTRACommand },
  {   4, &hf_lte_rrc_rrcConnectionReconfiguration, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReconfiguration },
  {   5, &hf_lte_rrc_rrcConnectionRelease, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionRelease },
  {   6, &hf_lte_rrc_securityModeCommand, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_SecurityModeCommand },
  {   7, &hf_lte_rrc_ueCapabilityEnquiry, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UECapabilityEnquiry },
  {   8, &hf_lte_rrc_counterCheck, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_CounterCheck },
  {   9, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {  10, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {  11, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {  12, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {  13, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {  14, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {  15, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_03, T_c1_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_messageClassExtension_03_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_messageClassExtension_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_messageClassExtension_03, T_messageClassExtension_03_sequence);

  return offset;
}


static const value_string lte_rrc_DL_DCCH_MessageType_vals[] = {
  {   0, "c1" },
  {   1, "messageClassExtension" },
  { 0, NULL }
};

static const per_choice_t DL_DCCH_MessageType_choice[] = {
  {   0, &hf_lte_rrc_c1_03       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_03 },
  {   1, &hf_lte_rrc_messageClassExtension_03, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_messageClassExtension_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_DL_DCCH_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_DL_DCCH_MessageType, DL_DCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DL_DCCH_Message_sequence[] = {
  { &hf_lte_rrc_message_04  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DL_DCCH_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DL_DCCH_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DL_DCCH_Message, DL_DCCH_Message_sequence);

  return offset;
}



static int
dissect_lte_rrc_ShortMAC_I(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL);

  return offset;
}


static const per_sequence_t ReestabUE_Identity_sequence[] = {
  { &hf_lte_rrc_c_RNTI      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_C_RNTI },
  { &hf_lte_rrc_physCellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentity },
  { &hf_lte_rrc_shortMAC_I  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ShortMAC_I },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ReestabUE_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ReestabUE_Identity, ReestabUE_Identity_sequence);

  return offset;
}


static const value_string lte_rrc_ReestablishmentCause_vals[] = {
  {   0, "reconfigurationFailure" },
  {   1, "handoverFailure" },
  {   2, "otherFailure" },
  {   3, "spare" },
  { 0, NULL }
};


static int
dissect_lte_rrc_ReestablishmentCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t RRCConnectionReestablishmentRequest_r8_IEs_sequence[] = {
  { &hf_lte_rrc_ue_Identity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReestabUE_Identity },
  { &hf_lte_rrc_reestablishmentCause, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReestablishmentCause },
  { &hf_lte_rrc_spare_01    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReestablishmentRequest_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReestablishmentRequest_r8_IEs, RRCConnectionReestablishmentRequest_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_13_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_13, T_criticalExtensionsFuture_13_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_13_vals[] = {
  {   0, "rrcConnectionReestablishmentRequest-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_13_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionReestablishmentRequest_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReestablishmentRequest_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_13, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_13 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_13, T_criticalExtensions_13_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionReestablishmentRequest_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_13, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_13 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReestablishmentRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionReestablishmentRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReestablishmentRequest, RRCConnectionReestablishmentRequest_sequence);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_40(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     40, 40, FALSE, NULL);

  return offset;
}


static const value_string lte_rrc_InitialUE_Identity_vals[] = {
  {   0, "s-TMSI" },
  {   1, "randomValue" },
  { 0, NULL }
};

static const per_choice_t InitialUE_Identity_choice[] = {
  {   0, &hf_lte_rrc_s_TMSI      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_S_TMSI },
  {   1, &hf_lte_rrc_randomValue , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_BIT_STRING_SIZE_40 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_InitialUE_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_InitialUE_Identity, InitialUE_Identity_choice,
                                 NULL);

  return offset;
}


static const value_string lte_rrc_EstablishmentCause_vals[] = {
  {   0, "emergency" },
  {   1, "highPriorityAccess" },
  {   2, "mt-Access" },
  {   3, "mo-Signalling" },
  {   4, "mo-Data" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_EstablishmentCause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t RRCConnectionRequest_r8_IEs_sequence[] = {
  { &hf_lte_rrc_ue_Identity_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_InitialUE_Identity },
  { &hf_lte_rrc_establishmentCause, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_EstablishmentCause },
  { &hf_lte_rrc_spare_02    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionRequest_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionRequest_r8_IEs, RRCConnectionRequest_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_16_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_16, T_criticalExtensionsFuture_16_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_16_vals[] = {
  {   0, "rrcConnectionRequest-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_16_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionRequest_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionRequest_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_16, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_16, T_criticalExtensions_16_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionRequest_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_16, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionRequest, RRCConnectionRequest_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_04_vals[] = {
  {   0, "rrcConnectionReestablishmentRequest" },
  {   1, "rrcConnectionRequest" },
  { 0, NULL }
};

static const per_choice_t T_c1_04_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionReestablishmentRequest, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReestablishmentRequest },
  {   1, &hf_lte_rrc_rrcConnectionRequest, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionRequest },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_04, T_c1_04_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_messageClassExtension_04_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_messageClassExtension_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_messageClassExtension_04, T_messageClassExtension_04_sequence);

  return offset;
}


static const value_string lte_rrc_UL_CCCH_MessageType_vals[] = {
  {   0, "c1" },
  {   1, "messageClassExtension" },
  { 0, NULL }
};

static const per_choice_t UL_CCCH_MessageType_choice[] = {
  {   0, &hf_lte_rrc_c1_04       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_04 },
  {   1, &hf_lte_rrc_messageClassExtension_04, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_messageClassExtension_04 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_UL_CCCH_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_UL_CCCH_MessageType, UL_CCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UL_CCCH_Message_sequence[] = {
  { &hf_lte_rrc_message_05  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UL_CCCH_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UL_CCCH_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UL_CCCH_Message, UL_CCCH_Message_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension, T_nonCriticalExtension_sequence);

  return offset;
}


static const per_sequence_t CDMA2000_CSFBParametersRequest_r8_IEs_sequence[] = {
  { &hf_lte_rrc_nonCriticalExtension, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CDMA2000_CSFBParametersRequest_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CDMA2000_CSFBParametersRequest_r8_IEs, CDMA2000_CSFBParametersRequest_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture, T_criticalExtensionsFuture_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_vals[] = {
  {   0, "cdma2000-CSFBParametersRequest-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_choice[] = {
  {   0, &hf_lte_rrc_cdma2000_CSFBParametersRequest_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_CDMA2000_CSFBParametersRequest_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions, T_criticalExtensions_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CDMA2000_CSFBParametersRequest_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CDMA2000_CSFBParametersRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "CDMA2000-CSFBParametersRequest");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CDMA2000_CSFBParametersRequest, CDMA2000_CSFBParametersRequest_sequence);

  return offset;
}


static const per_sequence_t T_measResultServing_sequence[] = {
  { &hf_lte_rrc_rsrpResult  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RSRP_Range },
  { &hf_lte_rrc_rsrqResult  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RSRQ_Range },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_measResultServing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_measResultServing, T_measResultServing_sequence);

  return offset;
}


static const per_sequence_t GlobalCellId_EUTRA_sequence[] = {
  { &hf_lte_rrc_plmn_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PLMN_Identity },
  { &hf_lte_rrc_cellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_GlobalCellId_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_GlobalCellId_EUTRA, GlobalCellId_EUTRA_sequence);

  return offset;
}


static const per_sequence_t PLMN_IdentityList2_item_sequence[] = {
  { &hf_lte_rrc_plmn_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PLMN_Identity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PLMN_IdentityList2_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PLMN_IdentityList2_item, PLMN_IdentityList2_item_sequence);

  return offset;
}


static const per_sequence_t PLMN_IdentityList2_sequence_of[1] = {
  { &hf_lte_rrc_PLMN_IdentityList2_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PLMN_IdentityList2_item },
};

static int
dissect_lte_rrc_PLMN_IdentityList2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_PLMN_IdentityList2, PLMN_IdentityList2_sequence_of,
                                                  1, 5, FALSE);

  return offset;
}


static const per_sequence_t T_globalCellIdentity_sequence[] = {
  { &hf_lte_rrc_globalCellID_EUTRA, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GlobalCellId_EUTRA },
  { &hf_lte_rrc_tac_ID      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_TrackingAreaCode },
  { &hf_lte_rrc_plmn_IdentityList_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_PLMN_IdentityList2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_globalCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_globalCellIdentity, T_globalCellIdentity_sequence);

  return offset;
}


static const per_sequence_t T_measResult_sequence[] = {
  { &hf_lte_rrc_rsrpResult  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_RSRP_Range },
  { &hf_lte_rrc_rsrqResult  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_RSRQ_Range },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_measResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_measResult, T_measResult_sequence);

  return offset;
}


static const per_sequence_t MeasResultListEUTRA_item_sequence[] = {
  { &hf_lte_rrc_physicalCellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentity },
  { &hf_lte_rrc_globalCellIdentity, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_globalCellIdentity },
  { &hf_lte_rrc_measResult  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_measResult },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasResultListEUTRA_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasResultListEUTRA_item, MeasResultListEUTRA_item_sequence);

  return offset;
}


static const per_sequence_t MeasResultListEUTRA_sequence_of[1] = {
  { &hf_lte_rrc_MeasResultListEUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasResultListEUTRA_item },
};

static int
dissect_lte_rrc_MeasResultListEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MeasResultListEUTRA, MeasResultListEUTRA_sequence_of,
                                                  1, maxCellReport, FALSE);

  return offset;
}


static const value_string lte_rrc_T_physicalCellIdentity_vals[] = {
  {   0, "cellIentityFDD" },
  {   1, "cellIentityTDD" },
  { 0, NULL }
};

static const per_choice_t T_physicalCellIdentity_choice[] = {
  {   0, &hf_lte_rrc_cellIentityFDD, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UTRA_FDD_CellIdentity },
  {   1, &hf_lte_rrc_cellIentityTDD, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UTRA_TDD_CellIdentity },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_physicalCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_physicalCellIdentity, T_physicalCellIdentity_choice,
                                 NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL);

  return offset;
}


static const per_sequence_t GlobalCellId_UTRA_sequence[] = {
  { &hf_lte_rrc_plmn_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PLMN_Identity },
  { &hf_lte_rrc_utra_CellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_28 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_GlobalCellId_UTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_GlobalCellId_UTRA, GlobalCellId_UTRA_sequence);

  return offset;
}


static const per_sequence_t T_globalCellIdentity_01_sequence[] = {
  { &hf_lte_rrc_globalcellID_UTRA, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GlobalCellId_UTRA },
  { &hf_lte_rrc_lac_Id      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { &hf_lte_rrc_rac_Id      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_BIT_STRING_SIZE_8 },
  { &hf_lte_rrc_plmn_IdentityList_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_PLMN_IdentityList2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_globalCellIdentity_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_globalCellIdentity_01, T_globalCellIdentity_01_sequence);

  return offset;
}


static const per_sequence_t T_fdd_sequence[] = {
  { &hf_lte_rrc_cpich_RSCP  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_M5_91 },
  { &hf_lte_rrc_cpich_EcN0  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_49 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_fdd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_fdd, T_fdd_sequence);

  return offset;
}


static const per_sequence_t T_tdd_sequence[] = {
  { &hf_lte_rrc_pccpch_RSCP , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_M5_91 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_tdd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_tdd, T_tdd_sequence);

  return offset;
}


static const value_string lte_rrc_T_mode_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_mode_choice[] = {
  {   0, &hf_lte_rrc_fdd         , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_fdd },
  {   1, &hf_lte_rrc_tdd         , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_tdd },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_mode, T_mode_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_measResult_01_sequence[] = {
  { &hf_lte_rrc_mode        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_mode },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_measResult_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_measResult_01, T_measResult_01_sequence);

  return offset;
}


static const per_sequence_t MeasResultListUTRA_item_sequence[] = {
  { &hf_lte_rrc_physicalCellIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_physicalCellIdentity },
  { &hf_lte_rrc_globalCellIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_globalCellIdentity_01 },
  { &hf_lte_rrc_measResult_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_measResult_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasResultListUTRA_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasResultListUTRA_item, MeasResultListUTRA_item_sequence);

  return offset;
}


static const per_sequence_t MeasResultListUTRA_sequence_of[1] = {
  { &hf_lte_rrc_MeasResultListUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasResultListUTRA_item },
};

static int
dissect_lte_rrc_MeasResultListUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MeasResultListUTRA, MeasResultListUTRA_sequence_of,
                                                  1, maxCellReport, FALSE);

  return offset;
}


static const per_sequence_t T_physicalCellIdentity_01_sequence[] = {
  { &hf_lte_rrc_geran_CarrierFreq, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_CarrierFreq },
  { &hf_lte_rrc_geran_CellIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GERAN_CellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_physicalCellIdentity_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_physicalCellIdentity_01, T_physicalCellIdentity_01_sequence);

  return offset;
}


static const per_sequence_t GlobalCellId_GERAN_sequence[] = {
  { &hf_lte_rrc_plmn_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PLMN_Identity },
  { &hf_lte_rrc_locationAreaCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { &hf_lte_rrc_geran_CellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_GlobalCellId_GERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_GlobalCellId_GERAN, GlobalCellId_GERAN_sequence);

  return offset;
}


static const per_sequence_t T_globalCellIdentity_02_sequence[] = {
  { &hf_lte_rrc_globalcellID_GERAN, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_GlobalCellId_GERAN },
  { &hf_lte_rrc_rac_Id      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_BIT_STRING_SIZE_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_globalCellIdentity_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_globalCellIdentity_02, T_globalCellIdentity_02_sequence);

  return offset;
}


static const per_sequence_t T_measResult_02_sequence[] = {
  { &hf_lte_rrc_rssi        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_6 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_measResult_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_measResult_02, T_measResult_02_sequence);

  return offset;
}


static const per_sequence_t MeasResultListGERAN_item_sequence[] = {
  { &hf_lte_rrc_physicalCellIdentity_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_physicalCellIdentity_01 },
  { &hf_lte_rrc_globalCellIdentity_02, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_globalCellIdentity_02 },
  { &hf_lte_rrc_measResult_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_measResult_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasResultListGERAN_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasResultListGERAN_item, MeasResultListGERAN_item_sequence);

  return offset;
}


static const per_sequence_t MeasResultListGERAN_sequence_of[1] = {
  { &hf_lte_rrc_MeasResultListGERAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasResultListGERAN_item },
};

static int
dissect_lte_rrc_MeasResultListGERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MeasResultListGERAN, MeasResultListGERAN_sequence_of,
                                                  1, maxCellReport, FALSE);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_47(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     47, 47, FALSE, NULL);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL);

  return offset;
}


static const value_string lte_rrc_GlobalCellId_CDMA2000_vals[] = {
  {   0, "globalCellId-oneXRTT" },
  {   1, "globalCellId-HRPD" },
  { 0, NULL }
};

static const per_choice_t GlobalCellId_CDMA2000_choice[] = {
  {   0, &hf_lte_rrc_globalCellId_oneXRTT, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_BIT_STRING_SIZE_47 },
  {   1, &hf_lte_rrc_globalCellId_HRPD, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_BIT_STRING_SIZE_128 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_GlobalCellId_CDMA2000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_GlobalCellId_CDMA2000, GlobalCellId_CDMA2000_choice,
                                 NULL);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_measResult_03_sequence[] = {
  { &hf_lte_rrc_pilotPnPhase, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_INTEGER_0_32767 },
  { &hf_lte_rrc_pilotStrength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_measResult_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_measResult_03, T_measResult_03_sequence);

  return offset;
}


static const per_sequence_t MeasResultListCDMA2000_item_sequence[] = {
  { &hf_lte_rrc_physicalCellIdentity_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_CellIdentity },
  { &hf_lte_rrc_globalCellIdentity_03, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_GlobalCellId_CDMA2000 },
  { &hf_lte_rrc_measResult_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_measResult_03 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasResultListCDMA2000_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasResultListCDMA2000_item, MeasResultListCDMA2000_item_sequence);

  return offset;
}


static const per_sequence_t MeasResultListCDMA2000_sequence_of[1] = {
  { &hf_lte_rrc_MeasResultListCDMA2000_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasResultListCDMA2000_item },
};

static int
dissect_lte_rrc_MeasResultListCDMA2000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_MeasResultListCDMA2000, MeasResultListCDMA2000_sequence_of,
                                                  1, maxCellReport, FALSE);

  return offset;
}


static const per_sequence_t MeasResultsCDMA2000_sequence[] = {
  { &hf_lte_rrc_hrpdPreRegistrationStatus, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_measResultListCDMA2000, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasResultListCDMA2000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasResultsCDMA2000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasResultsCDMA2000, MeasResultsCDMA2000_sequence);

  return offset;
}


static const value_string lte_rrc_T_neighbouringMeasResults_vals[] = {
  {   0, "measResultListEUTRA" },
  {   1, "measResultListUTRA" },
  {   2, "measResultListGERAN" },
  {   3, "measResultsCDMA2000" },
  { 0, NULL }
};

static const per_choice_t T_neighbouringMeasResults_choice[] = {
  {   0, &hf_lte_rrc_measResultListEUTRA, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_MeasResultListEUTRA },
  {   1, &hf_lte_rrc_measResultListUTRA, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_MeasResultListUTRA },
  {   2, &hf_lte_rrc_measResultListGERAN, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_MeasResultListGERAN },
  {   3, &hf_lte_rrc_measResultsCDMA2000, ASN1_EXTENSION_ROOT    , dissect_lte_rrc_MeasResultsCDMA2000 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_neighbouringMeasResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_neighbouringMeasResults, T_neighbouringMeasResults_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasuredResults_sequence[] = {
  { &hf_lte_rrc_measId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasId },
  { &hf_lte_rrc_measResultServing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_measResultServing },
  { &hf_lte_rrc_neighbouringMeasResults, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_neighbouringMeasResults },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasuredResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasuredResults, MeasuredResults_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_06_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_06, T_nonCriticalExtension_06_sequence);

  return offset;
}


static const per_sequence_t MeasurementReport_r8_IEs_sequence[] = {
  { &hf_lte_rrc_measuredResults, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasuredResults },
  { &hf_lte_rrc_nonCriticalExtension_06, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_06 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasurementReport_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasurementReport_r8_IEs, MeasurementReport_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_09_vals[] = {
  {   0, "measurementReport-r8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_09_choice[] = {
  {   0, &hf_lte_rrc_measurementReport_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_MeasurementReport_r8_IEs },
  {   1, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   4, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   5, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   6, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   7, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_09, T_c1_09_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_06_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_06, T_criticalExtensionsFuture_06_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_06_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_06_choice[] = {
  {   0, &hf_lte_rrc_c1_09       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_09 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_06, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_06 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_06, T_criticalExtensions_06_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasurementReport_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_06, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_06 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasurementReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "MeasurementReport");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasurementReport, MeasurementReport_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_10_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_10, T_nonCriticalExtension_10_sequence);

  return offset;
}


static const per_sequence_t RRCConnectionReconfigurationComplete_r8_IEs_sequence[] = {
  { &hf_lte_rrc_nonCriticalExtension_10, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_10 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReconfigurationComplete_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReconfigurationComplete_r8_IEs, RRCConnectionReconfigurationComplete_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_09_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_09, T_criticalExtensionsFuture_09_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_09_vals[] = {
  {   0, "rrcConnectionReconfigurationComplete-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_09_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionReconfigurationComplete_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReconfigurationComplete_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_09, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_09 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_09(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_09, T_criticalExtensions_09_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionReconfigurationComplete_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_09, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_09 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReconfigurationComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionReconfigurationComplete");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReconfigurationComplete, RRCConnectionReconfigurationComplete_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_12_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_12, T_nonCriticalExtension_12_sequence);

  return offset;
}


static const per_sequence_t RRCConnectionReestablishmentComplete_r8_IEs_sequence[] = {
  { &hf_lte_rrc_nonCriticalExtension_12, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_12 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReestablishmentComplete_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReestablishmentComplete_r8_IEs, RRCConnectionReestablishmentComplete_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_11_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_11, T_criticalExtensionsFuture_11_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_11_vals[] = {
  {   0, "rrcConnectionReestablishmentComplete-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_11_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionReestablishmentComplete_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReestablishmentComplete_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_11, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_11 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_11, T_criticalExtensions_11_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionReestablishmentComplete_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_11, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_11 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionReestablishmentComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionReestablishmentComplete");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionReestablishmentComplete, RRCConnectionReestablishmentComplete_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_1_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 6U, NULL, FALSE);

  return offset;
}


static const per_sequence_t RegisteredMME_sequence[] = {
  { &hf_lte_rrc_plmn_Identity, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_PLMN_Identity },
  { &hf_lte_rrc_mmegi       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BIT_STRING_SIZE_16 },
  { &hf_lte_rrc_mmec        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MMEC },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RegisteredMME(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RegisteredMME, RegisteredMME_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_17_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_17(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_17, T_nonCriticalExtension_17_sequence);

  return offset;
}


static const per_sequence_t RRCConnectionSetupComplete_r8_IEs_sequence[] = {
  { &hf_lte_rrc_selectedPLMN_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_6 },
  { &hf_lte_rrc_registeredMME, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_RegisteredMME },
  { &hf_lte_rrc_nas_DedicatedInformation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_NAS_DedicatedInformation },
  { &hf_lte_rrc_nonCriticalExtension_17, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_17 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionSetupComplete_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionSetupComplete_r8_IEs, RRCConnectionSetupComplete_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_16_vals[] = {
  {   0, "rrcConnectionSetupComplete-r8" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_16_choice[] = {
  {   0, &hf_lte_rrc_rrcConnectionSetupComplete_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionSetupComplete_r8_IEs },
  {   1, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_16, T_c1_16_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_18_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_18, T_criticalExtensionsFuture_18_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_18_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_18_choice[] = {
  {   0, &hf_lte_rrc_c1_16       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_16 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_18, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_18 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_18, T_criticalExtensions_18_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t RRCConnectionSetupComplete_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_18, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_18 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRCConnectionSetupComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "RRCConnectionSetupComplete");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRCConnectionSetupComplete, RRCConnectionSetupComplete_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_19_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_19, T_nonCriticalExtension_19_sequence);

  return offset;
}


static const per_sequence_t SecurityModeComplete_r8_IEs_sequence[] = {
  { &hf_lte_rrc_nonCriticalExtension_19, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_19 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SecurityModeComplete_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SecurityModeComplete_r8_IEs, SecurityModeComplete_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_20_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_20, T_criticalExtensionsFuture_20_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_20_vals[] = {
  {   0, "securityModeComplete-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_20_choice[] = {
  {   0, &hf_lte_rrc_securityModeComplete_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_SecurityModeComplete_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_20, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_20 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_20, T_criticalExtensions_20_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SecurityModeComplete_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_20, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_20 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SecurityModeComplete(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "SecurityModeComplete");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SecurityModeComplete, SecurityModeComplete_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_20_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_20, T_nonCriticalExtension_20_sequence);

  return offset;
}


static const per_sequence_t SecurityModeFailure_r8_IEs_sequence[] = {
  { &hf_lte_rrc_nonCriticalExtension_20, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_20 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SecurityModeFailure_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SecurityModeFailure_r8_IEs, SecurityModeFailure_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_21_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_21, T_criticalExtensionsFuture_21_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_21_vals[] = {
  {   0, "securityModeFailure-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_21_choice[] = {
  {   0, &hf_lte_rrc_securityModeFailure_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_SecurityModeFailure_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_21, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_21, T_criticalExtensions_21_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SecurityModeFailure_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_21, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_21 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SecurityModeFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "SecurityModeFailure");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SecurityModeFailure, SecurityModeFailure_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_24_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_24, T_nonCriticalExtension_24_sequence);

  return offset;
}


static const per_sequence_t UECapabilityInformation_r8_IEs_item_sequence[] = {
  { &hf_lte_rrc_rat_Type    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RAT_Type },
  { &hf_lte_rrc_ueCapabilitiesRAT_Container, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OCTET_STRING },
  { &hf_lte_rrc_nonCriticalExtension_24, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_24 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UECapabilityInformation_r8_IEs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UECapabilityInformation_r8_IEs_item, UECapabilityInformation_r8_IEs_item_sequence);

  return offset;
}


static const per_sequence_t UECapabilityInformation_r8_IEs_sequence_of[1] = {
  { &hf_lte_rrc_UECapabilityInformation_r8_IEs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UECapabilityInformation_r8_IEs_item },
};

static int
dissect_lte_rrc_UECapabilityInformation_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_UECapabilityInformation_r8_IEs, UECapabilityInformation_r8_IEs_sequence_of,
                                                  1, maxRAT_Capabilities, FALSE);

  return offset;
}


static const value_string lte_rrc_T_c1_19_vals[] = {
  {   0, "ueCapabilityInformation-r8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_19_choice[] = {
  {   0, &hf_lte_rrc_ueCapabilityInformation_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UECapabilityInformation_r8_IEs },
  {   1, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   4, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   5, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   6, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   7, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_19, T_c1_19_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_24_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_24, T_criticalExtensionsFuture_24_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_24_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_24_choice[] = {
  {   0, &hf_lte_rrc_c1_19       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_19 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_24, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_24 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_24, T_criticalExtensions_24_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UECapabilityInformation_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_24, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_24 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UECapabilityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "UECapabilityInformation");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UECapabilityInformation, UECapabilityInformation_sequence);

  return offset;
}



static int
dissect_lte_rrc_BIT_STRING_SIZE_56(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     56, 56, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_25_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_25(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_25, T_nonCriticalExtension_25_sequence);

  return offset;
}


static const per_sequence_t ULHandoverPreparationTransfer_r8_IEs_sequence[] = {
  { &hf_lte_rrc_cdma2000_Type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Type },
  { &hf_lte_rrc_cdma2000_MEID, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_BIT_STRING_SIZE_56 },
  { &hf_lte_rrc_cdma2000_DedicatedInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_DedicatedInfo },
  { &hf_lte_rrc_nonCriticalExtension_25, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_25 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ULHandoverPreparationTransfer_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ULHandoverPreparationTransfer_r8_IEs, ULHandoverPreparationTransfer_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_20_vals[] = {
  {   0, "ulHandoverPreparationTransfer-r8" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_20_choice[] = {
  {   0, &hf_lte_rrc_ulHandoverPreparationTransfer_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ULHandoverPreparationTransfer_r8_IEs },
  {   1, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_20, T_c1_20_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_25_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_25(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_25, T_criticalExtensionsFuture_25_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_25_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_25_choice[] = {
  {   0, &hf_lte_rrc_c1_20       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_20 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_25, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_25 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_25(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_25, T_criticalExtensions_25_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ULHandoverPreparationTransfer_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_25, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_25 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ULHandoverPreparationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "ULHandoverPreparationTransfer");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ULHandoverPreparationTransfer, ULHandoverPreparationTransfer_sequence);

  return offset;
}


static const per_sequence_t T_cdma2000_01_sequence[] = {
  { &hf_lte_rrc_cdma2000_Type, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Type },
  { &hf_lte_rrc_cdma2000_DedicatedInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_DedicatedInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_cdma2000_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_cdma2000_01, T_cdma2000_01_sequence);

  return offset;
}


static const value_string lte_rrc_T_informationType_01_vals[] = {
  {   0, "nas3GPP" },
  {   1, "cdma2000" },
  { 0, NULL }
};

static const per_choice_t T_informationType_01_choice[] = {
  {   0, &hf_lte_rrc_nas3GPP     , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NAS_DedicatedInformation },
  {   1, &hf_lte_rrc_cdma2000_01 , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_cdma2000_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_informationType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_informationType_01, T_informationType_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_26_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_26(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_26, T_nonCriticalExtension_26_sequence);

  return offset;
}


static const per_sequence_t ULInformationTransfer_r8_IEs_sequence[] = {
  { &hf_lte_rrc_informationType_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_informationType_01 },
  { &hf_lte_rrc_nonCriticalExtension_26, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_26 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ULInformationTransfer_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ULInformationTransfer_r8_IEs, ULInformationTransfer_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_21_vals[] = {
  {   0, "ulInformationTransfer-r8" },
  {   1, "spare3" },
  {   2, "spare2" },
  {   3, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_21_choice[] = {
  {   0, &hf_lte_rrc_ulInformationTransfer_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ULInformationTransfer_r8_IEs },
  {   1, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_21, T_c1_21_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_26_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_26(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_26, T_criticalExtensionsFuture_26_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_26_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_26_choice[] = {
  {   0, &hf_lte_rrc_c1_21       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_21 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_26, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_26 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_26(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_26, T_criticalExtensions_26_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ULInformationTransfer_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_26, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_26 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ULInformationTransfer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

col_append_str(actx->pinfo->cinfo, COL_INFO, "ULInformationTransfer");  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ULInformationTransfer, ULInformationTransfer_sequence);

  return offset;
}



static int
dissect_lte_rrc_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}


static const per_sequence_t DRB_CountInfoList_item_sequence[] = {
  { &hf_lte_rrc_drb_Identity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_32 },
  { &hf_lte_rrc_count_Uplink, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_4294967295 },
  { &hf_lte_rrc_count_Downlink, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_DRB_CountInfoList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_DRB_CountInfoList_item, DRB_CountInfoList_item_sequence);

  return offset;
}


static const per_sequence_t DRB_CountInfoList_sequence_of[1] = {
  { &hf_lte_rrc_DRB_CountInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DRB_CountInfoList_item },
};

static int
dissect_lte_rrc_DRB_CountInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_DRB_CountInfoList, DRB_CountInfoList_sequence_of,
                                                  0, maxDRB, FALSE);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_03_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_03, T_nonCriticalExtension_03_sequence);

  return offset;
}


static const per_sequence_t CounterCheckResponse_r8_IEs_sequence[] = {
  { &hf_lte_rrc_drb_CountInfoList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_DRB_CountInfoList },
  { &hf_lte_rrc_nonCriticalExtension_03, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_03 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CounterCheckResponse_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CounterCheckResponse_r8_IEs, CounterCheckResponse_r8_IEs_sequence);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_03_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_03, T_criticalExtensionsFuture_03_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_03_vals[] = {
  {   0, "counterCheckResponse-r8" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_03_choice[] = {
  {   0, &hf_lte_rrc_counterCheckResponse_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_CounterCheckResponse_r8_IEs },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_03, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_03, T_criticalExtensions_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CounterCheckResponse_sequence[] = {
  { &hf_lte_rrc_rrc_TransactionIdentifier, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RRC_TransactionIdentifier },
  { &hf_lte_rrc_criticalExtensions_03, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_03 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CounterCheckResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CounterCheckResponse, CounterCheckResponse_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_05_vals[] = {
  {   0, "cdma2000-CSFBParametersRequest" },
  {   1, "measurementReport" },
  {   2, "rrcConnectionReconfigurationComplete" },
  {   3, "rrcConnectionReestablishmentComplete" },
  {   4, "rrcConnectionSetupComplete" },
  {   5, "securityModeComplete" },
  {   6, "securityModeFailure" },
  {   7, "ueCapabilityInformation" },
  {   8, "ulHandoverPreparationTransfer" },
  {   9, "ulInformationTransfer" },
  {  10, "counterCheckResponse" },
  {  11, "spare5" },
  {  12, "spare4" },
  {  13, "spare3" },
  {  14, "spare2" },
  {  15, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_05_choice[] = {
  {   0, &hf_lte_rrc_cdma2000_CSFBParametersRequest, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_CDMA2000_CSFBParametersRequest },
  {   1, &hf_lte_rrc_measurementReport, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_MeasurementReport },
  {   2, &hf_lte_rrc_rrcConnectionReconfigurationComplete, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReconfigurationComplete },
  {   3, &hf_lte_rrc_rrcConnectionReestablishmentComplete, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionReestablishmentComplete },
  {   4, &hf_lte_rrc_rrcConnectionSetupComplete, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_RRCConnectionSetupComplete },
  {   5, &hf_lte_rrc_securityModeComplete, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_SecurityModeComplete },
  {   6, &hf_lte_rrc_securityModeFailure, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_SecurityModeFailure },
  {   7, &hf_lte_rrc_ueCapabilityInformation, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UECapabilityInformation },
  {   8, &hf_lte_rrc_ulHandoverPreparationTransfer, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ULHandoverPreparationTransfer },
  {   9, &hf_lte_rrc_ulInformationTransfer, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_ULInformationTransfer },
  {  10, &hf_lte_rrc_counterCheckResponse, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_CounterCheckResponse },
  {  11, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {  12, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {  13, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {  14, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {  15, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_05, T_c1_05_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_messageClassExtension_05_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_messageClassExtension_05(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_messageClassExtension_05, T_messageClassExtension_05_sequence);

  return offset;
}


static const value_string lte_rrc_UL_DCCH_MessageType_vals[] = {
  {   0, "c1" },
  {   1, "messageClassExtension" },
  { 0, NULL }
};

static const per_choice_t UL_DCCH_MessageType_choice[] = {
  {   0, &hf_lte_rrc_c1_05       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_05 },
  {   1, &hf_lte_rrc_messageClassExtension_05, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_messageClassExtension_05 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_UL_DCCH_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_UL_DCCH_MessageType, UL_DCCH_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UL_DCCH_Message_sequence[] = {
  { &hf_lte_rrc_message_06  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_UL_DCCH_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UL_DCCH_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UL_DCCH_Message, UL_DCCH_Message_sequence);

  return offset;
}


static const per_sequence_t CDMA2000_NeighbourCellInformation_sequence[] = {
  { &hf_lte_rrc_cdma2000_CarrierInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_CarrierInfo },
  { &hf_lte_rrc_pnOffset    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_CellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CDMA2000_NeighbourCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CDMA2000_NeighbourCellInformation, CDMA2000_NeighbourCellInformation_sequence);

  return offset;
}


static const value_string lte_rrc_AccessStratumRelease_vals[] = {
  {   0, "rel8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_AccessStratumRelease(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t T_supportedROHCprofiles_sequence[] = {
  { &hf_lte_rrc_profile0x0001, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0002, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0003, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0004, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0006, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0101, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0102, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0103, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_profile0x0104, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_supportedROHCprofiles(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_supportedROHCprofiles, T_supportedROHCprofiles_sequence);

  return offset;
}


static const value_string lte_rrc_T_maxNumberROHC_ContextSessions_vals[] = {
  {   0, "cs2" },
  {   1, "cs4" },
  {   2, "cs8" },
  {   3, "cs12" },
  {   4, "cs16" },
  {   5, "cs24" },
  {   6, "cs32" },
  {   7, "cs48" },
  {   8, "cs64" },
  {   9, "cs128" },
  {  10, "cs256" },
  {  11, "cs512" },
  {  12, "cs1024" },
  {  13, "cs16384" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_maxNumberROHC_ContextSessions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PDCP_Parameters_sequence[] = {
  { &hf_lte_rrc_supportedROHCprofiles, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_supportedROHCprofiles },
  { &hf_lte_rrc_maxNumberROHC_ContextSessions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_maxNumberROHC_ContextSessions },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PDCP_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PDCP_Parameters, PDCP_Parameters_sequence);

  return offset;
}


static const per_sequence_t PhyLayerParameters_sequence[] = {
  { &hf_lte_rrc_ue_TxAntennaSelectionSupported, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { &hf_lte_rrc_ue_SpecificRefSigsSupported, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_PhyLayerParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_PhyLayerParameters, PhyLayerParameters_sequence);

  return offset;
}


static const per_sequence_t SupportedEUTRA_BandList_item_sequence[] = {
  { &hf_lte_rrc_eutra_Band  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_64 },
  { &hf_lte_rrc_halfDuplex  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SupportedEUTRA_BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SupportedEUTRA_BandList_item, SupportedEUTRA_BandList_item_sequence);

  return offset;
}


static const per_sequence_t SupportedEUTRA_BandList_sequence_of[1] = {
  { &hf_lte_rrc_SupportedEUTRA_BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedEUTRA_BandList_item },
};

static int
dissect_lte_rrc_SupportedEUTRA_BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SupportedEUTRA_BandList, SupportedEUTRA_BandList_sequence_of,
                                                  1, maxBands, FALSE);

  return offset;
}


static const per_sequence_t RF_Parameters_sequence[] = {
  { &hf_lte_rrc_supportedEUTRA_BandList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedEUTRA_BandList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RF_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RF_Parameters, RF_Parameters_sequence);

  return offset;
}


static const per_sequence_t InterFreqEUTRA_BandList_item_sequence[] = {
  { &hf_lte_rrc_interFreqNeedForGaps, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_InterFreqEUTRA_BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_InterFreqEUTRA_BandList_item, InterFreqEUTRA_BandList_item_sequence);

  return offset;
}


static const per_sequence_t InterFreqEUTRA_BandList_sequence_of[1] = {
  { &hf_lte_rrc_InterFreqEUTRA_BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_InterFreqEUTRA_BandList_item },
};

static int
dissect_lte_rrc_InterFreqEUTRA_BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_InterFreqEUTRA_BandList, InterFreqEUTRA_BandList_sequence_of,
                                                  1, maxBands, FALSE);

  return offset;
}


static const per_sequence_t InterRAT_BandList_item_sequence[] = {
  { &hf_lte_rrc_interRAT_NeedForGaps, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_InterRAT_BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_InterRAT_BandList_item, InterRAT_BandList_item_sequence);

  return offset;
}


static const per_sequence_t InterRAT_BandList_sequence_of[1] = {
  { &hf_lte_rrc_InterRAT_BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_InterRAT_BandList_item },
};

static int
dissect_lte_rrc_InterRAT_BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_InterRAT_BandList, InterRAT_BandList_sequence_of,
                                                  1, maxBands, FALSE);

  return offset;
}


static const per_sequence_t EUTRA_BandList_item_sequence[] = {
  { &hf_lte_rrc_interFreqEUTRA_BandList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_InterFreqEUTRA_BandList },
  { &hf_lte_rrc_interRAT_BandList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_InterRAT_BandList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_EUTRA_BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_EUTRA_BandList_item, EUTRA_BandList_item_sequence);

  return offset;
}


static const per_sequence_t EUTRA_BandList_sequence_of[1] = {
  { &hf_lte_rrc_EUTRA_BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_EUTRA_BandList_item },
};

static int
dissect_lte_rrc_EUTRA_BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_EUTRA_BandList, EUTRA_BandList_sequence_of,
                                                  1, maxBands, FALSE);

  return offset;
}


static const per_sequence_t MeasurementParameters_sequence[] = {
  { &hf_lte_rrc_eutra_BandList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_EUTRA_BandList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_MeasurementParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_MeasurementParameters, MeasurementParameters_sequence);

  return offset;
}


static const value_string lte_rrc_T_utra_FDD_Band_vals[] = {
  {   0, "bandI" },
  {   1, "bandII" },
  {   2, "bandIII" },
  {   3, "bandIV" },
  {   4, "bandV" },
  {   5, "bandVI" },
  {   6, "bandVII" },
  {   7, "bandVIII" },
  {   8, "bandIX" },
  {   9, "bandX" },
  {  10, "bandXI" },
  {  11, "bandXII" },
  {  12, "bandXIII" },
  {  13, "bandXIV" },
  {  14, "bandXV" },
  {  15, "bandXVI" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_utra_FDD_Band(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SupportedUTRA_FDD_BandList_item_sequence[] = {
  { &hf_lte_rrc_utra_FDD_Band, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_utra_FDD_Band },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SupportedUTRA_FDD_BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SupportedUTRA_FDD_BandList_item, SupportedUTRA_FDD_BandList_item_sequence);

  return offset;
}


static const per_sequence_t SupportedUTRA_FDD_BandList_sequence_of[1] = {
  { &hf_lte_rrc_SupportedUTRA_FDD_BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedUTRA_FDD_BandList_item },
};

static int
dissect_lte_rrc_SupportedUTRA_FDD_BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SupportedUTRA_FDD_BandList, SupportedUTRA_FDD_BandList_sequence_of,
                                                  1, maxBands, FALSE);

  return offset;
}


static const per_sequence_t IRAT_UTRA_FDD_Parameters_sequence[] = {
  { &hf_lte_rrc_supportedUTRA_FDD_BandList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedUTRA_FDD_BandList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_IRAT_UTRA_FDD_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_IRAT_UTRA_FDD_Parameters, IRAT_UTRA_FDD_Parameters_sequence);

  return offset;
}


static const value_string lte_rrc_T_utra_TDD128Band_vals[] = {
  {   0, "a" },
  {   1, "b" },
  {   2, "c" },
  {   3, "d" },
  {   4, "e" },
  {   5, "f" },
  {   6, "g" },
  {   7, "h" },
  {   8, "i" },
  {   9, "j" },
  {  10, "k" },
  {  11, "l" },
  {  12, "m" },
  {  13, "n" },
  {  14, "o" },
  {  15, "p" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_utra_TDD128Band(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SupportedUTRA_TDD128BandList_item_sequence[] = {
  { &hf_lte_rrc_utra_TDD128Band, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_utra_TDD128Band },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SupportedUTRA_TDD128BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SupportedUTRA_TDD128BandList_item, SupportedUTRA_TDD128BandList_item_sequence);

  return offset;
}


static const per_sequence_t SupportedUTRA_TDD128BandList_sequence_of[1] = {
  { &hf_lte_rrc_SupportedUTRA_TDD128BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedUTRA_TDD128BandList_item },
};

static int
dissect_lte_rrc_SupportedUTRA_TDD128BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SupportedUTRA_TDD128BandList, SupportedUTRA_TDD128BandList_sequence_of,
                                                  1, maxBands, FALSE);

  return offset;
}


static const per_sequence_t IRAT_UTRA_TDD128_Parameters_sequence[] = {
  { &hf_lte_rrc_supportedUTRA_TDD128BandList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedUTRA_TDD128BandList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_IRAT_UTRA_TDD128_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_IRAT_UTRA_TDD128_Parameters, IRAT_UTRA_TDD128_Parameters_sequence);

  return offset;
}


static const value_string lte_rrc_T_utra_TDD384Band_vals[] = {
  {   0, "a" },
  {   1, "b" },
  {   2, "c" },
  {   3, "d" },
  {   4, "e" },
  {   5, "f" },
  {   6, "g" },
  {   7, "h" },
  {   8, "i" },
  {   9, "j" },
  {  10, "k" },
  {  11, "l" },
  {  12, "m" },
  {  13, "n" },
  {  14, "o" },
  {  15, "p" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_utra_TDD384Band(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SupportedUTRA_TDD384BandList_item_sequence[] = {
  { &hf_lte_rrc_utra_TDD384Band, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_utra_TDD384Band },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SupportedUTRA_TDD384BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SupportedUTRA_TDD384BandList_item, SupportedUTRA_TDD384BandList_item_sequence);

  return offset;
}


static const per_sequence_t SupportedUTRA_TDD384BandList_sequence_of[1] = {
  { &hf_lte_rrc_SupportedUTRA_TDD384BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedUTRA_TDD384BandList_item },
};

static int
dissect_lte_rrc_SupportedUTRA_TDD384BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SupportedUTRA_TDD384BandList, SupportedUTRA_TDD384BandList_sequence_of,
                                                  1, maxBands, FALSE);

  return offset;
}


static const per_sequence_t IRAT_UTRA_TDD384_Parameters_sequence[] = {
  { &hf_lte_rrc_supportedUTRA_TDD384BandList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedUTRA_TDD384BandList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_IRAT_UTRA_TDD384_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_IRAT_UTRA_TDD384_Parameters, IRAT_UTRA_TDD384_Parameters_sequence);

  return offset;
}


static const value_string lte_rrc_T_utra_TDD768Band_vals[] = {
  {   0, "a" },
  {   1, "b" },
  {   2, "c" },
  {   3, "d" },
  {   4, "e" },
  {   5, "f" },
  {   6, "g" },
  {   7, "h" },
  {   8, "i" },
  {   9, "j" },
  {  10, "k" },
  {  11, "l" },
  {  12, "m" },
  {  13, "n" },
  {  14, "o" },
  {  15, "p" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_utra_TDD768Band(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SupportedUTRA_TDD768BandList_item_sequence[] = {
  { &hf_lte_rrc_utra_TDD768Band, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_utra_TDD768Band },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SupportedUTRA_TDD768BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SupportedUTRA_TDD768BandList_item, SupportedUTRA_TDD768BandList_item_sequence);

  return offset;
}


static const per_sequence_t SupportedUTRA_TDD768BandList_sequence_of[1] = {
  { &hf_lte_rrc_SupportedUTRA_TDD768BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedUTRA_TDD768BandList_item },
};

static int
dissect_lte_rrc_SupportedUTRA_TDD768BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SupportedUTRA_TDD768BandList, SupportedUTRA_TDD768BandList_sequence_of,
                                                  1, maxBands, FALSE);

  return offset;
}


static const per_sequence_t IRAT_UTRA_TDD768_Parameters_sequence[] = {
  { &hf_lte_rrc_supportedUTRA_TDD768BandList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedUTRA_TDD768BandList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_IRAT_UTRA_TDD768_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_IRAT_UTRA_TDD768_Parameters, IRAT_UTRA_TDD768_Parameters_sequence);

  return offset;
}


static const value_string lte_rrc_T_geran_Band_vals[] = {
  {   0, "gsm450" },
  {   1, "gsm480" },
  {   2, "gsm850" },
  {   3, "gsm900P" },
  {   4, "gsm900E" },
  {   5, "gsm1800" },
  {   6, "gsm1900" },
  {   7, "spare1" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_geran_Band(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SupportedGERAN_BandList_item_sequence[] = {
  { &hf_lte_rrc_geran_Band  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_geran_Band },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SupportedGERAN_BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SupportedGERAN_BandList_item, SupportedGERAN_BandList_item_sequence);

  return offset;
}


static const per_sequence_t SupportedGERAN_BandList_sequence_of[1] = {
  { &hf_lte_rrc_SupportedGERAN_BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedGERAN_BandList_item },
};

static int
dissect_lte_rrc_SupportedGERAN_BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SupportedGERAN_BandList, SupportedGERAN_BandList_sequence_of,
                                                  1, maxBands, FALSE);

  return offset;
}


static const per_sequence_t IRAT_GERAN_Parameters_sequence[] = {
  { &hf_lte_rrc_supportedGERAN_BandList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedGERAN_BandList },
  { &hf_lte_rrc_interRAT_PS_HO_ToGERAN, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_IRAT_GERAN_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_IRAT_GERAN_Parameters, IRAT_GERAN_Parameters_sequence);

  return offset;
}


static const per_sequence_t SupportedHRPD_BandList_item_sequence[] = {
  { &hf_lte_rrc_cdma2000_HRPD_Band, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Bandclass },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_SupportedHRPD_BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_SupportedHRPD_BandList_item, SupportedHRPD_BandList_item_sequence);

  return offset;
}


static const per_sequence_t SupportedHRPD_BandList_sequence_of[1] = {
  { &hf_lte_rrc_SupportedHRPD_BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedHRPD_BandList_item },
};

static int
dissect_lte_rrc_SupportedHRPD_BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_SupportedHRPD_BandList, SupportedHRPD_BandList_sequence_of,
                                                  0, maxCDMA_BandClass, FALSE);

  return offset;
}


static const value_string lte_rrc_T_cdma2000_HRPD_TxConfig_vals[] = {
  {   0, "single" },
  {   1, "dual" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_cdma2000_HRPD_TxConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_cdma2000_HRPD_RxConfig_vals[] = {
  {   0, "single" },
  {   1, "dual" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_cdma2000_HRPD_RxConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t IRAT_CDMA2000_HRPD_Parameters_sequence[] = {
  { &hf_lte_rrc_supportedHRPD_BandList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SupportedHRPD_BandList },
  { &hf_lte_rrc_cdma2000_HRPD_TxConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cdma2000_HRPD_TxConfig },
  { &hf_lte_rrc_cdma2000_HRPD_RxConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cdma2000_HRPD_RxConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_IRAT_CDMA2000_HRPD_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_IRAT_CDMA2000_HRPD_Parameters, IRAT_CDMA2000_HRPD_Parameters_sequence);

  return offset;
}


static const per_sequence_t Supported1xRTT_BandList_item_sequence[] = {
  { &hf_lte_rrc_cdma2000_1xRTT_Band, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CDMA2000_Bandclass },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_Supported1xRTT_BandList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_Supported1xRTT_BandList_item, Supported1xRTT_BandList_item_sequence);

  return offset;
}


static const per_sequence_t Supported1xRTT_BandList_sequence_of[1] = {
  { &hf_lte_rrc_Supported1xRTT_BandList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_Supported1xRTT_BandList_item },
};

static int
dissect_lte_rrc_Supported1xRTT_BandList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_Supported1xRTT_BandList, Supported1xRTT_BandList_sequence_of,
                                                  0, maxCDMA_BandClass, FALSE);

  return offset;
}


static const value_string lte_rrc_T_cdma2000_1xRTT_TxConfig_vals[] = {
  {   0, "single" },
  {   1, "dual" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_cdma2000_1xRTT_TxConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lte_rrc_T_cdma2000_1xRTT_RxConfig_vals[] = {
  {   0, "single" },
  {   1, "dual" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_cdma2000_1xRTT_RxConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t IRAT_CDMA2000_1xRTT_Parameters_sequence[] = {
  { &hf_lte_rrc_supported1xRTT_BandList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_Supported1xRTT_BandList },
  { &hf_lte_rrc_cdma2000_1xRTT_TxConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cdma2000_1xRTT_TxConfig },
  { &hf_lte_rrc_cdma2000_1xRTT_RxConfig, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_cdma2000_1xRTT_RxConfig },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_IRAT_CDMA2000_1xRTT_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_IRAT_CDMA2000_1xRTT_Parameters, IRAT_CDMA2000_1xRTT_Parameters_sequence);

  return offset;
}


static const per_sequence_t T_interRAT_Parameters_sequence[] = {
  { &hf_lte_rrc_utraFDD     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_IRAT_UTRA_FDD_Parameters },
  { &hf_lte_rrc_utraTDD128  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_IRAT_UTRA_TDD128_Parameters },
  { &hf_lte_rrc_utraTDD384  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_IRAT_UTRA_TDD384_Parameters },
  { &hf_lte_rrc_utraTDD768  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_IRAT_UTRA_TDD768_Parameters },
  { &hf_lte_rrc_geran_02    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_IRAT_GERAN_Parameters },
  { &hf_lte_rrc_cdma2000_HRPD_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_IRAT_CDMA2000_HRPD_Parameters },
  { &hf_lte_rrc_cdma2000_1xRTT_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_IRAT_CDMA2000_1xRTT_Parameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_interRAT_Parameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_interRAT_Parameters, T_interRAT_Parameters_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_27_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_27(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_27, T_nonCriticalExtension_27_sequence);

  return offset;
}


static const per_sequence_t UE_EUTRA_Capability_sequence[] = {
  { &hf_lte_rrc_accessStratumRelease, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_AccessStratumRelease },
  { &hf_lte_rrc_ue_Category , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER_1_16 },
  { &hf_lte_rrc_pdcp_Parameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PDCP_Parameters },
  { &hf_lte_rrc_phyLayerParameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhyLayerParameters },
  { &hf_lte_rrc_rf_Parameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RF_Parameters },
  { &hf_lte_rrc_measurementParameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasurementParameters },
  { &hf_lte_rrc_interRAT_Parameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_interRAT_Parameters },
  { &hf_lte_rrc_nonCriticalExtension_27, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_27 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UE_EUTRA_Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UE_EUTRA_Capability, UE_EUTRA_Capability_sequence);

  return offset;
}


static const per_sequence_t T_speedDependentParameters_01_sequence[] = {
  { &hf_lte_rrc_mobilityStateParameters, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MobilityStateParameters },
  { &hf_lte_rrc_speedDependentScalingParameters_06, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ConnectedModeSpeedDependentScalingParameters },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_speedDependentParameters_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_speedDependentParameters_01, T_speedDependentParameters_01_sequence);

  return offset;
}


static const per_sequence_t VarMeasurementConfiguration_sequence[] = {
  { &hf_lte_rrc_measIdList  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_MeasIdToAddModifyList },
  { &hf_lte_rrc_measObjectList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_MeasObjectToAddModifyList },
  { &hf_lte_rrc_reportConfigList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_ReportConfigToAddModifyList },
  { &hf_lte_rrc_quantityConfig, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_QuantityConfig },
  { &hf_lte_rrc_s_Measure   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_RSRP_Range },
  { &hf_lte_rrc_cdma2000_SystemTimeInfo, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_CDMA2000_SystemTimeInfo },
  { &hf_lte_rrc_neighbourCellConfiguration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_NeighbourCellConfiguration },
  { &hf_lte_rrc_speedDependentParameters_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_speedDependentParameters_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_VarMeasurementConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_VarMeasurementConfiguration, VarMeasurementConfiguration_sequence);

  return offset;
}


static const per_sequence_t CellsTriggeredList_item_sequence[] = {
  { &hf_lte_rrc_cellIdentity_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_CellsTriggeredList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_CellsTriggeredList_item, CellsTriggeredList_item_sequence);

  return offset;
}


static const per_sequence_t CellsTriggeredList_sequence_of[1] = {
  { &hf_lte_rrc_CellsTriggeredList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CellsTriggeredList_item },
};

static int
dissect_lte_rrc_CellsTriggeredList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_CellsTriggeredList, CellsTriggeredList_sequence_of,
                                                  1, maxCellMeas, FALSE);

  return offset;
}



static int
dissect_lte_rrc_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t VarMeasurementReports_item_sequence[] = {
  { &hf_lte_rrc_measId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasId },
  { &hf_lte_rrc_cellsTriggeredList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_CellsTriggeredList },
  { &hf_lte_rrc_numberOfReportsSent, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_VarMeasurementReports_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_VarMeasurementReports_item, VarMeasurementReports_item_sequence);

  return offset;
}


static const per_sequence_t VarMeasurementReports_sequence_of[1] = {
  { &hf_lte_rrc_VarMeasurementReports_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_VarMeasurementReports_item },
};

static int
dissect_lte_rrc_VarMeasurementReports(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_VarMeasurementReports, VarMeasurementReports_sequence_of,
                                                  1, maxMeasId, FALSE);

  return offset;
}


static const per_sequence_t VarShortMAC_Input_sequence[] = {
  { &hf_lte_rrc_cellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CellIdentity },
  { &hf_lte_rrc_physicalCellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentity },
  { &hf_lte_rrc_c_RNTI      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_C_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_VarShortMAC_Input(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_VarShortMAC_Input, VarShortMAC_Input_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_28_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_28, T_nonCriticalExtension_28_sequence);

  return offset;
}


static const per_sequence_t InterRAT_Message_r8_IEs_sequence[] = {
  { &hf_lte_rrc_interRAT_Message_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OCTET_STRING },
  { &hf_lte_rrc_nonCriticalExtension_28, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_28 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_InterRAT_Message_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_InterRAT_Message_r8_IEs, InterRAT_Message_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_23_vals[] = {
  {   0, "interRAT-Message-r8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_23_choice[] = {
  {   0, &hf_lte_rrc_interRAT_Message_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_InterRAT_Message_r8_IEs },
  {   1, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   4, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   5, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   6, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   7, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_23, T_c1_23_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_27_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_27(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_27, T_criticalExtensionsFuture_27_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_27_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_27_choice[] = {
  {   0, &hf_lte_rrc_c1_23       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_23 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_27, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_27 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_27(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_27, T_criticalExtensions_27_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InterRAT_Message_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_27, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_27 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_InterRAT_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_InterRAT_Message, InterRAT_Message_sequence);

  return offset;
}



static int
dissect_lte_rrc_T_handoverCommandMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_DL_DCCH_Message_PDU);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_29_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_29(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_29, T_nonCriticalExtension_29_sequence);

  return offset;
}


static const per_sequence_t HandoverCommand_r8_IEs_sequence[] = {
  { &hf_lte_rrc_handoverCommandMessage, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_handoverCommandMessage },
  { &hf_lte_rrc_nonCriticalExtension_29, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_29 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_HandoverCommand_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_HandoverCommand_r8_IEs, HandoverCommand_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_24_vals[] = {
  {   0, "handoverCommand-r8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_24_choice[] = {
  {   0, &hf_lte_rrc_handoverCommand_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_HandoverCommand_r8_IEs },
  {   1, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   4, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   5, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   6, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   7, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_24, T_c1_24_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_28_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_28, T_criticalExtensionsFuture_28_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_28_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_28_choice[] = {
  {   0, &hf_lte_rrc_c1_24       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_24 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_28, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_28 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_28, T_criticalExtensions_28_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t HandoverCommand_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_28, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_28 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_HandoverCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_HandoverCommand, HandoverCommand_sequence);

  return offset;
}


static const per_sequence_t AS_Configuration_sequence[] = {
  { &hf_lte_rrc_sourceMeasurementConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MeasurementConfiguration },
  { &hf_lte_rrc_sourceRadioResourceConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_RadioResourceConfigDedicated },
  { &hf_lte_rrc_sourceSecurityConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SecurityConfiguration },
  { &hf_lte_rrc_sourceUE_Identity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_C_RNTI },
  { &hf_lte_rrc_sourceMasterInformationBlock, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_MasterInformationBlock },
  { &hf_lte_rrc_sourceSystemInformationBlockType1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SystemInformationBlockType1 },
  { &hf_lte_rrc_sourceSystemInformationBlockType2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_SystemInformationBlockType2 },
  { &hf_lte_rrc_antennaInformationCommon, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_AntennaInformationCommon },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_AS_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_AS_Configuration, AS_Configuration_sequence);

  return offset;
}


static const value_string lte_rrc_T_ue_InactiveTime_vals[] = {
  {   0, "v1sec" },
  {   1, "v2sec" },
  {   2, "v3sec" },
  {   3, "v5sec" },
  {   4, "v7sec" },
  {   5, "v10sec" },
  {   6, "v15sec" },
  {   7, "v20sec" },
  {   8, "v25sec" },
  {   9, "v30sec" },
  {  10, "v40sec" },
  {  11, "v50sec" },
  {  12, "v1min" },
  {  13, "v1min20sec" },
  {  14, "v1min40sec" },
  {  15, "v2min" },
  {  16, "v2min30sec" },
  {  17, "v3min" },
  {  18, "v3min30sec" },
  {  19, "v4min" },
  {  20, "v5min" },
  {  21, "v6min" },
  {  22, "v7min" },
  {  23, "v8min" },
  {  24, "v9min" },
  {  25, "v10min" },
  {  26, "v12min" },
  {  27, "v14min" },
  {  28, "v17min" },
  {  29, "v20min" },
  {  30, "v24min" },
  {  31, "v28min" },
  {  32, "v33min" },
  {  33, "v38min" },
  {  34, "v44min" },
  {  35, "v50min" },
  {  36, "v1hr" },
  {  37, "v1hr30min" },
  {  38, "v2hr" },
  {  39, "v2hr30min" },
  {  40, "v3hr" },
  {  41, "v3hr30min" },
  {  42, "v4hr" },
  {  43, "v5hr" },
  {  44, "v6hr" },
  {  45, "v8hr" },
  {  46, "v10hr" },
  {  47, "v13hr" },
  {  48, "v16hr" },
  {  49, "v20hr" },
  {  50, "v1day" },
  {  51, "v1day12hr" },
  {  52, "v2day" },
  {  53, "v2day12hr" },
  {  54, "v3day" },
  {  55, "v4day" },
  {  56, "v5day" },
  {  57, "v7day" },
  {  58, "v10day" },
  {  59, "v14day" },
  {  60, "v19day" },
  {  61, "v24day" },
  {  62, "v30day" },
  {  63, "morethan30day" },
  { 0, NULL }
};


static int
dissect_lte_rrc_T_ue_InactiveTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     64, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t RRM_Configuration_sequence[] = {
  { &hf_lte_rrc_ue_InactiveTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_T_ue_InactiveTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_RRM_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_RRM_Configuration, RRM_Configuration_sequence);

  return offset;
}



static int
dissect_lte_rrc_T_ue_RadioAccessCapabilityInfo_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_UECapabilityInformation_PDU);

  return offset;
}



static int
dissect_lte_rrc_Key_eNodeB_Star(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL);

  return offset;
}


static const per_sequence_t AdditionalReestabInfoList_item_sequence[] = {
  { &hf_lte_rrc_cellIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_CellIdentity },
  { &hf_lte_rrc_key_eNodeB_Star, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_Key_eNodeB_Star },
  { &hf_lte_rrc_shortMAC_I  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ShortMAC_I },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_AdditionalReestabInfoList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_AdditionalReestabInfoList_item, AdditionalReestabInfoList_item_sequence);

  return offset;
}


static const per_sequence_t AdditionalReestabInfoList_sequence_of[1] = {
  { &hf_lte_rrc_AdditionalReestabInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_AdditionalReestabInfoList_item },
};

static int
dissect_lte_rrc_AdditionalReestabInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lte_rrc_AdditionalReestabInfoList, AdditionalReestabInfoList_sequence_of,
                                                  1, maxReestabInfo, FALSE);

  return offset;
}


static const per_sequence_t ReestablishmentInfo_sequence[] = {
  { &hf_lte_rrc_sourcePhysicalCellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_PhysicalCellIdentity },
  { &hf_lte_rrc_targetCellShortMAC_I, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ShortMAC_I },
  { &hf_lte_rrc_additionalReestabInfoList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lte_rrc_AdditionalReestabInfoList },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_ReestablishmentInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_ReestablishmentInfo, ReestablishmentInfo_sequence);

  return offset;
}


static const per_sequence_t AS_Context_sequence[] = {
  { &hf_lte_rrc_ue_RadioAccessCapabilityInfo_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_ue_RadioAccessCapabilityInfo_01 },
  { &hf_lte_rrc_ue_SecurityCapabilityInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_OCTET_STRING },
  { &hf_lte_rrc_reestablishmentInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_ReestablishmentInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_AS_Context(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_AS_Context, AS_Context_sequence);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_30_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_30, T_nonCriticalExtension_30_sequence);

  return offset;
}


static const per_sequence_t HandoverPreparationInformation_r8_IEs_sequence[] = {
  { &hf_lte_rrc_as_Configuration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_AS_Configuration },
  { &hf_lte_rrc_rrm_Configuration, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_RRM_Configuration },
  { &hf_lte_rrc_as_Context  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_AS_Context },
  { &hf_lte_rrc_nonCriticalExtension_30, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_30 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_HandoverPreparationInformation_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_HandoverPreparationInformation_r8_IEs, HandoverPreparationInformation_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_25_vals[] = {
  {   0, "handoverPreparationInformation-r8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_25_choice[] = {
  {   0, &hf_lte_rrc_handoverPreparationInformation_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_HandoverPreparationInformation_r8_IEs },
  {   1, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   4, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   5, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   6, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   7, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_25(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_25, T_c1_25_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_29_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_29(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_29, T_criticalExtensionsFuture_29_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_29_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_29_choice[] = {
  {   0, &hf_lte_rrc_c1_25       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_25 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_29, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_29 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_29(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_29, T_criticalExtensions_29_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t HandoverPreparationInformation_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_29, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_29 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_HandoverPreparationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_HandoverPreparationInformation, HandoverPreparationInformation_sequence);

  return offset;
}



static int
dissect_lte_rrc_T_ue_RadioAccessCapabilityInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string_containing_pdu_new(tvb, offset, actx, tree, hf_index,
                                                                NO_BOUND, NO_BOUND, FALSE, dissect_UECapabilityInformation_PDU);

  return offset;
}


static const per_sequence_t T_nonCriticalExtension_31_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_nonCriticalExtension_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_nonCriticalExtension_31, T_nonCriticalExtension_31_sequence);

  return offset;
}


static const per_sequence_t UERadioAccessCapabilityInformation_r8_IEs_sequence[] = {
  { &hf_lte_rrc_ue_RadioAccessCapabilityInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_ue_RadioAccessCapabilityInfo },
  { &hf_lte_rrc_nonCriticalExtension_31, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_lte_rrc_T_nonCriticalExtension_31 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UERadioAccessCapabilityInformation_r8_IEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UERadioAccessCapabilityInformation_r8_IEs, UERadioAccessCapabilityInformation_r8_IEs_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_26_vals[] = {
  {   0, "ueRadioAccessCapabilityInformation-r8" },
  {   1, "spare7" },
  {   2, "spare6" },
  {   3, "spare5" },
  {   4, "spare4" },
  {   5, "spare3" },
  {   6, "spare2" },
  {   7, "spare1" },
  { 0, NULL }
};

static const per_choice_t T_c1_26_choice[] = {
  {   0, &hf_lte_rrc_ueRadioAccessCapabilityInformation_r8, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UERadioAccessCapabilityInformation_r8_IEs },
  {   1, &hf_lte_rrc_spare7      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   2, &hf_lte_rrc_spare6      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   3, &hf_lte_rrc_spare5      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   4, &hf_lte_rrc_spare4      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   5, &hf_lte_rrc_spare3      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   6, &hf_lte_rrc_spare2      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  {   7, &hf_lte_rrc_spare1      , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_26(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_26, T_c1_26_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_criticalExtensionsFuture_30_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensionsFuture_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_criticalExtensionsFuture_30, T_criticalExtensionsFuture_30_sequence);

  return offset;
}


static const value_string lte_rrc_T_criticalExtensions_30_vals[] = {
  {   0, "c1" },
  {   1, "criticalExtensionsFuture" },
  { 0, NULL }
};

static const per_choice_t T_criticalExtensions_30_choice[] = {
  {   0, &hf_lte_rrc_c1_26       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_26 },
  {   1, &hf_lte_rrc_criticalExtensionsFuture_30, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_criticalExtensionsFuture_30 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_criticalExtensions_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_criticalExtensions_30, T_criticalExtensions_30_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UERadioAccessCapabilityInformation_sequence[] = {
  { &hf_lte_rrc_criticalExtensions_30, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_T_criticalExtensions_30 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_UERadioAccessCapabilityInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_UERadioAccessCapabilityInformation, UERadioAccessCapabilityInformation_sequence);

  return offset;
}


static const value_string lte_rrc_T_c1_22_vals[] = {
  {   0, "interRAT-Message" },
  {   1, "handoverCommand" },
  {   2, "handoverPreparationInformation" },
  {   3, "ueRadioAccessCapabilityInformation" },
  { 0, NULL }
};

static const per_choice_t T_c1_22_choice[] = {
  {   0, &hf_lte_rrc_interRAT_Message, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_InterRAT_Message },
  {   1, &hf_lte_rrc_handoverCommand, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_HandoverCommand },
  {   2, &hf_lte_rrc_handoverPreparationInformation, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_HandoverPreparationInformation },
  {   3, &hf_lte_rrc_ueRadioAccessCapabilityInformation, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_UERadioAccessCapabilityInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_T_c1_22(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_T_c1_22, T_c1_22_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_messageClassExtension_06_sequence[] = {
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_T_messageClassExtension_06(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_T_messageClassExtension_06, T_messageClassExtension_06_sequence);

  return offset;
}


static const value_string lte_rrc_InterNode_MessageType_vals[] = {
  {   0, "c1" },
  {   1, "messageClassExtension" },
  { 0, NULL }
};

static const per_choice_t InterNode_MessageType_choice[] = {
  {   0, &hf_lte_rrc_c1_22       , ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_c1_22 },
  {   1, &hf_lte_rrc_messageClassExtension_06, ASN1_NO_EXTENSIONS     , dissect_lte_rrc_T_messageClassExtension_06 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lte_rrc_InterNode_MessageType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lte_rrc_InterNode_MessageType, InterNode_MessageType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InterNode_Message_sequence[] = {
  { &hf_lte_rrc_message_07  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lte_rrc_InterNode_MessageType },
  { NULL, 0, 0, NULL }
};

static int
dissect_lte_rrc_InterNode_Message(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lte_rrc_InterNode_Message, InterNode_Message_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_BCCH_BCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_lte_rrc_BCCH_BCH_Message(tvb, offset, &asn1_ctx, tree, hf_lte_rrc_BCCH_BCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_BCCH_DL_SCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_lte_rrc_BCCH_DL_SCH_Message(tvb, offset, &asn1_ctx, tree, hf_lte_rrc_BCCH_DL_SCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_lte_rrc_PCCH_Message(tvb, offset, &asn1_ctx, tree, hf_lte_rrc_PCCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DL_CCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_lte_rrc_DL_CCCH_Message(tvb, offset, &asn1_ctx, tree, hf_lte_rrc_DL_CCCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_DL_DCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_lte_rrc_DL_DCCH_Message(tvb, offset, &asn1_ctx, tree, hf_lte_rrc_DL_DCCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UL_CCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_lte_rrc_UL_CCCH_Message(tvb, offset, &asn1_ctx, tree, hf_lte_rrc_UL_CCCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UL_DCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_lte_rrc_UL_DCCH_Message(tvb, offset, &asn1_ctx, tree, hf_lte_rrc_UL_DCCH_Message_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UECapabilityInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_lte_rrc_UECapabilityInformation(tvb, offset, &asn1_ctx, tree, hf_lte_rrc_UECapabilityInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-lte-rrc-fn.c ---*/
#line 66 "packet-lte-rrc-template.c"

/*--- proto_register_rrc -------------------------------------------*/
void proto_register_lte_rrc(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-lte-rrc-hfarr.c ---*/
#line 1 "packet-lte-rrc-hfarr.c"
    { &hf_lte_rrc_BCCH_BCH_Message_PDU,
      { "BCCH-BCH-Message", "lte-rrc.BCCH_BCH_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.BCCH_BCH_Message", HFILL }},
    { &hf_lte_rrc_BCCH_DL_SCH_Message_PDU,
      { "BCCH-DL-SCH-Message", "lte-rrc.BCCH_DL_SCH_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.BCCH_DL_SCH_Message", HFILL }},
    { &hf_lte_rrc_PCCH_Message_PDU,
      { "PCCH-Message", "lte-rrc.PCCH_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PCCH_Message", HFILL }},
    { &hf_lte_rrc_DL_CCCH_Message_PDU,
      { "DL-CCCH-Message", "lte-rrc.DL_CCCH_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DL_CCCH_Message", HFILL }},
    { &hf_lte_rrc_DL_DCCH_Message_PDU,
      { "DL-DCCH-Message", "lte-rrc.DL_DCCH_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DL_DCCH_Message", HFILL }},
    { &hf_lte_rrc_UL_CCCH_Message_PDU,
      { "UL-CCCH-Message", "lte-rrc.UL_CCCH_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UL_CCCH_Message", HFILL }},
    { &hf_lte_rrc_UL_DCCH_Message_PDU,
      { "UL-DCCH-Message", "lte-rrc.UL_DCCH_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UL_DCCH_Message", HFILL }},
    { &hf_lte_rrc_UECapabilityInformation_PDU,
      { "UECapabilityInformation", "lte-rrc.UECapabilityInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UECapabilityInformation", HFILL }},
    { &hf_lte_rrc_message,
      { "message", "lte-rrc.message",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.BCCH_BCH_MessageType", HFILL }},
    { &hf_lte_rrc_message_01,
      { "message", "lte-rrc.message",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_BCCH_DL_SCH_MessageType_vals), 0,
        "lte_rrc.BCCH_DL_SCH_MessageType", HFILL }},
    { &hf_lte_rrc_c1,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_vals), 0,
        "lte_rrc.T_c1", HFILL }},
    { &hf_lte_rrc_systemInformation,
      { "systemInformation", "lte-rrc.systemInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformation", HFILL }},
    { &hf_lte_rrc_systemInformationBlockType1,
      { "systemInformationBlockType1", "lte-rrc.systemInformationBlockType1",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType1", HFILL }},
    { &hf_lte_rrc_messageClassExtension,
      { "messageClassExtension", "lte-rrc.messageClassExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_messageClassExtension", HFILL }},
    { &hf_lte_rrc_message_02,
      { "message", "lte-rrc.message",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_PCCH_MessageType_vals), 0,
        "lte_rrc.PCCH_MessageType", HFILL }},
    { &hf_lte_rrc_c1_01,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_01_vals), 0,
        "lte_rrc.T_c1_01", HFILL }},
    { &hf_lte_rrc_paging,
      { "paging", "lte-rrc.paging",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.Paging", HFILL }},
    { &hf_lte_rrc_messageClassExtension_01,
      { "messageClassExtension", "lte-rrc.messageClassExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_messageClassExtension_01", HFILL }},
    { &hf_lte_rrc_message_03,
      { "message", "lte-rrc.message",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_DL_CCCH_MessageType_vals), 0,
        "lte_rrc.DL_CCCH_MessageType", HFILL }},
    { &hf_lte_rrc_c1_02,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_02_vals), 0,
        "lte_rrc.T_c1_02", HFILL }},
    { &hf_lte_rrc_rrcConnectionReestablishment,
      { "rrcConnectionReestablishment", "lte-rrc.rrcConnectionReestablishment",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReestablishment", HFILL }},
    { &hf_lte_rrc_rrcConnectionReestablishmentReject,
      { "rrcConnectionReestablishmentReject", "lte-rrc.rrcConnectionReestablishmentReject",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReestablishmentReject", HFILL }},
    { &hf_lte_rrc_rrcConnectionReject,
      { "rrcConnectionReject", "lte-rrc.rrcConnectionReject",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReject", HFILL }},
    { &hf_lte_rrc_rrcConnectionSetup,
      { "rrcConnectionSetup", "lte-rrc.rrcConnectionSetup",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionSetup", HFILL }},
    { &hf_lte_rrc_messageClassExtension_02,
      { "messageClassExtension", "lte-rrc.messageClassExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_messageClassExtension_02", HFILL }},
    { &hf_lte_rrc_message_04,
      { "message", "lte-rrc.message",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_DL_DCCH_MessageType_vals), 0,
        "lte_rrc.DL_DCCH_MessageType", HFILL }},
    { &hf_lte_rrc_c1_03,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_03_vals), 0,
        "lte_rrc.T_c1_03", HFILL }},
    { &hf_lte_rrc_cdma2000_CSFBParametersResponse,
      { "cdma2000-CSFBParametersResponse", "lte-rrc.cdma2000_CSFBParametersResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_CSFBParametersResponse", HFILL }},
    { &hf_lte_rrc_dlInformationTransfer,
      { "dlInformationTransfer", "lte-rrc.dlInformationTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DLInformationTransfer", HFILL }},
    { &hf_lte_rrc_handoverFromEUTRAPreparationRequest,
      { "handoverFromEUTRAPreparationRequest", "lte-rrc.handoverFromEUTRAPreparationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.HandoverFromEUTRAPreparationRequest", HFILL }},
    { &hf_lte_rrc_mobilityFromEUTRACommand,
      { "mobilityFromEUTRACommand", "lte-rrc.mobilityFromEUTRACommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MobilityFromEUTRACommand", HFILL }},
    { &hf_lte_rrc_rrcConnectionReconfiguration,
      { "rrcConnectionReconfiguration", "lte-rrc.rrcConnectionReconfiguration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReconfiguration", HFILL }},
    { &hf_lte_rrc_rrcConnectionRelease,
      { "rrcConnectionRelease", "lte-rrc.rrcConnectionRelease",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionRelease", HFILL }},
    { &hf_lte_rrc_securityModeCommand,
      { "securityModeCommand", "lte-rrc.securityModeCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SecurityModeCommand", HFILL }},
    { &hf_lte_rrc_ueCapabilityEnquiry,
      { "ueCapabilityEnquiry", "lte-rrc.ueCapabilityEnquiry",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UECapabilityEnquiry", HFILL }},
    { &hf_lte_rrc_counterCheck,
      { "counterCheck", "lte-rrc.counterCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CounterCheck", HFILL }},
    { &hf_lte_rrc_spare7,
      { "spare7", "lte-rrc.spare7",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_spare6,
      { "spare6", "lte-rrc.spare6",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_spare5,
      { "spare5", "lte-rrc.spare5",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_spare4,
      { "spare4", "lte-rrc.spare4",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_spare3,
      { "spare3", "lte-rrc.spare3",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_spare2,
      { "spare2", "lte-rrc.spare2",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_spare1,
      { "spare1", "lte-rrc.spare1",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_messageClassExtension_03,
      { "messageClassExtension", "lte-rrc.messageClassExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_messageClassExtension_03", HFILL }},
    { &hf_lte_rrc_message_05,
      { "message", "lte-rrc.message",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_UL_CCCH_MessageType_vals), 0,
        "lte_rrc.UL_CCCH_MessageType", HFILL }},
    { &hf_lte_rrc_c1_04,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_04_vals), 0,
        "lte_rrc.T_c1_04", HFILL }},
    { &hf_lte_rrc_rrcConnectionReestablishmentRequest,
      { "rrcConnectionReestablishmentRequest", "lte-rrc.rrcConnectionReestablishmentRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReestablishmentRequest", HFILL }},
    { &hf_lte_rrc_rrcConnectionRequest,
      { "rrcConnectionRequest", "lte-rrc.rrcConnectionRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionRequest", HFILL }},
    { &hf_lte_rrc_messageClassExtension_04,
      { "messageClassExtension", "lte-rrc.messageClassExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_messageClassExtension_04", HFILL }},
    { &hf_lte_rrc_message_06,
      { "message", "lte-rrc.message",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_UL_DCCH_MessageType_vals), 0,
        "lte_rrc.UL_DCCH_MessageType", HFILL }},
    { &hf_lte_rrc_c1_05,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_05_vals), 0,
        "lte_rrc.T_c1_05", HFILL }},
    { &hf_lte_rrc_cdma2000_CSFBParametersRequest,
      { "cdma2000-CSFBParametersRequest", "lte-rrc.cdma2000_CSFBParametersRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_CSFBParametersRequest", HFILL }},
    { &hf_lte_rrc_measurementReport,
      { "measurementReport", "lte-rrc.measurementReport",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasurementReport", HFILL }},
    { &hf_lte_rrc_rrcConnectionReconfigurationComplete,
      { "rrcConnectionReconfigurationComplete", "lte-rrc.rrcConnectionReconfigurationComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReconfigurationComplete", HFILL }},
    { &hf_lte_rrc_rrcConnectionReestablishmentComplete,
      { "rrcConnectionReestablishmentComplete", "lte-rrc.rrcConnectionReestablishmentComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReestablishmentComplete", HFILL }},
    { &hf_lte_rrc_rrcConnectionSetupComplete,
      { "rrcConnectionSetupComplete", "lte-rrc.rrcConnectionSetupComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionSetupComplete", HFILL }},
    { &hf_lte_rrc_securityModeComplete,
      { "securityModeComplete", "lte-rrc.securityModeComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SecurityModeComplete", HFILL }},
    { &hf_lte_rrc_securityModeFailure,
      { "securityModeFailure", "lte-rrc.securityModeFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SecurityModeFailure", HFILL }},
    { &hf_lte_rrc_ueCapabilityInformation,
      { "ueCapabilityInformation", "lte-rrc.ueCapabilityInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UECapabilityInformation", HFILL }},
    { &hf_lte_rrc_ulHandoverPreparationTransfer,
      { "ulHandoverPreparationTransfer", "lte-rrc.ulHandoverPreparationTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ULHandoverPreparationTransfer", HFILL }},
    { &hf_lte_rrc_ulInformationTransfer,
      { "ulInformationTransfer", "lte-rrc.ulInformationTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ULInformationTransfer", HFILL }},
    { &hf_lte_rrc_counterCheckResponse,
      { "counterCheckResponse", "lte-rrc.counterCheckResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CounterCheckResponse", HFILL }},
    { &hf_lte_rrc_messageClassExtension_05,
      { "messageClassExtension", "lte-rrc.messageClassExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_messageClassExtension_05", HFILL }},
    { &hf_lte_rrc_rrc_TransactionIdentifier,
      { "rrc-TransactionIdentifier", "lte-rrc.rrc_TransactionIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.RRC_TransactionIdentifier", HFILL }},
    { &hf_lte_rrc_criticalExtensions,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_vals), 0,
        "lte_rrc.T_criticalExtensions", HFILL }},
    { &hf_lte_rrc_cdma2000_CSFBParametersRequest_r8,
      { "cdma2000-CSFBParametersRequest-r8", "lte-rrc.cdma2000_CSFBParametersRequest_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_CSFBParametersRequest_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension", HFILL }},
    { &hf_lte_rrc_criticalExtensions_01,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_01_vals), 0,
        "lte_rrc.T_criticalExtensions_01", HFILL }},
    { &hf_lte_rrc_cdma2000_1xParametersForCSFB_r8,
      { "cdma2000-1xParametersForCSFB-r8", "lte-rrc.cdma2000_1xParametersForCSFB_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_CSFBParametersResponse_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_01,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_01", HFILL }},
    { &hf_lte_rrc_cdma2000_RAND,
      { "cdma2000-RAND", "lte-rrc.cdma2000_RAND",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_RAND", HFILL }},
    { &hf_lte_rrc_cdma2000_MobilityParameters,
      { "cdma2000-MobilityParameters", "lte-rrc.cdma2000_MobilityParameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_MobilityParameters", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_01,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_01", HFILL }},
    { &hf_lte_rrc_criticalExtensions_02,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_02_vals), 0,
        "lte_rrc.T_criticalExtensions_02", HFILL }},
    { &hf_lte_rrc_c1_06,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_06_vals), 0,
        "lte_rrc.T_c1_06", HFILL }},
    { &hf_lte_rrc_counterCheck_r8,
      { "counterCheck-r8", "lte-rrc.counterCheck_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CounterCheck_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_02,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_02", HFILL }},
    { &hf_lte_rrc_drb_CountMSB_InfoList,
      { "drb-CountMSB-InfoList", "lte-rrc.drb_CountMSB_InfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.DRB_CountMSB_InfoList", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_02,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_02", HFILL }},
    { &hf_lte_rrc_DRB_CountMSB_InfoList_item,
      { "DRB-CountMSB-InfoList item", "lte-rrc.DRB_CountMSB_InfoList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DRB_CountMSB_InfoList_item", HFILL }},
    { &hf_lte_rrc_drb_Identity,
      { "drb-Identity", "lte-rrc.drb_Identity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_32", HFILL }},
    { &hf_lte_rrc_countMSB_Uplink,
      { "countMSB-Uplink", "lte-rrc.countMSB_Uplink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_33554431", HFILL }},
    { &hf_lte_rrc_countMSB_Downlink,
      { "countMSB-Downlink", "lte-rrc.countMSB_Downlink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_33554431", HFILL }},
    { &hf_lte_rrc_criticalExtensions_03,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_03_vals), 0,
        "lte_rrc.T_criticalExtensions_03", HFILL }},
    { &hf_lte_rrc_counterCheckResponse_r8,
      { "counterCheckResponse-r8", "lte-rrc.counterCheckResponse_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CounterCheckResponse_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_03,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_03", HFILL }},
    { &hf_lte_rrc_drb_CountInfoList,
      { "drb-CountInfoList", "lte-rrc.drb_CountInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.DRB_CountInfoList", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_03,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_03", HFILL }},
    { &hf_lte_rrc_DRB_CountInfoList_item,
      { "DRB-CountInfoList item", "lte-rrc.DRB_CountInfoList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DRB_CountInfoList_item", HFILL }},
    { &hf_lte_rrc_count_Uplink,
      { "count-Uplink", "lte-rrc.count_Uplink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_4294967295", HFILL }},
    { &hf_lte_rrc_count_Downlink,
      { "count-Downlink", "lte-rrc.count_Downlink",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_4294967295", HFILL }},
    { &hf_lte_rrc_criticalExtensions_04,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_04_vals), 0,
        "lte_rrc.T_criticalExtensions_04", HFILL }},
    { &hf_lte_rrc_c1_07,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_07_vals), 0,
        "lte_rrc.T_c1_07", HFILL }},
    { &hf_lte_rrc_dlInformationTransfer_r8,
      { "dlInformationTransfer-r8", "lte-rrc.dlInformationTransfer_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DLInformationTransfer_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_04,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_04", HFILL }},
    { &hf_lte_rrc_informationType,
      { "informationType", "lte-rrc.informationType",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_informationType_vals), 0,
        "lte_rrc.T_informationType", HFILL }},
    { &hf_lte_rrc_nas3GPP,
      { "nas3GPP", "lte-rrc.nas3GPP",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.NAS_DedicatedInformation", HFILL }},
    { &hf_lte_rrc_cdma2000,
      { "cdma2000", "lte-rrc.cdma2000",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_cdma2000", HFILL }},
    { &hf_lte_rrc_cdma2000_Type,
      { "cdma2000-Type", "lte-rrc.cdma2000_Type",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_CDMA2000_Type_vals), 0,
        "lte_rrc.CDMA2000_Type", HFILL }},
    { &hf_lte_rrc_cdma2000_DedicatedInfo,
      { "cdma2000-DedicatedInfo", "lte-rrc.cdma2000_DedicatedInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_DedicatedInfo", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_04,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_04", HFILL }},
    { &hf_lte_rrc_criticalExtensions_05,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_05_vals), 0,
        "lte_rrc.T_criticalExtensions_05", HFILL }},
    { &hf_lte_rrc_c1_08,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_08_vals), 0,
        "lte_rrc.T_c1_08", HFILL }},
    { &hf_lte_rrc_handoverFromEUTRAPreparationRequest_r8,
      { "handoverFromEUTRAPreparationRequest-r8", "lte-rrc.handoverFromEUTRAPreparationRequest_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.HandoverFromEUTRAPreparationRequest_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_05,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_05", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_05,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_05", HFILL }},
    { &hf_lte_rrc_dl_Bandwidth,
      { "dl-Bandwidth", "lte-rrc.dl_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_dl_Bandwidth_vals), 0,
        "lte_rrc.T_dl_Bandwidth", HFILL }},
    { &hf_lte_rrc_phich_Configuration,
      { "phich-Configuration", "lte-rrc.phich_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PHICH_Configuration", HFILL }},
    { &hf_lte_rrc_systemFrameNumber,
      { "systemFrameNumber", "lte-rrc.systemFrameNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_8", HFILL }},
    { &hf_lte_rrc_spare,
      { "spare", "lte-rrc.spare",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_10", HFILL }},
    { &hf_lte_rrc_criticalExtensions_06,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_06_vals), 0,
        "lte_rrc.T_criticalExtensions_06", HFILL }},
    { &hf_lte_rrc_c1_09,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_09_vals), 0,
        "lte_rrc.T_c1_09", HFILL }},
    { &hf_lte_rrc_measurementReport_r8,
      { "measurementReport-r8", "lte-rrc.measurementReport_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasurementReport_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_06,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_06", HFILL }},
    { &hf_lte_rrc_measuredResults,
      { "measuredResults", "lte-rrc.measuredResults",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasuredResults", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_06,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_06", HFILL }},
    { &hf_lte_rrc_criticalExtensions_07,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_07_vals), 0,
        "lte_rrc.T_criticalExtensions_07", HFILL }},
    { &hf_lte_rrc_c1_10,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_10_vals), 0,
        "lte_rrc.T_c1_10", HFILL }},
    { &hf_lte_rrc_mobilityFromEUTRACommand_r8,
      { "mobilityFromEUTRACommand-r8", "lte-rrc.mobilityFromEUTRACommand_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MobilityFromEUTRACommand_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_07,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_07", HFILL }},
    { &hf_lte_rrc_csFallbackIndicator,
      { "csFallbackIndicator", "lte-rrc.csFallbackIndicator",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_csFallbackIndicator_vals), 0,
        "lte_rrc.T_csFallbackIndicator", HFILL }},
    { &hf_lte_rrc_purpose,
      { "purpose", "lte-rrc.purpose",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_purpose_vals), 0,
        "lte_rrc.T_purpose", HFILL }},
    { &hf_lte_rrc_handover,
      { "handover", "lte-rrc.handover",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.Handover", HFILL }},
    { &hf_lte_rrc_cellChangeOrder,
      { "cellChangeOrder", "lte-rrc.cellChangeOrder",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CellChangeOrder", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_07,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_07", HFILL }},
    { &hf_lte_rrc_targetRAT_Type,
      { "targetRAT-Type", "lte-rrc.targetRAT_Type",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_targetRAT_Type_vals), 0,
        "lte_rrc.T_targetRAT_Type", HFILL }},
    { &hf_lte_rrc_targetRAT_MessageContainer,
      { "targetRAT-MessageContainer", "lte-rrc.targetRAT_MessageContainer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING", HFILL }},
    { &hf_lte_rrc_nas_SecurityParamFromEUTRA,
      { "nas-SecurityParamFromEUTRA", "lte-rrc.nas_SecurityParamFromEUTRA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING", HFILL }},
    { &hf_lte_rrc_t304,
      { "t304", "lte-rrc.t304",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t304_vals), 0,
        "lte_rrc.T_t304", HFILL }},
    { &hf_lte_rrc_targetRAT_Type_01,
      { "targetRAT-Type", "lte-rrc.targetRAT_Type",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_targetRAT_Type_01_vals), 0,
        "lte_rrc.T_targetRAT_Type_01", HFILL }},
    { &hf_lte_rrc_geran,
      { "geran", "lte-rrc.geran",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_geran", HFILL }},
    { &hf_lte_rrc_bsic,
      { "bsic", "lte-rrc.bsic",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GERAN_CellIdentity", HFILL }},
    { &hf_lte_rrc_geran_CarrierFreq,
      { "geran-CarrierFreq", "lte-rrc.geran_CarrierFreq",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GERAN_CarrierFreq", HFILL }},
    { &hf_lte_rrc_networkControlOrder,
      { "networkControlOrder", "lte-rrc.networkControlOrder",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_2", HFILL }},
    { &hf_lte_rrc_geran_SystemInformation,
      { "geran-SystemInformation", "lte-rrc.geran_SystemInformation",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_geran_SystemInformation_vals), 0,
        "lte_rrc.T_geran_SystemInformation", HFILL }},
    { &hf_lte_rrc_si,
      { "si", "lte-rrc.si",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.GERAN_SystemInformation", HFILL }},
    { &hf_lte_rrc_psi,
      { "psi", "lte-rrc.psi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.GERAN_SystemInformation", HFILL }},
    { &hf_lte_rrc_GERAN_SystemInformation_item,
      { "GERAN-SystemInformation item", "lte-rrc.GERAN_SystemInformation_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING_SIZE_1_23", HFILL }},
    { &hf_lte_rrc_pagingRecordList,
      { "pagingRecordList", "lte-rrc.pagingRecordList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PagingRecordList", HFILL }},
    { &hf_lte_rrc_systemInfoModification,
      { "systemInfoModification", "lte-rrc.systemInfoModification",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_systemInfoModification_vals), 0,
        "lte_rrc.T_systemInfoModification", HFILL }},
    { &hf_lte_rrc_etws_Indication,
      { "etws-Indication", "lte-rrc.etws_Indication",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_etws_Indication_vals), 0,
        "lte_rrc.T_etws_Indication", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_08,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_08", HFILL }},
    { &hf_lte_rrc_PagingRecordList_item,
      { "PagingRecord", "lte-rrc.PagingRecord",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PagingRecord", HFILL }},
    { &hf_lte_rrc_ue_Identity,
      { "ue-Identity", "lte-rrc.ue_Identity",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_PagingUE_Identity_vals), 0,
        "lte_rrc.PagingUE_Identity", HFILL }},
    { &hf_lte_rrc_cn_Domain,
      { "cn-Domain", "lte-rrc.cn_Domain",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cn_Domain_vals), 0,
        "lte_rrc.T_cn_Domain", HFILL }},
    { &hf_lte_rrc_s_TMSI,
      { "s-TMSI", "lte-rrc.s_TMSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.S_TMSI", HFILL }},
    { &hf_lte_rrc_imsi,
      { "imsi", "lte-rrc.imsi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.IMSI", HFILL }},
    { &hf_lte_rrc_criticalExtensions_08,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_08_vals), 0,
        "lte_rrc.T_criticalExtensions_08", HFILL }},
    { &hf_lte_rrc_c1_11,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_11_vals), 0,
        "lte_rrc.T_c1_11", HFILL }},
    { &hf_lte_rrc_rrcConnectionReconfiguration_r8,
      { "rrcConnectionReconfiguration-r8", "lte-rrc.rrcConnectionReconfiguration_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReconfiguration_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_08,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_08", HFILL }},
    { &hf_lte_rrc_measurementConfiguration,
      { "measurementConfiguration", "lte-rrc.measurementConfiguration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasurementConfiguration", HFILL }},
    { &hf_lte_rrc_mobilityControlInformation,
      { "mobilityControlInformation", "lte-rrc.mobilityControlInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MobilityControlInformation", HFILL }},
    { &hf_lte_rrc_nas_DedicatedInformationList,
      { "nas-DedicatedInformationList", "lte-rrc.nas_DedicatedInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SEQUENCE_SIZE_1_maxDRB_OF_NAS_DedicatedInformation", HFILL }},
    { &hf_lte_rrc_nas_DedicatedInformationList_item,
      { "NAS-DedicatedInformation", "lte-rrc.NAS_DedicatedInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.NAS_DedicatedInformation", HFILL }},
    { &hf_lte_rrc_radioResourceConfiguration,
      { "radioResourceConfiguration", "lte-rrc.radioResourceConfiguration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RadioResourceConfigDedicated", HFILL }},
    { &hf_lte_rrc_securityConfiguration,
      { "securityConfiguration", "lte-rrc.securityConfiguration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SecurityConfiguration", HFILL }},
    { &hf_lte_rrc_nas_SecurityParamToEUTRA,
      { "nas-SecurityParamToEUTRA", "lte-rrc.nas_SecurityParamToEUTRA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING_SIZE_6", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_09,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_09", HFILL }},
    { &hf_lte_rrc_criticalExtensions_09,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_09_vals), 0,
        "lte_rrc.T_criticalExtensions_09", HFILL }},
    { &hf_lte_rrc_rrcConnectionReconfigurationComplete_r8,
      { "rrcConnectionReconfigurationComplete-r8", "lte-rrc.rrcConnectionReconfigurationComplete_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReconfigurationComplete_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_09,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_09", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_10,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_10", HFILL }},
    { &hf_lte_rrc_criticalExtensions_10,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_10_vals), 0,
        "lte_rrc.T_criticalExtensions_10", HFILL }},
    { &hf_lte_rrc_c1_12,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_12_vals), 0,
        "lte_rrc.T_c1_12", HFILL }},
    { &hf_lte_rrc_rrcConnectionReestablishment_r8,
      { "rrcConnectionReestablishment-r8", "lte-rrc.rrcConnectionReestablishment_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReestablishment_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_10,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_10", HFILL }},
    { &hf_lte_rrc_nextHopChainingCount,
      { "nextHopChainingCount", "lte-rrc.nextHopChainingCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.NextHopChainingCount", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_11,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_11", HFILL }},
    { &hf_lte_rrc_criticalExtensions_11,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_11_vals), 0,
        "lte_rrc.T_criticalExtensions_11", HFILL }},
    { &hf_lte_rrc_rrcConnectionReestablishmentComplete_r8,
      { "rrcConnectionReestablishmentComplete-r8", "lte-rrc.rrcConnectionReestablishmentComplete_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReestablishmentComplete_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_11,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_11", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_12,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_12", HFILL }},
    { &hf_lte_rrc_criticalExtensions_12,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_12_vals), 0,
        "lte_rrc.T_criticalExtensions_12", HFILL }},
    { &hf_lte_rrc_rrcConnectionReestablishmentReject_r8,
      { "rrcConnectionReestablishmentReject-r8", "lte-rrc.rrcConnectionReestablishmentReject_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReestablishmentReject_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_12,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_12", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_13,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_13", HFILL }},
    { &hf_lte_rrc_criticalExtensions_13,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_13_vals), 0,
        "lte_rrc.T_criticalExtensions_13", HFILL }},
    { &hf_lte_rrc_rrcConnectionReestablishmentRequest_r8,
      { "rrcConnectionReestablishmentRequest-r8", "lte-rrc.rrcConnectionReestablishmentRequest_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReestablishmentRequest_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_13,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_13", HFILL }},
    { &hf_lte_rrc_ue_Identity_01,
      { "ue-Identity", "lte-rrc.ue_Identity",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ReestabUE_Identity", HFILL }},
    { &hf_lte_rrc_reestablishmentCause,
      { "reestablishmentCause", "lte-rrc.reestablishmentCause",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ReestablishmentCause_vals), 0,
        "lte_rrc.ReestablishmentCause", HFILL }},
    { &hf_lte_rrc_spare_01,
      { "spare", "lte-rrc.spare",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_2", HFILL }},
    { &hf_lte_rrc_c_RNTI,
      { "c-RNTI", "lte-rrc.c_RNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.C_RNTI", HFILL }},
    { &hf_lte_rrc_physCellIdentity,
      { "physCellIdentity", "lte-rrc.physCellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PhysicalCellIdentity", HFILL }},
    { &hf_lte_rrc_shortMAC_I,
      { "shortMAC-I", "lte-rrc.shortMAC_I",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.ShortMAC_I", HFILL }},
    { &hf_lte_rrc_criticalExtensions_14,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_14_vals), 0,
        "lte_rrc.T_criticalExtensions_14", HFILL }},
    { &hf_lte_rrc_c1_13,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_13_vals), 0,
        "lte_rrc.T_c1_13", HFILL }},
    { &hf_lte_rrc_rrcConnectionReject_r8,
      { "rrcConnectionReject-r8", "lte-rrc.rrcConnectionReject_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionReject_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_14,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_14", HFILL }},
    { &hf_lte_rrc_waitTime,
      { "waitTime", "lte-rrc.waitTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_16", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_14,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_14", HFILL }},
    { &hf_lte_rrc_criticalExtensions_15,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_15_vals), 0,
        "lte_rrc.T_criticalExtensions_15", HFILL }},
    { &hf_lte_rrc_c1_14,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_14_vals), 0,
        "lte_rrc.T_c1_14", HFILL }},
    { &hf_lte_rrc_rrcConnectionRelease_r8,
      { "rrcConnectionRelease-r8", "lte-rrc.rrcConnectionRelease_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionRelease_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_15,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_15", HFILL }},
    { &hf_lte_rrc_releaseCause,
      { "releaseCause", "lte-rrc.releaseCause",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ReleaseCause_vals), 0,
        "lte_rrc.ReleaseCause", HFILL }},
    { &hf_lte_rrc_redirectionInformation,
      { "redirectionInformation", "lte-rrc.redirectionInformation",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_RedirectionInformation_vals), 0,
        "lte_rrc.RedirectionInformation", HFILL }},
    { &hf_lte_rrc_idleModeMobilityControlInfo,
      { "idleModeMobilityControlInfo", "lte-rrc.idleModeMobilityControlInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.IdleModeMobilityControlInfo", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_15,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_15", HFILL }},
    { &hf_lte_rrc_eutra_CarrierFreq,
      { "eutra-CarrierFreq", "lte-rrc.eutra_CarrierFreq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.EUTRA_DL_CarrierFreq", HFILL }},
    { &hf_lte_rrc_interRAT_target,
      { "interRAT-target", "lte-rrc.interRAT_target",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_interRAT_target_vals), 0,
        "lte_rrc.T_interRAT_target", HFILL }},
    { &hf_lte_rrc_geran_01,
      { "geran", "lte-rrc.geran",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GERAN_CarrierFreq", HFILL }},
    { &hf_lte_rrc_utra_FDD,
      { "utra-FDD", "lte-rrc.utra_FDD",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_DL_CarrierFreq", HFILL }},
    { &hf_lte_rrc_utra_TDD,
      { "utra-TDD", "lte-rrc.utra_TDD",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_DL_CarrierFreq", HFILL }},
    { &hf_lte_rrc_cdma2000_HRPD,
      { "cdma2000-HRPD", "lte-rrc.cdma2000_HRPD",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_CarrierInfo", HFILL }},
    { &hf_lte_rrc_cdma2000_1xRTT,
      { "cdma2000-1xRTT", "lte-rrc.cdma2000_1xRTT",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_CarrierInfo", HFILL }},
    { &hf_lte_rrc_interFreqPriorityList,
      { "interFreqPriorityList", "lte-rrc.interFreqPriorityList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.InterFreqPriorityList", HFILL }},
    { &hf_lte_rrc_geran_FreqPriorityList,
      { "geran-FreqPriorityList", "lte-rrc.geran_FreqPriorityList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.GERAN_FreqPriorityList", HFILL }},
    { &hf_lte_rrc_utra_FDD_FreqPriorityList,
      { "utra-FDD-FreqPriorityList", "lte-rrc.utra_FDD_FreqPriorityList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.UTRA_FDD_FreqPriorityList", HFILL }},
    { &hf_lte_rrc_utra_TDD_FreqPriorityList,
      { "utra-TDD-FreqPriorityList", "lte-rrc.utra_TDD_FreqPriorityList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.UTRA_TDD_FreqPriorityList", HFILL }},
    { &hf_lte_rrc_hrpd_BandClassPriorityList,
      { "hrpd-BandClassPriorityList", "lte-rrc.hrpd_BandClassPriorityList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.HRPD_BandClassPriorityList", HFILL }},
    { &hf_lte_rrc_oneXRTT_BandClassPriorityList,
      { "oneXRTT-BandClassPriorityList", "lte-rrc.oneXRTT_BandClassPriorityList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.OneXRTT_BandClassPriorityList", HFILL }},
    { &hf_lte_rrc_t320,
      { "t320", "lte-rrc.t320",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t320_vals), 0,
        "lte_rrc.T_t320", HFILL }},
    { &hf_lte_rrc_InterFreqPriorityList_item,
      { "InterFreqPriorityList item", "lte-rrc.InterFreqPriorityList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.InterFreqPriorityList_item", HFILL }},
    { &hf_lte_rrc_cellReselectionPriority,
      { "cellReselectionPriority", "lte-rrc.cellReselectionPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_GERAN_FreqPriorityList_item,
      { "GERAN-FreqPriorityList item", "lte-rrc.GERAN_FreqPriorityList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GERAN_FreqPriorityList_item", HFILL }},
    { &hf_lte_rrc_geran_BCCH_FrequencyGroup,
      { "geran-BCCH-FrequencyGroup", "lte-rrc.geran_BCCH_FrequencyGroup",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GERAN_CarrierFreqList", HFILL }},
    { &hf_lte_rrc_geran_CellReselectionPriority,
      { "geran-CellReselectionPriority", "lte-rrc.geran_CellReselectionPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_UTRA_FDD_FreqPriorityList_item,
      { "UTRA-FDD-FreqPriorityList item", "lte-rrc.UTRA_FDD_FreqPriorityList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_FDD_FreqPriorityList_item", HFILL }},
    { &hf_lte_rrc_utra_CarrierFreq,
      { "utra-CarrierFreq", "lte-rrc.utra_CarrierFreq",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_DL_CarrierFreq", HFILL }},
    { &hf_lte_rrc_utra_CellReselectionPriority,
      { "utra-CellReselectionPriority", "lte-rrc.utra_CellReselectionPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_UTRA_TDD_FreqPriorityList_item,
      { "UTRA-TDD-FreqPriorityList item", "lte-rrc.UTRA_TDD_FreqPriorityList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_TDD_FreqPriorityList_item", HFILL }},
    { &hf_lte_rrc_HRPD_BandClassPriorityList_item,
      { "HRPD-BandClassPriorityList item", "lte-rrc.HRPD_BandClassPriorityList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.HRPD_BandClassPriorityList_item", HFILL }},
    { &hf_lte_rrc_hrpd_bandClass,
      { "hrpd-bandClass", "lte-rrc.hrpd_bandClass",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_CDMA2000_Bandclass_vals), 0,
        "lte_rrc.CDMA2000_Bandclass", HFILL }},
    { &hf_lte_rrc_hrpd_CellReselectionPriority,
      { "hrpd-CellReselectionPriority", "lte-rrc.hrpd_CellReselectionPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_OneXRTT_BandClassPriorityList_item,
      { "OneXRTT-BandClassPriorityList item", "lte-rrc.OneXRTT_BandClassPriorityList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.OneXRTT_BandClassPriorityList_item", HFILL }},
    { &hf_lte_rrc_oneXRTT_bandClass,
      { "oneXRTT-bandClass", "lte-rrc.oneXRTT_bandClass",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_CDMA2000_Bandclass_vals), 0,
        "lte_rrc.CDMA2000_Bandclass", HFILL }},
    { &hf_lte_rrc_oneXRTT_CellReselectionPriority,
      { "oneXRTT-CellReselectionPriority", "lte-rrc.oneXRTT_CellReselectionPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_criticalExtensions_16,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_16_vals), 0,
        "lte_rrc.T_criticalExtensions_16", HFILL }},
    { &hf_lte_rrc_rrcConnectionRequest_r8,
      { "rrcConnectionRequest-r8", "lte-rrc.rrcConnectionRequest_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionRequest_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_16,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_16", HFILL }},
    { &hf_lte_rrc_ue_Identity_02,
      { "ue-Identity", "lte-rrc.ue_Identity",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_InitialUE_Identity_vals), 0,
        "lte_rrc.InitialUE_Identity", HFILL }},
    { &hf_lte_rrc_establishmentCause,
      { "establishmentCause", "lte-rrc.establishmentCause",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_EstablishmentCause_vals), 0,
        "lte_rrc.EstablishmentCause", HFILL }},
    { &hf_lte_rrc_spare_02,
      { "spare", "lte-rrc.spare",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_1", HFILL }},
    { &hf_lte_rrc_randomValue,
      { "randomValue", "lte-rrc.randomValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_40", HFILL }},
    { &hf_lte_rrc_criticalExtensions_17,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_17_vals), 0,
        "lte_rrc.T_criticalExtensions_17", HFILL }},
    { &hf_lte_rrc_c1_15,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_15_vals), 0,
        "lte_rrc.T_c1_15", HFILL }},
    { &hf_lte_rrc_rrcConnectionSetup_r8,
      { "rrcConnectionSetup-r8", "lte-rrc.rrcConnectionSetup_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionSetup_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_17,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_17", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_16,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_16", HFILL }},
    { &hf_lte_rrc_criticalExtensions_18,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_18_vals), 0,
        "lte_rrc.T_criticalExtensions_18", HFILL }},
    { &hf_lte_rrc_c1_16,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_16_vals), 0,
        "lte_rrc.T_c1_16", HFILL }},
    { &hf_lte_rrc_rrcConnectionSetupComplete_r8,
      { "rrcConnectionSetupComplete-r8", "lte-rrc.rrcConnectionSetupComplete_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRCConnectionSetupComplete_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_18,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_18", HFILL }},
    { &hf_lte_rrc_selectedPLMN_Identity,
      { "selectedPLMN-Identity", "lte-rrc.selectedPLMN_Identity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_6", HFILL }},
    { &hf_lte_rrc_registeredMME,
      { "registeredMME", "lte-rrc.registeredMME",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RegisteredMME", HFILL }},
    { &hf_lte_rrc_nas_DedicatedInformation,
      { "nas-DedicatedInformation", "lte-rrc.nas_DedicatedInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.NAS_DedicatedInformation", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_17,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_17", HFILL }},
    { &hf_lte_rrc_plmn_Identity,
      { "plmn-Identity", "lte-rrc.plmn_Identity",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PLMN_Identity", HFILL }},
    { &hf_lte_rrc_mmegi,
      { "mmegi", "lte-rrc.mmegi",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_16", HFILL }},
    { &hf_lte_rrc_mmec,
      { "mmec", "lte-rrc.mmec",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.MMEC", HFILL }},
    { &hf_lte_rrc_criticalExtensions_19,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_19_vals), 0,
        "lte_rrc.T_criticalExtensions_19", HFILL }},
    { &hf_lte_rrc_c1_17,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_17_vals), 0,
        "lte_rrc.T_c1_17", HFILL }},
    { &hf_lte_rrc_securityModeCommand_r8,
      { "securityModeCommand-r8", "lte-rrc.securityModeCommand_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SecurityModeCommand_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_19,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_19", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_18,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_18", HFILL }},
    { &hf_lte_rrc_criticalExtensions_20,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_20_vals), 0,
        "lte_rrc.T_criticalExtensions_20", HFILL }},
    { &hf_lte_rrc_securityModeComplete_r8,
      { "securityModeComplete-r8", "lte-rrc.securityModeComplete_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SecurityModeComplete_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_20,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_20", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_19,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_19", HFILL }},
    { &hf_lte_rrc_criticalExtensions_21,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_21_vals), 0,
        "lte_rrc.T_criticalExtensions_21", HFILL }},
    { &hf_lte_rrc_securityModeFailure_r8,
      { "securityModeFailure-r8", "lte-rrc.securityModeFailure_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SecurityModeFailure_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_21,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_21", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_20,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_20", HFILL }},
    { &hf_lte_rrc_criticalExtensions_22,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_22_vals), 0,
        "lte_rrc.T_criticalExtensions_22", HFILL }},
    { &hf_lte_rrc_systemInformation_r8,
      { "systemInformation-r8", "lte-rrc.systemInformation_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformation_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_22,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_22", HFILL }},
    { &hf_lte_rrc_sib_TypeAndInfo,
      { "sib-TypeAndInfo", "lte-rrc.sib_TypeAndInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.T_sib_TypeAndInfo", HFILL }},
    { &hf_lte_rrc_sib_TypeAndInfo_item,
      { "sib-TypeAndInfo item", "lte-rrc.sib_TypeAndInfo_item",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_sib_TypeAndInfo_item_vals), 0,
        "lte_rrc.T_sib_TypeAndInfo_item", HFILL }},
    { &hf_lte_rrc_sib2,
      { "sib2", "lte-rrc.sib2",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType2", HFILL }},
    { &hf_lte_rrc_sib3,
      { "sib3", "lte-rrc.sib3",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType3", HFILL }},
    { &hf_lte_rrc_sib4,
      { "sib4", "lte-rrc.sib4",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType4", HFILL }},
    { &hf_lte_rrc_sib5,
      { "sib5", "lte-rrc.sib5",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType5", HFILL }},
    { &hf_lte_rrc_sib6,
      { "sib6", "lte-rrc.sib6",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType6", HFILL }},
    { &hf_lte_rrc_sib7,
      { "sib7", "lte-rrc.sib7",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType7", HFILL }},
    { &hf_lte_rrc_sib8,
      { "sib8", "lte-rrc.sib8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType8", HFILL }},
    { &hf_lte_rrc_sib9,
      { "sib9", "lte-rrc.sib9",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType9", HFILL }},
    { &hf_lte_rrc_sib10,
      { "sib10", "lte-rrc.sib10",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType10", HFILL }},
    { &hf_lte_rrc_sib11,
      { "sib11", "lte-rrc.sib11",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType11", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_21,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_21", HFILL }},
    { &hf_lte_rrc_cellAccessRelatedInformation,
      { "cellAccessRelatedInformation", "lte-rrc.cellAccessRelatedInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_cellAccessRelatedInformation", HFILL }},
    { &hf_lte_rrc_plmn_IdentityList,
      { "plmn-IdentityList", "lte-rrc.plmn_IdentityList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PLMN_IdentityList", HFILL }},
    { &hf_lte_rrc_trackingAreaCode,
      { "trackingAreaCode", "lte-rrc.trackingAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.TrackingAreaCode", HFILL }},
    { &hf_lte_rrc_cellIdentity,
      { "cellIdentity", "lte-rrc.cellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.CellIdentity", HFILL }},
    { &hf_lte_rrc_cellBarred,
      { "cellBarred", "lte-rrc.cellBarred",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cellBarred_vals), 0,
        "lte_rrc.T_cellBarred", HFILL }},
    { &hf_lte_rrc_intraFrequencyReselection,
      { "intraFrequencyReselection", "lte-rrc.intraFrequencyReselection",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_intraFrequencyReselection_vals), 0,
        "lte_rrc.T_intraFrequencyReselection", HFILL }},
    { &hf_lte_rrc_csg_Indication,
      { "csg-Indication", "lte-rrc.csg_Indication",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_csg_Identity,
      { "csg-Identity", "lte-rrc.csg_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_27", HFILL }},
    { &hf_lte_rrc_cellSelectionInfo,
      { "cellSelectionInfo", "lte-rrc.cellSelectionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_cellSelectionInfo", HFILL }},
    { &hf_lte_rrc_q_RxLevMin,
      { "q-RxLevMin", "lte-rrc.q_RxLevMin",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M70_M22", HFILL }},
    { &hf_lte_rrc_q_RxLevMinOffset,
      { "q-RxLevMinOffset", "lte-rrc.q_RxLevMinOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_8", HFILL }},
    { &hf_lte_rrc_p_Max,
      { "p-Max", "lte-rrc.p_Max",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.P_Max", HFILL }},
    { &hf_lte_rrc_frequencyBandIndicator,
      { "frequencyBandIndicator", "lte-rrc.frequencyBandIndicator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_64", HFILL }},
    { &hf_lte_rrc_schedulingInformation,
      { "schedulingInformation", "lte-rrc.schedulingInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SchedulingInformation", HFILL }},
    { &hf_lte_rrc_tdd_Configuration,
      { "tdd-Configuration", "lte-rrc.tdd_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.TDD_Configuration", HFILL }},
    { &hf_lte_rrc_si_WindowLength,
      { "si-WindowLength", "lte-rrc.si_WindowLength",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_si_WindowLength_vals), 0,
        "lte_rrc.T_si_WindowLength", HFILL }},
    { &hf_lte_rrc_systemInformationValueTag,
      { "systemInformationValueTag", "lte-rrc.systemInformationValueTag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_31", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_22,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_22", HFILL }},
    { &hf_lte_rrc_PLMN_IdentityList_item,
      { "PLMN-IdentityList item", "lte-rrc.PLMN_IdentityList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PLMN_IdentityList_item", HFILL }},
    { &hf_lte_rrc_cellReservedForOperatorUse,
      { "cellReservedForOperatorUse", "lte-rrc.cellReservedForOperatorUse",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cellReservedForOperatorUse_vals), 0,
        "lte_rrc.T_cellReservedForOperatorUse", HFILL }},
    { &hf_lte_rrc_SchedulingInformation_item,
      { "SchedulingInformation item", "lte-rrc.SchedulingInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SchedulingInformation_item", HFILL }},
    { &hf_lte_rrc_si_Periodicity,
      { "si-Periodicity", "lte-rrc.si_Periodicity",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_si_Periodicity_vals), 0,
        "lte_rrc.T_si_Periodicity", HFILL }},
    { &hf_lte_rrc_sib_MappingInfo,
      { "sib-MappingInfo", "lte-rrc.sib_MappingInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SIB_MappingInfo", HFILL }},
    { &hf_lte_rrc_SIB_MappingInfo_item,
      { "SIB-Type", "lte-rrc.SIB_Type",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_SIB_Type_vals), 0,
        "lte_rrc.SIB_Type", HFILL }},
    { &hf_lte_rrc_criticalExtensions_23,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_23_vals), 0,
        "lte_rrc.T_criticalExtensions_23", HFILL }},
    { &hf_lte_rrc_c1_18,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_18_vals), 0,
        "lte_rrc.T_c1_18", HFILL }},
    { &hf_lte_rrc_ueCapabilityEnquiry_r8,
      { "ueCapabilityEnquiry-r8", "lte-rrc.ueCapabilityEnquiry_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UECapabilityEnquiry_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_23,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_23", HFILL }},
    { &hf_lte_rrc_ue_RadioAccessCapRequest,
      { "ue-RadioAccessCapRequest", "lte-rrc.ue_RadioAccessCapRequest",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.UE_RadioAccessCapRequest", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_23,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_23", HFILL }},
    { &hf_lte_rrc_UE_RadioAccessCapRequest_item,
      { "RAT-Type", "lte-rrc.RAT_Type",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_RAT_Type_vals), 0,
        "lte_rrc.RAT_Type", HFILL }},
    { &hf_lte_rrc_criticalExtensions_24,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_24_vals), 0,
        "lte_rrc.T_criticalExtensions_24", HFILL }},
    { &hf_lte_rrc_c1_19,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_19_vals), 0,
        "lte_rrc.T_c1_19", HFILL }},
    { &hf_lte_rrc_ueCapabilityInformation_r8,
      { "ueCapabilityInformation-r8", "lte-rrc.ueCapabilityInformation_r8",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.UECapabilityInformation_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_24,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_24", HFILL }},
    { &hf_lte_rrc_UECapabilityInformation_r8_IEs_item,
      { "UECapabilityInformation-r8-IEs item", "lte-rrc.UECapabilityInformation_r8_IEs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UECapabilityInformation_r8_IEs_item", HFILL }},
    { &hf_lte_rrc_rat_Type,
      { "rat-Type", "lte-rrc.rat_Type",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_RAT_Type_vals), 0,
        "lte_rrc.RAT_Type", HFILL }},
    { &hf_lte_rrc_ueCapabilitiesRAT_Container,
      { "ueCapabilitiesRAT-Container", "lte-rrc.ueCapabilitiesRAT_Container",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_24,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_24", HFILL }},
    { &hf_lte_rrc_criticalExtensions_25,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_25_vals), 0,
        "lte_rrc.T_criticalExtensions_25", HFILL }},
    { &hf_lte_rrc_c1_20,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_20_vals), 0,
        "lte_rrc.T_c1_20", HFILL }},
    { &hf_lte_rrc_ulHandoverPreparationTransfer_r8,
      { "ulHandoverPreparationTransfer-r8", "lte-rrc.ulHandoverPreparationTransfer_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ULHandoverPreparationTransfer_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_25,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_25", HFILL }},
    { &hf_lte_rrc_cdma2000_MEID,
      { "cdma2000-MEID", "lte-rrc.cdma2000_MEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_56", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_25,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_25", HFILL }},
    { &hf_lte_rrc_criticalExtensions_26,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_26_vals), 0,
        "lte_rrc.T_criticalExtensions_26", HFILL }},
    { &hf_lte_rrc_c1_21,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_21_vals), 0,
        "lte_rrc.T_c1_21", HFILL }},
    { &hf_lte_rrc_ulInformationTransfer_r8,
      { "ulInformationTransfer-r8", "lte-rrc.ulInformationTransfer_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ULInformationTransfer_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_26,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_26", HFILL }},
    { &hf_lte_rrc_informationType_01,
      { "informationType", "lte-rrc.informationType",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_informationType_01_vals), 0,
        "lte_rrc.T_informationType_01", HFILL }},
    { &hf_lte_rrc_cdma2000_01,
      { "cdma2000", "lte-rrc.cdma2000",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_cdma2000_01", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_26,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_26", HFILL }},
    { &hf_lte_rrc_accessBarringInformation,
      { "accessBarringInformation", "lte-rrc.accessBarringInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_accessBarringInformation", HFILL }},
    { &hf_lte_rrc_accessBarringForEmergencyCalls,
      { "accessBarringForEmergencyCalls", "lte-rrc.accessBarringForEmergencyCalls",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_accessBarringForSignalling,
      { "accessBarringForSignalling", "lte-rrc.accessBarringForSignalling",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.AccessClassBarringInformation", HFILL }},
    { &hf_lte_rrc_accessBarringForOriginatingCalls,
      { "accessBarringForOriginatingCalls", "lte-rrc.accessBarringForOriginatingCalls",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.AccessClassBarringInformation", HFILL }},
    { &hf_lte_rrc_radioResourceConfigCommon,
      { "radioResourceConfigCommon", "lte-rrc.radioResourceConfigCommon",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RadioResourceConfigCommonSIB", HFILL }},
    { &hf_lte_rrc_ue_TimersAndConstants,
      { "ue-TimersAndConstants", "lte-rrc.ue_TimersAndConstants",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UE_TimersAndConstants", HFILL }},
    { &hf_lte_rrc_frequencyInformation,
      { "frequencyInformation", "lte-rrc.frequencyInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_frequencyInformation", HFILL }},
    { &hf_lte_rrc_ul_EARFCN,
      { "ul-EARFCN", "lte-rrc.ul_EARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_maxEARFCN", HFILL }},
    { &hf_lte_rrc_ul_Bandwidth,
      { "ul-Bandwidth", "lte-rrc.ul_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_ul_Bandwidth_vals), 0,
        "lte_rrc.T_ul_Bandwidth", HFILL }},
    { &hf_lte_rrc_additionalSpectrumEmission,
      { "additionalSpectrumEmission", "lte-rrc.additionalSpectrumEmission",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_31", HFILL }},
    { &hf_lte_rrc_mbsfn_SubframeConfiguration,
      { "mbsfn-SubframeConfiguration", "lte-rrc.mbsfn_SubframeConfiguration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MBSFN_SubframeConfiguration", HFILL }},
    { &hf_lte_rrc_timeAlignmentTimerCommon,
      { "timeAlignmentTimerCommon", "lte-rrc.timeAlignmentTimerCommon",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_TimeAlignmentTimer_vals), 0,
        "lte_rrc.TimeAlignmentTimer", HFILL }},
    { &hf_lte_rrc_accessProbabilityFactor,
      { "accessProbabilityFactor", "lte-rrc.accessProbabilityFactor",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_accessProbabilityFactor_vals), 0,
        "lte_rrc.T_accessProbabilityFactor", HFILL }},
    { &hf_lte_rrc_accessBarringTime,
      { "accessBarringTime", "lte-rrc.accessBarringTime",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_accessBarringTime_vals), 0,
        "lte_rrc.T_accessBarringTime", HFILL }},
    { &hf_lte_rrc_accessClassBarringList,
      { "accessClassBarringList", "lte-rrc.accessClassBarringList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.AccessClassBarringList", HFILL }},
    { &hf_lte_rrc_AccessClassBarringList_item,
      { "AccessClassBarringList item", "lte-rrc.AccessClassBarringList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.AccessClassBarringList_item", HFILL }},
    { &hf_lte_rrc_accessClassBarring,
      { "accessClassBarring", "lte-rrc.accessClassBarring",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_MBSFN_SubframeConfiguration_item,
      { "MBSFN-SubframeConfiguration item", "lte-rrc.MBSFN_SubframeConfiguration_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MBSFN_SubframeConfiguration_item", HFILL }},
    { &hf_lte_rrc_radioframeAllocationPeriod,
      { "radioframeAllocationPeriod", "lte-rrc.radioframeAllocationPeriod",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_radioframeAllocationPeriod_vals), 0,
        "lte_rrc.T_radioframeAllocationPeriod", HFILL }},
    { &hf_lte_rrc_radioframeAllocationOffset,
      { "radioframeAllocationOffset", "lte-rrc.radioframeAllocationOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_subframeAllocation,
      { "subframeAllocation", "lte-rrc.subframeAllocation",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_subframeAllocation_vals), 0,
        "lte_rrc.T_subframeAllocation", HFILL }},
    { &hf_lte_rrc_oneFrame,
      { "oneFrame", "lte-rrc.oneFrame",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_6", HFILL }},
    { &hf_lte_rrc_fourFrames,
      { "fourFrames", "lte-rrc.fourFrames",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_24", HFILL }},
    { &hf_lte_rrc_cellReselectionInfoCommon,
      { "cellReselectionInfoCommon", "lte-rrc.cellReselectionInfoCommon",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_cellReselectionInfoCommon", HFILL }},
    { &hf_lte_rrc_q_Hyst,
      { "q-Hyst", "lte-rrc.q_Hyst",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_q_Hyst_vals), 0,
        "lte_rrc.T_q_Hyst", HFILL }},
    { &hf_lte_rrc_speedDependentReselection,
      { "speedDependentReselection", "lte-rrc.speedDependentReselection",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_speedDependentReselection", HFILL }},
    { &hf_lte_rrc_mobilityStateParameters,
      { "mobilityStateParameters", "lte-rrc.mobilityStateParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MobilityStateParameters", HFILL }},
    { &hf_lte_rrc_speedDependentScalingParametersHyst,
      { "speedDependentScalingParametersHyst", "lte-rrc.speedDependentScalingParametersHyst",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_speedDependentScalingParametersHyst", HFILL }},
    { &hf_lte_rrc_q_HystSF_Medium,
      { "q-HystSF-Medium", "lte-rrc.q_HystSF_Medium",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_q_HystSF_Medium_vals), 0,
        "lte_rrc.T_q_HystSF_Medium", HFILL }},
    { &hf_lte_rrc_q_HystSF_High,
      { "q-HystSF-High", "lte-rrc.q_HystSF_High",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_q_HystSF_High_vals), 0,
        "lte_rrc.T_q_HystSF_High", HFILL }},
    { &hf_lte_rrc_sameRefSignalsInNeighbour,
      { "sameRefSignalsInNeighbour", "lte-rrc.sameRefSignalsInNeighbour",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_cellReselectionServingFreqInfo,
      { "cellReselectionServingFreqInfo", "lte-rrc.cellReselectionServingFreqInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_cellReselectionServingFreqInfo", HFILL }},
    { &hf_lte_rrc_s_NonIntraSearch,
      { "s-NonIntraSearch", "lte-rrc.s_NonIntraSearch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ReselectionThreshold", HFILL }},
    { &hf_lte_rrc_threshServingLow,
      { "threshServingLow", "lte-rrc.threshServingLow",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ReselectionThreshold", HFILL }},
    { &hf_lte_rrc_intraFreqCellReselectionInfo,
      { "intraFreqCellReselectionInfo", "lte-rrc.intraFreqCellReselectionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_intraFreqCellReselectionInfo", HFILL }},
    { &hf_lte_rrc_s_IntraSearch,
      { "s-IntraSearch", "lte-rrc.s_IntraSearch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ReselectionThreshold", HFILL }},
    { &hf_lte_rrc_measurementBandwidth,
      { "measurementBandwidth", "lte-rrc.measurementBandwidth",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_MeasurementBandwidth_vals), 0,
        "lte_rrc.MeasurementBandwidth", HFILL }},
    { &hf_lte_rrc_neighbourCellConfiguration,
      { "neighbourCellConfiguration", "lte-rrc.neighbourCellConfiguration",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.NeighbourCellConfiguration", HFILL }},
    { &hf_lte_rrc_t_ReselectionEUTRAN,
      { "t-ReselectionEUTRAN", "lte-rrc.t_ReselectionEUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_speedDependentScalingParameters,
      { "speedDependentScalingParameters", "lte-rrc.speedDependentScalingParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_speedDependentScalingParameters", HFILL }},
    { &hf_lte_rrc_t_ReselectionEUTRAN_SF_Medium,
      { "t-ReselectionEUTRAN-SF-Medium", "lte-rrc.t_ReselectionEUTRAN_SF_Medium",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionEUTRAN_SF_Medium_vals), 0,
        "lte_rrc.T_t_ReselectionEUTRAN_SF_Medium", HFILL }},
    { &hf_lte_rrc_t_ReselectionEUTRAN_SF_High,
      { "t-ReselectionEUTRAN-SF-High", "lte-rrc.t_ReselectionEUTRAN_SF_High",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionEUTRAN_SF_High_vals), 0,
        "lte_rrc.T_t_ReselectionEUTRAN_SF_High", HFILL }},
    { &hf_lte_rrc_intraFreqNeighbouringCellList,
      { "intraFreqNeighbouringCellList", "lte-rrc.intraFreqNeighbouringCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.IntraFreqNeighbouringCellList", HFILL }},
    { &hf_lte_rrc_intraFreqBlacklistedCellList,
      { "intraFreqBlacklistedCellList", "lte-rrc.intraFreqBlacklistedCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.IntraFreqBlacklistedCellList", HFILL }},
    { &hf_lte_rrc_csg_PCI_Range,
      { "csg-PCI-Range", "lte-rrc.csg_PCI_Range",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_PhysicalCellIdentityAndRange_vals), 0,
        "lte_rrc.PhysicalCellIdentityAndRange", HFILL }},
    { &hf_lte_rrc_IntraFreqNeighbouringCellList_item,
      { "IntraFreqNeighbouringCellList item", "lte-rrc.IntraFreqNeighbouringCellList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.IntraFreqNeighbouringCellList_item", HFILL }},
    { &hf_lte_rrc_physicalCellIdentity,
      { "physicalCellIdentity", "lte-rrc.physicalCellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PhysicalCellIdentity", HFILL }},
    { &hf_lte_rrc_q_OffsetCell,
      { "q-OffsetCell", "lte-rrc.q_OffsetCell",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_q_OffsetCell_vals), 0,
        "lte_rrc.T_q_OffsetCell", HFILL }},
    { &hf_lte_rrc_IntraFreqBlacklistedCellList_item,
      { "IntraFreqBlacklistedCellList item", "lte-rrc.IntraFreqBlacklistedCellList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.IntraFreqBlacklistedCellList_item", HFILL }},
    { &hf_lte_rrc_physicalCellIdentityAndRange,
      { "physicalCellIdentityAndRange", "lte-rrc.physicalCellIdentityAndRange",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_PhysicalCellIdentityAndRange_vals), 0,
        "lte_rrc.PhysicalCellIdentityAndRange", HFILL }},
    { &hf_lte_rrc_interFreqCarrierFreqList,
      { "interFreqCarrierFreqList", "lte-rrc.interFreqCarrierFreqList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.InterFreqCarrierFreqList", HFILL }},
    { &hf_lte_rrc_InterFreqCarrierFreqList_item,
      { "InterFreqCarrierFreqList item", "lte-rrc.InterFreqCarrierFreqList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.InterFreqCarrierFreqList_item", HFILL }},
    { &hf_lte_rrc_speedDependentScalingParameters_01,
      { "speedDependentScalingParameters", "lte-rrc.speedDependentScalingParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_speedDependentScalingParameters_01", HFILL }},
    { &hf_lte_rrc_t_ReselectionEUTRAN_SF_Medium_01,
      { "t-ReselectionEUTRAN-SF-Medium", "lte-rrc.t_ReselectionEUTRAN_SF_Medium",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionEUTRAN_SF_Medium_01_vals), 0,
        "lte_rrc.T_t_ReselectionEUTRAN_SF_Medium_01", HFILL }},
    { &hf_lte_rrc_t_ReselectionEUTRAN_SF_High_01,
      { "t-ReselectionEUTRAN-SF-High", "lte-rrc.t_ReselectionEUTRAN_SF_High",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionEUTRAN_SF_High_01_vals), 0,
        "lte_rrc.T_t_ReselectionEUTRAN_SF_High_01", HFILL }},
    { &hf_lte_rrc_threshX_High,
      { "threshX-High", "lte-rrc.threshX_High",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ReselectionThreshold", HFILL }},
    { &hf_lte_rrc_threshX_Low,
      { "threshX-Low", "lte-rrc.threshX_Low",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ReselectionThreshold", HFILL }},
    { &hf_lte_rrc_q_OffsetFreq,
      { "q-OffsetFreq", "lte-rrc.q_OffsetFreq",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_q_OffsetFreq_vals), 0,
        "lte_rrc.T_q_OffsetFreq", HFILL }},
    { &hf_lte_rrc_interFreqNeighbouringCellList,
      { "interFreqNeighbouringCellList", "lte-rrc.interFreqNeighbouringCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.InterFreqNeighbouringCellList", HFILL }},
    { &hf_lte_rrc_interFreqBlacklistedCellList,
      { "interFreqBlacklistedCellList", "lte-rrc.interFreqBlacklistedCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.InterFreqBlacklistedCellList", HFILL }},
    { &hf_lte_rrc_InterFreqNeighbouringCellList_item,
      { "InterFreqNeighbouringCellList item", "lte-rrc.InterFreqNeighbouringCellList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.InterFreqNeighbouringCellList_item", HFILL }},
    { &hf_lte_rrc_q_OffsetCell_01,
      { "q-OffsetCell", "lte-rrc.q_OffsetCell",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_q_OffsetCell_01_vals), 0,
        "lte_rrc.T_q_OffsetCell_01", HFILL }},
    { &hf_lte_rrc_InterFreqBlacklistedCellList_item,
      { "InterFreqBlacklistedCellList item", "lte-rrc.InterFreqBlacklistedCellList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.InterFreqBlacklistedCellList_item", HFILL }},
    { &hf_lte_rrc_utra_FDD_CarrierFreqList,
      { "utra-FDD-CarrierFreqList", "lte-rrc.utra_FDD_CarrierFreqList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.UTRA_FDD_CarrierFreqList", HFILL }},
    { &hf_lte_rrc_utra_TDD_CarrierFreqList,
      { "utra-TDD-CarrierFreqList", "lte-rrc.utra_TDD_CarrierFreqList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.UTRA_TDD_CarrierFreqList", HFILL }},
    { &hf_lte_rrc_t_ReselectionUTRA,
      { "t-ReselectionUTRA", "lte-rrc.t_ReselectionUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_speedDependentScalingParameters_02,
      { "speedDependentScalingParameters", "lte-rrc.speedDependentScalingParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_speedDependentScalingParameters_02", HFILL }},
    { &hf_lte_rrc_t_ReselectionUTRA_SF_Medium,
      { "t-ReselectionUTRA-SF-Medium", "lte-rrc.t_ReselectionUTRA_SF_Medium",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionUTRA_SF_Medium_vals), 0,
        "lte_rrc.T_t_ReselectionUTRA_SF_Medium", HFILL }},
    { &hf_lte_rrc_t_ReselectionUTRA_SF_High,
      { "t-ReselectionUTRA-SF-High", "lte-rrc.t_ReselectionUTRA_SF_High",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionUTRA_SF_High_vals), 0,
        "lte_rrc.T_t_ReselectionUTRA_SF_High", HFILL }},
    { &hf_lte_rrc_UTRA_FDD_CarrierFreqList_item,
      { "UTRA-FDD-CarrierFreqList item", "lte-rrc.UTRA_FDD_CarrierFreqList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_FDD_CarrierFreqList_item", HFILL }},
    { &hf_lte_rrc_maxAllowedTxPower,
      { "maxAllowedTxPower", "lte-rrc.maxAllowedTxPower",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M50_33", HFILL }},
    { &hf_lte_rrc_q_QualMin,
      { "q-QualMin", "lte-rrc.q_QualMin",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M24_0", HFILL }},
    { &hf_lte_rrc_UTRA_TDD_CarrierFreqList_item,
      { "UTRA-TDD-CarrierFreqList item", "lte-rrc.UTRA_TDD_CarrierFreqList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_TDD_CarrierFreqList_item", HFILL }},
    { &hf_lte_rrc_t_ReselectionGERAN,
      { "t-ReselectionGERAN", "lte-rrc.t_ReselectionGERAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_speedDependentScalingParameters_03,
      { "speedDependentScalingParameters", "lte-rrc.speedDependentScalingParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_speedDependentScalingParameters_03", HFILL }},
    { &hf_lte_rrc_t_ReselectionGERAN_SF_Medium,
      { "t-ReselectionGERAN-SF-Medium", "lte-rrc.t_ReselectionGERAN_SF_Medium",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionGERAN_SF_Medium_vals), 0,
        "lte_rrc.T_t_ReselectionGERAN_SF_Medium", HFILL }},
    { &hf_lte_rrc_t_ReselectionGERAN_SF_High,
      { "t-ReselectionGERAN-SF-High", "lte-rrc.t_ReselectionGERAN_SF_High",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionGERAN_SF_High_vals), 0,
        "lte_rrc.T_t_ReselectionGERAN_SF_High", HFILL }},
    { &hf_lte_rrc_geran_NeigbourFreqList,
      { "geran-NeigbourFreqList", "lte-rrc.geran_NeigbourFreqList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.GERAN_NeigbourFreqList", HFILL }},
    { &hf_lte_rrc_GERAN_NeigbourFreqList_item,
      { "GERAN-BCCH-Group", "lte-rrc.GERAN_BCCH_Group",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GERAN_BCCH_Group", HFILL }},
    { &hf_lte_rrc_geran_BCCH_Configuration,
      { "geran-BCCH-Configuration", "lte-rrc.geran_BCCH_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_geran_BCCH_Configuration", HFILL }},
    { &hf_lte_rrc_ncc_Permitted,
      { "ncc-Permitted", "lte-rrc.ncc_Permitted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_8", HFILL }},
    { &hf_lte_rrc_q_RxLevMin_01,
      { "q-RxLevMin", "lte-rrc.q_RxLevMin",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_31", HFILL }},
    { &hf_lte_rrc_p_MaxGERAN,
      { "p-MaxGERAN", "lte-rrc.p_MaxGERAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_39", HFILL }},
    { &hf_lte_rrc_cdma2000_SystemTimeInfo,
      { "cdma2000-SystemTimeInfo", "lte-rrc.cdma2000_SystemTimeInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_SystemTimeInfo", HFILL }},
    { &hf_lte_rrc_searchWindowSize,
      { "searchWindowSize", "lte-rrc.searchWindowSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_15", HFILL }},
    { &hf_lte_rrc_hrpd_Parameters,
      { "hrpd-Parameters", "lte-rrc.hrpd_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_hrpd_Parameters", HFILL }},
    { &hf_lte_rrc_hrpd_PreRegistrationInfo,
      { "hrpd-PreRegistrationInfo", "lte-rrc.hrpd_PreRegistrationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.HRPD_PreRegistrationInfo", HFILL }},
    { &hf_lte_rrc_hrpd_CellReselectionParameters,
      { "hrpd-CellReselectionParameters", "lte-rrc.hrpd_CellReselectionParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_hrpd_CellReselectionParameters", HFILL }},
    { &hf_lte_rrc_hrpd_BandClassList,
      { "hrpd-BandClassList", "lte-rrc.hrpd_BandClassList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.HRPD_BandClassList", HFILL }},
    { &hf_lte_rrc_hrpd_NeighborCellList,
      { "hrpd-NeighborCellList", "lte-rrc.hrpd_NeighborCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CDMA2000_NeighbourCellList", HFILL }},
    { &hf_lte_rrc_t_ReselectionCDMA_HRPD,
      { "t-ReselectionCDMA-HRPD", "lte-rrc.t_ReselectionCDMA_HRPD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_speedDependentScalingParameters_04,
      { "speedDependentScalingParameters", "lte-rrc.speedDependentScalingParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_speedDependentScalingParameters_04", HFILL }},
    { &hf_lte_rrc_t_ReselectionCDMA_HRPD_SF_Medium,
      { "t-ReselectionCDMA-HRPD-SF-Medium", "lte-rrc.t_ReselectionCDMA_HRPD_SF_Medium",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionCDMA_HRPD_SF_Medium_vals), 0,
        "lte_rrc.T_t_ReselectionCDMA_HRPD_SF_Medium", HFILL }},
    { &hf_lte_rrc_t_ReselectionCDMA_HRPD_SF_High,
      { "t-ReselectionCDMA-HRPD-SF-High", "lte-rrc.t_ReselectionCDMA_HRPD_SF_High",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionCDMA_HRPD_SF_High_vals), 0,
        "lte_rrc.T_t_ReselectionCDMA_HRPD_SF_High", HFILL }},
    { &hf_lte_rrc_oneXRTT_Parameters,
      { "oneXRTT-Parameters", "lte-rrc.oneXRTT_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_oneXRTT_Parameters", HFILL }},
    { &hf_lte_rrc_oneXRTT_CSFB_RegistrationInfo,
      { "oneXRTT-CSFB-RegistrationInfo", "lte-rrc.oneXRTT_CSFB_RegistrationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.OneXRTT_CSFB_RegistrationInfo", HFILL }},
    { &hf_lte_rrc_oneXRTT_LongCodeState,
      { "oneXRTT-LongCodeState", "lte-rrc.oneXRTT_LongCodeState",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_42", HFILL }},
    { &hf_lte_rrc_oneXRTT_CellReselectionParameters,
      { "oneXRTT-CellReselectionParameters", "lte-rrc.oneXRTT_CellReselectionParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_oneXRTT_CellReselectionParameters", HFILL }},
    { &hf_lte_rrc_oneXRTT_BandClassList,
      { "oneXRTT-BandClassList", "lte-rrc.oneXRTT_BandClassList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.OneXRTT_BandClassList", HFILL }},
    { &hf_lte_rrc_oneXRTT_NeighborCellList,
      { "oneXRTT-NeighborCellList", "lte-rrc.oneXRTT_NeighborCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CDMA2000_NeighbourCellList", HFILL }},
    { &hf_lte_rrc_t_ReselectionCDMA_OneXRTT,
      { "t-ReselectionCDMA-OneXRTT", "lte-rrc.t_ReselectionCDMA_OneXRTT",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_speedDependentScalingParameters_05,
      { "speedDependentScalingParameters", "lte-rrc.speedDependentScalingParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_speedDependentScalingParameters_05", HFILL }},
    { &hf_lte_rrc_t_ReselectionCDMA_OneXRTT_SF_Medium,
      { "t-ReselectionCDMA-OneXRTT-SF-Medium", "lte-rrc.t_ReselectionCDMA_OneXRTT_SF_Medium",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionCDMA_OneXRTT_SF_Medium_vals), 0,
        "lte_rrc.T_t_ReselectionCDMA_OneXRTT_SF_Medium", HFILL }},
    { &hf_lte_rrc_t_ReselectionCDMA_OneXRTT_SF_High,
      { "t-ReselectionCDMA-OneXRTT-SF-High", "lte-rrc.t_ReselectionCDMA_OneXRTT_SF_High",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_ReselectionCDMA_OneXRTT_SF_High_vals), 0,
        "lte_rrc.T_t_ReselectionCDMA_OneXRTT_SF_High", HFILL }},
    { &hf_lte_rrc_CDMA2000_NeighbourCellList_item,
      { "CDMA2000-NeighbourCellList item", "lte-rrc.CDMA2000_NeighbourCellList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_NeighbourCellList_item", HFILL }},
    { &hf_lte_rrc_bandClass,
      { "bandClass", "lte-rrc.bandClass",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_CDMA2000_Bandclass_vals), 0,
        "lte_rrc.CDMA2000_Bandclass", HFILL }},
    { &hf_lte_rrc_frequencyList,
      { "frequencyList", "lte-rrc.frequencyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CDMA2000_NeighbourCellsPerBandclass", HFILL }},
    { &hf_lte_rrc_CDMA2000_NeighbourCellsPerBandclass_item,
      { "CDMA2000-NeighbourCellsPerBandclass item", "lte-rrc.CDMA2000_NeighbourCellsPerBandclass_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_NeighbourCellsPerBandclass_item", HFILL }},
    { &hf_lte_rrc_frequency,
      { "frequency", "lte-rrc.frequency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_2047", HFILL }},
    { &hf_lte_rrc_cellIdList,
      { "cellIdList", "lte-rrc.cellIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CDMA2000_CellIdList", HFILL }},
    { &hf_lte_rrc_CDMA2000_CellIdList_item,
      { "CDMA2000-CellIdentity", "lte-rrc.CDMA2000_CellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CDMA2000_CellIdentity", HFILL }},
    { &hf_lte_rrc_HRPD_BandClassList_item,
      { "HRPD-BandClassList item", "lte-rrc.HRPD_BandClassList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.HRPD_BandClassList_item", HFILL }},
    { &hf_lte_rrc_hrpd_BandClass,
      { "hrpd-BandClass", "lte-rrc.hrpd_BandClass",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_CDMA2000_Bandclass_vals), 0,
        "lte_rrc.CDMA2000_Bandclass", HFILL }},
    { &hf_lte_rrc_threshX_High_01,
      { "threshX-High", "lte-rrc.threshX_High",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_63", HFILL }},
    { &hf_lte_rrc_threshX_Low_01,
      { "threshX-Low", "lte-rrc.threshX_Low",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_63", HFILL }},
    { &hf_lte_rrc_OneXRTT_BandClassList_item,
      { "OneXRTT-BandClassList item", "lte-rrc.OneXRTT_BandClassList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.OneXRTT_BandClassList_item", HFILL }},
    { &hf_lte_rrc_oneXRTT_BandClass,
      { "oneXRTT-BandClass", "lte-rrc.oneXRTT_BandClass",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_CDMA2000_Bandclass_vals), 0,
        "lte_rrc.CDMA2000_Bandclass", HFILL }},
    { &hf_lte_rrc_hnbid,
      { "hnbid", "lte-rrc.hnbid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING_SIZE_1_48", HFILL }},
    { &hf_lte_rrc_messageIdentifier,
      { "messageIdentifier", "lte-rrc.messageIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_16", HFILL }},
    { &hf_lte_rrc_serialNumber,
      { "serialNumber", "lte-rrc.serialNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_16", HFILL }},
    { &hf_lte_rrc_warningType,
      { "warningType", "lte-rrc.warningType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING_SIZE_2", HFILL }},
    { &hf_lte_rrc_warningSecurityInformation,
      { "warningSecurityInformation", "lte-rrc.warningSecurityInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING_SIZE_50", HFILL }},
    { &hf_lte_rrc_warningMessageSegmentType,
      { "warningMessageSegmentType", "lte-rrc.warningMessageSegmentType",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_warningMessageSegmentType_vals), 0,
        "lte_rrc.T_warningMessageSegmentType", HFILL }},
    { &hf_lte_rrc_warningMessageSegmentNumber,
      { "warningMessageSegmentNumber", "lte-rrc.warningMessageSegmentNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_63", HFILL }},
    { &hf_lte_rrc_warningMessageSegment,
      { "warningMessageSegment", "lte-rrc.warningMessageSegment",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING", HFILL }},
    { &hf_lte_rrc_dataCodingScheme,
      { "dataCodingScheme", "lte-rrc.dataCodingScheme",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING_SIZE_1", HFILL }},
    { &hf_lte_rrc_antennaPortsCount,
      { "antennaPortsCount", "lte-rrc.antennaPortsCount",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_antennaPortsCount_vals), 0,
        "lte_rrc.T_antennaPortsCount", HFILL }},
    { &hf_lte_rrc_transmissionMode,
      { "transmissionMode", "lte-rrc.transmissionMode",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_transmissionMode_vals), 0,
        "lte_rrc.T_transmissionMode", HFILL }},
    { &hf_lte_rrc_codebookSubsetRestriction,
      { "codebookSubsetRestriction", "lte-rrc.codebookSubsetRestriction",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_codebookSubsetRestriction_vals), 0,
        "lte_rrc.T_codebookSubsetRestriction", HFILL }},
    { &hf_lte_rrc_n2TxAntenna_tm3,
      { "n2TxAntenna-tm3", "lte-rrc.n2TxAntenna_tm3",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_2", HFILL }},
    { &hf_lte_rrc_n4TxAntenna_tm3,
      { "n4TxAntenna-tm3", "lte-rrc.n4TxAntenna_tm3",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_4", HFILL }},
    { &hf_lte_rrc_n2TxAntenna_tm4,
      { "n2TxAntenna-tm4", "lte-rrc.n2TxAntenna_tm4",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_6", HFILL }},
    { &hf_lte_rrc_n4TxAntenna_tm4,
      { "n4TxAntenna-tm4", "lte-rrc.n4TxAntenna_tm4",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_64", HFILL }},
    { &hf_lte_rrc_n2TxAntenna_tm5,
      { "n2TxAntenna-tm5", "lte-rrc.n2TxAntenna_tm5",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_4", HFILL }},
    { &hf_lte_rrc_n4TxAntenna_tm5,
      { "n4TxAntenna-tm5", "lte-rrc.n4TxAntenna_tm5",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_16", HFILL }},
    { &hf_lte_rrc_n2TxAntenna_tm6,
      { "n2TxAntenna-tm6", "lte-rrc.n2TxAntenna_tm6",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_4", HFILL }},
    { &hf_lte_rrc_n4TxAntenna_tm6,
      { "n4TxAntenna-tm6", "lte-rrc.n4TxAntenna_tm6",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_16", HFILL }},
    { &hf_lte_rrc_ue_TransmitAntennaSelection,
      { "ue-TransmitAntennaSelection", "lte-rrc.ue_TransmitAntennaSelection",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_ue_TransmitAntennaSelection_vals), 0,
        "lte_rrc.T_ue_TransmitAntennaSelection", HFILL }},
    { &hf_lte_rrc_disable,
      { "disable", "lte-rrc.disable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_enable,
      { "enable", "lte-rrc.enable",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_enable_vals), 0,
        "lte_rrc.T_enable", HFILL }},
    { &hf_lte_rrc_cqi_ReportingModeAperiodic,
      { "cqi-ReportingModeAperiodic", "lte-rrc.cqi_ReportingModeAperiodic",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cqi_ReportingModeAperiodic_vals), 0,
        "lte_rrc.T_cqi_ReportingModeAperiodic", HFILL }},
    { &hf_lte_rrc_nomPDSCH_RS_EPRE_Offset,
      { "nomPDSCH-RS-EPRE-Offset", "lte-rrc.nomPDSCH_RS_EPRE_Offset",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M1_6", HFILL }},
    { &hf_lte_rrc_cqi_ReportingPeriodic,
      { "cqi-ReportingPeriodic", "lte-rrc.cqi_ReportingPeriodic",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_CQI_ReportingPeriodic_vals), 0,
        "lte_rrc.CQI_ReportingPeriodic", HFILL }},
    { &hf_lte_rrc_enable_01,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_01", HFILL }},
    { &hf_lte_rrc_cqi_PUCCH_ResourceIndex,
      { "cqi-PUCCH-ResourceIndex", "lte-rrc.cqi_PUCCH_ResourceIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_767", HFILL }},
    { &hf_lte_rrc_cqi_pmi_ConfigIndex,
      { "cqi-pmi-ConfigIndex", "lte-rrc.cqi_pmi_ConfigIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_511", HFILL }},
    { &hf_lte_rrc_cqi_FormatIndicatorPeriodic,
      { "cqi-FormatIndicatorPeriodic", "lte-rrc.cqi_FormatIndicatorPeriodic",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cqi_FormatIndicatorPeriodic_vals), 0,
        "lte_rrc.T_cqi_FormatIndicatorPeriodic", HFILL }},
    { &hf_lte_rrc_widebandCQI,
      { "widebandCQI", "lte-rrc.widebandCQI",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_subbandCQI,
      { "subbandCQI", "lte-rrc.subbandCQI",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_subbandCQI", HFILL }},
    { &hf_lte_rrc_k,
      { "k", "lte-rrc.k",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_4", HFILL }},
    { &hf_lte_rrc_ri_ConfigIndex,
      { "ri-ConfigIndex", "lte-rrc.ri_ConfigIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_1023", HFILL }},
    { &hf_lte_rrc_simultaneousAckNackAndCQI,
      { "simultaneousAckNackAndCQI", "lte-rrc.simultaneousAckNackAndCQI",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_ul_SpecificParameters,
      { "ul-SpecificParameters", "lte-rrc.ul_SpecificParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_ul_SpecificParameters", HFILL }},
    { &hf_lte_rrc_priority,
      { "priority", "lte-rrc.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_16", HFILL }},
    { &hf_lte_rrc_prioritizedBitRate,
      { "prioritizedBitRate", "lte-rrc.prioritizedBitRate",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_prioritizedBitRate_vals), 0,
        "lte_rrc.T_prioritizedBitRate", HFILL }},
    { &hf_lte_rrc_bucketSizeDuration,
      { "bucketSizeDuration", "lte-rrc.bucketSizeDuration",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_bucketSizeDuration_vals), 0,
        "lte_rrc.T_bucketSizeDuration", HFILL }},
    { &hf_lte_rrc_logicalChannelGroup,
      { "logicalChannelGroup", "lte-rrc.logicalChannelGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_3", HFILL }},
    { &hf_lte_rrc_dl_SCH_Configuration,
      { "dl-SCH-Configuration", "lte-rrc.dl_SCH_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_dl_SCH_Configuration", HFILL }},
    { &hf_lte_rrc_ul_SCH_Configuration,
      { "ul-SCH-Configuration", "lte-rrc.ul_SCH_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_ul_SCH_Configuration", HFILL }},
    { &hf_lte_rrc_maxHARQ_Tx,
      { "maxHARQ-Tx", "lte-rrc.maxHARQ_Tx",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_maxHARQ_Tx_vals), 0,
        "lte_rrc.T_maxHARQ_Tx", HFILL }},
    { &hf_lte_rrc_periodicBSR_Timer,
      { "periodicBSR-Timer", "lte-rrc.periodicBSR_Timer",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_periodicBSR_Timer_vals), 0,
        "lte_rrc.T_periodicBSR_Timer", HFILL }},
    { &hf_lte_rrc_retxBSR_Timer,
      { "retxBSR-Timer", "lte-rrc.retxBSR_Timer",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_retxBSR_Timer_vals), 0,
        "lte_rrc.T_retxBSR_Timer", HFILL }},
    { &hf_lte_rrc_ttiBundling,
      { "ttiBundling", "lte-rrc.ttiBundling",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_drx_Configuration,
      { "drx-Configuration", "lte-rrc.drx_Configuration",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_drx_Configuration_vals), 0,
        "lte_rrc.T_drx_Configuration", HFILL }},
    { &hf_lte_rrc_enable_02,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_02", HFILL }},
    { &hf_lte_rrc_onDurationTimer,
      { "onDurationTimer", "lte-rrc.onDurationTimer",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_onDurationTimer_vals), 0,
        "lte_rrc.T_onDurationTimer", HFILL }},
    { &hf_lte_rrc_drx_InactivityTimer,
      { "drx-InactivityTimer", "lte-rrc.drx_InactivityTimer",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_drx_InactivityTimer_vals), 0,
        "lte_rrc.T_drx_InactivityTimer", HFILL }},
    { &hf_lte_rrc_drx_RetransmissionTimer,
      { "drx-RetransmissionTimer", "lte-rrc.drx_RetransmissionTimer",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_drx_RetransmissionTimer_vals), 0,
        "lte_rrc.T_drx_RetransmissionTimer", HFILL }},
    { &hf_lte_rrc_longDRX_CycleStartOffset,
      { "longDRX-CycleStartOffset", "lte-rrc.longDRX_CycleStartOffset",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_longDRX_CycleStartOffset_vals), 0,
        "lte_rrc.T_longDRX_CycleStartOffset", HFILL }},
    { &hf_lte_rrc_sf10,
      { "sf10", "lte-rrc.sf10",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_9", HFILL }},
    { &hf_lte_rrc_sf20,
      { "sf20", "lte-rrc.sf20",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_19", HFILL }},
    { &hf_lte_rrc_sf32,
      { "sf32", "lte-rrc.sf32",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_31", HFILL }},
    { &hf_lte_rrc_sf40,
      { "sf40", "lte-rrc.sf40",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_39", HFILL }},
    { &hf_lte_rrc_sf64,
      { "sf64", "lte-rrc.sf64",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_63", HFILL }},
    { &hf_lte_rrc_sf80,
      { "sf80", "lte-rrc.sf80",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_79", HFILL }},
    { &hf_lte_rrc_sf128,
      { "sf128", "lte-rrc.sf128",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_127", HFILL }},
    { &hf_lte_rrc_sf160,
      { "sf160", "lte-rrc.sf160",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_159", HFILL }},
    { &hf_lte_rrc_sf256,
      { "sf256", "lte-rrc.sf256",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_255", HFILL }},
    { &hf_lte_rrc_sf320,
      { "sf320", "lte-rrc.sf320",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_319", HFILL }},
    { &hf_lte_rrc_sf512,
      { "sf512", "lte-rrc.sf512",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_511", HFILL }},
    { &hf_lte_rrc_sf640,
      { "sf640", "lte-rrc.sf640",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_639", HFILL }},
    { &hf_lte_rrc_sf1024,
      { "sf1024", "lte-rrc.sf1024",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_1023", HFILL }},
    { &hf_lte_rrc_sf1280,
      { "sf1280", "lte-rrc.sf1280",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_1279", HFILL }},
    { &hf_lte_rrc_sf2048,
      { "sf2048", "lte-rrc.sf2048",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_2047", HFILL }},
    { &hf_lte_rrc_sf2560,
      { "sf2560", "lte-rrc.sf2560",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_2559", HFILL }},
    { &hf_lte_rrc_shortDRX,
      { "shortDRX", "lte-rrc.shortDRX",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_shortDRX_vals), 0,
        "lte_rrc.T_shortDRX", HFILL }},
    { &hf_lte_rrc_enable_03,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_03", HFILL }},
    { &hf_lte_rrc_shortDRX_Cycle,
      { "shortDRX-Cycle", "lte-rrc.shortDRX_Cycle",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_shortDRX_Cycle_vals), 0,
        "lte_rrc.T_shortDRX_Cycle", HFILL }},
    { &hf_lte_rrc_drxShortCycleTimer,
      { "drxShortCycleTimer", "lte-rrc.drxShortCycleTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_16", HFILL }},
    { &hf_lte_rrc_timeAlignmentTimerDedicated,
      { "timeAlignmentTimerDedicated", "lte-rrc.timeAlignmentTimerDedicated",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_TimeAlignmentTimer_vals), 0,
        "lte_rrc.TimeAlignmentTimer", HFILL }},
    { &hf_lte_rrc_phr_Configuration,
      { "phr-Configuration", "lte-rrc.phr_Configuration",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_phr_Configuration_vals), 0,
        "lte_rrc.T_phr_Configuration", HFILL }},
    { &hf_lte_rrc_enable_04,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_04", HFILL }},
    { &hf_lte_rrc_periodicPHR_Timer,
      { "periodicPHR-Timer", "lte-rrc.periodicPHR_Timer",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_periodicPHR_Timer_vals), 0,
        "lte_rrc.T_periodicPHR_Timer", HFILL }},
    { &hf_lte_rrc_prohibitPHR_Timer,
      { "prohibitPHR-Timer", "lte-rrc.prohibitPHR_Timer",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_prohibitPHR_Timer_vals), 0,
        "lte_rrc.T_prohibitPHR_Timer", HFILL }},
    { &hf_lte_rrc_dl_PathlossChange,
      { "dl-PathlossChange", "lte-rrc.dl_PathlossChange",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_dl_PathlossChange_vals), 0,
        "lte_rrc.T_dl_PathlossChange", HFILL }},
    { &hf_lte_rrc_discardTimer,
      { "discardTimer", "lte-rrc.discardTimer",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_discardTimer_vals), 0,
        "lte_rrc.T_discardTimer", HFILL }},
    { &hf_lte_rrc_rlc_AM,
      { "rlc-AM", "lte-rrc.rlc_AM",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_rlc_AM", HFILL }},
    { &hf_lte_rrc_statusReportRequired,
      { "statusReportRequired", "lte-rrc.statusReportRequired",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_rlc_UM,
      { "rlc-UM", "lte-rrc.rlc_UM",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_rlc_UM", HFILL }},
    { &hf_lte_rrc_pdcp_SN_Size,
      { "pdcp-SN-Size", "lte-rrc.pdcp_SN_Size",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_pdcp_SN_Size_vals), 0,
        "lte_rrc.T_pdcp_SN_Size", HFILL }},
    { &hf_lte_rrc_headerCompression,
      { "headerCompression", "lte-rrc.headerCompression",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_headerCompression_vals), 0,
        "lte_rrc.T_headerCompression", HFILL }},
    { &hf_lte_rrc_notUsed,
      { "notUsed", "lte-rrc.notUsed",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_rohc,
      { "rohc", "lte-rrc.rohc",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_rohc", HFILL }},
    { &hf_lte_rrc_maxCID,
      { "maxCID", "lte-rrc.maxCID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_16383", HFILL }},
    { &hf_lte_rrc_profiles,
      { "profiles", "lte-rrc.profiles",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_profiles", HFILL }},
    { &hf_lte_rrc_profile0x0001,
      { "profile0x0001", "lte-rrc.profile0x0001",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_profile0x0002,
      { "profile0x0002", "lte-rrc.profile0x0002",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_profile0x0003,
      { "profile0x0003", "lte-rrc.profile0x0003",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_profile0x0004,
      { "profile0x0004", "lte-rrc.profile0x0004",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_profile0x0006,
      { "profile0x0006", "lte-rrc.profile0x0006",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_profile0x0101,
      { "profile0x0101", "lte-rrc.profile0x0101",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_profile0x0102,
      { "profile0x0102", "lte-rrc.profile0x0102",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_profile0x0103,
      { "profile0x0103", "lte-rrc.profile0x0103",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_profile0x0104,
      { "profile0x0104", "lte-rrc.profile0x0104",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_referenceSignalPower,
      { "referenceSignalPower", "lte-rrc.referenceSignalPower",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M60_50", HFILL }},
    { &hf_lte_rrc_p_b,
      { "p-b", "lte-rrc.p_b",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_p_b_vals), 0,
        "lte_rrc.T_p_b", HFILL }},
    { &hf_lte_rrc_p_a,
      { "p-a", "lte-rrc.p_a",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_p_a_vals), 0,
        "lte_rrc.T_p_a", HFILL }},
    { &hf_lte_rrc_phich_Duration,
      { "phich-Duration", "lte-rrc.phich_Duration",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_phich_Duration_vals), 0,
        "lte_rrc.T_phich_Duration", HFILL }},
    { &hf_lte_rrc_phich_Resource,
      { "phich-Resource", "lte-rrc.phich_Resource",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_phich_Resource_vals), 0,
        "lte_rrc.T_phich_Resource", HFILL }},
    { &hf_lte_rrc_pdsch_Configuration,
      { "pdsch-Configuration", "lte-rrc.pdsch_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PDSCH_ConfigDedicated", HFILL }},
    { &hf_lte_rrc_pucch_Configuration,
      { "pucch-Configuration", "lte-rrc.pucch_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PUCCH_ConfigDedicated", HFILL }},
    { &hf_lte_rrc_pusch_Configuration,
      { "pusch-Configuration", "lte-rrc.pusch_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PUSCH_ConfigDedicated", HFILL }},
    { &hf_lte_rrc_uplinkPowerControl,
      { "uplinkPowerControl", "lte-rrc.uplinkPowerControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UplinkPowerControlDedicated", HFILL }},
    { &hf_lte_rrc_tpc_PDCCH_ConfigPUCCH,
      { "tpc-PDCCH-ConfigPUCCH", "lte-rrc.tpc_PDCCH_ConfigPUCCH",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_TPC_PDCCH_Configuration_vals), 0,
        "lte_rrc.TPC_PDCCH_Configuration", HFILL }},
    { &hf_lte_rrc_tpc_PDCCH_ConfigPUSCH,
      { "tpc-PDCCH-ConfigPUSCH", "lte-rrc.tpc_PDCCH_ConfigPUSCH",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_TPC_PDCCH_Configuration_vals), 0,
        "lte_rrc.TPC_PDCCH_Configuration", HFILL }},
    { &hf_lte_rrc_cqi_Reporting,
      { "cqi-Reporting", "lte-rrc.cqi_Reporting",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CQI_Reporting", HFILL }},
    { &hf_lte_rrc_soundingRsUl_Config,
      { "soundingRsUl-Config", "lte-rrc.soundingRsUl_Config",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_SoundingRsUl_ConfigDedicated_vals), 0,
        "lte_rrc.SoundingRsUl_ConfigDedicated", HFILL }},
    { &hf_lte_rrc_antennaInformation,
      { "antennaInformation", "lte-rrc.antennaInformation",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_antennaInformation_vals), 0,
        "lte_rrc.T_antennaInformation", HFILL }},
    { &hf_lte_rrc_explicitValue,
      { "explicitValue", "lte-rrc.explicitValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.AntennaInformationDedicated", HFILL }},
    { &hf_lte_rrc_defaultValue,
      { "defaultValue", "lte-rrc.defaultValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_schedulingRequestConfig,
      { "schedulingRequestConfig", "lte-rrc.schedulingRequestConfig",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_SchedulingRequest_Configuration_vals), 0,
        "lte_rrc.SchedulingRequest_Configuration", HFILL }},
    { &hf_lte_rrc_rootSequenceIndex,
      { "rootSequenceIndex", "lte-rrc.rootSequenceIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_837", HFILL }},
    { &hf_lte_rrc_prach_ConfigInfo,
      { "prach-ConfigInfo", "lte-rrc.prach_ConfigInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PRACH_ConfigInfo", HFILL }},
    { &hf_lte_rrc_prach_ConfigurationIndex,
      { "prach-ConfigurationIndex", "lte-rrc.prach_ConfigurationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_63", HFILL }},
    { &hf_lte_rrc_highSpeedFlag,
      { "highSpeedFlag", "lte-rrc.highSpeedFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_zeroCorrelationZoneConfig,
      { "zeroCorrelationZoneConfig", "lte-rrc.zeroCorrelationZoneConfig",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_15", HFILL }},
    { &hf_lte_rrc_prach_FrequencyOffset,
      { "prach-FrequencyOffset", "lte-rrc.prach_FrequencyOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_104", HFILL }},
    { &hf_lte_rrc_deltaPUCCH_Shift,
      { "deltaPUCCH-Shift", "lte-rrc.deltaPUCCH_Shift",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_deltaPUCCH_Shift_vals), 0,
        "lte_rrc.T_deltaPUCCH_Shift", HFILL }},
    { &hf_lte_rrc_nRB_CQI,
      { "nRB-CQI", "lte-rrc.nRB_CQI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_63", HFILL }},
    { &hf_lte_rrc_nCS_AN,
      { "nCS-AN", "lte-rrc.nCS_AN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_n1PUCCH_AN,
      { "n1PUCCH-AN", "lte-rrc.n1PUCCH_AN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_2047", HFILL }},
    { &hf_lte_rrc_ackNackRepetition,
      { "ackNackRepetition", "lte-rrc.ackNackRepetition",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_ackNackRepetition_vals), 0,
        "lte_rrc.T_ackNackRepetition", HFILL }},
    { &hf_lte_rrc_enable_05,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_05", HFILL }},
    { &hf_lte_rrc_repetitionFactor,
      { "repetitionFactor", "lte-rrc.repetitionFactor",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_repetitionFactor_vals), 0,
        "lte_rrc.T_repetitionFactor", HFILL }},
    { &hf_lte_rrc_tddAckNackFeedbackMode,
      { "tddAckNackFeedbackMode", "lte-rrc.tddAckNackFeedbackMode",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_tddAckNackFeedbackMode_vals), 0,
        "lte_rrc.T_tddAckNackFeedbackMode", HFILL }},
    { &hf_lte_rrc_pusch_ConfigBasic,
      { "pusch-ConfigBasic", "lte-rrc.pusch_ConfigBasic",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_pusch_ConfigBasic", HFILL }},
    { &hf_lte_rrc_n_SB,
      { "n-SB", "lte-rrc.n_SB",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_n_SB_vals), 0,
        "lte_rrc.T_n_SB", HFILL }},
    { &hf_lte_rrc_hoppingMode,
      { "hoppingMode", "lte-rrc.hoppingMode",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_hoppingMode_vals), 0,
        "lte_rrc.T_hoppingMode", HFILL }},
    { &hf_lte_rrc_pusch_HoppingOffset,
      { "pusch-HoppingOffset", "lte-rrc.pusch_HoppingOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_63", HFILL }},
    { &hf_lte_rrc_enable64Qam,
      { "enable64Qam", "lte-rrc.enable64Qam",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_ul_ReferenceSignalsPUSCH,
      { "ul-ReferenceSignalsPUSCH", "lte-rrc.ul_ReferenceSignalsPUSCH",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UL_ReferenceSignalsPUSCH", HFILL }},
    { &hf_lte_rrc_deltaOffset_ACK_Index,
      { "deltaOffset-ACK-Index", "lte-rrc.deltaOffset_ACK_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_15", HFILL }},
    { &hf_lte_rrc_deltaOffset_RI_Index,
      { "deltaOffset-RI-Index", "lte-rrc.deltaOffset_RI_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_15", HFILL }},
    { &hf_lte_rrc_deltaOffset_CQI_Index,
      { "deltaOffset-CQI-Index", "lte-rrc.deltaOffset_CQI_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_15", HFILL }},
    { &hf_lte_rrc_ra_PreambleIndex,
      { "ra-PreambleIndex", "lte-rrc.ra_PreambleIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_64", HFILL }},
    { &hf_lte_rrc_ra_PRACH_MaskIndex,
      { "ra-PRACH-MaskIndex", "lte-rrc.ra_PRACH_MaskIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_15", HFILL }},
    { &hf_lte_rrc_preambleInformation,
      { "preambleInformation", "lte-rrc.preambleInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_preambleInformation", HFILL }},
    { &hf_lte_rrc_numberOfRA_Preambles,
      { "numberOfRA-Preambles", "lte-rrc.numberOfRA_Preambles",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_numberOfRA_Preambles_vals), 0,
        "lte_rrc.T_numberOfRA_Preambles", HFILL }},
    { &hf_lte_rrc_preamblesGroupAConfig,
      { "preamblesGroupAConfig", "lte-rrc.preamblesGroupAConfig",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_preamblesGroupAConfig", HFILL }},
    { &hf_lte_rrc_sizeOfRA_PreamblesGroupA,
      { "sizeOfRA-PreamblesGroupA", "lte-rrc.sizeOfRA_PreamblesGroupA",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_sizeOfRA_PreamblesGroupA_vals), 0,
        "lte_rrc.T_sizeOfRA_PreamblesGroupA", HFILL }},
    { &hf_lte_rrc_messageSizeGroupA,
      { "messageSizeGroupA", "lte-rrc.messageSizeGroupA",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_messageSizeGroupA_vals), 0,
        "lte_rrc.T_messageSizeGroupA", HFILL }},
    { &hf_lte_rrc_messagePowerOffsetGroupB,
      { "messagePowerOffsetGroupB", "lte-rrc.messagePowerOffsetGroupB",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_messagePowerOffsetGroupB_vals), 0,
        "lte_rrc.T_messagePowerOffsetGroupB", HFILL }},
    { &hf_lte_rrc_powerRampingParameters,
      { "powerRampingParameters", "lte-rrc.powerRampingParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_powerRampingParameters", HFILL }},
    { &hf_lte_rrc_powerRampingStep,
      { "powerRampingStep", "lte-rrc.powerRampingStep",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_powerRampingStep_vals), 0,
        "lte_rrc.T_powerRampingStep", HFILL }},
    { &hf_lte_rrc_preambleInitialReceivedTargetPower,
      { "preambleInitialReceivedTargetPower", "lte-rrc.preambleInitialReceivedTargetPower",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_preambleInitialReceivedTargetPower_vals), 0,
        "lte_rrc.T_preambleInitialReceivedTargetPower", HFILL }},
    { &hf_lte_rrc_ra_SupervisionInformation,
      { "ra-SupervisionInformation", "lte-rrc.ra_SupervisionInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_ra_SupervisionInformation", HFILL }},
    { &hf_lte_rrc_preambleTransMax,
      { "preambleTransMax", "lte-rrc.preambleTransMax",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_preambleTransMax_vals), 0,
        "lte_rrc.T_preambleTransMax", HFILL }},
    { &hf_lte_rrc_ra_ResponseWindowSize,
      { "ra-ResponseWindowSize", "lte-rrc.ra_ResponseWindowSize",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_ra_ResponseWindowSize_vals), 0,
        "lte_rrc.T_ra_ResponseWindowSize", HFILL }},
    { &hf_lte_rrc_mac_ContentionResolutionTimer,
      { "mac-ContentionResolutionTimer", "lte-rrc.mac_ContentionResolutionTimer",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_mac_ContentionResolutionTimer_vals), 0,
        "lte_rrc.T_mac_ContentionResolutionTimer", HFILL }},
    { &hf_lte_rrc_maxHARQ_Msg3Tx,
      { "maxHARQ-Msg3Tx", "lte-rrc.maxHARQ_Msg3Tx",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_8", HFILL }},
    { &hf_lte_rrc_rach_Configuration,
      { "rach-Configuration", "lte-rrc.rach_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RACH_ConfigCommon", HFILL }},
    { &hf_lte_rrc_bcch_Configuration,
      { "bcch-Configuration", "lte-rrc.bcch_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.BCCH_Configuration", HFILL }},
    { &hf_lte_rrc_pcch_Configuration,
      { "pcch-Configuration", "lte-rrc.pcch_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PCCH_Configuration", HFILL }},
    { &hf_lte_rrc_prach_Configuration,
      { "prach-Configuration", "lte-rrc.prach_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PRACH_ConfigurationSIB", HFILL }},
    { &hf_lte_rrc_pdsch_Configuration_01,
      { "pdsch-Configuration", "lte-rrc.pdsch_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PDSCH_ConfigCommon", HFILL }},
    { &hf_lte_rrc_pusch_Configuration_01,
      { "pusch-Configuration", "lte-rrc.pusch_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PUSCH_ConfigCommon", HFILL }},
    { &hf_lte_rrc_pucch_Configuration_01,
      { "pucch-Configuration", "lte-rrc.pucch_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PUCCH_ConfigCommon", HFILL }},
    { &hf_lte_rrc_soundingRsUl_Config_01,
      { "soundingRsUl-Config", "lte-rrc.soundingRsUl_Config",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SoundingRsUl_ConfigCommon", HFILL }},
    { &hf_lte_rrc_uplinkPowerControl_01,
      { "uplinkPowerControl", "lte-rrc.uplinkPowerControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UplinkPowerControlCommon", HFILL }},
    { &hf_lte_rrc_ul_CyclicPrefixLength,
      { "ul-CyclicPrefixLength", "lte-rrc.ul_CyclicPrefixLength",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_UL_CyclicPrefixLength_vals), 0,
        "lte_rrc.UL_CyclicPrefixLength", HFILL }},
    { &hf_lte_rrc_prach_Configuration_01,
      { "prach-Configuration", "lte-rrc.prach_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PRACH_Configuration", HFILL }},
    { &hf_lte_rrc_antennaInformationCommon,
      { "antennaInformationCommon", "lte-rrc.antennaInformationCommon",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.AntennaInformationCommon", HFILL }},
    { &hf_lte_rrc_modificationPeriodCoeff,
      { "modificationPeriodCoeff", "lte-rrc.modificationPeriodCoeff",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_modificationPeriodCoeff_vals), 0,
        "lte_rrc.T_modificationPeriodCoeff", HFILL }},
    { &hf_lte_rrc_defaultPagingCycle,
      { "defaultPagingCycle", "lte-rrc.defaultPagingCycle",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_defaultPagingCycle_vals), 0,
        "lte_rrc.T_defaultPagingCycle", HFILL }},
    { &hf_lte_rrc_nB,
      { "nB", "lte-rrc.nB",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_nB_vals), 0,
        "lte_rrc.T_nB", HFILL }},
    { &hf_lte_rrc_srb_ToAddModifyList,
      { "srb-ToAddModifyList", "lte-rrc.srb_ToAddModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SRB_ToAddModifyList", HFILL }},
    { &hf_lte_rrc_drb_ToAddModifyList,
      { "drb-ToAddModifyList", "lte-rrc.drb_ToAddModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.DRB_ToAddModifyList", HFILL }},
    { &hf_lte_rrc_drb_ToReleaseList,
      { "drb-ToReleaseList", "lte-rrc.drb_ToReleaseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.DRB_ToReleaseList", HFILL }},
    { &hf_lte_rrc_mac_MainConfig,
      { "mac-MainConfig", "lte-rrc.mac_MainConfig",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_mac_MainConfig_vals), 0,
        "lte_rrc.T_mac_MainConfig", HFILL }},
    { &hf_lte_rrc_explicitValue_01,
      { "explicitValue", "lte-rrc.explicitValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MAC_MainConfiguration", HFILL }},
    { &hf_lte_rrc_sps_Configuration,
      { "sps-Configuration", "lte-rrc.sps_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SPS_Configuration", HFILL }},
    { &hf_lte_rrc_physicalConfigDedicated,
      { "physicalConfigDedicated", "lte-rrc.physicalConfigDedicated",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PhysicalConfigDedicated", HFILL }},
    { &hf_lte_rrc_SRB_ToAddModifyList_item,
      { "SRB-ToAddModifyList item", "lte-rrc.SRB_ToAddModifyList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SRB_ToAddModifyList_item", HFILL }},
    { &hf_lte_rrc_srb_Identity,
      { "srb-Identity", "lte-rrc.srb_Identity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_2", HFILL }},
    { &hf_lte_rrc_rlc_Configuration,
      { "rlc-Configuration", "lte-rrc.rlc_Configuration",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_rlc_Configuration_vals), 0,
        "lte_rrc.T_rlc_Configuration", HFILL }},
    { &hf_lte_rrc_explicitValue_02,
      { "explicitValue", "lte-rrc.explicitValue",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_RLC_Configuration_vals), 0,
        "lte_rrc.RLC_Configuration", HFILL }},
    { &hf_lte_rrc_logicalChannelConfig,
      { "logicalChannelConfig", "lte-rrc.logicalChannelConfig",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_logicalChannelConfig_vals), 0,
        "lte_rrc.T_logicalChannelConfig", HFILL }},
    { &hf_lte_rrc_explicitValue_03,
      { "explicitValue", "lte-rrc.explicitValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.LogicalChannelConfig", HFILL }},
    { &hf_lte_rrc_DRB_ToAddModifyList_item,
      { "DRB-ToAddModifyList item", "lte-rrc.DRB_ToAddModifyList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DRB_ToAddModifyList_item", HFILL }},
    { &hf_lte_rrc_eps_BearerIdentity,
      { "eps-BearerIdentity", "lte-rrc.eps_BearerIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_15", HFILL }},
    { &hf_lte_rrc_pdcp_Configuration,
      { "pdcp-Configuration", "lte-rrc.pdcp_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PDCP_Configuration", HFILL }},
    { &hf_lte_rrc_rlc_Configuration_01,
      { "rlc-Configuration", "lte-rrc.rlc_Configuration",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_RLC_Configuration_vals), 0,
        "lte_rrc.RLC_Configuration", HFILL }},
    { &hf_lte_rrc_logicalChannelIdentity,
      { "logicalChannelIdentity", "lte-rrc.logicalChannelIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_3_10", HFILL }},
    { &hf_lte_rrc_logicalChannelConfig_01,
      { "logicalChannelConfig", "lte-rrc.logicalChannelConfig",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.LogicalChannelConfig", HFILL }},
    { &hf_lte_rrc_DRB_ToReleaseList_item,
      { "DRB-ToReleaseList item", "lte-rrc.DRB_ToReleaseList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DRB_ToReleaseList_item", HFILL }},
    { &hf_lte_rrc_am,
      { "am", "lte-rrc.am",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_am", HFILL }},
    { &hf_lte_rrc_ul_AM_RLC,
      { "ul-AM-RLC", "lte-rrc.ul_AM_RLC",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UL_AM_RLC", HFILL }},
    { &hf_lte_rrc_dl_AM_RLC,
      { "dl-AM-RLC", "lte-rrc.dl_AM_RLC",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DL_AM_RLC", HFILL }},
    { &hf_lte_rrc_um_Bi_Directional,
      { "um-Bi-Directional", "lte-rrc.um_Bi_Directional",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_um_Bi_Directional", HFILL }},
    { &hf_lte_rrc_ul_UM_RLC,
      { "ul-UM-RLC", "lte-rrc.ul_UM_RLC",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UL_UM_RLC", HFILL }},
    { &hf_lte_rrc_dl_UM_RLC,
      { "dl-UM-RLC", "lte-rrc.dl_UM_RLC",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DL_UM_RLC", HFILL }},
    { &hf_lte_rrc_um_Uni_Directional_UL,
      { "um-Uni-Directional-UL", "lte-rrc.um_Uni_Directional_UL",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_um_Uni_Directional_UL", HFILL }},
    { &hf_lte_rrc_um_Uni_Directional_DL,
      { "um-Uni-Directional-DL", "lte-rrc.um_Uni_Directional_DL",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_um_Uni_Directional_DL", HFILL }},
    { &hf_lte_rrc_t_PollRetransmit,
      { "t-PollRetransmit", "lte-rrc.t_PollRetransmit",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_PollRetransmit_vals), 0,
        "lte_rrc.T_PollRetransmit", HFILL }},
    { &hf_lte_rrc_pollPDU,
      { "pollPDU", "lte-rrc.pollPDU",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_PollPDU_vals), 0,
        "lte_rrc.PollPDU", HFILL }},
    { &hf_lte_rrc_pollByte,
      { "pollByte", "lte-rrc.pollByte",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_PollByte_vals), 0,
        "lte_rrc.PollByte", HFILL }},
    { &hf_lte_rrc_maxRetxThreshold,
      { "maxRetxThreshold", "lte-rrc.maxRetxThreshold",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_maxRetxThreshold_vals), 0,
        "lte_rrc.T_maxRetxThreshold", HFILL }},
    { &hf_lte_rrc_t_Reordering,
      { "t-Reordering", "lte-rrc.t_Reordering",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_Reordering_vals), 0,
        "lte_rrc.T_Reordering", HFILL }},
    { &hf_lte_rrc_t_StatusProhibit,
      { "t-StatusProhibit", "lte-rrc.t_StatusProhibit",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_StatusProhibit_vals), 0,
        "lte_rrc.T_StatusProhibit", HFILL }},
    { &hf_lte_rrc_sn_FieldLength,
      { "sn-FieldLength", "lte-rrc.sn_FieldLength",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_SN_FieldLength_vals), 0,
        "lte_rrc.SN_FieldLength", HFILL }},
    { &hf_lte_rrc_enable_06,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_06", HFILL }},
    { &hf_lte_rrc_sr_PUCCH_ResourceIndex,
      { "sr-PUCCH-ResourceIndex", "lte-rrc.sr_PUCCH_ResourceIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_2047", HFILL }},
    { &hf_lte_rrc_sr_ConfigurationIndex,
      { "sr-ConfigurationIndex", "lte-rrc.sr_ConfigurationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_155", HFILL }},
    { &hf_lte_rrc_dsr_TransMax,
      { "dsr-TransMax", "lte-rrc.dsr_TransMax",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_dsr_TransMax_vals), 0,
        "lte_rrc.T_dsr_TransMax", HFILL }},
    { &hf_lte_rrc_srsBandwidthConfiguration,
      { "srsBandwidthConfiguration", "lte-rrc.srsBandwidthConfiguration",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_srsBandwidthConfiguration_vals), 0,
        "lte_rrc.T_srsBandwidthConfiguration", HFILL }},
    { &hf_lte_rrc_srsSubframeConfiguration,
      { "srsSubframeConfiguration", "lte-rrc.srsSubframeConfiguration",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_srsSubframeConfiguration_vals), 0,
        "lte_rrc.T_srsSubframeConfiguration", HFILL }},
    { &hf_lte_rrc_ackNackSrsSimultaneousTransmission,
      { "ackNackSrsSimultaneousTransmission", "lte-rrc.ackNackSrsSimultaneousTransmission",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_srsMaxUpPts,
      { "srsMaxUpPts", "lte-rrc.srsMaxUpPts",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_enable_07,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_07", HFILL }},
    { &hf_lte_rrc_srsBandwidth,
      { "srsBandwidth", "lte-rrc.srsBandwidth",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_srsBandwidth_vals), 0,
        "lte_rrc.T_srsBandwidth", HFILL }},
    { &hf_lte_rrc_srsHoppingBandwidth,
      { "srsHoppingBandwidth", "lte-rrc.srsHoppingBandwidth",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_srsHoppingBandwidth_vals), 0,
        "lte_rrc.T_srsHoppingBandwidth", HFILL }},
    { &hf_lte_rrc_frequencyDomainPosition,
      { "frequencyDomainPosition", "lte-rrc.frequencyDomainPosition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_23", HFILL }},
    { &hf_lte_rrc_duration,
      { "duration", "lte-rrc.duration",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_srs_ConfigurationIndex,
      { "srs-ConfigurationIndex", "lte-rrc.srs_ConfigurationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_1023", HFILL }},
    { &hf_lte_rrc_transmissionComb,
      { "transmissionComb", "lte-rrc.transmissionComb",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_1", HFILL }},
    { &hf_lte_rrc_cyclicShift,
      { "cyclicShift", "lte-rrc.cyclicShift",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cyclicShift_vals), 0,
        "lte_rrc.T_cyclicShift", HFILL }},
    { &hf_lte_rrc_semiPersistSchedC_RNTI,
      { "semiPersistSchedC-RNTI", "lte-rrc.semiPersistSchedC_RNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.C_RNTI", HFILL }},
    { &hf_lte_rrc_sps_ConfigurationDL,
      { "sps-ConfigurationDL", "lte-rrc.sps_ConfigurationDL",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_SPS_ConfigurationDL_vals), 0,
        "lte_rrc.SPS_ConfigurationDL", HFILL }},
    { &hf_lte_rrc_sps_ConfigurationUL,
      { "sps-ConfigurationUL", "lte-rrc.sps_ConfigurationUL",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_SPS_ConfigurationUL_vals), 0,
        "lte_rrc.SPS_ConfigurationUL", HFILL }},
    { &hf_lte_rrc_enable_08,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_08", HFILL }},
    { &hf_lte_rrc_semiPersistSchedIntervalDL,
      { "semiPersistSchedIntervalDL", "lte-rrc.semiPersistSchedIntervalDL",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_semiPersistSchedIntervalDL_vals), 0,
        "lte_rrc.T_semiPersistSchedIntervalDL", HFILL }},
    { &hf_lte_rrc_numberOfConfSPS_Processes,
      { "numberOfConfSPS-Processes", "lte-rrc.numberOfConfSPS_Processes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_8", HFILL }},
    { &hf_lte_rrc_n1Pucch_AN_Persistent,
      { "n1Pucch-AN-Persistent", "lte-rrc.n1Pucch_AN_Persistent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_2047", HFILL }},
    { &hf_lte_rrc_enable_09,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_09", HFILL }},
    { &hf_lte_rrc_semiPersistSchedIntervalUL,
      { "semiPersistSchedIntervalUL", "lte-rrc.semiPersistSchedIntervalUL",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_semiPersistSchedIntervalUL_vals), 0,
        "lte_rrc.T_semiPersistSchedIntervalUL", HFILL }},
    { &hf_lte_rrc_implicitReleaseAfter,
      { "implicitReleaseAfter", "lte-rrc.implicitReleaseAfter",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_implicitReleaseAfter_vals), 0,
        "lte_rrc.T_implicitReleaseAfter", HFILL }},
    { &hf_lte_rrc_p0_Persistent,
      { "p0-Persistent", "lte-rrc.p0_Persistent",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_p0_Persistent", HFILL }},
    { &hf_lte_rrc_p0_NominalPUSCH_Persistent,
      { "p0-NominalPUSCH-Persistent", "lte-rrc.p0_NominalPUSCH_Persistent",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M126_24", HFILL }},
    { &hf_lte_rrc_p0_UePUSCH_Persistent,
      { "p0-UePUSCH-Persistent", "lte-rrc.p0_UePUSCH_Persistent",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M8_7", HFILL }},
    { &hf_lte_rrc_subframeAssignment,
      { "subframeAssignment", "lte-rrc.subframeAssignment",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_subframeAssignment_vals), 0,
        "lte_rrc.T_subframeAssignment", HFILL }},
    { &hf_lte_rrc_specialSubframePatterns,
      { "specialSubframePatterns", "lte-rrc.specialSubframePatterns",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_specialSubframePatterns_vals), 0,
        "lte_rrc.T_specialSubframePatterns", HFILL }},
    { &hf_lte_rrc_indexOfFormat3,
      { "indexOfFormat3", "lte-rrc.indexOfFormat3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_15", HFILL }},
    { &hf_lte_rrc_indexOfFormat3A,
      { "indexOfFormat3A", "lte-rrc.indexOfFormat3A",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_31", HFILL }},
    { &hf_lte_rrc_enable_10,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_10", HFILL }},
    { &hf_lte_rrc_tpc_RNTI,
      { "tpc-RNTI", "lte-rrc.tpc_RNTI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_16", HFILL }},
    { &hf_lte_rrc_tpc_Index,
      { "tpc-Index", "lte-rrc.tpc_Index",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_TPC_Index_vals), 0,
        "lte_rrc.TPC_Index", HFILL }},
    { &hf_lte_rrc_groupHoppingEnabled,
      { "groupHoppingEnabled", "lte-rrc.groupHoppingEnabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_groupAssignmentPUSCH,
      { "groupAssignmentPUSCH", "lte-rrc.groupAssignmentPUSCH",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_29", HFILL }},
    { &hf_lte_rrc_sequenceHoppingEnabled,
      { "sequenceHoppingEnabled", "lte-rrc.sequenceHoppingEnabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_cyclicShift_01,
      { "cyclicShift", "lte-rrc.cyclicShift",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_7", HFILL }},
    { &hf_lte_rrc_p0_NominalPUSCH,
      { "p0-NominalPUSCH", "lte-rrc.p0_NominalPUSCH",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M126_24", HFILL }},
    { &hf_lte_rrc_alpha,
      { "alpha", "lte-rrc.alpha",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_alpha_vals), 0,
        "lte_rrc.T_alpha", HFILL }},
    { &hf_lte_rrc_p0_NominalPUCCH,
      { "p0-NominalPUCCH", "lte-rrc.p0_NominalPUCCH",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M127_M96", HFILL }},
    { &hf_lte_rrc_deltaFList_PUCCH,
      { "deltaFList-PUCCH", "lte-rrc.deltaFList_PUCCH",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.DeltaFList_PUCCH", HFILL }},
    { &hf_lte_rrc_deltaPreambleMsg3,
      { "deltaPreambleMsg3", "lte-rrc.deltaPreambleMsg3",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M1_6", HFILL }},
    { &hf_lte_rrc_p0_UePUSCH,
      { "p0-UePUSCH", "lte-rrc.p0_UePUSCH",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M8_7", HFILL }},
    { &hf_lte_rrc_deltaMCS_Enabled,
      { "deltaMCS-Enabled", "lte-rrc.deltaMCS_Enabled",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_deltaMCS_Enabled_vals), 0,
        "lte_rrc.T_deltaMCS_Enabled", HFILL }},
    { &hf_lte_rrc_accumulationEnabled,
      { "accumulationEnabled", "lte-rrc.accumulationEnabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_p0_uePUCCH,
      { "p0-uePUCCH", "lte-rrc.p0_uePUCCH",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M8_7", HFILL }},
    { &hf_lte_rrc_pSRS_Offset,
      { "pSRS-Offset", "lte-rrc.pSRS_Offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_15", HFILL }},
    { &hf_lte_rrc_deltaF_PUCCH_Format1,
      { "deltaF-PUCCH-Format1", "lte-rrc.deltaF_PUCCH_Format1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_deltaF_PUCCH_Format1_vals), 0,
        "lte_rrc.T_deltaF_PUCCH_Format1", HFILL }},
    { &hf_lte_rrc_deltaF_PUCCH_Format1b,
      { "deltaF-PUCCH-Format1b", "lte-rrc.deltaF_PUCCH_Format1b",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_deltaF_PUCCH_Format1b_vals), 0,
        "lte_rrc.T_deltaF_PUCCH_Format1b", HFILL }},
    { &hf_lte_rrc_deltaF_PUCCH_Format2,
      { "deltaF-PUCCH-Format2", "lte-rrc.deltaF_PUCCH_Format2",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_deltaF_PUCCH_Format2_vals), 0,
        "lte_rrc.T_deltaF_PUCCH_Format2", HFILL }},
    { &hf_lte_rrc_deltaF_PUCCH_Format2a,
      { "deltaF-PUCCH-Format2a", "lte-rrc.deltaF_PUCCH_Format2a",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_deltaF_PUCCH_Format2a_vals), 0,
        "lte_rrc.T_deltaF_PUCCH_Format2a", HFILL }},
    { &hf_lte_rrc_deltaF_PUCCH_Format2b,
      { "deltaF-PUCCH-Format2b", "lte-rrc.deltaF_PUCCH_Format2b",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_deltaF_PUCCH_Format2b_vals), 0,
        "lte_rrc.T_deltaF_PUCCH_Format2b", HFILL }},
    { &hf_lte_rrc_integrityProtAlgorithm,
      { "integrityProtAlgorithm", "lte-rrc.integrityProtAlgorithm",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_IntegrityProtAlgorithm_vals), 0,
        "lte_rrc.IntegrityProtAlgorithm", HFILL }},
    { &hf_lte_rrc_cipheringAlgorithm,
      { "cipheringAlgorithm", "lte-rrc.cipheringAlgorithm",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_CipheringAlgorithm_vals), 0,
        "lte_rrc.CipheringAlgorithm", HFILL }},
    { &hf_lte_rrc_keyChangeIndicator,
      { "keyChangeIndicator", "lte-rrc.keyChangeIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_cdma2000_CarrierInfo,
      { "cdma2000-CarrierInfo", "lte-rrc.cdma2000_CarrierInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_CarrierInfo", HFILL }},
    { &hf_lte_rrc_pnOffset,
      { "pnOffset", "lte-rrc.pnOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CDMA2000_CellIdentity", HFILL }},
    { &hf_lte_rrc_cdma_EUTRA_Synchronisation,
      { "cdma-EUTRA-Synchronisation", "lte-rrc.cdma_EUTRA_Synchronisation",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_cdma_SystemTime,
      { "cdma-SystemTime", "lte-rrc.cdma_SystemTime",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cdma_SystemTime_vals), 0,
        "lte_rrc.T_cdma_SystemTime", HFILL }},
    { &hf_lte_rrc_cdma_SynchronousSystemTime,
      { "cdma-SynchronousSystemTime", "lte-rrc.cdma_SynchronousSystemTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_39", HFILL }},
    { &hf_lte_rrc_cdma_AsynchronousSystemTime,
      { "cdma-AsynchronousSystemTime", "lte-rrc.cdma_AsynchronousSystemTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_49", HFILL }},
    { &hf_lte_rrc_CellIndexList_item,
      { "CellIndexList item", "lte-rrc.CellIndexList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CellIndexList_item", HFILL }},
    { &hf_lte_rrc_cellIndex,
      { "cellIndex", "lte-rrc.cellIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_maxCellMeas", HFILL }},
    { &hf_lte_rrc_timeToTriggerSF_Medium,
      { "timeToTriggerSF-Medium", "lte-rrc.timeToTriggerSF_Medium",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_timeToTriggerSF_Medium_vals), 0,
        "lte_rrc.T_timeToTriggerSF_Medium", HFILL }},
    { &hf_lte_rrc_timeToTriggerSF_High,
      { "timeToTriggerSF-High", "lte-rrc.timeToTriggerSF_High",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_timeToTriggerSF_High_vals), 0,
        "lte_rrc.T_timeToTriggerSF_High", HFILL }},
    { &hf_lte_rrc_earfcn_DL,
      { "earfcn-DL", "lte-rrc.earfcn_DL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_maxEARFCN", HFILL }},
    { &hf_lte_rrc_earfcn_UL,
      { "earfcn-UL", "lte-rrc.earfcn_UL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.EUTRA_DL_CarrierFreq", HFILL }},
    { &hf_lte_rrc_arfcn,
      { "arfcn", "lte-rrc.arfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.GERAN_ARFCN_Value", HFILL }},
    { &hf_lte_rrc_bandIndicator,
      { "bandIndicator", "lte-rrc.bandIndicator",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_GERAN_BandIndicator_vals), 0,
        "lte_rrc.GERAN_BandIndicator", HFILL }},
    { &hf_lte_rrc_startingARFCN,
      { "startingARFCN", "lte-rrc.startingARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.GERAN_ARFCN_Value", HFILL }},
    { &hf_lte_rrc_followingARFCNs,
      { "followingARFCNs", "lte-rrc.followingARFCNs",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_followingARFCNs_vals), 0,
        "lte_rrc.T_followingARFCNs", HFILL }},
    { &hf_lte_rrc_explicitListOfARFCNs,
      { "explicitListOfARFCNs", "lte-rrc.explicitListOfARFCNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ExplicitListOfARFCNs", HFILL }},
    { &hf_lte_rrc_equallySpacedARFCNs,
      { "equallySpacedARFCNs", "lte-rrc.equallySpacedARFCNs",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_equallySpacedARFCNs", HFILL }},
    { &hf_lte_rrc_arfcn_Spacing,
      { "arfcn-Spacing", "lte-rrc.arfcn_Spacing",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_8", HFILL }},
    { &hf_lte_rrc_numberOfFollowingARFCNs,
      { "numberOfFollowingARFCNs", "lte-rrc.numberOfFollowingARFCNs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_31", HFILL }},
    { &hf_lte_rrc_variableBitMapOfARFCNs,
      { "variableBitMapOfARFCNs", "lte-rrc.variableBitMapOfARFCNs",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING_SIZE_1_16", HFILL }},
    { &hf_lte_rrc_ExplicitListOfARFCNs_item,
      { "GERAN-ARFCN-Value", "lte-rrc.GERAN_ARFCN_Value",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.GERAN_ARFCN_Value", HFILL }},
    { &hf_lte_rrc_networkColourCode,
      { "networkColourCode", "lte-rrc.networkColourCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_3", HFILL }},
    { &hf_lte_rrc_baseStationColourCode,
      { "baseStationColourCode", "lte-rrc.baseStationColourCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_3", HFILL }},
    { &hf_lte_rrc_utra_CellIdentity,
      { "utra-CellIdentity", "lte-rrc.utra_CellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_28", HFILL }},
    { &hf_lte_rrc_locationAreaCode,
      { "locationAreaCode", "lte-rrc.locationAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_16", HFILL }},
    { &hf_lte_rrc_geran_CellIdentity,
      { "geran-CellIdentity", "lte-rrc.geran_CellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_16", HFILL }},
    { &hf_lte_rrc_globalCellId_oneXRTT,
      { "globalCellId-oneXRTT", "lte-rrc.globalCellId_oneXRTT",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_47", HFILL }},
    { &hf_lte_rrc_globalCellId_HRPD,
      { "globalCellId-HRPD", "lte-rrc.globalCellId_HRPD",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_128", HFILL }},
    { &hf_lte_rrc_hrpd_PreRegistrationAllowed,
      { "hrpd-PreRegistrationAllowed", "lte-rrc.hrpd_PreRegistrationAllowed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_hrpd_PreRegistrationZoneId,
      { "hrpd-PreRegistrationZoneId", "lte-rrc.hrpd_PreRegistrationZoneId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_255", HFILL }},
    { &hf_lte_rrc_hrpd_SecondaryPreRegistrationZoneIdList,
      { "hrpd-SecondaryPreRegistrationZoneIdList", "lte-rrc.hrpd_SecondaryPreRegistrationZoneIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.HRPD_SecondaryPreRegistrationZoneIdList", HFILL }},
    { &hf_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList_item,
      { "HRPD-SecondaryPreRegistrationZoneIdList item", "lte-rrc.HRPD_SecondaryPreRegistrationZoneIdList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.HRPD_SecondaryPreRegistrationZoneIdList_item", HFILL }},
    { &hf_lte_rrc_hrpd_SecondaryPreRegistrationZoneId,
      { "hrpd-SecondaryPreRegistrationZoneId", "lte-rrc.hrpd_SecondaryPreRegistrationZoneId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_255", HFILL }},
    { &hf_lte_rrc_targetCellIdentity,
      { "targetCellIdentity", "lte-rrc.targetCellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PhysicalCellIdentity", HFILL }},
    { &hf_lte_rrc_eutra_CarrierFreq_01,
      { "eutra-CarrierFreq", "lte-rrc.eutra_CarrierFreq",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.EUTRA_CarrierFreq", HFILL }},
    { &hf_lte_rrc_eutra_CarrierBandwidth,
      { "eutra-CarrierBandwidth", "lte-rrc.eutra_CarrierBandwidth",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.EUTRA_CarrierBandwidth", HFILL }},
    { &hf_lte_rrc_t304_01,
      { "t304", "lte-rrc.t304",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t304_01_vals), 0,
        "lte_rrc.T_t304_01", HFILL }},
    { &hf_lte_rrc_newUE_Identity,
      { "newUE-Identity", "lte-rrc.newUE_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.C_RNTI", HFILL }},
    { &hf_lte_rrc_radioResourceConfigCommon_01,
      { "radioResourceConfigCommon", "lte-rrc.radioResourceConfigCommon",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RadioResourceConfigCommon", HFILL }},
    { &hf_lte_rrc_rach_ConfigDedicated,
      { "rach-ConfigDedicated", "lte-rrc.rach_ConfigDedicated",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RACH_ConfigDedicated", HFILL }},
    { &hf_lte_rrc_dl_Bandwidth_01,
      { "dl-Bandwidth", "lte-rrc.dl_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_dl_Bandwidth_01_vals), 0,
        "lte_rrc.T_dl_Bandwidth_01", HFILL }},
    { &hf_lte_rrc_ul_Bandwidth_01,
      { "ul-Bandwidth", "lte-rrc.ul_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_ul_Bandwidth_01_vals), 0,
        "lte_rrc.T_ul_Bandwidth_01", HFILL }},
    { &hf_lte_rrc_t_Evalulation,
      { "t-Evalulation", "lte-rrc.t_Evalulation",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_Evalulation_vals), 0,
        "lte_rrc.T_t_Evalulation", HFILL }},
    { &hf_lte_rrc_t_HystNormal,
      { "t-HystNormal", "lte-rrc.t_HystNormal",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t_HystNormal_vals), 0,
        "lte_rrc.T_t_HystNormal", HFILL }},
    { &hf_lte_rrc_n_CellChangeMedium,
      { "n-CellChangeMedium", "lte-rrc.n_CellChangeMedium",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_16", HFILL }},
    { &hf_lte_rrc_n_CellChangeHigh,
      { "n-CellChangeHigh", "lte-rrc.n_CellChangeHigh",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_16", HFILL }},
    { &hf_lte_rrc_oneXRTT_CSFB_RegistrationAllowed,
      { "oneXRTT-CSFB-RegistrationAllowed", "lte-rrc.oneXRTT_CSFB_RegistrationAllowed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_oneXRTT_RegistrationParameters,
      { "oneXRTT-RegistrationParameters", "lte-rrc.oneXRTT_RegistrationParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.OneXRTT_RegistrationParameters", HFILL }},
    { &hf_lte_rrc_oneXRTT_SID,
      { "oneXRTT-SID", "lte-rrc.oneXRTT_SID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_15", HFILL }},
    { &hf_lte_rrc_oneXRTT_NID,
      { "oneXRTT-NID", "lte-rrc.oneXRTT_NID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_16", HFILL }},
    { &hf_lte_rrc_oneXRTT_MultipleSID,
      { "oneXRTT-MultipleSID", "lte-rrc.oneXRTT_MultipleSID",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_oneXRTT_MultipleNID,
      { "oneXRTT-MultipleNID", "lte-rrc.oneXRTT_MultipleNID",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_oneXRTT_HomeReg,
      { "oneXRTT-HomeReg", "lte-rrc.oneXRTT_HomeReg",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_oneXRTT_ForeignSIDReg,
      { "oneXRTT-ForeignSIDReg", "lte-rrc.oneXRTT_ForeignSIDReg",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_oneXRTT_ForeignNIDReg,
      { "oneXRTT-ForeignNIDReg", "lte-rrc.oneXRTT_ForeignNIDReg",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_oneXRTT_ParameterReg,
      { "oneXRTT-ParameterReg", "lte-rrc.oneXRTT_ParameterReg",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_oneXRTT_RegistrationPeriod,
      { "oneXRTT-RegistrationPeriod", "lte-rrc.oneXRTT_RegistrationPeriod",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_7", HFILL }},
    { &hf_lte_rrc_oneXRTT_RegistrationZone,
      { "oneXRTT-RegistrationZone", "lte-rrc.oneXRTT_RegistrationZone",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_12", HFILL }},
    { &hf_lte_rrc_oneXRTT_TotalZone,
      { "oneXRTT-TotalZone", "lte-rrc.oneXRTT_TotalZone",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_3", HFILL }},
    { &hf_lte_rrc_oneXRTT_ZoneTimer,
      { "oneXRTT-ZoneTimer", "lte-rrc.oneXRTT_ZoneTimer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_3", HFILL }},
    { &hf_lte_rrc_singlePCI,
      { "singlePCI", "lte-rrc.singlePCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PhysicalCellIdentity", HFILL }},
    { &hf_lte_rrc_rangeOfPCI,
      { "rangeOfPCI", "lte-rrc.rangeOfPCI",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_rangeOfPCI", HFILL }},
    { &hf_lte_rrc_startPCI,
      { "startPCI", "lte-rrc.startPCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PhysicalCellIdentity", HFILL }},
    { &hf_lte_rrc_rangePCI,
      { "rangePCI", "lte-rrc.rangePCI",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_rangePCI_vals), 0,
        "lte_rrc.T_rangePCI", HFILL }},
    { &hf_lte_rrc_mcc,
      { "mcc", "lte-rrc.mcc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MCC", HFILL }},
    { &hf_lte_rrc_mnc,
      { "mnc", "lte-rrc.mnc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MNC", HFILL }},
    { &hf_lte_rrc_MCC_item,
      { "MCC-MNC-Digit", "lte-rrc.MCC_MNC_Digit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MCC_MNC_Digit", HFILL }},
    { &hf_lte_rrc_MNC_item,
      { "MCC-MNC-Digit", "lte-rrc.MCC_MNC_Digit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MCC_MNC_Digit", HFILL }},
    { &hf_lte_rrc_primaryScramblingCode,
      { "primaryScramblingCode", "lte-rrc.primaryScramblingCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_511", HFILL }},
    { &hf_lte_rrc_cellParametersID,
      { "cellParametersID", "lte-rrc.cellParametersID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_127", HFILL }},
    { &hf_lte_rrc_uarfcn_DL,
      { "uarfcn-DL", "lte-rrc.uarfcn_DL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_16383", HFILL }},
    { &hf_lte_rrc_gapActivation,
      { "gapActivation", "lte-rrc.gapActivation",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_gapActivation_vals), 0,
        "lte_rrc.T_gapActivation", HFILL }},
    { &hf_lte_rrc_activate,
      { "activate", "lte-rrc.activate",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_activate", HFILL }},
    { &hf_lte_rrc_gapPattern,
      { "gapPattern", "lte-rrc.gapPattern",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_gapPattern_vals), 0,
        "lte_rrc.T_gapPattern", HFILL }},
    { &hf_lte_rrc_gp1,
      { "gp1", "lte-rrc.gp1",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_gp1", HFILL }},
    { &hf_lte_rrc_gapOffset,
      { "gapOffset", "lte-rrc.gapOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_39", HFILL }},
    { &hf_lte_rrc_gp2,
      { "gp2", "lte-rrc.gp2",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_gp2", HFILL }},
    { &hf_lte_rrc_gapOffset_01,
      { "gapOffset", "lte-rrc.gapOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_79", HFILL }},
    { &hf_lte_rrc_deactivate,
      { "deactivate", "lte-rrc.deactivate",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_cdma2000_SearchWindowSize,
      { "cdma2000-SearchWindowSize", "lte-rrc.cdma2000_SearchWindowSize",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_15", HFILL }},
    { &hf_lte_rrc_offsetFreq,
      { "offsetFreq", "lte-rrc.offsetFreq",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_offsetFreq_vals), 0,
        "lte_rrc.T_offsetFreq", HFILL }},
    { &hf_lte_rrc_cellsToRemoveList,
      { "cellsToRemoveList", "lte-rrc.cellsToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CellIndexList", HFILL }},
    { &hf_lte_rrc_cellsToAddModifyList,
      { "cellsToAddModifyList", "lte-rrc.cellsToAddModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CDMA2000_CellsToAddModifyList", HFILL }},
    { &hf_lte_rrc_cellForWhichToReportCGI,
      { "cellForWhichToReportCGI", "lte-rrc.cellForWhichToReportCGI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CDMA2000_CellIdentity", HFILL }},
    { &hf_lte_rrc_CDMA2000_CellsToAddModifyList_item,
      { "CDMA2000-CellsToAddModifyList item", "lte-rrc.CDMA2000_CellsToAddModifyList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CDMA2000_CellsToAddModifyList_item", HFILL }},
    { &hf_lte_rrc_cellIdentity_01,
      { "cellIdentity", "lte-rrc.cellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CDMA2000_CellIdentity", HFILL }},
    { &hf_lte_rrc_eutra_CarrierInfo,
      { "eutra-CarrierInfo", "lte-rrc.eutra_CarrierInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.EUTRA_DL_CarrierFreq", HFILL }},
    { &hf_lte_rrc_offsetFreq_01,
      { "offsetFreq", "lte-rrc.offsetFreq",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_offsetFreq_01_vals), 0,
        "lte_rrc.T_offsetFreq_01", HFILL }},
    { &hf_lte_rrc_cellsToAddModifyList_01,
      { "cellsToAddModifyList", "lte-rrc.cellsToAddModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.NeighCellsToAddModifyList", HFILL }},
    { &hf_lte_rrc_blackListedCellsToRemoveList,
      { "blackListedCellsToRemoveList", "lte-rrc.blackListedCellsToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CellIndexList", HFILL }},
    { &hf_lte_rrc_blackListedCellsToAddModifyList,
      { "blackListedCellsToAddModifyList", "lte-rrc.blackListedCellsToAddModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.BlackListedCellsToAddModifyList", HFILL }},
    { &hf_lte_rrc_cellForWhichToReportCGI_01,
      { "cellForWhichToReportCGI", "lte-rrc.cellForWhichToReportCGI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PhysicalCellIdentity", HFILL }},
    { &hf_lte_rrc_NeighCellsToAddModifyList_item,
      { "NeighCellsToAddModifyList item", "lte-rrc.NeighCellsToAddModifyList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NeighCellsToAddModifyList_item", HFILL }},
    { &hf_lte_rrc_cellIdentity_02,
      { "cellIdentity", "lte-rrc.cellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PhysicalCellIdentity", HFILL }},
    { &hf_lte_rrc_cellIndividualOffset,
      { "cellIndividualOffset", "lte-rrc.cellIndividualOffset",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cellIndividualOffset_vals), 0,
        "lte_rrc.T_cellIndividualOffset", HFILL }},
    { &hf_lte_rrc_BlackListedCellsToAddModifyList_item,
      { "BlackListedCellsToAddModifyList item", "lte-rrc.BlackListedCellsToAddModifyList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.BlackListedCellsToAddModifyList_item", HFILL }},
    { &hf_lte_rrc_cellIdentityAndRange,
      { "cellIdentityAndRange", "lte-rrc.cellIdentityAndRange",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_PhysicalCellIdentityAndRange_vals), 0,
        "lte_rrc.PhysicalCellIdentityAndRange", HFILL }},
    { &hf_lte_rrc_geran_MeasFrequencyList,
      { "geran-MeasFrequencyList", "lte-rrc.geran_MeasFrequencyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.GERAN_MeasFrequencyList", HFILL }},
    { &hf_lte_rrc_offsetFreq_02,
      { "offsetFreq", "lte-rrc.offsetFreq",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M15_15", HFILL }},
    { &hf_lte_rrc_cellForWhichToReportCGI_02,
      { "cellForWhichToReportCGI", "lte-rrc.cellForWhichToReportCGI",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GERAN_CellIdentity", HFILL }},
    { &hf_lte_rrc_GERAN_MeasFrequencyList_item,
      { "GERAN-CarrierFreqList", "lte-rrc.GERAN_CarrierFreqList",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GERAN_CarrierFreqList", HFILL }},
    { &hf_lte_rrc_cellsToAddModifyList_02,
      { "cellsToAddModifyList", "lte-rrc.cellsToAddModifyList",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cellsToAddModifyList_vals), 0,
        "lte_rrc.T_cellsToAddModifyList", HFILL }},
    { &hf_lte_rrc_cellsToAddModifyListUTRA_FDD,
      { "cellsToAddModifyListUTRA-FDD", "lte-rrc.cellsToAddModifyListUTRA_FDD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.UTRA_FDD_CellsToAddModifyList", HFILL }},
    { &hf_lte_rrc_cellsToAddModifyListUTRA_TDD,
      { "cellsToAddModifyListUTRA-TDD", "lte-rrc.cellsToAddModifyListUTRA_TDD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.UTRA_TDD_CellsToAddModifyList", HFILL }},
    { &hf_lte_rrc_cellForWhichToReportCGI_03,
      { "cellForWhichToReportCGI", "lte-rrc.cellForWhichToReportCGI",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cellForWhichToReportCGI_vals), 0,
        "lte_rrc.T_cellForWhichToReportCGI", HFILL }},
    { &hf_lte_rrc_utra_FDD_01,
      { "utra-FDD", "lte-rrc.utra_FDD",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_FDD_CellIdentity", HFILL }},
    { &hf_lte_rrc_utra_TDD_01,
      { "utra-TDD", "lte-rrc.utra_TDD",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_TDD_CellIdentity", HFILL }},
    { &hf_lte_rrc_UTRA_FDD_CellsToAddModifyList_item,
      { "UTRA-FDD-CellsToAddModifyList item", "lte-rrc.UTRA_FDD_CellsToAddModifyList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_FDD_CellsToAddModifyList_item", HFILL }},
    { &hf_lte_rrc_utra_FDD_CellIdentity,
      { "utra-FDD-CellIdentity", "lte-rrc.utra_FDD_CellIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_FDD_CellIdentity", HFILL }},
    { &hf_lte_rrc_UTRA_TDD_CellsToAddModifyList_item,
      { "UTRA-TDD-CellsToAddModifyList item", "lte-rrc.UTRA_TDD_CellsToAddModifyList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_TDD_CellsToAddModifyList_item", HFILL }},
    { &hf_lte_rrc_utra_TDD_CellIdentity,
      { "utra-TDD-CellIdentity", "lte-rrc.utra_TDD_CellIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_TDD_CellIdentity", HFILL }},
    { &hf_lte_rrc_measId,
      { "measId", "lte-rrc.measId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasId", HFILL }},
    { &hf_lte_rrc_measResultServing,
      { "measResultServing", "lte-rrc.measResultServing",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_measResultServing", HFILL }},
    { &hf_lte_rrc_rsrpResult,
      { "rsrpResult", "lte-rrc.rsrpResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.RSRP_Range", HFILL }},
    { &hf_lte_rrc_rsrqResult,
      { "rsrqResult", "lte-rrc.rsrqResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.RSRQ_Range", HFILL }},
    { &hf_lte_rrc_neighbouringMeasResults,
      { "neighbouringMeasResults", "lte-rrc.neighbouringMeasResults",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_neighbouringMeasResults_vals), 0,
        "lte_rrc.T_neighbouringMeasResults", HFILL }},
    { &hf_lte_rrc_measResultListEUTRA,
      { "measResultListEUTRA", "lte-rrc.measResultListEUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasResultListEUTRA", HFILL }},
    { &hf_lte_rrc_measResultListUTRA,
      { "measResultListUTRA", "lte-rrc.measResultListUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasResultListUTRA", HFILL }},
    { &hf_lte_rrc_measResultListGERAN,
      { "measResultListGERAN", "lte-rrc.measResultListGERAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasResultListGERAN", HFILL }},
    { &hf_lte_rrc_measResultsCDMA2000,
      { "measResultsCDMA2000", "lte-rrc.measResultsCDMA2000",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasResultsCDMA2000", HFILL }},
    { &hf_lte_rrc_MeasResultListEUTRA_item,
      { "MeasResultListEUTRA item", "lte-rrc.MeasResultListEUTRA_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasResultListEUTRA_item", HFILL }},
    { &hf_lte_rrc_globalCellIdentity,
      { "globalCellIdentity", "lte-rrc.globalCellIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_globalCellIdentity", HFILL }},
    { &hf_lte_rrc_globalCellID_EUTRA,
      { "globalCellID-EUTRA", "lte-rrc.globalCellID_EUTRA",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GlobalCellId_EUTRA", HFILL }},
    { &hf_lte_rrc_tac_ID,
      { "tac-ID", "lte-rrc.tac_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.TrackingAreaCode", HFILL }},
    { &hf_lte_rrc_plmn_IdentityList_01,
      { "plmn-IdentityList", "lte-rrc.plmn_IdentityList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PLMN_IdentityList2", HFILL }},
    { &hf_lte_rrc_measResult,
      { "measResult", "lte-rrc.measResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_measResult", HFILL }},
    { &hf_lte_rrc_MeasResultListUTRA_item,
      { "MeasResultListUTRA item", "lte-rrc.MeasResultListUTRA_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasResultListUTRA_item", HFILL }},
    { &hf_lte_rrc_physicalCellIdentity_01,
      { "physicalCellIdentity", "lte-rrc.physicalCellIdentity",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_physicalCellIdentity_vals), 0,
        "lte_rrc.T_physicalCellIdentity", HFILL }},
    { &hf_lte_rrc_cellIentityFDD,
      { "cellIentityFDD", "lte-rrc.cellIentityFDD",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_FDD_CellIdentity", HFILL }},
    { &hf_lte_rrc_cellIentityTDD,
      { "cellIentityTDD", "lte-rrc.cellIentityTDD",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UTRA_TDD_CellIdentity", HFILL }},
    { &hf_lte_rrc_globalCellIdentity_01,
      { "globalCellIdentity", "lte-rrc.globalCellIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_globalCellIdentity_01", HFILL }},
    { &hf_lte_rrc_globalcellID_UTRA,
      { "globalcellID-UTRA", "lte-rrc.globalcellID_UTRA",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GlobalCellId_UTRA", HFILL }},
    { &hf_lte_rrc_lac_Id,
      { "lac-Id", "lte-rrc.lac_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_16", HFILL }},
    { &hf_lte_rrc_rac_Id,
      { "rac-Id", "lte-rrc.rac_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_8", HFILL }},
    { &hf_lte_rrc_measResult_01,
      { "measResult", "lte-rrc.measResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_measResult_01", HFILL }},
    { &hf_lte_rrc_mode,
      { "mode", "lte-rrc.mode",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_mode_vals), 0,
        "lte_rrc.T_mode", HFILL }},
    { &hf_lte_rrc_fdd,
      { "fdd", "lte-rrc.fdd",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_fdd", HFILL }},
    { &hf_lte_rrc_cpich_RSCP,
      { "cpich-RSCP", "lte-rrc.cpich_RSCP",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M5_91", HFILL }},
    { &hf_lte_rrc_cpich_EcN0,
      { "cpich-EcN0", "lte-rrc.cpich_EcN0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_49", HFILL }},
    { &hf_lte_rrc_tdd,
      { "tdd", "lte-rrc.tdd",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_tdd", HFILL }},
    { &hf_lte_rrc_pccpch_RSCP,
      { "pccpch-RSCP", "lte-rrc.pccpch_RSCP",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M5_91", HFILL }},
    { &hf_lte_rrc_MeasResultListGERAN_item,
      { "MeasResultListGERAN item", "lte-rrc.MeasResultListGERAN_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasResultListGERAN_item", HFILL }},
    { &hf_lte_rrc_physicalCellIdentity_02,
      { "physicalCellIdentity", "lte-rrc.physicalCellIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_physicalCellIdentity_01", HFILL }},
    { &hf_lte_rrc_geran_CellIdentity_01,
      { "geran-CellIdentity", "lte-rrc.geran_CellIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GERAN_CellIdentity", HFILL }},
    { &hf_lte_rrc_globalCellIdentity_02,
      { "globalCellIdentity", "lte-rrc.globalCellIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_globalCellIdentity_02", HFILL }},
    { &hf_lte_rrc_globalcellID_GERAN,
      { "globalcellID-GERAN", "lte-rrc.globalcellID_GERAN",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.GlobalCellId_GERAN", HFILL }},
    { &hf_lte_rrc_measResult_02,
      { "measResult", "lte-rrc.measResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_measResult_02", HFILL }},
    { &hf_lte_rrc_rssi,
      { "rssi", "lte-rrc.rssi",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_6", HFILL }},
    { &hf_lte_rrc_hrpdPreRegistrationStatus,
      { "hrpdPreRegistrationStatus", "lte-rrc.hrpdPreRegistrationStatus",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_measResultListCDMA2000,
      { "measResultListCDMA2000", "lte-rrc.measResultListCDMA2000",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasResultListCDMA2000", HFILL }},
    { &hf_lte_rrc_MeasResultListCDMA2000_item,
      { "MeasResultListCDMA2000 item", "lte-rrc.MeasResultListCDMA2000_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasResultListCDMA2000_item", HFILL }},
    { &hf_lte_rrc_physicalCellIdentity_03,
      { "physicalCellIdentity", "lte-rrc.physicalCellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CDMA2000_CellIdentity", HFILL }},
    { &hf_lte_rrc_globalCellIdentity_03,
      { "globalCellIdentity", "lte-rrc.globalCellIdentity",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_GlobalCellId_CDMA2000_vals), 0,
        "lte_rrc.GlobalCellId_CDMA2000", HFILL }},
    { &hf_lte_rrc_measResult_03,
      { "measResult", "lte-rrc.measResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_measResult_03", HFILL }},
    { &hf_lte_rrc_pilotPnPhase,
      { "pilotPnPhase", "lte-rrc.pilotPnPhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_32767", HFILL }},
    { &hf_lte_rrc_pilotStrength,
      { "pilotStrength", "lte-rrc.pilotStrength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_63", HFILL }},
    { &hf_lte_rrc_PLMN_IdentityList2_item,
      { "PLMN-IdentityList2 item", "lte-rrc.PLMN_IdentityList2_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PLMN_IdentityList2_item", HFILL }},
    { &hf_lte_rrc_measObjectToRemoveList,
      { "measObjectToRemoveList", "lte-rrc.measObjectToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasObjectToRemoveList", HFILL }},
    { &hf_lte_rrc_measObjectToAddModifyList,
      { "measObjectToAddModifyList", "lte-rrc.measObjectToAddModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasObjectToAddModifyList", HFILL }},
    { &hf_lte_rrc_reportConfigToRemoveList,
      { "reportConfigToRemoveList", "lte-rrc.reportConfigToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ReportConfigToRemoveList", HFILL }},
    { &hf_lte_rrc_reportConfigToAddModifyList,
      { "reportConfigToAddModifyList", "lte-rrc.reportConfigToAddModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ReportConfigToAddModifyList", HFILL }},
    { &hf_lte_rrc_measIdToRemoveList,
      { "measIdToRemoveList", "lte-rrc.measIdToRemoveList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasIdToRemoveList", HFILL }},
    { &hf_lte_rrc_measIdToAddModifyList,
      { "measIdToAddModifyList", "lte-rrc.measIdToAddModifyList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasIdToAddModifyList", HFILL }},
    { &hf_lte_rrc_quantityConfig,
      { "quantityConfig", "lte-rrc.quantityConfig",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.QuantityConfig", HFILL }},
    { &hf_lte_rrc_measGapConfig,
      { "measGapConfig", "lte-rrc.measGapConfig",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasGapConfig", HFILL }},
    { &hf_lte_rrc_s_Measure,
      { "s-Measure", "lte-rrc.s_Measure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.RSRP_Range", HFILL }},
    { &hf_lte_rrc_speedDependentParameters,
      { "speedDependentParameters", "lte-rrc.speedDependentParameters",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_speedDependentParameters_vals), 0,
        "lte_rrc.T_speedDependentParameters", HFILL }},
    { &hf_lte_rrc_enable_11,
      { "enable", "lte-rrc.enable",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_enable_11", HFILL }},
    { &hf_lte_rrc_speedDependentScalingParameters_06,
      { "speedDependentScalingParameters", "lte-rrc.speedDependentScalingParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ConnectedModeSpeedDependentScalingParameters", HFILL }},
    { &hf_lte_rrc_MeasIdToRemoveList_item,
      { "MeasIdToRemoveList item", "lte-rrc.MeasIdToRemoveList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasIdToRemoveList_item", HFILL }},
    { &hf_lte_rrc_MeasIdToAddModifyList_item,
      { "MeasIdToAddModifyList item", "lte-rrc.MeasIdToAddModifyList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasIdToAddModifyList_item", HFILL }},
    { &hf_lte_rrc_measObjectId,
      { "measObjectId", "lte-rrc.measObjectId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasObjectId", HFILL }},
    { &hf_lte_rrc_reportConfigId,
      { "reportConfigId", "lte-rrc.reportConfigId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ReportConfigId", HFILL }},
    { &hf_lte_rrc_MeasObjectToRemoveList_item,
      { "MeasObjectToRemoveList item", "lte-rrc.MeasObjectToRemoveList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasObjectToRemoveList_item", HFILL }},
    { &hf_lte_rrc_MeasObjectToAddModifyList_item,
      { "MeasObjectToAddModifyList item", "lte-rrc.MeasObjectToAddModifyList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasObjectToAddModifyList_item", HFILL }},
    { &hf_lte_rrc_measObject,
      { "measObject", "lte-rrc.measObject",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_measObject_vals), 0,
        "lte_rrc.T_measObject", HFILL }},
    { &hf_lte_rrc_measObjectEUTRA,
      { "measObjectEUTRA", "lte-rrc.measObjectEUTRA",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasObjectEUTRA", HFILL }},
    { &hf_lte_rrc_measObjectUTRA,
      { "measObjectUTRA", "lte-rrc.measObjectUTRA",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasObjectUTRA", HFILL }},
    { &hf_lte_rrc_measObjectGERAN,
      { "measObjectGERAN", "lte-rrc.measObjectGERAN",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasObjectGERAN", HFILL }},
    { &hf_lte_rrc_measObjectCDMA2000,
      { "measObjectCDMA2000", "lte-rrc.measObjectCDMA2000",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasObjectCDMA2000", HFILL }},
    { &hf_lte_rrc_ReportConfigToRemoveList_item,
      { "ReportConfigToRemoveList item", "lte-rrc.ReportConfigToRemoveList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ReportConfigToRemoveList_item", HFILL }},
    { &hf_lte_rrc_ReportConfigToAddModifyList_item,
      { "ReportConfigToAddModifyList item", "lte-rrc.ReportConfigToAddModifyList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ReportConfigToAddModifyList_item", HFILL }},
    { &hf_lte_rrc_reportConfig,
      { "reportConfig", "lte-rrc.reportConfig",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_reportConfig_vals), 0,
        "lte_rrc.T_reportConfig", HFILL }},
    { &hf_lte_rrc_reportConfigEUTRA,
      { "reportConfigEUTRA", "lte-rrc.reportConfigEUTRA",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ReportConfigEUTRA", HFILL }},
    { &hf_lte_rrc_reportConfigInterRAT,
      { "reportConfigInterRAT", "lte-rrc.reportConfigInterRAT",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ReportConfigInterRAT", HFILL }},
    { &hf_lte_rrc_quantityConfigEUTRA,
      { "quantityConfigEUTRA", "lte-rrc.quantityConfigEUTRA",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.QuantityConfigEUTRA", HFILL }},
    { &hf_lte_rrc_quantityConfigUTRA,
      { "quantityConfigUTRA", "lte-rrc.quantityConfigUTRA",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.QuantityConfigUTRA", HFILL }},
    { &hf_lte_rrc_quantityConfigGERAN,
      { "quantityConfigGERAN", "lte-rrc.quantityConfigGERAN",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.QuantityConfigGERAN", HFILL }},
    { &hf_lte_rrc_quantityConfigCDMA2000,
      { "quantityConfigCDMA2000", "lte-rrc.quantityConfigCDMA2000",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.QuantityConfigCDMA2000", HFILL }},
    { &hf_lte_rrc_filterCoefficientRSRP,
      { "filterCoefficientRSRP", "lte-rrc.filterCoefficientRSRP",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_FilterCoefficient_vals), 0,
        "lte_rrc.FilterCoefficient", HFILL }},
    { &hf_lte_rrc_filterCoefficientRSRQ,
      { "filterCoefficientRSRQ", "lte-rrc.filterCoefficientRSRQ",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_FilterCoefficient_vals), 0,
        "lte_rrc.FilterCoefficient", HFILL }},
    { &hf_lte_rrc_measQuantityUTRA_FDD,
      { "measQuantityUTRA-FDD", "lte-rrc.measQuantityUTRA_FDD",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_measQuantityUTRA_FDD_vals), 0,
        "lte_rrc.T_measQuantityUTRA_FDD", HFILL }},
    { &hf_lte_rrc_measQuantityUTRA_TDD,
      { "measQuantityUTRA-TDD", "lte-rrc.measQuantityUTRA_TDD",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_measQuantityUTRA_TDD_vals), 0,
        "lte_rrc.T_measQuantityUTRA_TDD", HFILL }},
    { &hf_lte_rrc_filterCoefficient,
      { "filterCoefficient", "lte-rrc.filterCoefficient",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_FilterCoefficient_vals), 0,
        "lte_rrc.FilterCoefficient", HFILL }},
    { &hf_lte_rrc_measQuantityGERAN,
      { "measQuantityGERAN", "lte-rrc.measQuantityGERAN",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_measQuantityGERAN_vals), 0,
        "lte_rrc.T_measQuantityGERAN", HFILL }},
    { &hf_lte_rrc_measQuantityCDMA2000,
      { "measQuantityCDMA2000", "lte-rrc.measQuantityCDMA2000",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_measQuantityCDMA2000_vals), 0,
        "lte_rrc.T_measQuantityCDMA2000", HFILL }},
    { &hf_lte_rrc_triggerType,
      { "triggerType", "lte-rrc.triggerType",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_triggerType_vals), 0,
        "lte_rrc.T_triggerType", HFILL }},
    { &hf_lte_rrc_event,
      { "event", "lte-rrc.event",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_event", HFILL }},
    { &hf_lte_rrc_eventId,
      { "eventId", "lte-rrc.eventId",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_eventId_vals), 0,
        "lte_rrc.T_eventId", HFILL }},
    { &hf_lte_rrc_eventA1,
      { "eventA1", "lte-rrc.eventA1",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_eventA1", HFILL }},
    { &hf_lte_rrc_a1_Threshold,
      { "a1-Threshold", "lte-rrc.a1_Threshold",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ThresholdEUTRA_vals), 0,
        "lte_rrc.ThresholdEUTRA", HFILL }},
    { &hf_lte_rrc_eventA2,
      { "eventA2", "lte-rrc.eventA2",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_eventA2", HFILL }},
    { &hf_lte_rrc_a2_Threshold,
      { "a2-Threshold", "lte-rrc.a2_Threshold",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ThresholdEUTRA_vals), 0,
        "lte_rrc.ThresholdEUTRA", HFILL }},
    { &hf_lte_rrc_eventA3,
      { "eventA3", "lte-rrc.eventA3",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_eventA3", HFILL }},
    { &hf_lte_rrc_a3_Offset,
      { "a3-Offset", "lte-rrc.a3_Offset",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M30_30", HFILL }},
    { &hf_lte_rrc_reportOnLeave,
      { "reportOnLeave", "lte-rrc.reportOnLeave",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_eventA4,
      { "eventA4", "lte-rrc.eventA4",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_eventA4", HFILL }},
    { &hf_lte_rrc_a4_Threshold,
      { "a4-Threshold", "lte-rrc.a4_Threshold",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ThresholdEUTRA_vals), 0,
        "lte_rrc.ThresholdEUTRA", HFILL }},
    { &hf_lte_rrc_eventA5,
      { "eventA5", "lte-rrc.eventA5",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_eventA5", HFILL }},
    { &hf_lte_rrc_a5_Threshold1,
      { "a5-Threshold1", "lte-rrc.a5_Threshold1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ThresholdEUTRA_vals), 0,
        "lte_rrc.ThresholdEUTRA", HFILL }},
    { &hf_lte_rrc_a5_Threshold2,
      { "a5-Threshold2", "lte-rrc.a5_Threshold2",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ThresholdEUTRA_vals), 0,
        "lte_rrc.ThresholdEUTRA", HFILL }},
    { &hf_lte_rrc_hysteresis,
      { "hysteresis", "lte-rrc.hysteresis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_30", HFILL }},
    { &hf_lte_rrc_timeToTrigger,
      { "timeToTrigger", "lte-rrc.timeToTrigger",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_TimeToTrigger_vals), 0,
        "lte_rrc.TimeToTrigger", HFILL }},
    { &hf_lte_rrc_periodical,
      { "periodical", "lte-rrc.periodical",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_periodical", HFILL }},
    { &hf_lte_rrc_purpose_01,
      { "purpose", "lte-rrc.purpose",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_purpose_01_vals), 0,
        "lte_rrc.T_purpose_01", HFILL }},
    { &hf_lte_rrc_reportStrongestCells,
      { "reportStrongestCells", "lte-rrc.reportStrongestCells",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_reportCGI,
      { "reportCGI", "lte-rrc.reportCGI",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_triggerQuantity,
      { "triggerQuantity", "lte-rrc.triggerQuantity",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_triggerQuantity_vals), 0,
        "lte_rrc.T_triggerQuantity", HFILL }},
    { &hf_lte_rrc_reportQuantity,
      { "reportQuantity", "lte-rrc.reportQuantity",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_reportQuantity_vals), 0,
        "lte_rrc.T_reportQuantity", HFILL }},
    { &hf_lte_rrc_maxReportCells,
      { "maxReportCells", "lte-rrc.maxReportCells",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_maxCellReport", HFILL }},
    { &hf_lte_rrc_reportInterval,
      { "reportInterval", "lte-rrc.reportInterval",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ReportInterval_vals), 0,
        "lte_rrc.ReportInterval", HFILL }},
    { &hf_lte_rrc_reportAmount,
      { "reportAmount", "lte-rrc.reportAmount",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_reportAmount_vals), 0,
        "lte_rrc.T_reportAmount", HFILL }},
    { &hf_lte_rrc_threshold_RSRP,
      { "threshold-RSRP", "lte-rrc.threshold_RSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.RSRP_Range", HFILL }},
    { &hf_lte_rrc_threshold_RSRQ,
      { "threshold-RSRQ", "lte-rrc.threshold_RSRQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.RSRQ_Range", HFILL }},
    { &hf_lte_rrc_triggerType_01,
      { "triggerType", "lte-rrc.triggerType",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_triggerType_01_vals), 0,
        "lte_rrc.T_triggerType_01", HFILL }},
    { &hf_lte_rrc_event_01,
      { "event", "lte-rrc.event",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_event_01", HFILL }},
    { &hf_lte_rrc_eventId_01,
      { "eventId", "lte-rrc.eventId",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_eventId_01_vals), 0,
        "lte_rrc.T_eventId_01", HFILL }},
    { &hf_lte_rrc_eventB1,
      { "eventB1", "lte-rrc.eventB1",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_eventB1", HFILL }},
    { &hf_lte_rrc_b1_Threshold,
      { "b1-Threshold", "lte-rrc.b1_Threshold",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_b1_Threshold_vals), 0,
        "lte_rrc.T_b1_Threshold", HFILL }},
    { &hf_lte_rrc_b1_Threshold_CDMA2000,
      { "b1-Threshold-CDMA2000", "lte-rrc.b1_Threshold_CDMA2000",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_63", HFILL }},
    { &hf_lte_rrc_b1_Threshold_UTRA,
      { "b1-Threshold-UTRA", "lte-rrc.b1_Threshold_UTRA",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ThresholdUTRA_vals), 0,
        "lte_rrc.ThresholdUTRA", HFILL }},
    { &hf_lte_rrc_b1_Threshold_GERAN,
      { "b1-Threshold-GERAN", "lte-rrc.b1_Threshold_GERAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ThresholdGERAN", HFILL }},
    { &hf_lte_rrc_eventB2,
      { "eventB2", "lte-rrc.eventB2",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_eventB2", HFILL }},
    { &hf_lte_rrc_b2_Threshold1,
      { "b2-Threshold1", "lte-rrc.b2_Threshold1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ThresholdEUTRA_vals), 0,
        "lte_rrc.ThresholdEUTRA", HFILL }},
    { &hf_lte_rrc_b2_Threshold2,
      { "b2-Threshold2", "lte-rrc.b2_Threshold2",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_b2_Threshold2_vals), 0,
        "lte_rrc.T_b2_Threshold2", HFILL }},
    { &hf_lte_rrc_b2_Threshold2_CDMA2000,
      { "b2-Threshold2-CDMA2000", "lte-rrc.b2_Threshold2_CDMA2000",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_63", HFILL }},
    { &hf_lte_rrc_b2_Threshold2_UTRA,
      { "b2-Threshold2-UTRA", "lte-rrc.b2_Threshold2_UTRA",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_ThresholdUTRA_vals), 0,
        "lte_rrc.ThresholdUTRA", HFILL }},
    { &hf_lte_rrc_b2_Threshold2_GERAN,
      { "b2-Threshold2-GERAN", "lte-rrc.b2_Threshold2_GERAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ThresholdGERAN", HFILL }},
    { &hf_lte_rrc_periodical_01,
      { "periodical", "lte-rrc.periodical",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_periodical_01", HFILL }},
    { &hf_lte_rrc_purpose_02,
      { "purpose", "lte-rrc.purpose",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_purpose_02_vals), 0,
        "lte_rrc.T_purpose_02", HFILL }},
    { &hf_lte_rrc_reportStrongestCellsForSON,
      { "reportStrongestCellsForSON", "lte-rrc.reportStrongestCellsForSON",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.NULL", HFILL }},
    { &hf_lte_rrc_reportAmount_01,
      { "reportAmount", "lte-rrc.reportAmount",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_reportAmount_01_vals), 0,
        "lte_rrc.T_reportAmount_01", HFILL }},
    { &hf_lte_rrc_thresholdUTRA_RSCP,
      { "thresholdUTRA-RSCP", "lte-rrc.thresholdUTRA_RSCP",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_M5_91", HFILL }},
    { &hf_lte_rrc_thresholdUTRA_EcNO,
      { "thresholdUTRA-EcNO", "lte-rrc.thresholdUTRA_EcNO",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_0_49", HFILL }},
    { &hf_lte_rrc_IMSI_item,
      { "IMSI-Digit", "lte-rrc.IMSI_Digit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.IMSI_Digit", HFILL }},
    { &hf_lte_rrc_m_TMSI,
      { "m-TMSI", "lte-rrc.m_TMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.BIT_STRING_SIZE_32", HFILL }},
    { &hf_lte_rrc_accessStratumRelease,
      { "accessStratumRelease", "lte-rrc.accessStratumRelease",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_AccessStratumRelease_vals), 0,
        "lte_rrc.AccessStratumRelease", HFILL }},
    { &hf_lte_rrc_ue_Category,
      { "ue-Category", "lte-rrc.ue_Category",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_16", HFILL }},
    { &hf_lte_rrc_pdcp_Parameters,
      { "pdcp-Parameters", "lte-rrc.pdcp_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PDCP_Parameters", HFILL }},
    { &hf_lte_rrc_phyLayerParameters,
      { "phyLayerParameters", "lte-rrc.phyLayerParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.PhyLayerParameters", HFILL }},
    { &hf_lte_rrc_rf_Parameters,
      { "rf-Parameters", "lte-rrc.rf_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RF_Parameters", HFILL }},
    { &hf_lte_rrc_measurementParameters,
      { "measurementParameters", "lte-rrc.measurementParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasurementParameters", HFILL }},
    { &hf_lte_rrc_interRAT_Parameters,
      { "interRAT-Parameters", "lte-rrc.interRAT_Parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_interRAT_Parameters", HFILL }},
    { &hf_lte_rrc_utraFDD,
      { "utraFDD", "lte-rrc.utraFDD",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.IRAT_UTRA_FDD_Parameters", HFILL }},
    { &hf_lte_rrc_utraTDD128,
      { "utraTDD128", "lte-rrc.utraTDD128",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.IRAT_UTRA_TDD128_Parameters", HFILL }},
    { &hf_lte_rrc_utraTDD384,
      { "utraTDD384", "lte-rrc.utraTDD384",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.IRAT_UTRA_TDD384_Parameters", HFILL }},
    { &hf_lte_rrc_utraTDD768,
      { "utraTDD768", "lte-rrc.utraTDD768",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.IRAT_UTRA_TDD768_Parameters", HFILL }},
    { &hf_lte_rrc_geran_02,
      { "geran", "lte-rrc.geran",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.IRAT_GERAN_Parameters", HFILL }},
    { &hf_lte_rrc_cdma2000_HRPD_01,
      { "cdma2000-HRPD", "lte-rrc.cdma2000_HRPD",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.IRAT_CDMA2000_HRPD_Parameters", HFILL }},
    { &hf_lte_rrc_cdma2000_1xRTT_01,
      { "cdma2000-1xRTT", "lte-rrc.cdma2000_1xRTT",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.IRAT_CDMA2000_1xRTT_Parameters", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_27,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_27", HFILL }},
    { &hf_lte_rrc_supportedROHCprofiles,
      { "supportedROHCprofiles", "lte-rrc.supportedROHCprofiles",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_supportedROHCprofiles", HFILL }},
    { &hf_lte_rrc_maxNumberROHC_ContextSessions,
      { "maxNumberROHC-ContextSessions", "lte-rrc.maxNumberROHC_ContextSessions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_maxNumberROHC_ContextSessions_vals), 0,
        "lte_rrc.T_maxNumberROHC_ContextSessions", HFILL }},
    { &hf_lte_rrc_ue_TxAntennaSelectionSupported,
      { "ue-TxAntennaSelectionSupported", "lte-rrc.ue_TxAntennaSelectionSupported",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_ue_SpecificRefSigsSupported,
      { "ue-SpecificRefSigsSupported", "lte-rrc.ue_SpecificRefSigsSupported",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_supportedEUTRA_BandList,
      { "supportedEUTRA-BandList", "lte-rrc.supportedEUTRA_BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SupportedEUTRA_BandList", HFILL }},
    { &hf_lte_rrc_SupportedEUTRA_BandList_item,
      { "SupportedEUTRA-BandList item", "lte-rrc.SupportedEUTRA_BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SupportedEUTRA_BandList_item", HFILL }},
    { &hf_lte_rrc_eutra_Band,
      { "eutra-Band", "lte-rrc.eutra_Band",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER_1_64", HFILL }},
    { &hf_lte_rrc_halfDuplex,
      { "halfDuplex", "lte-rrc.halfDuplex",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_eutra_BandList,
      { "eutra-BandList", "lte-rrc.eutra_BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.EUTRA_BandList", HFILL }},
    { &hf_lte_rrc_EUTRA_BandList_item,
      { "EUTRA-BandList item", "lte-rrc.EUTRA_BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.EUTRA_BandList_item", HFILL }},
    { &hf_lte_rrc_interFreqEUTRA_BandList,
      { "interFreqEUTRA-BandList", "lte-rrc.interFreqEUTRA_BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.InterFreqEUTRA_BandList", HFILL }},
    { &hf_lte_rrc_interRAT_BandList,
      { "interRAT-BandList", "lte-rrc.interRAT_BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.InterRAT_BandList", HFILL }},
    { &hf_lte_rrc_InterFreqEUTRA_BandList_item,
      { "InterFreqEUTRA-BandList item", "lte-rrc.InterFreqEUTRA_BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.InterFreqEUTRA_BandList_item", HFILL }},
    { &hf_lte_rrc_interFreqNeedForGaps,
      { "interFreqNeedForGaps", "lte-rrc.interFreqNeedForGaps",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_InterRAT_BandList_item,
      { "InterRAT-BandList item", "lte-rrc.InterRAT_BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.InterRAT_BandList_item", HFILL }},
    { &hf_lte_rrc_interRAT_NeedForGaps,
      { "interRAT-NeedForGaps", "lte-rrc.interRAT_NeedForGaps",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_supportedUTRA_FDD_BandList,
      { "supportedUTRA-FDD-BandList", "lte-rrc.supportedUTRA_FDD_BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SupportedUTRA_FDD_BandList", HFILL }},
    { &hf_lte_rrc_SupportedUTRA_FDD_BandList_item,
      { "SupportedUTRA-FDD-BandList item", "lte-rrc.SupportedUTRA_FDD_BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SupportedUTRA_FDD_BandList_item", HFILL }},
    { &hf_lte_rrc_utra_FDD_Band,
      { "utra-FDD-Band", "lte-rrc.utra_FDD_Band",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_utra_FDD_Band_vals), 0,
        "lte_rrc.T_utra_FDD_Band", HFILL }},
    { &hf_lte_rrc_supportedUTRA_TDD128BandList,
      { "supportedUTRA-TDD128BandList", "lte-rrc.supportedUTRA_TDD128BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SupportedUTRA_TDD128BandList", HFILL }},
    { &hf_lte_rrc_SupportedUTRA_TDD128BandList_item,
      { "SupportedUTRA-TDD128BandList item", "lte-rrc.SupportedUTRA_TDD128BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SupportedUTRA_TDD128BandList_item", HFILL }},
    { &hf_lte_rrc_utra_TDD128Band,
      { "utra-TDD128Band", "lte-rrc.utra_TDD128Band",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_utra_TDD128Band_vals), 0,
        "lte_rrc.T_utra_TDD128Band", HFILL }},
    { &hf_lte_rrc_supportedUTRA_TDD384BandList,
      { "supportedUTRA-TDD384BandList", "lte-rrc.supportedUTRA_TDD384BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SupportedUTRA_TDD384BandList", HFILL }},
    { &hf_lte_rrc_SupportedUTRA_TDD384BandList_item,
      { "SupportedUTRA-TDD384BandList item", "lte-rrc.SupportedUTRA_TDD384BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SupportedUTRA_TDD384BandList_item", HFILL }},
    { &hf_lte_rrc_utra_TDD384Band,
      { "utra-TDD384Band", "lte-rrc.utra_TDD384Band",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_utra_TDD384Band_vals), 0,
        "lte_rrc.T_utra_TDD384Band", HFILL }},
    { &hf_lte_rrc_supportedUTRA_TDD768BandList,
      { "supportedUTRA-TDD768BandList", "lte-rrc.supportedUTRA_TDD768BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SupportedUTRA_TDD768BandList", HFILL }},
    { &hf_lte_rrc_SupportedUTRA_TDD768BandList_item,
      { "SupportedUTRA-TDD768BandList item", "lte-rrc.SupportedUTRA_TDD768BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SupportedUTRA_TDD768BandList_item", HFILL }},
    { &hf_lte_rrc_utra_TDD768Band,
      { "utra-TDD768Band", "lte-rrc.utra_TDD768Band",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_utra_TDD768Band_vals), 0,
        "lte_rrc.T_utra_TDD768Band", HFILL }},
    { &hf_lte_rrc_supportedGERAN_BandList,
      { "supportedGERAN-BandList", "lte-rrc.supportedGERAN_BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SupportedGERAN_BandList", HFILL }},
    { &hf_lte_rrc_interRAT_PS_HO_ToGERAN,
      { "interRAT-PS-HO-ToGERAN", "lte-rrc.interRAT_PS_HO_ToGERAN",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "lte_rrc.BOOLEAN", HFILL }},
    { &hf_lte_rrc_SupportedGERAN_BandList_item,
      { "SupportedGERAN-BandList item", "lte-rrc.SupportedGERAN_BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SupportedGERAN_BandList_item", HFILL }},
    { &hf_lte_rrc_geran_Band,
      { "geran-Band", "lte-rrc.geran_Band",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_geran_Band_vals), 0,
        "lte_rrc.T_geran_Band", HFILL }},
    { &hf_lte_rrc_supportedHRPD_BandList,
      { "supportedHRPD-BandList", "lte-rrc.supportedHRPD_BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.SupportedHRPD_BandList", HFILL }},
    { &hf_lte_rrc_cdma2000_HRPD_TxConfig,
      { "cdma2000-HRPD-TxConfig", "lte-rrc.cdma2000_HRPD_TxConfig",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cdma2000_HRPD_TxConfig_vals), 0,
        "lte_rrc.T_cdma2000_HRPD_TxConfig", HFILL }},
    { &hf_lte_rrc_cdma2000_HRPD_RxConfig,
      { "cdma2000-HRPD-RxConfig", "lte-rrc.cdma2000_HRPD_RxConfig",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cdma2000_HRPD_RxConfig_vals), 0,
        "lte_rrc.T_cdma2000_HRPD_RxConfig", HFILL }},
    { &hf_lte_rrc_SupportedHRPD_BandList_item,
      { "SupportedHRPD-BandList item", "lte-rrc.SupportedHRPD_BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SupportedHRPD_BandList_item", HFILL }},
    { &hf_lte_rrc_cdma2000_HRPD_Band,
      { "cdma2000-HRPD-Band", "lte-rrc.cdma2000_HRPD_Band",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_CDMA2000_Bandclass_vals), 0,
        "lte_rrc.CDMA2000_Bandclass", HFILL }},
    { &hf_lte_rrc_supported1xRTT_BandList,
      { "supported1xRTT-BandList", "lte-rrc.supported1xRTT_BandList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.Supported1xRTT_BandList", HFILL }},
    { &hf_lte_rrc_cdma2000_1xRTT_TxConfig,
      { "cdma2000-1xRTT-TxConfig", "lte-rrc.cdma2000_1xRTT_TxConfig",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cdma2000_1xRTT_TxConfig_vals), 0,
        "lte_rrc.T_cdma2000_1xRTT_TxConfig", HFILL }},
    { &hf_lte_rrc_cdma2000_1xRTT_RxConfig,
      { "cdma2000-1xRTT-RxConfig", "lte-rrc.cdma2000_1xRTT_RxConfig",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_cdma2000_1xRTT_RxConfig_vals), 0,
        "lte_rrc.T_cdma2000_1xRTT_RxConfig", HFILL }},
    { &hf_lte_rrc_Supported1xRTT_BandList_item,
      { "Supported1xRTT-BandList item", "lte-rrc.Supported1xRTT_BandList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.Supported1xRTT_BandList_item", HFILL }},
    { &hf_lte_rrc_cdma2000_1xRTT_Band,
      { "cdma2000-1xRTT-Band", "lte-rrc.cdma2000_1xRTT_Band",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_CDMA2000_Bandclass_vals), 0,
        "lte_rrc.CDMA2000_Bandclass", HFILL }},
    { &hf_lte_rrc_t300,
      { "t300", "lte-rrc.t300",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t300_vals), 0,
        "lte_rrc.T_t300", HFILL }},
    { &hf_lte_rrc_t301,
      { "t301", "lte-rrc.t301",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t301_vals), 0,
        "lte_rrc.T_t301", HFILL }},
    { &hf_lte_rrc_t310,
      { "t310", "lte-rrc.t310",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t310_vals), 0,
        "lte_rrc.T_t310", HFILL }},
    { &hf_lte_rrc_n310,
      { "n310", "lte-rrc.n310",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_n310_vals), 0,
        "lte_rrc.T_n310", HFILL }},
    { &hf_lte_rrc_t311,
      { "t311", "lte-rrc.t311",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_t311_vals), 0,
        "lte_rrc.T_t311", HFILL }},
    { &hf_lte_rrc_n311,
      { "n311", "lte-rrc.n311",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_n311_vals), 0,
        "lte_rrc.T_n311", HFILL }},
    { &hf_lte_rrc_measIdList,
      { "measIdList", "lte-rrc.measIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasIdToAddModifyList", HFILL }},
    { &hf_lte_rrc_measObjectList,
      { "measObjectList", "lte-rrc.measObjectList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.MeasObjectToAddModifyList", HFILL }},
    { &hf_lte_rrc_reportConfigList,
      { "reportConfigList", "lte-rrc.reportConfigList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.ReportConfigToAddModifyList", HFILL }},
    { &hf_lte_rrc_speedDependentParameters_01,
      { "speedDependentParameters", "lte-rrc.speedDependentParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_speedDependentParameters_01", HFILL }},
    { &hf_lte_rrc_VarMeasurementReports_item,
      { "VarMeasurementReports item", "lte-rrc.VarMeasurementReports_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.VarMeasurementReports_item", HFILL }},
    { &hf_lte_rrc_cellsTriggeredList,
      { "cellsTriggeredList", "lte-rrc.cellsTriggeredList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.CellsTriggeredList", HFILL }},
    { &hf_lte_rrc_numberOfReportsSent,
      { "numberOfReportsSent", "lte-rrc.numberOfReportsSent",
        FT_INT32, BASE_DEC, NULL, 0,
        "lte_rrc.INTEGER", HFILL }},
    { &hf_lte_rrc_CellsTriggeredList_item,
      { "CellsTriggeredList item", "lte-rrc.CellsTriggeredList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.CellsTriggeredList_item", HFILL }},
    { &hf_lte_rrc_message_07,
      { "message", "lte-rrc.message",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_InterNode_MessageType_vals), 0,
        "lte_rrc.InterNode_MessageType", HFILL }},
    { &hf_lte_rrc_c1_22,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_22_vals), 0,
        "lte_rrc.T_c1_22", HFILL }},
    { &hf_lte_rrc_interRAT_Message,
      { "interRAT-Message", "lte-rrc.interRAT_Message",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.InterRAT_Message", HFILL }},
    { &hf_lte_rrc_handoverCommand,
      { "handoverCommand", "lte-rrc.handoverCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.HandoverCommand", HFILL }},
    { &hf_lte_rrc_handoverPreparationInformation,
      { "handoverPreparationInformation", "lte-rrc.handoverPreparationInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.HandoverPreparationInformation", HFILL }},
    { &hf_lte_rrc_ueRadioAccessCapabilityInformation,
      { "ueRadioAccessCapabilityInformation", "lte-rrc.ueRadioAccessCapabilityInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UERadioAccessCapabilityInformation", HFILL }},
    { &hf_lte_rrc_messageClassExtension_06,
      { "messageClassExtension", "lte-rrc.messageClassExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_messageClassExtension_06", HFILL }},
    { &hf_lte_rrc_criticalExtensions_27,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_27_vals), 0,
        "lte_rrc.T_criticalExtensions_27", HFILL }},
    { &hf_lte_rrc_c1_23,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_23_vals), 0,
        "lte_rrc.T_c1_23", HFILL }},
    { &hf_lte_rrc_interRAT_Message_r8,
      { "interRAT-Message-r8", "lte-rrc.interRAT_Message_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.InterRAT_Message_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_27,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_27", HFILL }},
    { &hf_lte_rrc_interRAT_Message_01,
      { "interRAT-Message", "lte-rrc.interRAT_Message",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_28,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_28", HFILL }},
    { &hf_lte_rrc_criticalExtensions_28,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_28_vals), 0,
        "lte_rrc.T_criticalExtensions_28", HFILL }},
    { &hf_lte_rrc_c1_24,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_24_vals), 0,
        "lte_rrc.T_c1_24", HFILL }},
    { &hf_lte_rrc_handoverCommand_r8,
      { "handoverCommand-r8", "lte-rrc.handoverCommand_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.HandoverCommand_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_28,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_28", HFILL }},
    { &hf_lte_rrc_handoverCommandMessage,
      { "handoverCommandMessage", "lte-rrc.handoverCommandMessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.T_handoverCommandMessage", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_29,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_29", HFILL }},
    { &hf_lte_rrc_criticalExtensions_29,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_29_vals), 0,
        "lte_rrc.T_criticalExtensions_29", HFILL }},
    { &hf_lte_rrc_c1_25,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_25_vals), 0,
        "lte_rrc.T_c1_25", HFILL }},
    { &hf_lte_rrc_handoverPreparationInformation_r8,
      { "handoverPreparationInformation-r8", "lte-rrc.handoverPreparationInformation_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.HandoverPreparationInformation_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_29,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_29", HFILL }},
    { &hf_lte_rrc_as_Configuration,
      { "as-Configuration", "lte-rrc.as_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.AS_Configuration", HFILL }},
    { &hf_lte_rrc_rrm_Configuration,
      { "rrm-Configuration", "lte-rrc.rrm_Configuration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RRM_Configuration", HFILL }},
    { &hf_lte_rrc_as_Context,
      { "as-Context", "lte-rrc.as_Context",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.AS_Context", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_30,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_30", HFILL }},
    { &hf_lte_rrc_criticalExtensions_30,
      { "criticalExtensions", "lte-rrc.criticalExtensions",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_criticalExtensions_30_vals), 0,
        "lte_rrc.T_criticalExtensions_30", HFILL }},
    { &hf_lte_rrc_c1_26,
      { "c1", "lte-rrc.c1",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_c1_26_vals), 0,
        "lte_rrc.T_c1_26", HFILL }},
    { &hf_lte_rrc_ueRadioAccessCapabilityInformation_r8,
      { "ueRadioAccessCapabilityInformation-r8", "lte-rrc.ueRadioAccessCapabilityInformation_r8",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.UERadioAccessCapabilityInformation_r8_IEs", HFILL }},
    { &hf_lte_rrc_criticalExtensionsFuture_30,
      { "criticalExtensionsFuture", "lte-rrc.criticalExtensionsFuture",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_criticalExtensionsFuture_30", HFILL }},
    { &hf_lte_rrc_ue_RadioAccessCapabilityInfo,
      { "ue-RadioAccessCapabilityInfo", "lte-rrc.ue_RadioAccessCapabilityInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.T_ue_RadioAccessCapabilityInfo", HFILL }},
    { &hf_lte_rrc_nonCriticalExtension_31,
      { "nonCriticalExtension", "lte-rrc.nonCriticalExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.T_nonCriticalExtension_31", HFILL }},
    { &hf_lte_rrc_sourceMeasurementConfiguration,
      { "sourceMeasurementConfiguration", "lte-rrc.sourceMeasurementConfiguration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MeasurementConfiguration", HFILL }},
    { &hf_lte_rrc_sourceRadioResourceConfiguration,
      { "sourceRadioResourceConfiguration", "lte-rrc.sourceRadioResourceConfiguration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.RadioResourceConfigDedicated", HFILL }},
    { &hf_lte_rrc_sourceSecurityConfiguration,
      { "sourceSecurityConfiguration", "lte-rrc.sourceSecurityConfiguration",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SecurityConfiguration", HFILL }},
    { &hf_lte_rrc_sourceUE_Identity,
      { "sourceUE-Identity", "lte-rrc.sourceUE_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.C_RNTI", HFILL }},
    { &hf_lte_rrc_sourceMasterInformationBlock,
      { "sourceMasterInformationBlock", "lte-rrc.sourceMasterInformationBlock",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.MasterInformationBlock", HFILL }},
    { &hf_lte_rrc_sourceSystemInformationBlockType1,
      { "sourceSystemInformationBlockType1", "lte-rrc.sourceSystemInformationBlockType1",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType1", HFILL }},
    { &hf_lte_rrc_sourceSystemInformationBlockType2,
      { "sourceSystemInformationBlockType2", "lte-rrc.sourceSystemInformationBlockType2",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.SystemInformationBlockType2", HFILL }},
    { &hf_lte_rrc_ue_RadioAccessCapabilityInfo_01,
      { "ue-RadioAccessCapabilityInfo", "lte-rrc.ue_RadioAccessCapabilityInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.T_ue_RadioAccessCapabilityInfo_01", HFILL }},
    { &hf_lte_rrc_ue_SecurityCapabilityInfo,
      { "ue-SecurityCapabilityInfo", "lte-rrc.ue_SecurityCapabilityInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.OCTET_STRING", HFILL }},
    { &hf_lte_rrc_reestablishmentInfo,
      { "reestablishmentInfo", "lte-rrc.reestablishmentInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.ReestablishmentInfo", HFILL }},
    { &hf_lte_rrc_sourcePhysicalCellIdentity,
      { "sourcePhysicalCellIdentity", "lte-rrc.sourcePhysicalCellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.PhysicalCellIdentity", HFILL }},
    { &hf_lte_rrc_targetCellShortMAC_I,
      { "targetCellShortMAC-I", "lte-rrc.targetCellShortMAC_I",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.ShortMAC_I", HFILL }},
    { &hf_lte_rrc_additionalReestabInfoList,
      { "additionalReestabInfoList", "lte-rrc.additionalReestabInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "lte_rrc.AdditionalReestabInfoList", HFILL }},
    { &hf_lte_rrc_AdditionalReestabInfoList_item,
      { "AdditionalReestabInfoList item", "lte-rrc.AdditionalReestabInfoList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "lte_rrc.AdditionalReestabInfoList_item", HFILL }},
    { &hf_lte_rrc_key_eNodeB_Star,
      { "key-eNodeB-Star", "lte-rrc.key_eNodeB_Star",
        FT_BYTES, BASE_NONE, NULL, 0,
        "lte_rrc.Key_eNodeB_Star", HFILL }},
    { &hf_lte_rrc_ue_InactiveTime,
      { "ue-InactiveTime", "lte-rrc.ue_InactiveTime",
        FT_UINT32, BASE_DEC, VALS(lte_rrc_T_ue_InactiveTime_vals), 0,
        "lte_rrc.T_ue_InactiveTime", HFILL }},

/*--- End of included file: packet-lte-rrc-hfarr.c ---*/
#line 74 "packet-lte-rrc-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_lte_rrc,

/*--- Included file: packet-lte-rrc-ettarr.c ---*/
#line 1 "packet-lte-rrc-ettarr.c"
    &ett_lte_rrc_BCCH_BCH_Message,
    &ett_lte_rrc_BCCH_DL_SCH_Message,
    &ett_lte_rrc_BCCH_DL_SCH_MessageType,
    &ett_lte_rrc_T_c1,
    &ett_lte_rrc_T_messageClassExtension,
    &ett_lte_rrc_PCCH_Message,
    &ett_lte_rrc_PCCH_MessageType,
    &ett_lte_rrc_T_c1_01,
    &ett_lte_rrc_T_messageClassExtension_01,
    &ett_lte_rrc_DL_CCCH_Message,
    &ett_lte_rrc_DL_CCCH_MessageType,
    &ett_lte_rrc_T_c1_02,
    &ett_lte_rrc_T_messageClassExtension_02,
    &ett_lte_rrc_DL_DCCH_Message,
    &ett_lte_rrc_DL_DCCH_MessageType,
    &ett_lte_rrc_T_c1_03,
    &ett_lte_rrc_T_messageClassExtension_03,
    &ett_lte_rrc_UL_CCCH_Message,
    &ett_lte_rrc_UL_CCCH_MessageType,
    &ett_lte_rrc_T_c1_04,
    &ett_lte_rrc_T_messageClassExtension_04,
    &ett_lte_rrc_UL_DCCH_Message,
    &ett_lte_rrc_UL_DCCH_MessageType,
    &ett_lte_rrc_T_c1_05,
    &ett_lte_rrc_T_messageClassExtension_05,
    &ett_lte_rrc_CDMA2000_CSFBParametersRequest,
    &ett_lte_rrc_T_criticalExtensions,
    &ett_lte_rrc_T_criticalExtensionsFuture,
    &ett_lte_rrc_CDMA2000_CSFBParametersRequest_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension,
    &ett_lte_rrc_CDMA2000_CSFBParametersResponse,
    &ett_lte_rrc_T_criticalExtensions_01,
    &ett_lte_rrc_T_criticalExtensionsFuture_01,
    &ett_lte_rrc_CDMA2000_CSFBParametersResponse_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_01,
    &ett_lte_rrc_CounterCheck,
    &ett_lte_rrc_T_criticalExtensions_02,
    &ett_lte_rrc_T_c1_06,
    &ett_lte_rrc_T_criticalExtensionsFuture_02,
    &ett_lte_rrc_CounterCheck_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_02,
    &ett_lte_rrc_DRB_CountMSB_InfoList,
    &ett_lte_rrc_DRB_CountMSB_InfoList_item,
    &ett_lte_rrc_CounterCheckResponse,
    &ett_lte_rrc_T_criticalExtensions_03,
    &ett_lte_rrc_T_criticalExtensionsFuture_03,
    &ett_lte_rrc_CounterCheckResponse_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_03,
    &ett_lte_rrc_DRB_CountInfoList,
    &ett_lte_rrc_DRB_CountInfoList_item,
    &ett_lte_rrc_DLInformationTransfer,
    &ett_lte_rrc_T_criticalExtensions_04,
    &ett_lte_rrc_T_c1_07,
    &ett_lte_rrc_T_criticalExtensionsFuture_04,
    &ett_lte_rrc_DLInformationTransfer_r8_IEs,
    &ett_lte_rrc_T_informationType,
    &ett_lte_rrc_T_cdma2000,
    &ett_lte_rrc_T_nonCriticalExtension_04,
    &ett_lte_rrc_HandoverFromEUTRAPreparationRequest,
    &ett_lte_rrc_T_criticalExtensions_05,
    &ett_lte_rrc_T_c1_08,
    &ett_lte_rrc_T_criticalExtensionsFuture_05,
    &ett_lte_rrc_HandoverFromEUTRAPreparationRequest_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_05,
    &ett_lte_rrc_MasterInformationBlock,
    &ett_lte_rrc_MeasurementReport,
    &ett_lte_rrc_T_criticalExtensions_06,
    &ett_lte_rrc_T_c1_09,
    &ett_lte_rrc_T_criticalExtensionsFuture_06,
    &ett_lte_rrc_MeasurementReport_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_06,
    &ett_lte_rrc_MobilityFromEUTRACommand,
    &ett_lte_rrc_T_criticalExtensions_07,
    &ett_lte_rrc_T_c1_10,
    &ett_lte_rrc_T_criticalExtensionsFuture_07,
    &ett_lte_rrc_MobilityFromEUTRACommand_r8_IEs,
    &ett_lte_rrc_T_purpose,
    &ett_lte_rrc_T_nonCriticalExtension_07,
    &ett_lte_rrc_Handover,
    &ett_lte_rrc_CellChangeOrder,
    &ett_lte_rrc_T_targetRAT_Type_01,
    &ett_lte_rrc_T_geran,
    &ett_lte_rrc_T_geran_SystemInformation,
    &ett_lte_rrc_GERAN_SystemInformation,
    &ett_lte_rrc_Paging,
    &ett_lte_rrc_T_nonCriticalExtension_08,
    &ett_lte_rrc_PagingRecordList,
    &ett_lte_rrc_PagingRecord,
    &ett_lte_rrc_PagingUE_Identity,
    &ett_lte_rrc_RRCConnectionReconfiguration,
    &ett_lte_rrc_T_criticalExtensions_08,
    &ett_lte_rrc_T_c1_11,
    &ett_lte_rrc_T_criticalExtensionsFuture_08,
    &ett_lte_rrc_RRCConnectionReconfiguration_r8_IEs,
    &ett_lte_rrc_SEQUENCE_SIZE_1_maxDRB_OF_NAS_DedicatedInformation,
    &ett_lte_rrc_T_nonCriticalExtension_09,
    &ett_lte_rrc_RRCConnectionReconfigurationComplete,
    &ett_lte_rrc_T_criticalExtensions_09,
    &ett_lte_rrc_T_criticalExtensionsFuture_09,
    &ett_lte_rrc_RRCConnectionReconfigurationComplete_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_10,
    &ett_lte_rrc_RRCConnectionReestablishment,
    &ett_lte_rrc_T_criticalExtensions_10,
    &ett_lte_rrc_T_c1_12,
    &ett_lte_rrc_T_criticalExtensionsFuture_10,
    &ett_lte_rrc_RRCConnectionReestablishment_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_11,
    &ett_lte_rrc_RRCConnectionReestablishmentComplete,
    &ett_lte_rrc_T_criticalExtensions_11,
    &ett_lte_rrc_T_criticalExtensionsFuture_11,
    &ett_lte_rrc_RRCConnectionReestablishmentComplete_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_12,
    &ett_lte_rrc_RRCConnectionReestablishmentReject,
    &ett_lte_rrc_T_criticalExtensions_12,
    &ett_lte_rrc_T_criticalExtensionsFuture_12,
    &ett_lte_rrc_RRCConnectionReestablishmentReject_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_13,
    &ett_lte_rrc_RRCConnectionReestablishmentRequest,
    &ett_lte_rrc_T_criticalExtensions_13,
    &ett_lte_rrc_T_criticalExtensionsFuture_13,
    &ett_lte_rrc_RRCConnectionReestablishmentRequest_r8_IEs,
    &ett_lte_rrc_ReestabUE_Identity,
    &ett_lte_rrc_RRCConnectionReject,
    &ett_lte_rrc_T_criticalExtensions_14,
    &ett_lte_rrc_T_c1_13,
    &ett_lte_rrc_T_criticalExtensionsFuture_14,
    &ett_lte_rrc_RRCConnectionReject_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_14,
    &ett_lte_rrc_RRCConnectionRelease,
    &ett_lte_rrc_T_criticalExtensions_15,
    &ett_lte_rrc_T_c1_14,
    &ett_lte_rrc_T_criticalExtensionsFuture_15,
    &ett_lte_rrc_RRCConnectionRelease_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_15,
    &ett_lte_rrc_RedirectionInformation,
    &ett_lte_rrc_T_interRAT_target,
    &ett_lte_rrc_IdleModeMobilityControlInfo,
    &ett_lte_rrc_InterFreqPriorityList,
    &ett_lte_rrc_InterFreqPriorityList_item,
    &ett_lte_rrc_GERAN_FreqPriorityList,
    &ett_lte_rrc_GERAN_FreqPriorityList_item,
    &ett_lte_rrc_UTRA_FDD_FreqPriorityList,
    &ett_lte_rrc_UTRA_FDD_FreqPriorityList_item,
    &ett_lte_rrc_UTRA_TDD_FreqPriorityList,
    &ett_lte_rrc_UTRA_TDD_FreqPriorityList_item,
    &ett_lte_rrc_HRPD_BandClassPriorityList,
    &ett_lte_rrc_HRPD_BandClassPriorityList_item,
    &ett_lte_rrc_OneXRTT_BandClassPriorityList,
    &ett_lte_rrc_OneXRTT_BandClassPriorityList_item,
    &ett_lte_rrc_RRCConnectionRequest,
    &ett_lte_rrc_T_criticalExtensions_16,
    &ett_lte_rrc_T_criticalExtensionsFuture_16,
    &ett_lte_rrc_RRCConnectionRequest_r8_IEs,
    &ett_lte_rrc_InitialUE_Identity,
    &ett_lte_rrc_RRCConnectionSetup,
    &ett_lte_rrc_T_criticalExtensions_17,
    &ett_lte_rrc_T_c1_15,
    &ett_lte_rrc_T_criticalExtensionsFuture_17,
    &ett_lte_rrc_RRCConnectionSetup_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_16,
    &ett_lte_rrc_RRCConnectionSetupComplete,
    &ett_lte_rrc_T_criticalExtensions_18,
    &ett_lte_rrc_T_c1_16,
    &ett_lte_rrc_T_criticalExtensionsFuture_18,
    &ett_lte_rrc_RRCConnectionSetupComplete_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_17,
    &ett_lte_rrc_RegisteredMME,
    &ett_lte_rrc_SecurityModeCommand,
    &ett_lte_rrc_T_criticalExtensions_19,
    &ett_lte_rrc_T_c1_17,
    &ett_lte_rrc_T_criticalExtensionsFuture_19,
    &ett_lte_rrc_SecurityModeCommand_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_18,
    &ett_lte_rrc_SecurityModeComplete,
    &ett_lte_rrc_T_criticalExtensions_20,
    &ett_lte_rrc_T_criticalExtensionsFuture_20,
    &ett_lte_rrc_SecurityModeComplete_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_19,
    &ett_lte_rrc_SecurityModeFailure,
    &ett_lte_rrc_T_criticalExtensions_21,
    &ett_lte_rrc_T_criticalExtensionsFuture_21,
    &ett_lte_rrc_SecurityModeFailure_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_20,
    &ett_lte_rrc_SystemInformation,
    &ett_lte_rrc_T_criticalExtensions_22,
    &ett_lte_rrc_T_criticalExtensionsFuture_22,
    &ett_lte_rrc_SystemInformation_r8_IEs,
    &ett_lte_rrc_T_sib_TypeAndInfo,
    &ett_lte_rrc_T_sib_TypeAndInfo_item,
    &ett_lte_rrc_T_nonCriticalExtension_21,
    &ett_lte_rrc_SystemInformationBlockType1,
    &ett_lte_rrc_T_cellAccessRelatedInformation,
    &ett_lte_rrc_T_cellSelectionInfo,
    &ett_lte_rrc_T_nonCriticalExtension_22,
    &ett_lte_rrc_PLMN_IdentityList,
    &ett_lte_rrc_PLMN_IdentityList_item,
    &ett_lte_rrc_SchedulingInformation,
    &ett_lte_rrc_SchedulingInformation_item,
    &ett_lte_rrc_SIB_MappingInfo,
    &ett_lte_rrc_UECapabilityEnquiry,
    &ett_lte_rrc_T_criticalExtensions_23,
    &ett_lte_rrc_T_c1_18,
    &ett_lte_rrc_T_criticalExtensionsFuture_23,
    &ett_lte_rrc_UECapabilityEnquiry_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_23,
    &ett_lte_rrc_UE_RadioAccessCapRequest,
    &ett_lte_rrc_UECapabilityInformation,
    &ett_lte_rrc_T_criticalExtensions_24,
    &ett_lte_rrc_T_c1_19,
    &ett_lte_rrc_T_criticalExtensionsFuture_24,
    &ett_lte_rrc_UECapabilityInformation_r8_IEs,
    &ett_lte_rrc_UECapabilityInformation_r8_IEs_item,
    &ett_lte_rrc_T_nonCriticalExtension_24,
    &ett_lte_rrc_ULHandoverPreparationTransfer,
    &ett_lte_rrc_T_criticalExtensions_25,
    &ett_lte_rrc_T_c1_20,
    &ett_lte_rrc_T_criticalExtensionsFuture_25,
    &ett_lte_rrc_ULHandoverPreparationTransfer_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_25,
    &ett_lte_rrc_ULInformationTransfer,
    &ett_lte_rrc_T_criticalExtensions_26,
    &ett_lte_rrc_T_c1_21,
    &ett_lte_rrc_T_criticalExtensionsFuture_26,
    &ett_lte_rrc_ULInformationTransfer_r8_IEs,
    &ett_lte_rrc_T_informationType_01,
    &ett_lte_rrc_T_cdma2000_01,
    &ett_lte_rrc_T_nonCriticalExtension_26,
    &ett_lte_rrc_SystemInformationBlockType2,
    &ett_lte_rrc_T_accessBarringInformation,
    &ett_lte_rrc_T_frequencyInformation,
    &ett_lte_rrc_AccessClassBarringInformation,
    &ett_lte_rrc_AccessClassBarringList,
    &ett_lte_rrc_AccessClassBarringList_item,
    &ett_lte_rrc_MBSFN_SubframeConfiguration,
    &ett_lte_rrc_MBSFN_SubframeConfiguration_item,
    &ett_lte_rrc_T_subframeAllocation,
    &ett_lte_rrc_SystemInformationBlockType3,
    &ett_lte_rrc_T_cellReselectionInfoCommon,
    &ett_lte_rrc_T_speedDependentReselection,
    &ett_lte_rrc_T_speedDependentScalingParametersHyst,
    &ett_lte_rrc_T_cellReselectionServingFreqInfo,
    &ett_lte_rrc_T_intraFreqCellReselectionInfo,
    &ett_lte_rrc_T_speedDependentScalingParameters,
    &ett_lte_rrc_SystemInformationBlockType4,
    &ett_lte_rrc_IntraFreqNeighbouringCellList,
    &ett_lte_rrc_IntraFreqNeighbouringCellList_item,
    &ett_lte_rrc_IntraFreqBlacklistedCellList,
    &ett_lte_rrc_IntraFreqBlacklistedCellList_item,
    &ett_lte_rrc_SystemInformationBlockType5,
    &ett_lte_rrc_InterFreqCarrierFreqList,
    &ett_lte_rrc_InterFreqCarrierFreqList_item,
    &ett_lte_rrc_T_speedDependentScalingParameters_01,
    &ett_lte_rrc_InterFreqNeighbouringCellList,
    &ett_lte_rrc_InterFreqNeighbouringCellList_item,
    &ett_lte_rrc_InterFreqBlacklistedCellList,
    &ett_lte_rrc_InterFreqBlacklistedCellList_item,
    &ett_lte_rrc_SystemInformationBlockType6,
    &ett_lte_rrc_T_speedDependentScalingParameters_02,
    &ett_lte_rrc_UTRA_FDD_CarrierFreqList,
    &ett_lte_rrc_UTRA_FDD_CarrierFreqList_item,
    &ett_lte_rrc_UTRA_TDD_CarrierFreqList,
    &ett_lte_rrc_UTRA_TDD_CarrierFreqList_item,
    &ett_lte_rrc_SystemInformationBlockType7,
    &ett_lte_rrc_T_speedDependentScalingParameters_03,
    &ett_lte_rrc_GERAN_NeigbourFreqList,
    &ett_lte_rrc_GERAN_BCCH_Group,
    &ett_lte_rrc_T_geran_BCCH_Configuration,
    &ett_lte_rrc_SystemInformationBlockType8,
    &ett_lte_rrc_T_hrpd_Parameters,
    &ett_lte_rrc_T_hrpd_CellReselectionParameters,
    &ett_lte_rrc_T_speedDependentScalingParameters_04,
    &ett_lte_rrc_T_oneXRTT_Parameters,
    &ett_lte_rrc_T_oneXRTT_CellReselectionParameters,
    &ett_lte_rrc_T_speedDependentScalingParameters_05,
    &ett_lte_rrc_CDMA2000_NeighbourCellList,
    &ett_lte_rrc_CDMA2000_NeighbourCellList_item,
    &ett_lte_rrc_CDMA2000_NeighbourCellsPerBandclass,
    &ett_lte_rrc_CDMA2000_NeighbourCellsPerBandclass_item,
    &ett_lte_rrc_CDMA2000_CellIdList,
    &ett_lte_rrc_HRPD_BandClassList,
    &ett_lte_rrc_HRPD_BandClassList_item,
    &ett_lte_rrc_OneXRTT_BandClassList,
    &ett_lte_rrc_OneXRTT_BandClassList_item,
    &ett_lte_rrc_SystemInformationBlockType9,
    &ett_lte_rrc_SystemInformationBlockType10,
    &ett_lte_rrc_SystemInformationBlockType11,
    &ett_lte_rrc_AntennaInformationCommon,
    &ett_lte_rrc_AntennaInformationDedicated,
    &ett_lte_rrc_T_codebookSubsetRestriction,
    &ett_lte_rrc_T_ue_TransmitAntennaSelection,
    &ett_lte_rrc_CQI_Reporting,
    &ett_lte_rrc_CQI_ReportingPeriodic,
    &ett_lte_rrc_T_enable_01,
    &ett_lte_rrc_T_cqi_FormatIndicatorPeriodic,
    &ett_lte_rrc_T_subbandCQI,
    &ett_lte_rrc_LogicalChannelConfig,
    &ett_lte_rrc_T_ul_SpecificParameters,
    &ett_lte_rrc_MAC_MainConfiguration,
    &ett_lte_rrc_T_dl_SCH_Configuration,
    &ett_lte_rrc_T_ul_SCH_Configuration,
    &ett_lte_rrc_T_drx_Configuration,
    &ett_lte_rrc_T_enable_02,
    &ett_lte_rrc_T_longDRX_CycleStartOffset,
    &ett_lte_rrc_T_shortDRX,
    &ett_lte_rrc_T_enable_03,
    &ett_lte_rrc_T_phr_Configuration,
    &ett_lte_rrc_T_enable_04,
    &ett_lte_rrc_PDCP_Configuration,
    &ett_lte_rrc_T_rlc_AM,
    &ett_lte_rrc_T_rlc_UM,
    &ett_lte_rrc_T_headerCompression,
    &ett_lte_rrc_T_rohc,
    &ett_lte_rrc_T_profiles,
    &ett_lte_rrc_PDSCH_ConfigCommon,
    &ett_lte_rrc_PDSCH_ConfigDedicated,
    &ett_lte_rrc_PHICH_Configuration,
    &ett_lte_rrc_PhysicalConfigDedicated,
    &ett_lte_rrc_T_antennaInformation,
    &ett_lte_rrc_PRACH_ConfigurationSIB,
    &ett_lte_rrc_PRACH_Configuration,
    &ett_lte_rrc_PRACH_ConfigInfo,
    &ett_lte_rrc_PUCCH_ConfigCommon,
    &ett_lte_rrc_PUCCH_ConfigDedicated,
    &ett_lte_rrc_T_ackNackRepetition,
    &ett_lte_rrc_T_enable_05,
    &ett_lte_rrc_PUSCH_ConfigCommon,
    &ett_lte_rrc_T_pusch_ConfigBasic,
    &ett_lte_rrc_PUSCH_ConfigDedicated,
    &ett_lte_rrc_RACH_ConfigDedicated,
    &ett_lte_rrc_RACH_ConfigCommon,
    &ett_lte_rrc_T_preambleInformation,
    &ett_lte_rrc_T_preamblesGroupAConfig,
    &ett_lte_rrc_T_powerRampingParameters,
    &ett_lte_rrc_T_ra_SupervisionInformation,
    &ett_lte_rrc_RadioResourceConfigCommonSIB,
    &ett_lte_rrc_RadioResourceConfigCommon,
    &ett_lte_rrc_BCCH_Configuration,
    &ett_lte_rrc_PCCH_Configuration,
    &ett_lte_rrc_RadioResourceConfigDedicated,
    &ett_lte_rrc_T_mac_MainConfig,
    &ett_lte_rrc_SRB_ToAddModifyList,
    &ett_lte_rrc_SRB_ToAddModifyList_item,
    &ett_lte_rrc_T_rlc_Configuration,
    &ett_lte_rrc_T_logicalChannelConfig,
    &ett_lte_rrc_DRB_ToAddModifyList,
    &ett_lte_rrc_DRB_ToAddModifyList_item,
    &ett_lte_rrc_DRB_ToReleaseList,
    &ett_lte_rrc_DRB_ToReleaseList_item,
    &ett_lte_rrc_RLC_Configuration,
    &ett_lte_rrc_T_am,
    &ett_lte_rrc_T_um_Bi_Directional,
    &ett_lte_rrc_T_um_Uni_Directional_UL,
    &ett_lte_rrc_T_um_Uni_Directional_DL,
    &ett_lte_rrc_UL_AM_RLC,
    &ett_lte_rrc_DL_AM_RLC,
    &ett_lte_rrc_UL_UM_RLC,
    &ett_lte_rrc_DL_UM_RLC,
    &ett_lte_rrc_SchedulingRequest_Configuration,
    &ett_lte_rrc_T_enable_06,
    &ett_lte_rrc_SoundingRsUl_ConfigCommon,
    &ett_lte_rrc_SoundingRsUl_ConfigDedicated,
    &ett_lte_rrc_T_enable_07,
    &ett_lte_rrc_SPS_Configuration,
    &ett_lte_rrc_SPS_ConfigurationDL,
    &ett_lte_rrc_T_enable_08,
    &ett_lte_rrc_SPS_ConfigurationUL,
    &ett_lte_rrc_T_enable_09,
    &ett_lte_rrc_T_p0_Persistent,
    &ett_lte_rrc_TDD_Configuration,
    &ett_lte_rrc_TPC_Index,
    &ett_lte_rrc_TPC_PDCCH_Configuration,
    &ett_lte_rrc_T_enable_10,
    &ett_lte_rrc_UL_ReferenceSignalsPUSCH,
    &ett_lte_rrc_UplinkPowerControlCommon,
    &ett_lte_rrc_UplinkPowerControlDedicated,
    &ett_lte_rrc_DeltaFList_PUCCH,
    &ett_lte_rrc_SecurityConfiguration,
    &ett_lte_rrc_CDMA2000_CarrierInfo,
    &ett_lte_rrc_CDMA2000_NeighbourCellInformation,
    &ett_lte_rrc_CDMA2000_SystemTimeInfo,
    &ett_lte_rrc_T_cdma_SystemTime,
    &ett_lte_rrc_CellIndexList,
    &ett_lte_rrc_CellIndexList_item,
    &ett_lte_rrc_ConnectedModeSpeedDependentScalingParameters,
    &ett_lte_rrc_EUTRA_CarrierFreq,
    &ett_lte_rrc_GERAN_CarrierFreq,
    &ett_lte_rrc_GERAN_CarrierFreqList,
    &ett_lte_rrc_T_followingARFCNs,
    &ett_lte_rrc_T_equallySpacedARFCNs,
    &ett_lte_rrc_ExplicitListOfARFCNs,
    &ett_lte_rrc_GERAN_CellIdentity,
    &ett_lte_rrc_GlobalCellId_EUTRA,
    &ett_lte_rrc_GlobalCellId_UTRA,
    &ett_lte_rrc_GlobalCellId_GERAN,
    &ett_lte_rrc_GlobalCellId_CDMA2000,
    &ett_lte_rrc_HRPD_PreRegistrationInfo,
    &ett_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList,
    &ett_lte_rrc_HRPD_SecondaryPreRegistrationZoneIdList_item,
    &ett_lte_rrc_MobilityControlInformation,
    &ett_lte_rrc_EUTRA_CarrierBandwidth,
    &ett_lte_rrc_MobilityStateParameters,
    &ett_lte_rrc_OneXRTT_CSFB_RegistrationInfo,
    &ett_lte_rrc_OneXRTT_RegistrationParameters,
    &ett_lte_rrc_PhysicalCellIdentityAndRange,
    &ett_lte_rrc_T_rangeOfPCI,
    &ett_lte_rrc_PLMN_Identity,
    &ett_lte_rrc_MCC,
    &ett_lte_rrc_MNC,
    &ett_lte_rrc_UTRA_FDD_CellIdentity,
    &ett_lte_rrc_UTRA_TDD_CellIdentity,
    &ett_lte_rrc_UTRA_DL_CarrierFreq,
    &ett_lte_rrc_MeasGapConfig,
    &ett_lte_rrc_T_gapActivation,
    &ett_lte_rrc_T_activate,
    &ett_lte_rrc_T_gapPattern,
    &ett_lte_rrc_T_gp1,
    &ett_lte_rrc_T_gp2,
    &ett_lte_rrc_MeasObjectCDMA2000,
    &ett_lte_rrc_CDMA2000_CellsToAddModifyList,
    &ett_lte_rrc_CDMA2000_CellsToAddModifyList_item,
    &ett_lte_rrc_MeasObjectEUTRA,
    &ett_lte_rrc_NeighCellsToAddModifyList,
    &ett_lte_rrc_NeighCellsToAddModifyList_item,
    &ett_lte_rrc_BlackListedCellsToAddModifyList,
    &ett_lte_rrc_BlackListedCellsToAddModifyList_item,
    &ett_lte_rrc_MeasObjectGERAN,
    &ett_lte_rrc_GERAN_MeasFrequencyList,
    &ett_lte_rrc_MeasObjectUTRA,
    &ett_lte_rrc_T_cellsToAddModifyList,
    &ett_lte_rrc_T_cellForWhichToReportCGI,
    &ett_lte_rrc_UTRA_FDD_CellsToAddModifyList,
    &ett_lte_rrc_UTRA_FDD_CellsToAddModifyList_item,
    &ett_lte_rrc_UTRA_TDD_CellsToAddModifyList,
    &ett_lte_rrc_UTRA_TDD_CellsToAddModifyList_item,
    &ett_lte_rrc_MeasuredResults,
    &ett_lte_rrc_T_measResultServing,
    &ett_lte_rrc_T_neighbouringMeasResults,
    &ett_lte_rrc_MeasResultListEUTRA,
    &ett_lte_rrc_MeasResultListEUTRA_item,
    &ett_lte_rrc_T_globalCellIdentity,
    &ett_lte_rrc_T_measResult,
    &ett_lte_rrc_MeasResultListUTRA,
    &ett_lte_rrc_MeasResultListUTRA_item,
    &ett_lte_rrc_T_physicalCellIdentity,
    &ett_lte_rrc_T_globalCellIdentity_01,
    &ett_lte_rrc_T_measResult_01,
    &ett_lte_rrc_T_mode,
    &ett_lte_rrc_T_fdd,
    &ett_lte_rrc_T_tdd,
    &ett_lte_rrc_MeasResultListGERAN,
    &ett_lte_rrc_MeasResultListGERAN_item,
    &ett_lte_rrc_T_physicalCellIdentity_01,
    &ett_lte_rrc_T_globalCellIdentity_02,
    &ett_lte_rrc_T_measResult_02,
    &ett_lte_rrc_MeasResultsCDMA2000,
    &ett_lte_rrc_MeasResultListCDMA2000,
    &ett_lte_rrc_MeasResultListCDMA2000_item,
    &ett_lte_rrc_T_measResult_03,
    &ett_lte_rrc_PLMN_IdentityList2,
    &ett_lte_rrc_PLMN_IdentityList2_item,
    &ett_lte_rrc_MeasurementConfiguration,
    &ett_lte_rrc_T_speedDependentParameters,
    &ett_lte_rrc_T_enable_11,
    &ett_lte_rrc_MeasIdToRemoveList,
    &ett_lte_rrc_MeasIdToRemoveList_item,
    &ett_lte_rrc_MeasIdToAddModifyList,
    &ett_lte_rrc_MeasIdToAddModifyList_item,
    &ett_lte_rrc_MeasObjectToRemoveList,
    &ett_lte_rrc_MeasObjectToRemoveList_item,
    &ett_lte_rrc_MeasObjectToAddModifyList,
    &ett_lte_rrc_MeasObjectToAddModifyList_item,
    &ett_lte_rrc_T_measObject,
    &ett_lte_rrc_ReportConfigToRemoveList,
    &ett_lte_rrc_ReportConfigToRemoveList_item,
    &ett_lte_rrc_ReportConfigToAddModifyList,
    &ett_lte_rrc_ReportConfigToAddModifyList_item,
    &ett_lte_rrc_T_reportConfig,
    &ett_lte_rrc_QuantityConfig,
    &ett_lte_rrc_QuantityConfigEUTRA,
    &ett_lte_rrc_QuantityConfigUTRA,
    &ett_lte_rrc_QuantityConfigGERAN,
    &ett_lte_rrc_QuantityConfigCDMA2000,
    &ett_lte_rrc_ReportConfigEUTRA,
    &ett_lte_rrc_T_triggerType,
    &ett_lte_rrc_T_event,
    &ett_lte_rrc_T_eventId,
    &ett_lte_rrc_T_eventA1,
    &ett_lte_rrc_T_eventA2,
    &ett_lte_rrc_T_eventA3,
    &ett_lte_rrc_T_eventA4,
    &ett_lte_rrc_T_eventA5,
    &ett_lte_rrc_T_periodical,
    &ett_lte_rrc_T_purpose_01,
    &ett_lte_rrc_ThresholdEUTRA,
    &ett_lte_rrc_ReportConfigInterRAT,
    &ett_lte_rrc_T_triggerType_01,
    &ett_lte_rrc_T_event_01,
    &ett_lte_rrc_T_eventId_01,
    &ett_lte_rrc_T_eventB1,
    &ett_lte_rrc_T_b1_Threshold,
    &ett_lte_rrc_T_eventB2,
    &ett_lte_rrc_T_b2_Threshold2,
    &ett_lte_rrc_T_periodical_01,
    &ett_lte_rrc_T_purpose_02,
    &ett_lte_rrc_ThresholdUTRA,
    &ett_lte_rrc_IMSI,
    &ett_lte_rrc_S_TMSI,
    &ett_lte_rrc_UE_EUTRA_Capability,
    &ett_lte_rrc_T_interRAT_Parameters,
    &ett_lte_rrc_T_nonCriticalExtension_27,
    &ett_lte_rrc_PDCP_Parameters,
    &ett_lte_rrc_T_supportedROHCprofiles,
    &ett_lte_rrc_PhyLayerParameters,
    &ett_lte_rrc_RF_Parameters,
    &ett_lte_rrc_SupportedEUTRA_BandList,
    &ett_lte_rrc_SupportedEUTRA_BandList_item,
    &ett_lte_rrc_MeasurementParameters,
    &ett_lte_rrc_EUTRA_BandList,
    &ett_lte_rrc_EUTRA_BandList_item,
    &ett_lte_rrc_InterFreqEUTRA_BandList,
    &ett_lte_rrc_InterFreqEUTRA_BandList_item,
    &ett_lte_rrc_InterRAT_BandList,
    &ett_lte_rrc_InterRAT_BandList_item,
    &ett_lte_rrc_IRAT_UTRA_FDD_Parameters,
    &ett_lte_rrc_SupportedUTRA_FDD_BandList,
    &ett_lte_rrc_SupportedUTRA_FDD_BandList_item,
    &ett_lte_rrc_IRAT_UTRA_TDD128_Parameters,
    &ett_lte_rrc_SupportedUTRA_TDD128BandList,
    &ett_lte_rrc_SupportedUTRA_TDD128BandList_item,
    &ett_lte_rrc_IRAT_UTRA_TDD384_Parameters,
    &ett_lte_rrc_SupportedUTRA_TDD384BandList,
    &ett_lte_rrc_SupportedUTRA_TDD384BandList_item,
    &ett_lte_rrc_IRAT_UTRA_TDD768_Parameters,
    &ett_lte_rrc_SupportedUTRA_TDD768BandList,
    &ett_lte_rrc_SupportedUTRA_TDD768BandList_item,
    &ett_lte_rrc_IRAT_GERAN_Parameters,
    &ett_lte_rrc_SupportedGERAN_BandList,
    &ett_lte_rrc_SupportedGERAN_BandList_item,
    &ett_lte_rrc_IRAT_CDMA2000_HRPD_Parameters,
    &ett_lte_rrc_SupportedHRPD_BandList,
    &ett_lte_rrc_SupportedHRPD_BandList_item,
    &ett_lte_rrc_IRAT_CDMA2000_1xRTT_Parameters,
    &ett_lte_rrc_Supported1xRTT_BandList,
    &ett_lte_rrc_Supported1xRTT_BandList_item,
    &ett_lte_rrc_UE_TimersAndConstants,
    &ett_lte_rrc_VarMeasurementConfiguration,
    &ett_lte_rrc_T_speedDependentParameters_01,
    &ett_lte_rrc_VarMeasurementReports,
    &ett_lte_rrc_VarMeasurementReports_item,
    &ett_lte_rrc_CellsTriggeredList,
    &ett_lte_rrc_CellsTriggeredList_item,
    &ett_lte_rrc_VarShortMAC_Input,
    &ett_lte_rrc_InterNode_Message,
    &ett_lte_rrc_InterNode_MessageType,
    &ett_lte_rrc_T_c1_22,
    &ett_lte_rrc_T_messageClassExtension_06,
    &ett_lte_rrc_InterRAT_Message,
    &ett_lte_rrc_T_criticalExtensions_27,
    &ett_lte_rrc_T_c1_23,
    &ett_lte_rrc_T_criticalExtensionsFuture_27,
    &ett_lte_rrc_InterRAT_Message_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_28,
    &ett_lte_rrc_HandoverCommand,
    &ett_lte_rrc_T_criticalExtensions_28,
    &ett_lte_rrc_T_c1_24,
    &ett_lte_rrc_T_criticalExtensionsFuture_28,
    &ett_lte_rrc_HandoverCommand_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_29,
    &ett_lte_rrc_HandoverPreparationInformation,
    &ett_lte_rrc_T_criticalExtensions_29,
    &ett_lte_rrc_T_c1_25,
    &ett_lte_rrc_T_criticalExtensionsFuture_29,
    &ett_lte_rrc_HandoverPreparationInformation_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_30,
    &ett_lte_rrc_UERadioAccessCapabilityInformation,
    &ett_lte_rrc_T_criticalExtensions_30,
    &ett_lte_rrc_T_c1_26,
    &ett_lte_rrc_T_criticalExtensionsFuture_30,
    &ett_lte_rrc_UERadioAccessCapabilityInformation_r8_IEs,
    &ett_lte_rrc_T_nonCriticalExtension_31,
    &ett_lte_rrc_AS_Configuration,
    &ett_lte_rrc_AS_Context,
    &ett_lte_rrc_ReestablishmentInfo,
    &ett_lte_rrc_AdditionalReestabInfoList,
    &ett_lte_rrc_AdditionalReestabInfoList_item,
    &ett_lte_rrc_RRM_Configuration,

/*--- End of included file: packet-lte-rrc-ettarr.c ---*/
#line 80 "packet-lte-rrc-template.c"
  };


  /* Register protocol */
  proto_lte_rrc = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_lte_rrc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register the dissectors defined in lte-rrc.conf */

/*--- Included file: packet-lte-rrc-dis-reg.c ---*/
#line 1 "packet-lte-rrc-dis-reg.c"
  new_register_dissector("lte-rrc.bcch.bch", dissect_BCCH_BCH_Message_PDU, proto_lte_rrc);
  new_register_dissector("lte-rrc.bcch.dl.sch", dissect_BCCH_DL_SCH_Message_PDU, proto_lte_rrc);
  new_register_dissector("lte-rrc.pcch", dissect_PCCH_Message_PDU, proto_lte_rrc);
  new_register_dissector("lte-rrc.dl.ccch", dissect_DL_CCCH_Message_PDU, proto_lte_rrc);
  new_register_dissector("lte-rrc.dl.dcch", dissect_DL_DCCH_Message_PDU, proto_lte_rrc);
  new_register_dissector("lte-rrc.ul.ccch", dissect_UL_CCCH_Message_PDU, proto_lte_rrc);
  new_register_dissector("lte-rrc.ul.dcch", dissect_UL_DCCH_Message_PDU, proto_lte_rrc);


/*--- End of included file: packet-lte-rrc-dis-reg.c ---*/
#line 91 "packet-lte-rrc-template.c"

}


/*--- proto_reg_handoff_rrc ---------------------------------------*/
void
proto_reg_handoff_lte_rrc(void)
{

	nas_eps_handle = find_dissector("nas-eps");
}


