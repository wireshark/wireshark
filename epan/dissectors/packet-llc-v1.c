/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-llc-v1.c                                                            */
/* asn2wrs.py -q -L -p llc-v1 -c ./llc-v1.cnf -s ./packet-llc-v1-template -D . -O ../.. llc-v1.0.asn e2sm-v7.00.asn */

/* packet-llc-v1-template.c
 * Copyright 2025, Martin Mathieson
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References: ORAN-WG3.E2SM-LLC-v01.00
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <wsutil/array.h>

#include "packet-e2ap.h"
#include "packet-per.h"

#define PNAME  "LLC V1"
#define PSNAME "LLCv1"
#define PFNAME "llc-v1"


void proto_register_llc_v1(void);
void proto_reg_handoff_llc_v1(void);


#define maxnoofLLIs                    63
#define maxnoofMeasurementsToReport    65535
#define maxnoofMeasurements            63
#define maxnoofRICStyles               63
#define maxnoofControlAction           65535
#define maxnoofUEInfo                  65535
#define maxnoofUEs                     65535
#define maxnoofReceiveAntennas         65535
#define maxnoofUEID                    65535
#define maxnoofCSIReports              255
#define maxnoofUEBearers               255
#define maxnoofLogicalChannels         63
#define maxnoofScheduledDLSlots        63
#define maxnoofDLGrants                63
#define maxnoofPdschSMGs               63
#define maxnoofCsiRsPrecodingBands     63
#define maxnoofPrecoders               255
#define maxnoofPrecoderCoefficients    65535
#define maxE1APid                      65535
#define maxF1APid                      4
#define maxEARFCN                      65535
#define maxNRARFCN                     3279165
#define maxnoofNrCellBands             32
#define maxNrofSSBs_1                  63

/* Initialize the protocol and registered fields */
static int proto_llc_v1;
static int hf_llc_v1_E2SM_LLC_EventTrigger_PDU;   /* E2SM_LLC_EventTrigger */
static int hf_llc_v1_E2SM_LLC_ActionDefinition_PDU;  /* E2SM_LLC_ActionDefinition */
static int hf_llc_v1_E2SM_LLC_IndicationHeader_PDU;  /* E2SM_LLC_IndicationHeader */
static int hf_llc_v1_E2SM_LLC_IndicationMessage_PDU;  /* E2SM_LLC_IndicationMessage */
static int hf_llc_v1_E2SM_LLC_ControlHeader_PDU;  /* E2SM_LLC_ControlHeader */
static int hf_llc_v1_E2SM_LLC_ControlMessage_PDU;  /* E2SM_LLC_ControlMessage */
static int hf_llc_v1_E2SM_LLC_ControlOutcome_PDU;  /* E2SM_LLC_ControlOutcome */
static int hf_llc_v1_E2SM_LLC_RANFunctionDefinition_PDU;  /* E2SM_LLC_RANFunctionDefinition */
static int hf_llc_v1_ueInfo_List;                 /* SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item */
static int hf_llc_v1_ueInfo_List_item;            /* EventTrigger_UE_Info_Item */
static int hf_llc_v1_eventTriggerUEID;            /* RIC_EventTrigger_UE_ID */
static int hf_llc_v1_ueType;                      /* T_ueType */
static int hf_llc_v1_ueType_Choice_Individual;    /* EventTrigger_UE_Info_Item_Choice_Individual */
static int hf_llc_v1_ueType_Choice_Group;         /* EventTrigger_UE_Info_Item_Choice_Group */
static int hf_llc_v1_logicalOR;                   /* LogicalOR */
static int hf_llc_v1_ueID;                        /* UEID */
static int hf_llc_v1_groupOfUEs;                  /* GroupOfUEs */
static int hf_llc_v1_cellGlobalID;                /* CGI */
static int hf_llc_v1_ueIdentifier_List;           /* SEQUENCE_SIZE_0_maxnoofUEs_OF_UeIdentifier_Item */
static int hf_llc_v1_ueIdentifier_List_item;      /* UeIdentifier_Item */
static int hf_llc_v1_slotInfo;                    /* SlotInfo */
static int hf_llc_v1_slotStartTime;               /* OCTET_STRING_SIZE_8 */
static int hf_llc_v1_systemFramNumber;            /* INTEGER_0_1023_ */
static int hf_llc_v1_slotIndex;                   /* T_slotIndex */
static int hf_llc_v1_scs_15;                      /* INTEGER_0_9 */
static int hf_llc_v1_scs_30;                      /* INTEGER_0_19 */
static int hf_llc_v1_scs_60;                      /* INTEGER_0_39 */
static int hf_llc_v1_scs_120;                     /* INTEGER_0_79 */
static int hf_llc_v1_srsReceiveAntenna_List;      /* SEQUENCE_SIZE_1_maxnoofReceiveAntennas_OF_SrsReceiveAntenna_Item */
static int hf_llc_v1_srsReceiveAntenna_List_item;  /* SrsReceiveAntenna_Item */
static int hf_llc_v1_srsSymbol_List;              /* SEQUENCE_SIZE_CONSTR001__OF_SrsSymbol_Item */
static int hf_llc_v1_srsSymbol_List_item;         /* SrsSymbol_Item */
static int hf_llc_v1_srsCompressionHeader;        /* OCTET_STRING_SIZE_1 */
static int hf_llc_v1_rawSRS;                      /* OCTET_STRING */
static int hf_llc_v1_csiUeIdentifier_List;        /* SEQUENCE_SIZE_1_maxnoofUEID_OF_CsiUeIdentifier_Item */
static int hf_llc_v1_csiUeIdentifier_List_item;   /* CsiUeIdentifier_Item */
static int hf_llc_v1_channelCarryingUCI;          /* T_channelCarryingUCI */
static int hf_llc_v1_csiReport_List;              /* SEQUENCE_SIZE_1_maxnoofCSIReports_OF_CsiReport_Item */
static int hf_llc_v1_csiReport_List_item;         /* CsiReport_Item */
static int hf_llc_v1_csiReportConfigID;           /* INTEGER */
static int hf_llc_v1_csiFieldsCsiReport_Part1;    /* BIT_STRING */
static int hf_llc_v1_csiFieldsCsiReport_Part2;    /* BIT_STRING */
static int hf_llc_v1_dlRlcUeIdentifiers_List;     /* SEQUENCE_SIZE_1_maxnoofUEID_OF_DlRlcUeIdentifiers_Item */
static int hf_llc_v1_dlRlcUeIdentifiers_List_item;  /* DlRlcUeIdentifiers_Item */
static int hf_llc_v1_dlRlcUeBearers_List;         /* SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlRlcUeBearers_Item */
static int hf_llc_v1_dlRlcUeBearers_List_item;    /* DlRlcUeBearers_Item */
static int hf_llc_v1_lcID;                        /* INTEGER_1_32_ */
static int hf_llc_v1_dlRlcBufferOccupancy;        /* INTEGER */
static int hf_llc_v1_dlRlcHolTimeToLive;          /* INTEGER_0_1032_ */
static int hf_llc_v1_dlPdcpUeIdentifiers_List;    /* SEQUENCE_SIZE_1_maxnoofUEID_OF_DlPdcpUeIdentifiers_Item */
static int hf_llc_v1_dlPdcpUeIdentifiers_List_item;  /* DlPdcpUeIdentifiers_Item */
static int hf_llc_v1_dlPdcpUeBearers_List;        /* SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlPdcpUeBearers_Item */
static int hf_llc_v1_dlPdcpUeBearers_List_item;   /* DlPdcpUeBearers_Item */
static int hf_llc_v1_drbID;                       /* INTEGER_1_32_ */
static int hf_llc_v1_dlPdcpBufferOccupancy;       /* INTEGER */
static int hf_llc_v1_dlPdcpHolTimeToLive;         /* INTEGER_0_1032_ */
static int hf_llc_v1_dlHarqUeIdentifier_List;     /* SEQUENCE_SIZE_1_maxnoofUEID_OF_DlHarqUeIdentifier_Item */
static int hf_llc_v1_dlHarqUeIdentifier_List_item;  /* DlHarqUeIdentifier_Item */
static int hf_llc_v1_harqUeID;                    /* UEID */
static int hf_llc_v1_dlHarqCodeword_List;         /* SEQUENCE_SIZE_CONSTR002__OF_DlHarqCodeword_Item */
static int hf_llc_v1_dlHarqCodeword_List_item;    /* DlHarqCodeword_Item */
static int hf_llc_v1_dlSu_ACK_Count;              /* INTEGER */
static int hf_llc_v1_dlSu_NACK_Count;             /* INTEGER */
static int hf_llc_v1_dlSu_DTX_Count;              /* INTEGER */
static int hf_llc_v1_dlMu_ACK_Count;              /* INTEGER */
static int hf_llc_v1_dlMu_NACK_Count;             /* INTEGER */
static int hf_llc_v1_dlMu_DTX_Count;              /* INTEGER */
static int hf_llc_v1_logicalChannelUEID_List;     /* SEQUENCE_SIZE_1_maxnoofUEID_OF_LogicalChannelUEID_Item */
static int hf_llc_v1_logicalChannelUEID_List_item;  /* LogicalChannelUEID_Item */
static int hf_llc_v1_logicalChanContByNearRTRicToAdd_List;  /* SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToAdd_Item */
static int hf_llc_v1_logicalChanContByNearRTRicToAdd_List_item;  /* LogicalChanContByNearRTRicToAdd_Item */
static int hf_llc_v1_logicalChanContByNearRTRicToRel_List;  /* SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToRel_Item */
static int hf_llc_v1_logicalChanContByNearRTRicToRel_List_item;  /* LogicalChanContByNearRTRicToRel_Item */
static int hf_llc_v1_logicalChannelID;            /* LogicalChannelID */
static int hf_llc_v1_startingSlotNumber;          /* SlotInfo */
static int hf_llc_v1_dlSlotToBeScheduled_List;    /* SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlSlotToBeScheduled_Item */
static int hf_llc_v1_dlSlotToBeScheduled_List_item;  /* DlSlotToBeScheduled_Item */
static int hf_llc_v1_dlGrant_List;                /* SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrant_Item */
static int hf_llc_v1_dlGrant_List_item;           /* DlGrant_Item */
static int hf_llc_v1_pdschSMG_List;               /* SEQUENCE_SIZE_1_maxnoofPdschSMGs_OF_PdschSMG_Item */
static int hf_llc_v1_pdschSMG_List_item;          /* PdschSMG_Item */
static int hf_llc_v1_csiRsPrecodingBand_List;     /* SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBand_Item */
static int hf_llc_v1_csiRsPrecodingBand_List_item;  /* CsiRsPrecodingBand_Item */
static int hf_llc_v1_precoder_List;               /* SEQUENCE_SIZE_1_maxnoofPrecoders_OF_Precoder_Item */
static int hf_llc_v1_precoder_List_item;          /* Precoder_Item */
static int hf_llc_v1_grantID;                     /* INTEGER_1_63_ */
static int hf_llc_v1_bwpID;                       /* INTEGER_0_4_ */
static int hf_llc_v1_logicalChannel_List;         /* SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChannel_Item */
static int hf_llc_v1_logicalChannel_List_item;    /* LogicalChannel_Item */
static int hf_llc_v1_dlControlInfoType;           /* T_dlControlInfoType */
static int hf_llc_v1_dci_10;                      /* Dci_10 */
static int hf_llc_v1_dci_11;                      /* Dci_11 */
static int hf_llc_v1_semiPersistence;             /* NULL */
static int hf_llc_v1_noofBytes_TB1;               /* INTEGER */
static int hf_llc_v1_noofBytes_TB2;               /* INTEGER */
static int hf_llc_v1_useCsiRnti;                  /* T_useCsiRnti */
static int hf_llc_v1_spsConfigIndex;              /* SpsConfigIndex */
static int hf_llc_v1_activation;                  /* T_activation */
static int hf_llc_v1_freqDomainResources;         /* INTEGER */
static int hf_llc_v1_timeDomainResources;         /* INTEGER_0_15_ */
static int hf_llc_v1_vrbToPrbMapping;             /* T_vrbToPrbMapping */
static int hf_llc_v1_mcs;                         /* INTEGER_0_31_ */
static int hf_llc_v1_redundancyVersion;           /* INTEGER_0_3_ */
static int hf_llc_v1_useCsiRnti_01;               /* T_useCsiRnti_01 */
static int hf_llc_v1_carrierIndicator;            /* INTEGER_1_7_ */
static int hf_llc_v1_freqDomainResources_01;      /* BIT_STRING */
static int hf_llc_v1_vrbToPrbMapping_01;          /* T_vrbToPrbMapping_01 */
static int hf_llc_v1_prbBundlingSizeIndicagor;    /* INTEGER_0_1_ */
static int hf_llc_v1_mcs_TB1;                     /* INTEGER_0_31_ */
static int hf_llc_v1_redundancyVersion_TB1;       /* INTEGER_0_3_ */
static int hf_llc_v1_mcs_TB2;                     /* INTEGER_0_31_ */
static int hf_llc_v1_redundancyVersion_TB2;       /* INTEGER_0_3_ */
static int hf_llc_v1_antennaPorts;                /* BIT_STRING_SIZE_4_6 */
static int hf_llc_v1_transmissionConfigIndication;  /* INTEGER_0_7_ */
static int hf_llc_v1_srsRequest;                  /* BIT_STRING_SIZE_2_3 */
static int hf_llc_v1_dmrsSequenceInit;            /* INTEGER_0_1 */
static int hf_llc_v1_precoderID;                  /* INTEGER_0_63_ */
static int hf_llc_v1_smgProirity;                 /* INTEGER_0_31_ */
static int hf_llc_v1_startRB;                     /* INTEGER */
static int hf_llc_v1_noofRBs;                     /* INTEGER */
static int hf_llc_v1_startSymbol;                 /* INTEGER */
static int hf_llc_v1_noofSymbols;                 /* INTEGER */
static int hf_llc_v1_ueid;                        /* UEID */
static int hf_llc_v1_nzpCsiRsResourceID;          /* INTEGER_0_191_ */
static int hf_llc_v1_compressionInformation;      /* T_compressionInformation */
static int hf_llc_v1_precoderCompressionHeader;   /* OCTET_STRING */
static int hf_llc_v1_precoderCompressionParam;    /* OCTET_STRING */
static int hf_llc_v1_precoderCoeff_List;          /* SEQUENCE_SIZE_1_maxnoofPrecoderCoefficients_OF_PrecoderCoeff_Item */
static int hf_llc_v1_precoderCoeff_List_item;     /* PrecoderCoeff_Item */
static int hf_llc_v1_precoderCoeff_I;             /* INTEGER */
static int hf_llc_v1_precoderCoeff_Q;             /* INTEGER */
static int hf_llc_v1_receivedTimstamp;            /* ReceivedTimestamp */
static int hf_llc_v1_processingTimeMargin;        /* INTEGER_M32767_32767 */
static int hf_llc_v1_scheduledSlotOutcome_List;   /* SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlScheduledSlotOutcome_Item */
static int hf_llc_v1_scheduledSlotOutcome_List_item;  /* DlScheduledSlotOutcome_Item */
static int hf_llc_v1_dlGrantOutome_List;          /* SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrantOutcome_Item */
static int hf_llc_v1_dlGrantOutome_List_item;     /* DlGrantOutcome_Item */
static int hf_llc_v1_additionalDlAllocation_List;  /* SEQUENCE_SIZE_0_maxnoofDLGrants_OF_AdditionalDlAllocation_Item */
static int hf_llc_v1_additionalDlAllocation_List_item;  /* AdditionalDlAllocation_Item */
static int hf_llc_v1_csiRsPrecodingBandsNotExecuted_List;  /* SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBandsNotExecuted_Item */
static int hf_llc_v1_csiRsPrecodingBandsNotExecuted_List_item;  /* CsiRsPrecodingBandsNotExecuted_Item */
static int hf_llc_v1_executionLevel;              /* T_executionLevel */
static int hf_llc_v1_fullyExecuted;               /* NULL */
static int hf_llc_v1_notFullyExecuted;            /* T_notFullyExecuted */
static int hf_llc_v1_scheduledLogicalChannelOutcome_List;  /* SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_ScheduledLogicalChannelOutcome_Item */
static int hf_llc_v1_scheduledLogicalChannelOutcome_List_item;  /* ScheduledLogicalChannelOutcome_Item */
static int hf_llc_v1_noofBytesScheduled;          /* INTEGER */
static int hf_llc_v1_cause;                       /* INTEGER */
static int hf_llc_v1_csiRsPrecodingBandID;        /* INTEGER_0_63_ */
static int hf_llc_v1_ric_eventTrigger_formats;    /* T_ric_eventTrigger_formats */
static int hf_llc_v1_eventTrigger_Format1;        /* E2SM_LLC_EventTrigger_Format1 */
static int hf_llc_v1_eventTrigger_Format2;        /* E2SM_LLC_EventTrigger_Format2 */
static int hf_llc_v1_message_List;                /* SEQUENCE_SIZE_1_maxnoofLLIs_OF_E2SM_LLC_EventTrigger_Format1_Item */
static int hf_llc_v1_message_List_item;           /* E2SM_LLC_EventTrigger_Format1_Item */
static int hf_llc_v1_globalAssociatedUEInfo;      /* EventTrigger_UE_Info */
static int hf_llc_v1_ric_eventTriggerCondition_ID;  /* RIC_EventTriggerCondition_ID */
static int hf_llc_v1_lowerLayersInfoType;         /* LowerLayers_Info_Type */
static int hf_llc_v1_associatedUEInfo;            /* EventTrigger_UE_Info */
static int hf_llc_v1_reportingPeriod;             /* INTEGER_1_65535 */
static int hf_llc_v1_ric_Style_Type;              /* RIC_Style_Type */
static int hf_llc_v1_ric_actionDefinition_formats;  /* T_ric_actionDefinition_formats */
static int hf_llc_v1_actionDefinition_Format1;    /* E2SM_LLC_ActionDefinition_Format1 */
static int hf_llc_v1_actionDefinition_Format2;    /* E2SM_LLC_ActionDefinition_Format2 */
static int hf_llc_v1_measurementToReport_List;    /* SEQUENCE_SIZE_1_maxnoofMeasurementsToReport_OF_MeasurementToReport_Item */
static int hf_llc_v1_measurementToReport_List_item;  /* MeasurementToReport_Item */
static int hf_llc_v1_lowerLayers_Meas_Type;       /* LowerLayers_Meas_Type */
static int hf_llc_v1_ric_indicationHeader_formats;  /* T_ric_indicationHeader_formats */
static int hf_llc_v1_indicationHeader_Format1;    /* E2SM_LLC_IndicationHeader_Format1 */
static int hf_llc_v1_ric_indicationMessage_formats;  /* T_ric_indicationMessage_formats */
static int hf_llc_v1_indicationMessage_Format1;   /* E2SM_LLC_IndicationMessage_Format1 */
static int hf_llc_v1_indicationMessage_Format2;   /* E2SM_LLC_IndicationMessage_Format2 */
static int hf_llc_v1_slotTimeStamp;               /* SlotTimeStamp */
static int hf_llc_v1_lowerLayersInfoType_01;      /* T_lowerLayersInfoType */
static int hf_llc_v1_sRS;                         /* SRS */
static int hf_llc_v1_cSI;                         /* CSI */
static int hf_llc_v1_lowerLayersMeasurement_List;  /* SEQUENCE_SIZE_1_maxnoofMeasurements_OF_LowerLayersMeasurement_Item */
static int hf_llc_v1_lowerLayersMeasurement_List_item;  /* LowerLayersMeasurement_Item */
static int hf_llc_v1_lowerLayersMeasurementType;  /* T_lowerLayersMeasurementType */
static int hf_llc_v1_dlRlcBufferStatus;           /* DlRlcBufferStatus */
static int hf_llc_v1_dlPdcpBufferStatus;          /* DlPdcpBufferStatus */
static int hf_llc_v1_dlHarqStatistics;            /* DlHarqStatistics */
static int hf_llc_v1_slotTimeStamp_01;            /* NULL */
static int hf_llc_v1_ric_controlHeader_formats;   /* T_ric_controlHeader_formats */
static int hf_llc_v1_controlHeader_Format1;       /* E2SM_LLC_ControlHeader_Format1 */
static int hf_llc_v1_ric_StyleType;               /* RIC_Style_Type */
static int hf_llc_v1_ric_ControlAction_ID;        /* RIC_ControlAction_ID */
static int hf_llc_v1_ric_controlMessage_formats;  /* T_ric_controlMessage_formats */
static int hf_llc_v1_controlMessage_Format1;      /* E2SM_LLC_ControlMessage_Format1 */
static int hf_llc_v1_controlType;                 /* T_controlType */
static int hf_llc_v1_logicalChannelHandlingControl;  /* LogicalChannelHandlingControl */
static int hf_llc_v1_dlSchedulingControl;         /* DlSchedulingControl */
static int hf_llc_v1_ric_controlOutcome_formats;  /* T_ric_controlOutcome_formats */
static int hf_llc_v1_controlOutcome_Format1;      /* E2SM_LLC_ControlOutcome_Format1 */
static int hf_llc_v1_controlType_01;              /* T_controlType_01 */
static int hf_llc_v1_logicalChannelHandling;      /* ReceivedTimestamp */
static int hf_llc_v1_dlSchedulingParameters;      /* DlSchedulingControlOutcome */
static int hf_llc_v1_ranFunction_Name;            /* RANfunction_Name */
static int hf_llc_v1_ranFunctionDefinition_EventTrigger;  /* RANFunctionDefinition_EventTrigger_LLC */
static int hf_llc_v1_ranFunctionDefinition_Report;  /* RANFunctionDefinition_Report_LLC */
static int hf_llc_v1_ranFunctionDefinition_Control;  /* RANFunctionDefinition_Control_LLC */
static int hf_llc_v1_ric_EventTriggerStyle_List;  /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_LLC */
static int hf_llc_v1_ric_EventTriggerStyle_List_item;  /* RANFunctionDefinition_EventTrigger_Style_Item_LLC */
static int hf_llc_v1_ric_EventTriggerStyle_Type;  /* RIC_Style_Type */
static int hf_llc_v1_ric_EventTriggerStyle_Name;  /* RIC_Style_Name */
static int hf_llc_v1_ric_EventTriggerFormat_Type;  /* RIC_Format_Type */
static int hf_llc_v1_ric_ReportStyle_List;        /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_LLC */
static int hf_llc_v1_ric_ReportStyle_List_item;   /* RANFunctionDefinition_Report_Item_LLC */
static int hf_llc_v1_ric_ReportStyle_Type;        /* RIC_Style_Type */
static int hf_llc_v1_ric_ReportStyle_Name;        /* RIC_Style_Name */
static int hf_llc_v1_ric_SupportedEventTriggerStyle_Type;  /* RIC_Style_Type */
static int hf_llc_v1_ric_ReportActionFormat_Type;  /* RIC_Format_Type */
static int hf_llc_v1_ric_IndicationHeaderFormat_Type;  /* RIC_Format_Type */
static int hf_llc_v1_ric_IndicationMessageFormat_Type;  /* RIC_Format_Type */
static int hf_llc_v1_ric_ControlStyle_List;       /* SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_LLC */
static int hf_llc_v1_ric_ControlStyle_List_item;  /* RANFunctionDefinition_Control_Item_LLC */
static int hf_llc_v1_ric_ControlStyle_Type;       /* RIC_Style_Type */
static int hf_llc_v1_ric_ControlStyle_Name;       /* RIC_Style_Name */
static int hf_llc_v1_ric_ControlAction_List;      /* SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_LLC */
static int hf_llc_v1_ric_ControlAction_List_item;  /* RANFunctionDefinition_Control_Action_Item_LLC */
static int hf_llc_v1_ric_ControlHeaderFormat_Type;  /* RIC_Format_Type */
static int hf_llc_v1_ric_ControlMessageFormat_Type;  /* RIC_Format_Type */
static int hf_llc_v1_ric_CallProcessIDFormat_Type;  /* RIC_Format_Type */
static int hf_llc_v1_ric_ControlOutcomeFormat_Type;  /* RIC_Format_Type */
static int hf_llc_v1_ric_ControlAction_Name;      /* RIC_ControlAction_Name */
static int hf_llc_v1_c_RNTI;                      /* RNTI_Value */
static int hf_llc_v1_cell_Global_ID;              /* CGI */
static int hf_llc_v1_nR_CGI;                      /* NR_CGI */
static int hf_llc_v1_eUTRA_CGI;                   /* EUTRA_CGI */
static int hf_llc_v1_ranFunction_ShortName;       /* T_ranFunction_ShortName */
static int hf_llc_v1_ranFunction_E2SM_OID;        /* T_ranFunction_E2SM_OID */
static int hf_llc_v1_ranFunction_Description;     /* PrintableString_SIZE_1_150_ */
static int hf_llc_v1_ranFunction_Instance;        /* INTEGER */
static int hf_llc_v1_gNB_UEID;                    /* UEID_GNB */
static int hf_llc_v1_gNB_DU_UEID;                 /* UEID_GNB_DU */
static int hf_llc_v1_gNB_CU_UP_UEID;              /* UEID_GNB_CU_UP */
static int hf_llc_v1_ng_eNB_UEID;                 /* UEID_NG_ENB */
static int hf_llc_v1_ng_eNB_DU_UEID;              /* UEID_NG_ENB_DU */
static int hf_llc_v1_en_gNB_UEID;                 /* UEID_EN_GNB */
static int hf_llc_v1_eNB_UEID;                    /* UEID_ENB */
static int hf_llc_v1_amf_UE_NGAP_ID;              /* AMF_UE_NGAP_ID */
static int hf_llc_v1_guami;                       /* GUAMI */
static int hf_llc_v1_gNB_CU_UE_F1AP_ID_List;      /* UEID_GNB_CU_F1AP_ID_List */
static int hf_llc_v1_gNB_CU_CP_UE_E1AP_ID_List;   /* UEID_GNB_CU_CP_E1AP_ID_List */
static int hf_llc_v1_ran_UEID;                    /* RANUEID */
static int hf_llc_v1_m_NG_RAN_UE_XnAP_ID;         /* NG_RANnodeUEXnAPID */
static int hf_llc_v1_globalGNB_ID;                /* GlobalGNB_ID */
static int hf_llc_v1_globalNG_RANNode_ID;         /* GlobalNGRANNodeID */
static int hf_llc_v1_cell_RNTI;                   /* Cell_RNTI */
static int hf_llc_v1_UEID_GNB_CU_CP_E1AP_ID_List_item;  /* UEID_GNB_CU_CP_E1AP_ID_Item */
static int hf_llc_v1_gNB_CU_CP_UE_E1AP_ID;        /* GNB_CU_CP_UE_E1AP_ID */
static int hf_llc_v1_UEID_GNB_CU_F1AP_ID_List_item;  /* UEID_GNB_CU_CP_F1AP_ID_Item */
static int hf_llc_v1_gNB_CU_UE_F1AP_ID;           /* GNB_CU_UE_F1AP_ID */
static int hf_llc_v1_ng_eNB_CU_UE_W1AP_ID;        /* NGENB_CU_UE_W1AP_ID */
static int hf_llc_v1_globalNgENB_ID;              /* GlobalNgENB_ID */
static int hf_llc_v1_m_eNB_UE_X2AP_ID;            /* ENB_UE_X2AP_ID */
static int hf_llc_v1_m_eNB_UE_X2AP_ID_Extension;  /* ENB_UE_X2AP_ID_Extension */
static int hf_llc_v1_globalENB_ID;                /* GlobalENB_ID */
static int hf_llc_v1_mME_UE_S1AP_ID;              /* MME_UE_S1AP_ID */
static int hf_llc_v1_gUMMEI;                      /* GUMMEI */
static int hf_llc_v1_macro_eNB_ID;                /* BIT_STRING_SIZE_20 */
static int hf_llc_v1_home_eNB_ID;                 /* BIT_STRING_SIZE_28 */
static int hf_llc_v1_short_Macro_eNB_ID;          /* BIT_STRING_SIZE_18 */
static int hf_llc_v1_long_Macro_eNB_ID;           /* BIT_STRING_SIZE_21 */
static int hf_llc_v1_pLMNIdentity;                /* PLMNIdentity */
static int hf_llc_v1_eNB_ID;                      /* ENB_ID */
static int hf_llc_v1_pLMN_Identity;               /* PLMNIdentity */
static int hf_llc_v1_mME_Group_ID;                /* MME_Group_ID */
static int hf_llc_v1_mME_Code;                    /* MME_Code */
static int hf_llc_v1_eUTRACellIdentity;           /* EUTRACellIdentity */
static int hf_llc_v1_gnb_id_choice;               /* GNB_ID */
static int hf_llc_v1_ngENB_ID;                    /* NgENB_ID */
static int hf_llc_v1_gNB_ID;                      /* BIT_STRING_SIZE_22_32 */
static int hf_llc_v1_aMFRegionID;                 /* AMFRegionID */
static int hf_llc_v1_aMFSetID;                    /* AMFSetID */
static int hf_llc_v1_aMFPointer;                  /* AMFPointer */
static int hf_llc_v1_macroNgENB_ID;               /* BIT_STRING_SIZE_20 */
static int hf_llc_v1_shortMacroNgENB_ID;          /* BIT_STRING_SIZE_18 */
static int hf_llc_v1_longMacroNgENB_ID;           /* BIT_STRING_SIZE_21 */
static int hf_llc_v1_nRCellIdentity;              /* NRCellIdentity */
static int hf_llc_v1_gNB;                         /* GlobalGNB_ID */
static int hf_llc_v1_ng_eNB;                      /* GlobalNgENB_ID */


static int ett_llc_v1_EventTrigger_UE_Info;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item;
static int ett_llc_v1_EventTrigger_UE_Info_Item;
static int ett_llc_v1_T_ueType;
static int ett_llc_v1_EventTrigger_UE_Info_Item_Choice_Individual;
static int ett_llc_v1_EventTrigger_UE_Info_Item_Choice_Group;
static int ett_llc_v1_GroupOfUEs;
static int ett_llc_v1_SEQUENCE_SIZE_0_maxnoofUEs_OF_UeIdentifier_Item;
static int ett_llc_v1_UeIdentifier_Item;
static int ett_llc_v1_SlotTimeStamp;
static int ett_llc_v1_SlotInfo;
static int ett_llc_v1_T_slotIndex;
static int ett_llc_v1_SRS;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofReceiveAntennas_OF_SrsReceiveAntenna_Item;
static int ett_llc_v1_SrsReceiveAntenna_Item;
static int ett_llc_v1_SEQUENCE_SIZE_CONSTR001__OF_SrsSymbol_Item;
static int ett_llc_v1_SrsSymbol_Item;
static int ett_llc_v1_CSI;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_CsiUeIdentifier_Item;
static int ett_llc_v1_CsiUeIdentifier_Item;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofCSIReports_OF_CsiReport_Item;
static int ett_llc_v1_CsiReport_Item;
static int ett_llc_v1_DlRlcBufferStatus;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlRlcUeIdentifiers_Item;
static int ett_llc_v1_DlRlcUeIdentifiers_Item;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlRlcUeBearers_Item;
static int ett_llc_v1_DlRlcUeBearers_Item;
static int ett_llc_v1_DlPdcpBufferStatus;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlPdcpUeIdentifiers_Item;
static int ett_llc_v1_DlPdcpUeIdentifiers_Item;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlPdcpUeBearers_Item;
static int ett_llc_v1_DlPdcpUeBearers_Item;
static int ett_llc_v1_DlHarqStatistics;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlHarqUeIdentifier_Item;
static int ett_llc_v1_DlHarqUeIdentifier_Item;
static int ett_llc_v1_SEQUENCE_SIZE_CONSTR002__OF_DlHarqCodeword_Item;
static int ett_llc_v1_DlHarqCodeword_Item;
static int ett_llc_v1_LogicalChannelHandlingControl;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_LogicalChannelUEID_Item;
static int ett_llc_v1_LogicalChannelUEID_Item;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToAdd_Item;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToRel_Item;
static int ett_llc_v1_LogicalChanContByNearRTRicToAdd_Item;
static int ett_llc_v1_LogicalChanContByNearRTRicToRel_Item;
static int ett_llc_v1_DlSchedulingControl;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlSlotToBeScheduled_Item;
static int ett_llc_v1_DlSlotToBeScheduled_Item;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrant_Item;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofPdschSMGs_OF_PdschSMG_Item;
static int ett_llc_v1_SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBand_Item;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofPrecoders_OF_Precoder_Item;
static int ett_llc_v1_DlGrant_Item;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChannel_Item;
static int ett_llc_v1_T_dlControlInfoType;
static int ett_llc_v1_LogicalChannel_Item;
static int ett_llc_v1_Dci_10;
static int ett_llc_v1_T_useCsiRnti;
static int ett_llc_v1_Dci_11;
static int ett_llc_v1_T_useCsiRnti_01;
static int ett_llc_v1_PdschSMG_Item;
static int ett_llc_v1_CsiRsPrecodingBand_Item;
static int ett_llc_v1_Precoder_Item;
static int ett_llc_v1_T_compressionInformation;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofPrecoderCoefficients_OF_PrecoderCoeff_Item;
static int ett_llc_v1_PrecoderCoeff_Item;
static int ett_llc_v1_DlSchedulingControlOutcome;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlScheduledSlotOutcome_Item;
static int ett_llc_v1_DlScheduledSlotOutcome_Item;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrantOutcome_Item;
static int ett_llc_v1_SEQUENCE_SIZE_0_maxnoofDLGrants_OF_AdditionalDlAllocation_Item;
static int ett_llc_v1_SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBandsNotExecuted_Item;
static int ett_llc_v1_DlGrantOutcome_Item;
static int ett_llc_v1_T_executionLevel;
static int ett_llc_v1_T_notFullyExecuted;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_ScheduledLogicalChannelOutcome_Item;
static int ett_llc_v1_ScheduledLogicalChannelOutcome_Item;
static int ett_llc_v1_AdditionalDlAllocation_Item;
static int ett_llc_v1_CsiRsPrecodingBandsNotExecuted_Item;
static int ett_llc_v1_E2SM_LLC_EventTrigger;
static int ett_llc_v1_T_ric_eventTrigger_formats;
static int ett_llc_v1_E2SM_LLC_EventTrigger_Format1;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLLIs_OF_E2SM_LLC_EventTrigger_Format1_Item;
static int ett_llc_v1_E2SM_LLC_EventTrigger_Format1_Item;
static int ett_llc_v1_E2SM_LLC_EventTrigger_Format2;
static int ett_llc_v1_E2SM_LLC_ActionDefinition;
static int ett_llc_v1_T_ric_actionDefinition_formats;
static int ett_llc_v1_E2SM_LLC_ActionDefinition_Format1;
static int ett_llc_v1_E2SM_LLC_ActionDefinition_Format2;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofMeasurementsToReport_OF_MeasurementToReport_Item;
static int ett_llc_v1_MeasurementToReport_Item;
static int ett_llc_v1_E2SM_LLC_IndicationHeader;
static int ett_llc_v1_T_ric_indicationHeader_formats;
static int ett_llc_v1_E2SM_LLC_IndicationHeader_Format1;
static int ett_llc_v1_E2SM_LLC_IndicationMessage;
static int ett_llc_v1_T_ric_indicationMessage_formats;
static int ett_llc_v1_E2SM_LLC_IndicationMessage_Format1;
static int ett_llc_v1_T_lowerLayersInfoType;
static int ett_llc_v1_E2SM_LLC_IndicationMessage_Format2;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofMeasurements_OF_LowerLayersMeasurement_Item;
static int ett_llc_v1_LowerLayersMeasurement_Item;
static int ett_llc_v1_T_lowerLayersMeasurementType;
static int ett_llc_v1_E2SM_LLC_ControlHeader;
static int ett_llc_v1_T_ric_controlHeader_formats;
static int ett_llc_v1_E2SM_LLC_ControlHeader_Format1;
static int ett_llc_v1_E2SM_LLC_ControlMessage;
static int ett_llc_v1_T_ric_controlMessage_formats;
static int ett_llc_v1_E2SM_LLC_ControlMessage_Format1;
static int ett_llc_v1_T_controlType;
static int ett_llc_v1_E2SM_LLC_ControlOutcome;
static int ett_llc_v1_T_ric_controlOutcome_formats;
static int ett_llc_v1_E2SM_LLC_ControlOutcome_Format1;
static int ett_llc_v1_T_controlType_01;
static int ett_llc_v1_E2SM_LLC_RANFunctionDefinition;
static int ett_llc_v1_RANFunctionDefinition_EventTrigger_LLC;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_LLC;
static int ett_llc_v1_RANFunctionDefinition_EventTrigger_Style_Item_LLC;
static int ett_llc_v1_RANFunctionDefinition_Report_LLC;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_LLC;
static int ett_llc_v1_RANFunctionDefinition_Report_Item_LLC;
static int ett_llc_v1_RANFunctionDefinition_Control_LLC;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_LLC;
static int ett_llc_v1_RANFunctionDefinition_Control_Item_LLC;
static int ett_llc_v1_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_LLC;
static int ett_llc_v1_RANFunctionDefinition_Control_Action_Item_LLC;
static int ett_llc_v1_Cell_RNTI;
static int ett_llc_v1_CGI;
static int ett_llc_v1_RANfunction_Name;
static int ett_llc_v1_UEID;
static int ett_llc_v1_UEID_GNB;
static int ett_llc_v1_UEID_GNB_CU_CP_E1AP_ID_List;
static int ett_llc_v1_UEID_GNB_CU_CP_E1AP_ID_Item;
static int ett_llc_v1_UEID_GNB_CU_F1AP_ID_List;
static int ett_llc_v1_UEID_GNB_CU_CP_F1AP_ID_Item;
static int ett_llc_v1_UEID_GNB_DU;
static int ett_llc_v1_UEID_GNB_CU_UP;
static int ett_llc_v1_UEID_NG_ENB;
static int ett_llc_v1_UEID_NG_ENB_DU;
static int ett_llc_v1_UEID_EN_GNB;
static int ett_llc_v1_UEID_ENB;
static int ett_llc_v1_ENB_ID;
static int ett_llc_v1_GlobalENB_ID;
static int ett_llc_v1_GUMMEI;
static int ett_llc_v1_EUTRA_CGI;
static int ett_llc_v1_GlobalGNB_ID;
static int ett_llc_v1_GlobalNgENB_ID;
static int ett_llc_v1_GNB_ID;
static int ett_llc_v1_GUAMI;
static int ett_llc_v1_NgENB_ID;
static int ett_llc_v1_NR_CGI;
static int ett_llc_v1_GlobalNGRANNodeID;


/* Forward declarations */
static int dissect_E2SM_LLC_RANFunctionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static int dissect_E2SM_LLC_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_LLC_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_LLC_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);

static int dissect_E2SM_LLC_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_LLC_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_LLC_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);
static int dissect_E2SM_LLC_EventTrigger_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_);



static const value_string llc_v1_LogicalOR_vals[] = {
  {   0, "true" },
  {   1, "false" },
  { 0, NULL }
};


static int
dissect_llc_v1_LogicalOR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string llc_v1_LowerLayers_Info_Type_vals[] = {
  {   0, "srs" },
  {   1, "csi" },
  { 0, NULL }
};


static int
dissect_llc_v1_LowerLayers_Info_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string llc_v1_LowerLayers_Meas_Type_vals[] = {
  {   0, "dl-rlc-buffer-status" },
  {   1, "dl-pdcp-buffer-status" },
  {   2, "dl-harq-statistics" },
  {   3, "slot-time-stamp" },
  { 0, NULL }
};


static int
dissect_llc_v1_LowerLayers_Meas_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_llc_v1_LogicalChannelID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_SpsConfigIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_ReceivedTimestamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}



static int
dissect_llc_v1_RIC_EventTrigger_UE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_AMF_UE_NGAP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(1099511627775), NULL, false);

  return offset;
}



static int
dissect_llc_v1_PLMNIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}



static int
dissect_llc_v1_AMFRegionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_llc_v1_AMFSetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_llc_v1_AMFPointer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GUAMI_sequence[] = {
  { &hf_llc_v1_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_PLMNIdentity },
  { &hf_llc_v1_aMFRegionID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_AMFRegionID },
  { &hf_llc_v1_aMFSetID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_AMFSetID },
  { &hf_llc_v1_aMFPointer   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_AMFPointer },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_GUAMI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_GUAMI, GUAMI_sequence);

  return offset;
}



static int
dissect_llc_v1_GNB_CU_UE_F1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_F1AP_ID_Item_sequence[] = {
  { &hf_llc_v1_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_GNB_CU_UE_F1AP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_UEID_GNB_CU_CP_F1AP_ID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_UEID_GNB_CU_CP_F1AP_ID_Item, UEID_GNB_CU_CP_F1AP_ID_Item_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_F1AP_ID_List_sequence_of[1] = {
  { &hf_llc_v1_UEID_GNB_CU_F1AP_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID_GNB_CU_CP_F1AP_ID_Item },
};

static int
dissect_llc_v1_UEID_GNB_CU_F1AP_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_UEID_GNB_CU_F1AP_ID_List, UEID_GNB_CU_F1AP_ID_List_sequence_of,
                                                  1, maxF1APid, false);

  return offset;
}



static int
dissect_llc_v1_GNB_CU_CP_UE_E1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_E1AP_ID_Item_sequence[] = {
  { &hf_llc_v1_gNB_CU_CP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_GNB_CU_CP_UE_E1AP_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_UEID_GNB_CU_CP_E1AP_ID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_UEID_GNB_CU_CP_E1AP_ID_Item, UEID_GNB_CU_CP_E1AP_ID_Item_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_CP_E1AP_ID_List_sequence_of[1] = {
  { &hf_llc_v1_UEID_GNB_CU_CP_E1AP_ID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID_GNB_CU_CP_E1AP_ID_Item },
};

static int
dissect_llc_v1_UEID_GNB_CU_CP_E1AP_ID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_UEID_GNB_CU_CP_E1AP_ID_List, UEID_GNB_CU_CP_E1AP_ID_List_sequence_of,
                                                  1, maxE1APid, false);

  return offset;
}



static int
dissect_llc_v1_RANUEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}



static int
dissect_llc_v1_NG_RANnodeUEXnAPID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_llc_v1_BIT_STRING_SIZE_22_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     22, 32, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string llc_v1_GNB_ID_vals[] = {
  {   0, "gNB-ID" },
  { 0, NULL }
};

static const per_choice_t GNB_ID_choice[] = {
  {   0, &hf_llc_v1_gNB_ID       , ASN1_EXTENSION_ROOT    , dissect_llc_v1_BIT_STRING_SIZE_22_32 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_GNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_GNB_ID, GNB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalGNB_ID_sequence[] = {
  { &hf_llc_v1_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_PLMNIdentity },
  { &hf_llc_v1_gnb_id_choice, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_GNB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_GlobalGNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_GlobalGNB_ID, GlobalGNB_ID_sequence);

  return offset;
}



static int
dissect_llc_v1_BIT_STRING_SIZE_20(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_llc_v1_BIT_STRING_SIZE_18(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_llc_v1_BIT_STRING_SIZE_21(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string llc_v1_NgENB_ID_vals[] = {
  {   0, "macroNgENB-ID" },
  {   1, "shortMacroNgENB-ID" },
  {   2, "longMacroNgENB-ID" },
  { 0, NULL }
};

static const per_choice_t NgENB_ID_choice[] = {
  {   0, &hf_llc_v1_macroNgENB_ID, ASN1_EXTENSION_ROOT    , dissect_llc_v1_BIT_STRING_SIZE_20 },
  {   1, &hf_llc_v1_shortMacroNgENB_ID, ASN1_EXTENSION_ROOT    , dissect_llc_v1_BIT_STRING_SIZE_18 },
  {   2, &hf_llc_v1_longMacroNgENB_ID, ASN1_EXTENSION_ROOT    , dissect_llc_v1_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_NgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_NgENB_ID, NgENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalNgENB_ID_sequence[] = {
  { &hf_llc_v1_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_PLMNIdentity },
  { &hf_llc_v1_ngENB_ID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_NgENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_GlobalNgENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_GlobalNgENB_ID, GlobalNgENB_ID_sequence);

  return offset;
}


static const value_string llc_v1_GlobalNGRANNodeID_vals[] = {
  {   0, "gNB" },
  {   1, "ng-eNB" },
  { 0, NULL }
};

static const per_choice_t GlobalNGRANNodeID_choice[] = {
  {   0, &hf_llc_v1_gNB          , ASN1_EXTENSION_ROOT    , dissect_llc_v1_GlobalGNB_ID },
  {   1, &hf_llc_v1_ng_eNB       , ASN1_EXTENSION_ROOT    , dissect_llc_v1_GlobalNgENB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_GlobalNGRANNodeID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_GlobalNGRANNodeID, GlobalNGRANNodeID_choice,
                                 NULL);

  return offset;
}



static int
dissect_llc_v1_RNTI_Value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_llc_v1_NRCellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NR_CGI_sequence[] = {
  { &hf_llc_v1_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_PLMNIdentity },
  { &hf_llc_v1_nRCellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_NRCellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_NR_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_NR_CGI, NR_CGI_sequence);

  return offset;
}



static int
dissect_llc_v1_EUTRACellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t EUTRA_CGI_sequence[] = {
  { &hf_llc_v1_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_PLMNIdentity },
  { &hf_llc_v1_eUTRACellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_EUTRACellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_EUTRA_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_EUTRA_CGI, EUTRA_CGI_sequence);

  return offset;
}


static const value_string llc_v1_CGI_vals[] = {
  {   0, "nR-CGI" },
  {   1, "eUTRA-CGI" },
  { 0, NULL }
};

static const per_choice_t CGI_choice[] = {
  {   0, &hf_llc_v1_nR_CGI       , ASN1_EXTENSION_ROOT    , dissect_llc_v1_NR_CGI },
  {   1, &hf_llc_v1_eUTRA_CGI    , ASN1_EXTENSION_ROOT    , dissect_llc_v1_EUTRA_CGI },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_CGI, CGI_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Cell_RNTI_sequence[] = {
  { &hf_llc_v1_c_RNTI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RNTI_Value },
  { &hf_llc_v1_cell_Global_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_CGI },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_Cell_RNTI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_Cell_RNTI, Cell_RNTI_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_sequence[] = {
  { &hf_llc_v1_amf_UE_NGAP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_AMF_UE_NGAP_ID },
  { &hf_llc_v1_guami        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_GUAMI },
  { &hf_llc_v1_gNB_CU_UE_F1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_UEID_GNB_CU_F1AP_ID_List },
  { &hf_llc_v1_gNB_CU_CP_UE_E1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_UEID_GNB_CU_CP_E1AP_ID_List },
  { &hf_llc_v1_ran_UEID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_RANUEID },
  { &hf_llc_v1_m_NG_RAN_UE_XnAP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_NG_RANnodeUEXnAPID },
  { &hf_llc_v1_globalGNB_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_GlobalGNB_ID },
  { &hf_llc_v1_globalNG_RANNode_ID, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_llc_v1_GlobalNGRANNodeID },
  { &hf_llc_v1_cell_RNTI    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_llc_v1_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_UEID_GNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_UEID_GNB, UEID_GNB_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_DU_sequence[] = {
  { &hf_llc_v1_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_GNB_CU_UE_F1AP_ID },
  { &hf_llc_v1_ran_UEID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_RANUEID },
  { &hf_llc_v1_cell_RNTI    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_llc_v1_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_UEID_GNB_DU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_UEID_GNB_DU, UEID_GNB_DU_sequence);

  return offset;
}


static const per_sequence_t UEID_GNB_CU_UP_sequence[] = {
  { &hf_llc_v1_gNB_CU_CP_UE_E1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_GNB_CU_CP_UE_E1AP_ID },
  { &hf_llc_v1_ran_UEID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_RANUEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_UEID_GNB_CU_UP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_UEID_GNB_CU_UP, UEID_GNB_CU_UP_sequence);

  return offset;
}



static int
dissect_llc_v1_NGENB_CU_UE_W1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}


static const per_sequence_t UEID_NG_ENB_sequence[] = {
  { &hf_llc_v1_amf_UE_NGAP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_AMF_UE_NGAP_ID },
  { &hf_llc_v1_guami        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_GUAMI },
  { &hf_llc_v1_ng_eNB_CU_UE_W1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_NGENB_CU_UE_W1AP_ID },
  { &hf_llc_v1_m_NG_RAN_UE_XnAP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_NG_RANnodeUEXnAPID },
  { &hf_llc_v1_globalNgENB_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_GlobalNgENB_ID },
  { &hf_llc_v1_globalNG_RANNode_ID, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_llc_v1_GlobalNGRANNodeID },
  { &hf_llc_v1_cell_RNTI    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_llc_v1_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_UEID_NG_ENB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_UEID_NG_ENB, UEID_NG_ENB_sequence);

  return offset;
}


static const per_sequence_t UEID_NG_ENB_DU_sequence[] = {
  { &hf_llc_v1_ng_eNB_CU_UE_W1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_NGENB_CU_UE_W1AP_ID },
  { &hf_llc_v1_cell_RNTI    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_llc_v1_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_UEID_NG_ENB_DU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_UEID_NG_ENB_DU, UEID_NG_ENB_DU_sequence);

  return offset;
}



static int
dissect_llc_v1_ENB_UE_X2AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}



static int
dissect_llc_v1_ENB_UE_X2AP_ID_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_BIT_STRING_SIZE_28(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string llc_v1_ENB_ID_vals[] = {
  {   0, "macro-eNB-ID" },
  {   1, "home-eNB-ID" },
  {   2, "short-Macro-eNB-ID" },
  {   3, "long-Macro-eNB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_llc_v1_macro_eNB_ID , ASN1_EXTENSION_ROOT    , dissect_llc_v1_BIT_STRING_SIZE_20 },
  {   1, &hf_llc_v1_home_eNB_ID  , ASN1_EXTENSION_ROOT    , dissect_llc_v1_BIT_STRING_SIZE_28 },
  {   2, &hf_llc_v1_short_Macro_eNB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_llc_v1_BIT_STRING_SIZE_18 },
  {   3, &hf_llc_v1_long_Macro_eNB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_llc_v1_BIT_STRING_SIZE_21 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GlobalENB_ID_sequence[] = {
  { &hf_llc_v1_pLMNIdentity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_PLMNIdentity },
  { &hf_llc_v1_eNB_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_ENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_GlobalENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_GlobalENB_ID, GlobalENB_ID_sequence);

  return offset;
}


static const per_sequence_t UEID_EN_GNB_sequence[] = {
  { &hf_llc_v1_m_eNB_UE_X2AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_ENB_UE_X2AP_ID },
  { &hf_llc_v1_m_eNB_UE_X2AP_ID_Extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_ENB_UE_X2AP_ID_Extension },
  { &hf_llc_v1_globalENB_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_GlobalENB_ID },
  { &hf_llc_v1_gNB_CU_UE_F1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_GNB_CU_UE_F1AP_ID },
  { &hf_llc_v1_gNB_CU_CP_UE_E1AP_ID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_UEID_GNB_CU_CP_E1AP_ID_List },
  { &hf_llc_v1_ran_UEID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_RANUEID },
  { &hf_llc_v1_cell_RNTI    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_llc_v1_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_UEID_EN_GNB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_UEID_EN_GNB, UEID_EN_GNB_sequence);

  return offset;
}



static int
dissect_llc_v1_MME_UE_S1AP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_llc_v1_MME_Group_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, false, NULL);

  return offset;
}



static int
dissect_llc_v1_MME_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t GUMMEI_sequence[] = {
  { &hf_llc_v1_pLMN_Identity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_PLMNIdentity },
  { &hf_llc_v1_mME_Group_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_MME_Group_ID },
  { &hf_llc_v1_mME_Code     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_MME_Code },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_GUMMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_GUMMEI, GUMMEI_sequence);

  return offset;
}


static const per_sequence_t UEID_ENB_sequence[] = {
  { &hf_llc_v1_mME_UE_S1AP_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_MME_UE_S1AP_ID },
  { &hf_llc_v1_gUMMEI       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_GUMMEI },
  { &hf_llc_v1_m_eNB_UE_X2AP_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_ENB_UE_X2AP_ID },
  { &hf_llc_v1_m_eNB_UE_X2AP_ID_Extension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_ENB_UE_X2AP_ID_Extension },
  { &hf_llc_v1_globalENB_ID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_GlobalENB_ID },
  { &hf_llc_v1_cell_RNTI    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_llc_v1_Cell_RNTI },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_UEID_ENB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_UEID_ENB, UEID_ENB_sequence);

  return offset;
}


static const value_string llc_v1_UEID_vals[] = {
  {   0, "gNB-UEID" },
  {   1, "gNB-DU-UEID" },
  {   2, "gNB-CU-UP-UEID" },
  {   3, "ng-eNB-UEID" },
  {   4, "ng-eNB-DU-UEID" },
  {   5, "en-gNB-UEID" },
  {   6, "eNB-UEID" },
  { 0, NULL }
};

static const per_choice_t UEID_choice[] = {
  {   0, &hf_llc_v1_gNB_UEID     , ASN1_EXTENSION_ROOT    , dissect_llc_v1_UEID_GNB },
  {   1, &hf_llc_v1_gNB_DU_UEID  , ASN1_EXTENSION_ROOT    , dissect_llc_v1_UEID_GNB_DU },
  {   2, &hf_llc_v1_gNB_CU_UP_UEID, ASN1_EXTENSION_ROOT    , dissect_llc_v1_UEID_GNB_CU_UP },
  {   3, &hf_llc_v1_ng_eNB_UEID  , ASN1_EXTENSION_ROOT    , dissect_llc_v1_UEID_NG_ENB },
  {   4, &hf_llc_v1_ng_eNB_DU_UEID, ASN1_EXTENSION_ROOT    , dissect_llc_v1_UEID_NG_ENB_DU },
  {   5, &hf_llc_v1_en_gNB_UEID  , ASN1_EXTENSION_ROOT    , dissect_llc_v1_UEID_EN_GNB },
  {   6, &hf_llc_v1_eNB_UEID     , ASN1_EXTENSION_ROOT    , dissect_llc_v1_UEID_ENB },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_UEID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_UEID, UEID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_Item_Choice_Individual_sequence[] = {
  { &hf_llc_v1_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_EventTrigger_UE_Info_Item_Choice_Individual(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_EventTrigger_UE_Info_Item_Choice_Individual, EventTrigger_UE_Info_Item_Choice_Individual_sequence);

  return offset;
}


static const per_sequence_t UeIdentifier_Item_sequence[] = {
  { &hf_llc_v1_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_UeIdentifier_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_UeIdentifier_Item, UeIdentifier_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofUEs_OF_UeIdentifier_Item_sequence_of[1] = {
  { &hf_llc_v1_ueIdentifier_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_UeIdentifier_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_0_maxnoofUEs_OF_UeIdentifier_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_0_maxnoofUEs_OF_UeIdentifier_Item, SEQUENCE_SIZE_0_maxnoofUEs_OF_UeIdentifier_Item_sequence_of,
                                                  0, maxnoofUEs, false);

  return offset;
}


static const per_sequence_t GroupOfUEs_sequence[] = {
  { &hf_llc_v1_cellGlobalID , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_CGI },
  { &hf_llc_v1_ueIdentifier_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_0_maxnoofUEs_OF_UeIdentifier_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_GroupOfUEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_GroupOfUEs, GroupOfUEs_sequence);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_Item_Choice_Group_sequence[] = {
  { &hf_llc_v1_groupOfUEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_GroupOfUEs },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_EventTrigger_UE_Info_Item_Choice_Group(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_EventTrigger_UE_Info_Item_Choice_Group, EventTrigger_UE_Info_Item_Choice_Group_sequence);

  return offset;
}


static const value_string llc_v1_T_ueType_vals[] = {
  {   0, "ueType-Choice-Individual" },
  {   1, "ueType-Choice-Group" },
  { 0, NULL }
};

static const per_choice_t T_ueType_choice[] = {
  {   0, &hf_llc_v1_ueType_Choice_Individual, ASN1_EXTENSION_ROOT    , dissect_llc_v1_EventTrigger_UE_Info_Item_Choice_Individual },
  {   1, &hf_llc_v1_ueType_Choice_Group, ASN1_EXTENSION_ROOT    , dissect_llc_v1_EventTrigger_UE_Info_Item_Choice_Group },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_ueType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_ueType, T_ueType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_Item_sequence[] = {
  { &hf_llc_v1_eventTriggerUEID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_EventTrigger_UE_ID },
  { &hf_llc_v1_ueType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_ueType },
  { &hf_llc_v1_logicalOR    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_EventTrigger_UE_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_EventTrigger_UE_Info_Item, EventTrigger_UE_Info_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item_sequence_of[1] = {
  { &hf_llc_v1_ueInfo_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_EventTrigger_UE_Info_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item, SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item_sequence_of,
                                                  1, maxnoofUEInfo, false);

  return offset;
}


static const per_sequence_t EventTrigger_UE_Info_sequence[] = {
  { &hf_llc_v1_ueInfo_List  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_EventTrigger_UE_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_EventTrigger_UE_Info, EventTrigger_UE_Info_sequence);

  return offset;
}



static int
dissect_llc_v1_RIC_ControlAction_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_RIC_ControlAction_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_llc_v1_RIC_EventTriggerCondition_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_1023_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, false);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 19U, NULL, false);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_39(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 39U, NULL, false);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_79(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 79U, NULL, false);

  return offset;
}


static const value_string llc_v1_T_slotIndex_vals[] = {
  {   0, "scs-15" },
  {   1, "scs-30" },
  {   2, "scs-60" },
  {   3, "scs-120" },
  { 0, NULL }
};

static const per_choice_t T_slotIndex_choice[] = {
  {   0, &hf_llc_v1_scs_15       , ASN1_EXTENSION_ROOT    , dissect_llc_v1_INTEGER_0_9 },
  {   1, &hf_llc_v1_scs_30       , ASN1_EXTENSION_ROOT    , dissect_llc_v1_INTEGER_0_19 },
  {   2, &hf_llc_v1_scs_60       , ASN1_EXTENSION_ROOT    , dissect_llc_v1_INTEGER_0_39 },
  {   3, &hf_llc_v1_scs_120      , ASN1_EXTENSION_ROOT    , dissect_llc_v1_INTEGER_0_79 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_slotIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_slotIndex, T_slotIndex_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SlotInfo_sequence[] = {
  { &hf_llc_v1_systemFramNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_1023_ },
  { &hf_llc_v1_slotIndex    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_slotIndex },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_SlotInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_SlotInfo, SlotInfo_sequence);

  return offset;
}



static int
dissect_llc_v1_OCTET_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}


static const per_sequence_t SlotTimeStamp_sequence[] = {
  { &hf_llc_v1_slotInfo     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SlotInfo },
  { &hf_llc_v1_slotStartTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_OCTET_STRING_SIZE_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_SlotTimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_SlotTimeStamp, SlotTimeStamp_sequence);

  return offset;
}



static int
dissect_llc_v1_OCTET_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}



static int
dissect_llc_v1_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const per_sequence_t SrsSymbol_Item_sequence[] = {
  { &hf_llc_v1_srsCompressionHeader, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_OCTET_STRING_SIZE_1 },
  { &hf_llc_v1_rawSRS       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_SrsSymbol_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_SrsSymbol_Item, SrsSymbol_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_CONSTR001__OF_SrsSymbol_Item_sequence_of[1] = {
  { &hf_llc_v1_srsSymbol_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_SrsSymbol_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_CONSTR001__OF_SrsSymbol_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_CONSTR001__OF_SrsSymbol_Item, SEQUENCE_SIZE_CONSTR001__OF_SrsSymbol_Item_sequence_of,
                                                  1, 4, true);

  return offset;
}


static const per_sequence_t SrsReceiveAntenna_Item_sequence[] = {
  { &hf_llc_v1_srsSymbol_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_CONSTR001__OF_SrsSymbol_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_SrsReceiveAntenna_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_SrsReceiveAntenna_Item, SrsReceiveAntenna_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofReceiveAntennas_OF_SrsReceiveAntenna_Item_sequence_of[1] = {
  { &hf_llc_v1_srsReceiveAntenna_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_SrsReceiveAntenna_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofReceiveAntennas_OF_SrsReceiveAntenna_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofReceiveAntennas_OF_SrsReceiveAntenna_Item, SEQUENCE_SIZE_1_maxnoofReceiveAntennas_OF_SrsReceiveAntenna_Item_sequence_of,
                                                  1, maxnoofReceiveAntennas, false);

  return offset;
}


static const per_sequence_t SRS_sequence[] = {
  { &hf_llc_v1_srsReceiveAntenna_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofReceiveAntennas_OF_SrsReceiveAntenna_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_SRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_SRS, SRS_sequence);

  return offset;
}


static const value_string llc_v1_T_channelCarryingUCI_vals[] = {
  {   0, "pucch" },
  {   1, "pusch" },
  { 0, NULL }
};


static int
dissect_llc_v1_T_channelCarryingUCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_llc_v1_INTEGER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_llc_v1_BIT_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t CsiReport_Item_sequence[] = {
  { &hf_llc_v1_csiReportConfigID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_csiFieldsCsiReport_Part1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_BIT_STRING },
  { &hf_llc_v1_csiFieldsCsiReport_Part2, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_BIT_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_CsiReport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_CsiReport_Item, CsiReport_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofCSIReports_OF_CsiReport_Item_sequence_of[1] = {
  { &hf_llc_v1_csiReport_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_CsiReport_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofCSIReports_OF_CsiReport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofCSIReports_OF_CsiReport_Item, SEQUENCE_SIZE_1_maxnoofCSIReports_OF_CsiReport_Item_sequence_of,
                                                  1, maxnoofCSIReports, false);

  return offset;
}


static const per_sequence_t CsiUeIdentifier_Item_sequence[] = {
  { &hf_llc_v1_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID },
  { &hf_llc_v1_channelCarryingUCI, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_channelCarryingUCI },
  { &hf_llc_v1_csiReport_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofCSIReports_OF_CsiReport_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_CsiUeIdentifier_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_CsiUeIdentifier_Item, CsiUeIdentifier_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEID_OF_CsiUeIdentifier_Item_sequence_of[1] = {
  { &hf_llc_v1_csiUeIdentifier_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_CsiUeIdentifier_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_CsiUeIdentifier_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_CsiUeIdentifier_Item, SEQUENCE_SIZE_1_maxnoofUEID_OF_CsiUeIdentifier_Item_sequence_of,
                                                  1, maxnoofUEID, false);

  return offset;
}


static const per_sequence_t CSI_sequence[] = {
  { &hf_llc_v1_csiUeIdentifier_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_CsiUeIdentifier_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_CSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_CSI, CSI_sequence);

  return offset;
}



static int
dissect_llc_v1_INTEGER_1_32_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_1032_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1032U, NULL, true);

  return offset;
}


static const per_sequence_t DlRlcUeBearers_Item_sequence[] = {
  { &hf_llc_v1_lcID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_1_32_ },
  { &hf_llc_v1_dlRlcBufferOccupancy, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_dlRlcHolTimeToLive, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_1032_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlRlcUeBearers_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlRlcUeBearers_Item, DlRlcUeBearers_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlRlcUeBearers_Item_sequence_of[1] = {
  { &hf_llc_v1_dlRlcUeBearers_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_DlRlcUeBearers_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlRlcUeBearers_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlRlcUeBearers_Item, SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlRlcUeBearers_Item_sequence_of,
                                                  1, maxnoofUEBearers, false);

  return offset;
}


static const per_sequence_t DlRlcUeIdentifiers_Item_sequence[] = {
  { &hf_llc_v1_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID },
  { &hf_llc_v1_dlRlcUeBearers_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlRlcUeBearers_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlRlcUeIdentifiers_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlRlcUeIdentifiers_Item, DlRlcUeIdentifiers_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEID_OF_DlRlcUeIdentifiers_Item_sequence_of[1] = {
  { &hf_llc_v1_dlRlcUeIdentifiers_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_DlRlcUeIdentifiers_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlRlcUeIdentifiers_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlRlcUeIdentifiers_Item, SEQUENCE_SIZE_1_maxnoofUEID_OF_DlRlcUeIdentifiers_Item_sequence_of,
                                                  1, maxnoofUEID, false);

  return offset;
}


static const per_sequence_t DlRlcBufferStatus_sequence[] = {
  { &hf_llc_v1_dlRlcUeIdentifiers_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlRlcUeIdentifiers_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlRlcBufferStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlRlcBufferStatus, DlRlcBufferStatus_sequence);

  return offset;
}


static const per_sequence_t DlPdcpUeBearers_Item_sequence[] = {
  { &hf_llc_v1_drbID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_1_32_ },
  { &hf_llc_v1_dlPdcpBufferOccupancy, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_dlPdcpHolTimeToLive, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_1032_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlPdcpUeBearers_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlPdcpUeBearers_Item, DlPdcpUeBearers_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlPdcpUeBearers_Item_sequence_of[1] = {
  { &hf_llc_v1_dlPdcpUeBearers_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_DlPdcpUeBearers_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlPdcpUeBearers_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlPdcpUeBearers_Item, SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlPdcpUeBearers_Item_sequence_of,
                                                  1, maxnoofUEBearers, false);

  return offset;
}


static const per_sequence_t DlPdcpUeIdentifiers_Item_sequence[] = {
  { &hf_llc_v1_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID },
  { &hf_llc_v1_dlPdcpUeBearers_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlPdcpUeBearers_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlPdcpUeIdentifiers_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlPdcpUeIdentifiers_Item, DlPdcpUeIdentifiers_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEID_OF_DlPdcpUeIdentifiers_Item_sequence_of[1] = {
  { &hf_llc_v1_dlPdcpUeIdentifiers_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_DlPdcpUeIdentifiers_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlPdcpUeIdentifiers_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlPdcpUeIdentifiers_Item, SEQUENCE_SIZE_1_maxnoofUEID_OF_DlPdcpUeIdentifiers_Item_sequence_of,
                                                  1, maxnoofUEID, false);

  return offset;
}


static const per_sequence_t DlPdcpBufferStatus_sequence[] = {
  { &hf_llc_v1_dlPdcpUeIdentifiers_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlPdcpUeIdentifiers_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlPdcpBufferStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlPdcpBufferStatus, DlPdcpBufferStatus_sequence);

  return offset;
}


static const per_sequence_t DlHarqCodeword_Item_sequence[] = {
  { &hf_llc_v1_dlSu_ACK_Count, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_dlSu_NACK_Count, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_dlSu_DTX_Count, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_dlMu_ACK_Count, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_dlMu_NACK_Count, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_dlMu_DTX_Count, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlHarqCodeword_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlHarqCodeword_Item, DlHarqCodeword_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_CONSTR002__OF_DlHarqCodeword_Item_sequence_of[1] = {
  { &hf_llc_v1_dlHarqCodeword_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_DlHarqCodeword_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_CONSTR002__OF_DlHarqCodeword_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_CONSTR002__OF_DlHarqCodeword_Item, SEQUENCE_SIZE_CONSTR002__OF_DlHarqCodeword_Item_sequence_of,
                                                  1, 2, true);

  return offset;
}


static const per_sequence_t DlHarqUeIdentifier_Item_sequence[] = {
  { &hf_llc_v1_harqUeID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID },
  { &hf_llc_v1_dlHarqCodeword_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_CONSTR002__OF_DlHarqCodeword_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlHarqUeIdentifier_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlHarqUeIdentifier_Item, DlHarqUeIdentifier_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEID_OF_DlHarqUeIdentifier_Item_sequence_of[1] = {
  { &hf_llc_v1_dlHarqUeIdentifier_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_DlHarqUeIdentifier_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlHarqUeIdentifier_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlHarqUeIdentifier_Item, SEQUENCE_SIZE_1_maxnoofUEID_OF_DlHarqUeIdentifier_Item_sequence_of,
                                                  1, maxnoofUEID, false);

  return offset;
}


static const per_sequence_t DlHarqStatistics_sequence[] = {
  { &hf_llc_v1_dlHarqUeIdentifier_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlHarqUeIdentifier_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlHarqStatistics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlHarqStatistics, DlHarqStatistics_sequence);

  return offset;
}


static const per_sequence_t LogicalChanContByNearRTRicToAdd_Item_sequence[] = {
  { &hf_llc_v1_logicalChannelID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_LogicalChannelID },
  { &hf_llc_v1_startingSlotNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SlotInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_LogicalChanContByNearRTRicToAdd_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_LogicalChanContByNearRTRicToAdd_Item, LogicalChanContByNearRTRicToAdd_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToAdd_Item_sequence_of[1] = {
  { &hf_llc_v1_logicalChanContByNearRTRicToAdd_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_LogicalChanContByNearRTRicToAdd_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToAdd_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToAdd_Item, SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToAdd_Item_sequence_of,
                                                  1, maxnoofLogicalChannels, false);

  return offset;
}


static const per_sequence_t LogicalChanContByNearRTRicToRel_Item_sequence[] = {
  { &hf_llc_v1_logicalChannelID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_LogicalChannelID },
  { &hf_llc_v1_startingSlotNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SlotInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_LogicalChanContByNearRTRicToRel_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_LogicalChanContByNearRTRicToRel_Item, LogicalChanContByNearRTRicToRel_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToRel_Item_sequence_of[1] = {
  { &hf_llc_v1_logicalChanContByNearRTRicToRel_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_LogicalChanContByNearRTRicToRel_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToRel_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToRel_Item, SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToRel_Item_sequence_of,
                                                  1, maxnoofLogicalChannels, false);

  return offset;
}


static const per_sequence_t LogicalChannelUEID_Item_sequence[] = {
  { &hf_llc_v1_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID },
  { &hf_llc_v1_logicalChanContByNearRTRicToAdd_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToAdd_Item },
  { &hf_llc_v1_logicalChanContByNearRTRicToRel_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToRel_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_LogicalChannelUEID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_LogicalChannelUEID_Item, LogicalChannelUEID_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofUEID_OF_LogicalChannelUEID_Item_sequence_of[1] = {
  { &hf_llc_v1_logicalChannelUEID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_LogicalChannelUEID_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_LogicalChannelUEID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_LogicalChannelUEID_Item, SEQUENCE_SIZE_1_maxnoofUEID_OF_LogicalChannelUEID_Item_sequence_of,
                                                  1, maxnoofUEID, false);

  return offset;
}


static const per_sequence_t LogicalChannelHandlingControl_sequence[] = {
  { &hf_llc_v1_logicalChannelUEID_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_LogicalChannelUEID_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_LogicalChannelHandlingControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_LogicalChannelHandlingControl, LogicalChannelHandlingControl_sequence);

  return offset;
}



static int
dissect_llc_v1_INTEGER_1_63_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 63U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_4_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4U, NULL, true);

  return offset;
}


static const per_sequence_t LogicalChannel_Item_sequence[] = {
  { &hf_llc_v1_logicalChannelID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_LogicalChannelID },
  { &hf_llc_v1_noofBytes_TB1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_noofBytes_TB2, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_LogicalChannel_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_LogicalChannel_Item, LogicalChannel_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChannel_Item_sequence_of[1] = {
  { &hf_llc_v1_logicalChannel_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_LogicalChannel_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChannel_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChannel_Item, SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChannel_Item_sequence_of,
                                                  1, maxnoofLogicalChannels, false);

  return offset;
}


static const value_string llc_v1_T_activation_vals[] = {
  {   0, "activate" },
  {   1, "deactivate" },
  { 0, NULL }
};


static int
dissect_llc_v1_T_activation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t T_useCsiRnti_sequence[] = {
  { &hf_llc_v1_spsConfigIndex, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_SpsConfigIndex },
  { &hf_llc_v1_activation   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_activation },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_T_useCsiRnti(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_T_useCsiRnti, T_useCsiRnti_sequence);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_15_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, true);

  return offset;
}


static const value_string llc_v1_T_vrbToPrbMapping_vals[] = {
  {   0, "interleaved" },
  { 0, NULL }
};


static int
dissect_llc_v1_T_vrbToPrbMapping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_31_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_3_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, true);

  return offset;
}


static const per_sequence_t Dci_10_sequence[] = {
  { &hf_llc_v1_useCsiRnti   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_T_useCsiRnti },
  { &hf_llc_v1_freqDomainResources, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_timeDomainResources, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_15_ },
  { &hf_llc_v1_vrbToPrbMapping, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_T_vrbToPrbMapping },
  { &hf_llc_v1_mcs          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_31_ },
  { &hf_llc_v1_redundancyVersion, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_3_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_Dci_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_Dci_10, Dci_10_sequence);

  return offset;
}


static const per_sequence_t T_useCsiRnti_01_sequence[] = {
  { &hf_llc_v1_spsConfigIndex, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_SpsConfigIndex },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_T_useCsiRnti_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_T_useCsiRnti_01, T_useCsiRnti_01_sequence);

  return offset;
}



static int
dissect_llc_v1_INTEGER_1_7_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 7U, NULL, true);

  return offset;
}


static const value_string llc_v1_T_vrbToPrbMapping_01_vals[] = {
  {   0, "interleaved" },
  { 0, NULL }
};


static int
dissect_llc_v1_T_vrbToPrbMapping_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_1_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_BIT_STRING_SIZE_4_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 6, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_7_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, true);

  return offset;
}



static int
dissect_llc_v1_BIT_STRING_SIZE_2_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 3, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, false);

  return offset;
}


static const per_sequence_t Dci_11_sequence[] = {
  { &hf_llc_v1_useCsiRnti_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_T_useCsiRnti_01 },
  { &hf_llc_v1_carrierIndicator, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER_1_7_ },
  { &hf_llc_v1_freqDomainResources_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_BIT_STRING },
  { &hf_llc_v1_timeDomainResources, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_15_ },
  { &hf_llc_v1_vrbToPrbMapping_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_T_vrbToPrbMapping_01 },
  { &hf_llc_v1_prbBundlingSizeIndicagor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_1_ },
  { &hf_llc_v1_mcs_TB1      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_31_ },
  { &hf_llc_v1_redundancyVersion_TB1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_3_ },
  { &hf_llc_v1_mcs_TB2      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER_0_31_ },
  { &hf_llc_v1_redundancyVersion_TB2, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER_0_3_ },
  { &hf_llc_v1_antennaPorts , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_BIT_STRING_SIZE_4_6 },
  { &hf_llc_v1_transmissionConfigIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER_0_7_ },
  { &hf_llc_v1_srsRequest   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_BIT_STRING_SIZE_2_3 },
  { &hf_llc_v1_dmrsSequenceInit, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_Dci_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_Dci_11, Dci_11_sequence);

  return offset;
}



static int
dissect_llc_v1_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string llc_v1_T_dlControlInfoType_vals[] = {
  {   0, "dci-10" },
  {   1, "dci-11" },
  {   2, "semiPersistence" },
  { 0, NULL }
};

static const per_choice_t T_dlControlInfoType_choice[] = {
  {   0, &hf_llc_v1_dci_10       , ASN1_EXTENSION_ROOT    , dissect_llc_v1_Dci_10 },
  {   1, &hf_llc_v1_dci_11       , ASN1_EXTENSION_ROOT    , dissect_llc_v1_Dci_11 },
  {   2, &hf_llc_v1_semiPersistence, ASN1_EXTENSION_ROOT    , dissect_llc_v1_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_dlControlInfoType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_dlControlInfoType, T_dlControlInfoType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DlGrant_Item_sequence[] = {
  { &hf_llc_v1_grantID      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_1_63_ },
  { &hf_llc_v1_bwpID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER_0_4_ },
  { &hf_llc_v1_ueID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID },
  { &hf_llc_v1_logicalChannel_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChannel_Item },
  { &hf_llc_v1_dlControlInfoType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_dlControlInfoType },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlGrant_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlGrant_Item, DlGrant_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrant_Item_sequence_of[1] = {
  { &hf_llc_v1_dlGrant_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_DlGrant_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrant_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrant_Item, SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrant_Item_sequence_of,
                                                  1, maxnoofDLGrants, false);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_63_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, true);

  return offset;
}


static const per_sequence_t PdschSMG_Item_sequence[] = {
  { &hf_llc_v1_precoderID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_63_ },
  { &hf_llc_v1_smgProirity  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER_0_31_ },
  { &hf_llc_v1_startRB      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_noofRBs      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_startSymbol  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_noofSymbols  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_PdschSMG_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_PdschSMG_Item, PdschSMG_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofPdschSMGs_OF_PdschSMG_Item_sequence_of[1] = {
  { &hf_llc_v1_pdschSMG_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_PdschSMG_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofPdschSMGs_OF_PdschSMG_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofPdschSMGs_OF_PdschSMG_Item, SEQUENCE_SIZE_1_maxnoofPdschSMGs_OF_PdschSMG_Item_sequence_of,
                                                  1, maxnoofPdschSMGs, false);

  return offset;
}



static int
dissect_llc_v1_INTEGER_0_191_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 191U, NULL, true);

  return offset;
}


static const per_sequence_t CsiRsPrecodingBand_Item_sequence[] = {
  { &hf_llc_v1_precoderID   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_63_ },
  { &hf_llc_v1_ueid         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_UEID },
  { &hf_llc_v1_nzpCsiRsResourceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_191_ },
  { &hf_llc_v1_startRB      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_noofRBs      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_CsiRsPrecodingBand_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_CsiRsPrecodingBand_Item, CsiRsPrecodingBand_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBand_Item_sequence_of[1] = {
  { &hf_llc_v1_csiRsPrecodingBand_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_CsiRsPrecodingBand_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBand_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBand_Item, SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBand_Item_sequence_of,
                                                  0, maxnoofCsiRsPrecodingBands, false);

  return offset;
}


static const per_sequence_t T_compressionInformation_sequence[] = {
  { &hf_llc_v1_precoderCompressionHeader, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_OCTET_STRING },
  { &hf_llc_v1_precoderCompressionParam, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_OCTET_STRING },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_T_compressionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_T_compressionInformation, T_compressionInformation_sequence);

  return offset;
}


static const per_sequence_t PrecoderCoeff_Item_sequence[] = {
  { &hf_llc_v1_precoderCoeff_I, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_precoderCoeff_Q, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_PrecoderCoeff_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_PrecoderCoeff_Item, PrecoderCoeff_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofPrecoderCoefficients_OF_PrecoderCoeff_Item_sequence_of[1] = {
  { &hf_llc_v1_precoderCoeff_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_PrecoderCoeff_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofPrecoderCoefficients_OF_PrecoderCoeff_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofPrecoderCoefficients_OF_PrecoderCoeff_Item, SEQUENCE_SIZE_1_maxnoofPrecoderCoefficients_OF_PrecoderCoeff_Item_sequence_of,
                                                  1, maxnoofPrecoderCoefficients, false);

  return offset;
}


static const per_sequence_t Precoder_Item_sequence[] = {
  { &hf_llc_v1_compressionInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_T_compressionInformation },
  { &hf_llc_v1_precoderCoeff_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofPrecoderCoefficients_OF_PrecoderCoeff_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_Precoder_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_Precoder_Item, Precoder_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofPrecoders_OF_Precoder_Item_sequence_of[1] = {
  { &hf_llc_v1_precoder_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_Precoder_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofPrecoders_OF_Precoder_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofPrecoders_OF_Precoder_Item, SEQUENCE_SIZE_1_maxnoofPrecoders_OF_Precoder_Item_sequence_of,
                                                  1, maxnoofPrecoders, false);

  return offset;
}


static const per_sequence_t DlSlotToBeScheduled_Item_sequence[] = {
  { &hf_llc_v1_slotInfo     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SlotInfo },
  { &hf_llc_v1_dlGrant_List , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrant_Item },
  { &hf_llc_v1_pdschSMG_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofPdschSMGs_OF_PdschSMG_Item },
  { &hf_llc_v1_csiRsPrecodingBand_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBand_Item },
  { &hf_llc_v1_precoder_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofPrecoders_OF_Precoder_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlSlotToBeScheduled_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlSlotToBeScheduled_Item, DlSlotToBeScheduled_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlSlotToBeScheduled_Item_sequence_of[1] = {
  { &hf_llc_v1_dlSlotToBeScheduled_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_DlSlotToBeScheduled_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlSlotToBeScheduled_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlSlotToBeScheduled_Item, SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlSlotToBeScheduled_Item_sequence_of,
                                                  1, maxnoofScheduledDLSlots, false);

  return offset;
}


static const per_sequence_t DlSchedulingControl_sequence[] = {
  { &hf_llc_v1_dlSlotToBeScheduled_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlSlotToBeScheduled_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlSchedulingControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlSchedulingControl, DlSchedulingControl_sequence);

  return offset;
}



static int
dissect_llc_v1_INTEGER_M32767_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32767, 32767U, NULL, false);

  return offset;
}


static const per_sequence_t ScheduledLogicalChannelOutcome_Item_sequence[] = {
  { &hf_llc_v1_logicalChannelID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_LogicalChannelID },
  { &hf_llc_v1_noofBytesScheduled, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_cause        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_ScheduledLogicalChannelOutcome_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_ScheduledLogicalChannelOutcome_Item, ScheduledLogicalChannelOutcome_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_ScheduledLogicalChannelOutcome_Item_sequence_of[1] = {
  { &hf_llc_v1_scheduledLogicalChannelOutcome_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_ScheduledLogicalChannelOutcome_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_ScheduledLogicalChannelOutcome_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_ScheduledLogicalChannelOutcome_Item, SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_ScheduledLogicalChannelOutcome_Item_sequence_of,
                                                  1, maxnoofLogicalChannels, false);

  return offset;
}


static const per_sequence_t T_notFullyExecuted_sequence[] = {
  { &hf_llc_v1_scheduledLogicalChannelOutcome_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_ScheduledLogicalChannelOutcome_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_T_notFullyExecuted(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_T_notFullyExecuted, T_notFullyExecuted_sequence);

  return offset;
}


static const value_string llc_v1_T_executionLevel_vals[] = {
  {   0, "fullyExecuted" },
  {   1, "notFullyExecuted" },
  { 0, NULL }
};

static const per_choice_t T_executionLevel_choice[] = {
  {   0, &hf_llc_v1_fullyExecuted, ASN1_EXTENSION_ROOT    , dissect_llc_v1_NULL },
  {   1, &hf_llc_v1_notFullyExecuted, ASN1_EXTENSION_ROOT    , dissect_llc_v1_T_notFullyExecuted },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_executionLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_executionLevel, T_executionLevel_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DlGrantOutcome_Item_sequence[] = {
  { &hf_llc_v1_grantID      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_1_63_ },
  { &hf_llc_v1_executionLevel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_executionLevel },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlGrantOutcome_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlGrantOutcome_Item, DlGrantOutcome_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrantOutcome_Item_sequence_of[1] = {
  { &hf_llc_v1_dlGrantOutome_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_DlGrantOutcome_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrantOutcome_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrantOutcome_Item, SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrantOutcome_Item_sequence_of,
                                                  1, maxnoofDLGrants, false);

  return offset;
}


static const per_sequence_t AdditionalDlAllocation_Item_sequence[] = {
  { &hf_llc_v1_ueid         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_UEID },
  { &hf_llc_v1_logicalChannelID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_LogicalChannelID },
  { &hf_llc_v1_noofBytesScheduled, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { &hf_llc_v1_startSymbol  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER },
  { &hf_llc_v1_noofSymbols  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER },
  { &hf_llc_v1_startRB      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER },
  { &hf_llc_v1_noofRBs      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_AdditionalDlAllocation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_AdditionalDlAllocation_Item, AdditionalDlAllocation_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofDLGrants_OF_AdditionalDlAllocation_Item_sequence_of[1] = {
  { &hf_llc_v1_additionalDlAllocation_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_AdditionalDlAllocation_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_0_maxnoofDLGrants_OF_AdditionalDlAllocation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_0_maxnoofDLGrants_OF_AdditionalDlAllocation_Item, SEQUENCE_SIZE_0_maxnoofDLGrants_OF_AdditionalDlAllocation_Item_sequence_of,
                                                  0, maxnoofDLGrants, false);

  return offset;
}


static const per_sequence_t CsiRsPrecodingBandsNotExecuted_Item_sequence[] = {
  { &hf_llc_v1_csiRsPrecodingBandID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_0_63_ },
  { &hf_llc_v1_cause        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_CsiRsPrecodingBandsNotExecuted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_CsiRsPrecodingBandsNotExecuted_Item, CsiRsPrecodingBandsNotExecuted_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBandsNotExecuted_Item_sequence_of[1] = {
  { &hf_llc_v1_csiRsPrecodingBandsNotExecuted_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_CsiRsPrecodingBandsNotExecuted_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBandsNotExecuted_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBandsNotExecuted_Item, SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBandsNotExecuted_Item_sequence_of,
                                                  0, maxnoofCsiRsPrecodingBands, false);

  return offset;
}


static const per_sequence_t DlScheduledSlotOutcome_Item_sequence[] = {
  { &hf_llc_v1_slotInfo     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SlotInfo },
  { &hf_llc_v1_dlGrantOutome_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrantOutcome_Item },
  { &hf_llc_v1_additionalDlAllocation_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_0_maxnoofDLGrants_OF_AdditionalDlAllocation_Item },
  { &hf_llc_v1_csiRsPrecodingBandsNotExecuted_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBandsNotExecuted_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlScheduledSlotOutcome_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlScheduledSlotOutcome_Item, DlScheduledSlotOutcome_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlScheduledSlotOutcome_Item_sequence_of[1] = {
  { &hf_llc_v1_scheduledSlotOutcome_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_DlScheduledSlotOutcome_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlScheduledSlotOutcome_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlScheduledSlotOutcome_Item, SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlScheduledSlotOutcome_Item_sequence_of,
                                                  1, maxnoofScheduledDLSlots, false);

  return offset;
}


static const per_sequence_t DlSchedulingControlOutcome_sequence[] = {
  { &hf_llc_v1_receivedTimstamp, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_ReceivedTimestamp },
  { &hf_llc_v1_processingTimeMargin, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_M32767_32767 },
  { &hf_llc_v1_scheduledSlotOutcome_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlScheduledSlotOutcome_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_DlSchedulingControlOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_DlSchedulingControlOutcome, DlSchedulingControlOutcome_sequence);

  return offset;
}


static const per_sequence_t E2SM_LLC_EventTrigger_Format1_Item_sequence[] = {
  { &hf_llc_v1_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_EventTriggerCondition_ID },
  { &hf_llc_v1_lowerLayersInfoType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_LowerLayers_Info_Type },
  { &hf_llc_v1_associatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_EventTrigger_UE_Info },
  { &hf_llc_v1_logicalOR    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_LogicalOR },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_EventTrigger_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_EventTrigger_Format1_Item, E2SM_LLC_EventTrigger_Format1_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofLLIs_OF_E2SM_LLC_EventTrigger_Format1_Item_sequence_of[1] = {
  { &hf_llc_v1_message_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_E2SM_LLC_EventTrigger_Format1_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofLLIs_OF_E2SM_LLC_EventTrigger_Format1_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLLIs_OF_E2SM_LLC_EventTrigger_Format1_Item, SEQUENCE_SIZE_1_maxnoofLLIs_OF_E2SM_LLC_EventTrigger_Format1_Item_sequence_of,
                                                  1, maxnoofLLIs, false);

  return offset;
}


static const per_sequence_t E2SM_LLC_EventTrigger_Format1_sequence[] = {
  { &hf_llc_v1_message_List , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofLLIs_OF_E2SM_LLC_EventTrigger_Format1_Item },
  { &hf_llc_v1_globalAssociatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_EventTrigger_UE_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_EventTrigger_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_EventTrigger_Format1, E2SM_LLC_EventTrigger_Format1_sequence);

  return offset;
}



static int
dissect_llc_v1_INTEGER_1_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t E2SM_LLC_EventTrigger_Format2_sequence[] = {
  { &hf_llc_v1_reportingPeriod, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_INTEGER_1_65535 },
  { &hf_llc_v1_associatedUEInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_EventTrigger_UE_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_EventTrigger_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_EventTrigger_Format2, E2SM_LLC_EventTrigger_Format2_sequence);

  return offset;
}


static const value_string llc_v1_T_ric_eventTrigger_formats_vals[] = {
  {   0, "eventTrigger-Format1" },
  {   1, "eventTrigger-Format2" },
  { 0, NULL }
};

static const per_choice_t T_ric_eventTrigger_formats_choice[] = {
  {   0, &hf_llc_v1_eventTrigger_Format1, ASN1_EXTENSION_ROOT    , dissect_llc_v1_E2SM_LLC_EventTrigger_Format1 },
  {   1, &hf_llc_v1_eventTrigger_Format2, ASN1_EXTENSION_ROOT    , dissect_llc_v1_E2SM_LLC_EventTrigger_Format2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_ric_eventTrigger_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_ric_eventTrigger_formats, T_ric_eventTrigger_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_EventTrigger_sequence[] = {
  { &hf_llc_v1_ric_eventTrigger_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_ric_eventTrigger_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_EventTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_EventTrigger, E2SM_LLC_EventTrigger_sequence);

  return offset;
}



static int
dissect_llc_v1_RIC_Style_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_ActionDefinition_Format1_sequence[] = {
  { &hf_llc_v1_lowerLayersInfoType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_LowerLayers_Info_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_ActionDefinition_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_ActionDefinition_Format1, E2SM_LLC_ActionDefinition_Format1_sequence);

  return offset;
}


static const per_sequence_t MeasurementToReport_Item_sequence[] = {
  { &hf_llc_v1_lowerLayers_Meas_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_LowerLayers_Meas_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_MeasurementToReport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_MeasurementToReport_Item, MeasurementToReport_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofMeasurementsToReport_OF_MeasurementToReport_Item_sequence_of[1] = {
  { &hf_llc_v1_measurementToReport_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_MeasurementToReport_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofMeasurementsToReport_OF_MeasurementToReport_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofMeasurementsToReport_OF_MeasurementToReport_Item, SEQUENCE_SIZE_1_maxnoofMeasurementsToReport_OF_MeasurementToReport_Item_sequence_of,
                                                  1, maxnoofMeasurementsToReport, false);

  return offset;
}


static const per_sequence_t E2SM_LLC_ActionDefinition_Format2_sequence[] = {
  { &hf_llc_v1_measurementToReport_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofMeasurementsToReport_OF_MeasurementToReport_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_ActionDefinition_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_ActionDefinition_Format2, E2SM_LLC_ActionDefinition_Format2_sequence);

  return offset;
}


static const value_string llc_v1_T_ric_actionDefinition_formats_vals[] = {
  {   0, "actionDefinition-Format1" },
  {   1, "actionDefinition-Format2" },
  { 0, NULL }
};

static const per_choice_t T_ric_actionDefinition_formats_choice[] = {
  {   0, &hf_llc_v1_actionDefinition_Format1, ASN1_EXTENSION_ROOT    , dissect_llc_v1_E2SM_LLC_ActionDefinition_Format1 },
  {   1, &hf_llc_v1_actionDefinition_Format2, ASN1_EXTENSION_ROOT    , dissect_llc_v1_E2SM_LLC_ActionDefinition_Format2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_ric_actionDefinition_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_ric_actionDefinition_formats, T_ric_actionDefinition_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_ActionDefinition_sequence[] = {
  { &hf_llc_v1_ric_Style_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Style_Type },
  { &hf_llc_v1_ric_actionDefinition_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_ric_actionDefinition_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_ActionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_ActionDefinition, E2SM_LLC_ActionDefinition_sequence);

  return offset;
}


static const per_sequence_t E2SM_LLC_IndicationHeader_Format1_sequence[] = {
  { &hf_llc_v1_ric_eventTriggerCondition_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_RIC_EventTriggerCondition_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_IndicationHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_IndicationHeader_Format1, E2SM_LLC_IndicationHeader_Format1_sequence);

  return offset;
}


static const value_string llc_v1_T_ric_indicationHeader_formats_vals[] = {
  {   0, "indicationHeader-Format1" },
  { 0, NULL }
};

static const per_choice_t T_ric_indicationHeader_formats_choice[] = {
  {   0, &hf_llc_v1_indicationHeader_Format1, ASN1_EXTENSION_ROOT    , dissect_llc_v1_E2SM_LLC_IndicationHeader_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_ric_indicationHeader_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_ric_indicationHeader_formats, T_ric_indicationHeader_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_IndicationHeader_sequence[] = {
  { &hf_llc_v1_ric_indicationHeader_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_ric_indicationHeader_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_IndicationHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_IndicationHeader, E2SM_LLC_IndicationHeader_sequence);

  return offset;
}


static const value_string llc_v1_T_lowerLayersInfoType_vals[] = {
  {   0, "sRS" },
  {   1, "cSI" },
  { 0, NULL }
};

static const per_choice_t T_lowerLayersInfoType_choice[] = {
  {   0, &hf_llc_v1_sRS          , ASN1_EXTENSION_ROOT    , dissect_llc_v1_SRS },
  {   1, &hf_llc_v1_cSI          , ASN1_EXTENSION_ROOT    , dissect_llc_v1_CSI },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_lowerLayersInfoType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_lowerLayersInfoType, T_lowerLayersInfoType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_IndicationMessage_Format1_sequence[] = {
  { &hf_llc_v1_slotTimeStamp, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SlotTimeStamp },
  { &hf_llc_v1_lowerLayersInfoType_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_lowerLayersInfoType },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_IndicationMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_IndicationMessage_Format1, E2SM_LLC_IndicationMessage_Format1_sequence);

  return offset;
}


static const value_string llc_v1_T_lowerLayersMeasurementType_vals[] = {
  {   0, "dlRlcBufferStatus" },
  {   1, "dlPdcpBufferStatus" },
  {   2, "dlHarqStatistics" },
  {   3, "slotTimeStamp" },
  { 0, NULL }
};

static const per_choice_t T_lowerLayersMeasurementType_choice[] = {
  {   0, &hf_llc_v1_dlRlcBufferStatus, ASN1_EXTENSION_ROOT    , dissect_llc_v1_DlRlcBufferStatus },
  {   1, &hf_llc_v1_dlPdcpBufferStatus, ASN1_EXTENSION_ROOT    , dissect_llc_v1_DlPdcpBufferStatus },
  {   2, &hf_llc_v1_dlHarqStatistics, ASN1_EXTENSION_ROOT    , dissect_llc_v1_DlHarqStatistics },
  {   3, &hf_llc_v1_slotTimeStamp_01, ASN1_EXTENSION_ROOT    , dissect_llc_v1_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_lowerLayersMeasurementType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_lowerLayersMeasurementType, T_lowerLayersMeasurementType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t LowerLayersMeasurement_Item_sequence[] = {
  { &hf_llc_v1_slotTimeStamp, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SlotTimeStamp },
  { &hf_llc_v1_lowerLayersMeasurementType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_lowerLayersMeasurementType },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_LowerLayersMeasurement_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_LowerLayersMeasurement_Item, LowerLayersMeasurement_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofMeasurements_OF_LowerLayersMeasurement_Item_sequence_of[1] = {
  { &hf_llc_v1_lowerLayersMeasurement_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_LowerLayersMeasurement_Item },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofMeasurements_OF_LowerLayersMeasurement_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofMeasurements_OF_LowerLayersMeasurement_Item, SEQUENCE_SIZE_1_maxnoofMeasurements_OF_LowerLayersMeasurement_Item_sequence_of,
                                                  1, maxnoofMeasurements, false);

  return offset;
}


static const per_sequence_t E2SM_LLC_IndicationMessage_Format2_sequence[] = {
  { &hf_llc_v1_lowerLayersMeasurement_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofMeasurements_OF_LowerLayersMeasurement_Item },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_IndicationMessage_Format2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_IndicationMessage_Format2, E2SM_LLC_IndicationMessage_Format2_sequence);

  return offset;
}


static const value_string llc_v1_T_ric_indicationMessage_formats_vals[] = {
  {   0, "indicationMessage-Format1" },
  {   1, "indicationMessage-Format2" },
  { 0, NULL }
};

static const per_choice_t T_ric_indicationMessage_formats_choice[] = {
  {   0, &hf_llc_v1_indicationMessage_Format1, ASN1_EXTENSION_ROOT    , dissect_llc_v1_E2SM_LLC_IndicationMessage_Format1 },
  {   1, &hf_llc_v1_indicationMessage_Format2, ASN1_EXTENSION_ROOT    , dissect_llc_v1_E2SM_LLC_IndicationMessage_Format2 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_ric_indicationMessage_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_ric_indicationMessage_formats, T_ric_indicationMessage_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_IndicationMessage_sequence[] = {
  { &hf_llc_v1_ric_indicationMessage_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_ric_indicationMessage_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_IndicationMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_IndicationMessage, E2SM_LLC_IndicationMessage_sequence);

  return offset;
}


static const per_sequence_t E2SM_LLC_ControlHeader_Format1_sequence[] = {
  { &hf_llc_v1_ric_StyleType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Style_Type },
  { &hf_llc_v1_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_ControlAction_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_ControlHeader_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_ControlHeader_Format1, E2SM_LLC_ControlHeader_Format1_sequence);

  return offset;
}


static const value_string llc_v1_T_ric_controlHeader_formats_vals[] = {
  {   0, "controlHeader-Format1" },
  { 0, NULL }
};

static const per_choice_t T_ric_controlHeader_formats_choice[] = {
  {   0, &hf_llc_v1_controlHeader_Format1, ASN1_EXTENSION_ROOT    , dissect_llc_v1_E2SM_LLC_ControlHeader_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_ric_controlHeader_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_ric_controlHeader_formats, T_ric_controlHeader_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_ControlHeader_sequence[] = {
  { &hf_llc_v1_ric_controlHeader_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_ric_controlHeader_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_ControlHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_ControlHeader, E2SM_LLC_ControlHeader_sequence);

  return offset;
}


static const value_string llc_v1_T_controlType_vals[] = {
  {   0, "logicalChannelHandlingControl" },
  {   1, "dlSchedulingControl" },
  { 0, NULL }
};

static const per_choice_t T_controlType_choice[] = {
  {   0, &hf_llc_v1_logicalChannelHandlingControl, ASN1_EXTENSION_ROOT    , dissect_llc_v1_LogicalChannelHandlingControl },
  {   1, &hf_llc_v1_dlSchedulingControl, ASN1_EXTENSION_ROOT    , dissect_llc_v1_DlSchedulingControl },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_controlType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_controlType, T_controlType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_ControlMessage_Format1_sequence[] = {
  { &hf_llc_v1_controlType  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_controlType },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_ControlMessage_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_ControlMessage_Format1, E2SM_LLC_ControlMessage_Format1_sequence);

  return offset;
}


static const value_string llc_v1_T_ric_controlMessage_formats_vals[] = {
  {   0, "controlMessage-Format1" },
  { 0, NULL }
};

static const per_choice_t T_ric_controlMessage_formats_choice[] = {
  {   0, &hf_llc_v1_controlMessage_Format1, ASN1_EXTENSION_ROOT    , dissect_llc_v1_E2SM_LLC_ControlMessage_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_ric_controlMessage_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_ric_controlMessage_formats, T_ric_controlMessage_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_ControlMessage_sequence[] = {
  { &hf_llc_v1_ric_controlMessage_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_ric_controlMessage_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_ControlMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_ControlMessage, E2SM_LLC_ControlMessage_sequence);

  return offset;
}


static const value_string llc_v1_T_controlType_01_vals[] = {
  {   0, "logicalChannelHandling" },
  {   1, "dlSchedulingParameters" },
  { 0, NULL }
};

static const per_choice_t T_controlType_01_choice[] = {
  {   0, &hf_llc_v1_logicalChannelHandling, ASN1_EXTENSION_ROOT    , dissect_llc_v1_ReceivedTimestamp },
  {   1, &hf_llc_v1_dlSchedulingParameters, ASN1_EXTENSION_ROOT    , dissect_llc_v1_DlSchedulingControlOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_controlType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_controlType_01, T_controlType_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_ControlOutcome_Format1_sequence[] = {
  { &hf_llc_v1_controlType_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_controlType_01 },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_ControlOutcome_Format1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_ControlOutcome_Format1, E2SM_LLC_ControlOutcome_Format1_sequence);

  return offset;
}


static const value_string llc_v1_T_ric_controlOutcome_formats_vals[] = {
  {   0, "controlOutcome-Format1" },
  { 0, NULL }
};

static const per_choice_t T_ric_controlOutcome_formats_choice[] = {
  {   0, &hf_llc_v1_controlOutcome_Format1, ASN1_EXTENSION_ROOT    , dissect_llc_v1_E2SM_LLC_ControlOutcome_Format1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_llc_v1_T_ric_controlOutcome_formats(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_llc_v1_T_ric_controlOutcome_formats, T_ric_controlOutcome_formats_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t E2SM_LLC_ControlOutcome_sequence[] = {
  { &hf_llc_v1_ric_controlOutcome_formats, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_ric_controlOutcome_formats },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_ControlOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_ControlOutcome, E2SM_LLC_ControlOutcome_sequence);

  return offset;
}



static int
dissect_llc_v1_T_ranFunction_ShortName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *value_tvb;
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          &value_tvb);

  if (!actx->pinfo->fd->visited) {
    /* N.B. too early to work out exact dissector, as don't have OID yet */
    e2ap_store_ran_function_mapping(actx->pinfo, tree, value_tvb,
                                    tvb_get_string_enc(actx->pinfo->pool, value_tvb, 0, tvb_captured_length(value_tvb), ENC_ASCII));
  }



  return offset;
}



static int
dissect_llc_v1_T_ranFunction_E2SM_OID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
    offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 1000, true,
                                          &parameter_tvb);

  e2ap_update_ran_function_mapping(actx->pinfo, tree, parameter_tvb,
                                   tvb_get_string_enc(actx->pinfo->pool, parameter_tvb, 0,
				   tvb_captured_length(parameter_tvb), ENC_ASCII));



  return offset;
}



static int
dissect_llc_v1_PrintableString_SIZE_1_150_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}


static const per_sequence_t RANfunction_Name_sequence[] = {
  { &hf_llc_v1_ranFunction_ShortName, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_ranFunction_ShortName },
  { &hf_llc_v1_ranFunction_E2SM_OID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_T_ranFunction_E2SM_OID },
  { &hf_llc_v1_ranFunction_Description, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_PrintableString_SIZE_1_150_ },
  { &hf_llc_v1_ranFunction_Instance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_INTEGER },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_RANfunction_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_RANfunction_Name, RANfunction_Name_sequence);

  return offset;
}



static int
dissect_llc_v1_RIC_Style_Name(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          1, 150, true,
                                          NULL);

  return offset;
}



static int
dissect_llc_v1_RIC_Format_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_integer(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_EventTrigger_Style_Item_LLC_sequence[] = {
  { &hf_llc_v1_ric_EventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Style_Type },
  { &hf_llc_v1_ric_EventTriggerStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Style_Name },
  { &hf_llc_v1_ric_EventTriggerFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_RANFunctionDefinition_EventTrigger_Style_Item_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_RANFunctionDefinition_EventTrigger_Style_Item_LLC, RANFunctionDefinition_EventTrigger_Style_Item_LLC_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_LLC_sequence_of[1] = {
  { &hf_llc_v1_ric_EventTriggerStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_RANFunctionDefinition_EventTrigger_Style_Item_LLC },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_LLC, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_LLC_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_EventTrigger_LLC_sequence[] = {
  { &hf_llc_v1_ric_EventTriggerStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_LLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_RANFunctionDefinition_EventTrigger_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_RANFunctionDefinition_EventTrigger_LLC, RANFunctionDefinition_EventTrigger_LLC_sequence);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Report_Item_LLC_sequence[] = {
  { &hf_llc_v1_ric_ReportStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Style_Type },
  { &hf_llc_v1_ric_ReportStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Style_Name },
  { &hf_llc_v1_ric_SupportedEventTriggerStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Style_Type },
  { &hf_llc_v1_ric_ReportActionFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Format_Type },
  { &hf_llc_v1_ric_IndicationHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Format_Type },
  { &hf_llc_v1_ric_IndicationMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_RANFunctionDefinition_Report_Item_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_RANFunctionDefinition_Report_Item_LLC, RANFunctionDefinition_Report_Item_LLC_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_LLC_sequence_of[1] = {
  { &hf_llc_v1_ric_ReportStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_RANFunctionDefinition_Report_Item_LLC },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_LLC, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_LLC_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Report_LLC_sequence[] = {
  { &hf_llc_v1_ric_ReportStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_LLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_RANFunctionDefinition_Report_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_RANFunctionDefinition_Report_LLC, RANFunctionDefinition_Report_LLC_sequence);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Control_Action_Item_LLC_sequence[] = {
  { &hf_llc_v1_ric_ControlAction_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_ControlAction_ID },
  { &hf_llc_v1_ric_ControlAction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_ControlAction_Name },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_RANFunctionDefinition_Control_Action_Item_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_RANFunctionDefinition_Control_Action_Item_LLC, RANFunctionDefinition_Control_Action_Item_LLC_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_LLC_sequence_of[1] = {
  { &hf_llc_v1_ric_ControlAction_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_RANFunctionDefinition_Control_Action_Item_LLC },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_LLC, SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_LLC_sequence_of,
                                                  1, maxnoofControlAction, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Control_Item_LLC_sequence[] = {
  { &hf_llc_v1_ric_ControlStyle_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Style_Type },
  { &hf_llc_v1_ric_ControlStyle_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Style_Name },
  { &hf_llc_v1_ric_ControlAction_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_LLC },
  { &hf_llc_v1_ric_ControlHeaderFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Format_Type },
  { &hf_llc_v1_ric_ControlMessageFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Format_Type },
  { &hf_llc_v1_ric_CallProcessIDFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_RIC_Format_Type },
  { &hf_llc_v1_ric_ControlOutcomeFormat_Type, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RIC_Format_Type },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_RANFunctionDefinition_Control_Item_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_RANFunctionDefinition_Control_Item_LLC, RANFunctionDefinition_Control_Item_LLC_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_LLC_sequence_of[1] = {
  { &hf_llc_v1_ric_ControlStyle_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_llc_v1_RANFunctionDefinition_Control_Item_LLC },
};

static int
dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_LLC, SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_LLC_sequence_of,
                                                  1, maxnoofRICStyles, false);

  return offset;
}


static const per_sequence_t RANFunctionDefinition_Control_LLC_sequence[] = {
  { &hf_llc_v1_ric_ControlStyle_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_LLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_RANFunctionDefinition_Control_LLC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_RANFunctionDefinition_Control_LLC, RANFunctionDefinition_Control_LLC_sequence);

  return offset;
}


static const per_sequence_t E2SM_LLC_RANFunctionDefinition_sequence[] = {
  { &hf_llc_v1_ranFunction_Name, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_llc_v1_RANfunction_Name },
  { &hf_llc_v1_ranFunctionDefinition_EventTrigger, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_RANFunctionDefinition_EventTrigger_LLC },
  { &hf_llc_v1_ranFunctionDefinition_Report, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_RANFunctionDefinition_Report_LLC },
  { &hf_llc_v1_ranFunctionDefinition_Control, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_llc_v1_RANFunctionDefinition_Control_LLC },
  { NULL, 0, 0, NULL }
};

static int
dissect_llc_v1_E2SM_LLC_RANFunctionDefinition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_llc_v1_E2SM_LLC_RANFunctionDefinition, E2SM_LLC_RANFunctionDefinition_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_E2SM_LLC_EventTrigger_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_llc_v1_E2SM_LLC_EventTrigger(tvb, offset, &asn1_ctx, tree, hf_llc_v1_E2SM_LLC_EventTrigger_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_LLC_ActionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_llc_v1_E2SM_LLC_ActionDefinition(tvb, offset, &asn1_ctx, tree, hf_llc_v1_E2SM_LLC_ActionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_LLC_IndicationHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_llc_v1_E2SM_LLC_IndicationHeader(tvb, offset, &asn1_ctx, tree, hf_llc_v1_E2SM_LLC_IndicationHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_LLC_IndicationMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_llc_v1_E2SM_LLC_IndicationMessage(tvb, offset, &asn1_ctx, tree, hf_llc_v1_E2SM_LLC_IndicationMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_LLC_ControlHeader_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_llc_v1_E2SM_LLC_ControlHeader(tvb, offset, &asn1_ctx, tree, hf_llc_v1_E2SM_LLC_ControlHeader_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_LLC_ControlMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_llc_v1_E2SM_LLC_ControlMessage(tvb, offset, &asn1_ctx, tree, hf_llc_v1_E2SM_LLC_ControlMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_LLC_ControlOutcome_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_llc_v1_E2SM_LLC_ControlOutcome(tvb, offset, &asn1_ctx, tree, hf_llc_v1_E2SM_LLC_ControlOutcome_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E2SM_LLC_RANFunctionDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_llc_v1_E2SM_LLC_RANFunctionDefinition(tvb, offset, &asn1_ctx, tree, hf_llc_v1_E2SM_LLC_RANFunctionDefinition_PDU);
  offset += 7; offset >>= 3;
  return offset;
}



/*--- proto_reg_handoff_llc_v1 ---------------------------------------*/
void
proto_reg_handoff_llc_v1(void)
{
//#include "packet-llc-v1-dis-tab.c"

    static ran_function_dissector_t llc =
    { "ORAN-E2SM-LLC", "1.3.6.1.4.1.53148.1.1.2.5", 1, 0,
      {  dissect_E2SM_LLC_RANFunctionDefinition_PDU,

         dissect_E2SM_LLC_ControlHeader_PDU,
         dissect_E2SM_LLC_ControlMessage_PDU,
         dissect_E2SM_LLC_ControlOutcome_PDU,

         NULL,
         NULL,
         NULL,

         dissect_E2SM_LLC_ActionDefinition_PDU,
         dissect_E2SM_LLC_IndicationMessage_PDU,
         dissect_E2SM_LLC_IndicationHeader_PDU,
         NULL,
         dissect_E2SM_LLC_EventTrigger_PDU
       }
    };

    /* Register dissector with e2ap */
    register_e2ap_ran_function_dissector(LLC_RANFUNCTIONS, &llc);
}



/*--- proto_register_llc_v1 -------------------------------------------*/
void proto_register_llc_v1(void) {

  /* List of fields */

  static hf_register_info hf[] = {
    { &hf_llc_v1_E2SM_LLC_EventTrigger_PDU,
      { "E2SM-LLC-EventTrigger", "llc-v1.E2SM_LLC_EventTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_E2SM_LLC_ActionDefinition_PDU,
      { "E2SM-LLC-ActionDefinition", "llc-v1.E2SM_LLC_ActionDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_E2SM_LLC_IndicationHeader_PDU,
      { "E2SM-LLC-IndicationHeader", "llc-v1.E2SM_LLC_IndicationHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_E2SM_LLC_IndicationMessage_PDU,
      { "E2SM-LLC-IndicationMessage", "llc-v1.E2SM_LLC_IndicationMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_E2SM_LLC_ControlHeader_PDU,
      { "E2SM-LLC-ControlHeader", "llc-v1.E2SM_LLC_ControlHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_E2SM_LLC_ControlMessage_PDU,
      { "E2SM-LLC-ControlMessage", "llc-v1.E2SM_LLC_ControlMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_E2SM_LLC_ControlOutcome_PDU,
      { "E2SM-LLC-ControlOutcome", "llc-v1.E2SM_LLC_ControlOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_E2SM_LLC_RANFunctionDefinition_PDU,
      { "E2SM-LLC-RANFunctionDefinition", "llc-v1.E2SM_LLC_RANFunctionDefinition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ueInfo_List,
      { "ueInfo-List", "llc-v1.ueInfo_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item", HFILL }},
    { &hf_llc_v1_ueInfo_List_item,
      { "EventTrigger-UE-Info-Item", "llc-v1.EventTrigger_UE_Info_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_eventTriggerUEID,
      { "eventTriggerUEID", "llc-v1.eventTriggerUEID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RIC_EventTrigger_UE_ID", HFILL }},
    { &hf_llc_v1_ueType,
      { "ueType", "llc-v1.ueType",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_ueType_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_ueType_Choice_Individual,
      { "ueType-Choice-Individual", "llc-v1.ueType_Choice_Individual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info_Item_Choice_Individual", HFILL }},
    { &hf_llc_v1_ueType_Choice_Group,
      { "ueType-Choice-Group", "llc-v1.ueType_Choice_Group_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info_Item_Choice_Group", HFILL }},
    { &hf_llc_v1_logicalOR,
      { "logicalOR", "llc-v1.logicalOR",
        FT_UINT32, BASE_DEC, VALS(llc_v1_LogicalOR_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_ueID,
      { "ueID", "llc-v1.ueID",
        FT_UINT32, BASE_DEC, VALS(llc_v1_UEID_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_groupOfUEs,
      { "groupOfUEs", "llc-v1.groupOfUEs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_cellGlobalID,
      { "cellGlobalID", "llc-v1.cellGlobalID",
        FT_UINT32, BASE_DEC, VALS(llc_v1_CGI_vals), 0,
        "CGI", HFILL }},
    { &hf_llc_v1_ueIdentifier_List,
      { "ueIdentifier-List", "llc-v1.ueIdentifier_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofUEs_OF_UeIdentifier_Item", HFILL }},
    { &hf_llc_v1_ueIdentifier_List_item,
      { "UeIdentifier-Item", "llc-v1.UeIdentifier_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_slotInfo,
      { "slotInfo", "llc-v1.slotInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_slotStartTime,
      { "slotStartTime", "llc-v1.slotStartTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_llc_v1_systemFramNumber,
      { "systemFramNumber", "llc-v1.systemFramNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023_", HFILL }},
    { &hf_llc_v1_slotIndex,
      { "slotIndex", "llc-v1.slotIndex",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_slotIndex_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_scs_15,
      { "scs-15", "llc-v1.scs_15",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_llc_v1_scs_30,
      { "scs-30", "llc-v1.scs_30",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_19", HFILL }},
    { &hf_llc_v1_scs_60,
      { "scs-60", "llc-v1.scs_60",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_39", HFILL }},
    { &hf_llc_v1_scs_120,
      { "scs-120", "llc-v1.scs_120",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_79", HFILL }},
    { &hf_llc_v1_srsReceiveAntenna_List,
      { "srsReceiveAntenna-List", "llc-v1.srsReceiveAntenna_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofReceiveAntennas_OF_SrsReceiveAntenna_Item", HFILL }},
    { &hf_llc_v1_srsReceiveAntenna_List_item,
      { "SrsReceiveAntenna-Item", "llc-v1.SrsReceiveAntenna_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_srsSymbol_List,
      { "srsSymbol-List", "llc-v1.srsSymbol_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_CONSTR001__OF_SrsSymbol_Item", HFILL }},
    { &hf_llc_v1_srsSymbol_List_item,
      { "SrsSymbol-Item", "llc-v1.SrsSymbol_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_srsCompressionHeader,
      { "srsCompressionHeader", "llc-v1.srsCompressionHeader",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_llc_v1_rawSRS,
      { "rawSRS", "llc-v1.rawSRS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_llc_v1_csiUeIdentifier_List,
      { "csiUeIdentifier-List", "llc-v1.csiUeIdentifier_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEID_OF_CsiUeIdentifier_Item", HFILL }},
    { &hf_llc_v1_csiUeIdentifier_List_item,
      { "CsiUeIdentifier-Item", "llc-v1.CsiUeIdentifier_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_channelCarryingUCI,
      { "channelCarryingUCI", "llc-v1.channelCarryingUCI",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_channelCarryingUCI_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_csiReport_List,
      { "csiReport-List", "llc-v1.csiReport_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofCSIReports_OF_CsiReport_Item", HFILL }},
    { &hf_llc_v1_csiReport_List_item,
      { "CsiReport-Item", "llc-v1.CsiReport_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_csiReportConfigID,
      { "csiReportConfigID", "llc-v1.csiReportConfigID",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_csiFieldsCsiReport_Part1,
      { "csiFieldsCsiReport-Part1", "llc-v1.csiFieldsCsiReport_Part1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_llc_v1_csiFieldsCsiReport_Part2,
      { "csiFieldsCsiReport-Part2", "llc-v1.csiFieldsCsiReport_Part2",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_llc_v1_dlRlcUeIdentifiers_List,
      { "dlRlcUeIdentifiers-List", "llc-v1.dlRlcUeIdentifiers_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEID_OF_DlRlcUeIdentifiers_Item", HFILL }},
    { &hf_llc_v1_dlRlcUeIdentifiers_List_item,
      { "DlRlcUeIdentifiers-Item", "llc-v1.DlRlcUeIdentifiers_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_dlRlcUeBearers_List,
      { "dlRlcUeBearers-List", "llc-v1.dlRlcUeBearers_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlRlcUeBearers_Item", HFILL }},
    { &hf_llc_v1_dlRlcUeBearers_List_item,
      { "DlRlcUeBearers-Item", "llc-v1.DlRlcUeBearers_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_lcID,
      { "lcID", "llc-v1.lcID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32_", HFILL }},
    { &hf_llc_v1_dlRlcBufferOccupancy,
      { "dlRlcBufferOccupancy", "llc-v1.dlRlcBufferOccupancy",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_dlRlcHolTimeToLive,
      { "dlRlcHolTimeToLive", "llc-v1.dlRlcHolTimeToLive",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1032_", HFILL }},
    { &hf_llc_v1_dlPdcpUeIdentifiers_List,
      { "dlPdcpUeIdentifiers-List", "llc-v1.dlPdcpUeIdentifiers_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEID_OF_DlPdcpUeIdentifiers_Item", HFILL }},
    { &hf_llc_v1_dlPdcpUeIdentifiers_List_item,
      { "DlPdcpUeIdentifiers-Item", "llc-v1.DlPdcpUeIdentifiers_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_dlPdcpUeBearers_List,
      { "dlPdcpUeBearers-List", "llc-v1.dlPdcpUeBearers_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlPdcpUeBearers_Item", HFILL }},
    { &hf_llc_v1_dlPdcpUeBearers_List_item,
      { "DlPdcpUeBearers-Item", "llc-v1.DlPdcpUeBearers_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_drbID,
      { "drbID", "llc-v1.drbID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32_", HFILL }},
    { &hf_llc_v1_dlPdcpBufferOccupancy,
      { "dlPdcpBufferOccupancy", "llc-v1.dlPdcpBufferOccupancy",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_dlPdcpHolTimeToLive,
      { "dlPdcpHolTimeToLive", "llc-v1.dlPdcpHolTimeToLive",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1032_", HFILL }},
    { &hf_llc_v1_dlHarqUeIdentifier_List,
      { "dlHarqUeIdentifier-List", "llc-v1.dlHarqUeIdentifier_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEID_OF_DlHarqUeIdentifier_Item", HFILL }},
    { &hf_llc_v1_dlHarqUeIdentifier_List_item,
      { "DlHarqUeIdentifier-Item", "llc-v1.DlHarqUeIdentifier_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_harqUeID,
      { "harqUeID", "llc-v1.harqUeID",
        FT_UINT32, BASE_DEC, VALS(llc_v1_UEID_vals), 0,
        "UEID", HFILL }},
    { &hf_llc_v1_dlHarqCodeword_List,
      { "dlHarqCodeword-List", "llc-v1.dlHarqCodeword_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_CONSTR002__OF_DlHarqCodeword_Item", HFILL }},
    { &hf_llc_v1_dlHarqCodeword_List_item,
      { "DlHarqCodeword-Item", "llc-v1.DlHarqCodeword_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_dlSu_ACK_Count,
      { "dlSu-ACK-Count", "llc-v1.dlSu_ACK_Count",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_dlSu_NACK_Count,
      { "dlSu-NACK-Count", "llc-v1.dlSu_NACK_Count",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_dlSu_DTX_Count,
      { "dlSu-DTX-Count", "llc-v1.dlSu_DTX_Count",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_dlMu_ACK_Count,
      { "dlMu-ACK-Count", "llc-v1.dlMu_ACK_Count",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_dlMu_NACK_Count,
      { "dlMu-NACK-Count", "llc-v1.dlMu_NACK_Count",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_dlMu_DTX_Count,
      { "dlMu-DTX-Count", "llc-v1.dlMu_DTX_Count",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_logicalChannelUEID_List,
      { "logicalChannelUEID-List", "llc-v1.logicalChannelUEID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofUEID_OF_LogicalChannelUEID_Item", HFILL }},
    { &hf_llc_v1_logicalChannelUEID_List_item,
      { "LogicalChannelUEID-Item", "llc-v1.LogicalChannelUEID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_logicalChanContByNearRTRicToAdd_List,
      { "logicalChanContByNearRTRicToAdd-List", "llc-v1.logicalChanContByNearRTRicToAdd_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToAdd_Item", HFILL }},
    { &hf_llc_v1_logicalChanContByNearRTRicToAdd_List_item,
      { "LogicalChanContByNearRTRicToAdd-Item", "llc-v1.LogicalChanContByNearRTRicToAdd_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_logicalChanContByNearRTRicToRel_List,
      { "logicalChanContByNearRTRicToRel-List", "llc-v1.logicalChanContByNearRTRicToRel_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToRel_Item", HFILL }},
    { &hf_llc_v1_logicalChanContByNearRTRicToRel_List_item,
      { "LogicalChanContByNearRTRicToRel-Item", "llc-v1.LogicalChanContByNearRTRicToRel_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_logicalChannelID,
      { "logicalChannelID", "llc-v1.logicalChannelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_startingSlotNumber,
      { "startingSlotNumber", "llc-v1.startingSlotNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SlotInfo", HFILL }},
    { &hf_llc_v1_dlSlotToBeScheduled_List,
      { "dlSlotToBeScheduled-List", "llc-v1.dlSlotToBeScheduled_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlSlotToBeScheduled_Item", HFILL }},
    { &hf_llc_v1_dlSlotToBeScheduled_List_item,
      { "DlSlotToBeScheduled-Item", "llc-v1.DlSlotToBeScheduled_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_dlGrant_List,
      { "dlGrant-List", "llc-v1.dlGrant_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrant_Item", HFILL }},
    { &hf_llc_v1_dlGrant_List_item,
      { "DlGrant-Item", "llc-v1.DlGrant_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_pdschSMG_List,
      { "pdschSMG-List", "llc-v1.pdschSMG_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofPdschSMGs_OF_PdschSMG_Item", HFILL }},
    { &hf_llc_v1_pdschSMG_List_item,
      { "PdschSMG-Item", "llc-v1.PdschSMG_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_csiRsPrecodingBand_List,
      { "csiRsPrecodingBand-List", "llc-v1.csiRsPrecodingBand_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBand_Item", HFILL }},
    { &hf_llc_v1_csiRsPrecodingBand_List_item,
      { "CsiRsPrecodingBand-Item", "llc-v1.CsiRsPrecodingBand_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_precoder_List,
      { "precoder-List", "llc-v1.precoder_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofPrecoders_OF_Precoder_Item", HFILL }},
    { &hf_llc_v1_precoder_List_item,
      { "Precoder-Item", "llc-v1.Precoder_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_grantID,
      { "grantID", "llc-v1.grantID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_63_", HFILL }},
    { &hf_llc_v1_bwpID,
      { "bwpID", "llc-v1.bwpID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4_", HFILL }},
    { &hf_llc_v1_logicalChannel_List,
      { "logicalChannel-List", "llc-v1.logicalChannel_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChannel_Item", HFILL }},
    { &hf_llc_v1_logicalChannel_List_item,
      { "LogicalChannel-Item", "llc-v1.LogicalChannel_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_dlControlInfoType,
      { "dlControlInfoType", "llc-v1.dlControlInfoType",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_dlControlInfoType_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_dci_10,
      { "dci-10", "llc-v1.dci_10_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_dci_11,
      { "dci-11", "llc-v1.dci_11_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_semiPersistence,
      { "semiPersistence", "llc-v1.semiPersistence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_noofBytes_TB1,
      { "noofBytes-TB1", "llc-v1.noofBytes_TB1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_noofBytes_TB2,
      { "noofBytes-TB2", "llc-v1.noofBytes_TB2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_useCsiRnti,
      { "useCsiRnti", "llc-v1.useCsiRnti_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_spsConfigIndex,
      { "spsConfigIndex", "llc-v1.spsConfigIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_activation,
      { "activation", "llc-v1.activation",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_activation_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_freqDomainResources,
      { "freqDomainResources", "llc-v1.freqDomainResources",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_timeDomainResources,
      { "timeDomainResources", "llc-v1.timeDomainResources",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15_", HFILL }},
    { &hf_llc_v1_vrbToPrbMapping,
      { "vrbToPrbMapping", "llc-v1.vrbToPrbMapping",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_vrbToPrbMapping_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_mcs,
      { "mcs", "llc-v1.mcs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31_", HFILL }},
    { &hf_llc_v1_redundancyVersion,
      { "redundancyVersion", "llc-v1.redundancyVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3_", HFILL }},
    { &hf_llc_v1_useCsiRnti_01,
      { "useCsiRnti", "llc-v1.useCsiRnti_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_useCsiRnti_01", HFILL }},
    { &hf_llc_v1_carrierIndicator,
      { "carrierIndicator", "llc-v1.carrierIndicator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_7_", HFILL }},
    { &hf_llc_v1_freqDomainResources_01,
      { "freqDomainResources", "llc-v1.freqDomainResources",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_llc_v1_vrbToPrbMapping_01,
      { "vrbToPrbMapping", "llc-v1.vrbToPrbMapping",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_vrbToPrbMapping_01_vals), 0,
        "T_vrbToPrbMapping_01", HFILL }},
    { &hf_llc_v1_prbBundlingSizeIndicagor,
      { "prbBundlingSizeIndicagor", "llc-v1.prbBundlingSizeIndicagor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1_", HFILL }},
    { &hf_llc_v1_mcs_TB1,
      { "mcs-TB1", "llc-v1.mcs_TB1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31_", HFILL }},
    { &hf_llc_v1_redundancyVersion_TB1,
      { "redundancyVersion-TB1", "llc-v1.redundancyVersion_TB1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3_", HFILL }},
    { &hf_llc_v1_mcs_TB2,
      { "mcs-TB2", "llc-v1.mcs_TB2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31_", HFILL }},
    { &hf_llc_v1_redundancyVersion_TB2,
      { "redundancyVersion-TB2", "llc-v1.redundancyVersion_TB2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3_", HFILL }},
    { &hf_llc_v1_antennaPorts,
      { "antennaPorts", "llc-v1.antennaPorts",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4_6", HFILL }},
    { &hf_llc_v1_transmissionConfigIndication,
      { "transmissionConfigIndication", "llc-v1.transmissionConfigIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7_", HFILL }},
    { &hf_llc_v1_srsRequest,
      { "srsRequest", "llc-v1.srsRequest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2_3", HFILL }},
    { &hf_llc_v1_dmrsSequenceInit,
      { "dmrsSequenceInit", "llc-v1.dmrsSequenceInit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_llc_v1_precoderID,
      { "precoderID", "llc-v1.precoderID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63_", HFILL }},
    { &hf_llc_v1_smgProirity,
      { "smgProirity", "llc-v1.smgProirity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31_", HFILL }},
    { &hf_llc_v1_startRB,
      { "startRB", "llc-v1.startRB",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_noofRBs,
      { "noofRBs", "llc-v1.noofRBs",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_startSymbol,
      { "startSymbol", "llc-v1.startSymbol",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_noofSymbols,
      { "noofSymbols", "llc-v1.noofSymbols",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_ueid,
      { "ueid", "llc-v1.ueid",
        FT_UINT32, BASE_DEC, VALS(llc_v1_UEID_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_nzpCsiRsResourceID,
      { "nzpCsiRsResourceID", "llc-v1.nzpCsiRsResourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_191_", HFILL }},
    { &hf_llc_v1_compressionInformation,
      { "compressionInformation", "llc-v1.compressionInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_precoderCompressionHeader,
      { "precoderCompressionHeader", "llc-v1.precoderCompressionHeader",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_llc_v1_precoderCompressionParam,
      { "precoderCompressionParam", "llc-v1.precoderCompressionParam",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_llc_v1_precoderCoeff_List,
      { "precoderCoeff-List", "llc-v1.precoderCoeff_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofPrecoderCoefficients_OF_PrecoderCoeff_Item", HFILL }},
    { &hf_llc_v1_precoderCoeff_List_item,
      { "PrecoderCoeff-Item", "llc-v1.PrecoderCoeff_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_precoderCoeff_I,
      { "precoderCoeff-I", "llc-v1.precoderCoeff_I",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_precoderCoeff_Q,
      { "precoderCoeff-Q", "llc-v1.precoderCoeff_Q",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_receivedTimstamp,
      { "receivedTimstamp", "llc-v1.receivedTimstamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ReceivedTimestamp", HFILL }},
    { &hf_llc_v1_processingTimeMargin,
      { "processingTimeMargin", "llc-v1.processingTimeMargin",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32767_32767", HFILL }},
    { &hf_llc_v1_scheduledSlotOutcome_List,
      { "scheduledSlotOutcome-List", "llc-v1.scheduledSlotOutcome_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlScheduledSlotOutcome_Item", HFILL }},
    { &hf_llc_v1_scheduledSlotOutcome_List_item,
      { "DlScheduledSlotOutcome-Item", "llc-v1.DlScheduledSlotOutcome_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_dlGrantOutome_List,
      { "dlGrantOutome-List", "llc-v1.dlGrantOutome_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrantOutcome_Item", HFILL }},
    { &hf_llc_v1_dlGrantOutome_List_item,
      { "DlGrantOutcome-Item", "llc-v1.DlGrantOutcome_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_additionalDlAllocation_List,
      { "additionalDlAllocation-List", "llc-v1.additionalDlAllocation_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofDLGrants_OF_AdditionalDlAllocation_Item", HFILL }},
    { &hf_llc_v1_additionalDlAllocation_List_item,
      { "AdditionalDlAllocation-Item", "llc-v1.AdditionalDlAllocation_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_csiRsPrecodingBandsNotExecuted_List,
      { "csiRsPrecodingBandsNotExecuted-List", "llc-v1.csiRsPrecodingBandsNotExecuted_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBandsNotExecuted_Item", HFILL }},
    { &hf_llc_v1_csiRsPrecodingBandsNotExecuted_List_item,
      { "CsiRsPrecodingBandsNotExecuted-Item", "llc-v1.CsiRsPrecodingBandsNotExecuted_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_executionLevel,
      { "executionLevel", "llc-v1.executionLevel",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_executionLevel_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_fullyExecuted,
      { "fullyExecuted", "llc-v1.fullyExecuted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_notFullyExecuted,
      { "notFullyExecuted", "llc-v1.notFullyExecuted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_scheduledLogicalChannelOutcome_List,
      { "scheduledLogicalChannelOutcome-List", "llc-v1.scheduledLogicalChannelOutcome_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_ScheduledLogicalChannelOutcome_Item", HFILL }},
    { &hf_llc_v1_scheduledLogicalChannelOutcome_List_item,
      { "ScheduledLogicalChannelOutcome-Item", "llc-v1.ScheduledLogicalChannelOutcome_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_noofBytesScheduled,
      { "noofBytesScheduled", "llc-v1.noofBytesScheduled",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_cause,
      { "cause", "llc-v1.cause",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_csiRsPrecodingBandID,
      { "csiRsPrecodingBandID", "llc-v1.csiRsPrecodingBandID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63_", HFILL }},
    { &hf_llc_v1_ric_eventTrigger_formats,
      { "ric-eventTrigger-formats", "llc-v1.ric_eventTrigger_formats",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_ric_eventTrigger_formats_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_eventTrigger_Format1,
      { "eventTrigger-Format1", "llc-v1.eventTrigger_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_LLC_EventTrigger_Format1", HFILL }},
    { &hf_llc_v1_eventTrigger_Format2,
      { "eventTrigger-Format2", "llc-v1.eventTrigger_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_LLC_EventTrigger_Format2", HFILL }},
    { &hf_llc_v1_message_List,
      { "message-List", "llc-v1.message_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofLLIs_OF_E2SM_LLC_EventTrigger_Format1_Item", HFILL }},
    { &hf_llc_v1_message_List_item,
      { "E2SM-LLC-EventTrigger-Format1-Item", "llc-v1.E2SM_LLC_EventTrigger_Format1_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_globalAssociatedUEInfo,
      { "globalAssociatedUEInfo", "llc-v1.globalAssociatedUEInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info", HFILL }},
    { &hf_llc_v1_ric_eventTriggerCondition_ID,
      { "ric-eventTriggerCondition-ID", "llc-v1.ric_eventTriggerCondition_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_lowerLayersInfoType,
      { "lowerLayersInfoType", "llc-v1.lowerLayersInfoType",
        FT_UINT32, BASE_DEC, VALS(llc_v1_LowerLayers_Info_Type_vals), 0,
        "LowerLayers_Info_Type", HFILL }},
    { &hf_llc_v1_associatedUEInfo,
      { "associatedUEInfo", "llc-v1.associatedUEInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventTrigger_UE_Info", HFILL }},
    { &hf_llc_v1_reportingPeriod,
      { "reportingPeriod", "llc-v1.reportingPeriod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65535", HFILL }},
    { &hf_llc_v1_ric_Style_Type,
      { "ric-Style-Type", "llc-v1.ric_Style_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ric_actionDefinition_formats,
      { "ric-actionDefinition-formats", "llc-v1.ric_actionDefinition_formats",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_ric_actionDefinition_formats_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_actionDefinition_Format1,
      { "actionDefinition-Format1", "llc-v1.actionDefinition_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_LLC_ActionDefinition_Format1", HFILL }},
    { &hf_llc_v1_actionDefinition_Format2,
      { "actionDefinition-Format2", "llc-v1.actionDefinition_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_LLC_ActionDefinition_Format2", HFILL }},
    { &hf_llc_v1_measurementToReport_List,
      { "measurementToReport-List", "llc-v1.measurementToReport_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofMeasurementsToReport_OF_MeasurementToReport_Item", HFILL }},
    { &hf_llc_v1_measurementToReport_List_item,
      { "MeasurementToReport-Item", "llc-v1.MeasurementToReport_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_lowerLayers_Meas_Type,
      { "lowerLayers-Meas-Type", "llc-v1.lowerLayers_Meas_Type",
        FT_UINT32, BASE_DEC, VALS(llc_v1_LowerLayers_Meas_Type_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_ric_indicationHeader_formats,
      { "ric-indicationHeader-formats", "llc-v1.ric_indicationHeader_formats",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_ric_indicationHeader_formats_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_indicationHeader_Format1,
      { "indicationHeader-Format1", "llc-v1.indicationHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_LLC_IndicationHeader_Format1", HFILL }},
    { &hf_llc_v1_ric_indicationMessage_formats,
      { "ric-indicationMessage-formats", "llc-v1.ric_indicationMessage_formats",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_ric_indicationMessage_formats_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_indicationMessage_Format1,
      { "indicationMessage-Format1", "llc-v1.indicationMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_LLC_IndicationMessage_Format1", HFILL }},
    { &hf_llc_v1_indicationMessage_Format2,
      { "indicationMessage-Format2", "llc-v1.indicationMessage_Format2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_LLC_IndicationMessage_Format2", HFILL }},
    { &hf_llc_v1_slotTimeStamp,
      { "slotTimeStamp", "llc-v1.slotTimeStamp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_lowerLayersInfoType_01,
      { "lowerLayersInfoType", "llc-v1.lowerLayersInfoType",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_lowerLayersInfoType_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_sRS,
      { "sRS", "llc-v1.sRS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_cSI,
      { "cSI", "llc-v1.cSI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_lowerLayersMeasurement_List,
      { "lowerLayersMeasurement-List", "llc-v1.lowerLayersMeasurement_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofMeasurements_OF_LowerLayersMeasurement_Item", HFILL }},
    { &hf_llc_v1_lowerLayersMeasurement_List_item,
      { "LowerLayersMeasurement-Item", "llc-v1.LowerLayersMeasurement_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_lowerLayersMeasurementType,
      { "lowerLayersMeasurementType", "llc-v1.lowerLayersMeasurementType",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_lowerLayersMeasurementType_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_dlRlcBufferStatus,
      { "dlRlcBufferStatus", "llc-v1.dlRlcBufferStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_dlPdcpBufferStatus,
      { "dlPdcpBufferStatus", "llc-v1.dlPdcpBufferStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_dlHarqStatistics,
      { "dlHarqStatistics", "llc-v1.dlHarqStatistics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_slotTimeStamp_01,
      { "slotTimeStamp", "llc-v1.slotTimeStamp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ric_controlHeader_formats,
      { "ric-controlHeader-formats", "llc-v1.ric_controlHeader_formats",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_ric_controlHeader_formats_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_controlHeader_Format1,
      { "controlHeader-Format1", "llc-v1.controlHeader_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_LLC_ControlHeader_Format1", HFILL }},
    { &hf_llc_v1_ric_StyleType,
      { "ric-StyleType", "llc-v1.ric_StyleType",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_llc_v1_ric_ControlAction_ID,
      { "ric-ControlAction-ID", "llc-v1.ric_ControlAction_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ric_controlMessage_formats,
      { "ric-controlMessage-formats", "llc-v1.ric_controlMessage_formats",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_ric_controlMessage_formats_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_controlMessage_Format1,
      { "controlMessage-Format1", "llc-v1.controlMessage_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_LLC_ControlMessage_Format1", HFILL }},
    { &hf_llc_v1_controlType,
      { "controlType", "llc-v1.controlType",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_controlType_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_logicalChannelHandlingControl,
      { "logicalChannelHandlingControl", "llc-v1.logicalChannelHandlingControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_dlSchedulingControl,
      { "dlSchedulingControl", "llc-v1.dlSchedulingControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ric_controlOutcome_formats,
      { "ric-controlOutcome-formats", "llc-v1.ric_controlOutcome_formats",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_ric_controlOutcome_formats_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_controlOutcome_Format1,
      { "controlOutcome-Format1", "llc-v1.controlOutcome_Format1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "E2SM_LLC_ControlOutcome_Format1", HFILL }},
    { &hf_llc_v1_controlType_01,
      { "controlType", "llc-v1.controlType",
        FT_UINT32, BASE_DEC, VALS(llc_v1_T_controlType_01_vals), 0,
        "T_controlType_01", HFILL }},
    { &hf_llc_v1_logicalChannelHandling,
      { "logicalChannelHandling", "llc-v1.logicalChannelHandling",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ReceivedTimestamp", HFILL }},
    { &hf_llc_v1_dlSchedulingParameters,
      { "dlSchedulingParameters", "llc-v1.dlSchedulingParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DlSchedulingControlOutcome", HFILL }},
    { &hf_llc_v1_ranFunction_Name,
      { "ranFunction-Name", "llc-v1.ranFunction_Name_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ranFunctionDefinition_EventTrigger,
      { "ranFunctionDefinition-EventTrigger", "llc-v1.ranFunctionDefinition_EventTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANFunctionDefinition_EventTrigger_LLC", HFILL }},
    { &hf_llc_v1_ranFunctionDefinition_Report,
      { "ranFunctionDefinition-Report", "llc-v1.ranFunctionDefinition_Report_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANFunctionDefinition_Report_LLC", HFILL }},
    { &hf_llc_v1_ranFunctionDefinition_Control,
      { "ranFunctionDefinition-Control", "llc-v1.ranFunctionDefinition_Control_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RANFunctionDefinition_Control_LLC", HFILL }},
    { &hf_llc_v1_ric_EventTriggerStyle_List,
      { "ric-EventTriggerStyle-List", "llc-v1.ric_EventTriggerStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_LLC", HFILL }},
    { &hf_llc_v1_ric_EventTriggerStyle_List_item,
      { "RANFunctionDefinition-EventTrigger-Style-Item-LLC", "llc-v1.RANFunctionDefinition_EventTrigger_Style_Item_LLC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ric_EventTriggerStyle_Type,
      { "ric-EventTriggerStyle-Type", "llc-v1.ric_EventTriggerStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_llc_v1_ric_EventTriggerStyle_Name,
      { "ric-EventTriggerStyle-Name", "llc-v1.ric_EventTriggerStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_llc_v1_ric_EventTriggerFormat_Type,
      { "ric-EventTriggerFormat-Type", "llc-v1.ric_EventTriggerFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_llc_v1_ric_ReportStyle_List,
      { "ric-ReportStyle-List", "llc-v1.ric_ReportStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_LLC", HFILL }},
    { &hf_llc_v1_ric_ReportStyle_List_item,
      { "RANFunctionDefinition-Report-Item-LLC", "llc-v1.RANFunctionDefinition_Report_Item_LLC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ric_ReportStyle_Type,
      { "ric-ReportStyle-Type", "llc-v1.ric_ReportStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_llc_v1_ric_ReportStyle_Name,
      { "ric-ReportStyle-Name", "llc-v1.ric_ReportStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_llc_v1_ric_SupportedEventTriggerStyle_Type,
      { "ric-SupportedEventTriggerStyle-Type", "llc-v1.ric_SupportedEventTriggerStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_llc_v1_ric_ReportActionFormat_Type,
      { "ric-ReportActionFormat-Type", "llc-v1.ric_ReportActionFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_llc_v1_ric_IndicationHeaderFormat_Type,
      { "ric-IndicationHeaderFormat-Type", "llc-v1.ric_IndicationHeaderFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_llc_v1_ric_IndicationMessageFormat_Type,
      { "ric-IndicationMessageFormat-Type", "llc-v1.ric_IndicationMessageFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_llc_v1_ric_ControlStyle_List,
      { "ric-ControlStyle-List", "llc-v1.ric_ControlStyle_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_LLC", HFILL }},
    { &hf_llc_v1_ric_ControlStyle_List_item,
      { "RANFunctionDefinition-Control-Item-LLC", "llc-v1.RANFunctionDefinition_Control_Item_LLC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ric_ControlStyle_Type,
      { "ric-ControlStyle-Type", "llc-v1.ric_ControlStyle_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Style_Type", HFILL }},
    { &hf_llc_v1_ric_ControlStyle_Name,
      { "ric-ControlStyle-Name", "llc-v1.ric_ControlStyle_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIC_Style_Name", HFILL }},
    { &hf_llc_v1_ric_ControlAction_List,
      { "ric-ControlAction-List", "llc-v1.ric_ControlAction_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_LLC", HFILL }},
    { &hf_llc_v1_ric_ControlAction_List_item,
      { "RANFunctionDefinition-Control-Action-Item-LLC", "llc-v1.RANFunctionDefinition_Control_Action_Item_LLC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ric_ControlHeaderFormat_Type,
      { "ric-ControlHeaderFormat-Type", "llc-v1.ric_ControlHeaderFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_llc_v1_ric_ControlMessageFormat_Type,
      { "ric-ControlMessageFormat-Type", "llc-v1.ric_ControlMessageFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_llc_v1_ric_CallProcessIDFormat_Type,
      { "ric-CallProcessIDFormat-Type", "llc-v1.ric_CallProcessIDFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_llc_v1_ric_ControlOutcomeFormat_Type,
      { "ric-ControlOutcomeFormat-Type", "llc-v1.ric_ControlOutcomeFormat_Type",
        FT_INT32, BASE_DEC, NULL, 0,
        "RIC_Format_Type", HFILL }},
    { &hf_llc_v1_ric_ControlAction_Name,
      { "ric-ControlAction-Name", "llc-v1.ric_ControlAction_Name",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_c_RNTI,
      { "c-RNTI", "llc-v1.c_RNTI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RNTI_Value", HFILL }},
    { &hf_llc_v1_cell_Global_ID,
      { "cell-Global-ID", "llc-v1.cell_Global_ID",
        FT_UINT32, BASE_DEC, VALS(llc_v1_CGI_vals), 0,
        "CGI", HFILL }},
    { &hf_llc_v1_nR_CGI,
      { "nR-CGI", "llc-v1.nR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_eUTRA_CGI,
      { "eUTRA-CGI", "llc-v1.eUTRA_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ranFunction_ShortName,
      { "ranFunction-ShortName", "llc-v1.ranFunction_ShortName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ranFunction_E2SM_OID,
      { "ranFunction-E2SM-OID", "llc-v1.ranFunction_E2SM_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ranFunction_Description,
      { "ranFunction-Description", "llc-v1.ranFunction_Description",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_150_", HFILL }},
    { &hf_llc_v1_ranFunction_Instance,
      { "ranFunction-Instance", "llc-v1.ranFunction_Instance",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_llc_v1_gNB_UEID,
      { "gNB-UEID", "llc-v1.gNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB", HFILL }},
    { &hf_llc_v1_gNB_DU_UEID,
      { "gNB-DU-UEID", "llc-v1.gNB_DU_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB_DU", HFILL }},
    { &hf_llc_v1_gNB_CU_UP_UEID,
      { "gNB-CU-UP-UEID", "llc-v1.gNB_CU_UP_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_GNB_CU_UP", HFILL }},
    { &hf_llc_v1_ng_eNB_UEID,
      { "ng-eNB-UEID", "llc-v1.ng_eNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_NG_ENB", HFILL }},
    { &hf_llc_v1_ng_eNB_DU_UEID,
      { "ng-eNB-DU-UEID", "llc-v1.ng_eNB_DU_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_NG_ENB_DU", HFILL }},
    { &hf_llc_v1_en_gNB_UEID,
      { "en-gNB-UEID", "llc-v1.en_gNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_EN_GNB", HFILL }},
    { &hf_llc_v1_eNB_UEID,
      { "eNB-UEID", "llc-v1.eNB_UEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UEID_ENB", HFILL }},
    { &hf_llc_v1_amf_UE_NGAP_ID,
      { "amf-UE-NGAP-ID", "llc-v1.amf_UE_NGAP_ID",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_guami,
      { "guami", "llc-v1.guami_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_gNB_CU_UE_F1AP_ID_List,
      { "gNB-CU-UE-F1AP-ID-List", "llc-v1.gNB_CU_UE_F1AP_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UEID_GNB_CU_F1AP_ID_List", HFILL }},
    { &hf_llc_v1_gNB_CU_CP_UE_E1AP_ID_List,
      { "gNB-CU-CP-UE-E1AP-ID-List", "llc-v1.gNB_CU_CP_UE_E1AP_ID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UEID_GNB_CU_CP_E1AP_ID_List", HFILL }},
    { &hf_llc_v1_ran_UEID,
      { "ran-UEID", "llc-v1.ran_UEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RANUEID", HFILL }},
    { &hf_llc_v1_m_NG_RAN_UE_XnAP_ID,
      { "m-NG-RAN-UE-XnAP-ID", "llc-v1.m_NG_RAN_UE_XnAP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NG_RANnodeUEXnAPID", HFILL }},
    { &hf_llc_v1_globalGNB_ID,
      { "globalGNB-ID", "llc-v1.globalGNB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_globalNG_RANNode_ID,
      { "globalNG-RANNode-ID", "llc-v1.globalNG_RANNode_ID",
        FT_UINT32, BASE_DEC, VALS(llc_v1_GlobalNGRANNodeID_vals), 0,
        "GlobalNGRANNodeID", HFILL }},
    { &hf_llc_v1_cell_RNTI,
      { "cell-RNTI", "llc-v1.cell_RNTI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_UEID_GNB_CU_CP_E1AP_ID_List_item,
      { "UEID-GNB-CU-CP-E1AP-ID-Item", "llc-v1.UEID_GNB_CU_CP_E1AP_ID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_gNB_CU_CP_UE_E1AP_ID,
      { "gNB-CU-CP-UE-E1AP-ID", "llc-v1.gNB_CU_CP_UE_E1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_UEID_GNB_CU_F1AP_ID_List_item,
      { "UEID-GNB-CU-CP-F1AP-ID-Item", "llc-v1.UEID_GNB_CU_CP_F1AP_ID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_gNB_CU_UE_F1AP_ID,
      { "gNB-CU-UE-F1AP-ID", "llc-v1.gNB_CU_UE_F1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_ng_eNB_CU_UE_W1AP_ID,
      { "ng-eNB-CU-UE-W1AP-ID", "llc-v1.ng_eNB_CU_UE_W1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NGENB_CU_UE_W1AP_ID", HFILL }},
    { &hf_llc_v1_globalNgENB_ID,
      { "globalNgENB-ID", "llc-v1.globalNgENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_m_eNB_UE_X2AP_ID,
      { "m-eNB-UE-X2AP-ID", "llc-v1.m_eNB_UE_X2AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ENB_UE_X2AP_ID", HFILL }},
    { &hf_llc_v1_m_eNB_UE_X2AP_ID_Extension,
      { "m-eNB-UE-X2AP-ID-Extension", "llc-v1.m_eNB_UE_X2AP_ID_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ENB_UE_X2AP_ID_Extension", HFILL }},
    { &hf_llc_v1_globalENB_ID,
      { "globalENB-ID", "llc-v1.globalENB_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_mME_UE_S1AP_ID,
      { "mME-UE-S1AP-ID", "llc-v1.mME_UE_S1AP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_gUMMEI,
      { "gUMMEI", "llc-v1.gUMMEI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_macro_eNB_ID,
      { "macro-eNB-ID", "llc-v1.macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_llc_v1_home_eNB_ID,
      { "home-eNB-ID", "llc-v1.home_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_28", HFILL }},
    { &hf_llc_v1_short_Macro_eNB_ID,
      { "short-Macro-eNB-ID", "llc-v1.short_Macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_llc_v1_long_Macro_eNB_ID,
      { "long-Macro-eNB-ID", "llc-v1.long_Macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_llc_v1_pLMNIdentity,
      { "pLMNIdentity", "llc-v1.pLMNIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_eNB_ID,
      { "eNB-ID", "llc-v1.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(llc_v1_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_pLMN_Identity,
      { "pLMN-Identity", "llc-v1.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNIdentity", HFILL }},
    { &hf_llc_v1_mME_Group_ID,
      { "mME-Group-ID", "llc-v1.mME_Group_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_mME_Code,
      { "mME-Code", "llc-v1.mME_Code",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_eUTRACellIdentity,
      { "eUTRACellIdentity", "llc-v1.eUTRACellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_gnb_id_choice,
      { "gNB-ID", "llc-v1.gnb_id_choice",
        FT_UINT32, BASE_DEC, VALS(llc_v1_GNB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_ngENB_ID,
      { "ngENB-ID", "llc-v1.ngENB_ID",
        FT_UINT32, BASE_DEC, VALS(llc_v1_NgENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_llc_v1_gNB_ID,
      { "gNB-ID", "llc-v1.gNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_22_32", HFILL }},
    { &hf_llc_v1_aMFRegionID,
      { "aMFRegionID", "llc-v1.aMFRegionID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_aMFSetID,
      { "aMFSetID", "llc-v1.aMFSetID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_aMFPointer,
      { "aMFPointer", "llc-v1.aMFPointer",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_macroNgENB_ID,
      { "macroNgENB-ID", "llc-v1.macroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_20", HFILL }},
    { &hf_llc_v1_shortMacroNgENB_ID,
      { "shortMacroNgENB-ID", "llc-v1.shortMacroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_18", HFILL }},
    { &hf_llc_v1_longMacroNgENB_ID,
      { "longMacroNgENB-ID", "llc-v1.longMacroNgENB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_21", HFILL }},
    { &hf_llc_v1_nRCellIdentity,
      { "nRCellIdentity", "llc-v1.nRCellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_llc_v1_gNB,
      { "gNB", "llc-v1.gNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalGNB_ID", HFILL }},
    { &hf_llc_v1_ng_eNB,
      { "ng-eNB", "llc-v1.ng_eNB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GlobalNgENB_ID", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_llc_v1_EventTrigger_UE_Info,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEInfo_OF_EventTrigger_UE_Info_Item,
    &ett_llc_v1_EventTrigger_UE_Info_Item,
    &ett_llc_v1_T_ueType,
    &ett_llc_v1_EventTrigger_UE_Info_Item_Choice_Individual,
    &ett_llc_v1_EventTrigger_UE_Info_Item_Choice_Group,
    &ett_llc_v1_GroupOfUEs,
    &ett_llc_v1_SEQUENCE_SIZE_0_maxnoofUEs_OF_UeIdentifier_Item,
    &ett_llc_v1_UeIdentifier_Item,
    &ett_llc_v1_SlotTimeStamp,
    &ett_llc_v1_SlotInfo,
    &ett_llc_v1_T_slotIndex,
    &ett_llc_v1_SRS,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofReceiveAntennas_OF_SrsReceiveAntenna_Item,
    &ett_llc_v1_SrsReceiveAntenna_Item,
    &ett_llc_v1_SEQUENCE_SIZE_CONSTR001__OF_SrsSymbol_Item,
    &ett_llc_v1_SrsSymbol_Item,
    &ett_llc_v1_CSI,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_CsiUeIdentifier_Item,
    &ett_llc_v1_CsiUeIdentifier_Item,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofCSIReports_OF_CsiReport_Item,
    &ett_llc_v1_CsiReport_Item,
    &ett_llc_v1_DlRlcBufferStatus,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlRlcUeIdentifiers_Item,
    &ett_llc_v1_DlRlcUeIdentifiers_Item,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlRlcUeBearers_Item,
    &ett_llc_v1_DlRlcUeBearers_Item,
    &ett_llc_v1_DlPdcpBufferStatus,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlPdcpUeIdentifiers_Item,
    &ett_llc_v1_DlPdcpUeIdentifiers_Item,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEBearers_OF_DlPdcpUeBearers_Item,
    &ett_llc_v1_DlPdcpUeBearers_Item,
    &ett_llc_v1_DlHarqStatistics,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_DlHarqUeIdentifier_Item,
    &ett_llc_v1_DlHarqUeIdentifier_Item,
    &ett_llc_v1_SEQUENCE_SIZE_CONSTR002__OF_DlHarqCodeword_Item,
    &ett_llc_v1_DlHarqCodeword_Item,
    &ett_llc_v1_LogicalChannelHandlingControl,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofUEID_OF_LogicalChannelUEID_Item,
    &ett_llc_v1_LogicalChannelUEID_Item,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToAdd_Item,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChanContByNearRTRicToRel_Item,
    &ett_llc_v1_LogicalChanContByNearRTRicToAdd_Item,
    &ett_llc_v1_LogicalChanContByNearRTRicToRel_Item,
    &ett_llc_v1_DlSchedulingControl,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlSlotToBeScheduled_Item,
    &ett_llc_v1_DlSlotToBeScheduled_Item,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrant_Item,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofPdschSMGs_OF_PdschSMG_Item,
    &ett_llc_v1_SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBand_Item,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofPrecoders_OF_Precoder_Item,
    &ett_llc_v1_DlGrant_Item,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_LogicalChannel_Item,
    &ett_llc_v1_T_dlControlInfoType,
    &ett_llc_v1_LogicalChannel_Item,
    &ett_llc_v1_Dci_10,
    &ett_llc_v1_T_useCsiRnti,
    &ett_llc_v1_Dci_11,
    &ett_llc_v1_T_useCsiRnti_01,
    &ett_llc_v1_PdschSMG_Item,
    &ett_llc_v1_CsiRsPrecodingBand_Item,
    &ett_llc_v1_Precoder_Item,
    &ett_llc_v1_T_compressionInformation,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofPrecoderCoefficients_OF_PrecoderCoeff_Item,
    &ett_llc_v1_PrecoderCoeff_Item,
    &ett_llc_v1_DlSchedulingControlOutcome,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofScheduledDLSlots_OF_DlScheduledSlotOutcome_Item,
    &ett_llc_v1_DlScheduledSlotOutcome_Item,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofDLGrants_OF_DlGrantOutcome_Item,
    &ett_llc_v1_SEQUENCE_SIZE_0_maxnoofDLGrants_OF_AdditionalDlAllocation_Item,
    &ett_llc_v1_SEQUENCE_SIZE_0_maxnoofCsiRsPrecodingBands_OF_CsiRsPrecodingBandsNotExecuted_Item,
    &ett_llc_v1_DlGrantOutcome_Item,
    &ett_llc_v1_T_executionLevel,
    &ett_llc_v1_T_notFullyExecuted,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLogicalChannels_OF_ScheduledLogicalChannelOutcome_Item,
    &ett_llc_v1_ScheduledLogicalChannelOutcome_Item,
    &ett_llc_v1_AdditionalDlAllocation_Item,
    &ett_llc_v1_CsiRsPrecodingBandsNotExecuted_Item,
    &ett_llc_v1_E2SM_LLC_EventTrigger,
    &ett_llc_v1_T_ric_eventTrigger_formats,
    &ett_llc_v1_E2SM_LLC_EventTrigger_Format1,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofLLIs_OF_E2SM_LLC_EventTrigger_Format1_Item,
    &ett_llc_v1_E2SM_LLC_EventTrigger_Format1_Item,
    &ett_llc_v1_E2SM_LLC_EventTrigger_Format2,
    &ett_llc_v1_E2SM_LLC_ActionDefinition,
    &ett_llc_v1_T_ric_actionDefinition_formats,
    &ett_llc_v1_E2SM_LLC_ActionDefinition_Format1,
    &ett_llc_v1_E2SM_LLC_ActionDefinition_Format2,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofMeasurementsToReport_OF_MeasurementToReport_Item,
    &ett_llc_v1_MeasurementToReport_Item,
    &ett_llc_v1_E2SM_LLC_IndicationHeader,
    &ett_llc_v1_T_ric_indicationHeader_formats,
    &ett_llc_v1_E2SM_LLC_IndicationHeader_Format1,
    &ett_llc_v1_E2SM_LLC_IndicationMessage,
    &ett_llc_v1_T_ric_indicationMessage_formats,
    &ett_llc_v1_E2SM_LLC_IndicationMessage_Format1,
    &ett_llc_v1_T_lowerLayersInfoType,
    &ett_llc_v1_E2SM_LLC_IndicationMessage_Format2,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofMeasurements_OF_LowerLayersMeasurement_Item,
    &ett_llc_v1_LowerLayersMeasurement_Item,
    &ett_llc_v1_T_lowerLayersMeasurementType,
    &ett_llc_v1_E2SM_LLC_ControlHeader,
    &ett_llc_v1_T_ric_controlHeader_formats,
    &ett_llc_v1_E2SM_LLC_ControlHeader_Format1,
    &ett_llc_v1_E2SM_LLC_ControlMessage,
    &ett_llc_v1_T_ric_controlMessage_formats,
    &ett_llc_v1_E2SM_LLC_ControlMessage_Format1,
    &ett_llc_v1_T_controlType,
    &ett_llc_v1_E2SM_LLC_ControlOutcome,
    &ett_llc_v1_T_ric_controlOutcome_formats,
    &ett_llc_v1_E2SM_LLC_ControlOutcome_Format1,
    &ett_llc_v1_T_controlType_01,
    &ett_llc_v1_E2SM_LLC_RANFunctionDefinition,
    &ett_llc_v1_RANFunctionDefinition_EventTrigger_LLC,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_EventTrigger_Style_Item_LLC,
    &ett_llc_v1_RANFunctionDefinition_EventTrigger_Style_Item_LLC,
    &ett_llc_v1_RANFunctionDefinition_Report_LLC,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Report_Item_LLC,
    &ett_llc_v1_RANFunctionDefinition_Report_Item_LLC,
    &ett_llc_v1_RANFunctionDefinition_Control_LLC,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofRICStyles_OF_RANFunctionDefinition_Control_Item_LLC,
    &ett_llc_v1_RANFunctionDefinition_Control_Item_LLC,
    &ett_llc_v1_SEQUENCE_SIZE_1_maxnoofControlAction_OF_RANFunctionDefinition_Control_Action_Item_LLC,
    &ett_llc_v1_RANFunctionDefinition_Control_Action_Item_LLC,
    &ett_llc_v1_Cell_RNTI,
    &ett_llc_v1_CGI,
    &ett_llc_v1_RANfunction_Name,
    &ett_llc_v1_UEID,
    &ett_llc_v1_UEID_GNB,
    &ett_llc_v1_UEID_GNB_CU_CP_E1AP_ID_List,
    &ett_llc_v1_UEID_GNB_CU_CP_E1AP_ID_Item,
    &ett_llc_v1_UEID_GNB_CU_F1AP_ID_List,
    &ett_llc_v1_UEID_GNB_CU_CP_F1AP_ID_Item,
    &ett_llc_v1_UEID_GNB_DU,
    &ett_llc_v1_UEID_GNB_CU_UP,
    &ett_llc_v1_UEID_NG_ENB,
    &ett_llc_v1_UEID_NG_ENB_DU,
    &ett_llc_v1_UEID_EN_GNB,
    &ett_llc_v1_UEID_ENB,
    &ett_llc_v1_ENB_ID,
    &ett_llc_v1_GlobalENB_ID,
    &ett_llc_v1_GUMMEI,
    &ett_llc_v1_EUTRA_CGI,
    &ett_llc_v1_GlobalGNB_ID,
    &ett_llc_v1_GlobalNgENB_ID,
    &ett_llc_v1_GNB_ID,
    &ett_llc_v1_GUAMI,
    &ett_llc_v1_NgENB_ID,
    &ett_llc_v1_NR_CGI,
    &ett_llc_v1_GlobalNGRANNodeID,
  };


  /* Register protocol */
  proto_llc_v1 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_llc_v1, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

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
