/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-nrppa.c                                                             */
/* asn2wrs.py -q -L -p nrppa -c ./nrppa.cnf -s ./packet-nrppa-template -D . -O ../.. NRPPA-CommonDataTypes.asn NRPPA-Constants.asn NRPPA-Containers.asn NRPPA-PDU-Descriptions.asn NRPPA-IEs.asn NRPPA-PDU-Contents.asn */

/* packet-nrppa.c
 * Routines for 3GPP NR Positioning Protocol A (NRPPa) packet dissection
 * Copyright 2019, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref 3GPP TS 38.455 V18.2.0 (2024-06)
 * https://www.3gpp.org
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-nrppa.h"

#define PNAME  "NR Positioning Protocol A (NRPPa)"
#define PSNAME "NRPPa"
#define PFNAME "nrppa"

void proto_register_nrppa(void);
void proto_reg_handoff_nrppa(void);

/* Initialize the protocol and registered fields */
static int proto_nrppa;

static int hf_nrppa_NRPPA_PDU_PDU;                /* NRPPA_PDU */
static int hf_nrppa_AbortTransmission_PDU;        /* AbortTransmission */
static int hf_nrppa_AggregatedPosSRSResourceID_List_PDU;  /* AggregatedPosSRSResourceID_List */
static int hf_nrppa_AggregatedPRSResourceSetList_PDU;  /* AggregatedPRSResourceSetList */
static int hf_nrppa_ExtendedAdditionalPathList_PDU;  /* ExtendedAdditionalPathList */
static int hf_nrppa_AoA_AssistanceInfo_PDU;       /* AoA_AssistanceInfo */
static int hf_nrppa_ARP_ID_PDU;                   /* ARP_ID */
static int hf_nrppa_ARPLocationInformation_PDU;   /* ARPLocationInformation */
static int hf_nrppa_nrppa_Assistance_Information_PDU;  /* Assistance_Information */
static int hf_nrppa_AssistanceInformationFailureList_PDU;  /* AssistanceInformationFailureList */
static int hf_nrppa_Bandwidth_Aggregation_Request_Indication_PDU;  /* Bandwidth_Aggregation_Request_Indication */
static int hf_nrppa_Broadcast_PDU;                /* Broadcast */
static int hf_nrppa_PositioningBroadcastCells_PDU;  /* PositioningBroadcastCells */
static int hf_nrppa_Cause_PDU;                    /* Cause */
static int hf_nrppa_Cell_Portion_ID_PDU;          /* Cell_Portion_ID */
static int hf_nrppa_CGI_NR_PDU;                   /* CGI_NR */
static int hf_nrppa_CriticalityDiagnostics_PDU;   /* CriticalityDiagnostics */
static int hf_nrppa_CommonTAParameters_PDU;       /* CommonTAParameters */
static int hf_nrppa_E_CID_MeasurementResult_PDU;  /* E_CID_MeasurementResult */
static int hf_nrppa_GeographicalCoordinates_PDU;  /* GeographicalCoordinates */
static int hf_nrppa_LoS_NLoSInformation_PDU;      /* LoS_NLoSInformation */
static int hf_nrppa_MeasBasedOnAggregatedResources_PDU;  /* MeasBasedOnAggregatedResources */
static int hf_nrppa_Measurement_ID_PDU;           /* Measurement_ID */
static int hf_nrppa_MeasurementAmount_PDU;        /* MeasurementAmount */
static int hf_nrppa_MeasurementBeamInfoRequest_PDU;  /* MeasurementBeamInfoRequest */
static int hf_nrppa_MeasurementPeriodicity_PDU;   /* MeasurementPeriodicity */
static int hf_nrppa_MeasurementPeriodicityExtended_PDU;  /* MeasurementPeriodicityExtended */
static int hf_nrppa_MeasurementPeriodicityNR_AoA_PDU;  /* MeasurementPeriodicityNR_AoA */
static int hf_nrppa_MeasurementQuantities_PDU;    /* MeasurementQuantities */
static int hf_nrppa_MeasurementQuantities_Item_PDU;  /* MeasurementQuantities_Item */
static int hf_nrppa_MeasurementTimeOccasion_PDU;  /* MeasurementTimeOccasion */
static int hf_nrppa_MeasurementCharacteristicsRequestIndicator_PDU;  /* MeasurementCharacteristicsRequestIndicator */
static int hf_nrppa_MeasuredResultsAssociatedInfoList_PDU;  /* MeasuredResultsAssociatedInfoList */
static int hf_nrppa_Mobile_TRP_LocationInformation_PDU;  /* Mobile_TRP_LocationInformation */
static int hf_nrppa_Mobile_IAB_MT_UE_ID_PDU;      /* Mobile_IAB_MT_UE_ID */
static int hf_nrppa_MultipleULAoA_PDU;            /* MultipleULAoA */
static int hf_nrppa_MeasuredFrequencyHops_PDU;    /* MeasuredFrequencyHops */
static int hf_nrppa_NrofSymbolsExtended_PDU;      /* NrofSymbolsExtended */
static int hf_nrppa_NR_PCI_PDU;                   /* NR_PCI */
static int hf_nrppa_NR_TADV_PDU;                  /* NR_TADV */
static int hf_nrppa_NumberOfTRPRxTEG_PDU;         /* NumberOfTRPRxTEG */
static int hf_nrppa_NumberOfTRPRxTxTEG_PDU;       /* NumberOfTRPRxTxTEG */
static int hf_nrppa_OnDemandPRS_Info_PDU;         /* OnDemandPRS_Info */
static int hf_nrppa_OTDOACells_PDU;               /* OTDOACells */
static int hf_nrppa_OtherRATMeasurementQuantities_PDU;  /* OtherRATMeasurementQuantities */
static int hf_nrppa_OtherRATMeasurementQuantities_Item_PDU;  /* OtherRATMeasurementQuantities_Item */
static int hf_nrppa_OtherRATMeasurementResult_PDU;  /* OtherRATMeasurementResult */
static int hf_nrppa_PRSBWAggregationRequestIndication_PDU;  /* PRSBWAggregationRequestIndication */
static int hf_nrppa_PosSRSResourceSet_Aggregation_List_PDU;  /* PosSRSResourceSet_Aggregation_List */
static int hf_nrppa_PreconfigurationResult_PDU;   /* PreconfigurationResult */
static int hf_nrppa_PRSConfigRequestType_PDU;     /* PRSConfigRequestType */
static int hf_nrppa_PRS_Measurements_Info_List_PDU;  /* PRS_Measurements_Info_List */
static int hf_nrppa_ExtendedResourceSymbolOffset_PDU;  /* ExtendedResourceSymbolOffset */
static int hf_nrppa_PRS_Resource_ID_PDU;          /* PRS_Resource_ID */
static int hf_nrppa_PRSTRPList_PDU;               /* PRSTRPList */
static int hf_nrppa_PRSTransmissionTRPList_PDU;   /* PRSTransmissionTRPList */
static int hf_nrppa_PosValidityAreaCellList_PDU;  /* PosValidityAreaCellList */
static int hf_nrppa_PointA_PDU;                   /* PointA */
static int hf_nrppa_RepetitionFactorExtended_PDU;  /* RepetitionFactorExtended */
static int hf_nrppa_ReportCharacteristics_PDU;    /* ReportCharacteristics */
static int hf_nrppa_ReportingGranularitykminus1_PDU;  /* ReportingGranularitykminus1 */
static int hf_nrppa_ReportingGranularitykminus2_PDU;  /* ReportingGranularitykminus2 */
static int hf_nrppa_ReportingGranularitykminus3_PDU;  /* ReportingGranularitykminus3 */
static int hf_nrppa_ReportingGranularitykminus4_PDU;  /* ReportingGranularitykminus4 */
static int hf_nrppa_ReportingGranularitykminus5_PDU;  /* ReportingGranularitykminus5 */
static int hf_nrppa_ReportingGranularitykminus6_PDU;  /* ReportingGranularitykminus6 */
static int hf_nrppa_ReportingGranularitykminus1AdditionalPath_PDU;  /* ReportingGranularitykminus1AdditionalPath */
static int hf_nrppa_ReportingGranularitykminus2AdditionalPath_PDU;  /* ReportingGranularitykminus2AdditionalPath */
static int hf_nrppa_ReportingGranularitykminus3AdditionalPath_PDU;  /* ReportingGranularitykminus3AdditionalPath */
static int hf_nrppa_ReportingGranularitykminus4AdditionalPath_PDU;  /* ReportingGranularitykminus4AdditionalPath */
static int hf_nrppa_ReportingGranularitykminus5AdditionalPath_PDU;  /* ReportingGranularitykminus5AdditionalPath */
static int hf_nrppa_ReportingGranularitykminus6AdditionalPath_PDU;  /* ReportingGranularitykminus6AdditionalPath */
static int hf_nrppa_RequestedSRSTransmissionCharacteristics_PDU;  /* RequestedSRSTransmissionCharacteristics */
static int hf_nrppa_RequestedSRSPreconfigurationCharacteristics_List_PDU;  /* RequestedSRSPreconfigurationCharacteristics_List */
static int hf_nrppa_RequestType_PDU;              /* RequestType */
static int hf_nrppa_ResponseTime_PDU;             /* ResponseTime */
static int hf_nrppa_ResultCSI_RSRP_PDU;           /* ResultCSI_RSRP */
static int hf_nrppa_ResultCSI_RSRQ_PDU;           /* ResultCSI_RSRQ */
static int hf_nrppa_ResultEUTRA_PDU;              /* ResultEUTRA */
static int hf_nrppa_ResultSS_RSRP_PDU;            /* ResultSS_RSRP */
static int hf_nrppa_ResultSS_RSRQ_PDU;            /* ResultSS_RSRQ */
static int hf_nrppa_ResultNR_PDU;                 /* ResultNR */
static int hf_nrppa_SCS_480_PDU;                  /* SCS_480 */
static int hf_nrppa_SCS_960_PDU;                  /* SCS_960 */
static int hf_nrppa_SCS_SpecificCarrier_PDU;      /* SCS_SpecificCarrier */
static int hf_nrppa_RelativeTime1900_PDU;         /* RelativeTime1900 */
static int hf_nrppa_SFNInitialisationTime_EUTRA_PDU;  /* SFNInitialisationTime_EUTRA */
static int hf_nrppa_SlotNumber_PDU;               /* SlotNumber */
static int hf_nrppa_SpatialRelationInfo_PDU;      /* SpatialRelationInfo */
static int hf_nrppa_SpatialRelationPerSRSResource_PDU;  /* SpatialRelationPerSRSResource */
static int hf_nrppa_nrppa_SRSConfiguration_PDU;   /* SRSConfiguration */
static int hf_nrppa_SrsFrequency_PDU;             /* SrsFrequency */
static int hf_nrppa_SRSPortIndex_PDU;             /* SRSPortIndex */
static int hf_nrppa_SRSResourcetype_PDU;          /* SRSResourcetype */
static int hf_nrppa_SRSTransmissionStatus_PDU;    /* SRSTransmissionStatus */
static int hf_nrppa_StartRBIndex_PDU;             /* StartRBIndex */
static int hf_nrppa_StartRBHopping_PDU;           /* StartRBHopping */
static int hf_nrppa_SymbolIndex_PDU;              /* SymbolIndex */
static int hf_nrppa_SystemFrameNumber_PDU;        /* SystemFrameNumber */
static int hf_nrppa_SRSReservationType_PDU;       /* SRSReservationType */
static int hf_nrppa_SRSPreconfiguration_List_PDU;  /* SRSPreconfiguration_List */
static int hf_nrppa_TDD_Config_EUTRA_Item_PDU;    /* TDD_Config_EUTRA_Item */
static int hf_nrppa_TRPTEGInformation_PDU;        /* TRPTEGInformation */
static int hf_nrppa_TimingErrorMargin_PDU;        /* TimingErrorMargin */
static int hf_nrppa_TimingReportingGranularityFactorExtended_PDU;  /* TimingReportingGranularityFactorExtended */
static int hf_nrppa_TimeWindowInformation_Measurement_List_PDU;  /* TimeWindowInformation_Measurement_List */
static int hf_nrppa_TimeWindowInformation_SRS_List_PDU;  /* TimeWindowInformation_SRS_List */
static int hf_nrppa_TransmissionCombn8_PDU;       /* TransmissionCombn8 */
static int hf_nrppa_TRPBeamAntennaInformation_PDU;  /* TRPBeamAntennaInformation */
static int hf_nrppa_TRPMeasurementQuantities_PDU;  /* TRPMeasurementQuantities */
static int hf_nrppa_TRPPhaseQuality_PDU;          /* TRPPhaseQuality */
static int hf_nrppa_TRP_MeasurementRequestList_PDU;  /* TRP_MeasurementRequestList */
static int hf_nrppa_TRP_MeasurementResponseList_PDU;  /* TRP_MeasurementResponseList */
static int hf_nrppa_TRP_MeasurementUpdateList_PDU;  /* TRP_MeasurementUpdateList */
static int hf_nrppa_TRPInformationListTRPResp_PDU;  /* TRPInformationListTRPResp */
static int hf_nrppa_TRPInformationTypeListTRPReq_PDU;  /* TRPInformationTypeListTRPReq */
static int hf_nrppa_TRPInformationTypeItem_PDU;   /* TRPInformationTypeItem */
static int hf_nrppa_TRPList_PDU;                  /* TRPList */
static int hf_nrppa_TRP_PRS_Information_List_PDU;  /* TRP_PRS_Information_List */
static int hf_nrppa_TRP_Rx_TEGInformation_PDU;    /* TRP_Rx_TEGInformation */
static int hf_nrppa_TRPTxTEGAssociation_PDU;      /* TRPTxTEGAssociation */
static int hf_nrppa_TRPType_PDU;                  /* TRPType */
static int hf_nrppa_TxHoppingConfiguration_PDU;   /* TxHoppingConfiguration */
static int hf_nrppa_UE_Measurement_ID_PDU;        /* UE_Measurement_ID */
static int hf_nrppa_UEReportingInformation_PDU;   /* UEReportingInformation */
static int hf_nrppa_UE_Rx_Tx_Time_Diff_PDU;       /* UE_Rx_Tx_Time_Diff */
static int hf_nrppa_UE_TEG_ReportingPeriodicity_PDU;  /* UE_TEG_ReportingPeriodicity */
static int hf_nrppa_UETxTEGAssociationList_PDU;   /* UETxTEGAssociationList */
static int hf_nrppa_UE_TEG_Info_Request_PDU;      /* UE_TEG_Info_Request */
static int hf_nrppa_UL_AoA_PDU;                   /* UL_AoA */
static int hf_nrppa_UL_RSCPMeas_PDU;              /* UL_RSCPMeas */
static int hf_nrppa_UL_SRS_RSRPP_PDU;             /* UL_SRS_RSRPP */
static int hf_nrppa_ValidityAreaSpecificSRSInformation_PDU;  /* ValidityAreaSpecificSRSInformation */
static int hf_nrppa_WLANMeasurementQuantities_PDU;  /* WLANMeasurementQuantities */
static int hf_nrppa_WLANMeasurementQuantities_Item_PDU;  /* WLANMeasurementQuantities_Item */
static int hf_nrppa_WLANMeasurementResult_PDU;    /* WLANMeasurementResult */
static int hf_nrppa_ZoA_PDU;                      /* ZoA */
static int hf_nrppa_E_CIDMeasurementInitiationRequest_PDU;  /* E_CIDMeasurementInitiationRequest */
static int hf_nrppa_E_CIDMeasurementInitiationResponse_PDU;  /* E_CIDMeasurementInitiationResponse */
static int hf_nrppa_E_CIDMeasurementInitiationFailure_PDU;  /* E_CIDMeasurementInitiationFailure */
static int hf_nrppa_E_CIDMeasurementFailureIndication_PDU;  /* E_CIDMeasurementFailureIndication */
static int hf_nrppa_E_CIDMeasurementReport_PDU;   /* E_CIDMeasurementReport */
static int hf_nrppa_E_CIDMeasurementTerminationCommand_PDU;  /* E_CIDMeasurementTerminationCommand */
static int hf_nrppa_OTDOAInformationRequest_PDU;  /* OTDOAInformationRequest */
static int hf_nrppa_OTDOA_Information_Type_PDU;   /* OTDOA_Information_Type */
static int hf_nrppa_OTDOA_Information_Type_Item_PDU;  /* OTDOA_Information_Type_Item */
static int hf_nrppa_OTDOAInformationResponse_PDU;  /* OTDOAInformationResponse */
static int hf_nrppa_OTDOAInformationFailure_PDU;  /* OTDOAInformationFailure */
static int hf_nrppa_AssistanceInformationControl_PDU;  /* AssistanceInformationControl */
static int hf_nrppa_AssistanceInformationFeedback_PDU;  /* AssistanceInformationFeedback */
static int hf_nrppa_ErrorIndication_PDU;          /* ErrorIndication */
static int hf_nrppa_PrivateMessage_PDU;           /* PrivateMessage */
static int hf_nrppa_PositioningInformationRequest_PDU;  /* PositioningInformationRequest */
static int hf_nrppa_PositioningInformationResponse_PDU;  /* PositioningInformationResponse */
static int hf_nrppa_PositioningInformationFailure_PDU;  /* PositioningInformationFailure */
static int hf_nrppa_PositioningInformationUpdate_PDU;  /* PositioningInformationUpdate */
static int hf_nrppa_MeasurementRequest_PDU;       /* MeasurementRequest */
static int hf_nrppa_MeasurementResponse_PDU;      /* MeasurementResponse */
static int hf_nrppa_MeasurementFailure_PDU;       /* MeasurementFailure */
static int hf_nrppa_MeasurementReport_PDU;        /* MeasurementReport */
static int hf_nrppa_MeasurementUpdate_PDU;        /* MeasurementUpdate */
static int hf_nrppa_MeasurementAbort_PDU;         /* MeasurementAbort */
static int hf_nrppa_MeasurementFailureIndication_PDU;  /* MeasurementFailureIndication */
static int hf_nrppa_TRPInformationRequest_PDU;    /* TRPInformationRequest */
static int hf_nrppa_TRPInformationResponse_PDU;   /* TRPInformationResponse */
static int hf_nrppa_TRPInformationFailure_PDU;    /* TRPInformationFailure */
static int hf_nrppa_PositioningActivationRequest_PDU;  /* PositioningActivationRequest */
static int hf_nrppa_SRSType_PDU;                  /* SRSType */
static int hf_nrppa_PositioningActivationResponse_PDU;  /* PositioningActivationResponse */
static int hf_nrppa_PositioningActivationFailure_PDU;  /* PositioningActivationFailure */
static int hf_nrppa_PositioningDeactivation_PDU;  /* PositioningDeactivation */
static int hf_nrppa_PRSConfigurationRequest_PDU;  /* PRSConfigurationRequest */
static int hf_nrppa_PRSConfigurationResponse_PDU;  /* PRSConfigurationResponse */
static int hf_nrppa_PRSConfigurationFailure_PDU;  /* PRSConfigurationFailure */
static int hf_nrppa_MeasurementPreconfigurationRequired_PDU;  /* MeasurementPreconfigurationRequired */
static int hf_nrppa_MeasurementPreconfigurationConfirm_PDU;  /* MeasurementPreconfigurationConfirm */
static int hf_nrppa_MeasurementPreconfigurationRefuse_PDU;  /* MeasurementPreconfigurationRefuse */
static int hf_nrppa_MeasurementActivation_PDU;    /* MeasurementActivation */
static int hf_nrppa_SRSInformationReservationNotification_PDU;  /* SRSInformationReservationNotification */
static int hf_nrppa_local;                        /* INTEGER_0_maxPrivateIEs */
static int hf_nrppa_global;                       /* OBJECT_IDENTIFIER */
static int hf_nrppa_ProtocolIE_Container_item;    /* ProtocolIE_Field */
static int hf_nrppa_id;                           /* ProtocolIE_ID */
static int hf_nrppa_criticality;                  /* Criticality */
static int hf_nrppa_ie_field_value;               /* T_ie_field_value */
static int hf_nrppa_ProtocolExtensionContainer_item;  /* ProtocolExtensionField */
static int hf_nrppa_ext_id;                       /* ProtocolIE_ID */
static int hf_nrppa_extensionValue;               /* T_extensionValue */
static int hf_nrppa_PrivateIE_Container_item;     /* PrivateIE_Field */
static int hf_nrppa_id_01;                        /* PrivateIE_ID */
static int hf_nrppa_value;                        /* T_value */
static int hf_nrppa_initiatingMessage;            /* InitiatingMessage */
static int hf_nrppa_successfulOutcome;            /* SuccessfulOutcome */
static int hf_nrppa_unsuccessfulOutcome;          /* UnsuccessfulOutcome */
static int hf_nrppa_procedureCode;                /* ProcedureCode */
static int hf_nrppa_nrppatransactionID;           /* NRPPATransactionID */
static int hf_nrppa_initiatingMessagevalue;       /* InitiatingMessage_value */
static int hf_nrppa_successfulOutcome_value;      /* SuccessfulOutcome_value */
static int hf_nrppa_unsuccessfulOutcome_value;    /* UnsuccessfulOutcome_value */
static int hf_nrppa_deactivateSRSResourceSetID;   /* SRSResourceSetID */
static int hf_nrppa_releaseALL;                   /* NULL */
static int hf_nrppa_choice_extension;             /* ProtocolIE_Single_Container */
static int hf_nrppa_locationAndBandwidth;         /* INTEGER_0_37949_ */
static int hf_nrppa_subcarrierSpacing;            /* T_subcarrierSpacing */
static int hf_nrppa_cyclicPrefix;                 /* T_cyclicPrefix */
static int hf_nrppa_txDirectCurrentLocation;      /* INTEGER_0_3301_ */
static int hf_nrppa_shift7dot5kHz;                /* T_shift7dot5kHz */
static int hf_nrppa_sRSConfig;                    /* SRSConfig */
static int hf_nrppa_iE_Extensions;                /* ProtocolExtensionContainer */
static int hf_nrppa_AdditionalPathList_item;      /* AdditionalPathListItem */
static int hf_nrppa_relativeTimeOfPath;           /* RelativePathDelay */
static int hf_nrppa_pathQuality;                  /* TrpMeasurementQuality */
static int hf_nrppa_AggregatedPosSRSResourceID_List_item;  /* AggregatedPosSRSResourceID_Item */
static int hf_nrppa_sRSPosResource_ID;            /* SRSPosResourceID */
static int hf_nrppa_AggregatedPRSResourceSetList_item;  /* AggregatedPRSResourceSet_Item */
static int hf_nrppa_dl_PRS_ResourceSet_List;      /* DL_PRS_ResourceSet_List */
static int hf_nrppa_DL_PRS_ResourceSet_List_item;  /* DL_PRS_ResourceSet_Item */
static int hf_nrppa_dl_prs_ResourceSetIndex;      /* INTEGER_1_8 */
static int hf_nrppa_ExtendedAdditionalPathList_item;  /* ExtendedAdditionalPathList_Item */
static int hf_nrppa_multipleULAoA;                /* MultipleULAoA */
static int hf_nrppa_pathPower;                    /* UL_SRS_RSRPP */
static int hf_nrppa_angleMeasurement;             /* AngleMeasurementType */
static int hf_nrppa_lCS_to_GCS_Translation;       /* LCS_to_GCS_Translation */
static int hf_nrppa_AperiodicSRSResourceTriggerList_item;  /* AperiodicSRSResourceTrigger */
static int hf_nrppa_expected_ULAoA;               /* Expected_UL_AoA */
static int hf_nrppa_expected_ZoA;                 /* Expected_ZoA_only */
static int hf_nrppa_expected_Azimuth_AoA;         /* Expected_Azimuth_AoA */
static int hf_nrppa_expected_Zenith_AoA;          /* Expected_Zenith_AoA */
static int hf_nrppa_iE_extensions;                /* ProtocolExtensionContainer */
static int hf_nrppa_expected_ZoA_only;            /* Expected_Zenith_AoA */
static int hf_nrppa_expected_Azimuth_AoA_value;   /* Expected_Value_AoA */
static int hf_nrppa_expected_Azimuth_AoA_uncertainty;  /* Uncertainty_range_AoA */
static int hf_nrppa_expected_Zenith_AoA_value;    /* Expected_Value_ZoA */
static int hf_nrppa_expected_Zenith_AoA_uncertainty;  /* Uncertainty_range_ZoA */
static int hf_nrppa_ARPLocationInformation_item;  /* ARPLocationInformation_Item */
static int hf_nrppa_aRP_ID;                       /* ARP_ID */
static int hf_nrppa_aRPLocationType;              /* ARPLocationType */
static int hf_nrppa_aRPPositionRelativeGeodetic;  /* RelativeGeodeticLocation */
static int hf_nrppa_aRPPositionRelativeCartesian;  /* RelativeCartesianLocation */
static int hf_nrppa_systemInformation;            /* SystemInformation */
static int hf_nrppa_AssistanceInformationFailureList_item;  /* AssistanceInformationFailureList_item */
static int hf_nrppa_posSIB_Type;                  /* PosSIB_Type */
static int hf_nrppa_outcome;                      /* Outcome */
static int hf_nrppa_encrypted;                    /* T_encrypted */
static int hf_nrppa_gNSSID;                       /* T_gNSSID */
static int hf_nrppa_sBASID;                       /* T_sBASID */
static int hf_nrppa_fR1;                          /* T_fR1 */
static int hf_nrppa_fR2;                          /* T_fR2 */
static int hf_nrppa_PositioningBroadcastCells_item;  /* NG_RAN_CGI */
static int hf_nrppa_pointA;                       /* INTEGER_0_3279165 */
static int hf_nrppa_offsetToCarrier;              /* INTEGER_0_2199_ */
static int hf_nrppa_radioNetwork;                 /* CauseRadioNetwork */
static int hf_nrppa_protocol;                     /* CauseProtocol */
static int hf_nrppa_misc;                         /* CauseMisc */
static int hf_nrppa_choice_Extension;             /* ProtocolIE_Single_Container */
static int hf_nrppa_pLMN_Identity;                /* PLMN_Identity */
static int hf_nrppa_eUTRAcellIdentifier;          /* EUTRACellIdentifier */
static int hf_nrppa_nRcellIdentifier;             /* NRCellIdentifier */
static int hf_nrppa_triggeringMessage;            /* TriggeringMessage */
static int hf_nrppa_procedureCriticality;         /* Criticality */
static int hf_nrppa_iEsCriticalityDiagnostics;    /* CriticalityDiagnostics_IE_List */
static int hf_nrppa_CriticalityDiagnostics_IE_List_item;  /* CriticalityDiagnostics_IE_List_item */
static int hf_nrppa_iECriticality;                /* Criticality */
static int hf_nrppa_iE_ID;                        /* ProtocolIE_ID */
static int hf_nrppa_typeOfError;                  /* TypeOfError */
static int hf_nrppa_epochTime;                    /* OCTET_STRING */
static int hf_nrppa_taInfo;                       /* OCTET_STRING */
static int hf_nrppa_prsid;                        /* PRS_ID */
static int hf_nrppa_dl_PRSResourceSetID;          /* PRS_Resource_Set_ID */
static int hf_nrppa_dl_PRSResourceID;             /* PRS_Resource_ID */
static int hf_nrppa_two;                          /* BIT_STRING_SIZE_2 */
static int hf_nrppa_four;                         /* BIT_STRING_SIZE_4 */
static int hf_nrppa_six;                          /* BIT_STRING_SIZE_6 */
static int hf_nrppa_eight;                        /* BIT_STRING_SIZE_8 */
static int hf_nrppa_sixteen;                      /* BIT_STRING_SIZE_16 */
static int hf_nrppa_thirty_two;                   /* BIT_STRING_SIZE_32 */
static int hf_nrppa_listofDL_PRSResourceSetARP;   /* SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_DLPRSResourceSetARP */
static int hf_nrppa_listofDL_PRSResourceSetARP_item;  /* DLPRSResourceSetARP */
static int hf_nrppa_dL_PRSResourceSetARPLocation;  /* DL_PRSResourceSetARPLocation */
static int hf_nrppa_listofDL_PRSResourceARP;      /* SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceARP */
static int hf_nrppa_listofDL_PRSResourceARP_item;  /* DLPRSResourceARP */
static int hf_nrppa_relativeGeodeticLocation;     /* RelativeGeodeticLocation */
static int hf_nrppa_relativeCartesianLocation;    /* RelativeCartesianLocation */
static int hf_nrppa_dL_PRSResourceARPLocation;    /* DL_PRSResourceARPLocation */
static int hf_nrppa_servingCell_ID;               /* NG_RAN_CGI */
static int hf_nrppa_servingCellTAC;               /* TAC */
static int hf_nrppa_nG_RANAccessPointPosition;    /* NG_RANAccessPointPosition */
static int hf_nrppa_measuredResults;              /* MeasuredResults */
static int hf_nrppa_tRPPositionDefinitionType;    /* TRPPositionDefinitionType */
static int hf_nrppa_dLPRSResourceCoordinates;     /* DLPRSResourceCoordinates */
static int hf_nrppa_rxTxTimeDiff;                 /* GNBRxTxTimeDiffMeas */
static int hf_nrppa_additionalPathList;           /* AdditionalPathList */
static int hf_nrppa_k0;                           /* INTEGER_0_1970049 */
static int hf_nrppa_k1;                           /* INTEGER_0_985025 */
static int hf_nrppa_k2;                           /* INTEGER_0_492513 */
static int hf_nrppa_k3;                           /* INTEGER_0_246257 */
static int hf_nrppa_k4;                           /* INTEGER_0_123129 */
static int hf_nrppa_k5;                           /* INTEGER_0_61565 */
static int hf_nrppa_alpha;                        /* INTEGER_0_3599 */
static int hf_nrppa_beta;                         /* INTEGER_0_3599 */
static int hf_nrppa_gamma;                        /* INTEGER_0_3599 */
static int hf_nrppa_alpha_01;                     /* INTEGER_0_359 */
static int hf_nrppa_alphaFine;                    /* INTEGER_0_9 */
static int hf_nrppa_beta_01;                      /* INTEGER_0_359 */
static int hf_nrppa_betaFine;                     /* INTEGER_0_9 */
static int hf_nrppa_gamma_01;                     /* INTEGER_0_359 */
static int hf_nrppa_gammaFine;                    /* INTEGER_0_9 */
static int hf_nrppa_horizontalUncertainty;        /* INTEGER_0_255 */
static int hf_nrppa_horizontalConfidence;         /* INTEGER_0_100 */
static int hf_nrppa_verticalUncertainty;          /* INTEGER_0_255 */
static int hf_nrppa_verticalConfidence;           /* INTEGER_0_100 */
static int hf_nrppa_loS_NLoSIndicatorSoft;        /* LoS_NLoSIndicatorSoft */
static int hf_nrppa_loS_NLoSIndicatorHard;        /* LoS_NLoSIndicatorHard */
static int hf_nrppa_pRS_Resource_ID;              /* PRS_Resource_ID */
static int hf_nrppa_pRS_Resource_Set_ID;          /* PRS_Resource_Set_ID */
static int hf_nrppa_sSB_Index;                    /* SSB_Index */
static int hf_nrppa_MeasurementQuantities_item;   /* ProtocolIE_Single_Container */
static int hf_nrppa_measurementQuantitiesValue;   /* MeasurementQuantitiesValue */
static int hf_nrppa_MeasuredResults_item;         /* MeasuredResultsValue */
static int hf_nrppa_MeasuredResultsAssociatedInfoList_item;  /* MeasuredResultsAssociatedInfoItem */
static int hf_nrppa_timeStamp;                    /* TimeStamp */
static int hf_nrppa_measurementQuality;           /* TrpMeasurementQuality */
static int hf_nrppa_valueAngleOfArrival_EUTRA;    /* INTEGER_0_719 */
static int hf_nrppa_valueTimingAdvanceType1_EUTRA;  /* INTEGER_0_7690 */
static int hf_nrppa_valueTimingAdvanceType2_EUTRA;  /* INTEGER_0_7690 */
static int hf_nrppa_resultRSRP_EUTRA;             /* ResultRSRP_EUTRA */
static int hf_nrppa_resultRSRQ_EUTRA;             /* ResultRSRQ_EUTRA */
static int hf_nrppa_location_Information;         /* OCTET_STRING */
static int hf_nrppa_velocity_Information;         /* OCTET_STRING */
static int hf_nrppa_location_time_stamp;          /* TimeStamp */
static int hf_nrppa_multipleULAoA_01;             /* MultipleULAoA_List */
static int hf_nrppa_MultipleULAoA_List_item;      /* MultipleULAoA_Item */
static int hf_nrppa_uL_AoA;                       /* UL_AoA */
static int hf_nrppa_ul_ZoA;                       /* ZoA */
static int hf_nrppa_latitudeSign;                 /* T_latitudeSign */
static int hf_nrppa_latitude;                     /* INTEGER_0_8388607 */
static int hf_nrppa_longitude;                    /* INTEGER_M8388608_8388607 */
static int hf_nrppa_directionOfAltitude;          /* T_directionOfAltitude */
static int hf_nrppa_altitude;                     /* INTEGER_0_32767 */
static int hf_nrppa_uncertaintySemi_major;        /* INTEGER_0_127 */
static int hf_nrppa_uncertaintySemi_minor;        /* INTEGER_0_127 */
static int hf_nrppa_orientationOfMajorAxis;       /* INTEGER_0_179 */
static int hf_nrppa_uncertaintyAltitude;          /* INTEGER_0_127 */
static int hf_nrppa_confidence;                   /* INTEGER_0_100 */
static int hf_nrppa_latitude_01;                  /* INTEGER_M2147483648_2147483647 */
static int hf_nrppa_longitude_01;                 /* INTEGER_M2147483648_2147483647 */
static int hf_nrppa_altitude_01;                  /* INTEGER_M64000_1280000 */
static int hf_nrppa_uncertaintySemi_major_01;     /* INTEGER_0_255 */
static int hf_nrppa_uncertaintySemi_minor_01;     /* INTEGER_0_255 */
static int hf_nrppa_uncertaintyAltitude_01;       /* INTEGER_0_255 */
static int hf_nrppa_nG_RANcell;                   /* NG_RANCell */
static int hf_nrppa_eUTRA_CellID;                 /* EUTRACellIdentifier */
static int hf_nrppa_nR_CellID;                    /* NRCellIdentifier */
static int hf_nrppa_nR_PRS_Beam_InformationList;  /* SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_NR_PRS_Beam_InformationItem */
static int hf_nrppa_nR_PRS_Beam_InformationList_item;  /* NR_PRS_Beam_InformationItem */
static int hf_nrppa_lCS_to_GCS_TranslationList;   /* SEQUENCE_SIZE_1_maxnolcs_gcs_translation_OF_LCS_to_GCS_TranslationItem */
static int hf_nrppa_lCS_to_GCS_TranslationList_item;  /* LCS_to_GCS_TranslationItem */
static int hf_nrppa_pRSresourceSetID;             /* PRS_Resource_Set_ID */
static int hf_nrppa_pRSAngle;                     /* SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_PRSAngleItem */
static int hf_nrppa_pRSAngle_item;                /* PRSAngleItem */
static int hf_nrppa_onDemandPRSRequestAllowed;    /* BIT_STRING_SIZE_16 */
static int hf_nrppa_allowedResourceSetPeriodicityValues;  /* BIT_STRING_SIZE_24 */
static int hf_nrppa_allowedPRSBandwidthValues;    /* BIT_STRING_SIZE_64 */
static int hf_nrppa_allowedResourceRepetitionFactorValues;  /* BIT_STRING_SIZE_8 */
static int hf_nrppa_allowedResourceNumberOfSymbolsValues;  /* BIT_STRING_SIZE_8 */
static int hf_nrppa_allowedCombSizeValues;        /* BIT_STRING_SIZE_8 */
static int hf_nrppa_OTDOACells_item;              /* OTDOACells_item */
static int hf_nrppa_oTDOACellInfo;                /* OTDOACell_Information */
static int hf_nrppa_OTDOACell_Information_item;   /* OTDOACell_Information_Item */
static int hf_nrppa_pCI_EUTRA;                    /* PCI_EUTRA */
static int hf_nrppa_cGI_EUTRA;                    /* CGI_EUTRA */
static int hf_nrppa_tAC;                          /* TAC */
static int hf_nrppa_eARFCN;                       /* EARFCN */
static int hf_nrppa_pRS_Bandwidth_EUTRA;          /* PRS_Bandwidth_EUTRA */
static int hf_nrppa_pRS_ConfigurationIndex_EUTRA;  /* PRS_ConfigurationIndex_EUTRA */
static int hf_nrppa_cPLength_EUTRA;               /* CPLength_EUTRA */
static int hf_nrppa_numberOfDlFrames_EUTRA;       /* NumberOfDlFrames_EUTRA */
static int hf_nrppa_numberOfAntennaPorts_EUTRA;   /* NumberOfAntennaPorts_EUTRA */
static int hf_nrppa_sFNInitialisationTime_EUTRA;  /* SFNInitialisationTime_EUTRA */
static int hf_nrppa_pRSMutingConfiguration_EUTRA;  /* PRSMutingConfiguration_EUTRA */
static int hf_nrppa_prsid_EUTRA;                  /* PRS_ID_EUTRA */
static int hf_nrppa_tpid_EUTRA;                   /* TP_ID_EUTRA */
static int hf_nrppa_tpType_EUTRA;                 /* TP_Type_EUTRA */
static int hf_nrppa_numberOfDlFrames_Extended_EUTRA;  /* NumberOfDlFrames_Extended_EUTRA */
static int hf_nrppa_crsCPlength_EUTRA;            /* CPLength_EUTRA */
static int hf_nrppa_dL_Bandwidth_EUTRA;           /* DL_Bandwidth_EUTRA */
static int hf_nrppa_pRSOccasionGroup_EUTRA;       /* PRSOccasionGroup_EUTRA */
static int hf_nrppa_pRSFrequencyHoppingConfiguration_EUTRA;  /* PRSFrequencyHoppingConfiguration_EUTRA */
static int hf_nrppa_OtherRATMeasurementQuantities_item;  /* ProtocolIE_Single_Container */
static int hf_nrppa_otherRATMeasurementQuantitiesValue;  /* OtherRATMeasurementQuantitiesValue */
static int hf_nrppa_OtherRATMeasurementResult_item;  /* OtherRATMeasuredResultsValue */
static int hf_nrppa_resultGERAN;                  /* ResultGERAN */
static int hf_nrppa_resultUTRAN;                  /* ResultUTRAN */
static int hf_nrppa_pathlossReferenceSignal;      /* PathlossReferenceSignal */
static int hf_nrppa_sSB_Reference;                /* SSB */
static int hf_nrppa_dL_PRS_Reference;             /* DL_PRS */
static int hf_nrppa_PeriodicityList_item;         /* PeriodicityItem */
static int hf_nrppa_PosSIBs_item;                 /* PosSIBs_item */
static int hf_nrppa_posSIB_Segments;              /* PosSIB_Segments */
static int hf_nrppa_assistanceInformationMetaData;  /* AssistanceInformationMetaData */
static int hf_nrppa_broadcastPriority;            /* INTEGER_1_16_ */
static int hf_nrppa_PosSIB_Segments_item;         /* PosSIB_Segments_item */
static int hf_nrppa_assistanceDataSIBelement;     /* OCTET_STRING */
static int hf_nrppa_PosSRSResource_List_item;     /* PosSRSResource_Item */
static int hf_nrppa_srs_PosResourceId;            /* SRSPosResourceID */
static int hf_nrppa_transmissionCombPos;          /* TransmissionCombPos */
static int hf_nrppa_startPosition;                /* INTEGER_0_13 */
static int hf_nrppa_nrofSymbols;                  /* T_nrofSymbols */
static int hf_nrppa_freqDomainShift;              /* INTEGER_0_268 */
static int hf_nrppa_c_SRS;                        /* INTEGER_0_63 */
static int hf_nrppa_groupOrSequenceHopping;       /* T_groupOrSequenceHopping */
static int hf_nrppa_resourceTypePos;              /* ResourceTypePos */
static int hf_nrppa_sequenceId;                   /* INTEGER_0_65535 */
static int hf_nrppa_spatialRelationPos;           /* SpatialRelationPos */
static int hf_nrppa_PosSRSResourceID_List_item;   /* SRSPosResourceID */
static int hf_nrppa_PosSRSResourceSet_List_item;  /* PosSRSResourceSet_Item */
static int hf_nrppa_PosSRSResourceIDPerSet_List_item;  /* SRSPosResourceID */
static int hf_nrppa_possrsResourceSetID;          /* INTEGER_0_15 */
static int hf_nrppa_possRSResourceIDPerSet_List;  /* PosSRSResourceIDPerSet_List */
static int hf_nrppa_posresourceSetType;           /* PosResourceSetType */
static int hf_nrppa_PosSRSResourceSet_Aggregation_List_item;  /* PosSRSResourceSet_Aggregation_Item */
static int hf_nrppa_pCI_NR;                       /* INTEGER_0_1007 */
static int hf_nrppa_periodic;                     /* PosResourceSetTypePeriodic */
static int hf_nrppa_semi_persistent;              /* PosResourceSetTypeSemi_persistent */
static int hf_nrppa_aperiodic;                    /* PosResourceSetTypeAperiodic */
static int hf_nrppa_posperiodicSet;               /* T_posperiodicSet */
static int hf_nrppa_possemi_persistentSet;        /* T_possemi_persistentSet */
static int hf_nrppa_sRSResourceTrigger;           /* INTEGER_1_3 */
static int hf_nrppa_nRPRSAzimuth;                 /* INTEGER_0_359 */
static int hf_nrppa_nRPRSAzimuthFine;             /* INTEGER_0_9 */
static int hf_nrppa_nRPRSElevation;               /* INTEGER_0_180 */
static int hf_nrppa_nRPRSElevationFine;           /* INTEGER_0_9 */
static int hf_nrppa_pRS_IDPos;                    /* PRS_ID */
static int hf_nrppa_pRS_Resource_Set_IDPos;       /* PRS_Resource_Set_ID */
static int hf_nrppa_pRS_Resource_IDPos;           /* PRS_Resource_ID */
static int hf_nrppa_pRSResourceSet_List;          /* PRSResourceSet_List */
static int hf_nrppa_sixty_four;                   /* BIT_STRING_SIZE_64 */
static int hf_nrppa_one_hundred_and_twenty_eight;  /* BIT_STRING_SIZE_128 */
static int hf_nrppa_two_hundred_and_fifty_six;    /* BIT_STRING_SIZE_256 */
static int hf_nrppa_five_hundred_and_twelve;      /* BIT_STRING_SIZE_512 */
static int hf_nrppa_one_thousand_and_twenty_four;  /* BIT_STRING_SIZE_1024 */
static int hf_nrppa_noOfFreqHoppingBands;         /* NumberOfFrequencyHoppingBands */
static int hf_nrppa_bandPositions;                /* SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex */
static int hf_nrppa_bandPositions_item;           /* NarrowBandIndex */
static int hf_nrppa_PRS_Measurements_Info_List_item;  /* PRS_Measurements_Info_List_Item */
static int hf_nrppa_measPRSPeriodicity;           /* T_measPRSPeriodicity */
static int hf_nrppa_measPRSOffset;                /* INTEGER_0_159_ */
static int hf_nrppa_measurementPRSLength;         /* T_measurementPRSLength */
static int hf_nrppa_pRSMutingOption1;             /* PRSMutingOption1 */
static int hf_nrppa_pRSMutingOption2;             /* PRSMutingOption2 */
static int hf_nrppa_mutingPattern;                /* DL_PRSMutingPattern */
static int hf_nrppa_mutingBitRepetitionFactor;    /* T_mutingBitRepetitionFactor */
static int hf_nrppa_PRSResource_List_item;        /* PRSResource_Item */
static int hf_nrppa_pRSResourceID;                /* PRS_Resource_ID */
static int hf_nrppa_sequenceID;                   /* INTEGER_0_4095 */
static int hf_nrppa_rEOffset;                     /* INTEGER_0_11_ */
static int hf_nrppa_resourceSlotOffset;           /* INTEGER_0_511 */
static int hf_nrppa_resourceSymbolOffset;         /* INTEGER_0_12 */
static int hf_nrppa_qCLInfo;                      /* PRSResource_QCLInfo */
static int hf_nrppa_qCLSourceSSB;                 /* PRSResource_QCLSourceSSB */
static int hf_nrppa_qCLSourcePRS;                 /* PRSResource_QCLSourcePRS */
static int hf_nrppa_qCLSourcePRSResourceSetID;    /* PRS_Resource_Set_ID */
static int hf_nrppa_qCLSourcePRSResourceID;       /* PRS_Resource_ID */
static int hf_nrppa_PRSResourceSet_List_item;     /* PRSResourceSet_Item */
static int hf_nrppa_pRSResourceSetID;             /* PRS_Resource_Set_ID */
static int hf_nrppa_subcarrierSpacing_01;         /* T_subcarrierSpacing_01 */
static int hf_nrppa_pRSbandwidth;                 /* INTEGER_1_63 */
static int hf_nrppa_startPRB;                     /* INTEGER_0_2176 */
static int hf_nrppa_combSize;                     /* T_combSize */
static int hf_nrppa_cPType;                       /* T_cPType */
static int hf_nrppa_resourceSetPeriodicity;       /* T_resourceSetPeriodicity */
static int hf_nrppa_resourceSetSlotOffset;        /* INTEGER_0_81919_ */
static int hf_nrppa_resourceRepetitionFactor;     /* T_resourceRepetitionFactor */
static int hf_nrppa_resourceTimeGap;              /* T_resourceTimeGap */
static int hf_nrppa_resourceNumberofSymbols;      /* T_resourceNumberofSymbols */
static int hf_nrppa_pRSMuting;                    /* PRSMuting */
static int hf_nrppa_pRSResourceTransmitPower;     /* INTEGER_M60_50 */
static int hf_nrppa_pRSResource_List;             /* PRSResource_List */
static int hf_nrppa_pRSTransmissionOffPerTRP;     /* NULL */
static int hf_nrppa_pRSTransmissionOffPerResourceSet;  /* PRSTransmissionOffPerResourceSet */
static int hf_nrppa_pRSTransmissionOffPerResource;  /* PRSTransmissionOffPerResource */
static int hf_nrppa_PRSTransmissionOffPerResource_item;  /* PRSTransmissionOffPerResource_Item */
static int hf_nrppa_pRSTransmissionOffIndicationPerResourceList;  /* SEQUENCE_SIZE_1_maxnoofPRSresource_OF_PRSTransmissionOffIndicationPerResource_Item */
static int hf_nrppa_pRSTransmissionOffIndicationPerResourceList_item;  /* PRSTransmissionOffIndicationPerResource_Item */
static int hf_nrppa_pRSTransmissionOffIndication;  /* PRSTransmissionOffIndication */
static int hf_nrppa_PRSTransmissionOffPerResourceSet_item;  /* PRSTransmissionOffPerResourceSet_Item */
static int hf_nrppa_PRSTRPList_item;              /* PRSTRPItem */
static int hf_nrppa_tRP_ID;                       /* TRP_ID */
static int hf_nrppa_requestedDLPRSTransmissionCharacteristics;  /* RequestedDLPRSTransmissionCharacteristics */
static int hf_nrppa_pRSTransmissionOffInformation;  /* PRSTransmissionOffInformation */
static int hf_nrppa_PRSTransmissionTRPList_item;  /* PRSTransmissionTRPItem */
static int hf_nrppa_pRSConfiguration;             /* PRSConfiguration */
static int hf_nrppa_PosValidityAreaCellList_item;  /* PosValidityAreaCell_Item */
static int hf_nrppa_nR_CGI;                       /* CGI_NR */
static int hf_nrppa_nR_PCI;                       /* NR_PCI */
static int hf_nrppa_nZP_CSI_RS;                   /* NZP_CSI_RS_ResourceID */
static int hf_nrppa_sSB;                          /* SSB */
static int hf_nrppa_sRS;                          /* SRSResourceID */
static int hf_nrppa_positioningSRS;               /* SRSPosResourceID */
static int hf_nrppa_dL_PRS;                       /* DL_PRS */
static int hf_nrppa_relativeCoordinateID;         /* CoordinateID */
static int hf_nrppa_referencePointCoordinate;     /* NG_RANAccessPointPosition */
static int hf_nrppa_referencePointCoordinateHA;   /* NGRANHighAccuracyAccessPointPosition */
static int hf_nrppa_milli_Arc_SecondUnits;        /* T_milli_Arc_SecondUnits */
static int hf_nrppa_heightUnits;                  /* T_heightUnits */
static int hf_nrppa_deltaLatitude;                /* INTEGER_M1024_1023 */
static int hf_nrppa_deltaLongitude;               /* INTEGER_M1024_1023 */
static int hf_nrppa_deltaHeight;                  /* INTEGER_M1024_1023 */
static int hf_nrppa_locationUncertainty;          /* LocationUncertainty */
static int hf_nrppa_xYZunit;                      /* T_xYZunit */
static int hf_nrppa_xvalue;                       /* INTEGER_M65536_65535 */
static int hf_nrppa_yvalue;                       /* INTEGER_M65536_65535 */
static int hf_nrppa_zvalue;                       /* INTEGER_M32768_32767 */
static int hf_nrppa_k0_01;                        /* INTEGER_0_16351 */
static int hf_nrppa_k1_01;                        /* INTEGER_0_8176 */
static int hf_nrppa_k2_01;                        /* INTEGER_0_4088 */
static int hf_nrppa_k3_01;                        /* INTEGER_0_2044 */
static int hf_nrppa_k4_01;                        /* INTEGER_0_1022 */
static int hf_nrppa_k5_01;                        /* INTEGER_0_511 */
static int hf_nrppa_requestedDLPRSResourceSet_List;  /* RequestedDLPRSResourceSet_List */
static int hf_nrppa_numberofFrequencyLayers;      /* INTEGER_1_4 */
static int hf_nrppa_startTimeAndDuration;         /* StartTimeAndDuration */
static int hf_nrppa_RequestedDLPRSResourceSet_List_item;  /* RequestedDLPRSResourceSet_Item */
static int hf_nrppa_combSize_01;                  /* T_combSize_01 */
static int hf_nrppa_resourceSetPeriodicity_01;    /* T_resourceSetPeriodicity_01 */
static int hf_nrppa_resourceRepetitionFactor_01;  /* T_resourceRepetitionFactor_01 */
static int hf_nrppa_resourceNumberofSymbols_01;   /* T_resourceNumberofSymbols_01 */
static int hf_nrppa_requestedDLPRSResource_List;  /* RequestedDLPRSResource_List */
static int hf_nrppa_resourceSetStartTimeAndDuration;  /* StartTimeAndDuration */
static int hf_nrppa_RequestedDLPRSResource_List_item;  /* RequestedDLPRSResource_Item */
static int hf_nrppa_numberOfTransmissions;        /* INTEGER_0_500_ */
static int hf_nrppa_resourceType;                 /* T_resourceType */
static int hf_nrppa_bandwidth;                    /* BandwidthSRS */
static int hf_nrppa_listOfSRSResourceSet;         /* SEQUENCE_SIZE_1_maxnoSRS_ResourceSets_OF_SRSResourceSet_Item */
static int hf_nrppa_listOfSRSResourceSet_item;    /* SRSResourceSet_Item */
static int hf_nrppa_sSBInformation;               /* SSBInfo */
static int hf_nrppa_nrofSumbols;                  /* T_nrofSumbols */
static int hf_nrppa_RequestedSRSPreconfigurationCharacteristics_List_item;  /* RequestedSRSPreconfigurationCharacteristics_Item */
static int hf_nrppa_requestedSRSTransmissionCharacteristics;  /* RequestedSRSTransmissionCharacteristics */
static int hf_nrppa_numberOfSRSResourcePerSet;    /* INTEGER_1_16_ */
static int hf_nrppa_periodicityList;              /* PeriodicityList */
static int hf_nrppa_spatialRelationInformation;   /* SpatialRelationInfo */
static int hf_nrppa_pathlossReferenceInformation;  /* PathlossReferenceInformation */
static int hf_nrppa_periodic_01;                  /* ResourceSetTypePeriodic */
static int hf_nrppa_semi_persistent_01;           /* ResourceSetTypeSemi_persistent */
static int hf_nrppa_aperiodic_01;                 /* ResourceSetTypeAperiodic */
static int hf_nrppa_periodicSet;                  /* T_periodicSet */
static int hf_nrppa_semi_persistentSet;           /* T_semi_persistentSet */
static int hf_nrppa_slotoffset;                   /* INTEGER_0_32 */
static int hf_nrppa_periodic_02;                  /* ResourceTypePeriodic */
static int hf_nrppa_semi_persistent_02;           /* ResourceTypeSemi_persistent */
static int hf_nrppa_aperiodic_02;                 /* ResourceTypeAperiodic */
static int hf_nrppa_periodicity;                  /* T_periodicity */
static int hf_nrppa_offset;                       /* INTEGER_0_2559_ */
static int hf_nrppa_periodicity_01;               /* T_periodicity_01 */
static int hf_nrppa_aperiodicResourceType;        /* T_aperiodicResourceType */
static int hf_nrppa_periodic_03;                  /* ResourceTypePeriodicPos */
static int hf_nrppa_semi_persistent_03;           /* ResourceTypeSemi_persistentPos */
static int hf_nrppa_aperiodic_03;                 /* ResourceTypeAperiodicPos */
static int hf_nrppa_sRSPeriodicity;               /* SRSPeriodicity */
static int hf_nrppa_offset_01;                    /* INTEGER_0_81919_ */
static int hf_nrppa_slotOffset;                   /* INTEGER_0_32 */
static int hf_nrppa_time;                         /* INTEGER_1_128_ */
static int hf_nrppa_timeUnit;                     /* T_timeUnit */
static int hf_nrppa_ResultCSI_RSRP_item;          /* ResultCSI_RSRP_Item */
static int hf_nrppa_nR_ARFCN;                     /* NR_ARFCN */
static int hf_nrppa_cGI_NR;                       /* CGI_NR */
static int hf_nrppa_valueCSI_RSRP_Cell;           /* ValueRSRP_NR */
static int hf_nrppa_cSI_RSRP_PerCSI_RS;           /* ResultCSI_RSRP_PerCSI_RS */
static int hf_nrppa_ResultCSI_RSRP_PerCSI_RS_item;  /* ResultCSI_RSRP_PerCSI_RS_Item */
static int hf_nrppa_cSI_RS_Index;                 /* INTEGER_0_95 */
static int hf_nrppa_valueCSI_RSRP;                /* ValueRSRP_NR */
static int hf_nrppa_ResultCSI_RSRQ_item;          /* ResultCSI_RSRQ_Item */
static int hf_nrppa_valueCSI_RSRQ_Cell;           /* ValueRSRQ_NR */
static int hf_nrppa_cSI_RSRQ_PerCSI_RS;           /* ResultCSI_RSRQ_PerCSI_RS */
static int hf_nrppa_ResultCSI_RSRQ_PerCSI_RS_item;  /* ResultCSI_RSRQ_PerCSI_RS_Item */
static int hf_nrppa_valueCSI_RSRQ;                /* ValueRSRQ_NR */
static int hf_nrppa_ResultEUTRA_item;             /* ResultEUTRA_Item */
static int hf_nrppa_valueRSRP_EUTRA;              /* ValueRSRP_EUTRA */
static int hf_nrppa_valueRSRQ_EUTRA;              /* ValueRSRQ_EUTRA */
static int hf_nrppa_ResultRSRP_EUTRA_item;        /* ResultRSRP_EUTRA_Item */
static int hf_nrppa_ResultRSRQ_EUTRA_item;        /* ResultRSRQ_EUTRA_Item */
static int hf_nrppa_cGI_UTRA;                     /* CGI_EUTRA */
static int hf_nrppa_ResultSS_RSRP_item;           /* ResultSS_RSRP_Item */
static int hf_nrppa_valueSS_RSRP_Cell;            /* ValueRSRP_NR */
static int hf_nrppa_sS_RSRP_PerSSB;               /* ResultSS_RSRP_PerSSB */
static int hf_nrppa_ResultSS_RSRP_PerSSB_item;    /* ResultSS_RSRP_PerSSB_Item */
static int hf_nrppa_valueSS_RSRP;                 /* ValueRSRP_NR */
static int hf_nrppa_ResultSS_RSRQ_item;           /* ResultSS_RSRQ_Item */
static int hf_nrppa_valueSS_RSRQ_Cell;            /* ValueRSRQ_NR */
static int hf_nrppa_sS_RSRQ_PerSSB;               /* ResultSS_RSRQ_PerSSB */
static int hf_nrppa_ResultSS_RSRQ_PerSSB_item;    /* ResultSS_RSRQ_PerSSB_Item */
static int hf_nrppa_valueSS_RSRQ;                 /* ValueRSRQ_NR */
static int hf_nrppa_ResultGERAN_item;             /* ResultGERAN_Item */
static int hf_nrppa_bCCH;                         /* BCCH */
static int hf_nrppa_physCellIDGERAN;              /* PhysCellIDGERAN */
static int hf_nrppa_rSSI;                         /* RSSI */
static int hf_nrppa_ResultNR_item;                /* ResultNR_Item */
static int hf_nrppa_ResultUTRAN_item;             /* ResultUTRAN_Item */
static int hf_nrppa_uARFCN;                       /* UARFCN */
static int hf_nrppa_physCellIDUTRAN;              /* T_physCellIDUTRAN */
static int hf_nrppa_physCellIDUTRA_FDD;           /* PhysCellIDUTRA_FDD */
static int hf_nrppa_physCellIDUTRA_TDD;           /* PhysCellIDUTRA_TDD */
static int hf_nrppa_uTRA_RSCP;                    /* UTRA_RSCP */
static int hf_nrppa_uTRA_EcN0;                    /* UTRA_EcN0 */
static int hf_nrppa_subcarrierSpacing_02;         /* T_subcarrierSpacing_02 */
static int hf_nrppa_carrierBandwidth;             /* INTEGER_1_275_ */
static int hf_nrppa_expectedPropagationDelay;     /* INTEGER_M3841_3841_ */
static int hf_nrppa_delayUncertainty;             /* INTEGER_1_246_ */
static int hf_nrppa_SlotOffsetForRemainingHopsList_item;  /* SlotOffsetForRemainingHopsItem */
static int hf_nrppa_slotOffsetRemainingHops;      /* SlotOffsetRemainingHops */
static int hf_nrppa_aperiodic_04;                 /* SlotOffsetRemainingHopsAperiodic */
static int hf_nrppa_semi_persistent_04;           /* SlotOffsetRemainingHopsSemiPersistent */
static int hf_nrppa_periodic_04;                  /* SlotOffsetRemainingHopsPeriodic */
static int hf_nrppa_slotOffset_01;                /* INTEGER_1_32 */
static int hf_nrppa_sRSperiodicity;               /* SRSPeriodicity */
static int hf_nrppa_nR_PRS_Beam_Information;      /* NR_PRS_Beam_Information */
static int hf_nrppa_spatialRelationforResourceID;  /* SpatialRelationforResourceID */
static int hf_nrppa_SpatialRelationforResourceID_item;  /* SpatialRelationforResourceIDItem */
static int hf_nrppa_referenceSignal;              /* ReferenceSignal */
static int hf_nrppa_spatialRelationPerSRSResource_List;  /* SpatialRelationPerSRSResource_List */
static int hf_nrppa_SpatialRelationPerSRSResource_List_item;  /* SpatialRelationPerSRSResourceItem */
static int hf_nrppa_sSBPos;                       /* SSB */
static int hf_nrppa_pRSInformationPos;            /* PRSInformationPos */
static int hf_nrppa_sRSResource_List;             /* SRSResource_List */
static int hf_nrppa_posSRSResource_List;          /* PosSRSResource_List */
static int hf_nrppa_sRSResourceSet_List;          /* SRSResourceSet_List */
static int hf_nrppa_posSRSResourceSet_List;       /* PosSRSResourceSet_List */
static int hf_nrppa_SRSCarrier_List_item;         /* SRSCarrier_List_Item */
static int hf_nrppa_uplinkChannelBW_PerSCS_List;  /* UplinkChannelBW_PerSCS_List */
static int hf_nrppa_activeULBWP;                  /* ActiveULBWP */
static int hf_nrppa_sRSCarrier_List;              /* SRSCarrier_List */
static int hf_nrppa_sRSResourceID;                /* SRSResourceID */
static int hf_nrppa_nrofSRS_Ports;                /* T_nrofSRS_Ports */
static int hf_nrppa_transmissionComb;             /* TransmissionComb */
static int hf_nrppa_nrofSymbols_01;               /* T_nrofSymbols_01 */
static int hf_nrppa_repetitionFactor;             /* T_repetitionFactor */
static int hf_nrppa_freqDomainPosition;           /* INTEGER_0_67 */
static int hf_nrppa_b_SRS;                        /* INTEGER_0_3 */
static int hf_nrppa_b_hop;                        /* INTEGER_0_3 */
static int hf_nrppa_groupOrSequenceHopping_01;    /* T_groupOrSequenceHopping_01 */
static int hf_nrppa_resourceType_01;              /* ResourceType */
static int hf_nrppa_sequenceId_01;                /* INTEGER_0_1023 */
static int hf_nrppa_SRSResource_List_item;        /* SRSResource */
static int hf_nrppa_SRSResourceSet_List_item;     /* SRSResourceSet */
static int hf_nrppa_SRSResourceID_List_item;      /* SRSResourceID */
static int hf_nrppa_sRSResourceSetID1;            /* INTEGER_0_15 */
static int hf_nrppa_sRSResourceID_List;           /* SRSResourceID_List */
static int hf_nrppa_resourceSetType;              /* ResourceSetType */
static int hf_nrppa_aperiodicSRSResourceTriggerList;  /* AperiodicSRSResourceTriggerList */
static int hf_nrppa_sRSResourceTypeChoice;        /* SRSResourceTypeChoice */
static int hf_nrppa_sRSResourceInfo;              /* SRSInfo */
static int hf_nrppa_posSRSResourceInfo;           /* PosSRSInfo */
static int hf_nrppa_sRSResource;                  /* SRSResourceID */
static int hf_nrppa_posSRSResourceID;             /* SRSPosResourceID */
static int hf_nrppa_listOfSSBInfo;                /* SEQUENCE_SIZE_1_maxNoSSBs_OF_SSBInfoItem */
static int hf_nrppa_listOfSSBInfo_item;           /* SSBInfoItem */
static int hf_nrppa_sSB_Configuration;            /* TF_Configuration */
static int hf_nrppa_ssb_index;                    /* SSB_Index */
static int hf_nrppa_shortBitmap;                  /* BIT_STRING_SIZE_4 */
static int hf_nrppa_mediumBitmap;                 /* BIT_STRING_SIZE_8 */
static int hf_nrppa_longBitmap;                   /* BIT_STRING_SIZE_64 */
static int hf_nrppa_freqScalingFactor2;           /* INTEGER_0_1 */
static int hf_nrppa_freqScalingFactor4;           /* INTEGER_0_3 */
static int hf_nrppa_startTime;                    /* RelativeTime1900 */
static int hf_nrppa_duration;                     /* INTEGER_0_90060_ */
static int hf_nrppa_SystemInformation_item;       /* SystemInformation_item */
static int hf_nrppa_broadcastPeriodicity;         /* BroadcastPeriodicity */
static int hf_nrppa_posSIBs;                      /* PosSIBs */
static int hf_nrppa_SRSPreconfiguration_List_item;  /* SRSPreconfiguration_Item */
static int hf_nrppa_sRSConfiguration;             /* SRSConfiguration */
static int hf_nrppa_posValidityAreaCellList;      /* PosValidityAreaCellList */
static int hf_nrppa_subframeAssignment;           /* T_subframeAssignment */
static int hf_nrppa_rxTx_TEG;                     /* RxTxTEG */
static int hf_nrppa_rx_TEG;                       /* RxTEG */
static int hf_nrppa_tRP_RxTx_TEGInformation;      /* TRP_RxTx_TEGInformation */
static int hf_nrppa_tRP_Tx_TEGInformation;        /* TRP_Tx_TEGInformation */
static int hf_nrppa_tRP_Rx_TEGInformation;        /* TRP_Rx_TEGInformation */
static int hf_nrppa_sSB_frequency;                /* INTEGER_0_3279165 */
static int hf_nrppa_sSB_subcarrier_spacing;       /* T_sSB_subcarrier_spacing */
static int hf_nrppa_sSB_Transmit_power;           /* INTEGER_M60_50 */
static int hf_nrppa_sSB_periodicity;              /* T_sSB_periodicity */
static int hf_nrppa_sSB_half_frame_offset;        /* INTEGER_0_1 */
static int hf_nrppa_sSB_SFN_offset;               /* INTEGER_0_15 */
static int hf_nrppa_sSB_BurstPosition;            /* SSBBurstPosition */
static int hf_nrppa_sFN_initialisation_time;      /* RelativeTime1900 */
static int hf_nrppa_systemFrameNumber;            /* SystemFrameNumber */
static int hf_nrppa_slotIndex;                    /* TimeStampSlotIndex */
static int hf_nrppa_measurementTime;              /* RelativeTime1900 */
static int hf_nrppa_iE_Extension;                 /* ProtocolExtensionContainer */
static int hf_nrppa_sCS_15;                       /* INTEGER_0_9 */
static int hf_nrppa_sCS_30;                       /* INTEGER_0_19 */
static int hf_nrppa_sCS_60;                       /* INTEGER_0_39 */
static int hf_nrppa_sCS_120;                      /* INTEGER_0_79 */
static int hf_nrppa_durationSlots;                /* T_durationSlots */
static int hf_nrppa_durationSymbols;              /* T_durationSymbols */
static int hf_nrppa_durationSlots_01;             /* T_durationSlots_01 */
static int hf_nrppa_slotNumber;                   /* SlotNumber */
static int hf_nrppa_symbolIndex;                  /* INTEGER_0_13 */
static int hf_nrppa_TimeWindowInformation_Measurement_List_item;  /* TimeWindowInformation_Measurement_Item */
static int hf_nrppa_timeWindowDurationMeasurement;  /* TimeWindowDurationMeasurement */
static int hf_nrppa_timeWindowType;               /* T_timeWindowType */
static int hf_nrppa_timeWindowPeriodicityMeasurement;  /* TimeWindowPeriodicityMeasurement */
static int hf_nrppa_TimeWindowInformation_SRS_List_item;  /* TimeWindowInformation_SRS_Item */
static int hf_nrppa_timeWindowStartSRS;           /* TimeWindowStartSRS */
static int hf_nrppa_timeWindowDurationSRS;        /* TimeWindowDurationSRS */
static int hf_nrppa_timeWindowType_01;            /* T_timeWindowType_01 */
static int hf_nrppa_timeWindowPeriodicitySRS;     /* TimeWindowPeriodicitySRS */
static int hf_nrppa_n2;                           /* T_n2 */
static int hf_nrppa_combOffset_n2;                /* INTEGER_0_1 */
static int hf_nrppa_cyclicShift_n2;               /* INTEGER_0_7 */
static int hf_nrppa_n4;                           /* T_n4 */
static int hf_nrppa_combOffset_n4;                /* INTEGER_0_3 */
static int hf_nrppa_cyclicShift_n4;               /* INTEGER_0_11 */
static int hf_nrppa_combOffset_n8;                /* INTEGER_0_7 */
static int hf_nrppa_cyclicShift_n8;               /* INTEGER_0_5 */
static int hf_nrppa_n2_01;                        /* T_n2_01 */
static int hf_nrppa_n4_01;                        /* T_n4_01 */
static int hf_nrppa_n8;                           /* T_n8 */
static int hf_nrppa_choice_TRP_Beam_Antenna_Info_Item;  /* Choice_TRP_Beam_Antenna_Info_Item */
static int hf_nrppa_reference;                    /* TRP_ID */
static int hf_nrppa_explicit;                     /* TRP_BeamAntennaExplicitInformation */
static int hf_nrppa_noChange;                     /* NULL */
static int hf_nrppa_trp_BeamAntennaAngles;        /* TRP_BeamAntennaAngles */
static int hf_nrppa_lcs_to_gcs_translation;       /* LCS_to_GCS_Translation */
static int hf_nrppa_TRP_BeamAntennaAngles_item;   /* TRP_BeamAntennaAnglesList_Item */
static int hf_nrppa_trp_azimuth_angle;            /* INTEGER_0_359 */
static int hf_nrppa_trp_azimuth_angle_fine;       /* INTEGER_0_9 */
static int hf_nrppa_trp_elevation_angle_list;     /* SEQUENCE_SIZE_1_maxnoElevationAngles_OF_TRP_ElevationAngleList_Item */
static int hf_nrppa_trp_elevation_angle_list_item;  /* TRP_ElevationAngleList_Item */
static int hf_nrppa_trp_elevation_angle;          /* INTEGER_0_180 */
static int hf_nrppa_trp_elevation_angle_fine;     /* INTEGER_0_9 */
static int hf_nrppa_trp_beam_power_list;          /* SEQUENCE_SIZE_2_maxNumResourcesPerAngle_OF_TRP_Beam_Power_Item */
static int hf_nrppa_trp_beam_power_list_item;     /* TRP_Beam_Power_Item */
static int hf_nrppa_relativePower;                /* INTEGER_0_30 */
static int hf_nrppa_relativePowerFine;            /* INTEGER_0_9 */
static int hf_nrppa_TRPMeasurementQuantities_item;  /* TRPMeasurementQuantitiesList_Item */
static int hf_nrppa_tRPMeasurementQuantities_Item;  /* TRPMeasurementType */
static int hf_nrppa_timingReportingGranularityFactor;  /* INTEGER_0_5 */
static int hf_nrppa_TrpMeasurementResult_item;    /* TrpMeasurementResultItem */
static int hf_nrppa_measuredResultsValue;         /* TrpMeasuredResultsValue */
static int hf_nrppa_measurementBeamInfo;          /* MeasurementBeamInfo */
static int hf_nrppa_uL_AngleOfArrival;            /* UL_AoA */
static int hf_nrppa_uL_SRS_RSRP;                  /* UL_SRS_RSRP */
static int hf_nrppa_uL_RTOA;                      /* UL_RTOAMeasurement */
static int hf_nrppa_gNB_RxTxTimeDiff;             /* GNB_RxTxTimeDiff */
static int hf_nrppa_timingMeasQuality;            /* TrpMeasurementTimingQuality */
static int hf_nrppa_angleMeasQuality;             /* TrpMeasurementAngleQuality */
static int hf_nrppa_measurementQuality_01;        /* INTEGER_0_31 */
static int hf_nrppa_resolution;                   /* T_resolution */
static int hf_nrppa_azimuthQuality;               /* INTEGER_0_255 */
static int hf_nrppa_zenithQuality;                /* INTEGER_0_255 */
static int hf_nrppa_resolution_01;                /* T_resolution_01 */
static int hf_nrppa_phaseQualityIndex;            /* INTEGER_0_179 */
static int hf_nrppa_resolution_02;                /* T_resolution_02 */
static int hf_nrppa_TRP_MeasurementRequestList_item;  /* TRP_MeasurementRequestItem */
static int hf_nrppa_search_window_information;    /* Search_window_information */
static int hf_nrppa_TRP_MeasurementResponseList_item;  /* TRP_MeasurementResponseItem */
static int hf_nrppa_measurementResult;            /* TrpMeasurementResult */
static int hf_nrppa_TRP_MeasurementUpdateList_item;  /* TRP_MeasurementUpdateItem */
static int hf_nrppa_aoA_window_information;       /* AoA_AssistanceInfo */
static int hf_nrppa_TRPInformationListTRPResp_item;  /* TRPInformationListTRPResp_item */
static int hf_nrppa_tRPInformation;               /* TRPInformation */
static int hf_nrppa_tRPInformationTypeResponseList;  /* TRPInformationTypeResponseList */
static int hf_nrppa_TRPInformationTypeResponseList_item;  /* TRPInformationTypeResponseItem */
static int hf_nrppa_aRFCN;                        /* INTEGER_0_3279165 */
static int hf_nrppa_sSBinformation;               /* SSBInfo */
static int hf_nrppa_sFNInitialisationTime;        /* RelativeTime1900 */
static int hf_nrppa_spatialDirectionInformation;  /* SpatialDirectionInformation */
static int hf_nrppa_geographicalCoordinates;      /* GeographicalCoordinates */
static int hf_nrppa_TRPInformationTypeListTRPReq_item;  /* ProtocolIE_Single_Container */
static int hf_nrppa_TRPList_item;                 /* TRPItem */
static int hf_nrppa_direct;                       /* TRPPositionDirect */
static int hf_nrppa_referenced;                   /* TRPPositionReferenced */
static int hf_nrppa_accuracy;                     /* TRPPositionDirectAccuracy */
static int hf_nrppa_tRPPosition;                  /* NG_RANAccessPointPosition */
static int hf_nrppa_tRPHAposition;                /* NGRANHighAccuracyAccessPointPosition */
static int hf_nrppa_referencePoint;               /* ReferencePoint */
static int hf_nrppa_referencePointType;           /* TRPReferencePointType */
static int hf_nrppa_TRP_PRS_Information_List_item;  /* TRP_PRS_Information_List_Item */
static int hf_nrppa_tRPPositionRelativeGeodetic;  /* RelativeGeodeticLocation */
static int hf_nrppa_tRPPositionRelativeCartesian;  /* RelativeCartesianLocation */
static int hf_nrppa_tRP_Rx_TEGID;                 /* INTEGER_0_31 */
static int hf_nrppa_tRP_Rx_TimingErrorMargin;     /* TimingErrorMargin */
static int hf_nrppa_tRP_RxTx_TEGID;               /* INTEGER_0_255 */
static int hf_nrppa_tRP_RxTx_TimingErrorMargin;   /* RxTxTimingErrorMargin */
static int hf_nrppa_tRP_Tx_TEGID;                 /* INTEGER_0_7 */
static int hf_nrppa_tRP_Tx_TimingErrorMargin;     /* TimingErrorMargin */
static int hf_nrppa_TRPTxTEGAssociation_item;     /* TRPTEGItem */
static int hf_nrppa_dl_PRSResourceID_List;        /* SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceID_Item */
static int hf_nrppa_dl_PRSResourceID_List_item;   /* DLPRSResourceID_Item */
static int hf_nrppa_overlapValue;                 /* T_overlapValue */
static int hf_nrppa_numberOfHops;                 /* INTEGER_1_6 */
static int hf_nrppa_slotOffsetForRemainingHopsList;  /* SlotOffsetForRemainingHopsList */
static int hf_nrppa_reportingAmount;              /* T_reportingAmount */
static int hf_nrppa_reportingInterval;            /* T_reportingInterval */
static int hf_nrppa_UETxTEGAssociationList_item;  /* UETxTEGAssociationItem */
static int hf_nrppa_uE_Tx_TEG_ID;                 /* INTEGER_0_7 */
static int hf_nrppa_posSRSResourceID_List;        /* PosSRSResourceID_List */
static int hf_nrppa_carrierFreq;                  /* CarrierFreq */
static int hf_nrppa_azimuthAoA;                   /* INTEGER_0_3599 */
static int hf_nrppa_zenithAoA;                    /* INTEGER_0_1799 */
static int hf_nrppa_uLRTOAmeas;                   /* ULRTOAMeas */
static int hf_nrppa_uLRSCP;                       /* INTEGER_0_3599 */
static int hf_nrppa_firstPathRSRPP;               /* INTEGER_0_126 */
static int hf_nrppa_UplinkChannelBW_PerSCS_List_item;  /* SCS_SpecificCarrier */
static int hf_nrppa_resourceMapping;              /* ResourceMapping */
static int hf_nrppa_sequenceIDPos;                /* INTEGER_0_65535 */
static int hf_nrppa_WLANMeasurementQuantities_item;  /* ProtocolIE_Single_Container */
static int hf_nrppa_wLANMeasurementQuantitiesValue;  /* WLANMeasurementQuantitiesValue */
static int hf_nrppa_WLANMeasurementResult_item;   /* WLANMeasurementResult_Item */
static int hf_nrppa_wLAN_RSSI;                    /* WLAN_RSSI */
static int hf_nrppa_sSID;                         /* SSID */
static int hf_nrppa_bSSID;                        /* BSSID */
static int hf_nrppa_hESSID;                       /* HESSID */
static int hf_nrppa_operatingClass;               /* WLANOperatingClass */
static int hf_nrppa_countryCode;                  /* WLANCountryCode */
static int hf_nrppa_wLANChannelList;              /* WLANChannelList */
static int hf_nrppa_wLANBand;                     /* WLANBand */
static int hf_nrppa_WLANChannelList_item;         /* WLANChannel */
static int hf_nrppa_protocolIEs;                  /* ProtocolIE_Container */
static int hf_nrppa_OTDOA_Information_Type_item;  /* ProtocolIE_Single_Container */
static int hf_nrppa_oTDOA_Information_Item;       /* OTDOA_Information_Item */
static int hf_nrppa_privateIEs;                   /* PrivateIE_Container */
static int hf_nrppa_semipersistentSRS;            /* SemipersistentSRS */
static int hf_nrppa_aperiodicSRS;                 /* AperiodicSRS */
static int hf_nrppa_sRSResourceSetID;             /* SRSResourceSetID */
static int hf_nrppa_aperiodic_05;                 /* T_aperiodic */
static int hf_nrppa_sRSResourceTrigger_01;        /* SRSResourceTrigger */

/* Initialize the subtree pointers */
static int ett_nrppa;
static int ett_nrppa_PrivateIE_ID;
static int ett_nrppa_ProtocolIE_Container;
static int ett_nrppa_ProtocolIE_Field;
static int ett_nrppa_ProtocolExtensionContainer;
static int ett_nrppa_ProtocolExtensionField;
static int ett_nrppa_PrivateIE_Container;
static int ett_nrppa_PrivateIE_Field;
static int ett_nrppa_NRPPA_PDU;
static int ett_nrppa_InitiatingMessage;
static int ett_nrppa_SuccessfulOutcome;
static int ett_nrppa_UnsuccessfulOutcome;
static int ett_nrppa_AbortTransmission;
static int ett_nrppa_ActiveULBWP;
static int ett_nrppa_AdditionalPathList;
static int ett_nrppa_AdditionalPathListItem;
static int ett_nrppa_AggregatedPosSRSResourceID_List;
static int ett_nrppa_AggregatedPosSRSResourceID_Item;
static int ett_nrppa_AggregatedPRSResourceSetList;
static int ett_nrppa_AggregatedPRSResourceSet_Item;
static int ett_nrppa_DL_PRS_ResourceSet_List;
static int ett_nrppa_DL_PRS_ResourceSet_Item;
static int ett_nrppa_ExtendedAdditionalPathList;
static int ett_nrppa_ExtendedAdditionalPathList_Item;
static int ett_nrppa_AoA_AssistanceInfo;
static int ett_nrppa_AperiodicSRSResourceTriggerList;
static int ett_nrppa_AngleMeasurementType;
static int ett_nrppa_Expected_UL_AoA;
static int ett_nrppa_Expected_ZoA_only;
static int ett_nrppa_Expected_Azimuth_AoA;
static int ett_nrppa_Expected_Zenith_AoA;
static int ett_nrppa_ARPLocationInformation;
static int ett_nrppa_ARPLocationInformation_Item;
static int ett_nrppa_ARPLocationType;
static int ett_nrppa_Assistance_Information;
static int ett_nrppa_AssistanceInformationFailureList;
static int ett_nrppa_AssistanceInformationFailureList_item;
static int ett_nrppa_AssistanceInformationMetaData;
static int ett_nrppa_BandwidthSRS;
static int ett_nrppa_PositioningBroadcastCells;
static int ett_nrppa_CarrierFreq;
static int ett_nrppa_Cause;
static int ett_nrppa_CGI_EUTRA;
static int ett_nrppa_CGI_NR;
static int ett_nrppa_CriticalityDiagnostics;
static int ett_nrppa_CriticalityDiagnostics_IE_List;
static int ett_nrppa_CriticalityDiagnostics_IE_List_item;
static int ett_nrppa_CommonTAParameters;
static int ett_nrppa_DL_PRS;
static int ett_nrppa_DL_PRSMutingPattern;
static int ett_nrppa_DLPRSResourceCoordinates;
static int ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_DLPRSResourceSetARP;
static int ett_nrppa_DLPRSResourceSetARP;
static int ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceARP;
static int ett_nrppa_DL_PRSResourceSetARPLocation;
static int ett_nrppa_DLPRSResourceARP;
static int ett_nrppa_DL_PRSResourceARPLocation;
static int ett_nrppa_E_CID_MeasurementResult;
static int ett_nrppa_GeographicalCoordinates;
static int ett_nrppa_GNB_RxTxTimeDiff;
static int ett_nrppa_GNBRxTxTimeDiffMeas;
static int ett_nrppa_LCS_to_GCS_Translation;
static int ett_nrppa_LCS_to_GCS_TranslationItem;
static int ett_nrppa_LocationUncertainty;
static int ett_nrppa_LoS_NLoSInformation;
static int ett_nrppa_MeasurementBeamInfo;
static int ett_nrppa_MeasurementQuantities;
static int ett_nrppa_MeasurementQuantities_Item;
static int ett_nrppa_MeasuredResults;
static int ett_nrppa_MeasuredResultsAssociatedInfoList;
static int ett_nrppa_MeasuredResultsAssociatedInfoItem;
static int ett_nrppa_MeasuredResultsValue;
static int ett_nrppa_Mobile_TRP_LocationInformation;
static int ett_nrppa_MultipleULAoA;
static int ett_nrppa_MultipleULAoA_List;
static int ett_nrppa_MultipleULAoA_Item;
static int ett_nrppa_NG_RANAccessPointPosition;
static int ett_nrppa_NGRANHighAccuracyAccessPointPosition;
static int ett_nrppa_NG_RAN_CGI;
static int ett_nrppa_NG_RANCell;
static int ett_nrppa_NR_PRS_Beam_Information;
static int ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_NR_PRS_Beam_InformationItem;
static int ett_nrppa_SEQUENCE_SIZE_1_maxnolcs_gcs_translation_OF_LCS_to_GCS_TranslationItem;
static int ett_nrppa_NR_PRS_Beam_InformationItem;
static int ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_PRSAngleItem;
static int ett_nrppa_OnDemandPRS_Info;
static int ett_nrppa_OTDOACells;
static int ett_nrppa_OTDOACells_item;
static int ett_nrppa_OTDOACell_Information;
static int ett_nrppa_OTDOACell_Information_Item;
static int ett_nrppa_OtherRATMeasurementQuantities;
static int ett_nrppa_OtherRATMeasurementQuantities_Item;
static int ett_nrppa_OtherRATMeasurementResult;
static int ett_nrppa_OtherRATMeasuredResultsValue;
static int ett_nrppa_PathlossReferenceInformation;
static int ett_nrppa_PathlossReferenceSignal;
static int ett_nrppa_PeriodicityList;
static int ett_nrppa_PosSIBs;
static int ett_nrppa_PosSIBs_item;
static int ett_nrppa_PosSIB_Segments;
static int ett_nrppa_PosSIB_Segments_item;
static int ett_nrppa_PosSRSResource_List;
static int ett_nrppa_PosSRSResource_Item;
static int ett_nrppa_PosSRSResourceID_List;
static int ett_nrppa_PosSRSResourceSet_List;
static int ett_nrppa_PosSRSResourceIDPerSet_List;
static int ett_nrppa_PosSRSResourceSet_Item;
static int ett_nrppa_PosSRSResourceSet_Aggregation_List;
static int ett_nrppa_PosSRSResourceSet_Aggregation_Item;
static int ett_nrppa_PosResourceSetType;
static int ett_nrppa_PosResourceSetTypePeriodic;
static int ett_nrppa_PosResourceSetTypeSemi_persistent;
static int ett_nrppa_PosResourceSetTypeAperiodic;
static int ett_nrppa_PRSAngleItem;
static int ett_nrppa_PRSInformationPos;
static int ett_nrppa_PRSConfiguration;
static int ett_nrppa_PRSMutingConfiguration_EUTRA;
static int ett_nrppa_PRSFrequencyHoppingConfiguration_EUTRA;
static int ett_nrppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex;
static int ett_nrppa_PRS_Measurements_Info_List;
static int ett_nrppa_PRS_Measurements_Info_List_Item;
static int ett_nrppa_PRSMuting;
static int ett_nrppa_PRSMutingOption1;
static int ett_nrppa_PRSMutingOption2;
static int ett_nrppa_PRSResource_List;
static int ett_nrppa_PRSResource_Item;
static int ett_nrppa_PRSResource_QCLInfo;
static int ett_nrppa_PRSResource_QCLSourceSSB;
static int ett_nrppa_PRSResource_QCLSourcePRS;
static int ett_nrppa_PRSResourceSet_List;
static int ett_nrppa_PRSResourceSet_Item;
static int ett_nrppa_PRSTransmissionOffIndication;
static int ett_nrppa_PRSTransmissionOffPerResource;
static int ett_nrppa_PRSTransmissionOffPerResource_Item;
static int ett_nrppa_SEQUENCE_SIZE_1_maxnoofPRSresource_OF_PRSTransmissionOffIndicationPerResource_Item;
static int ett_nrppa_PRSTransmissionOffIndicationPerResource_Item;
static int ett_nrppa_PRSTransmissionOffInformation;
static int ett_nrppa_PRSTransmissionOffPerResourceSet;
static int ett_nrppa_PRSTransmissionOffPerResourceSet_Item;
static int ett_nrppa_PRSTRPList;
static int ett_nrppa_PRSTRPItem;
static int ett_nrppa_PRSTransmissionTRPList;
static int ett_nrppa_PRSTransmissionTRPItem;
static int ett_nrppa_PosValidityAreaCellList;
static int ett_nrppa_PosValidityAreaCell_Item;
static int ett_nrppa_ReferenceSignal;
static int ett_nrppa_ReferencePoint;
static int ett_nrppa_RelativeGeodeticLocation;
static int ett_nrppa_RelativeCartesianLocation;
static int ett_nrppa_RelativePathDelay;
static int ett_nrppa_RequestedDLPRSTransmissionCharacteristics;
static int ett_nrppa_RequestedDLPRSResourceSet_List;
static int ett_nrppa_RequestedDLPRSResourceSet_Item;
static int ett_nrppa_RequestedDLPRSResource_List;
static int ett_nrppa_RequestedDLPRSResource_Item;
static int ett_nrppa_RequestedSRSTransmissionCharacteristics;
static int ett_nrppa_SEQUENCE_SIZE_1_maxnoSRS_ResourceSets_OF_SRSResourceSet_Item;
static int ett_nrppa_ResourceMapping;
static int ett_nrppa_RequestedSRSPreconfigurationCharacteristics_List;
static int ett_nrppa_RequestedSRSPreconfigurationCharacteristics_Item;
static int ett_nrppa_SRSResourceSet_Item;
static int ett_nrppa_ResourceSetType;
static int ett_nrppa_ResourceSetTypePeriodic;
static int ett_nrppa_ResourceSetTypeSemi_persistent;
static int ett_nrppa_ResourceSetTypeAperiodic;
static int ett_nrppa_ResourceType;
static int ett_nrppa_ResourceTypePeriodic;
static int ett_nrppa_ResourceTypeSemi_persistent;
static int ett_nrppa_ResourceTypeAperiodic;
static int ett_nrppa_ResourceTypePos;
static int ett_nrppa_ResourceTypePeriodicPos;
static int ett_nrppa_ResourceTypeSemi_persistentPos;
static int ett_nrppa_ResourceTypeAperiodicPos;
static int ett_nrppa_ResponseTime;
static int ett_nrppa_ResultCSI_RSRP;
static int ett_nrppa_ResultCSI_RSRP_Item;
static int ett_nrppa_ResultCSI_RSRP_PerCSI_RS;
static int ett_nrppa_ResultCSI_RSRP_PerCSI_RS_Item;
static int ett_nrppa_ResultCSI_RSRQ;
static int ett_nrppa_ResultCSI_RSRQ_Item;
static int ett_nrppa_ResultCSI_RSRQ_PerCSI_RS;
static int ett_nrppa_ResultCSI_RSRQ_PerCSI_RS_Item;
static int ett_nrppa_ResultEUTRA;
static int ett_nrppa_ResultEUTRA_Item;
static int ett_nrppa_ResultRSRP_EUTRA;
static int ett_nrppa_ResultRSRP_EUTRA_Item;
static int ett_nrppa_ResultRSRQ_EUTRA;
static int ett_nrppa_ResultRSRQ_EUTRA_Item;
static int ett_nrppa_ResultSS_RSRP;
static int ett_nrppa_ResultSS_RSRP_Item;
static int ett_nrppa_ResultSS_RSRP_PerSSB;
static int ett_nrppa_ResultSS_RSRP_PerSSB_Item;
static int ett_nrppa_ResultSS_RSRQ;
static int ett_nrppa_ResultSS_RSRQ_Item;
static int ett_nrppa_ResultSS_RSRQ_PerSSB;
static int ett_nrppa_ResultSS_RSRQ_PerSSB_Item;
static int ett_nrppa_ResultGERAN;
static int ett_nrppa_ResultGERAN_Item;
static int ett_nrppa_ResultNR;
static int ett_nrppa_ResultNR_Item;
static int ett_nrppa_ResultUTRAN;
static int ett_nrppa_ResultUTRAN_Item;
static int ett_nrppa_T_physCellIDUTRAN;
static int ett_nrppa_SCS_SpecificCarrier;
static int ett_nrppa_Search_window_information;
static int ett_nrppa_SlotOffsetForRemainingHopsList;
static int ett_nrppa_SlotOffsetForRemainingHopsItem;
static int ett_nrppa_SlotOffsetRemainingHops;
static int ett_nrppa_SlotOffsetRemainingHopsAperiodic;
static int ett_nrppa_SlotOffsetRemainingHopsSemiPersistent;
static int ett_nrppa_SlotOffsetRemainingHopsPeriodic;
static int ett_nrppa_SpatialDirectionInformation;
static int ett_nrppa_SpatialRelationInfo;
static int ett_nrppa_SpatialRelationforResourceID;
static int ett_nrppa_SpatialRelationforResourceIDItem;
static int ett_nrppa_SpatialRelationPerSRSResource;
static int ett_nrppa_SpatialRelationPerSRSResource_List;
static int ett_nrppa_SpatialRelationPerSRSResourceItem;
static int ett_nrppa_SpatialRelationPos;
static int ett_nrppa_SRSConfig;
static int ett_nrppa_SRSCarrier_List;
static int ett_nrppa_SRSCarrier_List_Item;
static int ett_nrppa_SRSConfiguration;
static int ett_nrppa_SRSResource;
static int ett_nrppa_SRSResource_List;
static int ett_nrppa_SRSResourceSet_List;
static int ett_nrppa_SRSResourceID_List;
static int ett_nrppa_SRSResourceSet;
static int ett_nrppa_SRSResourceTrigger;
static int ett_nrppa_SRSResourcetype;
static int ett_nrppa_SRSResourceTypeChoice;
static int ett_nrppa_SRSInfo;
static int ett_nrppa_PosSRSInfo;
static int ett_nrppa_SSBInfo;
static int ett_nrppa_SEQUENCE_SIZE_1_maxNoSSBs_OF_SSBInfoItem;
static int ett_nrppa_SSBInfoItem;
static int ett_nrppa_SSB;
static int ett_nrppa_SSBBurstPosition;
static int ett_nrppa_StartRBIndex;
static int ett_nrppa_StartTimeAndDuration;
static int ett_nrppa_SystemInformation;
static int ett_nrppa_SystemInformation_item;
static int ett_nrppa_SRSPreconfiguration_List;
static int ett_nrppa_SRSPreconfiguration_Item;
static int ett_nrppa_TDD_Config_EUTRA_Item;
static int ett_nrppa_TRPTEGInformation;
static int ett_nrppa_RxTxTEG;
static int ett_nrppa_RxTEG;
static int ett_nrppa_TF_Configuration;
static int ett_nrppa_TimeStamp;
static int ett_nrppa_TimeStampSlotIndex;
static int ett_nrppa_TimeWindowDurationMeasurement;
static int ett_nrppa_TimeWindowDurationSRS;
static int ett_nrppa_TimeWindowStartSRS;
static int ett_nrppa_TimeWindowInformation_Measurement_List;
static int ett_nrppa_TimeWindowInformation_Measurement_Item;
static int ett_nrppa_TimeWindowInformation_SRS_List;
static int ett_nrppa_TimeWindowInformation_SRS_Item;
static int ett_nrppa_TransmissionComb;
static int ett_nrppa_T_n2;
static int ett_nrppa_T_n4;
static int ett_nrppa_TransmissionCombn8;
static int ett_nrppa_TransmissionCombPos;
static int ett_nrppa_T_n2_01;
static int ett_nrppa_T_n4_01;
static int ett_nrppa_T_n8;
static int ett_nrppa_TRPBeamAntennaInformation;
static int ett_nrppa_Choice_TRP_Beam_Antenna_Info_Item;
static int ett_nrppa_TRP_BeamAntennaExplicitInformation;
static int ett_nrppa_TRP_BeamAntennaAngles;
static int ett_nrppa_TRP_BeamAntennaAnglesList_Item;
static int ett_nrppa_SEQUENCE_SIZE_1_maxnoElevationAngles_OF_TRP_ElevationAngleList_Item;
static int ett_nrppa_TRP_ElevationAngleList_Item;
static int ett_nrppa_SEQUENCE_SIZE_2_maxNumResourcesPerAngle_OF_TRP_Beam_Power_Item;
static int ett_nrppa_TRP_Beam_Power_Item;
static int ett_nrppa_TRPMeasurementQuantities;
static int ett_nrppa_TRPMeasurementQuantitiesList_Item;
static int ett_nrppa_TrpMeasurementResult;
static int ett_nrppa_TrpMeasurementResultItem;
static int ett_nrppa_TrpMeasuredResultsValue;
static int ett_nrppa_TrpMeasurementQuality;
static int ett_nrppa_TrpMeasurementTimingQuality;
static int ett_nrppa_TrpMeasurementAngleQuality;
static int ett_nrppa_TRPPhaseQuality;
static int ett_nrppa_TRP_MeasurementRequestList;
static int ett_nrppa_TRP_MeasurementRequestItem;
static int ett_nrppa_TRP_MeasurementResponseList;
static int ett_nrppa_TRP_MeasurementResponseItem;
static int ett_nrppa_TRP_MeasurementUpdateList;
static int ett_nrppa_TRP_MeasurementUpdateItem;
static int ett_nrppa_TRPInformationListTRPResp;
static int ett_nrppa_TRPInformationListTRPResp_item;
static int ett_nrppa_TRPInformation;
static int ett_nrppa_TRPInformationTypeResponseList;
static int ett_nrppa_TRPInformationTypeResponseItem;
static int ett_nrppa_TRPInformationTypeListTRPReq;
static int ett_nrppa_TRPList;
static int ett_nrppa_TRPItem;
static int ett_nrppa_TRPPositionDefinitionType;
static int ett_nrppa_TRPPositionDirect;
static int ett_nrppa_TRPPositionDirectAccuracy;
static int ett_nrppa_TRPPositionReferenced;
static int ett_nrppa_TRP_PRS_Information_List;
static int ett_nrppa_TRP_PRS_Information_List_Item;
static int ett_nrppa_TRPReferencePointType;
static int ett_nrppa_TRP_Rx_TEGInformation;
static int ett_nrppa_TRP_RxTx_TEGInformation;
static int ett_nrppa_TRP_Tx_TEGInformation;
static int ett_nrppa_TRPTxTEGAssociation;
static int ett_nrppa_TRPTEGItem;
static int ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceID_Item;
static int ett_nrppa_DLPRSResourceID_Item;
static int ett_nrppa_TxHoppingConfiguration;
static int ett_nrppa_UEReportingInformation;
static int ett_nrppa_UETxTEGAssociationList;
static int ett_nrppa_UETxTEGAssociationItem;
static int ett_nrppa_UL_AoA;
static int ett_nrppa_UL_RTOAMeasurement;
static int ett_nrppa_UL_RSCPMeas;
static int ett_nrppa_ULRTOAMeas;
static int ett_nrppa_UL_SRS_RSRPP;
static int ett_nrppa_UplinkChannelBW_PerSCS_List;
static int ett_nrppa_ValidityAreaSpecificSRSInformation;
static int ett_nrppa_WLANMeasurementQuantities;
static int ett_nrppa_WLANMeasurementQuantities_Item;
static int ett_nrppa_WLANMeasurementResult;
static int ett_nrppa_WLANMeasurementResult_Item;
static int ett_nrppa_WLANChannelList;
static int ett_nrppa_ZoA;
static int ett_nrppa_E_CIDMeasurementInitiationRequest;
static int ett_nrppa_E_CIDMeasurementInitiationResponse;
static int ett_nrppa_E_CIDMeasurementInitiationFailure;
static int ett_nrppa_E_CIDMeasurementFailureIndication;
static int ett_nrppa_E_CIDMeasurementReport;
static int ett_nrppa_E_CIDMeasurementTerminationCommand;
static int ett_nrppa_OTDOAInformationRequest;
static int ett_nrppa_OTDOA_Information_Type;
static int ett_nrppa_OTDOA_Information_Type_Item;
static int ett_nrppa_OTDOAInformationResponse;
static int ett_nrppa_OTDOAInformationFailure;
static int ett_nrppa_AssistanceInformationControl;
static int ett_nrppa_AssistanceInformationFeedback;
static int ett_nrppa_ErrorIndication;
static int ett_nrppa_PrivateMessage;
static int ett_nrppa_PositioningInformationRequest;
static int ett_nrppa_PositioningInformationResponse;
static int ett_nrppa_PositioningInformationFailure;
static int ett_nrppa_PositioningInformationUpdate;
static int ett_nrppa_MeasurementRequest;
static int ett_nrppa_MeasurementResponse;
static int ett_nrppa_MeasurementFailure;
static int ett_nrppa_MeasurementReport;
static int ett_nrppa_MeasurementUpdate;
static int ett_nrppa_MeasurementAbort;
static int ett_nrppa_MeasurementFailureIndication;
static int ett_nrppa_TRPInformationRequest;
static int ett_nrppa_TRPInformationResponse;
static int ett_nrppa_TRPInformationFailure;
static int ett_nrppa_PositioningActivationRequest;
static int ett_nrppa_SRSType;
static int ett_nrppa_SemipersistentSRS;
static int ett_nrppa_AperiodicSRS;
static int ett_nrppa_PositioningActivationResponse;
static int ett_nrppa_PositioningActivationFailure;
static int ett_nrppa_PositioningDeactivation;
static int ett_nrppa_PRSConfigurationRequest;
static int ett_nrppa_PRSConfigurationResponse;
static int ett_nrppa_PRSConfigurationFailure;
static int ett_nrppa_MeasurementPreconfigurationRequired;
static int ett_nrppa_MeasurementPreconfigurationConfirm;
static int ett_nrppa_MeasurementPreconfigurationRefuse;
static int ett_nrppa_MeasurementActivation;
static int ett_nrppa_SRSInformationReservationNotification;

/* Global variables */
static uint32_t ProcedureCode;
static uint32_t ProtocolIE_ID;

/* Dissector tables */
static dissector_table_t nrppa_ies_dissector_table;
static dissector_table_t nrppa_extension_dissector_table;
static dissector_table_t nrppa_proc_imsg_dissector_table;
static dissector_table_t nrppa_proc_sout_dissector_table;
static dissector_table_t nrppa_proc_uout_dissector_table;

/* Include constants */
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfErrors                  256
#define maxCellinRANnode               3840
#define maxIndexesReport               64
#define maxNoMeas                      64
#define maxCellReport                  9
#define maxCellReportNR                9
#define maxnoOTDOAtypes                63
#define maxServCell                    5
#define maxEUTRAMeas                   8
#define maxGERANMeas                   8
#define maxNRMeas                      8
#define maxUTRANMeas                   8
#define maxWLANchannels                16
#define maxnoFreqHoppingBandsMinusOne  7
#define maxNoPath                      2
#define maxNrOfPosSImessage            32
#define maxnoAssistInfoFailureListItems 32
#define maxNrOfSegments                64
#define maxNrOfPosSIBs                 32
#define maxNoOfMeasTRPs                64
#define maxnoTRPs                      65535
#define maxnoTRPInfoTypes              64
#define maxnoofAngleInfo               65535
#define maxnolcs_gcs_translation       3
#define maxnoBcastCell                 16384
#define maxnoSRSTriggerStates          3
#define maxnoSpatialRelations          64
#define maxnoPosMeas                   16384
#define maxnoSRS_Carriers              32
#define maxnoSCSs                      5
#define maxnoSRS_Resources             64
#define maxnoSRS_PosResources          64
#define maxnoSRS_ResourceSets          16
#define maxnoSRS_ResourcePerSet        16
#define maxnoSRS_PosResourceSets       16
#define maxnoSRS_PosResourcePerSet     16
#define maxPRS_ResourceSets            2
#define maxPRS_ResourcesPerSet         64
#define maxNoSSBs                      255
#define maxnoofPRSresourceSet          8
#define maxnoofPRSresource             64
#define maxnoofULAoAs                  8
#define maxNoPathExtended              8
#define maxnoARPs                      16
#define maxnoUETEGs                    256
#define maxnoTRPTEGs                   8
#define maxFreqLayers                  4
#define maxNumResourcesPerAngle        24
#define maxnoAzimuthAngles             3600
#define maxnoElevationAngles           1801
#define maxnoPRSTRPs                   256
#define maxnoVACell                    32
#define maxnoaggregatedPosSRS_Resources 3
#define maxnoaggregatedPosSRS_ResourceSets 48
#define maxnoAggPosPRSResourceSets     3
#define maxnoofTimeWindowSRS           16
#define maxnoofTimeWindowMeas          16
#define maxnoPreconfiguredSRS          16
#define maxnoofHopsMinusOne            5
#define maxnoAggCombinations           2

typedef enum _ProcedureCode_enum {
  id_errorIndication =   0,
  id_privateMessage =   1,
  id_e_CIDMeasurementInitiation =   2,
  id_e_CIDMeasurementFailureIndication =   3,
  id_e_CIDMeasurementReport =   4,
  id_e_CIDMeasurementTermination =   5,
  id_oTDOAInformationExchange =   6,
  id_assistanceInformationControl =   7,
  id_assistanceInformationFeedback =   8,
  id_positioningInformationExchange =   9,
  id_positioningInformationUpdate =  10,
  id_Measurement =  11,
  id_MeasurementReport =  12,
  id_MeasurementUpdate =  13,
  id_MeasurementAbort =  14,
  id_MeasurementFailureIndication =  15,
  id_tRPInformationExchange =  16,
  id_positioningActivation =  17,
  id_positioningDeactivation =  18,
  id_pRSConfigurationExchange =  19,
  id_measurementPreconfiguration =  20,
  id_measurementActivation =  21,
  id_sRSInformationReservationNotification =  22
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Cause     =   0,
  id_CriticalityDiagnostics =   1,
  id_LMF_UE_Measurement_ID =   2,
  id_ReportCharacteristics =   3,
  id_MeasurementPeriodicity =   4,
  id_MeasurementQuantities =   5,
  id_RAN_UE_Measurement_ID =   6,
  id_E_CID_MeasurementResult =   7,
  id_OTDOACells =   8,
  id_OTDOA_Information_Type_Group =   9,
  id_OTDOA_Information_Type_Item =  10,
  id_MeasurementQuantities_Item =  11,
  id_RequestedSRSTransmissionCharacteristics =  12,
  id_Cell_Portion_ID =  14,
  id_OtherRATMeasurementQuantities =  15,
  id_OtherRATMeasurementQuantities_Item =  16,
  id_OtherRATMeasurementResult =  17,
  id_WLANMeasurementQuantities =  19,
  id_WLANMeasurementQuantities_Item =  20,
  id_WLANMeasurementResult =  21,
  id_TDD_Config_EUTRA_Item =  22,
  id_Assistance_Information =  23,
  id_Broadcast =  24,
  id_AssistanceInformationFailureList =  25,
  id_SRSConfiguration =  26,
  id_MeasurementResult =  27,
  id_TRP_ID    =  28,
  id_TRPInformationTypeListTRPReq =  29,
  id_TRPInformationListTRPResp =  30,
  id_MeasurementBeamInfoRequest =  31,
  id_ResultSS_RSRP =  32,
  id_ResultSS_RSRQ =  33,
  id_ResultCSI_RSRP =  34,
  id_ResultCSI_RSRQ =  35,
  id_AngleOfArrivalNR =  36,
  id_GeographicalCoordinates =  37,
  id_PositioningBroadcastCells =  38,
  id_LMF_Measurement_ID =  39,
  id_RAN_Measurement_ID =  40,
  id_TRP_MeasurementRequestList =  41,
  id_TRP_MeasurementResponseList =  42,
  id_TRP_MeasurementReportList =  43,
  id_SRSType   =  44,
  id_ActivationTime =  45,
  id_SRSResourceSetID =  46,
  id_TRPList   =  47,
  id_SRSSpatialRelation =  48,
  id_SystemFrameNumber =  49,
  id_SlotNumber =  50,
  id_SRSResourceTrigger =  51,
  id_TRPMeasurementQuantities =  52,
  id_AbortTransmission =  53,
  id_SFNInitialisationTime =  54,
  id_ResultNR  =  55,
  id_ResultEUTRA =  56,
  id_TRPInformationTypeItem =  57,
  id_CGI_NR    =  58,
  id_SFNInitialisationTime_NR =  59,
  id_Cell_ID   =  60,
  id_SrsFrequency =  61,
  id_TRPType   =  62,
  id_SRSSpatialRelationPerSRSResource =  63,
  id_MeasurementPeriodicityExtended =  64,
  id_PRS_Resource_ID =  65,
  id_PRSTRPList =  66,
  id_PRSTransmissionTRPList =  67,
  id_OnDemandPRS =  68,
  id_AoA_SearchWindow =  69,
  id_TRP_MeasurementUpdateList =  70,
  id_ZoA       =  71,
  id_ResponseTime =  72,
  id_UEReportingInformation =  73,
  id_MultipleULAoA =  74,
  id_UL_SRS_RSRPP =  75,
  id_SRSResourcetype =  76,
  id_ExtendedAdditionalPathList =  77,
  id_ARPLocationInfo =  78,
  id_ARP_ID    =  79,
  id_LoS_NLoSInformation =  80,
  id_UETxTEGAssociationList =  81,
  id_NumberOfTRPRxTEG =  82,
  id_NumberOfTRPRxTxTEG =  83,
  id_TRPTxTEGAssociation =  84,
  id_TRPTEGInformation =  85,
  id_TRP_Rx_TEGInformation =  86,
  id_TRP_PRS_Information_List =  87,
  id_PRS_Measurements_Info_List =  88,
  id_PRSConfigRequestType =  89,
  id_UE_TEG_Info_Request =  90,
  id_MeasurementTimeOccasion =  91,
  id_MeasurementCharacteristicsRequestIndicator =  92,
  id_TRPBeamAntennaInformation =  93,
  id_NR_TADV   =  94,
  id_MeasurementAmount =  95,
  id_pathPower =  96,
  id_PreconfigurationResult =  97,
  id_RequestType =  98,
  id_UE_TEG_ReportingPeriodicity =  99,
  id_SRSPortIndex = 100,
  id_procedure_code_101_not_to_be_used = 101,
  id_procedure_code_102_not_to_be_used = 102,
  id_procedure_code_103_not_to_be_used = 103,
  id_UETxTimingErrorMargin = 104,
  id_MeasurementPeriodicityNR_AoA = 105,
  id_SRSTransmissionStatus = 106,
  id_nrofSymbolsExtended = 107,
  id_repetitionFactorExtended = 108,
  id_StartRBHopping = 109,
  id_StartRBIndex = 110,
  id_transmissionCombn8 = 111,
  id_ExtendedResourceSymbolOffset = 112,
  id_NewNRCGI  = 113,
  id_Mobile_TRP_LocationInformation = 114,
  id_Mobile_IAB_MT_UE_ID = 115,
  id_MobileAccessPointLocation = 116,
  id_CommonTAParameters = 117,
  id_UE_Rx_Tx_Time_Diff = 118,
  id_SCS_480   = 119,
  id_SCS_960   = 120,
  id_Bandwidth_Aggregation_Request_Indication = 121,
  id_PosSRSResourceSet_Aggregation_List = 122,
  id_TimingReportingGranularityFactorExtended = 123,
  id_TimeWindowInformation_SRS_List = 124,
  id_TimeWindowInformation_Measurement_List = 125,
  id_UL_RSCPMeas = 126,
  id_SymbolIndex = 127,
  id_PosValidityAreaCellList = 128,
  id_SRSReservationType = 129,
  id_PRSBWAggregationRequestIndication = 130,
  id_AggregatedPosSRSResourceID_List = 131,
  id_AggregatedPRSResourceSetList = 132,
  id_TRPPhaseQuality = 133,
  id_NewCellIdentity = 134,
  id_ValidityAreaSpecificSRSInformation = 135,
  id_RequestedSRSPreconfigurationCharacteristics_List = 136,
  id_SRSPreconfiguration_List = 137,
  id_SRSInformation = 138,
  id_TxHoppingConfiguration = 139,
  id_MeasuredFrequencyHops = 140,
  id_ReportingGranularitykminus1 = 141,
  id_ReportingGranularitykminus2 = 142,
  id_ReportingGranularitykminus3 = 143,
  id_ReportingGranularitykminus4 = 144,
  id_ReportingGranularitykminus5 = 145,
  id_ReportingGranularitykminus6 = 146,
  id_ReportingGranularitykminus1AdditionalPath = 147,
  id_ReportingGranularitykminus2AdditionalPath = 148,
  id_ReportingGranularitykminus3AdditionalPath = 149,
  id_ReportingGranularitykminus4AdditionalPath = 150,
  id_ReportingGranularitykminus5AdditionalPath = 151,
  id_ReportingGranularitykminus6AdditionalPath = 152,
  id_MeasuredResultsAssociatedInfoList = 153,
  id_PointA    = 154,
  id_NR_PCI    = 155,
  id_SCS_SpecificCarrier = 156,
  id_MeasBasedOnAggregatedResources = 157
} ProtocolIE_ID_enum;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


static const value_string nrppa_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_nrppa_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_nrppa_NRPPATransactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_maxPrivateIEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxPrivateIEs, NULL, false);

  return offset;
}



static int
dissect_nrppa_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string nrppa_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_nrppa_local         , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_maxPrivateIEs },
  {   1, &hf_nrppa_global        , ASN1_NO_EXTENSIONS     , dissect_nrppa_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_ProcedureCode_vals[] = {
  { id_errorIndication, "id-errorIndication" },
  { id_privateMessage, "id-privateMessage" },
  { id_e_CIDMeasurementInitiation, "id-e-CIDMeasurementInitiation" },
  { id_e_CIDMeasurementFailureIndication, "id-e-CIDMeasurementFailureIndication" },
  { id_e_CIDMeasurementReport, "id-e-CIDMeasurementReport" },
  { id_e_CIDMeasurementTermination, "id-e-CIDMeasurementTermination" },
  { id_oTDOAInformationExchange, "id-oTDOAInformationExchange" },
  { id_assistanceInformationControl, "id-assistanceInformationControl" },
  { id_assistanceInformationFeedback, "id-assistanceInformationFeedback" },
  { id_positioningInformationExchange, "id-positioningInformationExchange" },
  { id_positioningInformationUpdate, "id-positioningInformationUpdate" },
  { id_Measurement, "id-Measurement" },
  { id_MeasurementReport, "id-MeasurementReport" },
  { id_MeasurementUpdate, "id-MeasurementUpdate" },
  { id_MeasurementAbort, "id-MeasurementAbort" },
  { id_MeasurementFailureIndication, "id-MeasurementFailureIndication" },
  { id_tRPInformationExchange, "id-tRPInformationExchange" },
  { id_positioningActivation, "id-positioningActivation" },
  { id_positioningDeactivation, "id-positioningDeactivation" },
  { id_pRSConfigurationExchange, "id-pRSConfigurationExchange" },
  { id_measurementPreconfiguration, "id-measurementPreconfiguration" },
  { id_measurementActivation, "id-measurementActivation" },
  { id_sRSInformationReservationNotification, "id-sRSInformationReservationNotification" },
  { 0, NULL }
};


static int
dissect_nrppa_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, false);

  col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
               val_to_str_const(ProcedureCode, nrppa_ProcedureCode_vals,
                                "unknown message"));
  return offset;
}


static const value_string nrppa_ProtocolIE_ID_vals[] = {
  { id_Cause, "id-Cause" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_LMF_UE_Measurement_ID, "id-LMF-UE-Measurement-ID" },
  { id_ReportCharacteristics, "id-ReportCharacteristics" },
  { id_MeasurementPeriodicity, "id-MeasurementPeriodicity" },
  { id_MeasurementQuantities, "id-MeasurementQuantities" },
  { id_RAN_UE_Measurement_ID, "id-RAN-UE-Measurement-ID" },
  { id_E_CID_MeasurementResult, "id-E-CID-MeasurementResult" },
  { id_OTDOACells, "id-OTDOACells" },
  { id_OTDOA_Information_Type_Group, "id-OTDOA-Information-Type-Group" },
  { id_OTDOA_Information_Type_Item, "id-OTDOA-Information-Type-Item" },
  { id_MeasurementQuantities_Item, "id-MeasurementQuantities-Item" },
  { id_RequestedSRSTransmissionCharacteristics, "id-RequestedSRSTransmissionCharacteristics" },
  { id_Cell_Portion_ID, "id-Cell-Portion-ID" },
  { id_OtherRATMeasurementQuantities, "id-OtherRATMeasurementQuantities" },
  { id_OtherRATMeasurementQuantities_Item, "id-OtherRATMeasurementQuantities-Item" },
  { id_OtherRATMeasurementResult, "id-OtherRATMeasurementResult" },
  { id_WLANMeasurementQuantities, "id-WLANMeasurementQuantities" },
  { id_WLANMeasurementQuantities_Item, "id-WLANMeasurementQuantities-Item" },
  { id_WLANMeasurementResult, "id-WLANMeasurementResult" },
  { id_TDD_Config_EUTRA_Item, "id-TDD-Config-EUTRA-Item" },
  { id_Assistance_Information, "id-Assistance-Information" },
  { id_Broadcast, "id-Broadcast" },
  { id_AssistanceInformationFailureList, "id-AssistanceInformationFailureList" },
  { id_SRSConfiguration, "id-SRSConfiguration" },
  { id_MeasurementResult, "id-MeasurementResult" },
  { id_TRP_ID, "id-TRP-ID" },
  { id_TRPInformationTypeListTRPReq, "id-TRPInformationTypeListTRPReq" },
  { id_TRPInformationListTRPResp, "id-TRPInformationListTRPResp" },
  { id_MeasurementBeamInfoRequest, "id-MeasurementBeamInfoRequest" },
  { id_ResultSS_RSRP, "id-ResultSS-RSRP" },
  { id_ResultSS_RSRQ, "id-ResultSS-RSRQ" },
  { id_ResultCSI_RSRP, "id-ResultCSI-RSRP" },
  { id_ResultCSI_RSRQ, "id-ResultCSI-RSRQ" },
  { id_AngleOfArrivalNR, "id-AngleOfArrivalNR" },
  { id_GeographicalCoordinates, "id-GeographicalCoordinates" },
  { id_PositioningBroadcastCells, "id-PositioningBroadcastCells" },
  { id_LMF_Measurement_ID, "id-LMF-Measurement-ID" },
  { id_RAN_Measurement_ID, "id-RAN-Measurement-ID" },
  { id_TRP_MeasurementRequestList, "id-TRP-MeasurementRequestList" },
  { id_TRP_MeasurementResponseList, "id-TRP-MeasurementResponseList" },
  { id_TRP_MeasurementReportList, "id-TRP-MeasurementReportList" },
  { id_SRSType, "id-SRSType" },
  { id_ActivationTime, "id-ActivationTime" },
  { id_SRSResourceSetID, "id-SRSResourceSetID" },
  { id_TRPList, "id-TRPList" },
  { id_SRSSpatialRelation, "id-SRSSpatialRelation" },
  { id_SystemFrameNumber, "id-SystemFrameNumber" },
  { id_SlotNumber, "id-SlotNumber" },
  { id_SRSResourceTrigger, "id-SRSResourceTrigger" },
  { id_TRPMeasurementQuantities, "id-TRPMeasurementQuantities" },
  { id_AbortTransmission, "id-AbortTransmission" },
  { id_SFNInitialisationTime, "id-SFNInitialisationTime" },
  { id_ResultNR, "id-ResultNR" },
  { id_ResultEUTRA, "id-ResultEUTRA" },
  { id_TRPInformationTypeItem, "id-TRPInformationTypeItem" },
  { id_CGI_NR, "id-CGI-NR" },
  { id_SFNInitialisationTime_NR, "id-SFNInitialisationTime-NR" },
  { id_Cell_ID, "id-Cell-ID" },
  { id_SrsFrequency, "id-SrsFrequency" },
  { id_TRPType, "id-TRPType" },
  { id_SRSSpatialRelationPerSRSResource, "id-SRSSpatialRelationPerSRSResource" },
  { id_MeasurementPeriodicityExtended, "id-MeasurementPeriodicityExtended" },
  { id_PRS_Resource_ID, "id-PRS-Resource-ID" },
  { id_PRSTRPList, "id-PRSTRPList" },
  { id_PRSTransmissionTRPList, "id-PRSTransmissionTRPList" },
  { id_OnDemandPRS, "id-OnDemandPRS" },
  { id_AoA_SearchWindow, "id-AoA-SearchWindow" },
  { id_TRP_MeasurementUpdateList, "id-TRP-MeasurementUpdateList" },
  { id_ZoA, "id-ZoA" },
  { id_ResponseTime, "id-ResponseTime" },
  { id_UEReportingInformation, "id-UEReportingInformation" },
  { id_MultipleULAoA, "id-MultipleULAoA" },
  { id_UL_SRS_RSRPP, "id-UL-SRS-RSRPP" },
  { id_SRSResourcetype, "id-SRSResourcetype" },
  { id_ExtendedAdditionalPathList, "id-ExtendedAdditionalPathList" },
  { id_ARPLocationInfo, "id-ARPLocationInfo" },
  { id_ARP_ID, "id-ARP-ID" },
  { id_LoS_NLoSInformation, "id-LoS-NLoSInformation" },
  { id_UETxTEGAssociationList, "id-UETxTEGAssociationList" },
  { id_NumberOfTRPRxTEG, "id-NumberOfTRPRxTEG" },
  { id_NumberOfTRPRxTxTEG, "id-NumberOfTRPRxTxTEG" },
  { id_TRPTxTEGAssociation, "id-TRPTxTEGAssociation" },
  { id_TRPTEGInformation, "id-TRPTEGInformation" },
  { id_TRP_Rx_TEGInformation, "id-TRP-Rx-TEGInformation" },
  { id_TRP_PRS_Information_List, "id-TRP-PRS-Information-List" },
  { id_PRS_Measurements_Info_List, "id-PRS-Measurements-Info-List" },
  { id_PRSConfigRequestType, "id-PRSConfigRequestType" },
  { id_UE_TEG_Info_Request, "id-UE-TEG-Info-Request" },
  { id_MeasurementTimeOccasion, "id-MeasurementTimeOccasion" },
  { id_MeasurementCharacteristicsRequestIndicator, "id-MeasurementCharacteristicsRequestIndicator" },
  { id_TRPBeamAntennaInformation, "id-TRPBeamAntennaInformation" },
  { id_NR_TADV, "id-NR-TADV" },
  { id_MeasurementAmount, "id-MeasurementAmount" },
  { id_pathPower, "id-pathPower" },
  { id_PreconfigurationResult, "id-PreconfigurationResult" },
  { id_RequestType, "id-RequestType" },
  { id_UE_TEG_ReportingPeriodicity, "id-UE-TEG-ReportingPeriodicity" },
  { id_SRSPortIndex, "id-SRSPortIndex" },
  { id_procedure_code_101_not_to_be_used, "id-procedure-code-101-not-to-be-used" },
  { id_procedure_code_102_not_to_be_used, "id-procedure-code-102-not-to-be-used" },
  { id_procedure_code_103_not_to_be_used, "id-procedure-code-103-not-to-be-used" },
  { id_UETxTimingErrorMargin, "id-UETxTimingErrorMargin" },
  { id_MeasurementPeriodicityNR_AoA, "id-MeasurementPeriodicityNR-AoA" },
  { id_SRSTransmissionStatus, "id-SRSTransmissionStatus" },
  { id_nrofSymbolsExtended, "id-nrofSymbolsExtended" },
  { id_repetitionFactorExtended, "id-repetitionFactorExtended" },
  { id_StartRBHopping, "id-StartRBHopping" },
  { id_StartRBIndex, "id-StartRBIndex" },
  { id_transmissionCombn8, "id-transmissionCombn8" },
  { id_ExtendedResourceSymbolOffset, "id-ExtendedResourceSymbolOffset" },
  { id_NewNRCGI, "id-NewNRCGI" },
  { id_Mobile_TRP_LocationInformation, "id-Mobile-TRP-LocationInformation" },
  { id_Mobile_IAB_MT_UE_ID, "id-Mobile-IAB-MT-UE-ID" },
  { id_MobileAccessPointLocation, "id-MobileAccessPointLocation" },
  { id_CommonTAParameters, "id-CommonTAParameters" },
  { id_UE_Rx_Tx_Time_Diff, "id-UE-Rx-Tx-Time-Diff" },
  { id_SCS_480, "id-SCS-480" },
  { id_SCS_960, "id-SCS-960" },
  { id_Bandwidth_Aggregation_Request_Indication, "id-Bandwidth-Aggregation-Request-Indication" },
  { id_PosSRSResourceSet_Aggregation_List, "id-PosSRSResourceSet-Aggregation-List" },
  { id_TimingReportingGranularityFactorExtended, "id-TimingReportingGranularityFactorExtended" },
  { id_TimeWindowInformation_SRS_List, "id-TimeWindowInformation-SRS-List" },
  { id_TimeWindowInformation_Measurement_List, "id-TimeWindowInformation-Measurement-List" },
  { id_UL_RSCPMeas, "id-UL-RSCPMeas" },
  { id_SymbolIndex, "id-SymbolIndex" },
  { id_PosValidityAreaCellList, "id-PosValidityAreaCellList" },
  { id_SRSReservationType, "id-SRSReservationType" },
  { id_PRSBWAggregationRequestIndication, "id-PRSBWAggregationRequestIndication" },
  { id_AggregatedPosSRSResourceID_List, "id-AggregatedPosSRSResourceID-List" },
  { id_AggregatedPRSResourceSetList, "id-AggregatedPRSResourceSetList" },
  { id_TRPPhaseQuality, "id-TRPPhaseQuality" },
  { id_NewCellIdentity, "id-NewCellIdentity" },
  { id_ValidityAreaSpecificSRSInformation, "id-ValidityAreaSpecificSRSInformation" },
  { id_RequestedSRSPreconfigurationCharacteristics_List, "id-RequestedSRSPreconfigurationCharacteristics-List" },
  { id_SRSPreconfiguration_List, "id-SRSPreconfiguration-List" },
  { id_SRSInformation, "id-SRSInformation" },
  { id_TxHoppingConfiguration, "id-TxHoppingConfiguration" },
  { id_MeasuredFrequencyHops, "id-MeasuredFrequencyHops" },
  { id_ReportingGranularitykminus1, "id-ReportingGranularitykminus1" },
  { id_ReportingGranularitykminus2, "id-ReportingGranularitykminus2" },
  { id_ReportingGranularitykminus3, "id-ReportingGranularitykminus3" },
  { id_ReportingGranularitykminus4, "id-ReportingGranularitykminus4" },
  { id_ReportingGranularitykminus5, "id-ReportingGranularitykminus5" },
  { id_ReportingGranularitykminus6, "id-ReportingGranularitykminus6" },
  { id_ReportingGranularitykminus1AdditionalPath, "id-ReportingGranularitykminus1AdditionalPath" },
  { id_ReportingGranularitykminus2AdditionalPath, "id-ReportingGranularitykminus2AdditionalPath" },
  { id_ReportingGranularitykminus3AdditionalPath, "id-ReportingGranularitykminus3AdditionalPath" },
  { id_ReportingGranularitykminus4AdditionalPath, "id-ReportingGranularitykminus4AdditionalPath" },
  { id_ReportingGranularitykminus5AdditionalPath, "id-ReportingGranularitykminus5AdditionalPath" },
  { id_ReportingGranularitykminus6AdditionalPath, "id-ReportingGranularitykminus6AdditionalPath" },
  { id_MeasuredResultsAssociatedInfoList, "id-MeasuredResultsAssociatedInfoList" },
  { id_PointA, "id-PointA" },
  { id_NR_PCI, "id-NR-PCI" },
  { id_SCS_SpecificCarrier, "id-SCS-SpecificCarrier" },
  { id_MeasBasedOnAggregatedResources, "id-MeasBasedOnAggregatedResources" },
  { 0, NULL }
};


static int
dissect_nrppa_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &ProtocolIE_ID, false);

  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2),
                           ": %s",
                           val_to_str(ProtocolIE_ID, VALS(nrppa_ProtocolIE_ID_vals), "unknown (%d)"));
  }
  return offset;
}


static const value_string nrppa_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_nrppa_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_nrppa_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_nrppa_id            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_ID },
  { &hf_nrppa_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_Criticality },
  { &hf_nrppa_ie_field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_nrppa_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Field },
};

static int
dissect_nrppa_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, false);

  return offset;
}



static int
dissect_nrppa_ProtocolIE_Single_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nrppa_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_nrppa_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_nrppa_ext_id        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_ID },
  { &hf_nrppa_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_Criticality },
  { &hf_nrppa_extensionValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_nrppa_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolExtensionField },
};

static int
dissect_nrppa_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, false);

  return offset;
}



static int
dissect_nrppa_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_nrppa_id_01         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PrivateIE_ID },
  { &hf_nrppa_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_Criticality },
  { &hf_nrppa_value         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_nrppa_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PrivateIE_Field },
};

static int
dissect_nrppa_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, false);

  return offset;
}



static int
dissect_nrppa_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_nrppa_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProcedureCode },
  { &hf_nrppa_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_Criticality },
  { &hf_nrppa_nrppatransactionID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_NRPPATransactionID },
  { &hf_nrppa_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_nrppa_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_nrppa_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProcedureCode },
  { &hf_nrppa_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_Criticality },
  { &hf_nrppa_nrppatransactionID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_NRPPATransactionID },
  { &hf_nrppa_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_nrppa_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_nrppa_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProcedureCode },
  { &hf_nrppa_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_Criticality },
  { &hf_nrppa_nrppatransactionID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_NRPPATransactionID },
  { &hf_nrppa_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string nrppa_NRPPA_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t NRPPA_PDU_choice[] = {
  {   0, &hf_nrppa_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_nrppa_InitiatingMessage },
  {   1, &hf_nrppa_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_nrppa_SuccessfulOutcome },
  {   2, &hf_nrppa_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_nrppa_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_NRPPA_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  proto_tree_add_item(tree, proto_nrppa, tvb, 0, -1, ENC_NA);
  add_per_encoded_label(tvb, actx->pinfo, tree);

  col_append_sep_str(actx->pinfo->cinfo, COL_PROTOCOL, "/", "NRPPa");
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_NRPPA_PDU, NRPPA_PDU_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_SRSResourceSetID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, true);

  return offset;
}



static int
dissect_nrppa_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string nrppa_AbortTransmission_vals[] = {
  {   0, "deactivateSRSResourceSetID" },
  {   1, "releaseALL" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t AbortTransmission_choice[] = {
  {   0, &hf_nrppa_deactivateSRSResourceSetID, ASN1_NO_EXTENSIONS     , dissect_nrppa_SRSResourceSetID },
  {   1, &hf_nrppa_releaseALL    , ASN1_NO_EXTENSIONS     , dissect_nrppa_NULL },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_AbortTransmission(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_AbortTransmission, AbortTransmission_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_37949_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 37949U, NULL, true);

  return offset;
}


static const value_string nrppa_T_subcarrierSpacing_vals[] = {
  {   0, "kHz15" },
  {   1, "kHz30" },
  {   2, "kHz60" },
  {   3, "kHz120" },
  {   4, "kHz480" },
  {   5, "kHz960" },
  { 0, NULL }
};


static int
dissect_nrppa_T_subcarrierSpacing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 2, NULL);

  return offset;
}


static const value_string nrppa_T_cyclicPrefix_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_nrppa_T_cyclicPrefix(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_3301_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3301U, NULL, true);

  return offset;
}


static const value_string nrppa_T_shift7dot5kHz_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_T_shift7dot5kHz(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_SRSResourceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const value_string nrppa_T_nrofSRS_Ports_vals[] = {
  {   0, "port1" },
  {   1, "ports2" },
  {   2, "ports4" },
  { 0, NULL }
};


static int
dissect_nrppa_T_nrofSRS_Ports(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}


static const per_sequence_t T_n2_sequence[] = {
  { &hf_nrppa_combOffset_n2 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_1 },
  { &hf_nrppa_cyclicShift_n2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_T_n2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_T_n2, T_n2_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 11U, NULL, false);

  return offset;
}


static const per_sequence_t T_n4_sequence[] = {
  { &hf_nrppa_combOffset_n4 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3 },
  { &hf_nrppa_cyclicShift_n4, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_11 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_T_n4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_T_n4, T_n4_sequence);

  return offset;
}


static const value_string nrppa_TransmissionComb_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TransmissionComb_choice[] = {
  {   0, &hf_nrppa_n2            , ASN1_NO_EXTENSIONS     , dissect_nrppa_T_n2 },
  {   1, &hf_nrppa_n4            , ASN1_NO_EXTENSIONS     , dissect_nrppa_T_n4 },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TransmissionComb(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TransmissionComb, TransmissionComb_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 13U, NULL, false);

  return offset;
}


static const value_string nrppa_T_nrofSymbols_01_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  { 0, NULL }
};


static int
dissect_nrppa_T_nrofSymbols_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}


static const value_string nrppa_T_repetitionFactor_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  { 0, NULL }
};


static int
dissect_nrppa_T_repetitionFactor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_67(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 67U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_268(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 268U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const value_string nrppa_T_groupOrSequenceHopping_01_vals[] = {
  {   0, "neither" },
  {   1, "groupHopping" },
  {   2, "sequenceHopping" },
  { 0, NULL }
};


static int
dissect_nrppa_T_groupOrSequenceHopping_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}


static const value_string nrppa_T_periodicity_vals[] = {
  {   0, "slot1" },
  {   1, "slot2" },
  {   2, "slot4" },
  {   3, "slot5" },
  {   4, "slot8" },
  {   5, "slot10" },
  {   6, "slot16" },
  {   7, "slot20" },
  {   8, "slot32" },
  {   9, "slot40" },
  {  10, "slot64" },
  {  11, "slot80" },
  {  12, "slot160" },
  {  13, "slot320" },
  {  14, "slot640" },
  {  15, "slot1280" },
  {  16, "slot2560" },
  { 0, NULL }
};


static int
dissect_nrppa_T_periodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     17, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_2559_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2559U, NULL, true);

  return offset;
}


static const per_sequence_t ResourceTypePeriodic_sequence[] = {
  { &hf_nrppa_periodicity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_periodicity },
  { &hf_nrppa_offset        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_2559_ },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResourceTypePeriodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResourceTypePeriodic, ResourceTypePeriodic_sequence);

  return offset;
}


static const value_string nrppa_T_periodicity_01_vals[] = {
  {   0, "slot1" },
  {   1, "slot2" },
  {   2, "slot4" },
  {   3, "slot5" },
  {   4, "slot8" },
  {   5, "slot10" },
  {   6, "slot16" },
  {   7, "slot20" },
  {   8, "slot32" },
  {   9, "slot40" },
  {  10, "slot64" },
  {  11, "slot80" },
  {  12, "slot160" },
  {  13, "slot320" },
  {  14, "slot640" },
  {  15, "slot1280" },
  {  16, "slot2560" },
  { 0, NULL }
};


static int
dissect_nrppa_T_periodicity_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     17, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ResourceTypeSemi_persistent_sequence[] = {
  { &hf_nrppa_periodicity_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_periodicity_01 },
  { &hf_nrppa_offset        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_2559_ },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResourceTypeSemi_persistent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResourceTypeSemi_persistent, ResourceTypeSemi_persistent_sequence);

  return offset;
}


static const value_string nrppa_T_aperiodicResourceType_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_T_aperiodicResourceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ResourceTypeAperiodic_sequence[] = {
  { &hf_nrppa_aperiodicResourceType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_aperiodicResourceType },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResourceTypeAperiodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResourceTypeAperiodic, ResourceTypeAperiodic_sequence);

  return offset;
}


static const value_string nrppa_ResourceType_vals[] = {
  {   0, "periodic" },
  {   1, "semi-persistent" },
  {   2, "aperiodic" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ResourceType_choice[] = {
  {   0, &hf_nrppa_periodic_02   , ASN1_NO_EXTENSIONS     , dissect_nrppa_ResourceTypePeriodic },
  {   1, &hf_nrppa_semi_persistent_02, ASN1_NO_EXTENSIONS     , dissect_nrppa_ResourceTypeSemi_persistent },
  {   2, &hf_nrppa_aperiodic_02  , ASN1_NO_EXTENSIONS     , dissect_nrppa_ResourceTypeAperiodic },
  {   3, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_ResourceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_ResourceType, ResourceType_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, false);

  return offset;
}


static const per_sequence_t SRSResource_sequence[] = {
  { &hf_nrppa_sRSResourceID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSResourceID },
  { &hf_nrppa_nrofSRS_Ports , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_nrofSRS_Ports },
  { &hf_nrppa_transmissionComb, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TransmissionComb },
  { &hf_nrppa_startPosition , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_13 },
  { &hf_nrppa_nrofSymbols_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_nrofSymbols_01 },
  { &hf_nrppa_repetitionFactor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_repetitionFactor },
  { &hf_nrppa_freqDomainPosition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_67 },
  { &hf_nrppa_freqDomainShift, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_268 },
  { &hf_nrppa_c_SRS         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_63 },
  { &hf_nrppa_b_SRS         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3 },
  { &hf_nrppa_b_hop         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3 },
  { &hf_nrppa_groupOrSequenceHopping_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_groupOrSequenceHopping_01 },
  { &hf_nrppa_resourceType_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ResourceType },
  { &hf_nrppa_sequenceId_01 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_1023 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSResource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSResource, SRSResource_sequence);

  return offset;
}


static const per_sequence_t SRSResource_List_sequence_of[1] = {
  { &hf_nrppa_SRSResource_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSResource },
};

static int
dissect_nrppa_SRSResource_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SRSResource_List, SRSResource_List_sequence_of,
                                                  1, maxnoSRS_Resources, false);

  return offset;
}



static int
dissect_nrppa_SRSPosResourceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const per_sequence_t T_n2_01_sequence[] = {
  { &hf_nrppa_combOffset_n2 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_1 },
  { &hf_nrppa_cyclicShift_n2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_T_n2_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_T_n2_01, T_n2_01_sequence);

  return offset;
}


static const per_sequence_t T_n4_01_sequence[] = {
  { &hf_nrppa_combOffset_n4 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3 },
  { &hf_nrppa_cyclicShift_n4, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_11 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_T_n4_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_T_n4_01, T_n4_01_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 5U, NULL, false);

  return offset;
}


static const per_sequence_t T_n8_sequence[] = {
  { &hf_nrppa_combOffset_n8 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_7 },
  { &hf_nrppa_cyclicShift_n8, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_5 },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_T_n8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_T_n8, T_n8_sequence);

  return offset;
}


static const value_string nrppa_TransmissionCombPos_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  {   2, "n8" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TransmissionCombPos_choice[] = {
  {   0, &hf_nrppa_n2_01         , ASN1_NO_EXTENSIONS     , dissect_nrppa_T_n2_01 },
  {   1, &hf_nrppa_n4_01         , ASN1_NO_EXTENSIONS     , dissect_nrppa_T_n4_01 },
  {   2, &hf_nrppa_n8            , ASN1_NO_EXTENSIONS     , dissect_nrppa_T_n8 },
  {   3, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TransmissionCombPos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TransmissionCombPos, TransmissionCombPos_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_T_nrofSymbols_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  {   4, "n12" },
  { 0, NULL }
};


static int
dissect_nrppa_T_nrofSymbols(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, false, 0, NULL);

  return offset;
}


static const value_string nrppa_T_groupOrSequenceHopping_vals[] = {
  {   0, "neither" },
  {   1, "groupHopping" },
  {   2, "sequenceHopping" },
  { 0, NULL }
};


static int
dissect_nrppa_T_groupOrSequenceHopping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}


static const value_string nrppa_SRSPeriodicity_vals[] = {
  {   0, "slot1" },
  {   1, "slot2" },
  {   2, "slot4" },
  {   3, "slot5" },
  {   4, "slot8" },
  {   5, "slot10" },
  {   6, "slot16" },
  {   7, "slot20" },
  {   8, "slot32" },
  {   9, "slot40" },
  {  10, "slot64" },
  {  11, "slot80" },
  {  12, "slot160" },
  {  13, "slot320" },
  {  14, "slot640" },
  {  15, "slot1280" },
  {  16, "slot2560" },
  {  17, "slot5120" },
  {  18, "slot10240" },
  {  19, "slot40960" },
  {  20, "slot81920" },
  {  21, "slot128" },
  {  22, "slot256" },
  {  23, "slot512" },
  {  24, "slot20480" },
  { 0, NULL }
};


static int
dissect_nrppa_SRSPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     21, NULL, true, 4, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_81919_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 81919U, NULL, true);

  return offset;
}


static const per_sequence_t ResourceTypePeriodicPos_sequence[] = {
  { &hf_nrppa_sRSPeriodicity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSPeriodicity },
  { &hf_nrppa_offset_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_81919_ },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResourceTypePeriodicPos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResourceTypePeriodicPos, ResourceTypePeriodicPos_sequence);

  return offset;
}


static const per_sequence_t ResourceTypeSemi_persistentPos_sequence[] = {
  { &hf_nrppa_sRSPeriodicity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSPeriodicity },
  { &hf_nrppa_offset_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_81919_ },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResourceTypeSemi_persistentPos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResourceTypeSemi_persistentPos, ResourceTypeSemi_persistentPos_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32U, NULL, false);

  return offset;
}


static const per_sequence_t ResourceTypeAperiodicPos_sequence[] = {
  { &hf_nrppa_slotOffset    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_32 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResourceTypeAperiodicPos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResourceTypeAperiodicPos, ResourceTypeAperiodicPos_sequence);

  return offset;
}


static const value_string nrppa_ResourceTypePos_vals[] = {
  {   0, "periodic" },
  {   1, "semi-persistent" },
  {   2, "aperiodic" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ResourceTypePos_choice[] = {
  {   0, &hf_nrppa_periodic_03   , ASN1_NO_EXTENSIONS     , dissect_nrppa_ResourceTypePeriodicPos },
  {   1, &hf_nrppa_semi_persistent_03, ASN1_NO_EXTENSIONS     , dissect_nrppa_ResourceTypeSemi_persistentPos },
  {   2, &hf_nrppa_aperiodic_03  , ASN1_NO_EXTENSIONS     , dissect_nrppa_ResourceTypeAperiodicPos },
  {   3, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_ResourceTypePos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_ResourceTypePos, ResourceTypePos_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_1007(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, false);

  return offset;
}



static int
dissect_nrppa_SSB_Index(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const per_sequence_t SSB_sequence[] = {
  { &hf_nrppa_pCI_NR        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_1007 },
  { &hf_nrppa_ssb_index     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SSB_Index },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SSB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SSB, SSB_sequence);

  return offset;
}



static int
dissect_nrppa_PRS_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_nrppa_PRS_Resource_Set_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}



static int
dissect_nrppa_PRS_Resource_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const per_sequence_t PRSInformationPos_sequence[] = {
  { &hf_nrppa_pRS_IDPos     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_ID },
  { &hf_nrppa_pRS_Resource_Set_IDPos, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_pRS_Resource_IDPos, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRS_Resource_ID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSInformationPos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSInformationPos, PRSInformationPos_sequence);

  return offset;
}


static const value_string nrppa_SpatialRelationPos_vals[] = {
  {   0, "sSBPos" },
  {   1, "pRSInformationPos" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t SpatialRelationPos_choice[] = {
  {   0, &hf_nrppa_sSBPos        , ASN1_NO_EXTENSIONS     , dissect_nrppa_SSB },
  {   1, &hf_nrppa_pRSInformationPos, ASN1_NO_EXTENSIONS     , dissect_nrppa_PRSInformationPos },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_SpatialRelationPos(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_SpatialRelationPos, SpatialRelationPos_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PosSRSResource_Item_sequence[] = {
  { &hf_nrppa_srs_PosResourceId, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSPosResourceID },
  { &hf_nrppa_transmissionCombPos, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TransmissionCombPos },
  { &hf_nrppa_startPosition , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_13 },
  { &hf_nrppa_nrofSymbols   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_nrofSymbols },
  { &hf_nrppa_freqDomainShift, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_268 },
  { &hf_nrppa_c_SRS         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_63 },
  { &hf_nrppa_groupOrSequenceHopping, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_groupOrSequenceHopping },
  { &hf_nrppa_resourceTypePos, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ResourceTypePos },
  { &hf_nrppa_sequenceId    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_65535 },
  { &hf_nrppa_spatialRelationPos, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SpatialRelationPos },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PosSRSResource_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PosSRSResource_Item, PosSRSResource_Item_sequence);

  return offset;
}


static const per_sequence_t PosSRSResource_List_sequence_of[1] = {
  { &hf_nrppa_PosSRSResource_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSRSResource_Item },
};

static int
dissect_nrppa_PosSRSResource_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PosSRSResource_List, PosSRSResource_List_sequence_of,
                                                  1, maxnoSRS_PosResources, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}


static const per_sequence_t SRSResourceID_List_sequence_of[1] = {
  { &hf_nrppa_SRSResourceID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSResourceID },
};

static int
dissect_nrppa_SRSResourceID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SRSResourceID_List, SRSResourceID_List_sequence_of,
                                                  1, maxnoSRS_ResourcePerSet, false);

  return offset;
}


static const value_string nrppa_T_periodicSet_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_T_periodicSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ResourceSetTypePeriodic_sequence[] = {
  { &hf_nrppa_periodicSet   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_periodicSet },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResourceSetTypePeriodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResourceSetTypePeriodic, ResourceSetTypePeriodic_sequence);

  return offset;
}


static const value_string nrppa_T_semi_persistentSet_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_T_semi_persistentSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ResourceSetTypeSemi_persistent_sequence[] = {
  { &hf_nrppa_semi_persistentSet, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_semi_persistentSet },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResourceSetTypeSemi_persistent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResourceSetTypeSemi_persistent, ResourceSetTypeSemi_persistent_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_1_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 3U, NULL, false);

  return offset;
}


static const per_sequence_t ResourceSetTypeAperiodic_sequence[] = {
  { &hf_nrppa_sRSResourceTrigger, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_1_3 },
  { &hf_nrppa_slotoffset    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_32 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResourceSetTypeAperiodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResourceSetTypeAperiodic, ResourceSetTypeAperiodic_sequence);

  return offset;
}


static const value_string nrppa_ResourceSetType_vals[] = {
  {   0, "periodic" },
  {   1, "semi-persistent" },
  {   2, "aperiodic" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ResourceSetType_choice[] = {
  {   0, &hf_nrppa_periodic_01   , ASN1_NO_EXTENSIONS     , dissect_nrppa_ResourceSetTypePeriodic },
  {   1, &hf_nrppa_semi_persistent_01, ASN1_NO_EXTENSIONS     , dissect_nrppa_ResourceSetTypeSemi_persistent },
  {   2, &hf_nrppa_aperiodic_01  , ASN1_NO_EXTENSIONS     , dissect_nrppa_ResourceSetTypeAperiodic },
  {   3, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_ResourceSetType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_ResourceSetType, ResourceSetType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SRSResourceSet_sequence[] = {
  { &hf_nrppa_sRSResourceSetID1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_15 },
  { &hf_nrppa_sRSResourceID_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSResourceID_List },
  { &hf_nrppa_resourceSetType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ResourceSetType },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSResourceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSResourceSet, SRSResourceSet_sequence);

  return offset;
}


static const per_sequence_t SRSResourceSet_List_sequence_of[1] = {
  { &hf_nrppa_SRSResourceSet_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSResourceSet },
};

static int
dissect_nrppa_SRSResourceSet_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SRSResourceSet_List, SRSResourceSet_List_sequence_of,
                                                  1, maxnoSRS_ResourceSets, false);

  return offset;
}


static const per_sequence_t PosSRSResourceIDPerSet_List_sequence_of[1] = {
  { &hf_nrppa_PosSRSResourceIDPerSet_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSPosResourceID },
};

static int
dissect_nrppa_PosSRSResourceIDPerSet_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PosSRSResourceIDPerSet_List, PosSRSResourceIDPerSet_List_sequence_of,
                                                  1, maxnoSRS_PosResourcePerSet, false);

  return offset;
}


static const value_string nrppa_T_posperiodicSet_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_T_posperiodicSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PosResourceSetTypePeriodic_sequence[] = {
  { &hf_nrppa_posperiodicSet, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_posperiodicSet },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PosResourceSetTypePeriodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PosResourceSetTypePeriodic, PosResourceSetTypePeriodic_sequence);

  return offset;
}


static const value_string nrppa_T_possemi_persistentSet_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_T_possemi_persistentSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PosResourceSetTypeSemi_persistent_sequence[] = {
  { &hf_nrppa_possemi_persistentSet, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_possemi_persistentSet },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PosResourceSetTypeSemi_persistent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PosResourceSetTypeSemi_persistent, PosResourceSetTypeSemi_persistent_sequence);

  return offset;
}


static const per_sequence_t PosResourceSetTypeAperiodic_sequence[] = {
  { &hf_nrppa_sRSResourceTrigger, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_1_3 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PosResourceSetTypeAperiodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PosResourceSetTypeAperiodic, PosResourceSetTypeAperiodic_sequence);

  return offset;
}


static const value_string nrppa_PosResourceSetType_vals[] = {
  {   0, "periodic" },
  {   1, "semi-persistent" },
  {   2, "aperiodic" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t PosResourceSetType_choice[] = {
  {   0, &hf_nrppa_periodic      , ASN1_NO_EXTENSIONS     , dissect_nrppa_PosResourceSetTypePeriodic },
  {   1, &hf_nrppa_semi_persistent, ASN1_NO_EXTENSIONS     , dissect_nrppa_PosResourceSetTypeSemi_persistent },
  {   2, &hf_nrppa_aperiodic     , ASN1_NO_EXTENSIONS     , dissect_nrppa_PosResourceSetTypeAperiodic },
  {   3, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_PosResourceSetType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_PosResourceSetType, PosResourceSetType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PosSRSResourceSet_Item_sequence[] = {
  { &hf_nrppa_possrsResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_15 },
  { &hf_nrppa_possRSResourceIDPerSet_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSRSResourceIDPerSet_List },
  { &hf_nrppa_posresourceSetType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PosResourceSetType },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PosSRSResourceSet_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PosSRSResourceSet_Item, PosSRSResourceSet_Item_sequence);

  return offset;
}


static const per_sequence_t PosSRSResourceSet_List_sequence_of[1] = {
  { &hf_nrppa_PosSRSResourceSet_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSRSResourceSet_Item },
};

static int
dissect_nrppa_PosSRSResourceSet_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PosSRSResourceSet_List, PosSRSResourceSet_List_sequence_of,
                                                  1, maxnoSRS_PosResourceSets, false);

  return offset;
}


static const per_sequence_t SRSConfig_sequence[] = {
  { &hf_nrppa_sRSResource_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SRSResource_List },
  { &hf_nrppa_posSRSResource_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PosSRSResource_List },
  { &hf_nrppa_sRSResourceSet_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SRSResourceSet_List },
  { &hf_nrppa_posSRSResourceSet_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PosSRSResourceSet_List },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSConfig, SRSConfig_sequence);

  return offset;
}


static const per_sequence_t ActiveULBWP_sequence[] = {
  { &hf_nrppa_locationAndBandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_37949_ },
  { &hf_nrppa_subcarrierSpacing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_subcarrierSpacing },
  { &hf_nrppa_cyclicPrefix  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_cyclicPrefix },
  { &hf_nrppa_txDirectCurrentLocation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3301_ },
  { &hf_nrppa_shift7dot5kHz , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_T_shift7dot5kHz },
  { &hf_nrppa_sRSConfig     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSConfig },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ActiveULBWP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ActiveULBWP, ActiveULBWP_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_16351(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16351U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_8176(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8176U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_4088(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4088U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_2044(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2044U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_1022(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1022U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, false);

  return offset;
}


static const value_string nrppa_RelativePathDelay_vals[] = {
  {   0, "k0" },
  {   1, "k1" },
  {   2, "k2" },
  {   3, "k3" },
  {   4, "k4" },
  {   5, "k5" },
  {   6, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t RelativePathDelay_choice[] = {
  {   0, &hf_nrppa_k0_01         , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_16351 },
  {   1, &hf_nrppa_k1_01         , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_8176 },
  {   2, &hf_nrppa_k2_01         , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_4088 },
  {   3, &hf_nrppa_k3_01         , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_2044 },
  {   4, &hf_nrppa_k4_01         , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_1022 },
  {   5, &hf_nrppa_k5_01         , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_511 },
  {   6, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_RelativePathDelay(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_RelativePathDelay, RelativePathDelay_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, false);

  return offset;
}


static const value_string nrppa_T_resolution_vals[] = {
  {   0, "m0dot1" },
  {   1, "m1" },
  {   2, "m10" },
  {   3, "m30" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resolution(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TrpMeasurementTimingQuality_sequence[] = {
  { &hf_nrppa_measurementQuality_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_31 },
  { &hf_nrppa_resolution    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_resolution },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TrpMeasurementTimingQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TrpMeasurementTimingQuality, TrpMeasurementTimingQuality_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const value_string nrppa_T_resolution_01_vals[] = {
  {   0, "deg0dot1" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resolution_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TrpMeasurementAngleQuality_sequence[] = {
  { &hf_nrppa_azimuthQuality, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_255 },
  { &hf_nrppa_zenithQuality , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_255 },
  { &hf_nrppa_resolution_01 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_resolution_01 },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TrpMeasurementAngleQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TrpMeasurementAngleQuality, TrpMeasurementAngleQuality_sequence);

  return offset;
}


static const value_string nrppa_TrpMeasurementQuality_vals[] = {
  {   0, "timingMeasQuality" },
  {   1, "angleMeasQuality" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t TrpMeasurementQuality_choice[] = {
  {   0, &hf_nrppa_timingMeasQuality, ASN1_NO_EXTENSIONS     , dissect_nrppa_TrpMeasurementTimingQuality },
  {   1, &hf_nrppa_angleMeasQuality, ASN1_NO_EXTENSIONS     , dissect_nrppa_TrpMeasurementAngleQuality },
  {   2, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TrpMeasurementQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TrpMeasurementQuality, TrpMeasurementQuality_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AdditionalPathListItem_sequence[] = {
  { &hf_nrppa_relativeTimeOfPath, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_RelativePathDelay },
  { &hf_nrppa_pathQuality   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TrpMeasurementQuality },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_AdditionalPathListItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_AdditionalPathListItem, AdditionalPathListItem_sequence);

  return offset;
}


static const per_sequence_t AdditionalPathList_sequence_of[1] = {
  { &hf_nrppa_AdditionalPathList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_AdditionalPathListItem },
};

static int
dissect_nrppa_AdditionalPathList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_AdditionalPathList, AdditionalPathList_sequence_of,
                                                  1, maxNoPath, false);

  return offset;
}


static const per_sequence_t AggregatedPosSRSResourceID_Item_sequence[] = {
  { &hf_nrppa_sRSPosResource_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSPosResourceID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_AggregatedPosSRSResourceID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_AggregatedPosSRSResourceID_Item, AggregatedPosSRSResourceID_Item_sequence);

  return offset;
}


static const per_sequence_t AggregatedPosSRSResourceID_List_sequence_of[1] = {
  { &hf_nrppa_AggregatedPosSRSResourceID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_AggregatedPosSRSResourceID_Item },
};

static int
dissect_nrppa_AggregatedPosSRSResourceID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_AggregatedPosSRSResourceID_List, AggregatedPosSRSResourceID_List_sequence_of,
                                                  2, maxnoaggregatedPosSRS_Resources, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_1_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, false);

  return offset;
}


static const per_sequence_t DL_PRS_ResourceSet_Item_sequence[] = {
  { &hf_nrppa_dl_prs_ResourceSetIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_1_8 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_DL_PRS_ResourceSet_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_DL_PRS_ResourceSet_Item, DL_PRS_ResourceSet_Item_sequence);

  return offset;
}


static const per_sequence_t DL_PRS_ResourceSet_List_sequence_of[1] = {
  { &hf_nrppa_DL_PRS_ResourceSet_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_DL_PRS_ResourceSet_Item },
};

static int
dissect_nrppa_DL_PRS_ResourceSet_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_DL_PRS_ResourceSet_List, DL_PRS_ResourceSet_List_sequence_of,
                                                  1, maxnoAggPosPRSResourceSets, false);

  return offset;
}


static const per_sequence_t AggregatedPRSResourceSet_Item_sequence[] = {
  { &hf_nrppa_dl_PRS_ResourceSet_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_DL_PRS_ResourceSet_List },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_AggregatedPRSResourceSet_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_AggregatedPRSResourceSet_Item, AggregatedPRSResourceSet_Item_sequence);

  return offset;
}


static const per_sequence_t AggregatedPRSResourceSetList_sequence_of[1] = {
  { &hf_nrppa_AggregatedPRSResourceSetList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_AggregatedPRSResourceSet_Item },
};

static int
dissect_nrppa_AggregatedPRSResourceSetList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_AggregatedPRSResourceSetList, AggregatedPRSResourceSetList_sequence_of,
                                                  1, maxnoAggCombinations, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_3599(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3599U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_1799(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1799U, NULL, false);

  return offset;
}


static const per_sequence_t LCS_to_GCS_Translation_sequence[] = {
  { &hf_nrppa_alpha         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3599 },
  { &hf_nrppa_beta          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3599 },
  { &hf_nrppa_gamma         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3599 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_LCS_to_GCS_Translation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_LCS_to_GCS_Translation, LCS_to_GCS_Translation_sequence);

  return offset;
}


static const per_sequence_t UL_AoA_sequence[] = {
  { &hf_nrppa_azimuthAoA    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3599 },
  { &hf_nrppa_zenithAoA     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_1799 },
  { &hf_nrppa_lCS_to_GCS_Translation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_LCS_to_GCS_Translation },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_UL_AoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_UL_AoA, UL_AoA_sequence);

  return offset;
}


static const per_sequence_t ZoA_sequence[] = {
  { &hf_nrppa_zenithAoA     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_1799 },
  { &hf_nrppa_lCS_to_GCS_Translation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_LCS_to_GCS_Translation },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ZoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ZoA, ZoA_sequence);

  return offset;
}


static const value_string nrppa_MultipleULAoA_Item_vals[] = {
  {   0, "uL-AoA" },
  {   1, "ul-ZoA" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t MultipleULAoA_Item_choice[] = {
  {   0, &hf_nrppa_uL_AoA        , ASN1_NO_EXTENSIONS     , dissect_nrppa_UL_AoA },
  {   1, &hf_nrppa_ul_ZoA        , ASN1_NO_EXTENSIONS     , dissect_nrppa_ZoA },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_MultipleULAoA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_MultipleULAoA_Item, MultipleULAoA_Item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MultipleULAoA_List_sequence_of[1] = {
  { &hf_nrppa_MultipleULAoA_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_MultipleULAoA_Item },
};

static int
dissect_nrppa_MultipleULAoA_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_MultipleULAoA_List, MultipleULAoA_List_sequence_of,
                                                  1, maxnoofULAoAs, false);

  return offset;
}


static const per_sequence_t MultipleULAoA_sequence[] = {
  { &hf_nrppa_multipleULAoA_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_MultipleULAoA_List },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MultipleULAoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MultipleULAoA, MultipleULAoA_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_126(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 126U, NULL, false);

  return offset;
}


static const per_sequence_t UL_SRS_RSRPP_sequence[] = {
  { &hf_nrppa_firstPathRSRPP, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_126 },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_UL_SRS_RSRPP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_UL_SRS_RSRPP, UL_SRS_RSRPP_sequence);

  return offset;
}


static const per_sequence_t ExtendedAdditionalPathList_Item_sequence[] = {
  { &hf_nrppa_relativeTimeOfPath, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_RelativePathDelay },
  { &hf_nrppa_pathQuality   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TrpMeasurementQuality },
  { &hf_nrppa_multipleULAoA , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_MultipleULAoA },
  { &hf_nrppa_pathPower     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_UL_SRS_RSRPP },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ExtendedAdditionalPathList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ExtendedAdditionalPathList_Item, ExtendedAdditionalPathList_Item_sequence);

  return offset;
}


static const per_sequence_t ExtendedAdditionalPathList_sequence_of[1] = {
  { &hf_nrppa_ExtendedAdditionalPathList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ExtendedAdditionalPathList_Item },
};

static int
dissect_nrppa_ExtendedAdditionalPathList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ExtendedAdditionalPathList, ExtendedAdditionalPathList_sequence_of,
                                                  1, maxNoPathExtended, false);

  return offset;
}



static int
dissect_nrppa_Expected_Value_AoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3599U, NULL, false);

  return offset;
}



static int
dissect_nrppa_Uncertainty_range_AoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3599U, NULL, false);

  return offset;
}


static const per_sequence_t Expected_Azimuth_AoA_sequence[] = {
  { &hf_nrppa_expected_Azimuth_AoA_value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_Expected_Value_AoA },
  { &hf_nrppa_expected_Azimuth_AoA_uncertainty, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_Uncertainty_range_AoA },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_Expected_Azimuth_AoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_Expected_Azimuth_AoA, Expected_Azimuth_AoA_sequence);

  return offset;
}



static int
dissect_nrppa_Expected_Value_ZoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1799U, NULL, false);

  return offset;
}



static int
dissect_nrppa_Uncertainty_range_ZoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1799U, NULL, false);

  return offset;
}


static const per_sequence_t Expected_Zenith_AoA_sequence[] = {
  { &hf_nrppa_expected_Zenith_AoA_value, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_Expected_Value_ZoA },
  { &hf_nrppa_expected_Zenith_AoA_uncertainty, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_Uncertainty_range_ZoA },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_Expected_Zenith_AoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_Expected_Zenith_AoA, Expected_Zenith_AoA_sequence);

  return offset;
}


static const per_sequence_t Expected_UL_AoA_sequence[] = {
  { &hf_nrppa_expected_Azimuth_AoA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_Expected_Azimuth_AoA },
  { &hf_nrppa_expected_Zenith_AoA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_Expected_Zenith_AoA },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_Expected_UL_AoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_Expected_UL_AoA, Expected_UL_AoA_sequence);

  return offset;
}


static const per_sequence_t Expected_ZoA_only_sequence[] = {
  { &hf_nrppa_expected_ZoA_only, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_Expected_Zenith_AoA },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_Expected_ZoA_only(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_Expected_ZoA_only, Expected_ZoA_only_sequence);

  return offset;
}


static const value_string nrppa_AngleMeasurementType_vals[] = {
  {   0, "expected-ULAoA" },
  {   1, "expected-ZoA" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t AngleMeasurementType_choice[] = {
  {   0, &hf_nrppa_expected_ULAoA, ASN1_NO_EXTENSIONS     , dissect_nrppa_Expected_UL_AoA },
  {   1, &hf_nrppa_expected_ZoA  , ASN1_NO_EXTENSIONS     , dissect_nrppa_Expected_ZoA_only },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_AngleMeasurementType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_AngleMeasurementType, AngleMeasurementType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AoA_AssistanceInfo_sequence[] = {
  { &hf_nrppa_angleMeasurement, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_AngleMeasurementType },
  { &hf_nrppa_lCS_to_GCS_Translation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_LCS_to_GCS_Translation },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_AoA_AssistanceInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_AoA_AssistanceInfo, AoA_AssistanceInfo_sequence);

  return offset;
}



static int
dissect_nrppa_AperiodicSRSResourceTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 3U, NULL, false);

  return offset;
}


static const per_sequence_t AperiodicSRSResourceTriggerList_sequence_of[1] = {
  { &hf_nrppa_AperiodicSRSResourceTriggerList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_AperiodicSRSResourceTrigger },
};

static int
dissect_nrppa_AperiodicSRSResourceTriggerList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_AperiodicSRSResourceTriggerList, AperiodicSRSResourceTriggerList_sequence_of,
                                                  1, maxnoSRSTriggerStates, false);

  return offset;
}



static int
dissect_nrppa_ARP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, true);

  return offset;
}


static const value_string nrppa_T_milli_Arc_SecondUnits_vals[] = {
  {   0, "zerodot03" },
  {   1, "zerodot3" },
  {   2, "three" },
  { 0, NULL }
};


static int
dissect_nrppa_T_milli_Arc_SecondUnits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_heightUnits_vals[] = {
  {   0, "mm" },
  {   1, "cm" },
  {   2, "m" },
  { 0, NULL }
};


static int
dissect_nrppa_T_heightUnits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_M1024_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1024, 1023U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_100(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, false);

  return offset;
}


static const per_sequence_t LocationUncertainty_sequence[] = {
  { &hf_nrppa_horizontalUncertainty, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_255 },
  { &hf_nrppa_horizontalConfidence, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_100 },
  { &hf_nrppa_verticalUncertainty, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_255 },
  { &hf_nrppa_verticalConfidence, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_100 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_LocationUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_LocationUncertainty, LocationUncertainty_sequence);

  return offset;
}


static const per_sequence_t RelativeGeodeticLocation_sequence[] = {
  { &hf_nrppa_milli_Arc_SecondUnits, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_milli_Arc_SecondUnits },
  { &hf_nrppa_heightUnits   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_heightUnits },
  { &hf_nrppa_deltaLatitude , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M1024_1023 },
  { &hf_nrppa_deltaLongitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M1024_1023 },
  { &hf_nrppa_deltaHeight   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M1024_1023 },
  { &hf_nrppa_locationUncertainty, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_LocationUncertainty },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_RelativeGeodeticLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_RelativeGeodeticLocation, RelativeGeodeticLocation_sequence);

  return offset;
}


static const value_string nrppa_T_xYZunit_vals[] = {
  {   0, "mm" },
  {   1, "cm" },
  {   2, "dm" },
  { 0, NULL }
};


static int
dissect_nrppa_T_xYZunit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_M65536_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -65536, 65535U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_M32768_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, false);

  return offset;
}


static const per_sequence_t RelativeCartesianLocation_sequence[] = {
  { &hf_nrppa_xYZunit       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_xYZunit },
  { &hf_nrppa_xvalue        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M65536_65535 },
  { &hf_nrppa_yvalue        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M65536_65535 },
  { &hf_nrppa_zvalue        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M32768_32767 },
  { &hf_nrppa_locationUncertainty, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_LocationUncertainty },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_RelativeCartesianLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_RelativeCartesianLocation, RelativeCartesianLocation_sequence);

  return offset;
}


static const value_string nrppa_ARPLocationType_vals[] = {
  {   0, "aRPPositionRelativeGeodetic" },
  {   1, "aRPPositionRelativeCartesian" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ARPLocationType_choice[] = {
  {   0, &hf_nrppa_aRPPositionRelativeGeodetic, ASN1_NO_EXTENSIONS     , dissect_nrppa_RelativeGeodeticLocation },
  {   1, &hf_nrppa_aRPPositionRelativeCartesian, ASN1_NO_EXTENSIONS     , dissect_nrppa_RelativeCartesianLocation },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_ARPLocationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_ARPLocationType, ARPLocationType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ARPLocationInformation_Item_sequence[] = {
  { &hf_nrppa_aRP_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ARP_ID },
  { &hf_nrppa_aRPLocationType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ARPLocationType },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ARPLocationInformation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ARPLocationInformation_Item, ARPLocationInformation_Item_sequence);

  return offset;
}


static const per_sequence_t ARPLocationInformation_sequence_of[1] = {
  { &hf_nrppa_ARPLocationInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ARPLocationInformation_Item },
};

static int
dissect_nrppa_ARPLocationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ARPLocationInformation, ARPLocationInformation_sequence_of,
                                                  1, maxnoARPs, false);

  return offset;
}


static const value_string nrppa_BroadcastPeriodicity_vals[] = {
  {   0, "ms80" },
  {   1, "ms160" },
  {   2, "ms320" },
  {   3, "ms640" },
  {   4, "ms1280" },
  {   5, "ms2560" },
  {   6, "ms5120" },
  { 0, NULL }
};


static int
dissect_nrppa_BroadcastPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_PosSIB_Type_vals[] = {
  {   0, "posSibType1-1" },
  {   1, "posSibType1-2" },
  {   2, "posSibType1-3" },
  {   3, "posSibType1-4" },
  {   4, "posSibType1-5" },
  {   5, "posSibType1-6" },
  {   6, "posSibType1-7" },
  {   7, "posSibType1-8" },
  {   8, "posSibType2-1" },
  {   9, "posSibType2-2" },
  {  10, "posSibType2-3" },
  {  11, "posSibType2-4" },
  {  12, "posSibType2-5" },
  {  13, "posSibType2-6" },
  {  14, "posSibType2-7" },
  {  15, "posSibType2-8" },
  {  16, "posSibType2-9" },
  {  17, "posSibType2-10" },
  {  18, "posSibType2-11" },
  {  19, "posSibType2-12" },
  {  20, "posSibType2-13" },
  {  21, "posSibType2-14" },
  {  22, "posSibType2-15" },
  {  23, "posSibType2-16" },
  {  24, "posSibType2-17" },
  {  25, "posSibType2-18" },
  {  26, "posSibType2-19" },
  {  27, "posSibType2-20" },
  {  28, "posSibType2-21" },
  {  29, "posSibType2-22" },
  {  30, "posSibType2-23" },
  {  31, "posSibType2-24" },
  {  32, "posSibType2-25" },
  {  33, "posSibType3-1" },
  {  34, "posSibType4-1" },
  {  35, "posSibType5-1" },
  {  36, "posSibType6-1" },
  {  37, "posSibType6-2" },
  {  38, "posSibType6-3" },
  {  39, "posSibType1-9" },
  {  40, "posSibType1-10" },
  {  41, "posSibType6-4" },
  {  42, "posSibType6-5" },
  {  43, "posSibType6-6" },
  {  44, "posSibType1-11" },
  {  45, "posSibType1-12" },
  {  46, "posSibType2-17a" },
  {  47, "posSibType2-18a" },
  {  48, "posSibType2-20a" },
  {  49, "posSibType2-26" },
  {  50, "posSibType2-27" },
  {  51, "posSibType6-7" },
  {  52, "posSibType7-1" },
  {  53, "posSibType7-2" },
  {  54, "posSibType7-3" },
  {  55, "posSibType7-4" },
  { 0, NULL }
};


static int
dissect_nrppa_PosSIB_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     39, NULL, true, 17, NULL);

  return offset;
}



static int
dissect_nrppa_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const per_sequence_t PosSIB_Segments_item_sequence[] = {
  { &hf_nrppa_assistanceDataSIBelement, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_OCTET_STRING },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PosSIB_Segments_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PosSIB_Segments_item, PosSIB_Segments_item_sequence);

  return offset;
}


static const per_sequence_t PosSIB_Segments_sequence_of[1] = {
  { &hf_nrppa_PosSIB_Segments_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSIB_Segments_item },
};

static int
dissect_nrppa_PosSIB_Segments(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PosSIB_Segments, PosSIB_Segments_sequence_of,
                                                  1, maxNrOfSegments, false);

  return offset;
}


static const value_string nrppa_T_encrypted_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_T_encrypted(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_gNSSID_vals[] = {
  {   0, "gps" },
  {   1, "sbas" },
  {   2, "qzss" },
  {   3, "galileo" },
  {   4, "glonass" },
  {   5, "bds" },
  {   6, "navic" },
  { 0, NULL }
};


static int
dissect_nrppa_T_gNSSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_sBASID_vals[] = {
  {   0, "waas" },
  {   1, "egnos" },
  {   2, "msas" },
  {   3, "gagan" },
  { 0, NULL }
};


static int
dissect_nrppa_T_sBASID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t AssistanceInformationMetaData_sequence[] = {
  { &hf_nrppa_encrypted     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_T_encrypted },
  { &hf_nrppa_gNSSID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_T_gNSSID },
  { &hf_nrppa_sBASID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_T_sBASID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_AssistanceInformationMetaData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_AssistanceInformationMetaData, AssistanceInformationMetaData_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_1_16_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, true);

  return offset;
}


static const per_sequence_t PosSIBs_item_sequence[] = {
  { &hf_nrppa_posSIB_Type   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSIB_Type },
  { &hf_nrppa_posSIB_Segments, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSIB_Segments },
  { &hf_nrppa_assistanceInformationMetaData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_AssistanceInformationMetaData },
  { &hf_nrppa_broadcastPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_1_16_ },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PosSIBs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PosSIBs_item, PosSIBs_item_sequence);

  return offset;
}


static const per_sequence_t PosSIBs_sequence_of[1] = {
  { &hf_nrppa_PosSIBs_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSIBs_item },
};

static int
dissect_nrppa_PosSIBs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PosSIBs, PosSIBs_sequence_of,
                                                  1, maxNrOfPosSIBs, false);

  return offset;
}


static const per_sequence_t SystemInformation_item_sequence[] = {
  { &hf_nrppa_broadcastPeriodicity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_BroadcastPeriodicity },
  { &hf_nrppa_posSIBs       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSIBs },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SystemInformation_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SystemInformation_item, SystemInformation_item_sequence);

  return offset;
}


static const per_sequence_t SystemInformation_sequence_of[1] = {
  { &hf_nrppa_SystemInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SystemInformation_item },
};

static int
dissect_nrppa_SystemInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SystemInformation, SystemInformation_sequence_of,
                                                  1, maxNrOfPosSImessage, false);

  return offset;
}


static const per_sequence_t Assistance_Information_sequence[] = {
  { &hf_nrppa_systemInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SystemInformation },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_Assistance_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_Assistance_Information, Assistance_Information_sequence);

  return offset;
}


static const value_string nrppa_Outcome_vals[] = {
  {   0, "failed" },
  { 0, NULL }
};


static int
dissect_nrppa_Outcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t AssistanceInformationFailureList_item_sequence[] = {
  { &hf_nrppa_posSIB_Type   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSIB_Type },
  { &hf_nrppa_outcome       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_Outcome },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_AssistanceInformationFailureList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_AssistanceInformationFailureList_item, AssistanceInformationFailureList_item_sequence);

  return offset;
}


static const per_sequence_t AssistanceInformationFailureList_sequence_of[1] = {
  { &hf_nrppa_AssistanceInformationFailureList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_AssistanceInformationFailureList_item },
};

static int
dissect_nrppa_AssistanceInformationFailureList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_AssistanceInformationFailureList, AssistanceInformationFailureList_sequence_of,
                                                  1, maxnoAssistInfoFailureListItems, false);

  return offset;
}


static const value_string nrppa_T_fR1_vals[] = {
  {   0, "mHz5" },
  {   1, "mHz10" },
  {   2, "mHz20" },
  {   3, "mHz40" },
  {   4, "mHz50" },
  {   5, "mHz80" },
  {   6, "mHz100" },
  {   7, "mHz160" },
  {   8, "mHz200" },
  { 0, NULL }
};


static int
dissect_nrppa_T_fR1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 2, NULL);

  return offset;
}


static const value_string nrppa_T_fR2_vals[] = {
  {   0, "mHz50" },
  {   1, "mHz100" },
  {   2, "mHz200" },
  {   3, "mHz400" },
  {   4, "mHz600" },
  {   5, "mhz800" },
  {   6, "mHz1600" },
  {   7, "mHz2000" },
  { 0, NULL }
};


static int
dissect_nrppa_T_fR2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 4, NULL);

  return offset;
}


static const value_string nrppa_BandwidthSRS_vals[] = {
  {   0, "fR1" },
  {   1, "fR2" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t BandwidthSRS_choice[] = {
  {   0, &hf_nrppa_fR1           , ASN1_NO_EXTENSIONS     , dissect_nrppa_T_fR1 },
  {   1, &hf_nrppa_fR2           , ASN1_NO_EXTENSIONS     , dissect_nrppa_T_fR2 },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_BandwidthSRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_BandwidthSRS, BandwidthSRS_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_Bandwidth_Aggregation_Request_Indication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_Bandwidth_Aggregation_Request_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_BCCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, true);

  return offset;
}


static const value_string nrppa_Broadcast_vals[] = {
  {   0, "start" },
  {   1, "stop" },
  { 0, NULL }
};


static int
dissect_nrppa_Broadcast(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, NULL);

  return offset;
}



static int
dissect_nrppa_EUTRACellIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_NRCellIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string nrppa_NG_RANCell_vals[] = {
  {   0, "eUTRA-CellID" },
  {   1, "nR-CellID" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t NG_RANCell_choice[] = {
  {   0, &hf_nrppa_eUTRA_CellID  , ASN1_NO_EXTENSIONS     , dissect_nrppa_EUTRACellIdentifier },
  {   1, &hf_nrppa_nR_CellID     , ASN1_NO_EXTENSIONS     , dissect_nrppa_NRCellIdentifier },
  {   2, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_NG_RANCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_NG_RANCell, NG_RANCell_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NG_RAN_CGI_sequence[] = {
  { &hf_nrppa_pLMN_Identity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PLMN_Identity },
  { &hf_nrppa_nG_RANcell    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NG_RANCell },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_NG_RAN_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_NG_RAN_CGI, NG_RAN_CGI_sequence);

  return offset;
}


static const per_sequence_t PositioningBroadcastCells_sequence_of[1] = {
  { &hf_nrppa_PositioningBroadcastCells_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_NG_RAN_CGI },
};

static int
dissect_nrppa_PositioningBroadcastCells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PositioningBroadcastCells, PositioningBroadcastCells_sequence_of,
                                                  1, maxnoBcastCell, false);

  return offset;
}



static int
dissect_nrppa_BSSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, false, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_3279165(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3279165U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_2199_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2199U, NULL, true);

  return offset;
}


static const per_sequence_t CarrierFreq_sequence[] = {
  { &hf_nrppa_pointA        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3279165 },
  { &hf_nrppa_offsetToCarrier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_2199_ },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_CarrierFreq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_CarrierFreq, CarrierFreq_sequence);

  return offset;
}


static const value_string nrppa_CauseRadioNetwork_vals[] = {
  {   0, "unspecified" },
  {   1, "requested-item-not-supported" },
  {   2, "requested-item-temporarily-not-available" },
  {   3, "serving-NG-RAN-node-changed" },
  {   4, "requested-item-not-supported-on-time" },
  { 0, NULL }
};


static int
dissect_nrppa_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 2, NULL);

  return offset;
}


static const value_string nrppa_CauseProtocol_vals[] = {
  {   0, "transfer-syntax-error" },
  {   1, "abstract-syntax-error-reject" },
  {   2, "abstract-syntax-error-ignore-and-notify" },
  {   3, "message-not-compatible-with-receiver-state" },
  {   4, "semantic-error" },
  {   5, "unspecified" },
  {   6, "abstract-syntax-error-falsely-constructed-message" },
  { 0, NULL }
};


static int
dissect_nrppa_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_CauseMisc_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};


static int
dissect_nrppa_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "protocol" },
  {   2, "misc" },
  {   3, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_nrppa_radioNetwork  , ASN1_NO_EXTENSIONS     , dissect_nrppa_CauseRadioNetwork },
  {   1, &hf_nrppa_protocol      , ASN1_NO_EXTENSIONS     , dissect_nrppa_CauseProtocol },
  {   2, &hf_nrppa_misc          , ASN1_NO_EXTENSIONS     , dissect_nrppa_CauseMisc },
  {   3, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_Cause, Cause_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_Cell_Portion_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, true);

  return offset;
}


static const per_sequence_t CGI_EUTRA_sequence[] = {
  { &hf_nrppa_pLMN_Identity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PLMN_Identity },
  { &hf_nrppa_eUTRAcellIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_EUTRACellIdentifier },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_CGI_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_CGI_EUTRA, CGI_EUTRA_sequence);

  return offset;
}


static const per_sequence_t CGI_NR_sequence[] = {
  { &hf_nrppa_pLMN_Identity , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PLMN_Identity },
  { &hf_nrppa_nRcellIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NRCellIdentifier },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_CGI_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_CGI_NR, CGI_NR_sequence);

  return offset;
}


static const value_string nrppa_CPLength_EUTRA_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_nrppa_CPLength_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_nrppa_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_nrppa_iECriticality , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_Criticality },
  { &hf_nrppa_iE_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_ID },
  { &hf_nrppa_typeOfError   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TypeOfError },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_nrppa_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_nrppa_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, false);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_nrppa_procedureCode , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProcedureCode },
  { &hf_nrppa_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TriggeringMessage },
  { &hf_nrppa_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_Criticality },
  { &hf_nrppa_nrppatransactionID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_NRPPATransactionID },
  { &hf_nrppa_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CriticalityDiagnostics_IE_List },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}


static const per_sequence_t CommonTAParameters_sequence[] = {
  { &hf_nrppa_epochTime     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_OCTET_STRING },
  { &hf_nrppa_taInfo        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_OCTET_STRING },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_CommonTAParameters(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_CommonTAParameters, CommonTAParameters_sequence);

  return offset;
}


static const value_string nrppa_DL_Bandwidth_EUTRA_vals[] = {
  {   0, "bw6" },
  {   1, "bw15" },
  {   2, "bw25" },
  {   3, "bw50" },
  {   4, "bw75" },
  {   5, "bw100" },
  { 0, NULL }
};


static int
dissect_nrppa_DL_Bandwidth_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t DL_PRS_sequence[] = {
  { &hf_nrppa_prsid         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_ID },
  { &hf_nrppa_dl_PRSResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_dl_PRSResourceID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRS_Resource_ID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_DL_PRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_DL_PRS, DL_PRS_sequence);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string nrppa_DL_PRSMutingPattern_vals[] = {
  {   0, "two" },
  {   1, "four" },
  {   2, "six" },
  {   3, "eight" },
  {   4, "sixteen" },
  {   5, "thirty-two" },
  {   6, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t DL_PRSMutingPattern_choice[] = {
  {   0, &hf_nrppa_two           , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_2 },
  {   1, &hf_nrppa_four          , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_4 },
  {   2, &hf_nrppa_six           , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_6 },
  {   3, &hf_nrppa_eight         , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_8 },
  {   4, &hf_nrppa_sixteen       , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_16 },
  {   5, &hf_nrppa_thirty_two    , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_32 },
  {   6, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_DL_PRSMutingPattern(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_DL_PRSMutingPattern, DL_PRSMutingPattern_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_DL_PRSResourceSetARPLocation_vals[] = {
  {   0, "relativeGeodeticLocation" },
  {   1, "relativeCartesianLocation" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t DL_PRSResourceSetARPLocation_choice[] = {
  {   0, &hf_nrppa_relativeGeodeticLocation, ASN1_NO_EXTENSIONS     , dissect_nrppa_RelativeGeodeticLocation },
  {   1, &hf_nrppa_relativeCartesianLocation, ASN1_NO_EXTENSIONS     , dissect_nrppa_RelativeCartesianLocation },
  {   2, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_DL_PRSResourceSetARPLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_DL_PRSResourceSetARPLocation, DL_PRSResourceSetARPLocation_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_DL_PRSResourceARPLocation_vals[] = {
  {   0, "relativeGeodeticLocation" },
  {   1, "relativeCartesianLocation" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t DL_PRSResourceARPLocation_choice[] = {
  {   0, &hf_nrppa_relativeGeodeticLocation, ASN1_NO_EXTENSIONS     , dissect_nrppa_RelativeGeodeticLocation },
  {   1, &hf_nrppa_relativeCartesianLocation, ASN1_NO_EXTENSIONS     , dissect_nrppa_RelativeCartesianLocation },
  {   2, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_DL_PRSResourceARPLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_DL_PRSResourceARPLocation, DL_PRSResourceARPLocation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DLPRSResourceARP_sequence[] = {
  { &hf_nrppa_dl_PRSResourceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_ID },
  { &hf_nrppa_dL_PRSResourceARPLocation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_DL_PRSResourceARPLocation },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_DLPRSResourceARP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_DLPRSResourceARP, DLPRSResourceARP_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceARP_sequence_of[1] = {
  { &hf_nrppa_listofDL_PRSResourceARP_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_DLPRSResourceARP },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceARP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceARP, SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceARP_sequence_of,
                                                  1, maxPRS_ResourcesPerSet, false);

  return offset;
}


static const per_sequence_t DLPRSResourceSetARP_sequence[] = {
  { &hf_nrppa_dl_PRSResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_dL_PRSResourceSetARPLocation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_DL_PRSResourceSetARPLocation },
  { &hf_nrppa_listofDL_PRSResourceARP, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceARP },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_DLPRSResourceSetARP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_DLPRSResourceSetARP, DLPRSResourceSetARP_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_DLPRSResourceSetARP_sequence_of[1] = {
  { &hf_nrppa_listofDL_PRSResourceSetARP_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_DLPRSResourceSetARP },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_DLPRSResourceSetARP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_DLPRSResourceSetARP, SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_DLPRSResourceSetARP_sequence_of,
                                                  1, maxPRS_ResourceSets, false);

  return offset;
}


static const per_sequence_t DLPRSResourceCoordinates_sequence[] = {
  { &hf_nrppa_listofDL_PRSResourceSetARP, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_DLPRSResourceSetARP },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_DLPRSResourceCoordinates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_DLPRSResourceCoordinates, DLPRSResourceCoordinates_sequence);

  return offset;
}



static int
dissect_nrppa_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb = NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       3, 3, false, &parameter_tvb);

  if (parameter_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, parameter_tvb, 0, 3, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const value_string nrppa_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_nrppa_T_latitudeSign(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, false);

  return offset;
}


static const value_string nrppa_T_directionOfAltitude_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_nrppa_T_directionOfAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_179(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 179U, NULL, false);

  return offset;
}


static const per_sequence_t NG_RANAccessPointPosition_sequence[] = {
  { &hf_nrppa_latitudeSign  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_latitudeSign },
  { &hf_nrppa_latitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_8388607 },
  { &hf_nrppa_longitude     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M8388608_8388607 },
  { &hf_nrppa_directionOfAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_directionOfAltitude },
  { &hf_nrppa_altitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_32767 },
  { &hf_nrppa_uncertaintySemi_major, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_127 },
  { &hf_nrppa_uncertaintySemi_minor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_127 },
  { &hf_nrppa_orientationOfMajorAxis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_179 },
  { &hf_nrppa_uncertaintyAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_127 },
  { &hf_nrppa_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_100 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_NG_RANAccessPointPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_NG_RANAccessPointPosition, NG_RANAccessPointPosition_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_719(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 719U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_7690(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7690U, NULL, false);

  return offset;
}



static int
dissect_nrppa_PCI_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, true);

  return offset;
}



static int
dissect_nrppa_EARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, true);

  return offset;
}



static int
dissect_nrppa_ValueRSRP_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, true);

  return offset;
}


static const per_sequence_t ResultRSRP_EUTRA_Item_sequence[] = {
  { &hf_nrppa_pCI_EUTRA     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PCI_EUTRA },
  { &hf_nrppa_eARFCN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_EARFCN },
  { &hf_nrppa_cGI_EUTRA     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CGI_EUTRA },
  { &hf_nrppa_valueRSRP_EUTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ValueRSRP_EUTRA },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultRSRP_EUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultRSRP_EUTRA_Item, ResultRSRP_EUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t ResultRSRP_EUTRA_sequence_of[1] = {
  { &hf_nrppa_ResultRSRP_EUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultRSRP_EUTRA_Item },
};

static int
dissect_nrppa_ResultRSRP_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultRSRP_EUTRA, ResultRSRP_EUTRA_sequence_of,
                                                  1, maxCellReport, false);

  return offset;
}



static int
dissect_nrppa_ValueRSRQ_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, true);

  return offset;
}


static const per_sequence_t ResultRSRQ_EUTRA_Item_sequence[] = {
  { &hf_nrppa_pCI_EUTRA     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PCI_EUTRA },
  { &hf_nrppa_eARFCN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_EARFCN },
  { &hf_nrppa_cGI_UTRA      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CGI_EUTRA },
  { &hf_nrppa_valueRSRQ_EUTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ValueRSRQ_EUTRA },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultRSRQ_EUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultRSRQ_EUTRA_Item, ResultRSRQ_EUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t ResultRSRQ_EUTRA_sequence_of[1] = {
  { &hf_nrppa_ResultRSRQ_EUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultRSRQ_EUTRA_Item },
};

static int
dissect_nrppa_ResultRSRQ_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultRSRQ_EUTRA, ResultRSRQ_EUTRA_sequence_of,
                                                  1, maxCellReport, false);

  return offset;
}


static const value_string nrppa_MeasuredResultsValue_vals[] = {
  {   0, "valueAngleOfArrival-EUTRA" },
  {   1, "valueTimingAdvanceType1-EUTRA" },
  {   2, "valueTimingAdvanceType2-EUTRA" },
  {   3, "resultRSRP-EUTRA" },
  {   4, "resultRSRQ-EUTRA" },
  {   5, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t MeasuredResultsValue_choice[] = {
  {   0, &hf_nrppa_valueAngleOfArrival_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_719 },
  {   1, &hf_nrppa_valueTimingAdvanceType1_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_7690 },
  {   2, &hf_nrppa_valueTimingAdvanceType2_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_7690 },
  {   3, &hf_nrppa_resultRSRP_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_ResultRSRP_EUTRA },
  {   4, &hf_nrppa_resultRSRQ_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_ResultRSRQ_EUTRA },
  {   5, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_MeasuredResultsValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_MeasuredResultsValue, MeasuredResultsValue_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasuredResults_sequence_of[1] = {
  { &hf_nrppa_MeasuredResults_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_MeasuredResultsValue },
};

static int
dissect_nrppa_MeasuredResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_MeasuredResults, MeasuredResults_sequence_of,
                                                  1, maxNoMeas, false);

  return offset;
}


static const per_sequence_t E_CID_MeasurementResult_sequence[] = {
  { &hf_nrppa_servingCell_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NG_RAN_CGI },
  { &hf_nrppa_servingCellTAC, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TAC },
  { &hf_nrppa_nG_RANAccessPointPosition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_NG_RANAccessPointPosition },
  { &hf_nrppa_measuredResults, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_MeasuredResults },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_E_CID_MeasurementResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_E_CID_MeasurementResult, E_CID_MeasurementResult_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_M2147483648_2147483647(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            INT32_MIN, 2147483647U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_M64000_1280000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -64000, 1280000U, NULL, false);

  return offset;
}


static const per_sequence_t NGRANHighAccuracyAccessPointPosition_sequence[] = {
  { &hf_nrppa_latitude_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M2147483648_2147483647 },
  { &hf_nrppa_longitude_01  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M2147483648_2147483647 },
  { &hf_nrppa_altitude_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M64000_1280000 },
  { &hf_nrppa_uncertaintySemi_major_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_255 },
  { &hf_nrppa_uncertaintySemi_minor_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_255 },
  { &hf_nrppa_orientationOfMajorAxis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_179 },
  { &hf_nrppa_horizontalConfidence, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_100 },
  { &hf_nrppa_uncertaintyAltitude_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_255 },
  { &hf_nrppa_verticalConfidence, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_100 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_NGRANHighAccuracyAccessPointPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_NGRANHighAccuracyAccessPointPosition, NGRANHighAccuracyAccessPointPosition_sequence);

  return offset;
}


static const value_string nrppa_TRPPositionDirectAccuracy_vals[] = {
  {   0, "tRPPosition" },
  {   1, "tRPHAposition" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TRPPositionDirectAccuracy_choice[] = {
  {   0, &hf_nrppa_tRPPosition   , ASN1_NO_EXTENSIONS     , dissect_nrppa_NG_RANAccessPointPosition },
  {   1, &hf_nrppa_tRPHAposition , ASN1_NO_EXTENSIONS     , dissect_nrppa_NGRANHighAccuracyAccessPointPosition },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TRPPositionDirectAccuracy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TRPPositionDirectAccuracy, TRPPositionDirectAccuracy_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TRPPositionDirect_sequence[] = {
  { &hf_nrppa_accuracy      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPPositionDirectAccuracy },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPPositionDirect(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPPositionDirect, TRPPositionDirect_sequence);

  return offset;
}



static int
dissect_nrppa_CoordinateID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, true);

  return offset;
}


static const value_string nrppa_ReferencePoint_vals[] = {
  {   0, "relativeCoordinateID" },
  {   1, "referencePointCoordinate" },
  {   2, "referencePointCoordinateHA" },
  {   3, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t ReferencePoint_choice[] = {
  {   0, &hf_nrppa_relativeCoordinateID, ASN1_NO_EXTENSIONS     , dissect_nrppa_CoordinateID },
  {   1, &hf_nrppa_referencePointCoordinate, ASN1_NO_EXTENSIONS     , dissect_nrppa_NG_RANAccessPointPosition },
  {   2, &hf_nrppa_referencePointCoordinateHA, ASN1_NO_EXTENSIONS     , dissect_nrppa_NGRANHighAccuracyAccessPointPosition },
  {   3, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_ReferencePoint(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_ReferencePoint, ReferencePoint_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_TRPReferencePointType_vals[] = {
  {   0, "tRPPositionRelativeGeodetic" },
  {   1, "tRPPositionRelativeCartesian" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TRPReferencePointType_choice[] = {
  {   0, &hf_nrppa_tRPPositionRelativeGeodetic, ASN1_NO_EXTENSIONS     , dissect_nrppa_RelativeGeodeticLocation },
  {   1, &hf_nrppa_tRPPositionRelativeCartesian, ASN1_NO_EXTENSIONS     , dissect_nrppa_RelativeCartesianLocation },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TRPReferencePointType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TRPReferencePointType, TRPReferencePointType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TRPPositionReferenced_sequence[] = {
  { &hf_nrppa_referencePoint, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ReferencePoint },
  { &hf_nrppa_referencePointType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPReferencePointType },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPPositionReferenced(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPPositionReferenced, TRPPositionReferenced_sequence);

  return offset;
}


static const value_string nrppa_TRPPositionDefinitionType_vals[] = {
  {   0, "direct" },
  {   1, "referenced" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TRPPositionDefinitionType_choice[] = {
  {   0, &hf_nrppa_direct        , ASN1_NO_EXTENSIONS     , dissect_nrppa_TRPPositionDirect },
  {   1, &hf_nrppa_referenced    , ASN1_NO_EXTENSIONS     , dissect_nrppa_TRPPositionReferenced },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TRPPositionDefinitionType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TRPPositionDefinitionType, TRPPositionDefinitionType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GeographicalCoordinates_sequence[] = {
  { &hf_nrppa_tRPPositionDefinitionType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPPositionDefinitionType },
  { &hf_nrppa_dLPRSResourceCoordinates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_DLPRSResourceCoordinates },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_GeographicalCoordinates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_GeographicalCoordinates, GeographicalCoordinates_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_1970049(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1970049U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_985025(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 985025U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_492513(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 492513U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_246257(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 246257U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_123129(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 123129U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_61565(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 61565U, NULL, false);

  return offset;
}


static const value_string nrppa_GNBRxTxTimeDiffMeas_vals[] = {
  {   0, "k0" },
  {   1, "k1" },
  {   2, "k2" },
  {   3, "k3" },
  {   4, "k4" },
  {   5, "k5" },
  {   6, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t GNBRxTxTimeDiffMeas_choice[] = {
  {   0, &hf_nrppa_k0            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_1970049 },
  {   1, &hf_nrppa_k1            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_985025 },
  {   2, &hf_nrppa_k2            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_492513 },
  {   3, &hf_nrppa_k3            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_246257 },
  {   4, &hf_nrppa_k4            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_123129 },
  {   5, &hf_nrppa_k5            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_61565 },
  {   6, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_GNBRxTxTimeDiffMeas(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_GNBRxTxTimeDiffMeas, GNBRxTxTimeDiffMeas_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GNB_RxTxTimeDiff_sequence[] = {
  { &hf_nrppa_rxTxTimeDiff  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_GNBRxTxTimeDiffMeas },
  { &hf_nrppa_additionalPathList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_AdditionalPathList },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_GNB_RxTxTimeDiff(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_GNB_RxTxTimeDiff, GNB_RxTxTimeDiff_sequence);

  return offset;
}



static int
dissect_nrppa_HESSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, false, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_359(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 359U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, false);

  return offset;
}


static const per_sequence_t LCS_to_GCS_TranslationItem_sequence[] = {
  { &hf_nrppa_alpha_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_359 },
  { &hf_nrppa_alphaFine     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_9 },
  { &hf_nrppa_beta_01       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_359 },
  { &hf_nrppa_betaFine      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_9 },
  { &hf_nrppa_gamma_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_359 },
  { &hf_nrppa_gammaFine     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_9 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_LCS_to_GCS_TranslationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_LCS_to_GCS_TranslationItem, LCS_to_GCS_TranslationItem_sequence);

  return offset;
}


static const value_string nrppa_LoS_NLoSIndicatorHard_vals[] = {
  {   0, "nlos" },
  {   1, "los" },
  { 0, NULL }
};


static int
dissect_nrppa_LoS_NLoSIndicatorHard(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_nrppa_LoS_NLoSIndicatorSoft(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10U, NULL, false);

  return offset;
}


static const value_string nrppa_LoS_NLoSInformation_vals[] = {
  {   0, "loS-NLoSIndicatorSoft" },
  {   1, "loS-NLoSIndicatorHard" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t LoS_NLoSInformation_choice[] = {
  {   0, &hf_nrppa_loS_NLoSIndicatorSoft, ASN1_NO_EXTENSIONS     , dissect_nrppa_LoS_NLoSIndicatorSoft },
  {   1, &hf_nrppa_loS_NLoSIndicatorHard, ASN1_NO_EXTENSIONS     , dissect_nrppa_LoS_NLoSIndicatorHard },
  {   2, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_LoS_NLoSInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_LoS_NLoSInformation, LoS_NLoSInformation_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_MeasBasedOnAggregatedResources_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_MeasBasedOnAggregatedResources(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_Measurement_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65536U, NULL, true);

  return offset;
}


static const value_string nrppa_MeasurementAmount_vals[] = {
  {   0, "ma0" },
  {   1, "ma1" },
  {   2, "ma2" },
  {   3, "ma4" },
  {   4, "ma8" },
  {   5, "ma16" },
  {   6, "ma32" },
  {   7, "ma64" },
  { 0, NULL }
};


static int
dissect_nrppa_MeasurementAmount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, false, 0, NULL);

  return offset;
}


static const value_string nrppa_MeasurementBeamInfoRequest_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_MeasurementBeamInfoRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MeasurementBeamInfo_sequence[] = {
  { &hf_nrppa_pRS_Resource_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRS_Resource_ID },
  { &hf_nrppa_pRS_Resource_Set_ID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_sSB_Index     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SSB_Index },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementBeamInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementBeamInfo, MeasurementBeamInfo_sequence);

  return offset;
}


static const value_string nrppa_MeasurementPeriodicity_vals[] = {
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
  {  13, "ms20480" },
  {  14, "ms40960" },
  {  15, "extended" },
  { 0, NULL }
};


static int
dissect_nrppa_MeasurementPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, true, 3, NULL);

  return offset;
}


static const value_string nrppa_MeasurementPeriodicityExtended_vals[] = {
  {   0, "ms160" },
  {   1, "ms320" },
  {   2, "ms1280" },
  {   3, "ms2560" },
  {   4, "ms61440" },
  {   5, "ms81920" },
  {   6, "ms368640" },
  {   7, "ms737280" },
  {   8, "ms1843200" },
  { 0, NULL }
};


static int
dissect_nrppa_MeasurementPeriodicityExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     9, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_MeasurementPeriodicityNR_AoA_vals[] = {
  {   0, "ms160" },
  {   1, "ms320" },
  {   2, "ms640" },
  {   3, "ms1280" },
  {   4, "ms2560" },
  {   5, "ms5120" },
  {   6, "ms10240" },
  {   7, "ms20480" },
  {   8, "ms40960" },
  {   9, "ms61440" },
  {  10, "ms81920" },
  {  11, "ms368640" },
  {  12, "ms737280" },
  {  13, "ms1843200" },
  { 0, NULL }
};


static int
dissect_nrppa_MeasurementPeriodicityNR_AoA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t MeasurementQuantities_sequence_of[1] = {
  { &hf_nrppa_MeasurementQuantities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Single_Container },
};

static int
dissect_nrppa_MeasurementQuantities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_MeasurementQuantities, MeasurementQuantities_sequence_of,
                                                  1, maxNoMeas, false);

  return offset;
}


static const value_string nrppa_MeasurementQuantitiesValue_vals[] = {
  {   0, "cell-ID" },
  {   1, "angleOfArrival" },
  {   2, "timingAdvanceType1" },
  {   3, "timingAdvanceType2" },
  {   4, "rSRP" },
  {   5, "rSRQ" },
  {   6, "sS-RSRP" },
  {   7, "sS-RSRQ" },
  {   8, "cSI-RSRP" },
  {   9, "cSI-RSRQ" },
  {  10, "angleOfArrivalNR" },
  {  11, "timingAdvanceNR" },
  {  12, "uE-Rx-Tx-Time-Diff" },
  { 0, NULL }
};


static int
dissect_nrppa_MeasurementQuantitiesValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 7, NULL);

  return offset;
}


static const per_sequence_t MeasurementQuantities_Item_sequence[] = {
  { &hf_nrppa_measurementQuantitiesValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_MeasurementQuantitiesValue },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementQuantities_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementQuantities_Item, MeasurementQuantities_Item_sequence);

  return offset;
}


static const value_string nrppa_MeasurementTimeOccasion_vals[] = {
  {   0, "o1" },
  {   1, "o4" },
  { 0, NULL }
};


static int
dissect_nrppa_MeasurementTimeOccasion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_MeasurementCharacteristicsRequestIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_SystemFrameNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 19U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_39(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 39U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_79(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 79U, NULL, false);

  return offset;
}


static const value_string nrppa_TimeStampSlotIndex_vals[] = {
  {   0, "sCS-15" },
  {   1, "sCS-30" },
  {   2, "sCS-60" },
  {   3, "sCS-120" },
  {   4, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TimeStampSlotIndex_choice[] = {
  {   0, &hf_nrppa_sCS_15        , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_9 },
  {   1, &hf_nrppa_sCS_30        , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_19 },
  {   2, &hf_nrppa_sCS_60        , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_39 },
  {   3, &hf_nrppa_sCS_120       , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_79 },
  {   4, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TimeStampSlotIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TimeStampSlotIndex, TimeStampSlotIndex_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_RelativeTime1900(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t TimeStamp_sequence[] = {
  { &hf_nrppa_systemFrameNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SystemFrameNumber },
  { &hf_nrppa_slotIndex     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TimeStampSlotIndex },
  { &hf_nrppa_measurementTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_RelativeTime1900 },
  { &hf_nrppa_iE_Extension  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TimeStamp, TimeStamp_sequence);

  return offset;
}


static const per_sequence_t MeasuredResultsAssociatedInfoItem_sequence[] = {
  { &hf_nrppa_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TimeStamp },
  { &hf_nrppa_measurementQuality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TrpMeasurementQuality },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasuredResultsAssociatedInfoItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasuredResultsAssociatedInfoItem, MeasuredResultsAssociatedInfoItem_sequence);

  return offset;
}


static const per_sequence_t MeasuredResultsAssociatedInfoList_sequence_of[1] = {
  { &hf_nrppa_MeasuredResultsAssociatedInfoList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_MeasuredResultsAssociatedInfoItem },
};

static int
dissect_nrppa_MeasuredResultsAssociatedInfoList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_MeasuredResultsAssociatedInfoList, MeasuredResultsAssociatedInfoList_sequence_of,
                                                  1, maxNoMeas, false);

  return offset;
}


static const per_sequence_t Mobile_TRP_LocationInformation_sequence[] = {
  { &hf_nrppa_location_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_OCTET_STRING },
  { &hf_nrppa_velocity_Information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_OCTET_STRING },
  { &hf_nrppa_location_time_stamp, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TimeStamp },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_Mobile_TRP_LocationInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_Mobile_TRP_LocationInformation, Mobile_TRP_LocationInformation_sequence);

  return offset;
}



static int
dissect_nrppa_Mobile_IAB_MT_UE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}


static const value_string nrppa_MeasuredFrequencyHops_vals[] = {
  {   0, "singleHop" },
  {   1, "multiHop" },
  { 0, NULL }
};


static int
dissect_nrppa_MeasuredFrequencyHops(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_NarrowBandIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, true);

  return offset;
}



static int
dissect_nrppa_NR_ARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3279165U, NULL, false);

  return offset;
}


static const value_string nrppa_NrofSymbolsExtended_vals[] = {
  {   0, "n8" },
  {   1, "n10" },
  {   2, "n12" },
  {   3, "n14" },
  { 0, NULL }
};


static int
dissect_nrppa_NrofSymbolsExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_NR_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_180(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 180U, NULL, false);

  return offset;
}


static const per_sequence_t PRSAngleItem_sequence[] = {
  { &hf_nrppa_nRPRSAzimuth  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_359 },
  { &hf_nrppa_nRPRSAzimuthFine, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_9 },
  { &hf_nrppa_nRPRSElevation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_180 },
  { &hf_nrppa_nRPRSElevationFine, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_9 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSAngleItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSAngleItem, PRSAngleItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_PRSAngleItem_sequence_of[1] = {
  { &hf_nrppa_pRSAngle_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSAngleItem },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_PRSAngleItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_PRSAngleItem, SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_PRSAngleItem_sequence_of,
                                                  1, maxPRS_ResourcesPerSet, false);

  return offset;
}


static const per_sequence_t NR_PRS_Beam_InformationItem_sequence[] = {
  { &hf_nrppa_pRSresourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_pRSAngle      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_PRSAngleItem },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_NR_PRS_Beam_InformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_NR_PRS_Beam_InformationItem, NR_PRS_Beam_InformationItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_NR_PRS_Beam_InformationItem_sequence_of[1] = {
  { &hf_nrppa_nR_PRS_Beam_InformationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_PRS_Beam_InformationItem },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_NR_PRS_Beam_InformationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_NR_PRS_Beam_InformationItem, SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_NR_PRS_Beam_InformationItem_sequence_of,
                                                  1, maxPRS_ResourceSets, false);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnolcs_gcs_translation_OF_LCS_to_GCS_TranslationItem_sequence_of[1] = {
  { &hf_nrppa_lCS_to_GCS_TranslationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_LCS_to_GCS_TranslationItem },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxnolcs_gcs_translation_OF_LCS_to_GCS_TranslationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxnolcs_gcs_translation_OF_LCS_to_GCS_TranslationItem, SEQUENCE_SIZE_1_maxnolcs_gcs_translation_OF_LCS_to_GCS_TranslationItem_sequence_of,
                                                  1, maxnolcs_gcs_translation, false);

  return offset;
}


static const per_sequence_t NR_PRS_Beam_Information_sequence[] = {
  { &hf_nrppa_nR_PRS_Beam_InformationList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_NR_PRS_Beam_InformationItem },
  { &hf_nrppa_lCS_to_GCS_TranslationList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SEQUENCE_SIZE_1_maxnolcs_gcs_translation_OF_LCS_to_GCS_TranslationItem },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_NR_PRS_Beam_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_NR_PRS_Beam_Information, NR_PRS_Beam_Information_sequence);

  return offset;
}



static int
dissect_nrppa_NR_TADV(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7690U, NULL, false);

  return offset;
}


static const value_string nrppa_NumberOfAntennaPorts_EUTRA_vals[] = {
  {   0, "n1-or-n2" },
  {   1, "n4" },
  { 0, NULL }
};


static int
dissect_nrppa_NumberOfAntennaPorts_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_NumberOfDlFrames_EUTRA_vals[] = {
  {   0, "sf1" },
  {   1, "sf2" },
  {   2, "sf4" },
  {   3, "sf6" },
  { 0, NULL }
};


static int
dissect_nrppa_NumberOfDlFrames_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_NumberOfDlFrames_Extended_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 160U, NULL, true);

  return offset;
}


static const value_string nrppa_NumberOfFrequencyHoppingBands_vals[] = {
  {   0, "twobands" },
  {   1, "fourbands" },
  { 0, NULL }
};


static int
dissect_nrppa_NumberOfFrequencyHoppingBands(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_NumberOfTRPRxTEG_vals[] = {
  {   0, "two" },
  {   1, "three" },
  {   2, "four" },
  {   3, "six" },
  {   4, "eight" },
  { 0, NULL }
};


static int
dissect_nrppa_NumberOfTRPRxTEG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_NumberOfTRPRxTxTEG_vals[] = {
  {   0, "two" },
  {   1, "three" },
  {   2, "four" },
  {   3, "six" },
  {   4, "eight" },
  { 0, NULL }
};


static int
dissect_nrppa_NumberOfTRPRxTxTEG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_NZP_CSI_RS_ResourceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 191U, NULL, false);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t OnDemandPRS_Info_sequence[] = {
  { &hf_nrppa_onDemandPRSRequestAllowed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_BIT_STRING_SIZE_16 },
  { &hf_nrppa_allowedResourceSetPeriodicityValues, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_BIT_STRING_SIZE_24 },
  { &hf_nrppa_allowedPRSBandwidthValues, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_BIT_STRING_SIZE_64 },
  { &hf_nrppa_allowedResourceRepetitionFactorValues, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_BIT_STRING_SIZE_8 },
  { &hf_nrppa_allowedResourceNumberOfSymbolsValues, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_BIT_STRING_SIZE_8 },
  { &hf_nrppa_allowedCombSizeValues, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_BIT_STRING_SIZE_8 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_OnDemandPRS_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_OnDemandPRS_Info, OnDemandPRS_Info_sequence);

  return offset;
}


static const value_string nrppa_PRS_Bandwidth_EUTRA_vals[] = {
  {   0, "bw6" },
  {   1, "bw15" },
  {   2, "bw25" },
  {   3, "bw50" },
  {   4, "bw75" },
  {   5, "bw100" },
  { 0, NULL }
};


static int
dissect_nrppa_PRS_Bandwidth_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_PRS_ConfigurationIndex_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, true);

  return offset;
}



static int
dissect_nrppa_SFNInitialisationTime_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_512(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     512, 512, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_1024(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1024, 1024, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string nrppa_PRSMutingConfiguration_EUTRA_vals[] = {
  {   0, "two" },
  {   1, "four" },
  {   2, "eight" },
  {   3, "sixteen" },
  {   4, "thirty-two" },
  {   5, "sixty-four" },
  {   6, "one-hundred-and-twenty-eight" },
  {   7, "two-hundred-and-fifty-six" },
  {   8, "five-hundred-and-twelve" },
  {   9, "one-thousand-and-twenty-four" },
  {  10, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t PRSMutingConfiguration_EUTRA_choice[] = {
  {   0, &hf_nrppa_two           , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_2 },
  {   1, &hf_nrppa_four          , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_4 },
  {   2, &hf_nrppa_eight         , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_8 },
  {   3, &hf_nrppa_sixteen       , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_16 },
  {   4, &hf_nrppa_thirty_two    , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_32 },
  {   5, &hf_nrppa_sixty_four    , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_64 },
  {   6, &hf_nrppa_one_hundred_and_twenty_eight, ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_128 },
  {   7, &hf_nrppa_two_hundred_and_fifty_six, ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_256 },
  {   8, &hf_nrppa_five_hundred_and_twelve, ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_512 },
  {   9, &hf_nrppa_one_thousand_and_twenty_four, ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_1024 },
  {  10, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_PRSMutingConfiguration_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_PRSMutingConfiguration_EUTRA, PRSMutingConfiguration_EUTRA_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_PRS_ID_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, true);

  return offset;
}



static int
dissect_nrppa_TP_ID_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, true);

  return offset;
}


static const value_string nrppa_TP_Type_EUTRA_vals[] = {
  {   0, "prs-only-tp" },
  { 0, NULL }
};


static int
dissect_nrppa_TP_Type_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_PRSOccasionGroup_EUTRA_vals[] = {
  {   0, "og2" },
  {   1, "og4" },
  {   2, "og8" },
  {   3, "og16" },
  {   4, "og32" },
  {   5, "og64" },
  {   6, "og128" },
  { 0, NULL }
};


static int
dissect_nrppa_PRSOccasionGroup_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex_sequence_of[1] = {
  { &hf_nrppa_bandPositions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_NarrowBandIndex },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex, SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex_sequence_of,
                                                  1, maxnoFreqHoppingBandsMinusOne, false);

  return offset;
}


static const per_sequence_t PRSFrequencyHoppingConfiguration_EUTRA_sequence[] = {
  { &hf_nrppa_noOfFreqHoppingBands, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NumberOfFrequencyHoppingBands },
  { &hf_nrppa_bandPositions , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSFrequencyHoppingConfiguration_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSFrequencyHoppingConfiguration_EUTRA, PRSFrequencyHoppingConfiguration_EUTRA_sequence);

  return offset;
}


static const value_string nrppa_OTDOACell_Information_Item_vals[] = {
  {   0, "pCI-EUTRA" },
  {   1, "cGI-EUTRA" },
  {   2, "tAC" },
  {   3, "eARFCN" },
  {   4, "pRS-Bandwidth-EUTRA" },
  {   5, "pRS-ConfigurationIndex-EUTRA" },
  {   6, "cPLength-EUTRA" },
  {   7, "numberOfDlFrames-EUTRA" },
  {   8, "numberOfAntennaPorts-EUTRA" },
  {   9, "sFNInitialisationTime-EUTRA" },
  {  10, "nG-RANAccessPointPosition" },
  {  11, "pRSMutingConfiguration-EUTRA" },
  {  12, "prsid-EUTRA" },
  {  13, "tpid-EUTRA" },
  {  14, "tpType-EUTRA" },
  {  15, "numberOfDlFrames-Extended-EUTRA" },
  {  16, "crsCPlength-EUTRA" },
  {  17, "dL-Bandwidth-EUTRA" },
  {  18, "pRSOccasionGroup-EUTRA" },
  {  19, "pRSFrequencyHoppingConfiguration-EUTRA" },
  {  20, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t OTDOACell_Information_Item_choice[] = {
  {   0, &hf_nrppa_pCI_EUTRA     , ASN1_NO_EXTENSIONS     , dissect_nrppa_PCI_EUTRA },
  {   1, &hf_nrppa_cGI_EUTRA     , ASN1_NO_EXTENSIONS     , dissect_nrppa_CGI_EUTRA },
  {   2, &hf_nrppa_tAC           , ASN1_NO_EXTENSIONS     , dissect_nrppa_TAC },
  {   3, &hf_nrppa_eARFCN        , ASN1_NO_EXTENSIONS     , dissect_nrppa_EARFCN },
  {   4, &hf_nrppa_pRS_Bandwidth_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_PRS_Bandwidth_EUTRA },
  {   5, &hf_nrppa_pRS_ConfigurationIndex_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_PRS_ConfigurationIndex_EUTRA },
  {   6, &hf_nrppa_cPLength_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_CPLength_EUTRA },
  {   7, &hf_nrppa_numberOfDlFrames_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_NumberOfDlFrames_EUTRA },
  {   8, &hf_nrppa_numberOfAntennaPorts_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_NumberOfAntennaPorts_EUTRA },
  {   9, &hf_nrppa_sFNInitialisationTime_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_SFNInitialisationTime_EUTRA },
  {  10, &hf_nrppa_nG_RANAccessPointPosition, ASN1_NO_EXTENSIONS     , dissect_nrppa_NG_RANAccessPointPosition },
  {  11, &hf_nrppa_pRSMutingConfiguration_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_PRSMutingConfiguration_EUTRA },
  {  12, &hf_nrppa_prsid_EUTRA   , ASN1_NO_EXTENSIONS     , dissect_nrppa_PRS_ID_EUTRA },
  {  13, &hf_nrppa_tpid_EUTRA    , ASN1_NO_EXTENSIONS     , dissect_nrppa_TP_ID_EUTRA },
  {  14, &hf_nrppa_tpType_EUTRA  , ASN1_NO_EXTENSIONS     , dissect_nrppa_TP_Type_EUTRA },
  {  15, &hf_nrppa_numberOfDlFrames_Extended_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_NumberOfDlFrames_Extended_EUTRA },
  {  16, &hf_nrppa_crsCPlength_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_CPLength_EUTRA },
  {  17, &hf_nrppa_dL_Bandwidth_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_DL_Bandwidth_EUTRA },
  {  18, &hf_nrppa_pRSOccasionGroup_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_PRSOccasionGroup_EUTRA },
  {  19, &hf_nrppa_pRSFrequencyHoppingConfiguration_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_PRSFrequencyHoppingConfiguration_EUTRA },
  {  20, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_OTDOACell_Information_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_OTDOACell_Information_Item, OTDOACell_Information_Item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t OTDOACell_Information_sequence_of[1] = {
  { &hf_nrppa_OTDOACell_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_OTDOACell_Information_Item },
};

static int
dissect_nrppa_OTDOACell_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_OTDOACell_Information, OTDOACell_Information_sequence_of,
                                                  1, maxnoOTDOAtypes, false);

  return offset;
}


static const per_sequence_t OTDOACells_item_sequence[] = {
  { &hf_nrppa_oTDOACellInfo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_OTDOACell_Information },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_OTDOACells_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_OTDOACells_item, OTDOACells_item_sequence);

  return offset;
}


static const per_sequence_t OTDOACells_sequence_of[1] = {
  { &hf_nrppa_OTDOACells_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_OTDOACells_item },
};

static int
dissect_nrppa_OTDOACells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_OTDOACells, OTDOACells_sequence_of,
                                                  1, maxCellinRANnode, false);

  return offset;
}


static const value_string nrppa_OTDOA_Information_Item_vals[] = {
  {   0, "pci" },
  {   1, "cGI" },
  {   2, "tac" },
  {   3, "earfcn" },
  {   4, "prsBandwidth" },
  {   5, "prsConfigIndex" },
  {   6, "cpLength" },
  {   7, "noDlFrames" },
  {   8, "noAntennaPorts" },
  {   9, "sFNInitTime" },
  {  10, "nG-RANAccessPointPosition" },
  {  11, "prsmutingconfiguration" },
  {  12, "prsid" },
  {  13, "tpid" },
  {  14, "tpType" },
  {  15, "crsCPlength" },
  {  16, "dlBandwidth" },
  {  17, "multipleprsConfigurationsperCell" },
  {  18, "prsOccasionGroup" },
  {  19, "prsFrequencyHoppingConfiguration" },
  {  20, "tddConfig" },
  { 0, NULL }
};


static int
dissect_nrppa_OTDOA_Information_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, true, 1, NULL);

  return offset;
}


static const per_sequence_t OtherRATMeasurementQuantities_sequence_of[1] = {
  { &hf_nrppa_OtherRATMeasurementQuantities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Single_Container },
};

static int
dissect_nrppa_OtherRATMeasurementQuantities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_OtherRATMeasurementQuantities, OtherRATMeasurementQuantities_sequence_of,
                                                  0, maxNoMeas, false);

  return offset;
}


static const value_string nrppa_OtherRATMeasurementQuantitiesValue_vals[] = {
  {   0, "geran" },
  {   1, "utran" },
  {   2, "nR" },
  {   3, "eUTRA" },
  { 0, NULL }
};


static int
dissect_nrppa_OtherRATMeasurementQuantitiesValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 2, NULL);

  return offset;
}


static const per_sequence_t OtherRATMeasurementQuantities_Item_sequence[] = {
  { &hf_nrppa_otherRATMeasurementQuantitiesValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_OtherRATMeasurementQuantitiesValue },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_OtherRATMeasurementQuantities_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_OtherRATMeasurementQuantities_Item, OtherRATMeasurementQuantities_Item_sequence);

  return offset;
}



static int
dissect_nrppa_PhysCellIDGERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, true);

  return offset;
}



static int
dissect_nrppa_RSSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, true);

  return offset;
}


static const per_sequence_t ResultGERAN_Item_sequence[] = {
  { &hf_nrppa_bCCH          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_BCCH },
  { &hf_nrppa_physCellIDGERAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PhysCellIDGERAN },
  { &hf_nrppa_rSSI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_RSSI },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultGERAN_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultGERAN_Item, ResultGERAN_Item_sequence);

  return offset;
}


static const per_sequence_t ResultGERAN_sequence_of[1] = {
  { &hf_nrppa_ResultGERAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultGERAN_Item },
};

static int
dissect_nrppa_ResultGERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultGERAN, ResultGERAN_sequence_of,
                                                  1, maxGERANMeas, false);

  return offset;
}



static int
dissect_nrppa_UARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, true);

  return offset;
}



static int
dissect_nrppa_PhysCellIDUTRA_FDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, true);

  return offset;
}



static int
dissect_nrppa_PhysCellIDUTRA_TDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, true);

  return offset;
}


static const value_string nrppa_T_physCellIDUTRAN_vals[] = {
  {   0, "physCellIDUTRA-FDD" },
  {   1, "physCellIDUTRA-TDD" },
  { 0, NULL }
};

static const per_choice_t T_physCellIDUTRAN_choice[] = {
  {   0, &hf_nrppa_physCellIDUTRA_FDD, ASN1_NO_EXTENSIONS     , dissect_nrppa_PhysCellIDUTRA_FDD },
  {   1, &hf_nrppa_physCellIDUTRA_TDD, ASN1_NO_EXTENSIONS     , dissect_nrppa_PhysCellIDUTRA_TDD },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_T_physCellIDUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_T_physCellIDUTRAN, T_physCellIDUTRAN_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_UTRA_RSCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -5, 91U, NULL, true);

  return offset;
}



static int
dissect_nrppa_UTRA_EcN0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 49U, NULL, true);

  return offset;
}


static const per_sequence_t ResultUTRAN_Item_sequence[] = {
  { &hf_nrppa_uARFCN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_UARFCN },
  { &hf_nrppa_physCellIDUTRAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_physCellIDUTRAN },
  { &hf_nrppa_uTRA_RSCP     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_UTRA_RSCP },
  { &hf_nrppa_uTRA_EcN0     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_UTRA_EcN0 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultUTRAN_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultUTRAN_Item, ResultUTRAN_Item_sequence);

  return offset;
}


static const per_sequence_t ResultUTRAN_sequence_of[1] = {
  { &hf_nrppa_ResultUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultUTRAN_Item },
};

static int
dissect_nrppa_ResultUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultUTRAN, ResultUTRAN_sequence_of,
                                                  1, maxUTRANMeas, false);

  return offset;
}


static const value_string nrppa_OtherRATMeasuredResultsValue_vals[] = {
  {   0, "resultGERAN" },
  {   1, "resultUTRAN" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t OtherRATMeasuredResultsValue_choice[] = {
  {   0, &hf_nrppa_resultGERAN   , ASN1_NO_EXTENSIONS     , dissect_nrppa_ResultGERAN },
  {   1, &hf_nrppa_resultUTRAN   , ASN1_NO_EXTENSIONS     , dissect_nrppa_ResultUTRAN },
  {   2, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_OtherRATMeasuredResultsValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_OtherRATMeasuredResultsValue, OtherRATMeasuredResultsValue_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t OtherRATMeasurementResult_sequence_of[1] = {
  { &hf_nrppa_OtherRATMeasurementResult_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_OtherRATMeasuredResultsValue },
};

static int
dissect_nrppa_OtherRATMeasurementResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_OtherRATMeasurementResult, OtherRATMeasurementResult_sequence_of,
                                                  1, maxNoMeas, false);

  return offset;
}


static const value_string nrppa_PathlossReferenceSignal_vals[] = {
  {   0, "sSB-Reference" },
  {   1, "dL-PRS-Reference" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t PathlossReferenceSignal_choice[] = {
  {   0, &hf_nrppa_sSB_Reference , ASN1_NO_EXTENSIONS     , dissect_nrppa_SSB },
  {   1, &hf_nrppa_dL_PRS_Reference, ASN1_NO_EXTENSIONS     , dissect_nrppa_DL_PRS },
  {   2, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_PathlossReferenceSignal(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_PathlossReferenceSignal, PathlossReferenceSignal_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PathlossReferenceInformation_sequence[] = {
  { &hf_nrppa_pathlossReferenceSignal, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PathlossReferenceSignal },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PathlossReferenceInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PathlossReferenceInformation, PathlossReferenceInformation_sequence);

  return offset;
}


static const value_string nrppa_PeriodicityItem_vals[] = {
  {   0, "ms0dot125" },
  {   1, "ms0dot25" },
  {   2, "ms0dot5" },
  {   3, "ms0dot625" },
  {   4, "ms1" },
  {   5, "ms1dot25" },
  {   6, "ms2" },
  {   7, "ms2dot5" },
  {   8, "ms4dot" },
  {   9, "ms5" },
  {  10, "ms8" },
  {  11, "ms10" },
  {  12, "ms16" },
  {  13, "ms20" },
  {  14, "ms32" },
  {  15, "ms40" },
  {  16, "ms64" },
  {  17, "ms80m" },
  {  18, "ms160" },
  {  19, "ms320" },
  {  20, "ms640m" },
  {  21, "ms1280" },
  {  22, "ms2560" },
  {  23, "ms5120" },
  {  24, "ms10240" },
  { 0, NULL }
};


static int
dissect_nrppa_PeriodicityItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     25, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PeriodicityList_sequence_of[1] = {
  { &hf_nrppa_PeriodicityList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PeriodicityItem },
};

static int
dissect_nrppa_PeriodicityList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PeriodicityList, PeriodicityList_sequence_of,
                                                  1, maxnoSRS_ResourcePerSet, false);

  return offset;
}


static const value_string nrppa_PRSBWAggregationRequestIndication_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_PRSBWAggregationRequestIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PosSRSResourceID_List_sequence_of[1] = {
  { &hf_nrppa_PosSRSResourceID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSPosResourceID },
};

static int
dissect_nrppa_PosSRSResourceID_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PosSRSResourceID_List, PosSRSResourceID_List_sequence_of,
                                                  1, maxnoSRS_PosResources, false);

  return offset;
}


static const per_sequence_t PosSRSResourceSet_Aggregation_Item_sequence[] = {
  { &hf_nrppa_pointA        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3279165 },
  { &hf_nrppa_pCI_NR        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_1007 },
  { &hf_nrppa_possrsResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_15 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PosSRSResourceSet_Aggregation_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PosSRSResourceSet_Aggregation_Item, PosSRSResourceSet_Aggregation_Item_sequence);

  return offset;
}


static const per_sequence_t PosSRSResourceSet_Aggregation_List_sequence_of[1] = {
  { &hf_nrppa_PosSRSResourceSet_Aggregation_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSRSResourceSet_Aggregation_Item },
};

static int
dissect_nrppa_PosSRSResourceSet_Aggregation_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PosSRSResourceSet_Aggregation_List, PosSRSResourceSet_Aggregation_List_sequence_of,
                                                  1, maxnoaggregatedPosSRS_ResourceSets, false);

  return offset;
}



static int
dissect_nrppa_PreconfigurationResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string nrppa_PRSConfigRequestType_vals[] = {
  {   0, "configure" },
  {   1, "off" },
  { 0, NULL }
};


static int
dissect_nrppa_PRSConfigRequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_subcarrierSpacing_01_vals[] = {
  {   0, "kHz15" },
  {   1, "kHz30" },
  {   2, "kHz60" },
  {   3, "kHz120" },
  { 0, NULL }
};


static int
dissect_nrppa_T_subcarrierSpacing_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_1_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 63U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_2176(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2176U, NULL, false);

  return offset;
}


static const value_string nrppa_T_combSize_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  {   2, "n6" },
  {   3, "n12" },
  { 0, NULL }
};


static int
dissect_nrppa_T_combSize(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_cPType_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_nrppa_T_cPType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_resourceSetPeriodicity_vals[] = {
  {   0, "n4" },
  {   1, "n5" },
  {   2, "n8" },
  {   3, "n10" },
  {   4, "n16" },
  {   5, "n20" },
  {   6, "n32" },
  {   7, "n40" },
  {   8, "n64" },
  {   9, "n80" },
  {  10, "n160" },
  {  11, "n320" },
  {  12, "n640" },
  {  13, "n1280" },
  {  14, "n2560" },
  {  15, "n5120" },
  {  16, "n10240" },
  {  17, "n20480" },
  {  18, "n40960" },
  {  19, "n81920" },
  {  20, "n128" },
  {  21, "n256" },
  {  22, "n512" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resourceSetPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, true, 3, NULL);

  return offset;
}


static const value_string nrppa_T_resourceRepetitionFactor_vals[] = {
  {   0, "rf1" },
  {   1, "rf2" },
  {   2, "rf4" },
  {   3, "rf6" },
  {   4, "rf8" },
  {   5, "rf16" },
  {   6, "rf32" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resourceRepetitionFactor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_resourceTimeGap_vals[] = {
  {   0, "tg1" },
  {   1, "tg2" },
  {   2, "tg4" },
  {   3, "tg8" },
  {   4, "tg16" },
  {   5, "tg32" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resourceTimeGap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_resourceNumberofSymbols_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  {   2, "n6" },
  {   3, "n12" },
  {   4, "n1" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resourceNumberofSymbols(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 1, NULL);

  return offset;
}


static const value_string nrppa_T_mutingBitRepetitionFactor_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  { 0, NULL }
};


static int
dissect_nrppa_T_mutingBitRepetitionFactor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PRSMutingOption1_sequence[] = {
  { &hf_nrppa_mutingPattern , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_DL_PRSMutingPattern },
  { &hf_nrppa_mutingBitRepetitionFactor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_mutingBitRepetitionFactor },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSMutingOption1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSMutingOption1, PRSMutingOption1_sequence);

  return offset;
}


static const per_sequence_t PRSMutingOption2_sequence[] = {
  { &hf_nrppa_mutingPattern , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_DL_PRSMutingPattern },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSMutingOption2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSMutingOption2, PRSMutingOption2_sequence);

  return offset;
}


static const per_sequence_t PRSMuting_sequence[] = {
  { &hf_nrppa_pRSMutingOption1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRSMutingOption1 },
  { &hf_nrppa_pRSMutingOption2, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRSMutingOption2 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSMuting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSMuting, PRSMuting_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_M60_50(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -60, 50U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_11_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 11U, NULL, true);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_12(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 12U, NULL, false);

  return offset;
}


static const per_sequence_t PRSResource_QCLSourceSSB_sequence[] = {
  { &hf_nrppa_pCI_NR        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_1007 },
  { &hf_nrppa_sSB_Index     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SSB_Index },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSResource_QCLSourceSSB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSResource_QCLSourceSSB, PRSResource_QCLSourceSSB_sequence);

  return offset;
}


static const per_sequence_t PRSResource_QCLSourcePRS_sequence[] = {
  { &hf_nrppa_qCLSourcePRSResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_qCLSourcePRSResourceID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRS_Resource_ID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSResource_QCLSourcePRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSResource_QCLSourcePRS, PRSResource_QCLSourcePRS_sequence);

  return offset;
}


static const value_string nrppa_PRSResource_QCLInfo_vals[] = {
  {   0, "qCLSourceSSB" },
  {   1, "qCLSourcePRS" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t PRSResource_QCLInfo_choice[] = {
  {   0, &hf_nrppa_qCLSourceSSB  , ASN1_NO_EXTENSIONS     , dissect_nrppa_PRSResource_QCLSourceSSB },
  {   1, &hf_nrppa_qCLSourcePRS  , ASN1_NO_EXTENSIONS     , dissect_nrppa_PRSResource_QCLSourcePRS },
  {   2, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_PRSResource_QCLInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_PRSResource_QCLInfo, PRSResource_QCLInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PRSResource_Item_sequence[] = {
  { &hf_nrppa_pRSResourceID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_ID },
  { &hf_nrppa_sequenceID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_4095 },
  { &hf_nrppa_rEOffset      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_11_ },
  { &hf_nrppa_resourceSlotOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_511 },
  { &hf_nrppa_resourceSymbolOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_12 },
  { &hf_nrppa_qCLInfo       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRSResource_QCLInfo },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSResource_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSResource_Item, PRSResource_Item_sequence);

  return offset;
}


static const per_sequence_t PRSResource_List_sequence_of[1] = {
  { &hf_nrppa_PRSResource_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSResource_Item },
};

static int
dissect_nrppa_PRSResource_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PRSResource_List, PRSResource_List_sequence_of,
                                                  1, maxnoofPRSresource, false);

  return offset;
}


static const per_sequence_t PRSResourceSet_Item_sequence[] = {
  { &hf_nrppa_pRSResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_subcarrierSpacing_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_subcarrierSpacing_01 },
  { &hf_nrppa_pRSbandwidth  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_1_63 },
  { &hf_nrppa_startPRB      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_2176 },
  { &hf_nrppa_pointA        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3279165 },
  { &hf_nrppa_combSize      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_combSize },
  { &hf_nrppa_cPType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_cPType },
  { &hf_nrppa_resourceSetPeriodicity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_resourceSetPeriodicity },
  { &hf_nrppa_resourceSetSlotOffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_81919_ },
  { &hf_nrppa_resourceRepetitionFactor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_resourceRepetitionFactor },
  { &hf_nrppa_resourceTimeGap, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_resourceTimeGap },
  { &hf_nrppa_resourceNumberofSymbols, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_resourceNumberofSymbols },
  { &hf_nrppa_pRSMuting     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRSMuting },
  { &hf_nrppa_pRSResourceTransmitPower, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M60_50 },
  { &hf_nrppa_pRSResource_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSResource_List },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSResourceSet_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSResourceSet_Item, PRSResourceSet_Item_sequence);

  return offset;
}


static const per_sequence_t PRSResourceSet_List_sequence_of[1] = {
  { &hf_nrppa_PRSResourceSet_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSResourceSet_Item },
};

static int
dissect_nrppa_PRSResourceSet_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PRSResourceSet_List, PRSResourceSet_List_sequence_of,
                                                  1, maxnoofPRSresourceSet, false);

  return offset;
}


static const per_sequence_t PRSConfiguration_sequence[] = {
  { &hf_nrppa_pRSResourceSet_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSResourceSet_List },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSConfiguration, PRSConfiguration_sequence);

  return offset;
}


static const value_string nrppa_T_measPRSPeriodicity_vals[] = {
  {   0, "ms20" },
  {   1, "ms40" },
  {   2, "ms80" },
  {   3, "ms160" },
  { 0, NULL }
};


static int
dissect_nrppa_T_measPRSPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_159_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 159U, NULL, true);

  return offset;
}


static const value_string nrppa_T_measurementPRSLength_vals[] = {
  {   0, "ms1dot5" },
  {   1, "ms3" },
  {   2, "ms3dot5" },
  {   3, "ms4" },
  {   4, "ms5dot5" },
  {   5, "ms6" },
  {   6, "ms10" },
  {   7, "ms20" },
  { 0, NULL }
};


static int
dissect_nrppa_T_measurementPRSLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t PRS_Measurements_Info_List_Item_sequence[] = {
  { &hf_nrppa_pointA        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3279165 },
  { &hf_nrppa_measPRSPeriodicity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_measPRSPeriodicity },
  { &hf_nrppa_measPRSOffset , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_159_ },
  { &hf_nrppa_measurementPRSLength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_measurementPRSLength },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRS_Measurements_Info_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRS_Measurements_Info_List_Item, PRS_Measurements_Info_List_Item_sequence);

  return offset;
}


static const per_sequence_t PRS_Measurements_Info_List_sequence_of[1] = {
  { &hf_nrppa_PRS_Measurements_Info_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Measurements_Info_List_Item },
};

static int
dissect_nrppa_PRS_Measurements_Info_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PRS_Measurements_Info_List, PRS_Measurements_Info_List_sequence_of,
                                                  1, maxFreqLayers, false);

  return offset;
}



static int
dissect_nrppa_ExtendedResourceSymbolOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 13U, NULL, true);

  return offset;
}


static const per_sequence_t PRSTransmissionOffPerResourceSet_Item_sequence[] = {
  { &hf_nrppa_pRSResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSTransmissionOffPerResourceSet_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSTransmissionOffPerResourceSet_Item, PRSTransmissionOffPerResourceSet_Item_sequence);

  return offset;
}


static const per_sequence_t PRSTransmissionOffPerResourceSet_sequence_of[1] = {
  { &hf_nrppa_PRSTransmissionOffPerResourceSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSTransmissionOffPerResourceSet_Item },
};

static int
dissect_nrppa_PRSTransmissionOffPerResourceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PRSTransmissionOffPerResourceSet, PRSTransmissionOffPerResourceSet_sequence_of,
                                                  1, maxnoofPRSresourceSet, false);

  return offset;
}


static const per_sequence_t PRSTransmissionOffIndicationPerResource_Item_sequence[] = {
  { &hf_nrppa_pRSResourceID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_ID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSTransmissionOffIndicationPerResource_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSTransmissionOffIndicationPerResource_Item, PRSTransmissionOffIndicationPerResource_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoofPRSresource_OF_PRSTransmissionOffIndicationPerResource_Item_sequence_of[1] = {
  { &hf_nrppa_pRSTransmissionOffIndicationPerResourceList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSTransmissionOffIndicationPerResource_Item },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxnoofPRSresource_OF_PRSTransmissionOffIndicationPerResource_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxnoofPRSresource_OF_PRSTransmissionOffIndicationPerResource_Item, SEQUENCE_SIZE_1_maxnoofPRSresource_OF_PRSTransmissionOffIndicationPerResource_Item_sequence_of,
                                                  1, maxnoofPRSresource, false);

  return offset;
}


static const per_sequence_t PRSTransmissionOffPerResource_Item_sequence[] = {
  { &hf_nrppa_pRSResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_pRSTransmissionOffIndicationPerResourceList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SEQUENCE_SIZE_1_maxnoofPRSresource_OF_PRSTransmissionOffIndicationPerResource_Item },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSTransmissionOffPerResource_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSTransmissionOffPerResource_Item, PRSTransmissionOffPerResource_Item_sequence);

  return offset;
}


static const per_sequence_t PRSTransmissionOffPerResource_sequence_of[1] = {
  { &hf_nrppa_PRSTransmissionOffPerResource_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSTransmissionOffPerResource_Item },
};

static int
dissect_nrppa_PRSTransmissionOffPerResource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PRSTransmissionOffPerResource, PRSTransmissionOffPerResource_sequence_of,
                                                  1, maxnoofPRSresourceSet, false);

  return offset;
}


static const value_string nrppa_PRSTransmissionOffIndication_vals[] = {
  {   0, "pRSTransmissionOffPerTRP" },
  {   1, "pRSTransmissionOffPerResourceSet" },
  {   2, "pRSTransmissionOffPerResource" },
  {   3, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t PRSTransmissionOffIndication_choice[] = {
  {   0, &hf_nrppa_pRSTransmissionOffPerTRP, ASN1_NO_EXTENSIONS     , dissect_nrppa_NULL },
  {   1, &hf_nrppa_pRSTransmissionOffPerResourceSet, ASN1_NO_EXTENSIONS     , dissect_nrppa_PRSTransmissionOffPerResourceSet },
  {   2, &hf_nrppa_pRSTransmissionOffPerResource, ASN1_NO_EXTENSIONS     , dissect_nrppa_PRSTransmissionOffPerResource },
  {   3, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_PRSTransmissionOffIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_PRSTransmissionOffIndication, PRSTransmissionOffIndication_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PRSTransmissionOffInformation_sequence[] = {
  { &hf_nrppa_pRSTransmissionOffIndication, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSTransmissionOffIndication },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSTransmissionOffInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSTransmissionOffInformation, PRSTransmissionOffInformation_sequence);

  return offset;
}



static int
dissect_nrppa_TRP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxnoTRPs, NULL, true);

  return offset;
}


static const value_string nrppa_T_combSize_01_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  {   2, "n6" },
  {   3, "n12" },
  { 0, NULL }
};


static int
dissect_nrppa_T_combSize_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_resourceSetPeriodicity_01_vals[] = {
  {   0, "n4" },
  {   1, "n5" },
  {   2, "n8" },
  {   3, "n10" },
  {   4, "n16" },
  {   5, "n20" },
  {   6, "n32" },
  {   7, "n40" },
  {   8, "n64" },
  {   9, "n80" },
  {  10, "n160" },
  {  11, "n320" },
  {  12, "n640" },
  {  13, "n1280" },
  {  14, "n2560" },
  {  15, "n5120" },
  {  16, "n10240" },
  {  17, "n20480" },
  {  18, "n40960" },
  {  19, "n81920" },
  {  20, "n128" },
  {  21, "n256" },
  {  22, "n512" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resourceSetPeriodicity_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, true, 3, NULL);

  return offset;
}


static const value_string nrppa_T_resourceRepetitionFactor_01_vals[] = {
  {   0, "rf1" },
  {   1, "rf2" },
  {   2, "rf4" },
  {   3, "rf6" },
  {   4, "rf8" },
  {   5, "rf16" },
  {   6, "rf32" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resourceRepetitionFactor_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_resourceNumberofSymbols_01_vals[] = {
  {   0, "n2" },
  {   1, "n4" },
  {   2, "n6" },
  {   3, "n12" },
  {   4, "n1" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resourceNumberofSymbols_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 1, NULL);

  return offset;
}


static const per_sequence_t RequestedDLPRSResource_Item_sequence[] = {
  { &hf_nrppa_qCLInfo       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRSResource_QCLInfo },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_RequestedDLPRSResource_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_RequestedDLPRSResource_Item, RequestedDLPRSResource_Item_sequence);

  return offset;
}


static const per_sequence_t RequestedDLPRSResource_List_sequence_of[1] = {
  { &hf_nrppa_RequestedDLPRSResource_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_RequestedDLPRSResource_Item },
};

static int
dissect_nrppa_RequestedDLPRSResource_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_RequestedDLPRSResource_List, RequestedDLPRSResource_List_sequence_of,
                                                  1, maxnoofPRSresource, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_90060_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 90060U, NULL, true);

  return offset;
}


static const per_sequence_t StartTimeAndDuration_sequence[] = {
  { &hf_nrppa_startTime     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_RelativeTime1900 },
  { &hf_nrppa_duration      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_90060_ },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_StartTimeAndDuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_StartTimeAndDuration, StartTimeAndDuration_sequence);

  return offset;
}


static const per_sequence_t RequestedDLPRSResourceSet_Item_sequence[] = {
  { &hf_nrppa_pRSbandwidth  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_1_63 },
  { &hf_nrppa_combSize_01   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_T_combSize_01 },
  { &hf_nrppa_resourceSetPeriodicity_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_T_resourceSetPeriodicity_01 },
  { &hf_nrppa_resourceRepetitionFactor_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_T_resourceRepetitionFactor_01 },
  { &hf_nrppa_resourceNumberofSymbols_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_T_resourceNumberofSymbols_01 },
  { &hf_nrppa_requestedDLPRSResource_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_RequestedDLPRSResource_List },
  { &hf_nrppa_resourceSetStartTimeAndDuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_StartTimeAndDuration },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_RequestedDLPRSResourceSet_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_RequestedDLPRSResourceSet_Item, RequestedDLPRSResourceSet_Item_sequence);

  return offset;
}


static const per_sequence_t RequestedDLPRSResourceSet_List_sequence_of[1] = {
  { &hf_nrppa_RequestedDLPRSResourceSet_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_RequestedDLPRSResourceSet_Item },
};

static int
dissect_nrppa_RequestedDLPRSResourceSet_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_RequestedDLPRSResourceSet_List, RequestedDLPRSResourceSet_List_sequence_of,
                                                  1, maxnoofPRSresourceSet, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_1_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 4U, NULL, false);

  return offset;
}


static const per_sequence_t RequestedDLPRSTransmissionCharacteristics_sequence[] = {
  { &hf_nrppa_requestedDLPRSResourceSet_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_RequestedDLPRSResourceSet_List },
  { &hf_nrppa_numberofFrequencyLayers, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_1_4 },
  { &hf_nrppa_startTimeAndDuration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_StartTimeAndDuration },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_RequestedDLPRSTransmissionCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_RequestedDLPRSTransmissionCharacteristics, RequestedDLPRSTransmissionCharacteristics_sequence);

  return offset;
}


static const per_sequence_t PRSTRPItem_sequence[] = {
  { &hf_nrppa_tRP_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_ID },
  { &hf_nrppa_requestedDLPRSTransmissionCharacteristics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_RequestedDLPRSTransmissionCharacteristics },
  { &hf_nrppa_pRSTransmissionOffInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRSTransmissionOffInformation },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSTRPItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSTRPItem, PRSTRPItem_sequence);

  return offset;
}


static const per_sequence_t PRSTRPList_sequence_of[1] = {
  { &hf_nrppa_PRSTRPList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSTRPItem },
};

static int
dissect_nrppa_PRSTRPList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PRSTRPList, PRSTRPList_sequence_of,
                                                  1, maxnoTRPs, false);

  return offset;
}


static const per_sequence_t PRSTransmissionTRPItem_sequence[] = {
  { &hf_nrppa_tRP_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_ID },
  { &hf_nrppa_pRSConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSConfiguration },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSTransmissionTRPItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSTransmissionTRPItem, PRSTransmissionTRPItem_sequence);

  return offset;
}


static const per_sequence_t PRSTransmissionTRPList_sequence_of[1] = {
  { &hf_nrppa_PRSTransmissionTRPList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSTransmissionTRPItem },
};

static int
dissect_nrppa_PRSTransmissionTRPList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PRSTransmissionTRPList, PRSTransmissionTRPList_sequence_of,
                                                  1, maxnoTRPs, false);

  return offset;
}


static const per_sequence_t PosValidityAreaCell_Item_sequence[] = {
  { &hf_nrppa_nR_CGI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_CGI_NR },
  { &hf_nrppa_nR_PCI        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_NR_PCI },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PosValidityAreaCell_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PosValidityAreaCell_Item, PosValidityAreaCell_Item_sequence);

  return offset;
}


static const per_sequence_t PosValidityAreaCellList_sequence_of[1] = {
  { &hf_nrppa_PosValidityAreaCellList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_PosValidityAreaCell_Item },
};

static int
dissect_nrppa_PosValidityAreaCellList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_PosValidityAreaCellList, PosValidityAreaCellList_sequence_of,
                                                  1, maxnoVACell, false);

  return offset;
}



static int
dissect_nrppa_PointA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3279165U, NULL, false);

  return offset;
}


static const value_string nrppa_ReferenceSignal_vals[] = {
  {   0, "nZP-CSI-RS" },
  {   1, "sSB" },
  {   2, "sRS" },
  {   3, "positioningSRS" },
  {   4, "dL-PRS" },
  {   5, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t ReferenceSignal_choice[] = {
  {   0, &hf_nrppa_nZP_CSI_RS    , ASN1_NO_EXTENSIONS     , dissect_nrppa_NZP_CSI_RS_ResourceID },
  {   1, &hf_nrppa_sSB           , ASN1_NO_EXTENSIONS     , dissect_nrppa_SSB },
  {   2, &hf_nrppa_sRS           , ASN1_NO_EXTENSIONS     , dissect_nrppa_SRSResourceID },
  {   3, &hf_nrppa_positioningSRS, ASN1_NO_EXTENSIONS     , dissect_nrppa_SRSPosResourceID },
  {   4, &hf_nrppa_dL_PRS        , ASN1_NO_EXTENSIONS     , dissect_nrppa_DL_PRS },
  {   5, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_ReferenceSignal(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_ReferenceSignal, ReferenceSignal_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_RepetitionFactorExtended_vals[] = {
  {   0, "n3" },
  {   1, "n5" },
  {   2, "n6" },
  {   3, "n7" },
  {   4, "n8" },
  {   5, "n10" },
  {   6, "n12" },
  {   7, "n14" },
  { 0, NULL }
};


static int
dissect_nrppa_RepetitionFactorExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_ReportCharacteristics_vals[] = {
  {   0, "onDemand" },
  {   1, "periodic" },
  { 0, NULL }
};


static int
dissect_nrppa_ReportCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3940097U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7880193U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15760385U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31520769U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63041537U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 126083073U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus1AdditionalPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32701U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus2AdditionalPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65401U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus3AdditionalPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 130801U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus4AdditionalPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 261601U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus5AdditionalPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 523201U, NULL, false);

  return offset;
}



static int
dissect_nrppa_ReportingGranularitykminus6AdditionalPath(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1046401U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_500_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 500U, NULL, true);

  return offset;
}


static const value_string nrppa_T_resourceType_vals[] = {
  {   0, "periodic" },
  {   1, "semi-persistent" },
  {   2, "aperiodic" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resourceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t SpatialRelationforResourceIDItem_sequence[] = {
  { &hf_nrppa_referenceSignal, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ReferenceSignal },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SpatialRelationforResourceIDItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SpatialRelationforResourceIDItem, SpatialRelationforResourceIDItem_sequence);

  return offset;
}


static const per_sequence_t SpatialRelationforResourceID_sequence_of[1] = {
  { &hf_nrppa_SpatialRelationforResourceID_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SpatialRelationforResourceIDItem },
};

static int
dissect_nrppa_SpatialRelationforResourceID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SpatialRelationforResourceID, SpatialRelationforResourceID_sequence_of,
                                                  1, maxnoSpatialRelations, false);

  return offset;
}


static const per_sequence_t SpatialRelationInfo_sequence[] = {
  { &hf_nrppa_spatialRelationforResourceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SpatialRelationforResourceID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SpatialRelationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SpatialRelationInfo, SpatialRelationInfo_sequence);

  return offset;
}


static const per_sequence_t SRSResourceSet_Item_sequence[] = {
  { &hf_nrppa_numberOfSRSResourcePerSet, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_1_16_ },
  { &hf_nrppa_periodicityList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PeriodicityList },
  { &hf_nrppa_spatialRelationInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SpatialRelationInfo },
  { &hf_nrppa_pathlossReferenceInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PathlossReferenceInformation },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSResourceSet_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSResourceSet_Item, SRSResourceSet_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoSRS_ResourceSets_OF_SRSResourceSet_Item_sequence_of[1] = {
  { &hf_nrppa_listOfSRSResourceSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSResourceSet_Item },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxnoSRS_ResourceSets_OF_SRSResourceSet_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxnoSRS_ResourceSets_OF_SRSResourceSet_Item, SEQUENCE_SIZE_1_maxnoSRS_ResourceSets_OF_SRSResourceSet_Item_sequence_of,
                                                  1, maxnoSRS_ResourceSets, false);

  return offset;
}


static const value_string nrppa_T_sSB_subcarrier_spacing_vals[] = {
  {   0, "kHz15" },
  {   1, "kHz30" },
  {   2, "kHz120" },
  {   3, "kHz240" },
  {   4, "kHz60" },
  {   5, "kHz480" },
  {   6, "kHz960" },
  { 0, NULL }
};


static int
dissect_nrppa_T_sSB_subcarrier_spacing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 3, NULL);

  return offset;
}


static const value_string nrppa_T_sSB_periodicity_vals[] = {
  {   0, "ms5" },
  {   1, "ms10" },
  {   2, "ms20" },
  {   3, "ms40" },
  {   4, "ms80" },
  {   5, "ms160" },
  { 0, NULL }
};


static int
dissect_nrppa_T_sSB_periodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_SSBBurstPosition_vals[] = {
  {   0, "shortBitmap" },
  {   1, "mediumBitmap" },
  {   2, "longBitmap" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t SSBBurstPosition_choice[] = {
  {   0, &hf_nrppa_shortBitmap   , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_4 },
  {   1, &hf_nrppa_mediumBitmap  , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_8 },
  {   2, &hf_nrppa_longBitmap    , ASN1_NO_EXTENSIONS     , dissect_nrppa_BIT_STRING_SIZE_64 },
  {   3, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_SSBBurstPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_SSBBurstPosition, SSBBurstPosition_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TF_Configuration_sequence[] = {
  { &hf_nrppa_sSB_frequency , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3279165 },
  { &hf_nrppa_sSB_subcarrier_spacing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_sSB_subcarrier_spacing },
  { &hf_nrppa_sSB_Transmit_power, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M60_50 },
  { &hf_nrppa_sSB_periodicity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_sSB_periodicity },
  { &hf_nrppa_sSB_half_frame_offset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_1 },
  { &hf_nrppa_sSB_SFN_offset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_15 },
  { &hf_nrppa_sSB_BurstPosition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SSBBurstPosition },
  { &hf_nrppa_sFN_initialisation_time, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_RelativeTime1900 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TF_Configuration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TF_Configuration, TF_Configuration_sequence);

  return offset;
}


static const per_sequence_t SSBInfoItem_sequence[] = {
  { &hf_nrppa_sSB_Configuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TF_Configuration },
  { &hf_nrppa_pCI_NR        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_1007 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SSBInfoItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SSBInfoItem, SSBInfoItem_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxNoSSBs_OF_SSBInfoItem_sequence_of[1] = {
  { &hf_nrppa_listOfSSBInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SSBInfoItem },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxNoSSBs_OF_SSBInfoItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxNoSSBs_OF_SSBInfoItem, SEQUENCE_SIZE_1_maxNoSSBs_OF_SSBInfoItem_sequence_of,
                                                  1, maxNoSSBs, false);

  return offset;
}


static const per_sequence_t SSBInfo_sequence[] = {
  { &hf_nrppa_listOfSSBInfo , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SEQUENCE_SIZE_1_maxNoSSBs_OF_SSBInfoItem },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SSBInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SSBInfo, SSBInfo_sequence);

  return offset;
}


static const per_sequence_t RequestedSRSTransmissionCharacteristics_sequence[] = {
  { &hf_nrppa_numberOfTransmissions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_500_ },
  { &hf_nrppa_resourceType  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_resourceType },
  { &hf_nrppa_bandwidth     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_BandwidthSRS },
  { &hf_nrppa_listOfSRSResourceSet, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SEQUENCE_SIZE_1_maxnoSRS_ResourceSets_OF_SRSResourceSet_Item },
  { &hf_nrppa_sSBInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SSBInfo },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_RequestedSRSTransmissionCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_RequestedSRSTransmissionCharacteristics, RequestedSRSTransmissionCharacteristics_sequence);

  return offset;
}


static const value_string nrppa_T_nrofSumbols_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  {   4, "n12" },
  { 0, NULL }
};


static int
dissect_nrppa_T_nrofSumbols(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t ResourceMapping_sequence[] = {
  { &hf_nrppa_startPosition , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_13 },
  { &hf_nrppa_nrofSumbols   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_nrofSumbols },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResourceMapping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResourceMapping, ResourceMapping_sequence);

  return offset;
}


static const per_sequence_t RequestedSRSPreconfigurationCharacteristics_Item_sequence[] = {
  { &hf_nrppa_requestedSRSTransmissionCharacteristics, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_RequestedSRSTransmissionCharacteristics },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_RequestedSRSPreconfigurationCharacteristics_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_RequestedSRSPreconfigurationCharacteristics_Item, RequestedSRSPreconfigurationCharacteristics_Item_sequence);

  return offset;
}


static const per_sequence_t RequestedSRSPreconfigurationCharacteristics_List_sequence_of[1] = {
  { &hf_nrppa_RequestedSRSPreconfigurationCharacteristics_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_RequestedSRSPreconfigurationCharacteristics_Item },
};

static int
dissect_nrppa_RequestedSRSPreconfigurationCharacteristics_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_RequestedSRSPreconfigurationCharacteristics_List, RequestedSRSPreconfigurationCharacteristics_List_sequence_of,
                                                  1, maxnoPreconfiguredSRS, false);

  return offset;
}


static const value_string nrppa_RequestType_vals[] = {
  {   0, "activate" },
  {   1, "deactivate" },
  { 0, NULL }
};


static int
dissect_nrppa_RequestType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_1_128_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 128U, NULL, true);

  return offset;
}


static const value_string nrppa_T_timeUnit_vals[] = {
  {   0, "second" },
  {   1, "ten-seconds" },
  {   2, "ten-milliseconds" },
  { 0, NULL }
};


static int
dissect_nrppa_T_timeUnit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t ResponseTime_sequence[] = {
  { &hf_nrppa_time          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_1_128_ },
  { &hf_nrppa_timeUnit      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_timeUnit },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResponseTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResponseTime, ResponseTime_sequence);

  return offset;
}



static int
dissect_nrppa_ValueRSRP_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_95(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 95U, NULL, false);

  return offset;
}


static const per_sequence_t ResultCSI_RSRP_PerCSI_RS_Item_sequence[] = {
  { &hf_nrppa_cSI_RS_Index  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_95 },
  { &hf_nrppa_valueCSI_RSRP , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ValueRSRP_NR },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultCSI_RSRP_PerCSI_RS_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultCSI_RSRP_PerCSI_RS_Item, ResultCSI_RSRP_PerCSI_RS_Item_sequence);

  return offset;
}


static const per_sequence_t ResultCSI_RSRP_PerCSI_RS_sequence_of[1] = {
  { &hf_nrppa_ResultCSI_RSRP_PerCSI_RS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultCSI_RSRP_PerCSI_RS_Item },
};

static int
dissect_nrppa_ResultCSI_RSRP_PerCSI_RS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultCSI_RSRP_PerCSI_RS, ResultCSI_RSRP_PerCSI_RS_sequence_of,
                                                  1, maxIndexesReport, false);

  return offset;
}


static const per_sequence_t ResultCSI_RSRP_Item_sequence[] = {
  { &hf_nrppa_nR_PCI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_PCI },
  { &hf_nrppa_nR_ARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_ARFCN },
  { &hf_nrppa_cGI_NR        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CGI_NR },
  { &hf_nrppa_valueCSI_RSRP_Cell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ValueRSRP_NR },
  { &hf_nrppa_cSI_RSRP_PerCSI_RS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ResultCSI_RSRP_PerCSI_RS },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultCSI_RSRP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultCSI_RSRP_Item, ResultCSI_RSRP_Item_sequence);

  return offset;
}


static const per_sequence_t ResultCSI_RSRP_sequence_of[1] = {
  { &hf_nrppa_ResultCSI_RSRP_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultCSI_RSRP_Item },
};

static int
dissect_nrppa_ResultCSI_RSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultCSI_RSRP, ResultCSI_RSRP_sequence_of,
                                                  1, maxCellReportNR, false);

  return offset;
}



static int
dissect_nrppa_ValueRSRQ_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t ResultCSI_RSRQ_PerCSI_RS_Item_sequence[] = {
  { &hf_nrppa_cSI_RS_Index  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_95 },
  { &hf_nrppa_valueCSI_RSRQ , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ValueRSRQ_NR },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultCSI_RSRQ_PerCSI_RS_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultCSI_RSRQ_PerCSI_RS_Item, ResultCSI_RSRQ_PerCSI_RS_Item_sequence);

  return offset;
}


static const per_sequence_t ResultCSI_RSRQ_PerCSI_RS_sequence_of[1] = {
  { &hf_nrppa_ResultCSI_RSRQ_PerCSI_RS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultCSI_RSRQ_PerCSI_RS_Item },
};

static int
dissect_nrppa_ResultCSI_RSRQ_PerCSI_RS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultCSI_RSRQ_PerCSI_RS, ResultCSI_RSRQ_PerCSI_RS_sequence_of,
                                                  1, maxIndexesReport, false);

  return offset;
}


static const per_sequence_t ResultCSI_RSRQ_Item_sequence[] = {
  { &hf_nrppa_nR_PCI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_PCI },
  { &hf_nrppa_nR_ARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_ARFCN },
  { &hf_nrppa_cGI_NR        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CGI_NR },
  { &hf_nrppa_valueCSI_RSRQ_Cell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ValueRSRQ_NR },
  { &hf_nrppa_cSI_RSRQ_PerCSI_RS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ResultCSI_RSRQ_PerCSI_RS },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultCSI_RSRQ_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultCSI_RSRQ_Item, ResultCSI_RSRQ_Item_sequence);

  return offset;
}


static const per_sequence_t ResultCSI_RSRQ_sequence_of[1] = {
  { &hf_nrppa_ResultCSI_RSRQ_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultCSI_RSRQ_Item },
};

static int
dissect_nrppa_ResultCSI_RSRQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultCSI_RSRQ, ResultCSI_RSRQ_sequence_of,
                                                  1, maxCellReportNR, false);

  return offset;
}


static const per_sequence_t ResultEUTRA_Item_sequence[] = {
  { &hf_nrppa_pCI_EUTRA     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PCI_EUTRA },
  { &hf_nrppa_eARFCN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_EARFCN },
  { &hf_nrppa_valueRSRP_EUTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ValueRSRP_EUTRA },
  { &hf_nrppa_valueRSRQ_EUTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ValueRSRQ_EUTRA },
  { &hf_nrppa_cGI_EUTRA     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CGI_EUTRA },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultEUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultEUTRA_Item, ResultEUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t ResultEUTRA_sequence_of[1] = {
  { &hf_nrppa_ResultEUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultEUTRA_Item },
};

static int
dissect_nrppa_ResultEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultEUTRA, ResultEUTRA_sequence_of,
                                                  1, maxEUTRAMeas, false);

  return offset;
}


static const per_sequence_t ResultSS_RSRP_PerSSB_Item_sequence[] = {
  { &hf_nrppa_sSB_Index     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SSB_Index },
  { &hf_nrppa_valueSS_RSRP  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ValueRSRP_NR },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultSS_RSRP_PerSSB_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultSS_RSRP_PerSSB_Item, ResultSS_RSRP_PerSSB_Item_sequence);

  return offset;
}


static const per_sequence_t ResultSS_RSRP_PerSSB_sequence_of[1] = {
  { &hf_nrppa_ResultSS_RSRP_PerSSB_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultSS_RSRP_PerSSB_Item },
};

static int
dissect_nrppa_ResultSS_RSRP_PerSSB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultSS_RSRP_PerSSB, ResultSS_RSRP_PerSSB_sequence_of,
                                                  1, maxIndexesReport, false);

  return offset;
}


static const per_sequence_t ResultSS_RSRP_Item_sequence[] = {
  { &hf_nrppa_nR_PCI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_PCI },
  { &hf_nrppa_nR_ARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_ARFCN },
  { &hf_nrppa_cGI_NR        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CGI_NR },
  { &hf_nrppa_valueSS_RSRP_Cell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ValueRSRP_NR },
  { &hf_nrppa_sS_RSRP_PerSSB, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ResultSS_RSRP_PerSSB },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultSS_RSRP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultSS_RSRP_Item, ResultSS_RSRP_Item_sequence);

  return offset;
}


static const per_sequence_t ResultSS_RSRP_sequence_of[1] = {
  { &hf_nrppa_ResultSS_RSRP_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultSS_RSRP_Item },
};

static int
dissect_nrppa_ResultSS_RSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultSS_RSRP, ResultSS_RSRP_sequence_of,
                                                  1, maxCellReportNR, false);

  return offset;
}


static const per_sequence_t ResultSS_RSRQ_PerSSB_Item_sequence[] = {
  { &hf_nrppa_sSB_Index     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SSB_Index },
  { &hf_nrppa_valueSS_RSRQ  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ValueRSRQ_NR },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultSS_RSRQ_PerSSB_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultSS_RSRQ_PerSSB_Item, ResultSS_RSRQ_PerSSB_Item_sequence);

  return offset;
}


static const per_sequence_t ResultSS_RSRQ_PerSSB_sequence_of[1] = {
  { &hf_nrppa_ResultSS_RSRQ_PerSSB_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultSS_RSRQ_PerSSB_Item },
};

static int
dissect_nrppa_ResultSS_RSRQ_PerSSB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultSS_RSRQ_PerSSB, ResultSS_RSRQ_PerSSB_sequence_of,
                                                  1, maxIndexesReport, false);

  return offset;
}


static const per_sequence_t ResultSS_RSRQ_Item_sequence[] = {
  { &hf_nrppa_nR_PCI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_PCI },
  { &hf_nrppa_nR_ARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_ARFCN },
  { &hf_nrppa_cGI_NR        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CGI_NR },
  { &hf_nrppa_valueSS_RSRQ_Cell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ValueRSRQ_NR },
  { &hf_nrppa_sS_RSRQ_PerSSB, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ResultSS_RSRQ_PerSSB },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultSS_RSRQ_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultSS_RSRQ_Item, ResultSS_RSRQ_Item_sequence);

  return offset;
}


static const per_sequence_t ResultSS_RSRQ_sequence_of[1] = {
  { &hf_nrppa_ResultSS_RSRQ_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultSS_RSRQ_Item },
};

static int
dissect_nrppa_ResultSS_RSRQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultSS_RSRQ, ResultSS_RSRQ_sequence_of,
                                                  1, maxCellReportNR, false);

  return offset;
}


static const per_sequence_t ResultNR_Item_sequence[] = {
  { &hf_nrppa_nR_PCI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_PCI },
  { &hf_nrppa_nR_ARFCN      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_ARFCN },
  { &hf_nrppa_valueSS_RSRP_Cell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ValueRSRP_NR },
  { &hf_nrppa_valueSS_RSRQ_Cell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ValueRSRQ_NR },
  { &hf_nrppa_sS_RSRP_PerSSB, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ResultSS_RSRP_PerSSB },
  { &hf_nrppa_sS_RSRQ_PerSSB, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ResultSS_RSRQ_PerSSB },
  { &hf_nrppa_cGI_NR        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CGI_NR },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ResultNR_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ResultNR_Item, ResultNR_Item_sequence);

  return offset;
}


static const per_sequence_t ResultNR_sequence_of[1] = {
  { &hf_nrppa_ResultNR_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ResultNR_Item },
};

static int
dissect_nrppa_ResultNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_ResultNR, ResultNR_sequence_of,
                                                  1, maxNRMeas, false);

  return offset;
}


static const value_string nrppa_RxTxTimingErrorMargin_vals[] = {
  {   0, "tc0dot5" },
  {   1, "tc1" },
  {   2, "tc2" },
  {   3, "tc4" },
  {   4, "tc8" },
  {   5, "tc12" },
  {   6, "tc16" },
  {   7, "tc20" },
  {   8, "tc24" },
  {   9, "tc32" },
  {  10, "tc40" },
  {  11, "tc48" },
  {  12, "tc64" },
  {  13, "tc80" },
  {  14, "tc96" },
  {  15, "tc128" },
  { 0, NULL }
};


static int
dissect_nrppa_RxTxTimingErrorMargin(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_SCS_480(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 319U, NULL, false);

  return offset;
}



static int
dissect_nrppa_SCS_960(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 639U, NULL, false);

  return offset;
}


static const value_string nrppa_T_subcarrierSpacing_02_vals[] = {
  {   0, "kHz15" },
  {   1, "kHz30" },
  {   2, "kHz60" },
  {   3, "kHz120" },
  {   4, "kHz480" },
  {   5, "kHz960" },
  { 0, NULL }
};


static int
dissect_nrppa_T_subcarrierSpacing_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 2, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_1_275_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 275U, NULL, true);

  return offset;
}


static const per_sequence_t SCS_SpecificCarrier_sequence[] = {
  { &hf_nrppa_offsetToCarrier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_2199_ },
  { &hf_nrppa_subcarrierSpacing_02, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_subcarrierSpacing_02 },
  { &hf_nrppa_carrierBandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_1_275_ },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SCS_SpecificCarrier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SCS_SpecificCarrier, SCS_SpecificCarrier_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_M3841_3841_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -3841, 3841U, NULL, true);

  return offset;
}



static int
dissect_nrppa_INTEGER_1_246_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 246U, NULL, true);

  return offset;
}


static const per_sequence_t Search_window_information_sequence[] = {
  { &hf_nrppa_expectedPropagationDelay, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_M3841_3841_ },
  { &hf_nrppa_delayUncertainty, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_1_246_ },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_Search_window_information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_Search_window_information, Search_window_information_sequence);

  return offset;
}



static int
dissect_nrppa_SlotNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 79U, NULL, false);

  return offset;
}



static int
dissect_nrppa_INTEGER_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, false);

  return offset;
}


static const per_sequence_t SlotOffsetRemainingHopsAperiodic_sequence[] = {
  { &hf_nrppa_slotOffset_01 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_1_32 },
  { &hf_nrppa_startPosition , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_13 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SlotOffsetRemainingHopsAperiodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SlotOffsetRemainingHopsAperiodic, SlotOffsetRemainingHopsAperiodic_sequence);

  return offset;
}


static const per_sequence_t SlotOffsetRemainingHopsSemiPersistent_sequence[] = {
  { &hf_nrppa_sRSperiodicity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSPeriodicity },
  { &hf_nrppa_offset_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_81919_ },
  { &hf_nrppa_startPosition , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_13 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SlotOffsetRemainingHopsSemiPersistent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SlotOffsetRemainingHopsSemiPersistent, SlotOffsetRemainingHopsSemiPersistent_sequence);

  return offset;
}


static const per_sequence_t SlotOffsetRemainingHopsPeriodic_sequence[] = {
  { &hf_nrppa_sRSperiodicity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSPeriodicity },
  { &hf_nrppa_offset_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_81919_ },
  { &hf_nrppa_startPosition , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_13 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SlotOffsetRemainingHopsPeriodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SlotOffsetRemainingHopsPeriodic, SlotOffsetRemainingHopsPeriodic_sequence);

  return offset;
}


static const value_string nrppa_SlotOffsetRemainingHops_vals[] = {
  {   0, "aperiodic" },
  {   1, "semi-persistent" },
  {   2, "periodic" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t SlotOffsetRemainingHops_choice[] = {
  {   0, &hf_nrppa_aperiodic_04  , ASN1_NO_EXTENSIONS     , dissect_nrppa_SlotOffsetRemainingHopsAperiodic },
  {   1, &hf_nrppa_semi_persistent_04, ASN1_NO_EXTENSIONS     , dissect_nrppa_SlotOffsetRemainingHopsSemiPersistent },
  {   2, &hf_nrppa_periodic_04   , ASN1_NO_EXTENSIONS     , dissect_nrppa_SlotOffsetRemainingHopsPeriodic },
  {   3, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_SlotOffsetRemainingHops(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_SlotOffsetRemainingHops, SlotOffsetRemainingHops_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SlotOffsetForRemainingHopsItem_sequence[] = {
  { &hf_nrppa_slotOffsetRemainingHops, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SlotOffsetRemainingHops },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SlotOffsetForRemainingHopsItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SlotOffsetForRemainingHopsItem, SlotOffsetForRemainingHopsItem_sequence);

  return offset;
}


static const per_sequence_t SlotOffsetForRemainingHopsList_sequence_of[1] = {
  { &hf_nrppa_SlotOffsetForRemainingHopsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SlotOffsetForRemainingHopsItem },
};

static int
dissect_nrppa_SlotOffsetForRemainingHopsList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SlotOffsetForRemainingHopsList, SlotOffsetForRemainingHopsList_sequence_of,
                                                  1, maxnoofHopsMinusOne, false);

  return offset;
}


static const per_sequence_t SpatialDirectionInformation_sequence[] = {
  { &hf_nrppa_nR_PRS_Beam_Information, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_PRS_Beam_Information },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SpatialDirectionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SpatialDirectionInformation, SpatialDirectionInformation_sequence);

  return offset;
}


static const per_sequence_t SpatialRelationPerSRSResourceItem_sequence[] = {
  { &hf_nrppa_referenceSignal, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ReferenceSignal },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SpatialRelationPerSRSResourceItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SpatialRelationPerSRSResourceItem, SpatialRelationPerSRSResourceItem_sequence);

  return offset;
}


static const per_sequence_t SpatialRelationPerSRSResource_List_sequence_of[1] = {
  { &hf_nrppa_SpatialRelationPerSRSResource_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SpatialRelationPerSRSResourceItem },
};

static int
dissect_nrppa_SpatialRelationPerSRSResource_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SpatialRelationPerSRSResource_List, SpatialRelationPerSRSResource_List_sequence_of,
                                                  1, maxnoSRS_ResourcePerSet, false);

  return offset;
}


static const per_sequence_t SpatialRelationPerSRSResource_sequence[] = {
  { &hf_nrppa_spatialRelationPerSRSResource_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SpatialRelationPerSRSResource_List },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SpatialRelationPerSRSResource(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SpatialRelationPerSRSResource, SpatialRelationPerSRSResource_sequence);

  return offset;
}


static const per_sequence_t UplinkChannelBW_PerSCS_List_sequence_of[1] = {
  { &hf_nrppa_UplinkChannelBW_PerSCS_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SCS_SpecificCarrier },
};

static int
dissect_nrppa_UplinkChannelBW_PerSCS_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_UplinkChannelBW_PerSCS_List, UplinkChannelBW_PerSCS_List_sequence_of,
                                                  1, maxnoSCSs, false);

  return offset;
}


static const per_sequence_t SRSCarrier_List_Item_sequence[] = {
  { &hf_nrppa_pointA        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3279165 },
  { &hf_nrppa_uplinkChannelBW_PerSCS_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_UplinkChannelBW_PerSCS_List },
  { &hf_nrppa_activeULBWP   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ActiveULBWP },
  { &hf_nrppa_pCI_NR        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_1007 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSCarrier_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSCarrier_List_Item, SRSCarrier_List_Item_sequence);

  return offset;
}


static const per_sequence_t SRSCarrier_List_sequence_of[1] = {
  { &hf_nrppa_SRSCarrier_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSCarrier_List_Item },
};

static int
dissect_nrppa_SRSCarrier_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SRSCarrier_List, SRSCarrier_List_sequence_of,
                                                  1, maxnoSRS_Carriers, false);

  return offset;
}


static const per_sequence_t SRSConfiguration_sequence[] = {
  { &hf_nrppa_sRSCarrier_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSCarrier_List },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSConfiguration, SRSConfiguration_sequence);

  return offset;
}



static int
dissect_nrppa_SrsFrequency(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3279165U, NULL, false);

  return offset;
}


static const value_string nrppa_SRSPortIndex_vals[] = {
  {   0, "id1000" },
  {   1, "id1001" },
  {   2, "id1002" },
  {   3, "id1003" },
  { 0, NULL }
};


static int
dissect_nrppa_SRSPortIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t SRSResourceTrigger_sequence[] = {
  { &hf_nrppa_aperiodicSRSResourceTriggerList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_AperiodicSRSResourceTriggerList },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSResourceTrigger(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSResourceTrigger, SRSResourceTrigger_sequence);

  return offset;
}


static const per_sequence_t SRSInfo_sequence[] = {
  { &hf_nrppa_sRSResource   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSResourceID },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSInfo, SRSInfo_sequence);

  return offset;
}


static const per_sequence_t PosSRSInfo_sequence[] = {
  { &hf_nrppa_posSRSResourceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSPosResourceID },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PosSRSInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PosSRSInfo, PosSRSInfo_sequence);

  return offset;
}


static const value_string nrppa_SRSResourceTypeChoice_vals[] = {
  {   0, "sRSResourceInfo" },
  {   1, "posSRSResourceInfo" },
  { 0, NULL }
};

static const per_choice_t SRSResourceTypeChoice_choice[] = {
  {   0, &hf_nrppa_sRSResourceInfo, ASN1_EXTENSION_ROOT    , dissect_nrppa_SRSInfo },
  {   1, &hf_nrppa_posSRSResourceInfo, ASN1_EXTENSION_ROOT    , dissect_nrppa_PosSRSInfo },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_SRSResourceTypeChoice(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_SRSResourceTypeChoice, SRSResourceTypeChoice_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SRSResourcetype_sequence[] = {
  { &hf_nrppa_sRSResourceTypeChoice, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSResourceTypeChoice },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSResourcetype(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSResourcetype, SRSResourcetype_sequence);

  return offset;
}


static const value_string nrppa_SRSTransmissionStatus_vals[] = {
  {   0, "stopped" },
  { 0, NULL }
};


static int
dissect_nrppa_SRSTransmissionStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_SSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 32, false, NULL);

  return offset;
}


static const value_string nrppa_StartRBIndex_vals[] = {
  {   0, "freqScalingFactor2" },
  {   1, "freqScalingFactor4" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t StartRBIndex_choice[] = {
  {   0, &hf_nrppa_freqScalingFactor2, ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_1 },
  {   1, &hf_nrppa_freqScalingFactor4, ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_3 },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_StartRBIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_StartRBIndex, StartRBIndex_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_StartRBHopping_vals[] = {
  {   0, "enable" },
  { 0, NULL }
};


static int
dissect_nrppa_StartRBHopping(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_nrppa_SymbolIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 13U, NULL, false);

  return offset;
}


static const value_string nrppa_SRSReservationType_vals[] = {
  {   0, "reserve" },
  {   1, "release" },
  { 0, NULL }
};


static int
dissect_nrppa_SRSReservationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t SRSPreconfiguration_Item_sequence[] = {
  { &hf_nrppa_sRSConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSConfiguration },
  { &hf_nrppa_posValidityAreaCellList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PosValidityAreaCellList },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSPreconfiguration_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSPreconfiguration_Item, SRSPreconfiguration_Item_sequence);

  return offset;
}


static const per_sequence_t SRSPreconfiguration_List_sequence_of[1] = {
  { &hf_nrppa_SRSPreconfiguration_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSPreconfiguration_Item },
};

static int
dissect_nrppa_SRSPreconfiguration_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SRSPreconfiguration_List, SRSPreconfiguration_List_sequence_of,
                                                  1, maxnoPreconfiguredSRS, false);

  return offset;
}


static const value_string nrppa_T_subframeAssignment_vals[] = {
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
dissect_nrppa_T_subframeAssignment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TDD_Config_EUTRA_Item_sequence[] = {
  { &hf_nrppa_subframeAssignment, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_subframeAssignment },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TDD_Config_EUTRA_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TDD_Config_EUTRA_Item, TDD_Config_EUTRA_Item_sequence);

  return offset;
}


static const per_sequence_t TRP_RxTx_TEGInformation_sequence[] = {
  { &hf_nrppa_tRP_RxTx_TEGID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_255 },
  { &hf_nrppa_tRP_RxTx_TimingErrorMargin, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_RxTxTimingErrorMargin },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_RxTx_TEGInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_RxTx_TEGInformation, TRP_RxTx_TEGInformation_sequence);

  return offset;
}


static const value_string nrppa_TimingErrorMargin_vals[] = {
  {   0, "tc0" },
  {   1, "tc2" },
  {   2, "tc4" },
  {   3, "tc6" },
  {   4, "tc8" },
  {   5, "tc12" },
  {   6, "tc16" },
  {   7, "tc20" },
  {   8, "tc24" },
  {   9, "tc32" },
  {  10, "tc40" },
  {  11, "tc48" },
  {  12, "tc56" },
  {  13, "tc64" },
  {  14, "tc72" },
  {  15, "tc80" },
  { 0, NULL }
};


static int
dissect_nrppa_TimingErrorMargin(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     16, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TRP_Tx_TEGInformation_sequence[] = {
  { &hf_nrppa_tRP_Tx_TEGID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_7 },
  { &hf_nrppa_tRP_Tx_TimingErrorMargin, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TimingErrorMargin },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_Tx_TEGInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_Tx_TEGInformation, TRP_Tx_TEGInformation_sequence);

  return offset;
}


static const per_sequence_t RxTxTEG_sequence[] = {
  { &hf_nrppa_tRP_RxTx_TEGInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_RxTx_TEGInformation },
  { &hf_nrppa_tRP_Tx_TEGInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TRP_Tx_TEGInformation },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_RxTxTEG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_RxTxTEG, RxTxTEG_sequence);

  return offset;
}


static const per_sequence_t TRP_Rx_TEGInformation_sequence[] = {
  { &hf_nrppa_tRP_Rx_TEGID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_31 },
  { &hf_nrppa_tRP_Rx_TimingErrorMargin, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TimingErrorMargin },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_Rx_TEGInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_Rx_TEGInformation, TRP_Rx_TEGInformation_sequence);

  return offset;
}


static const per_sequence_t RxTEG_sequence[] = {
  { &hf_nrppa_tRP_Rx_TEGInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_Rx_TEGInformation },
  { &hf_nrppa_tRP_Tx_TEGInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_Tx_TEGInformation },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_RxTEG(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_RxTEG, RxTEG_sequence);

  return offset;
}


static const value_string nrppa_TRPTEGInformation_vals[] = {
  {   0, "rxTx-TEG" },
  {   1, "rx-TEG" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TRPTEGInformation_choice[] = {
  {   0, &hf_nrppa_rxTx_TEG      , ASN1_NO_EXTENSIONS     , dissect_nrppa_RxTxTEG },
  {   1, &hf_nrppa_rx_TEG        , ASN1_NO_EXTENSIONS     , dissect_nrppa_RxTEG },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TRPTEGInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TRPTEGInformation, TRPTEGInformation_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_T_durationSlots_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n6" },
  {   4, "n8" },
  {   5, "n12" },
  {   6, "n16" },
  { 0, NULL }
};


static int
dissect_nrppa_T_durationSlots(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_TimeWindowDurationMeasurement_vals[] = {
  {   0, "durationSlots" },
  {   1, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TimeWindowDurationMeasurement_choice[] = {
  {   0, &hf_nrppa_durationSlots , ASN1_NO_EXTENSIONS     , dissect_nrppa_T_durationSlots },
  {   1, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TimeWindowDurationMeasurement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TimeWindowDurationMeasurement, TimeWindowDurationMeasurement_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_T_durationSymbols_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  {   4, "n12" },
  { 0, NULL }
};


static int
dissect_nrppa_T_durationSymbols(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_T_durationSlots_01_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n6" },
  {   4, "n8" },
  {   5, "n12" },
  {   6, "n16" },
  { 0, NULL }
};


static int
dissect_nrppa_T_durationSlots_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_TimeWindowDurationSRS_vals[] = {
  {   0, "durationSymbols" },
  {   1, "durationSlots" },
  {   2, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TimeWindowDurationSRS_choice[] = {
  {   0, &hf_nrppa_durationSymbols, ASN1_NO_EXTENSIONS     , dissect_nrppa_T_durationSymbols },
  {   1, &hf_nrppa_durationSlots_01, ASN1_NO_EXTENSIONS     , dissect_nrppa_T_durationSlots_01 },
  {   2, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TimeWindowDurationSRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TimeWindowDurationSRS, TimeWindowDurationSRS_choice,
                                 NULL);

  return offset;
}


static const value_string nrppa_TimeWindowPeriodicityMeasurement_vals[] = {
  {   0, "ms160" },
  {   1, "ms320" },
  {   2, "ms640" },
  {   3, "ms1280" },
  {   4, "ms2560" },
  {   5, "ms5120" },
  {   6, "ms10240" },
  {   7, "ms20480" },
  {   8, "ms40960" },
  {   9, "ms61440" },
  {  10, "ms81920" },
  {  11, "ms368640" },
  {  12, "ms737280" },
  {  13, "ms1843200" },
  { 0, NULL }
};


static int
dissect_nrppa_TimeWindowPeriodicityMeasurement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, true, 0, NULL);

  return offset;
}


static const value_string nrppa_TimeWindowPeriodicitySRS_vals[] = {
  {   0, "ms0dot125" },
  {   1, "ms0dot25" },
  {   2, "ms0dot5" },
  {   3, "ms0dot625" },
  {   4, "ms1" },
  {   5, "ms1dot25" },
  {   6, "ms2" },
  {   7, "ms2dot5" },
  {   8, "ms4" },
  {   9, "ms5" },
  {  10, "ms8" },
  {  11, "ms10" },
  {  12, "ms16" },
  {  13, "ms20" },
  {  14, "ms32" },
  {  15, "ms40" },
  {  16, "ms64" },
  {  17, "ms80" },
  {  18, "ms160" },
  {  19, "ms320" },
  {  20, "ms640" },
  {  21, "ms1280" },
  {  22, "ms2560" },
  {  23, "ms5120" },
  {  24, "ms10240" },
  { 0, NULL }
};


static int
dissect_nrppa_TimeWindowPeriodicitySRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     25, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TimeWindowStartSRS_sequence[] = {
  { &hf_nrppa_systemFrameNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SystemFrameNumber },
  { &hf_nrppa_slotNumber    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SlotNumber },
  { &hf_nrppa_symbolIndex   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_13 },
  { &hf_nrppa_iE_Extension  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TimeWindowStartSRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TimeWindowStartSRS, TimeWindowStartSRS_sequence);

  return offset;
}



static int
dissect_nrppa_TimingReportingGranularityFactorExtended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -6, -1, NULL, true);

  return offset;
}


static const value_string nrppa_T_timeWindowType_vals[] = {
  {   0, "single" },
  {   1, "periodic" },
  { 0, NULL }
};


static int
dissect_nrppa_T_timeWindowType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TimeWindowInformation_Measurement_Item_sequence[] = {
  { &hf_nrppa_timeWindowDurationMeasurement, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TimeWindowDurationMeasurement },
  { &hf_nrppa_timeWindowType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_timeWindowType },
  { &hf_nrppa_timeWindowPeriodicityMeasurement, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TimeWindowPeriodicityMeasurement },
  { &hf_nrppa_iE_Extension  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TimeWindowInformation_Measurement_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TimeWindowInformation_Measurement_Item, TimeWindowInformation_Measurement_Item_sequence);

  return offset;
}


static const per_sequence_t TimeWindowInformation_Measurement_List_sequence_of[1] = {
  { &hf_nrppa_TimeWindowInformation_Measurement_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TimeWindowInformation_Measurement_Item },
};

static int
dissect_nrppa_TimeWindowInformation_Measurement_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TimeWindowInformation_Measurement_List, TimeWindowInformation_Measurement_List_sequence_of,
                                                  1, maxnoofTimeWindowMeas, false);

  return offset;
}


static const value_string nrppa_T_timeWindowType_01_vals[] = {
  {   0, "single" },
  {   1, "periodic" },
  { 0, NULL }
};


static int
dissect_nrppa_T_timeWindowType_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TimeWindowInformation_SRS_Item_sequence[] = {
  { &hf_nrppa_timeWindowStartSRS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TimeWindowStartSRS },
  { &hf_nrppa_timeWindowDurationSRS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TimeWindowDurationSRS },
  { &hf_nrppa_timeWindowType_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_timeWindowType_01 },
  { &hf_nrppa_timeWindowPeriodicitySRS, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TimeWindowPeriodicitySRS },
  { &hf_nrppa_iE_Extension  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TimeWindowInformation_SRS_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TimeWindowInformation_SRS_Item, TimeWindowInformation_SRS_Item_sequence);

  return offset;
}


static const per_sequence_t TimeWindowInformation_SRS_List_sequence_of[1] = {
  { &hf_nrppa_TimeWindowInformation_SRS_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TimeWindowInformation_SRS_Item },
};

static int
dissect_nrppa_TimeWindowInformation_SRS_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TimeWindowInformation_SRS_List, TimeWindowInformation_SRS_List_sequence_of,
                                                  1, maxnoofTimeWindowSRS, false);

  return offset;
}


static const per_sequence_t TransmissionCombn8_sequence[] = {
  { &hf_nrppa_combOffset_n8 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_7 },
  { &hf_nrppa_cyclicShift_n8, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_5 },
  { &hf_nrppa_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TransmissionCombn8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TransmissionCombn8, TransmissionCombn8_sequence);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 30U, NULL, false);

  return offset;
}


static const per_sequence_t TRP_Beam_Power_Item_sequence[] = {
  { &hf_nrppa_pRSResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_pRSResourceID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_ID },
  { &hf_nrppa_relativePower , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_30 },
  { &hf_nrppa_relativePowerFine, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_9 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_Beam_Power_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_Beam_Power_Item, TRP_Beam_Power_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_2_maxNumResourcesPerAngle_OF_TRP_Beam_Power_Item_sequence_of[1] = {
  { &hf_nrppa_trp_beam_power_list_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_Beam_Power_Item },
};

static int
dissect_nrppa_SEQUENCE_SIZE_2_maxNumResourcesPerAngle_OF_TRP_Beam_Power_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_2_maxNumResourcesPerAngle_OF_TRP_Beam_Power_Item, SEQUENCE_SIZE_2_maxNumResourcesPerAngle_OF_TRP_Beam_Power_Item_sequence_of,
                                                  2, maxNumResourcesPerAngle, false);

  return offset;
}


static const per_sequence_t TRP_ElevationAngleList_Item_sequence[] = {
  { &hf_nrppa_trp_elevation_angle, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_180 },
  { &hf_nrppa_trp_elevation_angle_fine, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_9 },
  { &hf_nrppa_trp_beam_power_list, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SEQUENCE_SIZE_2_maxNumResourcesPerAngle_OF_TRP_Beam_Power_Item },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_ElevationAngleList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_ElevationAngleList_Item, TRP_ElevationAngleList_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoElevationAngles_OF_TRP_ElevationAngleList_Item_sequence_of[1] = {
  { &hf_nrppa_trp_elevation_angle_list_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_ElevationAngleList_Item },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxnoElevationAngles_OF_TRP_ElevationAngleList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxnoElevationAngles_OF_TRP_ElevationAngleList_Item, SEQUENCE_SIZE_1_maxnoElevationAngles_OF_TRP_ElevationAngleList_Item_sequence_of,
                                                  1, maxnoElevationAngles, false);

  return offset;
}


static const per_sequence_t TRP_BeamAntennaAnglesList_Item_sequence[] = {
  { &hf_nrppa_trp_azimuth_angle, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_359 },
  { &hf_nrppa_trp_azimuth_angle_fine, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_9 },
  { &hf_nrppa_trp_elevation_angle_list, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SEQUENCE_SIZE_1_maxnoElevationAngles_OF_TRP_ElevationAngleList_Item },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_BeamAntennaAnglesList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_BeamAntennaAnglesList_Item, TRP_BeamAntennaAnglesList_Item_sequence);

  return offset;
}


static const per_sequence_t TRP_BeamAntennaAngles_sequence_of[1] = {
  { &hf_nrppa_TRP_BeamAntennaAngles_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_BeamAntennaAnglesList_Item },
};

static int
dissect_nrppa_TRP_BeamAntennaAngles(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRP_BeamAntennaAngles, TRP_BeamAntennaAngles_sequence_of,
                                                  1, maxnoAzimuthAngles, false);

  return offset;
}


static const per_sequence_t TRP_BeamAntennaExplicitInformation_sequence[] = {
  { &hf_nrppa_trp_BeamAntennaAngles, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_BeamAntennaAngles },
  { &hf_nrppa_lcs_to_gcs_translation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_LCS_to_GCS_Translation },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_BeamAntennaExplicitInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_BeamAntennaExplicitInformation, TRP_BeamAntennaExplicitInformation_sequence);

  return offset;
}


static const value_string nrppa_Choice_TRP_Beam_Antenna_Info_Item_vals[] = {
  {   0, "reference" },
  {   1, "explicit" },
  {   2, "noChange" },
  {   3, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t Choice_TRP_Beam_Antenna_Info_Item_choice[] = {
  {   0, &hf_nrppa_reference     , ASN1_NO_EXTENSIONS     , dissect_nrppa_TRP_ID },
  {   1, &hf_nrppa_explicit      , ASN1_NO_EXTENSIONS     , dissect_nrppa_TRP_BeamAntennaExplicitInformation },
  {   2, &hf_nrppa_noChange      , ASN1_NO_EXTENSIONS     , dissect_nrppa_NULL },
  {   3, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_Choice_TRP_Beam_Antenna_Info_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_Choice_TRP_Beam_Antenna_Info_Item, Choice_TRP_Beam_Antenna_Info_Item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TRPBeamAntennaInformation_sequence[] = {
  { &hf_nrppa_choice_TRP_Beam_Antenna_Info_Item, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_Choice_TRP_Beam_Antenna_Info_Item },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPBeamAntennaInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPBeamAntennaInformation, TRPBeamAntennaInformation_sequence);

  return offset;
}


static const value_string nrppa_TRPMeasurementType_vals[] = {
  {   0, "gNB-RxTxTimeDiff" },
  {   1, "uL-SRS-RSRP" },
  {   2, "uL-AoA" },
  {   3, "uL-RTOA" },
  {   4, "multiple-UL-AoA" },
  {   5, "uL-SRS-RSRPP" },
  {   6, "ul-RSCP" },
  { 0, NULL }
};


static int
dissect_nrppa_TRPMeasurementType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 3, NULL);

  return offset;
}


static const per_sequence_t TRPMeasurementQuantitiesList_Item_sequence[] = {
  { &hf_nrppa_tRPMeasurementQuantities_Item, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPMeasurementType },
  { &hf_nrppa_timingReportingGranularityFactor, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_5 },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPMeasurementQuantitiesList_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPMeasurementQuantitiesList_Item, TRPMeasurementQuantitiesList_Item_sequence);

  return offset;
}


static const per_sequence_t TRPMeasurementQuantities_sequence_of[1] = {
  { &hf_nrppa_TRPMeasurementQuantities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPMeasurementQuantitiesList_Item },
};

static int
dissect_nrppa_TRPMeasurementQuantities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRPMeasurementQuantities, TRPMeasurementQuantities_sequence_of,
                                                  1, maxnoPosMeas, false);

  return offset;
}



static int
dissect_nrppa_UL_SRS_RSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 126U, NULL, false);

  return offset;
}


static const value_string nrppa_ULRTOAMeas_vals[] = {
  {   0, "k0" },
  {   1, "k1" },
  {   2, "k2" },
  {   3, "k3" },
  {   4, "k4" },
  {   5, "k5" },
  {   6, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t ULRTOAMeas_choice[] = {
  {   0, &hf_nrppa_k0            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_1970049 },
  {   1, &hf_nrppa_k1            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_985025 },
  {   2, &hf_nrppa_k2            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_492513 },
  {   3, &hf_nrppa_k3            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_246257 },
  {   4, &hf_nrppa_k4            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_123129 },
  {   5, &hf_nrppa_k5            , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_61565 },
  {   6, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_ULRTOAMeas(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_ULRTOAMeas, ULRTOAMeas_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UL_RTOAMeasurement_sequence[] = {
  { &hf_nrppa_uLRTOAmeas    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ULRTOAMeas },
  { &hf_nrppa_additionalPathList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_AdditionalPathList },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_UL_RTOAMeasurement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_UL_RTOAMeasurement, UL_RTOAMeasurement_sequence);

  return offset;
}


static const value_string nrppa_TrpMeasuredResultsValue_vals[] = {
  {   0, "uL-AngleOfArrival" },
  {   1, "uL-SRS-RSRP" },
  {   2, "uL-RTOA" },
  {   3, "gNB-RxTxTimeDiff" },
  {   4, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TrpMeasuredResultsValue_choice[] = {
  {   0, &hf_nrppa_uL_AngleOfArrival, ASN1_NO_EXTENSIONS     , dissect_nrppa_UL_AoA },
  {   1, &hf_nrppa_uL_SRS_RSRP   , ASN1_NO_EXTENSIONS     , dissect_nrppa_UL_SRS_RSRP },
  {   2, &hf_nrppa_uL_RTOA       , ASN1_NO_EXTENSIONS     , dissect_nrppa_UL_RTOAMeasurement },
  {   3, &hf_nrppa_gNB_RxTxTimeDiff, ASN1_NO_EXTENSIONS     , dissect_nrppa_GNB_RxTxTimeDiff },
  {   4, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TrpMeasuredResultsValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TrpMeasuredResultsValue, TrpMeasuredResultsValue_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TrpMeasurementResultItem_sequence[] = {
  { &hf_nrppa_measuredResultsValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TrpMeasuredResultsValue },
  { &hf_nrppa_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TimeStamp },
  { &hf_nrppa_measurementQuality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TrpMeasurementQuality },
  { &hf_nrppa_measurementBeamInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_MeasurementBeamInfo },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TrpMeasurementResultItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TrpMeasurementResultItem, TrpMeasurementResultItem_sequence);

  return offset;
}


static const per_sequence_t TrpMeasurementResult_sequence_of[1] = {
  { &hf_nrppa_TrpMeasurementResult_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TrpMeasurementResultItem },
};

static int
dissect_nrppa_TrpMeasurementResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TrpMeasurementResult, TrpMeasurementResult_sequence_of,
                                                  1, maxnoPosMeas, false);

  return offset;
}


static const value_string nrppa_T_resolution_02_vals[] = {
  {   0, "deg0dot1" },
  {   1, "deg1" },
  { 0, NULL }
};


static int
dissect_nrppa_T_resolution_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TRPPhaseQuality_sequence[] = {
  { &hf_nrppa_phaseQualityIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_179 },
  { &hf_nrppa_resolution_02 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_resolution_02 },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPPhaseQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPPhaseQuality, TRPPhaseQuality_sequence);

  return offset;
}


static const per_sequence_t TRP_MeasurementRequestItem_sequence[] = {
  { &hf_nrppa_tRP_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_ID },
  { &hf_nrppa_search_window_information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_Search_window_information },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_MeasurementRequestItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_MeasurementRequestItem, TRP_MeasurementRequestItem_sequence);

  return offset;
}


static const per_sequence_t TRP_MeasurementRequestList_sequence_of[1] = {
  { &hf_nrppa_TRP_MeasurementRequestList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_MeasurementRequestItem },
};

static int
dissect_nrppa_TRP_MeasurementRequestList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRP_MeasurementRequestList, TRP_MeasurementRequestList_sequence_of,
                                                  1, maxNoOfMeasTRPs, false);

  return offset;
}


static const per_sequence_t TRP_MeasurementResponseItem_sequence[] = {
  { &hf_nrppa_tRP_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_ID },
  { &hf_nrppa_measurementResult, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TrpMeasurementResult },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_MeasurementResponseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_MeasurementResponseItem, TRP_MeasurementResponseItem_sequence);

  return offset;
}


static const per_sequence_t TRP_MeasurementResponseList_sequence_of[1] = {
  { &hf_nrppa_TRP_MeasurementResponseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_MeasurementResponseItem },
};

static int
dissect_nrppa_TRP_MeasurementResponseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRP_MeasurementResponseList, TRP_MeasurementResponseList_sequence_of,
                                                  1, maxNoOfMeasTRPs, false);

  return offset;
}


static const per_sequence_t TRP_MeasurementUpdateItem_sequence[] = {
  { &hf_nrppa_tRP_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_ID },
  { &hf_nrppa_aoA_window_information, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_AoA_AssistanceInfo },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_MeasurementUpdateItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_MeasurementUpdateItem, TRP_MeasurementUpdateItem_sequence);

  return offset;
}


static const per_sequence_t TRP_MeasurementUpdateList_sequence_of[1] = {
  { &hf_nrppa_TRP_MeasurementUpdateList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_MeasurementUpdateItem },
};

static int
dissect_nrppa_TRP_MeasurementUpdateList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRP_MeasurementUpdateList, TRP_MeasurementUpdateList_sequence_of,
                                                  1, maxNoOfMeasTRPs, false);

  return offset;
}


static const value_string nrppa_TRPInformationTypeResponseItem_vals[] = {
  {   0, "pCI-NR" },
  {   1, "cGI-NR" },
  {   2, "aRFCN" },
  {   3, "pRSConfiguration" },
  {   4, "sSBinformation" },
  {   5, "sFNInitialisationTime" },
  {   6, "spatialDirectionInformation" },
  {   7, "geographicalCoordinates" },
  {   8, "choice-extension" },
  { 0, NULL }
};

static const per_choice_t TRPInformationTypeResponseItem_choice[] = {
  {   0, &hf_nrppa_pCI_NR        , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_1007 },
  {   1, &hf_nrppa_cGI_NR        , ASN1_NO_EXTENSIONS     , dissect_nrppa_CGI_NR },
  {   2, &hf_nrppa_aRFCN         , ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_3279165 },
  {   3, &hf_nrppa_pRSConfiguration, ASN1_NO_EXTENSIONS     , dissect_nrppa_PRSConfiguration },
  {   4, &hf_nrppa_sSBinformation, ASN1_NO_EXTENSIONS     , dissect_nrppa_SSBInfo },
  {   5, &hf_nrppa_sFNInitialisationTime, ASN1_NO_EXTENSIONS     , dissect_nrppa_RelativeTime1900 },
  {   6, &hf_nrppa_spatialDirectionInformation, ASN1_NO_EXTENSIONS     , dissect_nrppa_SpatialDirectionInformation },
  {   7, &hf_nrppa_geographicalCoordinates, ASN1_NO_EXTENSIONS     , dissect_nrppa_GeographicalCoordinates },
  {   8, &hf_nrppa_choice_extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_TRPInformationTypeResponseItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_TRPInformationTypeResponseItem, TRPInformationTypeResponseItem_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t TRPInformationTypeResponseList_sequence_of[1] = {
  { &hf_nrppa_TRPInformationTypeResponseList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPInformationTypeResponseItem },
};

static int
dissect_nrppa_TRPInformationTypeResponseList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRPInformationTypeResponseList, TRPInformationTypeResponseList_sequence_of,
                                                  1, maxnoTRPInfoTypes, false);

  return offset;
}


static const per_sequence_t TRPInformation_sequence[] = {
  { &hf_nrppa_tRP_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_ID },
  { &hf_nrppa_tRPInformationTypeResponseList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPInformationTypeResponseList },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPInformation, TRPInformation_sequence);

  return offset;
}


static const per_sequence_t TRPInformationListTRPResp_item_sequence[] = {
  { &hf_nrppa_tRPInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPInformation },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPInformationListTRPResp_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPInformationListTRPResp_item, TRPInformationListTRPResp_item_sequence);

  return offset;
}


static const per_sequence_t TRPInformationListTRPResp_sequence_of[1] = {
  { &hf_nrppa_TRPInformationListTRPResp_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPInformationListTRPResp_item },
};

static int
dissect_nrppa_TRPInformationListTRPResp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRPInformationListTRPResp, TRPInformationListTRPResp_sequence_of,
                                                  1, maxnoTRPs, false);

  return offset;
}


static const per_sequence_t TRPInformationTypeListTRPReq_sequence_of[1] = {
  { &hf_nrppa_TRPInformationTypeListTRPReq_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Single_Container },
};

static int
dissect_nrppa_TRPInformationTypeListTRPReq(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRPInformationTypeListTRPReq, TRPInformationTypeListTRPReq_sequence_of,
                                                  1, maxnoTRPInfoTypes, false);

  return offset;
}


static const value_string nrppa_TRPInformationTypeItem_vals[] = {
  {   0, "nrPCI" },
  {   1, "nG-RAN-CGI" },
  {   2, "arfcn" },
  {   3, "pRSConfig" },
  {   4, "sSBInfo" },
  {   5, "sFNInitTime" },
  {   6, "spatialDirectInfo" },
  {   7, "geoCoord" },
  {   8, "trp-type" },
  {   9, "ondemandPRSInfo" },
  {  10, "trpTxTeg" },
  {  11, "beam-antenna-info" },
  {  12, "mobile-trp-location-info" },
  {  13, "commonTA" },
  { 0, NULL }
};


static int
dissect_nrppa_TRPInformationTypeItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 6, NULL);

  return offset;
}


static const per_sequence_t TRPItem_sequence[] = {
  { &hf_nrppa_tRP_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_ID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPItem, TRPItem_sequence);

  return offset;
}


static const per_sequence_t TRPList_sequence_of[1] = {
  { &hf_nrppa_TRPList_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPItem },
};

static int
dissect_nrppa_TRPList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRPList, TRPList_sequence_of,
                                                  1, maxnoTRPs, false);

  return offset;
}


static const per_sequence_t TRP_PRS_Information_List_Item_sequence[] = {
  { &hf_nrppa_tRP_ID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_ID },
  { &hf_nrppa_nR_PCI        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_NR_PCI },
  { &hf_nrppa_cGI_NR        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CGI_NR },
  { &hf_nrppa_pRSConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRSConfiguration },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRP_PRS_Information_List_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRP_PRS_Information_List_Item, TRP_PRS_Information_List_Item_sequence);

  return offset;
}


static const per_sequence_t TRP_PRS_Information_List_sequence_of[1] = {
  { &hf_nrppa_TRP_PRS_Information_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_PRS_Information_List_Item },
};

static int
dissect_nrppa_TRP_PRS_Information_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRP_PRS_Information_List, TRP_PRS_Information_List_sequence_of,
                                                  1, maxnoPRSTRPs, false);

  return offset;
}


static const per_sequence_t DLPRSResourceID_Item_sequence[] = {
  { &hf_nrppa_dl_PRSResourceID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_ID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_DLPRSResourceID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_DLPRSResourceID_Item, DLPRSResourceID_Item_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceID_Item_sequence_of[1] = {
  { &hf_nrppa_dl_PRSResourceID_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_DLPRSResourceID_Item },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceID_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceID_Item, SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceID_Item_sequence_of,
                                                  1, maxPRS_ResourcesPerSet, false);

  return offset;
}


static const per_sequence_t TRPTEGItem_sequence[] = {
  { &hf_nrppa_tRP_Tx_TEGInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TRP_Tx_TEGInformation },
  { &hf_nrppa_dl_PRSResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PRS_Resource_Set_ID },
  { &hf_nrppa_dl_PRSResourceID_List, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceID_Item },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPTEGItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPTEGItem, TRPTEGItem_sequence);

  return offset;
}


static const per_sequence_t TRPTxTEGAssociation_sequence_of[1] = {
  { &hf_nrppa_TRPTxTEGAssociation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_TRPTEGItem },
};

static int
dissect_nrppa_TRPTxTEGAssociation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_TRPTxTEGAssociation, TRPTxTEGAssociation_sequence_of,
                                                  1, maxnoTRPTEGs, false);

  return offset;
}


static const value_string nrppa_TRPType_vals[] = {
  {   0, "prsOnlyTP" },
  {   1, "srsOnlyRP" },
  {   2, "tp" },
  {   3, "rp" },
  {   4, "trp" },
  {   5, "mobile-trp" },
  { 0, NULL }
};


static int
dissect_nrppa_TRPType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 1, NULL);

  return offset;
}


static const value_string nrppa_T_overlapValue_vals[] = {
  {   0, "rb0" },
  {   1, "rb1" },
  {   2, "rb2" },
  {   3, "rb4" },
  { 0, NULL }
};


static int
dissect_nrppa_T_overlapValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_1_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 6U, NULL, false);

  return offset;
}


static const per_sequence_t TxHoppingConfiguration_sequence[] = {
  { &hf_nrppa_overlapValue  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_overlapValue },
  { &hf_nrppa_numberOfHops  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_1_6 },
  { &hf_nrppa_slotOffsetForRemainingHopsList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SlotOffsetForRemainingHopsList },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TxHoppingConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TxHoppingConfiguration, TxHoppingConfiguration_sequence);

  return offset;
}



static int
dissect_nrppa_UE_Measurement_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, true);

  return offset;
}


static const value_string nrppa_T_reportingAmount_vals[] = {
  {   0, "ma0" },
  {   1, "ma1" },
  {   2, "ma2" },
  {   3, "ma4" },
  {   4, "ma8" },
  {   5, "ma16" },
  {   6, "ma32" },
  {   7, "ma64" },
  { 0, NULL }
};


static int
dissect_nrppa_T_reportingAmount(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, false, 0, NULL);

  return offset;
}


static const value_string nrppa_T_reportingInterval_vals[] = {
  {   0, "none" },
  {   1, "one" },
  {   2, "two" },
  {   3, "four" },
  {   4, "eight" },
  {   5, "ten" },
  {   6, "sixteen" },
  {   7, "twenty" },
  {   8, "thirty-two" },
  {   9, "sixty-four" },
  { 0, NULL }
};


static int
dissect_nrppa_T_reportingInterval(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t UEReportingInformation_sequence[] = {
  { &hf_nrppa_reportingAmount, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_reportingAmount },
  { &hf_nrppa_reportingInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_reportingInterval },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_UEReportingInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_UEReportingInformation, UEReportingInformation_sequence);

  return offset;
}



static int
dissect_nrppa_UE_Rx_Tx_Time_Diff(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 61565U, NULL, false);

  return offset;
}


static const value_string nrppa_UE_TEG_ReportingPeriodicity_vals[] = {
  {   0, "ms160" },
  {   1, "ms320" },
  {   2, "ms1280" },
  {   3, "ms2560" },
  {   4, "ms61440" },
  {   5, "ms81920" },
  {   6, "ms368640" },
  {   7, "ms737280" },
  { 0, NULL }
};


static int
dissect_nrppa_UE_TEG_ReportingPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t UETxTEGAssociationItem_sequence[] = {
  { &hf_nrppa_uE_Tx_TEG_ID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_7 },
  { &hf_nrppa_posSRSResourceID_List, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PosSRSResourceID_List },
  { &hf_nrppa_timeStamp     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_TimeStamp },
  { &hf_nrppa_carrierFreq   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_CarrierFreq },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_UETxTEGAssociationItem(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_UETxTEGAssociationItem, UETxTEGAssociationItem_sequence);

  return offset;
}


static const per_sequence_t UETxTEGAssociationList_sequence_of[1] = {
  { &hf_nrppa_UETxTEGAssociationList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_UETxTEGAssociationItem },
};

static int
dissect_nrppa_UETxTEGAssociationList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_UETxTEGAssociationList, UETxTEGAssociationList_sequence_of,
                                                  1, maxnoUETEGs, false);

  return offset;
}


static const value_string nrppa_UE_TEG_Info_Request_vals[] = {
  {   0, "onDemand" },
  {   1, "periodic" },
  {   2, "stop" },
  { 0, NULL }
};


static int
dissect_nrppa_UE_TEG_Info_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t UL_RSCPMeas_sequence[] = {
  { &hf_nrppa_uLRSCP        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_INTEGER_0_3599 },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_UL_RSCPMeas(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_UL_RSCPMeas, UL_RSCPMeas_sequence);

  return offset;
}


static const per_sequence_t ValidityAreaSpecificSRSInformation_sequence[] = {
  { &hf_nrppa_transmissionCombPos, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_TransmissionCombPos },
  { &hf_nrppa_resourceMapping, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ResourceMapping },
  { &hf_nrppa_freqDomainShift, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_268 },
  { &hf_nrppa_c_SRS         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_63 },
  { &hf_nrppa_resourceTypePos, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ResourceTypePos },
  { &hf_nrppa_sequenceIDPos , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_INTEGER_0_65535 },
  { &hf_nrppa_iE_extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ValidityAreaSpecificSRSInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ValidityAreaSpecificSRSInformation, ValidityAreaSpecificSRSInformation_sequence);

  return offset;
}


static const per_sequence_t WLANMeasurementQuantities_sequence_of[1] = {
  { &hf_nrppa_WLANMeasurementQuantities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Single_Container },
};

static int
dissect_nrppa_WLANMeasurementQuantities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_WLANMeasurementQuantities, WLANMeasurementQuantities_sequence_of,
                                                  0, maxNoMeas, false);

  return offset;
}


static const value_string nrppa_WLANMeasurementQuantitiesValue_vals[] = {
  {   0, "wlan" },
  { 0, NULL }
};


static int
dissect_nrppa_WLANMeasurementQuantitiesValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t WLANMeasurementQuantities_Item_sequence[] = {
  { &hf_nrppa_wLANMeasurementQuantitiesValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_WLANMeasurementQuantitiesValue },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_WLANMeasurementQuantities_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_WLANMeasurementQuantities_Item, WLANMeasurementQuantities_Item_sequence);

  return offset;
}



static int
dissect_nrppa_WLAN_RSSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 141U, NULL, true);

  return offset;
}



static int
dissect_nrppa_WLANOperatingClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const value_string nrppa_WLANCountryCode_vals[] = {
  {   0, "unitedStates" },
  {   1, "europe" },
  {   2, "japan" },
  {   3, "global" },
  { 0, NULL }
};


static int
dissect_nrppa_WLANCountryCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_nrppa_WLANChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t WLANChannelList_sequence_of[1] = {
  { &hf_nrppa_WLANChannelList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_WLANChannel },
};

static int
dissect_nrppa_WLANChannelList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_WLANChannelList, WLANChannelList_sequence_of,
                                                  1, maxWLANchannels, false);

  return offset;
}


static const value_string nrppa_WLANBand_vals[] = {
  {   0, "band2dot4" },
  {   1, "band5" },
  { 0, NULL }
};


static int
dissect_nrppa_WLANBand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t WLANMeasurementResult_Item_sequence[] = {
  { &hf_nrppa_wLAN_RSSI     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_WLAN_RSSI },
  { &hf_nrppa_sSID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SSID },
  { &hf_nrppa_bSSID         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_BSSID },
  { &hf_nrppa_hESSID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_HESSID },
  { &hf_nrppa_operatingClass, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_WLANOperatingClass },
  { &hf_nrppa_countryCode   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_WLANCountryCode },
  { &hf_nrppa_wLANChannelList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_WLANChannelList },
  { &hf_nrppa_wLANBand      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_WLANBand },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_WLANMeasurementResult_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_WLANMeasurementResult_Item, WLANMeasurementResult_Item_sequence);

  return offset;
}


static const per_sequence_t WLANMeasurementResult_sequence_of[1] = {
  { &hf_nrppa_WLANMeasurementResult_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_WLANMeasurementResult_Item },
};

static int
dissect_nrppa_WLANMeasurementResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_WLANMeasurementResult, WLANMeasurementResult_sequence_of,
                                                  1, maxNoMeas, false);

  return offset;
}


static const per_sequence_t E_CIDMeasurementInitiationRequest_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_E_CIDMeasurementInitiationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_E_CIDMeasurementInitiationRequest, E_CIDMeasurementInitiationRequest_sequence);

  return offset;
}


static const per_sequence_t E_CIDMeasurementInitiationResponse_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_E_CIDMeasurementInitiationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_E_CIDMeasurementInitiationResponse, E_CIDMeasurementInitiationResponse_sequence);

  return offset;
}


static const per_sequence_t E_CIDMeasurementInitiationFailure_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_E_CIDMeasurementInitiationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_E_CIDMeasurementInitiationFailure, E_CIDMeasurementInitiationFailure_sequence);

  return offset;
}


static const per_sequence_t E_CIDMeasurementFailureIndication_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_E_CIDMeasurementFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_E_CIDMeasurementFailureIndication, E_CIDMeasurementFailureIndication_sequence);

  return offset;
}


static const per_sequence_t E_CIDMeasurementReport_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_E_CIDMeasurementReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_E_CIDMeasurementReport, E_CIDMeasurementReport_sequence);

  return offset;
}


static const per_sequence_t E_CIDMeasurementTerminationCommand_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_E_CIDMeasurementTerminationCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_E_CIDMeasurementTerminationCommand, E_CIDMeasurementTerminationCommand_sequence);

  return offset;
}


static const per_sequence_t OTDOAInformationRequest_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_OTDOAInformationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_OTDOAInformationRequest, OTDOAInformationRequest_sequence);

  return offset;
}


static const per_sequence_t OTDOA_Information_Type_sequence_of[1] = {
  { &hf_nrppa_OTDOA_Information_Type_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Single_Container },
};

static int
dissect_nrppa_OTDOA_Information_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_OTDOA_Information_Type, OTDOA_Information_Type_sequence_of,
                                                  1, maxnoOTDOAtypes, false);

  return offset;
}


static const per_sequence_t OTDOA_Information_Type_Item_sequence[] = {
  { &hf_nrppa_oTDOA_Information_Item, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_OTDOA_Information_Item },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_OTDOA_Information_Type_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_OTDOA_Information_Type_Item, OTDOA_Information_Type_Item_sequence);

  return offset;
}


static const per_sequence_t OTDOAInformationResponse_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_OTDOAInformationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_OTDOAInformationResponse, OTDOAInformationResponse_sequence);

  return offset;
}


static const per_sequence_t OTDOAInformationFailure_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_OTDOAInformationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_OTDOAInformationFailure, OTDOAInformationFailure_sequence);

  return offset;
}


static const per_sequence_t AssistanceInformationControl_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_AssistanceInformationControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_AssistanceInformationControl, AssistanceInformationControl_sequence);

  return offset;
}


static const per_sequence_t AssistanceInformationFeedback_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_AssistanceInformationFeedback(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_AssistanceInformationFeedback, AssistanceInformationFeedback_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_nrppa_privateIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PrivateMessage, PrivateMessage_sequence);

  return offset;
}


static const per_sequence_t PositioningInformationRequest_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PositioningInformationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PositioningInformationRequest, PositioningInformationRequest_sequence);

  return offset;
}


static const per_sequence_t PositioningInformationResponse_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PositioningInformationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PositioningInformationResponse, PositioningInformationResponse_sequence);

  return offset;
}


static const per_sequence_t PositioningInformationFailure_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PositioningInformationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PositioningInformationFailure, PositioningInformationFailure_sequence);

  return offset;
}


static const per_sequence_t PositioningInformationUpdate_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PositioningInformationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PositioningInformationUpdate, PositioningInformationUpdate_sequence);

  return offset;
}


static const per_sequence_t MeasurementRequest_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementRequest, MeasurementRequest_sequence);

  return offset;
}


static const per_sequence_t MeasurementResponse_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementResponse, MeasurementResponse_sequence);

  return offset;
}


static const per_sequence_t MeasurementFailure_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementFailure, MeasurementFailure_sequence);

  return offset;
}


static const per_sequence_t MeasurementReport_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementReport, MeasurementReport_sequence);

  return offset;
}


static const per_sequence_t MeasurementUpdate_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementUpdate, MeasurementUpdate_sequence);

  return offset;
}


static const per_sequence_t MeasurementAbort_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementAbort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementAbort, MeasurementAbort_sequence);

  return offset;
}


static const per_sequence_t MeasurementFailureIndication_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementFailureIndication, MeasurementFailureIndication_sequence);

  return offset;
}


static const per_sequence_t TRPInformationRequest_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPInformationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPInformationRequest, TRPInformationRequest_sequence);

  return offset;
}


static const per_sequence_t TRPInformationResponse_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPInformationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPInformationResponse, TRPInformationResponse_sequence);

  return offset;
}


static const per_sequence_t TRPInformationFailure_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_TRPInformationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_TRPInformationFailure, TRPInformationFailure_sequence);

  return offset;
}


static const per_sequence_t PositioningActivationRequest_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PositioningActivationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PositioningActivationRequest, PositioningActivationRequest_sequence);

  return offset;
}


static const per_sequence_t SemipersistentSRS_sequence[] = {
  { &hf_nrppa_sRSResourceSetID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_SRSResourceSetID },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SemipersistentSRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SemipersistentSRS, SemipersistentSRS_sequence);

  return offset;
}


static const value_string nrppa_T_aperiodic_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_nrppa_T_aperiodic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t AperiodicSRS_sequence[] = {
  { &hf_nrppa_aperiodic_05  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_T_aperiodic },
  { &hf_nrppa_sRSResourceTrigger_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_SRSResourceTrigger },
  { &hf_nrppa_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nrppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_AperiodicSRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_AperiodicSRS, AperiodicSRS_sequence);

  return offset;
}


static const value_string nrppa_SRSType_vals[] = {
  {   0, "semipersistentSRS" },
  {   1, "aperiodicSRS" },
  {   2, "choice-Extension" },
  { 0, NULL }
};

static const per_choice_t SRSType_choice[] = {
  {   0, &hf_nrppa_semipersistentSRS, ASN1_NO_EXTENSIONS     , dissect_nrppa_SemipersistentSRS },
  {   1, &hf_nrppa_aperiodicSRS  , ASN1_NO_EXTENSIONS     , dissect_nrppa_AperiodicSRS },
  {   2, &hf_nrppa_choice_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
  { 0, NULL, 0, NULL }
};

static int
dissect_nrppa_SRSType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_SRSType, SRSType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PositioningActivationResponse_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PositioningActivationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PositioningActivationResponse, PositioningActivationResponse_sequence);

  return offset;
}


static const per_sequence_t PositioningActivationFailure_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PositioningActivationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PositioningActivationFailure, PositioningActivationFailure_sequence);

  return offset;
}


static const per_sequence_t PositioningDeactivation_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PositioningDeactivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PositioningDeactivation, PositioningDeactivation_sequence);

  return offset;
}


static const per_sequence_t PRSConfigurationRequest_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSConfigurationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSConfigurationRequest, PRSConfigurationRequest_sequence);

  return offset;
}


static const per_sequence_t PRSConfigurationResponse_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSConfigurationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSConfigurationResponse, PRSConfigurationResponse_sequence);

  return offset;
}


static const per_sequence_t PRSConfigurationFailure_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_PRSConfigurationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_PRSConfigurationFailure, PRSConfigurationFailure_sequence);

  return offset;
}


static const per_sequence_t MeasurementPreconfigurationRequired_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementPreconfigurationRequired(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementPreconfigurationRequired, MeasurementPreconfigurationRequired_sequence);

  return offset;
}


static const per_sequence_t MeasurementPreconfigurationConfirm_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementPreconfigurationConfirm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementPreconfigurationConfirm, MeasurementPreconfigurationConfirm_sequence);

  return offset;
}


static const per_sequence_t MeasurementPreconfigurationRefuse_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementPreconfigurationRefuse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementPreconfigurationRefuse, MeasurementPreconfigurationRefuse_sequence);

  return offset;
}


static const per_sequence_t MeasurementActivation_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_MeasurementActivation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_MeasurementActivation, MeasurementActivation_sequence);

  return offset;
}


static const per_sequence_t SRSInformationReservationNotification_sequence[] = {
  { &hf_nrppa_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_nrppa_SRSInformationReservationNotification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_nrppa_SRSInformationReservationNotification, SRSInformationReservationNotification_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_NRPPA_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_NRPPA_PDU(tvb, offset, &asn1_ctx, tree, hf_nrppa_NRPPA_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AbortTransmission_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_AbortTransmission(tvb, offset, &asn1_ctx, tree, hf_nrppa_AbortTransmission_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AggregatedPosSRSResourceID_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_AggregatedPosSRSResourceID_List(tvb, offset, &asn1_ctx, tree, hf_nrppa_AggregatedPosSRSResourceID_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AggregatedPRSResourceSetList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_AggregatedPRSResourceSetList(tvb, offset, &asn1_ctx, tree, hf_nrppa_AggregatedPRSResourceSetList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedAdditionalPathList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ExtendedAdditionalPathList(tvb, offset, &asn1_ctx, tree, hf_nrppa_ExtendedAdditionalPathList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AoA_AssistanceInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_AoA_AssistanceInfo(tvb, offset, &asn1_ctx, tree, hf_nrppa_AoA_AssistanceInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ARP_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ARP_ID(tvb, offset, &asn1_ctx, tree, hf_nrppa_ARP_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ARPLocationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ARPLocationInformation(tvb, offset, &asn1_ctx, tree, hf_nrppa_ARPLocationInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nrppa_Assistance_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_Assistance_Information(tvb, offset, &asn1_ctx, tree, hf_nrppa_nrppa_Assistance_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AssistanceInformationFailureList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_AssistanceInformationFailureList(tvb, offset, &asn1_ctx, tree, hf_nrppa_AssistanceInformationFailureList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Bandwidth_Aggregation_Request_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_Bandwidth_Aggregation_Request_Indication(tvb, offset, &asn1_ctx, tree, hf_nrppa_Bandwidth_Aggregation_Request_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Broadcast_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_Broadcast(tvb, offset, &asn1_ctx, tree, hf_nrppa_Broadcast_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningBroadcastCells_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PositioningBroadcastCells(tvb, offset, &asn1_ctx, tree, hf_nrppa_PositioningBroadcastCells_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_Cause(tvb, offset, &asn1_ctx, tree, hf_nrppa_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cell_Portion_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_Cell_Portion_ID(tvb, offset, &asn1_ctx, tree, hf_nrppa_Cell_Portion_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CGI_NR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_CGI_NR(tvb, offset, &asn1_ctx, tree, hf_nrppa_CGI_NR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_nrppa_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CommonTAParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_CommonTAParameters(tvb, offset, &asn1_ctx, tree, hf_nrppa_CommonTAParameters_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CID_MeasurementResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_E_CID_MeasurementResult(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CID_MeasurementResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_GeographicalCoordinates_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_GeographicalCoordinates(tvb, offset, &asn1_ctx, tree, hf_nrppa_GeographicalCoordinates_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LoS_NLoSInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_LoS_NLoSInformation(tvb, offset, &asn1_ctx, tree, hf_nrppa_LoS_NLoSInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasBasedOnAggregatedResources_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasBasedOnAggregatedResources(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasBasedOnAggregatedResources_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Measurement_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_Measurement_ID(tvb, offset, &asn1_ctx, tree, hf_nrppa_Measurement_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementAmount_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementAmount(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementAmount_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementBeamInfoRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementBeamInfoRequest(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementBeamInfoRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementPeriodicity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementPeriodicity(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementPeriodicity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementPeriodicityExtended_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementPeriodicityExtended(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementPeriodicityExtended_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementPeriodicityNR_AoA_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementPeriodicityNR_AoA(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementPeriodicityNR_AoA_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementQuantities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementQuantities(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementQuantities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementQuantities_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementQuantities_Item(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementQuantities_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementTimeOccasion_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementTimeOccasion(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementTimeOccasion_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementCharacteristicsRequestIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementCharacteristicsRequestIndicator(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementCharacteristicsRequestIndicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasuredResultsAssociatedInfoList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasuredResultsAssociatedInfoList(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasuredResultsAssociatedInfoList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Mobile_TRP_LocationInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_Mobile_TRP_LocationInformation(tvb, offset, &asn1_ctx, tree, hf_nrppa_Mobile_TRP_LocationInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Mobile_IAB_MT_UE_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_Mobile_IAB_MT_UE_ID(tvb, offset, &asn1_ctx, tree, hf_nrppa_Mobile_IAB_MT_UE_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MultipleULAoA_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MultipleULAoA(tvb, offset, &asn1_ctx, tree, hf_nrppa_MultipleULAoA_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasuredFrequencyHops_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasuredFrequencyHops(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasuredFrequencyHops_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NrofSymbolsExtended_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_NrofSymbolsExtended(tvb, offset, &asn1_ctx, tree, hf_nrppa_NrofSymbolsExtended_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NR_PCI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_NR_PCI(tvb, offset, &asn1_ctx, tree, hf_nrppa_NR_PCI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NR_TADV_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_NR_TADV(tvb, offset, &asn1_ctx, tree, hf_nrppa_NR_TADV_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NumberOfTRPRxTEG_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_NumberOfTRPRxTEG(tvb, offset, &asn1_ctx, tree, hf_nrppa_NumberOfTRPRxTEG_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_NumberOfTRPRxTxTEG_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_NumberOfTRPRxTxTEG(tvb, offset, &asn1_ctx, tree, hf_nrppa_NumberOfTRPRxTxTEG_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OnDemandPRS_Info_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_OnDemandPRS_Info(tvb, offset, &asn1_ctx, tree, hf_nrppa_OnDemandPRS_Info_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOACells_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_OTDOACells(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOACells_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OtherRATMeasurementQuantities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_OtherRATMeasurementQuantities(tvb, offset, &asn1_ctx, tree, hf_nrppa_OtherRATMeasurementQuantities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OtherRATMeasurementQuantities_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_OtherRATMeasurementQuantities_Item(tvb, offset, &asn1_ctx, tree, hf_nrppa_OtherRATMeasurementQuantities_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OtherRATMeasurementResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_OtherRATMeasurementResult(tvb, offset, &asn1_ctx, tree, hf_nrppa_OtherRATMeasurementResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRSBWAggregationRequestIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PRSBWAggregationRequestIndication(tvb, offset, &asn1_ctx, tree, hf_nrppa_PRSBWAggregationRequestIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PosSRSResourceSet_Aggregation_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PosSRSResourceSet_Aggregation_List(tvb, offset, &asn1_ctx, tree, hf_nrppa_PosSRSResourceSet_Aggregation_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PreconfigurationResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PreconfigurationResult(tvb, offset, &asn1_ctx, tree, hf_nrppa_PreconfigurationResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRSConfigRequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PRSConfigRequestType(tvb, offset, &asn1_ctx, tree, hf_nrppa_PRSConfigRequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRS_Measurements_Info_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PRS_Measurements_Info_List(tvb, offset, &asn1_ctx, tree, hf_nrppa_PRS_Measurements_Info_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ExtendedResourceSymbolOffset_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ExtendedResourceSymbolOffset(tvb, offset, &asn1_ctx, tree, hf_nrppa_ExtendedResourceSymbolOffset_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRS_Resource_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PRS_Resource_ID(tvb, offset, &asn1_ctx, tree, hf_nrppa_PRS_Resource_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRSTRPList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PRSTRPList(tvb, offset, &asn1_ctx, tree, hf_nrppa_PRSTRPList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRSTransmissionTRPList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PRSTransmissionTRPList(tvb, offset, &asn1_ctx, tree, hf_nrppa_PRSTransmissionTRPList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PosValidityAreaCellList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PosValidityAreaCellList(tvb, offset, &asn1_ctx, tree, hf_nrppa_PosValidityAreaCellList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PointA_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PointA(tvb, offset, &asn1_ctx, tree, hf_nrppa_PointA_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RepetitionFactorExtended_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_RepetitionFactorExtended(tvb, offset, &asn1_ctx, tree, hf_nrppa_RepetitionFactorExtended_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportCharacteristics(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportCharacteristics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus1(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus1_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus2(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus2_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus3(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus3_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus4_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus4(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus4_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus5_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus5(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus5_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus6_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus6(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus6_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus1AdditionalPath_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus1AdditionalPath(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus1AdditionalPath_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus2AdditionalPath_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus2AdditionalPath(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus2AdditionalPath_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus3AdditionalPath_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus3AdditionalPath(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus3AdditionalPath_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus4AdditionalPath_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus4AdditionalPath(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus4AdditionalPath_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus5AdditionalPath_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus5AdditionalPath(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus5AdditionalPath_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportingGranularitykminus6AdditionalPath_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ReportingGranularitykminus6AdditionalPath(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportingGranularitykminus6AdditionalPath_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestedSRSTransmissionCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_RequestedSRSTransmissionCharacteristics(tvb, offset, &asn1_ctx, tree, hf_nrppa_RequestedSRSTransmissionCharacteristics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestedSRSPreconfigurationCharacteristics_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_RequestedSRSPreconfigurationCharacteristics_List(tvb, offset, &asn1_ctx, tree, hf_nrppa_RequestedSRSPreconfigurationCharacteristics_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_RequestType(tvb, offset, &asn1_ctx, tree, hf_nrppa_RequestType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResponseTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ResponseTime(tvb, offset, &asn1_ctx, tree, hf_nrppa_ResponseTime_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResultCSI_RSRP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ResultCSI_RSRP(tvb, offset, &asn1_ctx, tree, hf_nrppa_ResultCSI_RSRP_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResultCSI_RSRQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ResultCSI_RSRQ(tvb, offset, &asn1_ctx, tree, hf_nrppa_ResultCSI_RSRQ_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResultEUTRA_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ResultEUTRA(tvb, offset, &asn1_ctx, tree, hf_nrppa_ResultEUTRA_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResultSS_RSRP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ResultSS_RSRP(tvb, offset, &asn1_ctx, tree, hf_nrppa_ResultSS_RSRP_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResultSS_RSRQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ResultSS_RSRQ(tvb, offset, &asn1_ctx, tree, hf_nrppa_ResultSS_RSRQ_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ResultNR_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ResultNR(tvb, offset, &asn1_ctx, tree, hf_nrppa_ResultNR_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCS_480_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SCS_480(tvb, offset, &asn1_ctx, tree, hf_nrppa_SCS_480_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCS_960_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SCS_960(tvb, offset, &asn1_ctx, tree, hf_nrppa_SCS_960_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SCS_SpecificCarrier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SCS_SpecificCarrier(tvb, offset, &asn1_ctx, tree, hf_nrppa_SCS_SpecificCarrier_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RelativeTime1900_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_RelativeTime1900(tvb, offset, &asn1_ctx, tree, hf_nrppa_RelativeTime1900_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SFNInitialisationTime_EUTRA_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SFNInitialisationTime_EUTRA(tvb, offset, &asn1_ctx, tree, hf_nrppa_SFNInitialisationTime_EUTRA_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SlotNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SlotNumber(tvb, offset, &asn1_ctx, tree, hf_nrppa_SlotNumber_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SpatialRelationInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SpatialRelationInfo(tvb, offset, &asn1_ctx, tree, hf_nrppa_SpatialRelationInfo_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SpatialRelationPerSRSResource_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SpatialRelationPerSRSResource(tvb, offset, &asn1_ctx, tree, hf_nrppa_SpatialRelationPerSRSResource_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_nrppa_SRSConfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SRSConfiguration(tvb, offset, &asn1_ctx, tree, hf_nrppa_nrppa_SRSConfiguration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SrsFrequency_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SrsFrequency(tvb, offset, &asn1_ctx, tree, hf_nrppa_SrsFrequency_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRSPortIndex_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SRSPortIndex(tvb, offset, &asn1_ctx, tree, hf_nrppa_SRSPortIndex_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRSResourcetype_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SRSResourcetype(tvb, offset, &asn1_ctx, tree, hf_nrppa_SRSResourcetype_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRSTransmissionStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SRSTransmissionStatus(tvb, offset, &asn1_ctx, tree, hf_nrppa_SRSTransmissionStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_StartRBIndex_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_StartRBIndex(tvb, offset, &asn1_ctx, tree, hf_nrppa_StartRBIndex_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_StartRBHopping_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_StartRBHopping(tvb, offset, &asn1_ctx, tree, hf_nrppa_StartRBHopping_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SymbolIndex_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SymbolIndex(tvb, offset, &asn1_ctx, tree, hf_nrppa_SymbolIndex_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SystemFrameNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SystemFrameNumber(tvb, offset, &asn1_ctx, tree, hf_nrppa_SystemFrameNumber_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRSReservationType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SRSReservationType(tvb, offset, &asn1_ctx, tree, hf_nrppa_SRSReservationType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRSPreconfiguration_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SRSPreconfiguration_List(tvb, offset, &asn1_ctx, tree, hf_nrppa_SRSPreconfiguration_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TDD_Config_EUTRA_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TDD_Config_EUTRA_Item(tvb, offset, &asn1_ctx, tree, hf_nrppa_TDD_Config_EUTRA_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPTEGInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPTEGInformation(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPTEGInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimingErrorMargin_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TimingErrorMargin(tvb, offset, &asn1_ctx, tree, hf_nrppa_TimingErrorMargin_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimingReportingGranularityFactorExtended_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TimingReportingGranularityFactorExtended(tvb, offset, &asn1_ctx, tree, hf_nrppa_TimingReportingGranularityFactorExtended_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeWindowInformation_Measurement_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TimeWindowInformation_Measurement_List(tvb, offset, &asn1_ctx, tree, hf_nrppa_TimeWindowInformation_Measurement_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TimeWindowInformation_SRS_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TimeWindowInformation_SRS_List(tvb, offset, &asn1_ctx, tree, hf_nrppa_TimeWindowInformation_SRS_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TransmissionCombn8_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TransmissionCombn8(tvb, offset, &asn1_ctx, tree, hf_nrppa_TransmissionCombn8_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPBeamAntennaInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPBeamAntennaInformation(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPBeamAntennaInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPMeasurementQuantities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPMeasurementQuantities(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPMeasurementQuantities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPPhaseQuality_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPPhaseQuality(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPPhaseQuality_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRP_MeasurementRequestList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRP_MeasurementRequestList(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRP_MeasurementRequestList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRP_MeasurementResponseList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRP_MeasurementResponseList(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRP_MeasurementResponseList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRP_MeasurementUpdateList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRP_MeasurementUpdateList(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRP_MeasurementUpdateList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPInformationListTRPResp_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPInformationListTRPResp(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPInformationListTRPResp_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPInformationTypeListTRPReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPInformationTypeListTRPReq(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPInformationTypeListTRPReq_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPInformationTypeItem_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPInformationTypeItem(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPInformationTypeItem_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPList(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRP_PRS_Information_List_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRP_PRS_Information_List(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRP_PRS_Information_List_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRP_Rx_TEGInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRP_Rx_TEGInformation(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRP_Rx_TEGInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPTxTEGAssociation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPTxTEGAssociation(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPTxTEGAssociation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPType(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TxHoppingConfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TxHoppingConfiguration(tvb, offset, &asn1_ctx, tree, hf_nrppa_TxHoppingConfiguration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Measurement_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_UE_Measurement_ID(tvb, offset, &asn1_ctx, tree, hf_nrppa_UE_Measurement_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEReportingInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_UEReportingInformation(tvb, offset, &asn1_ctx, tree, hf_nrppa_UEReportingInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Rx_Tx_Time_Diff_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_UE_Rx_Tx_Time_Diff(tvb, offset, &asn1_ctx, tree, hf_nrppa_UE_Rx_Tx_Time_Diff_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_TEG_ReportingPeriodicity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_UE_TEG_ReportingPeriodicity(tvb, offset, &asn1_ctx, tree, hf_nrppa_UE_TEG_ReportingPeriodicity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UETxTEGAssociationList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_UETxTEGAssociationList(tvb, offset, &asn1_ctx, tree, hf_nrppa_UETxTEGAssociationList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_TEG_Info_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_UE_TEG_Info_Request(tvb, offset, &asn1_ctx, tree, hf_nrppa_UE_TEG_Info_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UL_AoA_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_UL_AoA(tvb, offset, &asn1_ctx, tree, hf_nrppa_UL_AoA_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UL_RSCPMeas_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_UL_RSCPMeas(tvb, offset, &asn1_ctx, tree, hf_nrppa_UL_RSCPMeas_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UL_SRS_RSRPP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_UL_SRS_RSRPP(tvb, offset, &asn1_ctx, tree, hf_nrppa_UL_SRS_RSRPP_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ValidityAreaSpecificSRSInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ValidityAreaSpecificSRSInformation(tvb, offset, &asn1_ctx, tree, hf_nrppa_ValidityAreaSpecificSRSInformation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WLANMeasurementQuantities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_WLANMeasurementQuantities(tvb, offset, &asn1_ctx, tree, hf_nrppa_WLANMeasurementQuantities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WLANMeasurementQuantities_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_WLANMeasurementQuantities_Item(tvb, offset, &asn1_ctx, tree, hf_nrppa_WLANMeasurementQuantities_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WLANMeasurementResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_WLANMeasurementResult(tvb, offset, &asn1_ctx, tree, hf_nrppa_WLANMeasurementResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ZoA_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ZoA(tvb, offset, &asn1_ctx, tree, hf_nrppa_ZoA_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementInitiationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementInitiationRequest(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementInitiationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementInitiationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementInitiationResponse(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementInitiationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementInitiationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementInitiationFailure(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementInitiationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementFailureIndication(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementReport(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementTerminationCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementTerminationCommand(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementTerminationCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOAInformationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_OTDOAInformationRequest(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOAInformationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOA_Information_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_OTDOA_Information_Type(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOA_Information_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOA_Information_Type_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_OTDOA_Information_Type_Item(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOA_Information_Type_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOAInformationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_OTDOAInformationResponse(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOAInformationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOAInformationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_OTDOAInformationFailure(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOAInformationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AssistanceInformationControl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_AssistanceInformationControl(tvb, offset, &asn1_ctx, tree, hf_nrppa_AssistanceInformationControl_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AssistanceInformationFeedback_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_AssistanceInformationFeedback(tvb, offset, &asn1_ctx, tree, hf_nrppa_AssistanceInformationFeedback_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_nrppa_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_nrppa_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningInformationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PositioningInformationRequest(tvb, offset, &asn1_ctx, tree, hf_nrppa_PositioningInformationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningInformationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PositioningInformationResponse(tvb, offset, &asn1_ctx, tree, hf_nrppa_PositioningInformationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningInformationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PositioningInformationFailure(tvb, offset, &asn1_ctx, tree, hf_nrppa_PositioningInformationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningInformationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PositioningInformationUpdate(tvb, offset, &asn1_ctx, tree, hf_nrppa_PositioningInformationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementRequest(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementResponse(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementFailure(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementReport(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementUpdate(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementAbort_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementAbort(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementAbort_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementFailureIndication(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPInformationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPInformationRequest(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPInformationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPInformationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPInformationResponse(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPInformationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TRPInformationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_TRPInformationFailure(tvb, offset, &asn1_ctx, tree, hf_nrppa_TRPInformationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningActivationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PositioningActivationRequest(tvb, offset, &asn1_ctx, tree, hf_nrppa_PositioningActivationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRSType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SRSType(tvb, offset, &asn1_ctx, tree, hf_nrppa_SRSType_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningActivationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PositioningActivationResponse(tvb, offset, &asn1_ctx, tree, hf_nrppa_PositioningActivationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningActivationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PositioningActivationFailure(tvb, offset, &asn1_ctx, tree, hf_nrppa_PositioningActivationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PositioningDeactivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PositioningDeactivation(tvb, offset, &asn1_ctx, tree, hf_nrppa_PositioningDeactivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRSConfigurationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PRSConfigurationRequest(tvb, offset, &asn1_ctx, tree, hf_nrppa_PRSConfigurationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRSConfigurationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PRSConfigurationResponse(tvb, offset, &asn1_ctx, tree, hf_nrppa_PRSConfigurationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PRSConfigurationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_PRSConfigurationFailure(tvb, offset, &asn1_ctx, tree, hf_nrppa_PRSConfigurationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementPreconfigurationRequired_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementPreconfigurationRequired(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementPreconfigurationRequired_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementPreconfigurationConfirm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementPreconfigurationConfirm(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementPreconfigurationConfirm_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementPreconfigurationRefuse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementPreconfigurationRefuse(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementPreconfigurationRefuse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementActivation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_MeasurementActivation(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementActivation_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SRSInformationReservationNotification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_nrppa_SRSInformationReservationNotification(tvb, offset, &asn1_ctx, tree, hf_nrppa_SRSInformationReservationNotification_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, false, NULL)) ? tvb_captured_length(tvb) : 0;
}

/*--- proto_register_nrppa -------------------------------------------*/
void proto_register_nrppa(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_nrppa_NRPPA_PDU_PDU,
      { "NRPPA-PDU", "nrppa.NRPPA_PDU",
        FT_UINT32, BASE_DEC, VALS(nrppa_NRPPA_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_AbortTransmission_PDU,
      { "AbortTransmission", "nrppa.AbortTransmission",
        FT_UINT32, BASE_DEC, VALS(nrppa_AbortTransmission_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_AggregatedPosSRSResourceID_List_PDU,
      { "AggregatedPosSRSResourceID-List", "nrppa.AggregatedPosSRSResourceID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_AggregatedPRSResourceSetList_PDU,
      { "AggregatedPRSResourceSetList", "nrppa.AggregatedPRSResourceSetList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ExtendedAdditionalPathList_PDU,
      { "ExtendedAdditionalPathList", "nrppa.ExtendedAdditionalPathList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_AoA_AssistanceInfo_PDU,
      { "AoA-AssistanceInfo", "nrppa.AoA_AssistanceInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ARP_ID_PDU,
      { "ARP-ID", "nrppa.ARP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ARPLocationInformation_PDU,
      { "ARPLocationInformation", "nrppa.ARPLocationInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_nrppa_Assistance_Information_PDU,
      { "Assistance-Information", "nrppa.Assistance_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_AssistanceInformationFailureList_PDU,
      { "AssistanceInformationFailureList", "nrppa.AssistanceInformationFailureList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_Bandwidth_Aggregation_Request_Indication_PDU,
      { "Bandwidth-Aggregation-Request-Indication", "nrppa.Bandwidth_Aggregation_Request_Indication",
        FT_UINT32, BASE_DEC, VALS(nrppa_Bandwidth_Aggregation_Request_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_Broadcast_PDU,
      { "Broadcast", "nrppa.Broadcast",
        FT_UINT32, BASE_DEC, VALS(nrppa_Broadcast_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_PositioningBroadcastCells_PDU,
      { "PositioningBroadcastCells", "nrppa.PositioningBroadcastCells",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_Cause_PDU,
      { "Cause", "nrppa.Cause",
        FT_UINT32, BASE_DEC, VALS(nrppa_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_Cell_Portion_ID_PDU,
      { "Cell-Portion-ID", "nrppa.Cell_Portion_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_CGI_NR_PDU,
      { "CGI-NR", "nrppa.CGI_NR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "nrppa.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_CommonTAParameters_PDU,
      { "CommonTAParameters", "nrppa.CommonTAParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_E_CID_MeasurementResult_PDU,
      { "E-CID-MeasurementResult", "nrppa.E_CID_MeasurementResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_GeographicalCoordinates_PDU,
      { "GeographicalCoordinates", "nrppa.GeographicalCoordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_LoS_NLoSInformation_PDU,
      { "LoS-NLoSInformation", "nrppa.LoS_NLoSInformation",
        FT_UINT32, BASE_DEC, VALS(nrppa_LoS_NLoSInformation_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasBasedOnAggregatedResources_PDU,
      { "MeasBasedOnAggregatedResources", "nrppa.MeasBasedOnAggregatedResources",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasBasedOnAggregatedResources_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_Measurement_ID_PDU,
      { "Measurement-ID", "nrppa.Measurement_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementAmount_PDU,
      { "MeasurementAmount", "nrppa.MeasurementAmount",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasurementAmount_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementBeamInfoRequest_PDU,
      { "MeasurementBeamInfoRequest", "nrppa.MeasurementBeamInfoRequest",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasurementBeamInfoRequest_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementPeriodicity_PDU,
      { "MeasurementPeriodicity", "nrppa.MeasurementPeriodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasurementPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementPeriodicityExtended_PDU,
      { "MeasurementPeriodicityExtended", "nrppa.MeasurementPeriodicityExtended",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasurementPeriodicityExtended_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementPeriodicityNR_AoA_PDU,
      { "MeasurementPeriodicityNR-AoA", "nrppa.MeasurementPeriodicityNR_AoA",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasurementPeriodicityNR_AoA_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementQuantities_PDU,
      { "MeasurementQuantities", "nrppa.MeasurementQuantities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementQuantities_Item_PDU,
      { "MeasurementQuantities-Item", "nrppa.MeasurementQuantities_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementTimeOccasion_PDU,
      { "MeasurementTimeOccasion", "nrppa.MeasurementTimeOccasion",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasurementTimeOccasion_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementCharacteristicsRequestIndicator_PDU,
      { "MeasurementCharacteristicsRequestIndicator", "nrppa.MeasurementCharacteristicsRequestIndicator",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasuredResultsAssociatedInfoList_PDU,
      { "MeasuredResultsAssociatedInfoList", "nrppa.MeasuredResultsAssociatedInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_Mobile_TRP_LocationInformation_PDU,
      { "Mobile-TRP-LocationInformation", "nrppa.Mobile_TRP_LocationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_Mobile_IAB_MT_UE_ID_PDU,
      { "Mobile-IAB-MT-UE-ID", "nrppa.Mobile_IAB_MT_UE_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MultipleULAoA_PDU,
      { "MultipleULAoA", "nrppa.MultipleULAoA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasuredFrequencyHops_PDU,
      { "MeasuredFrequencyHops", "nrppa.MeasuredFrequencyHops",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasuredFrequencyHops_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_NrofSymbolsExtended_PDU,
      { "NrofSymbolsExtended", "nrppa.NrofSymbolsExtended",
        FT_UINT32, BASE_DEC, VALS(nrppa_NrofSymbolsExtended_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_NR_PCI_PDU,
      { "NR-PCI", "nrppa.NR_PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_NR_TADV_PDU,
      { "NR-TADV", "nrppa.NR_TADV",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_NumberOfTRPRxTEG_PDU,
      { "NumberOfTRPRxTEG", "nrppa.NumberOfTRPRxTEG",
        FT_UINT32, BASE_DEC, VALS(nrppa_NumberOfTRPRxTEG_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_NumberOfTRPRxTxTEG_PDU,
      { "NumberOfTRPRxTxTEG", "nrppa.NumberOfTRPRxTxTEG",
        FT_UINT32, BASE_DEC, VALS(nrppa_NumberOfTRPRxTxTEG_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_OnDemandPRS_Info_PDU,
      { "OnDemandPRS-Info", "nrppa.OnDemandPRS_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_OTDOACells_PDU,
      { "OTDOACells", "nrppa.OTDOACells",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_OtherRATMeasurementQuantities_PDU,
      { "OtherRATMeasurementQuantities", "nrppa.OtherRATMeasurementQuantities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_OtherRATMeasurementQuantities_Item_PDU,
      { "OtherRATMeasurementQuantities-Item", "nrppa.OtherRATMeasurementQuantities_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_OtherRATMeasurementResult_PDU,
      { "OtherRATMeasurementResult", "nrppa.OtherRATMeasurementResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSBWAggregationRequestIndication_PDU,
      { "PRSBWAggregationRequestIndication", "nrppa.PRSBWAggregationRequestIndication",
        FT_UINT32, BASE_DEC, VALS(nrppa_PRSBWAggregationRequestIndication_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_PosSRSResourceSet_Aggregation_List_PDU,
      { "PosSRSResourceSet-Aggregation-List", "nrppa.PosSRSResourceSet_Aggregation_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PreconfigurationResult_PDU,
      { "PreconfigurationResult", "nrppa.PreconfigurationResult",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSConfigRequestType_PDU,
      { "PRSConfigRequestType", "nrppa.PRSConfigRequestType",
        FT_UINT32, BASE_DEC, VALS(nrppa_PRSConfigRequestType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_PRS_Measurements_Info_List_PDU,
      { "PRS-Measurements-Info-List", "nrppa.PRS_Measurements_Info_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ExtendedResourceSymbolOffset_PDU,
      { "ExtendedResourceSymbolOffset", "nrppa.ExtendedResourceSymbolOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRS_Resource_ID_PDU,
      { "PRS-Resource-ID", "nrppa.PRS_Resource_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSTRPList_PDU,
      { "PRSTRPList", "nrppa.PRSTRPList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSTransmissionTRPList_PDU,
      { "PRSTransmissionTRPList", "nrppa.PRSTransmissionTRPList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PosValidityAreaCellList_PDU,
      { "PosValidityAreaCellList", "nrppa.PosValidityAreaCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PointA_PDU,
      { "PointA", "nrppa.PointA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_RepetitionFactorExtended_PDU,
      { "RepetitionFactorExtended", "nrppa.RepetitionFactorExtended",
        FT_UINT32, BASE_DEC, VALS(nrppa_RepetitionFactorExtended_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportCharacteristics_PDU,
      { "ReportCharacteristics", "nrppa.ReportCharacteristics",
        FT_UINT32, BASE_DEC, VALS(nrppa_ReportCharacteristics_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus1_PDU,
      { "ReportingGranularitykminus1", "nrppa.ReportingGranularitykminus1",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus2_PDU,
      { "ReportingGranularitykminus2", "nrppa.ReportingGranularitykminus2",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus3_PDU,
      { "ReportingGranularitykminus3", "nrppa.ReportingGranularitykminus3",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus4_PDU,
      { "ReportingGranularitykminus4", "nrppa.ReportingGranularitykminus4",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus5_PDU,
      { "ReportingGranularitykminus5", "nrppa.ReportingGranularitykminus5",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus6_PDU,
      { "ReportingGranularitykminus6", "nrppa.ReportingGranularitykminus6",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus1AdditionalPath_PDU,
      { "ReportingGranularitykminus1AdditionalPath", "nrppa.ReportingGranularitykminus1AdditionalPath",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus2AdditionalPath_PDU,
      { "ReportingGranularitykminus2AdditionalPath", "nrppa.ReportingGranularitykminus2AdditionalPath",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus3AdditionalPath_PDU,
      { "ReportingGranularitykminus3AdditionalPath", "nrppa.ReportingGranularitykminus3AdditionalPath",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus4AdditionalPath_PDU,
      { "ReportingGranularitykminus4AdditionalPath", "nrppa.ReportingGranularitykminus4AdditionalPath",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus5AdditionalPath_PDU,
      { "ReportingGranularitykminus5AdditionalPath", "nrppa.ReportingGranularitykminus5AdditionalPath",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ReportingGranularitykminus6AdditionalPath_PDU,
      { "ReportingGranularitykminus6AdditionalPath", "nrppa.ReportingGranularitykminus6AdditionalPath",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_RequestedSRSTransmissionCharacteristics_PDU,
      { "RequestedSRSTransmissionCharacteristics", "nrppa.RequestedSRSTransmissionCharacteristics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_RequestedSRSPreconfigurationCharacteristics_List_PDU,
      { "RequestedSRSPreconfigurationCharacteristics-List", "nrppa.RequestedSRSPreconfigurationCharacteristics_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_RequestType_PDU,
      { "RequestType", "nrppa.RequestType",
        FT_UINT32, BASE_DEC, VALS(nrppa_RequestType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_ResponseTime_PDU,
      { "ResponseTime", "nrppa.ResponseTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultCSI_RSRP_PDU,
      { "ResultCSI-RSRP", "nrppa.ResultCSI_RSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultCSI_RSRQ_PDU,
      { "ResultCSI-RSRQ", "nrppa.ResultCSI_RSRQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultEUTRA_PDU,
      { "ResultEUTRA", "nrppa.ResultEUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultSS_RSRP_PDU,
      { "ResultSS-RSRP", "nrppa.ResultSS_RSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultSS_RSRQ_PDU,
      { "ResultSS-RSRQ", "nrppa.ResultSS_RSRQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultNR_PDU,
      { "ResultNR", "nrppa.ResultNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SCS_480_PDU,
      { "SCS-480", "nrppa.SCS_480",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SCS_960_PDU,
      { "SCS-960", "nrppa.SCS_960",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SCS_SpecificCarrier_PDU,
      { "SCS-SpecificCarrier", "nrppa.SCS_SpecificCarrier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_RelativeTime1900_PDU,
      { "RelativeTime1900", "nrppa.RelativeTime1900",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SFNInitialisationTime_EUTRA_PDU,
      { "SFNInitialisationTime-EUTRA", "nrppa.SFNInitialisationTime_EUTRA",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SlotNumber_PDU,
      { "SlotNumber", "nrppa.SlotNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SpatialRelationInfo_PDU,
      { "SpatialRelationInfo", "nrppa.SpatialRelationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SpatialRelationPerSRSResource_PDU,
      { "SpatialRelationPerSRSResource", "nrppa.SpatialRelationPerSRSResource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_nrppa_SRSConfiguration_PDU,
      { "SRSConfiguration", "nrppa.SRSConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SrsFrequency_PDU,
      { "SrsFrequency", "nrppa.SrsFrequency",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSPortIndex_PDU,
      { "SRSPortIndex", "nrppa.SRSPortIndex",
        FT_UINT32, BASE_DEC, VALS(nrppa_SRSPortIndex_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSResourcetype_PDU,
      { "SRSResourcetype", "nrppa.SRSResourcetype_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSTransmissionStatus_PDU,
      { "SRSTransmissionStatus", "nrppa.SRSTransmissionStatus",
        FT_UINT32, BASE_DEC, VALS(nrppa_SRSTransmissionStatus_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_StartRBIndex_PDU,
      { "StartRBIndex", "nrppa.StartRBIndex",
        FT_UINT32, BASE_DEC, VALS(nrppa_StartRBIndex_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_StartRBHopping_PDU,
      { "StartRBHopping", "nrppa.StartRBHopping",
        FT_UINT32, BASE_DEC, VALS(nrppa_StartRBHopping_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_SymbolIndex_PDU,
      { "SymbolIndex", "nrppa.SymbolIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SystemFrameNumber_PDU,
      { "SystemFrameNumber", "nrppa.SystemFrameNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSReservationType_PDU,
      { "SRSReservationType", "nrppa.SRSReservationType",
        FT_UINT32, BASE_DEC, VALS(nrppa_SRSReservationType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSPreconfiguration_List_PDU,
      { "SRSPreconfiguration-List", "nrppa.SRSPreconfiguration_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TDD_Config_EUTRA_Item_PDU,
      { "TDD-Config-EUTRA-Item", "nrppa.TDD_Config_EUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPTEGInformation_PDU,
      { "TRPTEGInformation", "nrppa.TRPTEGInformation",
        FT_UINT32, BASE_DEC, VALS(nrppa_TRPTEGInformation_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_TimingErrorMargin_PDU,
      { "TimingErrorMargin", "nrppa.TimingErrorMargin",
        FT_UINT32, BASE_DEC, VALS(nrppa_TimingErrorMargin_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_TimingReportingGranularityFactorExtended_PDU,
      { "TimingReportingGranularityFactorExtended", "nrppa.TimingReportingGranularityFactorExtended",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TimeWindowInformation_Measurement_List_PDU,
      { "TimeWindowInformation-Measurement-List", "nrppa.TimeWindowInformation_Measurement_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TimeWindowInformation_SRS_List_PDU,
      { "TimeWindowInformation-SRS-List", "nrppa.TimeWindowInformation_SRS_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TransmissionCombn8_PDU,
      { "TransmissionCombn8", "nrppa.TransmissionCombn8_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPBeamAntennaInformation_PDU,
      { "TRPBeamAntennaInformation", "nrppa.TRPBeamAntennaInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPMeasurementQuantities_PDU,
      { "TRPMeasurementQuantities", "nrppa.TRPMeasurementQuantities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPPhaseQuality_PDU,
      { "TRPPhaseQuality", "nrppa.TRPPhaseQuality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRP_MeasurementRequestList_PDU,
      { "TRP-MeasurementRequestList", "nrppa.TRP_MeasurementRequestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRP_MeasurementResponseList_PDU,
      { "TRP-MeasurementResponseList", "nrppa.TRP_MeasurementResponseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRP_MeasurementUpdateList_PDU,
      { "TRP-MeasurementUpdateList", "nrppa.TRP_MeasurementUpdateList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPInformationListTRPResp_PDU,
      { "TRPInformationListTRPResp", "nrppa.TRPInformationListTRPResp",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPInformationTypeListTRPReq_PDU,
      { "TRPInformationTypeListTRPReq", "nrppa.TRPInformationTypeListTRPReq",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPInformationTypeItem_PDU,
      { "TRPInformationTypeItem", "nrppa.TRPInformationTypeItem",
        FT_UINT32, BASE_DEC, VALS(nrppa_TRPInformationTypeItem_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPList_PDU,
      { "TRPList", "nrppa.TRPList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRP_PRS_Information_List_PDU,
      { "TRP-PRS-Information-List", "nrppa.TRP_PRS_Information_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRP_Rx_TEGInformation_PDU,
      { "TRP-Rx-TEGInformation", "nrppa.TRP_Rx_TEGInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPTxTEGAssociation_PDU,
      { "TRPTxTEGAssociation", "nrppa.TRPTxTEGAssociation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPType_PDU,
      { "TRPType", "nrppa.TRPType",
        FT_UINT32, BASE_DEC, VALS(nrppa_TRPType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_TxHoppingConfiguration_PDU,
      { "TxHoppingConfiguration", "nrppa.TxHoppingConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_UE_Measurement_ID_PDU,
      { "UE-Measurement-ID", "nrppa.UE_Measurement_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_UEReportingInformation_PDU,
      { "UEReportingInformation", "nrppa.UEReportingInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_UE_Rx_Tx_Time_Diff_PDU,
      { "UE-Rx-Tx-Time-Diff", "nrppa.UE_Rx_Tx_Time_Diff",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_UE_TEG_ReportingPeriodicity_PDU,
      { "UE-TEG-ReportingPeriodicity", "nrppa.UE_TEG_ReportingPeriodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_UE_TEG_ReportingPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_UETxTEGAssociationList_PDU,
      { "UETxTEGAssociationList", "nrppa.UETxTEGAssociationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_UE_TEG_Info_Request_PDU,
      { "UE-TEG-Info-Request", "nrppa.UE_TEG_Info_Request",
        FT_UINT32, BASE_DEC, VALS(nrppa_UE_TEG_Info_Request_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_UL_AoA_PDU,
      { "UL-AoA", "nrppa.UL_AoA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_UL_RSCPMeas_PDU,
      { "UL-RSCPMeas", "nrppa.UL_RSCPMeas_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_UL_SRS_RSRPP_PDU,
      { "UL-SRS-RSRPP", "nrppa.UL_SRS_RSRPP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ValidityAreaSpecificSRSInformation_PDU,
      { "ValidityAreaSpecificSRSInformation", "nrppa.ValidityAreaSpecificSRSInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_WLANMeasurementQuantities_PDU,
      { "WLANMeasurementQuantities", "nrppa.WLANMeasurementQuantities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_WLANMeasurementQuantities_Item_PDU,
      { "WLANMeasurementQuantities-Item", "nrppa.WLANMeasurementQuantities_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_WLANMeasurementResult_PDU,
      { "WLANMeasurementResult", "nrppa.WLANMeasurementResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ZoA_PDU,
      { "ZoA", "nrppa.ZoA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_E_CIDMeasurementInitiationRequest_PDU,
      { "E-CIDMeasurementInitiationRequest", "nrppa.E_CIDMeasurementInitiationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_E_CIDMeasurementInitiationResponse_PDU,
      { "E-CIDMeasurementInitiationResponse", "nrppa.E_CIDMeasurementInitiationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_E_CIDMeasurementInitiationFailure_PDU,
      { "E-CIDMeasurementInitiationFailure", "nrppa.E_CIDMeasurementInitiationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_E_CIDMeasurementFailureIndication_PDU,
      { "E-CIDMeasurementFailureIndication", "nrppa.E_CIDMeasurementFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_E_CIDMeasurementReport_PDU,
      { "E-CIDMeasurementReport", "nrppa.E_CIDMeasurementReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_E_CIDMeasurementTerminationCommand_PDU,
      { "E-CIDMeasurementTerminationCommand", "nrppa.E_CIDMeasurementTerminationCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_OTDOAInformationRequest_PDU,
      { "OTDOAInformationRequest", "nrppa.OTDOAInformationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_OTDOA_Information_Type_PDU,
      { "OTDOA-Information-Type", "nrppa.OTDOA_Information_Type",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_OTDOA_Information_Type_Item_PDU,
      { "OTDOA-Information-Type-Item", "nrppa.OTDOA_Information_Type_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_OTDOAInformationResponse_PDU,
      { "OTDOAInformationResponse", "nrppa.OTDOAInformationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_OTDOAInformationFailure_PDU,
      { "OTDOAInformationFailure", "nrppa.OTDOAInformationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_AssistanceInformationControl_PDU,
      { "AssistanceInformationControl", "nrppa.AssistanceInformationControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_AssistanceInformationFeedback_PDU,
      { "AssistanceInformationFeedback", "nrppa.AssistanceInformationFeedback_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ErrorIndication_PDU,
      { "ErrorIndication", "nrppa.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PrivateMessage_PDU,
      { "PrivateMessage", "nrppa.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PositioningInformationRequest_PDU,
      { "PositioningInformationRequest", "nrppa.PositioningInformationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PositioningInformationResponse_PDU,
      { "PositioningInformationResponse", "nrppa.PositioningInformationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PositioningInformationFailure_PDU,
      { "PositioningInformationFailure", "nrppa.PositioningInformationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PositioningInformationUpdate_PDU,
      { "PositioningInformationUpdate", "nrppa.PositioningInformationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementRequest_PDU,
      { "MeasurementRequest", "nrppa.MeasurementRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementResponse_PDU,
      { "MeasurementResponse", "nrppa.MeasurementResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementFailure_PDU,
      { "MeasurementFailure", "nrppa.MeasurementFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementReport_PDU,
      { "MeasurementReport", "nrppa.MeasurementReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementUpdate_PDU,
      { "MeasurementUpdate", "nrppa.MeasurementUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementAbort_PDU,
      { "MeasurementAbort", "nrppa.MeasurementAbort_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementFailureIndication_PDU,
      { "MeasurementFailureIndication", "nrppa.MeasurementFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPInformationRequest_PDU,
      { "TRPInformationRequest", "nrppa.TRPInformationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPInformationResponse_PDU,
      { "TRPInformationResponse", "nrppa.TRPInformationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPInformationFailure_PDU,
      { "TRPInformationFailure", "nrppa.TRPInformationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PositioningActivationRequest_PDU,
      { "PositioningActivationRequest", "nrppa.PositioningActivationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSType_PDU,
      { "SRSType", "nrppa.SRSType",
        FT_UINT32, BASE_DEC, VALS(nrppa_SRSType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_PositioningActivationResponse_PDU,
      { "PositioningActivationResponse", "nrppa.PositioningActivationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PositioningActivationFailure_PDU,
      { "PositioningActivationFailure", "nrppa.PositioningActivationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PositioningDeactivation_PDU,
      { "PositioningDeactivation", "nrppa.PositioningDeactivation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSConfigurationRequest_PDU,
      { "PRSConfigurationRequest", "nrppa.PRSConfigurationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSConfigurationResponse_PDU,
      { "PRSConfigurationResponse", "nrppa.PRSConfigurationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSConfigurationFailure_PDU,
      { "PRSConfigurationFailure", "nrppa.PRSConfigurationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementPreconfigurationRequired_PDU,
      { "MeasurementPreconfigurationRequired", "nrppa.MeasurementPreconfigurationRequired_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementPreconfigurationConfirm_PDU,
      { "MeasurementPreconfigurationConfirm", "nrppa.MeasurementPreconfigurationConfirm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementPreconfigurationRefuse_PDU,
      { "MeasurementPreconfigurationRefuse", "nrppa.MeasurementPreconfigurationRefuse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementActivation_PDU,
      { "MeasurementActivation", "nrppa.MeasurementActivation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSInformationReservationNotification_PDU,
      { "SRSInformationReservationNotification", "nrppa.SRSInformationReservationNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_local,
      { "local", "nrppa.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxPrivateIEs", HFILL }},
    { &hf_nrppa_global,
      { "global", "nrppa.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_nrppa_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "nrppa.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_id,
      { "id", "nrppa.id",
        FT_UINT32, BASE_DEC, VALS(nrppa_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_nrppa_criticality,
      { "criticality", "nrppa.criticality",
        FT_UINT32, BASE_DEC, VALS(nrppa_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_ie_field_value,
      { "value", "nrppa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_nrppa_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "nrppa.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ext_id,
      { "id", "nrppa.id",
        FT_UINT32, BASE_DEC, VALS(nrppa_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_nrppa_extensionValue,
      { "extensionValue", "nrppa.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PrivateIE_Container_item,
      { "PrivateIE-Field", "nrppa.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_id_01,
      { "id", "nrppa.id",
        FT_UINT32, BASE_DEC, VALS(nrppa_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_nrppa_value,
      { "value", "nrppa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_initiatingMessage,
      { "initiatingMessage", "nrppa.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_successfulOutcome,
      { "successfulOutcome", "nrppa.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "nrppa.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_procedureCode,
      { "procedureCode", "nrppa.procedureCode",
        FT_UINT32, BASE_DEC, VALS(nrppa_ProcedureCode_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_nrppatransactionID,
      { "nrppatransactionID", "nrppa.nrppatransactionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_initiatingMessagevalue,
      { "value", "nrppa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_nrppa_successfulOutcome_value,
      { "value", "nrppa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_nrppa_unsuccessfulOutcome_value,
      { "value", "nrppa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
    { &hf_nrppa_deactivateSRSResourceSetID,
      { "deactivateSRSResourceSetID", "nrppa.deactivateSRSResourceSetID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SRSResourceSetID", HFILL }},
    { &hf_nrppa_releaseALL,
      { "releaseALL", "nrppa.releaseALL_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_choice_extension,
      { "choice-extension", "nrppa.choice_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Single_Container", HFILL }},
    { &hf_nrppa_locationAndBandwidth,
      { "locationAndBandwidth", "nrppa.locationAndBandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_37949_", HFILL }},
    { &hf_nrppa_subcarrierSpacing,
      { "subcarrierSpacing", "nrppa.subcarrierSpacing",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_subcarrierSpacing_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_cyclicPrefix,
      { "cyclicPrefix", "nrppa.cyclicPrefix",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_cyclicPrefix_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_txDirectCurrentLocation,
      { "txDirectCurrentLocation", "nrppa.txDirectCurrentLocation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3301_", HFILL }},
    { &hf_nrppa_shift7dot5kHz,
      { "shift7dot5kHz", "nrppa.shift7dot5kHz",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_shift7dot5kHz_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSConfig,
      { "sRSConfig", "nrppa.sRSConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_iE_Extensions,
      { "iE-Extensions", "nrppa.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_nrppa_AdditionalPathList_item,
      { "AdditionalPathListItem", "nrppa.AdditionalPathListItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_relativeTimeOfPath,
      { "relativeTimeOfPath", "nrppa.relativeTimeOfPath",
        FT_UINT32, BASE_DEC, VALS(nrppa_RelativePathDelay_vals), 0,
        "RelativePathDelay", HFILL }},
    { &hf_nrppa_pathQuality,
      { "pathQuality", "nrppa.pathQuality",
        FT_UINT32, BASE_DEC, VALS(nrppa_TrpMeasurementQuality_vals), 0,
        "TrpMeasurementQuality", HFILL }},
    { &hf_nrppa_AggregatedPosSRSResourceID_List_item,
      { "AggregatedPosSRSResourceID-Item", "nrppa.AggregatedPosSRSResourceID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSPosResource_ID,
      { "sRSPosResource-ID", "nrppa.sRSPosResource_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SRSPosResourceID", HFILL }},
    { &hf_nrppa_AggregatedPRSResourceSetList_item,
      { "AggregatedPRSResourceSet-Item", "nrppa.AggregatedPRSResourceSet_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_dl_PRS_ResourceSet_List,
      { "dl-PRS-ResourceSet-List", "nrppa.dl_PRS_ResourceSet_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_DL_PRS_ResourceSet_List_item,
      { "DL-PRS-ResourceSet-Item", "nrppa.DL_PRS_ResourceSet_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_dl_prs_ResourceSetIndex,
      { "dl-prs-ResourceSetIndex", "nrppa.dl_prs_ResourceSetIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8", HFILL }},
    { &hf_nrppa_ExtendedAdditionalPathList_item,
      { "ExtendedAdditionalPathList-Item", "nrppa.ExtendedAdditionalPathList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_multipleULAoA,
      { "multipleULAoA", "nrppa.multipleULAoA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pathPower,
      { "pathPower", "nrppa.pathPower_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL_SRS_RSRPP", HFILL }},
    { &hf_nrppa_angleMeasurement,
      { "angleMeasurement", "nrppa.angleMeasurement",
        FT_UINT32, BASE_DEC, VALS(nrppa_AngleMeasurementType_vals), 0,
        "AngleMeasurementType", HFILL }},
    { &hf_nrppa_lCS_to_GCS_Translation,
      { "lCS-to-GCS-Translation", "nrppa.lCS_to_GCS_Translation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_AperiodicSRSResourceTriggerList_item,
      { "AperiodicSRSResourceTrigger", "nrppa.AperiodicSRSResourceTrigger",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_expected_ULAoA,
      { "expected-ULAoA", "nrppa.expected_ULAoA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Expected_UL_AoA", HFILL }},
    { &hf_nrppa_expected_ZoA,
      { "expected-ZoA", "nrppa.expected_ZoA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Expected_ZoA_only", HFILL }},
    { &hf_nrppa_expected_Azimuth_AoA,
      { "expected-Azimuth-AoA", "nrppa.expected_Azimuth_AoA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_expected_Zenith_AoA,
      { "expected-Zenith-AoA", "nrppa.expected_Zenith_AoA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_iE_extensions,
      { "iE-extensions", "nrppa.iE_extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_nrppa_expected_ZoA_only,
      { "expected-ZoA-only", "nrppa.expected_ZoA_only_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Expected_Zenith_AoA", HFILL }},
    { &hf_nrppa_expected_Azimuth_AoA_value,
      { "expected-Azimuth-AoA-value", "nrppa.expected_Azimuth_AoA_value",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Expected_Value_AoA", HFILL }},
    { &hf_nrppa_expected_Azimuth_AoA_uncertainty,
      { "expected-Azimuth-AoA-uncertainty", "nrppa.expected_Azimuth_AoA_uncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uncertainty_range_AoA", HFILL }},
    { &hf_nrppa_expected_Zenith_AoA_value,
      { "expected-Zenith-AoA-value", "nrppa.expected_Zenith_AoA_value",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Expected_Value_ZoA", HFILL }},
    { &hf_nrppa_expected_Zenith_AoA_uncertainty,
      { "expected-Zenith-AoA-uncertainty", "nrppa.expected_Zenith_AoA_uncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uncertainty_range_ZoA", HFILL }},
    { &hf_nrppa_ARPLocationInformation_item,
      { "ARPLocationInformation-Item", "nrppa.ARPLocationInformation_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_aRP_ID,
      { "aRP-ID", "nrppa.aRP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_aRPLocationType,
      { "aRPLocationType", "nrppa.aRPLocationType",
        FT_UINT32, BASE_DEC, VALS(nrppa_ARPLocationType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_aRPPositionRelativeGeodetic,
      { "aRPPositionRelativeGeodetic", "nrppa.aRPPositionRelativeGeodetic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelativeGeodeticLocation", HFILL }},
    { &hf_nrppa_aRPPositionRelativeCartesian,
      { "aRPPositionRelativeCartesian", "nrppa.aRPPositionRelativeCartesian_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelativeCartesianLocation", HFILL }},
    { &hf_nrppa_systemInformation,
      { "systemInformation", "nrppa.systemInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_AssistanceInformationFailureList_item,
      { "AssistanceInformationFailureList item", "nrppa.AssistanceInformationFailureList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_posSIB_Type,
      { "posSIB-Type", "nrppa.posSIB_Type",
        FT_UINT32, BASE_DEC, VALS(nrppa_PosSIB_Type_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_outcome,
      { "outcome", "nrppa.outcome",
        FT_UINT32, BASE_DEC, VALS(nrppa_Outcome_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_encrypted,
      { "encrypted", "nrppa.encrypted",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_encrypted_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_gNSSID,
      { "gNSSID", "nrppa.gNSSID",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_gNSSID_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sBASID,
      { "sBASID", "nrppa.sBASID",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_sBASID_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_fR1,
      { "fR1", "nrppa.fR1",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_fR1_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_fR2,
      { "fR2", "nrppa.fR2",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_fR2_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_PositioningBroadcastCells_item,
      { "NG-RAN-CGI", "nrppa.NG_RAN_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pointA,
      { "pointA", "nrppa.pointA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3279165", HFILL }},
    { &hf_nrppa_offsetToCarrier,
      { "offsetToCarrier", "nrppa.offsetToCarrier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2199_", HFILL }},
    { &hf_nrppa_radioNetwork,
      { "radioNetwork", "nrppa.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(nrppa_CauseRadioNetwork_vals), 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_nrppa_protocol,
      { "protocol", "nrppa.protocol",
        FT_UINT32, BASE_DEC, VALS(nrppa_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_nrppa_misc,
      { "misc", "nrppa.misc",
        FT_UINT32, BASE_DEC, VALS(nrppa_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_nrppa_choice_Extension,
      { "choice-Extension", "nrppa.choice_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Single_Container", HFILL }},
    { &hf_nrppa_pLMN_Identity,
      { "pLMN-Identity", "nrppa.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_eUTRAcellIdentifier,
      { "eUTRAcellIdentifier", "nrppa.eUTRAcellIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_nRcellIdentifier,
      { "nRcellIdentifier", "nrppa.nRcellIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_triggeringMessage,
      { "triggeringMessage", "nrppa.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(nrppa_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_procedureCriticality,
      { "procedureCriticality", "nrppa.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(nrppa_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_nrppa_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "nrppa.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_nrppa_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "nrppa.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_iECriticality,
      { "iECriticality", "nrppa.iECriticality",
        FT_UINT32, BASE_DEC, VALS(nrppa_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_nrppa_iE_ID,
      { "iE-ID", "nrppa.iE_ID",
        FT_UINT32, BASE_DEC, VALS(nrppa_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_nrppa_typeOfError,
      { "typeOfError", "nrppa.typeOfError",
        FT_UINT32, BASE_DEC, VALS(nrppa_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_epochTime,
      { "epochTime", "nrppa.epochTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_nrppa_taInfo,
      { "taInfo", "nrppa.taInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_nrppa_prsid,
      { "prsid", "nrppa.prsid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_ID", HFILL }},
    { &hf_nrppa_dl_PRSResourceSetID,
      { "dl-PRSResourceSetID", "nrppa.dl_PRSResourceSetID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_Resource_Set_ID", HFILL }},
    { &hf_nrppa_dl_PRSResourceID,
      { "dl-PRSResourceID", "nrppa.dl_PRSResourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_Resource_ID", HFILL }},
    { &hf_nrppa_two,
      { "two", "nrppa.two",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_nrppa_four,
      { "four", "nrppa.four",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_nrppa_six,
      { "six", "nrppa.six",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_nrppa_eight,
      { "eight", "nrppa.eight",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_nrppa_sixteen,
      { "sixteen", "nrppa.sixteen",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_nrppa_thirty_two,
      { "thirty-two", "nrppa.thirty_two",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_nrppa_listofDL_PRSResourceSetARP,
      { "listofDL-PRSResourceSetARP", "nrppa.listofDL_PRSResourceSetARP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_DLPRSResourceSetARP", HFILL }},
    { &hf_nrppa_listofDL_PRSResourceSetARP_item,
      { "DLPRSResourceSetARP", "nrppa.DLPRSResourceSetARP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_dL_PRSResourceSetARPLocation,
      { "dL-PRSResourceSetARPLocation", "nrppa.dL_PRSResourceSetARPLocation",
        FT_UINT32, BASE_DEC, VALS(nrppa_DL_PRSResourceSetARPLocation_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_listofDL_PRSResourceARP,
      { "listofDL-PRSResourceARP", "nrppa.listofDL_PRSResourceARP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceARP", HFILL }},
    { &hf_nrppa_listofDL_PRSResourceARP_item,
      { "DLPRSResourceARP", "nrppa.DLPRSResourceARP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_relativeGeodeticLocation,
      { "relativeGeodeticLocation", "nrppa.relativeGeodeticLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_relativeCartesianLocation,
      { "relativeCartesianLocation", "nrppa.relativeCartesianLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_dL_PRSResourceARPLocation,
      { "dL-PRSResourceARPLocation", "nrppa.dL_PRSResourceARPLocation",
        FT_UINT32, BASE_DEC, VALS(nrppa_DL_PRSResourceARPLocation_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_servingCell_ID,
      { "servingCell-ID", "nrppa.servingCell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NG_RAN_CGI", HFILL }},
    { &hf_nrppa_servingCellTAC,
      { "servingCellTAC", "nrppa.servingCellTAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        "TAC", HFILL }},
    { &hf_nrppa_nG_RANAccessPointPosition,
      { "nG-RANAccessPointPosition", "nrppa.nG_RANAccessPointPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_measuredResults,
      { "measuredResults", "nrppa.measuredResults",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_tRPPositionDefinitionType,
      { "tRPPositionDefinitionType", "nrppa.tRPPositionDefinitionType",
        FT_UINT32, BASE_DEC, VALS(nrppa_TRPPositionDefinitionType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_dLPRSResourceCoordinates,
      { "dLPRSResourceCoordinates", "nrppa.dLPRSResourceCoordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_rxTxTimeDiff,
      { "rxTxTimeDiff", "nrppa.rxTxTimeDiff",
        FT_UINT32, BASE_DEC, VALS(nrppa_GNBRxTxTimeDiffMeas_vals), 0,
        "GNBRxTxTimeDiffMeas", HFILL }},
    { &hf_nrppa_additionalPathList,
      { "additionalPathList", "nrppa.additionalPathList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_k0,
      { "k0", "nrppa.k0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1970049", HFILL }},
    { &hf_nrppa_k1,
      { "k1", "nrppa.k1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_985025", HFILL }},
    { &hf_nrppa_k2,
      { "k2", "nrppa.k2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_492513", HFILL }},
    { &hf_nrppa_k3,
      { "k3", "nrppa.k3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_246257", HFILL }},
    { &hf_nrppa_k4,
      { "k4", "nrppa.k4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_123129", HFILL }},
    { &hf_nrppa_k5,
      { "k5", "nrppa.k5",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_61565", HFILL }},
    { &hf_nrppa_alpha,
      { "alpha", "nrppa.alpha",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3599", HFILL }},
    { &hf_nrppa_beta,
      { "beta", "nrppa.beta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3599", HFILL }},
    { &hf_nrppa_gamma,
      { "gamma", "nrppa.gamma",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3599", HFILL }},
    { &hf_nrppa_alpha_01,
      { "alpha", "nrppa.alpha",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_nrppa_alphaFine,
      { "alphaFine", "nrppa.alphaFine",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nrppa_beta_01,
      { "beta", "nrppa.beta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_nrppa_betaFine,
      { "betaFine", "nrppa.betaFine",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nrppa_gamma_01,
      { "gamma", "nrppa.gamma",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_nrppa_gammaFine,
      { "gammaFine", "nrppa.gammaFine",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nrppa_horizontalUncertainty,
      { "horizontalUncertainty", "nrppa.horizontalUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nrppa_horizontalConfidence,
      { "horizontalConfidence", "nrppa.horizontalConfidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_nrppa_verticalUncertainty,
      { "verticalUncertainty", "nrppa.verticalUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nrppa_verticalConfidence,
      { "verticalConfidence", "nrppa.verticalConfidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_nrppa_loS_NLoSIndicatorSoft,
      { "loS-NLoSIndicatorSoft", "nrppa.loS_NLoSIndicatorSoft",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_loS_NLoSIndicatorHard,
      { "loS-NLoSIndicatorHard", "nrppa.loS_NLoSIndicatorHard",
        FT_UINT32, BASE_DEC, VALS(nrppa_LoS_NLoSIndicatorHard_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_pRS_Resource_ID,
      { "pRS-Resource-ID", "nrppa.pRS_Resource_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRS_Resource_Set_ID,
      { "pRS-Resource-Set-ID", "nrppa.pRS_Resource_Set_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sSB_Index,
      { "sSB-Index", "nrppa.sSB_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementQuantities_item,
      { "ProtocolIE-Single-Container", "nrppa.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_measurementQuantitiesValue,
      { "measurementQuantitiesValue", "nrppa.measurementQuantitiesValue",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasurementQuantitiesValue_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasuredResults_item,
      { "MeasuredResultsValue", "nrppa.MeasuredResultsValue",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasuredResultsValue_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasuredResultsAssociatedInfoList_item,
      { "MeasuredResultsAssociatedInfoItem", "nrppa.MeasuredResultsAssociatedInfoItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_timeStamp,
      { "timeStamp", "nrppa.timeStamp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_measurementQuality,
      { "measurementQuality", "nrppa.measurementQuality",
        FT_UINT32, BASE_DEC, VALS(nrppa_TrpMeasurementQuality_vals), 0,
        "TrpMeasurementQuality", HFILL }},
    { &hf_nrppa_valueAngleOfArrival_EUTRA,
      { "valueAngleOfArrival-EUTRA", "nrppa.valueAngleOfArrival_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_719", HFILL }},
    { &hf_nrppa_valueTimingAdvanceType1_EUTRA,
      { "valueTimingAdvanceType1-EUTRA", "nrppa.valueTimingAdvanceType1_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7690", HFILL }},
    { &hf_nrppa_valueTimingAdvanceType2_EUTRA,
      { "valueTimingAdvanceType2-EUTRA", "nrppa.valueTimingAdvanceType2_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7690", HFILL }},
    { &hf_nrppa_resultRSRP_EUTRA,
      { "resultRSRP-EUTRA", "nrppa.resultRSRP_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_resultRSRQ_EUTRA,
      { "resultRSRQ-EUTRA", "nrppa.resultRSRQ_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_location_Information,
      { "location-Information", "nrppa.location_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_nrppa_velocity_Information,
      { "velocity-Information", "nrppa.velocity_Information",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_nrppa_location_time_stamp,
      { "location-time-stamp", "nrppa.location_time_stamp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_nrppa_multipleULAoA_01,
      { "multipleULAoA", "nrppa.multipleULAoA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MultipleULAoA_List", HFILL }},
    { &hf_nrppa_MultipleULAoA_List_item,
      { "MultipleULAoA-Item", "nrppa.MultipleULAoA_Item",
        FT_UINT32, BASE_DEC, VALS(nrppa_MultipleULAoA_Item_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_uL_AoA,
      { "uL-AoA", "nrppa.uL_AoA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ul_ZoA,
      { "ul-ZoA", "nrppa.ul_ZoA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ZoA", HFILL }},
    { &hf_nrppa_latitudeSign,
      { "latitudeSign", "nrppa.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_latitudeSign_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_latitude,
      { "latitude", "nrppa.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_nrppa_longitude,
      { "longitude", "nrppa.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_nrppa_directionOfAltitude,
      { "directionOfAltitude", "nrppa.directionOfAltitude",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_directionOfAltitude_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_altitude,
      { "altitude", "nrppa.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_nrppa_uncertaintySemi_major,
      { "uncertaintySemi-major", "nrppa.uncertaintySemi_major",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_nrppa_uncertaintySemi_minor,
      { "uncertaintySemi-minor", "nrppa.uncertaintySemi_minor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_nrppa_orientationOfMajorAxis,
      { "orientationOfMajorAxis", "nrppa.orientationOfMajorAxis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_nrppa_uncertaintyAltitude,
      { "uncertaintyAltitude", "nrppa.uncertaintyAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_nrppa_confidence,
      { "confidence", "nrppa.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_nrppa_latitude_01,
      { "latitude", "nrppa.latitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_nrppa_longitude_01,
      { "longitude", "nrppa.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_nrppa_altitude_01,
      { "altitude", "nrppa.altitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M64000_1280000", HFILL }},
    { &hf_nrppa_uncertaintySemi_major_01,
      { "uncertaintySemi-major", "nrppa.uncertaintySemi_major",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nrppa_uncertaintySemi_minor_01,
      { "uncertaintySemi-minor", "nrppa.uncertaintySemi_minor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nrppa_uncertaintyAltitude_01,
      { "uncertaintyAltitude", "nrppa.uncertaintyAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nrppa_nG_RANcell,
      { "nG-RANcell", "nrppa.nG_RANcell",
        FT_UINT32, BASE_DEC, VALS(nrppa_NG_RANCell_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_eUTRA_CellID,
      { "eUTRA-CellID", "nrppa.eUTRA_CellID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EUTRACellIdentifier", HFILL }},
    { &hf_nrppa_nR_CellID,
      { "nR-CellID", "nrppa.nR_CellID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "NRCellIdentifier", HFILL }},
    { &hf_nrppa_nR_PRS_Beam_InformationList,
      { "nR-PRS-Beam-InformationList", "nrppa.nR_PRS_Beam_InformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_NR_PRS_Beam_InformationItem", HFILL }},
    { &hf_nrppa_nR_PRS_Beam_InformationList_item,
      { "NR-PRS-Beam-InformationItem", "nrppa.NR_PRS_Beam_InformationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_lCS_to_GCS_TranslationList,
      { "lCS-to-GCS-TranslationList", "nrppa.lCS_to_GCS_TranslationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnolcs_gcs_translation_OF_LCS_to_GCS_TranslationItem", HFILL }},
    { &hf_nrppa_lCS_to_GCS_TranslationList_item,
      { "LCS-to-GCS-TranslationItem", "nrppa.LCS_to_GCS_TranslationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSresourceSetID,
      { "pRSresourceSetID", "nrppa.pRSresourceSetID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_Resource_Set_ID", HFILL }},
    { &hf_nrppa_pRSAngle,
      { "pRSAngle", "nrppa.pRSAngle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_PRSAngleItem", HFILL }},
    { &hf_nrppa_pRSAngle_item,
      { "PRSAngleItem", "nrppa.PRSAngleItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_onDemandPRSRequestAllowed,
      { "onDemandPRSRequestAllowed", "nrppa.onDemandPRSRequestAllowed",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_nrppa_allowedResourceSetPeriodicityValues,
      { "allowedResourceSetPeriodicityValues", "nrppa.allowedResourceSetPeriodicityValues",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_nrppa_allowedPRSBandwidthValues,
      { "allowedPRSBandwidthValues", "nrppa.allowedPRSBandwidthValues",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_64", HFILL }},
    { &hf_nrppa_allowedResourceRepetitionFactorValues,
      { "allowedResourceRepetitionFactorValues", "nrppa.allowedResourceRepetitionFactorValues",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_nrppa_allowedResourceNumberOfSymbolsValues,
      { "allowedResourceNumberOfSymbolsValues", "nrppa.allowedResourceNumberOfSymbolsValues",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_nrppa_allowedCombSizeValues,
      { "allowedCombSizeValues", "nrppa.allowedCombSizeValues",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_nrppa_OTDOACells_item,
      { "OTDOACells item", "nrppa.OTDOACells_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_oTDOACellInfo,
      { "oTDOACellInfo", "nrppa.oTDOACellInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OTDOACell_Information", HFILL }},
    { &hf_nrppa_OTDOACell_Information_item,
      { "OTDOACell-Information-Item", "nrppa.OTDOACell_Information_Item",
        FT_UINT32, BASE_DEC, VALS(nrppa_OTDOACell_Information_Item_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_pCI_EUTRA,
      { "pCI-EUTRA", "nrppa.pCI_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_cGI_EUTRA,
      { "cGI-EUTRA", "nrppa.cGI_EUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_tAC,
      { "tAC", "nrppa.tAC",
        FT_UINT24, BASE_DEC_HEX, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_eARFCN,
      { "eARFCN", "nrppa.eARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRS_Bandwidth_EUTRA,
      { "pRS-Bandwidth-EUTRA", "nrppa.pRS_Bandwidth_EUTRA",
        FT_UINT32, BASE_DEC, VALS(nrppa_PRS_Bandwidth_EUTRA_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_pRS_ConfigurationIndex_EUTRA,
      { "pRS-ConfigurationIndex-EUTRA", "nrppa.pRS_ConfigurationIndex_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_cPLength_EUTRA,
      { "cPLength-EUTRA", "nrppa.cPLength_EUTRA",
        FT_UINT32, BASE_DEC, VALS(nrppa_CPLength_EUTRA_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_numberOfDlFrames_EUTRA,
      { "numberOfDlFrames-EUTRA", "nrppa.numberOfDlFrames_EUTRA",
        FT_UINT32, BASE_DEC, VALS(nrppa_NumberOfDlFrames_EUTRA_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_numberOfAntennaPorts_EUTRA,
      { "numberOfAntennaPorts-EUTRA", "nrppa.numberOfAntennaPorts_EUTRA",
        FT_UINT32, BASE_DEC, VALS(nrppa_NumberOfAntennaPorts_EUTRA_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sFNInitialisationTime_EUTRA,
      { "sFNInitialisationTime-EUTRA", "nrppa.sFNInitialisationTime_EUTRA",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSMutingConfiguration_EUTRA,
      { "pRSMutingConfiguration-EUTRA", "nrppa.pRSMutingConfiguration_EUTRA",
        FT_UINT32, BASE_DEC, VALS(nrppa_PRSMutingConfiguration_EUTRA_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_prsid_EUTRA,
      { "prsid-EUTRA", "nrppa.prsid_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_ID_EUTRA", HFILL }},
    { &hf_nrppa_tpid_EUTRA,
      { "tpid-EUTRA", "nrppa.tpid_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TP_ID_EUTRA", HFILL }},
    { &hf_nrppa_tpType_EUTRA,
      { "tpType-EUTRA", "nrppa.tpType_EUTRA",
        FT_UINT32, BASE_DEC, VALS(nrppa_TP_Type_EUTRA_vals), 0,
        "TP_Type_EUTRA", HFILL }},
    { &hf_nrppa_numberOfDlFrames_Extended_EUTRA,
      { "numberOfDlFrames-Extended-EUTRA", "nrppa.numberOfDlFrames_Extended_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_crsCPlength_EUTRA,
      { "crsCPlength-EUTRA", "nrppa.crsCPlength_EUTRA",
        FT_UINT32, BASE_DEC, VALS(nrppa_CPLength_EUTRA_vals), 0,
        "CPLength_EUTRA", HFILL }},
    { &hf_nrppa_dL_Bandwidth_EUTRA,
      { "dL-Bandwidth-EUTRA", "nrppa.dL_Bandwidth_EUTRA",
        FT_UINT32, BASE_DEC, VALS(nrppa_DL_Bandwidth_EUTRA_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSOccasionGroup_EUTRA,
      { "pRSOccasionGroup-EUTRA", "nrppa.pRSOccasionGroup_EUTRA",
        FT_UINT32, BASE_DEC, VALS(nrppa_PRSOccasionGroup_EUTRA_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSFrequencyHoppingConfiguration_EUTRA,
      { "pRSFrequencyHoppingConfiguration-EUTRA", "nrppa.pRSFrequencyHoppingConfiguration_EUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_OtherRATMeasurementQuantities_item,
      { "ProtocolIE-Single-Container", "nrppa.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_otherRATMeasurementQuantitiesValue,
      { "otherRATMeasurementQuantitiesValue", "nrppa.otherRATMeasurementQuantitiesValue",
        FT_UINT32, BASE_DEC, VALS(nrppa_OtherRATMeasurementQuantitiesValue_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_OtherRATMeasurementResult_item,
      { "OtherRATMeasuredResultsValue", "nrppa.OtherRATMeasuredResultsValue",
        FT_UINT32, BASE_DEC, VALS(nrppa_OtherRATMeasuredResultsValue_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_resultGERAN,
      { "resultGERAN", "nrppa.resultGERAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_resultUTRAN,
      { "resultUTRAN", "nrppa.resultUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pathlossReferenceSignal,
      { "pathlossReferenceSignal", "nrppa.pathlossReferenceSignal",
        FT_UINT32, BASE_DEC, VALS(nrppa_PathlossReferenceSignal_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sSB_Reference,
      { "sSB-Reference", "nrppa.sSB_Reference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SSB", HFILL }},
    { &hf_nrppa_dL_PRS_Reference,
      { "dL-PRS-Reference", "nrppa.dL_PRS_Reference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DL_PRS", HFILL }},
    { &hf_nrppa_PeriodicityList_item,
      { "PeriodicityItem", "nrppa.PeriodicityItem",
        FT_UINT32, BASE_DEC, VALS(nrppa_PeriodicityItem_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_PosSIBs_item,
      { "PosSIBs item", "nrppa.PosSIBs_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_posSIB_Segments,
      { "posSIB-Segments", "nrppa.posSIB_Segments",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_assistanceInformationMetaData,
      { "assistanceInformationMetaData", "nrppa.assistanceInformationMetaData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_broadcastPriority,
      { "broadcastPriority", "nrppa.broadcastPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16_", HFILL }},
    { &hf_nrppa_PosSIB_Segments_item,
      { "PosSIB-Segments item", "nrppa.PosSIB_Segments_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_assistanceDataSIBelement,
      { "assistanceDataSIBelement", "nrppa.assistanceDataSIBelement",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_nrppa_PosSRSResource_List_item,
      { "PosSRSResource-Item", "nrppa.PosSRSResource_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_srs_PosResourceId,
      { "srs-PosResourceId", "nrppa.srs_PosResourceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SRSPosResourceID", HFILL }},
    { &hf_nrppa_transmissionCombPos,
      { "transmissionCombPos", "nrppa.transmissionCombPos",
        FT_UINT32, BASE_DEC, VALS(nrppa_TransmissionCombPos_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_startPosition,
      { "startPosition", "nrppa.startPosition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_13", HFILL }},
    { &hf_nrppa_nrofSymbols,
      { "nrofSymbols", "nrppa.nrofSymbols",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_nrofSymbols_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_freqDomainShift,
      { "freqDomainShift", "nrppa.freqDomainShift",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_268", HFILL }},
    { &hf_nrppa_c_SRS,
      { "c-SRS", "nrppa.c_SRS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_nrppa_groupOrSequenceHopping,
      { "groupOrSequenceHopping", "nrppa.groupOrSequenceHopping",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_groupOrSequenceHopping_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_resourceTypePos,
      { "resourceTypePos", "nrppa.resourceTypePos",
        FT_UINT32, BASE_DEC, VALS(nrppa_ResourceTypePos_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sequenceId,
      { "sequenceId", "nrppa.sequenceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_nrppa_spatialRelationPos,
      { "spatialRelationPos", "nrppa.spatialRelationPos",
        FT_UINT32, BASE_DEC, VALS(nrppa_SpatialRelationPos_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_PosSRSResourceID_List_item,
      { "SRSPosResourceID", "nrppa.SRSPosResourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PosSRSResourceSet_List_item,
      { "PosSRSResourceSet-Item", "nrppa.PosSRSResourceSet_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PosSRSResourceIDPerSet_List_item,
      { "SRSPosResourceID", "nrppa.SRSPosResourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_possrsResourceSetID,
      { "possrsResourceSetID", "nrppa.possrsResourceSetID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_nrppa_possRSResourceIDPerSet_List,
      { "possRSResourceIDPerSet-List", "nrppa.possRSResourceIDPerSet_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_posresourceSetType,
      { "posresourceSetType", "nrppa.posresourceSetType",
        FT_UINT32, BASE_DEC, VALS(nrppa_PosResourceSetType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_PosSRSResourceSet_Aggregation_List_item,
      { "PosSRSResourceSet-Aggregation-Item", "nrppa.PosSRSResourceSet_Aggregation_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pCI_NR,
      { "pCI-NR", "nrppa.pCI_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1007", HFILL }},
    { &hf_nrppa_periodic,
      { "periodic", "nrppa.periodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosResourceSetTypePeriodic", HFILL }},
    { &hf_nrppa_semi_persistent,
      { "semi-persistent", "nrppa.semi_persistent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosResourceSetTypeSemi_persistent", HFILL }},
    { &hf_nrppa_aperiodic,
      { "aperiodic", "nrppa.aperiodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosResourceSetTypeAperiodic", HFILL }},
    { &hf_nrppa_posperiodicSet,
      { "posperiodicSet", "nrppa.posperiodicSet",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_posperiodicSet_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_possemi_persistentSet,
      { "possemi-persistentSet", "nrppa.possemi_persistentSet",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_possemi_persistentSet_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSResourceTrigger,
      { "sRSResourceTrigger", "nrppa.sRSResourceTrigger",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_3", HFILL }},
    { &hf_nrppa_nRPRSAzimuth,
      { "nRPRSAzimuth", "nrppa.nRPRSAzimuth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_nrppa_nRPRSAzimuthFine,
      { "nRPRSAzimuthFine", "nrppa.nRPRSAzimuthFine",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nrppa_nRPRSElevation,
      { "nRPRSElevation", "nrppa.nRPRSElevation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_180", HFILL }},
    { &hf_nrppa_nRPRSElevationFine,
      { "nRPRSElevationFine", "nrppa.nRPRSElevationFine",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nrppa_pRS_IDPos,
      { "pRS-IDPos", "nrppa.pRS_IDPos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_ID", HFILL }},
    { &hf_nrppa_pRS_Resource_Set_IDPos,
      { "pRS-Resource-Set-IDPos", "nrppa.pRS_Resource_Set_IDPos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_Resource_Set_ID", HFILL }},
    { &hf_nrppa_pRS_Resource_IDPos,
      { "pRS-Resource-IDPos", "nrppa.pRS_Resource_IDPos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_Resource_ID", HFILL }},
    { &hf_nrppa_pRSResourceSet_List,
      { "pRSResourceSet-List", "nrppa.pRSResourceSet_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sixty_four,
      { "sixty-four", "nrppa.sixty_four",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_64", HFILL }},
    { &hf_nrppa_one_hundred_and_twenty_eight,
      { "one-hundred-and-twenty-eight", "nrppa.one_hundred_and_twenty_eight",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_128", HFILL }},
    { &hf_nrppa_two_hundred_and_fifty_six,
      { "two-hundred-and-fifty-six", "nrppa.two_hundred_and_fifty_six",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_256", HFILL }},
    { &hf_nrppa_five_hundred_and_twelve,
      { "five-hundred-and-twelve", "nrppa.five_hundred_and_twelve",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_512", HFILL }},
    { &hf_nrppa_one_thousand_and_twenty_four,
      { "one-thousand-and-twenty-four", "nrppa.one_thousand_and_twenty_four",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1024", HFILL }},
    { &hf_nrppa_noOfFreqHoppingBands,
      { "noOfFreqHoppingBands", "nrppa.noOfFreqHoppingBands",
        FT_UINT32, BASE_DEC, VALS(nrppa_NumberOfFrequencyHoppingBands_vals), 0,
        "NumberOfFrequencyHoppingBands", HFILL }},
    { &hf_nrppa_bandPositions,
      { "bandPositions", "nrppa.bandPositions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex", HFILL }},
    { &hf_nrppa_bandPositions_item,
      { "NarrowBandIndex", "nrppa.NarrowBandIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRS_Measurements_Info_List_item,
      { "PRS-Measurements-Info-List-Item", "nrppa.PRS_Measurements_Info_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_measPRSPeriodicity,
      { "measPRSPeriodicity", "nrppa.measPRSPeriodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_measPRSPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_measPRSOffset,
      { "measPRSOffset", "nrppa.measPRSOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_159_", HFILL }},
    { &hf_nrppa_measurementPRSLength,
      { "measurementPRSLength", "nrppa.measurementPRSLength",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_measurementPRSLength_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSMutingOption1,
      { "pRSMutingOption1", "nrppa.pRSMutingOption1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSMutingOption2,
      { "pRSMutingOption2", "nrppa.pRSMutingOption2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_mutingPattern,
      { "mutingPattern", "nrppa.mutingPattern",
        FT_UINT32, BASE_DEC, VALS(nrppa_DL_PRSMutingPattern_vals), 0,
        "DL_PRSMutingPattern", HFILL }},
    { &hf_nrppa_mutingBitRepetitionFactor,
      { "mutingBitRepetitionFactor", "nrppa.mutingBitRepetitionFactor",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_mutingBitRepetitionFactor_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSResource_List_item,
      { "PRSResource-Item", "nrppa.PRSResource_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSResourceID,
      { "pRSResourceID", "nrppa.pRSResourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_Resource_ID", HFILL }},
    { &hf_nrppa_sequenceID,
      { "sequenceID", "nrppa.sequenceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_nrppa_rEOffset,
      { "rEOffset", "nrppa.rEOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_11_", HFILL }},
    { &hf_nrppa_resourceSlotOffset,
      { "resourceSlotOffset", "nrppa.resourceSlotOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_511", HFILL }},
    { &hf_nrppa_resourceSymbolOffset,
      { "resourceSymbolOffset", "nrppa.resourceSymbolOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_12", HFILL }},
    { &hf_nrppa_qCLInfo,
      { "qCLInfo", "nrppa.qCLInfo",
        FT_UINT32, BASE_DEC, VALS(nrppa_PRSResource_QCLInfo_vals), 0,
        "PRSResource_QCLInfo", HFILL }},
    { &hf_nrppa_qCLSourceSSB,
      { "qCLSourceSSB", "nrppa.qCLSourceSSB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PRSResource_QCLSourceSSB", HFILL }},
    { &hf_nrppa_qCLSourcePRS,
      { "qCLSourcePRS", "nrppa.qCLSourcePRS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PRSResource_QCLSourcePRS", HFILL }},
    { &hf_nrppa_qCLSourcePRSResourceSetID,
      { "qCLSourcePRSResourceSetID", "nrppa.qCLSourcePRSResourceSetID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_Resource_Set_ID", HFILL }},
    { &hf_nrppa_qCLSourcePRSResourceID,
      { "qCLSourcePRSResourceID", "nrppa.qCLSourcePRSResourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_Resource_ID", HFILL }},
    { &hf_nrppa_PRSResourceSet_List_item,
      { "PRSResourceSet-Item", "nrppa.PRSResourceSet_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSResourceSetID,
      { "pRSResourceSetID", "nrppa.pRSResourceSetID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_Resource_Set_ID", HFILL }},
    { &hf_nrppa_subcarrierSpacing_01,
      { "subcarrierSpacing", "nrppa.subcarrierSpacing",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_subcarrierSpacing_01_vals), 0,
        "T_subcarrierSpacing_01", HFILL }},
    { &hf_nrppa_pRSbandwidth,
      { "pRSbandwidth", "nrppa.pRSbandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_63", HFILL }},
    { &hf_nrppa_startPRB,
      { "startPRB", "nrppa.startPRB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2176", HFILL }},
    { &hf_nrppa_combSize,
      { "combSize", "nrppa.combSize",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_combSize_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_cPType,
      { "cPType", "nrppa.cPType",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_cPType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_resourceSetPeriodicity,
      { "resourceSetPeriodicity", "nrppa.resourceSetPeriodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resourceSetPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_resourceSetSlotOffset,
      { "resourceSetSlotOffset", "nrppa.resourceSetSlotOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_81919_", HFILL }},
    { &hf_nrppa_resourceRepetitionFactor,
      { "resourceRepetitionFactor", "nrppa.resourceRepetitionFactor",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resourceRepetitionFactor_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_resourceTimeGap,
      { "resourceTimeGap", "nrppa.resourceTimeGap",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resourceTimeGap_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_resourceNumberofSymbols,
      { "resourceNumberofSymbols", "nrppa.resourceNumberofSymbols",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resourceNumberofSymbols_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSMuting,
      { "pRSMuting", "nrppa.pRSMuting_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSResourceTransmitPower,
      { "pRSResourceTransmitPower", "nrppa.pRSResourceTransmitPower",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M60_50", HFILL }},
    { &hf_nrppa_pRSResource_List,
      { "pRSResource-List", "nrppa.pRSResource_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSTransmissionOffPerTRP,
      { "pRSTransmissionOffPerTRP", "nrppa.pRSTransmissionOffPerTRP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSTransmissionOffPerResourceSet,
      { "pRSTransmissionOffPerResourceSet", "nrppa.pRSTransmissionOffPerResourceSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSTransmissionOffPerResource,
      { "pRSTransmissionOffPerResource", "nrppa.pRSTransmissionOffPerResource",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSTransmissionOffPerResource_item,
      { "PRSTransmissionOffPerResource-Item", "nrppa.PRSTransmissionOffPerResource_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSTransmissionOffIndicationPerResourceList,
      { "pRSTransmissionOffIndicationPerResourceList", "nrppa.pRSTransmissionOffIndicationPerResourceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoofPRSresource_OF_PRSTransmissionOffIndicationPerResource_Item", HFILL }},
    { &hf_nrppa_pRSTransmissionOffIndicationPerResourceList_item,
      { "PRSTransmissionOffIndicationPerResource-Item", "nrppa.PRSTransmissionOffIndicationPerResource_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSTransmissionOffIndication,
      { "pRSTransmissionOffIndication", "nrppa.pRSTransmissionOffIndication",
        FT_UINT32, BASE_DEC, VALS(nrppa_PRSTransmissionOffIndication_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSTransmissionOffPerResourceSet_item,
      { "PRSTransmissionOffPerResourceSet-Item", "nrppa.PRSTransmissionOffPerResourceSet_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSTRPList_item,
      { "PRSTRPItem", "nrppa.PRSTRPItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_tRP_ID,
      { "tRP-ID", "nrppa.tRP_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_requestedDLPRSTransmissionCharacteristics,
      { "requestedDLPRSTransmissionCharacteristics", "nrppa.requestedDLPRSTransmissionCharacteristics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSTransmissionOffInformation,
      { "pRSTransmissionOffInformation", "nrppa.pRSTransmissionOffInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PRSTransmissionTRPList_item,
      { "PRSTransmissionTRPItem", "nrppa.PRSTransmissionTRPItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_pRSConfiguration,
      { "pRSConfiguration", "nrppa.pRSConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PosValidityAreaCellList_item,
      { "PosValidityAreaCell-Item", "nrppa.PosValidityAreaCell_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_nR_CGI,
      { "nR-CGI", "nrppa.nR_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CGI_NR", HFILL }},
    { &hf_nrppa_nR_PCI,
      { "nR-PCI", "nrppa.nR_PCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_nZP_CSI_RS,
      { "nZP-CSI-RS", "nrppa.nZP_CSI_RS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NZP_CSI_RS_ResourceID", HFILL }},
    { &hf_nrppa_sSB,
      { "sSB", "nrppa.sSB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sRS,
      { "sRS", "nrppa.sRS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SRSResourceID", HFILL }},
    { &hf_nrppa_positioningSRS,
      { "positioningSRS", "nrppa.positioningSRS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SRSPosResourceID", HFILL }},
    { &hf_nrppa_dL_PRS,
      { "dL-PRS", "nrppa.dL_PRS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_relativeCoordinateID,
      { "relativeCoordinateID", "nrppa.relativeCoordinateID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CoordinateID", HFILL }},
    { &hf_nrppa_referencePointCoordinate,
      { "referencePointCoordinate", "nrppa.referencePointCoordinate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NG_RANAccessPointPosition", HFILL }},
    { &hf_nrppa_referencePointCoordinateHA,
      { "referencePointCoordinateHA", "nrppa.referencePointCoordinateHA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NGRANHighAccuracyAccessPointPosition", HFILL }},
    { &hf_nrppa_milli_Arc_SecondUnits,
      { "milli-Arc-SecondUnits", "nrppa.milli_Arc_SecondUnits",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_milli_Arc_SecondUnits_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_heightUnits,
      { "heightUnits", "nrppa.heightUnits",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_heightUnits_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_deltaLatitude,
      { "deltaLatitude", "nrppa.deltaLatitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_nrppa_deltaLongitude,
      { "deltaLongitude", "nrppa.deltaLongitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_nrppa_deltaHeight,
      { "deltaHeight", "nrppa.deltaHeight",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_nrppa_locationUncertainty,
      { "locationUncertainty", "nrppa.locationUncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_xYZunit,
      { "xYZunit", "nrppa.xYZunit",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_xYZunit_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_xvalue,
      { "xvalue", "nrppa.xvalue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M65536_65535", HFILL }},
    { &hf_nrppa_yvalue,
      { "yvalue", "nrppa.yvalue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M65536_65535", HFILL }},
    { &hf_nrppa_zvalue,
      { "zvalue", "nrppa.zvalue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_nrppa_k0_01,
      { "k0", "nrppa.k0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16351", HFILL }},
    { &hf_nrppa_k1_01,
      { "k1", "nrppa.k1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8176", HFILL }},
    { &hf_nrppa_k2_01,
      { "k2", "nrppa.k2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4088", HFILL }},
    { &hf_nrppa_k3_01,
      { "k3", "nrppa.k3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2044", HFILL }},
    { &hf_nrppa_k4_01,
      { "k4", "nrppa.k4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1022", HFILL }},
    { &hf_nrppa_k5_01,
      { "k5", "nrppa.k5",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_511", HFILL }},
    { &hf_nrppa_requestedDLPRSResourceSet_List,
      { "requestedDLPRSResourceSet-List", "nrppa.requestedDLPRSResourceSet_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_numberofFrequencyLayers,
      { "numberofFrequencyLayers", "nrppa.numberofFrequencyLayers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_4", HFILL }},
    { &hf_nrppa_startTimeAndDuration,
      { "startTimeAndDuration", "nrppa.startTimeAndDuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_RequestedDLPRSResourceSet_List_item,
      { "RequestedDLPRSResourceSet-Item", "nrppa.RequestedDLPRSResourceSet_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_combSize_01,
      { "combSize", "nrppa.combSize",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_combSize_01_vals), 0,
        "T_combSize_01", HFILL }},
    { &hf_nrppa_resourceSetPeriodicity_01,
      { "resourceSetPeriodicity", "nrppa.resourceSetPeriodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resourceSetPeriodicity_01_vals), 0,
        "T_resourceSetPeriodicity_01", HFILL }},
    { &hf_nrppa_resourceRepetitionFactor_01,
      { "resourceRepetitionFactor", "nrppa.resourceRepetitionFactor",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resourceRepetitionFactor_01_vals), 0,
        "T_resourceRepetitionFactor_01", HFILL }},
    { &hf_nrppa_resourceNumberofSymbols_01,
      { "resourceNumberofSymbols", "nrppa.resourceNumberofSymbols",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resourceNumberofSymbols_01_vals), 0,
        "T_resourceNumberofSymbols_01", HFILL }},
    { &hf_nrppa_requestedDLPRSResource_List,
      { "requestedDLPRSResource-List", "nrppa.requestedDLPRSResource_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_resourceSetStartTimeAndDuration,
      { "resourceSetStartTimeAndDuration", "nrppa.resourceSetStartTimeAndDuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StartTimeAndDuration", HFILL }},
    { &hf_nrppa_RequestedDLPRSResource_List_item,
      { "RequestedDLPRSResource-Item", "nrppa.RequestedDLPRSResource_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_numberOfTransmissions,
      { "numberOfTransmissions", "nrppa.numberOfTransmissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_500_", HFILL }},
    { &hf_nrppa_resourceType,
      { "resourceType", "nrppa.resourceType",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resourceType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_bandwidth,
      { "bandwidth", "nrppa.bandwidth",
        FT_UINT32, BASE_DEC, VALS(nrppa_BandwidthSRS_vals), 0,
        "BandwidthSRS", HFILL }},
    { &hf_nrppa_listOfSRSResourceSet,
      { "listOfSRSResourceSet", "nrppa.listOfSRSResourceSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoSRS_ResourceSets_OF_SRSResourceSet_Item", HFILL }},
    { &hf_nrppa_listOfSRSResourceSet_item,
      { "SRSResourceSet-Item", "nrppa.SRSResourceSet_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sSBInformation,
      { "sSBInformation", "nrppa.sSBInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SSBInfo", HFILL }},
    { &hf_nrppa_nrofSumbols,
      { "nrofSumbols", "nrppa.nrofSumbols",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_nrofSumbols_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_RequestedSRSPreconfigurationCharacteristics_List_item,
      { "RequestedSRSPreconfigurationCharacteristics-Item", "nrppa.RequestedSRSPreconfigurationCharacteristics_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_requestedSRSTransmissionCharacteristics,
      { "requestedSRSTransmissionCharacteristics", "nrppa.requestedSRSTransmissionCharacteristics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_numberOfSRSResourcePerSet,
      { "numberOfSRSResourcePerSet", "nrppa.numberOfSRSResourcePerSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16_", HFILL }},
    { &hf_nrppa_periodicityList,
      { "periodicityList", "nrppa.periodicityList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_spatialRelationInformation,
      { "spatialRelationInformation", "nrppa.spatialRelationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SpatialRelationInfo", HFILL }},
    { &hf_nrppa_pathlossReferenceInformation,
      { "pathlossReferenceInformation", "nrppa.pathlossReferenceInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_periodic_01,
      { "periodic", "nrppa.periodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceSetTypePeriodic", HFILL }},
    { &hf_nrppa_semi_persistent_01,
      { "semi-persistent", "nrppa.semi_persistent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceSetTypeSemi_persistent", HFILL }},
    { &hf_nrppa_aperiodic_01,
      { "aperiodic", "nrppa.aperiodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceSetTypeAperiodic", HFILL }},
    { &hf_nrppa_periodicSet,
      { "periodicSet", "nrppa.periodicSet",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_periodicSet_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_semi_persistentSet,
      { "semi-persistentSet", "nrppa.semi_persistentSet",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_semi_persistentSet_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_slotoffset,
      { "slotoffset", "nrppa.slotoffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32", HFILL }},
    { &hf_nrppa_periodic_02,
      { "periodic", "nrppa.periodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceTypePeriodic", HFILL }},
    { &hf_nrppa_semi_persistent_02,
      { "semi-persistent", "nrppa.semi_persistent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceTypeSemi_persistent", HFILL }},
    { &hf_nrppa_aperiodic_02,
      { "aperiodic", "nrppa.aperiodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceTypeAperiodic", HFILL }},
    { &hf_nrppa_periodicity,
      { "periodicity", "nrppa.periodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_periodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_offset,
      { "offset", "nrppa.offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2559_", HFILL }},
    { &hf_nrppa_periodicity_01,
      { "periodicity", "nrppa.periodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_periodicity_01_vals), 0,
        "T_periodicity_01", HFILL }},
    { &hf_nrppa_aperiodicResourceType,
      { "aperiodicResourceType", "nrppa.aperiodicResourceType",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_aperiodicResourceType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_periodic_03,
      { "periodic", "nrppa.periodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceTypePeriodicPos", HFILL }},
    { &hf_nrppa_semi_persistent_03,
      { "semi-persistent", "nrppa.semi_persistent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceTypeSemi_persistentPos", HFILL }},
    { &hf_nrppa_aperiodic_03,
      { "aperiodic", "nrppa.aperiodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResourceTypeAperiodicPos", HFILL }},
    { &hf_nrppa_sRSPeriodicity,
      { "sRSPeriodicity", "nrppa.sRSPeriodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_SRSPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_offset_01,
      { "offset", "nrppa.offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_81919_", HFILL }},
    { &hf_nrppa_slotOffset,
      { "slotOffset", "nrppa.slotOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32", HFILL }},
    { &hf_nrppa_time,
      { "time", "nrppa.time",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_128_", HFILL }},
    { &hf_nrppa_timeUnit,
      { "timeUnit", "nrppa.timeUnit",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_timeUnit_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultCSI_RSRP_item,
      { "ResultCSI-RSRP-Item", "nrppa.ResultCSI_RSRP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_nR_ARFCN,
      { "nR-ARFCN", "nrppa.nR_ARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_cGI_NR,
      { "cGI-NR", "nrppa.cGI_NR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_valueCSI_RSRP_Cell,
      { "valueCSI-RSRP-Cell", "nrppa.valueCSI_RSRP_Cell",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ValueRSRP_NR", HFILL }},
    { &hf_nrppa_cSI_RSRP_PerCSI_RS,
      { "cSI-RSRP-PerCSI-RS", "nrppa.cSI_RSRP_PerCSI_RS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResultCSI_RSRP_PerCSI_RS", HFILL }},
    { &hf_nrppa_ResultCSI_RSRP_PerCSI_RS_item,
      { "ResultCSI-RSRP-PerCSI-RS-Item", "nrppa.ResultCSI_RSRP_PerCSI_RS_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_cSI_RS_Index,
      { "cSI-RS-Index", "nrppa.cSI_RS_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_95", HFILL }},
    { &hf_nrppa_valueCSI_RSRP,
      { "valueCSI-RSRP", "nrppa.valueCSI_RSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ValueRSRP_NR", HFILL }},
    { &hf_nrppa_ResultCSI_RSRQ_item,
      { "ResultCSI-RSRQ-Item", "nrppa.ResultCSI_RSRQ_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_valueCSI_RSRQ_Cell,
      { "valueCSI-RSRQ-Cell", "nrppa.valueCSI_RSRQ_Cell",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ValueRSRQ_NR", HFILL }},
    { &hf_nrppa_cSI_RSRQ_PerCSI_RS,
      { "cSI-RSRQ-PerCSI-RS", "nrppa.cSI_RSRQ_PerCSI_RS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResultCSI_RSRQ_PerCSI_RS", HFILL }},
    { &hf_nrppa_ResultCSI_RSRQ_PerCSI_RS_item,
      { "ResultCSI-RSRQ-PerCSI-RS-Item", "nrppa.ResultCSI_RSRQ_PerCSI_RS_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_valueCSI_RSRQ,
      { "valueCSI-RSRQ", "nrppa.valueCSI_RSRQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ValueRSRQ_NR", HFILL }},
    { &hf_nrppa_ResultEUTRA_item,
      { "ResultEUTRA-Item", "nrppa.ResultEUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_valueRSRP_EUTRA,
      { "valueRSRP-EUTRA", "nrppa.valueRSRP_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_valueRSRQ_EUTRA,
      { "valueRSRQ-EUTRA", "nrppa.valueRSRQ_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultRSRP_EUTRA_item,
      { "ResultRSRP-EUTRA-Item", "nrppa.ResultRSRP_EUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultRSRQ_EUTRA_item,
      { "ResultRSRQ-EUTRA-Item", "nrppa.ResultRSRQ_EUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_cGI_UTRA,
      { "cGI-UTRA", "nrppa.cGI_UTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CGI_EUTRA", HFILL }},
    { &hf_nrppa_ResultSS_RSRP_item,
      { "ResultSS-RSRP-Item", "nrppa.ResultSS_RSRP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_valueSS_RSRP_Cell,
      { "valueSS-RSRP-Cell", "nrppa.valueSS_RSRP_Cell",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ValueRSRP_NR", HFILL }},
    { &hf_nrppa_sS_RSRP_PerSSB,
      { "sS-RSRP-PerSSB", "nrppa.sS_RSRP_PerSSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResultSS_RSRP_PerSSB", HFILL }},
    { &hf_nrppa_ResultSS_RSRP_PerSSB_item,
      { "ResultSS-RSRP-PerSSB-Item", "nrppa.ResultSS_RSRP_PerSSB_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_valueSS_RSRP,
      { "valueSS-RSRP", "nrppa.valueSS_RSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ValueRSRP_NR", HFILL }},
    { &hf_nrppa_ResultSS_RSRQ_item,
      { "ResultSS-RSRQ-Item", "nrppa.ResultSS_RSRQ_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_valueSS_RSRQ_Cell,
      { "valueSS-RSRQ-Cell", "nrppa.valueSS_RSRQ_Cell",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ValueRSRQ_NR", HFILL }},
    { &hf_nrppa_sS_RSRQ_PerSSB,
      { "sS-RSRQ-PerSSB", "nrppa.sS_RSRQ_PerSSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResultSS_RSRQ_PerSSB", HFILL }},
    { &hf_nrppa_ResultSS_RSRQ_PerSSB_item,
      { "ResultSS-RSRQ-PerSSB-Item", "nrppa.ResultSS_RSRQ_PerSSB_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_valueSS_RSRQ,
      { "valueSS-RSRQ", "nrppa.valueSS_RSRQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ValueRSRQ_NR", HFILL }},
    { &hf_nrppa_ResultGERAN_item,
      { "ResultGERAN-Item", "nrppa.ResultGERAN_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_bCCH,
      { "bCCH", "nrppa.bCCH",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_physCellIDGERAN,
      { "physCellIDGERAN", "nrppa.physCellIDGERAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_rSSI,
      { "rSSI", "nrppa.rSSI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultNR_item,
      { "ResultNR-Item", "nrppa.ResultNR_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultUTRAN_item,
      { "ResultUTRAN-Item", "nrppa.ResultUTRAN_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_uARFCN,
      { "uARFCN", "nrppa.uARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_physCellIDUTRAN,
      { "physCellIDUTRAN", "nrppa.physCellIDUTRAN",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_physCellIDUTRAN_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_physCellIDUTRA_FDD,
      { "physCellIDUTRA-FDD", "nrppa.physCellIDUTRA_FDD",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_physCellIDUTRA_TDD,
      { "physCellIDUTRA-TDD", "nrppa.physCellIDUTRA_TDD",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_uTRA_RSCP,
      { "uTRA-RSCP", "nrppa.uTRA_RSCP",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_uTRA_EcN0,
      { "uTRA-EcN0", "nrppa.uTRA_EcN0",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_subcarrierSpacing_02,
      { "subcarrierSpacing", "nrppa.subcarrierSpacing",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_subcarrierSpacing_02_vals), 0,
        "T_subcarrierSpacing_02", HFILL }},
    { &hf_nrppa_carrierBandwidth,
      { "carrierBandwidth", "nrppa.carrierBandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_275_", HFILL }},
    { &hf_nrppa_expectedPropagationDelay,
      { "expectedPropagationDelay", "nrppa.expectedPropagationDelay",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M3841_3841_", HFILL }},
    { &hf_nrppa_delayUncertainty,
      { "delayUncertainty", "nrppa.delayUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_246_", HFILL }},
    { &hf_nrppa_SlotOffsetForRemainingHopsList_item,
      { "SlotOffsetForRemainingHopsItem", "nrppa.SlotOffsetForRemainingHopsItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_slotOffsetRemainingHops,
      { "slotOffsetRemainingHops", "nrppa.slotOffsetRemainingHops",
        FT_UINT32, BASE_DEC, VALS(nrppa_SlotOffsetRemainingHops_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_aperiodic_04,
      { "aperiodic", "nrppa.aperiodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SlotOffsetRemainingHopsAperiodic", HFILL }},
    { &hf_nrppa_semi_persistent_04,
      { "semi-persistent", "nrppa.semi_persistent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SlotOffsetRemainingHopsSemiPersistent", HFILL }},
    { &hf_nrppa_periodic_04,
      { "periodic", "nrppa.periodic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SlotOffsetRemainingHopsPeriodic", HFILL }},
    { &hf_nrppa_slotOffset_01,
      { "slotOffset", "nrppa.slotOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_nrppa_sRSperiodicity,
      { "sRSperiodicity", "nrppa.sRSperiodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_SRSPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_nR_PRS_Beam_Information,
      { "nR-PRS-Beam-Information", "nrppa.nR_PRS_Beam_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_spatialRelationforResourceID,
      { "spatialRelationforResourceID", "nrppa.spatialRelationforResourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SpatialRelationforResourceID_item,
      { "SpatialRelationforResourceIDItem", "nrppa.SpatialRelationforResourceIDItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_referenceSignal,
      { "referenceSignal", "nrppa.referenceSignal",
        FT_UINT32, BASE_DEC, VALS(nrppa_ReferenceSignal_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_spatialRelationPerSRSResource_List,
      { "spatialRelationPerSRSResource-List", "nrppa.spatialRelationPerSRSResource_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SpatialRelationPerSRSResource_List_item,
      { "SpatialRelationPerSRSResourceItem", "nrppa.SpatialRelationPerSRSResourceItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sSBPos,
      { "sSBPos", "nrppa.sSBPos_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SSB", HFILL }},
    { &hf_nrppa_pRSInformationPos,
      { "pRSInformationPos", "nrppa.pRSInformationPos_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSResource_List,
      { "sRSResource-List", "nrppa.sRSResource_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_posSRSResource_List,
      { "posSRSResource-List", "nrppa.posSRSResource_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSResourceSet_List,
      { "sRSResourceSet-List", "nrppa.sRSResourceSet_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_posSRSResourceSet_List,
      { "posSRSResourceSet-List", "nrppa.posSRSResourceSet_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSCarrier_List_item,
      { "SRSCarrier-List-Item", "nrppa.SRSCarrier_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_uplinkChannelBW_PerSCS_List,
      { "uplinkChannelBW-PerSCS-List", "nrppa.uplinkChannelBW_PerSCS_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_activeULBWP,
      { "activeULBWP", "nrppa.activeULBWP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSCarrier_List,
      { "sRSCarrier-List", "nrppa.sRSCarrier_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSResourceID,
      { "sRSResourceID", "nrppa.sRSResourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_nrofSRS_Ports,
      { "nrofSRS-Ports", "nrppa.nrofSRS_Ports",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_nrofSRS_Ports_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_transmissionComb,
      { "transmissionComb", "nrppa.transmissionComb",
        FT_UINT32, BASE_DEC, VALS(nrppa_TransmissionComb_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_nrofSymbols_01,
      { "nrofSymbols", "nrppa.nrofSymbols",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_nrofSymbols_01_vals), 0,
        "T_nrofSymbols_01", HFILL }},
    { &hf_nrppa_repetitionFactor,
      { "repetitionFactor", "nrppa.repetitionFactor",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_repetitionFactor_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_freqDomainPosition,
      { "freqDomainPosition", "nrppa.freqDomainPosition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_67", HFILL }},
    { &hf_nrppa_b_SRS,
      { "b-SRS", "nrppa.b_SRS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_nrppa_b_hop,
      { "b-hop", "nrppa.b_hop",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_nrppa_groupOrSequenceHopping_01,
      { "groupOrSequenceHopping", "nrppa.groupOrSequenceHopping",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_groupOrSequenceHopping_01_vals), 0,
        "T_groupOrSequenceHopping_01", HFILL }},
    { &hf_nrppa_resourceType_01,
      { "resourceType", "nrppa.resourceType",
        FT_UINT32, BASE_DEC, VALS(nrppa_ResourceType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sequenceId_01,
      { "sequenceId", "nrppa.sequenceId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_nrppa_SRSResource_List_item,
      { "SRSResource", "nrppa.SRSResource_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSResourceSet_List_item,
      { "SRSResourceSet", "nrppa.SRSResourceSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSResourceID_List_item,
      { "SRSResourceID", "nrppa.SRSResourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSResourceSetID1,
      { "sRSResourceSetID1", "nrppa.sRSResourceSetID1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_nrppa_sRSResourceID_List,
      { "sRSResourceID-List", "nrppa.sRSResourceID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_resourceSetType,
      { "resourceSetType", "nrppa.resourceSetType",
        FT_UINT32, BASE_DEC, VALS(nrppa_ResourceSetType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_aperiodicSRSResourceTriggerList,
      { "aperiodicSRSResourceTriggerList", "nrppa.aperiodicSRSResourceTriggerList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSResourceTypeChoice,
      { "sRSResourceTypeChoice", "nrppa.sRSResourceTypeChoice",
        FT_UINT32, BASE_DEC, VALS(nrppa_SRSResourceTypeChoice_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSResourceInfo,
      { "sRSResourceInfo", "nrppa.sRSResourceInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SRSInfo", HFILL }},
    { &hf_nrppa_posSRSResourceInfo,
      { "posSRSResourceInfo", "nrppa.posSRSResourceInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosSRSInfo", HFILL }},
    { &hf_nrppa_sRSResource,
      { "sRSResource", "nrppa.sRSResource",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SRSResourceID", HFILL }},
    { &hf_nrppa_posSRSResourceID,
      { "posSRSResourceID", "nrppa.posSRSResourceID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SRSPosResourceID", HFILL }},
    { &hf_nrppa_listOfSSBInfo,
      { "listOfSSBInfo", "nrppa.listOfSSBInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxNoSSBs_OF_SSBInfoItem", HFILL }},
    { &hf_nrppa_listOfSSBInfo_item,
      { "SSBInfoItem", "nrppa.SSBInfoItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sSB_Configuration,
      { "sSB-Configuration", "nrppa.sSB_Configuration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TF_Configuration", HFILL }},
    { &hf_nrppa_ssb_index,
      { "ssb-index", "nrppa.ssb_index",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_shortBitmap,
      { "shortBitmap", "nrppa.shortBitmap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_nrppa_mediumBitmap,
      { "mediumBitmap", "nrppa.mediumBitmap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_nrppa_longBitmap,
      { "longBitmap", "nrppa.longBitmap",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_64", HFILL }},
    { &hf_nrppa_freqScalingFactor2,
      { "freqScalingFactor2", "nrppa.freqScalingFactor2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_nrppa_freqScalingFactor4,
      { "freqScalingFactor4", "nrppa.freqScalingFactor4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_nrppa_startTime,
      { "startTime", "nrppa.startTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RelativeTime1900", HFILL }},
    { &hf_nrppa_duration,
      { "duration", "nrppa.duration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_90060_", HFILL }},
    { &hf_nrppa_SystemInformation_item,
      { "SystemInformation item", "nrppa.SystemInformation_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_broadcastPeriodicity,
      { "broadcastPeriodicity", "nrppa.broadcastPeriodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_BroadcastPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_posSIBs,
      { "posSIBs", "nrppa.posSIBs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_SRSPreconfiguration_List_item,
      { "SRSPreconfiguration-Item", "nrppa.SRSPreconfiguration_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSConfiguration,
      { "sRSConfiguration", "nrppa.sRSConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_posValidityAreaCellList,
      { "posValidityAreaCellList", "nrppa.posValidityAreaCellList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_subframeAssignment,
      { "subframeAssignment", "nrppa.subframeAssignment",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_subframeAssignment_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_rxTx_TEG,
      { "rxTx-TEG", "nrppa.rxTx_TEG_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RxTxTEG", HFILL }},
    { &hf_nrppa_rx_TEG,
      { "rx-TEG", "nrppa.rx_TEG_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RxTEG", HFILL }},
    { &hf_nrppa_tRP_RxTx_TEGInformation,
      { "tRP-RxTx-TEGInformation", "nrppa.tRP_RxTx_TEGInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_tRP_Tx_TEGInformation,
      { "tRP-Tx-TEGInformation", "nrppa.tRP_Tx_TEGInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_tRP_Rx_TEGInformation,
      { "tRP-Rx-TEGInformation", "nrppa.tRP_Rx_TEGInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sSB_frequency,
      { "sSB-frequency", "nrppa.sSB_frequency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3279165", HFILL }},
    { &hf_nrppa_sSB_subcarrier_spacing,
      { "sSB-subcarrier-spacing", "nrppa.sSB_subcarrier_spacing",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_sSB_subcarrier_spacing_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sSB_Transmit_power,
      { "sSB-Transmit-power", "nrppa.sSB_Transmit_power",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M60_50", HFILL }},
    { &hf_nrppa_sSB_periodicity,
      { "sSB-periodicity", "nrppa.sSB_periodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_sSB_periodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sSB_half_frame_offset,
      { "sSB-half-frame-offset", "nrppa.sSB_half_frame_offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_nrppa_sSB_SFN_offset,
      { "sSB-SFN-offset", "nrppa.sSB_SFN_offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_nrppa_sSB_BurstPosition,
      { "sSB-BurstPosition", "nrppa.sSB_BurstPosition",
        FT_UINT32, BASE_DEC, VALS(nrppa_SSBBurstPosition_vals), 0,
        "SSBBurstPosition", HFILL }},
    { &hf_nrppa_sFN_initialisation_time,
      { "sFN-initialisation-time", "nrppa.sFN_initialisation_time",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RelativeTime1900", HFILL }},
    { &hf_nrppa_systemFrameNumber,
      { "systemFrameNumber", "nrppa.systemFrameNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_slotIndex,
      { "slotIndex", "nrppa.slotIndex",
        FT_UINT32, BASE_DEC, VALS(nrppa_TimeStampSlotIndex_vals), 0,
        "TimeStampSlotIndex", HFILL }},
    { &hf_nrppa_measurementTime,
      { "measurementTime", "nrppa.measurementTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RelativeTime1900", HFILL }},
    { &hf_nrppa_iE_Extension,
      { "iE-Extension", "nrppa.iE_Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_nrppa_sCS_15,
      { "sCS-15", "nrppa.sCS_15",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nrppa_sCS_30,
      { "sCS-30", "nrppa.sCS_30",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_19", HFILL }},
    { &hf_nrppa_sCS_60,
      { "sCS-60", "nrppa.sCS_60",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_39", HFILL }},
    { &hf_nrppa_sCS_120,
      { "sCS-120", "nrppa.sCS_120",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_79", HFILL }},
    { &hf_nrppa_durationSlots,
      { "durationSlots", "nrppa.durationSlots",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_durationSlots_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_durationSymbols,
      { "durationSymbols", "nrppa.durationSymbols",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_durationSymbols_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_durationSlots_01,
      { "durationSlots", "nrppa.durationSlots",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_durationSlots_01_vals), 0,
        "T_durationSlots_01", HFILL }},
    { &hf_nrppa_slotNumber,
      { "slotNumber", "nrppa.slotNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_symbolIndex,
      { "symbolIndex", "nrppa.symbolIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_13", HFILL }},
    { &hf_nrppa_TimeWindowInformation_Measurement_List_item,
      { "TimeWindowInformation-Measurement-Item", "nrppa.TimeWindowInformation_Measurement_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_timeWindowDurationMeasurement,
      { "timeWindowDurationMeasurement", "nrppa.timeWindowDurationMeasurement",
        FT_UINT32, BASE_DEC, VALS(nrppa_TimeWindowDurationMeasurement_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_timeWindowType,
      { "timeWindowType", "nrppa.timeWindowType",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_timeWindowType_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_timeWindowPeriodicityMeasurement,
      { "timeWindowPeriodicityMeasurement", "nrppa.timeWindowPeriodicityMeasurement",
        FT_UINT32, BASE_DEC, VALS(nrppa_TimeWindowPeriodicityMeasurement_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_TimeWindowInformation_SRS_List_item,
      { "TimeWindowInformation-SRS-Item", "nrppa.TimeWindowInformation_SRS_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_timeWindowStartSRS,
      { "timeWindowStartSRS", "nrppa.timeWindowStartSRS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_timeWindowDurationSRS,
      { "timeWindowDurationSRS", "nrppa.timeWindowDurationSRS",
        FT_UINT32, BASE_DEC, VALS(nrppa_TimeWindowDurationSRS_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_timeWindowType_01,
      { "timeWindowType", "nrppa.timeWindowType",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_timeWindowType_01_vals), 0,
        "T_timeWindowType_01", HFILL }},
    { &hf_nrppa_timeWindowPeriodicitySRS,
      { "timeWindowPeriodicitySRS", "nrppa.timeWindowPeriodicitySRS",
        FT_UINT32, BASE_DEC, VALS(nrppa_TimeWindowPeriodicitySRS_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_n2,
      { "n2", "nrppa.n2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_combOffset_n2,
      { "combOffset-n2", "nrppa.combOffset_n2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_nrppa_cyclicShift_n2,
      { "cyclicShift-n2", "nrppa.cyclicShift_n2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_nrppa_n4,
      { "n4", "nrppa.n4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_combOffset_n4,
      { "combOffset-n4", "nrppa.combOffset_n4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_nrppa_cyclicShift_n4,
      { "cyclicShift-n4", "nrppa.cyclicShift_n4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_11", HFILL }},
    { &hf_nrppa_combOffset_n8,
      { "combOffset-n8", "nrppa.combOffset_n8",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_nrppa_cyclicShift_n8,
      { "cyclicShift-n8", "nrppa.cyclicShift_n8",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_5", HFILL }},
    { &hf_nrppa_n2_01,
      { "n2", "nrppa.n2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_n2_01", HFILL }},
    { &hf_nrppa_n4_01,
      { "n4", "nrppa.n4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_n4_01", HFILL }},
    { &hf_nrppa_n8,
      { "n8", "nrppa.n8_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_choice_TRP_Beam_Antenna_Info_Item,
      { "choice-TRP-Beam-Antenna-Info-Item", "nrppa.choice_TRP_Beam_Antenna_Info_Item",
        FT_UINT32, BASE_DEC, VALS(nrppa_Choice_TRP_Beam_Antenna_Info_Item_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_reference,
      { "reference", "nrppa.reference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TRP_ID", HFILL }},
    { &hf_nrppa_explicit,
      { "explicit", "nrppa.explicit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TRP_BeamAntennaExplicitInformation", HFILL }},
    { &hf_nrppa_noChange,
      { "noChange", "nrppa.noChange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_trp_BeamAntennaAngles,
      { "trp-BeamAntennaAngles", "nrppa.trp_BeamAntennaAngles",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_lcs_to_gcs_translation,
      { "lcs-to-gcs-translation", "nrppa.lcs_to_gcs_translation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRP_BeamAntennaAngles_item,
      { "TRP-BeamAntennaAnglesList-Item", "nrppa.TRP_BeamAntennaAnglesList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_trp_azimuth_angle,
      { "trp-azimuth-angle", "nrppa.trp_azimuth_angle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_nrppa_trp_azimuth_angle_fine,
      { "trp-azimuth-angle-fine", "nrppa.trp_azimuth_angle_fine",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nrppa_trp_elevation_angle_list,
      { "trp-elevation-angle-list", "nrppa.trp_elevation_angle_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoElevationAngles_OF_TRP_ElevationAngleList_Item", HFILL }},
    { &hf_nrppa_trp_elevation_angle_list_item,
      { "TRP-ElevationAngleList-Item", "nrppa.TRP_ElevationAngleList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_trp_elevation_angle,
      { "trp-elevation-angle", "nrppa.trp_elevation_angle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_180", HFILL }},
    { &hf_nrppa_trp_elevation_angle_fine,
      { "trp-elevation-angle-fine", "nrppa.trp_elevation_angle_fine",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nrppa_trp_beam_power_list,
      { "trp-beam-power-list", "nrppa.trp_beam_power_list",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_2_maxNumResourcesPerAngle_OF_TRP_Beam_Power_Item", HFILL }},
    { &hf_nrppa_trp_beam_power_list_item,
      { "TRP-Beam-Power-Item", "nrppa.TRP_Beam_Power_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_relativePower,
      { "relativePower", "nrppa.relativePower",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_30", HFILL }},
    { &hf_nrppa_relativePowerFine,
      { "relativePowerFine", "nrppa.relativePowerFine",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_nrppa_TRPMeasurementQuantities_item,
      { "TRPMeasurementQuantitiesList-Item", "nrppa.TRPMeasurementQuantitiesList_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_tRPMeasurementQuantities_Item,
      { "tRPMeasurementQuantities-Item", "nrppa.tRPMeasurementQuantities_Item",
        FT_UINT32, BASE_DEC, VALS(nrppa_TRPMeasurementType_vals), 0,
        "TRPMeasurementType", HFILL }},
    { &hf_nrppa_timingReportingGranularityFactor,
      { "timingReportingGranularityFactor", "nrppa.timingReportingGranularityFactor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_5", HFILL }},
    { &hf_nrppa_TrpMeasurementResult_item,
      { "TrpMeasurementResultItem", "nrppa.TrpMeasurementResultItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_measuredResultsValue,
      { "measuredResultsValue", "nrppa.measuredResultsValue",
        FT_UINT32, BASE_DEC, VALS(nrppa_TrpMeasuredResultsValue_vals), 0,
        "TrpMeasuredResultsValue", HFILL }},
    { &hf_nrppa_measurementBeamInfo,
      { "measurementBeamInfo", "nrppa.measurementBeamInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_uL_AngleOfArrival,
      { "uL-AngleOfArrival", "nrppa.uL_AngleOfArrival_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL_AoA", HFILL }},
    { &hf_nrppa_uL_SRS_RSRP,
      { "uL-SRS-RSRP", "nrppa.uL_SRS_RSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_uL_RTOA,
      { "uL-RTOA", "nrppa.uL_RTOA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UL_RTOAMeasurement", HFILL }},
    { &hf_nrppa_gNB_RxTxTimeDiff,
      { "gNB-RxTxTimeDiff", "nrppa.gNB_RxTxTimeDiff_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_timingMeasQuality,
      { "timingMeasQuality", "nrppa.timingMeasQuality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TrpMeasurementTimingQuality", HFILL }},
    { &hf_nrppa_angleMeasQuality,
      { "angleMeasQuality", "nrppa.angleMeasQuality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TrpMeasurementAngleQuality", HFILL }},
    { &hf_nrppa_measurementQuality_01,
      { "measurementQuality", "nrppa.measurementQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_nrppa_resolution,
      { "resolution", "nrppa.resolution",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resolution_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_azimuthQuality,
      { "azimuthQuality", "nrppa.azimuthQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nrppa_zenithQuality,
      { "zenithQuality", "nrppa.zenithQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nrppa_resolution_01,
      { "resolution", "nrppa.resolution",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resolution_01_vals), 0,
        "T_resolution_01", HFILL }},
    { &hf_nrppa_phaseQualityIndex,
      { "phaseQualityIndex", "nrppa.phaseQualityIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_nrppa_resolution_02,
      { "resolution", "nrppa.resolution",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_resolution_02_vals), 0,
        "T_resolution_02", HFILL }},
    { &hf_nrppa_TRP_MeasurementRequestList_item,
      { "TRP-MeasurementRequestItem", "nrppa.TRP_MeasurementRequestItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_search_window_information,
      { "search-window-information", "nrppa.search_window_information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRP_MeasurementResponseList_item,
      { "TRP-MeasurementResponseItem", "nrppa.TRP_MeasurementResponseItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_measurementResult,
      { "measurementResult", "nrppa.measurementResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TrpMeasurementResult", HFILL }},
    { &hf_nrppa_TRP_MeasurementUpdateList_item,
      { "TRP-MeasurementUpdateItem", "nrppa.TRP_MeasurementUpdateItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_aoA_window_information,
      { "aoA-window-information", "nrppa.aoA_window_information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AoA_AssistanceInfo", HFILL }},
    { &hf_nrppa_TRPInformationListTRPResp_item,
      { "TRPInformationListTRPResp item", "nrppa.TRPInformationListTRPResp_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_tRPInformation,
      { "tRPInformation", "nrppa.tRPInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_tRPInformationTypeResponseList,
      { "tRPInformationTypeResponseList", "nrppa.tRPInformationTypeResponseList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPInformationTypeResponseList_item,
      { "TRPInformationTypeResponseItem", "nrppa.TRPInformationTypeResponseItem",
        FT_UINT32, BASE_DEC, VALS(nrppa_TRPInformationTypeResponseItem_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_aRFCN,
      { "aRFCN", "nrppa.aRFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3279165", HFILL }},
    { &hf_nrppa_sSBinformation,
      { "sSBinformation", "nrppa.sSBinformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SSBInfo", HFILL }},
    { &hf_nrppa_sFNInitialisationTime,
      { "sFNInitialisationTime", "nrppa.sFNInitialisationTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RelativeTime1900", HFILL }},
    { &hf_nrppa_spatialDirectionInformation,
      { "spatialDirectionInformation", "nrppa.spatialDirectionInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_geographicalCoordinates,
      { "geographicalCoordinates", "nrppa.geographicalCoordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPInformationTypeListTRPReq_item,
      { "ProtocolIE-Single-Container", "nrppa.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_TRPList_item,
      { "TRPItem", "nrppa.TRPItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_direct,
      { "direct", "nrppa.direct_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TRPPositionDirect", HFILL }},
    { &hf_nrppa_referenced,
      { "referenced", "nrppa.referenced_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TRPPositionReferenced", HFILL }},
    { &hf_nrppa_accuracy,
      { "accuracy", "nrppa.accuracy",
        FT_UINT32, BASE_DEC, VALS(nrppa_TRPPositionDirectAccuracy_vals), 0,
        "TRPPositionDirectAccuracy", HFILL }},
    { &hf_nrppa_tRPPosition,
      { "tRPPosition", "nrppa.tRPPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NG_RANAccessPointPosition", HFILL }},
    { &hf_nrppa_tRPHAposition,
      { "tRPHAposition", "nrppa.tRPHAposition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NGRANHighAccuracyAccessPointPosition", HFILL }},
    { &hf_nrppa_referencePoint,
      { "referencePoint", "nrppa.referencePoint",
        FT_UINT32, BASE_DEC, VALS(nrppa_ReferencePoint_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_referencePointType,
      { "referencePointType", "nrppa.referencePointType",
        FT_UINT32, BASE_DEC, VALS(nrppa_TRPReferencePointType_vals), 0,
        "TRPReferencePointType", HFILL }},
    { &hf_nrppa_TRP_PRS_Information_List_item,
      { "TRP-PRS-Information-List-Item", "nrppa.TRP_PRS_Information_List_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_tRPPositionRelativeGeodetic,
      { "tRPPositionRelativeGeodetic", "nrppa.tRPPositionRelativeGeodetic_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelativeGeodeticLocation", HFILL }},
    { &hf_nrppa_tRPPositionRelativeCartesian,
      { "tRPPositionRelativeCartesian", "nrppa.tRPPositionRelativeCartesian_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelativeCartesianLocation", HFILL }},
    { &hf_nrppa_tRP_Rx_TEGID,
      { "tRP-Rx-TEGID", "nrppa.tRP_Rx_TEGID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_nrppa_tRP_Rx_TimingErrorMargin,
      { "tRP-Rx-TimingErrorMargin", "nrppa.tRP_Rx_TimingErrorMargin",
        FT_UINT32, BASE_DEC, VALS(nrppa_TimingErrorMargin_vals), 0,
        "TimingErrorMargin", HFILL }},
    { &hf_nrppa_tRP_RxTx_TEGID,
      { "tRP-RxTx-TEGID", "nrppa.tRP_RxTx_TEGID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_nrppa_tRP_RxTx_TimingErrorMargin,
      { "tRP-RxTx-TimingErrorMargin", "nrppa.tRP_RxTx_TimingErrorMargin",
        FT_UINT32, BASE_DEC, VALS(nrppa_RxTxTimingErrorMargin_vals), 0,
        "RxTxTimingErrorMargin", HFILL }},
    { &hf_nrppa_tRP_Tx_TEGID,
      { "tRP-Tx-TEGID", "nrppa.tRP_Tx_TEGID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_nrppa_tRP_Tx_TimingErrorMargin,
      { "tRP-Tx-TimingErrorMargin", "nrppa.tRP_Tx_TimingErrorMargin",
        FT_UINT32, BASE_DEC, VALS(nrppa_TimingErrorMargin_vals), 0,
        "TimingErrorMargin", HFILL }},
    { &hf_nrppa_TRPTxTEGAssociation_item,
      { "TRPTEGItem", "nrppa.TRPTEGItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_dl_PRSResourceID_List,
      { "dl-PRSResourceID-List", "nrppa.dl_PRSResourceID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceID_Item", HFILL }},
    { &hf_nrppa_dl_PRSResourceID_List_item,
      { "DLPRSResourceID-Item", "nrppa.DLPRSResourceID_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_overlapValue,
      { "overlapValue", "nrppa.overlapValue",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_overlapValue_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_numberOfHops,
      { "numberOfHops", "nrppa.numberOfHops",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_6", HFILL }},
    { &hf_nrppa_slotOffsetForRemainingHopsList,
      { "slotOffsetForRemainingHopsList", "nrppa.slotOffsetForRemainingHopsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_reportingAmount,
      { "reportingAmount", "nrppa.reportingAmount",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_reportingAmount_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_reportingInterval,
      { "reportingInterval", "nrppa.reportingInterval",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_reportingInterval_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_UETxTEGAssociationList_item,
      { "UETxTEGAssociationItem", "nrppa.UETxTEGAssociationItem_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_uE_Tx_TEG_ID,
      { "uE-Tx-TEG-ID", "nrppa.uE_Tx_TEG_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_nrppa_posSRSResourceID_List,
      { "posSRSResourceID-List", "nrppa.posSRSResourceID_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_carrierFreq,
      { "carrierFreq", "nrppa.carrierFreq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_azimuthAoA,
      { "azimuthAoA", "nrppa.azimuthAoA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3599", HFILL }},
    { &hf_nrppa_zenithAoA,
      { "zenithAoA", "nrppa.zenithAoA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1799", HFILL }},
    { &hf_nrppa_uLRTOAmeas,
      { "uLRTOAmeas", "nrppa.uLRTOAmeas",
        FT_UINT32, BASE_DEC, VALS(nrppa_ULRTOAMeas_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_uLRSCP,
      { "uLRSCP", "nrppa.uLRSCP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3599", HFILL }},
    { &hf_nrppa_firstPathRSRPP,
      { "firstPathRSRPP", "nrppa.firstPathRSRPP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_126", HFILL }},
    { &hf_nrppa_UplinkChannelBW_PerSCS_List_item,
      { "SCS-SpecificCarrier", "nrppa.SCS_SpecificCarrier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_resourceMapping,
      { "resourceMapping", "nrppa.resourceMapping_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sequenceIDPos,
      { "sequenceIDPos", "nrppa.sequenceIDPos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_nrppa_WLANMeasurementQuantities_item,
      { "ProtocolIE-Single-Container", "nrppa.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_wLANMeasurementQuantitiesValue,
      { "wLANMeasurementQuantitiesValue", "nrppa.wLANMeasurementQuantitiesValue",
        FT_UINT32, BASE_DEC, VALS(nrppa_WLANMeasurementQuantitiesValue_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_WLANMeasurementResult_item,
      { "WLANMeasurementResult-Item", "nrppa.WLANMeasurementResult_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_wLAN_RSSI,
      { "wLAN-RSSI", "nrppa.wLAN_RSSI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sSID,
      { "sSID", "nrppa.sSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_bSSID,
      { "bSSID", "nrppa.bSSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_hESSID,
      { "hESSID", "nrppa.hESSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_operatingClass,
      { "operatingClass", "nrppa.operatingClass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "WLANOperatingClass", HFILL }},
    { &hf_nrppa_countryCode,
      { "countryCode", "nrppa.countryCode",
        FT_UINT32, BASE_DEC, VALS(nrppa_WLANCountryCode_vals), 0,
        "WLANCountryCode", HFILL }},
    { &hf_nrppa_wLANChannelList,
      { "wLANChannelList", "nrppa.wLANChannelList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_wLANBand,
      { "wLANBand", "nrppa.wLANBand",
        FT_UINT32, BASE_DEC, VALS(nrppa_WLANBand_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_WLANChannelList_item,
      { "WLANChannel", "nrppa.WLANChannel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_protocolIEs,
      { "protocolIEs", "nrppa.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_nrppa_OTDOA_Information_Type_item,
      { "ProtocolIE-Single-Container", "nrppa.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_oTDOA_Information_Item,
      { "oTDOA-Information-Item", "nrppa.oTDOA_Information_Item",
        FT_UINT32, BASE_DEC, VALS(nrppa_OTDOA_Information_Item_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_privateIEs,
      { "privateIEs", "nrppa.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_nrppa_semipersistentSRS,
      { "semipersistentSRS", "nrppa.semipersistentSRS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_aperiodicSRS,
      { "aperiodicSRS", "nrppa.aperiodicSRS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSResourceSetID,
      { "sRSResourceSetID", "nrppa.sRSResourceSetID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_aperiodic_05,
      { "aperiodic", "nrppa.aperiodic",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_aperiodic_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_sRSResourceTrigger_01,
      { "sRSResourceTrigger", "nrppa.sRSResourceTrigger_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_nrppa,
    &ett_nrppa_PrivateIE_ID,
    &ett_nrppa_ProtocolIE_Container,
    &ett_nrppa_ProtocolIE_Field,
    &ett_nrppa_ProtocolExtensionContainer,
    &ett_nrppa_ProtocolExtensionField,
    &ett_nrppa_PrivateIE_Container,
    &ett_nrppa_PrivateIE_Field,
    &ett_nrppa_NRPPA_PDU,
    &ett_nrppa_InitiatingMessage,
    &ett_nrppa_SuccessfulOutcome,
    &ett_nrppa_UnsuccessfulOutcome,
    &ett_nrppa_AbortTransmission,
    &ett_nrppa_ActiveULBWP,
    &ett_nrppa_AdditionalPathList,
    &ett_nrppa_AdditionalPathListItem,
    &ett_nrppa_AggregatedPosSRSResourceID_List,
    &ett_nrppa_AggregatedPosSRSResourceID_Item,
    &ett_nrppa_AggregatedPRSResourceSetList,
    &ett_nrppa_AggregatedPRSResourceSet_Item,
    &ett_nrppa_DL_PRS_ResourceSet_List,
    &ett_nrppa_DL_PRS_ResourceSet_Item,
    &ett_nrppa_ExtendedAdditionalPathList,
    &ett_nrppa_ExtendedAdditionalPathList_Item,
    &ett_nrppa_AoA_AssistanceInfo,
    &ett_nrppa_AperiodicSRSResourceTriggerList,
    &ett_nrppa_AngleMeasurementType,
    &ett_nrppa_Expected_UL_AoA,
    &ett_nrppa_Expected_ZoA_only,
    &ett_nrppa_Expected_Azimuth_AoA,
    &ett_nrppa_Expected_Zenith_AoA,
    &ett_nrppa_ARPLocationInformation,
    &ett_nrppa_ARPLocationInformation_Item,
    &ett_nrppa_ARPLocationType,
    &ett_nrppa_Assistance_Information,
    &ett_nrppa_AssistanceInformationFailureList,
    &ett_nrppa_AssistanceInformationFailureList_item,
    &ett_nrppa_AssistanceInformationMetaData,
    &ett_nrppa_BandwidthSRS,
    &ett_nrppa_PositioningBroadcastCells,
    &ett_nrppa_CarrierFreq,
    &ett_nrppa_Cause,
    &ett_nrppa_CGI_EUTRA,
    &ett_nrppa_CGI_NR,
    &ett_nrppa_CriticalityDiagnostics,
    &ett_nrppa_CriticalityDiagnostics_IE_List,
    &ett_nrppa_CriticalityDiagnostics_IE_List_item,
    &ett_nrppa_CommonTAParameters,
    &ett_nrppa_DL_PRS,
    &ett_nrppa_DL_PRSMutingPattern,
    &ett_nrppa_DLPRSResourceCoordinates,
    &ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_DLPRSResourceSetARP,
    &ett_nrppa_DLPRSResourceSetARP,
    &ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceARP,
    &ett_nrppa_DL_PRSResourceSetARPLocation,
    &ett_nrppa_DLPRSResourceARP,
    &ett_nrppa_DL_PRSResourceARPLocation,
    &ett_nrppa_E_CID_MeasurementResult,
    &ett_nrppa_GeographicalCoordinates,
    &ett_nrppa_GNB_RxTxTimeDiff,
    &ett_nrppa_GNBRxTxTimeDiffMeas,
    &ett_nrppa_LCS_to_GCS_Translation,
    &ett_nrppa_LCS_to_GCS_TranslationItem,
    &ett_nrppa_LocationUncertainty,
    &ett_nrppa_LoS_NLoSInformation,
    &ett_nrppa_MeasurementBeamInfo,
    &ett_nrppa_MeasurementQuantities,
    &ett_nrppa_MeasurementQuantities_Item,
    &ett_nrppa_MeasuredResults,
    &ett_nrppa_MeasuredResultsAssociatedInfoList,
    &ett_nrppa_MeasuredResultsAssociatedInfoItem,
    &ett_nrppa_MeasuredResultsValue,
    &ett_nrppa_Mobile_TRP_LocationInformation,
    &ett_nrppa_MultipleULAoA,
    &ett_nrppa_MultipleULAoA_List,
    &ett_nrppa_MultipleULAoA_Item,
    &ett_nrppa_NG_RANAccessPointPosition,
    &ett_nrppa_NGRANHighAccuracyAccessPointPosition,
    &ett_nrppa_NG_RAN_CGI,
    &ett_nrppa_NG_RANCell,
    &ett_nrppa_NR_PRS_Beam_Information,
    &ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourceSets_OF_NR_PRS_Beam_InformationItem,
    &ett_nrppa_SEQUENCE_SIZE_1_maxnolcs_gcs_translation_OF_LCS_to_GCS_TranslationItem,
    &ett_nrppa_NR_PRS_Beam_InformationItem,
    &ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_PRSAngleItem,
    &ett_nrppa_OnDemandPRS_Info,
    &ett_nrppa_OTDOACells,
    &ett_nrppa_OTDOACells_item,
    &ett_nrppa_OTDOACell_Information,
    &ett_nrppa_OTDOACell_Information_Item,
    &ett_nrppa_OtherRATMeasurementQuantities,
    &ett_nrppa_OtherRATMeasurementQuantities_Item,
    &ett_nrppa_OtherRATMeasurementResult,
    &ett_nrppa_OtherRATMeasuredResultsValue,
    &ett_nrppa_PathlossReferenceInformation,
    &ett_nrppa_PathlossReferenceSignal,
    &ett_nrppa_PeriodicityList,
    &ett_nrppa_PosSIBs,
    &ett_nrppa_PosSIBs_item,
    &ett_nrppa_PosSIB_Segments,
    &ett_nrppa_PosSIB_Segments_item,
    &ett_nrppa_PosSRSResource_List,
    &ett_nrppa_PosSRSResource_Item,
    &ett_nrppa_PosSRSResourceID_List,
    &ett_nrppa_PosSRSResourceSet_List,
    &ett_nrppa_PosSRSResourceIDPerSet_List,
    &ett_nrppa_PosSRSResourceSet_Item,
    &ett_nrppa_PosSRSResourceSet_Aggregation_List,
    &ett_nrppa_PosSRSResourceSet_Aggregation_Item,
    &ett_nrppa_PosResourceSetType,
    &ett_nrppa_PosResourceSetTypePeriodic,
    &ett_nrppa_PosResourceSetTypeSemi_persistent,
    &ett_nrppa_PosResourceSetTypeAperiodic,
    &ett_nrppa_PRSAngleItem,
    &ett_nrppa_PRSInformationPos,
    &ett_nrppa_PRSConfiguration,
    &ett_nrppa_PRSMutingConfiguration_EUTRA,
    &ett_nrppa_PRSFrequencyHoppingConfiguration_EUTRA,
    &ett_nrppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex,
    &ett_nrppa_PRS_Measurements_Info_List,
    &ett_nrppa_PRS_Measurements_Info_List_Item,
    &ett_nrppa_PRSMuting,
    &ett_nrppa_PRSMutingOption1,
    &ett_nrppa_PRSMutingOption2,
    &ett_nrppa_PRSResource_List,
    &ett_nrppa_PRSResource_Item,
    &ett_nrppa_PRSResource_QCLInfo,
    &ett_nrppa_PRSResource_QCLSourceSSB,
    &ett_nrppa_PRSResource_QCLSourcePRS,
    &ett_nrppa_PRSResourceSet_List,
    &ett_nrppa_PRSResourceSet_Item,
    &ett_nrppa_PRSTransmissionOffIndication,
    &ett_nrppa_PRSTransmissionOffPerResource,
    &ett_nrppa_PRSTransmissionOffPerResource_Item,
    &ett_nrppa_SEQUENCE_SIZE_1_maxnoofPRSresource_OF_PRSTransmissionOffIndicationPerResource_Item,
    &ett_nrppa_PRSTransmissionOffIndicationPerResource_Item,
    &ett_nrppa_PRSTransmissionOffInformation,
    &ett_nrppa_PRSTransmissionOffPerResourceSet,
    &ett_nrppa_PRSTransmissionOffPerResourceSet_Item,
    &ett_nrppa_PRSTRPList,
    &ett_nrppa_PRSTRPItem,
    &ett_nrppa_PRSTransmissionTRPList,
    &ett_nrppa_PRSTransmissionTRPItem,
    &ett_nrppa_PosValidityAreaCellList,
    &ett_nrppa_PosValidityAreaCell_Item,
    &ett_nrppa_ReferenceSignal,
    &ett_nrppa_ReferencePoint,
    &ett_nrppa_RelativeGeodeticLocation,
    &ett_nrppa_RelativeCartesianLocation,
    &ett_nrppa_RelativePathDelay,
    &ett_nrppa_RequestedDLPRSTransmissionCharacteristics,
    &ett_nrppa_RequestedDLPRSResourceSet_List,
    &ett_nrppa_RequestedDLPRSResourceSet_Item,
    &ett_nrppa_RequestedDLPRSResource_List,
    &ett_nrppa_RequestedDLPRSResource_Item,
    &ett_nrppa_RequestedSRSTransmissionCharacteristics,
    &ett_nrppa_SEQUENCE_SIZE_1_maxnoSRS_ResourceSets_OF_SRSResourceSet_Item,
    &ett_nrppa_ResourceMapping,
    &ett_nrppa_RequestedSRSPreconfigurationCharacteristics_List,
    &ett_nrppa_RequestedSRSPreconfigurationCharacteristics_Item,
    &ett_nrppa_SRSResourceSet_Item,
    &ett_nrppa_ResourceSetType,
    &ett_nrppa_ResourceSetTypePeriodic,
    &ett_nrppa_ResourceSetTypeSemi_persistent,
    &ett_nrppa_ResourceSetTypeAperiodic,
    &ett_nrppa_ResourceType,
    &ett_nrppa_ResourceTypePeriodic,
    &ett_nrppa_ResourceTypeSemi_persistent,
    &ett_nrppa_ResourceTypeAperiodic,
    &ett_nrppa_ResourceTypePos,
    &ett_nrppa_ResourceTypePeriodicPos,
    &ett_nrppa_ResourceTypeSemi_persistentPos,
    &ett_nrppa_ResourceTypeAperiodicPos,
    &ett_nrppa_ResponseTime,
    &ett_nrppa_ResultCSI_RSRP,
    &ett_nrppa_ResultCSI_RSRP_Item,
    &ett_nrppa_ResultCSI_RSRP_PerCSI_RS,
    &ett_nrppa_ResultCSI_RSRP_PerCSI_RS_Item,
    &ett_nrppa_ResultCSI_RSRQ,
    &ett_nrppa_ResultCSI_RSRQ_Item,
    &ett_nrppa_ResultCSI_RSRQ_PerCSI_RS,
    &ett_nrppa_ResultCSI_RSRQ_PerCSI_RS_Item,
    &ett_nrppa_ResultEUTRA,
    &ett_nrppa_ResultEUTRA_Item,
    &ett_nrppa_ResultRSRP_EUTRA,
    &ett_nrppa_ResultRSRP_EUTRA_Item,
    &ett_nrppa_ResultRSRQ_EUTRA,
    &ett_nrppa_ResultRSRQ_EUTRA_Item,
    &ett_nrppa_ResultSS_RSRP,
    &ett_nrppa_ResultSS_RSRP_Item,
    &ett_nrppa_ResultSS_RSRP_PerSSB,
    &ett_nrppa_ResultSS_RSRP_PerSSB_Item,
    &ett_nrppa_ResultSS_RSRQ,
    &ett_nrppa_ResultSS_RSRQ_Item,
    &ett_nrppa_ResultSS_RSRQ_PerSSB,
    &ett_nrppa_ResultSS_RSRQ_PerSSB_Item,
    &ett_nrppa_ResultGERAN,
    &ett_nrppa_ResultGERAN_Item,
    &ett_nrppa_ResultNR,
    &ett_nrppa_ResultNR_Item,
    &ett_nrppa_ResultUTRAN,
    &ett_nrppa_ResultUTRAN_Item,
    &ett_nrppa_T_physCellIDUTRAN,
    &ett_nrppa_SCS_SpecificCarrier,
    &ett_nrppa_Search_window_information,
    &ett_nrppa_SlotOffsetForRemainingHopsList,
    &ett_nrppa_SlotOffsetForRemainingHopsItem,
    &ett_nrppa_SlotOffsetRemainingHops,
    &ett_nrppa_SlotOffsetRemainingHopsAperiodic,
    &ett_nrppa_SlotOffsetRemainingHopsSemiPersistent,
    &ett_nrppa_SlotOffsetRemainingHopsPeriodic,
    &ett_nrppa_SpatialDirectionInformation,
    &ett_nrppa_SpatialRelationInfo,
    &ett_nrppa_SpatialRelationforResourceID,
    &ett_nrppa_SpatialRelationforResourceIDItem,
    &ett_nrppa_SpatialRelationPerSRSResource,
    &ett_nrppa_SpatialRelationPerSRSResource_List,
    &ett_nrppa_SpatialRelationPerSRSResourceItem,
    &ett_nrppa_SpatialRelationPos,
    &ett_nrppa_SRSConfig,
    &ett_nrppa_SRSCarrier_List,
    &ett_nrppa_SRSCarrier_List_Item,
    &ett_nrppa_SRSConfiguration,
    &ett_nrppa_SRSResource,
    &ett_nrppa_SRSResource_List,
    &ett_nrppa_SRSResourceSet_List,
    &ett_nrppa_SRSResourceID_List,
    &ett_nrppa_SRSResourceSet,
    &ett_nrppa_SRSResourceTrigger,
    &ett_nrppa_SRSResourcetype,
    &ett_nrppa_SRSResourceTypeChoice,
    &ett_nrppa_SRSInfo,
    &ett_nrppa_PosSRSInfo,
    &ett_nrppa_SSBInfo,
    &ett_nrppa_SEQUENCE_SIZE_1_maxNoSSBs_OF_SSBInfoItem,
    &ett_nrppa_SSBInfoItem,
    &ett_nrppa_SSB,
    &ett_nrppa_SSBBurstPosition,
    &ett_nrppa_StartRBIndex,
    &ett_nrppa_StartTimeAndDuration,
    &ett_nrppa_SystemInformation,
    &ett_nrppa_SystemInformation_item,
    &ett_nrppa_SRSPreconfiguration_List,
    &ett_nrppa_SRSPreconfiguration_Item,
    &ett_nrppa_TDD_Config_EUTRA_Item,
    &ett_nrppa_TRPTEGInformation,
    &ett_nrppa_RxTxTEG,
    &ett_nrppa_RxTEG,
    &ett_nrppa_TF_Configuration,
    &ett_nrppa_TimeStamp,
    &ett_nrppa_TimeStampSlotIndex,
    &ett_nrppa_TimeWindowDurationMeasurement,
    &ett_nrppa_TimeWindowDurationSRS,
    &ett_nrppa_TimeWindowStartSRS,
    &ett_nrppa_TimeWindowInformation_Measurement_List,
    &ett_nrppa_TimeWindowInformation_Measurement_Item,
    &ett_nrppa_TimeWindowInformation_SRS_List,
    &ett_nrppa_TimeWindowInformation_SRS_Item,
    &ett_nrppa_TransmissionComb,
    &ett_nrppa_T_n2,
    &ett_nrppa_T_n4,
    &ett_nrppa_TransmissionCombn8,
    &ett_nrppa_TransmissionCombPos,
    &ett_nrppa_T_n2_01,
    &ett_nrppa_T_n4_01,
    &ett_nrppa_T_n8,
    &ett_nrppa_TRPBeamAntennaInformation,
    &ett_nrppa_Choice_TRP_Beam_Antenna_Info_Item,
    &ett_nrppa_TRP_BeamAntennaExplicitInformation,
    &ett_nrppa_TRP_BeamAntennaAngles,
    &ett_nrppa_TRP_BeamAntennaAnglesList_Item,
    &ett_nrppa_SEQUENCE_SIZE_1_maxnoElevationAngles_OF_TRP_ElevationAngleList_Item,
    &ett_nrppa_TRP_ElevationAngleList_Item,
    &ett_nrppa_SEQUENCE_SIZE_2_maxNumResourcesPerAngle_OF_TRP_Beam_Power_Item,
    &ett_nrppa_TRP_Beam_Power_Item,
    &ett_nrppa_TRPMeasurementQuantities,
    &ett_nrppa_TRPMeasurementQuantitiesList_Item,
    &ett_nrppa_TrpMeasurementResult,
    &ett_nrppa_TrpMeasurementResultItem,
    &ett_nrppa_TrpMeasuredResultsValue,
    &ett_nrppa_TrpMeasurementQuality,
    &ett_nrppa_TrpMeasurementTimingQuality,
    &ett_nrppa_TrpMeasurementAngleQuality,
    &ett_nrppa_TRPPhaseQuality,
    &ett_nrppa_TRP_MeasurementRequestList,
    &ett_nrppa_TRP_MeasurementRequestItem,
    &ett_nrppa_TRP_MeasurementResponseList,
    &ett_nrppa_TRP_MeasurementResponseItem,
    &ett_nrppa_TRP_MeasurementUpdateList,
    &ett_nrppa_TRP_MeasurementUpdateItem,
    &ett_nrppa_TRPInformationListTRPResp,
    &ett_nrppa_TRPInformationListTRPResp_item,
    &ett_nrppa_TRPInformation,
    &ett_nrppa_TRPInformationTypeResponseList,
    &ett_nrppa_TRPInformationTypeResponseItem,
    &ett_nrppa_TRPInformationTypeListTRPReq,
    &ett_nrppa_TRPList,
    &ett_nrppa_TRPItem,
    &ett_nrppa_TRPPositionDefinitionType,
    &ett_nrppa_TRPPositionDirect,
    &ett_nrppa_TRPPositionDirectAccuracy,
    &ett_nrppa_TRPPositionReferenced,
    &ett_nrppa_TRP_PRS_Information_List,
    &ett_nrppa_TRP_PRS_Information_List_Item,
    &ett_nrppa_TRPReferencePointType,
    &ett_nrppa_TRP_Rx_TEGInformation,
    &ett_nrppa_TRP_RxTx_TEGInformation,
    &ett_nrppa_TRP_Tx_TEGInformation,
    &ett_nrppa_TRPTxTEGAssociation,
    &ett_nrppa_TRPTEGItem,
    &ett_nrppa_SEQUENCE_SIZE_1_maxPRS_ResourcesPerSet_OF_DLPRSResourceID_Item,
    &ett_nrppa_DLPRSResourceID_Item,
    &ett_nrppa_TxHoppingConfiguration,
    &ett_nrppa_UEReportingInformation,
    &ett_nrppa_UETxTEGAssociationList,
    &ett_nrppa_UETxTEGAssociationItem,
    &ett_nrppa_UL_AoA,
    &ett_nrppa_UL_RTOAMeasurement,
    &ett_nrppa_UL_RSCPMeas,
    &ett_nrppa_ULRTOAMeas,
    &ett_nrppa_UL_SRS_RSRPP,
    &ett_nrppa_UplinkChannelBW_PerSCS_List,
    &ett_nrppa_ValidityAreaSpecificSRSInformation,
    &ett_nrppa_WLANMeasurementQuantities,
    &ett_nrppa_WLANMeasurementQuantities_Item,
    &ett_nrppa_WLANMeasurementResult,
    &ett_nrppa_WLANMeasurementResult_Item,
    &ett_nrppa_WLANChannelList,
    &ett_nrppa_ZoA,
    &ett_nrppa_E_CIDMeasurementInitiationRequest,
    &ett_nrppa_E_CIDMeasurementInitiationResponse,
    &ett_nrppa_E_CIDMeasurementInitiationFailure,
    &ett_nrppa_E_CIDMeasurementFailureIndication,
    &ett_nrppa_E_CIDMeasurementReport,
    &ett_nrppa_E_CIDMeasurementTerminationCommand,
    &ett_nrppa_OTDOAInformationRequest,
    &ett_nrppa_OTDOA_Information_Type,
    &ett_nrppa_OTDOA_Information_Type_Item,
    &ett_nrppa_OTDOAInformationResponse,
    &ett_nrppa_OTDOAInformationFailure,
    &ett_nrppa_AssistanceInformationControl,
    &ett_nrppa_AssistanceInformationFeedback,
    &ett_nrppa_ErrorIndication,
    &ett_nrppa_PrivateMessage,
    &ett_nrppa_PositioningInformationRequest,
    &ett_nrppa_PositioningInformationResponse,
    &ett_nrppa_PositioningInformationFailure,
    &ett_nrppa_PositioningInformationUpdate,
    &ett_nrppa_MeasurementRequest,
    &ett_nrppa_MeasurementResponse,
    &ett_nrppa_MeasurementFailure,
    &ett_nrppa_MeasurementReport,
    &ett_nrppa_MeasurementUpdate,
    &ett_nrppa_MeasurementAbort,
    &ett_nrppa_MeasurementFailureIndication,
    &ett_nrppa_TRPInformationRequest,
    &ett_nrppa_TRPInformationResponse,
    &ett_nrppa_TRPInformationFailure,
    &ett_nrppa_PositioningActivationRequest,
    &ett_nrppa_SRSType,
    &ett_nrppa_SemipersistentSRS,
    &ett_nrppa_AperiodicSRS,
    &ett_nrppa_PositioningActivationResponse,
    &ett_nrppa_PositioningActivationFailure,
    &ett_nrppa_PositioningDeactivation,
    &ett_nrppa_PRSConfigurationRequest,
    &ett_nrppa_PRSConfigurationResponse,
    &ett_nrppa_PRSConfigurationFailure,
    &ett_nrppa_MeasurementPreconfigurationRequired,
    &ett_nrppa_MeasurementPreconfigurationConfirm,
    &ett_nrppa_MeasurementPreconfigurationRefuse,
    &ett_nrppa_MeasurementActivation,
    &ett_nrppa_SRSInformationReservationNotification,
  };

  /* Register protocol */
  proto_nrppa = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("nrppa", dissect_NRPPA_PDU_PDU, proto_nrppa);

  /* Register fields and subtrees */
  proto_register_field_array(proto_nrppa, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

   /* Register dissector tables */
  nrppa_ies_dissector_table = register_dissector_table("nrppa.ies", "NRPPA-PROTOCOL-IES", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_extension_dissector_table = register_dissector_table("nrppa.extension", "NRPPA-PROTOCOL-EXTENSION", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_proc_imsg_dissector_table = register_dissector_table("nrppa.proc.imsg", "NRPPA-ELEMENTARY-PROCEDURE InitiatingMessage", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_proc_sout_dissector_table = register_dissector_table("nrppa.proc.sout", "NRPPA-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_proc_uout_dissector_table = register_dissector_table("nrppa.proc.uout", "NRPPA-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_nrppa, FT_UINT32, BASE_DEC);
}

/*--- proto_reg_handoff_nrppa ---------------------------------------*/
void
proto_reg_handoff_nrppa(void)
{
  dissector_add_uint("nrppa.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_LMF_UE_Measurement_ID, create_dissector_handle(dissect_UE_Measurement_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportCharacteristics, create_dissector_handle(dissect_ReportCharacteristics_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementPeriodicity, create_dissector_handle(dissect_MeasurementPeriodicity_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementQuantities, create_dissector_handle(dissect_MeasurementQuantities_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_RAN_UE_Measurement_ID, create_dissector_handle(dissect_UE_Measurement_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_E_CID_MeasurementResult, create_dissector_handle(dissect_E_CID_MeasurementResult_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OTDOACells, create_dissector_handle(dissect_OTDOACells_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OTDOA_Information_Type_Group, create_dissector_handle(dissect_OTDOA_Information_Type_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OTDOA_Information_Type_Item, create_dissector_handle(dissect_OTDOA_Information_Type_Item_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementQuantities_Item, create_dissector_handle(dissect_MeasurementQuantities_Item_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_RequestedSRSTransmissionCharacteristics, create_dissector_handle(dissect_RequestedSRSTransmissionCharacteristics_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_Cell_Portion_ID, create_dissector_handle(dissect_Cell_Portion_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OtherRATMeasurementQuantities, create_dissector_handle(dissect_OtherRATMeasurementQuantities_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OtherRATMeasurementQuantities_Item, create_dissector_handle(dissect_OtherRATMeasurementQuantities_Item_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OtherRATMeasurementResult, create_dissector_handle(dissect_OtherRATMeasurementResult_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_WLANMeasurementQuantities, create_dissector_handle(dissect_WLANMeasurementQuantities_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_WLANMeasurementQuantities_Item, create_dissector_handle(dissect_WLANMeasurementQuantities_Item_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_WLANMeasurementResult, create_dissector_handle(dissect_WLANMeasurementResult_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TDD_Config_EUTRA_Item, create_dissector_handle(dissect_TDD_Config_EUTRA_Item_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_Assistance_Information, create_dissector_handle(dissect_nrppa_Assistance_Information_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_Broadcast, create_dissector_handle(dissect_Broadcast_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_AssistanceInformationFailureList, create_dissector_handle(dissect_AssistanceInformationFailureList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SRSConfiguration, create_dissector_handle(dissect_nrppa_SRSConfiguration_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRPInformationTypeListTRPReq, create_dissector_handle(dissect_TRPInformationTypeListTRPReq_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRPInformationListTRPResp, create_dissector_handle(dissect_TRPInformationListTRPResp_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementBeamInfoRequest, create_dissector_handle(dissect_MeasurementBeamInfoRequest_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ResultSS_RSRP, create_dissector_handle(dissect_ResultSS_RSRP_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ResultSS_RSRQ, create_dissector_handle(dissect_ResultSS_RSRQ_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ResultCSI_RSRP, create_dissector_handle(dissect_ResultCSI_RSRP_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ResultCSI_RSRQ, create_dissector_handle(dissect_ResultCSI_RSRQ_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_AngleOfArrivalNR, create_dissector_handle(dissect_UL_AoA_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_PositioningBroadcastCells, create_dissector_handle(dissect_PositioningBroadcastCells_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_LMF_Measurement_ID, create_dissector_handle(dissect_Measurement_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_RAN_Measurement_ID, create_dissector_handle(dissect_Measurement_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRP_MeasurementRequestList, create_dissector_handle(dissect_TRP_MeasurementRequestList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRP_MeasurementResponseList, create_dissector_handle(dissect_TRP_MeasurementResponseList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SRSType, create_dissector_handle(dissect_SRSType_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ActivationTime, create_dissector_handle(dissect_RelativeTime1900_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRPList, create_dissector_handle(dissect_TRPList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SystemFrameNumber, create_dissector_handle(dissect_SystemFrameNumber_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SlotNumber, create_dissector_handle(dissect_SlotNumber_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRPMeasurementQuantities, create_dissector_handle(dissect_TRPMeasurementQuantities_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_AbortTransmission, create_dissector_handle(dissect_AbortTransmission_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SFNInitialisationTime, create_dissector_handle(dissect_RelativeTime1900_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ResultNR, create_dissector_handle(dissect_ResultNR_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ResultEUTRA, create_dissector_handle(dissect_ResultEUTRA_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRPInformationTypeItem, create_dissector_handle(dissect_TRPInformationTypeItem_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_CGI_NR, create_dissector_handle(dissect_CGI_NR_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SFNInitialisationTime_NR, create_dissector_handle(dissect_SFNInitialisationTime_EUTRA_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_Cell_ID, create_dissector_handle(dissect_CGI_NR_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SrsFrequency, create_dissector_handle(dissect_SrsFrequency_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRPType, create_dissector_handle(dissect_TRPType_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementPeriodicityExtended, create_dissector_handle(dissect_MeasurementPeriodicityExtended_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_PRSTRPList, create_dissector_handle(dissect_PRSTRPList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_PRSTransmissionTRPList, create_dissector_handle(dissect_PRSTransmissionTRPList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OnDemandPRS, create_dissector_handle(dissect_OnDemandPRS_Info_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRP_MeasurementUpdateList, create_dissector_handle(dissect_TRP_MeasurementUpdateList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ZoA, create_dissector_handle(dissect_ZoA_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ResponseTime, create_dissector_handle(dissect_ResponseTime_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_UEReportingInformation, create_dissector_handle(dissect_UEReportingInformation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MultipleULAoA, create_dissector_handle(dissect_MultipleULAoA_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_UL_SRS_RSRPP, create_dissector_handle(dissect_UL_SRS_RSRPP_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_UETxTEGAssociationList, create_dissector_handle(dissect_UETxTEGAssociationList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRPTxTEGAssociation, create_dissector_handle(dissect_TRPTxTEGAssociation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRP_PRS_Information_List, create_dissector_handle(dissect_TRP_PRS_Information_List_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_PRS_Measurements_Info_List, create_dissector_handle(dissect_PRS_Measurements_Info_List_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_PRSConfigRequestType, create_dissector_handle(dissect_PRSConfigRequestType_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_UE_TEG_Info_Request, create_dissector_handle(dissect_UE_TEG_Info_Request_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementTimeOccasion, create_dissector_handle(dissect_MeasurementTimeOccasion_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementCharacteristicsRequestIndicator, create_dissector_handle(dissect_MeasurementCharacteristicsRequestIndicator_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRPBeamAntennaInformation, create_dissector_handle(dissect_TRPBeamAntennaInformation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_NR_TADV, create_dissector_handle(dissect_NR_TADV_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementAmount, create_dissector_handle(dissect_MeasurementAmount_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_PreconfigurationResult, create_dissector_handle(dissect_PreconfigurationResult_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_RequestType, create_dissector_handle(dissect_RequestType_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_UE_TEG_ReportingPeriodicity, create_dissector_handle(dissect_UE_TEG_ReportingPeriodicity_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementPeriodicityNR_AoA, create_dissector_handle(dissect_MeasurementPeriodicityNR_AoA_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SRSTransmissionStatus, create_dissector_handle(dissect_SRSTransmissionStatus_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_NewNRCGI, create_dissector_handle(dissect_CGI_NR_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_Mobile_TRP_LocationInformation, create_dissector_handle(dissect_Mobile_TRP_LocationInformation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_CommonTAParameters, create_dissector_handle(dissect_CommonTAParameters_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_UE_Rx_Tx_Time_Diff, create_dissector_handle(dissect_UE_Rx_Tx_Time_Diff_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SCS_480, create_dissector_handle(dissect_SCS_480_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SCS_960, create_dissector_handle(dissect_SCS_960_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_PosSRSResourceSet_Aggregation_List, create_dissector_handle(dissect_PosSRSResourceSet_Aggregation_List_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TimeWindowInformation_SRS_List, create_dissector_handle(dissect_TimeWindowInformation_SRS_List_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TimeWindowInformation_Measurement_List, create_dissector_handle(dissect_TimeWindowInformation_Measurement_List_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_UL_RSCPMeas, create_dissector_handle(dissect_UL_RSCPMeas_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_PosValidityAreaCellList, create_dissector_handle(dissect_PosValidityAreaCellList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SRSReservationType, create_dissector_handle(dissect_SRSReservationType_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TRPPhaseQuality, create_dissector_handle(dissect_TRPPhaseQuality_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_NewCellIdentity, create_dissector_handle(dissect_CGI_NR_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_RequestedSRSPreconfigurationCharacteristics_List, create_dissector_handle(dissect_RequestedSRSPreconfigurationCharacteristics_List_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SRSPreconfiguration_List, create_dissector_handle(dissect_SRSPreconfiguration_List_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_SRSInformation, create_dissector_handle(dissect_RequestedSRSTransmissionCharacteristics_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus1, create_dissector_handle(dissect_ReportingGranularitykminus1_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus2, create_dissector_handle(dissect_ReportingGranularitykminus2_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus3, create_dissector_handle(dissect_ReportingGranularitykminus3_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus4, create_dissector_handle(dissect_ReportingGranularitykminus4_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus5, create_dissector_handle(dissect_ReportingGranularitykminus5_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus6, create_dissector_handle(dissect_ReportingGranularitykminus6_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus1AdditionalPath, create_dissector_handle(dissect_ReportingGranularitykminus1AdditionalPath_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus2AdditionalPath, create_dissector_handle(dissect_ReportingGranularitykminus2AdditionalPath_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus3AdditionalPath, create_dissector_handle(dissect_ReportingGranularitykminus3AdditionalPath_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus4AdditionalPath, create_dissector_handle(dissect_ReportingGranularitykminus4AdditionalPath_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus5AdditionalPath, create_dissector_handle(dissect_ReportingGranularitykminus5AdditionalPath_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportingGranularitykminus6AdditionalPath, create_dissector_handle(dissect_ReportingGranularitykminus6AdditionalPath_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_GeographicalCoordinates, create_dissector_handle(dissect_GeographicalCoordinates_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_SRSSpatialRelation, create_dissector_handle(dissect_SpatialRelationInfo_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_SRSSpatialRelationPerSRSResource, create_dissector_handle(dissect_SpatialRelationPerSRSResource_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_PRS_Resource_ID, create_dissector_handle(dissect_PRS_Resource_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_AoA_SearchWindow, create_dissector_handle(dissect_AoA_AssistanceInfo_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_MultipleULAoA, create_dissector_handle(dissect_MultipleULAoA_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_SRSResourcetype, create_dissector_handle(dissect_SRSResourcetype_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_ExtendedAdditionalPathList, create_dissector_handle(dissect_ExtendedAdditionalPathList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_ARPLocationInfo, create_dissector_handle(dissect_ARPLocationInformation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_ARP_ID, create_dissector_handle(dissect_ARP_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_LoS_NLoSInformation, create_dissector_handle(dissect_LoS_NLoSInformation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_NumberOfTRPRxTEG, create_dissector_handle(dissect_NumberOfTRPRxTEG_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_NumberOfTRPRxTxTEG, create_dissector_handle(dissect_NumberOfTRPRxTxTEG_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_TRPTEGInformation, create_dissector_handle(dissect_TRPTEGInformation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_TRP_Rx_TEGInformation, create_dissector_handle(dissect_TRP_Rx_TEGInformation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_pathPower, create_dissector_handle(dissect_UL_SRS_RSRPP_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_SRSPortIndex, create_dissector_handle(dissect_SRSPortIndex_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_UETxTimingErrorMargin, create_dissector_handle(dissect_TimingErrorMargin_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_nrofSymbolsExtended, create_dissector_handle(dissect_NrofSymbolsExtended_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_repetitionFactorExtended, create_dissector_handle(dissect_RepetitionFactorExtended_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_StartRBHopping, create_dissector_handle(dissect_StartRBHopping_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_StartRBIndex, create_dissector_handle(dissect_StartRBIndex_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_transmissionCombn8, create_dissector_handle(dissect_TransmissionCombn8_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_ExtendedResourceSymbolOffset, create_dissector_handle(dissect_ExtendedResourceSymbolOffset_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_Mobile_TRP_LocationInformation, create_dissector_handle(dissect_Mobile_TRP_LocationInformation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_Mobile_IAB_MT_UE_ID, create_dissector_handle(dissect_Mobile_IAB_MT_UE_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_MobileAccessPointLocation, create_dissector_handle(dissect_Mobile_TRP_LocationInformation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_Bandwidth_Aggregation_Request_Indication, create_dissector_handle(dissect_Bandwidth_Aggregation_Request_Indication_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_PosSRSResourceSet_Aggregation_List, create_dissector_handle(dissect_PosSRSResourceSet_Aggregation_List_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_TimingReportingGranularityFactorExtended, create_dissector_handle(dissect_TimingReportingGranularityFactorExtended_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_SymbolIndex, create_dissector_handle(dissect_SymbolIndex_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_PosValidityAreaCellList, create_dissector_handle(dissect_PosValidityAreaCellList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_PRSBWAggregationRequestIndication, create_dissector_handle(dissect_PRSBWAggregationRequestIndication_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_AggregatedPosSRSResourceID_List, create_dissector_handle(dissect_AggregatedPosSRSResourceID_List_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_AggregatedPRSResourceSetList, create_dissector_handle(dissect_AggregatedPRSResourceSetList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_ValidityAreaSpecificSRSInformation, create_dissector_handle(dissect_ValidityAreaSpecificSRSInformation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_TxHoppingConfiguration, create_dissector_handle(dissect_TxHoppingConfiguration_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_MeasuredFrequencyHops, create_dissector_handle(dissect_MeasuredFrequencyHops_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_MeasuredResultsAssociatedInfoList, create_dissector_handle(dissect_MeasuredResultsAssociatedInfoList_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_PointA, create_dissector_handle(dissect_PointA_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_NR_PCI, create_dissector_handle(dissect_NR_PCI_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_SCS_SpecificCarrier, create_dissector_handle(dissect_SCS_SpecificCarrier_PDU, proto_nrppa));
  dissector_add_uint("nrppa.extension", id_MeasBasedOnAggregatedResources, create_dissector_handle(dissect_MeasBasedOnAggregatedResources_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_errorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_e_CIDMeasurementInitiation, create_dissector_handle(dissect_E_CIDMeasurementInitiationRequest_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.sout", id_e_CIDMeasurementInitiation, create_dissector_handle(dissect_E_CIDMeasurementInitiationResponse_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.uout", id_e_CIDMeasurementInitiation, create_dissector_handle(dissect_E_CIDMeasurementInitiationFailure_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_e_CIDMeasurementFailureIndication, create_dissector_handle(dissect_E_CIDMeasurementFailureIndication_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_e_CIDMeasurementReport, create_dissector_handle(dissect_E_CIDMeasurementReport_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_e_CIDMeasurementTermination, create_dissector_handle(dissect_E_CIDMeasurementTerminationCommand_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_oTDOAInformationExchange, create_dissector_handle(dissect_OTDOAInformationRequest_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.sout", id_oTDOAInformationExchange, create_dissector_handle(dissect_OTDOAInformationResponse_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.uout", id_oTDOAInformationExchange, create_dissector_handle(dissect_OTDOAInformationFailure_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_assistanceInformationControl, create_dissector_handle(dissect_AssistanceInformationControl_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_assistanceInformationFeedback, create_dissector_handle(dissect_AssistanceInformationFeedback_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_positioningInformationExchange, create_dissector_handle(dissect_PositioningInformationRequest_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.sout", id_positioningInformationExchange, create_dissector_handle(dissect_PositioningInformationResponse_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.uout", id_positioningInformationExchange, create_dissector_handle(dissect_PositioningInformationFailure_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_positioningInformationUpdate, create_dissector_handle(dissect_PositioningInformationUpdate_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_Measurement, create_dissector_handle(dissect_MeasurementRequest_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.sout", id_Measurement, create_dissector_handle(dissect_MeasurementResponse_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.uout", id_Measurement, create_dissector_handle(dissect_MeasurementFailure_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_MeasurementReport, create_dissector_handle(dissect_MeasurementReport_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_MeasurementUpdate, create_dissector_handle(dissect_MeasurementUpdate_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_MeasurementAbort, create_dissector_handle(dissect_MeasurementAbort_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_MeasurementFailureIndication, create_dissector_handle(dissect_MeasurementFailureIndication_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_tRPInformationExchange, create_dissector_handle(dissect_TRPInformationRequest_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.sout", id_tRPInformationExchange, create_dissector_handle(dissect_TRPInformationResponse_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.uout", id_tRPInformationExchange, create_dissector_handle(dissect_TRPInformationFailure_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_positioningActivation, create_dissector_handle(dissect_PositioningActivationRequest_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.sout", id_positioningActivation, create_dissector_handle(dissect_PositioningActivationResponse_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.uout", id_positioningActivation, create_dissector_handle(dissect_PositioningActivationFailure_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_positioningDeactivation, create_dissector_handle(dissect_PositioningDeactivation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_pRSConfigurationExchange, create_dissector_handle(dissect_PRSConfigurationRequest_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.sout", id_pRSConfigurationExchange, create_dissector_handle(dissect_PRSConfigurationResponse_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.uout", id_pRSConfigurationExchange, create_dissector_handle(dissect_PRSConfigurationFailure_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_measurementPreconfiguration, create_dissector_handle(dissect_MeasurementPreconfigurationRequired_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.sout", id_measurementPreconfiguration, create_dissector_handle(dissect_MeasurementPreconfigurationConfirm_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.uout", id_measurementPreconfiguration, create_dissector_handle(dissect_MeasurementPreconfigurationRefuse_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_measurementActivation, create_dissector_handle(dissect_MeasurementActivation_PDU, proto_nrppa));
  dissector_add_uint("nrppa.proc.imsg", id_sRSInformationReservationNotification, create_dissector_handle(dissect_SRSInformationReservationNotification_PDU, proto_nrppa));

}
