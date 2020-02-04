/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lppa.c                                                              */
/* asn2wrs.py -p lppa -c ./lppa.cnf -s ./packet-lppa-template -D . -O ../.. LPPA-Common.asn LPPA-Constant.asn LPPA-Container.asn LPPA-ElementaryProcedure.asn LPPA-InformationElement.asn LPPA-PDU.asn */

/* Input file: packet-lppa-template.c */

#line 1 "./asn1/lppa/packet-lppa-template.c"
/* packet-lppa.c
 * Routines for 3GPP LTE Positioning Protocol A (LLPa) packet dissection
 * Copyright 2011-2019, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref 3GPP TS 36.455 version 15.2.1 Release 15
 * http://www.3gpp.org
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/proto_data.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-lppa.h"

#define PNAME  "LTE Positioning Protocol A (LPPa)"
#define PSNAME "LPPa"
#define PFNAME "lppa"

void proto_register_lppa(void);
void proto_reg_handoff_lppa(void);

/* Initialize the protocol and registered fields */
static int proto_lppa = -1;


/*--- Included file: packet-lppa-hf.c ---*/
#line 1 "./asn1/lppa/packet-lppa-hf.c"
static int hf_lppa_LPPA_PDU_PDU = -1;             /* LPPA_PDU */
static int hf_lppa_Add_OTDOACells_PDU = -1;       /* Add_OTDOACells */
static int hf_lppa_Assistance_Information_PDU = -1;  /* Assistance_Information */
static int hf_lppa_AssistanceInformationFailureList_PDU = -1;  /* AssistanceInformationFailureList */
static int hf_lppa_Broadcast_PDU = -1;            /* Broadcast */
static int hf_lppa_Cause_PDU = -1;                /* Cause */
static int hf_lppa_Cell_Portion_ID_PDU = -1;      /* Cell_Portion_ID */
static int hf_lppa_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_lppa_E_CID_MeasurementResult_PDU = -1;  /* E_CID_MeasurementResult */
static int hf_lppa_InterRATMeasurementQuantities_PDU = -1;  /* InterRATMeasurementQuantities */
static int hf_lppa_InterRATMeasurementQuantities_Item_PDU = -1;  /* InterRATMeasurementQuantities_Item */
static int hf_lppa_InterRATMeasurementResult_PDU = -1;  /* InterRATMeasurementResult */
static int hf_lppa_Measurement_ID_PDU = -1;       /* Measurement_ID */
static int hf_lppa_MeasurementPeriodicity_PDU = -1;  /* MeasurementPeriodicity */
static int hf_lppa_MeasurementQuantities_PDU = -1;  /* MeasurementQuantities */
static int hf_lppa_MeasurementQuantities_Item_PDU = -1;  /* MeasurementQuantities_Item */
static int hf_lppa_OTDOACells_PDU = -1;           /* OTDOACells */
static int hf_lppa_ReportCharacteristics_PDU = -1;  /* ReportCharacteristics */
static int hf_lppa_RequestedSRSTransmissionCharacteristics_PDU = -1;  /* RequestedSRSTransmissionCharacteristics */
static int hf_lppa_ULConfiguration_PDU = -1;      /* ULConfiguration */
static int hf_lppa_WLANMeasurementQuantities_PDU = -1;  /* WLANMeasurementQuantities */
static int hf_lppa_WLANMeasurementQuantities_Item_PDU = -1;  /* WLANMeasurementQuantities_Item */
static int hf_lppa_WLANMeasurementResult_PDU = -1;  /* WLANMeasurementResult */
static int hf_lppa_E_CIDMeasurementInitiationRequest_PDU = -1;  /* E_CIDMeasurementInitiationRequest */
static int hf_lppa_E_CIDMeasurementInitiationResponse_PDU = -1;  /* E_CIDMeasurementInitiationResponse */
static int hf_lppa_E_CIDMeasurementInitiationFailure_PDU = -1;  /* E_CIDMeasurementInitiationFailure */
static int hf_lppa_E_CIDMeasurementFailureIndication_PDU = -1;  /* E_CIDMeasurementFailureIndication */
static int hf_lppa_E_CIDMeasurementReport_PDU = -1;  /* E_CIDMeasurementReport */
static int hf_lppa_E_CIDMeasurementTerminationCommand_PDU = -1;  /* E_CIDMeasurementTerminationCommand */
static int hf_lppa_OTDOAInformationRequest_PDU = -1;  /* OTDOAInformationRequest */
static int hf_lppa_OTDOA_Information_Type_PDU = -1;  /* OTDOA_Information_Type */
static int hf_lppa_OTDOA_Information_Type_Item_PDU = -1;  /* OTDOA_Information_Type_Item */
static int hf_lppa_OTDOAInformationResponse_PDU = -1;  /* OTDOAInformationResponse */
static int hf_lppa_OTDOAInformationFailure_PDU = -1;  /* OTDOAInformationFailure */
static int hf_lppa_UTDOAInformationRequest_PDU = -1;  /* UTDOAInformationRequest */
static int hf_lppa_UTDOAInformationResponse_PDU = -1;  /* UTDOAInformationResponse */
static int hf_lppa_UTDOAInformationFailure_PDU = -1;  /* UTDOAInformationFailure */
static int hf_lppa_UTDOAInformationUpdate_PDU = -1;  /* UTDOAInformationUpdate */
static int hf_lppa_AssistanceInformationControl_PDU = -1;  /* AssistanceInformationControl */
static int hf_lppa_AssistanceInformationFeedback_PDU = -1;  /* AssistanceInformationFeedback */
static int hf_lppa_ErrorIndication_PDU = -1;      /* ErrorIndication */
static int hf_lppa_PrivateMessage_PDU = -1;       /* PrivateMessage */
static int hf_lppa_local = -1;                    /* INTEGER_0_maxPrivateIEs */
static int hf_lppa_global = -1;                   /* OBJECT_IDENTIFIER */
static int hf_lppa_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_lppa_id = -1;                       /* ProtocolIE_ID */
static int hf_lppa_criticality = -1;              /* Criticality */
static int hf_lppa_ie_field_value = -1;           /* T_ie_field_value */
static int hf_lppa_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_lppa_extensionValue = -1;           /* T_extensionValue */
static int hf_lppa_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_lppa_id_01 = -1;                    /* PrivateIE_ID */
static int hf_lppa_value = -1;                    /* T_value */
static int hf_lppa_initiatingMessage = -1;        /* InitiatingMessage */
static int hf_lppa_successfulOutcome = -1;        /* SuccessfulOutcome */
static int hf_lppa_unsuccessfulOutcome = -1;      /* UnsuccessfulOutcome */
static int hf_lppa_procedureCode = -1;            /* ProcedureCode */
static int hf_lppa_lppatransactionID = -1;        /* LPPATransactionID */
static int hf_lppa_initiatingMessagevalue = -1;   /* InitiatingMessage_value */
static int hf_lppa_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_lppa_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */
static int hf_lppa_Add_OTDOACells_item = -1;      /* Add_OTDOACells_item */
static int hf_lppa_add_OTDOACellInfo = -1;        /* Add_OTDOACell_Information */
static int hf_lppa_iE_Extensions = -1;            /* ProtocolExtensionContainer */
static int hf_lppa_Add_OTDOACell_Information_item = -1;  /* OTDOACell_Information_Item */
static int hf_lppa_systemInformation = -1;        /* SystemInformation */
static int hf_lppa_AssistanceInformationFailureList_item = -1;  /* AssistanceInformationFailureList_item */
static int hf_lppa_posSIB_Type = -1;              /* PosSIB_Type */
static int hf_lppa_outcome = -1;                  /* Outcome */
static int hf_lppa_encrypted = -1;                /* T_encrypted */
static int hf_lppa_gNSSID = -1;                   /* T_gNSSID */
static int hf_lppa_sBASID = -1;                   /* T_sBASID */
static int hf_lppa_ten = -1;                      /* BIT_STRING_SIZE_10 */
static int hf_lppa_forty = -1;                    /* BIT_STRING_SIZE_40 */
static int hf_lppa_ten_tdd = -1;                  /* BIT_STRING_SIZE_8 */
static int hf_lppa_forty_tdd = -1;                /* BIT_STRING_SIZE_32 */
static int hf_lppa_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_lppa_protocol = -1;                 /* CauseProtocol */
static int hf_lppa_misc = -1;                     /* CauseMisc */
static int hf_lppa_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_lppa_procedureCriticality = -1;     /* Criticality */
static int hf_lppa_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_lppa_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_lppa_iECriticality = -1;            /* Criticality */
static int hf_lppa_iE_ID = -1;                    /* ProtocolIE_ID */
static int hf_lppa_typeOfError = -1;              /* TypeOfError */
static int hf_lppa_servingCell_ID = -1;           /* ECGI */
static int hf_lppa_servingCellTAC = -1;           /* TAC */
static int hf_lppa_e_UTRANAccessPointPosition = -1;  /* E_UTRANAccessPointPosition */
static int hf_lppa_measuredResults = -1;          /* MeasuredResults */
static int hf_lppa_pLMN_Identity = -1;            /* PLMN_Identity */
static int hf_lppa_eUTRANcellIdentifier = -1;     /* EUTRANCellIdentifier */
static int hf_lppa_latitudeSign = -1;             /* T_latitudeSign */
static int hf_lppa_latitude = -1;                 /* INTEGER_0_8388607 */
static int hf_lppa_longitude = -1;                /* INTEGER_M8388608_8388607 */
static int hf_lppa_directionOfAltitude = -1;      /* T_directionOfAltitude */
static int hf_lppa_altitude = -1;                 /* INTEGER_0_32767 */
static int hf_lppa_uncertaintySemi_major = -1;    /* INTEGER_0_127 */
static int hf_lppa_uncertaintySemi_minor = -1;    /* INTEGER_0_127 */
static int hf_lppa_orientationOfMajorAxis = -1;   /* INTEGER_0_179 */
static int hf_lppa_uncertaintyAltitude = -1;      /* INTEGER_0_127 */
static int hf_lppa_confidence = -1;               /* INTEGER_0_100 */
static int hf_lppa_InterRATMeasurementQuantities_item = -1;  /* ProtocolIE_Single_Container */
static int hf_lppa_interRATMeasurementQuantitiesValue = -1;  /* InterRATMeasurementQuantitiesValue */
static int hf_lppa_InterRATMeasurementResult_item = -1;  /* InterRATMeasuredResultsValue */
static int hf_lppa_resultGERAN = -1;              /* ResultGERAN */
static int hf_lppa_resultUTRAN = -1;              /* ResultUTRAN */
static int hf_lppa_MeasurementQuantities_item = -1;  /* ProtocolIE_Single_Container */
static int hf_lppa_measurementQuantitiesValue = -1;  /* MeasurementQuantitiesValue */
static int hf_lppa_MeasuredResults_item = -1;     /* MeasuredResultsValue */
static int hf_lppa_valueAngleOfArrival = -1;      /* INTEGER_0_719 */
static int hf_lppa_valueTimingAdvanceType1 = -1;  /* INTEGER_0_7690 */
static int hf_lppa_valueTimingAdvanceType2 = -1;  /* INTEGER_0_7690 */
static int hf_lppa_resultRSRP = -1;               /* ResultRSRP */
static int hf_lppa_resultRSRQ = -1;               /* ResultRSRQ */
static int hf_lppa_MBSFNsubframeConfiguration_item = -1;  /* MBSFNsubframeConfigurationValue */
static int hf_lppa_radioframeAllocationPeriod = -1;  /* T_radioframeAllocationPeriod */
static int hf_lppa_radioframeAllocationOffset = -1;  /* INTEGER_0_7 */
static int hf_lppa_subframeAllocation = -1;       /* Subframeallocation */
static int hf_lppa_nPRSSubframePartA = -1;        /* NPRSSubframePartA */
static int hf_lppa_nPRSSubframePartB = -1;        /* NPRSSubframePartB */
static int hf_lppa_two = -1;                      /* BIT_STRING_SIZE_2 */
static int hf_lppa_four = -1;                     /* BIT_STRING_SIZE_4 */
static int hf_lppa_eight = -1;                    /* BIT_STRING_SIZE_8 */
static int hf_lppa_sixteen = -1;                  /* BIT_STRING_SIZE_16 */
static int hf_lppa_bitmapsforNPRS = -1;           /* BitmapsforNPRS */
static int hf_lppa_nPRSMutingConfiguration = -1;  /* NPRSMutingConfiguration */
static int hf_lppa_numberofNPRSOneOccasion = -1;  /* T_numberofNPRSOneOccasion */
static int hf_lppa_periodicityofNPRS = -1;        /* T_periodicityofNPRS */
static int hf_lppa_startingsubframeoffset = -1;   /* T_startingsubframeoffset */
static int hf_lppa_sIB1_NB_Subframe_TDD = -1;     /* T_sIB1_NB_Subframe_TDD */
static int hf_lppa_OTDOACells_item = -1;          /* OTDOACells_item */
static int hf_lppa_oTDOACellInfo = -1;            /* OTDOACell_Information */
static int hf_lppa_OTDOACell_Information_item = -1;  /* OTDOACell_Information_Item */
static int hf_lppa_pCI = -1;                      /* PCI */
static int hf_lppa_cellId = -1;                   /* ECGI */
static int hf_lppa_tAC = -1;                      /* TAC */
static int hf_lppa_eARFCN = -1;                   /* EARFCN */
static int hf_lppa_pRS_Bandwidth = -1;            /* PRS_Bandwidth */
static int hf_lppa_pRS_ConfigurationIndex = -1;   /* PRS_Configuration_Index */
static int hf_lppa_cPLength = -1;                 /* CPLength */
static int hf_lppa_numberOfDlFrames = -1;         /* NumberOfDlFrames */
static int hf_lppa_numberOfAntennaPorts = -1;     /* NumberOfAntennaPorts */
static int hf_lppa_sFNInitialisationTime = -1;    /* SFNInitialisationTime */
static int hf_lppa_pRSMutingConfiguration = -1;   /* PRSMutingConfiguration */
static int hf_lppa_prsid = -1;                    /* PRS_ID */
static int hf_lppa_tpid = -1;                     /* TP_ID */
static int hf_lppa_tpType = -1;                   /* TP_Type */
static int hf_lppa_numberOfDlFrames_Extended = -1;  /* NumberOfDlFrames_Extended */
static int hf_lppa_crsCPlength = -1;              /* CPLength */
static int hf_lppa_mBSFNsubframeConfiguration = -1;  /* MBSFNsubframeConfiguration */
static int hf_lppa_nPRSConfiguration = -1;        /* NPRSConfiguration */
static int hf_lppa_offsetNBChanneltoEARFCN = -1;  /* OffsetNBChanneltoEARFCN */
static int hf_lppa_operationModeInfo = -1;        /* OperationModeInfo */
static int hf_lppa_nPRS_ID = -1;                  /* INTEGER_0_4095_ */
static int hf_lppa_dL_Bandwidth = -1;             /* DL_Bandwidth */
static int hf_lppa_pRSOccasionGroup = -1;         /* PRSOccasionGroup */
static int hf_lppa_pRSFreqHoppingConfig = -1;     /* PRSFrequencyHoppingConfiguration */
static int hf_lppa_repetitionNumberofSIB1_NB = -1;  /* RepetitionNumberofSIB1_NB */
static int hf_lppa_nPRSSequenceInfo = -1;         /* NPRSSequenceInfo */
static int hf_lppa_nPRSType2 = -1;                /* NPRSConfiguration */
static int hf_lppa_tddConfiguration = -1;         /* TDDConfiguration */
static int hf_lppa_PosSIBs_item = -1;             /* PosSIBs_item */
static int hf_lppa_posSIB_Segments = -1;          /* PosSIB_Segments */
static int hf_lppa_assistanceInformationMetaData = -1;  /* AssistanceInformationMetaData */
static int hf_lppa_broadcastPriority = -1;        /* INTEGER_1_16_ */
static int hf_lppa_PosSIB_Segments_item = -1;     /* PosSIB_Segments_item */
static int hf_lppa_assistanceDataSIBelement = -1;  /* OCTET_STRING */
static int hf_lppa_thirty_two = -1;               /* BIT_STRING_SIZE_32 */
static int hf_lppa_sixty_four = -1;               /* BIT_STRING_SIZE_64 */
static int hf_lppa_one_hundred_and_twenty_eight = -1;  /* BIT_STRING_SIZE_128 */
static int hf_lppa_two_hundred_and_fifty_six = -1;  /* BIT_STRING_SIZE_256 */
static int hf_lppa_five_hundred_and_twelve = -1;  /* BIT_STRING_SIZE_512 */
static int hf_lppa_one_thousand_and_twenty_four = -1;  /* BIT_STRING_SIZE_1024 */
static int hf_lppa_noOfFreqHoppingBands = -1;     /* NumberOfFrequencyHoppingBands */
static int hf_lppa_bandPositions = -1;            /* SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex */
static int hf_lppa_bandPositions_item = -1;       /* NarrowBandIndex */
static int hf_lppa_numberOfTransmissions = -1;    /* INTEGER_0_500_ */
static int hf_lppa_bandwidth = -1;                /* INTEGER_1_100_ */
static int hf_lppa_ResultRSRP_item = -1;          /* ResultRSRP_Item */
static int hf_lppa_eCGI = -1;                     /* ECGI */
static int hf_lppa_valueRSRP = -1;                /* ValueRSRP */
static int hf_lppa_ResultRSRQ_item = -1;          /* ResultRSRQ_Item */
static int hf_lppa_valueRSRQ = -1;                /* ValueRSRQ */
static int hf_lppa_ResultGERAN_item = -1;         /* ResultGERAN_Item */
static int hf_lppa_bCCH = -1;                     /* BCCH */
static int hf_lppa_physCellIDGERAN = -1;          /* PhysCellIDGERAN */
static int hf_lppa_rSSI = -1;                     /* RSSI */
static int hf_lppa_ResultUTRAN_item = -1;         /* ResultUTRAN_Item */
static int hf_lppa_uARFCN = -1;                   /* UARFCN */
static int hf_lppa_physCellIDUTRAN = -1;          /* T_physCellIDUTRAN */
static int hf_lppa_physCellIDUTRA_FDD = -1;       /* PhysCellIDUTRA_FDD */
static int hf_lppa_physCellIDUTRA_TDD = -1;       /* PhysCellIDUTRA_TDD */
static int hf_lppa_uTRA_RSCP = -1;                /* UTRA_RSCP */
static int hf_lppa_uTRA_EcN0 = -1;                /* UTRA_EcN0 */
static int hf_lppa_SRSConfigurationForAllCells_item = -1;  /* SRSConfigurationForOneCell */
static int hf_lppa_pci = -1;                      /* PCI */
static int hf_lppa_ul_earfcn = -1;                /* EARFCN */
static int hf_lppa_ul_bandwidth = -1;             /* T_ul_bandwidth */
static int hf_lppa_ul_cyclicPrefixLength = -1;    /* CPLength */
static int hf_lppa_srs_BandwidthConfig = -1;      /* T_srs_BandwidthConfig */
static int hf_lppa_srs_Bandwidth = -1;            /* T_srs_Bandwidth */
static int hf_lppa_srs_AntennaPort = -1;          /* T_srs_AntennaPort */
static int hf_lppa_srs_HoppingBandwidth = -1;     /* T_srs_HoppingBandwidth */
static int hf_lppa_srs_cyclicShift = -1;          /* T_srs_cyclicShift */
static int hf_lppa_srs_ConfigIndex = -1;          /* INTEGER_0_1023 */
static int hf_lppa_maxUpPts = -1;                 /* T_maxUpPts */
static int hf_lppa_transmissionComb = -1;         /* INTEGER_0_1 */
static int hf_lppa_freqDomainPosition = -1;       /* INTEGER_0_23 */
static int hf_lppa_groupHoppingEnabled = -1;      /* BOOLEAN */
static int hf_lppa_deltaSS = -1;                  /* INTEGER_0_29 */
static int hf_lppa_sfnInitialisationTime = -1;    /* SFNInitialisationTime */
static int hf_lppa_oneFrame = -1;                 /* BIT_STRING_SIZE_6 */
static int hf_lppa_fourFrames = -1;               /* BIT_STRING_SIZE_24 */
static int hf_lppa_SystemInformation_item = -1;   /* SystemInformation_item */
static int hf_lppa_broadcastPeriodicity = -1;     /* BroadcastPeriodicity */
static int hf_lppa_posSIBs = -1;                  /* PosSIBs */
static int hf_lppa_subframeAssignment = -1;       /* T_subframeAssignment */
static int hf_lppa_timingAdvanceType1 = -1;       /* INTEGER_0_7690 */
static int hf_lppa_timingAdvanceType2 = -1;       /* INTEGER_0_7690 */
static int hf_lppa_srsConfiguration = -1;         /* SRSConfigurationForAllCells */
static int hf_lppa_WLANMeasurementQuantities_item = -1;  /* ProtocolIE_Single_Container */
static int hf_lppa_wLANMeasurementQuantitiesValue = -1;  /* WLANMeasurementQuantitiesValue */
static int hf_lppa_WLANMeasurementResult_item = -1;  /* WLANMeasurementResult_Item */
static int hf_lppa_wLAN_RSSI = -1;                /* WLAN_RSSI */
static int hf_lppa_sSID = -1;                     /* SSID */
static int hf_lppa_bSSID = -1;                    /* BSSID */
static int hf_lppa_hESSID = -1;                   /* HESSID */
static int hf_lppa_operatingClass = -1;           /* WLANOperatingClass */
static int hf_lppa_countryCode = -1;              /* WLANCountryCode */
static int hf_lppa_wLANChannelList = -1;          /* WLANChannelList */
static int hf_lppa_wLANBand = -1;                 /* WLANBand */
static int hf_lppa_WLANChannelList_item = -1;     /* WLANChannel */
static int hf_lppa_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_lppa_OTDOA_Information_Type_item = -1;  /* ProtocolIE_Single_Container */
static int hf_lppa_oTDOA_Information_Type_Item = -1;  /* OTDOA_Information_Item */
static int hf_lppa_privateIEs = -1;               /* PrivateIE_Container */

/*--- End of included file: packet-lppa-hf.c ---*/
#line 35 "./asn1/lppa/packet-lppa-template.c"

/* Initialize the subtree pointers */
static gint ett_lppa = -1;

/*--- Included file: packet-lppa-ett.c ---*/
#line 1 "./asn1/lppa/packet-lppa-ett.c"
static gint ett_lppa_PrivateIE_ID = -1;
static gint ett_lppa_ProtocolIE_Container = -1;
static gint ett_lppa_ProtocolIE_Field = -1;
static gint ett_lppa_ProtocolExtensionContainer = -1;
static gint ett_lppa_ProtocolExtensionField = -1;
static gint ett_lppa_PrivateIE_Container = -1;
static gint ett_lppa_PrivateIE_Field = -1;
static gint ett_lppa_LPPA_PDU = -1;
static gint ett_lppa_InitiatingMessage = -1;
static gint ett_lppa_SuccessfulOutcome = -1;
static gint ett_lppa_UnsuccessfulOutcome = -1;
static gint ett_lppa_Add_OTDOACells = -1;
static gint ett_lppa_Add_OTDOACells_item = -1;
static gint ett_lppa_Add_OTDOACell_Information = -1;
static gint ett_lppa_Assistance_Information = -1;
static gint ett_lppa_AssistanceInformationFailureList = -1;
static gint ett_lppa_AssistanceInformationFailureList_item = -1;
static gint ett_lppa_AssistanceInformationMetaData = -1;
static gint ett_lppa_BitmapsforNPRS = -1;
static gint ett_lppa_Cause = -1;
static gint ett_lppa_CriticalityDiagnostics = -1;
static gint ett_lppa_CriticalityDiagnostics_IE_List = -1;
static gint ett_lppa_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_lppa_E_CID_MeasurementResult = -1;
static gint ett_lppa_ECGI = -1;
static gint ett_lppa_E_UTRANAccessPointPosition = -1;
static gint ett_lppa_InterRATMeasurementQuantities = -1;
static gint ett_lppa_InterRATMeasurementQuantities_Item = -1;
static gint ett_lppa_InterRATMeasurementResult = -1;
static gint ett_lppa_InterRATMeasuredResultsValue = -1;
static gint ett_lppa_MeasurementQuantities = -1;
static gint ett_lppa_MeasurementQuantities_Item = -1;
static gint ett_lppa_MeasuredResults = -1;
static gint ett_lppa_MeasuredResultsValue = -1;
static gint ett_lppa_MBSFNsubframeConfiguration = -1;
static gint ett_lppa_MBSFNsubframeConfigurationValue = -1;
static gint ett_lppa_NPRSConfiguration = -1;
static gint ett_lppa_NPRSMutingConfiguration = -1;
static gint ett_lppa_NPRSSubframePartA = -1;
static gint ett_lppa_NPRSSubframePartB = -1;
static gint ett_lppa_OTDOACells = -1;
static gint ett_lppa_OTDOACells_item = -1;
static gint ett_lppa_OTDOACell_Information = -1;
static gint ett_lppa_OTDOACell_Information_Item = -1;
static gint ett_lppa_PosSIBs = -1;
static gint ett_lppa_PosSIBs_item = -1;
static gint ett_lppa_PosSIB_Segments = -1;
static gint ett_lppa_PosSIB_Segments_item = -1;
static gint ett_lppa_PRSMutingConfiguration = -1;
static gint ett_lppa_PRSFrequencyHoppingConfiguration = -1;
static gint ett_lppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex = -1;
static gint ett_lppa_RequestedSRSTransmissionCharacteristics = -1;
static gint ett_lppa_ResultRSRP = -1;
static gint ett_lppa_ResultRSRP_Item = -1;
static gint ett_lppa_ResultRSRQ = -1;
static gint ett_lppa_ResultRSRQ_Item = -1;
static gint ett_lppa_ResultGERAN = -1;
static gint ett_lppa_ResultGERAN_Item = -1;
static gint ett_lppa_ResultUTRAN = -1;
static gint ett_lppa_ResultUTRAN_Item = -1;
static gint ett_lppa_T_physCellIDUTRAN = -1;
static gint ett_lppa_SRSConfigurationForAllCells = -1;
static gint ett_lppa_SRSConfigurationForOneCell = -1;
static gint ett_lppa_Subframeallocation = -1;
static gint ett_lppa_SystemInformation = -1;
static gint ett_lppa_SystemInformation_item = -1;
static gint ett_lppa_TDDConfiguration = -1;
static gint ett_lppa_ULConfiguration = -1;
static gint ett_lppa_WLANMeasurementQuantities = -1;
static gint ett_lppa_WLANMeasurementQuantities_Item = -1;
static gint ett_lppa_WLANMeasurementResult = -1;
static gint ett_lppa_WLANMeasurementResult_Item = -1;
static gint ett_lppa_WLANChannelList = -1;
static gint ett_lppa_E_CIDMeasurementInitiationRequest = -1;
static gint ett_lppa_E_CIDMeasurementInitiationResponse = -1;
static gint ett_lppa_E_CIDMeasurementInitiationFailure = -1;
static gint ett_lppa_E_CIDMeasurementFailureIndication = -1;
static gint ett_lppa_E_CIDMeasurementReport = -1;
static gint ett_lppa_E_CIDMeasurementTerminationCommand = -1;
static gint ett_lppa_OTDOAInformationRequest = -1;
static gint ett_lppa_OTDOA_Information_Type = -1;
static gint ett_lppa_OTDOA_Information_Type_Item = -1;
static gint ett_lppa_OTDOAInformationResponse = -1;
static gint ett_lppa_OTDOAInformationFailure = -1;
static gint ett_lppa_UTDOAInformationRequest = -1;
static gint ett_lppa_UTDOAInformationResponse = -1;
static gint ett_lppa_UTDOAInformationFailure = -1;
static gint ett_lppa_UTDOAInformationUpdate = -1;
static gint ett_lppa_AssistanceInformationControl = -1;
static gint ett_lppa_AssistanceInformationFeedback = -1;
static gint ett_lppa_ErrorIndication = -1;
static gint ett_lppa_PrivateMessage = -1;

/*--- End of included file: packet-lppa-ett.c ---*/
#line 39 "./asn1/lppa/packet-lppa-template.c"

enum {
    INITIATING_MESSAGE,
    SUCCESSFUL_OUTCOME,
    UNSUCCESSFUL_OUTCOME
};

/* Dissector tables */
static dissector_table_t lppa_ies_dissector_table;
static dissector_table_t lppa_proc_imsg_dissector_table;
static dissector_table_t lppa_proc_sout_dissector_table;
static dissector_table_t lppa_proc_uout_dissector_table;

/* Include constants */

/*--- Included file: packet-lppa-val.h ---*/
#line 1 "./asn1/lppa/packet-lppa-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfErrors                  256
#define maxCellineNB                   256
#define maxNoMeas                      63
#define maxCellReport                  9
#define maxnoOTDOAtypes                63
#define maxServCell                    5
#define maxGERANMeas                   8
#define maxUTRANMeas                   8
#define maxCellineNB_ext               3840
#define maxMBSFN_Allocations           8
#define maxWLANchannels                16
#define maxnoFreqHoppingBandsMinusOne  7
#define maxNrOfPosSImessage            32
#define maxnoAssistInfoFailureListItems 32
#define maxNrOfSegments                64
#define maxNrOfPosSIBs                 32

typedef enum _ProcedureCode_enum {
  id_errorIndication =   0,
  id_privateMessage =   1,
  id_e_CIDMeasurementInitiation =   2,
  id_e_CIDMeasurementFailureIndication =   3,
  id_e_CIDMeasurementReport =   4,
  id_e_CIDMeasurementTermination =   5,
  id_oTDOAInformationExchange =   6,
  id_uTDOAInformationExchange =   7,
  id_uTDOAInformationUpdate =   8,
  id_assistanceInformationControl =   9,
  id_assistanceInformationFeedback =  10
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Cause     =   0,
  id_CriticalityDiagnostics =   1,
  id_E_SMLC_UE_Measurement_ID =   2,
  id_ReportCharacteristics =   3,
  id_MeasurementPeriodicity =   4,
  id_MeasurementQuantities =   5,
  id_eNB_UE_Measurement_ID =   6,
  id_E_CID_MeasurementResult =   7,
  id_OTDOACells =   8,
  id_OTDOA_Information_Type_Group =   9,
  id_OTDOA_Information_Type_Item =  10,
  id_MeasurementQuantities_Item =  11,
  id_RequestedSRSTransmissionCharacteristics =  12,
  id_ULConfiguration =  13,
  id_Cell_Portion_ID =  14,
  id_InterRATMeasurementQuantities =  15,
  id_InterRATMeasurementQuantities_Item =  16,
  id_InterRATMeasurementResult =  17,
  id_AddOTDOACells =  18,
  id_WLANMeasurementQuantities =  19,
  id_WLANMeasurementQuantities_Item =  20,
  id_WLANMeasurementResult =  21,
  id_Assistance_Information =  22,
  id_Broadcast =  23,
  id_AssistanceInformationFailureList =  24
} ProtocolIE_ID_enum;

/*--- End of included file: packet-lppa-val.h ---*/
#line 54 "./asn1/lppa/packet-lppa-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

struct lppa_private_data {
    guint32 procedure_code;
    guint32 protocol_ie_id;
    guint32 protocol_extension_id;
    guint32 message_type;
};

static struct lppa_private_data*
lppa_get_private_data(packet_info* pinfo)
{
    struct lppa_private_data* lppa_data = (struct lppa_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_lppa, 0);
    if (!lppa_data) {
        lppa_data = wmem_new0(pinfo->pool, struct lppa_private_data);
        p_add_proto_data(pinfo->pool, pinfo, proto_lppa, 0, lppa_data);
    }
    return lppa_data;
}


/*--- Included file: packet-lppa-fn.c ---*/
#line 1 "./asn1/lppa/packet-lppa-fn.c"

static const value_string lppa_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_lppa_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lppa_LPPATransactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_INTEGER_0_maxPrivateIEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxPrivateIEs, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string lppa_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_lppa_local          , ASN1_NO_EXTENSIONS     , dissect_lppa_INTEGER_0_maxPrivateIEs },
  {   1, &hf_lppa_global         , ASN1_NO_EXTENSIONS     , dissect_lppa_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string lppa_ProcedureCode_vals[] = {
  { id_errorIndication, "id-errorIndication" },
  { id_privateMessage, "id-privateMessage" },
  { id_e_CIDMeasurementInitiation, "id-e-CIDMeasurementInitiation" },
  { id_e_CIDMeasurementFailureIndication, "id-e-CIDMeasurementFailureIndication" },
  { id_e_CIDMeasurementReport, "id-e-CIDMeasurementReport" },
  { id_e_CIDMeasurementTermination, "id-e-CIDMeasurementTermination" },
  { id_oTDOAInformationExchange, "id-oTDOAInformationExchange" },
  { id_uTDOAInformationExchange, "id-uTDOAInformationExchange" },
  { id_uTDOAInformationUpdate, "id-uTDOAInformationUpdate" },
  { id_assistanceInformationControl, "id-assistanceInformationControl" },
  { id_assistanceInformationFeedback, "id-assistanceInformationFeedback" },
  { 0, NULL }
};


static int
dissect_lppa_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 46 "./asn1/lppa/lppa.cnf"
  struct lppa_private_data *lppa_data = lppa_get_private_data(actx->pinfo);

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &lppa_data->procedure_code, FALSE);


  col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                 val_to_str(lppa_data->procedure_code, lppa_ProcedureCode_vals,
                            "unknown message"));


  return offset;
}


static const value_string lppa_ProtocolIE_ID_vals[] = {
  { id_Cause, "id-Cause" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_E_SMLC_UE_Measurement_ID, "id-E-SMLC-UE-Measurement-ID" },
  { id_ReportCharacteristics, "id-ReportCharacteristics" },
  { id_MeasurementPeriodicity, "id-MeasurementPeriodicity" },
  { id_MeasurementQuantities, "id-MeasurementQuantities" },
  { id_eNB_UE_Measurement_ID, "id-eNB-UE-Measurement-ID" },
  { id_E_CID_MeasurementResult, "id-E-CID-MeasurementResult" },
  { id_OTDOACells, "id-OTDOACells" },
  { id_OTDOA_Information_Type_Group, "id-OTDOA-Information-Type-Group" },
  { id_OTDOA_Information_Type_Item, "id-OTDOA-Information-Type-Item" },
  { id_MeasurementQuantities_Item, "id-MeasurementQuantities-Item" },
  { id_RequestedSRSTransmissionCharacteristics, "id-RequestedSRSTransmissionCharacteristics" },
  { id_ULConfiguration, "id-ULConfiguration" },
  { id_Cell_Portion_ID, "id-Cell-Portion-ID" },
  { id_InterRATMeasurementQuantities, "id-InterRATMeasurementQuantities" },
  { id_InterRATMeasurementQuantities_Item, "id-InterRATMeasurementQuantities-Item" },
  { id_InterRATMeasurementResult, "id-InterRATMeasurementResult" },
  { id_AddOTDOACells, "id-AddOTDOACells" },
  { id_WLANMeasurementQuantities, "id-WLANMeasurementQuantities" },
  { id_WLANMeasurementQuantities_Item, "id-WLANMeasurementQuantities-Item" },
  { id_WLANMeasurementResult, "id-WLANMeasurementResult" },
  { id_Assistance_Information, "id-Assistance-Information" },
  { id_Broadcast, "id-Broadcast" },
  { id_AssistanceInformationFailureList, "id-AssistanceInformationFailureList" },
  { 0, NULL }
};


static int
dissect_lppa_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 36 "./asn1/lppa/lppa.cnf"
  struct lppa_private_data *lppa_data = lppa_get_private_data(actx->pinfo);
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &lppa_data->protocol_ie_id, FALSE);




#line 40 "./asn1/lppa/lppa.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(lppa_data->protocol_ie_id, VALS(lppa_ProtocolIE_ID_vals), "unknown (%d)"));
  }

  return offset;
}


static const value_string lppa_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_lppa_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lppa_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_lppa_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_ID },
  { &hf_lppa_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_Criticality },
  { &hf_lppa_ie_field_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_lppa_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Field },
};

static int
dissect_lppa_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_lppa_ProtocolIE_Single_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_lppa_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_lppa_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_lppa_id             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_ID },
  { &hf_lppa_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_Criticality },
  { &hf_lppa_extensionValue , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_lppa_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolExtensionField },
};

static int
dissect_lppa_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_lppa_T_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_lppa_id_01          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_PrivateIE_ID },
  { &hf_lppa_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_Criticality },
  { &hf_lppa_value          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_T_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_lppa_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_PrivateIE_Field },
};

static int
dissect_lppa_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}



static int
dissect_lppa_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 59 "./asn1/lppa/lppa.cnf"
  struct lppa_private_data *lppa_data = lppa_get_private_data(actx->pinfo);
  lppa_data->message_type = INITIATING_MESSAGE;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_lppa_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProcedureCode },
  { &hf_lppa_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_Criticality },
  { &hf_lppa_lppatransactionID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_LPPATransactionID },
  { &hf_lppa_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_lppa_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 63 "./asn1/lppa/lppa.cnf"
  struct lppa_private_data *lppa_data = lppa_get_private_data(actx->pinfo);
  lppa_data->message_type = SUCCESSFUL_OUTCOME;

  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_lppa_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProcedureCode },
  { &hf_lppa_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_Criticality },
  { &hf_lppa_lppatransactionID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_LPPATransactionID },
  { &hf_lppa_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_lppa_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 67 "./asn1/lppa/lppa.cnf"
  struct lppa_private_data *lppa_data = lppa_get_private_data(actx->pinfo);
  lppa_data->message_type = UNSUCCESSFUL_OUTCOME;


  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_lppa_procedureCode  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProcedureCode },
  { &hf_lppa_criticality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_Criticality },
  { &hf_lppa_lppatransactionID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_LPPATransactionID },
  { &hf_lppa_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string lppa_LPPA_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t LPPA_PDU_choice[] = {
  {   0, &hf_lppa_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_lppa_InitiatingMessage },
  {   1, &hf_lppa_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_lppa_SuccessfulOutcome },
  {   2, &hf_lppa_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_lppa_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_LPPA_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 71 "./asn1/lppa/lppa.cnf"

  proto_tree_add_item(tree, proto_lppa, tvb, 0, -1, ENC_NA);

  col_append_sep_str(actx->pinfo->cinfo, COL_PROTOCOL, "/", "LPPa");

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_LPPA_PDU, LPPA_PDU_choice,
                                 NULL);

  return offset;
}



static int
dissect_lppa_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, TRUE);

  return offset;
}



static int
dissect_lppa_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_lppa_EUTRANCellIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t ECGI_sequence[] = {
  { &hf_lppa_pLMN_Identity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PLMN_Identity },
  { &hf_lppa_eUTRANcellIdentifier, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_EUTRANCellIdentifier },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_ECGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_ECGI, ECGI_sequence);

  return offset;
}



static int
dissect_lppa_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_lppa_EARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, TRUE);

  return offset;
}


static const value_string lppa_PRS_Bandwidth_vals[] = {
  {   0, "bw6" },
  {   1, "bw15" },
  {   2, "bw25" },
  {   3, "bw50" },
  {   4, "bw75" },
  {   5, "bw100" },
  { 0, NULL }
};


static int
dissect_lppa_PRS_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lppa_PRS_Configuration_Index(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const value_string lppa_CPLength_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_lppa_CPLength(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_NumberOfDlFrames_vals[] = {
  {   0, "sf1" },
  {   1, "sf2" },
  {   2, "sf4" },
  {   3, "sf6" },
  { 0, NULL }
};


static int
dissect_lppa_NumberOfDlFrames(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_NumberOfAntennaPorts_vals[] = {
  {   0, "n1-or-n2" },
  {   1, "n4" },
  { 0, NULL }
};


static int
dissect_lppa_NumberOfAntennaPorts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lppa_SFNInitialisationTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string lppa_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_lppa_T_latitudeSign(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lppa_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, FALSE);

  return offset;
}


static const value_string lppa_T_directionOfAltitude_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_lppa_T_directionOfAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lppa_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_INTEGER_0_179(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 179U, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_INTEGER_0_100(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}


static const per_sequence_t E_UTRANAccessPointPosition_sequence[] = {
  { &hf_lppa_latitudeSign   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_latitudeSign },
  { &hf_lppa_latitude       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_8388607 },
  { &hf_lppa_longitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_M8388608_8388607 },
  { &hf_lppa_directionOfAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_directionOfAltitude },
  { &hf_lppa_altitude       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_32767 },
  { &hf_lppa_uncertaintySemi_major, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_127 },
  { &hf_lppa_uncertaintySemi_minor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_127 },
  { &hf_lppa_orientationOfMajorAxis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_179 },
  { &hf_lppa_uncertaintyAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_127 },
  { &hf_lppa_confidence     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_100 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_E_UTRANAccessPointPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_E_UTRANAccessPointPosition, E_UTRANAccessPointPosition_sequence);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_512(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     512, 512, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_1024(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1024, 1024, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string lppa_PRSMutingConfiguration_vals[] = {
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
  { 0, NULL }
};

static const per_choice_t PRSMutingConfiguration_choice[] = {
  {   0, &hf_lppa_two            , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_2 },
  {   1, &hf_lppa_four           , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_4 },
  {   2, &hf_lppa_eight          , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_8 },
  {   3, &hf_lppa_sixteen        , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_16 },
  {   4, &hf_lppa_thirty_two     , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_BIT_STRING_SIZE_32 },
  {   5, &hf_lppa_sixty_four     , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_BIT_STRING_SIZE_64 },
  {   6, &hf_lppa_one_hundred_and_twenty_eight, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_BIT_STRING_SIZE_128 },
  {   7, &hf_lppa_two_hundred_and_fifty_six, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_BIT_STRING_SIZE_256 },
  {   8, &hf_lppa_five_hundred_and_twelve, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_BIT_STRING_SIZE_512 },
  {   9, &hf_lppa_one_thousand_and_twenty_four, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_BIT_STRING_SIZE_1024 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_PRSMutingConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_PRSMutingConfiguration, PRSMutingConfiguration_choice,
                                 NULL);

  return offset;
}



static int
dissect_lppa_PRS_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}



static int
dissect_lppa_TP_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const value_string lppa_TP_Type_vals[] = {
  {   0, "prs-only-tp" },
  { 0, NULL }
};


static int
dissect_lppa_TP_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lppa_NumberOfDlFrames_Extended(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 160U, NULL, TRUE);

  return offset;
}


static const value_string lppa_T_radioframeAllocationPeriod_vals[] = {
  {   0, "n1" },
  {   1, "n2" },
  {   2, "n4" },
  {   3, "n8" },
  {   4, "n16" },
  {   5, "n32" },
  { 0, NULL }
};


static int
dissect_lppa_T_radioframeAllocationPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lppa_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string lppa_Subframeallocation_vals[] = {
  {   0, "oneFrame" },
  {   1, "fourFrames" },
  { 0, NULL }
};

static const per_choice_t Subframeallocation_choice[] = {
  {   0, &hf_lppa_oneFrame       , ASN1_NO_EXTENSIONS     , dissect_lppa_BIT_STRING_SIZE_6 },
  {   1, &hf_lppa_fourFrames     , ASN1_NO_EXTENSIONS     , dissect_lppa_BIT_STRING_SIZE_24 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_Subframeallocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_Subframeallocation, Subframeallocation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MBSFNsubframeConfigurationValue_sequence[] = {
  { &hf_lppa_radioframeAllocationPeriod, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_T_radioframeAllocationPeriod },
  { &hf_lppa_radioframeAllocationOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_7 },
  { &hf_lppa_subframeAllocation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_Subframeallocation },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_MBSFNsubframeConfigurationValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_MBSFNsubframeConfigurationValue, MBSFNsubframeConfigurationValue_sequence);

  return offset;
}


static const per_sequence_t MBSFNsubframeConfiguration_sequence_of[1] = {
  { &hf_lppa_MBSFNsubframeConfiguration_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_MBSFNsubframeConfigurationValue },
};

static int
dissect_lppa_MBSFNsubframeConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_MBSFNsubframeConfiguration, MBSFNsubframeConfiguration_sequence_of,
                                                  1, maxMBSFN_Allocations, FALSE);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     10, 10, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_40(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     40, 40, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string lppa_BitmapsforNPRS_vals[] = {
  {   0, "ten" },
  {   1, "forty" },
  {   2, "ten-tdd" },
  {   3, "forty-tdd" },
  { 0, NULL }
};

static const per_choice_t BitmapsforNPRS_choice[] = {
  {   0, &hf_lppa_ten            , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_10 },
  {   1, &hf_lppa_forty          , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_40 },
  {   2, &hf_lppa_ten_tdd        , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_BIT_STRING_SIZE_8 },
  {   3, &hf_lppa_forty_tdd      , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_BIT_STRING_SIZE_32 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_BitmapsforNPRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_BitmapsforNPRS, BitmapsforNPRS_choice,
                                 NULL);

  return offset;
}


static const value_string lppa_NPRSMutingConfiguration_vals[] = {
  {   0, "two" },
  {   1, "four" },
  {   2, "eight" },
  {   3, "sixteen" },
  { 0, NULL }
};

static const per_choice_t NPRSMutingConfiguration_choice[] = {
  {   0, &hf_lppa_two            , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_2 },
  {   1, &hf_lppa_four           , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_4 },
  {   2, &hf_lppa_eight          , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_8 },
  {   3, &hf_lppa_sixteen        , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_NPRSMutingConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_NPRSMutingConfiguration, NPRSMutingConfiguration_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NPRSSubframePartA_sequence[] = {
  { &hf_lppa_bitmapsforNPRS , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_BitmapsforNPRS },
  { &hf_lppa_nPRSMutingConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_NPRSMutingConfiguration },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_NPRSSubframePartA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_NPRSSubframePartA, NPRSSubframePartA_sequence);

  return offset;
}


static const value_string lppa_T_numberofNPRSOneOccasion_vals[] = {
  {   0, "sf10" },
  {   1, "sf20" },
  {   2, "sf40" },
  {   3, "sf80" },
  {   4, "sf160" },
  {   5, "sf320" },
  {   6, "sf640" },
  {   7, "sf1280" },
  {   8, "sf2560" },
  { 0, NULL }
};


static int
dissect_lppa_T_numberofNPRSOneOccasion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 1, NULL);

  return offset;
}


static const value_string lppa_T_periodicityofNPRS_vals[] = {
  {   0, "sf160" },
  {   1, "sf320" },
  {   2, "sf640" },
  {   3, "sf1280" },
  {   4, "sf2560" },
  { 0, NULL }
};


static int
dissect_lppa_T_periodicityofNPRS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 1, NULL);

  return offset;
}


static const value_string lppa_T_startingsubframeoffset_vals[] = {
  {   0, "zero" },
  {   1, "one-Eighth" },
  {   2, "two-Eighths" },
  {   3, "three-Eighths" },
  {   4, "four-Eighths" },
  {   5, "five-Eighths" },
  {   6, "six-Eighths" },
  {   7, "seven-Eighths" },
  { 0, NULL }
};


static int
dissect_lppa_T_startingsubframeoffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_T_sIB1_NB_Subframe_TDD_vals[] = {
  {   0, "sf0" },
  {   1, "sf4" },
  {   2, "sf0and5" },
  { 0, NULL }
};


static int
dissect_lppa_T_sIB1_NB_Subframe_TDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t NPRSSubframePartB_sequence[] = {
  { &hf_lppa_numberofNPRSOneOccasion, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_numberofNPRSOneOccasion },
  { &hf_lppa_periodicityofNPRS, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_periodicityofNPRS },
  { &hf_lppa_startingsubframeoffset, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_startingsubframeoffset },
  { &hf_lppa_nPRSMutingConfiguration, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_NPRSMutingConfiguration },
  { &hf_lppa_sIB1_NB_Subframe_TDD, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_lppa_T_sIB1_NB_Subframe_TDD },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_NPRSSubframePartB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_NPRSSubframePartB, NPRSSubframePartB_sequence);

  return offset;
}


static const per_sequence_t NPRSConfiguration_sequence[] = {
  { &hf_lppa_nPRSSubframePartA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_NPRSSubframePartA },
  { &hf_lppa_nPRSSubframePartB, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_NPRSSubframePartB },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_NPRSConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_NPRSConfiguration, NPRSConfiguration_sequence);

  return offset;
}


static const value_string lppa_OffsetNBChanneltoEARFCN_vals[] = {
  {   0, "minusTen" },
  {   1, "minusNine" },
  {   2, "minusEight" },
  {   3, "minusSeven" },
  {   4, "minusSix" },
  {   5, "minusFive" },
  {   6, "minusFour" },
  {   7, "minusThree" },
  {   8, "minusTwo" },
  {   9, "minusOne" },
  {  10, "minusZeroDotFive" },
  {  11, "zero" },
  {  12, "one" },
  {  13, "two" },
  {  14, "three" },
  {  15, "four" },
  {  16, "five" },
  {  17, "six" },
  {  18, "seven" },
  {  19, "eight" },
  {  20, "nine" },
  { 0, NULL }
};


static int
dissect_lppa_OffsetNBChanneltoEARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     21, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_OperationModeInfo_vals[] = {
  {   0, "inband" },
  {   1, "guardband" },
  {   2, "standalone" },
  { 0, NULL }
};


static int
dissect_lppa_OperationModeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lppa_INTEGER_0_4095_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const value_string lppa_DL_Bandwidth_vals[] = {
  {   0, "bw6" },
  {   1, "bw15" },
  {   2, "bw25" },
  {   3, "bw50" },
  {   4, "bw75" },
  {   5, "bw100" },
  { 0, NULL }
};


static int
dissect_lppa_DL_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_PRSOccasionGroup_vals[] = {
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
dissect_lppa_PRSOccasionGroup(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_NumberOfFrequencyHoppingBands_vals[] = {
  {   0, "twobands" },
  {   1, "fourbands" },
  { 0, NULL }
};


static int
dissect_lppa_NumberOfFrequencyHoppingBands(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lppa_NarrowBandIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex_sequence_of[1] = {
  { &hf_lppa_bandPositions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_NarrowBandIndex },
};

static int
dissect_lppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex, SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex_sequence_of,
                                                  1, maxnoFreqHoppingBandsMinusOne, FALSE);

  return offset;
}


static const per_sequence_t PRSFrequencyHoppingConfiguration_sequence[] = {
  { &hf_lppa_noOfFreqHoppingBands, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_NumberOfFrequencyHoppingBands },
  { &hf_lppa_bandPositions  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_PRSFrequencyHoppingConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_PRSFrequencyHoppingConfiguration, PRSFrequencyHoppingConfiguration_sequence);

  return offset;
}


static const value_string lppa_RepetitionNumberofSIB1_NB_vals[] = {
  {   0, "r4" },
  {   1, "r8" },
  {   2, "r16" },
  { 0, NULL }
};


static int
dissect_lppa_RepetitionNumberofSIB1_NB(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lppa_NPRSSequenceInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 174U, NULL, TRUE);

  return offset;
}


static const value_string lppa_T_subframeAssignment_vals[] = {
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
dissect_lppa_T_subframeAssignment(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t TDDConfiguration_sequence[] = {
  { &hf_lppa_subframeAssignment, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_subframeAssignment },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_TDDConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_TDDConfiguration, TDDConfiguration_sequence);

  return offset;
}


static const value_string lppa_OTDOACell_Information_Item_vals[] = {
  {   0, "pCI" },
  {   1, "cellId" },
  {   2, "tAC" },
  {   3, "eARFCN" },
  {   4, "pRS-Bandwidth" },
  {   5, "pRS-ConfigurationIndex" },
  {   6, "cPLength" },
  {   7, "numberOfDlFrames" },
  {   8, "numberOfAntennaPorts" },
  {   9, "sFNInitialisationTime" },
  {  10, "e-UTRANAccessPointPosition" },
  {  11, "pRSMutingConfiguration" },
  {  12, "prsid" },
  {  13, "tpid" },
  {  14, "tpType" },
  {  15, "numberOfDlFrames-Extended" },
  {  16, "crsCPlength" },
  {  17, "mBSFNsubframeConfiguration" },
  {  18, "nPRSConfiguration" },
  {  19, "offsetNBChanneltoEARFCN" },
  {  20, "operationModeInfo" },
  {  21, "nPRS-ID" },
  {  22, "dL-Bandwidth" },
  {  23, "pRSOccasionGroup" },
  {  24, "pRSFreqHoppingConfig" },
  {  25, "repetitionNumberofSIB1-NB" },
  {  26, "nPRSSequenceInfo" },
  {  27, "nPRSType2" },
  {  28, "tddConfiguration" },
  { 0, NULL }
};

static const per_choice_t OTDOACell_Information_Item_choice[] = {
  {   0, &hf_lppa_pCI            , ASN1_EXTENSION_ROOT    , dissect_lppa_PCI },
  {   1, &hf_lppa_cellId         , ASN1_EXTENSION_ROOT    , dissect_lppa_ECGI },
  {   2, &hf_lppa_tAC            , ASN1_EXTENSION_ROOT    , dissect_lppa_TAC },
  {   3, &hf_lppa_eARFCN         , ASN1_EXTENSION_ROOT    , dissect_lppa_EARFCN },
  {   4, &hf_lppa_pRS_Bandwidth  , ASN1_EXTENSION_ROOT    , dissect_lppa_PRS_Bandwidth },
  {   5, &hf_lppa_pRS_ConfigurationIndex, ASN1_EXTENSION_ROOT    , dissect_lppa_PRS_Configuration_Index },
  {   6, &hf_lppa_cPLength       , ASN1_EXTENSION_ROOT    , dissect_lppa_CPLength },
  {   7, &hf_lppa_numberOfDlFrames, ASN1_EXTENSION_ROOT    , dissect_lppa_NumberOfDlFrames },
  {   8, &hf_lppa_numberOfAntennaPorts, ASN1_EXTENSION_ROOT    , dissect_lppa_NumberOfAntennaPorts },
  {   9, &hf_lppa_sFNInitialisationTime, ASN1_EXTENSION_ROOT    , dissect_lppa_SFNInitialisationTime },
  {  10, &hf_lppa_e_UTRANAccessPointPosition, ASN1_EXTENSION_ROOT    , dissect_lppa_E_UTRANAccessPointPosition },
  {  11, &hf_lppa_pRSMutingConfiguration, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_PRSMutingConfiguration },
  {  12, &hf_lppa_prsid          , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_PRS_ID },
  {  13, &hf_lppa_tpid           , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_TP_ID },
  {  14, &hf_lppa_tpType         , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_TP_Type },
  {  15, &hf_lppa_numberOfDlFrames_Extended, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_NumberOfDlFrames_Extended },
  {  16, &hf_lppa_crsCPlength    , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_CPLength },
  {  17, &hf_lppa_mBSFNsubframeConfiguration, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_MBSFNsubframeConfiguration },
  {  18, &hf_lppa_nPRSConfiguration, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_NPRSConfiguration },
  {  19, &hf_lppa_offsetNBChanneltoEARFCN, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_OffsetNBChanneltoEARFCN },
  {  20, &hf_lppa_operationModeInfo, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_OperationModeInfo },
  {  21, &hf_lppa_nPRS_ID        , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_INTEGER_0_4095_ },
  {  22, &hf_lppa_dL_Bandwidth   , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_DL_Bandwidth },
  {  23, &hf_lppa_pRSOccasionGroup, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_PRSOccasionGroup },
  {  24, &hf_lppa_pRSFreqHoppingConfig, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_PRSFrequencyHoppingConfiguration },
  {  25, &hf_lppa_repetitionNumberofSIB1_NB, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_RepetitionNumberofSIB1_NB },
  {  26, &hf_lppa_nPRSSequenceInfo, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_NPRSSequenceInfo },
  {  27, &hf_lppa_nPRSType2      , ASN1_NOT_EXTENSION_ROOT, dissect_lppa_NPRSConfiguration },
  {  28, &hf_lppa_tddConfiguration, ASN1_NOT_EXTENSION_ROOT, dissect_lppa_TDDConfiguration },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_OTDOACell_Information_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_OTDOACell_Information_Item, OTDOACell_Information_Item_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Add_OTDOACell_Information_sequence_of[1] = {
  { &hf_lppa_Add_OTDOACell_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_OTDOACell_Information_Item },
};

static int
dissect_lppa_Add_OTDOACell_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_Add_OTDOACell_Information, Add_OTDOACell_Information_sequence_of,
                                                  1, maxnoOTDOAtypes, FALSE);

  return offset;
}


static const per_sequence_t Add_OTDOACells_item_sequence[] = {
  { &hf_lppa_add_OTDOACellInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_Add_OTDOACell_Information },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_Add_OTDOACells_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_Add_OTDOACells_item, Add_OTDOACells_item_sequence);

  return offset;
}


static const per_sequence_t Add_OTDOACells_sequence_of[1] = {
  { &hf_lppa_Add_OTDOACells_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_Add_OTDOACells_item },
};

static int
dissect_lppa_Add_OTDOACells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_Add_OTDOACells, Add_OTDOACells_sequence_of,
                                                  1, maxCellineNB_ext, FALSE);

  return offset;
}


static const value_string lppa_BroadcastPeriodicity_vals[] = {
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
dissect_lppa_BroadcastPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_PosSIB_Type_vals[] = {
  {   0, "posSibType1-1" },
  {   1, "posSibType1-2" },
  {   2, "posSibType1-3" },
  {   3, "posSibType1-4" },
  {   4, "posSibType1-5" },
  {   5, "posSibType1-6" },
  {   6, "posSibType1-7" },
  {   7, "posSibType2-1" },
  {   8, "posSibType2-2" },
  {   9, "posSibType2-3" },
  {  10, "posSibType2-4" },
  {  11, "posSibType2-5" },
  {  12, "posSibType2-6" },
  {  13, "posSibType2-7" },
  {  14, "posSibType2-8" },
  {  15, "posSibType2-9" },
  {  16, "posSibType2-10" },
  {  17, "posSibType2-11" },
  {  18, "posSibType2-12" },
  {  19, "posSibType2-13" },
  {  20, "posSibType2-14" },
  {  21, "posSibType2-15" },
  {  22, "posSibType2-16" },
  {  23, "posSibType2-17" },
  {  24, "posSibType2-18" },
  {  25, "posSibType2-19" },
  {  26, "posSibType3-1" },
  { 0, NULL }
};


static int
dissect_lppa_PosSIB_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     27, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lppa_OCTET_STRING(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const per_sequence_t PosSIB_Segments_item_sequence[] = {
  { &hf_lppa_assistanceDataSIBelement, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_OCTET_STRING },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_PosSIB_Segments_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_PosSIB_Segments_item, PosSIB_Segments_item_sequence);

  return offset;
}


static const per_sequence_t PosSIB_Segments_sequence_of[1] = {
  { &hf_lppa_PosSIB_Segments_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_PosSIB_Segments_item },
};

static int
dissect_lppa_PosSIB_Segments(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_PosSIB_Segments, PosSIB_Segments_sequence_of,
                                                  1, maxNrOfSegments, FALSE);

  return offset;
}


static const value_string lppa_T_encrypted_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_lppa_T_encrypted(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_T_gNSSID_vals[] = {
  {   0, "gps" },
  {   1, "sbas" },
  {   2, "gzss" },
  {   3, "galileo" },
  {   4, "glonass" },
  {   5, "bds" },
  { 0, NULL }
};


static int
dissect_lppa_T_gNSSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_T_sBASID_vals[] = {
  {   0, "waas" },
  {   1, "egnos" },
  {   2, "msas" },
  {   3, "gagan" },
  { 0, NULL }
};


static int
dissect_lppa_T_sBASID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t AssistanceInformationMetaData_sequence[] = {
  { &hf_lppa_encrypted      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_T_encrypted },
  { &hf_lppa_gNSSID         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_T_gNSSID },
  { &hf_lppa_sBASID         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_T_sBASID },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_AssistanceInformationMetaData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_AssistanceInformationMetaData, AssistanceInformationMetaData_sequence);

  return offset;
}



static int
dissect_lppa_INTEGER_1_16_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, TRUE);

  return offset;
}


static const per_sequence_t PosSIBs_item_sequence[] = {
  { &hf_lppa_posSIB_Type    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PosSIB_Type },
  { &hf_lppa_posSIB_Segments, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PosSIB_Segments },
  { &hf_lppa_assistanceInformationMetaData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_AssistanceInformationMetaData },
  { &hf_lppa_broadcastPriority, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_INTEGER_1_16_ },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_PosSIBs_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_PosSIBs_item, PosSIBs_item_sequence);

  return offset;
}


static const per_sequence_t PosSIBs_sequence_of[1] = {
  { &hf_lppa_PosSIBs_item   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_PosSIBs_item },
};

static int
dissect_lppa_PosSIBs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_PosSIBs, PosSIBs_sequence_of,
                                                  1, maxNrOfPosSIBs, FALSE);

  return offset;
}


static const per_sequence_t SystemInformation_item_sequence[] = {
  { &hf_lppa_broadcastPeriodicity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_BroadcastPeriodicity },
  { &hf_lppa_posSIBs        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PosSIBs },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_SystemInformation_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_SystemInformation_item, SystemInformation_item_sequence);

  return offset;
}


static const per_sequence_t SystemInformation_sequence_of[1] = {
  { &hf_lppa_SystemInformation_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_SystemInformation_item },
};

static int
dissect_lppa_SystemInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_SystemInformation, SystemInformation_sequence_of,
                                                  1, maxNrOfPosSImessage, FALSE);

  return offset;
}


static const per_sequence_t Assistance_Information_sequence[] = {
  { &hf_lppa_systemInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_SystemInformation },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_Assistance_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_Assistance_Information, Assistance_Information_sequence);

  return offset;
}


static const value_string lppa_Outcome_vals[] = {
  {   0, "failed" },
  { 0, NULL }
};


static int
dissect_lppa_Outcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t AssistanceInformationFailureList_item_sequence[] = {
  { &hf_lppa_posSIB_Type    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PosSIB_Type },
  { &hf_lppa_outcome        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_Outcome },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_AssistanceInformationFailureList_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_AssistanceInformationFailureList_item, AssistanceInformationFailureList_item_sequence);

  return offset;
}


static const per_sequence_t AssistanceInformationFailureList_sequence_of[1] = {
  { &hf_lppa_AssistanceInformationFailureList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_AssistanceInformationFailureList_item },
};

static int
dissect_lppa_AssistanceInformationFailureList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_AssistanceInformationFailureList, AssistanceInformationFailureList_sequence_of,
                                                  1, maxnoAssistInfoFailureListItems, FALSE);

  return offset;
}



static int
dissect_lppa_BCCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, TRUE);

  return offset;
}


static const value_string lppa_Broadcast_vals[] = {
  {   0, "start" },
  {   1, "stop" },
  { 0, NULL }
};


static int
dissect_lppa_Broadcast(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lppa_BSSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, FALSE, NULL);

  return offset;
}


static const value_string lppa_CauseRadioNetwork_vals[] = {
  {   0, "unspecified" },
  {   1, "requested-item-not-supported" },
  {   2, "requested-item-temporarily-not-available" },
  { 0, NULL }
};


static int
dissect_lppa_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_CauseProtocol_vals[] = {
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
dissect_lppa_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_CauseMisc_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};


static int
dissect_lppa_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "protocol" },
  {   2, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_lppa_radioNetwork   , ASN1_EXTENSION_ROOT    , dissect_lppa_CauseRadioNetwork },
  {   1, &hf_lppa_protocol       , ASN1_EXTENSION_ROOT    , dissect_lppa_CauseProtocol },
  {   2, &hf_lppa_misc           , ASN1_EXTENSION_ROOT    , dissect_lppa_CauseMisc },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_Cause, Cause_choice,
                                 NULL);

  return offset;
}



static int
dissect_lppa_Cell_Portion_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, TRUE);

  return offset;
}


static const value_string lppa_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_lppa_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_lppa_iECriticality  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_Criticality },
  { &hf_lppa_iE_ID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_ID },
  { &hf_lppa_typeOfError    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_TypeOfError },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_lppa_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_lppa_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_lppa_procedureCode  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProcedureCode },
  { &hf_lppa_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_TriggeringMessage },
  { &hf_lppa_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_Criticality },
  { &hf_lppa_lppatransactionID, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_LPPATransactionID },
  { &hf_lppa_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_CriticalityDiagnostics_IE_List },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_lppa_INTEGER_0_719(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 719U, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_INTEGER_0_7690(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7690U, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_ValueRSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, TRUE);

  return offset;
}


static const per_sequence_t ResultRSRP_Item_sequence[] = {
  { &hf_lppa_pCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PCI },
  { &hf_lppa_eARFCN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_EARFCN },
  { &hf_lppa_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ECGI },
  { &hf_lppa_valueRSRP      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ValueRSRP },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_ResultRSRP_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_ResultRSRP_Item, ResultRSRP_Item_sequence);

  return offset;
}


static const per_sequence_t ResultRSRP_sequence_of[1] = {
  { &hf_lppa_ResultRSRP_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ResultRSRP_Item },
};

static int
dissect_lppa_ResultRSRP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_ResultRSRP, ResultRSRP_sequence_of,
                                                  1, maxCellReport, FALSE);

  return offset;
}



static int
dissect_lppa_ValueRSRQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, TRUE);

  return offset;
}


static const per_sequence_t ResultRSRQ_Item_sequence[] = {
  { &hf_lppa_pCI            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PCI },
  { &hf_lppa_eARFCN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_EARFCN },
  { &hf_lppa_eCGI           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ECGI },
  { &hf_lppa_valueRSRQ      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ValueRSRQ },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_ResultRSRQ_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_ResultRSRQ_Item, ResultRSRQ_Item_sequence);

  return offset;
}


static const per_sequence_t ResultRSRQ_sequence_of[1] = {
  { &hf_lppa_ResultRSRQ_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ResultRSRQ_Item },
};

static int
dissect_lppa_ResultRSRQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_ResultRSRQ, ResultRSRQ_sequence_of,
                                                  1, maxCellReport, FALSE);

  return offset;
}


static const value_string lppa_MeasuredResultsValue_vals[] = {
  {   0, "valueAngleOfArrival" },
  {   1, "valueTimingAdvanceType1" },
  {   2, "valueTimingAdvanceType2" },
  {   3, "resultRSRP" },
  {   4, "resultRSRQ" },
  { 0, NULL }
};

static const per_choice_t MeasuredResultsValue_choice[] = {
  {   0, &hf_lppa_valueAngleOfArrival, ASN1_EXTENSION_ROOT    , dissect_lppa_INTEGER_0_719 },
  {   1, &hf_lppa_valueTimingAdvanceType1, ASN1_EXTENSION_ROOT    , dissect_lppa_INTEGER_0_7690 },
  {   2, &hf_lppa_valueTimingAdvanceType2, ASN1_EXTENSION_ROOT    , dissect_lppa_INTEGER_0_7690 },
  {   3, &hf_lppa_resultRSRP     , ASN1_EXTENSION_ROOT    , dissect_lppa_ResultRSRP },
  {   4, &hf_lppa_resultRSRQ     , ASN1_EXTENSION_ROOT    , dissect_lppa_ResultRSRQ },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_MeasuredResultsValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_MeasuredResultsValue, MeasuredResultsValue_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MeasuredResults_sequence_of[1] = {
  { &hf_lppa_MeasuredResults_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_MeasuredResultsValue },
};

static int
dissect_lppa_MeasuredResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_MeasuredResults, MeasuredResults_sequence_of,
                                                  1, maxNoMeas, FALSE);

  return offset;
}


static const per_sequence_t E_CID_MeasurementResult_sequence[] = {
  { &hf_lppa_servingCell_ID , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ECGI },
  { &hf_lppa_servingCellTAC , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_TAC },
  { &hf_lppa_e_UTRANAccessPointPosition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_E_UTRANAccessPointPosition },
  { &hf_lppa_measuredResults, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_MeasuredResults },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_E_CID_MeasurementResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_E_CID_MeasurementResult, E_CID_MeasurementResult_sequence);

  return offset;
}



static int
dissect_lppa_HESSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, FALSE, NULL);

  return offset;
}


static const per_sequence_t InterRATMeasurementQuantities_sequence_of[1] = {
  { &hf_lppa_InterRATMeasurementQuantities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Single_Container },
};

static int
dissect_lppa_InterRATMeasurementQuantities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_InterRATMeasurementQuantities, InterRATMeasurementQuantities_sequence_of,
                                                  0, maxNoMeas, FALSE);

  return offset;
}


static const value_string lppa_InterRATMeasurementQuantitiesValue_vals[] = {
  {   0, "geran" },
  {   1, "utran" },
  { 0, NULL }
};


static int
dissect_lppa_InterRATMeasurementQuantitiesValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t InterRATMeasurementQuantities_Item_sequence[] = {
  { &hf_lppa_interRATMeasurementQuantitiesValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_InterRATMeasurementQuantitiesValue },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_InterRATMeasurementQuantities_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_InterRATMeasurementQuantities_Item, InterRATMeasurementQuantities_Item_sequence);

  return offset;
}



static int
dissect_lppa_PhysCellIDGERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, TRUE);

  return offset;
}



static int
dissect_lppa_RSSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, TRUE);

  return offset;
}


static const per_sequence_t ResultGERAN_Item_sequence[] = {
  { &hf_lppa_bCCH           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_BCCH },
  { &hf_lppa_physCellIDGERAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PhysCellIDGERAN },
  { &hf_lppa_rSSI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_RSSI },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_ResultGERAN_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_ResultGERAN_Item, ResultGERAN_Item_sequence);

  return offset;
}


static const per_sequence_t ResultGERAN_sequence_of[1] = {
  { &hf_lppa_ResultGERAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ResultGERAN_Item },
};

static int
dissect_lppa_ResultGERAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_ResultGERAN, ResultGERAN_sequence_of,
                                                  1, maxGERANMeas, FALSE);

  return offset;
}



static int
dissect_lppa_UARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, TRUE);

  return offset;
}



static int
dissect_lppa_PhysCellIDUTRA_FDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, TRUE);

  return offset;
}



static int
dissect_lppa_PhysCellIDUTRA_TDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, TRUE);

  return offset;
}


static const value_string lppa_T_physCellIDUTRAN_vals[] = {
  {   0, "physCellIDUTRA-FDD" },
  {   1, "physCellIDUTRA-TDD" },
  { 0, NULL }
};

static const per_choice_t T_physCellIDUTRAN_choice[] = {
  {   0, &hf_lppa_physCellIDUTRA_FDD, ASN1_NO_EXTENSIONS     , dissect_lppa_PhysCellIDUTRA_FDD },
  {   1, &hf_lppa_physCellIDUTRA_TDD, ASN1_NO_EXTENSIONS     , dissect_lppa_PhysCellIDUTRA_TDD },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_T_physCellIDUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_T_physCellIDUTRAN, T_physCellIDUTRAN_choice,
                                 NULL);

  return offset;
}



static int
dissect_lppa_UTRA_RSCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -5, 91U, NULL, TRUE);

  return offset;
}



static int
dissect_lppa_UTRA_EcN0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 49U, NULL, TRUE);

  return offset;
}


static const per_sequence_t ResultUTRAN_Item_sequence[] = {
  { &hf_lppa_uARFCN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_UARFCN },
  { &hf_lppa_physCellIDUTRAN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_physCellIDUTRAN },
  { &hf_lppa_uTRA_RSCP      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_UTRA_RSCP },
  { &hf_lppa_uTRA_EcN0      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_UTRA_EcN0 },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_ResultUTRAN_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_ResultUTRAN_Item, ResultUTRAN_Item_sequence);

  return offset;
}


static const per_sequence_t ResultUTRAN_sequence_of[1] = {
  { &hf_lppa_ResultUTRAN_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ResultUTRAN_Item },
};

static int
dissect_lppa_ResultUTRAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_ResultUTRAN, ResultUTRAN_sequence_of,
                                                  1, maxUTRANMeas, FALSE);

  return offset;
}


static const value_string lppa_InterRATMeasuredResultsValue_vals[] = {
  {   0, "resultGERAN" },
  {   1, "resultUTRAN" },
  { 0, NULL }
};

static const per_choice_t InterRATMeasuredResultsValue_choice[] = {
  {   0, &hf_lppa_resultGERAN    , ASN1_EXTENSION_ROOT    , dissect_lppa_ResultGERAN },
  {   1, &hf_lppa_resultUTRAN    , ASN1_EXTENSION_ROOT    , dissect_lppa_ResultUTRAN },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_InterRATMeasuredResultsValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_InterRATMeasuredResultsValue, InterRATMeasuredResultsValue_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t InterRATMeasurementResult_sequence_of[1] = {
  { &hf_lppa_InterRATMeasurementResult_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_InterRATMeasuredResultsValue },
};

static int
dissect_lppa_InterRATMeasurementResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_InterRATMeasurementResult, InterRATMeasurementResult_sequence_of,
                                                  1, maxNoMeas, FALSE);

  return offset;
}



static int
dissect_lppa_Measurement_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, TRUE);

  return offset;
}


static const value_string lppa_MeasurementPeriodicity_vals[] = {
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
  { 0, NULL }
};


static int
dissect_lppa_MeasurementPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t MeasurementQuantities_sequence_of[1] = {
  { &hf_lppa_MeasurementQuantities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Single_Container },
};

static int
dissect_lppa_MeasurementQuantities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_MeasurementQuantities, MeasurementQuantities_sequence_of,
                                                  1, maxNoMeas, FALSE);

  return offset;
}


static const value_string lppa_MeasurementQuantitiesValue_vals[] = {
  {   0, "cell-ID" },
  {   1, "angleOfArrival" },
  {   2, "timingAdvanceType1" },
  {   3, "timingAdvanceType2" },
  {   4, "rSRP" },
  {   5, "rSRQ" },
  { 0, NULL }
};


static int
dissect_lppa_MeasurementQuantitiesValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t MeasurementQuantities_Item_sequence[] = {
  { &hf_lppa_measurementQuantitiesValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_MeasurementQuantitiesValue },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_MeasurementQuantities_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_MeasurementQuantities_Item, MeasurementQuantities_Item_sequence);

  return offset;
}


static const per_sequence_t OTDOACell_Information_sequence_of[1] = {
  { &hf_lppa_OTDOACell_Information_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_OTDOACell_Information_Item },
};

static int
dissect_lppa_OTDOACell_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_OTDOACell_Information, OTDOACell_Information_sequence_of,
                                                  1, maxnoOTDOAtypes, FALSE);

  return offset;
}


static const per_sequence_t OTDOACells_item_sequence[] = {
  { &hf_lppa_oTDOACellInfo  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_OTDOACell_Information },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_OTDOACells_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_OTDOACells_item, OTDOACells_item_sequence);

  return offset;
}


static const per_sequence_t OTDOACells_sequence_of[1] = {
  { &hf_lppa_OTDOACells_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_OTDOACells_item },
};

static int
dissect_lppa_OTDOACells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_OTDOACells, OTDOACells_sequence_of,
                                                  1, maxCellineNB, FALSE);

  return offset;
}


static const value_string lppa_OTDOA_Information_Item_vals[] = {
  {   0, "pci" },
  {   1, "cellid" },
  {   2, "tac" },
  {   3, "earfcn" },
  {   4, "prsBandwidth" },
  {   5, "prsConfigIndex" },
  {   6, "cpLength" },
  {   7, "noDlFrames" },
  {   8, "noAntennaPorts" },
  {   9, "sFNInitTime" },
  {  10, "e-UTRANAccessPointPosition" },
  {  11, "prsmutingconfiguration" },
  {  12, "prsid" },
  {  13, "tpid" },
  {  14, "tpType" },
  {  15, "crsCPlength" },
  {  16, "mBSFNsubframeConfiguration" },
  {  17, "nPRSConfiguration" },
  {  18, "offsetNBChannelNumbertoEARFCN" },
  {  19, "operationModeInfo" },
  {  20, "nPRS-ID" },
  {  21, "dlBandwidth" },
  {  22, "multipleprsConfigurationsperCell" },
  {  23, "prsOccasionGroup" },
  {  24, "prsFrequencyHoppingConfiguration" },
  {  25, "repetitionNumberofSIB1-NB" },
  {  26, "nPRSSequenceInfo" },
  {  27, "nPRSType2" },
  {  28, "tddConfig" },
  { 0, NULL }
};


static int
dissect_lppa_OTDOA_Information_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, TRUE, 19, NULL);

  return offset;
}


static const value_string lppa_ReportCharacteristics_vals[] = {
  {   0, "onDemand" },
  {   1, "periodic" },
  { 0, NULL }
};


static int
dissect_lppa_ReportCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lppa_INTEGER_0_500_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 500U, NULL, TRUE);

  return offset;
}



static int
dissect_lppa_INTEGER_1_100_(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100U, NULL, TRUE);

  return offset;
}


static const per_sequence_t RequestedSRSTransmissionCharacteristics_sequence[] = {
  { &hf_lppa_numberOfTransmissions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_500_ },
  { &hf_lppa_bandwidth      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_1_100_ },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_RequestedSRSTransmissionCharacteristics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_RequestedSRSTransmissionCharacteristics, RequestedSRSTransmissionCharacteristics_sequence);

  return offset;
}


static const value_string lppa_T_ul_bandwidth_vals[] = {
  {   0, "n6" },
  {   1, "n15" },
  {   2, "n25" },
  {   3, "n50" },
  {   4, "n75" },
  {   5, "n100" },
  { 0, NULL }
};


static int
dissect_lppa_T_ul_bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lppa_T_srs_BandwidthConfig_vals[] = {
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
dissect_lppa_T_srs_BandwidthConfig(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lppa_T_srs_Bandwidth_vals[] = {
  {   0, "bw0" },
  {   1, "bw1" },
  {   2, "bw2" },
  {   3, "bw3" },
  { 0, NULL }
};


static int
dissect_lppa_T_srs_Bandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lppa_T_srs_AntennaPort_vals[] = {
  {   0, "an1" },
  {   1, "an2" },
  {   2, "an4" },
  { 0, NULL }
};


static int
dissect_lppa_T_srs_AntennaPort(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lppa_T_srs_HoppingBandwidth_vals[] = {
  {   0, "hbw0" },
  {   1, "hbw1" },
  {   2, "hbw2" },
  {   3, "hbw3" },
  { 0, NULL }
};


static int
dissect_lppa_T_srs_HoppingBandwidth(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lppa_T_srs_cyclicShift_vals[] = {
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
dissect_lppa_T_srs_cyclicShift(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lppa_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}


static const value_string lppa_T_maxUpPts_vals[] = {
  {   0, "true" },
  { 0, NULL }
};


static int
dissect_lppa_T_maxUpPts(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lppa_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_INTEGER_0_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 23U, NULL, FALSE);

  return offset;
}



static int
dissect_lppa_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_lppa_INTEGER_0_29(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 29U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SRSConfigurationForOneCell_sequence[] = {
  { &hf_lppa_pci            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PCI },
  { &hf_lppa_ul_earfcn      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_EARFCN },
  { &hf_lppa_ul_bandwidth   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_ul_bandwidth },
  { &hf_lppa_ul_cyclicPrefixLength, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_CPLength },
  { &hf_lppa_srs_BandwidthConfig, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_srs_BandwidthConfig },
  { &hf_lppa_srs_Bandwidth  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_srs_Bandwidth },
  { &hf_lppa_srs_AntennaPort, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_srs_AntennaPort },
  { &hf_lppa_srs_HoppingBandwidth, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_srs_HoppingBandwidth },
  { &hf_lppa_srs_cyclicShift, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_T_srs_cyclicShift },
  { &hf_lppa_srs_ConfigIndex, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_1023 },
  { &hf_lppa_maxUpPts       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_T_maxUpPts },
  { &hf_lppa_transmissionComb, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_1 },
  { &hf_lppa_freqDomainPosition, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_23 },
  { &hf_lppa_groupHoppingEnabled, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_BOOLEAN },
  { &hf_lppa_deltaSS        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_INTEGER_0_29 },
  { &hf_lppa_sfnInitialisationTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_SFNInitialisationTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_SRSConfigurationForOneCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_SRSConfigurationForOneCell, SRSConfigurationForOneCell_sequence);

  return offset;
}


static const per_sequence_t SRSConfigurationForAllCells_sequence_of[1] = {
  { &hf_lppa_SRSConfigurationForAllCells_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_SRSConfigurationForOneCell },
};

static int
dissect_lppa_SRSConfigurationForAllCells(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_SRSConfigurationForAllCells, SRSConfigurationForAllCells_sequence_of,
                                                  1, maxServCell, FALSE);

  return offset;
}



static int
dissect_lppa_SSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 32, FALSE, NULL);

  return offset;
}


static const per_sequence_t ULConfiguration_sequence[] = {
  { &hf_lppa_pci            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PCI },
  { &hf_lppa_ul_earfcn      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_EARFCN },
  { &hf_lppa_timingAdvanceType1, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_INTEGER_0_7690 },
  { &hf_lppa_timingAdvanceType2, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_INTEGER_0_7690 },
  { &hf_lppa_numberOfTransmissions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_INTEGER_0_500_ },
  { &hf_lppa_srsConfiguration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_SRSConfigurationForAllCells },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_ULConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_ULConfiguration, ULConfiguration_sequence);

  return offset;
}


static const per_sequence_t WLANMeasurementQuantities_sequence_of[1] = {
  { &hf_lppa_WLANMeasurementQuantities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Single_Container },
};

static int
dissect_lppa_WLANMeasurementQuantities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_WLANMeasurementQuantities, WLANMeasurementQuantities_sequence_of,
                                                  0, maxNoMeas, FALSE);

  return offset;
}


static const value_string lppa_WLANMeasurementQuantitiesValue_vals[] = {
  {   0, "wlan" },
  { 0, NULL }
};


static int
dissect_lppa_WLANMeasurementQuantitiesValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t WLANMeasurementQuantities_Item_sequence[] = {
  { &hf_lppa_wLANMeasurementQuantitiesValue, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_WLANMeasurementQuantitiesValue },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_WLANMeasurementQuantities_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_WLANMeasurementQuantities_Item, WLANMeasurementQuantities_Item_sequence);

  return offset;
}



static int
dissect_lppa_WLAN_RSSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 141U, NULL, TRUE);

  return offset;
}



static int
dissect_lppa_WLANOperatingClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string lppa_WLANCountryCode_vals[] = {
  {   0, "unitedStates" },
  {   1, "europe" },
  {   2, "japan" },
  {   3, "global" },
  { 0, NULL }
};


static int
dissect_lppa_WLANCountryCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lppa_WLANChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t WLANChannelList_sequence_of[1] = {
  { &hf_lppa_WLANChannelList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_WLANChannel },
};

static int
dissect_lppa_WLANChannelList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_WLANChannelList, WLANChannelList_sequence_of,
                                                  1, maxWLANchannels, FALSE);

  return offset;
}


static const value_string lppa_WLANBand_vals[] = {
  {   0, "band2dot4" },
  {   1, "band5" },
  { 0, NULL }
};


static int
dissect_lppa_WLANBand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t WLANMeasurementResult_Item_sequence[] = {
  { &hf_lppa_wLAN_RSSI      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_WLAN_RSSI },
  { &hf_lppa_sSID           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_SSID },
  { &hf_lppa_bSSID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_BSSID },
  { &hf_lppa_hESSID         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_HESSID },
  { &hf_lppa_operatingClass , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_WLANOperatingClass },
  { &hf_lppa_countryCode    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_WLANCountryCode },
  { &hf_lppa_wLANChannelList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_WLANChannelList },
  { &hf_lppa_wLANBand       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_WLANBand },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_WLANMeasurementResult_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_WLANMeasurementResult_Item, WLANMeasurementResult_Item_sequence);

  return offset;
}


static const per_sequence_t WLANMeasurementResult_sequence_of[1] = {
  { &hf_lppa_WLANMeasurementResult_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_WLANMeasurementResult_Item },
};

static int
dissect_lppa_WLANMeasurementResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_WLANMeasurementResult, WLANMeasurementResult_sequence_of,
                                                  1, maxNoMeas, FALSE);

  return offset;
}


static const per_sequence_t E_CIDMeasurementInitiationRequest_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_E_CIDMeasurementInitiationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_E_CIDMeasurementInitiationRequest, E_CIDMeasurementInitiationRequest_sequence);

  return offset;
}


static const per_sequence_t E_CIDMeasurementInitiationResponse_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_E_CIDMeasurementInitiationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_E_CIDMeasurementInitiationResponse, E_CIDMeasurementInitiationResponse_sequence);

  return offset;
}


static const per_sequence_t E_CIDMeasurementInitiationFailure_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_E_CIDMeasurementInitiationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_E_CIDMeasurementInitiationFailure, E_CIDMeasurementInitiationFailure_sequence);

  return offset;
}


static const per_sequence_t E_CIDMeasurementFailureIndication_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_E_CIDMeasurementFailureIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_E_CIDMeasurementFailureIndication, E_CIDMeasurementFailureIndication_sequence);

  return offset;
}


static const per_sequence_t E_CIDMeasurementReport_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_E_CIDMeasurementReport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_E_CIDMeasurementReport, E_CIDMeasurementReport_sequence);

  return offset;
}


static const per_sequence_t E_CIDMeasurementTerminationCommand_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_E_CIDMeasurementTerminationCommand(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_E_CIDMeasurementTerminationCommand, E_CIDMeasurementTerminationCommand_sequence);

  return offset;
}


static const per_sequence_t OTDOAInformationRequest_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_OTDOAInformationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_OTDOAInformationRequest, OTDOAInformationRequest_sequence);

  return offset;
}


static const per_sequence_t OTDOA_Information_Type_sequence_of[1] = {
  { &hf_lppa_OTDOA_Information_Type_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Single_Container },
};

static int
dissect_lppa_OTDOA_Information_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lppa_OTDOA_Information_Type, OTDOA_Information_Type_sequence_of,
                                                  1, maxnoOTDOAtypes, FALSE);

  return offset;
}


static const per_sequence_t OTDOA_Information_Type_Item_sequence[] = {
  { &hf_lppa_oTDOA_Information_Type_Item, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_OTDOA_Information_Item },
  { &hf_lppa_iE_Extensions  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lppa_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_OTDOA_Information_Type_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_OTDOA_Information_Type_Item, OTDOA_Information_Type_Item_sequence);

  return offset;
}


static const per_sequence_t OTDOAInformationResponse_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_OTDOAInformationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_OTDOAInformationResponse, OTDOAInformationResponse_sequence);

  return offset;
}


static const per_sequence_t OTDOAInformationFailure_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_OTDOAInformationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_OTDOAInformationFailure, OTDOAInformationFailure_sequence);

  return offset;
}


static const per_sequence_t UTDOAInformationRequest_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_UTDOAInformationRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_UTDOAInformationRequest, UTDOAInformationRequest_sequence);

  return offset;
}


static const per_sequence_t UTDOAInformationResponse_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_UTDOAInformationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_UTDOAInformationResponse, UTDOAInformationResponse_sequence);

  return offset;
}


static const per_sequence_t UTDOAInformationFailure_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_UTDOAInformationFailure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_UTDOAInformationFailure, UTDOAInformationFailure_sequence);

  return offset;
}


static const per_sequence_t UTDOAInformationUpdate_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_UTDOAInformationUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_UTDOAInformationUpdate, UTDOAInformationUpdate_sequence);

  return offset;
}


static const per_sequence_t AssistanceInformationControl_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_AssistanceInformationControl(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_AssistanceInformationControl, AssistanceInformationControl_sequence);

  return offset;
}


static const per_sequence_t AssistanceInformationFeedback_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_AssistanceInformationFeedback(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_AssistanceInformationFeedback, AssistanceInformationFeedback_sequence);

  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_lppa_protocolIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_ProtocolIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_ErrorIndication, ErrorIndication_sequence);

  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_lppa_privateIEs     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lppa_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_lppa_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lppa_PrivateMessage, PrivateMessage_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_LPPA_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_LPPA_PDU(tvb, offset, &asn1_ctx, tree, hf_lppa_LPPA_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Add_OTDOACells_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_Add_OTDOACells(tvb, offset, &asn1_ctx, tree, hf_lppa_Add_OTDOACells_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Assistance_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_Assistance_Information(tvb, offset, &asn1_ctx, tree, hf_lppa_Assistance_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AssistanceInformationFailureList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_AssistanceInformationFailureList(tvb, offset, &asn1_ctx, tree, hf_lppa_AssistanceInformationFailureList_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Broadcast_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_Broadcast(tvb, offset, &asn1_ctx, tree, hf_lppa_Broadcast_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_Cause(tvb, offset, &asn1_ctx, tree, hf_lppa_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cell_Portion_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_Cell_Portion_ID(tvb, offset, &asn1_ctx, tree, hf_lppa_Cell_Portion_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_lppa_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CID_MeasurementResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_E_CID_MeasurementResult(tvb, offset, &asn1_ctx, tree, hf_lppa_E_CID_MeasurementResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InterRATMeasurementQuantities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_InterRATMeasurementQuantities(tvb, offset, &asn1_ctx, tree, hf_lppa_InterRATMeasurementQuantities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InterRATMeasurementQuantities_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_InterRATMeasurementQuantities_Item(tvb, offset, &asn1_ctx, tree, hf_lppa_InterRATMeasurementQuantities_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_InterRATMeasurementResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_InterRATMeasurementResult(tvb, offset, &asn1_ctx, tree, hf_lppa_InterRATMeasurementResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Measurement_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_Measurement_ID(tvb, offset, &asn1_ctx, tree, hf_lppa_Measurement_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementPeriodicity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_MeasurementPeriodicity(tvb, offset, &asn1_ctx, tree, hf_lppa_MeasurementPeriodicity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementQuantities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_MeasurementQuantities(tvb, offset, &asn1_ctx, tree, hf_lppa_MeasurementQuantities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementQuantities_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_MeasurementQuantities_Item(tvb, offset, &asn1_ctx, tree, hf_lppa_MeasurementQuantities_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOACells_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_OTDOACells(tvb, offset, &asn1_ctx, tree, hf_lppa_OTDOACells_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_ReportCharacteristics(tvb, offset, &asn1_ctx, tree, hf_lppa_ReportCharacteristics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RequestedSRSTransmissionCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_RequestedSRSTransmissionCharacteristics(tvb, offset, &asn1_ctx, tree, hf_lppa_RequestedSRSTransmissionCharacteristics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ULConfiguration_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_ULConfiguration(tvb, offset, &asn1_ctx, tree, hf_lppa_ULConfiguration_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WLANMeasurementQuantities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_WLANMeasurementQuantities(tvb, offset, &asn1_ctx, tree, hf_lppa_WLANMeasurementQuantities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WLANMeasurementQuantities_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_WLANMeasurementQuantities_Item(tvb, offset, &asn1_ctx, tree, hf_lppa_WLANMeasurementQuantities_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WLANMeasurementResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_WLANMeasurementResult(tvb, offset, &asn1_ctx, tree, hf_lppa_WLANMeasurementResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementInitiationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_E_CIDMeasurementInitiationRequest(tvb, offset, &asn1_ctx, tree, hf_lppa_E_CIDMeasurementInitiationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementInitiationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_E_CIDMeasurementInitiationResponse(tvb, offset, &asn1_ctx, tree, hf_lppa_E_CIDMeasurementInitiationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementInitiationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_E_CIDMeasurementInitiationFailure(tvb, offset, &asn1_ctx, tree, hf_lppa_E_CIDMeasurementInitiationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_E_CIDMeasurementFailureIndication(tvb, offset, &asn1_ctx, tree, hf_lppa_E_CIDMeasurementFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_E_CIDMeasurementReport(tvb, offset, &asn1_ctx, tree, hf_lppa_E_CIDMeasurementReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementTerminationCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_E_CIDMeasurementTerminationCommand(tvb, offset, &asn1_ctx, tree, hf_lppa_E_CIDMeasurementTerminationCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOAInformationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_OTDOAInformationRequest(tvb, offset, &asn1_ctx, tree, hf_lppa_OTDOAInformationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOA_Information_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_OTDOA_Information_Type(tvb, offset, &asn1_ctx, tree, hf_lppa_OTDOA_Information_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOA_Information_Type_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_OTDOA_Information_Type_Item(tvb, offset, &asn1_ctx, tree, hf_lppa_OTDOA_Information_Type_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOAInformationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_OTDOAInformationResponse(tvb, offset, &asn1_ctx, tree, hf_lppa_OTDOAInformationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOAInformationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_OTDOAInformationFailure(tvb, offset, &asn1_ctx, tree, hf_lppa_OTDOAInformationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UTDOAInformationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_UTDOAInformationRequest(tvb, offset, &asn1_ctx, tree, hf_lppa_UTDOAInformationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UTDOAInformationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_UTDOAInformationResponse(tvb, offset, &asn1_ctx, tree, hf_lppa_UTDOAInformationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UTDOAInformationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_UTDOAInformationFailure(tvb, offset, &asn1_ctx, tree, hf_lppa_UTDOAInformationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UTDOAInformationUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_UTDOAInformationUpdate(tvb, offset, &asn1_ctx, tree, hf_lppa_UTDOAInformationUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AssistanceInformationControl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_AssistanceInformationControl(tvb, offset, &asn1_ctx, tree, hf_lppa_AssistanceInformationControl_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_AssistanceInformationFeedback_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_AssistanceInformationFeedback(tvb, offset, &asn1_ctx, tree, hf_lppa_AssistanceInformationFeedback_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_lppa_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_lppa_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-lppa-fn.c ---*/
#line 79 "./asn1/lppa/packet-lppa-template.c"


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    lppa_ctx_t lppa_ctx;
    struct lppa_private_data* lppa_data = lppa_get_private_data(pinfo);

    lppa_ctx.message_type = lppa_data->message_type;
    lppa_ctx.ProcedureCode = lppa_data->procedure_code;
    lppa_ctx.ProtocolIE_ID = lppa_data->protocol_ie_id;
    lppa_ctx.ProtocolExtensionID = lppa_data->protocol_extension_id;

  return (dissector_try_uint_new(lppa_ies_dissector_table, lppa_ctx.ProtocolIE_ID, tvb, pinfo, tree, FALSE, &lppa_ctx)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct lppa_private_data* lppa_data = lppa_get_private_data(pinfo);
    return (dissector_try_uint_new(lppa_proc_imsg_dissector_table, lppa_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct lppa_private_data* lppa_data = lppa_get_private_data(pinfo);
    return (dissector_try_uint_new(lppa_proc_sout_dissector_table, lppa_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    struct lppa_private_data* lppa_data = lppa_get_private_data(pinfo);

    return (dissector_try_uint_new(lppa_proc_uout_dissector_table, lppa_data->procedure_code, tvb, pinfo, tree, FALSE, data)) ? tvb_captured_length(tvb) : 0;
}

/*--- proto_register_lppa -------------------------------------------*/
void proto_register_lppa(void) {

    /* List of fields */
    static hf_register_info hf[] = {


/*--- Included file: packet-lppa-hfarr.c ---*/
#line 1 "./asn1/lppa/packet-lppa-hfarr.c"
    { &hf_lppa_LPPA_PDU_PDU,
      { "LPPA-PDU", "lppa.LPPA_PDU",
        FT_UINT32, BASE_DEC, VALS(lppa_LPPA_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_Add_OTDOACells_PDU,
      { "Add-OTDOACells", "lppa.Add_OTDOACells",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_Assistance_Information_PDU,
      { "Assistance-Information", "lppa.Assistance_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_AssistanceInformationFailureList_PDU,
      { "AssistanceInformationFailureList", "lppa.AssistanceInformationFailureList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_Broadcast_PDU,
      { "Broadcast", "lppa.Broadcast",
        FT_UINT32, BASE_DEC, VALS(lppa_Broadcast_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_Cause_PDU,
      { "Cause", "lppa.Cause",
        FT_UINT32, BASE_DEC, VALS(lppa_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_Cell_Portion_ID_PDU,
      { "Cell-Portion-ID", "lppa.Cell_Portion_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "lppa.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_E_CID_MeasurementResult_PDU,
      { "E-CID-MeasurementResult", "lppa.E_CID_MeasurementResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_InterRATMeasurementQuantities_PDU,
      { "InterRATMeasurementQuantities", "lppa.InterRATMeasurementQuantities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_InterRATMeasurementQuantities_Item_PDU,
      { "InterRATMeasurementQuantities-Item", "lppa.InterRATMeasurementQuantities_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_InterRATMeasurementResult_PDU,
      { "InterRATMeasurementResult", "lppa.InterRATMeasurementResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_Measurement_ID_PDU,
      { "Measurement-ID", "lppa.Measurement_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_MeasurementPeriodicity_PDU,
      { "MeasurementPeriodicity", "lppa.MeasurementPeriodicity",
        FT_UINT32, BASE_DEC, VALS(lppa_MeasurementPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_MeasurementQuantities_PDU,
      { "MeasurementQuantities", "lppa.MeasurementQuantities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_MeasurementQuantities_Item_PDU,
      { "MeasurementQuantities-Item", "lppa.MeasurementQuantities_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_OTDOACells_PDU,
      { "OTDOACells", "lppa.OTDOACells",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_ReportCharacteristics_PDU,
      { "ReportCharacteristics", "lppa.ReportCharacteristics",
        FT_UINT32, BASE_DEC, VALS(lppa_ReportCharacteristics_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_RequestedSRSTransmissionCharacteristics_PDU,
      { "RequestedSRSTransmissionCharacteristics", "lppa.RequestedSRSTransmissionCharacteristics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_ULConfiguration_PDU,
      { "ULConfiguration", "lppa.ULConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_WLANMeasurementQuantities_PDU,
      { "WLANMeasurementQuantities", "lppa.WLANMeasurementQuantities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_WLANMeasurementQuantities_Item_PDU,
      { "WLANMeasurementQuantities-Item", "lppa.WLANMeasurementQuantities_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_WLANMeasurementResult_PDU,
      { "WLANMeasurementResult", "lppa.WLANMeasurementResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_E_CIDMeasurementInitiationRequest_PDU,
      { "E-CIDMeasurementInitiationRequest", "lppa.E_CIDMeasurementInitiationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_E_CIDMeasurementInitiationResponse_PDU,
      { "E-CIDMeasurementInitiationResponse", "lppa.E_CIDMeasurementInitiationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_E_CIDMeasurementInitiationFailure_PDU,
      { "E-CIDMeasurementInitiationFailure", "lppa.E_CIDMeasurementInitiationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_E_CIDMeasurementFailureIndication_PDU,
      { "E-CIDMeasurementFailureIndication", "lppa.E_CIDMeasurementFailureIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_E_CIDMeasurementReport_PDU,
      { "E-CIDMeasurementReport", "lppa.E_CIDMeasurementReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_E_CIDMeasurementTerminationCommand_PDU,
      { "E-CIDMeasurementTerminationCommand", "lppa.E_CIDMeasurementTerminationCommand_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_OTDOAInformationRequest_PDU,
      { "OTDOAInformationRequest", "lppa.OTDOAInformationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_OTDOA_Information_Type_PDU,
      { "OTDOA-Information-Type", "lppa.OTDOA_Information_Type",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_OTDOA_Information_Type_Item_PDU,
      { "OTDOA-Information-Type-Item", "lppa.OTDOA_Information_Type_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_OTDOAInformationResponse_PDU,
      { "OTDOAInformationResponse", "lppa.OTDOAInformationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_OTDOAInformationFailure_PDU,
      { "OTDOAInformationFailure", "lppa.OTDOAInformationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_UTDOAInformationRequest_PDU,
      { "UTDOAInformationRequest", "lppa.UTDOAInformationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_UTDOAInformationResponse_PDU,
      { "UTDOAInformationResponse", "lppa.UTDOAInformationResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_UTDOAInformationFailure_PDU,
      { "UTDOAInformationFailure", "lppa.UTDOAInformationFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_UTDOAInformationUpdate_PDU,
      { "UTDOAInformationUpdate", "lppa.UTDOAInformationUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_AssistanceInformationControl_PDU,
      { "AssistanceInformationControl", "lppa.AssistanceInformationControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_AssistanceInformationFeedback_PDU,
      { "AssistanceInformationFeedback", "lppa.AssistanceInformationFeedback_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_ErrorIndication_PDU,
      { "ErrorIndication", "lppa.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_PrivateMessage_PDU,
      { "PrivateMessage", "lppa.PrivateMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_local,
      { "local", "lppa.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxPrivateIEs", HFILL }},
    { &hf_lppa_global,
      { "global", "lppa.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_lppa_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "lppa.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_id,
      { "id", "lppa.id",
        FT_UINT32, BASE_DEC, VALS(lppa_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_lppa_criticality,
      { "criticality", "lppa.criticality",
        FT_UINT32, BASE_DEC, VALS(lppa_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_ie_field_value,
      { "value", "lppa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_lppa_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "lppa.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_extensionValue,
      { "extensionValue", "lppa.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_PrivateIE_Container_item,
      { "PrivateIE-Field", "lppa.PrivateIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_id_01,
      { "id", "lppa.id",
        FT_UINT32, BASE_DEC, VALS(lppa_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_lppa_value,
      { "value", "lppa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_initiatingMessage,
      { "initiatingMessage", "lppa.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_successfulOutcome,
      { "successfulOutcome", "lppa.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "lppa.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_procedureCode,
      { "procedureCode", "lppa.procedureCode",
        FT_UINT32, BASE_DEC, VALS(lppa_ProcedureCode_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_lppatransactionID,
      { "lppatransactionID", "lppa.lppatransactionID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_initiatingMessagevalue,
      { "value", "lppa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_lppa_successfulOutcome_value,
      { "value", "lppa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_lppa_unsuccessfulOutcome_value,
      { "value", "lppa.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
    { &hf_lppa_Add_OTDOACells_item,
      { "Add-OTDOACells item", "lppa.Add_OTDOACells_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_add_OTDOACellInfo,
      { "add-OTDOACellInfo", "lppa.add_OTDOACellInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Add_OTDOACell_Information", HFILL }},
    { &hf_lppa_iE_Extensions,
      { "iE-Extensions", "lppa.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_lppa_Add_OTDOACell_Information_item,
      { "OTDOACell-Information-Item", "lppa.OTDOACell_Information_Item",
        FT_UINT32, BASE_DEC, VALS(lppa_OTDOACell_Information_Item_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_systemInformation,
      { "systemInformation", "lppa.systemInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_AssistanceInformationFailureList_item,
      { "AssistanceInformationFailureList item", "lppa.AssistanceInformationFailureList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_posSIB_Type,
      { "posSIB-Type", "lppa.posSIB_Type",
        FT_UINT32, BASE_DEC, VALS(lppa_PosSIB_Type_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_outcome,
      { "outcome", "lppa.outcome",
        FT_UINT32, BASE_DEC, VALS(lppa_Outcome_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_encrypted,
      { "encrypted", "lppa.encrypted",
        FT_UINT32, BASE_DEC, VALS(lppa_T_encrypted_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_gNSSID,
      { "gNSSID", "lppa.gNSSID",
        FT_UINT32, BASE_DEC, VALS(lppa_T_gNSSID_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_sBASID,
      { "sBASID", "lppa.sBASID",
        FT_UINT32, BASE_DEC, VALS(lppa_T_sBASID_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_ten,
      { "ten", "lppa.ten",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_10", HFILL }},
    { &hf_lppa_forty,
      { "forty", "lppa.forty",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_40", HFILL }},
    { &hf_lppa_ten_tdd,
      { "ten-tdd", "lppa.ten_tdd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_lppa_forty_tdd,
      { "forty-tdd", "lppa.forty_tdd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_lppa_radioNetwork,
      { "radioNetwork", "lppa.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(lppa_CauseRadioNetwork_vals), 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_lppa_protocol,
      { "protocol", "lppa.protocol",
        FT_UINT32, BASE_DEC, VALS(lppa_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_lppa_misc,
      { "misc", "lppa.misc",
        FT_UINT32, BASE_DEC, VALS(lppa_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_lppa_triggeringMessage,
      { "triggeringMessage", "lppa.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(lppa_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_procedureCriticality,
      { "procedureCriticality", "lppa.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(lppa_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_lppa_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "lppa.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_lppa_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "lppa.CriticalityDiagnostics_IE_List_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_iECriticality,
      { "iECriticality", "lppa.iECriticality",
        FT_UINT32, BASE_DEC, VALS(lppa_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_lppa_iE_ID,
      { "iE-ID", "lppa.iE_ID",
        FT_UINT32, BASE_DEC, VALS(lppa_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_lppa_typeOfError,
      { "typeOfError", "lppa.typeOfError",
        FT_UINT32, BASE_DEC, VALS(lppa_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_servingCell_ID,
      { "servingCell-ID", "lppa.servingCell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_lppa_servingCellTAC,
      { "servingCellTAC", "lppa.servingCellTAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TAC", HFILL }},
    { &hf_lppa_e_UTRANAccessPointPosition,
      { "e-UTRANAccessPointPosition", "lppa.e_UTRANAccessPointPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_measuredResults,
      { "measuredResults", "lppa.measuredResults",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_pLMN_Identity,
      { "pLMN-Identity", "lppa.pLMN_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_eUTRANcellIdentifier,
      { "eUTRANcellIdentifier", "lppa.eUTRANcellIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_latitudeSign,
      { "latitudeSign", "lppa.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(lppa_T_latitudeSign_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_latitude,
      { "latitude", "lppa.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_lppa_longitude,
      { "longitude", "lppa.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_lppa_directionOfAltitude,
      { "directionOfAltitude", "lppa.directionOfAltitude",
        FT_UINT32, BASE_DEC, VALS(lppa_T_directionOfAltitude_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_altitude,
      { "altitude", "lppa.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_lppa_uncertaintySemi_major,
      { "uncertaintySemi-major", "lppa.uncertaintySemi_major",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_lppa_uncertaintySemi_minor,
      { "uncertaintySemi-minor", "lppa.uncertaintySemi_minor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_lppa_orientationOfMajorAxis,
      { "orientationOfMajorAxis", "lppa.orientationOfMajorAxis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_lppa_uncertaintyAltitude,
      { "uncertaintyAltitude", "lppa.uncertaintyAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_lppa_confidence,
      { "confidence", "lppa.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_lppa_InterRATMeasurementQuantities_item,
      { "ProtocolIE-Single-Container", "lppa.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_interRATMeasurementQuantitiesValue,
      { "interRATMeasurementQuantitiesValue", "lppa.interRATMeasurementQuantitiesValue",
        FT_UINT32, BASE_DEC, VALS(lppa_InterRATMeasurementQuantitiesValue_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_InterRATMeasurementResult_item,
      { "InterRATMeasuredResultsValue", "lppa.InterRATMeasuredResultsValue",
        FT_UINT32, BASE_DEC, VALS(lppa_InterRATMeasuredResultsValue_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_resultGERAN,
      { "resultGERAN", "lppa.resultGERAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_resultUTRAN,
      { "resultUTRAN", "lppa.resultUTRAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_MeasurementQuantities_item,
      { "ProtocolIE-Single-Container", "lppa.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_measurementQuantitiesValue,
      { "measurementQuantitiesValue", "lppa.measurementQuantitiesValue",
        FT_UINT32, BASE_DEC, VALS(lppa_MeasurementQuantitiesValue_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_MeasuredResults_item,
      { "MeasuredResultsValue", "lppa.MeasuredResultsValue",
        FT_UINT32, BASE_DEC, VALS(lppa_MeasuredResultsValue_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_valueAngleOfArrival,
      { "valueAngleOfArrival", "lppa.valueAngleOfArrival",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_719", HFILL }},
    { &hf_lppa_valueTimingAdvanceType1,
      { "valueTimingAdvanceType1", "lppa.valueTimingAdvanceType1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7690", HFILL }},
    { &hf_lppa_valueTimingAdvanceType2,
      { "valueTimingAdvanceType2", "lppa.valueTimingAdvanceType2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7690", HFILL }},
    { &hf_lppa_resultRSRP,
      { "resultRSRP", "lppa.resultRSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_resultRSRQ,
      { "resultRSRQ", "lppa.resultRSRQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_MBSFNsubframeConfiguration_item,
      { "MBSFNsubframeConfigurationValue", "lppa.MBSFNsubframeConfigurationValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_radioframeAllocationPeriod,
      { "radioframeAllocationPeriod", "lppa.radioframeAllocationPeriod",
        FT_UINT32, BASE_DEC, VALS(lppa_T_radioframeAllocationPeriod_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_radioframeAllocationOffset,
      { "radioframeAllocationOffset", "lppa.radioframeAllocationOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_lppa_subframeAllocation,
      { "subframeAllocation", "lppa.subframeAllocation",
        FT_UINT32, BASE_DEC, VALS(lppa_Subframeallocation_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_nPRSSubframePartA,
      { "nPRSSubframePartA", "lppa.nPRSSubframePartA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_nPRSSubframePartB,
      { "nPRSSubframePartB", "lppa.nPRSSubframePartB_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_two,
      { "two", "lppa.two",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_lppa_four,
      { "four", "lppa.four",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_lppa_eight,
      { "eight", "lppa.eight",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_lppa_sixteen,
      { "sixteen", "lppa.sixteen",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_lppa_bitmapsforNPRS,
      { "bitmapsforNPRS", "lppa.bitmapsforNPRS",
        FT_UINT32, BASE_DEC, VALS(lppa_BitmapsforNPRS_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_nPRSMutingConfiguration,
      { "nPRSMutingConfiguration", "lppa.nPRSMutingConfiguration",
        FT_UINT32, BASE_DEC, VALS(lppa_NPRSMutingConfiguration_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_numberofNPRSOneOccasion,
      { "numberofNPRSOneOccasion", "lppa.numberofNPRSOneOccasion",
        FT_UINT32, BASE_DEC, VALS(lppa_T_numberofNPRSOneOccasion_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_periodicityofNPRS,
      { "periodicityofNPRS", "lppa.periodicityofNPRS",
        FT_UINT32, BASE_DEC, VALS(lppa_T_periodicityofNPRS_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_startingsubframeoffset,
      { "startingsubframeoffset", "lppa.startingsubframeoffset",
        FT_UINT32, BASE_DEC, VALS(lppa_T_startingsubframeoffset_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_sIB1_NB_Subframe_TDD,
      { "sIB1-NB-Subframe-TDD", "lppa.sIB1_NB_Subframe_TDD",
        FT_UINT32, BASE_DEC, VALS(lppa_T_sIB1_NB_Subframe_TDD_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_OTDOACells_item,
      { "OTDOACells item", "lppa.OTDOACells_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_oTDOACellInfo,
      { "oTDOACellInfo", "lppa.oTDOACellInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OTDOACell_Information", HFILL }},
    { &hf_lppa_OTDOACell_Information_item,
      { "OTDOACell-Information-Item", "lppa.OTDOACell_Information_Item",
        FT_UINT32, BASE_DEC, VALS(lppa_OTDOACell_Information_Item_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_pCI,
      { "pCI", "lppa.pCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_cellId,
      { "cellId", "lppa.cellId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ECGI", HFILL }},
    { &hf_lppa_tAC,
      { "tAC", "lppa.tAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_eARFCN,
      { "eARFCN", "lppa.eARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_pRS_Bandwidth,
      { "pRS-Bandwidth", "lppa.pRS_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(lppa_PRS_Bandwidth_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_pRS_ConfigurationIndex,
      { "pRS-ConfigurationIndex", "lppa.pRS_ConfigurationIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_Configuration_Index", HFILL }},
    { &hf_lppa_cPLength,
      { "cPLength", "lppa.cPLength",
        FT_UINT32, BASE_DEC, VALS(lppa_CPLength_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_numberOfDlFrames,
      { "numberOfDlFrames", "lppa.numberOfDlFrames",
        FT_UINT32, BASE_DEC, VALS(lppa_NumberOfDlFrames_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_numberOfAntennaPorts,
      { "numberOfAntennaPorts", "lppa.numberOfAntennaPorts",
        FT_UINT32, BASE_DEC, VALS(lppa_NumberOfAntennaPorts_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_sFNInitialisationTime,
      { "sFNInitialisationTime", "lppa.sFNInitialisationTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_pRSMutingConfiguration,
      { "pRSMutingConfiguration", "lppa.pRSMutingConfiguration",
        FT_UINT32, BASE_DEC, VALS(lppa_PRSMutingConfiguration_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_prsid,
      { "prsid", "lppa.prsid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PRS_ID", HFILL }},
    { &hf_lppa_tpid,
      { "tpid", "lppa.tpid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TP_ID", HFILL }},
    { &hf_lppa_tpType,
      { "tpType", "lppa.tpType",
        FT_UINT32, BASE_DEC, VALS(lppa_TP_Type_vals), 0,
        "TP_Type", HFILL }},
    { &hf_lppa_numberOfDlFrames_Extended,
      { "numberOfDlFrames-Extended", "lppa.numberOfDlFrames_Extended",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_crsCPlength,
      { "crsCPlength", "lppa.crsCPlength",
        FT_UINT32, BASE_DEC, VALS(lppa_CPLength_vals), 0,
        "CPLength", HFILL }},
    { &hf_lppa_mBSFNsubframeConfiguration,
      { "mBSFNsubframeConfiguration", "lppa.mBSFNsubframeConfiguration",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_nPRSConfiguration,
      { "nPRSConfiguration", "lppa.nPRSConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_offsetNBChanneltoEARFCN,
      { "offsetNBChanneltoEARFCN", "lppa.offsetNBChanneltoEARFCN",
        FT_UINT32, BASE_DEC, VALS(lppa_OffsetNBChanneltoEARFCN_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_operationModeInfo,
      { "operationModeInfo", "lppa.operationModeInfo",
        FT_UINT32, BASE_DEC, VALS(lppa_OperationModeInfo_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_nPRS_ID,
      { "nPRS-ID", "lppa.nPRS_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095_", HFILL }},
    { &hf_lppa_dL_Bandwidth,
      { "dL-Bandwidth", "lppa.dL_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(lppa_DL_Bandwidth_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_pRSOccasionGroup,
      { "pRSOccasionGroup", "lppa.pRSOccasionGroup",
        FT_UINT32, BASE_DEC, VALS(lppa_PRSOccasionGroup_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_pRSFreqHoppingConfig,
      { "pRSFreqHoppingConfig", "lppa.pRSFreqHoppingConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PRSFrequencyHoppingConfiguration", HFILL }},
    { &hf_lppa_repetitionNumberofSIB1_NB,
      { "repetitionNumberofSIB1-NB", "lppa.repetitionNumberofSIB1_NB",
        FT_UINT32, BASE_DEC, VALS(lppa_RepetitionNumberofSIB1_NB_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_nPRSSequenceInfo,
      { "nPRSSequenceInfo", "lppa.nPRSSequenceInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_nPRSType2,
      { "nPRSType2", "lppa.nPRSType2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NPRSConfiguration", HFILL }},
    { &hf_lppa_tddConfiguration,
      { "tddConfiguration", "lppa.tddConfiguration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_PosSIBs_item,
      { "PosSIBs item", "lppa.PosSIBs_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_posSIB_Segments,
      { "posSIB-Segments", "lppa.posSIB_Segments",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_assistanceInformationMetaData,
      { "assistanceInformationMetaData", "lppa.assistanceInformationMetaData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_broadcastPriority,
      { "broadcastPriority", "lppa.broadcastPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16_", HFILL }},
    { &hf_lppa_PosSIB_Segments_item,
      { "PosSIB-Segments item", "lppa.PosSIB_Segments_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_assistanceDataSIBelement,
      { "assistanceDataSIBelement", "lppa.assistanceDataSIBelement",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_lppa_thirty_two,
      { "thirty-two", "lppa.thirty_two",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_lppa_sixty_four,
      { "sixty-four", "lppa.sixty_four",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_64", HFILL }},
    { &hf_lppa_one_hundred_and_twenty_eight,
      { "one-hundred-and-twenty-eight", "lppa.one_hundred_and_twenty_eight",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_128", HFILL }},
    { &hf_lppa_two_hundred_and_fifty_six,
      { "two-hundred-and-fifty-six", "lppa.two_hundred_and_fifty_six",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_256", HFILL }},
    { &hf_lppa_five_hundred_and_twelve,
      { "five-hundred-and-twelve", "lppa.five_hundred_and_twelve",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_512", HFILL }},
    { &hf_lppa_one_thousand_and_twenty_four,
      { "one-thousand-and-twenty-four", "lppa.one_thousand_and_twenty_four",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1024", HFILL }},
    { &hf_lppa_noOfFreqHoppingBands,
      { "noOfFreqHoppingBands", "lppa.noOfFreqHoppingBands",
        FT_UINT32, BASE_DEC, VALS(lppa_NumberOfFrequencyHoppingBands_vals), 0,
        "NumberOfFrequencyHoppingBands", HFILL }},
    { &hf_lppa_bandPositions,
      { "bandPositions", "lppa.bandPositions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex", HFILL }},
    { &hf_lppa_bandPositions_item,
      { "NarrowBandIndex", "lppa.NarrowBandIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_numberOfTransmissions,
      { "numberOfTransmissions", "lppa.numberOfTransmissions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_500_", HFILL }},
    { &hf_lppa_bandwidth,
      { "bandwidth", "lppa.bandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_100_", HFILL }},
    { &hf_lppa_ResultRSRP_item,
      { "ResultRSRP-Item", "lppa.ResultRSRP_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_eCGI,
      { "eCGI", "lppa.eCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_valueRSRP,
      { "valueRSRP", "lppa.valueRSRP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_ResultRSRQ_item,
      { "ResultRSRQ-Item", "lppa.ResultRSRQ_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_valueRSRQ,
      { "valueRSRQ", "lppa.valueRSRQ",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_ResultGERAN_item,
      { "ResultGERAN-Item", "lppa.ResultGERAN_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_bCCH,
      { "bCCH", "lppa.bCCH",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_physCellIDGERAN,
      { "physCellIDGERAN", "lppa.physCellIDGERAN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_rSSI,
      { "rSSI", "lppa.rSSI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_ResultUTRAN_item,
      { "ResultUTRAN-Item", "lppa.ResultUTRAN_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_uARFCN,
      { "uARFCN", "lppa.uARFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_physCellIDUTRAN,
      { "physCellIDUTRAN", "lppa.physCellIDUTRAN",
        FT_UINT32, BASE_DEC, VALS(lppa_T_physCellIDUTRAN_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_physCellIDUTRA_FDD,
      { "physCellIDUTRA-FDD", "lppa.physCellIDUTRA_FDD",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_physCellIDUTRA_TDD,
      { "physCellIDUTRA-TDD", "lppa.physCellIDUTRA_TDD",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_uTRA_RSCP,
      { "uTRA-RSCP", "lppa.uTRA_RSCP",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_uTRA_EcN0,
      { "uTRA-EcN0", "lppa.uTRA_EcN0",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_SRSConfigurationForAllCells_item,
      { "SRSConfigurationForOneCell", "lppa.SRSConfigurationForOneCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_pci,
      { "pci", "lppa.pci",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_ul_earfcn,
      { "ul-earfcn", "lppa.ul_earfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EARFCN", HFILL }},
    { &hf_lppa_ul_bandwidth,
      { "ul-bandwidth", "lppa.ul_bandwidth",
        FT_UINT32, BASE_DEC, VALS(lppa_T_ul_bandwidth_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_ul_cyclicPrefixLength,
      { "ul-cyclicPrefixLength", "lppa.ul_cyclicPrefixLength",
        FT_UINT32, BASE_DEC, VALS(lppa_CPLength_vals), 0,
        "CPLength", HFILL }},
    { &hf_lppa_srs_BandwidthConfig,
      { "srs-BandwidthConfig", "lppa.srs_BandwidthConfig",
        FT_UINT32, BASE_DEC, VALS(lppa_T_srs_BandwidthConfig_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_srs_Bandwidth,
      { "srs-Bandwidth", "lppa.srs_Bandwidth",
        FT_UINT32, BASE_DEC, VALS(lppa_T_srs_Bandwidth_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_srs_AntennaPort,
      { "srs-AntennaPort", "lppa.srs_AntennaPort",
        FT_UINT32, BASE_DEC, VALS(lppa_T_srs_AntennaPort_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_srs_HoppingBandwidth,
      { "srs-HoppingBandwidth", "lppa.srs_HoppingBandwidth",
        FT_UINT32, BASE_DEC, VALS(lppa_T_srs_HoppingBandwidth_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_srs_cyclicShift,
      { "srs-cyclicShift", "lppa.srs_cyclicShift",
        FT_UINT32, BASE_DEC, VALS(lppa_T_srs_cyclicShift_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_srs_ConfigIndex,
      { "srs-ConfigIndex", "lppa.srs_ConfigIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_lppa_maxUpPts,
      { "maxUpPts", "lppa.maxUpPts",
        FT_UINT32, BASE_DEC, VALS(lppa_T_maxUpPts_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_transmissionComb,
      { "transmissionComb", "lppa.transmissionComb",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_lppa_freqDomainPosition,
      { "freqDomainPosition", "lppa.freqDomainPosition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_23", HFILL }},
    { &hf_lppa_groupHoppingEnabled,
      { "groupHoppingEnabled", "lppa.groupHoppingEnabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lppa_deltaSS,
      { "deltaSS", "lppa.deltaSS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_29", HFILL }},
    { &hf_lppa_sfnInitialisationTime,
      { "sfnInitialisationTime", "lppa.sfnInitialisationTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_oneFrame,
      { "oneFrame", "lppa.oneFrame",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_lppa_fourFrames,
      { "fourFrames", "lppa.fourFrames",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_lppa_SystemInformation_item,
      { "SystemInformation item", "lppa.SystemInformation_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_broadcastPeriodicity,
      { "broadcastPeriodicity", "lppa.broadcastPeriodicity",
        FT_UINT32, BASE_DEC, VALS(lppa_BroadcastPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_posSIBs,
      { "posSIBs", "lppa.posSIBs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_subframeAssignment,
      { "subframeAssignment", "lppa.subframeAssignment",
        FT_UINT32, BASE_DEC, VALS(lppa_T_subframeAssignment_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_timingAdvanceType1,
      { "timingAdvanceType1", "lppa.timingAdvanceType1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7690", HFILL }},
    { &hf_lppa_timingAdvanceType2,
      { "timingAdvanceType2", "lppa.timingAdvanceType2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7690", HFILL }},
    { &hf_lppa_srsConfiguration,
      { "srsConfiguration", "lppa.srsConfiguration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SRSConfigurationForAllCells", HFILL }},
    { &hf_lppa_WLANMeasurementQuantities_item,
      { "ProtocolIE-Single-Container", "lppa.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_wLANMeasurementQuantitiesValue,
      { "wLANMeasurementQuantitiesValue", "lppa.wLANMeasurementQuantitiesValue",
        FT_UINT32, BASE_DEC, VALS(lppa_WLANMeasurementQuantitiesValue_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_WLANMeasurementResult_item,
      { "WLANMeasurementResult-Item", "lppa.WLANMeasurementResult_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_wLAN_RSSI,
      { "wLAN-RSSI", "lppa.wLAN_RSSI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_sSID,
      { "sSID", "lppa.sSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_bSSID,
      { "bSSID", "lppa.bSSID",
        FT_ETHER, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_hESSID,
      { "hESSID", "lppa.hESSID",
        FT_ETHER, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_operatingClass,
      { "operatingClass", "lppa.operatingClass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "WLANOperatingClass", HFILL }},
    { &hf_lppa_countryCode,
      { "countryCode", "lppa.countryCode",
        FT_UINT32, BASE_DEC, VALS(lppa_WLANCountryCode_vals), 0,
        "WLANCountryCode", HFILL }},
    { &hf_lppa_wLANChannelList,
      { "wLANChannelList", "lppa.wLANChannelList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_wLANBand,
      { "wLANBand", "lppa.wLANBand",
        FT_UINT32, BASE_DEC, VALS(lppa_WLANBand_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_WLANChannelList_item,
      { "WLANChannel", "lppa.WLANChannel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_protocolIEs,
      { "protocolIEs", "lppa.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_lppa_OTDOA_Information_Type_item,
      { "ProtocolIE-Single-Container", "lppa.ProtocolIE_Single_Container_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_oTDOA_Information_Type_Item,
      { "oTDOA-Information-Type-Item", "lppa.oTDOA_Information_Type_Item",
        FT_UINT32, BASE_DEC, VALS(lppa_OTDOA_Information_Item_vals), 0,
        "OTDOA_Information_Item", HFILL }},
    { &hf_lppa_privateIEs,
      { "privateIEs", "lppa.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},

/*--- End of included file: packet-lppa-hfarr.c ---*/
#line 121 "./asn1/lppa/packet-lppa-template.c"
    };

    /* List of subtrees */
    static gint* ett[] = {
        &ett_lppa,

/*--- Included file: packet-lppa-ettarr.c ---*/
#line 1 "./asn1/lppa/packet-lppa-ettarr.c"
    &ett_lppa_PrivateIE_ID,
    &ett_lppa_ProtocolIE_Container,
    &ett_lppa_ProtocolIE_Field,
    &ett_lppa_ProtocolExtensionContainer,
    &ett_lppa_ProtocolExtensionField,
    &ett_lppa_PrivateIE_Container,
    &ett_lppa_PrivateIE_Field,
    &ett_lppa_LPPA_PDU,
    &ett_lppa_InitiatingMessage,
    &ett_lppa_SuccessfulOutcome,
    &ett_lppa_UnsuccessfulOutcome,
    &ett_lppa_Add_OTDOACells,
    &ett_lppa_Add_OTDOACells_item,
    &ett_lppa_Add_OTDOACell_Information,
    &ett_lppa_Assistance_Information,
    &ett_lppa_AssistanceInformationFailureList,
    &ett_lppa_AssistanceInformationFailureList_item,
    &ett_lppa_AssistanceInformationMetaData,
    &ett_lppa_BitmapsforNPRS,
    &ett_lppa_Cause,
    &ett_lppa_CriticalityDiagnostics,
    &ett_lppa_CriticalityDiagnostics_IE_List,
    &ett_lppa_CriticalityDiagnostics_IE_List_item,
    &ett_lppa_E_CID_MeasurementResult,
    &ett_lppa_ECGI,
    &ett_lppa_E_UTRANAccessPointPosition,
    &ett_lppa_InterRATMeasurementQuantities,
    &ett_lppa_InterRATMeasurementQuantities_Item,
    &ett_lppa_InterRATMeasurementResult,
    &ett_lppa_InterRATMeasuredResultsValue,
    &ett_lppa_MeasurementQuantities,
    &ett_lppa_MeasurementQuantities_Item,
    &ett_lppa_MeasuredResults,
    &ett_lppa_MeasuredResultsValue,
    &ett_lppa_MBSFNsubframeConfiguration,
    &ett_lppa_MBSFNsubframeConfigurationValue,
    &ett_lppa_NPRSConfiguration,
    &ett_lppa_NPRSMutingConfiguration,
    &ett_lppa_NPRSSubframePartA,
    &ett_lppa_NPRSSubframePartB,
    &ett_lppa_OTDOACells,
    &ett_lppa_OTDOACells_item,
    &ett_lppa_OTDOACell_Information,
    &ett_lppa_OTDOACell_Information_Item,
    &ett_lppa_PosSIBs,
    &ett_lppa_PosSIBs_item,
    &ett_lppa_PosSIB_Segments,
    &ett_lppa_PosSIB_Segments_item,
    &ett_lppa_PRSMutingConfiguration,
    &ett_lppa_PRSFrequencyHoppingConfiguration,
    &ett_lppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex,
    &ett_lppa_RequestedSRSTransmissionCharacteristics,
    &ett_lppa_ResultRSRP,
    &ett_lppa_ResultRSRP_Item,
    &ett_lppa_ResultRSRQ,
    &ett_lppa_ResultRSRQ_Item,
    &ett_lppa_ResultGERAN,
    &ett_lppa_ResultGERAN_Item,
    &ett_lppa_ResultUTRAN,
    &ett_lppa_ResultUTRAN_Item,
    &ett_lppa_T_physCellIDUTRAN,
    &ett_lppa_SRSConfigurationForAllCells,
    &ett_lppa_SRSConfigurationForOneCell,
    &ett_lppa_Subframeallocation,
    &ett_lppa_SystemInformation,
    &ett_lppa_SystemInformation_item,
    &ett_lppa_TDDConfiguration,
    &ett_lppa_ULConfiguration,
    &ett_lppa_WLANMeasurementQuantities,
    &ett_lppa_WLANMeasurementQuantities_Item,
    &ett_lppa_WLANMeasurementResult,
    &ett_lppa_WLANMeasurementResult_Item,
    &ett_lppa_WLANChannelList,
    &ett_lppa_E_CIDMeasurementInitiationRequest,
    &ett_lppa_E_CIDMeasurementInitiationResponse,
    &ett_lppa_E_CIDMeasurementInitiationFailure,
    &ett_lppa_E_CIDMeasurementFailureIndication,
    &ett_lppa_E_CIDMeasurementReport,
    &ett_lppa_E_CIDMeasurementTerminationCommand,
    &ett_lppa_OTDOAInformationRequest,
    &ett_lppa_OTDOA_Information_Type,
    &ett_lppa_OTDOA_Information_Type_Item,
    &ett_lppa_OTDOAInformationResponse,
    &ett_lppa_OTDOAInformationFailure,
    &ett_lppa_UTDOAInformationRequest,
    &ett_lppa_UTDOAInformationResponse,
    &ett_lppa_UTDOAInformationFailure,
    &ett_lppa_UTDOAInformationUpdate,
    &ett_lppa_AssistanceInformationControl,
    &ett_lppa_AssistanceInformationFeedback,
    &ett_lppa_ErrorIndication,
    &ett_lppa_PrivateMessage,

/*--- End of included file: packet-lppa-ettarr.c ---*/
#line 127 "./asn1/lppa/packet-lppa-template.c"
    };

    /* Register protocol */
    proto_lppa = proto_register_protocol(PNAME, PSNAME, PFNAME);
    register_dissector("lppa", dissect_LPPA_PDU_PDU, proto_lppa);

    /* Register fields and subtrees */
    proto_register_field_array(proto_lppa, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector tables */
    lppa_ies_dissector_table = register_dissector_table("lppa.ies", "LPPA-PROTOCOL-IES", proto_lppa, FT_UINT32, BASE_DEC);
    lppa_proc_imsg_dissector_table = register_dissector_table("lppa.proc.imsg", "LPPA-ELEMENTARY-PROCEDURE InitiatingMessage", proto_lppa, FT_UINT32, BASE_DEC);
    lppa_proc_sout_dissector_table = register_dissector_table("lppa.proc.sout", "LPPA-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_lppa, FT_UINT32, BASE_DEC);
    lppa_proc_uout_dissector_table = register_dissector_table("lppa.proc.uout", "LPPA-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_lppa, FT_UINT32, BASE_DEC);
}

/*--- proto_reg_handoff_lppa ---------------------------------------*/
void
proto_reg_handoff_lppa(void)
{

/*--- Included file: packet-lppa-dis-tab.c ---*/
#line 1 "./asn1/lppa/packet-lppa-dis-tab.c"
  dissector_add_uint("lppa.ies", id_MeasurementQuantities_Item, create_dissector_handle(dissect_MeasurementQuantities_Item_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_ReportCharacteristics, create_dissector_handle(dissect_ReportCharacteristics_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_MeasurementPeriodicity, create_dissector_handle(dissect_MeasurementPeriodicity_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_MeasurementQuantities, create_dissector_handle(dissect_MeasurementQuantities_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_E_CID_MeasurementResult, create_dissector_handle(dissect_E_CID_MeasurementResult_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_OTDOA_Information_Type_Group, create_dissector_handle(dissect_OTDOA_Information_Type_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_OTDOA_Information_Type_Item, create_dissector_handle(dissect_OTDOA_Information_Type_Item_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_OTDOACells, create_dissector_handle(dissect_OTDOACells_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_E_SMLC_UE_Measurement_ID, create_dissector_handle(dissect_Measurement_ID_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_eNB_UE_Measurement_ID, create_dissector_handle(dissect_Measurement_ID_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_RequestedSRSTransmissionCharacteristics, create_dissector_handle(dissect_RequestedSRSTransmissionCharacteristics_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_ULConfiguration, create_dissector_handle(dissect_ULConfiguration_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_InterRATMeasurementQuantities, create_dissector_handle(dissect_InterRATMeasurementQuantities_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_Cell_Portion_ID, create_dissector_handle(dissect_Cell_Portion_ID_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_InterRATMeasurementResult, create_dissector_handle(dissect_InterRATMeasurementResult_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_InterRATMeasurementQuantities_Item, create_dissector_handle(dissect_InterRATMeasurementQuantities_Item_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_WLANMeasurementQuantities, create_dissector_handle(dissect_WLANMeasurementQuantities_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_WLANMeasurementResult, create_dissector_handle(dissect_WLANMeasurementResult_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_AddOTDOACells, create_dissector_handle(dissect_Add_OTDOACells_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_WLANMeasurementQuantities_Item, create_dissector_handle(dissect_WLANMeasurementQuantities_Item_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_Assistance_Information, create_dissector_handle(dissect_Assistance_Information_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_Broadcast, create_dissector_handle(dissect_Broadcast_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_AssistanceInformationFailureList, create_dissector_handle(dissect_AssistanceInformationFailureList_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_e_CIDMeasurementInitiation, create_dissector_handle(dissect_E_CIDMeasurementInitiationRequest_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.sout", id_e_CIDMeasurementInitiation, create_dissector_handle(dissect_E_CIDMeasurementInitiationResponse_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.uout", id_e_CIDMeasurementInitiation, create_dissector_handle(dissect_E_CIDMeasurementInitiationFailure_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_e_CIDMeasurementFailureIndication, create_dissector_handle(dissect_E_CIDMeasurementFailureIndication_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_e_CIDMeasurementReport, create_dissector_handle(dissect_E_CIDMeasurementReport_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_e_CIDMeasurementTermination, create_dissector_handle(dissect_E_CIDMeasurementTerminationCommand_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_oTDOAInformationExchange, create_dissector_handle(dissect_OTDOAInformationRequest_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.sout", id_oTDOAInformationExchange, create_dissector_handle(dissect_OTDOAInformationResponse_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.uout", id_oTDOAInformationExchange, create_dissector_handle(dissect_OTDOAInformationFailure_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_errorIndication, create_dissector_handle(dissect_ErrorIndication_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_privateMessage, create_dissector_handle(dissect_PrivateMessage_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_uTDOAInformationExchange, create_dissector_handle(dissect_UTDOAInformationRequest_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.sout", id_uTDOAInformationExchange, create_dissector_handle(dissect_UTDOAInformationResponse_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.uout", id_uTDOAInformationExchange, create_dissector_handle(dissect_UTDOAInformationFailure_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_uTDOAInformationUpdate, create_dissector_handle(dissect_UTDOAInformationUpdate_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_assistanceInformationControl, create_dissector_handle(dissect_AssistanceInformationControl_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_assistanceInformationFeedback, create_dissector_handle(dissect_AssistanceInformationFeedback_PDU, proto_lppa));


/*--- End of included file: packet-lppa-dis-tab.c ---*/
#line 149 "./asn1/lppa/packet-lppa-template.c"
}
