/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-nrppa.c                                                             */
/* asn2wrs.py -p nrppa -c ./nrppa.cnf -s ./packet-nrppa-template -D . -O ../.. NRPPA-CommonDataTypes.asn NRPPA-Constants.asn NRPPA-Containers.asn NRPPA-PDU-Descriptions.asn NRPPA-IEs.asn NRPPA-PDU-Contents.asn */

/* Input file: packet-nrppa-template.c */

#line 1 "./asn1/nrppa/packet-nrppa-template.c"
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
 * Ref 3GPP TS 38.455 V15.2.1 (2019-01-14)
 * http://www.3gpp.org
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-per.h"

#define PNAME  "NR Positioning Protocol A (NRPPa)"
#define PSNAME "NRPPa"
#define PFNAME "nrppa"

void proto_register_nrppa(void);
void proto_reg_handoff_nrppa(void);

/* Initialize the protocol and registered fields */
static int proto_nrppa = -1;


/*--- Included file: packet-nrppa-hf.c ---*/
#line 1 "./asn1/nrppa/packet-nrppa-hf.c"
static int hf_nrppa_NRPPA_PDU_PDU = -1;           /* NRPPA_PDU */
static int hf_nrppa_Cause_PDU = -1;               /* Cause */
static int hf_nrppa_Cell_Portion_ID_PDU = -1;     /* Cell_Portion_ID */
static int hf_nrppa_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_nrppa_E_CID_MeasurementResult_PDU = -1;  /* E_CID_MeasurementResult */
static int hf_nrppa_Measurement_ID_PDU = -1;      /* Measurement_ID */
static int hf_nrppa_MeasurementPeriodicity_PDU = -1;  /* MeasurementPeriodicity */
static int hf_nrppa_MeasurementQuantities_PDU = -1;  /* MeasurementQuantities */
static int hf_nrppa_MeasurementQuantities_Item_PDU = -1;  /* MeasurementQuantities_Item */
static int hf_nrppa_OTDOACells_PDU = -1;          /* OTDOACells */
static int hf_nrppa_OtherRATMeasurementQuantities_PDU = -1;  /* OtherRATMeasurementQuantities */
static int hf_nrppa_OtherRATMeasurementQuantities_Item_PDU = -1;  /* OtherRATMeasurementQuantities_Item */
static int hf_nrppa_OtherRATMeasurementResult_PDU = -1;  /* OtherRATMeasurementResult */
static int hf_nrppa_ReportCharacteristics_PDU = -1;  /* ReportCharacteristics */
static int hf_nrppa_TDD_Config_EUTRA_Item_PDU = -1;  /* TDD_Config_EUTRA_Item */
static int hf_nrppa_WLANMeasurementQuantities_PDU = -1;  /* WLANMeasurementQuantities */
static int hf_nrppa_WLANMeasurementQuantities_Item_PDU = -1;  /* WLANMeasurementQuantities_Item */
static int hf_nrppa_WLANMeasurementResult_PDU = -1;  /* WLANMeasurementResult */
static int hf_nrppa_E_CIDMeasurementInitiationRequest_PDU = -1;  /* E_CIDMeasurementInitiationRequest */
static int hf_nrppa_E_CIDMeasurementInitiationResponse_PDU = -1;  /* E_CIDMeasurementInitiationResponse */
static int hf_nrppa_E_CIDMeasurementInitiationFailure_PDU = -1;  /* E_CIDMeasurementInitiationFailure */
static int hf_nrppa_E_CIDMeasurementFailureIndication_PDU = -1;  /* E_CIDMeasurementFailureIndication */
static int hf_nrppa_E_CIDMeasurementReport_PDU = -1;  /* E_CIDMeasurementReport */
static int hf_nrppa_E_CIDMeasurementTerminationCommand_PDU = -1;  /* E_CIDMeasurementTerminationCommand */
static int hf_nrppa_OTDOAInformationRequest_PDU = -1;  /* OTDOAInformationRequest */
static int hf_nrppa_OTDOA_Information_Type_PDU = -1;  /* OTDOA_Information_Type */
static int hf_nrppa_OTDOA_Information_Type_Item_PDU = -1;  /* OTDOA_Information_Type_Item */
static int hf_nrppa_OTDOAInformationResponse_PDU = -1;  /* OTDOAInformationResponse */
static int hf_nrppa_OTDOAInformationFailure_PDU = -1;  /* OTDOAInformationFailure */
static int hf_nrppa_ErrorIndication_PDU = -1;     /* ErrorIndication */
static int hf_nrppa_PrivateMessage_PDU = -1;      /* PrivateMessage */
static int hf_nrppa_local = -1;                   /* INTEGER_0_maxPrivateIEs */
static int hf_nrppa_global = -1;                  /* OBJECT_IDENTIFIER */
static int hf_nrppa_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_nrppa_id = -1;                      /* ProtocolIE_ID */
static int hf_nrppa_criticality = -1;             /* Criticality */
static int hf_nrppa_ie_field_value = -1;          /* T_ie_field_value */
static int hf_nrppa_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_nrppa_extensionValue = -1;          /* T_extensionValue */
static int hf_nrppa_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_nrppa_id_01 = -1;                   /* PrivateIE_ID */
static int hf_nrppa_value = -1;                   /* T_value */
static int hf_nrppa_initiatingMessage = -1;       /* InitiatingMessage */
static int hf_nrppa_successfulOutcome = -1;       /* SuccessfulOutcome */
static int hf_nrppa_unsuccessfulOutcome = -1;     /* UnsuccessfulOutcome */
static int hf_nrppa_procedureCode = -1;           /* ProcedureCode */
static int hf_nrppa_nrppatransactionID = -1;      /* NRPPATransactionID */
static int hf_nrppa_initiatingMessagevalue = -1;  /* InitiatingMessage_value */
static int hf_nrppa_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_nrppa_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */
static int hf_nrppa_radioNetwork = -1;            /* CauseRadioNetwork */
static int hf_nrppa_protocol = -1;                /* CauseProtocol */
static int hf_nrppa_misc = -1;                    /* CauseMisc */
static int hf_nrppa_cause_Extension = -1;         /* ProtocolIE_Single_Container */
static int hf_nrppa_pLMN_Identity = -1;           /* PLMN_Identity */
static int hf_nrppa_eUTRAcellIdentifier = -1;     /* EUTRACellIdentifier */
static int hf_nrppa_iE_Extensions = -1;           /* ProtocolExtensionContainer */
static int hf_nrppa_triggeringMessage = -1;       /* TriggeringMessage */
static int hf_nrppa_procedureCriticality = -1;    /* Criticality */
static int hf_nrppa_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_nrppa_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_nrppa_iECriticality = -1;           /* Criticality */
static int hf_nrppa_iE_ID = -1;                   /* ProtocolIE_ID */
static int hf_nrppa_typeOfError = -1;             /* TypeOfError */
static int hf_nrppa_servingCell_ID = -1;          /* NG_RAN_CGI */
static int hf_nrppa_servingCellTAC = -1;          /* TAC */
static int hf_nrppa_nG_RANAccessPointPosition = -1;  /* NG_RANAccessPointPosition */
static int hf_nrppa_measuredResults = -1;         /* MeasuredResults */
static int hf_nrppa_MeasurementQuantities_item = -1;  /* ProtocolIE_Single_Container */
static int hf_nrppa_measurementQuantitiesValue = -1;  /* MeasurementQuantitiesValue */
static int hf_nrppa_MeasuredResults_item = -1;    /* MeasuredResultsValue */
static int hf_nrppa_valueAngleOfArrival_EUTRA = -1;  /* INTEGER_0_719 */
static int hf_nrppa_valueTimingAdvanceType1_EUTRA = -1;  /* INTEGER_0_7690 */
static int hf_nrppa_valueTimingAdvanceType2_EUTRA = -1;  /* INTEGER_0_7690 */
static int hf_nrppa_resultRSRP_EUTRA = -1;        /* ResultRSRP_EUTRA */
static int hf_nrppa_resultRSRQ_EUTRA = -1;        /* ResultRSRQ_EUTRA */
static int hf_nrppa_measuredResultsValue_Extension = -1;  /* ProtocolIE_Single_Container */
static int hf_nrppa_latitudeSign = -1;            /* T_latitudeSign */
static int hf_nrppa_latitude = -1;                /* INTEGER_0_8388607 */
static int hf_nrppa_longitude = -1;               /* INTEGER_M8388608_8388607 */
static int hf_nrppa_directionOfAltitude = -1;     /* T_directionOfAltitude */
static int hf_nrppa_altitude = -1;                /* INTEGER_0_32767 */
static int hf_nrppa_uncertaintySemi_major = -1;   /* INTEGER_0_127 */
static int hf_nrppa_uncertaintySemi_minor = -1;   /* INTEGER_0_127 */
static int hf_nrppa_orientationOfMajorAxis = -1;  /* INTEGER_0_179 */
static int hf_nrppa_uncertaintyAltitude = -1;     /* INTEGER_0_127 */
static int hf_nrppa_confidence = -1;              /* INTEGER_0_100 */
static int hf_nrppa_nG_RANcell = -1;              /* NG_RANCell */
static int hf_nrppa_eUTRA_CellID = -1;            /* EUTRACellIdentifier */
static int hf_nrppa_nR_CellID = -1;               /* NRCellIdentifier */
static int hf_nrppa_nG_RANCell_Extension = -1;    /* ProtocolIE_Single_Container */
static int hf_nrppa_OTDOACells_item = -1;         /* OTDOACells_item */
static int hf_nrppa_oTDOACellInfo = -1;           /* OTDOACell_Information */
static int hf_nrppa_OTDOACell_Information_item = -1;  /* OTDOACell_Information_Item */
static int hf_nrppa_pCI_EUTRA = -1;               /* PCI_EUTRA */
static int hf_nrppa_cGI_EUTRA = -1;               /* CGI_EUTRA */
static int hf_nrppa_tAC = -1;                     /* TAC */
static int hf_nrppa_eARFCN = -1;                  /* EARFCN */
static int hf_nrppa_pRS_Bandwidth_EUTRA = -1;     /* PRS_Bandwidth_EUTRA */
static int hf_nrppa_pRS_ConfigurationIndex_EUTRA = -1;  /* PRS_ConfigurationIndex_EUTRA */
static int hf_nrppa_cPLength_EUTRA = -1;          /* CPLength_EUTRA */
static int hf_nrppa_numberOfDlFrames_EUTRA = -1;  /* NumberOfDlFrames_EUTRA */
static int hf_nrppa_numberOfAntennaPorts_EUTRA = -1;  /* NumberOfAntennaPorts_EUTRA */
static int hf_nrppa_sFNInitialisationTime_EUTRA = -1;  /* SFNInitialisationTime_EUTRA */
static int hf_nrppa_pRSMutingConfiguration_EUTRA = -1;  /* PRSMutingConfiguration_EUTRA */
static int hf_nrppa_prsid_EUTRA = -1;             /* PRS_ID_EUTRA */
static int hf_nrppa_tpid_EUTRA = -1;              /* TP_ID_EUTRA */
static int hf_nrppa_tpType_EUTRA = -1;            /* TP_Type_EUTRA */
static int hf_nrppa_numberOfDlFrames_Extended_EUTRA = -1;  /* NumberOfDlFrames_Extended_EUTRA */
static int hf_nrppa_crsCPlength_EUTRA = -1;       /* CPLength_EUTRA */
static int hf_nrppa_dL_Bandwidth_EUTRA = -1;      /* DL_Bandwidth_EUTRA */
static int hf_nrppa_pRSOccasionGroup_EUTRA = -1;  /* PRSOccasionGroup_EUTRA */
static int hf_nrppa_pRSFrequencyHoppingConfiguration_EUTRA = -1;  /* PRSFrequencyHoppingConfiguration_EUTRA */
static int hf_nrppa_oTDOACell_Information_Item_Extension = -1;  /* ProtocolIE_Single_Container */
static int hf_nrppa_OtherRATMeasurementQuantities_item = -1;  /* ProtocolIE_Single_Container */
static int hf_nrppa_otherRATMeasurementQuantitiesValue = -1;  /* OtherRATMeasurementQuantitiesValue */
static int hf_nrppa_OtherRATMeasurementResult_item = -1;  /* OtherRATMeasuredResultsValue */
static int hf_nrppa_resultGERAN = -1;             /* ResultGERAN */
static int hf_nrppa_resultUTRAN = -1;             /* ResultUTRAN */
static int hf_nrppa_otherRATMeasuredResultsValue_Extension = -1;  /* ProtocolIE_Single_Container */
static int hf_nrppa_two = -1;                     /* BIT_STRING_SIZE_2 */
static int hf_nrppa_four = -1;                    /* BIT_STRING_SIZE_4 */
static int hf_nrppa_eight = -1;                   /* BIT_STRING_SIZE_8 */
static int hf_nrppa_sixteen = -1;                 /* BIT_STRING_SIZE_16 */
static int hf_nrppa_thirty_two = -1;              /* BIT_STRING_SIZE_32 */
static int hf_nrppa_sixty_four = -1;              /* BIT_STRING_SIZE_64 */
static int hf_nrppa_one_hundred_and_twenty_eight = -1;  /* BIT_STRING_SIZE_128 */
static int hf_nrppa_two_hundred_and_fifty_six = -1;  /* BIT_STRING_SIZE_256 */
static int hf_nrppa_five_hundred_and_twelve = -1;  /* BIT_STRING_SIZE_512 */
static int hf_nrppa_one_thousand_and_twenty_four = -1;  /* BIT_STRING_SIZE_1024 */
static int hf_nrppa_pRSMutingConfiguration_EUTRA_Extension = -1;  /* ProtocolIE_Single_Container */
static int hf_nrppa_noOfFreqHoppingBands = -1;    /* NumberOfFrequencyHoppingBands */
static int hf_nrppa_bandPositions = -1;           /* SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex */
static int hf_nrppa_bandPositions_item = -1;      /* NarrowBandIndex */
static int hf_nrppa_ResultRSRP_EUTRA_item = -1;   /* ResultRSRP_EUTRA_Item */
static int hf_nrppa_valueRSRP_EUTRA = -1;         /* ValueRSRP_EUTRA */
static int hf_nrppa_ResultRSRQ_EUTRA_item = -1;   /* ResultRSRQ_EUTRA_Item */
static int hf_nrppa_cGI_UTRA = -1;                /* CGI_EUTRA */
static int hf_nrppa_valueRSRQ_EUTRA = -1;         /* ValueRSRQ_EUTRA */
static int hf_nrppa_ResultGERAN_item = -1;        /* ResultGERAN_Item */
static int hf_nrppa_bCCH = -1;                    /* BCCH */
static int hf_nrppa_physCellIDGERAN = -1;         /* PhysCellIDGERAN */
static int hf_nrppa_rSSI = -1;                    /* RSSI */
static int hf_nrppa_ResultUTRAN_item = -1;        /* ResultUTRAN_Item */
static int hf_nrppa_uARFCN = -1;                  /* UARFCN */
static int hf_nrppa_physCellIDUTRAN = -1;         /* T_physCellIDUTRAN */
static int hf_nrppa_physCellIDUTRA_FDD = -1;      /* PhysCellIDUTRA_FDD */
static int hf_nrppa_physCellIDUTRA_TDD = -1;      /* PhysCellIDUTRA_TDD */
static int hf_nrppa_uTRA_RSCP = -1;               /* UTRA_RSCP */
static int hf_nrppa_uTRA_EcN0 = -1;               /* UTRA_EcN0 */
static int hf_nrppa_subframeAssignment = -1;      /* T_subframeAssignment */
static int hf_nrppa_WLANMeasurementQuantities_item = -1;  /* ProtocolIE_Single_Container */
static int hf_nrppa_wLANMeasurementQuantitiesValue = -1;  /* WLANMeasurementQuantitiesValue */
static int hf_nrppa_WLANMeasurementResult_item = -1;  /* WLANMeasurementResult_Item */
static int hf_nrppa_wLAN_RSSI = -1;               /* WLAN_RSSI */
static int hf_nrppa_sSID = -1;                    /* SSID */
static int hf_nrppa_bSSID = -1;                   /* BSSID */
static int hf_nrppa_hESSID = -1;                  /* HESSID */
static int hf_nrppa_operatingClass = -1;          /* WLANOperatingClass */
static int hf_nrppa_countryCode = -1;             /* WLANCountryCode */
static int hf_nrppa_wLANChannelList = -1;         /* WLANChannelList */
static int hf_nrppa_wLANBand = -1;                /* WLANBand */
static int hf_nrppa_WLANChannelList_item = -1;    /* WLANChannel */
static int hf_nrppa_protocolIEs = -1;             /* ProtocolIE_Container */
static int hf_nrppa_OTDOA_Information_Type_item = -1;  /* ProtocolIE_Single_Container */
static int hf_nrppa_oTDOA_Information_Type_Item = -1;  /* OTDOA_Information_Item */
static int hf_nrppa_privateIEs = -1;              /* PrivateIE_Container */

/*--- End of included file: packet-nrppa-hf.c ---*/
#line 33 "./asn1/nrppa/packet-nrppa-template.c"

/* Initialize the subtree pointers */
static gint ett_nrppa = -1;

/*--- Included file: packet-nrppa-ett.c ---*/
#line 1 "./asn1/nrppa/packet-nrppa-ett.c"
static gint ett_nrppa_PrivateIE_ID = -1;
static gint ett_nrppa_ProtocolIE_Container = -1;
static gint ett_nrppa_ProtocolIE_Field = -1;
static gint ett_nrppa_ProtocolExtensionContainer = -1;
static gint ett_nrppa_ProtocolExtensionField = -1;
static gint ett_nrppa_PrivateIE_Container = -1;
static gint ett_nrppa_PrivateIE_Field = -1;
static gint ett_nrppa_NRPPA_PDU = -1;
static gint ett_nrppa_InitiatingMessage = -1;
static gint ett_nrppa_SuccessfulOutcome = -1;
static gint ett_nrppa_UnsuccessfulOutcome = -1;
static gint ett_nrppa_Cause = -1;
static gint ett_nrppa_CGI_EUTRA = -1;
static gint ett_nrppa_CriticalityDiagnostics = -1;
static gint ett_nrppa_CriticalityDiagnostics_IE_List = -1;
static gint ett_nrppa_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_nrppa_E_CID_MeasurementResult = -1;
static gint ett_nrppa_MeasurementQuantities = -1;
static gint ett_nrppa_MeasurementQuantities_Item = -1;
static gint ett_nrppa_MeasuredResults = -1;
static gint ett_nrppa_MeasuredResultsValue = -1;
static gint ett_nrppa_NG_RANAccessPointPosition = -1;
static gint ett_nrppa_NG_RAN_CGI = -1;
static gint ett_nrppa_NG_RANCell = -1;
static gint ett_nrppa_OTDOACells = -1;
static gint ett_nrppa_OTDOACells_item = -1;
static gint ett_nrppa_OTDOACell_Information = -1;
static gint ett_nrppa_OTDOACell_Information_Item = -1;
static gint ett_nrppa_OtherRATMeasurementQuantities = -1;
static gint ett_nrppa_OtherRATMeasurementQuantities_Item = -1;
static gint ett_nrppa_OtherRATMeasurementResult = -1;
static gint ett_nrppa_OtherRATMeasuredResultsValue = -1;
static gint ett_nrppa_PRSMutingConfiguration_EUTRA = -1;
static gint ett_nrppa_PRSFrequencyHoppingConfiguration_EUTRA = -1;
static gint ett_nrppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex = -1;
static gint ett_nrppa_ResultRSRP_EUTRA = -1;
static gint ett_nrppa_ResultRSRP_EUTRA_Item = -1;
static gint ett_nrppa_ResultRSRQ_EUTRA = -1;
static gint ett_nrppa_ResultRSRQ_EUTRA_Item = -1;
static gint ett_nrppa_ResultGERAN = -1;
static gint ett_nrppa_ResultGERAN_Item = -1;
static gint ett_nrppa_ResultUTRAN = -1;
static gint ett_nrppa_ResultUTRAN_Item = -1;
static gint ett_nrppa_T_physCellIDUTRAN = -1;
static gint ett_nrppa_TDD_Config_EUTRA_Item = -1;
static gint ett_nrppa_WLANMeasurementQuantities = -1;
static gint ett_nrppa_WLANMeasurementQuantities_Item = -1;
static gint ett_nrppa_WLANMeasurementResult = -1;
static gint ett_nrppa_WLANMeasurementResult_Item = -1;
static gint ett_nrppa_WLANChannelList = -1;
static gint ett_nrppa_E_CIDMeasurementInitiationRequest = -1;
static gint ett_nrppa_E_CIDMeasurementInitiationResponse = -1;
static gint ett_nrppa_E_CIDMeasurementInitiationFailure = -1;
static gint ett_nrppa_E_CIDMeasurementFailureIndication = -1;
static gint ett_nrppa_E_CIDMeasurementReport = -1;
static gint ett_nrppa_E_CIDMeasurementTerminationCommand = -1;
static gint ett_nrppa_OTDOAInformationRequest = -1;
static gint ett_nrppa_OTDOA_Information_Type = -1;
static gint ett_nrppa_OTDOA_Information_Type_Item = -1;
static gint ett_nrppa_OTDOAInformationResponse = -1;
static gint ett_nrppa_OTDOAInformationFailure = -1;
static gint ett_nrppa_ErrorIndication = -1;
static gint ett_nrppa_PrivateMessage = -1;

/*--- End of included file: packet-nrppa-ett.c ---*/
#line 37 "./asn1/nrppa/packet-nrppa-template.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;

/* Dissector tables */
static dissector_table_t nrppa_ies_dissector_table;
static dissector_table_t nrppa_proc_imsg_dissector_table;
static dissector_table_t nrppa_proc_sout_dissector_table;
static dissector_table_t nrppa_proc_uout_dissector_table;

/* Include constants */

/*--- Included file: packet-nrppa-val.h ---*/
#line 1 "./asn1/nrppa/packet-nrppa-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfErrors                  256
#define maxCellinRANnode               3840
#define maxNoMeas                      63
#define maxCellReport                  9
#define maxnoOTDOAtypes                63
#define maxServCell                    5
#define maxGERANMeas                   8
#define maxUTRANMeas                   8
#define maxWLANchannels                16
#define maxnoFreqHoppingBandsMinusOne  7

typedef enum _ProcedureCode_enum {
  id_errorIndication =   0,
  id_privateMessage =   1,
  id_e_CIDMeasurementInitiation =   2,
  id_e_CIDMeasurementFailureIndication =   3,
  id_e_CIDMeasurementReport =   4,
  id_e_CIDMeasurementTermination =   5,
  id_oTDOAInformationExchange =   6
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
  id_TDD_Config_EUTRA_Item =  22
} ProtocolIE_ID_enum;

/*--- End of included file: packet-nrppa-val.h ---*/
#line 50 "./asn1/nrppa/packet-nrppa-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


/*--- Included file: packet-nrppa-fn.c ---*/
#line 1 "./asn1/nrppa/packet-nrppa-fn.c"

static const value_string nrppa_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_nrppa_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nrppa_NRPPATransactionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_maxPrivateIEs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxPrivateIEs, NULL, FALSE);

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
  { 0, NULL }
};


static int
dissect_nrppa_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 44 "./asn1/nrppa/nrppa.cnf"
     col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                 val_to_str(ProcedureCode, nrppa_ProcedureCode_vals,
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
  { 0, NULL }
};


static int
dissect_nrppa_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &ProtocolIE_ID, FALSE);

#line 37 "./asn1/nrppa/nrppa.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(ProtocolIE_ID, VALS(nrppa_ProtocolIE_ID_vals), "unknown (%d)"));
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
                                     3, NULL, FALSE, 0, NULL);

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
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_nrppa_ProtocolIE_Single_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_nrppa_ProtocolIE_Field(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_nrppa_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_nrppa_id            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_ID },
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
                                                  1, maxProtocolExtensions, FALSE);

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
                                                  1, maxPrivateIEs, FALSE);

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
#line 58 "./asn1/nrppa/nrppa.cnf"

  proto_tree_add_item(tree, proto_nrppa, tvb, 0, -1, ENC_NA);

  col_append_sep_str(actx->pinfo->cinfo, COL_PROTOCOL, "/", "NRPPa");

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_nrppa_NRPPA_PDU, NRPPA_PDU_choice,
                                 NULL);

  return offset;
}



static int
dissect_nrppa_BCCH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_BSSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, FALSE, NULL);

  return offset;
}


static const value_string nrppa_CauseRadioNetwork_vals[] = {
  {   0, "unspecified" },
  {   1, "requested-item-not-supported" },
  {   2, "requested-item-temporarily-not-available" },
  { 0, NULL }
};


static int
dissect_nrppa_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

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
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string nrppa_CauseMisc_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};


static int
dissect_nrppa_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string nrppa_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "protocol" },
  {   2, "misc" },
  {   3, "cause-Extension" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_nrppa_radioNetwork  , ASN1_NO_EXTENSIONS     , dissect_nrppa_CauseRadioNetwork },
  {   1, &hf_nrppa_protocol      , ASN1_NO_EXTENSIONS     , dissect_nrppa_CauseProtocol },
  {   2, &hf_nrppa_misc          , ASN1_NO_EXTENSIONS     , dissect_nrppa_CauseMisc },
  {   3, &hf_nrppa_cause_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
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
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_nrppa_EUTRACellIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL, 0, NULL, NULL);

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


static const value_string nrppa_CPLength_EUTRA_vals[] = {
  {   0, "normal" },
  {   1, "extended" },
  { 0, NULL }
};


static int
dissect_nrppa_CPLength_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxNrOfErrors, FALSE);

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
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_nrppa_NRCellIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, FALSE, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string nrppa_NG_RANCell_vals[] = {
  {   0, "eUTRA-CellID" },
  {   1, "nR-CellID" },
  {   2, "nG-RANCell-Extension" },
  { 0, NULL }
};

static const per_choice_t NG_RANCell_choice[] = {
  {   0, &hf_nrppa_eUTRA_CellID  , ASN1_NO_EXTENSIONS     , dissect_nrppa_EUTRACellIdentifier },
  {   1, &hf_nrppa_nR_CellID     , ASN1_NO_EXTENSIONS     , dissect_nrppa_NRCellIdentifier },
  {   2, &hf_nrppa_nG_RANCell_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
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



static int
dissect_nrppa_TAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

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
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, FALSE);

  return offset;
}



static int
dissect_nrppa_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, FALSE);

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
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_179(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 179U, NULL, FALSE);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_100(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

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
                                                            0U, 719U, NULL, FALSE);

  return offset;
}



static int
dissect_nrppa_INTEGER_0_7690(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7690U, NULL, FALSE);

  return offset;
}



static int
dissect_nrppa_PCI_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_EARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_ValueRSRP_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, TRUE);

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
                                                  1, maxCellReport, FALSE);

  return offset;
}



static int
dissect_nrppa_ValueRSRQ_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, TRUE);

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
                                                  1, maxCellReport, FALSE);

  return offset;
}


static const value_string nrppa_MeasuredResultsValue_vals[] = {
  {   0, "valueAngleOfArrival-EUTRA" },
  {   1, "valueTimingAdvanceType1-EUTRA" },
  {   2, "valueTimingAdvanceType2-EUTRA" },
  {   3, "resultRSRP-EUTRA" },
  {   4, "resultRSRQ-EUTRA" },
  {   5, "measuredResultsValue-Extension" },
  { 0, NULL }
};

static const per_choice_t MeasuredResultsValue_choice[] = {
  {   0, &hf_nrppa_valueAngleOfArrival_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_719 },
  {   1, &hf_nrppa_valueTimingAdvanceType1_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_7690 },
  {   2, &hf_nrppa_valueTimingAdvanceType2_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_INTEGER_0_7690 },
  {   3, &hf_nrppa_resultRSRP_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_ResultRSRP_EUTRA },
  {   4, &hf_nrppa_resultRSRQ_EUTRA, ASN1_NO_EXTENSIONS     , dissect_nrppa_ResultRSRQ_EUTRA },
  {   5, &hf_nrppa_measuredResultsValue_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
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
                                                  1, maxNoMeas, FALSE);

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
dissect_nrppa_HESSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, FALSE, NULL);

  return offset;
}



static int
dissect_nrppa_Measurement_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 15U, NULL, TRUE);

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
  { 0, NULL }
};


static int
dissect_nrppa_MeasurementPeriodicity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     13, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t MeasurementQuantities_sequence_of[1] = {
  { &hf_nrppa_MeasurementQuantities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Single_Container },
};

static int
dissect_nrppa_MeasurementQuantities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_MeasurementQuantities, MeasurementQuantities_sequence_of,
                                                  1, maxNoMeas, FALSE);

  return offset;
}


static const value_string nrppa_MeasurementQuantitiesValue_vals[] = {
  {   0, "cell-ID" },
  {   1, "angleOfArrival" },
  {   2, "timingAdvanceType1" },
  {   3, "timingAdvanceType2" },
  {   4, "rSRP" },
  {   5, "rSRQ" },
  { 0, NULL }
};


static int
dissect_nrppa_MeasurementQuantitiesValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

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



static int
dissect_nrppa_NarrowBandIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, TRUE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_nrppa_NumberOfDlFrames_Extended_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 160U, NULL, TRUE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_nrppa_PRS_ConfigurationIndex_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_SFNInitialisationTime_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_512(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     512, 512, FALSE, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_nrppa_BIT_STRING_SIZE_1024(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1024, 1024, FALSE, NULL, 0, NULL, NULL);

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
  {  10, "pRSMutingConfiguration-EUTRA-Extension" },
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
  {  10, &hf_nrppa_pRSMutingConfiguration_EUTRA_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
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
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_TP_ID_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, TRUE);

  return offset;
}


static const value_string nrppa_TP_Type_EUTRA_vals[] = {
  {   0, "prs-only-tp" },
  { 0, NULL }
};


static int
dissect_nrppa_TP_Type_EUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex_sequence_of[1] = {
  { &hf_nrppa_bandPositions_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_NarrowBandIndex },
};

static int
dissect_nrppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex, SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex_sequence_of,
                                                  1, maxnoFreqHoppingBandsMinusOne, FALSE);

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
  {  20, "oTDOACell-Information-Item-Extension" },
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
  {  20, &hf_nrppa_oTDOACell_Information_Item_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
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
                                                  1, maxnoOTDOAtypes, FALSE);

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
                                                  1, maxCellinRANnode, FALSE);

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
                                     20, NULL, TRUE, 1, NULL);

  return offset;
}


static const per_sequence_t OtherRATMeasurementQuantities_sequence_of[1] = {
  { &hf_nrppa_OtherRATMeasurementQuantities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Single_Container },
};

static int
dissect_nrppa_OtherRATMeasurementQuantities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_OtherRATMeasurementQuantities, OtherRATMeasurementQuantities_sequence_of,
                                                  0, maxNoMeas, FALSE);

  return offset;
}


static const value_string nrppa_OtherRATMeasurementQuantitiesValue_vals[] = {
  {   0, "geran" },
  {   1, "utran" },
  { 0, NULL }
};


static int
dissect_nrppa_OtherRATMeasurementQuantitiesValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

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
                                                            0U, 63U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_RSSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, TRUE);

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
                                                  1, maxGERANMeas, FALSE);

  return offset;
}



static int
dissect_nrppa_UARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_PhysCellIDUTRA_FDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_PhysCellIDUTRA_TDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, TRUE);

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
                                                            -5, 91U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_UTRA_EcN0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 49U, NULL, TRUE);

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
                                                  1, maxUTRANMeas, FALSE);

  return offset;
}


static const value_string nrppa_OtherRATMeasuredResultsValue_vals[] = {
  {   0, "resultGERAN" },
  {   1, "resultUTRAN" },
  {   2, "otherRATMeasuredResultsValue-Extension" },
  { 0, NULL }
};

static const per_choice_t OtherRATMeasuredResultsValue_choice[] = {
  {   0, &hf_nrppa_resultGERAN   , ASN1_NO_EXTENSIONS     , dissect_nrppa_ResultGERAN },
  {   1, &hf_nrppa_resultUTRAN   , ASN1_NO_EXTENSIONS     , dissect_nrppa_ResultUTRAN },
  {   2, &hf_nrppa_otherRATMeasuredResultsValue_Extension, ASN1_NO_EXTENSIONS     , dissect_nrppa_ProtocolIE_Single_Container },
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
                                                  1, maxNoMeas, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_nrppa_SSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 32, FALSE, NULL);

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
                                     7, NULL, TRUE, 0, NULL);

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


static const per_sequence_t WLANMeasurementQuantities_sequence_of[1] = {
  { &hf_nrppa_WLANMeasurementQuantities_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_ProtocolIE_Single_Container },
};

static int
dissect_nrppa_WLANMeasurementQuantities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_WLANMeasurementQuantities, WLANMeasurementQuantities_sequence_of,
                                                  0, maxNoMeas, FALSE);

  return offset;
}


static const value_string nrppa_WLANMeasurementQuantitiesValue_vals[] = {
  {   0, "wlan" },
  { 0, NULL }
};


static int
dissect_nrppa_WLANMeasurementQuantitiesValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

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
                                                            0U, 141U, NULL, TRUE);

  return offset;
}



static int
dissect_nrppa_WLANOperatingClass(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

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
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_nrppa_WLANChannel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t WLANChannelList_sequence_of[1] = {
  { &hf_nrppa_WLANChannelList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nrppa_WLANChannel },
};

static int
dissect_nrppa_WLANChannelList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_nrppa_WLANChannelList, WLANChannelList_sequence_of,
                                                  1, maxWLANchannels, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
                                                  1, maxNoMeas, FALSE);

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
                                                  1, maxnoOTDOAtypes, FALSE);

  return offset;
}


static const per_sequence_t OTDOA_Information_Type_Item_sequence[] = {
  { &hf_nrppa_oTDOA_Information_Type_Item, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nrppa_OTDOA_Information_Item },
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

/*--- PDUs ---*/

static int dissect_NRPPA_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_NRPPA_PDU(tvb, offset, &asn1_ctx, tree, hf_nrppa_NRPPA_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_Cause(tvb, offset, &asn1_ctx, tree, hf_nrppa_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cell_Portion_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_Cell_Portion_ID(tvb, offset, &asn1_ctx, tree, hf_nrppa_Cell_Portion_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_nrppa_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CID_MeasurementResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_E_CID_MeasurementResult(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CID_MeasurementResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Measurement_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_Measurement_ID(tvb, offset, &asn1_ctx, tree, hf_nrppa_Measurement_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementPeriodicity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_MeasurementPeriodicity(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementPeriodicity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementQuantities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_MeasurementQuantities(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementQuantities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MeasurementQuantities_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_MeasurementQuantities_Item(tvb, offset, &asn1_ctx, tree, hf_nrppa_MeasurementQuantities_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOACells_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_OTDOACells(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOACells_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OtherRATMeasurementQuantities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_OtherRATMeasurementQuantities(tvb, offset, &asn1_ctx, tree, hf_nrppa_OtherRATMeasurementQuantities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OtherRATMeasurementQuantities_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_OtherRATMeasurementQuantities_Item(tvb, offset, &asn1_ctx, tree, hf_nrppa_OtherRATMeasurementQuantities_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OtherRATMeasurementResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_OtherRATMeasurementResult(tvb, offset, &asn1_ctx, tree, hf_nrppa_OtherRATMeasurementResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ReportCharacteristics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_ReportCharacteristics(tvb, offset, &asn1_ctx, tree, hf_nrppa_ReportCharacteristics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_TDD_Config_EUTRA_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_TDD_Config_EUTRA_Item(tvb, offset, &asn1_ctx, tree, hf_nrppa_TDD_Config_EUTRA_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WLANMeasurementQuantities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_WLANMeasurementQuantities(tvb, offset, &asn1_ctx, tree, hf_nrppa_WLANMeasurementQuantities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WLANMeasurementQuantities_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_WLANMeasurementQuantities_Item(tvb, offset, &asn1_ctx, tree, hf_nrppa_WLANMeasurementQuantities_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_WLANMeasurementResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_WLANMeasurementResult(tvb, offset, &asn1_ctx, tree, hf_nrppa_WLANMeasurementResult_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementInitiationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementInitiationRequest(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementInitiationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementInitiationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementInitiationResponse(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementInitiationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementInitiationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementInitiationFailure(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementInitiationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementFailureIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementFailureIndication(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementFailureIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementReport_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementReport(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementReport_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CIDMeasurementTerminationCommand_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_E_CIDMeasurementTerminationCommand(tvb, offset, &asn1_ctx, tree, hf_nrppa_E_CIDMeasurementTerminationCommand_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOAInformationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_OTDOAInformationRequest(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOAInformationRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOA_Information_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_OTDOA_Information_Type(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOA_Information_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOA_Information_Type_Item_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_OTDOA_Information_Type_Item(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOA_Information_Type_Item_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOAInformationResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_OTDOAInformationResponse(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOAInformationResponse_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_OTDOAInformationFailure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_OTDOAInformationFailure(tvb, offset, &asn1_ctx, tree, hf_nrppa_OTDOAInformationFailure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_nrppa_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_nrppa_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_nrppa_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-nrppa-fn.c ---*/
#line 57 "./asn1/nrppa/packet-nrppa-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint_new(nrppa_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE, NULL)) ? tvb_captured_length(tvb) : 0;
}

/*--- proto_register_nrppa -------------------------------------------*/
void proto_register_nrppa(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-nrppa-hfarr.c ---*/
#line 1 "./asn1/nrppa/packet-nrppa-hfarr.c"
    { &hf_nrppa_NRPPA_PDU_PDU,
      { "NRPPA-PDU", "nrppa.NRPPA_PDU",
        FT_UINT32, BASE_DEC, VALS(nrppa_NRPPA_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_Cause_PDU,
      { "Cause", "nrppa.Cause",
        FT_UINT32, BASE_DEC, VALS(nrppa_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_Cell_Portion_ID_PDU,
      { "Cell-Portion-ID", "nrppa.Cell_Portion_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "nrppa.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_E_CID_MeasurementResult_PDU,
      { "E-CID-MeasurementResult", "nrppa.E_CID_MeasurementResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_Measurement_ID_PDU,
      { "Measurement-ID", "nrppa.Measurement_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementPeriodicity_PDU,
      { "MeasurementPeriodicity", "nrppa.MeasurementPeriodicity",
        FT_UINT32, BASE_DEC, VALS(nrppa_MeasurementPeriodicity_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementQuantities_PDU,
      { "MeasurementQuantities", "nrppa.MeasurementQuantities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_MeasurementQuantities_Item_PDU,
      { "MeasurementQuantities-Item", "nrppa.MeasurementQuantities_Item_element",
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
    { &hf_nrppa_ReportCharacteristics_PDU,
      { "ReportCharacteristics", "nrppa.ReportCharacteristics",
        FT_UINT32, BASE_DEC, VALS(nrppa_ReportCharacteristics_vals), 0,
        NULL, HFILL }},
    { &hf_nrppa_TDD_Config_EUTRA_Item_PDU,
      { "TDD-Config-EUTRA-Item", "nrppa.TDD_Config_EUTRA_Item_element",
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
    { &hf_nrppa_ErrorIndication_PDU,
      { "ErrorIndication", "nrppa.ErrorIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_PrivateMessage_PDU,
      { "PrivateMessage", "nrppa.PrivateMessage_element",
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
    { &hf_nrppa_cause_Extension,
      { "cause-Extension", "nrppa.cause_Extension_element",
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
    { &hf_nrppa_iE_Extensions,
      { "iE-Extensions", "nrppa.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
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
    { &hf_nrppa_servingCell_ID,
      { "servingCell-ID", "nrppa.servingCell_ID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NG_RAN_CGI", HFILL }},
    { &hf_nrppa_servingCellTAC,
      { "servingCellTAC", "nrppa.servingCellTAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TAC", HFILL }},
    { &hf_nrppa_nG_RANAccessPointPosition,
      { "nG-RANAccessPointPosition", "nrppa.nG_RANAccessPointPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_measuredResults,
      { "measuredResults", "nrppa.measuredResults",
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
    { &hf_nrppa_measuredResultsValue_Extension,
      { "measuredResultsValue-Extension", "nrppa.measuredResultsValue_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Single_Container", HFILL }},
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
    { &hf_nrppa_nG_RANCell_Extension,
      { "nG-RANCell-Extension", "nrppa.nG_RANCell_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Single_Container", HFILL }},
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
        FT_BYTES, BASE_NONE, NULL, 0,
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
    { &hf_nrppa_oTDOACell_Information_Item_Extension,
      { "oTDOACell-Information-Item-Extension", "nrppa.oTDOACell_Information_Item_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Single_Container", HFILL }},
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
    { &hf_nrppa_otherRATMeasuredResultsValue_Extension,
      { "otherRATMeasuredResultsValue-Extension", "nrppa.otherRATMeasuredResultsValue_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Single_Container", HFILL }},
    { &hf_nrppa_two,
      { "two", "nrppa.two",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_nrppa_four,
      { "four", "nrppa.four",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
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
    { &hf_nrppa_pRSMutingConfiguration_EUTRA_Extension,
      { "pRSMutingConfiguration-EUTRA-Extension", "nrppa.pRSMutingConfiguration_EUTRA_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Single_Container", HFILL }},
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
    { &hf_nrppa_ResultRSRP_EUTRA_item,
      { "ResultRSRP-EUTRA-Item", "nrppa.ResultRSRP_EUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_valueRSRP_EUTRA,
      { "valueRSRP-EUTRA", "nrppa.valueRSRP_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_ResultRSRQ_EUTRA_item,
      { "ResultRSRQ-EUTRA-Item", "nrppa.ResultRSRQ_EUTRA_Item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nrppa_cGI_UTRA,
      { "cGI-UTRA", "nrppa.cGI_UTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CGI_EUTRA", HFILL }},
    { &hf_nrppa_valueRSRQ_EUTRA,
      { "valueRSRQ-EUTRA", "nrppa.valueRSRQ_EUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
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
    { &hf_nrppa_subframeAssignment,
      { "subframeAssignment", "nrppa.subframeAssignment",
        FT_UINT32, BASE_DEC, VALS(nrppa_T_subframeAssignment_vals), 0,
        NULL, HFILL }},
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
    { &hf_nrppa_oTDOA_Information_Type_Item,
      { "oTDOA-Information-Type-Item", "nrppa.oTDOA_Information_Type_Item",
        FT_UINT32, BASE_DEC, VALS(nrppa_OTDOA_Information_Item_vals), 0,
        "OTDOA_Information_Item", HFILL }},
    { &hf_nrppa_privateIEs,
      { "privateIEs", "nrppa.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},

/*--- End of included file: packet-nrppa-hfarr.c ---*/
#line 85 "./asn1/nrppa/packet-nrppa-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_nrppa,

/*--- Included file: packet-nrppa-ettarr.c ---*/
#line 1 "./asn1/nrppa/packet-nrppa-ettarr.c"
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
    &ett_nrppa_Cause,
    &ett_nrppa_CGI_EUTRA,
    &ett_nrppa_CriticalityDiagnostics,
    &ett_nrppa_CriticalityDiagnostics_IE_List,
    &ett_nrppa_CriticalityDiagnostics_IE_List_item,
    &ett_nrppa_E_CID_MeasurementResult,
    &ett_nrppa_MeasurementQuantities,
    &ett_nrppa_MeasurementQuantities_Item,
    &ett_nrppa_MeasuredResults,
    &ett_nrppa_MeasuredResultsValue,
    &ett_nrppa_NG_RANAccessPointPosition,
    &ett_nrppa_NG_RAN_CGI,
    &ett_nrppa_NG_RANCell,
    &ett_nrppa_OTDOACells,
    &ett_nrppa_OTDOACells_item,
    &ett_nrppa_OTDOACell_Information,
    &ett_nrppa_OTDOACell_Information_Item,
    &ett_nrppa_OtherRATMeasurementQuantities,
    &ett_nrppa_OtherRATMeasurementQuantities_Item,
    &ett_nrppa_OtherRATMeasurementResult,
    &ett_nrppa_OtherRATMeasuredResultsValue,
    &ett_nrppa_PRSMutingConfiguration_EUTRA,
    &ett_nrppa_PRSFrequencyHoppingConfiguration_EUTRA,
    &ett_nrppa_SEQUENCE_SIZE_1_maxnoFreqHoppingBandsMinusOne_OF_NarrowBandIndex,
    &ett_nrppa_ResultRSRP_EUTRA,
    &ett_nrppa_ResultRSRP_EUTRA_Item,
    &ett_nrppa_ResultRSRQ_EUTRA,
    &ett_nrppa_ResultRSRQ_EUTRA_Item,
    &ett_nrppa_ResultGERAN,
    &ett_nrppa_ResultGERAN_Item,
    &ett_nrppa_ResultUTRAN,
    &ett_nrppa_ResultUTRAN_Item,
    &ett_nrppa_T_physCellIDUTRAN,
    &ett_nrppa_TDD_Config_EUTRA_Item,
    &ett_nrppa_WLANMeasurementQuantities,
    &ett_nrppa_WLANMeasurementQuantities_Item,
    &ett_nrppa_WLANMeasurementResult,
    &ett_nrppa_WLANMeasurementResult_Item,
    &ett_nrppa_WLANChannelList,
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
    &ett_nrppa_ErrorIndication,
    &ett_nrppa_PrivateMessage,

/*--- End of included file: packet-nrppa-ettarr.c ---*/
#line 91 "./asn1/nrppa/packet-nrppa-template.c"
  };

  /* Register protocol */
  proto_nrppa = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("nrppa", dissect_NRPPA_PDU_PDU, proto_nrppa);

  /* Register fields and subtrees */
  proto_register_field_array(proto_nrppa, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

   /* Register dissector tables */
  nrppa_ies_dissector_table = register_dissector_table("nrppa.ies", "NRPPA-PROTOCOL-IES", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_proc_imsg_dissector_table = register_dissector_table("nrppa.proc.imsg", "NRPPA-ELEMENTARY-PROCEDURE InitiatingMessage", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_proc_sout_dissector_table = register_dissector_table("nrppa.proc.sout", "NRPPA-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_nrppa, FT_UINT32, BASE_DEC);
  nrppa_proc_uout_dissector_table = register_dissector_table("nrppa.proc.uout", "NRPPA-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_nrppa, FT_UINT32, BASE_DEC);
}

/*--- proto_reg_handoff_nrppa ---------------------------------------*/
void
proto_reg_handoff_nrppa(void)
{

/*--- Included file: packet-nrppa-dis-tab.c ---*/
#line 1 "./asn1/nrppa/packet-nrppa-dis-tab.c"
  dissector_add_uint("nrppa.ies", id_Cause, create_dissector_handle(dissect_Cause_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_CriticalityDiagnostics, create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_LMF_UE_Measurement_ID, create_dissector_handle(dissect_Measurement_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_ReportCharacteristics, create_dissector_handle(dissect_ReportCharacteristics_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementPeriodicity, create_dissector_handle(dissect_MeasurementPeriodicity_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementQuantities, create_dissector_handle(dissect_MeasurementQuantities_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_RAN_UE_Measurement_ID, create_dissector_handle(dissect_Measurement_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_E_CID_MeasurementResult, create_dissector_handle(dissect_E_CID_MeasurementResult_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OTDOACells, create_dissector_handle(dissect_OTDOACells_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OTDOA_Information_Type_Group, create_dissector_handle(dissect_OTDOA_Information_Type_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OTDOA_Information_Type_Item, create_dissector_handle(dissect_OTDOA_Information_Type_Item_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_MeasurementQuantities_Item, create_dissector_handle(dissect_MeasurementQuantities_Item_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_Cell_Portion_ID, create_dissector_handle(dissect_Cell_Portion_ID_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OtherRATMeasurementQuantities, create_dissector_handle(dissect_OtherRATMeasurementQuantities_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OtherRATMeasurementQuantities_Item, create_dissector_handle(dissect_OtherRATMeasurementQuantities_Item_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_OtherRATMeasurementResult, create_dissector_handle(dissect_OtherRATMeasurementResult_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_WLANMeasurementQuantities, create_dissector_handle(dissect_WLANMeasurementQuantities_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_WLANMeasurementQuantities_Item, create_dissector_handle(dissect_WLANMeasurementQuantities_Item_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_WLANMeasurementResult, create_dissector_handle(dissect_WLANMeasurementResult_PDU, proto_nrppa));
  dissector_add_uint("nrppa.ies", id_TDD_Config_EUTRA_Item, create_dissector_handle(dissect_TDD_Config_EUTRA_Item_PDU, proto_nrppa));
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


/*--- End of included file: packet-nrppa-dis-tab.c ---*/
#line 113 "./asn1/nrppa/packet-nrppa-template.c"
}
