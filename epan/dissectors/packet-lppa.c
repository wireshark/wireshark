/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lppa.c                                                              */
/* ../../tools/asn2wrs.py -p lppa -c ./lppa.cnf -s ./packet-lppa-template -D . -O ../../epan/dissectors LPPA-Common.asn LPPA-Constant.asn LPPA-Container.asn LPPA-ElementaryProcedure.asn LPPA-InformationElement.asn LPPA-PDU.asn */

/* Input file: packet-lppa-template.c */

#line 1 "../../asn1/lppa/packet-lppa-template.c"
/* packet-lppa.c
 * Routines for 3GPP LTE Positioning Protocol A (LLPa) packet dissection
 * Copyright 2011, Pascal Quantin <pascal.quantin@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Ref 3GPP TS 36.455 version 11.3.0 Release 11
 * http://www.3gpp.org
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-per.h"

#define PNAME  "LTE Positioning Protocol A (LPPa)"
#define PSNAME "LPPa"
#define PFNAME "lppa"

void proto_register_lppa(void);
void proto_reg_handoff_lppa(void);

/* Initialize the protocol and registered fields */
static int proto_lppa = -1;


/*--- Included file: packet-lppa-hf.c ---*/
#line 1 "../../asn1/lppa/packet-lppa-hf.c"
static int hf_lppa_LPPA_PDU_PDU = -1;             /* LPPA_PDU */
static int hf_lppa_Cause_PDU = -1;                /* Cause */
static int hf_lppa_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_lppa_E_CID_MeasurementResult_PDU = -1;  /* E_CID_MeasurementResult */
static int hf_lppa_Measurement_ID_PDU = -1;       /* Measurement_ID */
static int hf_lppa_MeasurementPeriodicity_PDU = -1;  /* MeasurementPeriodicity */
static int hf_lppa_MeasurementQuantities_PDU = -1;  /* MeasurementQuantities */
static int hf_lppa_MeasurementQuantities_Item_PDU = -1;  /* MeasurementQuantities_Item */
static int hf_lppa_OTDOACells_PDU = -1;           /* OTDOACells */
static int hf_lppa_ReportCharacteristics_PDU = -1;  /* ReportCharacteristics */
static int hf_lppa_RequestedSRSTransmissionCharacteristics_PDU = -1;  /* RequestedSRSTransmissionCharacteristics */
static int hf_lppa_ULConfiguration_PDU = -1;      /* ULConfiguration */
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
static int hf_lppa_radioNetwork = -1;             /* CauseRadioNetwork */
static int hf_lppa_protocol = -1;                 /* CauseProtocol */
static int hf_lppa_misc = -1;                     /* CauseMisc */
static int hf_lppa_triggeringMessage = -1;        /* TriggeringMessage */
static int hf_lppa_procedureCriticality = -1;     /* Criticality */
static int hf_lppa_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_lppa_iE_Extensions = -1;            /* ProtocolExtensionContainer */
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
static int hf_lppa_MeasurementQuantities_item = -1;  /* ProtocolIE_Single_Container */
static int hf_lppa_measurementQuantitiesValue = -1;  /* MeasurementQuantitiesValue */
static int hf_lppa_MeasuredResults_item = -1;     /* MeasuredResultsValue */
static int hf_lppa_valueAngleOfArrival = -1;      /* INTEGER_0_719 */
static int hf_lppa_valueTimingAdvanceType1 = -1;  /* INTEGER_0_7690 */
static int hf_lppa_valueTimingAdvanceType2 = -1;  /* INTEGER_0_7690 */
static int hf_lppa_resultRSRP = -1;               /* ResultRSRP */
static int hf_lppa_resultRSRQ = -1;               /* ResultRSRQ */
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
static int hf_lppa_two = -1;                      /* BIT_STRING_SIZE_2 */
static int hf_lppa_four = -1;                     /* BIT_STRING_SIZE_4 */
static int hf_lppa_eight = -1;                    /* BIT_STRING_SIZE_8 */
static int hf_lppa_sixteen = -1;                  /* BIT_STRING_SIZE_16 */
static int hf_lppa_numberOfTransmissions = -1;    /* INTEGER_0_500_ */
static int hf_lppa_bandwidth = -1;                /* INTEGER_1_100_ */
static int hf_lppa_ResultRSRP_item = -1;          /* ResultRSRP_Item */
static int hf_lppa_eCGI = -1;                     /* ECGI */
static int hf_lppa_valueRSRP = -1;                /* ValueRSRP */
static int hf_lppa_ResultRSRQ_item = -1;          /* ResultRSRQ_Item */
static int hf_lppa_valueRSRQ = -1;                /* ValueRSRQ */
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
static int hf_lppa_timingAdvanceType1 = -1;       /* INTEGER_0_7690 */
static int hf_lppa_timingAdvanceType2 = -1;       /* INTEGER_0_7690 */
static int hf_lppa_srsConfiguration = -1;         /* SRSConfigurationForAllCells */
static int hf_lppa_protocolIEs = -1;              /* ProtocolIE_Container */
static int hf_lppa_OTDOA_Information_Type_item = -1;  /* ProtocolIE_Single_Container */
static int hf_lppa_oTDOA_Information_Type_Item = -1;  /* OTDOA_Information_Item */
static int hf_lppa_privateIEs = -1;               /* PrivateIE_Container */

/*--- End of included file: packet-lppa-hf.c ---*/
#line 46 "../../asn1/lppa/packet-lppa-template.c"

/* Initialize the subtree pointers */
static gint ett_lppa = -1;

/*--- Included file: packet-lppa-ett.c ---*/
#line 1 "../../asn1/lppa/packet-lppa-ett.c"
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
static gint ett_lppa_Cause = -1;
static gint ett_lppa_CriticalityDiagnostics = -1;
static gint ett_lppa_CriticalityDiagnostics_IE_List = -1;
static gint ett_lppa_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_lppa_E_CID_MeasurementResult = -1;
static gint ett_lppa_ECGI = -1;
static gint ett_lppa_E_UTRANAccessPointPosition = -1;
static gint ett_lppa_MeasurementQuantities = -1;
static gint ett_lppa_MeasurementQuantities_Item = -1;
static gint ett_lppa_MeasuredResults = -1;
static gint ett_lppa_MeasuredResultsValue = -1;
static gint ett_lppa_OTDOACells = -1;
static gint ett_lppa_OTDOACells_item = -1;
static gint ett_lppa_OTDOACell_Information = -1;
static gint ett_lppa_OTDOACell_Information_Item = -1;
static gint ett_lppa_PRSMutingConfiguration = -1;
static gint ett_lppa_RequestedSRSTransmissionCharacteristics = -1;
static gint ett_lppa_ResultRSRP = -1;
static gint ett_lppa_ResultRSRP_Item = -1;
static gint ett_lppa_ResultRSRQ = -1;
static gint ett_lppa_ResultRSRQ_Item = -1;
static gint ett_lppa_SRSConfigurationForAllCells = -1;
static gint ett_lppa_SRSConfigurationForOneCell = -1;
static gint ett_lppa_ULConfiguration = -1;
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
static gint ett_lppa_ErrorIndication = -1;
static gint ett_lppa_PrivateMessage = -1;

/*--- End of included file: packet-lppa-ett.c ---*/
#line 50 "../../asn1/lppa/packet-lppa-template.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;

/* Dissector tables */
static dissector_table_t lppa_ies_dissector_table;
static dissector_table_t lppa_proc_imsg_dissector_table;
static dissector_table_t lppa_proc_sout_dissector_table;
static dissector_table_t lppa_proc_uout_dissector_table;

/* Include constants */

/*--- Included file: packet-lppa-val.h ---*/
#line 1 "../../asn1/lppa/packet-lppa-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfErrors                  256
#define maxCellineNB                   256
#define maxNoMeas                      63
#define maxCellReport                  9
#define maxnoOTDOAtypes                63
#define maxServCell                    5

typedef enum _ProcedureCode_enum {
  id_errorIndication =   0,
  id_privateMessage =   1,
  id_e_CIDMeasurementInitiation =   2,
  id_e_CIDMeasurementFailureIndication =   3,
  id_e_CIDMeasurementReport =   4,
  id_e_CIDMeasurementTermination =   5,
  id_oTDOAInformationExchange =   6,
  id_uTDOAInformationExchange =   7,
  id_uTDOAInformationUpdate =   8
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
  id_ULConfiguration =  13
} ProtocolIE_ID_enum;

/*--- End of included file: packet-lppa-val.h ---*/
#line 63 "../../asn1/lppa/packet-lppa-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


/*--- Included file: packet-lppa-fn.c ---*/
#line 1 "../../asn1/lppa/packet-lppa-fn.c"

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
  { 0, NULL }
};


static int
dissect_lppa_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 44 "../../asn1/lppa/lppa.cnf"
     col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ",
                 val_to_str(ProcedureCode, lppa_ProcedureCode_vals,
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
  { 0, NULL }
};


static int
dissect_lppa_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &ProtocolIE_ID, FALSE);

#line 37 "../../asn1/lppa/lppa.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(ProtocolIE_ID, VALS(lppa_ProtocolIE_ID_vals), "unknown (%d)"));
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
#line 58 "../../asn1/lppa/lppa.cnf"

  proto_tree_add_item(tree, proto_lppa, tvb, 0, -1, ENC_NA);

  col_append_sep_str(actx->pinfo->cinfo, COL_PROTOCOL, "/", "LPPa");

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_LPPA_PDU, LPPA_PDU_choice,
                                 NULL);

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
dissect_lppa_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_lppa_EUTRANCellIdentifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL, NULL);

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
dissect_lppa_PCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, TRUE);

  return offset;
}



static int
dissect_lppa_EARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, TRUE);

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



static int
dissect_lppa_SFNInitialisationTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_lppa_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}


static const value_string lppa_PRSMutingConfiguration_vals[] = {
  {   0, "two" },
  {   1, "four" },
  {   2, "eight" },
  {   3, "sixteen" },
  { 0, NULL }
};

static const per_choice_t PRSMutingConfiguration_choice[] = {
  {   0, &hf_lppa_two            , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_2 },
  {   1, &hf_lppa_four           , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_4 },
  {   2, &hf_lppa_eight          , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_8 },
  {   3, &hf_lppa_sixteen        , ASN1_EXTENSION_ROOT    , dissect_lppa_BIT_STRING_SIZE_16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_PRSMutingConfiguration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_PRSMutingConfiguration, PRSMutingConfiguration_choice,
                                 NULL);

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
  { 0, NULL, 0, NULL }
};

static int
dissect_lppa_OTDOACell_Information_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lppa_OTDOACell_Information_Item, OTDOACell_Information_Item_choice,
                                 NULL);

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
  { 0, NULL }
};


static int
dissect_lppa_OTDOA_Information_Item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, TRUE, 2, NULL);

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
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lppa_Cause(tvb, offset, &asn1_ctx, tree, hf_lppa_Cause_PDU);
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
#line 70 "../../asn1/lppa/packet-lppa-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lppa_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lppa_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lppa_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lppa_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

/*--- proto_register_lppa -------------------------------------------*/
void proto_register_lppa(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-lppa-hfarr.c ---*/
#line 1 "../../asn1/lppa/packet-lppa-hfarr.c"
    { &hf_lppa_LPPA_PDU_PDU,
      { "LPPA-PDU", "lppa.LPPA_PDU",
        FT_UINT32, BASE_DEC, VALS(lppa_LPPA_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_Cause_PDU,
      { "Cause", "lppa.Cause",
        FT_UINT32, BASE_DEC, VALS(lppa_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_lppa_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "lppa.CriticalityDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lppa_E_CID_MeasurementResult_PDU,
      { "E-CID-MeasurementResult", "lppa.E_CID_MeasurementResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
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
    { &hf_lppa_iE_Extensions,
      { "iE-Extensions", "lppa.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
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
#line 98 "../../asn1/lppa/packet-lppa-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_lppa,

/*--- Included file: packet-lppa-ettarr.c ---*/
#line 1 "../../asn1/lppa/packet-lppa-ettarr.c"
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
    &ett_lppa_Cause,
    &ett_lppa_CriticalityDiagnostics,
    &ett_lppa_CriticalityDiagnostics_IE_List,
    &ett_lppa_CriticalityDiagnostics_IE_List_item,
    &ett_lppa_E_CID_MeasurementResult,
    &ett_lppa_ECGI,
    &ett_lppa_E_UTRANAccessPointPosition,
    &ett_lppa_MeasurementQuantities,
    &ett_lppa_MeasurementQuantities_Item,
    &ett_lppa_MeasuredResults,
    &ett_lppa_MeasuredResultsValue,
    &ett_lppa_OTDOACells,
    &ett_lppa_OTDOACells_item,
    &ett_lppa_OTDOACell_Information,
    &ett_lppa_OTDOACell_Information_Item,
    &ett_lppa_PRSMutingConfiguration,
    &ett_lppa_RequestedSRSTransmissionCharacteristics,
    &ett_lppa_ResultRSRP,
    &ett_lppa_ResultRSRP_Item,
    &ett_lppa_ResultRSRQ,
    &ett_lppa_ResultRSRQ_Item,
    &ett_lppa_SRSConfigurationForAllCells,
    &ett_lppa_SRSConfigurationForOneCell,
    &ett_lppa_ULConfiguration,
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
    &ett_lppa_ErrorIndication,
    &ett_lppa_PrivateMessage,

/*--- End of included file: packet-lppa-ettarr.c ---*/
#line 104 "../../asn1/lppa/packet-lppa-template.c"
  };

  /* Register protocol */
  proto_lppa = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("lppa", dissect_LPPA_PDU_PDU, proto_lppa);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lppa, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

   /* Register dissector tables */
  lppa_ies_dissector_table = register_dissector_table("lppa.ies", "LPPA-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  lppa_proc_imsg_dissector_table = register_dissector_table("lppa.proc.imsg", "LPPA-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  lppa_proc_sout_dissector_table = register_dissector_table("lppa.proc.sout", "LPPA-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  lppa_proc_uout_dissector_table = register_dissector_table("lppa.proc.uout", "LPPA-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);
}

/*--- proto_reg_handoff_lppa ---------------------------------------*/
void
proto_reg_handoff_lppa(void)
{

/*--- Included file: packet-lppa-dis-tab.c ---*/
#line 1 "../../asn1/lppa/packet-lppa-dis-tab.c"
  dissector_add_uint("lppa.ies", id_MeasurementQuantities_Item, new_create_dissector_handle(dissect_MeasurementQuantities_Item_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_ReportCharacteristics, new_create_dissector_handle(dissect_ReportCharacteristics_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_MeasurementPeriodicity, new_create_dissector_handle(dissect_MeasurementPeriodicity_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_MeasurementQuantities, new_create_dissector_handle(dissect_MeasurementQuantities_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_E_CID_MeasurementResult, new_create_dissector_handle(dissect_E_CID_MeasurementResult_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_OTDOA_Information_Type_Group, new_create_dissector_handle(dissect_OTDOA_Information_Type_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_OTDOA_Information_Type_Item, new_create_dissector_handle(dissect_OTDOA_Information_Type_Item_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_OTDOACells, new_create_dissector_handle(dissect_OTDOACells_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_Cause, new_create_dissector_handle(dissect_Cause_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_CriticalityDiagnostics, new_create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_E_SMLC_UE_Measurement_ID, new_create_dissector_handle(dissect_Measurement_ID_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_eNB_UE_Measurement_ID, new_create_dissector_handle(dissect_Measurement_ID_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_RequestedSRSTransmissionCharacteristics, new_create_dissector_handle(dissect_RequestedSRSTransmissionCharacteristics_PDU, proto_lppa));
  dissector_add_uint("lppa.ies", id_ULConfiguration, new_create_dissector_handle(dissect_ULConfiguration_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_e_CIDMeasurementInitiation, new_create_dissector_handle(dissect_E_CIDMeasurementInitiationRequest_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.sout", id_e_CIDMeasurementInitiation, new_create_dissector_handle(dissect_E_CIDMeasurementInitiationResponse_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.uout", id_e_CIDMeasurementInitiation, new_create_dissector_handle(dissect_E_CIDMeasurementInitiationFailure_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_e_CIDMeasurementFailureIndication, new_create_dissector_handle(dissect_E_CIDMeasurementFailureIndication_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_e_CIDMeasurementReport, new_create_dissector_handle(dissect_E_CIDMeasurementReport_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_e_CIDMeasurementTermination, new_create_dissector_handle(dissect_E_CIDMeasurementTerminationCommand_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_oTDOAInformationExchange, new_create_dissector_handle(dissect_OTDOAInformationRequest_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.sout", id_oTDOAInformationExchange, new_create_dissector_handle(dissect_OTDOAInformationResponse_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.uout", id_oTDOAInformationExchange, new_create_dissector_handle(dissect_OTDOAInformationFailure_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_errorIndication, new_create_dissector_handle(dissect_ErrorIndication_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_privateMessage, new_create_dissector_handle(dissect_PrivateMessage_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_uTDOAInformationExchange, new_create_dissector_handle(dissect_UTDOAInformationRequest_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.sout", id_uTDOAInformationExchange, new_create_dissector_handle(dissect_UTDOAInformationResponse_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.uout", id_uTDOAInformationExchange, new_create_dissector_handle(dissect_UTDOAInformationFailure_PDU, proto_lppa));
  dissector_add_uint("lppa.proc.imsg", id_uTDOAInformationUpdate, new_create_dissector_handle(dissect_UTDOAInformationUpdate_PDU, proto_lppa));


/*--- End of included file: packet-lppa-dis-tab.c ---*/
#line 126 "../../asn1/lppa/packet-lppa-template.c"
}
