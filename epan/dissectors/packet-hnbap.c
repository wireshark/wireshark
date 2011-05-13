/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-hnbap.c                                                             */
/* ../../tools/asn2wrs.py -p hnbap -c ./hnbap.cnf -s ./packet-hnbap-template -D . HNBAP-CommonDataTypes.asn HNBAP-Constants.asn HNBAP-Containers.asn HNBAP-IEs.asn HNBAP-PDU-Contents.asn HNBAP-PDU-Descriptions.asn */

/* Input file: packet-hnbap-template.c */

#line 1 "../../asn1/hnbap/packet-hnbap-template.c"
/* packet-hnbap-template.c
 * Routines for UMTS Node B Application Part(HNBAP) packet dissection
 * Copyright 2010 Neil Piercy, ip.access Limited <Neil.Piercy@ipaccess.com>
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
 * Ref: 3GPP TS 25.469 version 8.4.0 Release 8
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/sctpppids.h>
#include <epan/asn1.h>
#include <epan/prefs.h>

#include "packet-per.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "UTRAN Iuh interface HNBAP signalling"
#define PSNAME "HNBAP"
#define PFNAME "hnbap"
/* Dissector will use SCTP PPID 20 or SCTP port. IANA assigned port = 29169*/
#define SCTP_PORT_HNBAP              29169


/*--- Included file: packet-hnbap-val.h ---*/
#line 1 "../../asn1/hnbap/packet-hnbap-val.h"
#define maxPrivateIEs                  65535
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535
#define maxNrOfErrors                  256

typedef enum _ProcedureCode_enum {
  id_HNBRegister =   1,
  id_HNBDe_Register =   2,
  id_UERegister =   3,
  id_UEDe_Register =   4,
  id_ErrorIndication =   5,
  id_privateMessage =   6,
  id_CSGMembershipUpdate =   7
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Cause     =   1,
  id_CriticalityDiagnostics =   2,
  id_HNB_Identity =   3,
  id_Context_ID =   4,
  id_UE_Identity =   5,
  id_LAC       =   6,
  id_RAC       =   7,
  id_HNB_Location_Information =   8,
  id_PLMNidentity =   9,
  id_SAC       =  10,
  id_CellIdentity =  11,
  id_Registration_Cause =  12,
  id_UE_Capabilities =  13,
  id_RNC_ID    =  14,
  id_CSG_ID    =  15,
  id_BackoffTimer =  16,
  id_HNB_Internet_Information =  17,
  id_HNB_Cell_Access_Mode =  18,
  id_MuxPortNumber =  19,
  id_Service_Area_For_Broadcast =  20,
  id_CSGMembershipStatus =  21
} ProtocolIE_ID_enum;

/*--- End of included file: packet-hnbap-val.h ---*/
#line 54 "../../asn1/hnbap/packet-hnbap-template.c"

/* Initialize the protocol and registered fields */
static int proto_hnbap = -1;


/*--- Included file: packet-hnbap-hf.c ---*/
#line 1 "../../asn1/hnbap/packet-hnbap-hf.c"
static int hf_hnbap_BackoffTimer_PDU = -1;        /* BackoffTimer */
static int hf_hnbap_Cause_PDU = -1;               /* Cause */
static int hf_hnbap_CellIdentity_PDU = -1;        /* CellIdentity */
static int hf_hnbap_Context_ID_PDU = -1;          /* Context_ID */
static int hf_hnbap_CriticalityDiagnostics_PDU = -1;  /* CriticalityDiagnostics */
static int hf_hnbap_CSG_ID_PDU = -1;              /* CSG_ID */
static int hf_hnbap_CSGMembershipStatus_PDU = -1;  /* CSGMembershipStatus */
static int hf_hnbap_HNB_Cell_Access_Mode_PDU = -1;  /* HNB_Cell_Access_Mode */
static int hf_hnbap_HNB_Location_Information_PDU = -1;  /* HNB_Location_Information */
static int hf_hnbap_HNB_Identity_PDU = -1;        /* HNB_Identity */
static int hf_hnbap_IP_Address_PDU = -1;          /* IP_Address */
static int hf_hnbap_LAC_PDU = -1;                 /* LAC */
static int hf_hnbap_MuxPortNumber_PDU = -1;       /* MuxPortNumber */
static int hf_hnbap_PLMNidentity_PDU = -1;        /* PLMNidentity */
static int hf_hnbap_RAC_PDU = -1;                 /* RAC */
static int hf_hnbap_Registration_Cause_PDU = -1;  /* Registration_Cause */
static int hf_hnbap_RNC_ID_PDU = -1;              /* RNC_ID */
static int hf_hnbap_SAC_PDU = -1;                 /* SAC */
static int hf_hnbap_UE_Capabilities_PDU = -1;     /* UE_Capabilities */
static int hf_hnbap_UE_Identity_PDU = -1;         /* UE_Identity */
static int hf_hnbap_HNBRegisterRequest_PDU = -1;  /* HNBRegisterRequest */
static int hf_hnbap_HNBRegisterAccept_PDU = -1;   /* HNBRegisterAccept */
static int hf_hnbap_HNBRegisterReject_PDU = -1;   /* HNBRegisterReject */
static int hf_hnbap_HNBDe_Register_PDU = -1;      /* HNBDe_Register */
static int hf_hnbap_UERegisterRequest_PDU = -1;   /* UERegisterRequest */
static int hf_hnbap_UERegisterAccept_PDU = -1;    /* UERegisterAccept */
static int hf_hnbap_UERegisterReject_PDU = -1;    /* UERegisterReject */
static int hf_hnbap_UEDe_Register_PDU = -1;       /* UEDe_Register */
static int hf_hnbap_CSGMembershipUpdate_PDU = -1;  /* CSGMembershipUpdate */
static int hf_hnbap_ErrorIndication_PDU = -1;     /* ErrorIndication */
static int hf_hnbap_PrivateMessage_PDU = -1;      /* PrivateMessage */
static int hf_hnbap_HNBAP_PDU_PDU = -1;           /* HNBAP_PDU */
static int hf_hnbap_local = -1;                   /* INTEGER_0_65535 */
static int hf_hnbap_global = -1;                  /* OBJECT_IDENTIFIER */
static int hf_hnbap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_hnbap_protocol_ie_field_id = -1;    /* ProtocolIE_ID */
static int hf_hnbap_criticality = -1;             /* Criticality */
static int hf_hnbap_ie_field_value = -1;          /* ProtocolIE_Field_value */
static int hf_hnbap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_hnbap_id = -1;                      /* ProtocolIE_ID */
static int hf_hnbap_extensionValue = -1;          /* T_extensionValue */
static int hf_hnbap_PrivateIE_Container_item = -1;  /* PrivateIE_Field */
static int hf_hnbap_private_ie_field_id = -1;     /* PrivateIE_ID */
static int hf_hnbap_private_value = -1;           /* PrivateIE_Field_value */
static int hf_hnbap_directionOfAltitude = -1;     /* T_directionOfAltitude */
static int hf_hnbap_altitude = -1;                /* INTEGER_0_32767 */
static int hf_hnbap_radioNetwork = -1;            /* CauseRadioNetwork */
static int hf_hnbap_transport = -1;               /* CauseTransport */
static int hf_hnbap_protocol = -1;                /* CauseProtocol */
static int hf_hnbap_misc = -1;                    /* CauseMisc */
static int hf_hnbap_procedureCode = -1;           /* ProcedureCode */
static int hf_hnbap_triggeringMessage = -1;       /* TriggeringMessage */
static int hf_hnbap_procedureCriticality = -1;    /* Criticality */
static int hf_hnbap_iEsCriticalityDiagnostics = -1;  /* CriticalityDiagnostics_IE_List */
static int hf_hnbap_iE_Extensions = -1;           /* ProtocolExtensionContainer */
static int hf_hnbap_CriticalityDiagnostics_IE_List_item = -1;  /* CriticalityDiagnostics_IE_List_item */
static int hf_hnbap_iECriticality = -1;           /* Criticality */
static int hf_hnbap_iE_ID = -1;                   /* ProtocolIE_ID */
static int hf_hnbap_typeOfError = -1;             /* TypeOfError */
static int hf_hnbap_pLMNidentity = -1;            /* PLMNidentity */
static int hf_hnbap_lAC = -1;                     /* LAC */
static int hf_hnbap_cI = -1;                      /* CI */
static int hf_hnbap_geographical_location_geographical_coordinates = -1;  /* GeographicalCoordinates */
static int hf_hnbap_altitudeAndDirection = -1;    /* AltitudeAndDirection */
static int hf_hnbap_latitudeSign = -1;            /* T_latitudeSign */
static int hf_hnbap_latitude = -1;                /* INTEGER_0_8388607 */
static int hf_hnbap_longitude = -1;               /* INTEGER_M8388608_8388607 */
static int hf_hnbap_macroCoverageInfo = -1;       /* MacroCoverageInformation */
static int hf_hnbap_hnb_location_information_geographical_coordinates = -1;  /* GeographicalLocation */
static int hf_hnbap_hNB_Identity_Info = -1;       /* HNB_Identity_Info */
static int hf_hnbap_iMSIDS41 = -1;                /* IMSIDS41 */
static int hf_hnbap_eSN = -1;                     /* ESN */
static int hf_hnbap_ipaddress = -1;               /* T_ipaddress */
static int hf_hnbap_ipv4info = -1;                /* Ipv4Address */
static int hf_hnbap_ipv6info = -1;                /* Ipv6Address */
static int hf_hnbap_pLMNID = -1;                  /* PLMNidentity */
static int hf_hnbap_cellIdentity = -1;            /* MacroCellID */
static int hf_hnbap_uTRANCellID = -1;             /* UTRANCellID */
static int hf_hnbap_gERANCellID = -1;             /* CGI */
static int hf_hnbap_pTMSI = -1;                   /* PTMSI */
static int hf_hnbap_rAI = -1;                     /* RAI */
static int hf_hnbap_lAI = -1;                     /* LAI */
static int hf_hnbap_rAC = -1;                     /* RAC */
static int hf_hnbap_tMSI = -1;                    /* BIT_STRING_SIZE_32 */
static int hf_hnbap_access_stratum_release_indicator = -1;  /* Access_stratum_release_indicator */
static int hf_hnbap_csg_indicator = -1;           /* CSG_Indicator */
static int hf_hnbap_uTRANcellID = -1;             /* CellIdentity */
static int hf_hnbap_iMSI = -1;                    /* IMSI */
static int hf_hnbap_tMSILAI = -1;                 /* TMSILAI */
static int hf_hnbap_pTMSIRAI = -1;                /* PTMSIRAI */
static int hf_hnbap_iMEI = -1;                    /* IMEI */
static int hf_hnbap_iMSIESN = -1;                 /* IMSIESN */
static int hf_hnbap_tMSIDS41 = -1;                /* TMSIDS41 */
static int hf_hnbap_protocolIEs = -1;             /* ProtocolIE_Container */
static int hf_hnbap_protocolExtensions = -1;      /* ProtocolExtensionContainer */
static int hf_hnbap_privateIEs = -1;              /* PrivateIE_Container */
static int hf_hnbap_initiatingMessage = -1;       /* InitiatingMessage */
static int hf_hnbap_successfulOutcome = -1;       /* SuccessfulOutcome */
static int hf_hnbap_unsuccessfulOutcome = -1;     /* UnsuccessfulOutcome */
static int hf_hnbap_initiatingMessagevalue = -1;  /* InitiatingMessage_value */
static int hf_hnbap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_hnbap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-hnbap-hf.c ---*/
#line 59 "../../asn1/hnbap/packet-hnbap-template.c"

/* Initialize the subtree pointers */
static int ett_hnbap = -1;


/*--- Included file: packet-hnbap-ett.c ---*/
#line 1 "../../asn1/hnbap/packet-hnbap-ett.c"
static gint ett_hnbap_PrivateIE_ID = -1;
static gint ett_hnbap_ProtocolIE_Container = -1;
static gint ett_hnbap_ProtocolIE_Field = -1;
static gint ett_hnbap_ProtocolExtensionContainer = -1;
static gint ett_hnbap_ProtocolExtensionField = -1;
static gint ett_hnbap_PrivateIE_Container = -1;
static gint ett_hnbap_PrivateIE_Field = -1;
static gint ett_hnbap_AltitudeAndDirection = -1;
static gint ett_hnbap_Cause = -1;
static gint ett_hnbap_CriticalityDiagnostics = -1;
static gint ett_hnbap_CriticalityDiagnostics_IE_List = -1;
static gint ett_hnbap_CriticalityDiagnostics_IE_List_item = -1;
static gint ett_hnbap_CGI = -1;
static gint ett_hnbap_GeographicalLocation = -1;
static gint ett_hnbap_GeographicalCoordinates = -1;
static gint ett_hnbap_HNB_Location_Information = -1;
static gint ett_hnbap_HNB_Identity = -1;
static gint ett_hnbap_IMSIESN = -1;
static gint ett_hnbap_IP_Address = -1;
static gint ett_hnbap_T_ipaddress = -1;
static gint ett_hnbap_LAI = -1;
static gint ett_hnbap_MacroCoverageInformation = -1;
static gint ett_hnbap_MacroCellID = -1;
static gint ett_hnbap_PTMSIRAI = -1;
static gint ett_hnbap_RAI = -1;
static gint ett_hnbap_TMSILAI = -1;
static gint ett_hnbap_UE_Capabilities = -1;
static gint ett_hnbap_UTRANCellID = -1;
static gint ett_hnbap_UE_Identity = -1;
static gint ett_hnbap_HNBRegisterRequest = -1;
static gint ett_hnbap_HNBRegisterAccept = -1;
static gint ett_hnbap_HNBRegisterReject = -1;
static gint ett_hnbap_HNBDe_Register = -1;
static gint ett_hnbap_UERegisterRequest = -1;
static gint ett_hnbap_UERegisterAccept = -1;
static gint ett_hnbap_UERegisterReject = -1;
static gint ett_hnbap_UEDe_Register = -1;
static gint ett_hnbap_CSGMembershipUpdate = -1;
static gint ett_hnbap_ErrorIndication = -1;
static gint ett_hnbap_PrivateMessage = -1;
static gint ett_hnbap_HNBAP_PDU = -1;
static gint ett_hnbap_InitiatingMessage = -1;
static gint ett_hnbap_SuccessfulOutcome = -1;
static gint ett_hnbap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-hnbap-ett.c ---*/
#line 64 "../../asn1/hnbap/packet-hnbap-template.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint global_sctp_port = SCTP_PORT_HNBAP;

/* Dissector tables */
static dissector_table_t hnbap_ies_dissector_table;
static dissector_table_t hnbap_extension_dissector_table;
static dissector_table_t hnbap_proc_imsg_dissector_table;
static dissector_table_t hnbap_proc_sout_dissector_table;
static dissector_table_t hnbap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
void proto_reg_handoff_hnbap(void);


/*--- Included file: packet-hnbap-fn.c ---*/
#line 1 "../../asn1/hnbap/packet-hnbap-fn.c"

static const value_string hnbap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_hnbap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_hnbap_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_hnbap_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const value_string hnbap_PrivateIE_ID_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const per_choice_t PrivateIE_ID_choice[] = {
  {   0, &hf_hnbap_local         , ASN1_NO_EXTENSIONS     , dissect_hnbap_INTEGER_0_65535 },
  {   1, &hf_hnbap_global        , ASN1_NO_EXTENSIONS     , dissect_hnbap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, NULL }
};

static int
dissect_hnbap_PrivateIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_hnbap_PrivateIE_ID, PrivateIE_ID_choice,
                                 NULL);

  return offset;
}


static const value_string hnbap_ProcedureCode_vals[] = {
  { id_HNBRegister, "id-HNBRegister" },
  { id_HNBDe_Register, "id-HNBDe-Register" },
  { id_UERegister, "id-UERegister" },
  { id_UEDe_Register, "id-UEDe-Register" },
  { id_ErrorIndication, "id-ErrorIndication" },
  { id_privateMessage, "id-privateMessage" },
  { id_CSGMembershipUpdate, "id-CSGMembershipUpdate" },
  { 0, NULL }
};


static int
dissect_hnbap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 59 "../../asn1/hnbap/hnbap.cnf"
  if (strcmp(val_to_str(ProcedureCode, hnbap_ProcedureCode_vals, "Unknown"), "Unknown") == 0) {
    col_set_str(actx->pinfo->cinfo, COL_INFO,
                      "Unknown Message");
  } /* Known Procedures should be included below and broken out as ELEMENTARY names to avoid confusion */


  return offset;
}


static const value_string hnbap_ProtocolIE_ID_vals[] = {
  { id_Cause, "id-Cause" },
  { id_CriticalityDiagnostics, "id-CriticalityDiagnostics" },
  { id_HNB_Identity, "id-HNB-Identity" },
  { id_Context_ID, "id-Context-ID" },
  { id_UE_Identity, "id-UE-Identity" },
  { id_LAC, "id-LAC" },
  { id_RAC, "id-RAC" },
  { id_HNB_Location_Information, "id-HNB-Location-Information" },
  { id_PLMNidentity, "id-PLMNidentity" },
  { id_SAC, "id-SAC" },
  { id_CellIdentity, "id-CellIdentity" },
  { id_Registration_Cause, "id-Registration-Cause" },
  { id_UE_Capabilities, "id-UE-Capabilities" },
  { id_RNC_ID, "id-RNC-ID" },
  { id_CSG_ID, "id-CSG-ID" },
  { id_BackoffTimer, "id-BackoffTimer" },
  { id_HNB_Internet_Information, "id-HNB-Internet-Information" },
  { id_HNB_Cell_Access_Mode, "id-HNB-Cell-Access-Mode" },
  { id_MuxPortNumber, "id-MuxPortNumber" },
  { id_Service_Area_For_Broadcast, "id-Service-Area-For-Broadcast" },
  { id_CSGMembershipStatus, "id-CSGMembershipStatus" },
  { 0, NULL }
};


static int
dissect_hnbap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxProtocolIEs, &ProtocolIE_ID, FALSE);

#line 48 "../../asn1/hnbap/hnbap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(ProtocolIE_ID, VALS(hnbap_ProtocolIE_ID_vals), "unknown (%d)"));
  }

  return offset;
}


static const value_string hnbap_TriggeringMessage_vals[] = {
  {   0, "initiating-message" },
  {   1, "successful-outcome" },
  {   2, "unsuccessful-outcome" },
  { 0, NULL }
};


static int
dissect_hnbap_TriggeringMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_hnbap_ProtocolIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_hnbap_protocol_ie_field_id, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_ID },
  { &hf_hnbap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_Criticality },
  { &hf_hnbap_ie_field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_hnbap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Field },
};

static int
dissect_hnbap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_hnbap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_hnbap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_hnbap_id            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_ID },
  { &hf_hnbap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_Criticality },
  { &hf_hnbap_extensionValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_hnbap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolExtensionField },
};

static int
dissect_hnbap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_hnbap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_hnbap_PrivateIE_Field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateIE_Field_sequence[] = {
  { &hf_hnbap_private_ie_field_id, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_PrivateIE_ID },
  { &hf_hnbap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_Criticality },
  { &hf_hnbap_private_value , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_PrivateIE_Field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_PrivateIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_PrivateIE_Field, PrivateIE_Field_sequence);

  return offset;
}


static const per_sequence_t PrivateIE_Container_sequence_of[1] = {
  { &hf_hnbap_PrivateIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_PrivateIE_Field },
};

static int
dissect_hnbap_PrivateIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_hnbap_PrivateIE_Container, PrivateIE_Container_sequence_of,
                                                  1, maxPrivateIEs, FALSE);

  return offset;
}


static const value_string hnbap_Access_stratum_release_indicator_vals[] = {
  {   0, "r99" },
  {   1, "rel-4" },
  {   2, "rel-5" },
  {   3, "rel-6" },
  {   4, "rel-7" },
  {   5, "rel-8-and-beyond" },
  { 0, NULL }
};


static int
dissect_hnbap_Access_stratum_release_indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string hnbap_T_directionOfAltitude_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_hnbap_T_directionOfAltitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_hnbap_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}


static const per_sequence_t AltitudeAndDirection_sequence[] = {
  { &hf_hnbap_directionOfAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_T_directionOfAltitude },
  { &hf_hnbap_altitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_INTEGER_0_32767 },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_AltitudeAndDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_AltitudeAndDirection, AltitudeAndDirection_sequence);

  return offset;
}



static int
dissect_hnbap_BackoffTimer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3600U, NULL, FALSE);

  return offset;
}


static const value_string hnbap_CauseRadioNetwork_vals[] = {
  {   0, "overload" },
  {   1, "unauthorised-Location" },
  {   2, "unauthorised-HNB" },
  {   3, "hNB-parameter-mismatch" },
  {   4, "invalid-UE-identity" },
  {   5, "uE-not-allowed-on-this-HNB" },
  {   6, "uE-unauthorised" },
  {   7, "connection-with-UE-lost" },
  {   8, "ue-RRC-telease" },
  {   9, "hNB-not-registered" },
  {  10, "unspecified" },
  {  11, "normal" },
  {  12, "uE-relocated" },
  {  13, "ue-registered-in-another-HNB" },
  { 0, NULL }
};


static int
dissect_hnbap_CauseRadioNetwork(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string hnbap_CauseTransport_vals[] = {
  {   0, "transport-resource-unavailable" },
  {   1, "unspecified" },
  { 0, NULL }
};


static int
dissect_hnbap_CauseTransport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string hnbap_CauseProtocol_vals[] = {
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
dissect_hnbap_CauseProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string hnbap_CauseMisc_vals[] = {
  {   0, "processing-overload" },
  {   1, "hardware-failure" },
  {   2, "o-and-m-intervention" },
  {   3, "unspecified" },
  { 0, NULL }
};


static int
dissect_hnbap_CauseMisc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string hnbap_Cause_vals[] = {
  {   0, "radioNetwork" },
  {   1, "transport" },
  {   2, "protocol" },
  {   3, "misc" },
  { 0, NULL }
};

static const per_choice_t Cause_choice[] = {
  {   0, &hf_hnbap_radioNetwork  , ASN1_EXTENSION_ROOT    , dissect_hnbap_CauseRadioNetwork },
  {   1, &hf_hnbap_transport     , ASN1_EXTENSION_ROOT    , dissect_hnbap_CauseTransport },
  {   2, &hf_hnbap_protocol      , ASN1_EXTENSION_ROOT    , dissect_hnbap_CauseProtocol },
  {   3, &hf_hnbap_misc          , ASN1_EXTENSION_ROOT    , dissect_hnbap_CauseMisc },
  { 0, NULL, 0, NULL }
};

static int
dissect_hnbap_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_hnbap_Cause, Cause_choice,
                                 NULL);

  return offset;
}



static int
dissect_hnbap_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL);

  return offset;
}



static int
dissect_hnbap_Context_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, FALSE, NULL);

  return offset;
}


static const value_string hnbap_TypeOfError_vals[] = {
  {   0, "not-understood" },
  {   1, "missing" },
  { 0, NULL }
};


static int
dissect_hnbap_TypeOfError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_item_sequence[] = {
  { &hf_hnbap_iECriticality , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_Criticality },
  { &hf_hnbap_iE_ID         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_ID },
  { &hf_hnbap_typeOfError   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_TypeOfError },
  { &hf_hnbap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_CriticalityDiagnostics_IE_List_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_CriticalityDiagnostics_IE_List_item, CriticalityDiagnostics_IE_List_item_sequence);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_IE_List_sequence_of[1] = {
  { &hf_hnbap_CriticalityDiagnostics_IE_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_CriticalityDiagnostics_IE_List_item },
};

static int
dissect_hnbap_CriticalityDiagnostics_IE_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_hnbap_CriticalityDiagnostics_IE_List, CriticalityDiagnostics_IE_List_sequence_of,
                                                  1, maxNrOfErrors, FALSE);

  return offset;
}


static const per_sequence_t CriticalityDiagnostics_sequence[] = {
  { &hf_hnbap_procedureCode , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProcedureCode },
  { &hf_hnbap_triggeringMessage, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_TriggeringMessage },
  { &hf_hnbap_procedureCriticality, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_Criticality },
  { &hf_hnbap_iEsCriticalityDiagnostics, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_CriticalityDiagnostics_IE_List },
  { &hf_hnbap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_CriticalityDiagnostics(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_CriticalityDiagnostics, CriticalityDiagnostics_sequence);

  return offset;
}



static int
dissect_hnbap_CSG_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     27, 27, FALSE, NULL);

  return offset;
}


static const value_string hnbap_CSG_Indicator_vals[] = {
  {   0, "csg-capable" },
  {   1, "not-csg-capable" },
  { 0, NULL }
};


static int
dissect_hnbap_CSG_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string hnbap_CSGMembershipStatus_vals[] = {
  {   0, "member" },
  {   1, "non-member" },
  { 0, NULL }
};


static int
dissect_hnbap_CSGMembershipStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_hnbap_PLMNidentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_hnbap_LAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_hnbap_CI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}


static const per_sequence_t CGI_sequence[] = {
  { &hf_hnbap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_PLMNidentity },
  { &hf_hnbap_lAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_LAC },
  { &hf_hnbap_cI            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_CI },
  { &hf_hnbap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_CGI, CGI_sequence);

  return offset;
}



static int
dissect_hnbap_ESN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, NULL);

  return offset;
}


static const value_string hnbap_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_hnbap_T_latitudeSign(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_hnbap_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, FALSE);

  return offset;
}



static int
dissect_hnbap_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GeographicalCoordinates_sequence[] = {
  { &hf_hnbap_latitudeSign  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_T_latitudeSign },
  { &hf_hnbap_latitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_INTEGER_0_8388607 },
  { &hf_hnbap_longitude     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_INTEGER_M8388608_8388607 },
  { &hf_hnbap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_GeographicalCoordinates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_GeographicalCoordinates, GeographicalCoordinates_sequence);

  return offset;
}


static const per_sequence_t GeographicalLocation_sequence[] = {
  { &hf_hnbap_geographical_location_geographical_coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_GeographicalCoordinates },
  { &hf_hnbap_altitudeAndDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_AltitudeAndDirection },
  { &hf_hnbap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_GeographicalLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_GeographicalLocation, GeographicalLocation_sequence);

  return offset;
}


static const value_string hnbap_HNB_Cell_Access_Mode_vals[] = {
  {   0, "closed" },
  {   1, "hybrid" },
  {   2, "open" },
  { 0, NULL }
};


static int
dissect_hnbap_HNB_Cell_Access_Mode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_hnbap_RAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t UTRANCellID_sequence[] = {
  { &hf_hnbap_lAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_LAC },
  { &hf_hnbap_rAC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_RAC },
  { &hf_hnbap_pLMNidentity  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_PLMNidentity },
  { &hf_hnbap_uTRANcellID   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_CellIdentity },
  { &hf_hnbap_iE_Extensions , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_UTRANCellID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_UTRANCellID, UTRANCellID_sequence);

  return offset;
}


static const value_string hnbap_MacroCellID_vals[] = {
  {   0, "uTRANCellID" },
  {   1, "gERANCellID" },
  { 0, NULL }
};

static const per_choice_t MacroCellID_choice[] = {
  {   0, &hf_hnbap_uTRANCellID   , ASN1_EXTENSION_ROOT    , dissect_hnbap_UTRANCellID },
  {   1, &hf_hnbap_gERANCellID   , ASN1_EXTENSION_ROOT    , dissect_hnbap_CGI },
  { 0, NULL, 0, NULL }
};

static int
dissect_hnbap_MacroCellID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_hnbap_MacroCellID, MacroCellID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t MacroCoverageInformation_sequence[] = {
  { &hf_hnbap_cellIdentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_MacroCellID },
  { &hf_hnbap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_MacroCoverageInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_MacroCoverageInformation, MacroCoverageInformation_sequence);

  return offset;
}


static const per_sequence_t HNB_Location_Information_sequence[] = {
  { &hf_hnbap_macroCoverageInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_MacroCoverageInformation },
  { &hf_hnbap_hnb_location_information_geographical_coordinates, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_GeographicalLocation },
  { &hf_hnbap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_HNB_Location_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_HNB_Location_Information, HNB_Location_Information_sequence);

  return offset;
}



static int
dissect_hnbap_HNB_Identity_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 255, FALSE, NULL);

  return offset;
}


static const per_sequence_t HNB_Identity_sequence[] = {
  { &hf_hnbap_hNB_Identity_Info, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_HNB_Identity_Info },
  { &hf_hnbap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_HNB_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_HNB_Identity, HNB_Identity_sequence);

  return offset;
}



static int
dissect_hnbap_IMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     60, 60, FALSE, NULL);

  return offset;
}



static int
dissect_hnbap_IMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 8, FALSE, NULL);

  return offset;
}



static int
dissect_hnbap_IMSIDS41(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       5, 7, FALSE, NULL);

  return offset;
}


static const per_sequence_t IMSIESN_sequence[] = {
  { &hf_hnbap_iMSIDS41      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_IMSIDS41 },
  { &hf_hnbap_eSN           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_ESN },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_IMSIESN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_IMSIESN, IMSIESN_sequence);

  return offset;
}



static int
dissect_hnbap_Ipv4Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_hnbap_Ipv6Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, FALSE, NULL);

  return offset;
}


static const value_string hnbap_T_ipaddress_vals[] = {
  {   0, "ipv4info" },
  {   1, "ipv6info" },
  { 0, NULL }
};

static const per_choice_t T_ipaddress_choice[] = {
  {   0, &hf_hnbap_ipv4info      , ASN1_EXTENSION_ROOT    , dissect_hnbap_Ipv4Address },
  {   1, &hf_hnbap_ipv6info      , ASN1_EXTENSION_ROOT    , dissect_hnbap_Ipv6Address },
  { 0, NULL, 0, NULL }
};

static int
dissect_hnbap_T_ipaddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_hnbap_T_ipaddress, T_ipaddress_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t IP_Address_sequence[] = {
  { &hf_hnbap_ipaddress     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_T_ipaddress },
  { &hf_hnbap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_IP_Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_IP_Address, IP_Address_sequence);

  return offset;
}


static const per_sequence_t LAI_sequence[] = {
  { &hf_hnbap_pLMNID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_PLMNidentity },
  { &hf_hnbap_lAC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_LAC },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_LAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_LAI, LAI_sequence);

  return offset;
}



static int
dissect_hnbap_MuxPortNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1024U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_hnbap_PTMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, NULL);

  return offset;
}


static const per_sequence_t RAI_sequence[] = {
  { &hf_hnbap_lAI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_LAI },
  { &hf_hnbap_rAC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_RAC },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_RAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_RAI, RAI_sequence);

  return offset;
}


static const per_sequence_t PTMSIRAI_sequence[] = {
  { &hf_hnbap_pTMSI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_PTMSI },
  { &hf_hnbap_rAI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_RAI },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_PTMSIRAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_PTMSIRAI, PTMSIRAI_sequence);

  return offset;
}


static const value_string hnbap_Registration_Cause_vals[] = {
  {   0, "emergency-call" },
  {   1, "normal" },
  { 0, NULL }
};


static int
dissect_hnbap_Registration_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_hnbap_RNC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_hnbap_SAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, FALSE, NULL);

  return offset;
}



static int
dissect_hnbap_BIT_STRING_SIZE_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE, NULL);

  return offset;
}


static const per_sequence_t TMSILAI_sequence[] = {
  { &hf_hnbap_tMSI          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_BIT_STRING_SIZE_32 },
  { &hf_hnbap_lAI           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_LAI },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_TMSILAI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_TMSILAI, TMSILAI_sequence);

  return offset;
}



static int
dissect_hnbap_TMSIDS41(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 17, FALSE, NULL);

  return offset;
}


static const per_sequence_t UE_Capabilities_sequence[] = {
  { &hf_hnbap_access_stratum_release_indicator, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_Access_stratum_release_indicator },
  { &hf_hnbap_csg_indicator , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_CSG_Indicator },
  { &hf_hnbap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_UE_Capabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_UE_Capabilities, UE_Capabilities_sequence);

  return offset;
}


static const value_string hnbap_UE_Identity_vals[] = {
  {   0, "iMSI" },
  {   1, "tMSILAI" },
  {   2, "pTMSIRAI" },
  {   3, "iMEI" },
  {   4, "eSN" },
  {   5, "iMSIDS41" },
  {   6, "iMSIESN" },
  {   7, "tMSIDS41" },
  { 0, NULL }
};

static const per_choice_t UE_Identity_choice[] = {
  {   0, &hf_hnbap_iMSI          , ASN1_EXTENSION_ROOT    , dissect_hnbap_IMSI },
  {   1, &hf_hnbap_tMSILAI       , ASN1_EXTENSION_ROOT    , dissect_hnbap_TMSILAI },
  {   2, &hf_hnbap_pTMSIRAI      , ASN1_EXTENSION_ROOT    , dissect_hnbap_PTMSIRAI },
  {   3, &hf_hnbap_iMEI          , ASN1_EXTENSION_ROOT    , dissect_hnbap_IMEI },
  {   4, &hf_hnbap_eSN           , ASN1_EXTENSION_ROOT    , dissect_hnbap_ESN },
  {   5, &hf_hnbap_iMSIDS41      , ASN1_EXTENSION_ROOT    , dissect_hnbap_IMSIDS41 },
  {   6, &hf_hnbap_iMSIESN       , ASN1_EXTENSION_ROOT    , dissect_hnbap_IMSIESN },
  {   7, &hf_hnbap_tMSIDS41      , ASN1_EXTENSION_ROOT    , dissect_hnbap_TMSIDS41 },
  { 0, NULL, 0, NULL }
};

static int
dissect_hnbap_UE_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_hnbap_UE_Identity, UE_Identity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t HNBRegisterRequest_sequence[] = {
  { &hf_hnbap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Container },
  { &hf_hnbap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_HNBRegisterRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 72 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "HNB_REGISTER_REQUEST ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_HNBRegisterRequest, HNBRegisterRequest_sequence);




  return offset;
}


static const per_sequence_t HNBRegisterAccept_sequence[] = {
  { &hf_hnbap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Container },
  { &hf_hnbap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_HNBRegisterAccept(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 77 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "HNB_REGISTER_ACCEPT ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_HNBRegisterAccept, HNBRegisterAccept_sequence);




  return offset;
}


static const per_sequence_t HNBRegisterReject_sequence[] = {
  { &hf_hnbap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Container },
  { &hf_hnbap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_HNBRegisterReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 82 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "HNB_REGISTER_REJECT ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_HNBRegisterReject, HNBRegisterReject_sequence);




  return offset;
}


static const per_sequence_t HNBDe_Register_sequence[] = {
  { &hf_hnbap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Container },
  { &hf_hnbap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_HNBDe_Register(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 107 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "HNB_DE-REGISTER ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_HNBDe_Register, HNBDe_Register_sequence);




  return offset;
}


static const per_sequence_t UERegisterRequest_sequence[] = {
  { &hf_hnbap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Container },
  { &hf_hnbap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_UERegisterRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 87 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "UE_REGISTER_REQUEST ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_UERegisterRequest, UERegisterRequest_sequence);




  return offset;
}


static const per_sequence_t UERegisterAccept_sequence[] = {
  { &hf_hnbap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Container },
  { &hf_hnbap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_UERegisterAccept(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 92 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "UE_REGISTER_ACCEPT ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_UERegisterAccept, UERegisterAccept_sequence);




  return offset;
}


static const per_sequence_t UERegisterReject_sequence[] = {
  { &hf_hnbap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Container },
  { &hf_hnbap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_UERegisterReject(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 97 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "UE_REGISTER_REJECT ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_UERegisterReject, UERegisterReject_sequence);




  return offset;
}


static const per_sequence_t UEDe_Register_sequence[] = {
  { &hf_hnbap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Container },
  { &hf_hnbap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_UEDe_Register(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 102 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "UE_DE-REGISTER ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_UEDe_Register, UEDe_Register_sequence);




  return offset;
}


static const per_sequence_t CSGMembershipUpdate_sequence[] = {
  { &hf_hnbap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Container },
  { &hf_hnbap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_CSGMembershipUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 118 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "CSG_MEMBERSHIP_UPDATE_MESSAGE ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_CSGMembershipUpdate, CSGMembershipUpdate_sequence);




  return offset;
}


static const per_sequence_t ErrorIndication_sequence[] = {
  { &hf_hnbap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_ProtocolIE_Container },
  { &hf_hnbap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hnbap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_ErrorIndication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 112 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "ERROR_INDICATION ");
    col_set_fence(actx->pinfo->cinfo, COL_INFO); /* Protect info from CriticalityDiagnostics decodes */
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_ErrorIndication, ErrorIndication_sequence);




  return offset;
}


static const per_sequence_t PrivateMessage_sequence[] = {
  { &hf_hnbap_privateIEs    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_hnbap_PrivateIE_Container },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_PrivateMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 123 "../../asn1/hnbap/hnbap.cnf"
    col_set_str(actx->pinfo->cinfo, COL_INFO,
               "PRIVATE_MESSAGE ");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_PrivateMessage, PrivateMessage_sequence);



  return offset;
}



static int
dissect_hnbap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_hnbap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_ProcedureCode },
  { &hf_hnbap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_Criticality },
  { &hf_hnbap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_hnbap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_hnbap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_ProcedureCode },
  { &hf_hnbap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_Criticality },
  { &hf_hnbap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_hnbap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_hnbap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_ProcedureCode },
  { &hf_hnbap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_Criticality },
  { &hf_hnbap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_hnbap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_hnbap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_hnbap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string hnbap_HNBAP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t HNBAP_PDU_choice[] = {
  {   0, &hf_hnbap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_hnbap_InitiatingMessage },
  {   1, &hf_hnbap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_hnbap_SuccessfulOutcome },
  {   2, &hf_hnbap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_hnbap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_hnbap_HNBAP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_hnbap_HNBAP_PDU, HNBAP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_BackoffTimer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_BackoffTimer(tvb, offset, &asn1_ctx, tree, hf_hnbap_BackoffTimer_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_Cause(tvb, offset, &asn1_ctx, tree, hf_hnbap_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CellIdentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_CellIdentity(tvb, offset, &asn1_ctx, tree, hf_hnbap_CellIdentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Context_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_Context_ID(tvb, offset, &asn1_ctx, tree, hf_hnbap_Context_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CriticalityDiagnostics_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_CriticalityDiagnostics(tvb, offset, &asn1_ctx, tree, hf_hnbap_CriticalityDiagnostics_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSG_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_CSG_ID(tvb, offset, &asn1_ctx, tree, hf_hnbap_CSG_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSGMembershipStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_CSGMembershipStatus(tvb, offset, &asn1_ctx, tree, hf_hnbap_CSGMembershipStatus_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HNB_Cell_Access_Mode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_HNB_Cell_Access_Mode(tvb, offset, &asn1_ctx, tree, hf_hnbap_HNB_Cell_Access_Mode_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HNB_Location_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_HNB_Location_Information(tvb, offset, &asn1_ctx, tree, hf_hnbap_HNB_Location_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HNB_Identity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_HNB_Identity(tvb, offset, &asn1_ctx, tree, hf_hnbap_HNB_Identity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IP_Address_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_IP_Address(tvb, offset, &asn1_ctx, tree, hf_hnbap_IP_Address_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LAC_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_LAC(tvb, offset, &asn1_ctx, tree, hf_hnbap_LAC_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MuxPortNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_MuxPortNumber(tvb, offset, &asn1_ctx, tree, hf_hnbap_MuxPortNumber_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PLMNidentity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_PLMNidentity(tvb, offset, &asn1_ctx, tree, hf_hnbap_PLMNidentity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAC_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_RAC(tvb, offset, &asn1_ctx, tree, hf_hnbap_RAC_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Registration_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_Registration_Cause(tvb, offset, &asn1_ctx, tree, hf_hnbap_Registration_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RNC_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_RNC_ID(tvb, offset, &asn1_ctx, tree, hf_hnbap_RNC_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_SAC_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_SAC(tvb, offset, &asn1_ctx, tree, hf_hnbap_SAC_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Capabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_UE_Capabilities(tvb, offset, &asn1_ctx, tree, hf_hnbap_UE_Capabilities_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Identity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_UE_Identity(tvb, offset, &asn1_ctx, tree, hf_hnbap_UE_Identity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HNBRegisterRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_HNBRegisterRequest(tvb, offset, &asn1_ctx, tree, hf_hnbap_HNBRegisterRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HNBRegisterAccept_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_HNBRegisterAccept(tvb, offset, &asn1_ctx, tree, hf_hnbap_HNBRegisterAccept_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HNBRegisterReject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_HNBRegisterReject(tvb, offset, &asn1_ctx, tree, hf_hnbap_HNBRegisterReject_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_HNBDe_Register_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_HNBDe_Register(tvb, offset, &asn1_ctx, tree, hf_hnbap_HNBDe_Register_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERegisterRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_UERegisterRequest(tvb, offset, &asn1_ctx, tree, hf_hnbap_UERegisterRequest_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERegisterAccept_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_UERegisterAccept(tvb, offset, &asn1_ctx, tree, hf_hnbap_UERegisterAccept_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UERegisterReject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_UERegisterReject(tvb, offset, &asn1_ctx, tree, hf_hnbap_UERegisterReject_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UEDe_Register_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_UEDe_Register(tvb, offset, &asn1_ctx, tree, hf_hnbap_UEDe_Register_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CSGMembershipUpdate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_CSGMembershipUpdate(tvb, offset, &asn1_ctx, tree, hf_hnbap_CSGMembershipUpdate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_ErrorIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_ErrorIndication(tvb, offset, &asn1_ctx, tree, hf_hnbap_ErrorIndication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_PrivateMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_hnbap_PrivateMessage(tvb, offset, &asn1_ctx, tree, hf_hnbap_PrivateMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static void dissect_HNBAP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  dissect_hnbap_HNBAP_PDU(tvb, 0, &asn1_ctx, tree, hf_hnbap_HNBAP_PDU_PDU);
}


/*--- End of included file: packet-hnbap-fn.c ---*/
#line 85 "../../asn1/hnbap/packet-hnbap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(hnbap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(hnbap_extension_dissector_table, ProtocolIE_ID, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}
#if 0
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureCode) return 0;
  return (dissector_try_string(hnbap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureCode) return 0;
  return (dissector_try_string(hnbap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  if (!ProcedureCode) return 0;
  return (dissector_try_string(hnbap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}
#endif

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(hnbap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(hnbap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint_new(hnbap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree, FALSE)) ? tvb_length(tvb) : 0;
}

static void
dissect_hnbap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item  *hnbap_item = NULL;
    proto_tree  *hnbap_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HNBAP");

    /* create the hnbap protocol tree */
    hnbap_item = proto_tree_add_item(tree, proto_hnbap, tvb, 0, -1, FALSE);
    hnbap_tree = proto_item_add_subtree(hnbap_item, ett_hnbap);

    dissect_HNBAP_PDU_PDU(tvb, pinfo, hnbap_tree);
}

/*--- proto_register_hnbap -------------------------------------------*/
void proto_register_hnbap(void) {
module_t *hnbap_module;

  /* List of fields */

  static hf_register_info hf[] = {


/*--- Included file: packet-hnbap-hfarr.c ---*/
#line 1 "../../asn1/hnbap/packet-hnbap-hfarr.c"
    { &hf_hnbap_BackoffTimer_PDU,
      { "BackoffTimer", "hnbap.BackoffTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_Cause_PDU,
      { "Cause", "hnbap.Cause",
        FT_UINT32, BASE_DEC, VALS(hnbap_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_CellIdentity_PDU,
      { "CellIdentity", "hnbap.CellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_Context_ID_PDU,
      { "Context-ID", "hnbap.Context_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_CriticalityDiagnostics_PDU,
      { "CriticalityDiagnostics", "hnbap.CriticalityDiagnostics",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_CSG_ID_PDU,
      { "CSG-ID", "hnbap.CSG_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_CSGMembershipStatus_PDU,
      { "CSGMembershipStatus", "hnbap.CSGMembershipStatus",
        FT_UINT32, BASE_DEC, VALS(hnbap_CSGMembershipStatus_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_HNB_Cell_Access_Mode_PDU,
      { "HNB-Cell-Access-Mode", "hnbap.HNB_Cell_Access_Mode",
        FT_UINT32, BASE_DEC, VALS(hnbap_HNB_Cell_Access_Mode_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_HNB_Location_Information_PDU,
      { "HNB-Location-Information", "hnbap.HNB_Location_Information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_HNB_Identity_PDU,
      { "HNB-Identity", "hnbap.HNB_Identity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_IP_Address_PDU,
      { "IP-Address", "hnbap.IP_Address",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_LAC_PDU,
      { "LAC", "hnbap.LAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_MuxPortNumber_PDU,
      { "MuxPortNumber", "hnbap.MuxPortNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_PLMNidentity_PDU,
      { "PLMNidentity", "hnbap.PLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_RAC_PDU,
      { "RAC", "hnbap.RAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_Registration_Cause_PDU,
      { "Registration-Cause", "hnbap.Registration_Cause",
        FT_UINT32, BASE_DEC, VALS(hnbap_Registration_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_RNC_ID_PDU,
      { "RNC-ID", "hnbap.RNC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_SAC_PDU,
      { "SAC", "hnbap.SAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_UE_Capabilities_PDU,
      { "UE-Capabilities", "hnbap.UE_Capabilities",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_UE_Identity_PDU,
      { "UE-Identity", "hnbap.UE_Identity",
        FT_UINT32, BASE_DEC, VALS(hnbap_UE_Identity_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_HNBRegisterRequest_PDU,
      { "HNBRegisterRequest", "hnbap.HNBRegisterRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_HNBRegisterAccept_PDU,
      { "HNBRegisterAccept", "hnbap.HNBRegisterAccept",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_HNBRegisterReject_PDU,
      { "HNBRegisterReject", "hnbap.HNBRegisterReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_HNBDe_Register_PDU,
      { "HNBDe-Register", "hnbap.HNBDe_Register",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_UERegisterRequest_PDU,
      { "UERegisterRequest", "hnbap.UERegisterRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_UERegisterAccept_PDU,
      { "UERegisterAccept", "hnbap.UERegisterAccept",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_UERegisterReject_PDU,
      { "UERegisterReject", "hnbap.UERegisterReject",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_UEDe_Register_PDU,
      { "UEDe-Register", "hnbap.UEDe_Register",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_CSGMembershipUpdate_PDU,
      { "CSGMembershipUpdate", "hnbap.CSGMembershipUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_ErrorIndication_PDU,
      { "ErrorIndication", "hnbap.ErrorIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_PrivateMessage_PDU,
      { "PrivateMessage", "hnbap.PrivateMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_HNBAP_PDU_PDU,
      { "HNBAP-PDU", "hnbap.HNBAP_PDU",
        FT_UINT32, BASE_DEC, VALS(hnbap_HNBAP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_local,
      { "local", "hnbap.local",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_hnbap_global,
      { "global", "hnbap.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_hnbap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "hnbap.ProtocolIE_Field",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_protocol_ie_field_id,
      { "id", "hnbap.id",
        FT_UINT32, BASE_DEC, VALS(hnbap_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_hnbap_criticality,
      { "criticality", "hnbap.criticality",
        FT_UINT32, BASE_DEC, VALS(hnbap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_ie_field_value,
      { "value", "hnbap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolIE_Field_value", HFILL }},
    { &hf_hnbap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "hnbap.ProtocolExtensionField",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_id,
      { "id", "hnbap.id",
        FT_UINT32, BASE_DEC, VALS(hnbap_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_hnbap_extensionValue,
      { "extensionValue", "hnbap.extensionValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_PrivateIE_Container_item,
      { "PrivateIE-Field", "hnbap.PrivateIE_Field",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_private_ie_field_id,
      { "id", "hnbap.id",
        FT_UINT32, BASE_DEC, VALS(hnbap_PrivateIE_ID_vals), 0,
        "PrivateIE_ID", HFILL }},
    { &hf_hnbap_private_value,
      { "value", "hnbap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateIE_Field_value", HFILL }},
    { &hf_hnbap_directionOfAltitude,
      { "directionOfAltitude", "hnbap.directionOfAltitude",
        FT_UINT32, BASE_DEC, VALS(hnbap_T_directionOfAltitude_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_altitude,
      { "altitude", "hnbap.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_hnbap_radioNetwork,
      { "radioNetwork", "hnbap.radioNetwork",
        FT_UINT32, BASE_DEC, VALS(hnbap_CauseRadioNetwork_vals), 0,
        "CauseRadioNetwork", HFILL }},
    { &hf_hnbap_transport,
      { "transport", "hnbap.transport",
        FT_UINT32, BASE_DEC, VALS(hnbap_CauseTransport_vals), 0,
        "CauseTransport", HFILL }},
    { &hf_hnbap_protocol,
      { "protocol", "hnbap.protocol",
        FT_UINT32, BASE_DEC, VALS(hnbap_CauseProtocol_vals), 0,
        "CauseProtocol", HFILL }},
    { &hf_hnbap_misc,
      { "misc", "hnbap.misc",
        FT_UINT32, BASE_DEC, VALS(hnbap_CauseMisc_vals), 0,
        "CauseMisc", HFILL }},
    { &hf_hnbap_procedureCode,
      { "procedureCode", "hnbap.procedureCode",
        FT_UINT32, BASE_DEC, VALS(hnbap_ProcedureCode_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_triggeringMessage,
      { "triggeringMessage", "hnbap.triggeringMessage",
        FT_UINT32, BASE_DEC, VALS(hnbap_TriggeringMessage_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_procedureCriticality,
      { "procedureCriticality", "hnbap.procedureCriticality",
        FT_UINT32, BASE_DEC, VALS(hnbap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_hnbap_iEsCriticalityDiagnostics,
      { "iEsCriticalityDiagnostics", "hnbap.iEsCriticalityDiagnostics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CriticalityDiagnostics_IE_List", HFILL }},
    { &hf_hnbap_iE_Extensions,
      { "iE-Extensions", "hnbap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_hnbap_CriticalityDiagnostics_IE_List_item,
      { "CriticalityDiagnostics-IE-List item", "hnbap.CriticalityDiagnostics_IE_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_iECriticality,
      { "iECriticality", "hnbap.iECriticality",
        FT_UINT32, BASE_DEC, VALS(hnbap_Criticality_vals), 0,
        "Criticality", HFILL }},
    { &hf_hnbap_iE_ID,
      { "iE-ID", "hnbap.iE_ID",
        FT_UINT32, BASE_DEC, VALS(hnbap_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_hnbap_typeOfError,
      { "typeOfError", "hnbap.typeOfError",
        FT_UINT32, BASE_DEC, VALS(hnbap_TypeOfError_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_pLMNidentity,
      { "pLMNidentity", "hnbap.pLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_lAC,
      { "lAC", "hnbap.lAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_cI,
      { "cI", "hnbap.cI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_geographical_location_geographical_coordinates,
      { "geographicalCoordinates", "hnbap.geographicalCoordinates",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_altitudeAndDirection,
      { "altitudeAndDirection", "hnbap.altitudeAndDirection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_latitudeSign,
      { "latitudeSign", "hnbap.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(hnbap_T_latitudeSign_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_latitude,
      { "latitude", "hnbap.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_hnbap_longitude,
      { "longitude", "hnbap.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_hnbap_macroCoverageInfo,
      { "macroCoverageInfo", "hnbap.macroCoverageInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "MacroCoverageInformation", HFILL }},
    { &hf_hnbap_hnb_location_information_geographical_coordinates,
      { "geographicalCoordinates", "hnbap.geographicalCoordinates",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeographicalLocation", HFILL }},
    { &hf_hnbap_hNB_Identity_Info,
      { "hNB-Identity-Info", "hnbap.hNB_Identity_Info",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_iMSIDS41,
      { "iMSIDS41", "hnbap.iMSIDS41",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_eSN,
      { "eSN", "hnbap.eSN",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_ipaddress,
      { "ipaddress", "hnbap.ipaddress",
        FT_UINT32, BASE_DEC, VALS(hnbap_T_ipaddress_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_ipv4info,
      { "ipv4info", "hnbap.ipv4info",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Ipv4Address", HFILL }},
    { &hf_hnbap_ipv6info,
      { "ipv6info", "hnbap.ipv6info",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Ipv6Address", HFILL }},
    { &hf_hnbap_pLMNID,
      { "pLMNID", "hnbap.pLMNID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMNidentity", HFILL }},
    { &hf_hnbap_cellIdentity,
      { "cellIdentity", "hnbap.cellIdentity",
        FT_UINT32, BASE_DEC, VALS(hnbap_MacroCellID_vals), 0,
        "MacroCellID", HFILL }},
    { &hf_hnbap_uTRANCellID,
      { "uTRANCellID", "hnbap.uTRANCellID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_gERANCellID,
      { "gERANCellID", "hnbap.gERANCellID",
        FT_NONE, BASE_NONE, NULL, 0,
        "CGI", HFILL }},
    { &hf_hnbap_pTMSI,
      { "pTMSI", "hnbap.pTMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_rAI,
      { "rAI", "hnbap.rAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_lAI,
      { "lAI", "hnbap.lAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_rAC,
      { "rAC", "hnbap.rAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_tMSI,
      { "tMSI", "hnbap.tMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_hnbap_access_stratum_release_indicator,
      { "access-stratum-release-indicator", "hnbap.access_stratum_release_indicator",
        FT_UINT32, BASE_DEC, VALS(hnbap_Access_stratum_release_indicator_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_csg_indicator,
      { "csg-indicator", "hnbap.csg_indicator",
        FT_UINT32, BASE_DEC, VALS(hnbap_CSG_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_hnbap_uTRANcellID,
      { "uTRANcellID", "hnbap.uTRANcellID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CellIdentity", HFILL }},
    { &hf_hnbap_iMSI,
      { "iMSI", "hnbap.iMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_tMSILAI,
      { "tMSILAI", "hnbap.tMSILAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_pTMSIRAI,
      { "pTMSIRAI", "hnbap.pTMSIRAI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_iMEI,
      { "iMEI", "hnbap.iMEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_iMSIESN,
      { "iMSIESN", "hnbap.iMSIESN",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_tMSIDS41,
      { "tMSIDS41", "hnbap.tMSIDS41",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_protocolIEs,
      { "protocolIEs", "hnbap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_hnbap_protocolExtensions,
      { "protocolExtensions", "hnbap.protocolExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_hnbap_privateIEs,
      { "privateIEs", "hnbap.privateIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrivateIE_Container", HFILL }},
    { &hf_hnbap_initiatingMessage,
      { "initiatingMessage", "hnbap.initiatingMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_successfulOutcome,
      { "successfulOutcome", "hnbap.successfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "hnbap.unsuccessfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_hnbap_initiatingMessagevalue,
      { "value", "hnbap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_hnbap_successfulOutcome_value,
      { "value", "hnbap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_hnbap_unsuccessfulOutcome_value,
      { "value", "hnbap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-hnbap-hfarr.c ---*/
#line 155 "../../asn1/hnbap/packet-hnbap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
          &ett_hnbap,

/*--- Included file: packet-hnbap-ettarr.c ---*/
#line 1 "../../asn1/hnbap/packet-hnbap-ettarr.c"
    &ett_hnbap_PrivateIE_ID,
    &ett_hnbap_ProtocolIE_Container,
    &ett_hnbap_ProtocolIE_Field,
    &ett_hnbap_ProtocolExtensionContainer,
    &ett_hnbap_ProtocolExtensionField,
    &ett_hnbap_PrivateIE_Container,
    &ett_hnbap_PrivateIE_Field,
    &ett_hnbap_AltitudeAndDirection,
    &ett_hnbap_Cause,
    &ett_hnbap_CriticalityDiagnostics,
    &ett_hnbap_CriticalityDiagnostics_IE_List,
    &ett_hnbap_CriticalityDiagnostics_IE_List_item,
    &ett_hnbap_CGI,
    &ett_hnbap_GeographicalLocation,
    &ett_hnbap_GeographicalCoordinates,
    &ett_hnbap_HNB_Location_Information,
    &ett_hnbap_HNB_Identity,
    &ett_hnbap_IMSIESN,
    &ett_hnbap_IP_Address,
    &ett_hnbap_T_ipaddress,
    &ett_hnbap_LAI,
    &ett_hnbap_MacroCoverageInformation,
    &ett_hnbap_MacroCellID,
    &ett_hnbap_PTMSIRAI,
    &ett_hnbap_RAI,
    &ett_hnbap_TMSILAI,
    &ett_hnbap_UE_Capabilities,
    &ett_hnbap_UTRANCellID,
    &ett_hnbap_UE_Identity,
    &ett_hnbap_HNBRegisterRequest,
    &ett_hnbap_HNBRegisterAccept,
    &ett_hnbap_HNBRegisterReject,
    &ett_hnbap_HNBDe_Register,
    &ett_hnbap_UERegisterRequest,
    &ett_hnbap_UERegisterAccept,
    &ett_hnbap_UERegisterReject,
    &ett_hnbap_UEDe_Register,
    &ett_hnbap_CSGMembershipUpdate,
    &ett_hnbap_ErrorIndication,
    &ett_hnbap_PrivateMessage,
    &ett_hnbap_HNBAP_PDU,
    &ett_hnbap_InitiatingMessage,
    &ett_hnbap_SuccessfulOutcome,
    &ett_hnbap_UnsuccessfulOutcome,

/*--- End of included file: packet-hnbap-ettarr.c ---*/
#line 161 "../../asn1/hnbap/packet-hnbap-template.c"
  };


  /* Register protocol */
  proto_hnbap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_hnbap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector */
  register_dissector("hnbap", dissect_hnbap, proto_hnbap);

  /* Register dissector tables */
  hnbap_ies_dissector_table = register_dissector_table("hnbap.ies", "HNBAP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  hnbap_extension_dissector_table = register_dissector_table("hnbap.extension", "HNBAP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  hnbap_proc_imsg_dissector_table = register_dissector_table("hnbap.proc.imsg", "HNBAP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  hnbap_proc_sout_dissector_table = register_dissector_table("hnbap.proc.sout", "HNBAP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  hnbap_proc_uout_dissector_table = register_dissector_table("hnbap.proc.uout", "HNBAP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);

  hnbap_module = prefs_register_protocol(proto_hnbap, proto_reg_handoff_hnbap);
  prefs_register_uint_preference(hnbap_module, "port", "HNBAP SCTP Port", "Set the port for HNBAP messages (Default of 29169)", 10, &global_sctp_port);
}


/*--- proto_reg_handoff_hnbap ---------------------------------------*/
void
proto_reg_handoff_hnbap(void)
{
        static gboolean initialized = FALSE;
        static dissector_handle_t hnbap_handle;
        static guint sctp_port;

        if (!initialized) {
                hnbap_handle = find_dissector("hnbap");
                dissector_add_uint("sctp.ppi", HNBAP_PAYLOAD_PROTOCOL_ID, hnbap_handle);
                initialized = TRUE;

/*--- Included file: packet-hnbap-dis-tab.c ---*/
#line 1 "../../asn1/hnbap/packet-hnbap-dis-tab.c"
  dissector_add_uint("hnbap.ies", id_Cause, new_create_dissector_handle(dissect_Cause_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_CriticalityDiagnostics, new_create_dissector_handle(dissect_CriticalityDiagnostics_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_HNB_Identity, new_create_dissector_handle(dissect_HNB_Identity_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_Context_ID, new_create_dissector_handle(dissect_Context_ID_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_UE_Identity, new_create_dissector_handle(dissect_UE_Identity_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_LAC, new_create_dissector_handle(dissect_LAC_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_RAC, new_create_dissector_handle(dissect_RAC_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_HNB_Location_Information, new_create_dissector_handle(dissect_HNB_Location_Information_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_PLMNidentity, new_create_dissector_handle(dissect_PLMNidentity_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_SAC, new_create_dissector_handle(dissect_SAC_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_CellIdentity, new_create_dissector_handle(dissect_CellIdentity_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_Registration_Cause, new_create_dissector_handle(dissect_Registration_Cause_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_UE_Capabilities, new_create_dissector_handle(dissect_UE_Capabilities_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_RNC_ID, new_create_dissector_handle(dissect_RNC_ID_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_CSG_ID, new_create_dissector_handle(dissect_CSG_ID_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_BackoffTimer, new_create_dissector_handle(dissect_BackoffTimer_PDU, proto_hnbap));
  dissector_add_uint("hnbap.ies", id_CSGMembershipStatus, new_create_dissector_handle(dissect_CSGMembershipStatus_PDU, proto_hnbap));
  dissector_add_uint("hnbap.extension", id_HNB_Internet_Information, new_create_dissector_handle(dissect_IP_Address_PDU, proto_hnbap));
  dissector_add_uint("hnbap.extension", id_HNB_Cell_Access_Mode, new_create_dissector_handle(dissect_HNB_Cell_Access_Mode_PDU, proto_hnbap));
  dissector_add_uint("hnbap.extension", id_MuxPortNumber, new_create_dissector_handle(dissect_MuxPortNumber_PDU, proto_hnbap));
  dissector_add_uint("hnbap.extension", id_CSGMembershipStatus, new_create_dissector_handle(dissect_CSGMembershipStatus_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.imsg", id_HNBRegister, new_create_dissector_handle(dissect_HNBRegisterRequest_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.sout", id_HNBRegister, new_create_dissector_handle(dissect_HNBRegisterAccept_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.uout", id_HNBRegister, new_create_dissector_handle(dissect_HNBRegisterReject_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.imsg", id_UERegister, new_create_dissector_handle(dissect_UERegisterRequest_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.sout", id_UERegister, new_create_dissector_handle(dissect_UERegisterAccept_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.uout", id_UERegister, new_create_dissector_handle(dissect_UERegisterReject_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.imsg", id_UEDe_Register, new_create_dissector_handle(dissect_UEDe_Register_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.imsg", id_HNBDe_Register, new_create_dissector_handle(dissect_HNBDe_Register_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.imsg", id_ErrorIndication, new_create_dissector_handle(dissect_ErrorIndication_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.imsg", id_CSGMembershipUpdate, new_create_dissector_handle(dissect_CSGMembershipUpdate_PDU, proto_hnbap));
  dissector_add_uint("hnbap.proc.imsg", id_privateMessage, new_create_dissector_handle(dissect_PrivateMessage_PDU, proto_hnbap));


/*--- End of included file: packet-hnbap-dis-tab.c ---*/
#line 198 "../../asn1/hnbap/packet-hnbap-template.c"

        } else {
                dissector_delete_uint("sctp.port", sctp_port, hnbap_handle);
        }
        /* Set our port number for future use */
        sctp_port = global_sctp_port;
        dissector_add_uint("sctp.port", sctp_port, hnbap_handle);
}
