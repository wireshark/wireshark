/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-lcsap.c                                                             */
/* ../../tools/asn2wrs.py -p lcsap -c ./lcsap.cnf -s ./packet-lcsap-template -D . -O ../../epan/dissectors LCS-AP-CommonDataTypes.asn LCS-AP-Constants.asn LCS-AP-Containers.asn LCS-AP-IEs.asn LCS-AP-PDU-Contents.asn LCS-AP-PDU-Descriptions.asn */

/* Input file: packet-lcsap-template.c */

#line 1 "../../asn1/lcsap/packet-lcsap-template.c"
/* packet-lcsap.c
 * Routines for LCS-AP packet dissembly.
 *
 * Copyright (c) 2011 by Spenser Sheng <spenser.sheng@ericsson.com>
 *
 * $Id: packet-lcsap.c 28770 2011-06-18 21:30:42Z stig  Spenser Sheng$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
 * References:
 * ETSI TS 129 171 V9.2.0 (2010-10)
 */
 
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-sccp.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "LCS Application Protocol"
#define PSNAME "LCSAP"
#define PFNAME "lcsap"

#define SCTP_PORT_LCSAP 9082

/*--- Included file: packet-lcsap-val.h ---*/
#line 1 "../../asn1/lcsap/packet-lcsap-val.h"
#define max_No_Of_Points               15
#define max_Set                        9
#define max_GNSS_Set                   9
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535

typedef enum _ProcedureCode_enum {
  id_Location_Service_Request =   0,
  id_Connection_Oriented_Information_Transfer =   1,
  id_Connectionless_Information_Transfer =   2,
  id_Location_Abort =   3,
  id_Reset     =   4
} ProcedureCode_enum;

typedef enum _ProtocolIE_ID_enum {
  id_Accuracy_Fulfillment_Indicator =   0,
  id_APDU      =   1,
  id_Correlation_ID =   2,
  id_Destination_ID =   3,
  id_E_UTRAN_Cell_Identifier =   4,
  id_Include_Velocity =   5,
  id_IMEI      =   6,
  id_IMSI      =   7,
  id_LCS_Client_Type =   8,
  id_LCS_Priority =   9,
  id_LCS_QOS   =  10,
  id_LCS_Cause =  11,
  id_Location_Estimate =  12,
  id_Location_Type =  13,
  id_MultipleAPDUs =  14,
  id_Payload_Type =  15,
  id_Positioning_Data =  16,
  id_Return_Error_Request =  17,
  id_Return_Error_Cause =  18,
  id_Source_Identity =  19,
  id_UE_Positioning_Capability =  20,
  id_Velocity_Estimate =  21
} ProtocolIE_ID_enum;

/*--- End of included file: packet-lcsap-val.h ---*/
#line 60 "../../asn1/lcsap/packet-lcsap-template.c"
/* Strcture to hold ProcedureCode */
struct pro_code {
        guint8 code;
} _pro_code;

/* Initialize the protocol and registered fields */
static int proto_lcsap  =   -1;

/*--- Included file: packet-lcsap-hf.c ---*/
#line 1 "../../asn1/lcsap/packet-lcsap-hf.c"
static int hf_lcsap_Accuracy_Fulfillment_Indicator_PDU = -1;  /* Accuracy_Fulfillment_Indicator */
static int hf_lcsap_lcsap_Correlation_ID_PDU = -1;  /* Correlation_ID */
static int hf_lcsap_E_CGI_PDU = -1;               /* E_CGI */
static int hf_lcsap_Geographical_Area_PDU = -1;   /* Geographical_Area */
static int hf_lcsap_IMSI_PDU = -1;                /* IMSI */
static int hf_lcsap_IMEI_PDU = -1;                /* IMEI */
static int hf_lcsap_Include_Velocity_PDU = -1;    /* Include_Velocity */
static int hf_lcsap_Location_Type_PDU = -1;       /* Location_Type */
static int hf_lcsap_LCS_Cause_PDU = -1;           /* LCS_Cause */
static int hf_lcsap_LCS_Client_Type_PDU = -1;     /* LCS_Client_Type */
static int hf_lcsap_LCS_Priority_PDU = -1;        /* LCS_Priority */
static int hf_lcsap_LCS_QoS_PDU = -1;             /* LCS_QoS */
static int hf_lcsap_MultipleAPDUs_PDU = -1;       /* MultipleAPDUs */
static int hf_lcsap_Network_Element_PDU = -1;     /* Network_Element */
static int hf_lcsap_Payload_Type_PDU = -1;        /* Payload_Type */
static int hf_lcsap_Positioning_Data_PDU = -1;    /* Positioning_Data */
static int hf_lcsap_Return_Error_Type_PDU = -1;   /* Return_Error_Type */
static int hf_lcsap_Return_Error_Cause_PDU = -1;  /* Return_Error_Cause */
static int hf_lcsap_UE_Positioning_Capability_PDU = -1;  /* UE_Positioning_Capability */
static int hf_lcsap_Velocity_Estimate_PDU = -1;   /* Velocity_Estimate */
static int hf_lcsap_Location_Request_PDU = -1;    /* Location_Request */
static int hf_lcsap_Location_Response_PDU = -1;   /* Location_Response */
static int hf_lcsap_Location_Abort_Request_PDU = -1;  /* Location_Abort_Request */
static int hf_lcsap_Connection_Oriented_Information_PDU = -1;  /* Connection_Oriented_Information */
static int hf_lcsap_Connectionless_Information_PDU = -1;  /* Connectionless_Information */
static int hf_lcsap_Reset_Request_PDU = -1;       /* Reset_Request */
static int hf_lcsap_Reset_Acknowledge_PDU = -1;   /* Reset_Acknowledge */
static int hf_lcsap_LCS_AP_PDU_PDU = -1;          /* LCS_AP_PDU */
static int hf_lcsap_ProtocolIE_Container_item = -1;  /* ProtocolIE_Field */
static int hf_lcsap_ieid = -1;                    /* ProtocolIE_ID */
static int hf_lcsap_criticality = -1;             /* Criticality */
static int hf_lcsap_ie_field_value = -1;          /* T_ie_field_value */
static int hf_lcsap_ProtocolExtensionContainer_item = -1;  /* ProtocolExtensionField */
static int hf_lcsap_extid = -1;                   /* ProtocolExtensionID */
static int hf_lcsap_extensionValue = -1;          /* T_extensionValue */
static int hf_lcsap_direction_Of_Altitude = -1;   /* Direction_Of_Altitude */
static int hf_lcsap_altitude = -1;                /* Altitude */
static int hf_lcsap_pLMNidentity = -1;            /* PLMN_ID */
static int hf_lcsap_cell_ID = -1;                 /* CellIdentity */
static int hf_lcsap_iE_Extensions = -1;           /* ProtocolExtensionContainer */
static int hf_lcsap_geographical_Coordinates = -1;  /* Geographical_Coordinates */
static int hf_lcsap_uncertainty_Ellipse = -1;     /* Uncertainty_Ellipse */
static int hf_lcsap_confidence = -1;              /* Confidence */
static int hf_lcsap_altitude_And_Direction = -1;  /* Altitude_And_Direction */
static int hf_lcsap_uncertainty_Altitude = -1;    /* Uncertainty_Altitude */
static int hf_lcsap_inner_Radius = -1;            /* Inner_Radius */
static int hf_lcsap_uncertainty_Radius = -1;      /* Uncertainty_Code */
static int hf_lcsap_offset_Angle = -1;            /* Angle */
static int hf_lcsap_included_Angle = -1;          /* Angle */
static int hf_lcsap_macro_eNB_ID = -1;            /* Macro_eNB_ID */
static int hf_lcsap_home_eNB_ID = -1;             /* Home_eNB_ID */
static int hf_lcsap_point = -1;                   /* Point */
static int hf_lcsap_point_With_Uncertainty = -1;  /* Point_With_Uncertainty */
static int hf_lcsap_ellipsoidPoint_With_Uncertainty_Ellipse = -1;  /* Ellipsoid_Point_With_Uncertainty_Ellipse */
static int hf_lcsap_polygon = -1;                 /* Polygon */
static int hf_lcsap_ellipsoid_Point_With_Altitude = -1;  /* Ellipsoid_Point_With_Altitude */
static int hf_lcsap_ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid = -1;  /* Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid */
static int hf_lcsap_ellipsoid_Arc = -1;           /* Ellipsoid_Arc */
static int hf_lcsap_latitudeSign = -1;            /* LatitudeSign */
static int hf_lcsap_degreesLatitude = -1;         /* DegreesLatitude */
static int hf_lcsap_degreesLongitude = -1;        /* DegreesLongitude */
static int hf_lcsap_pLMN_ID = -1;                 /* PLMN_ID */
static int hf_lcsap_eNB_ID = -1;                  /* ENB_ID */
static int hf_lcsap_GNSS_Positioning_Data_Set_item = -1;  /* GNSS_Positioning_Method_And_Usage */
static int hf_lcsap_bearing = -1;                 /* Bearing */
static int hf_lcsap_horizontal_Speed = -1;        /* INTEGER_0_2047 */
static int hf_lcsap_horizontal_Speed_And_Bearing = -1;  /* Horizontal_Speed_And_Bearing */
static int hf_lcsap_vertical_Velocity = -1;       /* Vertical_Velocity */
static int hf_lcsap_uncertainty_Speed = -1;       /* INTEGER_0_255 */
static int hf_lcsap_horizontal_Uncertainty_Speed = -1;  /* INTEGER_0_255 */
static int hf_lcsap_vertical_Uncertainty_Speed = -1;  /* INTEGER_0_255 */
static int hf_lcsap_radio_Network_Layer = -1;     /* Radio_Network_Layer_Cause */
static int hf_lcsap_transport_Layer = -1;         /* Transport_Layer_Cause */
static int hf_lcsap_protocol = -1;                /* Protocol_Cause */
static int hf_lcsap_misc = -1;                    /* Misc_Cause */
static int hf_lcsap_horizontal_Accuracy = -1;     /* Horizontal_Accuracy */
static int hf_lcsap_vertical_Requested = -1;      /* Vertical_Requested */
static int hf_lcsap_vertical_Accuracy = -1;       /* Vertical_Accuracy */
static int hf_lcsap_response_Time = -1;           /* Response_Time */
static int hf_lcsap_MultipleAPDUs_item = -1;      /* APDU */
static int hf_lcsap_global_eNB_ID = -1;           /* Global_eNB_ID */
static int hf_lcsap_e_SMLC_ID = -1;               /* E_SMLC_ID */
static int hf_lcsap_uncertainty_Code = -1;        /* Uncertainty_Code */
static int hf_lcsap_Polygon_item = -1;            /* Polygon_Point */
static int hf_lcsap_positioning_Data_Set = -1;    /* Positioning_Data_Set */
static int hf_lcsap_gNSS_Positioning_Data_Set = -1;  /* GNSS_Positioning_Data_Set */
static int hf_lcsap_Positioning_Data_Set_item = -1;  /* Positioning_Method_And_Usage */
static int hf_lcsap_uncertainty_SemiMajor = -1;   /* Uncertainty_Code */
static int hf_lcsap_uncertainty_SemiMinor = -1;   /* Uncertainty_Code */
static int hf_lcsap_orientation_Major_Axis = -1;  /* Orientation_Major_Axis */
static int hf_lcsap_lPP = -1;                     /* BOOLEAN */
static int hf_lcsap_horizontal_Velocity = -1;     /* Horizontal_Velocity */
static int hf_lcsap_horizontal_With_Vertical_Velocity = -1;  /* Horizontal_With_Vertical_Velocity */
static int hf_lcsap_horizontal_Velocity_With_Uncertainty = -1;  /* Horizontal_Velocity_With_Uncertainty */
static int hf_lcsap_horizontal_With_Vertical_Velocity_And_Uncertainty = -1;  /* Horizontal_With_Vertical_Velocity_And_Uncertainty */
static int hf_lcsap_vertical_Speed = -1;          /* INTEGER_0_255 */
static int hf_lcsap_vertical_Speed_Direction = -1;  /* Vertical_Speed_Direction */
static int hf_lcsap_protocolIEs = -1;             /* ProtocolIE_Container */
static int hf_lcsap_protocolExtensions = -1;      /* ProtocolExtensionContainer */
static int hf_lcsap_initiatingMessage = -1;       /* InitiatingMessage */
static int hf_lcsap_successfulOutcome = -1;       /* SuccessfulOutcome */
static int hf_lcsap_unsuccessfulOutcome = -1;     /* UnsuccessfulOutcome */
static int hf_lcsap_procedureCode = -1;           /* ProcedureCode */
static int hf_lcsap_initiatingMessagevalue = -1;  /* InitiatingMessage_value */
static int hf_lcsap_successfulOutcome_value = -1;  /* SuccessfulOutcome_value */
static int hf_lcsap_unsuccessfulOutcome_value = -1;  /* UnsuccessfulOutcome_value */

/*--- End of included file: packet-lcsap-hf.c ---*/
#line 68 "../../asn1/lcsap/packet-lcsap-template.c"

/* Initialize the subtree pointers */
static int ett_lcsap = -1;


/*--- Included file: packet-lcsap-ett.c ---*/
#line 1 "../../asn1/lcsap/packet-lcsap-ett.c"
static gint ett_lcsap_ProtocolIE_Container = -1;
static gint ett_lcsap_ProtocolIE_Field = -1;
static gint ett_lcsap_ProtocolExtensionContainer = -1;
static gint ett_lcsap_ProtocolExtensionField = -1;
static gint ett_lcsap_Altitude_And_Direction = -1;
static gint ett_lcsap_E_CGI = -1;
static gint ett_lcsap_Ellipsoid_Point_With_Uncertainty_Ellipse = -1;
static gint ett_lcsap_Ellipsoid_Point_With_Altitude = -1;
static gint ett_lcsap_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid = -1;
static gint ett_lcsap_Ellipsoid_Arc = -1;
static gint ett_lcsap_ENB_ID = -1;
static gint ett_lcsap_Geographical_Area = -1;
static gint ett_lcsap_Geographical_Coordinates = -1;
static gint ett_lcsap_Global_eNB_ID = -1;
static gint ett_lcsap_GNSS_Positioning_Data_Set = -1;
static gint ett_lcsap_Horizontal_Speed_And_Bearing = -1;
static gint ett_lcsap_Horizontal_Velocity = -1;
static gint ett_lcsap_Horizontal_With_Vertical_Velocity = -1;
static gint ett_lcsap_Horizontal_Velocity_With_Uncertainty = -1;
static gint ett_lcsap_Horizontal_With_Vertical_Velocity_And_Uncertainty = -1;
static gint ett_lcsap_LCS_Cause = -1;
static gint ett_lcsap_LCS_QoS = -1;
static gint ett_lcsap_MultipleAPDUs = -1;
static gint ett_lcsap_Network_Element = -1;
static gint ett_lcsap_Point = -1;
static gint ett_lcsap_Point_With_Uncertainty = -1;
static gint ett_lcsap_Polygon = -1;
static gint ett_lcsap_Polygon_Point = -1;
static gint ett_lcsap_Positioning_Data = -1;
static gint ett_lcsap_Positioning_Data_Set = -1;
static gint ett_lcsap_Uncertainty_Ellipse = -1;
static gint ett_lcsap_UE_Positioning_Capability = -1;
static gint ett_lcsap_Velocity_Estimate = -1;
static gint ett_lcsap_Vertical_Velocity = -1;
static gint ett_lcsap_Location_Request = -1;
static gint ett_lcsap_Location_Response = -1;
static gint ett_lcsap_Location_Abort_Request = -1;
static gint ett_lcsap_Connection_Oriented_Information = -1;
static gint ett_lcsap_Connectionless_Information = -1;
static gint ett_lcsap_Reset_Request = -1;
static gint ett_lcsap_Reset_Acknowledge = -1;
static gint ett_lcsap_LCS_AP_PDU = -1;
static gint ett_lcsap_InitiatingMessage = -1;
static gint ett_lcsap_SuccessfulOutcome = -1;
static gint ett_lcsap_UnsuccessfulOutcome = -1;

/*--- End of included file: packet-lcsap-ett.c ---*/
#line 73 "../../asn1/lcsap/packet-lcsap-template.c"

/* Global variables */
static guint32 ProcedureCode;
static guint32 ProtocolIE_ID;
static guint32 ProtocolExtensionID;
static guint gbl_lcsapSctpPort=SCTP_PORT_LCSAP;

/* Dissector tables */
static dissector_table_t lcsap_ies_dissector_table;

static dissector_table_t lcsap_extension_dissector_table;
static dissector_table_t lcsap_proc_imsg_dissector_table;
static dissector_table_t lcsap_proc_sout_dissector_table;
static dissector_table_t lcsap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);


/*--- Included file: packet-lcsap-fn.c ---*/
#line 1 "../../asn1/lcsap/packet-lcsap-fn.c"

static const value_string lcsap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_lcsap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lcsap_ProcedureCode_vals[] = {
  { id_Location_Service_Request, "id-Location-Service-Request" },
  { id_Connection_Oriented_Information_Transfer, "id-Connection-Oriented-Information-Transfer" },
  { id_Connectionless_Information_Transfer, "id-Connectionless-Information-Transfer" },
  { id_Location_Abort, "id-Location-Abort" },
  { id_Reset, "id-Reset" },
  { 0, NULL }
};


static int
dissect_lcsap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, FALSE);

#line 65 "../../asn1/lcsap/lcsap.cnf"

	if (check_col(actx->pinfo->cinfo, COL_INFO))
	{
		guint8 tmp = tvb_get_guint8(tvb, 0);
			
		if(tmp == 0)
				
		col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%sReq",
			   val_to_str(ProcedureCode, lcsap_ProcedureCode_vals,
			        "unknown message"));

		else if(tmp == 32)
			col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%sResp",
				  val_to_str(ProcedureCode, lcsap_ProcedureCode_vals,
				    "unknown message"));
			else
				col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s",
				  val_to_str(ProcedureCode, lcsap_ProcedureCode_vals,	
				    "unknown message"));
 
	}

        if (ProcedureCode != 0) 
	{
                
		_pro_code.code = ProcedureCode;
 
		actx->pinfo->private_data = &_pro_code;
   
	}

  return offset;
}



static int
dissect_lcsap_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolExtensionID, FALSE);

  return offset;
}


static const value_string lcsap_ProtocolIE_ID_vals[] = {
  { id_Accuracy_Fulfillment_Indicator, "id-Accuracy-Fulfillment-Indicator" },
  { id_APDU, "id-APDU" },
  { id_Correlation_ID, "id-Correlation-ID" },
  { id_Destination_ID, "id-Destination-ID" },
  { id_E_UTRAN_Cell_Identifier, "id-E-UTRAN-Cell-Identifier" },
  { id_Include_Velocity, "id-Include-Velocity" },
  { id_IMEI, "id-IMEI" },
  { id_IMSI, "id-IMSI" },
  { id_LCS_Client_Type, "id-LCS-Client-Type" },
  { id_LCS_Priority, "id-LCS-Priority" },
  { id_LCS_QOS, "id-LCS-QOS" },
  { id_LCS_Cause, "id-LCS-Cause" },
  { id_Location_Estimate, "id-Location-Estimate" },
  { id_Location_Type, "id-Location-Type" },
  { id_MultipleAPDUs, "id-MultipleAPDUs" },
  { id_Payload_Type, "id-Payload-Type" },
  { id_Positioning_Data, "id-Positioning-Data" },
  { id_Return_Error_Request, "id-Return-Error-Request" },
  { id_Return_Error_Cause, "id-Return-Error-Cause" },
  { id_Source_Identity, "id-Source-Identity" },
  { id_UE_Positioning_Capability, "id-UE-Positioning-Capability" },
  { id_Velocity_Estimate, "id-Velocity-Estimate" },
  { 0, NULL }
};


static int
dissect_lcsap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolIE_ID, FALSE);

#line 53 "../../asn1/lcsap/lcsap.cnf"
  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s", val_to_str(ProtocolIE_ID, VALS(lcsap_ProtocolIE_ID_vals), "unknown (%d)"));
  }

  return offset;
}



static int
dissect_lcsap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_lcsap_ieid          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_ID },
  { &hf_lcsap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Criticality },
  { &hf_lcsap_ie_field_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_T_ie_field_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_ProtocolIE_Field(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_ProtocolIE_Field, ProtocolIE_Field_sequence);

  return offset;
}


static const per_sequence_t ProtocolIE_Container_sequence_of[1] = {
  { &hf_lcsap_ProtocolIE_Container_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_Field },
};

static int
dissect_lcsap_ProtocolIE_Container(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_ProtocolIE_Container, ProtocolIE_Container_sequence_of,
                                                  0, maxProtocolIEs, FALSE);

  return offset;
}



static int
dissect_lcsap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_lcsap_extid         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolExtensionID },
  { &hf_lcsap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Criticality },
  { &hf_lcsap_extensionValue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_T_extensionValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_ProtocolExtensionField(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_ProtocolExtensionField, ProtocolExtensionField_sequence);

  return offset;
}


static const per_sequence_t ProtocolExtensionContainer_sequence_of[1] = {
  { &hf_lcsap_ProtocolExtensionContainer_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolExtensionField },
};

static int
dissect_lcsap_ProtocolExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_ProtocolExtensionContainer, ProtocolExtensionContainer_sequence_of,
                                                  1, maxProtocolExtensions, FALSE);

  return offset;
}



static int
dissect_lcsap_APDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, FALSE, NULL);

  return offset;
}


static const value_string lcsap_Accuracy_Fulfillment_Indicator_vals[] = {
  {   0, "requested-accuracy-fulfilled" },
  {   1, "requested-accuracy-not-fulfilled" },
  { 0, NULL }
};


static int
dissect_lcsap_Accuracy_Fulfillment_Indicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lcsap_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65535U, NULL, FALSE);

  return offset;
}


static const value_string lcsap_Direction_Of_Altitude_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_lcsap_Direction_Of_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Altitude_And_Direction_sequence[] = {
  { &hf_lcsap_direction_Of_Altitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Direction_Of_Altitude },
  { &hf_lcsap_altitude      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Altitude },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Altitude_And_Direction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Altitude_And_Direction, Altitude_And_Direction_sequence);

  return offset;
}



static int
dissect_lcsap_Angle(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 179U, NULL, FALSE);

  return offset;
}



static int
dissect_lcsap_Bearing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 359U, NULL, FALSE);

  return offset;
}



static int
dissect_lcsap_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL);

  return offset;
}



static int
dissect_lcsap_Confidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, FALSE);

  return offset;
}



static int
dissect_lcsap_Correlation_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_lcsap_DegreesLatitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, FALSE);

  return offset;
}



static int
dissect_lcsap_DegreesLongitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, FALSE);

  return offset;
}




static int
dissect_lcsap_PLMN_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 136 "../../asn1/lcsap/lcsap.cnf"
  tvbuff_t *parameter_tvb=NULL;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, &parameter_tvb);
	if(tvb_length(tvb)==0) 
		return offset;
		
	if (!parameter_tvb)
		return offset;
	dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, tree, 0, FALSE);


  return offset;
}


static const per_sequence_t E_CGI_sequence[] = {
  { &hf_lcsap_pLMNidentity  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_PLMN_ID },
  { &hf_lcsap_cell_ID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_CellIdentity },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_E_CGI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_E_CGI, E_CGI_sequence);

  return offset;
}


static const value_string lcsap_LatitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_lcsap_LatitudeSign(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Geographical_Coordinates_sequence[] = {
  { &hf_lcsap_latitudeSign  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_LatitudeSign },
  { &hf_lcsap_degreesLatitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_DegreesLatitude },
  { &hf_lcsap_degreesLongitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_DegreesLongitude },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Geographical_Coordinates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Geographical_Coordinates, Geographical_Coordinates_sequence);

  return offset;
}



static int
dissect_lcsap_Uncertainty_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_lcsap_Orientation_Major_Axis(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 89U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Uncertainty_Ellipse_sequence[] = {
  { &hf_lcsap_uncertainty_SemiMajor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Uncertainty_Code },
  { &hf_lcsap_uncertainty_SemiMinor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Uncertainty_Code },
  { &hf_lcsap_orientation_Major_Axis, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Orientation_Major_Axis },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Uncertainty_Ellipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Uncertainty_Ellipse, Uncertainty_Ellipse_sequence);

  return offset;
}


static const per_sequence_t Ellipsoid_Point_With_Uncertainty_Ellipse_sequence[] = {
  { &hf_lcsap_geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Geographical_Coordinates },
  { &hf_lcsap_uncertainty_Ellipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Uncertainty_Ellipse },
  { &hf_lcsap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Confidence },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Ellipsoid_Point_With_Uncertainty_Ellipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Ellipsoid_Point_With_Uncertainty_Ellipse, Ellipsoid_Point_With_Uncertainty_Ellipse_sequence);

  return offset;
}


static const per_sequence_t Ellipsoid_Point_With_Altitude_sequence[] = {
  { &hf_lcsap_geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Geographical_Coordinates },
  { &hf_lcsap_altitude_And_Direction, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Altitude_And_Direction },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Ellipsoid_Point_With_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Ellipsoid_Point_With_Altitude, Ellipsoid_Point_With_Altitude_sequence);

  return offset;
}



static int
dissect_lcsap_Uncertainty_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid_sequence[] = {
  { &hf_lcsap_geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Geographical_Coordinates },
  { &hf_lcsap_altitude_And_Direction, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Altitude_And_Direction },
  { &hf_lcsap_uncertainty_Ellipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Uncertainty_Ellipse },
  { &hf_lcsap_uncertainty_Altitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Uncertainty_Altitude },
  { &hf_lcsap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Confidence },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid, Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid_sequence);

  return offset;
}



static int
dissect_lcsap_Inner_Radius(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Ellipsoid_Arc_sequence[] = {
  { &hf_lcsap_geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Geographical_Coordinates },
  { &hf_lcsap_inner_Radius  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Inner_Radius },
  { &hf_lcsap_uncertainty_Radius, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Uncertainty_Code },
  { &hf_lcsap_offset_Angle  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Angle },
  { &hf_lcsap_included_Angle, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Angle },
  { &hf_lcsap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Confidence },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Ellipsoid_Arc(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Ellipsoid_Arc, Ellipsoid_Arc_sequence);

  return offset;
}



static int
dissect_lcsap_Macro_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     20, 20, FALSE, NULL);

  return offset;
}



static int
dissect_lcsap_Home_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, FALSE, NULL);

  return offset;
}


static const value_string lcsap_ENB_ID_vals[] = {
  {   0, "macro-eNB-ID" },
  {   1, "home-eNB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_lcsap_macro_eNB_ID  , ASN1_EXTENSION_ROOT    , dissect_lcsap_Macro_eNB_ID },
  {   1, &hf_lcsap_home_eNB_ID   , ASN1_EXTENSION_ROOT    , dissect_lcsap_Home_eNB_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_lcsap_ENB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lcsap_ENB_ID, ENB_ID_choice,
                                 NULL);

  return offset;
}



static int
dissect_lcsap_E_SMLC_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Point_sequence[] = {
  { &hf_lcsap_geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Geographical_Coordinates },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Point(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Point, Point_sequence);

  return offset;
}


static const per_sequence_t Point_With_Uncertainty_sequence[] = {
  { &hf_lcsap_geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Geographical_Coordinates },
  { &hf_lcsap_uncertainty_Code, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Uncertainty_Code },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Point_With_Uncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Point_With_Uncertainty, Point_With_Uncertainty_sequence);

  return offset;
}


static const per_sequence_t Polygon_Point_sequence[] = {
  { &hf_lcsap_geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Geographical_Coordinates },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Polygon_Point(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Polygon_Point, Polygon_Point_sequence);

  return offset;
}


static const per_sequence_t Polygon_sequence_of[1] = {
  { &hf_lcsap_Polygon_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Polygon_Point },
};

static int
dissect_lcsap_Polygon(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_Polygon, Polygon_sequence_of,
                                                  1, max_No_Of_Points, FALSE);

  return offset;
}


static const value_string lcsap_Geographical_Area_vals[] = {
  {   0, "point" },
  {   1, "point-With-Uncertainty" },
  {   2, "ellipsoidPoint-With-Uncertainty-Ellipse" },
  {   3, "polygon" },
  {   4, "ellipsoid-Point-With-Altitude" },
  {   5, "ellipsoid-Point-With-Altitude-And-Uncertainty-Ellipsoid" },
  {   6, "ellipsoid-Arc" },
  { 0, NULL }
};

static const per_choice_t Geographical_Area_choice[] = {
  {   0, &hf_lcsap_point         , ASN1_EXTENSION_ROOT    , dissect_lcsap_Point },
  {   1, &hf_lcsap_point_With_Uncertainty, ASN1_EXTENSION_ROOT    , dissect_lcsap_Point_With_Uncertainty },
  {   2, &hf_lcsap_ellipsoidPoint_With_Uncertainty_Ellipse, ASN1_EXTENSION_ROOT    , dissect_lcsap_Ellipsoid_Point_With_Uncertainty_Ellipse },
  {   3, &hf_lcsap_polygon       , ASN1_EXTENSION_ROOT    , dissect_lcsap_Polygon },
  {   4, &hf_lcsap_ellipsoid_Point_With_Altitude, ASN1_EXTENSION_ROOT    , dissect_lcsap_Ellipsoid_Point_With_Altitude },
  {   5, &hf_lcsap_ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid, ASN1_EXTENSION_ROOT    , dissect_lcsap_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid },
  {   6, &hf_lcsap_ellipsoid_Arc , ASN1_EXTENSION_ROOT    , dissect_lcsap_Ellipsoid_Arc },
  { 0, NULL, 0, NULL }
};

static int
dissect_lcsap_Geographical_Area(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lcsap_Geographical_Area, Geographical_Area_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Global_eNB_ID_sequence[] = {
  { &hf_lcsap_pLMN_ID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_PLMN_ID },
  { &hf_lcsap_eNB_ID        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_ENB_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Global_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Global_eNB_ID, Global_eNB_ID_sequence);

  return offset;
}



static int
dissect_lcsap_GNSS_Positioning_Method_And_Usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t GNSS_Positioning_Data_Set_sequence_of[1] = {
  { &hf_lcsap_GNSS_Positioning_Data_Set_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_GNSS_Positioning_Method_And_Usage },
};

static int
dissect_lcsap_GNSS_Positioning_Data_Set(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_GNSS_Positioning_Data_Set, GNSS_Positioning_Data_Set_sequence_of,
                                                  1, max_GNSS_Set, FALSE);

  return offset;
}



static int
dissect_lcsap_Horizontal_Accuracy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_lcsap_INTEGER_0_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Horizontal_Speed_And_Bearing_sequence[] = {
  { &hf_lcsap_bearing       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Bearing },
  { &hf_lcsap_horizontal_Speed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_INTEGER_0_2047 },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Horizontal_Speed_And_Bearing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Horizontal_Speed_And_Bearing, Horizontal_Speed_And_Bearing_sequence);

  return offset;
}


static const per_sequence_t Horizontal_Velocity_sequence[] = {
  { &hf_lcsap_horizontal_Speed_And_Bearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Horizontal_Speed_And_Bearing },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Horizontal_Velocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Horizontal_Velocity, Horizontal_Velocity_sequence);

  return offset;
}



static int
dissect_lcsap_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}


static const value_string lcsap_Vertical_Speed_Direction_vals[] = {
  {   0, "upward" },
  {   1, "downward" },
  { 0, NULL }
};


static int
dissect_lcsap_Vertical_Speed_Direction(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t Vertical_Velocity_sequence[] = {
  { &hf_lcsap_vertical_Speed, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_INTEGER_0_255 },
  { &hf_lcsap_vertical_Speed_Direction, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Vertical_Speed_Direction },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Vertical_Velocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Vertical_Velocity, Vertical_Velocity_sequence);

  return offset;
}


static const per_sequence_t Horizontal_With_Vertical_Velocity_sequence[] = {
  { &hf_lcsap_horizontal_Speed_And_Bearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Horizontal_Speed_And_Bearing },
  { &hf_lcsap_vertical_Velocity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Vertical_Velocity },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Horizontal_With_Vertical_Velocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Horizontal_With_Vertical_Velocity, Horizontal_With_Vertical_Velocity_sequence);

  return offset;
}


static const per_sequence_t Horizontal_Velocity_With_Uncertainty_sequence[] = {
  { &hf_lcsap_horizontal_Speed_And_Bearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Horizontal_Speed_And_Bearing },
  { &hf_lcsap_uncertainty_Speed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_INTEGER_0_255 },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Horizontal_Velocity_With_Uncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Horizontal_Velocity_With_Uncertainty, Horizontal_Velocity_With_Uncertainty_sequence);

  return offset;
}


static const per_sequence_t Horizontal_With_Vertical_Velocity_And_Uncertainty_sequence[] = {
  { &hf_lcsap_horizontal_Speed_And_Bearing, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Horizontal_Speed_And_Bearing },
  { &hf_lcsap_vertical_Velocity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Vertical_Velocity },
  { &hf_lcsap_horizontal_Uncertainty_Speed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_INTEGER_0_255 },
  { &hf_lcsap_vertical_Uncertainty_Speed, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_INTEGER_0_255 },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Horizontal_With_Vertical_Velocity_And_Uncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Horizontal_With_Vertical_Velocity_And_Uncertainty, Horizontal_With_Vertical_Velocity_And_Uncertainty_sequence);

  return offset;
}



static int
dissect_lcsap_IMSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 8, FALSE, NULL);

  return offset;
}



static int
dissect_lcsap_IMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, NULL);

  return offset;
}


static const value_string lcsap_Include_Velocity_vals[] = {
  {   0, "requested" },
  {   1, "not-Requested" },
  { 0, NULL }
};


static int
dissect_lcsap_Include_Velocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lcsap_Location_Type_vals[] = {
  {   0, "geographic-Information" },
  {   1, "assistance-Information" },
  { 0, NULL }
};


static int
dissect_lcsap_Location_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lcsap_Radio_Network_Layer_Cause_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};


static int
dissect_lcsap_Radio_Network_Layer_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lcsap_Transport_Layer_Cause_vals[] = {
  {   0, "tranport-Resource-Unavailable" },
  {   1, "unspecified" },
  { 0, NULL }
};


static int
dissect_lcsap_Transport_Layer_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lcsap_Protocol_Cause_vals[] = {
  {   0, "transfer-Syntax-Error" },
  {   1, "abstract-Syntax-Error-Reject" },
  {   2, "abstract-Syntax-Error-Ignore-And-Notify" },
  {   3, "message-Not-Compatible-With-Receiver-State" },
  {   4, "semantic-Error" },
  {   5, "unspecified" },
  {   6, "abstract-Syntax-Error" },
  { 0, NULL }
};


static int
dissect_lcsap_Protocol_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lcsap_Misc_Cause_vals[] = {
  {   0, "processing-Overload" },
  {   1, "hardware-Failure" },
  {   2, "o-And-M-Intervention" },
  {   3, "unspecified" },
  { 0, NULL }
};


static int
dissect_lcsap_Misc_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string lcsap_LCS_Cause_vals[] = {
  {   0, "radio-Network-Layer" },
  {   1, "transport-Layer" },
  {   2, "protocol" },
  {   3, "misc" },
  { 0, NULL }
};

static const per_choice_t LCS_Cause_choice[] = {
  {   0, &hf_lcsap_radio_Network_Layer, ASN1_NO_EXTENSIONS     , dissect_lcsap_Radio_Network_Layer_Cause },
  {   1, &hf_lcsap_transport_Layer, ASN1_NO_EXTENSIONS     , dissect_lcsap_Transport_Layer_Cause },
  {   2, &hf_lcsap_protocol      , ASN1_NO_EXTENSIONS     , dissect_lcsap_Protocol_Cause },
  {   3, &hf_lcsap_misc          , ASN1_NO_EXTENSIONS     , dissect_lcsap_Misc_Cause },
  { 0, NULL, 0, NULL }
};

static int
dissect_lcsap_LCS_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lcsap_LCS_Cause, LCS_Cause_choice,
                                 NULL);

  return offset;
}


static const value_string lcsap_LCS_Client_Type_vals[] = {
  {   0, "emergency-Services" },
  {   1, "value-Added-Services" },
  {   2, "pLMN-Operator-Services" },
  {   3, "lawful-Intercept-Services" },
  {   4, "pLMN-Operator-broadcast-Services" },
  {   5, "pLMN-Operator-OM" },
  {   6, "pLMN-Operator-Anonymous-Statistics" },
  {   7, "pLMN-Operator-Target-MS-Service-Support" },
  { 0, NULL }
};


static int
dissect_lcsap_LCS_Client_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lcsap_LCS_Priority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const value_string lcsap_Vertical_Requested_vals[] = {
  {   0, "vertical-coordinate-Is-Not-Requested" },
  {   1, "vertical-coordinate-Is-Requested" },
  { 0, NULL }
};


static int
dissect_lcsap_Vertical_Requested(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_lcsap_Vertical_Accuracy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const value_string lcsap_Response_Time_vals[] = {
  {   0, "low-Delay" },
  {   1, "delay-Tolerant" },
  { 0, NULL }
};


static int
dissect_lcsap_Response_Time(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t LCS_QoS_sequence[] = {
  { &hf_lcsap_horizontal_Accuracy, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_Horizontal_Accuracy },
  { &hf_lcsap_vertical_Requested, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_Vertical_Requested },
  { &hf_lcsap_vertical_Accuracy, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_Vertical_Accuracy },
  { &hf_lcsap_response_Time , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_Response_Time },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_LCS_QoS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_LCS_QoS, LCS_QoS_sequence);

  return offset;
}


static const per_sequence_t MultipleAPDUs_sequence_of[1] = {
  { &hf_lcsap_MultipleAPDUs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_APDU },
};

static int
dissect_lcsap_MultipleAPDUs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_MultipleAPDUs, MultipleAPDUs_sequence_of,
                                                  1, 3, FALSE);

  return offset;
}


static const value_string lcsap_Network_Element_vals[] = {
  {   0, "global-eNB-ID" },
  {   1, "e-SMLC-ID" },
  { 0, NULL }
};

static const per_choice_t Network_Element_choice[] = {
  {   0, &hf_lcsap_global_eNB_ID , ASN1_NO_EXTENSIONS     , dissect_lcsap_Global_eNB_ID },
  {   1, &hf_lcsap_e_SMLC_ID     , ASN1_NO_EXTENSIONS     , dissect_lcsap_E_SMLC_ID },
  { 0, NULL, 0, NULL }
};

static int
dissect_lcsap_Network_Element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lcsap_Network_Element, Network_Element_choice,
                                 NULL);

  return offset;
}


static const value_string lcsap_Payload_Type_vals[] = {
  {   0, "lPP" },
  {   1, "lPPa" },
  { 0, NULL }
};


static int
dissect_lcsap_Payload_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lcsap_Positioning_Method_And_Usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, FALSE, NULL);

  return offset;
}


static const per_sequence_t Positioning_Data_Set_sequence_of[1] = {
  { &hf_lcsap_Positioning_Data_Set_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Positioning_Method_And_Usage },
};

static int
dissect_lcsap_Positioning_Data_Set(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_Positioning_Data_Set, Positioning_Data_Set_sequence_of,
                                                  1, max_Set, FALSE);

  return offset;
}


static const per_sequence_t Positioning_Data_sequence[] = {
  { &hf_lcsap_positioning_Data_Set, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_Positioning_Data_Set },
  { &hf_lcsap_gNSS_Positioning_Data_Set, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_GNSS_Positioning_Data_Set },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Positioning_Data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Positioning_Data, Positioning_Data_sequence);

  return offset;
}


static const value_string lcsap_Return_Error_Type_vals[] = {
  {   0, "yes" },
  {   1, "no" },
  { 0, NULL }
};


static int
dissect_lcsap_Return_Error_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string lcsap_Return_Error_Cause_vals[] = {
  {   0, "system-Failure" },
  {   1, "protocol-Error" },
  {   2, "destination-Unknown" },
  {   3, "destination-Unreachable" },
  {   4, "congestion" },
  { 0, NULL }
};


static int
dissect_lcsap_Return_Error_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_lcsap_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t UE_Positioning_Capability_sequence[] = {
  { &hf_lcsap_lPP           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_UE_Positioning_Capability(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_UE_Positioning_Capability, UE_Positioning_Capability_sequence);

  return offset;
}


static const value_string lcsap_Velocity_Estimate_vals[] = {
  {   0, "horizontal-Velocity" },
  {   1, "horizontal-With-Vertical-Velocity" },
  {   2, "horizontal-Velocity-With-Uncertainty" },
  {   3, "horizontal-With-Vertical-Velocity-And-Uncertainty" },
  { 0, NULL }
};

static const per_choice_t Velocity_Estimate_choice[] = {
  {   0, &hf_lcsap_horizontal_Velocity, ASN1_EXTENSION_ROOT    , dissect_lcsap_Horizontal_Velocity },
  {   1, &hf_lcsap_horizontal_With_Vertical_Velocity, ASN1_EXTENSION_ROOT    , dissect_lcsap_Horizontal_With_Vertical_Velocity },
  {   2, &hf_lcsap_horizontal_Velocity_With_Uncertainty, ASN1_EXTENSION_ROOT    , dissect_lcsap_Horizontal_Velocity_With_Uncertainty },
  {   3, &hf_lcsap_horizontal_With_Vertical_Velocity_And_Uncertainty, ASN1_EXTENSION_ROOT    , dissect_lcsap_Horizontal_With_Vertical_Velocity_And_Uncertainty },
  { 0, NULL, 0, NULL }
};

static int
dissect_lcsap_Velocity_Estimate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lcsap_Velocity_Estimate, Velocity_Estimate_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Location_Request_sequence[] = {
  { &hf_lcsap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_Container },
  { &hf_lcsap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Location_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Location_Request, Location_Request_sequence);

  return offset;
}


static const per_sequence_t Location_Response_sequence[] = {
  { &hf_lcsap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_Container },
  { &hf_lcsap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Location_Response(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Location_Response, Location_Response_sequence);

  return offset;
}


static const per_sequence_t Location_Abort_Request_sequence[] = {
  { &hf_lcsap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_Container },
  { &hf_lcsap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Location_Abort_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Location_Abort_Request, Location_Abort_Request_sequence);

  return offset;
}


static const per_sequence_t Connection_Oriented_Information_sequence[] = {
  { &hf_lcsap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_Container },
  { &hf_lcsap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Connection_Oriented_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Connection_Oriented_Information, Connection_Oriented_Information_sequence);

  return offset;
}


static const per_sequence_t Connectionless_Information_sequence[] = {
  { &hf_lcsap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_Container },
  { &hf_lcsap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Connectionless_Information(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Connectionless_Information, Connectionless_Information_sequence);

  return offset;
}


static const per_sequence_t Reset_Request_sequence[] = {
  { &hf_lcsap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_Container },
  { &hf_lcsap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Reset_Request(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Reset_Request, Reset_Request_sequence);

  return offset;
}


static const per_sequence_t Reset_Acknowledge_sequence[] = {
  { &hf_lcsap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_Container },
  { &hf_lcsap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Reset_Acknowledge(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Reset_Acknowledge, Reset_Acknowledge_sequence);

  return offset;
}



static int
dissect_lcsap_InitiatingMessage_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_InitiatingMessageValue);

  return offset;
}


static const per_sequence_t InitiatingMessage_sequence[] = {
  { &hf_lcsap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_ProcedureCode },
  { &hf_lcsap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Criticality },
  { &hf_lcsap_initiatingMessagevalue, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_InitiatingMessage_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_InitiatingMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_InitiatingMessage, InitiatingMessage_sequence);

  return offset;
}



static int
dissect_lcsap_SuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_SuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t SuccessfulOutcome_sequence[] = {
  { &hf_lcsap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_ProcedureCode },
  { &hf_lcsap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Criticality },
  { &hf_lcsap_successfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_SuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_SuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_SuccessfulOutcome, SuccessfulOutcome_sequence);

  return offset;
}



static int
dissect_lcsap_UnsuccessfulOutcome_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_UnsuccessfulOutcomeValue);

  return offset;
}


static const per_sequence_t UnsuccessfulOutcome_sequence[] = {
  { &hf_lcsap_procedureCode , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_ProcedureCode },
  { &hf_lcsap_criticality   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Criticality },
  { &hf_lcsap_unsuccessfulOutcome_value, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_UnsuccessfulOutcome_value },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_UnsuccessfulOutcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_UnsuccessfulOutcome, UnsuccessfulOutcome_sequence);

  return offset;
}


static const value_string lcsap_LCS_AP_PDU_vals[] = {
  {   0, "initiatingMessage" },
  {   1, "successfulOutcome" },
  {   2, "unsuccessfulOutcome" },
  { 0, NULL }
};

static const per_choice_t LCS_AP_PDU_choice[] = {
  {   0, &hf_lcsap_initiatingMessage, ASN1_EXTENSION_ROOT    , dissect_lcsap_InitiatingMessage },
  {   1, &hf_lcsap_successfulOutcome, ASN1_EXTENSION_ROOT    , dissect_lcsap_SuccessfulOutcome },
  {   2, &hf_lcsap_unsuccessfulOutcome, ASN1_EXTENSION_ROOT    , dissect_lcsap_UnsuccessfulOutcome },
  { 0, NULL, 0, NULL }
};

static int
dissect_lcsap_LCS_AP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lcsap_LCS_AP_PDU, LCS_AP_PDU_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Accuracy_Fulfillment_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Accuracy_Fulfillment_Indicator(tvb, offset, &asn1_ctx, tree, hf_lcsap_Accuracy_Fulfillment_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_lcsap_Correlation_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Correlation_ID(tvb, offset, &asn1_ctx, tree, hf_lcsap_lcsap_Correlation_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_E_CGI(tvb, offset, &asn1_ctx, tree, hf_lcsap_E_CGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Geographical_Area_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Geographical_Area(tvb, offset, &asn1_ctx, tree, hf_lcsap_Geographical_Area_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IMSI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_IMSI(tvb, offset, &asn1_ctx, tree, hf_lcsap_IMSI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IMEI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_IMEI(tvb, offset, &asn1_ctx, tree, hf_lcsap_IMEI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Include_Velocity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Include_Velocity(tvb, offset, &asn1_ctx, tree, hf_lcsap_Include_Velocity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Location_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Location_Type(tvb, offset, &asn1_ctx, tree, hf_lcsap_Location_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_LCS_Cause(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_Client_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_LCS_Client_Type(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_Client_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_Priority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_LCS_Priority(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_Priority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_QoS_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_LCS_QoS(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_QoS_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MultipleAPDUs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_MultipleAPDUs(tvb, offset, &asn1_ctx, tree, hf_lcsap_MultipleAPDUs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Network_Element_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Network_Element(tvb, offset, &asn1_ctx, tree, hf_lcsap_Network_Element_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Payload_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Payload_Type(tvb, offset, &asn1_ctx, tree, hf_lcsap_Payload_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Positioning_Data_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Positioning_Data(tvb, offset, &asn1_ctx, tree, hf_lcsap_Positioning_Data_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Return_Error_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Return_Error_Type(tvb, offset, &asn1_ctx, tree, hf_lcsap_Return_Error_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Return_Error_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Return_Error_Cause(tvb, offset, &asn1_ctx, tree, hf_lcsap_Return_Error_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Positioning_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_UE_Positioning_Capability(tvb, offset, &asn1_ctx, tree, hf_lcsap_UE_Positioning_Capability_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Velocity_Estimate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Velocity_Estimate(tvb, offset, &asn1_ctx, tree, hf_lcsap_Velocity_Estimate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Location_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Location_Request(tvb, offset, &asn1_ctx, tree, hf_lcsap_Location_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Location_Response_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Location_Response(tvb, offset, &asn1_ctx, tree, hf_lcsap_Location_Response_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Location_Abort_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Location_Abort_Request(tvb, offset, &asn1_ctx, tree, hf_lcsap_Location_Abort_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Connection_Oriented_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Connection_Oriented_Information(tvb, offset, &asn1_ctx, tree, hf_lcsap_Connection_Oriented_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Connectionless_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Connectionless_Information(tvb, offset, &asn1_ctx, tree, hf_lcsap_Connectionless_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Reset_Request(tvb, offset, &asn1_ctx, tree, hf_lcsap_Reset_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_Acknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_Reset_Acknowledge(tvb, offset, &asn1_ctx, tree, hf_lcsap_Reset_Acknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  offset = dissect_lcsap_LCS_AP_PDU(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-lcsap-fn.c ---*/
#line 96 "../../asn1/lcsap/packet-lcsap-template.c"

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(lcsap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}


static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(lcsap_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(lcsap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(lcsap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return (dissector_try_uint(lcsap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_length(tvb) : 0;
}


static void
dissect_lcsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item	*lcsap_item = NULL;
	proto_tree	*lcsap_tree = NULL;

	/* make entry in the Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "LCSAP");

	/* create the lcsap protocol tree */
	lcsap_item = proto_tree_add_item(tree, proto_lcsap, tvb, 0, -1, FALSE);
	lcsap_tree = proto_item_add_subtree(lcsap_item, ett_lcsap);
	
	dissect_LCS_AP_PDU_PDU(tvb, pinfo, lcsap_tree);
}

/*--- proto_reg_handoff_lcsap ---------------------------------------*/
void
proto_reg_handoff_lcsap(void)
{
	static gboolean Initialized=FALSE;
	static dissector_handle_t lcsap_handle;
	static guint SctpPort;

	if (!Initialized) {
		lcsap_handle = find_dissector("lcsap");
		
		dissector_add_handle("sctp.port", lcsap_handle);   /* for "decode-as"  */
		dissector_add_uint("sctp.ppi", LCS_AP_PAYLOAD_PROTOCOL_ID,   lcsap_handle);
		Initialized=TRUE;

/*--- Included file: packet-lcsap-dis-tab.c ---*/
#line 1 "../../asn1/lcsap/packet-lcsap-dis-tab.c"
  dissector_add_uint("lcsap.ies", id_Return_Error_Request, new_create_dissector_handle(dissect_Return_Error_Type_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Destination_ID, new_create_dissector_handle(dissect_Network_Element_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Source_Identity, new_create_dissector_handle(dissect_Network_Element_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Location_Estimate, new_create_dissector_handle(dissect_Geographical_Area_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Correlation_ID, new_create_dissector_handle(dissect_lcsap_Correlation_ID_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Location_Type, new_create_dissector_handle(dissect_Location_Type_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_E_UTRAN_Cell_Identifier, new_create_dissector_handle(dissect_E_CGI_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_LCS_Priority, new_create_dissector_handle(dissect_LCS_Priority_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_LCS_QOS, new_create_dissector_handle(dissect_LCS_QoS_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_LCS_Client_Type, new_create_dissector_handle(dissect_LCS_Client_Type_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_UE_Positioning_Capability, new_create_dissector_handle(dissect_UE_Positioning_Capability_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Include_Velocity, new_create_dissector_handle(dissect_Include_Velocity_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_IMSI, new_create_dissector_handle(dissect_IMSI_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_IMEI, new_create_dissector_handle(dissect_IMEI_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_MultipleAPDUs, new_create_dissector_handle(dissect_MultipleAPDUs_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Positioning_Data, new_create_dissector_handle(dissect_Positioning_Data_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Velocity_Estimate, new_create_dissector_handle(dissect_Velocity_Estimate_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Accuracy_Fulfillment_Indicator, new_create_dissector_handle(dissect_Accuracy_Fulfillment_Indicator_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_LCS_Cause, new_create_dissector_handle(dissect_LCS_Cause_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Payload_Type, new_create_dissector_handle(dissect_Payload_Type_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Return_Error_Cause, new_create_dissector_handle(dissect_Return_Error_Cause_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Location_Service_Request, new_create_dissector_handle(dissect_Location_Request_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.sout", id_Location_Service_Request, new_create_dissector_handle(dissect_Location_Response_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.uout", id_Location_Service_Request, new_create_dissector_handle(dissect_Location_Response_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Connection_Oriented_Information_Transfer, new_create_dissector_handle(dissect_Connection_Oriented_Information_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Connectionless_Information_Transfer, new_create_dissector_handle(dissect_Connectionless_Information_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.uout", id_Connectionless_Information_Transfer, new_create_dissector_handle(dissect_Connectionless_Information_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Location_Abort, new_create_dissector_handle(dissect_Location_Abort_Request_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.sout", id_Location_Abort, new_create_dissector_handle(dissect_Location_Response_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Reset, new_create_dissector_handle(dissect_Reset_Request_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.sout", id_Reset, new_create_dissector_handle(dissect_Reset_Acknowledge_PDU, proto_lcsap));


/*--- End of included file: packet-lcsap-dis-tab.c ---*/
#line 156 "../../asn1/lcsap/packet-lcsap-template.c"
	} else {
		if (SctpPort != 0) {
			dissector_delete_uint("sctp.port", SctpPort, lcsap_handle);
		}
	}

	SctpPort=gbl_lcsapSctpPort;
	if (SctpPort != 0) {
		dissector_add_uint("sctp.port", SctpPort, lcsap_handle);
	}
}

/*--- proto_register_lcsap -------------------------------------------*/
void proto_register_lcsap(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-lcsap-hfarr.c ---*/
#line 1 "../../asn1/lcsap/packet-lcsap-hfarr.c"
    { &hf_lcsap_Accuracy_Fulfillment_Indicator_PDU,
      { "Accuracy-Fulfillment-Indicator", "lcsap.Accuracy_Fulfillment_Indicator",
        FT_UINT32, BASE_DEC, VALS(lcsap_Accuracy_Fulfillment_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_lcsap_Correlation_ID_PDU,
      { "Correlation-ID", "lcsap.Correlation_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_E_CGI_PDU,
      { "E-CGI", "lcsap.E_CGI",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Geographical_Area_PDU,
      { "Geographical-Area", "lcsap.Geographical_Area",
        FT_UINT32, BASE_DEC, VALS(lcsap_Geographical_Area_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_IMSI_PDU,
      { "IMSI", "lcsap.IMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_IMEI_PDU,
      { "IMEI", "lcsap.IMEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Include_Velocity_PDU,
      { "Include-Velocity", "lcsap.Include_Velocity",
        FT_UINT32, BASE_DEC, VALS(lcsap_Include_Velocity_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_Location_Type_PDU,
      { "Location-Type", "lcsap.Location_Type",
        FT_UINT32, BASE_DEC, VALS(lcsap_Location_Type_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_LCS_Cause_PDU,
      { "LCS-Cause", "lcsap.LCS_Cause",
        FT_UINT32, BASE_DEC, VALS(lcsap_LCS_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_LCS_Client_Type_PDU,
      { "LCS-Client-Type", "lcsap.LCS_Client_Type",
        FT_UINT32, BASE_DEC, VALS(lcsap_LCS_Client_Type_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_LCS_Priority_PDU,
      { "LCS-Priority", "lcsap.LCS_Priority",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_LCS_QoS_PDU,
      { "LCS-QoS", "lcsap.LCS_QoS",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_MultipleAPDUs_PDU,
      { "MultipleAPDUs", "lcsap.MultipleAPDUs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Network_Element_PDU,
      { "Network-Element", "lcsap.Network_Element",
        FT_UINT32, BASE_DEC, VALS(lcsap_Network_Element_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_Payload_Type_PDU,
      { "Payload-Type", "lcsap.Payload_Type",
        FT_UINT32, BASE_DEC, VALS(lcsap_Payload_Type_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_Positioning_Data_PDU,
      { "Positioning-Data", "lcsap.Positioning_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Return_Error_Type_PDU,
      { "Return-Error-Type", "lcsap.Return_Error_Type",
        FT_UINT32, BASE_DEC, VALS(lcsap_Return_Error_Type_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_Return_Error_Cause_PDU,
      { "Return-Error-Cause", "lcsap.Return_Error_Cause",
        FT_UINT32, BASE_DEC, VALS(lcsap_Return_Error_Cause_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_UE_Positioning_Capability_PDU,
      { "UE-Positioning-Capability", "lcsap.UE_Positioning_Capability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Velocity_Estimate_PDU,
      { "Velocity-Estimate", "lcsap.Velocity_Estimate",
        FT_UINT32, BASE_DEC, VALS(lcsap_Velocity_Estimate_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_Location_Request_PDU,
      { "Location-Request", "lcsap.Location_Request",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Location_Response_PDU,
      { "Location-Response", "lcsap.Location_Response",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Location_Abort_Request_PDU,
      { "Location-Abort-Request", "lcsap.Location_Abort_Request",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Connection_Oriented_Information_PDU,
      { "Connection-Oriented-Information", "lcsap.Connection_Oriented_Information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Connectionless_Information_PDU,
      { "Connectionless-Information", "lcsap.Connectionless_Information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Reset_Request_PDU,
      { "Reset-Request", "lcsap.Reset_Request",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Reset_Acknowledge_PDU,
      { "Reset-Acknowledge", "lcsap.Reset_Acknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_LCS_AP_PDU_PDU,
      { "LCS-AP-PDU", "lcsap.LCS_AP_PDU",
        FT_UINT32, BASE_DEC, VALS(lcsap_LCS_AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "lcsap.ProtocolIE_Field",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ieid,
      { "ieid", "lcsap.ieid",
        FT_UINT32, BASE_DEC, VALS(lcsap_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_lcsap_criticality,
      { "criticality", "lcsap.criticality",
        FT_UINT32, BASE_DEC, VALS(lcsap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_ie_field_value,
      { "value", "lcsap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_lcsap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "lcsap.ProtocolExtensionField",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_extid,
      { "extid", "lcsap.extid",
        FT_UINT8, BASE_DEC, VALS(lcsap_ProtocolIE_ID_vals), 0,
        "ProtocolExtensionID", HFILL }},
    { &hf_lcsap_extensionValue,
      { "extensionValue", "lcsap.extensionValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_direction_Of_Altitude,
      { "direction-Of-Altitude", "lcsap.direction_Of_Altitude",
        FT_UINT32, BASE_DEC, VALS(lcsap_Direction_Of_Altitude_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_altitude,
      { "altitude", "lcsap.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_pLMNidentity,
      { "pLMNidentity", "lcsap.pLMNidentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_ID", HFILL }},
    { &hf_lcsap_cell_ID,
      { "cell-ID", "lcsap.cell_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CellIdentity", HFILL }},
    { &hf_lcsap_iE_Extensions,
      { "iE-Extensions", "lcsap.iE_Extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_lcsap_geographical_Coordinates,
      { "geographical-Coordinates", "lcsap.geographical_Coordinates",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_uncertainty_Ellipse,
      { "uncertainty-Ellipse", "lcsap.uncertainty_Ellipse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_confidence,
      { "confidence", "lcsap.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_altitude_And_Direction,
      { "altitude-And-Direction", "lcsap.altitude_And_Direction",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_uncertainty_Altitude,
      { "uncertainty-Altitude", "lcsap.uncertainty_Altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_inner_Radius,
      { "inner-Radius", "lcsap.inner_Radius",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_uncertainty_Radius,
      { "uncertainty-Radius", "lcsap.uncertainty_Radius",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uncertainty_Code", HFILL }},
    { &hf_lcsap_offset_Angle,
      { "offset-Angle", "lcsap.offset_Angle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_lcsap_included_Angle,
      { "included-Angle", "lcsap.included_Angle",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Angle", HFILL }},
    { &hf_lcsap_macro_eNB_ID,
      { "macro-eNB-ID", "lcsap.macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_home_eNB_ID,
      { "home-eNB-ID", "lcsap.home_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_point,
      { "point", "lcsap.point",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_point_With_Uncertainty,
      { "point-With-Uncertainty", "lcsap.point_With_Uncertainty",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ellipsoidPoint_With_Uncertainty_Ellipse,
      { "ellipsoidPoint-With-Uncertainty-Ellipse", "lcsap.ellipsoidPoint_With_Uncertainty_Ellipse",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ellipsoid_Point_With_Uncertainty_Ellipse", HFILL }},
    { &hf_lcsap_polygon,
      { "polygon", "lcsap.polygon",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ellipsoid_Point_With_Altitude,
      { "ellipsoid-Point-With-Altitude", "lcsap.ellipsoid_Point_With_Altitude",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid,
      { "ellipsoid-Point-With-Altitude-And-Uncertainty-Ellipsoid", "lcsap.ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ellipsoid_Arc,
      { "ellipsoid-Arc", "lcsap.ellipsoid_Arc",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_latitudeSign,
      { "latitudeSign", "lcsap.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(lcsap_LatitudeSign_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_degreesLatitude,
      { "degreesLatitude", "lcsap.degreesLatitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_degreesLongitude,
      { "degreesLongitude", "lcsap.degreesLongitude",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_pLMN_ID,
      { "pLMN-ID", "lcsap.pLMN_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_eNB_ID,
      { "eNB-ID", "lcsap.eNB_ID",
        FT_UINT32, BASE_DEC, VALS(lcsap_ENB_ID_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_GNSS_Positioning_Data_Set_item,
      { "GNSS-Positioning-Method-And-Usage", "lcsap.GNSS_Positioning_Method_And_Usage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_bearing,
      { "bearing", "lcsap.bearing",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_horizontal_Speed,
      { "horizontal-Speed", "lcsap.horizontal_Speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2047", HFILL }},
    { &hf_lcsap_horizontal_Speed_And_Bearing,
      { "horizontal-Speed-And-Bearing", "lcsap.horizontal_Speed_And_Bearing",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_vertical_Velocity,
      { "vertical-Velocity", "lcsap.vertical_Velocity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_uncertainty_Speed,
      { "uncertainty-Speed", "lcsap.uncertainty_Speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_lcsap_horizontal_Uncertainty_Speed,
      { "horizontal-Uncertainty-Speed", "lcsap.horizontal_Uncertainty_Speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_lcsap_vertical_Uncertainty_Speed,
      { "vertical-Uncertainty-Speed", "lcsap.vertical_Uncertainty_Speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_lcsap_radio_Network_Layer,
      { "radio-Network-Layer", "lcsap.radio_Network_Layer",
        FT_UINT32, BASE_DEC, VALS(lcsap_Radio_Network_Layer_Cause_vals), 0,
        "Radio_Network_Layer_Cause", HFILL }},
    { &hf_lcsap_transport_Layer,
      { "transport-Layer", "lcsap.transport_Layer",
        FT_UINT32, BASE_DEC, VALS(lcsap_Transport_Layer_Cause_vals), 0,
        "Transport_Layer_Cause", HFILL }},
    { &hf_lcsap_protocol,
      { "protocol", "lcsap.protocol",
        FT_UINT32, BASE_DEC, VALS(lcsap_Protocol_Cause_vals), 0,
        "Protocol_Cause", HFILL }},
    { &hf_lcsap_misc,
      { "misc", "lcsap.misc",
        FT_UINT32, BASE_DEC, VALS(lcsap_Misc_Cause_vals), 0,
        "Misc_Cause", HFILL }},
    { &hf_lcsap_horizontal_Accuracy,
      { "horizontal-Accuracy", "lcsap.horizontal_Accuracy",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_vertical_Requested,
      { "vertical-Requested", "lcsap.vertical_Requested",
        FT_UINT32, BASE_DEC, VALS(lcsap_Vertical_Requested_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_vertical_Accuracy,
      { "vertical-Accuracy", "lcsap.vertical_Accuracy",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_response_Time,
      { "response-Time", "lcsap.response_Time",
        FT_UINT32, BASE_DEC, VALS(lcsap_Response_Time_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_MultipleAPDUs_item,
      { "APDU", "lcsap.APDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_global_eNB_ID,
      { "global-eNB-ID", "lcsap.global_eNB_ID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_e_SMLC_ID,
      { "e-SMLC-ID", "lcsap.e_SMLC_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_uncertainty_Code,
      { "uncertainty-Code", "lcsap.uncertainty_Code",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Polygon_item,
      { "Polygon-Point", "lcsap.Polygon_Point",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_positioning_Data_Set,
      { "positioning-Data-Set", "lcsap.positioning_Data_Set",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_gNSS_Positioning_Data_Set,
      { "gNSS-Positioning-Data-Set", "lcsap.gNSS_Positioning_Data_Set",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Positioning_Data_Set_item,
      { "Positioning-Method-And-Usage", "lcsap.Positioning_Method_And_Usage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_uncertainty_SemiMajor,
      { "uncertainty-SemiMajor", "lcsap.uncertainty_SemiMajor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uncertainty_Code", HFILL }},
    { &hf_lcsap_uncertainty_SemiMinor,
      { "uncertainty-SemiMinor", "lcsap.uncertainty_SemiMinor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Uncertainty_Code", HFILL }},
    { &hf_lcsap_orientation_Major_Axis,
      { "orientation-Major-Axis", "lcsap.orientation_Major_Axis",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_lPP,
      { "lPP", "lcsap.lPP",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lcsap_horizontal_Velocity,
      { "horizontal-Velocity", "lcsap.horizontal_Velocity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_horizontal_With_Vertical_Velocity,
      { "horizontal-With-Vertical-Velocity", "lcsap.horizontal_With_Vertical_Velocity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_horizontal_Velocity_With_Uncertainty,
      { "horizontal-Velocity-With-Uncertainty", "lcsap.horizontal_Velocity_With_Uncertainty",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_horizontal_With_Vertical_Velocity_And_Uncertainty,
      { "horizontal-With-Vertical-Velocity-And-Uncertainty", "lcsap.horizontal_With_Vertical_Velocity_And_Uncertainty",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_vertical_Speed,
      { "vertical-Speed", "lcsap.vertical_Speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_lcsap_vertical_Speed_Direction,
      { "vertical-Speed-Direction", "lcsap.vertical_Speed_Direction",
        FT_UINT32, BASE_DEC, VALS(lcsap_Vertical_Speed_Direction_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_protocolIEs,
      { "protocolIEs", "lcsap.protocolIEs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolIE_Container", HFILL }},
    { &hf_lcsap_protocolExtensions,
      { "protocolExtensions", "lcsap.protocolExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolExtensionContainer", HFILL }},
    { &hf_lcsap_initiatingMessage,
      { "initiatingMessage", "lcsap.initiatingMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_successfulOutcome,
      { "successfulOutcome", "lcsap.successfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "lcsap.unsuccessfulOutcome",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_procedureCode,
      { "procedureCode", "lcsap.procedureCode",
        FT_UINT32, BASE_DEC, VALS(lcsap_ProcedureCode_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_initiatingMessagevalue,
      { "value", "lcsap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_lcsap_successfulOutcome_value,
      { "value", "lcsap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_lcsap_unsuccessfulOutcome_value,
      { "value", "lcsap.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},

/*--- End of included file: packet-lcsap-hfarr.c ---*/
#line 174 "../../asn1/lcsap/packet-lcsap-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_lcsap,

/*--- Included file: packet-lcsap-ettarr.c ---*/
#line 1 "../../asn1/lcsap/packet-lcsap-ettarr.c"
    &ett_lcsap_ProtocolIE_Container,
    &ett_lcsap_ProtocolIE_Field,
    &ett_lcsap_ProtocolExtensionContainer,
    &ett_lcsap_ProtocolExtensionField,
    &ett_lcsap_Altitude_And_Direction,
    &ett_lcsap_E_CGI,
    &ett_lcsap_Ellipsoid_Point_With_Uncertainty_Ellipse,
    &ett_lcsap_Ellipsoid_Point_With_Altitude,
    &ett_lcsap_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid,
    &ett_lcsap_Ellipsoid_Arc,
    &ett_lcsap_ENB_ID,
    &ett_lcsap_Geographical_Area,
    &ett_lcsap_Geographical_Coordinates,
    &ett_lcsap_Global_eNB_ID,
    &ett_lcsap_GNSS_Positioning_Data_Set,
    &ett_lcsap_Horizontal_Speed_And_Bearing,
    &ett_lcsap_Horizontal_Velocity,
    &ett_lcsap_Horizontal_With_Vertical_Velocity,
    &ett_lcsap_Horizontal_Velocity_With_Uncertainty,
    &ett_lcsap_Horizontal_With_Vertical_Velocity_And_Uncertainty,
    &ett_lcsap_LCS_Cause,
    &ett_lcsap_LCS_QoS,
    &ett_lcsap_MultipleAPDUs,
    &ett_lcsap_Network_Element,
    &ett_lcsap_Point,
    &ett_lcsap_Point_With_Uncertainty,
    &ett_lcsap_Polygon,
    &ett_lcsap_Polygon_Point,
    &ett_lcsap_Positioning_Data,
    &ett_lcsap_Positioning_Data_Set,
    &ett_lcsap_Uncertainty_Ellipse,
    &ett_lcsap_UE_Positioning_Capability,
    &ett_lcsap_Velocity_Estimate,
    &ett_lcsap_Vertical_Velocity,
    &ett_lcsap_Location_Request,
    &ett_lcsap_Location_Response,
    &ett_lcsap_Location_Abort_Request,
    &ett_lcsap_Connection_Oriented_Information,
    &ett_lcsap_Connectionless_Information,
    &ett_lcsap_Reset_Request,
    &ett_lcsap_Reset_Acknowledge,
    &ett_lcsap_LCS_AP_PDU,
    &ett_lcsap_InitiatingMessage,
    &ett_lcsap_SuccessfulOutcome,
    &ett_lcsap_UnsuccessfulOutcome,

/*--- End of included file: packet-lcsap-ettarr.c ---*/
#line 180 "../../asn1/lcsap/packet-lcsap-template.c"
 };

  module_t *lcsap_module;

  /* Register protocol */
  proto_lcsap = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lcsap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_dissector("lcsap", dissect_lcsap, proto_lcsap);

  /* Register dissector tables */
  lcsap_ies_dissector_table = register_dissector_table("lcsap.ies", "LCS-AP-PROTOCOL-IES", FT_UINT32, BASE_DEC);
  

  lcsap_extension_dissector_table = register_dissector_table("lcsap.extension", "LCS-AP-PROTOCOL-EXTENSION", FT_UINT32, BASE_DEC);
  lcsap_proc_imsg_dissector_table = register_dissector_table("lcsap.proc.imsg", "LCS-AP-ELEMENTARY-PROCEDURE InitiatingMessage", FT_UINT32, BASE_DEC);
  lcsap_proc_sout_dissector_table = register_dissector_table("lcsap.proc.sout", "LCS-AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", FT_UINT32, BASE_DEC);
  lcsap_proc_uout_dissector_table = register_dissector_table("lcsap.proc.uout", "LCS-AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", FT_UINT32, BASE_DEC);
  
  /* Register configuration options for ports */
  lcsap_module = prefs_register_protocol(proto_lcsap, proto_reg_handoff_lcsap);

  prefs_register_uint_preference(lcsap_module, "sctp.port",
                                 "LCSAP SCTP Port",
                                 "Set the SCTP port for LCSAP messages",
                                 10,
                                 &gbl_lcsapSctpPort);

}


