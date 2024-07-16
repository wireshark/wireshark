/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-lcsap.c                                                             */
/* asn2wrs.py -q -L -p lcsap -c ./lcsap.cnf -s ./packet-lcsap-template -D . -O ../.. LCS-AP-CommonDataTypes.asn LCS-AP-Constants.asn LCS-AP-Containers.asn LCS-AP-IEs.asn LCS-AP-PDU-Contents.asn LCS-AP-PDU-Descriptions.asn */

/* packet-lcsap.c
 * Routines for LCS-AP packet dissembly.
 *
 * Copyright (c) 2011 by Spenser Sheng <spenser.sheng@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References:
 * ETSI TS 129 171 V9.2.0 (2010-10)
 */

#include "config.h"

#include <math.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/sctpppids.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-e212.h"
#include "packet-sccp.h"
#include "packet-lcsap.h"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

#define PNAME  "LCS Application Protocol"
#define PSNAME "LCSAP"
#define PFNAME "lcsap"

void proto_register_lcsap(void);
void proto_reg_handoff_lcsap(void);

#define SCTP_PORT_LCSAP 9082
#define max_No_Of_Points               15
#define max_Set                        9
#define max_GNSS_Set                   9
#define max_Add_Pos_Set                8
#define max_Cipher_Set                 16
#define maxProtocolExtensions          65535
#define maxProtocolIEs                 65535

typedef enum _ProcedureCode_enum {
  id_Location_Service_Request =   0,
  id_Connection_Oriented_Information_Transfer =   1,
  id_Connectionless_Information_Transfer =   2,
  id_Location_Abort =   3,
  id_Reset     =   4,
  id_Ciphering_Key_Data_Delivery =   5
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
  id_Velocity_Estimate =  21,
  id_LCS_Service_Type_ID =  22,
  id_Cell_Portion_ID =  23,
  id_Civic_Address =  24,
  id_Barometric_Pressure =  25,
  id_Additional_PositioningDataSet =  26,
  id_RAT_Type  =  27,
  id_Ciphering_Data =  28,
  id_Ciphering_Data_Ack =  29,
  id_Ciphering_Data_Error_Report =  30,
  id_Coverage_Level =  31,
  id_UE_Country_Determination_Indication =  32,
  id_UE_Area_Indication =  33
} ProtocolIE_ID_enum;

/* Initialize the protocol and registered fields */
static int proto_lcsap;

static int hf_lcsap_pos_method;
static int hf_lcsap_pos_usage;
static int hf_lcsap_gnss_pos_method;
static int hf_lcsap_gnss_id;
static int hf_lcsap_gnss_pos_usage;
static int hf_lcsap_APDU_PDU;                     /* APDU */
static int hf_lcsap_Accuracy_Fulfillment_Indicator_PDU;  /* Accuracy_Fulfillment_Indicator */
static int hf_lcsap_Additional_PositioningDataSet_PDU;  /* Additional_PositioningDataSet */
static int hf_lcsap_Barometric_Pressure_PDU;      /* Barometric_Pressure */
static int hf_lcsap_Cell_Portion_ID_PDU;          /* Cell_Portion_ID */
static int hf_lcsap_Ciphering_Data_PDU;           /* Ciphering_Data */
static int hf_lcsap_Ciphering_Data_Ack_PDU;       /* Ciphering_Data_Ack */
static int hf_lcsap_Ciphering_Data_Error_Report_PDU;  /* Ciphering_Data_Error_Report */
static int hf_lcsap_Civic_Address_PDU;            /* Civic_Address */
static int hf_lcsap_lcsap_Correlation_ID_PDU;     /* Correlation_ID */
static int hf_lcsap_E_CGI_PDU;                    /* E_CGI */
static int hf_lcsap_Coverage_Level_PDU;           /* Coverage_Level */
static int hf_lcsap_Geographical_Area_PDU;        /* Geographical_Area */
static int hf_lcsap_IMSI_PDU;                     /* IMSI */
static int hf_lcsap_IMEI_PDU;                     /* IMEI */
static int hf_lcsap_Include_Velocity_PDU;         /* Include_Velocity */
static int hf_lcsap_Location_Type_PDU;            /* Location_Type */
static int hf_lcsap_LCS_Cause_PDU;                /* LCS_Cause */
static int hf_lcsap_LCS_Client_Type_PDU;          /* LCS_Client_Type */
static int hf_lcsap_LCS_Priority_PDU;             /* LCS_Priority */
static int hf_lcsap_LCS_QoS_PDU;                  /* LCS_QoS */
static int hf_lcsap_LCS_Service_Type_ID_PDU;      /* LCS_Service_Type_ID */
static int hf_lcsap_MultipleAPDUs_PDU;            /* MultipleAPDUs */
static int hf_lcsap_Network_Element_PDU;          /* Network_Element */
static int hf_lcsap_Payload_Type_PDU;             /* Payload_Type */
static int hf_lcsap_lcsap_Positioning_Data_PDU;   /* Positioning_Data */
static int hf_lcsap_RAT_Type_PDU;                 /* RAT_Type */
static int hf_lcsap_Return_Error_Type_PDU;        /* Return_Error_Type */
static int hf_lcsap_Return_Error_Cause_PDU;       /* Return_Error_Cause */
static int hf_lcsap_UE_Positioning_Capability_PDU;  /* UE_Positioning_Capability */
static int hf_lcsap_UE_Country_Determination_Indication_PDU;  /* UE_Country_Determination_Indication */
static int hf_lcsap_UE_Area_Indication_PDU;       /* UE_Area_Indication */
static int hf_lcsap_Velocity_Estimate_PDU;        /* Velocity_Estimate */
static int hf_lcsap_Location_Request_PDU;         /* Location_Request */
static int hf_lcsap_Location_Response_PDU;        /* Location_Response */
static int hf_lcsap_Location_Abort_Request_PDU;   /* Location_Abort_Request */
static int hf_lcsap_Connection_Oriented_Information_PDU;  /* Connection_Oriented_Information */
static int hf_lcsap_Connectionless_Information_PDU;  /* Connectionless_Information */
static int hf_lcsap_Reset_Request_PDU;            /* Reset_Request */
static int hf_lcsap_Reset_Acknowledge_PDU;        /* Reset_Acknowledge */
static int hf_lcsap_Ciphering_Key_Data_PDU;       /* Ciphering_Key_Data */
static int hf_lcsap_Ciphering_Key_Data_Result_PDU;  /* Ciphering_Key_Data_Result */
static int hf_lcsap_LCS_AP_PDU_PDU;               /* LCS_AP_PDU */
static int hf_lcsap_ProtocolIE_Container_item;    /* ProtocolIE_Field */
static int hf_lcsap_id;                           /* ProtocolIE_ID */
static int hf_lcsap_criticality;                  /* Criticality */
static int hf_lcsap_ie_field_value;               /* T_ie_field_value */
static int hf_lcsap_ProtocolExtensionContainer_item;  /* ProtocolExtensionField */
static int hf_lcsap_ext_id;                       /* ProtocolExtensionID */
static int hf_lcsap_extensionValue;               /* T_extensionValue */
static int hf_lcsap_Additional_PositioningDataSet_item;  /* Additional_PositioningMethodAndUsage */
static int hf_lcsap_direction_Of_Altitude;        /* Direction_Of_Altitude */
static int hf_lcsap_altitude;                     /* Altitude */
static int hf_lcsap_Ciphering_Data_item;          /* Ciphering_Data_Set */
static int hf_lcsap_Ciphering_Data_Ack_item;      /* Ciphering_Set_ID */
static int hf_lcsap_Ciphering_Data_Error_Report_item;  /* Ciphering_Data_Error_Report_Contents */
static int hf_lcsap_ciphering_Set_ID;             /* Ciphering_Set_ID */
static int hf_lcsap_ciphering_Key;                /* Ciphering_Key */
static int hf_lcsap_c0;                           /* C0 */
static int hf_lcsap_sib_Types;                    /* SIB_Types */
static int hf_lcsap_validity_Start_Time;          /* Validity_Start_Time */
static int hf_lcsap_validity_Duration;            /* Validity_Duration */
static int hf_lcsap_tais_List;                    /* TAIs_List */
static int hf_lcsap_storage_Outcome;              /* Storage_Outcome */
static int hf_lcsap_pLMNidentity;                 /* PLMN_ID */
static int hf_lcsap_cell_ID;                      /* CellIdentity */
static int hf_lcsap_iE_Extensions;                /* ProtocolExtensionContainer */
static int hf_lcsap_geographical_Coordinates;     /* Geographical_Coordinates */
static int hf_lcsap_uncertainty_Ellipse;          /* Uncertainty_Ellipse */
static int hf_lcsap_confidence;                   /* Confidence */
static int hf_lcsap_altitude_And_Direction;       /* Altitude_And_Direction */
static int hf_lcsap_uncertainty_Altitude;         /* Uncertainty_Altitude */
static int hf_lcsap_inner_Radius;                 /* Inner_Radius */
static int hf_lcsap_uncertainty_Radius;           /* Uncertainty_Code */
static int hf_lcsap_offset_Angle;                 /* Angle */
static int hf_lcsap_included_Angle;               /* Angle */
static int hf_lcsap_macro_eNB_ID;                 /* Macro_eNB_ID */
static int hf_lcsap_home_eNB_ID;                  /* Home_eNB_ID */
static int hf_lcsap_short_macro_eNB_ID;           /* Short_Macro_eNB_ID */
static int hf_lcsap_long_macro_eNB_ID;            /* Long_Macro_eNB_ID */
static int hf_lcsap_point;                        /* Point */
static int hf_lcsap_point_With_Uncertainty;       /* Point_With_Uncertainty */
static int hf_lcsap_ellipsoidPoint_With_Uncertainty_Ellipse;  /* Ellipsoid_Point_With_Uncertainty_Ellipse */
static int hf_lcsap_polygon;                      /* Polygon */
static int hf_lcsap_ellipsoid_Point_With_Altitude;  /* Ellipsoid_Point_With_Altitude */
static int hf_lcsap_ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid;  /* Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid */
static int hf_lcsap_ellipsoid_Arc;                /* Ellipsoid_Arc */
static int hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse;  /* High_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse */
static int hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid;  /* High_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid */
static int hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse;  /* High_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse */
static int hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid;  /* High_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid */
static int hf_lcsap_latitudeSign;                 /* LatitudeSign */
static int hf_lcsap_degreesLatitude;              /* DegreesLatitude */
static int hf_lcsap_degreesLongitude;             /* DegreesLongitude */
static int hf_lcsap_pLMN_ID;                      /* PLMN_ID */
static int hf_lcsap_eNB_ID;                       /* ENB_ID */
static int hf_lcsap_GNSS_Positioning_Data_Set_item;  /* GNSS_Positioning_Method_And_Usage */
static int hf_lcsap_high_Accuracy_Geographical_Coordinates;  /* High_Accuracy_Geographical_Coordinates */
static int hf_lcsap_high_Accuracy_Uncertainty_Ellipse;  /* High_Accuracy_Uncertainty_Ellipse */
static int hf_lcsap_high_Accuracy_Scalable_Uncertainty_Ellipse;  /* High_Accuracy_Scalable_Uncertainty_Ellipse */
static int hf_lcsap_high_Accuracy_Altitude;       /* High_Accuracy_Altitude */
static int hf_lcsap_high_Accuracy_Uncertainty_Altitude;  /* High_Accuracy_Uncertainty_Code */
static int hf_lcsap_vertical_Confidence;          /* Confidence */
static int hf_lcsap_high_Accuracy_Scalable_Uncertainty_Altitude;  /* High_Accuracy_Scalable_Uncertainty_Altitude */
static int hf_lcsap_high_Accuracy_DegreesLatitude;  /* High_Accuracy_DegreesLatitude */
static int hf_lcsap_high_Accuracy_DegreesLongitude;  /* High_Accuracy_DegreesLongitude */
static int hf_lcsap_high_Accuracy_Uncertainty_SemiMajor;  /* High_Accuracy_Uncertainty_Code */
static int hf_lcsap_high_Accuracy_Uncertainty_SemiMinor;  /* High_Accuracy_Uncertainty_Code */
static int hf_lcsap_orientation_Major_Axis;       /* INTEGER_0_179 */
static int hf_lcsap_high_Accuracy_Extended_Uncertainty_SemiMajor;  /* High_Accuracy_Extended_Uncertainty_Code */
static int hf_lcsap_high_Accuracy_Extended_Uncertainty_SemiMinor;  /* High_Accuracy_Extended_Uncertainty_Code */
static int hf_lcsap_high_Accuracy_Extended_Uncertainty_Ellipse;  /* High_Accuracy_Extended_Uncertainty_Ellipse */
static int hf_lcsap_high_Accuracy_Extended_Uncertainty_Altitude;  /* High_Accuracy_Extended_Uncertainty_Code */
static int hf_lcsap_bearing;                      /* INTEGER_0_359 */
static int hf_lcsap_horizontal_Speed;             /* INTEGER_0_2047 */
static int hf_lcsap_horizontal_Speed_And_Bearing;  /* Horizontal_Speed_And_Bearing */
static int hf_lcsap_vertical_Velocity;            /* Vertical_Velocity */
static int hf_lcsap_uncertainty_Speed;            /* INTEGER_0_255 */
static int hf_lcsap_horizontal_Uncertainty_Speed;  /* INTEGER_0_255 */
static int hf_lcsap_vertical_Uncertainty_Speed;   /* INTEGER_0_255 */
static int hf_lcsap_radio_Network_Layer;          /* Radio_Network_Layer_Cause */
static int hf_lcsap_transport_Layer;              /* Transport_Layer_Cause */
static int hf_lcsap_protocol;                     /* Protocol_Cause */
static int hf_lcsap_misc;                         /* Misc_Cause */
static int hf_lcsap_horizontal_Accuracy;          /* Horizontal_Accuracy */
static int hf_lcsap_vertical_Requested;           /* Vertical_Requested */
static int hf_lcsap_vertical_Accuracy;            /* Vertical_Accuracy */
static int hf_lcsap_response_Time;                /* Response_Time */
static int hf_lcsap_MultipleAPDUs_item;           /* APDU */
static int hf_lcsap_global_eNB_ID;                /* Global_eNB_ID */
static int hf_lcsap_e_SMLC_ID;                    /* E_SMLC_ID */
static int hf_lcsap_uncertainty_Code;             /* Uncertainty_Code */
static int hf_lcsap_Polygon_item;                 /* Polygon_Point */
static int hf_lcsap_positioning_Data_Set;         /* Positioning_Data_Set */
static int hf_lcsap_gNSS_Positioning_Data_Set;    /* GNSS_Positioning_Data_Set */
static int hf_lcsap_Positioning_Data_Set_item;    /* Positioning_Method_And_Usage */
static int hf_lcsap_uncertainty_SemiMajor;        /* Uncertainty_Code */
static int hf_lcsap_uncertainty_SemiMinor;        /* Uncertainty_Code */
static int hf_lcsap_orientation_Major_Axis_01;    /* Orientation_Major_Axis */
static int hf_lcsap_lPP;                          /* BOOLEAN */
static int hf_lcsap_country;                      /* Country */
static int hf_lcsap_international_area_indication;  /* International_Area_Indication */
static int hf_lcsap_horizontal_Velocity;          /* Horizontal_Velocity */
static int hf_lcsap_horizontal_With_Vertical_Velocity;  /* Horizontal_With_Vertical_Velocity */
static int hf_lcsap_horizontal_Velocity_With_Uncertainty;  /* Horizontal_Velocity_With_Uncertainty */
static int hf_lcsap_horizontal_With_Vertical_Velocity_And_Uncertainty;  /* Horizontal_With_Vertical_Velocity_And_Uncertainty */
static int hf_lcsap_vertical_Speed;               /* INTEGER_0_255 */
static int hf_lcsap_vertical_Speed_Direction;     /* Vertical_Speed_Direction */
static int hf_lcsap_protocolIEs;                  /* ProtocolIE_Container */
static int hf_lcsap_protocolExtensions;           /* ProtocolExtensionContainer */
static int hf_lcsap_initiatingMessage;            /* InitiatingMessage */
static int hf_lcsap_successfulOutcome;            /* SuccessfulOutcome */
static int hf_lcsap_unsuccessfulOutcome;          /* UnsuccessfulOutcome */
static int hf_lcsap_procedureCode;                /* ProcedureCode */
static int hf_lcsap_initiatingMessagevalue;       /* InitiatingMessage_value */
static int hf_lcsap_successfulOutcome_value;      /* SuccessfulOutcome_value */
static int hf_lcsap_unsuccessfulOutcome_value;    /* UnsuccessfulOutcome_value */

/* Initialize the subtree pointers */
static int ett_lcsap;
static int ett_lcsap_plmnd_id;
static int ett_lcsap_imsi;
static int ett_lcsap_civic_address;

static int ett_lcsap_ProtocolIE_Container;
static int ett_lcsap_ProtocolIE_Field;
static int ett_lcsap_ProtocolExtensionContainer;
static int ett_lcsap_ProtocolExtensionField;
static int ett_lcsap_Additional_PositioningDataSet;
static int ett_lcsap_Altitude_And_Direction;
static int ett_lcsap_Ciphering_Data;
static int ett_lcsap_Ciphering_Data_Ack;
static int ett_lcsap_Ciphering_Data_Error_Report;
static int ett_lcsap_Ciphering_Data_Set;
static int ett_lcsap_Ciphering_Data_Error_Report_Contents;
static int ett_lcsap_E_CGI;
static int ett_lcsap_Ellipsoid_Point_With_Uncertainty_Ellipse;
static int ett_lcsap_Ellipsoid_Point_With_Altitude;
static int ett_lcsap_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid;
static int ett_lcsap_Ellipsoid_Arc;
static int ett_lcsap_ENB_ID;
static int ett_lcsap_Geographical_Area;
static int ett_lcsap_Geographical_Coordinates;
static int ett_lcsap_Global_eNB_ID;
static int ett_lcsap_GNSS_Positioning_Data_Set;
static int ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse;
static int ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse;
static int ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid;
static int ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid;
static int ett_lcsap_High_Accuracy_Geographical_Coordinates;
static int ett_lcsap_High_Accuracy_Uncertainty_Ellipse;
static int ett_lcsap_High_Accuracy_Extended_Uncertainty_Ellipse;
static int ett_lcsap_High_Accuracy_Scalable_Uncertainty_Ellipse;
static int ett_lcsap_High_Accuracy_Scalable_Uncertainty_Altitude;
static int ett_lcsap_Horizontal_Speed_And_Bearing;
static int ett_lcsap_Horizontal_Velocity;
static int ett_lcsap_Horizontal_With_Vertical_Velocity;
static int ett_lcsap_Horizontal_Velocity_With_Uncertainty;
static int ett_lcsap_Horizontal_With_Vertical_Velocity_And_Uncertainty;
static int ett_lcsap_LCS_Cause;
static int ett_lcsap_LCS_QoS;
static int ett_lcsap_MultipleAPDUs;
static int ett_lcsap_Network_Element;
static int ett_lcsap_Point;
static int ett_lcsap_Point_With_Uncertainty;
static int ett_lcsap_Polygon;
static int ett_lcsap_Polygon_Point;
static int ett_lcsap_Positioning_Data;
static int ett_lcsap_Positioning_Data_Set;
static int ett_lcsap_Uncertainty_Ellipse;
static int ett_lcsap_UE_Positioning_Capability;
static int ett_lcsap_UE_Area_Indication;
static int ett_lcsap_Velocity_Estimate;
static int ett_lcsap_Vertical_Velocity;
static int ett_lcsap_Location_Request;
static int ett_lcsap_Location_Response;
static int ett_lcsap_Location_Abort_Request;
static int ett_lcsap_Connection_Oriented_Information;
static int ett_lcsap_Connectionless_Information;
static int ett_lcsap_Reset_Request;
static int ett_lcsap_Reset_Acknowledge;
static int ett_lcsap_Ciphering_Key_Data;
static int ett_lcsap_Ciphering_Key_Data_Result;
static int ett_lcsap_LCS_AP_PDU;
static int ett_lcsap_InitiatingMessage;
static int ett_lcsap_SuccessfulOutcome;
static int ett_lcsap_UnsuccessfulOutcome;

static expert_field ei_lcsap_civic_data_not_xml;

/* Global variables */
static uint32_t ProcedureCode;
static uint32_t ProtocolIE_ID;
static uint32_t ProtocolExtensionID;
static uint32_t PayloadType = -1;

/* Dissector handles */
static dissector_handle_t lcsap_handle;
static dissector_handle_t lpp_handle;
static dissector_handle_t lppa_handle;
static dissector_handle_t xml_handle;

/* Dissector tables */
static dissector_table_t lcsap_ies_dissector_table;

static dissector_table_t lcsap_extension_dissector_table;
static dissector_table_t lcsap_proc_imsg_dissector_table;
static dissector_table_t lcsap_proc_sout_dissector_table;
static dissector_table_t lcsap_proc_uout_dissector_table;

static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);

static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);
static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *);


/* 7.4.13 Positioning Data
 * Coding of positioning method (bits 8-4)
 */
static const value_string lcsap_pos_method_vals[] = {
  { 0x00, "Cell ID" },
  { 0x01, "Reserved" },
  { 0x02, "E-CID" },
  { 0x03, "Reserved" },
  { 0x04, "OTDOA" },
  { 0x05, "Reserved" },
  { 0x06, "Reserved" },
  { 0x07, "Reserved" },
  { 0x08, "U-TDOA" },
  { 0x09, "Reserved" },
  { 0x0a, "Reserved" },
  { 0x0b, "Reserved" },
  { 0x0c, "Reserved for other location technologies" },
  { 0x0d, "Reserved for other location technologies" },
  { 0x0e, "Reserved for other location technologies" },
  { 0x0f, "Reserved for other location technologies" },
  { 0x10, "Reserved for network specific positioning methods" },
  { 0x11, "Reserved for network specific positioning methods" },
  { 0x12, "Reserved for network specific positioning methods" },
  { 0x13, "Reserved for network specific positioning methods" },
  { 0x14, "Reserved for network specific positioning methods" },
  { 0x15, "Reserved for network specific positioning methods" },
  { 0x16, "Reserved for network specific positioning methods" },
  { 0x17, "Reserved for network specific positioning methods" },
  { 0x18, "Reserved for network specific positioning methods" },
  { 0x19, "Reserved for network specific positioning methods" },
  { 0x1a, "Reserved for network specific positioning methods" },
  { 0x1b, "Reserved for network specific positioning methods" },
  { 0x1c, "Reserved for network specific positioning methods" },
  { 0x1d, "Reserved for network specific positioning methods" },
  { 0x1e, "Reserved for network specific positioning methods" },
  { 0x1f, "Reserved for network specific positioning methods" },
  { 0, NULL }
};

/* Coding of usage (bits 3-1)*/
static const value_string lcsap_pos_usage_vals[] = {
  { 0x00, "Attempted unsuccessfully due to failure or interruption - not used" },
  { 0x01, "Attempted successfully: results not used to generate location - not used." },
  { 0x02, "Attempted successfully: results used to verify but not generate location - not used." },
  { 0x03, "Attempted successfully: results used to generate location" },
  { 0x04, "Attempted successfully: case where UE supports multiple mobile based positioning methods and the actual method or methods used by the UE cannot be determined." },
  { 0x05, "Reserved" },
  { 0x06, "Reserved" },
  { 0x07, "Reserved" },
  { 0, NULL }
};

/* Coding of Method (Bits 8-7) */
static const value_string lcsap_gnss_pos_method_vals[] = {
  { 0x00, "UE-Based" },
  { 0x01, "UE-Assisted" },
  { 0x02, "Conventional" },
  { 0x03, "Reserved" },
  { 0, NULL }
};

/* Coding of GNSS ID (Bits 6-4) */
static const value_string lcsap_gnss_id_vals[] = {
  { 0x00, "GPS" },
  { 0x01, "Galileo" },
  { 0x02, "SBAS" },
  { 0x03, "Modernized GPS" },
  { 0x04, "QZSS" },
  { 0x05, "GLONASS" },
  { 0x06, "Reserved" },
  { 0x07, "Reserved" },
  { 0, NULL }
};

/* Coding of usage (bits 3- 1) */
static const value_string lcsap_gnss_pos_usage_vals[] = {
  { 0x00, "Attempted unsuccessfully due to failure or interruption" },
  { 0x01, "Attempted successfully: results not used to generate location" },
  { 0x02, "Attempted successfully: results used to verify but not generate location" },
  { 0x03, "Attempted successfully: results used to generate location" },
  { 0x04, "Attempted successfully: case where UE supports multiple mobile based positioning methods and the actual method or methods used by the UE cannot be determined." },
  { 0x05, "Reserved" },
  { 0x06, "Reserved" },
  { 0x07, "Reserved" },
  { 0, NULL }
};



static const value_string lcsap_Criticality_vals[] = {
  {   0, "reject" },
  {   1, "ignore" },
  {   2, "notify" },
  { 0, NULL }
};


static int
dissect_lcsap_Criticality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}


static const value_string lcsap_ProcedureCode_vals[] = {
  { id_Location_Service_Request, "id-Location-Service-Request" },
  { id_Connection_Oriented_Information_Transfer, "id-Connection-Oriented-Information-Transfer" },
  { id_Connectionless_Information_Transfer, "id-Connectionless-Information-Transfer" },
  { id_Location_Abort, "id-Location-Abort" },
  { id_Reset, "id-Reset" },
  { id_Ciphering_Key_Data_Delivery, "id-Ciphering-Key-Data-Delivery" },
  { 0, NULL }
};


static int
dissect_lcsap_ProcedureCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, &ProcedureCode, false);


  {
    uint8_t tmp = tvb_get_uint8(tvb, 0);

    if (tmp == 0)
      col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%sReq",
                   val_to_str_const(ProcedureCode, lcsap_ProcedureCode_vals, "unknown message"));
    else if (tmp == 32)
      col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%sResp",
                   val_to_str_const(ProcedureCode, lcsap_ProcedureCode_vals, "unknown message"));
    else
      col_add_str(actx->pinfo->cinfo, COL_INFO,
                   val_to_str_const(ProcedureCode, lcsap_ProcedureCode_vals, "unknown message"));
  }

  return offset;
}



static int
dissect_lcsap_ProtocolExtensionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolExtensionID, false);

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
  { id_LCS_Service_Type_ID, "id-LCS-Service-Type-ID" },
  { id_Cell_Portion_ID, "id-Cell-Portion-ID" },
  { id_Civic_Address, "id-Civic-Address" },
  { id_Barometric_Pressure, "id-Barometric-Pressure" },
  { id_Additional_PositioningDataSet, "id-Additional-PositioningDataSet" },
  { id_RAT_Type, "id-RAT-Type" },
  { id_Ciphering_Data, "id-Ciphering-Data" },
  { id_Ciphering_Data_Ack, "id-Ciphering-Data-Ack" },
  { id_Ciphering_Data_Error_Report, "id-Ciphering-Data-Error-Report" },
  { id_Coverage_Level, "id-Coverage-Level" },
  { id_UE_Country_Determination_Indication, "id-UE-Country-Determination-Indication" },
  { id_UE_Area_Indication, "id-UE-Area-Indication" },
  { 0, NULL }
};


static int
dissect_lcsap_ProtocolIE_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, &ProtocolIE_ID, false);

  if (tree) {
    proto_item_append_text(proto_item_get_parent_nth(actx->created_item, 2), ": %s",
                           val_to_str(ProtocolIE_ID, VALS(lcsap_ProtocolIE_ID_vals), "unknown (%d)"));
  }
  return offset;
}



static int
dissect_lcsap_T_ie_field_value(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolIEFieldValue);

  return offset;
}


static const per_sequence_t ProtocolIE_Field_sequence[] = {
  { &hf_lcsap_id            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_ID },
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
                                                  0, maxProtocolIEs, false);

  return offset;
}



static int
dissect_lcsap_T_extensionValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type_pdu_new(tvb, offset, actx, tree, hf_index, dissect_ProtocolExtensionFieldExtensionValue);

  return offset;
}


static const per_sequence_t ProtocolExtensionField_sequence[] = {
  { &hf_lcsap_ext_id        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolExtensionID },
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
                                                  1, maxProtocolExtensions, false);

  return offset;
}



static int
dissect_lcsap_APDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);


  if (parameter_tvb) {
    switch (PayloadType) {
    case 0:
      /* LPP */
      if (lpp_handle) {
        call_dissector(lpp_handle, parameter_tvb, actx->pinfo, tree);
      }
      break;
    case 1:
      /* LPPa */
      if (lppa_handle) {
        call_dissector(lppa_handle, parameter_tvb, actx->pinfo, tree);
      }
      break;
    default:
      break;
    }
  }
  PayloadType = -1;


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
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_lcsap_Additional_PositioningMethodAndUsage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

  return offset;
}


static const per_sequence_t Additional_PositioningDataSet_sequence_of[1] = {
  { &hf_lcsap_Additional_PositioningDataSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Additional_PositioningMethodAndUsage },
};

static int
dissect_lcsap_Additional_PositioningDataSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_Additional_PositioningDataSet, Additional_PositioningDataSet_sequence_of,
                                                  1, max_Add_Pos_Set, false);

  return offset;
}



static int
dissect_lcsap_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

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
                                     2, NULL, false, 0, NULL);

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
                                                            0U, 179U, NULL, false);

  return offset;
}



static int
dissect_lcsap_Barometric_Pressure(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            30000U, 115000U, NULL, false);

  return offset;
}



static int
dissect_lcsap_C0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 128, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lcsap_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lcsap_Cell_Portion_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, true);

  return offset;
}



static int
dissect_lcsap_Ciphering_Set_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_lcsap_Ciphering_Key(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, false, NULL);

  return offset;
}



static int
dissect_lcsap_SIB_Types(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}



static int
dissect_lcsap_Validity_Start_Time(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}



static int
dissect_lcsap_Validity_Duration(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_lcsap_TAIs_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       7, 97, false, NULL);

  return offset;
}


static const per_sequence_t Ciphering_Data_Set_sequence[] = {
  { &hf_lcsap_ciphering_Set_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Ciphering_Set_ID },
  { &hf_lcsap_ciphering_Key , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Ciphering_Key },
  { &hf_lcsap_c0            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_C0 },
  { &hf_lcsap_sib_Types     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_SIB_Types },
  { &hf_lcsap_validity_Start_Time, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Validity_Start_Time },
  { &hf_lcsap_validity_Duration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Validity_Duration },
  { &hf_lcsap_tais_List     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_TAIs_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Ciphering_Data_Set(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Ciphering_Data_Set, Ciphering_Data_Set_sequence);

  return offset;
}


static const per_sequence_t Ciphering_Data_sequence_of[1] = {
  { &hf_lcsap_Ciphering_Data_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Ciphering_Data_Set },
};

static int
dissect_lcsap_Ciphering_Data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_Ciphering_Data, Ciphering_Data_sequence_of,
                                                  1, max_Cipher_Set, false);

  return offset;
}


static const per_sequence_t Ciphering_Data_Ack_sequence_of[1] = {
  { &hf_lcsap_Ciphering_Data_Ack_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Ciphering_Set_ID },
};

static int
dissect_lcsap_Ciphering_Data_Ack(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_Ciphering_Data_Ack, Ciphering_Data_Ack_sequence_of,
                                                  1, max_Cipher_Set, false);

  return offset;
}


static const value_string lcsap_Storage_Outcome_vals[] = {
  {   0, "successful" },
  {   1, "failed" },
  { 0, NULL }
};


static int
dissect_lcsap_Storage_Outcome(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t Ciphering_Data_Error_Report_Contents_sequence[] = {
  { &hf_lcsap_ciphering_Set_ID, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Ciphering_Set_ID },
  { &hf_lcsap_storage_Outcome, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Storage_Outcome },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Ciphering_Data_Error_Report_Contents(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Ciphering_Data_Error_Report_Contents, Ciphering_Data_Error_Report_Contents_sequence);

  return offset;
}


static const per_sequence_t Ciphering_Data_Error_Report_sequence_of[1] = {
  { &hf_lcsap_Ciphering_Data_Error_Report_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Ciphering_Data_Error_Report_Contents },
};

static int
dissect_lcsap_Ciphering_Data_Error_Report(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_Ciphering_Data_Error_Report, Ciphering_Data_Error_Report_sequence_of,
                                                  1, max_Cipher_Set, false);

  return offset;
}



static int
dissect_lcsap_Civic_Address(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb=NULL;

    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, &parameter_tvb);

  if (parameter_tvb && xml_handle) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_lcsap_civic_address);
    if (tvb_strncaseeql(parameter_tvb, 0, "<?xml", 5) == 0) {
      call_dissector(xml_handle, parameter_tvb, actx->pinfo, subtree);
    } else {
      proto_tree_add_expert(tree, actx->pinfo, &ei_lcsap_civic_data_not_xml, parameter_tvb, 0, -1);
    }
  }





  return offset;
}



static int
dissect_lcsap_Confidence(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, false);

  return offset;
}



static int
dissect_lcsap_Correlation_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}



static int
dissect_lcsap_Country(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, false, NULL);

  return offset;
}



static int
dissect_lcsap_DegreesLatitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int32_t degrees;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, &degrees, false);

  proto_item_append_text(actx->created_item, " (%.5f degrees)", (((double)degrees/8388607) * 90));


  return offset;
}



static int
dissect_lcsap_DegreesLongitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  int32_t degrees;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, &degrees, false);

  proto_item_append_text(actx->created_item, " (%.5f degrees)", (((double)degrees/16777215) * 360));


  return offset;
}




static int
dissect_lcsap_PLMN_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb=NULL;
  proto_tree *subtree;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, false, &parameter_tvb);
  if(tvb_reported_length(tvb)==0)
    return offset;

  if (!parameter_tvb)
    return offset;
  subtree = proto_item_add_subtree(actx->created_item, ett_lcsap_plmnd_id);
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_NONE, false);

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


static const value_string lcsap_Coverage_Level_vals[] = {
  {   0, "extendedcoverage" },
  { 0, NULL }
};


static int
dissect_lcsap_Coverage_Level(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

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
                                     2, NULL, false, 0, NULL);

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
  uint32_t uncertainty_code;

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, &uncertainty_code, false);

  proto_item_append_text(actx->created_item, " (%.1f m)", 10 * (pow(1.1, (double)uncertainty_code) - 1));


  return offset;
}



static int
dissect_lcsap_Orientation_Major_Axis(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 89U, NULL, false);

  return offset;
}


static const per_sequence_t Uncertainty_Ellipse_sequence[] = {
  { &hf_lcsap_uncertainty_SemiMajor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Uncertainty_Code },
  { &hf_lcsap_uncertainty_SemiMinor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Uncertainty_Code },
  { &hf_lcsap_orientation_Major_Axis_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Orientation_Major_Axis },
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
                                                            0U, 127U, NULL, false);

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
                                                            0U, 65535U, NULL, false);

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
                                     20, 20, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lcsap_Home_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lcsap_Short_Macro_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     18, 18, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_lcsap_Long_Macro_eNB_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     21, 21, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string lcsap_ENB_ID_vals[] = {
  {   0, "macro-eNB-ID" },
  {   1, "home-eNB-ID" },
  {   2, "short-macro-eNB-ID" },
  {   3, "long-macro-eNB-ID" },
  { 0, NULL }
};

static const per_choice_t ENB_ID_choice[] = {
  {   0, &hf_lcsap_macro_eNB_ID  , ASN1_EXTENSION_ROOT    , dissect_lcsap_Macro_eNB_ID },
  {   1, &hf_lcsap_home_eNB_ID   , ASN1_EXTENSION_ROOT    , dissect_lcsap_Home_eNB_ID },
  {   2, &hf_lcsap_short_macro_eNB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_lcsap_Short_Macro_eNB_ID },
  {   3, &hf_lcsap_long_macro_eNB_ID, ASN1_NOT_EXTENSION_ROOT, dissect_lcsap_Long_Macro_eNB_ID },
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
                                                            0U, 255U, NULL, false);

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
                                                  1, max_No_Of_Points, false);

  return offset;
}



static int
dissect_lcsap_High_Accuracy_DegreesLatitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            INT32_MIN, 2147483647U, NULL, false);

  return offset;
}



static int
dissect_lcsap_High_Accuracy_DegreesLongitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            INT32_MIN, 2147483647U, NULL, false);

  return offset;
}


static const per_sequence_t High_Accuracy_Geographical_Coordinates_sequence[] = {
  { &hf_lcsap_high_Accuracy_DegreesLatitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_DegreesLatitude },
  { &hf_lcsap_high_Accuracy_DegreesLongitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_DegreesLongitude },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_High_Accuracy_Geographical_Coordinates(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_High_Accuracy_Geographical_Coordinates, High_Accuracy_Geographical_Coordinates_sequence);

  return offset;
}



static int
dissect_lcsap_High_Accuracy_Uncertainty_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_lcsap_INTEGER_0_179(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 179U, NULL, false);

  return offset;
}


static const per_sequence_t High_Accuracy_Uncertainty_Ellipse_sequence[] = {
  { &hf_lcsap_high_Accuracy_Uncertainty_SemiMajor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Uncertainty_Code },
  { &hf_lcsap_high_Accuracy_Uncertainty_SemiMinor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Uncertainty_Code },
  { &hf_lcsap_orientation_Major_Axis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_INTEGER_0_179 },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_High_Accuracy_Uncertainty_Ellipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_High_Accuracy_Uncertainty_Ellipse, High_Accuracy_Uncertainty_Ellipse_sequence);

  return offset;
}


static const per_sequence_t High_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse_sequence[] = {
  { &hf_lcsap_high_Accuracy_Geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Geographical_Coordinates },
  { &hf_lcsap_high_Accuracy_Uncertainty_Ellipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Uncertainty_Ellipse },
  { &hf_lcsap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Confidence },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_High_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse, High_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse_sequence);

  return offset;
}



static int
dissect_lcsap_High_Accuracy_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -64000, 1280000U, NULL, false);

  return offset;
}


static const per_sequence_t High_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid_sequence[] = {
  { &hf_lcsap_high_Accuracy_Geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Geographical_Coordinates },
  { &hf_lcsap_high_Accuracy_Altitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Altitude },
  { &hf_lcsap_high_Accuracy_Uncertainty_Ellipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Uncertainty_Ellipse },
  { &hf_lcsap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Confidence },
  { &hf_lcsap_high_Accuracy_Uncertainty_Altitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Uncertainty_Code },
  { &hf_lcsap_vertical_Confidence, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Confidence },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_High_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid, High_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid_sequence);

  return offset;
}



static int
dissect_lcsap_High_Accuracy_Extended_Uncertainty_Code(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t High_Accuracy_Extended_Uncertainty_Ellipse_sequence[] = {
  { &hf_lcsap_high_Accuracy_Extended_Uncertainty_SemiMajor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Extended_Uncertainty_Code },
  { &hf_lcsap_high_Accuracy_Extended_Uncertainty_SemiMinor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Extended_Uncertainty_Code },
  { &hf_lcsap_orientation_Major_Axis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_INTEGER_0_179 },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_High_Accuracy_Extended_Uncertainty_Ellipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_High_Accuracy_Extended_Uncertainty_Ellipse, High_Accuracy_Extended_Uncertainty_Ellipse_sequence);

  return offset;
}


static const value_string lcsap_High_Accuracy_Scalable_Uncertainty_Ellipse_vals[] = {
  {   0, "high-Accuracy-Uncertainty-Ellipse" },
  {   1, "high-Accuracy-Extended-Uncertainty-Ellipse" },
  { 0, NULL }
};

static const per_choice_t High_Accuracy_Scalable_Uncertainty_Ellipse_choice[] = {
  {   0, &hf_lcsap_high_Accuracy_Uncertainty_Ellipse, ASN1_NO_EXTENSIONS     , dissect_lcsap_High_Accuracy_Uncertainty_Ellipse },
  {   1, &hf_lcsap_high_Accuracy_Extended_Uncertainty_Ellipse, ASN1_NO_EXTENSIONS     , dissect_lcsap_High_Accuracy_Extended_Uncertainty_Ellipse },
  { 0, NULL, 0, NULL }
};

static int
dissect_lcsap_High_Accuracy_Scalable_Uncertainty_Ellipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lcsap_High_Accuracy_Scalable_Uncertainty_Ellipse, High_Accuracy_Scalable_Uncertainty_Ellipse_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t High_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse_sequence[] = {
  { &hf_lcsap_high_Accuracy_Geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Geographical_Coordinates },
  { &hf_lcsap_high_Accuracy_Scalable_Uncertainty_Ellipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Scalable_Uncertainty_Ellipse },
  { &hf_lcsap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Confidence },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_High_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse, High_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse_sequence);

  return offset;
}


static const value_string lcsap_High_Accuracy_Scalable_Uncertainty_Altitude_vals[] = {
  {   0, "high-Accuracy-Uncertainty-Altitude" },
  {   1, "high-Accuracy-Extended-Uncertainty-Altitude" },
  { 0, NULL }
};

static const per_choice_t High_Accuracy_Scalable_Uncertainty_Altitude_choice[] = {
  {   0, &hf_lcsap_high_Accuracy_Uncertainty_Altitude, ASN1_NO_EXTENSIONS     , dissect_lcsap_High_Accuracy_Uncertainty_Code },
  {   1, &hf_lcsap_high_Accuracy_Extended_Uncertainty_Altitude, ASN1_NO_EXTENSIONS     , dissect_lcsap_High_Accuracy_Extended_Uncertainty_Code },
  { 0, NULL, 0, NULL }
};

static int
dissect_lcsap_High_Accuracy_Scalable_Uncertainty_Altitude(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_lcsap_High_Accuracy_Scalable_Uncertainty_Altitude, High_Accuracy_Scalable_Uncertainty_Altitude_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t High_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid_sequence[] = {
  { &hf_lcsap_high_Accuracy_Geographical_Coordinates, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Geographical_Coordinates },
  { &hf_lcsap_high_Accuracy_Altitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Altitude },
  { &hf_lcsap_high_Accuracy_Scalable_Uncertainty_Ellipse, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Scalable_Uncertainty_Ellipse },
  { &hf_lcsap_confidence    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Confidence },
  { &hf_lcsap_high_Accuracy_Scalable_Uncertainty_Altitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_High_Accuracy_Scalable_Uncertainty_Altitude },
  { &hf_lcsap_vertical_Confidence, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_Confidence },
  { &hf_lcsap_iE_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_High_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid, High_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid_sequence);

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
  {   7, "high-Accuracy-Ellipsoid-Point-With-Uncertainty-Ellipse" },
  {   8, "high-Accuracy-Ellipsoid-Point-With-Altitude-And-Uncertainty-Ellipsoid" },
  {   9, "high-Accuracy-Ellipsoid-Point-With-Scalable-Uncertainty-Ellipse" },
  {  10, "high-Accuracy-Ellipsoid-Point-With-Altitude-And-Scalable-Uncertainty-Ellipsoid" },
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
  {   7, &hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse, ASN1_NOT_EXTENSION_ROOT, dissect_lcsap_High_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse },
  {   8, &hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid, ASN1_NOT_EXTENSION_ROOT, dissect_lcsap_High_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid },
  {   9, &hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse, ASN1_NOT_EXTENSION_ROOT, dissect_lcsap_High_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse },
  {  10, &hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid, ASN1_NOT_EXTENSION_ROOT, dissect_lcsap_High_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid },
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
  tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  proto_tree_add_item(tree, hf_lcsap_gnss_pos_method, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_lcsap_gnss_id, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_lcsap_gnss_pos_usage, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);


  return offset;
}


static const per_sequence_t GNSS_Positioning_Data_Set_sequence_of[1] = {
  { &hf_lcsap_GNSS_Positioning_Data_Set_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_GNSS_Positioning_Method_And_Usage },
};

static int
dissect_lcsap_GNSS_Positioning_Data_Set(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_GNSS_Positioning_Data_Set, GNSS_Positioning_Data_Set_sequence_of,
                                                  1, max_GNSS_Set, false);

  return offset;
}



static int
dissect_lcsap_Horizontal_Accuracy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t uncertainty_code;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, &uncertainty_code, false);



  proto_item_append_text(actx->created_item, " (%.1f m)", 10 * (pow(1.1, (double)uncertainty_code) - 1));

  return offset;
}



static int
dissect_lcsap_INTEGER_0_359(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 359U, NULL, false);

  return offset;
}



static int
dissect_lcsap_INTEGER_0_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, false);

  return offset;
}


static const per_sequence_t Horizontal_Speed_And_Bearing_sequence[] = {
  { &hf_lcsap_bearing       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_INTEGER_0_359 },
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
                                                            0U, 255U, NULL, false);

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
                                     2, NULL, false, 0, NULL);

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
  tvbuff_t *imsi_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 8, false, &imsi_tvb);

  if (imsi_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_lcsap_imsi);
    dissect_e212_imsi(imsi_tvb, actx->pinfo, subtree, 0, tvb_reported_length(imsi_tvb), false);
  }


  return offset;
}



static int
dissect_lcsap_IMEI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

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
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string lcsap_International_Area_Indication_vals[] = {
  {   0, "yes" },
  { 0, NULL }
};


static int
dissect_lcsap_International_Area_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static const value_string lcsap_Location_Type_vals[] = {
  {   0, "geographic-Information" },
  {   1, "assistance-Information" },
  {   2, "last-known-location" },
  { 0, NULL }
};


static int
dissect_lcsap_Location_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 1, NULL);

  return offset;
}


static const value_string lcsap_Radio_Network_Layer_Cause_vals[] = {
  {   0, "unspecified" },
  { 0, NULL }
};


static int
dissect_lcsap_Radio_Network_Layer_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

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
                                     2, NULL, true, 0, NULL);

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
                                     7, NULL, true, 0, NULL);

  return offset;
}


static const value_string lcsap_Misc_Cause_vals[] = {
  {   0, "processing-Overload" },
  {   1, "hardware-Failure" },
  {   2, "o-And-M-Intervention" },
  {   3, "unspecified" },
  {   4, "ciphering-key-data-lost" },
  { 0, NULL }
};


static int
dissect_lcsap_Misc_Cause(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 1, NULL);

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
                                     8, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_lcsap_LCS_Priority(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, NULL);

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
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_lcsap_Vertical_Accuracy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t vertical_uncertainty;
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, &vertical_uncertainty, false);



  proto_item_append_text(actx->created_item, " (%.1f m)", 45 * (pow(1.025, (double)vertical_uncertainty) - 1));

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
                                     2, NULL, true, 0, NULL);

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



static int
dissect_lcsap_LCS_Service_Type_ID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t MultipleAPDUs_sequence_of[1] = {
  { &hf_lcsap_MultipleAPDUs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_APDU },
};

static int
dissect_lcsap_MultipleAPDUs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_MultipleAPDUs, MultipleAPDUs_sequence_of,
                                                  1, 3, false);

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
                                     2, &PayloadType, true, 0, NULL);

  return offset;
}



static int
dissect_lcsap_Positioning_Method_And_Usage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb=NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, false, &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  proto_tree_add_item(tree, hf_lcsap_pos_method, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_lcsap_pos_usage, parameter_tvb, 0, 1, ENC_BIG_ENDIAN);



  return offset;
}


static const per_sequence_t Positioning_Data_Set_sequence_of[1] = {
  { &hf_lcsap_Positioning_Data_Set_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Positioning_Method_And_Usage },
};

static int
dissect_lcsap_Positioning_Data_Set(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_lcsap_Positioning_Data_Set, Positioning_Data_Set_sequence_of,
                                                  1, max_Set, false);

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


static const value_string lcsap_RAT_Type_vals[] = {
  {   0, "lte-wb" },
  {   1, "nb-iot" },
  {   2, "lte-m" },
  { 0, NULL }
};


static int
dissect_lcsap_RAT_Type(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 1, NULL);

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
                                     2, NULL, false, 0, NULL);

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
                                     5, NULL, true, 0, NULL);

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


static const value_string lcsap_UE_Country_Determination_Indication_vals[] = {
  {   0, "required" },
  {   1, "not-required" },
  { 0, NULL }
};


static int
dissect_lcsap_UE_Country_Determination_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t UE_Area_Indication_sequence[] = {
  { &hf_lcsap_country       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_Country },
  { &hf_lcsap_international_area_indication, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_lcsap_International_Area_Indication },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_UE_Area_Indication(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_UE_Area_Indication, UE_Area_Indication_sequence);

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

  PayloadType = 1;  /* LPPa */

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


static const per_sequence_t Ciphering_Key_Data_sequence[] = {
  { &hf_lcsap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_Container },
  { &hf_lcsap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Ciphering_Key_Data(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Ciphering_Key_Data, Ciphering_Key_Data_sequence);

  return offset;
}


static const per_sequence_t Ciphering_Key_Data_Result_sequence[] = {
  { &hf_lcsap_protocolIEs   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lcsap_ProtocolIE_Container },
  { &hf_lcsap_protocolExtensions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_lcsap_ProtocolExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_lcsap_Ciphering_Key_Data_Result(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_lcsap_Ciphering_Key_Data_Result, Ciphering_Key_Data_Result_sequence);

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

static int dissect_APDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_APDU(tvb, offset, &asn1_ctx, tree, hf_lcsap_APDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Accuracy_Fulfillment_Indicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Accuracy_Fulfillment_Indicator(tvb, offset, &asn1_ctx, tree, hf_lcsap_Accuracy_Fulfillment_Indicator_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Additional_PositioningDataSet_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Additional_PositioningDataSet(tvb, offset, &asn1_ctx, tree, hf_lcsap_Additional_PositioningDataSet_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Barometric_Pressure_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Barometric_Pressure(tvb, offset, &asn1_ctx, tree, hf_lcsap_Barometric_Pressure_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Cell_Portion_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Cell_Portion_ID(tvb, offset, &asn1_ctx, tree, hf_lcsap_Cell_Portion_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ciphering_Data_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Ciphering_Data(tvb, offset, &asn1_ctx, tree, hf_lcsap_Ciphering_Data_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ciphering_Data_Ack_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Ciphering_Data_Ack(tvb, offset, &asn1_ctx, tree, hf_lcsap_Ciphering_Data_Ack_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ciphering_Data_Error_Report_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Ciphering_Data_Error_Report(tvb, offset, &asn1_ctx, tree, hf_lcsap_Ciphering_Data_Error_Report_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Civic_Address_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Civic_Address(tvb, offset, &asn1_ctx, tree, hf_lcsap_Civic_Address_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_lcsap_Correlation_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Correlation_ID(tvb, offset, &asn1_ctx, tree, hf_lcsap_lcsap_Correlation_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_E_CGI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_E_CGI(tvb, offset, &asn1_ctx, tree, hf_lcsap_E_CGI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Coverage_Level_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Coverage_Level(tvb, offset, &asn1_ctx, tree, hf_lcsap_Coverage_Level_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Geographical_Area_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Geographical_Area(tvb, offset, &asn1_ctx, tree, hf_lcsap_Geographical_Area_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IMSI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_IMSI(tvb, offset, &asn1_ctx, tree, hf_lcsap_IMSI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_IMEI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_IMEI(tvb, offset, &asn1_ctx, tree, hf_lcsap_IMEI_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Include_Velocity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Include_Velocity(tvb, offset, &asn1_ctx, tree, hf_lcsap_Include_Velocity_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Location_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Location_Type(tvb, offset, &asn1_ctx, tree, hf_lcsap_Location_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_LCS_Cause(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_Client_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_LCS_Client_Type(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_Client_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_Priority_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_LCS_Priority(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_Priority_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_QoS_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_LCS_QoS(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_QoS_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_Service_Type_ID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_LCS_Service_Type_ID(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_Service_Type_ID_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_MultipleAPDUs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_MultipleAPDUs(tvb, offset, &asn1_ctx, tree, hf_lcsap_MultipleAPDUs_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Network_Element_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Network_Element(tvb, offset, &asn1_ctx, tree, hf_lcsap_Network_Element_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Payload_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Payload_Type(tvb, offset, &asn1_ctx, tree, hf_lcsap_Payload_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
int dissect_lcsap_Positioning_Data_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Positioning_Data(tvb, offset, &asn1_ctx, tree, hf_lcsap_lcsap_Positioning_Data_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_RAT_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_RAT_Type(tvb, offset, &asn1_ctx, tree, hf_lcsap_RAT_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Return_Error_Type_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Return_Error_Type(tvb, offset, &asn1_ctx, tree, hf_lcsap_Return_Error_Type_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Return_Error_Cause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Return_Error_Cause(tvb, offset, &asn1_ctx, tree, hf_lcsap_Return_Error_Cause_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Positioning_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_UE_Positioning_Capability(tvb, offset, &asn1_ctx, tree, hf_lcsap_UE_Positioning_Capability_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Country_Determination_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_UE_Country_Determination_Indication(tvb, offset, &asn1_ctx, tree, hf_lcsap_UE_Country_Determination_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_UE_Area_Indication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_UE_Area_Indication(tvb, offset, &asn1_ctx, tree, hf_lcsap_UE_Area_Indication_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Velocity_Estimate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Velocity_Estimate(tvb, offset, &asn1_ctx, tree, hf_lcsap_Velocity_Estimate_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Location_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Location_Request(tvb, offset, &asn1_ctx, tree, hf_lcsap_Location_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Location_Response_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Location_Response(tvb, offset, &asn1_ctx, tree, hf_lcsap_Location_Response_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Location_Abort_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Location_Abort_Request(tvb, offset, &asn1_ctx, tree, hf_lcsap_Location_Abort_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Connection_Oriented_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Connection_Oriented_Information(tvb, offset, &asn1_ctx, tree, hf_lcsap_Connection_Oriented_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Connectionless_Information_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Connectionless_Information(tvb, offset, &asn1_ctx, tree, hf_lcsap_Connectionless_Information_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_Request_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Reset_Request(tvb, offset, &asn1_ctx, tree, hf_lcsap_Reset_Request_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Reset_Acknowledge_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Reset_Acknowledge(tvb, offset, &asn1_ctx, tree, hf_lcsap_Reset_Acknowledge_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ciphering_Key_Data_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Ciphering_Key_Data(tvb, offset, &asn1_ctx, tree, hf_lcsap_Ciphering_Key_Data_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_Ciphering_Key_Data_Result_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_Ciphering_Key_Data_Result(tvb, offset, &asn1_ctx, tree, hf_lcsap_Ciphering_Key_Data_Result_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_LCS_AP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, true, pinfo);
  offset = dissect_lcsap_LCS_AP_PDU(tvb, offset, &asn1_ctx, tree, hf_lcsap_LCS_AP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


static int dissect_ProtocolIEFieldValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lcsap_ies_dissector_table, ProtocolIE_ID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}


static int dissect_ProtocolExtensionFieldExtensionValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lcsap_extension_dissector_table, ProtocolExtensionID, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_InitiatingMessageValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lcsap_proc_imsg_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_SuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lcsap_proc_sout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}

static int dissect_UnsuccessfulOutcomeValue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return (dissector_try_uint(lcsap_proc_uout_dissector_table, ProcedureCode, tvb, pinfo, tree)) ? tvb_captured_length(tvb) : 0;
}


static int
dissect_lcsap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item  *lcsap_item = NULL;
  proto_tree  *lcsap_tree = NULL;

  /* make entry in the Protocol column on summary display */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "LCSAP");

  /* create the lcsap protocol tree */
  lcsap_item = proto_tree_add_item(tree, proto_lcsap, tvb, 0, -1, ENC_NA);
  lcsap_tree = proto_item_add_subtree(lcsap_item, ett_lcsap);

  dissect_LCS_AP_PDU_PDU(tvb, pinfo, lcsap_tree, NULL);
  return tvb_captured_length(tvb);
}

/*--- proto_reg_handoff_lcsap ---------------------------------------*/
void
proto_reg_handoff_lcsap(void)
{
  lpp_handle = find_dissector_add_dependency("lpp", proto_lcsap);
  lppa_handle = find_dissector_add_dependency("lppa", proto_lcsap);
  xml_handle = find_dissector_add_dependency("xml", proto_lcsap);
  dissector_add_uint_with_preference("sctp.port", SCTP_PORT_LCSAP, lcsap_handle);
  dissector_add_uint("sctp.ppi", LCS_AP_PAYLOAD_PROTOCOL_ID,   lcsap_handle);
  dissector_add_uint("lcsap.ies", id_Accuracy_Fulfillment_Indicator, create_dissector_handle(dissect_Accuracy_Fulfillment_Indicator_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_APDU, create_dissector_handle(dissect_APDU_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Correlation_ID, create_dissector_handle(dissect_lcsap_Correlation_ID_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Destination_ID, create_dissector_handle(dissect_Network_Element_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_E_UTRAN_Cell_Identifier, create_dissector_handle(dissect_E_CGI_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Include_Velocity, create_dissector_handle(dissect_Include_Velocity_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_IMEI, create_dissector_handle(dissect_IMEI_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_IMSI, create_dissector_handle(dissect_IMSI_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_LCS_Client_Type, create_dissector_handle(dissect_LCS_Client_Type_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_LCS_Priority, create_dissector_handle(dissect_LCS_Priority_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_LCS_QOS, create_dissector_handle(dissect_LCS_QoS_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_LCS_Cause, create_dissector_handle(dissect_LCS_Cause_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Location_Estimate, create_dissector_handle(dissect_Geographical_Area_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Location_Type, create_dissector_handle(dissect_Location_Type_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_MultipleAPDUs, create_dissector_handle(dissect_MultipleAPDUs_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Payload_Type, create_dissector_handle(dissect_Payload_Type_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Positioning_Data, create_dissector_handle(dissect_lcsap_Positioning_Data_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Return_Error_Request, create_dissector_handle(dissect_Return_Error_Type_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Return_Error_Cause, create_dissector_handle(dissect_Return_Error_Cause_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Source_Identity, create_dissector_handle(dissect_Network_Element_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_UE_Positioning_Capability, create_dissector_handle(dissect_UE_Positioning_Capability_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Velocity_Estimate, create_dissector_handle(dissect_Velocity_Estimate_PDU, proto_lcsap));
  dissector_add_uint("lcsap.extension", id_Barometric_Pressure, create_dissector_handle(dissect_Barometric_Pressure_PDU, proto_lcsap));
  dissector_add_uint("lcsap.extension", id_Additional_PositioningDataSet, create_dissector_handle(dissect_Additional_PositioningDataSet_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_RAT_Type, create_dissector_handle(dissect_RAT_Type_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Ciphering_Data, create_dissector_handle(dissect_Ciphering_Data_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Ciphering_Data_Ack, create_dissector_handle(dissect_Ciphering_Data_Ack_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Ciphering_Data_Error_Report, create_dissector_handle(dissect_Ciphering_Data_Error_Report_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_Coverage_Level, create_dissector_handle(dissect_Coverage_Level_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_UE_Country_Determination_Indication, create_dissector_handle(dissect_UE_Country_Determination_Indication_PDU, proto_lcsap));
  dissector_add_uint("lcsap.ies", id_UE_Area_Indication, create_dissector_handle(dissect_UE_Area_Indication_PDU, proto_lcsap));
  dissector_add_uint("lcsap.extension", id_LCS_Service_Type_ID, create_dissector_handle(dissect_LCS_Service_Type_ID_PDU, proto_lcsap));
  dissector_add_uint("lcsap.extension", id_Cell_Portion_ID, create_dissector_handle(dissect_Cell_Portion_ID_PDU, proto_lcsap));
  dissector_add_uint("lcsap.extension", id_Civic_Address, create_dissector_handle(dissect_Civic_Address_PDU, proto_lcsap));
  dissector_add_uint("lcsap.extension", id_E_UTRAN_Cell_Identifier, create_dissector_handle(dissect_E_CGI_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Location_Service_Request, create_dissector_handle(dissect_Location_Request_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.sout", id_Location_Service_Request, create_dissector_handle(dissect_Location_Response_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.uout", id_Location_Service_Request, create_dissector_handle(dissect_Location_Response_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Connection_Oriented_Information_Transfer, create_dissector_handle(dissect_Connection_Oriented_Information_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Connectionless_Information_Transfer, create_dissector_handle(dissect_Connectionless_Information_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.uout", id_Connectionless_Information_Transfer, create_dissector_handle(dissect_Connectionless_Information_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Location_Abort, create_dissector_handle(dissect_Location_Abort_Request_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.sout", id_Location_Abort, create_dissector_handle(dissect_Location_Response_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Reset, create_dissector_handle(dissect_Reset_Request_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.sout", id_Reset, create_dissector_handle(dissect_Reset_Acknowledge_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.imsg", id_Ciphering_Key_Data_Delivery, create_dissector_handle(dissect_Ciphering_Key_Data_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.sout", id_Ciphering_Key_Data_Delivery, create_dissector_handle(dissect_Ciphering_Key_Data_Result_PDU, proto_lcsap));
  dissector_add_uint("lcsap.proc.uout", id_Ciphering_Key_Data_Delivery, create_dissector_handle(dissect_Ciphering_Key_Data_Result_PDU, proto_lcsap));


}

/*--- proto_register_lcsap -------------------------------------------*/
void proto_register_lcsap(void) {

  /* List of fields */
  static hf_register_info hf[] = {
      /* 7.4.13 Positioning Data */
      { &hf_lcsap_pos_method,
        { "Positioning Method", "lcsap.pos_method",
          FT_UINT8, BASE_DEC, VALS(lcsap_pos_method_vals), 0xf8,
          NULL, HFILL }
      },
      { &hf_lcsap_pos_usage,
        { "Positioning usage", "lcsap.pos_usage",
          FT_UINT8, BASE_DEC, VALS(lcsap_pos_usage_vals), 0x07,
          NULL, HFILL }
      },
      { &hf_lcsap_gnss_pos_method,
        { "GNSS Positioning Method", "lcsap.gnss_pos_method",
          FT_UINT8, BASE_DEC, VALS(lcsap_gnss_pos_method_vals), 0xc0,
          NULL, HFILL }
      },
      { &hf_lcsap_gnss_id,
        { "GNSS ID", "lcsap.gnss_id",
          FT_UINT8, BASE_DEC, VALS(lcsap_gnss_id_vals), 0x38,
          NULL, HFILL }
      },
      { &hf_lcsap_gnss_pos_usage,
        { "GNSS Positioning usage", "lcsap.gnss_pos_usage",
          FT_UINT8, BASE_DEC, VALS(lcsap_gnss_pos_usage_vals), 0x07,
          NULL, HFILL }
      },

    { &hf_lcsap_APDU_PDU,
      { "APDU", "lcsap.APDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Accuracy_Fulfillment_Indicator_PDU,
      { "Accuracy-Fulfillment-Indicator", "lcsap.Accuracy_Fulfillment_Indicator",
        FT_UINT32, BASE_DEC, VALS(lcsap_Accuracy_Fulfillment_Indicator_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_Additional_PositioningDataSet_PDU,
      { "Additional-PositioningDataSet", "lcsap.Additional_PositioningDataSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Barometric_Pressure_PDU,
      { "Barometric-Pressure", "lcsap.Barometric_Pressure",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Cell_Portion_ID_PDU,
      { "Cell-Portion-ID", "lcsap.Cell_Portion_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Ciphering_Data_PDU,
      { "Ciphering-Data", "lcsap.Ciphering_Data",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Ciphering_Data_Ack_PDU,
      { "Ciphering-Data-Ack", "lcsap.Ciphering_Data_Ack",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Ciphering_Data_Error_Report_PDU,
      { "Ciphering-Data-Error-Report", "lcsap.Ciphering_Data_Error_Report",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Civic_Address_PDU,
      { "Civic-Address", "lcsap.Civic_Address",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_lcsap_Correlation_ID_PDU,
      { "Correlation-ID", "lcsap.Correlation_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_E_CGI_PDU,
      { "E-CGI", "lcsap.E_CGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Coverage_Level_PDU,
      { "Coverage-Level", "lcsap.Coverage_Level",
        FT_UINT32, BASE_DEC, VALS(lcsap_Coverage_Level_vals), 0,
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
      { "LCS-QoS", "lcsap.LCS_QoS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_LCS_Service_Type_ID_PDU,
      { "LCS-Service-Type-ID", "lcsap.LCS_Service_Type_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
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
    { &hf_lcsap_lcsap_Positioning_Data_PDU,
      { "Positioning-Data", "lcsap.Positioning_Data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_RAT_Type_PDU,
      { "RAT-Type", "lcsap.RAT_Type",
        FT_UINT32, BASE_DEC, VALS(lcsap_RAT_Type_vals), 0,
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
      { "UE-Positioning-Capability", "lcsap.UE_Positioning_Capability_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_UE_Country_Determination_Indication_PDU,
      { "UE-Country-Determination-Indication", "lcsap.UE_Country_Determination_Indication",
        FT_UINT32, BASE_DEC, VALS(lcsap_UE_Country_Determination_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_UE_Area_Indication_PDU,
      { "UE-Area-Indication", "lcsap.UE_Area_Indication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Velocity_Estimate_PDU,
      { "Velocity-Estimate", "lcsap.Velocity_Estimate",
        FT_UINT32, BASE_DEC, VALS(lcsap_Velocity_Estimate_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_Location_Request_PDU,
      { "Location-Request", "lcsap.Location_Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Location_Response_PDU,
      { "Location-Response", "lcsap.Location_Response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Location_Abort_Request_PDU,
      { "Location-Abort-Request", "lcsap.Location_Abort_Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Connection_Oriented_Information_PDU,
      { "Connection-Oriented-Information", "lcsap.Connection_Oriented_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Connectionless_Information_PDU,
      { "Connectionless-Information", "lcsap.Connectionless_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Reset_Request_PDU,
      { "Reset-Request", "lcsap.Reset_Request_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Reset_Acknowledge_PDU,
      { "Reset-Acknowledge", "lcsap.Reset_Acknowledge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Ciphering_Key_Data_PDU,
      { "Ciphering-Key-Data", "lcsap.Ciphering_Key_Data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Ciphering_Key_Data_Result_PDU,
      { "Ciphering-Key-Data-Result", "lcsap.Ciphering_Key_Data_Result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_LCS_AP_PDU_PDU,
      { "LCS-AP-PDU", "lcsap.LCS_AP_PDU",
        FT_UINT32, BASE_DEC, VALS(lcsap_LCS_AP_PDU_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_ProtocolIE_Container_item,
      { "ProtocolIE-Field", "lcsap.ProtocolIE_Field_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_id,
      { "id", "lcsap.id",
        FT_UINT32, BASE_DEC, VALS(lcsap_ProtocolIE_ID_vals), 0,
        "ProtocolIE_ID", HFILL }},
    { &hf_lcsap_criticality,
      { "criticality", "lcsap.criticality",
        FT_UINT32, BASE_DEC, VALS(lcsap_Criticality_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_ie_field_value,
      { "value", "lcsap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_ie_field_value", HFILL }},
    { &hf_lcsap_ProtocolExtensionContainer_item,
      { "ProtocolExtensionField", "lcsap.ProtocolExtensionField_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ext_id,
      { "id", "lcsap.id",
        FT_UINT8, BASE_DEC, VALS(lcsap_ProtocolIE_ID_vals), 0,
        "ProtocolExtensionID", HFILL }},
    { &hf_lcsap_extensionValue,
      { "extensionValue", "lcsap.extensionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Additional_PositioningDataSet_item,
      { "Additional-PositioningMethodAndUsage", "lcsap.Additional_PositioningMethodAndUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_direction_Of_Altitude,
      { "direction-Of-Altitude", "lcsap.direction_Of_Altitude",
        FT_UINT32, BASE_DEC, VALS(lcsap_Direction_Of_Altitude_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_altitude,
      { "altitude", "lcsap.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Ciphering_Data_item,
      { "Ciphering-Data-Set", "lcsap.Ciphering_Data_Set_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Ciphering_Data_Ack_item,
      { "Ciphering-Set-ID", "lcsap.Ciphering_Set_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_Ciphering_Data_Error_Report_item,
      { "Ciphering-Data-Error-Report-Contents", "lcsap.Ciphering_Data_Error_Report_Contents_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ciphering_Set_ID,
      { "ciphering-Set-ID", "lcsap.ciphering_Set_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ciphering_Key,
      { "ciphering-Key", "lcsap.ciphering_Key",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_c0,
      { "c0", "lcsap.c0",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_sib_Types,
      { "sib-Types", "lcsap.sib_Types",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_validity_Start_Time,
      { "validity-Start-Time", "lcsap.validity_Start_Time",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_validity_Duration,
      { "validity-Duration", "lcsap.validity_Duration",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_tais_List,
      { "tais-List", "lcsap.tais_List",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_storage_Outcome,
      { "storage-Outcome", "lcsap.storage_Outcome",
        FT_UINT32, BASE_DEC, VALS(lcsap_Storage_Outcome_vals), 0,
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
      { "geographical-Coordinates", "lcsap.geographical_Coordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_uncertainty_Ellipse,
      { "uncertainty-Ellipse", "lcsap.uncertainty_Ellipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_confidence,
      { "confidence", "lcsap.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_altitude_And_Direction,
      { "altitude-And-Direction", "lcsap.altitude_And_Direction_element",
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
    { &hf_lcsap_short_macro_eNB_ID,
      { "short-macro-eNB-ID", "lcsap.short_macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_long_macro_eNB_ID,
      { "long-macro-eNB-ID", "lcsap.long_macro_eNB_ID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_point,
      { "point", "lcsap.point_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_point_With_Uncertainty,
      { "point-With-Uncertainty", "lcsap.point_With_Uncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ellipsoidPoint_With_Uncertainty_Ellipse,
      { "ellipsoidPoint-With-Uncertainty-Ellipse", "lcsap.ellipsoidPoint_With_Uncertainty_Ellipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ellipsoid_Point_With_Uncertainty_Ellipse", HFILL }},
    { &hf_lcsap_polygon,
      { "polygon", "lcsap.polygon",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ellipsoid_Point_With_Altitude,
      { "ellipsoid-Point-With-Altitude", "lcsap.ellipsoid_Point_With_Altitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid,
      { "ellipsoid-Point-With-Altitude-And-Uncertainty-Ellipsoid", "lcsap.ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_ellipsoid_Arc,
      { "ellipsoid-Arc", "lcsap.ellipsoid_Arc_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse,
      { "high-Accuracy-Ellipsoid-Point-With-Uncertainty-Ellipse", "lcsap.high_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid,
      { "high-Accuracy-Ellipsoid-Point-With-Altitude-And-Uncertainty-Ellipsoid", "lcsap.high_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse,
      { "high-Accuracy-Ellipsoid-Point-With-Scalable-Uncertainty-Ellipse", "lcsap.high_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid,
      { "high-Accuracy-Ellipsoid-Point-With-Altitude-And-Scalable-Uncertainty-Ellipsoid", "lcsap.high_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid_element",
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
    { &hf_lcsap_high_Accuracy_Geographical_Coordinates,
      { "high-Accuracy-Geographical-Coordinates", "lcsap.high_Accuracy_Geographical_Coordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_Uncertainty_Ellipse,
      { "high-Accuracy-Uncertainty-Ellipse", "lcsap.high_Accuracy_Uncertainty_Ellipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_Scalable_Uncertainty_Ellipse,
      { "high-Accuracy-Scalable-Uncertainty-Ellipse", "lcsap.high_Accuracy_Scalable_Uncertainty_Ellipse",
        FT_UINT32, BASE_DEC, VALS(lcsap_High_Accuracy_Scalable_Uncertainty_Ellipse_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_Altitude,
      { "high-Accuracy-Altitude", "lcsap.high_Accuracy_Altitude",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_Uncertainty_Altitude,
      { "high-Accuracy-Uncertainty-Altitude", "lcsap.high_Accuracy_Uncertainty_Altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "High_Accuracy_Uncertainty_Code", HFILL }},
    { &hf_lcsap_vertical_Confidence,
      { "vertical-Confidence", "lcsap.vertical_Confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Confidence", HFILL }},
    { &hf_lcsap_high_Accuracy_Scalable_Uncertainty_Altitude,
      { "high-Accuracy-Scalable-Uncertainty-Altitude", "lcsap.high_Accuracy_Scalable_Uncertainty_Altitude",
        FT_UINT32, BASE_DEC, VALS(lcsap_High_Accuracy_Scalable_Uncertainty_Altitude_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_DegreesLatitude,
      { "high-Accuracy-DegreesLatitude", "lcsap.high_Accuracy_DegreesLatitude",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_DegreesLongitude,
      { "high-Accuracy-DegreesLongitude", "lcsap.high_Accuracy_DegreesLongitude",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_Uncertainty_SemiMajor,
      { "high-Accuracy-Uncertainty-SemiMajor", "lcsap.high_Accuracy_Uncertainty_SemiMajor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "High_Accuracy_Uncertainty_Code", HFILL }},
    { &hf_lcsap_high_Accuracy_Uncertainty_SemiMinor,
      { "high-Accuracy-Uncertainty-SemiMinor", "lcsap.high_Accuracy_Uncertainty_SemiMinor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "High_Accuracy_Uncertainty_Code", HFILL }},
    { &hf_lcsap_orientation_Major_Axis,
      { "orientation-Major-Axis", "lcsap.orientation_Major_Axis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_lcsap_high_Accuracy_Extended_Uncertainty_SemiMajor,
      { "high-Accuracy-Extended-Uncertainty-SemiMajor", "lcsap.high_Accuracy_Extended_Uncertainty_SemiMajor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "High_Accuracy_Extended_Uncertainty_Code", HFILL }},
    { &hf_lcsap_high_Accuracy_Extended_Uncertainty_SemiMinor,
      { "high-Accuracy-Extended-Uncertainty-SemiMinor", "lcsap.high_Accuracy_Extended_Uncertainty_SemiMinor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "High_Accuracy_Extended_Uncertainty_Code", HFILL }},
    { &hf_lcsap_high_Accuracy_Extended_Uncertainty_Ellipse,
      { "high-Accuracy-Extended-Uncertainty-Ellipse", "lcsap.high_Accuracy_Extended_Uncertainty_Ellipse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_high_Accuracy_Extended_Uncertainty_Altitude,
      { "high-Accuracy-Extended-Uncertainty-Altitude", "lcsap.high_Accuracy_Extended_Uncertainty_Altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "High_Accuracy_Extended_Uncertainty_Code", HFILL }},
    { &hf_lcsap_bearing,
      { "bearing", "lcsap.bearing",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_lcsap_horizontal_Speed,
      { "horizontal-Speed", "lcsap.horizontal_Speed",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2047", HFILL }},
    { &hf_lcsap_horizontal_Speed_And_Bearing,
      { "horizontal-Speed-And-Bearing", "lcsap.horizontal_Speed_And_Bearing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_vertical_Velocity,
      { "vertical-Velocity", "lcsap.vertical_Velocity_element",
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
      { "global-eNB-ID", "lcsap.global_eNB_ID_element",
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
      { "Polygon-Point", "lcsap.Polygon_Point_element",
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
    { &hf_lcsap_orientation_Major_Axis_01,
      { "orientation-Major-Axis", "lcsap.orientation_Major_Axis",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_lPP,
      { "lPP", "lcsap.lPP",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_lcsap_country,
      { "country", "lcsap.country",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_international_area_indication,
      { "international-area-indication", "lcsap.international_area_indication",
        FT_UINT32, BASE_DEC, VALS(lcsap_International_Area_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_horizontal_Velocity,
      { "horizontal-Velocity", "lcsap.horizontal_Velocity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_horizontal_With_Vertical_Velocity,
      { "horizontal-With-Vertical-Velocity", "lcsap.horizontal_With_Vertical_Velocity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_horizontal_Velocity_With_Uncertainty,
      { "horizontal-Velocity-With-Uncertainty", "lcsap.horizontal_Velocity_With_Uncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_horizontal_With_Vertical_Velocity_And_Uncertainty,
      { "horizontal-With-Vertical-Velocity-And-Uncertainty", "lcsap.horizontal_With_Vertical_Velocity_And_Uncertainty_element",
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
      { "initiatingMessage", "lcsap.initiatingMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_successfulOutcome,
      { "successfulOutcome", "lcsap.successfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_unsuccessfulOutcome,
      { "unsuccessfulOutcome", "lcsap.unsuccessfulOutcome_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_lcsap_procedureCode,
      { "procedureCode", "lcsap.procedureCode",
        FT_UINT32, BASE_DEC, VALS(lcsap_ProcedureCode_vals), 0,
        NULL, HFILL }},
    { &hf_lcsap_initiatingMessagevalue,
      { "value", "lcsap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiatingMessage_value", HFILL }},
    { &hf_lcsap_successfulOutcome_value,
      { "value", "lcsap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuccessfulOutcome_value", HFILL }},
    { &hf_lcsap_unsuccessfulOutcome_value,
      { "value", "lcsap.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsuccessfulOutcome_value", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_lcsap,
    &ett_lcsap_plmnd_id,
    &ett_lcsap_imsi,
    &ett_lcsap_civic_address,
    &ett_lcsap_ProtocolIE_Container,
    &ett_lcsap_ProtocolIE_Field,
    &ett_lcsap_ProtocolExtensionContainer,
    &ett_lcsap_ProtocolExtensionField,
    &ett_lcsap_Additional_PositioningDataSet,
    &ett_lcsap_Altitude_And_Direction,
    &ett_lcsap_Ciphering_Data,
    &ett_lcsap_Ciphering_Data_Ack,
    &ett_lcsap_Ciphering_Data_Error_Report,
    &ett_lcsap_Ciphering_Data_Set,
    &ett_lcsap_Ciphering_Data_Error_Report_Contents,
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
    &ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Uncertainty_Ellipse,
    &ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Scalable_Uncertainty_Ellipse,
    &ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Altitude_And_Uncertainty_Ellipsoid,
    &ett_lcsap_High_Accuracy_Ellipsoid_Point_With_Altitude_And_Scalable_Uncertainty_Ellipsoid,
    &ett_lcsap_High_Accuracy_Geographical_Coordinates,
    &ett_lcsap_High_Accuracy_Uncertainty_Ellipse,
    &ett_lcsap_High_Accuracy_Extended_Uncertainty_Ellipse,
    &ett_lcsap_High_Accuracy_Scalable_Uncertainty_Ellipse,
    &ett_lcsap_High_Accuracy_Scalable_Uncertainty_Altitude,
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
    &ett_lcsap_UE_Area_Indication,
    &ett_lcsap_Velocity_Estimate,
    &ett_lcsap_Vertical_Velocity,
    &ett_lcsap_Location_Request,
    &ett_lcsap_Location_Response,
    &ett_lcsap_Location_Abort_Request,
    &ett_lcsap_Connection_Oriented_Information,
    &ett_lcsap_Connectionless_Information,
    &ett_lcsap_Reset_Request,
    &ett_lcsap_Reset_Acknowledge,
    &ett_lcsap_Ciphering_Key_Data,
    &ett_lcsap_Ciphering_Key_Data_Result,
    &ett_lcsap_LCS_AP_PDU,
    &ett_lcsap_InitiatingMessage,
    &ett_lcsap_SuccessfulOutcome,
    &ett_lcsap_UnsuccessfulOutcome,
 };

  /* module_t *lcsap_module; */
  expert_module_t *expert_lcsap;

  static ei_register_info ei[] = {
      { &ei_lcsap_civic_data_not_xml,
      { "lcsap.civic_data_not_xml", PI_PROTOCOL, PI_ERROR, "Should contain a UTF-8 encoded PIDF - LO XML document as defined in IETF RFC 4119", EXPFILL } },
  };


  /* Register protocol */
  proto_lcsap = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lcsap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  lcsap_handle = register_dissector("lcsap", dissect_lcsap, proto_lcsap);

  /* Register dissector tables */
  lcsap_ies_dissector_table = register_dissector_table("lcsap.ies", "LCS-AP-PROTOCOL-IES", proto_lcsap, FT_UINT32, BASE_DEC);

  expert_lcsap = expert_register_protocol(proto_lcsap);
  expert_register_field_array(expert_lcsap, ei, array_length(ei));

  lcsap_extension_dissector_table = register_dissector_table("lcsap.extension", "LCS-AP-PROTOCOL-EXTENSION", proto_lcsap, FT_UINT32, BASE_DEC);
  lcsap_proc_imsg_dissector_table = register_dissector_table("lcsap.proc.imsg", "LCS-AP-ELEMENTARY-PROCEDURE InitiatingMessage", proto_lcsap, FT_UINT32, BASE_DEC);
  lcsap_proc_sout_dissector_table = register_dissector_table("lcsap.proc.sout", "LCS-AP-ELEMENTARY-PROCEDURE SuccessfulOutcome", proto_lcsap, FT_UINT32, BASE_DEC);
  lcsap_proc_uout_dissector_table = register_dissector_table("lcsap.proc.uout", "LCS-AP-ELEMENTARY-PROCEDURE UnsuccessfulOutcome", proto_lcsap, FT_UINT32, BASE_DEC);

  /* lcsap_module = prefs_register_protocol(proto_lcsap, NULL); */

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
