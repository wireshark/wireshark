/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ansi_tcap.c                                                         */
/* asn2wrs.py -b -q -L -p ansi_tcap -c ./ansi_tcap.cnf -s ./packet-ansi_tcap-template -D . -O ../.. TCAP-Remote-Operations-Information-Objects.asn TCAPPackage.asn */

/* packet-ansi_tcap-template.c
 * Routines for ANSI TCAP
 * Copyright 2007 Anders Broman <anders.broman@ericsson.com>
 * Built from the gsm-map dissector Copyright 2004 - 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References: T1.114
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/strutil.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-tcap.h"
#include "packet-ansi_tcap.h"

#define PNAME  "ANSI Transaction Capabilities Application Part"
#define PSNAME "ANSI_TCAP"
#define PFNAME "ansi_tcap"

void proto_register_ansi_tcap(void);
void proto_reg_handoff_ansi_tcap(void);

/* Preference settings */
#define ANSI_TCAP_TID_ONLY            0
#define ANSI_TCAP_TID_AND_SOURCE      1
#define ANSI_TCAP_TID_SOURCE_AND_DEST 2
static int ansi_tcap_response_matching_type = ANSI_TCAP_TID_ONLY;

/* Initialize the protocol and registered fields */
static int proto_ansi_tcap;

#if 0
static int hf_ansi_tcapsrt_SessionId;
static int hf_ansi_tcapsrt_Duplicate;
static int hf_ansi_tcapsrt_BeginSession;
static int hf_ansi_tcapsrt_EndSession;
static int hf_ansi_tcapsrt_SessionTime;
#endif
static int hf_ansi_tcap_bit_h;
static int hf_ansi_tcap_op_family;
static int hf_ansi_tcap_op_specifier;
static int hf_ansi_tcap_parameter;
static int hf_ansi_tcap_parameter_length;
static int hf_ansi_tcap_parameter_timestamp_year;
static int hf_ansi_tcap_parameter_timestamp_month;
static int hf_ansi_tcap_parameter_timestamp_day;
static int hf_ansi_tcap_parameter_timestamp_hour;
static int hf_ansi_tcap_parameter_timestamp_minute;
static int hf_ansi_tcap_parameter_timestamp_difference;
static int hf_ansi_tcap_parameter_timestamp_local_hour;
static int hf_ansi_tcap_parameter_timestamp_local_minute;
static int hf_ansi_tcap_parameter_acg_control_cause_indicator;
static int hf_ansi_tcap_parameter_acg_duration_field;
static int hf_ansi_tcap_parameter_acg_gap;
static int hf_ansi_tcap_parameter_standard_announcement;
static int hf_ansi_tcap_parameter_customized_announcement;
static int hf_ansi_tcap_parameter_set;
static int hf_ansi_tcap_parameter_digits_type_of_digits;
static int hf_ansi_tcap_parameter_digits_nature_of_numbers;
static int hf_ansi_tcap_parameter_digits_number_planning;
static int hf_ansi_tcap_parameter_digits_encoding;
static int hf_ansi_tcap_parameter_digits_number_of_digits;
static int hf_ansi_tcap_parameter_digits;
static int hf_ansi_tcap_standard_user_error_code;
static int hf_ansi_tcap_sccp_calling_party_address;
static int hf_ansi_tcap_transaction_id;
static int hf_ansi_tcap_package_type;
static int hf_ansi_tcap_returned_data;
static int hf_ansi_tcap_service_key_identifier;
static int hf_ansi_tcap_digit_identifier;
static int hf_ansi_tcap_digit_length;
static int hf_ansi_tcap_destination_number_value;
static int hf_ansi_tcap_presentation_restriction;
static int hf_ansi_tcap_encoding_scheme;
static int hf_ansi_tcap_number_of_digits;
static int hf_ansi_tcap_destination_phone_number;
static int hf_ansi_tcap_return_phone_number;
static int hf_ansi_tcap_busy_idle_status;
static int hf_ansi_tcap_originating_restrictions;
static int hf_ansi_tcap_terminating_restrictions;
static int hf_ansi_tcap_parameter_set_start;
static int hf_ansi_tcap_parameter_call_forwarding_on_busy;
static int hf_ansi_tcap_parameter_call_forwarding_dont_answer;
static int hf_ansi_tcap_parameter_selective_forwarding;
static int hf_ansi_tcap_parameter_dn_match;
static int hf_ansi_tcap_parameter_dn_line_service;
static int hf_ansi_tcap_duration_hour;
static int hf_ansi_tcap_duration_minute;
static int hf_ansi_tcap_duration_second;
static int hf_ansi_tcap_parameter_bearer_capability_requested1;
static int hf_ansi_tcap_parameter_bearer_capability_requested2;
static int hf_ansi_tcap_parameter_bearer_capability_requested2a;
static int hf_ansi_tcap_parameter_bearer_capability_requested2b;
static int hf_ansi_tcap_parameter_bearer_capability_requested3;
static int hf_ansi_tcap_parameter_bearer_capability_requested3a;
static int hf_ansi_tcap_bearer_capability_supported;
static int hf_ansi_tcap_reference_id;
static int hf_ansi_tcap_parameter_business_group_length_spare;
static int hf_ansi_tcap_parameter_business_group_length_AttSt;
static int hf_ansi_tcap_parameter_business_group_length_BGID;
static int hf_ansi_tcap_parameter_business_group_length_LP11;
static int hf_ansi_tcap_parameter_business_group_length_Party_Selector;
static int hf_ansi_tcap_parameter_business_group_id;
static int hf_ansi_tcap_parameter_business_group_subgroup_id;
static int hf_ansi_tcap_parameter_business_group_line_privileges;
static int hf_ansi_tcap_parameter_signalling_networks_id;
static int hf_ansi_tcap_parameter_generic_name_type_name;
static int hf_ansi_tcap_parameter_generic_name_availability;
static int hf_ansi_tcap_parameter_generic_name_spare;
static int hf_ansi_tcap_parameter_generic_name_presentation;
static int hf_ansi_tcap_parameter_generic_name_characters;
static int hf_ansi_tcap_message_waiting_indicator_type;
static int hf_ansi_tcap_parameter_look_ahead_for_busy_ack_type;
static int hf_ansi_tcap_parameter_look_ahead_for_busy_spare;
static int hf_ansi_tcap_parameter_look_ahead_for_busy_location_field;
static int hf_ansi_tcap_parameter_CIC_lsb;
static int hf_ansi_tcap_parameter_CIC_spare;
static int hf_ansi_tcap_parameter_CIC_msb;
static int hf_ansi_tcap_parameter_precedence_level_spare;
static int hf_ansi_tcap_parameter_precedence_level;
static int hf_ansi_tcap_parameter_precedence_id1;
static int hf_ansi_tcap_parameter_precedence_id2;
static int hf_ansi_tcap_parameter_precedence_id3;
static int hf_ansi_tcap_parameter_precedence_id4;
static int hf_ansi_tcap_parameter_precedence_mlpp_service_domain;
static int hf_ansi_tcap_reference_id_call_identify;
static int hf_ansi_tcap_reference_id_point_code;
static int hf_ansi_tcap_parameter_authorization;
static int hf_ansi_tcap_integrity_algid_id;
static int hf_ansi_tcap_integrity_algid;
static int hf_ansi_tcap_integrity_value_id;
static int hf_ansi_tcap_integrity_value;
static int hf_ansi_tcap_sequence_number;
static int hf_ansi_tcap_num_messages;
static int hf_ansi_tcap_display_text;
static int hf_ansi_tcap_key_exchange_algid_id;
static int hf_ansi_tcap_key_exchange_algid;
static int hf_ansi_tcap_key_exchange_value_id;
static int hf_ansi_tcap_key_exchange_value;


static int hf_ansi_tcap_national;                 /* T_national */
static int hf_ansi_tcap_private;                  /* T_private */
static int hf_ansi_tcap_national_01;              /* INTEGER_M128_127 */
static int hf_ansi_tcap_ec_private;               /* ANSIMAPPrivateErrorcode */
static int hf_ansi_tcap_unidirectional;           /* T_unidirectional */
static int hf_ansi_tcap_queryWithPerm;            /* T_queryWithPerm */
static int hf_ansi_tcap_queryWithoutPerm;         /* T_queryWithoutPerm */
static int hf_ansi_tcap_response;                 /* T_response */
static int hf_ansi_tcap_conversationWithPerm;     /* T_conversationWithPerm */
static int hf_ansi_tcap_conversationWithoutPerm;  /* T_conversationWithoutPerm */
static int hf_ansi_tcap_abort;                    /* T_abort */
static int hf_ansi_tcap_identifier;               /* TransactionID */
static int hf_ansi_tcap_dialoguePortion;          /* DialoguePortion */
static int hf_ansi_tcap_componentPortion;         /* ComponentSequence */
static int hf_ansi_tcap_dialogPortion;            /* DialoguePortion */
static int hf_ansi_tcap_causeInformation;         /* T_causeInformation */
static int hf_ansi_tcap_abortCause;               /* P_Abort_cause */
static int hf_ansi_tcap_abort_userInformation;    /* UserAbortInformation */
static int hf_ansi_tcap_version;                  /* ProtocolVersion */
static int hf_ansi_tcap_applicationContext;       /* T_applicationContext */
static int hf_ansi_tcap_integerApplicationId;     /* IntegerApplicationContext */
static int hf_ansi_tcap_objectApplicationId;      /* ObjectIDApplicationContext */
static int hf_ansi_tcap_userInformation;          /* UserInformation */
static int hf_ansi_tcap_securityContext;          /* T_securityContext */
static int hf_ansi_tcap_integerSecurityId;        /* INTEGER */
static int hf_ansi_tcap_objectSecurityId;         /* OBJECT_IDENTIFIER */
static int hf_ansi_tcap_confidentiality;          /* Confidentiality */
static int hf_ansi_tcap__untag_item;              /* EXTERNAL */
static int hf_ansi_tcap_confidentialityId;        /* T_confidentialityId */
static int hf_ansi_tcap_integerConfidentialityId;  /* INTEGER */
static int hf_ansi_tcap_objectConfidentialityId;  /* OBJECT_IDENTIFIER */
static int hf_ansi_tcap__untag_item_01;           /* ComponentPDU */
static int hf_ansi_tcap_invokeLast;               /* Invoke */
static int hf_ansi_tcap_returnResultLast;         /* ReturnResult */
static int hf_ansi_tcap_returnError;              /* ReturnError */
static int hf_ansi_tcap_reject;                   /* Reject */
static int hf_ansi_tcap_invokeNotLast;            /* Invoke */
static int hf_ansi_tcap_returnResultNotLast;      /* ReturnResult */
static int hf_ansi_tcap_componentIDs;             /* T_componentIDs */
static int hf_ansi_tcap_operationCode;            /* OperationCode */
static int hf_ansi_tcap_invoke_parameter;         /* T_invoke_parameter */
static int hf_ansi_tcap_componentID;              /* T_componentID */
static int hf_ansi_tcap_returnResult_parameter;   /* T_returnResult_parameter */
static int hf_ansi_tcap_componentID_01;           /* T_componentID_01 */
static int hf_ansi_tcap_errorCode;                /* ErrorCode */
static int hf_ansi_tcap_returnError_parameter;    /* T_returnError_parameter */
static int hf_ansi_tcap_componentID_02;           /* OCTET_STRING_SIZE_0_1 */
static int hf_ansi_tcap_rejectProblem;            /* Problem */
static int hf_ansi_tcap_reject_parameter;         /* T_reject_parameter */
static int hf_ansi_tcap_paramSequence;            /* T_paramSequence */
static int hf_ansi_tcap_paramSet;                 /* T_paramSet */

/* Initialize the subtree pointers */
static int ett_tcap;
static int ett_param;
static int ett_ansi_tcap_op_code_nat;
static int ett_ansi_tcap_stat_timestamp;
static int ett_ansi_tcap_duration;

static int ett_otid;
static int ett_dtid;
static int ett_ansi_tcap_stat;

static expert_field ei_ansi_tcap_dissector_not_implemented;

static struct tcapsrt_info_t * gp_tcapsrt_info;
static bool tcap_subdissector_used=false;

static struct tcaphash_context_t * gp_tcap_context;

/* Note the high bit should be masked off when registering in this table (0x7fff)*/
static dissector_table_t  ansi_tcap_national_opcode_table; /* National Operation Codes */

static int ett_ansi_tcap_OperationCode;
static int ett_ansi_tcap_ErrorCode;
static int ett_ansi_tcap_PackageType;
static int ett_ansi_tcap_UniTransactionPDU;
static int ett_ansi_tcap_TransactionPDU;
static int ett_ansi_tcap_Abort;
static int ett_ansi_tcap_T_causeInformation;
static int ett_ansi_tcap_DialoguePortion_U;
static int ett_ansi_tcap_T_applicationContext;
static int ett_ansi_tcap_T_securityContext;
static int ett_ansi_tcap_UserInformation_U;
static int ett_ansi_tcap_Confidentiality;
static int ett_ansi_tcap_T_confidentialityId;
static int ett_ansi_tcap_SEQUENCE_OF_ComponentPDU;
static int ett_ansi_tcap_ComponentPDU;
static int ett_ansi_tcap_Invoke;
static int ett_ansi_tcap_ReturnResult;
static int ett_ansi_tcap_ReturnError;
static int ett_ansi_tcap_Reject;
static int ett_ansi_tcap_T_reject_parameter;
static int ett_ansi_tcap_T_paramSequence;
static int ett_ansi_tcap_T_paramSet;

#define MAX_SSN 254

/* When several Tcap components are received in a single TCAP message,
   we have to use several buffers for the stored parameters
   because else this data are erased during TAP dissector call */
#define MAX_TCAP_INSTANCE 10
int tcapsrt_global_current=0;
struct tcapsrt_info_t tcapsrt_global_info[MAX_TCAP_INSTANCE];

static dissector_table_t ber_oid_dissector_table;
static const char * cur_oid;
static const char * tcapext_oid;

static dissector_handle_t ansi_map_handle;
static dissector_handle_t ain_handle;

struct ansi_tcap_private_t ansi_tcap_private;
#define MAX_TID_STR_LEN 1024

static void ansi_tcap_ctx_init(struct ansi_tcap_private_t *a_tcap_ctx) {
  memset(a_tcap_ctx, '\0', sizeof(*a_tcap_ctx));
  a_tcap_ctx->signature = ANSI_TCAP_CTX_SIGNATURE;
  a_tcap_ctx->oid_is_present = false;
  a_tcap_ctx->TransactionID_str = NULL;
}

/* Tables for register*/

static const value_string ansi_tcap_national_op_code_family_vals[] = {
  {  0x0, "All Families" },
  {  0x1, "Parameter" },
  {  0x2, "Charging" },
  {  0x3, "Provide Instructions" },
  {  0x4, "Connection Control" },
  {  0x5, "Caller Interaction" },
  {  0x6, "Send Notification" },
  {  0x7, "Network Management" },
  {  0x8, "Procedural" },
  {  0x9, "Operation Control" },
  {  0xa, "Report Event" },
  /* Spare */
  {  0x7e, "Miscellaneous" },
  {  0x7f, "Reserved" },
  { 0, NULL }
};

static const value_string ansi_tcap_national_parameter_control_cause_indication[] = {
 { 1, "Vacant Code" },
 { 2, "Out-of-Band" },
 { 3, "Database Overload" },
 { 4, "Destination Mass Calling" },
 { 5, "Operation Support System Initiated" },
 { 0, NULL },
};


static const value_string ansi_tcap_national_parameter_duration_field[] = {
 { 0x0, "Not Used" },
 { 0x1, "1 Second" },
 { 0x2, "2 Seconds" },
 { 0x3, "4 Seconds" },
 { 0x4, "8 Seconds" },
 { 0x5, "16 Seconds" },
 { 0x6, "32 Seconds" },
 { 0x7, "64 Seconds" },
 { 0x8, "128 Seconds" },
 { 0x9, "256 Seconds" },
 { 0xa, "512 Seconds" },
 { 0xb, "1024 Seconds" },
 { 0xc, "2048 Seconds" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_gap[] = {
 { 0x0, "Remove Gap Control" },
 { 0x1, "0.00 Second" },
 { 0x2, "0.10 Seconds" },
 { 0x3, "0.25 Seconds" },
 { 0x4, "0.50 Seconds" },
 { 0x5, "1.00 Seconds" },
 { 0x6, "2.00 Seconds" },
 { 0x7, "5.00 Seconds" },
 { 0x8, "10.00 Seconds" },
 { 0x9, "15.00 Seconds" },
 { 0xa, "30.00 Seconds" },
 { 0xb, "60.00 Seconds" },
 { 0xc, "120.00 Seconds" },
 { 0xd, "300.00 Seconds" },
 { 0xe, "600.00 Seconds" },
 { 0xf, "Stop All Calls" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_digits_type_of_digits[] = {
 { 0x00, "Not Used" },
 { 0x01, "Called Party Number" },
 { 0x02, "Calling Party Number" },
 { 0x03, "Caller Interaction" },
 { 0x04, "Routing Number" },
 { 0x05, "Billing Number" },
 { 0x06, "Destination Number" },
 { 0x07, "LATA" },
 { 0x08, "Carrier" },
 { 0x09, "Last Calling Party" },
 { 0x0a, "Last Party Called" },
 { 0x0b, "Calling Directory Number" },
 { 0x0c, "VMSR Identifier" },
 { 0x0d, "Original Called Number" },
 { 0x0e, "Redirecting Number" },
 { 0x0f, "Connected Number" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_digits_nature_of_numbers[] = {
 { 0x0, "National" },
 { 0x1, "International" },
 { 0x2, "No Presentation Restriction" },
 { 0x3, "Presentation Restriction" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_digits_encoding[] = {
 { 0x0, "Not Used" },
 { 0x1, "BCD" },
 { 0x2, "IA5" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_digits_number_planning[] = {
 { 0x0, "Unknown or Not applicable" },
 { 0x1, "ISDN Numbering" },
 { 0x2, "Telephony Numbering" },
 { 0x3, "Data Numbering" },
 { 0x4, "Telex Numbering" },
 { 0x5, "Maritime Mobile Numbering" },
 { 0x6, "Land Mobile Numbering" },
 { 0x7, "Private Numbering Plan" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_digits_number_of_digits[] = {
 { 0x0, "Digit 0 or filler" },
 { 0x1, "Digit 1" },
 { 0x2, "Digit 2" },
 { 0x3, "Digit 3" },
 { 0x4, "Digit 4" },
 { 0x5, "Digit 5" },
 { 0x6, "Digit 6" },
 { 0x7, "Digit 7" },
 { 0x8, "Digit 8" },
 { 0x9, "Digit 9" },
 { 0xa, "Spare" },
 { 0xb, "Code 11" },
 { 0xc, "Code 12" },
 { 0xd, "*" },
 { 0xe, "#" },
 { 0xf, "ST" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_digits[] = {
 { 0x0, "Remove Gap Control" },
 { 0x1, "0.00 Second" },
 { 0x2, "0.10 Seconds" },
 { 0x3, "0.25 Seconds" },
 { 0x4, "0.50 Seconds" },
 { 0x5, "1.00 Seconds" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_spare[] = {
 { 0, "Service Not Supported" },
 { 1, "Active" },
 { 2, "Not Active" },
 { 3, "Spare" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_dn_match[] = {
 { 0, "spare" },
 { 1, "No Match" },
 { 2, "Match" },
 { 3, "Spare" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_dn_service_type[] = {
 { 0, "Individual" },
 { 1, "Coin" },
 { 2, "Series Completion" },
 { 3, "Multiline Hunt" },
 { 4, "Unassigned" },
 { 5, "PBX" },
 { 6, "Multiparty (3 or more)" },
 { 7, "Choke" },
 { 8, "Nonspecific" },
 { 9, "Temporarily Out-of-Service" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_generic_name_type_of_name[] = {
 { 0, "Spare" },
 { 1, "Calling name" },
 { 2, "Original called name" },
 { 3, "Redirected name" },
 { 4, "Redirected name" },
 { 5, "Spare" },
 { 6, "Spare" },
 { 7, "Spare" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_generic_name_availability[] = {
 { 0, "Name available/unknown" },
 { 1, "Name not available" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_generic_name_presentation_field[] = {
 { 0, "Presentation Allowed" },
 { 1, "Presentation Restricted" },
 { 2, "Blocking Toggle" },
 { 3, "No Indication" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_look_ahead_for_busy_ack[] = {
 { 0, "Path Reservation Denied" },
 { 1, "Negative Acknowledgement" },
 { 2, "Positive Acknowledgement" },
 { 3, "Spare" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_look_ahead_for_busy_location_field[] = {
 { 0, "User" },
 { 1, "Private Network Serving The Local User" },
 { 3, "Public Network Serving The Local User" },
 { 4, "Transit Network" },
 { 5, "Public Network Serving The Remote User" },
 { 6, "Private Network Serving The Remote User" },
 { 8, "Reserved" },
 { 9, "Internation Network" },
 { 0xa, "Network Beyond Interworking Point" },
 { 0, NULL },
};

static const value_string ansi_tcap_national_parameter_level[] = {
 { 0, "Flash Override" },
 { 1, "Flash" },
 { 3, "Immediate" },
 { 4, "Priority" },
 { 5, "Routine" },
 { 0, NULL },
};

/* Parameter list*/

#define TIMESTAMP                               0x17
#define ACG_INDICATORS                          0x81
#define STANDARD_ANNOUNCEMENT                   0x82
#define CUSTOMIZED_ANNOUNCEMENT                 0x83
#define DIGITS                                  0x84
#define STANDARD_USER_ERROR_CODE                0x85
#define PROBLEM_DATA                            0x86
#define SCCP_CALLING_PARTY_ADDRESS              0x87
#define TRANSACTION_ID                          0x88
#define PACKAGE_TYPE                            0x89
#define SERVICE_KEY                             0x8a
#define BUSY_IDLE_STATUS                        0x8b
#define CALL_FORWARDING_STATUS                  0x8c
#define ORIGINATING_RESTRICTIONS                0x8d
#define TERMINATING_RESTRICTIONS                0x8e
#define DN_TO_LINE_SERVICE_TYPE_MAPPING         0x8f
#define DURATION                                0x90
#define RETURNED_DATA                           0x91
#define BEARER_CAPABILITY_REQUESTED             0x92
#define BEARER_CAPABILITY_SUPPORTED             0x93
#define REFERENCE_ID                            0x94
#define BUSINESS_GROUP                          0x95
#define SIGNALLING_NETWORKS_IDENTIFIER          0x96
#define GENERIC_NAME                            0x97
#define MESSAGE_WAITING_INDICATOR_TYPE          0x98
#define LOOK_AHEAD_FOR_BUSY                     0x99
#define CIRCUIT_IDENTIFICATION_CODE             0x9a
#define PRECEDENCE_IDENTIFIER                   0x9b
#define CALL_REFERENCE_IDENTIFIER               0x9c
#define AUTHORIZATION                           0x9d
#define INTEGRITY                               0x9e
#define SEQUENCE_NUMBER                         0x9f1f
#define NUMBER_OF_MESSAGES                      0x7f20
#define DISPLAY_TEXT                            0x7f21
#define KEY_EXCHANGE                            0x7f22
#define SCCP_CALLED_PARTY_ADDRESS               0x7f23


static const value_string ansi_tcap_parameter_vals[] = {
 { TIMESTAMP, "Timestamp" },
 { ACG_INDICATORS, "ACG Indicators" },
 { STANDARD_ANNOUNCEMENT, "Standard Announcement" },
 { CUSTOMIZED_ANNOUNCEMENT, "Customized Announcement Format" },
 { DIGITS, "Digits" },
 { STANDARD_USER_ERROR_CODE, "Standard User Error Code" },
 { PROBLEM_DATA, "Problem Data" },
 { SCCP_CALLING_PARTY_ADDRESS, "SCCP Calling Party Address" },
 { TRANSACTION_ID, "Transaction ID" },
 { PACKAGE_TYPE, "Package Type Identifier" },
 { SERVICE_KEY, "Service Key Identifier" },
 { BUSY_IDLE_STATUS, "Busy Idle Status" },
 { CALL_FORWARDING_STATUS, "Call Forwarding Status" },
 { ORIGINATING_RESTRICTIONS, "Originating Restrictions" },
 { TERMINATING_RESTRICTIONS, "Terminating Restrictions" },
 { DN_TO_LINE_SERVICE_TYPE_MAPPING, "DN To Line Service Type Mapping" },
 { DURATION, "Duration" },
 { RETURNED_DATA, "Returned Data" },
 { BEARER_CAPABILITY_REQUESTED, "Bearer Capability Requested" },
 { BEARER_CAPABILITY_SUPPORTED, "Bearer Capability Supported" },
 { REFERENCE_ID, "Reference ID" },
 { BUSINESS_GROUP, "Business Group" },
 { SIGNALLING_NETWORKS_IDENTIFIER, "Signalling Networks Identifier" },
 { GENERIC_NAME, "Generic Name Identifier" },
 { MESSAGE_WAITING_INDICATOR_TYPE, "Message Waiting Indicator Type" },
 { LOOK_AHEAD_FOR_BUSY, "Look Ahead For Busy" },
 { CIRCUIT_IDENTIFICATION_CODE, "Circuit Identification Code" },
 { PRECEDENCE_IDENTIFIER, "Precedence Level" },
 { CALL_REFERENCE_IDENTIFIER, "Call Reference Identifier" },
 { AUTHORIZATION, "Authorization" },
 { INTEGRITY, "Integrity" },
 { SEQUENCE_NUMBER, "Sequence Number" },
 { 0xaa, "Service Key Identifier" },
 { NUMBER_OF_MESSAGES, "Number of Messages" },
 { DISPLAY_TEXT, "Display Text" },
 { KEY_EXCHANGE, "Key Exchange" },
 { SCCP_CALLED_PARTY_ADDRESS, "SCCP Called Party Address" },
 { 0, NULL },
};

static const value_string ansi_tcap_standard_announcements[] = {
 { 0, "Not Used" },
 { 1, "Out-of-Band" },
 { 2, "Vacant Code" },
 { 3, "Disconnected Number" },
 { 4, "Reorder (120 IPM)" },
 { 5, "Busy (60 IPM)" },
 { 6, "No Circuit Available" },
 { 7, "Reorder" },
 { 8, "Audible Ring" },
 { 0, NULL },
};

static const value_string ansi_tcap_standard_user_error_code[] = {
 { 0, "Call Abandoned" },
 { 1, "Improper Caller Response" },
 { 0, NULL },
};

static const value_string ansi_tcap_package_types[] = {
 { 0xE1, "Unidirectional" },
 { 0xE2, "Query with Permission" },
 { 0xE3, "Query without Permission" },
 { 0xE4, "Response" },
 { 0xE5, "Conversation with Permission" },
 { 0xE6, "Conversation without Permission" },
 { 0xE7, "Abort" },
 { 0, NULL },
};

static const value_string ansi_tcap_status_identifier[] = {
 { 0, "IDLE" },
 { 1, "BUSY" },
 { 0, NULL },
};

static const value_string ansi_tcap_originating_restrictions[] = {
 { 0, "Denied Origination" },
 { 1, "Fully Restricted Origination" },
 { 2, "Semi-Restricted Origination" },
 { 3, "Unrestricted Origination" },
 { 0, NULL },
};


static const value_string ansi_tcap_terminating_restrictions[] = {
 { 0, "Denied Termination" },
 { 1, "Fully Restricted Termination" },
 { 2, "Semi-Restricted Termination" },
 { 3, "Unrestricted Termination" },
 { 4, "Call Rejections Applies" },
 { 0, NULL },
};

static const value_string ansi_tcap_bearer_capabilities_supported[] = {
 { 1, "Not Supported" },
 { 2, "Supported" },
 { 3, "Not Authorized" },
 { 4, "Not Presently Available" },
 { 5, "Not Implemented" },
 { 0, NULL },
};


/* Transaction tracking */
/* Transaction table */
struct ansi_tcap_invokedata_t {
    int OperationCode;
      /*
         0 : national,
         1 : private
      */
    int32_t OperationCode_private;
    int32_t OperationCode_national;
};

static wmem_multimap_t *TransactionId_table;

// nibble swap function
static unsigned char swap_nibbles(unsigned char x){
    return (x & 0x0F)<<4 | (x & 0xF0)>>4;
}

static int parameter_type(proto_tree *tree, tvbuff_t *tvb, int offset_parameter_type)
{
  proto_tree *subtree;
  proto_item *ti, *subitem;
  uint8_t param_value = tvb_get_uint8(tvb, offset_parameter_type);
  uint32_t parameter, parameter_length;

  /* A general parameter decoding looks like: Identifier -> Length -> Value
   There is another case statement to account for the 'F' bit */
  if ((param_value & 0x0F) == 0x0F)
  {
      ti = proto_tree_add_item_ret_uint(tree, hf_ansi_tcap_parameter, tvb, offset_parameter_type, 2, ENC_BIG_ENDIAN, &parameter);
      offset_parameter_type += 2;
  }
  else
  {
      ti = proto_tree_add_item_ret_uint(tree, hf_ansi_tcap_parameter, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &parameter);
      offset_parameter_type += 1;
  }
  offset_parameter_type += 1;

  proto_tree_add_item_ret_uint(tree, hf_ansi_tcap_parameter_length, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &parameter_length);
  offset_parameter_type += 1;
  if (parameter_length == 0)
  {
    proto_item_append_text(ti, " (This parameter is asking to be returned)");
    return offset_parameter_type;
  }

  switch (parameter)
  {
    case TIMESTAMP:
    {
      int year, month, day, hour, minute, difference, local_hour, local_minute;
      subtree = proto_tree_add_subtree(tree, tvb, offset_parameter_type, 8, ett_ansi_tcap_stat_timestamp, &subitem, "Timestamp");

      proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_parameter_timestamp_year, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &year);
      offset_parameter_type += 1;
      proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_parameter_timestamp_month, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &month);
      offset_parameter_type += 1;
      proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_parameter_timestamp_day, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &day);
      offset_parameter_type += 1;
      proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_parameter_timestamp_hour, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &hour);
      offset_parameter_type += 1;
      proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_parameter_timestamp_minute, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &minute);
      offset_parameter_type += 1;
      proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_parameter_timestamp_difference, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &difference);
      offset_parameter_type += 1;
      proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_parameter_timestamp_local_hour, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &local_hour);
      offset_parameter_type += 1;
      proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_parameter_timestamp_local_minute, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &local_minute);
      offset_parameter_type += 1;
      proto_item_append_text(subitem, " (%02d/%02d/%02d %02d:%02d, diff=%d, local time=%02d:%02d)", day, month, year, hour, minute, difference, local_hour, local_minute);
    }
    break;
    case ACG_INDICATORS:
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_acg_control_cause_indicator, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_acg_duration_field, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_acg_gap, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
    break;
    case STANDARD_ANNOUNCEMENT:
        proto_tree_add_item(tree, hf_ansi_tcap_parameter_standard_announcement, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case CUSTOMIZED_ANNOUNCEMENT:
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_customized_announcement, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += (1 + tvb_get_uint8(tvb, offset_parameter_type));
      break;
    case DIGITS:
    {
        uint32_t num_digits;
        proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits_type_of_digits, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
        proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits_nature_of_numbers, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
        proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits_number_planning, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits_encoding, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
        proto_tree_add_item_ret_uint(tree, hf_ansi_tcap_parameter_digits_number_of_digits, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &num_digits);
        offset_parameter_type += 1;
        for (uint32_t i = 0; i <= num_digits; i++)
        {
            proto_tree_add_item(tree, hf_ansi_tcap_parameter_digits, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
            offset_parameter_type += 1;
        }
    }
    break;
    case STANDARD_USER_ERROR_CODE:
        proto_tree_add_item(tree, hf_ansi_tcap_standard_user_error_code, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case SCCP_CALLING_PARTY_ADDRESS:
        proto_tree_add_item(tree, hf_ansi_tcap_sccp_calling_party_address, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case TRANSACTION_ID:
        proto_tree_add_item(tree, hf_ansi_tcap_transaction_id, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case PACKAGE_TYPE:
        proto_tree_add_item(tree, hf_ansi_tcap_package_type, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    /* extra case to account for form bit (F bit)*/
    case SERVICE_KEY: case 0xaa:
    {
      proto_tree_add_item(tree, hf_ansi_tcap_digit_identifier, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_digit_length, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_destination_number_value, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_presentation_restriction, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_encoding_scheme, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_number_of_digits, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      uint8_t phoneNumber[5];
      for (int j = 0; j < 5; j++)
        phoneNumber[j] = swap_nibbles(tvb_get_uint8(tvb, offset_parameter_type+j));

      proto_tree_add_bytes_format_value(tree, hf_ansi_tcap_destination_phone_number, tvb, offset_parameter_type, 5, phoneNumber,
            "%x%x%x-%x%x", phoneNumber[0], phoneNumber[1], phoneNumber[2], phoneNumber[3], phoneNumber[4]);
      offset_parameter_type += 5;

      proto_tree_add_item(tree, hf_ansi_tcap_digit_identifier, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_digit_length, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_destination_number_value, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_presentation_restriction, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_encoding_scheme, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_number_of_digits, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      uint8_t phoneNumberReturn[5];
      for (int k = 0; k < 5; k++)
        phoneNumberReturn[k] = swap_nibbles(tvb_get_uint8(tvb, offset_parameter_type+k));

      proto_tree_add_bytes_format_value(tree, hf_ansi_tcap_return_phone_number, tvb, offset_parameter_type, 5, phoneNumberReturn,
          "%x%x%x-%x%x", phoneNumberReturn[0], phoneNumberReturn[1], phoneNumberReturn[2], phoneNumberReturn[3], phoneNumberReturn[4]);
      offset_parameter_type += 5;
    }
    break;
    case BUSY_IDLE_STATUS:
        proto_tree_add_item(tree, hf_ansi_tcap_busy_idle_status, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case CALL_FORWARDING_STATUS:
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_call_forwarding_on_busy, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_call_forwarding_dont_answer, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_selective_forwarding, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
    break;
    case ORIGINATING_RESTRICTIONS:
        proto_tree_add_item(tree, hf_ansi_tcap_originating_restrictions, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case TERMINATING_RESTRICTIONS:
        proto_tree_add_item(tree, hf_ansi_tcap_terminating_restrictions, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case DN_TO_LINE_SERVICE_TYPE_MAPPING:
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_dn_match, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_dn_line_service, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
      break;
    case DURATION:
    {
        int hour, minute, second;
        subtree = proto_tree_add_subtree(tree, tvb, offset_parameter_type, 3, ett_ansi_tcap_duration, &subitem, "Call duration");

        proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_duration_hour, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &hour);
        offset_parameter_type += 1;
        proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_duration_minute, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &minute);
        offset_parameter_type += 1;
        proto_tree_add_item_ret_int(subtree, hf_ansi_tcap_duration_second, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN, &second);
        offset_parameter_type += 1;
        proto_item_append_text(subitem, " (%02d:%02d:%02d)", hour, minute, second);
    }
    break;
    case RETURNED_DATA:
        proto_tree_add_item(tree, hf_ansi_tcap_returned_data, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case BEARER_CAPABILITY_REQUESTED:
    // TODO finishing out bearer capability, look into ansi_map
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested1, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested2, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested2a, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested2b, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested3, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_bearer_capability_requested3a, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
      break;
    case BEARER_CAPABILITY_SUPPORTED:
        proto_tree_add_item(tree, hf_ansi_tcap_bearer_capability_supported, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case REFERENCE_ID:
        proto_tree_add_item(tree, hf_ansi_tcap_reference_id, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case BUSINESS_GROUP:
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_length_spare, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_length_AttSt, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_length_BGID, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_length_LP11, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_length_Party_Selector, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_id, tvb, offset_parameter_type, 3, ENC_BIG_ENDIAN);
      offset_parameter_type +=3;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_subgroup_id, tvb, offset_parameter_type, 2, ENC_BIG_ENDIAN);
      offset_parameter_type +=2;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_business_group_line_privileges, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      break;
    case SIGNALLING_NETWORKS_IDENTIFIER:
        proto_tree_add_item(tree, hf_ansi_tcap_parameter_signalling_networks_id, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += (1+tvb_get_uint8(tvb, offset_parameter_type));
    break;
    case GENERIC_NAME:
    {
      uint8_t character_number = tvb_get_uint8(tvb, offset_parameter_type);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_generic_name_type_name, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_generic_name_availability, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_generic_name_spare, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_generic_name_presentation, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_generic_name_characters, tvb, offset_parameter_type, character_number, ENC_ASCII);
      offset_parameter_type += character_number;
    }
    break;
    case MESSAGE_WAITING_INDICATOR_TYPE:
      proto_tree_add_uint(tree, hf_ansi_tcap_message_waiting_indicator_type, tvb, offset_parameter_type, 1, swap_nibbles(tvb_get_uint8(tvb, offset_parameter_type)));
      offset_parameter_type += 1;
    break;
    case LOOK_AHEAD_FOR_BUSY:
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_look_ahead_for_busy_ack_type, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_look_ahead_for_busy_spare, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_look_ahead_for_busy_location_field, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
    break;
    case CIRCUIT_IDENTIFICATION_CODE:
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_CIC_lsb, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type +=1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_CIC_spare, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_CIC_msb, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
      break;
    case PRECEDENCE_IDENTIFIER:
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_precedence_level_spare, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_precedence_level, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_precedence_id1, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_precedence_id2, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_precedence_id3, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_precedence_id4, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += 1;
      proto_tree_add_item(tree, hf_ansi_tcap_parameter_precedence_mlpp_service_domain, tvb, offset_parameter_type, 3, ENC_NA);
      offset_parameter_type += 3;
    break;
    case CALL_REFERENCE_IDENTIFIER:
        proto_tree_add_item(tree, hf_ansi_tcap_reference_id_call_identify, tvb, offset_parameter_type, 3, ENC_NA);
        offset_parameter_type += 3;
        proto_tree_add_item(tree, hf_ansi_tcap_reference_id_point_code, tvb, offset_parameter_type, 3, ENC_NA);
        offset_parameter_type += 3;
    break;
    case AUTHORIZATION:
        proto_tree_add_item(tree, hf_ansi_tcap_parameter_authorization, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
    break;
    case INTEGRITY:
        proto_tree_add_item(tree, hf_ansi_tcap_integrity_algid_id, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
        proto_tree_add_item(tree, hf_ansi_tcap_integrity_algid, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += (1+ tvb_get_uint8(tvb, offset_parameter_type));
        proto_tree_add_item(tree, hf_ansi_tcap_integrity_value_id, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += 1;
        proto_tree_add_item(tree, hf_ansi_tcap_integrity_value, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += (1+ tvb_get_uint8(tvb, offset_parameter_type));
    break;

    /* 2 octet length parameters identifiers */
    case SEQUENCE_NUMBER:
      proto_tree_add_item(tree, hf_ansi_tcap_sequence_number, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
      offset_parameter_type += (1 + tvb_get_uint8(tvb, offset_parameter_type));
    break;
    case NUMBER_OF_MESSAGES:
        proto_tree_add_item(tree, hf_ansi_tcap_num_messages, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
        offset_parameter_type += (1 + tvb_get_uint8(tvb, offset_parameter_type));
        break;
      case DISPLAY_TEXT:
          proto_tree_add_item(tree, hf_ansi_tcap_display_text, tvb, offset_parameter_type, 1, ENC_ASCII|ENC_BIG_ENDIAN);
          offset_parameter_type += (1 + tvb_get_uint8(tvb, offset_parameter_type));
        break;

      case KEY_EXCHANGE:
          proto_tree_add_item(tree, hf_ansi_tcap_key_exchange_algid_id, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
          offset_parameter_type += 1;
          proto_tree_add_item(tree, hf_ansi_tcap_key_exchange_algid, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
          offset_parameter_type += (1 + tvb_get_uint8(tvb, offset_parameter_type));
          proto_tree_add_item(tree, hf_ansi_tcap_key_exchange_value_id, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
          offset_parameter_type += 1;
          proto_tree_add_item(tree, hf_ansi_tcap_key_exchange_value, tvb, offset_parameter_type, 1, ENC_BIG_ENDIAN);
          offset_parameter_type += (1 + tvb_get_uint8(tvb, offset_parameter_type));
        break;

      case SCCP_CALLED_PARTY_ADDRESS:
      // TODO Parameter found in T1.112
        break;

    default:
    break;
  }
  return offset_parameter_type;
}

/* Store Invoke information needed for the corresponding reply */
static void
save_invoke_data(packet_info *pinfo, proto_tree *tree _U_, tvbuff_t *tvb _U_){
  struct ansi_tcap_invokedata_t *ansi_tcap_saved_invokedata;
  char *src, *dst;
  char *buf;

  src = address_to_str(pinfo->pool, &(pinfo->src));
  dst = address_to_str(pinfo->pool, &(pinfo->dst));

  if ((!pinfo->fd->visited)&&(ansi_tcap_private.TransactionID_str)){

          /* Only do this once XXX I hope it's the right thing to do */
          /* The hash string needs to contain src and dest to distinguish different flows */
          switch(ansi_tcap_response_matching_type){
                        case ANSI_TCAP_TID_ONLY:
                                buf = wmem_strdup(pinfo->pool, ansi_tcap_private.TransactionID_str);
                                break;
                        case ANSI_TCAP_TID_AND_SOURCE:
                                buf = wmem_strdup_printf(pinfo->pool, "%s%s",ansi_tcap_private.TransactionID_str,src);
                                break;
                        case ANSI_TCAP_TID_SOURCE_AND_DEST:
                        default:
                                buf = wmem_strdup_printf(pinfo->pool, "%s%s%s",ansi_tcap_private.TransactionID_str,src,dst);
                                break;
                }

          ansi_tcap_saved_invokedata = wmem_new(wmem_file_scope(), struct ansi_tcap_invokedata_t);
          ansi_tcap_saved_invokedata->OperationCode = ansi_tcap_private.d.OperationCode;
          ansi_tcap_saved_invokedata->OperationCode_national = ansi_tcap_private.d.OperationCode_national;
          ansi_tcap_saved_invokedata->OperationCode_private = ansi_tcap_private.d.OperationCode_private;

          wmem_multimap_insert32(TransactionId_table,
                        wmem_strdup(wmem_file_scope(), buf),
                        pinfo->num,
                        ansi_tcap_saved_invokedata);
          /*
          ws_warning("Tcap Invoke Hash string %s",buf);
          */
  }
}

static bool
find_saved_invokedata(packet_info *pinfo, proto_tree *tree _U_, tvbuff_t *tvb _U_){
  struct ansi_tcap_invokedata_t *ansi_tcap_saved_invokedata;
  char *src, *dst;
  char *buf;

  if (!ansi_tcap_private.TransactionID_str) {
    return false;
  }

  src = address_to_str(pinfo->pool, &(pinfo->src));
  dst = address_to_str(pinfo->pool, &(pinfo->dst));

  /* The hash string needs to contain src and dest to distinguish different flows */
  buf = (char *)wmem_alloc(pinfo->pool, MAX_TID_STR_LEN);
  buf[0] = '\0';
  /* Reverse order to invoke */
  switch(ansi_tcap_response_matching_type){
        case ANSI_TCAP_TID_ONLY:
                snprintf(buf,MAX_TID_STR_LEN,"%s",ansi_tcap_private.TransactionID_str);
                break;
        case ANSI_TCAP_TID_AND_SOURCE:
                snprintf(buf,MAX_TID_STR_LEN,"%s%s",ansi_tcap_private.TransactionID_str,dst);
                break;
        case ANSI_TCAP_TID_SOURCE_AND_DEST:
        default:
                snprintf(buf,MAX_TID_STR_LEN,"%s%s%s",ansi_tcap_private.TransactionID_str,dst,src);
                break;
  }

  ansi_tcap_saved_invokedata = (struct ansi_tcap_invokedata_t *)wmem_multimap_lookup32_le(TransactionId_table, buf, pinfo->num);
  if(ansi_tcap_saved_invokedata){
          ansi_tcap_private.d.OperationCode                      = ansi_tcap_saved_invokedata->OperationCode;
          ansi_tcap_private.d.OperationCode_national = ansi_tcap_saved_invokedata->OperationCode_national;
          ansi_tcap_private.d.OperationCode_private  = ansi_tcap_saved_invokedata->OperationCode_private;
          return true;
  }
  return false;
}

/* As currently ANSI MAP is the only possible sub dissector this function
 *  must be improved to handle general cases.
 *
 *
 *
 * TODO:
 * 1)Handle national codes
 *     Design option
 *     - Create a ansi.tcap.national dissector table and have dissectors for
 *       national codes register there and let ansi tcap call them.
 * 2)Handle Private codes properly
 *     Design question
 *     Unclear how to differentiate between different private "code sets".
 *     Use SCCP SSN table as before? or a ansi.tcap.private dissector table?
 *
 */
static bool
find_tcap_subdissector(tvbuff_t *tvb, asn1_ctx_t *actx, proto_tree *tree){
        proto_item *item;

        /* If "DialoguePortion objectApplicationId ObjectIDApplicationContext
         * points to the subdissector this code can be used.
         *
        if(ansi_tcap_private.d.oid_is_present){
                call_ber_oid_callback(ansi_tcap_private.objectApplicationId_oid, tvb, 0, actx-pinfo, tree, NULL);
                return true;
        }
        */
        if(ansi_tcap_private.d.pdu == 1){
                /* Save Invoke data for this transaction */
                save_invoke_data(actx->pinfo, tree, tvb);
        }else{
                /* Get saved data for this transaction */
                if(find_saved_invokedata(actx->pinfo, tree, tvb)){
                        if(ansi_tcap_private.d.OperationCode == 0){
                                /* national */
                                item = proto_tree_add_int(tree, hf_ansi_tcap_national, tvb, 0, 0, ansi_tcap_private.d.OperationCode_national);
                        }else{
                                item = proto_tree_add_int(tree, hf_ansi_tcap_private, tvb, 0, 0, ansi_tcap_private.d.OperationCode_private);
                        }
                        proto_item_set_generated(item);
                        ansi_tcap_private.d.OperationCode_item = item;
                }
        }
        if(ansi_tcap_private.d.OperationCode == 0){
                /* national */
                proto_item          *item2=NULL;
                proto_tree          *tree2=NULL;
                uint8_t family = (ansi_tcap_private.d.OperationCode_national & 0x7f00)>>8;
                uint8_t specifier = (uint8_t)(ansi_tcap_private.d.OperationCode_national & 0xff);
                if(!dissector_try_uint(ansi_tcap_national_opcode_table, ansi_tcap_private.d.OperationCode_national, tvb, actx->pinfo, actx->subtree.top_tree)){
                        proto_tree_add_expert_format(tree, actx->pinfo, &ei_ansi_tcap_dissector_not_implemented, tvb, 0, -1,
                                        "Dissector for ANSI TCAP NATIONAL code:0x%x(Family %u, Specifier %u) \n"
                                        "not implemented. Contact Wireshark developers if you want this supported(Spec required)",
                                        ansi_tcap_private.d.OperationCode_national, family, specifier);
                        item2 = proto_tree_add_text_internal(tree, tvb, 0, 1, "Parameters");
                        tree2 = proto_item_add_subtree(item2, ett_tcap);
                        int offset_parameter = 0;
                        proto_tree_add_item(tree2, hf_ansi_tcap_parameter_set_start, tvb, 0, 1, ENC_BIG_ENDIAN);

                        if(((tvb_get_uint8(tvb, 0)) & 0xff) == 0xf2) {
                            offset_parameter += 1;
                            int parameter_length = tvb_get_uint8(tvb, offset_parameter);
                            proto_tree_add_item(tree2, hf_ansi_tcap_parameter_length, tvb, offset_parameter, 1, ENC_BIG_ENDIAN);
                            offset_parameter += 1;
                            while (offset_parameter <= parameter_length)
                            {
                                offset_parameter = parameter_type(tree2, tvb, offset_parameter);
                                offset_parameter +=1;
                            }
                        }else{
                            proto_tree_add_text_internal(tree2, tvb, 0, 1, "No parameters exists");
                        }

                        return false;
                }
                return true;
        }else if(ansi_tcap_private.d.OperationCode == 1){
                /* private */
                if((ansi_tcap_private.d.OperationCode_private & 0xff00) == 0x0900){
                    /* This is abit of a hack as it assumes the private codes with a "family" of 0x09 is ANSI MAP
                    * See TODO above.
                    * N.S0005-0 v 1.0 TCAP Formats and Procedures 5-16 Application Services
                    * 6.3.2 Component Portion
                    * The Operation Code is partitioned into an Operation Family followed by a
                    * Specifier associated with each Operation Family member. For TIA/EIA-41 the
                    * Operation Family is coded as decimal 9. Bit H of the Operation Family is always
                    * coded as 0.
                    */
                    call_dissector_with_data(ansi_map_handle, tvb, actx->pinfo, actx->subtree.top_tree, &ansi_tcap_private);

                    return true;
                } else if ((ansi_tcap_private.d.OperationCode_private & 0xf000) == 0x6000) {
                    call_dissector_with_data(ain_handle, tvb, actx->pinfo, actx->subtree.top_tree, &ansi_tcap_private);
                    return true;
                }
        }
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_ansi_tcap_dissector_not_implemented, tvb, 0, -1,
            "Dissector for ANSI TCAP PRIVATE code:%u not implemented.\n"
            "Contact Wireshark developers if you want this supported(Spec required)",
            ansi_tcap_private.d.OperationCode_private);
        return false;
}



static int
dissect_ansi_tcap_T_national(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 proto_tree *subtree;
 proto_item *spcifier_item;
 int start_offset = offset;
 uint8_t family;
 uint8_t specifier;

    offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            -32768, 32767U, hf_index, &ansi_tcap_private.d.OperationCode_national);

  /* mask off the H bit */
  ansi_tcap_private.d.OperationCode_national = (ansi_tcap_private.d.OperationCode_national&0x7fff);

  subtree = proto_item_add_subtree(actx->created_item, ett_ansi_tcap_op_code_nat);
  /* Bit H is used to distinguish between Operations that require a reply and those that do not. A value of 1
   * indicates that a reply is required; a value of 0 indicates that a reply is not required.
   */
  family = (ansi_tcap_private.d.OperationCode_national & 0x7f00)>>8;
  specifier = (uint8_t)(ansi_tcap_private.d.OperationCode_national & 0xff);
  proto_tree_add_item(subtree, hf_ansi_tcap_bit_h, tvb, start_offset, 2, ENC_BIG_ENDIAN);
  proto_tree_add_item(subtree, hf_ansi_tcap_op_family, tvb, start_offset, 2, ENC_BIG_ENDIAN);
  spcifier_item = proto_tree_add_item(subtree, hf_ansi_tcap_op_specifier, tvb, start_offset, 2, ENC_BIG_ENDIAN);

  switch(family){
	case 0:
		/* All Families ( Not used ) */
		break;
	case 1:
		/* Parameter */
		if(specifier== 1){
			proto_item_append_text(spcifier_item, " Provide Value");
		}else if (specifier== 2){
			proto_item_append_text(spcifier_item, " Set Value");
		}
		break;
	case 2:
		/* Charging */
		if (specifier== 1){
			proto_item_append_text(spcifier_item, " Bill Call");
		}
		break;
	case 3:
		/* Provide Instructions */
		if (specifier== 1){
			proto_item_append_text(spcifier_item, " Start");
		}else if (specifier== 2){
			proto_item_append_text(spcifier_item, " Assist");
		}
		break;
	case 4:
		/* Connection Control */
		if (specifier== 1){
			proto_item_append_text(spcifier_item, " Connect");
		}else if (specifier== 2){
			proto_item_append_text(spcifier_item, " Temporary Connect");
		}else if (specifier== 3){
			proto_item_append_text(spcifier_item, " Disconnect");
		}else if (specifier== 4){
			proto_item_append_text(spcifier_item, " Forward Disconnect");
		}
		break;
	default:
		break;
  }



  return offset;
}



static int
dissect_ansi_tcap_T_private(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &ansi_tcap_private.d.OperationCode_private);

  return offset;
}


static const value_string ansi_tcap_OperationCode_vals[] = {
  {  16, "national" },
  {  17, "private" },
  { 0, NULL }
};

static const ber_choice_t OperationCode_choice[] = {
  {  16, &hf_ansi_tcap_national  , BER_CLASS_PRI, 16, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_national },
  {  17, &hf_ansi_tcap_private   , BER_CLASS_PRI, 17, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_private },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_OperationCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OperationCode_choice, hf_index, ett_ansi_tcap_OperationCode,
                                 &ansi_tcap_private.d.OperationCode);

  ansi_tcap_private.d.OperationCode_item = actx->created_item;
  return offset;
}



static int
dissect_ansi_tcap_INTEGER_M128_127(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            -128, 127U, hf_index, NULL);

  return offset;
}


static const value_string ansi_tcap_ANSIMAPPrivateErrorcode_vals[] = {
  { 129, "unrecognized-MIN" },
  { 130, "unrecognized-ESN" },
  { 131, "mINorHLR-Mismatch" },
  { 132, "operation-Sequence-Problem" },
  { 133, "resource-Shortage" },
  { 134, "operation-Not-Supported" },
  { 135, "trunk-Unavailable" },
  { 136, "parameter-Error" },
  { 137, "system-Failure" },
  { 138, "unrecognized-Parameter-Value" },
  { 139, "feature-Inactive" },
  { 140, "missing-Parameter" },
  { 0, NULL }
};


static int
dissect_ansi_tcap_ANSIMAPPrivateErrorcode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, 255U, hf_index, NULL);

  return offset;
}


static const value_string ansi_tcap_ErrorCode_vals[] = {
  {  19, "national" },
  {  20, "private" },
  { 0, NULL }
};

static const ber_choice_t ErrorCode_choice[] = {
  {  19, &hf_ansi_tcap_national_01, BER_CLASS_PRI, 19, 0, dissect_ansi_tcap_INTEGER_M128_127 },
  {  20, &hf_ansi_tcap_ec_private, BER_CLASS_PRI, 20, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_ANSIMAPPrivateErrorcode },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ErrorCode_choice, hf_index, ett_ansi_tcap_ErrorCode,
                                 NULL);

  return offset;
}



static int
dissect_ansi_tcap_TransactionID_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

tvbuff_t *next_tvb;
uint8_t len;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &next_tvb);


if(next_tvb) {
	len = tvb_reported_length_remaining(next_tvb, 0);
	if(len !=0){
		/* 0 octets for the Unidirectional,
		 * 4 octets for Query, Response & Abort
		 * 8 octets for Conversation in the order Originating then Responding TID
		 *
		 * In order to match this it seems like we should only use the last 4 octets
		 * in the 8 octets case.
		 */
		if (len > 4){
			ansi_tcap_private.TransactionID_str = tvb_bytes_to_str(actx->pinfo->pool, next_tvb, 4,len-4);
		}else{
			ansi_tcap_private.TransactionID_str = tvb_bytes_to_str(actx->pinfo->pool, next_tvb, 0,len);
		}
	}
	switch(len) {
	case 1:
		gp_tcapsrt_info->src_tid=tvb_get_uint8(next_tvb, 0);
		break;
	case 2:
		gp_tcapsrt_info->src_tid=tvb_get_ntohs(next_tvb, 0);
		break;
	case 4:
		gp_tcapsrt_info->src_tid=tvb_get_ntohl(next_tvb, 0);
		break;
	default:
		gp_tcapsrt_info->src_tid=0;
		break;
	}
}


  return offset;
}



static int
dissect_ansi_tcap_TransactionID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 7, true, dissect_ansi_tcap_TransactionID_U);

  return offset;
}



static int
dissect_ansi_tcap_OCTET_STRING_SIZE_1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   1, 1, hf_index, NULL);

  return offset;
}



static int
dissect_ansi_tcap_ProtocolVersion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 26, true, dissect_ansi_tcap_OCTET_STRING_SIZE_1);

  return offset;
}



static int
dissect_ansi_tcap_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ansi_tcap_IntegerApplicationContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 27, true, dissect_ansi_tcap_INTEGER);

  return offset;
}



static int
dissect_ansi_tcap_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_ansi_tcap_ObjectIDApplicationContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

 static const char * oid_str;

   offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 28, true, dissect_ansi_tcap_OBJECT_IDENTIFIER);

 	ansi_tcap_private.objectApplicationId_oid= (const void*) oid_str;
	ansi_tcap_private.oid_is_present=true;


  return offset;
}


static const value_string ansi_tcap_T_applicationContext_vals[] = {
  {  27, "integerApplicationId" },
  {  28, "objectApplicationId" },
  { 0, NULL }
};

static const ber_choice_t T_applicationContext_choice[] = {
  {  27, &hf_ansi_tcap_integerApplicationId, BER_CLASS_PRI, 27, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_IntegerApplicationContext },
  {  28, &hf_ansi_tcap_objectApplicationId, BER_CLASS_PRI, 28, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_ObjectIDApplicationContext },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_applicationContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_applicationContext_choice, hf_index, ett_ansi_tcap_T_applicationContext,
                                 NULL);

  return offset;
}



static int
dissect_ansi_tcap_EXTERNAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const ber_sequence_t UserInformation_U_sequence_of[1] = {
  { &hf_ansi_tcap__untag_item, BER_CLASS_UNI, BER_UNI_TAG_EXTERNAL, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_EXTERNAL },
};

static int
dissect_ansi_tcap_UserInformation_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      UserInformation_U_sequence_of, hf_index, ett_ansi_tcap_UserInformation_U);

  return offset;
}



static int
dissect_ansi_tcap_UserInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 29, true, dissect_ansi_tcap_UserInformation_U);

  return offset;
}


static const value_string ansi_tcap_T_securityContext_vals[] = {
  {   0, "integerSecurityId" },
  {   1, "objectSecurityId" },
  { 0, NULL }
};

static const ber_choice_t T_securityContext_choice[] = {
  {   0, &hf_ansi_tcap_integerSecurityId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_INTEGER },
  {   1, &hf_ansi_tcap_objectSecurityId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_securityContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_securityContext_choice, hf_index, ett_ansi_tcap_T_securityContext,
                                 NULL);

  return offset;
}


static const value_string ansi_tcap_T_confidentialityId_vals[] = {
  {   0, "integerConfidentialityId" },
  {   1, "objectConfidentialityId" },
  { 0, NULL }
};

static const ber_choice_t T_confidentialityId_choice[] = {
  {   0, &hf_ansi_tcap_integerConfidentialityId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_INTEGER },
  {   1, &hf_ansi_tcap_objectConfidentialityId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_confidentialityId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_confidentialityId_choice, hf_index, ett_ansi_tcap_T_confidentialityId,
                                 NULL);

  return offset;
}


static const ber_sequence_t Confidentiality_sequence[] = {
  { &hf_ansi_tcap_confidentialityId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_confidentialityId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_Confidentiality(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Confidentiality_sequence, hf_index, ett_ansi_tcap_Confidentiality);

  return offset;
}


static const ber_sequence_t DialoguePortion_U_sequence[] = {
  { &hf_ansi_tcap_version   , BER_CLASS_PRI, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_ProtocolVersion },
  { &hf_ansi_tcap_applicationContext, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_applicationContext },
  { &hf_ansi_tcap_userInformation, BER_CLASS_PRI, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_UserInformation },
  { &hf_ansi_tcap_securityContext, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_securityContext },
  { &hf_ansi_tcap_confidentiality, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Confidentiality },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_DialoguePortion_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DialoguePortion_U_sequence, hf_index, ett_ansi_tcap_DialoguePortion_U);

  return offset;
}



static int
dissect_ansi_tcap_DialoguePortion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 25, true, dissect_ansi_tcap_DialoguePortion_U);

  return offset;
}



static int
dissect_ansi_tcap_T_componentIDs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   0, 2, hf_index, NULL);

  return offset;
}



static int
dissect_ansi_tcap_T_invoke_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  if(find_tcap_subdissector(tvb, actx, tree))
    offset = tvb_reported_length(tvb);



  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { &hf_ansi_tcap_componentIDs, BER_CLASS_PRI, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_componentIDs },
  { &hf_ansi_tcap_operationCode, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_OperationCode },
  { &hf_ansi_tcap_invoke_parameter, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_T_invoke_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_Invoke(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ansi_tcap_private.d.pdu = 1;


  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_ansi_tcap_Invoke);

  return offset;
}



static int
dissect_ansi_tcap_T_componentID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   1, 1, hf_index, NULL);

  return offset;
}



static int
dissect_ansi_tcap_T_returnResult_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if(find_tcap_subdissector(tvb, actx, tree))
    offset = tvb_reported_length(tvb);


  return offset;
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { &hf_ansi_tcap_componentID, BER_CLASS_PRI, 15, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_componentID },
  { &hf_ansi_tcap_returnResult_parameter, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_T_returnResult_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ReturnResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ansi_tcap_private.d.pdu = 2;



  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_ansi_tcap_ReturnResult);

  return offset;
}



static int
dissect_ansi_tcap_T_componentID_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   1, 1, hf_index, NULL);

  return offset;
}



static int
dissect_ansi_tcap_T_returnError_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if(find_tcap_subdissector(tvb, actx, tree))
    offset = tvb_reported_length(tvb);


  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_ansi_tcap_componentID_01, BER_CLASS_PRI, 15, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_componentID_01 },
  { &hf_ansi_tcap_errorCode , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_ErrorCode },
  { &hf_ansi_tcap_returnError_parameter, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_T_returnError_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ReturnError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ansi_tcap_private.d.pdu = 3;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_ansi_tcap_ReturnError);

  return offset;
}



static int
dissect_ansi_tcap_OCTET_STRING_SIZE_0_1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   0, 1, hf_index, NULL);

  return offset;
}


static const value_string ansi_tcap_Problem_vals[] = {
  { 257, "general-unrecognisedComponentType" },
  { 258, "general-incorrectComponentPortion" },
  { 259, "general-badlyStructuredCompPortion" },
  { 260, "general-incorrectComponentCoding" },
  { 513, "invoke-duplicateInvocation" },
  { 514, "invoke-unrecognisedOperation" },
  { 515, "invoke-incorrectParameter" },
  { 516, "invoke-unrecognisedCorrelationID" },
  { 769, "returnResult-unrecognisedCorrelationID" },
  { 770, "returnResult-unexpectedReturnResult" },
  { 771, "returnResult-incorrectParameter" },
  { 1025, "returnError-unrecognisedCorrelationID" },
  { 1026, "returnError-unexpectedReturnError" },
  { 1027, "returnError-unrecognisedError" },
  { 1028, "returnError-unexpectedError" },
  { 1029, "returnError-incorrectParameter" },
  { 1281, "transaction-unrecognizedPackageType" },
  { 1282, "transaction-incorrectTransPortion" },
  { 1283, "transaction-badlyStructuredTransPortion" },
  { 1284, "transaction-unassignedRespondingTransID" },
  { 1285, "transaction-permissionToReleaseProblem" },
  { 1286, "transaction-resourceUnavailable" },
  { 0, NULL }
};


static int
dissect_ansi_tcap_Problem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_paramSequence_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_paramSequence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_paramSequence_sequence, hf_index, ett_ansi_tcap_T_paramSequence);

  return offset;
}


static const ber_sequence_t T_paramSet_set[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_paramSet(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              T_paramSet_set, hf_index, ett_ansi_tcap_T_paramSet);

  return offset;
}


static const value_string ansi_tcap_T_reject_parameter_vals[] = {
  {  16, "paramSequence" },
  {  18, "paramSet" },
  { 0, NULL }
};

static const ber_choice_t T_reject_parameter_choice[] = {
  {  16, &hf_ansi_tcap_paramSequence, BER_CLASS_PRI, 16, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_paramSequence },
  {  18, &hf_ansi_tcap_paramSet  , BER_CLASS_PRI, 18, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_paramSet },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_reject_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_reject_parameter_choice, hf_index, ett_ansi_tcap_T_reject_parameter,
                                 NULL);

  return offset;
}


static const ber_sequence_t Reject_sequence[] = {
  { &hf_ansi_tcap_componentID_02, BER_CLASS_PRI, 15, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_OCTET_STRING_SIZE_0_1 },
  { &hf_ansi_tcap_rejectProblem, BER_CLASS_PRI, 21, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Problem },
  { &hf_ansi_tcap_reject_parameter, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_reject_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_Reject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_ansi_tcap_Reject);

  return offset;
}


static const value_string ansi_tcap_ComponentPDU_vals[] = {
  {   9, "invokeLast" },
  {  10, "returnResultLast" },
  {  11, "returnError" },
  {  12, "reject" },
  {  13, "invokeNotLast" },
  {  14, "returnResultNotLast" },
  { 0, NULL }
};

static const ber_choice_t ComponentPDU_choice[] = {
  {   9, &hf_ansi_tcap_invokeLast, BER_CLASS_PRI, 9, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Invoke },
  {  10, &hf_ansi_tcap_returnResultLast, BER_CLASS_PRI, 10, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_ReturnResult },
  {  11, &hf_ansi_tcap_returnError, BER_CLASS_PRI, 11, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_ReturnError },
  {  12, &hf_ansi_tcap_reject    , BER_CLASS_PRI, 12, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Reject },
  {  13, &hf_ansi_tcap_invokeNotLast, BER_CLASS_PRI, 13, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_Invoke },
  {  14, &hf_ansi_tcap_returnResultNotLast, BER_CLASS_PRI, 14, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_ReturnResult },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_ComponentPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ComponentPDU_choice, hf_index, ett_ansi_tcap_ComponentPDU,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ComponentPDU_sequence_of[1] = {
  { &hf_ansi_tcap__untag_item_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_ComponentPDU },
};

static int
dissect_ansi_tcap_SEQUENCE_OF_ComponentPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ComponentPDU_sequence_of, hf_index, ett_ansi_tcap_SEQUENCE_OF_ComponentPDU);

  return offset;
}



static int
dissect_ansi_tcap_ComponentSequence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 8, true, dissect_ansi_tcap_SEQUENCE_OF_ComponentPDU);

  return offset;
}


static const ber_sequence_t UniTransactionPDU_sequence[] = {
  { &hf_ansi_tcap_identifier, BER_CLASS_PRI, 7, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_TransactionID },
  { &hf_ansi_tcap_dialoguePortion, BER_CLASS_PRI, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_DialoguePortion },
  { &hf_ansi_tcap_componentPortion, BER_CLASS_PRI, 8, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_ComponentSequence },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_UniTransactionPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UniTransactionPDU_sequence, hf_index, ett_ansi_tcap_UniTransactionPDU);

  return offset;
}



static int
dissect_ansi_tcap_T_unidirectional(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "unidirectional ");

  offset = dissect_ansi_tcap_UniTransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t TransactionPDU_sequence[] = {
  { &hf_ansi_tcap_identifier, BER_CLASS_PRI, 7, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_TransactionID },
  { &hf_ansi_tcap_dialoguePortion, BER_CLASS_PRI, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_DialoguePortion },
  { &hf_ansi_tcap_componentPortion, BER_CLASS_PRI, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_ComponentSequence },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_TransactionPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TransactionPDU_sequence, hf_index, ett_ansi_tcap_TransactionPDU);

  return offset;
}



static int
dissect_ansi_tcap_T_queryWithPerm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "queryWithPerm ");

  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_queryWithoutPerm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "queryWithoutPerm ");

  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "response ");

  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_conversationWithPerm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "conversationWithPerm ");

  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_ansi_tcap_T_conversationWithoutPerm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ALL;
col_set_str(actx->pinfo->cinfo, COL_INFO, "conversationWithoutPerm ");

  offset = dissect_ansi_tcap_TransactionPDU(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string ansi_tcap_P_Abort_cause_U_vals[] = {
  {   1, "unrecognizedPackageType" },
  {   2, "incorrectTransactionPortion" },
  {   3, "badlyStructuredTransactionPortion" },
  {   4, "unassignedRespondingTransactionID" },
  {   5, "permissionToReleaseProblem" },
  {   6, "resourceUnavailable" },
  {   7, "unrecognizedDialoguePortionID" },
  {   8, "badlyStructuredDialoguePortion" },
  {   9, "missingDialoguePortion" },
  {  10, "inconsistentDialoguePortion" },
  { 0, NULL }
};


static int
dissect_ansi_tcap_P_Abort_cause_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ansi_tcap_P_Abort_cause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 23, true, dissect_ansi_tcap_P_Abort_cause_U);

  return offset;
}



static int
dissect_ansi_tcap_UserAbortInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_PRI, 24, false, dissect_ansi_tcap_EXTERNAL);

  return offset;
}


static const value_string ansi_tcap_T_causeInformation_vals[] = {
  {  23, "abortCause" },
  {  24, "userInformation" },
  { 0, NULL }
};

static const ber_choice_t T_causeInformation_choice[] = {
  {  23, &hf_ansi_tcap_abortCause, BER_CLASS_PRI, 23, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_P_Abort_cause },
  {  24, &hf_ansi_tcap_abort_userInformation, BER_CLASS_PRI, 24, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_UserAbortInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_T_causeInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_causeInformation_choice, hf_index, ett_ansi_tcap_T_causeInformation,
                                 NULL);

  return offset;
}


static const ber_sequence_t Abort_sequence[] = {
  { &hf_ansi_tcap_identifier, BER_CLASS_PRI, 7, BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_TransactionID },
  { &hf_ansi_tcap_dialogPortion, BER_CLASS_PRI, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ansi_tcap_DialoguePortion },
  { &hf_ansi_tcap_causeInformation, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ansi_tcap_T_causeInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_Abort(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Abort_sequence, hf_index, ett_ansi_tcap_Abort);

  return offset;
}



static int
dissect_ansi_tcap_T_abort(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
gp_tcapsrt_info->ope=TC_ANSI_ABORT;
col_set_str(actx->pinfo->cinfo, COL_INFO, "Abort ");

  offset = dissect_ansi_tcap_Abort(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_choice_t PackageType_choice[] = {
  {   1, &hf_ansi_tcap_unidirectional, BER_CLASS_PRI, 1, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_unidirectional },
  {   2, &hf_ansi_tcap_queryWithPerm, BER_CLASS_PRI, 2, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_queryWithPerm },
  {   3, &hf_ansi_tcap_queryWithoutPerm, BER_CLASS_PRI, 3, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_queryWithoutPerm },
  {   4, &hf_ansi_tcap_response  , BER_CLASS_PRI, 4, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_response },
  {   5, &hf_ansi_tcap_conversationWithPerm, BER_CLASS_PRI, 5, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_conversationWithPerm },
  {   6, &hf_ansi_tcap_conversationWithoutPerm, BER_CLASS_PRI, 6, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_conversationWithoutPerm },
  {  22, &hf_ansi_tcap_abort     , BER_CLASS_PRI, 22, BER_FLAGS_IMPLTAG, dissect_ansi_tcap_T_abort },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ansi_tcap_PackageType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PackageType_choice, hf_index, ett_ansi_tcap_PackageType,
                                 NULL);

  return offset;
}





static int
dissect_ansi_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    proto_item          *item=NULL;
    proto_tree          *tree=NULL;
#if 0
    proto_item          *stat_item=NULL;
    proto_tree          *stat_tree=NULL;
        int                     offset = 0;
    struct tcaphash_context_t * p_tcap_context;
    dissector_handle_t subdissector_handle;
#endif
        asn1_ctx_t asn1_ctx;

        asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
        ansi_tcap_ctx_init(&ansi_tcap_private);

    asn1_ctx.subtree.top_tree = parent_tree;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ANSI TCAP");

    /* create display subtree for the protocol */
    if(parent_tree){
      item = proto_tree_add_item(parent_tree, proto_ansi_tcap, tvb, 0, -1, ENC_NA);
      tree = proto_item_add_subtree(item, ett_tcap);
    }
    cur_oid = NULL;
    tcapext_oid = NULL;

    gp_tcapsrt_info=tcapsrt_razinfo();
    tcap_subdissector_used=false;
    gp_tcap_context=NULL;
    dissect_ansi_tcap_PackageType(false, tvb, 0, &asn1_ctx, tree, -1);

#if 0 /* Skip this part for now it will be rewritten */
    if (g_ansi_tcap_HandleSRT && !tcap_subdissector_used ) {
                if (gtcap_DisplaySRT && tree) {
                        stat_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_ansi_tcap_stat, &stat_item, "Stat");
                        proto_item_set_generated(stat_item);
                }
                p_tcap_context=tcapsrt_call_matching(tvb, pinfo, stat_tree, gp_tcapsrt_info);
                ansi_tcap_private.context=p_tcap_context;

                /* If the current message is TCAP only,
                 * save the Application context name for the next messages
                 */
                if ( p_tcap_context && cur_oid && !p_tcap_context->oid_present ) {
                        /* Save the application context and the sub dissector */
                        (void) g_strlcpy(p_tcap_context->oid, cur_oid, sizeof(p_tcap_context->oid));
                        if ( (subdissector_handle = dissector_get_string_handle(ber_oid_dissector_table, cur_oid)) ) {
                                p_tcap_context->subdissector_handle=subdissector_handle;
                                p_tcap_context->oid_present=true;
                        }
                }
                if (g_ansi_tcap_HandleSRT && p_tcap_context && p_tcap_context->callback) {
                        /* Callback function for the upper layer */
                        (p_tcap_context->callback)(tvb, pinfo, stat_tree, p_tcap_context);
                }
        }
#endif
    return tvb_captured_length(tvb);
}


void
proto_reg_handoff_ansi_tcap(void)
{
    ansi_map_handle = find_dissector_add_dependency("ansi_map", proto_ansi_tcap);
    ain_handle = find_dissector_add_dependency("ain", proto_ansi_tcap);
    ber_oid_dissector_table = find_dissector_table("ber.oid");
}



void
proto_register_ansi_tcap(void)
{
    module_t    *ansi_tcap_module;


/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
#if 0
        /* Tcap Service Response Time */
        { &hf_ansi_tcapsrt_SessionId,
          { "Session Id",
            "ansi_tcap.srt.session_id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcapsrt_BeginSession,
          { "Begin Session",
            "ansi_tcap.srt.begin",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "SRT Begin of Session", HFILL }
        },
        { &hf_ansi_tcapsrt_EndSession,
          { "End Session",
            "ansi_tcap.srt.end",
            FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "SRT End of Session", HFILL }
        },
        { &hf_ansi_tcapsrt_SessionTime,
          { "Session duration",
            "ansi_tcap.srt.sessiontime",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
            "Duration of the TCAP session", HFILL }
        },
        { &hf_ansi_tcapsrt_Duplicate,
          { "Request Duplicate",
            "ansi_tcap.srt.duplicate",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
#endif
        { &hf_ansi_tcap_bit_h,
          { "Require Reply", "ansi_tcap.req_rep",
            FT_BOOLEAN, 16, NULL, 0x8000,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_op_family,
          { "Family",
            "ansi_tcap.op_family",
            FT_UINT16, BASE_DEC, VALS(ansi_tcap_national_op_code_family_vals), 0x7f00,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_op_specifier,
          { "Specifier",
            "ansi_tcap.op_specifier",
            FT_UINT16, BASE_DEC, NULL, 0x00ff,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_set,
          { "Parameters",
            "ansi_tcap.parameter_set",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_set_start,
          { "Start of Parameters",
            "ansi_tcap.parameter_set_start",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter,
          { "Parameter",
            "ansi_tcap.parameter",
            FT_UINT16, BASE_HEX, VALS(ansi_tcap_parameter_vals), 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_length,
          { "The length of this Parameter set/sequence is",
            "ansi_tcap.parameter_length",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_service_key_identifier,
          { "Service key identifier",
            "ansi_tcap.ansi_tcap_service_key_identifier",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_digit_identifier,
          { "Service key digit identifier",
            "ansi_tcap.ansi_tcap_digit_identifier",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_digit_length,
          { "Service key digit length",
            "ansi_tcap.ansi_tcap_digit_length",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_destination_number_value,
          { "Destination number value",
            "ansi_tcap.ansi_tcap_destination_number_value",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_presentation_restriction,
          { "Presentation restriction indicator",
            "ansi_tcap.ansi_tcap_presentation_restriction",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_encoding_scheme,
          { "Encoding scheme and number planning is",
            "ansi_tcap.ansi_tcap_encoding_scheme",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_number_of_digits,
          { "Amount of digits in this phone number are",
            "ansi_tcap.ansi_tcap_number_of_digits",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_destination_phone_number,
          { "Destination Phone Number",
            "ansi_tcap.destination_phone_number",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_return_phone_number,
          { "Destination Phone Number",
            "ansi_tcap.return_phone_number",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_busy_idle_status,
          { "Status Identifier",
            "ansi_tcap.busy_idle_status",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_status_identifier), 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_originating_restrictions,
          { "Originating Restrictions",
            "ansi_tcap.originating_restrictions",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_originating_restrictions), 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_terminating_restrictions,
          { "Terminating Restrictions",
            "ansi_tcap.terminating_restrictions",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_terminating_restrictions), 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_bearer_capability_supported,
          { "Bearer Capability",
            "ansi_tcap.bearer_capability_supported",
            FT_UINT8, BASE_DEC, VALS(ansi_tcap_bearer_capabilities_supported), 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_reference_id,
          { "Reference ID",
            "ansi_tcap.reference_id",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_timestamp_year,
          { "Year",
            "ansi_tcap.timestamp.year",
            FT_INT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_timestamp_month,
          { "Month",
            "ansi_tcap.timestamp.month",
            FT_INT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_timestamp_day,
          { "Day",
            "ansi_tcap.timestamp.day",
            FT_INT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_timestamp_hour,
          { "Hour",
            "ansi_tcap.timestamp.hour",
            FT_INT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_timestamp_minute,
          { "Minute",
            "ansi_tcap.timestamp.minute",
            FT_INT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_timestamp_difference,
          { "Time Difference",
            "ansi_tcap.timestamp.difference",
            FT_INT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_timestamp_local_hour,
          { "Local Hour",
            "ansi_tcap.timestamp.local_hour",
            FT_INT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_timestamp_local_minute,
          { "Local Minute",
            "ansi_tcap.timestamp.local_minute",
            FT_INT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_call_forwarding_on_busy,
          { "Call Forwarding On Busy",
            "ansi_tcap.call_forwarding_on_busy",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0x30,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_call_forwarding_dont_answer,
          { "Call Forwarding Don't Answer",
            "ansi_tcap.call_forwarding_dont_answer",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0x0C,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_selective_forwarding,
          { "Selective Forwarding",
            "ansi_tcap.selective_forwarding",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_dn_match,
          { "DN Match",
            "ansi_tcap.dn_matc",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_dn_match), 0xC0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_dn_line_service,
          { "DN Line Service",
            "ansi_tcap.dn_line_service",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_dn_service_type), 0x3F,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_duration_hour,
          { "Hour",
            "ansi_tcap.duration.hour",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_duration_minute,
          { "Minute",
            "ansi_tcap.duration.minute",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_duration_second,
          { "Second",
            "ansi_tcap.duration.second",
            FT_INT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_length_spare,
          { "Spare",
            "ansi_tcap.business_group.length_spare",
            FT_UINT8, BASE_HEX, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_length_AttSt,
          { "AttSt",
            "ansi_tcap.business_group.length_AttSt",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_length_BGID,
          { "BGID",
            "ansi_tcap.business_group.length_BGID",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_length_LP11,
          { "LP11",
            "ansi_tcap.business_group.length_LP11",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_length_Party_Selector,
          { "Party Selector",
            "ansi_tcap.business_group.length_Party_Selector",
            FT_UINT8, BASE_HEX, NULL, 0x07,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_id,
          { "Business Group ID",
            "ansi_tcap.business_group.id",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_subgroup_id,
          { "Sub-Group ID",
            "ansi_tcap.business_group.subgroup_id",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_business_group_line_privileges,
          { "Line Privileges",
            "ansi_tcap.business_group.line_privileges",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_signalling_networks_id,
          { "Signalling Networks ID",
            "ansi_tcap.business_group.signalling_networks_id",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_generic_name_type_name,
          { "Generic Name Type",
            "ansi_tcap.generic_name.type_name",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_generic_name_type_of_name), 0xD0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_generic_name_availability,
          { "Generic Name Availability",
            "ansi_tcap.generic_name.availability",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_generic_name_availability), 0x10,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_generic_name_spare,
          { "Generic Name Spare",
            "ansi_tcap.generic_name.type_name_spare",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0x0C,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_generic_name_presentation,
          { "Generic Name Presentation",
            "ansi_tcap.generic_name.type_name_presentation",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_generic_name_presentation_field), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_message_waiting_indicator_type,
          { "Message Waiting Indicator Type",
            "ansi_tcap.message_waiting_indicator_type",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_generic_name_characters,
          { "Name Characters",
            "ansi_tcap.generic_name.characters",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_look_ahead_for_busy_ack_type,
          { "Act. Type",
            "ansi_tcap.look_ahead_for_busy_ack_type",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_look_ahead_for_busy_ack), 0xC0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_look_ahead_for_busy_spare,
          { "Spare",
            "ansi_tcap.look_ahead_for_busy_spare",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_spare), 0x30,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_look_ahead_for_busy_location_field,
          { "Location",
            "ansi_tcap.look_ahead_for_busy_location",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_look_ahead_for_busy_location_field), 0x03,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_acg_control_cause_indicator,
          { "Control Cause Indicator",
            "ansi_tcap.acg_control_cause_indicator",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_control_cause_indication), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_acg_duration_field,
          { "Duration Field",
            "ansi_tcap.acg_duration_field",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_duration_field), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_acg_gap,
          { "Gap",
            "ansi_tcap.acg_gap",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_gap), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_standard_announcement,
          { "Standard Announcement",
            "ansi_tcap.standard_announcement",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_standard_announcements), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_customized_announcement,
          { "Customized Announcement",
            "ansi_tcap.customized_announcement",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits_type_of_digits,
          { "Gap",
            "ansi_tcap.acg_gap",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits_type_of_digits), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits_nature_of_numbers,
          { "Gap",
            "ansi_tcap.acg_gap",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits_nature_of_numbers), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits_number_planning,
          { "Gap",
            "ansi_tcap.digits_number_planning",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits_number_planning), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits_encoding,
          { "Gap",
            "ansi_tcap.digits_number_planning",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits_encoding), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits_number_of_digits,
          { "Gap",
            "ansi_tcap.digits_number_planning",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits_number_of_digits), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_digits,
          { "Gap",
            "ansi_tcap.digits_number_planning",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_digits), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_standard_user_error_code,
          { "User Error Code",
            "ansi_tcap.standard_user_error_code",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_standard_user_error_code), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_sccp_calling_party_address,
          { "SCCP Calling Party Address",
            "ansi_tcap.sccp_calling_party_address",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_transaction_id,
          { "Transaction ID",
            "ansi_tcap.transaction_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_package_type,
          { "Package Type",
            "ansi_tcap.package_type",
            FT_UINT8, BASE_DEC, VALS(ansi_tcap_package_types), 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_returned_data,
          { "Returned Data",
            "ansi_tcap.returned_data",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_CIC_lsb,
          { "CIC Least Significant Bits",
            "ansi_tcap.CIC_lsb",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_CIC_spare,
          { "CIC Spare",
            "ansi_tcap.CIC_spare",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_CIC_msb,
          { "CIC Most Significant Bits",
            "ansi_tcap.CIC_msb",
            FT_UINT8, BASE_HEX, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_precedence_level_spare,
          { "Precedence Level Spare",
            "ansi_tcap.precedence_level_spare",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_precedence_level,
          { "Precedence Level",
            "ansi_tcap.precedence_level",
            FT_UINT8, BASE_HEX, VALS(ansi_tcap_national_parameter_level), 0x0F,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_precedence_id1,
          { "NI digit #1",
            "ansi_tcap.precedence_id1",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_precedence_id2,
          { "NI digit #2",
            "ansi_tcap.precedence_id2",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_precedence_id3,
          { "NI digit #3",
            "ansi_tcap.precedence_id3",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_precedence_id4,
          { "NI digit #4",
            "ansi_tcap.precedence_id4",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_precedence_mlpp_service_domain,
          { "MLPP Service Domain",
            "ansi_tcap.precedence_mlpp_service_domain",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_reference_id_call_identify,
          { "Call Identify",
            "ansi_tcap.reference_id.call_identify",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_reference_id_point_code,
          { "Point Code",
            "ansi_tcap.reference_id.point_code",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_parameter_authorization,
          { "Authorization",
            "ansi_tcap.authorization",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_integrity_algid_id,
          { "Integrity AlgID ID",
            "ansi_tcap.integrity.algid_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_integrity_algid,
          { "Integrity AlgID",
            "ansi_tcap.integrity.algid",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_integrity_value_id,
          { "Integrity Value AlgID ID",
            "ansi_tcap.integrity.value_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_integrity_value,
          { "Integrity Value AlgID",
            "ansi_tcap.integrity.value",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_sequence_number,
          { "Sequence Number",
            "ansi_tcap.sequence_number",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_num_messages,
          { "Number of Messages",
            "ansi_tcap.num_messages",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_display_text,
          { "Display Text",
            "ansi_tcap.display_text",
            FT_UINT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_key_exchange_algid_id,
          { "Key Exchange AlgID ID",
            "ansi_tcap.key_exchange.algid_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_key_exchange_algid,
          { "Key Exchange AlgID",
            "ansi_tcap.key_exchange.algid",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_key_exchange_value_id,
          { "Key Exchange Value AlgID ID",
            "ansi_tcap.key_exchange.value_id",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ansi_tcap_key_exchange_value,
          { "Key Exchange Value AlgID",
            "ansi_tcap.key_exchange.value",
            FT_UINT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

    { &hf_ansi_tcap_national,
      { "national", "ansi_tcap.national",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_private,
      { "private", "ansi_tcap.private",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_national_01,
      { "national", "ansi_tcap.national",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_ansi_tcap_ec_private,
      { "private", "ansi_tcap.ec_private",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_ANSIMAPPrivateErrorcode_vals), 0,
        "ANSIMAPPrivateErrorcode", HFILL }},
    { &hf_ansi_tcap_unidirectional,
      { "unidirectional", "ansi_tcap.unidirectional_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_queryWithPerm,
      { "queryWithPerm", "ansi_tcap.queryWithPerm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_queryWithoutPerm,
      { "queryWithoutPerm", "ansi_tcap.queryWithoutPerm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_response,
      { "response", "ansi_tcap.response_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_conversationWithPerm,
      { "conversationWithPerm", "ansi_tcap.conversationWithPerm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_conversationWithoutPerm,
      { "conversationWithoutPerm", "ansi_tcap.conversationWithoutPerm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_abort,
      { "abort", "ansi_tcap.abort_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_identifier,
      { "identifier", "ansi_tcap.identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TransactionID", HFILL }},
    { &hf_ansi_tcap_dialoguePortion,
      { "dialoguePortion", "ansi_tcap.dialoguePortion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_componentPortion,
      { "componentPortion", "ansi_tcap.componentPortion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ComponentSequence", HFILL }},
    { &hf_ansi_tcap_dialogPortion,
      { "dialogPortion", "ansi_tcap.dialogPortion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DialoguePortion", HFILL }},
    { &hf_ansi_tcap_causeInformation,
      { "causeInformation", "ansi_tcap.causeInformation",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_causeInformation_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_abortCause,
      { "abortCause", "ansi_tcap.abortCause",
        FT_INT32, BASE_DEC, VALS(ansi_tcap_P_Abort_cause_U_vals), 0,
        "P_Abort_cause", HFILL }},
    { &hf_ansi_tcap_abort_userInformation,
      { "userInformation", "ansi_tcap.abort_userInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserAbortInformation", HFILL }},
    { &hf_ansi_tcap_version,
      { "version", "ansi_tcap.version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ProtocolVersion", HFILL }},
    { &hf_ansi_tcap_applicationContext,
      { "applicationContext", "ansi_tcap.applicationContext",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_applicationContext_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_integerApplicationId,
      { "integerApplicationId", "ansi_tcap.integerApplicationId",
        FT_INT32, BASE_DEC, NULL, 0,
        "IntegerApplicationContext", HFILL }},
    { &hf_ansi_tcap_objectApplicationId,
      { "objectApplicationId", "ansi_tcap.objectApplicationId",
        FT_OID, BASE_NONE, NULL, 0,
        "ObjectIDApplicationContext", HFILL }},
    { &hf_ansi_tcap_userInformation,
      { "userInformation", "ansi_tcap.userInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_securityContext,
      { "securityContext", "ansi_tcap.securityContext",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_securityContext_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_integerSecurityId,
      { "integerSecurityId", "ansi_tcap.integerSecurityId",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ansi_tcap_objectSecurityId,
      { "objectSecurityId", "ansi_tcap.objectSecurityId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ansi_tcap_confidentiality,
      { "confidentiality", "ansi_tcap.confidentiality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap__untag_item,
      { "_untag item", "ansi_tcap._untag_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_ansi_tcap_confidentialityId,
      { "confidentialityId", "ansi_tcap.confidentialityId",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_confidentialityId_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_integerConfidentialityId,
      { "integerConfidentialityId", "ansi_tcap.integerConfidentialityId",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ansi_tcap_objectConfidentialityId,
      { "objectConfidentialityId", "ansi_tcap.objectConfidentialityId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ansi_tcap__untag_item_01,
      { "ComponentPDU", "ansi_tcap.ComponentPDU",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_ComponentPDU_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_invokeLast,
      { "invokeLast", "ansi_tcap.invokeLast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Invoke", HFILL }},
    { &hf_ansi_tcap_returnResultLast,
      { "returnResultLast", "ansi_tcap.returnResultLast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult", HFILL }},
    { &hf_ansi_tcap_returnError,
      { "returnError", "ansi_tcap.returnError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_reject,
      { "reject", "ansi_tcap.reject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_invokeNotLast,
      { "invokeNotLast", "ansi_tcap.invokeNotLast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Invoke", HFILL }},
    { &hf_ansi_tcap_returnResultNotLast,
      { "returnResultNotLast", "ansi_tcap.returnResultNotLast_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult", HFILL }},
    { &hf_ansi_tcap_componentIDs,
      { "componentIDs", "ansi_tcap.componentIDs",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_operationCode,
      { "operationCode", "ansi_tcap.operationCode",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_OperationCode_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_invoke_parameter,
      { "parameter", "ansi_tcap.invoke_parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_invoke_parameter", HFILL }},
    { &hf_ansi_tcap_componentID,
      { "componentID", "ansi_tcap.componentID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_returnResult_parameter,
      { "parameter", "ansi_tcap.returnResult_parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_returnResult_parameter", HFILL }},
    { &hf_ansi_tcap_componentID_01,
      { "componentID", "ansi_tcap.componentID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_componentID_01", HFILL }},
    { &hf_ansi_tcap_errorCode,
      { "errorCode", "ansi_tcap.errorCode",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_ErrorCode_vals), 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_returnError_parameter,
      { "parameter", "ansi_tcap.returnError_parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_returnError_parameter", HFILL }},
    { &hf_ansi_tcap_componentID_02,
      { "componentID", "ansi_tcap.componentID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_1", HFILL }},
    { &hf_ansi_tcap_rejectProblem,
      { "rejectProblem", "ansi_tcap.rejectProblem",
        FT_INT32, BASE_DEC, VALS(ansi_tcap_Problem_vals), 0,
        "Problem", HFILL }},
    { &hf_ansi_tcap_reject_parameter,
      { "parameter", "ansi_tcap.reject_parameter",
        FT_UINT32, BASE_DEC, VALS(ansi_tcap_T_reject_parameter_vals), 0,
        "T_reject_parameter", HFILL }},
    { &hf_ansi_tcap_paramSequence,
      { "paramSequence", "ansi_tcap.paramSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ansi_tcap_paramSet,
      { "paramSet", "ansi_tcap.paramSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    };

/* Setup protocol subtree array */
    static int *ett[] = {
        &ett_tcap,
        &ett_param,
        &ett_otid,
        &ett_dtid,
        &ett_ansi_tcap_stat,
        &ett_ansi_tcap_op_code_nat,
        &ett_ansi_tcap_stat_timestamp,
        &ett_ansi_tcap_duration,
    &ett_ansi_tcap_OperationCode,
    &ett_ansi_tcap_ErrorCode,
    &ett_ansi_tcap_PackageType,
    &ett_ansi_tcap_UniTransactionPDU,
    &ett_ansi_tcap_TransactionPDU,
    &ett_ansi_tcap_Abort,
    &ett_ansi_tcap_T_causeInformation,
    &ett_ansi_tcap_DialoguePortion_U,
    &ett_ansi_tcap_T_applicationContext,
    &ett_ansi_tcap_T_securityContext,
    &ett_ansi_tcap_UserInformation_U,
    &ett_ansi_tcap_Confidentiality,
    &ett_ansi_tcap_T_confidentialityId,
    &ett_ansi_tcap_SEQUENCE_OF_ComponentPDU,
    &ett_ansi_tcap_ComponentPDU,
    &ett_ansi_tcap_Invoke,
    &ett_ansi_tcap_ReturnResult,
    &ett_ansi_tcap_ReturnError,
    &ett_ansi_tcap_Reject,
    &ett_ansi_tcap_T_reject_parameter,
    &ett_ansi_tcap_T_paramSequence,
    &ett_ansi_tcap_T_paramSet,
    };

    static ei_register_info ei[] = {
        { &ei_ansi_tcap_dissector_not_implemented, { "ansi_tcap.dissector_not_implemented", PI_UNDECODED, PI_WARN, "Dissector not implemented", EXPFILL }},
    };

    expert_module_t* expert_ansi_tcap;

    static const enum_val_t ansi_tcap_response_matching_type_values[] = {
        {"tid",                  "Transaction ID only", ANSI_TCAP_TID_ONLY},
        {"tid_source",           "Transaction ID and Source", ANSI_TCAP_TID_AND_SOURCE},
        {"tid_source_dest",      "Transaction ID Source and Destination", ANSI_TCAP_TID_SOURCE_AND_DEST},
        {NULL, NULL, -1}
    };

/* Register the protocol name and description */
    proto_ansi_tcap = proto_register_protocol(PNAME, PSNAME, PFNAME);
    register_dissector("ansi_tcap", dissect_ansi_tcap, proto_ansi_tcap);

   /* Note the high bit should be masked off when registering in this table (0x7fff)*/
   ansi_tcap_national_opcode_table = register_dissector_table("ansi_tcap.nat.opcode", "ANSI TCAP National Opcodes", proto_ansi_tcap, FT_UINT16, BASE_DEC);
/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_tcap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_ansi_tcap = expert_register_protocol(proto_ansi_tcap);
    expert_register_field_array(expert_ansi_tcap, ei, array_length(ei));

    ansi_tcap_module = prefs_register_protocol(proto_ansi_tcap, proto_reg_handoff_ansi_tcap);

    prefs_register_enum_preference(ansi_tcap_module, "transaction.matchtype",
                                   "Type of matching invoke/response",
                                   "Type of matching invoke/response, risk of mismatch if loose matching chosen",
                                   &ansi_tcap_response_matching_type, ansi_tcap_response_matching_type_values, false);

    TransactionId_table = wmem_multimap_new_autoreset(wmem_epan_scope(), wmem_file_scope(), wmem_str_hash, g_str_equal);
}
