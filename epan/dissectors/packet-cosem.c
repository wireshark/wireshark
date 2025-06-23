/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-cosem.c                                                             */
/* asn2wrs.py -b -C -q -L -p cosem -c ./cosem.cnf -s ./packet-cosem-template -D . -O ../.. cosem.asn */

/* packet-cosem.c
 *
 * Based on the dissector
 * dlms.c - Device Language Message Specification dissector
 * Copyright (C) 2018 Andre B. Oliveira
 * https://github.com/bearxiong99/wireshark-dlms/tree/master
 *
 * Modified by adding asn1 generated parts and other enhancements
 * Routines for IEC 62 056 DLMS/COSEM dissection
 * Copyright 2024, Anders Broman <a.broman58[at]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <wsutil/array.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/tfs.h>

#include "packet-ber.h"
#include "packet-x509if.h"

#define PNAME  "DLMS/COSEM"
#define PSNAME "COSEM"
#define PFNAME "cosem"

void proto_register_cosem(void);
void proto_reg_handoff_cosem(void);

/* Initialize the protocol and registered fields */
static int proto_cosem;

static int hf_cosem_AARQ_apdu_PDU;                /* AARQ_apdu */
static int hf_cosem_AARE_apdu_PDU;                /* AARE_apdu */
static int hf_cosem_RLRQ_apdu_PDU;                /* RLRQ_apdu */
static int hf_cosem_RLRE_apdu_PDU;                /* RLRE_apdu */
static int hf_cosem_Conformance_PDU;              /* Conformance */
static int hf_cosem_protocol_version;             /* T_protocol_version */
static int hf_cosem_application_context_name;     /* Application_context_name */
static int hf_cosem_called_AP_title;              /* AP_title */
static int hf_cosem_called_AE_qualifier;          /* AE_qualifier */
static int hf_cosem_called_AP_invocation_identifier;  /* AP_invocation_identifier */
static int hf_cosem_called_AE_invocation_identifier;  /* AE_invocation_identifier */
static int hf_cosem_calling_AP_title;             /* AP_title */
static int hf_cosem_calling_AE_qualifier;         /* AE_qualifier */
static int hf_cosem_calling_AP_invocation_identifier;  /* AP_invocation_identifier */
static int hf_cosem_calling_AE_invocation_identifier;  /* AE_invocation_identifier */
static int hf_cosem_sender_acse_requirements;     /* ACSE_requirements */
static int hf_cosem_mechanism_name;               /* Mechanism_name */
static int hf_cosem_calling_authentication_value;  /* Authentication_value */
static int hf_cosem_implementation_information;   /* Implementation_data */
static int hf_cosem_user_information;             /* Association_information */
static int hf_cosem_protocol_version_01;          /* T_protocol_version_01 */
static int hf_cosem_aSO_context_name;             /* Application_context_name */
static int hf_cosem_result;                       /* Association_result */
static int hf_cosem_result_source_diagnostic;     /* Associate_source_diagnostic */
static int hf_cosem_responding_AP_title;          /* AP_title */
static int hf_cosem_responding_AE_qualifier;      /* AE_qualifier */
static int hf_cosem_responding_AP_invocation_identifier;  /* AP_invocation_identifier */
static int hf_cosem_responding_AE_invocation_identifier;  /* AE_invocation_identifier */
static int hf_cosem_responder_acse_requirements;  /* ACSE_requirements */
static int hf_cosem_responding_authentication_value;  /* Authentication_value */
static int hf_cosem_reason;                       /* Release_request_reason */
static int hf_cosem_reason_01;                    /* Release_response_reason */
static int hf_cosem_ap_title_form1;               /* AP_title_form1 */
static int hf_cosem_ap_title_form2;               /* AP_title_form2 */
static int hf_cosem_ap_title_form3;               /* AP_title_form3 */
static int hf_cosem_aso_qualifier_form1;          /* ASO_qualifier_form1 */
static int hf_cosem_aso_qualifier_form2;          /* ASO_qualifier_form2 */
static int hf_cosem_aso_qualifier_form3;          /* ASO_qualifier_form3 */
static int hf_cosem_aso_qualifier_form_any_octets;  /* ASO_qualifier_form_octets */
static int hf_cosem_other_mechanism_name;         /* OBJECT_IDENTIFIER */
static int hf_cosem_other_mechanism_value;        /* T_other_mechanism_value */
static int hf_cosem_charstring;                   /* GraphicString */
static int hf_cosem_bitstring;                    /* BIT_STRING */
static int hf_cosem_external;                     /* EXTERNALt */
static int hf_cosem_other;                        /* Authentication_value_other */
static int hf_cosem_direct_reference;             /* OBJECT_IDENTIFIER */
static int hf_cosem_indirect_reference;           /* INTEGER */
static int hf_cosem_data_value_descriptor;        /* ObjectDescriptor */
static int hf_cosem_encoding;                     /* T_encoding */
static int hf_cosem_single_ASN1_type;             /* OCTET_STRING */
static int hf_cosem_octet_aligned;                /* OCTET_STRING */
static int hf_cosem_arbitrary;                    /* BIT_STRING */
static int hf_cosem_acse_service_user;            /* T_acse_service_user */
static int hf_cosem_acse_service_provider;        /* T_acse_service_provider */
/* named bits */
static int hf_cosem_T_protocol_version_version1;
static int hf_cosem_T_protocol_version_01_version1;
static int hf_cosem_ACSE_requirements_authentication;
static int hf_cosem_ACSE_requirements_aSO_context_negotiation;
static int hf_cosem_ACSE_requirements_higher_level_association;
static int hf_cosem_ACSE_requirements_nested_association;
static int hf_cosem_Conformance_U_reserved0;
static int hf_cosem_Conformance_U_reserved1;
static int hf_cosem_Conformance_U_reserved2;
static int hf_cosem_Conformance_U_read;
static int hf_cosem_Conformance_U_write;
static int hf_cosem_Conformance_U_unconfirmed_write;
static int hf_cosem_Conformance_U_reserved6;
static int hf_cosem_Conformance_U_reserved7;
static int hf_cosem_Conformance_U_attribute0_supported_with_SET;
static int hf_cosem_Conformance_U_priority_mgmt_supported;
static int hf_cosem_Conformance_U_attribute0_supported_with_GET;
static int hf_cosem_Conformance_U_block_transfer_with_get;
static int hf_cosem_Conformance_U_block_transfer_with_set;
static int hf_cosem_Conformance_U_block_transfer_with_action;
static int hf_cosem_Conformance_U_multiple_references;
static int hf_cosem_Conformance_U_information_report;
static int hf_cosem_Conformance_U_reserved16;
static int hf_cosem_Conformance_U_reserved17;
static int hf_cosem_Conformance_U_parameterized_access;
static int hf_cosem_Conformance_U_get;
static int hf_cosem_Conformance_U_set;
static int hf_cosem_Conformance_U_selective_access;
static int hf_cosem_Conformance_U_event_notification;
static int hf_cosem_Conformance_U_action;

/* Initialize the subtree pointers */
static int ett_cosem;
static int ett_cosem_AARQ_apdu_U;
static int ett_cosem_T_protocol_version;
static int ett_cosem_AARE_apdu_U;
static int ett_cosem_T_protocol_version_01;
static int ett_cosem_RLRQ_apdu_U;
static int ett_cosem_RLRE_apdu_U;
static int ett_cosem_ACSE_requirements;
static int ett_cosem_AP_title;
static int ett_cosem_ASO_qualifier;
static int ett_cosem_Authentication_value_other;
static int ett_cosem_Authentication_value;
static int ett_cosem_EXTERNALt_U;
static int ett_cosem_T_encoding;
static int ett_cosem_Associate_source_diagnostic;
static int ett_cosem_Conformance_U;


/*
 * obis.h - OBIS (OBject Identification System) code names
 */

static const val64_string obis_code_names[] = {

    /* Application-independent OBIS codes and names */
    { 0x0000010000ff, "Clock" },

    { 0x0000280000ff, "Current association" },
    { 0x0000290000ff, "SAP assignment" },
    { 0x00002a0000ff, "COSEM logical device name" },

    /* Add your application-specific OBIS codes and names here */
    { 0x0000636207ff, "Event log 8" },

    /* Terminating entry (do not delete) */
    { 0, NULL }
};

/* Forward declaration */
static void dlms_dissect_apdu(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* parent_tree, int offset);

static int proto_dlms;
static int hf_dlms_hdlc_flag;
static int hf_dlms_hdlc_type;
static int hf_dlms_hdlc_segmentation;
static int hf_dlms_hdlc_length; /* frame format length sub-field */
static int hf_dlms_hdlc_address; /* destination/source address */
static int hf_dlms_hdlc_frame_i; /* control field & 0x01 (I) */
static int hf_dlms_hdlc_frame_rr_rnr; /* control field & 0x0f (RR or RNR) */
static int hf_dlms_hdlc_frame_other; /* control field & 0xef (all other) */
static int hf_dlms_hdlc_pf; /* poll/final bit */
static int hf_dlms_hdlc_rsn; /* receive sequence number N(R) */
static int hf_dlms_hdlc_ssn; /* send sequence number N(S) */
static int hf_dlms_hdlc_hcs; /* header check sequence */
static int hf_dlms_hdlc_fcs; /* frame check sequence */
static int hf_dlms_hdlc_parameter; /* information field parameter */
static int hf_dlms_hdlc_llc; /* LLC header */
static int hf_dlms_iec432llc;
static int hf_dlms_wrapper;

static int hf_dlms_apdu;
static int hf_dlms_client_max_receive_pdu_size;
static int hf_dlms_server_max_receive_pdu_size;
static int hf_dlms_get_request;
static int hf_dlms_set_request;
static int hf_dlms_action_request;
static int hf_dlms_get_response;
static int hf_dlms_set_response;
static int hf_dlms_action_response;
static int hf_dlms_access_request;
static int hf_dlms_access_response;


static int hf_dlms_class_id;
static int hf_dlms_instance_id;
static int hf_dlms_attribute_id;
static int hf_dlms_method_id;
static int hf_dlms_access_selector;
static int hf_dlms_data_access_result;
static int hf_dlms_block_number;
static int hf_dlms_last_block;
static int hf_dlms_type_description;
static int hf_dlms_action_result;
static int hf_dlms_date_time;
static int hf_dlms_data;
static int hf_dlms_length;
static int hf_dlms_state_error;
static int hf_dlms_service_error;

static int hf_dlms_invoke_id;
static int hf_dlms_service_class;
static int hf_dlms_priority;
static int hf_dlms_long_invoke_id;
static int hf_dlms_self_descriptive;
static int hf_dlms_processing_option;
static int hf_dlms_long_service_class;
static int hf_dlms_long_priority;

static int hf_dlms_fragments;
static int hf_dlms_fragment;
static int hf_dlms_fragment_overlap;
static int hf_dlms_fragment_conflict;
static int hf_dlms_fragment_multiple_tails;
static int hf_dlms_fragment_too_long;
static int hf_dlms_fragment_error;
static int hf_dlms_fragment_count;
static int hf_dlms_reassembled_in;
static int hf_dlms_reassembled_length;
static int hf_dlms_reassembled_data;
static int hf_dlms_dedicated_key;
static int hf_dlms_response_allowed;
static int hf_dlms_proposed_quality_of_service;
static int hf_dlms_proposed_dlms_version_number;
static int hf_dlms_negotiated_quality_of_service;
static int hf_dlms_negotiated_dlms_version_number;
static int hf_dlms_object_name;

static int ett_dlms;
static int ett_dlms_hdlc;

static int ett_dlms_hdlc_format;
static int ett_dlms_hdlc_address;
static int ett_dlms_hdlc_control;
static int ett_dlms_hdlc_information;
static int ett_dlms_invoke_id_and_priority;
static int ett_dlms_access_request_specification;
static int ett_dlms_access_request;
static int ett_dlms_access_response_specification;
static int ett_dlms_access_response;
static int ett_dlms_cosem_attribute_or_method_descriptor;
static int ett_dlms_selective_access_descriptor;
static int ett_dlms_composite_data;
static int ett_dlms_user_information; /* AARQ and AARE user-information field */
static int ett_dlms_conformance; /* InitiateRequest proposed-conformance and InitiateResponse negotiated-confirmance */
static int ett_dlms_datablock;
static int ett_dlms_data;
/* fragment_items */
static int ett_dlms_fragment;
static int ett_dlms_fragments;

static expert_field ei_dlms_no_success;
static expert_field ei_dlms_not_implemented;
static expert_field ei_dlms_check_sequence;

static dissector_handle_t cosem_handle;
static dissector_handle_t dlms_handle;
static dissector_handle_t acse_handle;

/* Choice values for the currently supported ACSE and xDLMS APDUs */
#define DLMS_INITIATE_REQUEST 1
#define DLMS_READ_REQUEST 5
#define DLMS_WRITE_REQUEST 6
#define DLMS_INITIATE_RESPONSE 8
#define DLMS_READ_RESPONSE 12
#define DLMS_WRITE_RESPONSE 13
#define DLMS_CONFIRMED_SERVICE_ERROR 14
#define DLMS_UNCONFIRMED_WRITE_REQUEST 22
#define DLMS_INFORMATION_REPORT_REQUEST 24


#define DLMS_DATA_NOTIFICATION 15
#define DLMS_AARQ 96
#define DLMS_AARE 97
#define DLMS_RLRQ 98
#define DLMS_RLRE 99
#define DLMS_GET_REQUEST 192
#define DLMS_SET_REQUEST 193
#define DLMS_EVENT_NOTIFICATION_REQUEST 194
#define DLMS_ACTION_REQUEST 195
#define DLMS_GET_RESPONSE 196
#define DLMS_SET_RESPONSE 197
#define DLMS_ACTION_RESPONSE 199
#define DLMS_EXCEPTION_RESPONSE 216
#define DLMS_ACCESS_REQUEST 217
#define DLMS_ACCESS_RESPONSE 218

static const value_string dlms_apdu_names[] = {
    { DLMS_INITIATE_REQUEST, "InitiateRequest" },
    { DLMS_READ_REQUEST, "ReadRequest" },
    { DLMS_DATA_NOTIFICATION, "data-notification" },
    { DLMS_AARQ, "aarq" },
    { DLMS_AARE, "aare" },
    { DLMS_RLRQ, "rlrq" },
    { DLMS_RLRE, "rlre" },
    { DLMS_GET_REQUEST, "get-request" },
    { DLMS_SET_REQUEST, "set-request" },
    { DLMS_EVENT_NOTIFICATION_REQUEST, "event-notification-request" },
    { DLMS_ACTION_REQUEST, "action-request" },
    { DLMS_GET_RESPONSE, "get-response" },
    { DLMS_SET_RESPONSE, "set-response" },
    { DLMS_ACTION_RESPONSE, "action-response" },
    { DLMS_EXCEPTION_RESPONSE, "exception-response" },
    { DLMS_ACCESS_REQUEST, "access-request" },
    { DLMS_ACCESS_RESPONSE, "access-response" },
    {0, NULL}
};

/* Choice values for a Get-Request */
#define DLMS_GET_REQUEST_NORMAL 1
#define DLMS_GET_REQUEST_NEXT 2
#define DLMS_GET_REQUEST_WITH_LIST 3
static const value_string dlms_get_request_names[] = {
    { DLMS_GET_REQUEST_NORMAL, "get-request-normal" },
    { DLMS_GET_REQUEST_NEXT, "get-request-next" },
    { DLMS_GET_REQUEST_WITH_LIST, "get-request-with-list" },
    {0, NULL}
};


/* Choice values for a Get-Response */
#define DLMS_GET_RESPONSE_NORMAL 1
#define DLMS_GET_RESPONSE_WITH_DATABLOCK 2
#define DLMS_GET_RESPONSE_WITH_LIST 3
static const value_string dlms_get_response_names[] = {
    { DLMS_GET_RESPONSE_NORMAL, "get-response-normal" },
    { DLMS_GET_RESPONSE_WITH_DATABLOCK, "get-response-with-datablock" },
    { DLMS_GET_RESPONSE_WITH_LIST, "get-response-with-list" },
    {0, NULL}
};

/* Choice values for a Set-Request */
#define DLMS_SET_REQUEST_NORMAL 1
#define DLMS_SET_REQUEST_WITH_FIRST_DATABLOCK 2
#define DLMS_SET_REQUEST_WITH_DATABLOCK 3
#define DLMS_SET_REQUEST_WITH_LIST 4
#define DLMS_SET_REQUEST_WITH_LIST_AND_FIRST_DATABLOCK 5
static const value_string dlms_set_request_names[] = {
    { DLMS_SET_REQUEST_NORMAL, "set-request-normal" },
    { DLMS_SET_REQUEST_WITH_FIRST_DATABLOCK, "set-request-with-first-datablock" },
    { DLMS_SET_REQUEST_WITH_DATABLOCK, "set-request-with-datablock" },
    { DLMS_SET_REQUEST_WITH_LIST, "set-request-with-list" },
    { DLMS_SET_REQUEST_WITH_LIST_AND_FIRST_DATABLOCK, "set-request-with-list-and-first-datablock" },
    {0, NULL}
};

/* Choice values for a Set-Response */
#define DLMS_SET_RESPONSE_NORMAL 1
#define DLMS_SET_RESPONSE_DATABLOCK 2
#define DLMS_SET_RESPONSE_LAST_DATABLOCK 3
#define DLMS_SET_RESPONSE_LAST_DATABLOCK_WITH_LIST 4
#define DLMS_SET_RESPONSE_WITH_LIST 5
static const value_string dlms_set_response_names[] = {
    { DLMS_SET_RESPONSE_NORMAL, "set-response-normal" },
    { DLMS_SET_RESPONSE_DATABLOCK, "set-response-datablock" },
    { DLMS_SET_RESPONSE_LAST_DATABLOCK, "set-response-last-datablock" },
    { DLMS_SET_RESPONSE_LAST_DATABLOCK_WITH_LIST, "set-response-last-datablock-with-list" },
    { DLMS_SET_RESPONSE_WITH_LIST, "set-response-with-list" },
    {0, NULL}
};

/* Choice values for an Action-Request */
#define DLMS_ACTION_REQUEST_NORMAL 1
#define DLMS_ACTION_REQUEST_NEXT_PBLOCK 2
#define DLMS_ACTION_REQUEST_WITH_LIST 3
#define DLMS_ACTION_REQUEST_WITH_FIRST_PBLOCK 4
#define DLMS_ACTION_REQUEST_WITH_LIST_AND_FIRST_PBLOCK 5
#define DLMS_ACTION_REQUEST_WITH_PBLOCK 6
static const value_string dlms_action_request_names[] = {
    { DLMS_ACTION_REQUEST_NORMAL, "action-request-normal" },
    { DLMS_ACTION_REQUEST_NEXT_PBLOCK, "action-request-next-pblock" },
    { DLMS_ACTION_REQUEST_WITH_LIST, "action-request-with-list" },
    { DLMS_ACTION_REQUEST_WITH_FIRST_PBLOCK, "action-request-with-first-pblock" },
    { DLMS_ACTION_REQUEST_WITH_LIST_AND_FIRST_PBLOCK, "action-request-with-list-and-first-pblock" },
    { DLMS_ACTION_REQUEST_WITH_PBLOCK, "action-request-with-pblock" },
    {0, NULL}
};

/* Choice values for an Action-Response */
#define DLMS_ACTION_RESPONSE_NORMAL 1
#define DLMS_ACTION_RESPONSE_WITH_PBLOCK 2
#define DLMS_ACTION_RESPONSE_WITH_LIST 3
#define DLMS_ACTION_RESPONSE_NEXT_PBLOCK 4
static const value_string dlms_action_response_names[] = {
    { DLMS_ACTION_RESPONSE_NORMAL, "action-response-normal" },
    { DLMS_ACTION_RESPONSE_WITH_PBLOCK, "action-response-with-pblock" },
    { DLMS_ACTION_RESPONSE_WITH_LIST, "action-response-with-list" },
    { DLMS_ACTION_RESPONSE_NEXT_PBLOCK, "action-response-next-pblock" },
    {0, NULL},
};

/* Choice values for an Access-Request-Specification */
#define DLMS_ACCESS_REQUEST_GET 1
#define DLMS_ACCESS_REQUEST_SET 2
#define DLMS_ACCESS_REQUEST_ACTION 3
#define DLMS_ACCESS_REQUEST_GET_WITH_SELECTION 4
#define DLMS_ACCESS_REQUEST_SET_WITH_SELECTION 5
static const value_string dlms_access_request_names[] = {
    { DLMS_ACCESS_REQUEST_GET, "access-request-get" },
    { DLMS_ACCESS_REQUEST_SET, "access-request-set" },
    { DLMS_ACCESS_REQUEST_ACTION, "access-request-action" },
    { DLMS_ACCESS_REQUEST_GET_WITH_SELECTION, "access-request-get-with-selection" },
    { DLMS_ACCESS_REQUEST_SET_WITH_SELECTION, "access-request-set-with-selection" },
    {0, NULL},
};

/* Choice values for an Access-Response-Specification */
static const value_string dlms_access_response_names[] = {
    { 1, "access-response-get" },
    { 2, "access-response-set" },
    { 3, "access-response-action" },
    {0, NULL},
};

/* Enumerated values for a Data-Access-Result */
static const value_string dlms_data_access_result_names[] = {
    { 0, "success" },
    { 1, "hardware-fault" },
    { 2, "temporary-failure" },
    { 3, "read-write-denied" },
    { 4, "object-undefined" },
    { 9, "object-class-inconsistent" },
    { 11, "object-unavailable" },
    { 12, "type-unmatched" },
    { 13, "scope-of-access-violated" },
    { 14, "data-block-unavailable" },
    { 15, "long-get-aborted" },
    { 16, "no-long-get-in-progress" },
    { 17, "long-set-aborted" },
    { 18, "no-long-set-in-progress" },
    { 19, "data-block-number-invalid" },
    { 250, "other-reason" },
    {0, NULL}
};

/* Enumerated values for an Action-Result */
static const value_string dlms_action_result_names[] = {
    { 0, "success" },
    { 1, "hardware-fault" },
    { 2, "temporary-failure" },
    { 3, "read-write-denied" },
    { 4, "object-undefined" },
    { 9, "object-class-inconsistent" },
    { 11, "object-unavailable" },
    { 12, "type-unmatched" },
    { 13, "scope-of-access-violated" },
    { 14, "data-block-unavailable" },
    { 15, "long-action-aborted" },
    { 16, "no-long-action-in-progress" },
    { 250, "other-reason" },
    {0, NULL}
};

/* Enumerated values for a state-error in an Exception-Response */
static const value_string dlms_state_error_names[] = {
    { 1, "service-not-allowed" },
    { 2, "service-unknown" },
    {0, NULL}
};

/* Enumerated values for a service-error in an Exception-Response */
static const value_string dlms_service_error_names[] = {
    { 1, "operation-not-possible" },
    { 2, "service-not-supported" },
    { 3, "other-reason" },
    {0, NULL}
};

/* Names of the values of the self-descriptive bit in the Long-Invoke-Id-And-Priority */
static const value_string dlms_self_descriptive_names[] = {
    { 0, "not-self-descriptive" },
    { 1, "self-descriptive" },
    {0, NULL}
};

/* Names of the values of the processing-option bit in the Long-Invoke-Id-And-Priority */
static const value_string dlms_processing_option_names[] = {
    { 0, "continue-on-error" },
    { 1, "break-on-error" },
    {0, NULL}
};


#define DLMS_PORT 4059

/* HDLC frame names for the control field values (with the RRR, P/F, and SSS bits masked off) */
static const value_string dlms_hdlc_frame_names[] = {
    { 0x00, "I (Information)" },
    { 0x01, "RR (Receive Ready)" },
    { 0x03, "UI (Unnumbered Information)" },
    { 0x05, "RNR (Receive Not Ready)" },
    { 0x0f, "DM (Disconnected Mode)" },
    { 0x43, "DISC (Disconnect)" },
    { 0x63, "UA (Unnumbered Acknowledge)" },
    { 0x83, "SNRM (Set Normal Response Mode)" },
    { 0x87, "FRMR (Frame Reject)" },
    { 0, NULL }
};


/* Structure with the names of a DLMS/COSEM class */
struct dlms_cosem_class {
    const char* name;
    const char* attributes[18]; /* index 0 is attribute 2 (attribute 1 is always "logical_name") */
    const char* methods[11]; /* index 0 is method 1 */
};
typedef struct dlms_cosem_class dlms_cosem_class;

/* Get the DLMS/COSEM class with the specified class_id */
static const dlms_cosem_class*
dlms_get_class(int class_id) {
    const short ids[] = {
        1, /* data */
        3, /* register */
        4, /* extended register */
        5, /* demand register */
        7, /* profile generic */
        8, /* clock */
        9, /* script table */
        10, /* schedule */
        11, /* special days table */
        15, /* association ln */
        17, /* sap assignment */
        18, /* image transfer */
        20, /* activity calendar */
        21, /* register monitor */
        22, /* single action schedule */
        23, /* iec hdlc setup */
        30, /* data protection */
        70, /* disconnect control */
        71, /* limiter */
        104, /* zigbee network control */
        111, /* account */
        112, /* credit */
        113, /* charge */
        115, /* token gateway */
        9000, /* extended data */
    };
    static const struct dlms_cosem_class classes[] = {
        {
            "data",
            {
                "value"
            },{
                "dummy entry"
            }
        },{
            "register",
            {
                "value",
                "scaler_unit"
            },{
                "reset"
            }
        },{
            "extended_register",
            {
                "value",
                "scaler_unit",
                "status",
                "capture_time"
            },{
                "reset"
            }
        },{
            "demand_register",
            {
                "current_average_value",
                "last_average_value",
                "scaler_unit",
                "status",
                "capture_time",
                "start_time_current",
                "period",
                "number_of_periods"
            },{
                "reset",
                "next_period"
            }
        },{
            "profile_generic",
            {
                "buffer",
                "capture_objects",
                "capture_period",
                "sort_method",
                "sort_object",
                "entries_in_use",
                "profile_entries"
            },{
                "reset",
                "capture",
                "get_buffer_by_range",
                "get_buffer_by_index"
            }
        },{
            "clock",
            {
                "time",
                "time_zone",
                "status",
                "daylight_savings_begin",
                "daylight_savings_end",
                "daylight_savings_deviation",
                "daylight_savings_enabled",
                "clock_base"
            },{
                "adjust_to_quarter",
                "adjust_to_measuring_period",
                "adjust_to_minute",
                "adjust_to_preset_time",
                "preset_adjusting_time",
                "shift_time"
            }
        },{
            "script_table",
            {
                "scripts"
            },{
                "execute"
            }
        },{
            "schedule",
            {
                "entries"
            },{
                "enable_disable",
                "insert",
                "delete"
            }
        },{
            "special_days_table",
            {
                "entries"
            },{
                "insert",
                "delete"
            }
        },{
            "association_ln",
            {
                "object_list",
                "associated_partners_id",
                "application_context_name",
                "xdlms_context_info",
                "authentication_mechanism_name",
                "secret",
                "association_status",
                "security_setup_reference",
                "user_list",
                "current_user"
            },{
                "reply_to_hls_authentication",
                "change_hls_secret",
                "add_object",
                "remove_object",
                "add_user",
                "remove_user"
            }
        },{
            "sap_assignment",
            {
                "sap_assignment_list"
            },{
                "connect_logical_devices"
            }
        },{
            "image_transfer",
            {
                "image_block_size",
                "image_transferred_blocks_status",
                "image_first_not_transferred_block_number",
                "image_transfer_enabled",
                "image_transfer_status",
                "image_to_activate_info"
            },{
                "image_transfer_initiate",
                "image_block_transfer",
                "image_verify",
                "image_activate"
            }
        },{
            "activity_calendar",
            {
                "calendar_name_active",
                "season_profile_active",
                "week_profile_table_active",
                "day_profile_table_active",
                "calendar_name_passive",
                "season_profile_passive",
                "week_profile_table_passive",
                "day_profile_table_passive",
                "active_passive_calendar_time"
            },{
                "active_passive_calendar"
            }
        },{
            "register_monitor",
            {
                "thresholds",
                "monitored_value",
                "actions"
            },{
                "dummy entry"
            }

        },{
            "single_action_schedule",
            {
                "executed_script",
                "type",
                "execution_time"
            },{
                "dummy entry"
            }
        },{
            "iec_hdlc_setup",
            {
                "comm_speed",
                "window_size_transmit",
                "window_size_receive",
                "max_info_field_length_transmit",
                "max_info_field_length_receive",
                "inter_octet_time_out",
                "inactivity_time_out",
                "device_address"
            },{
                "dummy entry"
            }
        },{
            "data_protection",
            {
                "protection_buffer",
                "protection_object_list",
                "protection_parameters_get",
                "protection_parameters_set",
                "required_protection"
            },{
                "get_protected_attributes",
                "set_protected_attributes",
                "invoke_protected_method"
            }
        },{
            "disconnect_control",
            {
                "output_state",
                "control_state",
                "control_mode"
            },{
                "remote_disconnect",
                "remote_reconnect"
            }
        },{
            "limiter",
            {
                "monitored_value",
                "threshold_active",
                "threshold_normal",
                "threshold_emergency",
                "min_over_threshold_duration",
                "min_under_threshold_duration",
                "emergency_profile",
                "emergency_profile_group_id_list",
                "emergency_profile_active",
                "actions"
            },{
                "dummy entry"
            }
        },{
            "zigbee_network_control",
            {
                "enable_disable_joining",
                "join_timeout",
                "active_devices"
            },{
                "register_device",
                "unregister_device",
                "unregister_all_devices",
                "backup_pan",
                "restore_pan",
                "identify_device",
                "remove_mirror",
                "update_network_key",
                "update_link_key",
                "create_pan",
                "remove_pan"
            }
        },{
            "account",
            {
                "account_mode_and_status",
                "current_credit_in_use",
                "current_credit_status",
                "available_credit",
                "amount_to_clear",
                "clearance_threshold",
                "aggregated_debt",
                "credit_reference_list",
                "charge_reference_list",
                "credit_charge_configuration",
                "token_gateway_configuration",
                "account_activation_time",
                "account_closure_time",
                "currency",
                "low_credit_threshold",
                "next_credit_available_threshold",
                "max_provision",
                "max_provision_period"
            },{
                "activate_account",
                "close_account",
                "reset_account"
            }
        },{
            "credit",
            {
                "current_credit_amount",
                "credit_type",
                "priority",
                "warning_threshold",
                "limit",
                "credit_configuration",
                "credit_status",
                "preset_credit_amount",
                "credit_available_threshold",
                "period"
            },{
                "update_amount",
                "set_amount_to_value",
                "invoke_credit"
            }
        },{
            "charge",
            {
                "total_amount_paid",
                "charge_type",
                "priority",
                "unit_charge_active",
                "unit_charge_passive",
                "unit_charge_activation_time",
                "period",
                "charge_configuration",
                "last_collection_time",
                "last_collection_amount",
                "total_amount_remaining",
                "proportion"
            },{
                "update_unit_charge",
                "activate_passive_unit_charge",
                "collect",
                "update_total_amount_remaining",
                "set_total_amount_remaining"
            }
        },{
            "token_gateway",
            {
                "token",
                "token_time",
                "token_description",
                "token_delivery_method",
                "token_status"
            },{
                "enter"
            }
        },{
            "extended_data",
            {
                "value_active",
                "scaler_unit_active",
                "value_passive",
                "scaler_unit_passive",
                "activate_passive_value_time"
            },{
                "reset",
                "activate_passive_value"
            }
        }
    };    unsigned i;

    for (i = 0; i < array_length(ids); i++) {
        if (ids[i] == class_id) {
            return &classes[i];
        }
    }

    return 0;
}

static const char*
dlms_get_attribute_name(const dlms_cosem_class* c, int attribute_id) {
    if (attribute_id > 1 && attribute_id < (int)array_length(c->attributes) + 2) {
        return c->attributes[attribute_id - 2];
    }
    else if (attribute_id == 1) {
        return "logical_name";
    }
    return (NULL);
}

static const char*
dlms_get_method_name(const dlms_cosem_class* c, int method_id) {
    if (method_id > 0 && method_id < (int)array_length(c->methods) + 1) {
        return c->methods[method_id - 1];
    }
    return (NULL);
}



static int * const T_protocol_version_bits[] = {
  &hf_cosem_T_protocol_version_version1,
  NULL
};

static int
dissect_cosem_T_protocol_version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_protocol_version_bits, 1, hf_index, ett_cosem_T_protocol_version,
                                    NULL);

  return offset;
}



static int
dissect_cosem_Application_context_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cosem_AP_title_form1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509if_Name(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cosem_AP_title_form2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cosem_AP_title_form3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string cosem_AP_title_vals[] = {
  {   0, "ap-title-form1" },
  {   1, "ap-title-form2" },
  {   2, "ap-title-form3" },
  { 0, NULL }
};

static const ber_choice_t AP_title_choice[] = {
  {   0, &hf_cosem_ap_title_form1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cosem_AP_title_form1 },
  {   1, &hf_cosem_ap_title_form2, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cosem_AP_title_form2 },
  {   2, &hf_cosem_ap_title_form3, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_cosem_AP_title_form3 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_AP_title(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AP_title_choice, hf_index, ett_cosem_AP_title,
                                 NULL);

  return offset;
}



static int
dissect_cosem_ASO_qualifier_form1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509if_RelativeDistinguishedName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cosem_ASO_qualifier_form2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_cosem_ASO_qualifier_form3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cosem_ASO_qualifier_form_octets(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string cosem_ASO_qualifier_vals[] = {
  {   0, "aso-qualifier-form1" },
  {   1, "aso-qualifier-form2" },
  {   2, "aso-qualifier-form3" },
  {   3, "aso-qualifier-form-any-octets" },
  { 0, NULL }
};

static const ber_choice_t ASO_qualifier_choice[] = {
  {   0, &hf_cosem_aso_qualifier_form1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cosem_ASO_qualifier_form1 },
  {   1, &hf_cosem_aso_qualifier_form2, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cosem_ASO_qualifier_form2 },
  {   2, &hf_cosem_aso_qualifier_form3, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_cosem_ASO_qualifier_form3 },
  {   3, &hf_cosem_aso_qualifier_form_any_octets, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cosem_ASO_qualifier_form_octets },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_ASO_qualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ASO_qualifier_choice, hf_index, ett_cosem_ASO_qualifier,
                                 NULL);

  return offset;
}



static int
dissect_cosem_AE_qualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cosem_ASO_qualifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cosem_AP_invocation_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_cosem_AE_invocation_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static int * const ACSE_requirements_bits[] = {
  &hf_cosem_ACSE_requirements_authentication,
  &hf_cosem_ACSE_requirements_aSO_context_negotiation,
  &hf_cosem_ACSE_requirements_higher_level_association,
  &hf_cosem_ACSE_requirements_nested_association,
  NULL
};

static int
dissect_cosem_ACSE_requirements(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ACSE_requirements_bits, 4, hf_index, ett_cosem_ACSE_requirements,
                                    NULL);

  return offset;
}



static int
dissect_cosem_Mechanism_name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cosem_GraphicString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cosem_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_cosem_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cosem_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_cosem_ObjectDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_ObjectDescriptor,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cosem_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string cosem_T_encoding_vals[] = {
  {   0, "single-ASN1-type" },
  {   1, "octet-aligned" },
  {   2, "arbitrary" },
  { 0, NULL }
};

static const ber_choice_t T_encoding_choice[] = {
  {   0, &hf_cosem_single_ASN1_type, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cosem_OCTET_STRING },
  {   1, &hf_cosem_octet_aligned , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cosem_OCTET_STRING },
  {   2, &hf_cosem_arbitrary     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cosem_BIT_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_T_encoding(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_encoding_choice, hf_index, ett_cosem_T_encoding,
                                 NULL);

  return offset;
}


static const ber_sequence_t EXTERNALt_U_sequence[] = {
  { &hf_cosem_direct_reference, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cosem_OBJECT_IDENTIFIER },
  { &hf_cosem_indirect_reference, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cosem_INTEGER },
  { &hf_cosem_data_value_descriptor, BER_CLASS_UNI, BER_UNI_TAG_ObjectDescriptor, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cosem_ObjectDescriptor },
  { &hf_cosem_encoding      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cosem_T_encoding },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_EXTERNALt_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EXTERNALt_U_sequence, hf_index, ett_cosem_EXTERNALt_U);

  return offset;
}



static int
dissect_cosem_EXTERNALt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_UNI, 8, true, dissect_cosem_EXTERNALt_U);

  return offset;
}



static int
dissect_cosem_T_other_mechanism_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if (actx->external.direct_ref_present) {
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, actx->subtree.top_tree, actx->private_data);
  }


  return offset;
}


static const ber_sequence_t Authentication_value_other_sequence[] = {
  { &hf_cosem_other_mechanism_name, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cosem_OBJECT_IDENTIFIER },
  { &hf_cosem_other_mechanism_value, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cosem_T_other_mechanism_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_Authentication_value_other(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Authentication_value_other_sequence, hf_index, ett_cosem_Authentication_value_other);

  return offset;
}


static const value_string cosem_Authentication_value_vals[] = {
  {   0, "charstring" },
  {   1, "bitstring" },
  {   2, "external" },
  {   3, "other" },
  { 0, NULL }
};

static const ber_choice_t Authentication_value_choice[] = {
  {   0, &hf_cosem_charstring    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cosem_GraphicString },
  {   1, &hf_cosem_bitstring     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cosem_BIT_STRING },
  {   2, &hf_cosem_external      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cosem_EXTERNALt },
  {   3, &hf_cosem_other         , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_cosem_Authentication_value_other },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_Authentication_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Authentication_value_choice, hf_index, ett_cosem_Authentication_value,
                                 NULL);

  return offset;
}



static int
dissect_cosem_Implementation_data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cosem_Association_information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb){
    return offset;
  }

  col_set_fence(actx->pinfo->cinfo, COL_INFO);
  dlms_dissect_apdu(parameter_tvb, actx->pinfo, tree, 0);


  return offset;
}


static const ber_sequence_t AARQ_apdu_U_sequence[] = {
  { &hf_cosem_protocol_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_T_protocol_version },
  { &hf_cosem_application_context_name, BER_CLASS_CON, 1, 0, dissect_cosem_Application_context_name },
  { &hf_cosem_called_AP_title, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cosem_AP_title },
  { &hf_cosem_called_AE_qualifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cosem_AE_qualifier },
  { &hf_cosem_called_AP_invocation_identifier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_cosem_AP_invocation_identifier },
  { &hf_cosem_called_AE_invocation_identifier, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_cosem_AE_invocation_identifier },
  { &hf_cosem_calling_AP_title, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cosem_AP_title },
  { &hf_cosem_calling_AE_qualifier, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cosem_AE_qualifier },
  { &hf_cosem_calling_AP_invocation_identifier, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_cosem_AP_invocation_identifier },
  { &hf_cosem_calling_AE_invocation_identifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_cosem_AE_invocation_identifier },
  { &hf_cosem_sender_acse_requirements, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_ACSE_requirements },
  { &hf_cosem_mechanism_name, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_Mechanism_name },
  { &hf_cosem_calling_authentication_value, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cosem_Authentication_value },
  { &hf_cosem_implementation_information, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_Implementation_data },
  { &hf_cosem_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_Association_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_AARQ_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AARQ_apdu_U_sequence, hf_index, ett_cosem_AARQ_apdu_U);

  return offset;
}



static int
dissect_cosem_AARQ_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, true, dissect_cosem_AARQ_apdu_U);

  return offset;
}


static int * const T_protocol_version_01_bits[] = {
  &hf_cosem_T_protocol_version_01_version1,
  NULL
};

static int
dissect_cosem_T_protocol_version_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_protocol_version_01_bits, 1, hf_index, ett_cosem_T_protocol_version_01,
                                    NULL);

  return offset;
}


static const value_string cosem_Association_result_vals[] = {
  {   0, "accepted" },
  {   1, "rejected-permanent" },
  {   2, "rejected-transient" },
  { 0, NULL }
};


static int
dissect_cosem_Association_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cosem_T_acse_service_user_vals[] = {
  {   0, "null" },
  {   1, "no-reason-given" },
  {   2, "application-context-name-not-supported" },
  {  11, "authentication-mechanism-name-not-recognised" },
  {  12, "authentication-mechanism-name-required" },
  {  13, "authentication-failure" },
  {  14, "authentication-required" },
  { 0, NULL }
};


static int
dissect_cosem_T_acse_service_user(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cosem_T_acse_service_provider_vals[] = {
  {   0, "null" },
  {   1, "no-reason-given" },
  {   2, "no-common-acse-version" },
  { 0, NULL }
};


static int
dissect_cosem_T_acse_service_provider(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cosem_Associate_source_diagnostic_vals[] = {
  {   1, "acse-service-user" },
  {   2, "acse-service-provider" },
  { 0, NULL }
};

static const ber_choice_t Associate_source_diagnostic_choice[] = {
  {   1, &hf_cosem_acse_service_user, BER_CLASS_CON, 1, 0, dissect_cosem_T_acse_service_user },
  {   2, &hf_cosem_acse_service_provider, BER_CLASS_CON, 2, 0, dissect_cosem_T_acse_service_provider },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_Associate_source_diagnostic(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Associate_source_diagnostic_choice, hf_index, ett_cosem_Associate_source_diagnostic,
                                 NULL);

  return offset;
}


static const ber_sequence_t AARE_apdu_U_sequence[] = {
  { &hf_cosem_protocol_version_01, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_T_protocol_version_01 },
  { &hf_cosem_aSO_context_name, BER_CLASS_CON, 1, 0, dissect_cosem_Application_context_name },
  { &hf_cosem_result        , BER_CLASS_CON, 2, 0, dissect_cosem_Association_result },
  { &hf_cosem_result_source_diagnostic, BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_cosem_Associate_source_diagnostic },
  { &hf_cosem_responding_AP_title, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cosem_AP_title },
  { &hf_cosem_responding_AE_qualifier, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cosem_AE_qualifier },
  { &hf_cosem_responding_AP_invocation_identifier, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_cosem_AP_invocation_identifier },
  { &hf_cosem_responding_AE_invocation_identifier, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_cosem_AE_invocation_identifier },
  { &hf_cosem_responder_acse_requirements, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_ACSE_requirements },
  { &hf_cosem_mechanism_name, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_Mechanism_name },
  { &hf_cosem_responding_authentication_value, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cosem_Authentication_value },
  { &hf_cosem_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_Association_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_AARE_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AARE_apdu_U_sequence, hf_index, ett_cosem_AARE_apdu_U);

  return offset;
}



static int
dissect_cosem_AARE_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 1, true, dissect_cosem_AARE_apdu_U);

  return offset;
}


static const value_string cosem_Release_request_reason_vals[] = {
  {   0, "normal" },
  {   1, "urgent" },
  {  30, "user-defined" },
  { 0, NULL }
};


static int
dissect_cosem_Release_request_reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RLRQ_apdu_U_sequence[] = {
  { &hf_cosem_reason        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_Release_request_reason },
  { &hf_cosem_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_Association_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_RLRQ_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RLRQ_apdu_U_sequence, hf_index, ett_cosem_RLRQ_apdu_U);

  return offset;
}



static int
dissect_cosem_RLRQ_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 2, true, dissect_cosem_RLRQ_apdu_U);

  return offset;
}


static const value_string cosem_Release_response_reason_vals[] = {
  {   0, "normal" },
  {   1, "not-finished" },
  {  30, "user-defined" },
  { 0, NULL }
};


static int
dissect_cosem_Release_response_reason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RLRE_apdu_U_sequence[] = {
  { &hf_cosem_reason_01     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_Release_response_reason },
  { &hf_cosem_user_information, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cosem_Association_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cosem_RLRE_apdu_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RLRE_apdu_U_sequence, hf_index, ett_cosem_RLRE_apdu_U);

  return offset;
}



static int
dissect_cosem_RLRE_apdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 3, true, dissect_cosem_RLRE_apdu_U);

  return offset;
}


static int * const Conformance_U_bits[] = {
  &hf_cosem_Conformance_U_reserved0,
  &hf_cosem_Conformance_U_reserved1,
  &hf_cosem_Conformance_U_reserved2,
  &hf_cosem_Conformance_U_read,
  &hf_cosem_Conformance_U_write,
  &hf_cosem_Conformance_U_unconfirmed_write,
  &hf_cosem_Conformance_U_reserved6,
  &hf_cosem_Conformance_U_reserved7,
  &hf_cosem_Conformance_U_attribute0_supported_with_SET,
  &hf_cosem_Conformance_U_priority_mgmt_supported,
  &hf_cosem_Conformance_U_attribute0_supported_with_GET,
  &hf_cosem_Conformance_U_block_transfer_with_get,
  &hf_cosem_Conformance_U_block_transfer_with_set,
  &hf_cosem_Conformance_U_block_transfer_with_action,
  &hf_cosem_Conformance_U_multiple_references,
  &hf_cosem_Conformance_U_information_report,
  &hf_cosem_Conformance_U_reserved16,
  &hf_cosem_Conformance_U_reserved17,
  &hf_cosem_Conformance_U_parameterized_access,
  &hf_cosem_Conformance_U_get,
  &hf_cosem_Conformance_U_set,
  &hf_cosem_Conformance_U_selective_access,
  &hf_cosem_Conformance_U_event_notification,
  &hf_cosem_Conformance_U_action,
  NULL
};

static int
dissect_cosem_Conformance_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Conformance_U_bits, 24, hf_index, ett_cosem_Conformance_U,
                                    NULL);

  return offset;
}



static int
dissect_cosem_Conformance(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 31, true, dissect_cosem_Conformance_U);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AARQ_apdu_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cosem_AARQ_apdu(false, tvb, offset, &asn1_ctx, tree, hf_cosem_AARQ_apdu_PDU);
  return offset;
}
static int dissect_AARE_apdu_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cosem_AARE_apdu(false, tvb, offset, &asn1_ctx, tree, hf_cosem_AARE_apdu_PDU);
  return offset;
}
static int dissect_RLRQ_apdu_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cosem_RLRQ_apdu(false, tvb, offset, &asn1_ctx, tree, hf_cosem_RLRQ_apdu_PDU);
  return offset;
}
static int dissect_RLRE_apdu_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cosem_RLRE_apdu(false, tvb, offset, &asn1_ctx, tree, hf_cosem_RLRE_apdu_PDU);
  return offset;
}
static int dissect_Conformance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cosem_Conformance(false, tvb, offset, &asn1_ctx, tree, hf_cosem_Conformance_PDU);
  return offset;
}


static int
dissect_cosem(tvbuff_t* tvb, packet_info* pinfo, proto_tree* parent_tree, void* data _U_)
{
    //proto_item* item = NULL;
    //proto_tree* tree = NULL;

    /*item = */proto_tree_add_item(parent_tree, proto_cosem, tvb, 0, -1, ENC_NA);
    //tree = proto_item_add_subtree(item, ett_cosem);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "COSEM");
    col_clear(pinfo->cinfo, COL_INFO);

    //dissect_COSEMpdu_PDU(tvb, pinfo, tree, NULL);

    return tvb_captured_length(tvb);
}

/*
 * The reassembly table is used for reassembling both
 * HDLC I frame segments and DLMS APDU datablocks.
 * The reassembly id is used as hash key to distinguish between the two.
 */
static reassembly_table dlms_reassembly_table;

enum {
    /* Do not use 0 as id because that would return a NULL key */
    DLMS_REASSEMBLY_ID_HDLC = 1,
    DLMS_REASSEMBLY_ID_DATABLOCK,
};

static unsigned
dlms_reassembly_hash_func(const void *key)
{
    return GPOINTER_TO_UINT(key);
}

static int
dlms_reassembly_equal_func(const void *key1, const void *key2)
{
    return key1 == key2;
}

static void *
dlms_reassembly_key_func(const packet_info* pinfo _U_, uint32_t id, const void* data _U_)
{
    return GUINT_TO_POINTER(id);
}

static void
dlms_reassembly_free_key_func(void *ptr _U_)
{
}

static const fragment_items dlms_fragment_items = {
    &ett_dlms_fragment,
    &ett_dlms_fragments,
    &hf_dlms_fragments,
    &hf_dlms_fragment,
    &hf_dlms_fragment_overlap,
    &hf_dlms_fragment_conflict,
    &hf_dlms_fragment_multiple_tails,
    &hf_dlms_fragment_too_long,
    &hf_dlms_fragment_error,
    &hf_dlms_fragment_count,
    &hf_dlms_reassembled_in,
    &hf_dlms_reassembled_length,
    &hf_dlms_reassembled_data,
    "Fragments"
};

static int
dlms_dissect_invoke_id_and_priority(proto_tree* tree, tvbuff_t* tvb, int offset)
{
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 1, ett_dlms_invoke_id_and_priority, NULL, "Invoke Id And Priority");
    proto_tree_add_item(subtree, hf_dlms_invoke_id, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlms_service_class, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(subtree, hf_dlms_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static void
dlms_dissect_long_invoke_id_and_priority(proto_tree* tree, tvbuff_t* tvb, int* offset)
{
    proto_tree* subtree;

    subtree = proto_tree_add_subtree(tree, tvb, *offset, 4, ett_dlms_invoke_id_and_priority, 0, "Long Invoke Id And Priority");
    proto_tree_add_item(subtree, hf_dlms_long_invoke_id, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_dlms_self_descriptive, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_dlms_processing_option, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_dlms_long_service_class, tvb, *offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_dlms_long_priority, tvb, *offset, 4, ENC_BIG_ENDIAN);
    *offset += 4;
}

static int
dlms_dissect_cosem_attribute_or_method_descriptor(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, int is_attribute)
{
    unsigned class_id, attribute_method_id;
    const dlms_cosem_class* cosem_class;
    const char* attribute_method_name;
    const char* instance_name;
    proto_tree* subtree;
    proto_item* item;

    class_id = tvb_get_ntohs(tvb, offset);
    attribute_method_id = tvb_get_uint8(tvb, offset + 8);

    cosem_class = dlms_get_class(class_id);
    if (cosem_class) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", cosem_class->name);
        if (is_attribute) {
            attribute_method_name = dlms_get_attribute_name(cosem_class, attribute_method_id);
        }
        else {
            attribute_method_name = dlms_get_method_name(cosem_class, attribute_method_id);
        }
    }
    else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %u", class_id);
        attribute_method_name = 0;
    }

    if (attribute_method_name) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ".%s", attribute_method_name);
    }
    else {
        col_append_fstr(pinfo->cinfo, COL_INFO, ".%u", attribute_method_id);
    }

    instance_name = try_val64_to_str(tvb_get_ntoh48(tvb, offset + 2), obis_code_names);
    if (instance_name) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s", instance_name);
    }
    else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %u.%u.%u.%u.%u.%u",
            tvb_get_uint8(tvb, offset + 2),
            tvb_get_uint8(tvb, offset + 3),
            tvb_get_uint8(tvb, offset + 4),
            tvb_get_uint8(tvb, offset + 5),
            tvb_get_uint8(tvb, offset + 6),
            tvb_get_uint8(tvb, offset + 7));
    }

    subtree = proto_tree_add_subtree(tree, tvb, offset, 9, ett_dlms_cosem_attribute_or_method_descriptor, 0,
        is_attribute ? "COSEM Attribute Descriptor" : "COSEM Method Descriptor");

    item = proto_tree_add_item(subtree, hf_dlms_class_id, tvb, offset, 2, ENC_NA);
    if (cosem_class) {
        proto_item_append_text(item, ": %s (%u)", cosem_class->name, class_id);
    }
    else {
        proto_item_append_text(item, ": Unknown (%u)", class_id);
        expert_add_info(pinfo, item, &ei_dlms_not_implemented);
    }
    offset += 2;

    item = proto_tree_add_item(subtree, hf_dlms_instance_id, tvb, offset, 6, ENC_NA);
    proto_item_append_text(item, ": %s (%u.%u.%u.%u.%u.%u)",
        instance_name ? instance_name : "Unknown",
        tvb_get_uint8(tvb, offset),
        tvb_get_uint8(tvb, offset + 1),
        tvb_get_uint8(tvb, offset + 2),
        tvb_get_uint8(tvb, offset + 3),
        tvb_get_uint8(tvb, offset + 4),
        tvb_get_uint8(tvb, offset + 5));
    offset += 6;

    item = proto_tree_add_item(subtree,
        is_attribute ? hf_dlms_attribute_id : hf_dlms_method_id,
        tvb, offset, 1, ENC_BIG_ENDIAN);
    if (attribute_method_name) {
        proto_item_append_text(item, ": %s (%u)", attribute_method_name, attribute_method_id);
    }
    else {
        proto_item_append_text(item, ": Unknown (%u)", attribute_method_id);
    }
    offset += 1;

    return offset;
}

static int
dlms_dissect_cosem_attribute_descriptor(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    return dlms_dissect_cosem_attribute_or_method_descriptor(tvb, pinfo, tree, offset, 1);
}

static int
dlms_dissect_cosem_method_descriptor(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    return dlms_dissect_cosem_attribute_or_method_descriptor(tvb, pinfo, tree, offset, 0);
}

static int
dlms_dissect_data_access_result(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    proto_item* item;
    int result;

    item = proto_tree_add_item(tree, hf_dlms_data_access_result, tvb, offset, 1, ENC_NA);
    result = tvb_get_uint8(tvb, offset);
    offset += 1;
    if (result != 0) {
        const char* str = val_to_str_const(result, dlms_data_access_result_names, "unknown result");
        col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", str);
        expert_add_info(pinfo, item, &ei_dlms_no_success);
    }
    return offset;
}

/* Get the value encoded in the specified length octets in definite form */
static unsigned
dlms_get_length(tvbuff_t* tvb, int* offset)
{
    unsigned length;

    length = tvb_get_uint8(tvb, *offset);
    if ((length & 0x80) == 0) {
        *offset += 1;
    }
    else {
        unsigned i, n = length & 0x7f;
        length = 0;
        for (i = 0; i < n; i++) {
            length = (length << 8) + tvb_get_uint8(tvb, *offset + 1 + i);
        }
        *offset += 1 + n;
    }

    return length;
}

static unsigned
dlms_dissect_length(tvbuff_t* tvb, proto_tree* tree, int* offset)
{
    int start;
    unsigned length;
    proto_item* item;

    start = *offset;
    length = dlms_get_length(tvb, offset);
    item = proto_tree_add_item(tree, hf_dlms_length, tvb, start, *offset - start, ENC_NA);
    proto_item_append_text(item, ": %u", length);

    return length;
}

/* Attempt to parse a date-time from an octet-string */
static void
dlms_append_date_time_maybe(tvbuff_t* tvb, proto_item* item, int offset, unsigned length)
{
    unsigned year, month, day_of_month, day_of_week;
    unsigned hour, minute, second, hundredths;
    /* TODO: unsigned deviation, clock; */

    if (length != 12) return;
    year = tvb_get_ntohs(tvb, offset);
    month = tvb_get_uint8(tvb, offset + 2);
    if (month < 1 || (month > 12 && month < 0xfd)) return;
    day_of_month = tvb_get_uint8(tvb, offset + 3);
    if (day_of_month < 1 || (day_of_month > 31 && day_of_month < 0xfd)) return;
    day_of_week = tvb_get_uint8(tvb, offset + 4);
    if (day_of_week < 1 || (day_of_week > 7 && day_of_week < 0xff)) return;
    hour = tvb_get_uint8(tvb, offset + 5);
    if (hour > 23 && hour < 0xff) return;
    minute = tvb_get_uint8(tvb, offset + 6);
    if (minute > 59 && minute < 0xff) return;
    second = tvb_get_uint8(tvb, offset + 7);
    if (second > 59 && second < 0xff) return;
    hundredths = tvb_get_uint8(tvb, offset + 8);
    if (hundredths > 99 && hundredths < 0xff) return;

    proto_item_append_text(item, year < 0xffff ? " (%u" : " (%X", year);
    proto_item_append_text(item, month < 13 ? "/%02u" : "/%02X", month);
    proto_item_append_text(item, day_of_month < 32 ? "/%02u" : "/%02X", day_of_month);
    proto_item_append_text(item, hour < 24 ? " %02u" : " %02X", hour);
    proto_item_append_text(item, minute < 60 ? ":%02u" : ":%02X", minute);
    proto_item_append_text(item, second < 60 ? ":%02u" : ":%02X", second);
    proto_item_append_text(item, hundredths < 100 ? ".%02u)" : ".%02X)", hundredths);
}

/* Set the value of an item with a planar data type (not array nor structure) */
static int
dlms_set_data_value(tvbuff_t* tvb, proto_item* item, int choice, int offset)
{
    if (choice == 0) {
        proto_item_set_text(item, "Null");
    }
    else if (choice == 3) {
        bool value = tvb_get_uint8(tvb, offset);
        proto_item_set_text(item, "Boolean: %s", value ? "true" : "false");
        offset += 1;
    }
    else if (choice == 4) {
        unsigned bits = dlms_get_length(tvb, &offset);
        unsigned bytes = (bits + 7) / 8;
        proto_item_set_text(item, "Bit-string (bits: %u, bytes: %u):", bits, bytes);
        offset += bytes;
    }
    else if (choice == 5) {
        int32_t value = tvb_get_ntohl(tvb, offset);
        proto_item_set_text(item, "Double Long: %d", value);
        offset += 4;
    }
    else if (choice == 6) {
        uint32_t value = tvb_get_ntohl(tvb, offset);
        proto_item_set_text(item, "Double Long Unsigned: %u", value);
        offset += 4;
    }
    else if (choice == 9) {
        unsigned length = dlms_get_length(tvb, &offset);
        proto_item_set_text(item, "Octet String (length %u)", length);
        dlms_append_date_time_maybe(tvb, item, offset, length);
        offset += length;
    }
    else if (choice == 10) {
        unsigned length = dlms_get_length(tvb, &offset);
        proto_item_set_text(item, "Visible String (length %u)", length);
        offset += length;
    }
    else if (choice == 12) {
        unsigned length = dlms_get_length(tvb, &offset);
        proto_item_set_text(item, "UTF8 String (length %u)", length);
        offset += length;
    }
    else if (choice == 13) {
        unsigned value = tvb_get_uint8(tvb, offset);
        proto_item_set_text(item, "BCD: 0x%02x", value);
        offset += 1;
    }
    else if (choice == 15) {
        int8_t value = tvb_get_uint8(tvb, offset);
        proto_item_set_text(item, "Integer: %d", value);
        offset += 1;
    }
    else if (choice == 16) {
        int16_t value = tvb_get_ntohs(tvb, offset);
        proto_item_set_text(item, "Long: %d", value);
        offset += 2;
    }
    else if (choice == 17) {
        uint8_t value = tvb_get_uint8(tvb, offset);
        proto_item_set_text(item, "Unsigned: %u", value);
        offset += 1;
    }
    else if (choice == 18) {
        uint16_t value = tvb_get_ntohs(tvb, offset);
        proto_item_set_text(item, "Long Unsigned: %u", value);
        offset += 2;
    }
    else if (choice == 20) {
        int64_t value = tvb_get_ntoh64(tvb, offset);
        proto_item_set_text(item, "Long64: %" PRIu64 "", value);
        offset += 8;
    }
    else if (choice == 21) {
        uint64_t value = tvb_get_ntoh64(tvb, offset);
        proto_item_set_text(item, "Long64 Unsigned: %" PRId64 "", value);
        offset += 8;
    }
    else if (choice == 22) {
        uint8_t value = tvb_get_uint8(tvb, offset);
        proto_item_set_text(item, "Enum: %u", value);
        offset += 1;
    }
    else if (choice == 23) {
        float value = tvb_get_ntohieee_float(tvb, offset);
        proto_item_set_text(item, "Float32: %f", value);
        offset += 4;
    }
    else if (choice == 24) {
        double value = tvb_get_ntohieee_double(tvb, offset);
        proto_item_set_text(item, "Float64: %f", value);
        offset += 8;
    }
    else if (choice == 25) {
        proto_item_set_text(item, "Date Time");
        offset += 12;
    }
    else if (choice == 26) {
        proto_item_set_text(item, "Date");
        offset += 5;
    }
    else if (choice == 27) {
        proto_item_set_text(item, "Time");
        offset += 4;
    }
    else if (choice == 255) {
        proto_item_set_text(item, "Don't Care");
    }
    else {
        DISSECTOR_ASSERT_HINT(choice, "Invalid data type");
    }

    return offset;
}


/* Calculate the number of bytes used by a TypeDescription of a compact array */
// NOLINTNEXTLINE(misc-no-recursion)
static int dlms_get_type_description_length(tvbuff_t* tvb, packet_info* pinfo, int offset)
{
    pinfo->dissection_depth += 2;
    increment_dissection_depth(pinfo);

    int choice = tvb_get_uint8(tvb, offset);
    if (choice == 1) { // array
        pinfo->dissection_depth -= 2;
        decrement_dissection_depth(pinfo);
        return 1 + 2 + dlms_get_type_description_length(tvb, pinfo, offset + 3);
    }
    else if (choice == 2) { // structure
        int end_offset = offset + 1;
        int sequence_of = dlms_get_length(tvb, &end_offset);
        while (sequence_of--) {
            end_offset += dlms_get_type_description_length(tvb, pinfo, end_offset);
        }
        pinfo->dissection_depth -= 2;
        decrement_dissection_depth(pinfo);
        return end_offset - offset;
    }
    else {
        pinfo->dissection_depth -= 2;
        decrement_dissection_depth(pinfo);
        return 1;
    }
}

// NOLINTNEXTLINE(misc-no-recursion)
static proto_item* dlms_dissect_compact_array_content(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int description_offset, int* content_offset)
{
    proto_item* item, * subitem;
    proto_tree* subtree;
    unsigned choice;

    pinfo->dissection_depth += 2;
    increment_dissection_depth(pinfo);

    item = proto_tree_add_item(tree, hf_dlms_data, tvb, *content_offset, 0, ENC_NA);
    choice = tvb_get_uint8(tvb, description_offset);
    description_offset += 1;
    if (choice == 1) { /* array */
        uint16_t i, elements = tvb_get_ntohs(tvb, description_offset);
        description_offset += 2;
        proto_item_set_text(item, "Array (%u elements)", elements);
        subtree = proto_item_add_subtree(item, ett_dlms_composite_data);
        for (i = 0; i < elements; i++) {
            subitem = dlms_dissect_compact_array_content(tvb, pinfo, subtree, description_offset, content_offset);
            proto_item_prepend_text(subitem, "[%u] ", i + 1);
        }
    }
    else if (choice == 2) { /* structure */
        uint32_t elements = dlms_get_length(tvb, &description_offset);
        proto_item_set_text(item, "Structure");
        subtree = proto_item_add_subtree(item, ett_dlms_composite_data);
        while (elements--) {
            dlms_dissect_compact_array_content(tvb, pinfo, subtree, description_offset, content_offset);
            description_offset += dlms_get_type_description_length(tvb, pinfo, description_offset);
        }
    }
    else { /* planar type */
        *content_offset = dlms_set_data_value(tvb, item, choice, *content_offset);
    }
    proto_item_set_end(item, tvb, *content_offset);

    pinfo->dissection_depth -= 2;
    decrement_dissection_depth(pinfo);

    return item;
}

// NOLINTNEXTLINE(misc-no-recursion)
static proto_item* dlms_dissect_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int* offset)
{
    proto_item* item, * subitem;
    proto_tree* subtree;
    unsigned choice, length, i;

    /* Protect against recursion */
    pinfo->dissection_depth += 2;
    increment_dissection_depth(pinfo);

    item = proto_tree_add_item(tree, hf_dlms_data, tvb, *offset, 1, ENC_NA);
    choice = tvb_get_uint8(tvb, *offset);
    *offset += 1;
    if (choice == 1) { /* array */
        length = dlms_get_length(tvb, offset);
        proto_item_set_text(item, "Array (%u elements)", length);
        subtree = proto_item_add_subtree(item, ett_dlms_composite_data);
        for (i = 0; i < length; i++) {
            subitem = dlms_dissect_data(tvb, pinfo, subtree, offset);
            proto_item_prepend_text(subitem, "[%u] ", i + 1);
        }
    }
    else if (choice == 2) { /* structure */
        length = dlms_get_length(tvb, offset);
        proto_item_set_text(item, "Structure");
        subtree = proto_item_add_subtree(item, ett_dlms_composite_data);
        for (i = 0; i < length; i++) {
            dlms_dissect_data(tvb, pinfo, subtree, offset);
        }
    }
    else if (choice == 19) { /* compact-array */
        int description_offset = *offset;
        int description_length = dlms_get_type_description_length(tvb, pinfo, *offset);
        int content_end;
        unsigned elements;
        subtree = proto_item_add_subtree(item, ett_dlms_composite_data);
        proto_tree_add_item(subtree, hf_dlms_type_description, tvb, description_offset, description_length, ENC_NA);
        *offset += description_length;
        length = dlms_dissect_length(tvb, subtree, offset);
        elements = 0;
        content_end = *offset + length;
        while (*offset < content_end) {
            subitem = dlms_dissect_compact_array_content(tvb, pinfo, subtree, description_offset, offset);
            proto_item_prepend_text(subitem, "[%u] ", ++elements);
        }
        proto_item_set_text(item, "Compact Array (%u elements)", elements);
    }
    else { /* planar type */
        *offset = dlms_set_data_value(tvb, item, choice, *offset);
    }
    proto_item_set_end(item, tvb, *offset);
    pinfo->dissection_depth -= 2;
    decrement_dissection_depth(pinfo);

    return item;
}

static void
dlms_dissect_list_of_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int* offset, const char* name)
{
    proto_tree* item;
    proto_tree* subtree;
    int sequence_of, i;

    subtree = proto_tree_add_subtree(tree, tvb, *offset, 0, ett_dlms_data, &item, name);
    sequence_of = dlms_get_length(tvb, offset);
    for (i = 0; i < sequence_of; i++) {
        proto_item* subitem = dlms_dissect_data(tvb, pinfo, subtree, offset);
        proto_item_prepend_text(subitem, "[%u] ", i + 1);
    }
    proto_item_set_end(item, tvb, *offset);
}

static int
dlms_dissect_datablock_data(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, proto_tree* subtree, int offset, unsigned block_number, unsigned last_block)
{
    unsigned saved_offset, raw_data_length;
    proto_item* item;
    fragment_head* frags;
    tvbuff_t* rtvb;

    col_append_fstr(pinfo->cinfo, COL_INFO, " (block %u)", block_number);
    if (last_block) {
        col_append_str(pinfo->cinfo, COL_INFO, " (last block)");
    }

    saved_offset = offset;
    raw_data_length = dlms_get_length(tvb, &offset);
    item = proto_tree_add_item(subtree, hf_dlms_data, tvb, saved_offset, offset - saved_offset + raw_data_length, ENC_NA);
    proto_item_append_text(item, " (length %u)", raw_data_length);

    if (block_number == 1) {
        fragment_delete(&dlms_reassembly_table, pinfo, DLMS_REASSEMBLY_ID_DATABLOCK, 0);
    }
    frags = fragment_add_seq_next(&dlms_reassembly_table, tvb, offset, pinfo, DLMS_REASSEMBLY_ID_DATABLOCK, 0, raw_data_length, last_block == 0);
    rtvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled", frags, &dlms_fragment_items, 0, tree);
    if (rtvb) {
        int rtvb_offset = 0;
        subtree = proto_tree_add_subtree(tree, rtvb, 0, 0, ett_dlms_data, 0, "Reassembled Data");
        dlms_dissect_data(rtvb, pinfo, subtree, &rtvb_offset);
    }

    offset += raw_data_length;
    return offset;
}

static void
dlms_dissect_datablock_g(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    proto_tree* subtree;
    unsigned last_block, block_number;
    int result;

    subtree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_dlms_datablock, 0, "Datablock G");

    proto_tree_add_item(subtree, hf_dlms_last_block, tvb, offset, 1, ENC_NA);
    last_block = tvb_get_uint8(tvb, offset);
    offset += 1;

    proto_tree_add_item(subtree, hf_dlms_block_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    block_number = tvb_get_ntohl(tvb, offset);
    offset += 4;

    result = tvb_get_uint8(tvb, offset);
    offset += 1;
    if (result == 0) {
        dlms_dissect_datablock_data(tvb, pinfo, tree, subtree, offset, block_number, last_block);
    }
    else if (result == 1) {
        dlms_dissect_data_access_result(tvb, pinfo, subtree, offset);
    }
}

static void
dlms_dissect_datablock_sa(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int* offset)
{
    proto_tree* subtree;
    unsigned last_block, block_number;

    subtree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_dlms_datablock, 0, "Datablock SA");

    proto_tree_add_item(subtree, hf_dlms_last_block, tvb, *offset, 1, ENC_NA);
    last_block = tvb_get_uint8(tvb, *offset);
    *offset += 1;

    proto_tree_add_item(subtree, hf_dlms_block_number, tvb, *offset, 4, ENC_BIG_ENDIAN);
    block_number = tvb_get_ntohl(tvb, *offset);
    *offset += 4;

    dlms_dissect_datablock_data(tvb, pinfo, tree, subtree, *offset, block_number, last_block);
}

static int
dlms_dissect_selective_access_descriptor(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    proto_item* item;
    proto_tree* subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_dlms_selective_access_descriptor, &item, "Selective Access Descriptor");
    int selector = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(subtree, hf_dlms_access_selector, tvb, offset, 1, ENC_NA);
    offset += 1;
    if (selector) {
        dlms_dissect_data(tvb, pinfo, subtree, &offset);
    }
    proto_item_set_end(item, tvb, offset);

    return offset;
}

static int
dlms_dissect_access_request_specification(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    proto_item* item, * subitem;
    proto_tree* subtree, * subsubtree;
    int sequence_of, i;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_dlms_access_request_specification, &item, "Access Request Specification");
    sequence_of = dlms_get_length(tvb, &offset);
    for (i = 0; i < sequence_of; i++) {
        int choice = tvb_get_uint8(tvb, offset);
        subitem = proto_tree_add_item(subtree, hf_dlms_access_request, tvb, offset, 1, ENC_NA);
        proto_item_prepend_text(subitem, "[%u] ", i + 1);
        subsubtree = proto_item_add_subtree(subitem, ett_dlms_access_request);
        offset += 1;
        switch (choice) {
        case DLMS_ACCESS_REQUEST_GET:
        case DLMS_ACCESS_REQUEST_SET:
            offset = dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, subsubtree, offset);
            break;
        case DLMS_ACCESS_REQUEST_ACTION:
            offset = dlms_dissect_cosem_method_descriptor(tvb, pinfo, subsubtree, offset);
            break;
        case DLMS_ACCESS_REQUEST_GET_WITH_SELECTION:
        case DLMS_ACCESS_REQUEST_SET_WITH_SELECTION:
            offset = dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, subsubtree, offset);
            offset = dlms_dissect_selective_access_descriptor(tvb, pinfo, subsubtree, offset);
            break;
        default:
            DISSECTOR_ASSERT_HINT(choice, "Invalid Access-Request-Specification CHOICE");
        }
    }
    proto_item_set_end(item, tvb, offset);
    return offset;
}


//static void
//dlms_dissect_aarq(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
//{
//    proto_tree* subtree;
//    int end, length, tag;
//
//    col_set_str(pinfo->cinfo, COL_INFO, "AARQ");
//    length = tvb_get_uint8(tvb, offset);
//    offset += 1;
//    end = offset + length;
//    while (offset < end) {
//        tag = tvb_get_uint8(tvb, offset);
//        length = tvb_get_uint8(tvb, offset + 1);
//        if (tag == 0xbe) { /* user-information */
//            subtree = proto_tree_add_subtree(tree, tvb, offset, 2 + length, ett_dlms_user_information, NULL, "User-Information");
//            dlms_dissect_conformance(tvb, subtree, offset + 2 + length - 9);
//            proto_tree_add_item(subtree, hf_dlms_client_max_receive_pdu_size, tvb, offset + 2 + length - 2, 2, ENC_BIG_ENDIAN);
//        }
//        offset += 2 + length;
//    }
//}

static void
dlms_dissect_initiate_request(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset)
{
    uint8_t oct;
    uint32_t length;

    /* dedicated-key                OCTET STRING OPTIONAL, */
    /* Check presence*/
    oct = tvb_get_uint8(tvb, offset);
    offset++;
    if (oct != 0) {
        offset = get_ber_length(tvb, offset, &length, NULL);
        proto_tree_add_item(tree, hf_dlms_dedicated_key, tvb, offset, length, ENC_NA);
        offset += length;
    }
    /* response-allowed             BOOLEAN DEFAULT true */
    proto_tree_add_item(tree, hf_dlms_response_allowed, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* proposed-quality-of-service  [0] IMPLICIT Integer8 OPTIONAL, */
    /* Check presence*/
    oct = tvb_get_uint8(tvb, offset);
    offset++;
    if (oct != 0) {
        /* skip tag 0 ?*/
        offset++;
        proto_tree_add_item(tree, hf_dlms_proposed_quality_of_service, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }
    /* proposed-dlms-version-number Unsigned8, */
    proto_tree_add_item(tree, hf_dlms_proposed_dlms_version_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* proposed-conformance         Conformance, */
    tvbuff_t* conformance_tvb = tvb_new_subset_remaining(tvb, offset);
    offset += dissect_Conformance_PDU(conformance_tvb, pinfo, tree, NULL);
    /* client-max-receive-pdu-size  Unsigned16 */
    proto_tree_add_item(tree, hf_dlms_client_max_receive_pdu_size, tvb, offset, 2, ENC_BIG_ENDIAN);
}

//static void
//dlms_dissect_read_request(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset)
//{
//
//}
static void
dlms_dissect_initiate_response(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* tree, int offset)
{

    uint8_t oct;

    /*negotiated - quality - of - service[0] IMPLICIT Integer8 OPTIONAL,*/
    /* Check presence*/
    oct = tvb_get_uint8(tvb, offset);
    offset++;
    if (oct != 0) {
        /* skip tag 0 ?*/
        offset++;
        proto_tree_add_item(tree, hf_dlms_negotiated_quality_of_service, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }
    /*negotiated - dlms - version - number Unsigned8,*/
    proto_tree_add_item(tree, hf_dlms_negotiated_dlms_version_number, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    /*negotiated - conformance         Conformance,*/
    tvbuff_t* conformance_tvb = tvb_new_subset_remaining(tvb, offset);
    offset += dissect_Conformance_PDU(conformance_tvb, pinfo, tree, NULL);

    /*server - max - receive - pdu - size    Unsigned16,*/
    proto_tree_add_item(tree, hf_dlms_server_max_receive_pdu_size, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /*vaa - name                       ObjectName*/
    /* ObjectName                 ::= Integer16 */
    proto_tree_add_item(tree, hf_dlms_object_name, tvb, offset, 2, ENC_BIG_ENDIAN);
}

static void
dlms_dissect_get_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    int choice;
    unsigned block_number;

    proto_tree_add_item(tree, hf_dlms_get_request, tvb, offset, 1, ENC_NA);
    choice = tvb_get_uint8(tvb, offset);
    offset += 1;
    offset = dlms_dissect_invoke_id_and_priority(tree, tvb, offset);
    if (choice == DLMS_GET_REQUEST_NORMAL) {
        col_set_str(pinfo->cinfo, COL_INFO, "Get-Request-Normal");
        offset = dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, tree, offset);
        /*offset = */dlms_dissect_selective_access_descriptor(tvb, pinfo, tree, offset);
    }
    else if (choice == DLMS_GET_REQUEST_NEXT) {
        proto_tree_add_item(tree, hf_dlms_block_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        block_number = tvb_get_ntohl(tvb, offset);
        /*offset += 4;*/
        col_add_fstr(pinfo->cinfo, COL_INFO, "Get-Request-Next (block %u)", block_number);
    }
    else {
        col_set_str(pinfo->cinfo, COL_INFO, "Get-Request");
    }
}

static void
dlms_dissect_set_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree,int offset)
{
    int choice;
    proto_tree* subtree;

    proto_tree_add_item(tree, hf_dlms_set_request, tvb, offset, 1, ENC_NA);
    choice = tvb_get_uint8(tvb, offset);
    offset += 1;
    offset = dlms_dissect_invoke_id_and_priority(tree, tvb, offset);
    if (choice == DLMS_SET_REQUEST_NORMAL) {
        col_set_str(pinfo->cinfo, COL_INFO, "Set-Request-Normal");
        offset = dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, tree, offset);
        offset = dlms_dissect_selective_access_descriptor(tvb, pinfo, tree, offset);
        subtree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_dlms_data, NULL, "Data");
        dlms_dissect_data(tvb, pinfo, subtree, &offset);
    }
    else if (choice == DLMS_SET_REQUEST_WITH_FIRST_DATABLOCK) {
        col_set_str(pinfo->cinfo, COL_INFO, "Set-Request-With-First-Datablock");
        offset = dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, tree, offset);
        offset = dlms_dissect_selective_access_descriptor(tvb, pinfo, tree, offset);
        dlms_dissect_datablock_sa(tvb, pinfo, tree, &offset);
    }
    else if (choice == DLMS_SET_REQUEST_WITH_DATABLOCK) {
        col_set_str(pinfo->cinfo, COL_INFO, "Set-Request-With-Datablock");
        dlms_dissect_datablock_sa(tvb, pinfo, tree, &offset);
    }
    else {
        col_set_str(pinfo->cinfo, COL_INFO, "Set-Request");
    }
}

static void
dlms_dissect_event_notification_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    proto_tree* subtree;

    col_set_str(pinfo->cinfo, COL_INFO, "Event-Notification-Request");
    offset += 1; /* time OPTIONAL (assume it is not present) */
    offset = dlms_dissect_cosem_attribute_descriptor(tvb, pinfo, tree, offset);
    subtree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_dlms_data, 0, "Data");
    dlms_dissect_data(tvb, pinfo, subtree, &offset);
}

static void
dlms_dissect_action_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    int choice, method_invocation_parameters;
    proto_tree* subtree;

    proto_tree_add_item(tree, hf_dlms_action_request, tvb, offset, 1, ENC_NA);
    choice = tvb_get_uint8(tvb, offset);
    offset += 1;
    offset = dlms_dissect_invoke_id_and_priority(tree, tvb, offset);
    if (choice == DLMS_ACTION_REQUEST_NORMAL) {
        col_set_str(pinfo->cinfo, COL_INFO, "Action-Request-Normal");
        offset = dlms_dissect_cosem_method_descriptor(tvb, pinfo, tree, offset);
        method_invocation_parameters = tvb_get_uint8(tvb, offset);
        if (method_invocation_parameters) {
            offset += 1;
            subtree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_dlms_data, 0, "Data");
            dlms_dissect_data(tvb, pinfo, subtree, &offset);
        }
    }
    else {
        col_set_str(pinfo->cinfo, COL_INFO, "Action-Request");
    }
}
static void
dlms_dissect_get_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    int choice, result;
    proto_tree* subtree;

    proto_tree_add_item(tree, hf_dlms_get_response, tvb, offset, 1, ENC_NA);
    choice = tvb_get_uint8(tvb, offset);
    offset += 1;
    offset = dlms_dissect_invoke_id_and_priority(tree, tvb, offset);
    if (choice == DLMS_GET_RESPONSE_NORMAL) {
        col_set_str(pinfo->cinfo, COL_INFO, "Get-Response-Normal");
        result = tvb_get_uint8(tvb, offset);
        offset += 1;
        if (result == 0) {
            subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_dlms_data, 0, "Data");
            dlms_dissect_data(tvb, pinfo, subtree, &offset);
        }
        else if (result == 1) {
            offset = dlms_dissect_data_access_result(tvb, pinfo, tree, offset);
        }
    }
    else if (choice == DLMS_GET_RESPONSE_WITH_DATABLOCK) {
        col_set_str(pinfo->cinfo, COL_INFO, "Get-Response-With-Datablock");
        dlms_dissect_datablock_g(tvb, pinfo, tree, offset);
    }
    else {
        col_set_str(pinfo->cinfo, COL_INFO, "Get-Response");
    }
}

static void
dlms_dissect_set_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    unsigned choice, block_number;

    proto_tree_add_item(tree, hf_dlms_set_response, tvb, offset, 1, ENC_NA);
    choice = tvb_get_uint8(tvb, offset);
    offset += 1;
    offset = dlms_dissect_invoke_id_and_priority(tree, tvb, offset);
    if (choice == DLMS_SET_RESPONSE_NORMAL) {
        col_set_str(pinfo->cinfo, COL_INFO, "Set-Response-Normal");
        dlms_dissect_data_access_result(tvb, pinfo, tree, offset);
    }
    else if (choice == DLMS_SET_RESPONSE_DATABLOCK) {
        col_set_str(pinfo->cinfo, COL_INFO, "Set-Response-Datablock");
        proto_tree_add_item(tree, hf_dlms_block_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        block_number = tvb_get_ntohl(tvb, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (block %u)", block_number);
    }
    else if (choice == DLMS_SET_RESPONSE_LAST_DATABLOCK) {
        col_set_str(pinfo->cinfo, COL_INFO, "Set-Response-Last-Datablock");
        dlms_dissect_data_access_result(tvb, pinfo, tree, offset);
        proto_tree_add_item(tree, hf_dlms_block_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        block_number = tvb_get_ntohl(tvb, offset);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (block %u)", block_number);
    }
    else {
        col_set_str(pinfo->cinfo, COL_INFO, "Set-Response");
    }
}

static void
dlms_dissect_action_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    unsigned choice, result;
    const char* result_name;
    proto_item* item;

    proto_tree_add_item(tree, hf_dlms_action_response, tvb, offset, 1, ENC_NA);
    choice = tvb_get_uint8(tvb, offset);
    offset += 1;
    offset = dlms_dissect_invoke_id_and_priority(tree, tvb, offset);
    if (choice == DLMS_ACTION_RESPONSE_NORMAL) {
        col_set_str(pinfo->cinfo, COL_INFO, "Action-Response-Normal");
        item = proto_tree_add_item(tree, hf_dlms_action_result, tvb, offset, 1, ENC_NA);
        result = tvb_get_uint8(tvb, offset);
        /*offset += 1;*/
        if (result) {
            result_name = val_to_str_const(result, dlms_action_result_names, "unknown");
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", result_name);
            expert_add_info(pinfo, item, &ei_dlms_no_success);
        }
    }
    else {
        col_set_str(pinfo->cinfo, COL_INFO, "Action-Response");
    }
}

static void
dlms_dissect_exception_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    proto_item* item;

    col_set_str(pinfo->cinfo, COL_INFO, "Exception-Response");
    item = proto_tree_add_item(tree, hf_dlms_state_error, tvb, offset, 1, ENC_NA);
    expert_add_info(pinfo, item, &ei_dlms_no_success);
    item = proto_tree_add_item(tree, hf_dlms_service_error, tvb, offset + 1, 1, ENC_NA);
    expert_add_info(pinfo, item, &ei_dlms_no_success);
}

static void
dlms_dissect_access_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    int date_time_offset;
    int date_time_length;
    proto_item* item;

    col_set_str(pinfo->cinfo, COL_INFO, "Access-Request");

    dlms_dissect_long_invoke_id_and_priority(tree, tvb, &offset);

    date_time_offset = offset;
    date_time_length = dlms_get_length(tvb, &offset);
    item = proto_tree_add_item(tree, hf_dlms_date_time, tvb, date_time_offset, offset - date_time_offset + date_time_length, ENC_NA);
    dlms_append_date_time_maybe(tvb, item, offset, date_time_length);

    offset = dlms_dissect_access_request_specification(tvb, pinfo, tree, offset);

    dlms_dissect_list_of_data(tvb, pinfo, tree, &offset, "Access Request List Of Data");
}

static void
dlms_dissect_access_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset)
{
    int date_time_offset;
    int date_time_length;
    proto_item* item;
    proto_tree* subtree, * subsubtree;
    int sequence_of, i;

    col_set_str(pinfo->cinfo, COL_INFO, "Access-Response");

    dlms_dissect_long_invoke_id_and_priority(tree, tvb, &offset);

    date_time_offset = offset;
    date_time_length = dlms_get_length(tvb, &offset);
    item = proto_tree_add_item(tree, hf_dlms_date_time, tvb, date_time_offset, offset - date_time_offset + date_time_length, ENC_NA);
    dlms_append_date_time_maybe(tvb, item, offset, date_time_length);

    offset = dlms_dissect_access_request_specification(tvb, pinfo, tree, offset);

    dlms_dissect_list_of_data(tvb, pinfo, tree, &offset, "Access Response List Of Data");

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_dlms_access_response_specification, 0, "Access Response Specification");
    sequence_of = dlms_get_length(tvb, &offset);
    for (i = 0; i < sequence_of; i++) {
        item = proto_tree_add_item(subtree, hf_dlms_access_response, tvb, offset, 1, ENC_NA);
        proto_item_prepend_text(item, "[%u] ", i + 1);
        subsubtree = proto_item_add_subtree(item, ett_dlms_access_request);
        offset += 1;
        dlms_dissect_data_access_result(tvb, pinfo, subsubtree, offset);
    }
}


/* Dissect a DLMS Application Packet Data Unit (APDU) */
static void
dlms_dissect_apdu(tvbuff_t* tvb, packet_info* pinfo _U_, proto_tree* parent_tree, int offset)
{
    proto_item* item = NULL;
    proto_tree* tree = NULL;

    uint32_t choice;
    tvbuff_t *apdu_tvb = tvb_new_subset_remaining(tvb, offset);

    item = proto_tree_add_item(parent_tree, proto_cosem, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_cosem);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DLMS/COSEM");
    col_clear(pinfo->cinfo, COL_INFO);


    proto_tree_add_item_ret_uint(tree, hf_dlms_apdu, tvb, offset, 1, ENC_NA, &choice);
    offset += 1;
    switch (choice) {
    case DLMS_INITIATE_REQUEST:
        dlms_dissect_initiate_request(tvb, pinfo, tree, offset);
        break;
    case DLMS_READ_REQUEST:
        //dlms_dissect_read_request(tvb, pinfo, tree, offset);
        break;
    case DLMS_WRITE_REQUEST:
        break;
    case DLMS_INITIATE_RESPONSE:
        dlms_dissect_initiate_response(tvb, pinfo, tree, offset);
        break;
    case DLMS_READ_RESPONSE:
    case DLMS_WRITE_RESPONSE:
    case DLMS_CONFIRMED_SERVICE_ERROR:
    case DLMS_UNCONFIRMED_WRITE_REQUEST:
    case DLMS_INFORMATION_REPORT_REQUEST:
        break;
    case DLMS_AARQ:
        col_set_str(pinfo->cinfo, COL_INFO, "AARQ");
        dissect_AARQ_apdu_PDU(apdu_tvb, pinfo, tree, NULL);
        break;
    case DLMS_AARE:
        col_set_str(pinfo->cinfo, COL_INFO, "AARE");
        dissect_AARE_apdu_PDU(apdu_tvb, pinfo, tree, NULL);
        break;
    case DLMS_RLRQ:
        col_set_str(pinfo->cinfo, COL_INFO, "RLRQ");
        dissect_RLRQ_apdu_PDU(apdu_tvb, pinfo, tree, NULL);
        break;
    case DLMS_RLRE:
        col_set_str(pinfo->cinfo, COL_INFO, "RLRE");
        dissect_RLRE_apdu_PDU(apdu_tvb, pinfo, tree, NULL);
        break;
    case DLMS_GET_REQUEST:    /* 192 */
        dlms_dissect_get_request(tvb, pinfo, tree, offset);
        break;
    case DLMS_SET_REQUEST:    /*193*/
        dlms_dissect_set_request(tvb, pinfo, tree, offset);
        break;
    case DLMS_EVENT_NOTIFICATION_REQUEST: /*194 0x90*/
        dlms_dissect_event_notification_request(tvb, pinfo, tree, offset);
        break;
    case DLMS_ACTION_REQUEST: /*195*/
        dlms_dissect_action_request(tvb, pinfo, tree, offset);
        break;
    case DLMS_GET_RESPONSE:  /*196*/
        dlms_dissect_get_response(tvb, pinfo, tree, offset);
        break;
    case DLMS_SET_RESPONSE: /*197*/
        dlms_dissect_set_response(tvb, pinfo, tree, offset);
        break;
    case DLMS_ACTION_RESPONSE: /*199*/
        dlms_dissect_action_response(tvb, pinfo, tree, offset);
        break;
    case DLMS_EXCEPTION_RESPONSE: /*216*/
        dlms_dissect_exception_response(tvb, pinfo, tree, offset);
        break;
    case DLMS_ACCESS_REQUEST: /*217*/
        dlms_dissect_access_request(tvb, pinfo, tree, offset);
        break;
    case DLMS_ACCESS_RESPONSE: /*218*/
        dlms_dissect_access_response(tvb, pinfo, tree, offset);
        break;
    default:
        break;
    }
    //choice = tvb_get_uint8(tvb, offset);
    //offset += 1;
    //if (choice == DLMS_DATA_NOTIFICATION) {
    //    dlms_dissect_data_notification(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_AARQ) {
    //    dlms_dissect_aarq(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_AARE) {
    //    dlms_dissect_aare(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_RLRQ) {
    //    col_set_str(pinfo->cinfo, COL_INFO, "RLRQ");
    //}
    //else if (choice == DLMS_RLRE) {
    //    col_set_str(pinfo->cinfo, COL_INFO, "RLRE");
    //}
    //else if (choice == DLMS_GET_REQUEST) {
    //    dlms_dissect_get_request(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_SET_REQUEST) {
    //    dlms_dissect_set_request(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_EVENT_NOTIFICATION_REQUEST) {
    //    dlms_dissect_event_notification_request(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_ACTION_REQUEST) {
    //    dlms_dissect_action_request(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_GET_RESPONSE) {
    //    dlms_dissect_get_response(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_SET_RESPONSE) {
    //    dlms_dissect_set_response(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_ACTION_RESPONSE) {
    //    dlms_dissect_action_response(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_EXCEPTION_RESPONSE) {
    //    dlms_dissect_exception_response(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_ACCESS_REQUEST) {
    //    dlms_dissect_access_request(tvb, pinfo, tree, offset);
    //}
    //else if (choice == DLMS_ACCESS_RESPONSE) {
    //    dlms_dissect_access_response(tvb, pinfo, tree, offset);
    //}
    //else {
    //    col_set_str(pinfo->cinfo, COL_INFO, "Unknown APDU");
    //}
}


/* Dissect a check sequence field (HCS or FCS) of an HDLC frame */
static void
dlms_dissect_hdlc_check_sequence(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset, int length, int hf_index)
{
    int i, j;
    unsigned cs;
    proto_item* item;

    cs = 0xffff;
    for (i = 0; i < length; i++) {
        cs = cs ^ tvb_get_uint8(tvb, offset + i);
        for (j = 0; j < 8; j++) {
            if (cs & 1) {
                cs = (cs >> 1) ^ 0x8408;
            }
            else {
                cs = cs >> 1;
            }
        }
    }
    cs = cs ^ 0xffff;

    item = proto_tree_add_item(tree, hf_index, tvb, offset + length, 2, ENC_NA);
    if (tvb_get_letohs(tvb, offset + length) != cs) {
        expert_add_info(pinfo, item, &ei_dlms_check_sequence);
    }
}

/* Dissect the information field of an HDLC (SNRM or UA) frame */
static void
dlms_dissect_hdlc_information(tvbuff_t* tvb, proto_tree* tree, int offset)
{
    proto_tree* subtree;
    proto_item* ti;
    int start_offset = offset;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 0, ett_dlms_hdlc_information, &ti, "Information");
    unsigned format = tvb_get_uint8(tvb, offset);
    offset += 1;
    if (format == 0x81) { /* format identifier */
        unsigned group = tvb_get_uint8(tvb, offset);
        offset += 1;
        if (group == 0x80) { /* group identifier */
            unsigned i, length = tvb_get_uint8(tvb, offset);
            offset += 1;
            for (i = 0; i < length; ) { /* parameters */
                proto_item* item;
                unsigned parameter = tvb_get_uint8(tvb, offset);
                unsigned j, parameter_length = tvb_get_uint8(tvb, offset + 1);
                unsigned value = 0;
                for (j = 0; j < parameter_length; j++) {
                    value = (value << 8) + tvb_get_uint8(tvb, offset + 2 + j);
                }
                item = proto_tree_add_item(subtree, hf_dlms_hdlc_parameter, tvb, offset, 2 + parameter_length, ENC_NA);
                proto_item_set_text(item, "%s: %u",
                    parameter == 5 ? "Maximum Information Field Length Transmit" :
                    parameter == 6 ? "Maximum Information Field Length Receive" :
                    parameter == 7 ? "Window Size Transmit" :
                    parameter == 8 ? "Window Size Receive" :
                    "Unknown Information Field Parameter",
                    value);
                i += 2 + parameter_length;
                offset += 2 + parameter_length;
            }
        }
    }
    proto_item_set_len(ti, offset - start_offset);
}


/* Dissect a DLMS APDU in an HDLC frame */
static void
dissect_dlms_hdlc(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    proto_tree* subtree, * subsubtree;
    proto_item* item;
    fragment_head* frags;
    tvbuff_t* rtvb; /* reassembled tvb */
    unsigned length, segmentation, control;

    subtree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_dlms_hdlc, 0, "HDLC");

    /* Opening flag */
    proto_tree_add_item(subtree, hf_dlms_hdlc_flag, tvb, 0, 1, ENC_NA);

    /* Frame format field */
    subsubtree = proto_tree_add_subtree(subtree, tvb, 1, 2, ett_dlms_hdlc_format, 0, "Frame Format");
    proto_tree_add_item(subsubtree, hf_dlms_hdlc_type, tvb, 1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subsubtree, hf_dlms_hdlc_segmentation, tvb, 1, 2, ENC_BIG_ENDIAN);
    segmentation = (tvb_get_ntohs(tvb, 1) >> 11) & 1;
    proto_tree_add_item(subsubtree, hf_dlms_hdlc_length, tvb, 1, 2, ENC_BIG_ENDIAN);
    length = tvb_get_ntohs(tvb, 1) & 0x7ff; /* length of HDLC frame excluding the opening and closing flag fields */

    /* Destination address field */
    subsubtree = proto_tree_add_subtree(subtree, tvb, 3, 1, ett_dlms_hdlc_address, 0, "Destination Address");
    proto_tree_add_item(subsubtree, hf_dlms_hdlc_address, tvb, 3, 1, ENC_NA);

    /* Source address field */
    subsubtree = proto_tree_add_subtree(subtree, tvb, 4, 1, ett_dlms_hdlc_address, 0, "Source Address");
    proto_tree_add_item(subsubtree, hf_dlms_hdlc_address, tvb, 4, 1, ENC_NA);

    /* Control field */
    subsubtree = proto_tree_add_subtree(subtree, tvb, 5, 1, ett_dlms_hdlc_control, 0, "Control");
    control = tvb_get_uint8(tvb, 5);

    /* Header check sequence field */
    if (length > 7) {
        dlms_dissect_hdlc_check_sequence(tvb, pinfo, subtree, 1, 5, hf_dlms_hdlc_hcs);
    }

    /* Control sub-fields and information field */
    if ((control & 0x01) == 0x00) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC I"); /* Information */
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_frame_i, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_pf, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_rsn, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_ssn, tvb, 5, 1, ENC_NA);

        subsubtree = proto_tree_add_subtree_format(subtree, tvb, 8, length - 9, ett_dlms_hdlc_information, 0, "Information Field (length %u)", length - 9);
        frags = fragment_add_seq_next(&dlms_reassembly_table, tvb, 8, pinfo, DLMS_REASSEMBLY_ID_HDLC, 0, length - 9, segmentation);
        rtvb = process_reassembled_data(tvb, 8, pinfo, "Reassembled", frags, &dlms_fragment_items, 0, tree);
        if (rtvb) {
            proto_tree_add_item(subsubtree, hf_dlms_hdlc_llc, rtvb, 0, 3, ENC_NA);
            dlms_dissect_apdu(rtvb, pinfo, tree, 3);
        }
    }
    else if ((control & 0x0f) == 0x01) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC RR"); /* Receive Ready */
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_frame_rr_rnr, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_pf, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_rsn, tvb, 5, 1, ENC_NA);
    }
    else if ((control & 0x0f) == 0x05) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC RNR"); /* Receive Not Ready */
        item = proto_tree_add_item(subsubtree, hf_dlms_hdlc_frame_rr_rnr, tvb, 5, 1, ENC_NA);
        expert_add_info(pinfo, item, &ei_dlms_no_success);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_pf, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_rsn, tvb, 5, 1, ENC_NA);
    }
    else if ((control & 0xef) == 0x83) { /* Set Normal Response Mode */
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC SNRM");
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_frame_other, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_pf, tvb, 5, 1, ENC_NA);
        if (length > 7) {
            dlms_dissect_hdlc_information(tvb, subtree, 8);
        }
    }
    else if ((control & 0xef) == 0x43) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC DISC"); /* Disconnect */
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_frame_other, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_pf, tvb, 5, 1, ENC_NA);
    }
    else if ((control & 0xef) == 0x63) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC UA"); /* Unnumbered Acknowledge */
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_frame_other, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_pf, tvb, 5, 1, ENC_NA);
        if (length > 7) {
            dlms_dissect_hdlc_information(tvb, subtree, 8);
        }
    }
    else if ((control & 0xef) == 0x0f) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC DM"); /* Disconnected Mode */
        item = proto_tree_add_item(subsubtree, hf_dlms_hdlc_frame_other, tvb, 5, 1, ENC_NA);
        expert_add_info(pinfo, item, &ei_dlms_no_success);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_pf, tvb, 5, 1, ENC_NA);
    }
    else if ((control & 0xef) == 0x87) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC FRMR"); /* Frame Reject */
        item = proto_tree_add_item(subsubtree, hf_dlms_hdlc_frame_other, tvb, 5, 1, ENC_NA);
        expert_add_info(pinfo, item, &ei_dlms_no_success);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_pf, tvb, 5, 1, ENC_NA);
    }
    else if ((control & 0xef) == 0x03) {
        col_set_str(pinfo->cinfo, COL_INFO, "HDLC UI"); /* Unnumbered Information */
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_frame_other, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(subsubtree, hf_dlms_hdlc_pf, tvb, 5, 1, ENC_NA);
    }
    else {
        col_set_str(pinfo->cinfo, COL_INFO, "Unknown HDLC frame");
    }

    /* Frame check sequence field */
    dlms_dissect_hdlc_check_sequence(tvb, pinfo, subtree, 1, length - 2, hf_dlms_hdlc_fcs);

    /* Closing flag */
    proto_tree_add_item(subtree, hf_dlms_hdlc_flag, tvb, length + 1, 1, ENC_NA);
}

/* Dissect a DLMS APDU in an IEC 61334-4-32 convergence layer data frame (PLC) */
static void
dlms_dissect_432(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    proto_tree_add_item(tree, hf_dlms_iec432llc, tvb, 0, 3, ENC_NA);
    dlms_dissect_apdu(tvb, pinfo, tree, 3);
}

/* Dissect a DLMS APDU in a Wrapper Protocol Data Unit (TCP/UDP/IP) */
static void
dlms_dissect_wrapper(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree)
{
    proto_tree_add_item(tree, hf_dlms_wrapper, tvb, 0, 8, ENC_NA);
    dlms_dissect_apdu(tvb, pinfo, tree, 8);
}


static int
dissect_dlms(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    proto_item* item;
    proto_tree* subtree;
    unsigned first_byte;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DLMS");

    item = proto_tree_add_item(tree, proto_dlms, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(item, ett_dlms);

    first_byte = tvb_get_uint8(tvb, 0);
    if (first_byte == 0x7e) {
        dissect_dlms_hdlc(tvb, pinfo, subtree);
    }
    else if (first_byte == 0x90) {
        dlms_dissect_432(tvb, pinfo, subtree);
    }
    else if (first_byte == 0) {
        dlms_dissect_wrapper(tvb, pinfo, subtree);
    }
    else {
        dlms_dissect_apdu(tvb, pinfo, subtree, 0);
    }

    return tvb_captured_length(tvb);
}
/*--- proto_register_cosem ----------------------------------------------*/
void proto_register_cosem(void) {

    /* List of fields */
    static hf_register_info hf[] = {

    { &hf_cosem_AARQ_apdu_PDU,
      { "AARQ-apdu", "cosem.AARQ_apdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_AARE_apdu_PDU,
      { "AARE-apdu", "cosem.AARE_apdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_RLRQ_apdu_PDU,
      { "RLRQ-apdu", "cosem.RLRQ_apdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_RLRE_apdu_PDU,
      { "RLRE-apdu", "cosem.RLRE_apdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_Conformance_PDU,
      { "Conformance", "cosem.Conformance",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_protocol_version,
      { "protocol-version", "cosem.protocol_version",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_application_context_name,
      { "application-context-name", "cosem.application_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_called_AP_title,
      { "called-AP-title", "cosem.called_AP_title",
        FT_UINT32, BASE_DEC, VALS(cosem_AP_title_vals), 0,
        "AP_title", HFILL }},
    { &hf_cosem_called_AE_qualifier,
      { "called-AE-qualifier", "cosem.called_AE_qualifier",
        FT_UINT32, BASE_DEC, VALS(cosem_ASO_qualifier_vals), 0,
        "AE_qualifier", HFILL }},
    { &hf_cosem_called_AP_invocation_identifier,
      { "called-AP-invocation-identifier", "cosem.called_AP_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AP_invocation_identifier", HFILL }},
    { &hf_cosem_called_AE_invocation_identifier,
      { "called-AE-invocation-identifier", "cosem.called_AE_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AE_invocation_identifier", HFILL }},
    { &hf_cosem_calling_AP_title,
      { "calling-AP-title", "cosem.calling_AP_title",
        FT_UINT32, BASE_DEC, VALS(cosem_AP_title_vals), 0,
        "AP_title", HFILL }},
    { &hf_cosem_calling_AE_qualifier,
      { "calling-AE-qualifier", "cosem.calling_AE_qualifier",
        FT_UINT32, BASE_DEC, VALS(cosem_ASO_qualifier_vals), 0,
        "AE_qualifier", HFILL }},
    { &hf_cosem_calling_AP_invocation_identifier,
      { "calling-AP-invocation-identifier", "cosem.calling_AP_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AP_invocation_identifier", HFILL }},
    { &hf_cosem_calling_AE_invocation_identifier,
      { "calling-AE-invocation-identifier", "cosem.calling_AE_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AE_invocation_identifier", HFILL }},
    { &hf_cosem_sender_acse_requirements,
      { "sender-acse-requirements", "cosem.sender_acse_requirements",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ACSE_requirements", HFILL }},
    { &hf_cosem_mechanism_name,
      { "mechanism-name", "cosem.mechanism_name",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_calling_authentication_value,
      { "calling-authentication-value", "cosem.calling_authentication_value",
        FT_UINT32, BASE_DEC, VALS(cosem_Authentication_value_vals), 0,
        "Authentication_value", HFILL }},
    { &hf_cosem_implementation_information,
      { "implementation-information", "cosem.implementation_information",
        FT_STRING, BASE_NONE, NULL, 0,
        "Implementation_data", HFILL }},
    { &hf_cosem_user_information,
      { "user-information", "cosem.user_information",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Association_information", HFILL }},
    { &hf_cosem_protocol_version_01,
      { "protocol-version", "cosem.protocol_version",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_protocol_version_01", HFILL }},
    { &hf_cosem_aSO_context_name,
      { "aSO-context-name", "cosem.aSO_context_name",
        FT_OID, BASE_NONE, NULL, 0,
        "Application_context_name", HFILL }},
    { &hf_cosem_result,
      { "result", "cosem.result",
        FT_INT32, BASE_DEC, VALS(cosem_Association_result_vals), 0,
        "Association_result", HFILL }},
    { &hf_cosem_result_source_diagnostic,
      { "result-source-diagnostic", "cosem.result_source_diagnostic",
        FT_UINT32, BASE_DEC, VALS(cosem_Associate_source_diagnostic_vals), 0,
        "Associate_source_diagnostic", HFILL }},
    { &hf_cosem_responding_AP_title,
      { "responding-AP-title", "cosem.responding_AP_title",
        FT_UINT32, BASE_DEC, VALS(cosem_AP_title_vals), 0,
        "AP_title", HFILL }},
    { &hf_cosem_responding_AE_qualifier,
      { "responding-AE-qualifier", "cosem.responding_AE_qualifier",
        FT_UINT32, BASE_DEC, VALS(cosem_ASO_qualifier_vals), 0,
        "AE_qualifier", HFILL }},
    { &hf_cosem_responding_AP_invocation_identifier,
      { "responding-AP-invocation-identifier", "cosem.responding_AP_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AP_invocation_identifier", HFILL }},
    { &hf_cosem_responding_AE_invocation_identifier,
      { "responding-AE-invocation-identifier", "cosem.responding_AE_invocation_identifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "AE_invocation_identifier", HFILL }},
    { &hf_cosem_responder_acse_requirements,
      { "responder-acse-requirements", "cosem.responder_acse_requirements",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ACSE_requirements", HFILL }},
    { &hf_cosem_responding_authentication_value,
      { "responding-authentication-value", "cosem.responding_authentication_value",
        FT_UINT32, BASE_DEC, VALS(cosem_Authentication_value_vals), 0,
        "Authentication_value", HFILL }},
    { &hf_cosem_reason,
      { "reason", "cosem.reason",
        FT_INT32, BASE_DEC, VALS(cosem_Release_request_reason_vals), 0,
        "Release_request_reason", HFILL }},
    { &hf_cosem_reason_01,
      { "reason", "cosem.reason",
        FT_INT32, BASE_DEC, VALS(cosem_Release_response_reason_vals), 0,
        "Release_response_reason", HFILL }},
    { &hf_cosem_ap_title_form1,
      { "ap-title-form1", "cosem.ap_title_form1",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        NULL, HFILL }},
    { &hf_cosem_ap_title_form2,
      { "ap-title-form2", "cosem.ap_title_form2",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_ap_title_form3,
      { "ap-title-form3", "cosem.ap_title_form3",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_aso_qualifier_form1,
      { "aso-qualifier-form1", "cosem.aso_qualifier_form1",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_aso_qualifier_form2,
      { "aso-qualifier-form2", "cosem.aso_qualifier_form2",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_aso_qualifier_form3,
      { "aso-qualifier-form3", "cosem.aso_qualifier_form3",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_aso_qualifier_form_any_octets,
      { "aso-qualifier-form-any-octets", "cosem.aso_qualifier_form_any_octets",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ASO_qualifier_form_octets", HFILL }},
    { &hf_cosem_other_mechanism_name,
      { "other-mechanism-name", "cosem.other_mechanism_name",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cosem_other_mechanism_value,
      { "other-mechanism-value", "cosem.other_mechanism_value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cosem_charstring,
      { "charstring", "cosem.charstring",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_cosem_bitstring,
      { "bitstring", "cosem.bitstring",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_cosem_external,
      { "external", "cosem.external_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNALt", HFILL }},
    { &hf_cosem_other,
      { "other", "cosem.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Authentication_value_other", HFILL }},
    { &hf_cosem_direct_reference,
      { "direct-reference", "cosem.direct_reference",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cosem_indirect_reference,
      { "indirect-reference", "cosem.indirect_reference",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cosem_data_value_descriptor,
      { "data-value-descriptor", "cosem.data_value_descriptor",
        FT_STRING, BASE_NONE, NULL, 0,
        "ObjectDescriptor", HFILL }},
    { &hf_cosem_encoding,
      { "encoding", "cosem.encoding",
        FT_UINT32, BASE_DEC, VALS(cosem_T_encoding_vals), 0,
        NULL, HFILL }},
    { &hf_cosem_single_ASN1_type,
      { "single-ASN1-type", "cosem.single_ASN1_type",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cosem_octet_aligned,
      { "octet-aligned", "cosem.octet_aligned",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cosem_arbitrary,
      { "arbitrary", "cosem.arbitrary",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_cosem_acse_service_user,
      { "acse-service-user", "cosem.acse_service_user",
        FT_INT32, BASE_DEC, VALS(cosem_T_acse_service_user_vals), 0,
        NULL, HFILL }},
    { &hf_cosem_acse_service_provider,
      { "acse-service-provider", "cosem.acse_service_provider",
        FT_INT32, BASE_DEC, VALS(cosem_T_acse_service_provider_vals), 0,
        NULL, HFILL }},
    { &hf_cosem_T_protocol_version_version1,
      { "version1", "cosem.T.protocol.version.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cosem_T_protocol_version_01_version1,
      { "version1", "cosem.T.protocol.version.01.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cosem_ACSE_requirements_authentication,
      { "authentication", "cosem.ACSE.requirements.authentication",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cosem_ACSE_requirements_aSO_context_negotiation,
      { "aSO-context-negotiation", "cosem.ACSE.requirements.aSO.context.negotiation",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cosem_ACSE_requirements_higher_level_association,
      { "higher-level-association", "cosem.ACSE.requirements.higher.level.association",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cosem_ACSE_requirements_nested_association,
      { "nested-association", "cosem.ACSE.requirements.nested.association",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_reserved0,
      { "reserved0", "cosem.Conformance.U.reserved0",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_reserved1,
      { "reserved1", "cosem.Conformance.U.reserved1",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_reserved2,
      { "reserved2", "cosem.Conformance.U.reserved2",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_read,
      { "read", "cosem.Conformance.U.read",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_write,
      { "write", "cosem.Conformance.U.write",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_unconfirmed_write,
      { "unconfirmed-write", "cosem.Conformance.U.unconfirmed.write",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_reserved6,
      { "reserved6", "cosem.Conformance.U.reserved6",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_reserved7,
      { "reserved7", "cosem.Conformance.U.reserved7",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_attribute0_supported_with_SET,
      { "attribute0-supported-with-SET", "cosem.Conformance.U.attribute0.supported.with.SET",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_priority_mgmt_supported,
      { "priority-mgmt-supported", "cosem.Conformance.U.priority.mgmt.supported",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_attribute0_supported_with_GET,
      { "attribute0-supported-with-GET", "cosem.Conformance.U.attribute0.supported.with.GET",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_block_transfer_with_get,
      { "block-transfer-with-get", "cosem.Conformance.U.block.transfer.with.get",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_block_transfer_with_set,
      { "block-transfer-with-set", "cosem.Conformance.U.block.transfer.with.set",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_block_transfer_with_action,
      { "block-transfer-with-action", "cosem.Conformance.U.block.transfer.with.action",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_multiple_references,
      { "multiple-references", "cosem.Conformance.U.multiple.references",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_information_report,
      { "information-report", "cosem.Conformance.U.information.report",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_reserved16,
      { "reserved16", "cosem.Conformance.U.reserved16",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_reserved17,
      { "reserved17", "cosem.Conformance.U.reserved17",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_parameterized_access,
      { "parameterized-access", "cosem.Conformance.U.parameterized.access",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_get,
      { "get", "cosem.Conformance.U.get",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_set,
      { "set", "cosem.Conformance.U.set",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_selective_access,
      { "selective-access", "cosem.Conformance.U.selective.access",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_event_notification,
      { "event-notification", "cosem.Conformance.U.event.notification",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_cosem_Conformance_U_action,
      { "action", "cosem.Conformance.U.action",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    };

    /* List of subtrees */
    static int *ett[] = {
            &ett_cosem,
    &ett_cosem_AARQ_apdu_U,
    &ett_cosem_T_protocol_version,
    &ett_cosem_AARE_apdu_U,
    &ett_cosem_T_protocol_version_01,
    &ett_cosem_RLRQ_apdu_U,
    &ett_cosem_RLRE_apdu_U,
    &ett_cosem_ACSE_requirements,
    &ett_cosem_AP_title,
    &ett_cosem_ASO_qualifier,
    &ett_cosem_Authentication_value_other,
    &ett_cosem_Authentication_value,
    &ett_cosem_EXTERNALt_U,
    &ett_cosem_T_encoding,
    &ett_cosem_Associate_source_diagnostic,
    &ett_cosem_Conformance_U,

    };

    /* Register protocol */
    proto_cosem = proto_register_protocol(PNAME, PSNAME, PFNAME);
    proto_dlms = proto_register_protocol("Device Language Message Specification", "DLMS", "dlms");

    cosem_handle = register_dissector(PFNAME, dissect_cosem, proto_cosem);

    proto_register_field_array(proto_cosem, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    static hf_register_info hf_dlms[] = {
    { &hf_dlms_hdlc_flag,
      { "Flag", "dlms.hdlc.flag",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
    { &hf_dlms_hdlc_type,
        { "Type", "dlms.hdlc.type",
        FT_UINT16, BASE_DEC, NULL, 0xf000,
        NULL, HFILL }},
    { &hf_dlms_hdlc_segmentation,
        { "Segmentation", "dlms.hdlc.segmentation",
        FT_UINT16, BASE_DEC, NULL, 0x0800,
        NULL, HFILL }},
    { &hf_dlms_hdlc_length,
    { "Length", "dlms.hdlc.length",
        FT_UINT16, BASE_DEC, NULL, 0x07ff,
        NULL, HFILL }},
    { &hf_dlms_hdlc_address,
        { "Upper HDLC Address", "dlms.hdlc.address",
        FT_UINT8, BASE_DEC, NULL, 0xfe,
        NULL, HFILL }},
    { &hf_dlms_hdlc_frame_i,
    { "Frame(I): I (Information) (0)", "dlms.hdlc.frame_i", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
    { &hf_dlms_hdlc_frame_rr_rnr,
    { "Frame(RR or RNR)", "dlms.hdlc.frame_rr_or_rnr", FT_UINT8, BASE_DEC, VALS(dlms_hdlc_frame_names), 0x0f, NULL, HFILL }},
    { &hf_dlms_hdlc_frame_other,
    { "Frame(all other)", "dlms.hdlc.frame_other", FT_UINT8, BASE_DEC, VALS(dlms_hdlc_frame_names), 0xef, NULL, HFILL }},
    { &hf_dlms_hdlc_pf,
    { "Poll/Final", "dlms.hdlc.pf", FT_UINT8, BASE_DEC, NULL, 0x10, NULL, HFILL }},
    { &hf_dlms_hdlc_rsn,
    { "Receive Sequence Number", "dlms.hdlc.rsn", FT_UINT8, BASE_DEC, NULL, 0xe0, NULL, HFILL }},
    { &hf_dlms_hdlc_ssn,
    { "Send Sequence Number", "dlms.hdlc.ssn", FT_UINT8, BASE_DEC, NULL, 0x0e, NULL, HFILL }},
    { &hf_dlms_hdlc_hcs,
    { "Header Check Sequence", "dlms.hdlc.hcs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_hdlc_fcs,
    { "Frame Check Sequence", "dlms.hdlc.fcs", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_hdlc_parameter,
    { "Parameter", "dlms.hdlc.parameter", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_hdlc_llc,
    { "LLC Header", "dlms.hdlc.llc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    /* IEC 4-32 LLC */
    { &hf_dlms_iec432llc,
    { "IEC 4-32 LLC Header", "dlms.iec432llc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    /* Wrapper Protocol Data Unit (WPDU) */
    { &hf_dlms_wrapper,
    { "Wrapper Header", "dlms.wrapper", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    /* APDU */
    { &hf_dlms_apdu,
    { "APDU", "dlms.apdu", FT_UINT8, BASE_DEC, VALS(dlms_apdu_names), 0x0, NULL, HFILL }},
    { &hf_dlms_client_max_receive_pdu_size,
    { "Client Max Receive PDU Size", "dlms.client_max_receive_pdu_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_server_max_receive_pdu_size,
    { "Server Max Receive PDU Size", "dlms.server_max_receive_pdu_size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_get_request,
    { "Get Request", "dlms.get_request", FT_UINT8, BASE_DEC, VALS(dlms_get_request_names), 0x0, NULL, HFILL }},
    { &hf_dlms_set_request,
    { "Set Request", "dlms.set_request", FT_UINT8, BASE_DEC, VALS(dlms_set_request_names), 0x0, NULL, HFILL }},
    { &hf_dlms_get_response,
    { "Get Response", "dlms.get_response", FT_UINT8, BASE_DEC, VALS(dlms_get_response_names), 0x0, NULL, HFILL }},
    { &hf_dlms_set_response,
    { "Set Response", "dlms.set_response", FT_UINT8, BASE_DEC, VALS(dlms_set_response_names), 0x0, NULL, HFILL }},
    { &hf_dlms_action_request,
    { "Action Request", "dlms.action_request", FT_UINT8, BASE_DEC, VALS(dlms_action_request_names), 0x0, NULL, HFILL }},
    { &hf_dlms_action_response,
    { "Action Response", "dlms.action_response", FT_UINT8, BASE_DEC, VALS(dlms_action_response_names), 0x0, NULL, HFILL }},
    { &hf_dlms_access_request,
    { "Access Request", "dlms.access_request", FT_UINT8, BASE_DEC, VALS(dlms_access_request_names), 0x0, NULL, HFILL }},
    { &hf_dlms_access_response,
    { "Access Response", "dlms.access_response", FT_UINT8, BASE_DEC, VALS(dlms_access_response_names), 0x0, NULL, HFILL }},
    { &hf_dlms_class_id,
    { "Class Id", "dlms.class_id", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_instance_id,
    { "Instance Id", "dlms.instance_id", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_attribute_id,
    { "Attribute Id", "dlms.attribute_id", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_method_id,
    { "Method Id", "dlms.method_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_access_selector,
    { "Access Selector", "dlms.access_selector", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_data_access_result,
    { "Data Access Result", "dlms.data_access_result", FT_UINT8, BASE_DEC, VALS(dlms_data_access_result_names), 0x0, NULL, HFILL }},
    { &hf_dlms_action_result,
    { "Action Result", "dlms.action_result", FT_UINT8, BASE_DEC, VALS(dlms_action_result_names), 0x0, NULL, HFILL }},
    { &hf_dlms_block_number,
    { "Block Number", "dlms.block_number", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_last_block,
    { "Last Block", "dlms.last_block", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_type_description,
    { "Type Description", "dlms.type_description", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_data,
    { "Data", "dlms.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_date_time,
    { "Date-Time", "dlms.date_time", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_length,
    { "Length", "dlms.length", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_state_error,
    { "State Error", "dlms.state_error", FT_UINT8, BASE_DEC, VALS(dlms_state_error_names), 0x0, NULL, HFILL }},
    { &hf_dlms_service_error,
    { "Service Error", "dlms.service_error", FT_UINT8, BASE_DEC, VALS(dlms_service_error_names), 0x0, NULL, HFILL }},
    /* Invoke-Id-And-Priority */
    { &hf_dlms_invoke_id,
    { "Invoke Id", "dlms.invoke_id", FT_UINT8, BASE_DEC, NULL, 0x0f, NULL, HFILL }},
    { &hf_dlms_service_class,
    { "Service Class", "dlms.service_class", FT_BOOLEAN, 8, TFS(&tfs_confirmed_unconfirmed), 0x40, NULL, HFILL }},
    { &hf_dlms_priority,
    { "Priority", "dlms.priority", FT_BOOLEAN, 32, TFS(&tfs_high_normal), 0x80, NULL, HFILL }},
    /* Long-Invoke-Id-And-Priority */
    { &hf_dlms_long_invoke_id,
    { "Long Invoke Id", "dlms.long_invoke_id", FT_UINT32, BASE_DEC, NULL, 0xffffff, NULL, HFILL }},
    { &hf_dlms_self_descriptive,
    { "Self Descriptive", "dlms.self_descriptive", FT_UINT32, BASE_DEC, VALS(dlms_self_descriptive_names), 0x10000000, NULL, HFILL }},
    { &hf_dlms_processing_option,
    { "Processing Option", "dlms.processing_option", FT_UINT32, BASE_DEC, VALS(dlms_processing_option_names), 0x20000000, NULL, HFILL }},
    { &hf_dlms_long_service_class,
    { "Service Class", "dlms.service_class", FT_BOOLEAN, 32, TFS(&tfs_confirmed_unconfirmed), 0x40000000, NULL, HFILL }},
    { &hf_dlms_long_priority,
    { "Priority", "dlms.priority", FT_BOOLEAN, 32, TFS(&tfs_high_normal), 0x80000000, NULL, HFILL }},
    /* fragment_items */
    { &hf_dlms_fragments,
    { "Fragments", "dlms.fragments", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_fragment,
    { "Fragment", "dlms.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_fragment_overlap,
    { "Fragment Overlap", "dlms.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
    { &hf_dlms_fragment_conflict,
    { "Fragment Conflict", "dlms.fragment.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
    { &hf_dlms_fragment_multiple_tails,
    { "Fragment Multiple", "dlms.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
    { &hf_dlms_fragment_too_long,
    { "Fragment Too Long", "dlms.fragment.too_long", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
    { &hf_dlms_fragment_error,
    { "Fragment Error", "dlms.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_fragment_count,
    { "Fragment Count", "dlms.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_reassembled_in,
    { "Reassembled In", "dlms_reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_reassembled_length,
    { "Reassembled Length", "dlms.reassembled_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_reassembled_data,
    { "Reassembled Data", "dlms.reassembled_data", FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL }},
    { &hf_dlms_dedicated_key,
    { "dedicated-key", "dlms.dedicated_key", FT_BYTES, SEP_SPACE, NULL, 0x0, NULL, HFILL } },
    { &hf_dlms_response_allowed,
    { "response-allowed", "dlms.response_allowed", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_dlms_proposed_quality_of_service,
    { "proposed-quality-of-service", "dlms.proposed_quality_of_service.count", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_dlms_proposed_dlms_version_number,
    { "proposed-dlms-version-number", "dlms.proposed_dlms_version_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_dlms_negotiated_quality_of_service,
    { "negotiated-quality-of-service", "dlms.negotiated_quality_of_service", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_dlms_negotiated_dlms_version_number,
    { "negotiated-dlms-version-number", "dlms.negotiated_dlms_version_number", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
    { &hf_dlms_object_name,
    { "ObjectName", "dlms.objectname", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },

    };

    static int* ett_dlms_array[] = {
            &ett_dlms,
            &ett_dlms_hdlc,
            &ett_dlms_hdlc_format,
            &ett_dlms_hdlc_address,
            &ett_dlms_hdlc_control,
            &ett_dlms_hdlc_information,
            &ett_dlms_invoke_id_and_priority,
            &ett_dlms_access_request_specification,
            &ett_dlms_access_request,
            &ett_dlms_access_response_specification,
            &ett_dlms_access_response,
            &ett_dlms_cosem_attribute_or_method_descriptor,
            &ett_dlms_selective_access_descriptor,
            &ett_dlms_composite_data,
            &ett_dlms_user_information, /* AARQ and AARE user-information field */
            &ett_dlms_conformance, /* InitiateRequest proposed-conformance and InitiateResponse negotiated-confirmance */
            &ett_dlms_datablock,
            &ett_dlms_data,
            /* fragment_items */
            &ett_dlms_fragment,
            &ett_dlms_fragments,
    };

    /* Register the dlms_ei expert info fields */
    static ei_register_info ei[] = {
        { &ei_dlms_no_success, { "dlms.no_success", PI_RESPONSE_CODE, PI_NOTE, "No success response", EXPFILL } },
        { &ei_dlms_not_implemented, { "dlms.not_implemented", PI_UNDECODED, PI_WARN, "Not implemented in the DLMS dissector", EXPFILL } },
        { &ei_dlms_check_sequence, { "dlms.check_sequence", PI_CHECKSUM, PI_WARN, "Bad HDLC check sequence field value", EXPFILL } },
    };

    expert_module_t* expert_dlms = expert_register_protocol(proto_dlms);

    expert_register_field_array(expert_dlms, ei, array_length(ei));

    static const reassembly_table_functions dlms_reassembly_functions = {
        dlms_reassembly_hash_func,
        dlms_reassembly_equal_func,
        dlms_reassembly_key_func,
        dlms_reassembly_key_func,
        dlms_reassembly_free_key_func,
        dlms_reassembly_free_key_func,
    };

    reassembly_table_init(&dlms_reassembly_table, &dlms_reassembly_functions);

    dlms_handle = register_dissector("dlms", dissect_dlms, proto_dlms);
    /* Register fields and subtrees */
    proto_register_field_array(proto_dlms, hf_dlms, array_length(hf_dlms));
    proto_register_subtree_array(ett_dlms_array, array_length(ett_dlms_array));

}


/*--- proto_reg_handoff_cosem -------------------------------------------*/
void proto_reg_handoff_cosem(void) {

    dissector_add_uint_with_preference("udp.port", DLMS_PORT, dlms_handle);
    dissector_add_uint_with_preference("tcp.port", DLMS_PORT, dlms_handle);

    acse_handle = find_dissector("acse");

    oid_add_from_string("Logical Name Referencing, Without Ciphering", "2.16.756.5.8.1.1");
    oid_add_from_string("Short Name Referencing, Without Ciphering", "2.16.756.5.8.1.2");
    oid_add_from_string("Logical Name Referencing, With Ciphering", "2.16.756.5.8.1.3");
    oid_add_from_string("Short Name Referencing, Without Ciphering", "2.16.756.5.8.1.4");

    oid_add_from_string("Lowest Level Security", "2.16.756.5.8.2.0");
    oid_add_from_string("LLS", "2.16.756.5.8.2.1");
    oid_add_from_string("HLS - Vendor Proprietary", "2.16.756.5.8.2.2");
    oid_add_from_string("HLS - MD5", "2.16.756.5.8.2.3");
    oid_add_from_string("HLS - SHA1", "2.16.756.5.8.2.4");
    oid_add_from_string("HLS - GMAC", "2.16.756.5.8.2.5");

}
