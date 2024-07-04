/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-gdt.c                                                               */
/* asn2wrs.py -b -q -L -p gdt -c ./gdt.cnf -s ./packet-gdt-template -D . -O ../.. gdt.asn */

/* packet-gdt-template.c
 *
 * Copyright 2022, Damir Franusic <damir.franusic@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


# include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/sctpppids.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-gdt.h"

#define PNAME  "Generic Data Transfer Protocol"
#define PSNAME "GDT"
#define PFNAME "gdt"

/* Initialize the protocol and registered fields */
static int proto_gdt;
static dissector_handle_t gdt_handle;

static int hf_gdt_GDTMessage_PDU;                 /* GDTMessage */
static int hf_gdt_version;                        /* INTEGER */
static int hf_gdt_source;                         /* EndPointDescriptor */
static int hf_gdt_destination;                    /* EndPointDescriptor */
static int hf_gdt_uuid;                           /* OCTET_STRING */
static int hf_gdt_sequence_num;                   /* INTEGER */
static int hf_gdt_sequence_flag;                  /* SequenceFlag */
static int hf_gdt_enc_info;                       /* EncryptionInfo */
static int hf_gdt_hop_info;                       /* HopInfo */
static int hf_gdt_status;                         /* ErrorCode */
static int hf_gdt_type;                           /* IA5String */
static int hf_gdt_end_point_id;                   /* IA5String */
static int hf_gdt_encrypted_data;                 /* OCTET_STRING */
static int hf_gdt_packet_fwd;                     /* PacketFwdMessage */
static int hf_gdt_filter;                         /* FilterMessage */
static int hf_gdt_data_retention;                 /* DataRetentionMessage */
static int hf_gdt_conf;                           /* ConfigMessage */
static int hf_gdt_stats;                          /* StatsMessage */
static int hf_gdt_auth;                           /* AuthMessage */
static int hf_gdt_reg;                            /* RegistrationMessage */
static int hf_gdt_ntfy;                           /* NotifyMessage */
static int hf_gdt_data;                           /* DataMessage */
static int hf_gdt_routing;                        /* RoutingMessage */
static int hf_gdt_service_msg;                    /* ServiceMessage */
static int hf_gdt_state_msg;                      /* StateMessage */
static int hf_gdt_stmch_id;                       /* OCTET_STRING */
static int hf_gdt_state_action;                   /* StateAction */
static int hf_gdt_params;                         /* Parameters */
static int hf_gdt_service_id;                     /* ServiceId */
static int hf_gdt_service_action;                 /* ServiceAction */
static int hf_gdt_routing_action;                 /* RoutingAction */
static int hf_gdt_reg_action;                     /* RegistrationAction */
static int hf_gdt_stats_action;                   /* StatsAction */
static int hf_gdt_auth_action;                    /* AuthAction */
static int hf_gdt_payload_type;                   /* PayloadType */
static int hf_gdt_payload;                        /* OCTET_STRING */
static int hf_gdt_dr_action;                      /* DataRetentionAction */
static int hf_gdt_filter_action;                  /* FilterAction */
static int hf_gdt_message_type;                   /* NotifyMessageType */
static int hf_gdt_message;                        /* OCTET_STRING */
static int hf_gdt_action;                         /* ConfigAction */
static int hf_gdt_parameter_type_id;              /* ParameterType */
static int hf_gdt_value;                          /* T_value */
static int hf_gdt_value_item;                     /* OCTET_STRING */
static int hf_gdt_Parameters_item;                /* Parameter */
static int hf_gdt_current_hop;                    /* INTEGER */
static int hf_gdt_max_hops;                       /* INTEGER */
static int hf_gdt_header;                         /* Header */
static int hf_gdt_body;                           /* Body */
static int hf_gdt_enc_type;                       /* OCTET_STRING */

/* Initialize the subtree pointers */
static int ett_gdt;
static int ett_gdt_Header;
static int ett_gdt_EndPointDescriptor;
static int ett_gdt_Body;
static int ett_gdt_StateMessage;
static int ett_gdt_ServiceMessage;
static int ett_gdt_RoutingMessage;
static int ett_gdt_RegistrationMessage;
static int ett_gdt_StatsMessage;
static int ett_gdt_AuthMessage;
static int ett_gdt_DataRetentionMessage;
static int ett_gdt_FilterMessage;
static int ett_gdt_PacketFwdMessage;
static int ett_gdt_NotifyMessage;
static int ett_gdt_DataMessage;
static int ett_gdt_ConfigMessage;
static int ett_gdt_Parameter;
static int ett_gdt_T_value;
static int ett_gdt_Parameters;
static int ett_gdt_HopInfo;
static int ett_gdt_GDTMessage;
static int ett_gdt_EncryptionInfo;



static int
dissect_gdt_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gdt_IA5String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t EndPointDescriptor_sequence[] = {
  { &hf_gdt_type            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gdt_IA5String },
  { &hf_gdt_end_point_id    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gdt_IA5String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_EndPointDescriptor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EndPointDescriptor_sequence, hf_index, ett_gdt_EndPointDescriptor);

  return offset;
}



static int
dissect_gdt_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string gdt_SequenceFlag_vals[] = {
  {   0, "sf-start" },
  {   1, "sf-continue" },
  {   2, "sf-end" },
  {   3, "sf-stateless-no-reply" },
  {   4, "sf-stateless" },
  {   5, "sf-stream-complete" },
  {   6, "sf-continue-wait" },
  {   7, "sf-heartbeat" },
  { 0, NULL }
};


static int
dissect_gdt_SequenceFlag(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string gdt_ParameterType_vals[] = {
  { 6000, "pt-mink-daemon-type" },
  { 6001, "pt-mink-daemon-id" },
  { 6002, "pt-mink-auth-id" },
  { 6003, "pt-mink-auth-password" },
  { 6004, "pt-mink-daemon-ip" },
  { 6005, "pt-mink-daemon-port" },
  { 6006, "pt-mink-daemon-description" },
  { 6007, "pt-mink-action" },
  { 6008, "pt-mink-dpi" },
  { 6009, "pt-mink-spi" },
  { 6010, "pt-mink-timestamp" },
  { 6011, "pt-mink-timestamp-nsec" },
  { 6012, "pt-mink-security-phase" },
  { 6013, "pt-mink-loop-count" },
  { 6014, "pt-mink-checksum" },
  { 6015, "pt-mink-timeout" },
  { 6016, "pt-mink-error" },
  { 6017, "pt-mink-error-msg" },
  { 6018, "pt-mink-status" },
  { 6019, "pt-mink-status-msg" },
  { 6020, "pt-mink-persistent-correlation" },
  { 6100, "pt-mink-routing-destination" },
  { 6101, "pt-mink-routing-source" },
  { 6102, "pt-mink-routing-gateway" },
  { 6103, "pt-mink-routing-interface" },
  { 6104, "pt-mink-routing-priority" },
  { 6105, "pt-mink-router-status" },
  { 6106, "pt-mink-routing-destination-type" },
  { 6107, "pt-mink-routing-index" },
  { 6108, "pt-mink-trunk-label" },
  { 6109, "pt-mink-connection-type" },
  { 6110, "pt-mink-service-id" },
  { 6111, "pt-mink-command-id" },
  { 6112, "pt-mink-routing-sub-destination" },
  { 6113, "pt-mink-routing-sub-destination-type" },
  { 6114, "pt-mink-correlation-notification" },
  { 6115, "pt-mink-guid" },
  { 6116, "pt-mink-routing-service-id" },
  { 6200, "pt-mink-event-id" },
  { 6201, "pt-mink-event-description" },
  { 6202, "pt-mink-event-callback-id" },
  { 6203, "pt-mink-event-callback-priority" },
  { 6300, "pt-mink-enc-public-key" },
  { 6301, "pt-mink-enc-private-key" },
  { 6302, "pt-mink-enc-type" },
  { 6400, "pt-mink-stats-id" },
  { 6401, "pt-mink-stats-description" },
  { 6402, "pt-mink-stats-value" },
  { 6403, "pt-mink-stats-count" },
  { 7400, "pt-mink-config-param-name" },
  { 7401, "pt-mink-config-param-value" },
  { 7402, "pt-mink-config-ac-line" },
  { 7403, "pt-mink-config-cfg-item-name" },
  { 7404, "pt-mink-config-cfg-item-desc" },
  { 7405, "pt-mink-config-cfg-item-ns" },
  { 7406, "pt-mink-config-cfg-item-value" },
  { 7407, "pt-mink-config-cfg-item-nvalue" },
  { 7408, "pt-mink-config-cfg-item-nt" },
  { 7409, "pt-mink-config-cfg-cm-mode" },
  { 7410, "pt-mink-config-cfg-ac-err" },
  { 7411, "pt-mink-config-cli-path" },
  { 7412, "pt-mink-config-cfg-line" },
  { 7413, "pt-mink-config-ac-err-count" },
  { 7414, "pt-mink-config-cfg-line-count" },
  { 7415, "pt-mink-config-cfg-item-path" },
  { 7416, "pt-mink-config-cfg-item-notify" },
  { 7417, "pt-mink-config-cfg-item-count" },
  { 7418, "pt-mink-config-replication-line" },
  { 7500, "pt-mink-sms-status" },
  { 7501, "pt-mink-sms-uuid" },
  { 7600, "pt-mink-filter-result" },
  { 7601, "pt-mink-filter-exit" },
  { 7602, "pt-mink-filter-list-id" },
  { 7603, "pt-mink-filter-list-label" },
  { 7604, "pt-mink-filter-data" },
  { 7605, "pt-mink-filter-data-size" },
  { 600, "pt-eth-destination-mac" },
  { 601, "pt-eth-source-mac" },
  { 700, "pt-ip-destination-ip" },
  { 701, "pt-ip-source-ip" },
  { 800, "pt-tcp-destination-port" },
  { 801, "pt-tcp-source-port" },
  { 900, "pt-udp-destination-port" },
  { 901, "pt-udp-source-port" },
  { 1000, "pt-sctp-destination-port" },
  { 1001, "pt-sctp-source-port" },
  { 500, "pt-gsmmap-scoa-digits" },
  { 501, "pt-gsmmap-scoa-type-of-number" },
  { 502, "pt-gsmmap-scoa-numbering-plan" },
  { 503, "pt-gsmmap-scda-digits" },
  { 504, "pt-gsmmap-scda-type-of-number" },
  { 505, "pt-gsmmap-scda-numbering-plan" },
  { 506, "pt-gsmmap-imsi" },
  { 507, "pt-gsmmap-msisdn-digits" },
  { 508, "pt-gsmmap-msisdn-type-of-number" },
  { 509, "pt-gsmmap-msisdn-numbering-plan" },
  { 510, "pt-tcap-source-transaction-id" },
  { 511, "pt-tcap-destination-transaction-id" },
  { 512, "pt-tcap-opcode" },
  { 513, "pt-tcap-component-type" },
  { 514, "pt-tcap-component-invoke-id" },
  { 515, "pt-tcap-error-type" },
  { 516, "pt-tcap-error-code" },
  { 517, "pt-tcap-dialogue-context-oid" },
  { 518, "pt-tcap-message-type" },
  { 519, "pt-gsmmap-nnn-digits" },
  { 520, "pt-gsmmap-nnn-type-of-number" },
  { 521, "pt-gsmmap-nnn-numbering-plan" },
  { 522, "pt-gsmmap-an-digits" },
  { 523, "pt-gsmmap-an-type-of-number" },
  { 524, "pt-gsmmap-an-numbering-plan" },
  { 525, "pt-gsmmap-sca-digits" },
  { 526, "pt-gsmmap-sca-type-of-number" },
  { 527, "pt-gsmmap-sca-numbering-plan" },
  { 528, "pt-tcap-component-count" },
  { 529, "pt-tcap-dialogue-context-supported" },
  { 530, "pt-tcap-component-index" },
  { 531, "pt-tcap-source-transaction-id-length" },
  { 532, "pt-tcap-destination-transaction-id-length" },
  { 533, "pt-gsmmap-version" },
  { 400, "pt-smstpdu-tp-udhi" },
  { 401, "pt-smstpdu-tp-sri" },
  { 402, "pt-smstpdu-tp-mms" },
  { 403, "pt-smstpdu-tp-mti" },
  { 404, "pt-smstpdu-tp-oa-type-of-number" },
  { 405, "pt-smstpdu-tp-oa-numbering-plan" },
  { 406, "pt-smstpdu-tp-oa-digits" },
  { 407, "pt-smstpdu-tp-pid" },
  { 408, "pt-smstpdu-tp-dcs" },
  { 409, "pt-smstpdu-tp-scts" },
  { 410, "pt-smstpdu-tp-udl" },
  { 411, "pt-smstpdu-tp-ud" },
  { 412, "pt-smstpdu-tp-rp" },
  { 413, "pt-smstpdu-tp-srr" },
  { 414, "pt-smstpdu-tp-vpf" },
  { 415, "pt-smstpdu-tp-rd" },
  { 416, "pt-smstpdu-tp-da-type-of-number" },
  { 417, "pt-smstpdu-tp-da-numbering-plan" },
  { 418, "pt-smstpdu-tp-da-digits" },
  { 419, "pt-smstpdu-tp-vp" },
  { 420, "pt-smstpdu-msg-id" },
  { 421, "pt-smstpdu-msg-parts" },
  { 422, "pt-smstpdu-msg-part" },
  { 423, "pt-smstpdu-tp-mr" },
  { 424, "pt-smstpdu-message-class" },
  { 300, "pt-sccp-destination-local-reference" },
  { 301, "pt-sccp-source-local-reference" },
  { 302, "pt-sccp-called-party" },
  { 303, "pt-sccp-calling-party" },
  { 304, "pt-sccp-protocol-class" },
  { 305, "pt-sccp-segmenting-reassembling" },
  { 306, "pt-sccp-receive-sequence-number" },
  { 307, "pt-sccp-sequencing-segmenting" },
  { 308, "pt-sccp-credit" },
  { 309, "pt-sccp-release-cause" },
  { 310, "pt-sccp-return-cause" },
  { 311, "pt-sccp-reset-cause" },
  { 312, "pt-sccp-error-cause" },
  { 313, "pt-sccp-refusal-cause" },
  { 314, "pt-sccp-data" },
  { 315, "pt-sccp-segmentation" },
  { 316, "pt-sccp-hop-counter" },
  { 317, "pt-sccp-importance" },
  { 318, "pt-sccp-long-data" },
  { 319, "pt-sccp-called-pa-routing-indicator" },
  { 320, "pt-sccp-called-pa-global-title-indicator" },
  { 321, "pt-sccp-called-pa-ssn-indicator" },
  { 322, "pt-sccp-called-pa-point-code-indicator" },
  { 323, "pt-sccp-called-pa-point-code-number" },
  { 324, "pt-sccp-called-pa-subsystem-number" },
  { 325, "pt-sccp-called-pa-gt-numbering-plan" },
  { 326, "pt-sccp-called-pa-gt-encoding-scheme" },
  { 327, "pt-sccp-called-pa-gt-nature-of-address" },
  { 328, "pt-sccp-called-pa-gt-address" },
  { 329, "pt-sccp-called-pa-gt-translation-type" },
  { 330, "pt-sccp-calling-pa-routing-indicator" },
  { 331, "pt-sccp-calling-pa-global-title-indicator" },
  { 332, "pt-sccp-calling-pa-ssn-indicator" },
  { 333, "pt-sccp-calling-pa-point-code-indicator" },
  { 334, "pt-sccp-calling-pa-point-code-number" },
  { 335, "pt-sccp-calling-pa-subsystem-number" },
  { 336, "pt-sccp-calling-pa-gt-numbering-plan" },
  { 337, "pt-sccp-calling-pa-gt-encoding-scheme" },
  { 338, "pt-sccp-calling-pa-gt-nature-of-address" },
  { 339, "pt-sccp-calling-pa-gt-address" },
  { 340, "pt-sccp-calling-pa-gt-translation-type" },
  { 341, "pt-sccp-message-type" },
  { 200, "pt-m3ua-info-string" },
  { 201, "pt-m3ua-routing-context" },
  { 202, "pt-m3ua-diagnostic-info" },
  { 203, "pt-m3ua-heartbeat" },
  { 204, "pt-m3ua-traffic-mode-type" },
  { 205, "pt-m3ua-error-code" },
  { 206, "pt-m3ua-status" },
  { 207, "pt-m3ua-asp-identifier" },
  { 208, "pt-m3ua-affected-point-code" },
  { 209, "pt-m3ua-correlation-id" },
  { 210, "pt-m3ua-network-appearance" },
  { 211, "pt-m3ua-user-cause" },
  { 212, "pt-m3ua-congestion-indications" },
  { 213, "pt-m3ua-concerned-destination" },
  { 214, "pt-m3ua-routing-key" },
  { 215, "pt-m3ua-registration-result" },
  { 216, "pt-m3ua-deregistration-result" },
  { 217, "pt-m3ua-local-routing-key-identifier" },
  { 218, "pt-m3ua-destination-point-code" },
  { 219, "pt-m3ua-service-indicators" },
  { 220, "pt-m3ua-origination-point-code-list" },
  { 221, "pt-m3ua-circuit-range" },
  { 222, "pt-m3ua-protocol-data" },
  { 223, "pt-m3ua-protocol-data-service-indicator" },
  { 224, "pt-m3ua-protocol-data-network-indicator" },
  { 225, "pt-m3ua-protocol-data-message-priority" },
  { 226, "pt-m3ua-protocol-data-destination-point-code" },
  { 227, "pt-m3ua-protocol-data-originating-point-code" },
  { 228, "pt-m3ua-protocol-data-signalling-link-selection-code" },
  { 229, "pt-m3ua-registration-status" },
  { 230, "pt-m3ua-deregistration-status" },
  { 231, "pt-m3ua-header-data" },
  { 232, "pt-m3ua-as-label" },
  { 233, "pt-m3ua-asp-label" },
  { 0, NULL }
};


static int
dissect_gdt_ParameterType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_value_sequence_of[1] = {
  { &hf_gdt_value_item      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gdt_OCTET_STRING },
};

static int
dissect_gdt_T_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_value_sequence_of, hf_index, ett_gdt_T_value);

  return offset;
}


static const ber_sequence_t Parameter_sequence[] = {
  { &hf_gdt_parameter_type_id, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_ParameterType },
  { &hf_gdt_value           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_T_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_Parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Parameter_sequence, hf_index, ett_gdt_Parameter);

  return offset;
}


static const ber_sequence_t Parameters_sequence_of[1] = {
  { &hf_gdt_Parameters_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gdt_Parameter },
};

static int
dissect_gdt_Parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Parameters_sequence_of, hf_index, ett_gdt_Parameters);

  return offset;
}


static const ber_sequence_t EncryptionInfo_sequence[] = {
  { &hf_gdt_enc_type        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gdt_OCTET_STRING },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_EncryptionInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptionInfo_sequence, hf_index, ett_gdt_EncryptionInfo);

  return offset;
}


static const ber_sequence_t HopInfo_sequence[] = {
  { &hf_gdt_current_hop     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gdt_INTEGER },
  { &hf_gdt_max_hops        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gdt_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_HopInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HopInfo_sequence, hf_index, ett_gdt_HopInfo);

  return offset;
}


static const value_string gdt_ErrorCode_vals[] = {
  {   0, "err-ok" },
  {   1, "err-out-of-sequence" },
  {   2, "err-unknown-sequence" },
  {   3, "err-unsupported-version" },
  {   4, "err-timeout" },
  {   5, "err-unknown-route" },
  {   6, "err-routing-not-supported" },
  {   7, "err-max-hops-exceeded" },
  { 255, "err-unknown-error" },
  { 0, NULL }
};


static int
dissect_gdt_ErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Header_sequence[] = {
  { &hf_gdt_version         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gdt_INTEGER },
  { &hf_gdt_source          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gdt_EndPointDescriptor },
  { &hf_gdt_destination     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gdt_EndPointDescriptor },
  { &hf_gdt_uuid            , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gdt_OCTET_STRING },
  { &hf_gdt_sequence_num    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gdt_INTEGER },
  { &hf_gdt_sequence_flag   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gdt_SequenceFlag },
  { &hf_gdt_enc_info        , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gdt_EncryptionInfo },
  { &hf_gdt_hop_info        , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gdt_HopInfo },
  { &hf_gdt_status          , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gdt_ErrorCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_Header(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Header_sequence, hf_index, ett_gdt_Header);

  return offset;
}


static const value_string gdt_PayloadType_vals[] = {
  { 1000, "dmt-unknown" },
  { 2000, "dmt-r14p" },
  {   0, "dmt-layer2" },
  {   1, "dmt-ip" },
  {   2, "dmt-sctp" },
  {   3, "dmt-tcp" },
  {   4, "dmt-udp" },
  {   5, "dmt-m3ua" },
  {   6, "dmt-m2ua" },
  {   7, "dmt-mtp3" },
  {   8, "dmt-isup" },
  {   9, "dmt-h248" },
  {  10, "dmt-sccp" },
  {  11, "dmt-smstpdu" },
  {  12, "dmt-smpp" },
  {  13, "dmt-tcap" },
  {  14, "dmt-rtp" },
  {  15, "dmt-sip" },
  {  16, "dmt-pop3" },
  {  17, "dmt-imap" },
  {  18, "dmt-http" },
  {  19, "dmt-radius" },
  {  20, "dmt-dhcp" },
  {  21, "dmt-smtp" },
  {  22, "dmt-m2pa" },
  {  23, "dmt-mtp2" },
  { 0, NULL }
};


static int
dissect_gdt_PayloadType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PacketFwdMessage_sequence[] = {
  { &hf_gdt_payload_type    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_PayloadType },
  { &hf_gdt_payload         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_OCTET_STRING },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_PacketFwdMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PacketFwdMessage_sequence, hf_index, ett_gdt_PacketFwdMessage);

  return offset;
}


static const value_string gdt_FilterAction_vals[] = {
  {   0, "fa-filter-request" },
  {   1, "fa-filter-result" },
  { 0, NULL }
};


static int
dissect_gdt_FilterAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t FilterMessage_sequence[] = {
  { &hf_gdt_filter_action   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_FilterAction },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_FilterMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FilterMessage_sequence, hf_index, ett_gdt_FilterMessage);

  return offset;
}


static const value_string gdt_DataRetentionAction_vals[] = {
  {   0, "ra-store" },
  {   1, "ra-delete" },
  {   2, "ra-fetch" },
  {   3, "ra-result" },
  { 0, NULL }
};


static int
dissect_gdt_DataRetentionAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DataRetentionMessage_sequence[] = {
  { &hf_gdt_payload_type    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_PayloadType },
  { &hf_gdt_payload         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_OCTET_STRING },
  { &hf_gdt_dr_action       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_DataRetentionAction },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_DataRetentionMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DataRetentionMessage_sequence, hf_index, ett_gdt_DataRetentionMessage);

  return offset;
}


static const value_string gdt_ConfigAction_vals[] = {
  {   0, "ca-cfg-get" },
  {   1, "ca-cfg-set" },
  {   2, "ca-cfg-replicate" },
  {   3, "ca-cfg-ac" },
  {   4, "ca-cfg-result" },
  {   5, "ca-cfg-user-login" },
  {   6, "ca-cfg-user-logout" },
  { 0, NULL }
};


static int
dissect_gdt_ConfigAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ConfigMessage_sequence[] = {
  { &hf_gdt_action          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_ConfigAction },
  { &hf_gdt_payload         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_OCTET_STRING },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_ConfigMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConfigMessage_sequence, hf_index, ett_gdt_ConfigMessage);

  return offset;
}


static const value_string gdt_StatsAction_vals[] = {
  {   0, "sa-request" },
  {   1, "sa-result" },
  { 0, NULL }
};


static int
dissect_gdt_StatsAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t StatsMessage_sequence[] = {
  { &hf_gdt_stats_action    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_StatsAction },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_StatsMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StatsMessage_sequence, hf_index, ett_gdt_StatsMessage);

  return offset;
}


static const value_string gdt_AuthAction_vals[] = {
  {   0, "aa-auth-request" },
  {   1, "aa-auth-result" },
  { 0, NULL }
};


static int
dissect_gdt_AuthAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t AuthMessage_sequence[] = {
  { &hf_gdt_auth_action     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_AuthAction },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_AuthMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthMessage_sequence, hf_index, ett_gdt_AuthMessage);

  return offset;
}


static const value_string gdt_RegistrationAction_vals[] = {
  {   0, "ra-reg-request" },
  {   1, "ra-reg-result" },
  { 0, NULL }
};


static int
dissect_gdt_RegistrationAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RegistrationMessage_sequence[] = {
  { &hf_gdt_reg_action      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_RegistrationAction },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_RegistrationMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RegistrationMessage_sequence, hf_index, ett_gdt_RegistrationMessage);

  return offset;
}



static int
dissect_gdt_NotifyMessageType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t NotifyMessage_sequence[] = {
  { &hf_gdt_message_type    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_NotifyMessageType },
  { &hf_gdt_message         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_OCTET_STRING },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_NotifyMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NotifyMessage_sequence, hf_index, ett_gdt_NotifyMessage);

  return offset;
}


static const ber_sequence_t DataMessage_sequence[] = {
  { &hf_gdt_payload_type    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_PayloadType },
  { &hf_gdt_payload         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_OCTET_STRING },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_DataMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DataMessage_sequence, hf_index, ett_gdt_DataMessage);

  return offset;
}


static const value_string gdt_RoutingAction_vals[] = {
  {   0, "roua-route-set" },
  {   1, "roua-route-get" },
  {   2, "roua-route-result" },
  { 0, NULL }
};


static int
dissect_gdt_RoutingAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RoutingMessage_sequence[] = {
  { &hf_gdt_routing_action  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_RoutingAction },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_RoutingMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RoutingMessage_sequence, hf_index, ett_gdt_RoutingMessage);

  return offset;
}


static const value_string gdt_ServiceId_vals[] = {
  {  42, "sid-stp-routing" },
  {  43, "sid-sgn-forward" },
  {  44, "sid-fgn-filtering" },
  {  45, "sid-security" },
  {  46, "sid-pdn-filtering" },
  {  47, "sid-sysagent" },
  { 0, NULL }
};


static int
dissect_gdt_ServiceId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string gdt_ServiceAction_vals[] = {
  {   0, "srvca-request" },
  {   1, "srvca-result" },
  {   2, "srvca-default" },
  {   3, "srvca-na" },
  { 0, NULL }
};


static int
dissect_gdt_ServiceAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ServiceMessage_sequence[] = {
  { &hf_gdt_service_id      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_ServiceId },
  { &hf_gdt_service_action  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_ServiceAction },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_ServiceMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceMessage_sequence, hf_index, ett_gdt_ServiceMessage);

  return offset;
}


static const value_string gdt_StateAction_vals[] = {
  {   0, "sta-update" },
  { 0, NULL }
};


static int
dissect_gdt_StateAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t StateMessage_sequence[] = {
  { &hf_gdt_stmch_id        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gdt_OCTET_STRING },
  { &hf_gdt_state_action    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gdt_StateAction },
  { &hf_gdt_params          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gdt_Parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_StateMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StateMessage_sequence, hf_index, ett_gdt_StateMessage);

  return offset;
}


static const value_string gdt_Body_vals[] = {
  {   1, "encrypted-data" },
  {   2, "packet-fwd" },
  {   3, "filter" },
  {   4, "data-retention" },
  {   6, "conf" },
  {   7, "stats" },
  {   8, "auth" },
  {   9, "reg" },
  {  10, "ntfy" },
  {  11, "data" },
  {  12, "routing" },
  {  13, "service-msg" },
  {  14, "state-msg" },
  { 0, NULL }
};

static const ber_choice_t Body_choice[] = {
  {   1, &hf_gdt_encrypted_data  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gdt_OCTET_STRING },
  {   2, &hf_gdt_packet_fwd      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gdt_PacketFwdMessage },
  {   3, &hf_gdt_filter          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gdt_FilterMessage },
  {   4, &hf_gdt_data_retention  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gdt_DataRetentionMessage },
  {   6, &hf_gdt_conf            , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gdt_ConfigMessage },
  {   7, &hf_gdt_stats           , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_gdt_StatsMessage },
  {   8, &hf_gdt_auth            , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_gdt_AuthMessage },
  {   9, &hf_gdt_reg             , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_gdt_RegistrationMessage },
  {  10, &hf_gdt_ntfy            , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gdt_NotifyMessage },
  {  11, &hf_gdt_data            , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_gdt_DataMessage },
  {  12, &hf_gdt_routing         , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_gdt_RoutingMessage },
  {  13, &hf_gdt_service_msg     , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gdt_ServiceMessage },
  {  14, &hf_gdt_state_msg       , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gdt_StateMessage },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_Body(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Body_choice, hf_index, ett_gdt_Body,
                                 NULL);

  return offset;
}


static const ber_sequence_t GDTMessage_sequence[] = {
  { &hf_gdt_header          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gdt_Header },
  { &hf_gdt_body            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gdt_Body },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gdt_GDTMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GDTMessage_sequence, hf_index, ett_gdt_GDTMessage);

  return offset;
}

/*--- PDUs ---*/

static int dissect_GDTMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_gdt_GDTMessage(false, tvb, offset, &asn1_ctx, tree, hf_gdt_GDTMessage_PDU);
  return offset;
}


static int dissect_gdt(tvbuff_t *tvb,
                       packet_info *pinfo,
                       proto_tree *tree,
                       void *data _U_) {
    proto_item *gdt_item = NULL;
    proto_tree *gdt_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* create the gdt protocol tree */
    if (tree) {
        gdt_item = proto_tree_add_item(tree, proto_gdt, tvb, 0, -1, ENC_NA);
        gdt_tree = proto_item_add_subtree(gdt_item, ett_gdt);
        dissect_GDTMessage_PDU(tvb, pinfo, gdt_tree, 0);
    }
    return tvb_captured_length(tvb);
}

/*--- proto_register_gdt ----------------------------------------------*/
void proto_register_gdt(void) {
    /* List of fields */
    static hf_register_info hf[] = {
    { &hf_gdt_GDTMessage_PDU,
      { "GDTMessage", "gdt.GDTMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gdt_version,
      { "version", "gdt.version",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gdt_source,
      { "source", "gdt.source_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndPointDescriptor", HFILL }},
    { &hf_gdt_destination,
      { "destination", "gdt.destination_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndPointDescriptor", HFILL }},
    { &hf_gdt_uuid,
      { "uuid", "gdt.uuid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gdt_sequence_num,
      { "sequence-num", "gdt.sequence_num",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gdt_sequence_flag,
      { "sequence-flag", "gdt.sequence_flag",
        FT_INT32, BASE_DEC, VALS(gdt_SequenceFlag_vals), 0,
        "SequenceFlag", HFILL }},
    { &hf_gdt_enc_info,
      { "enc-info", "gdt.enc_info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptionInfo", HFILL }},
    { &hf_gdt_hop_info,
      { "hop-info", "gdt.hop_info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HopInfo", HFILL }},
    { &hf_gdt_status,
      { "status", "gdt.status",
        FT_INT32, BASE_DEC, VALS(gdt_ErrorCode_vals), 0,
        "ErrorCode", HFILL }},
    { &hf_gdt_type,
      { "type", "gdt.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_gdt_end_point_id,
      { "id", "gdt.end_point_id",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_gdt_encrypted_data,
      { "encrypted-data", "gdt.encrypted_data",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gdt_packet_fwd,
      { "packet-fwd", "gdt.packet_fwd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PacketFwdMessage", HFILL }},
    { &hf_gdt_filter,
      { "filter", "gdt.filter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilterMessage", HFILL }},
    { &hf_gdt_data_retention,
      { "data-retention", "gdt.data_retention_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataRetentionMessage", HFILL }},
    { &hf_gdt_conf,
      { "conf", "gdt.conf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConfigMessage", HFILL }},
    { &hf_gdt_stats,
      { "stats", "gdt.stats_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StatsMessage", HFILL }},
    { &hf_gdt_auth,
      { "auth", "gdt.auth_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthMessage", HFILL }},
    { &hf_gdt_reg,
      { "reg", "gdt.reg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationMessage", HFILL }},
    { &hf_gdt_ntfy,
      { "ntfy", "gdt.ntfy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NotifyMessage", HFILL }},
    { &hf_gdt_data,
      { "data", "gdt.data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataMessage", HFILL }},
    { &hf_gdt_routing,
      { "routing", "gdt.routing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RoutingMessage", HFILL }},
    { &hf_gdt_service_msg,
      { "service-msg", "gdt.service_msg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceMessage", HFILL }},
    { &hf_gdt_state_msg,
      { "state-msg", "gdt.state_msg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StateMessage", HFILL }},
    { &hf_gdt_stmch_id,
      { "stmch-id", "gdt.stmch_id",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gdt_state_action,
      { "state-action", "gdt.state_action",
        FT_INT32, BASE_DEC, VALS(gdt_StateAction_vals), 0,
        "StateAction", HFILL }},
    { &hf_gdt_params,
      { "params", "gdt.params",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Parameters", HFILL }},
    { &hf_gdt_service_id,
      { "service-id", "gdt.service_id",
        FT_INT32, BASE_DEC, VALS(gdt_ServiceId_vals), 0,
        "ServiceId", HFILL }},
    { &hf_gdt_service_action,
      { "service-action", "gdt.service_action",
        FT_INT32, BASE_DEC, VALS(gdt_ServiceAction_vals), 0,
        "ServiceAction", HFILL }},
    { &hf_gdt_routing_action,
      { "routing-action", "gdt.routing_action",
        FT_INT32, BASE_DEC, VALS(gdt_RoutingAction_vals), 0,
        "RoutingAction", HFILL }},
    { &hf_gdt_reg_action,
      { "reg-action", "gdt.reg_action",
        FT_INT32, BASE_DEC, VALS(gdt_RegistrationAction_vals), 0,
        "RegistrationAction", HFILL }},
    { &hf_gdt_stats_action,
      { "stats-action", "gdt.stats_action",
        FT_INT32, BASE_DEC, VALS(gdt_StatsAction_vals), 0,
        "StatsAction", HFILL }},
    { &hf_gdt_auth_action,
      { "auth-action", "gdt.auth_action",
        FT_INT32, BASE_DEC, VALS(gdt_AuthAction_vals), 0,
        "AuthAction", HFILL }},
    { &hf_gdt_payload_type,
      { "payload-type", "gdt.payload_type",
        FT_INT32, BASE_DEC, VALS(gdt_PayloadType_vals), 0,
        "PayloadType", HFILL }},
    { &hf_gdt_payload,
      { "payload", "gdt.payload",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gdt_dr_action,
      { "dr-action", "gdt.dr_action",
        FT_INT32, BASE_DEC, VALS(gdt_DataRetentionAction_vals), 0,
        "DataRetentionAction", HFILL }},
    { &hf_gdt_filter_action,
      { "filter-action", "gdt.filter_action",
        FT_INT32, BASE_DEC, VALS(gdt_FilterAction_vals), 0,
        "FilterAction", HFILL }},
    { &hf_gdt_message_type,
      { "message-type", "gdt.message_type",
        FT_INT32, BASE_DEC, NULL, 0,
        "NotifyMessageType", HFILL }},
    { &hf_gdt_message,
      { "message", "gdt.message",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gdt_action,
      { "action", "gdt.action",
        FT_INT32, BASE_DEC, VALS(gdt_ConfigAction_vals), 0,
        "ConfigAction", HFILL }},
    { &hf_gdt_parameter_type_id,
      { "id", "gdt.parameter_type_id",
        FT_INT32, BASE_DEC, VALS(gdt_ParameterType_vals), 0,
        "ParameterType", HFILL }},
    { &hf_gdt_value,
      { "value", "gdt.value",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gdt_value_item,
      { "value item", "gdt.value_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gdt_Parameters_item,
      { "Parameter", "gdt.Parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gdt_current_hop,
      { "current-hop", "gdt.current_hop",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gdt_max_hops,
      { "max-hops", "gdt.max_hops",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gdt_header,
      { "header", "gdt.header_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gdt_body,
      { "body", "gdt.body",
        FT_UINT32, BASE_DEC, VALS(gdt_Body_vals), 0,
        NULL, HFILL }},
    { &hf_gdt_enc_type,
      { "enc-type", "gdt.enc_type",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    };

    /* List of subtrees */
    static int *ett[] = {
        &ett_gdt,
    &ett_gdt_Header,
    &ett_gdt_EndPointDescriptor,
    &ett_gdt_Body,
    &ett_gdt_StateMessage,
    &ett_gdt_ServiceMessage,
    &ett_gdt_RoutingMessage,
    &ett_gdt_RegistrationMessage,
    &ett_gdt_StatsMessage,
    &ett_gdt_AuthMessage,
    &ett_gdt_DataRetentionMessage,
    &ett_gdt_FilterMessage,
    &ett_gdt_PacketFwdMessage,
    &ett_gdt_NotifyMessage,
    &ett_gdt_DataMessage,
    &ett_gdt_ConfigMessage,
    &ett_gdt_Parameter,
    &ett_gdt_T_value,
    &ett_gdt_Parameters,
    &ett_gdt_HopInfo,
    &ett_gdt_GDTMessage,
    &ett_gdt_EncryptionInfo,
    };

    /* Register protocol */
    proto_gdt = proto_register_protocol(PNAME, PSNAME, PFNAME);

    /* Register fields and subtrees */
    proto_register_field_array(proto_gdt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    gdt_handle = register_dissector("gdt", dissect_gdt, proto_gdt);
}

/*--- proto_reg_handoff_gdt -------------------------------------------*/
void proto_reg_handoff_gdt(void) {
    static bool initialized = false;

    if (!initialized) {
        dissector_add_for_decode_as("sctp.ppi", gdt_handle);
        dissector_add_uint("sctp.ppi", GDT_PROTOCOL_ID, gdt_handle);
        initialized = true;
    }
}
