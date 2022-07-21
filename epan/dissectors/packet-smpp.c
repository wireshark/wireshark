/* packet-smpp.c
 * Routines for Short Message Peer to Peer dissection
 * Copyright 2001, Tom Uijldert.
 *
 * Data Coding Scheme decoding for GSM (SMS and CBS),
 * provided by Olivier Biot.
 *
 * Dissection of multiple SMPP PDUs within one packet
 * provided by Chris Wilson.
 *
 * Statistics support using Stats Tree API
 * provided by Abhik Sarkar
 *
 * Support for SMPP 5.0
 * introduced by Abhik Sarkar
 *
 * Support for Huawei SMPP+ extensions
 * introduced by Xu Bo and enhanced by Abhik Sarkar
 *
 * Enhanced error code handling
 * provided by Stipe Tolj from Kannel.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ----------
 *
 * Dissector of an SMPP (Short Message Peer to Peer) PDU, as defined by the
 * SMS forum (www.smsforum.net) in "SMPP protocol specification v3.4"
 * (document version: 12-Oct-1999 Issue 1.2)
 */

#include "config.h"


#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/stats_tree.h>
#include <epan/prefs.h>
#include <epan/exported_pdu.h>
#include <epan/conversation.h>
#include <epan/proto_data.h>
#include <wsutil/time_util.h>
#include "packet-tcp.h"
#include "packet-smpp.h"
#include <epan/strutil.h>

#define SMPP_FIXED_HEADER_LENGTH  16
#define SMPP_MIN_LENGTH SMPP_FIXED_HEADER_LENGTH

/* Forward declarations         */
void proto_register_smpp(void);
void proto_reg_handoff_smpp(void);

static gint exported_pdu_tap = -1;

/*
 * Initialize the protocol and registered fields
 *
 * Fixed header section
 */
static int proto_smpp                                 = -1;

static int st_smpp_ops                                = -1;
static int st_smpp_req                                = -1;
static int st_smpp_res                                = -1;
static int st_smpp_res_status                         = -1;

static int hf_smpp_command_id                         = -1;
static int hf_smpp_command_length                     = -1;
static int hf_smpp_command_status                     = -1;
static int hf_smpp_sequence_number                    = -1;

/*
 * Fixed body section
 */
static int hf_smpp_system_id                          = -1;
static int hf_smpp_password                           = -1;
static int hf_smpp_system_type                        = -1;
static int hf_smpp_interface_version                  = -1;
static int hf_smpp_addr_ton                           = -1;
static int hf_smpp_addr_npi                           = -1;
static int hf_smpp_address_range                      = -1;
static int hf_smpp_service_type                       = -1;
static int hf_smpp_source_addr_ton                    = -1;
static int hf_smpp_source_addr_npi                    = -1;
static int hf_smpp_source_addr                        = -1;
static int hf_smpp_dest_addr_ton                      = -1;
static int hf_smpp_dest_addr_npi                      = -1;
static int hf_smpp_destination_addr                   = -1;
static int hf_smpp_esm_submit_msg_mode                = -1;
static int hf_smpp_esm_submit_msg_type                = -1;
static int hf_smpp_esm_submit_features                = -1;
static int hf_smpp_protocol_id                        = -1;
static int hf_smpp_priority_flag                      = -1;
static int hf_smpp_schedule_delivery_time             = -1;
static int hf_smpp_schedule_delivery_time_r           = -1;
static int hf_smpp_validity_period                    = -1;
static int hf_smpp_validity_period_r                  = -1;
static int hf_smpp_regdel_receipt                     = -1;
static int hf_smpp_regdel_acks                        = -1;
static int hf_smpp_regdel_notif                       = -1;
static int hf_smpp_replace_if_present_flag            = -1;
static int hf_smpp_data_coding                        = -1;
static int hf_smpp_sm_default_msg_id                  = -1;
static int hf_smpp_sm_length                          = -1;
static int hf_smpp_short_message                      = -1;
static int hf_smpp_short_message_bin                  = -1;
static int hf_smpp_message_id                         = -1;
static int hf_smpp_dlist                              = -1;
static int hf_smpp_dlist_resp                         = -1;
static int hf_smpp_dl_name                            = -1;
static int hf_smpp_final_date                         = -1;
static int hf_smpp_final_date_r                       = -1;
static int hf_smpp_message_state                      = -1;
static int hf_smpp_error_code                         = -1;
static int hf_smpp_error_status_code                  = -1;
static int hf_smpp_esme_addr_ton                      = -1;
static int hf_smpp_esme_addr_npi                      = -1;
static int hf_smpp_esme_addr                          = -1;

/*
 * Optional parameter section
 */
static int hf_smpp_opt_params                         = -1;
static int hf_smpp_opt_param                          = -1;
static int hf_smpp_opt_param_tag                      = -1;
static int hf_smpp_opt_param_len                      = -1;
static int hf_smpp_vendor_op                          = -1;
static int hf_smpp_reserved_op                        = -1;

static int hf_smpp_dest_addr_subunit                  = -1;
static int hf_smpp_dest_network_type                  = -1;
static int hf_smpp_dest_bearer_type                   = -1;
static int hf_smpp_dest_telematics_id                 = -1;
static int hf_smpp_source_addr_subunit                = -1;
static int hf_smpp_source_network_type                = -1;
static int hf_smpp_source_bearer_type                 = -1;
static int hf_smpp_source_telematics_id               = -1;
static int hf_smpp_qos_time_to_live                   = -1;
static int hf_smpp_payload_type                       = -1;
static int hf_smpp_additional_status_info_text        = -1;
static int hf_smpp_receipted_message_id               = -1;
static int hf_smpp_msg_wait_ind                       = -1;
static int hf_smpp_msg_wait_type                      = -1;
static int hf_smpp_privacy_indicator                  = -1;
static int hf_smpp_source_subaddress                  = -1;
static int hf_smpp_dest_subaddress                    = -1;
static int hf_smpp_user_message_reference             = -1;
static int hf_smpp_user_response_code                 = -1;
static int hf_smpp_source_port                        = -1;
static int hf_smpp_destination_port                   = -1;
static int hf_smpp_sar_msg_ref_num                    = -1;
static int hf_smpp_language_indicator                 = -1;
static int hf_smpp_sar_total_segments                 = -1;
static int hf_smpp_sar_segment_seqnum                 = -1;
static int hf_smpp_SC_interface_version               = -1;
static int hf_smpp_callback_num_pres                  = -1;
static int hf_smpp_callback_num_scrn                  = -1;
static int hf_smpp_callback_num_atag                  = -1;
static int hf_smpp_number_of_messages                 = -1;
static int hf_smpp_callback_num                       = -1;
static int hf_smpp_dpf_result                         = -1;
static int hf_smpp_set_dpf                            = -1;
static int hf_smpp_ms_availability_status             = -1;
static int hf_smpp_network_error_type                 = -1;
static int hf_smpp_network_error_code                 = -1;
static int hf_smpp_message_payload                    = -1;
static int hf_smpp_delivery_failure_reason            = -1;
static int hf_smpp_more_messages_to_send              = -1;
static int hf_smpp_ussd_service_op                    = -1;
static int hf_smpp_display_time                       = -1;
static int hf_smpp_sms_signal                         = -1;
static int hf_smpp_ms_validity                        = -1;
static int hf_smpp_alert_on_message_delivery_null     = -1;
static int hf_smpp_alert_on_message_delivery_type     = -1;
static int hf_smpp_its_reply_type                     = -1;
static int hf_smpp_its_session_number                 = -1;
static int hf_smpp_its_session_sequence               = -1;
static int hf_smpp_its_session_ind                    = -1;

/* Optional Parameters introduced in SMPP 5.0   */
static int hf_smpp_congestion_state                   = -1;
static int hf_smpp_billing_identification             = -1;
static int hf_smpp_dest_addr_np_country               = -1;
static int hf_smpp_dest_addr_np_information           = -1;
static int hf_smpp_dest_addr_np_resolution            = -1;
static int hf_smpp_source_network_id                  = -1;
static int hf_smpp_source_node_id                     = -1;
static int hf_smpp_dest_network_id                    = -1;
static int hf_smpp_dest_node_id                       = -1;
/* Optional Parameters for Cell Broadcast Operations */
static int hf_smpp_broadcast_channel_indicator        = -1;
static int hf_smpp_broadcast_content_type_nw          = -1;
static int hf_smpp_broadcast_content_type_type        = -1;
static int hf_smpp_broadcast_content_type_info        = -1;
static int hf_smpp_broadcast_message_class            = -1;
static int hf_smpp_broadcast_rep_num                  = -1;
static int hf_smpp_broadcast_frequency_interval_unit  = -1;
static int hf_smpp_broadcast_frequency_interval_value = -1;
static int hf_smpp_broadcast_area_identifier          = -1;
static int hf_smpp_broadcast_area_identifier_format   = -1;
static int hf_smpp_broadcast_error_status             = -1;
static int hf_smpp_broadcast_area_success             = -1;
static int hf_smpp_broadcast_end_time                 = -1;
static int hf_smpp_broadcast_end_time_r               = -1;
static int hf_smpp_broadcast_service_group            = -1;

/*
 * Data Coding Scheme section
 */
static int hf_smpp_dcs_sms_coding_group               = -1;
static int hf_smpp_dcs_reserved                       = -1;
static int hf_smpp_dcs_charset                        = -1;
static int hf_smpp_dcs_class                          = -1;
static int hf_smpp_dcs_wait_ind                       = -1;
static int hf_smpp_dcs_reserved2                      = -1;
static int hf_smpp_dcs_wait_type                      = -1;

/*
 * Huawei SMPP+ extensions
 */
static int hf_huawei_smpp_smsc_addr                   = -1;
static int hf_huawei_smpp_msc_addr_noa                = -1;
static int hf_huawei_smpp_msc_addr_npi                = -1;
static int hf_huawei_smpp_msc_addr                    = -1;
static int hf_huawei_smpp_mo_mt_flag                  = -1;
static int hf_huawei_smpp_length_auth                 = -1;
static int hf_huawei_smpp_sm_id                       = -1;
static int hf_huawei_smpp_service_id                  = -1;
static int hf_huawei_smpp_operation_result            = -1;
static int hf_huawei_smpp_notify_mode                 = -1;
static int hf_huawei_smpp_delivery_result             = -1;

static expert_field ei_smpp_message_payload_duplicate = EI_INIT;

/* Initialize the subtree pointers */
static gint ett_smpp            = -1;
static gint ett_dlist           = -1;
static gint ett_dlist_resp      = -1;
static gint ett_opt_params      = -1;
static gint ett_opt_param       = -1;
static gint ett_dcs             = -1;

static dissector_handle_t smpp_handle;

/* Reassemble SMPP TCP segments */
static gboolean reassemble_over_tcp = TRUE;
static gboolean smpp_gsm7_unpacked = TRUE;

typedef enum {
  DECODE_AS_DEFAULT    =   0,
  DECODE_AS_ASCII      =   1,
  DECODE_AS_OCTET      =   2, /* 8-bit binary */
  DECODE_AS_ISO_8859_1 =   3,
  DECODE_AS_ISO_8859_5 =   6,
  DECODE_AS_ISO_8859_8 =   7,
  DECODE_AS_UCS2       =   8,
  DECODE_AS_KSC5601    =  14, /* Korean, EUC-KR as in ANSI 637 */
  DECODE_AS_GSM7       = 241, /* One of many GSM DCS values that means GSM7 */
} SMPP_DCS_Type;

/* ENC_NA is the same as ENC_ASCII, so use an artifical value to mean
 * "treat this as 8-bit binary / FT_BYTES, not a string."
 */
#define DO_NOT_DECODE G_MAXUINT

/* Default preference whether to decode the SMS over SMPP when DCS = 0 */
static gint smpp_decode_dcs_0_sms = DO_NOT_DECODE;

/* Tap */
static int smpp_tap             = -1;

#define SMPP_COMMAND_ID_GENERIC_NACK        0x00000000
#define SMPP_COMMAND_ID_BIND_RECEIVER       0x00000001
#define SMPP_COMMAND_ID_BIND_TRANSMITTER    0x00000002
#define SMPP_COMMAND_ID_QUERY_SM            0x00000003
#define SMPP_COMMAND_ID_SUBMIT_SM           0x00000004
#define SMPP_COMMAND_ID_DELIVER_SM          0x00000005
#define SMPP_COMMAND_ID_UNBIND              0x00000006
#define SMPP_COMMAND_ID_REPLACE_SM          0x00000007
#define SMPP_COMMAND_ID_CANCEL_SM           0x00000008
#define SMPP_COMMAND_ID_BIND_TRANSCEIVER    0x00000009
#define SMPP_COMMAND_ID_OUTBIND             0x0000000B
#define SMPP_COMMAND_ID_ENQUIRE_LINK        0x00000015
#define SMPP_COMMAND_ID_SUBMIT_MULTI        0x00000021
#define SMPP_COMMAND_ID_ALERT_NOTIFICATION  0x00000102
#define SMPP_COMMAND_ID_DATA_SM             0x00000103
/* Introduced in SMPP 5.0 */
#define SMPP_COMMAND_ID_BROADCAST_SM        0x00000111
#define SMPP_COMMAND_ID_QUERY_BROADCAST_SM  0x00000112
#define SMPP_COMMAND_ID_CANCEL_BROADCAST_SM 0x00000113
/* Huawei SMPP+ extensions */
#define SMPP_COMMAND_ID_HUAWEI_AUTH_ACC     0x01000001
#define SMPP_COMMAND_ID_HUAWEI_SM_RESULT_NOTIFY 0X01000002


#define SMPP_COMMAND_ID_RESPONSE_MASK       0x80000000

/*
 * Value-arrays for field-contents
 */
static const value_string vals_command_id[] = {         /* Operation    */
    { SMPP_COMMAND_ID_BIND_RECEIVER, "Bind_receiver" },
    { SMPP_COMMAND_ID_BIND_TRANSMITTER, "Bind_transmitter" },
    { SMPP_COMMAND_ID_QUERY_SM, "Query_sm" },
    { SMPP_COMMAND_ID_SUBMIT_SM, "Submit_sm" },
    { SMPP_COMMAND_ID_DELIVER_SM, "Deliver_sm" },
    { SMPP_COMMAND_ID_UNBIND, "Unbind" },
    { SMPP_COMMAND_ID_REPLACE_SM, "Replace_sm" },
    { SMPP_COMMAND_ID_CANCEL_SM, "Cancel_sm" },
    { SMPP_COMMAND_ID_BIND_TRANSCEIVER, "Bind_transceiver" },
    { SMPP_COMMAND_ID_OUTBIND, "Outbind" },
    { SMPP_COMMAND_ID_ENQUIRE_LINK, "Enquire_link" },
    { SMPP_COMMAND_ID_SUBMIT_MULTI, "Submit_multi" },
    { SMPP_COMMAND_ID_ALERT_NOTIFICATION, "Alert_notification" },
    { SMPP_COMMAND_ID_DATA_SM, "Data_sm" },
    { SMPP_COMMAND_ID_BROADCAST_SM, "Broadcast_sm" },
    { SMPP_COMMAND_ID_QUERY_BROADCAST_SM, "Query_broadcast_sm" },
    { SMPP_COMMAND_ID_CANCEL_BROADCAST_SM, "Cancel_broadcast_sm" },
    { SMPP_COMMAND_ID_HUAWEI_AUTH_ACC, "Auth_acc" },
    { SMPP_COMMAND_ID_HUAWEI_SM_RESULT_NOTIFY, "Sm_result_notify" },

    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_GENERIC_NACK, "Generic_nack" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_BIND_RECEIVER, "Bind_receiver - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_BIND_TRANSMITTER, "Bind_transmitter - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_QUERY_SM, "Query_sm - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_SUBMIT_SM, "Submit_sm - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_DELIVER_SM, "Deliver_sm - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_UNBIND, "Unbind - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_REPLACE_SM, "Replace_sm - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_CANCEL_SM, "Cancel_sm - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_BIND_TRANSCEIVER, "Bind_transceiver - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_ENQUIRE_LINK, "Enquire_link - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_SUBMIT_MULTI, "Submit_multi - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_DATA_SM, "Data_sm - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_BROADCAST_SM, "Broadcast_sm - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_QUERY_BROADCAST_SM, "Query_broadcast_sm - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_CANCEL_BROADCAST_SM, "Cancel_broadcast_sm - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_HUAWEI_AUTH_ACC, "Auth_acc - resp" },
    { SMPP_COMMAND_ID_RESPONSE_MASK|SMPP_COMMAND_ID_HUAWEI_SM_RESULT_NOTIFY, "Sm_result_notify - resp" },
    { 0, NULL }
};

static const range_string rvals_command_status[] = {     /* Status       */
    { 0x00000000, 0x00000000, "Ok" },
    { 0x00000001, 0x00000001, "Message length is invalid" },
    { 0x00000002, 0x00000002, "Command length is invalid" },
    { 0x00000003, 0x00000003, "Invalid command ID" },
    { 0x00000004, 0x00000004, "Incorrect BIND status for given command" },
    { 0x00000005, 0x00000005, "ESME already in bound state" },
    { 0x00000006, 0x00000006, "Invalid priority flag" },
    { 0x00000007, 0x00000007, "Invalid registered delivery flag" },
    { 0x00000008, 0x00000008, "System error" },
    { 0x00000009, 0x00000009, "[Reserved]" },
    { 0x0000000A, 0x0000000A, "Invalid source address" },
    { 0x0000000B, 0x0000000B, "Invalid destination address" },
    { 0x0000000C, 0x0000000C, "Message ID is invalid" },
    { 0x0000000D, 0x0000000D, "Bind failed" },
    { 0x0000000E, 0x0000000E, "Invalid password" },
    { 0x0000000F, 0x0000000F, "Invalid system ID" },
    { 0x00000010, 0x00000010, "[Reserved]" },
    { 0x00000011, 0x00000011, "Cancel SM failed" },
    { 0x00000012, 0x00000012, "[Reserved]" },
    { 0x00000013, 0x00000013, "Replace SM failed" },
    { 0x00000014, 0x00000014, "Message queue full" },
    { 0x00000015, 0x00000015, "Invalid service type" },
    { 0x00000016, 0x00000032, "[Reserved]" },
    { 0x00000033, 0x00000033, "Invalid number of destinations" },
    { 0x00000034, 0x00000034, "Invalid distribution list name" },
    { 0x00000035, 0x0000003F, "[Reserved]" },
    { 0x00000040, 0x00000040, "Destination flag is invalid (submit_multi)" },
    { 0x00000041, 0x00000041, "[Reserved]" },
    { 0x00000042, 0x00000042, "Invalid 'submit with replace' request" },
    { 0x00000043, 0x00000043, "Invalid esm_class field data" },
    { 0x00000044, 0x00000044, "Cannot submit to distribution list" },
    { 0x00000045, 0x00000045, "submit_sm or submit_multi failed" },
    { 0x00000046, 0x00000047, "[Reserved]" },
    { 0x00000048, 0x00000048, "Invalid source address TON" },
    { 0x00000049, 0x00000049, "Invalid source address NPI" },
    { 0x00000050, 0x00000050, "Invalid destination address TON" },
    { 0x00000051, 0x00000051, "Invalid destination address NPI" },
    { 0x00000052, 0x00000052, "[Reserved]" },
    { 0x00000053, 0x00000053, "Invalid system_type field" },
    { 0x00000054, 0x00000054, "Invalid replace_if_present flag" },
    { 0x00000055, 0x00000055, "Invalid number of messages" },
    { 0x00000056, 0x00000057, "[Reserved]" },
    { 0x00000058, 0x00000058, "Throttling error (ESME exceeded allowed message limits)" },
    { 0x00000059, 0x00000060, "[Reserved]" },
    { 0x00000061, 0x00000061, "Invalid scheduled delivery time" },
    { 0x00000062, 0x00000062, "Invalid message validity period (expiry time)" },
    { 0x00000063, 0x00000063, "Predefined message invalid or not found" },
    { 0x00000064, 0x00000064, "ESME receiver temporary app error code" },
    { 0x00000065, 0x00000065, "ESME receiver permanent app error code" },
    { 0x00000066, 0x00000066, "ESME receiver reject message error code" },
    { 0x00000067, 0x00000067, "query_sm request failed" },
    { 0x00000068, 0x000000BF, "[Reserved]" },
    { 0x000000C0, 0x000000C0, "Error in the optional part of the PDU body" },
    { 0x000000C1, 0x000000C1, "Optional parameter not allowed" },
    { 0x000000C2, 0x000000C2, "Invalid parameter length" },
    { 0x000000C3, 0x000000C3, "Expected optional parameter missing" },
    { 0x000000C4, 0x000000C4, "Invalid optional parameter  value" },
    { 0x000000C5, 0x000000FD, "[Reserved]" },
    { 0x000000FE, 0x000000FE, "(Transaction) Delivery failure (used for data_sm_resp)" },
    { 0x000000FF, 0x000000FF, "Unknown error" },
    /* Introduced in SMPP 5.0 */
    { 0x00000100, 0x00000100, "ESME Not authorised to use specified service_type." },
    { 0x00000101, 0x00000101, "ESME Prohibited from using specified operation."},
    { 0x00000102, 0x00000102, "Specified service_type is unavailable." },
    { 0x00000103, 0x00000103, "Specified service_type is denied." },
    { 0x00000104, 0x00000104, "Invalid Data Coding Scheme." },
    { 0x00000105, 0x00000105, "Source Address Sub unit is Invalid." },
    { 0x00000106, 0x00000106, "Destination Address Sub unit is Invalid." },
    { 0x00000107, 0x00000107, "Broadcast Frequency Interval is invalid." },
    { 0x00000108, 0x00000108, "Broadcast Alias Name is invalid." },
    { 0x00000109, 0x00000109, "Broadcast Area Format is invalid." },
    { 0x0000010A, 0x0000010A, "Number of Broadcast Areas is invalid." },
    { 0x0000010B, 0x0000010B, "Broadcast Content Type is invalid." },
    { 0x0000010C, 0x0000010C, "Broadcast Message Class is invalid." },
    { 0x0000010D, 0x0000010D, "broadcast_sm operation failed." },
    { 0x0000010E, 0x0000010E, "query_broadcast_sm operation failed." },
    { 0x0000010F, 0x0000010F, "cancel_broadcast_sm operation failed." },
    { 0x00000110, 0x00000110, "Number of Repeated Broadcasts is invalid." },
    { 0x00000111, 0x00000111, "Broadcast Service Group is invalid." },
    { 0x00000112, 0x00000112, "Broadcast Channel Indicator is invalid." },
    { 0x00000400, 0x000004FF, "[Vendor-specific Error]" },
    { 0x00000500, 0xFFFFFFFF, "[Reserved]" },
    { 0, 0, NULL }
};

static const value_string vals_tlv_tags[] = {
    { 0x0005, "dest_addr_subunit" },
    { 0x0006, "dest_network_type" },
    { 0x0007, "dest_bearer_type" },
    { 0x0008, "dest_telematics_id" },
    { 0x000D, "source_addr_subunit" },
    { 0x000E, "source_network_type" },
    { 0x000F, "source_bearer_type" },
    { 0x0010, "source_telematics_id" },
    { 0x0017, "qos_time_to_live" },
    { 0x0019, "payload_type" },
    { 0x001D, "additional_status_info_text" },
    { 0x001E, "receipted_message_id" },
    { 0x0030, "ms_msg_wait_facilities" },
    { 0x0201, "privacy_indicator" },
    { 0x0202, "source_subaddress" },
    { 0x0203, "dest_subaddress" },
    { 0x0204, "user_message_reference" },
    { 0x0205, "user_response_code" },
    { 0x020A, "source_port" },
    { 0x020B, "dest_port" },
    { 0x020C, "sar_msg_ref_num" },
    { 0x020D, "language_indicator" },
    { 0x020E, "sar_total_segments" },
    { 0x020F, "sar_segment_seqnum" },
    { 0x0210, "sc_interface_version" },
    { 0x0302, "callback_num_pres_ind" },
    { 0x0303, "callback_num_atag" },
    { 0x0304, "number_of_messages" },
    { 0x0381, "callback_num" },
    { 0x0420, "dpf_result" },
    { 0x0421, "set_dpf" },
    { 0x0422, "ms_availability_status" },
    { 0x0423, "network_error_code" },
    { 0x0424, "message_payload" },
    { 0x0425, "delivery_failure_reason" },
    { 0x0426, "more_messages_to_send" },
    { 0x0427, "message_state" },
    { 0x0428, "congestion_state" },
    { 0x0501, "ussd_service_op" },
    { 0x0600, "broadcast_channel_indicator" },
    { 0x0601, "broadcast_content_type" },
    { 0x0602, "broadcast_content_type_info" },
    { 0x0603, "broadcast_message_class" },
    { 0x0604, "broadcast_rep_num" },
    { 0x0605, "broadcast_frequency_interval" },
    { 0x0606, "broadcast_area_identifier" },
    { 0x0607, "broadcast_error_status" },
    { 0x0608, "broadcast_area_success" },
    { 0x0609, "broadcast_end_time" },
    { 0x060A, "broadcast_service_group" },
    { 0x060B, "billing_identification" },
    { 0x060D, "source_network_id" },
    { 0x060E, "dest_network_id" },
    { 0x060F, "source_node_id" },
    { 0x0610, "dest_node_id" },
    { 0x0611, "dest_addr_np_resolution" },
    { 0x0612, "dest_addr_np_information" },
    { 0x0613, "dest_addr_np_country" },
    { 0x1201, "display_time" },
    { 0x1203, "sms_signal" },
    { 0x1204, "ms_validity" },
    { 0x130C, "alert_on_message_delivery" },
    { 0x1380, "its_reply_type" },
    { 0x1383, "its_session_info" },
    { 0, NULL }
};

static const value_string vals_addr_ton[] = {
    { 0, "Unknown" },
    { 1, "International" },
    { 2, "National" },
    { 3, "Network specific" },
    { 4, "Subscriber number" },
    { 5, "Alphanumeric" },
    { 6, "Abbreviated" },
    { 0, NULL }
};

static const value_string vals_addr_npi[] = {
    {  0, "Unknown" },
    {  1, "ISDN (E163/E164)" },
    {  3, "Data (X.121)" },
    {  4, "Telex (F.69)" },
    {  6, "Land mobile (E.212)" },
    {  8, "National" },
    {  9, "Private" },
    { 10, "ERMES" },
    { 14, "Internet (IP)" },
    { 18, "WAP client Id" },
    {  0, NULL }
};

static const value_string vals_esm_submit_msg_mode[] = {
    {  0x0, "Default SMSC mode" },
    {  0x1, "Datagram mode" },
    {  0x2, "Forward mode" },
    {  0x3, "Store and forward mode" },
    {  0, NULL }
};

static const value_string vals_esm_submit_msg_type[] = {
    {  0x0, "Default message type" },
    {  0x1, "Short message contains SMSC Delivery Receipt" },
    {  0x2, "Short message contains (E)SME delivery acknowledgement" },
    {  0x3, "Reserved" },
    {  0x4, "Short message contains (E)SME manual/user acknowledgement" },
    {  0x5, "Reserved" },
    {  0x6, "Short message contains conversation abort" },
    {  0x7, "Reserved" },
    {  0x8, "Short message contains intermediate delivery notification" },
    {  0, NULL }
};

static const value_string vals_esm_submit_features[] = {
    {  0x0, "No specific features selected" },
    {  0x1, "UDHI indicator" },
    {  0x2, "Reply path" },
    {  0x3, "UDHI and reply path" },
    {  0, NULL }
};

static const value_string vals_priority_flag[] = {
    {  0, "GSM: None      ANSI-136: Bulk         IS-95: Normal" },
    {  1, "GSM: priority  ANSI-136: Normal       IS-95: Interactive" },
    {  2, "GSM: priority  ANSI-136: Urgent       IS-95: Urgent" },
    {  3, "GSM: priority  ANSI-136: Very Urgent  IS-95: Emergency" },
    {  0, NULL }
};

static const value_string vals_regdel_receipt[] = {
    {  0x0, "No SMSC delivery receipt requested" },
    {  0x1, "Delivery receipt requested (for success or failure)" },
    {  0x2, "Delivery receipt requested (for failure)" },
    {  0x3, "Reserved in version <= 3.4; Delivery receipt requested (for success) in 5.0" },
    {  0, NULL }
};

static const value_string vals_regdel_acks[] = {
    {  0x0, "No recipient SME acknowledgement requested" },
    {  0x1, "SME delivery acknowledgement requested" },
    {  0x2, "SME manual/user acknowledgement requested" },
    {  0x3, "Both delivery and manual/user acknowledgement requested" },
    {  0, NULL }
};

static const value_string vals_regdel_notif[] = {
    {  0x0, "No intermediate notification requested" },
    {  0x1, "Intermediate notification requested" },
    {  0, NULL }
};

static const value_string vals_replace_if_present_flag[] = {
    {  0x0, "Don't replace" },
    {  0x1, "Replace" },
    {  0, NULL }
};

static const range_string rvals_data_coding[] = {
    {    0,    0, "SMSC default alphabet" },
    {    1,    1, "IA5 (CCITT T.50)/ASCII (ANSI X3.4)" },
    {    2,    2, "Octet unspecified (8-bit binary)" },
    {    3,    3, "Latin 1 (ISO-8859-1)" },
    {    4,    4, "Octet unspecified (8-bit binary)" },
    {    5,    5, "JIS (X 0208-1990)" },
    {    6,    6, "Cyrillic (ISO-8859-5)" },
    {    7,    7, "Latin/Hebrew (ISO-8859-8)" },
    {    8,    8, "UCS2 (ISO/IEC-10646)" },
    {    9,    9, "Pictogram Encoding" },
    {   10,   10, "ISO-2022-JP (Music codes)" },
    {   11,   12, "Reserved" },
    {   13,   13, "Extended Kanji JIS (X 0212-1990)" },
    {   14,   14, "KS C 5601" },
    {   15, 0xBF, "Reserved" },
    { 0xC0, 0xEF, "GSM MWI control - see [GSM 03.38]" },
    { 0xF0, 0xFF, "GSM message class control - see [GSM 03.38]" },
    {    0,    0, NULL }
};

static const value_string vals_message_state[] = {
    {  1, "ENROUTE" },
    {  2, "DELIVERED" },
    {  3, "EXPIRED" },
    {  4, "DELETED" },
    {  5, "UNDELIVERABLE" },
    {  6, "ACCEPTED" },
    {  7, "UNKNOWN" },
    {  8, "REJECTED" },
    {  0, NULL }
};

static const value_string vals_addr_subunit[] = {
    {  0, "Unknown -default-" },
    {  1, "MS Display" },
    {  2, "Mobile equipment" },
    {  3, "Smart card 1" },
    {  4, "External unit 1" },
    {  0, NULL }
};

static const value_string vals_network_type[] = {
    {  0, "Unknown" },
    {  1, "GSM" },
    {  2, "ANSI-136/TDMA" },
    {  3, "IS-95/CDMA" },
    {  4, "PDC" },
    {  5, "PHS" },
    {  6, "iDEN" },
    {  7, "AMPS" },
    {  8, "Paging network" },
    {  0, NULL }
};

static const value_string vals_bearer_type[] = {
    {  0, "Unknown" },
    {  1, "SMS" },
    {  2, "Circuit Switched Data (CSD)" },
    {  3, "Packet data" },
    {  4, "USSD" },
    {  5, "CDPD" },
    {  6, "DataTAC" },
    {  7, "FLEX/ReFLEX" },
    {  8, "Cell Broadcast" },
    {  0, NULL }
};

static const value_string vals_payload_type[] = {
    {  0, "Default" },
    {  1, "WCMP message" },
    {  0, NULL }
};

static const value_string vals_privacy_indicator[] = {
    {  0, "Not restricted -default-" },
    {  1, "Restricted" },
    {  2, "Confidential" },
    {  3, "Secret" },
    {  0, NULL }
};

static const value_string vals_language_indicator[] = {
    {  0, "Unspecified -default-" },
    {  1, "english" },
    {  2, "french" },
    {  3, "spanish" },
    {  4, "german" },
    {  5, "portuguese" },
    {  0, NULL }
};

static const value_string vals_display_time[] = {
    {  0, "Temporary" },
    {  1, "Default -default-" },
    {  2, "Invoke" },
    {  0, NULL }
};

static const value_string vals_ms_validity[] = {
    {  0, "Store indefinitely -default-" },
    {  1, "Power down" },
    {  2, "SID based registration area" },
    {  3, "Display only" },
    {  0, NULL }
};

static const value_string vals_dpf_result[] = {
    {  0, "DPF not set" },
    {  1, "DPF set" },
    {  0, NULL }
};

static const value_string vals_set_dpf[] = {
    {  0, "Not requested (Set DPF for delivery failure)" },
    {  1, "Requested (Set DPF for delivery failure)" },
    {  0, NULL }
};

static const value_string vals_ms_availability_status[] = {
    {  0, "Available -default-" },
    {  1, "Denied" },
    {  2, "Unavailable" },
    {  0, NULL }
};

static const value_string vals_delivery_failure_reason[] = {
    {  0, "Destination unavailable" },
    {  1, "Destination address invalid" },
    {  2, "Permanent network error" },
    {  3, "Temporary network error" },
    {  0, NULL }
};

static const value_string vals_more_messages_to_send[] = {
    {  0, "No more messages" },
    {  1, "More messages -default-" },
    {  0, NULL }
};

static const value_string vals_its_reply_type[] = {
    {  0, "Digit" },
    {  1, "Number" },
    {  2, "Telephone no." },
    {  3, "Password" },
    {  4, "Character line" },
    {  5, "Menu" },
    {  6, "Date" },
    {  7, "Time" },
    {  8, "Continue" },
    {  0, NULL }
};

static const value_string vals_ussd_service_op[] = {
    {  0, "PSSD indication" },
    {  1, "PSSR indication" },
    {  2, "USSR request" },
    {  3, "USSN request" },
    { 16, "PSSD response" },
    { 17, "PSSR response" },
    { 18, "USSR confirm" },
    { 19, "USSN confirm" },
    {  0, NULL }
};

static const value_string vals_msg_wait_ind[] = {
    {  0, "Set indication inactive" },
    {  1, "Set indication active" },
    {  0, NULL }
};

static const value_string vals_msg_wait_type[] = {
    {  0, "Voicemail message waiting" },
    {  1, "Fax message waiting" },
    {  2, "Electronic mail message waiting" },
    {  3, "Other message waiting" },
    {  0, NULL }
};

static const value_string vals_callback_num_pres[] = {
    {  0, "Presentation allowed" },
    {  1, "Presentation restricted" },
    {  2, "Number not available" },
    {  3, "[Reserved]" },
    {  0, NULL }
};

static const value_string vals_callback_num_scrn[] = {
    {  0, "User provided, not screened" },
    {  1, "User provided, verified and passed" },
    {  2, "User provided, verified and failed" },
    {  3, "Network provided" },
    {  0, NULL }
};

static const value_string vals_network_error_type[] = {
    {  1, "ANSI-136 (Access Denied Reason)" },
    {  2, "IS-95 (Access Denied Reason)" },
    {  3, "GSM" },
    {  4, "[Reserved] in <= 3.4; ANSI 136 Cause Code in 5.0" },
    {  5, "[Reserved] in <= 3.4; IS 95 Cause Code in 5.0" },
    {  6, "[Reserved] in <= 3.4; ANSI-41 Error in 5.0" },
    {  7, "[Reserved] in <= 3.4; SMPP Error in 5.0" },
    {  8, "[Reserved] in <= 3.4; Message Center Specific in 5.0" },
    {  0, NULL }
};

static const value_string vals_its_session_ind[] = {
    {  0, "End of session indicator inactive" },
    {  1, "End of session indicator active" },
    {  0, NULL }
};

/* Data Coding Scheme: see 3GPP TS 23.040 and 3GPP TS 23.038.
 * Note values below 0x0C are not used in SMPP. */
static const value_string vals_dcs_sms_coding_group[] = {
#if 0
    { 0x00, "SMS DCS: General Data Coding indication - Uncompressed text, no message class" },
    { 0x01, "SMS DCS: General Data Coding indication - Uncompressed text" },
    { 0x02, "SMS DCS: General Data Coding indication - Compressed text, no message class" },
    { 0x03, "SMS DCS: General Data Coding indication - Compressed text" },
    { 0x04, "SMS DCS: Message Marked for Automatic Deletion - Uncompressed text, no message class" },
    { 0x05, "SMS DCS: Message Marked for Automatic Deletion - Uncompressed text" },
    { 0x06, "SMS DCS: Message Marked for Automatic Deletion - Compressed text, no message class" },
    { 0x07, "SMS DCS: Message Marked for Automatic Deletion - Compressed text" },
    { 0x08, "SMS DCS: Reserved" },
    { 0x09, "SMS DCS: Reserved" },
    { 0x0A, "SMS DCS: Reserved" },
    { 0x0B, "SMS DCS: Reserved" },
#endif
    { 0x0C, "SMS DCS: Message Waiting Indication - Discard Message" },
    { 0x0D, "SMS DCS: Message Waiting Indication - Store Message (GSM 7-bit default alphabet)" },
    { 0x0E, "SMS DCS: Message Waiting Indication - Store Message (UCS-2 character set)" },
    { 0x0F, "SMS DCS: Data coding / message class" },
    { 0x00, NULL }
};

static const value_string vals_dcs_charset[] = {
    { 0x00, "GSM 7-bit default alphabet" },
    { 0x01, "8-bit data" },
    { 0x00, NULL }
};

static const value_string vals_dcs_class[] = {
    { 0x00, "Class 0" },
    { 0x01, "Class 1 - ME specific" },
    { 0x02, "Class 2 - (U)SIM specific" },
    { 0x03, "Class 3 - TE specific" },
    { 0x00, NULL }
};

static const value_string vals_alert_on_message_delivery[] = {
    { 0x00, "Use mobile default alert (Default)" },
    { 0x01, "Use low-priority alert" },
    { 0x02, "Use medium-priority alert" },
    { 0x03, "Use high-priority alert" },
    { 0x00, NULL }
};

static const range_string vals_congestion_state[] = {
    {0,     0,      "Idle"},
    {1,     29,     "Low Load"},
    {30,    49,     "Medium Load"},
    {50,    79,     "High Load"},
    {80,    89,     "Optimum Load"}, /*Specs says 80-90, but that is probably a mistake */
    {90,    99,     "Nearing Congestion"},
    {100,   100,    "Congested / Maximum Load"},
    { 0,    0,      NULL }
};

static const range_string vals_broadcast_channel_indicator[] = {
    {0,     0,      "Basic Broadcast Channel (Default)"},
    {1,     1,      "Extended Broadcast Channel"},
    {2,     255,    "[Reserved]"},
    { 0,    0,      NULL }
};

static const value_string vals_broadcast_message_class[] = {
    {0, "No Class Specified (default)"},
    {1, "Class 1 (User Defined)"},
    {2, "Class 2 (User Defined)"},
    {3, "Class 3 (Terminal Equipment)"},
    {0, NULL }
};

static const range_string vals_broadcast_area_success[] = {
    {0,     100,    "%"},
    {101,   254,    "[Reserved]"},
    {255,   255,    "Information not available"},
    { 0,    0,      NULL }
};

static const value_string vals_broadcast_content_type_nw[] = {
    {0,     "Generic"},
    {1,     "GSM [23041]"},
    {2,     "TDMA [IS824][ANSI-41]"},
    {3,     "CDMA [IS824][IS637]"},
    {0,     NULL }
};

static const value_string vals_broadcast_content_type_type[] = {
    {0x0000,        "[System Service] Index"},
    {0x0001,        "[System Service] Emergency Broadcasts"},
    {0x0002,        "[System Service] IRDB Download"},
    {0x0010,        "[News Service] News Flashes"},
    {0x0011,        "[News Service] General News (Local)"},
    {0x0012,        "[News Service] General News (Regional)"},
    {0x0013,        "[News Service] General News (National)"},
    {0x0014,        "[News Service] General News (International)"},
    {0x0015,        "[News Service] Business/Financial News (Local)"},
    {0x0016,        "[News Service] Business/Financial News (Regional)"},
    {0x0017,        "[News Service] Business/Financial News (National)"},
    {0x0018,        "[News Service] Business/Financial News (International)"},
    {0x0019,        "[News Service] Sports News (Local)"},
    {0x001A,        "[News Service] Sports News (Regional)"},
    {0x001B,        "[News Service] Sports News (National)"},
    {0x001C,        "[News Service] Sports News (International)"},
    {0x001D,        "[News Service] Entertainment News (Local)"},
    {0x001E,        "[News Service] Entertainment News (Regional)"},
    {0x001F,        "[News Service] Entertainment News (National)"},
    {0x0020,        "[News Service] Entertainment News (International)"},
    {0x0021,        "[Subscriber Information Services] Medical/Health/Hospitals"},
    {0x0022,        "[Subscriber Information Services] Doctors"},
    {0x0023,        "[Subscriber Information Services] Pharmacy"},
    {0x0030,        "[Subscriber Information Services] Local Traffic/Road Reports"},
    {0x0031,        "[Subscriber Information Services] Long Distance Traffic/Road Reports"},
    {0x0032,        "[Subscriber Information Services] Taxis"},
    {0x0033,        "[Subscriber Information Services] Weather"},
    {0x0034,        "[Subscriber Information Services] Local Airport Flight Schedules"},
    {0x0035,        "[Subscriber Information Services] Restaurants"},
    {0x0036,        "[Subscriber Information Services] Lodgings"},
    {0x0037,        "[Subscriber Information Services] Retail Directory"},
    {0x0038,        "[Subscriber Information Services] Advertisements"},
    {0x0039,        "[Subscriber Information Services] Stock Quotes"},
    {0x0040,        "[Subscriber Information Services] Employment Opportunities"},
    {0x0041,        "[Subscriber Information Services] Technology News"},
    {0x0070,        "[Carrier Information Services] District (Base Station Info)"},
    {0x0071,        "[Carrier Information Services] Network Information"},
    {0x0080,        "[Subscriber Care Services] Operator Services"},
    {0x0081,        "[Subscriber Care Services] Directory Enquiries (National)"},
    {0x0082,        "[Subscriber Care Services] Directory Enquiries (International)"},
    {0x0083,        "[Subscriber Care Services] Customer Care (National)"},
    {0x0084,        "[Subscriber Care Services] Customer Care (International)"},
    {0x0085,        "[Subscriber Care Services] Local Date/Time/Time Zone"},
    {0x0100,        "[Multi Category Services] Multi Category Services"},
    {0x0000,        NULL }
};

static const value_string vals_broadcast_frequency_interval_unit[] = {
    {0x00,  "As frequently as possible"},
    {0x08,  "seconds"},
    {0x09,  "minutes"},
    {0x0A,  "hours"},
    {0x0B,  "days"},
    {0x0C,  "weeks"},
    {0x0D,  "months"},
    {0x0E,  "years"},
    {0x00,  NULL }
};

static const value_string vals_dest_addr_np_resolution[] = {
    {0x00,  "query has not been performed (default)"},
    {0x01,  "query has been performed, number not ported"},
    {0x02,  "query has been performed, number ported"},
    {0x00,  NULL }
};

static const range_string vals_broadcast_area_identifier_format[] = {
    {0,   0, "Alias / Name"},
    {1,   1, "Ellipsoid Arc"},
    {2,   2, "Polygon"},
    {3, 255, "[Reserved]"},
    {0, 0,  NULL }
};

/* Huawei SMPP+ extensions */
static const value_string vals_mo_mt_flag[] = {
    { 0x01, "MO" },
    { 0x02, "MT" },
    { 0x03, "Reserved" },
    { 0x00, NULL }
};

static const value_string vals_operation_result[] = {
    { 0x00, "Successful" },
    { 0x01, "Protocol is not supported" },
    { 0x0a, "Others" },
    { 0x0b, "MO account does not exist" },
    { 0x0c, "MT account does not exist" },
    { 0x0d, "MO account state is abnormal" },
    { 0x0e, "MT account state is abnormal" },
    { 0x0f, "MO account balance is not enough" },
    { 0x10, "MT account balance is not enough" },
    { 0x11, "MO VAS is not supported" },
    { 0x12, "MT VAS is not supported" },
    { 0x13, "MO user is post-paid user and checked success" },
    { 0x14, "MT user is post-paid user and checked success" },
    { 0x15, "MO post-paid user status is incorrect" },
    { 0x16, "MT post-paid user status is incorrect" },
    { 0x17, "MO post-paid user account balance is not sufficient" },
    { 0x18, "MT post-paid user account balance is not sufficient" },
    { 0x19, "MO post-paid user value-added services are not supported" },
    { 0x1a, "MT post-paid user value-added services are not supported" },
    { 0x00, NULL }
};

static const value_string vals_notify_mode[] = {
    { 0x01, "Deliver the report when it's successful or failed" },
    { 0x02, "Deliver the report only when it's failed" },
    { 0x03, "Deliver the report only when it's successful" },
    { 0x04, "Never deliver the report" },
    { 0x00, NULL }
};

static const value_string vals_delivery_result[] = {
    { 0x00, "Successful" },
    { 0x01, "Unsuccessful" },
    { 0x00, NULL }
};

static const value_string vals_msc_addr_noa    [] = {
    { 0x00, "Spare" },
    { 0x01, "Subscriber number" },
    { 0x02, "Unknown" },
    { 0x03, "National number" },
    { 0x04, "International" },
    { 0x00, NULL }
};

static const value_string vals_msc_addr_npi    [] = {
    { 0x00, "Spare" },
    { 0x01, "ISDN (Telephony) numbering plan (Recommendation E.164)" },
    { 0x02, "Spare" },
    { 0x03, "Data numbering plan (Recommendation X.121) (national use)" },
    { 0x04, "Telex numbering plan (Recommendation F.69) (national use)" },
    { 0x05, "Reserved for national use" },
    { 0x06, "Reserved for national use" },
    { 0x07, "Spare" },
    { 0x00, NULL }
};

static int * const regdel_fields[] = {
    &hf_smpp_regdel_receipt,
    &hf_smpp_regdel_acks,
    &hf_smpp_regdel_notif,
    NULL
};

static int * const submit_msg_fields[] = {
    &hf_smpp_esm_submit_msg_mode,
    &hf_smpp_esm_submit_msg_type,
    &hf_smpp_esm_submit_features,
    NULL
};

static dissector_handle_t gsm_sms_handle;

static smpp_data_t *
get_smpp_data(packet_info *pinfo)
{
    smpp_data_t *smpp_data = NULL;

    smpp_data = (smpp_data_t*)p_get_proto_data(pinfo->pool, pinfo, proto_smpp, 0);
    if (!smpp_data) {
        smpp_data = wmem_new0(pinfo->pool, smpp_data_t);
        p_add_proto_data(pinfo->pool, pinfo, proto_smpp, 0, smpp_data);
    }

    return smpp_data;
}

/*
 * For Stats Tree
 */
static void
smpp_stats_tree_init(stats_tree* st)
{
    st_smpp_ops = stats_tree_create_node(st, "SMPP Operations", 0, STAT_DT_INT, TRUE);
    st_smpp_req = stats_tree_create_node(st, "SMPP Requests", st_smpp_ops, STAT_DT_INT, TRUE);
    st_smpp_res = stats_tree_create_node(st, "SMPP Responses", st_smpp_ops, STAT_DT_INT, TRUE);
    st_smpp_res_status = stats_tree_create_node(st, "SMPP Response Status", 0, STAT_DT_INT, TRUE);

}

static tap_packet_status
smpp_stats_tree_per_packet(stats_tree *st, /* st as it was passed to us */
                           packet_info *pinfo _U_,
                           epan_dissect_t *edt _U_,
                           const void *p,
                           tap_flags_t flags _U_) /* Used for getting SMPP command_id values */
{
    const smpp_tap_rec_t* tap_rec = (const smpp_tap_rec_t*)p;

    tick_stat_node(st, "SMPP Operations", 0, TRUE);

    if ((tap_rec->command_id & SMPP_COMMAND_ID_RESPONSE_MASK) == SMPP_COMMAND_ID_RESPONSE_MASK) /* Response */
    {
        tick_stat_node(st, "SMPP Responses", st_smpp_ops, TRUE);
        tick_stat_node(st, val_to_str(tap_rec->command_id, vals_command_id, "Unknown 0x%08x"), st_smpp_res, FALSE);

        tick_stat_node(st, "SMPP Response Status", 0, TRUE);
        tick_stat_node(st, rval_to_str(tap_rec->command_status, rvals_command_status, "Unknown 0x%08x"), st_smpp_res_status, FALSE);

    }
    else  /* Request */
    {
        tick_stat_node(st, "SMPP Requests", st_smpp_ops, TRUE);
        tick_stat_node(st, val_to_str(tap_rec->command_id, vals_command_id, "Unknown 0x%08x"), st_smpp_req, FALSE);
    }

    return TAP_PACKET_REDRAW;
}

/*!
 * SMPP equivalent of mktime() (3). Convert date to standard 'time_t' format
 *
 * \param       datestr The SMPP-formatted date to convert
 * \param       secs    Returns the 'time_t' equivalent
 * \param       nsecs   Returns the additional nano-seconds
 *
 * \return              Whether time is specified relative (TRUE) or absolute (FALSE)
 *                      If invalid abs time: return *secs = (time_t)(-1) and *nsecs=0
 */

/* XXX: This function needs better error checking and handling */

static gboolean
smpp_mktime(const char *datestr, time_t *secs, int *nsecs)
{
    struct tm    r_time;
    time_t       t_diff;
    gboolean     relative = (datestr[15] == 'R') ? TRUE : FALSE;

    r_time.tm_year = 10 * (datestr[0] - '0') + (datestr[1] - '0');
    /*
     * Y2K rollover date as recommended in appendix C
     */
    if (r_time.tm_year < 38)
        r_time.tm_year += 100;
    r_time.tm_mon  = 10 * (datestr[2] - '0') + (datestr[3] - '0');
    r_time.tm_mon--;
    r_time.tm_mday = 10 * (datestr[4] - '0') + (datestr[5] - '0');
    r_time.tm_hour = 10 * (datestr[6] - '0') + (datestr[7] - '0');
    r_time.tm_min  = 10 * (datestr[8] - '0') + (datestr[9] - '0');
    r_time.tm_sec  = 10 * (datestr[10] - '0') + (datestr[11] - '0');
    r_time.tm_isdst = -1;

    if (relative == FALSE) {
        *secs = mktime_utc(&r_time);
        *nsecs = 0;
        if (*secs == (time_t)(-1)) {
            return relative;
        }
        *nsecs = (datestr[12] - '0') * 100000000;

        t_diff = (10 * (datestr[13] - '0') + (datestr[14] - '0')) * 900;
        if (datestr[15] == '-')
            /* Represented time is behind UTC, shift it forward to UTC */
            *secs += t_diff;
        else if (datestr[15] == '+')
            /* Represented time is ahead of UTC, shift it backward to UTC */
            *secs -= t_diff;
    } else {
        *secs = r_time.tm_sec + 60 *
            (r_time.tm_min + 60 *
             (r_time.tm_hour + 24 *
              r_time.tm_mday));
        *nsecs = 0;
    }

    return relative;
}

/*!
 * Scanning routines to add standard types (byte, int, string...) to the
 * protocol tree.
 *
 * \param       tree    The protocol tree to add to
 * \param       tvb     Buffer containing the data
 * \param       field   Actual field whose value needs displaying
 * \param       offset  Location of field in buffer, returns location of
 *                      next field
 */
static void
smpp_handle_string(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    guint        len;

    len = tvb_strsize(tvb, *offset);
    if (len > 1) {
        proto_tree_add_item(tree, field, tvb, *offset, len, ENC_NA);
    }
    (*offset) += len;
}

static const char *
smpp_handle_string_return(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int field, int *offset)
{
    gint         len;
    const char* str = (const char *)tvb_get_stringz_enc(pinfo->pool, tvb, *offset, &len, ENC_ASCII);

    if (len > 0)
        proto_tree_add_string(tree, field, tvb, *offset, len, str);

    (*offset) += len;
    return str;
}

static void
smpp_handle_string_z(proto_tree *tree, tvbuff_t *tvb, int field, int *offset,
                const char *null_string)
{
    gint         len;

    len = tvb_strsize(tvb, *offset);
    if (len > 1) {
        proto_tree_add_item(tree, field, tvb, *offset, len, ENC_NA);
    } else {
        proto_tree_add_string(tree, field, tvb, *offset, len, null_string);
    }
    (*offset) += len;
}

static void
smpp_handle_time(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
                 int field, int field_R, int *offset)
{
    char     *strval;
    gint      len;
    nstime_t  tmptime;

    strval = (char *) tvb_get_stringz_enc(pinfo->pool, tvb, *offset, &len, ENC_ASCII);
    if (*strval)
    {
        if (len >= 16)
        {
            if (smpp_mktime(strval, &tmptime.secs, &tmptime.nsecs))
                proto_tree_add_time(tree, field_R, tvb, *offset, len, &tmptime);
            else
                proto_tree_add_time(tree, field, tvb, *offset, len, &tmptime);
        }
        else
        {
            tmptime.secs = 0;
            tmptime.nsecs = 0;
            proto_tree_add_time_format_value(tree, field_R, tvb, *offset, len, &tmptime, "%s", strval);
        }
    }
    *offset += len;
}

/*!
 * Scanning routine to handle the destination-list of 'submit_multi'
 *
 * \param       tree    The protocol tree to add to
 * \param       tvb     Buffer containing the data
 * \param       offset  Location of field in buffer, returns location of
 *                      next field
 */
static void
smpp_handle_dlist(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    guint8       entries;
    int          tmpoff = *offset;
    proto_tree  *sub_tree = NULL;
    guint8       dest_flag;

    if ((entries = tvb_get_guint8(tvb, tmpoff++))) {
        proto_item  *pi;
        pi = proto_tree_add_item(tree, hf_smpp_dlist, tvb, *offset, 1, ENC_NA);
        sub_tree = proto_item_add_subtree(pi, ett_dlist);
    }
    while (entries--)
    {
        dest_flag = tvb_get_guint8(tvb, tmpoff++);
        if (dest_flag == 1)                     /* SME address  */
        {
            proto_tree_add_item(sub_tree, hf_smpp_dest_addr_ton, tvb, tmpoff, 1, ENC_NA);
            tmpoff += 1;
            proto_tree_add_item(sub_tree, hf_smpp_dest_addr_npi, tvb, tmpoff, 1, ENC_NA);
            tmpoff += 1;
            smpp_handle_string(sub_tree,tvb,hf_smpp_destination_addr,&tmpoff);
        }
        else                                    /* Distribution list    */
        {
            smpp_handle_string(sub_tree, tvb, hf_smpp_dl_name, &tmpoff);
        }
    }
    *offset = tmpoff;
}

/*!
 * Scanning routine to handle the destination result list
 * of 'submit_multi_resp'
 *
 * \param       tree    The protocol tree to add to
 * \param       tvb     Buffer containing the data
 * \param       offset  Location of field in buffer, returns location of
 *                      next field
 */
static void
smpp_handle_dlist_resp(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    guint8       entries;
    int          tmpoff = *offset;
    proto_tree  *sub_tree = NULL;

    if ((entries = tvb_get_guint8(tvb, tmpoff++))) {
        proto_item  *pi;
        pi = proto_tree_add_item(tree, hf_smpp_dlist_resp,
                                  tvb, *offset, 1, ENC_NA);
        sub_tree = proto_item_add_subtree(pi, ett_dlist_resp);
    }
    while (entries--)
    {
        proto_tree_add_item(sub_tree, hf_smpp_dest_addr_ton, tvb, tmpoff, 1, ENC_NA);
        tmpoff += 1;
        proto_tree_add_item(sub_tree, hf_smpp_dest_addr_npi, tvb, tmpoff, 1, ENC_NA);
        tmpoff += 1;
        smpp_handle_string(sub_tree,tvb,hf_smpp_destination_addr,&tmpoff);
        proto_tree_add_item(sub_tree, hf_smpp_error_status_code, tvb, tmpoff, 4, ENC_BIG_ENDIAN);
        tmpoff += 4;
    }
    *offset = tmpoff;
}

/*!
 * Scanning routine to handle all optional parameters of SMPP-operations.
 * The parameters have the format Tag Length Value (TLV), with a 2-byte tag
 * and 2-byte length.
 *
 * \param       tree    The protocol tree to add to
 * \param       tvb     Buffer containing the data
 * \param       offset  Location of field in buffer, returns location of
 *                      next field
 */
static void
smpp_handle_tlv(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *offset, tvbuff_t **tvb_msg)
{
    proto_tree *tlvs_tree = NULL;
    proto_item *pi;
    smpp_data_t *smpp_data;
    guint16 source_port = 0, dest_port = 0, sm_id = 0;
    guint8 frags = 0, frag = 0;
    gboolean source_port_found = FALSE, dest_port_found = FALSE;
    gboolean sm_id_found = FALSE;

    if (tvb_reported_length_remaining(tvb, *offset) >= 1) {
        pi = proto_tree_add_item(tree, hf_smpp_opt_params,
                                 tvb, *offset, -1, ENC_NA);
        tlvs_tree = proto_item_add_subtree(pi, ett_opt_params);
    }

    while (tvb_reported_length_remaining(tvb, *offset) >= 1)
    {
        proto_item *sub_tree;
        guint16  tag;
        guint16  length;

        tag = tvb_get_ntohs(tvb, *offset);
        length = tvb_get_ntohs(tvb, (*offset+2));

        pi = proto_tree_add_none_format(tlvs_tree, hf_smpp_opt_param, tvb,
                                        *offset, length+4,
                                        "Optional parameter: %s (0x%04x)",
                                        val_to_str(tag, vals_tlv_tags, "0x%04x"), tag);
        sub_tree = proto_item_add_subtree(pi, ett_opt_param);
        proto_tree_add_uint(sub_tree,hf_smpp_opt_param_tag,tvb,*offset,2,tag);
        proto_tree_add_uint(sub_tree,hf_smpp_opt_param_len,tvb,*offset+2,2,length);

        *offset += 4;

        switch (tag) {
            case  0x0005:       /* dest_addr_subunit    */
                proto_tree_add_item(sub_tree, hf_smpp_dest_addr_subunit, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0006:       /* dest_network_type    */
                proto_tree_add_item(sub_tree, hf_smpp_dest_network_type, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0007:       /* dest_bearer_type     */
                proto_tree_add_item(sub_tree, hf_smpp_dest_bearer_type, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0008:       /* dest_telematics_id   */
                proto_tree_add_item(sub_tree, hf_smpp_dest_telematics_id, tvb, *offset, 2, ENC_BIG_ENDIAN);
                (*offset) += 2;
                break;
            case  0x000D:       /* source_addr_subunit  */
                proto_tree_add_item(sub_tree, hf_smpp_source_addr_subunit, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x000E:       /* source_network_type  */
                proto_tree_add_item(sub_tree, hf_smpp_source_network_type, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x000F:       /* source_bearer_type   */
                proto_tree_add_item(sub_tree, hf_smpp_source_bearer_type, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0010:       /* source_telematics_id */
                proto_tree_add_item(sub_tree, hf_smpp_source_telematics_id, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0017:       /* qos_time_to_live     */
                proto_tree_add_item(sub_tree, hf_smpp_qos_time_to_live, tvb, *offset, 4, ENC_BIG_ENDIAN);
                (*offset) += 4;
                break;
            case  0x0019:       /* payload_type */
                proto_tree_add_item(sub_tree, hf_smpp_payload_type, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x001D:       /* additional_status_info_text  */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_additional_status_info_text,
                        tvb, *offset, length, ENC_NA | ENC_ASCII);
                (*offset) += length;
                break;
            case  0x001E:       /* receipted_message_id */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_receipted_message_id,
                        tvb, *offset, length, ENC_NA | ENC_ASCII);
                (*offset) += length;
                break;
            case  0x0030: {       /* ms_msg_wait_facilities       */
                static int * const fields[] = {
                    &hf_smpp_msg_wait_ind,
                    &hf_smpp_msg_wait_type,
                    NULL
                };


                proto_tree_add_bitmask_list(sub_tree, tvb, *offset, 1, fields, ENC_NA);
                (*offset)++;
                }
                break;
            case  0x0201:       /* privacy_indicator    */
                proto_tree_add_item(sub_tree, hf_smpp_privacy_indicator, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0202:       /* source_subaddress    */
                if (length) {
                    proto_tree_add_item(sub_tree, hf_smpp_source_subaddress,
                                    tvb, *offset, length, ENC_NA);
                    (*offset) += length;
                }
                break;
            case  0x0203:       /* dest_subaddress      */
                if (length) {
                    proto_tree_add_item(sub_tree, hf_smpp_dest_subaddress,
                                    tvb, *offset, length, ENC_NA);
                    (*offset) += length;
                }
                break;
            case  0x0204:       /* user_message_reference       */
                proto_tree_add_item(sub_tree, hf_smpp_user_message_reference, tvb, *offset, 2, ENC_BIG_ENDIAN);
                (*offset) += 2;
                break;
            case  0x0205:       /* user_response_code   */
                proto_tree_add_item(sub_tree, hf_smpp_user_response_code, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x020A:       /* source_port  */
                proto_tree_add_item(sub_tree, hf_smpp_source_port, tvb, *offset, 2, ENC_BIG_ENDIAN);
                source_port = tvb_get_ntohs(tvb, *offset);
                source_port_found = TRUE;
                (*offset) += 2;
                break;
            case  0x020B:       /* destination_port     */
                proto_tree_add_item(sub_tree, hf_smpp_destination_port, tvb, *offset, 2, ENC_BIG_ENDIAN);
                dest_port = tvb_get_ntohs(tvb, *offset);
                dest_port_found = TRUE;
                (*offset) += 2;
                break;
            case  0x020C:       /* sar_msg_ref_num      */
                proto_tree_add_item(sub_tree, hf_smpp_sar_msg_ref_num, tvb, *offset, 2, ENC_BIG_ENDIAN);
                sm_id = tvb_get_ntohs(tvb, *offset);
                sm_id_found = TRUE;
                (*offset) += 2;
                break;
            case  0x020D:       /* language_indicator   */
                proto_tree_add_item(sub_tree, hf_smpp_language_indicator, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x020E:       /* sar_total_segments   */
                proto_tree_add_item(sub_tree, hf_smpp_sar_total_segments, tvb, *offset, 1, ENC_NA);
                frags = tvb_get_guint8(tvb, *offset);
                (*offset) += 1;
                break;
            case  0x020F:       /* sar_segment_seqnum   */
                proto_tree_add_item(sub_tree, hf_smpp_sar_segment_seqnum, tvb, *offset, 1, ENC_NA);
                frag = tvb_get_guint8(tvb, *offset);
                (*offset) += 1;
                break;
            case  0x0210:       /* SC_interface_version */
                proto_tree_add_item(sub_tree, hf_smpp_SC_interface_version, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0302: {      /* callback_num_pres_ind        */

                static int * const fields[] = {
                    &hf_smpp_callback_num_pres,
                    &hf_smpp_callback_num_scrn,
                    NULL
                };

                proto_tree_add_bitmask_list(sub_tree, tvb, *offset, 1, fields, ENC_NA);
                (*offset)++;
                }
                break;
            case  0x0303:       /* callback_num_atag    */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_callback_num_atag,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case  0x0304:       /* number_of_messages   */
                proto_tree_add_item(sub_tree, hf_smpp_number_of_messages, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0381:       /* callback_num */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_callback_num,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case  0x0420:       /* dpf_result   */
                proto_tree_add_item(sub_tree, hf_smpp_dpf_result, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0421:       /* set_dpf      */
                proto_tree_add_item(sub_tree, hf_smpp_set_dpf, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0422:       /* ms_availability_status       */
                proto_tree_add_item(sub_tree, hf_smpp_ms_availability_status, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0423:       /* network_error_code   */
                proto_tree_add_item(sub_tree, hf_smpp_network_error_type, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                proto_tree_add_item(sub_tree, hf_smpp_network_error_code, tvb, *offset, 2, ENC_BIG_ENDIAN);
                (*offset) += 2;
                break;
            case  0x0424:       /* message_payload      */
                if (length) {
                    pi = proto_tree_add_item(sub_tree, hf_smpp_message_payload,
                                             tvb, *offset, length, ENC_NA);
                    if (tvb_msg) {
                        if (*tvb_msg != NULL) {
                            expert_add_info(pinfo, pi, &ei_smpp_message_payload_duplicate);
                        }
                        *tvb_msg = tvb_new_subset_length(tvb, *offset, length);
                    }
                }
                (*offset) += length;
                break;
            case  0x0425:       /* delivery_failure_reason      */
                proto_tree_add_item(sub_tree, hf_smpp_delivery_failure_reason, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0426:       /* more_messages_to_send        */
                proto_tree_add_item(sub_tree, hf_smpp_more_messages_to_send, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0427:       /* message_state        */
                proto_tree_add_item(sub_tree, hf_smpp_message_state, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case        0x0428: /* congestion_state */
                proto_tree_add_item(sub_tree, hf_smpp_congestion_state, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x0501:       /* ussd_service_op      */
                proto_tree_add_item(sub_tree, hf_smpp_ussd_service_op, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case 0x0600:        /* broadcast_channel_indicator */
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_channel_indicator, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case 0x0601:        /* broadcast_content_type */
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_content_type_nw, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_content_type_type, tvb, *offset, 2, ENC_BIG_ENDIAN);
                (*offset) += 2;
                break;
            case 0x0602:        /* broadcast_content_type_info */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_broadcast_content_type_info,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case 0x0603:        /* broadcast_message_class */
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_message_class, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case 0x0604:        /* broadcast_rep_num */
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_rep_num, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case 0x0605:        /* broadcast_frequency_interval */
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_frequency_interval_unit, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_frequency_interval_value, tvb, *offset, 2, ENC_BIG_ENDIAN);
                (*offset) += 2;
                break;
            case 0x0606:        /* broadcast_area_identifier */
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_area_identifier_format, tvb, *offset, 1, ENC_NA);
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_area_identifier,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case 0x0607:        /* broadcast_error_status */
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_error_status, tvb, *offset, 4, ENC_BIG_ENDIAN);
                (*offset) += 4;
                break;
            case 0x0608:        /* broadcast_area_success */
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_area_success, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case 0x0609:        /* broadcast_end_time */
                smpp_handle_time(sub_tree, tvb, pinfo, hf_smpp_broadcast_end_time,
                                hf_smpp_broadcast_end_time_r, offset);
                break;
            case 0x060A:        /* broadcast_service_group */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_broadcast_service_group,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case 0x060B:        /* billing_identification */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_billing_identification,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            /* 0x060C is skipped in the specs for some reason :-? */
            case 0x060D:        /* source_network_id */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_source_network_id,
                        tvb, *offset, length, ENC_NA|ENC_ASCII);
                (*offset) += length;
                break;
            case 0x060E:        /* dest_network_id */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_dest_network_id,
                        tvb, *offset, length, ENC_NA | ENC_ASCII);
                (*offset) += length;
                break;
            case 0x060F:        /* source_node_id */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_source_node_id,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case 0x0610:        /* dest_node_id */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_dest_node_id,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case 0x0611:        /* dest_addr_np_resolution */
                proto_tree_add_item(sub_tree, hf_smpp_dest_addr_np_resolution, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case 0x0612:        /* dest_addr_np_information */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_dest_addr_np_information,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case 0x0613:        /* dest_addr_np_country */
                /* TODO : Fetch values from packet-e164? */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_dest_addr_np_country,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case  0x1201:       /* display_time */
                proto_tree_add_item(sub_tree, hf_smpp_display_time, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x1203:       /* sms_signal   */
                proto_tree_add_item(sub_tree, hf_smpp_sms_signal, tvb, *offset, 2, ENC_BIG_ENDIAN);
                (*offset) += 2;
                /*! \todo Fill as per TIA/EIA-136-710-A         */
                break;
            case  0x1204:       /* ms_validity  */
                proto_tree_add_item(sub_tree, hf_smpp_ms_validity, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x130C:       /* alert_on_message_delivery    */
                if (length == 0) {
                        proto_tree_add_item(sub_tree,
                                    hf_smpp_alert_on_message_delivery_null,
                                    tvb, *offset, length, ENC_NA);
                } else {
                    proto_tree_add_item(sub_tree, hf_smpp_alert_on_message_delivery_type, tvb, *offset, 1, ENC_NA);
                    (*offset) += 1;
                }
                break;
            case  0x1380:       /* its_reply_type       */
                proto_tree_add_item(sub_tree, hf_smpp_its_reply_type, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                break;
            case  0x1383: {      /* its_session_info     */

                static int * const fields[] = {
                    &hf_smpp_its_session_sequence,
                    &hf_smpp_its_session_ind,
                    NULL
                };

                proto_tree_add_item(sub_tree, hf_smpp_its_session_number, tvb, *offset, 1, ENC_NA);
                (*offset) += 1;
                proto_tree_add_bitmask_list(sub_tree, tvb, *offset, 1, fields, ENC_NA);
                (*offset) += 1;
                }
                break;

            default:
                /* TODO : Hopefully to be implemented soon - handle vendor specific TLVs
                 * from a dictionary before treating them as unknown! */
                if ((tag >= 0x1400) && (tag <= 0x3FFF)) {
                    proto_tree_add_item(sub_tree, hf_smpp_vendor_op, tvb,
                                        *offset, length, ENC_NA);
                } else {
                    proto_tree_add_item(sub_tree, hf_smpp_reserved_op, tvb,
                                        *offset, length, ENC_NA);
                }

                if (length > 0) {
                    char *str;
                    str = tvb_bytes_to_str(NULL, tvb,*offset,length);
                    proto_item_append_text(sub_tree,": %s", str);
                    wmem_free(NULL, str);
                }

                (*offset) += length;
                break;
        }
    }

    if (source_port_found && dest_port_found) {
        smpp_data = get_smpp_data(pinfo);
        if (smpp_data->udh_fields == NULL) {
            smpp_data->udh_fields = wmem_new0(pinfo->pool, gsm_sms_udh_fields_t);
        }
        smpp_data->udh_fields->port_src = source_port;
        smpp_data->udh_fields->port_dst = dest_port;
    }

    if (sm_id_found && frags && frag) {
        /* frags and frag must be at least 1 */
        smpp_data = get_smpp_data(pinfo);
        if (smpp_data->udh_fields == NULL) {
            smpp_data->udh_fields = wmem_new0(pinfo->pool, gsm_sms_udh_fields_t);
        }
        smpp_data->udh_fields->sm_id = sm_id;
        smpp_data->udh_fields->frags = frags;
        smpp_data->udh_fields->frag  = frag;
    }
}

void
smpp_handle_dcs(proto_tree *tree, tvbuff_t *tvb, int *offset, guint *encoding)
{
    guint32     val;
    guint8      dataCoding;
    int         off     = *offset;
    proto_tree *subtree;
    proto_item *pi;

    /* SMPP Data Coding Scheme */
    pi = proto_tree_add_item_ret_uint(tree, hf_smpp_data_coding, tvb, off, 1, ENC_NA, &val);

    if (val & 0xC0) {

        /* GSM SMS Data Coding Scheme */
        subtree = proto_item_add_subtree(pi, ett_dcs);

        if ((val & 0xF0) == 0xF0) {
            static int * const gsm_msg_control_fields[] = {
                &hf_smpp_dcs_sms_coding_group,
                &hf_smpp_dcs_reserved,
                &hf_smpp_dcs_charset,
                &hf_smpp_dcs_class,
                NULL
            };

            proto_tree_add_bitmask_list(subtree, tvb, off, 1, gsm_msg_control_fields, ENC_NA);
            if ((val & 0x04) == 0x04) {
                dataCoding = DECODE_AS_OCTET;
            } else {
                dataCoding = DECODE_AS_GSM7;
            }
        } else {
            static int * const gsm_mwi_control_fields[] = {
                &hf_smpp_dcs_sms_coding_group,
                &hf_smpp_dcs_wait_ind,
                &hf_smpp_dcs_reserved2,
                &hf_smpp_dcs_wait_type,
                NULL
            };

            proto_tree_add_bitmask_list(subtree, tvb, off, 1, gsm_mwi_control_fields, ENC_NA);
            if ((val & 0xF0) == 0xE0) {
                dataCoding = DECODE_AS_UCS2;
            } else {
                dataCoding = DECODE_AS_GSM7;
            }
        }
    } else {
        dataCoding = val;
    }
    if (encoding != NULL) {
        switch (dataCoding)
        {
        case DECODE_AS_DEFAULT:
            *encoding = smpp_decode_dcs_0_sms;
            break;
        case DECODE_AS_ASCII:
            *encoding = ENC_ASCII;
            break;
        case DECODE_AS_OCTET:
            *encoding = DO_NOT_DECODE;
            break;
        case DECODE_AS_ISO_8859_1:
            *encoding = ENC_ISO_8859_1;
            break;
        case DECODE_AS_ISO_8859_5:
            *encoding = ENC_ISO_8859_5;
            break;
        case DECODE_AS_ISO_8859_8:
            *encoding = ENC_ISO_8859_8;
            break;
        case DECODE_AS_UCS2:
            *encoding = ENC_UCS_2|ENC_BIG_ENDIAN;
            break;
        case DECODE_AS_KSC5601:
            *encoding = ENC_EUC_KR;
            break;
        case DECODE_AS_GSM7:
            *encoding = smpp_gsm7_unpacked ? ENC_3GPP_TS_23_038_7BITS_UNPACKED :
                ENC_3GPP_TS_23_038_7BITS_PACKED;
            break;
        default:
            /* XXX: Support decoding unknown values according to the pref? */
            *encoding = DO_NOT_DECODE;
            break;
        }
    }

    (*offset)++;
}

static void
smpp_handle_msg(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, const char *src_str, const char *dst_str)
{
    smpp_data_t *smpp_data;
    address      save_src, save_dst;
    guint        encoding;
    int          udh_offset = 0;
    int          length;

    smpp_data = get_smpp_data(pinfo);
    encoding = smpp_data->encoding;

    length = tvb_reported_length(tvb);

    if (smpp_data->udhi) /* UDHI indicator present */
    {
        udh_offset = tvb_get_guint8(tvb, 0) + 1;
    }

    if (smpp_data->udhi || smpp_data->udh_fields) {
        /* Save original addresses */
        copy_address_shallow(&save_src, &pinfo->src);
        copy_address_shallow(&save_dst, &pinfo->dst);
        /* Set SMPP source and destination address */
        set_address(&(pinfo->src), AT_STRINGZ, 1+(int)strlen(src_str), src_str);
        set_address(&(pinfo->dst), AT_STRINGZ, 1+(int)strlen(dst_str), dst_str);
        call_dissector_with_data(gsm_sms_handle, tvb, pinfo, proto_tree_get_parent_tree(tree), smpp_data);
        /* Restore original addresses */
        copy_address_shallow(&pinfo->src, &save_src);
        copy_address_shallow(&pinfo->dst, &save_dst);
    }

    if (smpp_data->encoding != DO_NOT_DECODE) {
        if (smpp_data->encoding == ENC_3GPP_TS_23_038_7BITS_PACKED && smpp_data->udhi) {
            /* SMPP only has the number of octets of the payload, but when
             * packed 7-bit GSM alphabet is used with a UDH, there are fill
             * bits after the UDH to align the SM start with a septet boundary.
             * Calculate the fill bits after the UDH as well as the number of
             * septets that could fit in the bytes. (In certain circumstances
             * there are two possible numbers of septets that would require
             * a certain number of octets. This is part of why packet 7-bit
             * GSM alphabet is not usually used in SMPP, but there are reports
             * of some servers out there.)
             */
            guint8 fill_bits = 6 - ((udh_offset - 1) * 8) % 7;
            int septets = ((length - udh_offset) * 8 - fill_bits) / 7;
            proto_tree_add_ts_23_038_7bits_packed_item(tree, hf_smpp_short_message, tvb, udh_offset * 8 + fill_bits, septets);
        } else {
            proto_tree_add_item(tree, hf_smpp_short_message, tvb,
                    udh_offset, length-udh_offset, encoding);
        }
    }
}

/*!
 * The next set of routines handle the different operations, associated
 * with SMPP.
 */
static void
bind_receiver(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    smpp_handle_string(tree, tvb, hf_smpp_system_id, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_password, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_system_type, &offset);
    proto_tree_add_item(tree, hf_smpp_interface_version, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_string_z(tree, tvb, hf_smpp_address_range, &offset, "NULL");
}

static void
query_sm(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    proto_tree_add_item(tree, hf_smpp_source_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_source_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
}

static void
outbind(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    smpp_handle_string(tree, tvb, hf_smpp_system_id, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_password, &offset);
}

static void
submit_sm(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    tvbuff_t    *tvb_msg = NULL;
    smpp_data_t *smpp_data;
    guint32      length;
    const char  *src_str = NULL;
    const char  *dst_str = NULL;
    nstime_t     zero_time = NSTIME_INIT_ZERO;

    smpp_data = get_smpp_data(pinfo);

    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    proto_tree_add_item(tree, hf_smpp_source_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_source_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    src_str = smpp_handle_string_return(tree, tvb, pinfo, hf_smpp_source_addr, &offset);
    proto_tree_add_item(tree, hf_smpp_dest_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_dest_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    dst_str = smpp_handle_string_return(tree, tvb, pinfo, hf_smpp_destination_addr, &offset);

    smpp_data->udhi = tvb_get_guint8(tvb, offset) & 0x40;
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, submit_msg_fields, ENC_NA);
    offset++;

    proto_tree_add_item(tree, hf_smpp_protocol_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_priority_flag, tvb, offset, 1, ENC_NA);
    offset += 1;
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, pinfo, hf_smpp_schedule_delivery_time,
                         hf_smpp_schedule_delivery_time_r, &offset);
    } else { /* Time = NULL means Immediate delivery */
        proto_tree_add_time_format_value(tree, hf_smpp_schedule_delivery_time_r, tvb, offset++, 1, &zero_time, "Immediate delivery");
    }
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, pinfo, hf_smpp_validity_period,
                         hf_smpp_validity_period_r, &offset);
    } else { /* Time = NULL means SMSC default validity */
        proto_tree_add_time_format_value(tree, hf_smpp_validity_period_r, tvb, offset++, 1, &zero_time, "SMSC default validity period");
    }

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, regdel_fields, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_smpp_replace_if_present_flag, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_dcs(tree, tvb, &offset, &smpp_data->encoding);
    proto_tree_add_item(tree, hf_smpp_sm_default_msg_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_smpp_sm_length, tvb, offset++, 1, ENC_NA, &length);
    if (length)
    {
        proto_tree_add_item(tree, hf_smpp_short_message_bin,
                            tvb, offset, length, ENC_NA);
        tvb_msg = tvb_new_subset_length(tvb, offset, length);
        offset += length;
    }
    /* Get rid of SMPP text string addresses */
    smpp_handle_tlv(tree, tvb, pinfo, &offset, &tvb_msg);

    if (tvb_msg) {
        smpp_handle_msg(tree, tvb_msg, pinfo, src_str, dst_str);
    }
}

static void
replace_sm(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    tvbuff_t    *tvb_msg = NULL;
    smpp_data_t *smpp_data;
    guint32      length;
    const char  *src_str = NULL;
    nstime_t     zero_time = NSTIME_INIT_ZERO;

    smpp_data = get_smpp_data(pinfo);

    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    proto_tree_add_item(tree, hf_smpp_source_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_source_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    src_str = smpp_handle_string_return(tree, tvb, pinfo, hf_smpp_source_addr, &offset);
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, pinfo, hf_smpp_schedule_delivery_time,
                                hf_smpp_schedule_delivery_time_r, &offset);
    } else { /* Time = NULL */
        proto_tree_add_time_format_value(tree, hf_smpp_schedule_delivery_time_r, tvb, offset++, 1, &zero_time, "Keep initial delivery time setting");
    }
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, pinfo, hf_smpp_validity_period,
                                hf_smpp_validity_period_r, &offset);
    } else { /* Time = NULL */
        proto_tree_add_time_format_value(tree, hf_smpp_validity_period_r, tvb, offset++, 1,&zero_time, "Keep initial validity period setting");
    }
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, regdel_fields, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_smpp_sm_default_msg_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_smpp_sm_length, tvb, offset++, 1, ENC_NA, &length);
    /* XXX: replace_sm does not contain a DCS element, so theoretically
     * the encoding must be the same as the previously submitted message
     * with the same message ID. We don't track that, though, so just assume
     * default.
     */
    smpp_data->encoding = smpp_decode_dcs_0_sms;
    if (length) {
        proto_tree_add_item(tree, hf_smpp_short_message_bin,
                tvb, offset, length, ENC_NA);
        tvb_msg = tvb_new_subset_length(tvb, offset, length);
    }
    offset += length;
    smpp_handle_tlv(tree, tvb, pinfo, &offset, &tvb_msg);
    if (tvb_msg) {
        smpp_handle_msg(tree, tvb_msg, pinfo, src_str, "");
    }
}

static void
cancel_sm(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    proto_tree_add_item(tree, hf_smpp_source_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_source_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    proto_tree_add_item(tree, hf_smpp_dest_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_dest_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_smpp_destination_addr, &offset);
}

static void
submit_multi(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    tvbuff_t    *tvb_msg = NULL;
    smpp_data_t *smpp_data;
    guint32      length;
    const char  *src_str = NULL;
    nstime_t     zero_time = NSTIME_INIT_ZERO;

    smpp_data = get_smpp_data(pinfo);

    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    proto_tree_add_item(tree, hf_smpp_source_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_source_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    src_str = smpp_handle_string_return(tree, tvb, pinfo, hf_smpp_source_addr, &offset);

    smpp_handle_dlist(tree, tvb, &offset);

    proto_tree_add_bitmask_list(tree, tvb, offset, 1, submit_msg_fields, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_smpp_protocol_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_priority_flag, tvb, offset, 1, ENC_NA);
    offset += 1;
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, pinfo, hf_smpp_schedule_delivery_time,
                hf_smpp_schedule_delivery_time_r, &offset);
    } else { /* Time = NULL means Immediate delivery */
        proto_tree_add_time_format_value(tree, hf_smpp_schedule_delivery_time_r, tvb, offset++, 1, &zero_time, "Immediate delivery");
    }
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, pinfo, hf_smpp_validity_period, hf_smpp_validity_period_r, &offset);
    } else { /* Time = NULL means SMSC default validity */
        proto_tree_add_time_format_value(tree, hf_smpp_schedule_delivery_time_r, tvb, offset++, 1, &zero_time, "SMSC default validity period");
    }
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, regdel_fields, ENC_NA);
    offset++;
    proto_tree_add_item(tree, hf_smpp_replace_if_present_flag, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_dcs(tree, tvb, &offset, &smpp_data->encoding);
    proto_tree_add_item(tree, hf_smpp_sm_default_msg_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item_ret_uint(tree, hf_smpp_sm_length, tvb, offset++, 1, ENC_NA, &length);
    if (length) {
        proto_tree_add_item(tree, hf_smpp_short_message_bin,
                tvb, offset, length, ENC_NA);
        tvb_msg = tvb_new_subset_length(tvb, offset, length);
    }
    offset += length;
    smpp_handle_tlv(tree, tvb, pinfo, &offset, &tvb_msg);
    if (tvb_msg) {
        /* submit_multi can have many destinations; for reassembly purposes
         * use the null address, like a broadcast.
         */
        smpp_handle_msg(tree, tvb_msg, pinfo, src_str, "");
    }
}

static void
alert_notification(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    proto_tree_add_item(tree, hf_smpp_source_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_source_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    proto_tree_add_item(tree, hf_smpp_esme_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_esme_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_smpp_esme_addr, &offset);
    smpp_handle_tlv(tree, tvb, pinfo, &offset, NULL);
}

static void
data_sm(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    tvbuff_t    *tvb_msg = NULL;
    smpp_data_t *smpp_data;
    const char  *src_str = NULL;
    const char  *dst_str = NULL;

    smpp_data = get_smpp_data(pinfo);

    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    proto_tree_add_item(tree, hf_smpp_source_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_source_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    src_str = smpp_handle_string_return(tree, tvb, pinfo, hf_smpp_source_addr, &offset);
    proto_tree_add_item(tree, hf_smpp_dest_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_dest_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    dst_str = smpp_handle_string_return(tree, tvb, pinfo, hf_smpp_destination_addr, &offset);
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, submit_msg_fields, ENC_NA);
    offset++;
    proto_tree_add_bitmask_list(tree, tvb, offset, 1, regdel_fields, ENC_NA);
    offset++;
    smpp_handle_dcs(tree, tvb, &offset, &smpp_data->encoding);
    smpp_handle_tlv(tree, tvb, pinfo, &offset, &tvb_msg);
    if (tvb_msg) {
        smpp_handle_msg(tree, tvb_msg, pinfo, src_str, dst_str);
    }
}

/*
 * Request operations introduced in the SMPP 5.0
 */
static void
broadcast_sm(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    nstime_t     zero_time = NSTIME_INIT_ZERO;
    tvbuff_t    *tvb_msg = NULL;
    smpp_data_t *smpp_data;
    const char  *src_str = NULL;

    smpp_data = get_smpp_data(pinfo);

    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    proto_tree_add_item(tree, hf_smpp_source_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_source_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    src_str = smpp_handle_string_return(tree, tvb, pinfo, hf_smpp_source_addr, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    proto_tree_add_item(tree, hf_smpp_priority_flag, tvb, offset, 1, ENC_NA);
    offset += 1;
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, pinfo, hf_smpp_schedule_delivery_time,
                hf_smpp_schedule_delivery_time_r, &offset);
    } else { /* Time = NULL means Immediate delivery */
        proto_tree_add_time_format_value(tree, hf_smpp_schedule_delivery_time_r, tvb, offset++, 1, &zero_time, "Immediate delivery");
    }
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, pinfo, hf_smpp_validity_period, hf_smpp_validity_period_r, &offset);
    } else { /* Time = NULL means SMSC default validity */
        proto_tree_add_time_format_value(tree, hf_smpp_validity_period_r, tvb, offset++, 1, &zero_time, "SMSC default validity period");
    }
    proto_tree_add_item(tree, hf_smpp_replace_if_present_flag, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_dcs(tree, tvb, &offset, &smpp_data->encoding);
    proto_tree_add_item(tree, hf_smpp_sm_default_msg_id, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_tlv(tree, tvb, pinfo, &offset, &tvb_msg);
    if (tvb_msg) {
        smpp_handle_msg(tree, tvb_msg, pinfo, src_str, "");
    }
}

static void
query_broadcast_sm(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    proto_tree_add_item(tree, hf_smpp_source_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_source_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_tlv(tree, tvb, pinfo, &offset, NULL);
}

static void
cancel_broadcast_sm(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    proto_tree_add_item(tree, hf_smpp_source_addr_ton, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_source_addr_npi, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_tlv(tree, tvb, pinfo, &offset, NULL);
}

/*!
 * The next set of routines handle the different operation-responses,
 * associated with SMPP.
 */
static void
bind_receiver_resp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    smpp_handle_string(tree, tvb, hf_smpp_system_id, &offset);
    smpp_handle_tlv(tree, tvb, pinfo, &offset, NULL);
}

static void
query_sm_resp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_time(tree, tvb, pinfo, hf_smpp_final_date,
                                hf_smpp_final_date_r, &offset);
    proto_tree_add_item(tree, hf_smpp_message_state, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(tree, hf_smpp_error_code, tvb, offset, 1, ENC_NA);
    offset += 1;
}

static void
submit_sm_resp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_tlv(tree, tvb, pinfo, &offset, NULL);
}

static void
submit_multi_resp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_dlist_resp(tree, tvb, &offset);
    smpp_handle_tlv(tree, tvb, pinfo, &offset, NULL);
}

static void
data_sm_resp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_tlv(tree, tvb, pinfo, &offset, NULL);
}

static void
query_broadcast_sm_resp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_tlv(tree, tvb, pinfo, &offset, NULL);
}

/* Huawei SMPP+ extensions */
static void
huawei_auth_acc(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    guint32 version;

    proto_tree_add_item_ret_uint(tree, hf_smpp_error_code, tvb, offset, 1, ENC_NA, &version);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_huawei_smpp_smsc_addr, &offset);
    if ( version == '3' ) {
        proto_tree_add_item(tree, hf_huawei_smpp_msc_addr_noa, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(tree, hf_huawei_smpp_msc_addr_npi, tvb, offset, 1, ENC_NA);
        offset += 1;
        smpp_handle_string(tree, tvb, hf_huawei_smpp_msc_addr, &offset);
    }
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_destination_addr, &offset);
    proto_tree_add_item(tree, hf_huawei_smpp_mo_mt_flag, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_huawei_smpp_sm_id, &offset);
    proto_tree_add_item(tree, hf_huawei_smpp_length_auth, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_huawei_smpp_service_id, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
huawei_auth_acc_resp(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_tree_add_item(tree, hf_huawei_smpp_operation_result, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_huawei_smpp_notify_mode, tvb, offset, 1, ENC_NA);
}

static void
huawei_sm_result_notify(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    guint32 version;

    proto_tree_add_item_ret_uint(tree, hf_smpp_error_code, tvb, offset, 1, ENC_NA, &version);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_huawei_smpp_smsc_addr, &offset);

    if ( version == '3' ) {
        proto_tree_add_item(tree, hf_huawei_smpp_msc_addr_noa, tvb, offset, 1, ENC_NA);
        offset += 1;
        proto_tree_add_item(tree, hf_huawei_smpp_msc_addr_npi, tvb, offset, 1, ENC_NA);
        offset += 1;
        smpp_handle_string(tree, tvb, hf_huawei_smpp_msc_addr, &offset);
    }

    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_destination_addr, &offset);
    proto_tree_add_item(tree, hf_huawei_smpp_mo_mt_flag, tvb, offset, 1, ENC_NA);
    offset += 1;
    smpp_handle_string(tree, tvb, hf_huawei_smpp_sm_id, &offset);
    proto_tree_add_item(tree, hf_huawei_smpp_length_auth, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_huawei_smpp_delivery_result, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_huawei_smpp_service_id, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static void
huawei_sm_result_notify_resp(proto_tree *tree, tvbuff_t *tvb, int offset)
{
    proto_tree_add_item(tree, hf_huawei_smpp_delivery_result, tvb, offset, 4, ENC_BIG_ENDIAN);
}

static gboolean
test_smpp(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    guint32      command_id;            /* SMPP command         */
    guint32      command_status;        /* Status code          */
    guint32      command_length;        /* length of PDU        */

    if (tvb_reported_length_remaining(tvb, offset) < SMPP_MIN_LENGTH ||   /* Mandatory header     */
        tvb_captured_length_remaining(tvb, offset) < 12)
        return FALSE;
    command_length = tvb_get_ntohl(tvb, offset);
    if (command_length > 64 * 1024 || command_length < SMPP_MIN_LENGTH)
        return FALSE;
    command_id = tvb_get_ntohl(tvb, offset + 4);         /* Only known commands  */
    if (try_val_to_str(command_id, vals_command_id) == NULL)
        return FALSE;
    command_status = tvb_get_ntohl(tvb, offset + 8);     /* ..with known status  */
    if (try_rval_to_str(command_status, rvals_command_status) == NULL)
        return FALSE;

    return TRUE;
}

static guint
get_smpp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
    return tvb_get_ntohl(tvb, offset);
}

static void
export_smpp_pdu(packet_info *pinfo, tvbuff_t *tvb)
{
    exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, "smpp", EXP_PDU_TAG_PROTO_NAME);

    exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
    exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
    exp_pdu_data->pdu_tvb = tvb;

    tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);
}

/* Dissect a single SMPP PDU contained within "tvb". */
static int
dissect_smpp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int             offset      = 0; /* Offset within tvbuff */
    guint           command_length;  /* length of PDU        */
    guint           command_id;      /* SMPP command         */
    guint           command_status;  /* Status code          */
    guint           sequence_number; /* ...of command        */
    smpp_tap_rec_t *tap_rec;         /* Tap record           */
    const gchar    *command_str;
    const gchar    *command_status_str = NULL;
    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item     *ti;
    proto_tree     *smpp_tree;

    /*
     * Safety: don't even try to dissect the PDU
     * when the mandatory header isn't present.
     */
    if (tvb_reported_length(tvb) < SMPP_MIN_LENGTH)
        return 0;
    command_length = tvb_get_ntohl(tvb, offset);
    offset += 4;
    command_id = tvb_get_ntohl(tvb, offset);
    command_str = val_to_str(command_id, vals_command_id,
            "(Unknown SMPP Operation 0x%08X)");
    offset += 4;
    command_status = tvb_get_ntohl(tvb, offset);
    if (command_id & SMPP_COMMAND_ID_RESPONSE_MASK) {
        /* PDU is a response. */
        command_status_str = rval_to_str(command_status, rvals_command_status, "Unknown (0x%08x)");
    }
    offset += 4;
    sequence_number = tvb_get_ntohl(tvb, offset);

    if (have_tap_listener(exported_pdu_tap)){
        export_smpp_pdu(pinfo,tvb);
    }

    /*
     * Update the protocol column.
     */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMPP");
    col_clear(pinfo->cinfo, COL_INFO);

    /*
     * Create display subtree for the protocol
     */
    ti = proto_tree_add_item (tree, proto_smpp, tvb, 0, tvb_captured_length(tvb), ENC_NA);
    smpp_tree = proto_item_add_subtree (ti, ett_smpp);

    /*
     * Make entries in the Info column on the summary display
     */
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", command_str);

    /*
     * Display command status of responses in Info column
     */
    if (command_id & SMPP_COMMAND_ID_RESPONSE_MASK) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ": \"%s\"", command_status_str);
    }

    /*
     * Set the fence before dissecting the PDU because if the PDU is invalid it
     * may throw an exception and the next PDU will clear the info about the
     * current PDU
     */
    col_set_fence(pinfo->cinfo, COL_INFO);

    /*
     * Dissect the PDU
     */

    /*
     * Create display subtree for the PDU
     */
    proto_tree_add_uint(smpp_tree, hf_smpp_command_length, tvb, 0, 4, command_length);
    proto_tree_add_uint(smpp_tree, hf_smpp_command_id, tvb, 4, 4, command_id);
    proto_item_append_text(ti, ", Command: %s", command_str);

    /*
     * Status is only meaningful with responses
     */
    if (command_id & SMPP_COMMAND_ID_RESPONSE_MASK) {
        proto_tree_add_uint(smpp_tree, hf_smpp_command_status, tvb, 8, 4, command_status);
        proto_item_append_text (ti, ", Status: \"%s\"", command_status_str);
    }
    proto_tree_add_uint(smpp_tree, hf_smpp_sequence_number, tvb, 12, 4, sequence_number);
    proto_item_append_text(ti, ", Seq: %u, Len: %u", sequence_number, command_length);

    if (command_length <= tvb_reported_length(tvb))
    {
        if (command_id & SMPP_COMMAND_ID_RESPONSE_MASK)
        {
            switch (command_id & (~SMPP_COMMAND_ID_RESPONSE_MASK)) {
                /*
                    * All of these only have a fixed header
                    */
                case SMPP_COMMAND_ID_GENERIC_NACK:
                case SMPP_COMMAND_ID_UNBIND:
                case SMPP_COMMAND_ID_REPLACE_SM:
                case SMPP_COMMAND_ID_CANCEL_SM:
                case SMPP_COMMAND_ID_ENQUIRE_LINK:
                case SMPP_COMMAND_ID_CANCEL_BROADCAST_SM:
                    break;
                /* FIXME: The body of the response PDUs are only
                    * only dissected if the request was successful.
                    * However, in SMPP 5.0 some responses might
                    * contain body to provide additional information
                    * about the error. This needs to be handled.
                    */
                case SMPP_COMMAND_ID_BIND_RECEIVER:
                case SMPP_COMMAND_ID_BIND_TRANSMITTER:
                case SMPP_COMMAND_ID_BIND_TRANSCEIVER:
                    if (!command_status)
                        bind_receiver_resp(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_QUERY_SM:
                    if (!command_status)
                        query_sm_resp(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_SUBMIT_SM:
                case SMPP_COMMAND_ID_DELIVER_SM:
                case SMPP_COMMAND_ID_BROADCAST_SM:
                    if (!command_status)
                        submit_sm_resp(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_SUBMIT_MULTI:
                    if (!command_status)
                        submit_multi_resp(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_DATA_SM:
                    if (!command_status)
                        data_sm_resp(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_QUERY_BROADCAST_SM:
                    if (!command_status)
                        query_broadcast_sm_resp(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_HUAWEI_AUTH_ACC:
                    if (!command_status)
                        huawei_auth_acc_resp(smpp_tree, tvb, SMPP_FIXED_HEADER_LENGTH);
                    break;
                    case SMPP_COMMAND_ID_HUAWEI_SM_RESULT_NOTIFY:
                    if (!command_status)
                        huawei_sm_result_notify_resp(smpp_tree, tvb, SMPP_FIXED_HEADER_LENGTH);
                    break;
                default:
                    break;
            } /* switch (command_id & 0x7FFFFFFF) */
        }
        else
        {
            switch (command_id) {
                case SMPP_COMMAND_ID_BIND_RECEIVER:
                case SMPP_COMMAND_ID_BIND_TRANSMITTER:
                case SMPP_COMMAND_ID_BIND_TRANSCEIVER:
                    bind_receiver(smpp_tree, tvb, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_QUERY_SM:
                    query_sm(smpp_tree, tvb, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_SUBMIT_SM:
                case SMPP_COMMAND_ID_DELIVER_SM:
                    submit_sm(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_UNBIND:
                case SMPP_COMMAND_ID_ENQUIRE_LINK:
                    break;
                case SMPP_COMMAND_ID_REPLACE_SM:
                    replace_sm(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_CANCEL_SM:
                    cancel_sm(smpp_tree, tvb, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_OUTBIND:
                    outbind(smpp_tree, tvb, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_SUBMIT_MULTI:
                    submit_multi(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_ALERT_NOTIFICATION:
                    alert_notification(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_DATA_SM:
                    data_sm(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_BROADCAST_SM:
                    broadcast_sm(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_QUERY_BROADCAST_SM:
                    query_broadcast_sm(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_CANCEL_BROADCAST_SM:
                    cancel_broadcast_sm(smpp_tree, tvb, pinfo, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_HUAWEI_AUTH_ACC:
                    huawei_auth_acc(smpp_tree, tvb, SMPP_FIXED_HEADER_LENGTH);
                    break;
                case SMPP_COMMAND_ID_HUAWEI_SM_RESULT_NOTIFY:
                    huawei_sm_result_notify(smpp_tree, tvb, SMPP_FIXED_HEADER_LENGTH);
                    break;
                default:
                    break;
            } /* switch (command_id) */
        }

    }

    /* Queue packet for Tap */
    tap_rec = wmem_new0(pinfo->pool, smpp_tap_rec_t);
    tap_rec->command_id = command_id;
    tap_rec->command_status = command_status;
    tap_queue_packet(smpp_tap, pinfo, tap_rec);

    return tvb_captured_length(tvb);
}

static int
dissect_smpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    if (pinfo->ptype == PT_TCP) {       /* are we running on top of TCP */
        if (!test_smpp(pinfo, tvb, 0, data)) {
            return 0;
        }
        tcp_dissect_pdus(tvb, pinfo, tree,
            reassemble_over_tcp,    /* Do we try to reassemble      */
            SMPP_FIXED_HEADER_LENGTH, /* Length of fixed header       */
            /* XXX: We only use the first 4 bytes for the length, do we
             * really need to pass in the entire fixed header? */
            get_smpp_pdu_len,       /* Function returning PDU len   */
            dissect_smpp_pdu, data);      /* PDU dissector                */
    }
    else {                            /* no? probably X.25            */
        guint32 offset = 0;
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            guint16 pdu_len = tvb_get_ntohl(tvb, offset);
            gint pdu_real_len = tvb_captured_length_remaining(tvb, offset);
            tvbuff_t *pdu_tvb;

            if (pdu_len < 1)
                return offset;

            if (pdu_real_len <= 0)
                return offset;
            if (pdu_real_len > pdu_len)
                pdu_real_len = pdu_len;
            pdu_tvb = tvb_new_subset_length_caplen(tvb, offset, pdu_real_len, pdu_len);
            dissect_smpp_pdu(pdu_tvb, pinfo, tree, data);
            offset += pdu_len;
        }
    }

    return tvb_captured_length(tvb);
}

/*
* A 'heuristic dissector' that attemtps to establish whether we have
* a genuine SMPP PDU here.
* Only works when:
*      at least the fixed header is there
*      it has a correct overall PDU length
*      it is a 'well-known' operation
*      has a 'well-known' or 'reserved' status
*/
static gboolean
dissect_smpp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    guint32      command_id;            /* SMPP command         */

    conversation_t* conversation;

    if (!test_smpp(pinfo, tvb, 0, data)) {
        return FALSE;
    }

    // Test a few extra bytes in the heuristic dissector, past the
    // minimum fixed header length, to reduce false positives.

    command_id = tvb_get_ntohl(tvb, 4);
    //Check for specific values in commands (to avoid false positives)
    switch (command_id)
    {
    case SMPP_COMMAND_ID_ALERT_NOTIFICATION:
    {
        guint8 ton, npi;

        if (tvb_reported_length(tvb) < 19)
            return FALSE;
        ton = tvb_get_guint8(tvb, 16);
        if (try_val_to_str(ton, vals_addr_ton) == NULL)
            return FALSE;

        npi = tvb_get_guint8(tvb, 17);
        if (try_val_to_str(npi, vals_addr_npi) == NULL)
            return FALSE;

        //address must be NULL-terminated string of up to 65 ascii characters
        int end = tvb_find_guint8(tvb, 18, -1, 0);
        if ((end <= 0) || (end > 65))
            return FALSE;

        if (!tvb_ascii_isprint(tvb, 18, end - 18))
            return FALSE;
    }
    break;
    }

    /* This is called on TCP or X.25, both of which are endpoint types.
     * Set the conversation so we can handle TCP segmentation. */
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, smpp_handle);

    dissect_smpp(tvb, pinfo, tree, data);
    return TRUE;
}

static void
smpp_fmt_version(gchar *result, guint32 revision)
{
    snprintf(result, ITEM_LABEL_LENGTH, "%u.%u", (guint8)((revision & 0xF0) >> 4), (guint8)(revision & 0x0F));
}

/* Register the protocol with Wireshark */
void
proto_register_smpp(void)
{
    module_t *smpp_module; /* Preferences for SMPP */
    expert_module_t *expert_smpp;

    /* Setup list of header fields      */
    static hf_register_info hf[] = {
        {   &hf_smpp_command_length,
            {   "Length", "smpp.command_length",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "Total length of the SMPP PDU.",
                HFILL
            }
        },
        {   &hf_smpp_command_id,
            {   "Operation", "smpp.command_id",
                FT_UINT32, BASE_HEX, VALS(vals_command_id), 0x00,
                "Defines the SMPP PDU.",
                HFILL
            }
        },
        {   &hf_smpp_command_status,
            {   "Result", "smpp.command_status",
                FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(rvals_command_status), 0x00,
                "Indicates success or failure of the SMPP request.",
                HFILL
            }
        },
        {   &hf_smpp_sequence_number,
            {   "Sequence #", "smpp.sequence_number",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "A number to correlate requests with responses.",
                HFILL
            }
        },
        {   &hf_smpp_system_id,
            {   "System ID", "smpp.system_id",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Identifies a system.",
                HFILL
            }
        },
        {   &hf_smpp_password,
            {   "Password", "smpp.password",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Password used for authentication.",
                HFILL
            }
        },
        {   &hf_smpp_system_type,
            {   "System type", "smpp.system_type",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Categorizes the system.",
                HFILL
            }
        },
        {   &hf_smpp_interface_version,
            {   "Version (if)", "smpp.interface_version",
                FT_UINT8, BASE_CUSTOM, CF_FUNC(smpp_fmt_version), 0x00,
                "Version of SMPP interface supported.",
                HFILL
            }
        },
        {   &hf_smpp_service_type,
            {   "Service type", "smpp.service_type",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "SMS application service associated with the message.",
                HFILL
            }
        },
        {   &hf_smpp_addr_ton,
            {   "Type of number", "smpp.addr_ton",
                FT_UINT8, BASE_HEX, VALS(vals_addr_ton), 0x00,
                "Indicates the type of number, given in the address.",
                HFILL
            }
        },
        {   &hf_smpp_source_addr_ton,
            {   "Type of number (originator)", "smpp.source_addr_ton",
                FT_UINT8, BASE_HEX, VALS(vals_addr_ton), 0x00,
                "Indicates originator type of number, given in the address.",
                HFILL
            }
        },
        {   &hf_smpp_dest_addr_ton,
            {   "Type of number (recipient)", "smpp.dest_addr_ton",
                FT_UINT8, BASE_HEX, VALS(vals_addr_ton), 0x00,
                "Indicates recipient type of number, given in the address.",
                HFILL
            }
        },
        {   &hf_smpp_addr_npi,
            {   "Numbering plan indicator", "smpp.addr_npi",
                FT_UINT8, BASE_HEX, VALS(vals_addr_npi), 0x00,
                "Gives the numbering plan this address belongs to.",
                HFILL
            }
        },
        {   &hf_smpp_source_addr_npi,
            {   "Numbering plan indicator (originator)", "smpp.source_addr_npi",
                FT_UINT8, BASE_HEX, VALS(vals_addr_npi), 0x00,
                "Gives originator numbering plan this address belongs to.",
                HFILL
            }
        },
        {   &hf_smpp_dest_addr_npi,
            {   "Numbering plan indicator (recipient)", "smpp.dest_addr_npi",
                FT_UINT8, BASE_HEX, VALS(vals_addr_npi), 0x00,
                "Gives recipient numbering plan this address belongs to.",
                HFILL
            }
        },
        {   &hf_smpp_address_range,
            {   "Address", "smpp.address_range",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Given address or address range.",
                HFILL
            }
        },
        {   &hf_smpp_source_addr,
            {   "Originator address", "smpp.source_addr",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Address of SME originating this message.",
                HFILL
            }
        },
        {   &hf_smpp_destination_addr,
            {   "Recipient address", "smpp.destination_addr",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Address of SME receiving this message.",
                HFILL
            }
        },
        {   &hf_smpp_esm_submit_msg_mode,
            {   "Messaging mode", "smpp.esm.submit.msg_mode",
                FT_UINT8, BASE_HEX, VALS(vals_esm_submit_msg_mode), 0x03,
                "Mode attribute for this message.",
                HFILL
            }
        },
        {   &hf_smpp_esm_submit_msg_type,
            {   "Message type", "smpp.esm.submit.msg_type",
                FT_UINT8, BASE_HEX, VALS(vals_esm_submit_msg_type), 0x3C,
                "Type attribute for this message.",
                HFILL
            }
        },
        {   &hf_smpp_esm_submit_features,
            {   "GSM features", "smpp.esm.submit.features",
                FT_UINT8, BASE_HEX, VALS(vals_esm_submit_features), 0xC0,
                "GSM network specific features.",
                HFILL
            }
        },
        /*! \todo Get proper values from GSM-spec.      */
        {   &hf_smpp_protocol_id,
            {   "Protocol id.", "smpp.protocol_id",
                FT_UINT8, BASE_HEX, NULL, 0x00,
                "Protocol identifier according GSM 03.40.",
                HFILL
            }
        },
        {   &hf_smpp_priority_flag,
            {   "Priority level", "smpp.priority_flag",
                FT_UINT8, BASE_HEX, VALS(vals_priority_flag), 0x00,
                "The priority level of the short message.",
                HFILL
            }
        },
        {   &hf_smpp_schedule_delivery_time,
            {   "Scheduled delivery time", "smpp.schedule_delivery_time",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x00,
                "Scheduled time for delivery of short message.",
                HFILL
            }
        },
        {   &hf_smpp_schedule_delivery_time_r,
            {   "Scheduled delivery time", "smpp.schedule_delivery_time_r",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
                "Scheduled time for delivery of short message.",
                HFILL
            }
        },
        {   &hf_smpp_validity_period,
            {   "Validity period", "smpp.validity_period",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x00,
                "Validity period of this message.",
                HFILL
            }
        },
        {   &hf_smpp_validity_period_r,
            {   "Validity period", "smpp.validity_period_r",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
                "Validity period of this message.",
                HFILL
            }
        },
        {   &hf_smpp_regdel_receipt,
            {   "Delivery receipt", "smpp.regdel.receipt",
                FT_UINT8, BASE_HEX, VALS(vals_regdel_receipt), 0x03,
                "SMSC delivery receipt request.",
                HFILL
            }
        },
        {   &hf_smpp_regdel_acks,
            {   "Message type", "smpp.regdel.acks",
                FT_UINT8, BASE_HEX, VALS(vals_regdel_acks), 0x0C,
                "SME acknowledgement request.",
                HFILL
            }
        },
        {   &hf_smpp_regdel_notif,
            {   "Intermediate notif", "smpp.regdel.notif",
                FT_UINT8, BASE_HEX, VALS(vals_regdel_notif), 0x10,
                "Intermediate notification request.",
                HFILL
            }
        },
        {   &hf_smpp_replace_if_present_flag,
            {   "Replace", "smpp.replace_if_present_flag",
                FT_UINT8, BASE_HEX, VALS(vals_replace_if_present_flag), 0x01,
                "Replace the short message with this one or not.",
                HFILL
            }
        },
        {   &hf_smpp_data_coding,
            {   "Data coding", "smpp.data_coding",
                FT_UINT8, BASE_HEX|BASE_RANGE_STRING, RVALS(rvals_data_coding), 0x00,
                "Defines the encoding scheme of the message.",
                HFILL
            }
        },
        {   &hf_smpp_sm_default_msg_id,
            {   "Predefined message", "smpp.sm_default_msg_id",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Index of a predefined ('canned') short message.",
                HFILL
            }
        },
        {   &hf_smpp_sm_length,
            {   "Message length", "smpp.sm_length",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Length of the message content.",
                HFILL
            }
        },
        {   &hf_smpp_short_message,
            {   "Message", "smpp.message_text",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "The actual message or data.",
                HFILL
            }
        },
        {   &hf_smpp_short_message_bin,
            {   "Message bytes", "smpp.message",
                FT_BYTES, BASE_NONE, NULL, 0x00,
                "The actual message bytes.",
                HFILL
            }
        },
        {   &hf_smpp_message_id,
            {   "Message id.", "smpp.message_id",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Identifier of the submitted short message.",
                HFILL
            }
        },
        {   &hf_smpp_dlist,
            {   "Destination list", "smpp.dlist",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "The list of destinations for a short message.",
                HFILL
            }
        },
        {   &hf_smpp_dlist_resp,
            {   "Unsuccessful delivery list", "smpp.dlist_resp",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "The list of unsuccessful deliveries to destinations.",
                HFILL
            }
        },
        {   &hf_smpp_dl_name,
            {   "Distr. list name", "smpp.dl_name",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "The name of the distribution list.",
                HFILL
            }
        },
        {   &hf_smpp_final_date,
            {   "Final date", "smpp.final_date",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x00,
                "Date-time when the queried message reached a final state.",
                HFILL
            }
        },
        {   &hf_smpp_final_date_r,
            {   "Final date", "smpp.final_date_r",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
                "Date-time when the queried message reached a final state.",
                HFILL
            }
        },
        {   &hf_smpp_message_state,
            {   "Message state", "smpp.message_state",
                FT_UINT8, BASE_DEC, VALS(vals_message_state), 0x00,
                "Specifies the status of the queried short message.",
                HFILL
            }
        },
        {   &hf_smpp_error_code,
            {   "Error code", "smpp.error_code",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Network specific error code defining reason for failure.",
                HFILL
            }
        },
        {   &hf_smpp_error_status_code,
            {   "Status", "smpp.error_status_code",
                FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(rvals_command_status), 0x00,
                "Indicates success/failure of request for this address.",
                HFILL
            }
        },
        {   &hf_smpp_esme_addr_ton,
            {   "Type of number (ESME)", "smpp.esme_addr_ton",
                FT_UINT8, BASE_HEX, VALS(vals_addr_ton), 0x00,
                "Indicates recipient type of number, given in the address.",
                HFILL
            }
        },
        {   &hf_smpp_esme_addr_npi,
            {   "Numbering plan indicator (ESME)", "smpp.esme_addr_npi",
                FT_UINT8, BASE_HEX, VALS(vals_addr_npi), 0x00,
                "Gives the numbering plan this address belongs to.",
                HFILL
            }
        },
        {   &hf_smpp_esme_addr,
            {   "ESME address", "smpp.esme_addr",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Address of ESME originating this message.",
                HFILL
            }
        },
        {   &hf_smpp_dest_addr_subunit,
            {   "Subunit destination", "smpp.dest_addr_subunit",
                FT_UINT8, BASE_HEX, VALS(vals_addr_subunit), 0x00,
                "Subunit address within mobile to route message to.",
                HFILL
            }
        },
        {   &hf_smpp_source_addr_subunit,
            {   "Subunit origin", "smpp.source_addr_subunit",
                FT_UINT8, BASE_HEX, VALS(vals_addr_subunit), 0x00,
                "Subunit address within mobile that generated the message.",
                HFILL
            }
        },
        {   &hf_smpp_dest_network_type,
            {   "Destination network", "smpp.dest_network_type",
                FT_UINT8, BASE_HEX, VALS(vals_network_type), 0x00,
                "Network associated with the destination address.",
                HFILL
            }
        },
        {   &hf_smpp_source_network_type,
            {   "Originator network", "smpp.source_network_type",
                FT_UINT8, BASE_HEX, VALS(vals_network_type), 0x00,
                "Network associated with the originator address.",
                HFILL
            }
        },
        {   &hf_smpp_dest_bearer_type,
            {   "Destination bearer", "smpp.dest_bearer_type",
                FT_UINT8, BASE_HEX, VALS(vals_bearer_type), 0x00,
                "Desired bearer for delivery of message.",
                HFILL
            }
        },
        {   &hf_smpp_source_bearer_type,
            {   "Originator bearer", "smpp.source_bearer_type",
                FT_UINT8, BASE_HEX, VALS(vals_bearer_type), 0x00,
                "Bearer over which the message originated.",
                HFILL
            }
        },
        {   &hf_smpp_dest_telematics_id,
            {   "Telematic interworking (dest)", "smpp.dest_telematics_id",
                FT_UINT16, BASE_HEX, NULL, 0x00,
                "Telematic interworking to be used for message delivery.",
                HFILL
            }
        },
        {   &hf_smpp_source_telematics_id,
            {   "Telematic interworking (orig)", "smpp.source_telematics_id",
                FT_UINT8, BASE_HEX, NULL, 0x00,
                "Telematic interworking used for message submission.",
                HFILL
            }
        },
        {   &hf_smpp_qos_time_to_live,
            {   "Validity period", "smpp.qos_time_to_live",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "Number of seconds to retain message before expiry.",
                HFILL
            }
        },
        {   &hf_smpp_payload_type,
            {   "Payload", "smpp.payload_type",
                FT_UINT8, BASE_DEC, VALS(vals_payload_type), 0x00,
                "PDU type contained in the message payload.",
                HFILL
            }
        },
        {   &hf_smpp_additional_status_info_text,
            {   "Information", "smpp.additional_status_info_text",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Description of the meaning of a response PDU.",
                HFILL
            }
        },
        {   &hf_smpp_receipted_message_id,
            {   "SMSC identifier", "smpp.receipted_message_id",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "SMSC handle of the message being received.",
                HFILL
            }
        },
        {   &hf_smpp_privacy_indicator,
            {   "Privacy indicator", "smpp.privacy_indicator",
                FT_UINT8, BASE_DEC, VALS(vals_privacy_indicator), 0x00,
                "Indicates the privacy level of the message.",
                HFILL
            }
        },
    {   &hf_smpp_source_subaddress,
            {   "Source Subaddress", "smpp.source_subaddress",
                FT_BYTES, BASE_NONE, NULL, 0x00,
                NULL,
                HFILL
            }
        },
    {   &hf_smpp_dest_subaddress,
            {   "Destination Subaddress", "smpp.dest_subaddress",
                FT_BYTES, BASE_NONE, NULL, 0x00,
                NULL,
                HFILL
            }
        },
    {   &hf_smpp_user_message_reference,
            {   "Message reference", "smpp.user_message_reference",
                FT_UINT16, BASE_HEX, NULL, 0x00,
                "Reference to the message, assigned by the user.",
                HFILL
            }
        },
        {   &hf_smpp_user_response_code,
            {   "Application response code", "smpp.user_response_code",
                FT_UINT8, BASE_HEX, NULL, 0x00,
                "A response code set by the user.",
                HFILL
            }
        },
        {   &hf_smpp_language_indicator,
            {   "Language", "smpp.language_indicator",
                FT_UINT8, BASE_DEC, VALS(vals_language_indicator), 0x00,
                "Indicates the language of the short message.",
                HFILL
            }
        },
        {   &hf_smpp_source_port,
            {   "Source port", "smpp.source_port",
                FT_UINT16, BASE_HEX, NULL, 0x00,
                "Application port associated with the source of the message.",
                HFILL
            }
        },
        {   &hf_smpp_destination_port,
            {   "Destination port", "smpp.destination_port",
                FT_UINT16, BASE_HEX, NULL, 0x00,
                "Application port associated with the destination of the message.",
                HFILL
            }
        },
        {   &hf_smpp_sar_msg_ref_num,
            {   "SAR reference number", "smpp.sar_msg_ref_num",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                "Reference number for a concatenated short message.",
                HFILL
            }
        },
        {   &hf_smpp_sar_total_segments,
            {   "SAR size", "smpp.sar_total_segments",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                "Number of segments of a concatenated short message.",
                HFILL
            }
        },
        {   &hf_smpp_sar_segment_seqnum,
            {   "SAR sequence number", "smpp.sar_segment_seqnum",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Segment number within a concatenated short message.",
                HFILL
            }
        },
        {   &hf_smpp_display_time,
            {   "Display time", "smpp.display_time",
                FT_UINT8, BASE_DEC, VALS(vals_display_time), 0x00,
                "Associates a display time with the message on the handset.",
                HFILL
            }
        },
        {   &hf_smpp_sms_signal,
            {   "SMS signal", "smpp.sms_signal",
                FT_UINT16, BASE_HEX, NULL, 0x00,
                "Alert the user according to the information contained within this information element.",
                HFILL
            }
        },
        {   &hf_smpp_ms_validity,
            {   "Validity info", "smpp.ms_validity",
                FT_UINT8, BASE_DEC, VALS(vals_ms_validity), 0x00,
                "Associates validity info with the message on the handset.",
                HFILL
            }
        },
        {   &hf_smpp_dpf_result,
            {   "Delivery pending set?", "smpp.dpf_result",
                FT_UINT8, BASE_DEC, VALS(vals_dpf_result), 0x00,
                "Indicates whether Delivery Pending Flag was set.",
                HFILL
            }
        },
        {   &hf_smpp_set_dpf,
            {   "Request DPF set", "smpp.set_dpf",
                FT_UINT8, BASE_DEC, VALS(vals_set_dpf), 0x00,
                "Request to set the DPF for certain failure scenario's.",
                HFILL
            }
        },
        {   &hf_smpp_ms_availability_status,
            {   "Availability status", "smpp.ms_availability_status",
                FT_UINT8, BASE_DEC, VALS(vals_ms_availability_status), 0x00,
                "Indicates the availability state of the handset.",
                HFILL
            }
        },
        {   &hf_smpp_delivery_failure_reason,
            {   "Delivery failure reason", "smpp.delivery_failure_reason",
                FT_UINT8, BASE_DEC, VALS(vals_delivery_failure_reason), 0x00,
                "Indicates the reason for a failed delivery attempt.",
                HFILL
            }
        },
        {   &hf_smpp_more_messages_to_send,
            {   "More messages?", "smpp.more_messages_to_send",
                FT_UINT8, BASE_DEC, VALS(vals_more_messages_to_send), 0x00,
                "Indicates more messages pending for the same destination.",
                HFILL
            }
        },
        {   &hf_smpp_number_of_messages,
            {   "Number of messages", "smpp.number_of_messages",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Indicates number of messages stored in a mailbox.",
                HFILL
            }
        },
        {   &hf_smpp_its_reply_type,
            {   "Reply method", "smpp.its_reply_type",
                FT_UINT8, BASE_DEC, VALS(vals_its_reply_type), 0x00,
                "Indicates the handset reply method on message receipt.",
                HFILL
            }
        },
        {   &hf_smpp_ussd_service_op,
            {   "USSD service operation", "smpp.ussd_service_op",
                FT_UINT8, BASE_DEC, VALS(vals_ussd_service_op), 0x00,
                "Indicates the USSD service operation.",
                HFILL
            }
        },
        {   &hf_smpp_vendor_op,
            {   "Value", "smpp.vendor_op",
                FT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x00,
                "A supplied optional parameter specific to an SMSC-vendor.",
                HFILL
            }
        },
        {   &hf_smpp_reserved_op,
            {   "Value", "smpp.reserved_op",
                FT_BYTES, BASE_NONE|BASE_ALLOW_ZERO, NULL, 0x00,
                "An optional parameter that is reserved in this version.",
                HFILL
            }
        },
        {   &hf_smpp_msg_wait_ind,
            {   "Indication", "smpp.msg_wait.ind",
                FT_UINT8, BASE_HEX, VALS(vals_msg_wait_ind), 0x80,
                "Indicates to the handset that a message is waiting.",
                HFILL
            }
        },
        {   &hf_smpp_msg_wait_type,
            {   "Type", "smpp.msg_wait.type",
                FT_UINT8, BASE_HEX, VALS(vals_msg_wait_type), 0x03,
                "Indicates type of message that is waiting.",
                HFILL
            }
        },
        {   &hf_smpp_SC_interface_version,
            {   "SMSC-supported version", "smpp.SC_interface_version",
                FT_UINT8, BASE_CUSTOM, CF_FUNC(smpp_fmt_version), 0x00,
                "Version of SMPP interface supported by the SMSC.",
                HFILL
            }
        },
        {   &hf_smpp_callback_num_pres,
            {   "Presentation", "smpp.callback_num.pres",
                FT_UINT8, BASE_HEX, VALS(vals_callback_num_pres), 0x0C,
                "Controls the presentation indication.",
                HFILL
            }
        },
        {   &hf_smpp_callback_num_scrn,
            {   "Screening", "smpp.callback_num.scrn",
                FT_UINT8, BASE_HEX, VALS(vals_callback_num_scrn), 0x03,
                "Controls screening of the callback-number.",
                HFILL
            }
        },
        {   &hf_smpp_callback_num_atag,
            {   "Callback number - alphanumeric display tag",
                "smpp.callback_num_atag",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "Associates an alphanumeric display with call back number.",
                HFILL
            }
        },
        {   &hf_smpp_callback_num,
            {   "Callback number", "smpp.callback_num",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "Associates a call back number with the message.",
                HFILL
            }
        },
        {   &hf_smpp_network_error_type,
            {   "Error type", "smpp.network_error.type",
                FT_UINT8, BASE_DEC, VALS(vals_network_error_type), 0x00,
                "Indicates the network type.",
                HFILL
            }
        },
        {   &hf_smpp_network_error_code,
            {   "Error code", "smpp.network_error.code",
                FT_UINT16, BASE_HEX, NULL, 0x00,
                "Gives the actual network error code.",
                HFILL
            }
        },
        {   &hf_smpp_message_payload,
            {   "Payload", "smpp.message_payload",
                FT_BYTES, BASE_NONE, NULL, 0x00,
                "Short message user data.",
                HFILL
            }
        },
        {   &hf_smpp_alert_on_message_delivery_null,
            {   "Alert on delivery", "smpp.alert_on_message_delivery_null",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "Instructs the handset to alert user on message delivery.",
                HFILL
            }
        },
        {   &hf_smpp_alert_on_message_delivery_type,
            {   "Alert on delivery", "smpp.alert_on_message_delivery_type",
                FT_UINT8, BASE_DEC, VALS(vals_alert_on_message_delivery), 0x00,
                "Instructs the handset to alert user on message delivery.",
                HFILL
            }
        },
        {   &hf_smpp_its_session_number,
            {   "Session number", "smpp.its_session.number",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Session number of interactive teleservice.",
                HFILL
            }
        },
        {   &hf_smpp_its_session_sequence,
            {   "Sequence number", "smpp.its_session.sequence",
                FT_UINT8, BASE_HEX, NULL, 0xFE,
                "Sequence number of the dialogue unit.",
                HFILL
            }
        },
        {   &hf_smpp_its_session_ind,
            {   "Session indicator", "smpp.its_session.ind",
                FT_UINT8, BASE_HEX, VALS(vals_its_session_ind), 0x01,
                "Indicates whether this message is end of conversation.",
                HFILL
            }
        },
        {   &hf_smpp_opt_params,
            {   "Optional parameters", "smpp.opt_params",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "The list of optional parameters in this operation.",
                HFILL
            }
        },
        {   &hf_smpp_opt_param,
            {   "Optional parameter", "smpp.opt_param",
                FT_NONE, BASE_NONE, NULL, 0x00,
                NULL,
                HFILL
            }
        },
        {   &hf_smpp_opt_param_tag,
            {   "Tag", "smpp.opt_param_tag",
                FT_UINT16, BASE_HEX, NULL, 0x00,
                "Optional parameter identifier tag",
                HFILL
            }
        },
        {   &hf_smpp_opt_param_len,
            {   "Length", "smpp.opt_param_len",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                "Optional parameter length",
                HFILL
            }
        },

        /*
         * Data Coding Scheme
         */
        {   &hf_smpp_dcs_sms_coding_group,
            {   "DCS Coding Group for SMS", "smpp.dcs.sms_coding_group",
                FT_UINT8, BASE_HEX, VALS(vals_dcs_sms_coding_group), 0xF0,
                "Data Coding Scheme coding group for GSM Short Message Service.",
                HFILL
            }
        },
        {   &hf_smpp_dcs_reserved,
            {   "Reserved (should be zero)", "smpp.dcs.reserved",
                FT_UINT8, BASE_DEC, NULL, 0x08,
                NULL, HFILL
            }
        },
        {   &hf_smpp_dcs_charset,
            {   "DCS Character set", "smpp.dcs.charset",
                FT_UINT8, BASE_HEX, VALS(vals_dcs_charset), 0x04,
                "Specifies the character set used in the message.", HFILL
            }
        },
        {   &hf_smpp_dcs_class,
            {   "DCS Message class", "smpp.dcs.class",
                FT_UINT8, BASE_HEX, VALS(vals_dcs_class), 0x03,
                "Specifies the message class.", HFILL
            }
        },
        {   &hf_smpp_dcs_wait_ind,
            {   "Indication", "smpp.dcs.wait_ind",
                FT_UINT8, BASE_HEX, VALS(vals_msg_wait_ind), 0x08,
                "Indicates to the handset that a message is waiting.",
                HFILL
            }
        },
        {   &hf_smpp_dcs_reserved2,
            {   "Reserved (should be zero)", "smpp.dcs.reserved",
                FT_UINT8, BASE_DEC, NULL, 0x04,
                NULL, HFILL
            }
        },
        {   &hf_smpp_dcs_wait_type,
            {   "Type", "smpp.dcs.wait_type",
                FT_UINT8, BASE_HEX, VALS(vals_msg_wait_type), 0x03,
                "Indicates type of message that is waiting.",
                HFILL
            }
        },
        /* Changes in SMPP 5.0 */
        {       &hf_smpp_congestion_state,
                {       "Congestion State", "smpp.congestion_state",
                        FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vals_congestion_state), 0x00,
                        "Congestion info between ESME and MC for flow control/cong. control", HFILL
                }
        },
        {       &hf_smpp_billing_identification,
                {       "Billing Identification", "smpp.billing_id",
                        FT_BYTES, BASE_NONE, NULL, 0x00,
                        "Billing identification info", HFILL
                }
        },
        {       &hf_smpp_dest_addr_np_country,
                {       "Destination Country Code", "smpp.dest_addr_np_country",
                        FT_BYTES, BASE_NONE, NULL, 0x00,
                        "Destination Country Code (E.164 Region Code)", HFILL
                }
        },
        {       &hf_smpp_dest_addr_np_information,
                {       "Number Portability information", "smpp.dest_addr_np_info",
                        FT_BYTES, BASE_NONE, NULL, 0x00,
                        NULL, HFILL
                }
        },
        {       &hf_smpp_dest_addr_np_resolution,
                {       "Number Portability query information", "smpp.dest_addr_np_resolution",
                        FT_UINT8, BASE_DEC, VALS(vals_dest_addr_np_resolution), 0x00,
                        "Number Portability query information - method used to resolve number", HFILL
                }
        },
        {       &hf_smpp_source_network_id,
                {       "Source Network ID", "smpp.source_network_id",
                        FT_STRING, BASE_NONE, NULL, 0x00,
                        "Unique ID for a network or ESME operator", HFILL
                }
        },
        {       &hf_smpp_source_node_id,
                {       "Source Node ID", "smpp.source_node_id",
                        FT_BYTES, BASE_NONE, NULL, 0x00,
                        "Unique ID for a ESME or MC node", HFILL
                }
        },
        {       &hf_smpp_dest_network_id,
                {       "Destination Network ID", "smpp.dest_network_id",
                        FT_STRING, BASE_NONE, NULL, 0x00,
                        "Unique ID for a network or ESME operator", HFILL
                }
        },
        {       &hf_smpp_dest_node_id,
                {       "Destination Node ID", "smpp.dest_node_id",
                        FT_BYTES, BASE_NONE, NULL, 0x00,
                        "Unique ID for a ESME or MC node", HFILL
                }
        },
        {       &hf_smpp_broadcast_channel_indicator,
                {       "Cell Broadcast channel", "smpp.broadcast_channel_indicator",
                        FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vals_broadcast_channel_indicator), 0x00,
                        NULL, HFILL
                }
        },
        {       &hf_smpp_broadcast_content_type_nw,
                {       "Broadcast Content Type - Network Tag", "smpp.broadcast_content_type.nw",
                        FT_UINT8, BASE_DEC, VALS(vals_broadcast_content_type_nw), 0x00,
                        "Cell Broadcast content type", HFILL
                }
        },
        {       &hf_smpp_broadcast_content_type_type,
                {       "Broadcast Content Type - Content Type", "smpp.broadcast_content_type.type",
                        FT_UINT16, BASE_HEX, VALS(vals_broadcast_content_type_type), 0x00,
                        "Cell Broadcast content type", HFILL
                }
        },
        {       &hf_smpp_broadcast_content_type_info,
                {       "Broadcast Content Type Info", "smpp.broadcast_content_type.info",
                        FT_BYTES, BASE_NONE, NULL, 0x00,
                        "Cell Broadcast content type Info", HFILL
                }
        },
        {       &hf_smpp_broadcast_message_class,
                {       "Broadcast Message Class", "smpp.broadcast_message_class",
                        FT_UINT8, BASE_HEX, VALS(vals_broadcast_message_class), 0x00,
                        "Cell Broadcast Message Class", HFILL
                }
        },
        {       &hf_smpp_broadcast_rep_num,
                {       "Broadcast Message - Number of repetitions requested", "smpp.broadcast_rep_num",
                        FT_UINT16, BASE_DEC, NULL, 0x00,
                        "Cell Broadcast Message - Number of repetitions requested", HFILL
                }
        },
        {       &hf_smpp_broadcast_frequency_interval_unit,
                {       "Broadcast Message - frequency interval - Unit", "smpp.broadcast_frequency_interval.unit",
                        FT_UINT8, BASE_HEX, VALS(vals_broadcast_frequency_interval_unit), 0x00,
                        "Cell Broadcast Message - frequency interval at which broadcast must be repeated", HFILL
                }
        },
        {       &hf_smpp_broadcast_frequency_interval_value,
                {       "Broadcast Message - frequency interval - Unit", "smpp.broadcast_frequency_interval.value",
                        FT_UINT16, BASE_DEC, NULL, 0x00,
                        "Cell Broadcast Message - frequency interval at which broadcast must be repeated", HFILL
                }
        },
        {       &hf_smpp_broadcast_area_identifier,
                {       "Broadcast Message - Area Identifier", "smpp.broadcast_area_identifier",
                        FT_BYTES, BASE_NONE, NULL, 0x00,
                        "Cell Broadcast Message - Area Identifier", HFILL
                }
        },
        {       &hf_smpp_broadcast_area_identifier_format,
                {       "Broadcast Message - Area Identifier Format", "smpp.broadcast_area_identifier.format",
                        FT_UINT8, BASE_HEX | BASE_RANGE_STRING, RVALS(vals_broadcast_area_identifier_format), 0x00,
                        "Cell Broadcast Message - Area Identifier Format", HFILL
                }
        },
        {       &hf_smpp_broadcast_error_status,
                {       "Broadcast Message - Error Status", "smpp.broadcast_error_status",
                        FT_UINT32, BASE_HEX | BASE_RANGE_STRING, RVALS(rvals_command_status), 0x00,
                        "Cell Broadcast Message - Error Status", HFILL
                }
        },
        {       &hf_smpp_broadcast_area_success,
                {       "Broadcast Message - Area Success", "smpp.broadcast_area_success",
                        FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(vals_broadcast_area_success), 0x00,
                        "Cell Broadcast Message - success rate indicator (ratio) - No. of BTS which accepted Message:Total BTS", HFILL
                }
        },
        {       &hf_smpp_broadcast_end_time,
                {       "Broadcast Message - End Time", "smpp.broadcast_end_time",
                        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x00,
                        "Cell Broadcast Message - Date and time at which MC set the state of the message to terminated", HFILL
                }
        },
        {       &hf_smpp_broadcast_end_time_r,
                {       "Broadcast Message - End Time", "smpp.broadcast_end_time_r",
                        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
                        "Cell Broadcast Message - Date and time at which MC set the state of the message to terminated", HFILL
                }
        },
        {       &hf_smpp_broadcast_service_group,
                {       "Broadcast Message - Service Group", "smpp.broadcast_service_group",
                        FT_BYTES, BASE_NONE, NULL, 0x00,
                        "Cell Broadcast Message - Service Group", HFILL
                }
        },
        /* Huawei SMPP+ extensions */
        {        &hf_huawei_smpp_smsc_addr,
                {       "SMPP+: GT of SMSC", "smpp.smsc_addr",
                        FT_STRING, BASE_NONE, NULL, 0x00,
                        NULL, HFILL
                }
        },
        {        &hf_huawei_smpp_msc_addr_noa,
                {       "SMPP+: NOA of MSC address", "smpp.msc_addr_noa",
                        FT_UINT8, BASE_DEC, VALS(vals_msc_addr_noa), 0x00,
                        "SMPP+: Indicates the TON of MSC address", HFILL
                }
        },
        {        &hf_huawei_smpp_msc_addr_npi,
                {       "SMPP+: NPI of MSC address", "smpp.msc_addr_npi",
                        FT_UINT8, BASE_DEC, VALS(vals_msc_addr_npi), 0x00,
                        "SMPP+: Indicates the NPI of MSC address", HFILL
                }
        },
        {        &hf_huawei_smpp_msc_addr,
                {       "SMPP+: GT of MSC", "smpp.msc_addr",
                        FT_STRING, BASE_NONE, NULL, 0x00,
                        NULL, HFILL
                }
        },
        {        &hf_huawei_smpp_mo_mt_flag,
                {       "SMPP+: Charge for MO or MT", "smpp.mo_mt_flag",
                        FT_UINT8, BASE_DEC, VALS(vals_mo_mt_flag), 0x00,
                        "SMPP+: Indicates the Charge side of  MO or MT", HFILL
                }
        },
        {        &hf_huawei_smpp_sm_id,
                {       "SMPP+: Unique SM ID", "smpp.sm_id",
                        FT_STRING, BASE_NONE, NULL, 0x00,
                        "SMPP+: Unique SM ID which is generated by SMSC", HFILL
                }
        },
        {        &hf_huawei_smpp_length_auth,
                {       "SMPP+: Length of SMS", "smpp.length_auth",
                        FT_UINT32, BASE_DEC, NULL, 0x00,
                        "SMPP+: Indicates the Length of SMS", HFILL
                }
        },
        {        &hf_huawei_smpp_service_id,
                {       "SMPP+: Service ID of SMSC", "smpp.service_id",
                        FT_UINT32, BASE_DEC, NULL, 0x00,
                        "SMPP+: Indicates the Service ID of SMSC", HFILL
                }
        },
        {        &hf_huawei_smpp_operation_result,
                {       "SMPP+: Authentication result of SCP", "smpp.operation_result",
                        FT_UINT32, BASE_DEC, VALS(vals_operation_result), 0x00,
                        "SMPP+: Indicates the Authentication result of SCP", HFILL
                }
        },
        {        &hf_huawei_smpp_notify_mode,
                {       "SMPP+: SMS notify mode", "smpp.notify_mode",
                        FT_UINT8, BASE_DEC, VALS(vals_notify_mode), 0x00,
                        "SMPP+: Indicates the SMS notify mode", HFILL
                }
        },
        {        &hf_huawei_smpp_delivery_result,
                {       "SMPP+: Delivery result of SMS", "smpp.delivery_result",
                        FT_UINT32, BASE_DEC, VALS(vals_delivery_result), 0x00,
                        "SMPP+: Indicates the Delivery result of SMS", HFILL
                }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_smpp,
        &ett_dlist,
        &ett_dlist_resp,
        &ett_opt_params,
        &ett_opt_param,
        &ett_dcs,
    };

    static ei_register_info ei[] = {
        { &ei_smpp_message_payload_duplicate,
          { "smpp.message_payload.duplicate", PI_PROTOCOL, PI_WARN,
            "short_message field and message_payload TLV can only appear once in total",
            EXPFILL }
        }
    };

    /* Encoding used to decode the SMS over SMPP when DCS is 0 */
    static const enum_val_t smpp_dcs_0_sms_decode_options[] = {
        { "none",        "None",       DO_NOT_DECODE },
        { "ascii",       "ASCII",      ENC_ASCII },
        { "gsm7",        "GSM 7-bit",  ENC_3GPP_TS_23_038_7BITS_UNPACKED },
        { "gsm7-packed", "GSM 7-bit (packed)", ENC_3GPP_TS_23_038_7BITS_PACKED },
        { "iso-8859-1",  "ISO-8859-1", ENC_ISO_8859_1 },
        { "iso-8859-5",  "ISO-8859-5", ENC_ISO_8859_5 },
        { "iso-8859-8",  "ISO-8859-8", ENC_ISO_8859_8 },
        { "ucs2",        "UCS2",       ENC_UCS_2|ENC_BIG_ENDIAN },
        { "ks-c-5601",   "KS C 5601 (Korean)", ENC_EUC_KR },
        { NULL, NULL, 0 }
    };

    /* Register the protocol name and description */
    proto_smpp = proto_register_protocol("Short Message Peer to Peer",
                                         "SMPP", "smpp");

    /* Required function calls to register header fields and subtrees used */
    proto_register_field_array(proto_smpp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_smpp = expert_register_protocol(proto_smpp);
    expert_register_field_array(expert_smpp, ei, array_length(ei));

    /* Allow other dissectors to find this one by name. */
    smpp_handle = register_dissector("smpp", dissect_smpp, proto_smpp);

    /* Register for tapping */
    smpp_tap = register_tap("smpp");

    /* Preferences */
    smpp_module = prefs_register_protocol (proto_smpp, NULL);
    prefs_register_bool_preference (smpp_module,
            "reassemble_smpp_over_tcp",
            "Reassemble SMPP over TCP messages spanning multiple TCP segments",
            "Whether the SMPP dissector should reassemble messages spanning multiple TCP segments."
            " To use this option, you must also enable "
            "\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
            &reassemble_over_tcp);
    prefs_register_enum_preference(smpp_module, "decode_sms_over_smpp",
            "Decode DCS 0 SMS as",
            "Whether to decode the SMS contents when DCS is equal to 0 (zero).",
            &smpp_decode_dcs_0_sms, smpp_dcs_0_sms_decode_options, FALSE);
    prefs_register_bool_preference(smpp_module, "gsm7_unpacked",
            "GSM 7-bit alphabet unpacked",
            "When the DCS indicates that the encoding is the GSM 7-bit "
            "alphabet, whether to decode it as unpacked (one character "
            "per octet) instead of packed.",
            &smpp_gsm7_unpacked);
}

void
proto_reg_handoff_smpp(void)
{
    /*
     * SMPP can be spoken on any port under TCP or X.25
     * ...how *do* we do that under X.25?
     *
     * We can register the heuristic SMPP dissector with X.25, for one
     * thing.  We don't currently have any mechanism to allow the user
     * to specify that a given X.25 circuit is to be dissected as SMPP,
     * however.
     */
    dissector_add_for_decode_as_with_preference("tcp.port", smpp_handle);
    heur_dissector_add("tcp", dissect_smpp_heur, "SMPP over TCP Heuristics", "smpp_tcp", proto_smpp, HEURISTIC_ENABLE);
    heur_dissector_add("x.25", dissect_smpp_heur, "SMPP over X.25 Heuristics", "smpp_x25", proto_smpp, HEURISTIC_ENABLE);

    /* Required for call_dissector() */
    gsm_sms_handle = find_dissector_add_dependency("gsm_sms_ud", proto_smpp);
    DISSECTOR_ASSERT(gsm_sms_handle);

    /* Tapping setup */
    stats_tree_register_with_group("smpp","smpp_commands", "SM_PP Operations", 0,
                                   smpp_stats_tree_per_packet, smpp_stats_tree_init,
                                   NULL, REGISTER_STAT_GROUP_TELEPHONY);

    exported_pdu_tap = find_tap_id(EXPORT_PDU_TAP_NAME_LAYER_7);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
