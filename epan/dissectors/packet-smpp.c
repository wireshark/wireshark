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
 * ----------
 *
 * Dissector of an SMPP (Short Message Peer to Peer) PDU, as defined by the
 * SMS forum (www.smsforum.net) in "SMPP protocol specification v3.4"
 * (document version: 12-Oct-1999 Issue 1.2)
 */

#include "config.h"

#include <string.h>
#include <time.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/tap.h>
#include <epan/stats_tree.h>

#include <epan/prefs.h>
#include <epan/wmem/wmem.h>
#include "packet-tcp.h"
#include "packet-smpp.h"

/* General-purpose debug logger.
 * Requires double parentheses because of variable arguments of printf().
 *
 * Enable debug logging for SMPP by defining AM_CFLAGS
 * so that it contains "-DDEBUG_smpp"
 */
#ifdef DEBUG_smpp
#define DebugLog(x) \
    g_print("%s:%u: ", __FILE__, __LINE__);     \
    g_print x
#else
#define DebugLog(x) ;
#endif

#define SMPP_MIN_LENGTH 16

/* Forward declarations         */
void proto_register_smpp(void);
void proto_reg_handoff_smpp(void);
static int dissect_smpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data);
static guint get_smpp_pdu_len(packet_info *pinfo, tvbuff_t *tvb, int offset);
static int dissect_smpp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_);

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
static int hf_smpp_alert_on_message_delivery          = -1;
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
static int hf_smpp_dcs                                = -1;
static int hf_smpp_dcs_sms_coding_group               = -1;
static int hf_smpp_dcs_text_compression               = -1;
static int hf_smpp_dcs_class_present                  = -1;
static int hf_smpp_dcs_charset                        = -1;
static int hf_smpp_dcs_class                          = -1;
static int hf_smpp_dcs_cbs_coding_group               = -1;
static int hf_smpp_dcs_cbs_language                   = -1;
static int hf_smpp_dcs_wap_charset                    = -1;
static int hf_smpp_dcs_wap_class                      = -1;
static int hf_smpp_dcs_cbs_class                      = -1;

/*
 * Huawei SMPP+ extensions
 */
static int hf_huawei_smpp_version                     = -1;
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

/* Initialize the subtree pointers */
static gint ett_smpp            = -1;
static gint ett_dlist           = -1;
static gint ett_dlist_resp      = -1;
static gint ett_opt_params      = -1;
static gint ett_opt_param       = -1;
static gint ett_dcs             = -1;

/* Reassemble SMPP TCP segments */
static gboolean reassemble_over_tcp = TRUE;

/* Tap */
static int smpp_tap             = -1;

/*
 * Value-arrays for field-contents
 */
static const value_string vals_command_id[] = {         /* Operation    */
    { 0x80000000, "Generic_nack" },
    { 0x00000001, "Bind_receiver" },
    { 0x80000001, "Bind_receiver - resp" },
    { 0x00000002, "Bind_transmitter" },
    { 0x80000002, "Bind_transmitter - resp" },
    { 0x00000003, "Query_sm" },
    { 0x80000003, "Query_sm - resp" },
    { 0x00000004, "Submit_sm" },
    { 0x80000004, "Submit_sm - resp" },
    { 0x00000005, "Deliver_sm" },
    { 0x80000005, "Deliver_sm - resp" },
    { 0x00000006, "Unbind" },
    { 0x80000006, "Unbind - resp" },
    { 0x00000007, "Replace_sm" },
    { 0x80000007, "Replace_sm - resp" },
    { 0x00000008, "Cancel_sm" },
    { 0x80000008, "Cancel_sm - resp" },
    { 0x00000009, "Bind_transceiver" },
    { 0x80000009, "Bind_transceiver - resp" },
    { 0x0000000B, "Outbind" },
    { 0x00000015, "Enquire_link" },
    { 0x80000015, "Enquire_link - resp" },
    { 0x00000021, "Submit_multi" },
    { 0x80000021, "Submit_multi - resp" },
    { 0x00000102, "Alert_notification" },
    { 0x00000103, "Data_sm" },
    { 0x80000103, "Data_sm - resp" },
    /* Introduced in SMPP 5.0 */
    { 0x00000111, "Broadcast_sm" },
    { 0x80000111, "Broadcast_sm - resp" },
    { 0x00000112, "Query_broadcast_sm" },
    { 0x80000112, "Query_broadcast_sm - resp" },
    { 0x00000113, "Cancel_broadcast_sm" },
    { 0x80000113, "Cancel_broadcast_sm - resp" },
    /* Huawei SMPP+ extensions */
    { 0x01000001, "Auth_acc" },
    { 0x81000001, "Auth_acc - resp" },
    { 0X01000002, "Sm_result_notify" },
    { 0X81000002, "Sm_result_notify - resp" },
    { 0, NULL }
};

static const value_string vals_command_status[] = {     /* Status       */
    { 0x00000000, "Ok" },
    { 0x00000001, "Message length is invalid" },
    { 0x00000002, "Command length is invalid" },
    { 0x00000003, "Invalid command ID" },
    { 0x00000004, "Incorrect BIND status for given command" },
    { 0x00000005, "ESME already in bound state" },
    { 0x00000006, "Invalid priority flag" },
    { 0x00000007, "Invalid registered delivery flag" },
    { 0x00000008, "System error" },
    { 0x00000009, "[Reserved]" },
    { 0x0000000A, "Invalid source address" },
    { 0x0000000B, "Invalid destination address" },
    { 0x0000000C, "Message ID is invalid" },
    { 0x0000000D, "Bind failed" },
    { 0x0000000E, "Invalid password" },
    { 0x0000000F, "Invalid system ID" },
    { 0x00000010, "[Reserved]" },
    { 0x00000011, "Cancel SM failed" },
    { 0x00000012, "[Reserved]" },
    { 0x00000013, "Replace SM failed" },
    { 0x00000014, "Message queue full" },
    { 0x00000015, "Invalid service type" },
    { 0x00000033, "Invalid number of destinations" },
    { 0x00000034, "Invalid distribution list name" },
    { 0x00000040, "Destination flag is invalid (submit_multi)" },
    { 0x00000041, "[Reserved]" },
    { 0x00000042, "Invalid 'submit with replace' request" },
    { 0x00000043, "Invalid esm_class field data" },
    { 0x00000044, "Cannot submit to distribution list" },
    { 0x00000045, "submit_sm or submit_multi failed" },
    { 0x00000046, "[Reserved]" },
    { 0x00000047, "[Reserved]" },
    { 0x00000048, "Invalid source address TON" },
    { 0x00000049, "Invalid source address NPI" },
    { 0x00000050, "Invalid destination address TON" },
    { 0x00000051, "Invalid destination address NPI" },
    { 0x00000052, "[Reserved]" },
    { 0x00000053, "Invalid system_type field" },
    { 0x00000054, "Invalid replace_if_present flag" },
    { 0x00000055, "Invalid number of messages" },
    { 0x00000056, "[Reserved]" },
    { 0x00000057, "[Reserved]" },
    { 0x00000058, "Throttling error (ESME exceeded allowed message limits)" },
    { 0x00000059, "[Reserved]" },
    { 0x00000060, "[Reserved]" },
    { 0x00000061, "Invalid scheduled delivery time" },
    { 0x00000062, "Invalid message validity period (expiry time)" },
    { 0x00000063, "Predefined message invalid or not found" },
    { 0x00000064, "ESME receiver temporary app error code" },
    { 0x00000065, "ESME receiver permanent app error code" },
    { 0x00000066, "ESME receiver reject message error code" },
    { 0x00000067, "query_sm request failed" },
    { 0x000000C0, "Error in the optional part of the PDU body" },
    { 0x000000C1, "Optional parameter not allowed" },
    { 0x000000C2, "Invalid parameter length" },
    { 0x000000C3, "Expected optional parameter missing" },
    { 0x000000C4, "Invalid optional parameter  value" },
    { 0x000000FE, "(Transaction) Delivery failure (used for data_sm_resp)" },
    { 0x000000FF, "Unknown error" },
    /* Introduced in SMPP 5.0 */
    { 0x00000100, "ESME Not authorised to use specified service_type." },
    { 0x00000101, "ESME Prohibited from using specified operation."},
    { 0x00000102, "Specified service_type is unavailable." },
    { 0x00000103, "Specified service_type is denied." },
    { 0x00000104, "Invalid Data Coding Scheme." },
    { 0x00000105, "Source Address Sub unit is Invalid." },
    { 0x00000106, "Destination Address Sub unit is Invalid." },
    { 0x00000107, "Broadcast Frequency Interval is invalid." },
    { 0x00000108, "Broadcast Alias Name is invalid." },
    { 0x00000109, "Broadcast Area Format is invalid." },
    { 0x0000010A, "Number of Broadcast Areas is invalid." },
    { 0x0000010B, "Broadcast Content Type is invalid." },
    { 0x0000010C, "Broadcast Message Class is invalid." },
    { 0x0000010D, "broadcast_sm operation failed." },
    { 0x0000010E, "query_broadcast_sm operation failed." },
    { 0x0000010F, "cancel_broadcast_sm operation failed." },
    { 0x00000110, "Number of Repeated Broadcasts is invalid." },
    { 0x00000111, "Broadcast Service Group is invalid." },
    { 0x00000112, "Broadcast Channel Indicator is invalid." },
    { 0, NULL }
};

static const range_string reserved_command_status[] = {     /* Reserved ranges */
    { 0x00000016, 0x00000032, "[Reserved]" },
    { 0x00000035, 0x0000003F, "[Reserved]" },
    { 0x00000068, 0x000000BF, "[Reserved]" },
    { 0x000000C5, 0x000000FD, "[Reserved]" },
    { 0x00000400, 0x000004FF, "[Message center vendor-specific error code]" },
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

static const value_string vals_data_coding[] = {
    {   0, "SMSC default alphabet" },
    {   1, "IA5 (CCITT T.50/ASCII (ANSI X3.4)" },
    {   2, "Octet unspecified (8-bit binary)" },
    {   3, "Latin 1 (ISO-8859-1)" },
    {   4, "Octet unspecified (8-bit binary)" },
    {   5, "JIS (X 0208-1990)" },
    {   6, "Cyrillic (ISO-8859-5)" },
    {   7, "Latin/Hebrew (ISO-8859-8)" },
    {   8, "UCS2 (ISO/IEC-10646)" },
    {   9, "Pictogram encoding" },
    {  10, "ISO-2022-JP (Music codes)" },
    {  11, "reserved" },
    {  12, "reserved" },
    {  13, "Extended Kanji JIS(X 0212-1990)" },
    {  14, "KS C 5601" },
    /*! \TODO Rest to be defined (bitmask?) according GSM 03.38 */
    {  0, NULL }
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

/* Data Coding Scheme: see 3GPP TS 23.040 and 3GPP TS 23.038 */
static const value_string vals_dcs_sms_coding_group[] = {
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
    { 0x0C, "SMS DCS: Message Waiting Indication - Discard Message" },
    { 0x0D, "SMS DCS: Message Waiting Indication - Store Message (GSM 7-bit default alphabet)" },
    { 0x0E, "SMS DCS: Message Waiting Indication - Store Message (UCS-2 character set)" },
    { 0x0F, "SMS DCS: Data coding / message class" },
    { 0x00, NULL }
};

static const true_false_string tfs_dcs_text_compression = {
    "Compressed text",
    "Uncompressed text"
};

static const true_false_string tfs_dcs_class_present = {
    "Message class is present",
    "No message class"
};

static const value_string vals_dcs_charset[] = {
    { 0x00, "GSM 7-bit default alphabet" },
    { 0x01, "8-bit data" },
    { 0x02, "UCS-2 (16-bit) data" },
    { 0x03, "Reserved" },
    { 0x00, NULL }
};

static const value_string vals_dcs_class[] = {
    { 0x00, "Class 0" },
    { 0x01, "Class 1 - ME specific" },
    { 0x02, "Class 2 - (U)SIM specific" },
    { 0x03, "Class 3 - TE specific" },
    { 0x00, NULL }
};

static const value_string vals_dcs_cbs_coding_group[] = {
    { 0x00, "CBS DCS: Language using the GSM 7-bit default alphabet" },
    { 0x01, "CBS DCS: Language indication at beginning of message" },
    { 0x02, "CBS DCS: Language using the GSM 7-bit default alphabet" },
    { 0x03, "CBS DCS: Reserved" },
    { 0x04, "CBS DCS: General Data Coding indication - Uncompressed text, no message class" },
    { 0x05, "CBS DCS: General Data Coding indication - Uncompressed text" },
    { 0x06, "CBS DCS: General Data Coding indication - Compressed text, no message class" },
    { 0x07, "CBS DCS: General Data Coding indication - Compressed text" },
    { 0x08, "CBS DCS: Reserved" },
    { 0x09, "CBS DCS: Message with User Data Header structure" },
    { 0x0A, "CBS DCS: Reserved" },
    { 0x0B, "CBS DCS: Reserved" },
    { 0x0C, "CBS DCS: Reserved" },
    { 0x0D, "CBS DCS: Reserved" },
    { 0x0E, "CBS DCS: Defined by the WAP Forum" },
    { 0x0F, "SMS DCS: Data coding / message class" },
    { 0x00, NULL }
};

static const value_string vals_dcs_cbs_language[] = {
    { 0x00, "German" },
    { 0x01, "English" },
    { 0x02, "Italian" },
    { 0x03, "French" },
    { 0x04, "Spanish" },
    { 0x05, "Dutch" },
    { 0x06, "Swedish" },
    { 0x07, "Danish" },
    { 0x08, "Portuguese" },
    { 0x09, "Finnish" },
    { 0x0A, "Norwegian" },
    { 0x0B, "Greek" },
    { 0x0C, "Turkish" },
    { 0x0D, "Hungarian" },
    { 0x0E, "Polish" },
    { 0x0F, "Language not specified" },
    { 0x10, "GSM 7-bit default alphabet - message preceded by language indication" },
    { 0x11, "UCS-2 (16-bit) - message preceded by language indication" },
    { 0x20, "Czech" },
    { 0x21, "Hebrew" },
    { 0x22, "Arabic" },
    { 0x23, "Russian" },
    { 0x24, "Icelandic" },
    { 0x00, NULL }
};

static const value_string vals_dcs_cbs_class[] = {
    { 0x00, "No message class" },
    { 0x01, "Class 1 - User defined" },
    { 0x02, "Class 2 - User defined" },
    { 0x03, "Class 3 - TE specific" },
    { 0x00, NULL }
};

static const value_string vals_dcs_wap_class[] = {
    { 0x00, "No message class" },
    { 0x01, "Class 1 - ME specific" },
    { 0x02, "Class 2 - (U)SIM specific" },
    { 0x03, "Class 3 - TE specific" },
    { 0x00, NULL }
};

static const value_string vals_dcs_wap_charset[] = {
    { 0x00, "Reserved" },
    { 0x01, "8-bit data" },
    { 0x02, "Reserved" },
    { 0x03, "Reserved" },
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
    {0x0014,        "[News Service] General News (Internationa)"},
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

static dissector_handle_t gsm_sms_handle;

/*
 * For Stats Tree
 */
static void
smpp_stats_tree_init(stats_tree* st)
{
    st_smpp_ops = stats_tree_create_node(st, "SMPP Operations", 0, TRUE);
    st_smpp_req = stats_tree_create_node(st, "SMPP Requests", st_smpp_ops, TRUE);
    st_smpp_res = stats_tree_create_node(st, "SMPP Responses", st_smpp_ops, TRUE);
    st_smpp_res_status = stats_tree_create_node(st, "SMPP Response Status", 0, TRUE);

}

static int
smpp_stats_tree_per_packet(stats_tree *st, /* st as it was passed to us */
                           packet_info *pinfo _U_,
                           epan_dissect_t *edt _U_,
                           const void *p) /* Used for getting SMPP command_id values */
{
    const smpp_tap_rec_t* tap_rec = (const smpp_tap_rec_t*)p;

    tick_stat_node(st, "SMPP Operations", 0, TRUE);

    if ((tap_rec->command_id & 0x80000000) == 0x80000000) /* Response */
    {
        tick_stat_node(st, "SMPP Responses", st_smpp_ops, TRUE);
        tick_stat_node(st, val_to_str(tap_rec->command_id, vals_command_id, "Unknown 0x%08x"), st_smpp_res, FALSE);

        tick_stat_node(st, "SMPP Response Status", 0, TRUE);
        tick_stat_node(st, val_to_str(tap_rec->command_status, vals_command_status, "Unknown 0x%08x"), st_smpp_res_status, FALSE);

    }
    else  /* Request */
    {
        tick_stat_node(st, "SMPP Requests", st_smpp_ops, TRUE);
        tick_stat_node(st, val_to_str(tap_rec->command_id, vals_command_id, "Unknown 0x%08x"), st_smpp_req, FALSE);
    }

    return 1;
}

/*!
 * SMPP equivalent of mktime() (3). Convert date to standard 'time_t' format
 *
 * \param       datestr The SMPP-formatted date to convert
 * \param       secs    Returns the 'time_t' equivalent
 * \param       nsecs   Returns the additional nano-seconds
 *
 * \return              Whether time is specified relative or absolute
 * \retval      TRUE    Relative time
 * \retval      FALSE   Absolute time
 */
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
        struct tm *gm, *local_time;
        int gm_hour, gm_min;
        time_t current_time;

        *secs = mktime(&r_time);

        /* Subtract out the timezone information since we will adjust for
         * the presented time's timezone below and then display in UTC.
         *
         * To do that, first determine the current timezone's offset to UTC.
         */
        current_time = time(NULL);
        gm = gmtime(&current_time);
        gm_hour = gm->tm_hour;
        gm_min = gm->tm_min;
        local_time = localtime(&current_time);
        /* Then subtract out that difference (whether the difference is
         * measured in hours, minutes, or both).
         */
        *secs -= 3600*(gm_hour - local_time->tm_hour);
        *secs -= 60*(gm_min - local_time->tm_min);

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

/* NOTE - caller must free the returned string! */
static const char *
smpp_handle_string_return(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    gint         len;
    const char   *str;

    len = tvb_strsize(tvb, *offset);
    if (len > 1) {
        str = (char *)tvb_get_stringz_enc(wmem_packet_scope(), tvb, *offset, &len, ENC_ASCII);
        proto_tree_add_string(tree, field, tvb, *offset, len, str);
    } else {
        str = "";
    }
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
smpp_handle_int1(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    guint8       val;

    val = tvb_get_guint8(tvb, *offset);
    proto_tree_add_uint(tree, field, tvb, *offset, 1, val);
    (*offset)++;
}

static void
smpp_handle_int2(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    guint        val;

    val = tvb_get_ntohs(tvb, *offset);
    proto_tree_add_uint(tree, field, tvb, *offset, 2, val);
    (*offset) += 2;
}

static void
smpp_handle_int4(proto_tree *tree, tvbuff_t *tvb, int field, int *offset)
{
    guint        val;

    val = tvb_get_ntohl(tvb, *offset);
    proto_tree_add_uint(tree, field, tvb, *offset, 4, val);
    (*offset) += 4;
}

static void
smpp_handle_time(proto_tree *tree, tvbuff_t *tvb,
                 int field, int field_R, int *offset)
{
    char     *strval;
    gint      len;
    nstime_t  tmptime;

    strval = (char *) tvb_get_stringz_enc(wmem_packet_scope(), tvb, *offset, &len, ENC_ASCII);
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
            proto_tree_add_text(tree, tvb, *offset, len, "Invalid time: %s", strval);
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
            smpp_handle_int1(sub_tree, tvb, hf_smpp_dest_addr_ton, &tmpoff);
            smpp_handle_int1(sub_tree, tvb, hf_smpp_dest_addr_npi, &tmpoff);
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
        smpp_handle_int1(sub_tree, tvb, hf_smpp_dest_addr_ton, &tmpoff);
        smpp_handle_int1(sub_tree, tvb, hf_smpp_dest_addr_npi, &tmpoff);
        smpp_handle_string(sub_tree,tvb,hf_smpp_destination_addr,&tmpoff);
        smpp_handle_int4(sub_tree, tvb, hf_smpp_error_status_code, &tmpoff);
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
smpp_handle_tlv(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    proto_tree *tlvs_tree = NULL;
    proto_item *pi;

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

        guint8   field;
        guint16  field16;
        guint8   major, minor;
        char     *strval=NULL;

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
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_dest_addr_subunit, offset);
                break;
            case  0x0006:       /* dest_network_type    */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_dest_network_type, offset);
                break;
            case  0x0007:       /* dest_bearer_type     */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_dest_bearer_type, offset);
                break;
            case  0x0008:       /* dest_telematics_id   */
                smpp_handle_int2(sub_tree, tvb,
                                 hf_smpp_dest_telematics_id, offset);
                break;
            case  0x000D:       /* source_addr_subunit  */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_source_addr_subunit, offset);
                break;
            case  0x000E:       /* source_network_type  */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_source_network_type, offset);
                break;
            case  0x000F:       /* source_bearer_type   */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_source_bearer_type, offset);
                break;
            case  0x0010:       /* source_telematics_id */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_source_telematics_id, offset);
                break;
            case  0x0017:       /* qos_time_to_live     */
                smpp_handle_int4(sub_tree, tvb,
                                 hf_smpp_qos_time_to_live, offset);
                break;
            case  0x0019:       /* payload_type */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_payload_type, offset);
                break;
            case  0x001D:       /* additional_status_info_text  */
                smpp_handle_string(sub_tree, tvb,
                                   hf_smpp_additional_status_info_text, offset);
                break;
            case  0x001E:       /* receipted_message_id */
                smpp_handle_string(sub_tree, tvb,
                                   hf_smpp_receipted_message_id, offset);
                break;
            case  0x0030:       /* ms_msg_wait_facilities       */
                field = tvb_get_guint8(tvb, *offset);
                proto_tree_add_uint(sub_tree, hf_smpp_msg_wait_ind,
                                    tvb, *offset, 1, field);
                proto_tree_add_uint(sub_tree, hf_smpp_msg_wait_type,
                                    tvb, *offset, 1, field);
                (*offset)++;
                break;
            case  0x0201:       /* privacy_indicator    */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_privacy_indicator, offset);
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
                smpp_handle_int2(sub_tree, tvb,
                                 hf_smpp_user_message_reference, offset);
                break;
            case  0x0205:       /* user_response_code   */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_user_response_code, offset);
                break;
            case  0x020A:       /* source_port  */
                smpp_handle_int2(sub_tree, tvb,
                                 hf_smpp_source_port, offset);
                break;
            case  0x020B:       /* destination_port     */
                smpp_handle_int2(sub_tree, tvb,
                                 hf_smpp_destination_port, offset);
                break;
            case  0x020C:       /* sar_msg_ref_num      */
                smpp_handle_int2(sub_tree, tvb,
                                 hf_smpp_sar_msg_ref_num, offset);
                break;
            case  0x020D:       /* language_indicator   */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_language_indicator, offset);
                break;
            case  0x020E:       /* sar_total_segments   */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_sar_total_segments, offset);
                break;
            case  0x020F:       /* sar_segment_seqnum   */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_sar_segment_seqnum, offset);
                break;
            case  0x0210:       /* SC_interface_version */
                field = tvb_get_guint8(tvb, *offset);
                minor = field & 0x0F;
                major = (field & 0xF0) >> 4;
                strval=wmem_strdup_printf(wmem_packet_scope(), "%u.%u", major, minor);
                proto_tree_add_string(sub_tree, hf_smpp_SC_interface_version,
                                      tvb, *offset, 1, strval);
                (*offset)++;
                break;
            case  0x0302:       /* callback_num_pres_ind        */
                field = tvb_get_guint8(tvb, *offset);
                proto_tree_add_uint(sub_tree, hf_smpp_callback_num_pres,
                                    tvb, *offset, 1, field);
                proto_tree_add_uint(sub_tree, hf_smpp_callback_num_scrn,
                                    tvb, *offset, 1, field);
                (*offset)++;
                break;
            case  0x0303:       /* callback_num_atag    */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_callback_num_atag,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case  0x0304:       /* number_of_messages   */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_number_of_messages, offset);
                break;
            case  0x0381:       /* callback_num */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_callback_num,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case  0x0420:       /* dpf_result   */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_dpf_result, offset);
                break;
            case  0x0421:       /* set_dpf      */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_set_dpf, offset);
                break;
            case  0x0422:       /* ms_availability_status       */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_ms_availability_status, offset);
                break;
            case  0x0423:       /* network_error_code   */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_network_error_type, offset);
                smpp_handle_int2(sub_tree, tvb,
                                 hf_smpp_network_error_code, offset);
                break;
            case  0x0424:       /* message_payload      */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_message_payload,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case  0x0425:       /* delivery_failure_reason      */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_delivery_failure_reason, offset);
                break;
            case  0x0426:       /* more_messages_to_send        */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_more_messages_to_send, offset);
                break;
            case  0x0427:       /* message_state        */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_message_state, offset);
                break;
            case        0x0428: /* congestion_state */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_congestion_state, offset);

                break;
            case  0x0501:       /* ussd_service_op      */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_ussd_service_op, offset);
                break;
            case 0x0600:        /* broadcast_channel_indicator */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_broadcast_channel_indicator, offset);
                break;
            case 0x0601:        /* broadcast_content_type */
                field = tvb_get_guint8(tvb, *offset);
                proto_tree_add_uint(sub_tree, hf_smpp_broadcast_content_type_nw, tvb, *offset, 1, field);
                (*offset)++;
                field16 = tvb_get_ntohs(tvb, *offset);
                proto_tree_add_uint(sub_tree, hf_smpp_broadcast_content_type_type, tvb, *offset, 2, field16);
                (*offset) += 2;
                break;
            case 0x0602:        /* broadcast_content_type_info */
                if (length)
                    proto_tree_add_item(sub_tree, hf_smpp_broadcast_content_type_info,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case 0x0603:        /* broadcast_message_class */
                smpp_handle_int1(sub_tree, tvb,
                                hf_smpp_broadcast_message_class, offset);
                break;
            case 0x0604:        /* broadcast_rep_num */
                smpp_handle_int1(sub_tree, tvb,
                                hf_smpp_broadcast_rep_num, offset);
                break;
            case 0x0605:        /* broadcast_frequency_interval */
                field = tvb_get_guint8(tvb, *offset);
                proto_tree_add_uint(sub_tree, hf_smpp_broadcast_frequency_interval_unit, tvb, *offset, 1, field);
                (*offset)++;
                field16 = tvb_get_ntohs(tvb, *offset);
                proto_tree_add_uint(sub_tree, hf_smpp_broadcast_frequency_interval_value, tvb, *offset, 2, field16);
                (*offset) += 2;
                break;
            case 0x0606:        /* broadcast_area_identifier */
                field = tvb_get_guint8(tvb, *offset);
                proto_tree_add_uint(sub_tree, hf_smpp_broadcast_area_identifier_format, tvb, *offset, 1, field);
                proto_tree_add_item(sub_tree, hf_smpp_broadcast_area_identifier,
                                        tvb, *offset, length, ENC_NA);
                (*offset) += length;
                break;
            case 0x0607:        /* broadcast_error_status */
                smpp_handle_int4(sub_tree, tvb,
                                hf_smpp_broadcast_error_status, offset);
                break;
            case 0x0608:        /* broadcast_area_success */
                smpp_handle_int1(sub_tree, tvb,
                                hf_smpp_broadcast_area_success, offset);
                break;
            case 0x0609:        /* broadcast_end_time */
                smpp_handle_time(sub_tree, tvb, hf_smpp_broadcast_end_time,
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
                smpp_handle_string_z(sub_tree, tvb, hf_smpp_source_network_id,
                                offset, "Empty!");
                break;
            case 0x060E:        /* dest_network_id */
                smpp_handle_string_z(sub_tree, tvb, hf_smpp_dest_network_id,
                                offset, "Empty!");
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
                smpp_handle_int1(sub_tree, tvb,
                                hf_smpp_dest_addr_np_resolution, offset);
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
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_display_time, offset);
                break;
            case  0x1203:       /* sms_signal   */
                smpp_handle_int2(sub_tree, tvb,
                                 hf_smpp_sms_signal, offset);
                /*! \todo Fill as per TIA/EIA-136-710-A         */
                break;
            case  0x1204:       /* ms_validity  */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_ms_validity, offset);
                break;
            case  0x130C:       /* alert_on_message_delivery    */
                if (length == 0) {
                        proto_tree_add_item(sub_tree,
                                    hf_smpp_alert_on_message_delivery_null,
                                    tvb, *offset, length, ENC_NA);
                } else {
                        smpp_handle_int1(sub_tree, tvb,
                                    hf_smpp_alert_on_message_delivery, offset);
                }
                break;
            case  0x1380:       /* its_reply_type       */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_its_reply_type, offset);
                break;
            case  0x1383:       /* its_session_info     */
                smpp_handle_int1(sub_tree, tvb,
                                 hf_smpp_its_session_number, offset);
                field = tvb_get_guint8(tvb, *offset);
                proto_tree_add_uint(sub_tree, hf_smpp_its_session_sequence,
                                    tvb, *offset, 1, field);
                proto_tree_add_uint(sub_tree, hf_smpp_its_session_ind,
                                    tvb, *offset, 1, field);
                (*offset)++;
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

                proto_item_append_text(sub_tree,": %s", tvb_bytes_to_ep_str(tvb,*offset,length));
                (*offset) += length;
                break;
        }
    }
}

void
smpp_handle_dcs(proto_tree *tree, tvbuff_t *tvb, int *offset)
{
    guint8      val;
    int         off     = *offset;
    proto_tree *subtree = NULL;
    proto_item *pi;

    val = tvb_get_guint8(tvb, off);
    pi = proto_tree_add_uint(tree, hf_smpp_data_coding, tvb, off, 1, val);
    subtree = proto_item_add_subtree(pi, ett_dcs);
    /* SMPP Data Coding Scheme */
    proto_tree_add_uint(subtree, hf_smpp_dcs, tvb, off, 1, val);
    /* GSM SMS Data Coding Scheme */
    proto_tree_add_text(subtree, tvb, off, 1,
                        "GSM SMS Data Coding");
    proto_tree_add_uint(subtree,
                        hf_smpp_dcs_sms_coding_group, tvb, off, 1, val);
    if (val>>6 == 2) { /* Reserved */
        ;
    } else if (val < 0xF0) {
        proto_tree_add_boolean(subtree,
                               hf_smpp_dcs_text_compression, tvb, off, 1, val);
        proto_tree_add_boolean(subtree,
                               hf_smpp_dcs_class_present, tvb, off, 1, val);
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_charset, tvb, off, 1, val);
        if (val & 0x10)
            proto_tree_add_uint(subtree,
                                hf_smpp_dcs_class, tvb, off, 1, val);
    } else {
        if (val & 0x08)
            proto_tree_add_text(subtree, tvb, off, 1,
                                "SMPP: Bit .... 1... should be 0 (reserved)");
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_charset, tvb, off, 1, val);
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_class, tvb, off, 1, val);
    }
    /* Cell Broadcast Service (CBS) Data Coding Scheme */
    proto_tree_add_text(subtree, tvb, off, 1,
                        "GSM CBS Data Coding");
    proto_tree_add_uint(subtree,
                        hf_smpp_dcs_cbs_coding_group, tvb, off, 1, val);
    if (val < 0x40) { /* Language specified */
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_cbs_language, tvb, off, 1, val);
    } else if (val>>6 == 1) { /* General Data Coding indication */
        proto_tree_add_boolean(subtree,
                               hf_smpp_dcs_text_compression, tvb, off, 1, val);
        proto_tree_add_boolean(subtree,
                               hf_smpp_dcs_class_present, tvb, off, 1, val);
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_charset, tvb, off, 1, val);
        if (val & 0x10)
            proto_tree_add_uint(subtree,
                                hf_smpp_dcs_class, tvb, off, 1, val);
    } else if (val>>6 == 2) { /* Message with UDH structure */
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_charset, tvb, off, 1, val);
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_class, tvb, off, 1, val);
    } else if (val>>4 == 14) { /* WAP Forum */
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_wap_charset, tvb, off, 1, val);
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_wap_class, tvb, off, 1, val);
    } else if (val>>4 == 15) { /* Data coding / message handling */
        if (val & 0x08)
            proto_tree_add_text(subtree, tvb, off, 1,
                                "SMPP: Bit .... 1... should be 0 (reserved)");
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_charset, tvb, off, 1, val);
        proto_tree_add_uint(subtree,
                            hf_smpp_dcs_cbs_class, tvb, off, 1, val);
    }

    (*offset)++;
}

/*!
 * The next set of routines handle the different operations, associated
 * with SMPP.
 */
static void
bind_receiver(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;
    guint8       field;
    guint8       major, minor;
    char        *strval;

    smpp_handle_string(tree, tvb, hf_smpp_system_id, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_password, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_system_type, &offset);
    field = tvb_get_guint8(tvb, offset++);
    minor = field & 0x0F;
    major = (field & 0xF0) >> 4;
    strval=wmem_strdup_printf(wmem_packet_scope(), "%u.%u", major, minor);
    proto_tree_add_string(tree, hf_smpp_interface_version, tvb,
                          offset - 1, 1, strval);
    smpp_handle_int1(tree, tvb, hf_smpp_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_address_range, &offset);
}

#define bind_transmitter(a, b) bind_receiver(a, b)

static void
query_sm(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
}

#define bind_transceiver(a, b) bind_receiver(a, b)

static void
outbind(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string(tree, tvb, hf_smpp_system_id, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_password, &offset);
}

static void
submit_sm(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
                proto_tree *top_tree)
{
    tvbuff_t *tvb_msg;
    int       offset  = 0;
    guint8    flag, udhi;
    guint8    length;
    const char *src_str = NULL;
    const char *dst_str = NULL;
    address   save_src, save_dst;

    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_npi, &offset);
    src_str = smpp_handle_string_return(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_dest_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_dest_addr_npi, &offset);
    dst_str = smpp_handle_string_return(tree, tvb, hf_smpp_destination_addr, &offset);
    flag = tvb_get_guint8(tvb, offset);
    udhi = flag & 0x40;
    proto_tree_add_uint(tree, hf_smpp_esm_submit_msg_mode,
                        tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_esm_submit_msg_type,
                        tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_esm_submit_features,
                        tvb, offset, 1, flag);
    offset++;
    smpp_handle_int1(tree, tvb, hf_smpp_protocol_id, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_priority_flag, &offset);
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, hf_smpp_schedule_delivery_time,
                         hf_smpp_schedule_delivery_time_r, &offset);
    } else { /* Time = NULL means Immediate delivery */
        proto_tree_add_text(tree, tvb, offset++, 1,
                            "Scheduled delivery time: Immediate delivery");
    }
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, hf_smpp_validity_period,
                         hf_smpp_validity_period_r, &offset);
    } else { /* Time = NULL means SMSC default validity */
        proto_tree_add_text(tree, tvb, offset++, 1,
                            "Validity period: SMSC default validity period");
    }
    flag = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_smpp_regdel_receipt, tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_regdel_acks, tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_regdel_notif, tvb, offset, 1, flag);
    offset++;
    smpp_handle_int1(tree, tvb, hf_smpp_replace_if_present_flag, &offset);
        smpp_handle_dcs(tree, tvb, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_sm_default_msg_id, &offset);
    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_smpp_sm_length, tvb, offset++, 1, length);
    if (length)
    {
        proto_tree_add_item(tree, hf_smpp_short_message,
                            tvb, offset, length, ENC_NA);
        if (udhi) /* UDHI indicator present */
        {
            DebugLog(("UDHI present - set addresses\n"));
            /* Save original addresses */
            SET_ADDRESS(&save_src, pinfo->src.type, pinfo->src.len, pinfo->src.data);
            SET_ADDRESS(&save_dst, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);
            /* Set SMPP source and destination address */
            SET_ADDRESS(&(pinfo->src), AT_STRINGZ, 1+(int)strlen(src_str), src_str);
            SET_ADDRESS(&(pinfo->dst), AT_STRINGZ, 1+(int)strlen(dst_str), dst_str);
            tvb_msg = tvb_new_subset (tvb, offset,
                    MIN(length, tvb_reported_length(tvb) - offset), length);
            call_dissector (gsm_sms_handle, tvb_msg, pinfo, top_tree);
            /* Restore original addresses */
            SET_ADDRESS(&(pinfo->src), save_src.type, save_src.len, save_src.data );
            SET_ADDRESS(&(pinfo->dst), save_dst.type, save_dst.len, save_dst.data);
        }
        offset += length;
    }
    /* Get rid of SMPP text string addresses */
    smpp_handle_tlv(tree, tvb, &offset);
}

#define deliver_sm(a, b, c, d) submit_sm(a, b, c, d)

static void
replace_sm(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;
    guint8       flag;
    guint8       length;

    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
        if (tvb_get_guint8(tvb,offset)) {
    smpp_handle_time(tree, tvb, hf_smpp_schedule_delivery_time,
                                hf_smpp_schedule_delivery_time_r, &offset);
        } else { /* Time = NULL */
                proto_tree_add_text(tree, tvb, offset++, 1,
                                "Scheduled delivery time: Keep initial delivery time setting");
        }
        if (tvb_get_guint8(tvb,offset)) {
    smpp_handle_time(tree, tvb, hf_smpp_validity_period,
                                hf_smpp_validity_period_r, &offset);
        } else { /* Time = NULL */
                proto_tree_add_text(tree, tvb, offset++, 1,
                                "Validity period: Keep initial validity period setting");
        }
    flag = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_smpp_regdel_receipt, tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_regdel_acks, tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_regdel_notif, tvb, offset, 1, flag);
    offset++;
    smpp_handle_int1(tree, tvb, hf_smpp_sm_default_msg_id, &offset);
    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_smpp_sm_length, tvb, offset++, 1, length);
    if (length)
        proto_tree_add_item(tree, hf_smpp_short_message,
                            tvb, offset, length, ENC_NA);
    offset += length;
}

static void
cancel_sm(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_dest_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_dest_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_destination_addr, &offset);
}

static void
submit_multi(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;
    guint8       flag;
    guint8       length;

    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);

    smpp_handle_dlist(tree, tvb, &offset);

    flag = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_smpp_esm_submit_msg_mode,
            tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_esm_submit_msg_type,
            tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_esm_submit_features,
            tvb, offset, 1, flag);
    offset++;
    smpp_handle_int1(tree, tvb, hf_smpp_protocol_id, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_priority_flag, &offset);
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, hf_smpp_schedule_delivery_time,
                hf_smpp_schedule_delivery_time_r, &offset);
    } else { /* Time = NULL means Immediate delivery */
        proto_tree_add_text(tree, tvb, offset++, 1,
                "Scheduled delivery time: Immediate delivery");
    }
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, hf_smpp_validity_period,
                hf_smpp_validity_period_r, &offset);
    } else { /* Time = NULL means SMSC default validity */
        proto_tree_add_text(tree, tvb, offset++, 1,
                "Validity period: SMSC default validity period");
    }
    flag = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_smpp_regdel_receipt, tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_regdel_acks, tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_regdel_notif, tvb, offset, 1, flag);
    offset++;
    smpp_handle_int1(tree, tvb, hf_smpp_replace_if_present_flag, &offset);
    smpp_handle_dcs(tree, tvb, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_sm_default_msg_id, &offset);
    length = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_smpp_sm_length, tvb, offset++, 1, length);
    if (length)
        proto_tree_add_item(tree, hf_smpp_short_message,
                tvb, offset, length, ENC_NA);
    offset += length;
    smpp_handle_tlv(tree, tvb, &offset);
}

static void
alert_notification(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_esme_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_esme_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_esme_addr, &offset);
    smpp_handle_tlv(tree, tvb, &offset);
}

static void
data_sm(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;
    guint8       flag;

    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_dest_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_dest_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_destination_addr, &offset);
    flag = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_smpp_esm_submit_msg_mode,
                        tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_esm_submit_msg_type,
                        tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_esm_submit_features,
                        tvb, offset, 1, flag);
    offset++;
    flag = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(tree, hf_smpp_regdel_receipt, tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_regdel_acks, tvb, offset, 1, flag);
    proto_tree_add_uint(tree, hf_smpp_regdel_notif, tvb, offset, 1, flag);
    offset++;
        smpp_handle_dcs(tree, tvb, &offset);
    smpp_handle_tlv(tree, tvb, &offset);
}

/*
 * Request operations introduced in the SMPP 5.0
 */
static void
broadcast_sm(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_priority_flag, &offset);
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, hf_smpp_schedule_delivery_time,
                hf_smpp_schedule_delivery_time_r, &offset);
    } else { /* Time = NULL means Immediate delivery */
        proto_tree_add_text(tree, tvb, offset++, 1,
                "Scheduled delivery time: Immediate delivery");
    }
    if (tvb_get_guint8(tvb,offset)) {
        smpp_handle_time(tree, tvb, hf_smpp_validity_period,
                hf_smpp_validity_period_r, &offset);
    } else { /* Time = NULL means SMSC default validity */
        proto_tree_add_text(tree, tvb, offset++, 1,
                "Validity period: SMSC default validity period");
    }
    smpp_handle_int1(tree, tvb, hf_smpp_replace_if_present_flag, &offset);
    smpp_handle_dcs(tree, tvb, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_sm_default_msg_id, &offset);
    smpp_handle_tlv(tree, tvb, &offset);
}

static void
query_broadcast_sm(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_tlv(tree, tvb, &offset);
}

static void
cancel_broadcast_sm(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string_z(tree, tvb, hf_smpp_service_type, &offset, "(Default)");
    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_ton, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_source_addr_npi, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_tlv(tree, tvb, &offset);
}

/*!
 * The next set of routines handle the different operation-responses,
 * associated with SMPP.
 */
static void
bind_receiver_resp(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string(tree, tvb, hf_smpp_system_id, &offset);
    smpp_handle_tlv(tree, tvb, &offset);
}

#define bind_transmitter_resp(a, b) bind_receiver_resp(a, b)

static void
query_sm_resp(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_time(tree, tvb, hf_smpp_final_date,
                                hf_smpp_final_date_r, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_message_state, &offset);
    smpp_handle_int1(tree, tvb, hf_smpp_error_code, &offset);
}

#define bind_transceiver_resp(a, b) bind_receiver_resp(a, b)

static void
submit_sm_resp(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_tlv(tree, tvb, &offset);
}

#define deliver_sm_resp(a, b) submit_sm_resp(a, b)

static void
submit_multi_resp(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_dlist_resp(tree, tvb, &offset);
    smpp_handle_tlv(tree, tvb, &offset);
}

static void
data_sm_resp(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_tlv(tree, tvb, &offset);
}

#define broadcast_sm_resp(a, b) submit_sm_resp(a, b)

static void
query_broadcast_sm_resp(proto_tree *tree, tvbuff_t *tvb)
{
    int          offset = 0;

    smpp_handle_string(tree, tvb, hf_smpp_message_id, &offset);
    smpp_handle_tlv(tree, tvb, &offset);
}

/* Huawei SMPP+ extensions */
static void
huawei_auth_acc(proto_tree *tree, tvbuff_t *tvb)
{
    int    offset  = 0;
    guint8 version = 0;

    smpp_handle_int1(tree, tvb, hf_huawei_smpp_version, &offset);
    version = tvb_get_guint8(tvb, offset);
    smpp_handle_string(tree, tvb, hf_huawei_smpp_smsc_addr, &offset);
    if ( version == '3' ) {
        smpp_handle_int1(tree, tvb, hf_huawei_smpp_msc_addr_noa, &offset);
        smpp_handle_int1(tree, tvb, hf_huawei_smpp_msc_addr_npi, &offset);
        smpp_handle_string(tree, tvb, hf_huawei_smpp_msc_addr, &offset);
    }
    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_destination_addr, &offset);
    smpp_handle_int1(tree, tvb, hf_huawei_smpp_mo_mt_flag, &offset);
    smpp_handle_string(tree, tvb, hf_huawei_smpp_sm_id, &offset);
    smpp_handle_int4(tree, tvb, hf_huawei_smpp_length_auth, &offset);
    smpp_handle_int4(tree, tvb, hf_huawei_smpp_service_id, &offset);
}

static void
huawei_auth_acc_resp(proto_tree *tree, tvbuff_t *tvb)
{
    int offset = 0;

    smpp_handle_int4(tree, tvb, hf_huawei_smpp_operation_result, &offset);
    smpp_handle_int1(tree, tvb, hf_huawei_smpp_notify_mode, &offset);
}

static void
huawei_sm_result_notify(proto_tree *tree, tvbuff_t *tvb)
{
    int    offset  = 0;
    guint8 version = 0;

    smpp_handle_int1(tree, tvb, hf_huawei_smpp_version, &offset);
    version = tvb_get_guint8(tvb, offset);
    smpp_handle_string(tree, tvb, hf_huawei_smpp_smsc_addr, &offset);

    if ( version == '3' ) {
        smpp_handle_int1(tree, tvb, hf_huawei_smpp_msc_addr_noa, &offset);
        smpp_handle_int1(tree, tvb, hf_huawei_smpp_msc_addr_npi, &offset);
        smpp_handle_string(tree, tvb, hf_huawei_smpp_msc_addr, &offset);
    }

    smpp_handle_string(tree, tvb, hf_smpp_source_addr, &offset);
    smpp_handle_string(tree, tvb, hf_smpp_destination_addr, &offset);
    smpp_handle_int1(tree, tvb, hf_huawei_smpp_mo_mt_flag, &offset);
    smpp_handle_string(tree, tvb, hf_huawei_smpp_sm_id, &offset);
    smpp_handle_int4(tree, tvb, hf_huawei_smpp_length_auth, &offset);
    smpp_handle_int4(tree, tvb, hf_huawei_smpp_delivery_result, &offset);
    smpp_handle_int4(tree, tvb, hf_huawei_smpp_service_id, &offset);
}

static void
huawei_sm_result_notify_resp(proto_tree *tree, tvbuff_t *tvb)
{
    int offset = 0;

    smpp_handle_int4(tree, tvb, hf_huawei_smpp_operation_result, &offset);
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
    guint        command_id;            /* SMPP command         */
    guint        command_status;        /* Status code          */
    guint        command_length;        /* length of PDU        */

    if (tvb_reported_length(tvb) < SMPP_MIN_LENGTH)     /* Mandatory header     */
        return FALSE;
    command_length = tvb_get_ntohl(tvb, 0);
    if (command_length > 64 * 1024 || command_length < SMPP_MIN_LENGTH)
        return FALSE;
    command_id = tvb_get_ntohl(tvb, 4);         /* Only known commands  */
    if (try_val_to_str(command_id, vals_command_id) == NULL)
        return FALSE;
    command_status = tvb_get_ntohl(tvb, 8);     /* ..with known status  */
    if (try_val_to_str(command_status, vals_command_status) == NULL &&
                try_rval_to_str(command_status, reserved_command_status) == NULL)
        return FALSE;
    dissect_smpp(tvb, pinfo, tree, data);
    return TRUE;
}

static guint
get_smpp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
    return tvb_get_ntohl(tvb, offset);
}

/*
 * This global SMPP variable is used to determine whether the PDU to dissect
 * is the first SMPP PDU in the packet (or reassembled buffer), requiring
 * different column update code than subsequent SMPP PDUs within this packet
 * (or reassembled buffer).
 *
 * FIXME - This approach is NOT dissection multi-thread safe!
 */
static gboolean first = TRUE;

static int
dissect_smpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    first = TRUE;
    if (pinfo->ptype == PT_TCP) {       /* are we running on top of TCP */
        tcp_dissect_pdus(tvb, pinfo, tree,
                reassemble_over_tcp,    /* Do we try to reassemble      */
                16,                     /* Length of fixed header       */
                get_smpp_pdu_len,       /* Function returning PDU len   */
                dissect_smpp_pdu, data);      /* PDU dissector                */
    } else {                            /* no? probably X.25            */
        guint32 offset = 0;
        while (tvb_reported_length_remaining(tvb, offset) > 0) {
            guint16 pdu_len = tvb_get_ntohl(tvb, offset);
            gint pdu_real_len = tvb_length_remaining(tvb, offset);
            tvbuff_t *pdu_tvb;

            if (pdu_len < 1)
                THROW(ReportedBoundsError);

            if (pdu_real_len <= 0)
                return offset;
            if (pdu_real_len > pdu_len)
                pdu_real_len = pdu_len;
            pdu_tvb = tvb_new_subset(tvb, offset, pdu_real_len, pdu_len);
            dissect_smpp_pdu(pdu_tvb, pinfo, tree, data);
            offset += pdu_len;
            first = FALSE;
        }
    }

    return tvb_length(tvb);
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
    proto_item     *ti                 = NULL;
    proto_tree     *smpp_tree          = NULL;

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
    if (command_id & 0x80000000) {
        /* PDU is a response. */
        command_status_str = try_val_to_str(command_status, vals_command_status);
        if (command_status_str == NULL) {
                /* Check if the reserved value is in the vendor-specific range. */
                command_status_str = (command_status >= 0x400 && command_status <= 0x4FF ?
                                wmem_strdup_printf(wmem_packet_scope(), "Vendor-specific Error (0x%08X)", command_status) :
                                wmem_strdup_printf(wmem_packet_scope(), "(Reserved Error 0x%08X)", command_status));
        }
    }
    offset += 4;
    sequence_number = tvb_get_ntohl(tvb, offset);
    offset += 4;

    /*
     * Update the protocol column.
     */
    if (first == TRUE) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMPP");
    }

    /*
     * Create display subtree for the protocol
     */
    if (tree) {
        ti = proto_tree_add_item (tree, proto_smpp, tvb, 0, tvb_length(tvb), ENC_NA);
        smpp_tree = proto_item_add_subtree (ti, ett_smpp);
    }

    /*
     * Cycle over the encapsulated PDUs
     */
    {
        tvbuff_t *pdu_tvb;

        /*
         * Make entries in the Info column on the summary display
         */
        if (first == TRUE) {
            /*
                * First PDU - We already computed the fixed header
                */
            col_add_fstr(pinfo->cinfo, COL_INFO, "SMPP %s", command_str);
            first = FALSE;
        } else {
            /*
                * Subsequent PDUs
                */
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", command_str);
        }
        /*
            * Display command status of responses in Info column
            */
        if (command_id & 0x80000000) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": \"%s\"",
                    command_status_str);
        }

        /*
         * Create a tvb for the current PDU.
         * Physical length: at most command_length
         * Reported length: command_length
         */
        if (tvb_length_remaining(tvb, offset - 16 + command_length) > 0) {
            pdu_tvb = tvb_new_subset(tvb, offset - 16,
                    command_length,     /* Physical length */
                    command_length);    /* Length reported by the protocol */
        } else {
            pdu_tvb = tvb_new_subset(tvb, offset - 16,
                    tvb_length_remaining(tvb, offset - 16),/* Physical length */
                    command_length);    /* Length reported by the protocol */
        }

        /*
         * Dissect the PDU
         *
         * If "tree" is NULL, Wireshark is only interested in creation
         * of conversations, reassembly and subdissection but not in
         * the detailed protocol tree.
         * In the interest of speed, skip the generation of protocol tree
         * items when "tree" is NULL.
         *
         * The only PDU which requires subdissection currently is the
         * sm_submit PDU (command ID = 0x00000004).
         */
        if (tree || (command_id == 4))
        {
            /*
             * Create display subtree for the PDU
             */
            if (tree) {
                proto_tree_add_uint(smpp_tree, hf_smpp_command_length,
                        pdu_tvb, 0, 4, command_length);
                proto_tree_add_uint(smpp_tree, hf_smpp_command_id,
                        pdu_tvb, 4, 4, command_id);
                proto_item_append_text(ti, ", Command: %s", command_str);

                /*
                 * Status is only meaningful with responses
                 */
                if (command_id & 0x80000000) {
                    proto_tree_add_uint(smpp_tree, hf_smpp_command_status,
                            pdu_tvb, 8, 4, command_status);
                    proto_item_append_text (ti, ", Status: \"%s\"",
                            command_status_str);
                }
                proto_tree_add_uint(smpp_tree, hf_smpp_sequence_number,
                        pdu_tvb, 12, 4, sequence_number);
                proto_item_append_text(ti, ", Seq: %u, Len: %u",
                        sequence_number, command_length);
            }

            /*
             * End of fixed header.
             * Don't dissect variable part if it is shortened.
             *
             * FIXME - We then do not report a Short Frame or Malformed Packet
             */
            if (command_length <= tvb_reported_length(pdu_tvb))
            {
                tvbuff_t *tmp_tvb = tvb_new_subset(pdu_tvb, 16,
                        -1, command_length - 16);
                if (command_id & 0x80000000)
                {
                    switch (command_id & 0x7FFFFFFF) {
                        /*
                         * All of these only have a fixed header
                         */
                        case   0:       /* Generic nack         */
                        case   6:       /* Unbind resp          */
                        case   7:       /* Replace SM resp      */
                        case   8:       /* Cancel SM resp       */
                        case  21:       /* Enquire link resp    */
                        case 275:       /* Cancel Broadcast SM resp */
                            break;
                        /* FIXME: The body of the response PDUs are only
                         * only dissected if the request was successful.
                         * However, in SMPP 5.0 some responses might
                         * contain body to provide additional information
                         * about the error. This needs to be handled.
                         */
                        case   1:
                            if (!command_status)
                                bind_receiver_resp(smpp_tree, tmp_tvb);
                            break;
                        case   2:
                            if (!command_status)
                                bind_transmitter_resp(smpp_tree, tmp_tvb);
                            break;
                        case   3:
                            if (!command_status)
                                query_sm_resp(smpp_tree, tmp_tvb);
                            break;
                        case   4:
                            if (!command_status)
                                submit_sm_resp(smpp_tree, tmp_tvb);
                            break;
                        case   5:
                            if (!command_status)
                                deliver_sm_resp(smpp_tree, tmp_tvb);
                            break;
                        case   9:
                            if (!command_status)
                                bind_transceiver_resp(smpp_tree, tmp_tvb);
                            break;
                        case  33:
                            if (!command_status)
                                submit_multi_resp(smpp_tree, tmp_tvb);
                            break;
                        case 259:
                            if (!command_status)
                                data_sm_resp(smpp_tree, tmp_tvb);
                            break;
                        case 273:
                            if (!command_status)
                                broadcast_sm_resp(smpp_tree, tmp_tvb);
                            break;
                        case 274:
                            if (!command_status)
                                query_broadcast_sm_resp(smpp_tree, tmp_tvb);
                            break;
                        case 16777217:
                            if (!command_status)
                                huawei_auth_acc_resp(smpp_tree, tmp_tvb);
                            break;
                         case 16777218:
                            if (!command_status)
                                huawei_sm_result_notify_resp(smpp_tree, tmp_tvb);
                            break;
                        default:
                            break;
                    } /* switch (command_id & 0x7FFFFFFF) */
                }
                else
                {
                    switch (command_id) {
                        case   1:
                            bind_receiver(smpp_tree, tmp_tvb);
                            break;
                        case   2:
                            bind_transmitter(smpp_tree, tmp_tvb);
                            break;
                        case   3:
                            query_sm(smpp_tree, tmp_tvb);
                            break;
                        case   4:
                            submit_sm(smpp_tree, tmp_tvb, pinfo, tree);
                            break;
                        case   5:
                            deliver_sm(smpp_tree, tmp_tvb, pinfo, tree);
                            break;
                        case   6:       /* Unbind               */
                        case  21:       /* Enquire link         */
                            break;
                        case   7:
                            replace_sm(smpp_tree, tmp_tvb);
                            break;
                        case   8:
                            cancel_sm(smpp_tree, tmp_tvb);
                            break;
                        case   9:
                            bind_transceiver(smpp_tree, tmp_tvb);
                            break;
                        case  11:
                            outbind(smpp_tree, tmp_tvb);
                            break;
                        case  33:
                            submit_multi(smpp_tree, tmp_tvb);
                            break;
                        case  258:
                            alert_notification(smpp_tree, tmp_tvb);
                            break;
                        case  259:
                            data_sm(smpp_tree, tmp_tvb);
                            break;
                        case 273:
                            broadcast_sm(smpp_tree, tmp_tvb);
                            break;
                        case 274:
                            query_broadcast_sm(smpp_tree, tmp_tvb);
                            break;
                        case 275:
                            cancel_broadcast_sm(smpp_tree, tmp_tvb);
                            break;
                        case  16777217:
                            huawei_auth_acc(smpp_tree, tmp_tvb);
                            break;
                        case  16777218:
                            huawei_sm_result_notify(smpp_tree, tmp_tvb);
                            break;
                        default:
                            break;
                    } /* switch (command_id) */
                } /* if (command_id & 0x80000000) */

            } /* if (command_length <= tvb_reported_length(pdu_tvb)) */
            /*offset += command_length;*/
        } /* if (tree || (command_id == 4)) */

        /* Queue packet for Tap */
        tap_rec = wmem_new0(wmem_packet_scope(), smpp_tap_rec_t);
        tap_rec->command_id = command_id;
        tap_rec->command_status = command_status;
        tap_queue_packet(smpp_tap, pinfo, tap_rec);

        first = FALSE;
    }

    return tvb_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_smpp(void)
{
    module_t *smpp_module; /* Preferences for SMPP */

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
                FT_UINT32, BASE_HEX, VALS(vals_command_status), 0x00,
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
                FT_STRING, BASE_NONE, NULL, 0x00,
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
                FT_UINT8, BASE_HEX, NULL, 0x00,
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
            {   "Message", "smpp.message",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "The actual message or data.",
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
                FT_UINT32, BASE_HEX, VALS(vals_command_status), 0x00,
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
                FT_BYTES, BASE_NONE, NULL, 0x00,
                "A supplied optional parameter specific to an SMSC-vendor.",
                HFILL
            }
        },
        {   &hf_smpp_reserved_op,
            {   "Value", "smpp.reserved_op",
                FT_BYTES, BASE_NONE, NULL, 0x00,
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
                FT_STRING, BASE_NONE, NULL, 0x00,
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
                FT_NONE, BASE_NONE, NULL, 0x00,
                "Short message user data.",
                HFILL
            }
        },
        {   &hf_smpp_alert_on_message_delivery_null,
            {   "Alert on delivery", "smpp.alert_on_message_delivery",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "Instructs the handset to alert user on message delivery.",
                HFILL
            }
        },
        {   &hf_smpp_alert_on_message_delivery,
            {   "Alert on delivery", "smpp.alert_on_message_delivery",
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
        {       &hf_smpp_dcs,
                { "SMPP Data Coding Scheme", "smpp.dcs",
                FT_UINT8, BASE_HEX, VALS(vals_data_coding), 0x00,
                "Data Coding Scheme according to SMPP.",
                HFILL
            }
        },
        {       &hf_smpp_dcs_sms_coding_group,
                {       "DCS Coding Group for SMS", "smpp.dcs.sms_coding_group",
                        FT_UINT8, BASE_HEX, VALS(vals_dcs_sms_coding_group), 0xF0,
                        "Data Coding Scheme coding group for GSM Short Message Service.",
                        HFILL
                }
        },
        {       &hf_smpp_dcs_text_compression,
                {       "DCS Text compression", "smpp.dcs.text_compression",
                        FT_BOOLEAN, 8, TFS(&tfs_dcs_text_compression), 0x20,
                        "Indicates if text compression is used.", HFILL
                }
        },
        {       &hf_smpp_dcs_class_present,
                {       "DCS Class present", "smpp.dcs.class_present",
                        FT_BOOLEAN, 8, TFS(&tfs_dcs_class_present), 0x10,
                        "Indicates if the message class is present (defined).", HFILL
                }
        },
        {       &hf_smpp_dcs_charset,
                {       "DCS Character set", "smpp.dcs.charset",
                        FT_UINT8, BASE_HEX, VALS(vals_dcs_charset), 0x0C,
                        "Specifies the character set used in the message.", HFILL
                }
        },
        {       &hf_smpp_dcs_class,
                {       "DCS Message class", "smpp.dcs.class",
                        FT_UINT8, BASE_HEX, VALS(vals_dcs_class), 0x03,
                        "Specifies the message class.", HFILL
                }
        },
        {       &hf_smpp_dcs_cbs_coding_group,
                {       "DCS Coding Group for CBS", "smpp.dcs.cbs_coding_group",
                        FT_UINT8, BASE_HEX, VALS(vals_dcs_cbs_coding_group), 0xF0,
                        "Data Coding Scheme coding group for GSM Cell Broadcast Service.",
                        HFILL
                }
        },
        {       &hf_smpp_dcs_cbs_language,
                {       "DCS CBS Message language", "smpp.dcs.cbs_language",
                        FT_UINT8, BASE_HEX, VALS(vals_dcs_cbs_language), 0x3F,
                        "Language of the GSM Cell Broadcast Service message.", HFILL
                }
        },
        {       &hf_smpp_dcs_cbs_class,
                {       "DCS CBS Message class", "smpp.dcs.cbs_class",
                        FT_UINT8, BASE_HEX, VALS(vals_dcs_cbs_class), 0x03,
                        "Specifies the message class for GSM Cell Broadcast Service, for the Data coding / message handling code group.", HFILL
                }
        },
        {       &hf_smpp_dcs_wap_charset,
                {       "DCS Message coding", "smpp.dcs.wap_coding",
                        FT_UINT8, BASE_HEX, VALS(vals_dcs_wap_charset), 0x0C,
                        "Specifies the used message encoding, as specified by the WAP Forum (WAP over GSM USSD).", HFILL
                }
        },
        {       &hf_smpp_dcs_wap_class,
                {       "DCS CBS Message class", "smpp.dcs.wap_class",
                        FT_UINT8, BASE_HEX, VALS(vals_dcs_wap_class), 0x03,
                        "Specifies the message class for GSM Cell Broadcast Service, as specified by the WAP Forum (WAP over GSM USSD).", HFILL
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
                        FT_UINT32, BASE_HEX, VALS(vals_command_status), 0x00,
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
        {    &hf_huawei_smpp_version,
                {       "Version of SMPP+", "smpp.smppplus_version",
                        FT_UINT8, BASE_HEX, NULL, 0x00,
                        "Indicates the SMPP+ version", HFILL
                }
        },
        {        &hf_huawei_smpp_smsc_addr,
                {       "SMPP+: GT of SMSC", "smpp.smsc_addr",
                        FT_STRING, BASE_NONE, NULL, 0x00,
                        "SMPP+: GT of SMSC", HFILL
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
                        "SMPP+: GT of MSC", HFILL
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
    DebugLog(("Registering SMPP dissector\n"));
    /* Register the protocol name and description */
    proto_smpp = proto_register_protocol("Short Message Peer to Peer",
                                         "SMPP", "smpp");

    /* Required function calls to register header fields and subtrees used */
    proto_register_field_array(proto_smpp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    new_register_dissector("smpp", dissect_smpp, proto_smpp);

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
}

void
proto_reg_handoff_smpp(void)
{
    dissector_handle_t smpp_handle;

    /*
     * SMPP can be spoken on any port under TCP or X.25
     * ...how *do* we do that under X.25?
     *
     * We can register the heuristic SMPP dissector with X.25, for one
     * thing.  We don't currently have any mechanism to allow the user
     * to specify that a given X.25 circuit is to be dissected as SMPP,
     * however.
     */
    smpp_handle = find_dissector("smpp");
    dissector_add_for_decode_as("tcp.port", smpp_handle);
    heur_dissector_add("tcp", dissect_smpp_heur, proto_smpp);
    heur_dissector_add("x.25", dissect_smpp_heur, proto_smpp);

    /* Required for call_dissector() */
    DebugLog(("Finding gsm_sms_ud subdissector\n"));
    gsm_sms_handle = find_dissector("gsm_sms_ud");
    DISSECTOR_ASSERT(gsm_sms_handle);

    /* Tapping setup */
    stats_tree_register_with_group("smpp","smpp_commands", "SM_PP Operations", 0,
                                   smpp_stats_tree_per_packet, smpp_stats_tree_init,
                                   NULL, REGISTER_STAT_GROUP_TELEPHONY);
}
