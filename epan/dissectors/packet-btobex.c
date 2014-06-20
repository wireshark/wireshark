/* packet-btobex.c
 * Routines for Bluetooth OBEX dissection
 *
 * Copyright 2010, Allan M. Madsen
 * Copyright 2013, Michal Labedzki for Tieto Corporation
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
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/tap.h>
#include <epan/expert.h>
#include <epan/wmem/wmem.h>

#include "packet-bluetooth-hci.h"
#include "packet-btrfcomm.h"
#include "packet-btl2cap.h"
#include "packet-btsdp.h"

/* Initialize the protocol and registered fields */
static int proto_btobex = -1;
static int hf_opcode = -1;
static int hf_response_code = -1;
static int hf_final_flag = -1;
static int hf_length = -1;
static int hf_version = -1;
static int hf_flags = -1;
static int hf_constants = -1;
static int hf_max_pkt_len = -1;
static int hf_set_path_flags_0 = -1;
static int hf_set_path_flags_1 = -1;
static int hf_headers = -1;
static int hf_header = -1;
static int hf_hdr_id = -1;
static int hf_hdr_length = -1;
static int hf_hdr_val_unicode = -1;
static int hf_hdr_val_byte_seq = -1;
static int hf_hdr_val_byte = -1;
static int hf_hdr_val_long = -1;
static int hf_authentication_challenge_tag = -1;
static int hf_authentication_response_tag = -1;
static int hf_authentication_key = -1;
static int hf_authentication_result_key = -1;
static int hf_authentication_user_id = -1;
static int hf_authentication_length = -1;
static int hf_authentication_info_charset = -1;
static int hf_authentication_info = -1;
static int hf_authentication_option_reserved = -1;
static int hf_authentication_option_user_id = -1;
static int hf_authentication_option_read_only = -1;
static int hf_application_parameter = -1;
static int hf_application_parameter_id = -1;
static int hf_application_parameter_length = -1;
static int hf_application_parameter_data = -1;
static int hf_bpp_application_parameter_id = -1;
static int hf_bpp_application_parameter_data_offset = -1;
static int hf_bpp_application_parameter_data_count = -1;
static int hf_bpp_application_parameter_data_job_id = -1;
static int hf_bpp_application_parameter_data_file_size = -1;
static int hf_bip_application_parameter_id = -1;
static int hf_bip_application_parameter_data_number_of_returned_handles = -1;
static int hf_bip_application_parameter_data_list_start_offset = -1;
static int hf_bip_application_parameter_data_latest_captured_images = -1;
static int hf_bip_application_parameter_data_partial_file_length = -1;
static int hf_bip_application_parameter_data_partial_file_start_offset = -1;
static int hf_bip_application_parameter_data_total_file_size = -1;
static int hf_bip_application_parameter_data_end_flag = -1;
static int hf_bip_application_parameter_data_remote_display = -1;
static int hf_bip_application_parameter_data_service_id = -1;
static int hf_bip_application_parameter_data_store_flag = -1;
static int hf_pbap_application_parameter_id = -1;
static int hf_pbap_application_parameter_data_order = -1;
static int hf_pbap_application_parameter_data_search_value = -1;
static int hf_pbap_application_parameter_data_search_attribute = -1;
static int hf_pbap_application_parameter_data_max_list_count = -1;
static int hf_pbap_application_parameter_data_list_start_offset = -1;
static int hf_pbap_application_parameter_data_filter_version = -1;
static int hf_pbap_application_parameter_data_filter_fn = -1;
static int hf_pbap_application_parameter_data_filter_n = -1;
static int hf_pbap_application_parameter_data_filter_photo = -1;
static int hf_pbap_application_parameter_data_filter_birthday = -1;
static int hf_pbap_application_parameter_data_filter_adr = -1;
static int hf_pbap_application_parameter_data_filter_label = -1;
static int hf_pbap_application_parameter_data_filter_tel = -1;
static int hf_pbap_application_parameter_data_filter_email = -1;
static int hf_pbap_application_parameter_data_filter_mailer = -1;
static int hf_pbap_application_parameter_data_filter_time_zone = -1;
static int hf_pbap_application_parameter_data_filter_geographic_position = -1;
static int hf_pbap_application_parameter_data_filter_title = -1;
static int hf_pbap_application_parameter_data_filter_role = -1;
static int hf_pbap_application_parameter_data_filter_logo = -1;
static int hf_pbap_application_parameter_data_filter_agent = -1;
static int hf_pbap_application_parameter_data_filter_name_of_organization = -1;
static int hf_pbap_application_parameter_data_filter_comments = -1;
static int hf_pbap_application_parameter_data_filter_revision = -1;
static int hf_pbap_application_parameter_data_filter_pronunciation_of_name = -1;
static int hf_pbap_application_parameter_data_filter_url = -1;
static int hf_pbap_application_parameter_data_filter_uid = -1;
static int hf_pbap_application_parameter_data_filter_key = -1;
static int hf_pbap_application_parameter_data_filter_nickname = -1;
static int hf_pbap_application_parameter_data_filter_categories = -1;
static int hf_pbap_application_parameter_data_filter_product_id = -1;
static int hf_pbap_application_parameter_data_filter_class = -1;
static int hf_pbap_application_parameter_data_filter_sort_string = -1;
static int hf_pbap_application_parameter_data_filter_timestamp = -1;
static int hf_pbap_application_parameter_data_filter_reserved_29_31 = -1;
static int hf_pbap_application_parameter_data_filter_reserved_32_38 = -1;
static int hf_pbap_application_parameter_data_filter_proprietary_filter = -1;
static int hf_pbap_application_parameter_data_filter_reserved_for_proprietary_filter_usage = -1;
static int hf_pbap_application_parameter_data_format = -1;
static int hf_pbap_application_parameter_data_phonebook_size = -1;
static int hf_pbap_application_parameter_data_new_missed_calls = -1;
static int hf_map_application_parameter_id = -1;
static int hf_map_application_parameter_data_max_list_count = -1;
static int hf_map_application_parameter_data_start_offset = -1;
static int hf_map_application_parameter_data_filter_message_type_reserved = -1;
static int hf_map_application_parameter_data_filter_message_type_mms = -1;
static int hf_map_application_parameter_data_filter_message_type_email = -1;
static int hf_map_application_parameter_data_filter_message_type_sms_cdma = -1;
static int hf_map_application_parameter_data_filter_message_type_sms_gsm = -1;
static int hf_map_application_parameter_data_filter_period_begin = -1;
static int hf_map_application_parameter_data_filter_period_end = -1;
static int hf_map_application_parameter_data_filter_read_status_reserved_6 = -1;
static int hf_map_application_parameter_data_filter_read_status_get_read = -1;
static int hf_map_application_parameter_data_filter_read_status_get_unread = -1;
static int hf_map_application_parameter_data_filter_recipient = -1;
static int hf_map_application_parameter_data_filter_originator = -1;
static int hf_map_application_parameter_data_filter_priority_reserved_6 = -1;
static int hf_map_application_parameter_data_filter_priority_get_high = -1;
static int hf_map_application_parameter_data_filter_priority_non_high = -1;
static int hf_map_application_parameter_data_reserved_7 = -1;
static int hf_map_application_parameter_data_attachment = -1;
static int hf_map_application_parameter_data_transparent = -1;
static int hf_map_application_parameter_data_retry = -1;
static int hf_map_application_parameter_data_new_message = -1;
static int hf_map_application_parameter_data_notification_status = -1;
static int hf_map_application_parameter_data_mas_instance_id = -1;
static int hf_map_application_parameter_data_parameter_mask_reserved = -1;
static int hf_map_application_parameter_data_parameter_mask_reply_to_addressing = -1;
static int hf_map_application_parameter_data_parameter_mask_protected = -1;
static int hf_map_application_parameter_data_parameter_mask_sent = -1;
static int hf_map_application_parameter_data_parameter_mask_read = -1;
static int hf_map_application_parameter_data_parameter_mask_priority = -1;
static int hf_map_application_parameter_data_parameter_mask_attachment_size = -1;
static int hf_map_application_parameter_data_parameter_mask_text = -1;
static int hf_map_application_parameter_data_parameter_mask_reception_status = -1;
static int hf_map_application_parameter_data_parameter_mask_size = -1;
static int hf_map_application_parameter_data_parameter_mask_type = -1;
static int hf_map_application_parameter_data_parameter_mask_recipient_addressing = -1;
static int hf_map_application_parameter_data_parameter_mask_recipient_name = -1;
static int hf_map_application_parameter_data_parameter_mask_sender_addressing = -1;
static int hf_map_application_parameter_data_parameter_mask_sender_name = -1;
static int hf_map_application_parameter_data_parameter_mask_datetime = -1;
static int hf_map_application_parameter_data_parameter_mask_subject = -1;
static int hf_map_application_parameter_data_folder_listing_size = -1;
static int hf_map_application_parameter_data_messages_listing_size = -1;
static int hf_map_application_parameter_data_subject_length = -1;
static int hf_map_application_parameter_data_charset = -1;
static int hf_map_application_parameter_data_fraction_request = -1;
static int hf_map_application_parameter_data_fraction_deliver = -1;
static int hf_map_application_parameter_data_status_indicator = -1;
static int hf_map_application_parameter_data_status_value = -1;
static int hf_map_application_parameter_data_mse_time = -1;
static int hf_profile = -1;

static expert_field ei_unexpected_data = EI_INIT;


/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int hf_btobex_fragments = -1;
static int hf_btobex_fragment = -1;
static int hf_btobex_fragment_overlap = -1;
static int hf_btobex_fragment_overlap_conflict = -1;
static int hf_btobex_fragment_multiple_tails = -1;
static int hf_btobex_fragment_too_long_fragment = -1;
static int hf_btobex_fragment_error = -1;
static int hf_btobex_fragment_count = -1;
static int hf_btobex_reassembled_in = -1;
static int hf_btobex_reassembled_length = -1;

static gint ett_btobex_fragment = -1;
static gint ett_btobex_fragments = -1;

static expert_field ei_application_parameter_length_bad = EI_INIT;

static dissector_handle_t btobex_handle;

static reassembly_table btobex_reassembly_table;

static const fragment_items btobex_frag_items = {
    &ett_btobex_fragment,
    &ett_btobex_fragments,
    &hf_btobex_fragments,
    &hf_btobex_fragment,
    &hf_btobex_fragment_overlap,
    &hf_btobex_fragment_overlap_conflict,
    &hf_btobex_fragment_multiple_tails,
    &hf_btobex_fragment_too_long_fragment,
    &hf_btobex_fragment_error,
    &hf_btobex_fragment_count,
    &hf_btobex_reassembled_in,
    &hf_btobex_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

/* Initialize the subtree pointers */
static gint ett_btobex = -1;
static gint ett_btobex_hdrs = -1;
static gint ett_btobex_hdr = -1;
static gint ett_btobex_application_parameters = -1;

static wmem_tree_t *obex_profile = NULL;
static wmem_tree_t *obex_last_opcode = NULL;

static dissector_handle_t xml_handle;
static dissector_handle_t data_handle;

typedef struct _ext_value_string {
    guint8       value[16];
    gint         length;
    const gchar *strptr;
} ext_value_string;

typedef struct _obex_profile_data_t {
    guint32 interface_id;
    guint32 adapter_id;
    guint16 chandle;
    guint8  channel;
    gint    profile;
} obex_profile_data_t;

typedef struct _obex_last_opcode_data_t {
    guint32 interface_id;
    guint32 adapter_id;
    guint16 chandle;
    guint8  channel;
    gint    direction;
    gint    code;
} obex_last_opcode_data_t;

#define PROFILE_UNKNOWN  0
#define PROFILE_OPP      1
#define PROFILE_FTP      2
#define PROFILE_SYNCML   3
#define PROFILE_PBAP     4
#define PROFILE_MAP      5
#define PROFILE_BIP      6
#define PROFILE_BPP      7
#define PROFILE_SYNC     8

static const value_string profile_vals[] = {
    { PROFILE_UNKNOWN, "Unknown" },
    { PROFILE_OPP,     "OPP" },
    { PROFILE_FTP,     "FTP" },
    { PROFILE_SYNCML,  "SyncML" },
    { PROFILE_PBAP,    "PBAP" },
    { PROFILE_MAP,     "MAP" },
    { PROFILE_BIP,     "BIP" },
    { PROFILE_BPP,     "BPP" },
    { PROFILE_SYNC,    "SYNC" },
    { 0,               NULL }
};
static value_string_ext(profile_vals_ext) = VALUE_STRING_EXT_INIT(profile_vals);


static const ext_value_string target_vals[] = {
    {   { 0xF9, 0xEC, 0x7B, 0xC4, 0x95, 0x3C, 0x11, 0xD2, 0x98, 0x4E, 0x52, 0x54, 0x00, 0xDC, 0x9E, 0x09 }, 16, "Folder Browsing" },
    {   { 0x79, 0x61, 0x35, 0xf0, 0xf0, 0xc5, 0x11, 0xd8, 0x09, 0x66, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 }, 16, "Phone Book Access Profile" },
    {   { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x02, 0xEE, 0x00, 0x00, 0x02 }, 16, "SyncML" },
    {   { 0xE3, 0x3D, 0x95, 0x45, 0x83, 0x74, 0x4A, 0xD7, 0x9E, 0xC5, 0xC1, 0x6B, 0xE3, 0x1E, 0xDE, 0x8E }, 16, "Basic Imaging Profile - Push" },
    {   { 0x8E, 0xE9, 0xB3, 0xD0, 0x46, 0x08, 0x11, 0xD5, 0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E }, 16, "Basic Imaging Profile - Pull" },
    {   { 0x92, 0x35, 0x33, 0x50, 0x46, 0x08, 0x11, 0xD5, 0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E }, 16, "Basic Imaging Profile - Advanced Printing" },
    {   { 0x94, 0x01, 0x26, 0xC0, 0x46, 0x08, 0x11, 0xD5, 0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E }, 16, "Basic Imaging Profile - Automativ Archive" },
    {   { 0x94, 0x7E, 0x74, 0x20, 0x46, 0x08, 0x11, 0xD5, 0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E }, 16, "Basic Imaging Profile - Remote Camera" },
    {   { 0x94, 0xC7, 0xCD, 0x20, 0x46, 0x08, 0x11, 0xD5, 0x84, 0x1A, 0x00, 0x02, 0xA5, 0x32, 0x5B, 0x4E }, 16, "Basic Imaging Profile - Remote Display" },
    {   { 0x8E, 0x61, 0xF9, 0x5D, 0x1A, 0x79, 0x11, 0xD4, 0x8E, 0xA4, 0x00, 0x80, 0x5F, 0x9B, 0x98, 0x34 }, 16, "Basic Imaging Profile- Referenced Objects" },
    {   { 0x8E, 0x61, 0xF9, 0x5D, 0x1A, 0x79, 0x11, 0xD4, 0x8E, 0xA4, 0x00, 0x80, 0x5F, 0x9B, 0x98, 0x34 }, 16, "Basic Imaging Profile - Archived Objects" },
    {   { 0xbb, 0x58, 0x2b, 0x40, 0x42, 0x0c, 0x11, 0xdb, 0xb0, 0xde, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 }, 16, "Message Access Profile - Message Access Service" },
    {   { 0xbb, 0x58, 0x2b, 0x41, 0x42, 0x0c, 0x11, 0xdb, 0xb0, 0xde, 0x08, 0x00, 0x20, 0x0c, 0x9a, 0x66 }, 16, "Message Access Profile - Message Notification Service" },
    {   { 0x00, 0x00, 0x11, 0x18, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }, 16, "Basic Printing Profile - Direct Printing Service" },
    {   { 0x00, 0x00, 0x11, 0x19, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }, 16, "Basic Printing Profile - Reference Printing Service" },
    {   { 0x00, 0x00, 0x11, 0x20, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }, 16, "Basic Printing Profile - Direct Printing Referenced Objects Service" },
    {   { 0x00, 0x00, 0x11, 0x21, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }, 16, "Basic Printing Profile - Reflected UI" },
    {   { 0x00, 0x00, 0x11, 0x22, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }, 16, "Basic Printing Profile - Basic Printing" },
    {   { 0x00, 0x00, 0x11, 0x23, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5F, 0x9B, 0x34, 0xFB }, 16, "Basic Printing Profile - Printing Status" },
    {   { "IRMC-SYNC" }, 9, "Synchronization Profile" },
    {   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, 0, NULL },
};

/* This table must map tagets from "target_vals" to profile */
static const gint target_to_profile[] = {
    PROFILE_FTP,
    PROFILE_PBAP,
    PROFILE_SYNCML,
    PROFILE_BIP,
    PROFILE_BIP,
    PROFILE_BIP,
    PROFILE_BIP,
    PROFILE_BIP,
    PROFILE_BIP,
    PROFILE_BIP,
    PROFILE_BIP,
    PROFILE_MAP,
    PROFILE_MAP,
    PROFILE_BPP,
    PROFILE_BPP,
    PROFILE_BPP,
    PROFILE_BPP,
    PROFILE_BPP,
    PROFILE_BPP,
    PROFILE_SYNC
};

static const value_string version_vals[] = {
    { 0x10, "1.0" },
    { 0x11, "1.1" },
    { 0x12, "1.2" },
    { 0x13, "1.3" },
    { 0x20, "2.0" },
    { 0x21, "2.1" },
    { 0,      NULL }
};

#define BTOBEX_CODE_VALS_CONNECT    0x00
#define BTOBEX_CODE_VALS_DISCONNECT 0x01
#define BTOBEX_CODE_VALS_PUT        0x02
#define BTOBEX_CODE_VALS_GET        0x03
#define BTOBEX_CODE_VALS_SET_PATH   0x05
#define BTOBEX_CODE_VALS_CONTINUE   0x10
#define BTOBEX_CODE_VALS_ABORT      0x7F
#define BTOBEX_CODE_VALS_MASK       0x7F

static const value_string code_vals[] = {
    { BTOBEX_CODE_VALS_CONNECT, "Connect" },
    { BTOBEX_CODE_VALS_DISCONNECT, "Disconnect" },
    { BTOBEX_CODE_VALS_PUT, "Put" },
    { BTOBEX_CODE_VALS_GET, "Get"},
    { BTOBEX_CODE_VALS_SET_PATH, "Set Path" },
    { BTOBEX_CODE_VALS_CONTINUE, "Continue" },
    { 0x20, "Success" },
    { 0x21, "Created" },
    { 0x22, "Accepted" },
    { 0x23, "Non-Authoritative Information" },
    { 0x24, "No Content" },
    { 0x25, "Reset Content" },
    { 0x26, "Partial Content" },
    { 0x30, "Multiple Choices" },
    { 0x31, "Moved Permanently" },
    { 0x32, "Moved Temporarily" },
    { 0x33, "See Other" },
    { 0x34, "Not Modified" },
    { 0x35, "Use Proxy" },
    { 0x40, "Bad Request" },
    { 0x41, "Unauthorised" },
    { 0x42, "Payment Required" },
    { 0x43, "Forbidden" },
    { 0x44, "Not Found" },
    { 0x45, "Method Not Allowed" },
    { 0x46, "Not Acceptable" },
    { 0x47, "Proxy Authentication Required" },
    { 0x48, "Request Timeout" },
    { 0x49, "Conflict" },
    { 0x4a, "Gone" },
    { 0x4b, "Length Required" },
    { 0x4c, "Precondition Failed" },
    { 0x4d, "Requested Entity Too Large" },
    { 0x4e, "Requested URL Too Large" },
    { 0x4f, "Unsupported Media Type" },
    { 0x50, "Internal Server Error" },
    { 0x51, "Not Implemented" },
    { 0x52, "Bad Gateway" },
    { 0x53, "Service Unavailable" },
    { 0x54, "Gateway Timeout" },
    { 0x55, "HTTP Version Not Supported" },
    { 0x60, "Database Full" },
    { 0x61, "Database Locked" },
    { BTOBEX_CODE_VALS_ABORT, "Abort" },
    { 0,      NULL }
};
static value_string_ext(code_vals_ext) = VALUE_STRING_EXT_INIT(code_vals);

static const value_string header_id_vals[] = {
    { 0x01, "Name" },
    { 0x05, "Description" },
    { 0x30, "User Defined" },
    { 0x31, "User Defined" },
    { 0x32, "User Defined" },
    { 0x33, "User Defined" },
    { 0x34, "User Defined" },
    { 0x35, "User Defined" },
    { 0x36, "User Defined" },
    { 0x37, "User Defined" },
    { 0x38, "User Defined" },
    { 0x39, "User Defined" },
    { 0x3a, "User Defined" },
    { 0x3b, "User Defined" },
    { 0x3c, "User Defined" },
    { 0x3d, "User Defined" },
    { 0x3e, "User Defined" },
    { 0x3f, "User Defined" },
    { 0x42, "Type" },
    { 0x44, "Time (ISO8601)" },
    { 0x46, "Target" },
    { 0x47, "HTTP" },
    { 0x48, "Body" },
    { 0x49, "End Of Body" },
    { 0x4a, "Who" },
    { 0x4c, "Application Parameters" },
    { 0x4d, "Authentication Challenge" },
    { 0x4e, "Authentication Response" },
    { 0x4f, "Object Class" },
    { 0xc0, "Count" },
    { 0xc3, "Length" },
    { 0xc4, "Time" },
    { 0xcb, "Connection Id" },
    { 0,      NULL }
};
static value_string_ext header_id_vals_ext = VALUE_STRING_EXT_INIT(header_id_vals);

static const value_string map_application_parameters_vals[] = {
    { 0x01, "Max List Count" },
    { 0x02, "Start Offset" },
    { 0x03, "Filter Message Type" },
    { 0x04, "Filter Period Begin" },
    { 0x05, "End Filter PeriodEnd" },
    { 0x06, "Filter Read Status" },
    { 0x07, "Filter Recipient" },
    { 0x08, "Filter Originator" },
    { 0x09, "Filter Priority" },
    { 0x0A, "Attachment" },
    { 0x0B, "Transparent" },
    { 0x0C, "Retry" },
    { 0x0D, "New Message" },
    { 0x0E, "Notification Status" },
    { 0x0F, "MAS Instance ID" },
    { 0x10, "Parameter Mask" },
    { 0x11, "Folder Listing Size" },
    { 0x12, "Messages Listing Size" },
    { 0x13, "Subject Length" },
    { 0x14, "Charset" },
    { 0x15, "Fraction Request" },
    { 0x16, "Fraction Deliver" },
    { 0x17, "Status Indicator" },
    { 0x18, "Status Value" },
    { 0x19, "MSE Time" },
    { 0,    NULL }
};

static const value_string pbap_application_parameters_vals[] = {
    { 0x01, "Order" },
    { 0x02, "Search Value" },
    { 0x03, "Search Attribute" },
    { 0x04, "Max List Count" },
    { 0x05, "List Start Offset" },
    { 0x06, "Filter" },
    { 0x07, "Format" },
    { 0x08, "Phonebook Size" },
    { 0x09, "New Missed Calls" },
    { 0,    NULL }
};

static const value_string bpp_application_parameters_vals[] = {
    { 0x01, "Offset" },
    { 0x02, "Count" },
    { 0x03, "Job ID" },
    { 0x04, "File Size" },
    { 0,    NULL }
};

static const value_string bip_application_parameters_vals[] = {
    { 0x01, "Number of Returned Handles" },
    { 0x02, "List Start Offset" },
    { 0x03, "Latest Captures Images" },
    { 0x04, "Partial File Length" },
    { 0x05, "Partial File Start Offset" },
    { 0x06, "Total File Size" },
    { 0x07, "End Flag" },
    { 0x08, "Remote Display" },
    { 0x09, "Service ID" },
    { 0x0A, "Store Flag" },
    { 0,    NULL }
};

static const value_string bip_remote_display_vals[] = {
    { 0x01, "Next Image" },
    { 0x02, "Previous Image" },
    { 0x03, "Select Image" },
    { 0x04, "Current Image" },
    { 0,    NULL }
};

static const value_string pbap_order_vals[] = {
    { 0x00, "Indexed" },
    { 0x01, "Alphanumeric" },
    { 0x02, "Phonetic" },
    { 0,    NULL }
};

static const value_string pbap_format_vals[] = {
    { 0x00, "2.1" },
    { 0x01, "3.0" },
    { 0,    NULL }
};

static const value_string pbap_search_attribute_vals[] = {
    { 0x00, "Name" },
    { 0x01, "Number" },
    { 0x02, "Sound" },
    { 0,    NULL }
};

static const value_string map_charset_vals[] = {
    { 0x00, "Native" },
    { 0x01, "UTF-8" },
    { 0,    NULL }
};

static const value_string map_fraction_request_vals[] = {
    { 0x00, "First" },
    { 0x01, "Next" },
    { 0,    NULL }
};

static const value_string map_fraction_deliver_vals[] = {
    { 0x00, "More" },
    { 0x01, "Last" },
    { 0,    NULL }
};

static const value_string map_status_indicator_vals[] = {
    { 0x00, "Read Status" },
    { 0x01, "Deleted Status" },
    { 0,    NULL }
};

static const value_string authentication_challenge_tag_vals[] = {
    { 0x00, "Key" },
    { 0x01, "Options" },
    { 0x02, "Info" },
    { 0,    NULL }
};

static const value_string authentication_response_tag_vals[] = {
    { 0x00, "Result Key" },
    { 0x01, "User ID" },
    { 0x02, "Key" },
    { 0,    NULL }
};

static const value_string info_charset_vals[] = {
    { 0x00, "ASCII" },
    { 0xFF, "Unicode" },
    { 0,    NULL }
};

static value_string_ext map_application_parameters_vals_ext = VALUE_STRING_EXT_INIT(map_application_parameters_vals);
static value_string_ext pbap_application_parameters_vals_ext = VALUE_STRING_EXT_INIT(pbap_application_parameters_vals);
static value_string_ext bpp_application_parameters_vals_ext = VALUE_STRING_EXT_INIT(bpp_application_parameters_vals);
static value_string_ext bip_application_parameters_vals_ext = VALUE_STRING_EXT_INIT(bip_application_parameters_vals);

void proto_register_btobex(void);
void proto_reg_handoff_btobex(void);

static void
defragment_init(void)
{
    reassembly_table_init(&btobex_reassembly_table,
                          &addresses_reassembly_table_functions);
}

static int
is_ascii_str(const guint8 *str, int length)
{
    int i;

    if ((length < 1) || (str[length-1] != '\0'))
        return 0;

    for(i=0; i<length-1; i++) {
        if ((str[i] < 0x20) && (str[i] != 0x0a)) /* not strict ascii */
        break;
    }

    if (i < (length-1))
        return 0;

    return 1;
}

static int
display_unicode_string(tvbuff_t *tvb, proto_tree *tree, int offset, char **data)
{
    char    *str, *p;
    int      len;
    int      charoffset;
    guint16  character;

    /* display a unicode string from the tree and return new offset */
    /*
    * Get the length of the string.
    */
    len = 0;
    while (tvb_get_ntohs(tvb, offset + len) != '\0')
        len += 2;

    len += 2;   /* count the '\0' too */

    /*
    * Allocate a buffer for the string; "len" is the length in
    * bytes, not the length in characters.
    */
    str = (char *) wmem_alloc(wmem_packet_scope(), len / 2);

    /* - this assumes the string is just ISO 8859-1 */
    charoffset = offset;
    p = str;
    while ((character = tvb_get_ntohs(tvb, charoffset)) != '\0') {
        *p++ = (char) character;
        charoffset += 2;
    }
    *p = '\0';

    if (!is_ascii_str((const guint8 *) str, len / 2)) {
        *str = '\0';
    }

    proto_tree_add_string(tree, hf_hdr_val_unicode, tvb, offset, len, str);

    if (data)
        *data = str;

    return  offset+len;
}

static gint
dissect_raw_application_parameters(tvbuff_t *tvb, proto_tree *tree, gint offset,
        gint parameters_length)
{
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    guint8       parameter_id;
    gint parameter_length;

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset,
                -1, "Parameter: 0x%02x", parameter_id);
        parameter_tree = proto_item_add_subtree(parameter_item, ett_btobex_application_parameters);

        proto_tree_add_item(parameter_tree, hf_application_parameter_id, tvb, offset,
                1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(parameter_tree, hf_application_parameter_length, tvb, offset,
                1, ENC_BIG_ENDIAN);
        parameter_length = tvb_get_guint8(tvb, offset);
        proto_item_set_len(parameter_item, parameter_length + 2);
        offset += 1;

        proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset,
                parameter_length, ENC_NA);

        parameters_length -= 2 + parameter_length;
        offset += parameter_length;
    }

    return offset;
}

static gint
dissect_bpp_application_parameters(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, gint offset, gint parameters_length)
{
    proto_item  *item;
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    guint8       parameter_id;
    gint         parameter_length;

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_length = tvb_get_guint8(tvb, offset + 1);

        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset, parameter_length + 2,
                "Parameter: %s", val_to_str_const(parameter_id,
                bpp_application_parameters_vals, "Unknown"));
        parameter_tree = proto_item_add_subtree(parameter_item, ett_btobex_application_parameters);

        proto_tree_add_item(parameter_tree, hf_bpp_application_parameter_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        item = proto_tree_add_item(parameter_tree, hf_application_parameter_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (parameter_length != 4) {
                proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
                expert_add_info_format(pinfo, item, &ei_application_parameter_length_bad,
                        "According to the specification this parameter length should be 4, but there is %i", parameter_length);
        } else switch (parameter_id) {
            case 0x01:
               proto_tree_add_item(parameter_tree, hf_bpp_application_parameter_data_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
               break;
            case 0x02:
               proto_tree_add_item(parameter_tree, hf_bpp_application_parameter_data_count, tvb, offset, 4, ENC_BIG_ENDIAN);
               break;
            case 0x03:
               proto_tree_add_item(parameter_tree, hf_bpp_application_parameter_data_job_id, tvb, offset, 4, ENC_BIG_ENDIAN);
               break;
            case 0x04:
               proto_tree_add_item(parameter_tree, hf_bpp_application_parameter_data_file_size, tvb, offset, 4, ENC_BIG_ENDIAN);
               break;
            default:
                proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
        }

        parameters_length -= 2 + parameter_length;
        offset += parameter_length;
    }

    return offset;
}

static gint
dissect_bip_application_parameters(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, gint offset, gint parameters_length)
{
    proto_item  *item;
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    gint         parameter_length;
    guint8       parameter_id;
    static gint  required_length_map[] = {0, 2, 2, 1, 4, 4, 4, 1, 1, 16, 1};

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_length = tvb_get_guint8(tvb, offset + 1);

        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset, parameter_length + 2,
                "Parameter: %s", val_to_str_const(parameter_id,
                bip_application_parameters_vals, "Unknown"));
        parameter_tree = proto_item_add_subtree(parameter_item, ett_btobex_application_parameters);

        proto_tree_add_item(parameter_tree, hf_bip_application_parameter_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        item = proto_tree_add_item(parameter_tree, hf_application_parameter_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

       if (parameter_id < (sizeof(required_length_map)/sizeof(gint)) &&
                required_length_map[parameter_id] != parameter_length) {
            proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
            expert_add_info_format(pinfo, item, &ei_application_parameter_length_bad,
                    "According to the specification this parameter length should be %i, but there is %i",
                    required_length_map[parameter_id], parameter_length);
        } else switch (parameter_id) {
            case 0x01:
                proto_tree_add_item(parameter_tree, hf_bip_application_parameter_data_number_of_returned_handles, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x02:
                proto_tree_add_item(parameter_tree, hf_bip_application_parameter_data_list_start_offset, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x03:
                proto_tree_add_item(parameter_tree, hf_bip_application_parameter_data_latest_captured_images, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x04:
                proto_tree_add_item(parameter_tree, hf_bip_application_parameter_data_partial_file_length, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x05:
                proto_tree_add_item(parameter_tree, hf_bip_application_parameter_data_partial_file_start_offset, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x06:
                proto_tree_add_item(parameter_tree, hf_bip_application_parameter_data_total_file_size, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x07:
                proto_tree_add_item(parameter_tree, hf_bip_application_parameter_data_end_flag, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x08:
                proto_tree_add_item(parameter_tree, hf_bip_application_parameter_data_remote_display, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x09:
                proto_tree_add_item(parameter_tree, hf_bip_application_parameter_data_service_id, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x0A:
                proto_tree_add_item(parameter_tree, hf_bip_application_parameter_data_store_flag, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            default:
                proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
        }

        parameters_length -= 2 + parameter_length;
        offset += parameter_length;
    }

    return offset;
}

static gint
dissect_pbap_application_parameters(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, gint offset, gint parameters_length)
{
    proto_item  *item;
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    gint         parameter_length;
    guint8       parameter_id;
    static gint  required_length_map[] = {0, 1, -1, 1, 2, 2, 8, 1, 2, 1};

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_length = tvb_get_guint8(tvb, offset + 1);

        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset, parameter_length + 2,
                "Parameter: %s", val_to_str_const(parameter_id,
                pbap_application_parameters_vals, "Unknown"));
        parameter_tree = proto_item_add_subtree(parameter_item, ett_btobex_application_parameters);

        proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        item = proto_tree_add_item(parameter_tree, hf_application_parameter_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (parameter_id < (sizeof(required_length_map)/sizeof(gint)) &&
                required_length_map[parameter_id] != -1 &&
                required_length_map[parameter_id] != parameter_length) {
            proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
            expert_add_info_format(pinfo, item, &ei_application_parameter_length_bad,
                    "According to the specification this parameter length should be %i, but there is %i",
                    required_length_map[parameter_id], parameter_length);
        } else switch (parameter_id) {
            case 0x01:
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_order, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x02:
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_search_value, tvb, offset, parameter_length, ENC_ASCII | ENC_NA);
                break;
            case 0x03:
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_search_attribute, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x04:
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_max_list_count, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x05:
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_list_start_offset, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x06:
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_reserved_32_38, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_proprietary_filter, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_reserved_for_proprietary_filter_usage, tvb, offset, 4, ENC_BIG_ENDIAN);

                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_version, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_fn, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_n, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_photo, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_birthday, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_adr, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_label, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_tel, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_email, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_mailer, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_time_zone, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_geographic_position, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_title, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_role, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_logo, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_agent, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_name_of_organization, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_comments, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_revision, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_pronunciation_of_name, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_url, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_uid, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_key, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_nickname, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_categories, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_product_id, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_class, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_sort_string, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_timestamp, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_filter_reserved_29_31, tvb, offset + 4, 4, ENC_BIG_ENDIAN);
                break;
            case 0x07:
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_format, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x08:
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_phonebook_size, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x09:
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_new_missed_calls, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            default:
                proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
        }

        parameters_length -= 2 + parameter_length;
        offset += parameter_length;
    }

    return offset;
}

static int
dissect_map_application_parameters(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, gint offset, gint parameters_length)
{
    proto_item  *item;
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    gint         parameter_length;
    guint8       parameter_id;
    static gint  required_length_map[] = {0, 2, 2, 1, -1, -1, 1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 4, 2, 2, 1, 1, 1, 1, 1, 1, -1};

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_length = tvb_get_guint8(tvb, offset + 1);

        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset, parameter_length + 2,
                "Parameter: %s", val_to_str_const(parameter_id,
                map_application_parameters_vals, "Unknown"));
        parameter_tree = proto_item_add_subtree(parameter_item, ett_btobex_application_parameters);

        proto_tree_add_item(parameter_tree, hf_map_application_parameter_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        item = proto_tree_add_item(parameter_tree, hf_application_parameter_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (parameter_id < (sizeof(required_length_map)/sizeof(gint)) &&
                required_length_map[parameter_id] != -1 &&
                required_length_map[parameter_id] != parameter_length) {
            proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
            expert_add_info_format(pinfo, item, &ei_application_parameter_length_bad,
                    "According to the specification this parameter length should be %i, but there is %i",
                    required_length_map[parameter_id], parameter_length);
        } else switch (parameter_id) {
            case 0x01:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_max_list_count, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x02:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_start_offset, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x03:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_message_type_reserved, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_message_type_mms,      tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_message_type_email,    tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_message_type_sms_cdma, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_message_type_sms_gsm,  tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x04:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_period_begin, tvb, offset, parameter_length, ENC_ASCII | ENC_NA);
                break;
            case 0x05:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_period_end, tvb, offset, parameter_length, ENC_ASCII | ENC_NA);
                break;
            case 0x06:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_read_status_reserved_6, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_read_status_get_read, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_read_status_get_unread, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x07:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_recipient, tvb, offset, parameter_length, ENC_ASCII | ENC_NA);
                break;
            case 0x08:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_originator, tvb, offset, parameter_length, ENC_ASCII | ENC_NA);
                break;
            case 0x09:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_priority_reserved_6, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_priority_get_high, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_filter_priority_non_high, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x0A:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_reserved_7, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_attachment, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x0B:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_reserved_7, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_transparent, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x0C:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_reserved_7, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_retry, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x0D:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_reserved_7, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_new_message, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x0E:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_reserved_7, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_notification_status, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x0F:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_mas_instance_id, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x10:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_reserved,             tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_reply_to_addressing,  tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_protected,            tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_sent,                 tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_read,                 tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_priority,             tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_attachment_size,      tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_text,                 tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_reception_status,     tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_size,                 tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_type,                 tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_recipient_addressing, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_recipient_name,       tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_sender_addressing,    tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_sender_name,          tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_datetime,             tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_parameter_mask_subject,              tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);

                break;
            case 0x11:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_folder_listing_size, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                 break;
            case 0x12:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_messages_listing_size, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x13:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_subject_length, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x14:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_reserved_7, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_charset, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x15:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_reserved_7, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_fraction_request, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x16:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_reserved_7, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_fraction_deliver, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x17:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_reserved_7, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_status_indicator, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x18:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_reserved_7, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_status_value, tvb, offset, required_length_map[parameter_id], ENC_BIG_ENDIAN);
                break;
            case 0x19:
                proto_tree_add_item(parameter_tree, hf_map_application_parameter_data_mse_time, tvb, offset, parameter_length, ENC_ASCII | ENC_NA);
                break;
            default:
                proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
        }

        parameters_length -= 2 + parameter_length;
        offset += parameter_length;
    }

   return offset;
}

static int
dissect_headers(proto_tree *tree, tvbuff_t *tvb, int offset, packet_info *pinfo,
        gint profile, gboolean is_obex_over_l2cap, void *data)
{
    proto_tree *hdrs_tree   = NULL;
    proto_tree *hdr_tree    = NULL;
    proto_item *hdr         = NULL;
    proto_item *handle_item;
    gint        item_length = -1;
    gint        parameters_length;
    guint8      hdr_id, i;

    if (tvb_length_remaining(tvb, offset) > 0) {
        proto_item *hdrs;
        hdrs      = proto_tree_add_item(tree, hf_headers, tvb, offset, item_length, ENC_NA);
        hdrs_tree = proto_item_add_subtree(hdrs, ett_btobex_hdrs);
    }
    else {
        return offset;
    }

    while (tvb_length_remaining(tvb, offset) > 0) {
        hdr_id = tvb_get_guint8(tvb, offset);

        switch(0xC0 & hdr_id)
        {
            case 0x00: /* null terminated unicode */
                item_length = tvb_get_ntohs(tvb, offset+1);
                break;
            case 0x40:  /* byte sequence */
                item_length = tvb_get_ntohs(tvb, offset+1);
                break;
            case 0x80:  /* 1 byte */
                item_length = 2;
                break;
            case 0xc0:  /* 4 bytes */
                item_length = 5;
                break;
        }

        hdr = proto_tree_add_none_format(hdrs_tree, hf_header, tvb, offset, item_length, "%s",
                                  val_to_str_ext_const(hdr_id, &header_id_vals_ext, "Unknown"));
        hdr_tree = proto_item_add_subtree(hdr, ett_btobex_hdr);

        proto_tree_add_item(hdr_tree, hf_hdr_id, tvb, offset, 1, ENC_BIG_ENDIAN);

        offset++;

        switch(0xC0 & hdr_id)
        {
            case 0x00: /* null terminated unicode */
                {
                    proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    offset += 2;

                    if (item_length > 3) {
                        char *str;

                        display_unicode_string(tvb, hdr_tree, offset, &str);
                        proto_item_append_text(hdr_tree, " (\"%s\")", str);

                        col_append_fstr(pinfo->cinfo, COL_INFO, " \"%s\"", str);
                        offset += item_length - 3;
                    }
                    else {
                        col_append_str(pinfo->cinfo, COL_INFO, " \"\"");
                    }
                }
                break;
            case 0x40:  /* byte sequence */
                if (hdr_id == 0x4C) { /* Application Parameters */

                    proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    parameters_length = tvb_get_ntohs(tvb, offset) - 3;
                    offset += 2;

                    switch (profile) {
                        case PROFILE_BPP:
                            offset = dissect_bpp_application_parameters(tvb, pinfo, hdr_tree, offset, parameters_length);
                            break;
                        case PROFILE_BIP:
                            offset = dissect_bip_application_parameters(tvb, pinfo, hdr_tree, offset, parameters_length);
                            break;
                        case PROFILE_PBAP:
                            offset = dissect_pbap_application_parameters(tvb, pinfo, hdr_tree, offset, parameters_length);
                            break;
                        case PROFILE_MAP:
                            offset = dissect_map_application_parameters(tvb, pinfo, hdr_tree, offset, parameters_length);
                            break;
                        default:
                            offset = dissect_raw_application_parameters(tvb, hdr_tree, offset, parameters_length);
                            break;
                    }
                    break;
                } else if (hdr_id == 0x04D) { /* Authentication Challenge */
                    guint8 tag;

                    proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    parameters_length = tvb_get_ntohs(tvb, offset) - 3;
                    offset += 2;

                    while (parameters_length) {
                        guint8       parameter_id;
                        guint8       sub_parameter_length;
                        proto_item  *parameter_item;
                        proto_tree  *parameter_tree;

                        parameter_id = tvb_get_guint8(tvb, offset);
                        sub_parameter_length = tvb_get_guint8(tvb, offset + 1);

                        parameter_item = proto_tree_add_none_format(hdr_tree, hf_application_parameter, tvb, offset,
                                2 + sub_parameter_length, "Tag: %s", val_to_str_const(parameter_id,
                                authentication_challenge_tag_vals, "Unknown"));
                        parameter_tree = proto_item_add_subtree(parameter_item, ett_btobex_application_parameters);

                        proto_tree_add_item(parameter_tree, hf_authentication_challenge_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
                        tag = tvb_get_guint8(tvb, offset);
                        offset += 1;

                        proto_tree_add_item(parameter_tree, hf_authentication_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                        offset += 1;

                        switch (tag) {
                        case 0x00:
                            proto_tree_add_item(parameter_tree, hf_authentication_key, tvb, offset, 16, ENC_NA);
                            offset += 16;
                            break;
                        case 0x01:
                            proto_tree_add_item(parameter_tree, hf_authentication_option_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(parameter_tree, hf_authentication_option_read_only, tvb, offset, 1, ENC_BIG_ENDIAN);
                            proto_tree_add_item(parameter_tree, hf_authentication_option_user_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                            break;
                        case 0x02:
                            proto_tree_add_item(parameter_tree, hf_authentication_info_charset, tvb, offset, 1, ENC_BIG_ENDIAN);
                            offset += 1;
                            proto_tree_add_item(parameter_tree, hf_authentication_info, tvb, offset, sub_parameter_length - 1, ENC_ASCII|ENC_NA);
                            offset += sub_parameter_length - 1;
                        default:
                            proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);
                            offset += sub_parameter_length;
                        }

                        parameters_length -= 2 + sub_parameter_length;
                    }
                    break;
                } else if (hdr_id == 0x04E) { /* Authentication Response */
                    guint8 tag;

                    proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                    parameters_length = tvb_get_ntohs(tvb, offset) - 3;
                    offset += 2;

                    while (parameters_length) {
                        guint8       parameter_id;
                        guint8       sub_parameter_length;
                        proto_item  *parameter_item;
                        proto_tree  *parameter_tree;

                        parameter_id = tvb_get_guint8(tvb, offset);
                        sub_parameter_length = tvb_get_guint8(tvb, offset + 1);

                        parameter_item = proto_tree_add_none_format(hdr_tree, hf_application_parameter, tvb, offset,
                                2 + sub_parameter_length, "Tag: %s", val_to_str_const(parameter_id,
                                authentication_response_tag_vals, "Unknown"));
                        parameter_tree = proto_item_add_subtree(parameter_item, ett_btobex_application_parameters);

                        proto_tree_add_item(parameter_tree, hf_authentication_response_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
                        tag = tvb_get_guint8(tvb, offset);
                        offset += 1;

                        proto_tree_add_item(parameter_tree, hf_authentication_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                        sub_parameter_length = tvb_get_guint8(tvb, offset);
                        offset += 1;

                        switch (tag) {
                        case 0x00:
                            proto_tree_add_item(parameter_tree, hf_authentication_result_key, tvb, offset, 16, ENC_NA);
                            offset += 16;
                            break;
                        case 0x01:
                            proto_tree_add_item(parameter_tree, hf_authentication_user_id, tvb, offset, sub_parameter_length, ENC_NA);
                            offset += sub_parameter_length;
                            break;
                        case 0x02:
                            proto_tree_add_item(parameter_tree, hf_authentication_key, tvb, offset, 16, ENC_NA);
                            offset += 16;
                            break;
                        default:
                            proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);
                            offset += sub_parameter_length;
                            break;
                        }


                        parameters_length -= 2 + sub_parameter_length;
                    }
                    break;
                }

                proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                handle_item = proto_tree_add_item(hdr_tree, hf_hdr_val_byte_seq, tvb, offset, item_length - 3, ENC_NA);

                if (((hdr_id == 0x46) || (hdr_id == 0x4a)) && (item_length == 19)) { /* target or who */
                    for(i=0; target_vals[i].strptr != NULL; i++) {
                        if (tvb_memeql(tvb, offset, target_vals[i].value, target_vals[i].length) == 0) {
                            proto_item_append_text(handle_item, ": %s", target_vals[i].strptr);
                            proto_item_append_text(hdr_tree, " (%s)", target_vals[i].strptr);

                            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", target_vals[i].strptr);
                            if (!pinfo->fd->flags.visited) {
                                obex_profile_data_t  *obex_profile_data;
                                guint32               interface_id;
                                guint32               adapter_id;
                                guint32               chandle;
                                guint32               channel;
                                wmem_tree_key_t       key[6];
                                guint32               k_interface_id;
                                guint32               k_adapter_id;
                                guint32               k_frame_number;
                                guint32               k_chandle;
                                guint32               k_channel;

                                if (is_obex_over_l2cap) {
                                    btl2cap_data_t      *l2cap_data;

                                    l2cap_data   = (btl2cap_data_t *) data;
                                    interface_id = l2cap_data->interface_id;
                                    adapter_id   = l2cap_data->adapter_id;
                                    chandle      = l2cap_data->chandle;
                                    channel      = l2cap_data->cid;
                                } else {
                                    btrfcomm_data_t      *rfcomm_data;

                                    rfcomm_data  = (btrfcomm_data_t *) data;
                                    interface_id = rfcomm_data->interface_id;
                                    adapter_id   = rfcomm_data->adapter_id;
                                    chandle      = rfcomm_data->chandle;
                                    channel      = rfcomm_data->dlci >> 1;
                                }

                                k_interface_id = interface_id;
                                k_adapter_id   = adapter_id;
                                k_chandle      = chandle;
                                k_channel      = channel;
                                k_frame_number = pinfo->fd->num;

                                key[0].length = 1;
                                key[0].key = &k_interface_id;
                                key[1].length = 1;
                                key[1].key = &k_adapter_id;
                                key[2].length = 1;
                                key[2].key = &k_chandle;
                                key[3].length = 1;
                                key[3].key = &k_channel;
                                key[4].length = 1;
                                key[4].key = &k_frame_number;
                                key[5].length = 0;
                                key[5].key = NULL;

                                obex_profile_data = wmem_new(wmem_file_scope(), obex_profile_data_t);
                                obex_profile_data->interface_id = interface_id;
                                obex_profile_data->adapter_id = adapter_id;
                                obex_profile_data->chandle = chandle;
                                obex_profile_data->channel = channel;
                                obex_profile_data->profile = target_to_profile[i];

                                wmem_tree_insert32_array(obex_profile, key, obex_profile_data);
                            }
                        }
                    }
                }

                if (!tvb_strneql(tvb, offset, "<?xml", 5))
                {
                    tvbuff_t* next_tvb = tvb_new_subset_remaining(tvb, offset);

                    call_dissector(xml_handle, next_tvb, pinfo, tree);
                }
                else if (is_ascii_str(tvb_get_ptr(tvb, offset,item_length - 3), item_length - 3))
                {
                    proto_item_append_text(hdr_tree, " (\"%s\")", tvb_get_string_enc(wmem_packet_scope(), tvb, offset,item_length - 3, ENC_ASCII));
                    col_append_fstr(pinfo->cinfo, COL_INFO, " \"%s\"", tvb_get_string_enc(wmem_packet_scope(), tvb, offset,item_length - 3, ENC_ASCII));
                }

                if (item_length >= 3) /* prevent infinite loops */
                    offset += item_length - 3;
                break;
            case 0x80:  /* 1 byte */
                proto_item_append_text(hdr_tree, " (%i)", tvb_get_ntohl(tvb, offset));
                proto_tree_add_item(hdr_tree, hf_hdr_val_byte, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
                break;
            case 0xc0:  /* 4 bytes */
                proto_item_append_text(hdr_tree, " (%i)", tvb_get_ntohl(tvb, offset));
                proto_tree_add_item(hdr_tree, hf_hdr_val_long, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                break;
            default:
                break;
        }
    }

    return offset;
}

static gint
dissect_btobex(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    fragment_head *frag_msg       = NULL;
    gboolean       save_fragmented, complete;
    tvbuff_t*      new_tvb        = NULL;
    tvbuff_t*      next_tvb       = NULL;
    guint32        no_of_segments = 0;
    gint           offset         = 0;
    gint           profile        = PROFILE_UNKNOWN;
    gint           response_opcode = -1;
    gboolean       is_obex_over_l2cap = FALSE;
    obex_profile_data_t  *obex_profile_data;
    guint32               interface_id;
    guint32               adapter_id;
    guint32               chandle;
    guint32               channel;
    wmem_tree_key_t       key[7];
    guint32               k_interface_id;
    guint32               k_adapter_id;
    guint32               k_frame_number;
    guint32               k_chandle;
    guint32               k_channel;
    obex_last_opcode_data_t  *obex_last_opcode_data;
    guint32                   k_direction;
    guint32                   length;


    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;

    save_fragmented = pinfo->fragmented;

    is_obex_over_l2cap = (proto_btrfcomm == (gint) GPOINTER_TO_UINT(wmem_list_frame_data(
                wmem_list_frame_prev(wmem_list_tail(pinfo->layers)))));

    if (is_obex_over_l2cap) {
        btl2cap_data_t      *l2cap_data;

        l2cap_data   = (btl2cap_data_t *) data;

        interface_id = l2cap_data->interface_id;
        adapter_id   = l2cap_data->adapter_id;
        chandle      = l2cap_data->chandle;
        channel      = l2cap_data->cid;
    } else {
        btrfcomm_data_t      *rfcomm_data;

        rfcomm_data  = (btrfcomm_data_t *) data;

        interface_id = rfcomm_data->interface_id;
        adapter_id   = rfcomm_data->adapter_id;
        chandle      = rfcomm_data->chandle;
        channel      = rfcomm_data->dlci >> 1;
    }

    k_interface_id = interface_id;
    k_adapter_id   = adapter_id;
    k_chandle      = chandle;
    k_channel      = channel;
    k_frame_number = pinfo->fd->num;

    key[0].length = 1;
    key[0].key = &k_interface_id;
    key[1].length = 1;
    key[1].key = &k_adapter_id;
    key[2].length = 1;
    key[2].key = &k_chandle;
    key[3].length = 1;
    key[3].key = &k_channel;
    key[4].length = 1;
    key[4].key = &k_frame_number;
    key[5].length = 0;
    key[5].key = NULL;

    obex_profile_data = (obex_profile_data_t *)wmem_tree_lookup32_array_le(obex_profile, key);
    if (obex_profile_data && obex_profile_data->interface_id == interface_id &&
            obex_profile_data->adapter_id == adapter_id &&
            obex_profile_data->chandle == chandle &&
            obex_profile_data->channel == channel) {
        profile = obex_profile_data->profile;
    }

    complete = FALSE;

    if (fragment_get(&btobex_reassembly_table, pinfo, pinfo->p2p_dir, NULL)) {
        /* not the first fragment */
        frag_msg = fragment_add_seq_next(&btobex_reassembly_table,
                                tvb, 0, pinfo, pinfo->p2p_dir, NULL,
                                tvb_length(tvb), TRUE);

        new_tvb = process_reassembled_data(tvb, 0, pinfo,
                        "Reassembled Obex packet", frag_msg, &btobex_frag_items, NULL, tree);

        pinfo->fragmented = TRUE;
    } else {
        if (tvb_length(tvb) < tvb_get_ntohs(tvb, offset+1)) {
            /* first fragment in a sequence */
            no_of_segments = tvb_get_ntohs(tvb, offset+1)/tvb_length(tvb);
            if (tvb_get_ntohs(tvb, offset+1) > (no_of_segments * tvb_length(tvb)))
                no_of_segments++;

            frag_msg = fragment_add_seq_next(&btobex_reassembly_table,
                                tvb, 0, pinfo, pinfo->p2p_dir, NULL,
                                tvb_length(tvb), TRUE);

            fragment_set_tot_len(&btobex_reassembly_table,
                                pinfo, pinfo->p2p_dir, NULL,
                                no_of_segments-1);

            new_tvb = process_reassembled_data(tvb, 0, pinfo,
                        "Reassembled Obex packet", frag_msg, &btobex_frag_items, NULL, tree);

            pinfo->fragmented = TRUE;
            }
        else if (tvb_length(tvb) == tvb_get_ntohs(tvb, offset+1)) {
            /* non-fragmented */
            complete = TRUE;
            pinfo->fragmented = FALSE;
        }
    }

    if (new_tvb) { /* take it all */
        next_tvb = new_tvb;
        complete = TRUE;
    } else { /* make a new subset */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
    }

    if (complete) {
        proto_item  *ti;
        proto_tree  *st;
        proto_item  *sub_item;
        guint8       code;
        guint8       final_flag;

        /* fully dissectable packet ready */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "OBEX");

        ti = proto_tree_add_item(tree, proto_btobex, next_tvb, 0, -1, ENC_NA);
        st = proto_item_add_subtree(ti, ett_btobex);

        sub_item = proto_tree_add_uint(st, hf_profile, next_tvb, 0, 0, profile);
        PROTO_ITEM_SET_GENERATED(sub_item);

        /* op/response code */
        code = tvb_get_guint8(next_tvb, offset) & BTOBEX_CODE_VALS_MASK;
        final_flag = tvb_get_guint8(next_tvb, offset) & 0x80;

        switch (pinfo->p2p_dir) {
            case P2P_DIR_SENT:
                col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
                break;
            case P2P_DIR_RECV:
                col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
                break;
            default:
                col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
                    pinfo->p2p_dir);
                break;
        }

        col_append_str(pinfo->cinfo, COL_INFO,
                        val_to_str_ext_const(code, &code_vals_ext, "Unknown"));

        if (code < BTOBEX_CODE_VALS_CONTINUE || code == BTOBEX_CODE_VALS_ABORT) {
            proto_tree_add_item(st, hf_opcode, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            if (!pinfo->fd->flags.visited &&
                    (pinfo->p2p_dir == P2P_DIR_SENT ||
                    pinfo->p2p_dir == P2P_DIR_RECV)) {

                if (is_obex_over_l2cap) {
                    btl2cap_data_t      *l2cap_data;

                    l2cap_data   = (btl2cap_data_t *) data;
                    interface_id = l2cap_data->interface_id;
                    adapter_id   = l2cap_data->adapter_id;
                    chandle      = l2cap_data->chandle;
                    channel      = l2cap_data->cid;
                } else {
                    btrfcomm_data_t      *rfcomm_data;

                    rfcomm_data  = (btrfcomm_data_t *) data;
                    interface_id = rfcomm_data->interface_id;
                    adapter_id   = rfcomm_data->adapter_id;
                    chandle      = rfcomm_data->chandle;
                    channel      = rfcomm_data->dlci >> 1;
                }

                k_interface_id = interface_id;
                k_adapter_id   = adapter_id;
                k_chandle      = chandle;
                k_channel      = channel;
                k_direction    = pinfo->p2p_dir;
                k_frame_number = pinfo->fd->num;

                key[0].length = 1;
                key[0].key = &k_interface_id;
                key[1].length = 1;
                key[1].key = &k_adapter_id;
                key[2].length = 1;
                key[2].key = &k_chandle;
                key[3].length = 1;
                key[3].key = &k_channel;
                key[4].length = 1;
                key[4].key = &k_direction;
                key[5].length = 1;
                key[5].key = &k_frame_number;
                key[6].length = 0;
                key[6].key = NULL;

                obex_last_opcode_data = wmem_new(wmem_file_scope(), obex_last_opcode_data_t);
                obex_last_opcode_data->interface_id = interface_id;
                obex_last_opcode_data->adapter_id = adapter_id;
                obex_last_opcode_data->chandle = chandle;
                obex_last_opcode_data->channel = channel;
                obex_last_opcode_data->direction = pinfo->p2p_dir;
                obex_last_opcode_data->code = code;

                wmem_tree_insert32_array(obex_last_opcode, key, obex_last_opcode_data);
            }
        } else {
            proto_tree_add_item(st, hf_response_code, next_tvb, offset, 1, ENC_BIG_ENDIAN);
        }

        proto_tree_add_item(st, hf_final_flag, next_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* length */
        proto_tree_add_item(st, hf_length, next_tvb, offset, 2, ENC_BIG_ENDIAN);
        length = tvb_get_ntohs(tvb, offset) - 3;
        offset += 2;

        switch(code)
        {
        case BTOBEX_CODE_VALS_CONNECT:
            proto_tree_add_item(st, hf_version, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(st, hf_flags, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(st, hf_max_pkt_len, next_tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;

        case BTOBEX_CODE_VALS_PUT:
        case BTOBEX_CODE_VALS_GET:
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s",  (final_flag == 0x80) ? "final" : "continue");
            break;

        case BTOBEX_CODE_VALS_SET_PATH:
            proto_tree_add_item(st, hf_flags, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(st, hf_set_path_flags_0, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(st, hf_set_path_flags_1, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(st, hf_constants, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;

        case BTOBEX_CODE_VALS_DISCONNECT:
        case BTOBEX_CODE_VALS_ABORT:
            break;

        default:
            if (length == 0 && tvb_length_remaining(tvb, offset) > 0) {
                proto_tree_add_expert(st, pinfo, &ei_unexpected_data, tvb, offset, tvb_length_remaining(tvb, offset));
                offset += tvb_length_remaining(tvb, offset);
                break;
            } else if (length == 0) break;

            if (is_obex_over_l2cap) {
                btl2cap_data_t      *l2cap_data;

                l2cap_data   = (btl2cap_data_t *) data;
                interface_id = l2cap_data->interface_id;
                adapter_id   = l2cap_data->adapter_id;
                chandle      = l2cap_data->chandle;
                channel      = l2cap_data->cid;
            } else {
                btrfcomm_data_t      *rfcomm_data;

                rfcomm_data  = (btrfcomm_data_t *) data;
                interface_id = rfcomm_data->interface_id;
                adapter_id   = rfcomm_data->adapter_id;
                chandle      = rfcomm_data->chandle;
                channel      = rfcomm_data->dlci >> 1;
            }

            k_interface_id = interface_id;
            k_adapter_id   = adapter_id;
            k_chandle      = chandle;
            k_channel      = channel;
            k_direction    = (pinfo->p2p_dir + 1) & 0x01;
            k_frame_number = pinfo->fd->num;

            key[0].length = 1;
            key[0].key = &k_interface_id;
            key[1].length = 1;
            key[1].key = &k_adapter_id;
            key[2].length = 1;
            key[2].key = &k_chandle;
            key[3].length = 1;
            key[3].key = &k_channel;
            key[4].length = 1;
            key[4].key = &k_direction;
            key[5].length = 1;
            key[5].key = &k_frame_number;
            key[6].length = 0;
            key[6].key = NULL;

            obex_last_opcode_data = (obex_last_opcode_data_t *)wmem_tree_lookup32_array_le(obex_last_opcode, key);
            if (obex_last_opcode_data && obex_last_opcode_data->interface_id == interface_id &&
                    obex_last_opcode_data->adapter_id == adapter_id &&
                    obex_last_opcode_data->chandle == chandle &&
                    obex_last_opcode_data->channel == channel &&
                    obex_last_opcode_data->direction == ((pinfo->p2p_dir + 1) & 0x01)) {
                response_opcode = obex_last_opcode_data->code;
            }

            if (response_opcode == BTOBEX_CODE_VALS_CONNECT) {
                proto_tree_add_item(st, hf_version, next_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;

                proto_tree_add_item(st, hf_flags, next_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;

                proto_tree_add_item(st, hf_max_pkt_len, next_tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            break;
        }

        dissect_headers(st, next_tvb, offset, pinfo, profile, is_obex_over_l2cap, data);
    } else {
        /* packet fragment */
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s Obex fragment",
                     (pinfo->p2p_dir==P2P_DIR_SENT) ? "Sent" : "Rcvd");

        call_dissector(data_handle, next_tvb, pinfo, tree);
    }

    pinfo->fragmented = save_fragmented;

    return offset;
}


void
proto_register_btobex(void)
{
    expert_module_t *expert_btobex;

    static hf_register_info hf[] = {
        { &hf_opcode,
          { "Opcode", "btobex.opcode",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &code_vals_ext, BTOBEX_CODE_VALS_MASK,
            "Request Opcode", HFILL}
        },
        { &hf_response_code,
          { "Response Code", "btobex.resp_code",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &code_vals_ext, BTOBEX_CODE_VALS_MASK,
            NULL, HFILL}
        },
        { &hf_final_flag,
          { "Final Flag", "btobex.final_flag",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL}
        },
        { &hf_length,
          { "Packet Length", "btobex.pkt_len",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_version,
          { "Version", "btobex.version",
            FT_UINT8, BASE_HEX, VALS(version_vals), 0x00,
            "Obex Protocol Version", HFILL}
        },
        { &hf_flags,
          { "Flags", "btobex.flags",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_constants,
          { "Constants", "btobex.constants",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_max_pkt_len,
          { "Max. Packet Length", "btobex.max_pkt_len",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_set_path_flags_0,
          { "Go back one folder (../) first", "btobex.set_path_flags_0",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_set_path_flags_1,
          { "Do not create folder, if not existing", "btobex.set_path_flags_1",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_headers,
          { "Headers", "btobex.headers",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_header,
          { "Header", "btobex.header",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_hdr_id,
          { "Header Id", "btobex.header.id",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &header_id_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_hdr_length,
          { "Length", "btobex.header.length",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Header Length", HFILL}
        },
        { &hf_hdr_val_unicode,
          { "Value", "btobex.header.value.unicode",
            FT_STRING, BASE_NONE, NULL, 0,
            "Unicode Value", HFILL }
        },
        { &hf_hdr_val_byte_seq,
          { "Value", "btobex.header.value.byte_sequence",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Byte Value", HFILL}
        },
        { &hf_hdr_val_byte,
          { "Value", "btobex.header.value.byte",
            FT_UINT8, BASE_HEX, NULL, 0,
            "Byte Sequence Value", HFILL}
        },
        { &hf_hdr_val_long,
          { "Value", "btobex.header.value.long",
            FT_UINT32, BASE_DEC, NULL, 0,
            "4-byte Value", HFILL}
        },
        { &hf_authentication_challenge_tag,
          { "Tag", "btobex.authentication.challenge_tag",
            FT_UINT8, BASE_HEX, VALS(authentication_challenge_tag_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_authentication_response_tag,
          { "Tag", "btobex.authentication.response_tag",
            FT_UINT8, BASE_HEX, VALS(authentication_response_tag_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_authentication_length,
          { "Length", "btobex.authentication.length",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_authentication_key,
          { "Key", "btobex.authentication.key",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_authentication_result_key,
          { "Result Key", "btobex.authentication.result_key",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_authentication_user_id,
          { "User Id", "btobex.authentication.user_id",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_authentication_option_reserved,
          { "Reserved", "btobex.authentication.option.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL}
        },
        { &hf_authentication_option_read_only,
          { "Read Only", "btobex.authentication.option.read_only",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_authentication_option_user_id,
          { "User ID", "btobex.authentication.option.user_id",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_authentication_info_charset,
          { "Charset", "btobex.authentication.info.charset",
            FT_UINT8, BASE_HEX, VALS(info_charset_vals), 0,
            NULL, HFILL}
        },
        { &hf_authentication_info,
          { "Info", "btobex.authentication.info",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_application_parameter,
          { "Parameter", "btobex.parameter",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_application_parameter_id,
          { "Parameter Id", "btobex.parameter.id",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_application_parameter_length,
          { "Parameter Length", "btobex.parameter.length",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_application_parameter_data,
          { "Parameter Value", "btobex.parameter.value",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        /* application parameters for BPP */
        { &hf_bpp_application_parameter_id,
          { "Parameter Id", "btobex.parameter.id",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bpp_application_parameters_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_bpp_application_parameter_data_offset,
          { "Offset", "btobex.parameter.value.offset",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "The byte offset into the image or file.", HFILL}
        },
        { &hf_bpp_application_parameter_data_count,
          { "Count", "btobex.parameter.value.count",
            FT_INT32, BASE_DEC, NULL, 0,
            "The number of bytes of the image or file to be sent.", HFILL}
        },
        { &hf_bpp_application_parameter_data_job_id,
          { "Job ID", "btobex.parameter.value.job_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "The job identifier of the print job.", HFILL}
        },
        { &hf_bpp_application_parameter_data_file_size,
          { "File Size", "btobex.parameter.value.file_size",
            FT_INT32, BASE_DEC, NULL, 0,
            "The size (in bytes) of object or file.", HFILL}
        },
        /* application parameters for BIP */
        { &hf_bip_application_parameter_id,
          { "Parameter Id", "btobex.parameter.id",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bip_application_parameters_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_bip_application_parameter_data_number_of_returned_handles,
            { "Number of Returned Handles",   "btobex.parameter.value.number_of_returned_handles",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_list_start_offset,
            { "List Start Offset",   "btobex.parameter.value.list_start_offset",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_latest_captured_images,
            { "Latest Captured Images",   "btobex.parameter.value.latest_captured_images",
            FT_BOOLEAN, 8, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_partial_file_length,
            { "Partial File Length",   "btobex.parameter.value.partial_file_length",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_partial_file_start_offset,
            { "Partial File Start Offset",   "btobex.parameter.value.partial_file_start_offset",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_total_file_size,
            { "Total File Size",   "btobex.parameter.value.total_file_size",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_end_flag,
            { "End Flag",   "btobex.parameter.value.end_flag",
            FT_BOOLEAN, 8, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_remote_display,
            { "Remote Display",   "btobex.parameter.value.remote_display",
            FT_UINT8, BASE_HEX, VALS(bip_remote_display_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_service_id,
            { "Service ID",   "btobex.parameter.value.service_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bt_sig_uuid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_store_flag,
            { "Store Flag",   "btobex.parameter.value.store_flag",
            FT_BOOLEAN, 8, NULL, 0x00,
            NULL, HFILL }
        },
        /* application parameters for PBAP */
        { &hf_pbap_application_parameter_id,
          { "Parameter Id", "btobex.parameter.id",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &pbap_application_parameters_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_order,
          { "Max List Count", "btobex.parameter.value.order",
            FT_UINT8, BASE_HEX, VALS(pbap_order_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_search_value,
          { "Search Value", "btobex.parameter.value.order",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_search_attribute,
          { "Search Attribute", "btobex.parameter.value.search_attribute",
            FT_UINT8, BASE_HEX, VALS(pbap_search_attribute_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_max_list_count,
          { "Max List Count", "btobex.parameter.value.max_list_count",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_list_start_offset,
          { "List Start Offset", "btobex.parameter.value.list_start_offset",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_version,
          { "vCard Version", "btobex.parameter.value.filter.version",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_fn,
          { "Formatted Name", "btobex.parameter.value.filter.fn",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_n,
          { "Structured Presentation of Name", "btobex.parameter.value.filter.n",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_photo,
          { "Associated Image or Photo", "btobex.parameter.value.filter.photo",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_birthday,
          { "Birthday", "btobex.parameter.value.filter.birthday",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_adr,
          { "Delivery Address", "btobex.parameter.value.filter.adr",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_label,
          { "Delivery", "btobex.parameter.value.filter.label",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_tel,
          { "Telephone Number", "btobex.parameter.value.filter.tel",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_email,
          { "Electronic Mail Address", "btobex.parameter.value.filter.email",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_mailer,
          { "Electronic Mail", "btobex.parameter.value.filter.mailer",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_time_zone,
          { "Time Zone", "btobex.parameter.value.filter.time_zone",
            FT_BOOLEAN, 32, NULL, 0x00000400,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_geographic_position,
          { "Geographic Position", "btobex.parameter.value.filter.geographic_position",
            FT_BOOLEAN, 32, NULL, 0x00000800,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_title,
          { "Job", "btobex.parameter.value.filter.title",
            FT_BOOLEAN, 32, NULL, 0x00001000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_role,
          { "Role within the Organization", "btobex.parameter.value.filter.role",
            FT_BOOLEAN, 32, NULL, 0x00002000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_logo,
          { "Organization Logo", "btobex.parameter.value.filter.logo",
            FT_BOOLEAN, 32, NULL, 0x00004000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_agent,
          { "vCard of Person Representing", "btobex.parameter.value.filter.agent",
            FT_BOOLEAN, 32, NULL, 0x00008000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_name_of_organization,
          { "Name of Organization", "btobex.parameter.value.filter.name_of_organization",
            FT_BOOLEAN, 32, NULL, 0x00010000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_comments,
          { "Comments", "btobex.parameter.value.filter.comments",
            FT_BOOLEAN, 32, NULL, 0x00020000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_revision,
          { "Revision", "btobex.parameter.value.filter.revision",
            FT_BOOLEAN, 32, NULL, 0x00040000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_pronunciation_of_name,
          { "Pronunciation of Name", "btobex.parameter.value.filter.pronunciation_of_name",
            FT_BOOLEAN, 32, NULL, 0x00080000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_url,
          { "Uniform Resource Locator", "btobex.parameter.value.filter.url",
            FT_BOOLEAN, 32, NULL, 0x00100000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_uid,
          { "Unique ID", "btobex.parameter.value.filter.uid",
            FT_BOOLEAN, 32, NULL, 0x00200000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_key,
          { "Public Encryption Key", "btobex.parameter.value.filter.key",
            FT_BOOLEAN, 32, NULL, 0x00400000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_nickname,
          { "Nickname", "btobex.parameter.value.filter.nickname",
            FT_BOOLEAN, 32, NULL, 0x00800000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_categories,
          { "Categories", "btobex.parameter.value.filter.categories",
            FT_BOOLEAN, 32, NULL, 0x01000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_product_id,
          { "Product ID", "btobex.parameter.value.filter.product_id",
            FT_BOOLEAN, 32, NULL, 0x02000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_class,
          { "Class Information", "btobex.parameter.value.filter.class",
            FT_BOOLEAN, 32, NULL, 0x04000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_sort_string,
          { "String Used For Sorting Operations", "btobex.parameter.value.filter.sort_string",
            FT_BOOLEAN, 32, NULL, 0x08000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_timestamp,
          { "Timestamp", "btobex.parameter.value.filter.timestamp",
            FT_BOOLEAN, 32, NULL, 0x10000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_reserved_29_31,
          { "Reserved", "btobex.parameter.value.filter.reserved_29_31",
            FT_UINT32, BASE_HEX, NULL, 0xE0000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_reserved_32_38,
          { "Reserved", "btobex.parameter.value.filter.reserved_32_38",
            FT_UINT32, BASE_HEX, NULL, 0x0000007F,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_proprietary_filter,
          { "Proprietary Filter", "btobex.parameter.value.filter.proprietary_filter",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_reserved_for_proprietary_filter_usage,
          { "Reserved for Proprietary Filter Usage", "btobex.parameter.value.filter.reserved_for_proprietary_filter_usage",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFFF00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_format,
          { "Format", "btobex.parameter.value.format",
            FT_UINT8, BASE_HEX, VALS(pbap_format_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_phonebook_size,
          { "Phonebook Size", "btobex.parameter.value.phonebook_size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_new_missed_calls,
          { "New Missed Calls", "btobex.parameter.value.new_missed_calls",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL}
        },
        /* application parameters for MAP */
        { &hf_map_application_parameter_id,
          { "Parameter Id", "btobex.parameter.id",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &map_application_parameters_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_max_list_count,
          { "Max List Count", "btobex.parameter.value.max_list_count",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_start_offset,
          { "Start Offset", "btobex.parameter.value.start_offset",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_message_type_reserved,
          { "Reserved", "btobex.parameter.value.filter_message_type.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_message_type_mms,
          { "MMS", "btobex.parameter.value.filter_message_type.mms",
            FT_BOOLEAN, 8, NULL, 0x08,
            "True to filter out, False to listing this type", HFILL}
        },
        { &hf_map_application_parameter_data_filter_message_type_email,
          { "EMAIL", "btobex.parameter.value.filter_message_type.sms_email",
            FT_BOOLEAN, 8, NULL, 0x04,
            "True to filter out, False to listing this type", HFILL}
        },
        { &hf_map_application_parameter_data_filter_message_type_sms_cdma,
          { "SMS_CDMA", "btobex.parameter.value.filter_message_type.sms_cdma",
            FT_BOOLEAN, 8, NULL, 0x02,
            "True to filter out, False to listing this type", HFILL}
        },
        { &hf_map_application_parameter_data_filter_message_type_sms_gsm,
          { "SMS_GSM", "btobex.parameter.value.filter_message_type.sms_gsm",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_period_begin,
          { "Filter Period Begin", "btobex.parameter.value.filter_period_begin",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_period_end,
          { "Filter Period End", "btobex.parameter.value.filter_period_end",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_read_status_reserved_6,
          { "Filter Read Status: Reserved", "btobex.parameter.value.filter_read_status.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_read_status_get_read,
          { "Filter Read Status: Get Read", "btobex.parameter.value.filter_read_status.get_read",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_read_status_get_unread,
          { "Filter Read Status: Get Unread", "btobex.parameter.value.filter_read_status.get_unread",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_recipient,
          { "Filter Recipient", "btobex.parameter.value.filter_recipient",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_originator,
          { "Filter Originator", "btobex.parameter.value.filter_originator",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_priority_reserved_6,
          { "Filter Priority: Reserved", "btobex.parameter.value.filter_priority.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_priority_get_high,
          { "Filter Priority: Get Read", "btobex.parameter.value.filter_priority.get_high",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_priority_non_high,
          { "Filter Priority: Get Non High", "btobex.parameter.value.filter_priority.non_high",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_reserved_7,
          { "Reserved", "btobex.parameter.value.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_attachment,
          { "Attachment", "btobex.parameter.value.attachment",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_transparent,
          { "Transparent", "btobex.parameter.value.transparent",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_retry,
          { "Retry", "btobex.parameter.value.retry",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_new_message,
          { "New Message", "btobex.parameter.value.new_message",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_notification_status,
          { "Notification Status", "btobex.parameter.value.notification_status",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_mas_instance_id,
          { "MAS Instance ID", "btobex.parameter.value.mas_instance_id",
            FT_UINT8, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_reserved,
          { "Parameter Mask: Reserved", "btobex.parameter.value.parameter_mask.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_reply_to_addressing,
          { "Parameter Mask: Reply to Addressing", "btobex.parameter.value.parameter_mask.reply_to_addressing",
            FT_BOOLEAN, 32, NULL, 0x8000,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_protected,
          { "Parameter Mask: Protected", "btobex.parameter.value.parameter_mask.protected",
            FT_BOOLEAN, 32, NULL, 0x4000,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_sent,
          { "Parameter Mask: Sent", "btobex.parameter.value.parameter_mask.sent",
            FT_BOOLEAN, 32, NULL, 0x2000,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_read,
          { "Parameter Mask: Read", "btobex.parameter.value.parameter_mask.read",
            FT_BOOLEAN, 32, NULL, 0x1000,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_priority,
          { "Parameter Mask: Priority", "btobex.parameter.value.parameter_mask.priority",
            FT_BOOLEAN, 32, NULL, 0x0800,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_attachment_size,
          { "Parameter Mask: Attachment Size", "btobex.parameter.value.parameter_mask.attachment_size",
            FT_BOOLEAN, 32, NULL, 0x0400,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_text,
          { "Parameter Mask: Text", "btobex.parameter.value.parameter_mask.text",
            FT_BOOLEAN, 32, NULL, 0x0200,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_reception_status,
          { "Parameter Mask: Reception Status", "btobex.parameter.value.parameter_mask.reception_status",
            FT_BOOLEAN, 32, NULL, 0x0100,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_size,
          { "Parameter Mask: Size", "btobex.parameter.value.parameter_mask.size",
            FT_BOOLEAN, 32, NULL, 0x0080,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_type,
          { "Parameter Mask: Type", "btobex.parameter.value.parameter_mask.type",
            FT_BOOLEAN, 32, NULL, 0x0040,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_recipient_addressing,
          { "Parameter Mask: Recipient Addressing", "btobex.parameter.value.parameter_mask.recipient_addressing",
            FT_BOOLEAN, 32, NULL, 0x0020,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_recipient_name,
          { "Parameter Mask: Recipient Name", "btobex.parameter.value.parameter_mask.recipient_name",
            FT_BOOLEAN, 32, NULL, 0x0010,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_sender_addressing,
          { "Parameter Mask: Sender Addressing", "btobex.parameter.value.parameter_mask.sender_addressing",
            FT_BOOLEAN, 32, NULL, 0x0008,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_sender_name,
          { "Parameter Mask: Sender Name", "btobex.parameter.value.parameter_mask.sender_name",
            FT_BOOLEAN, 32, NULL, 0x0004,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_datetime,
          { "Parameter Mask: Datetime", "btobex.parameter.value.parameter_mask.datetime",
            FT_BOOLEAN, 32, NULL, 0x0002,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_subject,
          { "Parameter Mask: Subject", "btobex.parameter.value.parameter_mask.subject",
            FT_BOOLEAN, 32, NULL, 0x0001,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_folder_listing_size,
          { "Folder Listing Size", "btobex.parameter.value.folder_listing_size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_messages_listing_size,
          { "Messages Listing Size", "btobex.parameter.value.messages_listing_size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_subject_length,
          { "Subject Length", "btobex.parameter.value.subject_length",
            FT_UINT8, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_charset,
          { "Charset", "btobex.parameter.value.charset",
            FT_UINT8, BASE_HEX, VALS(map_charset_vals), 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_fraction_request,
          { "Fraction Request", "btobex.parameter.value.fraction_request",
            FT_UINT8, BASE_HEX, VALS(map_fraction_request_vals), 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_fraction_deliver,
          { "Fraction Deliver", "btobex.parameter.value.fraction_deliver",
            FT_UINT8, BASE_HEX, VALS(map_fraction_deliver_vals), 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_status_indicator,
          { "Status Indicator", "btobex.parameter.value.status_indicator",
            FT_UINT8, BASE_HEX, VALS(map_status_indicator_vals), 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_status_value,
          { "Status Value", "btobex.parameter.value.status_value",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_mse_time,
          { "MSE Time", "btobex.parameter.value.mse_time",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        /* for fragmentation */
        { &hf_btobex_fragment_overlap,
          { "Fragment overlap",   "btobex.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_btobex_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap",   "btobex.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_btobex_fragment_multiple_tails,
          { "Multiple tail fragments found",  "btobex.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_btobex_fragment_too_long_fragment,
          { "Fragment too long",  "btobex.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }
        },
        { &hf_btobex_fragment_error,
          { "Defragmentation error", "btobex.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_btobex_fragment_count,
          { "Fragment count", "btobex.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_btobex_fragment,
          { "OBEX Fragment", "btobex.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "btobex Fragment", HFILL }
        },
        { &hf_btobex_fragments,
          { "OBEX Fragments", "btobex.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
            "btobex Fragments", HFILL }
        },
        { &hf_btobex_reassembled_in,
          { "Reassembled OBEX in frame", "btobex.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This OBEX frame is reassembled in this frame", HFILL }
        },
        { &hf_btobex_reassembled_length,
          { "Reassembled OBEX length", "btobex.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }
        },
        { &hf_profile,
          { "Profile", "btobex.profile", FT_UINT32, BASE_DEC | BASE_EXT_STRING, &profile_vals_ext, 0x0,
            "Blutooth Profile used in this OBEX session", HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_btobex,
        &ett_btobex_hdrs,
        &ett_btobex_hdr,
        &ett_btobex_fragment,
        &ett_btobex_fragments,
        &ett_btobex_application_parameters
    };

    static ei_register_info ei[] = {
        { &ei_application_parameter_length_bad, { "btobex.parameter.length.bad", PI_PROTOCOL, PI_WARN, "Parameter length bad", EXPFILL }},
        { &ei_unexpected_data, { "btobex.expert.unexpected_data", PI_PROTOCOL, PI_WARN, "Unexpected data", EXPFILL }},
    };

    obex_profile     = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    obex_last_opcode = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_btobex = proto_register_protocol("Bluetooth OBEX Protocol", "BT OBEX", "btobex");

    btobex_handle = new_register_dissector("btobex", dissect_btobex, proto_btobex);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btobex, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_btobex = expert_register_protocol(proto_btobex);
    expert_register_field_array(expert_btobex, ei, array_length(ei));

    register_init_routine(&defragment_init);
}

void
proto_reg_handoff_btobex(void)
{
    /* register in rfcomm and l2cap the profiles/services this dissector should handle */
    dissector_add_uint("btrfcomm.service", BTSDP_OPP_SERVICE_UUID,                          btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_FTP_SERVICE_UUID,                          btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_BPP_DIRECT_PRINTING_SERVICE_UUID,          btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_BPP_REFERENCE_PRINTING_SERVICE_UUID,       btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_BPP_DIRECT_PRINTING_REF_OBJ_SERVICE_UUID,  btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_BPP_REFLECTED_UI_SERVICE_UUID,             btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_BPP_SERVICE_UUID,                          btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_BPP_STATUS_SERVICE_UUID,                   btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_BIP_SERVICE_UUID,                          btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_BIP_RESPONDER_SERVICE_UUID,                btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_BIP_AUTO_ARCH_SERVICE_UUID,                btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_BIP_REF_OBJ_SERVICE_UUID,                  btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_PBAP_PCE_SERVICE_UUID,                     btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_PBAP_PSE_SERVICE_UUID,                     btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_PBAP_SERVICE_UUID,                         btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_MAP_SERVICE_UUID,                          btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_MAP_ACCESS_SRV_SERVICE_UUID,               btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_MAP_NOTIFICATION_SRV_SERVICE_UUID,         btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_SYNC_SERVICE_UUID,                         btobex_handle);
    dissector_add_uint("btrfcomm.service", BTSDP_SYNC_COMMAND_SERVICE_UUID,                 btobex_handle);

    dissector_add_uint("btl2cap.service",  BTSDP_OPP_SERVICE_UUID,                          btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_FTP_SERVICE_UUID,                          btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_BPP_DIRECT_PRINTING_SERVICE_UUID,          btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_BPP_REFERENCE_PRINTING_SERVICE_UUID,       btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_BPP_DIRECT_PRINTING_REF_OBJ_SERVICE_UUID,  btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_BPP_REFLECTED_UI_SERVICE_UUID,             btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_BPP_SERVICE_UUID,                          btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_BPP_STATUS_SERVICE_UUID,                   btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_BIP_SERVICE_UUID,                          btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_BIP_RESPONDER_SERVICE_UUID,                btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_BIP_AUTO_ARCH_SERVICE_UUID,                btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_BIP_REF_OBJ_SERVICE_UUID,                  btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_PBAP_PCE_SERVICE_UUID,                     btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_PBAP_PSE_SERVICE_UUID,                     btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_PBAP_SERVICE_UUID,                         btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_MAP_SERVICE_UUID,                          btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_MAP_ACCESS_SRV_SERVICE_UUID,               btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_MAP_NOTIFICATION_SRV_SERVICE_UUID,         btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_SYNC_SERVICE_UUID,                         btobex_handle);
    dissector_add_uint("btl2cap.service",  BTSDP_SYNC_COMMAND_SERVICE_UUID,                 btobex_handle);

    xml_handle  = find_dissector("xml");
    data_handle = find_dissector("data");

    dissector_add_for_decode_as("btrfcomm.channel", btobex_handle);
    dissector_add_for_decode_as("btl2cap.psm", btobex_handle);
    dissector_add_for_decode_as("btl2cap.cid", btobex_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
