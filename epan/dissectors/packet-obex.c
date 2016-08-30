/* packet-obex.c
 * Routines for OBEX dissection
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
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>
#include "packet-bluetooth.h"
#include "packet-btrfcomm.h"
#include "packet-btl2cap.h"
#include "packet-btsdp.h"

/* Initialize the protocol and registered fields */
static int proto_obex = -1;
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
static int hf_hdr_id_encoding = -1;
static int hf_hdr_id_meaning = -1;
static int hf_hdr_length = -1;
static int hf_hdr_val_unicode = -1;
static int hf_hdr_val_byte_seq = -1;
static int hf_hdr_val_byte = -1;
static int hf_hdr_val_long = -1;
static int hf_authentication_parameter = -1;
static int hf_authentication_parameter_data = -1;
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
static int hf_pbap_application_parameter_data_filter = -1;
static int hf_pbap_application_parameter_vcard_selector = -1;
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
static int hf_pbap_application_parameter_data_primary_version_counter = -1;
static int hf_pbap_application_parameter_data_secondary_version_counter = -1;
static int hf_pbap_application_parameter_data_database_identifier = -1;
static int hf_pbap_application_parameter_data_vcard_selector_operator = -1;
static int hf_pbap_application_parameter_data_reset_new_missed_calls = -1;
static int hf_pbap_application_parameter_data_supported_features = -1;
static int hf_pbap_application_parameter_data_supported_features_reserved = -1;
static int hf_pbap_application_parameter_data_supported_features_download = -1;
static int hf_pbap_application_parameter_data_supported_features_browsing = -1;
static int hf_pbap_application_parameter_data_supported_features_database_identifier = -1;
static int hf_pbap_application_parameter_data_supported_features_folder_version_counters = -1;
static int hf_pbap_application_parameter_data_supported_features_vcard_selecting = -1;
static int hf_pbap_application_parameter_data_supported_features_enhanced_missed_calls = -1;
static int hf_pbap_application_parameter_data_supported_features_x_bt_uci_vcard_property = -1;
static int hf_pbap_application_parameter_data_supported_features_x_bt_uid_vcard_property = -1;
static int hf_pbap_application_parameter_data_supported_features_contact_referencing = -1;
static int hf_pbap_application_parameter_data_supported_features_default_contact_image_format = -1;
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
static int hf_gpp_application_parameter_id = -1;
static int hf_gpp_application_parameter_data_max_list_count = -1;
static int hf_gpp_application_parameter_data_list_start_offset = -1;
static int hf_gpp_application_parameter_data_reserved_7 = -1;
static int hf_gpp_application_parameter_data_notification_status = -1;
static int hf_gpp_application_parameter_data_instance_id = -1;
static int hf_gpp_application_parameter_data_listing_size = -1;
static int hf_ctn_application_parameter_id = -1;
static int hf_ctn_application_parameter_data_acoustic_alarm_status = -1;
static int hf_ctn_application_parameter_data_attachment = -1;
static int hf_ctn_application_parameter_data_send = -1;
static int hf_ctn_application_parameter_data_filter_period_begin = -1;
static int hf_ctn_application_parameter_data_filter_period_end = -1;
static int hf_ctn_application_parameter_data_parameter_mask = -1;
static int hf_ctn_application_parameter_data_parameter_mask_reserved = -1;
static int hf_ctn_application_parameter_data_parameter_mask_recurrent = -1;
static int hf_ctn_application_parameter_data_parameter_mask_send_status = -1;
static int hf_ctn_application_parameter_data_parameter_mask_alarm_status = -1;
static int hf_ctn_application_parameter_data_parameter_mask_pstatus = -1;
static int hf_ctn_application_parameter_data_parameter_mask_priority = -1;
static int hf_ctn_application_parameter_data_parameter_mask_originator_address = -1;
static int hf_ctn_application_parameter_data_parameter_mask_originator_name = -1;
static int hf_ctn_application_parameter_data_parameter_mask_end_time = -1;
static int hf_ctn_application_parameter_data_parameter_mask_summary = -1;
static int hf_ctn_application_parameter_data_parameter_mask_attachment = -1;
static int hf_ctn_application_parameter_data_status_indicator = -1;
static int hf_ctn_application_parameter_data_status_value = -1;
static int hf_ctn_application_parameter_data_postpone_val = -1;
static int hf_ctn_application_parameter_data_email_uri = -1;
static int hf_ctn_application_parameter_data_cse_time = -1;
static int hf_ctn_application_parameter_data_recurrent = -1;
static int hf_ctn_application_parameter_data_attach_id = -1;
static int hf_ctn_application_parameter_data_last_update = -1;
static int hf_profile = -1;
static int hf_type = -1;
static int hf_object_class = -1;
static int hf_time_iso8601 = -1;
static int hf_wan_uuid = -1;
static int hf_hdr_val_action = -1;
static int hf_hdr_val_single_response_mode = -1;
static int hf_hdr_val_single_response_mode_parameter = -1;
static int hf_session_parameter = -1;
static int hf_session_parameter_tag = -1;
static int hf_session_parameter_length = -1;
static int hf_session_parameter_data = -1;
static int hf_session_parameter_nonce = -1;
static int hf_session_parameter_session_id = -1;
static int hf_session_parameter_next_sequence_number = -1;
static int hf_session_parameter_timeout = -1;
static int hf_session_parameter_opcode = -1;
static int hf_sender_bd_addr = -1;
static int hf_count = -1;
static int hf_data_length = -1;
static int hf_connection_id = -1;
static int hf_name = -1;
static int hf_current_path = -1;
static int hf_request_in_frame = -1;
static int hf_response_in_frame = -1;

static const int *hfx_hdr_id[] = {
    &hf_hdr_id_encoding,
    &hf_hdr_id_meaning,
    NULL
};

static const int *hfx_pbap_application_parameter_data_filter_1[] = {
    &hf_pbap_application_parameter_data_filter_reserved_32_38,
    &hf_pbap_application_parameter_data_filter_proprietary_filter,
    &hf_pbap_application_parameter_data_filter_reserved_for_proprietary_filter_usage,
    NULL
};

static const int *hfx_pbap_application_parameter_data_filter_0[] = {
    &hf_pbap_application_parameter_data_filter_version,
    &hf_pbap_application_parameter_data_filter_fn,
    &hf_pbap_application_parameter_data_filter_n,
    &hf_pbap_application_parameter_data_filter_photo,
    &hf_pbap_application_parameter_data_filter_birthday,
    &hf_pbap_application_parameter_data_filter_adr,
    &hf_pbap_application_parameter_data_filter_label,
    &hf_pbap_application_parameter_data_filter_tel,
    &hf_pbap_application_parameter_data_filter_email,
    &hf_pbap_application_parameter_data_filter_mailer,
    &hf_pbap_application_parameter_data_filter_time_zone,
    &hf_pbap_application_parameter_data_filter_geographic_position,
    &hf_pbap_application_parameter_data_filter_title,
    &hf_pbap_application_parameter_data_filter_role,
    &hf_pbap_application_parameter_data_filter_logo,
    &hf_pbap_application_parameter_data_filter_agent,
    &hf_pbap_application_parameter_data_filter_name_of_organization,
    &hf_pbap_application_parameter_data_filter_comments,
    &hf_pbap_application_parameter_data_filter_revision,
    &hf_pbap_application_parameter_data_filter_pronunciation_of_name,
    &hf_pbap_application_parameter_data_filter_url,
    &hf_pbap_application_parameter_data_filter_uid,
    &hf_pbap_application_parameter_data_filter_key,
    &hf_pbap_application_parameter_data_filter_nickname,
    &hf_pbap_application_parameter_data_filter_categories,
    &hf_pbap_application_parameter_data_filter_product_id,
    &hf_pbap_application_parameter_data_filter_class,
    &hf_pbap_application_parameter_data_filter_sort_string,
    &hf_pbap_application_parameter_data_filter_timestamp,
    &hf_pbap_application_parameter_data_filter_reserved_29_31,
    NULL
};

static const int *hfx_pbap_application_parameter_data_supported_features[] = {
    &hf_pbap_application_parameter_data_supported_features_reserved,
    &hf_pbap_application_parameter_data_supported_features_default_contact_image_format,
    &hf_pbap_application_parameter_data_supported_features_contact_referencing,
    &hf_pbap_application_parameter_data_supported_features_x_bt_uid_vcard_property,
    &hf_pbap_application_parameter_data_supported_features_x_bt_uci_vcard_property,
    &hf_pbap_application_parameter_data_supported_features_enhanced_missed_calls,
    &hf_pbap_application_parameter_data_supported_features_vcard_selecting,
    &hf_pbap_application_parameter_data_supported_features_folder_version_counters,
    &hf_pbap_application_parameter_data_supported_features_database_identifier,
    &hf_pbap_application_parameter_data_supported_features_browsing,
    &hf_pbap_application_parameter_data_supported_features_download,
    NULL
};

static const int *hfx_ctn_application_parameter_data_parameter_mask[] = {
    &hf_ctn_application_parameter_data_parameter_mask_reserved,
    &hf_ctn_application_parameter_data_parameter_mask_recurrent,
    &hf_ctn_application_parameter_data_parameter_mask_send_status,
    &hf_ctn_application_parameter_data_parameter_mask_alarm_status,
    &hf_ctn_application_parameter_data_parameter_mask_pstatus,
    &hf_ctn_application_parameter_data_parameter_mask_priority,
    &hf_ctn_application_parameter_data_parameter_mask_originator_address,
    &hf_ctn_application_parameter_data_parameter_mask_originator_name,
    &hf_ctn_application_parameter_data_parameter_mask_end_time,
    &hf_ctn_application_parameter_data_parameter_mask_summary,
    &hf_ctn_application_parameter_data_parameter_mask_attachment,
    NULL
};

static expert_field ei_unexpected_data = EI_INIT;
static expert_field ei_application_parameter_length_bad = EI_INIT;
static expert_field ei_decoded_as_profile = EI_INIT;

static dissector_table_t obex_profile_table;
static dissector_table_t media_type_dissector_table;


/* ************************************************************************* */
/*                   Header values for reassembly                            */
/* ************************************************************************* */
static int hf_obex_fragments = -1;
static int hf_obex_fragment = -1;
static int hf_obex_fragment_overlap = -1;
static int hf_obex_fragment_overlap_conflict = -1;
static int hf_obex_fragment_multiple_tails = -1;
static int hf_obex_fragment_too_long_fragment = -1;
static int hf_obex_fragment_error = -1;
static int hf_obex_fragment_count = -1;
static int hf_obex_reassembled_in = -1;
static int hf_obex_reassembled_length = -1;

static gint ett_obex_fragment = -1;
static gint ett_obex_fragments = -1;

static dissector_handle_t obex_handle;
static dissector_handle_t raw_application_parameters_handle;
static dissector_handle_t bt_bpp_application_parameters_handle;
static dissector_handle_t bt_bip_application_parameters_handle;
static dissector_handle_t bt_gpp_application_parameters_handle;
static dissector_handle_t bt_ctn_application_parameters_handle;
static dissector_handle_t bt_map_application_parameters_handle;
static dissector_handle_t bt_pbap_application_parameters_handle;

static reassembly_table obex_reassembly_table;

static const fragment_items obex_frag_items = {
    &ett_obex_fragment,
    &ett_obex_fragments,
    &hf_obex_fragments,
    &hf_obex_fragment,
    &hf_obex_fragment_overlap,
    &hf_obex_fragment_overlap_conflict,
    &hf_obex_fragment_multiple_tails,
    &hf_obex_fragment_too_long_fragment,
    &hf_obex_fragment_error,
    &hf_obex_fragment_count,
    &hf_obex_reassembled_in,
    &hf_obex_reassembled_length,
    /* Reassembled data field */
    NULL,
    "fragments"
};

/* Initialize the subtree pointers */
static gint ett_obex = -1;
static gint ett_obex_hdrs = -1;
static gint ett_obex_hdr = -1;
static gint ett_obex_hdr_id = -1;
static gint ett_obex_filter = -1;
static gint ett_obex_parameter = -1;
static gint ett_obex_session_parameters = -1;
static gint ett_obex_application_parameters = -1;
static gint ett_obex_authentication_parameters = -1;

static wmem_tree_t *obex_path = NULL;
static wmem_tree_t *obex_profile = NULL;
static wmem_tree_t *obex_last_opcode = NULL;

static dissector_handle_t http_handle;
static dissector_handle_t xml_handle;
static dissector_handle_t data_handle;
static dissector_handle_t data_text_lines_handle;

static const gchar  *path_unknown = "?";
static const gchar  *path_root    = "/";

typedef struct _obex_proto_data_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint32  chandle;
    guint32  channel;
} obex_proto_data_t;

typedef struct _ext_value_string {
    guint8       value[16];
    gint         length;
    const gchar *strptr;
} ext_value_string;

typedef struct _obex_path_data_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint32  chandle;
    guint32   channel;
/* TODO: add OBEX ConnectionId */

    const gchar  *path;
} obex_path_data_t;

typedef struct _obex_profile_data_t {
    guint32  interface_id;
    guint32  adapter_id;
    guint32  chandle;
    guint32  channel;
/* TODO: add OBEX ConnectionId */

    gint     profile;
} obex_profile_data_t;

typedef struct _obex_last_opcode_data_t {
    guint32 interface_id;
    guint32 adapter_id;
    guint32 chandle;
    guint32 channel;
/* TODO: add OBEX ConnectionId */
    gint    code;

    gboolean final_flag;

    guint32  request_in_frame;
    guint32  response_in_frame;

    union {
        struct {
            const gchar  *name;
            gboolean      go_up;
        } set_data;
        struct {
            gchar     *type;
            gchar     *name;
        } get_put;
    } data;
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
#define PROFILE_CTN      9
#define PROFILE_GPP     10

#define PROTO_DATA_MEDIA_TYPE       0x00
#define PROTO_DATA_OBEX_PROFILE     0x01

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
    { PROFILE_CTN,     "CTN" },
    { PROFILE_GPP,     "GPP" },
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

static const value_string header_id_encoding_vals[] = {
    { 0x00, "Null terminated Unicode text, length prefixed with 2 byte Unsigned Integer" },
    { 0x01, "Byte sequence, length prefixed with 2 byte Unsigned Integer" },
    { 0x02, "1 byte quantity" },
    { 0x03, "4 byte quantity (network order)" },
    { 0,    NULL }
};

#define OBEX_CODE_VALS_CONNECT    0x00
#define OBEX_CODE_VALS_DISCONNECT 0x01
#define OBEX_CODE_VALS_PUT        0x02
#define OBEX_CODE_VALS_GET        0x03
#define OBEX_CODE_VALS_SET_PATH   0x05
#define OBEX_CODE_VALS_CONTINUE   0x10
#define OBEX_CODE_VALS_SUCCESS    0x20
#define OBEX_CODE_VALS_ABORT      0x7F
#define OBEX_CODE_VALS_MASK       0x7F

static const value_string code_vals[] = {
    { 0x00, "Connect" },
    { 0x01, "Disconnect" },
    { 0x02, "Put" },
    { 0x03, "Get"},
    { 0x05, "Set Path" },
    { 0x06, "Action" },
    { 0x07, "Session" },
    { 0x10, "Continue" },
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
    { OBEX_CODE_VALS_ABORT, "Abort" },
    { 0,      NULL }
};
static value_string_ext(code_vals_ext) = VALUE_STRING_EXT_INIT(code_vals);

static const value_string header_id_meaning_vals[] = {
    { 0x00, "Count" },
    { 0x01, "Name" },
    { 0x02, "Type" },
    { 0x03, "Length" },
    { 0x04, "Time" },
    { 0x05, "Description" },
    { 0x06, "Target" },
    { 0x07, "HTTP" },
    { 0x08, "Body" },
    { 0x09, "End Of Body" },
    { 0x0A, "Who" },
    { 0x0B, "Connection Id" },
    { 0x0C, "Application Parameters" },
    { 0x0D, "Authentication Challenge" },
    { 0x0E, "Authentication Response" },
    { 0x0F, "Creator" },
    { 0x10, "WAN UUID" },
    { 0x11, "Object Class" },
    { 0x12, "Session Parameter" },
    { 0x13, "Session Sequence Number" },
    { 0x14, "Action" },
    { 0x15, "Destination Name" },
    { 0x16, "Permissions" },
    { 0x17, "Single Response Mode" },
    { 0x18, "Single Response Mode Parameter" },
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
    { 0x3A, "User Defined" },
    { 0x3B, "User Defined" },
    { 0x3C, "User Defined" },
    { 0x3D, "User Defined" },
    { 0x3E, "User Defined" },
    { 0x3F, "User Defined" },
    { 0,      NULL }
};

static const value_string header_id_vals[] = {
/* 0x00 - 0x3F - Null terminated Unicode text, length prefixed with 2 byte Unsigned Integer */
    { 0x01, "Name" },
    { 0x05, "Description" },
    { 0x15, "Destination Name" },
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
/* 0x40 - 0x07F -  Byte sequence, length prefixed with 2 byte Unsigned Integer */
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
    { 0x50, "WAN UUID" },
    { 0x51, "Object Class" },
    { 0x52, "Session Parameter" },
/* 0x80 - 0xBF - 1 byte quantity */
    { 0x93, "Session Sequence Number" },
    { 0x94, "Action" },
    { 0x97, "Single Response Mode" },
    { 0x98, "Single Response Mode Parameter" },
/* 0xC0 - 0xFF - 4 byte quantity (network order) */
    { 0xc0, "Count" },
    { 0xc3, "Length" },
    { 0xc4, "Time (UNIX)" },
    { 0xcb, "Connection Id" },
    { 0xcf, "Creator" },
    { 0xd6, "Permissions" },
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
    { 0x0A, "Primary Version Counter" },
    { 0x0B, "Secondary Version Counter" },
    { 0x0C, "vCard Selector" },
    { 0x0D, "Database Identifier" },
    { 0x0E, "vCard Selector Operator" },
    { 0x0F, "Reset New Missed Calls" },
    { 0x10, "PBAP Supported Features" },
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

static const value_string gpp_application_parameters_vals[] = {
    { 0x41, "Max List Count" },
    { 0x42, "List Start Offset" },
    { 0x43, "Notification Status" },
    { 0x44, "Instance ID" },
    { 0x46, "Listing Size" },
    { 0,    NULL }
};

static const value_string ctn_application_parameters_vals[] = {
    { 0x01, "Acoustic Alarm Status" },
    { 0x02, "Attachment" },
    { 0x03, "Send" },
    { 0x04, "Filter Period Begin" },
    { 0x05, "Filter Period End" },
    { 0x06, "Parameter Mask" },
    { 0x07, "Status Indicator" },
    { 0x08, "Status Value" },
    { 0x09, "Postpone Val" },
    { 0x0A, "Email URI" },
    { 0x0B, "CSE Time" },
    { 0x0C, "Recurrent" },
    { 0x0D, "Attach ID" },
    { 0x0E, "Last Update" },
    { 0x41, "Max List Count" },
    { 0x42, "List Start Offset" },
    { 0x43, "Notification Status" },
    { 0x44, "Instance ID" },
    { 0x46, "Listing Size" },
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

static const value_string action_vals[] = {
    { 0x00, "Copy" },
    { 0x01, "Move" },
    { 0x02, "Set Permission" },
    { 0,    NULL }
};

static const value_string single_response_mode_vals[] = {
    { 0x00, "Disable" },
    { 0x01, "Enable" },
    { 0x02, "Indicate" },
    { 0,    NULL }
};

static const value_string single_response_mode_parameter_vals[] = {
    { 0x00, "Next" },
    { 0x01, "Wait" },
    { 0x02, "Next and Wait" },
    { 0,    NULL }
};

static const value_string session_tag_vals[] = {
    { 0x00, "Device Address" },
    { 0x01, "Nonce" },
    { 0x02, "Session ID" },
    { 0x03, "Next Sequence Number" },
    { 0x04, "Timeout" },
    { 0x05, "Session Opcode" },
    { 0,    NULL }
};

static const value_string session_opcode_vals[] = {
    { 0x00, "Create Session" },
    { 0x01, "Close Session" },
    { 0x02, "Suspend Session" },
    { 0x03, "Resume Session" },
    { 0x04, "Set Timeout" },
    { 0,    NULL }
};

static const value_string pbap_application_parameter_data_vcard_selector_operator_vals[] = {
    { 0x00, "Or" },
    { 0x01, "And" },
    { 0,    NULL }
};

static const value_string pbap_application_parameter_data_reset_new_missed_calls_vals[] = {
    { 0x01, "Reset" },
    { 0,    NULL }
};

static const value_string off_on_vals[] = {
    { 0x00, "Off" },
    { 0x01, "On" },
    { 0,    NULL }
};

static const value_string no_yes_vals[] = {
    { 0x00, "No" },
    { 0x01, "Yes" },
    { 0,    NULL }
};

static const value_string ctn_application_parameter_data_attachment_vals[] = {
    { 0x00, "On" },
    { 0x01, "Off" },
    { 0x02, "Selected" },
    { 0,    NULL }
};

static const value_string ctn_application_parameter_data_status_indicator_vals[] = {
    { 0x00, "pStatus" },
    { 0x01, "Alarm Status" },
    { 0x02, "Send Status" },
    { 0x03, "Deleted Status" },
    { 0,    NULL }
};

static const value_string ctn_application_parameter_data_status_value_vals[] = {
    { 0x00, "No" },
    { 0x01, "Yes" },
    { 0x02, "Postpone" },
    { 0x03, "Tentative" },
    { 0x04, "Needs-action" },
    { 0x05, "Accepted" },
    { 0x06, "Declined" },
    { 0x07, "Delegated" },
    { 0x08, "Completed" },
    { 0x09, "In-progress" },
    { 0,    NULL }
};

static value_string_ext map_application_parameters_vals_ext = VALUE_STRING_EXT_INIT(map_application_parameters_vals);
static value_string_ext pbap_application_parameters_vals_ext = VALUE_STRING_EXT_INIT(pbap_application_parameters_vals);
static value_string_ext bpp_application_parameters_vals_ext = VALUE_STRING_EXT_INIT(bpp_application_parameters_vals);
static value_string_ext bip_application_parameters_vals_ext = VALUE_STRING_EXT_INIT(bip_application_parameters_vals);

void proto_register_obex(void);
void proto_reg_handoff_obex(void);

static void
save_path(packet_info *pinfo, const gchar *current_path, const gchar *name,
        gboolean go_up, obex_proto_data_t *obex_proto_data)
{

/* On Connect response sets "/"
   On SetPath sets what is needed
 */
    if (!pinfo->fd->flags.visited) {
        obex_path_data_t     *obex_path_data;
        wmem_tree_key_t       key[6];
        guint32               frame_number;
        const gchar          *path = path_unknown;

        frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key = &obex_proto_data->interface_id;
        key[1].length = 1;
        key[1].key = &obex_proto_data->adapter_id;
        key[2].length = 1;
        key[2].key = &obex_proto_data->chandle;
        key[3].length = 1;
        key[3].key = &obex_proto_data->channel;
        key[4].length = 1;
        key[4].key = &frame_number;
        key[5].length = 0;
        key[5].key = NULL;

        obex_path_data = wmem_new(wmem_file_scope(), obex_path_data_t);
        obex_path_data->interface_id = obex_proto_data->interface_id;
        obex_path_data->adapter_id = obex_proto_data->adapter_id;
        obex_path_data->chandle = obex_proto_data->chandle;
        obex_path_data->channel = obex_proto_data->channel;

        if (go_up == TRUE) {
            if (current_path != path_unknown && current_path != path_root) {
                gchar *i_path;

                i_path = g_strrstr(current_path, "/");
                if (!i_path) {
                    current_path = path_unknown;
                } else {
                    if (i_path == current_path)
                        path = current_path = path_root;
                    else
                        path = current_path = wmem_strndup(wmem_epan_scope(), current_path, i_path - current_path - 1);
                }
            }
        }

        if (name && *name == '\0')
            path = path_root;
        else if (name && current_path == path_root)
            path = wmem_strdup_printf(wmem_file_scope(), "/%s", name);
        else if (name)
            path = wmem_strdup_printf(wmem_file_scope(), "%s/%s", current_path, name);

        obex_path_data->path = path;

        wmem_tree_insert32_array(obex_path, key, obex_path_data);
    }
}

static void media_type_prompt(packet_info *pinfo, gchar* result)
{
    gchar *value_data;

    value_data = (gchar *) p_get_proto_data(pinfo->pool, pinfo, proto_obex, PROTO_DATA_MEDIA_TYPE);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Media Type %s as", (gchar *) value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown Media Type");
}

static gpointer media_type_value(packet_info *pinfo)
{
    gchar *value_data;

    value_data = (gchar *) p_get_proto_data(pinfo->pool, pinfo, proto_obex, PROTO_DATA_MEDIA_TYPE);

    if (value_data)
        return (gpointer) value_data;

    return NULL;
}

static void obex_profile_prompt(packet_info *pinfo _U_, gchar* result)
{
    guint8 *value_data;

    value_data = (guint8 *) p_get_proto_data(pinfo->pool, pinfo, proto_obex, PROTO_DATA_OBEX_PROFILE);
    if (value_data)
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "OBEX Profile 0x%04x as", (guint) *value_data);
    else
        g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Unknown OBEX Profile");
}

static gpointer obex_profile_value(packet_info *pinfo _U_)
{
    guint8 *value_data;

    value_data = (guint8 *) p_get_proto_data(pinfo->pool, pinfo, proto_obex, PROTO_DATA_OBEX_PROFILE);

    if (value_data)
        return GUINT_TO_POINTER((gulong)*value_data);

    return NULL;
}

static void
defragment_init(void)
{
    reassembly_table_init(&obex_reassembly_table,
                          &addresses_reassembly_table_functions);
}

static void
defragment_cleanup(void)
{
    reassembly_table_destroy(&obex_reassembly_table);
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

static gint
dissect_obex_application_parameter_raw(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    guint8       parameter_id;
    gint         offset = 0;
    gint         parameters_length;
    gint         parameter_length;

    parameters_length = tvb_reported_length(tvb);

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset,
                tvb_captured_length_remaining(tvb, offset), "Parameter: 0x%02x", parameter_id);
        parameter_tree = proto_item_add_subtree(parameter_item, ett_obex_application_parameters);

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
dissect_obex_application_parameter_bt_bpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *item;
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    guint8       parameter_id;
    gint         offset = 0;
    gint         parameters_length;
    gint         parameter_length;

    parameters_length = tvb_reported_length(tvb);

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_length = tvb_get_guint8(tvb, offset + 1);

        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset, parameter_length + 2,
                "Parameter: %s", val_to_str_const(parameter_id,
                bpp_application_parameters_vals, "Unknown"));
        parameter_tree = proto_item_add_subtree(parameter_item, ett_obex_application_parameters);

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
dissect_obex_application_parameter_bt_bip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *item;
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    guint8       parameter_id;
    gint         offset = 0;
    gint         parameters_length;
    gint         parameter_length;
    static gint  required_length_map[] = {0, 2, 2, 1, 4, 4, 4, 1, 1, 16, 1};

    parameters_length = tvb_reported_length(tvb);

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_length = tvb_get_guint8(tvb, offset + 1);

        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset, parameter_length + 2,
                "Parameter: %s", val_to_str_const(parameter_id,
                bip_application_parameters_vals, "Unknown"));
        parameter_tree = proto_item_add_subtree(parameter_item, ett_obex_application_parameters);

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
dissect_obex_application_parameter_bt_pbap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *item;
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    guint8       parameter_id;
    gint         offset = 0;
    gint         parameters_length;
    gint         parameter_length;
    static gint  required_length_map[] = {0, 1, -1, 1, 2, 2, 8, 1, 2, 1, 16, 16, 8, 16, 1, 1};

    parameters_length = tvb_reported_length(tvb);

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_length = tvb_get_guint8(tvb, offset + 1);

        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset, parameter_length + 2,
                "Parameter: %s", val_to_str_const(parameter_id,
                pbap_application_parameters_vals, "Unknown"));
        parameter_tree = proto_item_add_subtree(parameter_item, ett_obex_application_parameters);

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
            case 0x01: /* Order */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_order, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 0x02: /* Search Value */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_search_value, tvb, offset, parameter_length, ENC_ASCII | ENC_NA);
                break;
            case 0x03: /* Search Attribute */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_search_attribute, tvb, offset, 1, ENC_BIG_ENDIAN);
                break;
            case 0x04: /* Max List Count */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_max_list_count, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x05: /* List Start Offset */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_list_start_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x06: /* Filter */
                proto_tree_add_bitmask(parameter_tree, tvb, offset, hf_pbap_application_parameter_data_filter, ett_obex_filter,  hfx_pbap_application_parameter_data_filter_1, ENC_BIG_ENDIAN);
                proto_tree_add_bitmask(parameter_tree, tvb, offset, hf_pbap_application_parameter_data_filter, ett_obex_filter,  hfx_pbap_application_parameter_data_filter_0, ENC_BIG_ENDIAN);
                break;
            case 0x07: /* Format */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_format, tvb, offset, 1, ENC_NA);
                break;
            case 0x08: /* Phonebook Size */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_phonebook_size, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x09: /* New Missed Calls */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_new_missed_calls, tvb, offset, 1, ENC_NA);
                break;
            case 0x0A: /* Primary Version Counter */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_primary_version_counter, tvb, offset, 16, ENC_NA);
                break;
            case 0x0B: /* Secondary Version Counter */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_secondary_version_counter, tvb, offset, 16, ENC_NA);
                break;
            case 0x0C: /* vCard Selector */
                proto_tree_add_bitmask(parameter_tree, tvb, offset, hf_pbap_application_parameter_vcard_selector, ett_obex_filter,  hfx_pbap_application_parameter_data_filter_1, ENC_BIG_ENDIAN);
                proto_tree_add_bitmask(parameter_tree, tvb, offset, hf_pbap_application_parameter_vcard_selector, ett_obex_filter,  hfx_pbap_application_parameter_data_filter_0, ENC_BIG_ENDIAN);
                break;
            case 0x0D: /* Database Identifier */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_database_identifier, tvb, offset, 16, ENC_NA);
                break;
            case 0x0E: /* vCard Selector Operator */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_vcard_selector_operator, tvb, offset, 1, ENC_NA);
                break;
            case 0x0F: /* Reset New Missed Calls */
                proto_tree_add_item(parameter_tree, hf_pbap_application_parameter_data_reset_new_missed_calls, tvb, offset, 1, ENC_NA);
                break;
            case 0x10: /* PBAP Supported Features */
                proto_tree_add_bitmask(parameter_tree, tvb, offset, hf_pbap_application_parameter_data_supported_features, ett_obex_parameter,  hfx_pbap_application_parameter_data_supported_features, ENC_BIG_ENDIAN);
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
dissect_obex_application_parameter_bt_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *item;
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    guint8       parameter_id;
    gint         offset = 0;
    gint         parameters_length;
    gint         parameter_length;
    static gint  required_length_map[] = {0, 2, 2, 1, -1, -1, 1, -1, -1, 1, 1, 1, 1, 1, 1, 1, 4, 2, 2, 1, 1, 1, 1, 1, 1, -1};

    parameters_length = tvb_reported_length(tvb);

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_length = tvb_get_guint8(tvb, offset + 1);

        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset, parameter_length + 2,
                "Parameter: %s", val_to_str_const(parameter_id,
                map_application_parameters_vals, "Unknown"));
        parameter_tree = proto_item_add_subtree(parameter_item, ett_obex_application_parameters);

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

static gint
dissect_obex_application_parameter_bt_gpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *item;
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    guint8       parameter_id;
    gint         offset = 0;
    gint         parameters_length;
    gint         parameter_length;
    static gint  required_length_map[] = {2, 2, 1, 1, 0, 2};

    parameters_length = tvb_reported_length(tvb);

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_length = tvb_get_guint8(tvb, offset + 1);

        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset, parameter_length + 2,
                "Parameter: %s", val_to_str_const(parameter_id,
                gpp_application_parameters_vals, "Unknown"));
        parameter_tree = proto_item_add_subtree(parameter_item, ett_obex_application_parameters);

        proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        item = proto_tree_add_item(parameter_tree, hf_application_parameter_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (parameter_id >= 0x41 && (guint8)(parameter_id - 0x41) < (sizeof(required_length_map)/sizeof(gint)) &&
                required_length_map[parameter_id - 0x41] != -1 &&
                required_length_map[parameter_id - 0x41] != parameter_length) {
            proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
            expert_add_info_format(pinfo, item, &ei_application_parameter_length_bad,
                    "According to the specification this parameter length should be %i, but there is %i",
                    required_length_map[parameter_id - 0x41], parameter_length);
        } else switch (parameter_id) {
            case 0x41: /* Max List Count */
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_max_list_count, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x42: /* List Start Offset */
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_list_start_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x43: /* Notification Status */
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_reserved_7, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_notification_status, tvb, offset, 1, ENC_NA);
                break;
            case 0x44: /* Instance ID */
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_instance_id, tvb, offset, 1, ENC_NA);
                break;
            case 0x46: /* Listing Size */
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_listing_size, tvb, offset, 2, ENC_BIG_ENDIAN);
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
dissect_obex_application_parameter_bt_ctn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item  *item;
    proto_item  *parameter_item;
    proto_tree  *parameter_tree;
    guint8       parameter_id;
    gint         offset = 0;
    gint         parameters_length;
    gint         parameter_length;
    static gint  required_length_map[] = {0, 1, 1, 1, -1, -1, 4, 1, 1, 4, -1, -1, 1, 1, -1};
    static gint  required_length_map_gpp[] = {2, 2, 1, 1, -1, 2};

    parameters_length = tvb_reported_length(tvb);

    while (parameters_length > 0) {
        parameter_id = tvb_get_guint8(tvb, offset);
        parameter_length = tvb_get_guint8(tvb, offset + 1);

        parameter_item = proto_tree_add_none_format(tree, hf_application_parameter, tvb, offset, parameter_length + 2,
                "Parameter: %s", val_to_str_const(parameter_id,
                ctn_application_parameters_vals, "Unknown"));
        parameter_tree = proto_item_add_subtree(parameter_item, ett_obex_application_parameters);

        proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        item = proto_tree_add_item(parameter_tree, hf_application_parameter_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (parameter_id < 0x41 && parameter_id < (sizeof(required_length_map)/sizeof(gint)) &&
                required_length_map[parameter_id] != -1 &&
                required_length_map[parameter_id] != parameter_length) {
            proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
            expert_add_info_format(pinfo, item, &ei_application_parameter_length_bad,
                    "According to the specification this parameter length should be %i, but there is %i",
                    required_length_map[parameter_id], parameter_length);
        } else if (parameter_id >= 0x41 && (guint8)(parameter_id - 0x41) < (sizeof(required_length_map_gpp)/sizeof(gint)) &&
                required_length_map[parameter_id - 0x41] != -1 &&
                required_length_map[parameter_id - 0x41] != parameter_length) {
            proto_tree_add_item(parameter_tree, hf_application_parameter_data, tvb, offset, parameter_length, ENC_NA);
            expert_add_info_format(pinfo, item, &ei_application_parameter_length_bad,
                    "According to the specification this parameter length should be %i, but there is %i",
                    required_length_map_gpp[parameter_id - 0x41], parameter_length);
        } else switch (parameter_id) {
            case 0x41: /* Max List Count */
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_max_list_count, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x42: /* List Start Offset */
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_list_start_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x43: /* Notification Status */
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_reserved_7, tvb, offset, 1, ENC_NA);
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_notification_status, tvb, offset, 1, ENC_NA);
                break;
            case 0x44: /* Instance ID */
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_instance_id, tvb, offset, 1, ENC_NA);
                break;
            case 0x46: /* Listing Size */
                proto_tree_add_item(parameter_tree, hf_gpp_application_parameter_data_listing_size, tvb, offset, 2, ENC_BIG_ENDIAN);
                break;
            case 0x01: /* Acoustic Alarm Status */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_acoustic_alarm_status, tvb, offset, 1, ENC_NA);
                break;
            case 0x02: /* Attachment */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_attachment, tvb, offset, 1, ENC_NA);
                break;
            case 0x03: /* Send */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_send, tvb, offset, 1, ENC_NA);
                break;
            case 0x04: /* Filter Period Begin */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_filter_period_begin, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
                break;
            case 0x05: /* Filter Period End */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_filter_period_end, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
                break;
            case 0x06: /* Parameter Mask */
                proto_tree_add_bitmask(parameter_tree, tvb, offset, hf_ctn_application_parameter_data_parameter_mask, ett_obex_filter,  hfx_ctn_application_parameter_data_parameter_mask, ENC_BIG_ENDIAN);
                break;
            case 0x07: /* Status Indicator */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_status_indicator, tvb, offset, 1, ENC_NA);
                break;
            case 0x08: /* Status Value */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_status_value, tvb, offset, 1, ENC_NA);
                break;
            case 0x09: /* Postpone Val */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_postpone_val, tvb, offset, 4, ENC_BIG_ENDIAN);
                break;
            case 0x0A: /* Email URI */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_email_uri, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
                break;
            case 0x0B: /* CSE Time */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_cse_time, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
                break;
            case 0x0C: /* Recurrent */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_recurrent, tvb, offset, 1, ENC_NA);
                break;
            case 0x0D: /* Attach ID */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_attach_id, tvb, offset, 1, ENC_NA);
                break;
            case 0x0E: /* Last Update */
                proto_tree_add_item(parameter_tree, hf_ctn_application_parameter_data_last_update, tvb, offset, parameter_length, ENC_NA | ENC_ASCII);
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
        gint profile, obex_last_opcode_data_t *obex_last_opcode_data,
        obex_proto_data_t *obex_proto_data)
{
    proto_tree *hdrs_tree   = NULL;
    proto_tree *hdr_tree    = NULL;
    proto_item *hdr         = NULL;
    proto_item *handle_item;
    tvbuff_t   *next_tvb;
    gint        new_offset;
    gint        item_length = 0;
    gint        value_length = 0;
    guint8      hdr_id, i;
    guint32     value;
    guint32     frame_number;
    guint8      tag;
    gchar      *str = NULL;

    if (tvb_reported_length_remaining(tvb, offset) > 0) {
        proto_item *hdrs;
        hdrs      = proto_tree_add_item(tree, hf_headers, tvb, offset, tvb_reported_length_remaining(tvb, offset), ENC_NA);
        hdrs_tree = proto_item_add_subtree(hdrs, ett_obex_hdrs);
    }
    else {
        return offset;
    }

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        hdr_id = tvb_get_guint8(tvb, offset);

        switch(0xC0 & hdr_id)
        {
            case 0x00: /* null terminated unicode */
                item_length = tvb_get_ntohs(tvb, offset + 1);
                value_length = item_length - 3;
                break;
            case 0x40:  /* byte sequence */
                item_length = tvb_get_ntohs(tvb, offset + 1);
                value_length = item_length - 3;
                break;
            case 0x80:  /* 1 byte */
                item_length = 1 + 1;
                value_length = 1;
                break;
            case 0xc0:  /* 4 bytes */
                item_length = 1 + 4;
                value_length = 4;
                break;
        }

        hdr = proto_tree_add_none_format(hdrs_tree, hf_header, tvb, offset, item_length, "%s",
                                  val_to_str_ext_const(hdr_id, &header_id_vals_ext, "Unknown"));
        hdr_tree = proto_item_add_subtree(hdr, ett_obex_hdr);

        proto_tree_add_bitmask_with_flags(hdr_tree, tvb, offset, hf_hdr_id, ett_obex_hdr_id,  hfx_hdr_id, ENC_NA, BMT_NO_APPEND);

        offset++;

        switch(0xC0 & hdr_id)
        {
            case 0x00: /* null terminated unicode */
                proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                switch (hdr_id) {
                case 0x01: /* Name */
                    proto_tree_add_item(hdr_tree, hf_name, tvb, offset, value_length, ENC_UCS_2 | ENC_BIG_ENDIAN);
                    if (!pinfo->fd->flags.visited && obex_last_opcode_data) {
                        if (obex_last_opcode_data->code == OBEX_CODE_VALS_SET_PATH)
                            obex_last_opcode_data->data.set_data.name = tvb_get_string_enc(wmem_file_scope(), tvb, offset, value_length, ENC_UCS_2 | ENC_BIG_ENDIAN);
                        else if (obex_last_opcode_data->code == OBEX_CODE_VALS_GET || obex_last_opcode_data->code == OBEX_CODE_VALS_PUT)
                            obex_last_opcode_data->data.get_put.name = tvb_get_string_enc(wmem_file_scope(), tvb, offset, value_length, ENC_UCS_2 | ENC_BIG_ENDIAN);
                    }
                    break;
                default:
                    proto_tree_add_item(hdr_tree, hf_hdr_val_unicode, tvb, offset, value_length, ENC_UCS_2 | ENC_BIG_ENDIAN);
                }
                str = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, value_length, ENC_UCS_2 | ENC_BIG_ENDIAN);
                proto_item_append_text(hdr_tree, ": \"%s\"", str);

                col_append_fstr(pinfo->cinfo, COL_INFO, " \"%s\"", str);
                offset += value_length;

                break;
            case 0x40:  /* byte sequence */
                proto_tree_add_item(hdr_tree, hf_hdr_length, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                switch (hdr_id) {
                case 0x4c: /* Application Parameters */
                    next_tvb = tvb_new_subset_length(tvb, offset, value_length);
                    if (!(new_offset = dissector_try_uint_new(obex_profile_table, profile, next_tvb, pinfo, hdr_tree, TRUE, NULL))) {
                        new_offset = call_dissector(raw_application_parameters_handle, next_tvb, pinfo, hdr_tree);
                    }
                    offset += new_offset;

                    break;
                case 0x4d: /* Authentication Challenge */
                    while (value_length) {
                        guint8       parameter_id;
                        guint8       sub_parameter_length;
                        proto_item  *parameter_item;
                        proto_tree  *parameter_tree;

                        parameter_id = tvb_get_guint8(tvb, offset);
                        sub_parameter_length = tvb_get_guint8(tvb, offset + 1);

                        parameter_item = proto_tree_add_none_format(hdr_tree, hf_authentication_parameter, tvb, offset,
                                2 + sub_parameter_length, "Tag: %s", val_to_str_const(parameter_id,
                                authentication_challenge_tag_vals, "Unknown"));
                        parameter_tree = proto_item_add_subtree(parameter_item, ett_obex_authentication_parameters);

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
                            break;
                        default:
                            proto_tree_add_item(parameter_tree, hf_authentication_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);
                            offset += sub_parameter_length;
                        }

                        value_length -= 2 + sub_parameter_length;
                    }
                    break;
                case 0x4e: /* Authentication Response */
                    while (value_length) {
                        guint8       parameter_id;
                        guint8       sub_parameter_length;
                        proto_item  *parameter_item;
                        proto_tree  *parameter_tree;

                        parameter_id = tvb_get_guint8(tvb, offset);
                        sub_parameter_length = tvb_get_guint8(tvb, offset + 1);

                        parameter_item = proto_tree_add_none_format(hdr_tree, hf_authentication_parameter, tvb, offset,
                                2 + sub_parameter_length, "Tag: %s", val_to_str_const(parameter_id,
                                authentication_response_tag_vals, "Unknown"));
                        parameter_tree = proto_item_add_subtree(parameter_item, ett_obex_authentication_parameters);

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
                            proto_tree_add_item(parameter_tree, hf_authentication_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);
                            offset += sub_parameter_length;
                            break;
                        }


                        value_length -= 2 + sub_parameter_length;
                    }
                    break;
                case 0x42: /* Type */
                    proto_tree_add_item(hdr_tree, hf_type, tvb, offset, value_length, ENC_ASCII | ENC_NA);
                    proto_item_append_text(hdr_tree, ": \"%s\"", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, value_length, ENC_ASCII));
                    if (!pinfo->fd->flags.visited && obex_last_opcode_data && (obex_last_opcode_data->code == OBEX_CODE_VALS_GET || obex_last_opcode_data->code == OBEX_CODE_VALS_PUT)) {
                        obex_last_opcode_data->data.get_put.type = tvb_get_string_enc(wmem_file_scope(), tvb, offset, value_length, ENC_ASCII | ENC_NA);
                    }
                    if (p_get_proto_data(pinfo->pool, pinfo, proto_obex, PROTO_DATA_MEDIA_TYPE) == NULL) {
                        guint8 *value_data;

                        value_data = tvb_get_string_enc(wmem_file_scope(), tvb, offset, value_length, ENC_ASCII | ENC_NA);

                        p_add_proto_data(pinfo->pool, pinfo, proto_obex, PROTO_DATA_MEDIA_TYPE, value_data);
                    }
                    offset += value_length;

                    break;
                case 0x44: /* Time (ISO8601) */
                    {
                    const guint8* time_str;
                    proto_tree_add_item_ret_string(hdr_tree, hf_time_iso8601, tvb, offset, value_length, ENC_ASCII | ENC_NA, wmem_packet_scope(), &time_str);
                    proto_item_append_text(hdr_tree, ": \"%s\"", time_str);

                    offset += value_length;
                    }
                    break;
                case 0x48: /* Body */
                case 0x49: /* End Of Body */
                    proto_tree_add_item(hdr_tree, hf_hdr_val_byte_seq, tvb, offset, value_length, ENC_NA);
                    next_tvb = tvb_new_subset_length(tvb, offset, value_length);

                    if (value_length > 0 && obex_last_opcode_data &&
                            (obex_last_opcode_data->code == OBEX_CODE_VALS_GET || obex_last_opcode_data->code == OBEX_CODE_VALS_PUT) &&
                            p_get_proto_data(pinfo->pool, pinfo, proto_obex, PROTO_DATA_MEDIA_TYPE) == NULL) {
                        guint8 *value_data;

                        value_data = obex_last_opcode_data->data.get_put.type;

                        p_add_proto_data(pinfo->pool, pinfo, proto_obex, PROTO_DATA_MEDIA_TYPE, value_data);
                    }
                    if (value_length > 0 && obex_last_opcode_data &&
                            (obex_last_opcode_data->code == OBEX_CODE_VALS_GET || obex_last_opcode_data->code == OBEX_CODE_VALS_PUT) &&
                            obex_last_opcode_data->data.get_put.type &&
                            dissector_try_string(media_type_dissector_table, obex_last_opcode_data->data.get_put.type, next_tvb, pinfo, tree, NULL) > 0) {
                        offset += value_length;
                    } else {
                        if (!tvb_strneql(tvb, offset, "<?xml", 5))
                        {
                            call_dissector(xml_handle, next_tvb, pinfo, tree);
                        } else if (is_ascii_str(tvb_get_ptr(tvb, offset, value_length), value_length)) {
                            proto_item_append_text(hdr_tree, ": \"%s\"", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, value_length, ENC_ASCII));
                            col_append_fstr(pinfo->cinfo, COL_INFO, " \"%s\"", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, value_length, ENC_ASCII));
                        }
                        offset += value_length;
                    }

                    break;
                case 0x46: /* Target */
                case 0x4a: /* Who */
                    handle_item = proto_tree_add_item(hdr_tree, hf_hdr_val_byte_seq, tvb, offset, value_length, ENC_NA);

                    if (value_length == 16) for (i = 0; target_vals[i].strptr != NULL; i++) {
                        if (tvb_memeql(tvb, offset, target_vals[i].value, target_vals[i].length) == 0) {
                            proto_item_append_text(handle_item, ": %s", target_vals[i].strptr);
                            proto_item_append_text(hdr_tree, ": %s", target_vals[i].strptr);

                            col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", target_vals[i].strptr);
                            if (!pinfo->fd->flags.visited) {
                                obex_profile_data_t  *obex_profile_data;

                                wmem_tree_key_t       key[6];
                                frame_number = pinfo->num;

                                key[0].length = 1;
                                key[0].key = &obex_proto_data->interface_id;
                                key[1].length = 1;
                                key[1].key = &obex_proto_data->adapter_id;
                                key[2].length = 1;
                                key[2].key = &obex_proto_data->chandle;
                                key[3].length = 1;
                                key[3].key = &obex_proto_data->channel;
                                key[4].length = 1;
                                key[4].key = &frame_number;
                                key[5].length = 0;
                                key[5].key = NULL;

                                obex_profile_data = wmem_new(wmem_file_scope(), obex_profile_data_t);
                                obex_profile_data->interface_id = obex_proto_data->interface_id;
                                obex_profile_data->adapter_id   = obex_proto_data->adapter_id;
                                obex_profile_data->chandle      = obex_proto_data->chandle;
                                obex_profile_data->channel      = obex_proto_data->channel;
                                obex_profile_data->profile      = target_to_profile[i];

                                wmem_tree_insert32_array(obex_profile, key, obex_profile_data);
                            }
                        }
                    }
                    offset += value_length;

                    break;
                case 0x47: /* HTTP */ {
                    next_tvb = tvb_new_subset_remaining(tvb, offset);

                    call_dissector(http_handle, next_tvb, pinfo, hdr_tree);

                    }
                    break;
                case 0x50: /* WAN UUID */
                    if (value_length == 2) {
                        proto_tree_add_item(hdr_tree, hf_wan_uuid, tvb, offset, 2, ENC_BIG_ENDIAN);
                        offset += 2;
                    } else {
                        proto_tree_add_item(hdr_tree, hf_hdr_val_byte_seq, tvb, offset, value_length, ENC_NA);
                        offset += value_length;
                    }

                    break;
                case 0x51: /* Object Class */
                    {
                    const guint8* obj_str;
                    proto_tree_add_item_ret_string(hdr_tree, hf_object_class, tvb, offset, value_length, ENC_ASCII | ENC_NA, wmem_packet_scope(), &obj_str);
                    proto_item_append_text(hdr_tree, ": \"%s\"", obj_str);

                    offset += value_length;
                    }
                    break;
                case 0x52: /* Session Parameter */
                    while (value_length) {
                        guint8       parameter_id;
                        guint8       sub_parameter_length;
                        proto_item  *parameter_item;
                        proto_tree  *parameter_tree;

                        parameter_id = tvb_get_guint8(tvb, offset);
                        sub_parameter_length = tvb_get_guint8(tvb, offset + 1);

                        parameter_item = proto_tree_add_none_format(hdr_tree, hf_session_parameter, tvb, offset,
                                2 + sub_parameter_length, "Tag: %s", val_to_str_const(parameter_id,
                                session_tag_vals, "Unknown"));
                        parameter_tree = proto_item_add_subtree(parameter_item, ett_obex_session_parameters);

                        proto_tree_add_item(parameter_tree, hf_session_parameter_tag, tvb, offset, 1, ENC_BIG_ENDIAN);
                        tag = tvb_get_guint8(tvb, offset);
                        offset += 1;

                        proto_tree_add_item(parameter_tree, hf_session_parameter_length, tvb, offset, 1, ENC_BIG_ENDIAN);
                        sub_parameter_length = tvb_get_guint8(tvb, offset);
                        offset += 1;

                        switch (tag) {
                        case 0x00: /* Device Address */
                            if (sub_parameter_length == 6) {
                                offset = dissect_bd_addr(hf_sender_bd_addr, pinfo, parameter_tree, tvb, offset, FALSE, obex_proto_data->interface_id, obex_proto_data->adapter_id, NULL);
                            } else {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);

                                offset += sub_parameter_length;
                            }

                            break;
                        case 0x01: /* Nonce */
                            if (sub_parameter_length >= 4 && sub_parameter_length <= 16) {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_nonce, tvb, offset, sub_parameter_length, ENC_NA);

                                offset += sub_parameter_length;
                            } else {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);

                                offset += sub_parameter_length;
                            }

                            break;
                        case 0x02: /* Session ID */
                            if (sub_parameter_length == 16) {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_session_id, tvb, offset, 16, ENC_NA);

                                offset += 16;
                            } else {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);

                                offset += sub_parameter_length;
                            }

                            break;
                        case 0x03: /* Next Sequence Number */
                            if (sub_parameter_length == 1) {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_next_sequence_number, tvb, offset, 1, ENC_NA);

                                offset += 1;
                            } else {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);

                                offset += sub_parameter_length;
                            }

                            break;
                        case 0x04: /* Timeout */
                            if (sub_parameter_length == 4) {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_timeout, tvb, offset, 4, ENC_BIG_ENDIAN);

                                offset += 4;
                            } else {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);

                                offset += sub_parameter_length;
                            }

                            break;
                        case 0x05: /* Session Opcode */
                            if (sub_parameter_length == 1) {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_opcode, tvb, offset, 1, ENC_NA);

                                offset += 1;
                            } else {
                                proto_tree_add_item(parameter_tree, hf_session_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);

                                offset += sub_parameter_length;
                            }

                            break;
                        default:
                            proto_tree_add_item(parameter_tree, hf_session_parameter_data, tvb, offset, sub_parameter_length, ENC_NA);
                            offset += sub_parameter_length;
                            break;
                        }


                        value_length -= 2 + sub_parameter_length;
                    }
                    break;
                default:
                    proto_tree_add_item(hdr_tree, hf_hdr_val_byte_seq, tvb, offset, value_length, ENC_NA);
                    offset += value_length;
                }

                break;
            case 0x80:  /* 1 byte */
                value = tvb_get_guint8(tvb, offset);

                switch (hdr_id) {
                case 0x94: /* Action */
                    proto_tree_add_item(hdr_tree, hf_hdr_val_action, tvb, offset, 1, ENC_NA);
                    proto_item_append_text(hdr_tree, ": %s", val_to_str_const(value, action_vals, "Unknown"));

                    break;
                case 0x97: /* Single Response Mode */
                    proto_tree_add_item(hdr_tree, hf_hdr_val_single_response_mode, tvb, offset, 1, ENC_NA);
                    proto_item_append_text(hdr_tree, ": %s", val_to_str_const(value, single_response_mode_vals, "Unknown"));

                    break;
                case 0x98: /* Single Response Mode Parameter */
                    proto_tree_add_item(hdr_tree, hf_hdr_val_single_response_mode_parameter, tvb, offset, 1, ENC_NA);
                    proto_item_append_text(hdr_tree, ": %s", val_to_str_const(value, single_response_mode_parameter_vals, "Unknown"));

                    break;
                case 0x93: /* Session Sequence Number */
                default:
                    proto_tree_add_item(hdr_tree, hf_hdr_val_byte, tvb, offset, 1, ENC_NA);
                    proto_item_append_text(hdr_tree, ": %i", value);
                }

                offset += 1;

                break;
            case 0xC0:  /* 4 bytes */
                switch (hdr_id) {
                case 0xC0: /* Count */
                    proto_item_append_text(hdr_tree, ": %i", tvb_get_ntohl(tvb, offset));
                    proto_tree_add_item(hdr_tree, hf_count, tvb, offset, 4, ENC_BIG_ENDIAN);

                    break;
                case 0xC3: /* Length */
                    proto_item_append_text(hdr_tree, ": %i", tvb_get_ntohl(tvb, offset));
                    proto_tree_add_item(hdr_tree, hf_data_length, tvb, offset, 4, ENC_BIG_ENDIAN);

                    break;
                case 0xCB: /* Connection Id */
                    proto_item_append_text(hdr_tree, ": %i", tvb_get_ntohl(tvb, offset));
                    proto_tree_add_item(hdr_tree, hf_connection_id, tvb, offset, 4, ENC_BIG_ENDIAN);

                    break;
                case 0xC4: /* Time */
                case 0xCF: /* Creator */
                case 0xD6: /* Permissions */
                default:
                    proto_item_append_text(hdr_tree, ": %i", tvb_get_ntohl(tvb, offset));
                    proto_tree_add_item(hdr_tree, hf_hdr_val_long, tvb, offset, 4, ENC_BIG_ENDIAN);
                }

                offset += 4;

                break;
            default:
                break;
        }
    }

    return offset;
}

static gint
dissect_obex(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item    *main_item;
    proto_tree    *main_tree;
    proto_item    *sub_item;
    fragment_head *frag_msg       = NULL;
    gboolean       save_fragmented;
    gboolean       complete;
    tvbuff_t*      new_tvb        = NULL;
    tvbuff_t*      next_tvb       = NULL;
    gint           offset         = 0;
    gint           profile        = PROFILE_UNKNOWN;
    const gchar   *path           = path_unknown;
    obex_profile_data_t      *obex_profile_data;
    wmem_tree_key_t           key[6];
    guint32                   frame_number;
    obex_last_opcode_data_t  *obex_last_opcode_data;
    obex_path_data_t         *obex_path_data;
    guint32                   length;
    guint8                   *profile_data;
    dissector_handle_t        current_handle;
    dissector_handle_t        default_handle;
    gint                      previous_proto;
    obex_proto_data_t         obex_proto_data;

    previous_proto = (GPOINTER_TO_INT(wmem_list_frame_data(wmem_list_frame_prev(wmem_list_tail(pinfo->layers)))));
    if (previous_proto == proto_btl2cap) {
        btl2cap_data_t  *l2cap_data;

        l2cap_data = (btl2cap_data_t *) data;

        obex_proto_data.interface_id = l2cap_data->interface_id;
        obex_proto_data.adapter_id   = l2cap_data->adapter_id;
        obex_proto_data.chandle      = l2cap_data->chandle;
        obex_proto_data.channel      = l2cap_data->cid;
    } else if (previous_proto == proto_btrfcomm) {
        btrfcomm_data_t  *rfcomm_data;

        rfcomm_data = (btrfcomm_data_t *) data;

        obex_proto_data.interface_id = rfcomm_data->interface_id;
        obex_proto_data.adapter_id   = rfcomm_data->adapter_id;
        obex_proto_data.chandle      = rfcomm_data->chandle;
        obex_proto_data.channel      = rfcomm_data->dlci >> 1;
    } else {
        obex_proto_data.interface_id = HCI_INTERFACE_DEFAULT;
        obex_proto_data.adapter_id   = HCI_ADAPTER_DEFAULT;
        obex_proto_data.chandle      = 0;
        obex_proto_data.channel      = 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OBEX");

    main_item = proto_tree_add_item(tree, proto_obex, tvb, 0, tvb_captured_length(tvb), ENC_NA);
    main_tree = proto_item_add_subtree(main_item, ett_obex);

    save_fragmented = pinfo->fragmented;

    frame_number = pinfo->num;

    key[0].length = 1;
    key[0].key = &obex_proto_data.interface_id;
    key[1].length = 1;
    key[1].key = &obex_proto_data.adapter_id;
    key[2].length = 1;
    key[2].key = &obex_proto_data.chandle;
    key[3].length = 1;
    key[3].key = &obex_proto_data.channel;
    key[4].length = 1;
    key[4].key = &frame_number;
    key[5].length = 0;
    key[5].key = NULL;

    profile_data = (guint8 *) p_get_proto_data(pinfo->pool, pinfo, proto_obex, PROTO_DATA_OBEX_PROFILE);
    if (profile_data == NULL) {
        obex_profile_data = (obex_profile_data_t *)wmem_tree_lookup32_array_le(obex_profile, key);
        if (obex_profile_data && obex_profile_data->interface_id == obex_proto_data.interface_id &&
                obex_profile_data->adapter_id == obex_proto_data.adapter_id &&
                obex_profile_data->chandle == obex_proto_data.chandle &&
                obex_profile_data->channel == obex_proto_data.channel) {
            profile = obex_profile_data->profile;
        }

        profile_data = wmem_new(wmem_file_scope(), guint8);
        *profile_data = profile;

        p_add_proto_data(pinfo->pool, pinfo, proto_obex, PROTO_DATA_OBEX_PROFILE, profile_data);
    }

    obex_path_data = (obex_path_data_t *)wmem_tree_lookup32_array_le(obex_path, key);
    if (obex_path_data && obex_path_data->interface_id == obex_proto_data.interface_id &&
            obex_path_data->adapter_id == obex_proto_data.adapter_id &&
            obex_path_data->chandle == obex_proto_data.chandle &&
            obex_path_data->channel == obex_proto_data.channel) {
        path = obex_path_data->path;
      }

    sub_item = proto_tree_add_uint(main_tree, hf_profile, tvb, 0, 0, profile);
    PROTO_ITEM_SET_GENERATED(sub_item);

    if (path) {
        sub_item = proto_tree_add_string(main_tree, hf_current_path, tvb, 0, 0, path);
        PROTO_ITEM_SET_GENERATED(sub_item);
    }

    current_handle = dissector_get_uint_handle(obex_profile_table, profile);
    default_handle = dissector_get_default_uint_handle("obex.profile", profile);
    if (current_handle != default_handle) {
        expert_add_info_format(pinfo, main_item, &ei_decoded_as_profile, "Decoded As %s", dissector_handle_get_long_name(current_handle));
    }

    complete = FALSE;

    if (tvb_captured_length(tvb) == tvb_reported_length(tvb)) {
        frag_msg = fragment_get_reassembled_id(&obex_reassembly_table, pinfo, pinfo->p2p_dir);
        if (frag_msg && pinfo->num != frag_msg->reassembled_in) {
            /* reassembled but not last */

            new_tvb = process_reassembled_data(tvb, 0, pinfo,
                    "Reassembled Obex packet", frag_msg, &obex_frag_items, NULL, main_tree);
        } else if (frag_msg && pinfo->num == frag_msg->reassembled_in) {
            /* reassembled and last, so dissect reassembled packet here */

            new_tvb = process_reassembled_data(tvb, 0, pinfo,
                    "Reassembled Obex packet", frag_msg, &obex_frag_items, NULL, main_tree);
        } else {
            frag_msg = fragment_get(&obex_reassembly_table, pinfo, pinfo->p2p_dir, NULL);

            if (frag_msg) {
                /* not the first fragment */

                /* packet stream is guaranted to be sequence of fragments, one by one,
                   so find last fragment for its offset and length */
                while (frag_msg->next) {
                    frag_msg = frag_msg->next;
                }

                frag_msg = fragment_add_check(&obex_reassembly_table,
                        tvb, 0, pinfo, pinfo->p2p_dir, NULL,
                        frag_msg->offset + frag_msg->len, tvb_reported_length(tvb),
                                ((frag_msg->offset + frag_msg->len + tvb_reported_length(tvb)) <
                                    fragment_get_tot_len(&obex_reassembly_table, pinfo, pinfo->p2p_dir, NULL)) ? TRUE : FALSE);

                new_tvb = process_reassembled_data(tvb, 0, pinfo,
                        "Reassembled Obex packet", frag_msg, &obex_frag_items, NULL, main_tree);

                pinfo->fragmented = TRUE;
            } else {
                if (tvb_reported_length(tvb) < 3) {
                    /* Packet length is in the second and the third bye of packet, anything shorter than 3 is bad */
                    col_add_fstr(pinfo->cinfo, COL_INFO, "%s OBEX packet too short",
                                (pinfo->p2p_dir==P2P_DIR_SENT) ? "Sent" : "Rcvd");
                    call_dissector(data_handle, tvb, pinfo, main_tree);
                    return tvb_reported_length(tvb);
                } else if (tvb_reported_length(tvb) >= 3 && tvb_reported_length(tvb) < tvb_get_ntohs(tvb, offset+1)) {
                    /* first fragment in a sequence */
                    frag_msg = fragment_add_check(&obex_reassembly_table,
                                        tvb, 0, pinfo, pinfo->p2p_dir, NULL,
                                        0, tvb_reported_length(tvb), TRUE);

                    fragment_set_tot_len(&obex_reassembly_table,
                                        pinfo, pinfo->p2p_dir, NULL,
                                        tvb_get_ntohs(tvb, offset + 1));

                    new_tvb = process_reassembled_data(tvb, 0, pinfo,
                                "Reassembled Obex packet", frag_msg, &obex_frag_items, NULL, main_tree);
                    pinfo->fragmented = TRUE;
                } else if (tvb_reported_length(tvb) == tvb_get_ntohs(tvb, offset+1)) {
                    /* non-fragmented */
                    complete = TRUE;
                    pinfo->fragmented = FALSE;
                }
            }
        }
    }

    if (new_tvb) { /* take it all */
        next_tvb = new_tvb;
        complete = TRUE;
    } else { /* make a new subset */
        next_tvb = tvb_new_subset_remaining(tvb, offset);
    }

    if (complete) {
        guint8       code;
        guint8       final_flag;

        /* fully dissectable packet ready */

        /* op/response code */
        code = tvb_get_guint8(next_tvb, offset) & OBEX_CODE_VALS_MASK;
        final_flag = tvb_get_guint8(next_tvb, offset) & 0x80;

        switch (pinfo->p2p_dir) {
            case P2P_DIR_SENT:
                col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
                break;
            case P2P_DIR_RECV:
                col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
                break;
            default:
                col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
                break;
        }

        col_append_str(pinfo->cinfo, COL_INFO,
                        val_to_str_ext_const(code, &code_vals_ext, "Unknown"));

        if (code < OBEX_CODE_VALS_CONTINUE || code == OBEX_CODE_VALS_ABORT) {
            proto_tree_add_item(main_tree, hf_opcode, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            if (!pinfo->fd->flags.visited &&
                    (pinfo->p2p_dir == P2P_DIR_SENT ||
                    pinfo->p2p_dir == P2P_DIR_RECV)) {
                frame_number = pinfo->num;

                key[0].length = 1;
                key[0].key = &obex_proto_data.interface_id;
                key[1].length = 1;
                key[1].key = &obex_proto_data.adapter_id;
                key[2].length = 1;
                key[2].key = &obex_proto_data.chandle;
                key[3].length = 1;
                key[3].key = &obex_proto_data.channel;
                key[4].length = 1;
                key[4].key = &frame_number;
                key[5].length = 0;
                key[5].key = NULL;

                obex_last_opcode_data = wmem_new0(wmem_file_scope(), obex_last_opcode_data_t);
                obex_last_opcode_data->interface_id      = obex_proto_data.interface_id;
                obex_last_opcode_data->adapter_id        = obex_proto_data.adapter_id;
                obex_last_opcode_data->chandle           = obex_proto_data.chandle;
                obex_last_opcode_data->channel           = obex_proto_data.channel;
                obex_last_opcode_data->code              = code;
                obex_last_opcode_data->final_flag        = final_flag;
                obex_last_opcode_data->request_in_frame  = frame_number;
                obex_last_opcode_data->response_in_frame = 0;

                wmem_tree_insert32_array(obex_last_opcode, key, obex_last_opcode_data);
            }
        } else {
            proto_tree_add_item(main_tree, hf_response_code, next_tvb, offset, 1, ENC_BIG_ENDIAN);
        }

        proto_tree_add_item(main_tree, hf_final_flag, next_tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        /* length */
        proto_tree_add_item(main_tree, hf_length, next_tvb, offset, 2, ENC_BIG_ENDIAN);
        length = tvb_get_ntohs(tvb, offset) - 3;
        offset += 2;

        frame_number = pinfo->num;

        key[0].length = 1;
        key[0].key = &obex_proto_data.interface_id;
        key[1].length = 1;
        key[1].key = &obex_proto_data.adapter_id;
        key[2].length = 1;
        key[2].key = &obex_proto_data.chandle;
        key[3].length = 1;
        key[3].key = &obex_proto_data.channel;
        key[4].length = 1;
        key[4].key = &frame_number;
        key[5].length = 0;
        key[5].key = NULL;

        obex_last_opcode_data = (obex_last_opcode_data_t *)wmem_tree_lookup32_array_le(obex_last_opcode, key);
        if (obex_last_opcode_data && obex_last_opcode_data->interface_id == obex_proto_data.interface_id &&
                obex_last_opcode_data->adapter_id == obex_proto_data.adapter_id &&
                obex_last_opcode_data->chandle == obex_proto_data.chandle &&
                obex_last_opcode_data->channel == obex_proto_data.channel) {
            if (obex_last_opcode_data->request_in_frame > 0 && obex_last_opcode_data->request_in_frame != pinfo->num) {
                sub_item = proto_tree_add_uint(main_tree, hf_request_in_frame, next_tvb, 0, 0, obex_last_opcode_data->request_in_frame);
                PROTO_ITEM_SET_GENERATED(sub_item);
            }

            if (!pinfo->fd->flags.visited && obex_last_opcode_data->response_in_frame == 0 && obex_last_opcode_data->request_in_frame < pinfo->num) {
                obex_last_opcode_data->response_in_frame = pinfo->num;
            }

            if (obex_last_opcode_data->response_in_frame > 0 && obex_last_opcode_data->response_in_frame != pinfo->num) {
                sub_item = proto_tree_add_uint(main_tree, hf_response_in_frame, next_tvb, 0, 0, obex_last_opcode_data->response_in_frame);
                PROTO_ITEM_SET_GENERATED(sub_item);
            }
        }

        switch(code)
        {
        case OBEX_CODE_VALS_CONNECT:
            proto_tree_add_item(main_tree, hf_version, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(main_tree, hf_flags, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(main_tree, hf_max_pkt_len, next_tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;

        case OBEX_CODE_VALS_PUT:
        case OBEX_CODE_VALS_GET:
            col_append_fstr(pinfo->cinfo, COL_INFO, " %s",  (final_flag == 0x80) ? "final" : "continue");
            break;

        case OBEX_CODE_VALS_SET_PATH:
            proto_tree_add_item(main_tree, hf_flags, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(main_tree, hf_set_path_flags_0, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(main_tree, hf_set_path_flags_1, next_tvb, offset, 1, ENC_BIG_ENDIAN);

            if (!pinfo->fd->flags.visited && obex_last_opcode_data) {
                obex_last_opcode_data->data.set_data.go_up = tvb_get_guint8(tvb, offset) & 0x01;
                obex_last_opcode_data->data.set_data.name = NULL;
            }

            offset++;

            proto_tree_add_item(main_tree, hf_constants, next_tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;

        case OBEX_CODE_VALS_DISCONNECT:
        case OBEX_CODE_VALS_ABORT:
            break;

        default:
            if (length == 0 && tvb_reported_length_remaining(tvb, offset) > 0) {
                proto_tree_add_expert(main_tree, pinfo, &ei_unexpected_data, tvb, offset, tvb_reported_length_remaining(tvb, offset));
                offset += tvb_reported_length_remaining(tvb, offset);
                break;
            } else if (length == 0) break;

            if (obex_last_opcode_data &&  obex_last_opcode_data->code == OBEX_CODE_VALS_CONNECT) {
                proto_tree_add_item(main_tree, hf_version, next_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;

                proto_tree_add_item(main_tree, hf_flags, next_tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;

                proto_tree_add_item(main_tree, hf_max_pkt_len, next_tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                if (!pinfo->fd->flags.visited)
                    save_path(pinfo, path, "", FALSE, &obex_proto_data);
            }
            break;
        }

        dissect_headers(main_tree, next_tvb, offset, pinfo, profile, obex_last_opcode_data, &obex_proto_data);
        if (!pinfo->fd->flags.visited &&
                    obex_last_opcode_data &&
                    obex_last_opcode_data->data.set_data.name &&
                    obex_last_opcode_data->code == OBEX_CODE_VALS_SET_PATH &&
                    code == OBEX_CODE_VALS_SUCCESS) {
            save_path(pinfo, path, obex_last_opcode_data->data.set_data.name, obex_last_opcode_data->data.set_data.go_up, &obex_proto_data);
        }
    } else {
        /* packet fragment */
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s OBEX fragment",
                     (pinfo->p2p_dir==P2P_DIR_SENT) ? "Sent" : "Rcvd");
        call_dissector(data_handle, next_tvb, pinfo, main_tree);

        offset = tvb_reported_length(tvb);
    }

    pinfo->fragmented = save_fragmented;

    return offset;
}


void
proto_register_obex(void)
{
    module_t        *module;
    expert_module_t *expert_obex;
    int              proto_raw;
    int              proto_bpp;
    int              proto_bip;
    int              proto_map;
    int              proto_bt_gpp;
    int              proto_bt_ctn;
    int              proto_bt_pbap;

    static hf_register_info hf[] = {
        { &hf_opcode,
          { "Opcode", "obex.opcode",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &code_vals_ext, OBEX_CODE_VALS_MASK,
            "Request Opcode", HFILL}
        },
        { &hf_response_code,
          { "Response Code", "obex.resp_code",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &code_vals_ext, OBEX_CODE_VALS_MASK,
            NULL, HFILL}
        },
        { &hf_final_flag,
          { "Final Flag", "obex.final_flag",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL}
        },
        { &hf_length,
          { "Packet Length", "obex.pkt_len",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_version,
          { "Version", "obex.version",
            FT_UINT8, BASE_HEX, VALS(version_vals), 0x00,
            "Obex Protocol Version", HFILL}
        },
        { &hf_flags,
          { "Flags", "obex.flags",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_constants,
          { "Constants", "obex.constants",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_max_pkt_len,
          { "Max. Packet Length", "obex.max_pkt_len",
            FT_UINT16, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_set_path_flags_0,
          { "Go back one folder (../) first", "obex.set_path_flags_0",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_set_path_flags_1,
          { "Do not create folder, if not existing", "obex.set_path_flags_1",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_headers,
          { "Headers", "obex.headers",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_header,
          { "Header", "obex.header",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_hdr_id,
          { "Header Id", "obex.header.id",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &header_id_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_hdr_id_encoding,
          { "Encoding", "obex.header.id.encoding",
            FT_UINT8, BASE_HEX, VALS(header_id_encoding_vals), 0xC0,
            NULL, HFILL}
        },
        { &hf_hdr_id_meaning,
          { "Meaning", "obex.header.id.meaning",
            FT_UINT8, BASE_HEX, VALS(header_id_meaning_vals), 0x3F,
            NULL, HFILL}
        },
        { &hf_hdr_length,
          { "Length", "obex.header.length",
            FT_UINT16, BASE_DEC, NULL, 0,
            "Header Length", HFILL}
        },
        { &hf_hdr_val_unicode,
          { "Value", "obex.header.value.unicode",
            FT_STRING, BASE_NONE, NULL, 0,
            "Unicode Value", HFILL }
        },
        { &hf_hdr_val_byte_seq,
          { "Value", "obex.header.value.byte_sequence",
            FT_BYTES, BASE_NONE, NULL, 0,
            "Byte Sequence Value", HFILL}
        },
        { &hf_hdr_val_byte,
          { "Value", "obex.header.value.byte",
            FT_UINT8, BASE_DEC_HEX, NULL, 0,
            "Byte Value", HFILL}
        },
        { &hf_hdr_val_long,
          { "Value", "obex.header.value.long",
            FT_UINT32, BASE_DEC, NULL, 0,
            "4-byte Value", HFILL}
        },
        { &hf_count,
          { "Count", "obex.count",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_data_length,
          { "Length", "obex.length",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_connection_id,
          { "Connection ID", "obex.connection_id",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_session_parameter,
          { "Session Parameter", "obex.session",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_session_parameter_data,
          { "Parameter Value", "obex.session.value",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_session_parameter_tag,
          { "Tag", "obex.session.tag",
            FT_UINT8, BASE_HEX, VALS(session_tag_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_session_parameter_length,
          { "Length", "obex.session.length",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_session_parameter_nonce,
          { "Nonce", "obex.session.nonce",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_session_parameter_session_id,
          { "Session ID", "obex.session.session_id",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_session_parameter_next_sequence_number,
          { "Next Sequence Number", "obex.session.next_sequence_number",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_session_parameter_timeout,
          { "Timeout", "obex.session.timeout",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_session_parameter_opcode,
          { "Opcode", "obex.session.opcode",
            FT_UINT8, BASE_HEX, VALS(session_opcode_vals), 0,
            NULL, HFILL}
        },
        { &hf_authentication_parameter,
          { "Authentication Parameter", "obex.authentication",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_authentication_parameter_data,
          { "Parameter Value", "obex.authentication.value",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_authentication_challenge_tag,
          { "Tag", "obex.authentication.challenge_tag",
            FT_UINT8, BASE_HEX, VALS(authentication_challenge_tag_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_authentication_response_tag,
          { "Tag", "obex.authentication.response_tag",
            FT_UINT8, BASE_HEX, VALS(authentication_response_tag_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_authentication_length,
          { "Length", "obex.authentication.length",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_authentication_key,
          { "Key", "obex.authentication.key",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_authentication_result_key,
          { "Result Key", "obex.authentication.result_key",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_authentication_user_id,
          { "User Id", "obex.authentication.user_id",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_authentication_option_reserved,
          { "Reserved", "obex.authentication.option.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL}
        },
        { &hf_authentication_option_read_only,
          { "Read Only", "obex.authentication.option.read_only",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_authentication_option_user_id,
          { "User ID", "obex.authentication.option.user_id",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_authentication_info_charset,
          { "Charset", "obex.authentication.info.charset",
            FT_UINT8, BASE_HEX, VALS(info_charset_vals), 0,
            NULL, HFILL}
        },
        { &hf_authentication_info,
          { "Info", "obex.authentication.info",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_application_parameter,
          { "Parameter", "obex.parameter",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_application_parameter_id,
          { "Parameter Id", "obex.parameter.id",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_application_parameter_length,
          { "Parameter Length", "obex.parameter.length",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL}
        },
        { &hf_application_parameter_data,
          { "Parameter Value", "obex.parameter.value",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        /* application parameters for BPP */
        { &hf_bpp_application_parameter_id,
          { "Parameter Id", "obex.parameter.id",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bpp_application_parameters_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_bpp_application_parameter_data_offset,
          { "Offset", "obex.parameter.value.offset",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "The byte offset into the image or file.", HFILL}
        },
        { &hf_bpp_application_parameter_data_count,
          { "Count", "obex.parameter.value.count",
            FT_INT32, BASE_DEC, NULL, 0,
            "The number of bytes of the image or file to be sent.", HFILL}
        },
        { &hf_bpp_application_parameter_data_job_id,
          { "Job ID", "obex.parameter.value.job_id",
            FT_UINT32, BASE_DEC_HEX, NULL, 0,
            "The job identifier of the print job.", HFILL}
        },
        { &hf_bpp_application_parameter_data_file_size,
          { "File Size", "obex.parameter.value.file_size",
            FT_INT32, BASE_DEC, NULL, 0,
            "The size (in bytes) of object or file.", HFILL}
        },
        /* application parameters for BIP */
        { &hf_bip_application_parameter_id,
          { "Parameter Id", "obex.parameter.id",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &bip_application_parameters_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_bip_application_parameter_data_number_of_returned_handles,
            { "Number of Returned Handles",   "obex.parameter.value.number_of_returned_handles",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_list_start_offset,
            { "List Start Offset",   "obex.parameter.value.list_start_offset",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_latest_captured_images,
            { "Latest Captured Images",   "obex.parameter.value.latest_captured_images",
            FT_BOOLEAN, 8, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_partial_file_length,
            { "Partial File Length",   "obex.parameter.value.partial_file_length",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_partial_file_start_offset,
            { "Partial File Start Offset",   "obex.parameter.value.partial_file_start_offset",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_total_file_size,
            { "Total File Size",   "obex.parameter.value.total_file_size",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_end_flag,
            { "End Flag",   "obex.parameter.value.end_flag",
            FT_BOOLEAN, 8, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_remote_display,
            { "Remote Display",   "obex.parameter.value.remote_display",
            FT_UINT8, BASE_HEX, VALS(bip_remote_display_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_service_id,
            { "Service ID",   "obex.parameter.value.service_id",
            FT_UINT16, BASE_HEX | BASE_EXT_STRING, &bluetooth_uuid_vals_ext, 0x00,
            NULL, HFILL }
        },
        { &hf_bip_application_parameter_data_store_flag,
            { "Store Flag",   "obex.parameter.value.store_flag",
            FT_BOOLEAN, 8, NULL, 0x00,
            NULL, HFILL }
        },
        /* application parameters for PBAP */
        { &hf_pbap_application_parameter_id,
          { "Parameter Id", "obex.parameter.id",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &pbap_application_parameters_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_order,
          { "Max List Count", "obex.parameter.value.order",
            FT_UINT8, BASE_HEX, VALS(pbap_order_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_search_value,
          { "Search Value", "obex.parameter.value.search_value",
            FT_STRING, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_search_attribute,
          { "Search Attribute", "obex.parameter.value.search_attribute",
            FT_UINT8, BASE_HEX, VALS(pbap_search_attribute_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_max_list_count,
          { "Max List Count", "obex.parameter.value.max_list_count",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_list_start_offset,
          { "List Start Offset", "obex.parameter.value.list_start_offset",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter,
          { "Filter", "obex.parameter.value.filter",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_vcard_selector,
          { "vCard Selector", "obex.parameter.value.filter",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_version,
          { "vCard Version", "obex.parameter.value.filter.version",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_fn,
          { "Formatted Name", "obex.parameter.value.filter.fn",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_n,
          { "Structured Presentation of Name", "obex.parameter.value.filter.n",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_photo,
          { "Associated Image or Photo", "obex.parameter.value.filter.photo",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_birthday,
          { "Birthday", "obex.parameter.value.filter.birthday",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_adr,
          { "Delivery Address", "obex.parameter.value.filter.adr",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_label,
          { "Delivery", "obex.parameter.value.filter.label",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_tel,
          { "Telephone Number", "obex.parameter.value.filter.tel",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_email,
          { "Electronic Mail Address", "obex.parameter.value.filter.email",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_mailer,
          { "Electronic Mail", "obex.parameter.value.filter.mailer",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_time_zone,
          { "Time Zone", "obex.parameter.value.filter.time_zone",
            FT_BOOLEAN, 32, NULL, 0x00000400,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_geographic_position,
          { "Geographic Position", "obex.parameter.value.filter.geographic_position",
            FT_BOOLEAN, 32, NULL, 0x00000800,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_title,
          { "Job", "obex.parameter.value.filter.title",
            FT_BOOLEAN, 32, NULL, 0x00001000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_role,
          { "Role within the Organization", "obex.parameter.value.filter.role",
            FT_BOOLEAN, 32, NULL, 0x00002000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_logo,
          { "Organization Logo", "obex.parameter.value.filter.logo",
            FT_BOOLEAN, 32, NULL, 0x00004000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_agent,
          { "vCard of Person Representing", "obex.parameter.value.filter.agent",
            FT_BOOLEAN, 32, NULL, 0x00008000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_name_of_organization,
          { "Name of Organization", "obex.parameter.value.filter.name_of_organization",
            FT_BOOLEAN, 32, NULL, 0x00010000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_comments,
          { "Comments", "obex.parameter.value.filter.comments",
            FT_BOOLEAN, 32, NULL, 0x00020000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_revision,
          { "Revision", "obex.parameter.value.filter.revision",
            FT_BOOLEAN, 32, NULL, 0x00040000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_pronunciation_of_name,
          { "Pronunciation of Name", "obex.parameter.value.filter.pronunciation_of_name",
            FT_BOOLEAN, 32, NULL, 0x00080000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_url,
          { "Uniform Resource Locator", "obex.parameter.value.filter.url",
            FT_BOOLEAN, 32, NULL, 0x00100000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_uid,
          { "Unique ID", "obex.parameter.value.filter.uid",
            FT_BOOLEAN, 32, NULL, 0x00200000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_key,
          { "Public Encryption Key", "obex.parameter.value.filter.key",
            FT_BOOLEAN, 32, NULL, 0x00400000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_nickname,
          { "Nickname", "obex.parameter.value.filter.nickname",
            FT_BOOLEAN, 32, NULL, 0x00800000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_categories,
          { "Categories", "obex.parameter.value.filter.categories",
            FT_BOOLEAN, 32, NULL, 0x01000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_product_id,
          { "Product ID", "obex.parameter.value.filter.product_id",
            FT_BOOLEAN, 32, NULL, 0x02000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_class,
          { "Class Information", "obex.parameter.value.filter.class",
            FT_BOOLEAN, 32, NULL, 0x04000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_sort_string,
          { "String Used For Sorting Operations", "obex.parameter.value.filter.sort_string",
            FT_BOOLEAN, 32, NULL, 0x08000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_timestamp,
          { "Timestamp", "obex.parameter.value.filter.timestamp",
            FT_BOOLEAN, 32, NULL, 0x10000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_reserved_29_31,
          { "Reserved", "obex.parameter.value.filter.reserved_29_31",
            FT_UINT32, BASE_HEX, NULL, 0xE0000000,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_reserved_32_38,
          { "Reserved", "obex.parameter.value.filter.reserved_32_38",
            FT_UINT32, BASE_HEX, NULL, 0x0000007F,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_proprietary_filter,
          { "Proprietary Filter", "obex.parameter.value.filter.proprietary_filter",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_filter_reserved_for_proprietary_filter_usage,
          { "Reserved for Proprietary Filter Usage", "obex.parameter.value.filter.reserved_for_proprietary_filter_usage",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFFF00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_format,
          { "Format", "obex.parameter.value.format",
            FT_UINT8, BASE_HEX, VALS(pbap_format_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_phonebook_size,
          { "Phonebook Size", "obex.parameter.value.phonebook_size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_new_missed_calls,
          { "New Missed Calls", "obex.parameter.value.new_missed_calls",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_primary_version_counter,
          { "Primary Version Counter", "obex.parameter.value.primary_version_counter",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_secondary_version_counter,
          { "Secondary Version Counter", "obex.parameter.value.secondary_version_counter",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_database_identifier,
          { "Database Identifier", "obex.parameter.value.database_identifier",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_vcard_selector_operator,
          { "vCard Selector Operator", "obex.parameter.value.vcard_selector_operator",
            FT_UINT8, BASE_HEX, VALS(pbap_application_parameter_data_vcard_selector_operator_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_reset_new_missed_calls,
          { "vCard Selector Operator", "obex.parameter.value.reset_new_missed_calls",
            FT_UINT8, BASE_HEX, VALS(pbap_application_parameter_data_reset_new_missed_calls_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_pbap_application_parameter_data_supported_features,
            { "Supported Features",              "obex.parameter.supported_features",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_reserved,
            { "Reserved",                        "obex.parameter.supported_features.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFFC00,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_default_contact_image_format,
            { "Default Contact Image Format",    "obex.parameter.supported_features.default_contact_image_format",
            FT_BOOLEAN, 32, NULL, 0x00000200,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_contact_referencing,
            { "Contact Referencing",             "obex.parameter.supported_features.contact_referencing",
            FT_BOOLEAN, 32, NULL, 0x00000100,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_x_bt_uid_vcard_property,
            { "X-BT-UID vCard Property",         "obex.parameter.supported_features.x_bt_uid_vcard_property",
            FT_BOOLEAN, 32, NULL, 0x00000080,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_x_bt_uci_vcard_property,
            { "X-BT-UCI vCard Property",         "obex.parameter.supported_features.x_bt_uci_vcard_property",
            FT_BOOLEAN, 32, NULL, 0x00000040,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_enhanced_missed_calls,
            { "Enhanced Missed Calls",           "obex.parameter.supported_features.enhanced_missed_calls",
            FT_BOOLEAN, 32, NULL, 0x00000020,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_vcard_selecting,
            { "vCard Selecting",                 "obex.parameter.supported_features.vcard_selecting",
            FT_BOOLEAN, 32, NULL, 0x00000010,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_folder_version_counters,
            { "Folder Version Counters",         "obex.parameter.supported_features.folder_version_counters",
            FT_BOOLEAN, 32, NULL, 0x00000008,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_database_identifier,
            { "Database Identifier",             "obex.parameter.supported_features.database_identifier",
            FT_BOOLEAN, 32, NULL, 0x00000004,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_browsing,
            { "Browsing",                        "obex.parameter.supported_features.browsing",
            FT_BOOLEAN, 32, NULL, 0x00000002,
            NULL, HFILL }
        },
        { &hf_pbap_application_parameter_data_supported_features_download,
            { "Download",                        "obex.parameter.supported_features.download",
            FT_BOOLEAN, 32, NULL, 0x00000001,
            NULL, HFILL }
        },
        /* application parameters for MAP */
        { &hf_map_application_parameter_id,
          { "Parameter Id", "obex.parameter.id",
            FT_UINT8, BASE_HEX | BASE_EXT_STRING, &map_application_parameters_vals_ext, 0x00,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_max_list_count,
          { "Max List Count", "obex.parameter.value.max_list_count",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_start_offset,
          { "Start Offset", "obex.parameter.value.start_offset",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_message_type_reserved,
          { "Reserved", "obex.parameter.value.filter_message_type.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_message_type_mms,
          { "MMS", "obex.parameter.value.filter_message_type.mms",
            FT_BOOLEAN, 8, NULL, 0x08,
            "True to filter out, False to listing this type", HFILL}
        },
        { &hf_map_application_parameter_data_filter_message_type_email,
          { "EMAIL", "obex.parameter.value.filter_message_type.sms_email",
            FT_BOOLEAN, 8, NULL, 0x04,
            "True to filter out, False to listing this type", HFILL}
        },
        { &hf_map_application_parameter_data_filter_message_type_sms_cdma,
          { "SMS_CDMA", "obex.parameter.value.filter_message_type.sms_cdma",
            FT_BOOLEAN, 8, NULL, 0x02,
            "True to filter out, False to listing this type", HFILL}
        },
        { &hf_map_application_parameter_data_filter_message_type_sms_gsm,
          { "SMS_GSM", "obex.parameter.value.filter_message_type.sms_gsm",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_period_begin,
          { "Filter Period Begin", "obex.parameter.value.filter_period_begin",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_period_end,
          { "Filter Period End", "obex.parameter.value.filter_period_end",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_read_status_reserved_6,
          { "Filter Read Status: Reserved", "obex.parameter.value.filter_read_status.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_read_status_get_read,
          { "Filter Read Status: Get Read", "obex.parameter.value.filter_read_status.get_read",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_read_status_get_unread,
          { "Filter Read Status: Get Unread", "obex.parameter.value.filter_read_status.get_unread",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_recipient,
          { "Filter Recipient", "obex.parameter.value.filter_recipient",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_originator,
          { "Filter Originator", "obex.parameter.value.filter_originator",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_priority_reserved_6,
          { "Filter Priority: Reserved", "obex.parameter.value.filter_priority.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_priority_get_high,
          { "Filter Priority: Get Read", "obex.parameter.value.filter_priority.get_high",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_filter_priority_non_high,
          { "Filter Priority: Get Non High", "obex.parameter.value.filter_priority.non_high",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_reserved_7,
          { "Reserved", "obex.parameter.value.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_attachment,
          { "Attachment", "obex.parameter.value.attachment",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_transparent,
          { "Transparent", "obex.parameter.value.transparent",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_retry,
          { "Retry", "obex.parameter.value.retry",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_new_message,
          { "New Message", "obex.parameter.value.new_message",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_notification_status,
          { "Notification Status", "obex.parameter.value.notification_status",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_mas_instance_id,
          { "MAS Instance ID", "obex.parameter.value.mas_instance_id",
            FT_UINT8, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_reserved,
          { "Parameter Mask: Reserved", "obex.parameter.value.parameter_mask.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFF0000,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_reply_to_addressing,
          { "Parameter Mask: Reply to Addressing", "obex.parameter.value.parameter_mask.reply_to_addressing",
            FT_BOOLEAN, 32, NULL, 0x8000,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_protected,
          { "Parameter Mask: Protected", "obex.parameter.value.parameter_mask.protected",
            FT_BOOLEAN, 32, NULL, 0x4000,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_sent,
          { "Parameter Mask: Sent", "obex.parameter.value.parameter_mask.sent",
            FT_BOOLEAN, 32, NULL, 0x2000,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_read,
          { "Parameter Mask: Read", "obex.parameter.value.parameter_mask.read",
            FT_BOOLEAN, 32, NULL, 0x1000,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_priority,
          { "Parameter Mask: Priority", "obex.parameter.value.parameter_mask.priority",
            FT_BOOLEAN, 32, NULL, 0x0800,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_attachment_size,
          { "Parameter Mask: Attachment Size", "obex.parameter.value.parameter_mask.attachment_size",
            FT_BOOLEAN, 32, NULL, 0x0400,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_text,
          { "Parameter Mask: Text", "obex.parameter.value.parameter_mask.text",
            FT_BOOLEAN, 32, NULL, 0x0200,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_reception_status,
          { "Parameter Mask: Reception Status", "obex.parameter.value.parameter_mask.reception_status",
            FT_BOOLEAN, 32, NULL, 0x0100,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_size,
          { "Parameter Mask: Size", "obex.parameter.value.parameter_mask.size",
            FT_BOOLEAN, 32, NULL, 0x0080,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_type,
          { "Parameter Mask: Type", "obex.parameter.value.parameter_mask.type",
            FT_BOOLEAN, 32, NULL, 0x0040,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_recipient_addressing,
          { "Parameter Mask: Recipient Addressing", "obex.parameter.value.parameter_mask.recipient_addressing",
            FT_BOOLEAN, 32, NULL, 0x0020,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_recipient_name,
          { "Parameter Mask: Recipient Name", "obex.parameter.value.parameter_mask.recipient_name",
            FT_BOOLEAN, 32, NULL, 0x0010,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_sender_addressing,
          { "Parameter Mask: Sender Addressing", "obex.parameter.value.parameter_mask.sender_addressing",
            FT_BOOLEAN, 32, NULL, 0x0008,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_sender_name,
          { "Parameter Mask: Sender Name", "obex.parameter.value.parameter_mask.sender_name",
            FT_BOOLEAN, 32, NULL, 0x0004,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_datetime,
          { "Parameter Mask: Datetime", "obex.parameter.value.parameter_mask.datetime",
            FT_BOOLEAN, 32, NULL, 0x0002,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_parameter_mask_subject,
          { "Parameter Mask: Subject", "obex.parameter.value.parameter_mask.subject",
            FT_BOOLEAN, 32, NULL, 0x0001,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_folder_listing_size,
          { "Folder Listing Size", "obex.parameter.value.folder_listing_size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_messages_listing_size,
          { "Messages Listing Size", "obex.parameter.value.messages_listing_size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_subject_length,
          { "Subject Length", "obex.parameter.value.subject_length",
            FT_UINT8, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_charset,
          { "Charset", "obex.parameter.value.charset",
            FT_UINT8, BASE_HEX, VALS(map_charset_vals), 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_fraction_request,
          { "Fraction Request", "obex.parameter.value.fraction_request",
            FT_UINT8, BASE_HEX, VALS(map_fraction_request_vals), 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_fraction_deliver,
          { "Fraction Deliver", "obex.parameter.value.fraction_deliver",
            FT_UINT8, BASE_HEX, VALS(map_fraction_deliver_vals), 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_status_indicator,
          { "Status Indicator", "obex.parameter.value.status_indicator",
            FT_UINT8, BASE_HEX, VALS(map_status_indicator_vals), 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_status_value,
          { "Status Value", "obex.parameter.value.status_value",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_map_application_parameter_data_mse_time,
          { "MSE Time", "obex.parameter.value.mse_time",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL}
        },
        /* application parameters for GPP */
        { &hf_gpp_application_parameter_id,
          { "Parameter Id", "obex.parameter.gpp.id",
            FT_UINT8, BASE_HEX, VALS(gpp_application_parameters_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_gpp_application_parameter_data_max_list_count,
          { "Max List Count", "obex.parameter.gpp.value.max_list_count",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_gpp_application_parameter_data_list_start_offset,
          { "List Start Offset", "obex.parameter.gpp.value.list_start_offset",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_gpp_application_parameter_data_reserved_7,
          { "Reserved", "obex.parameter.gpp.value.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            NULL, HFILL}
        },
        { &hf_gpp_application_parameter_data_notification_status,
          { "Notification Status", "obex.parameter.gpp.value.notification_status",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        { &hf_gpp_application_parameter_data_instance_id,
          { "Instance ID", "obex.parameter.gpp.value.instance_id",
            FT_UINT8, BASE_DEC_HEX, NULL, 0,
            NULL, HFILL}
        },
        { &hf_gpp_application_parameter_data_listing_size,
          { "Listing Size", "obex.parameter.gpp.value.listing_size",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        /* application parameters for CTN */
        { &hf_ctn_application_parameter_id,
          { "Parameter Id", "obex.parameter.ctn.id",
            FT_UINT8, BASE_HEX, VALS(ctn_application_parameters_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_acoustic_alarm_status,
          { "Acoustic Alarm Status", "obex.parameter.ctn.acoustic_alarm_status",
            FT_UINT8, BASE_HEX, VALS(off_on_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_attachment,
          { "Attachment", "obex.parameter.ctn.attachment",
            FT_UINT8, BASE_HEX, VALS(ctn_application_parameter_data_attachment_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_send,
          { "Attachment", "obex.parameter.ctn.attachment",
            FT_UINT8, BASE_HEX, VALS(no_yes_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_filter_period_begin,
          { "Filter Period Begin", "obex.parameter.ctn.filter_period_begin",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_filter_period_end,
          { "Filter Period End", "obex.parameter.ctn.filter_period_end",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask,
          { "Parameter Mask", "obex.parameter.ctn.parameter_mask",
            FT_UINT32, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_reserved,
          { "Reserved", "obex.parameter.ctn.parameter_mask.reserved",
            FT_UINT32, BASE_HEX, NULL, 0xFFFFFC00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_recurrent,
          { "Recurrent", "obex.parameter.ctn.parameter_mask.recurrent",
            FT_UINT32, BASE_HEX, NULL, 0x00000200,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_send_status,
          { "Send Status", "obex.parameter.ctn.parameter_mask.send_status",
            FT_UINT32, BASE_HEX, NULL, 0x00000100,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_alarm_status,
          { "Alarm Status", "obex.parameter.ctn.parameter_mask.",
            FT_UINT32, BASE_HEX, NULL, 0x00000080,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_pstatus,
          { "pStatus", "obex.parameter.ctn.parameter_mask.pstatus",
            FT_UINT32, BASE_HEX, NULL, 0x00000040,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_priority,
          { "Priority", "obex.parameter.ctn.parameter_mask.priority",
            FT_UINT32, BASE_HEX, NULL, 0x00000020,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_originator_address,
          { "Originator Address", "obex.parameter.ctn.parameter_mask.originator_address",
            FT_UINT32, BASE_HEX, NULL, 0x00000010,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_originator_name,
          { "Originator Name", "obex.parameter.ctn.parameter_mask.originator_name",
            FT_UINT32, BASE_HEX, NULL, 0x00000008,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_end_time,
          { "End Time", "obex.parameter.ctn.parameter_mask.end_time",
            FT_UINT32, BASE_HEX, NULL, 0x00000004,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_summary,
          { "Summary", "obex.parameter.ctn.parameter_mask.summary",
            FT_UINT32, BASE_HEX, NULL, 0x00000002,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_parameter_mask_attachment,
          { "Attachment", "obex.parameter.ctn.parameter_mask.attachment",
            FT_UINT32, BASE_HEX, NULL, 0x00000001,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_status_indicator,
          { "Status Indicator", "obex.parameter.ctn.status_indicator",
            FT_UINT8, BASE_HEX, VALS(ctn_application_parameter_data_status_indicator_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_status_value,
          { "Status Value", "obex.parameter.ctn.status_value",
            FT_UINT8, BASE_HEX, VALS(ctn_application_parameter_data_status_value_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_postpone_val,
          { "Postpone Val", "obex.parameter.ctn.postpone_val",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_email_uri,
          { "Email URI", "obex.parameter.ctn.email_uri",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_cse_time,
          { "CSE Time", "obex.parameter.ctn.cse_time",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_recurrent,
          { "Recurrent", "obex.parameter.ctn.recurrent",
            FT_UINT8, BASE_HEX, VALS(no_yes_vals), 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_attach_id,
          { "Attach ID", "obex.parameter.ctn.attach_id",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL}
        },
        { &hf_ctn_application_parameter_data_last_update,
          { "Last Update", "obex.parameter.ctn.last_update",
            FT_STRING, STR_ASCII, NULL, 0x00,
            NULL, HFILL}
        },
        /* for fragmentation */
        { &hf_obex_fragment_overlap,
          { "Fragment overlap",   "obex.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment overlaps with other fragments", HFILL }
        },
        { &hf_obex_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap",   "obex.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }
        },
        { &hf_obex_fragment_multiple_tails,
          { "Multiple tail fragments found",  "obex.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }
        },
        { &hf_obex_fragment_too_long_fragment,
          { "Fragment too long",  "obex.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }
        },
        { &hf_obex_fragment_error,
          { "Defragmentation error", "obex.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Defragmentation error due to illegal fragments", HFILL }
        },
        { &hf_obex_fragment_count,
          { "Fragment count", "obex.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_obex_fragment,
          { "OBEX Fragment", "obex.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_obex_fragments,
          { "OBEX Fragments", "obex.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_obex_reassembled_in,
          { "Reassembled OBEX in frame", "obex.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This OBEX frame is reassembled in this frame", HFILL }
        },
        { &hf_obex_reassembled_length,
          { "Reassembled OBEX length", "obex.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }
        },
        { &hf_profile,
          { "Profile", "obex.profile", FT_UINT32, BASE_DEC | BASE_EXT_STRING, &profile_vals_ext, 0x0,
            "Blutooth Profile used in this OBEX session", HFILL }
        },
        { &hf_type,
          { "Type", "obex.type", FT_STRINGZ, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_object_class,
          { "Object Class", "obex.object_class", FT_STRINGZ, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_time_iso8601,
          { "Time", "obex.time", FT_STRINGZ, STR_ASCII, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_hdr_val_action,
          { "Action", "obex.action", FT_UINT8, BASE_DEC, VALS(action_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_hdr_val_single_response_mode,
          { "Single Response Mode", "obex.single_response_mode", FT_UINT8, BASE_DEC, VALS(single_response_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_hdr_val_single_response_mode_parameter,
          { "Single Response Mode Parameter", "obex.single_response_mode_parameter", FT_UINT8, BASE_DEC, VALS(single_response_mode_parameter_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_wan_uuid,
            { "WAN UUID",   "obex.wan_uuid",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_sender_bd_addr,
            { "Sender Address", "obex.sender_bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_name,
          { "Name", "obex.name",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_current_path,
          { "Current Path", "obex.current_path",
            FT_STRINGZ, BASE_NONE, NULL, 0,
            NULL, HFILL }
        },
        { &hf_request_in_frame,
          { "Request in Frame", "obex.request_in_frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
            NULL, HFILL}
        },
        { &hf_response_in_frame,
          { "Response in Frame", "obex.response_in_frame", FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
            NULL, HFILL}
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_obex,
        &ett_obex_hdrs,
        &ett_obex_hdr,
        &ett_obex_hdr_id,
        &ett_obex_filter,
        &ett_obex_parameter,
        &ett_obex_fragment,
        &ett_obex_fragments,
        &ett_obex_session_parameters,
        &ett_obex_application_parameters,
        &ett_obex_authentication_parameters
    };

    static ei_register_info ei[] = {
        { &ei_application_parameter_length_bad, { "obex.parameter.length.bad", PI_PROTOCOL, PI_WARN, "Parameter length bad", EXPFILL }},
        { &ei_unexpected_data, { "obex.expert.unexpected_data", PI_PROTOCOL, PI_WARN, "Unexpected data", EXPFILL }},
        { &ei_decoded_as_profile, { "obex.expert.decoded_as.profile", PI_PROTOCOL, PI_NOTE, "Decoded As", EXPFILL }},
    };

    /* Decode As handling */
    static build_valid_func obex_profile_da_build_value[1] = {obex_profile_value};
    static decode_as_value_t obex_profile_da_values = {obex_profile_prompt, 1, obex_profile_da_build_value};
    static decode_as_t obex_profile_da = {"obex", "OBEX Profile", "obex.profile", 1, 0, &obex_profile_da_values, NULL, NULL,
            decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    static build_valid_func media_type_da_build_value[1] = {media_type_value};
    static decode_as_value_t media_type_da_values = {media_type_prompt, 1, media_type_da_build_value};
    static decode_as_t media_type_da = {"obex", "Media Type", "media_type",
            1, 0, &media_type_da_values, NULL, NULL,
            decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};


    obex_path        = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    obex_profile     = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    obex_last_opcode = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    proto_obex = proto_register_protocol("OBEX Protocol", "OBEX", "obex");

    obex_handle = register_dissector("obex", dissect_obex, proto_obex);

    obex_profile_table = register_dissector_table("obex.profile", "OBEX Profile", proto_obex, FT_UINT8, BASE_DEC);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_obex, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_obex = expert_register_protocol(proto_obex);
    expert_register_field_array(expert_obex, ei, array_length(ei));

    register_init_routine(&defragment_init);
    register_cleanup_routine(&defragment_cleanup);

    register_decode_as(&obex_profile_da);

    proto_raw = proto_register_protocol("OBEX Raw Application Parameters", "Raw Application Parameters", "obex.parameter.raw");
    raw_application_parameters_handle  = register_dissector("obex.parameter.raw",  dissect_obex_application_parameter_raw, proto_raw);

    proto_bpp = proto_register_protocol("Bluetooth OBEX BPP Application Parameters", "BT BPP Application Parameters", "obex.parameter.bt.bpp");
    bt_bpp_application_parameters_handle  = register_dissector("obex.parameter.bt.bpp",  dissect_obex_application_parameter_bt_bpp, proto_bpp);

    proto_bip = proto_register_protocol("Bluetooth OBEX BIP Application Parameters", "BT BIP Application Parameters", "obex.parameter.bt.bip");
    bt_bip_application_parameters_handle  = register_dissector("obex.parameter.bt.bip",  dissect_obex_application_parameter_bt_bip, proto_bip);

    proto_map = proto_register_protocol("Bluetooth OBEX MAP Application Parameters", "BT MAP Application Parameters", "obex.parameter.bt.map");
    bt_map_application_parameters_handle  = register_dissector("obex.parameter.bt.map",  dissect_obex_application_parameter_bt_map, proto_map);

    proto_bt_gpp = proto_register_protocol("Bluetooth OBEX GPP Application Parameters", "BT GPP Application Parameters", "obex.parameter.bt.gpp");
    bt_gpp_application_parameters_handle  = register_dissector("obex.parameter.bt.gpp",  dissect_obex_application_parameter_bt_gpp, proto_bt_gpp);

    proto_bt_ctn = proto_register_protocol("Bluetooth OBEX CTN Application Parameters", "BT CTN Application Parameters", "obex.parameter.bt.ctn");
    bt_ctn_application_parameters_handle  = register_dissector("obex.parameter.bt.ctn",  dissect_obex_application_parameter_bt_ctn, proto_bt_ctn);

    proto_bt_pbap = proto_register_protocol("Bluetooth OBEX PBAP Application Parameters", "BT PBAP Application Parameters", "obex.parameter.bt.pbap");
    bt_pbap_application_parameters_handle = register_dissector("obex.parameter.bt.pbap", dissect_obex_application_parameter_bt_pbap, proto_bt_pbap);

    register_decode_as(&media_type_da);

    module = prefs_register_protocol(proto_obex, NULL);
    prefs_register_static_text_preference(module, "supported_bluetooth_profiles",
            "Protocol OBEX support Bluetooth profiles: BIP 1.2, BPP 1.2, CTN 1.0, FTP 1.3, GOEP 1.3, GPP 1.0, MAP 1.2, OPP 1.2, PBAP 1.2, SYNCH 1.2",
            "Versions of Bluetooth profiles supported by this dissector.");
}

void
proto_reg_handoff_obex(void)
{
    dissector_add_string("bluetooth.uuid",  "1104",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1105",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1106",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1107",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1118",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1119",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "111a",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "111b",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "111c",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "111d",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1120",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1121",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1122",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1123",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "112e",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "112f",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1130",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1132",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1133",  obex_handle);
    dissector_add_string("bluetooth.uuid",  "1134",  obex_handle);

    http_handle = find_dissector_add_dependency("http", proto_obex);
    xml_handle  = find_dissector_add_dependency("xml", proto_obex);
    data_handle = find_dissector("data");
    data_text_lines_handle = find_dissector("data-text-lines");

    dissector_add_uint("obex.profile", PROFILE_UNKNOWN,  raw_application_parameters_handle);
    dissector_add_uint("obex.profile", PROFILE_BPP,      bt_bpp_application_parameters_handle);
    dissector_add_uint("obex.profile", PROFILE_BIP,      bt_bip_application_parameters_handle);
    dissector_add_uint("obex.profile", PROFILE_CTN,      bt_ctn_application_parameters_handle);
    dissector_add_uint("obex.profile", PROFILE_GPP,      bt_gpp_application_parameters_handle);
    dissector_add_uint("obex.profile", PROFILE_MAP,      bt_map_application_parameters_handle);
    dissector_add_uint("obex.profile", PROFILE_PBAP,     bt_pbap_application_parameters_handle);

    dissector_add_uint("obex.profile", PROFILE_OPP,      raw_application_parameters_handle);
    dissector_add_uint("obex.profile", PROFILE_FTP,      raw_application_parameters_handle);
    dissector_add_uint("obex.profile", PROFILE_SYNCML,   raw_application_parameters_handle);
    dissector_add_uint("obex.profile", PROFILE_SYNC,     raw_application_parameters_handle);

    dissector_add_for_decode_as("btrfcomm.dlci", obex_handle);
    dissector_add_for_decode_as("btl2cap.psm", obex_handle);
    dissector_add_for_decode_as("btl2cap.cid", obex_handle);

    /* PBAP */
    dissector_add_string("media_type", "x-bt/phonebook",      data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/vcard",          data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/vcard-listing",  xml_handle);
    /* MAP */
    dissector_add_string("media_type", "x-bt/message",                       data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/messageStatus",                 data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/MAP-messageUpdate",             data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/MAP-NotificationRegistration",  data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/MASInstanceInformation",        data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/MAP-msg-listing",               xml_handle);
    dissector_add_string("media_type", "x-bt/MAP-event-report",              xml_handle);
    dissector_add_string("media_type", "x-obex/folder-listing",              xml_handle);
    /* CTN */
    dissector_add_string("media_type", "x-bt/CTN-EventReport",              xml_handle);
    dissector_add_string("media_type", "x-bt/CTN-Listing",                  xml_handle);
    dissector_add_string("media_type", "x-bt/CTN-NotificationRegistration", data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/Calendar",                     data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/CalendarStatus",               data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/CTN-forward",                  data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/InstanceDescription",          data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/Update",                       data_text_lines_handle);
    /* BPP */
    dissector_add_string("media_type", "text/x-ref-simple",                 data_text_lines_handle);
    dissector_add_string("media_type", "text/x-ref-list",                   data_text_lines_handle);
    dissector_add_string("media_type", "x-obex/RUI",                        data_text_lines_handle);
    dissector_add_string("media_type", "x-obex/bt-SOAP",                    xml_handle);
    /* BIP */
    dissector_add_string("media_type", "x-bt/img-listing",                  xml_handle);
    dissector_add_string("media_type", "x-bt/img-properties",               xml_handle);
    dissector_add_string("media_type", "x-bt/img-capabilities",             xml_handle);
    dissector_add_string("media_type", "x-bt/img-print",                    data_text_lines_handle);
    dissector_add_string("media_type", "x-bt/img-img",                      data_handle);
    dissector_add_string("media_type", "x-bt/img-thm",                      data_handle);
    dissector_add_string("media_type", "x-bt/img-attachment",               data_handle);
    dissector_add_string("media_type", "x-bt/img-display",                  data_handle);
    dissector_add_string("media_type", "x-bt/img-partial",                  data_handle);
    dissector_add_string("media_type", "x-bt/img-archive",                  data_handle);
    dissector_add_string("media_type", "x-bt/img-status",                   data_handle);
    dissector_add_string("media_type", "x-bt/img-monitoring",               data_handle);

    media_type_dissector_table = find_dissector_table("media_type");

    dissector_add_for_decode_as("usb.product",  obex_handle);
    dissector_add_for_decode_as("usb.device",   obex_handle);
    dissector_add_for_decode_as("usb.protocol", obex_handle);
    dissector_add_for_decode_as("tcp.port",     obex_handle);
    dissector_add_for_decode_as("udp.port",     obex_handle);
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
