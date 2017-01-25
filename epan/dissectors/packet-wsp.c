/* packet-wsp.c
 *
 * Routines to dissect WSP component of WAP traffic.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter.
 *
 * WTLS support by Alexandre P. Ferreira (Splice IP).
 *
 * Openwave header support by Dermot Bradley (Openwave).
 *
 * Code optimizations, header value dissection simplification with parse error
 * notification and macros, extra missing headers, WBXML registration,
 * summary line of WSP PDUs,
 * Session Initiation Request dissection
 * by Olivier Biot.
 *
 * TODO - Move parts of dissection before and other parts after "if (tree)",
 * for example skip almost all but content type in replies if tree is closed.
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
#include <epan/to_str.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <epan/iana_charsets.h>

#include <wsutil/str_util.h>

#include "packet-wap.h"
#include "packet-wsp.h"

/* Statistics (see doc/README.tapping) */
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>

void proto_register_wsp(void);
void proto_reg_handoff_wsp(void);
void proto_register_sir(void);
void proto_reg_handoff_sir(void);

static int wsp_tap = -1;


/* File scoped variables for the protocol and registered fields */
static int proto_wsp                                    = -1;
static int proto_sir                                    = -1;

/*
 * Initialize the header field pointers
 */

/* WSP header fields and their subfields if available */
static int hf_hdr_name_value                            = -1;
static int hf_hdr_name_string                           = -1;
static int hf_hdr_accept                                = -1;
static int hf_hdr_accept_charset                        = -1;
static int hf_hdr_accept_encoding                       = -1;
static int hf_hdr_accept_language                       = -1;
static int hf_hdr_accept_ranges                         = -1;
static int hf_hdr_age                                   = -1;
static int hf_hdr_allow                                 = -1;
static int hf_hdr_authorization                         = -1;
static int hf_hdr_authorization_scheme                  = -1; /* Subfield */
static int hf_hdr_authorization_user_id                 = -1; /* Subfield */
static int hf_hdr_authorization_password                = -1; /* Subfield */
static int hf_hdr_cache_control                         = -1;
static int hf_hdr_connection                            = -1;
static int hf_hdr_content_base                          = -1;
static int hf_hdr_content_encoding                      = -1;
static int hf_hdr_content_language                      = -1;
static int hf_hdr_content_length                        = -1;
static int hf_hdr_content_location                      = -1;
static int hf_hdr_content_md5                           = -1;
static int hf_hdr_content_range                         = -1;
static int hf_hdr_content_range_first_byte_pos          = -1; /* Subfield */
static int hf_hdr_content_range_entity_length           = -1; /* Subfield */
static int hf_hdr_content_type                          = -1;
static int hf_hdr_date                                  = -1;
static int hf_hdr_etag                                  = -1;
static int hf_hdr_expires                               = -1;
static int hf_hdr_from                                  = -1;
static int hf_hdr_host                                  = -1;
static int hf_hdr_if_modified_since                     = -1;
static int hf_hdr_if_match                              = -1;
static int hf_hdr_if_none_match                         = -1;
static int hf_hdr_if_range                              = -1;
static int hf_hdr_if_unmodified_since                   = -1;
static int hf_hdr_last_modified                         = -1;
static int hf_hdr_location                              = -1;
static int hf_hdr_max_forwards                          = -1;
static int hf_hdr_pragma                                = -1;
static int hf_hdr_proxy_authenticate                    = -1;
static int hf_hdr_proxy_authenticate_scheme             = -1; /* Subfield */
static int hf_hdr_proxy_authenticate_realm              = -1; /* Subfield */
static int hf_hdr_proxy_authorization                   = -1;
static int hf_hdr_proxy_authorization_scheme            = -1; /* Subfield */
static int hf_hdr_proxy_authorization_user_id           = -1; /* Subfield */
static int hf_hdr_proxy_authorization_password          = -1; /* Subfield */
static int hf_hdr_public                                = -1;
static int hf_hdr_range                                 = -1;
static int hf_hdr_range_first_byte_pos                  = -1; /* Subfield */
static int hf_hdr_range_last_byte_pos                   = -1; /* Subfield */
static int hf_hdr_range_suffix_length                   = -1; /* Subfield */
static int hf_hdr_referer                               = -1;
static int hf_hdr_retry_after                           = -1;
static int hf_hdr_server                                = -1;
static int hf_hdr_transfer_encoding                     = -1;
static int hf_hdr_upgrade                               = -1;
static int hf_hdr_user_agent                            = -1;
static int hf_hdr_vary                                  = -1;
static int hf_hdr_via                                   = -1;
static int hf_hdr_warning                               = -1;
static int hf_hdr_warning_code                          = -1; /* Subfield */
static int hf_hdr_warning_agent                         = -1; /* Subfield */
static int hf_hdr_warning_text                          = -1; /* Subfield */
static int hf_hdr_www_authenticate                      = -1;
static int hf_hdr_www_authenticate_scheme               = -1; /* Subfield */
static int hf_hdr_www_authenticate_realm                = -1; /* Subfield */
static int hf_hdr_content_disposition                   = -1;
static int hf_hdr_application_id                        = -1;
static int hf_hdr_content_uri                           = -1;
static int hf_hdr_initiator_uri                         = -1;
static int hf_hdr_bearer_indication                     = -1;
static int hf_hdr_push_flag                             = -1;
static int hf_hdr_push_flag_auth                        = -1; /* Subfield */
static int hf_hdr_push_flag_trust                       = -1; /* Subfield */
static int hf_hdr_push_flag_last                        = -1; /* Subfield */
static int hf_hdr_profile                               = -1;
static int hf_hdr_profile_diff                          = -1;
static int hf_hdr_profile_warning                       = -1;
static int hf_hdr_expect                                = -1;
static int hf_hdr_te                                    = -1;
static int hf_hdr_trailer                               = -1;
static int hf_hdr_x_wap_tod                             = -1;
static int hf_hdr_content_id                            = -1;
static int hf_hdr_set_cookie                            = -1;
static int hf_hdr_cookie                                = -1;
static int hf_hdr_encoding_version                      = -1;
static int hf_hdr_x_wap_security                        = -1;
static int hf_hdr_x_wap_application_id                  = -1;
static int hf_hdr_accept_application                    = -1;


/* Openwave headers */
static int hf_hdr_openwave_default_int                  = -1;
static int hf_hdr_openwave_default_string               = -1;
static int hf_hdr_openwave_default_val_len              = -1;
static int hf_hdr_openwave_name_value                   = -1;
static int hf_hdr_openwave_x_up_proxy_operator_domain   = -1;
static int hf_hdr_openwave_x_up_proxy_home_page         = -1;
static int hf_hdr_openwave_x_up_proxy_uplink_version    = -1;
static int hf_hdr_openwave_x_up_proxy_ba_realm          = -1;
static int hf_hdr_openwave_x_up_proxy_request_uri       = -1;
#if 0
static int hf_hdr_openwave_x_up_proxy_client_id         = -1;
#endif
static int hf_hdr_openwave_x_up_proxy_bookmark          = -1;
static int hf_hdr_openwave_x_up_proxy_push_seq          = -1;
static int hf_hdr_openwave_x_up_proxy_notify            = -1;
static int hf_hdr_openwave_x_up_proxy_net_ask           = -1;
static int hf_hdr_openwave_x_up_proxy_tod               = -1;
static int hf_hdr_openwave_x_up_proxy_ba_enable         = -1;
static int hf_hdr_openwave_x_up_proxy_redirect_enable   = -1;
static int hf_hdr_openwave_x_up_proxy_redirect_status   = -1;
static int hf_hdr_openwave_x_up_proxy_linger            = -1;
static int hf_hdr_openwave_x_up_proxy_enable_trust      = -1;
static int hf_hdr_openwave_x_up_proxy_trust             = -1;
static int hf_hdr_openwave_x_up_devcap_has_color        = -1;
static int hf_hdr_openwave_x_up_devcap_num_softkeys     = -1;
static int hf_hdr_openwave_x_up_devcap_softkey_size     = -1;
static int hf_hdr_openwave_x_up_devcap_screen_chars     = -1;
static int hf_hdr_openwave_x_up_devcap_screen_pixels    = -1;
static int hf_hdr_openwave_x_up_devcap_em_size          = -1;
static int hf_hdr_openwave_x_up_devcap_screen_depth     = -1;
static int hf_hdr_openwave_x_up_devcap_immed_alert      = -1;
static int hf_hdr_openwave_x_up_devcap_gui              = -1;
static int hf_hdr_openwave_x_up_proxy_trans_charset     = -1;
static int hf_hdr_openwave_x_up_proxy_push_accept       = -1;


/* WSP parameter fields */
static int hf_parameter_q                               = -1;
static int hf_parameter_charset                         = -1;

/* Old header fields */

static int hf_wsp_header_tid                            = -1;
static int hf_wsp_header_pdu_type                       = -1;
static int hf_wsp_version_major                         = -1;
static int hf_wsp_version_minor                         = -1;
/* Session capabilities (CO-WSP) */
static int hf_capabilities_length                       = -1;
static int hf_capabilities_section                      = -1;
static int hf_capa_client_sdu_size                      = -1;
static int hf_capa_server_sdu_size                      = -1;
static int hf_capa_protocol_options                     = -1;
static int hf_capa_protocol_option_confirmed_push       = -1; /* Subfield */
static int hf_capa_protocol_option_push                 = -1; /* Subfield */
static int hf_capa_protocol_option_session_resume       = -1; /* Subfield */
static int hf_capa_protocol_option_ack_headers          = -1; /* Subfield */
static int hf_capa_protocol_option_large_data_transfer  = -1; /* Subfield */
static int hf_capa_method_mor                           = -1;
static int hf_capa_push_mor                             = -1;
static int hf_capa_extended_method                      = -1;
static int hf_capa_header_code_page                     = -1;
static int hf_capa_aliases                              = -1;
static int hf_capa_client_message_size                  = -1;
static int hf_capa_server_message_size                  = -1;

static int hf_wsp_header_uri_len                        = -1;
static int hf_wsp_header_uri                            = -1;
static int hf_wsp_server_session_id                     = -1;
static int hf_wsp_header_status                         = -1;
static int hf_wsp_header_length                         = -1;
static int hf_wsp_headers_section                       = -1;
static int hf_wsp_parameter_untype_quote_text           = -1;
static int hf_wsp_parameter_untype_text                 = -1;
static int hf_wsp_parameter_untype_int                  = -1;
static int hf_wsp_parameter_type                        = -1;
static int hf_wsp_parameter_int_type                    = -1;
static int hf_wsp_parameter_name                        = -1;
static int hf_wsp_parameter_filename                    = -1;
static int hf_wsp_parameter_start                       = -1;
static int hf_wsp_parameter_start_info                  = -1;
static int hf_wsp_parameter_comment                     = -1;
static int hf_wsp_parameter_domain                      = -1;
static int hf_wsp_parameter_path                        = -1;
static int hf_wsp_parameter_sec                         = -1;
static int hf_wsp_parameter_mac                         = -1;
static int hf_wsp_parameter_upart_type                  = -1;
static int hf_wsp_parameter_level                       = -1;
static int hf_wsp_parameter_size                        = -1;
#if 0
static int hf_wsp_reply_data                            = -1;
#endif
static int hf_wsp_post_data                             = -1;
#if 0
static int hf_wsp_push_data                             = -1;
static int hf_wsp_multipart_data                        = -1;
#endif
static int hf_wsp_mpart                                 = -1;
static int hf_wsp_header_text_value                     = -1;
static int hf_wsp_variable_value                        = -1;
static int hf_wsp_default_int                           = -1;
static int hf_wsp_default_string                        = -1;
static int hf_wsp_default_val_len                       = -1;

/* Header code page shift sequence */
static int hf_wsp_header_shift_code                     = -1;

/* WSP Redirect fields */
static int hf_wsp_redirect_flags                        = -1;
static int hf_wsp_redirect_permanent                    = -1;
static int hf_wsp_redirect_reuse_security_session       = -1;
static int hf_redirect_addresses                        = -1;

/* Address fields */
static int hf_address_entry                             = -1;
static int hf_address_flags_length                      = -1;
static int hf_address_flags_length_bearer_type_included = -1; /* Subfield */
static int hf_address_flags_length_port_number_included = -1; /* Subfield */
static int hf_address_flags_length_address_len          = -1; /* Subfield */
static int hf_address_bearer_type                       = -1;
static int hf_address_port_num                          = -1;
static int hf_address_ipv4_addr                         = -1;
static int hf_address_ipv6_addr                         = -1;
static int hf_address_addr                              = -1;

/* Session Initiation Request fields */
static int hf_sir_section                               = -1;
static int hf_sir_version                               = -1;
static int hf_sir_app_id_list_len                       = -1;
static int hf_sir_app_id_list                           = -1;
static int hf_sir_wsp_contact_points_len                = -1;
static int hf_sir_wsp_contact_points                    = -1;
static int hf_sir_contact_points_len                    = -1;
static int hf_sir_contact_points                        = -1;
static int hf_sir_protocol_options_len                  = -1;
static int hf_sir_protocol_options                      = -1;
static int hf_sir_prov_url_len                          = -1;
static int hf_sir_prov_url                              = -1;
static int hf_sir_cpi_tag_len                           = -1;
static int hf_sir_cpi_tag                               = -1;

/*
 * Initialize the subtree pointers
 */

/* WSP tree */
static int ett_wsp                      = -1;
/* WSP headers tree */
static int ett_header                   = -1;
/* WSP header subtree */
static int ett_headers                  = -1;
static int ett_wsp_parameter_type       = -1;
static int ett_content_type_header      = -1;
/* CO-WSP session capabilities */
static int ett_capabilities             = -1;
static int ett_capabilities_entry       = -1;
static int ett_proto_option_capability  = -1;
static int ett_capabilities_header_code_pages = -1;
static int ett_capabilities_extended_methods = -1;
static int ett_post                     = -1;
static int ett_redirect_flags           = -1;
static int ett_address_flags            = -1;
static int ett_multiparts               = -1;
static int ett_mpartlist                = -1;
/* Session Initiation Request tree */
static int ett_sir                      = -1;
static int ett_addresses                = -1;
static int ett_address                  = -1;

static int ett_default                  = -1;
static int ett_add_content_type         = -1;
static int ett_accept_x_q_header        = -1;
static int ett_push_flag                = -1;
static int ett_profile_diff_wbxml       = -1;
static int ett_allow                    = -1;
static int ett_public                   = -1;
static int ett_vary                     = -1;
static int ett_x_wap_security           = -1;
static int ett_connection               = -1;
static int ett_transfer_encoding        = -1;
static int ett_accept_ranges            = -1;
static int ett_content_encoding         = -1;
static int ett_accept_encoding          = -1;
static int ett_content_disposition      = -1;
static int ett_text_header              = -1;
static int ett_content_id               = -1;
static int ett_text_or_date_value       = -1;
static int ett_date_value               = -1;
static int ett_tod_value                = -1;
static int ett_age                      = -1;
static int ett_integer_lookup           = -1;
static int ett_challenge                = -1;
static int ett_credentials_value        = -1;
static int ett_content_md5              = -1;
static int ett_pragma                   = -1;
static int ett_integer_value            = -1;
static int ett_integer_lookup_value     = -1;
static int ett_cache_control            = -1;
static int ett_warning                  = -1;
static int ett_profile_warning          = -1;
static int ett_encoding_version         = -1;
static int ett_content_range            = -1;
static int ett_range                    = -1;
static int ett_te_value                 = -1;
static int ett_openwave_default         = -1;

static expert_field ei_wsp_capability_invalid = EI_INIT;
static expert_field ei_wsp_capability_length_invalid = EI_INIT;
static expert_field ei_wsp_capability_encoding_invalid = EI_INIT;
static expert_field ei_wsp_text_field_invalid = EI_INIT;
static expert_field ei_wsp_header_invalid_value    = EI_INIT;
static expert_field ei_wsp_invalid_parameter_value = EI_INIT;
static expert_field ei_wsp_undecoded_parameter = EI_INIT;
static expert_field ei_hdr_x_wap_tod = EI_INIT;
static expert_field ei_wsp_trailing_quote = EI_INIT;
static expert_field ei_wsp_header_invalid = EI_INIT;
static expert_field ei_wsp_oversized_uintvar = EI_INIT;


/* Handle for WSP-over-UDP dissector */
static dissector_handle_t wsp_fromudp_handle;

/* Handle for WTP-over-UDP dissector */
static dissector_handle_t wtp_fromudp_handle;

/* Handle for generic media dissector */
static dissector_handle_t media_handle;

/* Handle for WBXML-encoded UAPROF dissector */
static dissector_handle_t wbxml_uaprof_handle;

static const value_string wsp_vals_pdu_type[] = {
    { 0x00, "Reserved" },
    { 0x01, "Connect" },
    { 0x02, "ConnectReply" },
    { 0x03, "Redirect" },
    { 0x04, "Reply" },
    { 0x05, "Disconnect" },
    { 0x06, "Push" },
    { 0x07, "ConfirmedPush" },
    { 0x08, "Suspend" },
    { 0x09, "Resume" },

    /* 0x10 - 0x3F Unassigned */

    { 0x40, "Get" },
    { 0x41, "Options" },
    { 0x42, "Head" },
    { 0x43, "Delete" },
    { 0x44, "Trace" },

    /* 0x45 - 0x4F Unassigned (Get PDU) */
    /* 0x50 - 0x5F Extended method (Get PDU) */
    { 0x50, "Extended Get Method 0"},
    { 0x51, "Extended Get Method 1"},
    { 0x52, "Extended Get Method 2"},
    { 0x53, "Extended Get Method 3"},
    { 0x54, "Extended Get Method 4"},
    { 0x55, "Extended Get Method 5"},
    { 0x56, "Extended Get Method 6"},
    { 0x57, "Extended Get Method 7"},
    { 0x58, "Extended Get Method 8"},
    { 0x59, "Extended Get Method 9"},
    { 0x5A, "Extended Get Method 10"},
    { 0x5B, "Extended Get Method 11"},
    { 0x5C, "Extended Get Method 12"},
    { 0x5D, "Extended Get Method 13"},
    { 0x5E, "Extended Get Method 14"},
    { 0x5F, "Extended Get Method 15"},

    { 0x60, "Post" },
    { 0x61, "Put" },

    /* 0x62 - 0x6F Unassigned (Post PDU) */
    /* 0x70 - 0x7F Extended method (Post PDU) */
    { 0x70, "Extended Post Method 0"},
    { 0x71, "Extended Post Method 1"},
    { 0x72, "Extended Post Method 2"},
    { 0x73, "Extended Post Method 3"},
    { 0x74, "Extended Post Method 4"},
    { 0x75, "Extended Post Method 5"},
    { 0x76, "Extended Post Method 6"},
    { 0x77, "Extended Post Method 7"},
    { 0x78, "Extended Post Method 8"},
    { 0x79, "Extended Post Method 9"},
    { 0x7A, "Extended Post Method 10"},
    { 0x7B, "Extended Post Method 11"},
    { 0x7C, "Extended Post Method 12"},
    { 0x7D, "Extended Post Method 13"},
    { 0x7E, "Extended Post Method 14"},
    { 0x7F, "Extended Post Method 15"},

    /* 0x80 - 0xFF Reserved */

    { 0x00, NULL }

};
value_string_ext wsp_vals_pdu_type_ext = VALUE_STRING_EXT_INIT(wsp_vals_pdu_type);

/* The WSP status codes are inherited from the HTTP status codes */
static const value_string wsp_vals_status[] = {
    /* 0x00 - 0x0F Reserved */

    { 0x10, "100 Continue" },
    { 0x11, "101 Switching Protocols" },

    { 0x20, "200 OK" },
    { 0x21, "201 Created" },
    { 0x22, "202 Accepted" },
    { 0x23, "203 Non-Authoritative Information" },
    { 0x24, "204 No Content" },
    { 0x25, "205 Reset Content" },
    { 0x26, "206 Partial Content" },

    { 0x30, "300 Multiple Choices" },
    { 0x31, "301 Moved Permanently" },
    { 0x32, "302 Moved Temporarily" },
    { 0x33, "303 See Other" },
    { 0x34, "304 Not Modified" },
    { 0x35, "305 Use Proxy" },
    { 0x37, "307 Temporary Redirect" },

    { 0x40, "400 Bad Request" },
    { 0x41, "401 Unauthorised" },
    { 0x42, "402 Payment Required" },
    { 0x43, "403 Forbidden" },
    { 0x44, "404 Not Found" },
    { 0x45, "405 Method Not Allowed" },
    { 0x46, "406 Not Acceptable" },
    { 0x47, "407 Proxy Authentication Required" },
    { 0x48, "408 Request Timeout" },
    { 0x49, "409 Conflict" },
    { 0x4A, "410 Gone" },
    { 0x4B, "411 Length Required" },
    { 0x4C, "412 Precondition Failed" },
    { 0x4D, "413 Request Entity Too Large" },
    { 0x4E, "414 Request-URI Too Large" },
    { 0x4F, "415 Unsupported Media Type" },
    { 0x50, "416 Requested Range Not Satisfiable" },
    { 0x51, "417 Expectation Failed" },

    { 0x60, "500 Internal Server Error" },
    { 0x61, "501 Not Implemented" },
    { 0x62, "502 Bad Gateway" },
    { 0x63, "503 Service Unavailable" },
    { 0x64, "504 Gateway Timeout" },
    { 0x65, "505 WSP/HTTP Version Not Supported" },

    { 0x00, NULL }
};
value_string_ext wsp_vals_status_ext = VALUE_STRING_EXT_INIT(wsp_vals_status);

static const value_string vals_wsp_reason_codes[] = {
    { 0xE0, "Protocol Error (Illegal PDU)" },
    { 0xE1, "Session disconnected" },
    { 0xE2, "Session suspended" },
    { 0xE3, "Session resumed" },
    { 0xE4, "Peer congested" },
    { 0xE5, "Session connect failed" },
    { 0xE6, "Maximum receive unit size exceeded" },
    { 0xE7, "Maximum outstanding requests exceeded" },
    { 0xE8, "Peer request" },
    { 0xE9, "Network error" },
    { 0xEA, "User request" },
    { 0xEB, "No specific cause, no retries" },
    { 0xEC, "Push message cannot be delivered" },
    { 0xED, "Push message discarded" },
    { 0xEE, "Content type cannot be processed" },

    { 0x00, NULL }
};
value_string_ext vals_wsp_reason_codes_ext = VALUE_STRING_EXT_INIT(vals_wsp_reason_codes);

/*
 * Field names.
 */
#define FN_ACCEPT                 0x00
#define FN_ACCEPT_CHARSET_DEP     0x01    /* encoding version 1.1, deprecated */
#define FN_ACCEPT_ENCODING_DEP    0x02    /* encoding version 1.1, deprecated */
#define FN_ACCEPT_LANGUAGE        0x03
#define FN_ACCEPT_RANGES          0x04
#define FN_AGE                    0x05
#define FN_ALLOW                  0x06
#define FN_AUTHORIZATION          0x07
#define FN_CACHE_CONTROL_DEP      0x08    /* encoding version 1.1, deprecated */
#define FN_CONNECTION             0x09
#define FN_CONTENT_BASE           0x0A
#define FN_CONTENT_ENCODING       0x0B
#define FN_CONTENT_LANGUAGE       0x0C
#define FN_CONTENT_LENGTH         0x0D
#define FN_CONTENT_LOCATION       0x0E
#define FN_CONTENT_MD5            0x0F
#define FN_CONTENT_RANGE_DEP      0x10    /* encoding version 1.1, deprecated */
#define FN_CONTENT_TYPE           0x11
#define FN_DATE                   0x12
#define FN_ETAG                   0x13
#define FN_EXPIRES                0x14
#define FN_FROM                   0x15
#define FN_HOST                   0x16
#define FN_IF_MODIFIED_SINCE      0x17
#define FN_IF_MATCH               0x18
#define FN_IF_NONE_MATCH          0x19
#define FN_IF_RANGE               0x1A
#define FN_IF_UNMODIFIED_SINCE    0x1B
#define FN_LOCATION               0x1C
#define FN_LAST_MODIFIED          0x1D
#define FN_MAX_FORWARDS           0x1E
#define FN_PRAGMA                 0x1F
#define FN_PROXY_AUTHENTICATE     0x20
#define FN_PROXY_AUTHORIZATION    0x21
#define FN_PUBLIC                 0x22
#define FN_RANGE                  0x23
#define FN_REFERER                0x24
#define FN_RETRY_AFTER            0x25
#define FN_SERVER                 0x26
#define FN_TRANSFER_ENCODING      0x27
#define FN_UPGRADE                0x28
#define FN_USER_AGENT             0x29
#define FN_VARY                   0x2A
#define FN_VIA                    0x2B
#define FN_WARNING                0x2C
#define FN_WWW_AUTHENTICATE       0x2D
#define FN_CONTENT_DISPOSITION    0x2E
#define FN_X_WAP_APPLICATION_ID   0x2F
#define FN_X_WAP_CONTENT_URI      0x30
#define FN_X_WAP_INITIATOR_URI    0x31
#define FN_ACCEPT_APPLICATION     0x32
#define FN_BEARER_INDICATION      0x33
#define FN_PUSH_FLAG              0x34
#define FN_PROFILE                0x35
#define FN_PROFILE_DIFF           0x36
#define FN_PROFILE_WARNING        0x37
#define FN_EXPECT                 0x38
#define FN_TE                     0x39
#define FN_TRAILER                0x3A
#define FN_ACCEPT_CHARSET         0x3B    /* encoding version 1.3 */
#define FN_ACCEPT_ENCODING        0x3C    /* encoding version 1.3 */
#define FN_CACHE_CONTROL          0x3D    /* encoding version 1.3 */
#define FN_CONTENT_RANGE          0x3E    /* encoding version 1.3 */
#define FN_X_WAP_TOD              0x3F
#define FN_CONTENT_ID             0x40
#define FN_SET_COOKIE             0x41
#define FN_COOKIE                 0x42
#define FN_ENCODING_VERSION       0x43
#define FN_PROFILE_WARNING14      0x44    /* encoding version 1.4 */
#define FN_CONTENT_DISPOSITION14  0x45    /* encoding version 1.4 */
#define FN_X_WAP_SECURITY         0x46
#define FN_CACHE_CONTROL14        0x47    /* encoding version 1.4 */
#define FN_EXPECT15               0x48        /* encoding version 1.5 */
#define FN_X_WAP_LOC_INVOCATION   0x49
#define FN_X_WAP_LOC_DELIVERY     0x4A


/*
 * Openwave field names.
 */
#define FN_OPENWAVE_PROXY_PUSH_ADDR             0x00
#define FN_OPENWAVE_PROXY_PUSH_ACCEPT           0x01
#define FN_OPENWAVE_PROXY_PUSH_SEQ              0x02
#define FN_OPENWAVE_PROXY_NOTIFY                0x03
#define FN_OPENWAVE_PROXY_OPERATOR_DOMAIN       0x04
#define FN_OPENWAVE_PROXY_HOME_PAGE             0x05
#define FN_OPENWAVE_DEVCAP_HAS_COLOR            0x06
#define FN_OPENWAVE_DEVCAP_NUM_SOFTKEYS         0x07
#define FN_OPENWAVE_DEVCAP_SOFTKEY_SIZE         0x08
#define FN_OPENWAVE_DEVCAP_SCREEN_CHARS         0x09
#define FN_OPENWAVE_DEVCAP_SCREEN_PIXELS        0x0A
#define FN_OPENWAVE_DEVCAP_EM_SIZE              0x0B
#define FN_OPENWAVE_DEVCAP_SCREEN_DEPTH         0x0C
#define FN_OPENWAVE_DEVCAP_IMMED_ALERT          0x0D
#define FN_OPENWAVE_PROXY_NET_ASK               0x0E
#define FN_OPENWAVE_PROXY_UPLINK_VERSION        0x0F
#define FN_OPENWAVE_PROXY_TOD                   0x10
#define FN_OPENWAVE_PROXY_BA_ENABLE             0x11
#define FN_OPENWAVE_PROXY_BA_REALM              0x12
#define FN_OPENWAVE_PROXY_REDIRECT_ENABLE       0x13
#define FN_OPENWAVE_PROXY_REQUEST_URI           0x14
#define FN_OPENWAVE_PROXY_REDIRECT_STATUS       0x15
#define FN_OPENWAVE_PROXY_TRANS_CHARSET         0x16
#define FN_OPENWAVE_PROXY_LINGER                0x17
#define FN_OPENWAVE_PROXY_CLIENT_ID             0x18
#define FN_OPENWAVE_PROXY_ENABLE_TRUST          0x19
#define FN_OPENWAVE_PROXY_TRUST_OLD             0x1A
#define FN_OPENWAVE_PROXY_TRUST                 0x20
#define FN_OPENWAVE_PROXY_BOOKMARK              0x21
#define FN_OPENWAVE_DEVCAP_GUI                  0x22

static const value_string vals_openwave_field_names[] = {
    { FN_OPENWAVE_PROXY_PUSH_ADDR,         "x-up-proxy-push-addr" },
    { FN_OPENWAVE_PROXY_PUSH_ACCEPT,       "x-up-proxy-push-accept" },
    { FN_OPENWAVE_PROXY_PUSH_SEQ,          "x-up-proxy-seq" },
    { FN_OPENWAVE_PROXY_NOTIFY,            "x-up-proxy-notify" },
    { FN_OPENWAVE_PROXY_OPERATOR_DOMAIN,   "x-up-proxy-operator-domain" },
    { FN_OPENWAVE_PROXY_HOME_PAGE,         "x-up-proxy-home-page" },
    { FN_OPENWAVE_DEVCAP_HAS_COLOR,        "x-up-devcap-has-color" },
    { FN_OPENWAVE_DEVCAP_NUM_SOFTKEYS,     "x-up-devcap-num-softkeys" },
    { FN_OPENWAVE_DEVCAP_SOFTKEY_SIZE,     "x-up-devcap-softkey-size" },
    { FN_OPENWAVE_DEVCAP_SCREEN_CHARS,     "x-up-devcap-screen-chars" },
    { FN_OPENWAVE_DEVCAP_SCREEN_PIXELS,    "x-up-devcap-screen-pixels" },
    { FN_OPENWAVE_DEVCAP_EM_SIZE,          "x-up-devcap-em-size" },
    { FN_OPENWAVE_DEVCAP_SCREEN_DEPTH,     "x-up-devcap-screen-depth" },
    { FN_OPENWAVE_DEVCAP_IMMED_ALERT,      "x-up-devcap-immed-alert" },
    { FN_OPENWAVE_PROXY_NET_ASK,           "x-up-proxy-net-ask" },
    { FN_OPENWAVE_PROXY_UPLINK_VERSION,    "x-up-proxy-uplink-version" },
    { FN_OPENWAVE_PROXY_TOD,               "x-up-proxy-tod" },
    { FN_OPENWAVE_PROXY_BA_ENABLE,         "x-up-proxy-ba-enable" },
    { FN_OPENWAVE_PROXY_BA_REALM,          "x-up-proxy-ba-realm" },
    { FN_OPENWAVE_PROXY_REDIRECT_ENABLE,   "x-up-proxy-redirect-enable" },
    { FN_OPENWAVE_PROXY_REQUEST_URI,       "x-up-proxy-request-uri" },
    { FN_OPENWAVE_PROXY_REDIRECT_STATUS,   "x-up-proxy-redirect-status" },
    { FN_OPENWAVE_PROXY_TRANS_CHARSET,     "x-up-proxy-trans-charset" },
    { FN_OPENWAVE_PROXY_LINGER,            "x-up-proxy-linger" },
    { FN_OPENWAVE_PROXY_CLIENT_ID,         "x-up-proxy-client-id" },
    { FN_OPENWAVE_PROXY_ENABLE_TRUST,      "x-up-proxy-enable-trust" },
    { FN_OPENWAVE_PROXY_TRUST_OLD,         "x-up-proxy-trust-old" },
    { FN_OPENWAVE_PROXY_TRUST,             "x-up-proxy-trust" },
    { FN_OPENWAVE_PROXY_BOOKMARK,          "x-up-proxy-bookmark" },
    { FN_OPENWAVE_DEVCAP_GUI,              "x-up-devcap-gui" },
    { 0,                                   NULL }
};
static value_string_ext vals_openwave_field_names_ext = VALUE_STRING_EXT_INIT(vals_openwave_field_names);

static const value_string vals_field_names[] = {
    { FN_ACCEPT,               "Accept" },
    { FN_ACCEPT_CHARSET_DEP,   "Accept-Charset (encoding 1.1)" },
    { FN_ACCEPT_ENCODING_DEP,  "Accept-Encoding (encoding 1.1)" },
    { FN_ACCEPT_LANGUAGE,      "Accept-Language" },
    { FN_ACCEPT_RANGES,        "Accept-Ranges" },
    { FN_AGE,                  "Age" },
    { FN_ALLOW,                "Allow" },
    { FN_AUTHORIZATION,        "Authorization" },
    { FN_CACHE_CONTROL_DEP,    "Cache-Control (encoding 1.1)" },
    { FN_CONNECTION,           "Connection" },
    { FN_CONTENT_BASE,         "Content-Base" },
    { FN_CONTENT_ENCODING,     "Content-Encoding" },
    { FN_CONTENT_LANGUAGE,     "Content-Language" },
    { FN_CONTENT_LENGTH,       "Content-Length" },
    { FN_CONTENT_LOCATION,     "Content-Location" },
    { FN_CONTENT_MD5,          "Content-MD5" },
    { FN_CONTENT_RANGE_DEP,    "Content-Range (encoding 1.1)" },
    { FN_CONTENT_TYPE,         "Content-Type" },
    { FN_DATE,                 "Date" },
    { FN_ETAG,                 "ETag" },
    { FN_EXPIRES,              "Expires" },
    { FN_FROM,                 "From" },
    { FN_HOST,                 "Host" },
    { FN_IF_MODIFIED_SINCE,    "If-Modified-Since" },
    { FN_IF_MATCH,             "If-Match" },
    { FN_IF_NONE_MATCH,        "If-None-Match" },
    { FN_IF_RANGE,             "If-Range" },
    { FN_IF_UNMODIFIED_SINCE,  "If-Unmodified-Since" },
    { FN_LOCATION,             "Location" },
    { FN_LAST_MODIFIED,        "Last-Modified" },
    { FN_MAX_FORWARDS,         "Max-Forwards" },
    { FN_PRAGMA,               "Pragma" },
    { FN_PROXY_AUTHENTICATE,   "Proxy-Authenticate" },
    { FN_PROXY_AUTHORIZATION,  "Proxy-Authorization" },
    { FN_PUBLIC,               "Public" },
    { FN_RANGE,                "Range" },
    { FN_REFERER,              "Referer" },
    { FN_RETRY_AFTER,          "Retry-After" },
    { FN_SERVER,               "Server" },
    { FN_TRANSFER_ENCODING,    "Transfer-Encoding" },
    { FN_UPGRADE,              "Upgrade" },
    { FN_USER_AGENT,           "User-Agent" },
    { FN_VARY,                 "Vary" },
    { FN_VIA,                  "Via" },
    { FN_WARNING,              "Warning" },
    { FN_WWW_AUTHENTICATE,     "WWW-Authenticate" },
    { FN_CONTENT_DISPOSITION,  "Content-Disposition" },
    { FN_X_WAP_APPLICATION_ID, "X-Wap-Application-ID" },
    { FN_X_WAP_CONTENT_URI,    "X-Wap-Content-URI" },
    { FN_X_WAP_INITIATOR_URI,  "X-Wap-Initiator-URI" },
    { FN_ACCEPT_APPLICATION,   "Accept-Application" },
    { FN_BEARER_INDICATION,    "Bearer-Indication" },
    { FN_PUSH_FLAG,            "Push-Flag" },
    { FN_PROFILE,              "Profile" },
    { FN_PROFILE_DIFF,         "Profile-Diff" },
    { FN_PROFILE_WARNING,      "Profile-Warning" },
    { FN_EXPECT,               "Expect" },
    { FN_TE,                   "TE" },
    { FN_TRAILER,              "Trailer" },
    { FN_ACCEPT_CHARSET,       "Accept-Charset" },
    { FN_ACCEPT_ENCODING,      "Accept-Encoding" },
    { FN_CACHE_CONTROL,        "Cache-Control" },
    { FN_CONTENT_RANGE,        "Content-Range" },
    { FN_X_WAP_TOD,            "X-Wap-Tod" },
    { FN_CONTENT_ID,           "Content-ID" },
    { FN_SET_COOKIE,           "Set-Cookie" },
    { FN_COOKIE,               "Cookie" },
    { FN_ENCODING_VERSION,     "Encoding-Version" },
    { FN_PROFILE_WARNING14,    "Profile-Warning (encoding 1.4)" },
    { FN_CONTENT_DISPOSITION14,"Content-Disposition (encoding 1.4)" },
    { FN_X_WAP_SECURITY,       "X-WAP-Security" },
    { FN_CACHE_CONTROL14,      "Cache-Control (encoding 1.4)" },
    /* encoding-version 1.5 */
    { FN_EXPECT15,             "Expect (encoding 1.5)" },
    { FN_X_WAP_LOC_INVOCATION, "X-Wap-Loc-Invocation" },
    { FN_X_WAP_LOC_DELIVERY,   "X-Wap-Loc-Delivery" },
    { 0,                       NULL }
};
static value_string_ext vals_field_names_ext = VALUE_STRING_EXT_INIT(vals_field_names);

/*
 * Bearer types (from the WDP specification).
 */
#define BT_IPv4                 0x00
#define BT_IPv6                 0x01
#define BT_GSM_USSD             0x02
#define BT_GSM_SMS              0x03
#define BT_ANSI_136_GUTS        0x04
#define BT_IS_95_SMS            0x05
#define BT_IS_95_CSD            0x06
#define BT_IS_95_PACKET_DATA    0x07
#define BT_ANSI_136_CSD         0x08
#define BT_ANSI_136_PACKET_DATA 0x09
#define BT_GSM_CSD              0x0A
#define BT_GSM_GPRS             0x0B
#define BT_GSM_USSD_IPv4        0x0C
#define BT_AMPS_CDPD            0x0D
#define BT_PDC_CSD              0x0E
#define BT_PDC_PACKET_DATA      0x0F
#define BT_IDEN_SMS             0x10
#define BT_IDEN_CSD             0x11
#define BT_IDEN_PACKET_DATA     0x12
#define BT_PAGING_FLEX          0x13
#define BT_PHS_SMS              0x14
#define BT_PHS_CSD              0x15
#define BT_GSM_USSD_GSM_SC      0x16
#define BT_TETRA_SDS_ITSI       0x17
#define BT_TETRA_SDS_MSISDN     0x18
#define BT_TETRA_PACKET_DATA    0x19
#define BT_PAGING_REFLEX        0x1A
#define BT_GSM_USSD_MSISDN      0x1B
#define BT_MOBITEX_MPAK         0x1C
#define BT_ANSI_136_GHOST       0x1D

static const value_string vals_bearer_types[] = {
    { BT_IPv4,                 "IPv4" },
    { BT_IPv6,                 "IPv6" },
    { BT_GSM_USSD,             "GSM USSD" },
    { BT_GSM_SMS,              "GSM SMS" },
    { BT_ANSI_136_GUTS,        "ANSI-136 GUTS/R-Data" },
    { BT_IS_95_SMS,            "IS-95 CDMA SMS" },
    { BT_IS_95_CSD,            "IS-95 CDMA CSD" },
    { BT_IS_95_PACKET_DATA,    "IS-95 CDMA Packet data" },
    { BT_ANSI_136_CSD,         "ANSI-136 CSD" },
    { BT_ANSI_136_PACKET_DATA, "ANSI-136 Packet data" },
    { BT_GSM_CSD,              "GSM CSD" },
    { BT_GSM_GPRS,             "GSM GPRS" },
    { BT_GSM_USSD_IPv4,        "GSM USSD (IPv4 addresses)" },
    { BT_AMPS_CDPD,            "AMPS CDPD" },
    { BT_PDC_CSD,              "PDC CSD" },
    { BT_PDC_PACKET_DATA,      "PDC Packet data" },
    { BT_IDEN_SMS,             "IDEN SMS" },
    { BT_IDEN_CSD,             "IDEN CSD" },
    { BT_IDEN_PACKET_DATA,     "IDEN Packet data" },
    { BT_PAGING_FLEX,          "Paging network FLEX(TM)" },
    { BT_PHS_SMS,              "PHS SMS" },
    { BT_PHS_CSD,              "PHS CSD" },
    { BT_GSM_USSD_GSM_SC,      "GSM USSD (GSM Service Code addresses)" },
    { BT_TETRA_SDS_ITSI,       "TETRA SDS (ITSI addresses)" },
    { BT_TETRA_SDS_MSISDN,     "TETRA SDS (MSISDN addresses)" },
    { BT_TETRA_PACKET_DATA,    "TETRA Packet data" },
    { BT_PAGING_REFLEX,        "Paging network ReFLEX(TM)" },
    { BT_GSM_USSD_MSISDN,      "GSM USSD (MSISDN addresses)" },
    { BT_MOBITEX_MPAK,         "Mobitex MPAK" },
    { BT_ANSI_136_GHOST,       "ANSI-136 GHOST/R-Data" },
    { 0,                       NULL }
};
static value_string_ext vals_bearer_types_ext = VALUE_STRING_EXT_INIT(vals_bearer_types);

static const value_string vals_content_types[] = {
    /* Well-known media types */
    /* XXX: hack: "..." "..." used to define several strings so that checkAPIs & etc won't see a 'start of comment' */
    { 0x00, "*" "/" "*" },
    { 0x01, "text/" "*" },
    { 0x02, "text/html" },
    { 0x03, "text/plain" },
    { 0x04, "text/x-hdml" },
    { 0x05, "text/x-ttml" },
    { 0x06, "text/x-vCalendar" },
    { 0x07, "text/x-vCard" },
    { 0x08, "text/vnd.wap.wml" },
    { 0x09, "text/vnd.wap.wmlscript" },
    { 0x0A, "text/vnd.wap.channel" },
    { 0x0B, "multipart/" "*" },
    { 0x0C, "multipart/mixed" },
    { 0x0D, "multipart/form-data" },
    { 0x0E, "multipart/byteranges" },
    { 0x0F, "multipart/alternative" },
    { 0x10, "application/" "*" },
    { 0x11, "application/java-vm" },
    { 0x12, "application/x-www-form-urlencoded" },
    { 0x13, "application/x-hdmlc" },
    { 0x14, "application/vnd.wap.wmlc" },
    { 0x15, "application/vnd.wap.wmlscriptc" },
    { 0x16, "application/vnd.wap.channelc" },
    { 0x17, "application/vnd.wap.uaprof" },
    { 0x18, "application/vnd.wap.wtls-ca-certificate" },
    { 0x19, "application/vnd.wap.wtls-user-certificate" },
    { 0x1A, "application/x-x509-ca-cert" },
    { 0x1B, "application/x-x509-user-cert" },
    { 0x1C, "image/" "*" },
    { 0x1D, "image/gif" },
    { 0x1E, "image/jpeg" },
    { 0x1F, "image/tiff" },
    { 0x20, "image/png" },
    { 0x21, "image/vnd.wap.wbmp" },
    { 0x22, "application/vnd.wap.multipart.*" },
    { 0x23, "application/vnd.wap.multipart.mixed" },
    { 0x24, "application/vnd.wap.multipart.form-data" },
    { 0x25, "application/vnd.wap.multipart.byteranges" },
    { 0x26, "application/vnd.wap.multipart.alternative" },
    { 0x27, "application/xml" },
    { 0x28, "text/xml" },
    { 0x29, "application/vnd.wap.wbxml" },
    { 0x2A, "application/x-x968-cross-cert" },
    { 0x2B, "application/x-x968-ca-cert" },
    { 0x2C, "application/x-x968-user-cert" },
    { 0x2D, "text/vnd.wap.si" },
    { 0x2E, "application/vnd.wap.sic" },
    { 0x2F, "text/vnd.wap.sl" },
    { 0x30, "application/vnd.wap.slc" },
    { 0x31, "text/vnd.wap.co" },
    { 0x32, "application/vnd.wap.coc" },
    { 0x33, "application/vnd.wap.multipart.related" },
    { 0x34, "application/vnd.wap.sia" },
    { 0x35, "text/vnd.wap.connectivity-xml" },
    { 0x36, "application/vnd.wap.connectivity-wbxml" },
    { 0x37, "application/pkcs7-mime" },
    { 0x38, "application/vnd.wap.hashed-certificate" },
    { 0x39, "application/vnd.wap.signed-certificate" },
    { 0x3A, "application/vnd.wap.cert-response" },
    { 0x3B, "application/xhtml+xml" },
    { 0x3C, "application/wml+xml" },
    { 0x3D, "text/css" },
    { 0x3E, "application/vnd.wap.mms-message" },
    { 0x3F, "application/vnd.wap.rollover-certificate" },
    { 0x40, "application/vnd.wap.locc+wbxml"},
    { 0x41, "application/vnd.wap.loc+xml"},
    { 0x42, "application/vnd.syncml.dm+wbxml"},
    { 0x43, "application/vnd.syncml.dm+xml"},
    { 0x44, "application/vnd.syncml.notification"},
    { 0x45, "application/vnd.wap.xhtml+xml"},
    { 0x46, "application/vnd.wv.csp.cir"},
    { 0x47, "application/vnd.oma.dd+xml"},
    { 0x48, "application/vnd.oma.drm.message"},
    { 0x49, "application/vnd.oma.drm.content"},
    { 0x4A, "application/vnd.oma.drm.rights+xml"},
    { 0x4B, "application/vnd.oma.drm.rights+wbxml"},
    { 0x4C, "application/vnd.wv.csp+xml"},
    { 0x4D, "application/vnd.wv.csp+wbxml"},
    /* The following media types are registered by 3rd parties */
    { 0x0201, "application/vnd.uplanet.cachop-wbxml" },
    { 0x0202, "application/vnd.uplanet.signal" },
    { 0x0203, "application/vnd.uplanet.alert-wbxml" },
    { 0x0204, "application/vnd.uplanet.list-wbxml" },
    { 0x0205, "application/vnd.uplanet.listcmd-wbxml" },
    { 0x0206, "application/vnd.uplanet.channel-wbxml" },
    { 0x0207, "application/vnd.uplanet.provisioning-status-uri" },
    { 0x0208, "x-wap.multipart/vnd.uplanet.header-set" },
    { 0x0209, "application/vnd.uplanet.bearer-choice-wbxml" },
    { 0x020A, "application/vnd.phonecom.mmc-wbxml" },
    { 0x020B, "application/vnd.nokia.syncset+wbxml" },
    { 0x020C, "image/x-up-wpng"},
    { 0x0300, "application/iota.mmc-wbxml"},
    { 0x0301, "application/iota.mmc-xml"},
    { 0x00, NULL }
};
static value_string_ext vals_content_types_ext = VALUE_STRING_EXT_INIT(vals_content_types);

static const value_string vals_languages[] = {
    { 0x00, "*" },
    { 0x01, "Afar (aa)" },
    { 0x02, "Abkhazian (ab)" },
    { 0x03, "Afrikaans (af)" },
    { 0x04, "Amharic (am)" },
    { 0x05, "Arabic (ar)" },
    { 0x06, "Assamese (as)" },
    { 0x07, "Aymara (ay)" },
    { 0x08, "Azerbaijani (az)" },
    { 0x09, "Bashkir (ba)" },
    { 0x0A, "Byelorussian (be)" },
    { 0x0B, "Bulgarian (bg)" },
    { 0x0C, "Bihari (bh)" },
    { 0x0D, "Bislama (bi)" },
    { 0x0E, "Bengali; Bangla (bn)" },
    { 0x0F, "Tibetan (bo)" },
    { 0x10, "Breton (br)" },
    { 0x11, "Catalan (ca)" },
    { 0x12, "Corsican (co)" },
    { 0x13, "Czech (cs)" },
    { 0x14, "Welsh (cy)" },
    { 0x15, "Danish (da)" },
    { 0x16, "German (de)" },
    { 0x17, "Bhutani (dz)" },
    { 0x18, "Greek (el)" },
    { 0x19, "English (en)" },
    { 0x1A, "Esperanto (eo)" },
    { 0x1B, "Spanish (es)" },
    { 0x1C, "Estonian (et)" },
    { 0x1D, "Basque (eu)" },
    { 0x1E, "Persian (fa)" },
    { 0x1F, "Finnish (fi)" },
    { 0x20, "Fiji (fj)" },
    { 0x21, "Urdu (ur)" },
    { 0x22, "French (fr)" },
    { 0x23, "Uzbek (uz)" },
    { 0x24, "Irish (ga)" },
    { 0x25, "Scots Gaelic (gd)" },
    { 0x26, "Galician (gl)" },
    { 0x27, "Guarani (gn)" },
    { 0x28, "Gujarati (gu)" },
    { 0x29, "Hausa (ha)" },
    { 0x2A, "Hebrew (formerly iw) (he)" },
    { 0x2B, "Hindi (hi)" },
    { 0x2C, "Croatian (hr)" },
    { 0x2D, "Hungarian (hu)" },
    { 0x2E, "Armenian (hy)" },
    { 0x2F, "Vietnamese (vi)" },
    { 0x30, "Indonesian (formerly in) (id)" },
    { 0x31, "Wolof (wo)" },
    { 0x32, "Xhosa (xh)" },
    { 0x33, "Icelandic (is)" },
    { 0x34, "Italian (it)" },
    { 0x35, "Yoruba (yo)" },
    { 0x36, "Japanese (ja)" },
    { 0x37, "Javanese (jw)" },
    { 0x38, "Georgian (ka)" },
    { 0x39, "Kazakh (kk)" },
    { 0x3A, "Zhuang (za)" },
    { 0x3B, "Cambodian (km)" },
    { 0x3C, "Kannada (kn)" },
    { 0x3D, "Korean (ko)" },
    { 0x3E, "Kashmiri (ks)" },
    { 0x3F, "Kurdish (ku)" },
    { 0x40, "Kirghiz (ky)" },
    { 0x41, "Chinese (zh)" },
    { 0x42, "Lingala (ln)" },
    { 0x43, "Laothian (lo)" },
    { 0x44, "Lithuanian (lt)" },
    { 0x45, "Latvian, Lettish (lv)" },
    { 0x46, "Malagasy (mg)" },
    { 0x47, "Maori (mi)" },
    { 0x48, "Macedonian (mk)" },
    { 0x49, "Malayalam (ml)" },
    { 0x4A, "Mongolian (mn)" },
    { 0x4B, "Moldavian (mo)" },
    { 0x4C, "Marathi (mr)" },
    { 0x4D, "Malay (ms)" },
    { 0x4E, "Maltese (mt)" },
    { 0x4F, "Burmese (my)" },
    { 0x50, "Ukrainian (uk)" },
    { 0x51, "Nepali (ne)" },
    { 0x52, "Dutch (nl)" },
    { 0x53, "Norwegian (no)" },
    { 0x54, "Occitan (oc)" },
    { 0x55, "(Afan) Oromo (om)" },
    { 0x56, "Oriya (or)" },
    { 0x57, "Punjabi (pa)" },
    { 0x58, "Polish (po)" },
    { 0x59, "Pashto, Pushto (ps)" },
    { 0x5A, "Portuguese (pt)" },
    { 0x5B, "Quechua (qu)" },
    { 0x5C, "Zulu (zu)" },
    { 0x5D, "Kirundi (rn)" },
    { 0x5E, "Romanian (ro)" },
    { 0x5F, "Russian (ru)" },
    { 0x60, "Kinyarwanda (rw)" },
    { 0x61, "Sanskrit (sa)" },
    { 0x62, "Sindhi (sd)" },
    { 0x63, "Sangho (sg)" },
    { 0x64, "Serbo-Croatian (sh)" },
    { 0x65, "Sinhalese (si)" },
    { 0x66, "Slovak (sk)" },
    { 0x67, "Slovenian (sl)" },
    { 0x68, "Samoan (sm)" },
    { 0x69, "Shona (sn)" },
    { 0x6A, "Somali (so)" },
    { 0x6B, "Albanian (sq)" },
    { 0x6C, "Serbian (sr)" },
    { 0x6D, "Siswati (ss)" },
    { 0x6E, "Sesotho (st)" },
    { 0x6F, "Sundanese (su)" },
    { 0x70, "Swedish (sv)" },
    { 0x71, "Swahili (sw)" },
    { 0x72, "Tamil (ta)" },
    { 0x73, "Telugu (te)" },
    { 0x74, "Tajik (tg)" },
    { 0x75, "Thai (th)" },
    { 0x76, "Tigrinya (ti)" },
    { 0x77, "Turkmen (tk)" },
    { 0x78, "Tagalog (tl)" },
    { 0x79, "Setswana (tn)" },
    { 0x7A, "Tonga (to)" },
    { 0x7B, "Turkish (tr)" },
    { 0x7C, "Tsonga (ts)" },
    { 0x7D, "Tatar (tt)" },
    { 0x7E, "Twi (tw)" },
    { 0x7F, "Uighur (ug)" },
    { 0x81, "Nauru (na)" },
    { 0x82, "Faeroese (fo)" },
    { 0x83, "Frisian (fy)" },
    { 0x84, "Interlingua (ia)" },
    { 0x85, "Volapuk (vo)" },
    { 0x86, "Interlingue (ie)" },
    { 0x87, "Inupiak (ik)" },
    { 0x88, "Yiddish (formerly ji) (yi)" },
    { 0x89, "Inuktitut (iu)" },
    { 0x8A, "Greenlandic (kl)" },
    { 0x8B, "Latin (la)" },
    { 0x8C, "Rhaeto-Romance (rm)" },
    { 0x00, NULL }
};
static value_string_ext vals_languages_ext = VALUE_STRING_EXT_INIT(vals_languages);


#define CACHE_CONTROL_NO_CACHE          0x00
#define CACHE_CONTROL_NO_STORE          0x01
#define CACHE_CONTROL_MAX_AGE           0x02
#define CACHE_CONTROL_MAX_STALE         0x03
#define CACHE_CONTROL_MIN_FRESH         0x04
#define CACHE_CONTROL_ONLY_IF_CACHED    0x05
#define CACHE_CONTROL_PUBLIC            0x06
#define CACHE_CONTROL_PRIVATE           0x07
#define CACHE_CONTROL_NO_TRANSFORM      0x08
#define CACHE_CONTROL_MUST_REVALIDATE   0x09
#define CACHE_CONTROL_PROXY_REVALIDATE  0x0A
#define CACHE_CONTROL_S_MAXAGE          0x0B

static const value_string vals_cache_control[] = {
    { CACHE_CONTROL_NO_CACHE,         "no-cache" },
    { CACHE_CONTROL_NO_STORE,         "no-store" },
    { CACHE_CONTROL_MAX_AGE,          "max-age" },
    { CACHE_CONTROL_MAX_STALE,        "max-stale" },
    { CACHE_CONTROL_MIN_FRESH,        "min-fresh" },
    { CACHE_CONTROL_ONLY_IF_CACHED,   "only-if-cached" },
    { CACHE_CONTROL_PUBLIC,           "public" },
    { CACHE_CONTROL_PRIVATE,          "private" },
    { CACHE_CONTROL_NO_TRANSFORM,     "no-transform" },
    { CACHE_CONTROL_MUST_REVALIDATE,  "must-revalidate" },
    { CACHE_CONTROL_PROXY_REVALIDATE, "proxy-revalidate" },
    { CACHE_CONTROL_S_MAXAGE,         "s-max-age" },

    { 0x00, NULL }
};
static value_string_ext vals_cache_control_ext = VALUE_STRING_EXT_INIT(vals_cache_control);

static const value_string vals_wap_application_ids[] = {
    /* Well-known WAP applications */
    { 0x0000, "x-wap-application:*"},
    { 0x0001, "x-wap-application:push.sia"},
    { 0x0002, "x-wap-application:wml.ua"},
    { 0x0003, "x-wap-application:wta.ua"},
    { 0x0004, "x-wap-application:mms.ua"},
    { 0x0005, "x-wap-application:push.syncml"},
    { 0x0006, "x-wap-application:loc.ua"},
    { 0x0007, "x-wap-application:syncml.dm"},
    { 0x0008, "x-wap-application:drm.ua"},
    { 0x0009, "x-wap-application:emn.ua"},
    { 0x000A, "x-wap-application:wv.ua"},
    /* Registered by 3rd parties */
    { 0x8000, "x-wap-microsoft:localcontent.ua"},
    { 0x8001, "x-wap-microsoft:IMclient.ua"},
    { 0x8002, "x-wap-docomo:imode.mail.ua"},
    { 0x8003, "x-wap-docomo:imode.mr.ua"},
    { 0x8004, "x-wap-docomo:imode.mf.ua"},
    { 0x8005, "x-motorola:location.ua"},
    { 0x8006, "x-motorola:now.ua"},
    { 0x8007, "x-motorola:otaprov.ua"},
    { 0x8008, "x-motorola:browser.ua"},
    { 0x8009, "x-motorola:splash.ua"},
    /* 0x800A: unassigned */
    { 0x800B, "x-wap-nai:mvsw.command"},
    /* 0x800C -- 0x800F: unassigned */
    { 0x8010, "x-wap-openwave:iota.ua"},
    /* 0x8011 -- 0x8FFF: unassigned */
    { 0x9000, "x-wap-docomo:imode.mail2.ua"},
    { 0x9001, "x-oma-nec:otaprov.ua"},
    { 0x9002, "x-oma-nokia:call.ua"},
    { 0x9003, "x-oma-coremobility:sqa.ua"},

    { 0x00, NULL }
};
static value_string_ext vals_wap_application_ids_ext = VALUE_STRING_EXT_INIT(vals_wap_application_ids);


/* Parameters and well-known encodings */
static const value_string vals_wsp_parameter_sec[] = {
    { 0x00, "NETWPIN" },
    { 0x01, "USERPIN" },
    { 0x02, "USERNETWPIN" },
    { 0x03, "USERPINMAC" },

    { 0x00, NULL }
};
static value_string_ext vals_wsp_parameter_sec_ext = VALUE_STRING_EXT_INIT(vals_wsp_parameter_sec);

/* Warning codes and mappings */
static const value_string vals_wsp_warning_code[] = {
    { 10, "110 Response is stale" },
    { 11, "111 Revalidation failed" },
    { 12, "112 Disconnected operation" },
    { 13, "113 Heuristic expiration" },
    { 14, "214 Transformation applied" },
    { 99, "199/299 Miscellaneous warning" },

    { 0, NULL }
};
static value_string_ext vals_wsp_warning_code_ext = VALUE_STRING_EXT_INIT(vals_wsp_warning_code);

static const value_string vals_wsp_warning_code_short[] = {
    { 10, "110" },
    { 11, "111" },
    { 12, "112" },
    { 13, "113" },
    { 14, "214" },
    { 99, "199/299" },

    { 0, NULL }
};
static value_string_ext vals_wsp_warning_code_short_ext = VALUE_STRING_EXT_INIT(vals_wsp_warning_code_short);

/* Profile-Warning codes - see http://www.w3.org/TR/NOTE-CCPPexchange */
static const value_string vals_wsp_profile_warning_code[] = {
    { 0x10, "100 OK" },
    { 0x11, "101 Used stale profile" },
    { 0x12, "102 Not used profile" },
    { 0x20, "200 Not applied" },
    { 0x21, "101 Content selection applied" },
    { 0x22, "202 Content generation applied" },
    { 0x23, "203 Transformation applied" },

    { 0x00, NULL }
};
static value_string_ext vals_wsp_profile_warning_code_ext = VALUE_STRING_EXT_INIT(vals_wsp_profile_warning_code);

/* Well-known TE values */
static const value_string vals_well_known_te[] = {
    { 0x82, "chunked" },
    { 0x83, "identity" },
    { 0x84, "gzip" },
    { 0x85, "compress" },
    { 0x86, "deflate" },

    { 0x00, NULL }
};
static value_string_ext vals_well_known_te_ext = VALUE_STRING_EXT_INIT(vals_well_known_te);


/*
 * Redirect flags.
 */
#define PERMANENT_REDIRECT      0x80
#define REUSE_SECURITY_SESSION  0x40

/*
 * Redirect address flags and length.
 */
#define BEARER_TYPE_INCLUDED    0x80
#define PORT_NUMBER_INCLUDED    0x40
#define ADDRESS_LEN             0x3f

static const value_string vals_false_true[] = {
    { 0, "False" },
    { 1, "True" },
    { 0, NULL }
};

enum {
    WSP_PDU_RESERVED        = 0x00,
    WSP_PDU_CONNECT         = 0x01,
    WSP_PDU_CONNECTREPLY    = 0x02,
    WSP_PDU_REDIRECT        = 0x03,         /* No sample data */
    WSP_PDU_REPLY           = 0x04,
    WSP_PDU_DISCONNECT      = 0x05,
    WSP_PDU_PUSH            = 0x06,         /* No sample data */
    WSP_PDU_CONFIRMEDPUSH   = 0x07,         /* No sample data */
    WSP_PDU_SUSPEND         = 0x08,         /* No sample data */
    WSP_PDU_RESUME          = 0x09,         /* No sample data */

    WSP_PDU_GET             = 0x40,
    WSP_PDU_OPTIONS         = 0x41,         /* No sample data */
    WSP_PDU_HEAD            = 0x42,         /* No sample data */
    WSP_PDU_DELETE          = 0x43,         /* No sample data */
    WSP_PDU_TRACE           = 0x44,         /* No sample data */

    WSP_PDU_POST            = 0x60,
    WSP_PDU_PUT             = 0x61          /* No sample data */
};


/* Dissector tables for handoff */
static dissector_table_t media_type_table;
static heur_dissector_list_t heur_subdissector_list;

static void add_uri (proto_tree *, packet_info *, tvbuff_t *, guint, guint, proto_item *);

static void add_post_variable (proto_tree *, tvbuff_t *, guint, guint, guint, guint);
static void add_multipart_data (proto_tree *, tvbuff_t *, packet_info *pinfo);

static void add_capabilities (proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint8 pdu_type);


/*
 * Dissect the WSP header part.
 * This function calls wkh_XXX functions that dissect well-known headers.
 */
static void add_headers (proto_tree *tree, tvbuff_t *tvb, int hf, packet_info *pinfo);

/* The following macros define WSP basic data structures as found
 * in the ABNF notation of WSP headers.
 * Currently all text data types are mapped to text_string.
 */
#define is_short_integer(x)         ( (x) & 0x80 )
#define is_long_integer(x)          ( (x) <= 30 )
#define is_date_value(x)            is_long_integer(x)
#define is_integer_value(x)         (is_short_integer(x) || is_long_integer(x))
#define is_delta_seconds_value(x)   is_integer_value(x)
/* Text string == *TEXT 0x00, thus also an empty string matches the rule! */
#define is_text_string(x)           ( ((x) == 0) || ( ((x) >= 32) && ((x) <= 127)) )
#define is_quoted_string(x)         ( (x) == 0x22 ) /* " */
#define is_token_text(x)            is_text_string(x)
#define is_text_value(x)            is_text_string(x)
#define is_uri_value(x)             is_text_string(x)

#define get_uintvar_integer(val,tvb,start,len,ok) \
    val = tvb_get_guintvar(tvb,start,&len, pinfo, &ei_wsp_oversized_uintvar); \
    if (len>5) ok = FALSE; else ok = TRUE;
#define get_short_integer(val,tvb,start,len,ok) \
    val = tvb_get_guint8(tvb,start); \
    if (val & 0x80) ok = TRUE; else ok=FALSE; \
    val &= 0x7F; len = 1;
#define get_long_integer(val,tvb,start,len,ok) \
    len = tvb_get_guint8(tvb,start); \
    ok = TRUE; /* Valid lengths for us are 1-4 */ \
    if (len==1) { val = tvb_get_guint8(tvb,start+1); } \
    else if (len==2) { val = tvb_get_ntohs(tvb,start+1); } \
    else if (len==3) { val = tvb_get_ntoh24(tvb,start+1); } \
    else if (len==4) { val = tvb_get_ntohl(tvb,start+1); } \
    else ok = FALSE; \
    len++; /* Add the 1st octet to the length */
#define get_integer_value(val,tvb,start,len,ok) \
    len = tvb_get_guint8(tvb,start); \
    ok = TRUE; \
    if (len & 0x80) { val = len & 0x7F; len = 0; } \
    else if (len==1) { val = tvb_get_guint8(tvb,start+1); } \
    else if (len==2) { val = tvb_get_ntohs(tvb,start+1); } \
    else if (len==3) { val = tvb_get_ntoh24(tvb,start+1); } \
    else if (len==4) { val = tvb_get_ntohl(tvb,start+1); } \
    else ok = FALSE; \
    len++; /* Add the 1st octet to the length */
#define get_date_value(val,tvb,start,len,ok) \
    get_long_integer(val,tvb,start,len,ok)
#define get_delta_seconds_value(val,tvb,start,len,ok) \
    get_integer_value(val,tvb,start,len,ok)

/* NOTE - Do NOT call g_free() for the str returned after using it because the
 * get_text_string() macro now returns wmem_alloc'd memory. */
#define get_text_string(str,tvb,start,len,ok) \
    if (is_text_string(tvb_get_guint8(tvb,start))) { \
        str = (gchar *)tvb_get_stringz_enc(wmem_packet_scope(), tvb,start,(gint *)&len,ENC_ASCII); \
        ok = TRUE; \
    } else { len = 0; str = NULL; ok = FALSE; }
#define get_token_text(str,tvb,start,len,ok) \
    get_text_string(str,tvb,start,len,ok)
#define get_extension_media(str,tvb,start,len,ok) \
    get_text_string(str,tvb,start,len,ok)
#define get_text_value(str,tvb,start,len,ok) \
    get_text_string(str,tvb,start,len,ok)
#define get_quoted_string(str,tvb,start,len,ok) \
    get_text_string(str,tvb,start,len,ok)
#define get_uri_value(str,tvb,start,len,ok) \
    get_text_string(str,tvb,start,len,ok)

#define get_version_value(val,str,tvb,start,len,ok) \
    val = tvb_get_guint8(tvb,start); \
    ok = TRUE; \
    if (val & 0x80) { /* High nibble "." Low nibble */ \
        len = 1; \
        val &= 0x7F; \
        str = wmem_strdup_printf(wmem_packet_scope(), "%u.%u", val >> 4, val & 0x0F); \
    } else { get_text_string(str,tvb,start,len,ok); }

/* Parameter parser */
static int
parameter (proto_tree *tree, packet_info *pinfo, proto_item *ti, tvbuff_t *tvb, int start, int len);
static int
parameter_value_q (proto_tree *tree, packet_info *pinfo, proto_item *ti, tvbuff_t *tvb, int start);

/* The following macros hide common processing for all well-known headers
 * and shortens the code to be written in a wkh_XXX() function.
 * Even declarations are hidden by a macro.
 *
 * Define a wkh_XXX() function as follows:
 *
 * static guint32
 * wkh_XXX (proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
 * {
 *      wkh_0_Declarations;
 *      << add other required declarations here >>
 *
 *      wkh_1_WellKnownValue;
 *          << add well-known value proto item here; don't forget to set the
 *          ok variable to TRUE if parsing was correct >>
 *      wkh_2_TextualValue;
 *          << add textual value proto item here; don't forget to set the
 *          ok variable to TRUE if parsing was correct >>
 *      wkh_3_ValueWithLength;
 *          << add custom code for value processing and value proto item here >>
 *
 *      wkh_4_End();
 *          << This macro takes care of parse errors within the header value;
 *          it requires the header field index if the header has not yet been
 *          written to the protocol tree (ti == NULL). >>
 * }
 *
 *  NOTE:   You only need to write parsing code for the successful case,
 *          Errors are automatically reported through the wkh_4_End() macro
 *          when ok <> TRUE.
 */

/* The following code is the generic template with which the value of a
 * well-known header can be processed. Not all sections yield a semantically
 * correct result, so appropriate error information must be provided.
 */


#define wkh_0a_Declarations                 /* Declarations for Parsing */ \
    gboolean ok = FALSE; /* Triggers error notification code at end */ \
    proto_tree *header_tree; /* base tree for all fields */ \
    proto_item *header_item; /* base item for all fields */ \
    guint32 val_start = hdr_start + 1; \
    guint8 val_id = tvb_get_guint8 (tvb, val_start); \
    guint32 offset = val_start; /* Offset to one past this header */ \
    guint32 val_len; /* length for value with length field */ \
    guint32 val_len_len /* length of length field */

#define wkh_0_Declarations \
    wkh_0a_Declarations; \
        const gchar *val_str = NULL

#define wkh_1_WellKnownValue(hf_hdr, ett, header)          /* Parse Well Known Value */ \
    header_tree = proto_tree_add_subtree(tree, tvb, hdr_start, offset - hdr_start, ett, \
                                                &header_item, header); \
    proto_tree_add_item(header_tree, hf_hdr, tvb, hdr_start, 1, ENC_NA); \
    if (val_id & 0x80) { /* Well-known value */ \
        offset++; \
        /* Well-known value processing starts HERE \
         * \
         * BEGIN */

#define wkh_2_TextualValue                  /* Parse Textual Value */ \
        /* END */ \
    } else if ((val_id == 0) || (val_id >= 0x20)) { /* Textual value */ \
        val_str = (gchar *)tvb_get_stringz_enc(wmem_packet_scope(), tvb, val_start, (gint *)&val_len, ENC_ASCII); \
        offset = val_start + val_len; \
        /* Textual value processing starts HERE \
         * \
         * BEGIN */

#define wkh_2_TextualValueInv                   /* Parse Textual Value */ \
        /* END */ \
    } else if ((val_id == 0) || (val_id >= 0x20)) { /* Textual value */ \
        /*val_str = (gchar *)*/tvb_get_stringz_enc(wmem_packet_scope(), tvb, val_start, (gint *)&val_len, ENC_ASCII); \
        offset = val_start + val_len; \
        /* Textual value processing starts HERE \
         * \
         * BEGIN */

#define wkh_3_ValueWithLength               /* Parse Value With Length */ \
        /* END */ \
    } else { /* val_start points to 1st byte of length field */ \
        if (val_id == 0x1F) { /* Value Length = guintvar */ \
            val_len = tvb_get_guintvar(tvb, val_start + 1, &val_len_len, pinfo, &ei_wsp_oversized_uintvar); \
            val_len_len++; /* 0x1F length indicator byte */ \
        } else { /* Short length followed by Len data octets */ \
            val_len = tvb_get_guint8(tvb, offset); \
            val_len_len = 1; \
        } \
        offset += val_len_len + val_len; \
        /* Value with length processing starts HERE \
         * The value lies between val_start and offset: \
         *  - Value Length: Start  = val_start \
         *                  Length = val_len_len \
         *  - Value Data  : Start  = val_start + val_len_len \
         *                  Length = val_len \
         *                  End    = offset - 1 \
         * BEGIN */

#define wkh_4_End()                       /* End of value parsing */ \
        /* END */ \
    } \
    /* Check for errors */ \
    if (! ok) { \
        expert_add_info(pinfo, header_item, &ei_wsp_header_invalid_value); \
    } \
    return offset;


/*
 * This yields the following default header value parser function body
 */
static guint32
wkh_default(proto_tree *tree, tvbuff_t *tvb,
        guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;
    guint8 hdr_id = tvb_get_guint8 (tvb, hdr_start) & 0x7F;

    ok = TRUE; /* Bypass error checking as we don't parse the values! */

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_default, "default");
        proto_tree_add_uint_format(tree, hf_wsp_default_int, tvb, hdr_start, offset - hdr_start,
                val_id & 0x7F, "%s: (Undecoded well-known value 0x%02x)",
                val_to_str_ext (hdr_id, &vals_field_names_ext,
                    "<Unknown WSP header field 0x%02X>"), val_id & 0x7F);
    wkh_2_TextualValue;
        proto_tree_add_string_format(tree, hf_wsp_default_string, tvb, hdr_start, offset - hdr_start,
                "%s: %s",
                val_to_str_ext (hdr_id, &vals_field_names_ext,
                    "<Unknown WSP header field 0x%02X>"), val_str);
    wkh_3_ValueWithLength;
        proto_tree_add_uint_format(tree, hf_wsp_default_val_len, tvb, hdr_start, offset - hdr_start,
                val_len, "%s: (Undecoded value in general form with length indicator)",
                val_to_str_ext (hdr_id, &vals_field_names_ext,
                    "<Unknown WSP header field 0x%02X>"));

    wkh_4_End(); /* The default parser has no associated hf_index;
                            additionally the error code is always bypassed */
}


/* Content-type processing uses the following common core: */
static guint32
wkh_content_type_header(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo, int hf, const char* name)
{
    wkh_0_Declarations;
    guint32 off, val = 0, len;
    guint8 peek;
    proto_item *ti = NULL;
    proto_tree *parameter_tree = NULL;
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Content type: %s", name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_content_type_header, header_name);
        proto_tree_add_string(header_tree, hf, tvb, val_start, 1,
                val_to_str_ext(val_id & 0x7F, &vals_content_types_ext,
                    "(Unknown content type identifier 0x%X)"));
        proto_item_set_len(header_item, 2);
        ok = TRUE;
    wkh_2_TextualValue;
        /* Sometimes with a No-Content response, a NULL content type
         * is reported. Process this correctly! */
        if (*val_str) {
            proto_tree_add_string(header_tree, hf, tvb, val_start, val_len, val_str);
            proto_item_set_len(header_item, val_len+1);
        } else {
            proto_tree_add_string(header_tree, hf, tvb, val_start, 0,
                    "<no content type has been specified>");
            proto_item_set_len(header_item, 2);
        }
        ok = TRUE;
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        peek = tvb_get_guint8(tvb, off);
        if (is_text_string(peek)) {
            val_str = (gchar *)tvb_get_stringz_enc(wmem_packet_scope(), tvb, off, (gint*)&len, ENC_ASCII);
            off += len; /* off now points to 1st byte after string */
            ti = proto_tree_add_string (header_tree, hf, tvb, hdr_start, offset - hdr_start, val_str);
        } else if (is_integer_value(peek)) {
            get_integer_value(val, tvb, off, len, ok);
            if (ok) {
                ti = proto_tree_add_string(header_tree, hf,
                        tvb, hdr_start, offset - hdr_start,
                        val_to_str_ext(val, &vals_content_types_ext,
                            "(Unknown content type identifier 0x%X)"));
            }
            off += len;
        } else {
            ok = FALSE;
        }

        /* Remember: offset == val_start + val_len + val_len_len */
        if (ok && (off < offset)) { /* Add parameters if any */
            parameter_tree = proto_item_add_subtree (ti, ett_header);
            while (off < offset) {
                off = parameter (parameter_tree, pinfo, ti, tvb, off, offset - off);
            }
        }
    wkh_4_End();
}


/*
 * Accept-value =
 *    Short-integer
 *  | Extension-media
 *  | ( Value-length ( Extension-media | Integer-value ) *( Parameter ) )
 */
static guint32
wkh_accept(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo)
{
    return wkh_content_type_header(tree, tvb, hdr_start, pinfo, hf_hdr_accept, "Accept");
}


/*
 * Content-type-value =
 *    Short-integer
 *  | Extension-media
 *  | ( Value-length ( Extension-media | Integer-value ) *( Parameter ) )
 *
 * Beware: this header should not appear as such; it is dissected elsewhere
 * and at the same time the content type is used for subdissectors.
 * It is here for the sake of completeness.
 */
static guint32
wkh_content_type(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo)
{
    return wkh_content_type_header(tree, tvb, hdr_start, pinfo, hf_hdr_content_type, "Content-Type");
}


/*
 * Content-type-value =
 *    Short-integer
 *  | Extension-media
 *  | ( Value-length ( Extension-media | Integer-value ) *( Parameter ) )
 *
 * This function adds the content type value to the protocol tree,
 * and computes either the numeric or textual media type in return,
 * which will be used for further subdissection (e.g., MMS, WBXML).
 */
guint32
add_content_type(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint32 val_start,
        guint32 *well_known_content, const char **textual_content)
{
    /* Replace wkh_0_Declarations with slightly modified declarations
     * so we can still make use of the wkh_[1-4]_XXX macros! */
    guint32 hdr_start = val_start; /* No header name, only value! */
    guint8 val_id = tvb_get_guint8 (tvb, val_start);
    guint32 offset = val_start; /* Offset to one past this header */
    guint32 val_len; /* length for value with length field */
    guint32 val_len_len; /* length of length field */
    gchar *val_str = NULL;
    guint32 off, val = 0, len;
    guint8 peek;
    gboolean ok = FALSE;
    proto_item *ti = NULL;
    proto_tree *parameter_tree = NULL;
    proto_tree *header_tree;
    proto_item *header_item;

    *textual_content = NULL;
    *well_known_content = 0;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_add_content_type, "Content-Type");
        *textual_content = val_to_str_ext(val_id & 0x7F, &vals_content_types_ext,
                "<Unknown media type identifier 0x%X>");
        proto_tree_add_string(tree, hf_hdr_content_type,
                tvb, hdr_start, offset - hdr_start,
                *textual_content);
        *well_known_content = val_id & 0x7F;
        ok = TRUE;
    wkh_2_TextualValue;
        /* Sometimes with a No-Content response, a NULL content type
         * is reported. Process this correctly! */
        if (*val_str) {
            proto_tree_add_string(tree, hf_hdr_content_type,
                    tvb, hdr_start, offset - hdr_start,
                    val_str);
            *textual_content = g_strdup(val_str);
            *well_known_content = 0;
        } else {
            proto_tree_add_string(tree, hf_hdr_content_type,
                    tvb, hdr_start, offset - hdr_start,
                    "<no media type has been specified>");
            *textual_content = NULL;
            *well_known_content = 0;
        }
        ok = TRUE;
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        peek = tvb_get_guint8(tvb, off);
        if (is_text_string(peek)) {
            get_extension_media(val_str, tvb, off, len, ok);
            if (ok) {
                off += len; /* off now points to 1st byte after string */
                ti = proto_tree_add_string (tree, hf_hdr_content_type,
                    tvb, hdr_start, offset - hdr_start, val_str);
            }
            /* Following statement: required? */
            *textual_content = g_strdup(val_str);
            *well_known_content = 0;
        } else if (is_integer_value(peek)) {
            get_integer_value(val, tvb, off, len, ok);
            if (ok) {
                *textual_content = val_to_str_ext(val, &vals_content_types_ext,
                        "<Unknown media type identifier 0x%X>");
                ti = proto_tree_add_string(tree, hf_hdr_content_type,
                        tvb, hdr_start, offset - hdr_start,
                        *textual_content);
                *well_known_content = val;
            }
            off += len;
        } /* else ok = FALSE */
        /* Remember: offset == val_start + val_len_len + val_len */
        if (ok && (off < offset)) { /* Add parameters if any */
            parameter_tree = proto_item_add_subtree (ti, ett_header);
            while (off < offset) {
                off = parameter (parameter_tree, pinfo, ti, tvb, off, offset - off);
            }
        }

    wkh_4_End();
}


/*
 * Template for accept_X headers with optional Q parameter value
 */
#define wkh_accept_x_q_header(underscored,Text,valueStringExtAddr,valueName) \
static guint32 \
wkh_ ## underscored (proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo) \
{   \
    return wkh_accept_x_q_header_func(tree, tvb, hdr_start, pinfo,   \
                hf_hdr_ ## underscored, Text, valueStringExtAddr, \
                "<Unknown " valueName " identifier 0x%X>");   \
}

static guint32
wkh_accept_x_q_header_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo,
                           int hf, const char* name, value_string_ext *valueStringExtAddr, const char* value_format)
                           G_GNUC_PRINTF(8, 0);

static guint32
wkh_accept_x_q_header_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo,
                           int hf, const char* name, value_string_ext *valueStringExtAddr, const char* value_format)
{
    wkh_0_Declarations;
    guint32 off, val = 0, len;
    guint8 peek;
    proto_item *ti = NULL;
    proto_tree *parameter_tree = NULL;
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Accept X: %s", name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_accept_x_q_header, header_name);
        proto_tree_add_string(tree, hf,
                tvb, hdr_start, offset - hdr_start,
                val_to_str_ext(val_id & 0x7F, valueStringExtAddr, value_format));
        ok = TRUE;
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        peek = tvb_get_guint8(tvb, off);
        if (is_text_string(peek)) {
            get_token_text(val_str, tvb, off, len, ok);
            if (ok) {
                off += len; /* off now points to 1st byte after string */
                ti = proto_tree_add_string (tree, hf,
                        tvb, hdr_start, offset - hdr_start, val_str);
            }
        } else if (is_integer_value(peek)) {
            get_integer_value(val, tvb, off, len, ok);
            if (ok) {
                ti = proto_tree_add_string(tree, hf,
                        tvb, hdr_start, offset - hdr_start,
                        val_to_str_ext(val, valueStringExtAddr, value_format));
            }
            off += len;
        } /* else ok = FALSE */
        /* Remember: offset == val_start + val_len */
        if (ok && (off < offset)) { /* Add Q-value if available */
            parameter_tree = proto_item_add_subtree (ti, ett_header);
            /*off =*/ parameter_value_q (parameter_tree, pinfo, ti, tvb, off);
        }

    wkh_4_End();
}

/*
 * Accept-charset-value =
 *    Short-integer
 *  | Extension-media
 *  | ( Value-length ( Token-text | Integer-value ) [ Q-value ] )
 */
wkh_accept_x_q_header(accept_charset, "Accept-Charset",
        &mibenum_vals_character_sets_ext, "character set")
/*
 * Accept-language-value =
 *    Short-integer
 *  | Extension-media
 *  | ( Value-length ( Text-string | Integer-value ) [ Q-value ] )
 */
wkh_accept_x_q_header(accept_language, "Accept-Language",
        &vals_languages_ext, "language")


/*
 * Push-flag-value = Short-integer
 */
static guint32
wkh_push_flag(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0a_Declarations;
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;
    wmem_strbuf_t *push_flag_str = wmem_strbuf_new(wmem_packet_scope(), "");

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_push_flag, "Push Flag");
    if (val_id & 0x01)
        wmem_strbuf_append(push_flag_str, " (Initiator URI authenticated)");
    if (val_id & 0x02)
        wmem_strbuf_append(push_flag_str, " (Content trusted)");
    if (val_id & 0x04)
        wmem_strbuf_append(push_flag_str, " (Last push message)");
    if (val_id & 0x78)
        wmem_strbuf_append(push_flag_str, " <Warning: Reserved flags set>");
    else
        ok = TRUE;

    ti = proto_tree_add_string(tree, hf_hdr_push_flag,
            tvb, hdr_start, offset - hdr_start, wmem_strbuf_get_str(push_flag_str));
    subtree = proto_item_add_subtree(ti, ett_header);
    proto_tree_add_uint(subtree, hf_hdr_push_flag_auth,
            tvb, val_start, 1, val_id);
    proto_tree_add_uint(subtree, hf_hdr_push_flag_trust,
            tvb, val_start, 1, val_id);
    proto_tree_add_uint(subtree, hf_hdr_push_flag_last,
            tvb, val_start, 1, val_id);

    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}


/*
 * Profile-Diff (with WBXML): Profile-diff-value =
 *      Value-length <WBXML-Content>
 */
static guint32 wkh_profile_diff_wbxml (proto_tree *tree, tvbuff_t *tvb,
        guint32 hdr_start, packet_info *pinfo)
{
    wkh_0a_Declarations;
    tvbuff_t   *tmp_tvb;
    proto_item *ti = NULL;
    proto_tree *subtree;

    ok = TRUE; /* Bypass error checking as we don't parse the values! */

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_profile_diff_wbxml, "Profile-Diff (with WBXML)");
        /* Invalid */
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        ti = proto_tree_add_string(tree, hf_hdr_profile_diff, tvb, hdr_start, offset - hdr_start,
                "(Profile-Diff value as WBXML)");
        subtree = proto_item_add_subtree(ti, ett_header);
        tmp_tvb = tvb_new_subset_length(tvb, val_start + val_len_len, val_len); /* TODO: fix 2nd length */
        call_dissector(wbxml_uaprof_handle, tmp_tvb, pinfo, subtree);
        ok = TRUE;
    wkh_4_End();
}


/*
 * Allow-value =
 *     Short-integer
1 */
static guint32
wkh_allow(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo)
{
    wkh_0a_Declarations;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_allow, "Allow");
        val_id &= 0x7F;
        if (val_id >= 0x40) { /* Valid WSP method */
            proto_tree_add_string(tree, hf_hdr_allow,
                    tvb, hdr_start, offset - hdr_start,
                    val_to_str_ext(val_id & 0x7F, &wsp_vals_pdu_type_ext,
                        "<Unknown WSP method 0x%02X>"));
            ok = TRUE;
        }
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}


/*
 * Public-value =
 *     Token-text | Short-integer
2 */
static guint32
wkh_public(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo)
{
    wkh_0_Declarations;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_public, "Public");
        val_id &= 0x7F;
        if (val_id >= 0x40) { /* Valid WSP method */
            proto_tree_add_string(tree, hf_hdr_public,
                    tvb, hdr_start, offset - hdr_start,
                    val_to_str_ext(val_id & 0x7F, &wsp_vals_pdu_type_ext,
                        "<Unknown WSP method 0x%02X>"));
            ok = TRUE;
        }
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf_hdr_public,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}


/*
 * Vary-value =
 *     Token-text | Short-integer
 */
static guint32
wkh_vary(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_vary, "Vary");
        proto_tree_add_string(tree, hf_hdr_vary,
                tvb, hdr_start, offset - hdr_start,
                val_to_str_ext(val_id & 0x7F, &vals_field_names_ext,
                    "<Unknown WSP header field 0x%02X>"));
        ok = TRUE;
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf_hdr_vary,
                tvb, hdr_start, offset - hdr_start,
                val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}


/*
 * X-wap-security-value = 0x80
 */
static guint32
wkh_x_wap_security(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0a_Declarations;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_x_wap_security, "X-wap-security-value");
        if (val_id == 0x80) {
            proto_tree_add_string(tree, hf_hdr_x_wap_security,
                    tvb, hdr_start, offset - hdr_start, "close-subordinate");
            ok = TRUE;
        }
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}


/*
 * Connection-value = 0x80 | Token-text
5 */
static guint32
wkh_connection(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo)
{
    wkh_0_Declarations;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_connection, "Connection");
        if (val_id == 0x80) {
            proto_tree_add_string(tree, hf_hdr_connection,
                    tvb, hdr_start, offset - hdr_start, "close");
            ok = TRUE;
        }
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf_hdr_connection,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}


/*
 * Transfer-encoding-value = 0x80 | Token-text
 */
static guint32
wkh_transfer_encoding(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_transfer_encoding, "Transfer encoding");
        if (val_id == 0x80) {
            proto_tree_add_string(tree, hf_hdr_transfer_encoding,
                    tvb, hdr_start, offset - hdr_start, "chunked");
            ok = TRUE;
        }
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf_hdr_transfer_encoding,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}


/*
 * Accept-range-value = 0x80 | 0x81 | Token-text
 */
static guint32
wkh_accept_ranges(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_accept_ranges, "Accept Ranges");
        switch (val_id) {
            case 0x80: /* none */
                proto_tree_add_string(tree, hf_hdr_accept_ranges,
                        tvb, hdr_start, offset - hdr_start, "none");
                ok = TRUE;
                break;
            case 0x81: /* bytes */
                proto_tree_add_string(tree, hf_hdr_accept_ranges,
                        tvb, hdr_start, offset - hdr_start, "bytes");
                ok = TRUE;
                break;
        }
    wkh_2_TextualValue;
       proto_tree_add_string(tree, hf_hdr_accept_ranges,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}


/*
 * Content-encoding-value = 0x80 | 0x81 | 0x82 | Token-text
 */
static guint32
wkh_content_encoding(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_content_encoding, "Content Encoding");
        switch (val_id) {
            case 0x80: /* gzip */
                proto_tree_add_string(tree, hf_hdr_content_encoding,
                        tvb, hdr_start, offset - hdr_start, "gzip");
                ok = TRUE;
                break;
            case 0x81: /* compress */
                proto_tree_add_string(tree, hf_hdr_content_encoding,
                        tvb, hdr_start, offset - hdr_start, "compress");
                ok = TRUE;
                break;
            case 0x82: /* deflate */
                proto_tree_add_string(tree, hf_hdr_content_encoding,
                        tvb, hdr_start, offset - hdr_start, "deflate");
                ok = TRUE;
                break;
        }
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf_hdr_content_encoding,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}


/*
 * Accept-encoding-value =
 *    Short-integer
 *  | Token-text
 *  | ( Value-length ( Short-integer | Text-string ) [ Q-value ] )
 */
static guint32
wkh_accept_encoding(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo)
{
    wkh_0_Declarations;
    guint32     len, off;
    guint8      peek;
    gchar      *str;
    proto_item *ti = NULL;
    proto_tree *parameter_tree = NULL;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_accept_encoding, "Accept Encoding");
        switch (val_id) {
            case 0x80: /* gzip */
                proto_tree_add_string(tree, hf_hdr_accept_encoding,
                        tvb, hdr_start, offset - hdr_start, "gzip");
                ok = TRUE;
                break;
            case 0x81: /* compress */
                proto_tree_add_string(tree, hf_hdr_accept_encoding,
                        tvb, hdr_start, offset - hdr_start, "compress");
                ok = TRUE;
                break;
            case 0x82: /* deflate */
                proto_tree_add_string(tree, hf_hdr_accept_encoding,
                        tvb, hdr_start, offset - hdr_start, "deflate");
                ok = TRUE;
                break;
            case 0x83: /* * */
                proto_tree_add_string(tree, hf_hdr_accept_encoding,
                        tvb, hdr_start, offset - hdr_start, "*");
                ok = TRUE;
                break;
        }
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf_hdr_accept_encoding,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        peek = tvb_get_guint8(tvb, off);
        if (is_short_integer(peek)) {
            switch (peek) {
                case 0x80: /* gzip */
                    ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
                            tvb, hdr_start, offset - hdr_start, "gzip");
                    ok = TRUE;
                    break;
                case 0x81: /* compress */
                    ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
                            tvb, hdr_start, offset - hdr_start, "compress");
                    ok = TRUE;
                    break;
                case 0x82: /* deflate */
                    ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
                            tvb, hdr_start, offset - hdr_start, "deflate");
                    ok = TRUE;
                    break;
                case 0x83: /* any */
                    ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
                            tvb, hdr_start, offset - hdr_start, "*");
                    ok = TRUE;
                    break;
            }
            off++;
        } else {
            get_token_text(str, tvb, off, len, ok);
            if (ok) {
                ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
                        tvb, hdr_start, offset - hdr_start, str);
            }
            off += len;
        }
        if (ok) {
            /* Remember: offset == val_start + val_len_len + val_len */
            if (off < offset) { /* Add Q-value if available */
                parameter_tree = proto_item_add_subtree(ti, ett_header);
                parameter_value_q(parameter_tree, pinfo, ti, tvb, off);
            }
        }
    wkh_4_End();
}


/*
 * Content-disposition-value = Value-length ( Disposition ) *( Parameter )
 *  Disposition = Form-data | Attachment | Inline | Token-text
 *  Form-data = 0x80
 *  Attachment = 0x81
 *  Inline = 0x82
 * We handle this as:
 *  Value-length ( Short-integer | Text-string ) *( Parameter )
 */
static guint32
wkh_content_disposition(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo)
{
    wkh_0a_Declarations;
    guint32     len, off;
    guint8      peek;
    gchar      *str;
    proto_item *ti = NULL;
    proto_tree *parameter_tree = NULL;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_content_disposition, "Content Disposition");
        /* Invalid */
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        peek = tvb_get_guint8(tvb, off);
        if (is_short_integer(peek)) {
            switch (peek) {
                case 0x80: /* form-data */
                    ti = proto_tree_add_string(tree, hf_hdr_content_disposition,
                            tvb, hdr_start, offset - hdr_start, "form-data");
                    ok = TRUE;
                    break;
                case 0x81: /* attachment */
                    ti = proto_tree_add_string(tree, hf_hdr_content_disposition,
                            tvb, hdr_start, offset - hdr_start, "attachment");
                    ok = TRUE;
                    break;
                case 0x82: /* inline */
                    ti = proto_tree_add_string(tree, hf_hdr_content_disposition,
                            tvb, hdr_start, offset - hdr_start, "inline");
                    ok = TRUE;
                    break;
            }
            off++;
        } else {
            get_token_text(str, tvb, off, len, ok);
            if (ok) {
                ti = proto_tree_add_string(tree, hf_hdr_content_disposition,
                        tvb, hdr_start, offset - hdr_start, str);
            }
            off += len;
        }
        if ((ok) && (off < offset)) {
            /* Remember: offset == val_start + val_len_len + val_len */
            parameter_tree = proto_item_add_subtree(ti, ett_header);
            while (off < offset) { /* Add parameters if available */
                off = parameter(parameter_tree, pinfo, ti, tvb, off, offset - off);
            }
        }
    wkh_4_End();
}


/*
 * Common code for headers with only a textual value
 * is written in the macro below:
 */
#define wkh_text_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{   \
    return wkh_text_header_func(tree, tvb, hdr_start, pinfo, hf_hdr_ ## underscored, Text);  \
}

static guint32
wkh_text_header_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo, int hf, const char* name)
{
    wkh_0_Declarations;
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Header: %s", name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_text_header, header_name);
        /* Invalid */
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}

/* Text-only headers: */
wkh_text_header(content_base, "Content-Base")
wkh_text_header(content_location, "Content-Location")
wkh_text_header(etag, "ETag")
wkh_text_header(from, "From")
wkh_text_header(host, "Host")
wkh_text_header(if_match, "If-Match")
wkh_text_header(if_none_match, "If-None-Match")
wkh_text_header(location, "Location")
wkh_text_header(referer, "Referer")
wkh_text_header(server, "Server")
wkh_text_header(user_agent, "User-Agent")
wkh_text_header(upgrade, "Upgrade")
wkh_text_header(via, "Via")
wkh_text_header(content_uri, "Content-Uri")
wkh_text_header(initiator_uri, "Initiator-Uri")
wkh_text_header(profile, "Profile")

/*
 * Same for quoted-string value
 */
static guint32
wkh_content_id(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo)
{
    wkh_0_Declarations;
    gchar *str;
    proto_item *ti = NULL;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_content_id, "Content ID");
        /* Invalid */
    wkh_2_TextualValue;
        if (is_quoted_string(val_str[0])) {
            if (is_quoted_string(val_str[val_len-2])) {
                /* Trailing quote - issue a warning */
                ti = proto_tree_add_string(tree, hf_hdr_content_id,
                    tvb, hdr_start, offset - hdr_start, val_str);
                expert_add_info(pinfo, ti, &ei_wsp_trailing_quote);
            } else { /* OK (no trailing quote) */
                str = wmem_strdup_printf(wmem_packet_scope(), "%s\"", val_str);
                proto_tree_add_string(tree, hf_hdr_content_id,
                    tvb, hdr_start, offset - hdr_start, str);
            }
        } else {
            ti = proto_tree_add_string(tree, hf_hdr_content_id,
                    tvb, hdr_start, offset - hdr_start, val_str);
            expert_add_info(pinfo, ti, &ei_wsp_trailing_quote);
        }
        ok = TRUE;
    wkh_3_ValueWithLength;
        /* Invalid */
    wkh_4_End();
}


/*
 * Common code for headers with only a textual or a date value
 * is written in the macro below:
 */
#define wkh_text_or_date_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo) \
{   \
    return wkh_text_or_date_value_header_func(tree, tvb, hdr_start, pinfo, hf_hdr_ ## underscored, Text);   \
}

static guint32
wkh_text_or_date_value_header_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo, int hf, const char* name)
{
    wkh_0_Declarations;
    guint32 val = 0, off = val_start, len;
    gchar *str; /* may not be freed! */
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Text or Date: %s", name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_text_or_date_value, header_name);
        /* Invalid */
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        if (val_id <= 4) { /* Length field already parsed by macro! */
            get_date_value(val, tvb, off, len, ok);
            if (ok) {
                str = abs_time_secs_to_str(wmem_packet_scope(), val, ABSOLUTE_TIME_LOCAL, TRUE);
                proto_tree_add_string(tree, hf,
                        tvb, hdr_start, offset - hdr_start, str);
            }
        }
    wkh_4_End();
}

/* If-Range */
wkh_text_or_date_value_header(if_range,"If-Range")


/*
 * Common code for headers with only a date value
 * is written in the macro below:
 */
#define wkh_date_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo) \
{   \
    return wkh_date_value_header_func(tree, tvb, hdr_start, pinfo, hf_hdr_ ## underscored, Text);   \
}

static guint32
wkh_date_value_header_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo, int hf, const char* name)
{
    wkh_0a_Declarations;
    guint32 val = 0, off = val_start, len;
    gchar *str; /* may not be freed! */
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Date: %s", name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_date_value, header_name);
        /* Invalid */
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        if (val_id <= 4) { /* Length field already parsed by macro! */
            get_date_value(val, tvb, off, len, ok);
            if (ok) {
                str = abs_time_secs_to_str(wmem_packet_scope(), val, ABSOLUTE_TIME_LOCAL, TRUE);
                proto_tree_add_string(tree, hf,
                        tvb, hdr_start, offset - hdr_start, str);
                /* BEHOLD: do NOT try to free str, as
                 * abs_time_secs_to_str(wmem_packet_scope(), ) returns wmem_allocated data */
            }
        }
    wkh_4_End();
}

/* Date-value only headers: */
wkh_date_value_header(date, "Date")
wkh_date_value_header(expires, "Expires")
wkh_date_value_header(if_modified_since, "If-Modified-Since")
wkh_date_value_header(if_unmodified_since, "If-Unmodified-Since")
wkh_date_value_header(last_modified, "Last-Modified")


/* Date-value with special interpretation of zero value */
#define wkh_tod_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo) \
{   \
    return wkh_tod_value_header_func(tree, tvb, hdr_start, pinfo, hf_hdr_ ## underscored, Text);   \
}

static guint32
wkh_tod_value_header_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo, int hf, const char* name)
{
    wkh_0a_Declarations;
    guint32 val = 0, off = val_start, len;
    gchar *str; /* may not be freed! */
    proto_item *ti = NULL;
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Time of Day: %s", name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_tod_value, header_name);
        if (val_id == 0x80) { /* Openwave TOD header uses this format */
            ti = proto_tree_add_string(tree, hf,
                    tvb, hdr_start, offset - hdr_start,
                    "Requesting Time Of Day");
            proto_item_append_text(ti,
                    " <Warning: should be encoded as long-integer>");
            ok = TRUE;
        }
        /* It seems VERY unlikely that we'll see date values within the first
         * 127 seconds of the UNIX 1-1-1970 00:00:00 start of the date clocks
         * so I assume such a value is a genuine error */
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        if (val_id <= 4) { /* Length field already parsed by macro! */
            get_date_value(val, tvb, off, len, ok);
            if (ok) {
                if (val == 0) {
                    proto_tree_add_string(tree, hf,
                            tvb, hdr_start, offset - hdr_start,
                            "Requesting Time Of Day");
                } else {
                    str = abs_time_secs_to_str(wmem_packet_scope(), val, ABSOLUTE_TIME_LOCAL, TRUE);
                    proto_tree_add_string(tree, hf,
                            tvb, hdr_start, offset - hdr_start, str);
                }
            }
        }
    wkh_4_End();
}

wkh_tod_value_header(x_wap_tod, "X-Wap-Tod")


/*
 * Age-value: Delta-seconds-value
 */
static guint32
wkh_age(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;
    guint32 val = 0, off = val_start, len;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_age, "Age");
        val = val_id & 0x7F;
        val_str = wmem_strdup_printf(wmem_packet_scope(), "%u second%s", val, plurality(val, "", "s"));
        proto_tree_add_string(tree, hf_hdr_age,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        if (val_id <= 4) { /* Length field already parsed by macro! */
            get_long_integer(val, tvb, off, len, ok);
            if (ok) {
                val_str = wmem_strdup_printf(wmem_packet_scope(), "%u second%s", val, plurality(val, "", "s"));
                proto_tree_add_string(tree, hf_hdr_age,
                        tvb, hdr_start, offset - hdr_start, val_str);
            }
        }
    wkh_4_End();
}


/*
 * Template for Integer lookup or text value headers:
 */
#define wkh_integer_lookup_or_text_value(underscored,Text,valueStringExtAddr,valueName) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo) \
{   \
    return wkh_integer_lookup_or_text_value_func(tree, tvb, hdr_start, pinfo,          \
                        hf_hdr_ ## underscored, Text,valueStringExtAddr, \
                        "<Unknown " valueName " identifier 0x%X>");   \
}

static guint32
wkh_integer_lookup_or_text_value_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo,
                        int hf, const char* name, value_string_ext *valueStringExtAddr, const char* value_format)
                        G_GNUC_PRINTF(8, 0);

static guint32
wkh_integer_lookup_or_text_value_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo,
                        int hf, const char* name, value_string_ext *valueStringExtAddr, const char* value_format)
{
    wkh_0_Declarations;
    guint32 off = val_start, len;
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Integer lookup: %s", name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_integer_lookup, header_name);
        proto_tree_add_string(tree, hf,
                tvb, hdr_start, offset - hdr_start,
                val_to_str_ext(val_id & 0x7F, valueStringExtAddr, value_format));
        ok = TRUE;
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        if (val_id <= 4) { /* Length field already parsed by macro! */
            len = tvb_get_guint8(tvb,off);
            ok = (len >= 1 && len <= 4); /* Valid lengths for us are 1-4 */
            if (ok) {
                proto_tree_add_string(tree, hf,
                        tvb, hdr_start, offset - hdr_start,
                        val_to_str_ext(val_id & 0x7F, valueStringExtAddr, value_format));
            }
        }
    wkh_4_End();
}

/*
 * Wap-application-value: Uri-value | Integer-value
 */
wkh_integer_lookup_or_text_value(x_wap_application_id, "X-Wap-Application-Id",
        &vals_wap_application_ids_ext, "WAP application")
wkh_integer_lookup_or_text_value(accept_application, "Accept-Application",
        &vals_wap_application_ids_ext, "WAP application")
wkh_integer_lookup_or_text_value(content_language, "Content-Language",
        &vals_languages_ext, "language")
/* NOTE - Although the WSP spec says this is an integer-value, the WSP headers
 * are encoded as a 7-bit entity! */
wkh_integer_lookup_or_text_value(trailer, "Trailer",
        &vals_field_names_ext, "well-known-header")


/*
 * Challenge
 */

/*
 * Common code for headers with only a challenge value
 * is written in the macro below:
 */
#define wkh_challenge_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo) \
{   \
    return wkh_challenge_value_header_func(tree, tvb, hdr_start, pinfo,               \
                     hf_hdr_ ## underscored, hf_hdr_ ## underscored ## _scheme,         \
                     hf_hdr_ ## underscored ## _realm, Text);   \
}

static guint32
wkh_challenge_value_header_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo,
                                   int hf, int hf_scheme, int hf_realm, const char* name)
{
    wkh_0a_Declarations;
    guint8 peek;
    guint32 off, len;
    proto_tree *subtree;
    gchar *str;
    proto_item *ti = NULL;
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Challenge: %s", name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_challenge, header_name);
        /* Invalid */
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        peek = tvb_get_guint8(tvb, off);
        if (peek == 0x80) { /* Basic */
            ti = proto_tree_add_string(tree, hf,
                    tvb, hdr_start, offset - hdr_start, "basic");
            subtree = proto_item_add_subtree(ti, ett_header);
            proto_tree_add_string(subtree, hf_scheme,
                    tvb, off, 1, "basic");
            off++;
            /* Realm: text-string */
            get_text_string(str,tvb,off,len,ok);
            if (ok) {
                proto_tree_add_string(subtree,
                        hf_realm,
                        tvb, off, len, str);
                proto_item_append_text(ti, "; realm=%s", str);
                /*off += len;*/
            }
        } else { /* Authentication-scheme: token-text */
            get_token_text(str, tvb, off, len, ok);
            if (ok) {
                ti = proto_tree_add_string(tree, hf,
                        tvb, hdr_start, off - hdr_start, str);
                subtree = proto_item_add_subtree(ti, ett_header);
                proto_tree_add_string(subtree,
                        hf_scheme,
                        tvb, hdr_start, off - hdr_start, str);
                off += len;
                /* Realm: text-string */
                get_text_string(str,tvb,off,len,ok);
                if (ok) {
                    proto_tree_add_string(subtree,
                            hf_realm,
                            tvb, off, len, str);
                    proto_item_append_text(ti, "; realm=%s", str);
                    off += len;
                    /* Auth-params: parameter - TODO */
                    while (off < offset) /* Parse parameters */
                        off = parameter(subtree, pinfo, ti, tvb, off, offset - off);
                }
            }
        }
    wkh_4_End();
}

/* Challenge-value only headers: */
wkh_challenge_value_header(www_authenticate, "WWW-Authenticate")
wkh_challenge_value_header(proxy_authenticate, "Proxy-Authenticate")


/*
 * Credentials
 */

/*
 * Common code for headers with only a credentials value
 * is written in the macro below:
 */
#define wkh_credentials_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo) \
{   \
    return wkh_credentials_value_header_func(tree, tvb, hdr_start, pinfo,               \
                     hf_hdr_ ## underscored, hf_hdr_ ## underscored ## _scheme,         \
                     hf_hdr_ ## underscored ## _user_id, hf_hdr_ ## underscored ## _password, Text);   \
}

static guint32
wkh_credentials_value_header_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo,
                                   int hf, int hf_scheme, int hf_userid, int hf_password, const char* name)
{
    wkh_0a_Declarations;
    guint8 peek;
    guint32 off, len;
    proto_tree *subtree;
    gchar *str;
    proto_item *ti = NULL;
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Credentials: %s", name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_credentials_value, header_name);
        /* Invalid */
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        peek = tvb_get_guint8(tvb, off);
        if (peek == 0x80) { /* Basic */
            ti = proto_tree_add_string(tree, hf,
                    tvb, hdr_start, offset - hdr_start, "basic");
            subtree = proto_item_add_subtree(ti, ett_header);
            proto_tree_add_string(subtree, hf_scheme,
                    tvb, off, 1, "basic");
            off++;
            /* User-id: text-string */
            get_text_string(str,tvb,off,len,ok);
            if (ok) {
                proto_tree_add_string(subtree,
                        hf_userid,
                        tvb, off, len, str);
                proto_item_append_text(ti, "; user-id=%s", str);
                off += len;
                /* Password: text-string */
                get_text_string(str,tvb,off,len,ok);
                if (ok) {
                    proto_tree_add_string(subtree,
                            hf_password,
                            tvb, off, len, str);
                    proto_item_append_text(ti, "; password=%s", str);
                    /*off += len;*/
                }
            }
        } else { /* Authentication-scheme: token-text */
            get_token_text(str, tvb, off, len, ok);
            if (ok) {
                ti = proto_tree_add_string(tree, hf,
                        tvb, hdr_start, off - hdr_start, str);
                subtree = proto_item_add_subtree(ti, ett_header);
                proto_tree_add_string(subtree,
                        hf_scheme,
                        tvb, hdr_start, off - hdr_start, str);
                off += len;
                /* Auth-params: parameter - TODO */
                while (off < offset) /* Parse parameters */
                    off = parameter(subtree, pinfo, ti, tvb, off, offset - off);
            }
        }
    wkh_4_End();
}

/* Credentials-value only headers: */
wkh_credentials_value_header(authorization, "Authorization")
wkh_credentials_value_header(proxy_authorization, "Proxy-Authorization")


/*
 * Content-md5-value = 16*16 OCTET
 */
static guint32
wkh_content_md5 (proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0a_Declarations;
    guint32 off;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_content_md5, "Content-md5");
        /* Invalid */
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        if (val_len == 16) {
            proto_tree_add_item(tree, hf_hdr_content_md5,
                    tvb, off, val_len, ENC_NA);
            ok = TRUE;
        }
    wkh_4_End();
}


/*
 * Pragma-value = 0x80 | Length Parameter
 */
static guint32
wkh_pragma(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo)
{
    wkh_0a_Declarations;
    guint32 off;
    proto_item *ti = NULL;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_pragma, "Pragma");
        if (val_id == 0x80) {
            proto_tree_add_string(tree, hf_hdr_pragma,
                    tvb, hdr_start, offset - hdr_start, "no-cache");
            ok = TRUE;
        }
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        ti = proto_tree_add_string(tree, hf_hdr_pragma,
                tvb, hdr_start, off - hdr_start, "");
        /* NULL subtree for parameter() results in no subtree
         * TODO - provide a single parameter dissector that appends data
         * to the header field data. */
        parameter(NULL, pinfo, ti, tvb, off, offset - off);
        ok = TRUE;
    wkh_4_End();
}


/*
 * Integer-value
 */
#define wkh_integer_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo) \
{   \
    return wkh_integer_value_header_func(tree, tvb, hdr_start, pinfo, hf_hdr_ ## underscored, Text); \
}

static guint32
wkh_integer_value_header_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo, int hf, const char* name)
{
    wkh_0a_Declarations;
    guint32 val = 0, off = val_start, len;
    gchar *str; /* may not be freed! */
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Integer-value: %s", name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_integer_value, header_name);
        str = wmem_strdup_printf(wmem_packet_scope(), "%u", val_id & 0x7F);
        proto_tree_add_string(tree, hf,
                tvb, hdr_start, offset - hdr_start, str);
        ok = TRUE;
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        if (val_id <= 4) { /* Length field already parsed by macro! */
            get_long_integer(val, tvb, off, len, ok);
            if (ok) {
                str = wmem_strdup_printf(wmem_packet_scope(), "%u", val);
                proto_tree_add_string(tree, hf,
                        tvb, hdr_start, offset - hdr_start, str);
            }
        }
    wkh_4_End();
}

wkh_integer_value_header(content_length, "Content-Length")
wkh_integer_value_header(max_forwards, "Max-Forwards")


#define wkh_integer_lookup_value_header(underscored,Text,valueStringExtAddr,valueName) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo) \
{   \
    return wkh_integer_lookup_value_header_func(tree, tvb, hdr_start, pinfo,          \
                        hf_hdr_ ## underscored, Text,valueStringExtAddr, valueName);   \
}

static guint32
wkh_integer_lookup_value_header_func(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo,
                        int hf, const char* name, value_string_ext *valueStringExtAddr, const char* value_name)
{
    wkh_0_Declarations;
    guint32 off = val_start, len;
    gchar* header_name = wmem_strdup_printf(wmem_packet_scope(), "Integer lookup: %s", name);
    gchar* value_name_str = wmem_strdup_printf(wmem_packet_scope(), "<Unknown %s>", value_name);

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_integer_lookup_value, header_name);
        val_str = try_val_to_str_ext(val_id & 0x7F, valueStringExtAddr);
        if (val_str) {
            proto_tree_add_string(tree, hf,
                tvb, hdr_start, offset - hdr_start, val_str);
            ok = TRUE;
        } else {
            proto_tree_add_string(tree, hf,
                tvb, hdr_start, offset - hdr_start,
                value_name_str);
        }
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        if (val_id <= 4) { /* Length field already parsed by macro! */
            len = tvb_get_guint8(tvb,off);
            ok = (len >= 1 && len <= 4); /* Valid lengths for us are 1-4 */
            if (ok) {
                val_str = try_val_to_str_ext(val_id & 0x7F, valueStringExtAddr);
                if (val_str) {
                    proto_tree_add_string(tree, hf,
                        tvb, hdr_start, offset - hdr_start, val_str);
                    ok = TRUE;
                } else {
                    proto_tree_add_string(tree, hf,
                        tvb, hdr_start, offset - hdr_start,
                        value_name_str);
                }
            }
        }
    wkh_4_End();
}

wkh_integer_lookup_value_header(bearer_indication, "Bearer-Indication",
        &vals_bearer_types_ext, "bearer type")


/*
 * Cache-control-value
 */
static guint32
wkh_cache_control(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;
    guint32 off, len, val = 0;
    guint8 peek, cache_control_directive;
    proto_item *ti = NULL;
    wmem_strbuf_t *cache_str;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_cache_control, "Cache-control");
        val = val_id & 0x7F;
        val_str = try_val_to_str_ext(val, &vals_cache_control_ext);
        if (val_str) {
            proto_tree_add_string(tree, hf_hdr_cache_control,
                    tvb, hdr_start, offset - hdr_start, val_str);
            ok = TRUE;
        }
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf_hdr_cache_control,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        /* General form:
         *    ( no-cache | private ) 1*( Field-name )
         *  | ( max-age | max-stale | min-fresh | s-maxage) Delta-seconds-value
         *  | Token-text ( Integer-value | Text-value )
         * Where:
         *  Field-name = Short-integer | Token-text
         */
        off = val_start + val_len_len;
        cache_control_directive = tvb_get_guint8(tvb, off++);
        if (cache_control_directive & 0x80) { /* Well known cache directive */
            switch (cache_control_directive & 0x7F) {
                case CACHE_CONTROL_NO_CACHE:
                case CACHE_CONTROL_PRIVATE:
                    cache_str = wmem_strbuf_new(wmem_packet_scope(), val_to_str_ext (cache_control_directive & 0x7F, &vals_cache_control_ext,
                                "<Unknown cache control directive 0x%02X>"));
                    /* TODO: split multiple entries */
                    ok = TRUE;
                    while (ok && (off < offset)) { /* 1*( Field-name ) */
                        peek = tvb_get_guint8(tvb, off);
                        if (peek & 0x80) { /* Well-known-field-name */
                            wmem_strbuf_append(cache_str,
                                    val_to_str (peek, vals_field_names,
                                        "<Unknown WSP header field 0x%02X>"));
                            off++;
                        } else { /* Token-text */
                            get_token_text(val_str, tvb, off, len, ok);
                            if (ok) {
                                wmem_strbuf_append(cache_str, val_str);
                                off += len;
                            }
                        }
                    }
                    proto_tree_add_string(tree, hf_hdr_cache_control,
                            tvb, hdr_start, offset - hdr_start,
                            wmem_strbuf_get_str(cache_str));
                    break;

                case CACHE_CONTROL_MAX_AGE:
                case CACHE_CONTROL_MAX_STALE:
                case CACHE_CONTROL_MIN_FRESH:
                case CACHE_CONTROL_S_MAXAGE:
                    ti = proto_tree_add_string(tree, hf_hdr_cache_control,
                            tvb, hdr_start, offset - hdr_start,
                            val_to_str_ext (cache_control_directive & 0x7F, &vals_cache_control_ext,
                                "<Unknown cache control directive 0x%02X>"));
                    get_delta_seconds_value(val, tvb, off, len, ok);
                    if (ok) {
                        proto_item_append_text(ti, "=%u second%s", val, plurality(val, "", "s"));
                    }
                    break;

                default:
                    /* ok = FALSE */
                    break;
            }
        } else if (is_token_text(cache_control_directive)) {
            get_token_text(val_str, tvb, off, len, ok);
            if (ok) {
                ti = proto_tree_add_string(tree, hf_hdr_cache_control,
                        tvb, hdr_start, offset - hdr_start, val_str);
                get_integer_value(val, tvb, off, len, ok);
                if (ok) { /* Integer-value */
                    proto_item_append_text(ti, "=%u", val);
                } else { /* Text-value */
                    get_text_string(val_str, tvb, off, len, ok);
                    if (ok) {
                        if (is_quoted_string(val_str[0])) {
                            if (is_quoted_string(val_str[len-2])) {
                                /* Trailing quote - issue a warning */
                                expert_add_info(pinfo, ti, &ei_wsp_trailing_quote);
                            } else { /* OK (no trailing quote) */
                                proto_item_append_text(ti, "%s\"", val_str);
                            }
                        } else { /* Token-text | 0x00 */
                            /* TODO - check that we have Token-text or 0x00 */
                            proto_item_append_text(ti, "%s", val_str);
                        }
                    }
                }
            }
        }
    wkh_4_End();
}


/*
 * Warning-value =
 *    Short-integer
 *  | ( Value-length Short-integer Text-string Text-string )
 */
static guint32
wkh_warning(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;
    guint32     off, len, val;
    guint8      warn_code;
    gchar      *str;
    proto_item *ti = NULL;
    proto_tree *subtree;

    /* TODO - subtree with values */

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_warning, "Warning");
        val = val_id & 0x7F;
        val_str = try_val_to_str_ext(val, &vals_wsp_warning_code_ext);
        if (val_str) {
            ti = proto_tree_add_string(tree, hf_hdr_warning,
                    tvb, hdr_start, offset - hdr_start, val_str);
            subtree = proto_item_add_subtree(ti, ett_header);
            proto_tree_add_uint(subtree, hf_hdr_warning_code,
                    tvb, val_start, 1, val);
            ok = TRUE;
        }
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        /* TODO - subtree with individual values */
        off = val_start + val_len_len;
        warn_code = tvb_get_guint8(tvb, off);
        if (warn_code & 0x80) { /* Well known warn code */
            val = warn_code & 0x7f;
            val_str = try_val_to_str_ext(val, &vals_wsp_warning_code_short_ext);
            if (val_str) { /* OK */
                str = wmem_strdup_printf(wmem_packet_scope(), "code=%s", val_str);
                ti = proto_tree_add_string(tree, hf_hdr_warning,
                        tvb, hdr_start, offset - hdr_start, str);
                subtree = proto_item_add_subtree(ti, ett_header);
                proto_tree_add_uint(subtree, hf_hdr_warning_code,
                        tvb, off, 1, val);
                off++; /* Now skip to the warn-agent subfield */
                get_text_string(str, tvb, off, len, ok);
                if (ok) { /* Valid warn-agent string */
                    proto_tree_add_string(subtree, hf_hdr_warning_agent,
                            tvb, off, len, str);
                    proto_item_append_text(ti, "; agent=%s", str);
                    off += len;
                    get_text_string(str, tvb, off, len, ok);
                    if (ok) { /* Valid warn-text string */
                        proto_tree_add_string(subtree,
                                hf_hdr_warning_text,
                                tvb, off, len, str);
                        proto_item_append_text(ti, "; text=%s", str);
                        /*off += len;*/
                    }
                }
            }
        }
    wkh_4_End();
}


/*
 * Profile-warning-value =
 *    Short-integer
 *  | ( Value-length Short-integer Text-string *( Date-value ) )
 */
static guint32
wkh_profile_warning(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;
    guint32  off, len, val = 0;
    guint8   warn_code;
    proto_item *ti = NULL;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_profile_warning, "Profile-warning");
        val = val_id & 0x7F;
        val_str = try_val_to_str_ext(val, &vals_wsp_profile_warning_code_ext);
        if (val_str) {
            proto_tree_add_string(tree, hf_hdr_profile_warning,
                    tvb, hdr_start, offset - hdr_start, val_str);
            ok = TRUE;
        }
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        warn_code = tvb_get_guint8(tvb, off++);
        if (warn_code & 0x80) { /* Well known warn code */
            val_str = try_val_to_str_ext(val, &vals_wsp_profile_warning_code_ext);
            if (val_str) { /* OK */
                ti = proto_tree_add_string(tree, hf_hdr_profile_warning,
                        tvb, hdr_start, offset - hdr_start, val_str);
                get_uri_value(val_str, tvb, off, len, ok);
                if (ok) { /* Valid warn-target string */
                    /* TODO: Why did we just call get_uri_value() and not use
                     * the str, since the pointer to it is immediately
                     * forgotten with the call to g_strdup_printf()? */
                    off += len;
                    proto_item_append_text(ti, "; target=%s", val_str);
                    /* Add zero or more dates */
                    while (ok && (off < offset)) {
                        get_date_value(val, tvb, off, len, ok);
                        if (ok) { /* Valid warn-text string */
                            off += len;
                            proto_item_append_text(ti, "; date=%s", abs_time_secs_to_str(wmem_packet_scope(), val, ABSOLUTE_TIME_LOCAL, TRUE));
                        }
                    }
                }
            }
        }
    wkh_4_End();
}


/* Encoding-version-value =
 *    Short-integer
 *  | Text-string
 *  | Length Short-integer [ Short-integer | text-string ]
 */
static guint32 wkh_encoding_version (proto_tree *tree, tvbuff_t *tvb,
        guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;
    proto_item *ti = NULL;
    guint32  off, val, len;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_encoding_version, "Encoding-version");
        val = val_id & 0x7F;
        val_str = wmem_strdup_printf(wmem_packet_scope(), "%u.%u", val >> 4, val & 0x0F);
        proto_tree_add_string(tree, hf_hdr_encoding_version,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_2_TextualValue;
        proto_tree_add_string(tree, hf_hdr_encoding_version,
                tvb, hdr_start, offset - hdr_start, val_str);
        ok = TRUE;
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        val = tvb_get_guint8(tvb, off);
        if (val & 0x80) { /* Header Code Page */
            val_str = wmem_strdup_printf(wmem_packet_scope(), "code-page=%u", val & 0x7F);
            ti = proto_tree_add_string(tree, hf_hdr_encoding_version,
                    tvb, hdr_start, offset - hdr_start, val_str);
            off++;
            ok = TRUE;
            if (off < offset) { /* Extra version-value */
                get_version_value(val,val_str,tvb,off,len,ok);
                if (ok) { /* Always creates a string if OK */
                    proto_item_append_text(ti, ": %s", val_str);
                }
            }
        }

    wkh_4_End();
}


/* Content-range-value =
 *    Length Uintvar-integer ( 0x80 | Uintvar-integer )
 */
static guint32
wkh_content_range(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;
    guint32     off, val, len;
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_content_range, "Content range");
        /* Invalid */
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        get_uintvar_integer (val, tvb, off, len, ok); /* Uintvar start */
        if (ok) {
            val_str = wmem_strdup_printf(wmem_packet_scope(), "first-byte-pos=%u", val);
            ti = proto_tree_add_string(tree, hf_hdr_content_range,
                    tvb, hdr_start, offset - hdr_start, val_str);
            subtree = proto_item_add_subtree(ti, ett_header);
            proto_tree_add_uint(subtree, hf_hdr_content_range_first_byte_pos,
                    tvb, off, len, val);
            off += len;
            /* Now check next value */
            val = tvb_get_guint8(tvb, off);
            if (val == 0x80) { /* Unknown length */
                proto_item_append_text(ti, "%s", "; entity-length=unknown");
            } else { /* Uintvar entity length */
                get_uintvar_integer (val, tvb, off, len, ok);
                if (ok) {
                    proto_item_append_text(ti, "; entity-length=%u", val);
                    proto_tree_add_uint(subtree,
                            hf_hdr_content_range_entity_length,
                            tvb, off, len, val);
                }
            }
        }

    wkh_4_End();
}


/* Range-value =
 *  Length
 *      0x80 Uintvar-integer [ Uintvar-integer ]
 *    | 0x81 Uintvar-integer
 */
static guint32
wkh_range(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0a_Declarations;
    guint32     off, val, len;
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_range, "Range");
        /* Invalid */
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        val = tvb_get_guint8(tvb, off);
        if (val == 0x80) { /* Byte-range */
            ti = proto_tree_add_string(tree, hf_hdr_range,
                    tvb, hdr_start, offset - hdr_start, "byte-range");
            subtree = proto_item_add_subtree(ti, ett_header);
            /* Get the First-byte-pos (Uintvar-integer) */
            get_uintvar_integer (val, tvb, off, len, ok);
            if (ok) {
                proto_item_append_text(ti, "; first-byte-pos=%u", val);
                proto_tree_add_uint(subtree, hf_hdr_range_first_byte_pos,
                        tvb, off, len, val);
                off += len;
                /* Get the optional Last-byte-pos (Uintvar-integer) */
                if (off < offset) {
                    get_uintvar_integer (val, tvb, off, len, ok);
                    if (ok) {
                        proto_item_append_text(ti, "; last-byte-pos=%u", val);
                        proto_tree_add_uint(subtree,
                                hf_hdr_range_last_byte_pos,
                                tvb, off, len, val);
                    }
                }
            }
        } else if (val == 0x81) { /* Suffix-byte-range */
            ti = proto_tree_add_string(tree, hf_hdr_range,
                    tvb, hdr_start, offset - hdr_start, "suffix-byte-range");
            subtree = proto_item_add_subtree(ti, ett_header);
            /* Get the Suffix-length (Uintvar-integer) */
            get_uintvar_integer (val, tvb, off, len, ok);
            if (ok) {
                proto_item_append_text(ti, "; suffix-length=%u", val);
                proto_tree_add_uint(subtree, hf_hdr_range_suffix_length,
                        tvb, off, len, val);
            }
        }

    wkh_4_End();
}


/* TE-value =
 *    0x81
 *  | Value-length (0x82--0x86 | Token-text) [ Q-token Q-value ]
 */
static guint32 wkh_te (proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;
    guint32 off, val, len;

    wkh_1_WellKnownValue(hf_hdr_name_value, ett_te_value, "TE-value");
        if (val_id == 0x81) {
            proto_tree_add_string(tree, hf_hdr_encoding_version,
                    tvb, hdr_start, offset - hdr_start, "trailers");
            ok = TRUE;
        }
    wkh_2_TextualValueInv;
        /* Invalid */
    wkh_3_ValueWithLength;
        off = val_start + val_len_len;
        val = tvb_get_guint8(tvb, off);
        if (val & 0x80) { /* Well-known-TE */
            val_str = try_val_to_str_ext((val & 0x7F), &vals_well_known_te_ext);
            if (val_str) {
                proto_tree_add_string(tree, hf_hdr_te,
                        tvb, hdr_start, off - hdr_start, val_str);
                off++;
                ok = TRUE;
            }
        } else { /* TE in Token-text format */
            get_token_text(val_str, tvb, off, len, ok);
            if (ok) {
                proto_tree_add_string(tree, hf_hdr_te,
                        tvb, hdr_start, off - hdr_start, val_str);
                off += len;
            }
        }
        if ((ok) && (off < offset)) { /* Q-token Q-value */
            /* TODO */
        }

    wkh_4_End();
}


/****************************************************************************
 *                     O p e n w a v e   h e a d e r s
 ****************************************************************************/


/* Dissect the Openwave header value (generic) */
static guint32
wkh_openwave_default(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
    wkh_0_Declarations;
    guint8 hdr_id = tvb_get_guint8 (tvb, hdr_start) & 0x7F;

    ok = TRUE; /* Bypass error checking as we don't parse the values! */

    wkh_1_WellKnownValue(hf_hdr_openwave_name_value, ett_openwave_default, "Default");
        proto_tree_add_uint_format(tree, hf_hdr_openwave_default_int, tvb, hdr_start, offset - hdr_start,
                val_id & 0x7F, "%s: (Undecoded well-known value 0x%02x)",
                val_to_str_ext (hdr_id, &vals_openwave_field_names_ext,
                    "<Unknown WSP header field 0x%02X>"), val_id & 0x7F);
    wkh_2_TextualValue;
        proto_tree_add_string_format(tree, hf_hdr_openwave_default_string, tvb, hdr_start, offset - hdr_start,
                "%s: %s",
                val_to_str_ext (hdr_id, &vals_openwave_field_names_ext,
                    "<Unknown WSP header field 0x%02X>"), val_str);
    wkh_3_ValueWithLength;
        proto_tree_add_uint_format(tree, hf_hdr_openwave_default_val_len, tvb, hdr_start, offset - hdr_start,
                val_len, "%s: (Undecoded value in general form with length indicator)",
                val_to_str_ext (hdr_id, &vals_openwave_field_names_ext,
                    "<Unknown WSP header field 0x%02X>"));

    wkh_4_End(); /* See wkh_default for explanation */
}


/* Textual Openwave headers */
wkh_text_header(openwave_x_up_proxy_operator_domain,
        "x-up-proxy-operator-domain")
wkh_text_header(openwave_x_up_proxy_home_page,
        "x-up-proxy-home-page")
wkh_text_header(openwave_x_up_proxy_uplink_version,
        "x-up-proxy-uplink-version")
wkh_text_header(openwave_x_up_proxy_ba_realm,
        "x-up-proxy-ba-realm")
wkh_text_header(openwave_x_up_proxy_request_uri,
        "x-up-proxy-request-uri")
wkh_text_header(openwave_x_up_proxy_bookmark,
        "x-up-proxy-bookmark")

/* Integer Openwave headers */
wkh_integer_value_header(openwave_x_up_proxy_push_seq,
        "x-up-proxy-push-seq")
wkh_integer_value_header(openwave_x_up_proxy_notify,
        "x-up-proxy-notify")
wkh_integer_value_header(openwave_x_up_proxy_net_ask,
        "x-up-proxy-net-ask")
wkh_integer_value_header(openwave_x_up_proxy_ba_enable,
        "x-up-proxy-ba-enable")
wkh_integer_value_header(openwave_x_up_proxy_redirect_enable,
        "x-up-proxy-redirect-enable")
wkh_integer_value_header(openwave_x_up_proxy_redirect_status,
        "x-up-proxy-redirect-status")
wkh_integer_value_header(openwave_x_up_proxy_linger,
        "x-up-proxy-linger")
wkh_integer_value_header(openwave_x_up_proxy_enable_trust,
        "x-up-proxy-enable-trust")
wkh_integer_value_header(openwave_x_up_proxy_trust,
        "x-up-proxy-trust")

wkh_integer_value_header(openwave_x_up_devcap_has_color,
        "x-up-devcap-has-color")
wkh_integer_value_header(openwave_x_up_devcap_num_softkeys,
        "x-up-devcap-num-softkeys")
wkh_integer_value_header(openwave_x_up_devcap_softkey_size,
        "x-up-devcap-softkey-size")
wkh_integer_value_header(openwave_x_up_devcap_screen_chars,
        "x-up-devcap-screen-chars")
wkh_integer_value_header(openwave_x_up_devcap_screen_pixels,
        "x-up-devcap-screen-pixels")
wkh_integer_value_header(openwave_x_up_devcap_em_size,
        "x-up-devcap-em-size")
wkh_integer_value_header(openwave_x_up_devcap_screen_depth,
        "x-up-devcap-screen-depth")
wkh_integer_value_header(openwave_x_up_devcap_immed_alert,
        "x-up-devcap-immed_alert")
wkh_integer_value_header(openwave_x_up_devcap_gui,
        "x-up-devcap-gui")

/* Openwave Time-Of-Day value header */
wkh_tod_value_header(openwave_x_up_proxy_tod,
        "x-up-proxy-tod")

/* Openwave accept_x_q header */
wkh_accept_x_q_header(openwave_x_up_proxy_trans_charset,
        "x-up-proxy-trans-charset",
        &mibenum_vals_character_sets_ext, "character set")

/* Openwave content type header */
static guint32
wkh_openwave_x_up_proxy_push_accept(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo)
{
    return wkh_content_type_header(tree, tvb, hdr_start, pinfo, hf_hdr_openwave_x_up_proxy_push_accept, "x-up-proxy-push-accept");
}


static gboolean parameter_text(proto_tree *tree, tvbuff_t *tvb, int *offset, proto_item *ti, int hf)
{
    gchar *val_str;
    gboolean ok;
    guint32 val_len;

    get_text_string(val_str, tvb, (*offset), val_len, ok);
    if (ok) {
        proto_tree_add_string(tree, hf, tvb, *offset, val_len, val_str);
        proto_item_append_text(ti, "; %s=%s", proto_registrar_get_name(hf), val_str);
        (*offset) += val_len;
    }

    return ok;
}

static gboolean parameter_text_value(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int *offset, proto_item *ti, int hf)
{
    gchar *val_str, *str;
    gboolean ok;
    guint32 val_len;
    proto_item* ti2;

    get_text_string(val_str, tvb, (*offset), val_len, ok);
    if (ok) {
        if (is_quoted_string(val_str[0])) {
            if (is_quoted_string(val_str[val_len-2])) {
                /* Trailing quote - issue a warning */
                ti2 = proto_tree_add_string(tree, hf,
                        tvb, *offset, val_len, val_str);
                expert_add_info(pinfo, ti2, &ei_wsp_trailing_quote);
            } else { /* OK (no trailing quote) */
                str = wmem_strdup_printf(wmem_packet_scope(), "%s\"", val_str);
                proto_tree_add_string(tree, hf,
                        tvb, *offset, val_len, str);
            }
        } else { /* Token-text | 0x00 */
            /* TODO - verify that we have either Token-text or 0x00 */
            proto_tree_add_string(tree, hf,
                    tvb, *offset, val_len, val_str);
        }
        proto_item_append_text(ti, "; %s=%s", proto_registrar_get_name(hf), val_str);
        (*offset) += val_len;
    }

    return ok;
}

static const value_string parameter_type_vals[] = {
    { 0x00,         "Q: Q-value" },
    { 0x01,         "Well-known-charset" },
    { 0x02,         "Level: Version-value" },
    { 0x03,         "Integer-value" },
    { 0x05,         "Name (Text-string)" },
    { 0x06,         "Filename (Text-string)" },
    { 0x07,         "Differences" },
    { 0x08,         "Padding" },
    { 0x09,         "Special Constrained-encoding" },
    { 0x0A,         "Start (Text-string)" },
    { 0x0B,         "Start-info (Text-string)" },
    { 0x0C,         "Comment (Text-string)" },
    { 0x0D,         "Domain (Text-string)" },
    { 0x0E,         "Max-Age" },
    { 0x0F,         "Path (Text-string)" },
    { 0x10,         "Secure" },
    { 0x11,         "SEC: Short-integer" },
    { 0x12,         "MAC: Text-value" },
    { 0x13,         "Creation-date" },
    { 0x14,         "Modification-date" },
    { 0x15,         "Read-date" },
    { 0x16,         "Size: Integer-value" },
    { 0x17,         "Name (Text-value)" },
    { 0x18,         "Filename (Text-value)" },
    { 0x19,         "Start (with multipart/related) (Text-value)" },
    { 0x1A,         "Start-info (with multipart/related) (Text-value)" },
    { 0x1B,         "Comment (Text-value)" },
    { 0x1C,         "Domain (Text-value)" },
    { 0x1D,         "Path (Text-value)" },

    { 0x00, NULL }
};

value_string_ext parameter_type_vals_ext = VALUE_STRING_EXT_INIT(parameter_type_vals);

/* Parameter = Untyped-parameter | Typed-parameter
 * Untyped-parameter = Token-text ( Integer-value | Text-value )
 * Typed-parameter =
 *      Integer-value (
 *          ( Integer-value | Date-value | Delta-seconds-value
 *            | Q-value | Version-value | Uri-value )
 *          | Text-value )
 *
 *
 * Returns: next offset
 *
 * TODO - Verify byte highlighting in case of invalid parameter values
 */
static int
parameter (proto_tree *tree, packet_info *pinfo, proto_item *ti, tvbuff_t *tvb, int start, int len)
{
    int offset = start;
    guint8 peek = tvb_get_guint8 (tvb,start);
    guint32 val = 0, type = 0, type_len, val_len;
    const gchar *str = NULL;
    const gchar *val_str = NULL;
    gboolean ok;
    proto_item* ti2;

    if (is_token_text (peek)) {
        /*
         * Untyped parameter
         */
        get_token_text (str,tvb,start,val_len,ok); /* Should always succeed */
        if (ok) { /* Found a textual parameter name: str */
            offset += val_len;
            get_text_value(val_str, tvb, offset, val_len, ok);
            if (ok) { /* Also found a textual parameter value: val_str */
                offset += val_len;
                if (is_quoted_string(val_str[0])) { /* Add trailing quote! */
                    if (is_quoted_string(val_str[val_len-2])) {
                        /* Trailing quote - issue a warning */
                        ti2 = proto_tree_add_string_format(tree, hf_wsp_parameter_untype_quote_text,
                                tvb, start, offset - start, val_str,
                                "%s: %s", str, val_str);
                        expert_add_info(pinfo, ti2, &ei_wsp_trailing_quote);
                        proto_item_append_text(ti, "; %s=%s", str, val_str);
                    } else { /* OK (no trailing quote) */
                        proto_tree_add_string_format(tree, hf_wsp_parameter_untype_quote_text,
                                tvb, start, offset - start, val_str,
                                "%s: %s\"", str, val_str);
                        proto_item_append_text(ti, "; %s=%s\"", str, val_str);
                    }
                } else { /* Token-text | 0x00 */
                    /* TODO - verify that it is either Token-text or 0x00
                     * and flag with warning if invalid */
                    proto_tree_add_string_format(tree, hf_wsp_parameter_untype_text,
                                tvb, start, offset - start, val_str,
                                "%s: %s", str, val_str);
                    proto_item_append_text(ti, "; %s=%s", str, val_str);
                }
            } else { /* Try integer value */
                get_integer_value (val,tvb,offset,val_len,ok);
                if (ok) { /* Also found a valid integer parameter value: val */
                    offset += val_len;
                    proto_tree_add_uint_format(tree, hf_wsp_parameter_untype_int, tvb, start, offset - start,
                            val, "%s: %u", str, val);
                    proto_item_append_text(ti, "; %s=%u", str, val);
                } else { /* Error: neither token-text not Integer-value */
                    proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, offset - start,
                            "Invalid untyped parameter definition");
                    offset = start + len; /* Skip to end of buffer */
                }
            }
        }
        return offset;
    }
    /*
     * Else: Typed parameter
     */
    get_integer_value (type,tvb,start,type_len,ok);
    if (!ok) {
        proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, offset - start,
                "Invalid typed parameter definition");
        return (start + len); /* Skip to end of buffer */
    }
    offset += type_len;
    /* Now offset points to the parameter value */
    proto_tree_add_uint(tree, hf_wsp_parameter_type, tvb, start, type_len, type);

    switch (type) {
        case 0x01:  /* WSP 1.1 encoding - Charset: Well-known-charset */
            get_integer_value(val, tvb, offset, val_len, ok);
            if (ok) {
                val_str = val_to_str_ext(val, &mibenum_vals_character_sets_ext,
                        "<Unknown character set Identifier %u>");
                proto_tree_add_string(tree, hf_parameter_charset,
                        tvb, offset, val_len, val_str);
                proto_item_append_text(ti, "; charset=%s", val_str);
                offset += val_len;
            } else {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                        "Invalid Charset parameter value: invalid Integer-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x03:  /* WSP 1.1 encoding - Type: Integer-value */
            get_integer_value (val,tvb,offset,val_len,ok);
            if (ok) {
                proto_tree_add_uint (tree, hf_wsp_parameter_int_type,
                        tvb, offset, val_len, val);
                proto_item_append_text(ti, "; Type=%u", val);
                offset += val_len;
            } else {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                        "Invalid Type parameter value: invalid Integer-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x05:  /* WSP 1.1 encoding - Name: Text-string */
            if (!parameter_text(tree, tvb, &offset, ti, hf_wsp_parameter_name))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Name (WSP 1.1 encoding) parameter value: invalid Text-string");
                offset = start + len; /* Skip to end of buffer */
            }
            break;
        case 0x17:  /* WSP 1.4 encoding - Name: Text-value */
            if (!parameter_text_value(tree, pinfo, tvb, &offset, ti, hf_wsp_parameter_name))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Name (WSP 1.4 encoding) parameter value: invalid Text-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x06:  /* WSP 1.1 encoding - Filename: Text-string */
            if (!parameter_text(tree, tvb, &offset, ti, hf_wsp_parameter_filename))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Filename (WSP 1.1 encoding) parameter value: invalid Text-string");
                offset = start + len; /* Skip to end of buffer */
            }
            break;
        case 0x18:  /* WSP 1.4 encoding - Filename: Text-value */
            if (!parameter_text_value(tree, pinfo, tvb, &offset, ti, hf_wsp_parameter_filename))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Filename (WSP 1.4 encoding) parameter value: invalid Text-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x09:  /* WSP 1.2 encoding - Type (special): Constrained-encoding */
            /* This is similar to the Content-Type header decoding,
             * but it is much simpler:
             * Constrained-encoding = Short-integer | Extension-media
             * Extension-media = *TEXT <Octet 0>
             */
            get_extension_media(val_str,tvb,offset,val_len,ok);
            if (ok) { /* Extension-media */
                proto_tree_add_string (tree, hf_wsp_parameter_upart_type,
                        tvb, offset, val_len, val_str);
                proto_item_append_text(ti, "; type=%s", val_str);
                offset += val_len;
            } else {
                get_short_integer(val,tvb,offset,val_len,ok);
                if (ok) {
                    proto_tree_add_string (tree, hf_wsp_parameter_upart_type,
                            tvb, offset, val_len, val_to_str_ext(val, &vals_content_types_ext,
                            "(Unknown content type identifier 0x%X)"));
                    offset += val_len;
                } /* Else: invalid parameter value */
            }
            if (!ok) {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                        "Invalid Type parameter value: invalid Constrained-encoding");
                offset = start + len; /* Skip the parameters */
            }
            break;

        case 0x0A:  /* WSP 1.2 encoding - Start: Text-string */
            if (!parameter_text(tree, tvb, &offset, ti, hf_wsp_parameter_start))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Start (WSP 1.2 encoding) parameter value: invalid Text-string");
                offset = start + len; /* Skip to end of buffer */
            }
            break;
        case 0x19:  /* WSP 1.4 encoding - Start (with multipart/related): Text-value */
            if (!parameter_text_value(tree, pinfo, tvb, &offset, ti, hf_wsp_parameter_start))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Start (with multipart/related) parameter value: invalid Text-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x0B:  /* WSP 1.2 encoding - Start-info: Text-string */
            if (!parameter_text(tree, tvb, &offset, ti, hf_wsp_parameter_start_info))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Start-info (WSP 1.2 encoding) parameter value: invalid Text-string");
                offset = start + len; /* Skip to end of buffer */
            }
            break;
        case 0x1A:  /* WSP 1.4 encoding - Start-info (with multipart/related): Text-value */
            if (!parameter_text_value(tree, pinfo, tvb, &offset, ti, hf_wsp_parameter_start_info))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Start-info (WSP 1.4 encoding) parameter value: invalid Text-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x0C:  /* WSP 1.3 encoding - Comment: Text-string */
            if (!parameter_text(tree, tvb, &offset, ti, hf_wsp_parameter_comment))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Comment (WSP 1.3 encoding) parameter value: invalid Text-string");
                offset = start + len; /* Skip to end of buffer */
            }
            break;
        case 0x1B:  /* WSP 1.4 encoding - Comment: Text-value */
            if (!parameter_text_value(tree, pinfo, tvb, &offset, ti, hf_wsp_parameter_comment))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Comment (WSP 1.4 encoding) parameter value: invalid Text-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x0D:  /* WSP 1.3 encoding - Domain: Text-string */
            if (!parameter_text(tree, tvb, &offset, ti, hf_wsp_parameter_domain))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Domain (WSP 1.3 encoding) parameter value: invalid Text-string");
                offset = start + len; /* Skip to end of buffer */
            }
            break;
        case 0x1C:  /* WSP 1.4 encoding - Domain: Text-value */
            if (!parameter_text_value(tree, pinfo, tvb, &offset, ti, hf_wsp_parameter_domain))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Domain (WSP 1.4 encoding) parameter value: invalid Text-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x0F:  /* WSP 1.3 encoding - Path: Text-string */
            if (!parameter_text(tree, tvb, &offset, ti, hf_wsp_parameter_path))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Path (WSP 1.3 encoding) parameter value: invalid Text-string");
                offset = start + len; /* Skip to end of buffer */
            }
            break;
        case 0x1D:  /* WSP 1.4 encoding - Path: Text-value */
            if (!parameter_text_value(tree, pinfo, tvb, &offset, ti, hf_wsp_parameter_path))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid Path (WSP 1.4 encoding) parameter value: invalid Text-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x11:  /* WSP 1.4 encoding - SEC: Short-integer (OCTET) */
            peek = tvb_get_guint8 (tvb, start+1);
            if (peek & 0x80) { /* Valid Short-integer */
                peek &= 0x7F;
                proto_tree_add_uint (tree, hf_wsp_parameter_sec,
                        tvb, offset, 1, peek);
                proto_item_append_text(ti, "; SEC=%s", val_to_str_ext_const(peek, &vals_wsp_parameter_sec_ext, "Undefined"));
                offset++;
            } else { /* Error */
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                        "Invalid SEC parameter value: invalid Short-integer-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x12:  /* WSP 1.4 encoding - MAC: Text-value */
            if (!parameter_text_value(tree, pinfo, tvb, &offset, ti, hf_wsp_parameter_mac))
            {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                                "Invalid MAC (WSP 1.4 encoding) parameter value: invalid Text-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x02:  /* WSP 1.1 encoding - Level: Version-value */
            get_version_value(val,str,tvb,offset,val_len,ok);
            if (ok) {
                proto_tree_add_string (tree, hf_wsp_parameter_level,
                        tvb, offset, val_len, str);
                proto_item_append_text(ti, "; level=%s", str);
                offset += val_len;
            } else {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                        "Invalid Level parameter value: invalid Version-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

        case 0x00:  /* WSP 1.1 encoding - Q: Q-value */
            offset = parameter_value_q(tree, pinfo, ti, tvb, offset);
            break;

        case 0x16:  /* WSP 1.4 encoding - Size: Integer-value */
            get_integer_value (val,tvb,offset,val_len,ok);
            if (ok) {
                proto_tree_add_uint (tree, hf_wsp_parameter_size,
                        tvb, offset, val_len, val);
                proto_item_append_text(ti, "; Size=%u", val);
                offset += val_len;
            } else {
                proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, len,
                        "Invalid Size parameter value: invalid Integer-value");
                offset = start + len; /* Skip to end of buffer */
            }
            break;

            /*
             * TODO
             */

        case 0x07:  /* WSP 1.1 encoding - Differences: Field-name */
            proto_tree_add_expert_format(tree, pinfo, &ei_wsp_undecoded_parameter, tvb, start, offset - start,
                    "Undecoded parameter Differences");
            offset = start + len; /* Skip the parameters */
            break;

        case 0x08:  /* WSP 1.1 encoding - Padding: Short-integer */
            proto_tree_add_expert_format(tree, pinfo, &ei_wsp_undecoded_parameter, tvb, start, offset - start,
                    "Undecoded parameter Padding");
            offset = start + len; /* Skip the parameters */
            break;

        case 0x0E:  /* WSP 1.3 encoding - Max-Age: Delta-seconds-value */
            proto_tree_add_expert_format(tree, pinfo, &ei_wsp_undecoded_parameter, tvb, start, offset - start,
                    "Undecoded parameter Max-Age");
            offset = start + len; /* Skip the parameters */
            break;

        case 0x10:  /* WSP 1.3 encoding - Secure: No-value */
            proto_tree_add_expert_format(tree, pinfo, &ei_wsp_undecoded_parameter, tvb, start, offset - start,
                    "Undecoded parameter Secure");
            offset = start + len; /* Skip the parameters */
            break;

        case 0x13:  /* WSP 1.4 encoding - Creation-date: Date-value */
            proto_tree_add_expert_format(tree, pinfo, &ei_wsp_undecoded_parameter, tvb, start, offset - start,
                    "Undecoded parameter Creation-Date");
            offset = start + len; /* Skip the parameters */
            break;

        case 0x14:  /* WSP 1.4 encoding - Modification-date: Date-value */
            proto_tree_add_expert_format(tree, pinfo, &ei_wsp_undecoded_parameter, tvb, start, offset - start,
                    "Undecoded parameter Modification-Date");
            offset = start + len; /* Skip the parameters */
            break;

        case 0x15:  /* WSP 1.4 encoding - Read-date: Date-value */
            proto_tree_add_expert_format(tree, pinfo, &ei_wsp_undecoded_parameter, tvb, start, offset - start,
                    "Undecoded parameter Read-Date");
            offset = start + len; /* Skip the parameters */
            break;

        default:
            proto_tree_add_expert_format(tree, pinfo, &ei_wsp_undecoded_parameter, tvb, start, offset - start,
                    "Undecoded parameter type 0x%02x", type);
            offset = start + len; /* Skip the parameters */
            break;
    }
    return offset;
}


/*
 * Dissects the Q-value parameter value.
 *
 * Returns: next offset
 */
static int
parameter_value_q (proto_tree *tree, packet_info *pinfo, proto_item *ti, tvbuff_t *tvb, int start)
{
    int      offset = start;
    guint32  val    = 0, val_len;
    gchar   *str    = NULL;
    guint8   ok;

    get_uintvar_integer (val, tvb, offset, val_len, ok);
    if (ok && (val < 1100)) {
        if (val <= 100) { /* Q-value in 0.01 steps */
            str = wmem_strdup_printf(wmem_packet_scope(), "0.%02u", val - 1);
        } else { /* Q-value in 0.001 steps */
            str = wmem_strdup_printf(wmem_packet_scope(), "0.%03u", val - 100);
        }
        proto_item_append_text(ti, "; q=%s", str);
        proto_tree_add_string (tree, hf_parameter_q,
                tvb, start, val_len, str);
        offset += val_len;
    } else {
        proto_tree_add_expert_format(tree, pinfo, &ei_wsp_invalid_parameter_value, tvb, start, offset,
                "Invalid Q parameter value: invalid Q-value");
        offset += val_len;
    }
    return offset;
}

static const int * address_length_flags[] = {
    &hf_address_flags_length_bearer_type_included,
    &hf_address_flags_length_port_number_included,
    &hf_address_flags_length_address_len,
    NULL
};

/* Code to actually dissect the packets */

/*
 * WSP redirect
 */

/* Dissect a WSP redirect PDU.
 * Looks up or builds conversations, so parts of the code must always run,
 * even if tree is NULL.
 */
static void
dissect_redirect(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, dissector_handle_t dissector_handle)
{
    proto_item        *ti;
    proto_tree        *addresses_tree = NULL;
    proto_tree        *addr_tree      = NULL;
    guint8             bearer_type;
    guint8             address_flags_len;
    int                address_len;
    guint16            port_num;
    guint32            address_ipv4;
    struct e_in6_addr  address_ipv6;
    address            redir_address;
    conversation_t    *conv;
    guint32            idx            = 0; /* Address index */
    guint32            address_record_len; /* Length of the entire address record */
    static const int * flags[] = {
        &hf_wsp_redirect_permanent,
        &hf_wsp_redirect_reuse_security_session,
        NULL
    };


    /*
     * Redirect flags.
     */
    proto_tree_add_bitmask(tree, tvb, offset, hf_wsp_redirect_flags, ett_redirect_flags, flags, ENC_NA);
    offset++;

    /*
     * Redirect addresses.
     */
    if (tree) {
        ti = proto_tree_add_item(tree, hf_redirect_addresses,
                tvb, 0, -1, ENC_NA);
        addresses_tree = proto_item_add_subtree(ti, ett_addresses);
    }

    while (tvb_reported_length_remaining (tvb, offset) > 0) {
        idx++;
        /*
         * Read a single address at a time.
         */
        address_flags_len = tvb_get_guint8 (tvb, offset);
        address_len = address_flags_len & ADDRESS_LEN;
        address_record_len = address_len
            + (address_flags_len & BEARER_TYPE_INCLUDED ? 1 : 0)
            + (address_flags_len & PORT_NUMBER_INCLUDED ? 2 : 0)
        ;

        ti = proto_tree_add_uint(addresses_tree, hf_address_entry,
                tvb, offset, 1 + address_record_len, idx);
        addr_tree = proto_item_add_subtree(ti, ett_address);

        proto_tree_add_bitmask(addr_tree, tvb, offset, hf_address_flags_length, ett_address_flags, address_length_flags, ENC_NA);
        offset++;
        if (address_flags_len & BEARER_TYPE_INCLUDED) {
            bearer_type = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint (addr_tree, hf_address_bearer_type,
                    tvb, offset, 1, bearer_type);
            offset++;
        } else {
            bearer_type = 0x00; /* XXX */
        }
        if (address_flags_len & PORT_NUMBER_INCLUDED) {
            port_num = tvb_get_ntohs (tvb, offset);
            proto_tree_add_uint (addr_tree, hf_address_port_num,
                    tvb, offset, 2, port_num);
            offset += 2;
        } else {
            /*
             * Redirecting to the same server port number as was
             * being used, i.e. the source port number of this
             * redirect.
             */
            port_num = pinfo->srcport;
        }
        if (!(address_flags_len & BEARER_TYPE_INCLUDED)) {
            /*
             * We don't have the bearer type in the message,
             * so we don't know the address type.
             * (It's the same bearer type as the original
             * connection.)
             */
            goto unknown_address_type;
        }

        /*
         * We know the bearer type, so we know the address type.
         */
        switch (bearer_type) {

        case BT_IPv4:
        case BT_IS_95_CSD:
        case BT_IS_95_PACKET_DATA:
        case BT_ANSI_136_CSD:
        case BT_ANSI_136_PACKET_DATA:
        case BT_GSM_CSD:
        case BT_GSM_GPRS:
        case BT_GSM_USSD_IPv4:
        case BT_AMPS_CDPD:
        case BT_PDC_CSD:
        case BT_PDC_PACKET_DATA:
        case BT_IDEN_CSD:
        case BT_IDEN_PACKET_DATA:
        case BT_PHS_CSD:
        case BT_TETRA_PACKET_DATA:
            /*
             * IPv4.
             */
            if (address_len != 4) {
                /*
                 * Say what?
                 */
                goto unknown_address_type;
            }
            address_ipv4 = tvb_get_ipv4(tvb, offset);
            if (tree) {
                proto_tree_add_ipv4 (addr_tree,
                    hf_address_ipv4_addr,
                    tvb, offset, 4, address_ipv4);
            }

            /*
             * Create a conversation so that the
             * redirected session will be dissected
             * as WAP.
             */
            redir_address.type = AT_IPv4;
            redir_address.len = 4;
            redir_address.data = (const guint8 *)&address_ipv4;
            /* Find a conversation based on redir_address and pinfo->dst */
            conv = find_conversation(pinfo->num, &redir_address, &pinfo->dst,
                PT_UDP, port_num, 0, NO_PORT_B);
            if (conv == NULL) { /* This conversation does not exist yet */
                conv = conversation_new(pinfo->num, &redir_address,
                    &pinfo->dst, PT_UDP, port_num, 0, NO_PORT2);
            }
            /* Apply WSP dissection to the conversation */
            conversation_set_dissector(conv, dissector_handle);
            break;

        case BT_IPv6:
            /*
             * IPv6.
             */
            if (address_len != 16) {
                /*
                 * Say what?
                 */
                goto unknown_address_type;
            }
            tvb_get_ipv6(tvb, offset, &address_ipv6);
            if (tree) {
                proto_tree_add_ipv6 (addr_tree,
                    hf_address_ipv6_addr,
                    tvb, offset, 16, &address_ipv6);
            }

            /*
             * Create a conversation so that the
             * redirected session will be dissected
             * as WAP.
             */
            redir_address.type = AT_IPv6;
            redir_address.len = 16;
            redir_address.data = (const guint8 *)&address_ipv6;
            /* Find a conversation based on redir_address and pinfo->dst */
            conv = find_conversation(pinfo->num, &redir_address, &pinfo->dst,
                PT_UDP, port_num, 0, NO_PORT_B);
            if (conv == NULL) { /* This conversation does not exist yet */
                conv = conversation_new(pinfo->num, &redir_address,
                    &pinfo->dst, PT_UDP, port_num, 0, NO_PORT2);
            }
            /* Apply WSP dissection to the conversation */
            conversation_set_dissector(conv, dissector_handle);
            break;

        unknown_address_type:
        default:
            if (address_len != 0) {
                if (tree) {
                    proto_tree_add_item (addr_tree, hf_address_addr,
                            tvb, offset, address_len, ENC_NA);
                }
            }
            break;
        }
        offset += address_len;
    } /* while */
}

/* Add addresses to the protocol tree.
 * This is a display-only function, so return if tree is NULL
 */
static void
add_addresses(proto_tree *tree, tvbuff_t *tvb, int hf)
{
    proto_item        *ti;
    proto_tree        *addresses_tree;
    proto_tree        *addr_tree;
    guint8             bearer_type;
    guint8             address_flags_len;
    int                address_len;
    guint32            tvb_len = tvb_reported_length(tvb);
    guint32            offset  = 0;
    guint32            idx     = 0; /* Address index */
    guint32            address_record_len; /* Length of the entire address record */

    /* Skip needless processing */
    if (! tree)
        return;
    if (offset >= tvb_len)
        return;

    /*
     * Addresses.
     */
    /* XXX: the field pointed to by hf has a type of FT_NONE */
    ti = proto_tree_add_item(tree, hf, tvb, 0, -1, ENC_NA);
    addresses_tree = proto_item_add_subtree(ti, ett_addresses);

    while (offset < tvb_len) {
        idx++;
        /*
         * Read a single address at a time.
         */
        address_flags_len = tvb_get_guint8 (tvb, offset);
        address_len = address_flags_len & ADDRESS_LEN;
        address_record_len = address_len
            + (address_flags_len & BEARER_TYPE_INCLUDED ? 1 : 0)
            + (address_flags_len & PORT_NUMBER_INCLUDED ? 2 : 0)
        ;

        ti = proto_tree_add_uint(addresses_tree, hf_address_entry,
                tvb, offset, 1 + address_record_len, idx);
        addr_tree = proto_item_add_subtree(ti, ett_address);

        proto_tree_add_bitmask(addr_tree, tvb, offset, hf_address_flags_length, ett_address_flags, address_length_flags, ENC_NA);
        offset++;
        if (address_flags_len & BEARER_TYPE_INCLUDED) {
            bearer_type = tvb_get_guint8 (tvb, offset);
            proto_tree_add_uint (addr_tree, hf_address_bearer_type,
                    tvb, offset, 1, bearer_type);
            offset++;
        } else {
            bearer_type = 0x00; /* XXX */
        }
        if (address_flags_len & PORT_NUMBER_INCLUDED) {
                proto_tree_add_uint (addr_tree, hf_address_port_num,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }
        if (!(address_flags_len & BEARER_TYPE_INCLUDED)) {
            /*
             * We don't have the bearer type in the message,
             * so we don't know the address type.
             * (It's the same bearer type as the original
             * connection.)
             */
            goto unknown_address_type;
        }

        /*
         * We know the bearer type, so we know the address type.
         */
        switch (bearer_type) {

        case BT_IPv4:
        case BT_IS_95_CSD:
        case BT_IS_95_PACKET_DATA:
        case BT_ANSI_136_CSD:
        case BT_ANSI_136_PACKET_DATA:
        case BT_GSM_CSD:
        case BT_GSM_GPRS:
        case BT_GSM_USSD_IPv4:
        case BT_AMPS_CDPD:
        case BT_PDC_CSD:
        case BT_PDC_PACKET_DATA:
        case BT_IDEN_CSD:
        case BT_IDEN_PACKET_DATA:
        case BT_PHS_CSD:
        case BT_TETRA_PACKET_DATA:
            /*
             * IPv4.
             */
            if (address_len != 4) {
                /*
                 * Say what?
                 */
                goto unknown_address_type;
            }
            proto_tree_add_item (addr_tree, hf_address_ipv4_addr,
                    tvb, offset, 4, ENC_NA);
            break;

        case BT_IPv6:
            /*
             * IPv6.
             */
            if (address_len != 16) {
                /*
                 * Say what?
                 */
                goto unknown_address_type;
            }
            proto_tree_add_item (addr_tree, hf_address_ipv6_addr,
                    tvb, offset, 16, ENC_NA);
            break;

        unknown_address_type:
        default:
            if (address_len != 0) {
                proto_tree_add_item (addr_tree, hf_address_addr,
                        tvb, offset, address_len, ENC_NA);
            }
            break;
        }
        offset += address_len;
    } /* while */
}

/* Define a pointer to function data type for the well-known header
 * lookup table below */
typedef guint32 (*hdr_parse_func_ptr) (proto_tree *, tvbuff_t *, guint32, packet_info *);

/* Lookup table for well-known header parsing functions */
static const hdr_parse_func_ptr WellKnownHeader[128] = {
    /* 0x00 */  wkh_accept,             /* 0x01 */  wkh_accept_charset,
    /* 0x02 */  wkh_accept_encoding,    /* 0x03 */  wkh_accept_language,
    /* 0x04 */  wkh_accept_ranges,      /* 0x05 */  wkh_age,
    /* 0x06 */  wkh_allow,              /* 0x07 */  wkh_authorization,
    /* 0x08 */  wkh_cache_control,      /* 0x09 */  wkh_connection,
    /* 0x0A */  wkh_content_base,       /* 0x0B */  wkh_content_encoding,
    /* 0x0C */  wkh_content_language,   /* 0x0D */  wkh_content_length,
    /* 0x0E */  wkh_content_location,   /* 0x0F */  wkh_content_md5,
    /* 0x10 */  wkh_content_range,      /* 0x11 */  wkh_content_type,
    /* 0x12 */  wkh_date,               /* 0x13 */  wkh_etag,
    /* 0x14 */  wkh_expires,            /* 0x15 */  wkh_from,
    /* 0x16 */  wkh_host,               /* 0x17 */  wkh_if_modified_since,
    /* 0x18 */  wkh_if_match,           /* 0x19 */  wkh_if_none_match,
    /* 0x1A */  wkh_if_range,           /* 0x1B */  wkh_if_unmodified_since,
    /* 0x1C */  wkh_location,           /* 0x1D */  wkh_last_modified,
    /* 0x1E */  wkh_max_forwards,       /* 0x1F */  wkh_pragma,
    /* 0x20 */  wkh_proxy_authenticate, /* 0x21 */  wkh_proxy_authorization,
    /* 0x22 */  wkh_public,             /* 0x23 */  wkh_range,
    /* 0x24 */  wkh_referer,            /* 0x25 */  wkh_default,
    /* 0x26 */  wkh_server,             /* 0x27 */  wkh_transfer_encoding,
    /* 0x28 */  wkh_upgrade,            /* 0x29 */  wkh_user_agent,
    /* 0x2A */  wkh_vary,               /* 0x2B */  wkh_via,
    /* 0x2C */  wkh_warning,            /* 0x2D */  wkh_www_authenticate,
    /* 0x2E */  wkh_content_disposition,/* 0x2F */  wkh_x_wap_application_id,
    /* 0x30 */  wkh_content_uri,        /* 0x31 */  wkh_initiator_uri,
    /* 0x32 */  wkh_accept_application, /* 0x33 */  wkh_bearer_indication,
    /* 0x34 */  wkh_push_flag,          /* 0x35 */  wkh_profile,
    /* 0x36 */  wkh_profile_diff_wbxml, /* 0x37 */  wkh_profile_warning,
    /* 0x38 */  wkh_default,            /* 0x39 */  wkh_te,
    /* 0x3A */  wkh_trailer,            /* 0x3B */  wkh_accept_charset,
    /* 0x3C */  wkh_accept_encoding,    /* 0x3D */  wkh_cache_control,
    /* 0x3E */  wkh_content_range,      /* 0x3F */  wkh_x_wap_tod,
    /* 0x40 */  wkh_content_id,         /* 0x41 */  wkh_default,
    /* 0x42 */  wkh_default,            /* 0x43 */  wkh_encoding_version,
    /* 0x44 */  wkh_profile_warning,    /* 0x45 */  wkh_content_disposition,
    /* 0x46 */  wkh_x_wap_security,     /* 0x47 */  wkh_cache_control,
    /*******************************************************
     *** The following headers are not (yet) registered. ***
     *******************************************************/
    /* 0x48 */  wkh_default,            /* 0x49 */  wkh_default,
    /* 0x4A */  wkh_default,            /* 0x4B */  wkh_default,
    /* 0x4C */  wkh_default,            /* 0x4D */  wkh_default,
    /* 0x4E */  wkh_default,            /* 0x4F */  wkh_default,
    /* 0x50 */  wkh_default,            /* 0x51 */  wkh_default,
    /* 0x52 */  wkh_default,            /* 0x53 */  wkh_default,
    /* 0x54 */  wkh_default,            /* 0x55 */  wkh_default,
    /* 0x56 */  wkh_default,            /* 0x57 */  wkh_default,
    /* 0x58 */  wkh_default,            /* 0x59 */  wkh_default,
    /* 0x5A */  wkh_default,            /* 0x5B */  wkh_default,
    /* 0x5C */  wkh_default,            /* 0x5D */  wkh_default,
    /* 0x5E */  wkh_default,            /* 0x5F */  wkh_default,
    /* 0x60 */  wkh_default,            /* 0x61 */  wkh_default,
    /* 0x62 */  wkh_default,            /* 0x63 */  wkh_default,
    /* 0x64 */  wkh_default,            /* 0x65 */  wkh_default,
    /* 0x66 */  wkh_default,            /* 0x67 */  wkh_default,
    /* 0x68 */  wkh_default,            /* 0x69 */  wkh_default,
    /* 0x6A */  wkh_default,            /* 0x6B */  wkh_default,
    /* 0x6C */  wkh_default,            /* 0x6D */  wkh_default,
    /* 0x6E */  wkh_default,            /* 0x6F */  wkh_default,
    /* 0x70 */  wkh_default,            /* 0x71 */  wkh_default,
    /* 0x72 */  wkh_default,            /* 0x73 */  wkh_default,
    /* 0x74 */  wkh_default,            /* 0x75 */  wkh_default,
    /* 0x76 */  wkh_default,            /* 0x77 */  wkh_default,
    /* 0x78 */  wkh_default,            /* 0x79 */  wkh_default,
    /* 0x7A */  wkh_default,            /* 0x7B */  wkh_default,
    /* 0x7C */  wkh_default,            /* 0x7D */  wkh_default,
    /* 0x7E */  wkh_default,            /* 0x7F */  wkh_default,
};

/* Lookup table for well-known header parsing functions */
static const hdr_parse_func_ptr WellKnownOpenwaveHeader[128] = {
    /* 0x00 */  wkh_openwave_default,
    /* 0x01 */  wkh_openwave_x_up_proxy_push_accept,
    /* 0x02 */  wkh_openwave_x_up_proxy_push_seq,
    /* 0x03 */  wkh_openwave_x_up_proxy_notify,
    /* 0x04 */  wkh_openwave_x_up_proxy_operator_domain,
    /* 0x05 */  wkh_openwave_x_up_proxy_home_page,
    /* 0x06 */  wkh_openwave_x_up_devcap_has_color,
    /* 0x07 */  wkh_openwave_x_up_devcap_num_softkeys,
    /* 0x08 */  wkh_openwave_x_up_devcap_softkey_size,
    /* 0x09 */  wkh_openwave_x_up_devcap_screen_chars,
    /* 0x0A */  wkh_openwave_x_up_devcap_screen_pixels,
    /* 0x0B */  wkh_openwave_x_up_devcap_em_size,
    /* 0x0C */  wkh_openwave_x_up_devcap_screen_depth,
    /* 0x0D */  wkh_openwave_x_up_devcap_immed_alert,
    /* 0x0E */  wkh_openwave_x_up_proxy_net_ask,
    /* 0x0F */  wkh_openwave_x_up_proxy_uplink_version,
    /* 0x10 */  wkh_openwave_x_up_proxy_tod,
    /* 0x11 */  wkh_openwave_x_up_proxy_ba_enable,
    /* 0x12 */  wkh_openwave_x_up_proxy_ba_realm,
    /* 0x13 */  wkh_openwave_x_up_proxy_redirect_enable,
    /* 0x14 */  wkh_openwave_x_up_proxy_request_uri,
    /* 0x15 */  wkh_openwave_x_up_proxy_redirect_status,
    /* 0x16 */  wkh_openwave_x_up_proxy_trans_charset,
    /* 0x17 */  wkh_openwave_x_up_proxy_linger,
    /* 0x18 */  wkh_openwave_default,
    /* 0x19 */  wkh_openwave_x_up_proxy_enable_trust,
    /* 0x1A */  wkh_openwave_x_up_proxy_trust,
    /* 0x1B */  wkh_openwave_default,
    /* 0x1C */  wkh_openwave_default,
    /* 0x1D */  wkh_openwave_default,
    /* 0x1E */  wkh_openwave_default,
    /* 0x1F */  wkh_openwave_default,
    /* 0x20 */  wkh_openwave_x_up_proxy_trust,
    /* 0x21 */  wkh_openwave_x_up_proxy_bookmark,
    /* 0x22 */  wkh_openwave_x_up_devcap_gui,
    /*******************************************************
     *** The following headers are not (yet) registered. ***
     *******************************************************/
    /* 0x23 */  wkh_openwave_default,
    /* 0x24 */  wkh_openwave_default,       /* 0x25 */  wkh_openwave_default,
    /* 0x26 */  wkh_openwave_default,       /* 0x27 */  wkh_openwave_default,
    /* 0x28 */  wkh_openwave_default,       /* 0x29 */  wkh_openwave_default,
    /* 0x2A */  wkh_openwave_default,       /* 0x2B */  wkh_openwave_default,
    /* 0x2C */  wkh_openwave_default,       /* 0x2D */  wkh_openwave_default,
    /* 0x2E */  wkh_openwave_default,       /* 0x2F */  wkh_openwave_default,
    /* 0x30 */  wkh_openwave_default,       /* 0x31 */  wkh_openwave_default,
    /* 0x32 */  wkh_openwave_default,       /* 0x33 */  wkh_openwave_default,
    /* 0x34 */  wkh_openwave_default,       /* 0x35 */  wkh_openwave_default,
    /* 0x36 */  wkh_openwave_default,       /* 0x37 */  wkh_openwave_default,
    /* 0x38 */  wkh_openwave_default,       /* 0x39 */  wkh_openwave_default,
    /* 0x3A */  wkh_openwave_default,       /* 0x3B */  wkh_openwave_default,
    /* 0x3C */  wkh_openwave_default,       /* 0x3D */  wkh_openwave_default,
    /* 0x3E */  wkh_openwave_default,       /* 0x3F */  wkh_openwave_default,
    /* 0x40 */  wkh_openwave_default,       /* 0x41 */  wkh_openwave_default,
    /* 0x42 */  wkh_openwave_default,       /* 0x43 */  wkh_openwave_default,
    /* 0x44 */  wkh_openwave_default,       /* 0x45 */  wkh_openwave_default,
    /* 0x46 */  wkh_openwave_default,       /* 0x47 */  wkh_openwave_default,
    /* 0x48 */  wkh_openwave_default,       /* 0x49 */  wkh_openwave_default,
    /* 0x4A */  wkh_openwave_default,       /* 0x4B */  wkh_openwave_default,
    /* 0x4C */  wkh_openwave_default,       /* 0x4D */  wkh_openwave_default,
    /* 0x4E */  wkh_openwave_default,       /* 0x4F */  wkh_openwave_default,
    /* 0x50 */  wkh_openwave_default,       /* 0x51 */  wkh_openwave_default,
    /* 0x52 */  wkh_openwave_default,       /* 0x53 */  wkh_openwave_default,
    /* 0x54 */  wkh_openwave_default,       /* 0x55 */  wkh_openwave_default,
    /* 0x56 */  wkh_openwave_default,       /* 0x57 */  wkh_openwave_default,
    /* 0x58 */  wkh_openwave_default,       /* 0x59 */  wkh_openwave_default,
    /* 0x5A */  wkh_openwave_default,       /* 0x5B */  wkh_openwave_default,
    /* 0x5C */  wkh_openwave_default,       /* 0x5D */  wkh_openwave_default,
    /* 0x5E */  wkh_openwave_default,       /* 0x5F */  wkh_openwave_default,
    /* 0x60 */  wkh_openwave_default,       /* 0x61 */  wkh_openwave_default,
    /* 0x62 */  wkh_openwave_default,       /* 0x63 */  wkh_openwave_default,
    /* 0x64 */  wkh_openwave_default,       /* 0x65 */  wkh_openwave_default,
    /* 0x66 */  wkh_openwave_default,       /* 0x67 */  wkh_openwave_default,
    /* 0x68 */  wkh_openwave_default,       /* 0x69 */  wkh_openwave_default,
    /* 0x6A */  wkh_openwave_default,       /* 0x6B */  wkh_openwave_default,
    /* 0x6C */  wkh_openwave_default,       /* 0x6D */  wkh_openwave_default,
    /* 0x6E */  wkh_openwave_default,       /* 0x6F */  wkh_openwave_default,
    /* 0x70 */  wkh_openwave_default,       /* 0x71 */  wkh_openwave_default,
    /* 0x72 */  wkh_openwave_default,       /* 0x73 */  wkh_openwave_default,
    /* 0x74 */  wkh_openwave_default,       /* 0x75 */  wkh_openwave_default,
    /* 0x76 */  wkh_openwave_default,       /* 0x77 */  wkh_openwave_default,
    /* 0x78 */  wkh_openwave_default,       /* 0x79 */  wkh_openwave_default,
    /* 0x7A */  wkh_openwave_default,       /* 0x7B */  wkh_openwave_default,
    /* 0x7C */  wkh_openwave_default,       /* 0x7D */  wkh_openwave_default,
    /* 0x7E */  wkh_openwave_default,       /* 0x7F */  wkh_openwave_default
};



/* WSP header format
 *   1st byte: 0x00        : <Not allowed>
 *   1st byte: 0x01 -- 0x1F: <Shorthand Header Code Page switch>
 *   1st byte: 0x20 -- 0x7E: <Textual header (C string)>
 *       Followed with: <Textual header value (C string)>
 *   1st byte: 0x7F        : <Header Code Page switch>
 *       Followed with: 2nd byte: <Header Code Page>
 *   1st byte: 0x80 -- 0xFF: <Binary header (7-bit encoded ID)>
 *       Followed with:
 *         2nd byte: 0x00 -- 0x1E: <Value Length (bytes)>
 *             Followed with: <Len> bytes of data
 *         2nd byte: 0x1F        : <Value Length is a guintvar>
 *             Followed with: <guintvar Len>
 *             Followed with: <Len> bytes of data
 *         2nd byte: 0x20 -- 0x7F: <Textual header value (C string)>
 *         2nd byte: 0x80 -- 0xFF: <Binary value (7-bit encoded ID)>
 */
static void
add_headers (proto_tree *tree, tvbuff_t *tvb, int hf, packet_info *pinfo)
{
    guint8      hdr_id, val_id, codepage = 1;
    gint32      tvb_len                  = tvb_reported_length(tvb);
    gint32      offset                   = 0;
    gint32      save_offset;
    gint32      hdr_len, hdr_start;
    gint32      val_len, val_start;
    gchar      *hdr_str, *val_str;
    proto_tree *wsp_headers;
    proto_item *ti, *hidden_item;
    guint8      ok;
    guint32     val                      = 0;

    if (offset >= tvb_len)
        return; /* No headers! */

    /* XXX: the field pointed to by hf has a type of FT_NONE */
    ti = proto_tree_add_item(tree, hf,
                             tvb, offset, tvb_len, ENC_NA);
    wsp_headers = proto_item_add_subtree(ti, ett_headers);

    while (offset < tvb_len) {
        hdr_start = offset;
        hdr_id = tvb_get_guint8(tvb, offset);
        if (hdr_id & 0x80) { /* Well-known header */
            hdr_len = 1;
            /* Call header value dissector for given header */
            if (codepage == 1) { /* Default header code page */
                save_offset = offset;
                offset = WellKnownHeader[hdr_id & 0x7F](wsp_headers, tvb,
                                                        hdr_start, pinfo);
                /* Make sure we're progressing forward */
                if (save_offset <= offset) {
                    expert_add_info(pinfo, ti, &ei_wsp_header_invalid);
                    break;
                }
            } else { /* Openwave header code page */
                /* Here I'm delibarately assuming that Openwave is the only
                 * company that defines a WSP header code page. */
                save_offset = offset;
                offset = WellKnownOpenwaveHeader[hdr_id & 0x7F](wsp_headers,
                                                                tvb, hdr_start, pinfo);
                /* Make sure we're progressing forward */
                if (save_offset <= offset) {
                    expert_add_info(pinfo, ti, &ei_wsp_header_invalid);
                    break;
                }
            }
        } else if (hdr_id == 0x7F) { /* HCP shift sequence */
            codepage = tvb_get_guint8(tvb, offset+1);
            proto_tree_add_uint(wsp_headers, hf_wsp_header_shift_code,
                                tvb, offset, 2, codepage);
            offset += 2;
        } else if (hdr_id >= 0x20) { /* Textual header */
            /* Header name MUST be NUL-ended string ==> tvb_get_stringz_enc() */
            hdr_str = (gchar *)tvb_get_stringz_enc(wmem_packet_scope(), tvb, hdr_start, (gint *)&hdr_len, ENC_ASCII);
            val_start = hdr_start + hdr_len;
            val_id = tvb_get_guint8(tvb, val_start);
            /* Call header value dissector for given header */
            if (val_id >= 0x20 && val_id <=0x7E) { /* OK! */
                val_str = (gchar *)tvb_get_stringz_enc(wmem_packet_scope(), tvb, val_start, (gint *)&val_len, ENC_ASCII);
                offset = val_start + val_len;
                proto_tree_add_string_format(wsp_headers, hf_wsp_header_text_value, tvb, hdr_start, offset-hdr_start,
                                    val_str, "%s: %s", hdr_str, val_str);
            } else {
                /* Old-style X-WAP-TOD uses a non-textual value
                 * after a textual header. */
                if (g_ascii_strcasecmp(hdr_str, "x-wap.tod") == 0) {
                    get_delta_seconds_value(val, tvb, val_start, val_len, ok);
                    if (ok) {
                        nstime_t t;
                        t.secs = (time_t)val;
                        t.nsecs = 0;
                        if (val == 0) {
                            ti = proto_tree_add_time_format_value(wsp_headers, hf_hdr_x_wap_tod,
                                                        tvb, hdr_start, hdr_len + val_len, &t,
                                                        "Requesting Time Of Day");
                        } else {
                            ti = proto_tree_add_time(wsp_headers, hf_hdr_x_wap_tod,
                                                        tvb, hdr_start, hdr_len + val_len, &t);
                        }
                        expert_add_info(pinfo, ti, &ei_hdr_x_wap_tod);
                    } else {
                        /* I prefer using X-Wap-Tod to the real hdr_str */
                        proto_tree_add_expert_format(wsp_headers, pinfo, &ei_wsp_text_field_invalid,
                                               tvb, hdr_start, hdr_len + val_len,
                                               "Invalid value for the 'X-Wap-Tod' header");

                    }
                } else {
                    proto_tree_add_expert_format(wsp_headers, pinfo, &ei_wsp_text_field_invalid, tvb, hdr_start, hdr_len,
                                         "Invalid value for the textual '%s' header (should be a textual value)",
                                         hdr_str);
                }
                offset = tvb_len;
            }
            hidden_item = proto_tree_add_string(wsp_headers, hf_hdr_name_string,
                                                tvb, hdr_start, offset - hdr_start, hdr_str);
            PROTO_ITEM_SET_HIDDEN(hidden_item);
        } else if (hdr_id > 0) { /* Shorthand HCP switch */
            codepage = hdr_id;
            proto_tree_add_uint (wsp_headers, hf_wsp_header_shift_code,
                                 tvb, offset, 1, codepage);
            offset++;
        } else {
            proto_tree_add_expert_format (wsp_headers, pinfo, &ei_wsp_text_field_invalid, tvb, hdr_start, 1,
                                 "Invalid zero-length textual header");

            offset = tvb_len;
        }
    }
}

static const value_string vals_sir_protocol_options[] = {
    { 0, "OTA-HTTP, no CPITag present" },
    { 1, "OTA-HTTP, CPITag present" },
    /* 2--255 are reserved */
    /* 256--16383 are available for private WINA registration */

    { 0x00, NULL }
};


/* Dissect a Session Initiation Request.
 *
 * Arguably this should be a separate dissector, but SIR does not make sense
 * outside of WSP anyway.
 */
static int
dissect_sir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint8      version;
    guint32     val_len;
    guint32     val_len_save;
    guint32     len;
    guint32     offset = 0;
    guint32     i;
    tvbuff_t   *tmp_tvb;
    proto_tree *subtree;
    proto_item *ti;

    /* Append status code to INFO column */
    col_append_str(pinfo->cinfo, COL_INFO, ": WAP Session Initiation Request");

    ti = proto_tree_add_item(tree, hf_sir_section,
            tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_sir);

    /* Version */
    version = tvb_get_guint8(tvb, 0);
    proto_tree_add_uint(subtree, hf_sir_version,
            tvb, 0, 1, version);

    /* Length of Application-Id headers list */
    val_len = tvb_get_guintvar(tvb, 1, &len, pinfo, &ei_wsp_oversized_uintvar);
    proto_tree_add_uint(subtree, hf_sir_app_id_list_len,
            tvb, 1, len, val_len);
    offset = 1 + len;
    /* Application-Id headers */
    tmp_tvb = tvb_new_subset_length(tvb, offset, val_len);
    add_headers (subtree, tmp_tvb, hf_sir_app_id_list, pinfo);
    offset += val_len;

    /* Length of WSP contact points list */
    val_len = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
    proto_tree_add_uint(subtree, hf_sir_wsp_contact_points_len,
            tvb, offset, len, val_len);
    offset += len;
    /* WSP contact point list */
    tmp_tvb = tvb_new_subset_length (tvb, offset, val_len);
    add_addresses(subtree, tmp_tvb, hf_sir_wsp_contact_points);

    /* End of version 0 SIR content */
    if (version == 0)
        return offset;

    offset += val_len;

    /* Length of non-WSP contact points list */
    val_len = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
    proto_tree_add_uint(subtree, hf_sir_contact_points_len,
            tvb, offset, len, val_len);
    offset += len;
    /* Non-WSP contact point list */
    tmp_tvb = tvb_new_subset_length(tvb, offset, val_len);
    add_addresses(subtree, tmp_tvb, hf_sir_contact_points);

    offset += val_len;

    /* Number of entries in the Protocol Options list */
    val_len = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
    proto_tree_add_uint(subtree, hf_sir_protocol_options_len,
            tvb, offset, len, val_len);
    offset += len;
    /* Protocol Options list.
     * Each protocol option is encoded as a guintvar */

    val_len_save = val_len;
    for (i = 0; i < val_len_save; i++) {
        val_len = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
        proto_tree_add_uint(subtree, hf_sir_protocol_options,
                tvb, offset, len, val_len);
        offset += len;
    }

    /* Length of ProvURL */
    val_len = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
    proto_tree_add_uint(subtree, hf_sir_prov_url_len,
            tvb, offset, len, val_len);
    offset += len;
    /* ProvURL */
    proto_tree_add_item (tree, hf_sir_prov_url,
            tvb, offset, val_len, ENC_ASCII|ENC_NA);
    offset += val_len;

    /* Number of entries in the CPITag list */
    val_len = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
    proto_tree_add_uint(subtree, hf_sir_cpi_tag_len,
            tvb, offset, len, val_len);
    offset += len;

    /* CPITag list.
     * Each CPITag is encoded as 4 octets of opaque data.
     * In OTA-HTTP, it is conveyed in the X-Wap-CPITag header
     * but with a Base64 encoding of the 4 bytes. */
    for (i = 0; i < val_len; i++) {
        proto_tree_add_item(subtree, hf_sir_cpi_tag,
                            tvb, offset, 4, ENC_NA);
        offset += 4;
    }
    return tvb_captured_length(tvb);
}

static void
dissect_wsp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    dissector_handle_t dissector_handle, gboolean is_connectionless)
{
    int offset = 0;

    guint8      pdut;
    guint       count            = 0;
    guint       value            = 0;
    guint       uriLength        = 0;
    guint       uriStart         = 0;
    guint       capabilityLength = 0;
    guint       headersLength    = 0;
    guint       headerLength     = 0;
    guint       headerStart      = 0;
    guint       nextOffset       = 0;
    guint       contentTypeStart = 0;
    guint       contentType      = 0;
    const char *contentTypeStr;
    tvbuff_t   *tmp_tvb;
    int         found_match;
    heur_dtbl_entry_t *hdtbl_entry;
    proto_item* ti;

/* Set up structures we will need to add the protocol subtree and manage it */
    proto_item *proto_ti = NULL; /* for the proto entry */
    proto_tree *wsp_tree = NULL;

    wsp_info_value_t *stat_info;
    stat_info = (wsp_info_value_t *)wmem_alloc(wmem_packet_scope(), sizeof(wsp_info_value_t));
    stat_info->status_code = 0;

/* This field shows up as the "Info" column in the display; you should make
   it, if possible, summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. */

    /* Connection-less mode has a TID first */
    if (is_connectionless)
    {
        offset++; /* Skip the 1-byte Transaction ID */
    };

    /* Find the PDU type */
    pdut = tvb_get_guint8 (tvb, offset);

    /* Develop the string to put in the Info column */
    col_append_fstr(pinfo->cinfo, COL_INFO, "WSP %s (0x%02x)",
            val_to_str_ext (pdut, &wsp_vals_pdu_type_ext, "Unknown PDU type (0x%02x)"),
            pdut);

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items. */
    if (tree) {
        proto_ti = proto_tree_add_item(tree, proto_wsp,
                tvb, 0, -1, ENC_NA);
        wsp_tree = proto_item_add_subtree(proto_ti, ett_wsp);
        proto_item_append_text(proto_ti, ", Method: %s (0x%02x)",
                val_to_str_ext (pdut, &wsp_vals_pdu_type_ext, "Unknown (0x%02x)"),
                pdut);

        /* Add common items: only TID and PDU Type */

        /* If this is connectionless, then the TID Field is always first */
        if (is_connectionless)
        {
            proto_tree_add_item (wsp_tree, hf_wsp_header_tid,
                    tvb, 0, 1, ENC_LITTLE_ENDIAN);
        }
        proto_tree_add_item( wsp_tree, hf_wsp_header_pdu_type,
                tvb, offset, 1, ENC_LITTLE_ENDIAN);
    }
    offset++;

    /* Map extended methods to the main method now the Column info has been
     * written; this way we can dissect the extended method PDUs. */
    if ((pdut >= 0x50) && (pdut <= 0x5F)) /* Extended GET --> GET */
        pdut = WSP_PDU_GET;
    else if ((pdut >= 0x70) && (pdut <= 0x7F)) /* Extended POST --> POST */
        pdut = WSP_PDU_POST;

    switch (pdut)
    {
        case WSP_PDU_CONNECT:
        case WSP_PDU_CONNECTREPLY:
        case WSP_PDU_RESUME:
            if (pdut == WSP_PDU_CONNECT)
            {
                proto_tree_add_item (wsp_tree, hf_wsp_version_major,
                        tvb, offset, 1, ENC_LITTLE_ENDIAN);
                proto_tree_add_item (wsp_tree, hf_wsp_version_minor,
                        tvb, offset, 1, ENC_LITTLE_ENDIAN);
                {
                    guint8 ver = tvb_get_guint8(tvb, offset);
                    proto_item_append_text(proto_ti, ", Version: %u.%u",
                            ver >> 4, ver & 0x0F);
                }
                offset++;
            } else {
                count = 0;  /* Initialise count */
                value = tvb_get_guintvar (tvb, offset, &count, pinfo, &ei_wsp_oversized_uintvar);
                proto_tree_add_uint (wsp_tree,
                        hf_wsp_server_session_id,
                        tvb, offset, count, value);
                proto_item_append_text(proto_ti, ", Session ID: %u", value);
                offset += count;
            }
            count = 0;  /* Initialise count */
            capabilityLength = tvb_get_guintvar (tvb, offset, &count, pinfo, &ei_wsp_oversized_uintvar);
            ti = proto_tree_add_uint (wsp_tree, hf_capabilities_length,
                    tvb, offset, count, capabilityLength);
            offset += count;
            if (capabilityLength > tvb_reported_length(tvb))
            {
                expert_add_info(pinfo, ti, &ei_wsp_capability_length_invalid);
                break;
            }

            if (pdut != WSP_PDU_RESUME)
            {
                count = 0;  /* Initialise count */
                headerLength = tvb_get_guintvar (tvb, offset, &count, pinfo, &ei_wsp_oversized_uintvar);
                proto_tree_add_uint (wsp_tree, hf_wsp_header_length,
                        tvb, offset, count, headerLength);
                offset += count;

            } else {
                    /* Resume computes the headerlength
                        * by remaining bytes */
                headerStart = offset + capabilityLength;
                headerLength = tvb_reported_length_remaining (tvb,
                        headerStart);
            }
            if (capabilityLength > 0)
            {
                tmp_tvb = tvb_new_subset_length (tvb, offset,
                        capabilityLength);
                add_capabilities (wsp_tree, pinfo, tmp_tvb, pdut);
                offset += capabilityLength;
            }

            if (headerLength > 0)
            {
                tmp_tvb = tvb_new_subset_length (tvb, offset,
                        headerLength);
                add_headers (wsp_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
            }

            break;

        case WSP_PDU_REDIRECT:
            dissect_redirect(tvb, offset, pinfo, wsp_tree, dissector_handle);
            break;

        case WSP_PDU_DISCONNECT:
        case WSP_PDU_SUSPEND:
            if (tree) {
                count = 0;  /* Initialise count */
                value = tvb_get_guintvar (tvb, offset, &count, pinfo, &ei_wsp_oversized_uintvar);
                proto_tree_add_uint (wsp_tree,
                        hf_wsp_server_session_id,
                        tvb, offset, count, value);
                proto_item_append_text(proto_ti, ", Session ID: %u", value);
            }
            break;

        case WSP_PDU_GET:
        case WSP_PDU_OPTIONS:
        case WSP_PDU_HEAD:
        case WSP_PDU_DELETE:
        case WSP_PDU_TRACE:
            count = 0;  /* Initialise count */
            /* Length of URI and size of URILen field */
            value = tvb_get_guintvar (tvb, offset, &count, pinfo, &ei_wsp_oversized_uintvar);
            nextOffset = offset + count;
            add_uri (wsp_tree, pinfo, tvb, offset, nextOffset, proto_ti);
            if (tree) {
                offset += value + count; /* VERIFY */
                tmp_tvb = tvb_new_subset_remaining (tvb, offset);
                add_headers (wsp_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
            }
            break;

        case WSP_PDU_POST:
        case WSP_PDU_PUT:
            uriStart = offset;
            count = 0;  /* Initialise count */
            uriLength = tvb_get_guintvar (tvb, offset, &count, pinfo, &ei_wsp_oversized_uintvar);
            headerStart = uriStart+count;
            count = 0;  /* Initialise count */
            headersLength = tvb_get_guintvar (tvb, headerStart, &count, pinfo, &ei_wsp_oversized_uintvar);
            offset = headerStart + count;

            add_uri (wsp_tree, pinfo, tvb, uriStart, offset, proto_ti);
            offset += uriLength;

            if (tree)
                proto_tree_add_uint (wsp_tree, hf_wsp_header_length,
                        tvb, headerStart, count, headersLength);

            /* Stop processing POST PDU if length of headers is zero;
             * this should not happen as we expect at least Content-Type. */
            if (headersLength == 0)
                break;

            contentTypeStart = offset;
            nextOffset = add_content_type (wsp_tree, pinfo,
                    tvb, offset, &contentType, &contentTypeStr);

            /* Add content type to protocol summary line */
            if (contentTypeStr) {
                proto_item_append_text(proto_ti, ", Content-Type: %s",
                        contentTypeStr);
            } else {
                proto_item_append_text(proto_ti, ", Content-Type: 0x%X",
                        contentType);
            }

            /* Add headers subtree that will hold the headers fields */
            /* Runs from nextOffset for
                * headersLength - (length of content-type field) */
            headerLength = headersLength - (nextOffset - contentTypeStart);
            if (headerLength > 0)
            {
                tmp_tvb = tvb_new_subset_length (tvb, nextOffset,
                        headerLength);
                add_headers (wsp_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
            }
            /* XXX - offset is no longer used after this point */
            /* offset = nextOffset+headerLength; */

            /* WSP_PDU_POST data - First check whether a subdissector exists
             * for the content type */
            if (tvb_reported_length_remaining(tvb,
                        headerStart + count + uriLength + headersLength) > 0)
            {
                tmp_tvb = tvb_new_subset_remaining (tvb,
                        headerStart + count + uriLength + headersLength);
                /*
                 * Try finding a dissector for the content
                 * first, then fallback.
                 */
                found_match = 0;
                if (contentTypeStr) {
                    /*
                     * Content type is a string.
                     */
                    found_match = dissector_try_string(media_type_table,
                            contentTypeStr, tmp_tvb, pinfo, tree, NULL);
                }
                if (! found_match) {
                    if (! dissector_try_heuristic(heur_subdissector_list,
                                tmp_tvb, pinfo, tree, &hdtbl_entry, NULL)) {

                        pinfo->match_string = contentTypeStr;
                        call_dissector_with_data(media_handle, tmp_tvb, pinfo, tree, NULL /* TODO: parameters */);
#if 0
                        if (tree) /* Only display if needed */
                            add_post_data (wsp_tree, tmp_tvb,
                                    contentType, contentTypeStr, pinfo);
#endif
                    }
                }
            }
            break;

        case WSP_PDU_REPLY:
            count = 0;  /* Initialise count */
            headersLength = tvb_get_guintvar (tvb, offset+1, &count, pinfo, &ei_wsp_oversized_uintvar);
            headerStart = offset + count + 1;
            {
                guint8 reply_status = tvb_get_guint8(tvb, offset);
                const char *reply_status_str;

                reply_status_str = val_to_str_ext_const (reply_status, &wsp_vals_status_ext, "(Unknown response status)");
                if (tree) {
                    proto_tree_add_item (wsp_tree, hf_wsp_header_status,
                            tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    proto_item_append_text(proto_ti, ", Status: %s (0x%02x)",
                            reply_status_str, reply_status);
                }
                stat_info->status_code = (gint) reply_status;
                /* Append status code to INFO column */
                col_append_fstr(pinfo->cinfo, COL_INFO,
                            ": %s (0x%02x)",
                            reply_status_str, reply_status);
            }
            nextOffset = offset + 1 + count;
            if (tree)
                proto_tree_add_uint (wsp_tree, hf_wsp_header_length,
                        tvb, offset + 1, count, headersLength);

            if (headersLength == 0)
                break;

            contentTypeStart = nextOffset;
            nextOffset = add_content_type (wsp_tree, pinfo, tvb,
                    nextOffset, &contentType, &contentTypeStr);

            /* Add content type to protocol summary line */
            if (contentTypeStr) {
                proto_item_append_text(proto_ti, ", Content-Type: %s",
                        contentTypeStr);
            } else {
                proto_item_append_text(proto_ti, ", Content-Type: 0x%X",
                        contentType);
            }

            /* Add headers subtree that will hold the headers fields */
            /* Runs from nextOffset for
                * headersLength - (length of Content-Type field) */
            headerLength = headersLength - (nextOffset - contentTypeStart);
            if (headerLength > 0)
            {
                tmp_tvb = tvb_new_subset_length (tvb, nextOffset,
                        headerLength);
                add_headers (wsp_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
            }
            /* XXX - offset is no longer used after this point */
            /* offset += count+headersLength+1;*/

            /* WSP_PDU_REPLY data - First check whether a subdissector exists
             * for the content type */
            if (tvb_reported_length_remaining(tvb, headerStart + headersLength)
                    > 0)
            {
                tmp_tvb = tvb_new_subset_remaining (tvb, headerStart + headersLength);
                /*
                 * Try finding a dissector for the content
                 * first, then fallback.
                 */
                found_match = 0;
                if (contentTypeStr) {
                    /*
                     * Content type is a string.
                     */
                    found_match = dissector_try_string(media_type_table,
                            contentTypeStr, tmp_tvb, pinfo, tree, NULL);
                }
                if (! found_match) {
                    if (! dissector_try_heuristic(heur_subdissector_list,
                                tmp_tvb, pinfo, tree, &hdtbl_entry, NULL)) {

                        pinfo->match_string = contentTypeStr;
                        call_dissector_with_data(media_handle, tmp_tvb, pinfo, tree, NULL /* TODO: parameters */);
#if 0
                        if (tree) / * Only display if needed * /
                            proto_tree_add_item (wsp_tree,
                                hf_wsp_reply_data,
                                tmp_tvb, 0, -1, ENC_NA);
#endif
                    }
                }
            }
            break;

        case WSP_PDU_PUSH:
        case WSP_PDU_CONFIRMEDPUSH:
            count = 0;  /* Initialise count */
            headersLength = tvb_get_guintvar (tvb, offset, &count, pinfo, &ei_wsp_oversized_uintvar);
            headerStart = offset + count;

            proto_tree_add_uint (wsp_tree, hf_wsp_header_length,
                        tvb, offset, count, headersLength);

            if (headersLength == 0)
                break;

            offset += count;
            contentTypeStart = offset;
            nextOffset = add_content_type (wsp_tree, pinfo,
                    tvb, offset, &contentType, &contentTypeStr);

            /* Add content type to protocol summary line */
            if (contentTypeStr) {
                proto_item_append_text(proto_ti, ", Content-Type: %s",
                        contentTypeStr);
            } else {
                proto_item_append_text(proto_ti, ", Content-Type: 0x%X",
                        contentType);
            }

            /* Add headers subtree that will hold the headers fields */
            /* Runs from nextOffset for
                * headersLength-(length of Content-Type field) */
            headerLength = headersLength-(nextOffset-contentTypeStart);
            if (headerLength > 0)
            {
                tmp_tvb = tvb_new_subset_length (tvb, nextOffset,
                        headerLength);
                add_headers (wsp_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
            }
            /* XXX - offset is no longer used after this point */
            /*offset += headersLength;*/

            /* WSP_PDU_PUSH data - First check whether a subdissector exists
             * for the content type */
            if (tvb_reported_length_remaining(tvb, headerStart + headersLength)
                    > 0)
            {
                tmp_tvb = tvb_new_subset_remaining (tvb, headerStart + headersLength);
                /*
                 * Try finding a dissector for the content
                 * first, then fallback.
                 */
                found_match = 0;
                if (contentTypeStr) {
                    /*
                     * Content type is a string.
                     */
                    /*
                    if (g_ascii_strcasecmp(contentTypeStr, "application/vnd.wap.sia") == 0) {
                        dissect_sir(tree, tmp_tvb);
                    } else
                    */
                    found_match = dissector_try_string(media_type_table,
                            contentTypeStr, tmp_tvb, pinfo, tree, NULL);
                }
                if (! found_match) {
                    if (! dissector_try_heuristic(heur_subdissector_list,
                                tmp_tvb, pinfo, tree, &hdtbl_entry, NULL)) {

                        pinfo->match_string = contentTypeStr;
                        call_dissector_with_data(media_handle, tmp_tvb, pinfo, tree, NULL /* TODO: parameters */);
#if 0
                        if (tree) /* Only display if needed */
                            proto_tree_add_item (wsp_tree,
                                    hf_wsp_push_data,
                                    tmp_tvb, 0, -1, ENC_NA);
#endif
                    }
                }
            }
            break;

    }
    stat_info->pdut = pdut;
    tap_queue_packet (wsp_tap, pinfo, stat_info);
}


/*
 * Called directly from UDP.
 * Put "WSP" into the "Protocol" column.
 */
static int
dissect_wsp_fromudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "WSP");
    col_clear(pinfo->cinfo, COL_INFO);

    dissect_wsp_common(tvb, pinfo, tree, wsp_fromudp_handle, TRUE);
    return tvb_captured_length(tvb);
}


/*
 * Called from a higher-level WAP dissector, in connection-oriented mode.
 * Leave the "Protocol" column alone - the dissector calling us should
 * have set it.
 */
static int
dissect_wsp_fromwap_co(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /*
     * XXX - what about WTLS->WTP->WSP?
     */
    dissect_wsp_common(tvb, pinfo, tree, wtp_fromudp_handle, FALSE);
    return tvb_captured_length(tvb);
}


/*
 * Called from a higher-level WAP dissector, in connectionless mode.
 * Leave the "Protocol" column alone - the dissector calling us should
 * have set it.
 */
static int
dissect_wsp_fromwap_cl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    /*
     * XXX - what about WTLS->WSP?
     */
    col_clear(pinfo->cinfo, COL_INFO);
    dissect_wsp_common(tvb, pinfo, tree, wtp_fromudp_handle, TRUE);
    return tvb_captured_length(tvb);
}


static void
add_uri (proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
        guint URILenOffset, guint URIOffset, proto_item *proto_ti)
{
    guint  count  = 0;
    guint  uriLen = tvb_get_guintvar (tvb, URILenOffset, &count, pinfo, &ei_wsp_oversized_uintvar);
    gchar *str;

    proto_tree_add_uint (tree, hf_wsp_header_uri_len,
            tvb, URILenOffset, count, uriLen);

    proto_tree_add_item (tree, hf_wsp_header_uri,
            tvb, URIOffset, uriLen, ENC_ASCII|ENC_NA);

    str = tvb_format_text (tvb, URIOffset, uriLen);
    /* XXX - tvb_format_text() returns a pointer to a static text string
     * so please DO NOT attempt at g_free()ing it!
     */
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", str);

    if (proto_ti)
        proto_item_append_text(proto_ti, ", URI: %s", str);
}


/*
 * CO-WSP capability negotiation
 */

enum {
    WSP_CAPA_CLIENT_SDU_SIZE = 0x00,
    WSP_CAPA_SERVER_SDU_SIZE,
    WSP_CAPA_PROTOCOL_OPTIONS,
    WSP_CAPA_METHOD_MOR,
    WSP_CAPA_PUSH_MOR,
    WSP_CAPA_EXTENDED_METHODS,
    WSP_CAPA_HEADER_CODE_PAGES,
    WSP_CAPA_ALIASES,
    WSP_CAPA_CLIENT_MESSAGE_SIZE,
    WSP_CAPA_SERVER_MESSAGE_SIZE
};

static const value_string wsp_capability_vals [] = {
    { WSP_CAPA_CLIENT_SDU_SIZE,      "Client SDU Size" },
    { WSP_CAPA_SERVER_SDU_SIZE,      "Server SDU Size" },
    { WSP_CAPA_PROTOCOL_OPTIONS,     "Protocol Options" },
    { WSP_CAPA_METHOD_MOR,           "Method MOR" },
    { WSP_CAPA_PUSH_MOR,             "Push MOR" },
    { WSP_CAPA_EXTENDED_METHODS,     "Extended Methods" },
    { WSP_CAPA_HEADER_CODE_PAGES,    "Header Code Pages" },
    { WSP_CAPA_ALIASES,              "Aliases" },
    { WSP_CAPA_CLIENT_MESSAGE_SIZE,  "Client Message Size" },
    { WSP_CAPA_SERVER_MESSAGE_SIZE,  "Server Message Size" },
    { 0, NULL }
};

static void
add_capabilities (proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint8 pdu_type)
{
    proto_tree *wsp_capabilities, *cap_subtree, *cap_subtree2;
    proto_item *ti, *cap_item, *cap_item2;

    char       *capaName, *str;
    guint32     offset       = 0;
    guint32     len          = 0;
    guint32     capaStart    = 0; /* Start offset of the capability */
    guint32     capaLen      = 0; /* Length of the entire capability */
    guint32     capaValueLen = 0; /* Length of the capability value & type */
    guint32     tvb_len      = tvb_reported_length(tvb);
    gboolean    ok           = FALSE;
    guint8      peek;
    guint32     value;

    if (tvb_len == 0) {
        return;
    }

    ti = proto_tree_add_item(tree, hf_capabilities_section,
            tvb, 0, tvb_len, ENC_NA);
    wsp_capabilities = proto_item_add_subtree(ti, ett_capabilities);

    while (offset < tvb_len) {
        /*
         * WSP capabilities consist of:
         *  - a guint32 length field,
         *  - a capability identifier as Token-text or Short-integer,
         *  - a capability-specific sequence of <length> octets.
         */
        capaStart = offset;
        /*
         * Now Offset points to the 1st byte of a capability field.
         * Get the length of the capability field
         */
        capaValueLen = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
        capaLen = capaValueLen + len;

        cap_subtree = proto_tree_add_subtree(wsp_capabilities, tvb, offset, capaLen, ett_capabilities_entry, &cap_item, "Capability");
        offset += len;
        /*
         * Now offset points to the 1st byte of the capability type.
         * Get the capability identifier.
         */
        peek = tvb_get_guint8(tvb, offset);
        if (is_token_text(peek)) { /* Literal capability name */
            /* 1. Get the string from the tvb */
            capaName = (gchar *)tvb_get_stringz_enc(wmem_packet_scope(), tvb, capaStart, (gint *)&len, ENC_ASCII);

            /* 2. Look up the string capability name */
            if (g_ascii_strcasecmp(capaName, "client-sdu-size") == 0) {
                peek = WSP_CAPA_CLIENT_SDU_SIZE;
            } else if (g_ascii_strcasecmp(capaName, "server-sdu-size") == 0) {
                peek = WSP_CAPA_SERVER_SDU_SIZE;
            } else if (g_ascii_strcasecmp(capaName, "protocol options") == 0) {
                peek = WSP_CAPA_PROTOCOL_OPTIONS;
            } else if (g_ascii_strcasecmp(capaName, "method-mor") == 0) {
                peek = WSP_CAPA_METHOD_MOR;
            } else if (g_ascii_strcasecmp(capaName, "push-mor") == 0) {
                peek = WSP_CAPA_PUSH_MOR;
            } else if (g_ascii_strcasecmp(capaName, "extended methods") == 0) {
                peek = WSP_CAPA_EXTENDED_METHODS;
            } else if (g_ascii_strcasecmp(capaName, "header code pages") == 0) {
                peek = WSP_CAPA_HEADER_CODE_PAGES;
            } else if (g_ascii_strcasecmp(capaName, "aliases") == 0) {
                peek = WSP_CAPA_ALIASES;
            } else if (g_ascii_strcasecmp(capaName, "client-message-size") == 0) {
                peek = WSP_CAPA_CLIENT_MESSAGE_SIZE;
            } else if (g_ascii_strcasecmp(capaName, "server-message-size") == 0) {
                peek = WSP_CAPA_SERVER_MESSAGE_SIZE;
            } else {
                expert_add_info_format(pinfo, cap_item, &ei_wsp_capability_invalid,
                        "Unknown or invalid textual capability: %s", capaName);
                /* Skip this capability */
                offset = capaStart + capaLen;
                continue;
            }
            offset += len;
            /* Now offset points to the 1st value byte of the capability. */
        } else if (peek < 0x80) {
            expert_add_info_format(pinfo, cap_item, &ei_wsp_capability_invalid,
                    "Invalid well-known capability: 0x%02X", peek);
            /* Skip further capability parsing */
            return;
        }
        if (peek & 0x80) { /* Well-known capability */
            peek &= 0x7F;
            len = 1;
            offset++;
            /* Now offset points to the 1st value byte of the capability. */
        }

        proto_item_append_text(cap_item, ": %s", val_to_str_const(peek, wsp_capability_vals, "Invalid capabiliity"));
        /* Now the capability type is known */
        switch (peek) {
            case WSP_CAPA_CLIENT_SDU_SIZE:
                value = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
                proto_tree_add_uint(cap_subtree, hf_capa_client_sdu_size,
                        tvb, offset, len, value);
                break;
            case WSP_CAPA_SERVER_SDU_SIZE:
                value = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
                proto_tree_add_uint(cap_subtree, hf_capa_server_sdu_size,
                        tvb, offset, len, value);
                break;
            case WSP_CAPA_PROTOCOL_OPTIONS:
                /*
                 * The bits are stored in one or more octets, not an
                 * uintvar-integer! Note that capability name and value
                 * have length capaValueLength, and that the capability
                 * name has length = len. Hence the remaining length is
                 * given by capaValueLen - len.
                 */
                if (capaValueLen - len == 1) {
                    static const int * capabilities[] = {
                        &hf_capa_protocol_option_confirmed_push,
                        &hf_capa_protocol_option_push,
                        &hf_capa_protocol_option_session_resume,
                        &hf_capa_protocol_option_ack_headers,
                        &hf_capa_protocol_option_large_data_transfer,
                        NULL
                    };

                    proto_tree_add_bitmask_with_flags(cap_subtree, tvb, offset, hf_capa_protocol_options,
                                   ett_proto_option_capability, capabilities, ENC_NA, BMT_NO_FALSE);
                }
                else
                {
                    /*
                     * The WSP spec foresees that this bit field can be
                     * extended in the future. This does not make sense yet.
                     */
                    proto_item_append_text(cap_item,
                            " <warning: bit field too large>");
                    offset = capaStart + capaLen;
                    continue;
                }
                break;
            case WSP_CAPA_METHOD_MOR:
                proto_tree_add_item(cap_subtree, hf_capa_method_mor, tvb, offset, len, ENC_NA);
                break;
            case WSP_CAPA_PUSH_MOR:
                proto_tree_add_item(cap_subtree, hf_capa_push_mor, tvb, offset, len, ENC_NA);
               break;
            case WSP_CAPA_EXTENDED_METHODS:
                /* Extended Methods capability format:
                 * Connect PDU: collection of { Method (octet), Method-name (Token-text) }
                 * ConnectReply PDU: collection of accepted { Method (octet) }
                 */
                cap_subtree2 = proto_tree_add_subtree(cap_subtree, tvb, capaStart, capaLen, ett_capabilities_extended_methods, &cap_item2, "Extended Methods");
                if (pdu_type == WSP_PDU_CONNECT) {
                    while (offset < capaStart + capaLen) {
                        ti = proto_tree_add_item(cap_subtree2, hf_capa_extended_method, tvb, offset, 1, ENC_NA);
                        offset++;

                        get_text_string(str, tvb, offset, len, ok);
                        if (! ok) {
                            expert_add_info(pinfo, ti, &ei_wsp_capability_encoding_invalid);
                            return;
                        }
                        proto_item_append_text(ti, " = %s", str);
                        proto_item_set_len(ti, len+1);
                        offset += len;
                    }
                } else {
                    while (offset < capaStart + capaLen) {
                        proto_tree_add_item(cap_subtree2, hf_capa_extended_method, tvb, offset, 1, ENC_NA);
                        offset++;
                    }
                }
                break;
            case WSP_CAPA_HEADER_CODE_PAGES:
                /* Header Code Pages capability format:
                 * Connect PDU: collection of { Page-id (octet), Page-name (Token-text) }
                 * ConnectReply PDU: collection of accepted { Page-id (octet) }
                 */
                cap_subtree2 = proto_tree_add_subtree(cap_subtree, tvb, capaStart, capaLen, ett_capabilities_header_code_pages, &cap_item2, "Header Code Pages");
                if (pdu_type == WSP_PDU_CONNECT) {
                    while (offset < capaStart + capaLen) {
                        ti = proto_tree_add_item(cap_subtree2, hf_capa_header_code_page, tvb, offset, 1, ENC_NA);
                        offset++;

                        get_text_string(str, tvb, offset, len, ok);
                        if (! ok) {
                            expert_add_info(pinfo, ti, &ei_wsp_capability_encoding_invalid);
                            return;
                        }
                        proto_item_append_text(ti, " = %s", str);
                        proto_item_set_len(ti, len+1);
                        offset += len;
                    }
                } else {
                    while (offset < capaStart + capaLen) {
                        proto_tree_add_item(cap_subtree2, hf_capa_header_code_page, tvb, offset, 1, ENC_NA);
                        offset++;
                    }
                }
                break;
            case WSP_CAPA_ALIASES:
                /* TODO - same format as redirect addresses */
                proto_tree_add_item(cap_subtree, hf_capa_aliases,
                        tvb, capaStart, capaLen, ENC_NA);
                break;
            case WSP_CAPA_CLIENT_MESSAGE_SIZE:
                value = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
                proto_tree_add_uint(cap_subtree, hf_capa_client_message_size,
                        tvb, offset, len, value);
                break;
            case WSP_CAPA_SERVER_MESSAGE_SIZE:
                value = tvb_get_guintvar(tvb, offset, &len, pinfo, &ei_wsp_oversized_uintvar);
                proto_tree_add_uint(cap_subtree, hf_capa_server_message_size,
                        tvb, offset, len, value);
                break;
            default:
                expert_add_info_format(pinfo, cap_item, &ei_wsp_capability_invalid,
                        "Unknown well-known capability: 0x%02X", peek);
                break;
        }
        offset = capaStart + capaLen;
    }
}

void
add_post_data (proto_tree *tree, tvbuff_t *tvb, guint contentType,
    const char *contentTypeStr, packet_info *pinfo)
{
    guint       offset        = 0;
    guint       variableStart = 0;
    guint       variableEnd   = 0;
    guint       valueStart    = 0;
    guint8      peek          = 0;
    proto_item *ti;
    proto_tree *sub_tree      = NULL;

    /* VERIFY ti = proto_tree_add_item (tree, hf_wsp_post_data,tvb,offset,-1,ENC_NA); */
    if (tree) {
        ti = proto_tree_add_item (tree, hf_wsp_post_data,
                tvb, offset, -1, ENC_NA);
        sub_tree = proto_item_add_subtree(ti, ett_post);
    }

    if ( (contentTypeStr == NULL && contentType == 0x12)
            || (contentTypeStr && (g_ascii_strcasecmp(contentTypeStr,
                        "application/x-www-form-urlencoded") == 0)) )
    {
        if (tree) {
            /*
             * URL Encoded data.
             * Iterate through post data.
             */
            for (offset = 0; offset < tvb_reported_length (tvb); offset++)
            {
                peek = tvb_get_guint8 (tvb, offset);
                if (peek == '=')
                {
                    variableEnd = offset;
                    valueStart = offset+1;
                }
                else if (peek == '&')
                {
                    if (variableEnd > 0)
                    {
                        add_post_variable (sub_tree, tvb, variableStart, variableEnd, valueStart, offset);
                    }
                    variableStart = offset+1;
                    variableEnd = 0;
                    valueStart = 0;
                }
            }

            /* See if there's outstanding data */
            if (variableEnd > 0)
            {
                add_post_variable (sub_tree, tvb, variableStart, variableEnd, valueStart, offset);
            }
        } /* if (tree) */
    }
    else if ((contentType == 0x22) || (contentType == 0x23) || (contentType == 0x24) ||
         (contentType == 0x25) || (contentType == 0x26) || (contentType == 0x33))
    {
        /* add_multipart_data takes also care of subdissection */
        add_multipart_data(sub_tree, tvb, pinfo);
    }
}

static void
add_post_variable (proto_tree *tree, tvbuff_t *tvb, guint variableStart, guint variableEnd, guint valueStart, guint valueEnd)
{
    int   variableLength = variableEnd-variableStart;
    int   valueLength    = 0;
    char *variableBuffer;
    char *valueBuffer;

    variableBuffer = tvb_get_string_enc(wmem_packet_scope(), tvb, variableStart, variableLength, ENC_ASCII);

    if (valueEnd < valueStart)
    {
        valueBuffer = (char *)wmem_alloc(wmem_packet_scope(), 1);
        valueBuffer[0] = 0;
        valueEnd = valueStart;
    }
    else
    {
        valueLength = valueEnd-valueStart;
        valueBuffer = tvb_get_string_enc(wmem_packet_scope(), tvb, valueStart, valueLength, ENC_ASCII);
    }

    /* Check for variables with no value */
    if (valueStart >= tvb_reported_length (tvb))
    {
        valueStart = tvb_reported_length (tvb);
        valueEnd = valueStart;
    }
    valueLength = valueEnd-valueStart;

    proto_tree_add_string_format(tree, hf_wsp_variable_value, tvb, variableStart, valueLength, valueBuffer, "%s: %s", variableBuffer, valueBuffer);

}

static void
add_multipart_data (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo)
{
    int         offset      = 0;
    guint       nextOffset;
    guint       nEntries    = 0;
    guint       count;
    guint       HeadersLen;
    guint       DataLen;
    guint       contentType = 0;
    const char *contentTypeStr;
    tvbuff_t   *tmp_tvb;
    int         partnr      = 1;
    int         part_start;
    int         found_match = 0;

    proto_item *sub_tree   = NULL;
    proto_item *ti         = NULL;
    proto_tree *mpart_tree = NULL;

    heur_dtbl_entry_t       *hdtbl_entry;

    nEntries = tvb_get_guintvar (tvb, offset, &count, pinfo, &ei_wsp_oversized_uintvar);
    offset += count;
    if (nEntries)
    {
        sub_tree = proto_tree_add_subtree(tree, tvb, offset - count, 0,
                    ett_mpartlist, NULL, "Multipart body");
    }
    while (nEntries--)
    {
        part_start = offset;
        HeadersLen = tvb_get_guintvar (tvb, offset, &count, pinfo, &ei_wsp_oversized_uintvar);
        offset += count;
        DataLen = tvb_get_guintvar (tvb, offset, &count, pinfo, &ei_wsp_oversized_uintvar);
        offset += count;

        ti = proto_tree_add_uint(sub_tree, hf_wsp_mpart, tvb, part_start,
                    HeadersLen + DataLen + (offset - part_start), partnr);
        mpart_tree = proto_item_add_subtree(ti, ett_multiparts);

        nextOffset = add_content_type (mpart_tree, pinfo, tvb, offset,
                &contentType, &contentTypeStr);

        if (tree) {
            /* Add content type to protocol summary line */
            if (contentTypeStr) {
                proto_item_append_text(ti, ", content-type: %s",
                        contentTypeStr);
            } else {
                proto_item_append_text(ti, ", content-type: 0x%X",
                        contentType);
            }
        }

        HeadersLen -= (nextOffset - offset);
        if (HeadersLen > 0)
        {
            tmp_tvb = tvb_new_subset_length (tvb, nextOffset, HeadersLen);
            add_headers (mpart_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
        }
        offset = nextOffset + HeadersLen;
        /*
         * Try the dissectors of the multipart content.
         *
         * TODO - handle nested multipart documents.
         */
        tmp_tvb = tvb_new_subset_length(tvb, offset, DataLen);
        /*
         * Try finding a dissector for the content
         * first, then fallback.
         */
        found_match = 0;
        if (contentTypeStr) {
            /*
             * Content type is a string.
             */
            found_match = dissector_try_string(media_type_table,
                    contentTypeStr, tmp_tvb, pinfo, mpart_tree, NULL);
        }
        if (! found_match) {
            if (! dissector_try_heuristic(heur_subdissector_list,
                        tmp_tvb, pinfo, mpart_tree, &hdtbl_entry, NULL)) {

                pinfo->match_string = contentTypeStr;
                call_dissector_with_data(media_handle, tmp_tvb, pinfo, mpart_tree, NULL /* TODO: parameters */);
#if 0
                if (tree) /* Only display if needed */
                    proto_tree_add_item (mpart_tree, hf_wsp_multipart_data,
                            tvb, offset, DataLen, ENC_NA);
#endif
            }
        }

        offset += DataLen;
        partnr++;
    }
}

/* TAP STAT INFO */
typedef enum
{
	MESSAGE_TYPE_COLUMN = 0,
	PACKET_COLUMN
} wsp_stat_columns;

static stat_tap_table_item wsp_stat_fields[] = {
	{TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "Type / Code", "%-25s"},
	{TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Packets", "%d"}
	};

static int unknown_pt_idx;
static int unknown_sc_idx;

static void wsp_stat_init(stat_tap_table_ui* new_stat, new_stat_tap_gui_init_cb gui_callback, void* gui_data)
{
	int num_fields = sizeof(wsp_stat_fields)/sizeof(stat_tap_table_item);
	stat_tap_table* pt_table = new_stat_tap_init_table("PDU Types", num_fields, 0, NULL, gui_callback, gui_data);
	stat_tap_table_item_type pt_items[sizeof(wsp_stat_fields)/sizeof(stat_tap_table_item)];
	stat_tap_table* sc_table = new_stat_tap_init_table("Status Codes", num_fields, 0, NULL, gui_callback, gui_data);
	stat_tap_table_item_type sc_items[sizeof(wsp_stat_fields)/sizeof(stat_tap_table_item)];
	int table_idx;

	new_stat_tap_add_table(new_stat, pt_table);
	new_stat_tap_add_table(new_stat, sc_table);

	/* Add a row for each PDU type and status code */
	table_idx = 0;
	memset(pt_items, 0, sizeof(pt_items));
	pt_items[MESSAGE_TYPE_COLUMN].type = TABLE_ITEM_STRING;
	pt_items[PACKET_COLUMN].type = TABLE_ITEM_UINT;
	while (wsp_vals_pdu_type[table_idx].strptr)
	{
		pt_items[MESSAGE_TYPE_COLUMN].value.string_value = g_strdup(wsp_vals_pdu_type[table_idx].strptr);
		pt_items[MESSAGE_TYPE_COLUMN].user_data.uint_value = wsp_vals_pdu_type[table_idx].value;

		new_stat_tap_init_table_row(pt_table, table_idx, num_fields, pt_items);
		table_idx++;
	}
	pt_items[MESSAGE_TYPE_COLUMN].value.string_value = g_strdup("Unknown PDU type");
	pt_items[MESSAGE_TYPE_COLUMN].user_data.uint_value = 0;
	new_stat_tap_init_table_row(pt_table, table_idx, num_fields, pt_items);
	unknown_pt_idx = table_idx;

	table_idx = 0;
	memset(sc_items, 0, sizeof(sc_items));
	sc_items[MESSAGE_TYPE_COLUMN].type = TABLE_ITEM_STRING;
	sc_items[PACKET_COLUMN].type = TABLE_ITEM_UINT;
	while (wsp_vals_status[table_idx].strptr)
	{
		sc_items[MESSAGE_TYPE_COLUMN].value.string_value = g_strdup(wsp_vals_status[table_idx].strptr);
		sc_items[MESSAGE_TYPE_COLUMN].user_data.uint_value = wsp_vals_status[table_idx].value;

		new_stat_tap_init_table_row(sc_table, table_idx, num_fields, sc_items);
		table_idx++;
	}
	sc_items[MESSAGE_TYPE_COLUMN].value.string_value = g_strdup("Unknown status code");
	sc_items[MESSAGE_TYPE_COLUMN].user_data.uint_value = 0;
	new_stat_tap_init_table_row(sc_table, table_idx, num_fields, sc_items);
	unknown_sc_idx = table_idx;
}

static gboolean
wsp_stat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *wiv_ptr)
{
	new_stat_data_t* stat_data = (new_stat_data_t*)tapdata;
	const wsp_info_value_t *value = (const wsp_info_value_t *)wiv_ptr;
	stat_tap_table *pt_table, *sc_table;
	guint element;
	stat_tap_table_item_type* item_data;
	gboolean found;

	pt_table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);
	sc_table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 1);

	found = FALSE;
	for (element = 0; element < pt_table->num_elements; element++) {
		item_data = new_stat_tap_get_field_data(pt_table, element, MESSAGE_TYPE_COLUMN);
		if (value->pdut == item_data->user_data.uint_value) {
			found = TRUE;
			break;
		}
	}
	if (!found) {
		element = unknown_pt_idx;
	}
	item_data = new_stat_tap_get_field_data(pt_table, element, PACKET_COLUMN);
	item_data->value.uint_value++;
	new_stat_tap_set_field_data(pt_table, element, PACKET_COLUMN, item_data);

	if (value->status_code != 0) {
		found = FALSE;
		for (element = 0; element < sc_table->num_elements; element++) {
			item_data = new_stat_tap_get_field_data(sc_table, element, MESSAGE_TYPE_COLUMN);
			if (value->status_code == (int) item_data->user_data.uint_value) {
				found = TRUE;
				break;
			}
		}
		if (!found) {
			element = unknown_sc_idx;
		}
		item_data = new_stat_tap_get_field_data(sc_table, element, PACKET_COLUMN);
		item_data->value.uint_value++;
		new_stat_tap_set_field_data(sc_table, element, PACKET_COLUMN, item_data);
	}

	return TRUE;
}

static void
wsp_stat_reset(stat_tap_table* table)
{
	guint element;
	stat_tap_table_item_type* item_data;

	for (element = 0; element < table->num_elements; element++)
	{
		item_data = new_stat_tap_get_field_data(table, element, PACKET_COLUMN);
		item_data->value.uint_value = 0;
		new_stat_tap_set_field_data(table, element, PACKET_COLUMN, item_data);
	}
}

static void
wsp_stat_free_table_item(stat_tap_table* table _U_, guint row _U_, guint column, stat_tap_table_item_type* field_data)
{
	if (column != MESSAGE_TYPE_COLUMN) return;
	g_free((char*)field_data->value.string_value);
	field_data->value.string_value = NULL;
}

/* Register the protocol with Wireshark */
void
proto_register_wsp(void)
{

/* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_wsp_header_tid,
          {     "Transaction ID",
                "wsp.TID",
                FT_UINT8, BASE_HEX, NULL, 0x00,
                "WSP Transaction ID (for connectionless WSP)", HFILL
          }
        },
        { &hf_wsp_header_pdu_type,
          {     "PDU Type",
                "wsp.pdu_type",
                FT_UINT8, BASE_HEX|BASE_EXT_STRING,  &wsp_vals_pdu_type_ext, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_version_major,
          {     "Version (Major)",
                "wsp.version.major",
                FT_UINT8, BASE_DEC, NULL, 0xF0,
                NULL, HFILL
          }
        },
        { &hf_wsp_version_minor,
          {     "Version (Minor)",
                "wsp.version.minor",
                FT_UINT8, BASE_DEC, NULL, 0x0F,
                NULL, HFILL
          }
        },
        { &hf_capabilities_length,
          {     "Capabilities Length",
                "wsp.capabilities.length",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "Length of Capabilities field (bytes)", HFILL
          }
        },
        { &hf_wsp_header_length,
          {     "Headers Length",
                "wsp.headers_length",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "Length of Headers field (bytes)", HFILL
          }
        },
        { &hf_capabilities_section,
          {     "Capabilities",
                "wsp.capabilities",
                FT_NONE, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_headers_section,
          {     "Headers",
                "wsp.headers",
                FT_NONE, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_header_uri_len,
          {     "URI Length",
                "wsp.uri_length",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "Length of URI field", HFILL
          }
        },
        { &hf_wsp_header_uri,
          {     "URI",
                "wsp.uri",
                FT_STRING, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_server_session_id,
          {     "Server Session ID",
                "wsp.server.session_id",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_header_status,
          {     "Status",
                "wsp.reply.status",
                FT_UINT8, BASE_HEX|BASE_EXT_STRING,  &wsp_vals_status_ext, 0x00,
                "Reply Status", HFILL
          }
        },
        { &hf_wsp_parameter_untype_quote_text,
          {     "Untyped quoted text",
                "wsp.untype.quote_text",
                FT_STRING, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_parameter_untype_text,
          {     "Untyped text",
                "wsp.untype.text",
                FT_STRING, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_parameter_untype_int,
          {     "Untyped integer",
                "wsp.untype.int",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_parameter_type,
          {     "Parameter Type",
                "wsp.parameter.type",
                FT_UINT32, BASE_DEC|BASE_EXT_STRING, &parameter_type_vals_ext, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_parameter_int_type,
          {     "Integer Type",
                "wsp.parameter.int_type",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "Type parameter", HFILL
          }
        },
        { &hf_wsp_parameter_name,
          {     "Name",
                "wsp.parameter.name",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Name parameter", HFILL
          }
        },
        { &hf_wsp_parameter_filename,
          {     "Filename",
                "wsp.parameter.filename",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Filename parameter", HFILL
          }
        },
        { &hf_wsp_parameter_start,
          {     "Start",
                "wsp.parameter.start",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Start parameter", HFILL
          }
        },
        { &hf_wsp_parameter_start_info,
          {     "Start-info",
                "wsp.parameter.start_info",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Start-info parameter", HFILL
          }
        },
        { &hf_wsp_parameter_comment,
          {     "Comment",
                "wsp.parameter.comment",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Comment parameter", HFILL
          }
        },
        { &hf_wsp_parameter_domain,
          {     "Domain",
                "wsp.parameter.domain",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Domain parameter", HFILL
          }
        },
        { &hf_wsp_parameter_path,
          {     "Path",
                "wsp.parameter.path",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Path parameter", HFILL
          }
        },
        { &hf_wsp_parameter_sec,
          {     "SEC",
                "wsp.parameter.sec",
                FT_UINT8, BASE_HEX|BASE_EXT_STRING, &vals_wsp_parameter_sec_ext, 0x00,
                "SEC parameter (Content-Type: application/vnd.wap.connectivity-wbxml)", HFILL
          }
        },
        { &hf_wsp_parameter_mac,
          {     "MAC",
                "wsp.parameter.mac",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "MAC parameter (Content-Type: application/vnd.wap.connectivity-wbxml)", HFILL
          }
        },
        { &hf_wsp_parameter_upart_type,
          {     "Type",
                "wsp.parameter.upart.type",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Multipart type parameter", HFILL
          }
        },
        { &hf_wsp_parameter_level,
          {     "Level",
                "wsp.parameter.level",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Level parameter", HFILL
          }
        },
        { &hf_wsp_parameter_size,
          {     "Size",
                "wsp.parameter.size",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "Size parameter", HFILL
          }
        },
#if 0
        { &hf_wsp_reply_data,
          {     "Data",
                "wsp.reply.data",
                FT_NONE, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
#endif
        { &hf_wsp_header_shift_code,
          {     "Switching to WSP header code-page",
                "wsp.code_page",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Header code-page shift code", HFILL
          }
        },
        /*
         * CO-WSP capability negotiation
         */
        { &hf_capa_client_sdu_size,
          { "Client SDU Size",
            "wsp.capability.client_sdu_size",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Client Service Data Unit size (bytes)", HFILL
          }
        },
        { &hf_capa_server_sdu_size,
          { "Server SDU Size",
            "wsp.capability.server_sdu_size",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Server Service Data Unit size (bytes)", HFILL
          }
        },
        { &hf_capa_protocol_options,
          { "Protocol Options",
            "wsp.capability.protocol_opt",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL
          }
        },
        { &hf_capa_protocol_option_confirmed_push,
          { "Confirmed Push facility",
            "wsp.capability.protocol_option.confirmed_push",
            FT_BOOLEAN, 8, NULL, 0x80,
            "If set, this CO-WSP session supports the Confirmed Push facility", HFILL
          }
        },
        { &hf_capa_protocol_option_push,
          { "Push facility",
            "wsp.capability.protocol_option.push",
            FT_BOOLEAN, 8, NULL, 0x40,
            "If set, this CO-WSP session supports the Push facility", HFILL
          }
        },
        { &hf_capa_protocol_option_session_resume,
          { "Session Resume facility",
            "wsp.capability.protocol_option.session_resume",
            FT_BOOLEAN, 8, NULL, 0x20,
            "If set, this CO-WSP session supports the Session Resume facility", HFILL
          }
        },
        { &hf_capa_protocol_option_ack_headers,
          { "Acknowledgement headers",
            "wsp.capability.protocol_option.ack_headers",
            FT_BOOLEAN, 8, NULL, 0x10,
            "If set, this CO-WSP session supports Acknowledgement headers", HFILL
          }
        },
        { &hf_capa_protocol_option_large_data_transfer,
          { "Large data transfer",
            "wsp.capability.protocol_option.large_data_transfer",
            FT_BOOLEAN, 8, NULL, 0x08,
            "If set, this CO-WSP session supports Large data transfer", HFILL
          }
        },
        { &hf_capa_method_mor,
          { "Method MOR",
            "wsp.capability.method_mor",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL
          }
        },
        { &hf_capa_push_mor,
          { "Push MOR",
            "wsp.capability.push_mor",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL
          }
        },
        { &hf_capa_extended_method,
          { "Extended Method",
            "wsp.capability.extended_method",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL
          }
        },
        { &hf_capa_header_code_page,
          { "Header Code Page",
            "wsp.capability.code_page",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL
          }
        },
        { &hf_capa_aliases,
          { "Aliases",
            "wsp.capability.aliases",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL
          }
        },
        { &hf_capa_client_message_size,
          { "Client Message Size",
            "wsp.capability.client_message_size",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Client Message size (bytes)", HFILL
          }
        },
        { &hf_capa_server_message_size,
          { "Server Message Size",
            "wsp.capability.server_message_size",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Server Message size (bytes)", HFILL
          }
        },
        { &hf_wsp_post_data,
          {     "Data (Post)",
                "wsp.post.data",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "Post Data", HFILL
          }
        },
#if 0
        { &hf_wsp_push_data,
          {     "Push Data",
                "wsp.push.data",
                FT_NONE, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_multipart_data,
          {     "Data in this part",
                "wsp.multipart.data",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "The data of 1 MIME-multipart part.", HFILL
          }
        },
#endif
        { &hf_wsp_mpart,
          {     "Part",
                "wsp.multipart",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "MIME part of multipart data.", HFILL
          }
        },
        { &hf_wsp_header_text_value,
          {     "Header textual value",
                "wsp.header_text_value",
                FT_STRING, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_variable_value,
          {     "Variable value",
                "wsp.variable_value",
                FT_STRING, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_default_int,
          {     "Default integer",
                "wsp.default_int",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_default_string,
          {     "Default string value",
                "wsp.default_string",
                FT_STRING, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_default_val_len,
          {     "Default value len",
                "wsp.default_val_len",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_wsp_redirect_flags,
          {     "Flags",
                "wsp.redirect.flags",
                FT_UINT8, BASE_HEX, NULL, 0x00,
                "Redirect Flags", HFILL
          }
        },
        { &hf_wsp_redirect_permanent,
          {     "Permanent Redirect",
                "wsp.redirect.flags.permanent",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), PERMANENT_REDIRECT,
                NULL, HFILL
          }
        },
        { &hf_wsp_redirect_reuse_security_session,
          {     "Reuse Security Session",
                "wsp.redirect.flags.reuse_security_session",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), REUSE_SECURITY_SESSION,
                "If set, the existing Security Session may be reused", HFILL
          }
        },
        { &hf_redirect_addresses,
          { "Redirect Addresses",
            "wsp.redirect.addresses",
            FT_NONE, BASE_NONE, NULL, 0x00,
            "List of Redirect Addresses", HFILL
          }
        },

        /*
         * Addresses
         */
        { &hf_address_entry,
          { "Address Record",
            "wsp.address",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL
          }
        },
        { &hf_address_flags_length,
          {     "Flags/Length",
                "wsp.address.flags",
                FT_UINT8, BASE_HEX, NULL, 0x00,
                "Address Flags/Length", HFILL
          }
        },
        { &hf_address_flags_length_bearer_type_included,
          {     "Bearer Type Included",
                "wsp.address.flags.bearer_type_included",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), BEARER_TYPE_INCLUDED,
                "Address bearer type included", HFILL
          }
        },
        { &hf_address_flags_length_port_number_included,
          {     "Port Number Included",
                "wsp.address.flags.port_number_included",
                FT_BOOLEAN, 8, TFS(&tfs_yes_no), PORT_NUMBER_INCLUDED,
                "Address port number included", HFILL
          }
        },
        { &hf_address_flags_length_address_len,
          {     "Address Length",
                "wsp.address.flags.length",
                FT_UINT8, BASE_DEC, NULL, ADDRESS_LEN,
                NULL, HFILL
          }
        },
        { &hf_address_bearer_type,
          {     "Bearer Type",
                "wsp.address.bearer_type",
                FT_UINT8, BASE_HEX|BASE_EXT_STRING, &vals_bearer_types_ext, 0x0,
                NULL, HFILL
          }
        },
        { &hf_address_port_num,
          {     "Port Number",
                "wsp.address.port",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
          }
        },
        { &hf_address_ipv4_addr,
          {     "IPv4 Address",
                "wsp.address.ipv4",
                FT_IPv4, BASE_NONE, NULL, 0x0,
                "Address (IPv4)", HFILL
          }
        },
        { &hf_address_ipv6_addr,
          {     "IPv6 Address",
                "wsp.address.ipv6",
                FT_IPv6, BASE_NONE, NULL, 0x0,
                "Address (IPv6)", HFILL
          }
        },
        { &hf_address_addr,
          {     "Address",
                "wsp.address.unknown",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                "Address (unknown)", HFILL
          }
        },


        /*
         * New WSP header fields
         */


        /* WSP header name */
        { &hf_hdr_name_value,
          { "Header name",
            "wsp.header.name_value",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &vals_field_names_ext, 0x7F,
            "Name of the WSP header as numeric value", HFILL
          }
        },
        { &hf_hdr_name_string,
          { "Header name",
            "wsp.header.name_string",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Name of the WSP header as string", HFILL
          }
        },
        /* WSP headers start here */
        { &hf_hdr_accept,
          { "Accept",
            "wsp.header.accept",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Accept", HFILL
          }
        },
        { &hf_hdr_accept_charset,
          { "Accept-Charset",
            "wsp.header.accept_charset",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Accept-Charset", HFILL
          }
        },
        { &hf_hdr_accept_encoding,
          { "Accept-Encoding",
            "wsp.header.accept_encoding",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Accept-Encoding", HFILL
          }
        },
        { &hf_hdr_accept_language,
          { "Accept-Language",
            "wsp.header.accept_language",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Accept-Language", HFILL
          }
        },
        { &hf_hdr_accept_ranges,
          { "Accept-Ranges",
            "wsp.header.accept_ranges",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Accept-Ranges", HFILL
          }
        },
        { &hf_hdr_age,
          { "Age",
            "wsp.header.age",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Age", HFILL
          }
        },
        { &hf_hdr_allow,
          { "Allow",
            "wsp.header.allow",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Allow", HFILL
          }
        },
        { &hf_hdr_authorization,
          { "Authorization",
            "wsp.header.authorization",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Authorization", HFILL
          }
        },
        { &hf_hdr_authorization_scheme,
          { "Authorization Scheme",
            "wsp.header.authorization.scheme",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Authorization: used scheme", HFILL
          }
        },
        { &hf_hdr_authorization_user_id,
          { "User-id",
            "wsp.header.authorization.user_id",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Authorization: user ID for basic authorization", HFILL
          }
        },
        { &hf_hdr_authorization_password,
          { "Password",
            "wsp.header.authorization.password",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Authorization: password for basic authorization", HFILL
          }
        },
        { &hf_hdr_cache_control,
          { "Cache-Control",
            "wsp.header.cache_control",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Cache-Control", HFILL
          }
        },
        { &hf_hdr_connection,
          { "Connection",
            "wsp.header.connection",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Connection", HFILL
          }
        },
        { &hf_hdr_content_base,
          { "Content-Base",
            "wsp.header.content_base",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Content-Base", HFILL
          }
        },
        { &hf_hdr_content_encoding,
          { "Content-Encoding",
            "wsp.header.content_encoding",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Content-Encoding", HFILL
          }
        },
        { &hf_hdr_content_language,
          { "Content-Language",
            "wsp.header.content_language",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Content-Language", HFILL
          }
        },
        { &hf_hdr_content_length,
          { "Content-Length",
            "wsp.header.content_length",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Content-Length", HFILL
          }
        },
        { &hf_hdr_content_location,
          { "Content-Location",
            "wsp.header.content_location",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Content-Location", HFILL
          }
        },
        { &hf_hdr_content_md5,
          { "Content-Md5",
            "wsp.header.content_md5",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "WSP header Content-Md5", HFILL
          }
        },
        { &hf_hdr_content_range,
          { "Content-Range",
            "wsp.header.content_range",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Content-Range", HFILL
          }
        },
        { &hf_hdr_content_range_first_byte_pos,
          { "First-byte-position",
            "wsp.header.content_range.first_byte_pos",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "WSP header Content-Range: position of first byte", HFILL
          }
        },
        { &hf_hdr_content_range_entity_length,
          { "Entity-length",
            "wsp.header.content_range.entity_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "WSP header Content-Range: length of the entity", HFILL
          }
        },
        { &hf_hdr_content_type,
          { "Content-Type",
            "wsp.header.content_type",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Content-Type", HFILL
          }
        },
        { &hf_hdr_date,
          { "Date",
            "wsp.header.date",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Date", HFILL
          }
        },
        { &hf_hdr_etag,
          { "ETag",
            "wsp.header.etag",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header ETag", HFILL
          }
        },
        { &hf_hdr_expires,
          { "Expires",
            "wsp.header.expires",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Expires", HFILL
          }
        },
        { &hf_hdr_from,
          { "From",
            "wsp.header.from",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header From", HFILL
          }
        },
        { &hf_hdr_host,
          { "Host",
            "wsp.header.host",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Host", HFILL
          }
        },
        { &hf_hdr_if_modified_since,
          { "If-Modified-Since",
            "wsp.header.if_modified_since",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header If-Modified-Since", HFILL
          }
        },
        { &hf_hdr_if_match,
          { "If-Match",
            "wsp.header.if_match",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header If-Match", HFILL
          }
        },
        { &hf_hdr_if_none_match,
          { "If-None-Match",
            "wsp.header.if_none_match",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header If-None-Match", HFILL
          }
        },
        { &hf_hdr_if_range,
          { "If-Range",
            "wsp.header.if_range",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header If-Range", HFILL
          }
        },
        { &hf_hdr_if_unmodified_since,
          { "If-Unmodified-Since",
            "wsp.header.if_unmodified_since",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header If-Unmodified-Since", HFILL
          }
        },
        { &hf_hdr_last_modified,
          { "Last-Modified",
            "wsp.header.last_modified",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Last-Modified", HFILL
          }
        },
        { &hf_hdr_location,
          { "Location",
            "wsp.header.location",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Location", HFILL
          }
        },
        { &hf_hdr_max_forwards,
          { "Max-Forwards",
            "wsp.header.max_forwards",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Max-Forwards", HFILL
          }
        },
        { &hf_hdr_pragma,
          { "Pragma",
            "wsp.header.pragma",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Pragma", HFILL
          }
        },
        { &hf_hdr_proxy_authenticate,
          { "Proxy-Authenticate",
            "wsp.header.proxy_authenticate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Proxy-Authenticate", HFILL
          }
        },
        { &hf_hdr_proxy_authenticate_scheme,
          { "Authentication Scheme",
            "wsp.header.proxy_authenticate.scheme",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Proxy-Authenticate: used scheme", HFILL
          }
        },
        { &hf_hdr_proxy_authenticate_realm,
          { "Authentication Realm",
            "wsp.header.proxy_authenticate.realm",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Proxy-Authenticate: used realm", HFILL
          }
        },
        { &hf_hdr_proxy_authorization,
          { "Proxy-Authorization",
            "wsp.header.proxy_authorization",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Proxy-Authorization", HFILL
          }
        },
        { &hf_hdr_proxy_authorization_scheme,
          { "Authorization Scheme",
            "wsp.header.proxy_authorization.scheme",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Proxy-Authorization: used scheme", HFILL
          }
        },
        { &hf_hdr_proxy_authorization_user_id,
          { "User-id",
            "wsp.header.proxy_authorization.user_id",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Proxy-Authorization: user ID for basic authorization", HFILL
          }
        },
        { &hf_hdr_proxy_authorization_password,
          { "Password",
            "wsp.header.proxy_authorization.password",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Proxy-Authorization: password for basic authorization", HFILL
          }
        },
        { &hf_hdr_public,
          { "Public",
            "wsp.header.public",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Public", HFILL
          }
        },
        { &hf_hdr_range,
          { "Range",
            "wsp.header.range",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Range", HFILL
          }
        },
        { &hf_hdr_range_first_byte_pos,
          { "First-byte-position",
            "wsp.header.range.first_byte_pos",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "WSP header Range: position of first byte", HFILL
          }
        },
        { &hf_hdr_range_last_byte_pos,
          { "Last-byte-position",
            "wsp.header.range.last_byte_pos",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "WSP header Range: position of last byte", HFILL
          }
        },
        { &hf_hdr_range_suffix_length,
          { "Suffix-length",
            "wsp.header.range.suffix_length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "WSP header Range: length of the suffix", HFILL
          }
        },
        { &hf_hdr_referer,
          { "Referer",
            "wsp.header.referer",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Referer", HFILL
          }
        },
        { &hf_hdr_retry_after,
          { "Retry-After",
            "wsp.header.retry_after",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Retry-After", HFILL
          }
        },
        { &hf_hdr_server,
          { "Server",
            "wsp.header.server",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Server", HFILL
          }
        },
        { &hf_hdr_transfer_encoding,
          { "Transfer-Encoding",
            "wsp.header.transfer_encoding",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Transfer-Encoding", HFILL
          }
        },
        { &hf_hdr_upgrade,
          { "Upgrade",
            "wsp.header.upgrade",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Upgrade", HFILL
          }
        },
        { &hf_hdr_user_agent,
          { "User-Agent",
            "wsp.header.user_agent",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header User-Agent", HFILL
          }
        },
        { &hf_hdr_vary,
          { "Vary",
            "wsp.header.vary",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Vary", HFILL
          }
        },
        { &hf_hdr_via,
          { "Via",
            "wsp.header.via",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Via", HFILL
          }
        },
        { &hf_hdr_warning,
          { "Warning",
            "wsp.header.warning",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Warning", HFILL
          }
        },
        { &hf_hdr_warning_code,
          { "Warning code",
            "wsp.header.warning.code",
            FT_UINT8, BASE_HEX|BASE_EXT_STRING, &vals_wsp_warning_code_ext, 0x00,
            "WSP header Warning code", HFILL
          }
        },
        { &hf_hdr_warning_agent,
          { "Warning agent",
            "wsp.header.warning.agent",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Warning agent", HFILL
          }
        },
        { &hf_hdr_warning_text,
          { "Warning text",
            "wsp.header.warning.text",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Warning text", HFILL
          }
        },
        { &hf_hdr_www_authenticate,
          { "Www-Authenticate",
            "wsp.header.www_authenticate",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Www-Authenticate", HFILL
          }
        },
        { &hf_hdr_www_authenticate_scheme,
          { "Authentication Scheme",
            "wsp.header.www_authenticate.scheme",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header WWW-Authenticate: used scheme", HFILL
          }
        },
        { &hf_hdr_www_authenticate_realm,
          { "Authentication Realm",
            "wsp.header.www_authenticate.realm",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header WWW-Authenticate: used realm", HFILL
          }
        },
        { &hf_hdr_content_disposition,
          { "Content-Disposition",
            "wsp.header.content_disposition",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Content-Disposition", HFILL
          }
        },
        { &hf_hdr_application_id,
          { "Application-Id",
            "wsp.header.application_id",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Application-Id", HFILL
          }
        },
        { &hf_hdr_content_uri,
          { "Content-Uri",
            "wsp.header.content_uri",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Content-Uri", HFILL
          }
        },
        { &hf_hdr_initiator_uri,
          { "Initiator-Uri",
            "wsp.header.initiator_uri",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Initiator-Uri", HFILL
          }
        },
        { &hf_hdr_bearer_indication,
          { "Bearer-Indication",
            "wsp.header.bearer_indication",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Bearer-Indication", HFILL
          }
        },
        { &hf_hdr_push_flag,
          { "Push-Flag",
            "wsp.header.push_flag",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Push-Flag", HFILL
          }
        },
        { &hf_hdr_push_flag_auth,
          { "Initiator URI is authenticated",
            "wsp.header.push_flag.authenticated",
            FT_UINT8, BASE_DEC, VALS(vals_false_true), 0x01,
            "The X-Wap-Initiator-URI has been authenticated.", HFILL
          }
        },
        { &hf_hdr_push_flag_trust,
          { "Content is trusted",
            "wsp.header.push_flag.trusted",
            FT_UINT8, BASE_DEC, VALS(vals_false_true), 0x02,
            "The push content is trusted.", HFILL
          }
        },
        { &hf_hdr_push_flag_last,
          { "Last push message",
            "wsp.header.push_flag.last",
            FT_UINT8, BASE_DEC, VALS(vals_false_true), 0x04,
            "Indicates whether this is the last push message.", HFILL
          }
        },
        { &hf_hdr_profile,
          { "Profile",
            "wsp.header.profile",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Profile", HFILL
          }
        },
        { &hf_hdr_profile_diff,
          { "Profile-Diff",
            "wsp.header.profile_diff",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Profile-Diff", HFILL
          }
        },
        { &hf_hdr_profile_warning,
          { "Profile-Warning",
            "wsp.header.profile_warning",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Profile-Warning", HFILL
          }
        },
        { &hf_hdr_expect,
          { "Expect",
            "wsp.header.expect",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Expect", HFILL
          }
        },
        { &hf_hdr_te,
          { "Te",
            "wsp.header.te",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Te", HFILL
          }
        },
        { &hf_hdr_trailer,
          { "Trailer",
            "wsp.header.trailer",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Trailer", HFILL
          }
        },
        { &hf_hdr_x_wap_tod,
          { "X-Wap-Tod",
            "wsp.header.x_wap_tod",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
            "WSP header X-Wap-Tod", HFILL
          }
        },
        { &hf_hdr_content_id,
          { "Content-Id",
            "wsp.header.content_id",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Content-Id", HFILL
          }
        },
        { &hf_hdr_set_cookie,
          { "Set-Cookie",
            "wsp.header.set_cookie",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Set-Cookie", HFILL
          }
        },
        { &hf_hdr_cookie,
          { "Cookie",
            "wsp.header.cookie",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Cookie", HFILL
          }
        },
        { &hf_hdr_encoding_version,
          { "Encoding-Version",
            "wsp.header.encoding_version",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Encoding-Version", HFILL
          }
        },
        { &hf_hdr_x_wap_security,
          { "X-Wap-Security",
            "wsp.header.x_wap_security",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header X-Wap-Security", HFILL
          }
        },
        { &hf_hdr_x_wap_application_id,
          { "X-Wap-Application-Id",
            "wsp.header.x_wap_application_id",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header X-Wap-Application-Id", HFILL
          }
        },
        { &hf_hdr_accept_application,
          { "Accept-Application",
            "wsp.header.accept_application",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP header Accept-Application", HFILL
          }
        },


        /*
         * Openwave headers
         * Header Code Page: x-up-1
         */
        { &hf_hdr_openwave_default_int,
          {     "Default integer",
                "wsp.default_int",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_hdr_openwave_default_string,
          {     "Default string value",
                "wsp.default_string",
                FT_STRING, BASE_NONE, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_hdr_openwave_default_val_len,
          {     "Default value len",
                "wsp.default_val_len",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                NULL, HFILL
          }
        },
        { &hf_hdr_openwave_name_value,
          { "Header name",
            "wsp.header.name_value",
            FT_UINT8, BASE_DEC|BASE_EXT_STRING, &vals_openwave_field_names_ext, 0x7F,
            "WSP Openwave header as numeric value", HFILL
          }
        },

        /* Textual headers */
        { &hf_hdr_openwave_x_up_proxy_operator_domain,
          { "x-up-proxy-operator-domain",
            "wsp.header.x_up_1.x_up_proxy_operator_domain",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-operator-domain", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_home_page,
          { "x-up-proxy-home-page",
            "wsp.header.x_up_1.x_up_proxy_home_page",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-home-page", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_uplink_version,
          { "x-up-proxy-uplink-version",
            "wsp.header.x_up_1.x_up_proxy_uplink_version",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-uplink-version", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_ba_realm,
          { "x-up-proxy-ba-realm",
            "wsp.header.x_up_1.x_up_proxy_ba_realm",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-ba-realm", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_request_uri,
          { "x-up-proxy-request-uri",
            "wsp.header.x_up_1.x_up_proxy_request_uri",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-request-uri", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_bookmark,
          { "x-up-proxy-bookmark",
            "wsp.header.x_up_1.x_up_proxy_bookmark",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-bookmark", HFILL
          }
        },
        /* Integer-value headers */
        { &hf_hdr_openwave_x_up_proxy_push_seq,
          { "x-up-proxy-push-seq",
            "wsp.header.x_up_1.x_up_proxy_push_seq",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-push-seq", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_notify,
          { "x-up-proxy-notify",
            "wsp.header.x_up_1.x_up_proxy_notify",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-notify", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_net_ask,
          { "x-up-proxy-net-ask",
            "wsp.header.x_up_1.x_up_proxy_net_ask",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-net-ask", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_tod,
          { "x-up-proxy-tod",
            "wsp.header.x_up_1.x_up_proxy_tod",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-tod", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_ba_enable,
          { "x-up-proxy-ba-enable",
            "wsp.header.x_up_1.x_up_proxy_ba_enable",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-ba-enable", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_redirect_enable,
          { "x-up-proxy-redirect-enable",
            "wsp.header.x_up_1.x_up_proxy_redirect_enable",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-redirect-enable", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_redirect_status,
          { "x-up-proxy-redirect-status",
            "wsp.header.x_up_1.x_up_proxy_redirect_status",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-redirect-status", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_linger,
          { "x-up-proxy-linger",
            "wsp.header.x_up_1.x_up_proxy_linger",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-linger", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_enable_trust,
          { "x-up-proxy-enable-trust",
            "wsp.header.x_up_1.x_up_proxy_enable_trust",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-enable-trust", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_trust,
          { "x-up-proxy-trust",
            "wsp.header.x_up_1.x_up_proxy_trust",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-trust", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_devcap_has_color,
          { "x-up-devcap-has-color",
            "wsp.header.x_up_1.x_up_devcap_has_color",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-devcap-has-color", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_devcap_num_softkeys,
          { "x-up-devcap-num-softkeys",
            "wsp.header.x_up_1.x_up_devcap_num_softkeys",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-devcap-num-softkeys", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_devcap_softkey_size,
          { "x-up-devcap-softkey-size",
            "wsp.header.x_up_1.x_up_devcap_softkey_size",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-devcap-softkey-size", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_devcap_screen_chars,
          { "x-up-devcap-screen-chars",
            "wsp.header.x_up_1.x_up_devcap_screen_chars",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-devcap-screen-chars", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_devcap_screen_pixels,
          { "x-up-devcap-screen-pixels",
            "wsp.header.x_up_1.x_up_devcap_screen_pixels",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-devcap-screen-pixels", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_devcap_em_size,
          { "x-up-devcap-em-size",
            "wsp.header.x_up_1.x_up_devcap_em_size",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-devcap-em-size", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_devcap_screen_depth,
          { "x-up-devcap-screen-depth",
            "wsp.header.x_up_1.x_up_devcap_screen_depth",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-devcap-screen-depth", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_devcap_immed_alert,
          { "x-up-devcap-immed-alert",
            "wsp.header.x_up_1.x_up_devcap_immed_alert",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-devcap-immed-alert", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_devcap_gui,
          { "x-up-devcap-gui",
            "wsp.header.x_up_1.x_up_devcap_gui",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-devcap-gui", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_trans_charset,
          { "x-up-proxy-trans-charset",
            "wsp.header.x_up_1.x_up_proxy_trans_charset",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-trans-charset", HFILL
          }
        },
        { &hf_hdr_openwave_x_up_proxy_push_accept,
          { "x-up-proxy-push-accept",
            "wsp.header.x_up_1.x_up_proxy_push_accept",
            FT_STRING, BASE_NONE, NULL, 0x00,
            "WSP Openwave header x-up-proxy-push-accept", HFILL
          }
        },

#if 0
        /* Not used for now */
           { &hf_hdr_openwave_x_up_proxy_client_id,
           {    "x-up-proxy-client-id",
           "wsp.header.x_up_1.x_up_proxy_client_id",
           FT_STRING, BASE_NONE, NULL, 0x00,
           "WSP Openwave header x-up-proxy-client-id", HFILL
           }
           },
#endif

        /*
         * Header value parameters
         */

        { &hf_parameter_q,
          {     "Q",
                "wsp.parameter.q",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Q parameter", HFILL
          }
        },
        { &hf_parameter_charset,
          {     "Charset",
                "wsp.parameter.charset",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "Charset parameter", HFILL
          }
        }
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_wsp,
        &ett_header, /* Header field subtree */
        &ett_headers, /* Subtree for WSP headers */
        &ett_content_type_header,
        &ett_wsp_parameter_type,
        &ett_capabilities, /* CO-WSP Session Capabilities */
        &ett_capabilities_entry,
        &ett_proto_option_capability, /* CO-WSP Session single Capability */
        &ett_capabilities_extended_methods,
        &ett_capabilities_header_code_pages,
        &ett_post,
        &ett_redirect_flags,
        &ett_address_flags,
        &ett_multiparts,
        &ett_mpartlist,
        &ett_addresses,     /* Addresses */
        &ett_address,       /* Single address */
        &ett_default,
        &ett_add_content_type,
        &ett_accept_x_q_header,
        &ett_push_flag,
        &ett_profile_diff_wbxml,
        &ett_allow,
        &ett_public,
        &ett_vary,
        &ett_x_wap_security,
        &ett_connection,
        &ett_transfer_encoding,
        &ett_accept_ranges,
        &ett_content_encoding,
        &ett_accept_encoding,
        &ett_content_disposition,
        &ett_text_header,
        &ett_content_id,
        &ett_text_or_date_value,
        &ett_date_value,
        &ett_tod_value,
        &ett_age,
        &ett_integer_lookup,
        &ett_challenge,
        &ett_credentials_value,
        &ett_content_md5,
        &ett_pragma,
        &ett_integer_value,
        &ett_integer_lookup_value,
        &ett_cache_control,
        &ett_warning,
        &ett_profile_warning,
        &ett_encoding_version,
        &ett_content_range,
        &ett_range,
        &ett_te_value,
        &ett_openwave_default,
    };

    static ei_register_info ei[] = {
      { &ei_wsp_capability_invalid, { "wsp.capability.invalid", PI_PROTOCOL, PI_WARN, "Invalid capability", EXPFILL }},
      { &ei_wsp_capability_length_invalid, { "wsp.capabilities.length.invalid", PI_PROTOCOL, PI_WARN, "Invalid capability length", EXPFILL }},
      { &ei_wsp_capability_encoding_invalid, { "wsp.capability_encoding.invalid", PI_PROTOCOL, PI_WARN, "Invalid capability encoding", EXPFILL }},
      { &ei_wsp_text_field_invalid, { "wsp.text_field_invalid", PI_PROTOCOL, PI_WARN, "Text field invalid", EXPFILL }},
      { &ei_wsp_invalid_parameter_value, { "wsp.invalid_parameter_value", PI_PROTOCOL, PI_WARN, "Invalid parameter value", EXPFILL }},
      { &ei_wsp_header_invalid_value, { "wsp.header_invalid_value", PI_PROTOCOL, PI_WARN, "Invalid header value", EXPFILL }},
      { &ei_hdr_x_wap_tod, { "wsp.header.x_wap_tod.not_text", PI_PROTOCOL, PI_WARN, "Should be encoded as a textual value", EXPFILL }},
      { &ei_wsp_undecoded_parameter, { "wsp.undecoded_parameter", PI_UNDECODED, PI_WARN, "Invalid parameter value", EXPFILL }},
      { &ei_wsp_trailing_quote, { "wsp.trailing_quote", PI_PROTOCOL, PI_WARN, "Quoted-string value has been encoded with a trailing quote", EXPFILL }},
      { &ei_wsp_header_invalid, { "wsp.header_invalid", PI_MALFORMED, PI_ERROR, "Malformed header", EXPFILL }},
      { &ei_wsp_oversized_uintvar, { "wsp.oversized_uintvar", PI_MALFORMED, PI_ERROR, "Uintvar is oversized", EXPFILL }}
    };

    expert_module_t* expert_wsp;

/* Register the protocol name and description */
    proto_wsp = proto_register_protocol(
        "Wireless Session Protocol",    /* protocol name for use by wireshark */
        "WSP",                          /* short version of name */
        "wsp"                           /* Abbreviated protocol name,
                                           should Match IANA:
                                           < URL:http://www.iana.org/assignments/port-numbers/ >
                                        */
        );
    wsp_tap = register_tap("wsp");
    /* Init the hash table */
/*  wsp_sessions = g_hash_table_new(
    (GHashFunc) wsp_session_hash,
    (GEqualFunc)wsp_session_equal);*/

/* Required function calls to register the header fields and subtrees used  */
    proto_register_field_array(proto_wsp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_wsp = expert_register_protocol(proto_wsp);
    expert_register_field_array(expert_wsp, ei, array_length(ei));

    register_dissector("wsp-co", dissect_wsp_fromwap_co, proto_wsp);
    register_dissector("wsp-cl", dissect_wsp_fromwap_cl, proto_wsp);
    heur_subdissector_list = register_heur_dissector_list("wsp", proto_wsp);

    wsp_fromudp_handle = create_dissector_handle(dissect_wsp_fromudp,
                                                 proto_wsp);
}

void
proto_reg_handoff_wsp(void)
{
    /*
     * Get a handle for the WTP-over-UDP and the generic media dissectors.
     */
    wtp_fromudp_handle = find_dissector_add_dependency("wtp-udp", proto_wsp);
    media_handle = find_dissector_add_dependency("media", proto_wsp);
    wbxml_uaprof_handle = find_dissector_add_dependency("wbxml-uaprof", proto_wsp);

    /* Only connection-less WSP has no previous handler */
    dissector_add_uint("udp.port", UDP_PORT_WSP, wsp_fromudp_handle);
    dissector_add_uint("udp.port", UDP_PORT_WSP_PUSH, wsp_fromudp_handle);

    /* GSM SMS UD dissector can also carry WSP */
    dissector_add_uint("gsm_sms_ud.udh.port", UDP_PORT_WSP, wsp_fromudp_handle);
    dissector_add_uint("gsm_sms_ud.udh.port", UDP_PORT_WSP_PUSH, wsp_fromudp_handle);

    /* GSM SMS dissector can also carry WSP */
    dissector_add_uint("gsm_sms.udh.port", UDP_PORT_WSP, wsp_fromudp_handle);
    dissector_add_uint("gsm_sms.udh.port", UDP_PORT_WSP_PUSH, wsp_fromudp_handle);

    /* As the media types for WSP and HTTP are the same, the WSP dissector
     * uses the same string dissector table as the HTTP protocol. */
    media_type_table = find_dissector_table("media_type");

    /* This dissector is also called from the WTP and WTLS dissectors */
}

/*
 * Session Initiation Request
 */

/* Register the protocol with Wireshark */
void
proto_register_sir(void)
{
    /* Setup list of header fields */
    static hf_register_info hf[] = {
        { &hf_sir_section,
          { "Session Initiation Request",
            "wap.sir",
            FT_NONE, BASE_NONE, NULL, 0x00,
            "Session Initiation Request content", HFILL
          }
        },
        { &hf_sir_version,
          { "Version",
            "wap.sir.version",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            "Version of the Session Initiation Request document", HFILL
          }
        },
        { &hf_sir_app_id_list_len,
          { "Application-ID List Length",
            "wap.sir.app_id_list.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "Length of the Application-ID list (bytes)", HFILL
          }
        },
        { &hf_sir_app_id_list,
          { "Application-ID List",
            "wap.sir.app_id_list",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL
          }
        },
        { &hf_sir_wsp_contact_points_len,
          { "WSP Contact Points Length",
            "wap.sir.wsp_contact_points.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "Length of the WSP Contact Points list (bytes)", HFILL
          }
        },
        { &hf_sir_wsp_contact_points,
          { "WSP Contact Points",
            "wap.sir.wsp_contact_points",
            FT_NONE, BASE_NONE, NULL, 0x00,
            "WSP Contact Points list", HFILL
          }
        },
        { &hf_sir_contact_points_len,
          { "Non-WSP Contact Points Length",
            "wap.sir.contact_points.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "Length of the Non-WSP Contact Points list (bytes)", HFILL
          }
        },
        { &hf_sir_contact_points,
          { "Non-WSP Contact Points",
            "wap.sir.contact_points",
            FT_NONE, BASE_NONE, NULL, 0x00,
            "Non-WSP Contact Points list", HFILL
          }
        },
        { &hf_sir_protocol_options_len,
          { "Protocol Options List Entries",
            "wap.sir.protocol_options.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "Number of entries in the Protocol Options list", HFILL
          }
        },
        { &hf_sir_protocol_options,
          { "Protocol Options",
            "wap.sir.protocol_options",
            FT_UINT16, BASE_DEC, VALS(vals_sir_protocol_options), 0x00,
            "Protocol Options list", HFILL
          }
        },
        { &hf_sir_prov_url_len,
          {     "X-Wap-ProvURL Length",
                "wap.sir.prov_url.length",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "Length of the X-Wap-ProvURL (Identifies the WAP Client Provisioning Context)", HFILL
          }
        },
        { &hf_sir_prov_url,
          {     "X-Wap-ProvURL",
                "wap.sir.prov_url",
                FT_STRING, BASE_NONE, NULL, 0x00,
                "X-Wap-ProvURL (Identifies the WAP Client Provisioning Context)", HFILL
          }
        },
        { &hf_sir_cpi_tag_len,
          { "CPITag List Entries",
            "wap.sir.cpi_tag.length",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            "Number of entries in the CPITag list", HFILL
          }
        },
        { &hf_sir_cpi_tag,
          { "CPITag",
            "wap.sir.cpi_tag",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            "CPITag (OTA-HTTP)", HFILL
          }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_sir            /* Session Initiation Request */
    };

    static tap_param wsp_stat_params[] = {
        { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
    };

    static stat_tap_table_ui wsp_stat_table = {
        REGISTER_STAT_GROUP_TELEPHONY,
        "WAP-WSP Packet Counter",
        "wsp",
        "wsp,stat",
        wsp_stat_init,
        wsp_stat_packet,
        wsp_stat_reset,
        wsp_stat_free_table_item,
        NULL,
        sizeof(wsp_stat_fields)/sizeof(stat_tap_table_item), wsp_stat_fields,
        sizeof(wsp_stat_params)/sizeof(tap_param), wsp_stat_params,
        NULL,
        0
    };


    /* Register the dissector */
    proto_sir = proto_register_protocol(
        "WAP Session Initiation Request",   /* protocol name for use by wireshark */
        "WAP SIR",                          /* short version of name */
        "wap-sir"                           /* Abbreviated protocol name,
                                               should Match IANA:
                                               < URL:http://www.iana.org/assignments/port-numbers/ >
                                            */
        );

    /* Register header fields and protocol subtrees */
    proto_register_field_array(proto_sir, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_stat_tap_table_ui(&wsp_stat_table);

}

void
proto_reg_handoff_sir(void)
{
    dissector_handle_t sir_handle;

    sir_handle = create_dissector_handle(dissect_sir, proto_sir);

    /* Add dissector bindings for SIR dissection */
    dissector_add_string("media_type", "application/vnd.wap.sia", sir_handle);
}



/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
