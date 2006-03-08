/* packet-wsp.c
 *
 * Routines to dissect WSP component of WAP traffic.
 *
 * $Id$
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* Edit with a 4-space tabulation */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include "packet-wap.h"
#include "packet-wsp.h"

/* General-purpose debug logger.
 * Requires double parentheses because of variable arguments of printf().
 *
 * Enable debug logging for WSP by defining AM_CFLAGS
 * so that it contains "-DDEBUG_wsp"
 */
#ifdef DEBUG_wsp
#define DebugLog(x) \
	g_print("%s:%u: ", __FILE__, __LINE__); \
	g_print x
#else
#define DebugLog(x) ;
#endif

/* Statistics (see doc/README.tapping) */
#include <epan/tap.h>
static int wsp_tap = -1;


/* File scoped variables for the protocol and registered fields */
static int proto_wsp 					= HF_EMPTY;
static int proto_sir 					= HF_EMPTY;

/*
 * Initialize the header field pointers
 */

/* WSP header fields and their subfields if available */
static int hf_hdr_name					= HF_EMPTY;
static int hf_hdr_accept				= HF_EMPTY;
static int hf_hdr_accept_charset		= HF_EMPTY;
static int hf_hdr_accept_encoding		= HF_EMPTY;
static int hf_hdr_accept_language		= HF_EMPTY;
static int hf_hdr_accept_ranges			= HF_EMPTY;
static int hf_hdr_age					= HF_EMPTY;
static int hf_hdr_allow					= HF_EMPTY;
static int hf_hdr_authorization			= HF_EMPTY;
static int hf_hdr_authorization_scheme			= HF_EMPTY; /* Subfield */
static int hf_hdr_authorization_user_id			= HF_EMPTY; /* Subfield */
static int hf_hdr_authorization_password		= HF_EMPTY; /* Subfield */
static int hf_hdr_cache_control			= HF_EMPTY;
static int hf_hdr_connection			= HF_EMPTY;
static int hf_hdr_content_base			= HF_EMPTY;
static int hf_hdr_content_encoding		= HF_EMPTY;
static int hf_hdr_content_language		= HF_EMPTY;
static int hf_hdr_content_length		= HF_EMPTY;
static int hf_hdr_content_location		= HF_EMPTY;
static int hf_hdr_content_md5			= HF_EMPTY;
static int hf_hdr_content_range			= HF_EMPTY;
static int hf_hdr_content_range_first_byte_pos	= HF_EMPTY; /* Subfield */
static int hf_hdr_content_range_entity_length	= HF_EMPTY; /* Subfield */
static int hf_hdr_content_type			= HF_EMPTY;
static int hf_hdr_date					= HF_EMPTY;
static int hf_hdr_etag					= HF_EMPTY;
static int hf_hdr_expires				= HF_EMPTY;
static int hf_hdr_from					= HF_EMPTY;
static int hf_hdr_host					= HF_EMPTY;
static int hf_hdr_if_modified_since		= HF_EMPTY;
static int hf_hdr_if_match				= HF_EMPTY;
static int hf_hdr_if_none_match			= HF_EMPTY;
static int hf_hdr_if_range				= HF_EMPTY;
static int hf_hdr_if_unmodified_since	= HF_EMPTY;
static int hf_hdr_last_modified			= HF_EMPTY;
static int hf_hdr_location				= HF_EMPTY;
static int hf_hdr_max_forwards			= HF_EMPTY;
static int hf_hdr_pragma				= HF_EMPTY;
static int hf_hdr_proxy_authenticate	= HF_EMPTY;
static int hf_hdr_proxy_authenticate_scheme		= HF_EMPTY; /* Subfield */
static int hf_hdr_proxy_authenticate_realm		= HF_EMPTY; /* Subfield */
static int hf_hdr_proxy_authorization	= HF_EMPTY;
static int hf_hdr_proxy_authorization_scheme	= HF_EMPTY; /* Subfield */
static int hf_hdr_proxy_authorization_user_id	= HF_EMPTY; /* Subfield */
static int hf_hdr_proxy_authorization_password	= HF_EMPTY; /* Subfield */
static int hf_hdr_public				= HF_EMPTY;
static int hf_hdr_range					= HF_EMPTY;
static int hf_hdr_range_first_byte_pos			= HF_EMPTY; /* Subfield */
static int hf_hdr_range_last_byte_pos			= HF_EMPTY; /* Subfield */
static int hf_hdr_range_suffix_length			= HF_EMPTY; /* Subfield */
static int hf_hdr_referer				= HF_EMPTY;
static int hf_hdr_retry_after			= HF_EMPTY;
static int hf_hdr_server				= HF_EMPTY;
static int hf_hdr_transfer_encoding		= HF_EMPTY;
static int hf_hdr_upgrade				= HF_EMPTY;
static int hf_hdr_user_agent			= HF_EMPTY;
static int hf_hdr_vary					= HF_EMPTY;
static int hf_hdr_via					= HF_EMPTY;
static int hf_hdr_warning				= HF_EMPTY;
static int hf_hdr_warning_code					= HF_EMPTY; /* Subfield */
static int hf_hdr_warning_agent					= HF_EMPTY; /* Subfield */
static int hf_hdr_warning_text					= HF_EMPTY; /* Subfield */
static int hf_hdr_www_authenticate		= HF_EMPTY;
static int hf_hdr_www_authenticate_scheme		= HF_EMPTY; /* Subfield */
static int hf_hdr_www_authenticate_realm		= HF_EMPTY; /* Subfield */
static int hf_hdr_content_disposition	= HF_EMPTY;
static int hf_hdr_application_id		= HF_EMPTY;
static int hf_hdr_content_uri			= HF_EMPTY;
static int hf_hdr_initiator_uri			= HF_EMPTY;
static int hf_hdr_bearer_indication		= HF_EMPTY;
static int hf_hdr_push_flag				= HF_EMPTY;
static int hf_hdr_push_flag_auth				= HF_EMPTY; /* Subfield */
static int hf_hdr_push_flag_trust				= HF_EMPTY; /* Subfield */
static int hf_hdr_push_flag_last				= HF_EMPTY; /* Subfield */
static int hf_hdr_profile				= HF_EMPTY;
static int hf_hdr_profile_diff			= HF_EMPTY;
static int hf_hdr_profile_warning		= HF_EMPTY;
static int hf_hdr_expect				= HF_EMPTY;
static int hf_hdr_te					= HF_EMPTY;
static int hf_hdr_trailer				= HF_EMPTY;
static int hf_hdr_x_wap_tod				= HF_EMPTY;
static int hf_hdr_content_id			= HF_EMPTY;
static int hf_hdr_set_cookie			= HF_EMPTY;
static int hf_hdr_cookie				= HF_EMPTY;
static int hf_hdr_encoding_version		= HF_EMPTY;
static int hf_hdr_x_wap_security		= HF_EMPTY;
static int hf_hdr_x_wap_application_id	= HF_EMPTY;
static int hf_hdr_accept_application	= HF_EMPTY;


/* Openwave headers */
static int hf_hdr_openwave_x_up_proxy_operator_domain	= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_home_page			= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_uplink_version	= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_ba_realm			= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_request_uri		= HF_EMPTY;
#if 0
static int hf_hdr_openwave_x_up_proxy_client_id			= HF_EMPTY;
#endif
static int hf_hdr_openwave_x_up_proxy_bookmark			= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_push_seq			= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_notify			= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_net_ask			= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_tod				= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_ba_enable			= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_redirect_enable	= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_redirect_status	= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_linger			= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_enable_trust		= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_trust				= HF_EMPTY;
static int hf_hdr_openwave_x_up_devcap_has_color		= HF_EMPTY;
static int hf_hdr_openwave_x_up_devcap_num_softkeys		= HF_EMPTY;
static int hf_hdr_openwave_x_up_devcap_softkey_size		= HF_EMPTY;
static int hf_hdr_openwave_x_up_devcap_screen_chars		= HF_EMPTY;
static int hf_hdr_openwave_x_up_devcap_screen_pixels	= HF_EMPTY;
static int hf_hdr_openwave_x_up_devcap_em_size			= HF_EMPTY;
static int hf_hdr_openwave_x_up_devcap_screen_depth		= HF_EMPTY;
static int hf_hdr_openwave_x_up_devcap_immed_alert		= HF_EMPTY;
static int hf_hdr_openwave_x_up_devcap_gui				= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_trans_charset		= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_push_accept		= HF_EMPTY;


/* WSP parameter fields */
static int hf_parameter_q					= HF_EMPTY;
static int hf_parameter_charset				= HF_EMPTY;
#if 0
static int hf_parameter_textual				= HF_EMPTY;
static int hf_parameter_type				= HF_EMPTY;
static int hf_parameter_name				= HF_EMPTY;
static int hf_parameter_filename			= HF_EMPTY;
static int hf_parameter_start				= HF_EMPTY;
static int hf_parameter_start_info			= HF_EMPTY;
static int hf_parameter_comment				= HF_EMPTY;
static int hf_parameter_domain				= HF_EMPTY;
static int hf_parameter_path				= HF_EMPTY;
static int hf_parameter_sec					= HF_EMPTY;
static int hf_parameter_mac					= HF_EMPTY;
static int hf_parameter_upart_type			= HF_EMPTY;
static int hf_parameter_upart_type_value	= HF_EMPTY;
static int hf_parameter_level				= HF_EMPTY;
#endif

/* Old header fields */

static int hf_wsp_header_tid				= HF_EMPTY;
static int hf_wsp_header_pdu_type			= HF_EMPTY;
static int hf_wsp_version_major				= HF_EMPTY;
static int hf_wsp_version_minor				= HF_EMPTY;
/* Session capabilities (CO-WSP) */
static int hf_capabilities_length		= HF_EMPTY;
static int hf_capabilities_section		= HF_EMPTY;
static int hf_capa_client_sdu_size		= HF_EMPTY;
static int hf_capa_server_sdu_size		= HF_EMPTY;
static int hf_capa_protocol_options		= HF_EMPTY;
static int hf_capa_protocol_option_confirmed_push		= HF_EMPTY; /* Subfield */
static int hf_capa_protocol_option_push					= HF_EMPTY; /* Subfield */
static int hf_capa_protocol_option_session_resume		= HF_EMPTY; /* Subfield */
static int hf_capa_protocol_option_ack_headers			= HF_EMPTY; /* Subfield */
static int hf_capa_protocol_option_large_data_transfer	= HF_EMPTY; /* Subfield */
static int hf_capa_method_mor			= HF_EMPTY;
static int hf_capa_push_mor				= HF_EMPTY;
static int hf_capa_extended_methods		= HF_EMPTY;
static int hf_capa_header_code_pages	= HF_EMPTY;
static int hf_capa_aliases				= HF_EMPTY;
static int hf_capa_client_message_size	= HF_EMPTY;
static int hf_capa_server_message_size	= HF_EMPTY;

static int hf_wsp_header_uri_len			= HF_EMPTY;
static int hf_wsp_header_uri				= HF_EMPTY;
static int hf_wsp_server_session_id			= HF_EMPTY;
static int hf_wsp_header_status				= HF_EMPTY;
static int hf_wsp_header_length				= HF_EMPTY;
static int hf_wsp_headers_section			= HF_EMPTY;
static int hf_wsp_parameter_type			= HF_EMPTY;
static int hf_wsp_parameter_name			= HF_EMPTY;
static int hf_wsp_parameter_filename			= HF_EMPTY;
static int hf_wsp_parameter_start			= HF_EMPTY;
static int hf_wsp_parameter_start_info			= HF_EMPTY;
static int hf_wsp_parameter_comment			= HF_EMPTY;
static int hf_wsp_parameter_domain			= HF_EMPTY;
static int hf_wsp_parameter_path			= HF_EMPTY;
static int hf_wsp_parameter_sec			= HF_EMPTY;
static int hf_wsp_parameter_mac			= HF_EMPTY;
static int hf_wsp_parameter_upart_type			= HF_EMPTY;
static int hf_wsp_parameter_level			= HF_EMPTY;
static int hf_wsp_parameter_size			= HF_EMPTY;
static int hf_wsp_reply_data				= HF_EMPTY;
static int hf_wsp_post_data				= HF_EMPTY;
static int hf_wsp_push_data				= HF_EMPTY;
static int hf_wsp_multipart_data			= HF_EMPTY;
static int hf_wsp_mpart					= HF_EMPTY;

/* Header code page shift sequence */
static int hf_wsp_header_shift_code			= HF_EMPTY;

/* WSP Redirect fields */
static int hf_wsp_redirect_flags					= HF_EMPTY;
static int hf_wsp_redirect_permanent				= HF_EMPTY;
static int hf_wsp_redirect_reuse_security_session	= HF_EMPTY;
static int hf_redirect_addresses					= HF_EMPTY;

/* Address fields */
static int hf_address_entry				= HF_EMPTY;
static int hf_address_flags_length		= HF_EMPTY;
static int hf_address_flags_length_bearer_type_included	= HF_EMPTY; /* Subfield */
static int hf_address_flags_length_port_number_included	= HF_EMPTY; /* Subfield */
static int hf_address_flags_length_address_len			= HF_EMPTY; /* Subfield */
static int hf_address_bearer_type		= HF_EMPTY;
static int hf_address_port_num			= HF_EMPTY;
static int hf_address_ipv4_addr			= HF_EMPTY;
static int hf_address_ipv6_addr			= HF_EMPTY;
static int hf_address_addr				= HF_EMPTY;

/* Session Initiation Request fields */
static int hf_sir_section					= HF_EMPTY;
static int hf_sir_version					= HF_EMPTY;
static int hf_sir_app_id_list_len			= HF_EMPTY;
static int hf_sir_app_id_list				= HF_EMPTY;
static int hf_sir_wsp_contact_points_len	= HF_EMPTY;
static int hf_sir_wsp_contact_points		= HF_EMPTY;
static int hf_sir_contact_points_len		= HF_EMPTY;
static int hf_sir_contact_points			= HF_EMPTY;
static int hf_sir_protocol_options_len		= HF_EMPTY;
static int hf_sir_protocol_options			= HF_EMPTY;
static int hf_sir_prov_url_len				= HF_EMPTY;
static int hf_sir_prov_url					= HF_EMPTY;
static int hf_sir_cpi_tag_len				= HF_EMPTY;
static int hf_sir_cpi_tag					= HF_EMPTY;

/*
 * Initialize the subtree pointers
 */

/* WSP tree */
static int ett_wsp 						= ETT_EMPTY;
/* WSP headers tree */
static int ett_header 					= ETT_EMPTY;
/* WSP header subtree */
static int ett_headers					= ETT_EMPTY;
/* CO-WSP session capabilities */
static int ett_capabilities				= ETT_EMPTY;
static int ett_capability				= ETT_EMPTY;
static int ett_post						= ETT_EMPTY;
static int ett_redirect_flags			= ETT_EMPTY;
static int ett_address_flags			= ETT_EMPTY;
static int ett_multiparts				= ETT_EMPTY;
static int ett_mpartlist				= ETT_EMPTY;
/* Session Initiation Request tree */
static int ett_sir						= ETT_EMPTY;
static int ett_addresses				= ETT_EMPTY;
static int ett_address					= ETT_EMPTY;



/* Handle for WSP-over-UDP dissector */
static dissector_handle_t wsp_fromudp_handle;

/* Handle for WTP-over-UDP dissector */
static dissector_handle_t wtp_fromudp_handle;

/* Handle for generic media dissector */
static dissector_handle_t media_handle;

/* Handle for WBXML-encoded UAPROF dissector */
static dissector_handle_t wbxml_uaprof_handle;

const value_string vals_pdu_type[] = {
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

/* The WSP status codes are inherited from the HTTP status codes */
const value_string vals_status[] = {
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

const value_string vals_wsp_reason_codes[] = {
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

/*
 * Field names.
 */
#define FN_ACCEPT		0x00
#define FN_ACCEPT_CHARSET_DEP	0x01	/* encoding version 1.1, deprecated */
#define FN_ACCEPT_ENCODING_DEP	0x02	/* encoding version 1.1, deprecated */
#define FN_ACCEPT_LANGUAGE	0x03
#define FN_ACCEPT_RANGES	0x04
#define FN_AGE			0x05
#define FN_ALLOW		0x06
#define FN_AUTHORIZATION	0x07
#define FN_CACHE_CONTROL_DEP	0x08	/* encoding version 1.1, deprecated */
#define FN_CONNECTION		0x09
#define FN_CONTENT_BASE		0x0A
#define FN_CONTENT_ENCODING	0x0B
#define FN_CONTENT_LANGUAGE	0x0C
#define FN_CONTENT_LENGTH	0x0D
#define FN_CONTENT_LOCATION	0x0E
#define FN_CONTENT_MD5		0x0F
#define FN_CONTENT_RANGE_DEP	0x10	/* encoding version 1.1, deprecated */
#define FN_CONTENT_TYPE		0x11
#define FN_DATE			0x12
#define FN_ETAG			0x13
#define FN_EXPIRES		0x14
#define FN_FROM			0x15
#define FN_HOST			0x16
#define FN_IF_MODIFIED_SINCE	0x17
#define FN_IF_MATCH		0x18
#define FN_IF_NONE_MATCH	0x19
#define FN_IF_RANGE		0x1A
#define FN_IF_UNMODIFIED_SINCE	0x1B
#define FN_LOCATION		0x1C
#define FN_LAST_MODIFIED	0x1D
#define FN_MAX_FORWARDS		0x1E
#define FN_PRAGMA		0x1F
#define FN_PROXY_AUTHENTICATE	0x20
#define FN_PROXY_AUTHORIZATION	0x21
#define FN_PUBLIC		0x22
#define FN_RANGE		0x23
#define FN_REFERER		0x24
#define FN_RETRY_AFTER		0x25
#define FN_SERVER		0x26
#define FN_TRANSFER_ENCODING	0x27
#define FN_UPGRADE		0x28
#define FN_USER_AGENT		0x29
#define FN_VARY			0x2A
#define FN_VIA			0x2B
#define FN_WARNING		0x2C
#define FN_WWW_AUTHENTICATE	0x2D
#define FN_CONTENT_DISPOSITION	0x2E
#define FN_X_WAP_APPLICATION_ID	0x2F
#define FN_X_WAP_CONTENT_URI	0x30
#define FN_X_WAP_INITIATOR_URI	0x31
#define FN_ACCEPT_APPLICATION	0x32
#define FN_BEARER_INDICATION	0x33
#define FN_PUSH_FLAG		0x34
#define FN_PROFILE		0x35
#define FN_PROFILE_DIFF		0x36
#define FN_PROFILE_WARNING	0x37
#define FN_EXPECT		0x38
#define FN_TE			0x39
#define FN_TRAILER		0x3A
#define FN_ACCEPT_CHARSET	0x3B	/* encoding version 1.3 */
#define FN_ACCEPT_ENCODING	0x3C	/* encoding version 1.3 */
#define FN_CACHE_CONTROL	0x3D	/* encoding version 1.3 */
#define FN_CONTENT_RANGE	0x3E	/* encoding version 1.3 */
#define FN_X_WAP_TOD		0x3F
#define FN_CONTENT_ID		0x40
#define FN_SET_COOKIE		0x41
#define FN_COOKIE		0x42
#define FN_ENCODING_VERSION	0x43
#define FN_PROFILE_WARNING14	0x44	/* encoding version 1.4 */
#define FN_CONTENT_DISPOSITION14	0x45	/* encoding version 1.4 */
#define FN_X_WAP_SECURITY	0x46
#define FN_CACHE_CONTROL14	0x47	/* encoding version 1.4 */
#define FN_EXPECT15 0x48	/* encoding version 1.5 */
#define FN_X_WAP_LOC_INVOCATION 0x49
#define FN_X_WAP_LOC_DELIVERY 0x4A


/*
 * Openwave field names.
 */
#define FN_OPENWAVE_PROXY_PUSH_ADDR		0x00
#define FN_OPENWAVE_PROXY_PUSH_ACCEPT		0x01
#define FN_OPENWAVE_PROXY_PUSH_SEQ		0x02
#define FN_OPENWAVE_PROXY_NOTIFY		0x03
#define FN_OPENWAVE_PROXY_OPERATOR_DOMAIN	0x04
#define FN_OPENWAVE_PROXY_HOME_PAGE		0x05
#define FN_OPENWAVE_DEVCAP_HAS_COLOR		0x06
#define FN_OPENWAVE_DEVCAP_NUM_SOFTKEYS		0x07
#define FN_OPENWAVE_DEVCAP_SOFTKEY_SIZE		0x08
#define FN_OPENWAVE_DEVCAP_SCREEN_CHARS		0x09
#define FN_OPENWAVE_DEVCAP_SCREEN_PIXELS	0x0A
#define FN_OPENWAVE_DEVCAP_EM_SIZE		0x0B
#define FN_OPENWAVE_DEVCAP_SCREEN_DEPTH		0x0C
#define FN_OPENWAVE_DEVCAP_IMMED_ALERT		0x0D
#define FN_OPENWAVE_PROXY_NET_ASK		0x0E
#define FN_OPENWAVE_PROXY_UPLINK_VERSION	0x0F
#define FN_OPENWAVE_PROXY_TOD			0x10
#define FN_OPENWAVE_PROXY_BA_ENABLE		0x11
#define FN_OPENWAVE_PROXY_BA_REALM		0x12
#define FN_OPENWAVE_PROXY_REDIRECT_ENABLE	0x13
#define FN_OPENWAVE_PROXY_REQUEST_URI		0x14
#define FN_OPENWAVE_PROXY_REDIRECT_STATUS	0x15
#define FN_OPENWAVE_PROXY_TRANS_CHARSET		0x16
#define FN_OPENWAVE_PROXY_LINGER		0x17
#define FN_OPENWAVE_PROXY_CLIENT_ID		0x18
#define FN_OPENWAVE_PROXY_ENABLE_TRUST		0x19
#define FN_OPENWAVE_PROXY_TRUST_OLD		0x1A
#define FN_OPENWAVE_PROXY_TRUST			0x20
#define FN_OPENWAVE_PROXY_BOOKMARK		0x21
#define FN_OPENWAVE_DEVCAP_GUI			0x22

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

/*
 * Bearer types (from the WDP specification).
 */
#define BT_IPv4			0x00
#define BT_IPv6			0x01
#define BT_GSM_USSD		0x02
#define BT_GSM_SMS		0x03
#define BT_ANSI_136_GUTS	0x04
#define BT_IS_95_SMS		0x05
#define BT_IS_95_CSD		0x06
#define BT_IS_95_PACKET_DATA	0x07
#define BT_ANSI_136_CSD		0x08
#define BT_ANSI_136_PACKET_DATA	0x09
#define BT_GSM_CSD		0x0A
#define BT_GSM_GPRS		0x0B
#define BT_GSM_USSD_IPv4	0x0C
#define BT_AMPS_CDPD		0x0D
#define BT_PDC_CSD		0x0E
#define BT_PDC_PACKET_DATA	0x0F
#define BT_IDEN_SMS		0x10
#define BT_IDEN_CSD		0x11
#define BT_IDEN_PACKET_DATA	0x12
#define BT_PAGING_FLEX		0x13
#define BT_PHS_SMS		0x14
#define BT_PHS_CSD		0x15
#define BT_GSM_USSD_GSM_SC	0x16
#define BT_TETRA_SDS_ITSI	0x17
#define BT_TETRA_SDS_MSISDN	0x18
#define BT_TETRA_PACKET_DATA	0x19
#define BT_PAGING_REFLEX	0x1A
#define BT_GSM_USSD_MSISDN	0x1B
#define BT_MOBITEX_MPAK		0x1C
#define BT_ANSI_136_GHOST	0x1D

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

static const value_string vals_content_types[] = {
	/* Well-known media types */
	{ 0x00, "*/*" },
	{ 0x01, "text/*" },
	{ 0x02, "text/html" },
	{ 0x03, "text/plain" },
	{ 0x04, "text/x-hdml" },
	{ 0x05, "text/x-ttml" },
	{ 0x06, "text/x-vCalendar" },
	{ 0x07, "text/x-vCard" },
	{ 0x08, "text/vnd.wap.wml" },
	{ 0x09, "text/vnd.wap.wmlscript" },
	{ 0x0A, "text/vnd.wap.channel" },
	{ 0x0B, "multipart/*" },
	{ 0x0C, "multipart/mixed" },
	{ 0x0D, "multipart/form-data" },
	{ 0x0E, "multipart/byteranges" },
	{ 0x0F, "multipart/alternative" },
	{ 0x10, "application/*" },
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
	{ 0x1C, "image/*" },
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

static const value_string vals_languages[] = {
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


#define CACHE_CONTROL_NO_CACHE			0x00
#define CACHE_CONTROL_NO_STORE			0x01
#define CACHE_CONTROL_MAX_AGE			0x02
#define CACHE_CONTROL_MAX_STALE			0x03
#define CACHE_CONTROL_MIN_FRESH			0x04
#define CACHE_CONTROL_ONLY_IF_CACHED	0x05
#define CACHE_CONTROL_PUBLIC			0x06
#define CACHE_CONTROL_PRIVATE			0x07
#define CACHE_CONTROL_NO_TRANSFORM		0x08
#define CACHE_CONTROL_MUST_REVALIDATE	0x09
#define CACHE_CONTROL_PROXY_REVALIDATE	0x0A
#define CACHE_CONTROL_S_MAXAGE			0x0B

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

static const value_string vals_wap_application_ids[] = {
	/* Well-known WAP applications */
	{ 0x00, "x-wap-application:*"},
	{ 0x01, "x-wap-application:push.sia"},
	{ 0x02, "x-wap-application:wml.ua"},
	{ 0x03, "x-wap-application:wta.ua"},
	{ 0x04, "x-wap-application:mms.ua"},
	{ 0x05, "x-wap-application:push.syncml"},
	{ 0x06, "x-wap-application:loc.ua"},
	{ 0x07, "x-wap-application:syncml.dm"},
	{ 0x08, "x-wap-application:drm.ua"},
	{ 0x09, "x-wap-application:emn.ua"},
	{ 0x0A, "x-wap-application:wv.ua"},
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


/* Parameters and well-known encodings */
static const value_string vals_wsp_parameter_sec[] = {
	{ 0x00,	"NETWPIN" },
	{ 0x01,	"USERPIN" },
	{ 0x02,	"USERNETWPIN" },
	{ 0x03,	"USERPINMAC" },

	{ 0x00, NULL }
};

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

static const value_string vals_wsp_warning_code_short[] = {
	{ 10, "110" },
	{ 11, "111" },
	{ 12, "112" },
	{ 13, "113" },
	{ 14, "214" },
	{ 99, "199/299" },

	{ 0, NULL }
};

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

/* Well-known TE values */
static const value_string vals_well_known_te[] = {
	{ 0x82, "chunked" },
	{ 0x83, "identity" },
	{ 0x84, "gzip" },
	{ 0x85, "compress" },
	{ 0x86, "deflate" },

	{ 0x00, NULL }
};


/*
 * Redirect flags.
 */
#define PERMANENT_REDIRECT		0x80
#define REUSE_SECURITY_SESSION	0x40

/*
 * Redirect address flags and length.
 */
#define BEARER_TYPE_INCLUDED	0x80
#define PORT_NUMBER_INCLUDED	0x40
#define ADDRESS_LEN				0x3f

static const true_false_string yes_no_truth = {
	"Yes" ,
	"No"
};

static const value_string vals_false_true[] = {
	{ 0, "False" },
	{ 1, "True" },
	{ 0, NULL },
};

enum {
	WSP_PDU_RESERVED		= 0x00,
	WSP_PDU_CONNECT			= 0x01,
	WSP_PDU_CONNECTREPLY		= 0x02,
	WSP_PDU_REDIRECT		= 0x03,			/* No sample data */
	WSP_PDU_REPLY			= 0x04,
	WSP_PDU_DISCONNECT		= 0x05,
	WSP_PDU_PUSH			= 0x06,			/* No sample data */
	WSP_PDU_CONFIRMEDPUSH		= 0x07,			/* No sample data */
	WSP_PDU_SUSPEND			= 0x08,			/* No sample data */
	WSP_PDU_RESUME			= 0x09,			/* No sample data */

	WSP_PDU_GET			= 0x40,
	WSP_PDU_OPTIONS			= 0x41,			/* No sample data */
	WSP_PDU_HEAD			= 0x42,			/* No sample data */
	WSP_PDU_DELETE			= 0x43,			/* No sample data */
	WSP_PDU_TRACE			= 0x44,			/* No sample data */

	WSP_PDU_POST			= 0x60,
	WSP_PDU_PUT			= 0x61			/* No sample data */
};


/* Dissector tables for handoff */
static dissector_table_t media_type_table;
static heur_dissector_list_t heur_subdissector_list;

static void add_uri (proto_tree *, packet_info *, tvbuff_t *, guint, guint, proto_item *);

static void add_post_variable (proto_tree *, tvbuff_t *, guint, guint, guint, guint);
static void add_multipart_data (proto_tree *, tvbuff_t *, packet_info *pinfo);

static void add_capabilities (proto_tree *tree, tvbuff_t *tvb, guint8 pdu_type);


/*
 * Dissect the WSP header part.
 * This function calls wkh_XXX functions that dissect well-known headers.
 */
static void add_headers (proto_tree *tree, tvbuff_t *tvb, int hf, packet_info *pinfo);

/* The following macros define WSP basic data structures as found
 * in the ABNF notation of WSP headers.
 * Currently all text data types are mapped to text_string.
 */
#define is_short_integer(x)		( (x) & 0x80 )
#define is_long_integer(x)		( (x) <= 30 )
#define is_date_value(x)		is_long_integer(x)
#define is_integer_value(x)		(is_short_integer(x) || is_long_integer(x))
#define is_delta_seconds_value(x)	is_integer_value(x)
/* Text string == *TEXT 0x00, thus also an empty string matches the rule! */
#define is_text_string(x)	( ((x) == 0) || ( ((x) >= 32) && ((x) <= 127)) )
#define is_quoted_string(x)		( (x) == 0x22 ) /* " */
#define is_token_text(x)		is_text_string(x)
#define is_text_value(x)		is_text_string(x)
#define is_uri_value(x)			is_text_string(x)

#define get_uintvar_integer(val,tvb,start,len,ok) \
	val = tvb_get_guintvar(tvb,start,&len); \
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

/* NOTE - Don't forget to g_free() the str value after its usage as the
 * tvb_get_stringz() functions return g_malloc()ed memory! */
#define get_text_string(str,tvb,start,len,ok) \
	if (is_text_string(tvb_get_guint8(tvb,start))) { \
		str = (gchar *)tvb_get_stringz(tvb,start,(gint *)&len); \
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
		str = g_strdup_printf("%u.%u", val >> 4, val & 0x0F); \
	} else { get_text_string(str,tvb,start,len,ok); }

/* Parameter parser */
static int
parameter (proto_tree *tree, proto_item *ti, tvbuff_t *tvb, int start, int len);
static int
parameter_value_q (proto_tree *tree, proto_item *ti, tvbuff_t *tvb, int start);

#define InvalidValueForHeader(hdr) \
	"<Error: Invalid value for the '" hdr "' header>"
#define InvalidTextualHeader \
	"<Error: Invalid zero-length textual header>"
#define TrailingQuoteWarning \
	" <Warning: Quoted-string value has been encoded with a trailing quote>"

/* WSP well-known header parsing function prototypes;
 * will be listed in the function lookup table WellKnownHeaders[] */
static guint32 wkh_default (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_accept (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_content_type (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_accept_charset (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_accept_language (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_connection (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_push_flag (proto_tree *tree, tvbuff_t *tvb,
		guint32 header_start, packet_info *pinfo _U_);
static guint32 wkh_vary (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_accept_ranges (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_content_disposition (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_accept_encoding (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_content_encoding (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_transfer_encoding (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_pragma (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Single short-integer value */
static guint32 wkh_x_wap_security (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Text */
static guint32 wkh_content_base (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_content_location (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_etag (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_from (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_host (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_if_match (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_if_none_match (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_location (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_referer (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_server (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_user_agent (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_upgrade (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_via (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_content_uri (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_initiator_uri (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_profile (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_content_id (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Date-value or text */
static guint32 wkh_if_range (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Date-value */
static guint32 wkh_date (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_expires (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_if_modified_since (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_if_unmodified_since (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_last_modified (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Date-value with special meaning */
static guint32 wkh_x_wap_tod (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Delta-seconds-value */
static guint32 wkh_age (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Challenge */
static guint32 wkh_proxy_authenticate (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_www_authenticate (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Credentials */
static guint32 wkh_authorization (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_proxy_authorization (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Pragma */
static guint32 wkh_pragma (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Integer-value */
static guint32 wkh_content_length (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_max_forwards (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);

/* Integer lookup value */
static guint32 wkh_bearer_indication (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);

/* WAP application ID value */
static guint32 wkh_x_wap_application_id (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_accept_application (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_content_language (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);

/* Allow and Public */
static guint32 wkh_allow(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_public(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);

/* Cache-control */
static guint32 wkh_cache_control (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Warning */
static guint32 wkh_warning (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Profile-warning */
static guint32 wkh_profile_warning (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);

/* Content-MD5 */
static guint32 wkh_content_md5 (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);

/* WSP encoding version */
static guint32 wkh_encoding_version (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);

/* Content-Range and Range */
static guint32 wkh_content_range (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_range (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);

/* TE */
static guint32 wkh_te (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);

/* Header value */
static guint32 wkh_trailer (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);

/* Profile-Diff with WBXML UAPROF document */
static guint32 wkh_profile_diff_wbxml (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo);

/* TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
static guint32 wkh_retry_after (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_expect (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_set_cookie (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_cookie (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
*/


/* WSP well-known Openwave header parsing function prototypes;
 * will be listed in the function lookup table WellKnownOpenwaveHeaders[] */
static guint32 wkh_openwave_default (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_);
/* Textual headers */
static guint32 wkh_openwave_x_up_proxy_operator_domain(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_home_page(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_uplink_version(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_ba_realm(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_request_uri(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_bookmark(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
/* Integer headers */
static guint32 wkh_openwave_x_up_proxy_push_seq(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_notify(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_net_ask(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_tod (proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_ba_enable(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_redirect_enable(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_redirect_status(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_linger(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_enable_trust(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_trust(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_devcap_has_color(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_devcap_num_softkeys(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_devcap_softkey_size(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_devcap_screen_chars(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_devcap_screen_pixels(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_devcap_em_size(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_devcap_screen_depth(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_devcap_immed_alert(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_devcap_gui(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);

static guint32 wkh_openwave_x_up_proxy_trans_charset(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);
static guint32 wkh_openwave_x_up_proxy_push_accept(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_);


/* Define a pointer to function data type for the well-known header
 * lookup table below */
typedef guint32 (*hdr_parse_func_ptr) (proto_tree *, tvbuff_t *, guint32, packet_info *);

/* Lookup table for well-known header parsing functions */
static const hdr_parse_func_ptr WellKnownHeader[128] = {
	/* 0x00 */	wkh_accept,				/* 0x01 */	wkh_accept_charset,
	/* 0x02 */	wkh_accept_encoding,	/* 0x03 */	wkh_accept_language,
	/* 0x04 */	wkh_accept_ranges,		/* 0x05 */	wkh_age,
	/* 0x06 */	wkh_allow,				/* 0x07 */	wkh_authorization,
	/* 0x08 */	wkh_cache_control,		/* 0x09 */	wkh_connection,
	/* 0x0A */	wkh_content_base,		/* 0x0B */	wkh_content_encoding,
	/* 0x0C */	wkh_content_language,	/* 0x0D */	wkh_content_length,
	/* 0x0E */	wkh_content_location,	/* 0x0F */	wkh_content_md5,
	/* 0x10 */	wkh_content_range,		/* 0x11 */	wkh_content_type,
	/* 0x12 */	wkh_date,				/* 0x13 */	wkh_etag,
	/* 0x14 */	wkh_expires,			/* 0x15 */	wkh_from,
	/* 0x16 */	wkh_host,				/* 0x17 */	wkh_if_modified_since,
	/* 0x18 */	wkh_if_match,			/* 0x19 */	wkh_if_none_match,
	/* 0x1A */	wkh_if_range,			/* 0x1B */	wkh_if_unmodified_since,
	/* 0x1C */	wkh_location,			/* 0x1D */	wkh_last_modified,
	/* 0x1E */	wkh_max_forwards,		/* 0x1F */	wkh_pragma,
	/* 0x20 */	wkh_proxy_authenticate,	/* 0x21 */	wkh_proxy_authorization,
	/* 0x22 */	wkh_public,				/* 0x23 */	wkh_range,
	/* 0x24 */	wkh_referer,			/* 0x25 */	wkh_default,
	/* 0x26 */	wkh_server,				/* 0x27 */	wkh_transfer_encoding,
	/* 0x28 */	wkh_upgrade,			/* 0x29 */	wkh_user_agent,
	/* 0x2A */	wkh_vary,				/* 0x2B */	wkh_via,
	/* 0x2C */	wkh_warning,			/* 0x2D */	wkh_www_authenticate,
	/* 0x2E */	wkh_content_disposition,/* 0x2F */	wkh_x_wap_application_id,
	/* 0x30 */	wkh_content_uri,		/* 0x31 */	wkh_initiator_uri,
	/* 0x32 */	wkh_accept_application,	/* 0x33 */	wkh_bearer_indication,
	/* 0x34 */	wkh_push_flag,			/* 0x35 */	wkh_profile,
	/* 0x36 */	wkh_profile_diff_wbxml,	/* 0x37 */	wkh_profile_warning,
	/* 0x38 */	wkh_default,			/* 0x39 */	wkh_te,
	/* 0x3A */	wkh_trailer,			/* 0x3B */	wkh_accept_charset,
	/* 0x3C */	wkh_accept_encoding,	/* 0x3D */	wkh_cache_control,
	/* 0x3E */	wkh_content_range,		/* 0x3F */	wkh_x_wap_tod,
	/* 0x40 */	wkh_content_id,			/* 0x41 */	wkh_default,
	/* 0x42 */	wkh_default,			/* 0x43 */	wkh_encoding_version,
	/* 0x44 */	wkh_profile_warning,	/* 0x45 */	wkh_content_disposition,
	/* 0x46 */	wkh_x_wap_security,		/* 0x47 */	wkh_cache_control,
	/*******************************************************
	 *** The following headers are not (yet) registered. ***
	 *******************************************************/
	/* 0x48 */	wkh_default,			/* 0x49 */	wkh_default,
	/* 0x4A */	wkh_default,			/* 0x4B */	wkh_default,
	/* 0x4C */	wkh_default,			/* 0x4D */	wkh_default,
	/* 0x4E */	wkh_default,			/* 0x4F */	wkh_default,
	/* 0x50 */	wkh_default,			/* 0x51 */	wkh_default,
	/* 0x52 */	wkh_default,			/* 0x53 */	wkh_default,
	/* 0x54 */	wkh_default,			/* 0x55 */	wkh_default,
	/* 0x56 */	wkh_default,			/* 0x57 */	wkh_default,
	/* 0x58 */	wkh_default,			/* 0x59 */	wkh_default,
	/* 0x5A */	wkh_default,			/* 0x5B */	wkh_default,
	/* 0x5C */	wkh_default,			/* 0x5D */	wkh_default,
	/* 0x5E */	wkh_default,			/* 0x5F */	wkh_default,
	/* 0x60 */	wkh_default,			/* 0x61 */	wkh_default,
	/* 0x62 */	wkh_default,			/* 0x63 */	wkh_default,
	/* 0x64 */	wkh_default,			/* 0x65 */	wkh_default,
	/* 0x66 */	wkh_default,			/* 0x67 */	wkh_default,
	/* 0x68 */	wkh_default,			/* 0x69 */	wkh_default,
	/* 0x6A */	wkh_default,			/* 0x6B */	wkh_default,
	/* 0x6C */	wkh_default,			/* 0x6D */	wkh_default,
	/* 0x6E */	wkh_default,			/* 0x6F */	wkh_default,
	/* 0x70 */	wkh_default,			/* 0x71 */	wkh_default,
	/* 0x72 */	wkh_default,			/* 0x73 */	wkh_default,
	/* 0x74 */	wkh_default,			/* 0x75 */	wkh_default,
	/* 0x76 */	wkh_default,			/* 0x77 */	wkh_default,
	/* 0x78 */	wkh_default,			/* 0x79 */	wkh_default,
	/* 0x7A */	wkh_default,			/* 0x7B */	wkh_default,
	/* 0x7C */	wkh_default,			/* 0x7D */	wkh_default,
	/* 0x7E */	wkh_default,			/* 0x7F */	wkh_default,
};

/* Lookup table for well-known header parsing functions */
static const hdr_parse_func_ptr WellKnownOpenwaveHeader[128] = {
	/* 0x00 */	wkh_openwave_default,
	/* 0x01 */	wkh_openwave_x_up_proxy_push_accept,
	/* 0x02 */	wkh_openwave_x_up_proxy_push_seq,
	/* 0x03 */	wkh_openwave_x_up_proxy_notify,
	/* 0x04 */	wkh_openwave_x_up_proxy_operator_domain,
	/* 0x05 */	wkh_openwave_x_up_proxy_home_page,
	/* 0x06 */	wkh_openwave_x_up_devcap_has_color,
	/* 0x07 */	wkh_openwave_x_up_devcap_num_softkeys,
	/* 0x08 */	wkh_openwave_x_up_devcap_softkey_size,
	/* 0x09 */	wkh_openwave_x_up_devcap_screen_chars,
	/* 0x0A */	wkh_openwave_x_up_devcap_screen_pixels,
	/* 0x0B */	wkh_openwave_x_up_devcap_em_size,
	/* 0x0C */	wkh_openwave_x_up_devcap_screen_depth,
	/* 0x0D */	wkh_openwave_x_up_devcap_immed_alert,
	/* 0x0E */	wkh_openwave_x_up_proxy_net_ask,
	/* 0x0F */	wkh_openwave_x_up_proxy_uplink_version,
	/* 0x10 */	wkh_openwave_x_up_proxy_tod,
	/* 0x11 */	wkh_openwave_x_up_proxy_ba_enable,
	/* 0x12 */	wkh_openwave_x_up_proxy_ba_realm,
	/* 0x13 */	wkh_openwave_x_up_proxy_redirect_enable,
	/* 0x14 */	wkh_openwave_x_up_proxy_request_uri,
	/* 0x15 */	wkh_openwave_x_up_proxy_redirect_status,
	/* 0x16 */	wkh_openwave_x_up_proxy_trans_charset,
	/* 0x17 */	wkh_openwave_x_up_proxy_linger,
	/* 0x18 */	wkh_openwave_default,
	/* 0x19 */	wkh_openwave_x_up_proxy_enable_trust,
	/* 0x1A */	wkh_openwave_x_up_proxy_trust,
	/* 0x1B */	wkh_openwave_default,
	/* 0x1C */	wkh_openwave_default,
	/* 0x1D */	wkh_openwave_default,
	/* 0x1E */	wkh_openwave_default,
	/* 0x1F */	wkh_openwave_default,
	/* 0x20 */	wkh_openwave_x_up_proxy_trust,
	/* 0x21 */	wkh_openwave_x_up_proxy_bookmark,
	/* 0x22 */	wkh_openwave_x_up_devcap_gui,
	/*******************************************************
	 *** The following headers are not (yet) registered. ***
	 *******************************************************/
	/* 0x23 */	wkh_openwave_default,
	/* 0x24 */	wkh_openwave_default,		/* 0x25 */	wkh_openwave_default,
	/* 0x26 */	wkh_openwave_default,		/* 0x27 */	wkh_openwave_default,
	/* 0x28 */	wkh_openwave_default,		/* 0x29 */	wkh_openwave_default,
	/* 0x2A */	wkh_openwave_default,		/* 0x2B */	wkh_openwave_default,
	/* 0x2C */	wkh_openwave_default,		/* 0x2D */	wkh_openwave_default,
	/* 0x2E */	wkh_openwave_default,		/* 0x2F */	wkh_openwave_default,
	/* 0x30 */	wkh_openwave_default,		/* 0x31 */	wkh_openwave_default,
	/* 0x32 */	wkh_openwave_default,		/* 0x33 */	wkh_openwave_default,
	/* 0x34 */	wkh_openwave_default,		/* 0x35 */	wkh_openwave_default,
	/* 0x36 */	wkh_openwave_default,		/* 0x37 */	wkh_openwave_default,
	/* 0x38 */	wkh_openwave_default,		/* 0x39 */	wkh_openwave_default,
	/* 0x3A */	wkh_openwave_default,		/* 0x3B */	wkh_openwave_default,
	/* 0x3C */	wkh_openwave_default,		/* 0x3D */	wkh_openwave_default,
	/* 0x3E */	wkh_openwave_default,		/* 0x3F */	wkh_openwave_default,
	/* 0x40 */	wkh_openwave_default,		/* 0x41 */	wkh_openwave_default,
	/* 0x42 */	wkh_openwave_default,		/* 0x43 */	wkh_openwave_default,
	/* 0x44 */	wkh_openwave_default,		/* 0x45 */	wkh_openwave_default,
	/* 0x46 */	wkh_openwave_default,		/* 0x47 */	wkh_openwave_default,
	/* 0x48 */	wkh_openwave_default,		/* 0x49 */	wkh_openwave_default,
	/* 0x4A */	wkh_openwave_default,		/* 0x4B */	wkh_openwave_default,
	/* 0x4C */	wkh_openwave_default,		/* 0x4D */	wkh_openwave_default,
	/* 0x4E */	wkh_openwave_default,		/* 0x4F */	wkh_openwave_default,
	/* 0x50 */	wkh_openwave_default,		/* 0x51 */	wkh_openwave_default,
	/* 0x52 */	wkh_openwave_default,		/* 0x53 */	wkh_openwave_default,
	/* 0x54 */	wkh_openwave_default,		/* 0x55 */	wkh_openwave_default,
	/* 0x56 */	wkh_openwave_default,		/* 0x57 */	wkh_openwave_default,
	/* 0x58 */	wkh_openwave_default,		/* 0x59 */	wkh_openwave_default,
	/* 0x5A */	wkh_openwave_default,		/* 0x5B */	wkh_openwave_default,
	/* 0x5C */	wkh_openwave_default,		/* 0x5D */	wkh_openwave_default,
	/* 0x5E */	wkh_openwave_default,		/* 0x5F */	wkh_openwave_default,
	/* 0x60 */	wkh_openwave_default,		/* 0x61 */	wkh_openwave_default,
	/* 0x62 */	wkh_openwave_default,		/* 0x63 */	wkh_openwave_default,
	/* 0x64 */	wkh_openwave_default,		/* 0x65 */	wkh_openwave_default,
	/* 0x66 */	wkh_openwave_default,		/* 0x67 */	wkh_openwave_default,
	/* 0x68 */	wkh_openwave_default,		/* 0x69 */	wkh_openwave_default,
	/* 0x6A */	wkh_openwave_default,		/* 0x6B */	wkh_openwave_default,
	/* 0x6C */	wkh_openwave_default,		/* 0x6D */	wkh_openwave_default,
	/* 0x6E */	wkh_openwave_default,		/* 0x6F */	wkh_openwave_default,
	/* 0x70 */	wkh_openwave_default,		/* 0x71 */	wkh_openwave_default,
	/* 0x72 */	wkh_openwave_default,		/* 0x73 */	wkh_openwave_default,
	/* 0x74 */	wkh_openwave_default,		/* 0x75 */	wkh_openwave_default,
	/* 0x76 */	wkh_openwave_default,		/* 0x77 */	wkh_openwave_default,
	/* 0x78 */	wkh_openwave_default,		/* 0x79 */	wkh_openwave_default,
	/* 0x7A */	wkh_openwave_default,		/* 0x7B */	wkh_openwave_default,
	/* 0x7C */	wkh_openwave_default,		/* 0x7D */	wkh_openwave_default,
	/* 0x7E */	wkh_openwave_default,		/* 0x7F */	wkh_openwave_default,
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
	guint8 hdr_id, val_id, codepage = 1;
	gint32 tvb_len = tvb_length(tvb);
	gint32 offset = 0, hdr_len, hdr_start;
	gint32 val_len, val_start;
	gchar *hdr_str, *val_str;
	proto_tree *wsp_headers;
	proto_item *ti;
	guint8 ok;
	guint32 val = 0;
	nstime_t tv;

	if (! tree)
		return;
	if (offset >= tvb_len)
		return; /* No headers! */

	ti = proto_tree_add_item(tree, hf,
			tvb, offset, tvb_len, bo_little_endian);
	wsp_headers = proto_item_add_subtree(ti, ett_headers);

	while (offset < tvb_len) {
		hdr_start = offset;
		hdr_id = tvb_get_guint8(tvb, offset);
		if (hdr_id & 0x80) { /* Well-known header */
			hdr_len = 1;
			val_start = ++offset;
			val_id = tvb_get_guint8(tvb, val_start);
			/* Call header value dissector for given header */
			if (codepage == 1) { /* Default header code page */
				DebugLog(("add_headers(code page 0): %s\n",
							val_to_str (hdr_id & 0x7f, vals_field_names, "Undefined")));
				offset = WellKnownHeader[hdr_id & 0x7F](wsp_headers, tvb,
						hdr_start, pinfo);
			} else { /* Openwave header code page */
				/* Here I'm delibarately assuming that Openwave is the only
				 * company that defines a WSP header code page. */
				DebugLog(("add_headers(code page 0x%02x - assumed to be x-up-1): %s\n",
							codepage, val_to_str (hdr_id & 0x7f, vals_openwave_field_names, "Undefined")));
				offset = WellKnownOpenwaveHeader[hdr_id & 0x7F](wsp_headers,
						tvb, hdr_start, pinfo);
			}
		} else if (hdr_id == 0x7F) { /* HCP shift sequence */
			codepage = tvb_get_guint8(tvb, offset+1);
			proto_tree_add_uint(wsp_headers, hf_wsp_header_shift_code,
					tvb, offset, 2, codepage);
			offset += 2;
		} else if (hdr_id >= 0x20) { /* Textual header */
			/* Header name MUST be NUL-ended string ==> tvb_get_stringz() */
			hdr_str = (gchar *)tvb_get_ephemeral_stringz(tvb, hdr_start, (gint *)&hdr_len);
			val_start = hdr_start + hdr_len;
			val_id = tvb_get_guint8(tvb, val_start);
			/* Call header value dissector for given header */
			if (val_id >= 0x20 && val_id <=0x7E) { /* OK! */
				val_str = (gchar *)tvb_get_ephemeral_stringz(tvb, val_start, (gint *)&val_len);
				offset = val_start + val_len;
				tvb_ensure_bytes_exist(tvb, hdr_start, offset-hdr_start);
				proto_tree_add_text(wsp_headers,tvb,hdr_start,offset-hdr_start,
						"%s: %s", hdr_str, val_str);
			} else {
				/* Old-style X-WAP-TOD uses a non-textual value
				 * after a textual header. */
				if (strcasecmp(hdr_str, "x-wap.tod") == 0) {
					get_delta_seconds_value(val, tvb, val_start, val_len, ok);
					if (ok) {
						if (val == 0) {
							ti = proto_tree_add_string (wsp_headers,
									hf_hdr_x_wap_tod,
									tvb, hdr_start, hdr_len + val_len,
									"Requesting Time Of Day");
						} else {
							tv.secs = val;
							tv.nsecs = 0;
							val_str = abs_time_to_str(&tv);
							ti = proto_tree_add_string (wsp_headers,
									hf_hdr_x_wap_tod,
									tvb, hdr_start, hdr_len + val_len, val_str);
						}
						proto_item_append_text(ti, " <Warning: "
								"should be encoded as a textual value>");
					} else {
						/* I prefer using X-Wap-Tod to the real hdr_str */
						proto_tree_add_string (wsp_headers, hf_hdr_x_wap_tod,
								tvb, hdr_start, hdr_len + val_len,
								InvalidValueForHeader("X-Wap-Tod"));
					}
				} else {
					proto_tree_add_text (wsp_headers, tvb, hdr_start, hdr_len,
							"<Error: Invalid value for the textual '%s' header"
							" (should be a textual value)>",
							hdr_str);
				}
				offset = tvb_len;
			}
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			proto_tree_add_string_hidden(wsp_headers, hf_hdr_name,
					tvb, hdr_start, offset - hdr_start, hdr_str);
		} else if (hdr_id > 0) { /* Shorthand HCP switch */
			codepage = hdr_id;
			proto_tree_add_uint (wsp_headers, hf_wsp_header_shift_code,
					tvb, offset, 1, codepage);
			offset++;
		} else {
			proto_tree_add_text (wsp_headers, tvb, hdr_start, 1,
					InvalidTextualHeader);
			offset = tvb_len;
		}
	}
}


/* The following macros hide common processing for all well-known headers
 * and shortens the code to be written in a wkh_XXX() function.
 * Even declarations are hidden by a macro.
 *
 * Define a wkh_XXX() function as follows:
 *
 * static guint32
 * wkh_XXX (proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
 * {
 * 		wkh_0_Declarations;
 *		<< add other required declarations here >>
 *
 *		wkh_1_WellKnownValue;
 *			<< add well-known value proto item here; don't forget to set the
 *			ok variable to TRUE if parsing was correct >>
 *		wkh_2_TextualValue;
 *			<< add textual value proto item here; don't forget to set the
 *			ok variable to TRUE if parsing was correct >>
 *		wkh_3_ValueWithLength;
 *			<< add custom code for value processing and value proto item here >>
 *
 *		wkh_4_End(hf);
 *			<< This macro takes care of parse errors within the header value;
 *			it requires the header field index if the header has not yet been
 *			written to the protocol tree (ti == NULL). >>
 * }
 *
 *	NOTE:	You only need to write parsing code for the successful case,
 *			Errors are automatically reported through the wkh_4_End() macro
 *			when ok <> TRUE.
 */

/* The following code is the generic template with which the value of a
 * well-known header can be processed. Not all sections yield a semantically
 * correct result, so appropriate error information must be provided.
 */


#define wkh_0_Declarations					/* Declarations for Parsing */ \
	gboolean ok = FALSE; /* Triggers error notification code at end */ \
	proto_item *ti = NULL; /* Needed for error notification at end */ \
	guint32 val_start = hdr_start + 1; \
	guint8 hdr_id = tvb_get_guint8 (tvb, hdr_start) & 0x7F; \
	guint8 val_id = tvb_get_guint8 (tvb, val_start); \
	guint32 offset = val_start; /* Offset to one past this header */ \
	guint32 val_len; /* length for value with length field */ \
	guint32 val_len_len; /* length of length field */ \
	gchar *val_str = NULL

#define wkh_1_WellKnownValue				/* Parse Well Known Value */ \
	proto_tree_add_string_hidden(tree, hf_hdr_name, \
			tvb, hdr_start, offset - hdr_start, \
			val_to_str (hdr_id, vals_field_names, \
				"<Unknown WSP header field 0x%02X>")); \
	if (val_id & 0x80) { /* Well-known value */ \
		offset++; \
		/* Well-known value processing starts HERE \
		 * \
		 * BEGIN */

#define wkh_2_TextualValue					/* Parse Textual Value */ \
		/* END */ \
	} else if ((val_id == 0) || (val_id >= 0x20)) { /* Textual value */ \
		val_str = (gchar *)tvb_get_ephemeral_stringz (tvb, val_start, (gint *)&val_len); \
		offset = val_start + val_len; \
		/* Textual value processing starts HERE \
		 * \
		 * BEGIN */

#define wkh_3_ValueWithLength				/* Parse Value With Length */ \
		/* END */ \
	} else { /* val_start points to 1st byte of length field */ \
		if (val_id == 0x1F) { /* Value Length = guintvar */ \
			val_len = tvb_get_guintvar(tvb, val_start + 1, &val_len_len); \
			val_len_len++; /* 0x1F length indicator byte */ \
		} else { /* Short length followed by Len data octets */ \
			val_len = tvb_get_guint8(tvb, offset); \
			val_len_len = 1; \
		} \
		offset += val_len_len + val_len; \
		/* Value with length processing starts HERE \
		 * The value lies between val_start and offset: \
		 *  - Value Length:	Start  = val_start \
		 *					Length = val_len_len \
		 *  - Value Data  :	Start  = val_start + val_len_len \
		 *					Length = val_len \
		 *					End    = offset - 1 \
		 * BEGIN */

#define wkh_4_End(hf)						/* End of value parsing */ \
		/* END */ \
	} \
	/* Check for errors */ \
	if (! ok) { \
		if (ti) { /* Append to protocol tree item label */ \
			proto_item_append_text(ti, \
					" <Error: Invalid header value>"); \
		} else if (hf > 0) { /* Create protocol tree item */ \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			proto_tree_add_string(tree, hf, \
					tvb, hdr_start, offset - hdr_start, \
					" <Error: Invalid header value>"); \
		} else { /* Create anonymous header field entry */ \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			proto_tree_add_text(tree, tvb, hdr_start, offset - hdr_start, \
					"%s: <Error: Invalid header value>", \
					val_to_str (hdr_id, vals_field_names, \
						"<Unknown WSP header field 0x%02X>")); \
		} \
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

	ok = TRUE; /* Bypass error checking as we don't parse the values! */

	wkh_1_WellKnownValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_text (tree, tvb, hdr_start, offset - hdr_start,
				"%s: (Undecoded well-known value 0x%02x)",
				val_to_str (hdr_id, vals_field_names,
					"<Unknown WSP header field 0x%02X>"), val_id & 0x7F);
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_text(tree, tvb, hdr_start, offset - hdr_start,
				"%s: %s",
				val_to_str (hdr_id, vals_field_names,
					"<Unknown WSP header field 0x%02X>"), val_str);
	wkh_3_ValueWithLength;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_text (tree, tvb, hdr_start, offset - hdr_start,
				"%s: (Undecoded value in general form with length indicator)",
				val_to_str (hdr_id, vals_field_names,
					"<Unknown WSP header field 0x%02X>"));

	wkh_4_End(HF_EMPTY); /* The default parser has no associated hf_index;
							additionally the error code is always bypassed */
}


/* Content-type processing uses the following common core: */
#define wkh_content_type_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	guint32 off, val = 0, len; \
	guint8 peek; \
	proto_tree *parameter_tree = NULL; \
	\
	wkh_1_WellKnownValue; \
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, \
				val_to_str(val_id & 0x7F, vals_content_types, \
					"(Unknown content type identifier 0x%X)")); \
		ok = TRUE; \
	wkh_2_TextualValue; \
		/* Sometimes with a No-Content response, a NULL content type \
		 * is reported. Process this correctly! */ \
		if (*val_str) { \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, \
					val_str); \
		} else { \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, \
					"<no content type has been specified>"); \
		} \
		ok = TRUE; \
	wkh_3_ValueWithLength; \
		off = val_start + val_len_len; \
		peek = tvb_get_guint8(tvb, off); \
		if (is_text_string(peek)) { \
			get_extension_media(val_str, tvb, off, len, ok); \
			/* As we're using val_str, it is automatically g_free()d */ \
			off += len; /* off now points to 1st byte after string */ \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string (tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, val_str); \
		} else if (is_integer_value(peek)) { \
			get_integer_value(val, tvb, off, len, ok); \
			if (ok) { \
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, \
						val_to_str(val, vals_content_types, \
							"(Unknown content type identifier 0x%X)")); \
			} \
			off += len; \
		} \
		/* Remember: offset == val_start + val_len + val_len_len */ \
		if (ok && (off < offset)) { /* Add parameters if any */ \
			parameter_tree = proto_item_add_subtree (ti, ett_header); \
			while (off < offset) { \
				off = parameter (parameter_tree, ti, tvb, off, offset - off); \
			} \
		} \
	\
	wkh_4_End(hf_hdr_ ## underscored); \
}


/*
 * Accept-value =
 *	  Short-integer
 *	| Extension-media
 *	| ( Value-length ( Extension-media | Integer-value ) *( Parameter ) )
 */
wkh_content_type_header(accept, "Accept")


/*
 * Content-type-value =
 *	  Short-integer
 *	| Extension-media
 *	| ( Value-length ( Extension-media | Integer-value ) *( Parameter ) )
 *
 * Beware: this header should not appear as such; it is dissected elsewhere
 * and at the same time the content type is used for subdissectors.
 * It is here for the sake of completeness.
 */
wkh_content_type_header(content_type, "Content-Type")


/*
 * Content-type-value =
 *	  Short-integer
 *	| Extension-media
 *	| ( Value-length ( Extension-media | Integer-value ) *( Parameter ) )
 *
 * This function adds the content type value to the protocol tree,
 * and computes either the numeric or textual media type in return,
 * which will be used for further subdissection (e.g., MMS, WBXML).
 */
guint32
add_content_type(proto_tree *tree, tvbuff_t *tvb, guint32 val_start,
		guint32 *well_known_content, const char **textual_content)
{
	/* Replace wkh_0_Declarations with slightly modified declarations
	 * so we can still make use of the wkh_[1-4]_XXX macros! */
	guint32 hdr_start = val_start; /* No header name, only value! */
	guint8 hdr_id = FN_CONTENT_TYPE; /* Same remark */
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

	/* this function will call proto_item_append_string() which
	   doesnt work with the TRY_TO_FAKE_THIS_ITEM
	   speed optimization.
	   So we have to disable that one and become "slow" by pretending that
	   the tree is "visible".

	 * This code must be present for the MMSE dissector which calls this function.
	 * Otherwise this causes a dissector_assert [bug 492] (proto_item_append_string() issue).
	 */
	if (tree)
		PTREE_DATA(tree)->visible=1;

	*textual_content = NULL;
	*well_known_content = 0;

	DebugLog(("add_content_type() - START\n"));

	wkh_1_WellKnownValue;
		DebugLog(("add_content_type() - Well-known - Start\n"));
		*textual_content = val_to_str(val_id & 0x7F, vals_content_types,
				"<Unknown media type identifier 0x%X>");
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_content_type,
				tvb, hdr_start, offset - hdr_start,
				*textual_content);
		*well_known_content = val_id & 0x7F;
		ok = TRUE;
		DebugLog(("add_content_type() - Well-known - End\n"));
	wkh_2_TextualValue;
		DebugLog(("add_content_type() - Textual - Start\n"));
		/* Sometimes with a No-Content response, a NULL content type
		 * is reported. Process this correctly! */
		if (*val_str) {
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_content_type,
					tvb, hdr_start, offset - hdr_start,
					val_str);
			/* As we're using val_str, it is automatically g_free()d */
			*textual_content = g_strdup(val_str);
			*well_known_content = 0;
		} else {
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_content_type,
					tvb, hdr_start, offset - hdr_start,
					"<no media type has been specified>");
			*textual_content = NULL;
			*well_known_content = 0;
		}
		ok = TRUE;
		DebugLog(("add_content_type() - Textual - End\n"));
	wkh_3_ValueWithLength;
		DebugLog(("add_content_type() - General form - Start\n"));
		off = val_start + val_len_len;
		peek = tvb_get_guint8(tvb, off);
		if (is_text_string(peek)) {
			DebugLog(("add_content_type() - General form - extension-media\n"));
			get_extension_media(val_str, tvb, off, len, ok);
			/* As we're using val_str, it is automatically g_free()d */
			/* ??? Not sure anymore, we're in wkh_3, not in wkh_2 ! */
			off += len; /* off now points to 1st byte after string */
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string (tree, hf_hdr_content_type,
					tvb, hdr_start, offset - hdr_start, val_str);
			/* Following statement: required? */
			*textual_content = g_strdup(val_str);
			*well_known_content = 0;
		} else if (is_integer_value(peek)) {
			DebugLog(("add_content_type() - General form - integer_value\n"));
			get_integer_value(val, tvb, off, len, ok);
			if (ok) {
				*textual_content = val_to_str(val, vals_content_types,
						"<Unknown media type identifier 0x%X>");
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_content_type,
						tvb, hdr_start, offset - hdr_start,
						*textual_content);
				*well_known_content = val;
			}
			off += len;
		} /* else ok = FALSE */
		/* Remember: offset == val_start + val_len_len + val_len */
		if (ok && (off < offset)) { /* Add parameters if any */
			DebugLog(("add_content_type() - General form - parameters\n"));
			parameter_tree = proto_item_add_subtree (ti, ett_header);
			while (off < offset) {
				DebugLog(("add_content_type() - General form - parameter start "
							"(off = %u)\n", off));
				off = parameter (parameter_tree, ti, tvb, off, offset - off);
				DebugLog(("add_content_type() - General form - parameter end "
							"(off = %u)\n", off));
			}
		}
		DebugLog(("add_content_type() - General form - End\n"));

	wkh_4_End(hf_hdr_content_type);
}


/*
 * Template for accept_X headers with optional Q parameter value
 */
#define wkh_accept_x_q_header(underscored,Text,valueString,valueName) \
static guint32 \
wkh_ ## underscored (proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	guint32 off, val = 0, len; \
	guint8 peek; \
	proto_tree *parameter_tree = NULL; \
	\
	wkh_1_WellKnownValue; \
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, \
				val_to_str(val_id & 0x7F, valueString, \
					"<Unknown " valueName " identifier 0x%X>")); \
		ok = TRUE; \
	wkh_2_TextualValue; \
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, val_str); \
		ok = TRUE; \
	wkh_3_ValueWithLength; \
		off = val_start + val_len_len; \
		peek = tvb_get_guint8(tvb, off); \
		if (is_text_string(peek)) { \
			get_token_text(val_str, tvb, off, len, ok); \
			/* As we're using val_str, it is automatically g_free()d */ \
			off += len; /* off now points to 1st byte after string */ \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string (tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, val_str); \
		} else if (is_integer_value(peek)) { \
			get_integer_value(val, tvb, off, len, ok); \
			if (ok) { \
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, \
						val_to_str(val, valueString, \
							"<Unknown " valueName " identifier 0x%X>")); \
			} \
			off += len; \
		} /* else ok = FALSE */ \
		/* Remember: offset == val_start + val_len */ \
		if (ok && (off < offset)) { /* Add Q-value if available */ \
			parameter_tree = proto_item_add_subtree (ti, ett_header); \
			off = parameter_value_q (parameter_tree, ti, tvb, off); \
		} \
	\
	wkh_4_End(hf_hdr_ ## underscored); \
}

/*
 * Accept-charset-value =
 *	  Short-integer
 *	| Extension-media
 *	| ( Value-length ( Token-text | Integer-value ) [ Q-value ] )
 */
wkh_accept_x_q_header(accept_charset, "Accept-Charset",
		vals_character_sets, "character set")
/*
 * Accept-language-value =
 *	  Short-integer
 *	| Extension-media
 *	| ( Value-length ( Text-string | Integer-value ) [ Q-value ] )
 */
wkh_accept_x_q_header(accept_language, "Accept-Language",
		vals_languages, "language")


/*
 * Push-flag-value = Short-integer
 */
static guint32
wkh_push_flag(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	proto_tree *subtree = NULL;

	wkh_1_WellKnownValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_push_flag,
				tvb, hdr_start, offset - hdr_start, "");
		subtree = proto_item_add_subtree(ti, ett_header);
		proto_tree_add_uint(subtree, hf_hdr_push_flag_auth,
				tvb, val_start, 1, val_id);
		proto_tree_add_uint(subtree, hf_hdr_push_flag_trust,
				tvb, val_start, 1, val_id);
		proto_tree_add_uint(subtree, hf_hdr_push_flag_last,
				tvb, val_start, 1, val_id);
		if (val_id & 0x01)
			proto_item_append_string(ti, " (Initiator URI authenticated)");
		if (val_id & 0x02)
			proto_item_append_string(ti, " (Content trusted)");
		if (val_id & 0x04)
			proto_item_append_string(ti, " (Last push message)");
		if (val_id & 0x78)
			proto_item_append_text(ti, " <Warning: Reserved flags set>");
		else
			ok = TRUE;
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		/* Invalid */
	wkh_4_End(hf_hdr_push_flag);
}


/*
 * Profile-Diff (with WBXML): Profile-diff-value =
 *		Value-length <WBXML-Content>
 */
static guint32 wkh_profile_diff_wbxml (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo)
{
	wkh_0_Declarations;
	tvbuff_t *tmp_tvb;
	proto_tree *subtree;

	ok = TRUE; /* Bypass error checking as we don't parse the values! */

	wkh_1_WellKnownValue;
		/* Invalid */
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_profile_diff, tvb, hdr_start, offset - hdr_start,
				"(Profile-Diff value as WBXML)");
		subtree = proto_item_add_subtree(ti, ett_header);
		tmp_tvb = tvb_new_subset(tvb, val_start + val_len_len, val_len, val_len); /* TODO: fix 2nd length */
		call_dissector(wbxml_uaprof_handle, tmp_tvb, pinfo, subtree);
		ok = TRUE;
	wkh_4_End(hf_hdr_profile_diff);
}


/*
 * Allow-value =
 *     Short-integer
 */
static guint32
wkh_allow(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		val_id &= 0x7F;
		if (val_id >= 0x40) { /* Valid WSP method */
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_allow,
					tvb, hdr_start, offset - hdr_start,
					val_to_str(val_id & 0x7F, vals_pdu_type,
						"<Unknown WSP method 0x%02X>"));
			ok = TRUE;
		}
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		/* Invalid */
	wkh_4_End(hf_hdr_allow);
}


/*
 * Public-value =
 *     Token-text | Short-integer
 */
static guint32
wkh_public(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		val_id &= 0x7F;
		if (val_id >= 0x40) { /* Valid WSP method */
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_public,
					tvb, hdr_start, offset - hdr_start,
					val_to_str(val_id & 0x7F, vals_pdu_type,
						"<Unknown WSP method 0x%02X>"));
			ok = TRUE;
		}
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_public,
				tvb, hdr_start, offset - hdr_start, val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		/* Invalid */
	wkh_4_End(hf_hdr_public);
}


/*
 * Vary-value =
 *     Token-text | Short-integer
 */
static guint32
wkh_vary(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_vary,
				tvb, hdr_start, offset - hdr_start,
				val_to_str(val_id & 0x7F, vals_field_names,
					"<Unknown WSP header field 0x%02X>"));
		ok = TRUE;
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_vary,
				tvb, hdr_start, offset - hdr_start,
				val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		/* Invalid */
	wkh_4_End(hf_hdr_vary);
}


/*
 * X-wap-security-value = 0x80
 */
static guint32
wkh_x_wap_security(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		if (val_id == 0x80) {
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_x_wap_security,
					tvb, hdr_start, offset - hdr_start, "close-subordinate");
			ok = TRUE;
		}
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		/* Invalid */
	wkh_4_End(hf_hdr_x_wap_security);
}


/*
 * Connection-value = 0x80 | Token-text
 */
static guint32
wkh_connection(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		if (val_id == 0x80) {
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_connection,
					tvb, hdr_start, offset - hdr_start, "close");
			ok = TRUE;
		}
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_connection,
				tvb, hdr_start, offset - hdr_start, val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		/* Invalid */
	wkh_4_End(hf_hdr_connection);
}


/*
 * Transfer-encoding-value = 0x80 | Token-text
 */
static guint32
wkh_transfer_encoding(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		if (val_id == 0x80) {
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_transfer_encoding,
					tvb, hdr_start, offset - hdr_start, "chunked");
			ok = TRUE;
		}
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_transfer_encoding,
				tvb, hdr_start, offset - hdr_start, val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		/* Invalid */
	wkh_4_End(hf_hdr_transfer_encoding);
}


/*
 * Accept-range-value = 0x80 | 0x81 | Token-text
 */
static guint32
wkh_accept_ranges(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		switch (val_id) {
			case 0x80: /* none */
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_accept_ranges,
						tvb, hdr_start, offset - hdr_start, "none");
				ok = TRUE;
				break;
			case 0x81: /* bytes */
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_accept_ranges,
						tvb, hdr_start, offset - hdr_start, "bytes");
				ok = TRUE;
				break;
		}
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_accept_ranges,
				tvb, hdr_start, offset - hdr_start, val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		/* Invalid */
	wkh_4_End(hf_hdr_accept_ranges);
}


/*
 * Content-encoding-value = 0x80 | 0x81 | 0x82 | Token-text
 */
static guint32
wkh_content_encoding(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		switch (val_id) {
			case 0x80: /* gzip */
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_content_encoding,
						tvb, hdr_start, offset - hdr_start, "gzip");
				ok = TRUE;
				break;
			case 0x81: /* compress */
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_content_encoding,
						tvb, hdr_start, offset - hdr_start, "compress");
				ok = TRUE;
				break;
			case 0x82: /* deflate */
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_content_encoding,
						tvb, hdr_start, offset - hdr_start, "deflate");
				ok = TRUE;
				break;
		}
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_content_encoding,
				tvb, hdr_start, offset - hdr_start, val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		/* Invalid */
	wkh_4_End(hf_hdr_content_encoding);
}


/*
 * Accept-encoding-value =
 *	  Short-integer
 *	| Token-text
 *	| ( Value-length ( Short-integer | Text-string ) [ Q-value ] )
 */
static guint32
wkh_accept_encoding(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	guint32 len, off;
	guint8 peek;
	gchar *str;
	proto_tree *parameter_tree = NULL;

	wkh_1_WellKnownValue;
		switch (val_id) {
			case 0x80: /* gzip */
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
						tvb, hdr_start, offset - hdr_start, "gzip");
				ok = TRUE;
				break;
			case 0x81: /* compress */
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
						tvb, hdr_start, offset - hdr_start, "compress");
				ok = TRUE;
				break;
			case 0x82: /* deflate */
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
						tvb, hdr_start, offset - hdr_start, "deflate");
				ok = TRUE;
				break;
		}
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		proto_tree_add_string(tree, hf_hdr_accept_encoding,
				tvb, hdr_start, offset - hdr_start, val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		peek = tvb_get_guint8(tvb, off);
		if (is_short_integer(peek)) {
			switch (peek) {
				case 0x80: /* gzip */
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
					ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
							tvb, hdr_start, offset - hdr_start, "gzip");
					ok = TRUE;
					break;
				case 0x81: /* compress */
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
					ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
							tvb, hdr_start, offset - hdr_start, "compress");
					ok = TRUE;
					break;
				case 0x82: /* deflate */
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
					ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
							tvb, hdr_start, offset - hdr_start, "deflate");
					ok = TRUE;
					break;
				case 0x83: /* any */
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
					ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
							tvb, hdr_start, offset - hdr_start, "*");
					ok = TRUE;
					break;
			}
			off++;
		} else {
			get_token_text(str, tvb, off, len, ok);
			if (ok) {
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_accept_encoding,
						tvb, hdr_start, offset - hdr_start, str);
				g_free(str);
			}
			off += len;
		}
		if (ok) {
			/* Remember: offset == val_start + val_len_len + val_len */
			if (off < offset) { /* Add Q-value if available */
				parameter_tree = proto_item_add_subtree(ti, ett_header);
				off = parameter_value_q(parameter_tree, ti, tvb, off);
			}
		}
	wkh_4_End(hf_hdr_accept_encoding);
}


/*
 * Content-disposition-value = Value-length ( Disposition ) *( Parameter )
 *	Disposition = Form-data | Attachment | Inline | Token-text
 *	Form-data = 0x80
 *	Attachment = 0x81
 *	Inline = 0x82
 * We handle this as:
 *	Value-length ( Short-integer | Text-string ) *( Parameter )
 */
static guint32
wkh_content_disposition(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	guint32 len, off;
	guint8 peek;
	gchar *str;
	proto_tree *parameter_tree = NULL;

	wkh_1_WellKnownValue;
		/* Invalid */
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		peek = tvb_get_guint8(tvb, off);
		if (is_short_integer(peek)) {
			switch (peek) {
				case 0x80: /* form-data */
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
					ti = proto_tree_add_string(tree, hf_hdr_content_disposition,
							tvb, hdr_start, offset - hdr_start, "form-data");
					ok = TRUE;
					break;
				case 0x81: /* attachment */
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
					ti = proto_tree_add_string(tree, hf_hdr_content_disposition,
							tvb, hdr_start, offset - hdr_start, "attachment");
					ok = TRUE;
					break;
				case 0x82: /* inline */
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
					ti = proto_tree_add_string(tree, hf_hdr_content_disposition,
							tvb, hdr_start, offset - hdr_start, "inline");
					ok = TRUE;
					break;
			}
			off++;
		} else {
			get_token_text(str, tvb, off, len, ok);
			if (ok) {
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_content_disposition,
						tvb, hdr_start, offset - hdr_start, str);
				g_free(str);
			}
			off += len;
		}
		if ((ok) && (off < offset)) {
			/* Remember: offset == val_start + val_len_len + val_len */
			parameter_tree = proto_item_add_subtree(ti, ett_header);
			while (off < offset) { /* Add parameters if available */
				off = parameter(parameter_tree, ti, tvb, off, offset - off);
			}
		}
	wkh_4_End(hf_hdr_content_disposition);
}


/*
 * Common code for headers with only a textual value
 * is written in the macro below:
 */
#define wkh_text_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	\
	wkh_1_WellKnownValue; \
		/* Invalid */ \
	wkh_2_TextualValue; \
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, val_str); \
		ok = TRUE; \
	wkh_3_ValueWithLength; \
		/* Invalid */ \
	wkh_4_End(hf_hdr_ ## underscored); \
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
#define wkh_quoted_string_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	gchar *str; \
	\
	wkh_1_WellKnownValue; \
		/* Invalid */ \
	wkh_2_TextualValue; \
		if (is_quoted_string(val_str[0])) { \
			if (is_quoted_string(val_str[val_len-2])) { \
				/* Trailing quote - issue a warning */ \
				str = g_strdup_printf("%s" TrailingQuoteWarning, val_str); \
			} else { /* OK (no trailing quote) */ \
				str = g_strdup_printf("%s\"", val_str); \
			} \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, str); \
			g_free(str); \
		} else { \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, val_str); \
			proto_item_append_text(ti, \
					" <Warning: should be encoded as a Quoted-string>"); \
		} \
		ok = TRUE; \
	wkh_3_ValueWithLength; \
		/* Invalid */ \
	wkh_4_End(hf_hdr_ ## underscored); \
}

wkh_quoted_string_header(content_id, "Content-ID")


/*
 * Common code for headers with only a textual or a date value
 * is written in the macro below:
 */
#define wkh_text_or_date_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	nstime_t tv; \
	gchar *str; /* may not be freed! */ \
	\
	wkh_1_WellKnownValue; \
		/* Invalid */ \
	wkh_2_TextualValue; \
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, val_str); \
		ok = TRUE; \
	wkh_3_ValueWithLength; \
		if (val_id <= 4) { /* Length field already parsed by macro! */ \
			get_date_value(val, tvb, off, len, ok); \
			if (ok) { \
				tv.secs = val; \
				tv.nsecs = 0; \
				str = abs_time_to_str(&tv); \
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, str); \
				/* BEHOLD: do NOT try to free str, as this generates a core
				 * dump!  It looks like abs_time_to_str() is buggy or works
				 * with static data. */ \
			} \
		} \
	wkh_4_End(hf_hdr_ ## underscored); \
}

/* If-Range */
wkh_text_or_date_value_header(if_range,"If-Range")


/*
 * Common code for headers with only a date value
 * is written in the macro below:
 */
#define wkh_date_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	nstime_t tv; \
	gchar *str; /* may not be freed! */ \
	\
	wkh_1_WellKnownValue; \
		/* Invalid */ \
	wkh_2_TextualValue; \
		/* Invalid */ \
	wkh_3_ValueWithLength; \
		if (val_id <= 4) { /* Length field already parsed by macro! */ \
			get_date_value(val, tvb, off, len, ok); \
			if (ok) { \
				tv.secs = val; \
				tv.nsecs = 0; \
				str = abs_time_to_str(&tv); \
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, str); \
				/* BEHOLD: do NOT try to free str, as this generates a core
				 * dump!  It looks like abs_time_to_str() is buggy or works
				 * with static data. */ \
			} \
		} \
	wkh_4_End(hf_hdr_ ## underscored); \
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
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	nstime_t tv; \
	gchar *str; /* may not be freed! */ \
	\
	wkh_1_WellKnownValue; \
		if (val_id == 0x80) { /* Openwave TOD header uses this format */ \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, \
					"Requesting Time Of Day"); \
			proto_item_append_text(ti, \
					" <Warning: should be encoded as long-integer>"); \
			ok = TRUE; \
		} \
		/* It seems VERY unlikely that we'll see date values within the first \
		 * 127 seconds of the UNIX 1-1-1970 00:00:00 start of the date clocks \
		 * so I assume such a value is a genuine error */ \
	wkh_2_TextualValue; \
		/* Invalid */ \
	wkh_3_ValueWithLength; \
		if (val_id <= 4) { /* Length field already parsed by macro! */ \
			get_date_value(val, tvb, off, len, ok); \
			if (ok) { \
				if (val == 0) { \
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
					ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
							tvb, hdr_start, offset - hdr_start, \
							"Requesting Time Of Day"); \
				} else { \
					tv.secs = val; \
					tv.nsecs = 0; \
					str = abs_time_to_str(&tv); \
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
					ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
							tvb, hdr_start, offset - hdr_start, str); \
				} \
			} \
		} \
	wkh_4_End(hf_hdr_ ## underscored); \
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

	wkh_1_WellKnownValue;
		val = val_id & 0x7F;
		val_str = g_strdup_printf("%u second%s", val, plurality(val, "", "s"));
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_age,
				tvb, hdr_start, offset - hdr_start, val_str);
		g_free(val_str); /* proto_XXX creates a copy */
		ok = TRUE;
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		if (val_id <= 4) { /* Length field already parsed by macro! */
			get_long_integer(val, tvb, off, len, ok);
			if (ok) {
				val_str = g_strdup_printf("%u second%s", val, plurality(val, "", "s"));
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_age,
						tvb, hdr_start, offset - hdr_start, val_str);
				g_free(val_str); /* proto_XXX creates a copy */
			}
		}
	wkh_4_End(hf_hdr_age);
}


/*
 * Template for Integer lookup or text value headers:
 */
#define wkh_integer_lookup_or_text_value(underscored,Text,valueString,valueName) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	\
	wkh_1_WellKnownValue; \
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, \
				val_to_str(val_id & 0x7F, valueString, \
				"(Unknown " valueName " identifier 0x%X)")); \
		ok = TRUE; \
	wkh_2_TextualValue; \
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, val_str); \
		ok = TRUE; \
	wkh_3_ValueWithLength; \
		if (val_id <= 4) { /* Length field already parsed by macro! */ \
			get_long_integer(val, tvb, off, len, ok); \
			if (ok) { \
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, \
						val_to_str(val_id & 0x7F, valueString, \
						"(Unknown " valueName " identifier 0x%X)")); \
			} \
		} \
	wkh_4_End(hf_hdr_ ## underscored); \
}

/*
 * Wap-application-value: Uri-value | Integer-value
 */
wkh_integer_lookup_or_text_value(x_wap_application_id, "X-Wap-Application-Id",
		vals_wap_application_ids, "WAP application")
wkh_integer_lookup_or_text_value(accept_application, "Accept-Application",
		vals_wap_application_ids, "WAP application")
wkh_integer_lookup_or_text_value(content_language, "Content-Language",
		vals_languages, "language")
/* NOTE - Although the WSP spec says this is an integer-value, the WSP headers
 * are encoded as a 7-bit entity! */
wkh_integer_lookup_or_text_value(trailer, "Trailer",
		vals_field_names, "well-known-header")


/*
 * Challenge
 */

/*
 * Common code for headers with only a challenge value
 * is written in the macro below:
 */
#define wkh_challenge_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, \
		guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	guint8 peek; \
	guint32 off, len; \
	proto_tree *subtree; \
	gchar *str; \
	\
	wkh_1_WellKnownValue; \
		/* Invalid */ \
	wkh_2_TextualValue; \
		/* Invalid */ \
	wkh_3_ValueWithLength; \
		off = val_start + val_len_len; \
		peek = tvb_get_guint8(tvb, off); \
		if (peek == 0x80) { /* Basic */ \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, "basic"); \
			subtree = proto_item_add_subtree(ti, ett_header); \
			proto_tree_add_string(subtree, hf_hdr_ ## underscored ## _scheme, \
					tvb, off, 1, "basic"); \
			off++; \
			/* Realm: text-string */ \
			get_text_string(str,tvb,off,len,ok); \
			if (ok) { \
				proto_tree_add_string(subtree, \
						hf_hdr_ ## underscored ## _realm, \
						tvb, off, len, str); \
				val_str = g_strdup_printf("; realm=%s", str); \
				proto_item_append_string(ti, val_str); \
				g_free(val_str); \
				g_free(str); \
				off += len; \
			} \
		} else { /* Authentication-scheme: token-text */ \
			get_token_text(str, tvb, off, len, ok); \
			if (ok) { \
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, off - hdr_start, str); \
				subtree = proto_item_add_subtree(ti, ett_header); \
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
				proto_tree_add_string(subtree, \
						hf_hdr_ ## underscored ## _scheme, \
						tvb, hdr_start, off - hdr_start, str); \
				g_free(str); \
				off += len; \
				/* Realm: text-string */ \
				get_text_string(str,tvb,off,len,ok); \
				if (ok) { \
					proto_tree_add_string(subtree, \
							hf_hdr_ ## underscored ## _realm, \
							tvb, off, len, str); \
					val_str = g_strdup_printf("; realm=%s", str); \
					proto_item_append_string(ti, val_str); \
					g_free(val_str); \
					g_free(str); \
					off += len; \
					/* Auth-params: parameter - TODO */ \
					while (off < offset) /* Parse parameters */ \
						off = parameter(subtree, ti, tvb, off, offset - off); \
				} \
			} \
		} \
	wkh_4_End(hf_hdr_ ## underscored); \
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
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, \
		guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	guint8 peek; \
	guint32 off, len; \
	proto_tree *subtree; \
	gchar *str; \
	\
	wkh_1_WellKnownValue; \
		/* Invalid */ \
	wkh_2_TextualValue; \
		/* Invalid */ \
	wkh_3_ValueWithLength; \
		off = val_start + val_len_len; \
		peek = tvb_get_guint8(tvb, off); \
		if (peek == 0x80) { /* Basic */ \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, "basic"); \
			subtree = proto_item_add_subtree(ti, ett_header); \
			proto_tree_add_string(subtree, hf_hdr_ ## underscored ## _scheme, \
					tvb, off, 1, "basic"); \
			off++; \
			/* User-id: text-string */ \
			get_text_string(str,tvb,off,len,ok); \
			if (ok) { \
				proto_tree_add_string(subtree, \
						hf_hdr_ ## underscored ## _user_id, \
						tvb, off, len, str); \
				val_str = g_strdup_printf("; user-id=%s", str); \
				proto_item_append_string(ti, val_str); \
				g_free(val_str); \
				g_free(str); \
				off += len; \
				/* Password: text-string */ \
				get_text_string(str,tvb,off,len,ok); \
				if (ok) { \
					proto_tree_add_string(subtree, \
							hf_hdr_ ## underscored ## _password, \
							tvb, off, len, str); \
					val_str = g_strdup_printf("; password=%s", str); \
					proto_item_append_string(ti, val_str); \
					g_free(val_str); \
					g_free(str); \
					off += len; \
				} \
			} \
		} else { /* Authentication-scheme: token-text */ \
			get_token_text(str, tvb, off, len, ok); \
			if (ok) { \
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, off - hdr_start, str); \
				subtree = proto_item_add_subtree(ti, ett_header); \
				proto_tree_add_string(subtree, \
						hf_hdr_ ## underscored ## _scheme, \
						tvb, hdr_start, off - hdr_start, str); \
				g_free(str); \
				off += len; \
				/* Auth-params: parameter - TODO */ \
				while (off < offset) /* Parse parameters */ \
					off = parameter(subtree, ti, tvb, off, offset - off); \
			} \
		} \
	wkh_4_End(hf_hdr_ ## underscored); \
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
	wkh_0_Declarations;
	guint32 off;

	wkh_1_WellKnownValue;
		/* Invalid */
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		if (val_len == 16) {
			val_str = g_strdup_printf(
					"%02x%02x%02x%02x%02x%02x%02x%02x"
					"%02x%02x%02x%02x%02x%02x%02x%02x",
					tvb_get_guint8(tvb, off),
					tvb_get_guint8(tvb, off + 1),
					tvb_get_guint8(tvb, off + 2),
					tvb_get_guint8(tvb, off + 3),
					tvb_get_guint8(tvb, off + 4),
					tvb_get_guint8(tvb, off + 5),
					tvb_get_guint8(tvb, off + 6),
					tvb_get_guint8(tvb, off + 7),
					tvb_get_guint8(tvb, off + 8),
					tvb_get_guint8(tvb, off + 9),
					tvb_get_guint8(tvb, off + 10),
					tvb_get_guint8(tvb, off + 11),
					tvb_get_guint8(tvb, off + 12),
					tvb_get_guint8(tvb, off + 13),
					tvb_get_guint8(tvb, off + 14),
					tvb_get_guint8(tvb, off + 15)
			);
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_content_md5,
					tvb, hdr_start, offset - hdr_start, val_str);
			g_free(val_str);
			ok = TRUE;
		}
	wkh_4_End(hf_hdr_content_md5);
}


/*
 * Pragma-value = 0x80 | Length Parameter
 */
static guint32
wkh_pragma(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	guint32 off;

	wkh_1_WellKnownValue;
		if (val_id == 0x80) {
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_pragma,
					tvb, hdr_start, offset - hdr_start, "no-cache");
			ok = TRUE;
		}
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_pragma,
				tvb, hdr_start, off - hdr_start, "");
		/* NULL subtree for parameter() results in no subtree
		 * TODO - provide a single parameter dissector that appends data
		 * to the header field data. */
		off = parameter(NULL, ti, tvb, off, offset - off);
		ok = TRUE;
	wkh_4_End(hf_hdr_pragma);
}


/*
 * Integer-value
 */
#define wkh_integer_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	gchar *str; /* may not be freed! */ \
	\
	wkh_1_WellKnownValue; \
		str = g_strdup_printf("%u", val_id & 0x7F); \
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, str); \
		g_free(str); \
		ok = TRUE; \
	wkh_2_TextualValue; \
		/* Invalid */ \
	wkh_3_ValueWithLength; \
		if (val_id <= 4) { /* Length field already parsed by macro! */ \
			get_long_integer(val, tvb, off, len, ok); \
			if (ok) { \
				str = g_strdup_printf("%u", val); \
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, str); \
				g_free(str); \
			} \
		} \
	wkh_4_End(hf_hdr_ ## underscored); \
}

wkh_integer_value_header(content_length, "Content-Length")
wkh_integer_value_header(max_forwards, "Max-Forwards")


#define wkh_integer_lookup_value_header(underscored,Text,valueString,valueName) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	\
	wkh_1_WellKnownValue; \
		val_str = match_strval(val_id & 0x7F, valueString); \
		if (val_str) { \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, val_str); \
			ok = TRUE; \
		} else { \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, \
				"<Unknown " valueName ">"); \
		} \
	wkh_2_TextualValue; \
		/* Invalid */ \
	wkh_3_ValueWithLength; \
		if (val_id <= 4) { /* Length field already parsed by macro! */ \
			get_long_integer(val, tvb, off, len, ok); \
			if (ok) { \
				val_str = match_strval(val_id & 0x7F, valueString); \
				if (val_str) { \
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
					ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, val_str); \
					ok = TRUE; \
				} else { \
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
					ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, \
						"<Unknown " valueName ">"); \
				} \
			} \
		} \
	wkh_4_End(hf_hdr_ ## underscored); \
}

wkh_integer_lookup_value_header(bearer_indication, "Bearer-Indication",
		vals_bearer_types, "bearer type")


/*
 * Cache-control-value
 */
static guint32
wkh_cache_control(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	guint32 off, len, val = 0;
	guint8 peek, cache_control_directive;
	gchar *str;

	wkh_1_WellKnownValue;
		val = val_id & 0x7F;
		val_str = match_strval(val, vals_cache_control);
		if (val_str) {
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_cache_control,
					tvb, hdr_start, offset - hdr_start, val_str);
			ok = TRUE;
		}
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_string(tree, hf_hdr_cache_control,
				tvb, hdr_start, offset - hdr_start, val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		/* General form:
		 *	  ( no-cache | private ) 1*( Field-name )
		 *	| ( max-age | max-stale | min-fresh | s-maxage) Delta-seconds-value
		 *	| Token-text ( Integer-value | Text-value )
		 * Where:
		 *	Field-name = Short-integer | Token-text
		 */
		off = val_start + val_len_len;
		cache_control_directive = tvb_get_guint8(tvb, off++);
		if (cache_control_directive & 0x80) { /* Well known cache directive */
			switch (cache_control_directive & 0x7F) {
				case CACHE_CONTROL_NO_CACHE:
				case CACHE_CONTROL_PRIVATE:
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
					ti = proto_tree_add_string(tree, hf_hdr_cache_control,
							tvb, hdr_start, offset - hdr_start,
							val_to_str (cache_control_directive & 0x7F, vals_cache_control,
								"<Unknown cache control directive 0x%02X>"));
					/* TODO: split multiple entries */
					while (ok && (off < offset)) { /* 1*( Field-name ) */
						ok = TRUE;
						peek = tvb_get_guint8(tvb, off);
						if (peek & 0x80) { /* Well-known-field-name */
							proto_item_append_string(ti,
									val_to_str (peek, vals_field_names,
										"<Unknown WSP header field 0x%02X>"));
							off++;
						} else { /* Token-text */
							get_token_text(val_str, tvb, off, len, ok);
							if (ok) {
								proto_item_append_string(ti, val_str);
								g_free(val_str);
								off += len;
							}
						}
					}
					break;

				case CACHE_CONTROL_MAX_AGE:
				case CACHE_CONTROL_MAX_STALE:
				case CACHE_CONTROL_MIN_FRESH:
				case CACHE_CONTROL_S_MAXAGE:
					tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
					ti = proto_tree_add_string(tree, hf_hdr_cache_control,
							tvb, hdr_start, offset - hdr_start,
							val_to_str (cache_control_directive & 0x7F, vals_cache_control,
								"<Unknown cache control directive 0x%02X>"));
					get_delta_seconds_value(val, tvb, off, len, ok);
					if (ok) {
						val_str = g_strdup_printf("=%u second%s",
								val, plurality(val, "", "s"));
						proto_item_append_string(ti, val_str);
						g_free(val_str); /* proto_XXX creates a copy */
					}
					break;

				default:
					/* ok = FALSE */
					break;
			}
		} else if (is_token_text(cache_control_directive)) {
			get_token_text(val_str, tvb, off, len, ok);
			if (ok) {
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_cache_control,
						tvb, hdr_start, offset - hdr_start, val_str);
				g_free(val_str);
				get_integer_value(val, tvb, off, len, ok);
				if (ok) { /* Integer-value */
					val_str = g_strdup_printf("=%u", val);
					proto_item_append_string(ti, val_str);
					g_free(val_str); /* proto_XXX creates a copy */
				} else { /* Text-value */
					get_text_string(val_str, tvb, off, len, ok);
					if (ok) {
						if (is_quoted_string(val_str[0])) {
							if (is_quoted_string(val_str[len-2])) {
								/* Trailing quote - issue a warning */
								str = g_strdup_printf("%s" TrailingQuoteWarning,
										val_str);
							} else { /* OK (no trailing quote) */
								str = g_strdup_printf("%s\"", val_str);
							}
							proto_item_append_string(ti, str);
							g_free(str);
						} else { /* Token-text | 0x00 */
							/* TODO - check that we have Token-text or 0x00 */
							proto_item_append_string(ti, val_str);
						}
						g_free(val_str);
					}
				}
			}
		}
	wkh_4_End(hf_hdr_cache_control);
}


/*
 * Warning-value =
 *	  Short-integer
 *	| ( Value-length Short-integer Text-string Text-string )
 */
static guint32
wkh_warning(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	guint32 off, len, val;
	guint8 warn_code;
	gchar *str;
	proto_tree *subtree;

	/* TODO - subtree with values */

	wkh_1_WellKnownValue;
		val = val_id & 0x7F;
		val_str = match_strval(val, vals_wsp_warning_code);
		if (val_str) {
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_warning,
					tvb, hdr_start, offset - hdr_start, val_str);
			subtree = proto_item_add_subtree(ti, ett_header);
			proto_tree_add_uint(subtree, hf_hdr_warning_code,
					tvb, val_start, 1, val);
			ok = TRUE;
		}
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		/* TODO - subtree with individual values */
		off = val_start + val_len_len;
		warn_code = tvb_get_guint8(tvb, off);
		if (warn_code & 0x80) { /* Well known warn code */
			val = warn_code & 0x7f;
			val_str = match_strval(val, vals_wsp_warning_code_short);
			if (val_str) { /* OK */
				str = g_strdup_printf("code=%s", val_str);
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_warning,
						tvb, hdr_start, offset - hdr_start, str);
				g_free(str);
				subtree = proto_item_add_subtree(ti, ett_header);
				proto_tree_add_uint(subtree, hf_hdr_warning_code,
						tvb, off, 1, val);
				off++; /* Now skip to the warn-agent subfield */
				get_text_string(str, tvb, off, len, ok);
				if (ok) { /* Valid warn-agent string */
					proto_tree_add_string(subtree, hf_hdr_warning_agent,
							tvb, off, len, str);
					val_str = g_strdup_printf("; agent=%s", str);
					proto_item_append_string(ti, val_str);
					g_free(val_str); /* proto_XXX creates a copy */
					g_free(str);
					off += len;
					get_text_string(str, tvb, off, len, ok);
					if (ok) { /* Valid warn-text string */
						proto_tree_add_string(subtree,
								hf_hdr_warning_text,
								tvb, off, len, str);
						val_str = g_strdup_printf("; text=%s", str);
						proto_item_append_string(ti, val_str);
						g_free(val_str); /* proto_XXX creates a copy */
						g_free(str);
						off += len;
					}
				}
			}
		}
	wkh_4_End(hf_hdr_warning);
}


/*
 * Profile-warning-value =
 *	  Short-integer
 *	| ( Value-length Short-integer Text-string *( Date-value ) )
 */
static guint32
wkh_profile_warning(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	guint32 off, len, val = 0;
	nstime_t tv;
	guint8 warn_code;
	gchar *str;

	wkh_1_WellKnownValue;
		val = val_id & 0x7F;
		val_str = match_strval(val, vals_wsp_profile_warning_code);
		if (val_str) {
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_profile_warning,
					tvb, hdr_start, offset - hdr_start, val_str);
			ok = TRUE;
		}
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		warn_code = tvb_get_guint8(tvb, off++);
		if (warn_code & 0x80) { /* Well known warn code */
			val_str = match_strval(val, vals_wsp_profile_warning_code);
			if (val_str) { /* OK */
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_profile_warning,
						tvb, hdr_start, offset - hdr_start, val_str);
				get_uri_value(str, tvb, off, len, ok);
				if (ok) { /* Valid warn-target string */
					off += len;
					str = g_strdup_printf("; target=%s", val_str);
					proto_item_append_string(ti, str);
					g_free(str); /* proto_XXX creates a copy */
					/* Add zero or more dates */
					while (ok && (off < offset)) {
						get_date_value(val, tvb, off, len, ok);
						if (ok) { /* Valid warn-text string */
							off += len;
							tv.secs = val;
							tv.nsecs = 0;
							val_str = abs_time_to_str(&tv);
							str = g_strdup_printf("; date=%s", val_str);
							proto_item_append_string(ti, str);
							g_free(str); /* proto_XXX creates a copy */
							/* BEHOLD: do NOT try to free val_str, as this
							 * generates a core dump!
							 * It looks like abs_time_to_str() is
							 * buggy or works with static data. */
						}
					}
				}
			}
		}
	wkh_4_End(hf_hdr_profile_warning);
}


/* Encoding-version-value =
 *	  Short-integer
 *	| Text-string
 *	| Length Short-integer [ Short-integer | text-string ]
 */
static guint32 wkh_encoding_version (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	guint32 off, val, len;
	gchar *str;

	wkh_1_WellKnownValue;
		val = val_id & 0x7F;
		val_str = g_strdup_printf("%u.%u", val >> 4, val & 0x0F);
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		proto_tree_add_string(tree, hf_hdr_encoding_version,
				tvb, hdr_start, offset - hdr_start, val_str);
		g_free(val_str);
		ok = TRUE;
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		proto_tree_add_string(tree, hf_hdr_encoding_version,
				tvb, hdr_start, offset - hdr_start, val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		val = tvb_get_guint8(tvb, off);
		if (val & 0x80) { /* Header Code Page */
			val_str = g_strdup_printf("code-page=%u", val & 0x7F);
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_encoding_version,
					tvb, hdr_start, offset - hdr_start, val_str);
			g_free(val_str);
			off++;
			ok = TRUE;
			if (off < offset) { /* Extra version-value */
				get_version_value(val,val_str,tvb,off,len,ok);
				if (ok) { /* Always creates a string if OK */
					str = g_strdup_printf(": %s", val_str);
					proto_item_append_string(ti, str);
					g_free(str);
					g_free(val_str);
				}
			}
		}

	wkh_4_End(hf_hdr_encoding_version);
}


/* Content-range-value =
 *	  Length Uintvar-integer ( 0x80 | Uintvar-integer )
 */
static guint32
wkh_content_range(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	guint32 off, val, len;
	proto_tree *subtree = NULL;

	wkh_1_WellKnownValue;
		/* Invalid */
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		get_uintvar_integer (val, tvb, off, len, ok); /* Uintvar start */
		if (ok) {
			val_str = g_strdup_printf("first-byte-pos=%u", val);
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_content_range,
					tvb, hdr_start, offset - hdr_start, val_str);
			subtree = proto_item_add_subtree(ti, ett_header);
			proto_tree_add_uint(subtree, hf_hdr_content_range_first_byte_pos,
					tvb, off, len, val);
			g_free(val_str);
			off += len;
			/* Now check next value */
			val = tvb_get_guint8(tvb, off);
			if (val == 0x80) { /* Unknown length */
				proto_item_append_string(ti, "; entity-length=unknown");
			} else { /* Uintvar entity length */
				get_uintvar_integer (val, tvb, off, len, ok);
				if (ok) {
					val_str = g_strdup_printf("; entity-length=%u", val);
					proto_item_append_string(ti, val_str);
					proto_tree_add_uint(subtree,
							hf_hdr_content_range_entity_length,
							tvb, off, len, val);
					g_free(val_str);
				}
			}
		}

	wkh_4_End(hf_hdr_content_range);
}


/* Range-value =
 *	Length
 *		0x80 Uintvar-integer [ Uintvar-integer ]
 *	  | 0x81 Uintvar-integer
 */
static guint32
wkh_range(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	guint32 off, val, len;
	proto_tree *subtree = NULL;

	wkh_1_WellKnownValue;
		/* Invalid */
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		val = tvb_get_guint8(tvb, off);
		if (val == 0x80) { /* Byte-range */
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_range,
					tvb, hdr_start, offset - hdr_start, "byte-range");
			subtree = proto_item_add_subtree(ti, ett_header);
			/* Get the First-byte-pos (Uintvar-integer) */
			get_uintvar_integer (val, tvb, off, len, ok);
			if (ok) {
				val_str = g_strdup_printf("; first-byte-pos=%u", val);
				proto_item_append_string(ti, val_str);
				proto_tree_add_uint(subtree, hf_hdr_range_first_byte_pos,
						tvb, off, len, val);
				g_free(val_str);
				off += len;
				/* Get the optional Last-byte-pos (Uintvar-integer) */
				if (off < offset) {
					get_uintvar_integer (val, tvb, off, len, ok);
					if (ok) {
						val_str = g_strdup_printf("; last-byte-pos=%u", val);
						proto_item_append_string(ti, val_str);
						proto_tree_add_uint(subtree,
								hf_hdr_range_last_byte_pos,
								tvb, off, len, val);
						g_free(val_str);
					}
				}
			}
		} else if (val == 0x81) { /* Suffix-byte-range */
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			ti = proto_tree_add_string(tree, hf_hdr_range,
					tvb, hdr_start, offset - hdr_start, "suffix-byte-range");
			subtree = proto_item_add_subtree(ti, ett_header);
			/* Get the Suffix-length (Uintvar-integer) */
			get_uintvar_integer (val, tvb, off, len, ok);
			if (ok) {
				val_str = g_strdup_printf("; suffix-length=%u", val);
				proto_item_append_string(ti, val_str);
				proto_tree_add_uint(subtree, hf_hdr_range_suffix_length,
						tvb, off, len, val);
				g_free(val_str);
			}
		}

	wkh_4_End(hf_hdr_range);
}


/* TE-value =
 *	  0x81
 *	| Value-length (0x82--0x86 | Token-text) [ Q-token Q-value ]
 */
static guint32 wkh_te (proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;
	guint32 off, val, len;

	wkh_1_WellKnownValue;
		if (val_id == 0x81) {
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
			proto_tree_add_string(tree, hf_hdr_encoding_version,
					tvb, hdr_start, offset - hdr_start, "trailers");
			ok = TRUE;
		}
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		val = tvb_get_guint8(tvb, off);
		if (val & 0x80) { /* Well-known-TE */
			val_str = match_strval((val & 0x7F), vals_well_known_te);
			if (val_str) {
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_te,
						tvb, hdr_start, off - hdr_start, val_str);
				off++;
				ok = TRUE;
			}
		} else { /* TE in Token-text format */
			get_token_text(val_str, tvb, off, len, ok);
			if (ok) {
				tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
				ti = proto_tree_add_string(tree, hf_hdr_te,
						tvb, hdr_start, off - hdr_start, val_str);
				g_free(val_str);
				off += len;
			}
		}
		if ((ok) && (off < offset)) { /* Q-token Q-value */
			/* TODO */
		}

	wkh_4_End(hf_hdr_te);
}


/****************************************************************************
 *                     O p e n w a v e   h e a d e r s
 ****************************************************************************/




/*
 * Redefine the WellKnownValue parsing so Openwave header field names are used
 * are used instead of the default WSP header field names
 */
#undef wkh_1_WellKnownValue
#define wkh_1_WellKnownValue			/* Parse Well Known Value */ \
	tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
	proto_tree_add_string_hidden(tree, hf_hdr_name, \
			tvb, hdr_start, offset - hdr_start, \
			val_to_str (hdr_id, vals_openwave_field_names, \
					"<Unknown WSP header field 0x%02X>")); \
	if (val_id & 0x80) { /* Well-known value */ \
		offset++; \
		/* Well-known value processing starts HERE \
		 * \
		 * BEGIN */

/*
 * Redefine the End parsing so Openwave header field names are used
 * instead of the default WSP field names
 */
#undef wkh_4_End
#define wkh_4_End(hf)						/* End of value parsing */ \
		/* END */ \
	} \
	/* Check for errors */ \
	if (! ok) { \
		if (ti) { /* Append to protocol tree item label */ \
			proto_item_append_text(ti, \
					"<Error: Invalid header value>"); \
		} else if (hf > 0) { /* Create protocol tree item */ \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			proto_tree_add_string(tree, hf, \
					tvb, hdr_start, offset - hdr_start, \
					" <Error: Invalid header value>"); \
		} else { /* Create anonymous header field entry */ \
			tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start); \
			proto_tree_add_text(tree, tvb, hdr_start, offset - hdr_start, \
					"%s: <Error: Invalid header value>", \
					val_to_str (hdr_id, vals_openwave_field_names, \
						"<Unknown WSP header field 0x%02X>")); \
		} \
	} \
	return offset;


/* Dissect the Openwave header value (generic) */
static guint32
wkh_openwave_default(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start, packet_info *pinfo _U_)
{
	wkh_0_Declarations;

	ok = TRUE; /* Bypass error checking as we don't parse the values! */

	wkh_1_WellKnownValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_text(tree, tvb, hdr_start, offset - hdr_start,
				"%s: (Undecoded well-known value 0x%02x)",
				val_to_str (hdr_id, vals_openwave_field_names,
					"<Unknown WSP header field 0x%02X>"), val_id & 0x7F);
	wkh_2_TextualValue;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_text(tree,tvb,hdr_start, offset - hdr_start,
				"%s: %s",
				val_to_str (hdr_id, vals_openwave_field_names,
					"<Unknown WSP header field 0x%02X>"), val_str);
	wkh_3_ValueWithLength;
		tvb_ensure_bytes_exist(tvb, hdr_start, offset - hdr_start);
		ti = proto_tree_add_text(tree, tvb, hdr_start, offset - hdr_start,
				"%s: (Undecoded value in general form with length indicator)",
				val_to_str (hdr_id, vals_openwave_field_names,
					"<Unknown WSP header field 0x%02X>"));

	wkh_4_End(HF_EMPTY); /* See wkh_default for explanation */
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
		vals_character_sets, "character set")

/* Openwave content type header */
wkh_content_type_header(openwave_x_up_proxy_push_accept,
		"x-up-proxy-push-accept")

/*
 * Header value parameter parsing
 */
#define InvalidParameterValue(parameter,value) \
	"<Error: Invalid " parameter " parameter value: invalid " value ">"





#define parameter_text(hf,lowercase,Uppercase,value) \
	DebugLog(("parameter with text_string value: " Uppercase "\n")); \
	get_text_string(val_str, tvb, offset, val_len, ok); \
	if (ok) { \
		DebugLog(("OK, valid text_string value found!\n")); \
		DebugLog(("Adding val_str to the header field in proto tree\n")); \
		proto_tree_add_string(tree, hf, \
				tvb, start, type_len + val_len, val_str); \
		DebugLog(("Creating str to append to ti\n")); \
		str = g_strdup_printf("; " lowercase "=%s", val_str); \
		DebugLog(("Appending str to ti\n")); \
		proto_item_append_string(ti, str); \
		DebugLog(("\tFreeing str [%s]\n", str)); \
		g_free(str); \
		DebugLog(("\tFreeing val_str [%s]\n", val_str)); \
		g_free(val_str); \
		offset += val_len; \
	} else { \
		DebugLog(("\tError: invalid parameter value!\n")); \
		proto_tree_add_string(tree, hf, tvb, start, len, \
				InvalidParameterValue(Uppercase, value)); \
		offset = start + len; /* Skip to end of buffer */ \
	} \
	DebugLog(("parameter with text_string value - END\n"));


#define parameter_text_value(hf,lowercase,Uppercase,value) \
	get_text_string(val_str, tvb, offset, val_len, ok); \
	if (ok) { \
		if (is_quoted_string(val_str[0])) { \
			if (is_quoted_string(val_str[val_len-2])) { \
				/* Trailing quote - issue a warning */ \
				str = g_strdup_printf("%s" TrailingQuoteWarning, val_str); \
				proto_tree_add_string(tree, hf, \
						tvb, start, type_len + val_len, str); \
				g_free(str); \
				str = g_strdup_printf("; " lowercase "=%s", val_str); \
			} else { /* OK (no trailing quote) */ \
				str = g_strdup_printf("%s\"", val_str); \
				proto_tree_add_string(tree, hf, \
						tvb, start, type_len + val_len, str); \
				g_free(str); \
				str = g_strdup_printf("; " lowercase "=%s\"", val_str); \
			} \
		} else { /* Token-text | 0x00 */ \
			/* TODO - verify that we have either Token-text or 0x00 */ \
			proto_tree_add_string(tree, hf, \
					tvb, start, type_len + val_len, val_str); \
			str = g_strdup_printf("; " lowercase "=%s", val_str); \
		} \
		proto_item_append_string(ti, str); \
		g_free(str); \
		g_free(val_str); \
		offset += val_len; \
	} else { \
		proto_tree_add_string(tree, hf, tvb, start, len, \
				InvalidParameterValue(Uppercase, value)); \
		offset = start + len; /* Skip to end of buffer */ \
	}


/* Parameter = Untyped-parameter | Typed-parameter
 * Untyped-parameter = Token-text ( Integer-value | Text-value )
 * Typed-parameter =
 * 		Integer-value (
 * 			( Integer-value | Date-value | Delta-seconds-value
 * 			  | Q-value | Version-value | Uri-value )
 * 			| Text-value )
 *
 *
 * Returns: next offset
 *
 * TODO - Verify byte highlighting in case of invalid parameter values
 */
static int
parameter (proto_tree *tree, proto_item *ti, tvbuff_t *tvb, int start, int len)
{
	int offset = start;
	guint8 peek = tvb_get_guint8 (tvb,start);
	guint32 val = 0, type = 0, type_len, val_len;
	gchar *str = NULL;
	gchar *val_str = NULL;
	gchar *s;
	gboolean ok;

	DebugLog(("parameter(start = %u, len = %u)\n", start, len));
	if (is_token_text (peek)) {
		/*
		 * Untyped parameter
		 */
		DebugLog(("parameter() - Untyped - Start\n"));
		get_token_text (str,tvb,start,val_len,ok); /* Should always succeed */
		if (ok) { /* Found a textual parameter name: str */
			offset += val_len;
			get_text_value(val_str, tvb, offset, val_len, ok);
			if (ok) { /* Also found a textual parameter value: val_str */
				DebugLog(("Trying textual parameter value.\n"));
				offset += val_len;
				if (is_quoted_string(val_str[0])) { /* Add trailing quote! */
					if (is_quoted_string(val_str[val_len-2])) {
						/* Trailing quote - issue a warning */
						tvb_ensure_bytes_exist(tvb, start, offset - start);
						proto_tree_add_text(tree, tvb, start, offset - start,
								"%s: %s" TrailingQuoteWarning, str, val_str);
						s = g_strdup_printf("; %s=%s", str, val_str);
					} else { /* OK (no trailing quote) */
						tvb_ensure_bytes_exist(tvb, start, offset - start);
						proto_tree_add_text(tree, tvb, start, offset - start,
								"%s: %s\"", str, val_str);
						s = g_strdup_printf("; %s=%s\"", str, val_str);
					}
				} else { /* Token-text | 0x00 */
					/* TODO - verify that it is either Token-text or 0x00
					 * and flag with warning if invalid */
					tvb_ensure_bytes_exist(tvb, start, offset - start);
					proto_tree_add_text(tree, tvb, start, offset - start,
							"%s: %s", str, val_str);
					s = g_strdup_printf("; %s=%s", str, val_str);
				}
				/* TODO - check if we can insert a searchable field in the
				 * protocol tree for the untyped parameter case */
				DebugLog(("parameter() - Untyped: %s\n", s));
				proto_item_append_string(ti, s);
				DebugLog(("Freeing s\n"));
				g_free(s);
				DebugLog(("Freeing val_str\n"));
				g_free(val_str);
				DebugLog(("Done!\n"));
			} else { /* Try integer value */
				DebugLog(("Trying integer parameter value.\n"));
				get_integer_value (val,tvb,offset,val_len,ok);
				if (ok) { /* Also found a valid integer parameter value: val */
					offset += val_len;
					tvb_ensure_bytes_exist(tvb, start, offset - start);
					proto_tree_add_text(tree, tvb, start, offset - start,
							"%s: %u", str, val);
					s = g_strdup_printf("; %s=%u", str, val);
					proto_item_append_string(ti, s);
					DebugLog(("parameter() - Untyped: %s\n", s));
					g_free(s);
					/* TODO - check if we can insert a searchable field in the
					 * protocol tree for the untyped parameter case */
				} else { /* Error: neither token-text not Integer-value */
					DebugLog(("Invalid untyped parameter value!\n"));
					tvb_ensure_bytes_exist(tvb, start, offset - start);
					proto_tree_add_text (tree, tvb, start, offset - start,
							"<Error: Invalid untyped parameter definition>");
					offset = start + len; /* Skip to end of buffer */
				}
			}
			g_free(str);
		}
		DebugLog(("parameter() - Untyped - End\n"));
		return offset;
	}
	/*
	 * Else: Typed parameter
	 */
	DebugLog(("parameter() - Typed - Start\n"));
	get_integer_value (type,tvb,start,type_len,ok);
	if (!ok) {
		tvb_ensure_bytes_exist(tvb, start, offset - start);
		proto_tree_add_text (tree, tvb, start, offset - start,
				"<Error: Invalid typed parameter definition>");
		return (start + len); /* Skip to end of buffer */
	}
	offset += type_len;
	/* Now offset points to the parameter value */
	DebugLog(("Typed parameter = 0x%02x\n", type));
	switch (type) {
		case 0x01:	/* WSP 1.1 encoding - Charset: Well-known-charset */
			get_integer_value(val, tvb, offset, val_len, ok);
			if (ok) {
				val_str = val_to_str(val, vals_character_sets,
						"<Unknown character set Identifier 0x%X>");
				proto_tree_add_string(tree, hf_parameter_charset,
						tvb, start, type_len + val_len, val_str);
				str = g_strdup_printf("; charset=%s", val_str);
				proto_item_append_string(ti, str);
				g_free(str);
				offset += val_len;
			} else {
				proto_tree_add_text (tree, tvb, start, offset,
						InvalidParameterValue("Charset", "Integer-value"));
				offset = start + len; /* Skip to end of buffer */
			}
			break;

		case 0x03:	/* WSP 1.1 encoding - Type: Integer-value */
			get_integer_value (val,tvb,offset,val_len,ok);
			if (ok) {
				proto_tree_add_uint (tree, hf_wsp_parameter_type,
						tvb, start, type_len + val_len, val);
				s = g_strdup_printf("; Type=%u", val);
				proto_item_append_string (ti, s);
				g_free(s);
				offset += val_len;
			} else {
				proto_tree_add_text (tree, tvb, start, offset,
						InvalidParameterValue("Type", "Integer-value"));
				offset = start + len; /* Skip to end of buffer */
			}
			break;

		case 0x05:	/* WSP 1.1 encoding - Name: Text-string */
			parameter_text(hf_wsp_parameter_name, "name",
					"Name (WSP 1.1 encoding)", "Text-string");
			break;
		case 0x17:	/* WSP 1.4 encoding - Name: Text-value */
			parameter_text_value(hf_wsp_parameter_name, "name",
					"Name (WSP 1.4 encoding)", "Text-value");
			break;

		case 0x06:	/* WSP 1.1 encoding - Filename: Text-string */
			parameter_text(hf_wsp_parameter_filename, "filename",
					"Filename (WSP 1.1 encoding)", "Text-string");
			break;
		case 0x18:	/* WSP 1.4 encoding - Filename: Text-value */
			parameter_text_value(hf_wsp_parameter_filename, "filename",
					"Filename (WSP 1.4 encoding)", "Text-value");
			break;

		case 0x09:	/* WSP 1.2 encoding - Type (special): Constrained-encoding */
			/* This is similar to the Content-Type header decoding,
			 * but it is much simpler:
			 * Constrained-encoding = Short-integer | Extension-media
			 * Extension-media = *TEXT <Octet 0>
			 */
			get_extension_media(val_str,tvb,offset,val_len,ok);
			if (ok) { /* Extension-media */
				offset += val_len;
			} else {
				get_short_integer(val,tvb,offset,val_len,ok);
				if (ok) {
					offset += val_len;
					val_str = val_to_str(val, vals_content_types,
							"(Unknown content type identifier 0x%X)");
				} /* Else: invalid parameter value */
			}
			if (ok) {
				tvb_ensure_bytes_exist(tvb, start, offset - start);
				proto_tree_add_string (tree, hf_wsp_parameter_upart_type,
						tvb, start, offset - start, val_str);
				str = g_strdup_printf("; type=%s", val_str);
				proto_item_append_string(ti, str);
				g_free(str);
			} else { /* Invalid parameter value */
				proto_tree_add_text (tree, tvb, start, len,
						InvalidParameterValue("Type",
							"Constrained-encoding"));
				offset = start + len; /* Skip the parameters */
			}
			break;

		case 0x0A:	/* WSP 1.2 encoding - Start: Text-string */
			parameter_text(hf_wsp_parameter_start, "start",
					"Start (WSP 1.2 encoding)", "Text-string");
			break;
		case 0x19:	/* WSP 1.4 encoding - Start (with multipart/related): Text-value */
			parameter_text_value(hf_wsp_parameter_start, "start",
					"Start (WSP 1.4 encoding)", "Text-value");
			break;

		case 0x0B:	/* WSP 1.2 encoding - Start-info: Text-string */
			parameter_text(hf_wsp_parameter_start_info, "start-info",
					"Start-info (WSP 1.2 encoding)", "Text-string");
			break;
		case 0x1A:	/* WSP 1.4 encoding - Start-info (with multipart/related): Text-value */
			parameter_text_value(hf_wsp_parameter_start_info, "start-info",
					"Start-info (WSP 1.4 encoding)", "Text-value");
			break;

		case 0x0C:	/* WSP 1.3 encoding - Comment: Text-string */
			parameter_text(hf_wsp_parameter_comment, "comment",
					"Comment (WSP 1.3 encoding)", "Text-string");
			break;
		case 0x1B:	/* WSP 1.4 encoding - Comment: Text-value */
			parameter_text_value(hf_wsp_parameter_comment, "comment",
					"Comment (WSP 1.4 encoding)", "Text-value");
			break;

		case 0x0D:	/* WSP 1.3 encoding - Domain: Text-string */
			parameter_text(hf_wsp_parameter_domain, "domain",
					"Domain (WSP 1.3 encoding)", "Text-string");
			break;
		case 0x1C:	/* WSP 1.4 encoding - Domain: Text-value */
			parameter_text_value(hf_wsp_parameter_domain, "domain",
					"Domain (WSP 1.4 encoding)", "Text-value");
			break;

		case 0x0F:	/* WSP 1.3 encoding - Path: Text-string */
			parameter_text(hf_wsp_parameter_path, "path",
					"Path (WSP 1.3 encoding)", "Text-string");
			break;
		case 0x1D:	/* WSP 1.4 encoding - Path: Text-value */
			parameter_text_value(hf_wsp_parameter_path, "path",
					"Path (WSP 1.4 encoding)", "Text-value");
			break;

		case 0x11:	/* WSP 1.4 encoding - SEC: Short-integer (OCTET) */
			peek = tvb_get_guint8 (tvb, start+1);
			if (peek & 0x80) { /* Valid Short-integer */
				peek &= 0x7F;
				proto_tree_add_uint (tree, hf_wsp_parameter_sec,
						tvb, start, 2, peek);
				str = val_to_str(peek, vals_wsp_parameter_sec, "Undefined");
				s = g_strdup_printf("; SEC=%s", str);
				proto_item_append_string (ti, s);
				g_free(s);
				offset++;
			} else { /* Error */
				proto_tree_add_text (tree, tvb, start, len,
						InvalidParameterValue("SEC", "Short-integer"));
				offset = start + len; /* Skip to end of buffer */
			}
			break;

		case 0x12:	/* WSP 1.4 encoding - MAC: Text-value */
			parameter_text_value(hf_wsp_parameter_mac, "MAC",
					"MAC", "Text-value");
			break;

		case 0x02:	/* WSP 1.1 encoding - Level: Version-value */
			get_version_value(val,str,tvb,offset,val_len,ok);
			if (ok) {
				proto_tree_add_string (tree, hf_wsp_parameter_level,
						tvb, start, type_len + val_len, str);
				s = g_strdup_printf("; level=%s", str);
				proto_item_append_string (ti, s);
				g_free(s);
				offset += val_len;
			} else {
				proto_tree_add_text (tree, tvb, start, len,
						InvalidParameterValue("Level", "Version-value"));
				offset = start + len; /* Skip to end of buffer */
			}
			break;

		case 0x00:	/* WSP 1.1 encoding - Q: Q-value */
			offset = parameter_value_q(tree, ti, tvb, offset);
			break;

		case 0x16:	/* WSP 1.4 encoding - Size: Integer-value */
			get_integer_value (val,tvb,offset,val_len,ok);
			if (ok) {
				proto_tree_add_uint (tree, hf_wsp_parameter_size,
						tvb, start, type_len + val_len, val);
				s = g_strdup_printf("; Size=%u", val);
				proto_item_append_string (ti, s);
				g_free(s);
				offset += val_len;
			} else {
				proto_tree_add_text (tree, tvb, start, offset,
						InvalidParameterValue("Size", "Integer-value"));
				offset = start + len; /* Skip to end of buffer */
			}
			break;

			/*
			 * TODO
			 */

		case 0x07:	/* WSP 1.1 encoding - Differences: Field-name */
			DebugLog(("Skipping remaining parameters from here\n"));
			tvb_ensure_bytes_exist(tvb, start, offset - start);
			proto_tree_add_text(tree, tvb, start, offset - start,
					"Undecoded parameter Differences - decoding stopped");
			break;

		case 0x08:	/* WSP 1.1 encoding - Padding: Short-integer */
			DebugLog(("Skipping remaining parameters from here\n"));
			tvb_ensure_bytes_exist(tvb, start, offset - start);
			proto_tree_add_text(tree, tvb, start, offset - start,
					"Undecoded parameter Padding - decoding stopped");
			break;

		case 0x0E:	/* WSP 1.3 encoding - Max-Age: Delta-seconds-value */
			DebugLog(("Skipping remaining parameters from here\n"));
			tvb_ensure_bytes_exist(tvb, start, offset - start);
			proto_tree_add_text(tree, tvb, start, offset - start,
					"Undecoded parameter Max-Age - decoding stopped");
			break;

		case 0x10:	/* WSP 1.3 encoding - Secure: No-value */
			DebugLog(("Skipping remaining parameters from here\n"));
			tvb_ensure_bytes_exist(tvb, start, offset - start);
			proto_tree_add_text(tree, tvb, start, offset - start,
					"Undecoded parameter Secure - decoding stopped");
			break;

		case 0x13:	/* WSP 1.4 encoding - Creation-date: Date-value */
			DebugLog(("Skipping remaining parameters from here\n"));
			tvb_ensure_bytes_exist(tvb, start, offset - start);
			proto_tree_add_text(tree, tvb, start, offset - start,
					"Undecoded parameter Creation-Date - decoding stopped");
			break;

		case 0x14:	/* WSP 1.4 encoding - Modification-date: Date-value */
			DebugLog(("Skipping remaining parameters from here\n"));
			tvb_ensure_bytes_exist(tvb, start, offset - start);
			proto_tree_add_text(tree, tvb, start, offset - start,
					"Undecoded parameter Modification-Date - decoding stopped");
			break;

		case 0x15:	/* WSP 1.4 encoding - Read-date: Date-value */
			DebugLog(("Skipping remaining parameters from here\n"));
			tvb_ensure_bytes_exist(tvb, start, offset - start);
			proto_tree_add_text(tree, tvb, start, offset - start,
					"Undecoded parameter Read-Date - decoding stopped");
			break;

		default:
			DebugLog(("Skipping remaining parameters from here\n"));
			tvb_ensure_bytes_exist(tvb, start, offset - start);
			proto_tree_add_text(tree, tvb, start, offset - start,
					"Undecoded parameter type 0x%02x - decoding stopped",
					type);
			offset = start + len; /* Skip the parameters */
			break;
	}
	DebugLog(("parameter() - Typed - End\n"));
	return offset;
}


/*
 * Dissects the Q-value parameter value.
 *
 * Returns: next offset
 */
static int
parameter_value_q (proto_tree *tree, proto_item *ti, tvbuff_t *tvb, int start)
{
	int offset = start;
	guint32 val = 0, val_len;
	gchar *str = NULL, *s = NULL;
	guint8 ok;

	get_uintvar_integer (val, tvb, offset, val_len, ok);
	if (ok && (val < 1100)) {
		if (val <= 100) { /* Q-value in 0.01 steps */
			str = g_strdup_printf("0.%02u", val - 1);
		} else { /* Q-value in 0.001 steps */
			str = g_strdup_printf("0.%03u", val - 100);
		}
		s = g_strdup_printf("; q=%s", str);
		proto_item_append_string (ti, s);
		g_free(s);
		proto_tree_add_string (tree, hf_parameter_q,
				tvb, start, val_len, str);
		g_free(str);
		offset += val_len;
	} else {
		proto_tree_add_text (tree, tvb, start, offset,
				InvalidParameterValue("Q", "Q-value"));
		offset += val_len;
	}
	return offset;
}


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
	guint8 flags;
	proto_item *ti;
	proto_tree *addresses_tree = NULL;
	proto_tree *addr_tree = NULL;
	proto_tree *flags_tree;
	guint8 bearer_type;
	guint8 address_flags_len;
	int address_len;
	proto_tree *address_flags_tree;
	guint16 port_num;
	guint32 address_ipv4;
	struct e_in6_addr address_ipv6;
	address redir_address;
	conversation_t *conv;
	guint32 index = 0; /* Address index */
	guint32 address_record_len; /* Length of the entire address record */

	/*
	 * Redirect flags.
	 */
	flags = tvb_get_guint8 (tvb, offset);
	if (tree) {
		ti = proto_tree_add_uint (tree, hf_wsp_redirect_flags,
		    tvb, offset, 1, flags);
		flags_tree = proto_item_add_subtree (ti, ett_redirect_flags);
		proto_tree_add_boolean (flags_tree, hf_wsp_redirect_permanent,
		    tvb, offset, 1, flags);
		proto_tree_add_boolean (flags_tree, hf_wsp_redirect_reuse_security_session,
		    tvb, offset, 1, flags);
	}
	offset++;

	/*
	 * Redirect addresses.
	 */
	if (tree) {
		ti = proto_tree_add_item(tree, hf_redirect_addresses,
				tvb, 0, -1, bo_little_endian);
		addresses_tree = proto_item_add_subtree(ti, ett_addresses);
	}

	while (tvb_reported_length_remaining (tvb, offset) > 0) {
		index++;
		/*
		 * Read a single address at a time.
		 */
		address_flags_len = tvb_get_guint8 (tvb, offset);
		address_len = address_flags_len & ADDRESS_LEN;
		address_record_len = address_len
			+ (address_flags_len & BEARER_TYPE_INCLUDED ? 1 : 0)
			+ (address_flags_len & PORT_NUMBER_INCLUDED ? 2 : 0)
		;

		if (tree) {
			ti = proto_tree_add_uint(addresses_tree, hf_address_entry,
					tvb, offset, 1 + address_record_len, index);
			addr_tree = proto_item_add_subtree(ti, ett_address);

			ti = proto_tree_add_uint (addr_tree, hf_address_flags_length,
			    tvb, offset, 1, address_flags_len);
			address_flags_tree = proto_item_add_subtree (ti, ett_address_flags);
			proto_tree_add_boolean (address_flags_tree, hf_address_flags_length_bearer_type_included,
			    tvb, offset, 1, address_flags_len);
			proto_tree_add_boolean (address_flags_tree, hf_address_flags_length_port_number_included,
			    tvb, offset, 1, address_flags_len);
			proto_tree_add_uint (address_flags_tree, hf_address_flags_length_address_len,
			    tvb, offset, 1, address_flags_len);
		}
		offset++;
		if (address_flags_len & BEARER_TYPE_INCLUDED) {
			bearer_type = tvb_get_guint8 (tvb, offset);
			if (tree) {
				proto_tree_add_uint (addr_tree, hf_address_bearer_type,
				    tvb, offset, 1, bearer_type);
			}
			offset++;
		} else {
			bearer_type = 0x00;	/* XXX */
		}
		if (address_flags_len & PORT_NUMBER_INCLUDED) {
			port_num = tvb_get_ntohs (tvb, offset);
			if (tree) {
				proto_tree_add_uint (addr_tree, hf_address_port_num,
				    tvb, offset, 2, port_num);
			}
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
			conv = find_conversation(pinfo->fd->num, &redir_address, &pinfo->dst,
			    PT_UDP, port_num, 0, NO_PORT_B);
			if (conv == NULL) { /* This conversation does not exist yet */
				conv = conversation_new(pinfo->fd->num, &redir_address,
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
				    tvb, offset, 16, (guint8 *)&address_ipv6);
			}

			/*
			 * Create a conversation so that the
			 * redirected session will be dissected
			 * as WAP.
			 */
			redir_address.type = AT_IPv6;
			redir_address.len = 16;
			redir_address.data = (const guint8 *)&address_ipv4;
			/* Find a conversation based on redir_address and pinfo->dst */
			conv = find_conversation(pinfo->fd->num, &redir_address, &pinfo->dst,
			    PT_UDP, port_num, 0, NO_PORT_B);
			if (conv == NULL) { /* This conversation does not exist yet */
				conv = conversation_new(pinfo->fd->num, &redir_address,
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
							tvb, offset, address_len, bo_little_endian);
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
	proto_item *ti;
	proto_tree *addresses_tree;
	proto_tree *addr_tree;
	guint8 bearer_type;
	guint8 address_flags_len;
	int address_len;
	proto_tree *address_flags_tree;
	guint16 port_num;
	guint32 address_ipv4;
	struct e_in6_addr address_ipv6;
	guint32 tvb_len = tvb_length(tvb);
	guint32 offset = 0;
	guint32 index = 0; /* Address index */
	guint32 address_record_len; /* Length of the entire address record */

	/* Skip needless processing */
	if (! tree)
		return;
	if (offset >= tvb_len)
		return;

	/*
	 * Addresses.
	 */
	ti = proto_tree_add_item(tree, hf, tvb, 0, -1, bo_little_endian);
	addresses_tree = proto_item_add_subtree(ti, ett_addresses);

	while (offset < tvb_len) {
		index++;
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
				tvb, offset, 1 + address_record_len, index);
		addr_tree = proto_item_add_subtree(ti, ett_address);

		ti = proto_tree_add_uint (addr_tree, hf_address_flags_length,
				tvb, offset, 1, address_flags_len);
		address_flags_tree = proto_item_add_subtree (ti, ett_address_flags);
		proto_tree_add_boolean (address_flags_tree, hf_address_flags_length_bearer_type_included,
				tvb, offset, 1, address_flags_len);
		proto_tree_add_boolean (address_flags_tree, hf_address_flags_length_port_number_included,
				tvb, offset, 1, address_flags_len);
		proto_tree_add_uint (address_flags_tree, hf_address_flags_length_address_len,
				tvb, offset, 1, address_flags_len);
		offset++;
		if (address_flags_len & BEARER_TYPE_INCLUDED) {
			bearer_type = tvb_get_guint8 (tvb, offset);
			proto_tree_add_uint (addr_tree, hf_address_bearer_type,
					tvb, offset, 1, bearer_type);
			offset++;
		} else {
			bearer_type = 0x00;	/* XXX */
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
			port_num = 0;
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
			proto_tree_add_ipv4 (addr_tree, hf_address_ipv4_addr,
					tvb, offset, 4, address_ipv4);
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
			proto_tree_add_ipv6 (addr_tree, hf_address_ipv6_addr,
					tvb, offset, 16, (guint8 *)&address_ipv6);
			break;

		unknown_address_type:
		default:
			if (address_len != 0) {
				proto_tree_add_item (addr_tree, hf_address_addr,
						tvb, offset, address_len, bo_little_endian);
			}
			break;
		}
		offset += address_len;
	} /* while */
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
static void
dissect_sir(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 version;
	guint32 val_len;
	guint32 len;
	guint32 offset = 0;
	guint32 i;
	tvbuff_t *tmp_tvb;
	proto_tree *subtree;
	proto_item *ti;

	if (check_col(pinfo->cinfo, COL_INFO))
	{ /* Append status code to INFO column */
		col_append_fstr(pinfo->cinfo, COL_INFO,
				": WAP Session Initiation Request");
	}

	/* The remainder of the code adds items to the protocol tree */
	if (! tree)
		return;

	ti = proto_tree_add_item(tree, hf_sir_section,
			tvb, 0, -1, bo_little_endian);
	subtree = proto_item_add_subtree(ti, ett_sir);

	/* Version */
	version = tvb_get_guint8(tvb, 0);
	proto_tree_add_uint(subtree, hf_sir_version,
			tvb, 0, 1, version);

	/* Length of Application-Id headers list */
	val_len = tvb_get_guintvar(tvb, 1, &len);
	proto_tree_add_uint(subtree, hf_sir_app_id_list_len,
			tvb, 1, len, val_len);
	offset = 1 + len;
	/* Application-Id headers */
	tmp_tvb = tvb_new_subset(tvb, offset, val_len, val_len);
	add_headers (subtree, tmp_tvb, hf_sir_app_id_list, pinfo);
	offset += val_len;

	/* Length of WSP contact points list */
	val_len = tvb_get_guintvar(tvb, offset, &len);
	proto_tree_add_uint(subtree, hf_sir_wsp_contact_points_len,
			tvb, offset, len, val_len);
	offset += len;
	/* WSP contact point list */
	tmp_tvb = tvb_new_subset (tvb, offset, val_len, val_len);
	add_addresses(subtree, tmp_tvb, hf_sir_wsp_contact_points);
	tvb_free(tmp_tvb);

	/* End of version 0 SIR content */
	if (version == 0)
		return;

	offset += val_len;

	/* Length of non-WSP contact points list */
	val_len = tvb_get_guintvar(tvb, offset, &len);
	proto_tree_add_uint(subtree, hf_sir_contact_points_len,
			tvb, offset, len, val_len);
	offset += len;
	/* Non-WSP contact point list */
	tmp_tvb = tvb_new_subset (tvb, offset, val_len, val_len);
	add_addresses(subtree, tmp_tvb, hf_sir_contact_points);
	tvb_free(tmp_tvb);

	offset += val_len;

	/* Number of entries in the Protocol Options list */
	val_len = tvb_get_guintvar(tvb, offset, &len);
	proto_tree_add_uint(subtree, hf_sir_protocol_options_len,
			tvb, offset, len, val_len);
	offset += len;
	/* Protocol Options list.
	 * Each protocol option is encoded as a guintvar */
	for (i = 0; i < val_len; i++) {
		val_len = tvb_get_guintvar(tvb, offset, &len);
		proto_tree_add_uint(subtree, hf_sir_protocol_options,
				tvb, offset, len, val_len);
		offset += len;
	}

	/* Length of ProvURL */
	val_len = tvb_get_guintvar(tvb, offset, &len);
	proto_tree_add_uint(subtree, hf_sir_prov_url_len,
			tvb, offset, len, val_len);
	offset += len;
	/* ProvURL */
	tvb_ensure_bytes_exist(tvb, offset, val_len);
	ti = proto_tree_add_item (tree, hf_sir_prov_url,
			tvb, offset, val_len, bo_little_endian);
	offset += val_len;

	/* Number of entries in the CPITag list */
	val_len = tvb_get_guintvar(tvb, offset, &len);
	proto_tree_add_uint(subtree, hf_sir_cpi_tag_len,
			tvb, offset, len, val_len);
	offset += len;
	/* CPITag list.
	 * Each CPITag is encoded as 4 octets of opaque data.
	 * In OTA-HTTP, it is conveyed in the X-Wap-CPITag header
	 * but with a Base64 encoding of the 4 bytes. */
	for (i = 0; i < val_len; i++) {
		val_len = tvb_get_guintvar(tvb, offset, &len);
		proto_tree_add_item(subtree, hf_sir_cpi_tag,
				tvb, offset, 4, val_len);
		offset += 4;
	}
}

static void
dissect_wsp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    dissector_handle_t dissector_handle, gboolean is_connectionless)
{
	int offset = 0;

	guint8 pdut;
	guint count = 0;
	guint value = 0;
	guint uriLength = 0;
	guint uriStart = 0;
	guint capabilityLength = 0;
	guint capabilityStart = 0;
	guint headersLength = 0;
	guint headerLength = 0;
	guint headerStart = 0;
	guint nextOffset = 0;
	guint contentTypeStart = 0;
	guint contentType = 0;
	const char *contentTypeStr;
	tvbuff_t *tmp_tvb;
	gboolean found_match;

/* Set up structures we will need to add the protocol subtree and manage it */
	proto_item *ti;
	proto_item *proto_ti = NULL; /* for the proto entry */
	proto_tree *wsp_tree = NULL;

	wsp_info_value_t *stat_info;
	stat_info = g_malloc( sizeof(wsp_info_value_t) );
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
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "WSP %s (0x%02x)",
				val_to_str (pdut, vals_pdu_type, "Unknown PDU type (0x%02x)"),
				pdut);
	};

	/* In the interest of speed, if "tree" is NULL, don't do any work not
	 * necessary to generate protocol tree items. */
	if (tree) {
		proto_ti = proto_tree_add_item(tree, proto_wsp,
				tvb, 0, -1, bo_little_endian);
		wsp_tree = proto_item_add_subtree(proto_ti, ett_wsp);
		proto_item_append_text(proto_ti, ", Method: %s (0x%02x)",
				val_to_str (pdut, vals_pdu_type, "Unknown (0x%02x)"),
				pdut);

		/* Add common items: only TID and PDU Type */

		/* If this is connectionless, then the TID Field is always first */
		if (is_connectionless)
		{
			ti = proto_tree_add_item (wsp_tree, hf_wsp_header_tid,
					tvb, 0, 1, bo_little_endian);
		}
		ti = proto_tree_add_item( wsp_tree, hf_wsp_header_pdu_type,
				tvb, offset, 1, bo_little_endian);
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
			if (tree) {
				if (pdut == WSP_PDU_CONNECT)
				{
					ti = proto_tree_add_item (wsp_tree, hf_wsp_version_major,
							tvb, offset, 1, bo_little_endian);
					ti = proto_tree_add_item (wsp_tree, hf_wsp_version_minor,
							tvb, offset, 1, bo_little_endian);
					{
						guint8 ver = tvb_get_guint8(tvb, offset);
						proto_item_append_text(proto_ti, ", Version: %u.%u",
								ver >> 4, ver & 0x0F);
					}
					offset++;
				} else {
					count = 0;	/* Initialise count */
					value = tvb_get_guintvar (tvb, offset, &count);
					ti = proto_tree_add_uint (wsp_tree,
							hf_wsp_server_session_id,
							tvb, offset, count, value);
					proto_item_append_text(proto_ti, ", Session ID: %u", value);
					offset += count;
				}
				capabilityStart = offset;
				count = 0;	/* Initialise count */
				capabilityLength = tvb_get_guintvar (tvb, offset, &count);
				offset += count;
				ti = proto_tree_add_uint (wsp_tree, hf_capabilities_length,
						tvb, capabilityStart, count, capabilityLength);

				if (pdut != WSP_PDU_RESUME)
				{
					count = 0;	/* Initialise count */
					headerLength = tvb_get_guintvar (tvb, offset, &count);
					ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,
							tvb, offset, count, headerLength);
					offset += count;
					capabilityStart = offset;
					headerStart = capabilityStart + capabilityLength;
				} else {
						/* Resume computes the headerlength
						 * by remaining bytes */
					capabilityStart = offset;
					headerStart = capabilityStart + capabilityLength;
					headerLength = tvb_reported_length_remaining (tvb,
							headerStart);
				}
				if (capabilityLength > 0)
				{
					tmp_tvb = tvb_new_subset (tvb, offset,
							capabilityLength, capabilityLength);
					add_capabilities (wsp_tree, tmp_tvb, pdut);
					offset += capabilityLength;
				}

				if (headerLength > 0)
				{
					tmp_tvb = tvb_new_subset (tvb, offset,
							headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
				}
			} /* if (tree) */

			break;

		case WSP_PDU_REDIRECT:
			dissect_redirect(tvb, offset, pinfo, wsp_tree, dissector_handle);
			break;

		case WSP_PDU_DISCONNECT:
		case WSP_PDU_SUSPEND:
			if (tree) {
				count = 0;	/* Initialise count */
				value = tvb_get_guintvar (tvb, offset, &count);
				ti = proto_tree_add_uint (wsp_tree,
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
			count = 0;	/* Initialise count */
			/* Length of URI and size of URILen field */
			value = tvb_get_guintvar (tvb, offset, &count);
			nextOffset = offset + count;
			add_uri (wsp_tree, pinfo, tvb, offset, nextOffset, proto_ti);
			if (tree) {
				offset += value + count; /* VERIFY */
				tmp_tvb = tvb_new_subset (tvb, offset, -1, -1);
				add_headers (wsp_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
			}
			break;

		case WSP_PDU_POST:
		case WSP_PDU_PUT:
			uriStart = offset;
			count = 0;	/* Initialise count */
			uriLength = tvb_get_guintvar (tvb, offset, &count);
			headerStart = uriStart+count;
			count = 0;	/* Initialise count */
			headersLength = tvb_get_guintvar (tvb, headerStart, &count);
			offset = headerStart + count;

			add_uri (wsp_tree, pinfo, tvb, uriStart, offset, proto_ti);
			offset += uriLength;

			if (tree)
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,
						tvb, headerStart, count, headersLength);

			/* Stop processing POST PDU if length of headers is zero;
			 * this should not happen as we expect at least Content-Type. */
			if (headersLength == 0)
				break;

			contentTypeStart = offset;
			nextOffset = add_content_type (wsp_tree,
					tvb, offset, &contentType, &contentTypeStr);

			if (tree) {
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
					tmp_tvb = tvb_new_subset (tvb, nextOffset,
							headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
				}
				/* XXX - offset is no longer used after this point */
				offset = nextOffset+headerLength;
			}
			/* WSP_PDU_POST data - First check whether a subdissector exists
			 * for the content type */
			if (tvb_reported_length_remaining(tvb,
						headerStart + count + uriLength + headersLength) > 0)
			{
				tmp_tvb = tvb_new_subset (tvb,
						headerStart + count + uriLength + headersLength,
						-1, -1);
				/*
				 * Try finding a dissector for the content
				 * first, then fallback.
				 */
				found_match = FALSE;
				if (contentTypeStr) {
					/*
					 * Content type is a string.
					 */
					found_match = dissector_try_string(media_type_table,
							contentTypeStr, tmp_tvb, pinfo, tree);
				}
				if (! found_match) {
					if (! dissector_try_heuristic(heur_subdissector_list,
								tmp_tvb, pinfo, tree)) {
						guint8* save_private_data = pinfo->private_data;

						pinfo->match_string = contentTypeStr;
						pinfo->private_data = NULL; /* TODO: parameters */
						call_dissector(media_handle, tmp_tvb, pinfo, tree);
						pinfo->private_data = save_private_data;
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
			count = 0;	/* Initialise count */
			headersLength = tvb_get_guintvar (tvb, offset+1, &count);
			headerStart = offset + count + 1;
			{
				guint8 reply_status = tvb_get_guint8(tvb, offset);
				const char *reply_status_str;

				reply_status_str = val_to_str (reply_status, vals_status, "(Unknown response status)");
				if (tree) {
					ti = proto_tree_add_item (wsp_tree, hf_wsp_header_status,
							tvb, offset, 1, bo_little_endian);
					proto_item_append_text(proto_ti, ", Status: %s (0x%02x)",
							reply_status_str, reply_status);
				}
				stat_info->status_code = (gint) reply_status;
				if (check_col(pinfo->cinfo, COL_INFO))
				{ /* Append status code to INFO column */
					col_append_fstr(pinfo->cinfo, COL_INFO,
							": %s (0x%02x)",
							reply_status_str, reply_status);
				}
			}
			nextOffset = offset + 1 + count;
			if (tree)
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,
						tvb, offset + 1, count, headersLength);

			if (headersLength == 0)
				break;

			contentTypeStart = nextOffset;
			nextOffset = add_content_type (wsp_tree, tvb,
					nextOffset, &contentType, &contentTypeStr);

			if (tree) {
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
					tmp_tvb = tvb_new_subset (tvb, nextOffset,
							headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
				}
				/* XXX - offset is no longer used after this point */
				offset += count+headersLength+1;
			}
			/* WSP_PDU_REPLY data - First check whether a subdissector exists
			 * for the content type */
			if (tvb_reported_length_remaining(tvb, headerStart + headersLength)
					> 0)
			{
				tmp_tvb = tvb_new_subset (tvb, headerStart + headersLength,
						-1, -1);
				/*
				 * Try finding a dissector for the content
				 * first, then fallback.
				 */
				found_match = FALSE;
				if (contentTypeStr) {
					/*
					 * Content type is a string.
					 */
					found_match = dissector_try_string(media_type_table,
							contentTypeStr, tmp_tvb, pinfo, tree);
				}
				if (! found_match) {
					if (! dissector_try_heuristic(heur_subdissector_list,
								tmp_tvb, pinfo, tree)) {
						guint8* save_private_data = pinfo->private_data;

						pinfo->match_string = contentTypeStr;
						pinfo->private_data = NULL; /* TODO: parameters */
						call_dissector(media_handle, tmp_tvb, pinfo, tree);
						pinfo->private_data = save_private_data;
#if 0
						if (tree) / * Only display if needed * /
							ti = proto_tree_add_item (wsp_tree,
							    hf_wsp_reply_data,
							    tmp_tvb, 0, -1, bo_little_endian);
#endif
					}
				}
			}
			break;

		case WSP_PDU_PUSH:
		case WSP_PDU_CONFIRMEDPUSH:
			count = 0;	/* Initialise count */
			headersLength = tvb_get_guintvar (tvb, offset, &count);
			headerStart = offset + count;

			if (tree)
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,
						tvb, offset, count, headersLength);

			if (headersLength == 0)
				break;

			offset += count;
			contentTypeStart = offset;
			nextOffset = add_content_type (wsp_tree,
					tvb, offset, &contentType, &contentTypeStr);

			if (tree) {
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
					tmp_tvb = tvb_new_subset (tvb, nextOffset,
							headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
				}
				/* XXX - offset is no longer used after this point */
				offset += headersLength;
			}
			/* WSP_PDU_PUSH data - First check whether a subdissector exists
			 * for the content type */
			if (tvb_reported_length_remaining(tvb, headerStart + headersLength)
					> 0)
			{
				tmp_tvb = tvb_new_subset (tvb, headerStart + headersLength,
						-1, -1);
				/*
				 * Try finding a dissector for the content
				 * first, then fallback.
				 */
				found_match = FALSE;
				if (contentTypeStr) {
					/*
					 * Content type is a string.
					 */
					/*
					if (strcasecmp(contentTypeStr, "application/vnd.wap.sia") == 0) {
						dissect_sir(tree, tmp_tvb);
					} else
					*/
					found_match = dissector_try_string(media_type_table,
							contentTypeStr, tmp_tvb, pinfo, tree);
				}
				if (! found_match) {
					if (! dissector_try_heuristic(heur_subdissector_list,
								tmp_tvb, pinfo, tree)) {
						guint8* save_private_data = pinfo->private_data;

						pinfo->match_string = contentTypeStr;
						pinfo->private_data = NULL; /* TODO: parameters */
						call_dissector(media_handle, tmp_tvb, pinfo, tree);
						pinfo->private_data = save_private_data;
#if 0
						if (tree) /* Only display if needed */
							ti = proto_tree_add_item (wsp_tree,
									hf_wsp_push_data,
									tmp_tvb, 0, -1, bo_little_endian);
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
static void
dissect_wsp_fromudp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "WSP" );
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	dissect_wsp_common(tvb, pinfo, tree, wsp_fromudp_handle, TRUE);
}


/*
 * Called from a higher-level WAP dissector, in connection-oriented mode.
 * Leave the "Protocol" column alone - the dissector calling us should
 * have set it.
 */
static void
dissect_wsp_fromwap_co(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/*
	 * XXX - what about WTLS->WTP->WSP?
	 */
	dissect_wsp_common(tvb, pinfo, tree, wtp_fromudp_handle, FALSE);
}


/*
 * Called from a higher-level WAP dissector, in connectionless mode.
 * Leave the "Protocol" column alone - the dissector calling us should
 * have set it.
 */
static void
dissect_wsp_fromwap_cl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/*
	 * XXX - what about WTLS->WSP?
	 */
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_clear(pinfo->cinfo, COL_INFO);
	}
	dissect_wsp_common(tvb, pinfo, tree, wtp_fromudp_handle, TRUE);
}


static void
add_uri (proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
		guint URILenOffset, guint URIOffset, proto_item *proto_ti)
{
	proto_item *ti;

	guint count = 0;
	guint uriLen = tvb_get_guintvar (tvb, URILenOffset, &count);
	gchar *str = NULL;

	if (tree)
		ti = proto_tree_add_uint (tree, hf_wsp_header_uri_len,
				tvb, URILenOffset, count, uriLen);

	tvb_ensure_bytes_exist(tvb, URIOffset, uriLen);
	if (tree)
		ti = proto_tree_add_item (tree, hf_wsp_header_uri,
				tvb, URIOffset, uriLen, bo_little_endian);

	str = tvb_format_text (tvb, URIOffset, uriLen);
	/* XXX - tvb_format_text() returns a pointer to a static text string
	 * so please DO NOT attempt at g_free()ing it!
	 */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s", str);
	}
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

static void
add_capabilities (proto_tree *tree, tvbuff_t *tvb, guint8 pdu_type)
{
	proto_tree *wsp_capabilities;
	proto_tree *capa_subtree;
	proto_item *ti;
	char *capaName, *str, *valStr;
	guint32 offset = 0;
	guint32 len = 0;
	guint32 capaStart = 0;		/* Start offset of the capability */
	guint32 capaLen = 0;		/* Length of the entire capability */
	guint32 capaValueLen = 0;	/* Length of the capability value & type */
	guint32 tvb_len = tvb_reported_length(tvb);
	gboolean ok = FALSE;
	guint8 peek;
	guint32 value;

	if (tvb_len == 0) {
		DebugLog(("add_capabilities(): Capabilities = 0\n"));
		return;
	}

	DebugLog(("add_capabilities(): capabilities to process\n"));

	ti = proto_tree_add_item(tree, hf_capabilities_section,
			tvb, 0, tvb_len, bo_little_endian);
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
		capaValueLen = tvb_get_guintvar(tvb, offset, &len);
		capaLen = capaValueLen + len;
		tvb_ensure_bytes_exist(tvb, offset, capaLen);
		offset += len;
		/*
		 * Now offset points to the 1st byte of the capability type.
		 * Get the capability identifier.
		 */
		peek = tvb_get_guint8(tvb, offset);
		if (is_token_text(peek)) { /* Literal capability name */
			/* 1. Get the string from the tvb */
			get_token_text(capaName, tvb, offset, len, ok);
			if (! ok) {
				DebugLog(("add_capabilities(): expecting capability name as token_text "
							"at offset %u (1st char = 0x%02x)\n", offset, peek));
				return;
			}
			/* 2. Look up the string capability name */
			if (strcasecmp(capaName, "client-sdu-size") == 0) {
				peek = WSP_CAPA_CLIENT_SDU_SIZE;
			} else if (strcasecmp(capaName, "server-sdu-size") == 0) {
				peek = WSP_CAPA_SERVER_SDU_SIZE;
			} else if (strcasecmp(capaName, "protocol options") == 0) {
				peek = WSP_CAPA_PROTOCOL_OPTIONS;
			} else if (strcasecmp(capaName, "method-mor") == 0) {
				peek = WSP_CAPA_METHOD_MOR;
			} else if (strcasecmp(capaName, "push-mor") == 0) {
				peek = WSP_CAPA_PUSH_MOR;
			} else if (strcasecmp(capaName, "extended methods") == 0) {
				peek = WSP_CAPA_EXTENDED_METHODS;
			} else if (strcasecmp(capaName, "header code pages") == 0) {
				peek = WSP_CAPA_HEADER_CODE_PAGES;
			} else if (strcasecmp(capaName, "aliases") == 0) {
				peek = WSP_CAPA_ALIASES;
			} else if (strcasecmp(capaName, "client-message-size") == 0) {
				peek = WSP_CAPA_CLIENT_MESSAGE_SIZE;
			} else if (strcasecmp(capaName, "server-message-size") == 0) {
				peek = WSP_CAPA_SERVER_MESSAGE_SIZE;
			} else {
				DebugLog(("add_capabilities(): unknown capability '%s' at offset %u\n",
							capaName, offset));
				proto_tree_add_text(wsp_capabilities, tvb, capaStart, capaLen,
						"Unknown or invalid textual capability: %s", capaName);
				g_free(capaName);
				/* Skip this capability */
				offset = capaStart + capaLen;
				continue;
			}
			g_free(capaName);
			offset += len;
			/* Now offset points to the 1st value byte of the capability. */
		} else if (peek < 0x80) {
			DebugLog(("add_capabilities(): invalid capability type identifier 0x%02X at offset %u.",
						peek, offset - 1));
			proto_tree_add_text(wsp_capabilities, tvb, capaStart, capaLen,
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
		/* Now the capability type is known */
		switch (peek) {
			case WSP_CAPA_CLIENT_SDU_SIZE:
				value = tvb_get_guintvar(tvb, offset, &len);
				DebugLog(("add_capabilities(client-sdu-size): "
							"guintvar = %u (0x%X) at offset %u (1st byte = 0x%02X) (len = %u)\n",
							value, value, offset, tvb_get_guint8(tvb, offset), len));
				proto_tree_add_uint(wsp_capabilities, hf_capa_client_sdu_size,
						tvb, capaStart, capaLen, value);
				break;
			case WSP_CAPA_SERVER_SDU_SIZE:
				value = tvb_get_guintvar(tvb, offset, &len);
				DebugLog(("add_capabilities(server-sdu-size): "
							"guintvar = %u (0x%X) at offset %u (1st byte = 0x%02X) (len = %u)\n",
							value, value, offset, tvb_get_guint8(tvb, offset), len));
				proto_tree_add_uint(wsp_capabilities, hf_capa_server_sdu_size,
						tvb, capaStart, capaLen, value);
				break;
			case WSP_CAPA_PROTOCOL_OPTIONS:
				ti = proto_tree_add_string(wsp_capabilities, hf_capa_protocol_options,
						tvb, capaStart, capaLen, "");
				capa_subtree = proto_item_add_subtree(ti, ett_capability);
				/*
				 * The bits are stored in one or more octets, not an
				 * uintvar-integer! Note that capability name and value
				 * have length capaValueLength, and that the capability
				 * name has length = len. Hence the remaining length is
				 * given by capaValueLen - len.
				 */
				switch (capaValueLen - len) {
					case 1:
						value = tvb_get_guint8(tvb, offset);
						len = 1;
						break;
					default:
						/*
						 * The WSP spec foresees that this bit field can be
						 * extended in the future. This does not make sense yet.
						 */
							DebugLog(("add_capabilities(protocol options): "
										"bit field too large (%u bytes)\n",
										capaValueLen));
							proto_item_append_text(ti,
									" <warning: bit field too large>");
							offset = capaStart + capaLen;
							continue;
				}
				DebugLog(("add_capabilities(protocol options): "
							"guintvar = %u (0x%X) at offset %u (1st byte = 0x%02X) (len = %u)\n",
							value, value, offset, tvb_get_guint8(tvb, offset), len));
				if (value & 0x80)
					proto_item_append_string(ti, " (confirmed push facility)");
				if (value & 0x40)
					proto_item_append_string(ti, " (push facility)");
				if (value & 0x20)
					proto_item_append_string(ti, " (session resume facility)");
				if (value & 0x10)
					proto_item_append_string(ti, " (acknowledgement headers)");
				if (value & 0x08)
					proto_item_append_string(ti, " (large data transfer)");
				if (value & 0xFFFFFF07)
					proto_item_append_text(ti, " <warning: reserved bits have been set>");
				proto_tree_add_boolean(capa_subtree,
						hf_capa_protocol_option_confirmed_push,
						tvb, offset, len, value);
				proto_tree_add_boolean(capa_subtree,
						hf_capa_protocol_option_push,
						tvb, offset, len, value);
				proto_tree_add_boolean(capa_subtree,
						hf_capa_protocol_option_session_resume,
						tvb, offset, len, value);
				proto_tree_add_boolean(capa_subtree,
						hf_capa_protocol_option_ack_headers,
						tvb, offset, len, value);
				proto_tree_add_boolean(capa_subtree,
						hf_capa_protocol_option_large_data_transfer,
						tvb, offset, len, value);
				break;
			case WSP_CAPA_METHOD_MOR:
				value = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint (wsp_capabilities,
						hf_capa_method_mor,
						tvb, capaStart, capaLen, value);
				break;
			case WSP_CAPA_PUSH_MOR:
				value = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint (wsp_capabilities,
						hf_capa_push_mor,
						tvb, capaStart, capaLen, value);
				break;
			case WSP_CAPA_EXTENDED_METHODS:
				/* Extended Methods capability format:
				 * Connect PDU: collection of { Method (octet), Method-name (Token-text) }
				 * ConnectReply PDU: collection of accepted { Method (octet) }
				 */
				ti = proto_tree_add_string(wsp_capabilities,
						hf_capa_extended_methods,
						tvb, capaStart, capaLen, "");
				if (pdu_type == WSP_PDU_CONNECT) {
					while (offset < capaStart + capaLen) {
						peek = tvb_get_guint8(tvb, offset++);
						get_text_string(str, tvb, offset, len, ok);
						if (! ok) {
							proto_item_append_text(ti, " <error: invalid capability encoding>");
							DebugLog(("add_capability(extended methods): "
										"invalid method name at offset %u "
										"(octet = 0x%02X)\n",
										offset, tvb_get_guint8(tvb, offset)));
							return;
						}
						valStr = g_strdup_printf(" (0x%02x = %s)", peek, str);
						DebugLog(("add_capabilities(extended methods):%s\n",
									valStr));
						proto_item_append_string(ti, valStr);
						g_free(valStr);
						g_free(str);
						offset += len;
					}
				} else {
					while (offset < capaStart + capaLen) {
						peek = tvb_get_guint8(tvb, offset++);
						valStr = g_strdup_printf(" (0x%02x)", peek);
						DebugLog(("add_capabilities(extended methods):%s\n",
									valStr));
						proto_item_append_string(ti, valStr);
						g_free(valStr);
					}
				}
				break;
			case WSP_CAPA_HEADER_CODE_PAGES:
				/* Header Code Pages capability format:
				 * Connect PDU: collection of { Page-id (octet), Page-name (Token-text) }
				 * ConnectReply PDU: collection of accepted { Page-id (octet) }
				 */
				ti = proto_tree_add_string(wsp_capabilities,
						hf_capa_header_code_pages,
						tvb, capaStart, capaLen, "");
				if (pdu_type == WSP_PDU_CONNECT) {
					while (offset < capaStart + capaLen) {
						peek = tvb_get_guint8(tvb, offset++);
						get_text_string(str, tvb, offset, len, ok);
						if (! ok) {
							proto_item_append_text(ti,
									" <error: invalid capability encoding>");
							DebugLog(("add_capability(header code pages): "
										"invalid header code page name at offset %u "
										"(octet = 0x%02X)\n",
										offset, tvb_get_guint8(tvb, offset)));
							return;
						}
						valStr = g_strdup_printf(" (0x%02x = %s)", peek, str);
						DebugLog(("add_capabilities(header code pages):%s\n",
									valStr));
						proto_item_append_string(ti, valStr);
						g_free(valStr);
						g_free(str);
						offset += len;
					}
				} else {
					while (offset < capaStart + capaLen) {
						peek = tvb_get_guint8(tvb, offset++);
						valStr = g_strdup_printf(" (0x%02x)", peek);
						DebugLog(("add_capabilities(header code pages):%s\n",
									valStr));
						proto_item_append_string(ti, valStr);
						g_free(valStr);
					}
				}
				break;
			case WSP_CAPA_ALIASES:
				/* TODO - same format as redirect addresses */
				proto_tree_add_item(wsp_capabilities, hf_capa_aliases,
						tvb, capaStart, capaLen, bo_little_endian);
				break;
			case WSP_CAPA_CLIENT_MESSAGE_SIZE:
				value = tvb_get_guintvar(tvb, offset, &len);
				DebugLog(("add_capabilities(client-message-size): "
							"guintvar = %u (0x%X) at offset %u (1st byte = 0x%02X) (len = %u)\n",
							value, value, offset, tvb_get_guint8(tvb, offset), len));
				proto_tree_add_uint(wsp_capabilities, hf_capa_client_message_size,
						tvb, capaStart, capaLen, value);
				break;
			case WSP_CAPA_SERVER_MESSAGE_SIZE:
				value = tvb_get_guintvar(tvb, offset, &len);
				DebugLog(("add_capabilities(server-message-size): "
							"guintvar = %u (0x%X) at offset %u (1st byte = 0x%02X) (len = %u)\n",
							value, value, offset, tvb_get_guint8(tvb, offset), len));
				proto_tree_add_uint(wsp_capabilities, hf_capa_server_message_size,
						tvb, capaStart, capaLen, value);
				break;
			default:
				proto_tree_add_text(wsp_capabilities, tvb, capaStart, capaLen,
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
	guint offset = 0;
	guint variableStart = 0;
	guint variableEnd = 0;
	guint valueStart = 0;
	guint valueEnd = 0;
	guint8 peek = 0;
	proto_item *ti;
	proto_tree *sub_tree = NULL;

	DebugLog(("add_post_data() - START\n"));

	/* VERIFY ti = proto_tree_add_item (tree, hf_wsp_post_data,tvb,offset,-1,bo_little_endian); */
	if (tree) {
		ti = proto_tree_add_item (tree, hf_wsp_post_data,
				tvb, offset, -1, bo_little_endian);
		sub_tree = proto_item_add_subtree(ti, ett_post);
	}

	if ( (contentTypeStr == NULL && contentType == 0x12)
			|| (contentTypeStr && (strcasecmp(contentTypeStr,
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
					valueEnd = 0;
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
	DebugLog(("add_post_data() - END\n"));
}

static void
add_post_variable (proto_tree *tree, tvbuff_t *tvb, guint variableStart, guint variableEnd, guint valueStart, guint valueEnd)
{
	int variableLength = variableEnd-variableStart;
	int valueLength = 0;
	char *variableBuffer;
	char *valueBuffer;

	variableBuffer = tvb_get_ephemeral_string(tvb, variableStart, variableLength);

	if (valueEnd < valueStart)
	{
		valueBuffer = g_malloc (1);
		valueBuffer[0] = 0;
		valueEnd = valueStart;
	}
	else
	{
		valueLength = valueEnd-valueStart;
		/* XXX - if this throws an exception, "variableBuffer"
		   is leaked */
		valueBuffer = tvb_get_ephemeral_string(tvb, valueStart, valueLength);
	}

	/* Check for variables with no value */
	if (valueStart >= tvb_reported_length (tvb))
	{
		valueStart = tvb_reported_length (tvb);
		valueEnd = valueStart;
	}
	valueLength = valueEnd-valueStart;

	proto_tree_add_text (tree, tvb, variableStart, valueEnd-variableStart, "%s: %s", variableBuffer, valueBuffer);

}

static void
add_multipart_data (proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo)
{
	int		 offset = 0;
	guint		 nextOffset;
	guint		 nEntries = 0;
	guint		 count;
	guint		 HeadersLen;
	guint		 DataLen;
	guint		 contentType = 0;
	const char	*contentTypeStr;
	tvbuff_t	*tmp_tvb;
	int		 partnr = 1;
	int		 part_start;
	gboolean found_match = FALSE;

	proto_item	*sub_tree = NULL;
	proto_item	*ti = NULL;
	proto_tree	*mpart_tree = NULL;

	DebugLog(("add_multipart_data(): offset = %u, byte = 0x%02x: ",
				offset, tvb_get_guint8(tvb,offset)));
	nEntries = tvb_get_guintvar (tvb, offset, &count);
	DebugLog(("parts = %u\n", nEntries));
	offset += count;
	if (nEntries)
	{
		sub_tree = proto_tree_add_text(tree, tvb, offset - count, 0,
					"Multipart body");
		proto_item_add_subtree(sub_tree, ett_mpartlist);
	}
	while (nEntries--)
	{
		DebugLog(("add_multipart_data(): Parts to do after this: %u"
				" (offset = %u, 0x%02x): ",
				nEntries, offset, tvb_get_guint8(tvb,offset)));
		part_start = offset;
		HeadersLen = tvb_get_guintvar (tvb, offset, &count);
		offset += count;
		DataLen = tvb_get_guintvar (tvb, offset, &count);
		offset += count;
		if (tree) {
			tvb_ensure_bytes_exist(tvb, part_start, HeadersLen + DataLen + (offset - part_start));
			ti = proto_tree_add_uint(sub_tree, hf_wsp_mpart, tvb, part_start,
					HeadersLen + DataLen + (offset - part_start), partnr);
			mpart_tree = proto_item_add_subtree(ti, ett_multiparts);
		}
		nextOffset = add_content_type (mpart_tree, tvb, offset,
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
			tmp_tvb = tvb_new_subset (tvb, nextOffset, HeadersLen, HeadersLen);
			add_headers (mpart_tree, tmp_tvb, hf_wsp_headers_section, pinfo);
		}
		offset = nextOffset + HeadersLen;
		/*
		 * Try the dissectors of the multipart content.
		 *
		 * TODO - handle nested multipart documents.
		 */
		tmp_tvb = tvb_new_subset(tvb, offset, DataLen, DataLen);
		/*
		 * Try finding a dissector for the content
		 * first, then fallback.
		 */
		found_match = FALSE;
		if (contentTypeStr) {
			/*
			 * Content type is a string.
			 */
			found_match = dissector_try_string(media_type_table,
					contentTypeStr, tmp_tvb, pinfo, mpart_tree);
		}
		if (! found_match) {
			if (! dissector_try_heuristic(heur_subdissector_list,
						tmp_tvb, pinfo, mpart_tree)) {
				guint8* save_private_data = pinfo->private_data;

				pinfo->match_string = contentTypeStr;
				pinfo->private_data = NULL; /* TODO: parameters */
				call_dissector(media_handle, tmp_tvb, pinfo, tree);
				pinfo->private_data = save_private_data;
#if 0
				if (tree) /* Only display if needed */
					proto_tree_add_item (mpart_tree, hf_wsp_multipart_data,
							tvb, offset, DataLen, bo_little_endian);
#endif
			}
		}

		offset += DataLen;
		partnr++;
	}
}


/* Register the protocol with Ethereal */
void
proto_register_wsp(void)
{

/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_wsp_header_tid,
			{ 	"Transaction ID",
				"wsp.TID",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"WSP Transaction ID (for connectionless WSP)", HFILL
			}
		},
		{ &hf_wsp_header_pdu_type,
			{ 	"PDU Type",
				"wsp.pdu_type",
				 FT_UINT8, BASE_HEX, VALS( vals_pdu_type ), 0x00,
				"PDU Type", HFILL
			}
		},
		{ &hf_wsp_version_major,
			{ 	"Version (Major)",
				"wsp.version.major",
				 FT_UINT8, BASE_DEC, NULL, 0xF0,
				"Version (Major)", HFILL
			}
		},
		{ &hf_wsp_version_minor,
			{ 	"Version (Minor)",
				"wsp.version.minor",
				 FT_UINT8, BASE_DEC, NULL, 0x0F,
				"Version (Minor)", HFILL
			}
		},
		{ &hf_capabilities_length,
			{ 	"Capabilities Length",
				"wsp.capabilities.length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Length of Capabilities field (bytes)", HFILL
			}
		},
		{ &hf_wsp_header_length,
			{ 	"Headers Length",
				"wsp.headers_length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Length of Headers field (bytes)", HFILL
			}
		},
		{ &hf_capabilities_section,
			{ 	"Capabilities",
				"wsp.capabilities",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Capabilities", HFILL
			}
		},
		{ &hf_wsp_headers_section,
			{ 	"Headers",
				"wsp.headers",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Headers", HFILL
			}
		},
		{ &hf_wsp_header_uri_len,
			{ 	"URI Length",
				"wsp.uri_length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Length of URI field", HFILL
			}
		},
		{ &hf_wsp_header_uri,
			{ 	"URI",
				"wsp.uri",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"URI", HFILL
			}
		},
		{ &hf_wsp_server_session_id,
			{ 	"Server Session ID",
				"wsp.server.session_id",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Server Session ID", HFILL
			}
		},
		{ &hf_wsp_header_status,
			{ 	"Status",
				"wsp.reply.status",
				 FT_UINT8, BASE_HEX, VALS( vals_status ), 0x00,
				"Reply Status", HFILL
			}
		},
		{ &hf_wsp_parameter_type,
			{ 	"Type",
				"wsp.parameter.type",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Type parameter", HFILL
			}
		},
		{ &hf_wsp_parameter_name,
			{ 	"Name",
				"wsp.parameter.name",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Name parameter", HFILL
			}
		},
		{ &hf_wsp_parameter_filename,
			{ 	"Filename",
				"wsp.parameter.filename",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Filename parameter", HFILL
			}
		},
		{ &hf_wsp_parameter_start,
			{ 	"Start",
				"wsp.parameter.start",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Start parameter", HFILL
			}
		},
		{ &hf_wsp_parameter_start_info,
			{ 	"Start-info",
				"wsp.parameter.start_info",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Start-info parameter", HFILL
			}
		},
		{ &hf_wsp_parameter_comment,
			{ 	"Comment",
				"wsp.parameter.comment",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Comment parameter", HFILL
			}
		},
		{ &hf_wsp_parameter_domain,
			{ 	"Domain",
				"wsp.parameter.domain",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Domain parameter", HFILL
			}
		},
		{ &hf_wsp_parameter_path,
			{ 	"Path",
				"wsp.parameter.path",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Path parameter", HFILL
			}
		},
		{ &hf_wsp_parameter_sec,
			{ 	"SEC",
				"wsp.parameter.sec",
				 FT_UINT8, BASE_HEX, VALS (vals_wsp_parameter_sec), 0x00,
				"SEC parameter (Content-Type: application/vnd.wap.connectivity-wbxml)", HFILL
			}
		},
		{ &hf_wsp_parameter_mac,
			{ 	"MAC",
				"wsp.parameter.mac",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"MAC parameter (Content-Type: application/vnd.wap.connectivity-wbxml)", HFILL
			}
		},
		{ &hf_wsp_parameter_upart_type,
			{ 	"Type",
				"wsp.parameter.upart.type",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Multipart type parameter", HFILL
			}
		},
		{ &hf_wsp_parameter_level,
			{ 	"Level",
				"wsp.parameter.level",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Level parameter", HFILL
			}
		},
		{ &hf_wsp_parameter_size,
			{ 	"Size",
				"wsp.parameter.size",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Size parameter", HFILL
			}
		},
		{ &hf_wsp_reply_data,
			{ 	"Data",
				"wsp.reply.data",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"Data", HFILL
			}
		},
		{ &hf_wsp_header_shift_code,
			{ 	"Switching to WSP header code-page",
				"wsp.code_page",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Header code-page shift code", HFILL
			}
		},
		/*
		 * CO-WSP capability negotiation
		 */
		{ &hf_capa_client_sdu_size,
			{	"Client SDU Size",
				"wsp.capability.client_sdu_size",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Client Service Data Unit size (bytes)", HFILL
			}
		},
		{ &hf_capa_server_sdu_size,
			{	"Server SDU Size",
				"wsp.capability.server_sdu_size",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Server Service Data Unit size (bytes)", HFILL
			}
		},
		{ &hf_capa_protocol_options,
			{	"Protocol Options",
				"wsp.capability.protocol_opt",
				 FT_STRING, BASE_HEX, NULL, 0x00,
				"Protocol Options", HFILL
			}
		},
		{ &hf_capa_protocol_option_confirmed_push,
			{	"Confirmed Push facility",
				"wsp.capability.protocol_option.confirmed_push",
				FT_BOOLEAN, 8, NULL, 0x80,
				"If set, this CO-WSP session supports the Confirmed Push facility", HFILL
			}
		},
		{ &hf_capa_protocol_option_push,
			{	"Push facility",
				"wsp.capability.protocol_option.push",
				FT_BOOLEAN, 8, NULL, 0x40,
				"If set, this CO-WSP session supports the Push facility", HFILL
			}
		},
		{ &hf_capa_protocol_option_session_resume,
			{	"Session Resume facility",
				"wsp.capability.protocol_option.session_resume",
				FT_BOOLEAN, 8, NULL, 0x20,
				"If set, this CO-WSP session supports the Session Resume facility", HFILL
			}
		},
		{ &hf_capa_protocol_option_ack_headers,
			{	"Acknowledgement headers",
				"wsp.capability.protocol_option.ack_headers",
				FT_BOOLEAN, 8, NULL, 0x10,
				"If set, this CO-WSP session supports Acknowledgement headers", HFILL
			}
		},
		{ &hf_capa_protocol_option_large_data_transfer,
			{	"Large data transfer",
				"wsp.capability.protocol_option.large_data_transfer",
				FT_BOOLEAN, 8, NULL, 0x08,
				"If set, this CO-WSP session supports Large data transfer", HFILL
			}
		},
		{ &hf_capa_method_mor,
			{	"Method MOR",
				"wsp.capability.method_mor",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Method MOR", HFILL
			}
		},
		{ &hf_capa_push_mor,
			{	"Push MOR",
				"wsp.capability.push_mor",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Push MOR", HFILL
			}
		},
		{ &hf_capa_extended_methods,
			{	"Extended Methods",
				"wsp.capability.extended_methods",
				 FT_STRING, BASE_HEX, NULL, 0x00,
				"Extended Methods", HFILL
			}
		},
		{ &hf_capa_header_code_pages,
			{	"Header Code Pages",
				"wsp.capability.code_pages",
				 FT_STRING, BASE_HEX, NULL, 0x00,
				"Header Code Pages", HFILL
			}
		},
		{ &hf_capa_aliases,
			{	"Aliases",
				"wsp.capability.aliases",
				 FT_BYTES, BASE_NONE, NULL, 0x00,
				"Aliases", HFILL
			}
		},
		{ &hf_capa_client_message_size,
			{	"Client Message Size",
				"wsp.capability.client_message_size",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Client Message size (bytes)", HFILL
			}
		},
		{ &hf_capa_server_message_size,
			{	"Server Message Size",
				"wsp.capability.server_message_size",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Server Message size (bytes)", HFILL
			}
		},
		{ &hf_wsp_post_data,
			{ 	"Data (Post)",
				"wsp.post.data",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"Post Data", HFILL
			}
		},
		{ &hf_wsp_push_data,
			{ 	"Push Data",
				"wsp.push.data",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"Push Data", HFILL
			}
		},
		{ &hf_wsp_multipart_data,
			{ 	"Data in this part",
				"wsp.multipart.data",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"The data of 1 MIME-multipart part.", HFILL
			}
		},
		{ &hf_wsp_mpart,
			{ 	"Part",
				"wsp.multipart",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"MIME part of multipart data.", HFILL
			}
		},
		{ &hf_wsp_redirect_flags,
			{ 	"Flags",
				"wsp.redirect.flags",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Redirect Flags", HFILL
			}
		},
		{ &hf_wsp_redirect_permanent,
			{ 	"Permanent Redirect",
				"wsp.redirect.flags.permanent",
				 FT_BOOLEAN, 8, TFS(&yes_no_truth), PERMANENT_REDIRECT,
				"Permanent Redirect", HFILL
			}
		},
		{ &hf_wsp_redirect_reuse_security_session,
			{ 	"Reuse Security Session",
				"wsp.redirect.flags.reuse_security_session",
				 FT_BOOLEAN, 8, TFS(&yes_no_truth), REUSE_SECURITY_SESSION,
				"If set, the existing Security Session may be reused", HFILL
			}
		},
		{ &hf_redirect_addresses,
			{	"Redirect Addresses",
				"wsp.redirect.addresses",
				FT_NONE, BASE_NONE, NULL, 0x00,
				"List of Redirect Addresses", HFILL
			}
		},

		/*
		 * Addresses
		 */
		{ &hf_address_entry,
			{	"Address Record",
				"wsp.address",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"Address Record", HFILL
			}
		},
		{ &hf_address_flags_length,
			{ 	"Flags/Length",
				"wsp.address.flags",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Address Flags/Length", HFILL
			}
		},
		{ &hf_address_flags_length_bearer_type_included,
			{ 	"Bearer Type Included",
				"wsp.address.flags.bearer_type_included",
				 FT_BOOLEAN, 8, TFS(&yes_no_truth), BEARER_TYPE_INCLUDED,
				"Address bearer type included", HFILL
			}
		},
		{ &hf_address_flags_length_port_number_included,
			{ 	"Port Number Included",
				"wsp.address.flags.port_number_included",
				 FT_BOOLEAN, 8, TFS(&yes_no_truth), PORT_NUMBER_INCLUDED,
				"Address port number included", HFILL
			}
		},
		{ &hf_address_flags_length_address_len,
			{ 	"Address Length",
				"wsp.address.flags.length",
				 FT_UINT8, BASE_DEC, NULL, ADDRESS_LEN,
				"Address Length", HFILL
			}
		},
		{ &hf_address_bearer_type,
			{ 	"Bearer Type",
				"wsp.address.bearer_type",
				 FT_UINT8, BASE_HEX, VALS(vals_bearer_types), 0x0,
				"Bearer Type", HFILL
			}
		},
		{ &hf_address_port_num,
			{ 	"Port Number",
				"wsp.address.port",
				 FT_UINT16, BASE_DEC, NULL, 0x0,
				"Port Number", HFILL
			}
		},
		{ &hf_address_ipv4_addr,
			{ 	"IPv4 Address",
				"wsp.address.ipv4",
				 FT_IPv4, BASE_NONE, NULL, 0x0,
				"Address (IPv4)", HFILL
			}
		},
		{ &hf_address_ipv6_addr,
			{ 	"IPv6 Address",
				"wsp.address.ipv6",
				 FT_IPv6, BASE_NONE, NULL, 0x0,
				"Address (IPv6)", HFILL
			}
		},
		{ &hf_address_addr,
			{ 	"Address",
				"wsp.address.unknown",
				 FT_BYTES, BASE_NONE, NULL, 0x0,
				"Address (unknown)", HFILL
			}
		},


		/*
		 * New WSP header fields
		 */


		/* WSP header name */
		{ &hf_hdr_name,
			{	"Header name",
				"wsp.header.name",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"Name of the WSP header", HFILL
			}
		},
		/* WSP headers start here */
		{ &hf_hdr_accept,
			{	"Accept",
				"wsp.header.accept",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept", HFILL
			}
		},
		{ &hf_hdr_accept_charset,
			{	"Accept-Charset",
				"wsp.header.accept_charset",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept-Charset", HFILL
			}
		},
		{ &hf_hdr_accept_encoding,
			{	"Accept-Encoding",
				"wsp.header.accept_encoding",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept-Encoding", HFILL
			}
		},
		{ &hf_hdr_accept_language,
			{	"Accept-Language",
				"wsp.header.accept_language",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept-Language", HFILL
			}
		},
		{ &hf_hdr_accept_ranges,
			{	"Accept-Ranges",
				"wsp.header.accept_ranges",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept-Ranges", HFILL
			}
		},
		{ &hf_hdr_age,
			{	"Age",
				"wsp.header.age",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Age", HFILL
			}
		},
		{ &hf_hdr_allow,
			{	"Allow",
				"wsp.header.allow",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Allow", HFILL
			}
		},
		{ &hf_hdr_authorization,
			{	"Authorization",
				"wsp.header.authorization",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Authorization", HFILL
			}
		},
		{ &hf_hdr_authorization_scheme,
			{	"Authorization Scheme",
				"wsp.header.authorization.scheme",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Authorization: used scheme", HFILL
			}
		},
		{ &hf_hdr_authorization_user_id,
			{	"User-id",
				"wsp.header.authorization.user_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Authorization: user ID for basic authorization", HFILL
			}
		},
		{ &hf_hdr_authorization_password,
			{	"Password",
				"wsp.header.authorization.password",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Authorization: password for basic authorization", HFILL
			}
		},
		{ &hf_hdr_cache_control,
			{	"Cache-Control",
				"wsp.header.cache_control",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Cache-Control", HFILL
			}
		},
		{ &hf_hdr_connection,
			{	"Connection",
				"wsp.header.connection",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Connection", HFILL
			}
		},
		{ &hf_hdr_content_base,
			{	"Content-Base",
				"wsp.header.content_base",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Base", HFILL
			}
		},
		{ &hf_hdr_content_encoding,
			{	"Content-Encoding",
				"wsp.header.content_encoding",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Encoding", HFILL
			}
		},
		{ &hf_hdr_content_language,
			{	"Content-Language",
				"wsp.header.content_language",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Language", HFILL
			}
		},
		{ &hf_hdr_content_length,
			{	"Content-Length",
				"wsp.header.content_length",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Length", HFILL
			}
		},
		{ &hf_hdr_content_location,
			{	"Content-Location",
				"wsp.header.content_location",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Location", HFILL
			}
		},
		{ &hf_hdr_content_md5,
			{	"Content-Md5",
				"wsp.header.content_md5",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Md5", HFILL
			}
		},
		{ &hf_hdr_content_range,
			{	"Content-Range",
				"wsp.header.content_range",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Range", HFILL
			}
		},
		{ &hf_hdr_content_range_first_byte_pos,
			{	"First-byte-position",
				"wsp.header.content_range.first_byte_pos",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"WSP header Content-Range: position of first byte", HFILL
			}
		},
		{ &hf_hdr_content_range_entity_length,
			{	"Entity-length",
				"wsp.header.content_range.entity_length",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"WSP header Content-Range: length of the entity", HFILL
			}
		},
		{ &hf_hdr_content_type,
			{	"Content-Type",
				"wsp.header.content_type",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Type", HFILL
			}
		},
		{ &hf_hdr_date,
			{	"Date",
				"wsp.header.date",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Date", HFILL
			}
		},
		{ &hf_hdr_etag,
			{	"ETag",
				"wsp.header.etag",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header ETag", HFILL
			}
		},
		{ &hf_hdr_expires,
			{	"Expires",
				"wsp.header.expires",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Expires", HFILL
			}
		},
		{ &hf_hdr_from,
			{	"From",
				"wsp.header.from",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header From", HFILL
			}
		},
		{ &hf_hdr_host,
			{	"Host",
				"wsp.header.host",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Host", HFILL
			}
		},
		{ &hf_hdr_if_modified_since,
			{	"If-Modified-Since",
				"wsp.header.if_modified_since",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header If-Modified-Since", HFILL
			}
		},
		{ &hf_hdr_if_match,
			{	"If-Match",
				"wsp.header.if_match",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header If-Match", HFILL
			}
		},
		{ &hf_hdr_if_none_match,
			{	"If-None-Match",
				"wsp.header.if_none_match",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header If-None-Match", HFILL
			}
		},
		{ &hf_hdr_if_range,
			{	"If-Range",
				"wsp.header.if_range",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header If-Range", HFILL
			}
		},
		{ &hf_hdr_if_unmodified_since,
			{	"If-Unmodified-Since",
				"wsp.header.if_unmodified_since",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header If-Unmodified-Since", HFILL
			}
		},
		{ &hf_hdr_last_modified,
			{	"Last-Modified",
				"wsp.header.last_modified",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Last-Modified", HFILL
			}
		},
		{ &hf_hdr_location,
			{	"Location",
				"wsp.header.location",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Location", HFILL
			}
		},
		{ &hf_hdr_max_forwards,
			{	"Max-Forwards",
				"wsp.header.max_forwards",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Max-Forwards", HFILL
			}
		},
		{ &hf_hdr_pragma,
			{	"Pragma",
				"wsp.header.pragma",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Pragma", HFILL
			}
		},
		{ &hf_hdr_proxy_authenticate,
			{	"Proxy-Authenticate",
				"wsp.header.proxy_authenticate",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authenticate", HFILL
			}
		},
		{ &hf_hdr_proxy_authenticate_scheme,
			{	"Authentication Scheme",
				"wsp.header.proxy_authenticate.scheme",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authenticate: used scheme", HFILL
			}
		},
		{ &hf_hdr_proxy_authenticate_realm,
			{	"Authentication Realm",
				"wsp.header.proxy_authenticate.realm",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authenticate: used realm", HFILL
			}
		},
		{ &hf_hdr_proxy_authorization,
			{	"Proxy-Authorization",
				"wsp.header.proxy_authorization",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authorization", HFILL
			}
		},
		{ &hf_hdr_proxy_authorization_scheme,
			{	"Authorization Scheme",
				"wsp.header.proxy_authorization.scheme",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authorization: used scheme", HFILL
			}
		},
		{ &hf_hdr_proxy_authorization_user_id,
			{	"User-id",
				"wsp.header.proxy_authorization.user_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authorization: user ID for basic authorization", HFILL
			}
		},
		{ &hf_hdr_proxy_authorization_password,
			{	"Password",
				"wsp.header.proxy_authorization.password",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authorization: password for basic authorization", HFILL
			}
		},
		{ &hf_hdr_public,
			{	"Public",
				"wsp.header.public",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Public", HFILL
			}
		},
		{ &hf_hdr_range,
			{	"Range",
				"wsp.header.range",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Range", HFILL
			}
		},
		{ &hf_hdr_range_first_byte_pos,
			{	"First-byte-position",
				"wsp.header.range.first_byte_pos",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"WSP header Range: position of first byte", HFILL
			}
		},
		{ &hf_hdr_range_last_byte_pos,
			{	"Last-byte-position",
				"wsp.header.range.last_byte_pos",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"WSP header Range: position of last byte", HFILL
			}
		},
		{ &hf_hdr_range_suffix_length,
			{	"Suffix-length",
				"wsp.header.range.suffix_length",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"WSP header Range: length of the suffix", HFILL
			}
		},
		{ &hf_hdr_referer,
			{	"Referer",
				"wsp.header.referer",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Referer", HFILL
			}
		},
		{ &hf_hdr_retry_after,
			{	"Retry-After",
				"wsp.header.retry_after",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Retry-After", HFILL
			}
		},
		{ &hf_hdr_server,
			{	"Server",
				"wsp.header.server",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Server", HFILL
			}
		},
		{ &hf_hdr_transfer_encoding,
			{	"Transfer-Encoding",
				"wsp.header.transfer_encoding",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Transfer-Encoding", HFILL
			}
		},
		{ &hf_hdr_upgrade,
			{	"Upgrade",
				"wsp.header.upgrade",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Upgrade", HFILL
			}
		},
		{ &hf_hdr_user_agent,
			{	"User-Agent",
				"wsp.header.user_agent",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header User-Agent", HFILL
			}
		},
		{ &hf_hdr_vary,
			{	"Vary",
				"wsp.header.vary",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Vary", HFILL
			}
		},
		{ &hf_hdr_via,
			{	"Via",
				"wsp.header.via",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Via", HFILL
			}
		},
		{ &hf_hdr_warning,
			{	"Warning",
				"wsp.header.warning",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Warning", HFILL
			}
		},
		{ &hf_hdr_warning_code,
			{	"Warning code",
				"wsp.header.warning.code",
				FT_UINT8, BASE_HEX, VALS(vals_wsp_warning_code), 0x00,
				"WSP header Warning code", HFILL
			}
		},
		{ &hf_hdr_warning_agent,
			{	"Warning agent",
				"wsp.header.warning.agent",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Warning agent", HFILL
			}
		},
		{ &hf_hdr_warning_text,
			{	"Warning text",
				"wsp.header.warning.text",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Warning text", HFILL
			}
		},
		{ &hf_hdr_www_authenticate,
			{	"Www-Authenticate",
				"wsp.header.www_authenticate",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Www-Authenticate", HFILL
			}
		},
		{ &hf_hdr_www_authenticate_scheme,
			{	"Authentication Scheme",
				"wsp.header.www_authenticate.scheme",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header WWW-Authenticate: used scheme", HFILL
			}
		},
		{ &hf_hdr_www_authenticate_realm,
			{	"Authentication Realm",
				"wsp.header.www_authenticate.realm",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header WWW-Authenticate: used realm", HFILL
			}
		},
		{ &hf_hdr_content_disposition,
			{	"Content-Disposition",
				"wsp.header.content_disposition",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Disposition", HFILL
			}
		},
		{ &hf_hdr_application_id,
			{	"Application-Id",
				"wsp.header.application_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Application-Id", HFILL
			}
		},
		{ &hf_hdr_content_uri,
			{	"Content-Uri",
				"wsp.header.content_uri",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Uri", HFILL
			}
		},
		{ &hf_hdr_initiator_uri,
			{	"Initiator-Uri",
				"wsp.header.initiator_uri",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Initiator-Uri", HFILL
			}
		},
		{ &hf_hdr_bearer_indication,
			{	"Bearer-Indication",
				"wsp.header.bearer_indication",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Bearer-Indication", HFILL
			}
		},
		{ &hf_hdr_push_flag,
			{	"Push-Flag",
				"wsp.header.push_flag",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Push-Flag", HFILL
			}
		},
		{ &hf_hdr_push_flag_auth,
			{	"Initiator URI is authenticated",
				"wsp.header.push_flag.authenticated",
				FT_UINT8, BASE_DEC, VALS(vals_false_true), 0x01,
				"The X-Wap-Initiator-URI has been authenticated.", HFILL
			}
		},
		{ &hf_hdr_push_flag_trust,
			{	"Content is trusted",
				"wsp.header.push_flag.trusted",
				FT_UINT8, BASE_DEC, VALS(vals_false_true), 0x02,
				"The push content is trusted.", HFILL
			}
		},
		{ &hf_hdr_push_flag_last,
			{	"Last push message",
				"wsp.header.push_flag.last",
				FT_UINT8, BASE_DEC, VALS(vals_false_true), 0x04,
				"Indicates whether this is the last push message.", HFILL
			}
		},
		{ &hf_hdr_profile,
			{	"Profile",
				"wsp.header.profile",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Profile", HFILL
			}
		},
		{ &hf_hdr_profile_diff,
			{	"Profile-Diff",
				"wsp.header.profile_diff",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Profile-Diff", HFILL
			}
		},
		{ &hf_hdr_profile_warning,
			{	"Profile-Warning",
				"wsp.header.profile_warning",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Profile-Warning", HFILL
			}
		},
		{ &hf_hdr_expect,
			{	"Expect",
				"wsp.header.expect",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Expect", HFILL
			}
		},
		{ &hf_hdr_te,
			{	"Te",
				"wsp.header.te",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Te", HFILL
			}
		},
		{ &hf_hdr_trailer,
			{	"Trailer",
				"wsp.header.trailer",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Trailer", HFILL
			}
		},
		{ &hf_hdr_x_wap_tod,
			{	"X-Wap-Tod",
				"wsp.header.x_wap_tod",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header X-Wap-Tod", HFILL
			}
		},
		{ &hf_hdr_content_id,
			{	"Content-Id",
				"wsp.header.content_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Id", HFILL
			}
		},
		{ &hf_hdr_set_cookie,
			{	"Set-Cookie",
				"wsp.header.set_cookie",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Set-Cookie", HFILL
			}
		},
		{ &hf_hdr_cookie,
			{	"Cookie",
				"wsp.header.cookie",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Cookie", HFILL
			}
		},
		{ &hf_hdr_encoding_version,
			{	"Encoding-Version",
				"wsp.header.encoding_version",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Encoding-Version", HFILL
			}
		},
		{ &hf_hdr_x_wap_security,
			{	"X-Wap-Security",
				"wsp.header.x_wap_security",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header X-Wap-Security", HFILL
			}
		},
		{ &hf_hdr_x_wap_application_id,
			{	"X-Wap-Application-Id",
				"wsp.header.x_wap_application_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header X-Wap-Application-Id", HFILL
			}
		},
		{ &hf_hdr_accept_application,
			{	"Accept-Application",
				"wsp.header.accept_application",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept-Application", HFILL
			}
		},


		/*
		 * Openwave headers
		 * Header Code Page: x-up-1
		 */

		/* Textual headers */
		{ &hf_hdr_openwave_x_up_proxy_operator_domain,
			{	"x-up-proxy-operator-domain",
				"wsp.header.x_up_1.x_up_proxy_operator_domain",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-operator-domain", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_home_page,
			{	"x-up-proxy-home-page",
				"wsp.header.x_up_1.x_up_proxy_home_page",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-home-page", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_uplink_version,
			{	"x-up-proxy-uplink-version",
				"wsp.header.x_up_1.x_up_proxy_uplink_version",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-uplink-version", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_ba_realm,
			{	"x-up-proxy-ba-realm",
				"wsp.header.x_up_1.x_up_proxy_ba_realm",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-ba-realm", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_request_uri,
			{	"x-up-proxy-request-uri",
				"wsp.header.x_up_1.x_up_proxy_request_uri",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-request-uri", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_bookmark,
			{	"x-up-proxy-bookmark",
				"wsp.header.x_up_1.x_up_proxy_bookmark",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-bookmark", HFILL
			}
		},
		/* Integer-value headers */
		{ &hf_hdr_openwave_x_up_proxy_push_seq,
			{	"x-up-proxy-push-seq",
				"wsp.header.x_up_1.x_up_proxy_push_seq",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-push-seq", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_notify,
			{	"x-up-proxy-notify",
				"wsp.header.x_up_1.x_up_proxy_notify",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-notify", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_net_ask,
			{	"x-up-proxy-net-ask",
				"wsp.header.x_up_1.x_up_proxy_net_ask",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-net-ask", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_tod,
			{	"x-up-proxy-tod",
				"wsp.header.x_up_1.x_up_proxy_tod",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-tod", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_ba_enable,
			{	"x-up-proxy-ba-enable",
				"wsp.header.x_up_1.x_up_proxy_ba_enable",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-ba-enable", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_redirect_enable,
			{	"x-up-proxy-redirect-enable",
				"wsp.header.x_up_1.x_up_proxy_redirect_enable",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-redirect-enable", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_redirect_status,
			{	"x-up-proxy-redirect-status",
				"wsp.header.x_up_1.x_up_proxy_redirect_status",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-redirect-status", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_linger,
			{	"x-up-proxy-linger",
				"wsp.header.x_up_1.x_up_proxy_linger",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-linger", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_enable_trust,
			{	"x-up-proxy-enable-trust",
				"wsp.header.x_up_1.x_up_proxy_enable_trust",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-enable-trust", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_trust,
			{	"x-up-proxy-trust",
				"wsp.header.x_up_1.x_up_proxy_trust",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-trust", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_has_color,
			{	"x-up-devcap-has-color",
				"wsp.header.x_up_1.x_up_devcap_has_color",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-has-color", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_num_softkeys,
			{	"x-up-devcap-num-softkeys",
				"wsp.header.x_up_1.x_up_devcap_num_softkeys",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-num-softkeys", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_softkey_size,
			{	"x-up-devcap-softkey-size",
				"wsp.header.x_up_1.x_up_devcap_softkey_size",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-softkey-size", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_screen_chars,
			{	"x-up-devcap-screen-chars",
				"wsp.header.x_up_1.x_up_devcap_screen_chars",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-screen-chars", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_screen_pixels,
			{	"x-up-devcap-screen-pixels",
				"wsp.header.x_up_1.x_up_devcap_screen_pixels",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-screen-pixels", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_em_size,
			{	"x-up-devcap-em-size",
				"wsp.header.x_up_1.x_up_devcap_em_size",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-em-size", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_screen_depth,
			{	"x-up-devcap-screen-depth",
				"wsp.header.x_up_1.x_up_devcap_screen_depth",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-screen-depth", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_immed_alert,
			{	"x-up-devcap-immed-alert",
				"wsp.header.x_up_1.x_up_devcap_immed_alert",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-immed-alert", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_gui,
			{	"x-up-devcap-gui",
				"wsp.header.x_up_1.x_up_devcap_gui",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-gui", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_trans_charset,
			{	"x-up-proxy-trans-charset",
				"wsp.header.x_up_1.x_up_proxy_trans_charset",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-trans-charset", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_push_accept,
			{	"x-up-proxy-push-accept",
				"wsp.header.x_up_1.x_up_proxy_push_accept",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-push-accept", HFILL
			}
		},

		/* Not used for now
		{ &hf_hdr_openwave_x_up_proxy_client_id,
			{	"x-up-proxy-client-id",
				"wsp.header.x_up_1.x_up_proxy_client_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-client-id", HFILL
			}
		},
		*/

		/*
		 * Header value parameters
		 */

		{ &hf_parameter_q,
			{ 	"Q",
				"wsp.parameter.q",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Q parameter", HFILL
			}
		},
		{ &hf_parameter_charset,
			{ 	"Charset",
				"wsp.parameter.charset",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Charset parameter", HFILL
			}
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_wsp,
		&ett_header, /* Header field subtree */
		&ett_headers, /* Subtree for WSP headers */
		&ett_capabilities, /* CO-WSP Session Capabilities */
		&ett_capability, /* CO-WSP Session single Capability */
		&ett_post,
		&ett_redirect_flags,
		&ett_address_flags,
		&ett_multiparts,
		&ett_mpartlist,
		&ett_addresses,		/* Addresses */
		&ett_address,		/* Single address */
	};

/* Register the protocol name and description */
	proto_wsp = proto_register_protocol(
		"Wireless Session Protocol",   	/* protocol name for use by ethereal */
		"WSP",                          /* short version of name */
		"wsp"                   	    /* Abbreviated protocol name,
										   should Match IANA:
	    < URL:http://www.iana.org/assignments/port-numbers/ >
										*/
	);
	wsp_tap = register_tap("wsp");
	/* Init the hash table */
/*	wsp_sessions = g_hash_table_new(
			(GHashFunc) wsp_session_hash,
			(GEqualFunc)wsp_session_equal);*/

/* Required function calls to register the header fields and subtrees used  */
	proto_register_field_array(proto_wsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("wsp-co", dissect_wsp_fromwap_co, proto_wsp);
	register_dissector("wsp-cl", dissect_wsp_fromwap_cl, proto_wsp);
	/* As the media types for WSP and HTTP are the same, the WSP dissector
	 * uses the same string dissector table as the HTTP protocol. */
	media_type_table = find_dissector_table("media_type");
	register_heur_dissector_list("wsp", &heur_subdissector_list);

	wsp_fromudp_handle = create_dissector_handle(dissect_wsp_fromudp,
	    proto_wsp);
}

void
proto_reg_handoff_wsp(void)
{
	/*
	 * Get a handle for the WTP-over-UDP and the generic media dissectors.
	 */
	wtp_fromudp_handle = find_dissector("wtp-udp");
	media_handle = find_dissector("media");
	wbxml_uaprof_handle = find_dissector("wbxml-uaprof");

	/* Only connection-less WSP has no previous handler */
	dissector_add("udp.port", UDP_PORT_WSP, wsp_fromudp_handle);
	dissector_add("udp.port", UDP_PORT_WSP_PUSH, wsp_fromudp_handle);

	/* GSM SMS UD dissector can also carry WSP */
	dissector_add("gsm-sms-ud.udh.port", UDP_PORT_WSP, wsp_fromudp_handle);
	dissector_add("gsm-sms-ud.udh.port", UDP_PORT_WSP_PUSH, wsp_fromudp_handle);

	/* This dissector is also called from the WTP and WTLS dissectors */
}

/*
 * Session Initiation Request
 */

/* Register the protocol with Ethereal */
void
proto_register_sir(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_sir_section,
			{	"Session Initiation Request",
				"wap.sir",
				FT_NONE, BASE_NONE, NULL, 0x00,
				"Session Initiation Request content", HFILL
			}
		},
		{ &hf_sir_version,
			{	"Version",
				"wap.sir.version",
				FT_UINT8, BASE_DEC, NULL, 0x00,
				"Version of the Session Initiation Request document", HFILL
			}
		},
		{ &hf_sir_app_id_list_len,
			{	"Application-ID List Length",
				"wap.sir.app_id_list.length",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"Length of the Application-ID list (bytes)", HFILL
			}
		},
		{ &hf_sir_app_id_list,
			{	"Application-ID List",
				"wap.sir.app_id_list",
				FT_NONE, BASE_NONE, NULL, 0x00,
				"Application-ID list", HFILL
			}
		},
		{ &hf_sir_wsp_contact_points_len,
			{	"WSP Contact Points Length",
				"wap.sir.wsp_contact_points.length",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"Length of the WSP Contact Points list (bytes)", HFILL
			}
		},
		{ &hf_sir_wsp_contact_points,
			{	"WSP Contact Points",
				"wap.sir.wsp_contact_points",
				FT_NONE, BASE_NONE, NULL, 0x00,
				"WSP Contact Points list", HFILL
			}
		},
		{ &hf_sir_contact_points_len,
			{	"Non-WSP Contact Points Length",
				"wap.sir.contact_points.length",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"Length of the Non-WSP Contact Points list (bytes)", HFILL
			}
		},
		{ &hf_sir_contact_points,
			{	"Non-WSP Contact Points",
				"wap.sir.contact_points",
				FT_NONE, BASE_NONE, NULL, 0x00,
				"Non-WSP Contact Points list", HFILL
			}
		},
		{ &hf_sir_protocol_options_len,
			{	"Protocol Options List Entries",
				"wap.sir.protocol_options.length",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"Number of entries in the Protocol Options list", HFILL
			}
		},
		{ &hf_sir_protocol_options,
			{	"Protocol Options",
				"wap.sir.protocol_options",
				FT_UINT16, BASE_DEC, VALS(vals_sir_protocol_options), 0x00,
				"Protocol Options list", HFILL
			}
		},
		{ &hf_sir_prov_url_len,
			{ 	"X-Wap-ProvURL Length",
				"wap.sir.prov_url.length",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"Length of the X-Wap-ProvURL (Identifies the WAP Client Provisioning Context)", HFILL
			}
		},
		{ &hf_sir_prov_url,
			{ 	"X-Wap-ProvURL",
				"wap.sir.prov_url",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"X-Wap-ProvURL (Identifies the WAP Client Provisioning Context)", HFILL
			}
		},
		{ &hf_sir_cpi_tag_len,
			{	"CPITag List Entries",
				"wap.sir.cpi_tag.length",
				FT_UINT32, BASE_DEC, NULL, 0x00,
				"Number of entries in the CPITag list", HFILL
			}
		},
		{ &hf_sir_cpi_tag,
			{	"CPITag",
				"wap.sir.cpi_tag",
				FT_BYTES, BASE_HEX, NULL, 0x00,
				"CPITag (OTA-HTTP)", HFILL
			}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sir,			/* Session Initiation Request */
	};

	/* Register the dissector */
	proto_sir = proto_register_protocol(
		"WAP Session Initiation Request",  	/* protocol name for use by ethereal */
		"WAP SIR",                          /* short version of name */
		"wap-sir"                   	    /* Abbreviated protocol name,
											   should Match IANA:
	    < URL:http://www.iana.org/assignments/port-numbers/ >
										*/
	);

	/* Register header fields and protocol subtrees */
	proto_register_field_array(proto_sir, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_sir(void)
{
	dissector_handle_t sir_handle;

	sir_handle = create_dissector_handle(dissect_sir, proto_sir);

	/* Add dissector bindings for SIR dissection */
	dissector_add_string("media_type", "application/vnd.wap.sia", sir_handle);
}
