/* packet-wsp.c
 *
 * Routines to dissect WSP component of WAP traffic.
 *
 * $Id: packet-wsp.c,v 1.80 2003/11/03 10:16:00 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
 * Openwave header support by Dermot Bradley <dermot.bradley@openwave.com>
 * Code optimizations, header value dissection simplification with parse error
 * notification and macros, extra missing headers, WBXML registration
 * by Olivier Biot <olivier.biot(ad)siemens.com>.
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/ipv6-utils.h>
#include <epan/conversation.h>
#include "packet-wap.h"
#include "packet-wsp.h"

#define PLURALIZE(x)	( (x) == 1 ? "" : "s" )

/* Statistics (see doc/README.tapping) */
#include "tap.h"
static int wsp_tap = -1;

/* File scoped variables for the protocol and registered fields */
static int proto_wsp 					= HF_EMPTY;

/* These fields used by fixed part of header */

/* WSP header fields */
static int hf_hdr_name					= HF_EMPTY;
static int hf_hdr_id					= HF_EMPTY;
static int hf_hdr_accept				= HF_EMPTY;
static int hf_hdr_accept_charset		= HF_EMPTY;
static int hf_hdr_accept_encoding		= HF_EMPTY;
static int hf_hdr_accept_language		= HF_EMPTY;
static int hf_hdr_accept_ranges			= HF_EMPTY;
static int hf_hdr_age					= HF_EMPTY;
static int hf_hdr_allow					= HF_EMPTY;
static int hf_hdr_authorization			= HF_EMPTY;
static int hf_hdr_cache_control			= HF_EMPTY;
static int hf_hdr_connection			= HF_EMPTY;
static int hf_hdr_content_encoding		= HF_EMPTY;
static int hf_hdr_content_language		= HF_EMPTY;
static int hf_hdr_content_length		= HF_EMPTY;
static int hf_hdr_content_location		= HF_EMPTY;
static int hf_hdr_content_md5			= HF_EMPTY;
static int hf_hdr_content_range			= HF_EMPTY;
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
static int hf_hdr_proxy_authorization	= HF_EMPTY;
static int hf_hdr_public				= HF_EMPTY;
static int hf_hdr_range					= HF_EMPTY;
static int hf_hdr_referer				= HF_EMPTY;
static int hf_hdr_retry_after			= HF_EMPTY;
static int hf_hdr_server				= HF_EMPTY;
static int hf_hdr_transfer_encoding		= HF_EMPTY;
static int hf_hdr_upgrade				= HF_EMPTY;
static int hf_hdr_user_agent			= HF_EMPTY;
static int hf_hdr_vary					= HF_EMPTY;
static int hf_hdr_via					= HF_EMPTY;
static int hf_hdr_warning				= HF_EMPTY;
static int hf_hdr_www_authenticate		= HF_EMPTY;
static int hf_hdr_content_disposition	= HF_EMPTY;
static int hf_hdr_application_id		= HF_EMPTY;
static int hf_hdr_content_uri			= HF_EMPTY;
static int hf_hdr_initiator_uri			= HF_EMPTY;
static int hf_hdr_bearer_indication		= HF_EMPTY;
static int hf_hdr_push_flag				= HF_EMPTY;
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

/* For Authorization and Proxy-Authorization */
static int hf_hdr_authorization_scheme			= HF_EMPTY;
static int hf_hdr_authorization_user_id			= HF_EMPTY;
static int hf_hdr_authorization_password		= HF_EMPTY;
static int hf_hdr_proxy_authorization_scheme	= HF_EMPTY;
static int hf_hdr_proxy_authorization_user_id	= HF_EMPTY;
static int hf_hdr_proxy_authorization_password	= HF_EMPTY;

/* Push-specific WSP headers */
static int hf_hdr_push_flag_auth				= HF_EMPTY;
static int hf_hdr_push_flag_trust				= HF_EMPTY;
static int hf_hdr_push_flag_last				= HF_EMPTY;


/* Openwave headers */
static int hf_hdr_openwave_x_up_proxy_operator_domain	= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_home_page			= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_uplink_version	= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_ba_realm			= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_request_uri		= HF_EMPTY;
static int hf_hdr_openwave_x_up_proxy_client_id			= HF_EMPTY;
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
#if 0
static int hf_parameter_textual				= HF_EMPTY;
static int hf_parameter_charset				= HF_EMPTY;
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
static int hf_wsp_capability_length			= HF_EMPTY;
static int hf_wsp_capabilities_section			= HF_EMPTY;
static int hf_wsp_capabilities_client_SDU		= HF_EMPTY;
static int hf_wsp_capabilities_server_SDU		= HF_EMPTY;
static int hf_wsp_capabilities_protocol_opt		= HF_EMPTY;
static int hf_wsp_capabilities_method_MOR		= HF_EMPTY;
static int hf_wsp_capabilities_push_MOR			= HF_EMPTY;
static int hf_wsp_capabilities_extended_methods		= HF_EMPTY;
static int hf_wsp_capabilities_header_code_pages	= HF_EMPTY;
static int hf_wsp_capabilities_aliases			= HF_EMPTY;
static int hf_wsp_header_uri_len			= HF_EMPTY;
static int hf_wsp_header_uri				= HF_EMPTY;
static int hf_wsp_server_session_id			= HF_EMPTY;
static int hf_wsp_header_status				= HF_EMPTY;
static int hf_wsp_header_length				= HF_EMPTY;
static int hf_wsp_headers_section			= HF_EMPTY;
static int hf_wsp_header				= HF_EMPTY;
static int hf_wsp_content_type				= HF_EMPTY;
static int hf_wsp_content_type_str			= HF_EMPTY;
static int hf_wsp_parameter_well_known_charset		= HF_EMPTY;
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
static int hf_wsp_parameter_upart_type_value		= HF_EMPTY;
static int hf_wsp_parameter_level			= HF_EMPTY;
static int hf_wsp_reply_data				= HF_EMPTY;
static int hf_wsp_post_data				= HF_EMPTY;
static int hf_wsp_push_data				= HF_EMPTY;
static int hf_wsp_multipart_data			= HF_EMPTY;
static int hf_wsp_mpart					= HF_EMPTY;



static int hf_wsp_header_shift_code			= HF_EMPTY;

#if 0

static int hf_wsp_header_accept				= HF_EMPTY;
static int hf_wsp_header_accept_str			= HF_EMPTY;
static int hf_wsp_header_accept_application		= HF_EMPTY;
static int hf_wsp_header_accept_application_str		= HF_EMPTY;
static int hf_wsp_header_accept_charset			= HF_EMPTY;
static int hf_wsp_header_accept_charset_str		= HF_EMPTY;
static int hf_wsp_header_accept_language		= HF_EMPTY;
static int hf_wsp_header_accept_language_str		= HF_EMPTY;
static int hf_wsp_header_accept_ranges			= HF_EMPTY;
static int hf_wsp_header_accept_ranges_str		= HF_EMPTY;
static int hf_wsp_header_cache_control			= HF_EMPTY;
static int hf_wsp_header_cache_control_str		= HF_EMPTY;
static int hf_wsp_header_cache_control_field_name	= HF_EMPTY;
static int hf_wsp_header_connection			= HF_EMPTY;
static int hf_wsp_header_connection_str			= HF_EMPTY;
static int hf_wsp_header_cache_control_field_name_str	= HF_EMPTY;
static int hf_wsp_header_content_length			= HF_EMPTY;
static int hf_wsp_header_age				= HF_EMPTY;
static int hf_wsp_header_bearer_indication		= HF_EMPTY;
static int hf_wsp_header_date				= HF_EMPTY;
static int hf_wsp_header_etag				= HF_EMPTY;
static int hf_wsp_header_expires			= HF_EMPTY;
static int hf_wsp_header_last_modified			= HF_EMPTY;
static int hf_wsp_header_location			= HF_EMPTY;
static int hf_wsp_header_if_modified_since		= HF_EMPTY;
static int hf_wsp_header_profile			= HF_EMPTY;
static int hf_wsp_header_pragma				= HF_EMPTY;
static int hf_wsp_header_proxy_authenticate				= HF_EMPTY;
static int hf_wsp_header_www_authenticate				= HF_EMPTY;
static int hf_wsp_header_proxy_authorization			= HF_EMPTY;
static int hf_wsp_header_proxy_authorization_scheme		= HF_EMPTY;
static int hf_wsp_header_proxy_authorization_user_id	= HF_EMPTY;
static int hf_wsp_header_proxy_authorization_password	= HF_EMPTY;
static int hf_wsp_header_authorization					= HF_EMPTY;
static int hf_wsp_header_authorization_scheme			= HF_EMPTY;
static int hf_wsp_header_authorization_user_id			= HF_EMPTY;
static int hf_wsp_header_authorization_password			= HF_EMPTY;
static int hf_wsp_header_server				= HF_EMPTY;
static int hf_wsp_header_user_agent			= HF_EMPTY;
static int hf_wsp_header_warning			= HF_EMPTY;
static int hf_wsp_header_warning_code			= HF_EMPTY;
static int hf_wsp_header_warning_agent			= HF_EMPTY;
static int hf_wsp_header_warning_text			= HF_EMPTY;
static int hf_wsp_header_application_header		= HF_EMPTY;
static int hf_wsp_header_application_value		= HF_EMPTY;
static int hf_wsp_header_x_wap_tod			= HF_EMPTY;
static int hf_wsp_header_content_ID			= HF_EMPTY;
static int hf_wsp_header_transfer_encoding		= HF_EMPTY;
static int hf_wsp_header_transfer_encoding_str		= HF_EMPTY;
static int hf_wsp_header_via				= HF_EMPTY;
static int hf_wsp_header_wap_application_id		= HF_EMPTY;
static int hf_wsp_header_wap_application_id_str		= HF_EMPTY;

static int hf_wsp_header_vary_well_known		= HF_EMPTY;
static int hf_wsp_header_vary_str		= HF_EMPTY;

/* Push-specific WSP headers */
static int hf_wsp_header_push_flag			= HF_EMPTY;
static int hf_wsp_header_push_flag_auth		= HF_EMPTY;
static int hf_wsp_header_push_flag_trust	= HF_EMPTY;
static int hf_wsp_header_push_flag_last		= HF_EMPTY;

/* Openwave-specific WSP headers */
static int hf_wsp_header_openwave_proxy_push_addr	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_push_accept	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_push_seq	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_notify		= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_operator_domain	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_home_page	= HF_EMPTY;
static int hf_wsp_header_openwave_devcap_has_color	= HF_EMPTY;
static int hf_wsp_header_openwave_devcap_num_softkeys	= HF_EMPTY;
static int hf_wsp_header_openwave_devcap_softkey_size	= HF_EMPTY;
static int hf_wsp_header_openwave_devcap_screen_chars	= HF_EMPTY;
static int hf_wsp_header_openwave_devcap_screen_pixels	= HF_EMPTY;
static int hf_wsp_header_openwave_devcap_em_size	= HF_EMPTY;
static int hf_wsp_header_openwave_devcap_screen_depth	= HF_EMPTY;
static int hf_wsp_header_openwave_devcap_immed_alert	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_net_ask		= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_uplink_version	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_tod		= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_ba_enable	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_ba_realm	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_redirect_enable	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_request_uri	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_redirect_status	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_trans_charset	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_trans_charset_str	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_linger		= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_client_id	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_enable_trust	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_trust_old	= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_trust		= HF_EMPTY;
static int hf_wsp_header_openwave_proxy_bookmark	= HF_EMPTY;
static int hf_wsp_header_openwave_devcap_gui		= HF_EMPTY;

#endif

static int hf_wsp_redirect_flags			= HF_EMPTY;
static int hf_wsp_redirect_permanent			= HF_EMPTY;
static int hf_wsp_redirect_reuse_security_session	= HF_EMPTY;
static int hf_wsp_redirect_afl				= HF_EMPTY;
static int hf_wsp_redirect_afl_bearer_type_included	= HF_EMPTY;
static int hf_wsp_redirect_afl_port_number_included	= HF_EMPTY;
static int hf_wsp_redirect_afl_address_len		= HF_EMPTY;
static int hf_wsp_redirect_bearer_type			= HF_EMPTY;
static int hf_wsp_redirect_port_num			= HF_EMPTY;
static int hf_wsp_redirect_ipv4_addr			= HF_EMPTY;
static int hf_wsp_redirect_ipv6_addr			= HF_EMPTY;
static int hf_wsp_redirect_addr				= HF_EMPTY;

/* Initialize the subtree pointers */
static gint ett_wsp 					= ETT_EMPTY;
static gint ett_content_type_parameters			= ETT_EMPTY;
static gint ett_header 					= ETT_EMPTY;
static gint ett_headers					= ETT_EMPTY;
static gint ett_header_warning				= ETT_EMPTY;
static gint ett_header_cache_control_parameters		= ETT_EMPTY;
static gint ett_header_cache_control_field_names	= ETT_EMPTY;
static gint ett_capabilities				= ETT_EMPTY;
static gint ett_post					= ETT_EMPTY;
static gint ett_content_type				= ETT_EMPTY;
static gint ett_redirect_flags				= ETT_EMPTY;
static gint ett_redirect_afl				= ETT_EMPTY;
static gint ett_multiparts				= ETT_EMPTY;
static gint ett_mpartlist				= ETT_EMPTY;
static gint ett_header_credentials			= ETT_EMPTY;
static gint ett_push_flags			= ETT_EMPTY;
static gint ett_parameters			= ETT_EMPTY;

/* Authorization, Proxy-Authorization */
static gint ett_authorization	= ETT_EMPTY;
/* WWW-Authenticate, Proxy-Authenticate */
static gint ett_authenticate	= ETT_EMPTY;
/* Warning */
static gint ett_warning			= ETT_EMPTY;


/* Handle for WSP-over-UDP dissector */
static dissector_handle_t wsp_fromudp_handle;

/* Handle for WTP-over-UDP dissector */
static dissector_handle_t wtp_fromudp_handle;

/* Handle for WBXML dissector */
static dissector_handle_t wbxml_handle;

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

static const value_string vals_accept_ranges[] = {
	{ 0x00, "none" },
	{ 0x01, "bytes" },
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
	/* 0x800A: unused */
	{ 0x800B, "x-wap-nai:mvsw.command"},
	{ 0x8010, "x-wap-openwave:iota.ua"},
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
	WSP_PDU_CONNECTREPLY	= 0x02,
	WSP_PDU_REDIRECT		= 0x03,			/* No sample data */
	WSP_PDU_REPLY			= 0x04,
	WSP_PDU_DISCONNECT		= 0x05,
	WSP_PDU_PUSH			= 0x06,			/* No sample data */
	WSP_PDU_CONFIRMEDPUSH	= 0x07,			/* No sample data */
	WSP_PDU_SUSPEND			= 0x08,			/* No sample data */
	WSP_PDU_RESUME			= 0x09,			/* No sample data */

	WSP_PDU_GET				= 0x40,
	WSP_PDU_OPTIONS			= 0x41,			/* No sample data */
	WSP_PDU_HEAD			= 0x42,			/* No sample data */
	WSP_PDU_DELETE			= 0x43,			/* No sample data */
	WSP_PDU_TRACE			= 0x44,			/* No sample data */

	WSP_PDU_POST			= 0x60,
	WSP_PDU_PUT				= 0x61,			/* No sample data */
};

#define VAL_STRING_SIZE 200

typedef enum {
	VALUE_LEN_SUPPLIED,
	VALUE_IS_TEXT_STRING,
	VALUE_IN_LEN,
} value_type_t;

static dissector_table_t wsp_dissector_table;
static dissector_table_t wsp_dissector_table_text;
static heur_dissector_list_t heur_subdissector_list;

static void add_uri (proto_tree *, packet_info *, tvbuff_t *, guint, guint);

static int add_parameter_charset (proto_tree *, tvbuff_t *, int, int);
static int add_constrained_encoding (proto_tree *, tvbuff_t *, int, int);
static int add_parameter_type (proto_tree *, tvbuff_t *, int, int);
static int add_parameter_text (proto_tree *, tvbuff_t *, int, int, int, const char *);
static void add_post_variable (proto_tree *, tvbuff_t *, guint, guint, guint, guint);
static void add_multipart_data (proto_tree *, tvbuff_t *);

static void add_capabilities (proto_tree *tree, tvbuff_t *tvb, int type);
static void add_capability_vals(tvbuff_t *, gboolean, int, guint, guint, char *, size_t);
static value_type_t get_value_type_len (tvbuff_t *, int, guint *, int *, int *);
static guint get_uintvar (tvbuff_t *, guint, guint);
static gint get_integer (tvbuff_t *, guint, guint, value_type_t, guint *);



/*
 * Dissect the WSP header part.
 * This function calls wkh_XXX functions that dissect well-known headers.
 */
static void add_headers (proto_tree *tree, tvbuff_t *tvb);

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
#define is_quoted_string(x)		is_text_string(x)
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

#define get_text_string(str,tvb,start,len,ok) \
	if (is_text_string(tvb_get_guint8(tvb,start))) { \
		str = tvb_get_stringz(tvb,start,&len); \
		g_assert (str); \
		ok = TRUE; \
	} else { len = 0; str = NULL; ok = FALSE; }
#define get_token_text(str,tvb,start,len,ok) \
	get_text_string(str,tvb,start,len,ok)
#define get_extension_media(str,tvb,start,len,ok) \
	get_text_string(str,tvb,start,len,ok)
#define get_text_value(str,tvb,start,len,ok) \
	get_text_string(str,tvb,start,len,ok)
#define get_extension_media(str,tvb,start,len,ok) \
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
		if (str) g_free (str); \
		str = g_malloc (6 * sizeof(char)); \
		g_assert (str); \
		snprintf (str,5,"%u.%u",val>>4,val&0x0F); \
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

/* WSP well-known header parsing function prototypes;
 * will be listed in the function lookup table WellKnownHeaders[] */
static guint32 wkh_default (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_accept (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_content_type (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_accept_charset (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_accept_language (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_connection (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_push_flag (proto_tree *tree, tvbuff_t *tvb,
		guint32 header_start);
static guint32 wkh_vary (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_accept_ranges (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_accept_encoding (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_content_encoding (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_transfer_encoding (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_pragma (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Single short-integer value */
static guint32 wkh_x_wap_security (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Text */
static guint32 wkh_content_location (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_etag (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_from (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_host (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_if_match (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_if_none_match (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_location (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_referer (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_server (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_user_agent (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_upgrade (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_via (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_content_uri (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_initiator_uri (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_profile (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_content_id (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Date-value or text */
static guint32 wkh_if_range (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Date-value */
static guint32 wkh_date (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_expires (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_if_modified_since (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_if_unmodified_since (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_last_modified (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Date-value with special meaning */
static guint32 wkh_x_wap_tod (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Delta-seconds-value */
static guint32 wkh_age (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Credentials */
static guint32 wkh_authorization (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_proxy_authorization (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Pragma */
static guint32 wkh_pragma (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Integer-value */
static guint32 wkh_content_length (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_max_forwards (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);

/* Integer lookup value */
static guint32 wkh_bearer_indication (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);

/* WAP application ID value */
static guint32 wkh_x_wap_application_id (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_accept_application (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_content_language (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);

/* Allow and Public */
static guint32 wkh_allow(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_public(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start);

/* Cache-control */
static guint32 wkh_cache_control (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Warning */
static guint32 wkh_warning (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Profile-warning */
static guint32 wkh_profile_warning (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);

/* Content-MD5 */
static guint32 wkh_content_md5 (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);


/* TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO
static guint32 wkh_content_base (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_content_range (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_proxy_authenticate (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_www_authenticate (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_range (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_retry_after (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_content_disposition (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_profile_diff (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_expect (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_te (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_content_id (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_set_cookie (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_cookie (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
static guint32 wkh_encoding_version (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
*/


/* WSP well-known Openwave header parsing function prototypes;
 * will be listed in the function lookup table WellKnownOpenwaveHeaders[] */
static guint32 wkh_openwave_default (proto_tree *tree, tvbuff_t *tvb,
		guint32 hdr_start);
/* Textual headers */
static guint32 wkh_openwave_x_up_proxy_operator_domain(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_home_page(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_uplink_version(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_ba_realm(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_request_uri(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_client_id(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_bookmark(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
/* Integer headers */
static guint32 wkh_openwave_x_up_proxy_push_seq(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_notify(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_net_ask(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_tod (proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_ba_enable(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_redirect_enable(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_redirect_status(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_linger(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_enable_trust(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_trust(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_devcap_has_color(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_devcap_num_softkeys(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_devcap_softkey_size(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_devcap_screen_chars(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_devcap_screen_pixels(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_devcap_em_size(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_devcap_screen_depth(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_devcap_immed_alert(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_devcap_gui(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);

static guint32 wkh_openwave_x_up_proxy_trans_charset(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);
static guint32 wkh_openwave_x_up_proxy_push_accept(proto_tree *tree,
		tvbuff_t *tvb, guint32 hdr_start);


/* Define a pointer to function data type for the well-known header
 * lookup table below */
typedef guint32 (*hdr_parse_func_ptr) (proto_tree *, tvbuff_t *, guint32);

/* Lookup table for well-known header parsing functions */
static const hdr_parse_func_ptr WellKnownHeader[128] = {
	/* 0x00 */	wkh_accept,				/* 0x01 */	wkh_accept_charset,
	/* 0x02 */	wkh_accept_encoding,	/* 0x03 */	wkh_accept_language,
	/* 0x04 */	wkh_accept_ranges,		/* 0x05 */	wkh_age,
	/* 0x06 */	wkh_allow,				/* 0x07 */	wkh_authorization,
	/* 0x08 */	wkh_cache_control,		/* 0x09 */	wkh_connection,
	/* 0x0A */	wkh_default,			/* 0x0B */	wkh_content_encoding,
	/* 0x0C */	wkh_content_language,	/* 0x0D */	wkh_content_length,
	/* 0x0E */	wkh_content_location,	/* 0x0F */	wkh_content_md5,
	/* 0x10 */	wkh_default,			/* 0x11 */	wkh_content_type,
	/* 0x12 */	wkh_date,				/* 0x13 */	wkh_etag,
	/* 0x14 */	wkh_expires,			/* 0x15 */	wkh_from,
	/* 0x16 */	wkh_host,				/* 0x17 */	wkh_if_modified_since,
	/* 0x18 */	wkh_if_match,			/* 0x19 */	wkh_if_none_match,
	/* 0x1A */	wkh_if_range,			/* 0x1B */	wkh_if_unmodified_since,
	/* 0x1C */	wkh_location,			/* 0x1D */	wkh_last_modified,
	/* 0x1E */	wkh_max_forwards,		/* 0x1F */	wkh_pragma,
	/* 0x20 */	wkh_default,			/* 0x21 */	wkh_proxy_authorization,
	/* 0x22 */	wkh_public,				/* 0x23 */	wkh_default,
	/* 0x24 */	wkh_referer,			/* 0x25 */	wkh_default,
	/* 0x26 */	wkh_server,				/* 0x27 */	wkh_transfer_encoding,
	/* 0x28 */	wkh_upgrade,			/* 0x29 */	wkh_user_agent,
	/* 0x2A */	wkh_vary,				/* 0x2B */	wkh_via,
	/* 0x2C */	wkh_warning,			/* 0x2D */	wkh_default,
	/* 0x2E */	wkh_default,			/* 0x2F */	wkh_x_wap_application_id,
	/* 0x30 */	wkh_content_uri,		/* 0x31 */	wkh_initiator_uri,
	/* 0x32 */	wkh_accept_application,	/* 0x33 */	wkh_bearer_indication,
	/* 0x34 */	wkh_push_flag,			/* 0x35 */	wkh_profile,
	/* 0x36 */	wkh_default,			/* 0x37 */	wkh_profile_warning,
	/* 0x38 */	wkh_default,			/* 0x39 */	wkh_default,
	/* 0x3A */	wkh_content_id,			/* 0x3B */	wkh_accept_charset,
	/* 0x3C */	wkh_accept_encoding,	/* 0x3D */	wkh_cache_control,
	/* 0x3E */	wkh_default,			/* 0x3F */	wkh_x_wap_tod,
	/* 0x40 */	wkh_default,			/* 0x41 */	wkh_default,
	/* 0x42 */	wkh_default,			/* 0x43 */	wkh_default,
	/* 0x44 */	wkh_profile_warning,	/* 0x45 */	wkh_default,
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
	/* 0x18 */	wkh_openwave_x_up_proxy_client_id,
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
add_headers (proto_tree *tree, tvbuff_t *tvb)
{
	guint8 hdr_id, val_id, codepage = 1;
	gint32 tvb_len = tvb_length(tvb);
	gint32 offset = 0, hdr_len, hdr_start;
	gint32 val_len, val_start;
	guint8 *hdr_str, *val_str;
	proto_tree *wsp_headers;
	proto_item *ti;
	guint8 ok;
	guint32 val = 0;
	nstime_t tv;

	if (offset >= tvb_len)
		return; /* No headers! */

	ti = proto_tree_add_item(tree, hf_wsp_headers_section,
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
				offset = WellKnownHeader[hdr_id & 0x7F](wsp_headers, tvb,
						hdr_start);
			} else { /* Openwave header code page */
				/* Here I'm delibarately assuming that Openwave is the only
				 * company that defines a WSP header code page. */
				offset = WellKnownOpenwaveHeader[hdr_id & 0x7F](wsp_headers,
						tvb, hdr_start);
			}
		} else if (hdr_id == 0x7F) { /* HCP shift sequence */
			codepage = tvb_get_guint8(tvb, offset+1);
			proto_tree_add_uint(wsp_headers, hf_wsp_header_shift_code,
					tvb, offset, 2, codepage);
			offset += 2;
		} else if (hdr_id >= 0x20) { /* Textual header */
			/* Header name MUST be NUL-ended string ==> tvb_get_stringz() */
			hdr_str = tvb_get_stringz(tvb, hdr_start, &hdr_len);
			val_start = hdr_start + hdr_len;
			val_id = tvb_get_guint8(tvb, val_start);
			/* Call header value dissector for given header */
			if (val_id >= 0x20 && val_id <=0x7E) { /* OK! */
				/* Header value sometimes NOT NUL-ended => tvb_strnlen() */
				val_len = tvb_strnlen(tvb, val_start, tvb_len - val_start);
				if (val_len == -1) { /* Reached end-of-tvb before '\0' */
					val_len = tvb_len - val_start;
					val_str = tvb_get_string(tvb, val_start, val_len);
					val_len++; /* For extra '\0' byte */
					offset = tvb_len;
				} else { /* OK */
					val_str = tvb_get_stringz(tvb, val_start, &val_len);
					g_assert(val_str);
					offset = val_start + val_len;
				}
				proto_tree_add_text(wsp_headers,tvb,hdr_start,offset-hdr_start,
						"%s: %s", hdr_str, val_str);
				g_free (val_str);
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
							g_assert (val_str);
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
 * wkh_XXX (proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
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
	guint8 *val_str = NULL

#define wkh_1_WellKnownValue				/* Parse Well Known Value */ \
	proto_tree_add_string_hidden(tree, hf_hdr_name, \
			tvb, hdr_start, offset - hdr_start, \
			match_strval (hdr_id, vals_field_names)); \
	if (val_id & 0x80) { /* Well-known value */ \
		offset++; \
		/* Well-known value processing starts HERE \
		 * \
		 * BEGIN */

#define wkh_2_TextualValue					/* Parse Textual Value */ \
		/* END */ \
	} else if ((val_id == 0) || (val_id >=0x20)) { /* Textual value */ \
		val_str = tvb_get_stringz (tvb, val_start, &val_len); \
		g_assert(val_str); \
		offset = val_start + val_len; \
		/* Textual value processing starts HERE \
		 * \
		 * BEGIN */

#define wkh_3_ValueWithLength				/* Parse Value With Length */ \
		/* END */ \
		g_free(val_str); \
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
					"<Error: Invalid header value>"); \
		} else if (hf > 0) { /* Create protocol tree item */ \
			proto_tree_add_string(tree, hf, \
					tvb, hdr_start, offset - hdr_start, \
					" <Error: Invalid header value>"); \
		} else { /* Create anonymous header field entry */ \
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
		guint32 hdr_start)
{
	wkh_0_Declarations;

	ok = TRUE; /* Bypass error checking as we don't parse the values! */

	wkh_1_WellKnownValue;
		ti = proto_tree_add_text (tree, tvb, hdr_start, offset - hdr_start,
				"%s: (Undecoded well-known value 0x%02x)",
				match_strval (hdr_id, vals_field_names), val_id & 0x7F);
	wkh_2_TextualValue;
		ti = proto_tree_add_text(tree, tvb, hdr_start, offset - hdr_start,
				"%s: %s",
				match_strval (hdr_id, vals_field_names), val_str);
	wkh_3_ValueWithLength;
		ti = proto_tree_add_text (tree, tvb, hdr_start, offset - hdr_start,
				"%s: (Undecoded value in general form with length indicator)",
				match_strval (hdr_id, vals_field_names));

	wkh_4_End(HF_EMPTY); /* The default parser has no associated hf_index;
							additionally the error code is always bypassed */
}


/* Content-type processing uses the following common core: */
#define wkh_content_type_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start) \
{ \
	wkh_0_Declarations; \
	guint32 off, val = 0, len; \
	guint8 peek; \
	proto_tree *parameter_tree = NULL; \
	\
	wkh_1_WellKnownValue; \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, \
				val_to_str(val_id & 0x7F, vals_content_types, \
					"(Unknown content type identifier 0x%X)")); \
		ok = TRUE; \
	wkh_2_TextualValue; \
		/* Sometimes with a No-Content response, a NULL content type \
		 * is reported. Process this correctly! */ \
		if (*val_str) { \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, \
					val_str); \
		} else { \
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
			off += len; /* off now points to 1st byte after string */ \
			ti = proto_tree_add_string (tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, val_str); \
		} else if (is_integer_value(peek)) { \
			get_integer_value(val, tvb, off, len, ok); \
			if (ok) { \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, \
						val_to_str(val, vals_content_types, \
							"(Unknown content type identifier 0x%X)")); \
			} \
			off += len; \
		} \
		/* Remember: offset == val_start + val_len */ \
		if (ok && (off < offset)) { /* Add parameters if any */ \
			parameter_tree = proto_item_add_subtree (ti, \
					ett_parameters); \
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
	guint8 *val_str = NULL;
	guint32 off, val = 0, len;
	guint8 peek;
	gboolean ok = FALSE;
	proto_item *ti = NULL;
	proto_tree *parameter_tree = NULL;

	*textual_content = NULL;
	*well_known_content = 0;

	wkh_1_WellKnownValue;
		ti = proto_tree_add_string(tree, hf_hdr_content_type,
				tvb, hdr_start, offset - hdr_start,
				val_to_str(val_id & 0x7F, vals_content_types,
					"<Unknown content type identifier 0x%X>"));
		*well_known_content = val_id & 0x7F;
		ok = TRUE;
	wkh_2_TextualValue;
		/* Sometimes with a No-Content response, a NULL content type
		 * is reported. Process this correctly! */
		if (*val_str) {
			ti = proto_tree_add_string(tree, hf_hdr_content_type,
					tvb, hdr_start, offset - hdr_start,
					val_str);
			*textual_content = g_strdup(val_str);
		} else {
			ti = proto_tree_add_string(tree, hf_hdr_content_type,
					tvb, hdr_start, offset - hdr_start,
					"<no content type has been specified>");
		}
		ok = TRUE;
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		peek = tvb_get_guint8(tvb, off);
		if (is_text_string(peek)) {
			get_extension_media(val_str, tvb, off, len, ok);
			off += len; /* off now points to 1st byte after string */
			ti = proto_tree_add_string (tree, hf_hdr_content_type,
					tvb, hdr_start, offset - hdr_start, val_str);
			*textual_content = g_strdup(val_str);
		} else if (is_integer_value(peek)) {
			get_integer_value(val, tvb, off, len, ok);
			if (ok) {
				ti = proto_tree_add_string(tree, hf_hdr_content_type,
						tvb, hdr_start, offset - hdr_start,
						val_to_str(val, vals_content_types,
							"<Unknown content type identifier 0x%X>"));
				*well_known_content = val;
			}
			off += len;
		} /* else ok = FALSE */
		/* Remember: offset == val_start + val_len */
		if (ok && (off < offset)) { /* Add parameters if any */
			parameter_tree = proto_item_add_subtree (ti,
					ett_parameters);
			while (off < offset) {
				off = parameter (parameter_tree, ti, tvb, off, offset - off);
			}
		}

	wkh_4_End(hf_hdr_content_type);
}


/*
 * Template for accept_X headers with optional Q parameter value
 */
#define wkh_accept_x_q_header(underscored,Text,valueString,valueName) \
static guint32 \
wkh_ ## underscored (proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start) \
{ \
	wkh_0_Declarations; \
	guint32 off, val = 0, len; \
	guint8 peek; \
	proto_tree *parameter_tree = NULL; \
	\
	wkh_1_WellKnownValue; \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, \
				val_to_str(val_id & 0x7F, valueString, \
					"<Unknown " valueName " identifier 0x%X>")); \
		ok = TRUE; \
	wkh_2_TextualValue; \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, val_str); \
	wkh_3_ValueWithLength; \
		off = val_start + val_len_len; \
		peek = tvb_get_guint8(tvb, off); \
		if (is_text_string(peek)) { \
			get_token_text(val_str, tvb, off, len, ok); \
			off += len; /* off now points to 1st byte after string */ \
			ti = proto_tree_add_string (tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, val_str); \
		} else if (is_integer_value(peek)) { \
			get_integer_value(val, tvb, off, len, ok); \
			if (ok) { \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, \
						val_to_str(val, valueString, \
							"<Unknown " valueName " identifier 0x%X>")); \
			} \
			off += len; \
		} /* else ok = FALSE */ \
		/* Remember: offset == val_start + val_len */ \
		if (ok && (off < offset)) { /* Add Q-value if available */ \
			parameter_tree = proto_item_add_subtree (ti, \
					ett_parameters); \
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
wkh_push_flag(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;
	proto_tree *subtree = NULL;

	wkh_1_WellKnownValue;
		ti = proto_tree_add_string(tree, hf_hdr_push_flag,
				tvb, hdr_start, offset - hdr_start, "");
		subtree = proto_item_add_subtree(ti, ett_push_flags);
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
 * Allow-value =
 *     Short-integer
 */
static guint32
wkh_allow(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		val_id &= 0x7F;
		if (val_id >= 0x40) { /* Valid WSP method */
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
wkh_public(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		val_id &= 0x7F;
		if (val_id >= 0x40) { /* Valid WSP method */
			ti = proto_tree_add_string(tree, hf_hdr_public,
					tvb, hdr_start, offset - hdr_start,
					val_to_str(val_id & 0x7F, vals_pdu_type,
						"<Unknown WSP method 0x%02X>"));
			ok = TRUE;
		}
	wkh_2_TextualValue;
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
wkh_vary(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		ti = proto_tree_add_string(tree, hf_hdr_vary,
				tvb, hdr_start, offset - hdr_start,
				val_to_str(val_id & 0x7F, vals_field_names,
					"<Unknown WSP header field 0x%02X>"));
		ok = TRUE;
	wkh_2_TextualValue;
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
wkh_x_wap_security(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		if (val_id == 0x80) {
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
wkh_connection(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		if (val_id == 0x80) {
			ti = proto_tree_add_string(tree, hf_hdr_connection,
					tvb, hdr_start, offset - hdr_start, "close");
			ok = TRUE;
		}
	wkh_2_TextualValue;
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
wkh_transfer_encoding(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		if (val_id == 0x80) {
			ti = proto_tree_add_string(tree, hf_hdr_transfer_encoding,
					tvb, hdr_start, offset - hdr_start, "chunked");
			ok = TRUE;
		}
	wkh_2_TextualValue;
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
wkh_accept_ranges(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		switch (val_id) {
			case 0x80: /* none */
				ti = proto_tree_add_string(tree, hf_hdr_accept_ranges,
						tvb, hdr_start, offset - hdr_start, "none");
				ok = TRUE;
				break;
			case 0x81: /* bytes */
				ti = proto_tree_add_string(tree, hf_hdr_accept_ranges,
						tvb, hdr_start, offset - hdr_start, "bytes");
				ok = TRUE;
				break;
		}
	wkh_2_TextualValue;
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
wkh_content_encoding(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;

	wkh_1_WellKnownValue;
		switch (val_id) {
			case 0x80: /* gzip */
				ti = proto_tree_add_string(tree, hf_hdr_content_encoding,
						tvb, hdr_start, offset - hdr_start, "gzip");
				ok = TRUE;
				break;
			case 0x81: /* compress */
				ti = proto_tree_add_string(tree, hf_hdr_content_encoding,
						tvb, hdr_start, offset - hdr_start, "compress");
				ok = TRUE;
				break;
			case 0x82: /* deflate */
				ti = proto_tree_add_string(tree, hf_hdr_content_encoding,
						tvb, hdr_start, offset - hdr_start, "deflate");
				ok = TRUE;
				break;
		}
	wkh_2_TextualValue;
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
wkh_accept_encoding(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;
	guint32 len, off;
	guint8 peek;
	gchar *str;
	proto_tree *parameter_tree = NULL;

	wkh_1_WellKnownValue;
		switch (val_id) {
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
		}
	wkh_2_TextualValue;
		proto_tree_add_string(tree, hf_hdr_accept_encoding,
				tvb, hdr_start, offset - hdr_start, val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		off = val_start + val_len_len;
		peek = tvb_get_guint8(tvb, off);
		if (is_short_integer(peek)) {
			switch (val_id) {
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
			/* Remember: offset == val_start + val_len */
			if (off < offset) { /* Add Q-value if available */
				parameter_tree = proto_item_add_subtree(ti, ett_parameters);
				off = parameter_value_q(parameter_tree, ti, tvb, off);
			}
		}
	wkh_4_End(hf_hdr_accept_encoding);
}


/*
 * Common code for headers with only a textual value
 * is written in the macro below:
 */
#define wkh_text_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start) \
{ \
	wkh_0_Declarations; \
	\
	wkh_1_WellKnownValue; \
		/* Invalid */ \
	wkh_2_TextualValue; \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, val_str); \
		ok = TRUE; \
	wkh_3_ValueWithLength; \
		/* Invalid */ \
	wkh_4_End(hf_hdr_ ## underscored); \
}

/* Text-only headers: */
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
wkh_text_header(content_id, "Content-ID")


/*
 * Common code for headers with only a textual or a date value
 * is written in the macro below:
 */
#define wkh_text_or_date_value_header(underscored,Text) \
static guint32 \
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	nstime_t tv; \
	gchar *str; /* may not be freed! */ \
	\
	wkh_1_WellKnownValue; \
		/* Invalid */ \
	wkh_2_TextualValue; \
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
				g_assert(str); \
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
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start) \
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
				g_assert(str); \
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
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	nstime_t tv; \
	gchar *str; /* may not be freed! */ \
	\
	wkh_1_WellKnownValue; \
		if (val_id == 0x80) { /* Openwave TOD header uses this format */ \
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
					ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
							tvb, hdr_start, offset - hdr_start, \
							"Requesting Time Of Day"); \
				} else { \
					tv.secs = val; \
					tv.nsecs = 0; \
					str = abs_time_to_str(&tv); \
					g_assert(str); \
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
wkh_age(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;
	guint32 val = 0, off = val_start, len;

	wkh_1_WellKnownValue;
		val = val_id & 0x7F;
		val_str = malloc(20 * sizeof(gchar));
		g_assert(val_str);
		sprintf(val_str, "%u second%s", val, PLURALIZE(val));
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
				val_str = malloc(20 * sizeof(gchar));
				g_assert(val_str);
				sprintf(val_str, "%u second%s", val, PLURALIZE(val));
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
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	\
	wkh_1_WellKnownValue; \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, \
				val_to_str(val_id & 0x7F, valueString, \
				"(Unknown " valueName " identifier 0x%X)")); \
		ok = TRUE; \
	wkh_2_TextualValue; \
		ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, val_str); \
		ok = TRUE; \
	wkh_3_ValueWithLength; \
		if (val_id <= 4) { /* Length field already parsed by macro! */ \
			get_long_integer(val, tvb, off, len, ok); \
			if (ok) { \
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
		guint32 hdr_start) \
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
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
					tvb, hdr_start, offset - hdr_start, "basic"); \
			subtree = proto_item_add_subtree(ti, ett_header_credentials); \
			proto_tree_add_string(subtree, hf_hdr_ ## underscored ## _scheme, \
					tvb, off, 1, "basic"); \
			off++; \
			/* User-id: text-string */ \
			get_text_string(str,tvb,off,len,ok); \
			if (ok) { \
				proto_tree_add_string(subtree, \
						hf_hdr_ ## underscored ## _user_id, \
						tvb, off, len, str); \
				val_str = malloc((len + 13) * sizeof(char)); \
				sprintf(val_str, "; user-id='%s'", str); \
				proto_item_append_string(ti, val_str); \
				g_free(val_str); \
				off += len; \
				/* Password: text-string */ \
				get_text_string(str,tvb,off,len,ok); \
				if (ok) { \
					proto_tree_add_string(subtree, \
							hf_hdr_ ## underscored ## _password, \
							tvb, off, len, str); \
					val_str = malloc((len + 14) * sizeof(char)); \
					sprintf(val_str, "; password='%s'", str); \
					proto_item_append_string(ti, val_str); \
					g_free(val_str); \
					off += len; \
				} \
			} \
		} else { /* Authentication-scheme: token-text */ \
			get_token_text(str, tvb, off, len, ok); \
			if (ok) { \
				ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, off - hdr_start, str); \
				subtree = proto_item_add_subtree(ti, ett_header_credentials); \
				proto_tree_add_string(subtree, \
						hf_hdr_ ## underscored ## _scheme, \
						tvb, hdr_start, off - hdr_start, str); \
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
wkh_content_md5 (proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
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
			val_str = g_malloc((1 + 32) * sizeof(char));
			g_assert(val_str);
			sprintf(val_str,
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
wkh_pragma(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;
	guint32 off;

	wkh_1_WellKnownValue;
		if (val_id == 0x80) {
			ti = proto_tree_add_string(tree, hf_hdr_pragma,
					tvb, hdr_start, offset - hdr_start, "no-cache");
			ok = TRUE;
		}
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		off = val_start;
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
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	gchar *str; /* may not be freed! */ \
	\
	wkh_1_WellKnownValue; \
		str = malloc(4 * sizeof(gchar)); \
		g_assert(str); \
		sprintf(str, "%u", val_id & 0x7F); \
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
				str = malloc(11 * sizeof(gchar)); \
				g_assert(str); \
				sprintf(str, "%u", val); \
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
wkh_ ## underscored(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start) \
{ \
	wkh_0_Declarations; \
	guint32 val = 0, off = val_start, len; \
	\
	wkh_1_WellKnownValue; \
		val_str = match_strval(val_id & 0x7F, valueString); \
		if (val_str) { \
			ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
				tvb, hdr_start, offset - hdr_start, val_str); \
			ok = TRUE; \
		} else { \
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
					ti = proto_tree_add_string(tree, hf_hdr_ ## underscored, \
						tvb, hdr_start, offset - hdr_start, val_str); \
					ok = TRUE; \
				} else { \
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
wkh_cache_control(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;
	guint32 off, len, val = 0;
	guint8 peek, cache_control_directive;

	wkh_1_WellKnownValue;
		val = val_id & 0x7F;
		val_str = match_strval(val, vals_cache_control);
		if (val_str) {
			ti = proto_tree_add_string(tree, hf_hdr_cache_control,
					tvb, hdr_start, offset - hdr_start, val_str);
			ok = TRUE;
		}
	wkh_2_TextualValue;
		ti = proto_tree_add_string(tree, hf_hdr_cache_control,
				tvb, hdr_start, offset - hdr_start, val_str);
		ok = TRUE;
	wkh_3_ValueWithLength;
		/* General form:
		 *	  ( no-cache | private ) 1*( Field-name )
		 *	| ( max-age | max-stale | min-fresh | s-maxage) Delta-seconds-value
		 *	| Token-text ( Integer-value | Text-string )
		 * Where:
		 *	Field-name = Short-integer | Token-text
		 */
		off = val_start + val_len_len;
		cache_control_directive = tvb_get_guint8(tvb, off++);
		if (cache_control_directive & 0x80) { /* Well known cache directive */
			switch (cache_control_directive & 0x7F) {
				case CACHE_CONTROL_NO_CACHE:
				case CACHE_CONTROL_PRIVATE:
					ti = proto_tree_add_string(tree, hf_hdr_cache_control,
							tvb, hdr_start, offset - hdr_start,
							match_strval(cache_control_directive & 0x7F,
								vals_cache_control));
					/* TODO: split multiple entries */
					while (ok && (off < offset)) { /* 1*( Field-name ) */
						ok = TRUE;
						peek = tvb_get_guint8(tvb, off);
						if (peek & 0x80) { /* Well-known-field-name */
							proto_item_append_string(ti,
									match_strval(peek, vals_field_names));
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
					ti = proto_tree_add_string(tree, hf_hdr_cache_control,
							tvb, hdr_start, offset - hdr_start,
							match_strval(cache_control_directive & 0x7F,
								vals_cache_control));
					get_delta_seconds_value(val, tvb, off, len, ok);
					if (ok) {
						val_str = malloc(22 * sizeof(gchar));
						g_assert(val_str);
						sprintf(val_str, " = %u second%s", val, PLURALIZE(val));
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
				ti = proto_tree_add_string(tree, hf_hdr_cache_control,
						tvb, hdr_start, offset - hdr_start, val_str);
				get_integer_value(val, tvb, off, len, ok);
				if (ok) { /* Integer-value */
					val_str = g_malloc(20 * sizeof(char));
					g_assert(val_str);
					sprintf(val_str, " = %u", val);
					proto_item_append_string(ti, val_str);
					g_free(val_str); /* proto_XXX creates a copy */
				} else { /* Text-string */
					get_text_string(val_str, tvb, off, len, ok);
					if (ok) {
						proto_item_append_string(ti, val_str);
						g_free(val_str); /* proto_XXX creates a copy */
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
wkh_warning(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;
	guint32 off, len, val;
	guint8 warn_code;
	char *str;

	/* TODO - subtree with values */

	wkh_1_WellKnownValue;
		val = val_id & 0x7F;
		val_str = match_strval(val, vals_wsp_warning_code);
		if (val_str) {
			ti = proto_tree_add_string(tree, hf_hdr_warning,
					tvb, hdr_start, offset - hdr_start, val_str);
			ok = TRUE;
		}
	wkh_2_TextualValue;
		/* Invalid */
	wkh_3_ValueWithLength;
		/* TODO - subtree with individual values */
		off = val_start + val_len_len;
		warn_code = tvb_get_guint8(tvb, off++);
		if (warn_code & 0x80) { /* Well known warn code */
			val_str = match_strval(warn_code & 0x7F,
					vals_wsp_warning_code_short);
			if (val_str) { /* OK */
				ti = proto_tree_add_string(tree, hf_hdr_warning,
						tvb, hdr_start, offset - hdr_start, val_str);
				get_text_string(str, tvb, off, len, ok);
				if (ok) { /* Valid warn-agent string */
					off += len;
					val_str = g_malloc((len+11) * sizeof(char));
					g_assert(val_str);
					sprintf(val_str, "; Agent = %s", str);
					proto_item_append_string(ti, val_str);
					g_free(val_str); /* proto_XXX creates a copy */
					get_text_string(str, tvb, off, len, ok);
					if (ok) { /* Valid warn-text string */
						off += len;
						val_str = g_malloc((len+3) * sizeof(char));
						g_assert(val_str);
						sprintf(val_str, ": %s", str);
						proto_item_append_string(ti, val_str);
						g_free(val_str); /* proto_XXX creates a copy */
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
wkh_profile_warning(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;
	guint32 off, len, val = 0;
	nstime_t tv;
	guint8 warn_code;
	char *str;

	wkh_1_WellKnownValue;
		val = val_id & 0x7F;
		val_str = match_strval(val, vals_wsp_profile_warning_code);
		if (val_str) {
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
				ti = proto_tree_add_string(tree, hf_hdr_profile_warning,
						tvb, hdr_start, offset - hdr_start, val_str);
				get_uri_value(str, tvb, off, len, ok);
				if (ok) { /* Valid warn-target string */
					off += len;
					str = g_malloc((len+12) * sizeof(char));
					g_assert(str);
					sprintf(str, "; Target = %s", val_str);
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
							g_assert(val_str);
							str = g_malloc((strlen(val_str)+10) * sizeof(char));
							g_assert(str);
							sprintf(str,"; Date = %s", val_str);
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




/****************************************************************************
 *                     O p e n w a v e   h e a d e r s
 ****************************************************************************/




/*
 * Redefine the WellKnownValue parsing so Openwave header field names are used
 * are used instead of the default WSP header field names
 */
#undef wkh_1_WellKnownValue
#define wkh_1_WellKnownValue			/* Parse Well Known Value */ \
	proto_tree_add_string_hidden(tree, hf_hdr_name, \
			tvb, hdr_start, offset - hdr_start, \
			match_strval (hdr_id, vals_openwave_field_names)); \
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
			proto_tree_add_string(tree, hf, \
					tvb, hdr_start, offset - hdr_start, \
					" <Error: Invalid header value>"); \
		} else { /* Create anonymous header field entry */ \
			proto_tree_add_text(tree, tvb, hdr_start, offset - hdr_start, \
					"%s: <Error: Invalid header value>", \
					val_to_str (hdr_id, vals_openwave_field_names, \
						"<Unknown WSP header field 0x%02X>")); \
		} \
	} \
	return offset;


/* Dissect the Openwave header value (generic) */
static guint32
wkh_openwave_default(proto_tree *tree, tvbuff_t *tvb, guint32 hdr_start)
{
	wkh_0_Declarations;

	ok = TRUE; /* Bypass error checking as we don't parse the values! */

	wkh_1_WellKnownValue;
		ti = proto_tree_add_text(tree, tvb, hdr_start, offset - hdr_start,
				"%s: (Undecoded well-known value 0x%02x)",
				match_strval(hdr_id, vals_openwave_field_names), val_id & 0x7F);
	wkh_2_TextualValue;
		ti = proto_tree_add_text(tree,tvb,hdr_start, offset - hdr_start,
				"%s: %s",
				match_strval(hdr_id, vals_openwave_field_names), val_str);
	wkh_3_ValueWithLength;
		ti = proto_tree_add_text(tree, tvb, hdr_start, offset - hdr_start,
				"%s: (Undecoded value in general form with length indicator)",
				match_strval(hdr_id, vals_openwave_field_names));

	wkh_4_End(HF_EMPTY); /* See wkh_default for explanation */
}


/* Textual Openwave headers */
wkh_text_header(openwave_x_up_proxy_operator_domain,
		"x-up-proxy-operator-domain");
wkh_text_header(openwave_x_up_proxy_home_page,
		"x-up-proxy-home-page");
wkh_text_header(openwave_x_up_proxy_uplink_version,
		"x-up-proxy-uplink-version");
wkh_text_header(openwave_x_up_proxy_ba_realm,
		"x-up-proxy-ba-realm");
wkh_text_header(openwave_x_up_proxy_request_uri,
		"x-up-proxy-request-uri");
wkh_text_header(openwave_x_up_proxy_client_id,
		"x-up-proxy-client-id");
wkh_text_header(openwave_x_up_proxy_bookmark,
		"x-up-proxy-bookmark");

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

/* Parameter = Untyped-parameter | Typed-parameter
 * Untyped-parameter = Token-text ( Integer-value | Text-value )
 * Typed-parameter =
 * 		Integer-value (
 * 			( Integer-value | Date-value | Delta-seconds-value
 * 			  | Q-value | Version-value | Uri-value )
 * 			| Text-value )
 */
static int
parameter (proto_tree *tree, proto_item *ti, tvbuff_t *tvb, int start, int len)
{
	int offset = start;
	guint8 peek = tvb_get_guint8 (tvb,start);
	guint32 val = 0, val_len;
	char *str = NULL;
	char *str2 = NULL;
	guint8 ok;

	if (is_token_text (peek)) { /* Untyped parameter */
		get_token_text (str,tvb,start,val_len,ok); /* always succeeds */
		offset += val_len;
		get_token_text (str2,tvb,offset,val_len,ok);
		offset += val_len;
		if (ok) { /* Valid str2 as string */
			proto_tree_add_text(tree, tvb, start, offset - start,
					"%s: %s", str, str2);
			proto_item_append_text(ti, "; %s=%s", str, str2);
		} else {
			get_integer_value (val,tvb,offset,val_len,ok);
			offset += val_len;
			if (ok) { /* Valid val as integer */
				proto_tree_add_text(tree, tvb, start, offset - start,
						"%s: %u", str, val);
				proto_item_append_text(ti, "; %s=%u", str, val);
			} else { /* Error: neither token-text not Integer-value */
				proto_tree_add_text (tree, tvb, start, offset - start,
						"<Error: Invalid untyped parameter definition>");
				offset = start + len; /* Skip to end of buffer */
			}
		}
		/* XXX - HERE is the fault: I only check the 1st string! * /
		offset = add_untyped_parameter (tree, tvb, offset, val_len); */
		return offset;
	} /* Else: typed parameter */
	get_integer_value (val,tvb,start,len,ok);
	if (!ok) {
		proto_tree_add_text (tree, tvb, start, offset - start,
				"<Error: Invalid typed parameter definition>");
		return (start + len); /* Skip to end of buffer */
	}
	offset += len;
	/* Now offset points to the parameter value */
	switch (val) {
		case 0x01:	/* WSP 1.1 encoding - Charset: Well-known-charset */
			offset = add_parameter_charset (tree, tvb, start, offset);
			break;

		case 0x03:	/* WSP 1.1 encoding - Type: Integer-value */
			get_integer_value (val,tvb,offset,val_len,ok);
			if (ok)
				proto_item_append_text (ti, "; Type=%u", val);
			else
				proto_tree_add_text (tree, tvb, start, offset,
						InvalidParameterValue("Type", "Integer-value"));
			offset = add_parameter_type (tree, tvb, start, offset);
			break;

		case 0x05:	/* WSP 1.1 encoding - Name: Text-string */
		case 0x17:	/* WSP 1.4 encoding - Name: Text-value */
			offset = add_parameter_text (tree, tvb, start, offset,
					hf_wsp_parameter_name, "Name");
			break;

		case 0x06:	/* WSP 1.1 encoding - Filename: Text-string */
		case 0x18:	/* WSP 1.4 encoding - Filename: Text-value */
			offset = add_parameter_text (tree, tvb, start, offset,
					hf_wsp_parameter_filename, "Filename");
			break;

		case 0x09:	/* WSP 1.2 encoding - Type (special): Constrained-encoding */
			offset = add_constrained_encoding(tree, tvb, start, offset);
			break;

		case 0x0A:	/* WSP 1.2 encoding - Start: Text-string */
		case 0x19:	/* WSP 1.4 encoding - Start (with multipart/related): Text-value */
			offset = add_parameter_text (tree, tvb, start, offset,
					hf_wsp_parameter_start, "Start");
			break;

		case 0x0B:	/* WSP 1.2 encoding - Start-info: Text-string */
		case 0x1A:	/* WSP 1.4 encoding - Start-info (with multipart/related): Text-value */
			offset = add_parameter_text (tree, tvb, start, offset,
					hf_wsp_parameter_start_info, "Start-info");
			break;

		case 0x0C:	/* WSP 1.3 encoding - Comment: Text-string */
		case 0x1B:	/* WSP 1.4 encoding - Comment: Text-value */
			offset = add_parameter_text (tree, tvb, start, offset,
					hf_wsp_parameter_comment, "Comment");
			break;

		case 0x0D:	/* WSP 1.3 encoding - Domain: Text-string */
		case 0x1C:	/* WSP 1.4 encoding - Domain: Text-value */
			offset = add_parameter_text (tree, tvb, start, offset,
					hf_wsp_parameter_domain, "Domain");
			break;

		case 0x0F:	/* WSP 1.3 encoding - Path: Text-string */
		case 0x1D:	/* WSP 1.4 encoding - Path: Text-value */
			offset = add_parameter_text (tree, tvb, start, offset,
					hf_wsp_parameter_path, "Path");
			break;

		case 0x11:	/* WSP 1.4 encoding - SEC: Short-integer (OCTET) */
			proto_tree_add_uint (tree, hf_wsp_parameter_sec, tvb, start, 2,
					tvb_get_guint8 (tvb, start+1) & 0x7F);
			offset++;
			break;

		case 0x12:	/* WSP 1.4 encoding - MAC: Text-value */
			offset = add_parameter_text (tree, tvb, start, offset,
					hf_wsp_parameter_mac, "MAC");
			break;

		case 0x02:	/* WSP 1.1 encoding - Level: Version-value */
			get_version_value(val,str,tvb,offset,val_len,ok);
			if (ok) {
				proto_tree_add_string (tree, hf_wsp_parameter_level,
						tvb, start, 1 + val_len, str);
				proto_item_append_text (ti, "; Level=%s", str);
			} else {
				proto_tree_add_text (tree, tvb, start, offset,
						InvalidParameterValue("Type", "Integer-value"));
			}
			offset += val_len;
			break;

		case 0x00:	/* WSP 1.1 encoding - Q: Q-value */
			get_uintvar_integer (val, tvb, offset, val_len, ok);
			if (ok && (val < 1100)) {
				if (val <= 100) { /* Q-value in 0.01 steps */
					str = g_malloc (3 * sizeof (char));
					g_assert (str);
					sprintf (str, "0.%02u", val - 1);
				} else { /* Q-value in 0.001 steps */
					str = g_malloc (4 * sizeof (char));
					g_assert (str);
					sprintf (str, "0.%03u", val - 100);
				}
				proto_item_append_text (ti, "; Q=%s", str);
				offset += val_len;
			} else {
				proto_tree_add_text (tree, tvb, start, offset,
						InvalidParameterValue("Q", "Q-value"));
				offset += val_len;
			}
			break;

		case 0x07:	/* WSP 1.1 encoding - Differences: Field-name */
		case 0x08:	/* WSP 1.1 encoding - Padding: Short-integer */
		case 0x0E:	/* WSP 1.3 encoding - Max-Age: Delta-seconds-value */
		case 0x10:	/* WSP 1.3 encoding - Secure: No-value */
		case 0x13:	/* WSP 1.4 encoding - Creation-date: Date-value */
		case 0x14:	/* WSP 1.4 encoding - Modification-date: Date-value */
		case 0x15:	/* WSP 1.4 encoding - Read-date: Date-value */
		case 0x16:	/* WSP 1.4 encoding - Size: Integer-value */
		default:
			offset += len; /* Skip the parameters */
			break;
	}
	return offset;
}


static int
parameter_value_q (proto_tree *tree, proto_item *ti, tvbuff_t *tvb, int start)
{
	int offset = start;
	guint32 val = 0, val_len;
	char *str = NULL;
	guint8 ok;

	get_uintvar_integer (val, tvb, offset, val_len, ok);
	if (ok && (val < 1100)) {
		if (val <= 100) { /* Q-value in 0.01 steps */
			str = g_malloc (3 * sizeof (char));
			g_assert (str);
			sprintf (str, "0.%02u", val - 1);
		} else { /* Q-value in 0.001 steps */
			str = g_malloc (4 * sizeof (char));
			g_assert (str);
			sprintf (str, "0.%03u", val - 100);
		}
		proto_item_append_text (ti, "; Q=%s", str);
		proto_tree_add_string (tree, hf_parameter_q,
				tvb, start, val_len, str);
		offset += val_len;
	} else {
		proto_tree_add_text (tree, tvb, start, offset,
				InvalidParameterValue("Q", "Q-value"));
		offset += val_len;
	}
	return val_len;
}




/* Code to actually dissect the packets */

/*
 * WSP redirect
 */

static void
dissect_redirect(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, dissector_handle_t dissector_handle)
{
	guint8 flags;
	proto_item *ti;
	proto_tree *flags_tree;
	guint8 bearer_type;
	guint8 address_flags_len;
	int address_len;
	proto_tree *atf_tree;
	guint16 port_num;
	guint32 address_ipv4;
	struct e_in6_addr address_ipv6;
	address redir_address;
	conversation_t *conv;

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
	while (tvb_reported_length_remaining (tvb, offset) > 0) {
		address_flags_len = tvb_get_guint8 (tvb, offset);
		if (tree) {
			ti = proto_tree_add_uint (tree, hf_wsp_redirect_afl,
			    tvb, offset, 1, address_flags_len);
			atf_tree = proto_item_add_subtree (ti, ett_redirect_afl);
			proto_tree_add_boolean (atf_tree, hf_wsp_redirect_afl_bearer_type_included,
			    tvb, offset, 1, address_flags_len);
			proto_tree_add_boolean (atf_tree, hf_wsp_redirect_afl_port_number_included,
			    tvb, offset, 1, address_flags_len);
			proto_tree_add_uint (atf_tree, hf_wsp_redirect_afl_address_len,
			    tvb, offset, 1, address_flags_len);
		}
		offset++;
		if (address_flags_len & BEARER_TYPE_INCLUDED) {
			bearer_type = tvb_get_guint8 (tvb, offset);
			if (tree) {
				proto_tree_add_uint (tree, hf_wsp_redirect_bearer_type,
				    tvb, offset, 1, bearer_type);
			}
			offset++;
		} else
			bearer_type = 0x00;	/* XXX */
		if (address_flags_len & PORT_NUMBER_INCLUDED) {
			port_num = tvb_get_ntohs (tvb, offset);
			if (tree) {
				proto_tree_add_uint (tree, hf_wsp_redirect_port_num,
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
		address_len = address_flags_len & ADDRESS_LEN;
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
			tvb_memcpy(tvb, (guint8 *)&address_ipv4, offset, 4);
			if (tree) {
				proto_tree_add_ipv4 (tree,
				    hf_wsp_redirect_ipv4_addr,
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
			conv = find_conversation(&redir_address, &pinfo->dst,
			    PT_UDP, port_num, 0, NO_PORT_B);
			if (conv == NULL) {
				conv = conversation_new(&redir_address,
				    &pinfo->dst, PT_UDP, port_num, 0, NO_PORT2);
			}
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
			tvb_memcpy(tvb, (guint8 *)&address_ipv6, offset, 16);
			if (tree) {
				proto_tree_add_ipv6 (tree,
				    hf_wsp_redirect_ipv6_addr,
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
			conv = find_conversation(&redir_address, &pinfo->dst,
			    PT_UDP, port_num, 0, NO_PORT_B);
			if (conv == NULL) {
				conv = conversation_new(&redir_address,
				    &pinfo->dst, PT_UDP, port_num, 0, NO_PORT2);
			}
			conversation_set_dissector(conv, dissector_handle);
			break;

		unknown_address_type:
		default:
			if (address_len != 0) {
				if (tree) {
					proto_tree_add_item (tree,
					    hf_wsp_redirect_addr,
					    tvb, offset, address_len,
					    bo_little_endian);
				}
			}
			break;
		}
		offset += address_len;
	}
}

static void
dissect_wsp_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    dissector_handle_t dissector_handle, gboolean is_connectionless)
{
	int offset = 0;

	guint8 pdut;
	guint8 reply_status;
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
	proto_tree *wsp_tree = NULL;
/*	proto_tree *wsp_header_fixed; */

	wsp_info_value_t *stat_info;
	stat_info = g_malloc( sizeof(wsp_info_value_t) );
	stat_info->status_code = 0;

/* This field shows up as the "Info" column in the display; you should make
   it, if possible, summarize what's in the packet, so that a user looking
   at the list of packets can tell what type of packet it is. */

	/* Connection-less mode has a TID first */
	if (is_connectionless)
	{
		offset++;
	};

	/* Find the PDU type */
	pdut = tvb_get_guint8 (tvb, offset);

	/* Develop the string to put in the Info column */
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, "WSP %s",
			val_to_str (pdut, vals_pdu_type, "Unknown PDU type (0x%02x)"));
	};

/* In the interest of speed, if "tree" is NULL, don't do any work not
   necessary to generate protocol tree items. */
	if (tree) {
		ti = proto_tree_add_item(tree, proto_wsp, tvb, 0, -1,
		    bo_little_endian);
		wsp_tree = proto_item_add_subtree(ti, ett_wsp);

/* Code to process the packet goes here */
/*
		wsp_header_fixed = proto_item_add_subtree(ti, ett_header );
*/

		/* Add common items: only TID and PDU Type */

		/* If this is connectionless, then the TID Field is always first */
		if (is_connectionless)
		{
			ti = proto_tree_add_item (wsp_tree, hf_wsp_header_tid,tvb,
				0,1,bo_little_endian);
		}

		ti = proto_tree_add_item(
				wsp_tree, 		/* tree */
				hf_wsp_header_pdu_type, /* id */
				tvb,
				offset, 		/* start of high light */
				1,			/* length of high light */
				bo_little_endian	/* value */
		     );
	}
	offset++;

	/* Map extended methods to the main method now the Column info has been written;
	 * this way we can dissect the extended method PDUs. */
	if ((pdut >= 0x50) && (pdut <= 0x5F))
		pdut = WSP_PDU_GET;
	else if ((pdut >= 0x70) && (pdut <= 0x7F))
		pdut = WSP_PDU_POST;

	switch (pdut)
	{
		case WSP_PDU_CONNECT:
		case WSP_PDU_CONNECTREPLY:
		case WSP_PDU_RESUME:
			if (tree) {
				if (pdut == WSP_PDU_CONNECT)
				{
					ti = proto_tree_add_item (wsp_tree, hf_wsp_version_major,tvb,offset,1,bo_little_endian);
					ti = proto_tree_add_item (wsp_tree, hf_wsp_version_minor,tvb,offset,1,bo_little_endian);
					offset++;
				} else {
					count = 0;	/* Initialise count */
					value = tvb_get_guintvar (tvb, offset, &count);
					ti = proto_tree_add_uint (wsp_tree, hf_wsp_server_session_id,tvb,offset,count,value);
					offset += count;
				}
				capabilityStart = offset;
				count = 0;	/* Initialise count */
				capabilityLength = tvb_get_guintvar (tvb, offset, &count);
				offset += count;
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_capability_length,tvb,capabilityStart,count,capabilityLength);

				if (pdut != WSP_PDU_RESUME)
				{
					count = 0;	/* Initialise count */
					headerLength = tvb_get_guintvar (tvb, offset, &count);
					ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,offset,count,headerLength);
					offset += count;
					capabilityStart = offset;
					headerStart = capabilityStart + capabilityLength;
				} else {
						/* Resume computes the headerlength by remaining bytes */
					capabilityStart = offset;
					headerStart = capabilityStart + capabilityLength;
					headerLength = tvb_reported_length_remaining (tvb, headerStart);
				}
				if (capabilityLength > 0)
				{
					tmp_tvb = tvb_new_subset (tvb, offset, capabilityLength, capabilityLength);
					add_capabilities (wsp_tree, tmp_tvb, pdut);
					offset += capabilityLength;
				}

				if (headerLength > 0)
				{
					tmp_tvb = tvb_new_subset (tvb, offset, headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb);
				}
			}

			break;

		case WSP_PDU_REDIRECT:
			dissect_redirect(tvb, offset, pinfo, wsp_tree,
			  dissector_handle);
			break;

		case WSP_PDU_DISCONNECT:
		case WSP_PDU_SUSPEND:
			if (tree) {
				count = 0;	/* Initialise count */
				value = tvb_get_guintvar (tvb, offset, &count);
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_server_session_id,tvb,offset,count,value);
			}
			break;

		case WSP_PDU_GET:
			count = 0;	/* Initialise count */
				/* Length of URI and size of URILen field */
			value = tvb_get_guintvar (tvb, offset, &count);
			nextOffset = offset + count;
			add_uri (wsp_tree, pinfo, tvb, offset, nextOffset);
			if (tree) {
				offset += (value+count); /* VERIFY */
				tmp_tvb = tvb_new_subset (tvb, offset, -1, -1);
				add_headers (wsp_tree, tmp_tvb);
			}
			break;

		case WSP_PDU_POST:
			uriStart = offset;
			count = 0;	/* Initialise count */
			uriLength = tvb_get_guintvar (tvb, offset, &count);
			headerStart = uriStart+count;
			count = 0;	/* Initialise count */
			headersLength = tvb_get_guintvar (tvb, headerStart, &count);
			offset = headerStart + count;

			add_uri (wsp_tree, pinfo, tvb, uriStart, offset);
			offset += uriLength;

			if (tree)
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,headerStart,count,headersLength);

			if (headersLength == 0)
				break;

			contentTypeStart = offset;
			nextOffset = add_content_type (wsp_tree,
			    tvb, offset, &contentType,
			    &contentTypeStr);

			if (tree) {
				/* Add headers subtree that will hold the headers fields */
				/* Runs from nextOffset for headersLength-(length of content-type field)*/
				headerLength = headersLength-(nextOffset-contentTypeStart);
				if (headerLength > 0)
				{
					tmp_tvb = tvb_new_subset (tvb, nextOffset, headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb);
				}
				offset = nextOffset+headerLength;
			}
			/* WSP_PDU_POST data - First check whether a subdissector exists for the content type */
			if (tvb_reported_length_remaining(tvb, headerStart + count + uriLength + headersLength) > 0)
			{
				tmp_tvb = tvb_new_subset (tvb, headerStart + count + uriLength + headersLength, -1, -1);
				/*
				 * Try finding a dissector for the content
				 * first, then fallback.
				 */
				if (contentTypeStr == NULL) {
					/*
					 * Content type is numeric.
					 */
					found_match =
					    dissector_try_port(wsp_dissector_table,
					      contentType, tmp_tvb, pinfo, tree);
				} else {
					/*
					 * Content type is a string.
					 */
					found_match = dissector_try_string(wsp_dissector_table_text,
					    contentTypeStr, tmp_tvb, pinfo, tree);
				}
				if (!found_match) {
					if (!dissector_try_heuristic(heur_subdissector_list,
					    tmp_tvb, pinfo, tree))
						if (tree) /* Only display if needed */
							add_post_data (wsp_tree, tmp_tvb,
							    contentType,
							    contentTypeStr);
				}
			}
			break;

		case WSP_PDU_REPLY:
			count = 0;	/* Initialise count */
			headersLength = tvb_get_guintvar (tvb, offset+1, &count);
			headerStart = offset + count + 1;
			reply_status = tvb_get_guint8(tvb, offset);
			if (tree)
				ti = proto_tree_add_item (wsp_tree, hf_wsp_header_status,tvb,offset,1,bo_little_endian);
 			stat_info->status_code = (gint) tvb_get_guint8( tvb, offset);				
			if (check_col(pinfo->cinfo, COL_INFO))
			{ /* Append status code to INFO column */
				col_append_fstr(pinfo->cinfo, COL_INFO, ": \"0x%02x %s\"", reply_status,
						val_to_str (reply_status, vals_status, "Unknown response status (0x%02x)"));
			}
			nextOffset = offset + 1 + count;
			if (tree)
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,offset+1,count,headersLength);

			if (headersLength == 0)
				break;

			contentTypeStart = nextOffset;
			nextOffset = add_content_type (wsp_tree,
			    tvb, nextOffset, &contentType,
			    &contentTypeStr);

			if (tree) {
				/* Add headers subtree that will hold the headers fields */
				/* Runs from nextOffset for headersLength-(length of content-type field)*/
				headerLength = headersLength-(nextOffset-contentTypeStart);
				if (headerLength > 0)
				{
					tmp_tvb = tvb_new_subset (tvb, nextOffset, headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb);
				}
				offset += count+headersLength+1;
			}
			/* WSP_PDU_REPLY data - First check whether a subdissector exists for the content type */
			if (tvb_reported_length_remaining(tvb, headerStart + headersLength) > 0)
			{
				tmp_tvb = tvb_new_subset (tvb, headerStart + headersLength, -1, -1);
				/*
				 * Try finding a dissector for the content
				 * first, then fallback.
				 */
				if (contentTypeStr == NULL) {
					/*
					 * Content type is numeric.
					 */
					found_match = dissector_try_port(wsp_dissector_table,
					    contentType, tmp_tvb, pinfo, tree);
				} else {
					/*
					 * Content type is a string.
					 */
					found_match = dissector_try_string(wsp_dissector_table_text,
					    contentTypeStr, tmp_tvb, pinfo, tree);
				}
				if (!found_match) {
					if (!dissector_try_heuristic(heur_subdissector_list,
					    tmp_tvb, pinfo, tree))
						if (tree) /* Only display if needed */
							ti = proto_tree_add_item (wsp_tree,
							    hf_wsp_reply_data,
							    tmp_tvb, 0, -1,
							    bo_little_endian);
				}
			}
			break;

		case WSP_PDU_PUSH:
		case WSP_PDU_CONFIRMEDPUSH:
			count = 0;	/* Initialise count */
			headersLength = tvb_get_guintvar (tvb, offset, &count);
			headerStart = offset + count;

			if (tree)
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,offset,count,headersLength);

			if (headersLength == 0)
				break;

			offset += count;
			contentTypeStart = offset;
			nextOffset = add_content_type (wsp_tree,
			    tvb, offset, &contentType,
			    &contentTypeStr);

			if (tree) {
				/* Add headers subtree that will hold the headers fields */
				/* Runs from nextOffset for headersLength-(length of content-type field)*/
				headerLength = headersLength-(nextOffset-contentTypeStart);
				if (headerLength > 0)
				{
					tmp_tvb = tvb_new_subset (tvb, nextOffset, headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb);
				}
				offset += headersLength;
			}
			/* WSP_PDU_PUSH data - First check whether a subdissector exists for the content type */
			if (tvb_reported_length_remaining(tvb, headerStart + headersLength) > 0)
			{
				tmp_tvb = tvb_new_subset (tvb, headerStart + headersLength, -1, -1);
				/* Try finding a dissector for the content first, then fallback */
				/*
				 * Try finding a dissector for the content
				 * first, then fallback.
				 */
				if (contentTypeStr == NULL) {
					/*
					 * Content type is numeric.
					 */
					found_match = dissector_try_port(wsp_dissector_table,
					    contentType, tmp_tvb, pinfo, tree);
				} else {
					/*
					 * Content type is a string.
					 */
					found_match = dissector_try_string(wsp_dissector_table_text,
					    contentTypeStr, tmp_tvb, pinfo, tree);
				}
				if (!found_match) {
					if (!dissector_try_heuristic(heur_subdissector_list,
					    tmp_tvb, pinfo, tree))
						if (tree) /* Only display if needed */
							ti = proto_tree_add_item (wsp_tree,
							    hf_wsp_push_data,
							    tmp_tvb, 0, -1,
							    bo_little_endian);
				}
			}
			break;

	}
	stat_info->pdut = pdut ;
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
add_uri (proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, guint URILenOffset, guint URIOffset)
{
	proto_item *ti;

	guint count = 0;
	guint uriLen = tvb_get_guintvar (tvb, URILenOffset, &count);

	if (tree)
		ti = proto_tree_add_uint (tree, hf_wsp_header_uri_len,tvb,URILenOffset,count,uriLen);

	tvb_ensure_bytes_exist(tvb, URIOffset, uriLen);
	if (tree)
		ti = proto_tree_add_item (tree, hf_wsp_header_uri,tvb,URIOffset,uriLen,bo_little_endian);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
		    tvb_format_text (tvb, URIOffset, uriLen));
	}
}


/*
 * CO-WSP capability negotiation
 */
static void
add_capabilities (proto_tree *tree, tvbuff_t *tvb, int type)
{
	proto_item *ti;
	proto_tree *wsp_capabilities;
	guint offset = 0;
	guint offsetStr = 0;
	guint capabilitiesLen = tvb_reported_length (tvb);
	guint capabilitiesStart = 0;
	guint peek = 0;
	guint length = 0;
	guint value = 0;
	guint i;
	int ret;
	char valString[VAL_STRING_SIZE];

#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: Offset is %d, size is %d\n", offset, capabilitiesLen);
#endif

	/* End of buffer */
	if (capabilitiesLen <= 0)
	{
		fprintf (stderr, "dissect_wsp: Capabilities = 0\n");
		return;
	}

#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: capabilities to process\n");
#endif

	ti = proto_tree_add_item (tree, hf_wsp_capabilities_section,tvb,offset,capabilitiesLen,bo_little_endian);
	wsp_capabilities = proto_item_add_subtree( ti, ett_capabilities );

	/* Parse Headers */

	while (offset < capabilitiesLen)
	{
		/* Loop round each header */
		capabilitiesStart = offset;
		length = tvb_get_guint8 (tvb, capabilitiesStart);

		if (length >= 127)		/* length */
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: capabilities length invalid %d\n",length);
#endif
			offset+=length;
			continue;
		}
		offset++;
		peek = tvb_get_guint8 (tvb, offset);
		offset++;
		switch (peek & 0x7f)
		{
			case 0x00 : /* Client-SDU-Size */
				value = get_uintvar (tvb, offset, length+capabilitiesStart+1);
				proto_tree_add_uint (wsp_capabilities, hf_wsp_capabilities_client_SDU, tvb, capabilitiesStart, length+1, value);
				break;
			case 0x01 : /* Server-SDU-Size */
				value = get_uintvar (tvb, offset, length+capabilitiesStart+1);
				proto_tree_add_uint (wsp_capabilities, hf_wsp_capabilities_server_SDU, tvb, capabilitiesStart, length+1, value);
				break;
			case 0x02 : /* Protocol Options */
				value = get_uintvar (tvb, offset, length+capabilitiesStart+1);
				i = 0;
				valString[0]=0;
				if (value & 0x80)
				{
					ret = snprintf(valString+i,VAL_STRING_SIZE-i,"%s","(Confirmed push facility) ");
					if (ret == -1 || (unsigned int) ret >= VAL_STRING_SIZE-i) {
						/*
						 * We've been truncated
						 */
						goto add_string;
					}
					i += ret;
				}
				if (value & 0x40)
				{
					if (i >= 200) {
						/* No more room. */
						goto add_string;
					}
					ret = snprintf(valString+i,VAL_STRING_SIZE-i,"%s","(Push facility) ");
					if (ret == -1 || (unsigned int) ret >= VAL_STRING_SIZE-i) {
						/*
						 * We've been truncated
						 */
						goto add_string;
					}
					i += ret;
				}
				if (value & 0x20)
				{
					if (i >= 200) {
						/* No more room. */
						goto add_string;
					}
					ret = snprintf(valString+i,VAL_STRING_SIZE-i,"%s","(Session resume facility) ");
					if (ret == -1 || (unsigned int) ret >= VAL_STRING_SIZE-i) {
						/*
						 * We've been truncated
						 */
						goto add_string;
					}
					i += ret;
				}
				if (value & 0x10)
				{
					if (i >= VAL_STRING_SIZE) {
						/* No more room. */
						goto add_string;
					}
					ret = snprintf(valString+i,VAL_STRING_SIZE-i,"%s","(Acknowledgement headers) ");
					if (ret == -1 || (unsigned int) ret >= VAL_STRING_SIZE-i) {
						/*
						 * We've been truncated
						 */
						goto add_string;
					}
					i += ret;
				}
			add_string:
				valString[VAL_STRING_SIZE-1] = '\0';
				proto_tree_add_string(wsp_capabilities, hf_wsp_capabilities_protocol_opt, tvb, capabilitiesStart, length+1, valString);
				break;
			case 0x03 : /* Method-MOR */
				value = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint (wsp_capabilities, hf_wsp_capabilities_method_MOR, tvb, capabilitiesStart, length+1, value);
				break;
			case 0x04 : /* Push-MOR */
				value = tvb_get_guint8(tvb, offset);
				proto_tree_add_uint (wsp_capabilities, hf_wsp_capabilities_push_MOR, tvb, capabilitiesStart, length+1, value);
				break;
				break;
			case 0x05 : /* Extended Methods */
				offsetStr = offset;
				offset++;
				add_capability_vals(tvb, (type == WSP_PDU_CONNECT),
				    offsetStr, length, capabilitiesStart,
				    valString, sizeof valString);
				proto_tree_add_string(wsp_capabilities, hf_wsp_capabilities_extended_methods, tvb, capabilitiesStart, length+1, valString);
				break;
			case 0x06 : /* Header Code Pages */
				offsetStr = offset;
				offset++;
				add_capability_vals(tvb, (type == WSP_PDU_CONNECT),
				    offsetStr, length, capabilitiesStart,
				    valString, sizeof valString);
				proto_tree_add_string(wsp_capabilities, hf_wsp_capabilities_header_code_pages, tvb, capabilitiesStart, length+1, valString);
				break;
			case 0x07 : /* Aliases */
				break;
			default:
				proto_tree_add_text (wsp_capabilities, tvb , capabilitiesStart, length+1,
				       "Undecoded Header (0x%02X)", peek & 0x7F);
				break;
		}
		offset=capabilitiesStart+length+1;
	}
}

static void
add_capability_vals(tvbuff_t *tvb, gboolean add_string, int offsetStr,
    guint length, guint capabilitiesStart, char *valString,
    size_t valStringSize)
{
	guint i;
	int ret;
	guint value;
	guint8 c;

	i = 0;
	while ((offsetStr-capabilitiesStart) <= length)
	{
		value = tvb_get_guint8(tvb, offsetStr);
		if (i >= valStringSize) {
			/* No more room. */
			break;
		}
		if (add_string)
		{
			ret = snprintf(valString+i,valStringSize-i,
			    "(0x%02x - ",value);
		}
		else
		{
			ret = snprintf(valString+i,valStringSize-i,"(0x%02x) ",
			    value);
		}
		if (ret == -1 || (unsigned int) ret >= valStringSize-i) {
			/*
			 * We've been truncated.
			 */
			break;
		}
		i += ret;
		offsetStr++;
		if (add_string)
		{
			for (;(c = tvb_get_guint8(tvb, offsetStr))
			    && i < valStringSize - 1; i++,offsetStr++)
				valString[i] = c;
			offsetStr++;
			if (i < valStringSize - 2) {
				valString[i++] = ')';
				valString[i++] = ' ';
			}
		}
	}
	valString[i] = '\0';
}

static value_type_t
get_value_type_len (tvbuff_t *tvb, int offset, guint *valueLen,
    int *valueOffset, int *nextOffset)
{
	guint8 peek;
	guint32 len;
	guint count;

	/* Get value part of header */
	peek = tvb_get_guint8 (tvb, offset);
	if (peek <= 30)
	{
		/*
		 * The value follows "peek", and is "peek" octets long.
		 */
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Looking for %d octets\n", peek);
#endif
		len = peek;
		*valueLen = len;	/* Length of value */
		offset++;		/* Skip the length */
		*valueOffset = offset;	/* Offset of value */
		offset += len;		/* Skip the value */
		*nextOffset = offset;	/* Offset after value */
		return VALUE_LEN_SUPPLIED;
	}
	else if (peek == 31)
	{
		/*
		 * A uintvar giving the length of the value follows
		 * "peek", and the value follows that.
		 */
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Looking for uintvar octets\n");
#endif
		offset++;		/* Skip the uintvar indicator */
		count = 0;		/* Initialise count */
		len = tvb_get_guintvar (tvb, offset, &count);
		*valueLen = len;	/* Length of value */
		offset += count;	/* Skip the length */
		*valueOffset = offset;	/* Offset of value */
		offset += len;		/* Skip the value */
		*nextOffset = offset;	/* Offset after value */
		return VALUE_LEN_SUPPLIED;
	}
	else if (peek <= 127)
	{
		/*
		 * The value is a NUL-terminated string, and "peek"
		 * is the first octet of the string.
		 */
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Looking for NUL-terminated string\n");
#endif
		len = tvb_strsize (tvb, offset);
		*valueLen = len;	/* Length of value */
		*valueOffset = offset;	/* Offset of value */
		offset += len;		/* Skip the value */
		*nextOffset = offset;	/* Offset after value */
		return VALUE_IS_TEXT_STRING;
	}
	else
	{
		/*
		 * "peek", with the 8th bit stripped off, is the value.
		 */
#ifdef DEBUG
		fprintf (stderr, "dissect_wsp: Value is %d\n", (peek & 0x7F));
#endif
		*valueLen = peek & 0x7F; /* Return the value itself */
		*valueOffset = offset;	/* Offset of value */
		offset++;		/* Skip the value */
		*nextOffset = offset;	/* Offset after value */
		return VALUE_IN_LEN;
	}
}

static guint
get_uintvar (tvbuff_t *tvb, guint offset, guint offsetEnd)
{
	guint value = 0;
	guint octet;

	do
	{
       		octet = tvb_get_guint8 (tvb, offset);
		offset++;
		value <<= 7;
		value += octet & 0x7f;
	}
	while ((offsetEnd > offset) && (octet & 0x80));
	return value;
}


static int
add_parameter_charset (proto_tree *tree, tvbuff_t *value_buff, int startOffset,
    int offset)
{
	value_type_t valueType;
	int subvalueLen;
	int subvalueOffset;
	guint value;

	valueType = get_value_type_len (value_buff, offset,
	    &subvalueLen, &subvalueOffset, &offset);
	if (valueType == VALUE_IN_LEN)
	{
		/*
		 * Integer-value.
		 */
		proto_tree_add_uint (tree, hf_wsp_parameter_well_known_charset,
		    value_buff, startOffset, offset - startOffset,
		    subvalueLen);	/* subvalueLen is the value */
		return offset;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Invalid.
		 */
	    	proto_tree_add_text (tree, value_buff, startOffset,
		    offset - startOffset, "Invalid Well-known charset");
		return offset;
	}

	/*
	 * First byte had the 8th bit set.
	 */
	if (subvalueLen == 0) {
		/*
		 * Any-charset.
		 * XXX - add this as a field?
		 */
		proto_tree_add_text (tree, value_buff, startOffset,
		    offset- startOffset, "*");
		return offset;
	}

	if (get_integer(value_buff, subvalueOffset, subvalueLen,
	    valueType, &value) == -1) {
	    	proto_tree_add_text (tree, value_buff, startOffset,
		    offset - startOffset, "Length %u not handled in Well-known charset",
		        subvalueLen);
	} else {
		proto_tree_add_uint (tree, hf_wsp_parameter_well_known_charset,
		    value_buff, startOffset, offset - startOffset, value);
	}
	return offset;
}

static int
add_constrained_encoding (proto_tree *tree, tvbuff_t *value_buff, int startOffset,
    int offset)
{
	value_type_t valueType;
	int subvalueLen;
	int subvalueOffset;
	guint value;

	valueType = get_value_type_len (value_buff, offset,
	    &subvalueLen, &subvalueOffset, &offset);
	if (valueType == VALUE_IN_LEN)
	{
		/*
		 * Integer-value, invalid
		 */
	    	proto_tree_add_text (tree, value_buff, startOffset,
		    offset - startOffset, "Invalid multipart type parameter");
		return offset;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * type-label.
		 */
		proto_tree_add_string (tree, hf_wsp_parameter_upart_type,
		    value_buff, startOffset, offset - startOffset,
		    tvb_get_ptr (value_buff, subvalueOffset, subvalueLen));
		return offset;
	}
	/*
	 * First byte had the 8th bit set.
	 */
	get_integer(value_buff, subvalueOffset, subvalueLen, valueType, &value);
	proto_tree_add_uint (tree, hf_wsp_parameter_upart_type_value,
	    value_buff, startOffset, offset - startOffset, value);
	return offset;
}

static int
add_parameter_type (proto_tree *tree, tvbuff_t *value_buff, int startOffset,
    int offset)
{
	value_type_t valueType;
	int subvalueLen;
	int subvalueOffset;
	guint value;

	valueType = get_value_type_len (value_buff, offset,
	    &subvalueLen, &subvalueOffset, &offset);
	if (get_integer(value_buff, subvalueOffset, subvalueLen,
	    valueType, &value) == -1) {
	    	proto_tree_add_text (tree, value_buff, startOffset,
		    offset - startOffset, "Invalid type");
	} else {
		proto_tree_add_uint (tree, hf_wsp_parameter_type, value_buff,
		    startOffset, offset - startOffset, value);
	}
	return offset;
}

static int
add_parameter_text (proto_tree *tree, tvbuff_t *value_buff, int startOffset,
    int offset, int hf_string, const char *paramName)
{
	value_type_t valueType;
	int subvalueLen;
	int subvalueOffset;

	valueType = get_value_type_len (value_buff, offset,
	    &subvalueLen, &subvalueOffset, &offset);
	if (valueType != VALUE_IS_TEXT_STRING) {
	    	proto_tree_add_text (tree, value_buff, startOffset,
		    offset - startOffset, "Invalid %s", paramName);
	} else {
		proto_tree_add_string (tree, hf_string, value_buff,
			    startOffset, offset - startOffset,
			    tvb_get_ptr (value_buff, subvalueOffset, subvalueLen));
	}
	return offset;
}

void
add_post_data (proto_tree *tree, tvbuff_t *tvb, guint contentType,
    const char *contentTypeStr)
{
	guint offset = 0;
	guint variableStart = 0;
	guint variableEnd = 0;
	guint valueStart = 0;
	guint valueEnd = 0;
	guint8 peek = 0;
	proto_item *ti;
	proto_tree *sub_tree;

	/* VERIFY ti = proto_tree_add_item (tree, hf_wsp_post_data,tvb,offset,-1,bo_little_endian); */
	ti = proto_tree_add_item (tree, hf_wsp_post_data,tvb,offset,-1,bo_little_endian);
	sub_tree = proto_item_add_subtree(ti, ett_post);

	if (contentTypeStr == NULL && contentType == 0x12)
	{
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
	}
	else if ((contentType == 0x22) || (contentType == 0x23) || (contentType == 0x24) ||
		 (contentType == 0x25) || (contentType == 0x26) || (contentType == 0x33))
	{
		add_multipart_data(sub_tree, tvb);
	}
}

static void
add_post_variable (proto_tree *tree, tvbuff_t *tvb, guint variableStart, guint variableEnd, guint valueStart, guint valueEnd)
{
	int variableLength = variableEnd-variableStart;
	int valueLength = 0;
	char *variableBuffer;
	char *valueBuffer;

	variableBuffer = g_malloc (variableLength+1);
	strncpy (variableBuffer, tvb_get_ptr (tvb, variableStart, variableLength), variableLength);
	variableBuffer[variableLength] = 0;

	if (valueEnd < valueStart)
	{
		valueBuffer = g_malloc (1);
		valueBuffer[0] = 0;
		valueEnd = valueStart;
	}
	else
	{
		valueLength = valueEnd-valueStart;
		valueBuffer = g_malloc (valueLength+1);
		strncpy (valueBuffer, tvb_get_ptr (tvb, valueStart, valueLength), valueLength);
		valueBuffer[valueLength] = 0;
	}

	/* Check for variables with no value */
	if (valueStart >= tvb_reported_length (tvb))
	{
		valueStart = tvb_reported_length (tvb);
		valueEnd = valueStart;
	}
	valueLength = valueEnd-valueStart;

	proto_tree_add_text (tree, tvb, variableStart, valueEnd-variableStart, "%s: %s", variableBuffer, valueBuffer);

	g_free (variableBuffer);
	g_free (valueBuffer);
}

static void
add_multipart_data (proto_tree *tree, tvbuff_t *tvb)
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

	proto_item	*sub_tree = NULL,
			*ti;
	proto_tree	*mpart_tree;

	nEntries = tvb_get_guintvar (tvb, offset, &count);
	offset += count;
	if (nEntries)
	{
		sub_tree = proto_tree_add_text(tree, tvb, offset - count, 0,
					"Multipart body");
		proto_item_add_subtree(sub_tree, ett_mpartlist);
	}
	while (nEntries--)
	{
		part_start = offset;
		HeadersLen = tvb_get_guintvar (tvb, offset, &count);
		offset += count;
		DataLen = tvb_get_guintvar (tvb, offset, &count);
		offset += count;
		ti = proto_tree_add_uint(sub_tree, hf_wsp_mpart, tvb, part_start,
					HeadersLen + DataLen + (offset - part_start), partnr);
		mpart_tree = proto_item_add_subtree(ti, ett_multiparts);
		nextOffset = add_content_type (mpart_tree, tvb, offset, &contentType, &contentTypeStr);
		HeadersLen -= (nextOffset - offset);
		if (HeadersLen > 0)
		{
			tmp_tvb = tvb_new_subset (tvb, nextOffset, HeadersLen, HeadersLen);
			add_headers (mpart_tree, tmp_tvb);
		}
		offset = nextOffset + HeadersLen;
		/* TODO - Try the dissectors of the multipart content */
		proto_tree_add_item (mpart_tree, hf_wsp_multipart_data, tvb, offset, DataLen, bo_little_endian);
		offset += DataLen;
		partnr++;
	}
}

static gint
get_integer (tvbuff_t *tvb, guint offset, guint valueLength,
    value_type_t valueType, guint *value)
{
	if (valueType == VALUE_IS_TEXT_STRING) {
		/*
		 * Not valid.
		 */
		return -1;
	}

	if (valueType == VALUE_IN_LEN) {
		/*
		 * Short-integer.
		 */
		*value = valueLength;
		return 0;
	}

	/*
	 * Long-integer.
	 */
	switch (valueLength)
	{
		case 1:
			*value = tvb_get_guint8(tvb, offset);
			break;
		case 2:
			*value = tvb_get_ntohs(tvb, offset);
			break;
		case 3:
		        *value = tvb_get_ntoh24(tvb, offset);
			break;
		case 4:
			*value = tvb_get_ntohl(tvb, offset);
			break;
		default:
		        /* TODO: Need to read peek octets */
		        *value = 0;
		        fprintf (stderr, "dissect_wsp: get_integer size %u NYI\n", valueLength);
	        	break;
	}
	return 0;
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
				"Transaction ID", HFILL
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
		{ &hf_wsp_capability_length,
			{ 	"Capability Length",
				"wsp.capability.length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Capability Length", HFILL
			}
		},
		{ &hf_wsp_header_length,
			{ 	"Headers Length",
				"wsp.headers_length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Headers Length", HFILL
			}
		},
		{ &hf_wsp_capabilities_section,
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
		{ &hf_wsp_header,
			{ 	"Header",
				"wsp.headers.header",
				 FT_NONE, BASE_DEC, NULL, 0x00,
				"Header", HFILL
			}
		},
		{ &hf_wsp_header_uri_len,
			{ 	"URI Length",
				"wsp.uri_length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"URI Length", HFILL
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
				"Status", HFILL
			}
		},
		{ &hf_wsp_content_type,
			{ 	"Content Type",
				"wsp.content_type.type",
				 FT_UINT8, BASE_HEX, VALS ( vals_content_types ), 0x00,
				"Content Type", HFILL
			}
		},
		{ &hf_wsp_content_type_str,
			{ 	"Content Type",
				"wsp.content_type.type.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Content Type", HFILL
			}
		},
		{ &hf_wsp_parameter_well_known_charset,
			{ 	"Charset",
				"wsp.content_type.parameter.charset",
				 FT_UINT16, BASE_HEX, VALS ( vals_character_sets ), 0x00,
				"Charset", HFILL
			}
		},
		{ &hf_wsp_parameter_type,
			{ 	"Type",
				"wsp.content_type.parameter.type",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Type", HFILL
			}
		},
		{ &hf_wsp_parameter_name,
			{ 	"Name",
				"wsp.content_type.parameter.name",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Name", HFILL
			}
		},
		{ &hf_wsp_parameter_filename,
			{ 	"Filename",
				"wsp.content_type.parameter.filename",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Filename", HFILL
			}
		},
		{ &hf_wsp_parameter_start,
			{ 	"Start",
				"wsp.content_type.parameter.start",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Start", HFILL
			}
		},
		{ &hf_wsp_parameter_start_info,
			{ 	"Start-info",
				"wsp.content_type.parameter.start_info",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Start-info", HFILL
			}
		},
		{ &hf_wsp_parameter_comment,
			{ 	"Comment",
				"wsp.content_type.parameter.comment",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Comment", HFILL
			}
		},
		{ &hf_wsp_parameter_domain,
			{ 	"Domain",
				"wsp.content_type.parameter.domain",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Domain", HFILL
			}
		},
		{ &hf_wsp_parameter_path,
			{ 	"Path",
				"wsp.content_type.parameter.path",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Path", HFILL
			}
		},
		{ &hf_wsp_parameter_sec,
			{ 	"SEC",
				"wsp.content_type.parameter.sec",
				 FT_UINT8, BASE_HEX, VALS (vals_wsp_parameter_sec), 0x00,
				"SEC parameter (Content-Type: application/vnd.wap.connectivity-wbxml)", HFILL
			}
		},
		{ &hf_wsp_parameter_mac,
			{ 	"MAC",
				"wsp.content_type.parameter.mac",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"MAC parameter (Content-Type: application/vnd.wap.connectivity-wbxml)", HFILL
			}
		},
		{ &hf_wsp_parameter_upart_type,
			{ 	"Type",
				"wsp.content_type.parameter.upart.type",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Multipart type", HFILL
			}
		},
		{ &hf_wsp_parameter_upart_type_value,
			{ 	"Type",
				"wsp.content_type.parameter.upart.type.int",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Multipart type (int value)", HFILL
			}
		},
		{ &hf_wsp_parameter_level,
			{ 	"Level",
				"wsp.content_type.parameter.level",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Level parameter", HFILL
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
			{ 	"Shift code",
				"wsp.header.shift",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Header code page shift code", HFILL
			}
		},
		/*
		 * CO-WSP capability negotiation
		 */
		{ &hf_wsp_capabilities_client_SDU,
			{	"Client SDU",
				"wsp.capabilities.client_SDU",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Client SDU", HFILL
			}
		},
		{ &hf_wsp_capabilities_server_SDU,
			{	"Server SDU",
				"wsp.capabilities.server_SDU",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Server SDU", HFILL
			}
		},
		{ &hf_wsp_capabilities_protocol_opt,
			{	"Protocol Options",
				"wsp.capabilities.protocol_opt",
				 FT_STRING, BASE_HEX, NULL, 0x00,
				"Protocol Options", HFILL
			}
		},
		{ &hf_wsp_capabilities_method_MOR,
			{	"Method MOR",
				"wsp.capabilities.method_mor",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Method MOR", HFILL
			}
		},
		{ &hf_wsp_capabilities_push_MOR,
			{	"Push MOR",
				"wsp.capabilities.push_mor",
				 FT_UINT8, BASE_DEC, NULL, 0x00,
				"Push MOR", HFILL
			}
		},
		{ &hf_wsp_capabilities_extended_methods,
			{	"Extended Methods",
				"wsp.capabilities.extend_methods",
				 FT_STRING, BASE_HEX, NULL, 0x00,
				"Extended Methods", HFILL
			}
		},
		{ &hf_wsp_capabilities_header_code_pages,
			{	"Header Code Pages",
				"wsp.capabilities.code_pages",
				 FT_STRING, BASE_HEX, NULL, 0x00,
				"Header Code Pages", HFILL
			}
		},
		{ &hf_wsp_capabilities_aliases,
			{	"Aliases",
				"wsp.capabilities.aliases",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Aliases", HFILL
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
				"wsp.redirect_flags",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Redirect Flags", HFILL
			}
		},
		{ &hf_wsp_redirect_permanent,
			{ 	"Permanent Redirect",
				"wsp.redirect_flags.permanent",
				 FT_BOOLEAN, 8, TFS(&yes_no_truth), PERMANENT_REDIRECT,
				"Permanent Redirect", HFILL
			}
		},
		{ &hf_wsp_redirect_reuse_security_session,
			{ 	"Reuse Security Session",
				"wsp.redirect_flags.reuse_security_session",
				 FT_BOOLEAN, 8, TFS(&yes_no_truth), REUSE_SECURITY_SESSION,
				"Permanent Redirect", HFILL
			}
		},
		{ &hf_wsp_redirect_afl,
			{ 	"Flags/Length",
				"wsp.redirect_afl",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Redirect Address Flags/Length", HFILL
			}
		},
		{ &hf_wsp_redirect_afl_bearer_type_included,
			{ 	"Bearer Type Included",
				"wsp.redirect_afl.bearer_type_included",
				 FT_BOOLEAN, 8, TFS(&yes_no_truth), BEARER_TYPE_INCLUDED,
				"Redirect Address bearer type included", HFILL
			}
		},
		{ &hf_wsp_redirect_afl_port_number_included,
			{ 	"Port Number Included",
				"wsp.redirect_afl.port_number_included",
				 FT_BOOLEAN, 8, TFS(&yes_no_truth), PORT_NUMBER_INCLUDED,
				"Redirect Address port number included", HFILL
			}
		},
		{ &hf_wsp_redirect_afl_address_len,
			{ 	"Address Len",
				"wsp.redirect_afl.address_len",
				 FT_UINT8, BASE_DEC, NULL, ADDRESS_LEN,
				"Redirect Address Length", HFILL
			}
		},
		{ &hf_wsp_redirect_bearer_type,
			{ 	"Bearer Type",
				"wsp.redirect_bearer_type",
				 FT_UINT8, BASE_HEX, VALS(vals_bearer_types), 0x0,
				"Redirect Bearer Type", HFILL
			}
		},
		{ &hf_wsp_redirect_port_num,
			{ 	"Port Number",
				"wsp.redirect_port_num",
				 FT_UINT16, BASE_DEC, NULL, 0x0,
				"Redirect Port Number", HFILL
			}
		},
		{ &hf_wsp_redirect_ipv4_addr,
			{ 	"IP Address",
				"wsp.redirect_ipv4_addr",
				 FT_IPv4, BASE_NONE, NULL, 0x0,
				"Redirect Address (IP)", HFILL
			}
		},
		{ &hf_wsp_redirect_ipv6_addr,
			{ 	"IPv6 Address",
				"wsp.redirect_ipv6_addr",
				 FT_IPv6, BASE_NONE, NULL, 0x0,
				"Redirect Address (IPv6)", HFILL
			}
		},
		{ &hf_wsp_redirect_addr,
			{ 	"Address",
				"wsp.redirect_addr",
				 FT_BYTES, BASE_NONE, NULL, 0x0,
				"Redirect Address", HFILL
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
		/* WSP well-known header ID */
		{ &hf_hdr_id,
			{	"Header well-known ID",
				"wsp.header.id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"7-bit identifier of a well-known WSP header", HFILL
			}
		},
		/* WSP headers start here */
		{ &hf_hdr_accept,
			{	"Accept",
				"wsp.hdr.accept",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept", HFILL
			}
		},
		{ &hf_hdr_accept_charset,
			{	"Accept-Charset",
				"wsp.hdr.accept_charset",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept-Charset", HFILL
			}
		},
		{ &hf_hdr_accept_encoding,
			{	"Accept-Encoding",
				"wsp.hdr.accept_encoding",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept-Encoding", HFILL
			}
		},
		{ &hf_hdr_accept_language,
			{	"Accept-Language",
				"wsp.hdr.accept_language",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept-Language", HFILL
			}
		},
		{ &hf_hdr_accept_ranges,
			{	"Accept-Ranges",
				"wsp.hdr.accept_ranges",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept-Ranges", HFILL
			}
		},
		{ &hf_hdr_age,
			{	"Age",
				"wsp.hdr.age",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Age", HFILL
			}
		},
		{ &hf_hdr_allow,
			{	"Allow",
				"wsp.hdr.allow",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Allow", HFILL
			}
		},
		{ &hf_hdr_authorization,
			{	"Authorization",
				"wsp.hdr.authorization",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Authorization", HFILL
			}
		},
		{ &hf_hdr_authorization_scheme,
			{	"Authorization Scheme",
				"wsp.hdr.authorization.scheme",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Authorization: used scheme", HFILL
			}
		},
		{ &hf_hdr_authorization_user_id,
			{	"user_id",
				"wsp.hdr.authorization.user_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Authorization: user ID for basic authorization", HFILL
			}
		},
		{ &hf_hdr_authorization_password,
			{	"password",
				"wsp.hdr.authorization.password",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Authorization: password for basic authorization", HFILL
			}
		},
		{ &hf_hdr_cache_control,
			{	"Cache-Control",
				"wsp.hdr.cache_control",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Cache-Control", HFILL
			}
		},
		{ &hf_hdr_connection,
			{	"Connection",
				"wsp.hdr.connection",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Connection", HFILL
			}
		},
		{ &hf_hdr_content_encoding,
			{	"Content-Encoding",
				"wsp.hdr.content_encoding",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Encoding", HFILL
			}
		},
		{ &hf_hdr_content_language,
			{	"Content-Language",
				"wsp.hdr.content_language",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Language", HFILL
			}
		},
		{ &hf_hdr_content_length,
			{	"Content-Length",
				"wsp.hdr.content_length",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Length", HFILL
			}
		},
		{ &hf_hdr_content_location,
			{	"Content-Location",
				"wsp.hdr.content_location",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Location", HFILL
			}
		},
		{ &hf_hdr_content_md5,
			{	"Content-Md5",
				"wsp.hdr.content_md5",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Md5", HFILL
			}
		},
		{ &hf_hdr_content_range,
			{	"Content-Range",
				"wsp.hdr.content_range",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Range", HFILL
			}
		},
		{ &hf_hdr_content_type,
			{	"Content-Type",
				"wsp.hdr.content_type",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Type", HFILL
			}
		},
		{ &hf_hdr_date,
			{	"Date",
				"wsp.hdr.date",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Date", HFILL
			}
		},
		{ &hf_hdr_etag,
			{	"ETag",
				"wsp.hdr.etag",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header ETag", HFILL
			}
		},
		{ &hf_hdr_expires,
			{	"Expires",
				"wsp.hdr.expires",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Expires", HFILL
			}
		},
		{ &hf_hdr_from,
			{	"From",
				"wsp.hdr.from",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header From", HFILL
			}
		},
		{ &hf_hdr_host,
			{	"Host",
				"wsp.hdr.host",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Host", HFILL
			}
		},
		{ &hf_hdr_if_modified_since,
			{	"If-Modified-Since",
				"wsp.hdr.if_modified_since",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header If-Modified-Since", HFILL
			}
		},
		{ &hf_hdr_if_match,
			{	"If-Match",
				"wsp.hdr.if_match",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header If-Match", HFILL
			}
		},
		{ &hf_hdr_if_none_match,
			{	"If-None-Match",
				"wsp.hdr.if_none_match",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header If-None-Match", HFILL
			}
		},
		{ &hf_hdr_if_range,
			{	"If-Range",
				"wsp.hdr.if_range",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header If-Range", HFILL
			}
		},
		{ &hf_hdr_if_unmodified_since,
			{	"If-Unmodified-Since",
				"wsp.hdr.if_unmodified_since",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header If-Unmodified-Since", HFILL
			}
		},
		{ &hf_hdr_last_modified,
			{	"Last-Modified",
				"wsp.hdr.last_modified",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Last-Modified", HFILL
			}
		},
		{ &hf_hdr_location,
			{	"Location",
				"wsp.hdr.location",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Location", HFILL
			}
		},
		{ &hf_hdr_max_forwards,
			{	"Max-Forwards",
				"wsp.hdr.max_forwards",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Max-Forwards", HFILL
			}
		},
		{ &hf_hdr_pragma,
			{	"Pragma",
				"wsp.hdr.pragma",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Pragma", HFILL
			}
		},
		{ &hf_hdr_proxy_authenticate,
			{	"Proxy-Authenticate",
				"wsp.hdr.proxy_authenticate",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authenticate", HFILL
			}
		},
		{ &hf_hdr_proxy_authorization,
			{	"Proxy-Authorization",
				"wsp.hdr.proxy_authorization",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authorization", HFILL
			}
		},
		{ &hf_hdr_proxy_authorization_scheme,
			{	"Authorization Scheme",
				"wsp.hdr.proxy_authorization.scheme",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authorization: used scheme", HFILL
			}
		},
		{ &hf_hdr_proxy_authorization_user_id,
			{	"user_id",
				"wsp.hdr.proxy_authorization.user_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authorization: user ID for basic authorization", HFILL
			}
		},
		{ &hf_hdr_proxy_authorization_password,
			{	"password",
				"wsp.hdr.proxy_authorization.password",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Proxy-Authorization: password for basic authorization", HFILL
			}
		},
		{ &hf_hdr_public,
			{	"Public",
				"wsp.hdr.public",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Public", HFILL
			}
		},
		{ &hf_hdr_range,
			{	"Range",
				"wsp.hdr.range",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Range", HFILL
			}
		},
		{ &hf_hdr_referer,
			{	"Referer",
				"wsp.hdr.referer",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Referer", HFILL
			}
		},
		{ &hf_hdr_retry_after,
			{	"Retry-After",
				"wsp.hdr.retry_after",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Retry-After", HFILL
			}
		},
		{ &hf_hdr_server,
			{	"Server",
				"wsp.hdr.server",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Server", HFILL
			}
		},
		{ &hf_hdr_transfer_encoding,
			{	"Transfer-Encoding",
				"wsp.hdr.transfer_encoding",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Transfer-Encoding", HFILL
			}
		},
		{ &hf_hdr_upgrade,
			{	"Upgrade",
				"wsp.hdr.upgrade",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Upgrade", HFILL
			}
		},
		{ &hf_hdr_user_agent,
			{	"User-Agent",
				"wsp.hdr.user_agent",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header User-Agent", HFILL
			}
		},
		{ &hf_hdr_vary,
			{	"Vary",
				"wsp.hdr.vary",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Vary", HFILL
			}
		},
		{ &hf_hdr_via,
			{	"Via",
				"wsp.hdr.via",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Via", HFILL
			}
		},
		{ &hf_hdr_warning,
			{	"Warning",
				"wsp.hdr.warning",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Warning", HFILL
			}
		},
		{ &hf_hdr_www_authenticate,
			{	"Www-Authenticate",
				"wsp.hdr.www_authenticate",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Www-Authenticate", HFILL
			}
		},
		{ &hf_hdr_content_disposition,
			{	"Content-Disposition",
				"wsp.hdr.content_disposition",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Disposition", HFILL
			}
		},
		{ &hf_hdr_application_id,
			{	"Application-Id",
				"wsp.hdr.application_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Application-Id", HFILL
			}
		},
		{ &hf_hdr_content_uri,
			{	"Content-Uri",
				"wsp.hdr.content_uri",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Uri", HFILL
			}
		},
		{ &hf_hdr_initiator_uri,
			{	"Initiator-Uri",
				"wsp.hdr.initiator_uri",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Initiator-Uri", HFILL
			}
		},
		{ &hf_hdr_bearer_indication,
			{	"Bearer-Indication",
				"wsp.hdr.bearer_indication",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Bearer-Indication", HFILL
			}
		},
		{ &hf_hdr_push_flag,
			{	"Push-Flag",
				"wsp.hdr.push_flag",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Push-Flag", HFILL
			}
		},
		{ &hf_hdr_push_flag_auth,
			{	"Initiator URI is authenticated",
				"wsp.hdr.push_flag.authenticated",
				FT_UINT8, BASE_DEC, VALS(vals_false_true), 0x01,
				"The X-Wap-Initiator-URI has been authenticated.", HFILL
			}
		},
		{ &hf_hdr_push_flag_trust,
			{	"Content is trusted",
				"wsp.hdr.push_flag.trusted",
				FT_UINT8, BASE_DEC, VALS(vals_false_true), 0x02,
				"The push content is trusted.", HFILL
			}
		},
		{ &hf_hdr_push_flag_last,
			{	"Last push message",
				"wsp.hdr.push_flag.last",
				FT_UINT8, BASE_DEC, VALS(vals_false_true), 0x04,
				"Indicates whether this is the last push message.", HFILL
			}
		},
		{ &hf_hdr_profile,
			{	"Profile",
				"wsp.hdr.profile",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Profile", HFILL
			}
		},
		{ &hf_hdr_profile_diff,
			{	"Profile-Diff",
				"wsp.hdr.profile_diff",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Profile-Diff", HFILL
			}
		},
		{ &hf_hdr_profile_warning,
			{	"Profile-Warning",
				"wsp.hdr.profile_warning",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Profile-Warning", HFILL
			}
		},
		{ &hf_hdr_expect,
			{	"Expect",
				"wsp.hdr.expect",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Expect", HFILL
			}
		},
		{ &hf_hdr_te,
			{	"Te",
				"wsp.hdr.te",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Te", HFILL
			}
		},
		{ &hf_hdr_trailer,
			{	"Trailer",
				"wsp.hdr.trailer",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Trailer", HFILL
			}
		},
		{ &hf_hdr_x_wap_tod,
			{	"X-Wap-Tod",
				"wsp.hdr.x_wap_tod",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header X-Wap-Tod", HFILL
			}
		},
		{ &hf_hdr_content_id,
			{	"Content-Id",
				"wsp.hdr.content_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Content-Id", HFILL
			}
		},
		{ &hf_hdr_set_cookie,
			{	"Set-Cookie",
				"wsp.hdr.set_cookie",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Set-Cookie", HFILL
			}
		},
		{ &hf_hdr_cookie,
			{	"Cookie",
				"wsp.hdr.cookie",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Cookie", HFILL
			}
		},
		{ &hf_hdr_encoding_version,
			{	"Encoding-Version",
				"wsp.hdr.encoding_version",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Encoding-Version", HFILL
			}
		},
		{ &hf_hdr_x_wap_security,
			{	"X-Wap-Security",
				"wsp.hdr.x_wap_security",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header X-Wap-Security", HFILL
			}
		},
		{ &hf_hdr_x_wap_application_id,
			{	"X-Wap-Application-Id",
				"wsp.hdr.x_wap_application_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header X-Wap-Application-Id", HFILL
			}
		},
		{ &hf_hdr_accept_application,
			{	"Accept-Application",
				"wsp.hdr.accept_application",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP header Accept-Application", HFILL
			}
		},


		/*
		 * Openwave headers
		 */

		/* Textual headers */
		{ &hf_hdr_openwave_x_up_proxy_operator_domain,
			{	"x-up-proxy-operator-domain",
				"wsp.hdr.openwave.x_up_proxy_operator_domain",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-operator-domain", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_home_page,
			{	"x-up-proxy-home-page",
				"wsp.hdr.openwave.x_up_proxy_home_page",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-home-page", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_uplink_version,
			{	"x-up-proxy-uplink-version",
				"wsp.hdr.openwave.x_up_proxy_uplink_version",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-uplink-version", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_ba_realm,
			{	"x-up-proxy-ba-realm",
				"wsp.hdr.openwave.x_up_proxy_ba_realm",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-ba-realm", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_request_uri,
			{	"x-up-proxy-request-uri",
				"wsp.hdr.openwave.x_up_proxy_request_uri",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-request-uri", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_client_id,
			{	"x-up-proxy-client-id",
				"wsp.hdr.openwave.x_up_proxy_client_id",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-client-id", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_bookmark,
			{	"x-up-proxy-bookmark",
				"wsp.hdr.openwave.x_up_proxy_bookmark",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-bookmark", HFILL
			}
		},
		/* Integer-value headers */
		{ &hf_hdr_openwave_x_up_proxy_push_seq,
			{	"x-up-proxy-push-seq",
				"wsp.hdr.openwave.x_up_proxy_push_seq",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-push-seq", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_notify,
			{	"x-up-proxy-notify",
				"wsp.hdr.openwave.x_up_proxy_notify",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-notify", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_net_ask,
			{	"x-up-proxy-net-ask",
				"wsp.hdr.openwave.x_up_proxy_net_ask",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-net-ask", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_tod,
			{	"x-up-proxy-tod",
				"wsp.hdr.openwave.x_up_proxy_tod",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-tod", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_ba_enable,
			{	"x-up-proxy-ba-enable",
				"wsp.hdr.openwave.x_up_proxy_ba_enable",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-ba-enable", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_redirect_enable,
			{	"x-up-proxy-redirect-enable",
				"wsp.hdr.openwave.x_up_proxy_redirect_enable",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-redirect-enable", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_redirect_status,
			{	"x-up-proxy-redirect-status",
				"wsp.hdr.openwave.x_up_proxy_redirect_status",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-redirect-status", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_linger,
			{	"x-up-proxy-linger",
				"wsp.hdr.openwave.x_up_proxy_linger",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-linger", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_enable_trust,
			{	"x-up-proxy-enable-trust",
				"wsp.hdr.openwave.x_up_proxy_enable_trust",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-enable-trust", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_trust,
			{	"x-up-proxy-trust",
				"wsp.hdr.openwave.x_up_proxy_trust",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-trust", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_has_color,
			{	"x-up-devcap-has-color",
				"wsp.hdr.openwave.x_up_devcap_has_color",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-has-color", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_num_softkeys,
			{	"x-up-devcap-num-softkeys",
				"wsp.hdr.openwave.x_up_devcap_num_softkeys",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-num-softkeys", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_softkey_size,
			{	"x-up-devcap-softkey-size",
				"wsp.hdr.openwave.x_up_devcap_softkey_size",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-softkey-size", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_screen_chars,
			{	"x-up-devcap-screen-chars",
				"wsp.hdr.openwave.x_up_devcap_screen_chars",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-screen-chars", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_screen_pixels,
			{	"x-up-devcap-screen-pixels",
				"wsp.hdr.openwave.x_up_devcap_screen_pixels",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-screen-pixels", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_em_size,
			{	"x-up-devcap-em-size",
				"wsp.hdr.openwave.x_up_devcap_em_size",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-em-size", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_screen_depth,
			{	"x-up-devcap-screen-depth",
				"wsp.hdr.openwave.x_up_devcap_screen_depth",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-screen-depth", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_immed_alert,
			{	"x-up-devcap-immed-alert",
				"wsp.hdr.openwave.x_up_devcap_immed_alert",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-immed-alert", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_devcap_gui,
			{	"x-up-devcap-gui",
				"wsp.hdr.openwave.x_up_devcap_gui",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-devcap-gui", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_trans_charset,
			{	"x-up-proxy-trans-charset",
				"wsp.hdr.openwave.x_up_proxy_trans_charset",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-trans-charset", HFILL
			}
		},
		{ &hf_hdr_openwave_x_up_proxy_push_accept,
			{	"x-up-proxy-push-accept",
				"wsp.hdr.openwave.x_up_proxy_push_accept",
				FT_STRING, BASE_NONE, NULL, 0x00,
				"WSP Openwave header x-up-proxy-push-accept", HFILL
			}
		},

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
	};


/* Setup protocol subtree array */
	static gint *ett[] = { /* TODO - remove unneeded subtrees */
		&ett_wsp,
		&ett_content_type_parameters,
		&ett_header,
		&ett_headers,
		&ett_header_warning,
		&ett_header_cache_control_parameters,
		&ett_header_cache_control_field_names,
		&ett_capabilities,
		&ett_post,
		&ett_content_type,
		&ett_redirect_flags,
		&ett_redirect_afl,
		&ett_multiparts,
		&ett_mpartlist,
		&ett_header_credentials,
		&ett_push_flags,
		&ett_parameters,
		&ett_authorization,	/* Authorization, Proxy-Authorization */
		&ett_authenticate, /* WWW-Authenticate, Proxy-Authenticate */
		&ett_warning, /* Warning */
	};

/* Register the protocol name and description */
	proto_wsp = proto_register_protocol(
		"Wireless Session Protocol",   	/* protocol name for use by ethereal */
		"WSP",                          /* short version of name */
		"wap-wsp"                   	/* Abbreviated protocol name,
										   should Match IANA:
	    < URL:http://www.isi.edu/in-notes/iana/assignments/port-numbers/ >
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
	wsp_dissector_table = register_dissector_table(
			"wsp.content_type.integer",
			"WSP content type (well-known integer value)",
			FT_UINT32, BASE_HEX);
	wsp_dissector_table_text = register_dissector_table(
			"wsp.content_type.literal",
			"WSP content type (textual value)",
			FT_STRING, BASE_NONE);
	register_heur_dissector_list("wsp", &heur_subdissector_list);

	wsp_fromudp_handle = create_dissector_handle(dissect_wsp_fromudp,
	    proto_wsp);
	
	
};

void
proto_reg_handoff_wsp(void)
{
	/*
	 * Get a handle for the WBXML dissector.
	 */
	wbxml_handle = find_dissector("wbxml");

	/*
	 * And get a handle for the WTP-over-UDP dissector.
	 */
	wtp_fromudp_handle = find_dissector("wtp-udp");

	/* Only connection-less WSP has no previous handler */
	dissector_add("udp.port", UDP_PORT_WSP, wsp_fromudp_handle);
	dissector_add("udp.port", UDP_PORT_WSP_PUSH, wsp_fromudp_handle);

	/* SMPP dissector can also carry WSP */
	dissector_add("smpp.udh.port", UDP_PORT_WSP, wsp_fromudp_handle);
	dissector_add("smpp.udh.port", UDP_PORT_WSP_PUSH, wsp_fromudp_handle);

	/* This dissector is also called from the WTP and WTLS dissectors */
}
