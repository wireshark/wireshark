/* packet-wsp.c
 *
 * Routines to dissect WSP component of WAP traffic.
 * 
 * $Id: packet-wsp.c,v 1.53 2002/02/01 07:12:09 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * WAP dissector based on original work by Ben Fowler
 * Updated by Neil Hunter <neil.hunter@energis-squared.com>
 * WTLS support by Alexandre P. Ferreira (Splice IP)
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/ipv6-utils.h>
#include <epan/conversation.h>
#include "packet-wap.h"
#include "packet-wsp.h"

/* File scoped variables for the protocol and registered fields */
static int proto_wsp 					= HF_EMPTY;

/* These fields used by fixed part of header */
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
static int hf_wsp_parameter_upart_type			= HF_EMPTY;
static int hf_wsp_parameter_upart_type_value		= HF_EMPTY;
static int hf_wsp_reply_data				= HF_EMPTY;
static int hf_wsp_post_data				= HF_EMPTY;
static int hf_wsp_push_data				= HF_EMPTY;
static int hf_wsp_multipart_data			= HF_EMPTY;
static int hf_wsp_mpart					= HF_EMPTY;

static int hf_wsp_header_shift_code			= HF_EMPTY;
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
static gint ett_content_type				= ETT_EMPTY;
static gint ett_redirect_flags				= ETT_EMPTY;
static gint ett_redirect_afl				= ETT_EMPTY;
static gint ett_multiparts				= ETT_EMPTY;
static gint ett_mpartlist				= ETT_EMPTY;

/* Handle for WSP-over-UDP dissector */
static dissector_handle_t wsp_fromudp_handle;

/* Handle for WTP-over-UDP dissector */
static dissector_handle_t wtp_fromudp_handle;

/* Handle for WMLC dissector */
static dissector_handle_t wmlc_handle;

static const value_string vals_pdu_type[] = {
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

	{ 0x60, "Post" },
	{ 0x61, "Put" },

	/* 0x62 - 0x6F Unassigned (Post PDU) */
	/* 0x70 - 0x7F Extended method (Post PDU) */
	/* 0x80 - 0xFF Reserved */

	{ 0x00, NULL }

};

static const value_string vals_status[] = {
	/* 0x00 - 0x0F Reserved */

	{ 0x10, "Continue" },
	{ 0x11, "Switching Protocols" },

	{ 0x20, "OK" },
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
	{ 0x37, "Temporary Redirect" },

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
	{ 0x4A, "Gone" },
	{ 0x4B, "Length Required" },
	{ 0x4C, "Precondition Failed" },
	{ 0x4D, "Request Entity Too Large" },
	{ 0x4E, "Request-URI Too Large" },
	{ 0x4F, "Unsupported Media Type" },
	{ 0x50, "Requested Range Not Satisfiable" },
	{ 0x51, "Expectation Failed" },

	{ 0x60, "Internal Server Error" },
	{ 0x61, "Not Implemented" },
	{ 0x62, "Bad Gateway" },
	{ 0x63, "Service Unavailable" },
	{ 0x64, "Gateway Timeout" },
	{ 0x65, "HTTP Version Not Supported" },
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
	{ FN_ETAG,                 "Etag" },
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
	{ 0x0B, "Multipart/*" },
	{ 0x0C, "Multipart/mixed" },
	{ 0x0D, "Multipart/form-data" },
	{ 0x0E, "Multipart/byteranges" },
	{ 0x0F, "Multipart/alternative" },
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
	{ 0x22, "French (fr)" },
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
	{ 0x30, "Indonesian (formerly in) (id)" },
	{ 0x47, "Maori (mi)" },
	{ 0x48, "Macedonian (mk)" },
	{ 0x49, "Malayalam (ml)" },
	{ 0x4A, "Mongolian (mn)" },
	{ 0x4B, "Moldavian (mo)" },
	{ 0x4C, "Marathi (mr)" },
	{ 0x4D, "Malay (ms)" },
	{ 0x4E, "Maltese (mt)" },
	{ 0x4F, "Burmese (my)" },
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
	{ 0x81, "Nauru (na)" },
	{ 0x82, "Faeroese (fo)" },
	{ 0x83, "Frisian (fy)" },
	{ 0x84, "Interlingua (ia)" },
	{ 0x8C, "Rhaeto-Romance (rm)" },
	{ 0x00, NULL }
};

static const value_string vals_accept_ranges[] = {
	{ 0x00, "None" },
	{ 0x01, "Bytes" },
	{ 0x00, NULL }
};

#define NO_CACHE		0x00
#define NO_STORE		0x01
#define MAX_AGE			0x02
#define MAX_STALE		0x03
#define MIN_FRESH		0x04
#define ONLY_IF_CACHED		0x05
#define PUBLIC			0x06
#define PRIVATE			0x07
#define NO_TRANSFORM		0x08
#define MUST_REVALIDATE		0x09
#define PROXY_REVALIDATE	0x0A
#define S_MAXAGE		0x0B

static const value_string vals_cache_control[] = {
	{ NO_CACHE,         "No-cache" },
	{ NO_STORE,         "No-store" },
	{ MAX_AGE,          "Max-age" },
	{ MAX_STALE,        "Max-stale" },
	{ MIN_FRESH,        "Min-fresh" },
	{ ONLY_IF_CACHED,   "Only-if-cached" },
	{ PUBLIC,           "Public" },
	{ PRIVATE,          "Private" },
	{ NO_TRANSFORM,     "No-transform" },
	{ MUST_REVALIDATE,  "Must-revalidate" },
	{ PROXY_REVALIDATE, "Proxy-revalidate" },
	{ S_MAXAGE,         "S-max-age" },
	{ 0x00,             NULL }
};

static const value_string vals_connection[] = {
	{ 0x00, "Close" },
	{ 0x00, NULL }
};

static const value_string vals_transfer_encoding[] = {
	{ 0x00, "Chunked" },
	{ 0x00, NULL }
};

/*
 * Redirect flags.
 */
#define PERMANENT_REDIRECT	0x80
#define REUSE_SECURITY_SESSION	0x40

/*
 * Redirect address flags and length.
 */
#define BEARER_TYPE_INCLUDED	0x80
#define PORT_NUMBER_INCLUDED	0x40
#define ADDRESS_LEN		0x3f

static const true_false_string yes_no_truth = { 
	"Yes" ,
	"No"
};

/*
 * Windows appears to define DELETE.
 */
#ifdef DELETE
#undef DELETE
#endif

enum {
	RESERVED		= 0x00,
	CONNECT			= 0x01,
	CONNECTREPLY		= 0x02,
	REDIRECT		= 0x03,			/* No sample data */
	REPLY			= 0x04,
	DISCONNECT		= 0x05,
	PUSH			= 0x06,			/* No sample data */
	CONFIRMEDPUSH		= 0x07,			/* No sample data */
	SUSPEND			= 0x08,			/* No sample data */
	RESUME			= 0x09,			/* No sample data */

	GET			= 0x40,
	OPTIONS			= 0x41,			/* No sample data */
	HEAD			= 0x42,			/* No sample data */
	DELETE			= 0x43,			/* No sample data */
	TRACE			= 0x44,			/* No sample data */

	POST			= 0x60,
	PUT			= 0x61,			/* No sample data */
};

typedef enum {
	VALUE_LEN_SUPPLIED,
	VALUE_IS_TEXT_STRING,
	VALUE_IN_LEN,
} value_type_t;

static dissector_table_t wsp_dissector_table;
static heur_dissector_list_t heur_subdissector_list;

static void add_uri (proto_tree *, packet_info *, tvbuff_t *, guint, guint);
static void add_headers (proto_tree *, tvbuff_t *);
static int add_well_known_header (proto_tree *, tvbuff_t *, int, guint8);
static int add_unknown_header (proto_tree *, tvbuff_t *, int, guint8);
static int add_application_header (proto_tree *, tvbuff_t *, int);
static void add_accept_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int);
static void add_accept_xxx_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int, int, int, const value_string *,
    const char *);
static void add_accept_ranges_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int);
static void add_cache_control_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int);
static int add_cache_control_field_name (proto_tree *, tvbuff_t *, int, guint);
static void add_connection_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int);
static void add_content_type_value (proto_tree *, tvbuff_t *, int, int,
    tvbuff_t *, value_type_t, int, int, int, guint *, const char **);
static void add_wap_application_id_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int);
static void add_integer_value_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int, int, guint8);
static void add_string_value_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int, int, guint8);
static void add_quoted_string_value_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int, int, guint8);
static void add_date_value_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int, int, guint8);
static int add_parameter (proto_tree *, tvbuff_t *, int);
static int add_untyped_parameter (proto_tree *, tvbuff_t *, int, int);
static int add_parameter_charset (proto_tree *, tvbuff_t *, int, int);
static int add_constrained_encoding (proto_tree *, tvbuff_t *, int, int);
static int add_parameter_type (proto_tree *, tvbuff_t *, int, int);
static int add_parameter_text (proto_tree *, tvbuff_t *, int, int, int, const char *);
static void add_post_data (proto_tree *, tvbuff_t *, guint, const char *);
static void add_post_variable (proto_tree *, tvbuff_t *, guint, guint, guint, guint);
static void add_pragma_header (proto_tree *, tvbuff_t *, int, tvbuff_t *,
    value_type_t, int);
static void add_transfer_encoding_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int);
static void add_warning_header (proto_tree *, tvbuff_t *, int, tvbuff_t *,
    value_type_t, int);
static void add_accept_application_header (proto_tree *, tvbuff_t *, int,
    tvbuff_t *, value_type_t, int);
static void add_capabilities (proto_tree *tree, tvbuff_t *tvb, int type);
static void add_capability_vals(tvbuff_t *, gboolean, int, guint, guint, char *, size_t);
static value_type_t get_value_type_len (tvbuff_t *, int, guint *, int *, int *);
static guint get_uintvar (tvbuff_t *, guint, guint);
static gint get_integer (tvbuff_t *, guint, guint, value_type_t, guint *);

/* Code to actually dissect the packets */
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

/* Set up structures we will need to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *wsp_tree = NULL;
/*	proto_tree *wsp_header_fixed; */
	
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

	switch (pdut)
	{
		case CONNECT:
		case CONNECTREPLY:
		case RESUME:
			if (tree) {
				if (pdut == CONNECT)
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

				if (pdut != RESUME)
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

		case REDIRECT:
			dissect_redirect(tvb, offset, pinfo, wsp_tree,
			  dissector_handle);
			break;

		case DISCONNECT:
		case SUSPEND:
			if (tree) {
				count = 0;	/* Initialise count */
				value = tvb_get_guintvar (tvb, offset, &count);
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_server_session_id,tvb,offset,count,value);
			}
			break;

		case GET:
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

		case POST:
			uriStart = offset;
			count = 0;	/* Initialise count */
			uriLength = tvb_get_guintvar (tvb, offset, &count);
			headerStart = uriStart+count;
			count = 0;	/* Initialise count */
			headersLength = tvb_get_guintvar (tvb, headerStart, &count);
			offset = headerStart + count;

			add_uri (wsp_tree, pinfo, tvb, uriStart, offset);
			if (tree) {
				offset += uriLength;

				ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,headerStart,count,headersLength);

				if (headersLength == 0)
					break;

				contentTypeStart = offset;
				nextOffset = add_content_type (wsp_tree,
				    tvb, offset, &contentType,
				    &contentTypeStr);

				/* Add headers subtree that will hold the headers fields */
				/* Runs from nextOffset for headersLength-(length of content-type field)*/
				headerLength = headersLength-(nextOffset-contentTypeStart);
				if (headerLength > 0)
				{
					tmp_tvb = tvb_new_subset (tvb, nextOffset, headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb);
				}

				/* TODO: Post DATA */
				/* Runs from start of headers+headerLength to end of frame */
				offset = nextOffset+headerLength;
				tmp_tvb = tvb_new_subset (tvb, offset, tvb_reported_length (tvb)-offset, tvb_reported_length (tvb)-offset);
				add_post_data (wsp_tree, tmp_tvb,
				    contentType, contentTypeStr);
			}
			if (tvb_reported_length_remaining(tvb, headerStart + count + uriLength + headersLength) > 0)
			{
				tmp_tvb = tvb_new_subset (tvb, headerStart + count + uriLength + headersLength, -1, -1);
				if (!dissector_try_port(wsp_dissector_table, contentType, tmp_tvb, pinfo, tree))
					dissector_try_heuristic(heur_subdissector_list, tmp_tvb, pinfo, tree);
			}
			break;

		case REPLY:
			count = 0;	/* Initialise count */
			headersLength = tvb_get_guintvar (tvb, offset+1, &count);
			headerStart = offset + count + 1;
			if (tree) {
				ti = proto_tree_add_item (wsp_tree, hf_wsp_header_status,tvb,offset,1,bo_little_endian);
				nextOffset = offset + 1 + count;
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,offset+1,count,headersLength);

				if (headersLength == 0)
					break;

				contentTypeStart = nextOffset;
				nextOffset = add_content_type (wsp_tree,
				    tvb, nextOffset, &contentType,
				    &contentTypeStr);

				/* Add headers subtree that will hold the headers fields */
				/* Runs from nextOffset for headersLength-(length of content-type field)*/
				headerLength = headersLength-(nextOffset-contentTypeStart);
				if (headerLength > 0)
				{
					tmp_tvb = tvb_new_subset (tvb, nextOffset, headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb);
				}
				offset += count+headersLength+1;

				/* TODO: Data - decode WMLC */
				/* Runs from offset+1+count+headerLength+1 to end of frame */
				if (tvb_reported_length_remaining (tvb, offset) > 0)
				{
					ti = proto_tree_add_item (wsp_tree, hf_wsp_reply_data,tvb,offset,-1,bo_little_endian);
				}
			}
			if (tvb_reported_length_remaining(tvb, headerStart + headersLength) > 0)
			{
				tmp_tvb = tvb_new_subset (tvb, headerStart + headersLength, -1, -1);
				if (!dissector_try_port(wsp_dissector_table, contentType, tmp_tvb, pinfo, tree))
					dissector_try_heuristic(heur_subdissector_list, tmp_tvb, pinfo, tree);
			}
			break;

		case PUSH:
		case CONFIRMEDPUSH:
			count = 0;	/* Initialise count */
			headersLength = tvb_get_guintvar (tvb, offset, &count);
			headerStart = offset + count;

			if (tree) {
				ti = proto_tree_add_uint (wsp_tree, hf_wsp_header_length,tvb,offset,count,headersLength);

				if (headersLength == 0)
					break;

				offset += count;
				contentTypeStart = offset;
				nextOffset = add_content_type (wsp_tree,
				    tvb, offset, &contentType,
				    &contentTypeStr);

				/* Add headers subtree that will hold the headers fields */
				/* Runs from nextOffset for headersLength-(length of content-type field)*/
				headerLength = headersLength-(nextOffset-contentTypeStart);
				if (headerLength > 0)
				{
					tmp_tvb = tvb_new_subset (tvb, nextOffset, headerLength, headerLength);
					add_headers (wsp_tree, tmp_tvb);
				}
				offset += headersLength;

				/* Push DATA */
				if (tvb_reported_length_remaining (tvb, offset) > 0)
				{
					ti = proto_tree_add_item (wsp_tree, hf_wsp_push_data,tvb,offset,-1,bo_little_endian);
				}
			}
			if (tvb_reported_length_remaining(tvb, headerStart + headersLength) > 0)
			{
				tmp_tvb = tvb_new_subset (tvb, headerStart + headersLength, -1, -1);
				if (!dissector_try_port(wsp_dissector_table, contentType, tmp_tvb, pinfo, tree))
					dissector_try_heuristic(heur_subdissector_list, tmp_tvb, pinfo, tree);
			}
			break;

	}
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
	char *newBuffer;

	guint count = 0;
	guint uriLen = tvb_get_guintvar (tvb, URILenOffset, &count);

	if (tree)
		ti = proto_tree_add_uint (tree, hf_wsp_header_uri_len,tvb,URILenOffset,count,uriLen);

	newBuffer = g_malloc (uriLen+2);
	newBuffer[0] = ' ';  /* This is for COL_INFO */
	strncpy (newBuffer+1, tvb_get_ptr (tvb, URIOffset, uriLen), uriLen);
	newBuffer[uriLen+1] = 0;
	if (tree)
		ti = proto_tree_add_string (tree, hf_wsp_header_uri,tvb,URIOffset,uriLen,newBuffer+1);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_str(pinfo->cinfo, COL_INFO, newBuffer);
	};
	g_free (newBuffer);
}

static void
add_headers (proto_tree *tree, tvbuff_t *tvb)
{
	proto_item *ti;
	proto_tree *wsp_headers;
	guint offset = 0;
	guint headersLen = tvb_reported_length (tvb);
	guint headerStart = 0;
	guint peek = 0;
	guint pageCode = 1;

#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: Offset is %d, size is %d\n", offset, headersLen);
#endif

	/* End of buffer */
	if (headersLen <= 0)
	{
		return;
	}

#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: Headers to process\n");
#endif

	ti = proto_tree_add_item (tree, hf_wsp_headers_section,tvb,offset,headersLen,bo_little_endian);
	wsp_headers = proto_item_add_subtree( ti, ett_headers );

	/* Parse Headers */

	while (offset < headersLen)
	{
		/* Loop round each header */
		headerStart = offset;
		peek = tvb_get_guint8 (tvb, headerStart);

		if (peek < 32)		/* Short-cut shift delimiter */
		{
			pageCode = peek;
			proto_tree_add_uint (wsp_headers,
			    hf_wsp_header_shift_code, tvb, offset, 1,
			    pageCode);
			offset += 1;
			continue;
		}
		else if (peek == 0x7F)	/* Shift delimiter */
		{
			pageCode = tvb_get_guint8(tvb, offset+1);
			proto_tree_add_uint (wsp_headers,
			    hf_wsp_header_shift_code, tvb, offset, 2,
			    pageCode);
			offset += 2;
			continue;
		}
		else if (peek < 127)
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: header: application-header start %d (0x%02X)\n", peek, peek);
#endif
			/*
			 * Token-text, followed by Application-specific-value.
			 */
			offset = add_application_header (wsp_headers, tvb,
			    headerStart);
		}
		else if (peek & 0x80)
		{
#ifdef DEBUG
			fprintf (stderr, "dissect_wsp: header: well-known %d (0x%02X)\n", peek, peek);
#endif
			/*
			 * Well-known-header; the lower 7 bits of "peek"
			 * are the header code.
			 */
			if (pageCode == 1)
			{
				offset = add_well_known_header (wsp_headers,
				    tvb, headerStart, peek & 0x7F);
			}
			else 
			{
				offset = add_unknown_header (wsp_headers,
				    tvb, headerStart, peek & 0x7F);
			}
		}
	}
}

static int
add_well_known_header (proto_tree *tree, tvbuff_t *tvb, int offset,
    guint8 headerType)
{
	int headerStart;
	value_type_t valueType;
	int headerLen;
	guint valueLen;
	int valueStart;
	tvbuff_t *header_buff;
	tvbuff_t *value_buff;

#ifdef DEBUG
	fprintf (stderr, "dissect_wsp: Got header 0x%02x\n", headerType);
#endif
	headerStart = offset;

	/*
	 * Skip the Short-Integer header type.
	 */
	offset++;

	/*
	 * Get the value type and length (or, if the type is VALUE_IN_LEN,
	 * meaning the value is a Short-integer, get the value type
	 * and the value itself).
	 */ 
	valueType = get_value_type_len (tvb, offset, &valueLen,
	    &valueStart, &offset);
	headerLen = offset - headerStart;

	/*
	 * Get a tvbuff for the entire header.
	 * XXX - cut the actual length short so that it doesn't run
	 * past the actual length of tvb.
	 */
	header_buff = tvb_new_subset (tvb, headerStart, headerLen,
	    headerLen);

	/*
	 * If the value wasn't in the length, get a tvbuff for the value.
	 * XXX - can valueLen be 0?
	 * XXX - cut the actual length short so that it doesn't run
	 * past the actual length of tvb.
	 */
	if (valueType != VALUE_IN_LEN) {
		value_buff = tvb_new_subset (tvb, valueStart, valueLen,
		    valueLen);
	} else {
		/*
		 * XXX - when the last dissector is tvbuffified,
		 * so that NULL is no longer a valid tvb pointer
		 * value in "proto_tree_add" calls, just
		 * set "value_buff" to NULL.
		 *
		 * XXX - can we already do that?  I.e., will that
		 * cause us always to crash if we mistakenly try
		 * to fetch the value of a VALUE_IN_LEN item?
		 */
		value_buff = tvb_new_subset (tvb, headerStart, 0, 0);
	}

	switch (headerType) {

	case FN_ACCEPT:			/* Accept */
		add_accept_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen);
		break;

	case FN_ACCEPT_CHARSET_DEP:	/* Accept-Charset */
		/*
		 * XXX - should both encoding versions 1.1 and
		 * 1.3 be handled this way?
		 */
		add_accept_xxx_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_accept_charset,
		    hf_wsp_header_accept_charset_str,
		    vals_character_sets, "Unknown charset (%u)");
		break;

	case FN_ACCEPT_LANGUAGE:	/* Accept-Language */
		add_accept_xxx_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_accept_language,
		    hf_wsp_header_accept_language_str,
		    vals_languages, "Unknown language (%u)");
		break;

	case FN_ACCEPT_RANGES:		/* Accept-Ranges */
		add_accept_ranges_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen);
		break;

	case FN_AGE:			/* Age */
		add_integer_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen, hf_wsp_header_age,
		    headerType);
		break;

	case FN_CACHE_CONTROL_DEP:	/* Cache-Control */
	case FN_CACHE_CONTROL:
	case FN_CACHE_CONTROL14:
		/*
		 * XXX - is the only difference in the three different
		 * versions (1.1, 1.3, 1.4) really only S_MAXAGE?
		 */
		add_cache_control_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen);
		break;
				
	case FN_CONNECTION:	/* Connection */
		add_connection_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen);
		break;

	case FN_CONTENT_LENGTH:		/* Content-Length */
		add_integer_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_content_length,
		    headerType);
		break;
				
	case FN_DATE:			/* Date */
		add_date_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_date, headerType);
		break;

	case FN_ETAG:			/* Etag */
		add_string_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_etag, headerType);
		break;

	case FN_EXPIRES:		/* Expires */
		add_date_value_header (tree, header_buff, headerLen,
		    value_buff,	valueType, valueLen,
		    hf_wsp_header_expires, headerType);
		break;

	case FN_IF_MODIFIED_SINCE:	/* If-Modified-Since */
		add_date_value_header (tree, header_buff, headerLen,
		    value_buff,	valueType, valueLen,
		    hf_wsp_header_if_modified_since, headerType);
		break;
				
	case FN_LOCATION:		/* Location */
		add_string_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_location, headerType);
		break;

	case FN_LAST_MODIFIED:		/* Last-Modified */
		add_date_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_last_modified, headerType);
		break;
				
	case FN_PRAGMA:			/* Pragma */
		add_pragma_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen);
		break;
				
	case FN_SERVER:			/* Server */
		add_string_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_server, headerType);
		break;

	case FN_TRANSFER_ENCODING:	/* Transfer-Encoding */
		add_transfer_encoding_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen);
		break;

	case FN_USER_AGENT:		/* User-Agent */
		add_string_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_user_agent, headerType);
		break;

	case FN_VIA:			/* Via */
		add_string_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_via, headerType);
		break;

	case FN_WARNING:		/* Warning */
		add_warning_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen);
		break;

	case FN_ACCEPT_APPLICATION:	/* Accept-Application */
		add_accept_application_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen);
		break;

	case FN_BEARER_INDICATION:	/* Bearer-Indication */
		add_integer_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_bearer_indication, headerType);
		break;

	case FN_PROFILE:		/* Profile */
		add_string_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_profile, headerType);
		break;

	case FN_X_WAP_APPLICATION_ID:	/* X-Wap-Application-Id */
		add_wap_application_id_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen);
		break;

	case FN_CONTENT_ID:		/* Content-ID	*/
		add_quoted_string_value_header (tree, header_buff, headerLen,
		    value_buff, valueType, valueLen,
		    hf_wsp_header_content_ID, headerType);
		break;

	default:
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Unsupported Header: %s",
		    val_to_str (headerType, vals_field_names, "Unknown (0x%02X)"));
		break;
	}
	return offset;
}

static int
add_unknown_header (proto_tree *tree, tvbuff_t *tvb, int offset,
    guint8 headerType)
{
	int headerStart;
	int valueStart;
	value_type_t valueType;
	int headerLen;
	guint valueLen;
	int valueOffset;

	headerStart = offset;

	/*
	 * Skip the Short-Integer header type.
	 */
	offset++;

	valueStart = offset;

	/*
	 * Get the value type and length (or, if the type is VALUE_IN_LEN,
	 * meaning the value is a Short-integer, get the value type
	 * and the value itself).
	 */ 
	valueType = get_value_type_len (tvb, valueStart, &valueLen,
	    &valueOffset, &offset);
	headerLen = offset - headerStart;

	proto_tree_add_text (tree, tvb, headerStart, headerLen,
		       "Unsupported Header (0x%02X)", headerType);
	return offset;
}

static int
add_application_header (proto_tree *tree, tvbuff_t *tvb, int offset)
{
	int startOffset;
	guint tokenSize;
	const guint8 *token;
	value_type_t valueType;
	int subvalueLen;
	int subvalueOffset;
	guint secs;
	nstime_t timeValue;
	int asvOffset;
	guint stringSize;

	startOffset = offset;
	tokenSize = tvb_strsize (tvb, startOffset);
	token = tvb_get_ptr (tvb, startOffset, tokenSize);
	offset += tokenSize;

	/*
	 * Special case header "X-WAP.TOD" that is sometimes followed
	 * by a 4-byte date value.
	 *
	 * XXX - according to the 4-May-2000 WSP spec, X-Wap-Tod is
	 * encoded as a well known header, with a code of 0x3F.
	 */
	if (tokenSize == 10 && strncasecmp ("x-wap.tod", token, 9) == 0)
	{
		valueType = get_value_type_len (tvb, offset,
		    &subvalueLen, &subvalueOffset, &offset);
		if (get_integer (tvb, subvalueOffset, subvalueLen,
		    valueType, &secs) == 0)
		{
			/*
			 * Fill in the "struct timeval", and add it to the
			 * protocol tree.
			 * Note: this will succeed even if it's a Short-integer.
			 * A Short-integer would work, but, as the time values
			 * are UNIX seconds-since-the-Epoch value, and as
			 * there weren't WAP phones or Web servers back in
			 * late 1969/early 1970, they're unlikely to be used.
			 */
			timeValue.secs = secs;
			timeValue.nsecs = 0;
			proto_tree_add_time (tree, hf_wsp_header_x_wap_tod,
			    tvb, startOffset, offset - startOffset, &timeValue);
		}
		else
		{
			proto_tree_add_text (tree, tvb, startOffset,
			    offset - startOffset,
			    "%s: invalid date value", token);
		}
	}
	else
	{
		asvOffset = offset;
		stringSize = tvb_strsize (tvb, asvOffset);
		offset += stringSize;
		proto_tree_add_text (tree, tvb, startOffset,
		    offset - startOffset,
		    "%s: %s", token,
		    tvb_get_ptr (tvb, asvOffset, stringSize));
	}
	return offset;
}

static void
add_accept_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen)
{
	guint contentType;
	const char *contentTypeStr;

	add_content_type_value (tree, header_buff, 0, headerLen, value_buff,
	    valueType, valueLen, hf_wsp_header_accept,
	    hf_wsp_header_accept_str, &contentType, &contentTypeStr);
}

static void
add_accept_xxx_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen, int hf_numeric, int hf_string,
    const value_string *vals, const char *unknown_tag)
{
	int offset = 0;
	int subvalueLen;
	int subvalueOffset;
	guint value = 0;
	char valString[100];
	const char *valMatch;
	guint peek;
	double q_value = 1.0;

	if (valueType == VALUE_IN_LEN)
	{
		/*
		 * Constrained-{charset,language} (Short-Integer).
		 */
		proto_tree_add_uint (tree, hf_numeric,
		    header_buff, 0, headerLen,
		    valueLen);	/* valueLen is the value */
		return;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Constrained-{charset,language} (text, i.e.
		 * Extension-Media).
		 */
		proto_tree_add_string (tree, hf_string,
		    header_buff, 0, headerLen,
		    tvb_get_ptr (value_buff, 0, valueLen));
		return;
	}

	/*
	 * First byte had the 8th bit set.
	 */
	if (valueLen == 0) {
		/*
		 * Any-{charset,language}.
		 */
		proto_tree_add_string (tree, hf_string,
			header_buff, 0, headerLen,
			"*");
		return;
	}

	/*
	 * Accept-{charset,language}-general-form; Value-length, followed
	 * by Well-known-{charset,language} or {Token-text,Text-string},
	 * possibly followed by a Q-value.
	 * 
	 * Get Value-length.
	 */
	valueType = get_value_type_len (value_buff, 0, &subvalueLen,
	    &subvalueOffset, &offset);
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * {Token-text,Text-string}.
		 */
		valMatch =
		    tvb_get_ptr (value_buff, subvalueOffset, subvalueLen);
		proto_tree_add_string (tree, hf_string,
			value_buff, 0, valueLen, valMatch);
	} else {
		/*
		 * Well-known-{charset,langugage}; starts with an
		 * Integer-value.
		 */
		if (get_integer (value_buff, subvalueOffset, subvalueLen,
		    valueType, &value) < 0)
		{
			valMatch = "Invalid integer";
		}
		else
		{
			valMatch = val_to_str(value, vals, unknown_tag);
		}
	}

	/* Any remaining data relates to Q-value */
	if (offset < valueLen)
	{
		peek = tvb_get_guintvar (value_buff, offset, NULL);
		if (peek <= 100) {
			peek = (peek - 1) * 10;
		}
		else {
			peek -= 100;
		}
		q_value = peek/1000.0;
	}

	/* Build string including Q-value if present */
	if (q_value == 1.0)			/* Default */
	{
		snprintf (valString, 100, "%s", valMatch);
	}
	else
	{
		snprintf (valString, 100, "%s; Q=%5.3f", valMatch, q_value);
	}
	/* Add string to tree */
	proto_tree_add_string (tree, hf_string,
	    header_buff, 0, headerLen, valString);
}

static void
add_accept_ranges_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen)
{
	if (valueType == VALUE_IN_LEN)
	{
		/*
		 * Must be 0 (None) or 1 (Bytes) (the 8th bit was stripped
		 * off).
		 */
		proto_tree_add_uint (tree, hf_wsp_header_accept_ranges,
		    header_buff, 0, headerLen,
		    valueLen);	/* valueLen is the value */
		return;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Token-text.
		 */
		proto_tree_add_string (tree, hf_wsp_header_accept_ranges_str,
		    header_buff, 0, headerLen,
		    tvb_get_ptr (value_buff, 0, valueLen));
		return;
	}

	/*
	 * Not valid.
	 */
	fprintf(stderr, "dissect_wsp: Accept-Ranges is neither None, Bytes, nor Token-text\n");
	return;
}

static void
add_cache_control_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen)
{
	int offset = 0;
	int subvalueLen;
	int subvalueOffset;
	guint value;
	proto_item *ti;
	proto_tree *parameter_tree;
	proto_tree *field_names_tree;
	guint delta_secs;

	if (valueType == VALUE_IN_LEN)
	{
		/*
		 * No-cache, No-store, Max-age, Max-stale, Min-fresh,
		 * Only-if-cached, Public, Private, No-transform,
		 * Must-revalidate, Proxy-revalidate, or S-maxage.
		 */
		proto_tree_add_uint (tree, hf_wsp_header_cache_control,
		    header_buff, 0, headerLen,
		    valueLen);	/* valueLen is the value */
		return;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Cache-extension.
		 */
		proto_tree_add_string (tree, hf_wsp_header_cache_control_str,
		    header_buff, 0, headerLen,
		    tvb_get_ptr (value_buff, 0, valueLen));
		return;
	}

	/*
	 * Value-length Cache-directive.
	 * Get first field of Cache-directive.
	 */
	valueType = get_value_type_len (value_buff, offset, &subvalueLen,
	    &subvalueOffset, &offset);
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Cache-extension Parameter.
		 */
		ti = proto_tree_add_string (tree, hf_wsp_header_cache_control_str,
		    header_buff, 0, headerLen,
		    tvb_get_ptr (value_buff, 0, valueLen));
		parameter_tree = proto_item_add_subtree (ti,
		    ett_header_cache_control_parameters);

		/*
		 * Process the rest of the value as parameters.
		 */
		while (tvb_reported_length_remaining (value_buff, offset) > 0) {
			offset = add_parameter (parameter_tree, value_buff,
			    offset);
		}
		return;
	}
	if (get_integer (value_buff, subvalueOffset, subvalueLen, valueType,
	    &value) < 0)
	{
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Invalid Cache-Control Cache-directive value");
	}
	else
	{
		switch (value) {

		case NO_CACHE:
		case PRIVATE:
			/*
			 * Loop, processing Field-names.
			 */
			ti = proto_tree_add_uint (tree,
			    hf_wsp_header_cache_control,
			    header_buff, 0, headerLen,
			    value);
			field_names_tree = proto_item_add_subtree (ti,
			    ett_header_cache_control_field_names);
			while (tvb_reported_length_remaining (value_buff, offset)
			    > 0) {
				offset = add_cache_control_field_name (tree,
			    	    value_buff, offset, value);
			}
			break;

		case MAX_AGE:
		case MAX_STALE:
		case MIN_FRESH:
		case S_MAXAGE:
			/*
			 * Get Delta-second-value.
			 */
			valueType = get_value_type_len (value_buff, offset,
			    &subvalueLen, &subvalueOffset, &offset);
			if (get_integer (value_buff, subvalueOffset,
			    subvalueLen, valueType, &delta_secs) < 0)
			{
				proto_tree_add_text (tree,
				    header_buff, 0, headerLen,
				    "Invalid Cache-Control %s Delta-second-value",
				    match_strval (value, vals_cache_control));
			}
			else 
			{
				proto_tree_add_uint_format (tree,
				    hf_wsp_header_cache_control,
				    header_buff, 0, headerLen,
				    value,
				    "Cache-Control: %s %u secs",
				    match_strval (value, vals_cache_control),
				    delta_secs);
			}
			break;

		default:
			/*
			 * This should not happen, but handle it anyway.
			 */
			proto_tree_add_uint (tree,
			    hf_wsp_header_cache_control,
			    header_buff, 0, headerLen,
			    value);
			break;
		}
	}
}

static int
add_cache_control_field_name (proto_tree *tree, tvbuff_t *value_buff,
    int offset, guint cache_control_value)
{
	value_type_t valueType;
	int startOffset;
	int subvalueLen;
	int subvalueOffset;

	startOffset = offset;
	valueType = get_value_type_len (value_buff, offset,
	    &subvalueLen, &subvalueOffset, &offset);
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Token-text.
		 */
		proto_tree_add_item (tree, 
		    hf_wsp_header_cache_control_field_name_str,
		    value_buff, startOffset, offset - startOffset,
		    bo_little_endian);
	}
	else if (valueType == VALUE_IN_LEN)
	{
		/*
		 * Short-integer Field-name.
		 */
		proto_tree_add_uint (tree,
		    hf_wsp_header_cache_control_field_name,
		    value_buff, startOffset, offset - startOffset,
		    subvalueLen);
	}
	else
	{
		/*
		 * Long-integer - illegal.
		 */
		proto_tree_add_text (tree,
		    value_buff, startOffset, offset - startOffset,
		    "Invalid Cache-Control %s Field-name",
		    match_strval (cache_control_value, vals_cache_control));
	}	
	return offset;
}

static void
add_connection_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen)
{
	int offset = 0;

	if (valueType == VALUE_LEN_SUPPLIED)
	{
		/*
		 * Invalid.
		 */
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Invalid Connection value");
		return;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Token-text.
		 */
		proto_tree_add_string (tree,
		    hf_wsp_header_connection_str,
		    header_buff, 0, headerLen,
		    tvb_get_ptr (value_buff, 0, valueLen));
		return;
	}

	/*
	 * First byte had the 8th bit set.
	 */
	if (valueLen == 0) {
		/*
		 * Close.
		 */
		proto_tree_add_uint (tree, hf_wsp_header_connection,
		    header_buff, offset, headerLen, valueLen);
		return;
	}

	/*
	 * Invalid.
	 */
	proto_tree_add_text (tree, header_buff, 0, headerLen,
	    "Invalid Connection value");
}

static void
add_pragma_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen)
{
	int offset = 0;
	int subvalueLen;
	int subvalueOffset;

	if (valueType == VALUE_IN_LEN)
	{
		/*
		 * Invalid.
		 */
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Invalid Pragma");
		return;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Invalid?
		 */
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Invalid Pragma");
		return;
	}

	/*
	 * First byte had the 8th bit set.
	 */
	if (valueLen == 0) {
		/*
		 * No-cache.
		 */
		proto_tree_add_string (tree, hf_wsp_header_pragma,
		    header_buff, 0, headerLen, "No-cache");
		return;
	}

	/*
	 * Value-length, followed by Parameter.
	 * 
	 * Get Value-length.
	 */
	valueType = get_value_type_len (value_buff, 0, &subvalueLen,
	    &subvalueOffset, &offset);
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Parameter - a text string.
		 */
		proto_tree_add_string (tree, hf_wsp_header_pragma,
		    header_buff, 0, headerLen,
		    tvb_get_ptr (value_buff, subvalueOffset, subvalueLen));
	} else {
		/*
		 * Parameter - numeric; illegal?
		 */
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Invalid Pragma");
	}
}

static void
add_transfer_encoding_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen)
{
	int offset = 0;

	if (valueType == VALUE_LEN_SUPPLIED)
	{
		/*
		 * Invalid.
		 */
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Invalid Transfer-Encoding value");
		return;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Token-text.
		 */
		proto_tree_add_string (tree,
		    hf_wsp_header_transfer_encoding_str,
		    header_buff, 0, headerLen,
		    tvb_get_ptr (value_buff, 0, valueLen));
		return;
	}

	/*
	 * First byte had the 8th bit set.
	 */
	if (valueLen == 0) {
		/*
		 * Chunked.
		 */
		proto_tree_add_uint (tree, hf_wsp_header_transfer_encoding,
		    header_buff, offset, headerLen, valueLen);
		return;
	}

	/*
	 * Invalid.
	 */
	proto_tree_add_text (tree, header_buff, 0, headerLen,
	    "Invalid Transfer Encoding value");
}

static void
add_warning_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen)
{
	int offset = 0;
	proto_item *ti;
	proto_tree *warning_tree;
	int subvalueLen;
	int subvalueOffset;

	/*
	 * Put the items under a header.
	 * XXX - make the text of the item summarize the elements.
	 */
	ti = proto_tree_add_item (tree, hf_wsp_header_warning,
	    header_buff, 0, headerLen, bo_little_endian);
	warning_tree = proto_item_add_subtree(ti, ett_header_warning);
	
	if (valueType == VALUE_IN_LEN)
	{
		/*
		 * Warn-code (Short-integer).
		 */
		proto_tree_add_uint (warning_tree, hf_wsp_header_warning_code,
		    header_buff, 0, headerLen,
		    valueLen);	/* valueLen is the value */
		return;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Invalid.
		 */
		proto_tree_add_text (warning_tree, header_buff, 0, headerLen,
		    "Invalid Warning (all text)");
		return;
	}

	/*
	 * Warning-value; Warn-code, followed by Warn-agent, followed by
	 * Warn-text.
	 */
	/*
	 * Get Short-integer Warn-code.
	 */
	valueType = get_value_type_len (value_buff, offset, &subvalueLen,
	    &subvalueOffset, &offset);
	if (valueType != VALUE_IN_LEN)
	{
		/*
		 * Not a Short-integer.
		 */
		proto_tree_add_text (warning_tree, value_buff, subvalueOffset,
		    subvalueLen, "Invalid Warn-code (not a Short-integer)");
		return;
	}
	proto_tree_add_uint (warning_tree, hf_wsp_header_warning_code,
	    value_buff, subvalueOffset, 1,
	    subvalueLen);	/* subvalueLen is the value */

	/*
	 * Warn-agent; must be text.
	 */
	valueType = get_value_type_len (value_buff, offset, &subvalueLen,
	    &subvalueOffset, &offset);
	if (valueType != VALUE_IS_TEXT_STRING)
	{
		/*
		 * Not text.
		 */
		proto_tree_add_text (warning_tree, value_buff, subvalueOffset,
		    subvalueLen, "Invalid Warn-agent (not a text string)");
		return;
	}
	proto_tree_add_item (warning_tree,
		hf_wsp_header_warning_agent,
		value_buff, subvalueOffset, subvalueLen, bo_little_endian);

	/*
	 * Warn-text; must be text.
	 */
	valueType = get_value_type_len (value_buff, offset, &subvalueLen,
	    &subvalueOffset, &offset);
	if (valueType != VALUE_IS_TEXT_STRING)
	{
		/*
		 * Not text.
		 */
		proto_tree_add_text (warning_tree, value_buff, subvalueOffset,
		    subvalueLen, "Invalid Warn-text (not a text string)");
		return;
	}
	proto_tree_add_item (warning_tree,
		hf_wsp_header_warning_text,
		value_buff, subvalueOffset, subvalueLen, bo_little_endian);
}

static void
add_accept_application_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen)
{
	guint value;

	if (valueType == VALUE_IN_LEN)
	{
		/*
		 * Application-id-value; numeric, so it's App-assigned-code.
		 */
		proto_tree_add_uint (tree, hf_wsp_header_accept_application,
		    header_buff, 0, headerLen,
		    valueLen);	/* valueLen is the value */
		return;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Uri-value.
		 */
		proto_tree_add_string (tree, hf_wsp_header_accept_application_str,
		    header_buff, 0, headerLen,
		    tvb_get_ptr (value_buff, 0, valueLen));
		return;
	}

	/*
	 * First byte had the 8th bit set.
	 */
	if (valueLen == 0) {
		/*
		 * Any-application.
		 */
		proto_tree_add_string (tree, hf_wsp_header_accept_application_str,
			header_buff, 0, headerLen,
			"*");
		return;
	}

	/*
	 * Integer-value, hence App-assigned-code.
	 */
	if (get_integer (value_buff, 0, valueLen, valueType, &value) < 0)
	{
		proto_tree_add_text (tree, header_buff, 0, headerLen,
			"Invalid Accept-Application App-assigned-code");
	}
	else
	{
		proto_tree_add_uint (tree, hf_wsp_header_accept_application,
		    header_buff, 0, headerLen, value);
	}
}

static void
add_wap_application_id_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen)
{
	if (valueType == VALUE_IN_LEN)
	{
		/*
		 * Must application-id (the 8th bit was stripped off).
		 */
		proto_tree_add_uint (tree, hf_wsp_header_wap_application_id,
		    header_buff, 0, headerLen,
		    valueLen);	/* valueLen is the value */
		return;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Token-text.
		 */
		proto_tree_add_string (tree, hf_wsp_header_wap_application_id_str,
		    header_buff, 0, headerLen,
		    tvb_get_ptr (value_buff, 0, valueLen));
		return;
	}

	/*
	 * Not valid.
	 */
	fprintf(stderr, "dissect_wsp: Suprising format of X-Wap-Application-Id\n");
	return;
}

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
	char valString[200];

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
					ret = snprintf(valString+i,200-i,"%s","(Confirmed push facility) ");
					if (ret == -1) {
						/*
						 * Some versions of snprintf
						 * return -1 if they'd
						 * truncate the output.
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
					ret = snprintf(valString+i,200-i,"%s","(Push facility) ");
					if (ret == -1) {
						/*
						 * Some versions of snprintf
						 * return -1 if they'd
						 * truncate the output.
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
					ret = snprintf(valString+i,200-i,"%s","(Session resume facility) ");
					if (ret == -1) {
						/*
						 * Some versions of snprintf
						 * return -1 if they'd
						 * truncate the output.
						 */
						goto add_string;
					}
					i += ret;
				}
				if (value & 0x10)
				{
					if (i >= 200) {
						/* No more room. */
						goto add_string;
					}
					ret = snprintf(valString+i,200-i,"%s","(Acknowledgement headers) ");
					if (ret == -1) {
						/*
						 * Some versions of snprintf
						 * return -1 if they'd
						 * truncate the output.
						 */
						goto add_string;
					}
					i += ret;
				}
			add_string:
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
				add_capability_vals(tvb, (type == CONNECT),
				    offsetStr, length, capabilitiesStart,
				    valString, sizeof valString);
				proto_tree_add_string(wsp_capabilities, hf_wsp_capabilities_extended_methods, tvb, capabilitiesStart, length+1, valString);
				break;
			case 0x06 : /* Header Code Pages */ 
				offsetStr = offset;
				offset++;
				add_capability_vals(tvb, (type == CONNECT),
				    offsetStr, length, capabilitiesStart,
				    valString, sizeof valString);
				proto_tree_add_string(wsp_capabilities, hf_wsp_capabilities_header_code_pages, tvb, capabilitiesStart, length+1, valString);
				break;
			case 0x07 : /* Aliases */
				break;
			default:
				proto_tree_add_text (wsp_capabilities, tvb , capabilitiesStart, length+1,
				       "Unsupported Header (0x%02X)", peek & 0x7F);
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
			    "(%d - ",value);
		}
		else
		{
			ret = snprintf(valString+i,valStringSize-i,"(%d) ",
			    value);
		}
		if (ret == -1) {
			/*
			 * Some versions of snprintf return -1
			 * if they'd truncate the output.
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

static void
add_content_type_value (proto_tree *tree, tvbuff_t *header_buff,
    int headerOffset, int headerLen, tvbuff_t *value_buff,
    value_type_t valueType, int valueLen, int hf_numeric, int hf_string,
    guint *contentTypep, const char **contentTypeStrp)
{
	proto_item *ti;
	proto_tree *parameter_tree;
	const char *contentTypeStr;
	int offset;
	int subvalueLen;
	int subvalueOffset;
	guint value;

	if (valueType == VALUE_IN_LEN)
	{
		/*
		 * Constrained-media (Short-Integer).
		 */
		proto_tree_add_uint (tree, hf_numeric,
		    header_buff, headerOffset, headerLen,
		    valueLen);	/* valueLen is the value */

		/*
		 * Return the numerical value, and a null string value
		 * indicating that the value is numerical.
		 */
		*contentTypep = valueLen;
		*contentTypeStrp = NULL;
		return;
	}
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Constrained-media (text, i.e. Extension-Media).
		 */
		contentTypeStr = tvb_get_ptr (value_buff, 0, valueLen);
		proto_tree_add_string (tree, hf_string,
		    header_buff, headerOffset, headerLen,
		    contentTypeStr);

		/*
		 * Return the string value, and set the numerical value
		 * to 0 (as it shouldn't be used).
		 */
		*contentTypep = 0;
		*contentTypeStrp = contentTypeStr;
		return;
	}

	/*
	 * Content-general-form; Value-length, followed by Media-range,
	 * followed by optional Accept-parameters.
	 *
	 * Get Value-length.
	 */
	valueType = get_value_type_len (value_buff, 0, &subvalueLen,
	    &subvalueOffset, &offset);
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Extension-Media; value is a string.
		 */
		contentTypeStr =
		    tvb_get_ptr (value_buff, subvalueOffset, subvalueLen);
		ti = proto_tree_add_string (tree, hf_string, header_buff,
		    headerOffset, headerLen, contentTypeStr);

		/*
		 * Return the string value, and set the numerical value
		 * to 0 (as it shouldn't be used).
		 */
		*contentTypep = 0;
		*contentTypeStrp = contentTypeStr;
	}
	else
	{
		/*
		 * Well-known-media; value is an Integer.
		 */
		if (get_integer (value_buff, subvalueOffset, subvalueLen,
		    valueType, &value) < 0)
		{
			proto_tree_add_text (tree, header_buff,
			    headerOffset, headerLen,
			    "Invalid integer for Well-known-media");

			/*
			 * Content type is invalid.
			 * Don't try to parse the rest of the value.
			 */
			*contentTypep = 0;
			*contentTypeStrp = NULL;
			return;
		}
		ti = proto_tree_add_uint (tree, hf_numeric,
		    header_buff, headerOffset, headerLen, value);

		/*
		 * Return the numerical value, and a null string value
		 * indicating that the value is numerical.
		 */
		*contentTypep = value;
		*contentTypeStrp = NULL;
	}

	/*
	 * Process the rest of the value as parameters.
	 */
	parameter_tree = proto_item_add_subtree(ti,
	    ett_content_type_parameters);
	while (tvb_reported_length_remaining (value_buff, offset) > 0)
		offset = add_parameter (parameter_tree, value_buff, offset);
}

guint
add_content_type (proto_tree *tree, tvbuff_t *tvb, guint offset,
    guint *contentTypep, const char **contentTypeStrp)
{
	int valueStart;
	value_type_t valueType;
	int valueTypeLen;
	guint valueLen;
	int valueOffset;
	tvbuff_t *value_buff;

	valueStart = offset;

	/*
	 * Get the value type and length (or, if the type is VALUE_IN_LEN,
	 * meaning the value is a Short-integer, get the value type
	 * and the value itself).
	 */ 
	valueType = get_value_type_len (tvb, valueStart, &valueLen,
	    &valueOffset, &offset);
	valueTypeLen = offset - valueStart;

	/*
	 * Get a tvbuff for the value.
	 * XXX - can valueLen be 0?
	 * XXX - cut the actual length short so that it doesn't run
	 * past the actual length of tvb.
	 */
	if (valueType != VALUE_IN_LEN) {
		value_buff = tvb_new_subset (tvb, valueOffset, valueLen,
		    valueLen);
	} else {
		/*
		 * XXX - when the last dissector is tvbuffified,
		 * so that NULL is no longer a valid tvb pointer
		 * value in "proto_tree_add" calls, just
		 * set "value_buff" to NULL.
		 *
		 * XXX - can we already do that?  I.e., will that
		 * cause us always to crash if we mistakenly try
		 * to fetch the value of a VALUE_IN_LEN item?
		 */
		value_buff = tvb_new_subset (tvb, valueStart, 0, 0);
	}

	add_content_type_value (tree, tvb, valueStart, valueTypeLen, value_buff,
	    valueType, valueLen, hf_wsp_content_type,
	    hf_wsp_content_type_str, contentTypep, contentTypeStrp);

	return offset;
}

static void
add_integer_value_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen, int hf_numeric, guint8 headerType)
{
	guint value;

	if (get_integer (value_buff, 0, valueLen, valueType, &value) < 0)
	{
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Invalid %s integer value",
		    match_strval (headerType, vals_field_names));
	}
	else
	{
		proto_tree_add_uint (tree, hf_numeric,
		    header_buff, 0, headerLen, value);
	}
}

static void
add_string_value_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen, int hf_string, guint8 headerType)
{
	if (valueType != VALUE_IS_TEXT_STRING)
	{
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Invalid %s string value",
		    match_strval (headerType, vals_field_names));
	}
	else
	{
		proto_tree_add_string (tree, hf_string, header_buff,
			0, headerLen, tvb_get_ptr (value_buff, 0, valueLen));
	}
}

static void
add_quoted_string_value_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen, int hf_string, guint8 headerType)
{
	if (valueType != VALUE_IS_TEXT_STRING)
	{
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Invalid %s quoted string value",
		    match_strval (headerType, vals_field_names));
	}
	else
	{
		proto_tree_add_string (tree, hf_string, header_buff,
			0, headerLen, tvb_get_ptr (value_buff, 1, valueLen - 1));
	}
}

/* Utility function to add a date value to the protocol tree */
static void
add_date_value_header (proto_tree *tree, tvbuff_t *header_buff,
    int headerLen, tvbuff_t *value_buff, value_type_t valueType,
    int valueLen, int hf_time, guint8 headerType)
{
	guint secs;
	nstime_t timeValue;

	/* Attempt to get the date value from the buffer */
	if (get_integer (value_buff, 0, valueLen, valueType, &secs) == 0)
	{
		/*
		 * Fill in the "struct timeval", and add it to the
		 * protocol tree.
		 * Note: this will succeed even if it's a Short-integer.
		 * A Short-integer would work, but, as the time values
		 * are UNIX seconds-since-the-Epoch value, and as
		 * there weren't WAP phones or Web servers back in
		 * late 1969/early 1970, they're unlikely to be used.
		 */
		timeValue.secs = secs;
		timeValue.nsecs = 0;
		proto_tree_add_time (tree, hf_time, header_buff, 0,
			headerLen, &timeValue);
	}
	else
	{
		proto_tree_add_text (tree, header_buff, 0, headerLen,
		    "Invalid %s date value",
		    match_strval (headerType, vals_field_names));
	}
}

static int
add_parameter (proto_tree *tree, tvbuff_t *value_buff, int offset)
{
	int startOffset;
	value_type_t valueType;
	int subvalueLen;
	int subvalueOffset;
	guint value;

	startOffset = offset;
	valueType = get_value_type_len (value_buff, offset,
	    &subvalueLen, &subvalueOffset, &offset);
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Untyped-parameter.
		 */
		offset = add_untyped_parameter (tree, value_buff, startOffset, offset);
		return offset;
	}

	/*
	 * Well-known-parameter-token.
	 */
	if (get_integer (value_buff, subvalueOffset,
	    subvalueLen, valueType, &value) < 0)
	{
	    	proto_tree_add_text (tree, value_buff, startOffset,
		    offset - startOffset,
		    "Invalid Well-known-parameter-token");
		return offset;
	}

	switch (value) {

	case 0x01:	/* Charset */
		offset = add_parameter_charset (tree, value_buff, startOffset, offset);
		break;

	case 0x03:	/* Type */
		offset = add_parameter_type (tree, value_buff, startOffset, offset);
		break;

	case 0x05:	/* Name */
		offset = add_parameter_text (tree, value_buff, startOffset, offset,
				    hf_wsp_parameter_name, "Name");
		break;

	case 0x06:	/* Filename */
		offset = add_parameter_text (tree, value_buff, startOffset, offset,
				    hf_wsp_parameter_filename, "Filename");
		break;

	case 0x09:	/* Type (special) */
		offset = add_constrained_encoding(tree, value_buff, startOffset, offset);
		break;

	case 0x0A:	/* Start */
		offset = add_parameter_text (tree, value_buff, startOffset, offset,
				    hf_wsp_parameter_start, "Start");
		break;

	case 0x0B:	/* Start-info */
		offset = add_parameter_text (tree, value_buff, startOffset, offset,
				    hf_wsp_parameter_start_info, "Start-info");
		break;

	case 0x0C:	/* Comment */
		offset = add_parameter_text (tree, value_buff, startOffset, offset,
				    hf_wsp_parameter_comment, "Comment");
		break;

	case 0x0D:	/* Domain */
		offset = add_parameter_text (tree, value_buff, startOffset, offset,
				    hf_wsp_parameter_domain, "Domain");
		break;

	case 0x0F:	/* Path */
		offset = add_parameter_text (tree, value_buff, startOffset, offset,
				    hf_wsp_parameter_path, "Path");
		break;

	case 0x00:	/* Q */
	case 0x02:	/* Level */
	case 0x07:	/* Differences */
	case 0x08:	/* Padding */
	case 0x0E:	/* Max-Age */
	case 0x10:	/* Secure */
	default:
		break;
	}

	return offset;
}

static int
add_untyped_parameter (proto_tree *tree, tvbuff_t *value_buff, int startOffset,
    int offset)
{
	const guint8 *token;
	value_type_t valueType;
	int subvalueLen;
	int subvalueOffset;
	guint value;
	int vOffset = offset;

	token = tvb_get_ptr (value_buff, startOffset, offset - startOffset);
	/*
	 * Now an Untyped-value; either an Integer-value or a Text-value.
	 */
	valueType = get_value_type_len (value_buff, offset,
	    &subvalueLen, &subvalueOffset, &offset);
	if (valueType == VALUE_IS_TEXT_STRING)
	{
		/*
		 * Text-value.
		 */
		if ((offset - vOffset) == 1) {
			/*
			 * No-value.  (stringSize includes the terminating
			 * null byte, so an empty string has a size of 1.)
			 */
			proto_tree_add_text (tree, value_buff, startOffset,
			    offset - startOffset,
			    "%s", token);
			return offset;
		}
		proto_tree_add_text (tree, value_buff, startOffset,
		    offset - startOffset,
		    "%s: %s", token,
		    tvb_get_ptr (value_buff, vOffset, offset - vOffset));
	}
	else
	{
		/*
		 * Integer-value.
		 */
		if (get_integer (value_buff, subvalueOffset, subvalueLen,
		    valueType, &value) == 0)
		{
			proto_tree_add_text (tree, value_buff, startOffset,
			    offset - startOffset,
			    "%s: %u", token, value);
		}
		else
		{
			proto_tree_add_text (tree, value_buff, startOffset,
			    offset - startOffset,
			    "%s: Invalid Integer-value", token);
		}
	}
	return offset;
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

static void
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
	
	/* VERIFY ti = proto_tree_add_item (tree, hf_wsp_post_data,tvb,offset,-1,bo_little_endian); */
	ti = proto_tree_add_item (tree, hf_wsp_post_data,tvb,offset,-1,bo_little_endian);

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
					add_post_variable (ti, tvb, variableStart, variableEnd, valueStart, offset);
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
			add_post_variable (ti, tvb, variableStart, variableEnd, valueStart, offset);
		}
	}
	else if ((contentType == 0x22) || (contentType == 0x23) || (contentType == 0x23) || (contentType == 0x24) ||
		 (contentType == 0x25) || (contentType == 0x26) || (contentType == 0x33))
	{
		add_multipart_data(ti, tvb);
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

void
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
			{ 	"Transmission ID",           
				"wsp.TID",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"Transmission ID", HFILL
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
				"Shift code", HFILL
			}
		},
		{ &hf_wsp_header_accept,
			{ 	"Accept",           
				"wsp.header.accept",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_UINT8, BASE_HEX, VALS ( vals_content_types ), 0x00,
				"Accept", HFILL
			}
		},
		{ &hf_wsp_header_accept_str,
			{ 	"Accept",           
				"wsp.header.accept.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Accept", HFILL
			}
		},
		{ &hf_wsp_header_accept_application,
			{ 	"Accept-Application",           
				"wsp.header.accept_application",
				 FT_UINT32, BASE_HEX, NULL, 0x00,
				"Accept-Application", HFILL
			}
		},
		{ &hf_wsp_header_accept_application_str,
			{ 	"Accept-Application",
				"wsp.header.accept_application.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Accept-Application", HFILL
			}
		},
		{ &hf_wsp_header_accept_charset,
			{ 	"Accept-Charset",           
				"wsp.header.accept_charset",
				 FT_UINT16, BASE_HEX, VALS ( vals_character_sets ), 0x00,
				"Accept-Charset", HFILL
			}
		},
		{ &hf_wsp_header_accept_charset_str,
			{ 	"Accept-Charset",           
				"wsp.header.accept_charset.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Accept-Charset", HFILL
			}
		},
		{ &hf_wsp_header_accept_language,
			{ 	"Accept-Language",           
				"wsp.header.accept_language",
				 FT_UINT8, BASE_HEX, VALS ( vals_languages ), 0x00,
				"Accept-Language", HFILL
			}
		},
		{ &hf_wsp_header_accept_language_str,
			{ 	"Accept-Language",           
				"wsp.header.accept_language.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Accept-Language", HFILL
			}
		},
		{ &hf_wsp_header_accept_ranges,
			{ 	"Accept-Ranges",           
				"wsp.header.accept_ranges",
				 FT_UINT8, BASE_HEX, VALS ( vals_accept_ranges ), 0x00,
				"Accept-Ranges", HFILL
			}
		},
		{ &hf_wsp_header_accept_ranges_str,
			{ 	"Accept-Ranges",           
				"wsp.header.accept_ranges.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Accept-Ranges", HFILL
			}
		},
		{ &hf_wsp_header_age,
			{ 	"Age",           
				"wsp.header.age",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Age", HFILL
			}
		},
		{ &hf_wsp_header_bearer_indication,
			/*
			 * XXX - I'm assuming that the bearer indication is
			 * just a bearer type.
			 */
			{ 	"Bearer-indication",           
				"wsp.header.bearer_indication",
				 FT_UINT32, BASE_HEX, VALS(vals_bearer_types), 0x00,
				"Bearer-indication", HFILL
			}
		},
		{ &hf_wsp_header_cache_control,
			{ 	"Cache-Control",           
				"wsp.header.cache_control",
				 FT_UINT8, BASE_HEX, VALS ( vals_cache_control ), 0x00,
				"Cache-Control", HFILL
			}
		},
		{ &hf_wsp_header_cache_control_str,
			{ 	"Cache-Control",           
				"wsp.header.cache_control.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Cache-Control", HFILL
			}
		},
		{ &hf_wsp_header_cache_control_field_name,
			{ 	"Field Name",
				"wsp.header.cache_control.field_name",
				 FT_UINT8, BASE_HEX, VALS ( vals_field_names ), 0x00,
				"Cache-Control field name", HFILL
			}
		},
		{ &hf_wsp_header_cache_control_field_name_str,
			{ 	"Field Name",
				"wsp.header.cache_control.field_name.str",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Cache-Control field name", HFILL
			}
		},
		{ &hf_wsp_header_connection,
			{ 	"Connection",           
				"wsp.header.connection",
				 FT_UINT8, BASE_HEX, VALS ( vals_connection ), 0x00,
				"Connection", HFILL
			}
		},
		{ &hf_wsp_header_connection_str,
			{ 	"Connection",           
				"wsp.header.connection_str",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Connection", HFILL
			}
		},
		{ &hf_wsp_header_content_length,
			{ 	"Content-Length",           
				"wsp.header.content_length",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Content-Length", HFILL
			}
		},
		{ &hf_wsp_header_date,
			{ 	"Date",           
				"wsp.header.date",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"Date", HFILL
			}
		},
		{ &hf_wsp_header_etag,
			{ 	"Etag",           
				"wsp.header.etag",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Etag", HFILL
			}
		},
		{ &hf_wsp_header_expires,
			{ 	"Expires",           
				"wsp.header.expires",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"Expires", HFILL
			}
		},
		{ &hf_wsp_header_last_modified,
			{ 	"Last-Modified",           
				"wsp.header.last_modified",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"Last-Modified", HFILL
			}
		},
		{ &hf_wsp_header_location,
			{ 	"Location",           
				"wsp.header.location",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Location", HFILL
			}
		},
		{ &hf_wsp_header_if_modified_since,
			{ 	"If-Modified-Since",           
				"wsp.header.if_modified_since",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"If-Modified-Since", HFILL
			}
		},
		{ &hf_wsp_header_pragma,
			{ 	"Pragma",           
				"wsp.header.pragma",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"pragma", HFILL
			}
		},
		{ &hf_wsp_header_profile,
			{ 	"Profile",           
				"wsp.header.profile",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Profile", HFILL
			}
		},
		{ &hf_wsp_header_server,
			{ 	"Server",           
				"wsp.header.server",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Server", HFILL
			}
		},
		{ &hf_wsp_header_transfer_encoding,
			{ 	"Transfer Encoding",           
				"wsp.header.transfer_enc",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_UINT8, BASE_HEX, VALS ( vals_transfer_encoding ), 0x00,
				"Transfer Encoding", HFILL
			}
		},
		{ &hf_wsp_header_transfer_encoding_str,
			{ 	"Transfer Encoding",           
				"wsp.header.transfer_enc_str",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Transfer Encoding", HFILL
			}
		},
		{ &hf_wsp_header_user_agent,
			{ 	"User-Agent",           
				"wsp.header.user_agent",
				 /*FT_NONE, BASE_DEC, NULL, 0x00,*/
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"User-Agent", HFILL
			}
		},
		{ &hf_wsp_header_via,
			{ 	"Via",           
				"wsp.header.via",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Via", HFILL
			}
		},
		{ &hf_wsp_header_wap_application_id,
			{ 	"X-Wap-Application-Id",           
				"wsp.header.wap_application_id",
				 FT_UINT8, BASE_HEX, NULL, 0x00,
				"WAP application id", HFILL
			}
		},
		{ &hf_wsp_header_wap_application_id_str,
			{ 	"X-Wap-Application-Id",           
				"wsp.header.wap_application_id.string",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"WAP application id", HFILL
			}
		},
		{ &hf_wsp_header_warning,
			{ 	"Warning",
				"wsp.header.warning",
				 FT_NONE, BASE_NONE, NULL, 0x00,
				"Warning", HFILL
			}
		},
		{ &hf_wsp_header_warning_code,
			{ 	"Warning Code",
				"wsp.header.warning.code",
				 FT_UINT32, BASE_DEC, NULL, 0x00,
				"Warning Code", HFILL
			}
		},
		{ &hf_wsp_header_warning_agent,
			{ 	"Warning Agent",
				"wsp.header.warning.agent",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Warning Agent", HFILL
			}
		},
		{ &hf_wsp_header_warning_text,
			{ 	"Warning Text",
				"wsp.header.warning.text",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Warning Text", HFILL
			}
		},
		{ &hf_wsp_header_application_header,
			{ 	"Application Header",           
				"wsp.header.application_header",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Application Header", HFILL
			}
		},
		{ &hf_wsp_header_application_value,
			{ 	"Application Header Value",           
				"wsp.header.application_header.value",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Application Header Value", HFILL
			}
		},
		{ &hf_wsp_header_content_ID,
			{ 	"Content-ID",           
				"wsp.header.content-id",
				 FT_STRING, BASE_NONE, NULL, 0x00,
				"Content-ID", HFILL
			}
		},
		{ &hf_wsp_header_x_wap_tod,
			{ 	"X-WAP.TOD",           
				"wsp.header.x_wap_tod",
				 FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0,
				"X-WAP.TOD", HFILL
			}
		},
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
			{ 	"Post Data",           
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
	};
	
/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_wsp,
		&ett_content_type_parameters,
		&ett_header,
		&ett_headers,
		&ett_header_warning,
		&ett_header_cache_control_parameters,
		&ett_header_cache_control_field_names,
		&ett_capabilities,
		&ett_content_type,
		&ett_redirect_flags,
		&ett_redirect_afl,
		&ett_multiparts,
		&ett_mpartlist
	};

/* Register the protocol name and description */
	proto_wsp = proto_register_protocol(
		"Wireless Session Protocol",   	/* protocol name for use by ethereal */ 
		"WSP",                          /* short version of name */
		"wap-wsp"                   	/* Abbreviated protocol name, should Match IANA 
						    < URL:http://www.isi.edu/in-notes/iana/assignments/port-numbers/ >
						  */
	);

/* Required function calls to register the header fields and subtrees used  */
	proto_register_field_array(proto_wsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("wsp-co", dissect_wsp_fromwap_co, proto_wsp);
	register_dissector("wsp-cl", dissect_wsp_fromwap_cl, proto_wsp);
	wsp_dissector_table = register_dissector_table("wsp.content_type.type",
	    "WSP content type", FT_UINT8, BASE_HEX);
	register_heur_dissector_list("wsp", &heur_subdissector_list);

	wsp_fromudp_handle = create_dissector_handle(dissect_wsp_fromudp,
	    proto_wsp);
};

void
proto_reg_handoff_wsp(void)
{
	/*
	 * Get a handle for the WMLC dissector.
	 */
	wmlc_handle = find_dissector("wmlc");	/* Coming soon :) */

	/*
	 * And get a handle for the WTP-over-UDP dissector.
	 */
	wtp_fromudp_handle = find_dissector("wtp-udp");

	/* Only connection-less WSP has no previous handler */
	dissector_add("udp.port", UDP_PORT_WSP, wsp_fromudp_handle);
	dissector_add("udp.port", UDP_PORT_WSP_PUSH, wsp_fromudp_handle);

	/* This dissector is also called from the WTP and WTLS dissectors */
}
