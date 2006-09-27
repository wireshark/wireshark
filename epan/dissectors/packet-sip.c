/* packet-sip.c
 * Routines for the Session Initiation Protocol (SIP) dissection.
 * RFCs 3261-3264
 *
 * TODO: Pay attention to Content-Type: It might not always be SDP.
 *	Content-Type is fixed, mixed/mode is not handled though.
 *       hf_ display filters for headers of SIP extension RFCs:
 *		Done for RFC 3265, RFC 3262
 *		Use hash table for list of headers
 *       Add sip msg body dissection based on Content-Type for:
 *                SDP, MIME, and other types
 *       Align SIP methods with recent Internet Drafts or RFC
 *               (SIP INFO, rfc2976 - done)
 *               (SIP SUBSCRIBE-NOTIFY - done)
 *               (SIP REFER - done)
 *               check for other
 *
 * Copyright 2000, Heikki Vatiainen <hessu@cs.tut.fi>
 * Copyright 2001, Jean-Francois Mule <jfm@cablelabs.com>
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-cops.c
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
#include <string.h>
#include <ctype.h>

#include <epan/prefs.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/req_resp_hdrs.h>
#include <epan/emem.h>

#include "packet-sip.h"
#include <epan/tap.h>
#include <epan/emem.h>
#include <epan/expert.h>

#include "packet-tcp.h"
#include "packet-ssl.h"

#define TCP_PORT_SIP 5060
#define UDP_PORT_SIP 5060
#define TLS_PORT_SIP 5061

static gint sip_tap = -1;
static dissector_handle_t sigcomp_handle;

/* Dissectors */
static dissector_handle_t sip_handle = NULL;
static dissector_handle_t sip_tcp_handle = NULL;

/* Initialize the protocol and registered fields */
static gint proto_sip				= -1;
static gint proto_raw_sip			= -1;
static gint hf_msg_hdr				= -1;
static gint hf_Method				= -1;
static gint hf_Request_Line			= -1;
static gint hf_Status_Code			= -1;
static gint hf_Status_Line			= -1;
static gint hf_sip_display			= -1;
static gint hf_sip_to_addr			= -1;
static gint hf_sip_from_addr		= -1;
static gint hf_sip_tag				= -1;
static gint hf_sip_uri				= -1;
static gint hf_sip_contact_addr		= -1;
static gint hf_sip_contact_item		= -1;
static gint hf_sip_resend			= -1;
static gint hf_sip_original_frame	= -1;

static gint hf_sip_auth                  = -1;
static gint hf_sip_auth_scheme           = -1;
static gint hf_sip_auth_digest_response  = -1;
static gint hf_sip_auth_nc               = -1;
static gint hf_sip_auth_username         = -1;
static gint hf_sip_auth_realm            = -1;
static gint hf_sip_auth_nonce            = -1;
static gint hf_sip_auth_algorithm        = -1;
static gint hf_sip_auth_opaque           = -1;
static gint hf_sip_auth_qop              = -1;
static gint hf_sip_auth_cnonce           = -1;
static gint hf_sip_auth_uri              = -1;
static gint hf_sip_auth_domain           = -1;
static gint hf_sip_auth_stale            = -1;
static gint hf_sip_auth_auts             = -1;
static gint hf_sip_auth_rspauth          = -1;
static gint hf_sip_auth_nextnonce        = -1;

static gint hf_sip_cseq_seq_no           = -1;
static gint hf_sip_cseq_method           = -1;

/* Initialize the subtree pointers */
static gint ett_sip 				= -1;
static gint ett_sip_reqresp 		= -1;
static gint ett_sip_hdr 			= -1;
static gint ett_raw_text 			= -1;
static gint ett_sip_element 		= -1;
static gint ett_sip_uri				= -1;
static gint ett_sip_contact_item	= -1;
static gint ett_sip_message_body	= -1;
static gint ett_sip_cseq			= -1;

/* PUBLISH method added as per http://www.ietf.org/internet-drafts/draft-ietf-sip-publish-01.txt */
static const char *sip_methods[] = {
        "<Invalid method>",      /* Pad so that the real methods start at index 1 */
        "ACK",
        "BYE",
        "CANCEL",
        "DO",
        "INFO",
        "INVITE",
        "MESSAGE",
        "NOTIFY",
        "OPTIONS",
        "PRACK",
        "QAUTH",
        "REFER",
        "REGISTER",
        "SPRACK",
        "SUBSCRIBE",
        "UPDATE",
        "PUBLISH"
};

/* from RFC 3261
 * Updated with info from http://www.iana.org/assignments/sip-parameters
 * (last updated 2004-10-17)
 * Updated with: http://www.ietf.org/internet-drafts/draft-ietf-sip-resource-priority-05.txt
 */
typedef struct {
        const char *name;
        const char *compact_name;
} sip_header_t;
static const sip_header_t sip_headers[] = {
                { "Unknown-header", 			NULL }, /* 0 Pad so that the real headers start at index 1 */
                { "Accept", 					NULL }, /* 1 */
                { "Accept-Contact",				"a"	 }, /* 2 RFC3841  */
                { "Accept-Encoding", 			NULL }, /* 3 */
                { "Accept-Language", 			NULL }, /* 4 */
                { "Accept-Resource-Priority",		NULL },	/* 5 draft-ietf-sip-resource-priority-05.txt */
                { "Alert-Info", 				NULL },
                { "Allow", 						NULL },
                { "Allow-Events", 				"u"  },	/* 8 RFC3265  */
                { "Authentication-Info",	 	NULL },
                { "Authorization", 				NULL }, /* 10 */
                { "Call-ID", 					"i"  },
                { "Call-Info", 					NULL },
                { "Contact", 					"m"  },
                { "Content-Disposition", 		NULL },
                { "Content-Encoding", 			"e"  }, /* 15 */
                { "Content-Language", 			NULL },
                { "Content-Length", 			"l"  },
                { "Content-Type", 				"c"  },
                { "CSeq", 						NULL },
                { "Date", 						NULL }, /* 20 */
                { "Error-Info", 				NULL },
                { "Event", 						"o"  },
                { "Expires", 					NULL },
                { "From", 						"f"  },
                { "In-Reply-To", 				NULL },	/*  25 RFC3261  */
                { "Join",		 				NULL }, /*  26 RFC-ietf-sip-join-03.txt  */
                { "Max-Forwards", 				NULL },
                { "MIME-Version", 				NULL },
                { "Min-Expires", 				NULL },
                { "Min-SE",						NULL },  /*  30 RFC-ietf-sip-session-timer-15.txt  */
                { "Organization", 				NULL },
                { "P-Access-Network-Info",		NULL },  /*  32 RFC3455  */
                { "P-Asserted-Identity",        NULL },  /*  33 RFC3325  */
                { "P-Associated-URI",           NULL },	 /*  34 RFC3455  */
                { "P-Called-Party-ID",          NULL },	 /*  35 RFC3455  */
                { "P-Charging-Function-Addresses",NULL },/*  36 RFC3455  */
                { "P-Charging-Vector",          NULL },  /*  37 RFC3455  */
                { "P-DCS-Trace-Party-ID",       NULL },  /*  38 RFC3603  */
                { "P-DCS-OSPS",                 NULL },  /*  39 RFC3603  */
                { "P-DCS-Billing-Info",         NULL },  /*  40 RFC3603  */
                { "P-DCS-LAES",                 NULL },  /*  41 RFC3603  */
                { "P-DCS-Redirect",             NULL },  /*  42 RFC3603  */
                { "P-Media-Authorization",      NULL },  /*  43 RFC3313  */
                { "P-Preferred-Identity",       NULL },  /*  44 RFC3325  */
                { "P-Visited-Network-ID",       NULL },  /*  45 RFC3455  */
                { "Path",                       NULL },  /*  46 RFC3327  */
                { "Priority", 					NULL },
                { "Privacy",                    NULL },  /*  48 RFC3323  */
                { "Proxy-Authenticate", 		NULL },
                { "Proxy-Authorization", 		NULL },	 /* 50 */
                { "Proxy-Require", 				NULL },
                { "RAck", 						NULL },  /*  52 RFC3262  */
                { "Reason",                     NULL },  /*  53 RFC3326  */
                { "Record-Route", 				NULL },
                { "Referred-By",				"b"  },  /*  55 RFC3892  */
                { "Reject-Contact",				"j"  },  /*  56 RFC3841  */
                { "Replaces",					NULL },  /*  57 RFC3891  */
                { "Reply-To", 					NULL },  /*  58 RFC3261  */
                { "Request-Disposition",		"d"  },  /*  59 RFC3841  */
                { "Require", 					NULL },  /*  60 RFC3261  */
                { "Resource-Priority",			NULL },	 /*  61 draft-ietf-sip-resource-priority-05.txt */
                { "Retry-After", 				NULL },  /*  62 RFC3261  */
                { "Route", 						NULL },  /*  63 RFC3261  */
                { "RSeq", 						NULL },  /*  64 RFC3262  */
                { "Security-Client",			NULL },  /*  65 RFC3329  */
                { "Security-Server",			NULL },  /*  66 RFC3329  */
                { "Security-Verify",			NULL },  /*  67 RFC3329  */
                { "Server",			 			NULL },  /*  68 RFC3261  */
                { "Service-Route",				NULL },  /*  69 RFC3608  */
                { "Session-Expires",			"x"  },  /*  70 RFC-ietf-sip-session-timer-15.txt  */
                { "SIP-ETag",					NULL },  /*  71 draft-ietf-sip-publish-03  */
                { "SIP-If-Match",				NULL },  /*  72 draft-ietf-sip-publish-03  */
                { "Subject",					"s"  },  /*  73 RFC3261  */
                { "Subscription-State", 		NULL },  /*  74 RFC3265  */
                { "Supported",					"k"	 },  /*  75 RFC3261  */
                { "Timestamp",					NULL },  /*  76 RFC3261  */
                { "To",							"t"  },  /*  77 RFC3261  */
                { "Unsupported",				NULL },  /*  78 RFC3261  */
                { "User-Agent", 				NULL },  /*  79 RFC3261  */
                { "Via",			 			"v"  },  /*  80 RFC3261  */
                { "Warning",		 			NULL },  /*  81 RFC3261  */
                { "WWW-Authenticate",			NULL },  /*  82 RFC3261  */
                { "Refer-To",					"r"  },  /*  83 RFC3515  */
                { "History-Info", 				NULL },  /*  84 RFC4244  */

};


#define POS_ACCEPT							1
#define POS_ACCEPT_CONTACT					2
#define POS_ACCEPT_ENCODING					3
#define POS_ACCEPT_LANGUAGE					4
#define POS_ACCEPT_RESOURCE_PRIORITY		5
#define POS_ALERT_INFO						6
#define POS_ALLOW							7
#define POS_ALLOW_EVENTS					8
#define POS_AUTHENTICATION_INFO				9
#define POS_AUTHORIZATION					10
#define POS_CALL_ID							11
#define POS_CALL_INFO						12
#define POS_CONTACT							13
#define POS_CONTENT_DISPOSITION				14
#define POS_CONTENT_ENCODING				15
#define POS_CONTENT_LANGUAGE				16
#define POS_CONTENT_LENGTH					17
#define POS_CONTENT_TYPE					18
#define POS_CSEQ							19
#define POS_DATE							20
#define POS_ERROR_INFO						21
#define POS_EVENT							22
#define POS_EXPIRES							23
#define POS_FROM							24
#define POS_IN_REPLY_TO						25
#define POS_JOIN							26
#define POS_MAX_FORWARDS					27
#define POS_MIME_VERSION					28
#define POS_MIN_EXPIRES						29
#define POS_MIN_SE							30
#define POS_ORGANIZATION					31
#define POS_P_ACCESS_NETWORK_INFO			32
#define POS_P_ASSERTED_IDENTITY				33
#define POS_P_ASSOCIATED_URI				34
#define POS_P_CALLED_PARTY_ID				35
#define POS_P_CHARGING_FUNCTION_ADDRESSES	36
#define POS_P_CHARGING_VECTOR				37
#define POS_P_DCS_TRACE_PARTY_ID			38
#define POS_P_DCS_OSPS						39
#define POS_P_DCS_BILLING_INFO				40
#define POS_P_DCS_LAES						41
#define POS_P_DCS_REDIRECT					42
#define POS_P_MEDIA_AUTHORIZATION			43
#define POS_P_PREFERRED_IDENTITY			44
#define POS_P_VISITED_NETWORK_ID			45
#define POS_PATH							46
#define POS_PRIORITY						47
#define POS_PRIVACY							48
#define POS_PROXY_AUTHENTICATE				49
#define POS_PROXY_AUTHORIZATION				50
#define POS_PROXY_REQUIRE					51
#define POS_RACK							52
#define POS_REASON							53
#define POS_RECORD_ROUTE					54
#define POS_REFERED_BY						55
#define POS_REJECT_CONTACT					56
#define POS_REPLACES						57
#define POS_REPLY_TO						58
#define POS_REQUEST_DISPOSITION				59
#define POS_REQUIRE							60
#define POS_RESOURCE_PRIORITY				61
#define POS_RETRY_AFTER						62
#define POS_ROUTE							63
#define POS_RSEQ							64
#define POS_SECURITY_CLIENT					65
#define POS_SECURITY_SERVER					66
#define POS_SECURITY_VERIFY					67
#define POS_SERVER							68
#define POS_SERVICE_ROUTE					69
#define POS_SESSION_EXPIRES					70
#define POS_SIP_ETAG						71
#define POS_SIP_IF_MATCH					72
#define POS_SUBJECT							73
#define POS_SUBSCRIPTION_STATE				74
#define POS_SUPPORTED						75
#define POS_TIMESTAMP						76
#define POS_TO								77
#define POS_UNSUPPORTED						78
#define POS_USER_AGENT						79
#define POS_VIA								80
#define POS_WARNING							81
#define POS_WWW_AUTHENTICATE				82
#define POS_REFER_TO						83
#define POS_HISTORY_INFO					84

static gint hf_header_array[] = {
                -1, /* 0"Unknown-header" - Pad so that the real headers start at index 1 */
                -1, /* 1"Accept"										*/
                -1, /* 2"Accept-Contact"					RFC3841		*/
                -1, /* 3"Accept-Encoding"								*/
                -1, /* 4"Accept-Language"								*/
                -1, /* 5"Accept-Resource-Priority"  draft-ietf-sip-resource-priority-05.txt	*/
                -1, /* 6"Alert-Info",									*/
                -1, /* 7"Allow", 										*/
                -1, /* 8"Allow-Events",						RFC3265		*/
                -1, /* 9"Authentication-Info"							*/
                -1, /* 10"Authorization",								*/
                -1, /* 11"Call-ID",										*/
                -1, /* 12"Call-Info"									*/
                -1, /* 13"Contact",										*/
                -1, /* 14"Content-Disposition",							*/
                -1, /* 15"Content-Encoding",							*/
                -1, /* 16"Content-Language",							*/
                -1, /* 17"Content-Length",								*/
                -1, /* 18"Content-Type",								*/
                -1, /* 19"CSeq",										*/
                -1, /* 20"Date",										*/
                -1, /* 21"Error-Info",									*/
                -1, /* 22"Event",										*/
                -1, /* 23"Expires",										*/
                -1, /* 24"From", 										*/
                -1, /* 25"In-Reply-To",						RFC3261		*/
                -1, /* 26"Join",							RFC-ietf-sip-join-03.txt  */
                -1, /* 27"Max-Forwards",								*/
                -1, /* 28"MIME-Version",								*/
                -1, /* 29"Min-Expires",									*/
                -1, /* 30"Min-SE",							RFC-ietf-sip-session-timer-15.txt  */
                -1, /* 31"Organization",								*/
                -1, /* 32"P-Access-Network-Info",				RFC3455	*/
                -1, /* 33"P-Asserted-Identity",					RFC3325	*/
                -1, /* 34"P-Associated-URI",					RFC3455	*/
                -1, /* 35"P-Called-Party-ID",					RFC3455	*/
                -1, /* 36"P-Charging-Function-Addresses",		RFC3455 */
                -1, /* 37"P-Charging-Vector",					RFC3455 */
                -1, /* 38"P-DCS-Trace-Party-ID",				RFC3603 */
                -1, /* 39"P-DCS-OSPS",							RFC3603 */
                -1, /* 40"P-DCS-Billing-Info",					RFC3603 */
                -1, /* 41"P-DCS-LAES",							RFC3603 */
                -1, /* 42"P-DCS-Redirect",						RFC3603 */
                -1, /* 43"P-Media-Authorization",				RFC3313 */
                -1, /* 44"P-Preferred-Identity",				RFC3325 */
                -1, /* 45"P-Visited-Network-ID",				RFC3455 */
                -1, /* 46"Path",								RFC3327 */
                -1, /* 47"Priority"										*/
                -1, /* 48"Privacy",								RFC3323 */
                -1, /* 49"Proxy-Authenticate",							*/
                -1, /* 50"Proxy-Authorization",							*/
                -1, /* 51"Proxy-Require",								*/
                -1, /* 52"RAck",								RFC3262 */
                -1, /* 53"Reason",								RFC3326 */
                -1, /* 54"Record-Route",								*/
                -1, /* 55"Referred-By",									*/
                -1, /* 56"Reject-Contact",						RFC3841 */
                -1, /* 57"Replaces",							RFC3891 */
                -1, /* 58"Reply-To",							RFC3261 */
                -1, /* 59"Request-Disposition",					RFC3841 */
                -1, /* 60"Require",								RFC3261 */
				-1, /* 61"Resource-Priority",draft-ietf-sip-resource-priority-05.txt */
				-1, /* 62"Retry-After",							RFC3261 */
                -1, /* 63"Route",								RFC3261 */
                -1, /* 64"RSeq",								RFC3262 */
                -1, /* 65"Security-Client",						RFC3329 */
                -1, /* 66"Security-Server",						RFC3329 */
                -1, /* 67"Security-Verify",						RFC3329 */
                -1, /* 68"Server",								RFC3261 */
                -1, /* 69"Service-Route",						RFC3608 */
                -1, /* 70"Session-Expires",	RFC-ietf-sip-session-timer-15.txt  */
                -1, /* 71"SIP-ETag",			  draft-ietf-sip-publish-04  */
                -1, /* 72"SIP-If-Match",		  draft-ietf-sip-publish-04  */
                -1, /* 73"Subject",								RFC3261 */
                -1, /* 74"Subscription-State",					RFC3265 */
                -1, /* 75"Supported",							RFC3261 */
                -1, /* 76"Timestamp",							RFC3261 */
                -1, /* 77"To",									RFC3261 */
                -1, /* 78"Unsupported",							RFC3261 */
                -1, /* 79"User-Agent",							RFC3261 */
                -1, /* 80"Via",									RFC3261 */
                -1, /* 81"Warning",								RFC3261 */
                -1, /* 82"WWW-Authenticate",					RFC3261 */
                -1, /* 83"Refer-To",							RFC3515 */
                -1, /* 84"History-Info",						RFC4244 */

};

/* Track associations between parameter name and hf item */
typedef struct {
	const char  *param_name;
	const gint  *hf_item;
} auth_parameter_t;

static auth_parameter_t auth_parameters_hf_array[] =
{
	{"response",        &hf_sip_auth_digest_response},
	{"nc",              &hf_sip_auth_nc},
	{"username",        &hf_sip_auth_username},
	{"realm",           &hf_sip_auth_realm},
	{"nonce",           &hf_sip_auth_nonce},
	{"algorithm",       &hf_sip_auth_algorithm},
	{"opaque",          &hf_sip_auth_opaque},
	{"qop",             &hf_sip_auth_qop},
	{"cnonce",          &hf_sip_auth_cnonce},
	{"uri",             &hf_sip_auth_uri},
	{"domain",          &hf_sip_auth_domain},
	{"stale",           &hf_sip_auth_stale},
	{"auts",            &hf_sip_auth_auts},
	{"rspauth",         &hf_sip_auth_rspauth},
	{"nextnonce",       &hf_sip_auth_nextnonce},
};

/*
 * Type of line.  It's either a SIP Request-Line, a SIP Status-Line, or
 * another type of line.
 */
typedef enum {
	REQUEST_LINE,
	STATUS_LINE,
	OTHER_LINE
} line_type_t;

/* global_sip_raw_text determines whether we are going to display		*/
/* the raw text of the SIP message, much like the MEGACO dissector does.	*/
static gboolean global_sip_raw_text = FALSE;
/* strict_sip_version determines whether the SIP dissector enforces
 * the SIP version to be "SIP/2.0". */
static gboolean strict_sip_version = TRUE;

/*
 * desegmentation of SIP headers
 * (when we are over TCP or another protocol providing the desegmentation API)
 */
static gboolean sip_desegment_headers = TRUE;

/*
 * desegmentation of SIP bodies
 * (when we are over TCP or another protocol providing the desegmentation API)
 */
static gboolean sip_desegment_body = TRUE;

static gboolean dissect_sip_common(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, gboolean is_heur, gboolean use_reassembly);
static line_type_t sip_parse_line(tvbuff_t *tvb, int offset, gint linelen,
    guint *token_1_len);
static gboolean sip_is_known_request(tvbuff_t *tvb, int meth_offset,
    guint meth_len, guint *meth_idx);
static gint sip_is_known_sip_header(tvbuff_t *tvb, int offset,
    guint header_len);
static void dfilter_sip_request_line(tvbuff_t *tvb, proto_tree *tree,
    guint meth_len);
static void dfilter_sip_status_line(tvbuff_t *tvb, proto_tree *tree);
static void tvb_raw_text_add(tvbuff_t *tvb, int offset, int length, proto_tree *tree);
static guint sip_is_packet_resend(packet_info *pinfo,
				gchar* cseq_method,
				gchar* call_id,
				guchar cseq_number_set, guint32 cseq_number,
				line_type_t line_type);


/* SIP content type and internet media type used by other dissectors
 * are the same.  List of media types from IANA at:
 * http://www.iana.org/assignments/media-types/index.html */
static dissector_table_t media_type_dissector_table;

static heur_dissector_list_t heur_subdissector_list;

#define SIP2_HDR "SIP/2.0"
#define SIP2_HDR_LEN (strlen (SIP2_HDR))

/* Store the info needed by the SIP tap for one packet */
static sip_info_value_t *stat_info;

/* The buffer size for the cseq_method name */
#define MAX_CSEQ_METHOD_SIZE 16

/****************************************************************************
 * Conversation-type definitions
 *
 * For each call, keep track of the current cseq number and state of
 * transaction, in order to be able to detect retransmissions.
 *
 * Don't use the conservation mechanism, but instead:
 * - store with each dissected packet original frame (if any)
 * - maintain a global hash table of
 *   (call_id, source_addr, dest_addr) -> (cseq, transaction_state, frame)
 ****************************************************************************/

static GHashTable *sip_hash = NULL;           /* Hash table */

/* Types for hash table keys and values */
#define MAX_CALL_ID_SIZE 128
typedef struct
{
	char call_id[MAX_CALL_ID_SIZE];
	address source_address;
	guint32 source_port;
	address dest_address;
	guint32 dest_port;
} sip_hash_key;


typedef enum
{
	nothing_seen,
	request_seen,
	provisional_response_seen,
	final_response_seen
} transaction_state_t;

typedef struct
{
	guint32 cseq;
	transaction_state_t transaction_state;
	gchar method[MAX_CSEQ_METHOD_SIZE];
	guint32 response_code;
	gint frame_number;
} sip_hash_value;


/************************/
/* Hash table functions */

/* Equal keys */
static gint sip_equal(gconstpointer v, gconstpointer v2)
{
	const sip_hash_key* val1 = v;
	const sip_hash_key* val2 = v2;

	/* Call id must match */
	if (strcmp(val1->call_id, val2->call_id) != 0)
	{
		return 0;
	}

	/* Addresses must match */
	return  (ADDRESSES_EQUAL(&(val1->source_address), &(val2->source_address))) &&
		(val1->source_port == val2->source_port) &&
		(ADDRESSES_EQUAL(&(val1->dest_address), &(val2->dest_address))) &&
		(val1->dest_port == val2->dest_port);
}

/* Compute a hash value for a given key. */
/* Don't try to use addresses here, call-id should be almost unique. */
static guint sip_hash_func(gconstpointer v)
{
	gint n;
	const sip_hash_key *key = v;
	guint value = strlen(key->call_id);
	gint chars_to_use = value / 4;

	/* First few characters from the call-id should be enough... */
	for (n=0; n < chars_to_use; n++)
	{
		value += key->call_id[n];
	}

	return value;
}


/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in wireshark */
static void
sip_init_protocol(void)
{
	/* Destroy any existing hashes. */
	if (sip_hash)
		g_hash_table_destroy(sip_hash);

	/* Now create them over */
	sip_hash = g_hash_table_new(sip_hash_func, sip_equal);
}

/*
 * Copied from the mgcp dissector. (This function should be moved to /epan )
 * tvb_skip_wsp - Returns the position in tvb of the first non-whitespace
 *                character following offset or offset + maxlength -1 whichever
 *                is smaller.
 *
 * Parameters:
 * tvb - The tvbuff in which we are skipping whitespace.
 * offset - The offset in tvb from which we begin trying to skip whitespace.
 * maxlength - The maximum distance from offset that we may try to skip
 * whitespace.
 *
 * Returns: The position in tvb of the first non-whitespace
 *          character following offset or offset + maxlength -1 whichever
 *          is smaller.
 */
static gint tvb_skip_wsp(tvbuff_t* tvb, gint offset, gint maxlength)
{
	gint counter = offset;
	gint end = offset + maxlength,tvb_len;
	guint8 tempchar;

	/* Get the length remaining */
	tvb_len = tvb_length(tvb);
	end = offset + maxlength;
	if (end >= tvb_len)
	{
		end = tvb_len;
	}

	/* Skip past spaces, tabs, CRs and LFs until run out or meet something else */
	for (counter = offset;
	     counter < end &&
	      ((tempchar = tvb_get_guint8(tvb,counter)) == ' ' ||
	      tempchar == '\t' || tempchar == '\r' || tempchar == '\n');
	     counter++);

	return (counter);
}

/* Structure to collect info about a sip uri */
typedef struct _uri_offset_info
{
	gint display_name_start;
	gint display_name_end;
	gint uri_start;
	gint uri_end;
	gint uri_parameters_start;
	gint uri_parameters_end;
	gint name_addr_start;
	gint name_addr_end;
} uri_offset_info;

/* Code to parse a sip uri.
 * Returns Offset end off parsing or -1 for unsuccessful parsing
 */
static gint
dissect_sip_uri(tvbuff_t *tvb, packet_info *pinfo _U_, gint start_offset,
                gint line_end_offset, uri_offset_info *uri_offsets)
{
	gchar c;
	gint i;
	gint current_offset;
	gint queried_offset;
	gint colon_offset;
	gint comma_offset;
	gint semicolon_offset;
	gint question_mark_offset;
	gboolean uri_without_angle_quotes = FALSE;

	/* skip Spaces and Tabs */
	current_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

	if(current_offset >= line_end_offset) {
		/* Nothing to parse */
		return -1;
	}

	uri_offsets->name_addr_start = current_offset;

	/* First look, if we have a display name */
	c=tvb_get_guint8(tvb, current_offset);
	switch(c)
	{
		case '"':
			/* We have a display name, look for the next unescaped '"' */
			uri_offsets->display_name_start = current_offset;
			do
			{
				queried_offset = tvb_find_guint8(tvb, current_offset + 1, line_end_offset - (current_offset + 1), '"');
				if(queried_offset == -1)
				{
					/* malformed URI */
					return -1;
				}
				current_offset = queried_offset;

				/* Is it escaped? */
				/* count back slashes before '"' */
				for(i=1;tvb_get_guint8(tvb, queried_offset - i) == '\\';i++);
				i--;

				if(i % 2 == 0)
				{
					/* not escaped */
					break;
				}
			} while (current_offset < line_end_offset);
			if(current_offset >= line_end_offset)
			{
				/* malformed URI */
				return -1;
			}

			uri_offsets->display_name_end = current_offset;

			/* find start of the URI */
			queried_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, '<');
			if(queried_offset == -1)
			{
				/* malformed Uri */
				return -1;
			}
			current_offset = queried_offset + 1;
			break;

		case '<':
			/* We don't have a display name */
			current_offset++;
			break;

		default:
			/* We have either an URI without angles or a display name with a limited character set */
			/* Look for the right angle quote or colon */
			queried_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, '<');
			colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ':');
			if(queried_offset != -1 && colon_offset != -1)
			{
				if(queried_offset < colon_offset)
				{
					/* we have an URI with angle quotes */
					uri_offsets->display_name_start = current_offset;
					uri_offsets->display_name_end = queried_offset - 1;
					current_offset = queried_offset + 1;
				}
				else
				{
					/* we have an URI without angle quotes */
					uri_without_angle_quotes = TRUE;
				}
			}
			else
			{
				if(queried_offset != -1)
				{
					/* we have an URI with angle quotes */
					uri_offsets->display_name_start = current_offset;
					uri_offsets->display_name_end = queried_offset - 1;
					current_offset = queried_offset + 1;
					break;
				}
				if(colon_offset != -1)
				{
					/* we have an URI without angle quotes */
					uri_without_angle_quotes = TRUE;
					break;
				}
				/* If this point is reached, we can't parse the URI */
				return -1;
			}
			break;
	}

	/* Start parsing of URI */
	uri_offsets->uri_start = current_offset;
	if(uri_without_angle_quotes == TRUE)
	{
		/* look for the first ',' or ';' which will mark the end of this URI
		 * In this case a semicolon indicates a header field parameter, and not an uri parameter.
		 */
		comma_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ',');
		semicolon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ';');

		if (semicolon_offset != -1 && comma_offset != -1)
		{
			if(semicolon_offset < comma_offset)
			{
				uri_offsets->uri_end = semicolon_offset - 1;
			}
			else
			{
				uri_offsets->uri_end = comma_offset - 1;
			}
		}
		else
		{
			if (semicolon_offset != -1)
			{
				uri_offsets->uri_end = semicolon_offset - 1;
			}
			if (comma_offset != -1)
			{
				uri_offsets->uri_end = comma_offset - 1;
			}
			/* If both offsets are equal to -1, we don't have a semicolon or a comma.
			 * In that case, we assume that the end of the URI is at the line end
			 */
			uri_offsets->uri_end = line_end_offset - 2;
		}
		uri_offsets->name_addr_end = uri_offsets->uri_end;
		current_offset = uri_offsets->uri_end + 1; /* Now save current_offset, as it is the value to be returned now */
	}
	else
	{
		/* look for closing angle quote */
		queried_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, '>');
		if(queried_offset == -1)
		{
			/* malformed Uri */
			return -1;
		}
		uri_offsets->name_addr_end = queried_offset;
		uri_offsets->uri_end = queried_offset - 1;
		current_offset = queried_offset; /* Now save current_offset. It contains the value we have to return */

		/* Look for '@' within URI */
		queried_offset = tvb_find_guint8(tvb, uri_offsets->uri_start, uri_offsets->uri_end - uri_offsets->uri_start, '@');
		if(queried_offset == -1)
		{
			/* no '@': look for the first ';' or '?' in the URI */
			question_mark_offset = tvb_find_guint8(tvb, uri_offsets->uri_start, uri_offsets->uri_end - uri_offsets->uri_start, '?');
			semicolon_offset = tvb_find_guint8(tvb, uri_offsets->uri_start, uri_offsets->uri_end - uri_offsets->uri_start, ';');
		}
		else
		{
			/* with '@': look for the first ';' or '?' behind the '@' */
			question_mark_offset = tvb_find_guint8(tvb, queried_offset, uri_offsets->uri_end - queried_offset, '?');
			semicolon_offset = tvb_find_guint8(tvb, queried_offset, uri_offsets->uri_end - queried_offset, ';');
		}

		/* Set Parameter*/
		if (semicolon_offset != -1 && question_mark_offset != -1)
		{
			if(semicolon_offset < question_mark_offset)
			{
				uri_offsets->uri_parameters_start = semicolon_offset;
			}
			else
			{
				uri_offsets->uri_parameters_start = question_mark_offset;
			}
			uri_offsets->uri_parameters_end = uri_offsets->uri_end;
			uri_offsets->uri_end = uri_offsets->uri_parameters_start - 1;
		}
		else
		{
			if (semicolon_offset != -1)
			{
				uri_offsets->uri_parameters_start = semicolon_offset;
				uri_offsets->uri_parameters_end = uri_offsets->uri_end;
				uri_offsets->uri_end = uri_offsets->uri_parameters_start - 1;
			}
			if (question_mark_offset != -1)
			{
				uri_offsets->uri_parameters_start = question_mark_offset;
				uri_offsets->uri_parameters_end = uri_offsets->uri_end;
				uri_offsets->uri_end = uri_offsets->uri_parameters_start - 1;
			}
			/* If both offsets are equal to -1, we don't have a semicolon or a question mark.
			 * In that case, we don't have to save any offsets.
			 */
		}

	}

	return current_offset;
}


/* Code to parse a contact header item
 * Returns Offset end off parsing or -1 for unsuccessful parsing
 */
static gint
dissect_sip_contact_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint start_offset, gint line_end_offset)
{
	gchar c;
	gint i;
	proto_item *ti = NULL;
	proto_tree *contact_item_tree = NULL, *uri_tree = NULL;

	gint current_offset;
	gint queried_offset;
	gint contact_params_start_offset = -1;
	gint contact_item_end_offset = -1;
	uri_offset_info uri_offsets;

	uri_offsets.display_name_start = -1;
	uri_offsets.display_name_end = -1;
	uri_offsets.uri_start = -1;
	uri_offsets.uri_end = -1;
	uri_offsets.uri_parameters_start = -1;
	uri_offsets.uri_parameters_end = -1;
	uri_offsets.name_addr_start = -1;
	uri_offsets.name_addr_end = -1;

	/* skip Spaces and Tabs */
	start_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

	if(start_offset >= line_end_offset) {
		/* Nothing to parse */
		return -1;
	}

	current_offset = dissect_sip_uri(tvb, pinfo, start_offset, line_end_offset, &uri_offsets);
	if(current_offset == -1)
	{
		/* Parsing failed */
		return -1;
	}

	/* Now look for the end of the contact item */
	while (current_offset < line_end_offset)
	{
		c=tvb_get_guint8(tvb, current_offset);

		if(c == ';' && contact_params_start_offset == -1)
		{
			/* here we start with contact parameters */
			contact_params_start_offset = current_offset;
		}

		if(c == '"')
		{
			/* look for the next unescaped '"' */
			do
			{
				queried_offset = tvb_find_guint8(tvb, current_offset + 1, line_end_offset - (current_offset + 1), '"');
				if(queried_offset == -1)
				{
					/* malformed Contact header */
					return -1;
				}
				current_offset = queried_offset;

				/* Is it escaped?
				 * Look for uneven number of backslashes before '"' */
				for(i=0;tvb_get_guint8(tvb, queried_offset - (i+1) ) == '\\';i++);
				i=i%2;
			} while (i == 1);
		}

		if(c == ',')
		{
			/* end of contact item found. */
			contact_item_end_offset = current_offset - 1; /* remove ',' */
			break;
		}

		current_offset++;
	}

	if(contact_item_end_offset == -1)
		contact_item_end_offset = line_end_offset - 3;  /* remove '\r\n' */

	/* Build the tree, now */
	if(tree)
	{
		ti = proto_tree_add_string(tree, hf_sip_contact_item, tvb, start_offset, contact_item_end_offset - start_offset + 1,
		                           tvb_format_text(tvb, start_offset, contact_item_end_offset - start_offset + 1));
		contact_item_tree = proto_item_add_subtree(ti, ett_sip_contact_item);

		ti = proto_tree_add_string(contact_item_tree, hf_sip_uri, tvb, uri_offsets.name_addr_start, uri_offsets.name_addr_end - uri_offsets.name_addr_start + 1,
		                           tvb_format_text(tvb, uri_offsets.name_addr_start, uri_offsets.name_addr_end - uri_offsets.name_addr_start + 1));
		uri_tree = proto_item_add_subtree(ti, ett_sip_uri);

		if(uri_offsets.display_name_start != -1 && uri_offsets.display_name_end != -1)
		{
			proto_tree_add_string(uri_tree, hf_sip_display, tvb, uri_offsets.display_name_start,
			                      uri_offsets.display_name_end - uri_offsets.display_name_start + 1,
			                      tvb_format_text(tvb, uri_offsets.display_name_start,
			                                      uri_offsets.display_name_end - uri_offsets.display_name_start + 1));
		}

		if(uri_offsets.uri_start != -1 && uri_offsets.uri_end != -1)
		{
			proto_tree_add_string(uri_tree, hf_sip_contact_addr, tvb, uri_offsets.uri_start,
			                      uri_offsets.uri_end - uri_offsets.uri_start + 1,
			                      tvb_format_text(tvb, uri_offsets.uri_start,
			                                      uri_offsets.uri_end - uri_offsets.uri_start + 1));
		}

		/* Parse URI and Contact header Parameters now */
		/* TODO */
	}

	return current_offset;
}

/* Code to parse an authorization header item
 * Returns offset at end of parsing, or -1 for unsuccessful parsing
 */
static gint
dissect_sip_authorization_item(tvbuff_t *tvb, proto_tree *tree, gint start_offset, gint line_end_offset)
{
	gchar c;
	gint current_offset;
	gint equals_offset = 0;
	gchar *name;
	auth_parameter_t *auth_parameter;
	guint i = 0;
	gboolean in_quoted_string = FALSE;

	/* skip Spaces and Tabs */
	start_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

	if (start_offset >= line_end_offset)
	{
		/* Nothing to parse */
		return -1;
	}

	current_offset = start_offset;

	/* Now look for the end of the parameter */
	while (current_offset < line_end_offset)
	{
		c = tvb_get_guint8(tvb, current_offset);

		if (c == '=')
		{
			equals_offset = current_offset;
		}

		if(c == '"')
		{
			/* look for the next unescaped '"' */
			do
			{
				current_offset = tvb_find_guint8(tvb, current_offset + 1, line_end_offset - (current_offset + 1), '"');
				if(current_offset == -1)
				{
					/* malformed parameter */
					return -1;
				}

				/* Is it escaped?
				 * Look for uneven number of backslashes before '"' */
				for(i=0;tvb_get_guint8(tvb, current_offset - (i+1) ) == '\\';i++);
				i=i%2;
			} while (i == 1);
			current_offset++;
			current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);
			continue;
		}

		if (c == ',')
		{
			break;
		}
		current_offset++;
	}

	if (equals_offset == 0)
	{
		/* Give up if equals not found */
		return -1;
	}

	/* Extract the parameter name */
	name = tvb_get_ephemeral_string(tvb, start_offset, equals_offset-start_offset);

	/* Try to add parameter as a filterable item */
	for (auth_parameter = &auth_parameters_hf_array[i];
	     i < array_length(auth_parameters_hf_array);
	     i++, auth_parameter++)
	{
		if (strcasecmp(name, auth_parameter->param_name) == 0)
		{
			proto_tree_add_item(tree, *(auth_parameter->hf_item), tvb,
			                    equals_offset+1, current_offset-equals_offset-1,
			                    FALSE);
			break;
		}
	}

	/* If not matched, just add as text... */
	if (i == array_length(auth_parameters_hf_array))
	{
		proto_tree_add_text(tree, tvb, start_offset, current_offset-start_offset,
		                    "%s", tvb_format_text(tvb, start_offset,
		                                    current_offset-start_offset));
	}

	return current_offset;
}


/* Code to actually dissect the packets */
static int
dissect_sip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 octet;
	int len;

	octet = tvb_get_guint8(tvb,0);
	if ((octet  & 0xf8) == 0xf8){
		call_dissector(sigcomp_handle, tvb, pinfo, tree);
		return tvb_length(tvb);
	}

	len = dissect_sip_common(tvb, 0, pinfo, tree, FALSE, FALSE);
	if (len < 0)
		return 0;	/* not SIP */
	else
		return len;
}

static void
dissect_sip_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8 octet;
	int offset = 0;
	int len;

	octet = tvb_get_guint8(tvb,0);
	if ((octet  & 0xf8) == 0xf8){
		call_dissector(sigcomp_handle, tvb, pinfo, tree);
		return;
	}

	while (tvb_reported_length_remaining(tvb, offset) != 0) {
		len = dissect_sip_common(tvb, offset, pinfo, tree, TRUE, TRUE);
		if (len <= 0)
			break;
		offset += len;
	}
}

static gboolean
dissect_sip_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	int len;
	gboolean first = TRUE;

	while (tvb_reported_length_remaining(tvb, offset) != 0) {
		len = dissect_sip_common(tvb, offset, pinfo, tree, !first, TRUE);
		if (len == -2) {
			if (first) {
				/*
				 * If the first packet doesn't start with
				 * a valid SIP request or response, don't
				 * treat this as SIP.
				 */
				return FALSE;
			}
			break;
		}
		if (len == -1)
			break;	/* need more data */
		offset += len;
	}
	return TRUE;
}

static gboolean
dissect_sip_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	return dissect_sip_common(tvb, 0, pinfo, tree, FALSE, FALSE) > 0;
}

static int
dissect_sip_common(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
    gboolean dissect_other_as_continuation, gboolean use_reassembly)
{
	int orig_offset;
	gint next_offset, linelen;
	int content_length, datalen, reported_datalen;
	line_type_t line_type;
	tvbuff_t *next_tvb;
	gboolean is_known_request;
	gboolean found_match = FALSE;
	const char *descr;
	guint token_1_len = 0;
	guint current_method_idx = 0;
	proto_item *ts = NULL, *ti = NULL, *th = NULL, *sip_element_item = NULL;
	proto_tree *sip_tree = NULL, *reqresp_tree = NULL , *hdr_tree = NULL, *sip_element_tree = NULL, *message_body_tree = NULL, *cseq_tree = NULL;
	guchar contacts = 0, contact_is_star = 0, expires_is_0 = 0;
	guint32 cseq_number = 0;
	guchar  cseq_number_set = 0;
	char    cseq_method[MAX_CSEQ_METHOD_SIZE] = "";
	char	call_id[MAX_CALL_ID_SIZE] = "";
	char *media_type_str = NULL;
	char *media_type_str_lower_case = NULL;
	char *content_type_parameter_str = NULL;
	guint resend_for_packet = 0;
	int strlen_to_copy;

	/* Initialise stat info for passing to tap */
	stat_info = ep_alloc(sizeof(sip_info_value_t));
	stat_info->response_code = 0;
	stat_info->request_method = NULL;
	stat_info->reason_phrase = NULL;
	stat_info->resend = 0;
	stat_info->tap_call_id = NULL;
	stat_info->tap_from_addr = NULL;
	stat_info->tap_to_addr = NULL;

	/*
	 * Note that "tvb_find_line_end()" will return a value that
	 * is not longer than what's in the buffer, so the
	 * "tvb_get_ptr()" calls below won't throw exceptions.
	 *
	 * Note that "tvb_strneql()" doesn't throw exceptions, so
	 * "sip_parse_line()" won't throw an exception.
	 */
	orig_offset = offset;
	linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
	if (tvb_strnlen(tvb, offset, linelen) > -1)
	{
		/*
		 * There's a NULL in the line,
		 * this may be SIP within another protocol.
		 * This heuristic still needs to improve.
		 */
		return -2;
	}
	line_type = sip_parse_line(tvb, offset, linelen, &token_1_len);
	if (line_type == OTHER_LINE) {
		/*
		 * This is neither a SIP request nor response.
		 */
		if (!dissect_other_as_continuation) {
			/*
			 * We were asked to reject this.
			 */
			return -2;
		}

		/*
		 * Just dissect it as a continuation.
		 */
	} else if (use_reassembly) {

		/*
		 * Yes, it's a request or response.
		 * Do header desegmentation if we've been told to,
		 * and do body desegmentation if we've been told to and
		 * we find a Content-Length header.
		 */
		if (!req_resp_hdrs_do_reassembly(tvb, offset, pinfo,
		    sip_desegment_headers, sip_desegment_body)) {
			/*
			 * More data needed for desegmentation.
			 */
			return -1;
		}
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIP");

	switch (line_type) {

	case REQUEST_LINE:
		is_known_request = sip_is_known_request(tvb, offset, token_1_len, &current_method_idx);
		descr = is_known_request ? "Request" : "Unknown request";
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
			             descr,
			             tvb_format_text(tvb, offset, linelen - SIP2_HDR_LEN - 1));
		}
		break;

	case STATUS_LINE:
		descr = "Status";
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_fstr(pinfo->cinfo, COL_INFO, "Status: %s",
			             tvb_format_text(tvb, offset + SIP2_HDR_LEN + 1, linelen - SIP2_HDR_LEN - 1));
		}
		stat_info->reason_phrase = tvb_get_ephemeral_string(tvb, offset + SIP2_HDR_LEN + 5, linelen - (SIP2_HDR_LEN + 5));
		break;

	case OTHER_LINE:
	default: /* Squelch compiler complaints */
		descr = "Continuation";
		if (check_col(pinfo->cinfo, COL_INFO))
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
		break;
	}

	if (tree) {
		ts = proto_tree_add_item(tree, proto_sip, tvb, offset, -1, FALSE);
		sip_tree = proto_item_add_subtree(ts, ett_sip);
	}

	switch (line_type) {

	case REQUEST_LINE:
		if (sip_tree) {
			ti = proto_tree_add_string(sip_tree, hf_Request_Line, tvb, offset, linelen,
			                           tvb_format_text(tvb, offset, linelen));
			reqresp_tree = proto_item_add_subtree(ti, ett_sip_reqresp);
		}
		dfilter_sip_request_line(tvb, reqresp_tree, token_1_len);
		break;

	case STATUS_LINE:
		if (sip_tree) {
			ti = proto_tree_add_string(sip_tree, hf_Status_Line, tvb, offset, linelen,
			                           tvb_format_text(tvb, offset, linelen));
			reqresp_tree = proto_item_add_subtree(ti, ett_sip_reqresp);
		}
		dfilter_sip_status_line(tvb, reqresp_tree);
		break;

	case OTHER_LINE:
		if (sip_tree) {
			ti = proto_tree_add_text(sip_tree, tvb, offset, next_offset,
			                         "%s line: %s", descr,
			                         tvb_format_text(tvb, offset, linelen));
			reqresp_tree = proto_item_add_subtree(ti, ett_sip_reqresp);
			proto_tree_add_text(sip_tree, tvb, offset, -1,
			                    "Continuation data");
		}
		return tvb_length_remaining(tvb, offset);
	}

	offset = next_offset;
	if (sip_tree) {
		th = proto_tree_add_item(sip_tree, hf_msg_hdr, tvb, offset, -1, FALSE);
		hdr_tree = proto_item_add_subtree(th, ett_sip_hdr);
	}

	/*
	 * Process the headers - if we're not building a protocol tree,
	 * we just do this to find the blank line separating the
	 * headers from the message body.
	 */
	next_offset = offset;
	content_length = -1;
	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		gint line_end_offset;
		gint colon_offset;
		gint semi_colon_offset;
		gint len;
		gint parameter_offset;
		gint parameter_end_offset;
		gint parameter_len;
		gint content_type_len, content_type_parameter_str_len;
		gint header_len;
		gint hf_index;
		gint value_offset;
		gint sub_value_offset;
		gint comma_offset;
		guchar c;
		size_t value_len;
		char *value;

		linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
		if (linelen == 0) {
			/*
			 * This is a blank line separating the
			 * message header from the message body.
			 */
			offset = next_offset;
			break;
		}

		line_end_offset = offset + linelen;
		while ((c = tvb_get_guint8(tvb, next_offset)) == ' ' || c == '\t')
		{
			/*
			 * This line end is not a header seperator.
			 * It just extends the header with another line.
			 * Look for next line end:
			 */
			linelen += (next_offset - line_end_offset);
			linelen += tvb_find_line_end(tvb, next_offset, -1, &next_offset, FALSE);
			line_end_offset = offset + linelen;
		}

		colon_offset = tvb_find_guint8(tvb, offset, linelen, ':');
		if (colon_offset == -1) {
			/*
			 * Malformed header - no colon after the name.
			 */
			if(hdr_tree) {
				proto_tree_add_text(hdr_tree, tvb, offset,
				                    next_offset - offset, "%s",
				                    tvb_format_text(tvb, offset, linelen));
			}
		} else {
			header_len = colon_offset - offset;
			hf_index = sip_is_known_sip_header(tvb, offset, header_len);

			if (hf_index == -1) {
				if(hdr_tree) {
					proto_item *ti = proto_tree_add_text(hdr_tree, tvb,
					                                     offset, next_offset - offset, "%s",
					                                     tvb_format_text(tvb, offset, linelen));
					expert_add_info_format(pinfo, ti,
					                       PI_UNDECODED, PI_NOTE,
					                       "Unrecognised SIP header (%s)",
					                       tvb_format_text(tvb, offset, header_len));
				}
			} else {
				/*
				 * Skip whitespace after the colon.
				 */
				value_offset = tvb_skip_wsp(tvb, colon_offset + 1, line_end_offset - (colon_offset + 1));

				/*
				 * Fetch the value.
				 */
				value_len = line_end_offset - value_offset;
				value = tvb_get_ephemeral_string(tvb, value_offset,
				                       value_len);

				/*
				 * Add it to the protocol tree,
				 * but display the line as is.
				 */
				switch ( hf_index ) {

					case POS_TO :
						if(hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   value, "%s",
							                   tvb_format_text(tvb, offset, linelen));
							sip_element_tree = proto_item_add_subtree( sip_element_item,
							                   ett_sip_element);
						}
						/* See if we have a SIP/SIPS uri enclosed in <>, if so anything in front is
						 * display info.
						 */
						parameter_offset = tvb_find_guint8(tvb, value_offset,value_len, '<');
						if ( parameter_offset != -1){
							len = parameter_offset - value_offset;
							if ( len > 1){
								/* Something in front, must be display info
								 * TODO: Get rid of trailing space(s)
								 */
								proto_tree_add_item(sip_element_tree, hf_sip_display, tvb, value_offset,
								                    len, FALSE);
							}
							parameter_offset ++;
							parameter_end_offset = parameter_offset;
							/* RFC3261 paragraph 20
							 * The Contact, From, and To header fields contain a URI.  If the URI
							 * contains a comma, question mark or semicolon, the URI MUST be
							 * enclosed in angle brackets (< and >).  Any URI parameters are
							 * contained within these brackets.  If the URI is not enclosed in angle
							 * brackets, any semicolon-delimited parameters are header-parameters,
							 * not URI parameters.
							 */
							while (parameter_end_offset < line_end_offset){
								parameter_end_offset++;
								c = tvb_get_guint8(tvb, parameter_end_offset);
								switch (c) {
									case '>':
									case ',':
									case ';':
									case '?':
										goto separator_found;
									default :
									break;
								}
							}
separator_found:
							parameter_len = parameter_end_offset - parameter_offset;
							proto_tree_add_item(sip_element_tree, hf_sip_to_addr, tvb, parameter_offset,
							                    parameter_len, FALSE);
							/*info for the tap for voip_calls.c*/
							stat_info->tap_to_addr=tvb_get_ephemeral_string(tvb, parameter_offset, parameter_len);

							parameter_offset = parameter_end_offset + 1;
							/*
							 * URI parameters ?
							 */
							parameter_end_offset = tvb_find_guint8(tvb, parameter_offset,( line_end_offset - parameter_offset), ';');
							if ( parameter_end_offset == -1)
								parameter_end_offset = line_end_offset;

							offset = parameter_end_offset;
						}
						else
						{
							/* Extract SIP/SIPS URI */
							parameter_offset = value_offset;
							while (parameter_offset < line_end_offset
							       && (tvb_strneql(tvb, parameter_offset, "sip", 3) != 0))
								parameter_offset++;
							len = parameter_offset - value_offset;
							if ( len > 1){
								/* Something in front, must be display info
								 * TODO: Get rid of trailing space(s)
								 */
								proto_tree_add_item(sip_element_tree, hf_sip_display, tvb, value_offset,
								                    len, FALSE);
							}
							parameter_end_offset = tvb_find_guint8(tvb, parameter_offset,
							                                       (line_end_offset - parameter_offset), ';');
							if ( parameter_end_offset == -1)
								parameter_end_offset = line_end_offset;
							parameter_len = parameter_end_offset - parameter_offset;
							proto_tree_add_item(sip_element_tree, hf_sip_to_addr, tvb, parameter_offset,
							                    parameter_len, FALSE);
							/*info for the tap for voip_calls.c*/
							stat_info->tap_to_addr=tvb_get_ephemeral_string(tvb, parameter_offset, parameter_len);
							offset = parameter_end_offset;
						}
						/* Find parameter tag if present.
						 * TODO make this generic to find any interesting parameter
						 * use the same method as for SIP headers ?
						 */

						parameter_offset = offset;
						while (parameter_offset < line_end_offset
						       && (tvb_strneql(tvb, parameter_offset, "tag=", 4) != 0))
							parameter_offset++;
						if ( parameter_offset < line_end_offset ){ /* Tag found */
							parameter_offset = parameter_offset + 4;
							parameter_end_offset = tvb_find_guint8(tvb, parameter_offset,
							                                       (line_end_offset - parameter_offset), ';');
							if ( parameter_end_offset == -1)
								parameter_end_offset = line_end_offset;
							parameter_len = parameter_end_offset - parameter_offset;
							proto_tree_add_item(sip_element_tree, hf_sip_tag, tvb, parameter_offset,
							                    parameter_len, FALSE);

						}
					break;

					case POS_FROM :
						if(hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   value, "%s",
							                   tvb_format_text(tvb, offset, linelen));
							sip_element_tree = proto_item_add_subtree( sip_element_item, ett_sip_element);
						}
						/* See if we have a SIP/SIPS uri enclosed in <>, if so anything in front is
						 * display info.
						 */
						parameter_offset = tvb_find_guint8(tvb, value_offset,value_len, '<');
						if ( parameter_offset != -1){
							len = parameter_offset - value_offset;
							if ( len > 1){
								/* Something in front, must be display info
								 * TODO: Get rid of trailing space(s)
								 */
								proto_tree_add_item(sip_element_tree, hf_sip_display, tvb, value_offset,
								                    len, FALSE);
							}
							parameter_offset ++;
							parameter_end_offset = parameter_offset;
							/* RFC3261 paragraph 20
							 * The Contact, From, and To header fields contain a URI.  If the URI
							 * contains a comma, question mark or semicolon, the URI MUST be
							 * enclosed in angle brackets (< and >).  Any URI parameters are
							 * contained within these brackets.  If the URI is not enclosed in angle
							 * brackets, any semicolon-delimited parameters are header-parameters,
							 * not URI parameters.
							 */
							while (parameter_end_offset < line_end_offset){
								parameter_end_offset++;
								c = tvb_get_guint8(tvb, parameter_end_offset);
								switch (c) {
									case '>':
									case ',':
									case ';':
									case '?':
										goto separator_found2;
									default :
									break;
								}
							}
separator_found2:
							parameter_len = parameter_end_offset - parameter_offset;
							dfilter_store_sip_from_addr(tvb, sip_element_tree,
							                            parameter_offset, parameter_len);
							/*info for the tap for voip_calls.c*/
							stat_info->tap_from_addr=tvb_get_ephemeral_string(tvb, parameter_offset, parameter_len);
							parameter_offset = parameter_end_offset + 1;
							/*
							 * URI parameters ?
							 */
							parameter_end_offset = tvb_find_guint8(tvb, parameter_offset,( line_end_offset - parameter_offset), ';');
							if ( parameter_end_offset == -1)
								parameter_end_offset = line_end_offset;

							offset = parameter_end_offset;
						}
						else
						{
							/* Extract SIP/SIPS URI */
							parameter_offset = value_offset;
							while (parameter_offset < line_end_offset
							       && (tvb_strneql(tvb, parameter_offset, "sip", 3) != 0))
								parameter_offset++;
							len = parameter_offset - value_offset;
							if ( len > 1){
								/* Something in front, must be display info
								 * TODO: Get rid of trailing space(s)
								 */
								proto_tree_add_item(sip_element_tree, hf_sip_display, tvb, value_offset,
								                    len, FALSE);
							}
							parameter_end_offset = tvb_find_guint8(tvb, parameter_offset,
							                                       (line_end_offset - parameter_offset), ';');
							if ( parameter_end_offset == -1)
								parameter_end_offset = line_end_offset;
							parameter_len = parameter_end_offset - parameter_offset;
							proto_tree_add_item(sip_element_tree, hf_sip_from_addr, tvb, parameter_offset,
							                    parameter_len, FALSE);
							/*info for the tap for voip_calls.c*/
							stat_info->tap_from_addr=tvb_get_ephemeral_string(tvb, parameter_offset, parameter_len);
							offset = parameter_end_offset;
						}
						/* Find parameter tag if present.
						 * TODO make this generic to find any interesting parameter
						 * use the same method as for SIP headers ?
						 */

						parameter_offset = offset;
						while (parameter_offset < line_end_offset
						       && (tvb_strneql(tvb, parameter_offset, "tag=", 4) != 0))
							parameter_offset++;
						if ( parameter_offset < line_end_offset ){ /* Tag found */
							parameter_offset = parameter_offset + 4;
							parameter_end_offset = tvb_find_guint8(tvb, parameter_offset,
							                                       (line_end_offset - parameter_offset), ';');
							if ( parameter_end_offset == -1)
								parameter_end_offset = line_end_offset;
							parameter_len = parameter_end_offset - parameter_offset;
							proto_tree_add_item(sip_element_tree, hf_sip_tag, tvb, parameter_offset,
							                    parameter_len, FALSE);

						}
					break;

					case POS_CSEQ :
						/* Store the sequence number */
						cseq_number = atoi(value);
						cseq_number_set = 1;
						stat_info->tap_cseq_number=cseq_number;

						/* Add CSeq  tree */
						if (hdr_tree) {
							ti = proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
							cseq_tree = proto_item_add_subtree(ti, ett_sip_cseq);
						}

						/* Walk past number and spaces characters to get to start
						   of method name */
						for (sub_value_offset=0; sub_value_offset < (gint)strlen(value); sub_value_offset++)
						{
							if (!isdigit((guchar)value[sub_value_offset]))
							{
								proto_tree_add_uint(cseq_tree, hf_sip_cseq_seq_no,
								                    tvb, value_offset, sub_value_offset,
								                    cseq_number);
								break;
							}
						}

						for (; sub_value_offset < (gint)strlen(value); sub_value_offset++)
						{
							if (isalpha((guchar)value[sub_value_offset]))
							{
								/* Have reached start of method name */
								break;
							}
						}

						if (sub_value_offset == (gint)strlen(value))
						{
							/* Didn't find method name */
							THROW(ReportedBoundsError);
							return offset - orig_offset;
						}

						/* Extract method name from value */
						strlen_to_copy = strlen(value)-sub_value_offset;
						if (strlen_to_copy > MAX_CSEQ_METHOD_SIZE) {
							/* Note the error in the protocol tree */
							if (hdr_tree) {
								proto_tree_add_string_format(hdr_tree,
								                             hf_header_array[hf_index], tvb,
								                             offset, next_offset - offset,
								                             value+sub_value_offset, "%s String too big: %d bytes",
								                             sip_headers[POS_CSEQ].name,
								                             strlen_to_copy);
							}
							THROW(ReportedBoundsError);
							return offset - orig_offset;
						}
						else {
							strncpy(cseq_method, value+sub_value_offset, MIN(strlen_to_copy, MAX_CSEQ_METHOD_SIZE));

							/* Add CSeq method to the tree */
							if (cseq_tree)
							{
								proto_tree_add_item(cseq_tree, hf_sip_cseq_method, tvb,
								                    value_offset + sub_value_offset, strlen_to_copy, FALSE);
							}
						}
					break;

					case POS_CALL_ID :
						/* Store the Call-id */
						strncpy(call_id, value,
						        strlen(value)+1 < MAX_CALL_ID_SIZE ?
						        strlen(value)+1 :
						        MAX_CALL_ID_SIZE);
						stat_info->tap_call_id = ep_strdup(call_id);

						/* Add 'Call-id' string item to tree */
						if(hdr_tree) {
							proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
						}
					break;

					case POS_EXPIRES :
						if (strcmp(value, "0") == 0)
						{
							expires_is_0 = 1;
						}
						/* Add 'Expires' string item to tree */
						if(hdr_tree) {
							proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
						}
					break;

					/*
					 * Content-Type is the same as Internet
					 * media type used by other dissectors,
					 * appropriate dissector found by
					 * lookup in "media_type" dissector table.
					 */
					case POS_CONTENT_TYPE :
						if(hdr_tree) {
							proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
						}
						content_type_len = value_len;
						semi_colon_offset = tvb_find_guint8(tvb, value_offset, value_len, ';');
						if ( semi_colon_offset != -1) {
							/*
							 * Skip whitespace after the semicolon.
							 */
							parameter_offset = tvb_skip_wsp(tvb, semi_colon_offset +1, value_offset + value_len - (semi_colon_offset +1));

							content_type_len = semi_colon_offset - value_offset;
							content_type_parameter_str_len = value_offset + value_len - parameter_offset;
							content_type_parameter_str = tvb_get_ephemeral_string(tvb, parameter_offset,
							                             content_type_parameter_str_len);
						}
						media_type_str = tvb_get_ephemeral_string(tvb, value_offset, content_type_len);
#if GLIB_MAJOR_VERSION < 2
						media_type_str_lower_case = ep_strdup(media_type_str);
						g_strdown(media_type_str_lower_case);
#else
						media_type_str_lower_case = g_ascii_strdown(media_type_str, -1);
#endif
					break;

					case POS_CONTENT_LENGTH :
						content_length = atoi(value);
						if(hdr_tree) {
							proto_tree_add_uint(hdr_tree,
							                    hf_header_array[hf_index], tvb,
							                    offset, next_offset - offset,
							                    content_length);
						}
						break;

					case POS_MAX_FORWARDS :
						if(hdr_tree) {
							proto_tree_add_uint(hdr_tree,
							                    hf_header_array[hf_index], tvb,
							                    offset, next_offset - offset,
							                    atoi(value));
						}
						break;

					case POS_CONTACT :
						if(hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   value, "%s",
							                   tvb_format_text(tvb, offset, linelen));
							sip_element_tree = proto_item_add_subtree( sip_element_item,
							                   ett_sip_element);
						}
						if (strcmp(value, "*") == 0)
						{
							contact_is_star = 1;
							break;
						}

						comma_offset = value_offset;
						while((comma_offset = dissect_sip_contact_item(tvb, pinfo, sip_element_tree, comma_offset, next_offset)) != -1)
						{
							contacts++;
							if(comma_offset == next_offset)
							{
								/* Line End reached: Stop Parsing */
								break;
							}

							if(tvb_get_guint8(tvb, comma_offset) != ',')
							{
								/* Undefined value reached: Stop Parsing */
								break;
							}
							comma_offset++; /* skip comma */
						}
					break;

					case POS_AUTHORIZATION:
					case POS_WWW_AUTHENTICATE:
					case POS_PROXY_AUTHENTICATE:
					case POS_PROXY_AUTHORIZATION:
					case POS_AUTHENTICATION_INFO:
						/* Add tree using whole text of line */
						if (hdr_tree) {
							proto_item *ti;
							/* Add whole line as header tree */
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   value, "%s",
							                   tvb_format_text(tvb, offset, linelen));
							sip_element_tree = proto_item_add_subtree( sip_element_item,
							                   ett_sip_element);

							/* Set sip.auth as a hidden field/filter */
							ti = proto_tree_add_item(hdr_tree, hf_sip_auth, tvb,
							                         offset, next_offset-offset,
							                         FALSE);
							PROTO_ITEM_SET_HIDDEN(ti);
						}

						/* Parse each individual parameter in the line */
						comma_offset = tvb_pbrk_guint8(tvb, value_offset, line_end_offset - value_offset, " \t\r\n");

						/* Authentication-Info does not begin with the scheme name */
						if (hf_index != POS_AUTHENTICATION_INFO)
						{
							proto_tree_add_item(sip_element_tree, hf_sip_auth_scheme,
												tvb, value_offset, comma_offset - value_offset,
												FALSE);
						}

						while ((comma_offset = dissect_sip_authorization_item(tvb, sip_element_tree, comma_offset, line_end_offset)) != -1)
						{
							if(comma_offset == line_end_offset)
							{
								/* Line End reached: Stop Parsing */
								break;
							}

							if(tvb_get_guint8(tvb, comma_offset) != ',')
							{
								/* Undefined value reached: Stop Parsing */
								break;
							}
							comma_offset++; /* skip comma */
						}
					break;

					default :
						/* Default case is to assume its an FT_STRING field */
						if(hdr_tree) {
							proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
						}
					break;
				}/* end switch */
			}/*if HF_index */
		}/* if colon_offset */
		offset = next_offset;
	}/* End while */

	datalen = tvb_length_remaining(tvb, offset);
	reported_datalen = tvb_reported_length_remaining(tvb, offset);
	if (content_length != -1) {
		if (datalen > content_length)
			datalen = content_length;
		if (reported_datalen > content_length)
			reported_datalen = content_length;
	}

	if (datalen > 0) {
		/*
		 * There's a message body starting at "offset".
		 * Set the length of the header item.
		 */
		proto_item_set_end(th, tvb, offset);
		next_tvb = tvb_new_subset(tvb, offset, datalen, reported_datalen);
		if(sip_tree) {
			ti = proto_tree_add_text(sip_tree, next_tvb, 0, -1,
			                         "Message body");
			message_body_tree = proto_item_add_subtree(ti, ett_sip_message_body);
		}

		/* give the content type parameters to sub dissectors */

		if ( media_type_str_lower_case != NULL ) {
			void *save_private_data = pinfo->private_data;
			pinfo->private_data = content_type_parameter_str;
			found_match = dissector_try_string(media_type_dissector_table,
			                                   media_type_str_lower_case,
			                                   next_tvb, pinfo,
			                                   message_body_tree);
			pinfo->private_data = save_private_data;
			/* If no match dump as text */
		}
		if ( found_match != TRUE )
		{
            if (!(dissector_try_heuristic(heur_subdissector_list,
                                          next_tvb, pinfo, message_body_tree))) {
                int tmp_offset = 0;
                while (tvb_offset_exists(next_tvb, tmp_offset)) {
                    tvb_find_line_end(next_tvb, tmp_offset, -1, &next_offset, FALSE);
                    linelen = next_offset - tmp_offset;
                    if(message_body_tree) {
                        proto_tree_add_text(message_body_tree, next_tvb,
                                            tmp_offset, linelen, "%s",
                                            tvb_format_text(next_tvb, tmp_offset, linelen));
                        }
                    tmp_offset = next_offset;
                    }/* end while */
			}
		}
		offset += datalen;
	}


	/* Add to info column interesting things learned from header fields. */
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		/* Registration requests */
		if (strcmp(sip_methods[current_method_idx], "REGISTER") == 0)
		{
			if (contact_is_star && expires_is_0)
			{
				col_append_str(pinfo->cinfo, COL_INFO, "    (remove all bindings)");
			}
			else
			if (!contacts)
			{
				col_append_str(pinfo->cinfo, COL_INFO, "    (fetch bindings)");
			}
		}

		/* Registration responses */
		if (line_type == STATUS_LINE && (strcmp(cseq_method, "REGISTER") == 0))
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "    (%d bindings)", contacts);
		}
	}

	/* Check if this packet is a resend. */
	resend_for_packet = sip_is_packet_resend(pinfo, cseq_method, call_id,
	                                         cseq_number_set, cseq_number,
	                                         line_type);
	/* Mark whether this is a resend for the tap */
	stat_info->resend = (resend_for_packet > 0);

	/* And add the filterable field to the request/response line */
	if (reqresp_tree)
	{
		proto_item *item;
		item = proto_tree_add_boolean(reqresp_tree, hf_sip_resend, tvb, orig_offset, 0,
		                              resend_for_packet > 0);
		PROTO_ITEM_SET_GENERATED(item);
		if (resend_for_packet > 0)
		{
			item = proto_tree_add_uint(reqresp_tree, hf_sip_original_frame,
			                           tvb, orig_offset, 0, resend_for_packet);
			PROTO_ITEM_SET_GENERATED(item);
		}
	}


	if (ts != NULL)
		proto_item_set_len(ts, offset - orig_offset);

	if (global_sip_raw_text)
		tvb_raw_text_add(tvb, orig_offset, offset - orig_offset, tree);

	/* Report this packet to the tap */
	if (!pinfo->in_error_pkt)
	{
		tap_queue_packet(sip_tap, pinfo, stat_info);
	}

	return offset - orig_offset;
}

/* Display filter for SIP Request-Line */
static void
dfilter_sip_request_line(tvbuff_t *tvb, proto_tree *tree, guint meth_len)
{
	char	*string;

	/*
	 * We know we have the entire method; otherwise, "sip_parse_line()"
	 * would have returned OTHER_LINE.
	 */
	string = tvb_get_ephemeral_string(tvb, 0, meth_len);
	if (tree) {
		proto_tree_add_string(tree, hf_Method, tvb, 0, meth_len, string);
	}
	/* Copy request method for telling tap */
	stat_info->request_method = string;
}

/* Display filter for SIP Status-Line */
static void
dfilter_sip_status_line(tvbuff_t *tvb, proto_tree *tree)
{
	char string[3+1];
	gint response_code = 0;

	/*
	 * We know we have the entire status code; otherwise,
	 * "sip_parse_line()" would have returned OTHER_LINE.
	 * We also know that we have a version string followed by a
	 * space at the beginning of the line, for the same reason.
	 */
	tvb_memcpy(tvb, (guint8 *)string, SIP2_HDR_LEN + 1, 3);
	string[3] = '\0';
	response_code = atoi(string);

	/* Add numerical response code to tree */
	if (tree) {
		proto_tree_add_uint(tree, hf_Status_Code, tvb, SIP2_HDR_LEN + 1,
		                    3, response_code);
	}

	/* Add response code for sending to tap */
	stat_info->response_code = response_code;
}

void dfilter_store_sip_from_addr(tvbuff_t *tvb,proto_tree *tree,guint parameter_offset,
					  guint parameter_len)
{
	proto_tree_add_item(tree, hf_sip_from_addr, tvb, parameter_offset,
							parameter_len, FALSE);

}
/* From section 4.1 of RFC 2543:
 *
 * Request-Line  =  Method SP Request-URI SP SIP-Version CRLF
 *
 * From section 5.1 of RFC 2543:
 *
 * Status-Line  =  SIP-version SP Status-Code SP Reason-Phrase CRLF
 *
 * From section 7.1 of RFC 3261:
 *
 * Unlike HTTP, SIP treats the version number as a literal string.
 * In practice, this should make no difference.
 */
static line_type_t
sip_parse_line(tvbuff_t *tvb, int offset, gint linelen, guint *token_1_lenp)
{
	gint space_offset;
	gint token_1_start;
	guint token_1_len;
	gint token_2_start;
	guint token_2_len;
	gint token_3_start;
	guint token_3_len;
	gint colon_pos;

	token_1_start = offset;
	space_offset = tvb_find_guint8(tvb, token_1_start, -1, ' ');
	if ((space_offset == -1) || (space_offset == token_1_start)) {
		/*
		 * Either there's no space in the line (which means
		 * the line is empty or doesn't have a token followed
		 * by a space; neither is valid for a request or status), or
		 * the first character in the line is a space (meaning
		 * the method is empty, which isn't valid for a request,
		 * or the SIP version is empty, which isn't valid for a
		 * status).
		 */
		return OTHER_LINE;
	}
	token_1_len = space_offset - token_1_start;
	token_2_start = space_offset + 1;
	space_offset = tvb_find_guint8(tvb, token_2_start, -1, ' ');
	if (space_offset == -1) {
		/*
		 * There's no space after the second token, so we don't
		 * have a third token.
		 */
		return OTHER_LINE;
	}
	token_2_len = space_offset - token_2_start;
	token_3_start = space_offset + 1;
	token_3_len = token_1_start + linelen - token_3_start;

	*token_1_lenp = token_1_len;

	/*
	 * Is the first token a version string?
	 */
	if ( (strict_sip_version && (
		token_1_len == SIP2_HDR_LEN
		&& tvb_strneql(tvb, token_1_start, SIP2_HDR, SIP2_HDR_LEN) == 0)
	) || (! strict_sip_version && (
		tvb_strncaseeql(tvb, token_1_start, "SIP/", 4) == 0)
	)) {
		/*
		 * Yes, so this is either a Status-Line or something
		 * else other than a Request-Line.  To be a Status-Line,
		 * the second token must be a 3-digit number.
		 */
		if (token_2_len != 3) {
			/*
			 * We don't have 3-character status code.
			 */
			return OTHER_LINE;
		}
		if (!isdigit(tvb_get_guint8(tvb, token_2_start)) ||
		    !isdigit(tvb_get_guint8(tvb, token_2_start + 1)) ||
		    !isdigit(tvb_get_guint8(tvb, token_2_start + 2))) {
			/*
			 * 3 characters yes, 3 digits no.
			 */
			return OTHER_LINE;
		}
		return STATUS_LINE;
	} else {
		/*
		 * No, so this is either a Request-Line or something
		 * other than a Status-Line.  To be a Request-Line, the
		 * second token must be a URI and the third token must
		 * be a version string.
		 */
		if (token_2_len < 3) {
			/*
			 * We don't have a URI consisting of at least 3
			 * characters.
			 */
			return OTHER_LINE;
		}
		colon_pos = tvb_find_guint8(tvb, token_2_start + 1, -1, ':');
		if (colon_pos == -1) {
			/*
			 * There is no colon after the method, so the URI
			 * doesn't have a colon in it, so it's not valid.
			 */
			return OTHER_LINE;
		}
		if (colon_pos >= token_3_start) {
			/*
			 * The colon is in the version string, not the URI.
			 */
			return OTHER_LINE;
		}
		/* XXX - Check for a proper URI prefix? */
		if ( (strict_sip_version && (
			token_3_len != SIP2_HDR_LEN
			|| tvb_strneql(tvb, token_3_start, SIP2_HDR, SIP2_HDR_LEN) == -1)
		) || (! strict_sip_version && (
			tvb_strncaseeql(tvb, token_3_start, "SIP/", 4) == -1)
		)) {
			/*
			 * The version string isn't an SIP version 2.0 version
			 * string.
			 */
			return OTHER_LINE;
		}
		return REQUEST_LINE;
	}
}

static gboolean sip_is_known_request(tvbuff_t *tvb, int meth_offset,
    guint meth_len, guint *meth_idx)
{
        guint i;

        for (i = 1; i < array_length(sip_methods); i++) {
                if (meth_len == strlen(sip_methods[i]) &&
                    tvb_strneql(tvb, meth_offset, sip_methods[i], meth_len) == 0)
                {
                     *meth_idx = i;
                     return TRUE;
                }
        }

        return FALSE;
}

/* Returns index of method in sip_headers */
static gint sip_is_known_sip_header(tvbuff_t *tvb, int offset, guint header_len)
{
        guint i;

        for (i = 1; i < array_length(sip_headers); i++) {
                if (header_len == strlen(sip_headers[i].name) &&
                    tvb_strncaseeql(tvb, offset, sip_headers[i].name, header_len) == 0)
                        return i;
                if (sip_headers[i].compact_name != NULL &&
                    header_len == strlen(sip_headers[i].compact_name) &&
                    tvb_strncaseeql(tvb, offset, sip_headers[i].compact_name, header_len) == 0)
                        return i;
        }

        return -1;
}

/*
 * Display the entire message as raw text.
 */
static void
tvb_raw_text_add(tvbuff_t *tvb, int offset, int length, proto_tree *tree)
{
        proto_tree *raw_tree = NULL;
        proto_item *ti = NULL;
        int next_offset, linelen, end_offset;

	if(tree) {
		ti = proto_tree_add_item(tree, proto_raw_sip, tvb, offset, length, FALSE);
		raw_tree = proto_item_add_subtree(ti, ett_raw_text);
	}

        end_offset = offset + length;

        while (offset < end_offset) {
                tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
                linelen = next_offset - offset;
                if(raw_tree) {
			proto_tree_add_text(raw_tree, tvb, offset, linelen,
			    "%s", tvb_format_text(tvb, offset, linelen));
		}
                offset = next_offset;
        }
}

/* Check to see if this packet is a resent request.  Return value is number
   of the original frame this packet seems to be resending (0 = no resend). */
guint sip_is_packet_resend(packet_info *pinfo,
			gchar *cseq_method,
			gchar *call_id,
			guchar cseq_number_set,
			guint32 cseq_number, line_type_t line_type)
{
	guint32 cseq_to_compare = 0;
	sip_hash_key   key;
	sip_hash_key   *p_key = 0;
	sip_hash_value *p_val = 0;
	guint result = 0;

	/* Only consider retransmission of UDP packets */
	if (pinfo->ptype != PT_UDP)
	{
		return 0;
	}

	/* Don't consider packets that appear to be resent only because
	   they are e.g. returned in ICMP unreachable messages. */
	if (pinfo->in_error_pkt)
	{
		return 0;
	}

	/* A broken packet may have no cseq number set. Don't consider it as
	   a resend */
	if (!cseq_number_set)
	{
		return 0;
	}

	/* Return any answer stored from previous dissection */
	if (pinfo->fd->flags.visited)
	{
		return GPOINTER_TO_UINT(p_get_proto_data(pinfo->fd, proto_sip));
	}

	/* No packet entry found, consult global hash table */

	/* Prepare the key */
	strncpy(key.call_id, call_id,
		(strlen(call_id)+1 <= MAX_CALL_ID_SIZE) ?
			strlen(call_id)+1 :
			MAX_CALL_ID_SIZE);
	COPY_ADDRESS(&key.dest_address, &pinfo->net_dst);
	COPY_ADDRESS(&key.source_address, &pinfo->net_src);
	key.dest_port = pinfo->destport;
	key.source_port = pinfo->srcport;

	/* Do the lookup */
	p_val = (sip_hash_value*)g_hash_table_lookup(sip_hash, &key);

	if (p_val)
	{
		/* Table entry found, we'll use its value for comparison */
		cseq_to_compare = p_val->cseq;
	}
	else
	{
		/* Need to create a new table entry */

		/* Allocate a new key and value */
		p_key = se_alloc(sizeof(sip_hash_key));
		p_val = se_alloc(sizeof(sip_hash_value));

		/* Just give up if allocations failed */
		if (!p_key || !p_val)
		{
			return 0;
		}

		/* Fill in key and value details */
		g_snprintf(p_key->call_id, MAX_CALL_ID_SIZE, "%s", call_id);
		COPY_ADDRESS(&(p_key->dest_address), &pinfo->net_dst);
		COPY_ADDRESS(&(p_key->source_address), &pinfo->net_src);
		p_key->dest_port = pinfo->destport;
		p_key->source_port = pinfo->srcport;

		p_val->cseq = cseq_number;
		strncpy(p_val->method, cseq_method, MAX_CSEQ_METHOD_SIZE-1);
		p_val->method[MAX_CSEQ_METHOD_SIZE-1] = '\0';
		p_val->transaction_state = nothing_seen;
		p_val->frame_number = 0;

		/* Add entry */
		g_hash_table_insert(sip_hash, p_key, p_val);

		/* Assume have seen no cseq yet */
		cseq_to_compare = 0;
	}


	/******************************************/
	/* Is it a resend???                      */

	/* Does this look like a resent request (discount ACK, CANCEL, or a
	   different method from the original one) ? */

	if ((line_type == REQUEST_LINE) && (cseq_number == cseq_to_compare) &&
	    (p_val->transaction_state == request_seen) &&
	    (strcmp(cseq_method, p_val->method) == 0) &&
	    (strcmp(cseq_method, "ACK") != 0) &&
	    (strcmp(cseq_method, "CANCEL") != 0))
	{
		result = p_val->frame_number;
	}

	/* Does this look like a resent final response ? */
	if ((line_type == STATUS_LINE) && (cseq_number == cseq_to_compare) &&
	    (p_val->transaction_state == final_response_seen) &&
	    (strcmp(cseq_method, p_val->method) == 0) &&
	    (stat_info->response_code >= 200) &&
	    (stat_info->response_code == p_val->response_code))
	{
		result = p_val->frame_number;
	}

	/* Update state for this entry */
	p_val->cseq = cseq_number;

	switch (line_type)
	{
		case REQUEST_LINE:
			p_val->transaction_state = request_seen;
			if (!result)
			{
				p_val->frame_number = pinfo->fd->num;
			}
			break;
		case STATUS_LINE:
			if (stat_info->response_code >= 200)
			{
				p_val->response_code = stat_info->response_code;
				p_val->transaction_state = final_response_seen;
				if (!result)
				{
					p_val->frame_number = pinfo->fd->num;
				}
			}
			else
			{
				p_val->transaction_state = provisional_response_seen;
			}
			break;
		default:
			break;
	}

	/* Store return value with this packet */
	p_add_proto_data(pinfo->fd, proto_sip, GUINT_TO_POINTER(result));

	return result;
}


/* Register the protocol with Wireshark */
void proto_register_sip(void)
{

        /* Setup list of header fields */
        static hf_register_info hf[] = {

		{ &hf_msg_hdr,
				{ "Message Header",           "sip.msg_hdr",
                        FT_NONE, 0, NULL, 0,
                        "Message Header in SIP message", HFILL }
                },
		{ &hf_Method,
		       { "Method", 		"sip.Method",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"SIP Method", HFILL }
		},
		{ &hf_Request_Line,
				{ "Request-Line",                "sip.Request-Line",
					FT_STRING, BASE_NONE,NULL,0x0,
                       "SIP Request-Line", HFILL }
                },
		{ &hf_Status_Code,
		       { "Status-Code", 		"sip.Status-Code",
		       FT_UINT32, BASE_DEC,NULL,0x0,
			"SIP Status Code", HFILL }
		},
		{ &hf_Status_Line,
		       { "Status-Line",                 "sip.Status-Line",
		       FT_STRING, BASE_NONE,NULL,0x0,
                       "SIP Status-Line", HFILL }
                },
		{ &hf_sip_display,
			{ "SIP Display info", 		"sip.display.info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Display info", HFILL }
		},
		{ &hf_sip_to_addr,
				{ "SIP to address", 		"sip.to.addr",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: to addr", HFILL }
		},
		{ &hf_sip_from_addr,
		       { "SIP from address", 		"sip.from.addr",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: from addr", HFILL }
		},
		{ &hf_sip_contact_addr,
		       { "SIP contact address", 	"sip.contact.addr",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: contact addr", HFILL }
		},
		{ &hf_sip_uri,
				{ "URI", 		"sip.uri",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: SIP Uri", HFILL }
		},
		{ &hf_sip_contact_item,
		       { "Contact Binding", 		"sip.contact.binding",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: one contact binding", HFILL }
		},
		{ &hf_sip_tag,
		       { "SIP tag", 		"sip.tag",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: tag", HFILL }
		},
		{ &hf_header_array[POS_ACCEPT],
		       { "Accept", 		"sip.Accept",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Accept Header", HFILL }
		},
		{ &hf_header_array[POS_ACCEPT_CONTACT],
		       { "Accept-Contact", 		"sip.Accept-Contact",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3841: Accept-Contact Header", HFILL }
		},
		{ &hf_header_array[POS_ACCEPT_ENCODING],
		       { "Accept-Encoding", 		"sip.Accept-Encoding",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3841: Accept-Encoding Header", HFILL }
		},
		{ &hf_header_array[POS_ACCEPT_LANGUAGE],
		       { "Accept-Language", 		"sip.Accept-Language",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Accept-Language Header", HFILL }
		},
		{ &hf_header_array[POS_ACCEPT_RESOURCE_PRIORITY],
		       { "Accept-Resource-Priority", 		"sip.Accept-Resource-Priority",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Draft: Accept-Resource-Priority Header", HFILL }
		},
		{ &hf_header_array[POS_ALERT_INFO],
		       { "Alert-Info", 		"sip.Alert-Info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Alert-Info Header", HFILL }
		},
                { &hf_header_array[POS_ALLOW],
		       { "Allow", 		"sip.Allow",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Allow Header", HFILL }
		},
                { &hf_header_array[POS_ALLOW_EVENTS],
		       { "Allow-Events", 		"sip.Allow-Events",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3265: Allow-Events Header", HFILL }
		},
                { &hf_header_array[POS_AUTHENTICATION_INFO],
		       { "Authentication-Info", 		"sip.Authentication-Info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Authentication-Info Header", HFILL }
		},
                { &hf_header_array[POS_AUTHORIZATION],
		       { "Authorization", 		"sip.Authorization",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Authorization Header", HFILL }
		},
                { &hf_header_array[POS_CALL_ID],
		       { "Call-ID", 		"sip.Call-ID",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Call-ID Header", HFILL }
		},
                { &hf_header_array[POS_CALL_INFO],
		       { "Call-Info", 		"sip.Call-Info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Call-Info Header", HFILL }
		},
                { &hf_header_array[POS_CONTACT],
		       { "Contact", 		"sip.Contact",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Contact Header", HFILL }
		},
                { &hf_header_array[POS_CONTENT_DISPOSITION],
		       { "Content-Disposition", 		"sip.Content-Disposition",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Disposition Header", HFILL }
		},
                { &hf_header_array[POS_CONTENT_ENCODING],
		       { "Content-Encoding", 		"sip.Content-Encoding",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Encoding Header", HFILL }
		},
                { &hf_header_array[POS_CONTENT_LANGUAGE],
		       { "Content-Language", 		"sip.Content-Language",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Language Header", HFILL }
		},
                { &hf_header_array[POS_CONTENT_LENGTH],
		       { "Content-Length", 		"sip.Content-Length",
		       FT_UINT32, BASE_DEC,NULL,0x0,
			"RFC 3261: Content-Length Header", HFILL }
		},
                { &hf_header_array[POS_CONTENT_TYPE],
		       { "Content-Type", 		"sip.Content-Type",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Content-Type Header", HFILL }
		},
                { &hf_header_array[POS_CSEQ],
		       { "CSeq", 		"sip.CSeq",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: CSeq Header", HFILL }
		},
                { &hf_header_array[POS_DATE],
		       { "Date", 		"sip.Date",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Date Header", HFILL }
		},
                { &hf_header_array[POS_ERROR_INFO],
		       { "Error-Info", 		"sip.Error-Info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Error-Info Header", HFILL }
		},
                { &hf_header_array[POS_EVENT],
		       { "Event", 		"sip.Event",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3265: Event Header", HFILL }
		},
                { &hf_header_array[POS_EXPIRES],
		       { "Expires", 		"sip.Expires",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Expires Header", HFILL }
		},
                { &hf_header_array[POS_FROM],
		       { "From", 		"sip.From",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: From Header", HFILL }
		},
                { &hf_header_array[POS_IN_REPLY_TO],
		       { "In-Reply-To", 		"sip.In-Reply-To",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: In-Reply-To Header", HFILL }
		},
                { &hf_header_array[POS_JOIN],
		       { "Join", 		"sip.Join",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Draft: Join Header", HFILL }
		},
                { &hf_header_array[POS_MAX_FORWARDS],
		       { "Max-Forwards", 		"sip.Max-Forwards",
		       FT_UINT32, BASE_DEC,NULL,0x0,
			"RFC 3261: Max-Forwards Header", HFILL }
		},
                { &hf_header_array[POS_MIME_VERSION],
		       { "MIME-Version", 		"sip.MIME-Version",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: MIME-Version Header", HFILL }
		},
                { &hf_header_array[POS_MIN_EXPIRES],
		       { "Min-Expires", 		"sip.Min-Expires",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Min-Expires Header", HFILL }
		},
                { &hf_header_array[POS_MIN_SE],
		       { "Min-SE", 		"sip.Min-SE",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Draft: Min-SE Header", HFILL }
		},
                { &hf_header_array[POS_ORGANIZATION],
		       { "Organization", 		"sip.Organization",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Organization Header", HFILL }
		},
		{ &hf_header_array[POS_P_ACCESS_NETWORK_INFO],
		       { "P-Access-Network-Info",	"sip.P-Access-Network-Info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Access-Network-Info Header", HFILL }
		},

		{ &hf_header_array[POS_P_ASSERTED_IDENTITY],
		       { "P-Asserted-Identity",		"sip.P-Asserted-Identity",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Asserted-Identity Header", HFILL }
		},

		{ &hf_header_array[POS_P_ASSOCIATED_URI],
		       { "P-Associated-URI", 		"sip.P-Associated-URI",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Associated-URI Header", HFILL }
		},

		{ &hf_header_array[POS_P_CALLED_PARTY_ID],
		       { "P-Called-Party-ID", 		"sip.P-Called-Party-ID",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Called-Party-ID Header", HFILL }
		},

		{ &hf_header_array[POS_P_CHARGING_FUNCTION_ADDRESSES],
		       { "P-Charging-Function-Addresses","sip.P-Charging-Function-Addresses",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Charging-Function-Addresses", HFILL }
		},

		{ &hf_header_array[POS_P_CHARGING_VECTOR],
		       { "P-Charging-Vector", 		"sip.P-Charging-Vector",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Charging-Vector Header", HFILL }
		},

		{ &hf_header_array[POS_P_DCS_TRACE_PARTY_ID],
		       { "P-DCS-Trace-Party-ID", 	"sip.P-DCS-Trace-Party-ID",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-DCS-Trace-Party-ID Header", HFILL }
		},

		{ &hf_header_array[POS_P_DCS_OSPS],
		       { "P-DCS-OSPS", 			"sip.P-DCS-OSPS",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-DCS-OSPS Header", HFILL }
		},

		{ &hf_header_array[POS_P_DCS_BILLING_INFO],
		       { "P-DCS-Billing-Info", 		"sip.P-DCS-Billing-Info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-DCS-Billing-Info Header", HFILL }
		},

		{ &hf_header_array[POS_P_DCS_LAES],
		       { "P-DCS-LAES", 			"sip.P-DCS-LAES",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-DCS-LAES Header", HFILL }
		},

		{ &hf_header_array[POS_P_DCS_REDIRECT],
		       { "P-DCS-Redirect", 		"sip.P-DCS-Redirect",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-DCS-Redirect Header", HFILL }
		},

		{ &hf_header_array[POS_P_MEDIA_AUTHORIZATION],
		       { "P-Media-Authorization", 	"sip.P-Media-Authorization",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Media-Authorization Header", HFILL }
		},

		{ &hf_header_array[POS_P_PREFERRED_IDENTITY],
		       { "P-Preferred-Identity",  	"sip.P-Preferred-Identity",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Preferred-Identity Header", HFILL }
		},

		{ &hf_header_array[POS_P_VISITED_NETWORK_ID],
		       { "P-Visited-Network-ID", 	"sip.P-Visited-Network-ID",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Visited-Network-ID Header", HFILL }
		},

		{ &hf_header_array[POS_PATH],
		       { "Path", 			"sip.Path",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Path Header", HFILL }
		},

        { &hf_header_array[POS_PRIORITY],
		       { "Priority", 		"sip.Priority",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Priority Header", HFILL }
		},
		{ &hf_header_array[POS_PRIVACY],
		       { "Privacy", 			"sip.Privacy",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Privacy Header", HFILL }
		},

        { &hf_header_array[POS_PROXY_AUTHENTICATE],
		       { "Proxy-Authenticate", 		"sip.Proxy-Authenticate",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Proxy-Authenticate Header", HFILL }
		},
                { &hf_header_array[POS_PROXY_AUTHORIZATION],
		       { "Proxy-Authorization", 		"sip.Proxy-Authorization",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Proxy-Authorization Header", HFILL }
		},

        { &hf_header_array[POS_PROXY_REQUIRE],
		       { "Proxy-Require", 		"sip.Proxy-Require",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Proxy-Require Header", HFILL }
		},
		{ &hf_header_array[POS_RACK],
		       { "RAck", 		"sip.RAck",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3262: RAck Header", HFILL }
		},
		{ &hf_header_array[POS_REASON],
		       { "Reason", 			"sip.Reason",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3326 Reason Header", HFILL }
		},
		{ &hf_header_array[POS_RECORD_ROUTE],
		       { "Record-Route", 		"sip.Record-Route",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Record-Route Header", HFILL }
		},
		{ &hf_header_array[POS_REFERED_BY],
		       { "Refered By", 		"sip.Refered-by",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3892: Refered-by Header", HFILL }
		},
		{ &hf_header_array[POS_REJECT_CONTACT],
			{ "Reject-Contact", 		"sip.Reject-Contact",
			FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3841: Reject-Contact Header", HFILL }
		},
		{ &hf_header_array[POS_REPLACES],
			{ "Replaces", 		"sip.Replaces",
			FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3891: Replaces Header", HFILL }
		},
		{ &hf_header_array[POS_REPLY_TO],
		       { "Reply-To", 		"sip.Reply-To",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Reply-To Header", HFILL }
		},
		{ &hf_header_array[POS_REQUEST_DISPOSITION],
		       { "Request-Disposition", 	"sip.Request-Disposition",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3841: Request-Disposition Header", HFILL }
		},
		{ &hf_header_array[POS_REQUIRE],
			{ "Require", 		"sip.Require",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Require Header", HFILL }
		},
		{ &hf_header_array[POS_RESOURCE_PRIORITY],
			{ "Resource-Priority", 		"sip.Resource-Priority",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Draft: Resource-Priority Header", HFILL }
		},
		{ &hf_header_array[POS_RETRY_AFTER],
			{ "Retry-After", 		"sip.Retry-After",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Retry-After Header", HFILL }
		},
		{ &hf_header_array[POS_ROUTE],
		       { "Route", 		"sip.Route",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Route Header", HFILL }
		},
        { &hf_header_array[POS_RSEQ],
		       { "RSeq", 		"sip.RSeq",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3262: RSeq Header", HFILL }
		},
		{ &hf_header_array[ POS_SECURITY_CLIENT],
		       { "Security-Client", 		"sip.Security-Client",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3329 Security-Client Header", HFILL }
		},
		{ &hf_header_array[ POS_SECURITY_SERVER],
		       { "Security-Server", 		"sip.Security-Server",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3329 Security-Server Header", HFILL }
		},
		{ &hf_header_array[ POS_SECURITY_VERIFY],
		       { "Security-Verify", 		"sip.Security-Verify",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3329 Security-Verify Header", HFILL }
		},
		{ &hf_header_array[POS_SERVER],
			{ "Server", 		"sip.Server",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Server Header", HFILL }
		},
		{ &hf_header_array[POS_SERVICE_ROUTE],
		       { "Service-Route", 		"sip.Service-Route",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Service-Route Header", HFILL }
		},
		{ &hf_header_array[POS_SESSION_EXPIRES],
		       { "Session-Expires", 		"sip.Session-Expires",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Session-Expires Header", HFILL }
		},
		{ &hf_header_array[POS_SIP_ETAG],
		       { "ETag", 		"sip.ETag",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"SIP-ETag Header", HFILL }
		},
		{ &hf_header_array[POS_SIP_IF_MATCH],
		       { "If_Match", 		"sip.If_Match",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"SIP-If-Match Header", HFILL }
		},
		{ &hf_header_array[POS_SUBJECT],
		       { "Subject", 		"sip.Subject",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Subject Header", HFILL }
		},
		{ &hf_header_array[POS_SUBSCRIPTION_STATE],
		       { "Subscription-State", 		"sip.Subscription-State",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3265: Subscription-State Header", HFILL }
		},
		{ &hf_header_array[POS_SUPPORTED],
			{ "Supported", 		"sip.Supported",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Supported Header", HFILL }
		},
		{ &hf_header_array[POS_TIMESTAMP],
			{ "Timestamp", 		"sip.Timestamp",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Timestamp Header", HFILL }
		},
		{ &hf_header_array[POS_TO],
			{ "To", 		"sip.To",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: To Header", HFILL }
		},

		{ &hf_header_array[POS_UNSUPPORTED],
			{ "Unsupported", 		"sip.Unsupported",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Unsupported Header", HFILL }
		},
		{ &hf_header_array[POS_USER_AGENT],
			{ "User-Agent", 		"sip.User-Agent",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: User-Agent Header", HFILL }
		},
		{ &hf_header_array[POS_VIA],
			{ "Via", 		"sip.Via",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Via Header", HFILL }
		},
		{ &hf_header_array[POS_WARNING],
			{ "Warning", 		"sip.Warning",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Warning Header", HFILL }
		},

		{ &hf_header_array[POS_WWW_AUTHENTICATE],
			{ "WWW-Authenticate", 		"sip.WWW-Authenticate",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: WWW-Authenticate Header", HFILL }
		},
		{ &hf_header_array[POS_REFER_TO],
			{ "Refer-To", 			"sip.Refer-To",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"Refer-To Header", HFILL }
		},
		{ &hf_header_array[POS_HISTORY_INFO],
			{ "History-Info", 			"sip.History-Info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 4244: Request History Information", HFILL }
		},
		{ &hf_sip_resend,
			{ "Resent Packet", "sip.resend",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_sip_original_frame,
			{ "Suspected resend of frame",  "sip.resend-original",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    	"Original transmission of frame", HFILL}
		},
		{ &hf_sip_auth,
			{ "Authentication",  "sip.auth",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication", HFILL}
		},
		{ &hf_sip_auth_scheme,
			{ "Authentication Scheme",  "sip.auth.scheme",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Scheme", HFILL}
		},
		{ &hf_sip_auth_digest_response,
			{ "Digest Authentication Response",  "sip.auth.digest.response",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Digest Authentication Response Value ", HFILL}
		},
		{ &hf_sip_auth_nc,
			{ "Nonce Count",  "sip.auth.nc",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication nonce count", HFILL}
		},
		{ &hf_sip_auth_username,
			{ "Username",  "sip.auth.username",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"Sip authentication username", HFILL}
		},
		{ &hf_sip_auth_realm,
			{ "Realm",  "sip.auth.realm",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"Sip Authentication realm", HFILL}
		},
		{ &hf_sip_auth_nonce,
			{ "Nonce Value",  "sip.auth.nonce",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication nonce value", HFILL}
		},
		{ &hf_sip_auth_algorithm,
			{ "Algorithm",  "sip.auth.algorithm",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Algorithm", HFILL}
		},
		{ &hf_sip_auth_opaque,
			{ "Opaque Value",  "sip.auth.opaque",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication opaque value", HFILL}
		},
		{ &hf_sip_auth_qop,
			{ "QOP",  "sip.auth.qop",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication QOP", HFILL}
		},
		{ &hf_sip_auth_cnonce,
			{ "CNonce Value",  "sip.auth.cnonce",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Client Nonce value ", HFILL}
		},
		{ &hf_sip_auth_uri,
			{ "Authentication URI",  "sip.auth.uri",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication URI", HFILL}
		},
		{ &hf_sip_auth_domain,
			{ "Authentication Domain",  "sip.auth.domain",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Domain", HFILL}
		},
		{ &hf_sip_auth_stale,
			{ "Stale Flag",  "sip.auth.stale",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Stale Flag", HFILL}
		},
		{ &hf_sip_auth_auts,
			{ "Authentication Token",  "sip.auth.auts",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Token", HFILL}
		},
		{ &hf_sip_auth_rspauth,
			{ "Response auth",  "sip.auth.rspauth",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Response auth", HFILL}
		},
		{ &hf_sip_auth_nextnonce,
			{ "Next Nonce",  "sip.auth.nextnonce",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Next Nonce", HFILL}
		},
		{ &hf_sip_cseq_seq_no,
			{ "Sequence Number",  "sip.CSeq.seq",
			FT_UINT32, BASE_DEC, NULL, 0x0,
		    	"CSeq header sequence number", HFILL}
		},
		{ &hf_sip_cseq_method,
			{ "Method",  "sip.CSeq.method",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"CSeq header method", HFILL}
		}};


	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sip,
		&ett_sip_reqresp,
		&ett_sip_hdr,
		&ett_sip_element,
		&ett_sip_uri,
		&ett_sip_contact_item,
		&ett_sip_message_body,
		&ett_sip_cseq
	};
	static gint *ett_raw[] = {
		&ett_raw_text,
	};

	module_t *sip_module;

	/* Register the protocol name and description */
	proto_sip = proto_register_protocol("Session Initiation Protocol",
	                                    "SIP", "sip");
	proto_raw_sip = proto_register_protocol("Session Initiation Protocol (SIP as raw text)",
	                                        "Raw_SIP", "raw_sip");
	new_register_dissector("sip", dissect_sip, proto_sip);
	sip_handle = find_dissector("sip");
	register_dissector("sip.tcp", dissect_sip_tcp, proto_sip);
	sip_tcp_handle = find_dissector("sip.tcp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_sip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_subtree_array(ett_raw, array_length(ett_raw));

	/* SIP content type and internet media type used by other dissectors are the same */
	media_type_dissector_table = find_dissector_table("media_type");

	sip_module = prefs_register_protocol(proto_sip, NULL);

	prefs_register_bool_preference(sip_module, "display_raw_text",
		"Display raw text for SIP message",
		"Specifies that the raw text of the "
		"SIP message should be displayed "
		"in addition to the dissection tree",
		&global_sip_raw_text);
	prefs_register_bool_preference(sip_module, "strict_sip_version",
		"Enforce strict SIP version check (" SIP2_HDR ")",
		"If enabled, only " SIP2_HDR " traffic will be dissected as SIP. "
		"Disable it to allow SIP traffic with a different version "
		"to be dissected as SIP.",
		&strict_sip_version);
	prefs_register_bool_preference(sip_module, "desegment_headers",
	    "Reassemble SIP headers spanning multiple TCP segments",
	    "Whether the SIP dissector should reassemble headers "
	    "of a request spanning multiple TCP segments. "
		"To use this option, you must also enable "
        "\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &sip_desegment_headers);
	prefs_register_bool_preference(sip_module, "desegment_body",
	    "Reassemble SIP bodies spanning multiple TCP segments",
	    "Whether the SIP dissector should use the "
	    "\"Content-length:\" value, if present, to reassemble "
	    "the body of a request spanning multiple TCP segments, "
	    "and reassemble chunked data spanning multiple TCP segments. "
		"To use this option, you must also enable "
        "\"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
	    &sip_desegment_body);

	register_init_routine(&sip_init_protocol);
    register_heur_dissector_list("sip", &heur_subdissector_list);
	/* Register for tapping */
	sip_tap = register_tap("sip");
}

void
proto_reg_handoff_sip(void)
{

	dissector_add("udp.port", UDP_PORT_SIP, sip_handle);
	dissector_add_string("media_type", "message/sip", sip_handle);
	sigcomp_handle = find_dissector("sigcomp");

	dissector_add("tcp.port", TCP_PORT_SIP, sip_tcp_handle);
    ssl_dissector_add(TLS_PORT_SIP, "sip.tcp", TRUE);

	heur_dissector_add("udp", dissect_sip_heur, proto_sip);
	heur_dissector_add("tcp", dissect_sip_tcp_heur, proto_sip);
	heur_dissector_add("sctp", dissect_sip_heur, proto_sip);
}
