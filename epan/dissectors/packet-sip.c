/* packet-sip.c
 * Routines for the Session Initiation Protocol (SIP) dissection.
 * RFCs 3261-3264
 *
 * TODO:
 *      hf_ display filters for headers of SIP extension RFCs (ongoing)
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

#include <stdlib.h>
#include <ctype.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/req_resp_hdrs.h>
#include <epan/emem.h>
#include <epan/strutil.h>
#include <epan/tap.h>
#include <epan/expert.h>

#include <wsutil/str_util.h>

#include "packet-tcp.h"
#include "packet-ssl.h"

#include "packet-isup.h"
#include "packet-sip.h"

#define TCP_PORT_SIP 5060
#define UDP_PORT_SIP 5060
#define TLS_PORT_SIP 5061
#define DEFAULT_SIP_PORT_RANGE "5060"

static dissector_handle_t sip_tcp_handle;

static gint sip_tap = -1;
static dissector_handle_t sigcomp_handle;
static dissector_handle_t sip_diag_handle;

/* Initialize the protocol and registered fields */
static gint proto_sip                     = -1;
static gint proto_raw_sip                 = -1;
static gint hf_sip_raw_line               = -1;
static gint hf_sip_msg_hdr                = -1;
static gint hf_sip_Method                 = -1;
static gint hf_Request_Line               = -1;
static gint hf_sip_ruri                   = -1;
static gint hf_sip_ruri_user              = -1;
static gint hf_sip_ruri_host              = -1;
static gint hf_sip_ruri_port              = -1;
static gint hf_sip_Status_Code            = -1;
static gint hf_sip_Status_Line            = -1;
static gint hf_sip_display                = -1;
static gint hf_sip_to_addr                = -1;
static gint hf_sip_to_user                = -1;
static gint hf_sip_to_host                = -1;
static gint hf_sip_to_port                = -1;
static gint hf_sip_from_addr              = -1;
static gint hf_sip_from_user              = -1;
static gint hf_sip_from_host              = -1;
static gint hf_sip_from_port              = -1;
static gint hf_sip_tag                    = -1;
static gint hf_sip_pai_addr               = -1;
static gint hf_sip_pai_user               = -1;
static gint hf_sip_pai_host               = -1;
static gint hf_sip_pai_port               = -1;
static gint hf_sip_pmiss_addr             = -1;
static gint hf_sip_pmiss_user             = -1;
static gint hf_sip_pmiss_host             = -1;
static gint hf_sip_pmiss_port             = -1;
static gint hf_sip_ppi_addr               = -1;
static gint hf_sip_ppi_user               = -1;
static gint hf_sip_ppi_host               = -1;
static gint hf_sip_ppi_port               = -1;
static gint hf_sip_tc_addr                = -1;
static gint hf_sip_tc_user                = -1;
static gint hf_sip_tc_host                = -1;
static gint hf_sip_tc_port                = -1;
static gint hf_sip_tc_turi                = -1;
static gint hf_sip_contact_param          = -1;
static gint hf_sip_resend                 = -1;
static gint hf_sip_original_frame         = -1;
static gint hf_sip_matching_request_frame = -1;
static gint hf_sip_response_time          = -1;
static gint hf_sip_release_time           = -1;
static gint hf_sip_curi                   = -1;
static gint hf_sip_curi_user              = -1;
static gint hf_sip_curi_host              = -1;
static gint hf_sip_curi_port              = -1;

static gint hf_sip_auth                   = -1;
static gint hf_sip_auth_scheme            = -1;
static gint hf_sip_auth_digest_response   = -1;
static gint hf_sip_auth_nc                = -1;
static gint hf_sip_auth_username          = -1;
static gint hf_sip_auth_realm             = -1;
static gint hf_sip_auth_nonce             = -1;
static gint hf_sip_auth_algorithm         = -1;
static gint hf_sip_auth_opaque            = -1;
static gint hf_sip_auth_qop               = -1;
static gint hf_sip_auth_cnonce            = -1;
static gint hf_sip_auth_uri               = -1;
static gint hf_sip_auth_domain            = -1;
static gint hf_sip_auth_stale             = -1;
static gint hf_sip_auth_auts              = -1;
static gint hf_sip_auth_rspauth           = -1;
static gint hf_sip_auth_nextnonce         = -1;
static gint hf_sip_auth_ik                = -1;
static gint hf_sip_auth_ck                = -1;

static gint hf_sip_cseq_seq_no            = -1;
static gint hf_sip_cseq_method            = -1;

static gint hf_sip_via_transport          = -1;
static gint hf_sip_via_sent_by_address    = -1;
static gint hf_sip_via_sent_by_port       = -1;
static gint hf_sip_via_branch             = -1;
static gint hf_sip_via_maddr              = -1;
static gint hf_sip_via_rport              = -1;
static gint hf_sip_via_received           = -1;
static gint hf_sip_via_ttl                = -1;
static gint hf_sip_via_comp               = -1;
static gint hf_sip_via_sigcomp_id         = -1;

static gint hf_sip_rack_rseq_no           = -1;
static gint hf_sip_rack_cseq_no           = -1;
static gint hf_sip_rack_cseq_method       = -1;

static gint hf_sip_msg_body               = -1;

/* Initialize the subtree pointers */
static gint ett_sip                       = -1;
static gint ett_sip_reqresp               = -1;
static gint ett_sip_hdr                   = -1;
static gint ett_sip_ext_hdr               = -1;
static gint ett_raw_text                  = -1;
static gint ett_sip_element               = -1;
static gint ett_sip_uri                   = -1;
static gint ett_sip_contact_item          = -1;
static gint ett_sip_message_body          = -1;
static gint ett_sip_cseq                  = -1;
static gint ett_sip_via                   = -1;
static gint ett_sip_reason                = -1;
static gint ett_sip_rack                  = -1;
static gint ett_sip_ruri                  = -1;
static gint ett_sip_to_uri                = -1;
static gint ett_sip_curi                  = -1;
static gint ett_sip_from_uri              = -1;
static gint ett_sip_pai_uri               = -1;
static gint ett_sip_pmiss_uri             = -1;
static gint ett_sip_ppi_uri               = -1;
static gint ett_sip_tc_uri                = -1;

/* PUBLISH method added as per http://www.ietf.org/internet-drafts/draft-ietf-sip-publish-01.txt */
static const char *sip_methods[] = {
#define SIP_METHOD_INVALID	0
        "<Invalid method>",      /* Pad so that the real methods start at index 1 */
#define SIP_METHOD_ACK		1
        "ACK",
#define SIP_METHOD_BYE		2
        "BYE",
#define SIP_METHOD_CANCEL	3
        "CANCEL",
#define SIP_METHOD_DO		4
        "DO",
#define SIP_METHOD_INFO		5
        "INFO",
#define SIP_METHOD_INVITE	6
        "INVITE",
#define SIP_METHOD_MESSAGE	7
        "MESSAGE",
#define SIP_METHOD_NOTIFY	8
        "NOTIFY",
#define SIP_METHOD_OPTIONS	9
        "OPTIONS",
#define SIP_METHOD_PRACK	10
        "PRACK",
#define SIP_METHOD_QAUTH	11
        "QAUTH",
#define SIP_METHOD_REFER	12
        "REFER",
#define SIP_METHOD_REGISTER	13
        "REGISTER",
#define SIP_METHOD_SPRACK	14
        "SPRACK",
#define SIP_METHOD_SUBSCRIBE	15
        "SUBSCRIBE",
#define SIP_METHOD_UPDATE	16
        "UPDATE",
#define SIP_METHOD_PUBLISH	17
        "PUBLISH"
};

/* from RFC 3261
 * Updated with info from http://www.iana.org/assignments/sip-parameters
 * (last updated 2009-11-11)
 * Updated with: http://www.ietf.org/internet-drafts/draft-ietf-sip-resource-priority-05.txt
 */
typedef struct {
        const char *name;
        const char *compact_name;
} sip_header_t;
static const sip_header_t sip_headers[] = {
	{ "Unknown-header",                 NULL }, /* 0 Pad so that the real headers start at index 1 */
	{ "Accept",                         NULL }, /* 1 */
#define POS_ACCEPT                       1
	{ "Accept-Contact",                 "a"  }, /* 2 RFC3841  */
#define POS_ACCEPT_CONTACT               2
	{ "Accept-Encoding",                NULL }, /* 3 */
#define POS_ACCEPT_ENCODING              3
	{ "Accept-Language",                NULL }, /* 4 */
#define POS_ACCEPT_LANGUAGE              4
	{ "Accept-Resource-Priority",       NULL }, /* 5 RFC4412 */
#define POS_ACCEPT_RESOURCE_PRIORITY     5
	{ "Alert-Info",                     NULL },
#define POS_ALERT_INFO                   6
	{ "Allow",                          NULL },
#define POS_ALLOW                        7
	{ "Allow-Events",                   "u"  }, /* 8 RFC3265  */
#define POS_ALLOW_EVENTS                 8
	{ "Answer-Mode",                    NULL }, /* 9 RFC5373 */
#define POS_ANSWER_MODE                  9
	{ "Authentication-Info",            NULL },
#define POS_AUTHENTICATION_INFO         10
	{ "Authorization",                  NULL }, /* 11 */
#define POS_AUTHORIZATION               11
	{ "Call-ID",                        "i"  },
#define POS_CALL_ID                     12
	{ "Call-Info",                      NULL },
#define POS_CALL_INFO                   13
	{ "Contact",                        "m"  },
#define POS_CONTACT                     14
	{ "Content-Disposition",            NULL },
#define POS_CONTENT_DISPOSITION         15
	{ "Content-Encoding",               "e"  },  /*  16 */
#define POS_CONTENT_ENCODING            16
	{ "Content-Language",               NULL },
#define POS_CONTENT_LANGUAGE            17
	{ "Content-Length",                 "l"  },
#define POS_CONTENT_LENGTH              18
	{ "Content-Type",                   "c"  },
#define POS_CONTENT_TYPE                19
	{ "CSeq",                           NULL },
#define POS_CSEQ                        20
	{ "Date",                           NULL },  /*  21 */
#define POS_DATE                        21
/*              Encryption (Deprecated)       [RFC3261] */
	{ "Error-Info",                     NULL },  /*  22 */
#define POS_ERROR_INFO                  22
	{ "Event",                          "o"  },  /*  23 */
#define POS_EVENT                       23
	{ "Expires",                        NULL },  /*  24 */
#define POS_EXPIRES                     24
	{ "Flow-Timer",                     NULL },  /*  25 RFC5626  */
#define POS_FLOW_TIMER                  25
	{ "From",                           "f"  },  /*  26 */
#define POS_FROM                        26
/*              Hide                          [RFC3261] (deprecated)*/
	{ "History-Info",                   NULL },  /*  27 RFC4244  */
#define POS_HISTORY_INFO                27
	{ "Identity",                       "y"  },  /*  28 RFC4474  */
#define POS_IDENTITY                    28
	{ "Identity-Info",                  "n"  },  /*  29 RFC4474  */
#define POS_IDENTITY_INFO               29
	{ "Info-Package",                   NULL },  /*  30 RFC-ietf-sipcore-info-events-10.txt  */
#define POS_INFO_PKG                    30
	{ "In-Reply-To",                    NULL },  /*  31 RFC3261  */
#define POS_IN_REPLY_TO                 31
	{ "Join",                           NULL },  /*  32 RFC3911  */
#define POS_JOIN                        32
	{ "Max-Breadth",                    NULL },  /*  33 RFC5393*/
#define POS_MAX_BREADTH                 33
	{ "Max-Forwards",                   NULL },  /*  34 */
#define POS_MAX_FORWARDS                34
	{ "MIME-Version",                   NULL },  /*  35 */
#define POS_MIME_VERSION                35
	{ "Min-Expires",                    NULL },  /*  36 */
#define POS_MIN_EXPIRES                 36
	{ "Min-SE",                         NULL },  /*  37 RFC4028  */
#define POS_MIN_SE                      37
	{ "Organization",                   NULL },  /*  38 RFC3261  */
#define POS_ORGANIZATION                38
	{ "P-Access-Network-Info",          NULL },  /*  39 RFC3455  */
#define POS_P_ACCESS_NETWORK_INFO       39
	{ "P-Answer-State",                 NULL },  /*  40 RFC4964  */
#define POS_P_ANSWER_STATE              40
	{ "P-Asserted-Identity",            NULL },  /*  41 RFC3325  */
#define POS_P_ASSERTED_IDENTITY         41
	{ "P-Asserted-Service",             NULL },  /*  42 RFC-drage-sipping-service-identification-05.txt  */
#define POS_P_ASSERTED_SERV             42
	{ "P-Associated-URI",               NULL },  /*  43 RFC3455  */
#define POS_P_ASSOCIATED_URI            43
	{ "P-Called-Party-ID",              NULL },  /*  44 RFC3455  */
#define POS_P_CALLED_PARTY_ID           44
	{ "P-Charging-Function-Addresses",  NULL },/*  45 RFC3455  */
#define POS_P_CHARGING_FUNC_ADDRESSES   45
	{ "P-Charging-Vector",              NULL },  /*  46 RFC3455  */
#define POS_P_CHARGING_VECTOR           46
	{ "P-DCS-Trace-Party-ID",           NULL },  /*  47 RFC5503  */
#define POS_P_DCS_TRACE_PARTY_ID        47
	{ "P-DCS-OSPS",                     NULL },  /*  48 RFC5503  */
#define POS_P_DCS_OSPS                  48
	{ "P-DCS-Billing-Info",             NULL },  /*  49 RFC5503  */
#define POS_P_DCS_BILLING_INFO          49
	{ "P-DCS-LAES",                     NULL },  /*  50 RFC5503  */
#define POS_P_DCS_LAES                  50
	{ "P-DCS-Redirect",                 NULL },  /*  51 RFC5503  */
#define POS_P_DCS_REDIRECT              51
	{ "P-Early-Media",                  NULL },  /*  52 RFC5009  */
#define POS_P_EARLY_MEDIA               52
	{ "P-Media-Authorization",          NULL },  /*  53 RFC3313  */
#define POS_P_MEDIA_AUTHORIZATION       53
	{ "P-Preferred-Identity",           NULL },  /*  54 RFC3325  */
#define POS_P_PREFERRED_IDENTITY        54
	{ "P-Preferred-Service",            NULL },  /*  55 RFC-drage-sipping-service-identification-05.txt  */
#define POS_P_PREFERRED_SERV            55
	{ "P-Profile-Key",                  NULL },  /*  56 RFC5002  */
#define POS_P_PROFILE_KEY               56
	{ "P-Refused-URI-List",             NULL },  /*  57 RFC5318  */
#define POS_P_REFUSED_URI_LST           57
	{ "P-Served-User",                  NULL },  /*  58 RFC5502  */
#define POS_P_SERVED_USER               58
	{ "P-User-Database",                NULL },  /*  59 RFC4457  */
#define POS_P_USER_DATABASE             59
	{ "P-Visited-Network-ID",           NULL },  /*  60 RFC3455  */
#define POS_P_VISITED_NETWORK_ID        60
	{ "Path",                           NULL },  /*  61 RFC3327  */
#define POS_PATH                        61
	{ "Permission-Missing",             NULL },  /*  62 RFC5360  */
#define POS_PERMISSION_MISSING          62
	{ "Priority",                       NULL },  /*  63 RFC3261  */
#define POS_PRIORITY                    63
	{ "Priv-Answer-Mode",               NULL },  /*  64 RFC5373  */
#define POS_PRIV_ANSWER_MODE            64
	{ "Privacy",                        NULL },  /*  65 RFC3323  */
#define POS_PRIVACY                     65
	{ "Proxy-Authenticate",             NULL },  /*  66 */
#define POS_PROXY_AUTHENTICATE          66
	{ "Proxy-Authorization",            NULL },  /*  67 */
#define POS_PROXY_AUTHORIZATION         67
	{ "Proxy-Require",                  NULL },  /*  68 */
#define POS_PROXY_REQUIRE               68
	{ "RAck",                           NULL },  /*  69 RFC3262  */
#define POS_RACK                        69
	{ "Reason",                         NULL },  /*  70 RFC3326  */
#define POS_REASON                      70
	{ "Record-Route",                   NULL },  /*  71 */
#define POS_RECORD_ROUTE                71
	{ "Recv-Info",                      NULL },  /*  72 RFC-ietf-sipcore-info-events-10.txt*/
#define POS_RECV_INFO                   72
	{ "Refer-Sub",                      NULL },  /*  68 RFC4488  */
#define POS_REFER_SUB                   73
	{ "Refer-To",                       "r"  },  /*  69 RFC3515  */
#define POS_REFER_TO                    74
	{ "Referred-By",                    "b"  },  /*  70 RFC3892  */
#define POS_REFERED_BY                  75
	{ "Reject-Contact",                 "j"  },  /*  71 RFC3841  */
#define POS_REJECT_CONTACT              76
	{ "Replaces",                       NULL },  /*  72 RFC3891  */
#define POS_REPLACES                    77
	{ "Reply-To",                       NULL },  /*  73 RFC3261  */
#define POS_REPLY_TO                    78
	{ "Request-Disposition",            "d"  },  /*  74 RFC3841  */
#define POS_REQUEST_DISPOSITION         79
	{ "Require",                        NULL },  /*  75 RFC3261  */
#define POS_REQUIRE                     80
	{ "Resource-Priority",              NULL },  /*  76 RFC4412  */
#define POS_RESOURCE_PRIORITY           81
	/*{ "Response-Key (Deprecated)     [RFC3261]*/
	{ "Retry-After",                    NULL },  /*  77 RFC3261  */
#define POS_RETRY_AFTER                 82
	{ "Route",                          NULL },  /*  78 RFC3261  */
#define POS_ROUTE                       83
	{ "RSeq",                           NULL },  /*  79 RFC3262  */
#define POS_RSEQ                        84
	{ "Security-Client",                NULL },  /*  80 RFC3329  */
#define POS_SECURITY_CLIENT             85
	{ "Security-Server",                NULL },  /*  81 RFC3329  */
#define POS_SECURITY_SERVER             86
	{ "Security-Verify",                NULL },  /*  82 RFC3329  */
#define POS_SECURITY_VERIFY             87
	{ "Server",                         NULL },  /*  83 RFC3261  */
#define POS_SERVER                      88
	{ "Service-Route",                  NULL },  /*  84 RFC3608  */
#define POS_SERVICE_ROUTE               89
	{ "Session-Expires",                "x"  },  /*  85 RFC4028  */
#define POS_SESSION_EXPIRES             90
	{ "SIP-ETag",                       NULL },  /*  86 RFC3903  */
#define POS_SIP_ETAG                    91
	{ "SIP-If-Match",                   NULL },  /*  87 RFC3903  */
#define POS_SIP_IF_MATCH                92
	{ "Subject",                        "s"  },  /*  88 RFC3261  */
#define POS_SUBJECT                     93
	{ "Subscription-State",             NULL },  /*  89 RFC3265  */
#define POS_SUBSCRIPTION_STATE          94
	{ "Supported",                      "k"  },  /*  90 RFC3261  */
#define POS_SUPPORTED                   95
	{ "Target-Dialog",                  NULL },  /*  81 RFC4538  */
#define POS_TARGET_DALOG                96
	{ "Timestamp",                      NULL },  /*  92 RFC3261  */
#define POS_TIMESTAMP                   97
	{ "To",                             "t"  },  /*  93 RFC3261  */
#define POS_TO                          98
	{ "Trigger-Consent",                NULL },  /*  94 RFC5360  */
#define POS_TRIGGER_CONSENT             99
	{ "Unsupported",                    NULL },  /*  95 RFC3261  */
#define POS_UNSUPPORTED                 100
	{ "User-Agent",                     NULL },  /*  96 RFC3261  */
#define POS_USER_AGENT                  101
	{ "Via",                            "v"  },  /*  97 RFC3261  */
#define POS_VIA                         102
	{ "Warning",                        NULL },  /*  98 RFC3261  */
#define POS_WARNING                     103
	{ "WWW-Authenticate",               NULL },  /*  99 RFC3261  */
#define POS_WWW_AUTHENTICATE            104
	{ "Diversion",                      NULL },  /* 105 RFC5806  */
#define POS_DIVERSION                   105
	{ "User-to-User",                   NULL },  /* 106 draft-johnston-sipping-cc-uui-09  */
#define POS_USER_TO_USER                   106
};




static gint hf_header_array[] = {
	-1, /* 0"Unknown-header" - Pad so that the real headers start at index 1 */
	-1, /* 1"Accept"                                    */
	-1, /* 2"Accept-Contact"                    RFC3841 */
	-1, /* 3"Accept-Encoding"                           */
	-1, /* 4"Accept-Language"                           */
	-1, /* 5"Accept-Resource-Priority"          RFC4412 */
	-1, /* 6"Alert-Info",                               */
	-1, /* 7"Allow",                                    */
	-1, /* 8"Allow-Events",                     RFC3265 */
	-1, /* 9"Answer-Mode"                       RFC5373 */
	-1, /* 10"Authentication-Info"                      */
	-1, /* 11"Authorization",                           */
	-1, /* 12"Call-ID",                                 */
	-1, /* 13"Call-Info"                                */
	-1, /* 14"Contact",                                 */
	-1, /* 15"Content-Disposition",                     */
	-1, /* 16"Content-Encoding",                        */
	-1, /* 17"Content-Language",                        */
	-1, /* 18"Content-Length",                          */
	-1, /* 19"Content-Type",                            */
	-1, /* 20"CSeq",                                    */
	-1, /* 21"Date",                                    */
	-1, /* 22"Error-Info",                              */
	-1, /* 23"Event",                                   */
	-1, /* 24"Expires",                                 */
	-1, /* 25"From",                                    */
	-1, /* 26"Flow-Timer",                      RFC5626 */
	-1, /* 27"History-Info",                    RFC4244 */
	-1, /* 28"Identity",                                */
	-1, /* 29"Identity-Info",                   RFC4474 */
	-1, /* 30"Info-Package", RFC-ietf-sipcore-info-events-10.txt */
	-1, /* 31"In-Reply-To",                     RFC3261 */
	-1, /* 32"Join",                            RFC3911 */
	-1, /* 33"Max-Breadth"                      RFC5393 */
	-1, /* 34"Max-Forwards",                            */
	-1, /* 35"MIME-Version",                            */
	-1, /* 36"Min-Expires",                             */
	-1, /* 37"Min-SE",                          RFC4028 */
	-1, /* 38"Organization",                            */
	-1, /* 39"P-Access-Network-Info",           RFC3455 */
	-1, /* 40"P-Answer-State",                  RFC4964 */
	-1, /* 41"P-Asserted-Identity",             RFC3325 */
	-1, /* 42"P-Asserted-Service",  RFC-drage-sipping-service-identification-05.txt */
	-1, /* 43"P-Associated-URI",                RFC3455 */
	-1, /* 44"P-Called-Party-ID",               RFC3455 */
	-1, /* 45"P-Charging-Function-Addresses",   RFC3455 */
	-1, /* 46"P-Charging-Vector",               RFC3455 */
	-1, /* 47"P-DCS-Trace-Party-ID",            RFC3603 */
	-1, /* 48"P-DCS-OSPS",                      RFC3603 */
	-1, /* 49"P-DCS-Billing-Info",              RFC3603 */
	-1, /* 50"P-DCS-LAES",                      RFC3603 */
	-1, /* 51"P-DCS-Redirect",                  RFC3603 */
	-1, /* 52"P-Early-Media",                           */
	-1, /* 53"P-Media-Authorization",           RFC3313 */
	-1, /* 54"P-Preferred-Identity",            RFC3325 */
	-1, /* 55"P-Preferred-Service",  RFC-drage-sipping-service-identification-05.txt */
	-1, /* 56"P-Profile-Key",                           */
	-1, /* 57"P-Refused-URI-List",              RFC5318 */
	-1, /* 58"P-Served-User",                   RFC5502 */
	-1, /* 59"P-User-Database                   RFC4457 */
	-1, /* 60"P-Visited-Network-ID",            RFC3455 */
	-1, /* 61"Path",                            RFC3327 */
	-1, /* 62"Permission-Missing"               RFC5360 */
	-1, /* 63"Priority"                                 */
	-1, /* 64"Priv-Answer-mode"                 RFC5373 */
	-1, /* 65"Privacy",                         RFC3323 */
	-1, /* 66"Proxy-Authenticate",                      */
	-1, /* 67"Proxy-Authorization",                     */
	-1, /* 68"Proxy-Require",                           */
	-1, /* 69"RAck",                            RFC3262 */
	-1, /* 70"Reason",                          RFC3326 */
	-1, /* 71"Record-Route",                            */
	-1, /* 72"Recv-Info",   RFC-ietf-sipcore-info-events-10.txt */
	-1, /* 73"Refer-Sub",",                     RFC4488 */
	-1, /* 74"Refer-To",                        RFC3515 */
	-1, /* 75"Referred-By",                             */
	-1, /* 76"Reject-Contact",                  RFC3841 */
	-1, /* 77"Replaces",                        RFC3891 */
	-1, /* 78"Reply-To",                        RFC3261 */
	-1, /* 79"Request-Disposition",             RFC3841 */
	-1, /* 80"Require",                         RFC3261 */
	-1, /* 81"Resource-Priority",               RFC4412 */
	-1, /* 82"Retry-After",                     RFC3261 */
	-1, /* 83"Route",                           RFC3261 */
	-1, /* 84"RSeq",                            RFC3262 */
	-1, /* 85"Security-Client",                 RFC3329 */
	-1, /* 86"Security-Server",                 RFC3329 */
	-1, /* 87"Security-Verify",                 RFC3329 */
	-1, /* 88"Server",                          RFC3261 */
	-1, /* 89"Service-Route",                   RFC3608 */
	-1, /* 90"Session-Expires",                 RFC4028 */
	-1, /* 91"SIP-ETag",                        RFC3903 */
	-1, /* 92"SIP-If-Match",                    RFC3903 */
	-1, /* 93"Subject",                         RFC3261 */
	-1, /* 94"Subscription-State",              RFC3265 */
	-1, /* 95"Supported",                       RFC3261 */
	-1, /* 96"Target-Dialog",                   RFC4538 */
	-1, /* 97"Timestamp",                       RFC3261 */
	-1, /* 98"To",                              RFC3261 */
	-1, /* 99"Trigger-Consent"                  RFC5380 */
	-1, /* 100"Unsupported",                    RFC3261 */
	-1, /* 101"User-Agent",                     RFC3261 */
	-1, /* 102"Via",                            RFC3261 */
	-1, /* 103"Warning",                        RFC3261 */
	-1, /* 104"WWW-Authenticate",               RFC3261 */
	-1, /* 105"Diversion",                      RFC5806 */
	-1, /* 106"User-to-User",  draft-johnston-sipping-cc-uui-09 */

};

/* Track associations between parameter name and hf item */
typedef struct {
	const char  *param_name;
	const gint  *hf_item;
} header_parameter_t;

static header_parameter_t auth_parameters_hf_array[] =
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
	{"ik",              &hf_sip_auth_ik},
	{"ck",              &hf_sip_auth_ck}
};

static header_parameter_t via_parameters_hf_array[] =
{
	{"branch",        &hf_sip_via_branch},
	{"maddr",         &hf_sip_via_maddr},
	{"rport",         &hf_sip_via_rport},
	{"received",      &hf_sip_via_received},
	{"ttl",           &hf_sip_via_ttl},
	{"comp",          &hf_sip_via_comp},
	{"sigcomp-id",    &hf_sip_via_sigcomp_id}
};


typedef struct {
	gint *hf_sip_addr;
	gint *hf_sip_user;
	gint *hf_sip_host;
	gint *hf_sip_port;
	gint *ett_uri;
} hf_sip_uri_t;

static hf_sip_uri_t sip_pai_uri = {
	&hf_sip_pai_addr,
	&hf_sip_pai_user,
	&hf_sip_pai_host,
	&hf_sip_pai_port,
	&ett_sip_pai_uri
};

static hf_sip_uri_t sip_ppi_uri = {
	&hf_sip_ppi_addr,
	&hf_sip_ppi_user,
	&hf_sip_ppi_host,
	&hf_sip_ppi_port,
	&ett_sip_ppi_uri
};

static hf_sip_uri_t sip_pmiss_uri = {
	&hf_sip_pmiss_addr,
	&hf_sip_pmiss_user,
	&hf_sip_pmiss_host,
	&hf_sip_pmiss_port,
	&ett_sip_pmiss_uri
};


static hf_sip_uri_t sip_tc_uri = {
	&hf_sip_tc_addr,
	&hf_sip_tc_user,
	&hf_sip_tc_host,
	&hf_sip_tc_port,
	&ett_sip_tc_uri
};

static hf_sip_uri_t sip_to_uri = {
	&hf_sip_to_addr,
	&hf_sip_to_user,
	&hf_sip_to_host,
	&hf_sip_to_port,
	&ett_sip_to_uri
};

static hf_sip_uri_t sip_from_uri = {
	&hf_sip_from_addr,
	&hf_sip_from_user,
	&hf_sip_from_host,
	&hf_sip_from_port,
	&ett_sip_from_uri
};

static hf_sip_uri_t sip_req_uri = {
	&hf_sip_ruri,
	&hf_sip_ruri_user,
	&hf_sip_ruri_host,
	&hf_sip_ruri_port,
	&ett_sip_ruri
};

static hf_sip_uri_t sip_contact_uri = {
	&hf_sip_curi,
	&hf_sip_curi_user,
	&hf_sip_curi_host,
	&hf_sip_curi_port,
	&ett_sip_curi
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

/* Preferences */
static guint sip_tls_port = TLS_PORT_SIP;
static range_t *global_sip_tcp_port_range;

/* global_sip_raw_text determines whether we are going to display		*/
/* the raw text of the SIP message, much like the MEGACO dissector does.	*/
static gboolean global_sip_raw_text = FALSE;
/* global_sip_raw_text_without_crlf determines whether we are going to display	*/
/* the raw text of the SIP message with or without the '\r\n'.			*/
static gboolean global_sip_raw_text_without_crlf = FALSE;
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

/*
 * same source port for retransmissions
 */
static gboolean sip_retrans_the_same_sport = TRUE;

/* Extension header subdissectors */
static dissector_table_t ext_hdr_subdissector_table;

/* Forward declaration we need below */
void proto_reg_handoff_sip(void);
static gboolean dissect_sip_common(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree, gboolean is_heur, gboolean use_reassembly);
static line_type_t sip_parse_line(tvbuff_t *tvb, int offset, gint linelen,
    guint *token_1_len);
static gboolean sip_is_known_request(tvbuff_t *tvb, int meth_offset,
    guint meth_len, guint *meth_idx);
static gint sip_is_known_sip_header(gchar *header_name, guint header_len);
static void dfilter_sip_request_line(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint offset,
    guint meth_len, gint linelen);
static void dfilter_sip_status_line(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int line_end);
static void tvb_raw_text_add(tvbuff_t *tvb, int offset, int length, proto_tree *tree);
static guint sip_is_packet_resend(packet_info *pinfo,
				gchar* cseq_method,
				gchar* call_id,
				guchar cseq_number_set, guint32 cseq_number,
				line_type_t line_type);

static guint sip_find_request(packet_info *pinfo,
				gchar* cseq_method,
				gchar* call_id,
				guchar cseq_number_set, guint32 cseq_number,
				guint32 *response_time);

static guint sip_find_invite(packet_info *pinfo,
				gchar* cseq_method,
				gchar* call_id,
				guchar cseq_number_set, guint32 cseq_number,
				guint32 *response_time);

/* SIP content type and internet media type used by other dissectors
 * are the same.  List of media types from IANA at:
 * http://www.iana.org/assignments/media-types/index.html */
static dissector_table_t media_type_dissector_table;

static heur_dissector_list_t heur_subdissector_list;

#define SIP2_HDR "SIP/2.0"
#define SIP2_HDR_LEN 7

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
 *
 * N.B. This is broken for a couple of reasons:
 * - it won't cope properly with overlapping transactions within the
 *   same dialog
 * - request response mapping won't work where the response uses a different
 *   address pair from the request
 *
 * TODO: proper transaction matching uses RFC fields (use Max-forwards or
 * maybe Via count as extra key to limit view to one hop)
 ****************************************************************************/

static GHashTable *sip_hash = NULL;           /* Hash table */
static GHashTable *sip_headers_hash = NULL;		/* Hash table */

/* Types for hash table keys and values */
#define MAX_CALL_ID_SIZE 128
#define MAGIC_SOURCE_PORT 0

/* Conversation-type key */
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

/* Current conversation-type value */
typedef struct
{
	guint32             cseq;
	transaction_state_t transaction_state;
	gchar               method[MAX_CSEQ_METHOD_SIZE];
	nstime_t            request_time;
	guint32             response_code;
	gint                frame_number;
} sip_hash_value;

/* Result to be stored in per-packet info */
typedef struct
{
	gint       original_frame_num;
	gint       response_request_frame_num;
	gint       response_time;
} sip_frame_result_value;


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


/* Initializes the hash table and the mem_chunk area each time a new
 * file is loaded or re-loaded in wireshark */
static void
sip_init_protocol(void)
{
	 guint i;
	 gchar *value_copy;

	/* Destroy any existing hashes. */
	if (sip_hash)
		g_hash_table_destroy(sip_hash);

	/* Now create them again */
	sip_hash = g_hash_table_new(g_str_hash , sip_equal);
	/* Create a hashtable with the SIP headers; it will be used to find the related hf entry (POS_x).
	 * This is faster than the previously used for loop.
	 * There is no g_hash_table_destroy as the lifetime is the same as the lifetime of Wireshark.
	 */
	if(!sip_headers_hash){
		sip_headers_hash = g_hash_table_new(g_str_hash , g_str_equal);
		for (i = 1; i < array_length(sip_headers); i++){
			value_copy = g_strdup (sip_headers[i].name);
			/* Store (and compare) the string in lower case) */
			ascii_strdown_inplace(value_copy);
			g_hash_table_insert(sip_headers_hash, (gpointer)value_copy, GINT_TO_POINTER(i));
		}
	}
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
	gint uri_user_start;
	gint uri_user_end;
	gint uri_host_start;
	gint uri_host_end;
	gint uri_host_port_start;
	gint uri_host_port_end;
} uri_offset_info;

static void
sip_uri_offset_init(uri_offset_info *uri_offsets){

	/* Initialize the uri_offsets */
	uri_offsets->display_name_start = -1;
	uri_offsets->display_name_end = -1;
	uri_offsets->uri_start = -1;
	uri_offsets->uri_end = -1;
	uri_offsets->uri_parameters_start = -1;
	uri_offsets->uri_parameters_end = -1;
	uri_offsets->name_addr_start = -1;
	uri_offsets->name_addr_end = -1;
	uri_offsets->uri_user_start = -1;
	uri_offsets->uri_user_end = -1;
	uri_offsets->uri_host_start = -1;
	uri_offsets->uri_host_end = -1;
	uri_offsets->uri_host_port_start = -1;
	uri_offsets->uri_host_port_end = -1;

}
/* Code to parse a sip uri.
 * Returns Offset end off parsing or -1 for unsuccessful parsing
 * - sip_uri_offset_init() must have been called first.
 */
static gint
dissect_sip_uri(tvbuff_t *tvb, packet_info *pinfo _U_, gint start_offset,
                gint line_end_offset, uri_offset_info *uri_offsets)
{
	gchar c = '\0';
	gint current_offset;
	gint queried_offset;
	gint comma_offset;
	gint semicolon_offset;
	gint parameter_end_offset;
	gboolean in_ipv6 = FALSE;

	/* skip Spaces and Tabs */
	current_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

	if(current_offset >= line_end_offset) {
		/* Nothing to parse */
		return -1;
	}
	/* Set uri start offset in case this was called directly */
	uri_offsets->uri_start = current_offset;

	/* Check if it's realy a sip uri ( it might be a tel uri, parse that?) */
	queried_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ':');
	if (tvb_strneql(tvb, current_offset, "sip", 3) != 0)
		return -1;

	if(uri_offsets->uri_end == -1)
	{
		/* name-addr form was NOT used e.g no closing ">" */
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
			else if (comma_offset != -1)
			{
				uri_offsets->uri_end = comma_offset - 1;
			} else {

				/* If both offsets are equal to -1, we don't have a semicolon or a comma.
			 	* In that case, we assume that the end of the URI is at the line end
				 */
				uri_offsets->uri_end = line_end_offset - 3; /* remove '\r\n' */
			}
		}
		uri_offsets->name_addr_end = uri_offsets->uri_end;
	}

	/* Look for URI address parts (user, host, host-port) */

	/* Look for '@' within URI */
	queried_offset = tvb_find_guint8(tvb, uri_offsets->uri_start, uri_offsets->uri_end - uri_offsets->uri_start, '@');
	if(queried_offset == -1)
	{
		/* no '@' = no user part */
		uri_offsets->uri_host_start = tvb_find_guint8(tvb, uri_offsets->uri_start, uri_offsets->uri_end - uri_offsets->uri_start, ':')+1;
	}
	else
	{
		/* with '@' = with user part */
		uri_offsets->uri_user_start = tvb_find_guint8(tvb, uri_offsets->uri_start, uri_offsets->uri_end - uri_offsets->uri_start, ':')+1;
		uri_offsets->uri_user_end = tvb_find_guint8(tvb, uri_offsets->uri_user_start, uri_offsets->uri_end - uri_offsets->uri_start, '@')-1;
		uri_offsets->uri_host_start = uri_offsets->uri_user_end + 2;
	}

	/* find URI-Host end*/
	parameter_end_offset = uri_offsets->uri_host_start;

	in_ipv6 = (tvb_get_guint8(tvb, parameter_end_offset) == '[');
	while (parameter_end_offset < line_end_offset)
	{
			parameter_end_offset++;
			c = tvb_get_guint8(tvb, parameter_end_offset);
			switch (c) {
				case '>':
				case ',':
				case ';':
				case '?':
				case ' ':
				case '\r':
					goto uri_host_end_found;
				case ':':
					if (!in_ipv6)
						goto uri_host_end_found;
					break;
				case '[':
					in_ipv6 = TRUE;
					break;
				case ']':
					in_ipv6 = FALSE;
					break;
				default :
				break;
				}
	}

	uri_host_end_found:

		uri_offsets->uri_host_end = parameter_end_offset - 1;

		if (c == ':')
		{
			uri_offsets->uri_host_port_start = parameter_end_offset + 1;
			parameter_end_offset = uri_offsets->uri_host_port_start;
				while (parameter_end_offset < line_end_offset)
				{
						parameter_end_offset++;
						c = tvb_get_guint8(tvb, parameter_end_offset);
						switch (c) {
							case '>':
							case ',':
							case ';':
							case '?':
							case ' ':
							case '\r':
								goto uri_host_port_end_found;
							default :
							break;
						}
				}

			uri_host_port_end_found:

			uri_offsets->uri_host_port_end = parameter_end_offset -1;
		}
		return uri_offsets->name_addr_end;
}
/*
 *  token         =  1*(alphanum / "-" / "." / "!" / "%" / "*"
 *                    / "_" / "+" / "`" / "'" / "~" )
 *  LWS           =  [*WSP CRLF] 1*WSP ; linear whitespace
 *  name-addr     =  [ display-name ] LAQUOT addr-spec RAQUOT
 *  addr-spec     =  SIP-URI / SIPS-URI / absoluteURI
 *  display-name  =  *(token LWS)/ quoted-string
 */

static gint
dissect_sip_name_addr_or_addr_spec(tvbuff_t *tvb, packet_info *pinfo _U_, gint start_offset,
                gint line_end_offset, uri_offset_info *uri_offsets)
{
	gchar c;
	gint i;
	gint current_offset;
	gint queried_offset;
	gint colon_offset;
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
	/* Start of URI */
	uri_offsets->uri_start = current_offset;
	if(uri_without_angle_quotes==FALSE){
		/* name-addr form was used */
		/* look for closing angle quote */
		queried_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, '>');
		if(queried_offset == -1)
		{
			/* malformed Uri */
			return -1;
		}
		uri_offsets->name_addr_end = queried_offset;
		uri_offsets->uri_end = queried_offset - 1;
	}
	return dissect_sip_uri(tvb, pinfo, current_offset, line_end_offset, uri_offsets);
}


/*
* Code to add dissected SIP URI Information to proto tree
*/

static proto_tree *
display_sip_uri (tvbuff_t *tvb, proto_tree *sip_element_tree, uri_offset_info* uri_offsets, hf_sip_uri_t* uri)
{

	proto_item *ti;
	proto_tree *uri_item_tree = NULL;

	if(uri_offsets->display_name_end != uri_offsets->display_name_start) {
		proto_tree_add_item(sip_element_tree, hf_sip_display, tvb, uri_offsets->display_name_start,
		  		    uri_offsets->display_name_end - uri_offsets->display_name_start + 1, FALSE);
	}

	ti = proto_tree_add_item(sip_element_tree, *(uri->hf_sip_addr), tvb, uri_offsets->uri_start, uri_offsets->uri_end - uri_offsets->uri_start + 1, FALSE);
	uri_item_tree = proto_item_add_subtree(ti, *(uri->ett_uri));

	if(uri_offsets->uri_user_end > uri_offsets->uri_user_start) {
		proto_tree_add_item(uri_item_tree, *(uri->hf_sip_user), tvb, uri_offsets->uri_user_start,
		     		    uri_offsets->uri_user_end - uri_offsets->uri_user_start + 1, FALSE);
	}

	proto_tree_add_item(uri_item_tree, *(uri->hf_sip_host), tvb, uri_offsets->uri_host_start,
	 		    uri_offsets->uri_host_end - uri_offsets->uri_host_start + 1, FALSE);

	if(uri_offsets->uri_host_port_end > uri_offsets->uri_host_port_start) {
		proto_tree_add_item(uri_item_tree, *(uri->hf_sip_port), tvb, uri_offsets->uri_host_port_start,
				uri_offsets->uri_host_port_end - uri_offsets->uri_host_port_start + 1, FALSE);
	}

	return uri_item_tree;
}




/* Code to parse a contact header item
 * Returns Offset end off parsing or -1 for unsuccessful parsing
 * * contact-param  =  (name-addr / addr-spec) *(SEMI contact-params)
 */
static gint
dissect_sip_contact_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint start_offset, gint line_end_offset)
{
	gchar c;
	gint current_offset;
	gint queried_offset;
	gint contact_params_start_offset = -1;
	gint contact_param_end_offset = -1;
	uri_offset_info uri_offsets;

	/* skip Spaces and Tabs */
	start_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

	if(start_offset >= line_end_offset) {
		/* Nothing to parse */
		return -1;
	}
	queried_offset = tvb_find_guint8(tvb, start_offset , line_end_offset - start_offset, ';');
	if(queried_offset == -1){
		queried_offset = line_end_offset;
	}else{
		/* skip Spaces and Tabs */
		contact_params_start_offset = tvb_skip_wsp(tvb, queried_offset+1, line_end_offset - queried_offset+1);
	}
	/* Initialize the uri_offsets */
	sip_uri_offset_init(&uri_offsets);
	/* contact-param  =  (name-addr / addr-spec) *(SEMI contact-params) */
	current_offset = dissect_sip_name_addr_or_addr_spec(tvb, pinfo, start_offset, line_end_offset, &uri_offsets);
	display_sip_uri(tvb, tree, &uri_offsets, &sip_contact_uri);
	if(current_offset == -1)
	{
		/* Parsing failed */
		return -1;
	}
	/* check if contact-params is present */
	if(contact_params_start_offset == -1)
		return line_end_offset;

	/* Move current offset to the start of the first param */
	current_offset = contact_params_start_offset;

	/* Put the contact parameters in the tree */

	while(current_offset< line_end_offset){
		queried_offset = tvb_pbrk_guint8(tvb, current_offset, line_end_offset - current_offset, ",;", &c);
		if(queried_offset == -1){
			/* Reached line end */
			contact_param_end_offset = line_end_offset - 3;
			current_offset = line_end_offset;
		}else if(c==','){
			/* More contacts, make this the line end for this contact */
			line_end_offset = queried_offset;
			contact_param_end_offset = queried_offset;
			current_offset =  queried_offset;
		}else if (c==';'){
			/* More parameters */
			contact_param_end_offset = queried_offset-1;
			current_offset = tvb_skip_wsp(tvb, queried_offset+1, line_end_offset - queried_offset+1);
		}
		proto_tree_add_item(tree, hf_sip_contact_param, tvb, contact_params_start_offset ,
			contact_param_end_offset - contact_params_start_offset +1, FALSE);
		/* In case there are more parameters, point to the start of it */
		contact_params_start_offset = current_offset;
	}


	return current_offset;
}

/* Code to parse an authorization header item
 * Returns offset at end of parsing, or -1 for unsuccessful parsing
 */
static gint
dissect_sip_authorization_item(tvbuff_t *tvb, proto_tree *tree, gint start_offset, gint line_end_offset)
{
	gint current_offset, par_name_end_offset;
	gint equals_offset = 0;
	gchar *name;
	header_parameter_t *auth_parameter;
	guint i = 0;

	/* skip Spaces and Tabs */
	start_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

	if (start_offset >= line_end_offset)
	{
		/* Nothing to parse */
		return -1;
	}

	current_offset = start_offset;
	equals_offset = tvb_find_guint8(tvb, current_offset + 1, line_end_offset - (current_offset + 1), '=');
	if(current_offset == -1){
		/* malformed parameter */
		return -1;
	}
	par_name_end_offset = equals_offset - 1;
	par_name_end_offset = tvb_skip_wsp_return(tvb,par_name_end_offset);

	/* Extract the parameter name */
	name = tvb_get_ephemeral_string(tvb, start_offset, par_name_end_offset-start_offset+1);
	current_offset =  tvb_find_guint8(tvb, par_name_end_offset, line_end_offset - par_name_end_offset, ',');
	if(current_offset==-1)
		/* Last parameter, line end */
		current_offset = line_end_offset;

	/* Try to add parameter as a filterable item */
	for (auth_parameter = &auth_parameters_hf_array[i];
	     i < array_length(auth_parameters_hf_array);
	     i++, auth_parameter++)
	{
		if (g_ascii_strcasecmp(name, auth_parameter->param_name) == 0)
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

/* Dissect the details of a Reason header */
static void
dissect_sip_reason_header(tvbuff_t *tvb, proto_tree *tree, gint start_offset, gint line_end_offset){

	gint  current_offset, semi_colon_offset, length;
	gchar *param_name = NULL;
	guint cause_value;

		/* skip Spaces and Tabs */
	start_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

	if (start_offset >= line_end_offset)
	{
		/* Nothing to parse */
		return;
	}

	current_offset = start_offset;
	semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset-current_offset, ';');
	length = semi_colon_offset - current_offset;
	proto_tree_add_text(tree, tvb, start_offset, length,
		"Reason Protocols: %s", tvb_format_text(tvb, start_offset, length));

	param_name = tvb_get_ephemeral_string(tvb, start_offset, length);
	if (g_ascii_strcasecmp(param_name, "Q.850") == 0){
		current_offset = tvb_find_guint8(tvb, semi_colon_offset, line_end_offset-semi_colon_offset, '=')+1;
		length = line_end_offset - current_offset;

		/* q850_cause_code_vals */
		cause_value = atoi(tvb_get_ephemeral_string(tvb, current_offset, length));
		proto_tree_add_text(tree, tvb, current_offset, length,
			"Cause: %u(0x%x)[%s]", cause_value,cause_value,
			val_to_str_ext(cause_value, &q850_cause_code_vals_ext, "Unknown (%d)" ));

	}

}


/* Dissect the details of a Via header */
static void dissect_sip_via_header(tvbuff_t *tvb, proto_tree *tree, gint start_offset, gint line_end_offset)
{
	gint  current_offset;
	gint  transport_start_offset;
	gint  address_start_offset;
	gint  semicolon_offset;
	guint transport_slash_count;
	gboolean transport_name_started;
	gboolean colon_seen;
	gboolean ipv6_reference;
	gboolean ipv6_address;
	guchar c;
	gchar *param_name = NULL;

	current_offset = start_offset;

	while (1)
	{
		/* Reset flags and counters */
		transport_start_offset = 0;
		semicolon_offset = 0;
		transport_name_started = FALSE;
		transport_slash_count = 0;
		ipv6_reference = FALSE;
		ipv6_address = FALSE;
		colon_seen = FALSE;

		/* skip Spaces and Tabs */
		current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

		if (current_offset >= line_end_offset)
		{
			/* Nothing more to parse */
			return;
		}

		/* Now look for the end of the SIP/2.0/transport parameter.
		   There may be spaces between the slashes */
		while (current_offset < line_end_offset)
		{
			c = tvb_get_guint8(tvb, current_offset);
			if (c == '/')
			{
				transport_slash_count++;
			}
			else
			if (!transport_name_started && (transport_slash_count == 2) && isalpha(c))
			{
				transport_name_started = TRUE;
				transport_start_offset = current_offset;
			}
			else
			if (transport_name_started && ((c == ' ') || (c == '\t')))
			{
				proto_tree_add_item(tree, hf_sip_via_transport, tvb, transport_start_offset,
									current_offset - transport_start_offset, FALSE);

				break;
			}

			current_offset++;
		}

		/* skip Spaces and Tabs */
		current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

		/* Now read the address part */
		address_start_offset = current_offset;
		while (current_offset < line_end_offset)
		{
			c = tvb_get_guint8(tvb, current_offset);

			if (c == '[') {
				ipv6_reference = TRUE;
				ipv6_address = TRUE;
			}
			else if (c == ']')
			{
				ipv6_reference = FALSE;
			}

			if (colon_seen || (c == ' ') || (c == '\t') || ((c == ':') && (ipv6_reference == FALSE)) || (c == ';'))
			{
				break;
			}

			current_offset++;
		}
		/* Add address to tree */
		if (ipv6_address == TRUE) {
			proto_tree_add_item(tree, hf_sip_via_sent_by_address, tvb, address_start_offset + 1,
								current_offset - address_start_offset - 2, FALSE);
		} else {
			proto_tree_add_item(tree, hf_sip_via_sent_by_address, tvb, address_start_offset,
								current_offset - address_start_offset, FALSE);
		}

		/* Transport port number may follow ([space] : [space])*/
		current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);
		c = tvb_get_guint8(tvb, current_offset);

		if (c == ':')
		{
			/* Port number will follow any space after : */
			gint port_offset;
			colon_seen = TRUE;
			current_offset++;

			/* Skip optional space after colon */
			current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

			port_offset = current_offset;

			/* Find digits of port number */
			while (current_offset < line_end_offset)
			{
				c = tvb_get_guint8(tvb, current_offset);

				if (!isdigit(c))
				{
					if (current_offset > port_offset)
					{
						/* Add address port number to tree */
						proto_tree_add_uint(tree, hf_sip_via_sent_by_port, tvb, port_offset,
											current_offset - port_offset,
											atoi(tvb_get_ephemeral_string(tvb, port_offset,
																		  current_offset - port_offset)));
					}
					else
					{
						/* Shouldn't see a colon without a port number given */
						return;
					}
					break;
				}

				current_offset++;
			}
		}

		/* skip Spaces and Tabs */
		current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);


		/* Dissect any parameters found */
		while (current_offset < line_end_offset)
		{
			gboolean equals_found = FALSE;
			gboolean found_end_of_parameters = FALSE;
			gint parameter_name_end = 0;
			header_parameter_t *via_parameter;
			guint i = 0;

			/* Look for the semicolon that signals the start of a parameter */
			while (current_offset < line_end_offset)
			{
				c = tvb_get_guint8(tvb, current_offset);
				if (c == ';')
				{
					semicolon_offset = current_offset;
					current_offset++;
					break;
				}
				else
				if ((c != ' ') && (c != '\t'))
				{
					found_end_of_parameters = TRUE;
					break;
				}
				current_offset++;
			}

			if (found_end_of_parameters)
			{
				break;
			}

			if (current_offset == line_end_offset)
			{
				return;
			}

			/* Look for end of parameter name */
			while (current_offset < line_end_offset)
			{
				c = tvb_get_guint8(tvb, current_offset);
				if (!isalpha(c) && (c != '-'))
				{
					break;
				}
				current_offset++;
			}

			/* Not all params have an = */
			if (c == '=')
			{
				equals_found = TRUE;
			}
			parameter_name_end = current_offset;

			/* Read until end of parameter value */
			while (current_offset < line_end_offset)
			{
				c = tvb_get_guint8(tvb, current_offset);
				if ((c == ' ') || (c == '\t') || (c == ';') || (c == ','))
				{
					break;
				}
				current_offset++;
			}

			/* Note parameter name */
			param_name = tvb_get_ephemeral_string(tvb, semicolon_offset+1,
												  parameter_name_end - semicolon_offset - 1);

			/* Try to add parameter as a filterable item */
			for (via_parameter = &via_parameters_hf_array[i];
				 i < array_length(via_parameters_hf_array);
				 i++, via_parameter++)
			{
				if (g_ascii_strcasecmp(param_name, via_parameter->param_name) == 0)
				{
					if (equals_found)
					{
						proto_tree_add_item(tree, *(via_parameter->hf_item), tvb,
											parameter_name_end+1, current_offset-parameter_name_end-1,
											FALSE);
					}
					else
					{
						proto_tree_add_item(tree, *(via_parameter->hf_item), tvb,
											semicolon_offset+1, current_offset-semicolon_offset-1,
											FALSE);
					}
					break;
				}
			}

			/* If not matched, just add as text... */
			if (i == array_length(via_parameters_hf_array))
			{
				proto_tree_add_text(tree, tvb, semicolon_offset+1, current_offset-semicolon_offset-1,
									"%s", tvb_format_text(tvb, semicolon_offset+1,
									current_offset-semicolon_offset-1));
			}

			/* skip Spaces and Tabs */
			current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

			/* There may be a comma, followed by more Via entries... */
			if (current_offset < line_end_offset)
			{
				c = tvb_get_guint8(tvb, current_offset);
				if (c == ',')
				{
					/* Skip it and get out of parameter loop */
					current_offset++;
					break;
				}
			}
		}
	}
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
	guint current_method_idx = SIP_METHOD_INVALID;
	proto_item *ts = NULL, *ti_a = NULL, *th = NULL, *sip_element_item = NULL;
	proto_tree *sip_tree = NULL, *reqresp_tree = NULL , *hdr_tree = NULL,
		*sip_element_tree = NULL, *message_body_tree = NULL, *cseq_tree = NULL,
		*via_tree = NULL, *reason_tree = NULL, *rack_tree = NULL;
	guchar contacts = 0, contact_is_star = 0, expires_is_0 = 0;
	guint32 cseq_number = 0;
	guchar  cseq_number_set = 0;
	char    cseq_method[MAX_CSEQ_METHOD_SIZE] = "";
	char	call_id[MAX_CALL_ID_SIZE] = "";
	gchar  *media_type_str_lower_case = NULL;
	char   *content_type_parameter_str = NULL;
	guint   resend_for_packet = 0;
	guint   request_for_response = 0;
	guint32 response_time = 0;
	int     strlen_to_copy;


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
	} else if ((use_reassembly)&&( pinfo->ptype == PT_TCP)) {
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

	/* Initialise stat info for passing to tap */
	stat_info = ep_alloc0(sizeof(sip_info_value_t));

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIP");

	switch (line_type) {

	case REQUEST_LINE:
		is_known_request = sip_is_known_request(tvb, offset, token_1_len, &current_method_idx);
		descr = is_known_request ? "Request" : "Unknown request";
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s: %s",
		             descr,
		             tvb_format_text(tvb, offset, linelen - SIP2_HDR_LEN - 1));
		break;

	case STATUS_LINE:
		descr = "Status";
		col_add_fstr(pinfo->cinfo, COL_INFO, "Status: %s",
		             tvb_format_text(tvb, offset + SIP2_HDR_LEN + 1, linelen - SIP2_HDR_LEN - 1));
		stat_info->reason_phrase = tvb_get_ephemeral_string(tvb, offset + SIP2_HDR_LEN + 5, linelen - (SIP2_HDR_LEN + 5));
		break;

	case OTHER_LINE:
	default: /* Squelch compiler complaints */
		descr = "Continuation";
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
			ti_a = proto_tree_add_item(sip_tree, hf_Request_Line, tvb,
						offset, linelen, FALSE);

			reqresp_tree = proto_item_add_subtree(ti_a, ett_sip_reqresp);
		}
		dfilter_sip_request_line(tvb, reqresp_tree, pinfo, offset, token_1_len, linelen);
		break;

	case STATUS_LINE:
		if (sip_tree) {
			ti_a = proto_tree_add_item(sip_tree, hf_sip_Status_Line, tvb,
						offset, linelen, FALSE);
			reqresp_tree = proto_item_add_subtree(ti_a, ett_sip_reqresp);
		}
		dfilter_sip_status_line(tvb, reqresp_tree, pinfo, linelen);
		break;

	case OTHER_LINE:
		if (sip_tree) {
			ti_a = proto_tree_add_text(sip_tree, tvb, offset, next_offset,
			                         "%s line: %s", descr,
			                         tvb_format_text(tvb, offset, linelen));
			reqresp_tree = proto_item_add_subtree(ti_a, ett_sip_reqresp);
			/* XXX: Is adding to 'reqresp_tree as intended ? Changed from original 'sip_tree' */
			proto_tree_add_text(reqresp_tree, tvb, offset, -1, "Continuation data");
		}
		return tvb_length_remaining(tvb, offset);
	}

	offset = next_offset;
	if (sip_tree) {
		th = proto_tree_add_item(sip_tree, hf_sip_msg_hdr, tvb, offset,
		                         tvb_length_remaining(tvb, offset), FALSE);
		proto_item_set_text(th, "Message Header");
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
		gint parameter_offset;
		gint parameter_end_offset;
		gint parameter_len;
		gint content_type_len, content_type_parameter_str_len;
		gint header_len;
		gchar *header_name;
		dissector_handle_t ext_hdr_handle;
		gint hf_index;
		gint value_offset;
		gint sub_value_offset;
		gint comma_offset;
		guchar c;
		gint value_len;
		char *value;
		gboolean is_no_header_termination = FALSE;
		proto_item *cause;
		proto_tree *tc_uri_item_tree = NULL;
		uri_offset_info uri_offsets;





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
		if(tvb_reported_length_remaining(tvb, next_offset) == 0){
			is_no_header_termination = TRUE;
		}else{
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
			header_name = (gchar*)tvb_get_ephemeral_string(tvb, offset, header_len);
			ascii_strdown_inplace(header_name);
			hf_index = sip_is_known_sip_header(header_name, header_len);

			/*
			 * Skip whitespace after the colon.
			 */
			value_offset = tvb_skip_wsp(tvb, colon_offset + 1, line_end_offset - (colon_offset + 1));

			/*
			 * Fetch the value.
			 */
			value_len = (gint) (line_end_offset - value_offset);
			value = tvb_get_ephemeral_string(tvb, value_offset, value_len);

			if (hf_index == -1) {
				proto_item *ti_c = proto_tree_add_text(hdr_tree, tvb,
				                                     offset, next_offset - offset, "%s",
				                                     tvb_format_text(tvb, offset, linelen));
				ext_hdr_handle = dissector_get_string_handle(ext_hdr_subdissector_table, header_name);
				if (ext_hdr_handle != NULL) {
					tvbuff_t *next_tvb2;
					next_tvb2 = tvb_new_subset(tvb, value_offset, value_len, value_len);
					dissector_try_string(ext_hdr_subdissector_table, header_name, next_tvb2, pinfo, proto_item_add_subtree(ti_c, ett_sip_ext_hdr));
 				} else {
					expert_add_info_format(pinfo, ti_c,
					                       PI_UNDECODED, PI_NOTE,
					                       "Unrecognised SIP header (%s)",
					                       tvb_format_text(tvb, offset, header_len));
				}
			} else {
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
							/* To        =  ( "To" / "t" ) HCOLON ( name-addr
							 *               / addr-spec ) *( SEMI to-param )
							 */
							sip_uri_offset_init(&uri_offsets);
							if((dissect_sip_name_addr_or_addr_spec(tvb, pinfo, value_offset, line_end_offset+2, &uri_offsets)) != -1){
								display_sip_uri(tvb, sip_element_tree, &uri_offsets, &sip_to_uri);
								if((uri_offsets.name_addr_start != -1) && (uri_offsets.name_addr_end != -1)){
									stat_info->tap_to_addr=tvb_get_ephemeral_string(tvb, uri_offsets.name_addr_start,
										uri_offsets.name_addr_end - uri_offsets.name_addr_start);
								}
								offset = uri_offsets.name_addr_end +1;
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
								/* Tag indicates in-dialog messages, in case we have a INVITE, SUBSCRIBE or REFER, mark it */
								switch (current_method_idx) {

								case SIP_METHOD_INVITE:
								case SIP_METHOD_SUBSCRIBE:
								case SIP_METHOD_REFER:
									col_append_str(pinfo->cinfo, COL_INFO, ", in-dialog");
									break;
								}
							}
						} /* if hdr_tree */
					break;

					case POS_FROM :
						if(hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   value, "%s",
							                   tvb_format_text(tvb, offset, linelen));
							sip_element_tree = proto_item_add_subtree( sip_element_item, ett_sip_element);
							/*
							 * From        =  ( "From" / "f" ) HCOLON from-spec
							 * from-spec   =  ( name-addr / addr-spec )
							 *                *( SEMI from-param )
							 */

							sip_uri_offset_init(&uri_offsets);
							if((dissect_sip_name_addr_or_addr_spec(tvb, pinfo, value_offset, line_end_offset+2, &uri_offsets)) != -1){
								display_sip_uri(tvb, sip_element_tree, &uri_offsets, &sip_from_uri);
								if((uri_offsets.name_addr_start != -1) && (uri_offsets.name_addr_end != -1)){
									stat_info->tap_from_addr=tvb_get_ephemeral_string(tvb, uri_offsets.name_addr_start,
										uri_offsets.name_addr_end - uri_offsets.name_addr_start);
								}
								offset = uri_offsets.name_addr_end +1;
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
						}/* hdr_tree */
					break;

					case POS_P_ASSERTED_IDENTITY :
						if(hdr_tree)
						{
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   value, "%s",
							                   tvb_format_text(tvb, offset, linelen));
							sip_element_tree = proto_item_add_subtree( sip_element_item,
							                   ett_sip_element);

							/*
							 * PAssertedID = "P-Asserted-Identity" HCOLON PAssertedID-value
							 *                *(COMMA PAssertedID-value)
							 * PAssertedID-value = name-addr / addr-spec
							 *
							 * Initialize the uri_offsets
							 */
							sip_uri_offset_init(&uri_offsets);
							if((dissect_sip_name_addr_or_addr_spec(tvb, pinfo, value_offset, line_end_offset+2, &uri_offsets)) != -1)
								 display_sip_uri(tvb, sip_element_tree, &uri_offsets, &sip_pai_uri);
						}
						break;

					case POS_P_CHARGING_FUNC_ADDRESSES:
						if(hdr_tree)
						{
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   value, "%s",
							                   tvb_format_text(tvb, offset, linelen));
							sip_element_tree = proto_item_add_subtree( sip_element_item,
							                   ett_sip_element);
						}
						break;

					case POS_P_PREFERRED_IDENTITY :
						if(hdr_tree)
						{
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   value, "%s",
							                   tvb_format_text(tvb, offset, linelen));
							sip_element_tree = proto_item_add_subtree( sip_element_item,
							                   ett_sip_element);
							/*
							 * PPreferredID = "P-Preferred-Identity" HCOLON PPreferredID-value
							 *                   *(COMMA PPreferredID-value)
							 * PPreferredID-value = name-addr / addr-spec
							 *
							 * Initialize the uri_offsets
							 */
							sip_uri_offset_init(&uri_offsets);
							if((dissect_sip_name_addr_or_addr_spec(tvb, pinfo, value_offset, line_end_offset+2, &uri_offsets)) != -1)
								 display_sip_uri(tvb, sip_element_tree, &uri_offsets, &sip_ppi_uri);
						}
						break;

					case POS_PERMISSION_MISSING :
						if(hdr_tree)
						{
							sip_element_item = proto_tree_add_string_format(hdr_tree,
								               hf_header_array[hf_index], tvb,
								               offset, next_offset - offset,
								               value, "%s",
								               tvb_format_text(tvb, offset, linelen));

							sip_element_tree = proto_item_add_subtree( sip_element_item,
														           ett_sip_element);
							/*
							 * Permission-Missing  =  "Permission-Missing" HCOLON per-miss-spec
							 *                        *( COMMA per-miss-spec )
							 * per-miss-spec       =  ( name-addr / addr-spec )
							 *                       *( SEMI generic-param )
							 * Initialize the uri_offsets
							 */
							sip_uri_offset_init(&uri_offsets);
							if((dissect_sip_name_addr_or_addr_spec(tvb, pinfo, value_offset, line_end_offset+2, &uri_offsets)) != -1)
								 display_sip_uri(tvb, sip_element_tree, &uri_offsets, &sip_pmiss_uri);
						}
						break;


					case POS_TRIGGER_CONSENT :
						if(hdr_tree)
						{
							sip_element_item = proto_tree_add_string_format(hdr_tree,
										       hf_header_array[hf_index], tvb,
										       offset, next_offset - offset,
										       value, "%s",
										       tvb_format_text(tvb, offset, linelen));

							sip_element_tree = proto_item_add_subtree( sip_element_item,
																		ett_sip_element);
							/*
							 * Trigger-Consent     =  "Trigger-Consent" HCOLON trigger-cons-spec
							 *                        *( COMMA trigger-cons-spec )
							 * trigger-cons-spec   =  ( SIP-URI / SIPS-URI )
							 *                        *( SEMI trigger-param )
							 * trigger-param       =  target-uri / generic-param
							 * target-uri          =  "target-uri" EQUAL
							 *                            LDQUOT *( qdtext / quoted-pair ) RDQUOT
							 * Initialize the uri_offsets
							 */
							sip_uri_offset_init(&uri_offsets);
							if((dissect_sip_uri(tvb, pinfo, value_offset, line_end_offset+2, &uri_offsets)) != -1) {

								tc_uri_item_tree = display_sip_uri(tvb, sip_element_tree, &uri_offsets, &sip_tc_uri);
								if (line_end_offset > uri_offsets.uri_end) {
									gint hparam_offset = uri_offsets.uri_end + 1;
									/* Is there a header parameter */
									if (tvb_find_guint8(tvb, hparam_offset, 1,';')) {
										while ((hparam_offset != -1 && hparam_offset < line_end_offset) )  {
											/* Is this a target-uri ? */
											hparam_offset = hparam_offset + 1;
											if (tvb_strncaseeql(tvb, hparam_offset, "target-uri=\"", 12) == 0) {
												gint turi_start_offset = hparam_offset + 12;
												gint turi_end_offset   = tvb_find_guint8(tvb, turi_start_offset, -1,'\"');
												if (turi_end_offset != -1)
													proto_tree_add_item(tc_uri_item_tree, hf_sip_tc_turi, tvb, turi_start_offset,(turi_end_offset - turi_start_offset),FALSE);
												else
							 						break; /* malformed */
											}
											hparam_offset = tvb_find_guint8(tvb, hparam_offset, -1,';');
										}
									}
								}
							}
						}/* hdr_tree */
						break;

					case POS_CSEQ :
						/* Store the sequence number */
						cseq_number = atoi(value);
						cseq_number_set = 1;
						stat_info->tap_cseq_number=cseq_number;

						/* Add CSeq  tree */
						if (hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
							cseq_tree = proto_item_add_subtree(sip_element_item, ett_sip_cseq);
						}

						/* Walk past number and spaces characters to get to start
						   of method name */
						for (sub_value_offset=0; sub_value_offset < value_len; sub_value_offset++)
						{
							if (!isdigit((guchar)value[sub_value_offset]))
							{
								proto_tree_add_uint(cseq_tree, hf_sip_cseq_seq_no,
								                    tvb, value_offset, sub_value_offset,
								                    cseq_number);
								break;
							}
						}

						for (; sub_value_offset < value_len; sub_value_offset++)
						{
							if (isalpha((guchar)value[sub_value_offset]))
							{
								/* Have reached start of method name */
								break;
							}
						}

						if (sub_value_offset == value_len)
						{
							/* Didn't find method name */
							THROW(ReportedBoundsError);
							return offset - orig_offset;
						}

						/* Extract method name from value */
						strlen_to_copy = (int)value_len-sub_value_offset;
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
							g_strlcpy(cseq_method, value+sub_value_offset, MAX_CSEQ_METHOD_SIZE);

							/* Add CSeq method to the tree */
							if (cseq_tree)
							{
								proto_tree_add_item(cseq_tree, hf_sip_cseq_method, tvb,
								                    value_offset + sub_value_offset, strlen_to_copy, FALSE);
							}
						}
					break;

					case POS_RACK :
					{
						int cseq_no_offset;
						/*int cseq_method_offset;*/

						/* Add RAck  tree */
						if (hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
							rack_tree = proto_item_add_subtree(sip_element_item, ett_sip_rack);
						}

						/* RSeq number */
						for (sub_value_offset=0; sub_value_offset < value_len; sub_value_offset++)
						{
							if (!isdigit((guchar)value[sub_value_offset]))
							{
								proto_tree_add_uint(rack_tree, hf_sip_rack_rseq_no,
								                    tvb, value_offset, sub_value_offset,
								                    atoi(value));
								break;
							}
						}

						/* Get to start of CSeq number */
						for ( ; sub_value_offset < value_len; sub_value_offset++)
						{
							if (value[sub_value_offset] != ' ' &&
						        value[sub_value_offset] != '\t')
							{
								break;
							}
						}
						cseq_no_offset = sub_value_offset;

						/* CSeq number */
						for ( ; sub_value_offset < value_len; sub_value_offset++)
						{
							if (!isdigit((guchar)value[sub_value_offset]))
							{
								proto_tree_add_uint(rack_tree, hf_sip_rack_cseq_no,
								                    tvb, value_offset+cseq_no_offset,
								                    sub_value_offset-cseq_no_offset,
								                    atoi(value+cseq_no_offset));
								break;
							}
						}

						/* Get to start of CSeq method name */
						for ( ; sub_value_offset < value_len; sub_value_offset++)
						{
							if (isalpha((guchar)value[sub_value_offset]))
							{
								/* Have reached start of method name */
								break;
							}
						}
						/*cseq_method_offset = sub_value_offset;*/

						if (sub_value_offset == linelen)
						{
							/* Didn't find method name */
							THROW(ReportedBoundsError);
							return offset - orig_offset;
						}

						/* Add CSeq method to the tree */
						if (cseq_tree)
						{
							proto_tree_add_item(rack_tree, hf_sip_rack_cseq_method, tvb,
							                    value_offset + sub_value_offset,
							                    (int)linelen-sub_value_offset, FALSE);
						}

						break;
					}

					case POS_CALL_ID :
						/* Store the Call-id */
						g_strlcpy(call_id, value, MAX_CALL_ID_SIZE);
						stat_info->tap_call_id = ep_strdup(call_id);

						/* Add 'Call-id' string item to tree */
						if(hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
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
							sip_element_item = proto_tree_add_uint(hdr_tree,
							                    hf_header_array[hf_index], tvb,
							                    offset, next_offset - offset,
							                    atoi(value));
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
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
						}
						content_type_len = value_len;
						semi_colon_offset = tvb_find_guint8(tvb, value_offset, value_len, ';');
						/* Content-Type     =  ( "Content-Type" / "c" ) HCOLON media-type
						 * media-type       =  m-type SLASH m-subtype *(SEMI m-parameter)
						 * SEMI    =  SWS ";" SWS ; semicolon
						 * LWS  =  [*WSP CRLF] 1*WSP ; linear whitespace
						 * SWS  =  [LWS] ; sep whitespace
						 */
						if ( semi_colon_offset != -1) {
							gint content_type_end;
							/*
							 * Skip whitespace after the semicolon.
							 */
							parameter_offset = tvb_skip_wsp(tvb, semi_colon_offset +1, value_offset + value_len - (semi_colon_offset +1));
							content_type_end = tvb_skip_wsp_return(tvb, semi_colon_offset-1);
							content_type_len = content_type_end - value_offset;
							content_type_parameter_str_len = value_offset + value_len - parameter_offset;
							content_type_parameter_str = tvb_get_ephemeral_string(tvb, parameter_offset,
							                             content_type_parameter_str_len);
						}
						media_type_str_lower_case = ascii_strdown_inplace(
							(gchar *)tvb_get_ephemeral_string(tvb, value_offset, content_type_len));

						/* Debug code
						proto_tree_add_text(hdr_tree, tvb, value_offset,content_type_len,
						                    "media_type_str(lower cased)=%s",media_type_str_lower_case);
						*/
					break;

					case POS_CONTENT_LENGTH :
						content_length = atoi(value);
						if(hdr_tree) {
							sip_element_item = proto_tree_add_uint_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   content_length, "%s",
							                   tvb_format_text(tvb, offset, linelen));
						}
						break;

					case POS_MAX_BREADTH :
					case POS_MAX_FORWARDS :
					case POS_RSEQ :
						if(hdr_tree) {
							sip_element_item = proto_tree_add_uint(hdr_tree,
							                    hf_header_array[hf_index], tvb,
							                    offset, next_offset - offset,
							                    atoi(value));
						}
						break;

					case POS_CONTACT :
						/*
						 * Contact        =  ("Contact" / "m" ) HCOLON
						 *                   ( STAR / (contact-param *(COMMA contact-param)))
						 * contact-param  =  (name-addr / addr-spec) *(SEMI contact-params)
						 */
						if(hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   value, "%s",
							                   tvb_format_text(tvb, offset, linelen));
							sip_element_tree = proto_item_add_subtree( sip_element_item,
							                   ett_sip_element);
						}
						/* value_offset points to the first non SWS character after ':' */
						c = tvb_get_guint8(tvb, value_offset);
						if (c =='*'){
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
						/* Authorization     =  "Authorization" HCOLON credentials
						 * credentials       =  ("Digest" LWS digest-response)
						 *                      / other-response
						 * digest-response   =  dig-resp *(COMMA dig-resp)
						 * other-response    =  auth-scheme LWS auth-param
						 *                      *(COMMA auth-param)
						 */
					case POS_WWW_AUTHENTICATE:
						/* Proxy-Authenticate  =  "Proxy-Authenticate" HCOLON challenge
						 * challenge           =  ("Digest" LWS digest-cln *(COMMA digest-cln))
						 *                        / other-challenge
						 * other-challenge     =  auth-scheme LWS auth-param
						 *                        *(COMMA auth-param)
						 * auth-scheme         =  token
						 */
					case POS_PROXY_AUTHENTICATE:
						/* Proxy-Authenticate  =  "Proxy-Authenticate" HCOLON challenge
						 */
					case POS_PROXY_AUTHORIZATION:
						/* Proxy-Authorization  =  "Proxy-Authorization" HCOLON credentials
						 */
					case POS_AUTHENTICATION_INFO:
						/* Authentication-Info  =  "Authentication-Info" HCOLON ainfo
						 *                        *(COMMA ainfo)
						 * ainfo                =  nextnonce / message-qop
						 *                         / response-auth / cnonce
						 *                         / nonce-count
						 */
						/* Add tree using whole text of line */
						if (hdr_tree) {
							proto_item *ti_c;
							/* Add whole line as header tree */
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                   hf_header_array[hf_index], tvb,
							                   offset, next_offset - offset,
							                   value, "%s",
							                   tvb_format_text(tvb, offset, linelen));
							sip_element_tree = proto_item_add_subtree( sip_element_item,
							                   ett_sip_element);

							/* Set sip.auth as a hidden field/filter */
							ti_c = proto_tree_add_item(hdr_tree, hf_sip_auth, tvb,
							                         offset, next_offset-offset,
							                         FALSE);
							PROTO_ITEM_SET_HIDDEN(ti_c);

							/* Authentication-Info does not begin with the scheme name */
							if (hf_index != POS_AUTHENTICATION_INFO)
							{
								/* The first time comma_offset is "start of parameters" */
								comma_offset = tvb_pbrk_guint8(tvb, value_offset, line_end_offset - value_offset, " \t\r\n", NULL);
								proto_tree_add_item(sip_element_tree, hf_sip_auth_scheme,
													tvb, value_offset, comma_offset - value_offset,
													FALSE);
							}else{
								/* The first time comma_offset is "start of parameters" */
								comma_offset = value_offset;
							}

							/* Parse each individual parameter in the line */
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
						}/*hdr_tree*/
					break;

					case POS_VIA:
						/* Add Via subtree */
						if (hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
							via_tree = proto_item_add_subtree(sip_element_item, ett_sip_via);
							dissect_sip_via_header(tvb, via_tree, value_offset, line_end_offset);
						}
						break;
					case POS_REASON:
						if(hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
							reason_tree = proto_item_add_subtree(sip_element_item, ett_sip_reason);
							dissect_sip_reason_header(tvb, reason_tree, value_offset, line_end_offset);
						}
						break;
					default :
						/* Default case is to assume its an FT_STRING field */
						if(hdr_tree) {
							sip_element_item = proto_tree_add_string_format(hdr_tree,
							                             hf_header_array[hf_index], tvb,
							                             offset, next_offset - offset,
							                             value, "%s",
							                             tvb_format_text(tvb, offset, linelen));
						}
					break;
				}/* end switch */
			}/*if HF_index */
		}/* if colon_offset */
		if (is_no_header_termination == TRUE){
			/* Header not terminated by empty line CRLF */
			cause=proto_tree_add_text(hdr_tree, tvb, line_end_offset, -1,
						"[Header not terminated by empty line (CRLF)]");

			proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
			expert_add_info_format(pinfo, sip_element_item,
				PI_MALFORMED, PI_WARN,
				"Header not terminated by empty line (CRLF)");
		}
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
			ti_a = proto_tree_add_item(sip_tree, hf_sip_msg_body, next_tvb, 0, -1,
			                         ENC_NA);
			message_body_tree = proto_item_add_subtree(ti_a, ett_sip_message_body);
		}

		/* give the content type parameters to sub dissectors */

		if ( media_type_str_lower_case != NULL ) {
			void *save_private_data = pinfo->private_data;
			pinfo->private_data = content_type_parameter_str;
			found_match = dissector_try_string(media_type_dissector_table,
			                                   media_type_str_lower_case,
			                                   next_tvb, pinfo,
			                                   message_body_tree);
			if (!found_match &&
			    !strncmp(media_type_str_lower_case, "multipart/", sizeof("multipart/")-1)) {
				/* Try to decode the unknown multipart subtype anyway */
				found_match = dissector_try_string(media_type_dissector_table,
				                                   "multipart/",
				                                   next_tvb, pinfo,
				                                   message_body_tree);
			}
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
	/* Registration requests */
	if (current_method_idx == SIP_METHOD_REGISTER)
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
	/* Find the total setup time, Must be done before checking for resend
	 * As that will overwrite the "Request packet no".
	 */
	if ((line_type == REQUEST_LINE)&&(strcmp(cseq_method, "ACK") == 0))
	{
		request_for_response = sip_find_invite(pinfo, cseq_method, call_id,
		                                        cseq_number_set, cseq_number,
		                                        &response_time);
		stat_info->setup_time = response_time;
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

	/* For responses, try to link back to request frame */
	if (line_type == STATUS_LINE)
	{
		request_for_response = sip_find_request(pinfo, cseq_method, call_id,
		                                        cseq_number_set, cseq_number,
		                                        &response_time);
	}

	if (reqresp_tree)
	{
		proto_item *item;
		if (request_for_response > 0)
		{
			item = proto_tree_add_uint(reqresp_tree, hf_sip_matching_request_frame,
			                           tvb, orig_offset, 0, request_for_response);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_uint(reqresp_tree, hf_sip_response_time,
			                           tvb, orig_offset, 0, response_time);
			PROTO_ITEM_SET_GENERATED(item);
			if ((line_type == STATUS_LINE)&&(strcmp(cseq_method, "BYE") == 0)){
				item = proto_tree_add_uint(reqresp_tree, hf_sip_release_time,
				                          tvb, orig_offset, 0, response_time);
				PROTO_ITEM_SET_GENERATED(item);
			}
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
dfilter_sip_request_line(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint offset, guint meth_len, gint linelen)
{
	char	*value;
	guint	parameter_len = meth_len;
	uri_offset_info uri_offsets;

	/*
	 * We know we have the entire method; otherwise, "sip_parse_line()"
	 * would have returned OTHER_LINE.
	 * Request-Line  =  Method SP Request-URI SP SIP-Version CRLF
	 * SP = single space
	 * Request-URI    =  SIP-URI / SIPS-URI / absoluteURI
	 */

	/* get method string*/
	value = tvb_get_ephemeral_string(tvb, offset, parameter_len);

	/* Copy request method for telling tap */
	stat_info->request_method = value;

	if (tree) {
		proto_tree_add_string(tree, hf_sip_Method, tvb, offset, parameter_len, value);

		/* build Request-URI tree*/
		offset=offset + parameter_len+1;
		sip_uri_offset_init(&uri_offsets);
		/* calc R-URI len*/
		uri_offsets.uri_end = tvb_find_guint8(tvb, offset, linelen, ' ')-1;
		dissect_sip_uri(tvb, pinfo, offset, offset + linelen, &uri_offsets);
		display_sip_uri(tvb, tree, &uri_offsets, &sip_req_uri);
	}
}

/* Display filter for SIP Status-Line */
static void
dfilter_sip_status_line(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int line_end)
{
	gint response_code = 0;
	int offset, diag_len;
	tvbuff_t *next_tvb;

	/*
	 * We know we have the entire status code; otherwise,
	 * "sip_parse_line()" would have returned OTHER_LINE.
	 * We also know that we have a version string followed by a
	 * space at the beginning of the line, for the same reason.
	 */
	response_code = atoi((char*)tvb_get_ephemeral_string(tvb, SIP2_HDR_LEN + 1, 3));

	/* Add numerical response code to tree */
	if (tree) {
		proto_tree_add_uint(tree, hf_sip_Status_Code, tvb, SIP2_HDR_LEN + 1,
		                    3, response_code);
	}

	/* Add response code for sending to tap */
	stat_info->response_code = response_code;

	/* Skip past the responce code and possible trailing space */
	offset =  SIP2_HDR_LEN + 1 + 3 + 1;

	/* Check for diagnostics */
	diag_len = line_end - offset;
	if((diag_len) <= 0)
		return;

	/* If we have a SIP diagnostics sub dissector call it */
	if(sip_diag_handle){
		next_tvb = tvb_new_subset(tvb, offset, diag_len, diag_len);
		call_dissector(sip_diag_handle, next_tvb, pinfo, tree);
	}
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
	gchar *meth_name;

	meth_name = tvb_get_ephemeral_string(tvb, meth_offset, meth_len);

	for (i = 1; i < array_length(sip_methods); i++) {
		if (meth_len == strlen(sip_methods[i]) &&
		    strncmp(meth_name, sip_methods[i], meth_len) == 0)
		{
			*meth_idx = i;
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Returns index of method in sip_headers
 * Header namne should be in lower case
 */
static gint sip_is_known_sip_header(gchar *header_name, guint header_len)
{
	guint pos;

	/* Compact name is one character long */
	if(header_len>1){
		pos = GPOINTER_TO_INT(g_hash_table_lookup(sip_headers_hash, header_name));
		if (pos!=0)
			return pos;
	}

	/* Look for compact name match */
	for (pos = 1; pos < array_length(sip_headers); pos++) {
		if (sip_headers[pos].compact_name != NULL &&
				header_len == strlen(sip_headers[pos].compact_name) &&
				g_ascii_strncasecmp(header_name, sip_headers[pos].compact_name, header_len) == 0)
			return pos;
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
	char *str;

	if (tree) {
		ti = proto_tree_add_item(tree, proto_raw_sip, tvb, offset, length, FALSE);
		raw_tree = proto_item_add_subtree(ti, ett_raw_text);
	}

	end_offset = offset + length;

	while (offset < end_offset) {
		tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
		linelen = next_offset - offset;
		if (raw_tree) {
			if (global_sip_raw_text_without_crlf)
				str = tvb_format_text_wsp(tvb, offset, linelen);
			else
				str = tvb_format_text(tvb, offset, linelen);
			proto_tree_add_string_format(raw_tree, hf_sip_raw_line, tvb, offset, linelen,
						     str,
						     "%s",
						     str);
		}
		offset = next_offset;
	}
}

/* Check to see if this packet is a resent request.  Return value is the frame number
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
	sip_frame_result_value *sip_frame_result = NULL;
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
		sip_frame_result = (sip_frame_result_value*)p_get_proto_data(pinfo->fd, proto_sip);
		if (sip_frame_result != NULL)
		{
			return sip_frame_result->original_frame_num;
		}
		else
		{
			return 0;
		}
	}

	/* No packet entry found, consult global hash table */

	/* Prepare the key */
	g_strlcpy(key.call_id, call_id, MAX_CALL_ID_SIZE);

	/*  We're only using these addresses locally (for the hash lookup) so
	 *  there is no need to make a (g_malloc'd) copy of them.
	 */
	SET_ADDRESS(&key.dest_address, pinfo->net_dst.type, pinfo->net_dst.len,
		    pinfo->net_dst.data);
	SET_ADDRESS(&key.source_address, pinfo->net_src.type,
		    pinfo->net_src.len, pinfo->net_src.data);
	key.dest_port = pinfo->destport;
	if (sip_retrans_the_same_sport) {
		key.source_port = pinfo->srcport;
	} else {
		key.source_port = MAGIC_SOURCE_PORT;
	}

	/* Do the lookup */
	p_val = (sip_hash_value*)g_hash_table_lookup(sip_hash, &key);

	if (p_val)
	{
		/* Table entry found, we'll use its value for comparison */
		cseq_to_compare = p_val->cseq;

		/* First time through, must update value with current details if
		    cseq number has changed */
		if (cseq_number != p_val->cseq)
		{
			p_val->cseq = cseq_number;
			g_strlcpy(p_val->method, cseq_method, MAX_CSEQ_METHOD_SIZE);
			p_val->transaction_state = nothing_seen;
			p_val->frame_number = 0;
			if (line_type == REQUEST_LINE)
			{
				p_val->request_time = pinfo->fd->abs_ts;
			}
		}
	}
	else
	{
		/* Need to create a new table entry */

		/* Allocate a new key and value */
		p_key = se_alloc(sizeof(sip_hash_key));
		p_val = se_alloc(sizeof(sip_hash_value));

		/* Fill in key and value details */
		g_snprintf(p_key->call_id, MAX_CALL_ID_SIZE, "%s", call_id);
		SE_COPY_ADDRESS(&(p_key->dest_address), &pinfo->net_dst);
		SE_COPY_ADDRESS(&(p_key->source_address), &pinfo->net_src);
		p_key->dest_port = pinfo->destport;
		if (sip_retrans_the_same_sport) {
			p_key->source_port = pinfo->srcport;
		} else {
			p_key->source_port = MAGIC_SOURCE_PORT;
		}

		p_val->cseq = cseq_number;
		g_strlcpy(p_val->method, cseq_method, MAX_CSEQ_METHOD_SIZE);
		p_val->transaction_state = nothing_seen;
		p_val->frame_number = 0;
		if (line_type == REQUEST_LINE)
		{
			p_val->request_time = pinfo->fd->abs_ts;
		}

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
				/* This frame is the original request */
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
					/* This frame is the original response */
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

	sip_frame_result = p_get_proto_data(pinfo->fd, proto_sip);
	if (sip_frame_result == NULL)
	{
		sip_frame_result = se_alloc0(sizeof(sip_frame_result_value));
	}

	/* Store return value with this packet */
	sip_frame_result->original_frame_num = result;
	p_add_proto_data(pinfo->fd, proto_sip, sip_frame_result);

	return result;
}


/* Check to see if this packet is a resent request.  Return value is the frame number
   of the original frame this packet seems to be resending (0 = no resend). */
guint sip_find_request(packet_info *pinfo,
			gchar *cseq_method,
			gchar *call_id,
			guchar cseq_number_set,
			guint32 cseq_number,
			guint32 *response_time)
{
	guint32 cseq_to_compare = 0;
	sip_hash_key   key;
	sip_hash_value *p_val = 0;
	sip_frame_result_value *sip_frame_result = NULL;
	guint result = 0;
	gint seconds_between_packets;
	gint nseconds_between_packets;

	/* Only consider UDP */
	if (pinfo->ptype != PT_UDP)
	{
		return 0;
	}

	/* Ignore error (usually ICMP) frames */
	if (pinfo->in_error_pkt)
	{
		return 0;
	}

	/* A broken packet may have no cseq number set. Ignore. */
	if (!cseq_number_set)
	{
		return 0;
	}

	/* Return any answer stored from previous dissection */
	if (pinfo->fd->flags.visited)
	{
		sip_frame_result = (sip_frame_result_value*)p_get_proto_data(pinfo->fd, proto_sip);
		if (sip_frame_result != NULL)
		{
			*response_time = sip_frame_result->response_time;
			return sip_frame_result->response_request_frame_num;
		}
		else
		{
			return 0;
		}
	}

	/* No packet entry found, consult global hash table */

	/* Prepare the key */
	g_strlcpy(key.call_id, call_id, MAX_CALL_ID_SIZE);

	/* Looking for matching request, so reverse addresses for this lookup */
	SET_ADDRESS(&key.dest_address, pinfo->net_src.type, pinfo->net_src.len,
		    pinfo->net_src.data);
	SET_ADDRESS(&key.source_address, pinfo->net_dst.type, pinfo->net_dst.len,
			pinfo->net_dst.data);
	key.dest_port = pinfo->srcport;
	key.source_port = pinfo->destport;

	/* Do the lookup */
	p_val = (sip_hash_value*)g_hash_table_lookup(sip_hash, &key);

	if (p_val)
	{
		/* Table entry found, we'll use its value for comparison */
		cseq_to_compare = p_val->cseq;
	}
	else
	{
		/* We don't have the request */
		return 0;
	}


	/**************************************************/
	/* Is it a response to a request that we've seen? */
	if ((cseq_number == cseq_to_compare) &&
	    (p_val->transaction_state == request_seen) &&
	    (strcmp(cseq_method, p_val->method) == 0))
	{
		result = p_val->frame_number;
	}


	/* Store return value with this packet */
	sip_frame_result = p_get_proto_data(pinfo->fd, proto_sip);
	if (sip_frame_result == NULL)
	{
		/* Allocate and set all values to zero */
		sip_frame_result = se_alloc0(sizeof(sip_frame_result_value));
	}

	sip_frame_result->response_request_frame_num = result;

	/* Work out response time */
	seconds_between_packets = (gint)
	    (pinfo->fd->abs_ts.secs - p_val->request_time.secs);
	nseconds_between_packets =
	     pinfo->fd->abs_ts.nsecs - p_val->request_time.nsecs;
	sip_frame_result->response_time = (seconds_between_packets*1000) +
	                                  (nseconds_between_packets / 1000000);
	*response_time = sip_frame_result->response_time;

	p_add_proto_data(pinfo->fd, proto_sip, sip_frame_result);

	return result;
}

/*
 * Find the initial INVITE to calculate the total setup time
 */
guint sip_find_invite(packet_info *pinfo,
			gchar *cseq_method _U_,
			gchar *call_id,
			guchar cseq_number_set,
			guint32 cseq_number _U_,
			guint32 *response_time)
{
#if 0
	guint32 cseq_to_compare = 0;
#endif
	sip_hash_key   key;
	sip_hash_value *p_val = 0;
	sip_frame_result_value *sip_frame_result = NULL;
	guint result = 0;
	gint seconds_between_packets;
	gint nseconds_between_packets;

	/* Only consider UDP */
	if (pinfo->ptype != PT_UDP)
	{
		return 0;
	}

	/* Ignore error (usually ICMP) frames */
	if (pinfo->in_error_pkt)
	{
		return 0;
	}

	/* A broken packet may have no cseq number set. Ignore. */
	if (!cseq_number_set)
	{
		return 0;
	}

	/* Return any answer stored from previous dissection */
	if (pinfo->fd->flags.visited)
	{
		sip_frame_result = (sip_frame_result_value*)p_get_proto_data(pinfo->fd, proto_sip);
		if (sip_frame_result != NULL)
		{
			*response_time = sip_frame_result->response_time;
			return sip_frame_result->response_request_frame_num;
		}
		else
		{
			return 0;
		}
	}

	/* No packet entry found, consult global hash table */

	/* Prepare the key */
	g_strlcpy(key.call_id, call_id, MAX_CALL_ID_SIZE);

	/* Looking for matching INVITE */
	SET_ADDRESS(&key.dest_address, pinfo->net_dst.type, pinfo->net_dst.len,
			pinfo->net_dst.data);
	SET_ADDRESS(&key.source_address, pinfo->net_src.type, pinfo->net_src.len,
		    pinfo->net_src.data);
	key.dest_port = pinfo->destport;
	key.source_port = pinfo->srcport;

	/* Do the lookup */
	p_val = (sip_hash_value*)g_hash_table_lookup(sip_hash, &key);

	if (p_val)
	{
#if 0
		/* Table entry found, we'll use its value for comparison */
		cseq_to_compare = p_val->cseq;
#endif
	}
	else
	{
		/* We don't have the request */
		return 0;
	}


	/**************************************************/
	/* Is it a response to a request that we've seen? */
#if 0
	if ((cseq_number == cseq_to_compare) &&
	    (p_val->transaction_state == request_seen) &&
	    (strcmp(cseq_method, p_val->method) == 0))
	{
		result = p_val->frame_number;
	}
#endif

	result = p_val->frame_number;

	/* Store return value with this packet */
	sip_frame_result = p_get_proto_data(pinfo->fd, proto_sip);
	if (sip_frame_result == NULL)
	{
		/* Allocate and set all values to zero */
		sip_frame_result = se_alloc0(sizeof(sip_frame_result_value));
	}

	sip_frame_result->response_request_frame_num = result;

	/* Work out response time */
	seconds_between_packets = (gint)
	    (pinfo->fd->abs_ts.secs - p_val->request_time.secs);
	nseconds_between_packets =
	     pinfo->fd->abs_ts.nsecs - p_val->request_time.nsecs;
	sip_frame_result->response_time = (seconds_between_packets*1000) +
	                                  (nseconds_between_packets / 1000000);
	*response_time = sip_frame_result->response_time;

	p_add_proto_data(pinfo->fd, proto_sip, sip_frame_result);

	return result;
}
static void
tcp_range_add_callback(guint32 port)
{
	dissector_add_uint("tcp.port", port, sip_tcp_handle);
}

static void
tcp_range_delete_callback(guint32 port)
{
	dissector_delete_uint("tcp.port", port, sip_tcp_handle);
}

/* Register the protocol with Wireshark */
void proto_register_sip(void)
{

        /* Setup list of header fields */
        static hf_register_info hf[] = {

		{ &hf_sip_msg_hdr,
				{ "Message Header",           "sip.msg_hdr",
                        FT_STRING, BASE_NONE, NULL, 0,
                        "Message Header in SIP message", HFILL }
                },
		{ &hf_sip_Method,
		       { "Method", 		"sip.Method",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"SIP Method", HFILL }
		},
		{ &hf_Request_Line,
				{ "Request-Line",                "sip.Request-Line",
					FT_STRING, BASE_NONE,NULL,0x0,
                       "SIP Request-Line", HFILL }
                },
		{ &hf_sip_ruri,
				{ "Request-URI", 		"sip.r-uri",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: SIP R-URI", HFILL }
		},
		{ &hf_sip_ruri_user,
				{ "Request-URI User Part", 		"sip.r-uri.user",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: SIP R-URI User", HFILL }
		},
		{ &hf_sip_ruri_host,
				{ "Request-URI Host Part", 		"sip.r-uri.host",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: SIP R-URI Host", HFILL }
		},
		{ &hf_sip_ruri_port,
				{ "Request-URI Host Port", 		"sip.r-uri.port",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: SIP R-URI Port", HFILL }
		},
		{ &hf_sip_Status_Code,
		       { "Status-Code", 		"sip.Status-Code",
		       FT_UINT32, BASE_DEC,NULL,0x0,
			"SIP Status Code", HFILL }
		},
		{ &hf_sip_Status_Line,
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
			"RFC 3261: To Address", HFILL }
		},
		{ &hf_sip_to_user,
		       { "SIP to address User Part", 		"sip.to.user",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: To Address User", HFILL }
		},
		{ &hf_sip_to_host,
		       { "SIP to address Host Part", 		"sip.to.host",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: To Address Host", HFILL }
		},
		{ &hf_sip_to_port,
		       { "SIP to address Host Port", 		"sip.to.port",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: To Address Port", HFILL }
		},
		{ &hf_sip_from_addr,
		       { "SIP from address", 		"sip.from.addr",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: From Address", HFILL }
		},
		{ &hf_sip_from_user,
		       { "SIP from address User Part", 		"sip.from.user",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: From Address User", HFILL }
		},
		{ &hf_sip_from_host,
		       { "SIP from address Host Part", 		"sip.from.host",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: From Address Host", HFILL }
		},
		{ &hf_sip_from_port,
		       { "SIP from address Host Port", 		"sip.from.port",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: From Address Port", HFILL }
		},
/* etxrab */
		{ &hf_sip_curi,
				{ "Contact-URI", 		"sip.contact.uri",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: SIP C-URI", HFILL }
		},
		{ &hf_sip_curi_user,
				{ "Contactt-URI User Part", 		"sip.contact.user",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: SIP C-URI User", HFILL }
		},
		{ &hf_sip_curi_host,
				{ "Contact-URI Host Part", 		"sip.contact.host",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: SIP C-URI Host", HFILL }
		},
		{ &hf_sip_curi_port,
				{ "Contact-URI Host Port", 		"sip.contact.port",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: SIP C-URI Port", HFILL }
		},
		{ &hf_sip_contact_param,
		       { "Contact parameter", 		"sip.contact.parameter",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: one contact parameter", HFILL }
		},
		{ &hf_sip_tag,
		       { "SIP tag", 		"sip.tag",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: tag", HFILL }
		},
		{ &hf_sip_pai_addr,
		       { "SIP PAI Address", 		"sip.pai.addr",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: P-Asserted-Identity Address", HFILL }
		},
		{ &hf_sip_pai_user,
		       { "SIP PAI User Part", 		"sip.pai.user",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: P-Asserted-Identity User", HFILL }
		},
		{ &hf_sip_pai_host,
		       { "SIP PAI Host Part", 		"sip.pai.host",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: P-Asserted-Identity Host", HFILL }
		},
		{ &hf_sip_pai_port,
		       { "SIP PAI Host Port", 		"sip.pai.port",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: P-Asserted-Identity Port", HFILL }
		},
		{ &hf_sip_pmiss_addr,
		       { "SIP PMISS Address", 		"sip.pmiss.addr",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: Permission Missing Address", HFILL }
		},
		{ &hf_sip_pmiss_user,
		       { "SIP PMISS User Part", 	"sip.pmiss.user",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: Permission Missing User", HFILL }
		},
		{ &hf_sip_pmiss_host,
		       { "SIP PMISS Host Part", 	"sip.pmiss.host",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: Permission Missing Host", HFILL }
		},
		{ &hf_sip_pmiss_port,
		       { "SIP PMISS Host Port", 	"sip.pmiss.port",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: Permission Missing Port", HFILL }
		},

		{ &hf_sip_ppi_addr,
		       { "SIP PPI Address", 		"sip.ppi.addr",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: P-Preferred-Identity Address", HFILL }
		},
		{ &hf_sip_ppi_user,
		       { "SIP PPI User Part", 		"sip.ppi.user",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: P-Preferred-Identity User", HFILL }
		},
		{ &hf_sip_ppi_host,
		       { "SIP PPI Host Part", 		"sip.ppi.host",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: P-Preferred-Identity Host", HFILL }
		},
		{ &hf_sip_ppi_port,
		       { "SIP PPI Host Port", 		"sip.ppi.port",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: P-Preferred-Identity Port", HFILL }
		},
		{ &hf_sip_tc_addr,
		       { "SIP TC Address", 		"sip.tc.addr",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: Trigger Consent Address", HFILL }
		},
		{ &hf_sip_tc_user,
		       { "SIP TC User Part", 		"sip.tc.user",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: Trigger Consent User", HFILL }
		},
		{ &hf_sip_tc_host,
		       { "SIP TC Host Part", 		"sip.tc.host",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: Trigger Consent Host", HFILL }
		},
		{ &hf_sip_tc_port,
		       { "SIP TC Host Port", 		"sip.tc.port",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: Trigger Consent Port", HFILL }
		},
		{ &hf_sip_tc_turi,
		       { "SIP TC Target URI", 		"sip.tc.target-uri",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: Trigger Consent Target URI", HFILL }
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
                { &hf_header_array[POS_ANSWER_MODE],
		       { "Answer-Mode", 		"sip.Answer-Mode",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 5373: Answer-Mode Header", HFILL }
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
		       FT_UINT32, BASE_DEC,NULL,0x0,
			"RFC 3261: Expires Header", HFILL }
		},
		{ &hf_header_array[POS_FLOW_TIMER],
		       { "Flow-Timer", 		"sip.Flow-Timer",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 5626: Flow-Timer", HFILL }
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
                { &hf_header_array[POS_MAX_BREADTH],
		       { "Max-Breadth", 	"sip.Max-Breadth",
		       FT_UINT32, BASE_DEC,NULL,0x0,
			"RFC 5393: Max-Breadth Header", HFILL }
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
		{ &hf_header_array[POS_P_ANSWER_STATE],
		       { "P-Answer-State",		"sip.P-Answer-State",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 4964: P-Answer-State Header", HFILL }
		},
		{ &hf_header_array[POS_P_ASSERTED_IDENTITY],
		       { "P-Asserted-Identity",		"sip.P-Asserted-Identity",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: P-Asserted-Identity Header", HFILL }
		},
		{ &hf_header_array[POS_P_ASSERTED_SERV],
		       { "P-Asserted-Service",		"sip.P-Asserted-Service",
		       FT_STRING, BASE_NONE,NULL,0x0,
			NULL, HFILL }
		},
		{ &hf_header_array[POS_P_ASSOCIATED_URI],
		       { "P-Associated-URI", 		"sip.P-Associated-URI",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3455: P-Associated-URI Header", HFILL }
		},

		{ &hf_header_array[POS_P_CALLED_PARTY_ID],
		       { "P-Called-Party-ID", 		"sip.P-Called-Party-ID",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3455: P-Called-Party-ID Header", HFILL }
		},

		{ &hf_header_array[POS_P_CHARGING_FUNC_ADDRESSES],
		       { "P-Charging-Function-Addresses","sip.P-Charging-Function-Addresses",
		       FT_STRING, BASE_NONE,NULL,0x0,
			NULL, HFILL }
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

		{ &hf_header_array[POS_P_EARLY_MEDIA],
		       { "P-Early-Media", 		"sip.P-Early-Media",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Early-Media Header", HFILL }
		},

		{ &hf_header_array[POS_P_MEDIA_AUTHORIZATION],
		       { "P-Media-Authorization", 	"sip.P-Media-Authorization",
		       FT_STRING, BASE_NONE,NULL,0x0,
			   "RFC 3313: P-Media-Authorization Header", HFILL }
		},

		{ &hf_header_array[POS_P_PREFERRED_IDENTITY],
		       { "P-Preferred-Identity",  	"sip.P-Preferred-Identity",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3325: P-Preferred-Identity Header", HFILL }
		},
		{ &hf_header_array[POS_P_PREFERRED_SERV],
		       { "P-Preferred-Service",  	"sip.P-Preferred-Service",
		       FT_STRING, BASE_NONE,NULL,0x0,
			NULL, HFILL }
		},
		{ &hf_header_array[POS_P_PROFILE_KEY],
		       { "P-Profile-Key",  	"sip.P-Profile-Key",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Profile-Key Header", HFILL }
		},
		{ &hf_header_array[POS_P_REFUSED_URI_LST],
		       { "P-Refused-URI-List",  	"sip.P-Refused-URI-List",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-Refused-URI-List Header", HFILL }
		},
		{ &hf_header_array[POS_P_SERVED_USER],
		       { "P-Served-User",  	"sip.P-Served-User",
		       FT_STRING, BASE_NONE,NULL,0x0,
			NULL, HFILL }
		},
		{ &hf_header_array[POS_P_USER_DATABASE],
		       { "P-User-Database",  	"sip.P-User-Database",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"P-User-Database Header", HFILL }
		},

		{ &hf_header_array[POS_P_VISITED_NETWORK_ID],
		       { "P-Visited-Network-ID", 	"sip.P-Visited-Network-ID",
		       FT_STRING, BASE_NONE,NULL,0x0,
			   "RFC 3455: P-Visited-Network-ID Header", HFILL }
		},

		{ &hf_header_array[POS_PATH],
		       { "Path", 			"sip.Path",
		       FT_STRING, BASE_NONE,NULL,0x0,
			   "RFC 3327: Path Header", HFILL }
		},

		{ &hf_header_array[POS_PERMISSION_MISSING],
		       { "Permission-Missing", 		"sip.Permission-Missing",
		       FT_STRING, BASE_NONE,NULL,0x0,
			   "RFC 5360: Permission Missing Header", HFILL }
		},

		{ &hf_header_array[POS_PRIORITY],
		       { "Priority", 		"sip.Priority",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3261: Priority Header", HFILL }
		},
		{ &hf_header_array[POS_PRIV_ANSWER_MODE],
		       { "Priv-Answer-mode", 	"sip.Priv-Answer-mode",
		       FT_STRING, BASE_NONE,NULL,0x0,
			NULL, HFILL }
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
		{ &hf_header_array[POS_RECV_INFO],
		       { "Recv-Info", 		"sip.Recv-Info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			NULL, HFILL }
		},
		{ &hf_header_array[POS_REFER_SUB],
		       { "Refer-Sub", 		"sip.Refer-Sub",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 4488: Refer-Sub Header", HFILL }
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
		       FT_UINT32, BASE_DEC,NULL,0x0,
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
			"RFC 3608: Service-Route Header", HFILL }
		},
		{ &hf_header_array[POS_SESSION_EXPIRES],
		       { "Session-Expires", 		"sip.Session-Expires",
		       FT_STRING, BASE_NONE,NULL,0x0,
			   "RFC 4028: Session-Expires Header", HFILL }
		},
		{ &hf_header_array[POS_SIP_ETAG],
		       { "ETag", 		"sip.ETag",
		       FT_STRING, BASE_NONE,NULL,0x0,
			   "RFC 3903: SIP-ETag Header", HFILL }
		},
		{ &hf_header_array[POS_SIP_IF_MATCH],
		       { "If_Match", 		"sip.If_Match",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 3903: SIP-If-Match Header", HFILL }
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
		{ &hf_header_array[POS_TARGET_DALOG],
			{ "Target-Dialog", 		"sip.Target-Dialog",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 4538: Target-Dialog Header", HFILL }
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

		{ &hf_header_array[POS_TRIGGER_CONSENT],
			{ "Trigger-Consent", 		"sip.Trigger-Consent",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 5380: Trigger Consent", HFILL }
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
			"RFC 3515: Refer-To Header", HFILL }
		},
		{ &hf_header_array[POS_HISTORY_INFO],
			{ "History-Info", 			"sip.History-Info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 4244: Request History Information", HFILL }
		},
		{ &hf_header_array[POS_IDENTITY],
			{ "Identity", 			"sip.Identity",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 4474: Request Identity", HFILL }
		},
		{ &hf_header_array[POS_IDENTITY_INFO],
			{ "Identity-info", 			"sip.Identity-info",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 4474: Request Identity-info", HFILL }
		},
		{ &hf_header_array[POS_INFO_PKG],
			{ "Info-Package", 			"sip.Info-Package",
		       FT_STRING, BASE_NONE,NULL,0x0,
			NULL, HFILL }
		},
		{ &hf_header_array[POS_DIVERSION],
			{ "Diversion", 		"sip.Diversion",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"RFC 5806: Diversion Header", HFILL }
		},
		{ &hf_header_array[POS_USER_TO_USER],
			{ "User-to-User", 	"sip.uui",
		       FT_STRING, BASE_NONE,NULL,0x0,
			"draft-johnston-sipping-cc-uui-09: User-to-User header", HFILL }
		},
		{ &hf_sip_resend,
			{ "Resent Packet", "sip.resend",
			FT_BOOLEAN, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sip_original_frame,
			{ "Suspected resend of frame",  "sip.resend-original",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    	"Original transmission of frame", HFILL}
		},
		{ &hf_sip_matching_request_frame,
			{ "Request Frame",  "sip.response-request",
			FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    	NULL, HFILL}
		},
		{ &hf_sip_response_time,
			{ "Response Time (ms)",  "sip.response-time",
			FT_UINT32, BASE_DEC, NULL, 0x0,
		    	"Response time since original request (in milliseconds)", HFILL}
		},
		{ &hf_sip_release_time,
			{ "Release Time (ms)",  "sip.release-time",
			FT_UINT32, BASE_DEC, NULL, 0x0,
		    	"release time since original BYE (in milliseconds)", HFILL}
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
		    	"SIP Digest Authentication Response Value", HFILL}
		},
		{ &hf_sip_auth_nc,
			{ "Nonce Count",  "sip.auth.nc",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Nonce count", HFILL}
		},
		{ &hf_sip_auth_username,
			{ "Username",  "sip.auth.username",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Username", HFILL}
		},
		{ &hf_sip_auth_realm,
			{ "Realm",  "sip.auth.realm",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Realm", HFILL}
		},
		{ &hf_sip_auth_nonce,
			{ "Nonce Value",  "sip.auth.nonce",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Nonce", HFILL}
		},
		{ &hf_sip_auth_algorithm,
			{ "Algorithm",  "sip.auth.algorithm",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Algorithm", HFILL}
		},
		{ &hf_sip_auth_opaque,
			{ "Opaque Value",  "sip.auth.opaque",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Opaque value", HFILL}
		},
		{ &hf_sip_auth_qop,
			{ "QOP",  "sip.auth.qop",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication QOP", HFILL}
		},
		{ &hf_sip_auth_cnonce,
			{ "CNonce Value",  "sip.auth.cnonce",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Client Nonce", HFILL}
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
		    	"SIP Authentication Response auth", HFILL}
		},
		{ &hf_sip_auth_nextnonce,
			{ "Next Nonce",  "sip.auth.nextnonce",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Next Nonce", HFILL}
		},
		{ &hf_sip_auth_ik,
			{ "Integrity Key",  "sip.auth.ik",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Integrity Key", HFILL}
		},
		{ &hf_sip_auth_ck,
			{ "Cyphering Key",  "sip.auth.ck",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Authentication Cyphering Key", HFILL}
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
		},
		{ &hf_sip_via_transport,
			{ "Transport",  "sip.Via.transport",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"Via header Transport", HFILL}
		},
		{ &hf_sip_via_sent_by_address,
			{ "Sent-by Address",  "sip.Via.sent-by.address",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"Via header Sent-by Address", HFILL}
		},
		{ &hf_sip_via_sent_by_port,
			{ "Sent-by port",  "sip.Via.sent-by.port",
			FT_UINT16, BASE_DEC, NULL, 0x0,
		    	"Via header Sent-by Port", HFILL}
		},
		{ &hf_sip_via_branch,
			{ "Branch",  "sip.Via.branch",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Via Branch", HFILL},
		},
		{ &hf_sip_via_maddr,
			{ "Maddr",  "sip.Via.maddr",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Via Maddr", HFILL},
		},
		{ &hf_sip_via_rport,
			{ "RPort",  "sip.Via.rport",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Via RPort", HFILL},
		},
		{ &hf_sip_via_received,
			{ "Received",  "sip.Via.received",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Via Received", HFILL},
		},
		{ &hf_sip_via_ttl,
			{ "TTL",  "sip.Via.ttl",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Via TTL", HFILL}
		},
		{ &hf_sip_via_comp,
			{ "Comp",  "sip.Via.comp",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Via comp", HFILL}
		},
		{ &hf_sip_via_sigcomp_id,
			{ "Sigcomp identifier",  "sip.Via.sigcomp-id",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"SIP Via sigcomp identifier", HFILL}
		},
		{ &hf_sip_rack_rseq_no,
			{ "RSeq Sequence Number",  "sip.RAck.RSeq.seq",
			FT_UINT32, BASE_DEC, NULL, 0x0,
		    	"RAck RSeq header sequence number (from prov response)", HFILL}
		},
		{ &hf_sip_rack_cseq_no,
			{ "CSeq Sequence Number",  "sip.RAck.CSeq.seq",
			FT_UINT32, BASE_DEC, NULL, 0x0,
		    	"RAck CSeq header sequence number (from prov response)", HFILL}
		},
		{ &hf_sip_rack_cseq_method,
			{ "CSeq Method",  "sip.RAck.CSeq.method",
			FT_STRING, BASE_NONE, NULL, 0x0,
		    	"RAck CSeq header method (from prov response)", HFILL}
		},
		{ &hf_sip_msg_body,
				{ "Message Body",           "sip.msg_body",
				FT_NONE, BASE_NONE, NULL, 0x0,
				"Message Body in SIP message", HFILL }
		}};

        /* raw_sip header field(s) */
        static hf_register_info raw_hf[] = {

		{ &hf_sip_raw_line,
				{ "Raw SIP Line",                "raw_sip.line",
					FT_STRING, BASE_NONE,NULL,0x0,
				NULL, HFILL }
        }};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sip,
		&ett_sip_reqresp,
		&ett_sip_hdr,
		&ett_sip_ext_hdr,
		&ett_sip_element,
		&ett_sip_uri,
		&ett_sip_contact_item,
		&ett_sip_message_body,
		&ett_sip_cseq,
		&ett_sip_via,
		&ett_sip_reason,
		&ett_sip_rack,
		&ett_sip_ruri,
		&ett_sip_pai_uri,
		&ett_sip_pmiss_uri,
		&ett_sip_ppi_uri,
		&ett_sip_tc_uri,
		&ett_sip_to_uri,
		&ett_sip_from_uri,
		&ett_sip_curi
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
	register_dissector("sip.tcp", dissect_sip_tcp, proto_sip);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_sip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	proto_register_subtree_array(ett_raw, array_length(ett_raw));

	/* Register raw_sip field(s) */
	proto_register_field_array(proto_raw_sip, raw_hf, array_length(raw_hf));

	sip_module = prefs_register_protocol(proto_sip, proto_reg_handoff_sip);
	range_convert_str(&global_sip_tcp_port_range, DEFAULT_SIP_PORT_RANGE, MAX_UDP_PORT);


	prefs_register_range_preference(sip_module, "tcp.ports", "SIP TCP ports",
					"TCP ports to be decoded as SIP (default: "
					DEFAULT_SIP_PORT_RANGE ")",
					&global_sip_tcp_port_range, MAX_UDP_PORT);

	prefs_register_uint_preference(sip_module, "tls.port",
                                 "SIP TLS Port",
                                 "SIP Server TLS Port",
                                 10, &sip_tls_port);

	prefs_register_bool_preference(sip_module, "display_raw_text",
		"Display raw text for SIP message",
		"Specifies that the raw text of the "
		"SIP message should be displayed "
		"in addition to the dissection tree",
		&global_sip_raw_text);
	prefs_register_bool_preference(sip_module, "display_raw_text_without_crlf",
		"Don't show '\\r\\n' in raw SIP messages",
		"If the raw text of the SIP message "
		"is displayed, the trailing carriage "
		"return and line feed are not shown",
		&global_sip_raw_text_without_crlf);
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
	prefs_register_bool_preference(sip_module, "retrans_the_same_sport",
	    "Retransmissions always use the same source port",
	    "Whether retransmissions are detected coming from the same source port only.",
	    &sip_retrans_the_same_sport);

	prefs_register_obsolete_preference(sip_module, "tcp.port");

	register_init_routine(&sip_init_protocol);
	register_heur_dissector_list("sip", &heur_subdissector_list);
	/* Register for tapping */
	sip_tap = register_tap("sip");

	ext_hdr_subdissector_table = register_dissector_table("sip.hdr", "SIP Extension header", FT_STRING, BASE_NONE);

}

void
proto_reg_handoff_sip(void)
{
	static range_t *sip_tcp_port_range;

	static guint saved_sip_tls_port;
	static gboolean sip_prefs_initialized = FALSE;

	if (!sip_prefs_initialized) {
		dissector_handle_t sip_handle;
		sip_handle = find_dissector("sip");
		sip_tcp_handle = find_dissector("sip.tcp");
		sigcomp_handle = find_dissector("sigcomp");
		sip_diag_handle = find_dissector("sip.diagnostic");
		/* SIP content type and internet media type used by other dissectors are the same */
		media_type_dissector_table = find_dissector_table("media_type");

		dissector_add_uint("udp.port", UDP_PORT_SIP, sip_handle);
		dissector_add_string("media_type", "message/sip", sip_handle);

		heur_dissector_add("udp", dissect_sip_heur, proto_sip);
		heur_dissector_add("tcp", dissect_sip_tcp_heur, proto_sip);
		heur_dissector_add("sctp", dissect_sip_heur, proto_sip);
		heur_dissector_add("stun", dissect_sip_heur, proto_sip);
		sip_prefs_initialized = TRUE;
	} else {
		range_foreach(sip_tcp_port_range, tcp_range_delete_callback);
		g_free(sip_tcp_port_range);
		ssl_dissector_delete(saved_sip_tls_port, "sip.tcp", TRUE);
	}
	/* Set our port number for future use */
	sip_tcp_port_range = range_copy(global_sip_tcp_port_range);
	range_foreach(sip_tcp_port_range, tcp_range_add_callback);
	saved_sip_tls_port = sip_tls_port;
	ssl_dissector_add(saved_sip_tls_port, "sip.tcp", TRUE);

}
