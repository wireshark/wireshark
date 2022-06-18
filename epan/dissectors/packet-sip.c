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
 * Copyright 2011, Anders Broman <anders.broman@ericsson.com>, Johan Wahl <johan.wahl@ericsson.com>
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2020, Atul Sharma <asharm37@ncsu.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/exceptions.h>
#include <epan/exported_pdu.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/req_resp_hdrs.h>
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>
#include <epan/proto_data.h>
#include <epan/uat.h>
#include <epan/strutil.h>
#include <epan/to_str.h>
#include <epan/follow.h>
#include <epan/conversation.h>
#include <epan/addr_resolv.h>
#include <epan/epan_dissect.h>

#include <wsutil/str_util.h>
#include <wsutil/strtoi.h>
#include <wsutil/wsgcrypt.h>

#include "packet-tls.h"

#include "packet-isup.h"
#include "packet-e164.h"
#include "packet-sip.h"

#include "packet-http.h"
#include "packet-acdr.h"

#include "packet-sdp.h"  /* SDP needs a transport layer to determine request/response */

/* un-comment the following as well as this line in conversation.c, to enable debug printing */
/* #define DEBUG_CONVERSATION */
#include "conversation_debug.h"

#define TLS_PORT_SIP 5061
#define DEFAULT_SIP_PORT_RANGE "5060"

void proto_register_sip(void);

static gint sip_tap = -1;
static gint sip_follow_tap = -1;
static gint exported_pdu_tap = -1;
static dissector_handle_t sip_handle;
static dissector_handle_t sip_tcp_handle;
static dissector_handle_t sigcomp_handle;
static dissector_handle_t sip_diag_handle;
static dissector_handle_t sip_uri_userinfo_handle;
static dissector_handle_t sip_via_branch_handle;
static dissector_handle_t sip_via_be_route_handle;
/* Dissector to dissect the text part of an reason code */
static dissector_handle_t sip_reason_code_handle;

/* Initialize the protocol and registered fields */
static gint proto_sip                     = -1;
static gint proto_raw_sip                 = -1;
static gint hf_sip_raw_line               = -1;
static gint hf_sip_msg_hdr                = -1;
static gint hf_sip_Method                 = -1;
static gint hf_Request_Line               = -1;
static gint hf_sip_ruri_display           = -1;
static gint hf_sip_ruri                   = -1;
static gint hf_sip_ruri_user              = -1;
static gint hf_sip_ruri_host              = -1;
static gint hf_sip_ruri_port              = -1;
static gint hf_sip_ruri_param             = -1;
static gint hf_sip_Status_Code            = -1;
static gint hf_sip_Status_Line            = -1;
static gint hf_sip_display                = -1;
static gint hf_sip_to_display             = -1;
static gint hf_sip_to_addr                = -1;
static gint hf_sip_to_user                = -1;
static gint hf_sip_to_host                = -1;
static gint hf_sip_to_port                = -1;
static gint hf_sip_to_param               = -1;
static gint hf_sip_to_tag                 = -1;
static gint hf_sip_from_display           = -1;
static gint hf_sip_from_addr              = -1;
static gint hf_sip_from_user              = -1;
static gint hf_sip_from_host              = -1;
static gint hf_sip_from_port              = -1;
static gint hf_sip_from_param             = -1;
static gint hf_sip_from_tag               = -1;
static gint hf_sip_tag                    = -1;
static gint hf_sip_pai_display            = -1;
static gint hf_sip_pai_addr               = -1;
static gint hf_sip_pai_user               = -1;
static gint hf_sip_pai_host               = -1;
static gint hf_sip_pai_port               = -1;
static gint hf_sip_pai_param              = -1;
static gint hf_sip_pmiss_display          = -1;
static gint hf_sip_pmiss_addr             = -1;
static gint hf_sip_pmiss_user             = -1;
static gint hf_sip_pmiss_host             = -1;
static gint hf_sip_pmiss_port             = -1;
static gint hf_sip_pmiss_param            = -1;
static gint hf_sip_ppi_display            = -1;
static gint hf_sip_ppi_addr               = -1;
static gint hf_sip_ppi_user               = -1;
static gint hf_sip_ppi_host               = -1;
static gint hf_sip_ppi_port               = -1;
static gint hf_sip_ppi_param              = -1;
static gint hf_sip_tc_display             = -1;
static gint hf_sip_tc_addr                = -1;
static gint hf_sip_tc_user                = -1;
static gint hf_sip_tc_host                = -1;
static gint hf_sip_tc_port                = -1;
static gint hf_sip_tc_param               = -1;
static gint hf_sip_tc_turi                = -1;
static gint hf_sip_contact_param          = -1;
static gint hf_sip_resend                 = -1;
static gint hf_sip_original_frame         = -1;
static gint hf_sip_matching_request_frame = -1;
static gint hf_sip_response_time          = -1;
static gint hf_sip_release_time           = -1;
static gint hf_sip_curi_display           = -1;
static gint hf_sip_curi                   = -1;
static gint hf_sip_curi_user              = -1;
static gint hf_sip_curi_host              = -1;
static gint hf_sip_curi_port              = -1;
static gint hf_sip_curi_param             = -1;
static gint hf_sip_route_display          = -1;
static gint hf_sip_route                  = -1;
static gint hf_sip_route_user             = -1;
static gint hf_sip_route_host             = -1;
static gint hf_sip_route_port             = -1;
static gint hf_sip_route_param            = -1;
static gint hf_sip_record_route_display   = -1;
static gint hf_sip_record_route           = -1;
static gint hf_sip_record_route_user      = -1;
static gint hf_sip_record_route_host      = -1;
static gint hf_sip_record_route_port      = -1;
static gint hf_sip_record_route_param     = -1;
static gint hf_sip_service_route_display  = -1;
static gint hf_sip_service_route          = -1;
static gint hf_sip_service_route_user     = -1;
static gint hf_sip_service_route_host     = -1;
static gint hf_sip_service_route_port     = -1;
static gint hf_sip_service_route_param    = -1;
static gint hf_sip_path_display           = -1;
static gint hf_sip_path                   = -1;
static gint hf_sip_path_user              = -1;
static gint hf_sip_path_host              = -1;
static gint hf_sip_path_port              = -1;
static gint hf_sip_path_param             = -1;

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
static gint hf_sip_via_oc                 = -1;
static gint hf_sip_via_oc_val             = -1;
static gint hf_sip_via_oc_algo            = -1;
static gint hf_sip_via_oc_validity        = -1;
static gint hf_sip_via_oc_seq             = -1;
static gint hf_sip_oc_seq_timestamp       = -1;
static gint hf_sip_via_be_route           = -1;

static gint hf_sip_rack_rseq_no           = -1;
static gint hf_sip_rack_cseq_no           = -1;
static gint hf_sip_rack_cseq_method       = -1;

static gint hf_sip_reason_protocols       = -1;
static gint hf_sip_reason_cause_q850      = -1;
static gint hf_sip_reason_cause_sip       = -1;
static gint hf_sip_reason_cause_other     = -1;
static gint hf_sip_reason_text            = -1;

static gint hf_sip_msg_body               = -1;
static gint hf_sip_sec_mechanism          = -1;
static gint hf_sip_sec_mechanism_alg      = -1;
static gint hf_sip_sec_mechanism_ealg     = -1;
static gint hf_sip_sec_mechanism_prot     = -1;
static gint hf_sip_sec_mechanism_spi_c    = -1;
static gint hf_sip_sec_mechanism_spi_s    = -1;
static gint hf_sip_sec_mechanism_port1    = -1;
static gint hf_sip_sec_mechanism_port_c   = -1;
static gint hf_sip_sec_mechanism_port2    = -1;
static gint hf_sip_sec_mechanism_port_s   = -1;
static gint hf_sip_session_id_sess_id     = -1;
static gint hf_sip_session_id_param       = -1;
static gint hf_sip_session_id_local_uuid  = -1;
static gint hf_sip_session_id_remote_uuid = -1;
static gint hf_sip_session_id_logme       = -1;
static gint hf_sip_continuation           = -1;
static gint hf_sip_feature_cap            = -1;

static gint hf_sip_p_acc_net_i_acc_type   = -1;
static gint hf_sip_p_acc_net_i_ucid_3gpp  = -1;

static gint hf_sip_service_priority = -1;
static gint hf_sip_icid_value = -1;
static gint hf_sip_icid_gen_addr = -1;
static gint hf_sip_call_id_gen = -1;

/* Initialize the subtree pointers */
static gint ett_sip                       = -1;
static gint ett_sip_reqresp               = -1;
static gint ett_sip_hdr                   = -1;
static gint ett_sip_ext_hdr               = -1;
static gint ett_raw_text                  = -1;
static gint ett_sip_element               = -1;
static gint ett_sip_hist                  = -1;
static gint ett_sip_uri                   = -1;
static gint ett_sip_contact_item          = -1;
static gint ett_sip_message_body          = -1;
static gint ett_sip_cseq                  = -1;
static gint ett_sip_via                   = -1;
static gint ett_sip_reason                = -1;
static gint ett_sip_security_client       = -1;
static gint ett_sip_security_server       = -1;
static gint ett_sip_security_verify       = -1;
static gint ett_sip_rack                  = -1;
static gint ett_sip_route                 = -1;
static gint ett_sip_record_route          = -1;
static gint ett_sip_service_route         = -1;
static gint ett_sip_path                  = -1;
static gint ett_sip_ruri                  = -1;
static gint ett_sip_to_uri                = -1;
static gint ett_sip_curi                  = -1;
static gint ett_sip_from_uri              = -1;
static gint ett_sip_pai_uri               = -1;
static gint ett_sip_pmiss_uri             = -1;
static gint ett_sip_ppi_uri               = -1;
static gint ett_sip_tc_uri                = -1;
static gint ett_sip_session_id            = -1;
static gint ett_sip_p_access_net_info     = -1;
static gint ett_sip_p_charging_vector     = -1;
static gint ett_sip_feature_caps          = -1;
static gint ett_sip_via_be_route          = -1;

static expert_field ei_sip_unrecognized_header = EI_INIT;
static expert_field ei_sip_header_no_colon = EI_INIT;
static expert_field ei_sip_header_not_terminated = EI_INIT;
#if 0
static expert_field ei_sip_odd_register_response = EI_INIT;
#endif
static expert_field ei_sip_sipsec_malformed = EI_INIT;
static expert_field ei_sip_via_sent_by_port = EI_INIT;
static expert_field ei_sip_content_length_invalid = EI_INIT;
static expert_field ei_sip_retry_after_invalid = EI_INIT;
static expert_field ei_sip_Status_Code_invalid = EI_INIT;
static expert_field ei_sip_authorization_invalid = EI_INIT;
static expert_field ei_sip_session_id_sess_id = EI_INIT;

/* patterns used for tvb_ws_mempbrk_pattern_guint8 */
static ws_mempbrk_pattern pbrk_comma_semi;
static ws_mempbrk_pattern pbrk_whitespace;
static ws_mempbrk_pattern pbrk_param_end;
static ws_mempbrk_pattern pbrk_param_end_colon_brackets;
static ws_mempbrk_pattern pbrk_header_end_dquote;
static ws_mempbrk_pattern pbrk_tab_sp_fslash;
static ws_mempbrk_pattern pbrk_addr_end;
static ws_mempbrk_pattern pbrk_via_param_end;


/* PUBLISH method added as per https://tools.ietf.org/html/draft-ietf-sip-publish-01 */
static const char *sip_methods[] = {
#define SIP_METHOD_INVALID  0
        "<Invalid method>",      /* Pad so that the real methods start at index 1 */
#define SIP_METHOD_ACK      1
        "ACK",
#define SIP_METHOD_BYE      2
        "BYE",
#define SIP_METHOD_CANCEL   3
        "CANCEL",
#define SIP_METHOD_DO       4
        "DO",
#define SIP_METHOD_INFO     5
        "INFO",
#define SIP_METHOD_INVITE   6
        "INVITE",
#define SIP_METHOD_MESSAGE  7
        "MESSAGE",
#define SIP_METHOD_NOTIFY   8
        "NOTIFY",
#define SIP_METHOD_OPTIONS  9
        "OPTIONS",
#define SIP_METHOD_PRACK    10
        "PRACK",
#define SIP_METHOD_QAUTH    11
        "QAUTH",
#define SIP_METHOD_REFER    12
        "REFER",
#define SIP_METHOD_REGISTER 13
        "REGISTER",
#define SIP_METHOD_SPRACK   14
        "SPRACK",
#define SIP_METHOD_SUBSCRIBE    15
        "SUBSCRIBE",
#define SIP_METHOD_UPDATE   16
        "UPDATE",
#define SIP_METHOD_PUBLISH  17
        "PUBLISH"
};

/* from RFC 3261
 * Updated with info from https://www.iana.org/assignments/sip-parameters
 * (last updated 2009-11-11)
 * Updated with: https://tools.ietf.org/html/draft-ietf-sip-resource-priority-05
 */
typedef struct {
        const char *name;
        const char *compact_name;
} sip_header_t;
static const sip_header_t sip_headers[] = {
    { "Unknown-header",                 NULL }, /* 0 Pad so that the real headers start at index 1 */
    { "Accept",                         NULL }, /*  */
#define POS_ACCEPT                       1
    { "Accept-Contact",                 "a"  }, /* RFC3841  */
#define POS_ACCEPT_CONTACT               2
    { "Accept-Encoding",                NULL }, /* */
#define POS_ACCEPT_ENCODING              3
    { "Accept-Language",                NULL }, /* */
#define POS_ACCEPT_LANGUAGE              4
    { "Accept-Resource-Priority",       NULL }, /* RFC4412 */
#define POS_ACCEPT_RESOURCE_PRIORITY     5
    { "Additional-Identity",            NULL }, /* 3GPP TS 24.229 v16.7.0 */
#define POS_ADDITIONAL_IDENTITY          6
    { "Alert-Info",                     NULL },
#define POS_ALERT_INFO                   7
    { "Allow",                          NULL },
#define POS_ALLOW                        8
    { "Allow-Events",                   "u"  }, /* RFC3265  */
#define POS_ALLOW_EVENTS                 9
    { "Answer-Mode",                    NULL }, /* RFC5373 */
#define POS_ANSWER_MODE                 10
    { "Attestation-Info",               NULL }, /* [3GPP TS 24.229 v15.11.0] */
#define POS_ATTESTATION_INFO            11
    { "Authentication-Info",            NULL },
#define POS_AUTHENTICATION_INFO         12
    { "Authorization",                  NULL }, /*  */
#define POS_AUTHORIZATION               13
    { "Call-ID",                        "i"  },
#define POS_CALL_ID                     14
    { "Call-Info",                      NULL },
#define POS_CALL_INFO                   15
    { "Cellular-Network-Info",          NULL }, /* [3GPP TS 24.229 v13.9.0] */
#define POS_CELLULAR_NETWORK_INFO       16
    { "Contact",                        "m"  },
#define POS_CONTACT                     17
    { "Content-Disposition",            NULL },
#define POS_CONTENT_DISPOSITION         18
    { "Content-Encoding",               "e"  },  /*   */
#define POS_CONTENT_ENCODING            19
    { "Content-Language",               NULL },
#define POS_CONTENT_LANGUAGE            20
    { "Content-Length",                 "l"  },
#define POS_CONTENT_LENGTH              21
    { "Content-Type",                   "c"  },
#define POS_CONTENT_TYPE                22
    { "CSeq",                           NULL },
#define POS_CSEQ                        23
    { "Date",                           NULL },  /*   */
#define POS_DATE                        24
/*              Encryption (Deprecated)       [RFC3261] */
    { "Error-Info",                     NULL },  /*   */
#define POS_ERROR_INFO                  25
    { "Event",                          "o"  },  /*   */
#define POS_EVENT                       26
    { "Expires",                        NULL },  /*   */
#define POS_EXPIRES                     27
    { "Feature-Caps",                   NULL },  /*  RFC6809 */
#define POS_FEATURE_CAPS                28
    { "Flow-Timer",                     NULL },  /*  RFC5626  */
#define POS_FLOW_TIMER                  29
    { "From",                           "f"  },  /*   */
#define POS_FROM                        30

    { "Geolocation",                   NULL  },  /*   */
#define POS_GEOLOCATION                 31
    { "Geolocation-Error",             NULL  },  /*   */
#define POS_GEOLOCATION_ERROR           32
    { "Geolocation-Routing",           NULL  },  /*   */
#define POS_GEOLOCATION_ROUTING         33

/*              Hide                          RFC3261 (deprecated)*/
    { "History-Info",                   NULL },  /*  RFC4244  */
#define POS_HISTORY_INFO                34
    { "Identity",                       "y"  },  /*  RFC4474  */
#define POS_IDENTITY                    35
    { "Identity-Info",                  "n"  },  /*  RFC4474  */
#define POS_IDENTITY_INFO               36
    { "Info-Package",                   NULL },  /*  RFC-ietf-sipcore-info-events-10.txt  */
#define POS_INFO_PKG                    37
    { "In-Reply-To",                    NULL },  /*  RFC3261  */
#define POS_IN_REPLY_TO                 38
    { "Join",                           NULL },  /*  RFC3911  */
#define POS_JOIN                        39
    { "Max-Breadth",                    NULL },  /*  RFC5393*/
#define POS_MAX_BREADTH                 40
    { "Max-Forwards",                   NULL },  /*   */
#define POS_MAX_FORWARDS                41
    { "MIME-Version",                   NULL },  /*   */
#define POS_MIME_VERSION                42
    { "Min-Expires",                    NULL },  /*   */
#define POS_MIN_EXPIRES                 43
    { "Min-SE",                         NULL },  /*  RFC4028  */
#define POS_MIN_SE                      44
    { "Organization",                   NULL },  /*  RFC3261  */
#define POS_ORGANIZATION                45
    { "Origination-Id",                 NULL },  /*  [3GPP TS 24.229 v15.11.0]  */
#define POS_ORIGINATION_ID              46
    { "P-Access-Network-Info",          NULL },  /*  RFC3455  */
#define POS_P_ACCESS_NETWORK_INFO       47
    { "P-Answer-State",                 NULL },  /*  RFC4964  */
#define POS_P_ANSWER_STATE              48
    { "P-Asserted-Identity",            NULL },  /*  RFC3325  */
#define POS_P_ASSERTED_IDENTITY         49
    { "P-Asserted-Service",             NULL },  /*  RFC6050  */
#define POS_P_ASSERTED_SERV             50
    { "P-Associated-URI",               NULL },  /*  RFC3455  */
#define POS_P_ASSOCIATED_URI            51
    { "P-Called-Party-ID",              NULL },  /*  RFC3455  */
#define POS_P_CALLED_PARTY_ID           52
    { "P-Charge-Info",                  NULL },  /*  RFC8496  */
#define POS_P_CHARGE_INFO               53
    { "P-Charging-Function-Addresses",  NULL },  /*  RFC3455  */
#define POS_P_CHARGING_FUNC_ADDRESSES   54
    { "P-Charging-Vector",              NULL },  /*  RFC3455  */
#define POS_P_CHARGING_VECTOR           55
    { "P-DCS-Trace-Party-ID",           NULL },  /*  RFC5503  */
#define POS_P_DCS_TRACE_PARTY_ID        56
    { "P-DCS-OSPS",                     NULL },  /*  RFC5503  */
#define POS_P_DCS_OSPS                  57
    { "P-DCS-Billing-Info",             NULL },  /*  RFC5503  */
#define POS_P_DCS_BILLING_INFO          58
    { "P-DCS-LAES",                     NULL },  /*  RFC5503  */
#define POS_P_DCS_LAES                  59
    { "P-DCS-Redirect",                 NULL },  /*  RFC5503  */
#define POS_P_DCS_REDIRECT              60
    { "P-Early-Media",                  NULL },  /*  RFC5009  */
#define POS_P_EARLY_MEDIA               61
    { "P-Media-Authorization",          NULL },  /*  RFC3313  */
#define POS_P_MEDIA_AUTHORIZATION       62
    { "P-Preferred-Identity",           NULL },  /*  RFC3325  */
#define POS_P_PREFERRED_IDENTITY        63
    { "P-Preferred-Service",            NULL },  /*  RFC6050  */
#define POS_P_PREFERRED_SERV            64
    { "P-Profile-Key",                  NULL },  /*  RFC5002  */
#define POS_P_PROFILE_KEY               65
    { "P-Refused-URI-List",             NULL },  /*  RFC5318  */
#define POS_P_REFUSED_URI_LST           66
    { "P-Served-User",                  NULL },  /*  RFC5502  */
#define POS_P_SERVED_USER               67
    { "P-User-Database",                NULL },  /*  RFC4457  */
#define POS_P_USER_DATABASE             68
    { "P-Visited-Network-ID",           NULL },  /*  RFC3455  */
#define POS_P_VISITED_NETWORK_ID        69
    { "Path",                           NULL },  /*  RFC3327  */
#define POS_PATH                        70
    { "Permission-Missing",             NULL },  /*  RFC5360  */
#define POS_PERMISSION_MISSING          71
    { "Policy-Contact",                 NULL },  /*  RFC3261  */
#define POS_POLICY_CONTACT              72
    { "Policy-ID",                      NULL },  /*  RFC3261  */
#define POS_POLICY_ID                   73
    { "Priority",                       NULL },  /*  RFC3261  */
#define POS_PRIORITY                    74
    { "Priority-Share",                 NULL },  /*  [3GPP TS 24.229 v13.16.0]  */
#define POS_PRIORITY_SHARE              75
    { "Priv-Answer-Mode",               NULL },  /*  RFC5373  */
#define POS_PRIV_ANSWER_MODE            76
    { "Privacy",                        NULL },  /*  RFC3323  */
#define POS_PRIVACY                     77
    { "Proxy-Authenticate",             NULL },  /*  */
#define POS_PROXY_AUTHENTICATE          78
    { "Proxy-Authorization",            NULL },  /*  */
#define POS_PROXY_AUTHORIZATION         79
    { "Proxy-Require",                  NULL },  /*  */
#define POS_PROXY_REQUIRE               80
    { "RAck",                           NULL },  /*  RFC3262  */
#define POS_RACK                        81
    { "Reason",                         NULL },  /*  RFC3326  */
#define POS_REASON                      82
    { "Reason-Phrase",                  NULL },  /*  RFC3326  */
#define POS_REASON_PHRASE               83
    { "Record-Route",                   NULL },  /*   */
#define POS_RECORD_ROUTE                84
    { "Recv-Info",                      NULL },  /*  RFC6086 */
#define POS_RECV_INFO                   85
    { "Refer-Sub",                      NULL },  /*  RFC4488  */
#define POS_REFER_SUB                   86
    { "Refer-To",                       "r"  },  /*  RFC3515  */
#define POS_REFER_TO                    87
    { "Referred-By",                    "b"  },  /*  RFC3892  */
#define POS_REFERRED_BY                 88
    { "Reject-Contact",                 "j"  },  /*  RFC3841  */
#define POS_REJECT_CONTACT              89
    { "Relayed-Charge",                 NULL },   /*  [3GPP TS 24.229 v12.14.0]   */
#define POS_RELAYED_CHARGE              90
    { "Replaces",                       NULL },  /*  RFC3891  */
#define POS_REPLACES                    91
    { "Reply-To",                       NULL },  /*  RFC3261  */
#define POS_REPLY_TO                    92
    { "Request-Disposition",            "d"  },  /*  RFC3841  */
#define POS_REQUEST_DISPOSITION         93
    { "Require",                        NULL },  /*  RFC3261  */
#define POS_REQUIRE                     94
    { "Resource-Priority",              NULL },  /*  RFC4412  */
#define POS_RESOURCE_PRIORITY           95
    { "Resource-Share",                 NULL },  /*  [3GPP TS 24.229 v13.7.0]  */
#define POS_RESOURCE_SHARE              96
    /*{ "Response-Key (Deprecated)     [RFC3261]*/
    { "Response-Source",                NULL },  /*  [3GPP TS 24.229 v15.11.0]  */
#define POS_RESPONSE_SOURCE             97
    { "Restoration-Info",               NULL },  /*  [3GPP TS 24.229 v12.14.0]  */
#define POS_RESTORATION_INFO            98
    { "Retry-After",                    NULL },  /*  RFC3261  */
#define POS_RETRY_AFTER                 99
    { "Route",                          NULL },  /*  RFC3261  */
#define POS_ROUTE                      100
    { "RSeq",                           NULL },  /*  RFC3262  */
#define POS_RSEQ                       101
    { "Security-Client",                NULL },  /*  RFC3329  */
#define POS_SECURITY_CLIENT            102
    { "Security-Server",                NULL },  /*  RFC3329  */
#define POS_SECURITY_SERVER            103
    { "Security-Verify",                NULL },  /*  RFC3329  */
#define POS_SECURITY_VERIFY            104
    { "Server",                         NULL },  /*  RFC3261  */
#define POS_SERVER                     105
    { "Service-Interact-Info",          NULL },  /*  [3GPP TS 24.229 v13.18.0]  */
#define POS_SERVICE_INTERACT_INFO      106
    { "Service-Route",                  NULL },  /*  RFC3608  */
#define POS_SERVICE_ROUTE              107
    { "Session-Expires",                "x"  },  /*  RFC4028  */
#define POS_SESSION_EXPIRES            108
    { "Session-ID",                     NULL },  /*  RFC7329  */
#define POS_SESSION_ID                 109
    { "SIP-ETag",                       NULL },  /*  RFC3903  */
#define POS_SIP_ETAG                   110
    { "SIP-If-Match",                   NULL },  /*  RFC3903  */
#define POS_SIP_IF_MATCH               111
    { "Subject",                        "s"  },  /*  RFC3261  */
#define POS_SUBJECT                    112
    { "Subscription-State",             NULL },  /*  RFC3265  */
#define POS_SUBSCRIPTION_STATE         113
    { "Supported",                      "k"  },  /*  RFC3261  */
#define POS_SUPPORTED                  114
    { "Suppress-If-Match",              NULL },  /*  RFC5839  */
#define POS_SUPPRESS_IF_MATCH          115
    { "Target-Dialog",                  NULL },  /*  RFC4538  */
#define POS_TARGET_DIALOG              116
    { "Timestamp",                      NULL },  /*  RFC3261  */
#define POS_TIMESTAMP                  117
    { "To",                             "t"  },  /*  RFC3261  */
#define POS_TO                         118
    { "Trigger-Consent",                NULL },  /*  RFC5360  */
#define POS_TRIGGER_CONSENT            119
    { "Unsupported",                    NULL },  /*  RFC3261  */
#define POS_UNSUPPORTED                120
    { "User-Agent",                     NULL },  /*  RFC3261  */
#define POS_USER_AGENT                 121
    { "Via",                            "v"  },  /*  RFC3261  */
#define POS_VIA                        122
    { "Warning",                        NULL },  /*  RFC3261  */
#define POS_WARNING                    123
    { "WWW-Authenticate",               NULL },  /*  RFC3261  */
#define POS_WWW_AUTHENTICATE           124
    { "Diversion",                      NULL },  /*  RFC5806  */
#define POS_DIVERSION                  125
    { "User-to-User",                   NULL },  /*  RFC7433   */
#define POS_USER_TO_USER               126
};




static gint hf_header_array[] = {
    -1, /* 0"Unknown-header" - Pad so that the real headers start at index 1 */
    -1, /* 1"Accept"                                    */
    -1, /* 2"Accept-Contact"                    RFC3841 */
    -1, /* 3"Accept-Encoding"                           */
    -1, /* 4"Accept-Language"                           */
    -1, /* 5"Accept-Resource-Priority"          RFC4412 */
    -1, /* 6"Additional-Identity		[3GPP TS 24.229 v16.7.0]  */
    -1, /* 7"Alert-Info",                               */
    -1, /* 8"Allow",                                    */
    -1, /* 9"Allow-Events",                     RFC3265 */
    -1, /* 10"Answer-Mode"                      RFC5373 */
    -1, /* 11"Attestation-Info		[3GPP TS 24.229 v15.11.0] */
    -1, /* 12"Authentication-Info"                      */
    -1, /* 13"Authorization",                           */
    -1, /* 14"Call-ID",                                 */
    -1, /* 15"Call-Info"                                */
    -1, /* 16"Cellular-Network-Info		[3GPP TS 24.229 v13.9.0] */
    -1, /* 17"Contact",                                 */
    -1, /* 18"Content-Disposition",                     */
    -1, /* 19"Content-Encoding",                        */
    -1, /* 20"Content-Language",                        */
    -1, /* 21"Content-Length",                          */
    -1, /* 22"Content-Type",                            */
    -1, /* 23"CSeq",                                    */
    -1, /* 24"Date",                                    */
    -1, /* 25"Error-Info",                              */
    -1, /* 26"Event",                                   */
    -1, /* 27"Expires",                                 */
    -1, /* 28"Feature-Caps",                            */
    -1, /* 29"Flow-Timer",                      RFC5626 */
    -1, /* 30"From",                                    */
    -1, /* 31"Geolocation",                             */
    -1, /* 32"Geolocation-Error",                       */
    -1, /* 33"Geolocation-Routing",                     */
    -1, /* 34"History-Info",                    RFC4244 */
    -1, /* 35"Identity",                                */
    -1, /* 36"Identity-Info",                   RFC4474 */
    -1, /* 37"Info-Package", RFC-ietf-sipcore-info-events-10.txt */
    -1, /* 38"In-Reply-To",                     RFC3261 */
    -1, /* 39"Join",                            RFC3911 */
    -1, /* 40"Max-Breadth"                      RFC5393 */
    -1, /* 41"Max-Forwards",                            */
    -1, /* 42"MIME-Version",                            */
    -1, /* 43"Min-Expires",                             */
    -1, /* 44"Min-SE",                          RFC4028 */
    -1, /* 45"Organization",                            */
    -1, /* 46"Origination-Id		[3GPP TS 24.229 v15.11.0] */
    -1, /* 47"P-Access-Network-Info",           RFC3455 */
    -1, /* 48"P-Answer-State",                  RFC4964 */
    -1, /* 49"P-Asserted-Identity",             RFC3325 */
    -1, /* 50"P-Asserted-Service",  RFC-drage-sipping-service-identification-05.txt */
    -1, /* 51"P-Associated-URI",                RFC3455 */
    -1, /* 52"P-Charge-Info",                   RFC8496 */
    -1, /* 53"P-Called-Party-ID",               RFC3455 */
    -1, /* 54"P-Charging-Function-Addresses",   RFC3455 */
    -1, /* 55"P-Charging-Vector",               RFC3455 */
    -1, /* 56"P-DCS-Trace-Party-ID",            RFC3603 */
    -1, /* 57"P-DCS-OSPS",                      RFC3603 */
    -1, /* 58"P-DCS-Billing-Info",              RFC3603 */
    -1, /* 59"P-DCS-LAES",                      RFC3603 */
    -1, /* 60"P-DCS-Redirect",                  RFC3603 */
    -1, /* 61"P-Early-Media",                           */
    -1, /* 62"P-Media-Authorization",           RFC3313 */
    -1, /* 63"P-Preferred-Identity",            RFC3325 */
    -1, /* 64"P-Preferred-Service",  RFC-drage-sipping-service-identification-05.txt */
    -1, /* 65"P-Profile-Key",                           */
    -1, /* 66"P-Refused-URI-List",              RFC5318 */
    -1, /* 67"P-Served-User",                   RFC5502 */
    -1, /* 68"P-User-Database                   RFC4457 */
    -1, /* 69"P-Visited-Network-ID",            RFC3455 */
    -1, /* 70"Path",                            RFC3327 */
    -1, /* 71"Permission-Missing"               RFC5360 */
    -1, /* 72"Policy-Contact"                   RFC5360 */
    -1, /* 73"Policy-ID"                        RFC5360 */
    -1, /* 74"Priority"                                 */
    -1, /* 75"Priority-Share		[3GPP TS 24.229 v13.16.0] */
    -1, /* 76"Priv-Answer-mode"                 RFC5373 */
    -1, /* 77"Privacy",                         RFC3323 */
    -1, /* 78"Proxy-Authenticate",                      */
    -1, /* 79"Proxy-Authorization",                     */
    -1, /* 80"Proxy-Require",                           */
    -1, /* 81"RAck",                            RFC3262 */
    -1, /* 82"Reason",                          RFC3326 */
    -1, /* 83"Reason-Phrase",                   RFC3326 */
    -1, /* 84"Record-Route",                            */
    -1, /* 85"Recv-Info",                       RFC6086 */
    -1, /* 86"Refer-Sub",",                     RFC4488 */
    -1, /* 87"Refer-To",                        RFC3515 */
    -1, /* 88"Referred-By",                             */
    -1, /* 89"Reject-Contact",                  RFC3841 */
    -1, /* 90"Relayed-Charge		[3GPP TS 24.229 v12.14.0] */
    -1, /* 91"Replaces",                        RFC3891 */
    -1, /* 92"Reply-To",                        RFC3261 */
    -1, /* 93"Request-Disposition",             RFC3841 */
    -1, /* 94"Require",                         RFC3261 */
    -1, /* 95"Resource-Priority",               RFC4412 */
    -1, /* 96"Resource-Share		[3GPP TS 24.229 v13.7.0] */
    -1, /* 97"Response-Source		[3GPP TS 24.229 v15.11.0] */
    -1, /* 98"Restoration-Info		[3GPP TS 24.229 v12.14.0] */
    -1, /* 99"Retry-After",                     RFC3261 */
    -1, /* 100"Route",                          RFC3261 */
    -1, /* 101"RSeq",                           RFC3262 */
    -1, /* 102"Security-Client",                RFC3329 */
    -1, /* 103"Security-Server",                RFC3329 */
    -1, /* 104"Security-Verify",                RFC3329 */
    -1, /* 105"Server",                         RFC3261 */
    -1, /* 106"Service-Interact-Info		[3GPP TS 24.229 v13.18.0] */
    -1, /* 107"Service-Route",                  RFC3608 */
    -1, /* 108"Session-Expires",                RFC4028 */
    -1, /* 109"Session-ID",                     RFC7329 */
    -1, /* 110"SIP-ETag",                       RFC3903 */
    -1, /* 111"SIP-If-Match",                   RFC3903 */
    -1, /* 112"Subject",                        RFC3261 */
    -1, /* 113"Subscription-State",             RFC3265 */
    -1, /* 114"Supported",                      RFC3261 */
    -1, /* 115"Suppress-If-Match",              RFC4538 */
    -1, /* 116"Target-Dialog",                  RFC4538 */
    -1, /* 117"Timestamp",                      RFC3261 */
    -1, /* 118"To",                             RFC3261 */
    -1, /* 119"Trigger-Consent"                 RFC5380 */
    -1, /* 120"Unsupported",                    RFC3261 */
    -1, /* 121"User-Agent",                     RFC3261 */
    -1, /* 122"Via",                            RFC3261 */
    -1, /* 123"Warning",                        RFC3261 */
    -1, /* 124"WWW-Authenticate",               RFC3261 */
    -1, /* 125"Diversion",                      RFC5806 */
    -1, /* 126"User-to-User",  draft-johnston-sipping-cc-uui-09 */
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
    {"sigcomp-id",    &hf_sip_via_sigcomp_id},
    {"oc",            &hf_sip_via_oc},
    {"oc-validity",   &hf_sip_via_oc_validity },
    {"oc-seq",        &hf_sip_via_oc_seq},
    {"oc-algo",       &hf_sip_via_oc_algo},
    {"be-route",      &hf_sip_via_be_route}
};

typedef enum {
    MECH_PARA_STRING = 0,
    MECH_PARA_UINT = 1,
} mech_parameter_type_t;

/* Track associations between parameter name and hf item for security mechanism*/
typedef struct {
    const char  *param_name;
    const gint  para_type;
    const gint  *hf_item;
} mech_parameter_t;

static mech_parameter_t sec_mechanism_parameters_hf_array[] =
{
    {"alg",     MECH_PARA_STRING,    &hf_sip_sec_mechanism_alg},
    {"ealg",    MECH_PARA_STRING,    &hf_sip_sec_mechanism_ealg},
    {"prot",    MECH_PARA_STRING,    &hf_sip_sec_mechanism_prot},
    {"spi-c",   MECH_PARA_UINT,      &hf_sip_sec_mechanism_spi_c},
    {"spi-s",   MECH_PARA_UINT,      &hf_sip_sec_mechanism_spi_s},
    {"port1",   MECH_PARA_UINT,      &hf_sip_sec_mechanism_port1},
    {"port-c",  MECH_PARA_UINT,      &hf_sip_sec_mechanism_port_c},
    {"port2",   MECH_PARA_UINT,      &hf_sip_sec_mechanism_port2},
    {"port-s",  MECH_PARA_UINT,      &hf_sip_sec_mechanism_port_s},
    {NULL, 0, 0}
};

typedef struct {
    gint *hf_sip_display;
    gint *hf_sip_addr;
    gint *hf_sip_user;
    gint *hf_sip_host;
    gint *hf_sip_port;
    gint *hf_sip_param;
    gint *ett_uri;
} hf_sip_uri_t;

static hf_sip_uri_t sip_pai_uri = {
    &hf_sip_pai_display,
    &hf_sip_pai_addr,
    &hf_sip_pai_user,
    &hf_sip_pai_host,
    &hf_sip_pai_port,
    &hf_sip_pai_param,
    &ett_sip_pai_uri
};

static hf_sip_uri_t sip_ppi_uri = {
    &hf_sip_ppi_display,
    &hf_sip_ppi_addr,
    &hf_sip_ppi_user,
    &hf_sip_ppi_host,
    &hf_sip_ppi_port,
    &hf_sip_ppi_param,
    &ett_sip_ppi_uri
};

static hf_sip_uri_t sip_pmiss_uri = {
    &hf_sip_pmiss_display,
    &hf_sip_pmiss_addr,
    &hf_sip_pmiss_user,
    &hf_sip_pmiss_host,
    &hf_sip_pmiss_port,
    &hf_sip_pmiss_param,
    &ett_sip_pmiss_uri
};

static hf_sip_uri_t sip_tc_uri = {
    &hf_sip_tc_display,
    &hf_sip_tc_addr,
    &hf_sip_tc_user,
    &hf_sip_tc_host,
    &hf_sip_tc_port,
    &hf_sip_tc_param,
    &ett_sip_tc_uri
};

static hf_sip_uri_t sip_to_uri = {
    &hf_sip_to_display,
    &hf_sip_to_addr,
    &hf_sip_to_user,
    &hf_sip_to_host,
    &hf_sip_to_port,
    &hf_sip_to_param,
    &ett_sip_to_uri
};

static hf_sip_uri_t sip_from_uri = {
    &hf_sip_from_display,
    &hf_sip_from_addr,
    &hf_sip_from_user,
    &hf_sip_from_host,
    &hf_sip_from_port,
    &hf_sip_from_param,
    &ett_sip_from_uri
};

static hf_sip_uri_t sip_req_uri = {
    &hf_sip_ruri_display,
    &hf_sip_ruri,
    &hf_sip_ruri_user,
    &hf_sip_ruri_host,
    &hf_sip_ruri_port,
    &hf_sip_ruri_param,
    &ett_sip_ruri
};

static hf_sip_uri_t sip_contact_uri = {
    &hf_sip_curi_display,
    &hf_sip_curi,
    &hf_sip_curi_user,
    &hf_sip_curi_host,
    &hf_sip_curi_port,
    &hf_sip_curi_param,
    &ett_sip_curi
};

static hf_sip_uri_t sip_route_uri = {
    &hf_sip_route_display,
    &hf_sip_route,
    &hf_sip_route_user,
    &hf_sip_route_host,
    &hf_sip_route_port,
    &hf_sip_route_param,
    &ett_sip_route
};

static hf_sip_uri_t sip_record_route_uri = {
    &hf_sip_record_route_display,
    &hf_sip_record_route,
    &hf_sip_record_route_user,
    &hf_sip_record_route_host,
    &hf_sip_record_route_port,
    &hf_sip_record_route_param,
    &ett_sip_record_route
};

static hf_sip_uri_t sip_service_route_uri = {
    &hf_sip_service_route_display,
    &hf_sip_service_route,
    &hf_sip_service_route_user,
    &hf_sip_service_route_host,
    &hf_sip_service_route_port,
    &hf_sip_service_route_param,
    &ett_sip_service_route
};

static hf_sip_uri_t sip_path_uri = {
    &hf_sip_path_display,
    &hf_sip_path,
    &hf_sip_path_user,
    &hf_sip_path_host,
    &hf_sip_path_port,
    &hf_sip_path_param,
    &ett_sip_path
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

/* global_sip_raw_text determines whether we are going to display       */
/* the raw text of the SIP message, much like the MEGACO dissector does.    */
static gboolean global_sip_raw_text = FALSE;
/* global_sip_raw_text_without_crlf determines whether we are going to display  */
/* the raw text of the SIP message with or without the '\r\n'.          */
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

/* whether we hold off tracking RTP conversations until an SDP answer is received */
static gboolean sip_delay_sdp_changes = FALSE;

/* Hide the generated Call IDs or not */
static gboolean sip_hide_generatd_call_ids = FALSE;

/* Extension header subdissectors */
static dissector_table_t ext_hdr_subdissector_table;

/* Custom SIP headers */
typedef struct _header_field_t {
    gchar* header_name;
    gchar* header_desc;
} header_field_t;

static header_field_t* sip_custom_header_fields;
static guint sip_custom_num_header_fields;
static GHashTable *sip_custom_header_fields_hash;
static hf_register_info *dynamic_hf;
static guint dynamic_hf_size;

static gboolean
header_fields_update_cb(void *r, char **err)
{
    header_field_t *rec = (header_field_t *)r;
    char c;

    if (rec->header_name == NULL) {
        *err = g_strdup("Header name can't be empty");
        return FALSE;
    }

    g_strstrip(rec->header_name);
    if (rec->header_name[0] == 0) {
        *err = g_strdup("Header name can't be empty");
        return FALSE;
    }

    /* Check for invalid characters (to avoid asserting out when
    * registering the field).
    */
    c = proto_check_field_name(rec->header_name);
    if (c) {
        *err = ws_strdup_printf("Header name can't contain '%c'", c);
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}

static void *
header_fields_copy_cb(void* n, const void* o, size_t siz _U_)
{
    header_field_t* new_rec = (header_field_t*)n;
    const header_field_t* old_rec = (const header_field_t*)o;

    new_rec->header_name = g_strdup(old_rec->header_name);
    new_rec->header_desc = g_strdup(old_rec->header_desc);

    return new_rec;
}

static void
header_fields_free_cb(void*r)
{
    header_field_t* rec = (header_field_t*)r;

    g_free(rec->header_name);
    g_free(rec->header_desc);
}

static void
deregister_header_fields(void)
{
    if (dynamic_hf) {
        /* Deregister all fields */
        for (guint i = 0; i < dynamic_hf_size; i++) {
            proto_deregister_field(proto_sip, *(dynamic_hf[i].p_id));
            g_free(dynamic_hf[i].p_id);
        }

        proto_add_deregistered_data(dynamic_hf);
        dynamic_hf = NULL;
        dynamic_hf_size = 0;
    }

    if (sip_custom_header_fields_hash) {
        g_hash_table_destroy(sip_custom_header_fields_hash);
        sip_custom_header_fields_hash = NULL;
    }
}

static void
header_fields_post_update_cb(void)
{
    gint* hf_id;
    gchar* header_name;
    gchar* header_name_key;

    deregister_header_fields();

    if (sip_custom_num_header_fields) {
        sip_custom_header_fields_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
        dynamic_hf = g_new0(hf_register_info, sip_custom_num_header_fields);
        dynamic_hf_size = sip_custom_num_header_fields;

        for (guint i = 0; i < dynamic_hf_size; i++) {
            hf_id = g_new(gint, 1);
            *hf_id = -1;
            header_name = g_strdup(sip_custom_header_fields[i].header_name);
            header_name_key = g_ascii_strdown(header_name, -1);

            dynamic_hf[i].p_id = hf_id;
            dynamic_hf[i].hfinfo.name = header_name;
            dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("sip.%s", header_name);
            dynamic_hf[i].hfinfo.type = FT_STRING;
            dynamic_hf[i].hfinfo.display = BASE_NONE;
            dynamic_hf[i].hfinfo.strings = NULL;
            dynamic_hf[i].hfinfo.bitmask = 0;
            dynamic_hf[i].hfinfo.blurb = g_strdup(sip_custom_header_fields[i].header_desc);
            HFILL_INIT(dynamic_hf[i]);

            g_hash_table_insert(sip_custom_header_fields_hash, header_name_key, hf_id);
        }

        proto_register_field_array(proto_sip, dynamic_hf, dynamic_hf_size);
    }
}

static void
header_fields_reset_cb(void)
{
    deregister_header_fields();
}

UAT_CSTRING_CB_DEF(sip_custom_header_fields, header_name, header_field_t)
UAT_CSTRING_CB_DEF(sip_custom_header_fields, header_desc, header_field_t)

/* SIP authorization parameters */
static gboolean global_sip_validate_authorization = FALSE;

typedef struct _authorization_user_t {
    gchar* username;
    gchar* realm;
    gchar* password;
} authorization_user_t;

static authorization_user_t* sip_authorization_users = NULL;
static guint sip_authorization_num_users = 0;

static gboolean
authorization_users_update_cb(void *r, char **err)
{
    authorization_user_t *rec = (authorization_user_t *)r;
    char c;

    if (rec->username == NULL) {
        *err = g_strdup("Username can't be empty");
        return FALSE;
    }

    g_strstrip(rec->username);
    if (rec->username[0] == 0) {
        *err = g_strdup("Username can't be empty");
        return FALSE;
    }

    /* Check for invalid characters (to avoid asserting out when
    * registering the field).
    */
    c = proto_check_field_name(rec->username);
    if (c) {
        *err = ws_strdup_printf("Username can't contain '%c'", c);
        return FALSE;
    }

    *err = NULL;
    return TRUE;
}

static void *
authorization_users_copy_cb(void* n, const void* o, size_t siz _U_)
{
    authorization_user_t* new_rec = (authorization_user_t*)n;
    const authorization_user_t* old_rec = (const authorization_user_t*)o;

    new_rec->username = g_strdup(old_rec->username);
    new_rec->realm = g_strdup(old_rec->realm);
    new_rec->password = g_strdup(old_rec->password);

    return new_rec;
}

static void
authorization_users_free_cb(void*r)
{
    authorization_user_t* rec = (authorization_user_t*)r;

    g_free(rec->username);
    g_free(rec->realm);
    g_free(rec->password);
}

UAT_CSTRING_CB_DEF(sip_authorization_users, username, authorization_user_t)
UAT_CSTRING_CB_DEF(sip_authorization_users, realm, authorization_user_t)
UAT_CSTRING_CB_DEF(sip_authorization_users, password, authorization_user_t)

/* Forward declaration we need below */
void proto_reg_handoff_sip(void);
static gboolean dissect_sip_common(tvbuff_t *tvb, int offset, int remaining_length, packet_info *pinfo,
    proto_tree *tree, gboolean is_heur, gboolean use_reassembly);
static line_type_t sip_parse_line(tvbuff_t *tvb, int offset, gint linelen,
    guint *token_1_len);
static gboolean sip_is_known_request(tvbuff_t *tvb, int meth_offset,
    guint meth_len, guint *meth_idx);
static gint sip_is_known_sip_header(gchar *header_name, guint header_len);
static void dfilter_sip_request_line(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint offset,
    guint meth_len, gint linelen);
static void dfilter_sip_status_line(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint line_end, gint offset);
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

typedef struct
{
    gchar * username;
    gchar * realm;
    gchar * uri;
    gchar * nonce;
    gchar * cnonce;
    gchar * nonce_count;
    gchar * response;
    gchar * qop;
    gchar * algorithm;
    gchar * method;
} sip_authorization_t;

static authorization_user_t * sip_get_authorization(sip_authorization_t *authorization_info);
static gboolean sip_validate_authorization(sip_authorization_t *authorization_info, gchar *password);

static authorization_user_t * sip_get_authorization(sip_authorization_t *authorization_info)
{
    guint i;
    for (i = 0; i < sip_authorization_num_users; i++) {
        if ((!strcmp(sip_authorization_users[i].username, authorization_info->username)) &&
            (!strcmp(sip_authorization_users[i].realm, authorization_info->realm))) {
            return &sip_authorization_users[i];
        }
    }
    return NULL;
}

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
 * Don't use the conversation mechanism, but instead:
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
static GHashTable *sip_headers_hash = NULL;     /* Hash table */

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
    const sip_hash_key* val1 = (const sip_hash_key*)v;
    const sip_hash_key* val2 = (const sip_hash_key*)v2;

    /* Call id must match */
    if (strcmp(val1->call_id, val2->call_id) != 0)
    {
        return 0;
    }

    /* Addresses must match */
    return  (addresses_equal(&(val1->source_address), &(val2->source_address))) &&
        (val1->source_port == val2->source_port) &&
        (addresses_equal(&(val1->dest_address), &(val2->dest_address))) &&
        (val1->dest_port == val2->dest_port);
}


/* Initializes the hash table each time a new
 * file is loaded or re-loaded in wireshark */
static void
sip_init_protocol(void)
{
    guint i;
    gchar *value_copy;
    sip_hash = g_hash_table_new(g_str_hash , sip_equal);

    /* Hash table for quick lookup of SIP headers names to hf entry (POS_x) */
    sip_headers_hash = g_hash_table_new(g_str_hash , g_str_equal);
    for (i = 1; i < array_length(sip_headers); i++){
        value_copy = wmem_strdup(wmem_file_scope(), sip_headers[i].name);
        ascii_strdown_inplace(value_copy);
        g_hash_table_insert(sip_headers_hash, (gpointer)value_copy, GINT_TO_POINTER(i));
    }
}

static void
sip_cleanup_protocol(void)
{
     g_hash_table_destroy(sip_hash);
     g_hash_table_destroy(sip_headers_hash);
}

/* Call the export PDU tap with relevant data */
static void
export_sip_pdu(packet_info *pinfo, tvbuff_t *tvb)
{
  exp_pdu_data_t *exp_pdu_data = export_pdu_create_common_tags(pinfo, "sip", EXP_PDU_TAG_PROTO_NAME);

  exp_pdu_data->tvb_captured_length = tvb_captured_length(tvb);
  exp_pdu_data->tvb_reported_length = tvb_reported_length(tvb);
  exp_pdu_data->pdu_tvb = tvb;

  tap_queue_packet(exported_pdu_tap, pinfo, exp_pdu_data);

}

typedef enum
{
    SIP_URI_TYPE_ABSOLUTE_URI,
    SIP_URI_TYPE_SIP,
    SIP_URI_TYPE_TEL

} sip_uri_type_enum_t;

/* Structure to collect info about a sip uri */
typedef struct _uri_offset_info
{
    sip_uri_type_enum_t uri_type;
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
    uri_offsets->uri_type = SIP_URI_TYPE_ABSOLUTE_URI;
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
    guchar c = '\0';
    gint current_offset;
    gint queried_offset;
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

    /* Check if it's really a sip uri ( it might be a tel uri, parse that?) */
    if (tvb_strneql(tvb, current_offset, "sip", 3) != 0){
        if (uri_offsets->uri_end != -1) {
            /* We know where the URI ends, set the offsets*/
            return uri_offsets->name_addr_end;
        }
        return -1;
    }

    uri_offsets->uri_type = SIP_URI_TYPE_SIP;

    if(uri_offsets->uri_end == -1)
    {
        /* name-addr form was NOT used e.g no closing ">" */
        /* look for the first ',' or ';' which will mark the end of this URI
         * In this case a semicolon indicates a header field parameter, and not an uri parameter.
         */
        int end_offset;

        end_offset = tvb_ws_mempbrk_pattern_guint8(tvb, current_offset, line_end_offset - current_offset, &pbrk_comma_semi, NULL);

        if (end_offset != -1)
        {
            uri_offsets->uri_end = end_offset - 1;
        }
        else
        {
            /* We don't have a semicolon or a comma.
             * In that case, we assume that the end of the URI is at the line end
              */
            uri_offsets->uri_end = line_end_offset - 3; /* remove '\r\n' */
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
        parameter_end_offset = tvb_ws_mempbrk_pattern_guint8(tvb, parameter_end_offset, line_end_offset - parameter_end_offset, &pbrk_param_end_colon_brackets, &c);
        if (parameter_end_offset == -1)
        {
            parameter_end_offset = line_end_offset;
            break;
        }

        /* after adding character to this switch() , update also pbrk_param_end_colon_brackets */
        switch (c) {
            case '>':
            case ',':
                goto uri_host_end_found;
            case ';':
                uri_offsets->uri_parameters_start = parameter_end_offset + 1;
                goto uri_host_end_found;
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
                DISSECTOR_ASSERT_NOT_REACHED();
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
            parameter_end_offset = tvb_ws_mempbrk_pattern_guint8(tvb, parameter_end_offset, line_end_offset - parameter_end_offset, &pbrk_param_end, &c);
            if (parameter_end_offset == -1)
            {
                parameter_end_offset = line_end_offset;
                break;
            }

            /* after adding character to this switch(), update also pbrk_param_end */
            switch (c) {
                case '>':
                case ',':
                    goto uri_host_port_end_found;
                case ';':
                    uri_offsets->uri_parameters_start = parameter_end_offset + 1;
                    goto uri_host_port_end_found;
                case '?':
                case ' ':
                case '\r':
                    goto uri_host_port_end_found;
                default :
                    DISSECTOR_ASSERT_NOT_REACHED();
                    break;
            }
        }

    uri_host_port_end_found:

        uri_offsets->uri_host_port_end = parameter_end_offset -1;
    }

    return uri_offsets->name_addr_end;
}

void
dfilter_store_sip_from_addr(tvbuff_t *tvb,proto_tree *tree,guint parameter_offset, guint parameter_len)
{
    proto_item *pi;

    pi = proto_tree_add_item(tree, hf_sip_from_addr, tvb, parameter_offset, parameter_len, ENC_UTF_8);
    proto_item_set_generated(pi);
}

static proto_item *
sip_proto_tree_add_uint(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint value_offset, gint value_len)
{
    const char *str;
    unsigned long val;

    /* don't fetch string when field is not referenced */
    if (!proto_field_is_referenced(tree, hfindex))
        return tree;

    str = tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, value_len, ENC_UTF_8|ENC_NA);
    val = strtoul(str, NULL, 10);

    return proto_tree_add_uint(tree, hfindex, tvb, start, length, (guint32) val);
}

static proto_item *
sip_proto_tree_add_string(proto_tree *tree, int hfindex, tvbuff_t *tvb, gint start, gint length, gint value_offset, gint value_len)
{
    const char *str;

    /* don't fetch string when field is not referenced */
    if (!proto_field_is_referenced(tree, hfindex))
        return tree;

    str = tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, value_len, ENC_UTF_8|ENC_NA);

    return proto_tree_add_string(tree, hfindex, tvb, start, length, str);
}

static void
sip_proto_set_format_text(const proto_tree *tree, proto_item *item, tvbuff_t *tvb, int offset, int length)
{
    if (tree != item && item && PTREE_DATA(item)->visible)
        proto_item_set_text(item, "%s", tvb_format_text(wmem_packet_scope(), tvb, offset, length));
}
/*
 * XXXX If/when more parameters are added consider doing something similar to what's done in
 * packet-magaco.c for find_megaco_localParam_names() possibly adding the hf to the array and have a generic
 * dissection function here.
 */
static void
dissect_sip_generic_parameters(tvbuff_t *tvb, proto_tree* tree, packet_info *pinfo _U_, gint current_offset, gint line_end_offset)
{
    gint semi_colon_offset, par_name_end_offset, equals_offset, length;
    /* Loop over the generic parameter(s)*/
    while (current_offset < line_end_offset) {
        gchar *param_name = NULL;

        /* skip Spaces and Tabs */
        current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

        semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ';');

        if (semi_colon_offset == -1) {
            semi_colon_offset = line_end_offset;
        }

        length = semi_colon_offset - current_offset;

        /* Parse parameter and value */
        equals_offset = tvb_find_guint8(tvb, current_offset + 1, length, '=');
        if (equals_offset != -1) {
            /* Has value part */
            par_name_end_offset = equals_offset;
            /* Extract the parameter name */
            param_name = tvb_get_string_enc(wmem_packet_scope(), tvb, current_offset, par_name_end_offset - current_offset, ENC_UTF_8 | ENC_NA);
            /* Access-Info fields  */
            if ((param_name != NULL) && (g_ascii_strcasecmp(param_name, "service-priority") == 0)) {
                proto_tree_add_item(tree, hf_sip_service_priority, tvb,
                    equals_offset + 1, semi_colon_offset - equals_offset - 1, ENC_UTF_8 | ENC_NA);
            }
            else {
                proto_tree_add_format_text(tree, tvb, current_offset, length);
            }
        }
        else {
            proto_tree_add_format_text(tree, tvb, current_offset, length);
        }
        current_offset = semi_colon_offset + 1;
    }
}


/*
 *           History-Info = "History-Info" HCOLON
 *                            hi-entry *(COMMA hi-entry)
 *
 *          hi-entry = hi-targeted-to-uri *( SEMI hi-param )
 *          hi-targeted-to-uri= name-addr
 *
 *
 *          hi-param = hi-index / hi-extension
 *
 *          hi-index = "index" EQUAL 1*DIGIT *(DOT 1*DIGIT)
 *
 *          hi-extension = generic-param
 */

static gint
dissect_sip_history_info(tvbuff_t *tvb, proto_tree* tree, packet_info *pinfo _U_, gint current_offset,
                gint line_end_offset)
{
    int comma_offset;
    gboolean first_time = TRUE;

    /* split the line at the commas */
    while (line_end_offset > current_offset){
        comma_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ',');
        if(comma_offset == -1){
            if(first_time == TRUE){
                /* It was only on parameter no need to split it up */
                return line_end_offset;
            }
            /* Last parameter */
            comma_offset = line_end_offset;
        }
        first_time = FALSE;
        proto_tree_add_format_text(tree, tvb, current_offset, comma_offset-current_offset);

        current_offset = comma_offset+1;
    }

    return line_end_offset;

}


/*
 *    The syntax for the P-Charging-Function-Addresses header is described
 *   as follows:
 *
 *      P-Charging-Addr        = "P-Charging-Function-Addresses" HCOLON
 *                               charge-addr-params
 *                               *(SEMI charge-addr-params)
 *      charge-addr-params     = ccf / ecf / generic-param
 *      ccf                    = "ccf" EQUAL gen-value
 *      ecf                    = "ecf" EQUAL gen-value
 *      generic-param          =  token [ EQUAL gen-value ]
 *      gen-value              =  token / host / quoted-string
 *
 */

static gint
dissect_sip_p_charging_func_addresses(tvbuff_t *tvb, proto_tree* tree, packet_info *pinfo _U_, gint current_offset,
                gint line_end_offset)
{
    gint semi_offset, start_quote_offset, end_quote_offset;
    gboolean first_time = TRUE;

    while (line_end_offset > current_offset){
        /* Do we have a quoted string ? */
        start_quote_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, '"');
        if(start_quote_offset>0){
            /* Find end of quoted string */
            end_quote_offset = tvb_find_guint8(tvb, start_quote_offset+1, line_end_offset - (start_quote_offset+1), '"');
            /* Find parameter end */
            if (end_quote_offset>0)
                semi_offset = tvb_find_guint8(tvb, end_quote_offset+1, line_end_offset - (end_quote_offset+1), ';');
            else {
                /* XXX expert info about unterminated string */
                semi_offset = tvb_find_guint8(tvb, start_quote_offset+1, line_end_offset - (start_quote_offset+1), ';');
            }
        }else{
            /* Find parameter end */
            semi_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ';');
        }
        if(semi_offset == -1){
            if(first_time == TRUE){
            /* It was only one parameter no need to split it up */
            return line_end_offset;
            }
            /* Last parameter */
            semi_offset = line_end_offset;
        }
        first_time = FALSE;
        proto_tree_add_format_text(tree, tvb, current_offset, semi_offset-current_offset);

        current_offset = semi_offset+1;

    }

    return current_offset;
}

/*
 *  token         =  1*(alphanum / "-" / "." / "!" / "%" / "*"
 *                    / "_" / "+" / "`" / "'" / "~" )
 *  LWS           =  [*WSP CRLF] 1*WSP ; linear whitespace
 *  name-addr     =  [ display-name ] LAQUOT addr-spec RAQUOT
 *  addr-spec     =  SIP-URI / SIPS-URI / absoluteURI
 *  display-name  =  *(token LWS)/ quoted-string
 *  absoluteURI    =  scheme ":" ( hier-part / opaque-part )
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
display_sip_uri (tvbuff_t *tvb, proto_tree *sip_element_tree, packet_info *pinfo, uri_offset_info* uri_offsets, hf_sip_uri_t* uri)
{
    proto_item *ti;
    proto_tree *uri_item_tree = NULL;
    tvbuff_t *next_tvb;

    if(uri_offsets->display_name_end != uri_offsets->display_name_start) {
        proto_tree_add_item(sip_element_tree, *(uri->hf_sip_display), tvb, uri_offsets->display_name_start,
                            uri_offsets->display_name_end - uri_offsets->display_name_start + 1, ENC_UTF_8|ENC_NA);
        ti = proto_tree_add_item(sip_element_tree, hf_sip_display, tvb, uri_offsets->display_name_start,
                                 uri_offsets->display_name_end - uri_offsets->display_name_start + 1, ENC_UTF_8);
        proto_item_set_hidden(ti);
    }

    ti = proto_tree_add_item(sip_element_tree, *(uri->hf_sip_addr),
                             tvb, uri_offsets->uri_start, uri_offsets->uri_end - uri_offsets->uri_start + 1, ENC_UTF_8|ENC_NA);
    uri_item_tree = proto_item_add_subtree(ti, *(uri->ett_uri));

    if (uri_offsets->uri_type != SIP_URI_TYPE_SIP) {
        return ti;
    }

    if(uri_offsets->uri_user_end > uri_offsets->uri_user_start) {
        proto_tree_add_item(uri_item_tree, *(uri->hf_sip_user), tvb, uri_offsets->uri_user_start,
                            uri_offsets->uri_user_end - uri_offsets->uri_user_start + 1, ENC_UTF_8|ENC_NA);
        if (tvb_get_guint8(tvb, uri_offsets->uri_user_start) == '+') {
            dissect_e164_msisdn(tvb, uri_item_tree, uri_offsets->uri_user_start + 1, uri_offsets->uri_user_end - uri_offsets->uri_user_start, E164_ENC_UTF8);
        }

        /* If we have a SIP diagnostics sub dissector call it */
        if (sip_uri_userinfo_handle) {
            next_tvb = tvb_new_subset_length_caplen(tvb, uri_offsets->uri_user_start, uri_offsets->uri_user_end - uri_offsets->uri_user_start + 1,
                                      uri_offsets->uri_user_end - uri_offsets->uri_user_start + 1);
            call_dissector(sip_uri_userinfo_handle, next_tvb, pinfo, uri_item_tree);
        }

    }

    proto_tree_add_item(uri_item_tree, *(uri->hf_sip_host), tvb, uri_offsets->uri_host_start,
                        uri_offsets->uri_host_end - uri_offsets->uri_host_start + 1, ENC_UTF_8|ENC_NA);

    if(uri_offsets->uri_host_port_end > uri_offsets->uri_host_port_start) {
        proto_tree_add_item(uri_item_tree, *(uri->hf_sip_port), tvb, uri_offsets->uri_host_port_start,
                            uri_offsets->uri_host_port_end - uri_offsets->uri_host_port_start + 1, ENC_UTF_8|ENC_NA);
    }

    if (uri_offsets->uri_parameters_start != -1) {
        /* Move current offset to the start of the first param */
        gint current_offset          = uri_offsets->uri_parameters_start;
        gint uri_params_start_offset = current_offset;
        gint queried_offset;
        gint uri_param_end_offset = -1;
        gchar c;

        /* Put the contact parameters in the tree */

        while (current_offset < uri_offsets->name_addr_end) {
            queried_offset = tvb_ws_mempbrk_pattern_guint8(tvb, current_offset, uri_offsets->name_addr_end - current_offset, &pbrk_comma_semi, &c);

            if (queried_offset == -1) {
                /* Reached line end */
                /* Check if the line ends with a ">", if so decrement end offset. */
                c = tvb_get_guint8(tvb, uri_offsets->name_addr_end);

                if (c == '>') {
                    uri_param_end_offset = uri_offsets->name_addr_end - 1;
                } else {
                    uri_param_end_offset = uri_offsets->name_addr_end;
                }
                current_offset       = uri_offsets->name_addr_end;
            } else if (c==',') {
                uri_param_end_offset = queried_offset;
                current_offset       = queried_offset+1; /* must move forward */
            } else if (c==';') {
                /* More parameters */
                uri_param_end_offset = queried_offset-1;
                current_offset       = tvb_skip_wsp(tvb, queried_offset+1, uri_offsets->name_addr_end - queried_offset + 1);
            }

            proto_tree_add_item(uri_item_tree, *(uri->hf_sip_param), tvb, uri_params_start_offset ,
                uri_param_end_offset - uri_params_start_offset +1, ENC_UTF_8|ENC_NA);

            /* In case there are more parameters, point to the start of it */
            uri_params_start_offset = current_offset;
        }
    }

    return uri_item_tree;
}




/* Code to parse a contact header item
 * Returns Offset end off parsing or -1 for unsuccessful parsing
 * * contact-param  =  (name-addr / addr-spec) *(SEMI contact-params)
 */
static gint
dissect_sip_contact_item(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gint start_offset, gint line_end_offset,
            guchar* contacts_expires_0, guchar* contacts_expires_unknown)
{
    gchar c;
    gint current_offset;
    gint queried_offset;
    gint contact_params_start_offset = -1;
    /*gint contact_param_end_offset = -1;*/
    uri_offset_info uri_offsets;
    gboolean end_of_hdr = FALSE;
    gboolean has_expires_param = FALSE;

    /* skip Spaces and Tabs */
    start_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

    if(start_offset >= line_end_offset) {
        /* Nothing to parse */
        return -1;
    }

    /* Initialize the uri_offsets */
    sip_uri_offset_init(&uri_offsets);
    /* contact-param  =  (name-addr / addr-spec) *(SEMI contact-params) */
    current_offset = dissect_sip_name_addr_or_addr_spec(tvb, pinfo, start_offset, line_end_offset, &uri_offsets);
    if(current_offset == -1)
    {
        /* Parsing failed */
        return -1;
    }
    display_sip_uri(tvb, tree, pinfo, &uri_offsets, &sip_contact_uri);

    /* check if there's a comma before a ';', in which case we stop parsing this item at the comma */
    queried_offset = tvb_find_guint8(tvb, uri_offsets.uri_end, line_end_offset - uri_offsets.uri_end, ',');

    /* Check if we have contact parameters, the uri should be followed by a ';' */
    contact_params_start_offset = tvb_find_guint8(tvb, uri_offsets.uri_end, line_end_offset - uri_offsets.uri_end, ';');

    if (queried_offset != -1 && (queried_offset < contact_params_start_offset || contact_params_start_offset == -1)) {
        /* no expires param */
        (*contacts_expires_unknown)++;
        return queried_offset;
    }

    /* check if contact-params is present */
    if(contact_params_start_offset == -1) {
        /* no expires param */
        (*contacts_expires_unknown)++;
        return line_end_offset;
    }

    /* Move current offset to the start of the first param */
    contact_params_start_offset++;
    current_offset = contact_params_start_offset;

    /* Put the contact parameters in the tree */

    queried_offset = current_offset;

    while(current_offset< line_end_offset){
        c = '\0';
        queried_offset++;
        queried_offset = (queried_offset < line_end_offset) ? tvb_ws_mempbrk_pattern_guint8(tvb, queried_offset, line_end_offset - queried_offset, &pbrk_header_end_dquote, &c) : -1;
        if (queried_offset != -1)
        {
            switch (c) {
                /* prevent tree from displaying the '\r\n' as part of the param */
                case '\r':
                case '\n':
                    end_of_hdr = TRUE;
                    /* fall through */
                case ',':
                case ';':
                case '"':
                    break;
                default :
                    DISSECTOR_ASSERT_NOT_REACHED();
                    break;
            }
        }

        if (queried_offset == -1) {
            /* Last parameter, line end */
            current_offset = line_end_offset;
        }else if(c=='"'){
            /* Do we have a quoted string ? */
            queried_offset = tvb_find_guint8(tvb, queried_offset+1, line_end_offset - queried_offset, '"');
            if(queried_offset==-1){
                /* We have an opening quote but no closing quote. */
                current_offset = line_end_offset;
            } else {
                current_offset = tvb_ws_mempbrk_pattern_guint8(tvb, queried_offset+1, line_end_offset - queried_offset, &pbrk_comma_semi, &c);
                if(current_offset==-1){
                    /* Last parameter, line end */
                    current_offset = line_end_offset;
                }
            }
        }else{
            current_offset = queried_offset;
        }
        proto_tree_add_item(tree, hf_sip_contact_param, tvb, contact_params_start_offset ,
            current_offset - contact_params_start_offset, ENC_UTF_8);

        /* need to check for an 'expires' parameter
         * TODO: this should be done in a common way for all headers,
         * but To/From/etc do their own right now so doing the same here
         */
        /* also, this is a bad way of checking param names, but it's what To/From
         * etc, do. But legally "exPiRes = value" is also legit.
         */
        if (tvb_strncaseeql(tvb, contact_params_start_offset, "expires=", 8) == 0) {
            gint32 expire;
            /* if the expires param value is 0, then it's de-registering
             * this assumes the message is a REGISTER request/response, but these
             * contacts_expires_0/contacts_expires_unknown variables only get used then,
             * so that's ok
             */
            if (!ws_strtoi32(tvb_get_string_enc(wmem_packet_scope(), tvb, contact_params_start_offset+8,
                    current_offset - (contact_params_start_offset+8), ENC_UTF_8|ENC_NA), NULL, &expire))
                return contact_params_start_offset+8;
            if (expire == 0) {
                (*contacts_expires_0)++;
                /* it is actually unusual - arguably invalid - for a SIP REGISTER
                 * 200 OK _response_ to contain Contacts with expires=0.
                 *
                 * See Bug https://gitlab.com/wireshark/wireshark/-/issues/10364
                 * Why this warning was removed (3GPP usage, 3GPP TS24.229 )
                 */
#if 0
                if (stat_info && stat_info->response_code > 199 && stat_info->response_code < 300) {
                    proto_tree_add_expert_format(tree, pinfo, &ei_sip_odd_register_response,
                        tvb, contact_params_start_offset, current_offset - contact_params_start_offset,
                        "SIP REGISTER %d response contains Contact with expires=0",
                        stat_info->response_code);
                }
#endif
            } else {
                has_expires_param = TRUE;
            }
        }

        /* In case there are more parameters, point to the start of it */
        contact_params_start_offset = current_offset+1;
        queried_offset = contact_params_start_offset;
        if (end_of_hdr) {
            /* '\r' or '\n' found, stop parsing and also set current offset to end
             * so the return value indicates we reached line end
             */
            current_offset = line_end_offset;
        }
        if (c == ',') {
            /* comma separator found, stop parsing of current contact-param here */
            break;
        }
    }

    if (!has_expires_param) {
        (*contacts_expires_unknown)++;
    }

    return current_offset;
}

/* Code to parse an authorization header item
 * Returns offset at end of parsing, or -1 for unsuccessful parsing
 */
static gint
dissect_sip_authorization_item(tvbuff_t *tvb, proto_tree *tree, gint start_offset, gint line_end_offset, sip_authorization_t *authorization_info)
{
    gint current_offset, par_name_end_offset, queried_offset, value_offset, value_search_offset;
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
    if(equals_offset == -1){
        /* malformed parameter */
        return -1;
    }
    par_name_end_offset = equals_offset - 1;
    par_name_end_offset = tvb_skip_wsp_return(tvb,par_name_end_offset);

    /* Extract the parameter name */
    name = tvb_get_string_enc(wmem_packet_scope(), tvb, start_offset, par_name_end_offset-start_offset, ENC_UTF_8|ENC_NA);

    value_offset = tvb_skip_wsp(tvb, equals_offset + 1, line_end_offset - (equals_offset + 1));
    if (tvb_get_guint8(tvb, value_offset) == '\"') {
        /* quoted value */
        value_search_offset = value_offset;
        do {
            value_search_offset++;
            queried_offset = tvb_find_guint8 (tvb, value_search_offset, line_end_offset - value_search_offset, '\"');
        } while ((queried_offset != -1) && (tvb_get_guint8(tvb, queried_offset - 1) == '\\'));
        if (queried_offset == -1) {
            /* Closing quote not found, return line end */
            current_offset = line_end_offset;
        } else {
            /* Include closing quotes */
            current_offset = queried_offset + 1;
        }
    } else {
        /* unquoted value */
        queried_offset = tvb_find_guint8 (tvb, value_offset, line_end_offset - value_offset, ',');
        if (queried_offset == -1) {
            /* Last parameter, line end */
            current_offset = line_end_offset;
        } else {
            current_offset = queried_offset;
        }
    }

    /* Try to add parameter as a filterable item */
    for (auth_parameter = &auth_parameters_hf_array[i];
         i < array_length(auth_parameters_hf_array);
         i++, auth_parameter++)
    {
        if (g_ascii_strcasecmp(name, auth_parameter->param_name) == 0)
        {
            proto_tree_add_item(tree, *(auth_parameter->hf_item), tvb,
                                value_offset, current_offset - value_offset,
                                ENC_UTF_8|ENC_NA);
            if (global_sip_validate_authorization) {
                gint real_value_offset = value_offset;
                gint real_value_length = current_offset - value_offset;
                if ((tvb_get_guint8(tvb, value_offset) == '\"') && (tvb_get_guint8(tvb, current_offset - 1) == '\"') && (real_value_length > 1)) {
                    real_value_offset++;
                    real_value_length -= 2;
                }
                if (g_ascii_strcasecmp(name, "response") == 0) {
                    authorization_info->response = tvb_get_string_enc(wmem_packet_scope(), tvb, real_value_offset, real_value_length, ENC_ASCII);
                } else if (g_ascii_strcasecmp(name, "nc") == 0) {
                    authorization_info->nonce_count = tvb_get_string_enc(wmem_packet_scope(), tvb, real_value_offset, real_value_length, ENC_ASCII);
                } else if (g_ascii_strcasecmp(name, "username") == 0) {
                    authorization_info->username = tvb_get_string_enc(wmem_packet_scope(), tvb, real_value_offset, real_value_length, ENC_ASCII);
                } else if (g_ascii_strcasecmp(name, "realm") == 0) {
                    authorization_info->realm = tvb_get_string_enc(wmem_packet_scope(), tvb, real_value_offset, real_value_length, ENC_ASCII);
                } else if (g_ascii_strcasecmp(name, "algorithm") == 0) {
                    authorization_info->algorithm = tvb_get_string_enc(wmem_packet_scope(), tvb, real_value_offset, real_value_length, ENC_ASCII);
                } else if (g_ascii_strcasecmp(name, "nonce") == 0) {
                    authorization_info->nonce = tvb_get_string_enc(wmem_packet_scope(), tvb, real_value_offset, real_value_length, ENC_ASCII);
                } else if (g_ascii_strcasecmp(name, "qop") == 0) {
                    authorization_info->qop = tvb_get_string_enc(wmem_packet_scope(), tvb, real_value_offset, real_value_length, ENC_ASCII);
                } else if (g_ascii_strcasecmp(name, "cnonce") == 0) {
                    authorization_info->cnonce = tvb_get_string_enc(wmem_packet_scope(), tvb, real_value_offset, real_value_length, ENC_ASCII);
                } else if (g_ascii_strcasecmp(name, "uri") == 0) {
                    authorization_info->uri = tvb_get_string_enc(wmem_packet_scope(), tvb, real_value_offset, real_value_length, ENC_ASCII);
                }
            }
            break;
        }
    }

    /* If not matched, just add as text... */
    if (i == array_length(auth_parameters_hf_array))
    {
        proto_tree_add_format_text(tree, tvb, start_offset, current_offset-start_offset);
    }

    /* Find comma/end of line */
    queried_offset = tvb_find_guint8 (tvb, current_offset, line_end_offset - current_offset, ',');
    if (queried_offset == -1) {
        current_offset = line_end_offset;
    } else {
        current_offset = queried_offset;
    }
    return current_offset;
}

/* Dissect the details of a Reason header
 * Reason            =  "Reason" HCOLON reason-value *(COMMA reason-value)
 * reason-value      =  protocol *(SEMI reason-params)
 * protocol          =  "SIP" / "Q.850" / token
 * reason-params     =  protocol-cause / reason-text / reason-extension
 * protocol-cause    =  "cause" EQUAL cause
 * cause             =  1*DIGIT
 * reason-text       =  "text" EQUAL quoted-string
 * reason-extension  =  generic-param
 */
static void
dissect_sip_reason_header(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint start_offset, gint line_end_offset){

    gint  current_offset, semi_colon_offset, length, end_quote_offset;
    const guint8 *param_name = NULL;
    guint cause_value;
    sip_reason_code_info_t sip_reason_code_info;

        /* skip Spaces and Tabs */
    start_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

    if (start_offset >= line_end_offset)
    {
        /* Nothing to parse */
        return;
    }

    current_offset = start_offset;
    semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset-current_offset, ';');

    if(semi_colon_offset == -1)
        return;

    length = semi_colon_offset - current_offset;
    proto_tree_add_item_ret_string(tree, hf_sip_reason_protocols, tvb, start_offset, length, ENC_UTF_8|ENC_NA, wmem_packet_scope(), &param_name);
    current_offset = tvb_find_guint8(tvb, semi_colon_offset, line_end_offset - semi_colon_offset, '=') + 1;
    /* Do we have a text parameter too? */
    semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ';');

    if (semi_colon_offset == -1){
        length = line_end_offset - current_offset;
    } else {
        /* Text parmeter exist, set length accordingly */
        length = semi_colon_offset - current_offset;
    }

    /* Get cause value */
    cause_value = (guint)strtoul(tvb_get_string_enc(wmem_packet_scope(), tvb, current_offset, length, ENC_UTF_8 | ENC_NA), NULL, 10);

    if (g_ascii_strcasecmp(param_name, "Q.850") == 0){
        proto_tree_add_uint(tree, hf_sip_reason_cause_q850, tvb, current_offset, length, cause_value);
        sip_reason_code_info.protocol_type_num = SIP_PROTO_Q850;
    }
    else if (g_ascii_strcasecmp(param_name, "SIP") == 0) {
        proto_tree_add_uint(tree, hf_sip_reason_cause_sip, tvb, current_offset, length, cause_value);
        sip_reason_code_info.protocol_type_num = SIP_PROTO_SIP;
    }
    else {
        proto_tree_add_uint(tree, hf_sip_reason_cause_other, tvb, current_offset, length, cause_value);
        sip_reason_code_info.protocol_type_num = SIP_PROTO_OTHER;
    }

    if (semi_colon_offset == -1)
        /* Nothing to parse */
        return;

    /* reason-text       =  "text" EQUAL quoted-string */
    current_offset = tvb_find_guint8(tvb, semi_colon_offset, line_end_offset - semi_colon_offset, '"') + 1;
    if (current_offset == -1)
        /* Nothing to parse */
        return;
    end_quote_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, '"');
    if (end_quote_offset == -1)
        /* Nothing to parse */
        return;
    length = end_quote_offset - current_offset;
    proto_tree_add_item(tree, hf_sip_reason_text, tvb, current_offset, length, ENC_UTF_8 | ENC_NA);

    if (sip_reason_code_handle) {
        tvbuff_t *next_tvb;

        sip_reason_code_info.cause_value = cause_value;

        next_tvb = tvb_new_subset_length(tvb, current_offset, length);
        call_dissector_with_data(sip_reason_code_handle, next_tvb, pinfo, tree, &sip_reason_code_info);
    }
}

/* Dissect the details of a security client header
 * sec-mechanism    = mechanism-name *(SEMI mech-parameters)
 *     mech-parameters  = ( preference / digest-algorithm /
 *                          digest-qop / digest-verify / extension )
 *    preference       = "q" EQUAL qvalue
 *    qvalue           = ( "0" [ "." 0*3DIGIT ] )
 *                        / ( "1" [ "." 0*3("0") ] )
 *    digest-algorithm = "d-alg" EQUAL token
 *    digest-qop       = "d-qop" EQUAL token
 *    digest-verify    = "d-ver" EQUAL LDQUOT 32LHEX RDQUOT
 *    extension        = generic-param
 *
 *
 */
static void
dissect_sip_sec_mechanism(tvbuff_t *tvb, packet_info* pinfo, proto_tree *tree, gint start_offset, gint line_end_offset){

    gint  current_offset, semi_colon_offset, length, par_name_end_offset, equals_offset;

    /* skip Spaces and Tabs */
    start_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

    if (start_offset >= line_end_offset)
    {
        /* Nothing to parse */
        return;
    }

    current_offset = start_offset;
    semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset-current_offset, ';');
    if(semi_colon_offset == -1){
        semi_colon_offset = line_end_offset;
    }

    length = semi_colon_offset-current_offset;
    proto_tree_add_item(tree, hf_sip_sec_mechanism, tvb,
                                start_offset, length,
                                ENC_UTF_8);

    current_offset = current_offset + length + 1;


    while(current_offset < line_end_offset){
        gchar *param_name = NULL, *value = NULL;
        guint8 hf_index = 0;
        /* skip Spaces and Tabs */
        current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

        semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset-current_offset, ';');

        if(semi_colon_offset == -1){
            semi_colon_offset = line_end_offset;
        }

        length = semi_colon_offset - current_offset;

        /* Parse parameter and value */
        equals_offset = tvb_find_guint8(tvb, current_offset + 1, length, '=');
        if(equals_offset != -1){
            /* Has value part */
            par_name_end_offset = equals_offset;
            /* Extract the parameter name */
            param_name = tvb_get_string_enc(wmem_packet_scope(), tvb, current_offset, par_name_end_offset-current_offset, ENC_UTF_8|ENC_NA);
            /* Extract the value */
            value = tvb_get_string_enc(wmem_packet_scope(), tvb, equals_offset+1, semi_colon_offset-equals_offset+1, ENC_UTF_8|ENC_NA);
        } else {
            return;
        }


        while (sec_mechanism_parameters_hf_array[hf_index].param_name) {
            /* Protection algorithm to be used */
            if (g_ascii_strcasecmp(param_name, sec_mechanism_parameters_hf_array[hf_index].param_name) == 0) {
                switch (sec_mechanism_parameters_hf_array[hf_index].para_type) {
                    case MECH_PARA_STRING:
                        proto_tree_add_item(tree, *sec_mechanism_parameters_hf_array[hf_index].hf_item, tvb,
                                            equals_offset+1, semi_colon_offset-equals_offset-1,
                                            ENC_UTF_8);
                        break;
                    case MECH_PARA_UINT:
                        if (!value) {
                            proto_tree_add_expert(tree, pinfo, &ei_sip_sipsec_malformed,
                                                  tvb, current_offset, -1);
                        } else {
                            guint32 semi_para;
                            semi_para = (guint32)strtoul(value, NULL, 10);
                            proto_tree_add_uint(tree, *sec_mechanism_parameters_hf_array[hf_index].hf_item, tvb,
                                                equals_offset+1, semi_colon_offset-equals_offset-1, semi_para);
                        }
                        break;
                    default:
                        break;
                }
                break;
            }
            hf_index++;
        }

        if (!sec_mechanism_parameters_hf_array[hf_index].param_name) {
            proto_tree_add_format_text(tree, tvb, current_offset, length);
        }

        current_offset = semi_colon_offset+1;
    }

}

/* Dissect the details of a Route (and Record-Route) header */
static void dissect_sip_route_header(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, hf_sip_uri_t *sip_route_uri_p, gint start_offset, gint line_end_offset)
{
    gint current_offset;
    uri_offset_info uri_offsets;

    current_offset = start_offset;

    /* skip Spaces and Tabs */
    current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

    if (current_offset >= line_end_offset) {
        return;
    }

    while (current_offset < line_end_offset) {
        current_offset = tvb_find_guint8(tvb, current_offset, (line_end_offset - 1) - current_offset, ',');

        if (current_offset != -1) { /* found any ',' ? */
            sip_uri_offset_init(&uri_offsets);
            current_offset = dissect_sip_name_addr_or_addr_spec(tvb, pinfo, start_offset, current_offset, &uri_offsets);
            if(current_offset == -1)
                return;
            display_sip_uri(tvb, tree, pinfo, &uri_offsets, sip_route_uri_p);

            current_offset++;
            start_offset = current_offset + 1;

        } else {
            /* current_offset = (line_end_offset - 1); */

            sip_uri_offset_init(&uri_offsets);
            current_offset = dissect_sip_name_addr_or_addr_spec(tvb, pinfo, start_offset, line_end_offset, &uri_offsets);
            if(current_offset == -1)
                return;
            display_sip_uri(tvb, tree, pinfo, &uri_offsets, sip_route_uri_p);

            return;
        }

        current_offset++;
    }

    return;
}

/* Dissect the details of a Via header
 *
 * Via               =  ( "Via" / "v" ) HCOLON via-parm *(COMMA via-parm)
 * via-parm          =  sent-protocol LWS sent-by *( SEMI via-params )
 * via-params        =  via-ttl / via-maddr
 *                      / via-received / via-branch
 *                      / via-extension
 * via-ttl           =  "ttl" EQUAL ttl
 * via-maddr         =  "maddr" EQUAL host
 * via-received      =  "received" EQUAL (IPv4address / IPv6address)
 * via-branch        =  "branch" EQUAL token
 * via-extension     =  generic-param
 * sent-protocol     =  protocol-name SLASH protocol-version
 *                      SLASH transport
 * protocol-name     =  "SIP" / token
 * protocol-version  =  token
 * transport         =  "UDP" / "TCP" / "TLS" / "SCTP"
 *                      / other-transport
 * sent-by           =  host [ COLON port ]
 * ttl               =  1*3DIGIT ; 0 to 255
 *
 */
static void dissect_sip_via_header(tvbuff_t *tvb, proto_tree *tree, gint start_offset, gint line_end_offset, packet_info *pinfo)
{
    gint  current_offset;
    gint  address_start_offset;
    gint  semicolon_offset;
    gboolean colon_seen;
    gboolean ipv6_reference;
    gboolean ipv6_address;
    guchar c;
    gchar *param_name = NULL;

    current_offset = start_offset;

    while (1)
    {
        /* Reset flags and counters */
        semicolon_offset = 0;
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
         *  There may be spaces between the slashes
         *  sent-protocol     =  protocol-name SLASH protocol-version
         *                       SLASH transport
         */

        current_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, '/');
        if (current_offset != -1)
        {
            current_offset++;
            current_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, '/');
        }

        if (current_offset != -1)
        {
            current_offset++;
            /* skip Spaces and Tabs */
            current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);
        } else
            current_offset = line_end_offset;


        /* We should now be at the start of the first transport name (or at the end of the line) */

        /*
         * transport         =  "UDP" / "TCP" / "TLS" / "SCTP"
         *                      / other-transport
         */
        while (current_offset < line_end_offset)
        {
            int transport_start_offset = current_offset;

            current_offset = tvb_ws_mempbrk_pattern_guint8(tvb, current_offset, line_end_offset - current_offset, &pbrk_tab_sp_fslash, &c);
            if (current_offset != -1){
                proto_tree_add_item(tree, hf_sip_via_transport, tvb, transport_start_offset,
                                    current_offset - transport_start_offset, ENC_UTF_8);
                /* Check if we have more transport parameters */
                if(c=='/'){
                    current_offset++;
                    continue;
                }
                current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);
                c = tvb_get_guint8(tvb, current_offset);
                if(c=='/'){
                    current_offset++;
                    continue;
                }
                break;
            }else{
                current_offset = line_end_offset;
            }

        }

        /* skip Spaces and Tabs */
        current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

        /* Now read the address part */
        address_start_offset = current_offset;
        while (current_offset < line_end_offset)
        {
            current_offset = tvb_ws_mempbrk_pattern_guint8(tvb, current_offset, line_end_offset - current_offset, &pbrk_addr_end, &c);
            if (current_offset == -1)
            {
                current_offset = line_end_offset;
                break;
            }

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
                                current_offset - address_start_offset - 2, ENC_UTF_8);
        } else {
            proto_tree_add_item(tree, hf_sip_via_sent_by_address, tvb, address_start_offset,
                                current_offset - address_start_offset, ENC_UTF_8);
        }

        /* Transport port number may follow ([space] : [space])*/
        current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);
        c = tvb_get_guint8(tvb, current_offset);

        if (c == ':')
        {
            /* Port number will follow any space after : */
            gint port_offset;
            current_offset++;

            /* Skip optional space after colon */
            current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

            port_offset = current_offset;

            /* Find digits of port number */
            while (current_offset < line_end_offset)
            {
                c = tvb_get_guint8(tvb, current_offset);

                if (!g_ascii_isdigit(c))
                {
                    if (current_offset > port_offset)
                    {
                        /* Add address port number to tree */
                        guint16 port;
                        gboolean port_valid;
                        proto_item* pi;
                        port_valid = ws_strtou16(tvb_get_string_enc(wmem_packet_scope(), tvb, port_offset,
                            current_offset - port_offset, ENC_UTF_8|ENC_NA), NULL, &port);
                        pi = proto_tree_add_uint(tree, hf_sip_via_sent_by_port, tvb, port_offset,
                                            current_offset - port_offset, port);
                        if (!port_valid)
                            expert_add_info(pinfo, pi, &ei_sip_via_sent_by_port);
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
                if (!g_ascii_isalpha(c) && (c != '-'))
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
            current_offset = tvb_ws_mempbrk_pattern_guint8(tvb, current_offset, line_end_offset - current_offset, &pbrk_via_param_end, NULL);
            if (current_offset == -1)
                current_offset = line_end_offset;

            /* Note parameter name */
            param_name = tvb_get_string_enc(wmem_packet_scope(), tvb, semicolon_offset+1,
                                                  parameter_name_end - semicolon_offset - 1, ENC_UTF_8|ENC_NA);

            /* Try to add parameter as a filterable item */
            for (via_parameter = &via_parameters_hf_array[i];
                 i < array_length(via_parameters_hf_array);
                 i++, via_parameter++)
            {
                if (g_ascii_strcasecmp(param_name, via_parameter->param_name) == 0)
                {
                    if (equals_found)
                    {
                        proto_item* via_parameter_item;
                        via_parameter_item = proto_tree_add_item(tree, *(via_parameter->hf_item), tvb,
                            parameter_name_end + 1, current_offset - parameter_name_end - 1,
                            ENC_UTF_8 | ENC_NA);

                        if (sip_via_branch_handle && g_ascii_strcasecmp(param_name, "branch") == 0)
                        {
                            tvbuff_t *next_tvb;
                            next_tvb = tvb_new_subset_length_caplen(tvb, parameter_name_end + 1, current_offset - parameter_name_end - 1, current_offset - parameter_name_end - 1);

                            call_dissector(sip_via_branch_handle, next_tvb, pinfo, tree);
                        }
                        else if (g_ascii_strcasecmp(param_name, "oc") == 0) {
                            proto_item *ti;
                            char *value = tvb_get_string_enc(wmem_packet_scope(), tvb, parameter_name_end + 1,
                                current_offset - parameter_name_end - 1, ENC_UTF_8 | ENC_NA);
                            ti = proto_tree_add_uint(tree, hf_sip_via_oc_val, tvb,
                                parameter_name_end + 1, current_offset - parameter_name_end - 1,
                                (guint32)strtoul(value, NULL, 10));
                            proto_item_set_generated(ti);
                        }
                        else if (g_ascii_strcasecmp(param_name, "oc-seq") == 0) {
                            proto_item *ti;
                            nstime_t ts;
                            int dec_p_off = tvb_find_guint8(tvb, parameter_name_end + 1, - 1, '.');
                            char *value;

                            if(dec_p_off > 0){
                                value = tvb_get_string_enc(wmem_packet_scope(), tvb,
                                    parameter_name_end + 1, dec_p_off - parameter_name_end, ENC_UTF_8 | ENC_NA);
                                ts.secs = (time_t)strtoul(value, NULL, 10);
                                value = tvb_get_string_enc(wmem_packet_scope(), tvb,
                                    dec_p_off + 1, current_offset - parameter_name_end - 1, ENC_UTF_8 | ENC_NA);
                                ts.nsecs = (guint32)strtoul(value, NULL, 10) * 1000;
                                ti = proto_tree_add_time(tree, hf_sip_oc_seq_timestamp, tvb,
                                    parameter_name_end + 1, current_offset - parameter_name_end - 1, &ts);
                                proto_item_set_generated(ti);
                            }
                        } else if (g_ascii_strcasecmp(param_name, "be-route") == 0) {
                            tvbuff_t* next_tvb;
                            next_tvb = tvb_new_subset_length_caplen(tvb, parameter_name_end + 1, current_offset - parameter_name_end - 1, current_offset - parameter_name_end - 1);
                            call_dissector(sip_via_be_route_handle, next_tvb, pinfo, proto_item_add_subtree(via_parameter_item, ett_sip_via_be_route));
                        }
                    }
                    else
                    {
                        proto_tree_add_item(tree, *(via_parameter->hf_item), tvb,
                                            semicolon_offset+1, current_offset-semicolon_offset-1,
                                            ENC_UTF_8|ENC_NA);
                    }
                    break;
                }
            }

            /* If not matched, just add as text... */
            if (i == array_length(via_parameters_hf_array))
            {
                proto_tree_add_format_text(tree, tvb, semicolon_offset+1, current_offset-semicolon_offset-1);
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

/* Dissect the details of a Session-ID header
 *
 * Session-ID           =  "Session-ID" HCOLON sess-id
 *                         *( SEMI generic-param )
 * sess-id              =  32(DIGIT / %x61-66)  ; 32 chars of [0-9a-f]
 */
static void dissect_sip_session_id_header(tvbuff_t *tvb, proto_tree *tree, gint start_offset, gint line_end_offset, packet_info *pinfo)
{
    gint current_offset, semi_colon_offset, equals_offset, length, logme_end_offset;
    GByteArray *bytes;
    proto_item *pi;

    current_offset = start_offset;
    semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset-current_offset, ';');
    if(semi_colon_offset == -1){
        semi_colon_offset = line_end_offset;
    }

    length = semi_colon_offset-current_offset;
    bytes = g_byte_array_sized_new(16);
    if (length != 0) {
        pi = proto_tree_add_bytes_item(tree, hf_sip_session_id_sess_id, tvb,
                                  start_offset, length, ENC_UTF_8|ENC_STR_HEX|ENC_SEP_NONE,
                                  bytes, NULL, NULL);
    } else {
        pi = proto_tree_add_item(tree, hf_sip_session_id_sess_id, tvb,
            start_offset, length, ENC_UTF_8 | ENC_STR_HEX | ENC_SEP_NONE);
        expert_add_info(pinfo, pi, &ei_sip_session_id_sess_id);
    }

    current_offset = current_offset + length + 1;

    /* skip Spaces and Tabs */
    current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

    if (current_offset < line_end_offset) {
        /* Parse parameter and value */
        equals_offset = tvb_find_guint8(tvb, current_offset + 1, length, '=');
        if (equals_offset != -1) {
            /* Extract the parameter name */
            GByteArray *uuid = g_byte_array_sized_new(16);
            guint8 *param_name = tvb_get_string_enc(wmem_packet_scope(), tvb, current_offset,
                                                    tvb_skip_wsp_return(tvb, equals_offset - 1) - current_offset,
                                                    ENC_UTF_8|ENC_NA);

            if ((bytes->len == 16) && (g_ascii_strcasecmp(param_name, "remote") == 0) &&
                tvb_get_string_bytes(tvb, equals_offset + 1, line_end_offset - equals_offset - 1,
                                     ENC_UTF_8|ENC_STR_HEX|ENC_SEP_NONE, uuid, NULL) &&
                (uuid->len == 16)) {
                /* Decode header as draft-ietf-insipid-session-id
                 *
                 * session-id          = "Session-ID" HCOLON session-id-value
                 * session-id-value    = local-uuid *(SEMI sess-id-param)
                 * local-uuid          = sess-uuid / null
                 * remote-uuid         = sess-uuid / null
                 * sess-uuid           = 32(DIGIT / %x61-66)  ;32 chars of [0-9a-f]
                 * sess-id-param       = remote-param / generic-param
                 * remote-param        = "remote" EQUAL remote-uuid
                 * null                = 32("0")
                 */
                e_guid_t guid;

                proto_item_set_hidden(pi);
                guid.data1 = (bytes->data[0] << 24) | (bytes->data[1] << 16) |
                             (bytes->data[2] <<  8) |  bytes->data[3];
                guid.data2 = (bytes->data[4] <<  8) |  bytes->data[5];
                guid.data3 = (bytes->data[6] <<  8) |  bytes->data[7];
                memcpy(guid.data4, &bytes->data[8], 8);
                proto_tree_add_guid(tree, hf_sip_session_id_local_uuid, tvb,
                                    start_offset, semi_colon_offset - start_offset, &guid);
                guid.data1 = (uuid->data[0] << 24) | (uuid->data[1] << 16) |
                             (uuid->data[2] <<  8) |  uuid->data[3];
                guid.data2 = (uuid->data[4] <<  8) |  uuid->data[5];
                guid.data3 = (uuid->data[6] <<  8) |  uuid->data[7];
                memcpy(guid.data4, &uuid->data[8], 8);
                proto_tree_add_guid(tree, hf_sip_session_id_remote_uuid, tvb,
                                    equals_offset + 1, line_end_offset - equals_offset - 1, &guid);
     	       /* Decode logme parameter as per https://tools.ietf.org/html/rfc8497
                *
                * sess-id-param       =/ logme-param
                * logme-param         = "logme"
                */
                semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ';');
                while(semi_colon_offset != -1){
                    current_offset = semi_colon_offset + 1;
                    if(current_offset != line_end_offset){
                        logme_end_offset = current_offset + 5;
                        current_offset = tvb_skip_wsp_return(tvb,semi_colon_offset);
                        /* Extract logme parameter name */
                        gchar *name = tvb_get_string_enc(wmem_packet_scope(), tvb, current_offset,logme_end_offset - current_offset, ENC_UTF_8|ENC_NA);
                        if(g_ascii_strcasecmp(name, "logme") == 0){
                             proto_tree_add_boolean(tree, hf_sip_session_id_logme, tvb, current_offset, logme_end_offset - current_offset, 1);
                        } else if(current_offset != line_end_offset){
                             proto_tree_add_item(tree, hf_sip_session_id_param, tvb, current_offset,line_end_offset - current_offset, ENC_UTF_8);
                        }
                    }
                    semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ';');
                }
     	    } else {
                /* Display generic parameter */
                proto_tree_add_item(tree, hf_sip_session_id_param, tvb, current_offset,
                                    line_end_offset - current_offset, ENC_UTF_8);
            }
            g_byte_array_free(uuid, TRUE);
        } else {
            /* Display generic parameter */
            proto_tree_add_item(tree, hf_sip_session_id_param, tvb, current_offset,
                                line_end_offset - current_offset, ENC_UTF_8);
        }
    }

    g_byte_array_free(bytes, TRUE);
}

/* Dissect the headers for P-Access-Network-Info Headers
 *
 *  Spec found in 3GPP 24.229 7.2A.4
 *  P-Access-Network-Info  = "P-Access-Network-Info" HCOLON
 *  access-net-spec *(COMMA access-net-spec)
 *  access-net-spec        = (access-type / access-class) *(SEMI access-info)
 *  access-type            = "IEEE-802.11" / "IEEE-802.11a" / "IEEE-802.11b" / "IEEE-802.11g" / "IEEE-802.11n" / "3GPP-GERAN" /
 *                           "3GPP-UTRAN-FDD" / "3GPP-UTRAN-TDD" / "3GPP-E-UTRAN-FDD" / "3GPP-E-UTRAN-TDD" / "ADSL" / "ADSL2" /
 *                           "ADSL2+" / "RADSL" / "SDSL" / "HDSL" / "HDSL2" / "G.SHDSL" / "VDSL" / "IDSL" / "3GPP2-1X" /
 *                           "3GPP2-1X-Femto" / "3GPP2-1X-HRPD" / "3GPP2-UMB" / "DOCSIS" / "IEEE-802.3" / "IEEE-802.3a" /
 *                           "IEEE-802.3e" / "IEEE-802.3i" / "IEEE-802.3j" / "IEEE-802.3u" / "IEEE-802.3ab"/ "IEEE-802.3ae" /
 *                           "IEEE-802.3ak" / "IEEE-802.3aq" / "IEEE-802.3an" / "IEEE-802.3y" / "IEEE-802.3z" / "GPON" /
                             "XGPON1" / "GSTN"/ token
 *  access-class           = "3GPP-GERAN" / "3GPP-UTRAN" / "3GPP-E-UTRAN" / "3GPP-WLAN" / "3GPP-GAN" / "3GPP-HSPA" / token
 *  np                     = "network-provided"
 *  access-info            = cgi-3gpp / utran-cell-id-3gpp / dsl-location / i-wlan-node-id / ci-3gpp2 / ci-3gpp2-femto /
                             eth-location / fiber-location / np / gstn-location / extension-access-info
 *  extension-access-info  = gen-value
 *  cgi-3gpp               = "cgi-3gpp" EQUAL (token / quoted-string)
 *  utran-cell-id-3gpp     = "utran-cell-id-3gpp" EQUAL (token / quoted-string)
 *  i-wlan-node-id         = "i-wlan-node-id" EQUAL (token / quoted-string)
 *  dsl-location           = "dsl-location" EQUAL (token / quoted-string)
 *  eth-location           = "eth-location" EQUAL (token / quoted-string)
 *  fiber-location         = "fiber-location" EQUAL (token / quoted-string)
 *  ci-3gpp2               = "ci-3gpp2" EQUAL (token / quoted-string)
 *  ci-3gpp2-femto         = "ci-3gpp2-femto" EQUAL (token / quoted-string)
 *  gstn-location          = "gstn-location" EQUAL (token / quoted-string)
 *
 */
void dissect_sip_p_access_network_info_header(tvbuff_t *tvb, proto_tree *tree, gint start_offset, gint line_end_offset)
{

    gint  current_offset, semi_colon_offset, length, par_name_end_offset, equals_offset;

    /* skip Spaces and Tabs */
    start_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

    if (start_offset >= line_end_offset)
    {
        /* Nothing to parse */
        return;
    }

    /* Get the Access Type / Access Class*/
    current_offset = start_offset;
    semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ';');

    if (semi_colon_offset == -1)
        return;

    length = semi_colon_offset - current_offset;
    proto_tree_add_item(tree, hf_sip_p_acc_net_i_acc_type, tvb, start_offset, length, ENC_UTF_8 | ENC_NA);

    current_offset = current_offset + length + 1;


    while (current_offset < line_end_offset){
        gchar *param_name = NULL;

        /* skip Spaces and Tabs */
        current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

        semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ';');

        if (semi_colon_offset == -1){
            semi_colon_offset = line_end_offset;
        }

        length = semi_colon_offset - current_offset;

        /* Parse parameter and value */
        equals_offset = tvb_find_guint8(tvb, current_offset + 1, length, '=');
        if (equals_offset != -1){
            /* Has value part */
            par_name_end_offset = equals_offset;
            /* Extract the parameter name */
            param_name = tvb_get_string_enc(wmem_packet_scope(), tvb, current_offset, par_name_end_offset - current_offset, ENC_UTF_8 | ENC_NA);
            /* Access-Info fields  */
            if ((param_name != NULL)&&(g_ascii_strcasecmp(param_name, "utran-cell-id-3gpp") == 0)) {
                proto_tree_add_item(tree, hf_sip_p_acc_net_i_ucid_3gpp, tvb,
                    equals_offset + 1, semi_colon_offset - equals_offset - 1, ENC_UTF_8 | ENC_NA);
            }
            else {
                proto_tree_add_format_text(tree, tvb, current_offset, length);
            }
        }
        else {
            proto_tree_add_format_text(tree, tvb, current_offset, length);
        }

        current_offset = semi_colon_offset + 1;
    }
}

/*
The syntax for the P-Charging-Vector header field is described as
follows:

    P-Charging-Vector  = "P-Charging-Vector" HCOLON icid-value
    *(SEMI charge-params)
    charge-params      = icid-gen-addr / orig-ioi / term-ioi /
    transit-ioi / related-icid /
    related-icid-gen-addr / generic-param
    icid-value                = "icid-value" EQUAL gen-value
    icid-gen-addr             = "icid-generated-at" EQUAL host
    orig-ioi                  = "orig-ioi" EQUAL gen-value
    term-ioi                  = "term-ioi" EQUAL gen-value
    transit-ioi               = "transit-ioi" EQUAL transit-ioi-list
    transit-ioi-list          = DQUOTE transit-ioi-param
    *(COMMA transit-ioi-param) DQUOTE
    transit-ioi-param         = transit-ioi-indexed-value /
    transit-ioi-void-value
    transit-ioi-indexed-value = transit-ioi-name "."
    transit-ioi-index
    transit-ioi-name          = ALPHA *(ALPHA / DIGIT)
    transit-ioi-index         = 1*DIGIT
    transit-ioi-void-value    = "void"
    related-icid              = "related-icid" EQUAL gen-value
    related-icid-gen-addr     = "related-icid-generated-at" EQUAL host
*/
static void
dissect_sip_p_charging_vector_header(tvbuff_t *tvb, proto_tree *tree, gint start_offset, gint line_end_offset)
{

    gint  current_offset, semi_colon_offset, length, equals_offset;

    /* skip Spaces and Tabs */
    start_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

    if (start_offset >= line_end_offset)
    {
        /* Nothing to parse */
        return;
    }

    /* icid-value                = "icid-value" EQUAL gen-value */
    current_offset = start_offset;
    semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ';');

    if (semi_colon_offset == -1) {
        /* No parameters, is that allowed?*/
        semi_colon_offset = line_end_offset;
    }

    length = semi_colon_offset - current_offset;

    /* Parse parameter and value */
    equals_offset = tvb_find_guint8(tvb, current_offset + 1, length, '=');
    if (equals_offset == -1) {
        /* Does not conform to ABNF */
        return;
    }

    /* Get the icid-value */
    proto_tree_add_item(tree, hf_sip_icid_value, tvb,
        equals_offset + 1, semi_colon_offset - equals_offset - 1, ENC_UTF_8 | ENC_NA);

    current_offset = semi_colon_offset + 1;

    /* Add the rest of the parameters to the tree */
    while (current_offset < line_end_offset) {
        gchar *param_name = NULL;
        gint par_name_end_offset;
        /* skip Spaces and Tabs */
        current_offset = tvb_skip_wsp(tvb, current_offset, line_end_offset - current_offset);

        semi_colon_offset = tvb_find_guint8(tvb, current_offset, line_end_offset - current_offset, ';');

        if (semi_colon_offset == -1) {
            semi_colon_offset = line_end_offset;
        }

        length = semi_colon_offset - current_offset;

        /* Parse parameter and value */
        equals_offset = tvb_find_guint8(tvb, current_offset + 1, length, '=');
        if (equals_offset != -1) {
            /* Has value part */
            par_name_end_offset = equals_offset;
            /* Extract the parameter name */
            param_name = tvb_get_string_enc(wmem_packet_scope(), tvb, current_offset, par_name_end_offset - current_offset, ENC_UTF_8 | ENC_NA);
            /* charge-params */
            if ((param_name != NULL) && (g_ascii_strcasecmp(param_name, "icid-gen-addr") == 0)) {
                proto_tree_add_item(tree, hf_sip_icid_gen_addr, tvb,
                    equals_offset + 1, semi_colon_offset - equals_offset - 1, ENC_UTF_8 | ENC_NA);
            }
            else {
                proto_tree_add_format_text(tree, tvb, current_offset, length);
            }
        }
        else {
            proto_tree_add_format_text(tree, tvb, current_offset, length);
        }

        current_offset = semi_colon_offset + 1;
    }


}

/*
https://tools.ietf.org/html/rfc6809
The ABNF for the Feature-Caps header fields is:

Feature-Caps = "Feature-Caps" HCOLON fc-value
*(COMMA fc-value)
fc-value     = "*" *(SEMI feature-cap)

The ABNF for the feature-capability indicator is:

feature-cap       =  "+" fcap-name [EQUAL LDQUOT (fcap-value-list
/ fcap-string-value ) RDQUOT]
fcap-name         =  ftag-name
fcap-value-list   =  tag-value-list
fcap-string-value =  string-value
;; ftag-name, tag-value-list, string-value defined in RFC 3840

NOTE: In comparison with media feature tags, the "+" sign in front of
the feature-capability indicator name is mandatory.

*/
static void
dissect_sip_p_feature_caps(tvbuff_t *tvb, proto_tree *tree, gint start_offset, gint line_end_offset)
{
    gint current_offset, next_offset, length;
    guint16 semi_plus = 0x3b2b;

    /* skip Spaces and Tabs */
    next_offset = tvb_skip_wsp(tvb, start_offset, line_end_offset - start_offset);

    if (next_offset >= line_end_offset) {
        /* Nothing to parse */
        return;
    }

    while (next_offset < line_end_offset) {
        /* Find the end of feature cap or start of feature cap parameter, ";+" should indicate the start of a new feature-cap */
        current_offset = next_offset;
        next_offset = tvb_find_guint16(tvb, current_offset, line_end_offset - current_offset, semi_plus);
        if (next_offset == -1) {
            length = line_end_offset - current_offset;
            next_offset = line_end_offset;
        }
        else {
            length = next_offset - current_offset;
            next_offset += 2;
        }
        proto_tree_add_item(tree, hf_sip_feature_cap, tvb, current_offset, length, ENC_UTF_8 | ENC_NA);
    }
}

/* Code to actually dissect the packets */
static int
dissect_sip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 octet;
    int len;
    int remaining_length;

    octet = tvb_get_guint8(tvb,0);
    if ((octet  & 0xf8) == 0xf8){
        call_dissector(sigcomp_handle, tvb, pinfo, tree);
        return tvb_reported_length(tvb);
    }

    remaining_length = tvb_reported_length(tvb);
    len = dissect_sip_common(tvb, 0, remaining_length, pinfo, tree, FALSE, FALSE);
    if (len < 0)
        return 0;   /* not SIP */
    else
        return len;
}

static int
dissect_sip_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint8 octet;
    int offset = 0, linelen;
    int len;
    int remaining_length;

    octet = tvb_get_guint8(tvb,0);
    if ((octet  & 0xf8) == 0xf8){
        call_dissector(sigcomp_handle, tvb, pinfo, tree);
        return tvb_reported_length(tvb);
    }

    remaining_length = tvb_reported_length(tvb);
    /* Check if we have enough data or if we need another segment, as a safty measure set a length limit*/
    if (remaining_length < 1500){
        linelen = tvb_find_line_end(tvb, offset, remaining_length, NULL, TRUE);
        if (linelen == -1){
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return -1;
        }
    }
    len = dissect_sip_common(tvb, offset, remaining_length, pinfo, tree, TRUE, TRUE);
    if (len <= 0)
        return len;
    offset += len;
    remaining_length = remaining_length - len;

    /*
     * This is a bit of a cludge as the TCP dissector does not call the dissectors again if not all
     * the data in the segment was dissected and we do not know if we need another segment or not.
     * so DESEGMENT_ONE_MORE_SEGMENT can't be used in all cases.
     *
     */
    while (remaining_length > 0) {
        /* Check if we have enough data or if we need another segment, as a safty measure set a length limit*/
        if (remaining_length < 1500){
            linelen = tvb_find_line_end(tvb, offset, remaining_length, NULL, TRUE);
            if (linelen == -1){
                pinfo->desegment_offset = offset;
                pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
                return -1;
            }
        }
        len = dissect_sip_common(tvb, offset, remaining_length, pinfo, tree, TRUE, TRUE);
        if (len <= 0)
            return len;
        offset += len;
        remaining_length = remaining_length - len;
    }
    return offset;
}

static gboolean
dissect_sip_tcp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    int len;
    gboolean first = TRUE;
    int remaining_length;

    remaining_length = tvb_captured_length(tvb);
    while (remaining_length > 0) {
        len = dissect_sip_common(tvb, offset, remaining_length, pinfo, tree, !first, TRUE);
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
            break;  /* need more data */
        offset += len;
        remaining_length = remaining_length - len;
        first = FALSE;
    }
    return TRUE;
}

static gboolean
dissect_sip_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int remaining_length = tvb_captured_length(tvb);

    return dissect_sip_common(tvb, 0, remaining_length, pinfo, tree, FALSE, FALSE) > 0;
}

static int
dissect_sip_common(tvbuff_t *tvb, int offset, int remaining_length, packet_info *pinfo, proto_tree *tree,
    gboolean dissect_other_as_continuation, gboolean use_reassembly)
{
    int orig_offset;
    gint next_offset, linelen;
    int content_length, datalen, reported_datalen;
    line_type_t line_type;
    tvbuff_t *next_tvb;
    gboolean is_known_request;
    int found_match = 0;
    const char *descr;
    guint token_1_len = 0;
    guint current_method_idx = SIP_METHOD_INVALID;
    proto_item *ts, *ti_a = NULL, *th = NULL;
    proto_tree *sip_tree, *reqresp_tree      = NULL, *hdr_tree  = NULL,
        *message_body_tree = NULL, *cseq_tree = NULL,
        *via_tree         = NULL, *reason_tree       = NULL, *rack_tree = NULL,
        *route_tree       = NULL, *security_client_tree = NULL, *session_id_tree = NULL,
        *p_access_net_info_tree = NULL;
    guchar contacts = 0, contact_is_star = 0, expires_is_0 = 0, contacts_expires_0 = 0, contacts_expires_unknown = 0;
    guint32 cseq_number = 0;
    guchar  cseq_number_set = 0;
    char    cseq_method[MAX_CSEQ_METHOD_SIZE] = "";
    char    call_id[MAX_CALL_ID_SIZE] = "";
    gchar  *media_type_str_lower_case = NULL;
    http_message_info_t message_info = { SIP_DATA, NULL, NULL, NULL };
    char   *content_encoding_parameter_str = NULL;
    guint   resend_for_packet = 0;
    guint   request_for_response = 0;
    guint32 response_time = 0;
    int     strlen_to_copy;
    heur_dtbl_entry_t *hdtbl_entry;

    /*
     * If this should be a request of response, do this quick check to see if
     * it begins with a string...
     * Otherwise, SIP heuristics are expensive...
     *
     */

    if (!dissect_other_as_continuation &&
        ((remaining_length < 1) || !g_ascii_isprint(tvb_get_guint8(tvb, offset))))
    {
        return -2;
    }

    /*
     * Note that "tvb_find_line_end()" will return a value that
     * is not longer than what's in the buffer, so the
     * "tvb_get_ptr()" calls below won't throw exceptions.
     *
     * Note that "tvb_strneql()" doesn't throw exceptions, so
     * "sip_parse_line()" won't throw an exception.
     */
    orig_offset = offset;
    linelen = tvb_find_line_end(tvb, offset, remaining_length, &next_offset, FALSE);
    if(linelen==0){
        return -2;
    }

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
         *
         * RFC 6594, Section 20.14. requires Content-Length for TCP.
         */
        if (!req_resp_hdrs_do_reassembly(tvb, offset, pinfo,
            sip_desegment_headers, sip_desegment_body, FALSE)) {
            /*
             * More data needed for desegmentation.
             */
            return -1;
        }
    }

    /* Initialise stat info for passing to tap
     * Note: this isn't _only_ for taps - internal code here uses it too
     * also store stat info in proto_data for subdissectors
     */
    stat_info = wmem_new0(pinfo->pool, sip_info_value_t);
    p_add_proto_data(pinfo->pool, pinfo, proto_sip, pinfo->curr_layer_num, stat_info);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIP");

    if (!pinfo->flags.in_error_pkt && have_tap_listener(exported_pdu_tap)) {
        wmem_list_frame_t *cur;
        guint proto_id;
        const gchar *proto_name;
        void *tmp;

        /* For SIP messages with other sip messages embeded in the body, don't export those individually.
         * E.g. if we are called from the mime_multipart dissector don't export the message.
         */
        cur = wmem_list_frame_prev(wmem_list_tail(pinfo->layers));
        tmp = wmem_list_frame_data(cur);
        proto_id = GPOINTER_TO_UINT(tmp);
        proto_name = proto_get_protocol_filter_name(proto_id);
        if (strcmp(proto_name, "mime_multipart") != 0) {
            export_sip_pdu(pinfo, tvb);
        }
    }

    DPRINT2(("------------------------------ dissect_sip_common ------------------------------"));

    switch (line_type) {

    case REQUEST_LINE:
        is_known_request = sip_is_known_request(tvb, offset, token_1_len, &current_method_idx);
        descr = is_known_request ? "Request" : "Unknown request";
        col_add_lstr(pinfo->cinfo, COL_INFO,
                     descr, ": ",
                     tvb_format_text(pinfo->pool, tvb, offset, linelen - SIP2_HDR_LEN - 1),
                     COL_ADD_LSTR_TERMINATOR);
        DPRINT(("got %s: %s", descr,
                tvb_format_text(pinfo->pool, tvb, offset, linelen - SIP2_HDR_LEN - 1)));
        break;

    case STATUS_LINE:
        descr = "Status";
        col_add_lstr(pinfo->cinfo, COL_INFO,
                     "Status: ",
                     tvb_format_text(pinfo->pool, tvb, offset + SIP2_HDR_LEN + 1, linelen - SIP2_HDR_LEN - 1),
                     COL_ADD_LSTR_TERMINATOR);
        stat_info->reason_phrase = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + SIP2_HDR_LEN + 5,
                                                      linelen - (SIP2_HDR_LEN + 5),ENC_UTF_8|ENC_NA);
        DPRINT(("got Response: %s",
                tvb_format_text(pinfo->pool, tvb, offset + SIP2_HDR_LEN + 1, linelen - SIP2_HDR_LEN - 1)));
        break;

    case OTHER_LINE:
    default: /* Squelch compiler complaints */
        descr = "Continuation";
        col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
        DPRINT(("got continuation"));
        break;
    }

    ts = proto_tree_add_item(tree, proto_sip, tvb, offset, -1, ENC_NA);
    sip_tree = proto_item_add_subtree(ts, ett_sip);

    switch (line_type) {

    case REQUEST_LINE:
        if (sip_tree) {
            ti_a = proto_tree_add_item(sip_tree, hf_Request_Line, tvb,
                        offset, linelen, ENC_UTF_8);

            reqresp_tree = proto_item_add_subtree(ti_a, ett_sip_reqresp);
        }
        dfilter_sip_request_line(tvb, reqresp_tree, pinfo, offset, token_1_len, linelen);
        break;

    case STATUS_LINE:
        if (sip_tree) {
            ti_a = proto_tree_add_item(sip_tree, hf_sip_Status_Line, tvb,
                        offset, linelen, ENC_UTF_8);
            reqresp_tree = proto_item_add_subtree(ti_a, ett_sip_reqresp);
        }
        dfilter_sip_status_line(tvb, reqresp_tree, pinfo, linelen, offset);
        break;

    case OTHER_LINE:
        if (sip_tree) {
            reqresp_tree = proto_tree_add_subtree_format(sip_tree, tvb, offset, next_offset,
                                     ett_sip_reqresp, NULL, "%s line: %s", descr,
                                     tvb_format_text(pinfo->pool, tvb, offset, linelen));
            /* XXX: Is adding to 'reqresp_tree as intended ? Changed from original 'sip_tree' */
            proto_tree_add_item(reqresp_tree, hf_sip_continuation, tvb, offset, -1, ENC_NA);
        }
        return remaining_length;
    }

    remaining_length = remaining_length - (next_offset - offset);
    offset = next_offset;

    th = proto_tree_add_item(sip_tree, hf_sip_msg_hdr, tvb, offset,
                                 remaining_length, ENC_UTF_8);
    proto_item_set_text(th, "Message Header");
    hdr_tree = proto_item_add_subtree(th, ett_sip_hdr);

    if (have_tap_listener(sip_follow_tap))
        tap_queue_packet(sip_follow_tap, pinfo, tvb);

    /*
     * Process the headers - if we're not building a protocol tree,
     * we just do this to find the blank line separating the
     * headers from the message body.
     */
    content_length = -1;
    while (remaining_length > 0) {
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
        gboolean is_no_header_termination = FALSE;
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
        if(tvb_reported_length_remaining(tvb, next_offset) <= 0){
            is_no_header_termination = TRUE;
        }else{
            while (tvb_offset_exists(tvb, next_offset) && ((c = tvb_get_guint8(tvb, next_offset)) == ' ' || c == '\t'))
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
            expert_add_info(pinfo, th, &ei_sip_header_no_colon);
        } else {
            header_len = colon_offset - offset;
            header_name = (gchar*)tvb_get_string_enc(wmem_packet_scope(), tvb, offset, header_len, ENC_UTF_8|ENC_NA);
            ascii_strdown_inplace(header_name);
            hf_index = sip_is_known_sip_header(header_name, header_len);

            /*
             * Skip whitespace after the colon.
             */
            value_offset = tvb_skip_wsp(tvb, colon_offset + 1, line_end_offset - (colon_offset + 1));

            value_len = (gint) (line_end_offset - value_offset);

            if (hf_index == -1) {
                gint *hf_ptr = NULL;
                if (sip_custom_header_fields_hash) {
                    hf_ptr = (gint*)g_hash_table_lookup(sip_custom_header_fields_hash, header_name);
                }
                if (hf_ptr) {
                    sip_proto_tree_add_string(hdr_tree, *hf_ptr, tvb, offset,
                                              next_offset - offset, value_offset, value_len);
                } else {
                    proto_item *ti_c;
                    proto_tree *ti_tree = proto_tree_add_subtree(hdr_tree, tvb,
                                                         offset, next_offset - offset, ett_sip_ext_hdr, &ti_c,
                                                         tvb_format_text(pinfo->pool, tvb, offset, linelen));

                    ext_hdr_handle = dissector_get_string_handle(ext_hdr_subdissector_table, header_name);
                    if (ext_hdr_handle != NULL) {
                        tvbuff_t *next_tvb2;
                        next_tvb2 = tvb_new_subset_length(tvb, value_offset, value_len);
                        dissector_try_string(ext_hdr_subdissector_table, header_name, next_tvb2, pinfo, ti_tree, NULL);
                    } else {
                        expert_add_info_format(pinfo, ti_c, &ei_sip_unrecognized_header,
                                               "Unrecognised SIP header (%s)",
                                               header_name);
                    }
                }
            } else {
                proto_item *sip_element_item;
                proto_tree *sip_element_tree;

                /*
                 * Add it to the protocol tree,
                 * but display the line as is.
                 */
                switch ( hf_index ) {

                    case POS_TO :

                        /*if(hdr_tree)*/ {
                            proto_item *item;

                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            sip_element_tree = proto_item_add_subtree( sip_element_item,
                                               ett_sip_element);
                            /* To        =  ( "To" / "t" ) HCOLON ( name-addr
                             *               / addr-spec ) *( SEMI to-param )
                             */
                            sip_uri_offset_init(&uri_offsets);
                            if((dissect_sip_name_addr_or_addr_spec(tvb, pinfo, value_offset, line_end_offset+2, &uri_offsets)) != -1){
                                display_sip_uri(tvb, sip_element_tree, pinfo, &uri_offsets, &sip_to_uri);
                                if((uri_offsets.name_addr_start != -1) && (uri_offsets.name_addr_end != -1)){
                                    stat_info->tap_to_addr=tvb_get_string_enc(wmem_packet_scope(), tvb, uri_offsets.name_addr_start,
                                        uri_offsets.name_addr_end - uri_offsets.name_addr_start + 1, ENC_UTF_8|ENC_NA);
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
                                proto_tree_add_item(sip_element_tree, hf_sip_to_tag, tvb, parameter_offset,
                                                    parameter_len, ENC_UTF_8);
                                item = proto_tree_add_item(sip_element_tree, hf_sip_tag, tvb, parameter_offset,
                                                           parameter_len, ENC_UTF_8);
                                proto_item_set_hidden(item);

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
                        /*if(hdr_tree)*/ {
                            proto_item *item;

                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            sip_element_tree = proto_item_add_subtree( sip_element_item, ett_sip_element);
                            /*
                             * From        =  ( "From" / "f" ) HCOLON from-spec
                             * from-spec   =  ( name-addr / addr-spec )
                             *                *( SEMI from-param )
                             */

                            sip_uri_offset_init(&uri_offsets);
                            if((dissect_sip_name_addr_or_addr_spec(tvb, pinfo, value_offset, line_end_offset+2, &uri_offsets)) != -1){
                                display_sip_uri(tvb, sip_element_tree, pinfo, &uri_offsets, &sip_from_uri);
                                if((uri_offsets.name_addr_start != -1) && (uri_offsets.name_addr_end != -1)){
                                    stat_info->tap_from_addr=tvb_get_string_enc(wmem_packet_scope(), tvb, uri_offsets.name_addr_start,
                                        uri_offsets.name_addr_end - uri_offsets.name_addr_start + 1, ENC_UTF_8|ENC_NA);
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
                                proto_tree_add_item(sip_element_tree, hf_sip_from_tag, tvb, parameter_offset,
                                                    parameter_len, ENC_UTF_8);
                                item = proto_tree_add_item(sip_element_tree, hf_sip_tag, tvb, parameter_offset,
                                                           parameter_len, ENC_UTF_8);
                                proto_item_set_hidden(item);
                            }
                        }/* hdr_tree */
                    break;

                    case POS_P_ASSERTED_IDENTITY :
                        if(hdr_tree)
                        {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

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
                                 display_sip_uri(tvb, sip_element_tree, pinfo, &uri_offsets, &sip_pai_uri);
                        }
                        break;
                    case POS_P_ASSOCIATED_URI:
                        if (hdr_tree)
                        {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                hf_header_array[hf_index], tvb,
                                offset, next_offset - offset,
                                value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);
                            /*
                             * P-Associated-URI       = "P-Associated-URI" HCOLON
                             *                          [p-aso-uri-spec]
                             *                          *(COMMA p-aso-uri-spec)
                             * p-aso-uri-spec         = name-addr *(SEMI ai-param)
                             * ai-param               = generic-param
                             */
                            /* Skip to the end of the URI directly */
                            semi_colon_offset = tvb_find_guint8(tvb, value_offset, line_end_offset - value_offset, '>');
                            if (semi_colon_offset != -1) {
                                semi_colon_offset = tvb_find_guint8(tvb, semi_colon_offset, line_end_offset - semi_colon_offset, ';');
                                if (semi_colon_offset != -1) {
                                    sip_element_tree = proto_item_add_subtree(sip_element_item,
                                        ett_sip_element);
                                    /* We have generic parameters */
                                    dissect_sip_generic_parameters(tvb, sip_element_tree, pinfo, semi_colon_offset + 1, line_end_offset);
                                }
                            }

                        }
                        break;
                    case POS_HISTORY_INFO:
                        if(hdr_tree)
                        {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            sip_element_tree = proto_item_add_subtree( sip_element_item,
                                               ett_sip_hist);
                            dissect_sip_history_info(tvb, sip_element_tree, pinfo, value_offset, line_end_offset);
                        }
                        break;

                    case POS_P_CHARGING_FUNC_ADDRESSES:
                        if(hdr_tree)
                        {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            sip_element_tree = proto_item_add_subtree( sip_element_item,
                                               ett_sip_element);
                            dissect_sip_p_charging_func_addresses(tvb, sip_element_tree, pinfo, value_offset, line_end_offset);
                        }
                        break;

                    case POS_P_PREFERRED_IDENTITY :
                        if(hdr_tree)
                        {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

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
                                 display_sip_uri(tvb, sip_element_tree, pinfo, &uri_offsets, &sip_ppi_uri);
                        }
                        break;

                    case POS_PERMISSION_MISSING :
                        if(hdr_tree)
                        {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

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
                                 display_sip_uri(tvb, sip_element_tree, pinfo, &uri_offsets, &sip_pmiss_uri);
                        }
                        break;


                    case POS_TRIGGER_CONSENT :
                        if(hdr_tree)
                        {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

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

                                tc_uri_item_tree = display_sip_uri(tvb, sip_element_tree, pinfo, &uri_offsets, &sip_tc_uri);
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
                                                    proto_tree_add_item(tc_uri_item_tree, hf_sip_tc_turi, tvb, turi_start_offset,(turi_end_offset - turi_start_offset),ENC_UTF_8);
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
                    case POS_RETRY_AFTER:
                    {
                        /* Store the retry number */
                        char *value = tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, value_len, ENC_UTF_8 | ENC_NA);
                        guint32 retry;
                        gboolean retry_valid = ws_strtou32(value, NULL, &retry);


                        sip_element_item = proto_tree_add_uint(hdr_tree, hf_header_array[hf_index],
                            tvb, offset, next_offset - offset,
                            retry);

                        if (!retry_valid) {
                            expert_add_info(pinfo, sip_element_item, &ei_sip_retry_after_invalid);
                        }
                    }
                    break;
                    case POS_CSEQ :
                    {
                        /* Store the sequence number */
                        char *value = tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, value_len, ENC_UTF_8|ENC_NA);

                        cseq_number = (guint32)strtoul(value, NULL, 10);
                        cseq_number_set = 1;
                        stat_info->tap_cseq_number=cseq_number;

                        /* Add CSeq  tree */
                        if (hdr_tree) {
                            sip_element_item = proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            cseq_tree = proto_item_add_subtree(sip_element_item, ett_sip_cseq);
                        }

                        /* Walk past number and spaces characters to get to start
                           of method name */
                        for (sub_value_offset=0; sub_value_offset < value_len; sub_value_offset++)
                        {
                            if (!g_ascii_isdigit(value[sub_value_offset]))
                            {
                                proto_tree_add_uint(cseq_tree, hf_sip_cseq_seq_no,
                                                    tvb, value_offset, sub_value_offset,
                                                    cseq_number);
                                break;
                            }
                        }

                        for (; sub_value_offset < value_len; sub_value_offset++)
                        {
                            if (g_ascii_isalpha(value[sub_value_offset]))
                            {
                                /* Have reached start of method name */
                                break;
                            }
                        }

                        if (sub_value_offset == value_len)
                        {
                            /* Didn't find method name */
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
                            return offset - orig_offset;
                        }
                        else {
                            (void) g_strlcpy(cseq_method, value+sub_value_offset, MAX_CSEQ_METHOD_SIZE);

                            /* Add CSeq method to the tree */
                            if (cseq_tree)
                            {
                                proto_tree_add_item(cseq_tree, hf_sip_cseq_method, tvb,
                                                    value_offset + sub_value_offset, strlen_to_copy, ENC_UTF_8);
                            }
                        }
                    }
                    break;

                    case POS_RACK :
                    {
                        char *value = tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, value_len, ENC_UTF_8|ENC_NA);
                        int cseq_no_offset;
                        /*int cseq_method_offset;*/

                        /* Add RAck  tree */
                        if (hdr_tree) {
                            sip_element_item = proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            rack_tree = proto_item_add_subtree(sip_element_item, ett_sip_rack);
                        }

                        /* RSeq number */
                        for (sub_value_offset=0; sub_value_offset < value_len; sub_value_offset++)
                        {
                            if (!g_ascii_isdigit(value[sub_value_offset]))
                            {
                                proto_tree_add_uint(rack_tree, hf_sip_rack_rseq_no,
                                                    tvb, value_offset, sub_value_offset,
                                                    (guint32)strtoul(value, NULL, 10));
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
                            if (!g_ascii_isdigit(value[sub_value_offset]))
                            {
                                proto_tree_add_uint(rack_tree, hf_sip_rack_cseq_no,
                                                    tvb, value_offset+cseq_no_offset,
                                                    sub_value_offset-cseq_no_offset,
                                                    (guint32)strtoul(value+cseq_no_offset, NULL, 10));
                                break;
                            }
                        }

                        /* Get to start of CSeq method name */
                        for ( ; sub_value_offset < value_len; sub_value_offset++)
                        {
                            if (g_ascii_isalpha(value[sub_value_offset]))
                            {
                                /* Have reached start of method name */
                                break;
                            }
                        }
                        /*cseq_method_offset = sub_value_offset;*/

                        if (sub_value_offset == linelen)
                        {
                            /* Didn't find method name */
                            return offset - orig_offset;
                        }

                        /* Add CSeq method to the tree */
                        if (cseq_tree)
                        {
                            proto_tree_add_item(rack_tree, hf_sip_rack_cseq_method, tvb,
                                                value_offset + sub_value_offset,
                                                (int)value_len-sub_value_offset, ENC_UTF_8);
                        }

                        break;
                    }

                    case POS_CALL_ID :
                    {
                        char *value = tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, value_len, ENC_UTF_8|ENC_NA);
                        proto_item *gen_item;

                        /* Store the Call-id */
                        (void) g_strlcpy(call_id, value, MAX_CALL_ID_SIZE);
                        stat_info->tap_call_id = wmem_strdup(wmem_packet_scope(), call_id);

                        /* Add 'Call-id' string item to tree */
                        sip_element_item = proto_tree_add_string(hdr_tree,
                                                    hf_header_array[hf_index], tvb,
                                                    offset, next_offset - offset,
                                                    value);
                        gen_item = proto_tree_add_string(hdr_tree,
                                                    hf_sip_call_id_gen, tvb,
                                                    offset, next_offset - offset,
                                                    value);
                        proto_item_set_generated(gen_item);
                        if (sip_hide_generatd_call_ids) {
                            proto_item_set_hidden(gen_item);
                        }
                        sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);
                    }
                    break;

                    case POS_EXPIRES :
                        if (tvb_strneql(tvb, value_offset, "0", value_len) == 0)
                        {
                            expires_is_0 = 1;
                        }

                        /* Add 'Expires' string item to tree */
                        sip_proto_tree_add_uint(hdr_tree,
                                                hf_header_array[hf_index], tvb,
                                                offset, next_offset - offset,
                                                value_offset, value_len);
                    break;

                    /*
                     * Content-Type is the same as Internet
                     * media type used by other dissectors,
                     * appropriate dissector found by
                     * lookup in "media_type" dissector table.
                     */
                    case POS_CONTENT_TYPE :
                        sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                        sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

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
                            message_info.media_str = tvb_get_string_enc(wmem_packet_scope(), tvb, parameter_offset,
                                                         content_type_parameter_str_len, ENC_UTF_8|ENC_NA);
                        }
                        media_type_str_lower_case = ascii_strdown_inplace(
                            (gchar *)tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, content_type_len, ENC_UTF_8|ENC_NA));

                        /* Debug code
                        proto_tree_add_debug_text(hdr_tree, tvb, value_offset,content_type_len,
                                            "media_type_str(lower cased)=%s",media_type_str_lower_case);
                        */
                    break;

                    case POS_CONTENT_LENGTH :
                    {
                        char *value = tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset, value_len, ENC_UTF_8|ENC_NA);
                        gboolean content_length_valid = ws_strtou32(value, NULL, &content_length);

                        sip_element_item = proto_tree_add_uint(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               content_length);
                        sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);
                        if (!content_length_valid)
                            expert_add_info(pinfo, sip_element_item, &ei_sip_content_length_invalid);

                        break;
                    }

                    case POS_MAX_BREADTH :
                    case POS_MAX_FORWARDS :
                    case POS_RSEQ :
                        sip_proto_tree_add_uint(hdr_tree,
                                                hf_header_array[hf_index], tvb,
                                                offset, next_offset - offset,
                                                value_offset, value_len);
                        break;

                    case POS_CONTACT :
                        /*
                         * Contact        =  ("Contact" / "m" ) HCOLON
                         *                   ( STAR / (contact-param *(COMMA contact-param)))
                         * contact-param  =  (name-addr / addr-spec) *(SEMI contact-params)
                         */
                        sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               value_offset, value_len);
                        sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                        sip_element_tree = proto_item_add_subtree( sip_element_item,
                                               ett_sip_element);

                        /* value_offset points to the first non SWS character after ':' */
                        c = tvb_get_guint8(tvb, value_offset);
                        if (c =='*'){
                            contact_is_star = 1;
                            break;
                        }

                        /*if(hdr_tree)*/ {
                            comma_offset = value_offset;
                            while((comma_offset = dissect_sip_contact_item(tvb, pinfo, sip_element_tree, comma_offset,
                                    next_offset, &contacts_expires_0, &contacts_expires_unknown)) != -1)
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
                            sip_authorization_t authorization_info = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
                            authorization_user_t * authorization_user = NULL;
                            /* Add whole line as header tree */
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                               hf_header_array[hf_index], tvb,
                                               offset, next_offset - offset,
                                               value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            sip_element_tree = proto_item_add_subtree( sip_element_item,
                                               ett_sip_element);

                            /* Set sip.auth as a hidden field/filter */
                            ti_c = proto_tree_add_item(hdr_tree, hf_sip_auth, tvb,
                                                     offset, next_offset-offset,
                                                     ENC_UTF_8);
                            proto_item_set_hidden(ti_c);

                            /* Check if we have any parameters */
                            if ((line_end_offset - value_offset) != 0) {
                                /* Authentication-Info does not begin with the scheme name */
                                if (hf_index != POS_AUTHENTICATION_INFO)
                                {
                                    /* The first time comma_offset is "start of parameters" */
                                    comma_offset = tvb_ws_mempbrk_pattern_guint8(tvb, value_offset, line_end_offset - value_offset, &pbrk_whitespace, NULL);
                                    proto_tree_add_item(sip_element_tree, hf_sip_auth_scheme,
                                        tvb, value_offset, comma_offset - value_offset,
                                        ENC_UTF_8 | ENC_NA);
                                } else {
                                    /* The first time comma_offset is "start of parameters" */
                                    comma_offset = value_offset;
                                }

                                /* Parse each individual parameter in the line */
                                while ((comma_offset = dissect_sip_authorization_item(tvb, sip_element_tree, comma_offset, line_end_offset, &authorization_info)) != -1)
                                {
                                    if (comma_offset == line_end_offset)
                                    {
                                        /* Line End reached: Stop Parsing */
                                        break;
                                    }

                                    if (tvb_get_guint8(tvb, comma_offset) != ',')
                                    {
                                        /* Undefined value reached: Stop Parsing */
                                        break;
                                    }
                                    comma_offset++; /* skip comma */
                                }
                                if ((authorization_info.response != NULL) && (global_sip_validate_authorization) &&
                                        (authorization_info.username != NULL) && (authorization_info.realm != NULL)) { /* If there is a response, check for valid credentials */
                                    authorization_user = sip_get_authorization(&authorization_info);
                                    if (authorization_user) {
                                        authorization_info.method = wmem_strdup(wmem_packet_scope(), stat_info->request_method);
                                        if (!sip_validate_authorization(&authorization_info, authorization_user->password)) {
                                            proto_tree_add_expert_format(tree, pinfo, &ei_sip_authorization_invalid, tvb, offset, line_end_offset - offset, "SIP digest does not match known password %s", authorization_user->password);
                                        }
                                    }
                                }
                            } /* Check if we have any parameters */
                        }/*hdr_tree*/
                    break;

                    case POS_ROUTE:
                        /* Add Route subtree */
                        if (hdr_tree) {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            route_tree = proto_item_add_subtree(sip_element_item, ett_sip_route);
                            dissect_sip_route_header(tvb, route_tree, pinfo, &sip_route_uri, value_offset, line_end_offset);
                        }
                        break;
                    case POS_RECORD_ROUTE:
                        /* Add Record-Route subtree */
                        if (hdr_tree) {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            route_tree = proto_item_add_subtree(sip_element_item, ett_sip_route);
                            dissect_sip_route_header(tvb, route_tree, pinfo, &sip_record_route_uri, value_offset, line_end_offset);
                        }
                        break;
                    case POS_SERVICE_ROUTE:
                        /* Add Service-Route subtree */
                        if (hdr_tree) {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            route_tree = proto_item_add_subtree(sip_element_item, ett_sip_route);
                            dissect_sip_route_header(tvb, route_tree, pinfo, &sip_service_route_uri, value_offset, line_end_offset);
                        }
                        break;
                    case POS_PATH:
                        /* Add Path subtree */
                        if (hdr_tree) {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            route_tree = proto_item_add_subtree(sip_element_item, ett_sip_route);
                            dissect_sip_route_header(tvb, route_tree, pinfo, &sip_path_uri, value_offset, line_end_offset);
                        }
                        break;
                    case POS_VIA:
                        /* Add Via subtree */
                        if (hdr_tree) {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            via_tree = proto_item_add_subtree(sip_element_item, ett_sip_via);
                            dissect_sip_via_header(tvb, via_tree, value_offset, line_end_offset, pinfo);
                        }
                        break;
                    case POS_REASON:
                        if(hdr_tree) {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                            reason_tree = proto_item_add_subtree(sip_element_item, ett_sip_reason);
                            dissect_sip_reason_header(tvb, reason_tree, pinfo, value_offset, line_end_offset);
                        }
                        break;
                    case POS_CONTENT_ENCODING:
                        /* Content-Encoding  =  ( "Content-Encoding" / "e" ) HCOLON
                         * content-coding *(COMMA content-coding)
                         */
                        sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                        sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                        content_encoding_parameter_str = ascii_strdown_inplace(tvb_get_string_enc(wmem_packet_scope(), tvb, value_offset,
                                                         (line_end_offset-value_offset), ENC_UTF_8|ENC_NA));
                        break;
                    case POS_SECURITY_CLIENT:
                        /* security-client  = "Security-Client" HCOLON
                         *                     sec-mechanism *(COMMA sec-mechanism)
                         */
                        sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                        sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                        comma_offset = tvb_find_guint8(tvb, value_offset, line_end_offset - value_offset, ',');
                        while(comma_offset<line_end_offset){
                            comma_offset = tvb_find_guint8(tvb, value_offset, line_end_offset - value_offset, ',');
                            if(comma_offset == -1){
                                comma_offset = line_end_offset;
                            }
                            security_client_tree = proto_item_add_subtree(sip_element_item, ett_sip_security_client);
                            dissect_sip_sec_mechanism(tvb, pinfo, security_client_tree, value_offset, comma_offset);
                            comma_offset = value_offset = comma_offset+1;
                        }

                        break;
                    case POS_SECURITY_SERVER:
                        /* security-server  = "Security-Server" HCOLON
                         *                     sec-mechanism *(COMMA sec-mechanism)
                         */
                        sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                        sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                        comma_offset = tvb_find_guint8(tvb, value_offset, line_end_offset - value_offset, ',');
                        while(comma_offset<line_end_offset){
                            comma_offset = tvb_find_guint8(tvb, value_offset, line_end_offset - value_offset, ',');
                            if(comma_offset == -1){
                                comma_offset = line_end_offset;
                            }
                            security_client_tree = proto_item_add_subtree(sip_element_item, ett_sip_security_server);
                            dissect_sip_sec_mechanism(tvb, pinfo, security_client_tree, value_offset, comma_offset);
                            comma_offset = value_offset = comma_offset+1;
                        }

                        break;
                    case POS_SECURITY_VERIFY:
                        /* security-verify  = "Security-Verify" HCOLON
                         *                     sec-mechanism *(COMMA sec-mechanism)
                         */
                        sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                        sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);

                        comma_offset = tvb_find_guint8(tvb, value_offset, line_end_offset - value_offset, ',');
                        while(comma_offset<line_end_offset){
                            comma_offset = tvb_find_guint8(tvb, value_offset, line_end_offset - value_offset, ',');
                            if(comma_offset == -1){
                                comma_offset = line_end_offset;
                            }
                            security_client_tree = proto_item_add_subtree(sip_element_item, ett_sip_security_verify);
                            dissect_sip_sec_mechanism(tvb, pinfo, security_client_tree, value_offset, comma_offset);
                            comma_offset = value_offset = comma_offset+1;
                        }

                        break;
                    case POS_SESSION_ID:
                        if(hdr_tree) {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                            hf_header_array[hf_index], tvb,
                                                            offset, next_offset - offset,
                                                            value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);
                            session_id_tree = proto_item_add_subtree(sip_element_item, ett_sip_session_id);
                            dissect_sip_session_id_header(tvb, session_id_tree, value_offset, line_end_offset, pinfo);
                        }
                        break;
                    case POS_P_ACCESS_NETWORK_INFO:
                        /* Add P-Access-Network-Info subtree */
                        if (hdr_tree) {
                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                hf_header_array[hf_index], tvb,
                                offset, next_offset - offset,
                                value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);
                            p_access_net_info_tree = proto_item_add_subtree(sip_element_item, ett_sip_p_access_net_info);
                            dissect_sip_p_access_network_info_header(tvb, p_access_net_info_tree, value_offset, line_end_offset);
                        }
                        break;
                    case POS_P_CHARGING_VECTOR:
                        if (hdr_tree) {
                            proto_tree *p_charging_vector_tree;

                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                hf_header_array[hf_index], tvb,
                                offset, next_offset - offset,
                                value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);
                            p_charging_vector_tree = proto_item_add_subtree(sip_element_item, ett_sip_p_charging_vector);
                            dissect_sip_p_charging_vector_header(tvb, p_charging_vector_tree, value_offset, line_end_offset);
                        }
                        break;
                    case POS_FEATURE_CAPS:
                        if (hdr_tree) {
                            proto_tree *feature_caps_tree;

                            sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                hf_header_array[hf_index], tvb,
                                offset, next_offset - offset,
                                value_offset, value_len);
                            sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);
                            feature_caps_tree = proto_item_add_subtree(sip_element_item, ett_sip_feature_caps);
                            dissect_sip_p_feature_caps(tvb, feature_caps_tree, value_offset, line_end_offset);
                        }
                        break;
                    default :
                        /* Default case is to assume it's an FT_STRING field */
                        sip_element_item = sip_proto_tree_add_string(hdr_tree,
                                                         hf_header_array[hf_index], tvb,
                                                         offset, next_offset - offset,
                                                         value_offset, value_len);
                        sip_proto_set_format_text(hdr_tree, sip_element_item, tvb, offset, linelen);
                        break;
                }/* end switch */
            }/*if HF_index */
        }/* if colon_offset */
        if (is_no_header_termination == TRUE){
            /* Header not terminated by empty line CRLF */
            proto_tree_add_expert(hdr_tree, pinfo, &ei_sip_header_not_terminated,
                                    tvb, line_end_offset, -1);
        }
        remaining_length = remaining_length - (next_offset - offset);
        offset = next_offset;
    }/* End while */

    datalen = tvb_captured_length_remaining(tvb, offset);
    reported_datalen = tvb_reported_length_remaining(tvb, offset);
    if (content_length != -1) {
        if (datalen > content_length)
            datalen = content_length;
        if (reported_datalen > content_length)
            reported_datalen = content_length;
    }

    /* Add to info column interesting things learned from header fields. */

    /* for either REGISTER requests or responses, any contacts without expires
     * parameter use the Expires header's value
     */
    if (expires_is_0) {
        /* this may add nothing, but that's ok */
        contacts_expires_0 += contacts_expires_unknown;
    }

    /* Registration requests */
    if (current_method_idx == SIP_METHOD_REGISTER)
    {
        /* TODO: what if there's a *-contact but also non-*-contacts?
         * we should create expert info for that someday I guess
         */
        if (contact_is_star && expires_is_0)
        {
            col_append_str(pinfo->cinfo, COL_INFO, "  (remove all bindings)");
        }
        else
        if (contacts_expires_0 > 0)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "  (remove %d binding%s)",
                contacts_expires_0, contacts_expires_0 == 1 ? "":"s");
            if (contacts > contacts_expires_0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, " (add %d binding%s)",
                    contacts - contacts_expires_0,
                    (contacts - contacts_expires_0 == 1) ? "":"s");
            }
        }
        else
        if (!contacts)
        {
            col_append_str(pinfo->cinfo, COL_INFO, "  (fetch bindings)");
        }
        else
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, "  (%d binding%s)",
                contacts, contacts == 1 ? "":"s");
        }
    }

    /* Registration responses - this info only makes sense in 2xx responses */
    if (line_type == STATUS_LINE && stat_info)
    {
        if (stat_info->response_code == 200)
        {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", cseq_method);
        }
        if ((strcmp(cseq_method, "REGISTER") == 0) &&
            stat_info->response_code > 199 && stat_info->response_code < 300)
        {
            if (contacts_expires_0 > 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "  (removed %d binding%s)",
                    contacts_expires_0, contacts_expires_0 == 1 ? "":"s");
                if (contacts > contacts_expires_0) {
                    col_append_fstr(pinfo->cinfo, COL_INFO, " (%d binding%s kept)",
                        contacts - contacts_expires_0,
                        (contacts - contacts_expires_0 == 1) ? "":"s");
                }
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, "  (%d binding%s)",
                    contacts, contacts == 1 ? "":"s");
            }
        }
    }

    /* We've finished writing to the info col for this SIP message
     * Set fence in case there is more than one (SIP)message in the frame
     */
    /* XXX: this produces ugly output, since usually there's only one SIP
     * message in a frame yet this '|' gets added at the end. Need a better
     * way to do this.
     */
    col_append_str(pinfo->cinfo, COL_INFO, " | ");
    col_set_fence(pinfo->cinfo, COL_INFO);

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

    /* For responses, try to link back to request frame */
    if (line_type == STATUS_LINE)
    {
        request_for_response = sip_find_request(pinfo, cseq_method, call_id,
                                                cseq_number_set, cseq_number,
                                                &response_time);
    }

    /* Check if this packet is a resend. */
    resend_for_packet = sip_is_packet_resend(pinfo, cseq_method, call_id,
                                             cseq_number_set, cseq_number,
                                             line_type);
    /* Mark whether this is a resend for the tap */
    stat_info->resend = (resend_for_packet > 0);

    /* Report this packet to the tap */
    if (!pinfo->flags.in_error_pkt)
    {
        tap_queue_packet(sip_tap, pinfo, stat_info);
    }

    if (datalen > 0) {
        /*
         * There's a message body starting at "offset".
         * Set the length of the header item.
         */
        sdp_setup_info_t setup_info;

        setup_info.hf_id = hf_sip_call_id_gen;
        setup_info.add_hidden = sip_hide_generatd_call_ids;
        setup_info.hf_type = SDP_TRACE_ID_HF_TYPE_STR;
        setup_info.trace_id.str = wmem_strdup(wmem_file_scope(), call_id);
        message_info.data = &setup_info;

        proto_item_set_end(th, tvb, offset);
        if(content_encoding_parameter_str != NULL &&
            (!strncmp(content_encoding_parameter_str, "gzip", 4) ||
             !strncmp(content_encoding_parameter_str,"deflate",7))){
            /* The body is gzip:ed */
            next_tvb = tvb_uncompress(tvb, offset,  datalen);
            if (next_tvb) {
                add_new_data_source(pinfo, next_tvb, "gunzipped data");
                if(sip_tree) {
                    ti_a = proto_tree_add_item(sip_tree, hf_sip_msg_body, next_tvb, 0, -1,
                                         ENC_NA);
                    message_body_tree = proto_item_add_subtree(ti_a, ett_sip_message_body);
                }
            } else {
                next_tvb = tvb_new_subset_length_caplen(tvb, offset, datalen, reported_datalen);
                if(sip_tree) {
                    ti_a = proto_tree_add_item(sip_tree, hf_sip_msg_body, next_tvb, 0, -1,
                                         ENC_NA);
                    message_body_tree = proto_item_add_subtree(ti_a, ett_sip_message_body);
                }
            }
        }else{
            next_tvb = tvb_new_subset_length_caplen(tvb, offset, datalen, reported_datalen);
            if(sip_tree) {
                ti_a = proto_tree_add_item(sip_tree, hf_sip_msg_body, next_tvb, 0, -1,
                                     ENC_NA);
                message_body_tree = proto_item_add_subtree(ti_a, ett_sip_message_body);
            }
        }

        /* give the content type parameters to sub dissectors */
        if ( media_type_str_lower_case != NULL ) {
            /* SDP needs a transport layer to determine request/response */
            if (!strcmp(media_type_str_lower_case, "application/sdp")) {
                /* Resends don't count */
                if (resend_for_packet == 0) {
                    if (line_type == REQUEST_LINE) {
                        DPRINT(("calling setup_sdp_transport() SDP_EXCHANGE_OFFER frame=%d",
                                pinfo->num));
                        DINDENT();
                        setup_sdp_transport(next_tvb, pinfo, SDP_EXCHANGE_OFFER, pinfo->num, sip_delay_sdp_changes, &setup_info);
                        DENDENT();
                    } else if (line_type == STATUS_LINE) {
                        if (stat_info->response_code >= 400) {
                            DPRINT(("calling setup_sdp_transport() SDP_EXCHANGE_ANSWER_REJECT "
                                    "request_frame=%d, this=%d",
                                    request_for_response, pinfo->num));
                            DINDENT();
                            /* SIP client request failed, so SDP offer should fail */
                            setup_sdp_transport(next_tvb, pinfo, SDP_EXCHANGE_ANSWER_REJECT, request_for_response, sip_delay_sdp_changes, &setup_info);
                            DENDENT();
                        }
                        else if ((stat_info->response_code >= 200) && (stat_info->response_code <= 299)) {
                            DPRINT(("calling setup_sdp_transport() SDP_EXCHANGE_ANSWER_ACCEPT "
                                    "request_frame=%d, this=%d",
                                    request_for_response, pinfo->num));
                            DINDENT();
                            /* SIP success request, so SDP offer should be accepted */
                            setup_sdp_transport(next_tvb, pinfo, SDP_EXCHANGE_ANSWER_ACCEPT, request_for_response, sip_delay_sdp_changes, &setup_info);
                            DENDENT();
                        }
                    }
                } else {
                    DPRINT(("calling setup_sdp_transport() resend_for_packet "
                            "request_frame=%d, this=%d",
                            request_for_response, pinfo->num));
                    DINDENT();
                    setup_sdp_transport_resend(pinfo->num, resend_for_packet);
                    DENDENT();
                }
            }

            /* XXX: why is this called even if setup_sdp_transport() was called before? That will
                    parse the SDP a second time, for 'application/sdp' media MIME bodies */
            DPRINT(("calling dissector_try_string()"));
            DINDENT();
            found_match = dissector_try_string(media_type_dissector_table,
                                               media_type_str_lower_case,
                                               next_tvb, pinfo,
                                               message_body_tree, &message_info);
            DENDENT();
            DPRINT(("done calling dissector_try_string() with found_match=%u", found_match));

            if (!found_match &&
                !strncmp(media_type_str_lower_case, "multipart/", sizeof("multipart/")-1)) {
                DPRINT(("calling dissector_try_string() for multipart"));
                DINDENT();
                /* Try to decode the unknown multipart subtype anyway */
                found_match = dissector_try_string(media_type_dissector_table,
                                                   "multipart/",
                                                   next_tvb, pinfo,
                                                   message_body_tree, &message_info);
                DENDENT();
                DPRINT(("done calling dissector_try_string() with found_match=%u", found_match));
            }
            /* If no match dump as text */
        }
        if ( found_match == 0 )
        {
            DPRINT(("calling dissector_try_heuristic() with found_match=0"));
            DINDENT();
            if (!(dissector_try_heuristic(heur_subdissector_list,
                              next_tvb, pinfo, message_body_tree, &hdtbl_entry, NULL))) {
                int tmp_offset = 0;
                while (tvb_offset_exists(next_tvb, tmp_offset)) {
                    tvb_find_line_end(next_tvb, tmp_offset, -1, &next_offset, FALSE);
                    linelen = next_offset - tmp_offset;
                    proto_tree_add_format_text(message_body_tree, next_tvb,
                                tmp_offset, linelen);
                    tmp_offset = next_offset;
                }/* end while */
            }
            DENDENT();
        }
        offset += datalen;
    }

    /* And add the filterable field to the request/response line */
    if (reqresp_tree)
    {
        proto_item *item;
        item = proto_tree_add_boolean(reqresp_tree, hf_sip_resend, tvb, orig_offset, 0,
                                      resend_for_packet > 0);
        proto_item_set_generated(item);
        if (resend_for_packet > 0)
        {
            item = proto_tree_add_uint(reqresp_tree, hf_sip_original_frame,
                                       tvb, orig_offset, 0, resend_for_packet);
            proto_item_set_generated(item);
        }

        if (request_for_response > 0)
        {
            item = proto_tree_add_uint(reqresp_tree, hf_sip_matching_request_frame,
                                       tvb, orig_offset, 0, request_for_response);
            proto_item_set_generated(item);
            item = proto_tree_add_uint(reqresp_tree, hf_sip_response_time,
                                       tvb, orig_offset, 0, response_time);
            proto_item_set_generated(item);
            if ((line_type == STATUS_LINE)&&(strcmp(cseq_method, "BYE") == 0)){
                item = proto_tree_add_uint(reqresp_tree, hf_sip_release_time,
                                          tvb, orig_offset, 0, response_time);
                proto_item_set_generated(item);
            }
        }
    }

    if (ts != NULL)
        proto_item_set_len(ts, offset - orig_offset);

    if (global_sip_raw_text)
        tvb_raw_text_add(tvb, orig_offset, offset - orig_offset, tree);

    /* Append a brief summary to the SIP root item */
    if (stat_info->request_method) {
        proto_item_append_text(ts, " (%s)", stat_info->request_method);
    }
    else {
        proto_item_append_text(ts, " (%u)", stat_info->response_code);
    }
    return offset - orig_offset;
}

/* Display filter for SIP Request-Line */
static void
dfilter_sip_request_line(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint offset, guint meth_len, gint linelen)
{
    const guint8    *value;
    guint   parameter_len = meth_len;
    uri_offset_info uri_offsets;

    /*
     * We know we have the entire method; otherwise, "sip_parse_line()"
     * would have returned OTHER_LINE.
     * Request-Line  =  Method SP Request-URI SP SIP-Version CRLF
     * SP = single space
     * Request-URI    =  SIP-URI / SIPS-URI / absoluteURI
     */

    /* get method string*/
    proto_tree_add_item_ret_string(tree, hf_sip_Method, tvb, offset, parameter_len, ENC_ASCII | ENC_NA,
        wmem_packet_scope(), &value);

    /* Copy request method for telling tap */
    stat_info->request_method = value;

    if (tree) {
        /* build Request-URI tree*/
        offset=offset + parameter_len+1;
        sip_uri_offset_init(&uri_offsets);
        /* calc R-URI len*/
        uri_offsets.uri_end = tvb_find_guint8(tvb, offset, linelen, ' ')-1;
        dissect_sip_uri(tvb, pinfo, offset, offset + linelen, &uri_offsets);
        display_sip_uri(tvb, tree, pinfo, &uri_offsets, &sip_req_uri);
    }
}

/* Display filter for SIP Status-Line */
static void
dfilter_sip_status_line(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint line_end, gint offset)
{
    gint response_code = 0;
    gboolean response_code_valid;
    proto_item* pi;
    int diag_len;
    tvbuff_t *next_tvb;

    /*
     * We know we have the entire status code; otherwise,
     * "sip_parse_line()" would have returned OTHER_LINE.
     * We also know that we have a version string followed by a
     * space at the beginning of the line, for the same reason.
     */
    offset = offset + SIP2_HDR_LEN + 1;
    response_code_valid = ws_strtoi32(tvb_get_string_enc(wmem_packet_scope(), tvb, offset, 3,
        ENC_UTF_8|ENC_NA), NULL, &response_code);

    /* Add numerical response code to tree */
    pi = proto_tree_add_uint(tree, hf_sip_Status_Code, tvb, offset, 3, response_code);
    if (!response_code_valid)
        expert_add_info(pinfo, pi, &ei_sip_Status_Code_invalid);

    /* Add response code for sending to tap */
    stat_info->response_code = response_code;

    /* Skip past the response code and possible trailing space */
    offset = offset + 3 + 1;

    /* Check for diagnostics */
    diag_len = line_end - (SIP2_HDR_LEN + 1 + 3 + 1);
    if((diag_len) <= 0)
        return;

    /* If we have a SIP diagnostics sub dissector call it */
    if(sip_diag_handle){
        next_tvb = tvb_new_subset_length(tvb, offset, diag_len);
        call_dissector_only(sip_diag_handle, next_tvb, pinfo, tree, NULL);
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
        if (!g_ascii_isdigit(tvb_get_guint8(tvb, token_2_start)) ||
            !g_ascii_isdigit(tvb_get_guint8(tvb, token_2_start + 1)) ||
            !g_ascii_isdigit(tvb_get_guint8(tvb, token_2_start + 2))) {
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

    meth_name = tvb_get_string_enc(wmem_packet_scope(), tvb, meth_offset, meth_len, ENC_UTF_8|ENC_NA);

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
        pos = GPOINTER_TO_UINT(g_hash_table_lookup(sip_headers_hash, header_name));
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
    proto_tree *raw_tree;
    proto_item *ti;
    int next_offset, linelen, end_offset;
    char *str;

    ti = proto_tree_add_item(tree, proto_raw_sip, tvb, offset, length, ENC_NA);
    raw_tree = proto_item_add_subtree(ti, ett_raw_text);

    end_offset = offset + length;

    while (offset < end_offset) {
        tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
        linelen = next_offset - offset;
        if (raw_tree) {
            if (global_sip_raw_text_without_crlf)
                str = tvb_format_text_wsp(wmem_packet_scope(), tvb, offset, linelen);
            else
                str = tvb_format_text(wmem_packet_scope(), tvb, offset, linelen);
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
    if (pinfo->flags.in_error_pkt)
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
    if (pinfo->fd->visited)
    {
        sip_frame_result = (sip_frame_result_value*)p_get_proto_data(wmem_file_scope(), pinfo, proto_sip, pinfo->curr_layer_num);
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
    (void) g_strlcpy(key.call_id, call_id, MAX_CALL_ID_SIZE);

    /*  We're only using these addresses locally (for the hash lookup) so
     *  there is no need to make a (g_malloc'd) copy of them.
     */
    set_address(&key.dest_address, pinfo->net_dst.type, pinfo->net_dst.len,
            pinfo->net_dst.data);
    set_address(&key.source_address, pinfo->net_src.type,
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
            (void) g_strlcpy(p_val->method, cseq_method, MAX_CSEQ_METHOD_SIZE);
            p_val->transaction_state = nothing_seen;
            p_val->frame_number = 0;
            if (line_type == REQUEST_LINE)
            {
                p_val->request_time = pinfo->abs_ts;
            }
        }
    }
    else
    {
        /* Need to create a new table entry */

        /* Allocate a new key and value */
        p_key = wmem_new(wmem_file_scope(), sip_hash_key);
        p_val = wmem_new0(wmem_file_scope(), sip_hash_value);

        /* Fill in key and value details */
        snprintf(p_key->call_id, MAX_CALL_ID_SIZE, "%s", call_id);
        copy_address_wmem(wmem_file_scope(), &(p_key->dest_address), &pinfo->net_dst);
        copy_address_wmem(wmem_file_scope(), &(p_key->source_address), &pinfo->net_src);
        p_key->dest_port = pinfo->destport;
        if (sip_retrans_the_same_sport) {
            p_key->source_port = pinfo->srcport;
        } else {
            p_key->source_port = MAGIC_SOURCE_PORT;
        }

        p_val->cseq = cseq_number;
        (void) g_strlcpy(p_val->method, cseq_method, MAX_CSEQ_METHOD_SIZE);
        p_val->transaction_state = nothing_seen;
        if (line_type == REQUEST_LINE)
        {
            p_val->request_time = pinfo->abs_ts;
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
                p_val->frame_number = pinfo->num;
                p_val->request_time = pinfo->abs_ts;
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
                    p_val->frame_number = pinfo->num;
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

    sip_frame_result = (sip_frame_result_value *)p_get_proto_data(wmem_file_scope(), pinfo, proto_sip, pinfo->curr_layer_num);
    if (sip_frame_result == NULL)
    {
        sip_frame_result = wmem_new0(wmem_file_scope(), sip_frame_result_value);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_sip, pinfo->curr_layer_num, sip_frame_result);
    }

    /* Store return value with this packet */
    sip_frame_result->original_frame_num = result;

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
    if (pinfo->flags.in_error_pkt)
    {
        return 0;
    }

    /* A broken packet may have no cseq number set. Ignore. */
    if (!cseq_number_set)
    {
        return 0;
    }

    /* Return any answer stored from previous dissection */
    if (pinfo->fd->visited)
    {
        sip_frame_result = (sip_frame_result_value*)p_get_proto_data(wmem_file_scope(), pinfo, proto_sip, pinfo->curr_layer_num);
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
    (void) g_strlcpy(key.call_id, call_id, MAX_CALL_ID_SIZE);

    /* Looking for matching request, so reverse addresses for this lookup */
    set_address(&key.dest_address, pinfo->net_src.type, pinfo->net_src.len,
            pinfo->net_src.data);
    set_address(&key.source_address, pinfo->net_dst.type, pinfo->net_dst.len,
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
    sip_frame_result = (sip_frame_result_value *)p_get_proto_data(wmem_file_scope(), pinfo, proto_sip, pinfo->curr_layer_num);
    if (sip_frame_result == NULL)
    {
        /* Allocate and set all values to zero */
        sip_frame_result = wmem_new0(wmem_file_scope(), sip_frame_result_value);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_sip, pinfo->curr_layer_num, sip_frame_result);
    }

    sip_frame_result->response_request_frame_num = result;

    /* Work out response time */
    seconds_between_packets = (gint)
        (pinfo->abs_ts.secs - p_val->request_time.secs);
    nseconds_between_packets =
         pinfo->abs_ts.nsecs - p_val->request_time.nsecs;
    sip_frame_result->response_time = (seconds_between_packets*1000) +
                                      (nseconds_between_packets / 1000000);
    *response_time = sip_frame_result->response_time;

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
    if (pinfo->flags.in_error_pkt)
    {
        return 0;
    }

    /* A broken packet may have no cseq number set. Ignore. */
    if (!cseq_number_set)
    {
        return 0;
    }

    /* Return any answer stored from previous dissection */
    if (pinfo->fd->visited)
    {
        sip_frame_result = (sip_frame_result_value*)p_get_proto_data(wmem_file_scope(), pinfo, proto_sip, pinfo->curr_layer_num);
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
    (void) g_strlcpy(key.call_id, call_id, MAX_CALL_ID_SIZE);

    /* Looking for matching INVITE */
    set_address(&key.dest_address, pinfo->net_dst.type, pinfo->net_dst.len,
            pinfo->net_dst.data);
    set_address(&key.source_address, pinfo->net_src.type, pinfo->net_src.len,
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
    sip_frame_result = (sip_frame_result_value *)p_get_proto_data(wmem_file_scope(), pinfo, proto_sip, pinfo->curr_layer_num);
    if (sip_frame_result == NULL)
    {
        /* Allocate and set all values to zero */
        sip_frame_result = wmem_new0(wmem_file_scope(), sip_frame_result_value);
        p_add_proto_data(wmem_file_scope(), pinfo, proto_sip,  pinfo->curr_layer_num, sip_frame_result);
    }

    sip_frame_result->response_request_frame_num = result;

    /* Work out response time */
    seconds_between_packets = (gint)
        (pinfo->abs_ts.secs - p_val->request_time.secs);
    nseconds_between_packets =
         pinfo->abs_ts.nsecs - p_val->request_time.nsecs;
    sip_frame_result->response_time = (seconds_between_packets*1000) +
                                      (nseconds_between_packets / 1000000);
    *response_time = sip_frame_result->response_time;


    return result;
}

static gboolean sip_validate_authorization(sip_authorization_t *authorization_info, gchar *password) {
    gchar ha1[33] = {0};
    gchar ha2[33] = {0};
    gchar response[33] = {0};
    gcry_md_hd_t md5_handle;
    if ( (authorization_info->qop == NULL) ||
        (authorization_info->username == NULL) ||
        (authorization_info->realm == NULL) ||
        (authorization_info->method == NULL) ||
        (authorization_info->uri == NULL) ||
        (authorization_info->nonce == NULL) ) {
        return TRUE; /* If no qop, discard */
    }
    if (strcmp(authorization_info->qop, "auth") ||
        (authorization_info->nonce_count == NULL) ||
        (authorization_info->cnonce == NULL) ||
        (authorization_info->response == NULL) ||
        (password == NULL)) {
        return TRUE; /* Obsolete or not enough information, discard */
    }

    if (gcry_md_open(&md5_handle, GCRY_MD_MD5, 0)) {
        return FALSE;
    }

    gcry_md_write(md5_handle, authorization_info->username, strlen(authorization_info->username));
    gcry_md_putc(md5_handle, ':');
    gcry_md_write(md5_handle, authorization_info->realm, strlen(authorization_info->realm));
    gcry_md_putc(md5_handle, ':');
    gcry_md_write(md5_handle, password, strlen(password));
    /* Array is zeroed out so there is always a \0 at index 32 for string termination */
    bytes_to_hexstr(ha1, gcry_md_read(md5_handle, 0), HASH_MD5_LENGTH);
    gcry_md_reset(md5_handle);
    gcry_md_write(md5_handle, authorization_info->method, strlen(authorization_info->method));
    gcry_md_putc(md5_handle, ':');
    gcry_md_write(md5_handle, authorization_info->uri, strlen(authorization_info->uri));
    /* Array is zeroed out so there is always a \0 at index 32 for string termination */
    bytes_to_hexstr(ha2, gcry_md_read(md5_handle, 0), HASH_MD5_LENGTH);
    gcry_md_reset(md5_handle);
    gcry_md_write(md5_handle, ha1, strlen(ha1));
    gcry_md_putc(md5_handle, ':');
    gcry_md_write(md5_handle, authorization_info->nonce, strlen(authorization_info->nonce));
    gcry_md_putc(md5_handle, ':');
    gcry_md_write(md5_handle, authorization_info->nonce_count, strlen(authorization_info->nonce_count));
    gcry_md_putc(md5_handle, ':');
    gcry_md_write(md5_handle, authorization_info->cnonce, strlen(authorization_info->cnonce));
    gcry_md_putc(md5_handle, ':');
    gcry_md_write(md5_handle, authorization_info->qop, strlen(authorization_info->qop));
    gcry_md_putc(md5_handle, ':');
    gcry_md_write(md5_handle, ha2, strlen(ha2));
    /* Array is zeroed out so there is always a \0 at index 32 for string termination */
    bytes_to_hexstr(response, gcry_md_read(md5_handle, 0), HASH_MD5_LENGTH);
    gcry_md_close(md5_handle);
    if (!strncmp(response, authorization_info->response, 32)) {
        return TRUE;
    }
    return FALSE;
}

/* TAP STAT INFO */

/*
 * Much of this is from ui/gtk/sip_stat.c:
 * sip_stat   2004 Martin Mathieson
 */

/* TODO: extra codes to be added from SIP extensions?
 * https://www.iana.org/assignments/sip-parameters/sip-parameters.xhtml#sip-parameters-6
 */
const value_string sip_response_code_vals[] = {
    { 999, "Unknown response"}, /* Must be first */

    { 100, "Trying"},
    { 180, "Ringing"},
    { 181, "Call Is Being Forwarded"},
    { 182, "Queued"},
    { 183, "Session Progress"},
    { 199, "Informational - Others" },

    { 200, "OK"},
    { 202, "Accepted"},
    { 204, "No Notification"},
    { 299, "Success - Others"}, /* used to keep track of other Success packets */

    { 300, "Multiple Choices"},
    { 301, "Moved Permanently"},
    { 302, "Moved Temporarily"},
    { 305, "Use Proxy"},
    { 380, "Alternative Service"},
    { 399, "Redirection - Others"},

    { 400, "Bad Request"},
    { 401, "Unauthorized"},
    { 402, "Payment Required"},
    { 403, "Forbidden"},
    { 404, "Not Found"},
    { 405, "Method Not Allowed"},
    { 406, "Not Acceptable"},
    { 407, "Proxy Authentication Required"},
    { 408, "Request Timeout"},
    { 410, "Gone"},
    { 412, "Conditional Request Failed"},
    { 413, "Request Entity Too Large"},
    { 414, "Request-URI Too Long"},
    { 415, "Unsupported Media Type"},
    { 416, "Unsupported URI Scheme"},
    { 420, "Bad Extension"},
    { 421, "Extension Required"},
    { 422, "Session Timer Too Small"},
    { 423, "Interval Too Brief"},
    { 428, "Use Identity Header"},
    { 429, "Provide Referrer Identity"},
    { 430, "Flow Failed"},
    { 433, "Anonymity Disallowed"},
    { 436, "Bad Identity-Info"},
    { 437, "Unsupported Certificate"},
    { 438, "Invalid Identity Header"},
    { 439, "First Hop Lacks Outbound Support"},
    { 440, "Max-Breadth Exceeded"},
    { 470, "Consent Needed"},
    { 480, "Temporarily Unavailable"},
    { 481, "Call/Transaction Does Not Exist"},
    { 482, "Loop Detected"},
    { 483, "Too Many Hops"},
    { 484, "Address Incomplete"},
    { 485, "Ambiguous"},
    { 486, "Busy Here"},
    { 487, "Request Terminated"},
    { 488, "Not Acceptable Here"},
    { 489, "Bad Event"},
    { 491, "Request Pending"},
    { 493, "Undecipherable"},
    { 494, "Security Agreement Required"},
    { 499, "Client Error - Others"},

    { 500, "Server Internal Error"},
    { 501, "Not Implemented"},
    { 502, "Bad Gateway"},
    { 503, "Service Unavailable"},
    { 504, "Server Time-out"},
    { 505, "Version Not Supported"},
    { 513, "Message Too Large"},
    { 599, "Server Error - Others"},

    { 600, "Busy Everywhere"},
    { 603, "Decline"},
    { 604, "Does Not Exist Anywhere"},
    { 606, "Not Acceptable"},
    { 607, "Unwanted"},
    { 608, "Rejected"},
    { 699, "Global Failure - Others"},

    { 0, NULL}
};
#define RESPONSE_CODE_MIN 100
#define RESPONSE_CODE_MAX 699

typedef enum
{
    REQ_RESP_METHOD_COLUMN,
    COUNT_COLUMN,
    RESENT_COLUMN,
    MIN_SETUP_COLUMN,
    AVG_SETUP_COLUMN,
    MAX_SETUP_COLUMN
} sip_stat_columns;

static stat_tap_table_item sip_stat_fields[] = {
    {TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "Request Method / Response Code", "%-25s"},
    {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Count", "%d"},
    {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Resent", "%d"},
    {TABLE_ITEM_FLOAT, TAP_ALIGN_RIGHT, "Min Setup (s)", "%8.2f"},
    {TABLE_ITEM_FLOAT, TAP_ALIGN_RIGHT, "Avg Setup (s)", "%8.2f"},
    {TABLE_ITEM_FLOAT, TAP_ALIGN_RIGHT, "Max Setup (s)", "%8.2f"},
};

static const char *req_table_name = "SIP Requests";
static const char *resp_table_name = "SIP Responses";

static void sip_stat_init(stat_tap_table_ui* new_stat)
{
    /* XXX Should we have a single request + response table instead? */
    int num_fields = sizeof(sip_stat_fields)/sizeof(stat_tap_table_item);
    stat_tap_table *req_table;
    stat_tap_table *resp_table;
    stat_tap_table_item_type items[sizeof(sip_stat_fields)/sizeof(stat_tap_table_item)];
    guint i;

    // These values are fixed for all entries.
    items[REQ_RESP_METHOD_COLUMN].type = TABLE_ITEM_STRING;
    items[COUNT_COLUMN].type = TABLE_ITEM_UINT;
    items[COUNT_COLUMN].value.uint_value = 0;
    items[RESENT_COLUMN].type = TABLE_ITEM_UINT;
    items[RESENT_COLUMN].value.uint_value = 0;
    items[MIN_SETUP_COLUMN].type = TABLE_ITEM_FLOAT;
    items[MIN_SETUP_COLUMN].value.float_value = 0.0f;
    items[AVG_SETUP_COLUMN].type = TABLE_ITEM_FLOAT;
    items[AVG_SETUP_COLUMN].value.float_value = 0.0f;
    items[MAX_SETUP_COLUMN].type = TABLE_ITEM_FLOAT;
    items[MAX_SETUP_COLUMN].value.float_value = 0.0f;

    req_table = stat_tap_find_table(new_stat, req_table_name);
    if (req_table) {
        if (new_stat->stat_tap_reset_table_cb)
            new_stat->stat_tap_reset_table_cb(req_table);
    }
    else {
        req_table = stat_tap_init_table(req_table_name, num_fields, 0, NULL);
        stat_tap_add_table(new_stat, req_table);

        // For req_table, first column value is method.
        for (i = 1; i < array_length(sip_methods); i++) {
            items[REQ_RESP_METHOD_COLUMN].value.string_value = g_strdup(sip_methods[i]);
            stat_tap_init_table_row(req_table, i-1, num_fields, items);
        }
    }

    resp_table = stat_tap_find_table(new_stat, resp_table_name);
    if (resp_table) {
        if (new_stat->stat_tap_reset_table_cb)
            new_stat->stat_tap_reset_table_cb(resp_table);
    }
    else {
        resp_table = stat_tap_init_table(resp_table_name, num_fields, 0, NULL);
        stat_tap_add_table(new_stat, resp_table);

        // For responses entries, first column gets code and description.
        for (i = 1; sip_response_code_vals[i].strptr; i++) {
            unsigned response_code = sip_response_code_vals[i].value;
            items[REQ_RESP_METHOD_COLUMN].value.string_value =
                ws_strdup_printf("%u %s", response_code, sip_response_code_vals[i].strptr);
            items[REQ_RESP_METHOD_COLUMN].user_data.uint_value = response_code;
            stat_tap_init_table_row(resp_table, i-1, num_fields, items);
        }
    }
}

static tap_packet_status
sip_stat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *siv_ptr, tap_flags_t flags _U_)
{
    stat_data_t* stat_data = (stat_data_t*) tapdata;
    const sip_info_value_t *info_value = (const sip_info_value_t *) siv_ptr;
    stat_tap_table *cur_table = NULL;
    guint cur_row = 0;  /* 0 = Unknown for both tables */

    if (info_value->request_method && info_value->response_code < 1) {
        /* Request table */
        stat_tap_table *req_table = stat_tap_find_table(stat_data->stat_tap_data, req_table_name);
        stat_tap_table_item_type *item_data;
        guint element;

        cur_table = req_table;
        for (element = 0; element < req_table->num_elements; element++) {
            item_data = stat_tap_get_field_data(req_table, element, REQ_RESP_METHOD_COLUMN);
            if (g_ascii_strcasecmp(info_value->request_method, item_data->value.string_value) == 0) {
                cur_row = element;
                break;
            }
        }

    } else if (info_value->response_code > 0) {
        /* Response table */
        stat_tap_table *resp_table = stat_tap_find_table(stat_data->stat_tap_data, resp_table_name);
        guint response_code = info_value->response_code;
        stat_tap_table_item_type *item_data;
        guint element;

        cur_table = resp_table;
        if (response_code < RESPONSE_CODE_MIN || response_code > RESPONSE_CODE_MAX) {
            response_code = 999;
        } else if (!try_val_to_str(response_code, sip_response_code_vals)) {
            response_code = ((response_code / 100) * 100) + 99;
        }

        for (element = 0; element < resp_table->num_elements; element++) {
            item_data = stat_tap_get_field_data(resp_table, element, REQ_RESP_METHOD_COLUMN);
            if (item_data->user_data.uint_value == response_code) {
                cur_row = element;
                break;
            }
        }

    } else {
        return TAP_PACKET_DONT_REDRAW;
    }

    if (cur_table) {
        stat_tap_table_item_type *item_data;

        item_data = stat_tap_get_field_data(cur_table, cur_row, COUNT_COLUMN);
        item_data->value.uint_value++;
        stat_tap_set_field_data(cur_table, cur_row, COUNT_COLUMN, item_data);

        if (info_value->resend) {
            item_data = stat_tap_get_field_data(cur_table, cur_row, RESENT_COLUMN);
            item_data->value.uint_value++;
            stat_tap_set_field_data(cur_table, cur_row, RESENT_COLUMN, item_data);
        }

        if (info_value->setup_time > 0) {
            stat_tap_table_item_type *min_item_data = stat_tap_get_field_data(cur_table, cur_row, MIN_SETUP_COLUMN);
            stat_tap_table_item_type *avg_item_data = stat_tap_get_field_data(cur_table, cur_row, AVG_SETUP_COLUMN);
            stat_tap_table_item_type *max_item_data = stat_tap_get_field_data(cur_table, cur_row, MAX_SETUP_COLUMN);
            double setup_time = (double) info_value->setup_time / 1000;
            unsigned count;

            min_item_data->user_data.uint_value++; /* We store the setup count in MIN_SETUP_COLUMN */
            count = min_item_data->user_data.uint_value;
            avg_item_data->user_data.float_value += setup_time; /* We store the total setup time in AVG_SETUP_COLUMN */

            if (count <= 1) {
                min_item_data->value.float_value = setup_time;
                avg_item_data->value.float_value = setup_time;
                max_item_data->value.float_value = setup_time;
            } else {
                if (setup_time < min_item_data->value.float_value) {
                    min_item_data->value.float_value = setup_time;
                }
                avg_item_data->value.float_value = avg_item_data->user_data.float_value / count;
                if (setup_time > max_item_data->value.float_value) {
                    max_item_data->value.float_value = setup_time;
                }
            }

            stat_tap_set_field_data(cur_table, cur_row, MIN_SETUP_COLUMN, min_item_data);
            stat_tap_set_field_data(cur_table, cur_row, AVG_SETUP_COLUMN, avg_item_data);
            stat_tap_set_field_data(cur_table, cur_row, MAX_SETUP_COLUMN, max_item_data);
        }
    }

    return TAP_PACKET_REDRAW;
}

static void
sip_stat_reset(stat_tap_table* table)
{
    guint element;
    stat_tap_table_item_type* item_data;

    for (element = 0; element < table->num_elements; element++)
    {
        item_data = stat_tap_get_field_data(table, element, COUNT_COLUMN);
        item_data->value.uint_value = 0;
        stat_tap_set_field_data(table, element, COUNT_COLUMN, item_data);

        item_data = stat_tap_get_field_data(table, element, RESENT_COLUMN);
        item_data->value.uint_value = 0;
        stat_tap_set_field_data(table, element, RESENT_COLUMN, item_data);

        item_data = stat_tap_get_field_data(table, element, RESENT_COLUMN);
        item_data->value.uint_value = 0;
        stat_tap_set_field_data(table, element, RESENT_COLUMN, item_data);

        item_data = stat_tap_get_field_data(table, element, MIN_SETUP_COLUMN);
        item_data->user_data.uint_value = 0;
        item_data->value.float_value = 0.0f;
        stat_tap_set_field_data(table, element, MIN_SETUP_COLUMN, item_data);

        item_data = stat_tap_get_field_data(table, element, AVG_SETUP_COLUMN);
        item_data->user_data.float_value = 0;
        item_data->value.float_value = 0.0f;
        stat_tap_set_field_data(table, element, AVG_SETUP_COLUMN, item_data);

        item_data = stat_tap_get_field_data(table, element, MAX_SETUP_COLUMN);
        item_data->value.float_value = 0.0f;
        stat_tap_set_field_data(table, element, MAX_SETUP_COLUMN, item_data);
    }
}

static void
sip_stat_free_table_item(stat_tap_table* table _U_, guint row _U_, guint column, stat_tap_table_item_type* field_data)
{
    if (column != REQ_RESP_METHOD_COLUMN) return;
    g_free((char*)field_data->value.string_value);
    field_data->value.string_value = NULL;
}

static gchar *sip_follow_conv_filter(epan_dissect_t *edt, packet_info *pinfo _U_, guint *stream _U_, guint *sub_stream _U_)
{
    gchar *filter = NULL;

    /* Extract si.Call-ID from decoded tree in edt */
    if (edt != NULL) {
        int hfid = proto_registrar_get_id_byname("sip.Call-ID");
        GPtrArray *gp = proto_find_first_finfo(edt->tree, hfid);
        if (gp != NULL && gp->len != 0) {
            filter = ws_strdup_printf("sip.Call-ID == \"%s\"", fvalue_get_string(&((field_info *)gp->pdata[0])->value));
        }
        g_ptr_array_free(gp, TRUE);
    } else {
        filter = ws_strdup_printf("sip.Call-ID");
    }

    return filter;
}

static gchar *sip_follow_index_filter(guint stream _U_, guint sub_stream _U_)
{
    return NULL;
}

static gchar *sip_follow_address_filter(address *src_addr _U_, address *dst_addr _U_, int src_port _U_, int dst_port _U_)
{
    return NULL;
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
          { "Method",      "sip.Method",
            FT_STRING, BASE_NONE,NULL,0x0,
            "SIP Method", HFILL }
        },
        { &hf_Request_Line,
          { "Request-Line",                "sip.Request-Line",
            FT_STRING, BASE_NONE,NULL,0x0,
            "SIP Request-Line", HFILL }
        },
        { &hf_sip_ruri_display,
          { "Request-URI display info",        "sip.r-uri.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: SIP R-URI Display Info", HFILL }
        },
        { &hf_sip_ruri,
          { "Request-URI",        "sip.r-uri",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: SIP R-URI", HFILL }
        },
        { &hf_sip_ruri_user,
          { "Request-URI User Part",      "sip.r-uri.user",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: SIP R-URI User", HFILL }
        },
        { &hf_sip_ruri_host,
          { "Request-URI Host Part",      "sip.r-uri.host",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: SIP R-URI Host", HFILL }
        },
        { &hf_sip_ruri_port,
          { "Request-URI Host Port",      "sip.r-uri.port",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: SIP R-URI Port", HFILL }
        },
        { &hf_sip_ruri_param,
          { "Request URI parameter",      "sip.r-uri.param",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_sip_Status_Code,
          { "Status-Code",         "sip.Status-Code",
            FT_UINT32, BASE_DEC,NULL,0x0,
            "SIP Status Code", HFILL }
        },
        { &hf_sip_Status_Line,
          { "Status-Line",                 "sip.Status-Line",
            FT_STRING, BASE_NONE,NULL,0x0,
            "SIP Status-Line", HFILL }
        },
        { &hf_sip_display,
          { "SIP Display info",       "sip.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Display info", HFILL }
        },
        { &hf_sip_to_display,
          { "SIP to display info",       "sip.to.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: To Display info", HFILL }
        },
        { &hf_sip_to_addr,
          { "SIP to address",         "sip.to.addr",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: To Address", HFILL }
        },
        { &hf_sip_to_user,
          { "SIP to address User Part",        "sip.to.user",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: To Address User", HFILL }
        },
        { &hf_sip_to_host,
          { "SIP to address Host Part",        "sip.to.host",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: To Address Host", HFILL }
        },
        { &hf_sip_to_port,
          { "SIP to address Host Port",        "sip.to.port",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: To Address Port", HFILL }
        },
        { &hf_sip_to_param,
          { "SIP To URI parameter",        "sip.to.param",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_sip_to_tag,
          { "SIP to tag",          "sip.to.tag",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: to tag", HFILL }
        },
        { &hf_sip_from_display,
          { "SIP from display info",       "sip.from.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: From Display info", HFILL }
        },
        { &hf_sip_from_addr,
          { "SIP from address",        "sip.from.addr",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: From Address", HFILL }
        },
        { &hf_sip_from_user,
          { "SIP from address User Part",      "sip.from.user",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: From Address User", HFILL }
        },
        { &hf_sip_from_host,
          { "SIP from address Host Part",      "sip.from.host",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: From Address Host", HFILL }
        },
        { &hf_sip_from_port,
          { "SIP from address Host Port",      "sip.from.port",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: From Address Port", HFILL }
        },
        { &hf_sip_from_param,
          { "SIP From URI parameter",      "sip.from.param",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_sip_from_tag,
          { "SIP from tag",        "sip.from.tag",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: from tag", HFILL }
        },
        { &hf_sip_curi_display,
          { "SIP C-URI display info",       "sip.contact.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: SIP C-URI Display info", HFILL }
        },
        { &hf_sip_curi,
          { "Contact URI",        "sip.contact.uri",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: SIP C-URI", HFILL }
        },
        { &hf_sip_curi_user,
          { "Contact URI User Part",      "sip.contact.user",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: SIP C-URI User", HFILL }
        },
        { &hf_sip_curi_host,
          { "Contact URI Host Part",      "sip.contact.host",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: SIP C-URI Host", HFILL }
        },
        { &hf_sip_curi_port,
          { "Contact URI Host Port",      "sip.contact.port",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: SIP C-URI Port", HFILL }
        },
        { &hf_sip_curi_param,
          { "Contact URI parameter",      "sip.contact.param",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_sip_route_display,
          { "Route display info",       "sip.Route.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_route,
          { "Route URI",         "sip.Route.uri",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_route_user,
          { "Route Userinfo",    "sip.Route.user",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_route_host,
          { "Route Host Part",   "sip.Route.host",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_route_port,
          { "Route Host Port",   "sip.Route.port",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_route_param,
          { "Route URI parameter",   "sip.Route.param",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_record_route_display,
          { "Record-Route display info",       "sip.Record-Route.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_record_route,
          { "Record-Route URI",         "sip.Record-Route.uri",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_record_route_user,
          { "Record-Route Userinfo",    "sip.Record-Route.user",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_record_route_host,
          { "Record-Route Host Part",   "sip.Record-Route.host",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_record_route_port,
          { "Record-Route Host Port",   "sip.Record-Route.port",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_record_route_param,
          { "Record-Route URI parameter",   "sip.Record-Route.param",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_service_route_display,
          { "Service-Route display info",       "sip.Service-Route.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_service_route,
          { "Service-Route URI",         "sip.Service-Route.uri",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_service_route_user,
          { "Service-Route Userinfo",    "sip.Service-Route.user",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_service_route_host,
          { "Service-Route Host Part",   "sip.Service-Route.host",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_service_route_port,
          { "Service-Route Host Port",   "sip.Service-Route.port",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_service_route_param,
          { "Service-Route URI parameter",   "sip.Service-Route.param",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_path_display,
          { "Path URI",       "sip.Path.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_path,
          { "Path URI",         "sip.Path.uri",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_path_user,
          { "Path Userinfo",    "sip.Path.user",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_path_host,
          { "Path Host Part",   "sip.Path.host",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_path_port,
          { "Path Host Port",   "sip.Path.port",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_path_param,
          { "Path URI parameter",   "sip.Path.param",
            FT_STRING, BASE_NONE,NULL,0x0,NULL,HFILL }
        },
        { &hf_sip_contact_param,
          { "Contact parameter",       "sip.contact.parameter",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: one contact parameter", HFILL }
        },
        { &hf_sip_tag,
          { "SIP tag",         "sip.tag",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: tag", HFILL }
        },
        { &hf_sip_pai_display,
          { "SIP PAI display info",       "sip.pai.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Asserted-Identity Display info", HFILL }
        },
        { &hf_sip_pai_addr,
          { "SIP PAI Address",         "sip.pai.addr",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Asserted-Identity Address", HFILL }
        },
        { &hf_sip_pai_user,
          { "SIP PAI User Part",       "sip.pai.user",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Asserted-Identity User", HFILL }
        },
        { &hf_sip_pai_host,
          { "SIP PAI Host Part",       "sip.pai.host",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Asserted-Identity Host", HFILL }
        },
        { &hf_sip_pai_port,
          { "SIP PAI Host Port",       "sip.pai.port",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Asserted-Identity Port", HFILL }
        },
        { &hf_sip_pai_param,
          { "SIP PAI URI parameter",       "sip.pai.param",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_sip_pmiss_display,
          { "SIP PMISS display info",       "sip.pmiss.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Permission Missing Display info", HFILL }
        },
        { &hf_sip_pmiss_addr,
          { "SIP PMISS Address",       "sip.pmiss.addr",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Permission Missing Address", HFILL }
        },
        { &hf_sip_pmiss_user,
          { "SIP PMISS User Part",     "sip.pmiss.user",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Permission Missing User", HFILL }
        },
        { &hf_sip_pmiss_host,
          { "SIP PMISS Host Part",     "sip.pmiss.host",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Permission Missing Host", HFILL }
        },
        { &hf_sip_pmiss_port,
          { "SIP PMISS Host Port",     "sip.pmiss.port",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Permission Missing Port", HFILL }
        },
        { &hf_sip_pmiss_param,
          { "SIP PMISS URI parameter",     "sip.pmiss.param",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_sip_ppi_display,
          { "SIP PPI display info",       "sip.ppi.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Preferred-Identity Display info", HFILL }
        },
        { &hf_sip_ppi_addr,
          { "SIP PPI Address",         "sip.ppi.addr",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Preferred-Identity Address", HFILL }
        },
        { &hf_sip_ppi_user,
          { "SIP PPI User Part",       "sip.ppi.user",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Preferred-Identity User", HFILL }
        },
        { &hf_sip_ppi_host,
          { "SIP PPI Host Part",       "sip.ppi.host",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Preferred-Identity Host", HFILL }
        },
        { &hf_sip_ppi_port,
          { "SIP PPI Host Port",       "sip.ppi.port",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Preferred-Identity Port", HFILL }
        },
        { &hf_sip_ppi_param,
          { "SIP PPI URI parameter",       "sip.ppi.param",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_sip_tc_display,
          { "SIP TC display info",       "sip.tc.display.info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Trigger Consent Display info", HFILL }
        },
        { &hf_sip_tc_addr,
          { "SIP TC Address",      "sip.tc.addr",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Trigger Consent Address", HFILL }
        },
        { &hf_sip_tc_user,
          { "SIP TC User Part",        "sip.tc.user",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Trigger Consent User", HFILL }
        },
        { &hf_sip_tc_host,
          { "SIP TC Host Part",        "sip.tc.host",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Trigger Consent Host", HFILL }
        },
        { &hf_sip_tc_port,
          { "SIP TC Host Port",        "sip.tc.port",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Trigger Consent Port", HFILL }
        },
        { &hf_sip_tc_param,
          { "SIP TC URI parameter",        "sip.tc.param",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_sip_tc_turi,
          { "SIP TC Target URI",       "sip.tc.target-uri",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: Trigger Consent Target URI", HFILL }
        },
        { &hf_header_array[POS_ACCEPT],
          { "Accept",      "sip.Accept",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Accept Header", HFILL }
        },
        { &hf_header_array[POS_ACCEPT_CONTACT],
          { "Accept-Contact",      "sip.Accept-Contact",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3841: Accept-Contact Header", HFILL }
        },
        { &hf_header_array[POS_ACCEPT_ENCODING],
          { "Accept-Encoding",         "sip.Accept-Encoding",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3841: Accept-Encoding Header", HFILL }
        },
        { &hf_header_array[POS_ACCEPT_LANGUAGE],
          { "Accept-Language",         "sip.Accept-Language",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Accept-Language Header", HFILL }
        },
        { &hf_header_array[POS_ACCEPT_RESOURCE_PRIORITY],
          { "Accept-Resource-Priority",        "sip.Accept-Resource-Priority",
            FT_STRING, BASE_NONE,NULL,0x0,
            "Draft: Accept-Resource-Priority Header", HFILL }
        },
        { &hf_header_array[POS_ADDITIONAL_IDENTITY],
          { "Additional-Identity",        "sip.Additional-Identity",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_ALERT_INFO],
          { "Alert-Info",      "sip.Alert-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Alert-Info Header", HFILL }
        },
        { &hf_header_array[POS_ALLOW],
          { "Allow",       "sip.Allow",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Allow Header", HFILL }
        },
        { &hf_header_array[POS_ALLOW_EVENTS],
          { "Allow-Events",        "sip.Allow-Events",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3265: Allow-Events Header", HFILL }
        },
        { &hf_header_array[POS_ANSWER_MODE],
          { "Answer-Mode",         "sip.Answer-Mode",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 5373: Answer-Mode Header", HFILL }
        },
        { &hf_header_array[POS_ATTESTATION_INFO],
          { "Attestation-Info",         "sip.Attestation-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_AUTHENTICATION_INFO],
          { "Authentication-Info",         "sip.Authentication-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Authentication-Info Header", HFILL }
        },
        { &hf_header_array[POS_AUTHORIZATION],
          { "Authorization",       "sip.Authorization",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Authorization Header", HFILL }
        },
        { &hf_header_array[POS_CALL_ID],
          { "Call-ID",         "sip.Call-ID",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Call-ID Header", HFILL }
        },
        { &hf_header_array[POS_CALL_INFO],
          { "Call-Info",       "sip.Call-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Call-Info Header", HFILL }
        },
        { &hf_header_array[POS_CELLULAR_NETWORK_INFO],
          { "Cellular-Network-Info",       "sip.Cellular-Network-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_CONTACT],
          { "Contact",         "sip.Contact",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Contact Header", HFILL }
        },
        { &hf_header_array[POS_CONTENT_DISPOSITION],
          { "Content-Disposition",         "sip.Content-Disposition",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Content-Disposition Header", HFILL }
        },
        { &hf_header_array[POS_CONTENT_ENCODING],
          { "Content-Encoding",        "sip.Content-Encoding",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Content-Encoding Header", HFILL }
        },
        { &hf_header_array[POS_CONTENT_LANGUAGE],
          { "Content-Language",        "sip.Content-Language",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Content-Language Header", HFILL }
        },
        { &hf_header_array[POS_CONTENT_LENGTH],
          { "Content-Length",      "sip.Content-Length",
            FT_UINT32, BASE_DEC,NULL,0x0,
            "RFC 3261: Content-Length Header", HFILL }
        },
        { &hf_header_array[POS_CONTENT_TYPE],
          { "Content-Type",        "sip.Content-Type",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Content-Type Header", HFILL }
        },
        { &hf_header_array[POS_CSEQ],
          { "CSeq",        "sip.CSeq",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: CSeq Header", HFILL }
        },
        { &hf_header_array[POS_DATE],
          { "Date",        "sip.Date",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Date Header", HFILL }
        },
        { &hf_header_array[POS_ERROR_INFO],
          { "Error-Info",      "sip.Error-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Error-Info Header", HFILL }
        },
        { &hf_header_array[POS_EVENT],
          { "Event",       "sip.Event",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3265: Event Header", HFILL }
        },
        { &hf_header_array[POS_EXPIRES],
          { "Expires",         "sip.Expires",
            FT_UINT32, BASE_DEC,NULL,0x0,
            "RFC 3261: Expires Header", HFILL }
        },
        { &hf_header_array[POS_FEATURE_CAPS],
          { "Feature-Caps",        "sip.Feature-Caps",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 6809: Feature-Caps", HFILL }
        },
        { &hf_header_array[POS_FLOW_TIMER],
          { "Flow-Timer",      "sip.Flow-Timer",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 5626: Flow-Timer", HFILL }
        },
        { &hf_header_array[POS_FROM],
          { "From",        "sip.From",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: From Header", HFILL }
        },
        { &hf_header_array[POS_GEOLOCATION],
          { "Geolocation",         "sip.Geolocation",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_GEOLOCATION_ERROR],
          { "Geolocation-Error",       "sip.Geolocation-Error",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_GEOLOCATION_ROUTING],
          { "Geolocation-Routing",         "sip.Geolocation-Routing",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_HISTORY_INFO],
          { "History-Info",           "sip.History-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 4244: Request History Information", HFILL }
        },
        { &hf_header_array[POS_IDENTITY],
          { "Identity",           "sip.Identity",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 4474: Request Identity", HFILL }
        },
        { &hf_header_array[POS_IDENTITY_INFO],
          { "Identity-info",          "sip.Identity-info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 4474: Request Identity-info", HFILL }
        },
        { &hf_header_array[POS_INFO_PKG],
          { "Info-Package",           "sip.Info-Package",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_IN_REPLY_TO],
          { "In-Reply-To",         "sip.In-Reply-To",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: In-Reply-To Header", HFILL }
        },
        { &hf_header_array[POS_JOIN],
          { "Join",        "sip.Join",
            FT_STRING, BASE_NONE,NULL,0x0,
            "Draft: Join Header", HFILL }
        },
        { &hf_header_array[POS_MAX_BREADTH],
          { "Max-Breadth",     "sip.Max-Breadth",
            FT_UINT32, BASE_DEC,NULL,0x0,
            "RFC 5393: Max-Breadth Header", HFILL }
        },
        { &hf_header_array[POS_MAX_FORWARDS],
          { "Max-Forwards",        "sip.Max-Forwards",
            FT_UINT32, BASE_DEC,NULL,0x0,
            "RFC 3261: Max-Forwards Header", HFILL }
        },
        { &hf_header_array[POS_MIME_VERSION],
          { "MIME-Version",        "sip.MIME-Version",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: MIME-Version Header", HFILL }
        },
        { &hf_header_array[POS_MIN_EXPIRES],
          { "Min-Expires",         "sip.Min-Expires",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Min-Expires Header", HFILL }
        },
        { &hf_header_array[POS_MIN_SE],
          { "Min-SE",      "sip.Min-SE",
            FT_STRING, BASE_NONE,NULL,0x0,
            "Draft: Min-SE Header", HFILL }
        },
        { &hf_header_array[POS_ORGANIZATION],
          { "Organization",        "sip.Organization",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Organization Header", HFILL }
        },
        { &hf_header_array[POS_ORIGINATION_ID],
          { "Origination-Id",        "sip.Origination-Id",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_P_ACCESS_NETWORK_INFO],
          { "P-Access-Network-Info",   "sip.P-Access-Network-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-Access-Network-Info Header", HFILL }
        },
        { &hf_header_array[POS_P_ANSWER_STATE],
          { "P-Answer-State",      "sip.P-Answer-State",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 4964: P-Answer-State Header", HFILL }
        },
        { &hf_header_array[POS_P_ASSERTED_IDENTITY],
          { "P-Asserted-Identity",     "sip.P-Asserted-Identity",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Asserted-Identity Header", HFILL }
        },
        { &hf_header_array[POS_P_ASSERTED_SERV],
          { "P-Asserted-Service",      "sip.P-Asserted-Service",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_P_CHARGE_INFO],
          { "P-Charge-Info",      "sip.P-Charge-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_P_ASSOCIATED_URI],
          { "P-Associated-URI",        "sip.P-Associated-URI",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3455: P-Associated-URI Header", HFILL }
        },

        { &hf_header_array[POS_P_CALLED_PARTY_ID],
          { "P-Called-Party-ID",       "sip.P-Called-Party-ID",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3455: P-Called-Party-ID Header", HFILL }
        },

        { &hf_header_array[POS_P_CHARGING_FUNC_ADDRESSES],
          { "P-Charging-Function-Addresses","sip.P-Charging-Function-Addresses",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },

        { &hf_header_array[POS_P_CHARGING_VECTOR],
          { "P-Charging-Vector",       "sip.P-Charging-Vector",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-Charging-Vector Header", HFILL }
        },

        { &hf_header_array[POS_P_DCS_TRACE_PARTY_ID],
          { "P-DCS-Trace-Party-ID",    "sip.P-DCS-Trace-Party-ID",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-DCS-Trace-Party-ID Header", HFILL }
        },

        { &hf_header_array[POS_P_DCS_OSPS],
          { "P-DCS-OSPS",          "sip.P-DCS-OSPS",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-DCS-OSPS Header", HFILL }
        },

        { &hf_header_array[POS_P_DCS_BILLING_INFO],
          { "P-DCS-Billing-Info",      "sip.P-DCS-Billing-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-DCS-Billing-Info Header", HFILL }
        },

        { &hf_header_array[POS_P_DCS_LAES],
          { "P-DCS-LAES",          "sip.P-DCS-LAES",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-DCS-LAES Header", HFILL }
        },

        { &hf_header_array[POS_P_DCS_REDIRECT],
          { "P-DCS-Redirect",      "sip.P-DCS-Redirect",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-DCS-Redirect Header", HFILL }
        },

        { &hf_header_array[POS_P_EARLY_MEDIA],
          { "P-Early-Media",       "sip.P-Early-Media",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-Early-Media Header", HFILL }
        },

        { &hf_header_array[POS_P_MEDIA_AUTHORIZATION],
          { "P-Media-Authorization",   "sip.P-Media-Authorization",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3313: P-Media-Authorization Header", HFILL }
        },

        { &hf_header_array[POS_P_PREFERRED_IDENTITY],
          { "P-Preferred-Identity",    "sip.P-Preferred-Identity",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3325: P-Preferred-Identity Header", HFILL }
        },
        { &hf_header_array[POS_P_PREFERRED_SERV],
          { "P-Preferred-Service",     "sip.P-Preferred-Service",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_P_PROFILE_KEY],
          { "P-Profile-Key",   "sip.P-Profile-Key",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-Profile-Key Header", HFILL }
        },
        { &hf_header_array[POS_P_REFUSED_URI_LST],
          { "P-Refused-URI-List",      "sip.P-Refused-URI-List",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-Refused-URI-List Header", HFILL }
        },
        { &hf_header_array[POS_P_SERVED_USER],
          { "P-Served-User",   "sip.P-Served-User",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_P_USER_DATABASE],
          { "P-User-Database",     "sip.P-User-Database",
            FT_STRING, BASE_NONE,NULL,0x0,
            "P-User-Database Header", HFILL }
        },

        { &hf_header_array[POS_P_VISITED_NETWORK_ID],
          { "P-Visited-Network-ID",    "sip.P-Visited-Network-ID",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3455: P-Visited-Network-ID Header", HFILL }
        },

        { &hf_header_array[POS_PATH],
          { "Path",            "sip.Path",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3327: Path Header", HFILL }
        },

        { &hf_header_array[POS_PERMISSION_MISSING],
          { "Permission-Missing",      "sip.Permission-Missing",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 5360: Permission Missing Header", HFILL }
        },
        { &hf_header_array[POS_POLICY_CONTACT],
          { "Policy-Contact",      "sip.Policy_Contact",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_POLICY_ID],
          { "Policy-ID",       "sip.Policy_ID",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_PRIORITY],
          { "Priority",        "sip.Priority",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Priority Header", HFILL }
        },
        { &hf_header_array[POS_PRIORITY_SHARE],
          { "Priority-Share",        "sip.Priority-Share",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_PRIV_ANSWER_MODE],
          { "Priv-Answer-mode",    "sip.Priv-Answer-mode",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_PRIVACY],
          { "Privacy",             "sip.Privacy",
            FT_STRING, BASE_NONE,NULL,0x0,
            "Privacy Header", HFILL }
        },

        { &hf_header_array[POS_PROXY_AUTHENTICATE],
          { "Proxy-Authenticate",      "sip.Proxy-Authenticate",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Proxy-Authenticate Header", HFILL }
        },
        { &hf_header_array[POS_PROXY_AUTHORIZATION],
          { "Proxy-Authorization",         "sip.Proxy-Authorization",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Proxy-Authorization Header", HFILL }
        },

        { &hf_header_array[POS_PROXY_REQUIRE],
          { "Proxy-Require",       "sip.Proxy-Require",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Proxy-Require Header", HFILL }
        },
        { &hf_header_array[POS_RACK],
          { "RAck",        "sip.RAck",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3262: RAck Header", HFILL }
        },
        { &hf_header_array[POS_REASON],
          { "Reason",          "sip.Reason",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3326 Reason Header", HFILL }
        },
        { &hf_header_array[POS_REASON_PHRASE],
          { "Reason-Phrase",           "sip.Reason-Phrase",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_RECORD_ROUTE],
          { "Record-Route",        "sip.Record-Route",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Record-Route Header", HFILL }
        },
        { &hf_header_array[POS_RECV_INFO],
          { "Recv-Info",       "sip.Recv-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_REFER_SUB],
          { "Refer-Sub",       "sip.Refer-Sub",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 4488: Refer-Sub Header", HFILL }
        },
        { &hf_header_array[POS_REFER_TO],
          { "Refer-To",           "sip.Refer-To",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3515: Refer-To Header", HFILL }
        },
        { &hf_header_array[POS_REFERRED_BY],
          { "Referred By",      "sip.Referred-by",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3892: Referred-by Header", HFILL }
        },
        { &hf_header_array[POS_REJECT_CONTACT],
          { "Reject-Contact",         "sip.Reject-Contact",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3841: Reject-Contact Header", HFILL }
        },
        { &hf_header_array[POS_RELAYED_CHARGE],
          { "Relayed-Charge",         "sip.Relayed-Charge",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_REPLACES],
          { "Replaces",       "sip.Replaces",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3891: Replaces Header", HFILL }
        },
        { &hf_header_array[POS_REPLY_TO],
          { "Reply-To",        "sip.Reply-To",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Reply-To Header", HFILL }
        },
        { &hf_header_array[POS_REQUEST_DISPOSITION],
          { "Request-Disposition",     "sip.Request-Disposition",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3841: Request-Disposition Header", HFILL }
        },
        { &hf_header_array[POS_REQUIRE],
          { "Require",        "sip.Require",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Require Header", HFILL }
        },
        { &hf_header_array[POS_RESOURCE_PRIORITY],
          { "Resource-Priority",      "sip.Resource-Priority",
            FT_STRING, BASE_NONE,NULL,0x0,
            "Draft: Resource-Priority Header", HFILL }
        },
        { &hf_header_array[POS_RESOURCE_SHARE],
          { "Resource-Share",      "sip.Resource-Share",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_RESPONSE_SOURCE],
          { "Response-Source",      "sip.Response-Source",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_RESTORATION_INFO],
          { "Restoration-Info",      "sip.Restoration-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_RETRY_AFTER],
          { "Retry-After",        "sip.Retry-After",
            FT_UINT32, BASE_DEC,NULL,0x0,
            "RFC 3261: Retry-After Header", HFILL }
        },
        { &hf_header_array[POS_ROUTE],
          { "Route",       "sip.Route",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Route Header", HFILL }
        },
        { &hf_header_array[POS_RSEQ],
          { "RSeq",        "sip.RSeq",
            FT_UINT32, BASE_DEC,NULL,0x0,
            "RFC 3262: RSeq Header", HFILL }
        },
        { &hf_header_array[ POS_SECURITY_CLIENT],
          { "Security-Client",         "sip.Security-Client",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3329 Security-Client Header", HFILL }
        },
        { &hf_header_array[ POS_SECURITY_SERVER],
          { "Security-Server",         "sip.Security-Server",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3329 Security-Server Header", HFILL }
        },
        { &hf_header_array[ POS_SECURITY_VERIFY],
          { "Security-Verify",         "sip.Security-Verify",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3329 Security-Verify Header", HFILL }
        },
        { &hf_header_array[POS_SERVER],
          { "Server",         "sip.Server",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Server Header", HFILL }
        },
        { &hf_header_array[POS_SERVICE_INTERACT_INFO],
          { "Service-Interact-Info",         "sip.Service-Interact-Info",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_SERVICE_ROUTE],
          { "Service-Route",       "sip.Service-Route",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3608: Service-Route Header", HFILL }
        },
        { &hf_header_array[POS_SESSION_EXPIRES],
          { "Session-Expires",         "sip.Session-Expires",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 4028: Session-Expires Header", HFILL }
        },
        { &hf_header_array[POS_SESSION_ID],
          { "Session-ID", "sip.Session-ID",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_SIP_ETAG],
          { "ETag",        "sip.ETag",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3903: SIP-ETag Header", HFILL }
        },
        { &hf_header_array[POS_SIP_IF_MATCH],
          { "If_Match",        "sip.If_Match",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3903: SIP-If-Match Header", HFILL }
        },
        { &hf_header_array[POS_SUBJECT],
          { "Subject",         "sip.Subject",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Subject Header", HFILL }
        },
        { &hf_header_array[POS_SUBSCRIPTION_STATE],
          { "Subscription-State",      "sip.Subscription-State",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3265: Subscription-State Header", HFILL }
        },
        { &hf_header_array[POS_SUPPORTED],
          { "Supported",      "sip.Supported",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Supported Header", HFILL }
        },
        { &hf_header_array[POS_SUPPRESS_IF_MATCH],
          { "Suppress-If-Match",      "sip.Suppress_If_Match",
            FT_STRING, BASE_NONE,NULL,0x0,
            NULL, HFILL }
        },
        { &hf_header_array[POS_TARGET_DIALOG],
          { "Target-Dialog",      "sip.Target-Dialog",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 4538: Target-Dialog Header", HFILL }
        },
        { &hf_header_array[POS_TIMESTAMP],
          { "Timestamp",      "sip.Timestamp",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Timestamp Header", HFILL }
        },
        { &hf_header_array[POS_TO],
          { "To",         "sip.To",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: To Header", HFILL }
        },

        { &hf_header_array[POS_TRIGGER_CONSENT],
          { "Trigger-Consent",        "sip.Trigger-Consent",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 5380: Trigger Consent", HFILL }
        },

        { &hf_header_array[POS_UNSUPPORTED],
          { "Unsupported",        "sip.Unsupported",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Unsupported Header", HFILL }
        },
        { &hf_header_array[POS_USER_AGENT],
          { "User-Agent",         "sip.User-Agent",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: User-Agent Header", HFILL }
        },
        { &hf_header_array[POS_VIA],
          { "Via",        "sip.Via",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Via Header", HFILL }
        },
        { &hf_header_array[POS_WARNING],
          { "Warning",        "sip.Warning",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: Warning Header", HFILL }
        },

        { &hf_header_array[POS_WWW_AUTHENTICATE],
          { "WWW-Authenticate",       "sip.WWW-Authenticate",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 3261: WWW-Authenticate Header", HFILL }
        },
        { &hf_header_array[POS_DIVERSION],
          { "Diversion",      "sip.Diversion",
            FT_STRING, BASE_NONE,NULL,0x0,
            "RFC 5806: Diversion Header", HFILL }
        },
        { &hf_header_array[POS_USER_TO_USER],
          { "User-to-User",   "sip.uui",
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
            FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RETRANS_PREV), 0x0,
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
        { &hf_sip_via_oc,
        { "Overload Control",  "sip.Via.oc",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_via_oc_val,
        { "Overload Control Value",  "sip.Via.oc_val",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_via_oc_validity,
        { "Overload Control Validity",  "sip.Via.oc_validity",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_via_oc_seq,
        { "Overload Control Sequence",  "sip.Via.oc_seq",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_oc_seq_timestamp,
        { "Overload Control Sequence Time Stamp",
            "sip.Via.oc_seq.ts",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_via_oc_algo,
        { "Overload Control Algorithm",  "sip.Via.oc_algo",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_via_be_route,
        { "be-route",  "sip.Via.be_route",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_p_acc_net_i_acc_type,
           { "access-type", "sip.P-Access-Network-Info.access-type",
             FT_STRING, BASE_NONE, NULL, 0x0,
             "SIP P-Access-Network-Info access-type", HFILL}
        },
        { &hf_sip_p_acc_net_i_ucid_3gpp,
           { "utran-cell-id-3gpp", "sip.P-Access-Network-Info.utran-cell-id-3gpp",
             FT_STRING, BASE_NONE, NULL, 0x0,
             "SIP P-Access-Network-Info utran-cell-id-3gpp", HFILL}
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
        { &hf_sip_reason_protocols,
          { "Reason protocols",  "sip.reason_protocols",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_reason_cause_q850,
          { "Cause",  "sip.reason_cause_q850",
            FT_UINT32, BASE_DEC_HEX|BASE_EXT_STRING, &q850_cause_code_vals_ext, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_reason_cause_sip,
          { "Cause",  "sip.reason_cause_sip",
            FT_UINT32, BASE_DEC, VALS(sip_response_code_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_sip_reason_cause_other,
        { "Cause",  "sip.reason_cause_other",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_reason_text,
        { "Text",  "sip.reason_text",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_msg_body,
          { "Message Body",           "sip.msg_body",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Message Body in SIP message", HFILL }
        },
        { &hf_sip_sec_mechanism,
          { "[Security-mechanism]",  "sip.sec_mechanism",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_sec_mechanism_alg,
          { "alg",  "sip.sec_mechanism.alg",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_sec_mechanism_ealg,
          { "ealg",  "sip.sec_mechanism.ealg",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_sec_mechanism_prot,
          { "prot",  "sip.sec_mechanism.prot",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_sec_mechanism_spi_c,
          { "spi-c",  "sip.sec_mechanism.spi_c",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_sec_mechanism_spi_s,
          { "spi-s",  "sip.sec_mechanism.spi_s",
            FT_UINT32, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_sec_mechanism_port1,
          { "port1",  "sip.sec_mechanism.port1",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_sec_mechanism_port_c,
          { "port-c",  "sip.sec_mechanism.port_c",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_sec_mechanism_port2,
          { "port2",  "sip.sec_mechanism.port2",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_sec_mechanism_port_s,
          { "port-s",  "sip.sec_mechanism.port_s",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_session_id_sess_id,
            { "sess-id", "sip.Session-ID.sess_id",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_session_id_param,
            { "param", "sip.Session-ID.param",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_session_id_local_uuid,
            { "local-uuid", "sip.Session-ID.local_uuid",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_session_id_remote_uuid,
            { "remote-uuid", "sip.Session-ID.remote_uuid",
            FT_GUID, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
	{ &hf_sip_session_id_logme,
           { "logme",  "sip.Session-ID.logme",
             FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
             NULL, HFILL}
        },
        { &hf_sip_continuation,
          { "Continuation data",  "sip.continuation",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        { &hf_sip_feature_cap,
          { "Feature Cap",  "sip.feature_cap",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_service_priority,
          { "Service Priority",  "sip.service_priority",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_icid_value,
        { "icid-value",  "sip.icid_value",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_icid_gen_addr,
        { "icid-gen-addr",  "sip.icid_gen_addr",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_sip_call_id_gen,
        { "Generated Call-ID",         "sip.call_id_generated",
            FT_STRING, BASE_NONE,NULL,0x0,
            "Use to catch call id across protocols", HFILL }
        },

    };

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
        &ett_sip_hist,
        &ett_sip_uri,
        &ett_sip_contact_item,
        &ett_sip_message_body,
        &ett_sip_cseq,
        &ett_sip_via,
        &ett_sip_reason,
        &ett_sip_security_client,
        &ett_sip_security_server,
        &ett_sip_security_verify,
        &ett_sip_rack,
        &ett_sip_record_route,
        &ett_sip_service_route,
        &ett_sip_route,
        &ett_sip_path,
        &ett_sip_ruri,
        &ett_sip_pai_uri,
        &ett_sip_pmiss_uri,
        &ett_sip_ppi_uri,
        &ett_sip_tc_uri,
        &ett_sip_to_uri,
        &ett_sip_from_uri,
        &ett_sip_curi,
        &ett_sip_session_id,
        &ett_sip_p_access_net_info,
        &ett_sip_p_charging_vector,
        &ett_sip_feature_caps,
        &ett_sip_via_be_route
    };
    static gint *ett_raw[] = {
        &ett_raw_text,
    };

    static ei_register_info ei[] = {
        { &ei_sip_unrecognized_header, { "sip.unrecognized_header", PI_UNDECODED, PI_NOTE, "Unrecognised SIP header", EXPFILL }},
        { &ei_sip_header_no_colon, { "sip.header_no_colon", PI_MALFORMED, PI_WARN, "Header has no colon after the name", EXPFILL }},
        { &ei_sip_header_not_terminated, { "sip.header_not_terminated", PI_MALFORMED, PI_WARN, "Header not terminated by empty line (CRLF)", EXPFILL }},
#if 0
        { &ei_sip_odd_register_response, { "sip.response.unusual", PI_RESPONSE_CODE, PI_WARN, "SIP Response is unusual", EXPFILL }},
#endif
        { &ei_sip_sipsec_malformed, { "sip.sec_mechanism.malformed", PI_MALFORMED, PI_WARN, "SIP Security-mechanism header malformed", EXPFILL }},
        { &ei_sip_via_sent_by_port, { "sip.Via.sent-by.port.invalid", PI_MALFORMED, PI_NOTE, "Invalid SIP Via sent-by-port", EXPFILL }},
        { &ei_sip_content_length_invalid, { "sip.content_length.invalid", PI_MALFORMED, PI_NOTE, "Invalid content_length", EXPFILL }},
        { &ei_sip_retry_after_invalid, { "sip.retry_after.invalid", PI_MALFORMED, PI_NOTE, "Invalid retry_after value", EXPFILL }},
        { &ei_sip_Status_Code_invalid, { "sip.Status-Code.invalid", PI_MALFORMED, PI_NOTE, "Invalid Status-Code", EXPFILL }},
        { &ei_sip_authorization_invalid, { "sip.authorization.invalid", PI_PROTOCOL, PI_WARN, "Invalid authorization response for known credentials", EXPFILL }},
        { &ei_sip_session_id_sess_id,{ "sip.Session-ID.sess_id.invalid", PI_PROTOCOL, PI_WARN, "Session ID cannot be empty", EXPFILL }}
    };

    module_t *sip_module;
    expert_module_t* expert_sip;
    uat_t* sip_custom_headers_uat;
    uat_t* sip_authorization_users_uat;

    static tap_param sip_stat_params[] = {
      { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
    };

    static stat_tap_table_ui sip_stat_table = {
      REGISTER_STAT_GROUP_TELEPHONY,
      "SIP Statistics",
      "sip",
      "sip,stat",
      sip_stat_init,
      sip_stat_packet,
      sip_stat_reset,
      sip_stat_free_table_item,
      NULL,
      sizeof(sip_stat_fields)/sizeof(stat_tap_table_item), sip_stat_fields,
      sizeof(sip_stat_params)/sizeof(tap_param), sip_stat_params,
      NULL,
      0
    };

    /* UAT for header fields */
    static uat_field_t sip_custom_header_uat_fields[] = {
        UAT_FLD_CSTRING(sip_custom_header_fields, header_name, "Header name", "SIP header name"),
        UAT_FLD_CSTRING(sip_custom_header_fields, header_desc, "Field desc", "Description of the value contained in the header"),
        UAT_END_FIELDS
    };

    static uat_field_t sip_authorization_users_uat_fields[] = {
        UAT_FLD_CSTRING(sip_authorization_users, username, "Username", "SIP authorization username"),
        UAT_FLD_CSTRING(sip_authorization_users, realm, "Realm", "SIP authorization realm"),
        UAT_FLD_CSTRING(sip_authorization_users, password, "Password", "SIP authorization password"),
        UAT_END_FIELDS
    };

        /* Register the protocol name and description */
    proto_sip = proto_register_protocol("Session Initiation Protocol", "SIP", "sip");
    proto_raw_sip = proto_register_protocol("Session Initiation Protocol (SIP as raw text)",
                                            "Raw_SIP", "raw_sip");
    sip_handle = register_dissector("sip", dissect_sip, proto_sip);
    sip_tcp_handle = register_dissector("sip.tcp", dissect_sip_tcp, proto_sip);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_sip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_sip = expert_register_protocol(proto_sip);
    expert_register_field_array(expert_sip, ei, array_length(ei));
    proto_register_subtree_array(ett_raw, array_length(ett_raw));

    /* Register raw_sip field(s) */
    proto_register_field_array(proto_raw_sip, raw_hf, array_length(raw_hf));

    sip_module = prefs_register_protocol(proto_sip, proto_reg_handoff_sip);

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

    prefs_register_bool_preference(sip_module, "delay_sdp_changes",
        "Delay SDP changes for tracking media",
        "Whether SIP should delay tracking the media (e.g., RTP/RTCP) until an SDP offer "
        "is answered. If enabled, mid-dialog changes to SDP and media state only take "
        "effect if and when an SDP offer is successfully answered; however enabling this "
        "prevents tracking media in early-media call scenarios",
        &sip_delay_sdp_changes);

    prefs_register_bool_preference(sip_module, "hide_generatd_call_id",
        "Hide the generated Call Id",
        "Whether the generated call id should be hidden(not displayed) in the tree or not.",
        &sip_hide_generatd_call_ids);

    /* UAT */
    sip_custom_headers_uat = uat_new("Custom SIP Header Fields",
        sizeof(header_field_t),
        "custom_sip_header_fields",
        TRUE,
        &sip_custom_header_fields,
        &sip_custom_num_header_fields,
        /* specifies named fields, so affects dissection
            and the set of named fields */
        UAT_AFFECTS_DISSECTION|UAT_AFFECTS_FIELDS,
        NULL,
        header_fields_copy_cb,
        header_fields_update_cb,
        header_fields_free_cb,
        header_fields_post_update_cb,
        header_fields_reset_cb,
        sip_custom_header_uat_fields
    );

    prefs_register_uat_preference(sip_module, "custom_sip_header_fields", "Custom SIP header fields",
        "A table to define custom SIP header for which fields can be setup and used for filtering/data extraction etc.",
        sip_custom_headers_uat);

    prefs_register_bool_preference(sip_module, "validate_authorization",
        "Validate SIP authorization",
        "Validate SIP authorizations with known credentials",
        &global_sip_validate_authorization);

    sip_authorization_users_uat = uat_new("SIP authorization users",
        sizeof(authorization_user_t),
        "authorization_users_sip",
        TRUE,
        &sip_authorization_users,
        &sip_authorization_num_users,
        /* specifies named fields, so affects dissection
            and the set of named fields */
        UAT_AFFECTS_DISSECTION|UAT_AFFECTS_FIELDS,
        NULL,
        authorization_users_copy_cb,
        authorization_users_update_cb,
        authorization_users_free_cb,
        NULL,
        NULL,
        sip_authorization_users_uat_fields
    );

    prefs_register_uat_preference(sip_module, "authorization_users_sip", "SIP authorization users",
        "A table to define user credentials used for validating authorization attempts",
        sip_authorization_users_uat);

    register_init_routine(&sip_init_protocol);
    register_cleanup_routine(&sip_cleanup_protocol);
    heur_subdissector_list = register_heur_dissector_list("sip", proto_sip);
    /* Register for tapping */
    sip_tap = register_tap("sip");
    sip_follow_tap = register_tap("sip_follow");

    ext_hdr_subdissector_table = register_dissector_table("sip.hdr", "SIP Extension header", proto_sip, FT_STRING, BASE_NONE);

    register_stat_tap_table_ui(&sip_stat_table);

    /* compile patterns */
    ws_mempbrk_compile(&pbrk_comma_semi, ",;");
    ws_mempbrk_compile(&pbrk_whitespace, " \t\r\n");
    ws_mempbrk_compile(&pbrk_param_end, ">,;? \r");
    ws_mempbrk_compile(&pbrk_param_end_colon_brackets, ">,;? \r:[]");
    ws_mempbrk_compile(&pbrk_header_end_dquote, "\r\n,;\"");
    ws_mempbrk_compile(&pbrk_tab_sp_fslash, "\t /");
    ws_mempbrk_compile(&pbrk_addr_end, "[] \t:;");
    ws_mempbrk_compile(&pbrk_via_param_end, "\t;, ");

    register_follow_stream(proto_sip, "sip_follow", sip_follow_conv_filter, sip_follow_index_filter, sip_follow_address_filter,
                           udp_port_to_display, follow_tvb_tap_listener);
}

void
proto_reg_handoff_sip(void)
{
    static guint saved_sip_tls_port;
    static gboolean sip_prefs_initialized = FALSE;

    if (!sip_prefs_initialized) {
        sigcomp_handle = find_dissector_add_dependency("sigcomp", proto_sip);
        sip_diag_handle = find_dissector("sip.diagnostic");
        sip_uri_userinfo_handle = find_dissector("sip.uri_userinfo");
        sip_via_branch_handle = find_dissector("sip.via_branch");
        sip_via_be_route_handle = find_dissector("sip.via_be_route");
        /* Check for a dissector to parse Reason Code texts */
        sip_reason_code_handle = find_dissector("sip.reason_code");
        /* SIP content type and internet media type used by other dissectors are the same */
        media_type_dissector_table = find_dissector_table("media_type");

        dissector_add_uint_range_with_preference("udp.port", DEFAULT_SIP_PORT_RANGE, sip_handle);
        dissector_add_string("media_type", "message/sip", sip_handle);
        dissector_add_string("ws.protocol", "sip", sip_handle);  /* RFC 7118 */

        dissector_add_uint_range_with_preference("tcp.port", DEFAULT_SIP_PORT_RANGE, sip_tcp_handle);

        heur_dissector_add("udp", dissect_sip_heur, "SIP over UDP", "sip_udp", proto_sip, HEURISTIC_ENABLE);
        heur_dissector_add("tcp", dissect_sip_tcp_heur, "SIP over TCP", "sip_tcp", proto_sip, HEURISTIC_ENABLE);
        heur_dissector_add("sctp", dissect_sip_heur, "SIP over SCTP", "sip_sctp", proto_sip, HEURISTIC_ENABLE);
        heur_dissector_add("stun", dissect_sip_heur, "SIP over TURN", "sip_stun", proto_sip, HEURISTIC_ENABLE);
        sip_prefs_initialized = TRUE;
    } else {
        ssl_dissector_delete(saved_sip_tls_port, sip_tcp_handle);
    }
    /* Set our port number for future use */
    ssl_dissector_add(sip_tls_port, sip_tcp_handle);
    saved_sip_tls_port = sip_tls_port;

    dissector_add_uint("acdr.tls_application_port", 5061, sip_handle);
    dissector_add_uint("acdr.tls_application", TLS_APP_SIP, sip_handle);
    dissector_add_string("protobuf_field", "adc.sip.ResponsePDU.body", sip_handle);
    dissector_add_string("protobuf_field", "adc.sip.RequestPDU.body", sip_handle);

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
