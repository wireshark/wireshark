/* packet-rtsp.c
 * Routines for RTSP packet disassembly (RFC 2326)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * References:
 * RTSP is defined in RFC 2326, https://tools.ietf.org/html/rfc2326
 * https://www.iana.org/assignments/rsvp-parameters
 * RFC 7826 describes RTSP 2.0, and technically obsoletes RFC 2326.
 * However, in practice due to lack of backwards compatibility, it has
 * has seen limited adoption and this dissector does not attempt to
 * dissect it. RFC 7826 does, however, have some useful comments about
 * ambiguities and pitfalls in RFC 2326.
 */

#include "config.h"

#include <stdio.h>	/* for sscanf() */

#include <epan/packet.h>
#include <epan/req_resp_hdrs.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/tap-voip.h>
#include <epan/stats_tree.h>
#include <epan/addr_resolv.h>
#include <wsutil/str_util.h>
#include <wsutil/strtoi.h>
#include <wsutil/array.h>

#include "packet-rdt.h"
#include "packet-rtp.h"
#include "packet-rtcp.h"
#include "packet-e164.h"
#include "packet-rtsp.h"
#include "packet-media-type.h"

void proto_register_rtsp(void);

static int rtsp_tap;

/* http://www.iana.org/assignments/rtsp-parameters/rtsp-parameters.xml */

static const value_string rtsp_status_code_vals[] = {
    { 100, "Continue" },
    { 199, "Informational - Others" },

    { 200, "OK"},
    { 201, "Created"},
    { 250, "Low on Storage Space"},
    { 299, "Success - Others"},

    { 300, "Multiple Choices"},
    { 301, "Moved Permanently"},
    { 302, "Moved Temporarily"},
    { 303, "See Other"},
    { 305, "Use Proxy"},
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
    { 411, "Length Required"},
    { 412, "Precondition Failed"},
    { 413, "Request Entity Too Large"},
    { 414, "Request-URI Too Long"},
    { 415, "Unsupported Media Type"},
    { 451, "Invalid Parameter"},
    { 452, "Illegal Conference Identifier"},
    { 453, "Not Enough Bandwidth"},
    { 454, "Session Not Found"},
    { 455, "Method Not Valid In This State"},
    { 456, "Header Field Not Valid"},
    { 457, "Invalid Range"},
    { 458, "Parameter Is Read-Only"},
    { 459, "Aggregate Operation Not Allowed"},
    { 460, "Only Aggregate Operation Allowed"},
    { 461, "Unsupported Transport"},
    { 462, "Destination Unreachable"},
    { 499, "Client Error - Others"},

    { 500, "Internal Server Error"},
    { 501, "Not Implemented"},
    { 502, "Bad Gateway"},
    { 503, "Service Unavailable"},
    { 504, "Gateway Timeout"},
    { 505, "RTSP Version not supported"},
    { 551, "Option Not Support"},
    { 599, "Server Error - Others"},

    { 0,    NULL}
};

static int proto_rtsp;

static int ett_rtsp;
static int ett_rtspframe;
static int ett_rtsp_method;

static int hf_rtsp_request;
static int hf_rtsp_response;
static int hf_rtsp_response_in;
static int hf_rtsp_response_to;
static int hf_rtsp_content_type;
static int hf_rtsp_content_length;
static int hf_rtsp_method;
static int hf_rtsp_url;
static int hf_rtsp_status;
static int hf_rtsp_session;
static int hf_rtsp_transport;
static int hf_rtsp_rdtfeaturelevel;
static int hf_rtsp_cseq;
static int hf_rtsp_content_base;
static int hf_rtsp_content_location;
static int hf_rtsp_X_Vig_Msisdn;
static int hf_rtsp_magic;
static int hf_rtsp_channel;
static int hf_rtsp_length;
static int hf_rtsp_data;

static int voip_tap;

static expert_field ei_rtsp_unknown_transport_type;
static expert_field ei_rtsp_bad_server_port;
static expert_field ei_rtsp_bad_client_port;
static expert_field ei_rtsp_bad_interleaved_channel;
static expert_field ei_rtsp_content_length_invalid;
static expert_field ei_rtsp_rdtfeaturelevel_invalid;
static expert_field ei_rtsp_cseq_invalid;
static expert_field ei_rtsp_bad_server_ip_address;
static expert_field ei_rtsp_bad_client_ip_address;

static dissector_handle_t rtsp_handle;
static dissector_handle_t rtp_handle;
static dissector_handle_t rtp_rfc4571_handle;
static dissector_handle_t rtcp_handle;
static dissector_handle_t rdt_handle;
static dissector_table_t media_type_dissector_table;
static heur_dissector_list_t heur_subdissector_list;

static const char *st_str_packets = "Total RTSP Packets";
static const char *st_str_requests = "RTSP Request Packets";
static const char *st_str_responses = "RTSP Response Packets";
static const char *st_str_resp_broken = "???: broken";
static const char *st_str_resp_100 = "1xx: Informational";
static const char *st_str_resp_200 = "2xx: Success";
static const char *st_str_resp_300 = "3xx: Redirection";
static const char *st_str_resp_400 = "4xx: Client Error";
static const char *st_str_resp_500 = "5xx: Server Error";
static const char *st_str_other = "Other RTSP Packets";

static int st_node_packets = -1;
static int st_node_requests = -1;
static int st_node_responses = -1;
static int st_node_resp_broken = -1;
static int st_node_resp_100 = -1;
static int st_node_resp_200 = -1;
static int st_node_resp_300 = -1;
static int st_node_resp_400 = -1;
static int st_node_resp_500 = -1;
static int st_node_other = -1;

static void
rtsp_stats_tree_init(stats_tree* st)
{
    st_node_packets     = stats_tree_create_node(st, st_str_packets, 0, STAT_DT_INT, true);
    st_node_requests    = stats_tree_create_pivot(st, st_str_requests, st_node_packets);
    st_node_responses   = stats_tree_create_node(st, st_str_responses, st_node_packets, STAT_DT_INT, true);
    st_node_resp_broken = stats_tree_create_node(st, st_str_resp_broken, st_node_responses, STAT_DT_INT, true);
    st_node_resp_100    = stats_tree_create_node(st, st_str_resp_100,    st_node_responses, STAT_DT_INT, true);
    st_node_resp_200    = stats_tree_create_node(st, st_str_resp_200,    st_node_responses, STAT_DT_INT, true);
    st_node_resp_300    = stats_tree_create_node(st, st_str_resp_300,    st_node_responses, STAT_DT_INT, true);
    st_node_resp_400    = stats_tree_create_node(st, st_str_resp_400,    st_node_responses, STAT_DT_INT, true);
    st_node_resp_500    = stats_tree_create_node(st, st_str_resp_500,    st_node_responses, STAT_DT_INT, true);
    st_node_other       = stats_tree_create_node(st, st_str_other, st_node_packets, STAT_DT_INT, false);
}

/* RTSP/Packet Counter stats packet function */
static tap_packet_status
rtsp_stats_tree_packet(stats_tree* st, packet_info* pinfo _U_, epan_dissect_t* edt _U_, const void* p, tap_flags_t flags _U_)
{
    const rtsp_info_value_t *v = (const rtsp_info_value_t *)p;
    unsigned      i = v->response_code;
    int           resp_grp;
    const char   *resp_str;
    char         *str;

    tick_stat_node(st, st_str_packets, 0, false);

    if (i) {
        tick_stat_node(st, st_str_responses, st_node_packets, false);

        if ( (i<100)||(i>=600) ) {
            resp_grp = st_node_resp_broken;
            resp_str = st_str_resp_broken;
        } else if (i<200) {
            resp_grp = st_node_resp_100;
            resp_str = st_str_resp_100;
        } else if (i<300) {
            resp_grp = st_node_resp_200;
            resp_str = st_str_resp_200;
        } else if (i<400) {
            resp_grp = st_node_resp_300;
            resp_str = st_str_resp_300;
        } else if (i<500) {
            resp_grp = st_node_resp_400;
            resp_str = st_str_resp_400;
        } else {
            resp_grp = st_node_resp_500;
            resp_str = st_str_resp_500;
        }

        tick_stat_node(st, resp_str, st_node_responses, false);

        str = wmem_strdup_printf(pinfo->pool, "%u %s", i, val_to_str(pinfo->pool, i, rtsp_status_code_vals, "Unknown (%d)"));
        tick_stat_node(st, str, resp_grp, false);
    } else if (v->request_method) {
        stats_tree_tick_pivot(st,st_node_requests,v->request_method);
    } else {
        tick_stat_node(st, st_str_other, st_node_packets, false);
    }

    return TAP_PACKET_REDRAW;
}
void proto_reg_handoff_rtsp(void);

/*
 * desegmentation of RTSP headers
 * (when we are over TCP or another protocol providing the desegmentation API)
 */
static bool rtsp_desegment_headers = true;

/*
 * desegmentation of RTSP bodies
 * (when we are over TCP or another protocol providing the desegmentation API)
 * TODO let the user filter on content-type the bodies he wants desegmented
 */
static bool rtsp_desegment_body = true;

/* http://www.iana.org/assignments/port-numbers lists two rtsp ports.
 * In Addition RTSP uses display port over Wi-Fi Display: 7236.
 */
#define RTSP_TCP_PORT_RANGE           "554,8554,7236"

/*
 * Takes an array of bytes, assumed to contain a null-terminated
 * string, as an argument, and returns the length of the string -
 * i.e., the size of the array, minus 1 for the null terminator.
 */
#define STRLEN_CONST(str)   (sizeof (str) - 1)

#define RTSP_FRAMEHDR   ('$')

typedef struct {
    char    *request_uri;
    uint32_t req_frame;
    uint32_t resp_frame;

} rtsp_req_resp_t;

typedef struct {
    dissector_handle_t      dissector;
} rtsp_interleaved_t;

#define RTSP_MAX_INTERLEAVED        (256)

/*
 * Careful about dynamically allocating memory in this structure (say
 * for dynamically increasing the size of the 'interleaved' array) -
 * the containing structure is garbage collected and contained
 * pointers will not be freed.
 *
 * XXX - This is wmem allocated now. Rather than a array of fixed size,
 * the array could be, e.g., a tree or map indexed by the channel.
 */
typedef struct {
    rtsp_interleaved_t      interleaved[RTSP_MAX_INTERLEAVED];
    wmem_map_t  *req_resp_map;
} rtsp_conversation_data_t;

static rtsp_conversation_data_t*
get_rtsp_conversation_data(conversation_t *conv, packet_info *pinfo)
{
    rtsp_conversation_data_t *data;
    if (conv == NULL) {
        conv = find_or_create_conversation_strat(pinfo);
    }

    /* Look for previous data */
    data = (rtsp_conversation_data_t *)conversation_get_proto_data(conv, proto_rtsp);

    /* Create new data if necessary */
    if (!data)
    {
        data = wmem_new0(wmem_file_scope(), rtsp_conversation_data_t);
        data->req_resp_map = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
        conversation_add_proto_data(conv, proto_rtsp, data);
    }

    return data;
}

static int
dissect_rtspinterleaved(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree)
{
    unsigned        length_remaining;
    proto_item     *ti;
    proto_tree     *rtspframe_tree = NULL;
    int             orig_offset;
    uint8_t         rf_chan;    /* interleaved channel id */
    uint16_t        rf_len;     /* packet length */
    tvbuff_t       *next_tvb;
    conversation_t *conv;
    rtsp_conversation_data_t *data;
    dissector_handle_t        dissector;

    /*
     * This will throw an exception if we don't have any data left.
     * That's what we want.  (See "tcp_dissect_pdus()", which is
     * similar.)
     */
    length_remaining = tvb_ensure_captured_length_remaining(tvb, offset);

    /*
     * Can we do reassembly?
     */
    if (rtsp_desegment_headers && pinfo->can_desegment) {
        /*
         * Yes - would an RTSP multiplexed header starting at
         * this offset be split across segment boundaries?
         */
        if (length_remaining < 4) {
            /*
             * Yes.  Tell the TCP dissector where the data for
             * this message starts in the data it handed us and
             * that we need "some more data."  Don't tell it
             * exactly how many bytes we need because if/when we
             * ask for even more (after the header) that will
             * break reassembly.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
            return -1;
        }
    }

    /*
     * Get the "$", channel, and length from the header.
     */
    orig_offset = offset;
    rf_chan = tvb_get_uint8(tvb, offset+1);
    rf_len = tvb_get_ntohs(tvb, offset+2);

    /*
     * Can we do reassembly?
     */
    if (rtsp_desegment_body && pinfo->can_desegment) {
        /*
         * Yes - is the header + encapsulated packet split
         * across segment boundaries?
         */
        if (length_remaining < 4U + rf_len) {
            /*
             * Yes.  Tell the TCP dissector where the data
             * for this message starts in the data it handed
             * us, and how many more bytes we need, and return.
             */
            pinfo->desegment_offset = offset;
            pinfo->desegment_len = 4U + rf_len - length_remaining;
            return -1;
        }
    }

    col_add_fstr(pinfo->cinfo, COL_INFO,
            "Interleaved channel 0x%02x, %u bytes",
            rf_chan, rf_len);

    ti = proto_tree_add_protocol_format(tree, proto_rtsp, tvb,
        offset, 4,
        "RTSP Interleaved Frame, Channel: 0x%02x, %u bytes",
        rf_chan, rf_len);
    rtspframe_tree = proto_item_add_subtree(ti, ett_rtspframe);

    proto_tree_add_item(rtspframe_tree, hf_rtsp_magic, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    proto_tree_add_item(rtspframe_tree, hf_rtsp_channel, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    proto_tree_add_item(rtspframe_tree, hf_rtsp_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /*
     * We set the actual length of the tvbuff for the interleaved
     * stuff to the minimum of what's left in the tvbuff and the
     * length in the header.
     *
     * XXX - what if there's nothing left in the tvbuff?
     * We'd want a BoundsError exception to be thrown, so
     * that a Short Frame would be reported.
     */
    if (length_remaining > rf_len)
        length_remaining = rf_len;
    next_tvb = tvb_new_subset_length_caplen(tvb, offset, length_remaining, rf_len);

    conv = find_conversation_pinfo_strat(pinfo, 0);

    if (conv &&
        (data = (rtsp_conversation_data_t *)conversation_get_proto_data(conv, proto_rtsp)) &&
        /* Add the following condition if it is not always true.
        rf_chan < RTSP_MAX_INTERLEAVED &&
        */
        (dissector = data->interleaved[rf_chan].dissector)) {
        call_dissector(dissector, next_tvb, pinfo, tree);
    } else {
        bool dissected = false;
        heur_dtbl_entry_t *hdtbl_entry = NULL;

        dissected = dissector_try_heuristic(heur_subdissector_list,
                            next_tvb, pinfo, tree, &hdtbl_entry, NULL);

        if (!dissected) {
            proto_tree_add_item(rtspframe_tree, hf_rtsp_data, tvb, offset, rf_len, ENC_NA);
        }
    }

    offset += rf_len;

    return offset - orig_offset;
}

static char* process_rtsp_request(tvbuff_t *tvb, int offset, const unsigned char *data,
                                 size_t linelen, packet_info *pinfo, proto_tree *tree);

static void process_rtsp_reply(tvbuff_t *tvb, int offset, const unsigned char *data,
                               size_t linelen, packet_info *pinfo, proto_tree *tree);

typedef enum {
    RTSP_REQUEST,
    RTSP_REPLY,
    RTSP_NOT_FIRST_LINE
} rtsp_type_t;

static const char *rtsp_methods[] = {
    "DESCRIBE",
    "ANNOUNCE",
    "GET_PARAMETER",
    "OPTIONS",
    "PAUSE",
    "PLAY",
    "RECORD",
    "REDIRECT",
    "SETUP",
    "SET_PARAMETER",
    "TEARDOWN"
};

#define RTSP_NMETHODS   array_length(rtsp_methods)

static bool
is_rtsp_request_or_reply(const unsigned char *line, size_t linelen, rtsp_type_t *type,
                         rtsp_info_value_t *rtsp_stat_info, wmem_allocator_t *pool)
{
    unsigned      ii;
    const unsigned char *token, *next_token;
    int           tokenlen;
    char          response_chars[4];

    /* Is this an RTSP reply? */
    if (linelen >= 5 && g_ascii_strncasecmp("RTSP/", line, 5) == 0) {
        /*
         * Yes.
         */
        *type = RTSP_REPLY;
        /* The first token is the version. */
        tokenlen = get_token_len(line, line+linelen, &token);
        if (tokenlen != 0) {
            /* The next token is the status code. */
            tokenlen = get_token_len(token, line+linelen, &next_token);
            if (tokenlen >= 3) {
                memcpy(response_chars, token, 3);
                response_chars[3] = '\0';
                ws_strtou32(response_chars, NULL, &rtsp_stat_info->response_code);
            }
        }
        return true;
    }

    /*
     * Is this an RTSP request?
     * Check whether the line begins with one of the RTSP request
     * methods.
     */
    for (ii = 0; ii < RTSP_NMETHODS; ii++) {
        size_t len = strlen(rtsp_methods[ii]);
        if (linelen >= len &&
            g_ascii_strncasecmp(rtsp_methods[ii], line, len) == 0 &&
            (len == linelen || g_ascii_isspace(line[len])))
        {
            *type = RTSP_REQUEST;
            rtsp_stat_info->request_method =
               wmem_strndup(pool, rtsp_methods[ii], len+1);
            return true;
        }
    }

    /* Wasn't a request or a response */
    *type = RTSP_NOT_FIRST_LINE;
    return false;
}

static const char rtsp_content_type[]      = "Content-Type:";
static const char rtsp_transport[]         = "Transport:";
static const char rtsp_sps_server_port[]   = "server_port=";
static const char rtsp_cps_server_port[]   = "client_port=";
static const char rtsp_sps_dest_addr[]     = "dest_addr=";
static const char rtsp_cps_src_addr[]      = "src_addr=";
static const char rtsp_rtp_udp_default[]   = "rtp/avp";
static const char rtsp_rtp_udp[]           = "rtp/avp/udp";
static const char rtsp_rtp_tcp[]           = "rtp/avp/tcp";
static const char rtsp_rdt_feature_level[] = "RDTFeatureLevel";
static const char rtsp_real_rdt[]          = "x-real-rdt/";
static const char rtsp_real_tng[]          = "x-pn-tng/"; /* synonym for x-real-rdt */
static const char rtsp_inter[]             = "interleaved=";
static const char rtsp_cseq[]              = "CSeq:";
static const char rtsp_content_base[]      = "Content-Base:";
static const char rtsp_content_location[]  = "Content-Location:";

static sdp_setup_info_t*
rtsp_create_setup_info(packet_info *pinfo, const char* session_id, const char *base_uri)
{
    sdp_setup_info_t *setup_info = NULL;
    if (!PINFO_FD_VISITED(pinfo)) {
        // setup_info is only used on the first pass (by SDP or RTP)
        setup_info = wmem_new0(pinfo->pool, sdp_setup_info_t);
        setup_info->hf_id = hf_rtsp_session;
        setup_info->hf_type = SDP_TRACE_ID_HF_TYPE_STR;
        /* The session is a mandatory, opaque string for the session - but
         * not necessarily available at the time of media initialization via SDP,
         * whether DESCRIBE or via HTTP or some other protocol. It is known at
         * the time of actual RTP setup by RTSP, though.
         *
         * wmem_strdup will return "<NULL>" when it is not available, which
         * shouldn't ever be used by SDP (due to the "control" media attribute)
         * but prevents a possible null dereference with, e.g., fuzzed captures.
         *
         * It's in file scope (unlike the setup_info struct itself) because the
         * SDP and RTP dissectors don't copy the string but use it directly.
         * We probably could store the session id copy in conversation data.
         */
        setup_info->trace_id.str = wmem_strdup(wmem_file_scope(), session_id);
        setup_info->base_uri = base_uri;
    }

    return setup_info;
}

static void
rtsp_create_conversation(packet_info *pinfo, proto_item *ti,
                         const unsigned char *line_begin, size_t line_len,
                         int rdt_feature_level,
                         rtsp_type_t rtsp_type_packet,
                         sdp_setup_info_t *setup_info)
{
    char     buf[256];
    char    *tmp;
    bool      rtp_udp_transport = false;
    bool      rtp_tcp_transport = false;
    bool      rdt_transport = false;
    unsigned  c_data_port, c_mon_port;
    unsigned  s_data_port, s_mon_port;
    unsigned  ipv4_1, ipv4_2, ipv4_3, ipv4_4;
    bool      is_video      = false; /* FIX ME - need to indicate video or not */
    address   src_addr;
    address   dst_addr;
    uint32_t  ip4_addr;
    rtp_dyn_payload_t *rtp_dyn_payload = NULL;

    if (rtsp_type_packet != RTSP_REPLY) {
        return;
    }

    src_addr=pinfo->src;
    dst_addr=pinfo->dst;

    /* Copy line into buf */
    if (line_len > sizeof(buf) - 1)
    {
        /* Don't overflow the buffer. */
        line_len = sizeof(buf) - 1;
    }
    memcpy(buf, line_begin, line_len);
    buf[line_len] = '\0';

    /* Get past "Transport:" and spaces */
    tmp = buf + STRLEN_CONST(rtsp_transport);
    while (*tmp && g_ascii_isspace(*tmp))
        tmp++;

    /* Work out which transport type is here */
    if (g_ascii_strncasecmp(tmp, rtsp_rtp_udp, strlen(rtsp_rtp_udp)) == 0)
    {
        rtp_udp_transport = true;
    }
    else if (g_ascii_strncasecmp(tmp, rtsp_rtp_tcp, strlen(rtsp_rtp_tcp)) == 0)
    {
        rtp_tcp_transport = true;
    }
    else if (g_ascii_strncasecmp(tmp, rtsp_rtp_udp_default, strlen(rtsp_rtp_udp_default)) == 0)
    {
        rtp_udp_transport = true;
    }
    else if (g_ascii_strncasecmp(tmp, rtsp_real_rdt, strlen(rtsp_real_rdt)) == 0 ||
                 g_ascii_strncasecmp(tmp, rtsp_real_tng, strlen(rtsp_real_tng)) == 0)
    {
        rdt_transport = true;
    }
    else
    {
        /* Give up on unknown transport types */
        expert_add_info(pinfo, ti, &ei_rtsp_unknown_transport_type);
        return;
    }

    c_data_port = c_mon_port = 0;
    s_data_port = s_mon_port = 0;

    /* Look for server port */
    if ((tmp = strstr(buf, rtsp_sps_server_port))) {
        tmp += strlen(rtsp_sps_server_port);
        if (sscanf(tmp, "%u-%u", &s_data_port, &s_mon_port) < 1) {
            expert_add_info(pinfo, ti, &ei_rtsp_bad_server_port);
            return;
        }
    }
    else if ((tmp = strstr(buf, rtsp_sps_dest_addr))) {
        tmp += strlen(rtsp_sps_dest_addr);
        if (sscanf(tmp, "\":%u\"", &s_data_port) == 1) {
            /* :9 mean ignore */
            if (s_data_port == 9) {
                s_data_port = 0;
            }
        }
        else if (sscanf(tmp, "\"%u.%u.%u.%u:%u\"", &ipv4_1, &ipv4_2, &ipv4_3, &ipv4_4, &s_data_port) == 5) {
            char *tmp2;
            char *tmp3;

            /* Skip leading " */
            tmp++;
            tmp2=strstr(tmp,":");
            tmp3=g_strndup(tmp,tmp2-tmp);
            if (!str_to_ip(tmp3, &ip4_addr)) {
                g_free(tmp3);
                expert_add_info(pinfo, ti, &ei_rtsp_bad_server_ip_address);
                return;
            }
            set_address(&dst_addr, AT_IPv4, 4, &ip4_addr);
            g_free(tmp3);
        }
        else if (sscanf(tmp, "\"%u.%u.%u.%u\"", &ipv4_1, &ipv4_2, &ipv4_3, &ipv4_4) == 4) {
            char *tmp2;
            char *tmp3;

            /* Skip leading " */
            tmp++;
            tmp2=strstr(tmp,"\"");
            tmp3=g_strndup(tmp,tmp2-tmp);
            if (!str_to_ip(tmp3, &ip4_addr)) {
                g_free(tmp3);
                expert_add_info(pinfo, ti, &ei_rtsp_bad_server_ip_address);
                return;
            }
            set_address(&dst_addr, AT_IPv4, 4, &ip4_addr);
            g_free(tmp3);
        }
        else
        {
            expert_add_info(pinfo, ti, &ei_rtsp_bad_server_port);
            return;
        }
    }


    /* Look for client port */
    if ((tmp = strstr(buf, rtsp_cps_server_port))) {
        tmp += strlen(rtsp_cps_server_port);
        if (sscanf(tmp, "%u-%u", &c_data_port, &c_mon_port) < 1) {
            expert_add_info(pinfo, ti, &ei_rtsp_bad_client_port);
            return;
        }
    }
    else if ((tmp = strstr(buf, rtsp_cps_src_addr))) {
        tmp += strlen(rtsp_cps_src_addr);
        if (sscanf(tmp, "\"%u.%u.%u.%u:%u\"", &ipv4_1, &ipv4_2, &ipv4_3, &ipv4_4, &c_data_port) == 5) {
            char *tmp2;
            char *tmp3;

            /* Skip leading " */
            tmp++;
            tmp2=strstr(tmp,":");
            tmp3=g_strndup(tmp,tmp2-tmp);
            if (!str_to_ip(tmp3, &ip4_addr)) {
                g_free(tmp3);
                expert_add_info(pinfo, ti, &ei_rtsp_bad_client_ip_address);
                return;
            }
            set_address(&src_addr, AT_IPv4, 4, &ip4_addr);
            g_free(tmp3);
        }
    }

    if (setup_info && setup_info->base_uri) {
        rtp_dyn_payload = sdp_get_rtsp_media_desc(setup_info->base_uri);
    }

    /* Deal with RTSP TCP-interleaved conversations. */
    tmp = strstr(buf, rtsp_inter);
    if (tmp != NULL) {
        rtsp_conversation_data_t    *data;
        unsigned            s_data_chan, s_mon_chan;
        int             i;

        /* Move tmp to beyond interleaved string */
        tmp += strlen(rtsp_inter);
        /* Look for channel number(s) */
        i = sscanf(tmp, "%u-%u", &s_data_chan, &s_mon_chan);
        if (i < 1)
        {
            expert_add_info(pinfo, ti, &ei_rtsp_bad_interleaved_channel);
            return;
        }

        /* At least data channel present, look for conversation (presumably TCP) */
        data = get_rtsp_conversation_data(NULL, pinfo);

        /* XXX - This doesn't set up the rtp conversation data, including RTP
         * dynamic payload types and setup info. Two possible approaches:
         * 1) The RTP dissector have a function that attaches dynamic payload
         *    type and setup info to the TCP conversation but does *not* set
         *    the conversation dissector (TCP needs to call the RTSP dissector
         *    first for interleaved data).
         * 2) Define a CONVERSATION_RTSP type and change the RTP dissector to
         *    do something other than only look for conversations that match
         *    conversation_pt_to_conversation_type(pinfo->ptype).
         *
         * The former needs to attach a "bundled" rtp_dyn_payload_t that
         * includes mapping for the payload types of all possible channels;
         * this usually happens when RTSP is used because the media descriptor
         * port is usually 0, but we'd want to ensure it. (It also would not
         * work if multiple sessions were SETUP simultaneously and media
         * descriptors with different meanings for the same RTP dynamic payload
         * type were PLAYed on different interleaved channels simulateously.)
         */

        /* Now set the dissector handle of the interleaved channel
           according to the transport protocol used */
        if (rtp_tcp_transport)
        {
            if (s_data_chan < RTSP_MAX_INTERLEAVED) {
                data->interleaved[s_data_chan].dissector =
                    rtp_handle;
            }
            if (i > 1 && s_mon_chan < RTSP_MAX_INTERLEAVED) {
                data->interleaved[s_mon_chan].dissector =
                    rtcp_handle;
            }
        }
        else if (rdt_transport)
        {
            if (s_data_chan < RTSP_MAX_INTERLEAVED) {
                data->interleaved[s_data_chan].dissector =
                    rdt_handle;
            }
        }
        return;
    }

    /* Noninterleaved options follow */
    /*
     * We only want to match on the destination address, not the
     * source address, because the server might send back a packet
     * from an address other than the address to which its client
     * sent the packet, so we construct a conversation with no
     * second address.
     */
    else if (rtp_udp_transport)
    {
        /* RTP only if indicated */
        if (c_data_port)
        {
            srtp_add_address(pinfo, PT_UDP, &dst_addr, c_data_port, s_data_port,
                            "RTSP", pinfo->num, is_video, rtp_dyn_payload, NULL, setup_info);
        }
        else if (s_data_port)
        {
            srtp_add_address(pinfo, PT_UDP, &src_addr, s_data_port, 0,
                            "RTSP", pinfo->num, is_video, rtp_dyn_payload, NULL, setup_info);
        }

        /* RTCP only if indicated */
        if (c_mon_port)
        {
            rtcp_add_address(pinfo, &pinfo->dst, c_mon_port, s_mon_port,
                             "RTSP", pinfo->num);
        }
    }
    else if (rtp_tcp_transport)
    {
        /* RTP only if indicated */
        srtp_add_address(pinfo, PT_TCP, &src_addr, c_data_port, s_data_port,
                        "RTSP", pinfo->num, is_video, rtp_dyn_payload, NULL, setup_info);
    }
    else if (rdt_transport)
    {
        /* Real Data Transport */
        rdt_add_address(pinfo, &pinfo->dst, c_data_port, s_data_port,
                        "RTSP", rdt_feature_level);
    }
    return;
}

static const char rtsp_content_length[] = "Content-Length:";

static int
rtsp_get_content_length(const unsigned char *line_begin, size_t line_len)
{
    char  buf[256];
    char *tmp;
    int32_t content_length;
    const char *p;
    const char *up;

    if (line_len > sizeof(buf) - 1) {
        /*
         * Don't overflow the buffer.
         */
        line_len = sizeof(buf) - 1;
    }
    memcpy(buf, line_begin, line_len);
    buf[line_len] = '\0';

    tmp = buf + STRLEN_CONST(rtsp_content_length);
    while (*tmp && g_ascii_isspace(*tmp))
        tmp++;
    ws_strtoi32(tmp, &p, &content_length);
    up = p;
    if (up == tmp || (*up != '\0' && !g_ascii_isspace(*up)))
        return -1;  /* not a valid number */
    return content_length;
}

static const char rtsp_Session[] = "Session:";
static const char rtsp_X_Vig_Msisdn[] = "X-Vig-Msisdn";

static int
dissect_rtspmessage(tvbuff_t *tvb, int offset, packet_info *pinfo,
    proto_tree *tree)
{
    proto_tree   *rtsp_tree = NULL;
    proto_tree   *req_tree  = NULL;
    proto_tree   *sub_tree  = NULL;
    proto_item   *ti_top    = NULL;
    proto_item   *ti        = NULL;
    const unsigned char *line;
    int           next_offset;
    const unsigned char *linep, *lineend;
    int           orig_offset;
    int           first_linelen, linelen;
    int           line_end_offset;
    int           colon_offset;
    bool          is_request_or_reply;
    bool          body_requires_content_len;
    bool          saw_req_resp_or_header;
    unsigned char c;
    rtsp_type_t   rtsp_type_packet;
    rtsp_type_t   rtsp_type_line;
    bool          is_header;
    int           datalen;
    int           content_length;
    int           reported_datalen;
    int           value_offset;
    int           value_len;
    e164_info_t   e164_info;
    int           rdt_feature_level = 0;
    char         *media_type_str_lower_case = NULL;
    int           semi_colon_offset;
    int           par_end_offset;
    char         *frame_label = NULL;
    char         *session_id  = NULL;
    voip_packet_info_t *stat_info = NULL;
    bool          cseq_valid = false;
    uint32_t      cseq = 0;
    char         *content_base = NULL;
    char         *content_location = NULL;
    char         *request_uri = NULL;
    char         *base_uri = NULL;
    const char   *transport_line = NULL;
    int           transport_linelen;
    sdp_setup_info_t *setup_info = NULL;
    rtsp_info_value_t *rtsp_stat_info;

    rtsp_stat_info = wmem_new(pinfo->pool, rtsp_info_value_t);
    rtsp_stat_info->framenum = pinfo->num;
    rtsp_stat_info->response_code = 0;
    rtsp_stat_info->request_method = NULL;
    rtsp_stat_info->request_uri = NULL;
    rtsp_stat_info->rtsp_host = NULL;

    /*
     * Is this a request or response?
     *
     * Note that "tvb_find_line_end()" will return a value that
     * is not longer than what's in the buffer, so the
     * "tvb_get_ptr()" call won't throw an exception.
     */
    first_linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, false);

    /*
     * Is the first line a request or response?
     */
    line = tvb_get_ptr(tvb, offset, first_linelen);
    is_request_or_reply = is_rtsp_request_or_reply(line, first_linelen,
        &rtsp_type_packet, rtsp_stat_info, pinfo->pool);
    if (is_request_or_reply) {
        /*
         * Yes, it's a request or response.
         * Do header desegmentation if we've been told to,
         * and do body desegmentation if we've been told to and
         * we find a Content-Length header.
         *
         * RFC 7826, Section 18.17. requires Content-Length and
         * assumes zero if missing.
         */
        if (!req_resp_hdrs_do_reassembly(tvb, offset, pinfo,
            rtsp_desegment_headers, rtsp_desegment_body, false, NULL,
            NULL, NULL)) {
            /*
             * More data needed for desegmentation.
             */
            return -1;
        }
    }

    /*
     * RFC 2326 says that a content length must be specified
     * in requests that have a body, although section 4.4 speaks
     * of a server closing the connection indicating the end of
     * a reply body.
     *
     * To support pipelining, we check if line behind blank line
     * looks like RTSP header. If so, we process rest of packet with
     * RTSP loop.
     *
     * If no, we assume that an absent content length in a request means
     * that we don't have a body, and that an absent content length
     * in a reply means that the reply body runs to the end of
     * the connection.  If the first line is neither, we assume
     * that whatever follows a blank line should be treated as a
     * body; there's not much else we can do, as we're jumping
     * into the message in the middle.
     *
     * XXX - if there was no Content-Length entity header, we should
     * accumulate all data until the end of the connection.
     * That'd require that the TCP dissector call subdissectors
     * for all frames with FIN, even if they contain no data,
     * which would require subdissectors to deal intelligently
     * with empty segments.
     */
    if (rtsp_type_packet == RTSP_REQUEST)
        body_requires_content_len = true;
    else
        body_requires_content_len = false;

    line = tvb_get_ptr(tvb, offset, first_linelen);
    if (is_request_or_reply) {
        if ( rtsp_type_packet == RTSP_REPLY ) {
            frame_label = wmem_strdup_printf(pinfo->pool,
                  "Reply: %s", format_text(pinfo->pool, line, first_linelen));
        }
        else {
            frame_label = format_text(pinfo->pool, line, first_linelen);
        }
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTSP");
    /*
        * Put the first line from the buffer into the summary
        * if it's an RTSP request or reply (but leave out the
        * line terminator).
        * Otherwise, just call it a continuation.
        *
        * Note that "tvb_find_line_end()" will return a value that
        * is not longer than what's in the buffer, so the
        * "tvb_get_ptr()" call won't throw an exception.
        */
    if (is_request_or_reply)
        if ( rtsp_type_packet == RTSP_REPLY ) {
            col_set_str(pinfo->cinfo, COL_INFO, "Reply: ");
            col_append_str(pinfo->cinfo, COL_INFO,
                format_text(pinfo->pool, line, first_linelen));
        }
        else {
            col_add_str(pinfo->cinfo, COL_INFO,
                format_text(pinfo->pool, line, first_linelen));
        }

    else
        col_set_str(pinfo->cinfo, COL_INFO, "Continuation");

    orig_offset = offset;
    if (tree) {
        ti_top = proto_tree_add_item(tree, proto_rtsp, tvb, offset, -1,
                                     ENC_NA);
        rtsp_tree = proto_item_add_subtree(ti_top, ett_rtsp);
    }

    /*
     * We haven't yet seen a Content-Length header.
     */
    content_length = -1;

    /*
     * Process the packet data, a line at a time.
     */
    saw_req_resp_or_header = false; /* haven't seen anything yet */
    while (tvb_offset_exists(tvb, offset)) {
        /*
         * We haven't yet concluded that this is a header.
         */
        is_header = false;

        /*
         * Find the end of the line.
         */
        linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, false);
        if (linelen < 0)
            return -1;
        line_end_offset = offset + linelen;
        /*
         * colon_offset may be -1
         */
        colon_offset = tvb_find_uint8(tvb, offset, linelen, ':');


        /*
         * Get a buffer that refers to the line.
         */
        line = tvb_get_ptr(tvb, offset, linelen);
        lineend = line + linelen;

        /*
         * OK, does it look like an RTSP request or response?
         */
        is_request_or_reply = is_rtsp_request_or_reply(line, linelen, &rtsp_type_line,
            rtsp_stat_info, pinfo->pool);
        if (is_request_or_reply)
            goto is_rtsp;

        /*
         * No.  Does it look like a blank line (as would appear
         * at the end of an RTSP request)?
         */
        if (linelen == 0)
            goto is_rtsp;   /* Yes. */

        /*
         * No.  Does it look like a header?
         */
        linep = line;
        while (linep < lineend) {
            c = *linep++;

            /*
             * This must be a CHAR, and must not be a CTL, to be part
             * of a token; that means it must be printable ASCII.
             *
             * XXX - what about leading LWS on continuation
             * lines of a header?
             */
            if (!g_ascii_isprint(c))
                break;

            switch (c) {

            case '(':
            case ')':
            case '<':
            case '>':
            case '@':
            case ',':
            case ';':
            case '\\':
            case '"':
            case '/':
            case '[':
            case ']':
            case '?':
            case '=':
            case '{':
            case '}':
                /*
                 * It's a tspecial, so it's not
                 * part of a token, so it's not
                 * a field name for the beginning
                 * of a header.
                 */
                goto not_rtsp;

            case ':':
                /*
                 * This ends the token; we consider
                 * this to be a header.
                 */
                is_header = true;
                goto is_rtsp;

            case ' ':
            case '\t':
                /*
                 * LWS (RFC-2616, 4.2); continue the previous
                 * header.
                 */
                goto is_rtsp;
            }
        }

        /*
         * We haven't seen the colon, but everything else looks
         * OK for a header line.
         *
         * If we've already seen an RTSP request or response
         * line, or a header line, and we're at the end of
         * the tvbuff, we assume this is an incomplete header
         * line.  (We quit this loop after seeing a blank line,
         * so if we've seen a request or response line, or a
         * header line, this is probably more of the request
         * or response we're presumably seeing.  There is some
         * risk of false positives, but the same applies for
         * full request or response lines or header lines,
         * although that's less likely.)
         *
         * We throw an exception in that case, by checking for
         * the existence of the next byte after the last one
         * in the line.  If it exists, "tvb_ensure_bytes_exist()"
         * throws no exception, and we fall through to the
         * "not RTSP" case.  If it doesn't exist,
         * "tvb_ensure_bytes_exist()" will throw the appropriate
         * exception.
         */
        if (saw_req_resp_or_header)
            tvb_ensure_bytes_exist(tvb, offset, linelen + 1);

    not_rtsp:
        /*
         * We don't consider this part of an RTSP request or
         * reply, so we don't display it.
         */
        break;

    is_rtsp:
        /*
         * Process this line.
         */
        if (linelen == 0) {
            /*
             * This is a blank line, which means that
             * whatever follows it isn't part of this
             * request or reply.
             */
            proto_tree_add_format_text(rtsp_tree, tvb, offset, next_offset - offset);
            offset = next_offset;
            break;
        }

        /*
         * Not a blank line - either a request, a reply, or a header
         * line.
         */
        saw_req_resp_or_header = true;

        switch (rtsp_type_line)
        {
            case RTSP_REQUEST:
                /* Add a tree for this request */
                ti = proto_tree_add_string(rtsp_tree, hf_rtsp_request, tvb, offset,
                                          (int) (next_offset - offset),
                                          tvb_format_text(pinfo->pool, tvb, offset, (int) (next_offset - offset)));
                req_tree = proto_item_add_subtree(ti, ett_rtsp_method);
                request_uri = process_rtsp_request(tvb, offset, line, linelen, pinfo, req_tree);
                break;

            case RTSP_REPLY:
                /* Add a tree for this response */
                ti = proto_tree_add_string(rtsp_tree, hf_rtsp_response, tvb, offset,
                                           (int) (next_offset - offset),
                                           tvb_format_text(pinfo->pool, tvb, offset, (int) (next_offset - offset)));
                req_tree = proto_item_add_subtree(ti, ett_rtsp_method);
                process_rtsp_reply(tvb, offset, line, linelen, pinfo, req_tree);
                break;

            case RTSP_NOT_FIRST_LINE:
                /* Drop through, it may well be a header line */
                break;
        }

        if (is_header)
        {
            /* We know that colon_offset must be set */

            /* Skip whitespace after the colon. */
            value_offset = colon_offset + 1;
            while ((value_offset < line_end_offset) &&
                   ((c = tvb_get_uint8(tvb, value_offset)) == ' ' || c == '\t'))
            {
                value_offset++;
            }
            value_len = line_end_offset - value_offset;

            /*
             * Process some headers specially.
             */
#define HDR_MATCHES(header) \
    ( (size_t)linelen > STRLEN_CONST(header) && \
     g_ascii_strncasecmp(line, (header), STRLEN_CONST(header)) == 0)

            if (HDR_MATCHES(rtsp_transport))
            {
                ti = proto_tree_add_string(rtsp_tree, hf_rtsp_transport, tvb,
                                           offset, linelen,
                                           tvb_format_text(pinfo->pool, tvb, value_offset,
                                                           value_len));

                /* Setup the conversation after parsing all the headers. */
                transport_line = line;
                transport_linelen = linelen;
            } else if (HDR_MATCHES(rtsp_content_type))
            {
                proto_tree_add_string(rtsp_tree, hf_rtsp_content_type,
                                      tvb, offset, linelen,
                                      tvb_format_text(pinfo->pool, tvb, value_offset,
                                                      value_len));

                offset = offset + (int)STRLEN_CONST(rtsp_content_type);
                /* Skip wsp */
                offset = tvb_skip_wsp(tvb, offset, value_len);
                semi_colon_offset = tvb_find_uint8(tvb, value_offset, value_len, ';');
                if ( semi_colon_offset != -1) {
                    /* m-parameter present */
                    par_end_offset = tvb_skip_wsp_return(tvb, semi_colon_offset-1);
                    value_len = par_end_offset - offset;
                }

                media_type_str_lower_case = ascii_strdown_inplace(
                    (char *)tvb_get_string_enc(pinfo->pool, tvb, offset, value_len, ENC_ASCII));
            } else if (HDR_MATCHES(rtsp_content_length))
            {
                uint32_t clength;
                bool clength_valid;
                clength_valid = ws_strtou32(tvb_format_text(pinfo->pool, tvb, value_offset, value_len),
                    NULL, &clength);
                ti = proto_tree_add_uint(rtsp_tree, hf_rtsp_content_length,
                                    tvb, offset, linelen, clength);
                if (!clength_valid)
                    expert_add_info(pinfo, ti, &ei_rtsp_content_length_invalid);

                /*
                 * Only the amount specified by the
                 * Content-Length: header should be treated
                 * as payload.
                 */
                content_length = rtsp_get_content_length(line, linelen);

            } else if (HDR_MATCHES(rtsp_Session))
            {
                session_id = tvb_format_text(pinfo->pool, tvb, value_offset, value_len);
                /* Put the value into the protocol tree */
                proto_tree_add_string(rtsp_tree, hf_rtsp_session, tvb,
                                      offset, linelen,
                                      session_id);

            } else if (HDR_MATCHES(rtsp_X_Vig_Msisdn)) {
                /*
                 * Extract the X_Vig_Msisdn string
                 */
                if (colon_offset != -1)
                {
                    /* Put the value into the protocol tree */
                    ti = proto_tree_add_string(rtsp_tree, hf_rtsp_X_Vig_Msisdn,tvb,
                                               offset, linelen ,
                                               tvb_format_text(pinfo->pool, tvb, value_offset, value_len));
                    sub_tree = proto_item_add_subtree(ti, ett_rtsp_method);

                    e164_info.e164_number_type = CALLING_PARTY_NUMBER;
                    e164_info.nature_of_address = 0;

                    e164_info.E164_number_str = tvb_get_string_enc(pinfo->pool, tvb, value_offset,
                                                                  value_len, ENC_ASCII);
                    e164_info.E164_number_length = value_len;
                    dissect_e164_number(tvb, sub_tree, value_offset,
                                        value_len, e164_info);
                }
            } else if (HDR_MATCHES(rtsp_rdt_feature_level))
            {
                bool rdt_feature_level_valid;
                rdt_feature_level_valid = ws_strtou32(tvb_format_text(pinfo->pool, tvb, value_offset, value_len),
                    NULL, &rdt_feature_level);
                ti = proto_tree_add_uint(rtsp_tree, hf_rtsp_rdtfeaturelevel,
                tvb, offset, linelen, rdt_feature_level);
                if (!rdt_feature_level_valid)
                    expert_add_info(pinfo, ti, &ei_rtsp_rdtfeaturelevel_invalid);
            } else if (HDR_MATCHES(rtsp_cseq))
            {
                cseq_valid = ws_strtou32(tvb_format_text(pinfo->pool, tvb, value_offset, value_len),
                    NULL, &cseq);
                ti = proto_tree_add_uint(rtsp_tree, hf_rtsp_cseq, tvb, offset, linelen, cseq);
                if (!cseq_valid) {
                    expert_add_info(pinfo, ti, &ei_rtsp_cseq_invalid);
                }
            } else if (HDR_MATCHES(rtsp_content_base))
            {
                content_base = (char *)tvb_get_string_enc(pinfo->pool, tvb, value_offset, value_len, ENC_UTF_8);
                proto_tree_add_string(rtsp_tree, hf_rtsp_content_base,
                                      tvb, offset, linelen, content_base);
            } else if (HDR_MATCHES(rtsp_content_location))
            {
                content_location = (char *)tvb_get_string_enc(pinfo->pool, tvb, value_offset, value_len, ENC_UTF_8);
                proto_tree_add_string(rtsp_tree, hf_rtsp_content_location,
                                      tvb, offset, linelen, content_location);
            }
            else
            {
                /* Default case for headers. Show line as text */
                proto_tree_add_format_text(rtsp_tree, tvb, offset, next_offset - offset);
            }
        }
        else if (rtsp_type_line == RTSP_NOT_FIRST_LINE)
        {
            /* Catch-all for all other lines... Show line as text.
               TODO: should these be shown as errors? */
            proto_tree_add_format_text(rtsp_tree, tvb, offset, next_offset - offset);
        }

        offset = next_offset;
    }

    if (cseq_valid) {
        rtsp_conversation_data_t *conv_data = get_rtsp_conversation_data(NULL, pinfo);
        rtsp_req_resp_t *curr_req_resp = wmem_map_lookup(conv_data->req_resp_map, GUINT_TO_POINTER(cseq));
        if (!curr_req_resp) {
            curr_req_resp = wmem_new0(wmem_file_scope(), rtsp_req_resp_t);
            wmem_map_insert(conv_data->req_resp_map, GUINT_TO_POINTER(cseq), curr_req_resp);
        }
        if (rtsp_type_packet == RTSP_REQUEST) {
            if (curr_req_resp->req_frame == 0) {
                curr_req_resp->req_frame = pinfo->num;
            }
            if (curr_req_resp->resp_frame) {
                proto_tree_add_uint(req_tree, hf_rtsp_response_in, tvb, 0, 0, curr_req_resp->resp_frame);
            }
            if (request_uri && !curr_req_resp->request_uri) {
                curr_req_resp->request_uri = wmem_strdup(wmem_file_scope(), request_uri);
            }
        } else {
            if (curr_req_resp->resp_frame == 0) {
                curr_req_resp->resp_frame = pinfo->num;
            }
            if (curr_req_resp->request_uri) {
                ti = proto_tree_add_string(req_tree, hf_rtsp_url, tvb, 0, 0, curr_req_resp->request_uri);
                proto_item_set_generated(ti);
            }
            if (curr_req_resp->req_frame) {
                proto_tree_add_uint(req_tree, hf_rtsp_response_to, tvb, 0, 0, curr_req_resp->req_frame);
            }
        }
        if (curr_req_resp->request_uri) {
            base_uri = wmem_ascii_strdown(pinfo->pool, curr_req_resp->request_uri, -1);
        }
    }

    if (content_base) {
        base_uri = content_base;
    } else if (content_location) {
        /* XXX - Content-Location itself can be relative to the request_uri, at
         * least according to RFC 7826. (RTSP 2.0 is not widely implemented, but
         * it does have useful notes on gotchas and limitations of RTSP 1.0.)
         */
        base_uri = content_location;
    }

    if (session_id) {
        stat_info = wmem_new0(pinfo->pool, voip_packet_info_t);
        stat_info->protocol_name = wmem_strdup(pinfo->pool, "RTSP");
        stat_info->call_id = session_id;
        stat_info->frame_label = frame_label;
        stat_info->call_state = VOIP_CALL_SETUP;
        stat_info->call_active_state = VOIP_ACTIVE;
        stat_info->frame_comment = frame_label;
        tap_queue_packet(voip_tap, pinfo, stat_info);
    }

    if (transport_line) {
        /*
         * Based on the port numbers specified in the Transport: header, set up
         * a conversation that will be dissected with the appropriate dissector.
         */
        setup_info = rtsp_create_setup_info(pinfo, session_id, base_uri);
        rtsp_create_conversation(pinfo, ti, transport_line, transport_linelen, rdt_feature_level, rtsp_type_packet, setup_info);
    }

    /*
     * Have now read all of the lines of this message.
     *
     * If a content length was supplied, the amount of data to be
     * processed as RTSP payload is the minimum of the content
     * length and the amount of data remaining in the frame.
     *
     * If no content length was supplied (or if a bad content length
     * was supplied), the amount of data to be processed is the amount
     * of data remaining in the frame.
     */
    datalen = tvb_captured_length_remaining(tvb, offset);
    reported_datalen = tvb_reported_length_remaining(tvb, offset);
    if (content_length != -1) {
        /*
         * Content length specified; display only that amount
         * as payload.
         */
        if (datalen > content_length)
            datalen = content_length;

        /*
         * XXX - limit the reported length in the tvbuff we'll
         * hand to a subdissector to be no greater than the
         * content length.
         *
         * We really need both unreassembled and "how long it'd
         * be if it were reassembled" lengths for tvbuffs, so
         * that we throw the appropriate exceptions for
         * "not enough data captured" (running past the length),
         * "packet needed reassembly" (within the length but
         * running past the unreassembled length), and
         * "packet is malformed" (running past the reassembled
         * length).
         */
        if (reported_datalen > content_length)
            reported_datalen = content_length;
    } else {
        /*
         * No content length specified; if this message doesn't
         * have a body if no content length is specified, process
         * nothing as payload.
         */
        if (body_requires_content_len)
            datalen = 0;
    }

    if (datalen > 0) {
        /*
         * There's stuff left over; process it.
         */
        tvbuff_t *new_tvb;

        /*
         * Now create a tvbuff for the Content-type stuff and
         * dissect it.
         *
         * The amount of data to be processed that's
         * available in the tvbuff is "datalen", which
         * is the minimum of the amount of data left in
         * the tvbuff and any specified content length.
         *
         * The amount of data to be processed that's in
         * this frame, regardless of whether it was
         * captured or not, is "reported_datalen",
         * which, if no content length was specified,
         * is -1, i.e. "to the end of the frame.
         */
        new_tvb = tvb_new_subset_length_caplen(tvb, offset, datalen,
                reported_datalen);

        /*
         * Check if next line is RTSP message - pipelining
         * If yes, stop processing and start next loop
         * If no, process rest of packet with dissectors
         */
        first_linelen = tvb_find_line_end(new_tvb, 0, -1, &next_offset, false);
        line = tvb_get_ptr(new_tvb, 0, first_linelen);
        is_request_or_reply = is_rtsp_request_or_reply(line, first_linelen,
            &rtsp_type_packet, rtsp_stat_info, pinfo->pool);

        if (!is_request_or_reply){
            setup_info = rtsp_create_setup_info(pinfo, session_id, base_uri);
            media_content_info_t content_info = { MEDIA_CONTAINER_SIP_DATA, media_type_str_lower_case, NULL, setup_info };
            if (media_type_str_lower_case &&
                dissector_try_string_with_data(media_type_dissector_table,
                    media_type_str_lower_case,
                    new_tvb, pinfo, rtsp_tree, true, &content_info)) {

            } else {
                /*
                 * Fix up the top-level item so that it doesn't
                 * include the SDP stuff.
                 */
                if (ti_top != NULL)
                    proto_item_set_len(ti_top, offset);

                if (tvb_get_uint8(tvb, offset) == RTSP_FRAMEHDR) {
                    /*
                     * This is interleaved stuff; don't
                     * treat it as raw data - set "datalen"
                     * to 0, so we won't skip the offset
                     * past it, which will cause our
                     * caller to process that stuff itself.
                     */
                    datalen = 0;
                } else {
                    proto_tree_add_bytes_format(rtsp_tree, hf_rtsp_data, tvb, offset,
                        datalen, NULL, "Data (%d bytes)",
                        reported_datalen);
                }
            }

            /*
             * We've processed "datalen" bytes worth of data
             * (which may be no data at all); advance the
             * offset past whatever data we've processed.
             */
            offset += datalen;
        }
    }

    tap_queue_packet(rtsp_tap, pinfo, rtsp_stat_info);

    return offset - orig_offset;
}

static char*
process_rtsp_request(tvbuff_t *tvb, int offset, const unsigned char *data,
                     size_t linelen, packet_info *pinfo, proto_tree *tree)
{
    const unsigned char *lineend  = data + linelen;
    unsigned     ii;
    const unsigned char *url;
    const unsigned char *url_start;
    unsigned char       *tmp_url;

    /* Request Methods */
    for (ii = 0; ii < RTSP_NMETHODS; ii++) {
        size_t len = strlen(rtsp_methods[ii]);
        if (linelen >= len &&
            g_ascii_strncasecmp(rtsp_methods[ii], data, len) == 0 &&
            (len == linelen || g_ascii_isspace(data[len])))
            break;
    }
    if (ii == RTSP_NMETHODS) {
        /*
         * We got here because "is_rtsp_request_or_reply()" returned
         * RTSP_REQUEST, so we know one of the request methods
         * matched, so we "can't get here".
         */
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    /* Add method name to tree */
    proto_tree_add_string(tree, hf_rtsp_method, tvb, offset,
                          (int) strlen(rtsp_methods[ii]), rtsp_methods[ii]);

    /* URL */
    url = data;
    /* Skip method name again */
    while (url < lineend && !g_ascii_isspace(*url))
        url++;
    /* Skip spaces */
    while (url < lineend && g_ascii_isspace(*url))
        url++;
    /* URL starts here */
    url_start = url;
    /* Scan to end of URL */
    while (url < lineend && !g_ascii_isspace(*url))
        url++;
    /* Create a URL-sized buffer and copy contents */
    tmp_url = format_text(pinfo->pool, url_start, url - url_start);

    /* Add URL to tree */
    proto_tree_add_string(tree, hf_rtsp_url, tvb,
                          offset + (int) (url_start - data), (int) (url - url_start), tmp_url);
    return tmp_url;
}

/* Read first line of a reply message */
static void
process_rtsp_reply(tvbuff_t *tvb, int offset, const unsigned char *data,
    size_t linelen, packet_info *pinfo _U_, proto_tree *tree)
{
    const unsigned char *lineend  = data + linelen;
    const unsigned char *status   = data;
    const unsigned char *status_start;
    unsigned      status_i;

    /* status code */

    /* Skip protocol/version */
    while (status < lineend && !g_ascii_isspace(*status))
        status++;
    /* Skip spaces */
    while (status < lineend && g_ascii_isspace(*status))
        status++;

    /* Actual code number now */
    status_start = status;
    status_i = 0;
    while (status < lineend && g_ascii_isdigit(*status))
        status_i = status_i * 10 + *status++ - '0';

    /* Add field to tree */
    proto_tree_add_uint(tree, hf_rtsp_status, tvb,
                        offset + (int) (status_start - data),
                        (int) (status - status_start), status_i);
}

static int
dissect_rtsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    int offset = 0;
    int len;

    while (tvb_reported_length_remaining(tvb, offset) != 0) {
        /*
         * Add separator between multiple messages in column info text
         */
        if (offset > 0) {
                col_set_str(pinfo->cinfo, COL_INFO, ", ");
                col_set_fence(pinfo->cinfo, COL_INFO);
        }
        len = (tvb_get_uint8(tvb, offset) == RTSP_FRAMEHDR)
            ? dissect_rtspinterleaved(tvb, offset, pinfo, tree)
            : dissect_rtspmessage(tvb, offset, pinfo, tree);
        if (len == -1)
            break;
        offset += len;

        /*
         * OK, we've set the Protocol and Info columns for the
         * first RTSP message; set fence so changes are kept for
         * subsequent RTSP messages.
         */
        col_set_fence(pinfo->cinfo, COL_INFO);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_rtsp(void)
{
    static int *ett[] = {
        &ett_rtspframe,
        &ett_rtsp,
        &ett_rtsp_method,
    };
    static hf_register_info hf[] = {
        { &hf_rtsp_request,
            { "Request", "rtsp.request", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_response,
            { "Response", "rtsp.response", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_response_in,
            { "Response in frame", "rtsp.response_in", FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0, NULL, HFILL }},
        { &hf_rtsp_response_to,
            { "Response to frame", "rtsp.response_to", FT_FRAMENUM, BASE_NONE,
            FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0, NULL, HFILL }},
        { &hf_rtsp_method,
            { "Method", "rtsp.method", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_content_type,
            { "Content-type", "rtsp.content-type", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_content_length,
            { "Content-length", "rtsp.content-length", FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_url,
            { "URL", "rtsp.url", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_status,
            { "Status", "rtsp.status", FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_session,
            { "Session", "rtsp.session", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_transport,
            { "Transport", "rtsp.transport", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_rdtfeaturelevel,
            { "RDTFeatureLevel", "rtsp.rdt-feature-level", FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_cseq,
            { "CSeq", "rtsp.cseq", FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_content_base,
            { "Content-Base", "rtsp.content-base", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_content_location,
            { "Content-Location", "rtsp.content-location", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_X_Vig_Msisdn,
            { "X-Vig-Msisdn", "rtsp.X_Vig_Msisdn", FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_rtsp_magic,
            { "Magic", "rtsp.magic", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_rtsp_channel,
            { "Channel", "rtsp.channel", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},
        { &hf_rtsp_length,
            { "Length", "rtsp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},
        { &hf_rtsp_data,
            { "Data", "rtsp.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},
    };

    static ei_register_info ei[] = {
        { &ei_rtsp_unknown_transport_type,
          { "rtsp.unknown_transport_type", PI_UNDECODED, PI_WARN, "Unknown transport type",  EXPFILL }},
        { &ei_rtsp_bad_server_port,
          { "rtsp.bad_server_port", PI_UNDECODED, PI_WARN, "Bad server_port",  EXPFILL }},
        { &ei_rtsp_bad_client_port,
          { "rtsp.bad_client_port", PI_UNDECODED, PI_WARN, "Bad client port",  EXPFILL }},
        { &ei_rtsp_bad_interleaved_channel,
          { "rtsp.bad_interleaved_channel", PI_UNDECODED, PI_WARN, "Bad interleaved_channel",  EXPFILL }},
        { &ei_rtsp_content_length_invalid,
          { "rtsp.content-length.invalid", PI_MALFORMED, PI_ERROR, "Invalid content length", EXPFILL }},
        { &ei_rtsp_rdtfeaturelevel_invalid,
          { "rtsp.rdt-feature-level.invalid", PI_MALFORMED, PI_ERROR, "Invalid RDTFeatureLevel", EXPFILL }},
        { &ei_rtsp_cseq_invalid,
          { "rtsp.cseq.invalid", PI_PROTOCOL, PI_WARN, "Invalid CSeq", EXPFILL }},
        { &ei_rtsp_bad_server_ip_address,
          { "rtsp.bad_server_ip_address", PI_MALFORMED, PI_ERROR, "Bad server IP address", EXPFILL }},
        { &ei_rtsp_bad_client_ip_address,
          { "rtsp.bad_client_ip_address", PI_MALFORMED, PI_ERROR, "Bad client IP address", EXPFILL }}
    };

    module_t *rtsp_module;
    expert_module_t *expert_rtsp;

    proto_rtsp = proto_register_protocol("Real Time Streaming Protocol", "RTSP", "rtsp");

    proto_register_field_array(proto_rtsp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_rtsp = expert_register_protocol(proto_rtsp);
    expert_register_field_array(expert_rtsp, ei, array_length(ei));

    /* Make this dissector findable by name */
    rtsp_handle = register_dissector("rtsp", dissect_rtsp, proto_rtsp);

    /* Register our configuration options, particularly our ports */

    rtsp_module = prefs_register_protocol(proto_rtsp, NULL);

    prefs_register_obsolete_preference(rtsp_module, "tcp.alternate_port");

    prefs_register_bool_preference(rtsp_module, "desegment_headers",
        "Reassemble RTSP headers spanning multiple TCP segments",
        "Whether the RTSP dissector should reassemble headers "
        "of a request spanning multiple TCP segments. "
        " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
        &rtsp_desegment_headers);
    prefs_register_bool_preference(rtsp_module, "desegment_body",
        "Trust the \"Content-length:\" header when desegmenting",
        "Whether the RTSP dissector should use the "
        "\"Content-length:\" value to desegment the body "
        "of a request spanning multiple TCP segments",
        &rtsp_desegment_body);

    /*
     * Heuristic dissectors SHOULD register themselves in
     * this table using the standard heur_dissector_add()
     * function.
     */
    heur_subdissector_list = register_heur_dissector_list_with_description("rtsp", "RTSP data", proto_rtsp);

    /*
     * Register for tapping
     */
    rtsp_tap = register_tap("rtsp"); /* RTSP statistics tap */

    register_external_value_string("rtsp_status_code_vals", rtsp_status_code_vals);
}

void
proto_reg_handoff_rtsp(void)
{
    rtp_handle = find_dissector_add_dependency("rtp", proto_rtsp);
    rtp_rfc4571_handle = find_dissector_add_dependency("rtp.rfc4571", proto_rtsp);
    rtcp_handle = find_dissector_add_dependency("rtcp", proto_rtsp);
    rdt_handle = find_dissector_add_dependency("rdt", proto_rtsp);
    media_type_dissector_table = find_dissector_table("media_type");
    voip_tap = find_tap_id("voip");

    /* Set our port number for future use */
    dissector_add_uint_range_with_preference("tcp.port", RTSP_TCP_PORT_RANGE, rtsp_handle);

    /* XXX: Do the following only once ?? */
    stats_tree_register("rtsp","rtsp","RTSP" STATS_TREE_MENU_SEPARATOR "Packet Counter", 0, rtsp_stats_tree_packet, rtsp_stats_tree_init, NULL );

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: space
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
