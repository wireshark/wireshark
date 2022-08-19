/* packet-rtpproxy.c
 * RTPproxy command protocol dissector
 * Copyright 2013, Peter Lemenkov <lemenkov@gmail.com>
 *
 * This dissector tries to dissect rtpproxy control protocol. Please visit this
 * link for brief details on the command format:
 *
 * http://www.rtpproxy.org/wiki/RTPproxy/Protocol
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/rtp_pt.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>

/* For setting up RTP/RTCP dissectors based on the RTPproxy's answers */
#include "packet-rtp.h"
#include "packet-rtcp.h"

void proto_register_rtpproxy(void);

static dissector_handle_t rtpproxy_handle;

static int proto_rtpproxy = -1;

static int hf_rtpproxy_cookie = -1;
static int hf_rtpproxy_error = -1;
static int hf_rtpproxy_status = -1;
static int hf_rtpproxy_ok = -1;
static int hf_rtpproxy_ipv4 = -1;
static int hf_rtpproxy_ipv6 = -1;
static int hf_rtpproxy_port = -1;
static int hf_rtpproxy_lf = -1;
static int hf_rtpproxy_request = -1;
static int hf_rtpproxy_command = -1;
static int hf_rtpproxy_command_parameters = -1;
static int hf_rtpproxy_command_parameter = -1;
static int hf_rtpproxy_command_parameter_codec = -1;
static int hf_rtpproxy_command_parameter_local_ipv4 = -1;
static int hf_rtpproxy_command_parameter_remote_ipv4 = -1;
static int hf_rtpproxy_command_parameter_repacketize = -1;
static int hf_rtpproxy_command_parameter_dtmf = -1;
/* static int hf_rtpproxy_command_parameter_cmap = -1; TODO */
static int hf_rtpproxy_command_parameter_proto = -1;
static int hf_rtpproxy_command_parameter_transcode = -1;
static int hf_rtpproxy_command_parameter_acc = -1;
static int hf_rtpproxy_callid = -1;
static int hf_rtpproxy_copy_target = -1;
static int hf_rtpproxy_playback_filename = -1;
static int hf_rtpproxy_playback_codec = -1;
static int hf_rtpproxy_notify = -1;
static int hf_rtpproxy_notify_ipv4 = -1;
static int hf_rtpproxy_notify_ipv6 = -1;
static int hf_rtpproxy_notify_port = -1;
static int hf_rtpproxy_notify_tag = -1;
static int hf_rtpproxy_tag = -1;
static int hf_rtpproxy_mediaid = -1;
static int hf_rtpproxy_reply = -1;
static int hf_rtpproxy_version_request = -1;
static int hf_rtpproxy_version_supported = -1;
static int hf_rtpproxy_ng_bencode = -1;

/* Expert fields */
static expert_field ei_rtpproxy_timeout = EI_INIT;
static expert_field ei_rtpproxy_notify_no_ip = EI_INIT;
static expert_field ei_rtpproxy_bad_ipv4 = EI_INIT;
static expert_field ei_rtpproxy_bad_ipv6 = EI_INIT;

/* Request/response tracking */
static int hf_rtpproxy_request_in = -1;
static int hf_rtpproxy_response_in = -1;
static int hf_rtpproxy_response_time = -1;

typedef struct _rtpproxy_info {
    guint32 req_frame;
    guint32 resp_frame;
    nstime_t req_time;
    gchar* callid;
} rtpproxy_info_t;

static dissector_handle_t rtcp_handle;
static dissector_handle_t rtp_events_handle;
static dissector_handle_t rtp_handle;
static dissector_handle_t bencode_handle;

typedef struct _rtpproxy_conv_info {
    wmem_tree_t *trans;
} rtpproxy_conv_info_t;


static const string_string versiontypenames[] = {
    { "20040107", "Basic RTP proxy functionality" },
    { "20050322", "Support for multiple RTP streams and MOH" },
    { "20060704", "Support for extra parameter in the V command" },
    { "20071116", "Support for RTP re-packetization" },
    { "20071218", "Support for forking (copying) RTP stream" },
    { "20080403", "Support for RTP statistics querying" },
    { "20081102", "Support for setting codecs in the update/lookup command" },
    { "20081224", "Support for session timeout notifications" },
    { "20090810", "Support for automatic bridging" },
    { "20140323", "Support for tracking/reporting load" },
    { "20140617", "Support for anchoring session connect time" },
    { "20141004", "Support for extendable performance counters" },
    { "20150330", "Support for allocating a new port (\"Un\"/\"Ln\" commands)" },
    { 0, NULL }
};

static const value_string commandtypenames[] = {
    { 'V', "Handshake/Ping" },
    { 'v', "Handshake/Ping" },
    { 'U', "Offer/Update" },
    { 'u', "Offer/Update" },
    { 'L', "Answer/Lookup" },
    { 'l', "Answer/Lookup" },
    { 'I', "Information"},
    { 'i', "Information"},
    { 'X', "Close all active sessions"},
    { 'x', "Close all active sessions"},
    { 'D', "Delete an active session (Bye/Cancel/Error)"},
    { 'd', "Delete an active session (Bye/Cancel/Error)"},
    { 'P', "Start playback (music-on-hold)"},
    { 'p', "Start playback (music-on-hold)"},
    { 'S', "Stop playback (music-on-hold)"},
    { 's', "Stop playback (music-on-hold)"},
    { 'R', "Start recording"},
    { 'r', "Start recording"},
    { 'C', "Copy stream"},
    { 'c', "Copy stream"},
    { 'Q', "Query info about a session"},
    { 'q', "Query info about a session"},
    { 0, NULL }
};

static const value_string paramtypenames[] = {
    /* Official command parameters */
    {'4', "Remote address is IPv4"},
    {'6', "Remote address is IPv6"},
    {'a', "Asymmetric stream"},
    {'A', "Asymmetric stream"},
    {'b', "Brief stats"},
    {'B', "Brief stats"},
    {'c', "Codecs"},
    {'C', "Codecs"},
    {'e', "External network (non RFC 1918)"},
    {'E', "External network (non RFC 1918)"},
    {'i', "Internal network (RFC 1918)"},
    {'I', "Internal network (RFC 1918)"},
    {'l', "Local address / Load average"},
    {'L', "Local address / Load average"},
    {'n', "request New port"},
    {'N', "request New port"},
    {'r', "Remote address"},
    {'R', "Remote address"},
    {'s', "Symmetric stream / Single file"},
    {'S', "Symmetric stream / Single file"},
    {'w', "Weak connection (allows roaming)"},
    {'W', "Weak connection (allows roaming)"},
    {'z', "repacketiZe"},
    {'Z', "repacketiZe"},
    /* Unofficial command parameters / expensions */
    {'d', "DTMF payload ID (unofficial extension)"},
    {'D', "DTMF payload ID (unofficial extension)"},
    {'m', "codec Mapping (unofficial extension)"},
    {'M', "codec Mapping (unofficial extension)"},
    {'p', "Protocol type (unofficial extension)"},
    {'P', "Protocol type (unofficial extension)"},
    {'t', "Transcode to (unofficial extension)"},
    {'T', "Transcode to (unofficial extension)"},
    {'u', "accoUnting (unofficial extension)"},
    {'U', "accoUnting (unofficial extension)"},
    {0, NULL}
};

static const value_string prototypenames[] = {
    { '0', "UDP (default)"},
    { '1', "TCP"},
    { '2', "SCTP"},
    { 0, NULL }
};
static const value_string acctypenames[] = {
    { '0', "Start"},
    { '1', "Interim update"},
    { '2', "Stop"},
    { 0, NULL }
};

static const value_string oktypenames[] = {
    { '0', "Ok"},
    { '1', "Version Supported"},
    { 0, NULL }
};

static const string_string errortypenames[] = {
    { "E0", "Syntax error: unknown command (CMDUNKN)" },
    { "E1", "Syntax error: invalid number of arguments (PARSE_NARGS)" },
    { "E2", "Syntax error: modifiers are not supported by the command (PARSE_MODS)" },
    { "E3", "Syntax error: subcommand is not supported (PARSE_SUBC)" },
    { "E5", "PARSE_1" },
    { "E6", "PARSE_2" },
    { "E7", "PARSE_3" },
    { "E8", "PARSE_4" },
    { "E9", "PARSE_5" },
    { "E10", "PARSE_10" },
    { "E11", "PARSE_11" },
    { "E12", "PARSE_12" },
    { "E13", "PARSE_13" },
    { "E14", "PARSE_14" },
    { "E15", "PARSE_15" },
    { "E16", "PARSE_16" },
    { "E17", "PARSE_6" },
    { "E18", "PARSE_7" },
    { "E19", "PARSE_8" },
    { "E25", "Software error: output buffer overflow (RTOOBIG_1)" },
    { "E26", "Software error: output buffer overflow (RTOOBIG_2)" },
    { "E31", "Syntax error: invalid local address (INVLARG_1)" },
    { "E32", "Syntax error: invalid remote address (INVLARG_2)" },
    { "E33", "Syntax error: can't find local address for remote address (INVLARG_3)" },
    { "E34", "Syntax error: invalid local address (INVLARG_4)" },
    { "E35", "Syntax error: no codecs (INVLARG_5)" },
    { "E36", "Syntax error: cannot match local address for the session (INVLARG_6)" },
    { "E50", "Software error: session not found (SESUNKN)" },
    { "E60", "PLRFAIL" },
    { "E62", "Software error: unsupported/invalid counter name (QRYFAIL)" },
    { "E65", "CPYFAIL" },
    { "E68", "STSFAIL" },
    { "E71", "Software error: can't create listener (LSTFAIL_1)" },
    { "E72", "Software error: can't create listener (LSTFAIL_2)" },
    { "E75", "Software error: must permit notification socket with -n (NSOFF)" },
    { "E81", "Out of memory (NOMEM_1)" },
    { "E82", "Out of memory (NOMEM_2)" },
    { "E83", "Out of memory (NOMEM_3)" },
    { "E84", "Out of memory (NOMEM_4)" },
    { "E85", "Out of memory (NOMEM_5)" },
    { "E86", "Out of memory (NOMEM_6)" },
    { "E87", "Out of memory (NOMEM_7)" },
    { "E88", "Out of memory (NOMEM_8)" },
    { "E89", "Out of memory (NOMEM_9)" },
    { "E98", "OVERLOAD" },
    { "E99", "Software error: proxy is in the deorbiting-burn mode, new session rejected (SLOWSHTDN)" },
    { 0, NULL }
};

static gint ett_rtpproxy = -1;

static gint ett_rtpproxy_request = -1;
static gint ett_rtpproxy_command = -1;
static gint ett_rtpproxy_command_parameters = -1;
static gint ett_rtpproxy_command_parameters_codecs = -1;
static gint ett_rtpproxy_command_parameters_local = -1;
static gint ett_rtpproxy_command_parameters_remote = -1;
static gint ett_rtpproxy_command_parameters_repacketize = -1;
static gint ett_rtpproxy_command_parameters_dtmf = -1;
static gint ett_rtpproxy_command_parameters_cmap = -1;
static gint ett_rtpproxy_command_parameters_proto = -1;
static gint ett_rtpproxy_command_parameters_transcode = -1;
static gint ett_rtpproxy_command_parameters_acc = -1;
static gint ett_rtpproxy_tag = -1;
static gint ett_rtpproxy_notify = -1;

static gint ett_rtpproxy_reply = -1;

static gint ett_rtpproxy_ng_bencode = -1;

/* Default values */
#define RTPPROXY_PORT "22222"  /* Not IANA registered */
static range_t* rtpproxy_tcp_range = NULL;
static range_t* rtpproxy_udp_range = NULL;

static gboolean rtpproxy_establish_conversation = TRUE;
/* See - https://www.opensips.org/html/docs/modules/1.10.x/rtpproxy.html#id293555 */
/* See - http://www.kamailio.org/docs/modules/4.3.x/modules/rtpproxy.html#idp15794952 */
static guint rtpproxy_timeout = 1000;
static nstime_t rtpproxy_timeout_ns = NSTIME_INIT_ZERO;

void proto_reg_handoff_rtpproxy(void);

static gint
rtpproxy_add_tag(proto_tree *rtpproxy_tree, tvbuff_t *tvb, guint begin, guint realsize)
{
    proto_item *ti = NULL;
    proto_tree *another_tree = NULL;
    gint new_offset;
    guint end;

    new_offset = tvb_find_guint8(tvb, begin, -1, ' ');
    if(new_offset < 0)
        end = realsize; /* No more parameters */
    else
        end = new_offset;

    /* SER/OpenSER/OpenSIPS/Kamailio adds Media-ID right after the Tag
     * separated by a semicolon
     */
    new_offset = tvb_find_guint8(tvb, begin, end, ';');
    if(new_offset == -1){
        ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_tag, tvb, begin, end - begin, ENC_ASCII | ENC_NA);
        another_tree = proto_item_add_subtree(ti, ett_rtpproxy_tag);
        ti = proto_tree_add_item(another_tree, hf_rtpproxy_mediaid, tvb, new_offset+1, 0, ENC_ASCII | ENC_NA);
        proto_item_append_text(ti, "<skipped>");
        proto_item_set_generated(ti);
    }
    else{
        ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_tag, tvb, begin, new_offset - begin, ENC_ASCII | ENC_NA);
        if ((guint)new_offset == begin){
            proto_item_append_text(ti, "<skipped>"); /* A very first Offer/Update command */
            proto_item_set_generated(ti);
        }
        another_tree = proto_item_add_subtree(ti, ett_rtpproxy_tag);
        proto_tree_add_item(another_tree, hf_rtpproxy_mediaid, tvb, new_offset+1, end - (new_offset+1), ENC_ASCII | ENC_NA);
    }
    return (end == realsize ? -1 : (gint)end);
}

static void
rtpproxy_add_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtpproxy_tree, guint begin, guint realsize)
{
    proto_item *ti;
    proto_tree *another_tree = NULL;
    guint offset = 0;
    guint new_offset = 0;
    gint i;
    guint pt = 0;
    gchar** codecs = NULL;
    guint codec_len;
    guint8* rawstr = NULL;
    guint32 ipaddr[4]; /* Enough room for IPv4 or IPv6 */

    /* Extract the entire parameters line. */
    /* Something like "t4p1iic8,0,2,4,18,96,97,98,100,101" */
    rawstr = tvb_get_string_enc(pinfo->pool, tvb, begin, realsize, ENC_ASCII);

    while(offset < realsize){
        ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_command_parameter, tvb, begin + offset, 1, ENC_ASCII | ENC_NA);
        offset++; /* Skip 1-byte parameter's type */
        switch (g_ascii_tolower(tvb_get_guint8(tvb, begin+offset-1)))
        {
            /* Official long parameters */
            case 'c':
                new_offset = (gint)strspn(rawstr+offset, "0123456789,");
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_codecs);
                codecs = wmem_strsplit(pinfo->pool, tvb_get_string_enc(pinfo->pool, tvb, begin+offset, new_offset, ENC_ASCII), ",", 0);
                i = 0;
                while(codecs[i]){
                    /* We assume strings < 2^32-1 bytes long. :-) */
                    codec_len = (guint)strlen(codecs[i]);
                    ti = proto_tree_add_uint(another_tree, hf_rtpproxy_command_parameter_codec, tvb, begin+offset, codec_len,
                            (guint16) g_ascii_strtoull((gchar*)tvb_get_string_enc(pinfo->pool, tvb, begin+offset, codec_len, ENC_ASCII), NULL, 10));
                    proto_item_append_text(ti, " (%s)", val_to_str_ext((guint)strtoul(tvb_format_text(pinfo->pool, tvb,begin+offset,codec_len),NULL,10), &rtp_payload_type_vals_ext, "Unknown"));
                    offset += codec_len;
                    if(codecs[i+1])
                        offset++; /* skip comma */
                    i++;
                };
                break;
            case 'l':
                /* That's another one protocol shortcoming - the same parameter used twice. */
                /* https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#createupdatelookup-session */
                /* https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#get-information */
                new_offset = (gint)strspn(rawstr+offset, "0123456789.");
                if(new_offset){
                    another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_local);
                    if(str_to_ip((char*)tvb_get_string_enc(pinfo->pool, tvb, begin+offset, new_offset, ENC_ASCII), ipaddr))
                        proto_tree_add_ipv4(another_tree, hf_rtpproxy_command_parameter_local_ipv4, tvb, begin+offset, new_offset, ipaddr[0]);
                    else
                        proto_tree_add_expert(another_tree, pinfo, &ei_rtpproxy_bad_ipv4, tvb, begin+offset, new_offset);
                    offset += new_offset;
                }
                break;
            case 'r':
                new_offset = (gint)strspn(rawstr+offset, "0123456789.");
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_remote);
                if(str_to_ip((char*)tvb_get_string_enc(pinfo->pool, tvb, begin+offset, new_offset, ENC_ASCII), ipaddr))
                    proto_tree_add_ipv4(another_tree, hf_rtpproxy_command_parameter_remote_ipv4, tvb, begin+offset, new_offset, ipaddr[0]);
                else
                    proto_tree_add_expert(another_tree, pinfo, &ei_rtpproxy_bad_ipv4, tvb, begin+offset, new_offset);
                offset += new_offset;
                break;
            case 'z':
                new_offset = (gint)strspn(rawstr+offset, "0123456789");
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_repacketize);
                proto_tree_add_uint(another_tree, hf_rtpproxy_command_parameter_repacketize, tvb, begin+offset, new_offset,
                        (guint16) g_ascii_strtoull((gchar*)tvb_get_string_enc(pinfo->pool, tvb, begin+offset, new_offset, ENC_ASCII), NULL, 10));
                offset += new_offset;
                break;
            /* Unofficial long parameters */
            case 'd':
                new_offset = (gint)strspn(rawstr+offset, "0123456789");
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_dtmf);
                proto_tree_add_uint(another_tree, hf_rtpproxy_command_parameter_dtmf, tvb, begin+offset, new_offset,
                        (guint16) g_ascii_strtoull((gchar*)tvb_get_string_enc(pinfo->pool, tvb, begin+offset, new_offset, ENC_ASCII), NULL, 10));
                if(rtpproxy_establish_conversation){
                    pt = (guint)strtoul(tvb_format_text(pinfo->pool, tvb,begin+offset,new_offset),NULL,10);
                    dissector_add_uint("rtp.pt", pt, rtp_events_handle);
                }
                offset += new_offset;
                break;
            case 'm':
                new_offset = (gint)strspn(rawstr+offset, "0123456789=,");
                /* TODO */
                offset += new_offset;
                break;
            case 'p':
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_proto);
                proto_tree_add_item(another_tree, hf_rtpproxy_command_parameter_proto, tvb, begin+offset, 1, ENC_ASCII | ENC_NA);
                offset++;
                break;
            case 't':
                new_offset = (gint)strspn(rawstr+offset, "0123456789");
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_transcode);
                ti = proto_tree_add_uint(another_tree, hf_rtpproxy_command_parameter_transcode, tvb, begin+offset, new_offset,
                        (guint16) g_ascii_strtoull((gchar*)tvb_get_string_enc(pinfo->pool, tvb, begin+offset, new_offset, ENC_ASCII), NULL, 10));
                proto_item_append_text(ti, " (%s)", val_to_str_ext((guint)strtoul(tvb_format_text(pinfo->pool, tvb,begin+offset, new_offset),NULL,10), &rtp_payload_type_vals_ext, "Unknown"));
                offset += new_offset;
                break;
            case 'u':
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_acc);
                proto_tree_add_item(another_tree, hf_rtpproxy_command_parameter_acc, tvb, begin+offset, 1, ENC_ASCII | ENC_NA);
                offset++;
                break;
            default:
                break;
        }
    }
}

static rtpproxy_info_t *
rtpproxy_add_tid(gboolean is_request, tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtpproxy_tree, rtpproxy_conv_info_t *rtpproxy_conv, const guint8* cookie)
{
    rtpproxy_info_t *rtpproxy_info;
    proto_item *pi;

    if (!PINFO_FD_VISITED(pinfo)) {
        if (is_request){
            rtpproxy_info = wmem_new0(wmem_file_scope(), rtpproxy_info_t);
            rtpproxy_info->req_frame = pinfo->num;
            rtpproxy_info->req_time = pinfo->abs_ts;
            wmem_tree_insert_string(rtpproxy_conv->trans, cookie, rtpproxy_info, 0);
        } else {
            rtpproxy_info = (rtpproxy_info_t *)wmem_tree_lookup_string(rtpproxy_conv->trans, cookie, 0);
            if (rtpproxy_info) {
                rtpproxy_info->resp_frame = pinfo->num;
            }
        }
    } else {
        rtpproxy_info = (rtpproxy_info_t *)wmem_tree_lookup_string(rtpproxy_conv->trans, cookie, 0);
        if (rtpproxy_info && (is_request ? rtpproxy_info->resp_frame : rtpproxy_info->req_frame)) {
            nstime_t ns;

            pi = proto_tree_add_uint(rtpproxy_tree, is_request ? hf_rtpproxy_response_in : hf_rtpproxy_request_in, tvb, 0, 0, is_request ? rtpproxy_info->resp_frame : rtpproxy_info->req_frame);
            proto_item_set_generated(pi);

            /* If not a request (so it's a reply) then calculate response time */
            if (!is_request){
                nstime_delta(&ns, &pinfo->abs_ts, &rtpproxy_info->req_time);
                pi = proto_tree_add_time(rtpproxy_tree, hf_rtpproxy_response_time, tvb, 0, 0, &ns);
                proto_item_set_generated(pi);
                if (nstime_cmp(&rtpproxy_timeout_ns, &ns) < 0)
                    expert_add_info_format(pinfo, rtpproxy_tree, &ei_rtpproxy_timeout, "Response timeout %.3f seconds", nstime_to_sec(&ns));
            }
        }
    }
    /* Could be NULL so we should check it before dereferencing */
    return rtpproxy_info;
}

static void
rtpproxy_add_notify_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtpproxy_tree, guint begin, guint end)
{
    gint offset = 0;
    gint tmp = 0;
    gboolean ipv6 = FALSE;
    guint32 ipaddr[4]; /* Enough room for IPv4 or IPv6 */

    /* Check for at least one colon */
    offset = tvb_find_guint8(tvb, begin, end, ':');
    if(offset != -1){
        /* Find if it's the latest colon (not in case of a IPv6) */
        while((tmp = tvb_find_guint8(tvb, offset+1, end, ':')) != -1){
            ipv6 = TRUE;
            offset = tmp;
        }
        /* We have ip:port */
        if(ipv6){
            if(str_to_ip6((char*)tvb_get_string_enc(pinfo->pool, tvb, begin, offset - begin, ENC_ASCII), ipaddr))
                proto_tree_add_ipv6(rtpproxy_tree, hf_rtpproxy_notify_ipv6, tvb, begin, offset - begin, (const ws_in6_addr*)ipaddr);
            else
                proto_tree_add_expert(rtpproxy_tree, pinfo, &ei_rtpproxy_bad_ipv6, tvb, begin, offset - begin);
        }
        else{
            if(str_to_ip((char*)tvb_get_string_enc(pinfo->pool, tvb, begin, offset - begin, ENC_ASCII), ipaddr))
                proto_tree_add_ipv4(rtpproxy_tree, hf_rtpproxy_notify_ipv4, tvb, begin, offset - begin, ipaddr[0]);
            else
                proto_tree_add_expert(rtpproxy_tree, pinfo, &ei_rtpproxy_bad_ipv4, tvb, begin, offset - begin);
        }
        proto_tree_add_uint(rtpproxy_tree, hf_rtpproxy_notify_port, tvb, offset+1, end - (offset+1),
            (guint16) g_ascii_strtoull((gchar*)tvb_get_string_enc(pinfo->pool, tvb, offset+1, end - (offset+1), ENC_ASCII), NULL, 10));
    }
    else{
        proto_item *ti = NULL;
        /* Only port is supplied - take IPv4/IPv6 from  ip.src/ipv6.src respectively */
        expert_add_info(pinfo, rtpproxy_tree, &ei_rtpproxy_notify_no_ip);
        if (pinfo->src.type == AT_IPv4) {
            ti = proto_tree_add_ipv4(rtpproxy_tree, hf_rtpproxy_notify_ipv4, tvb, begin, 0, *(const guint32*)(pinfo->src.data));
        } else if (pinfo->src.type == AT_IPv6) {
            ti = proto_tree_add_ipv6(rtpproxy_tree, hf_rtpproxy_notify_ipv6, tvb, begin, 0, (const ws_in6_addr *)(pinfo->src.data));
        }
        if (ti) {
            proto_item_set_generated(ti);
            proto_tree_add_uint(rtpproxy_tree, hf_rtpproxy_notify_port, tvb, begin, end - begin,
                (guint16) g_ascii_strtoull((gchar*)tvb_get_string_enc(pinfo->pool, tvb, begin, end - begin, ENC_ASCII), NULL, 10));
        }
    }
}

static int
dissect_rtpproxy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gboolean has_lf = FALSE;
    gint offset = 0;
    gint new_offset = 0;
    guint tmp;
    guint tmp2;
    gint realsize = 0;
    guint8* rawstr;
    const guint8* tmpstr;
    proto_item *ti;
    proto_item *ti2;
    proto_tree *rtpproxy_tree;
    conversation_t *conversation;
    rtpproxy_conv_info_t *rtpproxy_conv;
    const guint8* cookie = NULL;
    /* For RT(C)P setup */
    address addr;
    guint16 port;
    guint32 ipaddr[4]; /* Enough room for IPv4 or IPv6 */
    rtpproxy_info_t *rtpproxy_info = NULL;
    tvbuff_t *subtvb;

    /* If it does not start with a printable character it's not RTPProxy */
    if(!g_ascii_isprint(tvb_get_guint8(tvb, 0)))
        return 0;

    /* Extract Cookie */
    offset = tvb_find_guint8(tvb, offset, -1, ' ');
    if(offset == -1)
        return 0;

    /* We believe it's likely a RTPproxy / RTPproxy-ng protocol */
    /* Note: we no longer distinct between packets with or w/o LF - it turned
     * out to be useless */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPproxy");

    /* Clear out stuff in the info column - we'll set it later */
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_rtpproxy, tvb, 0, -1, ENC_NA);
    rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy);

    proto_tree_add_item_ret_string(rtpproxy_tree, hf_rtpproxy_cookie, tvb, 0, offset, ENC_ASCII | ENC_NA, pinfo->pool, &cookie);

    /* Skip whitespace */
    offset = tvb_skip_wsp(tvb, offset+1, -1);

    /* Calculate size to prevent recalculation in the future */
    realsize = tvb_reported_length(tvb);

    /* Don't count trailing zeroes (inserted by some SIP-servers sometimes) */
    while (tvb_get_guint8(tvb, realsize - 1) == 0){
        realsize -= 1;
    }

    /* Check for LF (required for TCP connection, optional for UDP) */
    if (tvb_get_guint8(tvb, realsize - 1) == '\n'){
        /* Don't count trailing LF */
        realsize -= 1;
        has_lf = TRUE;
    }

    /* Try to create conversation */
    conversation = find_or_create_conversation(pinfo);
    rtpproxy_conv = (rtpproxy_conv_info_t *)conversation_get_proto_data(conversation, proto_rtpproxy);
    if (!rtpproxy_conv) {
        rtpproxy_conv = wmem_new(wmem_file_scope(), rtpproxy_conv_info_t);
        rtpproxy_conv->trans = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_rtpproxy, rtpproxy_conv);
    }

    /* Get payload string */
    rawstr = tvb_format_text(pinfo->pool, tvb, offset, realsize - offset);

    /* Extract command */
    tmp = g_ascii_tolower(tvb_get_guint8(tvb, offset));
    switch (tmp)
    {
        case 's':
            /* A specific case - long info answer */
            /* %COOKIE% sessions created %NUM0% active sessions: %NUM1% */
            /* FIXME https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#information */
            rtpproxy_add_tid(FALSE, tvb, pinfo, rtpproxy_tree, rtpproxy_conv, cookie);
            if ('e' == tvb_get_guint8(tvb, offset+1)){
                col_add_fstr(pinfo->cinfo, COL_INFO, "Reply: %s", rawstr);
                ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_reply, tvb, offset, -1, ENC_NA);

                rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_reply);
                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_status, tvb, offset, realsize - offset, ENC_ASCII | ENC_NA);
                break;
            }
        /* FALL THROUGH */
        case 'i':
        case 'x':
        case 'u':
        case 'l':
        case 'd':
            tmp2 = tvb_get_guint8(tvb, offset+1);
            if(('1' <= tmp2) && (tmp2 <= '9') && (tvb_get_guint8(tvb, offset+2) == ':')){
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPproxy-ng");
                col_add_fstr(pinfo->cinfo, COL_INFO, "RTPproxy-ng: %s", rawstr);
                ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_ng_bencode, tvb, offset, -1, ENC_ASCII | ENC_NA);
                rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_ng_bencode);
                subtvb = tvb_new_subset_remaining(tvb, offset);
                call_dissector(bencode_handle, subtvb, pinfo, rtpproxy_tree);
                break;
            }
        /* FALL THROUGH */
        case 'p':
        case 'v':
        case 'r':
        case 'c':
        case 'q':
            rtpproxy_info = rtpproxy_add_tid(TRUE, tvb, pinfo, rtpproxy_tree, rtpproxy_conv, cookie);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Request: %s", rawstr);
            ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_request, tvb, offset, -1, ENC_NA);
            rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_request);

            /* A specific case - version request:
             * https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#get-list-of-veatures
             *
             * In this case a command size must be bigger or equal to a "VF YYYYMMDD" string size.
             * It's bigger if there is more than one space inserted between "VF" and "YYYYMMDD" tokens.
             */
            if ((tmp == 'v') && (offset + (gint)strlen("VF YYYYMMDD") <= realsize)){
                /* Skip whitespace between "VF" and "YYYYMMDD" tokens */
                new_offset = tvb_skip_wsp(tvb, offset + ((guint)strlen("VF") + 1), -1);
                ti = proto_tree_add_item_ret_string(rtpproxy_tree, hf_rtpproxy_version_request, tvb, new_offset, (gint)strlen("YYYYMMDD"), ENC_ASCII | ENC_NA, pinfo->pool, &tmpstr);
                proto_item_append_text(ti, " (%s)", str_to_str(tmpstr, versiontypenames, "Unknown"));
                break;
            }

            /* All other commands */
            ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_command, tvb, offset, 1, ENC_ASCII | ENC_NA);

            /* A specific case - handshake/ping */
            if (tmp == 'v')
                break; /* No more parameters */

            /* A specific case - close all calls */
            if (tmp == 'x')
                break; /* No more parameters */

            /* Extract parameters */
            /* Parameters should be right after the command and before EOL (in case of Info command) or before whitespace */
            new_offset = (tmp == 'i' ? (realsize - 1 > offset ? offset + (gint)strlen("Ib") : offset + (gint)strlen("I")) : tvb_find_guint8(tvb, offset, -1, ' '));

            if (new_offset != offset + 1){
                rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_command);
                ti2 = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_command_parameters, tvb, offset+1, new_offset - (offset+1), ENC_ASCII | ENC_NA);
                rtpproxy_add_parameter(tvb, pinfo, proto_item_add_subtree(ti2, ett_rtpproxy_command_parameters), offset+1, new_offset - (offset+1));
                rtpproxy_tree = proto_item_get_parent(ti);
            }

            /* A specific case - query information */
            if (tmp == 'i')
                break; /* No more parameters */

            /* Skip whitespace */
            offset = tvb_skip_wsp(tvb, new_offset+1, -1);

            /* Extract Call-ID */
            new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
            proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_callid, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
            if(rtpproxy_info && !rtpproxy_info->callid)
                rtpproxy_info->callid = tvb_get_string_enc(wmem_file_scope(), tvb, offset, new_offset - offset, ENC_ASCII);
            /* Skip whitespace */
            offset = tvb_skip_wsp(tvb, new_offset+1, -1);

            /* Extract IP and Port in case of Offer/Answer */
            if ((tmp == 'u') || (tmp == 'l')){
                /* Extract IP */
                new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
                if (tvb_find_guint8(tvb, offset, new_offset - offset, ':') == -1){
                    if(str_to_ip((char*)tvb_get_string_enc(pinfo->pool, tvb, offset, new_offset - offset, ENC_ASCII), ipaddr))
                        proto_tree_add_ipv4(rtpproxy_tree, hf_rtpproxy_ipv4, tvb, offset, new_offset - offset, ipaddr[0]);
                    else
                        proto_tree_add_expert(rtpproxy_tree, pinfo, &ei_rtpproxy_bad_ipv4, tvb, offset, new_offset - offset);
                }
                else{
                    if(str_to_ip6((char*)tvb_get_string_enc(pinfo->pool, tvb, offset, new_offset - offset, ENC_ASCII), ipaddr))
                        proto_tree_add_ipv6(rtpproxy_tree, hf_rtpproxy_ipv6, tvb, offset, new_offset - offset, (const ws_in6_addr *)ipaddr);
                    else
                        proto_tree_add_expert(rtpproxy_tree, pinfo, &ei_rtpproxy_bad_ipv6, tvb, offset, new_offset - offset);
                }
                /* Skip whitespace */
                offset = tvb_skip_wsp(tvb, new_offset+1, -1);

                /* Extract Port */
                new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
                proto_tree_add_uint(rtpproxy_tree, hf_rtpproxy_port, tvb, offset, new_offset - offset,
                        (guint16) g_ascii_strtoull((gchar*)tvb_get_string_enc(pinfo->pool, tvb, offset, new_offset - offset, ENC_ASCII), NULL, 10));
                /* Skip whitespace */
                offset = tvb_skip_wsp(tvb, new_offset+1, -1);
            }

            /* Extract Copy target */
            if (tmp == 'c'){
                new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_copy_target, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
                /* Skip whitespace */
                offset = tvb_skip_wsp(tvb, new_offset+1, -1);
            }

            /* Extract Playback file and codecs */
            if (tmp == 'p'){
                /* Extract filename */
                new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_playback_filename, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA);
                /* Skip whitespace */
                offset = tvb_skip_wsp(tvb, new_offset+1, -1);

                /* Extract codec */
                new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
                proto_tree_add_uint(rtpproxy_tree, hf_rtpproxy_playback_codec, tvb, offset, new_offset - offset,
                        (guint16) g_ascii_strtoull((gchar*)tvb_get_string_enc(pinfo->pool, tvb, offset, new_offset - offset, ENC_ASCII), NULL, 10));
                /* Skip whitespace */
                offset = tvb_skip_wsp(tvb, new_offset+1, -1);
            }

            /* Extract first tag */
            new_offset = rtpproxy_add_tag(rtpproxy_tree, tvb, offset, realsize);
            if(new_offset == -1)
                break; /* No more parameters */
            /* Skip whitespace */
            offset = tvb_skip_wsp(tvb, new_offset+1, -1);

            /* Extract second tag */
            new_offset = rtpproxy_add_tag(rtpproxy_tree, tvb, offset, realsize);
            if(new_offset == -1)
                break; /* No more parameters */
            /* Skip whitespace */
            offset = tvb_skip_wsp(tvb, new_offset+1, -1);

            /* Extract Notification address */
            if (tmp == 'u'){
                ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify, tvb, offset, realsize - offset, ENC_ASCII | ENC_NA);
                proto_item_set_text(ti, "Notify");
                rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_notify);

                /* Check for NotifyTag parameter (separated by space) */
                new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
                if(new_offset == -1){
                    /* NotifyTag wasn't found (we should re-use Call-ID instead) */
                    rtpproxy_add_notify_addr(tvb, pinfo, rtpproxy_tree, offset, realsize);
                    break; /* No more parameters */
                }

                /* NotifyTag was found */
                rtpproxy_add_notify_addr(tvb, pinfo, rtpproxy_tree, offset, new_offset);
                /* Skip whitespace */
                offset = tvb_skip_wsp(tvb, new_offset+1, -1);

                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_tag, tvb, offset, realsize - offset, ENC_ASCII | ENC_NA);
            }
            break;
        case 'e':
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            rtpproxy_info = rtpproxy_add_tid(FALSE, tvb, pinfo, rtpproxy_tree, rtpproxy_conv, cookie);
            if (tmp == 'e')
                col_add_fstr(pinfo->cinfo, COL_INFO, "Error reply: %s", rawstr);
            else
                col_add_fstr(pinfo->cinfo, COL_INFO, "Reply: %s", rawstr);

            ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_reply, tvb, offset, -1, ENC_NA);
            rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_reply);

            if(rtpproxy_info && rtpproxy_info->callid){
                ti = proto_tree_add_string(rtpproxy_tree, hf_rtpproxy_callid, tvb, offset, 0, rtpproxy_info->callid);
                proto_item_set_generated(ti);
            }

            if (tmp == 'e'){
                tmp = tvb_find_line_end(tvb, offset, -1, &new_offset, FALSE);
                tmpstr = tvb_get_string_enc(pinfo->pool, tvb, offset, tmp, ENC_ASCII);
                ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_error, tvb, offset, (gint)strlen(tmpstr), ENC_ASCII | ENC_NA);
                proto_item_append_text(ti, " (%s)", str_to_str(tmpstr, errortypenames, "Unknown"));
                break;
            }

            /* Check for a single '0' or '1' character followed by the end-of-line.
             * These both are positive replies - either a 'positive reply' or a 'version ack'.
             *
             * https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#positive-reply
             * https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#version-reply
             */
            if (((tmp == '0') || (tmp == '1')) && (realsize == offset + (gint)strlen("X"))){
                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_ok, tvb, offset, 1, ENC_ASCII | ENC_NA);
                break;
            }

            /* Check for the VERSION_NUMBER string reply:
             * https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#version-reply
             *
             * If a total size equals to a current offset + size of "YYYYMMDD" string
             * then it's a version reply.
             */
            if (realsize == offset + (gint)strlen("YYYYMMDD")){
                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_version_supported, tvb, offset, (guint32)strlen("YYYYMMDD"), ENC_ASCII | ENC_NA);
                break;
            }

            /* Extract Port */
            new_offset = tvb_find_guint8(tvb, offset, -1, ' ');
            /* Convert port to unsigned 16-bit number */
            port = (guint16) g_ascii_strtoull((gchar*)tvb_get_string_enc(pinfo->pool, tvb, offset, new_offset - offset, ENC_ASCII), NULL, 10);
            proto_tree_add_uint(rtpproxy_tree, hf_rtpproxy_port, tvb, offset, new_offset - offset, port);
            /* Skip whitespace */
            offset = tvb_skip_wsp(tvb, new_offset+1, -1);

            /* Extract IP */
            memset(&addr, 0, sizeof(address));

            /* Try rtpengine bogus extension first. It appends 4 or
             * 6 depending on type of the IP. See
             * https://github.com/sipwise/rtpengine/blob/eea3256/daemon/call_interfaces.c#L74
             * for further details */
            tmp = tvb_find_guint8(tvb, offset, -1, ' ');
            if(tmp == (guint)(-1)){
                /* No extension - operate normally */
                tmp = tvb_find_line_end(tvb, offset, -1, &new_offset, FALSE);
            }
            else {
                tmp -= offset;
            }

            if (tvb_find_guint8(tvb, offset, -1, ':') == -1){
                if (str_to_ip((char*)tvb_get_string_enc(pinfo->pool, tvb, offset, tmp, ENC_ASCII), ipaddr)){
                    addr.type = AT_IPv4;
                    addr.len  = 4;
                    addr.data = wmem_memdup(pinfo->pool, ipaddr, 4);
                    proto_tree_add_ipv4(rtpproxy_tree, hf_rtpproxy_ipv4, tvb, offset, tmp, ipaddr[0]);
                }
                else
                    proto_tree_add_expert(rtpproxy_tree, pinfo, &ei_rtpproxy_bad_ipv4, tvb, offset, tmp);
            }
            else{
                if (str_to_ip6((char*)tvb_get_string_enc(pinfo->pool, tvb, offset, tmp, ENC_ASCII), ipaddr)){
                    addr.type = AT_IPv6;
                    addr.len  = 16;
                    addr.data = wmem_memdup(pinfo->pool, ipaddr, 16);
                    proto_tree_add_ipv6(rtpproxy_tree, hf_rtpproxy_ipv6, tvb, offset, tmp, (const ws_in6_addr *)ipaddr);
                }
                else
                    proto_tree_add_expert(rtpproxy_tree, pinfo, &ei_rtpproxy_bad_ipv6, tvb, offset, tmp);
            }

            if(rtpproxy_establish_conversation){
                if (rtp_handle) {
                    /* FIXME tell if isn't a video stream, and setup codec mapping */
                    if (addr.len)
                        rtp_add_address(pinfo, PT_UDP, &addr, port, 0, "RTPproxy", pinfo->num, 0, NULL);
                }
                if (rtcp_handle) {
                    if (addr.len)
                        rtcp_add_address(pinfo, &addr, port+1, 0, "RTPproxy", pinfo->num);
                }
            }
            break;
        default:
            break;
    }
    /* TODO add an expert warning about packets w/o LF sent over TCP */
    if (has_lf)
        proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_lf, tvb, realsize, 1, ENC_NA);

    return tvb_captured_length(tvb);
}

/* Preference callbacks */
static void
rtpproxy_prefs_apply(void) {

    rtpproxy_tcp_range = prefs_get_range_value("rtpproxy", "tcp.port");
    rtpproxy_udp_range = prefs_get_range_value("rtpproxy", "udp.port");
}

void
proto_register_rtpproxy(void)
{
    module_t *rtpproxy_module;
    expert_module_t* expert_rtpproxy_module;

    static hf_register_info hf[] = {
        {
            &hf_rtpproxy_cookie,
            {
                "Cookie",
                "rtpproxy.cookie",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_version_request,
            {
                "Version Request",
                "rtpproxy.version",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_version_supported,
            {
                "Version Supported",
                "rtpproxy.version_supported",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_error,
            {
                "Error",
                "rtpproxy.error",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_ok,
            {
                "Ok",
                "rtpproxy.ok",
                FT_CHAR,
                BASE_HEX,
                VALS(oktypenames),
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_status,
            {
                "Status",
                "rtpproxy.status",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_ipv4,
            {
                "IPv4",
                "rtpproxy.ipv4",
                FT_IPv4,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_ipv6,
            {
                "IPv6",
                "rtpproxy.ipv6",
                FT_IPv6,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_port,
            {
                "Port",
                "rtpproxy.port",
                FT_UINT16, /* 0 - 65535 */
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_request,
            {
                "Request",
                "rtpproxy.request",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command,
            {
                "Command",
                "rtpproxy.command",
                FT_CHAR,
                BASE_HEX,
                VALS(commandtypenames),
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameters,
            {
                "Command parameters",
                "rtpproxy.command_parameters",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter,
            {
                "Parameter",
                "rtpproxy.command_parameter",
                FT_CHAR,
                BASE_HEX,
                VALS(paramtypenames),
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_codec,
            {
                "Allowed codec",
                "rtpproxy.command_parameter_codec",
                FT_UINT8, /* 0 - 127 */
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_local_ipv4,
            {
                "Local IPv4 address",
                "rtpproxy.command_parameter_local_ipv4",
                FT_IPv4, /* FIXME - is it ever possible to see IPv6 here? */
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_remote_ipv4,
            {
                "Remote IPv4 address",
                "rtpproxy.command_parameter_remote_ipv4",
                FT_IPv4, /* FIXME - is it ever possible to see IPv6 here? */
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_repacketize,
            {
                "Repacketize (ms)",
                "rtpproxy.command_parameter_repacketize",
                FT_UINT16, /* 0 - 1000 milliseconds */
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_dtmf,
            {
                "DTMF payload ID",
                "rtpproxy.command_parameter_dtmf",
                FT_UINT8, /* 0 - 127 */
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_proto,
            {
                "RTP transmission protocol",
                "rtpproxy.command_parameter_proto",
                FT_CHAR,
                BASE_HEX,
                VALS(prototypenames),
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_transcode,
            {
                "Transcode to",
                "rtpproxy.command_parameter_transcode",
                FT_UINT8, /* 0 - 127 */
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_acc,
            {
                "Accounting",
                "rtpproxy.command_parameter_acc",
                FT_CHAR,
                BASE_HEX,
                VALS(acctypenames),
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_copy_target,
            {
                "Copy target",
                "rtpproxy.copy_target",
                FT_STRING, /* Filename or UDP address, e.g. /var/tmp/fileXXXX.yyy or IP:Port */
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_playback_filename,
            {
                "Playback filename",
                "rtpproxy.playback_filename",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_playback_codec,
            {
                "Playback codec",
                "rtpproxy.playback_codec",
                FT_UINT8, /* 0 - 127 */
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_callid,
            {
                "Call-ID",
                "rtpproxy.callid",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_notify,
            {
                "Notify",
                "rtpproxy.notify",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_tag,
            {
                "Tag",
                "rtpproxy.tag",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_mediaid,
            {
                "Media-ID",
                "rtpproxy.mediaid",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_notify_ipv4,
            {
                "Notification IPv4",
                "rtpproxy.notify_ipv4",
                FT_IPv4,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_notify_ipv6,
            {
                "Notification IPv6",
                "rtpproxy.notify_ipv6",
                FT_IPv6,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_notify_port,
            {
                "Notification Port",
                "rtpproxy.notify_port",
                FT_UINT16,
                BASE_DEC,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_notify_tag,
            {
                "Notification Tag",
                "rtpproxy.notify_tag",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_reply,
            {
                "Reply",
                "rtpproxy.reply",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_lf,
            {
                "LF",
                "rtpproxy.lf",
                FT_NONE,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_request_in,
            {
                "Request In",
                "rtpproxy.request_in",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }

        },
        {
            &hf_rtpproxy_response_in,
            {
                "Response In",
                "rtpproxy.response_in",
                FT_FRAMENUM,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_response_time,
            {
                "Response Time",
                "rtpproxy.response_time",
                FT_RELATIVE_TIME,
                BASE_NONE,
                NULL,
                0x0,
                "The time between the Request and the Reply",
                HFILL
             }
        },
        {
            &hf_rtpproxy_ng_bencode,
            {
                "RTPproxy-ng bencode packet",
                "rtpproxy.ng.bencode",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                "Serialized structure of integers, dictionaries, strings and lists.",
                HFILL
            }
        }
    };

    static ei_register_info ei[] = {
        { &ei_rtpproxy_timeout,
          { "rtpproxy.response_timeout", PI_RESPONSE_CODE, PI_WARN,
            "TIMEOUT", EXPFILL }},
        { &ei_rtpproxy_notify_no_ip,
          { "rtpproxy.notify_no_ip", PI_RESPONSE_CODE, PI_COMMENT,
            "No notification IP address provided. Using ip.src or ipv6.src as a value.", EXPFILL }},
        { &ei_rtpproxy_bad_ipv4,
          { "rtpproxy.bad_ipv4", PI_MALFORMED, PI_ERROR,
            "Bad IPv4", EXPFILL }},
        { &ei_rtpproxy_bad_ipv6,
          { "rtpproxy.bad_ipv6", PI_MALFORMED, PI_ERROR,
            "Bad IPv6", EXPFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_rtpproxy,
        &ett_rtpproxy_request,
        &ett_rtpproxy_command,
        &ett_rtpproxy_command_parameters,
        &ett_rtpproxy_command_parameters_codecs,
        &ett_rtpproxy_command_parameters_local,
        &ett_rtpproxy_command_parameters_remote,
        &ett_rtpproxy_command_parameters_repacketize,
        &ett_rtpproxy_command_parameters_dtmf,
        &ett_rtpproxy_command_parameters_cmap,
        &ett_rtpproxy_command_parameters_proto,
        &ett_rtpproxy_command_parameters_transcode,
        &ett_rtpproxy_command_parameters_acc,
        &ett_rtpproxy_tag,
        &ett_rtpproxy_notify,
        &ett_rtpproxy_reply,
        &ett_rtpproxy_ng_bencode
    };

    proto_rtpproxy = proto_register_protocol ("Sippy RTPproxy Protocol", "RTPproxy", "rtpproxy");
    rtpproxy_handle = register_dissector("rtpproxy", dissect_rtpproxy, proto_rtpproxy);

    proto_register_field_array(proto_rtpproxy, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_rtpproxy_module = expert_register_protocol(proto_rtpproxy);
    expert_register_field_array(expert_rtpproxy_module, ei, array_length(ei));

    rtpproxy_module = prefs_register_protocol(proto_rtpproxy, rtpproxy_prefs_apply);

    prefs_register_bool_preference(rtpproxy_module, "establish_conversation",
                                 "Establish Media Conversation",
                                 "Specifies that RTP/RTCP/T.38/MSRP/etc streams are decoded based "
                                 "upon port numbers found in RTPproxy answers",
                                 &rtpproxy_establish_conversation);

    prefs_register_uint_preference(rtpproxy_module, "reply.timeout",
                                 "RTPproxy reply timeout", /* Title */
                                 "Maximum timeout value in waiting for reply from RTPProxy (in milliseconds).", /* Descr */
                                 10,
                                 &rtpproxy_timeout);
}

void
proto_reg_handoff_rtpproxy(void)
{
    static gboolean rtpproxy_initialized = FALSE;

    if(!rtpproxy_initialized){
        /* Register TCP port for dissection */
        dissector_add_uint_range_with_preference("tcp.port", RTPPROXY_PORT, rtpproxy_handle);
        dissector_add_uint_range_with_preference("udp.port", RTPPROXY_PORT, rtpproxy_handle);
        rtpproxy_prefs_apply();
        rtpproxy_initialized = TRUE;
    }

    rtcp_handle   = find_dissector_add_dependency("rtcp", proto_rtpproxy);
    rtp_events_handle    = find_dissector_add_dependency("rtpevent", proto_rtpproxy);
    rtp_handle    = find_dissector_add_dependency("rtp", proto_rtpproxy);
    bencode_handle = find_dissector_add_dependency("bencode", proto_rtpproxy);

    /* Calculate nstime_t struct for the timeout from the rtpproxy_timeout value in milliseconds */
    rtpproxy_timeout_ns.secs = (rtpproxy_timeout - rtpproxy_timeout % 1000) / 1000;
    rtpproxy_timeout_ns.nsecs = (rtpproxy_timeout % 1000) * 1000;
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
