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
#include <epan/addr_resolv.h>
#include <epan/strutil.h>

/* For setting up RTP/RTCP dissectors based on the RTPproxy's answers */
#include "packet-rtp.h"
#include "packet-rtp_pt.h"
#include "packet-rtcp.h"

void proto_register_rtpproxy(void);

static dissector_handle_t rtpproxy_handle;

static int proto_rtpproxy;

static int hf_rtpproxy_cookie;
static int hf_rtpproxy_error;
static int hf_rtpproxy_status;
static int hf_rtpproxy_ok;
static int hf_rtpproxy_ipv4;
static int hf_rtpproxy_ipv6;
static int hf_rtpproxy_port;
static int hf_rtpproxy_lf;
static int hf_rtpproxy_request;
static int hf_rtpproxy_command;
static int hf_rtpproxy_command_parameters;
static int hf_rtpproxy_command_parameter;
static int hf_rtpproxy_command_parameter_codec;
static int hf_rtpproxy_command_parameter_local_ipv4;
static int hf_rtpproxy_command_parameter_local_ipv6;
static int hf_rtpproxy_command_parameter_local_label;
static int hf_rtpproxy_command_parameter_remote_ipv4;
static int hf_rtpproxy_command_parameter_remote_ipv6;
static int hf_rtpproxy_command_parameter_repacketize;
static int hf_rtpproxy_command_parameter_dtmf;
/* static int hf_rtpproxy_command_parameter_cmap; TODO */
static int hf_rtpproxy_command_parameter_transcode;
static int hf_rtpproxy_command_parameter_acc;
static int hf_rtpproxy_callid;
static int hf_rtpproxy_copy_target;
static int hf_rtpproxy_playback_filename;
static int hf_rtpproxy_playback_codec;
static int hf_rtpproxy_stat_name;
static int hf_rtpproxy_notify;
static int hf_rtpproxy_notify_ipv4;
static int hf_rtpproxy_notify_ipv6;
static int hf_rtpproxy_notify_port;
static int hf_rtpproxy_notify_path;
static int hf_rtpproxy_notify_wildcard;
static int hf_rtpproxy_notify_tag;
static int hf_rtpproxy_tag;
static int hf_rtpproxy_mediaid;
static int hf_rtpproxy_reply;
static int hf_rtpproxy_version_request;
static int hf_rtpproxy_version_supported;
static int hf_rtpproxy_ng_bencode;
static int hf_rtpproxy_subcommand;
static int hf_rtpproxy_subcommand_result;

/* Expert fields */
static expert_field ei_rtpproxy_timeout;
static expert_field ei_rtpproxy_notify_no_ip;
static expert_field ei_rtpproxy_bad_ipv4;
static expert_field ei_rtpproxy_bad_ipv6;

/* Request/response tracking */
static int hf_rtpproxy_request_in;
static int hf_rtpproxy_response_in;
static int hf_rtpproxy_response_time;

typedef struct _rtpproxy_info {
    uint32_t req_frame;
    uint32_t resp_frame;
    nstime_t req_time;
    char* callid;
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
    { "20150617", "Support for the wildcard %%CC_SELF%% as a disconnect notify target" },
    { "20191015", "Support for the && sub-command specifier" },
    { "20200226", "Support for the N command to stop recording" },
    { "20250523", "Support for the \"P\" modifier in the C command" },
    { "20260306", "Support for address labels in the \"Ul\"/\"Ll\" commands" },
    { NULL, NULL }
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
    { 'N', "Stop recording"},
    { 'n', "Stop recording"},
    { 'C', "Copy stream"},
    { 'c', "Copy stream"},
    { 'Q', "Query info about a session"},
    { 'q', "Query info about a session"},
    { 'G', "Get statistics"},
    { 'g', "Get statistics"},
    { 0, NULL }
};

static const value_string paramtypenames[] = {
    /* Official command parameters */
    {'4', "Remote address is IPv4"},
    {'6', "Remote address is IPv6"},
    {'a', "Asymmetric stream / All the recordings"},
    {'A', "Asymmetric stream / All the recordings"},
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
    {'p', "reply with the recording Port"},
    {'P', "reply with the recording Port"},
    {'r', "Remote address"},
    {'R', "Remote address"},
    {'s', "Symmetric stream / Single file"},
    {'S', "Symmetric stream / Single file"},
    {'v', "Verbose"},
    {'V', "Verbose"},
    {'w', "Weak connection (allows roaming)"},
    {'W', "Weak connection (allows roaming)"},
    {'z', "repacketiZe"},
    {'Z', "repacketiZe"},
    /* Unofficial command parameters / extensions */
    {'d', "DTMF payload ID (unofficial extension)"},
    {'D', "DTMF payload ID (unofficial extension)"},
    {'m', "codec Mapping (unofficial extension)"},
    {'M', "codec Mapping (unofficial extension)"},
    {'t', "Transcode to (unofficial extension)"},
    {'T', "Transcode to (unofficial extension)"},
    {'u', "accoUnting (unofficial extension)"},
    {'U', "accoUnting (unofficial extension)"},
    {0, NULL}
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
    { "E37", "Syntax error: can't resolve remote address (INVLARG_7)" },
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
    { NULL, NULL }
};

static int ett_rtpproxy;

static int ett_rtpproxy_request;
static int ett_rtpproxy_command;
static int ett_rtpproxy_command_parameters;
static int ett_rtpproxy_command_parameters_codecs;
static int ett_rtpproxy_command_parameters_local;
static int ett_rtpproxy_command_parameters_remote;
static int ett_rtpproxy_command_parameters_repacketize;
static int ett_rtpproxy_command_parameters_dtmf;
static int ett_rtpproxy_command_parameters_cmap;
static int ett_rtpproxy_command_parameters_transcode;
static int ett_rtpproxy_command_parameters_acc;
static int ett_rtpproxy_tag;
static int ett_rtpproxy_notify;

static int ett_rtpproxy_reply;

static int ett_rtpproxy_ng_bencode;

static int ett_rtpproxy_subcommands;

/* The wildcard standing for the address of the control connection. Spelled
 * with the doubled percent signs on the wire - see CC_SELF_STR in the RTPproxy
 * sources.
 */
#define RTPPROXY_CC_SELF "%%CC_SELF%%"

/* Default values */
#define RTPPROXY_PORT "22222"  /* Not IANA registered */
static range_t* rtpproxy_tcp_range;
static range_t* rtpproxy_udp_range;

static bool rtpproxy_establish_conversation = true;
/* See - https://www.opensips.org/html/docs/modules/1.10.x/rtpproxy.html#id293555 */
/* See - http://www.kamailio.org/docs/modules/4.3.x/modules/rtpproxy.html#idp15794952 */
static unsigned rtpproxy_timeout = 1000;
static nstime_t rtpproxy_timeout_ns;

void proto_reg_handoff_rtpproxy(void);

/* Find the end of the field starting at the offset - either the whitespace
 * separating it from the next one or the end of the command, whichever comes
 * first.
 */
static unsigned
rtpproxy_field_end(tvbuff_t *tvb, unsigned offset, unsigned realsize)
{
    unsigned end;

    tvb_find_uint8_length(tvb, offset, realsize - offset, ' ', &end);
    return end;
}

/* Step over the whitespace separating two fields of a command. Returns false
 * once the command has been consumed entirely - the fields the caller was
 * about to dissect are simply not there, which is what a truncated command
 * looks like.
 */
static bool
rtpproxy_next_field(tvbuff_t *tvb, unsigned *offset, unsigned new_offset, unsigned realsize)
{
    if (new_offset >= realsize)
        return false;

    *offset = tvb_skip_wsp(tvb, new_offset, realsize - new_offset);
    return (*offset < realsize);
}

/* RTPproxy-ng (bencode) payloads start with a bencoded dictionary or list,
 * e.g. "d7:command6:offer" - never with a plain command letter.
 */
static bool
rtpproxy_is_bencode(tvbuff_t *tvb, unsigned offset, unsigned realsize)
{
    uint8_t tmp;

    if (offset + 2 >= realsize)
        return false;

    tmp = tvb_get_uint8(tvb, offset + 1);
    return (('1' <= tmp) && (tmp <= '9') && (tvb_get_uint8(tvb, offset + 2) == ':'));
}

/* Find the next "&&" sub-command separator within [offset, realsize).
 * RTPproxy splits the command on whitespace and treats an argument which is
 * exactly "&&" as a separator, so a bare "&&" inside a Call-ID or a tag is
 * not one.
 */
static bool
rtpproxy_find_subcommand(tvbuff_t *tvb, unsigned offset, unsigned realsize, unsigned *sep_offset)
{
    unsigned pos = offset;

    while (pos < realsize) {
        if (!tvb_find_uint8_length(tvb, pos, realsize - pos, '&', &pos))
            return false;
        if ((pos > 0) && (tvb_get_uint8(tvb, pos - 1) == ' ') &&
            (pos + 1 < realsize) && (tvb_get_uint8(tvb, pos + 1) == '&') &&
            ((pos + 2 == realsize) || (tvb_get_uint8(tvb, pos + 2) == ' '))) {
            *sep_offset = pos;
            return true;
        }
        pos++;
    }
    return false;
}

/* Dissect the "&& subcommand1 && subcommand2 ..." trailer of a request, or the
 * matching "&& result1 && result2 ..." trailer of a reply.
 */
static void
rtpproxy_add_subcommands(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtpproxy_tree,
    unsigned begin, unsigned realsize, bool is_reply)
{
    proto_tree *another_tree;
    unsigned offset = begin;
    unsigned end;
    unsigned next;
    const uint8_t* tmpstr;

    another_tree = proto_tree_add_subtree(rtpproxy_tree, tvb, begin, realsize - begin,
        ett_rtpproxy_subcommands, NULL, is_reply ? "Sub-command results" : "Sub-commands");

    while (offset < realsize) {
        /* Skip the "&&" separator itself along with the whitespace following it.
         * Note that the offset always points at a separator here, so this is
         * what makes the loop advance on an empty sub-command as well.
         */
        offset += (unsigned)strlen("&&");
        if (offset >= realsize)
            break; /* A dangling separator */
        offset = tvb_skip_wsp(tvb, offset, realsize - offset);
        if (offset == realsize)
            break; /* A dangling separator */

        if (!rtpproxy_find_subcommand(tvb, offset, realsize, &next))
            next = realsize; /* That was the last one */
        /* Don't count the whitespace preceding the next separator */
        end = next;
        while ((end > offset) && (tvb_get_uint8(tvb, end - 1) == ' '))
            end--;

        if (end > offset) {
            proto_tree_add_item_ret_string(another_tree,
                is_reply ? hf_rtpproxy_subcommand_result : hf_rtpproxy_subcommand,
                tvb, offset, end - offset, ENC_ASCII | ENC_NA, pinfo->pool, &tmpstr);
            col_append_fstr(pinfo->cinfo, COL_INFO, is_reply ? ", Result: %s" : ", Sub-command: %s", tmpstr);
        }

        if (next == realsize)
            break;
        offset = next;
    }
}

static bool
rtpproxy_add_tag(tvbuff_t *tvb, packet_info* pinfo, proto_tree* rtpproxy_tree, unsigned *offset, unsigned realsize)
{
    proto_item *ti = NULL;
    proto_tree *another_tree = NULL;
    unsigned begin = *offset;
    unsigned new_offset;
    unsigned end;
    const uint8_t* tmpstr;

    if (begin >= realsize)
        return false; /* Nothing left */

    end = rtpproxy_field_end(tvb, begin, realsize);

    /* SER/OpenSER/OpenSIPS/Kamailio adds Media-ID right after the Tag
     * separated by a semicolon
     */
    if(!tvb_find_uint8_length(tvb, begin, end - begin, ';', &new_offset)){
        ti = proto_tree_add_item_ret_string(rtpproxy_tree, hf_rtpproxy_tag, tvb, begin, end - begin, ENC_ASCII | ENC_NA, pinfo->pool, &tmpstr);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Tag: %s", tmpstr);
        another_tree = proto_item_add_subtree(ti, ett_rtpproxy_tag);
        ti = proto_tree_add_item(another_tree, hf_rtpproxy_mediaid, tvb, begin, 0, ENC_ASCII);
        proto_item_append_text(ti, "<skipped>");
        proto_item_set_generated(ti);
    } else {
        ti = proto_tree_add_item_ret_string(rtpproxy_tree, hf_rtpproxy_tag, tvb, begin, new_offset - begin, ENC_ASCII | ENC_NA, pinfo->pool, &tmpstr);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Tag: %s", tmpstr);
        if (new_offset == begin){
            proto_item_append_text(ti, "<skipped>"); /* A very first Offer/Update command */
            proto_item_set_generated(ti);
        }
        another_tree = proto_item_add_subtree(ti, ett_rtpproxy_tag);
        proto_tree_add_item_ret_string(another_tree, hf_rtpproxy_mediaid, tvb, new_offset+1, end - (new_offset+1), ENC_ASCII | ENC_NA, pinfo->pool, &tmpstr);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Media id: %s", tmpstr);
    }
    if (end == realsize) {
        return false;
    } else {
        *offset = end;
        return true;
    }
}

/* Dissect the address of the "L"/"R" command modifiers. RTPproxy takes either
 * a plain IPv4 address or an IPv6 one enclosed in square brackets. Returns
 * false if there is no address at all - "L" doubles as the "load average"
 * modifier of the "I" command.
 */
static bool
rtpproxy_add_parameter_addr(tvbuff_t *tvb, packet_info *pinfo, proto_item *ti, int ett,
    const char* rawstr, unsigned *offset, int hf_ipv4, int hf_ipv6)
{
    proto_tree *another_tree;
    unsigned begin;
    unsigned len;
    uint32_t ipaddr[4]; /* Enough room for IPv4 or IPv6 */

    if (rawstr[*offset] == '['){
        begin = *offset + (unsigned)strlen("[");
        len = (unsigned)strspn(rawstr + begin, "0123456789abcdefABCDEF:");
        if ((len == 0) || (rawstr[begin + len] != ']'))
            return false; /* Unterminated */
        another_tree = proto_item_add_subtree(ti, ett);
        if(str_to_ip6((char*)tvb_get_string_enc(pinfo->pool, tvb, begin, len, ENC_ASCII), ipaddr))
            proto_tree_add_ipv6(another_tree, hf_ipv6, tvb, begin, len, (const ws_in6_addr*)ipaddr);
        else
            proto_tree_add_expert(another_tree, pinfo, &ei_rtpproxy_bad_ipv6, tvb, begin, len);
        *offset = begin + len + (unsigned)strlen("]");
        return true;
    }

    begin = *offset;
    len = (unsigned)strspn(rawstr + begin, "0123456789.");
    if (len == 0)
        return false;
    another_tree = proto_item_add_subtree(ti, ett);
    if(str_to_ip((char*)tvb_get_string_enc(pinfo->pool, tvb, begin, len, ENC_ASCII), ipaddr))
        proto_tree_add_ipv4(another_tree, hf_ipv4, tvb, begin, len, ipaddr[0]);
    else
        proto_tree_add_expert(another_tree, pinfo, &ei_rtpproxy_bad_ipv4, tvb, begin, len);
    *offset = begin + len;
    return true;
}

static void
rtpproxy_add_parameter(tvbuff_t *parent_tvb, packet_info *pinfo, proto_tree *rtpproxy_tree, unsigned begin, unsigned realsize)
{
    proto_item *ti;
    proto_tree *another_tree = NULL;
    tvbuff_t *tvb;
    unsigned offset = 0;
    unsigned new_offset = 0;
    uint8_t parameter_type;
    uint16_t parameter_value;
    const char* rawstr = NULL;

    /* Extract the entire parameters line. */
    /* Something like "t4p1iic8,0,2,4,18,96,97,98,100,101" */
    rawstr = (char*)tvb_get_string_enc(pinfo->pool, parent_tvb, begin, realsize, ENC_ASCII);

    tvb = tvb_new_subset_length(parent_tvb, begin, realsize);

    while (tvb_reported_length_remaining(tvb, offset)) {
        ti = proto_tree_add_item_ret_uint8(rtpproxy_tree, hf_rtpproxy_command_parameter, tvb, offset, 1, ENC_ASCII, &parameter_type);
        offset++; /* Skip 1-byte parameter's type */
        switch (g_ascii_tolower(parameter_type))
        {
            /* Official long parameters */
            case 'c':
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_codecs);
                while (tvb_get_string_uint16(tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_STR_DEC, &parameter_value, &new_offset)) {
                    ti = proto_tree_add_uint(another_tree, hf_rtpproxy_command_parameter_codec, tvb, offset, new_offset - offset, parameter_value);
                    proto_item_append_text(ti, " (%s)", val_to_str_ext_const(parameter_value, &rtp_payload_type_vals_ext, "Unknown"));
                    offset = new_offset;
                    if (tvb_reported_length_remaining(tvb, offset) && tvb_get_uint8(tvb, offset) == ',') {
                        offset++; /* skip comma */
                    }
                }
                break;
            case 'l':
                /* That's another one protocol shortcoming - the same parameter used twice. */
                /* https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#createupdatelookup-session */
                /* https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#get-information */
                if (rawstr[offset] == '{'){
                    /* A bind address label instead of an address - since the
                     * 20260306 protocol version */
                    new_offset = (unsigned)strcspn(rawstr + offset + (unsigned)strlen("{"), "}");
                    if ((new_offset == 0) || (rawstr[offset + (unsigned)strlen("{") + new_offset] != '}'))
                        break; /* Empty or unterminated */
                    another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_local);
                    proto_tree_add_item(another_tree, hf_rtpproxy_command_parameter_local_label, tvb, offset + (unsigned)strlen("{"), new_offset, ENC_ASCII);
                    offset += new_offset + (unsigned)strlen("{}");
                    break;
                }
                rtpproxy_add_parameter_addr(tvb, pinfo, ti, ett_rtpproxy_command_parameters_local,
                    rawstr, &offset, hf_rtpproxy_command_parameter_local_ipv4,
                    hf_rtpproxy_command_parameter_local_ipv6);
                break;
            case 'r':
                rtpproxy_add_parameter_addr(tvb, pinfo, ti, ett_rtpproxy_command_parameters_remote,
                    rawstr, &offset, hf_rtpproxy_command_parameter_remote_ipv4,
                    hf_rtpproxy_command_parameter_remote_ipv6);
                break;
            case 'z':
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_repacketize);
                tvb_get_string_uint16(tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_STR_DEC, &parameter_value, &new_offset);
                proto_tree_add_uint(another_tree, hf_rtpproxy_command_parameter_repacketize, tvb, offset, new_offset - offset, parameter_value);
                offset = new_offset;
                break;
            /* Unofficial long parameters */
            case 'd':
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_dtmf);
                tvb_get_string_uint16(tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_STR_DEC, &parameter_value, &new_offset);
                proto_tree_add_uint(another_tree, hf_rtpproxy_command_parameter_dtmf, tvb, offset, new_offset - offset, parameter_value);
                if(rtpproxy_establish_conversation){
                    dissector_add_uint("rtp.pt", parameter_value, rtp_events_handle);
                }
                offset = new_offset;
                break;
            case 'm':
                new_offset = (int)strspn(rawstr+offset, "0123456789=,");
                /* TODO */
                offset += new_offset;
                break;
            case 't':
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_transcode);
                tvb_get_string_uint16(tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_STR_DEC, &parameter_value, &new_offset);
                ti = proto_tree_add_uint(another_tree, hf_rtpproxy_command_parameter_transcode, tvb, offset, new_offset - offset, parameter_value);
                proto_item_append_text(ti, " (%s)", val_to_str_ext_const(parameter_value, &rtp_payload_type_vals_ext, "Unknown"));
                offset = new_offset;
                break;
            case 'u':
                if (!tvb_reported_length_remaining(tvb, offset))
                    break; /* No value supplied */
                another_tree = proto_item_add_subtree(ti, ett_rtpproxy_command_parameters_acc);
                proto_tree_add_item(another_tree, hf_rtpproxy_command_parameter_acc, tvb, offset, 1, ENC_ASCII);
                offset++;
                break;
            default:
                break;
        }
    }
}

static rtpproxy_info_t *
rtpproxy_add_tid(bool is_request, tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtpproxy_tree, rtpproxy_conv_info_t *rtpproxy_conv, const char* cookie)
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

/* Take the notification address from ip.src/ipv6.src - either because only a
 * port was supplied or because the wildcard asked for the address of the
 * control connection.
 */
static void
rtpproxy_add_notify_src_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtpproxy_tree, unsigned begin)
{
    proto_item *ti = NULL;

    if (pinfo->src.type == AT_IPv4) {
        uint32_t addr;
        memcpy(&addr, pinfo->src.data, 4);
        ti = proto_tree_add_ipv4(rtpproxy_tree, hf_rtpproxy_notify_ipv4, tvb, begin, 0, addr);
    } else if (pinfo->src.type == AT_IPv6) {
        ti = proto_tree_add_ipv6(rtpproxy_tree, hf_rtpproxy_notify_ipv6, tvb, begin, 0, (const ws_in6_addr *)(pinfo->src.data));
    }
    if (ti) {
        proto_item_set_generated(ti);
    }
}

static void
rtpproxy_add_notify_addr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *rtpproxy_tree, unsigned begin, unsigned end)
{
    unsigned offset = 0, end_offset;
    unsigned tmp;
    unsigned hbegin, hend;
    bool ipv6 = false;
    uint32_t ipaddr[4]; /* Enough room for IPv4 or IPv6 */
    uint16_t port;
    const char* rawstr;

    if (begin >= end)
        return;

    rawstr = (const char*)tvb_get_string_enc(pinfo->pool, tvb, begin, end - begin, ENC_ASCII);

    /* RTPproxy takes either a local (unix domain) socket - "unix:<path>", or
     * just a path for compatibility with the 1.0-2.0 releases - or an INET
     * one, "tcp:<host>:<port>". See parse_timeout_sock() in its sources.
     */
    if (g_str_has_prefix(rawstr, "unix:"))
        begin += (unsigned)strlen("unix:");
    else if (g_str_has_prefix(rawstr, "tcp:"))
        begin += (unsigned)strlen("tcp:");

    if (begin >= end)
        return; /* A prefix and nothing else */

    if (g_str_has_prefix(rawstr, "unix:")) {
        proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_path, tvb, begin, end - begin, ENC_ASCII);
        return;
    }

    /* Check for at least one colon */
    if (tvb_find_uint8_length(tvb, begin, end - begin, ':', &offset)) {
        /* Find if it's the latest colon (not in case of a IPv6) */
        while ((tvb_find_uint8_length(tvb, offset+1, end - (offset+1), ':', &tmp))) {
            ipv6 = true;
            offset = tmp;
        }
        /* We have ip:port, with the address possibly enclosed in brackets */
        hbegin = begin;
        hend = offset;
        if ((tvb_get_uint8(tvb, hbegin) == '[') && (hend > hbegin + 1) &&
            (tvb_get_uint8(tvb, hend - 1) == ']')) {
            hbegin += (unsigned)strlen("[");
            hend -= (unsigned)strlen("]");
            ipv6 = true;
        }
        /* The "%%CC_SELF%%" wildcard stands for the address the command has
         * arrived from - since the 20150617 protocol version */
        if (strcmp((const char*)tvb_get_string_enc(pinfo->pool, tvb, hbegin, hend - hbegin, ENC_ASCII), RTPPROXY_CC_SELF) == 0){
            proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_wildcard, tvb, hbegin, hend - hbegin, ENC_ASCII);
            rtpproxy_add_notify_src_addr(tvb, pinfo, rtpproxy_tree, hbegin);
        }
        else if(ipv6){
            if(str_to_ip6((char*)tvb_get_string_enc(pinfo->pool, tvb, hbegin, hend - hbegin, ENC_ASCII), ipaddr))
                proto_tree_add_ipv6(rtpproxy_tree, hf_rtpproxy_notify_ipv6, tvb, hbegin, hend - hbegin, (const ws_in6_addr*)ipaddr);
            else
                proto_tree_add_expert(rtpproxy_tree, pinfo, &ei_rtpproxy_bad_ipv6, tvb, hbegin, hend - hbegin);
        }
        else{
            if(str_to_ip((char*)tvb_get_string_enc(pinfo->pool, tvb, hbegin, hend - hbegin, ENC_ASCII), ipaddr))
                proto_tree_add_ipv4(rtpproxy_tree, hf_rtpproxy_notify_ipv4, tvb, hbegin, hend - hbegin, ipaddr[0]);
            else
                proto_tree_add_expert(rtpproxy_tree, pinfo, &ei_rtpproxy_bad_ipv4, tvb, hbegin, hend - hbegin);
        }
        tvb_get_string_uint16(tvb, offset+1, end - (offset+1), ENC_STR_DEC, &port, &end_offset);
        proto_tree_add_uint(rtpproxy_tree, hf_rtpproxy_notify_port, tvb, offset+1, end_offset - (offset + 1), port);
    }
    else{
        /* No colon at all - a local socket path unless it's a bare port */
        if (strspn(rawstr, "0123456789") != strlen(rawstr)) {
            proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_path, tvb, begin, end - begin, ENC_ASCII);
            return;
        }

        /* Only port is supplied - take IPv4/IPv6 from  ip.src/ipv6.src respectively */
        expert_add_info(pinfo, rtpproxy_tree, &ei_rtpproxy_notify_no_ip);
        rtpproxy_add_notify_src_addr(tvb, pinfo, rtpproxy_tree, begin);
        tvb_get_string_uint16(tvb, begin, end - begin, ENC_STR_DEC, &port, &end_offset);
        proto_tree_add_uint(rtpproxy_tree, hf_rtpproxy_notify_port, tvb, begin, end_offset - begin, port);
    }
}

static int
dissect_rtpproxy(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    bool has_lf = false;
    unsigned offset = 0;
    unsigned new_offset = 0;
    unsigned tmp;
    unsigned realsize = 0;
    unsigned fullsize;
    unsigned subc_offset = 0;
    bool is_reply;
    proto_tree *rtpproxy_main_tree;
    const char* rawstr;
    const char* tmpstr;
    proto_item *ti;
    proto_item *ti2;
    proto_tree *rtpproxy_tree;
    conversation_t *conversation;
    rtpproxy_conv_info_t *rtpproxy_conv;
    const char* cookie = NULL;
    /* For RT(C)P setup */
    address addr;
    uint16_t port, codec;
    uint32_t ipaddr[4]; /* Enough room for IPv4 or IPv6 */
    rtpproxy_info_t *rtpproxy_info = NULL;
    tvbuff_t *subtvb;

    /* If it does not start with a printable character it's not RTPProxy */
    if(!g_ascii_isprint(tvb_get_uint8(tvb, 0)))
        return 0;

    /* Extract Cookie */
    if(!tvb_find_uint8_remaining(tvb, offset, ' ', &offset))
        return 0;

    /* We believe it's likely a RTPproxy / RTPproxy-ng protocol */
    /* Note: we no longer distinct between packets with or w/o LF - it turned
     * out to be useless */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPproxy");

    /* Clear out stuff in the info column - we'll set it later */
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_rtpproxy, tvb, 0, -1, ENC_NA);
    rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy);
    rtpproxy_main_tree = rtpproxy_tree;

    proto_tree_add_item_ret_string(rtpproxy_tree, hf_rtpproxy_cookie, tvb, 0, offset, ENC_ASCII | ENC_NA, pinfo->pool, (const uint8_t**)&cookie);

    /* Skip whitespace */
    offset = tvb_skip_wsp(tvb, offset+1, tvb_captured_length(tvb));

    /* Calculate size to prevent recalculation in the future */
    realsize = tvb_reported_length(tvb);

    /* Don't count trailing zeroes (inserted by some SIP-servers sometimes) */
    while ((realsize > 0) && (tvb_get_uint8(tvb, realsize - 1) == 0)){
        realsize -= 1;
    }

    /* Check for LF (required for TCP connection, optional for UDP) */
    if ((realsize > 0) && (tvb_get_uint8(tvb, realsize - 1) == '\n')){
        /* Don't count trailing LF */
        realsize -= 1;
        has_lf = true;
    }

    /* A cookie and nothing else - there is no command to dissect */
    if (offset >= realsize)
        return tvb_captured_length(tvb);

    /* Try to create conversation */
    conversation = find_or_create_conversation(pinfo);
    rtpproxy_conv = (rtpproxy_conv_info_t *)conversation_get_proto_data(conversation, proto_rtpproxy);
    if (!rtpproxy_conv) {
        rtpproxy_conv = wmem_new(wmem_file_scope(), rtpproxy_conv_info_t);
        rtpproxy_conv->trans = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conversation, proto_rtpproxy, rtpproxy_conv);
    }

    /* Extract command */
    tmp = g_ascii_tolower(tvb_get_uint8(tvb, offset));

    /* Only the "U", "L" and "Q" commands accept sub-commands, and their replies
     * carry one result per sub-command. Cut them off so that the command itself
     * isn't parsed as if the sub-commands were its own arguments - the "&&"
     * would otherwise be reported as a tag.
     *
     * https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#sub-commands
     */
    fullsize = realsize;
    is_reply = (g_ascii_isdigit(tmp) != 0);
    if ((is_reply || (tmp == 'u') || (tmp == 'l') || (tmp == 'q')) &&
        (!rtpproxy_is_bencode(tvb, offset, realsize)) &&
        rtpproxy_find_subcommand(tvb, offset, realsize, &subc_offset)) {
        realsize = subc_offset;
        /* Don't count the whitespace preceding the first separator */
        while ((realsize > offset) && (tvb_get_uint8(tvb, realsize - 1) == ' '))
            realsize--;
    }

    /* Get payload string */
    rawstr = (char*)tvb_format_text_wsp(pinfo->pool, tvb, offset, realsize - offset);
    switch (tmp)
    {
        case 's':
            /* A specific case - long info answer */
            /* %COOKIE% sessions created %NUM0% active sessions: %NUM1% */
            /* FIXME https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#information */
            rtpproxy_add_tid(false, tvb, pinfo, rtpproxy_tree, rtpproxy_conv, cookie);
            if ((offset + 1 < realsize) && ('e' == tvb_get_uint8(tvb, offset+1))){
                col_add_fstr(pinfo->cinfo, COL_INFO, "Reply: %s", rawstr);
                ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_reply, tvb, offset, -1, ENC_NA);

                rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_reply);
                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_status, tvb, offset, realsize - offset, ENC_ASCII);
                break;
            }
        /* FALL THROUGH */
        case 'i':
        case 'x':
        case 'u':
        case 'l':
        case 'd':
            if(rtpproxy_is_bencode(tvb, offset, realsize)){
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTPproxy-ng");
                col_add_fstr(pinfo->cinfo, COL_INFO, "RTPproxy-ng: %s", rawstr);
                ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_ng_bencode, tvb, offset, -1, ENC_ASCII);
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
        case 'g':
        case 'n':
            rtpproxy_info = rtpproxy_add_tid(true, tvb, pinfo, rtpproxy_tree, rtpproxy_conv, cookie);
            col_add_fstr(pinfo->cinfo, COL_INFO, "Request: %s", val_to_str_const(tvb_get_uint8(tvb, offset), commandtypenames, "Unknown command code"));
            ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_request, tvb, offset, -1, ENC_NA);
            rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_request);

            /* A specific case - version request:
             * https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#get-list-of-veatures
             *
             * In this case a command size must be bigger or equal to a "VF YYYYMMDD" string size.
             * It's bigger if there is more than one space inserted between "VF" and "YYYYMMDD" tokens.
             */
            if ((tmp == 'v') && (offset + (int)strlen("VF YYYYMMDD") <= realsize)){
                /* Skip whitespace between "VF" and "YYYYMMDD" tokens */
                new_offset = tvb_skip_wsp(tvb, offset + ((unsigned)strlen("VF") + 1), tvb_captured_length(tvb));
                ti = proto_tree_add_item_ret_string(rtpproxy_tree, hf_rtpproxy_version_request, tvb, new_offset, (int)strlen("YYYYMMDD"), ENC_ASCII | ENC_NA, pinfo->pool, (const uint8_t**)&tmpstr);
                proto_item_append_text(ti, " (%s)", str_to_str_wmem(pinfo->pool, tmpstr, versiontypenames, "Unknown"));
                break;
            }

            /* All other commands */
            ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_command, tvb, offset, 1, ENC_ASCII);

            /* A specific case - handshake/ping */
            if (tmp == 'v')
                break; /* No more parameters */

            /* A specific case - close all calls */
            if (tmp == 'x')
                break; /* No more parameters */

            /* Extract parameters */
            /* Parameters should be right after the command and before EOL (in case of Info command) or before whitespace */
            //new_offset = (tmp == 'i' ? (realsize - 1 > offset ? offset + (int)strlen("Ib") : offset + (int)strlen("I")) : tvb_find_uint8(tvb, offset, -1, ' '));
            if (tmp == 'i') {
                if (realsize - 1 > offset) {
                    new_offset = offset + (int)strlen("Ib");
                } else {
                    new_offset = offset + (int)strlen("I");
                }
            } else {
                /* The modifiers end either at the whitespace separating them
                 * from the first argument or at the end of the command - the
                 * latter for the commands taking no arguments at all */
                new_offset = rtpproxy_field_end(tvb, offset, realsize);
            }
            if (new_offset != offset + 1){
                rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_command);
                ti2 = proto_tree_add_item_ret_string(rtpproxy_tree, hf_rtpproxy_command_parameters, tvb, offset+1, new_offset - (offset+1), ENC_ASCII | ENC_NA, pinfo->pool, (const uint8_t**)&tmpstr);
                col_append_fstr(pinfo->cinfo, COL_INFO, " %s", tmpstr);
                rtpproxy_add_parameter(tvb, pinfo, proto_item_add_subtree(ti2, ett_rtpproxy_command_parameters), offset+1, new_offset - (offset+1));
                rtpproxy_tree = proto_item_get_parent(ti);
            }

            /* A specific case - query information */
            if (tmp == 'i')
                break; /* No more parameters */

            /* A specific case - get statistics. There is no Call-ID, just an
             * optional list of the requested counters:
             * https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#get-statistics
             */
            if (tmp == 'g'){
                while (new_offset < realsize){
                    /* Skip whitespace */
                    offset = tvb_skip_wsp(tvb, new_offset, realsize - new_offset);
                    if (offset == realsize)
                        break; /* Trailing whitespace only */
                    tvb_find_uint8_length(tvb, offset, realsize - offset, ' ', &new_offset);
                    proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_stat_name, tvb, offset, new_offset - offset, ENC_ASCII);
                }
                break; /* No more parameters */
            }

            /* Skip whitespace */
            if (!rtpproxy_next_field(tvb, &offset, new_offset, realsize))
                break; /* No more parameters */

            /* Extract Call-ID */
            new_offset = rtpproxy_field_end(tvb, offset, realsize);
            proto_tree_add_item_ret_string(rtpproxy_tree, hf_rtpproxy_callid, tvb, offset, new_offset - offset, ENC_ASCII | ENC_NA, pinfo->pool, (const uint8_t**)&tmpstr);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Call-ID: %s", tmpstr);
            if(rtpproxy_info && !rtpproxy_info->callid)
                rtpproxy_info->callid = (char*)tvb_get_string_enc(wmem_file_scope(), tvb, offset, new_offset - offset, ENC_ASCII);
            /* Skip whitespace */
            if (!rtpproxy_next_field(tvb, &offset, new_offset, realsize))
                break; /* No more parameters */

            /* Extract IP and Port in case of Offer/Answer */
            if ((tmp == 'u') || (tmp == 'l')){
                /* Extract IP */
                new_offset = rtpproxy_field_end(tvb, offset, realsize);
                if (!tvb_find_uint8_length(tvb, offset, new_offset - offset, ':', NULL)){
                    tmpstr = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, new_offset - offset, ENC_ASCII);
                    if (str_to_ip(tmpstr, ipaddr)) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, ", IP: %s", tmpstr);
                        proto_tree_add_ipv4(rtpproxy_tree, hf_rtpproxy_ipv4, tvb, offset, new_offset - offset, ipaddr[0]);
                    }
                    else {
                        proto_tree_add_expert(rtpproxy_tree, pinfo, &ei_rtpproxy_bad_ipv4, tvb, offset, new_offset - offset);
                    }
                } else{
                    tmpstr = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, new_offset - offset, ENC_ASCII);
                    if (str_to_ip6(tmpstr, ipaddr)) {
                        col_append_fstr(pinfo->cinfo, COL_INFO, ", IP: [%s]", tmpstr);
                        proto_tree_add_ipv6(rtpproxy_tree, hf_rtpproxy_ipv6, tvb, offset, new_offset - offset, (const ws_in6_addr*)ipaddr);
                    } else {
                        proto_tree_add_expert(rtpproxy_tree, pinfo, &ei_rtpproxy_bad_ipv6, tvb, offset, new_offset - offset);
                    }
                }
                /* Skip whitespace */
                if (!rtpproxy_next_field(tvb, &offset, new_offset, realsize))
                    break; /* No more parameters */

                /* Extract Port */
                tvb_get_string_uint16(tvb, offset, realsize - offset, ENC_STR_DEC, &port, &new_offset);
                col_append_fstr(pinfo->cinfo, COL_INFO, ":%s", tmpstr);
                proto_tree_add_uint(rtpproxy_tree, hf_rtpproxy_port, tvb, offset, new_offset - offset, port);
                /* Skip whitespace */
                if (!rtpproxy_next_field(tvb, &offset, new_offset, realsize))
                    break; /* No more parameters */
            }

            /* Extract Copy target */
            if (tmp == 'c'){
                new_offset = rtpproxy_field_end(tvb, offset, realsize);
                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_copy_target, tvb, offset, new_offset - offset, ENC_ASCII);
                /* Skip whitespace */
                if (!rtpproxy_next_field(tvb, &offset, new_offset, realsize))
                    break; /* No more parameters */
            }

            /* Extract Playback file and codecs */
            if (tmp == 'p'){
                /* Extract filename */
                new_offset = rtpproxy_field_end(tvb, offset, realsize);
                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_playback_filename, tvb, offset, new_offset - offset, ENC_ASCII);
                /* Skip whitespace */
                if (!rtpproxy_next_field(tvb, &offset, new_offset, realsize))
                    break; /* No more parameters */

                /* Extract codec */
                tvb_get_string_uint16(tvb, offset, realsize - offset, ENC_STR_DEC, &codec, &new_offset);
                proto_tree_add_uint(rtpproxy_tree, hf_rtpproxy_playback_codec, tvb, offset, new_offset - offset, codec);
                /* Skip whitespace */
                if (!rtpproxy_next_field(tvb, &offset, new_offset, realsize))
                    break; /* No more parameters */
            }

            /* Extract first tag */
            if (!rtpproxy_add_tag(tvb, pinfo, rtpproxy_tree, &offset, realsize)) {
                break; /* No more parameters */
            }
            /* Skip whitespace */
            if (!rtpproxy_next_field(tvb, &offset, offset, realsize))
                break; /* No more parameters */

            /* Extract second tag */
            if (!rtpproxy_add_tag(tvb, pinfo, rtpproxy_tree, &offset, realsize)) {
                break; /* No more parameters */
            }
            /* Skip whitespace */
            if (!rtpproxy_next_field(tvb, &offset, offset, realsize))
                break; /* No more parameters */

            /* Extract the counters a query asks for. Without them RTPproxy
             * replies with a fixed set - see rtpproxy_add_query_reply().
             */
            if (tmp == 'q'){
                while (offset < realsize){
                    new_offset = rtpproxy_field_end(tvb, offset, realsize);
                    proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_stat_name, tvb, offset, new_offset - offset, ENC_ASCII);
                    if (!rtpproxy_next_field(tvb, &offset, new_offset, realsize))
                        break; /* No more parameters */
                }
                break;
            }

            /* Extract Notification address */
            if (tmp == 'u'){
                ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify, tvb, offset, realsize - offset, ENC_ASCII);
                proto_item_set_text(ti, "Notify");
                rtpproxy_tree = proto_item_add_subtree(ti, ett_rtpproxy_notify);

                /* The NotifyTag is separated by a space - without it the
                 * Call-ID is used instead */
                new_offset = rtpproxy_field_end(tvb, offset, realsize);
                rtpproxy_add_notify_addr(tvb, pinfo, rtpproxy_tree, offset, new_offset);
                /* Skip whitespace */
                if (!rtpproxy_next_field(tvb, &offset, new_offset, realsize))
                    break; /* No more parameters */

                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_notify_tag, tvb, offset, realsize - offset, ENC_ASCII);
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
            rtpproxy_info = rtpproxy_add_tid(false, tvb, pinfo, rtpproxy_tree, rtpproxy_conv, cookie);
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
                tvb_find_line_end_remaining(tvb, offset,&tmp, &new_offset);
                tmpstr = (char*)tvb_get_string_enc(pinfo->pool, tvb, offset, tmp, ENC_ASCII);
                ti = proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_error, tvb, offset, (int)strlen(tmpstr), ENC_ASCII);
                proto_item_append_text(ti, " (%s)", str_to_str_wmem(pinfo->pool, tmpstr, errortypenames, "Unknown"));
                break;
            }

            /* Check for a single '0' or '1' character followed by the end-of-line.
             * These both are positive replies - either a 'positive reply' or a 'version ack'.
             *
             * https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#positive-reply
             * https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#version-reply
             */
            if (((tmp == '0') || (tmp == '1')) && (realsize == offset + (int)strlen("X"))){
                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_ok, tvb, offset, 1, ENC_ASCII);
                break;
            }

            /* Check for the VERSION_NUMBER string reply:
             * https://github.com/sippy/rtpproxy/wiki/RTPP-%28RTPproxy-protocol%29-technical-specification#version-reply
             *
             * If a total size equals to a current offset + size of "YYYYMMDD" string
             * then it's a version reply.
             */
            if (realsize == offset + (int)strlen("YYYYMMDD")){
                proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_version_supported, tvb, offset, (uint32_t)strlen("YYYYMMDD"), ENC_ASCII);
                break;
            }

            /* Extract Port */
            tvb_get_string_uint16(tvb, offset, tvb_captured_length_remaining(tvb, offset), ENC_STR_DEC, &port, &new_offset);
            proto_tree_add_uint(rtpproxy_tree, hf_rtpproxy_port, tvb, offset, new_offset - offset, port);
            /* Skip whitespace */
            offset = tvb_skip_wsp(tvb, new_offset+1, tvb_captured_length(tvb));

            /* Extract IP */
            memset(&addr, 0, sizeof(address));

            /* Nothing but a port could have been replied - in which case
             * whatever follows is a sub-command result, not an address */
            if (offset >= realsize)
                break; /* No more parameters */

            /* Try rtpengine bogus extension first. It appends 4 or
             * 6 depending on type of the IP. See
             * https://github.com/sipwise/rtpengine/blob/eea3256/daemon/call_interfaces.c#L74
             * for further details */
            if(!tvb_find_uint8_remaining(tvb, offset, ' ', &tmp)){
                /* No extension - operate normally */
                tvb_find_line_end_remaining(tvb, offset, &tmp , &new_offset);
            }
            else {
                tmp -= offset;
            }

            if (!tvb_find_uint8_remaining(tvb, offset,':', NULL)){
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
    if (subc_offset)
        rtpproxy_add_subcommands(tvb, pinfo, rtpproxy_main_tree, subc_offset, fullsize, is_reply);

    /* TODO add an expert warning about packets w/o LF sent over TCP */
    if (has_lf)
        proto_tree_add_item(rtpproxy_tree, hf_rtpproxy_lf, tvb, fullsize, 1, ENC_NA);

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
                FT_IPv4,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_local_ipv6,
            {
                "Local IPv6 address",
                "rtpproxy.command_parameter_local_ipv6",
                FT_IPv6,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_local_label,
            {
                "Local address label",
                "rtpproxy.command_parameter_local_label",
                FT_STRING,
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
                FT_IPv4,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_command_parameter_remote_ipv6,
            {
                "Remote IPv6 address",
                "rtpproxy.command_parameter_remote_ipv6",
                FT_IPv6,
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
            &hf_rtpproxy_stat_name,
            {
                "Statistics name",
                "rtpproxy.stat_name",
                FT_STRING,
                BASE_NONE,
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
            &hf_rtpproxy_notify_path,
            {
                "Notification socket path",
                "rtpproxy.notify_path",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_notify_wildcard,
            {
                "Notification address wildcard",
                "rtpproxy.notify_wildcard",
                FT_STRING,
                BASE_NONE,
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
                FRAMENUM_TYPE(FT_FRAMENUM_REQUEST),
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
                FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE),
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
            &hf_rtpproxy_subcommand,
            {
                "Sub-command",
                "rtpproxy.subcommand",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
                HFILL
            }
        },
        {
            &hf_rtpproxy_subcommand_result,
            {
                "Sub-command result",
                "rtpproxy.subcommand_result",
                FT_STRING,
                BASE_NONE,
                NULL,
                0x0,
                NULL,
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
    static int *ett[] = {
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
        &ett_rtpproxy_command_parameters_transcode,
        &ett_rtpproxy_command_parameters_acc,
        &ett_rtpproxy_tag,
        &ett_rtpproxy_notify,
        &ett_rtpproxy_reply,
        &ett_rtpproxy_ng_bencode,
        &ett_rtpproxy_subcommands
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
    static bool rtpproxy_initialized = false;

    if(!rtpproxy_initialized){
        /* Register TCP port for dissection */
        dissector_add_uint_range_with_preference("tcp.port", RTPPROXY_PORT, rtpproxy_handle);
        dissector_add_uint_range_with_preference("udp.port", RTPPROXY_PORT, rtpproxy_handle);
        rtpproxy_prefs_apply();
        rtpproxy_initialized = true;
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
