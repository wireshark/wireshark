/* packet-proxy.c
 * Routines for HAPROXY PROXY (v1/v2) dissection
 * Copyright 2015, Alexis La Goutte (See AUTHORS)
 * Copyright 2019 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The PROXY protocol is a single, unfragmented header before the initial client
 * packet. Following this header, the proxied protocol will take over and
 * proceed normally.
 *
 * https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
 *
 * Requires "Try heuristics sub-dissectors first" in TCP protocol preferences.
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <wsutil/inet_addr.h>
#include <wsutil/strtoi.h>
#include <wsutil/utf8_entities.h>

#include "packet-tcp.h"
#include "packet-udp.h"

void proto_reg_handoff_proxy(void);
void proto_register_proxy(void);

static int proto_proxy;

static int hf_proxy_version;

static int hf_proxy_src_ipv4;
static int hf_proxy_dst_ipv4;
static int hf_proxy_src_ipv6;
static int hf_proxy_dst_ipv6;
static int hf_proxy_srcport;
static int hf_proxy_dstport;

/* V1 */
static int hf_proxy1_magic;
static int hf_proxy1_proto;
static int hf_proxy1_unknown;

/* V2 */
static int hf_proxy2_magic;
static int hf_proxy2_ver;
static int hf_proxy2_cmd;
static int hf_proxy2_addr_family;
static int hf_proxy2_protocol;
static int hf_proxy2_addr_family_protocol;
static int hf_proxy2_len;
static int hf_proxy2_src_unix;
static int hf_proxy2_dst_unix;

static int hf_proxy2_unknown;

static int hf_proxy2_tlv;
static int hf_proxy2_tlv_type;
static int hf_proxy2_tlv_length;
static int hf_proxy2_tlv_value;
static int hf_proxy2_tlv_ssl_client;
static int hf_proxy2_tlv_ssl_verify;
static int hf_proxy2_tlv_ssl_version;
static int hf_proxy2_tlv_ssl_cn;
static int hf_proxy2_tlv_ssl_cipher;
static int hf_proxy2_tlv_ssl_sig_alg;
static int hf_proxy2_tlv_ssl_key_alg;

static expert_field ei_proxy_header_length_too_small;
static expert_field ei_proxy_bad_format;


static int ett_proxy1;
static int ett_proxy2;
static int ett_proxy2_fampro;
static int ett_proxy2_tlv;

static dissector_handle_t proxy_v1_handle;
static dissector_handle_t proxy_v2_handle;

static const uint8_t proxy_v2_magic[] = { 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a };

static const value_string proxy2_cmd_vals[] = {
    { 0x0, "LOCAL" },
    { 0x1, "PROXY" },
    { 0 , NULL }
};

static const value_string proxy2_family_protocol_vals[] = {
    { 0x00, "UNSPEC" },
    { 0x11, "TCP over IPv4" },
    { 0x12, "UDP over IPv4" },
    { 0x21, "TCP over IPv6" },
    { 0x22, "UDP over IPv6" },
    { 0x31, "UNIX stream" },
    { 0x32, "UNIX datagram" },
    { 0, NULL }
};

static const value_string proxy2_family_vals[] = {
    { 0x1, "IPv4" },
    { 0x2, "IPv6" },
    { 0x3, "UNIX" },
    { 0, NULL }
};

#define PP2_TYPE_ALPN           0x01
#define PP2_TYPE_AUTHORITY      0x02
#define PP2_TYPE_CRC32C         0x03
#define PP2_TYPE_NOOP           0x04
#define PP2_TYPE_UNIQUE_ID      0x05
#define PP2_TYPE_SSL            0x20
#define PP2_SUBTYPE_SSL_VERSION 0x21
#define PP2_SUBTYPE_SSL_CN      0x22
#define PP2_SUBTYPE_SSL_CIPHER  0x23
#define PP2_SUBTYPE_SSL_SIG_ALG 0x24
#define PP2_SUBTYPE_SSL_KEY_ALG 0x25
#define PP2_TYPE_NETNS          0x30
#define PP2_TYPE_AWS            0xEA

static const value_string proxy2_tlv_vals[] = {
    { 0x00, "UNSPEC" },
    { PP2_TYPE_ALPN, "ALPN" },
    { PP2_TYPE_AUTHORITY, "AUTHORITY" },
    { PP2_TYPE_CRC32C, "CRC32C" },
    { PP2_TYPE_NOOP, "NOOP" },
    { PP2_TYPE_UNIQUE_ID, "UNIQUE_ID" },
    { PP2_TYPE_SSL, "SSL" },
    { PP2_SUBTYPE_SSL_VERSION, "SSL VERSION" },
    { PP2_SUBTYPE_SSL_CN, "SSL CN" },
    { PP2_SUBTYPE_SSL_CIPHER, "SSL CIPHER" },
    { PP2_SUBTYPE_SSL_SIG_ALG, "SSL SIG ALG" },
    { PP2_SUBTYPE_SSL_KEY_ALG, "SSL KEY ALG" },
    { PP2_TYPE_NETNS, "NETNS" },
    { PP2_TYPE_AWS, "AWS" },
    { 0, NULL }
};

/* XXX: The protocol specification says that the PROXY header is present
 * only once, at the beginning of a TCP connection. If we ever do find
 * the header more than once, we should use a wmem_tree. */
typedef struct _proxy_conv_info_t {
    address src;
    address dst;
    port_type ptype;
    uint16_t srcport;
    uint16_t dstport;
    uint32_t setup_frame;
} proxy_conv_info_t;

static int
dissect_proxy_proxied(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree,
    int offset, void* data, proxy_conv_info_t *proxy_info)
{
    conversation_t* conv = find_or_create_conversation(pinfo);
    /* A PROXY header was parsed here or in a previous frame, and
     * there's remaining data, so call the subdissector.
     */
    if (offset > 0) {
        /* If this is the frame with the header, set a fence. */
        col_append_str(pinfo->cinfo, COL_INFO, " | ");
        col_set_fence(pinfo->cinfo, COL_INFO);
    }
    uint32_t srcport, dstport;
    port_type ptype;
    if (proxy_info == NULL) {
        /* If we're not passed proxied information, e.g., a LOCAL command or
         * transported over UDP (connectionless), use the outer addressing.
         * Note that if the other dissector calls conversation_set_dissector()
         * or similar then on the second pass we won't call the PROXY heuristic
         * dissector for coalesced frames.
         */
        srcport = pinfo->srcport;
        dstport = pinfo->destport;
        ptype = pinfo->ptype;
    }
    else {
        /* If we're passed proxied connection info, set the endpoint used for
         * conversations to the proxied connection, so that if the subdissector
         * calls conversation_set_dissector() it will not prevent calling the
         * PROXY dissector on the header frame on the second pass.
         * Determine our direction.
         *
         * XXX: Perhaps we should actually change the values in pinfo, but
         * currently that doesn't work well with Follow Stream (whether we
         * change them back before returning to the TCP dissector or not.)
         */
        if (addresses_equal(&pinfo->src, conversation_key_addr1(conv->key_ptr)) &&
            (pinfo->srcport == conversation_key_port1(conv->key_ptr))) {
            conversation_set_conv_addr_port_endpoints(pinfo, &proxy_info->src, &proxy_info->dst,
                conversation_pt_to_conversation_type(proxy_info->ptype), proxy_info->srcport,
                proxy_info->dstport);
            srcport = proxy_info->srcport;
            dstport = proxy_info->dstport;
            ptype = proxy_info->ptype;
        }
        else {
            conversation_set_conv_addr_port_endpoints(pinfo, &proxy_info->dst, &proxy_info->src,
                conversation_pt_to_conversation_type(proxy_info->ptype), proxy_info->dstport,
                proxy_info->srcport);
            srcport = proxy_info->dstport;
            dstport = proxy_info->srcport;
            ptype = proxy_info->ptype;
        }
    }

    tvbuff_t* next_tvb = tvb_new_subset_remaining(tvb, offset);
    /* Allow subdissector to perform reassembly. */
    if (pinfo->can_desegment > 0)
        pinfo->can_desegment++;
    switch (ptype) {
    case (PT_TCP):
        /* Get the TCP conversation data associated with the transporting
         * connection. Note that this means that decode_tcp_ports() can
         * try tcp->server_port from the outer connection as well as
         * the ports from the proxied connection.
         */
        decode_tcp_ports(next_tvb, 0, pinfo, tree, srcport, dstport,
            get_tcp_conversation_data(conv, pinfo), (struct tcpinfo*)data);
        break;
    case (PT_UDP):
        decode_udp_ports(next_tvb, 0, pinfo, tree, srcport, dstport, -1);
        break;
    default:
        /* Dissect UNIX and UNSPEC protocols as data */
        call_data_dissector(next_tvb, pinfo, tree);
    }
    if (pinfo->desegment_len > 0) {
        /* If the subdissector requests desegmentation, adjust the
         * desegment offset past the PROXY header.
         */
        pinfo->desegment_offset += offset;
    }
    return tvb_reported_length_remaining(tvb, offset);
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_proxy_v2_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *proxy_tree, int offset, int next_offset)
{
    increment_dissection_depth(pinfo);
    while (offset < next_offset) {
        uint32_t type, length;
        proto_item *ti_tlv;
        proto_tree *tlv_tree;

        ti_tlv = proto_tree_add_item(proxy_tree, hf_proxy2_tlv, tvb, offset, 3, ENC_NA);
        tlv_tree = proto_item_add_subtree(ti_tlv, ett_proxy2_tlv);
        proto_tree_add_item_ret_uint(tlv_tree, hf_proxy2_tlv_type, tvb, offset, 1, ENC_NA, &type);
        offset += 1;
        proto_tree_add_item_ret_uint(tlv_tree, hf_proxy2_tlv_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
        offset += 2;

        proto_item_append_text(ti_tlv, ": (t=%u,l=%d) %s", type, length, val_to_str_const(type, proxy2_tlv_vals ,"Unknown type") );
        proto_item_set_len(ti_tlv, 1 + 2 + length);

        proto_tree_add_item(tlv_tree, hf_proxy2_tlv_value, tvb, offset, length, ENC_NA);
        switch (type) {
        case PP2_TYPE_SSL: /* SSL */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_client, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_verify, tvb, offset, 4, ENC_NA);
            offset += 4;
            offset = dissect_proxy_v2_tlv(tvb, pinfo, tlv_tree, offset, next_offset);
        break;
        case PP2_SUBTYPE_SSL_VERSION: /* SSL Version */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_version, tvb, offset, length, ENC_ASCII);
            proto_item_append_text(ti_tlv, ": %s", tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_ASCII));
            offset += length;
        break;
        case PP2_SUBTYPE_SSL_CN: /* SSL CommonName */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_cn, tvb, offset, length, ENC_ASCII);
            proto_item_append_text(ti_tlv, ": %s", tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_ASCII));
            offset += length;
        break;
        case PP2_SUBTYPE_SSL_CIPHER: /* SSL Cipher */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_cipher, tvb, offset, length, ENC_ASCII);
            offset += length;
        break;
        case PP2_SUBTYPE_SSL_SIG_ALG: /* SSL Signature Algorithm */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_sig_alg, tvb, offset, length, ENC_ASCII);
            offset += length;
        break;
        case PP2_SUBTYPE_SSL_KEY_ALG: /* SSL Key Algorithm */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_key_alg, tvb, offset, length, ENC_ASCII);
            offset += length;
        break;
        default:
            offset += length;
        break;
        }
    }
    decrement_dissection_depth(pinfo);

    return offset;
}

static bool
is_proxy_v2(tvbuff_t* tvb)
{
    int offset = 0;
    int length = tvb_reported_length(tvb);

    if (length < 16) {
        return false;
    }

    if (tvb_memeql(tvb, offset, (const uint8_t*)proxy_v2_magic, sizeof(proxy_v2_magic)) != 0) {
        return false;
    }
    // TODO maybe check for "(hdr.v2.ver_cmd & 0xF0) == 0x20" as done in "9. Sample code" from
    // https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt?

    return true;
}

/* "a 108-byte buffer is always enough to store all the line and a trailing zero" */
#define PROXY_V1_MAX_LINE_LENGTH 107

static bool
is_proxy_v1(tvbuff_t *tvb, int *header_length)
{
    const int min_header_size = sizeof("PROXY \r\n") - 1;
    int length = tvb_reported_length(tvb);
    int next_offset;

    if (length < min_header_size) {
        return false;
    }

    if (tvb_memeql(tvb, 0, (const uint8_t*)"PROXY ", 6) != 0) {
        return false;
    }

    length = MIN(length, PROXY_V1_MAX_LINE_LENGTH);
    if (tvb_find_line_end(tvb, 6, length, &next_offset, false) == -1) {
        return false;
    }

    /* The line must end with a CRLF and not just a single CR or LF. */
    if (tvb_memeql(tvb, next_offset - 2, (const uint8_t*)"\r\n", 2) != 0) {
        return false;
    }

    if (header_length) {
        *header_length = next_offset;
    }
    return true;
}

/**
 * Scan for the next non-empty token (terminated by a space). If invalid, add
 * expert info for the remaining part and return false. Otherwise return true
 * and the token length.
 */
static bool
proxy_v1_get_token_length(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int header_length, char *token, int *token_length)
{
    int space_pos = tvb_find_guint8(tvb, offset, header_length - offset, ' ');
    if (space_pos == -1) {
        proto_tree_add_expert(tree, pinfo, &ei_proxy_bad_format, tvb, offset, header_length - offset);
        return false;
    }
    int length = space_pos - offset;
    if (token && length) {
        DISSECTOR_ASSERT(length + 1 < PROXY_V1_MAX_LINE_LENGTH);
        tvb_memcpy(tvb, token, offset, length);
        token[length] = '\0';
    }
    *token_length = length;
    return length != 0;
}

static int
dissect_proxy_v1_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *proxy_tree;
    unsigned    offset = 0;
    int         header_length = 0;
    int         token_length = 0;
    int         tcp_ip_version = 0;
    uint16_t    srcport, dstport;
    char        buffer[PROXY_V1_MAX_LINE_LENGTH];
    uint32_t    src_ipv4, dst_ipv4;
    ws_in6_addr src_ipv6, dst_ipv6;
    address     src_addr, dst_addr;

    if (!is_proxy_v1(tvb, &header_length)) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROXYv1");

    ti = proto_tree_add_item(tree, proto_proxy, tvb, 0, header_length, ENC_NA);
    proxy_tree = proto_item_add_subtree(ti, ett_proxy1);

    /* Skip "PROXY" plus a space. */
    proto_tree_add_item(proxy_tree, hf_proxy1_magic, tvb, offset, 5, ENC_NA);
    offset += 5 + 1;

    /* Protocol and family */
    if (!proxy_v1_get_token_length(tvb, pinfo, proxy_tree, offset, header_length, buffer, &token_length)) {
        return tvb_captured_length(tvb);
    }
    proto_tree_add_item(proxy_tree, hf_proxy1_proto, tvb, offset, token_length, ENC_NA|ENC_ASCII);
    if (token_length == 4) {
        if (memcmp(buffer, "TCP4", 4) == 0) {
            tcp_ip_version = 4;
        } else if (memcmp(buffer, "TCP6", 4) == 0) {
            tcp_ip_version = 6;
        }
    }
    offset += token_length + 1;

    switch (tcp_ip_version) {
    case 4:
        /* IPv4 source address */
        if (!proxy_v1_get_token_length(tvb, pinfo, proxy_tree, offset, header_length, buffer, &token_length)) {
            return tvb_captured_length(tvb);
        }
        if (!ws_inet_pton4(buffer, &src_ipv4)) {
            proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                    "Unrecognized IPv4 address");
            return tvb_captured_length(tvb);
        }
        proto_tree_add_ipv4(proxy_tree, hf_proxy_src_ipv4, tvb, offset, token_length, src_ipv4);
        set_address(&src_addr, AT_IPv4, 4, &src_ipv4);
        offset += token_length + 1;

        /* IPv4 destination address */
        if (!proxy_v1_get_token_length(tvb, pinfo, proxy_tree, offset, header_length, buffer, &token_length)) {
            return tvb_captured_length(tvb);
        }
        if (!ws_inet_pton4(buffer, &dst_ipv4)) {
            proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                    "Unrecognized IPv4 address");
            return tvb_captured_length(tvb);
        }
        proto_tree_add_ipv4(proxy_tree, hf_proxy_dst_ipv4, tvb, offset, token_length, dst_ipv4);
        set_address(&dst_addr, AT_IPv4, 4, &dst_ipv4);
        offset += token_length + 1;
        break;

    case 6:
        /* IPv6 source address */
        if (!proxy_v1_get_token_length(tvb, pinfo, proxy_tree, offset, header_length, buffer, &token_length)) {
            return tvb_captured_length(tvb);
        }
        if (!ws_inet_pton6(buffer, &src_ipv6)) {
            proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                    "Unrecognized IPv6 address");
            return tvb_captured_length(tvb);
        }
        proto_tree_add_ipv6(proxy_tree, hf_proxy_src_ipv6, tvb, offset, token_length, &src_ipv6);
        set_address(&src_addr, AT_IPv6, sizeof(ws_in6_addr), &src_ipv6);
        offset += token_length + 1;

        /* IPv6 destination address */
        if (!proxy_v1_get_token_length(tvb, pinfo, proxy_tree, offset, header_length, buffer, &token_length)) {
            return tvb_captured_length(tvb);
        }
        if (!ws_inet_pton6(buffer, &dst_ipv6)) {
            proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                    "Unrecognized IPv6 address");
            return tvb_captured_length(tvb);
        }
        proto_tree_add_ipv6(proxy_tree, hf_proxy_dst_ipv6, tvb, offset, token_length, &dst_ipv6);
        set_address(&dst_addr, AT_IPv6, sizeof(ws_in6_addr), &dst_ipv6);
        offset += token_length + 1;
        break;

    default:
        proto_tree_add_item(proxy_tree, hf_proxy1_unknown, tvb, offset, header_length - 2 - offset, ENC_NA|ENC_ASCII);
        return tvb_captured_length(tvb);
    }

    /* Source port */
    if (!proxy_v1_get_token_length(tvb, pinfo, proxy_tree, offset, header_length, buffer, &token_length)) {
        return tvb_captured_length(tvb);
    }
    if (!ws_strtou16(buffer, NULL, &srcport)) {
        proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                "Unrecognized port");
        return tvb_captured_length(tvb);
    }
    proto_tree_add_uint(proxy_tree, hf_proxy_srcport, tvb, offset, token_length, srcport);
    offset += token_length + 1;

    /* Destination port */
    token_length = header_length - 2 - offset;
    if (token_length <= 0) {
        proto_tree_add_expert(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length);
        return tvb_captured_length(tvb);
    }
    tvb_memcpy(tvb, buffer, offset, token_length);
    buffer[token_length] = '\0';
    if (!ws_strtou16(buffer, NULL, &dstport)) {
        proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                "Unrecognized port");
        return tvb_captured_length(tvb);
    }
    proto_tree_add_uint(proxy_tree, hf_proxy_dstport, tvb, offset, token_length, dstport);

    col_add_lstr(pinfo->cinfo, COL_INFO, "PROXY ", address_to_str(pinfo->pool, &src_addr),
        " "UTF8_RIGHTWARDS_ARROW" ", address_to_str(pinfo->pool, &dst_addr), ", ",
        COL_ADD_LSTR_TERMINATOR);
    col_append_ports(pinfo->cinfo, COL_INFO, PT_TCP, srcport, dstport);
    conversation_t* conv = find_or_create_conversation(pinfo);
    proxy_conv_info_t* proxy_info = conversation_get_proto_data(conv, proto_proxy);
    if (proxy_info == NULL) {
        proxy_info = wmem_new(wmem_file_scope(), proxy_conv_info_t);
        copy_address_wmem(wmem_file_scope(), &proxy_info->src, &src_addr);
        copy_address_wmem(wmem_file_scope(), &proxy_info->dst, &dst_addr);
        proxy_info->ptype = PT_TCP;
        proxy_info->srcport = srcport;
        proxy_info->dstport = dstport;
        proxy_info->setup_frame = pinfo->num;
        conversation_add_proto_data(conv, proto_proxy, proxy_info);
    }
    return header_length;
}

static int
dissect_proxy_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    conversation_t* conv = find_or_create_conversation(pinfo);
    proxy_conv_info_t* proxy_info;
    int offset = dissect_proxy_v1_header(tvb, pinfo, tree);
    proxy_info = conversation_get_proto_data(conv, proto_proxy);
    if (proxy_info && pinfo->num >= proxy_info->setup_frame &&
            tvb_reported_length_remaining(tvb, offset)) {
        /* XXX: If this is a later frame, should we add some
         * generated fields with the proxy header information,
         * and a link back to the proxy setup frame? */
        offset += dissect_proxy_proxied(tvb, pinfo, tree, offset, data, proxy_info);
    }
    return offset;
}

static int
dissect_proxy_v2_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti , *ti_ver;
    proto_tree *proxy_tree, *fampro_tree;
    unsigned offset = 0, next_offset;
    uint32_t    header_len, fam_pro, cmd;
    address     src_addr = ADDRESS_INIT_NONE, dst_addr = ADDRESS_INIT_NONE;
    uint32_t    srcport, dstport;
    port_type   ptype = PT_NONE;

    if (!is_proxy_v2(tvb)) {
        return 0;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROXYv2");

    ti = proto_tree_add_item(tree, proto_proxy, tvb, 0, -1, ENC_NA);

    proxy_tree = proto_item_add_subtree(ti, ett_proxy2);

    proto_tree_add_item(proxy_tree, hf_proxy2_magic, tvb, offset, 12, ENC_NA);
    offset += 12;

    proto_tree_add_item(proxy_tree, hf_proxy2_ver, tvb, offset, 1, ENC_NA);
    proto_tree_add_item_ret_uint(proxy_tree, hf_proxy2_cmd, tvb, offset, 1, ENC_NA, &cmd);
    ti_ver = proto_tree_add_uint(proxy_tree, hf_proxy_version, tvb, offset, 1, 2);
    proto_item_set_generated(ti_ver);
    offset += 1;

    ti = proto_tree_add_item_ret_uint(proxy_tree, hf_proxy2_addr_family_protocol, tvb, offset, 1, ENC_NA, &fam_pro);
    fampro_tree = proto_item_add_subtree(ti, ett_proxy2_fampro);
    proto_tree_add_item(fampro_tree, hf_proxy2_addr_family, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(fampro_tree, hf_proxy2_protocol, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item_ret_uint(proxy_tree, hf_proxy2_len, tvb, offset, 2, ENC_BIG_ENDIAN, &header_len);
    offset += 2;

    next_offset = offset + header_len;

    switch (fam_pro){
        case 0x11: /* TCP over IPv4 */
        case 0x12: /* UDP over IPv4 */
            proto_tree_add_item(proxy_tree, hf_proxy_src_ipv4, tvb, offset, 4, ENC_NA);
            set_address_tvb(&src_addr, AT_IPv4, 4, tvb, offset);
            offset += 4;
            proto_tree_add_item(proxy_tree, hf_proxy_dst_ipv4, tvb, offset, 4, ENC_NA);
            set_address_tvb(&dst_addr, AT_IPv4, 4, tvb, offset);
            offset += 4;
            proto_tree_add_item_ret_uint(proxy_tree, hf_proxy_srcport, tvb, offset, 2, ENC_BIG_ENDIAN, &srcport);
            offset += 2;
            proto_tree_add_item_ret_uint(proxy_tree, hf_proxy_dstport, tvb, offset, 2, ENC_BIG_ENDIAN, &dstport);
            offset += 2;
            ptype = (fam_pro & 1) ? PT_TCP : PT_UDP;
        break;
        case 0x21: /* TCP over IPv6 */
        case 0x22: /* UDP over IPv6 */
            proto_tree_add_item(proxy_tree, hf_proxy_src_ipv6, tvb, offset, 16, ENC_NA);
            set_address_tvb(&src_addr, AT_IPv6, sizeof(ws_in6_addr), tvb, offset);
            offset += 16;
            proto_tree_add_item(proxy_tree, hf_proxy_dst_ipv6, tvb, offset, 16, ENC_NA);
            set_address_tvb(&dst_addr, AT_IPv6, sizeof(ws_in6_addr), tvb, offset);
            offset += 16;
            proto_tree_add_item_ret_uint(proxy_tree, hf_proxy_srcport, tvb, offset, 2, ENC_BIG_ENDIAN, &srcport);
            offset += 2;
            proto_tree_add_item_ret_uint(proxy_tree, hf_proxy_dstport, tvb, offset, 2, ENC_BIG_ENDIAN, &dstport);
            offset += 2;
            ptype = (fam_pro & 1) ? PT_TCP : PT_UDP;
        break;
        case 0x31: /* UNIX stream */
        case 0x32: /* UNIX datagram */
            proto_tree_add_item(proxy_tree, hf_proxy2_src_unix, tvb, offset, 108, ENC_NA);
            offset += 108;
            proto_tree_add_item(proxy_tree, hf_proxy2_dst_unix, tvb, offset, 108, ENC_NA);
            offset += 108;
        break;
        default:
            if (header_len) {
                proto_tree_add_item(proxy_tree, hf_proxy2_unknown, tvb, offset, header_len, ENC_NA);
                offset += header_len;
            }
        break;
    }

    if (offset > next_offset) {
        proto_tree_add_expert(proxy_tree, pinfo, &ei_proxy_header_length_too_small,
                                     tvb, offset, -1);
        return offset;
    }

    /* Do we have additional TLV to parse? */
    if (offset < next_offset) {
        /* TLV */
        offset = dissect_proxy_v2_tlv(tvb, pinfo, proxy_tree, offset, next_offset);
    }

    /* If the cmd is LOCAL, then ignore the proxy protocol block,
     * even if address and protocol information exists. */
    if (src_addr.type != AT_NONE) {
        col_add_lstr(pinfo->cinfo, COL_INFO, "PROXY ", address_to_str(pinfo->pool, &src_addr),
            " "UTF8_RIGHTWARDS_ARROW" ", address_to_str(pinfo->pool, &dst_addr), ", ",
            COL_ADD_LSTR_TERMINATOR);
        col_append_ports(pinfo->cinfo, COL_INFO, ptype, srcport, dstport);
        conversation_t* conv = find_or_create_conversation(pinfo);
        proxy_conv_info_t* proxy_info = conversation_get_proto_data(conv, proto_proxy);
        if (proxy_info == NULL && pinfo->ptype != PT_UDP && cmd != 0) {
            /* Don't add conversation info on connectionless transport (UDP) */
            /* If the command is LOCAL, then the receiver "MUST use the real
             * connection endpoints". */
            proxy_info = wmem_new(wmem_file_scope(), proxy_conv_info_t);
            copy_address_wmem(wmem_file_scope(), &proxy_info->src, &src_addr);
            copy_address_wmem(wmem_file_scope(), &proxy_info->dst, &dst_addr);
            proxy_info->ptype = PT_TCP;
            proxy_info->srcport = srcport;
            proxy_info->dstport = dstport;
            proxy_info->setup_frame = pinfo->num;
            conversation_add_proto_data(conv, proto_proxy, proxy_info);
        }
    }

    return offset;
}

static int
dissect_proxy_v2(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    conversation_t* conv = find_or_create_conversation(pinfo);
    proxy_conv_info_t *proxy_info;
    int offset = dissect_proxy_v2_header(tvb, pinfo, tree);
    proxy_info = conversation_get_proto_data(conv, proto_proxy);
    if (proxy_info && pinfo->num >= proxy_info->setup_frame &&
        tvb_reported_length_remaining(tvb, offset)) {
        /* XXX: If this is a later frame, should we add some
         * generated fields with the proxy header information,
         * and a link back to the proxy setup frame? */
        offset += dissect_proxy_proxied(tvb, pinfo, tree, offset, data, proxy_info);
    }
    return offset;
}

static bool
dissect_proxy_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    conversation_t* conv = find_or_create_conversation(pinfo);
    if (is_proxy_v2(tvb)) {
        conversation_set_dissector(conv, proxy_v2_handle);
        dissect_proxy_v2(tvb, pinfo, tree, data);
        return true;
    } else if (is_proxy_v1(tvb, NULL)) {
        conversation_set_dissector(conv, proxy_v1_handle);
        dissect_proxy_v1(tvb, pinfo, tree, data);
        return true;
    }
    return false;
}

static bool
dissect_proxy_heur_udp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    int offset;
    if (is_proxy_v2(tvb)) {
        offset = dissect_proxy_v2(tvb, pinfo, tree, data);
        if (offset && tvb_reported_length_remaining(tvb, offset)) {
            /* When the transport is UDP, treat this as connectionless
             * and just skip past the PROXY header after putting it
             * in the tree. If this is DNS, for example, every request
             * will have a PROXY header; the responses don't, and
             * there's no good way to associate the PROXY information
             * with the header that won't have problems if the UDP
             * responses are out of order. Note if the proxied dissector
             * calls conversation_set_dissector() then this dissector
             * won't get called on the second pass. */
            dissect_proxy_proxied(tvb, pinfo, tree, offset, data, NULL);
        }
        return true;
#if 0
    /* Proxy v1 is only for TCP */
    } else if (is_proxy_v1(tvb, NULL)) {
        dissect_proxy_v1(tvb, pinfo, tree, data);
#endif
    }
    return false;
}

void
proto_register_proxy(void)
{

    expert_module_t *expert_proxy;

    static hf_register_info hf[] = {
        { &hf_proxy_version,
          { "Version", "proxy.version",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_proxy_src_ipv4,
          { "Source Address", "proxy.src.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy_dst_ipv4,
          { "Destination Address", "proxy.dst.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy_src_ipv6,
          { "Source Address", "proxy.src.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy_dst_ipv6,
          { "Destination Address", "proxy.dst.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy_srcport,
          { "Source Port", "proxy.srcport",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy_dstport,
          { "Destination Port", "proxy.dstport",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_proxy1_magic,
          { "PROXY v1 magic", "proxy.v1.magic",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy1_proto,
          { "Protocol", "proxy.v1.proto",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Proxied protocol and family", HFILL }
        },
        { &hf_proxy1_unknown,
          { "Unknown data", "proxy.v1.unknown",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_proxy2_magic,
          { "Magic", "proxy.v2.magic",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy2_ver,
          { "Version", "proxy.v2.version",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            NULL, HFILL }
        },
        { &hf_proxy2_cmd,
          { "Command", "proxy.v2.cmd",
            FT_UINT8, BASE_DEC, VALS(proxy2_cmd_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_proxy2_addr_family_protocol,
          { "Address Family Protocol", "proxy.v2.addr_family_protocol",
            FT_UINT8, BASE_HEX, VALS(proxy2_family_protocol_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_proxy2_addr_family,
          { "Address Family", "proxy.v2.addr_family",
            FT_UINT8, BASE_HEX, VALS(proxy2_family_vals), 0xF0,
            NULL, HFILL }
        },
        { &hf_proxy2_protocol,
          { "Protocol", "proxy.v2.protocol",
            FT_UINT8, BASE_HEX, NULL, 0x0F,
            NULL, HFILL }
        },
        { &hf_proxy2_len,
          { "Length", "proxy.v2.length",
            FT_UINT16, BASE_DEC, NULL, 0x00,
            "Size of addresses and additional properties", HFILL }
        },


        { &hf_proxy2_src_unix,
          { "Source Address", "proxy.v2.src.unix",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy2_dst_unix,
          { "Destination Address", "proxy.v2.dst.unix",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_proxy2_unknown,
          { "Unknown data", "proxy.v2.unknown",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_proxy2_tlv,
          { "TLV", "proxy.v2.tlv",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy2_tlv_type,
          { "Type", "proxy.v2.tlv.type",
            FT_UINT8, BASE_HEX, VALS(proxy2_tlv_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_proxy2_tlv_length,
          { "Length", "proxy.v2.tlv.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy2_tlv_value,
          { "Value", "proxy.v2.tlv.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_proxy2_tlv_ssl_client,
          { "Client", "proxy.v2.tlv.ssl.client",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy2_tlv_ssl_verify,
          { "Verify", "proxy.v2.tlv.ssl.verify",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy2_tlv_ssl_version,
          { "Version", "proxy.v2.tlv.ssl.version",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy2_tlv_ssl_cn,
          { "CN", "proxy.v2.tlv.ssl.cn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "CommonName", HFILL }
        },
        { &hf_proxy2_tlv_ssl_cipher,
          { "Cipher", "proxy.v2.tlv.ssl.cipher",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_proxy2_tlv_ssl_sig_alg,
          { "SIG ALG", "proxy.v2.tlv.ssl.sig_alg",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Signature Algorithm", HFILL }
        },
        { &hf_proxy2_tlv_ssl_key_alg,
          { "Key ALG", "proxy.v2.tlv.ssl.keu_alg",
            FT_STRING, BASE_NONE, NULL, 0x0,
            "Key Algorithm", HFILL }
        },
    };

    static int *ett[] = {
        &ett_proxy1,
        &ett_proxy2,
        &ett_proxy2_fampro,
        &ett_proxy2_tlv,
    };

    static ei_register_info ei[] = {
        { &ei_proxy_header_length_too_small,
          { "proxy.header.length_too_small", PI_MALFORMED, PI_WARN,
            "Header length is too small", EXPFILL }
        },
        { &ei_proxy_bad_format,
          { "proxy.bad_format", PI_MALFORMED, PI_WARN,
            "Badly formatted PROXY header line", EXPFILL }
        }
    };

    proto_proxy = proto_register_protocol("PROXY Protocol", "PROXY", "proxy");

    proto_register_field_array(proto_proxy, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_proxy = expert_register_protocol(proto_proxy);
    expert_register_field_array(expert_proxy, ei, array_length(ei));

    proxy_v1_handle = register_dissector("proxy_v1", dissect_proxy_v1, proto_proxy);
    proxy_v2_handle = register_dissector("proxy_v2", dissect_proxy_v2, proto_proxy);
}

void
proto_reg_handoff_proxy(void)
{
    heur_dissector_add("tcp", dissect_proxy_heur, "PROXY over TCP", "proxy_tcp", proto_proxy, HEURISTIC_ENABLE);
    /* XXX: PROXY v1 is defined to be transported over TCP only. PROXY v2 is
     * strongly implied to also only be transported over TCP (though the
     * proxied connection can be UDP), but dnsdist (and others?) use PROXY
     * over UDP, adding the header to every request (but not response.)
     * Presumably the proxied payload can only be DGRAM, since there's no
     * way to deal with desegmentation or out of order without TCP sequence
     * numbers. */
    heur_dissector_add("udp", dissect_proxy_heur_udp, "PROXY over UDP", "proxy_udp", proto_proxy, HEURISTIC_ENABLE);
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
