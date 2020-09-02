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
#include <wsutil/inet_addr.h>
#include <wsutil/strtoi.h>

#include <packet-tcp.h>

void proto_reg_handoff_proxy(void);
void proto_register_proxy(void);

static int proto_proxy = -1;

static int hf_proxy_version = -1;

static int hf_proxy_src_ipv4 = -1;
static int hf_proxy_dst_ipv4 = -1;
static int hf_proxy_src_ipv6 = -1;
static int hf_proxy_dst_ipv6 = -1;
static int hf_proxy_srcport = -1;
static int hf_proxy_dstport = -1;

/* V1 */
static int hf_proxy1_magic = -1;
static int hf_proxy1_proto = -1;
static int hf_proxy1_unknown = -1;

/* V2 */
static int hf_proxy2_magic = -1;
static int hf_proxy2_ver = -1;
static int hf_proxy2_cmd = -1;
static int hf_proxy2_addr_family = -1;
static int hf_proxy2_protocol = -1;
static int hf_proxy2_addr_family_protocol = -1;
static int hf_proxy2_len = -1;
static int hf_proxy2_src_unix = -1;
static int hf_proxy2_dst_unix = -1;

static int hf_proxy2_unknown = -1;

static int hf_proxy2_tlv = -1;
static int hf_proxy2_tlv_type = -1;
static int hf_proxy2_tlv_length = -1;
static int hf_proxy2_tlv_value = -1;
static int hf_proxy2_tlv_ssl_client = -1;
static int hf_proxy2_tlv_ssl_verify = -1;
static int hf_proxy2_tlv_ssl_version = -1;
static int hf_proxy2_tlv_ssl_cn = -1;
static int hf_proxy2_tlv_ssl_cipher = -1;
static int hf_proxy2_tlv_ssl_sig_alg = -1;
static int hf_proxy2_tlv_ssl_key_alg = -1;

static expert_field ei_proxy_header_length_too_small = EI_INIT;
static expert_field ei_proxy_bad_format = EI_INIT;


static gint ett_proxy1 = -1;
static gint ett_proxy2 = -1;
static gint ett_proxy2_fampro = -1;
static gint ett_proxy2_tlv = -1;

static const guint8 proxy_v2_magic[] = { 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a };

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

static int
dissect_proxy_v2_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *proxy_tree, int offset)
{
    while ( tvb_reported_length_remaining(tvb, offset) > 0) {
        guint32 type, length;
        proto_item *ti_tlv;
        proto_tree *tlv_tree;

        ti_tlv = proto_tree_add_item(proxy_tree, hf_proxy2_tlv, tvb, offset, 3, ENC_NA);
        tlv_tree = proto_item_add_subtree(ti_tlv, ett_proxy2_tlv);
        proto_tree_add_item_ret_uint(tlv_tree, hf_proxy2_tlv_type, tvb, offset, 1, ENC_NA, &type);
        offset += 1;
        proto_tree_add_item_ret_uint(tlv_tree, hf_proxy2_tlv_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
        offset += 2;

        proto_item_append_text(ti_tlv, ": (t=%u,l=%d) %s", type, length, val_to_str(type, proxy2_tlv_vals ,"Unknown type") );
        proto_item_set_len(ti_tlv, 1 + 2 + length);

        proto_tree_add_item(tlv_tree, hf_proxy2_tlv_value, tvb, offset, length, ENC_NA);
        switch (type) {
        case PP2_TYPE_SSL: /* SSL */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_client, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_verify, tvb, offset, 4, ENC_NA);
            offset += 4;
            offset = dissect_proxy_v2_tlv(tvb, pinfo, tlv_tree, offset);
        break;
        case PP2_SUBTYPE_SSL_VERSION: /* SSL Version */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_version, tvb, offset, length, ENC_ASCII|ENC_NA);
            proto_item_append_text(ti_tlv, ": %s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII));
            offset += length;
        break;
        case PP2_SUBTYPE_SSL_CN: /* SSL CommonName */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_cn, tvb, offset, length, ENC_ASCII|ENC_NA);
            proto_item_append_text(ti_tlv, ": %s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, length, ENC_ASCII));
            offset += length;
        break;
        case PP2_SUBTYPE_SSL_CIPHER: /* SSL Cipher */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_cipher, tvb, offset, length, ENC_ASCII|ENC_NA);
            offset += length;
        break;
        case PP2_SUBTYPE_SSL_SIG_ALG: /* SSL Signature Algorithm */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_sig_alg, tvb, offset, length, ENC_ASCII|ENC_NA);
            offset += length;
        break;
        case PP2_SUBTYPE_SSL_KEY_ALG: /* SSL Key Algorithm */
            proto_tree_add_item(tlv_tree, hf_proxy2_tlv_ssl_key_alg, tvb, offset, length, ENC_ASCII|ENC_NA);
            offset += length;
        break;
        default:
            offset += length;
        break;
        }
    }

    return offset;
}


/* "a 108-byte buffer is always enough to store all the line and a trailing zero" */
#define PROXY_V1_MAX_LINE_LENGTH 107

static gboolean
is_proxy_v1(tvbuff_t *tvb, gint *header_length)
{
    const int min_header_size = sizeof("PROXY \r\n") - 1;
    int length = tvb_reported_length(tvb);
    gint next_offset;

    if (length < min_header_size) {
        return FALSE;
    }

    if (tvb_memeql(tvb, 0, "PROXY ", 6) != 0) {
        return FALSE;
    }

    length = MIN(length, PROXY_V1_MAX_LINE_LENGTH);
    if (tvb_find_line_end(tvb, 6, length, &next_offset, FALSE) == -1) {
        return FALSE;
    }

    /* The line must end with a CRLF and not just a single CR or LF. */
    if (tvb_memeql(tvb, next_offset - 2, "\r\n", 2) != 0) {
        return FALSE;
    }

    if (header_length) {
        *header_length = next_offset;
    }
    return TRUE;
}

/**
 * Scan for the next non-empty token (terminated by a space). If invalid, add
 * expert info for the remaining part and return FALSE. Otherwise return TRUE
 * and the token length.
 */
static gboolean
proxy_v1_get_token_length(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int header_length, gchar *token, gint *token_length)
{
    gint space_pos = tvb_find_guint8(tvb, offset, header_length - offset, ' ');
    if (space_pos == -1) {
        proto_tree_add_expert(tree, pinfo, &ei_proxy_bad_format, tvb, offset, header_length - offset);
        return FALSE;
    }
    gint length = space_pos - offset;
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
    guint       offset = 0;
    gint        header_length = 0;
    gint        token_length = 0;
    gint        tcp_ip_version = 0;
    guint16     port;
    gchar       buffer[PROXY_V1_MAX_LINE_LENGTH];
    guint32     addr_ipv4;
    ws_in6_addr addr_ipv6;

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
        if (!ws_inet_pton4(buffer, &addr_ipv4)) {
            proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                    "Unrecognized IPv4 address");
            return tvb_captured_length(tvb);
        }
        proto_tree_add_ipv4(proxy_tree, hf_proxy_src_ipv4, tvb, offset, token_length, addr_ipv4);
        offset += token_length + 1;

        /* IPv4 destination address */
        if (!proxy_v1_get_token_length(tvb, pinfo, proxy_tree, offset, header_length, buffer, &token_length)) {
            return tvb_captured_length(tvb);
        }
        if (!ws_inet_pton4(buffer, &addr_ipv4)) {
            proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                    "Unrecognized IPv4 address");
            return tvb_captured_length(tvb);
        }
        proto_tree_add_ipv4(proxy_tree, hf_proxy_dst_ipv4, tvb, offset, token_length, addr_ipv4);
        offset += token_length + 1;
        break;

    case 6:
        /* IPv6 source address */
        if (!proxy_v1_get_token_length(tvb, pinfo, proxy_tree, offset, header_length, buffer, &token_length)) {
            return tvb_captured_length(tvb);
        }
        if (!ws_inet_pton6(buffer, &addr_ipv6)) {
            proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                    "Unrecognized IPv6 address");
            return tvb_captured_length(tvb);
        }
        proto_tree_add_ipv6(proxy_tree, hf_proxy_src_ipv6, tvb, offset, token_length, &addr_ipv6);
        offset += token_length + 1;

        /* IPv6 destination address */
        if (!proxy_v1_get_token_length(tvb, pinfo, proxy_tree, offset, header_length, buffer, &token_length)) {
            return tvb_captured_length(tvb);
        }
        if (!ws_inet_pton6(buffer, &addr_ipv6)) {
            proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                    "Unrecognized IPv6 address");
            return tvb_captured_length(tvb);
        }
        proto_tree_add_ipv6(proxy_tree, hf_proxy_dst_ipv6, tvb, offset, token_length, &addr_ipv6);
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
    if (!ws_strtou16(buffer, NULL, &port)) {
        proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                "Unrecognized port");
        return tvb_captured_length(tvb);
    }
    proto_tree_add_uint(proxy_tree, hf_proxy_srcport, tvb, offset, token_length, port);
    offset += token_length + 1;

    /* Destination port */
    token_length = header_length - 2 - offset;
    if (token_length <= 0) {
        proto_tree_add_expert(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length);
        return tvb_captured_length(tvb);
    }
    tvb_memcpy(tvb, buffer, offset, token_length);
    buffer[token_length] = '\0';
    if (!ws_strtou16(buffer, NULL, &port)) {
        proto_tree_add_expert_format(proxy_tree, pinfo, &ei_proxy_bad_format, tvb, offset, token_length,
                "Unrecognized port");
        return tvb_captured_length(tvb);
    }
    proto_tree_add_uint(proxy_tree, hf_proxy_dstport, tvb, offset, token_length, port);

    return header_length;
}

static int
dissect_proxy_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int offset = dissect_proxy_v1_header(tvb, pinfo, tree);
    if (offset > 0 && tvb_reported_length_remaining(tvb, offset)) {
        /*
         * If the PROXY v1 header was successfully parsed with remaining data,
         * call the next dissector. The port number does not have to be changed
         * as the PROXY header is just a prefix. This also makes it easier to
         * use Decode As to replace the next dissector.
         *
         * Caveat: if the other dissector uses conversation_set_dissector or
         * similar, then the second pass will fail to call the PROXY dissector
         * through heuristics. This affects HTTP.
         * TODO fix two-pass dissection when coalesced with HTTP, see bug 15714.
         */
        tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, offset);
        /* Allow subdissector to perform reassembly. */
        if (pinfo->can_desegment > 0)
            pinfo->can_desegment++;
        decode_tcp_ports(next_tvb, 0, pinfo, tree, pinfo->srcport, pinfo->destport,
                NULL, (struct tcpinfo *)data);
        offset += tvb_captured_length(next_tvb);
    }
    return offset;
}

static int
dissect_proxy_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti , *ti_ver;
    proto_tree *proxy_tree, *fampro_tree;
    guint offset = 0, next_offset;
    guint32 header_len, fam_pro;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PROXYv2");

    ti = proto_tree_add_item(tree, proto_proxy, tvb, 0, -1, ENC_NA);

    proxy_tree = proto_item_add_subtree(ti, ett_proxy2);

    proto_tree_add_item(proxy_tree, hf_proxy2_magic, tvb, offset, 12, ENC_NA);
    offset += 12;

    proto_tree_add_item(proxy_tree, hf_proxy2_ver, tvb, offset, 1, ENC_NA);
    proto_tree_add_item(proxy_tree, hf_proxy2_cmd, tvb, offset, 1, ENC_NA);
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
            offset += 4;
            proto_tree_add_item(proxy_tree, hf_proxy_dst_ipv4, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(proxy_tree, hf_proxy_srcport, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(proxy_tree, hf_proxy_dstport, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case 0x21: /* TCP over IPv6 */
        case 0x22: /* UDP over IPv6 */
            proto_tree_add_item(proxy_tree, hf_proxy_src_ipv6, tvb, offset, 16, ENC_NA);
            offset += 16;
            proto_tree_add_item(proxy_tree, hf_proxy_dst_ipv6, tvb, offset, 16, ENC_NA);
            offset += 16;
            proto_tree_add_item(proxy_tree, hf_proxy_srcport, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item(proxy_tree, hf_proxy_dstport, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        break;
        case 0x31: /* UNIX stream */
        case 0x32: /* UNIX datagram */
            proto_tree_add_item(proxy_tree, hf_proxy2_src_unix, tvb, offset, 108, ENC_NA);
            offset += 108;
            proto_tree_add_item(proxy_tree, hf_proxy2_dst_unix, tvb, offset, 108, ENC_NA);
            offset += 108;
        break;
        default:
            proto_tree_add_item(proxy_tree, hf_proxy2_unknown, tvb, offset, header_len, ENC_NA);
            offset += header_len;
        break;
    }

    if (offset > next_offset) {
        proto_tree_add_expert(proxy_tree, pinfo, &ei_proxy_header_length_too_small,
                                     tvb, offset, -1);
        return offset;
    }

    if (offset < header_len) {
        /* TLV */
        offset = dissect_proxy_v2_tlv(tvb, pinfo, proxy_tree, offset);
    }

    return offset;
}

static gboolean
dissect_proxy_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (tvb_reported_length(tvb) >= 16 &&
        tvb_captured_length(tvb) >= sizeof(proxy_v2_magic) &&
        tvb_memeql(tvb, 0, proxy_v2_magic, sizeof(proxy_v2_magic)) == 0) {
        // TODO maybe check for "(hdr.v2.ver_cmd & 0xF0) == 0x20" as done in "9. Sample code" from
        // https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt?
        dissect_proxy_v2(tvb, pinfo, tree, data);
        return TRUE;
    } else if (is_proxy_v1(tvb, NULL)) {
        dissect_proxy_v1(tvb, pinfo, tree, data);
        return TRUE;
    }
    return FALSE;
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
            FT_UINT8, BASE_DEC, NULL, 0x0F,
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

    static gint *ett[] = {
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

}

void
proto_reg_handoff_proxy(void)
{
    heur_dissector_add("tcp", dissect_proxy_heur, "proxy", "proxy_tcp", proto_proxy, HEURISTIC_ENABLE);
    heur_dissector_add("udp", dissect_proxy_heur, "proxy", "proxy_udp", proto_proxy, HEURISTIC_ENABLE);
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
