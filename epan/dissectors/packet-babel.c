/* packet-babel.c
 * Routines for Babel dissection (RFC 6126)
 * Copyright 2011 by Juliusz Chroboczek <jch@pps.jussieu.fr>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

static int proto_babel = -1;

static gint ett_babel = -1;
static int hf_babel_magic = -1;
static int hf_babel_version = -1;
static int hf_babel_bodylen = -1;

static int hf_babel_message = -1;
static gint ett_message = -1;
static int hf_babel_message_type = -1;
static int hf_babel_message_length = -1;
static int hf_babel_message_nonce = -1;
static int hf_babel_message_interval = -1;
static int hf_babel_message_seqno = -1;
static int hf_babel_message_ae = -1;
static int hf_babel_message_prefix = -1;
static int hf_babel_message_rxcost = -1;
static int hf_babel_message_routerid = -1;
static int hf_babel_message_flags = -1;
static int hf_babel_message_plen = -1;
static int hf_babel_message_omitted = -1;
static int hf_babel_message_metric = -1;
static int hf_babel_message_hopcount = -1;

static gint ett_subtree = -1;

#define UDP_PORT_BABEL 6696
#define UDP_PORT_BABEL_OLD 6697

#define MESSAGE_PAD1 0
#define MESSAGE_PADN 1
#define MESSAGE_ACK_REQ 2
#define MESSAGE_ACK 3
#define MESSAGE_HELLO 4
#define MESSAGE_IHU 5
#define MESSAGE_ROUTER_ID 6
#define MESSAGE_NH 7
#define MESSAGE_UPDATE 8
#define MESSAGE_REQUEST 9
#define MESSAGE_MH_REQUEST 10

static const value_string messages[] = {
    { MESSAGE_PAD1, "pad1"},
    { MESSAGE_PADN, "padn"},
    { MESSAGE_ACK_REQ, "ack-req"},
    { MESSAGE_ACK, "ack"},
    { MESSAGE_HELLO, "hello"},
    { MESSAGE_IHU, "ihu"},
    { MESSAGE_ROUTER_ID, "router-id"},
    { MESSAGE_NH, "nh"},
    { MESSAGE_UPDATE, "update"},
    { MESSAGE_REQUEST, "request"},
    { MESSAGE_MH_REQUEST, "mh-request"},
    { 0, NULL}
};

static const value_string aes[] = {
    { 0, "Wildcard" },
    { 1, "IPv4" },
    { 2, "IPv6" },
    { 3, "Link-Local IPv6"},
    { 0, NULL }
};

/* The prefix for v6-mapped IPv4 addresses.  Format_address below
   returns IPv4 addresses in that format. */

static const unsigned char v4prefix[16] =
    {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };

/* The following two functions return ephemeral or constant strings, no
   need to call free. */

static const char *
format_address(const unsigned char *prefix)
{
    if(prefix == NULL)
        return "corrupt";
    else if(memcmp(prefix, v4prefix, 12) == 0)
        return ip_to_str(prefix + 12);
    else
        return ip6_to_str((const struct e_in6_addr*)prefix);
}

const char *
format_prefix(const unsigned char *prefix, unsigned char plen)
{
    return ep_strdup_printf("%s/%u", format_address(prefix), plen);
}

static int
network_prefix(int ae, int plen, unsigned int omitted,
               const unsigned char *p, const unsigned char *dp,
               unsigned int len, unsigned char *p_r)
{
    unsigned pb;
    unsigned char prefix[16];

    if(plen >= 0)
        pb = (plen + 7) / 8;
    else if(ae == 1)
        pb = 4;
    else
        pb = 16;

    if(pb > 16)
        return -1;

    memset(prefix, 0, 16);

    switch(ae) {
    case 0: break;
    case 1:
        if(omitted > 4 || pb > 4 || (pb > omitted && len < pb - omitted))
            return -1;
        memcpy(prefix, v4prefix, 12);
        if(omitted) {
            if (dp == NULL) return -1;
            memcpy(prefix, dp, 12 + omitted);
        }
        if(pb > omitted) memcpy(prefix + 12 + omitted, p, pb - omitted);
        break;
    case 2:
        if(omitted > 16 || (pb > omitted && len < pb - omitted))
            return -1;
        if(omitted) {
            if (dp == NULL) return -1;
            memcpy(prefix, dp, omitted);
        }
        if(pb > omitted) memcpy(prefix + omitted, p, pb - omitted);
        break;
    case 3:
        if(pb > 8 && len < pb - 8) return -1;
        prefix[0] = 0xfe;
        prefix[1] = 0x80;
        if(pb > 8) memcpy(prefix + 8, p, pb - 8);
        break;
    default:
        return -1;
    }

    memcpy(p_r, prefix, 16);
    return 1;
}

static int
network_address(int ae, const unsigned char *a, unsigned int len,
                unsigned char *a_r)
{
    return network_prefix(ae, -1, 0, a, NULL, len, a_r);
}

static int
dissect_babel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    unsigned char v4_prefix[16] = {0}, v6_prefix[16] = {0};
    int i = 0;
    proto_tree *babel_tree = NULL;
    guint8 version;
    guint16 bodylen;

    if(tvb_length(tvb) < 4)
        return 0;

    if(tvb_get_guint8(tvb, 0) != 42)
        return 0;
    version = tvb_get_guint8(tvb, 1);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Babel");
    col_set_str(pinfo->cinfo, COL_INFO, "Babel");

    if(version != 2) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Version %u", version);
        return 2;
    }

    if(tree) {
        ti = proto_tree_add_item(tree, proto_babel, tvb, 0, -1, ENC_NA);
        babel_tree = proto_item_add_subtree(ti, ett_babel);

        proto_tree_add_item(babel_tree, hf_babel_magic, tvb, 0, 1, ENC_NA);
        proto_tree_add_item(babel_tree, hf_babel_version, tvb, 1, 1, ENC_NA);
        proto_tree_add_item(babel_tree, hf_babel_bodylen,
                            tvb, 2, 2, ENC_BIG_ENDIAN);
    }

    bodylen = tvb_get_ntohs(tvb, 2);

    i = 0;
    while(i < bodylen) {
        guint8 type, len = 0, total_length;
        proto_tree *message_tree = NULL;
        int message = 4 + i;

        type = tvb_get_guint8(tvb, message);
        if(type == MESSAGE_PAD1)
            total_length = 1;
        else {
            len = tvb_get_guint8(tvb, message + 1);
            total_length = len + 2;
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
                        val_to_str(type, messages, "unknown"));

        ti = proto_tree_add_uint_format(babel_tree, hf_babel_message,
                                        tvb, message, total_length, type,
                                        "Message %s (%u)",
                                        val_to_str(type, messages,
                                                   "unknown"),
                                        type);

        if(tree) {
            message_tree = proto_item_add_subtree(ti, ett_message);
            proto_tree_add_item(message_tree, hf_babel_message_type,
                                tvb, message, 1, ENC_NA);
        }

        if(type == MESSAGE_PAD1) {
            i++;
            continue;
        }

        if(tree) {
            proto_tree_add_item(message_tree, hf_babel_message_length,
                                tvb, message + 1, 1, ENC_BIG_ENDIAN);

            if(type == MESSAGE_PADN) {
            } else if(type == MESSAGE_ACK_REQ) {
                proto_tree_add_item(message_tree, hf_babel_message_nonce,
                                    tvb, message + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_interval,
                                    tvb, message + 6, 2, ENC_BIG_ENDIAN);
            } else if(type == MESSAGE_ACK) {
                proto_tree_add_item(message_tree, hf_babel_message_nonce,
                                    tvb, message + 2, 2, ENC_BIG_ENDIAN);
            } else if(type == MESSAGE_HELLO) {
                proto_tree_add_item(message_tree, hf_babel_message_seqno,
                                    tvb, message + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_interval,
                                    tvb, message + 6, 2, ENC_BIG_ENDIAN);
            } else if(type == MESSAGE_IHU) {
                proto_tree *subtree;
                unsigned char address[16];
                int rc =
                    network_address(tvb_get_guint8(tvb, message + 2),
                                    tvb_get_ptr(tvb, message + 8, len - 6),
                                    len - 6,
                                    address);
                proto_tree_add_item(message_tree, hf_babel_message_rxcost,
                                    tvb, message + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_interval,
                                    tvb, message + 6, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_text(message_tree,
                                         tvb, message + 4, len - 2,
                                         "Address: %s",
                                         format_address(rc < 0 ?
                                                        NULL : address));
                subtree = proto_item_add_subtree(ti, ett_subtree);
                proto_tree_add_item(subtree, hf_babel_message_ae,
                                    tvb, message + 2, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_babel_message_prefix,
                                    tvb, message + 4, len - 2, ENC_NA);
            } else if(type == MESSAGE_ROUTER_ID) {
                proto_tree_add_item(message_tree, hf_babel_message_routerid,
                                    tvb, message + 4, 8, ENC_NA);
            } else if(type == MESSAGE_NH) {
                proto_tree *subtree;
                unsigned char nh[16];
                int rc =
                    network_address(tvb_get_guint8(tvb, message + 2),
                                    tvb_get_ptr(tvb, message + 4, len - 2),
                                    len - 2,
                                    nh);
                ti = proto_tree_add_text(message_tree,
                                         tvb, message + 4, len - 2,
                                         "NH: %s",
                                         format_address(rc < 0 ? NULL : nh));
                subtree = proto_item_add_subtree(ti, ett_subtree);
                proto_tree_add_item(subtree, hf_babel_message_ae,
                                    tvb, message + 2, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_babel_message_prefix,
                                    tvb, message + 4, len - 2, ENC_NA);
            } else if(type == MESSAGE_UPDATE) {
                proto_tree *subtree;
                unsigned char p[16];
                guint8 ae = tvb_get_guint8(tvb, message + 2);
                guint8 flags = tvb_get_guint8(tvb, message + 3);
                guint8 plen = tvb_get_guint8(tvb, message + 4);
                int rc =
                    network_prefix(ae, plen,
                                   tvb_get_guint8(tvb, message + 5),
                                   tvb_get_ptr(tvb, message + 12, len - 10),
                                   ae == 1 ? v4_prefix : v6_prefix,
                                   len - 10, p);
                if(rc >= 0 && (flags & 0x80)) {
                    if(ae == 1)
                        memcpy(v4_prefix, p, 16);
                    else
                        memcpy(v6_prefix, p, 16);
                }

                proto_tree_add_item(message_tree, hf_babel_message_flags,
                                    tvb, message + 3, 1, ENC_NA);
                proto_tree_add_item(message_tree, hf_babel_message_interval,
                                    tvb, message + 6, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_seqno,
                                    tvb, message + 8, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_metric,
                                    tvb, message + 10, 2, ENC_BIG_ENDIAN);
                ti = proto_tree_add_text(message_tree,
                                         tvb, message + 12, len - 10,
                                         "Prefix: %s",
                                         format_prefix(rc < 0 ? NULL : p,
                                                       plen));
                subtree = proto_item_add_subtree(ti, ett_subtree);
                proto_tree_add_item(subtree, hf_babel_message_ae,
                                    tvb, message + 2, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_babel_message_plen,
                                    tvb, message + 4, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_babel_message_omitted,
                                    tvb, message + 5, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_babel_message_prefix,
                                    tvb, message + 12, len - 10, ENC_NA);
            } else if(type == MESSAGE_REQUEST) {
                proto_tree *subtree;
                unsigned char p[16];
                guint8 plen = tvb_get_guint8(tvb, message + 3);
                int rc =
                    network_prefix(tvb_get_guint8(tvb, message + 2), plen,
                                   0,
                                   tvb_get_ptr(tvb, message + 4, len - 2),
                                   NULL,
                                   len - 2, p);
                ti = proto_tree_add_text(message_tree,
                                         tvb, message + 4, len - 2,
                                         "Prefix: %s",
                                         format_prefix(rc < 0 ? NULL : p,
                                                       plen));
                subtree = proto_item_add_subtree(ti, ett_subtree);
                proto_tree_add_item(subtree, hf_babel_message_ae,
                                    tvb, message + 2, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_babel_message_plen,
                                    tvb, message + 3, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_babel_message_prefix,
                                    tvb, message + 4, len - 2, ENC_NA);
            } else if(type == MESSAGE_MH_REQUEST) {
                proto_tree *subtree;
                unsigned char p[16];
                guint8 plen = tvb_get_guint8(tvb, message + 3);
                int rc =
                    network_prefix(tvb_get_guint8(tvb, message + 2), plen,
                                   0,
                                   tvb_get_ptr(tvb, message + 16, len - 14),
                                   NULL,
                                   len - 14, p);
                proto_tree_add_item(message_tree, hf_babel_message_seqno,
                                    tvb, message + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_hopcount,
                                    tvb, message + 6, 1, ENC_NA);
                proto_tree_add_item(message_tree, hf_babel_message_routerid,
                                    tvb, message + 8, 8, ENC_NA);
                ti = proto_tree_add_text(message_tree,
                                         tvb, message + 16, len - 14,
                                         "Prefix: %s",
                                         format_prefix(rc < 0 ? NULL : p,
                                                       plen));
                subtree = proto_item_add_subtree(ti, ett_subtree);
                proto_tree_add_item(subtree, hf_babel_message_ae,
                                    tvb, message + 2, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_babel_message_plen,
                                    tvb, message + 3, 1, ENC_NA);
                proto_tree_add_item(subtree, hf_babel_message_prefix,
                                    tvb, message + 16, len - 14, ENC_NA);
            }
        }
        i += len + 2;
    }
    return i;
}

void
proto_register_babel(void)
{
    static hf_register_info hf[] = {
        { &hf_babel_magic,
          { "Magic", "babel.magic", FT_UINT8, BASE_DEC,
            NULL, 0, "Magic value 42", HFILL }
        },
        { &hf_babel_version,
          { "Version", "babel.version", FT_UINT8, BASE_DEC,
            NULL, 0, "Version of the Babel protocol", HFILL }
        },
        { &hf_babel_bodylen,
          { "Body Length", "babel.bodylen", FT_UINT16, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_babel_message,
          { "Message", "babel.message", FT_UINT8, BASE_DEC,
            NULL, 0, "Babel Message", HFILL }
        },
        { &hf_babel_message_type,
          { "Message Type", "babel.message.type", FT_UINT8, BASE_DEC,
            VALS(messages), 0, NULL, HFILL }
        },
        { &hf_babel_message_length,
          { "Message Length", "babel.message.length", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_babel_message_nonce,
          { "Nonce", "babel.message.nonce", FT_UINT16, BASE_HEX,
           NULL, 0, NULL, HFILL }
        },
        { &hf_babel_message_interval,
          { "Interval", "babel.message.interval", FT_UINT16, BASE_DEC,
           NULL, 0, "Interval (in centiseconds)", HFILL }
        },
        { &hf_babel_message_seqno,
          { "Seqno", "babel.message.seqno", FT_UINT16, BASE_HEX,
           NULL, 0, NULL, HFILL }
        },
        { &hf_babel_message_ae,
          { "Address Encoding", "babel.message.ae", FT_UINT8, BASE_DEC,
            VALS(aes), 0, NULL, HFILL }
        },
        { &hf_babel_message_prefix,
          { "Raw Prefix", "babel.message.prefix", FT_BYTES, BASE_NONE,
            NULL, 0, NULL, HFILL }
        },
        { &hf_babel_message_rxcost,
          { "Rxcost", "babel.message.rxcost", FT_UINT16, BASE_HEX,
           NULL, 0, "Rxcost (from the point of vue of the sender)", HFILL }
        },
        { &hf_babel_message_routerid,
          { "Router ID", "babel.message.routerid", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL }
        },
        { &hf_babel_message_flags,
          { "Flags", "babel.message.flags", FT_UINT8, BASE_HEX,
            NULL, 0, NULL, HFILL }
        },
        { &hf_babel_message_plen,
          { "Prefix Length", "babel.message.plen", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
        { &hf_babel_message_omitted,
          { "Omitted Bytes", "babel.message.omitted", FT_UINT8, BASE_DEC,
            NULL, 0, "Number of bytes omitted from the prefix", HFILL }
        },
        { &hf_babel_message_metric,
          { "Metric", "babel.message.metric", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL }
        },
        { &hf_babel_message_hopcount,
          { "Hop Count", "babel.message.hopcount", FT_UINT8, BASE_DEC,
            NULL, 0, NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_babel,
        &ett_message,
        &ett_subtree,
    };

    proto_babel =
        proto_register_protocol("Babel Routing Protocol", "Babel", "babel");

    proto_register_field_array(proto_babel, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_babel(void)
{
    dissector_handle_t babel_handle;

    babel_handle = new_create_dissector_handle(dissect_babel, proto_babel);
    dissector_add_uint("udp.port", UDP_PORT_BABEL, babel_handle);
    dissector_add_uint("udp.port", UDP_PORT_BABEL_OLD, babel_handle);
}
