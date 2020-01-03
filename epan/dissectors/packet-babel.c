/* packet-babel.c
 * Routines for Babel dissection (RFC 6126)
 * Copyright 2011 by Juliusz Chroboczek <jch@pps.jussieu.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
void proto_register_babel(void);
void proto_reg_handoff_babel(void);

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
static int hf_babel_message_index = -1;
static int hf_babel_subtlv = -1;
static int hf_babel_subtlv_type = -1;
static int hf_babel_subtlv_len = -1;
static int hf_babel_subtlv_diversity = -1;

static gint ett_subtree = -1;
static gint ett_packet_trailer = -1;
static gint ett_unicast = -1;
static gint ett_subtlv = -1;
static gint ett_timestamp = -1;
static gint ett_mandatory = -1;

#define UDP_PORT_RANGE_BABEL "6696"

#define MESSAGE_PAD1        0
#define MESSAGE_PADN        1
#define MESSAGE_ACK_REQ     2
#define MESSAGE_ACK         3
#define MESSAGE_HELLO       4
#define MESSAGE_IHU         5
#define MESSAGE_ROUTER_ID   6
#define MESSAGE_NH          7
#define MESSAGE_UPDATE      8
#define MESSAGE_REQUEST     9
#define MESSAGE_MH_REQUEST 10
#define MESSAGE_TS_PC      11
#define MESSAGE_HMAC_OLD   12
#define MESSAGE_SRC_UPDATE 13
#define MESSAGE_SRC_REQUEST 14
#define MESSAGE_SRC_SEQNO   15
#define MESSAGE_HMAC    16
#define MESSAGE_PC      17
#define MESSAGE_CHALLENGE_REQUEST 18
#define MESSAGE_CHALLENGE_REPLY 19

/** sub-TLVs */
#define MESSAGE_SUB_PAD1 0
#define MESSAGE_SUB_PADN 1
#define MESSAGE_SUB_DIVERSITY 2
#define MESSAGE_SUB_TIMESTAMP 3

/** mask for bits */
#define UNICAST_FLAG 0x80
#define MANDATORY_FLAG 128

/** message string values listed in rfc7557 */
static const value_string messages[] = {
    { MESSAGE_PAD1,         "pad1"},
    { MESSAGE_PADN,         "padn"},
    { MESSAGE_ACK_REQ,      "ack-req"},
    { MESSAGE_ACK,          "ack"},
    { MESSAGE_HELLO,        "hello"},
    { MESSAGE_IHU,          "ihu"},
    { MESSAGE_ROUTER_ID,    "router-id"},
    { MESSAGE_NH,           "nh"},
    { MESSAGE_UPDATE,       "update"},
    { MESSAGE_REQUEST,      "request"},
    { MESSAGE_MH_REQUEST,   "mh-request"},
    { MESSAGE_TS_PC,        "ts/pc (obsolete)"},
    { MESSAGE_HMAC_OLD,     "hmac" },
    { MESSAGE_SRC_UPDATE,   "source-specific-update"},
    { MESSAGE_SRC_REQUEST,  "source-specific-req"},
    { MESSAGE_SRC_SEQNO,    "source-specific-seqno"},
    { MESSAGE_HMAC,         "hmac"},
    { MESSAGE_PC,           "pc"},
    { MESSAGE_CHALLENGE_REQUEST,  "challenge-request"},
    { MESSAGE_CHALLENGE_REPLY,    "challenge-reply"},
    { 0, NULL}
};

static const value_string subtlvs[] = {
    { MESSAGE_SUB_PAD1,       "sub-pad1"},
    { MESSAGE_SUB_PADN,       "sub-padn"},
    { MESSAGE_SUB_DIVERSITY,  "diversity"},
    { MESSAGE_SUB_TIMESTAMP,  "timestamp"},
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
    address addr;

    if (prefix == NULL)
        return "corrupt";
    else if (memcmp(prefix, v4prefix, 12) == 0)
    {
        addr.type = AT_IPv4;
        addr.len  = 4;
        addr.data = prefix + 12;

        return address_to_str(wmem_packet_scope(), &addr);
    }
    else
    {
        addr.type = AT_IPv6;
        addr.len  = 16;
        addr.data = prefix;

        return address_to_str(wmem_packet_scope(), &addr);
    }
}

static const char *
format_prefix(const unsigned char *prefix, unsigned char plen)
{
    return wmem_strdup_printf(wmem_packet_scope(), "%s/%u", format_address(prefix), plen);
}

static int
network_prefix(int ae, int plen, unsigned int omitted,
               tvbuff_t *tvb, int offset, const unsigned char *dp,
               unsigned int len, unsigned char *p_r)
{
    guint      pb;
    unsigned char prefix[16];
    int consumed = 0;

    if (plen >= 0)
        pb = (plen + 7) / 8;
    else if (ae == 1)
        pb = 4;
    else
        pb = 16;

    if (pb > 16)
        return -1;

    memset(prefix, 0, 16);

    switch(ae) {
    case 0: break;
    case 1:
        if (omitted > 4 || pb > 4 || (pb > omitted && len < pb - omitted))
            return -1;
        memcpy(prefix, v4prefix, 12);
        if (omitted) {
            if (dp == NULL) return -1;
            memcpy(prefix, dp, 12 + omitted);
        }
        if (pb > omitted) {
            tvb_memcpy(tvb, prefix + 12 + omitted, offset, pb - omitted);
            consumed = pb - omitted;
        }
        break;
    case 2:
        if (omitted > 16 || (pb > omitted && len < pb - omitted))
            return -1;
        if (omitted) {
            if (dp == NULL) return -1;
            memcpy(prefix, dp, omitted);
        }
        if (pb > omitted) {
            tvb_memcpy(tvb, prefix + omitted, offset, pb - omitted);
            consumed = pb - omitted;
        }
        break;
    case 3:
        if (pb > 8 && len < pb - 8) return -1;
        prefix[0] = 0xfe;
        prefix[1] = 0x80;
        if (pb > 8) {
            tvb_memcpy(tvb, prefix + 8, offset, pb - 8);
            consumed = pb - 8;
        }
        break;
    default:
        return -1;
    }

    memcpy(p_r, prefix, 16);
    return consumed;
}

static int
network_address(int ae, tvbuff_t *tvb, int offset, unsigned int len,
                unsigned char *a_r)
{
    return network_prefix(ae, -1, 0, tvb, offset, NULL, len, a_r);
}

static const char *
format_timestamp(const guint32 i)
{
    static char buf[sizeof("0000.000000s")];
    g_snprintf(buf, sizeof(buf), "%u.%06us", i / 1000000, i % 1000000);
    return buf;
}

static int
dissect_babel_subtlvs(tvbuff_t * tvb, guint8 type, guint16 beg,
                      guint16 end, proto_tree *message_tree)
{
    proto_tree *channel_tree = NULL;
    proto_item *sub_item;
    guint8      subtype, sublen;
    int i = 0;

    while(beg < end) {
        proto_tree *subtlv_tree;
        subtype = tvb_get_guint8(tvb, beg);
        if (subtype != MESSAGE_SUB_PAD1) {
            sublen = tvb_get_guint8(tvb, beg+1);
        } else {
            sublen = 0;
        }

        sub_item =
          proto_tree_add_uint_format(message_tree, hf_babel_subtlv,
                                     tvb, beg, sublen + ((subtype == MESSAGE_SUB_PAD1) ? 1 : 2),
                                     subtype, "Sub TLV %s (%u)",
                                     val_to_str_const(subtype, subtlvs, "unknown"),
                                     subtype);
        subtlv_tree = proto_item_add_subtree(sub_item, ett_subtlv);

        proto_tree_add_item(subtlv_tree, hf_babel_subtlv_type,
                            tvb, beg, 1, ENC_BIG_ENDIAN);
        if(subtype == MESSAGE_SUB_PAD1){
            beg += 1;
            continue;
        }
        proto_tree_add_item(subtlv_tree, hf_babel_subtlv_len,
                            tvb, beg+1, 1, ENC_BIG_ENDIAN);

        if ((MANDATORY_FLAG & subtype) != 0) {
            proto_tree_add_subtree_format(subtlv_tree, tvb, beg+2, sublen,
                                          ett_mandatory, NULL, "Mandatory");
        }

        switch(subtype) {
            case MESSAGE_SUB_PADN:
                break;
            case MESSAGE_SUB_DIVERSITY: {
                i = 0;
                channel_tree = proto_tree_add_subtree_format(subtlv_tree, tvb,
                                                             beg+2, 0, ett_subtlv,
                                                             NULL, "Channel");
                while(i < sublen) {
                    proto_tree_add_item(channel_tree, hf_babel_subtlv_diversity,
                                        tvb, beg+2+i, 1, ENC_BIG_ENDIAN);
                    i++;
                }
            }
                break;
            case MESSAGE_SUB_TIMESTAMP:  {
                if (type == MESSAGE_HELLO) {
                    guint32 t1 = tvb_get_guint32(tvb, beg+2, ENC_BIG_ENDIAN);
                    proto_tree_add_subtree_format(subtlv_tree, tvb, beg+2,
                                                  sublen, ett_timestamp, NULL,
                                                  "Timestamp : %s",
                                                  format_timestamp(t1));
                } else if (type == MESSAGE_IHU) {
                    guint32 t1 = tvb_get_guint32(tvb, beg+2, ENC_BIG_ENDIAN);
                    guint32 t2 = tvb_get_guint32(tvb, beg+6, ENC_BIG_ENDIAN);
                    proto_tree_add_subtree_format(subtlv_tree, tvb, beg+2,
                                                  sublen, ett_timestamp, NULL,
                                                  "Timestamp origin : %s",
                                                  format_timestamp(t1));
                    proto_tree_add_subtree_format(subtlv_tree, tvb, beg+6,
                                                  sublen, ett_timestamp, NULL,
                                                  "Timestamp receive: %s",
                                                  format_timestamp(t2));
                } else {
                    proto_tree_add_subtree_format(subtlv_tree, tvb, beg+2, sublen,
                                                  ett_timestamp, NULL, "Bogus");
                }
            }
              break;
        }
        beg += (sublen+2);
    }
    return end-beg;
}


/* The following function is used to read the packet body and
 the packet trailer */
static int
dissect_babel_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   int offset, guint16 bodylen)
{
    proto_item *ti = NULL;
    unsigned char  v4_prefix[16] = {0}, v6_prefix[16] = {0};
    int            i;


    i = offset;
    while (i-offset < bodylen) {
        guint8      type, len    = 0;
        guint16     total_length;
        proto_tree *message_tree = NULL;
        int         message      = 4 + i;

        type = tvb_get_guint8(tvb, message);
        if (type == MESSAGE_PAD1)
            total_length = 1;
        else {
            len = tvb_get_guint8(tvb, message + 1);
            total_length = len + 2;
        }

        col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
                        val_to_str_const(type, messages, "unknown"));

        ti = proto_tree_add_uint_format(tree, hf_babel_message,
                                        tvb, message, total_length, type,
                                        "Message %s (%u)",
                                        val_to_str_const(type, messages, "unknown"),
                                        type);

        if (tree) {
            message_tree = proto_item_add_subtree(ti, ett_message);
            proto_tree_add_item(message_tree, hf_babel_message_type,
                                tvb, message, 1, ENC_BIG_ENDIAN);
        }

        if (type == MESSAGE_PAD1) {
            i++;
            continue;
        }

        if (tree) {
            proto_tree_add_item(message_tree, hf_babel_message_length,
                                tvb, message + 1, 1, ENC_BIG_ENDIAN);
            if (type == MESSAGE_PADN) {
            } else if (type == MESSAGE_ACK_REQ) {
                proto_tree_add_item(message_tree, hf_babel_message_nonce,
                                    tvb, message + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_interval,
                                    tvb, message + 6, 2, ENC_BIG_ENDIAN);
            } else if (type == MESSAGE_ACK) {
                proto_tree_add_item(message_tree, hf_babel_message_nonce,
                                    tvb, message + 2, 2, ENC_BIG_ENDIAN);
            } else if (type == MESSAGE_HELLO) {
                guint8 unicast = tvb_get_guint8(tvb, 2);
                proto_tree_add_subtree_format(message_tree,
                                         tvb, message + 2, 2,
                                         ett_unicast, NULL,
                                         "Unicast : %u",
                                         unicast);
                proto_tree_add_item(message_tree, hf_babel_message_seqno,
                                    tvb, message + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_interval,
                                    tvb, message + 6, 2, ENC_BIG_ENDIAN);
                if(len > 6)
                    dissect_babel_subtlvs(tvb, type, message + 8,
                                          message + 2 + len, message_tree);
            } else if (type == MESSAGE_IHU) {
                proto_tree    *subtree;
                unsigned char  addr_str[16];
                int rc =
                    network_address(tvb_get_guint8(tvb, message + 2),
                                    tvb, message + 8, len - 6, addr_str);
                proto_tree_add_item(message_tree, hf_babel_message_rxcost,
                                    tvb, message + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_interval,
                                    tvb, message + 6, 2, ENC_BIG_ENDIAN);
                subtree = proto_tree_add_subtree_format(message_tree,
                                         tvb, message + 4, len - 2,
                                         ett_subtree, NULL, "Address: %s",
                                         format_address(rc < 0 ?
                                                        NULL : addr_str));
                proto_tree_add_item(subtree, hf_babel_message_ae,
                                    tvb, message + 2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_babel_message_prefix,
                                    tvb, message + 4, len - 2, ENC_NA);
                if (rc < len - 6)
                    dissect_babel_subtlvs(tvb, type, message + 8 + rc,
                                          message + 2 + len, message_tree);
            } else if (type == MESSAGE_ROUTER_ID) {
                proto_tree_add_item(message_tree, hf_babel_message_routerid,
                                    tvb, message + 4, 8, ENC_NA);
            } else if (type == MESSAGE_NH) {
                proto_tree    *subtree;
                unsigned char  nh[16];
                int rc =
                    network_address(tvb_get_guint8(tvb, message + 2),
                                    tvb, message + 4, len - 2, nh);
                subtree = proto_tree_add_subtree_format(message_tree,
                                         tvb, message + 4, len - 2,
                                         ett_subtree, NULL,
                                         "NH: %s",
                                         format_address(rc < 0 ? NULL : nh));
                proto_tree_add_item(subtree, hf_babel_message_ae,
                                    tvb, message + 2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_babel_message_prefix,
                                    tvb, message + 4, len - 2, ENC_NA);
            } else if (type == MESSAGE_UPDATE) {
                proto_tree    *subtree;
                unsigned char  p[16];
                guint8         ae    = tvb_get_guint8(tvb, message + 2);
                guint8         flags = tvb_get_guint8(tvb, message + 3);
                guint8         plen  = tvb_get_guint8(tvb, message + 4);
                int rc =
                    network_prefix(ae, plen,
                                   tvb_get_guint8(tvb, message + 5),
                                   tvb, message + 12,
                                   ae == 1 ? v4_prefix : v6_prefix,
                                   len - 10, p);
                if (rc >= 0 && (flags & 0x80)) {
                    if (ae == 1)
                        memcpy(v4_prefix, p, 16);
                    else
                        memcpy(v6_prefix, p, 16);
                }

                proto_tree_add_item(message_tree, hf_babel_message_flags,
                                    tvb, message + 3, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_interval,
                                    tvb, message + 6, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_seqno,
                                    tvb, message + 8, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_metric,
                                    tvb, message + 10, 2, ENC_BIG_ENDIAN);
                subtree = proto_tree_add_subtree_format(message_tree,
                                         tvb, message + 12, len - 10,
                                         ett_subtree, NULL,
                                         "Prefix: %s",
                                         format_prefix(rc < 0 ? NULL : p,
                                                       plen));
                proto_tree_add_item(subtree, hf_babel_message_ae,
                                    tvb, message + 2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_babel_message_plen,
                                    tvb, message + 4, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_babel_message_omitted,
                                    tvb, message + 5, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_babel_message_prefix,
                                    tvb, message + 12, len - 10, ENC_NA);
                if (((guint8)rc) < len - 10)
                    dissect_babel_subtlvs(tvb, type, message + 12 + rc,
                                          message + 2 + len, message_tree);
            } else if (type == MESSAGE_REQUEST) {
                proto_tree    *subtree;
                unsigned char  p[16];
                guint8         plen = tvb_get_guint8(tvb, message + 3);
                int rc =
                    network_prefix(tvb_get_guint8(tvb, message + 2), plen,
                                   0, tvb, message + 4, NULL,
                                   len - 2, p);
                subtree = proto_tree_add_subtree_format(message_tree,
                                         tvb, message + 4, len - 2,
                                         ett_subtree, NULL,
                                         "Prefix: %s",
                                         format_prefix(rc < 0 ? NULL : p,
                                                       plen));
                proto_tree_add_item(subtree, hf_babel_message_ae,
                                    tvb, message + 2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_babel_message_plen,
                                    tvb, message + 3, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_babel_message_prefix,
                                    tvb, message + 4, len - 2, ENC_NA);
            } else if (type == MESSAGE_MH_REQUEST) {
                proto_tree    *subtree;
                unsigned char  p[16];
                guint8         plen = tvb_get_guint8(tvb, message + 3);
                int rc =
                    network_prefix(tvb_get_guint8(tvb, message + 2), plen,
                                   0, tvb, message + 16, NULL,
                                   len - 14, p);
                proto_tree_add_item(message_tree, hf_babel_message_seqno,
                                    tvb, message + 4, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_hopcount,
                                    tvb, message + 6, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(message_tree, hf_babel_message_routerid,
                                    tvb, message + 8, 8, ENC_NA);
                subtree = proto_tree_add_subtree_format(message_tree,
                                         tvb, message + 16, len - 14,
                                         ett_subtree, NULL,
                                         "Prefix: %s",
                                         format_prefix(rc < 0 ? NULL : p,
                                                       plen));
                proto_tree_add_item(subtree, hf_babel_message_ae,
                                    tvb, message + 2, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_babel_message_plen,
                                    tvb, message + 3, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(subtree, hf_babel_message_prefix,
                                    tvb, message + 16, len - 14, ENC_NA);
            } else if (type == MESSAGE_PC){
                proto_tree_add_item(message_tree, hf_babel_message_index,
                                    tvb, message + 2, 4, ENC_NA);
            }
        }
        i += len + 2;
    }
    guint8 packet_len = tvb_reported_length(tvb) - bodylen - 4;
    if ((offset == 0) && (packet_len != 0)) {
        proto_tree * subtree;
        subtree = proto_tree_add_subtree_format(tree, tvb, 4+bodylen, packet_len,
                                                ett_packet_trailer, NULL,
                                                "Packet Trailer (%u)", packet_len);
        dissect_babel_body(tvb, pinfo, subtree, bodylen, packet_len);
    }
    return i;
}

static int
dissect_babel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item    *ti;
    proto_tree    *babel_tree = NULL;
    guint8         version;
    guint16        bodylen;

    if (tvb_captured_length(tvb) < 4)
        return 0;

    if (tvb_get_guint8(tvb, 0) != 42)
        return 0;
    version = tvb_get_guint8(tvb, 1);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Babel");
    col_set_str(pinfo->cinfo, COL_INFO, "Babel");

    if (version != 2) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Version %u", version);
        return 2;
    }

    if (tree) {
        ti = proto_tree_add_item(tree, proto_babel, tvb, 0, -1, ENC_NA);
        babel_tree = proto_item_add_subtree(ti, ett_babel);

        proto_tree_add_item(babel_tree, hf_babel_magic, tvb, 0, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(babel_tree, hf_babel_version, tvb, 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(babel_tree, hf_babel_bodylen,
                            tvb, 2, 2, ENC_BIG_ENDIAN);
    }
    bodylen = tvb_get_ntohs(tvb, 2);
    return dissect_babel_body(tvb, pinfo, babel_tree, 0, bodylen);

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
        { &hf_babel_message_index,
          { "Index", "babel.message.index", FT_UINT32, BASE_DEC,
          NULL, 0, NULL, HFILL }
        },
        { &hf_babel_subtlv,
          { "Sub-TLV", "babel.subtlv", FT_UINT8, BASE_DEC,
          NULL, 0, "Babel Sub-TLV", HFILL }
        },
        { &hf_babel_subtlv_type,
          { "Sub-TLV Type", "babel.subtlv.type", FT_UINT8, BASE_DEC,
          VALS(subtlvs), 0, NULL, HFILL }
        },
        { &hf_babel_subtlv_len,
          { "Sub-TLV Length", "babel.subtlv.length", FT_UINT8, BASE_DEC,
          VALS(subtlvs), 0, NULL, HFILL }
        },
        { &hf_babel_subtlv_diversity,
          { "Channel", "babel.subtlv.diversity.channel", FT_UINT8, BASE_DEC,
          NULL, 0, NULL, HFILL  }
        }
    };

    static gint *ett[] = {
        &ett_babel,
        &ett_message,
        &ett_subtree,
        &ett_packet_trailer,
        &ett_unicast,
        &ett_subtlv,
        &ett_timestamp,
        &ett_mandatory
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

    babel_handle = create_dissector_handle(dissect_babel, proto_babel);
    dissector_add_uint_range_with_preference("udp.port", UDP_PORT_RANGE_BABEL, babel_handle);
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
