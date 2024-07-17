/* packet-nflog.c
 * Copyright 2011,2012 Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/etypes.h>
#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <wsutil/ws_roundup.h>

#include "packet-netlink.h"

void proto_register_nflog(void);
void proto_reg_handoff_nflog(void);

/* nfulnl_attr_type enum from <linux/netfilter/nfnetlink_log.h> */
enum ws_nfulnl_attr_type {
    WS_NFULA_UNSPEC,
    WS_NFULA_PACKET_HDR,
    WS_NFULA_MARK,               /* __u32 nfmark */
    WS_NFULA_TIMESTAMP,          /* nfulnl_msg_packet_timestamp */
    WS_NFULA_IFINDEX_INDEV,      /* __u32 ifindex */
    WS_NFULA_IFINDEX_OUTDEV,     /* __u32 ifindex */
    WS_NFULA_IFINDEX_PHYSINDEV,  /* __u32 ifindex */
    WS_NFULA_IFINDEX_PHYSOUTDEV, /* __u32 ifindex */
    WS_NFULA_HWADDR,             /* nfulnl_msg_packet_hw */
    WS_NFULA_PAYLOAD,            /* opaque data payload */
    WS_NFULA_PREFIX,             /* string prefix */
    WS_NFULA_UID,                /* user id of socket */
    WS_NFULA_SEQ,                /* instance-local sequence number */
    WS_NFULA_SEQ_GLOBAL,         /* global sequence number */
    WS_NFULA_GID,                /* group id of socket */
    WS_NFULA_HWTYPE,             /* hardware type */
    WS_NFULA_HWHEADER,           /* hardware header */
    WS_NFULA_HWLEN               /* hardware header length */
};

static const value_string nflog_tlv_vals[] = {
    { WS_NFULA_UNSPEC,             "NFULA_UNSPEC" },
    { WS_NFULA_PACKET_HDR,         "NFULA_PACKET_HDR" },
    { WS_NFULA_MARK,               "NFULA_MARK" },
    { WS_NFULA_TIMESTAMP,          "NFULA_TIMESTAMP" },
    { WS_NFULA_IFINDEX_INDEV,      "NFULA_IFINDEX_INDEV" },
    { WS_NFULA_IFINDEX_OUTDEV,     "NFULA_IFINDEX_OUTDEV" },
    { WS_NFULA_IFINDEX_PHYSINDEV,  "NFULA_IFINDEX_PHYSINDEV" },
    { WS_NFULA_IFINDEX_PHYSOUTDEV, "NFULA_IFINDEX_PHYSOUTDEV" },
    { WS_NFULA_HWADDR,             "NFULA_HWADDR" },
    { WS_NFULA_PAYLOAD,            "NFULA_PAYLOAD" },
    { WS_NFULA_PREFIX,             "NFULA_PREFIX" },
    { WS_NFULA_UID,                "NFULA_UID" },
    { WS_NFULA_SEQ,                "NFULA_SEQ" },
    { WS_NFULA_SEQ_GLOBAL,         "NFULA_SEQ_GLOBAL" },
    { WS_NFULA_GID,                "NFULA_GID" },
    { WS_NFULA_HWTYPE,             "NFULA_HWTYPE" },
    { WS_NFULA_HWHEADER,           "NFULA_HWHEADER" },
    { WS_NFULA_HWLEN,              "NFULA_HWLEN" },
    { 0, NULL }
};

static int proto_nflog;

static int hf_nflog_family;
static int hf_nflog_resid;
static int hf_nflog_tlv;
static int hf_nflog_tlv_gid;
static int hf_nflog_tlv_hook;
static int hf_nflog_tlv_hwprotocol;
static int hf_nflog_tlv_ifindex_indev;
static int hf_nflog_tlv_ifindex_outdev;
static int hf_nflog_tlv_ifindex_physindev;
static int hf_nflog_tlv_ifindex_physoutdev;
static int hf_nflog_tlv_length;
static int hf_nflog_tlv_prefix;
static int hf_nflog_tlv_timestamp;
static int hf_nflog_tlv_type;
static int hf_nflog_tlv_uid;
static int hf_nflog_tlv_unknown;
static int hf_nflog_version;

static int ett_nflog;
static int ett_nflog_tlv;

static dissector_handle_t ip_handle;
static dissector_handle_t ip6_handle;
static dissector_table_t ethertype_table;
static dissector_handle_t nflog_handle;

static int
dissect_nflog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    const int start_tlv_offset = 4;

    proto_tree *nflog_tree = NULL;
    proto_item *ti;

    int offset = 0;

    tvbuff_t *next_tvb = NULL;
    int pf;
    uint16_t hw_protocol = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NFLOG");
    col_clear(pinfo->cinfo, COL_INFO);

    pf = tvb_get_uint8(tvb, 0);

    /* Header */
    if (proto_field_is_referenced(tree, proto_nflog)) {
        ti = proto_tree_add_item(tree, proto_nflog, tvb, 0, -1, ENC_NA);
        nflog_tree = proto_item_add_subtree(ti, ett_nflog);

        proto_tree_add_item(nflog_tree, hf_nflog_family, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(nflog_tree, hf_nflog_version, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(nflog_tree, hf_nflog_resid, tvb, offset, 2, ENC_BIG_ENDIAN);
        /*offset += 2;*/
    }

    offset = start_tlv_offset;
    /* TLVs */
    while (tvb_reported_length_remaining(tvb, offset) >= 4) {
        uint16_t tlv_len = tvb_get_h_uint16(tvb, offset + 0);
        uint16_t tlv_type;
        uint16_t value_len;

        proto_tree *tlv_tree;

        /* malformed */
        if (tlv_len < 4)
            return offset;

        value_len = tlv_len - 4;
        tlv_type = (tvb_get_h_uint16(tvb, offset + 2) & 0x7fff);

        if (nflog_tree) {
            bool handled = false;

            ti = proto_tree_add_bytes_format(nflog_tree, hf_nflog_tlv,
                             tvb, offset, tlv_len, NULL,
                             "TLV Type: %s (%u), Length: %u",
                             val_to_str_const(tlv_type, nflog_tlv_vals, "Unknown"),
                             tlv_type, tlv_len);
            tlv_tree = proto_item_add_subtree(ti, ett_nflog_tlv);

            proto_tree_add_item(tlv_tree, hf_nflog_tlv_length, tvb, offset + 0, 2, ENC_HOST_ENDIAN);
            proto_tree_add_item(tlv_tree, hf_nflog_tlv_type, tvb, offset + 2, 2, ENC_HOST_ENDIAN);
            switch (tlv_type) {
                case WS_NFULA_PACKET_HDR:
                    if (value_len == 4) {
                        proto_tree_add_item(tlv_tree, hf_nflog_tlv_hwprotocol,
                                    tvb, offset + 4, 2, ENC_BIG_ENDIAN);
                        proto_tree_add_item(tlv_tree, hf_nflog_tlv_hook,
                                    tvb, offset + 6, 1, ENC_NA);
                        handled = true;
                    }
                    break;

                case WS_NFULA_IFINDEX_INDEV:
                    if (value_len == 4) {
                        proto_tree_add_item(tlv_tree, hf_nflog_tlv_ifindex_indev, tvb, offset + 4, value_len, ENC_BIG_ENDIAN);
                        handled = true;
                    }
                    break;

                case WS_NFULA_IFINDEX_OUTDEV:
                    if (value_len == 4) {
                        proto_tree_add_item(tlv_tree, hf_nflog_tlv_ifindex_outdev, tvb, offset + 4, value_len, ENC_BIG_ENDIAN);
                        handled = true;
                    }
                    break;

                case WS_NFULA_IFINDEX_PHYSINDEV:
                    if (value_len == 4) {
                        proto_tree_add_item(tlv_tree, hf_nflog_tlv_ifindex_physindev, tvb, offset + 4, value_len, ENC_BIG_ENDIAN);
                        handled = true;
                    }
                    break;

                case WS_NFULA_IFINDEX_PHYSOUTDEV:
                    if (value_len == 4) {
                        proto_tree_add_item(tlv_tree, hf_nflog_tlv_ifindex_physoutdev, tvb, offset + 4, value_len, ENC_BIG_ENDIAN);
                        handled = true;
                    }
                    break;

                case WS_NFULA_PAYLOAD:
                    handled = true;
                    break;

                case WS_NFULA_PREFIX:
                    if (value_len >= 1) {
                        proto_tree_add_item(tlv_tree, hf_nflog_tlv_prefix,
                                    tvb, offset + 4, value_len, ENC_ASCII);
                        handled = true;
                    }
                    break;

                case WS_NFULA_UID:
                    if (value_len == 4) {
                        proto_tree_add_item(tlv_tree, hf_nflog_tlv_uid,
                                    tvb, offset + 4, value_len, ENC_BIG_ENDIAN);
                        handled = true;
                    }
                    break;

                case WS_NFULA_GID:
                    if (value_len == 4) {
                        proto_tree_add_item(tlv_tree, hf_nflog_tlv_gid,
                                    tvb, offset + 4, value_len, ENC_BIG_ENDIAN);
                        handled = true;
                    }
                    break;

                case WS_NFULA_TIMESTAMP:
                    if (value_len == 16) {
                        /*
                         * 64-bit seconds and 64-bit microseconds.
                         *
                         * XXX - add an "expert info" warning if the
                         * microseconds are >= 10^6?
                         */
                        proto_tree_add_item(tlv_tree, hf_nflog_tlv_timestamp,
                                    tvb, offset + 4, value_len,
                                    ENC_TIME_SECS_USECS|ENC_BIG_ENDIAN);
                        handled = true;
                    }
                    break;
            }

            if (!handled)
                    proto_tree_add_item(tlv_tree, hf_nflog_tlv_unknown,
                                        tvb, offset + 4, value_len, ENC_NA);
        }

        if (tlv_type == WS_NFULA_PACKET_HDR && value_len == 4)
            hw_protocol = tvb_get_ntohs(tvb, offset + 4);
        if (tlv_type == WS_NFULA_PAYLOAD)
            next_tvb = tvb_new_subset_length(tvb, offset + 4, value_len);

        offset += WS_ROUNDUP_4(tlv_len); /* next TLV aligned to 4B */
    }

    if (next_tvb && hw_protocol) {
        if (!dissector_try_uint(ethertype_table, hw_protocol, next_tvb, pinfo, tree))
            call_data_dissector(next_tvb, pinfo, tree);
    } else if (next_tvb) {
        switch (pf) {
            /* Note: NFPROTO_INET is not supposed to appear here, it is mapped
             * to NFPROTO_IPV4 or NFPROTO_IPV6 */
            case WS_NFPROTO_IPV4:
                call_dissector(ip_handle, next_tvb, pinfo, tree);
                break;
            case WS_NFPROTO_IPV6:
                call_dissector(ip6_handle, next_tvb, pinfo, tree);
                break;
            default:
                call_data_dissector(next_tvb, pinfo, tree);
                break;
        }
    }
    return tvb_captured_length(tvb);
}

void
proto_register_nflog(void)
{
    static hf_register_info hf[] = {
        { &hf_nflog_family,
            { "Family", "nflog.family",
              FT_UINT8, BASE_DEC, VALS(nfproto_family_vals), 0x00,
              NULL, HFILL }
        },
        { &hf_nflog_version,
            { "Version", "nflog.version",
              FT_UINT8, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nflog_resid,
            { "Resource id", "nflog.res_id",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nflog_tlv,
            { "TLV", "nflog.tlv",
              FT_BYTES, BASE_NONE, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nflog_tlv_length,
            { "Length", "nflog.tlv_length",
              FT_UINT16, BASE_DEC, NULL, 0x00,
              "TLV Length", HFILL }
        },
        { &hf_nflog_tlv_type,
            { "Type", "nflog.tlv_type",
              FT_UINT16, BASE_DEC, VALS(nflog_tlv_vals), 0x7fff,
              "TLV Type", HFILL }
        },
        { &hf_nflog_tlv_hwprotocol,
            { "HW protocol", "nflog.protocol",
              FT_UINT16, BASE_HEX, VALS(etype_vals), 0x00,
              NULL, HFILL }
        },
        { &hf_nflog_tlv_hook,
            { "Netfilter hook", "nflog.hook",
              FT_UINT8, BASE_DEC, VALS(netfilter_hooks_vals), 0x00,
              NULL, HFILL }
        },
        { &hf_nflog_tlv_ifindex_indev,
            { "IFINDEX_INDEV", "nflog.ifindex_indev",
              FT_UINT32, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nflog_tlv_ifindex_outdev,
            { "IFINDEX_OUTDEV", "nflog.ifindex_outdev",
              FT_UINT32, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nflog_tlv_ifindex_physindev,
            { "IFINDEX_PHYSINDEV", "nflog.ifindex_physindev",
              FT_UINT32, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nflog_tlv_ifindex_physoutdev,
            { "IFINDEX_PHYSOUTDEV", "nflog.ifindex_physoutdev",
              FT_UINT32, BASE_DEC, NULL, 0x00,
              NULL, HFILL }
        },
        { &hf_nflog_tlv_prefix,
            { "Prefix", "nflog.prefix",
              FT_STRINGZ, BASE_NONE, NULL, 0x00,
              "TLV Prefix Value", HFILL }
        },
        { &hf_nflog_tlv_uid,
            { "UID", "nflog.uid",
              FT_INT32, BASE_DEC, NULL, 0x00,
              "TLV UID Value", HFILL }
        },
        { &hf_nflog_tlv_gid,
            { "GID", "nflog.gid",
              FT_INT32, BASE_DEC, NULL, 0x00,
              "TLV GID Value", HFILL }
        },
        { &hf_nflog_tlv_timestamp,
            { "Timestamp", "nflog.timestamp",
              FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00,
              "TLV Timestamp Value", HFILL }
        },
        { &hf_nflog_tlv_unknown,
            { "Value", "nflog.tlv_value",
              FT_BYTES, BASE_NONE, NULL, 0x00,
              "TLV Value", HFILL }
        },
    };

    static int *ett[] = {
        &ett_nflog,
        &ett_nflog_tlv
    };

    proto_nflog = proto_register_protocol("Linux Netfilter NFLOG", "NFLOG", "nflog");

    nflog_handle = register_dissector("nflog", dissect_nflog, proto_nflog);

    proto_register_field_array(proto_nflog, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_nflog(void)
{
    ip_handle   = find_dissector_add_dependency("ip", proto_nflog);
    ip6_handle  = find_dissector_add_dependency("ipv6", proto_nflog);

    dissector_add_uint("wtap_encap", WTAP_ENCAP_NFLOG, nflog_handle);
    ethertype_table = find_dissector_table("ethertype");
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
