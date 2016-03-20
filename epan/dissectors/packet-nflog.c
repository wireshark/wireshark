/* packet-nflog.c
 * Copyright 2011,2012 Jakub Zawadzki <darkjames-ws@darkjames.pl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <epan/packet.h>
#include <epan/aftypes.h>
#include <wiretap/wtap.h>

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

static int ett_nflog = -1;
static int ett_nflog_tlv = -1;

static header_field_info *hfi_nflog = NULL;

#define NFLOG_HFI_INIT HFI_INIT(proto_nflog)

/* Header */
static header_field_info hfi_nflog_family NFLOG_HFI_INIT =
    { "Family", "nflog.family", FT_UINT8, BASE_DEC | BASE_EXT_STRING, &linux_af_vals_ext, 0x00, NULL, HFILL };

static header_field_info hfi_nflog_version NFLOG_HFI_INIT =
    { "Version", "nflog.version", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nflog_resid NFLOG_HFI_INIT =
    { "Resource id", "nflog.res_id", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL };

/* TLV */
static header_field_info hfi_nflog_tlv NFLOG_HFI_INIT =
    { "TLV", "nflog.tlv", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL };

static header_field_info hfi_nflog_tlv_length NFLOG_HFI_INIT =
    { "Length", "nflog.tlv_length", FT_UINT16, BASE_DEC, NULL, 0x00, "TLV Length", HFILL };

static header_field_info hfi_nflog_tlv_type NFLOG_HFI_INIT =
    { "Type", "nflog.tlv_type", FT_UINT16, BASE_DEC, VALS(nflog_tlv_vals), 0x7fff, "TLV Type", HFILL };

/* TLV values */
static header_field_info hfi_nflog_tlv_prefix NFLOG_HFI_INIT =
    { "Prefix", "nflog.prefix", FT_STRINGZ, BASE_NONE, NULL, 0x00, "TLV Prefix Value", HFILL };

static header_field_info hfi_nflog_tlv_uid NFLOG_HFI_INIT =
    { "UID", "nflog.uid", FT_INT32, BASE_DEC, NULL, 0x00, "TLV UID Value", HFILL };

static header_field_info hfi_nflog_tlv_gid NFLOG_HFI_INIT =
    { "GID", "nflog.gid", FT_INT32, BASE_DEC, NULL, 0x00, "TLV GID Value", HFILL };

static header_field_info hfi_nflog_tlv_timestamp NFLOG_HFI_INIT =
    { "Timestamp", "nflog.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x00, "TLV Timestamp Value", HFILL };

static header_field_info hfi_nflog_tlv_unknown NFLOG_HFI_INIT =
    { "Value", "nflog.tlv_value", FT_BYTES, BASE_NONE, NULL, 0x00, "TLV Value", HFILL };

static dissector_handle_t ip_handle;
static dissector_handle_t ip6_handle;

static int
dissect_nflog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    const int start_tlv_offset = 4;

    proto_tree *nflog_tree = NULL;
    proto_item *ti;

    int offset = 0;

    tvbuff_t *next_tvb = NULL;
    int aftype;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "NFLOG");
    col_clear(pinfo->cinfo, COL_INFO);

    aftype = tvb_get_guint8(tvb, 0);

    /* Header */
    if (proto_field_is_referenced(tree, hfi_nflog->id)) {
        ti = proto_tree_add_item(tree, hfi_nflog, tvb, 0, -1, ENC_NA);
        nflog_tree = proto_item_add_subtree(ti, ett_nflog);

        proto_tree_add_item(nflog_tree, &hfi_nflog_family, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(nflog_tree, &hfi_nflog_version, tvb, offset, 1, ENC_NA);
        offset += 1;

        proto_tree_add_item(nflog_tree, &hfi_nflog_resid, tvb, offset, 2, ENC_BIG_ENDIAN);
        /*offset += 2;*/
    }

    offset = start_tlv_offset;
    /* TLVs */
    while (tvb_reported_length_remaining(tvb, offset) >= 4) {
        guint16 tlv_len = tvb_get_h_guint16(tvb, offset + 0);
        guint16 tlv_type;
        guint16 value_len;

        proto_tree *tlv_tree;

        /* malformed */
        if (tlv_len < 4)
            return offset;

        value_len = tlv_len - 4;
        tlv_type = (tvb_get_h_guint16(tvb, offset + 2) & 0x7fff);

        if (nflog_tree) {
            gboolean handled = FALSE;

            ti = proto_tree_add_bytes_format(nflog_tree, hfi_nflog_tlv.id,
                             tvb, offset, tlv_len, NULL,
                             "TLV Type: %s (%u), Length: %u",
                             val_to_str_const(tlv_type, nflog_tlv_vals, "Unknown"),
                             tlv_type, tlv_len);
            tlv_tree = proto_item_add_subtree(ti, ett_nflog_tlv);

            proto_tree_add_item(tlv_tree, &hfi_nflog_tlv_length, tvb, offset + 0, 2, ENC_HOST_ENDIAN);
            proto_tree_add_item(tlv_tree, &hfi_nflog_tlv_type, tvb, offset + 2, 2, ENC_HOST_ENDIAN);
            switch (tlv_type) {
                case WS_NFULA_PAYLOAD:
                    handled = TRUE;
                    break;

                case WS_NFULA_PREFIX:
                    if (value_len >= 1) {
                        proto_tree_add_item(tlv_tree, &hfi_nflog_tlv_prefix,
                                    tvb, offset + 4, value_len, ENC_NA);
                        handled = TRUE;
                    }
                    break;

                case WS_NFULA_UID:
                    if (value_len == 4) {
                        proto_tree_add_item(tlv_tree, &hfi_nflog_tlv_uid,
                                    tvb, offset + 4, value_len, ENC_BIG_ENDIAN);
                        handled = TRUE;
                    }
                    break;

                case WS_NFULA_GID:
                    if (value_len == 4) {
                        proto_tree_add_item(tlv_tree, &hfi_nflog_tlv_gid,
                                    tvb, offset + 4, value_len, ENC_BIG_ENDIAN);
                        handled = TRUE;
                    }
                    break;

                case WS_NFULA_TIMESTAMP:
                    if (value_len == 16) {
                        nstime_t ts;

                        ts.secs  = (time_t)tvb_get_ntoh64(tvb, offset + 4);
                        /* XXX - add an "expert info" warning if this is >= 10^9? */
                        ts.nsecs = (int)tvb_get_ntoh64(tvb, offset + 12);
                        proto_tree_add_time(tlv_tree, &hfi_nflog_tlv_timestamp,
                                    tvb, offset + 4, value_len, &ts);
                        handled = TRUE;
                    }
                    break;
            }

            if (!handled)
                    proto_tree_add_item(tlv_tree, &hfi_nflog_tlv_unknown,
                                        tvb, offset + 4, value_len, ENC_NA);
        }

        if (tlv_type == WS_NFULA_PAYLOAD)
            next_tvb = tvb_new_subset_length(tvb, offset + 4, value_len);

        offset += ((tlv_len + 3) & ~3); /* next TLV aligned to 4B */
    }

    if (next_tvb) {
        switch (aftype) {
            case LINUX_AF_INET:
                call_dissector(ip_handle, next_tvb, pinfo, tree);
                break;
            case LINUX_AF_INET6:
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
#ifndef HAVE_HFI_SECTION_INIT
    static header_field_info *hfi[] = {
    /* Header */
        &hfi_nflog_family,
        &hfi_nflog_version,
        &hfi_nflog_resid,
    /* TLV */
        &hfi_nflog_tlv,
        &hfi_nflog_tlv_length,
        &hfi_nflog_tlv_type,
    /* TLV values */
        &hfi_nflog_tlv_prefix,
        &hfi_nflog_tlv_uid,
        &hfi_nflog_tlv_gid,
        &hfi_nflog_tlv_timestamp,
        &hfi_nflog_tlv_unknown,
    };
#endif

    static gint *ett[] = {
        &ett_nflog,
        &ett_nflog_tlv
    };

    int proto_nflog;

    proto_nflog = proto_register_protocol("Linux Netfilter NFLOG", "NFLOG", "nflog");
    hfi_nflog = proto_registrar_get_nth(proto_nflog);

    register_dissector("nflog", dissect_nflog, proto_nflog);

    proto_register_fields(proto_nflog, hfi, array_length(hfi));
    proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_nflog(void)
{
    dissector_handle_t nflog_handle;

    ip_handle   = find_dissector_add_dependency("ip", hfi_nflog->id);
    ip6_handle  = find_dissector_add_dependency("ipv6", hfi_nflog->id);

    nflog_handle = find_dissector("nflog");
    dissector_add_uint("wtap_encap", WTAP_ENCAP_NFLOG, nflog_handle);
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
