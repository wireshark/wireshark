/* packet-gue.c
 * Routines for Generic UDP Encapsulation dissection
 * Copyright 2026, Takeru Hayasaka <hayatake396@gmail.com>
 *
 * Generic UDP Encapsulation (GUE) is specified in draft-ietf-intarea-gue-09.
 * IANA has assigned UDP port 6080 to GUE, and the Linux kernel implements
 * it as part of its foo-over-UDP (fou) tunneling support.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN "gue"

#include <wireshark.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/iana-info.h>

void proto_register_gue(void);
void proto_reg_handoff_gue(void);

static dissector_table_t ip_dissector_table;

static int proto_gue;
static int hf_gue_variant;
static int hf_gue_control;
static int hf_gue_hlen;
static int hf_gue_proto;
static int hf_gue_ctype;
static int hf_gue_flags;
static int hf_gue_flags_priv;
static int hf_gue_flags_reserved;
static int hf_gue_priv_flags;
static int hf_gue_priv_flags_remcsum;
static int hf_gue_priv_flags_reserved;
static int hf_gue_remcsum_start;
static int hf_gue_remcsum_offset;
static int hf_gue_ext_data;
static int hf_gue_exid;
static int hf_gue_surplus;

static int ett_gue;
static int ett_gue_flags;
static int ett_gue_priv_flags;

static expert_field ei_gue_variant_unknown;
static expert_field ei_gue_ip_version_invalid;
static expert_field ei_gue_hlen_invalid;
static expert_field ei_gue_exid_missing;
static expert_field ei_gue_hlen_too_short;
static expert_field ei_gue_flags_unassigned;
static expert_field ei_gue_flags_undecoded;
static expert_field ei_gue_priv_flags_unknown;

static dissector_handle_t gue_handle;
static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;

#define UDP_PORT_GUE 6080

#define GUE_VARIANT_MASK 0xC0
#define GUE_CONTROL_MASK 0x20
#define GUE_HLEN_MASK    0x1F

#define GUE_CTYPE_EXPERIMENT 255
#define GUE_EXID_LEN         4

/*
 * Flag bits the Linux kernel assigns (include/net/gue.h).  PRIV is the only
 * standard flag it defines, so the private flags word it introduces is
 * always the first four bytes of the extension area.
 */
#define GUE_FLAG_PRIV     0x0001
#define GUE_FLAGS_ALL     GUE_FLAG_PRIV
#define GUE_LEN_PRIV      4

/* Flags assigned by draft-ietf-intarea-gue-extensions, not decoded here. */
#define GUE_FLAGS_EXTEN   0xFFC0

#define GUE_PFLAG_REMCSUM 0x80000000
#define GUE_PFLAGS_ALL    GUE_PFLAG_REMCSUM
#define GUE_PLEN_REMCSUM  4

static const value_string gue_ctype_vals[] = {
    { 0,   "Control payload needs more context" },
    { 255, "Experimental" },
    { 0, NULL }
};

static int * const gue_flags_fields[] = {
    &hf_gue_flags_reserved,
    &hf_gue_flags_priv,
    NULL
};

static int * const gue_priv_flags_fields[] = {
    &hf_gue_priv_flags_remcsum,
    &hf_gue_priv_flags_reserved,
    NULL
};

static int
dissect_gue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti, *variant_ti, *hlen_ti, *ctype_ti, *flags_ti;
    proto_tree *gue_tree;
    uint8_t     first_byte, variant;
    uint32_t    hlen, proto_or_ctype;
    uint16_t    flags;
    bool        is_control;
    unsigned    offset, opt_len, opt_used;
    tvbuff_t   *next_tvb;

    if (tvb_captured_length(tvb) < 1)
        return 0;

    first_byte = tvb_get_uint8(tvb, 0);
    variant = first_byte >> 6;

    /* Variant 0 packets always carry the four byte primary header. */
    if (variant == 0 && tvb_reported_length(tvb) < 4)
        return 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GUE");

    if (variant == 1) {
        dissector_handle_t next_handle;

        /* Direct encapsulation of IPv4 or IPv6: the UDP payload is the IP
         * packet itself, and the two-bit variant shares its byte with the
         * IP header's version field. */
        ti = proto_tree_add_item(tree, proto_gue, tvb, 0, 1, ENC_NA);
        proto_item_append_text(ti, " (variant 1, direct IP encapsulation)");
        gue_tree = proto_item_add_subtree(ti, ett_gue);
        variant_ti = proto_tree_add_item(gue_tree, hf_gue_variant, tvb, 0, 1, ENC_BIG_ENDIAN);

        switch (first_byte >> 4) {
        case 4:
            next_handle = ipv4_handle;
            break;
        case 6:
            next_handle = ipv6_handle;
            break;
        default:
            next_handle = NULL;
            break;
        }

        if (next_handle != NULL) {
            col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
            col_set_fence(pinfo->cinfo, COL_PROTOCOL);
            call_dissector(next_handle, tvb, pinfo, tree);
        } else {
            expert_add_info_format(pinfo, variant_ti, &ei_gue_ip_version_invalid,
                                   "Invalid IP version %u for GUE variant 1", first_byte >> 4);
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "Invalid IP version %u for GUE variant 1", first_byte >> 4);
            call_data_dissector(tvb, pinfo, tree);
        }
        return tvb_captured_length(tvb);
    }

    if (variant >= 2) {
        ti = proto_tree_add_item(tree, proto_gue, tvb, 0, -1, ENC_NA);
        gue_tree = proto_item_add_subtree(ti, ett_gue);
        variant_ti = proto_tree_add_item(gue_tree, hf_gue_variant, tvb, 0, 1, ENC_BIG_ENDIAN);
        expert_add_info_format(pinfo, variant_ti, &ei_gue_variant_unknown,
                               "Unknown GUE variant %u", variant);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown GUE variant %u", variant);
        return tvb_captured_length(tvb);
    }

    /* Variant 0: the four byte primary header, optional extension fields
     * and the encapsulated payload. */
    is_control = (first_byte & GUE_CONTROL_MASK) != 0;

    ti = proto_tree_add_item(tree, proto_gue, tvb, 0, -1, ENC_NA);
    gue_tree = proto_item_add_subtree(ti, ett_gue);

    proto_tree_add_item(gue_tree, hf_gue_variant, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(gue_tree, hf_gue_control, tvb, 0, 1, ENC_BIG_ENDIAN);
    hlen_ti = proto_tree_add_item_ret_uint(gue_tree, hf_gue_hlen, tvb, 0, 1,
                                           ENC_BIG_ENDIAN, &hlen);
    ctype_ti = proto_tree_add_item_ret_uint(gue_tree, is_control ? hf_gue_ctype : hf_gue_proto,
                                            tvb, 1, 1, ENC_BIG_ENDIAN, &proto_or_ctype);
    flags = tvb_get_ntohs(tvb, 2);
    flags_ti = proto_tree_add_bitmask(gue_tree, tvb, 2, hf_gue_flags, ett_gue_flags,
                                      gue_flags_fields, ENC_BIG_ENDIAN);

    offset = 4;
    opt_len = hlen * 4;

    if (4 + hlen * 4 > tvb_reported_length(tvb)) {
        expert_add_info_format(pinfo, hlen_ti, &ei_gue_hlen_invalid,
                               "GUE header length (%u bytes) exceeds packet length",
                               4 + hlen * 4);
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "Bogus GUE header length (%u bytes)", 4 + hlen * 4);
        return tvb_captured_length(tvb);
    }

    /*
     * Extension fields are laid out in flag order (section 3.3.1), so one
     * unrecognised flag makes every offset after it indeterminate.
     */
    opt_used = 0;
    if (flags & ~GUE_FLAGS_ALL) {
        if (flags & ~(GUE_FLAGS_ALL | GUE_FLAGS_EXTEN))
            expert_add_info(pinfo, flags_ti, &ei_gue_flags_unassigned);
        else
            expert_add_info(pinfo, flags_ti, &ei_gue_flags_undecoded);
        if (opt_len > 0)
            proto_tree_add_item(gue_tree, hf_gue_ext_data, tvb, offset, opt_len, ENC_NA);
        opt_used = opt_len;
    } else if (flags & GUE_FLAG_PRIV) {
        if (opt_len < GUE_LEN_PRIV) {
            expert_add_info(pinfo, hlen_ti, &ei_gue_hlen_too_short);
        } else {
            uint32_t    pflags = tvb_get_ntohl(tvb, offset);
            proto_item *pflags_ti;

            pflags_ti = proto_tree_add_bitmask(gue_tree, tvb, offset, hf_gue_priv_flags,
                                               ett_gue_priv_flags, gue_priv_flags_fields,
                                               ENC_BIG_ENDIAN);
            opt_used = GUE_LEN_PRIV;

            if (pflags & ~GUE_PFLAGS_ALL) {
                expert_add_info(pinfo, pflags_ti, &ei_gue_priv_flags_unknown);
                if (opt_len > opt_used)
                    proto_tree_add_item(gue_tree, hf_gue_ext_data, tvb,
                                        offset + opt_used, opt_len - opt_used, ENC_NA);
                opt_used = opt_len;
            } else if (pflags & GUE_PFLAG_REMCSUM) {
                if (opt_len < opt_used + GUE_PLEN_REMCSUM) {
                    expert_add_info(pinfo, hlen_ti, &ei_gue_hlen_too_short);
                } else {
                    proto_tree_add_item(gue_tree, hf_gue_remcsum_start, tvb,
                                        offset + opt_used, 2, ENC_BIG_ENDIAN);
                    proto_tree_add_item(gue_tree, hf_gue_remcsum_offset, tvb,
                                        offset + opt_used + 2, 2, ENC_BIG_ENDIAN);
                    opt_used += GUE_PLEN_REMCSUM;
                }
            }
        }
    }

    /* Surplus space is reserved and must not be interpreted (section 3.4). */
    if (opt_len > opt_used)
        proto_tree_add_item(gue_tree, hf_gue_surplus, tvb, offset + opt_used,
                            opt_len - opt_used, ENC_NA);

    offset += opt_len;
    proto_item_set_len(ti, offset);

    next_tvb = tvb_new_subset_remaining(tvb, offset);

    if (is_control) {
        unsigned control_offset = 0;

        proto_item_append_text(ti, ", Control message (type %u)", proto_or_ctype);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Control message (type %u)", proto_or_ctype);
        col_set_fence(pinfo->cinfo, COL_INFO);

        if (proto_or_ctype == GUE_CTYPE_EXPERIMENT) {
            /* The ExID lives in the payload, not the header, so Hlen
             * does not account for it (section 3.2.2). */
            if (tvb_reported_length(next_tvb) < GUE_EXID_LEN) {
                expert_add_info(pinfo, ctype_ti, &ei_gue_exid_missing);
            } else {
                proto_tree_add_item(gue_tree, hf_gue_exid, next_tvb, 0,
                                    GUE_EXID_LEN, ENC_BIG_ENDIAN);
                control_offset = GUE_EXID_LEN;
            }
        }

        /* An experimental control message may consist of nothing but the
         * ExID. */
        if (tvb_reported_length_remaining(next_tvb, control_offset) > 0)
            call_data_dissector(tvb_new_subset_remaining(next_tvb, control_offset), pinfo, tree);
    } else {
        /* Overwritten by the payload dissector; kept when nothing claims
         * the payload. */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated %s",
                     val_to_str_ext(pinfo->pool, proto_or_ctype, &ipproto_val_ext,
                                    "Unknown (%u)"));
        if (dissector_get_uint_handle(ip_dissector_table, proto_or_ctype) != NULL) {
            col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
            col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        }
        if (!dissector_try_uint(ip_dissector_table, proto_or_ctype, next_tvb, pinfo, tree))
            call_data_dissector(next_tvb, pinfo, tree);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_gue(void)
{
    static hf_register_info hf[] = {
        { &hf_gue_variant,
          { "Variant", "gue.variant",
            FT_UINT8, BASE_DEC, NULL, GUE_VARIANT_MASK,
            "GUE protocol variant number", HFILL }
        },
        { &hf_gue_control,
          { "Control message", "gue.c",
            FT_BOOLEAN, 8, NULL, GUE_CONTROL_MASK,
            "Set for a control message, clear for a data message", HFILL }
        },
        { &hf_gue_hlen,
          { "Header Length", "gue.hlen",
            FT_UINT8, BASE_DEC, NULL, GUE_HLEN_MASK,
            "Length of the optional extension fields in 32-bit words, not including the first four bytes", HFILL }
        },
        { &hf_gue_proto,
          { "Protocol", "gue.proto",
            FT_UINT8, BASE_DEC | BASE_EXT_STRING, &ipproto_val_ext, 0x0,
            "IANA Internet Protocol number of the encapsulated payload", HFILL }
        },
        { &hf_gue_ctype,
          { "Control Type", "gue.ctype",
            FT_UINT8, BASE_DEC, VALS(gue_ctype_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_gue_flags,
          { "Flags", "gue.flags",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            "Header flags that may indicate the presence of extension fields", HFILL }
        },
        { &hf_gue_flags_priv,
          { "Private Flags Present", "gue.flags.priv",
            FT_BOOLEAN, 16, NULL, GUE_FLAG_PRIV,
            "Linux kernel private flags extension is present (include/net/gue.h)", HFILL }
        },
        { &hf_gue_flags_reserved,
          { "Reserved", "gue.flags.reserved",
            FT_UINT16, BASE_HEX, NULL, (uint16_t)~GUE_FLAGS_ALL,
            NULL, HFILL }
        },
        { &hf_gue_priv_flags,
          { "Private Flags", "gue.priv_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Linux kernel private flags (include/net/gue.h)", HFILL }
        },
        { &hf_gue_priv_flags_remcsum,
          { "Remote Checksum Offload", "gue.priv_flags.remcsum",
            FT_BOOLEAN, 32, NULL, GUE_PFLAG_REMCSUM,
            NULL, HFILL }
        },
        { &hf_gue_priv_flags_reserved,
          { "Reserved", "gue.priv_flags.reserved",
            FT_UINT32, BASE_HEX, NULL, (uint32_t)~GUE_PFLAGS_ALL,
            NULL, HFILL }
        },
        { &hf_gue_remcsum_start,
          { "Checksum Start", "gue.remcsum.start",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Offset in the encapsulated packet where checksum computation starts", HFILL }
        },
        { &hf_gue_remcsum_offset,
          { "Checksum Offset", "gue.remcsum.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Offset in the encapsulated packet of the checksum field to update", HFILL }
        },
        { &hf_gue_ext_data,
          { "Extension Fields", "gue.ext_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_gue_exid,
          { "Experimental ID", "gue.exid",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "Identifies the experiment carried in a Type 255 control message; not counted by the Header Length", HFILL }
        },
        { &hf_gue_surplus,
          { "Surplus Space", "gue.surplus",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Reserved space left over once the flags' extension fields are accounted for", HFILL }
        },
    };

    static int *ett[] = {
        &ett_gue,
        &ett_gue_flags,
        &ett_gue_priv_flags,
    };

    static ei_register_info ei[] = {
        { &ei_gue_variant_unknown,
          { "gue.variant.unknown", PI_UNDECODED, PI_WARN,
            "Unknown GUE variant", EXPFILL }
        },
        { &ei_gue_ip_version_invalid,
          { "gue.ip_version.invalid", PI_PROTOCOL, PI_WARN,
            "Invalid IP version for GUE variant 1", EXPFILL }
        },
        { &ei_gue_hlen_invalid,
          { "gue.hlen.invalid", PI_MALFORMED, PI_ERROR,
            "GUE header length exceeds packet length", EXPFILL }
        },
        { &ei_gue_exid_missing,
          { "gue.exid.missing", PI_MALFORMED, PI_ERROR,
            "Experimental control message payload is too short to hold an ExID", EXPFILL }
        },
        { &ei_gue_hlen_too_short,
          { "gue.hlen.too_short", PI_MALFORMED, PI_ERROR,
            "GUE header length too short for the extension fields the flags require", EXPFILL }
        },
        { &ei_gue_flags_unassigned,
          { "gue.flags.unassigned", PI_PROTOCOL, PI_WARN,
            "Unassigned GUE flag set; extension fields left undecoded", EXPFILL }
        },
        { &ei_gue_flags_undecoded,
          { "gue.flags.undecoded", PI_UNDECODED, PI_WARN,
            "GUE extension flag not decoded; extension fields left undecoded", EXPFILL }
        },
        { &ei_gue_priv_flags_unknown,
          { "gue.priv_flags.unknown", PI_PROTOCOL, PI_WARN,
            "Unknown GUE private flag set; remaining extension fields left undecoded", EXPFILL }
        },
    };

    expert_module_t *expert_gue;

    proto_gue = proto_register_protocol("Generic UDP Encapsulation", "GUE", "gue");
    proto_register_field_array(proto_gue, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_gue = expert_register_protocol(proto_gue);
    expert_register_field_array(expert_gue, ei, array_length(ei));

    gue_handle = register_dissector("gue", dissect_gue, proto_gue);
}

void
proto_reg_handoff_gue(void)
{
    dissector_add_uint_with_preference("udp.port", UDP_PORT_GUE, gue_handle);

    ip_dissector_table = find_dissector_table("ip.proto");
    ipv4_handle = find_dissector_add_dependency("ip", proto_gue);
    ipv6_handle = find_dissector_add_dependency("ipv6", proto_gue);
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
