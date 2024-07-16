/* packet-geneve.c
 * Routines for Geneve - Generic Network Virtualization Encapsulation
 * https://tools.ietf.org/html/draft-ietf-nvo3-geneve
 *
 * Copyright (c) 2014 VMware, Inc. All Rights Reserved.
 * Author: Jesse Gross <jesse@nicira.com>
 *
 * Copyright 2021, Atul Sharma <asharm37@ncsu.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/value_string.h>

#define UDP_PORT_GENEVE  6081
#define GENEVE_VER 0

#define VER_SHIFT 6
#define HDR_OPTS_LEN_MASK 0x3F

#define FLAG_OAM (1 << 7)

#define OPT_TYPE_CRITICAL (1 << 7)
#define OPT_FLAGS_SHIFT 5
#define OPT_LEN_MASK 0x1F

static const range_string class_id_names[] = {
    { 0, 0xFF, "Standard" },
    { 0x0100, 0x0100, "Linux" },
    { 0x0101, 0x0101, "Open vSwitch" },
    { 0x0102, 0x0102, "Open Virtual Networking (OVN)" },
    { 0x0103, 0x0103, "In-band Network Telemetry (INT)" },
    { 0x0104, 0x0104, "VMware" },
    { 0x0105, 0x0105, "Amazon.com, Inc."},
    { 0x0106, 0x0106, "Cisco Systems, Inc." },
    { 0x0107, 0x0107, "Oracle Corporation" },
    { 0x0108, 0x0110, "Amazon.com, Inc." },
    { 0x0111, 0x0118, "IBM" },
    { 0x0119, 0x0128, "Ericsson" },
    { 0x0129, 0x0129, "Oxide Computer Company" },
    { 0x0130, 0x0131, "Cisco Systems, Inc." },
    { 0x0132, 0x0135, "Google LLC" },
    { 0x0136, 0x0136, "InfoQuick Global Connection Tech Ltd." },
    { 0x0137, 0xFEFF, "Unassigned" },
    { 0xFFF0, 0xFFFF, "Experimental" },
    { 0, 0, NULL }
};

#define GENEVE_GCP_VNID     0x013201
#define GENEVE_GCP_ENDPOINT 0x013202
#define GENEVE_GCP_PROFILE  0x013203

static const val64_string option_names[] = {
  { GENEVE_GCP_VNID,     "GCP Virtual Network ID" },
  { GENEVE_GCP_ENDPOINT, "GCP Endpoint ID" },
  { GENEVE_GCP_PROFILE,  "GCP Profile ID" },
  { 0, NULL }
};

void proto_register_geneve(void);
void proto_reg_handoff_geneve(void);

static dissector_handle_t geneve_handle;

static int proto_geneve;

static int hf_geneve_version;
static int hf_geneve_flags;
static int hf_geneve_flag_oam;
static int hf_geneve_flag_critical;
static int hf_geneve_flag_reserved;
static int hf_geneve_proto_type;
static int hf_geneve_vni;
static int hf_geneve_reserved;
static int hf_geneve_options;
static int hf_geneve_option_class;
static int hf_geneve_option_type;
static int hf_geneve_option_type_critical;
static int hf_geneve_option_flags;
static int hf_geneve_option_flags_reserved;
static int hf_geneve_option_length;
static int hf_geneve_option;
static int hf_geneve_opt_gcp_vnid;
static int hf_geneve_opt_gcp_reserved;
static int hf_geneve_opt_gcp_direction;
static int hf_geneve_opt_gcp_endpoint;
static int hf_geneve_opt_gcp_profile;
static int hf_geneve_opt_unknown_data;

static int ett_geneve;
static int ett_geneve_flags;
static int ett_geneve_opt_flags;
static int ett_geneve_options;
static int ett_geneve_opt_data;

static expert_field ei_geneve_ver_unknown;
static expert_field ei_geneve_opt_len_invalid;

static dissector_table_t ethertype_dissector_table;

static const struct true_false_string tfs_geneve_gcp_direction = {
  "Egress",
  "Ingress"
};

static const char *
format_option_name(wmem_allocator_t *scope, uint16_t opt_class, uint8_t opt_type)
{
    const char *name;

    name = wmem_strdup_printf(scope,
                              "%s, Class: %s (0x%04x) Type: 0x%02x",
                              val64_to_str_const(((uint64_t)opt_class << 8) | opt_type,
                                                 option_names, "Unknown"),
                              rval_to_str_const(opt_class, class_id_names, "Unknown"),
                              opt_class, opt_type);

    return name;
}

static void
dissect_option(wmem_allocator_t *scope, tvbuff_t *tvb, proto_tree *opts_tree, int offset,
               uint16_t opt_class, uint8_t opt_type, int len)
{
    proto_item *opt_item, *type_item, *hidden_item, *flag_item;
    proto_tree *opt_tree, *flag_tree;
    const char *critical;
    uint8_t flags;

    critical = opt_type & OPT_TYPE_CRITICAL ? "Critical" : "Non-critical";

    opt_item = proto_tree_add_item(opts_tree, hf_geneve_option,
                                   tvb, offset, len, ENC_NA);
    proto_item_set_text(opt_item, "%s (%s)",
                        format_option_name(scope, opt_class, opt_type),
                        critical);

    opt_tree = proto_item_add_subtree(opt_item, ett_geneve_opt_data);

    proto_tree_add_item(opt_tree, hf_geneve_option_class, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    type_item = proto_tree_add_item(opt_tree, hf_geneve_option_type, tvb,
                                    offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(type_item, " (%s)", critical);
    hidden_item = proto_tree_add_item(opt_tree, hf_geneve_option_type_critical,
                                      tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_item_set_hidden(hidden_item);
    offset += 1;

    flags = tvb_get_guint8(tvb, offset) >> OPT_FLAGS_SHIFT;
    flag_item = proto_tree_add_uint(opt_tree, hf_geneve_option_flags, tvb,
                                    offset, 1, flags);
    flag_tree = proto_item_add_subtree(flag_item, ett_geneve_opt_flags);
    proto_tree_add_item(flag_tree, hf_geneve_option_flags_reserved, tvb,
                        offset, 1, ENC_BIG_ENDIAN);
    if (flags) {
        proto_item_append_text(flag_item, " (RSVD)");
    } else {
        proto_item_set_hidden(flag_item);
    }

    proto_tree_add_uint(opt_tree, hf_geneve_option_length, tvb, offset, 1, len);
    offset += 1;

    switch (((uint64_t)opt_class << 8) | opt_type) {
        case GENEVE_GCP_VNID:
            proto_tree_add_bits_item(opt_tree, hf_geneve_opt_gcp_vnid, tvb, offset * 8,
                                     28, ENC_BIG_ENDIAN);
            proto_tree_add_item(opt_tree, hf_geneve_opt_gcp_direction, tvb, offset,
                                4, ENC_NA);
            proto_tree_add_item(opt_tree, hf_geneve_opt_gcp_reserved, tvb, offset,
                                4, ENC_NA);
            break;
        case GENEVE_GCP_ENDPOINT:
            proto_tree_add_item(opt_tree, hf_geneve_opt_gcp_endpoint, tvb, offset,
                                len - 4, ENC_NA);
            break;
        case GENEVE_GCP_PROFILE:
            proto_tree_add_item(opt_tree, hf_geneve_opt_gcp_profile, tvb, offset,
                                len - 4, ENC_BIG_ENDIAN);
            break;
        default:
            proto_tree_add_item(opt_tree, hf_geneve_opt_unknown_data, tvb, offset,
                                len - 4, ENC_NA);
            break;
    }
}

static void
dissect_geneve_options(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *geneve_tree, int offset, int len)
{
    proto_item *opts_item;
    proto_tree *opts_tree;
    uint16_t opt_class;
    uint8_t opt_type;
    uint8_t opt_len;

    opts_item = proto_tree_add_item(geneve_tree, hf_geneve_options, tvb,
                                    offset, len, ENC_NA);
    proto_item_set_text(opts_item, "Options: (%u bytes)", len);
    opts_tree = proto_item_add_subtree(opts_item, ett_geneve_options);

    while (len > 0) {
        opt_class = tvb_get_ntohs(tvb, offset);
        opt_type = tvb_get_guint8(tvb, offset + 2);
        opt_len = 4 + ((tvb_get_guint8(tvb, offset + 3) & OPT_LEN_MASK) * 4);

        if (opt_len > len) {
            proto_tree_add_expert_format(opts_tree, pinfo,
                                         &ei_geneve_opt_len_invalid, tvb,
                                         offset + 3, 1,
                                         "%s (length of %u is past end of options)",
                                         format_option_name(pinfo->pool, opt_class, opt_type),
                                         opt_len);
            return;
        }

        dissect_option(pinfo->pool, tvb, opts_tree, offset, opt_class, opt_type, opt_len);

        offset += opt_len;
        len -= opt_len;
    };
}

static int
dissect_geneve(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti, *rsvd_item;
    proto_tree *geneve_tree;
    tvbuff_t *next_tvb;
    int offset = 0;
    uint8_t ver_opt;
    uint8_t ver;
    uint8_t flags;
    uint16_t proto_type;
    int opts_len;
    static int * const flag_fields[] = {
        &hf_geneve_flag_oam,
        &hf_geneve_flag_critical,
        &hf_geneve_flag_reserved,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Geneve");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_geneve, tvb, offset, -1, ENC_NA);
    geneve_tree = proto_item_add_subtree(ti, ett_geneve);

    /* Version. */
    ver_opt = tvb_get_guint8(tvb, offset);
    ver = ver_opt >> VER_SHIFT;
    proto_tree_add_uint(geneve_tree, hf_geneve_version, tvb,
                        offset, 1, ver);

    if (ver != GENEVE_VER) {
        proto_tree_add_expert_format(geneve_tree, pinfo,
                                     &ei_geneve_ver_unknown, tvb, offset, 1,
                                     "Unknown version %u", ver);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown Geneve version %u", ver);
    }

    /* Option length. */
    opts_len = (ver_opt & HDR_OPTS_LEN_MASK) * 4;
    proto_tree_add_uint(geneve_tree, hf_geneve_option_length, tvb,
                                     offset, 1, opts_len);
    offset += 1;

    /* Flags. */
    flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_bitmask(geneve_tree, tvb, offset, hf_geneve_flags, ett_geneve_flags, flag_fields, ENC_BIG_ENDIAN);
    offset += 1;

    /* Protocol Type. */
    proto_tree_add_item(geneve_tree, hf_geneve_proto_type, tvb,
                        offset, 2, ENC_BIG_ENDIAN);

    proto_type = tvb_get_ntohs(tvb, offset);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated %s",
                 val_to_str(proto_type, etype_vals, "0x%04x (unknown)"));

    offset += 2;

    /* VNI. */
    proto_tree_add_item(geneve_tree, hf_geneve_vni, tvb, offset, 3,
                        ENC_BIG_ENDIAN);
    proto_item_append_text(ti, ", VNI: 0x%06x%s", tvb_get_ntoh24(tvb, offset),
                           flags & FLAG_OAM ? ", OAM" : "");
    offset += 3;

    /* Reserved. */
    rsvd_item = proto_tree_add_item(geneve_tree, hf_geneve_reserved, tvb,
                                    offset, 1, ENC_BIG_ENDIAN);
    if (!tvb_get_guint8(tvb, offset)) {
        proto_item_set_hidden(rsvd_item);
    }
    offset += 1;

    /* Options. */
    if (tree && opts_len) {
        dissect_geneve_options(tvb, pinfo, geneve_tree, offset, opts_len);
    }
    offset += opts_len;

    proto_item_set_len(ti, offset);

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (!dissector_try_uint(ethertype_dissector_table, proto_type, next_tvb, pinfo, tree))
        call_data_dissector(next_tvb, pinfo, tree);

    return tvb_captured_length(tvb);
}

/* Register Geneve with Wireshark */
void
proto_register_geneve(void)
{
    static hf_register_info hf[] = {
        { &hf_geneve_version,
          { "Version", "geneve.version",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_flags,
          { "Flags", "geneve.flags",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_flag_oam,
          { "Operations, Administration and Management Frame", "geneve.flags.oam",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_geneve_flag_critical,
          { "Critical Options Present", "geneve.flags.critical",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }
        },
        { &hf_geneve_flag_reserved,
          { "Reserved", "geneve.flags.reserved",
            FT_BOOLEAN, 8, NULL, 0x3F,
            NULL, HFILL }
        },
        { &hf_geneve_proto_type,
          { "Protocol Type", "geneve.proto_type",
            FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_geneve_vni,
          { "Virtual Network Identifier (VNI)", "geneve.vni",
            FT_UINT24, BASE_HEX_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_geneve_reserved,
          { "Reserved", "geneve.reserved",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_options,
          { "Geneve Options", "geneve.options",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_option_class,
          { "Class", "geneve.option.class",
            FT_UINT16, BASE_HEX | BASE_RANGE_STRING, RVALS(class_id_names), 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_option_type,
          { "Type", "geneve.option.type",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_option_type_critical,
          { "Critical Option", "geneve.option.type.critical",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_geneve_option_flags,
          { "Flags", "geneve.option.flags",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_option_flags_reserved,
          { "Reserved", "geneve.option.flags.reserved",
            FT_BOOLEAN, 8, NULL, 0xE0,
            NULL, HFILL }
        },
        { &hf_geneve_option_length,
          { "Length", "geneve.option.length",
            FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_byte_bytes, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_option,
          { "Option", "geneve.option",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_opt_gcp_vnid,
          { "GCP Virtual Network ID", "geneve.option.gcp.vnid",
            FT_UINT32, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_opt_gcp_reserved,
          { "GCP Reserved bits", "geneve.option.gcp.reserved",
            FT_BOOLEAN, 32, NULL, 0x0000000E,
            NULL, HFILL }
        },
        { &hf_geneve_opt_gcp_direction,
          { "GCP Traffic Direction", "geneve.option.gcp.direction",
            FT_BOOLEAN, 32, TFS(&tfs_geneve_gcp_direction), 0x00000001,
            NULL, HFILL }
        },
        { &hf_geneve_opt_gcp_endpoint,
          { "GCP Endpoint ID", "geneve.option.gcp.endpoint",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_opt_gcp_profile,
          { "GCP Profile ID", "geneve.option.gcp.profile",
            FT_UINT64, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_opt_unknown_data,
          { "Unknown Option Data", "geneve.option.unknown.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_geneve,
        &ett_geneve_flags,
        &ett_geneve_options,
        &ett_geneve_opt_flags,
        &ett_geneve_opt_data,
    };

    static ei_register_info ei[] = {
       { &ei_geneve_ver_unknown, { "geneve.version.unknown",
         PI_PROTOCOL, PI_WARN, "Unknown version", EXPFILL }},
       { &ei_geneve_opt_len_invalid, { "geneve.option.length.invalid",
         PI_PROTOCOL, PI_WARN, "Invalid length for option", EXPFILL }},
    };

    expert_module_t *expert_geneve;

    /* Register the protocol name and description */
    proto_geneve = proto_register_protocol("Generic Network Virtualization Encapsulation",
                                          "Geneve", "geneve");

    proto_register_field_array(proto_geneve, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_geneve = expert_register_protocol(proto_geneve);
    expert_register_field_array(expert_geneve, ei, array_length(ei));

    geneve_handle = register_dissector("geneve", dissect_geneve, proto_geneve);
}

void
proto_reg_handoff_geneve(void)
{
    dissector_add_uint_with_preference("udp.port", UDP_PORT_GENEVE, geneve_handle);

    ethertype_dissector_table = find_dissector_table("ethertype");
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
