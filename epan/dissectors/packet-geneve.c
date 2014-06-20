/* packet-geneve.c
 * Routines for Geneve - Generic Network Virtualization Encapsulation
 * http://tools.ietf.org/html/draft-gross-geneve-00
 *
 * Copyright (c) 2014 VMware, Inc. All Rights Reserved.
 * Author: Jesse Gross <jesse@nicira.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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


#include "config.h"

#include <epan/etypes.h>
#include <epan/expert.h>
#include <epan/packet.h>

#define UDP_PORT_GENEVE  6081

#define VER_SHIFT 6
#define HDR_OPTS_LEN_MASK 0x3F

#define FLAG_OAM (1 << 7)

#define OPT_TYPE_CRITICAL (1 << 7)
#define OPT_FLAGS_SHIFT 5
#define OPT_LEN_MASK 0x1F

static const range_string class_id_names[] = {
    { 0, 0xFF, "Standard" },
    { 0xFFFF, 0xFFFF, "Experimental" },
    { 0, 0, NULL }
};

void proto_register_geneve(void);
void proto_reg_handoff_geneve(void);

static int proto_geneve = -1;

static int hf_geneve_version = -1;
static int hf_geneve_opt_len = -1;
static int hf_geneve_flags = -1;
static int hf_geneve_flag_oam = -1;
static int hf_geneve_flag_critical = -1;
static int hf_geneve_flag_reserved = -1;
static int hf_geneve_proto_type = -1;
static int hf_geneve_vni = -1;
static int hf_geneve_reserved = -1;
static int hf_geneve_options = -1;
static int hf_geneve_option_class = -1;
static int hf_geneve_option_type = -1;
static int hf_geneve_option_type_critical = -1;
static int hf_geneve_option_flags = -1;
static int hf_geneve_option_flags_reserved = -1;
static int hf_geneve_option_length = -1;
static int hf_geneve_opt_unknown = -1;
static int hf_geneve_opt_unknown_data = -1;

static int ett_geneve = -1;
static int ett_geneve_flags = -1;
static int ett_geneve_opt_flags = -1;
static int ett_geneve_options = -1;
static int ett_geneve_unknown_opt = -1;

static expert_field ei_geneve_opt_len_invalid = EI_INIT;

static dissector_table_t ethertype_dissector_table;
static dissector_handle_t data_handle;

static void
print_flags(guint8 flags, proto_item *flag_item)
{
    static const char flag_names[][5] = {"OAM", "CRIT"};
    unsigned int i;

    if (!flags) {
        return;
    }

    proto_item_append_text(flag_item, " (");

    for (i = 0; i < array_length(flag_names); i++) {
        guint8 bit = 1 << (7 - i);

        if (flags & bit) {
            proto_item_append_text(flag_item, "%s", flag_names[i]);
            flags &= ~bit;

            if (flags) {
                proto_item_append_text(flag_item, ", ");
            }
        }
    }

    if (flags) {
        proto_item_append_text(flag_item, "RSVD");
    }

    proto_item_append_text(flag_item, ")");
}

static const char *
format_unknown_option_name(guint16 opt_class, guint8 opt_type)
{
    const char *name;

    name = wmem_strdup_printf(wmem_packet_scope(),
                              "Unknown, Class: %s (0x%04x) Type: 0x%02x",
                              rval_to_str_const(opt_class, class_id_names, "Unknown"),
                              opt_class, opt_type);

    return name;
}

static void
dissect_unknown_option(tvbuff_t *tvb, proto_tree *opts_tree, int offset,
                       guint16 opt_class, guint8 opt_type, int len)
{
    proto_item *opt_item, *type_item, *hidden_item, *flag_item;
    proto_tree *opt_tree, *flag_tree;
    const char *critical;
    guint8 flags;

    critical = opt_type & OPT_TYPE_CRITICAL ? "Critical" : "Non-critical";

    opt_item = proto_tree_add_item(opts_tree, hf_geneve_opt_unknown,
                                   tvb, offset, len, ENC_NA);
    proto_item_set_text(opt_item, "%s (%s)",
                        format_unknown_option_name(opt_class, opt_type),
                        critical);

    opt_tree = proto_item_add_subtree(opt_item, ett_geneve_unknown_opt);

    proto_tree_add_item(opt_tree, hf_geneve_option_class, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    type_item = proto_tree_add_item(opt_tree, hf_geneve_option_type, tvb,
                                    offset, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(type_item, " (%s)", critical);
    hidden_item = proto_tree_add_item(opt_tree, hf_geneve_option_type_critical,
                                      tvb, offset, 1, ENC_BIG_ENDIAN);
    PROTO_ITEM_SET_HIDDEN(hidden_item);
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
        PROTO_ITEM_SET_HIDDEN(flag_item);
    }

    proto_tree_add_uint_format_value(opt_tree, hf_geneve_option_length, tvb,
                                     offset, 1, len, "%u bytes", len);
    offset += 1;

    proto_tree_add_item(opt_tree, hf_geneve_opt_unknown_data, tvb, offset,
                        len - 4, ENC_NA);
}

static void
dissect_geneve_options(tvbuff_t *tvb, packet_info *pinfo,
                       proto_tree *geneve_tree, int offset, int len)
{
    proto_item *opts_item;
    proto_tree *opts_tree;
    guint16 opt_class;
    guint8 opt_type;
    guint8 opt_len;

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
                                         format_unknown_option_name(opt_class,
                                                                    opt_type),
                                         opt_len);
            return;
        }

        dissect_unknown_option(tvb, opts_tree, offset,
                               opt_class, opt_type, opt_len);

        offset += opt_len;
        len -= opt_len;
    };
}

static void
dissect_geneve(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti, *flag_item, *rsvd_item;
    proto_tree *geneve_tree, *flag_tree;
    tvbuff_t *next_tvb;
    int offset = 0;
    guint8 ver_opt;
    guint8 flags;
    guint16 proto_type;
    int opts_len;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Geneve");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_type = tvb_get_ntohs(tvb, 2);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Encapsulated %s",
                 val_to_str(proto_type, etype_vals, "0x%04x (unknown)"));

    flags = tvb_get_guint8(tvb, 1);
    ti = proto_tree_add_protocol_format(tree, proto_geneve, tvb, 0, -1,
                       "Generic Network Virtualization Encapsuation, VNI: 0x%06x"
                       "%s",
                       tvb_get_ntoh24(tvb, 4),
                       flags & FLAG_OAM ? ", OAM" : "");

    geneve_tree = proto_item_add_subtree(ti, ett_geneve);

    /* Version and option length. */
    ver_opt = tvb_get_guint8(tvb, offset);
    proto_tree_add_uint(geneve_tree, hf_geneve_version, tvb,
                        offset, 1, ver_opt >> VER_SHIFT);
    opts_len = (ver_opt & HDR_OPTS_LEN_MASK) * 4;
    proto_tree_add_uint_format_value(geneve_tree, hf_geneve_opt_len, tvb,
                                     offset, 1, opts_len, "%u bytes", opts_len);
    offset += 1;

    /* Flags. */
    if (tree) {
        flag_item = proto_tree_add_item(geneve_tree, hf_geneve_flags, tvb,
                                       offset, 1, ENC_BIG_ENDIAN);
        print_flags(flags, flag_item);

        flag_tree = proto_item_add_subtree(flag_item, ett_geneve_flags);

        proto_tree_add_item(flag_tree, hf_geneve_flag_oam, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_geneve_flag_critical, tvb, offset,
                            1, ENC_BIG_ENDIAN);
        proto_tree_add_item(flag_tree, hf_geneve_flag_reserved, tvb, offset,
                            1, ENC_BIG_ENDIAN);
    }
    offset += 1;

    /* Protocol Type. */
    proto_tree_add_item(geneve_tree, hf_geneve_proto_type, tvb,
                        offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* VNI. */
    proto_tree_add_item(geneve_tree, hf_geneve_vni, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;

    /* Reserved. */
    rsvd_item = proto_tree_add_item(geneve_tree, hf_geneve_reserved, tvb, offset,
                                    1, ENC_BIG_ENDIAN);
    if (!tvb_get_guint8(tvb, offset)) {
        PROTO_ITEM_SET_HIDDEN(rsvd_item);
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
        call_dissector(data_handle, next_tvb, pinfo, tree);
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
        { &hf_geneve_opt_len,
          { "Options Length", "geneve.options_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
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
            FT_UINT24, BASE_HEX, NULL, 0x0,
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
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_opt_unknown,
          { "Unknown Option", "geneve.option.unknown",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
        { &hf_geneve_opt_unknown_data,
          { "Option Data", "geneve.option.unknown.data",
            FT_BYTES, BASE_NONE, NULL, 0x00,
            NULL, HFILL }
        },
    };

    static gint *ett[] = {
        &ett_geneve,
        &ett_geneve_flags,
        &ett_geneve_options,
        &ett_geneve_opt_flags,
        &ett_geneve_unknown_opt,
    };

    static ei_register_info ei[] = {
       { &ei_geneve_opt_len_invalid, { "geneve.option.length.invalid",
         PI_SEQUENCE, PI_NOTE, "Invalid length for option", EXPFILL }},
    };

    expert_module_t *expert_geneve;

    /* Register the protocol name and description */
    proto_geneve = proto_register_protocol("Generic Network Virtualization Encapsulation",
                                          "Geneve", "geneve");

    proto_register_field_array(proto_geneve, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_geneve = expert_register_protocol(proto_geneve);
    expert_register_field_array(expert_geneve, ei, array_length(ei));
}

void
proto_reg_handoff_geneve(void)
{
    dissector_handle_t geneve_handle;

    geneve_handle = create_dissector_handle(dissect_geneve, proto_geneve);
    dissector_add_uint("udp.port", UDP_PORT_GENEVE, geneve_handle);
    dissector_add_for_decode_as("udp.port", geneve_handle);

    ethertype_dissector_table = find_dissector_table("ethertype");
    data_handle = find_dissector("data");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
