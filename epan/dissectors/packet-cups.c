/* packet-cups.c
 * Routines for Common Unix Printing System (CUPS) Browsing Protocol
 * packet disassembly for the Wireshark network traffic analyzer.
 *
 * Charles Levert <charles@comm.polymtl.ca>
 * Copyright 2001 Charles Levert
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <wsutil/str_util.h>

/**********************************************************************/

void proto_register_cups(void);
void proto_reg_handoff_cups(void);

static dissector_handle_t cups_handle;

/* From cups/cups.h, GNU GPL, Copyright 1997-2001 by Easy Software Products. */
typedef uint32_t cups_ptype_t;           /**** Printer Type/Capability Bits ****/
enum                                    /* Not a typedef'd enum so we can OR */
{
    CUPS_PRINTER_LOCAL = 0x0000,          /* Local printer or class */
    CUPS_PRINTER_CLASS = 0x0001,          /* Printer class */
    CUPS_PRINTER_REMOTE = 0x0002,         /* Remote printer or class */
    CUPS_PRINTER_BW = 0x0004,             /* Can do B&W printing */
    CUPS_PRINTER_COLOR = 0x0008,          /* Can do color printing */
    CUPS_PRINTER_DUPLEX = 0x0010,         /* Can do duplexing */
    CUPS_PRINTER_STAPLE = 0x0020,         /* Can staple output */
    CUPS_PRINTER_COPIES = 0x0040,         /* Can do copies */
    CUPS_PRINTER_COLLATE = 0x0080,        /* Can collage copies */
    CUPS_PRINTER_PUNCH = 0x0100,          /* Can punch output */
    CUPS_PRINTER_COVER = 0x0200,          /* Can cover output */
    CUPS_PRINTER_BIND = 0x0400,           /* Can bind output */
    CUPS_PRINTER_SORT = 0x0800,           /* Can sort output */
    CUPS_PRINTER_SMALL = 0x1000,          /* Can do Letter/Legal/A4 */
    CUPS_PRINTER_MEDIUM = 0x2000,         /* Can do Tabloid/B/C/A3/A2 */
    CUPS_PRINTER_LARGE = 0x4000,          /* Can do D/E/A1/A0 */
    CUPS_PRINTER_VARIABLE = 0x8000,       /* Can do variable sizes */
    CUPS_PRINTER_IMPLICIT = 0x10000,      /* Implicit class */
    CUPS_PRINTER_DEFAULT = 0x20000,       /* Default printer on network */
    CUPS_PRINTER_OPTIONS = 0xfffc         /* ~(CLASS | REMOTE | IMPLICIT) */
};
/* End insert from cups/cups.h */

typedef enum _cups_state {
    CUPS_IDLE = 3,
    CUPS_PROCESSING,
    CUPS_STOPPED
} cups_state_t;

static const value_string cups_state_values[] = {
    { CUPS_IDLE,       "idle" },
    { CUPS_PROCESSING, "processing" },
    { CUPS_STOPPED,    "stopped" },
    { 0,               NULL }
};

static const true_false_string tfs_implicit_explicit = { "Implicit class", "Explicit class" };
static const true_false_string tfs_printer_class = { "Printer class", "Single printer" };

static int proto_cups;
static int hf_cups_ptype;
static int hf_cups_ptype_default;
static int hf_cups_ptype_implicit;
static int hf_cups_ptype_variable;
static int hf_cups_ptype_large;
static int hf_cups_ptype_medium;
static int hf_cups_ptype_small;
static int hf_cups_ptype_sort;
static int hf_cups_ptype_bind;
static int hf_cups_ptype_cover;
static int hf_cups_ptype_punch;
static int hf_cups_ptype_collate;
static int hf_cups_ptype_copies;
static int hf_cups_ptype_staple;
static int hf_cups_ptype_duplex;
static int hf_cups_ptype_color;
static int hf_cups_ptype_bw;
static int hf_cups_ptype_remote;
static int hf_cups_ptype_class;
static int hf_cups_state;
static int hf_cups_uri;
static int hf_cups_location;
static int hf_cups_information;
static int hf_cups_make_model;

static int ett_cups;
static int ett_cups_ptype;

/* patterns used for tvb_ws_mempbrk_pattern_guint8 */
static ws_mempbrk_pattern pbrk_whitespace;

/* This protocol is heavily related to IPP, but it is CUPS-specific
   and non-standard. */
#define UDP_PORT_CUPS  631
#define PROTO_TAG_CUPS "CUPS"

static unsigned get_hex_uint(tvbuff_t *tvb, int offset, int *next_offset);
static bool skip_space(tvbuff_t *tvb, int offset, int *next_offset);
static const uint8_t* get_quoted_string(wmem_allocator_t *scope, tvbuff_t *tvb, int offset,
    int *next_offset, unsigned *len);
static const uint8_t* get_unquoted_string(wmem_allocator_t *scope, tvbuff_t *tvb, int offset,
    int *next_offset, unsigned *len);

/**********************************************************************/

static int
dissect_cups(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree   *cups_tree = NULL;
    proto_tree   *ptype_subtree = NULL;
    proto_item   *ti = NULL;
    int           offset = 0;
    int           next_offset;
    unsigned      len;
    const uint8_t *str;
    cups_ptype_t  ptype;
    unsigned int  state;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_CUPS);
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_cups, tvb, offset, -1, ENC_NA);
    cups_tree = proto_item_add_subtree(ti, ett_cups);

    /* Format (1450 bytes max.):  */
    /* type state uri ["location" ["info" ["make-and-model"]]]\n */

    ptype = get_hex_uint(tvb, offset, &next_offset);
    len = next_offset - offset;
    if (len != 0) {
        ti = proto_tree_add_uint(cups_tree, hf_cups_ptype, tvb, offset, len, ptype);
        ptype_subtree = proto_item_add_subtree(ti, ett_cups_ptype);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_default, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_implicit, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_variable, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_large, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_medium, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_small, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_sort, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_bind, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_cover, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_punch, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_collate, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_copies, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_staple, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_duplex, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_color, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_bw, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_remote, tvb, offset, len, ENC_BIG_ENDIAN);
        proto_tree_add_item(ptype_subtree, hf_cups_ptype_class, tvb, offset, len, ENC_BIG_ENDIAN);
    }
    offset = next_offset;

    if (!skip_space(tvb, offset, &next_offset))
        return offset;    /* end of packet */
    offset = next_offset;

    state = get_hex_uint(tvb, offset, &next_offset);
    len = next_offset - offset;
    if (len != 0) {
        proto_tree_add_uint(cups_tree, hf_cups_state, tvb, offset, len, state);
    }
    offset = next_offset;

    if (!skip_space(tvb, offset, &next_offset))
        return offset;    /* end of packet */
    offset = next_offset;

    str = get_unquoted_string(pinfo->pool, tvb, offset, &next_offset, &len);
    if (str == NULL)
        return offset;    /* separator/terminator not found */

    proto_tree_add_string(cups_tree, hf_cups_uri, tvb, offset, len, str);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s (%s)",
            str, val_to_str(state, cups_state_values, "0x%x"));
    offset = next_offset;

    if (!cups_tree)
        return offset;

    if (!skip_space(tvb, offset, &next_offset))
        return offset;    /* end of packet */
    offset = next_offset;

    str = get_quoted_string(pinfo->pool, tvb, offset, &next_offset, &len);
    if (str == NULL)
        return offset;    /* separator/terminator not found */
    proto_tree_add_string(cups_tree, hf_cups_location, tvb, offset+1, len, str);
    offset = next_offset;

    if (!skip_space(tvb, offset, &next_offset))
        return offset;    /* end of packet */
    offset = next_offset;

    str = get_quoted_string(pinfo->pool, tvb, offset, &next_offset, &len);
    if (str == NULL)
        return offset;    /* separator/terminator not found */
    proto_tree_add_string(cups_tree, hf_cups_information, tvb, offset+1, len, str);
    offset = next_offset;

    if (!skip_space(tvb, offset, &next_offset))
        return offset;    /* end of packet */
    offset = next_offset;

    str = get_quoted_string(pinfo->pool, tvb, offset, &next_offset, &len);
    if (str == NULL)
        return offset;    /* separator/terminator not found */
    proto_tree_add_string(cups_tree, hf_cups_make_model, tvb, offset+1, len, str);

    return next_offset;
}

static unsigned
get_hex_uint(tvbuff_t *tvb, int offset, int *next_offset)
{
    int c;
    unsigned u = 0;

    while (g_ascii_isxdigit(c = tvb_get_uint8(tvb, offset))) {
        u = 16*u + ws_xton(c);

        offset++;
    }

    *next_offset = offset;

    return u;
}

static bool
skip_space(tvbuff_t *tvb, int offset, int *next_offset)
{
    int c;

    while ((c = tvb_get_uint8(tvb, offset)) == ' ')
        offset++;
    if (c == '\r' || c == '\n')
        return false;    /* end of packet */

    *next_offset = offset;

    return true;
}

static const uint8_t*
get_quoted_string(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int *next_offset, unsigned *len)
{
    int c;
    const uint8_t* s = NULL;
    unsigned l = 0;
    int o;

    c = tvb_get_uint8(tvb, offset);
    if (c == '"') {
        o = tvb_find_guint8(tvb, offset+1, -1, '"');
        if (o != -1) {
            offset++;
            l = o - offset;
            s = tvb_get_string_enc(scope, tvb, offset, l, ENC_UTF_8);
            offset = o + 1;
        }
    }

    *next_offset = offset;
    *len = l;

    return s;
}

static const uint8_t*
get_unquoted_string(wmem_allocator_t *scope, tvbuff_t *tvb, int offset, int *next_offset, unsigned *len)
{
    const uint8_t* s = NULL;
    unsigned l = 0;
    int o;

    o = tvb_ws_mempbrk_pattern_guint8(tvb, offset, -1, &pbrk_whitespace, NULL);
    if (o != -1) {
        l = o - offset;
        s = tvb_get_string_enc(scope, tvb, offset, l, ENC_UTF_8);
        offset = o;
    }

    *next_offset = offset;
    *len = l;

    return s;
}

/**********************************************************************/

void
proto_register_cups(void)
{
    static hf_register_info hf[] = {
        { &hf_cups_ptype,
            { "Type",     "cups.ptype", FT_UINT32, BASE_HEX,
              NULL, 0x0, NULL, HFILL }},
        { &hf_cups_ptype_default,
            { "Default printer on network", "cups.ptype.default", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_DEFAULT, NULL, HFILL }},
        { &hf_cups_ptype_implicit,
            { "Class", "cups.ptype.implicit", FT_BOOLEAN, 32,
                TFS(&tfs_implicit_explicit), CUPS_PRINTER_IMPLICIT, NULL, HFILL }},
        { &hf_cups_ptype_variable,
            { "Can print variable sizes", "cups.ptype.variable", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_VARIABLE, NULL, HFILL }},
        { &hf_cups_ptype_large,
            { "Can print up to 36x48 inches", "cups.ptype.large", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_LARGE, NULL, HFILL }},
        { &hf_cups_ptype_medium,
            { "Can print up to 18x24 inches", "cups.ptype.medium", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_MEDIUM, NULL, HFILL }},
        { &hf_cups_ptype_small,
            { "Can print up to 9x14 inches", "cups.ptype.small", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_SMALL, NULL, HFILL }},
        { &hf_cups_ptype_sort,
            { "Can sort", "cups.ptype.sort", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_SORT, NULL, HFILL }},
        { &hf_cups_ptype_bind,
            { "Can bind", "cups.ptype.bind", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_BIND, NULL, HFILL }},
        { &hf_cups_ptype_cover,
            { "Can cover", "cups.ptype.cover", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_COVER, NULL, HFILL }},
        { &hf_cups_ptype_punch,
            { "Can punch holes", "cups.ptype.punch", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_PUNCH, NULL, HFILL }},
        { &hf_cups_ptype_collate,
            { "Can do fast collating", "cups.ptype.collate", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_COLLATE, NULL, HFILL }},
        { &hf_cups_ptype_copies,
            { "Can do fast copies", "cups.ptype.copies", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_COPIES, NULL, HFILL }},
        { &hf_cups_ptype_staple,
            { "Can staple", "cups.ptype.staple", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_STAPLE, NULL, HFILL }},
        { &hf_cups_ptype_duplex,
            { "Can duplex", "cups.ptype.duplex", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_DUPLEX, NULL, HFILL }},
        { &hf_cups_ptype_color,
            { "Can print color", "cups.ptype.color", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_COLOR, NULL, HFILL }},
        { &hf_cups_ptype_bw,
            { "Can print black", "cups.ptype.bw", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_BW, NULL, HFILL }},
        { &hf_cups_ptype_remote,
            { "Remote", "cups.ptype.remote", FT_BOOLEAN, 32,
                TFS(&tfs_yes_no), CUPS_PRINTER_REMOTE, NULL, HFILL }},
        { &hf_cups_ptype_class,
            { "Class", "cups.ptype.class", FT_BOOLEAN, 32,
                TFS(&tfs_printer_class), CUPS_PRINTER_CLASS, NULL, HFILL }},
        { &hf_cups_state,
            { "State",    "cups.state", FT_UINT8, BASE_HEX,
                VALS(cups_state_values), 0x0, NULL, HFILL }},
        { &hf_cups_uri,
            { "URI",    "cups.uri", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_cups_location,
            { "Location",    "cups.location", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_cups_information,
            { "Information",    "cups.information", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
        { &hf_cups_make_model,
            { "Make and model", "cups.make_model", FT_STRING, BASE_NONE,
                NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_cups,
        &ett_cups_ptype
    };

    proto_cups = proto_register_protocol("Common Unix Printing System (CUPS) Browsing Protocol", "CUPS", "cups");
    cups_handle = register_dissector("cups", dissect_cups, proto_cups);
    proto_register_field_array(proto_cups, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* compile patterns */
    ws_mempbrk_compile(&pbrk_whitespace, " \t\r\n");
}

void
proto_reg_handoff_cups(void)
{
    dissector_add_uint_with_preference("udp.port", UDP_PORT_CUPS, cups_handle);
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
