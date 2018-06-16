/* packet-at.c
 * Dissector for AT Commands
 *
 * Copyright 2011, Tyson Key <tyson.key@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_at_command(void);
void proto_reg_handoff_at_command(void);

static int proto_at = -1;
static int hf_at_command = -1;

/* Subtree handles: set by register_subtree_array */
static gint ett_at = -1;

static gint allowed_chars_len(tvbuff_t *tvb, gint captured_len)
{
    gint offset;
    guint8 val;

    /* Get the amount of characters within the TVB which are ASCII,
     * cartridge return or new line */
    for (offset = 0; offset < captured_len; offset++) {
        val = tvb_get_guint8(tvb, offset);
        if (!(g_ascii_isprint(val) || (val == 0x0a) || (val == 0x0d)))
            return offset;
    }
    return captured_len;
}
static gboolean is_padded(tvbuff_t *tvb, gint captured_len, gint first_pad_offset)
{
    gint offset;
    guint8 val;

    /* Check if the rest of the packet is 0x00 padding
     * and no other values*/
    for (offset = first_pad_offset; offset < captured_len; offset++) {
        val = tvb_get_guint8(tvb, offset);
        if (val != 0x00)
            return (FALSE);
    }
    return (TRUE);
}

/* The dissector itself */
static int dissect_at(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *item;
    proto_tree *at_tree;
    gchar *string;

    string = tvb_format_text_wsp(wmem_packet_scope(), tvb, 0, tvb_captured_length(tvb));
    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "AT");
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "AT Command: %s", string);

    /* Start with a top-level item to add everything else to */
    item = proto_tree_add_item(tree, proto_at, tvb, 0, -1, ENC_NA);
    proto_item_append_text(item, ": %s", string);
    at_tree = proto_item_add_subtree(item, ett_at);

    /* Command */
    proto_tree_add_item(at_tree, hf_at_command, tvb, 0, tvb_reported_length(tvb), ENC_ASCII|ENC_NA);

    return tvb_captured_length(tvb);
}


#define MIN_PADDED_ALLOWED_CHARS 4
/* Experimental approach based upon the one used for PPP */
static gboolean heur_dissect_at(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    const gchar at_magic1[2] = {0x0d, 0x0a};
    const gchar at_magic2[3] = {0x0d, 0x0d, 0x0a};
    const gchar at_magic3[2] = {'A', 'T'};
    gint len, allwd_chars_len;
    tvbuff_t *tvb_no_padding;

    if ((tvb_memeql(tvb, 0, at_magic1, sizeof(at_magic1)) == 0) ||
        (tvb_memeql(tvb, 0, at_magic2, sizeof(at_magic2)) == 0) ||
        (tvb_memeql(tvb, 0, at_magic3, sizeof(at_magic3)) == 0)){
        len = tvb_captured_length(tvb);
        allwd_chars_len = allowed_chars_len(tvb,len);
        if(allwd_chars_len < len && allwd_chars_len > MIN_PADDED_ALLOWED_CHARS) {
            /* Found some valid characters, check if rest is padding */
            if(is_padded(tvb,len,allwd_chars_len)) {
                /* This is a padded AT Command */
                tvb_no_padding = tvb_new_subset_length_caplen(tvb, 0, allwd_chars_len, allwd_chars_len);
                dissect_at(tvb_no_padding, pinfo, tree, data);
                return (TRUE);
            }
        }
        else if(allwd_chars_len == len) {
            /* This is an (unpadded) AT Command */
            dissect_at(tvb, pinfo, tree, data);
            return (TRUE);
        }
    }
    return (FALSE);
}

void
proto_register_at_command(void)
{
    static hf_register_info hf[] = {
        { &hf_at_command,
            { "AT Command", "at.command", FT_STRING, BASE_NONE,
              NULL, 0x0, NULL, HFILL }}
    };

    static gint *ett[] = {
        &ett_at
    };

    proto_at = proto_register_protocol("AT Command", "AT", "at");
    proto_register_field_array(proto_at, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("at", dissect_at, proto_at);
}

/* Handler registration */
void
proto_reg_handoff_at_command(void)
{
    heur_dissector_add("usb.bulk", heur_dissect_at, "AT Command USB bulk endpoint", "at_usb_bulk", proto_at, HEURISTIC_ENABLE);
    heur_dissector_add("usb.control", heur_dissect_at, "AT Command USB control endpoint", "at_usb_control", proto_at, HEURISTIC_ENABLE);
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
