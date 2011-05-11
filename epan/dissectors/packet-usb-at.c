/* packet-usb-at.c
 * Dissector for USB/AT Commands
 *
 * Copyright 2011, Tyson Key <tyson.key@gmail.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/strutil.h>
#include <ctype.h>

static int proto_at = -1;
static int hf_at_command = -1;

/* Forward-declare the dissector functions */
static void dissect_at(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Subtree handles: set by register_subtree_array */
static gint ett_at = -1;

static gboolean allowed_chars(tvbuff_t *tvb)
{
    gint offset, len;
    guint8 val;

    len = tvb_reported_length(tvb);
    for (offset = 0; offset < len; offset++) {
        val = tvb_get_guint8(tvb, offset);
        if (!(isprint(val) || (val == 0x0a) || (val == 0x0d)))
            return (FALSE);
    }
    return (TRUE);
}

/* Experimental approach based upon the one used for PPP */
static gboolean dissect_usb_at(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    const guchar at_magic_in[2] = {0x0d, 0x0a};
    const gchar at_magic_out[2] = {'A', 'T'};

    if (((tvb_memeql(tvb, 0, at_magic_in, sizeof(at_magic_in)) == 0) ||
         (tvb_memeql(tvb, 0, at_magic_out, sizeof(at_magic_out)) == 0)) &&
         allowed_chars(tvb)) {
        dissect_at(tvb, pinfo, tree);
        return (TRUE);
    }
    return (FALSE);
}

/* The dissector itself */
static void dissect_at(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item;
    proto_tree *at_tree;
    gint len;

    len = tvb_reported_length(tvb);
    col_append_str(pinfo->cinfo, COL_PROTOCOL, "/AT");
    col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "AT Command: %s",
        tvb_format_text_wsp(tvb, 0, len));

    if (tree) {
        /* Start with a top-level item to add everything else to */
        item = proto_tree_add_item(tree, proto_at, tvb, 0, -1, ENC_NA);
        at_tree = proto_item_add_subtree(item, ett_at);

        /* Command */
        proto_tree_add_item(at_tree, hf_at_command, tvb, 0, len, ENC_NA);
        proto_item_append_text(item, ": %s", tvb_format_text_wsp(tvb, 0, len));
    }
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
    heur_dissector_add("usb.bulk", dissect_usb_at, proto_at);
}

