/* Routines for sipfrag packet disassembly (RFC 3420)
 *
 * Martin Mathieson
 * Based on packet-sdp.c
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>

/*
 * TODO:
 * Doesn't currently dissect the lines of the message.
 * Need to refactor SIP dissector and make its functionality available here
 */


/* Initialize the protocol and registered fields. */
static int proto_sipfrag = -1;
static int hf_line = -1;

/* Protocol subtree. */
static int ett_sipfrag = -1;


/* Main dissection function. */
static void
dissect_sipfrag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree	*sipfrag_tree;
    proto_item	*ti;
    gint        offset = 0;
    gint        next_offset;
    int         linelen;
    char        *string;
    gint        lines = 0;

    /* Append this protocol name rather than replace. */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
        col_append_str(pinfo->cinfo, COL_PROTOCOL, "/sipfrag");

    /* Add mention of this protocol to info column */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, ", with Sipfrag");
    }

    /* Create sipfrag tree. */
    ti = proto_tree_add_item(tree, proto_sipfrag, tvb, offset, -1, FALSE);
    sipfrag_tree = proto_item_add_subtree(ti, ett_sipfrag);

    /* Show the sipfrag message a line at a time. */
    while (tvb_reported_length_remaining(tvb, offset) > 0)
    {
        /* Find the end of the line. */
        linelen = tvb_find_line_end_unquoted(tvb, offset, -1, &next_offset);

        /* For now, add all lines as unparsed strings */

        /* Extract & add the string. */
        string = tvb_get_ephemeral_string(tvb, offset, linelen);
        proto_tree_add_string_format(sipfrag_tree, hf_line,
                                     tvb, offset,
                                     linelen, string,
                                     "%s", string);
        lines++;

        /* Show first line in info column */
        if (lines == 1 && check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "(%s", string);
        }

        /* Move onto next line. */
        offset = next_offset;
    }

    /* Close off summary of sipfrag in info column */
    if (check_col(pinfo->cinfo, COL_INFO)) {
        col_append_str(pinfo->cinfo, COL_INFO, (lines > 1) ? "...)" : ")");
    }
}

void
proto_register_sipfrag(void)
{
    static hf_register_info hf[] =
    {
        { &hf_line,
            { "Line",
              "sipfrag.line",FT_STRING, BASE_NONE, NULL, 0x0, "Line", HFILL
            }
        },
    };

    static gint *ett[] =
    {
        &ett_sipfrag
    };

    /* Register protocol. */
    proto_sipfrag = proto_register_protocol("Sipfrag", "SIPFRAG", "sipfrag");
    proto_register_field_array(proto_sipfrag, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow other dissectors to find this one by name. */
    register_dissector("sipfrag", dissect_sipfrag, proto_sipfrag);
}

void
proto_reg_handoff_sipfrag(void)
{
    dissector_handle_t sipfrag_handle = find_dissector("sipfrag");
    dissector_add_string("media_type", "message/sipfrag", sipfrag_handle);
}


