/* packet-nasdaq-soup.c
 * Routines for NASDAQ SOUP 2.0 Protocol dissection
 * Copyright 2007,2008 Didier Gautheron <dgautheron@magic.fr>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Documentation: http://www.nasdaqtrader.com/Trader.aspx?id=DPSpecs
 * ex:
 * http://www.nasdaqtrader.com/content/technicalsupport/specifications/dataproducts/souptcp.pdf
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>

#include "packet-tcp.h"

static const value_string message_types_val[] = {
      { 'S', "Sequenced Data" },
      { 'R', "Client Heartbeat" },
      { 'H', "Server Heartbeat" },
      { '+' , "Debug Packet" },
      { 'A', "Login Accepted" },
      { 'J', "Login Rejected" },
      { 'L', "Login Request" },
      { 'U', "Unsequenced Data" },
      { 'O', "Logout Request" },
      { 0, NULL }
};

static const value_string reject_code_val[] = {
      { 'A', "Not authorized" },
      { 'S', "Session not available" },
      { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_nasdaq_soup = -1;
static dissector_handle_t nasdaq_soup_handle;
static dissector_handle_t nasdaq_itch_handle;

/* desegmentation of Nasdaq Soup */
static gboolean nasdaq_soup_desegment = TRUE;

static range_t *global_nasdaq_soup_tcp_range = NULL;
static range_t *nasdaq_soup_tcp_range = NULL;

/* Initialize the subtree pointers */
static gint ett_nasdaq_soup = -1;

static int hf_nasdaq_soup_packet_type = -1; 
static int hf_nasdaq_soup_message = -1; 
static int hf_nasdaq_soup_text = -1; 
static int hf_nasdaq_soup_packet_eol = -1; 
static int hf_nasdaq_soup_username = -1; 
static int hf_nasdaq_soup_password = -1; 
static int hf_nasdaq_soup_session = -1; 
static int hf_nasdaq_soup_seq_number = -1; 
static int hf_nasdaq_soup_reject_code = -1; 

static void
dissect_nasdaq_soup_packet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, proto_tree *tree, int offset, int linelen)
{
    guint8   nasdaq_soup_type;
    tvbuff_t *new_tvb = NULL;

    nasdaq_soup_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_nasdaq_soup_packet_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    switch (nasdaq_soup_type) {
    case '+': /* debug msg */
        proto_tree_add_item(tree, hf_nasdaq_soup_text, tvb, offset, linelen -1, ENC_ASCII|ENC_NA);
        offset += linelen -1;
        break;
    case 'A': /* login accept */
        proto_tree_add_item(tree, hf_nasdaq_soup_session, tvb, offset, 10, ENC_ASCII|ENC_NA);
        offset += 10;

        proto_tree_add_item(tree, hf_nasdaq_soup_seq_number, tvb, offset, 10, ENC_ASCII|ENC_NA);
        offset += 10;
        break;
    case 'J': /* login reject */
        proto_tree_add_item(tree, hf_nasdaq_soup_reject_code, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        break;

    case 'U': /* unsequenced data packed */
    case 'S': /* sequenced data packed */
        if (linelen > 1 && nasdaq_itch_handle) {
            new_tvb = tvb_new_subset(tvb, offset,linelen -1,linelen -1);
        } else {
            proto_tree_add_item(tree, hf_nasdaq_soup_message, tvb, offset, linelen -1, ENC_ASCII|ENC_NA);
        }
        offset += linelen -1;
        break;

    case 'L': /* login request */
        proto_tree_add_item(tree, hf_nasdaq_soup_username, tvb, offset, 6, ENC_ASCII|ENC_NA);
        offset += 6;

        proto_tree_add_item(tree, hf_nasdaq_soup_password, tvb, offset, 10, ENC_ASCII|ENC_NA);
        offset += 10;

        proto_tree_add_item(tree, hf_nasdaq_soup_session, tvb, offset, 10, ENC_ASCII|ENC_NA);
        offset += 10;

        proto_tree_add_item(tree, hf_nasdaq_soup_seq_number, tvb, offset, 10, ENC_ASCII|ENC_NA);
        offset += 10;
        break;

    case 'H': /* server heartbeat */
    case 'O': /* logout request */
    case 'R': /* client heartbeat */
        /* no payload */
        break;
    default:
        /* unknown */
        proto_tree_add_item(tree, hf_nasdaq_soup_message, tvb, offset, linelen -1, ENC_ASCII|ENC_NA);
        offset += linelen -1;
        break;
    }

    proto_tree_add_item(tree, hf_nasdaq_soup_packet_eol, tvb, offset, 1, ENC_ASCII|ENC_NA);
    if (new_tvb) {
        call_dissector(nasdaq_itch_handle, new_tvb, pinfo, parent_tree);
    }
    return;
}

/* ---------------------------- */
static void
dissect_nasdaq_soup(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *nasdaq_soup_tree = NULL;
    guint8 nasdaq_soup_type;
    int  linelen;
    gint next_offset;
    int  offset = 0;
    gint col_info;
    gint counter = 0;

    col_info = check_col(pinfo->cinfo, COL_INFO);
    while (tvb_offset_exists(tvb, offset)) {
      /* there's only a \n no \r */
      linelen = tvb_find_line_end(tvb, offset, -1, &next_offset, nasdaq_soup_desegment && pinfo->can_desegment);
      if (linelen == -1) {
        /*
         * We didn't find a line ending, and we're doing desegmentation;
         * tell the TCP dissector where the data for this message starts
         * in the data it handed us, and tell it we need one more byte
         * (we may need more, but we'll try again if what we get next
         * isn't enough), and return.
         */
        pinfo->desegment_offset = offset;
        pinfo->desegment_len = DESEGMENT_ONE_MORE_SEGMENT;
        return;
      }

      nasdaq_soup_type = tvb_get_guint8(tvb, offset);
      if (counter == 0) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "Nasdaq-SOUP");
        if (col_info)
            col_clear(pinfo->cinfo, COL_INFO);
      }
      if (col_info ) {
        if (counter) {
          col_append_str(pinfo->cinfo, COL_INFO, "; ");
          col_set_fence(pinfo->cinfo, COL_INFO);
        }
        col_append_str(pinfo->cinfo, COL_INFO, val_to_str(nasdaq_soup_type, message_types_val, "Unknown packet type (0x%02x)"));
      }
      counter++;
      if (tree) {
          ti = proto_tree_add_item(tree, proto_nasdaq_soup, tvb, offset, linelen +1, FALSE);
          nasdaq_soup_tree = proto_item_add_subtree(ti, ett_nasdaq_soup);
      }
      dissect_nasdaq_soup_packet(tvb, pinfo, tree, nasdaq_soup_tree, offset, linelen);
      offset = next_offset;
    }
}

/* Register the protocol with Wireshark */
static void range_delete_nasdaq_soup_tcp_callback(guint32 port) {
    dissector_delete_uint("tcp.port", port, nasdaq_soup_handle);
}

static void range_add_nasdaq_soup_tcp_callback(guint32 port) {
    dissector_add_uint("tcp.port", port, nasdaq_soup_handle);
}

static void nasdaq_soup_prefs(void) 
{
    range_foreach(nasdaq_soup_tcp_range, range_delete_nasdaq_soup_tcp_callback);
    g_free(nasdaq_soup_tcp_range);
    nasdaq_soup_tcp_range = range_copy(global_nasdaq_soup_tcp_range);
    range_foreach(nasdaq_soup_tcp_range, range_add_nasdaq_soup_tcp_callback);
}

void
proto_register_nasdaq_soup(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {

    { &hf_nasdaq_soup_packet_type, 
      { "Packet Type",       "nasdaq-soup.packet_type",
        FT_UINT8, BASE_DEC, VALS(message_types_val), 0x0,
        NULL, HFILL }},

    { &hf_nasdaq_soup_reject_code,
      { "Login Reject Code", "nasdaq-soup.reject_code",
        FT_UINT8, BASE_DEC, VALS(reject_code_val), 0x0,
        NULL, HFILL }},

    { &hf_nasdaq_soup_message,
      { "Message",           "nasdaq-soup.message",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_nasdaq_soup_text,
      { "Debug Text",        "nasdaq-soup.text",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_nasdaq_soup_username,
      { "User Name",         "nasdaq-soup.username",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_nasdaq_soup_password,
      { "Password",          "nasdaq-soup.password",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_nasdaq_soup_session,
      { "Session",           "nasdaq-soup.session",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Session ID", HFILL }},

    { &hf_nasdaq_soup_seq_number,
      { "Sequence number",   "nasdaq-soup.seq_number",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},

    { &hf_nasdaq_soup_packet_eol,
      { "End Of Packet",     "nasdaq-soup.packet_eol",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }}
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_nasdaq_soup
    };

    module_t *nasdaq_soup_module;

    /* Register the protocol name and description */
    proto_nasdaq_soup = proto_register_protocol("Nasdaq-SoupTCP version 2.0","NASDAQ-SOUP", "nasdaq_soup");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_nasdaq_soup, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    nasdaq_soup_module = prefs_register_protocol(proto_nasdaq_soup, nasdaq_soup_prefs);
    prefs_register_bool_preference(nasdaq_soup_module, "desegment",
        "Reassemble Nasdaq-SoupTCP messages spanning multiple TCP segments",
        "Whether the Nasdaq-SoupTCP dissector should reassemble messages spanning multiple TCP segments.",
        &nasdaq_soup_desegment);

    prefs_register_range_preference(nasdaq_soup_module, "tcp.port", "TCP Ports", "TCP Ports range", &global_nasdaq_soup_tcp_range, 65535);

    nasdaq_soup_tcp_range = range_empty();
}

/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_nasdaq_soup(void)
{
    nasdaq_soup_handle = create_dissector_handle(dissect_nasdaq_soup, proto_nasdaq_soup);
    nasdaq_itch_handle = find_dissector("nasdaq-itch");
    dissector_add_handle("tcp.port", nasdaq_soup_handle); /* for "decode-as" */
}

