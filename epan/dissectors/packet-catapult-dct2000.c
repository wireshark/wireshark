/* packet-catapult-dct2000.c
 * Routines for Catapult DCT2000 packet stub header disassembly
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include <string.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/proto.h>
#include <epan/prefs.h>

#include "../wiretap/catapult_dct2000.h"

/* Protocol and registered fields. */
static int proto_catapult_dct2000 = -1;

static int hf_catapult_dct2000_context = -1;
static int hf_catapult_dct2000_port_number = -1;
static int hf_catapult_dct2000_timestamp = -1;
static int hf_catapult_dct2000_protocol = -1;
static int hf_catapult_dct2000_direction = -1;
static int hf_catapult_dct2000_encap = -1;
static int hf_catapult_dct2000_unparsed_data = -1;

gboolean catapult_dct2000_board_ports_only;

/* Protocol subtree. */
static int ett_catapult_dct2000 = -1;

static const value_string direction_vals[] = {
	{ 0,   "Sent" },
	{ 1,   "Received" },
    { 0,   NULL },
};

static const value_string encap_vals[] = {
    { WTAP_ENCAP_RAW_IP,                 "Raw IP" },
    { WTAP_ENCAP_ETHERNET,               "Ethernet" },
    { WTAP_ENCAP_ISDN,                   "LAPD" },
    { WTAP_ENCAP_ATM_PDUS_UNTRUNCATED,   "ATM (PDUs untruncated)" },
    { WTAP_ENCAP_PPP,                    "PPP" },
    { DCT2000_ENCAP_SSCOP,               "SSCOP" },
    { WTAP_ENCAP_FRELAY,                 "Frame Relay" },
    { WTAP_ENCAP_MTP2,                   "MTP2" },
    { DCT2000_ENCAP_UNHANDLED,           "Unhandled Protocol" },
    { 0,                                 NULL },
};


/*****************************************/
/* Main dissection function.             */
/*****************************************/
static void
dissect_catapult_dct2000(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree	*dct2000_tree;
    proto_item	*ti;
    gint        offset = 0;
    gint        context_length;
    guint8      port_number;
    gint        protocol_start;
    gint        protocol_length;
    gint        timestamp_start;
    gint        timestamp_length;
    guint8      direction;
    tvbuff_t    *next_tvb;
    int         encap;
    dissector_handle_t protocol_handle = 0;
    int sub_dissector_result = 0;

    /* Protocol name */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
        col_add_str(pinfo->cinfo, COL_PROTOCOL, "DCT2000");
    }

    /* Info column */
    if (check_col(pinfo->cinfo, COL_INFO))
    {
        col_clear(pinfo->cinfo, COL_INFO);
    }

    /* Create protocol tree. */
    ti = proto_tree_add_item(tree, proto_catapult_dct2000, tvb, offset, -1, FALSE);
    dct2000_tree = proto_item_add_subtree(ti, ett_catapult_dct2000);

    /* Context Name */
    context_length = tvb_strsize(tvb, offset);
    proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_context, tvb,
                        offset, context_length, FALSE);
    offset += context_length;

    /* Context port number */
    proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_port_number, tvb,
                        offset, 1, FALSE);
    port_number = tvb_get_guint8(tvb, offset);
    offset++;

    /* Timestamp in file */
    timestamp_start = offset;
    timestamp_length = tvb_strsize(tvb, offset);
    proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_timestamp, tvb,
                        offset, timestamp_length, FALSE);
    offset += timestamp_length;


    /* Original protocol name */
    protocol_start = offset;
    protocol_length = tvb_strsize(tvb, offset);
    proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_protocol, tvb,
                        offset, protocol_length, FALSE);
    offset += protocol_length;

    /* Direction */
    direction = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_direction, tvb,
                        offset, 1, FALSE);
    offset++;

    /* Read file encap */
    proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_encap, tvb, offset, 1, FALSE);
    encap = tvb_get_guint8(tvb, offset);
    offset++;

    /* Set selection length of dct2000 tree */
    proto_item_set_len(dct2000_tree, offset);

    /* Add useful details to protocol tree label */
    proto_item_append_text(ti, "   context=%s.%u   t=%s   %c   prot=%s",
                           tvb_get_ephemeral_string(tvb, 0, context_length),
                           port_number,
                           tvb_get_ephemeral_string(tvb, timestamp_start, timestamp_length),
                           (direction == 0) ? 'S' : 'R',
                           tvb_get_ephemeral_string(tvb, protocol_start, protocol_length));


    /* Note that the first item of pinfo->pseudo_header->dct2000 will contain
       the pseudo-header needed (in some cases) by the ethereal dissector */


    /***********************************************************************/
    /* Now hand off to the dissector of intended packet encapsulation type */

    /* Get protocol handle, and set p2p_dir where necessary.
       (packet-frame.c won't copy it from pseudo-header because it doesn't
       know about Catapult DCT2000 encap type...)
    */
    switch (encap)
    {
        case WTAP_ENCAP_RAW_IP:
            protocol_handle = find_dissector("ip");
            break;
        case WTAP_ENCAP_ETHERNET:
            protocol_handle = find_dissector("eth_withoutfcs");
            break;
        case WTAP_ENCAP_ISDN:
            protocol_handle = find_dissector("lapd");
            pinfo->p2p_dir = pinfo->pseudo_header->isdn.uton;
            break;
        case WTAP_ENCAP_ATM_PDUS_UNTRUNCATED:
            protocol_handle = find_dissector("atm_untruncated");
            break;
        case WTAP_ENCAP_PPP:
            protocol_handle = find_dissector("ppp_hdlc");
            pinfo->p2p_dir = pinfo->pseudo_header->p2p.sent;
            break;
        case DCT2000_ENCAP_SSCOP:
            protocol_handle = find_dissector("sscop");
            break;
        case WTAP_ENCAP_FRELAY:
            protocol_handle = find_dissector("fr");
            break;
        case DCT2000_ENCAP_MTP2:
            protocol_handle = find_dissector("mtp2");
            break;
        case DCT2000_ENCAP_UNHANDLED:
            protocol_handle = 0;
            break;

        default:
            /* !! If get here, there is a mismatch between
               this dissector and the wiretap module catapult_dct2000.c !!
            */
            DISSECTOR_ASSERT_NOT_REACHED();
                return;
    }


    /* Try appropriate dissector, if selected */
    if (protocol_handle != 0)
    {
        /* Dissect the remainder of the frame using chosen protocol handle */
        next_tvb = tvb_new_subset(tvb, offset, -1, tvb_reported_length(tvb)-offset);
        sub_dissector_result = call_dissector_only(protocol_handle, next_tvb, pinfo, tree);
    }


    if (protocol_handle == 0 || sub_dissector_result == 0)
    {
        /* Could get here because:
           - encap is DCT2000_ENCAP_UNHANDLED, OR
           - desired protocol is unavailable (probably disabled), OR
           - protocol rejected our data
           Show remaining bytes as unparsed data */
        proto_tree_add_item(dct2000_tree, hf_catapult_dct2000_unparsed_data,
                            tvb, offset, -1, FALSE);
        if (check_col(pinfo->cinfo, COL_INFO))
        {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "Unparsed protocol data (context=%s.%u   t=%s   %c   prot=%s)",
                         tvb_get_ephemeral_string(tvb, 0, context_length),
                         port_number,
                         tvb_get_ephemeral_string(tvb, timestamp_start, timestamp_length),
                         (direction == 0) ? 'S' : 'R',
                         tvb_get_ephemeral_string(tvb, protocol_start, protocol_length));
        }
    }
}



/******************************************************************************/
/* Associate this protocol with the Catapult DCT2000 file encapsulation type. */
/******************************************************************************/
void proto_reg_handoff_catapult_dct2000(void)
{
    dissector_handle_t catapult_dct2000_handle = find_dissector("dct2000");
    dissector_add("wtap_encap", WTAP_ENCAP_CATAPULT_DCT2000,
                  catapult_dct2000_handle);
}

/****************************************/
/* Register the protocol                */
/****************************************/
void proto_register_catapult_dct2000(void)
{
    static hf_register_info hf[] =
    {
        { &hf_catapult_dct2000_context,
            { "Context",
              "dct2000.context", FT_STRING, BASE_NONE, NULL, 0x0,
              "Context name", HFILL
            }
        },
        { &hf_catapult_dct2000_port_number,
            { "Context Port number",
              "dct2000.context_port", FT_UINT8, BASE_DEC, NULL, 0x0,
              "Context port number", HFILL
            }
        },
        { &hf_catapult_dct2000_timestamp,
            { "Timestamp",
              "dct2000.timestamp", FT_STRING, BASE_NONE, NULL, 0x0,
              "File timestamp", HFILL
            }
        },
        { &hf_catapult_dct2000_protocol,
            { "DCT2000 protocol",
              "dct2000.protocol", FT_STRING, BASE_NONE, NULL, 0x0,
              "Original (DCT2000) protocol name", HFILL
            }
        },
        { &hf_catapult_dct2000_direction,
            { "Direction",
              "dct2000.direction", FT_UINT8, BASE_DEC, VALS(direction_vals), 0x0,
              "Frame direction (Sent or Received)", HFILL
            }
        },
        { &hf_catapult_dct2000_encap,
            { "Ethereal encapsulation",
              "dct2000.encapsulation", FT_UINT8, BASE_DEC, VALS(encap_vals), 0x0,
              "Ethereal encapsulation used", HFILL
            }
        },
        { &hf_catapult_dct2000_unparsed_data,
            { "Unparsed protocol data",
              "dct2000.unparsed_data", FT_BYTES, BASE_NONE, NULL, 0x0,
              "Unparsed DCT2000 protocol data", HFILL
            }
        },

    };

    static gint *ett[] =
    {
        &ett_catapult_dct2000
    };

    module_t *catapult_dct2000_module;
    
    /* Register protocol. */
    proto_catapult_dct2000 = proto_register_protocol("DCT2000", "DCT2000", "dct2000");
    proto_register_field_array(proto_catapult_dct2000, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Allow dissector to find be found by name. */
    register_dissector("dct2000", dissect_catapult_dct2000, proto_catapult_dct2000);

    /* Preferences */
    catapult_dct2000_module = prefs_register_protocol(proto_catapult_dct2000,
                                                      proto_reg_handoff_catapult_dct2000);

    /* Determines whether non-supported protocols should be shown anyway */
    prefs_register_bool_preference(catapult_dct2000_module, "board_ports_only",
                                   "Only show known 'board-port' protocols",
                                   "Don't show other protocols, i.e. unknown board-port "
                                   "protocols and non-standard primitives between "
                                   "contexts on the same card.  The capture file "
                                   "needs to be (re)-loaded before effect will be seen",
                                   &catapult_dct2000_board_ports_only);
}

