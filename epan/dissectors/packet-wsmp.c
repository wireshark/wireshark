/* packet-wsmp.c
 * Routines for WAVE Short Message  dissection (WSMP)
 * Copyright 2008, Arada Systems (http://www.aradasystems.com) (email: siva@aradasystems.com)
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/etypes.h>

static dissector_handle_t data_handle;

/* Initialize the protocol and registered fields */
static int proto_wsmp = -1;
static int hf_wsmp_version = -1;
static int hf_wsmp_security = -1;
static int hf_wsmp_rate = -1;
static int hf_wsmp_channel = -1;
static int hf_wsmp_txpower = -1;
static int hf_wsmp_appclass = -1;
static int hf_wsmp_acmlength = -1;
static int hf_wsmp_acm = -1;
static int hf_wsmp_wsmlength = -1;

/* Initialize the subtree pointers */
static gint ett_wsmp = -1;
static gint ett_wsmdata = -1;

/* Code to actually dissect the packets */
static void
dissect_wsmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

        /* Set up structures needed to add the protocol subtree and manage it */
        proto_item *ti, *wsmdata_item;
        proto_tree *wsmp_tree, *wsmdata_tree;
        tvbuff_t *wsmdata_tvb;
        guint16 acmlength, wsmlength, offset;

        /* Make entries in Protocol column and Info column on summary display */
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "WSMP");

        col_set_str(pinfo->cinfo, COL_INFO, "WAVE Short Message Protocol IEEE P1609.3");

        if (tree) {

                /* create display subtree for the protocol */
                ti = proto_tree_add_item(tree, proto_wsmp, tvb, 0, -1, ENC_NA);

                wsmp_tree = proto_item_add_subtree(ti, ett_wsmp);

                offset = 0;
                proto_tree_add_item(wsmp_tree,
                                hf_wsmp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset ++;

                proto_tree_add_item(wsmp_tree,
                                hf_wsmp_security, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset ++;

                proto_tree_add_item(wsmp_tree,
                                hf_wsmp_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset ++;

                proto_tree_add_item(wsmp_tree,
                                hf_wsmp_rate, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset ++;

                proto_tree_add_item(wsmp_tree,
                                hf_wsmp_txpower, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset ++;

                proto_tree_add_item(wsmp_tree,
                                hf_wsmp_appclass, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset ++;

                acmlength = tvb_get_guint8(tvb,offset);
                proto_tree_add_item(wsmp_tree,
                                hf_wsmp_acmlength, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset ++;

                proto_tree_add_item(wsmp_tree, hf_wsmp_acm, tvb, offset, acmlength, ENC_ASCII|ENC_NA);
                offset +=acmlength;

                wsmlength = tvb_get_letohs( tvb, offset);
                proto_tree_add_item(wsmp_tree,
                                hf_wsmp_wsmlength, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;

                wsmdata_item = proto_tree_add_text (wsmp_tree, tvb, offset, wsmlength,
                                                    "Wave Short Message");
                wsmdata_tree = proto_item_add_subtree(wsmdata_item, ett_wsmdata);

                /* TODO: Branch on the application context and display accordingly
                 * Default call the data dissector
                 */
                wsmdata_tvb = tvb_new_subset(tvb, offset,wsmlength, wsmlength);
                call_dissector(data_handle, wsmdata_tvb, pinfo, wsmdata_tree);
        }

}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
 */

void
proto_register_wsmp(void)
{
        /* Setup list of header fields  See Section 1.6.1 for details*/
        static hf_register_info hf[] = {
                { &hf_wsmp_version,
                        { "Version",           "wsmp.version", FT_UINT8, BASE_DEC, NULL, 0x0,
                                NULL, HFILL }},

                { &hf_wsmp_security,
                        { "Security",           "wsmp.security", FT_UINT8, BASE_DEC, NULL, 0x0,
                                NULL, HFILL }},

                { &hf_wsmp_channel,
                        { "Channel", "wsmp.channel", FT_UINT8, BASE_DEC, NULL, 0x0,
                                NULL, HFILL }},

                { &hf_wsmp_rate,
                        { "Rate", "wsmp.rate", FT_UINT8, BASE_DEC, NULL, 0x0,
                                NULL, HFILL }},

                { &hf_wsmp_txpower,
                        { "Transmit power", "wsmp.txpower", FT_UINT8, BASE_DEC, NULL, 0x0,
                                NULL, HFILL }},

                { &hf_wsmp_appclass,
                        { "App class", "wsmp.appclass", FT_UINT8, BASE_DEC, NULL, 0x0,
                                NULL, HFILL }},

                { &hf_wsmp_acmlength,
                        { "Acm Length", "wsmp.acmlength", FT_UINT8, BASE_DEC, NULL, 0x0,
                                NULL, HFILL }},

                { &hf_wsmp_acm,
                        { "Application Context Data", "wsmp.acm", FT_STRING,
                                BASE_NONE, NULL, 0x0, "Acm", HFILL }},
                { &hf_wsmp_wsmlength,
                        { "WSM Length", "wsmp.wsmlength", FT_UINT16, BASE_DEC, NULL, 0x0,
                                NULL, HFILL }},
        };

        /* Setup protocol subtree array */
        static gint *ett[] = {
                &ett_wsmp,
				&ett_wsmdata,
        };

        /* Register the protocol name and description */
        proto_wsmp = proto_register_protocol("Wave Short Message Protocol(IEEE P1609.3)",
                        "WSMP", "wsmp");

        /* Required function calls to register the header fields and subtrees used */
        proto_register_field_array(proto_wsmp, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

}

/* If this dissector uses sub-dissector registration add a registration routine.
   This exact format is required because a script is used to find these routines
   and create the code that calls these routines.
 */

void
proto_reg_handoff_wsmp(void)
{
        dissector_handle_t wsmp_handle;

        wsmp_handle = create_dissector_handle(dissect_wsmp, proto_wsmp);
        dissector_add_uint("ethertype", ETHERTYPE_WSMP, wsmp_handle);
        data_handle = find_dissector("data");
        return;
}
