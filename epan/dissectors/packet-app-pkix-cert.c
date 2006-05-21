/* packet-app-pkix-cert.c
 *
 * Routines for application/pkix-cert media dissection
 * Copyright 2004, Yaniv Kaul.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
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
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-x509af.h>


/* Initialize the protocol and registered fields */
static int proto_cert = -1;

static gint hf_cert = -1;

/* Initialize the subtree pointers */
static gint ett_cert = -1;


static void
dissect_cert(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
        proto_tree *subtree = NULL;
        proto_item *ti;
        
        if (check_col(pinfo->cinfo, COL_INFO))
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "(application/pkix-cert)");

        if (tree) {
                ti = proto_tree_add_item(tree, proto_cert, tvb, 0, -1, FALSE);
                subtree = proto_item_add_subtree(ti, ett_cert);
        }

        dissect_x509af_Certificate(FALSE, tvb, 0, pinfo, subtree, hf_cert);
        return;
}


/****************** Register the protocol with Wireshark ******************/


/* This format is required because a script is used to build the C function
 * that calls the protocol registration. */

void
proto_register_cert(void)
{
        /*
         * Setup list of header fields.
         */
        static hf_register_info hf[] = {
                { &hf_cert,
                { "Certififcate", "cert", FT_NONE, BASE_HEX, NULL, 0x00, "Certificate", HFILL}},
        };

        /* Setup protocol subtree array */
        static gint *ett[] = {
                &ett_cert,
        };

        /* Register the protocol name and description */
        proto_cert = proto_register_protocol(
                        "PKIX CERT File Format",
                        "PKIX Certificate",
                        "pkix-cert"     
        );

        /* Required function calls to register the header fields
         * and subtrees used */
        proto_register_field_array(proto_cert, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        register_dissector("application/pkix-cert", dissect_cert, proto_cert);
}


void
proto_reg_handoff_cert(void)
{
        dissector_handle_t cert_handle;

        cert_handle = create_dissector_handle(dissect_cert, proto_cert);

        /* Register the PKIX-CERT media type */
        dissector_add_string("media_type", "application/pkix-cert", cert_handle);
}
