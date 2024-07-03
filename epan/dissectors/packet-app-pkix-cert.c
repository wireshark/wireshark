/* packet-app-pkix-cert.c
 *
 * Routines for application/pkix-cert media dissection
 * Copyright 2004, Yaniv Kaul.
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include "packet-x509af.h"


void proto_register_cert(void);
void proto_reg_handoff_cert(void);

static dissector_handle_t cert_handle;

/* Initialize the protocol and registered fields */
static int proto_cert;

static int hf_cert;

/* Initialize the subtree pointers */
static int ett_cert;


static int
dissect_cert(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
        proto_tree *subtree = NULL;
        proto_item *ti;
        asn1_ctx_t asn1_ctx;
        asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

        col_append_sep_str(pinfo->cinfo, COL_INFO, " ", "(application/pkix-cert)");

        if (tree) {
                ti = proto_tree_add_item(tree, proto_cert, tvb, 0, -1, ENC_NA);
                subtree = proto_item_add_subtree(ti, ett_cert);
        }

        dissect_x509af_Certificate(false, tvb, 0, &asn1_ctx, subtree, hf_cert);
        return tvb_captured_length(tvb);
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
                { "Certificate", "pkix-cert.cert", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL}},
        };

        /* Setup protocol subtree array */
        static int *ett[] = {
                &ett_cert,
        };

        /* Register the protocol name and description */
        proto_cert = proto_register_protocol("PKIX CERT File Format", "PKIX Certificate", "pkix-cert");

        /* Required function calls to register the header fields
         * and subtrees used */
        proto_register_field_array(proto_cert, hf, array_length(hf));
        proto_register_subtree_array(ett, array_length(ett));

        cert_handle = register_dissector("pkix-cert", dissect_cert, proto_cert);
}


void
proto_reg_handoff_cert(void)
{
        /* Register the PKIX-CERT media type */
        dissector_add_string("media_type", "application/pkix-cert", cert_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 expandtab:
 * :indentSize=8:tabSize=8:noTabs=true:
 */
