/* packet-gdt-template.c
 *
 * Copyright 2022, Damir Franusic <damir.franusic@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


# include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/sctpppids.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-gdt.h"

#define PNAME  "Generic Data Transfer Protocol"
#define PSNAME "GDT"
#define PFNAME "gdt"

/* Initialize the protocol and registered fields */
static int proto_gdt;
static dissector_handle_t gdt_handle;

#include "packet-gdt-hf.c"

/* Initialize the subtree pointers */
static int ett_gdt;
#include "packet-gdt-ett.c"

#include "packet-gdt-fn.c"

static int dissect_gdt(tvbuff_t *tvb,
                       packet_info *pinfo,
                       proto_tree *tree,
                       void *data _U_) {
    proto_item *gdt_item = NULL;
    proto_tree *gdt_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* create the gdt protocol tree */
    if (tree) {
        gdt_item = proto_tree_add_item(tree, proto_gdt, tvb, 0, -1, ENC_NA);
        gdt_tree = proto_item_add_subtree(gdt_item, ett_gdt);
        dissect_GDTMessage_PDU(tvb, pinfo, gdt_tree, 0);
    }
    return tvb_captured_length(tvb);
}

/*--- proto_register_gdt ----------------------------------------------*/
void proto_register_gdt(void) {
    /* List of fields */
    static hf_register_info hf[] = {
#include "packet-gdt-hfarr.c"
    };

    /* List of subtrees */
    static int *ett[] = {
        &ett_gdt,
#include "packet-gdt-ettarr.c"
    };

    /* Register protocol */
    proto_gdt = proto_register_protocol(PNAME, PSNAME, PFNAME);

    /* Register fields and subtrees */
    proto_register_field_array(proto_gdt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register dissector */
    gdt_handle = register_dissector("gdt", dissect_gdt, proto_gdt);
}

/*--- proto_reg_handoff_gdt -------------------------------------------*/
void proto_reg_handoff_gdt(void) {
    static bool initialized = false;

    if (!initialized) {
        dissector_add_for_decode_as("sctp.ppi", gdt_handle);
        dissector_add_uint("sctp.ppi", GDT_PROTOCOL_ID, gdt_handle);
        initialized = true;
    }
}
