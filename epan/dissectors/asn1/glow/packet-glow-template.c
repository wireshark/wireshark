/* packet-glow.c
 * Routines for GLOW packet dissection
 *
 * Copyright 2018, Gilles Dufour <dufour.gilles@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

# include "config.h"

#include <epan/packet.h>
#include "packet-ber.h"

#define PNAME  "Glow"
#define PSNAME "GLOW"
#define PFNAME "glow"

void proto_register_glow(void);

static dissector_handle_t glow_handle=NULL;
static int proto_glow = -1;

#include "packet-glow-hf.c"

/* Initialize the subtree pointers */
static int ett_glow = -1;

#include "packet-glow-ett.c"

#include "packet-glow-fn.c"

static int
dissect_glow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item      *glow_item = NULL;
    proto_tree      *glow_tree = NULL;

    /* make entry in the Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);

    /* create the glow protocol tree */
    glow_item = proto_tree_add_item(tree, proto_glow, tvb, 0, -1, ENC_NA);
    glow_tree = proto_item_add_subtree(glow_item, ett_glow);

    dissect_Root_PDU(tvb, pinfo, glow_tree, data);

    return tvb_captured_length(tvb);
}

void proto_register_glow(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-glow-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
                  &ett_glow,
#include "packet-glow-ettarr.c"
  };


  /* Register protocol */
  proto_glow = proto_register_protocol(PNAME, PSNAME, PFNAME);
  glow_handle = register_dissector("glow", dissect_glow, proto_glow);

  /* Register fields and subtrees */
  proto_register_field_array(proto_glow, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
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
