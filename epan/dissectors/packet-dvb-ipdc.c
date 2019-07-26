/* packet-dvb-ipdc.c
 * Routines for ETSI IP Datacast ESG Bootstrap parsing
 * Copyright 2009 by Holger Hans Peter Freyther <zecke@selfish.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_dvb_ipdc(void);
void proto_reg_handoff_dvb_ipdc(void);

/* Initialize the protocol and registered fields */
static int proto_ipdc = -1;

/* static int hf_ipdc_esg_bootstrap_xml = -1; */

/* Initialize the subtree pointers */
static gint ett_ipdc = -1;


enum {
    DVB_IPDC_SUB_FLUTE,
    DVB_IPDC_SUB_MAX
};

static dissector_handle_t sub_handles[DVB_IPDC_SUB_MAX];

#define UDP_PORT_IPDC_ESG_BOOTSTRAP 9214


/* Code to actually dissect the packets */
static int
dissect_ipdc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    tvbuff_t   *next_tvb;
    proto_tree *esg_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "IPDC");
    col_clear(pinfo->cinfo, COL_INFO);

    /* call into flute */
    if (tree) {
        proto_item *ti;

        ti = proto_tree_add_protocol_format(tree, proto_ipdc, tvb, 0, -1,
                                            "ESG Bootstrap");
        esg_tree = proto_item_add_subtree(ti, ett_ipdc);
    }

    next_tvb = tvb_new_subset_remaining(tvb, 0);
    call_dissector(sub_handles[DVB_IPDC_SUB_FLUTE], next_tvb, pinfo, esg_tree);
    return tvb_captured_length(tvb);
}

void
proto_register_dvb_ipdc(void)
{
#if 0
    static hf_register_info hf[] = {
        {&hf_ipdc_esg_bootstrap_xml,
         {"ESG Provider Discovery", "dvb_ipdc.bootstrap",
          FT_STRING, BASE_NONE, NULL, 0x0, "List of ESG Providers", HFILL}}
    };
#endif

    static gint *ett[] = {
        &ett_ipdc,
    };

    proto_ipdc = proto_register_protocol("ETSI IPDC Bootstrap",
                                         "ESG Bootstrap", "dvb_ipdc");
#if 0
    proto_register_field_array(proto_ipdc, hf, array_length(hf));
#endif
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("dvb_ipdc", dissect_ipdc, proto_ipdc);
}

void
proto_reg_handoff_dvb_ipdc(void)
{
    dissector_handle_t ipdc_handle;

    sub_handles[DVB_IPDC_SUB_FLUTE] = find_dissector_add_dependency("alc", proto_ipdc);

    ipdc_handle = create_dissector_handle(dissect_ipdc, proto_ipdc);
    dissector_add_uint_with_preference("udp.port", UDP_PORT_IPDC_ESG_BOOTSTRAP, ipdc_handle);
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

