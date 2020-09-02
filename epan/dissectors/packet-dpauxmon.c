/* packet-dpauxmon.c
 * Routines for DisplayPort AUX-Channel monitor dissection
 * Copyright 2018, Dirk Eibach, Guntermann & Drunck GmbH <dirk.eibach@gdsys.cc>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <conversation.h>

#include "packet-dpaux.h"

#include <epan/packet.h>
#include <epan/proto_data.h>

enum {
    DPAUXMON_DATA = 0x00,
    DPAUXMON_DATA_END = 0x01,
    DPAUXMON_EVENT = 0x02,
    DPAUXMON_START = 0x03,
    DPAUXMON_STOP = 0x04,
    DPAUXMON_TS_OVERFLOW = 0x84,
};

void proto_reg_handoff_dpauxmon(void);
void proto_register_dpauxmon(void);

static dissector_handle_t dpaux_handle;

/* Initialize the protocol and registered fields */
static int proto_dpauxmon = -1;

static int hf_packet_type = -1;
static int hf_origin = -1;
static int hf_inputs = -1;
static int hf_hpd = -1;
static int hf_in0 = -1;
static int hf_in1 = -1;
static int hf_in2 = -1;

static int * const input_fields[] = {
    &hf_hpd,
    &hf_in0,
    &hf_in1,
    &hf_in2,
    NULL
};

/* Initialize the subtree pointers */
static gint ett_dpauxmon = -1;

static const value_string packet_type_vals[] = {
    { DPAUXMON_DATA, "Data" },
    { DPAUXMON_EVENT, "Event" },
    { DPAUXMON_START, "Start" },
    { DPAUXMON_STOP, "Stop" },
    { DPAUXMON_TS_OVERFLOW, "Timestamp Overflow" },
    { 0, NULL }
};

static const value_string origin_vals[] = {
    { 0, "Sink" },
    { 1, "Source" },
    { 0, NULL }
};

static int
dissect_dpauxmon(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *dpauxmon_tree;
    guint32 packet_type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DPAUXMON");
    col_set_str(pinfo->cinfo, COL_RES_DL_DST, "N/A");
    col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "Internal");

    /* create display subtree for the protocol */
    ti = proto_tree_add_item(tree, proto_dpauxmon, tvb, 0, -1, ENC_NA);
    dpauxmon_tree = proto_item_add_subtree(ti, ett_dpauxmon);

    proto_tree_add_item_ret_uint(dpauxmon_tree, hf_packet_type, tvb, 0, 1, ENC_NA, &packet_type);
    col_add_fstr(pinfo->cinfo, COL_INFO, "DisplayPort AUX channel - %s", val_to_str_const(packet_type, packet_type_vals, "Unknown"));

    switch (packet_type) {
    case DPAUXMON_DATA: {
        struct dpaux_info dpaux_info;

        dpaux_info.from_source = tvb_get_guint8(tvb, 1);
        proto_tree_add_uint(dpauxmon_tree, hf_origin, tvb, 1, 1, dpaux_info.from_source);

        call_dissector_with_data(dpaux_handle, tvb_new_subset_remaining(tvb, 2),
                 pinfo, dpauxmon_tree, &dpaux_info);
        break;
        }
    case DPAUXMON_EVENT:
    case DPAUXMON_START:
        proto_tree_add_bitmask(dpauxmon_tree, tvb, 1, hf_inputs, 0, input_fields,
                               ENC_BIG_ENDIAN);
        break;
    case DPAUXMON_STOP:
        break;
    case DPAUXMON_TS_OVERFLOW:
        break;
    };

    return tvb_captured_length(tvb);
}

void
proto_register_dpauxmon(void)
{
    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_dpauxmon
    };

    /* Setup list of header fields  See Section 1.5 of README.dissector for
     * details. */
    static hf_register_info hf[] = {
        { &hf_packet_type,
          { "Packet Type", "dpauxmon.packet_type",
            FT_UINT8, BASE_DEC, VALS(packet_type_vals), 0,
            NULL, HFILL }
        },
        { &hf_origin,
          { "Origin", "dpauxmon.origin",
            FT_UINT8, BASE_DEC, VALS(origin_vals), 0,
            NULL, HFILL }
        },
        { &hf_inputs,
          { "Inputs", "dpauxmon.inputs",
            FT_UINT8, BASE_HEX, NULL, 0,
            NULL, HFILL }
        },
        { &hf_hpd,
          { "Hotplug Detect", "dpauxmon.hpd",
            FT_BOOLEAN, 4, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_in0,
          { "IN0", "dpauxmon.in0",
            FT_BOOLEAN, 4, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_in1,
          { "IN1", "dpauxmon.in1",
            FT_BOOLEAN, 4, NULL, 0x04,
            NULL, HFILL }
        },
        { &hf_in2,
          { "IN2", "dpauxmon.in2",
            FT_BOOLEAN, 4, NULL, 0x08,
            NULL, HFILL }
        },
    };

    /* Register the protocol name and description */
    proto_dpauxmon = proto_register_protocol("DPAUXMON DisplayPort AUX channel monitor", "DPAUXMON", "dpauxmon");
    proto_register_field_array(proto_dpauxmon, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dpauxmon(void)
{
    static gboolean initialized = FALSE;
    static dissector_handle_t dpauxmon_handle;

    dpaux_handle = find_dissector_add_dependency("dpaux", proto_dpauxmon);

    if (!initialized) {
        dpauxmon_handle = create_dissector_handle(dissect_dpauxmon, proto_dpauxmon);
        initialized = TRUE;
    } else {
        dissector_delete_uint("wtap_encap", WTAP_ENCAP_DPAUXMON, dpauxmon_handle);
    }

    dissector_add_uint("wtap_encap", WTAP_ENCAP_DPAUXMON, dpauxmon_handle);
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
