/* packet-bthci_iso.c
 * Routines for the Bluetooth ISO dissection
 * Copyright 2020, Jakub Pawlowski <jpawlowski@google.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include "packet-bluetooth.h"

/* Initialize the protocol and registered fields */
static int proto_bthci_iso = -1;
static int hf_bthci_iso_connection_handle = -1;
static int hf_bthci_iso_pb_flag = -1;
static int hf_bthci_iso_ts_flag = -1;
static int hf_bthci_iso_reserved_1 = -1;
static int hf_bthci_iso_length = -1;
static int hf_bthci_iso_reserved_2 = -1;
static int hf_bthci_iso_data = -1;

/* Initialize the subtree pointers */
static gint ett_bthci_iso = -1;

static dissector_handle_t bthci_iso_handle;

static const value_string pb_flag_vals[] = {
    { 0, "First fragment of fragmented SDU" },
    { 1, "Continuation Fragment of an SDU" },
    { 2, "Complete SDU" },
    { 3, "Last fragment of an SDU" },
    { 0, NULL }
};

static const value_string ts_flag_vals[] = {
    { 0, "No Time Stamp" },
    { 1, "Contains Time Stamp" },
    { 0, NULL }
};

void proto_register_bthci_iso(void);
void proto_reg_handoff_bthci_iso(void);

/* Code to actually dissect the packets */
static gint
dissect_bthci_iso(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item               *bthci_iso_item;
    proto_tree               *bthci_iso_tree;
    proto_item               *sub_item;
    guint16                   flags;
    gboolean                  fragmented;
    gint                      offset                = 0;
    guint16                   pb_flag;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;

    bthci_iso_item = proto_tree_add_item(tree, proto_bthci_iso, tvb, offset, -1, ENC_NA);
    bthci_iso_tree = proto_item_add_subtree(bthci_iso_item, ett_bthci_iso);

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
        col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "HCI_ISO");

    flags   = tvb_get_letohs(tvb, offset);
    pb_flag = (flags & 0x3000) >> 12;
    proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_connection_handle, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_pb_flag, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_ts_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_reserved_1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_reserved_2, tvb, offset, 1, ENC_LITTLE_ENDIAN);

    offset += 2;

    /* determine if packet is fragmented */
    switch(pb_flag) {
    case 0x00:  /* First Fragment */
    case 0x01:  /* Continuation */
    case 0x11:  /* Last */
        fragmented = TRUE;
        break;
    case 0x10:  /* Complete */
    default:
        /* unknown pb_flag */
        fragmented = FALSE;
    }


    if (tvb_captured_length_remaining(tvb, offset) > 0) {
        sub_item = proto_tree_add_item(bthci_iso_tree, hf_bthci_iso_data, tvb, offset, -1, ENC_NA);
        if (fragmented) {
            proto_item_append_text(sub_item, " Fragment");
        }
    }

    return tvb_captured_length(tvb);
}


void
proto_register_bthci_iso(void)
{
     /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_bthci_iso_connection_handle,
          { "Connection Handle",                             "bthci_iso.connection_handle",
            FT_UINT16, BASE_HEX, NULL, 0x0FFF,
            NULL, HFILL }
        },
        { &hf_bthci_iso_pb_flag,
          { "PB Flag",                                       "bthci_iso.pb_flag",
            FT_UINT16, BASE_DEC, VALS(pb_flag_vals), 0x3000,
            "Packet Boundary Flag", HFILL }
        },
        { &hf_bthci_iso_ts_flag,
          { "TS Flag",                                       "bthci_iso.ts_flag",
            FT_UINT16, BASE_DEC, VALS(ts_flag_vals), 0x4000,
            "Time stamp Flag", HFILL }
        },
        { &hf_bthci_iso_reserved_1,
          { "Reserved 1",                                       "bthci_iso.reserved_1",
            FT_UINT16, BASE_DEC, NULL, 0x8000,
            "Reserved", HFILL }
        },
        { &hf_bthci_iso_length,
          { "ISO Data Load Length",                             "bthci_iso.length",
            FT_UINT16, BASE_DEC, NULL, 0x7FFFF,
            NULL, HFILL }
        },
        { &hf_bthci_iso_reserved_2,
          { "Reserved 2",                                       "bthci_iso.reserved_2",
            FT_UINT16, BASE_DEC, NULL, 0x8000,
            "Reserved", HFILL }
        },
        { &hf_bthci_iso_data,
          { "ISO Data Load",                                          "bthci_iso.data",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_bthci_iso,
    };

    /* Register the protocol name and description */
    proto_bthci_iso = proto_register_protocol("Bluetooth HCI ISO Packet", "HCI_ISO", "bthci_iso");
    bthci_iso_handle = register_dissector("bthci_iso", dissect_bthci_iso, proto_bthci_iso);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_bthci_iso, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    prefs_register_protocol_subtree("Bluetooth", proto_bthci_iso, NULL);
}


void
proto_reg_handoff_bthci_iso(void)
{
    dissector_add_uint("hci_h4.type", HCI_H4_TYPE_ISO, bthci_iso_handle);
    dissector_add_uint("hci_h1.type", BTHCI_CHANNEL_ISO, bthci_iso_handle);
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
