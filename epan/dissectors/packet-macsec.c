/* packet-macsec.c
 * Routines for IEEE 802.1AE MACsec dissection
 * Copyright 2013, Allan W. Nielsen <anielsen@vitesse.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

void proto_register_macsec(void);
void proto_reg_handoff_macsec(void);

static dissector_handle_t ethertype_handle;

/* TCI/AN field masks */
#define TCI_MASK     0xFC
#define TCI_V_MASK   0x80
#define TCI_ES_MASK  0x40
#define TCI_SC_MASK  0x20
#define TCI_SCB_MASK 0x10
#define TCI_E_MASK   0x08
#define TCI_C_MASK   0x04
#define AN_MASK      0x03


static int proto_macsec = -1;
static int hf_macsec_TCI                   = -1;
static int hf_macsec_TCI_V                 = -1;
static int hf_macsec_TCI_ES                = -1;
static int hf_macsec_TCI_SC                = -1;
static int hf_macsec_TCI_SCB               = -1;
static int hf_macsec_TCI_E                 = -1;
static int hf_macsec_TCI_C                 = -1;
static int hf_macsec_AN                    = -1;
static int hf_macsec_SL                    = -1;
static int hf_macsec_PN                    = -1;
static int hf_macsec_SCI_system_identifier = -1;
static int hf_macsec_SCI_port_identifier   = -1;
static int hf_macsec_etype                 = -1;
static int hf_macsec_ICV                   = -1;

/* Initialize the subtree pointers */
static gint ett_macsec = -1;
static gint ett_macsec_tci = -1;

/* Code to actually dissect the packets */
static int dissect_macsec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    unsigned    sectag_length, data_length, icv_length;
    unsigned    data_offset, icv_offset;
    guint8      tci_an_field;

    proto_item *macsec_item;
    proto_tree *macsec_tree = NULL;

    tvbuff_t *next_tvb;

    tci_an_field = tvb_get_guint8(tvb, 0);

    if ((tci_an_field & TCI_V_MASK) != 0) {  /* version must be zero */
        return 0;
    }

    icv_length = 16;  /* Fixed size for version 0 */

    if (tci_an_field & TCI_SC_MASK) {
        sectag_length = 14;  /* optional SCI present */
    } else {
        sectag_length = 6;
    }

    /* Check for short length */
    if (tvb_captured_length(tvb) <= (sectag_length + icv_length)) {
        return 0;
    }

    /* Get the payload section */
    data_offset = sectag_length;
    data_length = tvb_captured_length(tvb) - sectag_length - icv_length;
    icv_offset  = data_length + data_offset;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MACSEC");
    col_set_str(pinfo->cinfo, COL_INFO, "MACsec frame");

    if (tree) {
        if (((tci_an_field & TCI_E_MASK) == TCI_E_MASK) || ((tci_an_field & TCI_C_MASK) == TCI_C_MASK)) {
            macsec_item = proto_tree_add_item(tree,
                proto_macsec, tvb, 0, sectag_length, ENC_NA);
        } else {
            /* Add the EtherType too since this is authentication only. */
            macsec_item = proto_tree_add_item(tree,
                proto_macsec, tvb, 0, sectag_length + 2, ENC_NA);
        }
        macsec_tree = proto_item_add_subtree(macsec_item, ett_macsec);

        static int * const flags[] = {
            &hf_macsec_TCI_V,
            &hf_macsec_TCI_ES,
            &hf_macsec_TCI_SC,
            &hf_macsec_TCI_SCB,
            &hf_macsec_TCI_E,
            &hf_macsec_TCI_C,
            NULL
        };

        proto_tree_add_bitmask_with_flags(macsec_tree, tvb, 0,
                hf_macsec_TCI, ett_macsec_tci, flags, ENC_NA, BMT_NO_TFS);

        proto_tree_add_item(macsec_tree, hf_macsec_AN, tvb, 0, 1, ENC_NA);
        proto_tree_add_item(macsec_tree, hf_macsec_SL, tvb, 1, 1, ENC_NA);
        proto_tree_add_item(macsec_tree, hf_macsec_PN, tvb, 2, 4, ENC_BIG_ENDIAN);

        if (sectag_length == 14) {
            proto_tree_add_item(macsec_tree, hf_macsec_SCI_system_identifier,
                    tvb, 6, 6, ENC_NA);
            proto_tree_add_item(macsec_tree, hf_macsec_SCI_port_identifier, tvb,
                    12, 2, ENC_BIG_ENDIAN);
        }

        if (((tci_an_field & TCI_E_MASK) == TCI_E_MASK) || ((tci_an_field & TCI_C_MASK) == TCI_C_MASK)) {
            proto_tree_add_item(macsec_tree, hf_macsec_ICV, tvb, icv_offset, icv_length, ENC_NA);
        } else {
            proto_tree_add_item(macsec_tree, hf_macsec_etype, tvb, data_offset, 2, ENC_BIG_ENDIAN);
        }
    }

    /* if encrypted or changed, we can only display data */
    if (((tci_an_field & TCI_E_MASK) == TCI_E_MASK) || ((tci_an_field & TCI_C_MASK) == TCI_C_MASK)) {
        next_tvb = tvb_new_subset_length(tvb, data_offset, data_length);
        call_data_dissector(next_tvb, pinfo, tree);
    } else {
        ethertype_data_t ethertype_data;

        ethertype_data.etype = tvb_get_ntohs(tvb, data_offset);
        ethertype_data.payload_offset = data_offset + 2;
        ethertype_data.fh_tree = macsec_tree;
        ethertype_data.trailer_id = hf_macsec_ICV;
        ethertype_data.fcs_len = 0;

        call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_macsec(void)
{
    static hf_register_info hf[] = {
        { &hf_macsec_TCI,
            { "TCI", "macsec.TCI", FT_UINT8, BASE_HEX,
              NULL, TCI_MASK, "TAG Control Information", HFILL }
        },
        { &hf_macsec_TCI_V,
            { "VER", "macsec.TCI.V", FT_UINT8, BASE_HEX,
              NULL, TCI_V_MASK, "Version", HFILL }
        },
        { &hf_macsec_TCI_ES,
            { "ES", "macsec.TCI.ES", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), TCI_ES_MASK, "End Station", HFILL }
        },
        { &hf_macsec_TCI_SC,
            { "SC", "macsec.TCI.SC", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), TCI_SC_MASK, "Secure Channel", HFILL }
        },
        { &hf_macsec_TCI_SCB,
            { "SCB", "macsec.TCI.SCB", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), TCI_SCB_MASK, "Single Copy Broadcast", HFILL }
        },
        { &hf_macsec_TCI_E,
            { "E", "macsec.TCI.E", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), TCI_E_MASK, "Encryption", HFILL }
        },
        { &hf_macsec_TCI_C,
            { "C", "macsec.TCI.C", FT_BOOLEAN, 8,
              TFS(&tfs_set_notset), TCI_C_MASK, "Changed Text", HFILL }
        },
        { &hf_macsec_AN,
            { "AN", "macsec.AN", FT_UINT8, BASE_HEX,
              NULL, AN_MASK, "Association Number", HFILL }
        },
        { &hf_macsec_SL,
            { "Short length", "macsec.SL", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_PN,
            { "Packet number", "macsec.PN", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_SCI_system_identifier,
            { "System Identifier", "macsec.SCI.system_identifier", FT_ETHER, BASE_NONE,
                NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_SCI_port_identifier,
            { "Port Identifier", "macsec.SCI.port_identifier", FT_UINT16, BASE_DEC,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_etype,
            { "Ethertype", "macsec.etype", FT_UINT16, BASE_HEX,
              NULL, 0, NULL, HFILL }
        },
        { &hf_macsec_ICV,
            { "ICV", "macsec.ICV", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_macsec,
        &ett_macsec_tci
    };

    /* Register the protocol name and description */
    proto_macsec = proto_register_protocol("802.1AE Security tag", "MACsec", "macsec");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_macsec, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_macsec(void)
{
    dissector_handle_t macsec_handle;
    macsec_handle = create_dissector_handle(dissect_macsec, proto_macsec);
    dissector_add_uint("ethertype", ETHERTYPE_MACSEC, macsec_handle);

    ethertype_handle = find_dissector("ethertype");
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

