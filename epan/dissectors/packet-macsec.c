/* packet-macsec.c
 * Routines for MACSEC dissection
 * Copyright 2013, Allan W. Nielsen <anielsen@vitesse.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>

void proto_register_macsec(void);
void proto_reg_handoff_macsec(void);

#define TCI_V_MASK   0x80
#define TCI_ES_MASK  0x40
#define TCI_SC_MASK  0x20
#define TCI_SCB_MASK 0x10
#define TCI_E_MASK   0x08
#define TCI_C_MASK   0x04
#define TCI_AN_MASK  0x03


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
static int hf_macsec_SCI_System_identifier = -1;
static int hf_macsec_SCI_port_number       = -1;
static int hf_macsec_ICV                   = -1;

/* Initialize the subtree pointers */
static gint ett_macsec = -1;
static gint ett_macsec_tci = -1;

/* Code to actually dissect the packets */
static int dissect_macsec(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    unsigned    sectag_length,     data_length, icv_length = 16;
    unsigned    sectag_offset = 0, data_offset, icv_offset;
    guint8      tci_an_field;

    proto_item *macsec_item, *tci_item;
    proto_tree *macsec_tree, *tci_tree;

    tvbuff_t *next_tvb;

    tci_an_field = tvb_get_guint8(tvb, 0);

    if ((tci_an_field & TCI_V_MASK) != 0) {  /* version must be zero */
        return 0;
    }

    if (tci_an_field & TCI_SC_MASK) {
        sectag_length = 14;
    } else {
        sectag_length = 6;
    }

    /* Check for short length */
    if (tvb_captured_length(tvb) <= (sectag_length + icv_length)) {
        return 0;
    }

    data_offset = sectag_length;
    data_length = tvb_captured_length(tvb) - sectag_length - icv_length;
    icv_offset  = data_length + data_offset;

    next_tvb = tvb_new_subset_length(tvb, data_offset, data_length);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MACSEC");
    col_set_str(pinfo->cinfo, COL_INFO, "MACsec frame");

    if (tree) {
        macsec_item = proto_tree_add_item(tree,
                proto_macsec, tvb, 0, sectag_length, ENC_NA);
        macsec_tree = proto_item_add_subtree(macsec_item, ett_macsec);

        tci_item = proto_tree_add_uint_format(macsec_tree, hf_macsec_TCI, tvb,
                sectag_offset, 1, tci_an_field,
                "TCI=0x%02x: V=%d, ES=%d, SC=%d, SCB=%d, E=%d, C=%d, AN=%d",
                tci_an_field,
                ((TCI_V_MASK &   tci_an_field) ? 1:0),
                ((TCI_ES_MASK &  tci_an_field) ? 1:0),
                ((TCI_SC_MASK &  tci_an_field) ? 1:0),
                ((TCI_SCB_MASK & tci_an_field) ? 1:0),
                ((TCI_E_MASK &   tci_an_field) ? 1:0),
                ((TCI_C_MASK &   tci_an_field) ? 1:0),
                (TCI_AN_MASK &   tci_an_field));
        tci_tree = proto_item_add_subtree(tci_item, ett_macsec_tci);

        proto_tree_add_item(tci_tree, hf_macsec_TCI_V, tvb, sectag_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tci_tree, hf_macsec_TCI_ES, tvb, sectag_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tci_tree, hf_macsec_TCI_SC, tvb, sectag_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tci_tree, hf_macsec_TCI_SCB, tvb, sectag_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tci_tree, hf_macsec_TCI_E, tvb, sectag_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tci_tree, hf_macsec_TCI_C, tvb, sectag_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tci_tree, hf_macsec_AN, tvb, sectag_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(macsec_tree, hf_macsec_SL, tvb, sectag_offset + 1, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(macsec_tree, hf_macsec_PN, tvb, sectag_offset + 2, 4, ENC_BIG_ENDIAN);

        if (sectag_length == 14) {
            proto_tree_add_item(macsec_tree, hf_macsec_SCI_System_identifier,
                    tvb, sectag_offset + 6, 6, ENC_NA);
            proto_tree_add_item(macsec_tree, hf_macsec_SCI_port_number, tvb,
                    sectag_offset + 12, 2, ENC_BIG_ENDIAN);
        }

        call_data_dissector(next_tvb, pinfo, tree);

        proto_tree_add_item(macsec_tree, hf_macsec_ICV, tvb, icv_offset,
                icv_length, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_macsec(void)
{
    static hf_register_info hf[] = {
        { &hf_macsec_TCI, { "TAG Control Information", "macsec.TCI",FT_UINT8,
                            BASE_HEX, NULL, 0xfc, NULL, HFILL} },
        { &hf_macsec_TCI_V, { "VER", "macsec.TCI.V", FT_UINT8, BASE_HEX,
                                NULL, 0x80, NULL, HFILL} },
        { &hf_macsec_TCI_ES, { "ES", "macsec.TCI.ES", FT_UINT8, BASE_HEX, NULL,
                                 0x40, NULL, HFILL} },
        { &hf_macsec_TCI_SC, { "SC", "macsec.TCI.SC", FT_UINT8, BASE_HEX, NULL,
                                 0x20, NULL, HFILL} },
        { &hf_macsec_TCI_SCB, { "SCB", "macsec.TCI.SCB", FT_UINT8, BASE_HEX,
                                  NULL, 0x10, NULL, HFILL} },
        { &hf_macsec_TCI_E, { "E", "macsec.TCI.E", FT_UINT8, BASE_HEX, NULL,
                                0x08, NULL, HFILL} },
        { &hf_macsec_TCI_C, { "C", "macsec.TCI.C", FT_UINT8, BASE_HEX, NULL,
                                0x04, NULL, HFILL} },
        { &hf_macsec_AN, { "AN", "macsec.AN", FT_UINT8,
                             BASE_HEX, NULL, 0x03, NULL, HFILL} },
        { &hf_macsec_SL, { "Short length", "macsec.SL", FT_UINT8, BASE_DEC,
                             NULL, 0xFF, NULL, HFILL} },
        { &hf_macsec_PN, { "Packet number", "macsec.PN", FT_UINT32, BASE_DEC,
                             NULL, 0xFFFFFFFF, NULL, HFILL} },
        { &hf_macsec_SCI_System_identifier,
            { "System Identifier", "macsec.SCI.SytemIdentifier",
                FT_ETHER, BASE_NONE, NULL, 0x00, NULL, HFILL} },
        { &hf_macsec_SCI_port_number,
            { "Port number", "macsec.SCI.port_number",
                FT_UINT16, BASE_DEC, NULL, 0xFFFF, NULL, HFILL} },
        { &hf_macsec_ICV, { "ICV", "macsec.ICV",
                              FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL} }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_macsec,
        &ett_macsec_tci
    };

    /* Register the protocol name and description */
    proto_macsec = proto_register_protocol("802.1AE Secure tag", "macsec", "macsec");

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
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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

