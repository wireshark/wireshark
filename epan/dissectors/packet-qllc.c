/* packet-qllc.c
 * Routines for QLLC protocol - Qualified? LLC
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_qllc(void);
void proto_reg_handoff_qllc(void);

static int proto_qllc = -1;
static int hf_qllc_address = -1;
static int hf_qllc_control = -1;

static gint ett_qllc = -1;

static dissector_handle_t sna_handle;

#define QSM                 0x93
#define QDISC               0x53
#define QXID                0xbf
#define QTEST               0xf3
#define QRR                 0xf1
#define QRD                 0x53
#define QUA                 0x73
#define QDM                 0x1f
#define QFRMR               0x97
#define QUI                 0x03
#define QUI_NO_REPLY        0x13
#define QSIM                0x17

#define QRD_QDISC_VALUE     0x53
#define QDISC_TEXT          "QDISC"
#define QRD_TEXT            "QRD"

/* Control Field */
static const value_string qllc_control_vals[] = {
    { QUI,          "QUI" },
    { QUI_NO_REPLY, "QUI - reply required" },
    { QSIM,         "QSIM" },
    { QDM,          "QDM" },
    { QUA,          "QUA" },
    { QSM,          "QSM" },
    { QFRMR,        "QFRMR" },
    { QXID,         "QXID" },
    { QRR,          "QRR" },
    { QTEST,        "QTEST" },
    { QDISC,        QDISC_TEXT },
    { QRD,          QRD_TEXT },
    { 0x00, NULL },
};


static int
dissect_qllc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_tree *qllc_tree;
    proto_item *qllc_ti;
    gboolean   *q_bit_set;
    guint8      addr, ctrl;
    gboolean    command = FALSE;

    /* Reject the packet if data is NULL */
    if (data == NULL)
        return 0;
    q_bit_set = (gboolean *)data;

    /*
     * If the Q bit isn't set, this is just SNA data.
     */
    if (!(*q_bit_set)) {
        call_dissector(sna_handle, tvb, pinfo, tree);
        return tvb_captured_length(tvb);
    }

    /* Summary information */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "QLLC");
    col_clear(pinfo->cinfo, COL_INFO);

    qllc_ti = proto_tree_add_item(tree, proto_qllc, tvb, 0, -1, ENC_NA);
    qllc_tree = proto_item_add_subtree(qllc_ti, ett_qllc);

    /* Get the address; we need it to determine if this is a
     * COMMAND or a RESPONSE */
    addr = tvb_get_guint8(tvb, 0);
    proto_tree_add_item(qllc_tree, hf_qllc_address, tvb, 0, 1, ENC_BIG_ENDIAN);

    /* The address field equals X'FF' in commands (except QRR)
     * and anything in responses. */
    ctrl = tvb_get_guint8(tvb, 1);
    if (ctrl != QRR && addr == 0xff) {
        command = TRUE;
    }


    /* Disambiguate QRD_QDISC_VALUE, based on whether this packet is
     * a COMMAND or RESPONSE. */
    if (ctrl == QRD_QDISC_VALUE) {
        if (command) {
            col_set_str(pinfo->cinfo, COL_INFO, QDISC_TEXT);
            proto_tree_add_uint_format_value(qllc_tree, hf_qllc_control, tvb,
                    1, 1, ctrl, "%s (0x%02x)", QDISC_TEXT, ctrl);
        }
        else {
            col_set_str(pinfo->cinfo, COL_INFO, QRD_TEXT);
            proto_tree_add_uint_format_value(qllc_tree, hf_qllc_control, tvb,
                    1, 1, ctrl, "%s (0x%02x)", QRD_TEXT, ctrl);
        }
    }
    else {
        /* Non-ambiguous control field value */
        col_add_str(pinfo->cinfo, COL_INFO,
                    val_to_str(ctrl, qllc_control_vals,
                        "Control Field: 0x%02x (unknown)"));

        proto_tree_add_uint(qllc_tree, hf_qllc_control, tvb,
                    1, 1, ctrl);
    }

    /* Do we have an I field ? */
    /* XXX - I field exists for QUI too, but only for subarea nodes.
     * Need to test for this. */
    if (ctrl == QXID || ctrl == QTEST || ctrl == QFRMR) {
        /* yes */
    }

    return tvb_captured_length(tvb);
}

void
proto_register_qllc(void)
{
    static hf_register_info hf[] = {
        { &hf_qllc_address,
          { "Address Field", "qllc.address", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_qllc_control,
          { "Control Field", "qllc.control", FT_UINT8, BASE_HEX,
            VALS(qllc_control_vals), 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_qllc,
    };

    proto_qllc = proto_register_protocol("Qualified Logical Link Control", "QLLC", "qllc");
    proto_register_field_array(proto_qllc, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("qllc", dissect_qllc, proto_qllc);
}

void
proto_reg_handoff_qllc(void)
{
    sna_handle = find_dissector_add_dependency("sna", proto_qllc);
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
