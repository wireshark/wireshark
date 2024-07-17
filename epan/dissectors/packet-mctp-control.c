/* packet-mctp.c
 * Routines for Management Component Transport Protocol (MCTP) control
 * protocol disassembly
 * Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * MCTP control protocol provides transport-layer initialisation and
 * management for MCTP endpoints; typically for device discovery, enumeration
 * and address assigment.
 *
 * MCTP Control protocol is defined by DMTF standard DSP0236:
 * https://www.dmtf.org/dsp/DSP0236
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/to_str.h>
#include "packet-mctp.h"
#include "packet-sll.h"

#define MCTP_CTRL_MIN_LENGTH 3

void proto_register_mctp_control(void);
void proto_reg_handoff_mctp_control(void);

static int proto_mctp_ctrl;

static int hf_mctp_ctrl_command;
static int hf_mctp_ctrl_rq;
static int hf_mctp_ctrl_d;
static int hf_mctp_ctrl_instance;
static int hf_mctp_ctrl_cc;
static int hf_mctp_ctrl_data;

static int ett_mctp_ctrl;
static int ett_mctp_ctrl_hdr;

static const value_string command_vals[] = {
    { 0x00, "Reserved" },
    { 0x01, "Set Endpoint ID" },
    { 0x02, "Get Endpoint ID" },
    { 0x03, "Get Endpoint UUID" },
    { 0x04, "Get MCTP Version Support" },
    { 0x05, "Get Message Type Support" },
    { 0,    NULL },
};

static const value_string cc_vals[] = {
    { 0x00, "Success" },
    { 0x01, "Error" },
    { 0x02, "Error: invalid data" },
    { 0x03, "Error: invalid length" },
    { 0x04, "Error: not ready" },
    { 0x05, "Error: unsupported command" },
    { 0,    NULL },
};

static const true_false_string tfs_rq = { "Request", "Response" };

static int
dissect_mctp_ctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_tree *mctp_ctrl_tree, *mctp_ctrl_hdr_tree;
    unsigned len, payload_start, cmd;
    proto_item *ti, *hti;
    bool rq;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MCTP Control");
    col_clear(pinfo->cinfo, COL_INFO);

    /* Check that the packet is long enough for it to belong to us. */
    len = tvb_reported_length(tvb);

    if (len < MCTP_CTRL_MIN_LENGTH) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "Bogus length %u, minimum %u",
                     len, MCTP_CTRL_MIN_LENGTH);
        return tvb_captured_length(tvb);
    }

    ti = proto_tree_add_item(tree, proto_mctp_ctrl, tvb, 0, -1, ENC_NA);
    mctp_ctrl_tree = proto_item_add_subtree(ti, ett_mctp_ctrl);

    hti = proto_tree_add_item(mctp_ctrl_tree, proto_mctp_ctrl, tvb, 0, -1,
                              ENC_NA);
    proto_item_set_text(hti, "MCTP Control Protocol header");
    mctp_ctrl_hdr_tree = proto_item_add_subtree(hti, ett_mctp_ctrl_hdr);

    proto_tree_add_item_ret_boolean(mctp_ctrl_hdr_tree, hf_mctp_ctrl_rq,
                                    tvb, 1, 1, ENC_NA, &rq);

    proto_tree_add_item(mctp_ctrl_hdr_tree, hf_mctp_ctrl_d,
                        tvb, 1, 1, ENC_NA);

    proto_tree_add_item(mctp_ctrl_hdr_tree, hf_mctp_ctrl_instance,
                        tvb, 1, 1, ENC_NA);

    proto_tree_add_item_ret_uint(mctp_ctrl_hdr_tree, hf_mctp_ctrl_command,
                                 tvb, 2, 1, ENC_NA, &cmd);

    col_add_fstr(pinfo->cinfo, COL_INFO, "MCTP %s %s",
                 val_to_str_const(cmd, command_vals, "Control"),
                 tfs_get_string(rq, &tfs_rq));

    payload_start = 3;

    if (!rq) {
        if (len == 3) {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "Bogus length %u for response, minimum 4", len);
            return tvb_captured_length(tvb);
        }
        proto_tree_add_item(mctp_ctrl_tree, hf_mctp_ctrl_cc,
                            tvb, 3, 1, ENC_NA);
        payload_start++;
    }

    if (len > payload_start) {
        proto_tree_add_item(mctp_ctrl_tree, hf_mctp_ctrl_data,
                            tvb, payload_start, -1, ENC_NA);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_mctp_control(void)
{
    /* *INDENT-OFF* */
    /* Field definitions */
    static hf_register_info hf[] = {
        { &hf_mctp_ctrl_command,
          { "Command", "mctpc.command",
            FT_UINT8, BASE_DEC, VALS(command_vals), 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_rq,
          { "Rq", "mctpc.rq",
            FT_BOOLEAN, 8, TFS(&tfs_rq), 0x80,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_d,
          { "Datagram", "mctpc.d",
            FT_BOOLEAN, 8, TFS(&tfs_set_notset), 0x40,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_instance,
          { "Instance ID", "mctpc.instance",
            FT_UINT8, BASE_HEX, NULL, 0x1f,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_cc,
          { "Completion code", "mctpc.cc",
            FT_UINT8, BASE_HEX, VALS(cc_vals), 0,
            NULL, HFILL },
        },
        { &hf_mctp_ctrl_data,
          { "Data", "mctpc.data",
            FT_BYTES, SEP_SPACE, NULL, 0,
            NULL, HFILL },
        },
    };

    /* protocol subtree */
    static int *ett[] = {
        &ett_mctp_ctrl,
        &ett_mctp_ctrl_hdr,
    };

    proto_mctp_ctrl = proto_register_protocol("MCTP Control Protocol",
                                              "MCTP-Control", "mctpc");

    proto_register_field_array(proto_mctp_ctrl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}

void
proto_reg_handoff_mctp_control(void)
{
    dissector_handle_t mctp_ctrl_handle;
    mctp_ctrl_handle = create_dissector_handle(dissect_mctp_ctrl, proto_mctp_ctrl);
    dissector_add_uint("mctp.type", MCTP_TYPE_CONTROL, mctp_ctrl_handle);
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
