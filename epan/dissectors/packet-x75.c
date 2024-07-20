/* packet-x75.c
 * Routines for X.75 frame disassembly
 * Manawyrm <git@tbspace.de>
 *
 * based on lapb dissector by
 * Olivier Abad <oabad@noos.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/decode_as.h>
#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/xdlc.h>

static dissector_table_t x75_subdissector_table;

void proto_register_x75(void);
void proto_reg_handoff_x75(void);

#define X75_ADDRESS_SLP_STE_A 0x03
#define X75_ADDRESS_SLP_STE_B 0x01
#define X75_ADDRESS_MLP_STE_C 0x0F
#define X75_ADDRESS_MLP_STE_D 0x07

static int proto_x75;
static int hf_x75_address;
static int hf_x75_control;
static int hf_x75_n_r;
static int hf_x75_n_s;
static int hf_x75_p;
static int hf_x75_f;
static int hf_x75_s_ftype;
static int hf_x75_u_modifier_cmd;
static int hf_x75_u_modifier_resp;
static int hf_x75_ftype_i;
static int hf_x75_ftype_s_u;

static int ett_x75;
static int ett_x75_control;

static dissector_handle_t data_handle;
static dissector_handle_t x75_handle;

static const xdlc_cf_items x75_cf_items = {
    &hf_x75_n_r,
    &hf_x75_n_s,
    &hf_x75_p,
    &hf_x75_f,
    &hf_x75_s_ftype,
    &hf_x75_u_modifier_cmd,
    &hf_x75_u_modifier_resp,
    &hf_x75_ftype_i,
    &hf_x75_ftype_s_u
};

static int
dissect_x75(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_tree          *x75_tree, *ti;
    uint16_t            control;
    int                 is_response;
    uint8_t             byte0;
    tvbuff_t            *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "X.75");
    col_set_str(pinfo->cinfo, COL_RES_NET_DST, "Broadcast");

    byte0 = tvb_get_uint8(tvb, 0);

    if (byte0 != X75_ADDRESS_SLP_STE_A && byte0 != X75_ADDRESS_SLP_STE_B &&
        byte0 != X75_ADDRESS_MLP_STE_C && byte0 != X75_ADDRESS_MLP_STE_D) /* invalid X.75 frame */
    {
        col_set_str(pinfo->cinfo, COL_INFO, "Invalid X.75 frame");
        if (tree)
            proto_tree_add_protocol_format(tree, proto_x75, tvb, 0, -1,
                            "Invalid X.75 frame");
        return 1;
    }

    // Clear lower layer src/dst address types, so our custom names
    // are shown in the Packet List pane
    pinfo->src.type = AT_NONE;
    pinfo->dst.type = AT_NONE;

    switch (pinfo->p2p_dir) {
    case P2P_DIR_SENT:
        if (byte0 == X75_ADDRESS_SLP_STE_A || byte0 == X75_ADDRESS_SLP_STE_B)
        {
            col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "STE A");
            col_set_str(pinfo->cinfo, COL_RES_DL_DST, "STE B");
        }
        else
        {
            col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "STE C");
            col_set_str(pinfo->cinfo, COL_RES_DL_DST, "STE D");
        }

        if (byte0 == X75_ADDRESS_SLP_STE_A || byte0 == X75_ADDRESS_MLP_STE_C)
            is_response = true;
        else
            is_response = false;
        break;

    case P2P_DIR_RECV:
        if (byte0 == X75_ADDRESS_SLP_STE_A || byte0 == X75_ADDRESS_SLP_STE_B)
        {
            col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "STE B");
            col_set_str(pinfo->cinfo, COL_RES_DL_DST, "STE A");
        }
        else
        {
            col_set_str(pinfo->cinfo, COL_RES_DL_SRC, "STE D");
            col_set_str(pinfo->cinfo, COL_RES_DL_DST, "STE C");
        }

        if (byte0 == X75_ADDRESS_SLP_STE_B || byte0 == X75_ADDRESS_MLP_STE_D)
            is_response = true;
        else
            is_response = false;
        break;

    default:
        is_response = false;
        break;
    }

    if (is_response)
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "X.75 RSP");
    }
    else
    {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "X.75 CMD");
    }

    ti = proto_tree_add_protocol_format(tree, proto_x75, tvb, 0, 2,
                                        "X.75");
    x75_tree = proto_item_add_subtree(ti, ett_x75);
    proto_tree_add_uint(x75_tree, hf_x75_address, tvb, 0, 1, byte0);

    control = dissect_xdlc_control(tvb, 1, pinfo, x75_tree, hf_x75_control,
            ett_x75_control, &x75_cf_items, NULL, NULL, NULL,
            is_response, false, false);

    /* information frame ==> data */
    if (XDLC_IS_INFORMATION(control)) {
        next_tvb = tvb_new_subset_remaining(tvb, 2);

        int len = tvb_reported_length_remaining(next_tvb, 0);

        // limit number of bytes being shown in COL_INFO
        if (len > 128)
            len = 128;

        col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", tvb_format_text(pinfo->pool, next_tvb, 0, len));

	if (!dissector_try_payload_new(x75_subdissector_table, next_tvb, pinfo, tree, true, NULL)) {
            call_dissector(data_handle, next_tvb, pinfo, tree);
	}
    }
    return tvb_captured_length(tvb);
}

void
proto_register_x75(void)
{
    static hf_register_info hf[] = {
        { &hf_x75_address,
          { "Address", "x75.address", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_x75_control,
          { "Control Field", "x75.control", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_x75_n_r,
          { "N(R)", "x75.control.n_r", FT_UINT8, BASE_DEC,
            NULL, XDLC_N_R_MASK, NULL, HFILL }},

        { &hf_x75_n_s,
          { "N(S)", "x75.control.n_s", FT_UINT8, BASE_DEC,
            NULL, XDLC_N_S_MASK, NULL, HFILL }},

        { &hf_x75_p,
          { "Poll", "x75.control.p", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), XDLC_P_F, NULL, HFILL }},

        { &hf_x75_f,
          { "Final", "x75.control.f", FT_BOOLEAN, 8,
            TFS(&tfs_set_notset), XDLC_P_F, NULL, HFILL }},

        { &hf_x75_s_ftype,
          { "Supervisory frame type", "x75.control.s_ftype", FT_UINT8, BASE_HEX,
            VALS(stype_vals), XDLC_S_FTYPE_MASK, NULL, HFILL }},

        { &hf_x75_u_modifier_cmd,
          { "Command", "x75.control.u_modifier_cmd", FT_UINT8, BASE_HEX,
            VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK, NULL, HFILL }},

        { &hf_x75_u_modifier_resp,
          { "Response", "x75.control.u_modifier_resp", FT_UINT8, BASE_HEX,
            VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK, NULL, HFILL }},

        { &hf_x75_ftype_i,
          { "Frame type", "x75.control.ftype", FT_UINT8, BASE_HEX,
            VALS(ftype_vals), XDLC_I_MASK, NULL, HFILL }},

        { &hf_x75_ftype_s_u,
          { "Frame type", "x75.control.ftype", FT_UINT8, BASE_HEX,
            VALS(ftype_vals), XDLC_S_U_MASK, NULL, HFILL }},
    };
    static int *ett[] = {
        &ett_x75,
        &ett_x75_control,
    };

    proto_x75 = proto_register_protocol("Async data over ISDN (X.75)",
                                         "X.75", "x75");
    proto_register_field_array (proto_x75, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    x75_handle = register_dissector("x75", dissect_x75, proto_x75);

    x75_subdissector_table =
	    register_decode_as_next_proto(proto_x75,
			  "x75.subdissector", "X.75 payload subdissector", NULL);
}

void
proto_reg_handoff_x75(void)
{
    data_handle = find_dissector("data");
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
