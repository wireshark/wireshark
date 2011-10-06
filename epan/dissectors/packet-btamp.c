/* packet-btamp.c
 * Routines for the Bluetooth AMP dissection
 *
 * Copyright 2009, Kovarththanan Rajaratnam <kovarththanan.rajaratnam@gmail.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include "packet-btl2cap.h"

/* Initialize the protocol and registered fields */
static int proto_btamp = -1;
static int hf_btamp_command = -1;
static int hf_btamp_cmd_code = -1;
static int hf_btamp_cmd_ident = -1;
static int hf_btamp_cmd_length = -1;
static int hf_btamp_cmd_data = -1;
static int hf_btamp_rej_reason = -1;
static int hf_btamp_mtu = -1;
static int hf_btamp_extfeatures = -1;
static int hf_btamp_lcontroller_id = -1;
static int hf_btamp_rcontroller_id = -1;
static int hf_btamp_controller_list = -1;
static int hf_btamp_controllers = -1;
static int hf_btamp_controller_id = -1;
static int hf_btamp_controller_type = -1;
static int hf_btamp_controller_status = -1;
static int hf_btamp_status = -1;
static int hf_btamp_create_status = -1;
static int hf_btamp_disc_status = -1;
static int hf_btamp_total_bw = -1;
static int hf_btamp_max_guaran_bw = -1;
static int hf_btamp_min_latency = -1;
static int hf_btamp_pal_caps_guaranteed = -1;
static int hf_btamp_pal_caps_mask = -1;
static int hf_btamp_amp_assoc_size = -1;
static int hf_btamp_amp_assoc = -1;

/* Initialize the subtree pointers */
static gint ett_btamp = -1;
static gint ett_btamp_cmd = -1;
static gint ett_btamp_caps = -1;
static gint ett_btamp_controller_entry = -1;
static gint ett_btamp_controller_list = -1;

static const value_string command_code_vals[] = {
    { 0x01, "AMP Command Reject" },
    { 0x02, "AMP Discover Request" },
    { 0x03, "AMP Discover Response" },
    { 0x04, "AMP Change Notify" },
    { 0x05, "AMP Change Response" },
    { 0x06, "AMP Get Info Request" },
    { 0x07, "AMP Get Info Response" },
    { 0x08, "AMP Get AMP Assoc Request" },
    { 0x09, "AMP Get AMP Assoc Response" },
    { 0x0A, "AMP Create Physical Link Request" },
    { 0x0B, "AMP Create Physical Link Response" },
    { 0x0C, "AMP Disconnect Physical Link Request" },
    { 0x0D, "AMP Disconnect Physical Link Response" },
    { 0, NULL }
};

static const value_string reason_vals[] = {
    { 0x0000,   "Command not understood" },
    { 0, NULL }
};

static const value_string controller_type_vals[] = {
    { 0x0000, "Bluetooth BR/EDR" },
    { 0x0001, "802.11" },
    { 0x0002, "ECMA-368" },
    { 0, NULL }
};

static const value_string controller_status_vals[] = {
    { 0x0000, "Controller available but currently physically powered down" },
    { 0x0001, "Controller used exclusively by Bluetooth BR/EDR" },
    { 0x0002, "Controller has no capacity available for Bluetooth operation" },
    { 0x0003, "Controller has low capacity available for Bluetooth operation" },
    { 0x0004, "Controller has medium capacity available for Bluetooth operation" },
    { 0x0005, "Controller has high capacity available for Bluetooth operation" },
    { 0x0006, "Controller has full capacity available for Bluetooth operation" },
    { 0, NULL }
};

static const value_string status_vals[] = {
    { 0x0000,   "Success" },
    { 0x0001,   "Invalid Controller ID" },
    { 0, NULL }
};

static const value_string create_status_vals[] = {
    { 0x0000,   "Success" },
    { 0x0001,   "Invalid Controller ID" },
    { 0x0002,   "Failed - Unable to start link creation" },
    { 0x0003,   "Failed - Collision Occurred" },
    { 0x0004,   "Failed - AMP Disconnected Physical Link Request packet received" },
    { 0x0005,   "Failed - Physical Link Already Exists" },
    { 0, NULL }
};

static const value_string disc_status_vals[] = {
    { 0x0000,   "Success" },
    { 0x0001,   "Invalid Controller ID" },
    { 0x0002,   "Failed - No Physical Link exists and no Physical Link creation is in progress" },
    { 0, NULL }
};

static int
dissect_comrej(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint16 reason;

    reason = tvb_get_letohs(tvb, offset);
    proto_tree_add_item(tree, hf_btamp_rej_reason, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    switch(reason){
    case 0x0000: /* Command not understood */
        break;

    default:
        break;
    }

    return offset;
}

static int
dissect_discoverrequest(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_btamp_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    proto_tree_add_item(tree, hf_btamp_extfeatures, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    return offset;
}

static int
dissect_controller_entry(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, guint16 idx)
{
    proto_tree *btamp_controller_entry_tree=NULL;
    proto_item *ti_controller_entry=NULL;

    ti_controller_entry=proto_tree_add_none_format(tree,
            hf_btamp_controllers, tvb,
            offset, 3,
            "Entry: %u", idx);
    btamp_controller_entry_tree=proto_item_add_subtree(ti_controller_entry, ett_btamp_controller_entry);

    proto_tree_add_item(btamp_controller_entry_tree, hf_btamp_controller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(btamp_controller_entry_tree, hf_btamp_controller_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(btamp_controller_entry_tree, hf_btamp_controller_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    return offset;
}

static int
dissect_discoverresponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint16 length;
    guint16 idx = 1;
    proto_tree *btamp_controller_list_tree=NULL;
    proto_item *ti_controller_list=NULL;

    proto_tree_add_item(tree, hf_btamp_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    proto_tree_add_item(tree, hf_btamp_extfeatures, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    length = tvb_length_remaining(tvb, offset);
    ti_controller_list=proto_tree_add_none_format(tree,
            hf_btamp_controller_list, tvb,
            offset, length,
            "Controller list");
    btamp_controller_list_tree=proto_item_add_subtree(ti_controller_list, ett_btamp_controller_list);

    while (tvb_length_remaining(tvb, offset) >= 3) {
        offset = dissect_controller_entry(tvb, offset, pinfo, btamp_controller_list_tree, idx);
        ++idx;
    }

    return offset;
}

static int
dissect_changenotify(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    guint16 length;
    guint16 idx = 1;
    proto_tree *btamp_controller_list_tree=NULL;
    proto_item *ti_controller_list=NULL;

    length = tvb_length_remaining(tvb, offset);
    ti_controller_list=proto_tree_add_none_format(tree,
            hf_btamp_controller_list, tvb,
            offset, length,
            "Controller list");
    btamp_controller_list_tree=proto_item_add_subtree(ti_controller_list, ett_btamp_controller_list);

    while (tvb_length_remaining(tvb, offset) >= 3) {
        offset = dissect_controller_entry(tvb, offset, pinfo, btamp_controller_list_tree, idx);
        ++idx;
    }

    return offset;
}

static int
dissect_changeresponse(tvbuff_t *tvb _U_, int offset, packet_info *pinfo _U_, proto_tree *tree _U_)
{
    return offset;
}

static int
dissect_getinforequest(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_btamp_controller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    return offset;
}

static int
dissect_getinforesponse(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree *btamp_controller_tree=NULL;
    proto_item *ti_controller=NULL;

    proto_tree_add_item(tree, hf_btamp_controller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(tree, hf_btamp_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(tree, hf_btamp_total_bw, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    proto_tree_add_item(tree, hf_btamp_max_guaran_bw, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    proto_tree_add_item(tree, hf_btamp_min_latency, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;

    ti_controller=proto_tree_add_none_format(tree,
            hf_btamp_pal_caps_mask, tvb,
            offset, 2,
            "PAL Capabilities");
    btamp_controller_tree=proto_item_add_subtree(ti_controller, ett_btamp_caps);
    proto_tree_add_item(btamp_controller_tree, hf_btamp_pal_caps_guaranteed, tvb, offset, 2, TRUE);
    offset+=2;

    proto_tree_add_item(tree, hf_btamp_amp_assoc_size, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    return offset;
}

static int
dissect_getampassocrequest(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_btamp_controller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    return offset;
}

static int
dissect_ampassoc(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_btamp_amp_assoc, tvb, offset, tvb_length_remaining(tvb, offset), ENC_NA);
    offset+=tvb_length_remaining(tvb, offset);

    return offset;
}

static int
dissect_getampassocresponse(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_btamp_controller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(tree, hf_btamp_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    offset=dissect_ampassoc(tvb, offset, pinfo, tree);

    return offset;
}

static int
dissect_createphysicalrequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_btamp_lcontroller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(tree, hf_btamp_rcontroller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    offset=dissect_ampassoc(tvb, offset, pinfo, tree);

    return offset;
}

static int
dissect_createphysicalresponse(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_btamp_lcontroller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(tree, hf_btamp_rcontroller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(tree, hf_btamp_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    return offset;
}

static int
dissect_discphysicalchanrequest(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_btamp_lcontroller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(tree, hf_btamp_rcontroller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    return offset;
}

static int
dissect_discphysicalchanresponse(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_btamp_lcontroller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(tree, hf_btamp_rcontroller_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    proto_tree_add_item(tree, hf_btamp_controller_status, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;

    return offset;
}

static void dissect_btamp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset=0;
    proto_item *ti=NULL;
    proto_tree *btamp_tree=NULL;
    guint16 length;
    proto_tree *btamp_cmd_tree=NULL;
    proto_item *ti_command=NULL;
    guint8 cmd_code;
    guint16 cmd_length;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AMP");
    switch (pinfo->p2p_dir) {

    case P2P_DIR_SENT:
        col_add_str(pinfo->cinfo, COL_INFO, "Sent ");
        break;

    case P2P_DIR_RECV:
        col_add_str(pinfo->cinfo, COL_INFO, "Rcvd ");
        break;

    case P2P_DIR_UNKNOWN:
        col_clear(pinfo->cinfo, COL_INFO);
        break;

    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
                     pinfo->p2p_dir);
        break;
    }

    if(tree){
        ti=proto_tree_add_item(tree, proto_btamp, tvb, offset, -1, FALSE);
        btamp_tree=proto_item_add_subtree(ti, ett_btamp);
    }

    length = tvb_length_remaining(tvb, offset);
    ti_command=proto_tree_add_none_format(btamp_tree,
            hf_btamp_command, tvb,
            offset, length,
            "Command: ");
    btamp_cmd_tree=proto_item_add_subtree(ti_command, ett_btamp_cmd);

    cmd_code=tvb_get_guint8(tvb, offset);
    proto_tree_add_item(btamp_cmd_tree, hf_btamp_cmd_code, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    proto_tree_add_item(btamp_cmd_tree, hf_btamp_cmd_ident, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset++;

    cmd_length=tvb_get_letohs(tvb, offset);
    proto_tree_add_item(btamp_cmd_tree, hf_btamp_cmd_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    proto_item_set_len(ti_command, cmd_length+4);
    offset+=2;

    switch(cmd_code) {
    case 0x01: /* Command Reject */
        offset=dissect_comrej(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x02: /* Discover Request */
        offset=dissect_discoverrequest(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x03: /* Discover Response */
        offset=dissect_discoverresponse(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x04: /* AMP Change Notify */
        offset=dissect_changenotify(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x05: /* AMP Change Response */
        offset=dissect_changeresponse(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x06: /* AMP Get Info Request */
        offset=dissect_getinforequest(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x07: /* AMP Get Info Response */
        offset=dissect_getinforesponse(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x08: /* Get AMP Assoc Request */
        offset=dissect_getampassocrequest(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x09: /* Get AMP Assoc Response */
        offset=dissect_getampassocresponse(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x0A: /* Create Physical Link Request */
        offset=dissect_createphysicalrequest(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x0B: /* Create Physical Link Response */
        offset=dissect_createphysicalresponse(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x0c: /* Disconnect Physical Link Request */
        offset=dissect_discphysicalchanrequest(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    case 0x0d: /* Disconnect Physical Link Response */
        offset=dissect_discphysicalchanresponse(tvb, offset, pinfo, btamp_cmd_tree);
        break;

    default:
        proto_tree_add_item(btamp_cmd_tree, hf_btamp_cmd_data, tvb, offset, -1, ENC_NA);
        offset+=tvb_length_remaining(tvb, offset);
        break;
    }

    proto_item_append_text(ti_command, "%s", val_to_str(cmd_code, command_code_vals, "Unknown PDU (%u)"));
    col_append_str(pinfo->cinfo, COL_INFO, val_to_str(cmd_code, command_code_vals, "Unknown PDU (%u)"));
}

/* Register the protocol with Wireshark */
void
proto_register_btamp(void)
{
    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_btamp_command,
            { "Command",           "btamp.command",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "L2CAP Command", HFILL }
        },
        { &hf_btamp_cmd_code,
            { "Command Code",           "btamp.cmd_code",
                FT_UINT8, BASE_HEX, VALS(command_code_vals), 0x0,
                "L2CAP Command Code", HFILL }
        },
        { &hf_btamp_cmd_ident,
            { "Command Identifier",           "btamp.cmd_ident",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                "L2CAP Command Identifier", HFILL }
        },
        { &hf_btamp_cmd_length,
            { "Command Length",           "btamp.cmd_length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "L2CAP Command Length", HFILL }
        },
        { &hf_btamp_cmd_data,
            { "Command Data",           "btamp.cmd_data",
                FT_NONE, BASE_NONE, NULL, 0x0,
                "L2CAP Command Data", HFILL }
        },
        { &hf_btamp_rej_reason,
            { "Reason",           "btamp.rej_reason",
                FT_UINT16, BASE_HEX, VALS(reason_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_mtu,
            { "MPS/MTU",           "btamp.mps",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "MPS/MTU Size", HFILL }
        },
        { &hf_btamp_extfeatures,
            { "Extended Features",           "btamp.extfeatures",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                "Extended Features Mask", HFILL }
        },
        { &hf_btamp_controllers,
            { "Controller entry",           "btamp.ctrl_entry",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_controller_list,
            { "Controller list",           "btamp.ctrl_list",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_lcontroller_id,
            { "Local Controller ID",           "btamp.lctrl_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_rcontroller_id,
            { "Remote Controller ID",           "btamp.rctrl_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_controller_id,
            { "Controller ID",           "btamp.ctrl_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_controller_type,
            { "Controller Type",           "btamp.ctrl_type",
                FT_UINT8, BASE_DEC, VALS(controller_type_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_controller_status,
            { "Controller Status",           "btamp.ctrl_status",
                FT_UINT8, BASE_DEC, VALS(controller_status_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_status,
            { "Status",           "btamp.status",
                FT_UINT8, BASE_DEC, VALS(status_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_create_status,
            { "Status",           "btamp.create_status",
                FT_UINT8, BASE_DEC, VALS(create_status_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_disc_status,
            { "Status",           "btamp.disc_status",
                FT_UINT8, BASE_DEC, VALS(disc_status_vals), 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_pal_caps_mask,
            { "PAL Capabilities Mask",           "btamp.pal_caps_mask",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_pal_caps_guaranteed,
            { "Guaranteed Service type",           "btamp.guaranteed_type",
                FT_BOOLEAN, 16, NULL, 0x01,
                NULL, HFILL }
        },
        { &hf_btamp_total_bw,
            { "Total Bandwidth",           "btamp.total_bw",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_max_guaran_bw,
            { "Max Guaranteed Bandwidth",           "btamp.max_guaran_bw",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_min_latency,
            { "Minimum latency",           "btamp.min_latency",
                FT_UINT32, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_amp_assoc_size,
            { "Assoc Size",           "btamp.assoc_size",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_btamp_amp_assoc,
            { "Assoc",        "btamp.assoc",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_btamp,
        &ett_btamp_cmd,
        &ett_btamp_caps,
        &ett_btamp_controller_entry,
        &ett_btamp_controller_list,
    };

    /* Register the protocol name and description */
    proto_btamp = proto_register_protocol("Bluetooth AMP Packet", "AMP", "btamp");

    register_dissector("btamp", dissect_btamp, proto_btamp);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btamp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btamp(void)
{
    dissector_handle_t btamp_handle;

    btamp_handle = find_dissector("btamp");
    dissector_add_uint("btl2cap.cid", BTL2CAP_FIXED_CID_AMP_MAN, btamp_handle);
}

