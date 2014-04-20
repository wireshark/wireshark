/* packet-elmi.c
 * Routines for Ethernet Local Management Interface (E-LMI) dissection
 * Copyright 2014, Martin Kaiser <martin@kaiser.cx>
 *
 * based on a dissector written in lua
 * Copyright 2013, Werner Fischer (fischer-interactive.de)
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

/* E-LMI is defined in the MEF16 specification from Metro Ethernet Forum
   http://www.metroethernetforum.org/PDF_Documents/technical-specifications/MEF16.pdf */

#include "config.h"

#include <glib.h>
#include <epan/value_string.h>
#include <epan/etypes.h>
#include <epan/packet.h>


static int proto_elmi = -1;

void proto_register_elmi(void);
void proto_reg_handoff_elmi(void);

static gint ett_elmi = -1;
static gint ett_elmi_info_elem = -1;

static int hf_elmi_ver = -1;
static int hf_elmi_msg_type = -1;
static int hf_elmi_info_elem = -1;
static int hf_elmi_info_elem_len = -1;
static int hf_elmi_report_type = -1;
static int hf_elmi_snd_seq_num = -1;
static int hf_elmi_rcv_seq_num = -1;
static int hf_elmi_dat_inst = -1;

static const value_string elmi_msg_type[] = {
    { 0x75, "Status enquiry" },
    { 0x7C, "Status" },
    { 0, NULL }
};

#define TAG_REPORT_TYPE 0x01
#define TAG_SEQ_NUM     0x02
#define TAG_DATA_INST   0x03

static const value_string elmi_info_elem_tag[] = {
    { TAG_REPORT_TYPE, "Report type" },
    { TAG_SEQ_NUM,     "Sequence numbers" },
    { TAG_DATA_INST,   "Data instance" },
    { 0, NULL }
};

static const value_string elmi_report_type[] = {
    { 0x00, "Full status" },
    { 0x01, "E-LMI check" },
    { 0x02, "Single EVC async status" },
    { 0x03, "Full status continued" },
    { 0, NULL }
};


static gint
dissect_elmi_info_elem(
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    gint        offset_start;
    guint8      tag, len;
    proto_item *tree_pi;
    proto_tree *info_elem_tree;

    offset_start = offset;

    tag = tvb_get_guint8(tvb, offset);
    if (tag==0)
        return -1;

    tree_pi = proto_tree_add_text(
            tree, tvb, offset, -1, "Information element: %s",
            val_to_str_const(tag, elmi_info_elem_tag, "unknown"));
    info_elem_tree = proto_item_add_subtree(tree_pi, ett_elmi_info_elem);

    proto_tree_add_item(info_elem_tree, hf_elmi_info_elem,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(info_elem_tree, hf_elmi_info_elem_len,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    switch (tag) {
        case TAG_REPORT_TYPE:
            proto_tree_add_item(info_elem_tree, hf_elmi_report_type,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case TAG_SEQ_NUM:
            proto_tree_add_item(info_elem_tree, hf_elmi_snd_seq_num,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(info_elem_tree, hf_elmi_rcv_seq_num,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case TAG_DATA_INST:
            proto_tree_add_text(info_elem_tree, tvb, offset, 1, "Reserved");
            offset++;
            proto_tree_add_item(info_elem_tree, hf_elmi_dat_inst,
                    tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            break;
        default:
            offset += len;
            break;
    }

    proto_item_set_len(tree_pi, offset-offset_start);
    return offset-offset_start;
}


static int
dissect_elmi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *pi;
    proto_tree *elmi_tree;
    gint        offset=0;
    guint8      msg_type;
    gint        ret;

    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "E-LMI");

    pi = proto_tree_add_protocol_format(tree, proto_elmi,
            tvb, 0, tvb_captured_length(tvb),
            "Ethernet Local Management Interface (E-LMI)");
    elmi_tree = proto_item_add_subtree(pi, ett_elmi);

    proto_tree_add_item(elmi_tree, hf_elmi_ver, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    msg_type = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(elmi_tree, hf_elmi_msg_type,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s",
            val_to_str(msg_type, elmi_msg_type, "unknown (0x%x)"));
    offset++;

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        ret = dissect_elmi_info_elem(tvb, offset, pinfo, elmi_tree);
        if (ret<=0)
            break;
        offset += ret;
    }

    /* XXX - can we make the eth dissector handle our (standard) padding
     * and FCS? */
    return tvb_captured_length(tvb);
}


void
proto_register_elmi(void)
{
    static hf_register_info hf[] = {
        { &hf_elmi_ver,
            { "Version", "elmi.version", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_msg_type,
            { "Message type", "elmi.message_type", FT_UINT8, BASE_HEX,
                VALS(elmi_msg_type), 0, NULL, HFILL } },
        { &hf_elmi_info_elem,
            { "Tag", "elmi.info_element.tag", FT_UINT8, BASE_HEX,
                VALS(elmi_info_elem_tag), 0, NULL, HFILL } },
        { &hf_elmi_info_elem_len,
            { "Length", "elmi.info_element.length", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_report_type,
            { "Report type", "elmi.report_type", FT_UINT8, BASE_DEC,
                VALS(elmi_report_type), 0, NULL, HFILL } },
        { &hf_elmi_snd_seq_num,
            { "Send sequence number", "elmi.snd_seq_num", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_rcv_seq_num,
            { "Receive sequence number", "elmi.rcv_seq_num", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_dat_inst,
            { "Data instance", "elmi.data_instance", FT_UINT32, BASE_HEX,
                NULL, 0, NULL, HFILL } }
    };

    static gint *ett[] = {
        &ett_elmi,
        &ett_elmi_info_elem
    };


    proto_elmi = proto_register_protocol(
            "Ethernet Local Management Interface", "E-LMI", "elmi");

    proto_register_field_array(proto_elmi, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_elmi(void)
{
    dissector_handle_t elmi_handle;

    elmi_handle = new_create_dissector_handle(dissect_elmi, proto_elmi);
    dissector_add_uint("ethertype", ETHERTYPE_ELMI, elmi_handle);
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
