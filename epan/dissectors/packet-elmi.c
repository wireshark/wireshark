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

#include <epan/packet.h>
#include <epan/etypes.h>


static int proto_elmi = -1;

void proto_register_elmi(void);
void proto_reg_handoff_elmi(void);

static gint ett_elmi = -1;
static gint ett_elmi_info_elem = -1;
static gint ett_elmi_sub_info_elem = -1;

static int hf_elmi_ver = -1;
static int hf_elmi_msg_type = -1;
static int hf_elmi_info_elem = -1;
static int hf_elmi_info_elem_len = -1;
static int hf_elmi_report_type = -1;
static int hf_elmi_snd_seq_num = -1;
static int hf_elmi_rcv_seq_num = -1;
static int hf_elmi_dat_inst = -1;
static int hf_elmi_reserved = -1;
static int hf_elmi_uni_status = -1;
static int hf_elmi_evc_refid = -1;
static int hf_elmi_evc_status = -1;
static int hf_last_ie = -1;
static int hf_map_seq = -1;
static int hf_priority = -1;
static int hf_default_evc = -1;
static int hf_elmi_sub_info_elem = -1;
static int hf_elmi_sub_info_elem_len = -1;
static int hf_elmi_uni_id = -1;
static int hf_elmi_evc_type = -1;
static int hf_elmi_evc_id = -1;
static int hf_elmi_ce_vlan_id = -1;
static int hf_elmi_sub_info_color_mode_flag = -1;
static int hf_elmi_sub_info_coupling_flag = -1;
static int hf_elmi_sub_info_per_cos_bit = -1;
static int hf_elmi_sub_cir_magnitude = -1;
static int hf_elmi_sub_cir_multiplier = -1;
static int hf_elmi_sub_cbs_magnitude = -1;
static int hf_elmi_sub_cbs_multiplier = -1;
static int hf_elmi_sub_eir_magnitude = -1;
static int hf_elmi_sub_eir_multiplier = -1;
static int hf_elmi_sub_ebs_magnitude = -1;
static int hf_elmi_sub_ebs_multiplier = -1;
static int hf_elmi_sub_user_prio_0 = -1;
static int hf_elmi_sub_user_prio_1 = -1;
static int hf_elmi_sub_user_prio_2 = -1;
static int hf_elmi_sub_user_prio_3 = -1;
static int hf_elmi_sub_user_prio_4 = -1;
static int hf_elmi_sub_user_prio_5 = -1;
static int hf_elmi_sub_user_prio_6 = -1;
static int hf_elmi_sub_user_prio_7 = -1;

static const value_string elmi_msg_type[] = {
    { 0x75, "Status enquiry" },
    { 0x7D, "Status" },
    { 0, NULL }
};

#define TAG_REPORT_TYPE 0x01
#define TAG_SEQ_NUM     0x02
#define TAG_DATA_INST   0x03
#define TAG_UNI_STATUS  0x11
#define TAG_EVC_STATUS  0x21
#define TAG_VLAN_EVC    0x22

static const value_string elmi_info_elem_tag[] = {
    { TAG_REPORT_TYPE, "Report type" },
    { TAG_SEQ_NUM,     "Sequence numbers" },
    { TAG_DATA_INST,   "Data instance" },
    { TAG_UNI_STATUS,  "UNI Status" },
    { TAG_EVC_STATUS,  "EVC Status" },
    { TAG_VLAN_EVC,    "CE-VLAN ID/EVC Map" },
    { 0, NULL }
};

static const value_string elmi_report_type[] = {
    { 0x00, "Full status" },
    { 0x01, "E-LMI check" },
    { 0x02, "Single EVC async status" },
    { 0x03, "Full status continued" },
    { 0, NULL }
};

#define SUB_TAG_UNI_ID  0x51
#define SUB_TAG_EVC_PRM 0x61
#define SUB_TAG_EVC_ID  0x62
#define SUB_TAG_EVC_MAP 0x63
#define SUB_TAG_BW_PRO  0x71

static const value_string elmi_sub_info_elem_tag[] = {
    { SUB_TAG_UNI_ID,   "UNI Identifier" },
    { SUB_TAG_EVC_PRM,  "EVC Parameters" },
    { SUB_TAG_EVC_ID,   "EVC Identifier" },
    { SUB_TAG_EVC_MAP,  "EVC Map Entry" },
    { SUB_TAG_BW_PRO,   "Bandwidth Profile" },
    { 0, NULL }
};

static const value_string elmi_vlan_id_evc_map_type[] = {
    { 0x01, "All to one binding" },
    { 0x02, "Service Multiplexing with no bundling" },
    { 0x03, "Bundling" },
    { 0, NULL }
};

static const value_string elmi_evc_status_type[] = {
    { 0x00, "Not Active" },
    { 0x01, "New and Not Active" },
    { 0x02, "Active" },
    { 0x03, "New and Active" },
    { 0x04, "Partially Active" },
    { 0x05, "New and Partially Active" },
    { 0, NULL }
};

static const value_string elmi_evc_type[] = {
    { 0x00, "Point-to-Point EVC" },
    { 0x01, "Multipoint-to-Multipoint EVC" },
    { 0, NULL }
};

const true_false_string tfs_applicable_not_applicable = { "Applicable", "Not Applicable" };

static gint
dissect_elmi_sub_info_elem(
        tvbuff_t *tvb, gint offset, proto_tree *tree)
{
    gint        offset_start;
    guint8      sub_tag, len;
    proto_item *tree_pi;
    proto_tree *sub_info_elem_tree = tree;

    offset_start = offset;

    sub_tag = tvb_get_guint8(tvb, offset);
    len = tvb_get_guint8(tvb, offset + 1);

    sub_info_elem_tree = proto_tree_add_subtree_format(
            tree, tvb, offset, len + 2, ett_elmi_sub_info_elem, &tree_pi,
            "Sub-information element: %s", val_to_str_const(sub_tag, elmi_sub_info_elem_tag, "unknown"));

    proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_info_elem, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_info_elem_len, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    switch (sub_tag) {
        case SUB_TAG_UNI_ID:
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_uni_id, tvb, offset, len, ENC_ASCII|ENC_NA);
            offset += len;
            break;
        case SUB_TAG_EVC_PRM:
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_evc_type, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case SUB_TAG_EVC_ID:
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_evc_id, tvb, offset, len, ENC_ASCII|ENC_NA);
            offset += len;
            break;
        case SUB_TAG_EVC_MAP:
            while(offset < (offset_start + len + 2)) {
                proto_tree_add_item(sub_info_elem_tree, hf_elmi_ce_vlan_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            break;
        case SUB_TAG_BW_PRO:
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_info_color_mode_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_info_coupling_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_info_per_cos_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_cir_magnitude, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_cir_multiplier, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_cbs_magnitude, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_cbs_multiplier, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_eir_magnitude, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_eir_multiplier, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_ebs_magnitude, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_ebs_multiplier, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_user_prio_0, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_user_prio_1, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_user_prio_2, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_user_prio_3, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_user_prio_4, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_user_prio_5, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_user_prio_6, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_info_elem_tree, hf_elmi_sub_user_prio_7, tvb, offset, 1, ENC_BIG_ENDIAN);

            offset ++;
            break;
        default:
            offset += len;
            break;
    }

    proto_item_set_len(tree_pi, offset-offset_start);
    return offset-offset_start;

}

static gint
dissect_elmi_info_elem(
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    gint        offset_start;
    guint8      tag, len, ret;
    proto_item *tree_pi;
    proto_tree *info_elem_tree;

    offset_start = offset;

    tag = tvb_get_guint8(tvb, offset);
    if (tag==0)
        return -1;

    info_elem_tree = proto_tree_add_subtree_format(
            tree, tvb, offset, -1, ett_elmi_info_elem, &tree_pi,
            "Information element: %s", val_to_str_const(tag, elmi_info_elem_tag, "unknown"));

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
            proto_tree_add_item(info_elem_tree, hf_elmi_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(info_elem_tree, hf_elmi_dat_inst,
                    tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            break;
        case TAG_UNI_STATUS:
            proto_tree_add_item(info_elem_tree, hf_elmi_uni_status, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            while(offset < (offset_start + len + 2)) {
                ret = dissect_elmi_sub_info_elem(tvb, offset, info_elem_tree);
                if (ret<=0)
                    break;
                offset += ret;
            }
            break;
        case TAG_EVC_STATUS:
            proto_tree_add_item(info_elem_tree, hf_elmi_evc_refid, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            proto_tree_add_item(info_elem_tree, hf_elmi_evc_status, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            while(offset < (offset_start + len + 2)) {
                ret = dissect_elmi_sub_info_elem(tvb, offset, info_elem_tree);
                if (ret<=0)
                    break;
                offset += ret;
            }
            break;
        case TAG_VLAN_EVC:
            proto_tree_add_item(info_elem_tree, hf_elmi_evc_refid, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            proto_tree_add_item(info_elem_tree, hf_last_ie, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(info_elem_tree, hf_map_seq, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            proto_tree_add_item(info_elem_tree, hf_priority, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(info_elem_tree, hf_default_evc, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            while(offset < (offset_start + len + 2)) {
                ret = dissect_elmi_sub_info_elem(tvb, offset, info_elem_tree);
                if (ret<=0)
                    break;
                offset += ret;
            }
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
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_reserved,
            { "Reserved", "elmi.reserved", FT_UINT8, BASE_HEX,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_uni_status,
            { "CE-VLAN ID/EVC Map Type", "elmi.map_type", FT_UINT8, BASE_HEX,
                VALS(elmi_vlan_id_evc_map_type), 0, NULL, HFILL } },
        { &hf_elmi_evc_refid,
            { "EVC Reference Id", "elmi.evc.refid", FT_UINT16, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_evc_status,
            { "EVC Status Type", "elmi.evc.status", FT_UINT8, BASE_HEX,
                VALS(elmi_evc_status_type), 0x7, NULL, HFILL } },
        { &hf_last_ie,
            { "Last Information Element", "elmi.map.last_ie", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), 0x40, NULL, HFILL } },
        { &hf_map_seq,
            { "CE-VLAN ID/EVC Map Sequence", "elmi.map.seq", FT_UINT8, BASE_DEC,
                NULL, 0x3F, NULL, HFILL } },
        { &hf_priority,
            { "Priority Tagged", "elmi.map.priority", FT_BOOLEAN, 8,
                TFS(&tfs_yes_no), 0x2, NULL, HFILL } },
        { &hf_default_evc,
            { "Default EVC", "elmi.map.evc", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), 0x1, NULL, HFILL } },
        { &hf_elmi_sub_info_elem,
            { "Sub-Info Element :" , "elmi.sub_info.tag", FT_UINT8, BASE_HEX,
                VALS(elmi_sub_info_elem_tag), 0, NULL, HFILL } },
        { &hf_elmi_sub_info_elem_len,
            { "Sub-Info Length", "elmi.sub_info.len", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_uni_id,
            { "UNI Identifier", "elmi.sub_info.uni_id", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_evc_type,
            { "EVC Type", "elmi.sub_info.evc_type", FT_UINT8, BASE_DEC,
                VALS(elmi_evc_type), 0x7, NULL, HFILL } },
        { &hf_elmi_evc_id,
            { "EVC Identifier", "elmi.sub_info.evc_id", FT_STRING, BASE_NONE,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_ce_vlan_id,
            { "CE-VLAN ID", "elmi.sub_info.vlan_id", FT_UINT16, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_sub_info_color_mode_flag,
            { "Color Mode Flag", "elmi.sub_info.color_mode_flag", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), 0x4, NULL, HFILL } },
        { &hf_elmi_sub_info_coupling_flag,
            { "Coupling Flag", "elmi.sub_info.coupling_flag", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), 0x2, NULL, HFILL } },
        { &hf_elmi_sub_info_per_cos_bit,
            { "Per CoS bit values", "elmi.sub_info.per_cos_bit", FT_BOOLEAN, 8,
                TFS(&tfs_used_notused), 0x1, NULL, HFILL } },
        { &hf_elmi_sub_cir_magnitude,
            { "CIR Magnitude", "elmi.sub_info.cir_mag", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_sub_cir_multiplier,
            { "CIR Multiplier", "elmi.sub_info.cir_mult", FT_UINT16, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_sub_cbs_magnitude,
            { "CBS Magnitude", "elmi.sub_info.cbs_mag", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_sub_cbs_multiplier,
            { "CBS Multiplier", "elmi.sub_info.cbs_mult", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_sub_eir_magnitude,
            { "EIR Magnitude", "elmi.sub_info.eir_mag", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_sub_eir_multiplier,
            { "EIR Multiplier", "elmi.sub_info.eir_mult", FT_UINT16, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_sub_ebs_magnitude,
            { "EBS Magnitude", "elmi.sub_info.ebs_mag", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_sub_ebs_multiplier,
            { "EBS Multiplier", "elmi.sub_info.ebs_mult", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL } },
        { &hf_elmi_sub_user_prio_0,
            { "User Priority 0", "elmi.sub_info.bw_prio0", FT_BOOLEAN, 8,
                TFS(&tfs_applicable_not_applicable), 0x1, NULL, HFILL } },
        { &hf_elmi_sub_user_prio_1,
            { "User Priority 1", "elmi.sub_info.bw_prio1", FT_BOOLEAN, 8,
                TFS(&tfs_applicable_not_applicable), 0x2, NULL, HFILL } },
        { &hf_elmi_sub_user_prio_2,
            { "User Priority 2", "elmi.sub_info.bw_prio2", FT_BOOLEAN, 8,
                TFS(&tfs_applicable_not_applicable), 0x4, NULL, HFILL } },
        { &hf_elmi_sub_user_prio_3,
            { "User Priority 3", "elmi.sub_info.bw_prio3", FT_BOOLEAN, 8,
                TFS(&tfs_applicable_not_applicable), 0x8, NULL, HFILL } },
        { &hf_elmi_sub_user_prio_4,
            { "User Priority 4", "elmi.sub_info.bw_prio4", FT_BOOLEAN, 8,
                TFS(&tfs_applicable_not_applicable), 0x10, NULL, HFILL } },
        { &hf_elmi_sub_user_prio_5,
            { "User Priority 5", "elmi.sub_info.bw_prio5", FT_BOOLEAN, 8,
                TFS(&tfs_applicable_not_applicable), 0x20, NULL, HFILL } },
        { &hf_elmi_sub_user_prio_6,
            { "User Priority 6", "elmi.sub_info.bw_prio6", FT_BOOLEAN, 8,
                TFS(&tfs_applicable_not_applicable), 0x40, NULL, HFILL } },
        { &hf_elmi_sub_user_prio_7,
            { "User Priority 7", "elmi.sub_info.bw_prio7", FT_BOOLEAN, 8,
                TFS(&tfs_applicable_not_applicable), 0x80, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_elmi,
        &ett_elmi_info_elem,
        &ett_elmi_sub_info_elem
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

    elmi_handle = create_dissector_handle(dissect_elmi, proto_elmi);
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
