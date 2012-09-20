/* packet-dvb-ait.c
 * Routines for DVB Application Information Table (AIT) dissection
 * Copyright 2012, Martin Kaiser <martin@kaiser.cx>
 *
 * $Id$
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

/* This dissector processes a DVB Application Information Table (AIT) as
 * defined in ETSI TS 102 809. */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include "packet-mpeg-sect.h"
#include "packet-mpeg-descriptor.h"

static int proto_dvb_ait = -1;

static gint ett_dvb_ait       = -1;
static gint ett_dvb_ait_descr = -1;
static gint ett_dvb_ait_app   = -1;

static int hf_dvb_ait_test_app_flag = -1;
static int hf_dvb_ait_app_type = -1;
static int hf_dvb_ait_version_number = -1;
static int hf_dvb_ait_current_next_indicator = -1;
static int hf_dvb_ait_section_number = -1;
static int hf_dvb_ait_last_section_number = -1;
static int hf_dvb_ait_descr_loop_len = -1;
static int hf_dvb_ait_descr_tag = -1;
static int hf_dvb_ait_descr_len = -1;
static int hf_dvb_ait_descr_data = -1;
static int hf_dvb_ait_app_loop_len = -1;
static int hf_dvb_ait_org_id = -1;
static int hf_dvb_ait_app_id = -1;
static int hf_dvb_ait_app_ctrl_code = -1;

#define DVB_AIT_TID 0x74

static const value_string app_ctrl_code[] = {
    { 0x01,  "Autostart" },
    { 0x02,  "Present" },
    { 0x03,  "Destroy" },
    { 0x04,  "Kill" },
    { 0x05,  "Prefetch" },
    { 0x06,  "Remote" },
    { 0x07,  "Disabled" },
    { 0x08,  "Playback autostart" },
    { 0, NULL }
};

/* tags of the descriptors defined in ETSI TS 102 809
   some of these tags are conflicting with MPEG2 or DVB-SI definitions,
    therefore these descriptors aren't supported by packet-mpeg-descriptor.c */
static const value_string ait_descr_tag[] = {
    { 0x00, "Application descriptor" },
    { 0x01, "Application name descriptor" },
    { 0x02, "Transport protocol descriptor" },
    { 0x05, "External application authorization descriptor" },
    { 0x06, "Application recording descriptor" },
    { 0x0B, "Application icons descriptor" },
    { 0x10, "Application storage descriptor" },
    { 0x14, "Graphics constraints descriptor" },
    { 0x15, "Simple application location descriptor" },
    { 0x17, "Simple application boundary descriptor" },
    { 0x6F, "Application signalling descriptor" },
    { 0, NULL }
};

static gint
dissect_dvb_ait_descriptor(tvbuff_t *tvb, guint offset,
        packet_info *pinfo _U_, proto_tree *tree)
{
    gint        ret = 0;
    guint       offset_start;
    guint8      tag, len;
    proto_item *descr_tree_ti = NULL;
    proto_tree *descr_tree = NULL;

    tag = tvb_get_guint8(tvb, offset);
    len = tvb_get_guint8(tvb, offset+1);

    /* if the descriptor is a special one that's defined in ETSI TS 102 809,
        we dissect it ourselves
       otherwise, we assume it's a generic DVB-SI descriptor and pass it
        on to packet-mpeg-descriptor */
    if (match_strval(tag, ait_descr_tag)) {

        offset_start = offset;
        descr_tree_ti = proto_tree_add_text(tree, tvb, offset_start, len+2,
                "Descriptor Tag=0x%02x", tag);
        descr_tree = proto_item_add_subtree(descr_tree_ti, ett_dvb_ait_descr);

        proto_tree_add_item(descr_tree, hf_dvb_ait_descr_tag,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(descr_tree, hf_dvb_ait_descr_len,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(descr_tree, hf_dvb_ait_descr_data,
                tvb, offset, len, ENC_NA);
        offset += len;

        ret = (gint)(offset-offset_start);
    }
    else
        ret = (gint)proto_mpeg_descriptor_dissect(tvb, offset, tree);

    return ret;
}

 
static int
dissect_dvb_ait(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        offset=0;
    proto_item *ait_tree_ti = NULL, *app_tree_ti = NULL;
    proto_tree *ait_tree = NULL, *ait_app_tree = NULL;
    gint        offset_loop_start, offset_inner_loop_start, offset_app_start;
    guint16     descr_loop_len, app_loop_len;
    gint        ret;
    guint32     org_id;
    guint16     app_id;
    
    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_INFO, "Application Information Table (AIT)");

    if (tree) {
        ait_tree_ti = proto_tree_add_protocol_format(tree, proto_dvb_ait,
                tvb, 0, -1, "Application Information Table (AIT)");
        ait_tree = proto_item_add_subtree(ait_tree_ti, ett_dvb_ait);
    }

    offset += packet_mpeg_sect_header(tvb, offset, ait_tree, NULL, NULL);

    proto_tree_add_item(ait_tree, hf_dvb_ait_test_app_flag,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ait_tree, hf_dvb_ait_app_type,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    /* no hf for reserved bits */
    proto_tree_add_item(ait_tree, hf_dvb_ait_version_number,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(ait_tree, hf_dvb_ait_current_next_indicator,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ait_tree, hf_dvb_ait_section_number,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(ait_tree, hf_dvb_ait_last_section_number,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    descr_loop_len = tvb_get_ntohs(tvb, offset) & 0x0FFF;
    proto_tree_add_item(ait_tree, hf_dvb_ait_descr_loop_len,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    offset_loop_start = offset;
    while (offset-offset_loop_start < descr_loop_len) {
        ret = dissect_dvb_ait_descriptor(tvb, offset, pinfo, ait_tree);
        if (ret<=0)
            break;
        offset += ret;
    }

    app_loop_len = tvb_get_ntohs(tvb, offset) & 0x0FFF;
    proto_tree_add_item(ait_tree, hf_dvb_ait_app_loop_len,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    offset_loop_start = offset;
    while (offset-offset_loop_start < app_loop_len) {
        offset_app_start = offset;
        org_id = tvb_get_ntohl(tvb, offset);
        app_id = tvb_get_ntohs(tvb, offset+4);
        app_tree_ti = proto_tree_add_text(ait_tree, tvb, offset, -1,
                "Application: Org 0x%x, App 0x%x", org_id, app_id);
        ait_app_tree = proto_item_add_subtree(app_tree_ti, ett_dvb_ait_app);

        proto_tree_add_item(ait_app_tree, hf_dvb_ait_org_id,
            tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(ait_app_tree, hf_dvb_ait_app_id,
            tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_tree_add_item(ait_app_tree, hf_dvb_ait_app_ctrl_code,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        descr_loop_len = tvb_get_ntohs(tvb, offset) & 0x0FFF;
        proto_tree_add_item(ait_app_tree, hf_dvb_ait_descr_loop_len,
                tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        offset_inner_loop_start = offset;
        while (offset-offset_inner_loop_start < descr_loop_len) {
            ret = dissect_dvb_ait_descriptor(tvb, offset, pinfo, ait_app_tree);
            if (ret<=0)
                break;
            offset += ret;
        }
        proto_item_set_len(app_tree_ti, offset-offset_app_start);
    }

    offset += packet_mpeg_sect_crc(tvb, pinfo, ait_tree, 0, offset);

    proto_item_set_len(ait_tree_ti, offset);

    return offset;
}

void
proto_register_dvb_ait(void)
{
    static gint *ett[] = {
        &ett_dvb_ait,
        &ett_dvb_ait_descr,
        &ett_dvb_ait_app
    };

    static hf_register_info hf[] = {
        { &hf_dvb_ait_test_app_flag,
          { "Test application flag", "dvb_ait.test_app_flag",
            FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL } },
        { &hf_dvb_ait_app_type,
          { "Application type", "dvb_ait.app_type",
            FT_UINT16, BASE_HEX, NULL, 0x7FFF, NULL, HFILL } },
        { &hf_dvb_ait_version_number,
            { "Version Number", "dvb_ait.version",
                FT_UINT8, BASE_HEX, NULL, 0x3E, NULL, HFILL } },
        { &hf_dvb_ait_current_next_indicator,
            { "Current/Next Indicator", "dvb_ait.cur_next_ind",
                FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL } },
        { &hf_dvb_ait_section_number,
            { "Section Number", "dvb_ait.sect_num",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_last_section_number,
            { "Last Section Number", "dvb_ait.last_sect_num",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_loop_len,
          { "Descriptor loop length", "dvb_ait.descr_loop_len",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL } },
        { &hf_dvb_ait_descr_tag,
            { "Descriptor Tag", "dvb_ait.descr.tag",
                FT_UINT8, BASE_HEX, VALS(ait_descr_tag), 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_len,
            { "Descriptor Length", "dvb_ait.descr.len",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_data,
            { "Descriptor Data", "dvb_ait.descr.data",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_app_loop_len,
          { "Application loop length", "dvb_ait.app_loop_len",
            FT_UINT16, BASE_DEC, NULL, 0x0FFF, NULL, HFILL } },
        { &hf_dvb_ait_org_id,
            { "Organisation ID", "dvb_ait.app.org_id",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_app_id,
            { "Application ID", "dvb_ait.app.app_id",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_app_ctrl_code,
            { "Application control code", "dvb_ait.app.ctrl_code",
                FT_UINT8, BASE_HEX, VALS(app_ctrl_code), 0, NULL, HFILL } }
    };

    proto_dvb_ait = proto_register_protocol(
            "DVB Application Information Table", "DVB AIT", "dvb_ait");

    proto_register_field_array(proto_dvb_ait, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_dvb_ait(void)
{
    dissector_handle_t dvb_ait_handle;

    dvb_ait_handle = new_create_dissector_handle(dissect_dvb_ait, proto_dvb_ait);
    dissector_add_uint("mpeg_sect.tid", DVB_AIT_TID, dvb_ait_handle);
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
