/* packet-dvb-ait.c
 * Routines for DVB Application Information Table (AIT) dissection
 * Copyright 2012-2013, Martin Kaiser <martin@kaiser.cx>
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

void proto_register_dvb_ait(void);
void proto_reg_handoff_dvb_ait(void);

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
static int hf_dvb_ait_descr_app_prof_len = -1;
static int hf_dvb_ait_descr_app_prof = -1;
static int hf_dvb_ait_descr_app_ver = -1;
static int hf_dvb_ait_descr_app_svc_bound = -1;
static int hf_dvb_ait_descr_app_vis = -1;
static int hf_dvb_ait_descr_app_prio = -1;
static int hf_dvb_ait_descr_app_trpt_proto_label = -1;
static int hf_dvb_ait_descr_app_name_lang = -1;
static int hf_dvb_ait_descr_app_name_name = -1;
static int hf_dvb_ait_descr_trpt_proto_id = -1;
static int hf_dvb_ait_descr_trpt_proto_label = -1;
static int hf_dvb_ait_descr_trpt_sel_remote = -1;
static int hf_dvb_ait_descr_trpt_sel_onid = -1;
static int hf_dvb_ait_descr_trpt_sel_tsid = -1;
static int hf_dvb_ait_descr_trpt_sel_svcid = -1;
static int hf_dvb_ait_descr_trpt_sel_comp = -1;
static int hf_dvb_ait_descr_trpt_sel_url_base = -1;
static int hf_dvb_ait_descr_trpt_sel_url_ext_cnt = -1;
static int hf_dvb_ait_descr_trpt_sel_url_ext = -1;
static int hf_dvb_ait_descr_trpt_sel_bytes = -1;
static int hf_dvb_ait_descr_sal_init_path = -1;
static int hf_dvb_ait_app_loop_len = -1;
static int hf_dvb_ait_org_id = -1;
static int hf_dvb_ait_app_id = -1;
static int hf_dvb_ait_app_ctrl_code = -1;

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

#define AIT_DESCR_APP          0x00
#define AIT_DESCR_APP_NAME     0x01
#define AIT_DESCR_TRPT_PROTO   0x02
#define AIT_DESCR_EXT_APP_AUTH 0x05
#define AIT_DESCR_APP_REC      0x06
#define AIT_DESCR_APP_ICO      0x0B
#define AIT_DESCR_APP_STOR     0x10
#define AIT_DESCR_GRA_CONST    0x14
#define AIT_DESCR_SIM_APP_LOC  0x15
#define AIT_DESCR_SIM_APP_BND  0x17
#define AIT_DESCR_APP_SIG      0x6F

static const value_string ait_descr_tag[] = {
    { AIT_DESCR_APP,          "Application descriptor" },
    { AIT_DESCR_APP_NAME,     "Application name descriptor" },
    { AIT_DESCR_TRPT_PROTO,   "Transport protocol descriptor" },
    { AIT_DESCR_EXT_APP_AUTH, "External application authorization descriptor" },
    { AIT_DESCR_APP_REC,      "Application recording descriptor" },
    { AIT_DESCR_APP_ICO,      "Application icons descriptor" },
    { AIT_DESCR_APP_STOR,     "Application storage descriptor" },
    { AIT_DESCR_GRA_CONST,    "Graphics constraints descriptor" },
    { AIT_DESCR_SIM_APP_LOC,  "Simple application location descriptor" },
    { AIT_DESCR_SIM_APP_BND,  "Simple application boundary descriptor" },
    { AIT_DESCR_APP_SIG,      "Application signalling descriptor" },
    { 0, NULL }
};

#define TRPT_OBJ_CAROUSEL 0x0001
#define TRPT_HTTP         0x0003

static const value_string trpt_proto_id[] = {
    { TRPT_OBJ_CAROUSEL, "Object Carousel" },
    { TRPT_HTTP,         "Transport via HTTP" },
    { 0, NULL }
};

static const value_string app_vis[] = {
    { 0x0, "not visible" },
    { 0x1, "not visible to users, only to applications" },
    { 0x3, "fully visible" },
    { 0, NULL }
};


/* dissect the body of an application_descriptor
   offset points to the start of the body,
   i.e. to the first byte after the length field */
static gint
dissect_dvb_ait_app_desc_body(tvbuff_t *tvb, guint offset,
        guint8 body_len, packet_info *pinfo _U_, proto_tree *tree)
{
    guint   offset_start, offset_app_prof_start;
    guint8  app_prof_len;
    guint8  ver_maj, ver_min, ver_mic;

    offset_start = offset;

    app_prof_len = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_dvb_ait_descr_app_prof_len,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    offset_app_prof_start = offset;
    while (offset-offset_app_prof_start < app_prof_len) {
        proto_tree_add_item(tree, hf_dvb_ait_descr_app_prof,
                tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        ver_maj = tvb_get_guint8(tvb, offset);
        ver_min = tvb_get_guint8(tvb, offset+1);
        ver_mic = tvb_get_guint8(tvb, offset+2);
        proto_tree_add_uint_format(tree, hf_dvb_ait_descr_app_ver,
                tvb, offset, 3, ver_maj<<16|ver_min<<8|ver_mic,
                "Version %d.%d.%d", ver_maj, ver_min, ver_mic);
        offset += 3;
    }
    proto_tree_add_item(tree, hf_dvb_ait_descr_app_svc_bound,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_dvb_ait_descr_app_vis,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_dvb_ait_descr_app_prio,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    while (offset-offset_start < body_len) {
        proto_tree_add_item(tree, hf_dvb_ait_descr_app_trpt_proto_label,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }
    return (gint)(offset-offset_start);
}


static gint
dissect_dvb_ait_app_name_desc_body(tvbuff_t *tvb, guint offset,
        guint8 body_len, packet_info *pinfo _U_, proto_tree *tree)
{
    guint   offset_start;
    guint8  len;

    offset_start = offset;
    while (offset-offset_start < body_len) {
        proto_tree_add_item(tree, hf_dvb_ait_descr_app_name_lang,
              tvb, offset, 3, ENC_ASCII|ENC_NA);
        offset += 3;
        len = tvb_get_guint8(tvb, offset);
          /* FT_UINT_STRING with 1 leading len byte */
          proto_tree_add_item(tree, hf_dvb_ait_descr_app_name_name,
              tvb, offset, 1, ENC_ASCII|ENC_NA);
          offset += 1+len;
    }

    return (gint)(offset-offset_start);
}


static gint
dissect_dvb_ait_trpt_proto_desc_body(tvbuff_t *tvb, guint offset,
        guint8 body_len, packet_info *pinfo _U_, proto_tree *tree)
{
    guint     offset_start;
    guint16   proto_id;
    gboolean  remote_connection;

    offset_start = offset;

    proto_id = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_proto_id,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_proto_label,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    if (offset-offset_start < body_len) {
        if (proto_id == TRPT_OBJ_CAROUSEL) {
            remote_connection = ((tvb_get_guint8(tvb, offset) & 0x80) == 0x80);
            proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_sel_remote,
                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if (remote_connection) {
                proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_sel_onid,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_sel_tsid,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_sel_svcid,
                        tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }
            proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_sel_comp,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }
        else if (proto_id == TRPT_HTTP) {
            guint8 url_base_len, url_ext_cnt, url_ext_len, i;

            url_base_len = tvb_get_guint8(tvb, offset);
            /* FT_UINT_STRING with one leading length byte */
            proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_sel_url_base,
                tvb, offset, 1, ENC_ASCII|ENC_NA);
            offset += 1+url_base_len;

            url_ext_cnt = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_sel_url_ext_cnt,
                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            for (i=0; i<url_ext_cnt; i++) {
                url_ext_len = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_sel_url_ext,
                        tvb, offset, 1, ENC_ASCII|ENC_NA);
                offset += 1+url_ext_len;
            }
        }
        else {
            proto_tree_add_item(tree, hf_dvb_ait_descr_trpt_sel_bytes,
                tvb, offset, offset_start+body_len-offset, ENC_NA);
            offset = offset_start+body_len;
        }
    }

    return (gint)(offset-offset_start);
}


static gint
dissect_dvb_ait_descriptor(tvbuff_t *tvb, guint offset,
        packet_info *pinfo, proto_tree *tree)
{
    gint        ret;
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
    if (try_val_to_str(tag, ait_descr_tag)) {

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

        switch (tag) {
            case AIT_DESCR_APP:
                ret = dissect_dvb_ait_app_desc_body(tvb, offset, len,
                        pinfo, descr_tree);
                if (ret>0)
                    offset += ret;
                break;
            case AIT_DESCR_APP_NAME:
                ret = dissect_dvb_ait_app_name_desc_body(tvb, offset, len,
                        pinfo, descr_tree);
                if (ret>0)
                    offset += ret;
                break;
            case AIT_DESCR_TRPT_PROTO:
                ret = dissect_dvb_ait_trpt_proto_desc_body(tvb, offset, len,
                        pinfo, descr_tree);
                if (ret>0)
                    offset += ret;
                break;
            case AIT_DESCR_SIM_APP_LOC:
                proto_tree_add_item(descr_tree,
                        hf_dvb_ait_descr_sal_init_path,
                        tvb, offset, len, ENC_ASCII|ENC_NA);
                offset += len;
                break;
            default:
                proto_tree_add_item(descr_tree, hf_dvb_ait_descr_data,
                        tvb, offset, len, ENC_NA);
                offset += len;
                break;
        }

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
        { &hf_dvb_ait_descr_app_prof_len,
            { "Application profiles length", "dvb_ait.descr.app.prof_len",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_app_prof,
            { "Application profile", "dvb_ait.descr.app.prof",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        /* version is major|minor|micro */
        { &hf_dvb_ait_descr_app_ver,
            { "Version", "dvb_ait.descr.app.ver",
                FT_UINT24, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_app_svc_bound,
            { "Service-bound flag", "dvb_ait.descr.app.svc_bound_flag",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL } },
        { &hf_dvb_ait_descr_app_vis,
            { "Visibility", "dvb_ait.descr.app.visibility",
                FT_UINT8, BASE_HEX, VALS(app_vis), 0x60, NULL, HFILL } },
        { &hf_dvb_ait_descr_app_prio,
            { "Application priority", "dvb_ait.descr.app.prio",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_app_trpt_proto_label,
            { "Transport protocol label", "dvb_ait.descr.app.trpt_proto_label",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_app_name_lang,
          { "ISO 639 language code", "dvb_ait.descr.app_name.lang",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_app_name_name,
          { "Application name", "dvb_ait.descr.app_name.name",
            FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_proto_id,
            { "Protocol ID", "dvb_ait.descr.trpt_proto.id",
                FT_UINT16, BASE_HEX, VALS(trpt_proto_id), 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_proto_label,
            { "Transport protocol label", "dvb_ait.descr.trpt_proto.label",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_sel_remote,
            { "Remote connection", "dvb_ait.descr.trpt_proto.remote",
                FT_UINT8, BASE_HEX, NULL, 0x80, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_sel_onid,
            { "Original network ID", "dvb_ait.descr.trpt_proto.onid",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_sel_tsid,
            { "Transport stream ID", "dvb_ait.descr.trpt_proto.tsid",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_sel_svcid,
            { "Service ID", "dvb_ait.descr.trpt_proto.svcid",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_sel_comp,
            { "Component tag", "dvb_ait.descr.trpt_proto.comp_tag",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_sel_url_base,
            { "URL base", "dvb_ait.descr.trpt_proto.url_base",
            FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_sel_url_ext_cnt,
            { "URL extension count", "dvb_ait.descr.trpt_proto.url_ext_cnt",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_sel_url_ext,
            { "URL extension", "dvb_ait.descr.trpt_proto.url_ext",
            FT_UINT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_trpt_sel_bytes,
            { "Selector bytes", "dvb_ait.descr.trpt_proto.selector_bytes",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL } },
        { &hf_dvb_ait_descr_sal_init_path,
            { "Initial path", "dvb_ait.descr.sim_app_loc.initial_path",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL } },
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
