/* packet-dvb-nit.c
 * Routines for DVB (ETSI EN 300 468) Network Information Table (NIT) dissection
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
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
#include "packet-mpeg-sect.h"
#include "packet-mpeg-descriptor.h"

void proto_register_dvb_nit(void);
void proto_reg_handoff_dvb_nit(void);

static int proto_dvb_nit = -1;
static int hf_dvb_nit_network_id = -1;
static int hf_dvb_nit_reserved1 = -1;
static int hf_dvb_nit_version_number = -1;
static int hf_dvb_nit_current_next_indicator = -1;
static int hf_dvb_nit_section_number = -1;
static int hf_dvb_nit_last_section_number = -1;
static int hf_dvb_nit_reserved2 = -1;

static int hf_dvb_nit_network_descriptors_length = -1;
static int hf_dvb_nit_reserved3 = -1;
static int hf_dvb_nit_transport_stream_loop_length = -1;

static int hf_dvb_nit_transport_stream_id = -1;
static int hf_dvb_nit_original_network_id = -1;
static int hf_dvb_nit_reserved4 = -1;
static int hf_dvb_nit_transport_descriptors_length = -1;

static gint ett_dvb_nit = -1;
static gint ett_dvb_nit_ts = -1;


#define DVB_NIT_RESERVED1_MASK                            0xC0
#define DVB_NIT_VERSION_NUMBER_MASK                       0x3E
#define DVB_NIT_CURRENT_NEXT_INDICATOR_MASK               0x01
#define DVB_NIT_RESERVED2_MASK                          0xF000
#define DVB_NIT_NETWORK_DESCRIPTORS_LENGTH_MASK         0x0FFF
#define DVB_NIT_RESERVED3_MASK                          0xF000
#define DVB_NIT_TRANSPORT_STREAM_LOOP_LENGTH_MASK       0x0FFF
#define DVB_NIT_RESERVED4_MASK                          0xF000
#define DVB_NIT_TRANSPORT_DESCRIPTORS_LENGTH_MASK       0x0FFF

static const value_string dvb_nit_cur_next_vals[] = {
    { 0, "Not yet applicable" },
    { 1, "Currently applicable" },

    { 0, NULL }
};


static int
dissect_dvb_nit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

    guint       offset = 0;
    guint       ts_desc_len, desc_loop_len, ts_end;

    guint16     tsid;

    proto_item *ti;
    proto_tree *dvb_nit_tree;
    proto_tree *dvb_nit_ts_tree;

    col_set_str(pinfo->cinfo, COL_INFO, "Network Information Table (NIT)");

    ti = proto_tree_add_item(tree, proto_dvb_nit, tvb, offset, -1, ENC_NA);
    dvb_nit_tree = proto_item_add_subtree(ti, ett_dvb_nit);

    offset += packet_mpeg_sect_header(tvb, offset, dvb_nit_tree, NULL, NULL);

    proto_tree_add_item(dvb_nit_tree, hf_dvb_nit_network_id,                 tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(dvb_nit_tree, hf_dvb_nit_reserved1,                  tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_nit_tree, hf_dvb_nit_version_number,             tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_nit_tree, hf_dvb_nit_current_next_indicator,     tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(dvb_nit_tree, hf_dvb_nit_section_number,             tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(dvb_nit_tree, hf_dvb_nit_last_section_number,        tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(dvb_nit_tree, hf_dvb_nit_reserved2,                  tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_nit_tree, hf_dvb_nit_network_descriptors_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    desc_loop_len = tvb_get_ntohs(tvb, offset) & DVB_NIT_NETWORK_DESCRIPTORS_LENGTH_MASK;
    offset += 2;

    offset += proto_mpeg_descriptor_loop_dissect(tvb, offset, desc_loop_len, dvb_nit_tree);

    proto_tree_add_item(dvb_nit_tree, hf_dvb_nit_reserved3,                    tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_nit_tree, hf_dvb_nit_transport_stream_loop_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    ts_end = offset + (tvb_get_ntohs(tvb, offset) & DVB_NIT_TRANSPORT_STREAM_LOOP_LENGTH_MASK);
    offset += 2;

    while (offset < ts_end) {
        tsid = tvb_get_ntohs(tvb, offset);
        ts_desc_len = 3 + (tvb_get_ntohs(tvb, offset + 4) & DVB_NIT_TRANSPORT_DESCRIPTORS_LENGTH_MASK);

        dvb_nit_ts_tree = proto_tree_add_subtree_format(dvb_nit_tree, tvb, offset, ts_desc_len,
                               ett_dvb_nit_ts, NULL, "Stream ID=0x%04hx", tsid);

        proto_tree_add_item(dvb_nit_ts_tree, hf_dvb_nit_transport_stream_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(dvb_nit_ts_tree, hf_dvb_nit_original_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(dvb_nit_ts_tree, hf_dvb_nit_reserved4,                    tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(dvb_nit_ts_tree, hf_dvb_nit_transport_descriptors_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        desc_loop_len = tvb_get_ntohs(tvb, offset) & DVB_NIT_TRANSPORT_DESCRIPTORS_LENGTH_MASK;
        offset += 2;

        offset += proto_mpeg_descriptor_loop_dissect(tvb, offset, desc_loop_len, dvb_nit_ts_tree);
    }

    offset += packet_mpeg_sect_crc(tvb, pinfo, dvb_nit_tree, 0, offset);

    proto_item_set_len(ti, offset);
    return offset;
}


void
proto_register_dvb_nit(void)
{

    static hf_register_info hf[] = {

        { &hf_dvb_nit_network_id, {
            "Network ID", "dvb_nit.sid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_nit_reserved1, {
            "Reserved", "dvb_nit.reserved1",
            FT_UINT8, BASE_HEX, NULL, DVB_NIT_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_dvb_nit_version_number, {
            "Version Number", "dvb_nit.version",
            FT_UINT8, BASE_HEX, NULL, DVB_NIT_VERSION_NUMBER_MASK, NULL, HFILL
        } },

        { &hf_dvb_nit_current_next_indicator, {
            "Current/Next Indicator", "dvb_nit.cur_next_ind",
            FT_UINT8, BASE_DEC, VALS(dvb_nit_cur_next_vals), DVB_NIT_CURRENT_NEXT_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_dvb_nit_section_number, {
            "Section Number", "dvb_nit.sect_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_nit_last_section_number, {
            "Last Section Number", "dvb_nit.last_sect_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_nit_reserved2, {
            "Reserved", "dvb_nit.reserved2",
            FT_UINT16, BASE_HEX, NULL, DVB_NIT_RESERVED2_MASK, NULL, HFILL
        } },

        { &hf_dvb_nit_network_descriptors_length, {
            "Network Descriptors Length", "dvb_nit.network_desc_len",
            FT_UINT16, BASE_DEC, NULL, DVB_NIT_NETWORK_DESCRIPTORS_LENGTH_MASK, NULL, HFILL
        } },

        { &hf_dvb_nit_reserved3, {
            "Reserved", "dvb_nit.reserved3",
            FT_UINT16, BASE_HEX, NULL, DVB_NIT_RESERVED3_MASK, NULL, HFILL
        } },

        { &hf_dvb_nit_transport_stream_loop_length, {
            "Transport Stream Loop Length", "dvb_nit.ts_loop_len",
            FT_UINT16, BASE_DEC, NULL, DVB_NIT_TRANSPORT_STREAM_LOOP_LENGTH_MASK, NULL, HFILL
        } },

        { &hf_dvb_nit_transport_stream_id, {
            "Transport Stream ID", "dvb_nit.ts.id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_nit_original_network_id, {
            "Original Network ID", "dvb_nit.ts.original_network_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_nit_reserved4, {
            "Reserved", "dvb_nit.ts.reserved",
            FT_UINT16, BASE_HEX, NULL, DVB_NIT_RESERVED4_MASK, NULL, HFILL
        } },

        { &hf_dvb_nit_transport_descriptors_length, {
            "Transport Descriptors Length", "dvb_nit.ts.desc_len",
            FT_UINT16, BASE_DEC, NULL, DVB_NIT_TRANSPORT_DESCRIPTORS_LENGTH_MASK, NULL, HFILL
        } },

    };

    static gint *ett[] = {
        &ett_dvb_nit,
        &ett_dvb_nit_ts
    };

    proto_dvb_nit = proto_register_protocol("DVB Network Information Table", "DVB NIT", "dvb_nit");

    proto_register_field_array(proto_dvb_nit, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("dvb_nit", dissect_dvb_nit, proto_dvb_nit);
}


void proto_reg_handoff_dvb_nit(void)
{
    dissector_handle_t dvb_nit_handle;

    dvb_nit_handle = find_dissector("dvb_nit");

    dissector_add_uint("mpeg_sect.tid", DVB_NIT_TID, dvb_nit_handle);
    dissector_add_uint("mpeg_sect.tid", DVB_NIT_TID_OTHER, dvb_nit_handle);
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
