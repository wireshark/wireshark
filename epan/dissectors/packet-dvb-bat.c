/* packet-dvb-bat.c
 * Routines for DVB (ETSI EN 300 468) Bouquet Association Table (BAT) dissection
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

void proto_register_dvb_bat(void);
void proto_reg_handoff_dvb_bat(void);

static int proto_dvb_bat = -1;
static int hf_dvb_bat_bouquet_id = -1;
static int hf_dvb_bat_reserved1 = -1;
static int hf_dvb_bat_version_number = -1;
static int hf_dvb_bat_current_next_indicator = -1;
static int hf_dvb_bat_section_number = -1;
static int hf_dvb_bat_last_section_number = -1;

static int hf_dvb_bat_reserved2 = -1;
static int hf_dvb_bat_bouquet_descriptors_length = -1;

static int hf_dvb_bat_reserved3 = -1;
static int hf_dvb_bat_transport_stream_loop_length = -1;

static int hf_dvb_bat_transport_stream_id = -1;
static int hf_dvb_bat_original_network_id = -1;
static int hf_dvb_bat_reserved4 = -1;
static int hf_dvb_bat_transport_descriptors_length = -1;

static gint ett_dvb_bat = -1;
static gint ett_dvb_bat_transport_stream = -1;


#define DVB_BAT_RESERVED1_MASK                      0xC0
#define DVB_BAT_VERSION_NUMBER_MASK                 0x3E
#define DVB_BAT_CURRENT_NEXT_INDICATOR_MASK         0x01

#define DVB_BAT_RESERVED2_MASK                    0xF000
#define DVB_BAT_BOUQUET_DESCRIPTORS_LENGTH_MASK   0x0FFF

#define DVB_BAT_RESERVED3_MASK                    0xF000
#define DVB_BAT_TRANSPORT_STREAM_LOOP_LENGTH_MASK 0x0FFF

#define DVB_BAT_RESERVED4_MASK                    0xF000
#define DVB_BAT_TRANSPORT_DESCRIPTORS_LENGTH_MASK 0x0FFF

static const value_string dvb_bat_cur_next_vals[] = {
    { 0, "Not yet applicable" },
    { 1, "Currently applicable" },

    { 0, NULL }
};

#if 0
static const value_string dvb_bat_running_status_vals[] = {
    { 0, "Undefined" },
    { 1, "Not Running" },
    { 2, "Starts in a few seconds" },
    { 3, "Pausing" },
    { 4, "Running" },
    { 5, "Service off-air" },

    { 0, NULL }
};

static const value_string dvb_bat_free_ca_mode_vals[] = {
    { 0, "Not Scrambled" },
    { 1, "One or more component scrambled" },

    { 0, NULL }
};
#endif

static int
dissect_dvb_bat(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

    guint   offset = 0, length = 0, ts_loop_end;
    guint16 ts_id, descriptor_len, ts_loop_len;

    proto_item *ti;
    proto_tree *dvb_bat_tree;
    proto_tree *transport_stream_tree;

    col_set_str(pinfo->cinfo, COL_INFO, "Bouquet Association Table (BAT)");

    ti = proto_tree_add_item(tree, proto_dvb_bat,                              tvb, offset, -1, ENC_NA);
    dvb_bat_tree = proto_item_add_subtree(ti, ett_dvb_bat);

    offset += packet_mpeg_sect_header(tvb, offset, dvb_bat_tree, &length, NULL);
    length -= 4;

    proto_tree_add_item(dvb_bat_tree, hf_dvb_bat_bouquet_id,                   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(dvb_bat_tree, hf_dvb_bat_reserved1,                    tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_bat_tree, hf_dvb_bat_version_number,               tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_bat_tree, hf_dvb_bat_current_next_indicator,       tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(dvb_bat_tree, hf_dvb_bat_section_number,               tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(dvb_bat_tree, hf_dvb_bat_last_section_number,          tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    descriptor_len = tvb_get_ntohs(tvb, offset) & DVB_BAT_BOUQUET_DESCRIPTORS_LENGTH_MASK;
    proto_tree_add_item(dvb_bat_tree, hf_dvb_bat_reserved2,                    tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_bat_tree, hf_dvb_bat_bouquet_descriptors_length,   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset += proto_mpeg_descriptor_loop_dissect(tvb, offset, descriptor_len, dvb_bat_tree);

    ts_loop_len = tvb_get_ntohs(tvb, offset) & DVB_BAT_TRANSPORT_STREAM_LOOP_LENGTH_MASK;
    proto_tree_add_item(dvb_bat_tree, hf_dvb_bat_reserved3,                    tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_bat_tree, hf_dvb_bat_transport_stream_loop_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    ts_loop_end = offset + ts_loop_len;
    while (offset < ts_loop_end) {
        ts_id = tvb_get_ntohs(tvb, offset);
        descriptor_len = tvb_get_ntohs(tvb, offset + 4) & DVB_BAT_TRANSPORT_DESCRIPTORS_LENGTH_MASK;

        transport_stream_tree = proto_tree_add_subtree_format(dvb_bat_tree, tvb, offset, 6 + descriptor_len,
            ett_dvb_bat_transport_stream, NULL, "Transport Stream 0x%04x", ts_id);

        proto_tree_add_item(transport_stream_tree, hf_dvb_bat_transport_stream_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(transport_stream_tree, hf_dvb_bat_original_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(transport_stream_tree, hf_dvb_bat_reserved4, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(transport_stream_tree, hf_dvb_bat_transport_descriptors_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        offset += proto_mpeg_descriptor_loop_dissect(tvb, offset, descriptor_len, transport_stream_tree);
    }

    offset += packet_mpeg_sect_crc(tvb, pinfo, dvb_bat_tree, 0, offset);
    proto_item_set_len(ti, offset);
    return tvb_captured_length(tvb);
}


void
proto_register_dvb_bat(void)
{

    static hf_register_info hf[] = {

        { &hf_dvb_bat_bouquet_id, {
            "Bouquet ID", "dvb_bat.bouquet_id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_bat_reserved1, {
            "Reserved", "dvb_bat.reserved1",
            FT_UINT8, BASE_HEX, NULL, DVB_BAT_RESERVED1_MASK, NULL, HFILL
        } },

        { &hf_dvb_bat_version_number, {
            "Version Number", "dvb_bat.version",
            FT_UINT8, BASE_HEX, NULL, DVB_BAT_VERSION_NUMBER_MASK, NULL, HFILL
        } },

        { &hf_dvb_bat_current_next_indicator, {
            "Current/Next Indicator", "dvb_bat.cur_next_ind",
            FT_UINT8, BASE_DEC, VALS(dvb_bat_cur_next_vals), DVB_BAT_CURRENT_NEXT_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_dvb_bat_section_number, {
            "Section Number", "dvb_bat.sect_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_bat_last_section_number, {
            "Last Section Number", "dvb_bat.last_sect_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_bat_reserved2, {
            "Reserved", "dvb_bat.reserved2",
            FT_UINT16, BASE_HEX, NULL, DVB_BAT_RESERVED2_MASK, NULL, HFILL
        } },

        { &hf_dvb_bat_bouquet_descriptors_length, {
            "Bouquet Descriptors Length", "dvb_bat.bouquet_desc_len",
            FT_UINT16, BASE_DEC, NULL, DVB_BAT_BOUQUET_DESCRIPTORS_LENGTH_MASK, NULL, HFILL
        } },

        { &hf_dvb_bat_reserved3, {
            "Reserved", "dvb_bat.reserved3",
            FT_UINT16, BASE_HEX, NULL, DVB_BAT_RESERVED3_MASK, NULL, HFILL
        } },

        { &hf_dvb_bat_transport_stream_loop_length, {
            "Transport Stream Loop Length", "dvb_bat.ts_loop_len",
            FT_UINT16, BASE_DEC, NULL, DVB_BAT_TRANSPORT_STREAM_LOOP_LENGTH_MASK, NULL, HFILL
        } },

        { &hf_dvb_bat_transport_stream_id, {
            "Transport Stream ID", "dvb_bat.ts.id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_bat_original_network_id, {
            "Original Network ID", "dvb_bat.ts.original_nid",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_bat_reserved4, {
            "Reserved", "dvb_bat.ts.reserved",
            FT_UINT16, BASE_HEX, NULL, DVB_BAT_RESERVED4_MASK, NULL, HFILL
        } },

        { &hf_dvb_bat_transport_descriptors_length, {
            "Bouquet Descriptors Length", "dvb_bat.ts.desc_len",
            FT_UINT16, BASE_DEC, NULL, DVB_BAT_BOUQUET_DESCRIPTORS_LENGTH_MASK, NULL, HFILL
        } },

    };

    static gint *ett[] = {
        &ett_dvb_bat,
        &ett_dvb_bat_transport_stream
    };

    proto_dvb_bat = proto_register_protocol("DVB Bouquet Association Table", "DVB BAT", "dvb_bat");

    proto_register_field_array(proto_dvb_bat, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}


void proto_reg_handoff_dvb_bat(void)
{
    dissector_handle_t dvb_bat_handle;

    dvb_bat_handle = create_dissector_handle(dissect_dvb_bat, proto_dvb_bat);

    dissector_add_uint("mpeg_sect.tid", DVB_BAT_TID, dvb_bat_handle);
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
