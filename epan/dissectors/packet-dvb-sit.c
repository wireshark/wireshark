/* packet-dvb-sit.c
 * Routines for DVB (ETSI EN 300 468) Selection Information Table (SIT) dissection
 * Copyright 2021, Roman Volkov <volkoff_roman@ukr.net>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-mpeg-sect.h"
#include "packet-mpeg-descriptor.h"

void proto_register_dvb_sit(void);
void proto_reg_handoff_dvb_sit(void);

static dissector_handle_t dvb_sit_handle;

static int proto_dvb_sit = -1;

static int hf_dvb_sit_reserved_future_use1 = -1;
static int hf_dvb_sit_reserved = -1;
static int hf_dvb_sit_version_number = -1;
static int hf_dvb_sit_current_next_indicator = -1;
static int hf_dvb_sit_section_number = -1;
static int hf_dvb_sit_last_section_number = -1;
static int hf_dvb_sit_reserved_future_use2 = -1;
static int hf_dvb_sit_transmission_info_len = -1;
static int hf_dvb_sit_service_id = -1;
static int hf_dvb_sit_reserved_future_use3 = -1;
static int hf_dvb_sit_running_status = -1;
static int hf_dvb_sit_service_descriptors_length = -1;

static gint ett_dvb_sit = -1;
static gint ett_dvb_sit_service = -1;

#define DVB_SIT_RESERVED_MASK                   0xC0
#define DVB_SIT_VERSION_NUMBER_MASK             0x3E
#define DVB_SIT_CURRENT_NEXT_INDICATOR_MASK     0x01

#define DVB_SIT_RESERVED_FUTURE_USE2_MASK       0xF000
#define DVB_SIT_TRANSMISSION_INFO_MASK          0x0FFF

#define DVB_SIT_RESERVED_FUTURE_USE3_MASK       0x8000
#define DVB_SIT_RUNNING_STATUS_MASK             0x7000
#define DVB_SIT_SERVICE_DESCRIPTORS_LENGTH_MASK 0x0FFF

static const value_string dvb_sit_cur_next_vals[] = {
    { 0, "Not yet applicable" },
    { 1, "Currently applicable" },

    { 0, NULL }
};

static const value_string dvb_sit_running_status_vals[] = {
    { 0, "Undefined" },
    { 1, "Not Running" },
    { 2, "Starts in a few seconds" },
    { 3, "Pausing" },
    { 4, "Running" },
    { 5, "Service off-air" },

    { 0, NULL }
};

static int
dissect_dvb_sit(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

    guint       offset = 0, length = 0;
    guint       descriptor_len;
    guint16     svc_id;

    proto_item *ti;
    proto_tree *dvb_sit_tree;
    proto_tree *dvb_sit_service_tree;

    /* The TVB should start right after the section_length in the Section packet */

    col_set_str(pinfo->cinfo, COL_INFO, "Selection Information Table (SIT)");

    ti = proto_tree_add_item(tree, proto_dvb_sit, tvb, offset, -1, ENC_NA);
    dvb_sit_tree = proto_item_add_subtree(ti, ett_dvb_sit);

    offset += packet_mpeg_sect_header(tvb, offset, dvb_sit_tree, &length, NULL);
    length -= 4;

    proto_tree_add_item(dvb_sit_tree, hf_dvb_sit_reserved_future_use1,   tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(dvb_sit_tree, hf_dvb_sit_reserved,               tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_sit_tree, hf_dvb_sit_version_number,         tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_sit_tree, hf_dvb_sit_current_next_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(dvb_sit_tree, hf_dvb_sit_section_number,         tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    proto_tree_add_item(dvb_sit_tree, hf_dvb_sit_last_section_number,    tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    descriptor_len = tvb_get_ntohs(tvb, offset) & DVB_SIT_TRANSMISSION_INFO_MASK;
    proto_tree_add_item(dvb_sit_tree, hf_dvb_sit_reserved_future_use2,   tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_sit_tree, hf_dvb_sit_transmission_info_len,  tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset += proto_mpeg_descriptor_loop_dissect(tvb, offset, descriptor_len, dvb_sit_tree);

    if (offset >= length)
        return offset;

    /* Parse all the services */
    while (offset < length) {

        svc_id = tvb_get_ntohs(tvb, offset);
        dvb_sit_service_tree = proto_tree_add_subtree_format(dvb_sit_tree, tvb, offset, 5,
                    ett_dvb_sit_service, NULL, "Service 0x%04hx", svc_id);

        proto_tree_add_item(dvb_sit_service_tree, hf_dvb_sit_service_id,                 tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(dvb_sit_service_tree, hf_dvb_sit_reserved_future_use3,       tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(dvb_sit_service_tree, hf_dvb_sit_running_status,             tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(dvb_sit_service_tree, hf_dvb_sit_service_descriptors_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        descriptor_len = tvb_get_ntohs(tvb, offset) & DVB_SIT_SERVICE_DESCRIPTORS_LENGTH_MASK;
        offset += 2;

        offset += proto_mpeg_descriptor_loop_dissect(tvb, offset, descriptor_len, dvb_sit_service_tree);
    }

    offset += packet_mpeg_sect_crc(tvb, pinfo, dvb_sit_tree, 0, offset);
    proto_item_set_len(ti, offset);
    return tvb_captured_length(tvb);
}


void
proto_register_dvb_sit(void)
{

    static hf_register_info hf[] = {

        { &hf_dvb_sit_reserved_future_use1, {
            "Reserved", "dvb_sit.reserved_future_use1",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_sit_reserved, {
            "Reserved", "dvb_sit.reserved",
            FT_UINT8, BASE_HEX, NULL, DVB_SIT_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_dvb_sit_version_number, {
            "Version Number", "dvb_sit.version",
            FT_UINT8, BASE_HEX, NULL, DVB_SIT_VERSION_NUMBER_MASK, NULL, HFILL
        } },

        { &hf_dvb_sit_current_next_indicator, {
            "Current/Next Indicator", "dvb_sit.cur_next_ind",
            FT_UINT8, BASE_DEC, VALS(dvb_sit_cur_next_vals), DVB_SIT_CURRENT_NEXT_INDICATOR_MASK, NULL, HFILL
        } },

        { &hf_dvb_sit_section_number, {
            "Section Number", "dvb_sit.sect_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_sit_last_section_number, {
            "Last Section Number", "dvb_sit.last_sect_num",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_sit_reserved_future_use2, {
            "Reserved", "dvb_sit.reserved_future_use2",
            FT_UINT16, BASE_HEX, NULL, DVB_SIT_RESERVED_FUTURE_USE2_MASK, NULL, HFILL
        } },

        { &hf_dvb_sit_transmission_info_len, {
            "Transmission Info Descriptors Length", "dvb_sit.transmission_info_descriptors_length",
            FT_UINT16, BASE_DEC, NULL, DVB_SIT_TRANSMISSION_INFO_MASK, NULL, HFILL
        } },

        { &hf_dvb_sit_service_id, {
            "Service ID", "dvb_sit.svc.id",
            FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_sit_reserved_future_use3, {
            "Reserved", "dvb_sit.svc.reserved_future_use3",
            FT_UINT16, BASE_HEX, NULL, DVB_SIT_RESERVED_FUTURE_USE3_MASK, NULL, HFILL
        } },

        { &hf_dvb_sit_running_status, {
            "Running Status", "dvb_sit.svc.running_status",
            FT_UINT16, BASE_HEX, VALS(dvb_sit_running_status_vals), DVB_SIT_RUNNING_STATUS_MASK, NULL, HFILL
        } },

        { &hf_dvb_sit_service_descriptors_length, {
            "Service Descriptors Length", "dvb_sit.svc.service_descriptors_length",
            FT_UINT16, BASE_DEC, NULL, DVB_SIT_SERVICE_DESCRIPTORS_LENGTH_MASK, NULL, HFILL
        } }

    };

    static gint *ett[] = {
        &ett_dvb_sit,
        &ett_dvb_sit_service
    };

    proto_dvb_sit = proto_register_protocol("DVB Selection Information Table", "DVB SIT", "dvb_sit");
    dvb_sit_handle = register_dissector("dvb_sit", dissect_dvb_sit, proto_dvb_sit);

    proto_register_field_array(proto_dvb_sit, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

}


void proto_reg_handoff_dvb_sit(void)
{
    dissector_add_uint("mpeg_sect.tid", DVB_SIT_TID, dvb_sit_handle);
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
