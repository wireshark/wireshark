/* packet-dvb-tot.c
 * Routines for DVB (ETSI EN 300 468) Time Offset Table (TOT) dissection
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
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

void proto_register_dvb_tot(void);
void proto_reg_handoff_dvb_tot(void);

static dissector_handle_t dvb_tot_handle;

static int proto_dvb_tot;
static int hf_dvb_tot_utc_time;
static int hf_dvb_tot_reserved;
static int hf_dvb_tot_descriptors_loop_length;

static int ett_dvb_tot;

#define DVB_TOT_RESERVED_MASK                   0xF000
#define DVB_TOT_DESCRIPTORS_LOOP_LENGTH_MASK    0x0FFF

static int
dissect_dvb_tot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    unsigned    offset = 0;
    unsigned    descriptor_len;

    proto_item *ti;
    proto_tree *dvb_tot_tree;

    nstime_t    utc_time;

    col_set_str(pinfo->cinfo, COL_INFO, "Time Offset Table (TOT)");

    ti = proto_tree_add_item(tree, proto_dvb_tot, tvb, offset, -1, ENC_NA);
    dvb_tot_tree = proto_item_add_subtree(ti, ett_dvb_tot);

    offset += packet_mpeg_sect_header(tvb, offset, dvb_tot_tree, NULL, NULL);

    if (packet_mpeg_sect_mjd_to_utc_time(tvb, offset, &utc_time) < 0) {
        proto_tree_add_time_format_value(dvb_tot_tree, hf_dvb_tot_utc_time, tvb, offset, 5, &utc_time, "Unparseable time");
    } else {
        proto_tree_add_time(dvb_tot_tree, hf_dvb_tot_utc_time, tvb, offset, 5, &utc_time);
    }

    offset += 5;

    descriptor_len = tvb_get_ntohs(tvb, offset) & DVB_TOT_DESCRIPTORS_LOOP_LENGTH_MASK;
    proto_tree_add_item(dvb_tot_tree, hf_dvb_tot_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(dvb_tot_tree, hf_dvb_tot_descriptors_loop_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    offset += proto_mpeg_descriptor_loop_dissect(tvb, pinfo, offset, descriptor_len, dvb_tot_tree);

    offset += packet_mpeg_sect_crc(tvb, pinfo, dvb_tot_tree, 0, offset);
    proto_item_set_len(ti, offset);
    return tvb_captured_length(tvb);
}


void
proto_register_dvb_tot(void)
{

    static hf_register_info hf[] = {

        { &hf_dvb_tot_utc_time, {
            "UTC Time", "dvb_tot.utc_time",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0, NULL, HFILL
        } },

        { &hf_dvb_tot_reserved, {
            "Reserved", "dvb_tot.reserved",
            FT_UINT16, BASE_HEX, NULL, DVB_TOT_RESERVED_MASK, NULL, HFILL
        } },

        { &hf_dvb_tot_descriptors_loop_length, {
             "Descriptors Loop Length", "dvb_tot.descr_loop_len",
             FT_UINT16, BASE_DEC, NULL, DVB_TOT_DESCRIPTORS_LOOP_LENGTH_MASK, NULL, HFILL
        } }
    };

    static int *ett[] = {
        &ett_dvb_tot
    };

    proto_dvb_tot = proto_register_protocol("DVB Time Offset Table", "DVB TOT", "dvb_tot");

    proto_register_field_array(proto_dvb_tot, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    dvb_tot_handle = register_dissector("dvb_tot", dissect_dvb_tot, proto_dvb_tot);
}


void proto_reg_handoff_dvb_tot(void)
{
    dissector_add_uint("mpeg_sect.tid", DVB_TOT_TID, dvb_tot_handle);
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
