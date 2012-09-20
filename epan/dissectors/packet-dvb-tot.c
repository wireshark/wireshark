/* packet-dvb-tot.c
 * Routines for DVB (ETSI EN 300 468) Time Offset Table (TOT) dissection
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; tother version 2 of the License, or
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-mpeg-sect.h>

#include "packet-mpeg-descriptor.h"

static int proto_dvb_tot = -1;
static int hf_dvb_tot_utc_time = -1;
static int hf_dvb_tot_reserved = -1;
static int hf_dvb_tot_descriptors_loop_length = -1;

static gint ett_dvb_tot = -1;

#define DVB_TOT_TID				0x73

#define DVB_TOT_RESERVED_MASK			0xF000
#define DVB_TOT_DESCRIPTORS_LOOP_LENGTH_MASK	0x0FFF

static void
dissect_dvb_tot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	guint       offset = 0;
	guint       descriptor_len, descriptor_end;

	proto_item *ti;
	proto_tree *dvb_tot_tree;

	nstime_t    utc_time;

	col_set_str(pinfo->cinfo, COL_INFO, "Time Offset Table (TOT)");

	ti = proto_tree_add_item(tree, proto_dvb_tot, tvb, offset, -1, ENC_NA);
	dvb_tot_tree = proto_item_add_subtree(ti, ett_dvb_tot);

	offset += packet_mpeg_sect_header(tvb, offset, dvb_tot_tree, NULL, NULL);

	if (packet_mpeg_sect_mjd_to_utc_time(tvb, offset, &utc_time) < 0) {
		proto_tree_add_text(dvb_tot_tree, tvb, offset, 5, "UTC Time : Unparseable time");
	} else {
		proto_tree_add_time_format(dvb_tot_tree, hf_dvb_tot_utc_time, tvb, offset, 5, &utc_time,
			"UTC Time : %s UTC", abs_time_to_str(&utc_time, ABSOLUTE_TIME_UTC, FALSE));
	}

	offset += 5;

	descriptor_len = tvb_get_ntohs(tvb, offset) & DVB_TOT_DESCRIPTORS_LOOP_LENGTH_MASK;
	proto_tree_add_item(dvb_tot_tree, hf_dvb_tot_reserved, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(dvb_tot_tree, hf_dvb_tot_descriptors_loop_length, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	descriptor_end = offset + descriptor_len;
	while (offset < descriptor_end)
		offset += proto_mpeg_descriptor_dissect(tvb, offset, dvb_tot_tree);

	offset += packet_mpeg_sect_crc(tvb, pinfo, dvb_tot_tree, 0, offset);
	proto_item_set_len(ti, offset);
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

	static gint *ett[] = {
		&ett_dvb_tot
	};

	proto_dvb_tot = proto_register_protocol("DVB Time Offset Table", "DVB TOT", "dvb_tot");

	proto_register_field_array(proto_dvb_tot, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void proto_reg_handoff_dvb_tot(void)
{
	dissector_handle_t dvb_tot_handle;

	dvb_tot_handle = create_dissector_handle(dissect_dvb_tot, proto_dvb_tot);

	dissector_add_uint("mpeg_sect.tid", DVB_TOT_TID, dvb_tot_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 noexpandtab:
 * :indentSize=4:tabSize=4:noTabs=false:
 */
