/* packet-mpeg-sdt.c
 * Routines for DVB (ETSI EN 300 468) Servide Description Table (SDT) dissection
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
 * the Free Software Foundation; sdther version 2 of the License, or
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-mpeg-sect.h>

#include "packet-mpeg-descriptor.h"

static int proto_dvb_sdt = -1;
static int hf_dvb_sdt_transport_stream_id = -1;
static int hf_dvb_sdt_reserved1 = -1;
static int hf_dvb_sdt_version_number = -1;
static int hf_dvb_sdt_current_next_indicator = -1;
static int hf_dvb_sdt_section_number = -1;
static int hf_dvb_sdt_last_section_number = -1;

static int hf_dvb_sdt_original_network_id = -1;
static int hf_dvb_sdt_reserved2 = -1;

static int hf_dvb_sdt_service_id = -1;
static int hf_dvb_sdt_reserved3 = -1;
static int hf_dvb_sdt_eit_schedule_flag = -1;
static int hf_dvb_sdt_eit_present_following_flag = -1;
static int hf_dvb_sdt_running_status = -1;
static int hf_dvb_sdt_free_ca_mode = -1;
static int hf_dvb_sdt_descriptors_loop_length = -1;

static gint ett_dvb_sdt = -1;
static gint ett_dvb_sdt_service = -1;

#define DVB_SDT_TID_ACTUAL			0x42
#define DVB_SDT_TID_OTHER			0x46

#define DVB_SDT_RESERVED1_MASK			0xC0
#define DVB_SDT_VERSION_NUMBER_MASK		0x3E
#define DVB_SDT_CURRENT_NEXT_INDICATOR_MASK	0x01

#define DVB_SDT_RESERVED3_MASK			0xFC
#define DVB_SDT_EIT_SCHEDULE_FLAG_MASK		0x02
#define DVB_SDT_EIT_PRESENT_FOLLOWING_FLAG_MASK	0x01

#define DVB_SDT_RUNNING_STATUS_MASK		0xE000
#define DVB_SDT_FREE_CA_MODE_MASK		0x1000
#define DVB_SDT_DESCRIPTORS_LOOP_LENGTH_MASK	0x0FFF


static const value_string dvb_sdt_cur_next_vals[] = {
	{ 0, "Not yet applicable" },
	{ 1, "Currently applicable" },

	{ 0, NULL }
};

static const value_string dvb_sdt_running_status_vals[] = {
	{ 0, "Undefined" },
	{ 1, "Not Running" },
	{ 2, "Starts in a few seconds" },
	{ 3, "Pausing" },
	{ 4, "Running" },
	{ 5, "Service off-air" },

	{ 0, NULL }
};

static const value_string dvb_sdt_free_ca_mode_vals[] = {
	{ 0, "Not Scrambled" },
	{ 1, "One or more component scrambled" },

	{ 0, NULL }
};

static void
dissect_dvb_sdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	guint offset = 0, length = 0, descriptor_end = 0;
	guint16 svc_id = 0, descriptor_len = 0;

	proto_item *ti = NULL;
	proto_tree *dvb_sdt_tree = NULL;
	proto_item *si = NULL;
	proto_tree *dvb_sdt_service_tree = NULL;

	/* The TVB should start right after the section_length in the Section packet */

	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_INFO, "Service Description Table (SDT)");

	if (!tree)
		return;

	ti = proto_tree_add_item(tree, proto_dvb_sdt, tvb, offset, -1, ENC_NA);
	dvb_sdt_tree = proto_item_add_subtree(ti, ett_dvb_sdt);

	offset += packet_mpeg_sect_header(tvb, offset, dvb_sdt_tree, &length, NULL);
	length -= 4;

	proto_tree_add_item(dvb_sdt_tree, hf_dvb_sdt_transport_stream_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(dvb_sdt_tree, hf_dvb_sdt_reserved1, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dvb_sdt_tree, hf_dvb_sdt_version_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dvb_sdt_tree, hf_dvb_sdt_current_next_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(dvb_sdt_tree, hf_dvb_sdt_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(dvb_sdt_tree, hf_dvb_sdt_last_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(dvb_sdt_tree, hf_dvb_sdt_original_network_id, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(dvb_sdt_tree, hf_dvb_sdt_reserved2, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;


	if (offset >= length)
		return;

	/* Parse all the services */
	while (offset < length) {

		svc_id = tvb_get_ntohs(tvb, offset);
		si = proto_tree_add_text(dvb_sdt_tree, tvb, offset, 5, "Service 0x%04hx", svc_id);
		dvb_sdt_service_tree = proto_item_add_subtree(si, ett_dvb_sdt_service);

		proto_tree_add_item(dvb_sdt_service_tree, hf_dvb_sdt_service_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dvb_sdt_service_tree, hf_dvb_sdt_reserved3, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(dvb_sdt_service_tree, hf_dvb_sdt_eit_schedule_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(dvb_sdt_service_tree, hf_dvb_sdt_eit_present_following_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dvb_sdt_service_tree, hf_dvb_sdt_running_status, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(dvb_sdt_service_tree, hf_dvb_sdt_free_ca_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(dvb_sdt_service_tree, hf_dvb_sdt_descriptors_loop_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		descriptor_len = tvb_get_ntohs(tvb, offset) & DVB_SDT_DESCRIPTORS_LOOP_LENGTH_MASK;
		offset += 2;

		descriptor_end = offset + descriptor_len;
		while (offset < descriptor_end)
			offset += proto_mpeg_descriptor_dissect(tvb, offset, dvb_sdt_service_tree);

	}

	packet_mpeg_sect_crc(tvb, pinfo, dvb_sdt_tree, 0, offset);
}


void
proto_register_dvb_sdt(void)
{

	static hf_register_info hf[] = {

		{ &hf_dvb_sdt_transport_stream_id, {
			"Transport Stream ID", "dvb_sdt.tsid",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dvb_sdt_reserved1, {
			"Reserved", "dvb_sdt.reserved1",
			FT_UINT8, BASE_HEX, NULL, DVB_SDT_RESERVED1_MASK, NULL, HFILL
		} },

		{ &hf_dvb_sdt_version_number, {
			"Version Number", "dvb_sdt.version",
			FT_UINT8, BASE_HEX, NULL, DVB_SDT_VERSION_NUMBER_MASK, NULL, HFILL
		} },

		{ &hf_dvb_sdt_current_next_indicator, {
			"Current/Next Indicator", "dvb_sdt.cur_next_ind",
			FT_UINT8, BASE_DEC, VALS(dvb_sdt_cur_next_vals), DVB_SDT_CURRENT_NEXT_INDICATOR_MASK, NULL, HFILL
		} },

		{ &hf_dvb_sdt_section_number, {
			"Section Number", "dvb_sdt.sect_num",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dvb_sdt_last_section_number, {
			"Last Section Number", "dvb_sdt.last_sect_num",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dvb_sdt_original_network_id, {
			"Original Network ID", "dvb_sdt.original_nid",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dvb_sdt_reserved2, {
			"Reserved", "dvb_sdt.reserved2",
			FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL
		} },


		{ &hf_dvb_sdt_service_id, {
			"Service ID", "dvb_sdt.svc.id",
			FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL
		} },

		{ &hf_dvb_sdt_reserved3, {
			"Reserved", "dvb_sdt.svc.reserved",
			FT_UINT8, BASE_HEX, NULL, DVB_SDT_RESERVED3_MASK, NULL, HFILL
		} },

		{ &hf_dvb_sdt_eit_schedule_flag, {
			"EIT Schedule Flag", "dvb_sdt.svc.eit_schedule_flag",
			FT_UINT8, BASE_DEC, NULL, DVB_SDT_EIT_SCHEDULE_FLAG_MASK, NULL, HFILL
		} },

		{ &hf_dvb_sdt_eit_present_following_flag, {
			"EIT Present Following Flag", "dvb_sdt.svc.eit_present_following_flag",
			FT_UINT8, BASE_DEC, NULL, DVB_SDT_EIT_PRESENT_FOLLOWING_FLAG_MASK, NULL, HFILL
		} },

		{ &hf_dvb_sdt_running_status, {
			"Running Status", "dvb_sdt.svc.running_status",
			FT_UINT16, BASE_HEX, VALS(dvb_sdt_running_status_vals), DVB_SDT_RUNNING_STATUS_MASK, NULL, HFILL
		} },

		{ &hf_dvb_sdt_free_ca_mode, {
			"Free CA Mode", "dvb_sdt.svc.free_ca_mode",
			FT_UINT16, BASE_HEX, VALS(dvb_sdt_free_ca_mode_vals), DVB_SDT_FREE_CA_MODE_MASK, NULL, HFILL
		} },

		{ &hf_dvb_sdt_descriptors_loop_length, {
			"Descriptors Loop Length", "dvb_sdt.svc.descr_loop_len",
			FT_UINT16, BASE_HEX, NULL, DVB_SDT_DESCRIPTORS_LOOP_LENGTH_MASK, NULL, HFILL
		} }

	};

	static gint *ett[] = {
		&ett_dvb_sdt,
		&ett_dvb_sdt_service
	};

	proto_dvb_sdt = proto_register_protocol("DVB Service Description Table", "DVB SDT", "dvb_sdt");

	proto_register_field_array(proto_dvb_sdt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void proto_reg_handoff_dvb_sdt(void)
{
	dissector_handle_t dvb_sdt_handle;

	dvb_sdt_handle = create_dissector_handle(dissect_dvb_sdt, proto_dvb_sdt);
	dissector_add_uint("mpeg_sect.tid", DVB_SDT_TID_ACTUAL, dvb_sdt_handle);
	dissector_add_uint("mpeg_sect.tid", DVB_SDT_TID_OTHER, dvb_sdt_handle);
}
