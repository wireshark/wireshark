/* packet-dvb-data-mpe.c
 * Routines for DVB-DATA (ETSI EN 301 192) MultiProtocol Encapsulation
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/prefs.h>

static int proto_dvb_data_mpe = -1;
static int hf_dvb_data_mpe_reserved = -1;
static int hf_dvb_data_mpe_payload_scrambling_control = -1;
static int hf_dvb_data_mpe_address_scrambling_control = -1;
static int hf_dvb_data_mpe_llc_snap_flag = -1;
static int hf_dvb_data_mpe_current_next_indicator = -1;
static int hf_dvb_data_mpe_section_number = -1;
static int hf_dvb_data_mpe_last_section_number = -1;
static int hf_dvb_data_mpe_dst_mac = -1;

static gint ett_dvb_data_mpe = -1;

static dissector_handle_t ip_handle;
static dissector_handle_t llc_handle;

#define DVB_DATA_MPE_TID 0x3E


#define DVB_DATA_MPE_RESERVED_MASK			0xC0
#define DVB_DATA_MPE_PAYLOAD_SCRAMBLING_MASK		0x30
#define DVB_DATA_MPE_ADDRESS_SCRAMBLING_MASK		0x0C
#define DVB_DATA_MPE_LLC_SNAP_FLAG_MASK			0x02
#define DVB_DATA_MPE_CURRENT_NEXT_INDICATOR_MASK	0x01

static const value_string dvb_rcs_cur_next_vals[] = {
	
	{ 0x0, "Not yet applicable" },
	{ 0x1, "Currently applicable" },
	{ 0, NULL },

};


void
dissect_dvb_data_mpe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	guint offset = 0;
	guint8 llc_snap_flag = 0;
	int i;

	proto_item *ti = NULL;
	proto_tree *dvb_data_mpe_tree = NULL;
	tvbuff_t *mac_tvb = NULL;
	tvbuff_t *mac_bytes_tvb[6] = {0};
	tvbuff_t *data_tvb = NULL;

	/* The TVB should start right after the section_length in the Section packet */

	col_clear(pinfo->cinfo, COL_PROTOCOL);
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DVB-DATA");
	col_clear(pinfo->cinfo, COL_INFO);
	col_set_str(pinfo->cinfo, COL_INFO, "MultiProtocol Encapsulation");

	if (!tree)
		return;

	ti = proto_tree_add_item(tree, proto_dvb_data_mpe, tvb, offset, -1, ENC_NA);
	dvb_data_mpe_tree = proto_item_add_subtree(ti, ett_dvb_data_mpe);

	/* Parse the DMC-CC private section header */

	mac_bytes_tvb[5] = tvb_new_subset(tvb, offset, 1, 1);
	offset++;
	mac_bytes_tvb[4] = tvb_new_subset(tvb, offset, 1, 1);
	offset++;

	proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_payload_scrambling_control, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_address_scrambling_control, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_llc_snap_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_current_next_indicator, tvb, offset, 1, ENC_BIG_ENDIAN);
	llc_snap_flag = tvb_get_guint8(tvb, offset) & DVB_DATA_MPE_LLC_SNAP_FLAG_MASK;
	offset++;

	proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_last_section_number, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;

	for (i = 3; i >= 0; i--) {
		mac_bytes_tvb[i] = tvb_new_subset(tvb, offset, 1, 1);
		offset++;
	}

	mac_tvb = tvb_new_composite();

	for (i = 0; i < 6; i++)
		tvb_composite_append(mac_tvb, mac_bytes_tvb[i]);

	tvb_composite_finalize(mac_tvb);

	proto_tree_add_item(dvb_data_mpe_tree, hf_dvb_data_mpe_dst_mac, mac_tvb, 0 , 6, ENC_NA);
	col_clear(pinfo->cinfo, COL_RES_DL_DST);
	col_add_str(pinfo->cinfo, COL_RES_DL_DST, tvb_ether_to_str(mac_tvb, 0));

	data_tvb = tvb_new_subset(tvb, offset, -1, -1);

	if (llc_snap_flag) {
		call_dissector(llc_handle, data_tvb, pinfo, tree);
	} else {
		call_dissector(ip_handle, data_tvb, pinfo, tree);
	}

	

	return;

}

void
proto_register_dvb_data_mpe(void)
{

	static hf_register_info hf[] = {
		
		/* DSM-CC common fields */
		{ &hf_dvb_data_mpe_reserved, {
			"Reserved", "dvb_data_mpe.reserved",
			FT_UINT8, BASE_HEX, NULL, DVB_DATA_MPE_RESERVED_MASK, NULL, HFILL
		} },

		{ &hf_dvb_data_mpe_payload_scrambling_control, {
			"Payload Scrambling Control", "dvb_data_mpe.pload_scrambling",
			FT_UINT8, BASE_HEX, NULL, DVB_DATA_MPE_PAYLOAD_SCRAMBLING_MASK, NULL, HFILL
		} },

		{ &hf_dvb_data_mpe_address_scrambling_control, {
			"Address Scrambling Control", "dvb_data_mpe.addr_scrambling",
			FT_UINT8, BASE_HEX, NULL, DVB_DATA_MPE_ADDRESS_SCRAMBLING_MASK, NULL, HFILL
		} },
		
		{ &hf_dvb_data_mpe_llc_snap_flag, {
			"LLC SNAP Flag", "dvb_data_mpe.llc_snap_flag",
			FT_UINT8, BASE_HEX, NULL, DVB_DATA_MPE_LLC_SNAP_FLAG_MASK, NULL, HFILL
		} },

		{ &hf_dvb_data_mpe_current_next_indicator, {
			"Current/Next Indicator", "mpeg_sect.cur_next_ind",
			FT_UINT8, BASE_HEX, VALS(dvb_rcs_cur_next_vals), DVB_DATA_MPE_CURRENT_NEXT_INDICATOR_MASK, NULL, HFILL
		} },

		{ &hf_dvb_data_mpe_section_number, {
			"Section Number", "dvb_data_mpe.sect_num",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },
			
		{ &hf_dvb_data_mpe_last_section_number, {
			"Last Section Number", "dvb_data_mpe.last_sect_num",
			FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
		} },

		{ &hf_dvb_data_mpe_dst_mac, {
			"Destination MAC address", "dvb_data_mpe.dst_mac",
			FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
		} },


	};

	static gint *ett[] = {
		&ett_dvb_data_mpe,
	};

	proto_dvb_data_mpe = proto_register_protocol("DVB-DATA MultiProtocol Encapsulation", "DVB-DATA MPE", "dvb_data_mpe");
	proto_register_field_array(proto_dvb_data_mpe, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));
	
}


void
proto_reg_handoff_dvb_data_mpe(void)
{
	dissector_handle_t dvb_data_mpe_handle;

	dvb_data_mpe_handle = create_dissector_handle(dissect_dvb_data_mpe, proto_dvb_data_mpe);
	dissector_add_uint("mpeg_sect.tid", DVB_DATA_MPE_TID, dvb_data_mpe_handle);

	ip_handle = find_dissector("ip");
	llc_handle = find_dissector("llc");

}
