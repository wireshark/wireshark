/* packet-dmx-sip.c
 * DMX SIP packet disassembly.
 *
 * This dissector is written by
 *
 *  Erwin Rol <erwin@erwinrol.com>
 *  Copyright 2011 Erwin Rol
 *
 *  Wireshark - Network traffic analyzer
 *  Gerald Combs <gerald@wireshark.org>
 *  Copyright 1999 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor
 * Boston, MA  02110-1301, USA.
 */

/*
 * This dissector is based on;
 * American National Standard E1.11 - 2004
 * Entertainment Technology USITT DMX512-A
 * Asynchronous Serial Digital Data Transmission Standard
 * for Controlling Lighting Equipment and Accessories
 */

#include "config.h"

#include <epan/packet.h>

#define DMX_SC_SIP    0xCF

void proto_register_dmx_sip(void);

static int proto_dmx_sip = -1;

static int hf_dmx_sip_byte_count = -1;
static int hf_dmx_sip_control_bit_field = -1;
static int hf_dmx_sip_prev_packet_checksum = -1;
static int hf_dmx_sip_seq_nr = -1;
static int hf_dmx_sip_dmx_universe_nr = -1;
static int hf_dmx_sip_dmx_proc_level = -1;
static int hf_dmx_sip_dmx_software_version = -1;
static int hf_dmx_sip_dmx_packet_len = -1;
static int hf_dmx_sip_dmx_nr_packets = -1;
static int hf_dmx_sip_orig_dev_id = -1;
static int hf_dmx_sip_sec_dev_id = -1;
static int hf_dmx_sip_third_dev_id = -1;
static int hf_dmx_sip_fourth_dev_id = -1;
static int hf_dmx_sip_fifth_dev_id = -1;
static int hf_dmx_sip_reserved = -1;
static int hf_dmx_sip_checksum = -1;
static int hf_dmx_sip_checksum_good = -1;
static int hf_dmx_sip_checksum_bad = -1;
static int hf_dmx_sip_trailer = -1;

static int ett_dmx_sip = -1;

static guint8
dmx_sip_checksum(tvbuff_t *tvb, guint length)
{
	guint8    sum = DMX_SC_SIP;
	guint  i;
	for (i = 0; i < length; i++)
		sum += tvb_get_guint8(tvb, i);
	return sum;
}

static void
dissect_dmx_sip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "DMX SIP");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree != NULL) {
		guint    offset = 0;
		guint    byte_count;
		guint    checksum, checksum_shouldbe;
		proto_item *item;
		proto_tree *checksum_tree;

		proto_tree *ti = proto_tree_add_item(tree, proto_dmx_sip, tvb,
							offset, -1, ENC_NA);
		proto_tree *dmx_sip_tree = proto_item_add_subtree(ti, ett_dmx_sip);


		byte_count = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_byte_count, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_control_bit_field, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_prev_packet_checksum, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_seq_nr, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_dmx_universe_nr, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_dmx_proc_level, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_dmx_software_version, tvb,
							offset, 1, ENC_BIG_ENDIAN);
		offset++;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_dmx_packet_len, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_dmx_nr_packets, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_orig_dev_id, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_sec_dev_id, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_third_dev_id, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_fourth_dev_id, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_fifth_dev_id, tvb,
							offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		if (offset < byte_count) {
			proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_reserved, tvb,
							offset, byte_count - offset, ENC_NA);
			offset += (byte_count - offset);
		}

		dmx_sip_checksum(tvb, offset);

		checksum_shouldbe = dmx_sip_checksum(tvb, offset);
		checksum = tvb_get_guint8(tvb, offset);
		item = proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_checksum, tvb,
				offset, 1, ENC_BIG_ENDIAN);
		if (checksum == checksum_shouldbe) {
			proto_item_append_text(item, " [correct]");

			checksum_tree = proto_item_add_subtree(item, ett_dmx_sip);
			item = proto_tree_add_boolean(checksum_tree, hf_dmx_sip_checksum_good, tvb,
						offset, 1, TRUE);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_boolean(checksum_tree, hf_dmx_sip_checksum_bad, tvb,
						offset, 1, FALSE);
			PROTO_ITEM_SET_GENERATED(item);
		} else {
			proto_item_append_text(item, " [incorrect, should be 0x%02x]", checksum_shouldbe);

			checksum_tree = proto_item_add_subtree(item, ett_dmx_sip);
			item = proto_tree_add_boolean(checksum_tree, hf_dmx_sip_checksum_good, tvb,
						offset, 1, FALSE);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_boolean(checksum_tree, hf_dmx_sip_checksum_bad, tvb,
						offset, 1, TRUE);
			PROTO_ITEM_SET_GENERATED(item);
		}

		offset += 1;

		if (offset < tvb_length(tvb))
			proto_tree_add_item(dmx_sip_tree, hf_dmx_sip_trailer, tvb,
					offset, -1, ENC_NA);
	}
}

void
proto_register_dmx_sip(void)
{
	static hf_register_info hf[] = {
		{ &hf_dmx_sip_byte_count,
			{ "Byte Count", "dmx_sip.byte_count",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_control_bit_field,
			{ "Control Bit Field", "dmx_sip.control_bit_field",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_prev_packet_checksum,
			{ "Checksum of prev. packet", "dmx_sip.prev_packet_checksum",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_seq_nr,
			{ "SIP sequence nr.", "dmx_sip.seq_nr",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_dmx_universe_nr,
			{ "DMX512 universe nr.", "dmx_sip.dmx_universe_nr",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_dmx_proc_level,
			{ "DMX512 processing level", "dmx_sip.dmx_proc_level",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_dmx_software_version,
			{ "Software Version", "dmx_sip.dmx_software_version",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_dmx_packet_len,
			{ "Standard Packet Len", "dmx_sip.dmx_packet_len",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_dmx_nr_packets,
			{ "Number of Packets", "dmx_sip.dmx_nr_packets",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_orig_dev_id,
			{ "1st Device's ID", "dmx_sip.orig_dev_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_sec_dev_id,
			{ "2nd Device's ID", "dmx_sip.sec_dev_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_third_dev_id,
			{ "3rd Device's ID", "dmx_sip.third_dev_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_fourth_dev_id,
			{ "4th Device's ID", "dmx_sip.fourth_dev_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_fifth_dev_id,
			{ "5th Device's ID", "dmx_sip.fifth_dev_id",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_reserved,
			{ "Reserved", "dmx_sip.reserved",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_checksum,
			{ "Checksum", "dmx_sip.checksum",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_dmx_sip_checksum_good,
			{ "Good Checksum", "dmx_sip.checksum_good",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"True: checksum matches packet content; False: doesn't match content", HFILL }},

		{ &hf_dmx_sip_checksum_bad,
			{ "Bad Checksum", "dmx_sip.checksum_bad",
				FT_BOOLEAN, BASE_NONE, NULL, 0x0,
				"True: checksum doesn't match packet content; False: matches content", HFILL }},

		{ &hf_dmx_sip_trailer,
			{ "Trailer", "dmx_sip.trailer",
				FT_BYTES, BASE_NONE, NULL, 0x0,
				NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_dmx_sip
	};

	proto_dmx_sip = proto_register_protocol("DMX SIP", "DMX SIP", "dmx-sip");
	proto_register_field_array(proto_dmx_sip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("dmx-sip", dissect_dmx_sip, proto_dmx_sip);
}

