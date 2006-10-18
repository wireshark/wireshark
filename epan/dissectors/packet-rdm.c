/* packet-rdm.c
 * RDM (Remote Device Management) packet disassembly.
 *
 * $Id$
 *
 * This dissector is written by
 *
 *  Shaun Jackman <sjackman@gmail.com>
 *  Copyright 2006 Pathway Connectivity
 *
 *  Erwin Rol <erwin@erwinrol.com>
 *  Copyright 2003 Erwin Rol
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
 * ANSI E1.20-2006, Entertainment Technology
 * Remote Device Management over USITT DMX512, describes a method of
 * bi-directional communications over a USITT DMX512/1990 data link
 * between an entertainment lighting controller and one or more
 * remotely controlled lighting devices. The protocol also is intended
 * to work with the ANSI E1.11-2004 control protocol. It allows
 * discovery of devices on a DMX512/E1.11 network and the remote
 * setting of DMX starting addresses, as well as status and fault
 * reporting back to the control console.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

static int proto_rdm = -1;

static int hf_rdm_start_code = -1;
static int hf_rdm_sub_start_code = -1;
static int hf_rdm_message_length = -1;
static int hf_rdm_dest_uid = -1;
static int hf_rdm_src_uid = -1;
static int hf_rdm_transaction_number = -1;
static int hf_rdm_response_type = -1;
static int hf_rdm_message_count = -1;
static int hf_rdm_sub_device = -1;
static int hf_rdm_command_class = -1;
static int hf_rdm_parameter_id = -1;
static int hf_rdm_parameter_data_length = -1;
static int hf_rdm_parameter_data = -1;
static int hf_rdm_intron = -1;
static int hf_rdm_checksum = -1;
static int hf_rdm_trailer = -1;

static int ett_rdm = -1;

static guint16
rdm_checksum(tvbuff_t *tvb, unsigned length)
{
	guint16 sum = 0;
	unsigned i;
	for (i = 0; i < length; i++)
		sum += tvb_get_guint8(tvb, i);
	return sum;
}

static void
dissect_rdm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RDM");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree != NULL) {
		unsigned message_length, checksum, checksum_shouldbe,
				parameter_data_length, offset = 0;
		proto_item *item;

		proto_tree *ti = proto_tree_add_item(tree, proto_rdm, tvb,
				offset, -1, FALSE);
		proto_tree *rdm_tree = proto_item_add_subtree(ti, ett_rdm);

		proto_tree_add_item(rdm_tree, hf_rdm_start_code, tvb,
				offset, 1, FALSE);
		offset++;

		proto_tree_add_item(rdm_tree, hf_rdm_sub_start_code, tvb,
				offset, 1, FALSE);
		offset++;

		message_length = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(rdm_tree, hf_rdm_message_length, tvb,
				offset, 1, FALSE);
		offset++;

		proto_tree_add_item(rdm_tree, hf_rdm_dest_uid, tvb,
				offset, 6, FALSE);
		offset += 6;

		proto_tree_add_item(rdm_tree, hf_rdm_src_uid, tvb,
				offset, 6, FALSE);
		offset += 6;

		proto_tree_add_item(rdm_tree, hf_rdm_transaction_number, tvb,
				offset, 1, FALSE);
		offset++;

		proto_tree_add_item(rdm_tree, hf_rdm_response_type, tvb,
				offset, 1, FALSE);
		offset++;

		proto_tree_add_item(rdm_tree, hf_rdm_message_count, tvb,
				offset, 1, FALSE);
		offset++;

		proto_tree_add_item(rdm_tree, hf_rdm_sub_device, tvb,
				offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(rdm_tree, hf_rdm_command_class, tvb,
				offset, 1, FALSE);
		offset++;

		proto_tree_add_item(rdm_tree, hf_rdm_parameter_id, tvb,
				offset, 2, FALSE);
		offset += 2;

		parameter_data_length = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(rdm_tree, hf_rdm_parameter_data_length, tvb,
				offset, 1, FALSE);
		offset++;

		if (parameter_data_length > 0) {
			proto_tree_add_item(rdm_tree, hf_rdm_parameter_data, tvb,
					offset, parameter_data_length, FALSE);
			offset += parameter_data_length;
		}

		if (offset < message_length) {
			proto_tree_add_item(rdm_tree, hf_rdm_intron, tvb,
					offset, message_length - offset, FALSE);
			offset = message_length;
		}

		checksum_shouldbe = rdm_checksum(tvb, offset);
		checksum = tvb_get_ntohs(tvb, offset);
		item = proto_tree_add_item(rdm_tree, hf_rdm_checksum, tvb,
				offset, 2, FALSE);
		proto_item_append_text(item, checksum == checksum_shouldbe
				? " [correct]"
				: " [incorrect, should be 0x%04x]", checksum_shouldbe);
		offset += 2;

		if (offset < tvb_length(tvb))
			proto_tree_add_item(rdm_tree, hf_rdm_trailer, tvb,
					offset, -1, FALSE);
	}
}

void
proto_register_rdm(void)
{
	static hf_register_info hf[] = {
		{ &hf_rdm_start_code,
			{ "Start code", "rdm.sc",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_sub_start_code,
			{ "Sub-start code", "rdm.ssc",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_message_length,
			{ "Message length", "rdm.len",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_dest_uid,
			{ "Destination UID", "rdm.dst",
				FT_BYTES, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_src_uid,
			{ "Source UID", "rdm.src",
				FT_BYTES, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_transaction_number,
			{ "Transaction number", "rdm.tn",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_response_type,
			{ "Response type", "rdm.rt",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_message_count,
			{ "Message count", "rdm.mc",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_sub_device,
			{ "Sub-device", "rdm.sd",
				FT_UINT16, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_command_class,
			{ "Command class", "rdm.cc",
				FT_UINT8, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_parameter_id,
			{ "Parameter ID", "rdm.pid",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_parameter_data_length,
			{ "Parameter data length", "rdm.pdl",
				FT_UINT8, BASE_DEC, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_parameter_data,
			{ "Parameter data", "rdm.pd",
				FT_BYTES, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_intron,
			{ "Intron", "rdm.intron",
				FT_BYTES, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_checksum,
			{ "Checksum", "rdm.checksum",
				FT_UINT16, BASE_HEX, NULL, 0x0,
				NULL, HFILL }},

		{ &hf_rdm_trailer,
			{ "Trailer", "rdm.trailer",
				FT_BYTES, BASE_HEX, NULL, 0x0,
				NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_rdm
	};

	proto_rdm = proto_register_protocol("Remote Device Management",
			"RDM", "rdm");
	proto_register_field_array(proto_rdm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("rdm", dissect_rdm, proto_rdm);
}

void
proto_reg_handoff_rdm(void)
{
	create_dissector_handle(dissect_rdm, proto_rdm);
}
