/* packet-pcapng.c
 * Dissector to handle pcap-ng file-type-specific blocks.
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

#include <wiretap/wtap.h>

static int proto_pcapng_block = -1;

static dissector_table_t pcapng_block_type_dissector_table;

static void
dissect_pcapng_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/*
	 * Call the dissector for the block type of this block, if there
	 * is one.
	 */
	if (!dissector_try_uint(pcapng_block_type_dissector_table,
	    pinfo->pseudo_header->ftsrec.record_type, tvb, pinfo, tree)) {
		/*
		 * There isn't one; just do a minimal display.
		 */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCAP-NG");
		col_add_fstr(pinfo->cinfo, COL_INFO, "PCAP-NG block, type %u",
		    pinfo->pseudo_header->ftsrec.record_type);

		proto_tree_add_item(tree, proto_pcapng_block, tvb, 0, -1, ENC_NA);
	}
}

void proto_register_pcapng_block(void)
{
	proto_pcapng_block = proto_register_protocol("PCAP-NG block",
	    "PCAP-NG", "pcapng");
	pcapng_block_type_dissector_table = register_dissector_table("pcapng.block_type",
	    "pcap-ng block type", FT_UINT32, BASE_DEC);
}

void
proto_reg_handoff_pcapng_block(void)
{
	dissector_handle_t pcapng_block_handle;

	pcapng_block_handle = create_dissector_handle(dissect_pcapng_block,
	    proto_pcapng_block);
	dissector_add_uint("wtap_fts_rec", WTAP_FILE_TYPE_SUBTYPE_PCAPNG,
	    pcapng_block_handle);
}
