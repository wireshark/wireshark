/* packet-pcapng.c
 * Dissector to handle pcapng file-type-specific blocks.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <wiretap/wtap.h>

void proto_register_pcapng_block(void);
void proto_reg_handoff_pcapng_block(void);

static int proto_pcapng_block = -1;

static dissector_table_t pcapng_block_type_dissector_table;

static int
dissect_pcapng_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	/*
	 * Call the dissector for the block type of this block, if there
	 * is one.
	 */
	if (!dissector_try_uint(pcapng_block_type_dissector_table,
	    pinfo->rec->rec_header.ft_specific_header.record_type, tvb, pinfo, tree)) {
		/*
		 * There isn't one; just do a minimal display.
		 */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PCAPNG");
		col_add_fstr(pinfo->cinfo, COL_INFO, "Pcapng block, type %u",
		    pinfo->rec->rec_header.ft_specific_header.record_type);

		proto_tree_add_item(tree, proto_pcapng_block, tvb, 0, -1, ENC_NA);
	}
	return tvb_captured_length(tvb);
}

void proto_register_pcapng_block(void)
{
	proto_pcapng_block = proto_register_protocol("Pcapng block",
	    "PCAPNG", "pcapng");
	pcapng_block_type_dissector_table = register_dissector_table("pcapng.block_type",
	    "pcapng block type", proto_pcapng_block, FT_UINT32, BASE_DEC);
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

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
