/* packet-nwmtp.c
 * Routines for NexusWare MTP3 over UDP transport
 * Copyright 2010 by Holger Hans Peter Freyther <zecke@selfish.org>
 * Copyright 2010 by On-Waves
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_mwmtp(void);
void proto_reg_handoff_nwmtp(void);

static dissector_handle_t mtp_handle;
static gint proto_nwmtp = -1;

static int hf_nwmtp_transp_type = -1;
static int hf_nwmtp_user_context = -1;
static int hf_nwmtp_data_type = -1;
static int hf_nwmtp_data_index = -1;
static int hf_nwmtp_data_length = -1;

/* subtree pointer */
static gint ett_mwmtp = -1;

static dissector_handle_t nwmtp_handle;

static const value_string nwmtp_transport_type_vals[] = {
	{ 2,	    "UDP" },
	{ 3,	    "TCP" },
	{ 0,	    NULL  },
};

static const value_string nwmtp_data_type_vals[] = {
	{ 0,	    "MSU Prio 0" },
	{ 1,	    "MSU Prio 1" },
	{ 2,	    "MSU Prio 2" },
	{ 3,	    "MSU Prio 3" },
	{16,	    "Retrieved MSU Prio 0" },
	{17,	    "Retrieved MSU Prio 0" },
	{18,	    "Retrieved MSU Prio 0" },
	{32,	    "Retrieval complete"   },
	{33,	    "Retrieval impossible" },
	{34,	    "Link in service"      },
	{35,	    "Link out of service"  },
	{ 0,	    NULL },
};

static int dissect_nwmtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	gint offset = 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NW MTP");
	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0) {
		const gchar *type;
		proto_item *ti;
		proto_item *nwmtp_tree;
		guint32 len;
		tvbuff_t *next_tvb;

		/* update the info column */
		type = val_to_str_const(tvb_get_guint8(tvb, offset + 1),
					nwmtp_data_type_vals, "Unknown");
		col_set_str(pinfo->cinfo, COL_INFO, type);

		len = tvb_get_ntohl(tvb, offset + 8);

		if (tree) {
			ti = proto_tree_add_protocol_format(tree, proto_nwmtp,
					tvb, offset, len + 12,
					"NexusWare C7 UDP Protocol");

			nwmtp_tree = proto_item_add_subtree(ti, ett_mwmtp);
			proto_tree_add_item(nwmtp_tree, hf_nwmtp_transp_type,
					    tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(nwmtp_tree, hf_nwmtp_data_type,
					    tvb, offset + 1, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(nwmtp_tree, hf_nwmtp_data_index,
					    tvb, offset + 2, 2, ENC_BIG_ENDIAN);
			proto_tree_add_item(nwmtp_tree, hf_nwmtp_user_context,
					    tvb, offset + 4, 4, ENC_BIG_ENDIAN);
			proto_tree_add_item(nwmtp_tree, hf_nwmtp_data_length,
					    tvb, offset + 8, 4, ENC_BIG_ENDIAN);
		}

		next_tvb = tvb_new_subset_length(tvb, offset + 12, len);
		if (tvb_reported_length(next_tvb) > 0)
			call_dissector(mtp_handle, next_tvb, pinfo, tree);
		/* Check for overflows, which probably can't happen, but better
		 * safe than sorry. See
		 * https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8169
		 */
		DISSECTOR_ASSERT(len < G_MAXUINT32 - 11);
		DISSECTOR_ASSERT((guint64)offset + len + 12 < G_MAXINT);
		offset += len + 12;
	}

	return tvb_captured_length(tvb);
}

void proto_register_mwmtp(void)
{
	static hf_register_info hf[] = {
		{&hf_nwmtp_transp_type,
		 {"Transport Type", "nwmtp.transp_type",
		  FT_UINT8, BASE_DEC, VALS(nwmtp_transport_type_vals), 0x0,
		  "The Transport Type", HFILL}
		},
		{&hf_nwmtp_data_type,
		 {"Data Type", "nwmtp.data_type",
		  FT_UINT8, BASE_DEC, VALS(nwmtp_data_type_vals), 0x0,
		  "The Data Type", HFILL}
		},
		{&hf_nwmtp_data_index,
		 {"Link Index", "nwmtp.link_index",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_nwmtp_user_context,
		 {"User Context", "nwmtp.user_context",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Use Context", HFILL}
		},
		{&hf_nwmtp_data_length,
		 {"Length", "nwmtp.data_length",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Data Length", HFILL}
		},
	};

	static gint *ett[] = {
		&ett_mwmtp,
	};

	proto_nwmtp =
	     proto_register_protocol("NexusWare C7 MTP", "MTP over NW UDP", "nw_mtp");

	proto_register_field_array(proto_nwmtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	nwmtp_handle = register_dissector("nw_mtp", dissect_nwmtp, proto_nwmtp);
}

void proto_reg_handoff_nwmtp(void)
{
	dissector_add_for_decode_as("udp.port", nwmtp_handle);
	mtp_handle = find_dissector_add_dependency("mtp3", proto_nwmtp);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
