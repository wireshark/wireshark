/* packet-vntag.c
 *
 * $Id$
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>

static int proto_vntag = -1;

static int hf_vntag_etype = -1;
static int hf_vntag_len = -1;
static int hf_vntag_trailer = -1;

static gint ett_vntag = -1;

static void
dissect_vntag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint16     encap_proto;
	proto_tree *vntag_tree = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "VNTAG");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		proto_item *ti = proto_tree_add_item(tree, proto_vntag, tvb, 0, 4, ENC_NA);

		vntag_tree = proto_item_add_subtree(ti, ett_vntag);

		/* XXX, 4 bytes of data */

		/* from scapy (http://hg.secdev.org/scapy-com/rev/37acec891993) GPLv2:

		   BitField("dir",     0, 1),
		   BitField("ptr",     0, 1),
		   BitField("dst",     0, 14),
		   BitField("looped",  0, 1),
		   BitField("r",       0, 1),
		   BitField("version", 0, 2),
		   BitField("src",     0, 12) ]
		*/
		/* another: http://www.definethecloud.net/access-layer-network-virtualization-vn-tag-and-vepa */
	}

	encap_proto = tvb_get_ntohs(tvb, 4);

	/* copied from packet-vlan.c do we need it also for VNTAG? */
#if 0
	if (encap_proto <= IEEE_802_3_MAX_LEN) {
		gboolean is_802_2;

		/* Is there an 802.2 layer? I can tell by looking at the first 2
		   bytes after the VLAN header. If they are 0xffff, then what
		   follows the VLAN header is an IPX payload, meaning no 802.2.
		   (IPX/SPX is they only thing that can be contained inside a
		   straight 802.3 packet, so presumably the same applies for
		   Ethernet VLAN packets). A non-0xffff value means that there's an
		   802.2 layer inside the VLAN layer */
		is_802_2 = TRUE;

		/* Don't throw an exception for this check (even a BoundsError) */
		if (tvb_length_remaining(tvb, 4) >= 2) {
			if (tvb_get_ntohs(tvb, 4) == 0xffff)
				is_802_2 = FALSE;
		}

		dissect_802_3(encap_proto, is_802_2, tvb, 4, pinfo, tree, vntag_tree, hf_vntag_len, hf_vntag_trailer, 0);
	} else
#endif
		ethertype(encap_proto, tvb, 6, pinfo, tree, vntag_tree, hf_vntag_etype, hf_vntag_trailer, 0);
}

void
proto_register_vntag(void)
{
	static hf_register_info hf[] = {
		{ &hf_vntag_etype,
			{ "Type", "vntag.etype", FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0, NULL, HFILL }
		},
		{ &hf_vntag_len,
			{ "Length", "vntag.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_vntag_trailer,
			{ "Trailer", "vntag.trailer", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }
		}
	};

	static gint *ett[] = {
		&ett_vntag
	};

	proto_vntag = proto_register_protocol("VN-Tag", "VNTAG", "vntag");
	proto_register_field_array(proto_vntag, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vntag(void)
{
	dissector_handle_t vntag_handle;

	/* XXX, add 0x8926 define to epan/etypes.h && etype_vals */

	vntag_handle = create_dissector_handle(dissect_vntag, proto_vntag);
	dissector_add_uint("ethertype", 0x8926, vntag_handle);
}
