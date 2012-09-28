/* packet-pw-hdlc.c
 * Routines for HDLC PW dissection as per RFC4618.
 * Copyright 2009, Dmitry Trebich, Artem Tamazov <artem.tamazov@tellabs.com>
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
 *
 * History:
 * ---------------------------------
 * 02.03.2009 Initial implementation, supports:
 * - HDLC mode (rfc4618 5.1), no CW, payload is PPP (PPP in HDLC-like Framing (rfc1662)).
 * - FR port mode (rfc4618 5.2), no CW.
 *
 * [informative: Not supported yet:
 * - All kinds of HDLC PW with CW.
 * - PPP mode (rfc4618 5.3).
 * - For HDLC mode, decoding payloads other than PPP.]
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#include "packet-mpls.h"

static dissector_handle_t ppp_handle;
static dissector_handle_t fr_handle;

static gint proto_pw_hdlc_nocw_fr = -1;
static gint proto_pw_hdlc_nocw_hdlc_ppp = -1;

static gint ett_pw_hdlc = -1;

static int hf_pw_hdlc = -1;
static int hf_pw_hdlc_address_field = -1;
static int hf_pw_hdlc_address = -1;
static int hf_pw_hdlc_cr_bit = -1;
static int hf_pw_hdlc_control_field = -1;
static int hf_pw_hdlc_pf_bit = -1;

static void dissect_pw_hdlc_nocw_fr( tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree )
{
	call_dissector( fr_handle, tvb, pinfo, tree );
}


static void dissect_pw_hdlc_nocw_hdlc_ppp( tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree )
{
	if (tvb_reported_length_remaining(tvb, 0) < 2)
	{
		if (tree)
		{
			proto_tree_add_text(tree, tvb, 0, -1, "Error processing message");
		}
		return;
	}

	if (tree)
	{
		proto_tree  *tr;
		proto_item  *item;
		proto_item  *item_address;
		proto_item  *item_control;
		guint8      addr;
		guint8      control;

		addr	= tvb_get_guint8(tvb, 0);
		control	= tvb_get_guint8(tvb, 1);

		item = proto_tree_add_item( tree, proto_pw_hdlc_nocw_hdlc_ppp, tvb, 0, 2, ENC_NA );

		tr = proto_item_add_subtree( item, ett_pw_hdlc );

		item_address = proto_tree_add_uint( tr, hf_pw_hdlc_address_field, tvb, 0, 1, addr );
		item_control = proto_tree_add_uint_format( tr, hf_pw_hdlc_control_field, tvb, 1, 1, control, "Control field: 0x%x", control );

		tr = proto_item_add_subtree( item_address, ett_pw_hdlc );

		if ( 0x3F == (( addr & 0xFC ) >> 2 ))
			proto_tree_add_uint_format( tr, hf_pw_hdlc_address, tvb, 0, 1, 0xFC, "Address: 0x%x (All stations)", 0x3F );
		else
			proto_tree_add_uint( tr, hf_pw_hdlc_address, tvb, 0, 1, ( addr & 0xFC ) >> 2 );

		proto_tree_add_uint( tr, hf_pw_hdlc_cr_bit, tvb, 0, 1, ( addr & 2 ) >> 1 );

		tr = proto_item_add_subtree( item_control, ett_pw_hdlc );

		if ( control & 1 )
		{
			if ( control & 2 )
			{
				guint8 modifier2;
				guint8 modifier3;

				proto_tree_add_text( tr, tvb, 1, 1, "U frame" );

				proto_tree_add_uint( tr, hf_pw_hdlc_pf_bit, tvb, 1, 1, ( control & 0x10 ) >> 4 );

				modifier2 = (( control & 0xC ) >> 2 );
				modifier3 = (( control & 0xE0 ) >> 5 );

				/**/ if ( modifier2 == 0 && modifier3 == 0 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: UI - Unnumbered information" );
				else if ( modifier2 == 0 && modifier3 == 1 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: UP - Unnumbered poll" );
				else if ( modifier2 == 0 && modifier3 == 2 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: DISC/RD - Disconnect/Request disconnect" );
				else if ( modifier2 == 0 && modifier3 == 3 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: UA - Unnumbered acknowledgment" );
				else if ( modifier2 == 0 && modifier3 == 4 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: SNRM - Set normal response mode" );
				else if ( modifier2 == 0 && modifier3 == 7 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: TEST - Test" );
				else if ( modifier2 == 1 && modifier3 == 0 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: SIM/RIM"
						" - Set initialization mode/Request initialization mode" );
				else if ( modifier2 == 1 && modifier3 == 4 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: FRMR - Frame reject" );
				else if ( modifier2 == 3 && modifier3 == 0 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: SARM/DM"
						" - Set asynchronous response mode/Disconnect mode" );
				else if ( modifier2 == 3 && modifier3 == 1 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: SABM - Set asynchronous balanced mode" );
				else if ( modifier2 == 3 && modifier3 == 2 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: SARME - Set asynchronous response extended mode" );
				else if ( modifier2 == 3 && modifier3 == 3 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: SABME - Set asynchronous balanced extended mode" );
				else if ( modifier2 == 3 && modifier3 == 4 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: RSET - Reset" );
				else if ( modifier2 == 3 && modifier3 == 5 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: XID - Exchange identification" );
				else if ( modifier2 == 3 && modifier3 == 6 )
					proto_tree_add_text( tr, tvb, 1, 1,
						"Modifier: SNRME - Set normal response extended mode" );
			}
			else
			{
				proto_tree_add_text( tr, tvb, 1, 1, "S frame" );
			}
		}
		else
		{
			proto_tree_add_text( tr, tvb, 1, 1, "I frame" );
		}
	}
	call_dissector( ppp_handle, tvb_new_subset_remaining(tvb, 2), pinfo, tree );
}

void proto_register_pw_hdlc(void)
{
	static hf_register_info hf[] = {
		{
			&hf_pw_hdlc,
			{
				"PW HDLC", "pw_hdlc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_pw_hdlc_address_field,
			{
				"Address field", "pw_hdlc.address_field",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_pw_hdlc_address,
			{
				"Address", "pw_hdlc.address",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_pw_hdlc_cr_bit,
			{
				"C/R bit", "pw_hdlc.cr_bit",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_pw_hdlc_control_field,
			{
				"Control field", "pw_hdlc.control_field",
				FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL
			}
		},
		{
			&hf_pw_hdlc_pf_bit,
			{
				"Poll/Final bit", "pw_hdlc.pf_bit",
				FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
			}
		}
	};

	static gint *ett[] = {
		&ett_pw_hdlc
	};

	proto_pw_hdlc_nocw_fr = proto_register_protocol("HDLC PW, FR port mode (no CW)", /*not displayed*/
							"HDLC PW, FR port mode (no CW)",
							"pw_hdlc_nocw_fr" );
	proto_pw_hdlc_nocw_hdlc_ppp = proto_register_protocol("HDLC-like framing for PPP",
							      "HDLC PW with PPP payload (no CW)",
							      "pw_hdlc_nocw_hdlc_ppp" );

	proto_register_field_array(proto_pw_hdlc_nocw_fr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("pw_hdlc_nocw_fr", dissect_pw_hdlc_nocw_fr, proto_pw_hdlc_nocw_fr );
	register_dissector("pw_hdlc_nocw_hdlc_ppp", dissect_pw_hdlc_nocw_hdlc_ppp, proto_pw_hdlc_nocw_hdlc_ppp );
}

void proto_reg_handoff_pw_hdlc(void)
{
	dissector_handle_t handle;

	handle = find_dissector("pw_hdlc_nocw_fr");
	dissector_add_uint( "mpls.label", MPLS_LABEL_INVALID, handle );

	handle = find_dissector("pw_hdlc_nocw_hdlc_ppp");
	dissector_add_uint( "mpls.label", MPLS_LABEL_INVALID, handle );

	ppp_handle = find_dissector( "ppp" );
	fr_handle = find_dissector( "fr" );
}
