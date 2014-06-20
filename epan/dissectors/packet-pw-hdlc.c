/* packet-pw-hdlc.c
 * Routines for HDLC PW dissection as per RFC4618.
 * Copyright 2009, Dmitry Trebich, Artem Tamazov <artem.tamazov@tellabs.com>
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

void proto_register_pw_hdlc(void);
void proto_reg_handoff_pw_hdlc(void);

static dissector_handle_t ppp_handle;
static dissector_handle_t fr_handle;

static gint proto_pw_hdlc_nocw_fr = -1;
static gint proto_pw_hdlc_nocw_hdlc_ppp = -1;

static gint ett_pw_hdlc = -1;

/* static int hf_pw_hdlc = -1; */
static int hf_pw_hdlc_address_field = -1;
static int hf_pw_hdlc_address = -1;
static int hf_pw_hdlc_cr_bit = -1;
static int hf_pw_hdlc_control_field = -1;
static int hf_pw_hdlc_pf_bit = -1;
static int hf_pw_hdlc_modifier = -1;

static const value_string pw_hdlc_modifier_vals[] = {
	{0x00, "UI - Unnumbered information" },
	{0x08, "UP - Unnumbered poll" },
	{0x10, "DISC/RD - Disconnect/Request disconnect" },
	{0x18, "UA - Unnumbered acknowledgment" },
	{0x20, "SNRM - Set normal response mode" },
	{0x38, "TEST - Test" },
	{0x01, "SIM/RIM - Set initialization mode/Request initialization mode" },
	{0x21, "FRMR - Frame reject" },
	{0x03, "SARM/DM - Set asynchronous response mode/Disconnect mode" },
	{0x0B, "SABM - Set asynchronous balanced mode" },
	{0x13, "SARME - Set asynchronous response extended mode" },
	{0x1B, "SABME - Set asynchronous balanced extended mode" },
	{0x23, "RSET - Reset" },
	{0x2B, "XID - Exchange identification" },
	{0x33, "SNRME - Set normal response extended mode" },
	{0, NULL }
};

static void dissect_pw_hdlc_nocw_fr( tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree )
{
	call_dissector( fr_handle, tvb, pinfo, tree );
}


static void dissect_pw_hdlc_nocw_hdlc_ppp( tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree )
{
	if (tvb_reported_length_remaining(tvb, 0) < 2)
	{
		proto_tree_add_text(tree, tvb, 0, -1, "Error processing message");
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

		item_address = proto_tree_add_item( tr, hf_pw_hdlc_address_field, tvb, 0, 1, ENC_NA );
		item_control = proto_tree_add_item( tr, hf_pw_hdlc_control_field, tvb, 1, 1, ENC_NA );

		tr = proto_item_add_subtree( item_address, ett_pw_hdlc );

		if ( 0x3F == (( addr & 0xFC ) >> 2 ))
			proto_tree_add_uint_format_value( tr, hf_pw_hdlc_address, tvb, 0, 1, 0xFC, "0x%x (All stations)", 0x3F );
		else
			proto_tree_add_uint( tr, hf_pw_hdlc_address, tvb, 0, 1, ( addr & 0xFC ) >> 2 );

		proto_tree_add_uint( tr, hf_pw_hdlc_cr_bit, tvb, 0, 1, ( addr & 2 ) >> 1 );

		tr = proto_item_add_subtree( item_control, ett_pw_hdlc );

		if ( control & 1 )
		{
			if ( control & 2 )
			{
				proto_tree_add_text( tr, tvb, 1, 1, "U frame" );

				proto_tree_add_uint( tr, hf_pw_hdlc_pf_bit, tvb, 1, 1, ( control & 0x10 ) >> 4 );
				proto_tree_add_uint( tr, hf_pw_hdlc_modifier, tvb, 1, 1, (control & 0xEC) >> 2);
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
#if 0
		{
			&hf_pw_hdlc,
			{
				"PW HDLC", "pw_hdlc", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL
			}
		},
#endif
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
		},
		{
			&hf_pw_hdlc_modifier,
			{
				"Modifier", "pw_hdlc.modifier",
				FT_UINT8, BASE_HEX, VALS(pw_hdlc_modifier_vals), 0x0, NULL, HFILL
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
	dissector_add_for_decode_as( "mpls.label", handle );

	handle = find_dissector("pw_hdlc_nocw_hdlc_ppp");
	dissector_add_for_decode_as( "mpls.label", handle );

	ppp_handle = find_dissector( "ppp" );
	fr_handle = find_dissector( "fr" );
}
