/* packet-pw-fr.c
 * Routines for Frame Relay MPLS PW dissection as per RFC4619.
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
 * 18.03.2009 initial implementation
 * - FR DLCI mode
 * Not supported yet:
 * - Correct FR decode for encapsulations which contain fragmented FR frames.
 * - FR DLCI Martini (legacy) mode (i.e. legacy CW).
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-mpls.h"

void proto_register_pw_fr(void);
void proto_reg_handoff_pw_fr(void);

static gint proto_encaps = -1;
static gint ett_encaps = -1;

/* static int hf_pw_fr = -1; */
static int hf_cw_bits03 = -1;
static int hf_cw_fecn = -1;
static int hf_cw_becn = -1;
static int hf_cw_de = -1;
static int hf_cw_cr = -1;
static int hf_cw_frg = -1;
static int hf_cw_len = -1;
static int hf_cw_seq = -1;

static expert_field ei_payload_size_invalid = EI_INIT;
static expert_field ei_cw_bits03 = EI_INIT;
static expert_field ei_cw_packet_size_too_small = EI_INIT;

static const value_string vals_frg[] = {
	{ 0x0,	"Unfragmented" },
	{ 0x1,	"First fragment" },
	{ 0x2,	"Last fragment" },
	{ 0x3,	"Intermediate fragment" },
	{ 0,	NULL }
};


static dissector_handle_t fr_stripped_address_handle;


static void
dissect_pw_fr( tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree )
{
	gint packet_size;
	gint payload_size;
	gint payload_padding;
	const int encaps_size = 4; /*encapsulation consists of mandatory CW only*/
	enum {
		PQ_CW_BAD		       = 0x001
		,PQ_CW_BAD_BITS03	       = 0x002
		,PQ_CW_BAD_LEN_GT_PACKET       = 0x004
		,PQ_CW_BAD_LEN_MUST_BE_ZERO    = 0x008
		,PQ_CW_BAD_LEN_MUST_BE_NONZERO = 0x010
		,PQ_PAYLOAD_SIZE_ZERO	       = 0x020
	};
	int packet_quality;

	packet_size = tvb_reported_length_remaining(tvb, 0);
	if (packet_size < encaps_size)
	{
		{
			proto_item  *item;
			item = proto_tree_add_item(tree, proto_encaps, tvb, 0, -1, ENC_NA);
			expert_add_info_format(pinfo, item, &ei_cw_packet_size_too_small,
				"PW packet (%d) is smaller than PW encapsulation header (%d)",
				(int)packet_size,(int)encaps_size);
		}
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "FR PW");
		col_set_str(pinfo->cinfo, COL_INFO, "Malformed: PW packet < PW encapsulation header");
		return;
	}

	if (dissect_try_cw_first_nibble(tvb,pinfo,tree))
	{
		return;
	}

	/* check how "good" is this packet */
	/* also decide payload length from packet size and CW */
	packet_quality = 0;
	if (0 != (tvb_get_guint8(tvb, 0) & 0xf0 /*bits03*/))
	{
		packet_quality |= PQ_CW_BAD + PQ_CW_BAD_BITS03;
	}
	{
		/* RFC4619:
		 * [ If the frame's length (defined as the
		 * length of the layer 2 payload plus the length of the control word)
		 * is less than 64 octets, the length field MUST be set to the PW
		 * payload length.  Otherwise, the length field MUST be set to zero. ]
		 *
		 * Note difference from RFC4385 which states that:
		 * [..the length field MUST be set to the length of the PW payload
		 * *plus* the length of the *PWMCW*. ]
		 */
		int cw_len;
		gint payload_size_packet; /*derived from packet size*/

		cw_len = tvb_get_guint8(tvb, 1) & 0x3f;
		payload_size_packet = packet_size - encaps_size;

		/*
		 * Initial assumptions.
		 */
		payload_size = payload_size_packet;
		payload_padding = 0;

		if (payload_size_packet < 64)
		{
			gint payload_size_cw; /*derived from cw*/
			payload_size_cw = cw_len; /*RFC4619-specific*/
			if (payload_size_cw == 0)
			{
				packet_quality |= PQ_CW_BAD + PQ_CW_BAD_LEN_MUST_BE_NONZERO;
			}
			else if (payload_size_cw > payload_size_packet)
			{
				packet_quality |= PQ_CW_BAD + PQ_CW_BAD_LEN_GT_PACKET;
			}
			else /* ok */
			{
				payload_size = payload_size_cw;
				payload_padding = payload_size_packet - payload_size_cw; /* >=0 */
			}
		}
		else /* payload_size_packet >= 64 */
		{
			if (cw_len != 0)
			{
				packet_quality |= PQ_CW_BAD + PQ_CW_BAD_LEN_MUST_BE_ZERO;
			}
		}
	}
	if (payload_size == 0)
	{
		packet_quality |= PQ_PAYLOAD_SIZE_ZERO;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "FR PW");
	col_clear(pinfo->cinfo, COL_INFO);
	if (packet_quality & PQ_CW_BAD)
	{
		col_set_str(pinfo->cinfo, COL_INFO, "CW:Malformed, ");
	}
	col_append_fstr(pinfo->cinfo, COL_INFO, "%d payload octets", (int)payload_size);

	if (payload_padding != 0)
	{
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %d padding", (int)payload_padding);
	}

	{
		proto_tree* subtree;
		proto_item* item_headline;
		proto_item* item;

		item_headline = proto_tree_add_item(tree, proto_encaps, tvb, 0, 4, ENC_NA);
		proto_item_append_text(item_headline, ": 0x%.8" G_GINT32_MODIFIER "x", tvb_get_ntohl(tvb, 0));
		subtree = proto_item_add_subtree(item_headline, ett_encaps);

		if (packet_quality & PQ_CW_BAD_BITS03) /*display only if value is wrong*/
		{
			item = proto_tree_add_item(subtree, hf_cw_bits03, tvb, 0, 1, ENC_BIG_ENDIAN);
			expert_add_info(pinfo, item, &ei_cw_bits03);
		}

		(void)proto_tree_add_item( subtree, hf_cw_fecn, tvb, 0, 1, ENC_BIG_ENDIAN );
		(void)proto_tree_add_item( subtree, hf_cw_becn, tvb, 0, 1, ENC_BIG_ENDIAN );
		(void)proto_tree_add_item( subtree, hf_cw_de,   tvb, 0, 1, ENC_BIG_ENDIAN );
		(void)proto_tree_add_item( subtree, hf_cw_cr,   tvb, 0, 1, ENC_BIG_ENDIAN );
		(void)proto_tree_add_item( subtree, hf_cw_frg,  tvb, 1, 1, ENC_BIG_ENDIAN );

		item = proto_tree_add_item( subtree, hf_cw_len, tvb, 1, 1, ENC_BIG_ENDIAN );
		if (packet_quality & PQ_CW_BAD_LEN_GT_PACKET)
		{
			expert_add_info_format(pinfo, item, &ei_payload_size_invalid,
				"Bad Length: greater than FR payload size (%d)",
				(int)payload_size);
		}
		if (packet_quality & PQ_CW_BAD_LEN_MUST_BE_NONZERO)
		{
			expert_add_info_format(pinfo, item, &ei_payload_size_invalid,
				"Bad Length: must be non-zero if FR PW packet size (%d) is < 64",
				(int)(payload_size+encaps_size));
		}
		if (packet_quality & PQ_CW_BAD_LEN_MUST_BE_ZERO)
		{
			expert_add_info_format(pinfo, item, &ei_payload_size_invalid,
				"Bad Length: must be 0 if FR PW packet size (%d) is >= 64",
				(int)(payload_size+encaps_size));
		}

		proto_tree_add_item( subtree, hf_cw_seq, tvb, 2, 2, ENC_BIG_ENDIAN );

		if (payload_padding > 0)
		{
			proto_tree_add_text(subtree, tvb,
				encaps_size+payload_size, payload_padding,
				"[Padding: %d octets]",(int)payload_padding);
		}

		if (packet_quality & PQ_PAYLOAD_SIZE_ZERO)
		{
			expert_add_info_format(pinfo, item_headline, &ei_payload_size_invalid,
				"FR payload size must be non-zero");
		}

	}
	if (payload_size > 0)
	{
		tvbuff_t *tvb_payload;
		tvb_payload = tvb_new_subset_length(tvb, encaps_size, payload_size);
		call_dissector( fr_stripped_address_handle, tvb_payload, pinfo, tree );
	}
	return;
}


void
proto_register_pw_fr(void)
{
static hf_register_info hf[] = {
	{&hf_cw_bits03	,{"Bits 0 to 3"		,"pwfr.bits03"	,FT_UINT8	,BASE_HEX
			  ,NULL			,0xf0		,NULL
			  ,HFILL }},

	{&hf_cw_fecn	,{"FR FECN"		,"pwfr.fecn"	,FT_UINT8	,BASE_DEC
			  ,NULL			,0x08		,"FR Forward Explicit Congestion Notification bit"
			  ,HFILL}},

	{&hf_cw_becn	,{"FR BECN"		,"pwfr.becn"	,FT_UINT8	,BASE_DEC
			  ,NULL			,0x04		,"FR Backward Explicit Congestion Notification bit"
			  ,HFILL}},

	{&hf_cw_de	,{"FR DE bit"		,"pwfr.de"	,FT_UINT8	,BASE_DEC
			  ,NULL			,0x02		,"FR Discard Eligibility bit"
			  ,HFILL}},

	{&hf_cw_cr	,{"FR Frame C/R"	,"pwfr.cr"	,FT_UINT8	,BASE_DEC
			  ,NULL			,0x01		,"FR frame Command/Response bit"
			  ,HFILL}},

	{&hf_cw_frg	,{"Fragmentation"	,"pwfr.frag"	,FT_UINT8	,BASE_DEC
			  ,VALS(vals_frg)	,0xc0		,NULL
			  ,HFILL}},

	{&hf_cw_len	,{"Length"		,"pwfr.length"	,FT_UINT8	,BASE_DEC
			  ,NULL			,0x3f		,NULL
			  ,HFILL}},

	{&hf_cw_seq	,{"Sequence number"	,"pwfr.length"	,FT_UINT16	,BASE_DEC
			  ,NULL			,0		,NULL
			  ,HFILL}}
};

	static gint *ett[] = {
		&ett_encaps
	};

	static ei_register_info ei[] = {
		{ &ei_cw_packet_size_too_small, { "pwfr.packet_size_too_small", PI_MALFORMED, PI_ERROR, "PW packet is smaller than PW encapsulation header", EXPFILL }},
		{ &ei_cw_bits03, { "pwfr.cw.bits03.not_zero", PI_MALFORMED, PI_ERROR, "Bits 0..3 of Control Word must be 0", EXPFILL }},
		{ &ei_payload_size_invalid, { "pwfr.payload.size_invalid", PI_MALFORMED, PI_ERROR, "Bad Length: greater than FR payload size", EXPFILL }},
	};
	expert_module_t* expert_pwfr;

	proto_encaps = proto_register_protocol( "PW Frame Relay DLCI Control Word",
						"Frame Relay DLCI PW",
						"pwfr");
	proto_register_field_array(proto_encaps, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_pwfr = expert_register_protocol(proto_encaps);
	expert_register_field_array(expert_pwfr, ei, array_length(ei));
	register_dissector("pw_fr", dissect_pw_fr, proto_encaps );
}


void
proto_reg_handoff_pw_fr(void)
{
	dissector_handle_t h;
	h = find_dissector("pw_fr");
	dissector_add_for_decode_as("mpls.label", h);
	fr_stripped_address_handle = find_dissector("fr_stripped_address");
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
