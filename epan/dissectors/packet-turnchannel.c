/* packet-turnchannel.c
 * Routines for TURN channel dissection (TURN negociation is handled
 * in the STUN2 dissector
 * Copyright 2008, 8x8 Inc. <petithug@8x8.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Please refer to the following specs for protocol detail:
 * - draft-ietf-behave-rfc3489bis-15
 * - draft-ietf-mmusic-ice-19
 * - draft-ietf-behave-nat-behavior-discovery-03
 * - draft-ietf-behave-turn-07
 * - draft-ietf-behave-turn-ipv6-03
 *
 * XXX - these are now:
 * - RFC 5389
 * - RFC 5245
 * - RFC 5780
 * - RFC 5766
 * - RFC 6156
 * - RFC 8656
 *
 * Update as necessary.
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-tcp.h"

void proto_register_turnchannel(void);
void proto_reg_handoff_turnchannel(void);

/* heuristic subdissectors */
static heur_dissector_list_t heur_subdissector_list;

/* Initialize the protocol and registered fields */
static int proto_turnchannel = -1;

static int hf_turnchannel_id = -1;
static int hf_turnchannel_len = -1;

#define TURNCHANNEL_HDR_LEN	((guint)4)

#define MS_MULTIPLEX_TURN 0xFF10

/* Initialize the subtree pointers */
static gint ett_turnchannel = -1;

static dissector_handle_t turnchannel_tcp_handle;
static dissector_handle_t turnchannel_udp_handle;

/*
 * RFC 5764 defined a demultiplexing scheme to allow TURN is co-exist
 * on the same 5-tuple as STUN, DTLS, RTP/RTCP, and ZTLS by rejecting
 * previous reserved channel numbers, restricting the channel numbers
 * to 0x4000-0x7FFF. RFC 5766 (TURN) did not incorporate the restriction,
 * but RFC 8656 did, further restricting the channel numbers to the
 * range 0x4000-0x4FFF.
 *
 * Reject channel numbers outside 0x4000-0x7FFF (except for the special
 * MS-TURN multiplex channel number), since no implementation has used
 * any value outside that range, and the 0x5000-0x7FFF range is reserved
 * in the multiplexing scheme.
 */
static gboolean
test_turnchannel_id(guint16 channel_id)
{
	if ((channel_id & 0x4000) == 0x4000 || channel_id == MS_MULTIPLEX_TURN)
		return TRUE;

	return FALSE;
}

static int
dissect_turnchannel_message(tvbuff_t *tvb, packet_info *pinfo,
			    proto_tree *tree, void *data _U_)
{
	guint   len;
	guint16 channel_id;
	guint16 data_len;
	proto_item *ti;
	proto_tree *turnchannel_tree;
	heur_dtbl_entry_t *hdtbl_entry;

	len = tvb_captured_length(tvb);
	/* First, make sure we have enough data to do the check. */
	if (len < TURNCHANNEL_HDR_LEN) {
		  return 0;
	}

	channel_id = tvb_get_ntohs(tvb, 0);
	data_len = tvb_get_ntohs(tvb, 2);

	if (!test_turnchannel_id(channel_id)) {
	  return 0;
	}

	if (len != TURNCHANNEL_HDR_LEN + data_len) {
	  return 0;
	}

	/* Seems to be a decent TURN channel message */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TURN CHANNEL");

	col_add_fstr(pinfo->cinfo, COL_INFO, "Channel Id 0x%x", channel_id);

	ti = proto_tree_add_item(tree, proto_turnchannel, tvb, 0, -1, ENC_NA);

	turnchannel_tree = proto_item_add_subtree(ti, ett_turnchannel);

	proto_tree_add_uint(turnchannel_tree, hf_turnchannel_id, tvb, 0, 2, channel_id);
	proto_tree_add_uint(turnchannel_tree, hf_turnchannel_len, tvb, 2, 2, data_len);

	if (len > TURNCHANNEL_HDR_LEN) {
	  tvbuff_t *next_tvb;
	  guint reported_len, new_len;

	  new_len = tvb_captured_length_remaining(tvb, TURNCHANNEL_HDR_LEN);
	  reported_len = tvb_reported_length_remaining(tvb,
						       TURNCHANNEL_HDR_LEN);
	  if (data_len < reported_len) {
	    reported_len = data_len;
	  }
	  next_tvb = tvb_new_subset_length_caplen(tvb, TURNCHANNEL_HDR_LEN, new_len,
				    reported_len);


	  if (!dissector_try_heuristic(heur_subdissector_list,
				       next_tvb, pinfo, tree, &hdtbl_entry, NULL)) {
	    call_data_dissector(next_tvb, pinfo, tree);
	  }
	}

	return tvb_captured_length(tvb);
}

static guint
get_turnchannel_message_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                            int offset, void *data _U_)
{
	guint16 channel_id;
	channel_id = tvb_get_ntohs(tvb, 0);
	/* If the channel number is outside the range, either we missed
         * a TCP segment or this is STUN, DTLS, RTP, etc. multiplexed on
         * the same 5-tuple. Report the length as the rest of the packet
         * and dissect_turnchannel_message will reject it, rather than
         * using a bogus PDU length and messing up the dissection of
         * future TURN packets.
         */
	if (!test_turnchannel_id(channel_id)) {
		return tvb_reported_length(tvb);
	}
	return (guint)tvb_get_ntohs(tvb, offset+2) + TURNCHANNEL_HDR_LEN;
}

static int
dissect_turnchannel_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, TURNCHANNEL_HDR_LEN,
			get_turnchannel_message_len, dissect_turnchannel_message, data);
	return tvb_captured_length(tvb);
}


static gboolean
dissect_turnchannel_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	guint   len;
	guint16 channel_id;
	guint16 data_len;

	len = tvb_captured_length(tvb);
	/* First, make sure we have enough data to do the check. */
	if (len < TURNCHANNEL_HDR_LEN) {
		  return FALSE;
	}

	channel_id = tvb_get_ntohs(tvb, 0);
	data_len = tvb_get_ntohs(tvb, 2);

	if (!test_turnchannel_id(channel_id)) {
	  return FALSE;
	}

	if (len != TURNCHANNEL_HDR_LEN + data_len) {
	  return FALSE;
	}

	return dissect_turnchannel_message(tvb, pinfo, tree, NULL);
}

void
proto_register_turnchannel(void)
{
	static hf_register_info hf[] = {
		{ &hf_turnchannel_id,
			{ "TURN Channel ID",	"turnchannel.id",	FT_UINT16,
			BASE_HEX,	NULL,	0x0, 	NULL,	HFILL }
		},
		{ &hf_turnchannel_len,
			{ "Data Length",  "turnchannel.length",	FT_UINT16,
			BASE_DEC,	NULL,	0x0, 	NULL,	HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_turnchannel,
	};

/* Register the protocol name and description */
	proto_turnchannel = proto_register_protocol("TURN Channel",
	    "TURNCHANNEL", "turnchannel");

	turnchannel_tcp_handle = register_dissector("turnchannel-tcp", dissect_turnchannel_tcp, proto_turnchannel);
	turnchannel_udp_handle = register_dissector("turnchannel", dissect_turnchannel_message, proto_turnchannel);

/* subdissectors */
	/* XXX: Nothing actually registers to this list. All dissectors register
         * to the heuristic subdissector list for STUN, since the STUN dissector
         * doesn't actually call this dissector but uses its own implementation
         * of TURN Channel messages.
         */
	heur_subdissector_list = register_heur_dissector_list("turnchannel", proto_turnchannel);

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_turnchannel, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_turnchannel(void)
{
	/* Register for "Decode As" in case STUN negotiation isn't captured */
	dissector_add_for_decode_as_with_preference("tcp.port", turnchannel_tcp_handle);
	dissector_add_for_decode_as_with_preference("udp.port", turnchannel_udp_handle);

	/*
	 * SSL/TLS and DTLS Application-Layer Protocol Negotiation (ALPN)
	 * protocol ID.
	 */
	dissector_add_string("tls.alpn", "stun.turn", turnchannel_tcp_handle);
	dissector_add_string("dtls.alpn", "stun.turn", turnchannel_udp_handle);

	/* TURN negotiation is handled through STUN2 dissector (packet-stun.c),
	   so only it should be able to determine if a packet is a TURN packet */
	heur_dissector_add("stun", dissect_turnchannel_heur, "TURN Channel over STUN", "turnchannel_stun", proto_turnchannel, HEURISTIC_ENABLE);
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
