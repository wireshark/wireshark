/* packet-gsm_l2rcop.c
 * Routines for GSM L2RCOP (3GPP TS 27.002) dissection
 * (C) 2023 Harald Welte <laforge@osmocom.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/xdlc.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>

void proto_register_gsm_l2rcop(void);

static int proto_l2rcop;

static int hf_l2rcop_sa;
static int hf_l2rcop_sb;
static int hf_l2rcop_x;
static int hf_l2rcop_addr;
static int hf_l2rcop_break;
static int hf_l2rcop_break_ack;

static int ett_l2rcop;

static const value_string addr_vals[] = {
	{ 31, "last status change, remainder empty" },
	{ 30, "last status change, remainder full of characters" },
	{ 29, "destructive break signal, remainder empty" },
	{ 28, "destructive break acknowledge, remainder empty" },
	{ 27, "extended address in ext octet" },
	{ 0, NULL }
};

static void
add_characters(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, unsigned offset, unsigned len)
{
	tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, len);
	call_data_dissector(next_tvb, pinfo, tree);
}

/* Dissect a L2RCOP message as described in 3GPP TS 27.002 */
static int
dissect_l2rcop(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	int reported_len = tvb_reported_length(tvb);
	unsigned cur;

	/* we currently support RLP v0 + v1 (first octet is always status octet) */

	for (cur = 0; cur < (unsigned)reported_len; ) {
		uint8_t oct = tvb_get_guint8(tvb, cur);
		uint8_t addr = oct & 0x1f;
		proto_tree *l2rcop_tree;
		proto_item *ti;
		const char *addr_str = val_to_str(addr, addr_vals, "%u characters");

		ti = proto_tree_add_protocol_format(tree, proto_l2rcop, tvb, 0, reported_len,
						    "GSM L2RCOP Chunk Status=0x%02x (Addr: %s)", oct, addr_str);
		l2rcop_tree = proto_item_add_subtree(ti, ett_l2rcop);

		proto_tree_add_item(l2rcop_tree, hf_l2rcop_sa, tvb, cur, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(l2rcop_tree, hf_l2rcop_sb, tvb, cur, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(l2rcop_tree, hf_l2rcop_x, tvb, cur, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(l2rcop_tree, hf_l2rcop_addr, tvb, cur, 1, ENC_BIG_ENDIAN);

		switch (addr) {
		case 31: /* last status change, remainder empty */
			return reported_len;
		case 30: /* last status change, remainder full of characters */
			add_characters(l2rcop_tree, pinfo, tvb, cur+1, reported_len-cur-1);
			return reported_len;
		case 29: /* destructive break signal, remainder empty */
			proto_tree_add_item(l2rcop_tree, hf_l2rcop_break, tvb, cur, 1, ENC_BIG_ENDIAN);
			return reported_len;
		case 28: /* destructive break acknowledge, remainder empty */
			proto_tree_add_item(l2rcop_tree, hf_l2rcop_break_ack, tvb, cur, 1, ENC_BIG_ENDIAN);
			return reported_len;
		case 27: /* extended address in ext octet */
			cur++;
			addr = tvb_get_guint8(tvb, cur) & 0x3f;
			/* This "cannot happen"; let's abort processing right now. */
			if (addr == 0)
				return reported_len;
			proto_tree_add_uint(l2rcop_tree, hf_l2rcop_addr, tvb, cur, 1, addr);
			add_characters(l2rcop_tree, pinfo, tvb, cur+1, addr);
			cur += 1 + addr;
			break;
		case 0:
			/* This "cannot happen"; let's abort processing right now. */
			return reported_len;
		default:
			/* This "cannot happen"; let's abort processing right now. */
			if (addr == 0)
				return reported_len;
			add_characters(l2rcop_tree, pinfo, tvb, cur+1, addr);
			cur += 1 + addr;
			break;
		}
	}

	return reported_len;
}

static const true_false_string x_vals = {
	"flow control ACTIVE", "flow control inactive"
};


void
proto_register_gsm_l2rcop(void)
{
	static hf_register_info hf[] = {
		{ &hf_l2rcop_sa,
		  { "SA", "gsm_l2rcop.sa", FT_BOOLEAN, 8, TFS(&tfs_off_on), 0x80,
		    NULL, HFILL }},
		{ &hf_l2rcop_sb,
		  { "SB", "gsm_l2rcop.sb", FT_BOOLEAN, 8, TFS(&tfs_off_on), 0x40,
		    NULL, HFILL }},
		{ &hf_l2rcop_x,
		  { "X", "gsm_l2rcop.x", FT_BOOLEAN, 8, TFS(&x_vals), 0x20,
		    NULL, HFILL }},
		{ &hf_l2rcop_addr,
		  { "Address", "gsm_l2rcop.addr", FT_UINT8, BASE_DEC|BASE_SPECIAL_VALS, VALS(addr_vals), 0x1f,
		    NULL, HFILL }},
		{ &hf_l2rcop_break,
		  { "Break", "gsm_l2rcop.break", FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }},
		{ &hf_l2rcop_break_ack,
		  { "Break Ack", "gsm_l2rcop.break_ack", FT_UINT8, BASE_DEC, NULL, 0x00,
		    NULL, HFILL }},
	};
	static int *ett[] = {
		&ett_l2rcop,
	};

	proto_l2rcop = proto_register_protocol("GSM L2R Character Oriented Protocol (L2RCOP)", "GSM-L2RCOP",
						"gsm_l2rcop");
	proto_register_field_array(proto_l2rcop, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("gsm_l2rcop", dissect_l2rcop, proto_l2rcop);
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
