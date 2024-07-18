/* packet-redbackli.c
 *
 * Redback Lawful Intercept Packet dissector
 *
 * Copyright 2008 Florian Lohoff <flo[AT]rfc822.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_redbackli(void);
void proto_reg_handoff_redbackli(void);

static int proto_redbackli;

static int hf_redbackli_avptype;
static int hf_redbackli_avplen;
static int hf_redbackli_seqno;		/* Sequence No */
static int hf_redbackli_liid;		/* LI Id */
static int hf_redbackli_sessid;		/* Session Id */
static int hf_redbackli_label;		/* Label */
static int hf_redbackli_acctid;		/* Accounting Session Id */
static int hf_redbackli_dir;		/* Direction */
static int hf_redbackli_eohpad;		/* End Of Header Padding */
static int hf_redbackli_unknownavp;	/* Unknown AVP */

static int ett_redbackli;

static dissector_handle_t ip_handle;
static dissector_handle_t redbackli_handle;


#define RB_AVP_SEQNO	1
#define RB_AVP_LIID	2
#define RB_AVP_SESSID	3
#define RB_AVP_DIR	4
#define RB_AVP_LABEL	20
#define RB_AVP_ACCTID	40
#define RB_AVP_EOH	0

static const value_string avp_names[] = {
	{RB_AVP_SEQNO,		"Sequence No"},
	{RB_AVP_LIID,		"Lawful Intercept Id"},
	{RB_AVP_SESSID,		"Session Id"},
	{RB_AVP_LABEL,		"Label"},
	{RB_AVP_ACCTID,		"Accounting Session Id"},
	{RB_AVP_DIR,		"Direction"},
	{RB_AVP_EOH,		"End Of Header"},
	{0,			NULL}
};

static void
redbackli_dissect_avp(uint8_t avptype, uint8_t avplen, tvbuff_t *tvb, int offset, proto_tree *tree)
{
	const char	*avpname;
	proto_tree	*st = NULL;

	avpname = val_to_str_const(avptype, avp_names, "Unknown");

	st = proto_tree_add_subtree_format(tree, tvb, offset, avplen+2, ett_redbackli, NULL, "%s AVP", avpname);

	proto_tree_add_uint(st, hf_redbackli_avptype, tvb, offset, 1, avptype);
	proto_tree_add_uint(st, hf_redbackli_avplen, tvb, offset+1, 1, avplen);

	if (!avplen)
		return;

	/* XXX: ToDo: Validate the length (avplen) of the fixed length fields
	   before calling proto_tree_add_item().
	   Note that the field lengths have been validated when
	   dissect_avp() is called from redbackli_dissect_heur().
	*/

	switch (avptype) {
		case(RB_AVP_SEQNO):
			proto_tree_add_item(st, hf_redbackli_seqno, tvb,
					    offset+2, avplen, ENC_BIG_ENDIAN);
			break;
		case(RB_AVP_LIID):
			proto_tree_add_item(st, hf_redbackli_liid, tvb,
					    offset+2, avplen, ENC_BIG_ENDIAN);
			break;
		case(RB_AVP_SESSID):
			proto_tree_add_item(st, hf_redbackli_sessid, tvb,
					    offset+2, avplen, ENC_BIG_ENDIAN);
			break;
		case(RB_AVP_LABEL):
			proto_tree_add_item(st, hf_redbackli_label, tvb,
					    offset+2, avplen, ENC_ASCII);
			break;
		case(RB_AVP_EOH):
			proto_tree_add_item(st, hf_redbackli_eohpad, tvb,
					    offset+2, avplen, ENC_NA);
			break;
		case(RB_AVP_DIR):
			proto_tree_add_item(st, hf_redbackli_dir, tvb,
					offset+2, avplen, ENC_NA);
			break;
		case(RB_AVP_ACCTID):
			proto_tree_add_item(st, hf_redbackli_acctid, tvb,
					    offset+2, avplen, ENC_NA);
			break;
		default:
			proto_tree_add_item(st, hf_redbackli_unknownavp, tvb,
					    offset+2, avplen, ENC_NA);
			break;
	}

	return;
}

static int
redbackli_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	uint8_t		avptype, avplen;
	int		len, offset = 0;
	bool	eoh;
	proto_item	*ti;
	proto_tree	*redbackli_tree = NULL;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RBLI");

	ti = proto_tree_add_item(tree, proto_redbackli,
					 tvb, 0, -1, ENC_NA);
	redbackli_tree = proto_item_add_subtree(ti, ett_redbackli);

	len = tvb_reported_length(tvb);
	offset = 0;
	eoh = false;
	while (!eoh && (len > 2)) {
		avptype = tvb_get_uint8(tvb, offset+0);
		avplen = tvb_get_uint8(tvb, offset+1);

		if ((len-2) < avplen)		/* AVP Complete ? */
			break;

		if (tree)
			redbackli_dissect_avp(avptype, avplen, tvb, offset, redbackli_tree);

		if (avptype == RB_AVP_EOH)
			eoh = true;

		offset += 2 + avplen;
		len    -= 2 + avplen;
	}

	next_tvb = tvb_new_subset_remaining(tvb, offset);
	call_dissector(ip_handle, next_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}


#define REDBACKLI_INTSIZE	6
#define REDBACKLI_EOHSIZE	2
#define MIN_REDBACKLI_SIZE	(3*REDBACKLI_INTSIZE+REDBACKLI_EOHSIZE)

static bool
redbackli_dissect_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	int		len, offset = 0;
	bool	eoh = false;
	uint8_t		avptype, avplen;
	uint32_t		avpfound = 0;

	len = tvb_captured_length(tvb);
	if (len < MIN_REDBACKLI_SIZE)
		return false;

	/*
	 * We scan the possible AVPs and look out for mismatches.
	 * An int AVP needs to be 4 byte long, and the eoh must be 0 or 1
	 * long .. Unknown AVPs also mean not for us ...
	 *
	 */
	while ((len > 2) && !eoh) {
		avptype = tvb_get_uint8(tvb, offset+0);
		avplen = tvb_get_uint8(tvb, offset+1);

		switch (avptype) {
			case(RB_AVP_SEQNO):
			case(RB_AVP_LIID):
			case(RB_AVP_SESSID):
				if (avplen != 4)
					return false;
				avpfound |= 1<<avptype;
				break;
			case(RB_AVP_EOH):
				if (avplen > 1 || offset == 0)
					return false;
				eoh = true;
				break;
			case(RB_AVP_LABEL):
			case(RB_AVP_DIR):   /* Is this correct? the hf_ originally had FT_UINT8 for DIR */
			case(RB_AVP_ACCTID):
				break;
			default:
				return false;
		}
		offset += 2 + avplen;
		len    -= 2 + avplen;
	}

	if (!(avpfound & (1<<RB_AVP_SEQNO)))
		return false;
	if (!(avpfound & (1<<RB_AVP_SESSID)))
		return false;
	if (!(avpfound & (1<<RB_AVP_LIID)))
		return false;

	redbackli_dissect(tvb, pinfo, tree, data);

	return true;
}
void proto_register_redbackli(void) {
	static hf_register_info hf[] = {
		{ &hf_redbackli_avptype,
			{ "AVP Type", "redbackli.avptype", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redbackli_avplen,
			{ "AVP Length", "redbackli.avplen", FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redbackli_seqno,
			{ "Sequence No", "redbackli.seqno", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redbackli_liid,
			{ "Lawful Intercept Id", "redbackli.liid", FT_UINT32, BASE_DEC, NULL, 0x0,
			"LI Identifier", HFILL }},
		{ &hf_redbackli_sessid,
			{ "Session Id", "redbackli.sessid", FT_UINT32, BASE_DEC, NULL, 0x0,
			"Session Identifier", HFILL }},
		/* XXX: If one goes by the heuristic then this field can be variable length ??
		 * In the absence of any documentation We'll assume that's the case
		 * (even though 'direction' sounds like a fixed length field
		 */
		{ &hf_redbackli_dir,
			{ "Direction", "redbackli.dir", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redbackli_label,
			{ "Label", "redbackli.label", FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redbackli_acctid,
			{ "Acctid", "redbackli.acctid", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redbackli_eohpad,
			{ "End of Header Padding", "redbackli.eohpad", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redbackli_unknownavp,
			{ "Unknown AVP", "redbackli.unknownavp", FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }}
		};

	static int *ett[] = {
		&ett_redbackli
	};

	proto_redbackli = proto_register_protocol("Redback Lawful Intercept", "RedbackLI", "redbackli");

	proto_register_field_array(proto_redbackli, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	redbackli_handle = register_dissector("redbackli", redbackli_dissect, proto_redbackli);
}

void proto_reg_handoff_redbackli(void) {
	ip_handle = find_dissector_add_dependency("ip", proto_redbackli);

	dissector_add_for_decode_as_with_preference("udp.port", redbackli_handle);

	heur_dissector_add("udp", redbackli_dissect_heur, "Redback Lawful Intercept over UDP", "redbackli_udp", proto_redbackli, HEURISTIC_ENABLE);
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
