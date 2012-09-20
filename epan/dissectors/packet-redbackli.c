/* packet-redbackli.c
 *
 * $Id$
 *
 * Redback Lawful Intercept Packet dissector
 *
 * Copyright 2008 Florian Lohoff <flo[AT]rfc822.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald[AT]wireshark.org>
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>

static int proto_redbackli = -1;

static int hf_redbackli_seqno = -1;		/* Sequence No */
static int hf_redbackli_liid = -1;		/* LI Id */
static int hf_redbackli_sessid = -1;		/* Session Id */
static int hf_redbackli_label = -1;		/* Label */
static int hf_redbackli_acctid = -1;		/* Accounting Session Id */
static int hf_redbackli_dir = -1;		/* Direction */
static int hf_redbackli_eohpad = -1;		/* End Of Header Padding */
static int hf_redbackli_unknownavp = -1;	/* Unknown AVP */

static int ett_redbackli = -1;

static dissector_handle_t ip_handle;

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
redbackli_dissect_avp(guint8 avptype, guint8 avplen, tvbuff_t *tvb, gint offset, proto_tree *tree)
{
	const char	*avpname;
	proto_tree	*ti, *st=NULL;

	avpname=val_to_str_const(avptype, avp_names, "Unknown");

	ti = proto_tree_add_text(tree, tvb, offset, avplen+2, "%s AVP", avpname);
	st = proto_item_add_subtree(ti, ett_redbackli);

	proto_tree_add_text(st, tvb, offset, 1, "AVP Type: %d", avptype);
	proto_tree_add_text(st, tvb, offset+1, 1, "AVP Length: %d", avplen);

	if (!avplen)
		return;

        /* XXX: ToDo: Validate the length (avplen) of the fixed length fields
                before calling proto_tree_add_item().
                Note that the field lengths have been validated when
                dissect_avp() is called from redbackli_dissect_heur().
         */

	switch(avptype) {
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
					    offset+2, avplen, ENC_ASCII|ENC_NA);
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

static void
redbackli_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8		avptype, avplen;
	gint		len, offset=0;
	gboolean	eoh;
	proto_tree	*ti, *redbackli_tree=NULL;
	tvbuff_t	*next_tvb;

	col_set_str(pinfo->cinfo,COL_PROTOCOL,"RBLI");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_redbackli,
					 tvb, 0, -1, ENC_NA);
		redbackli_tree = proto_item_add_subtree(ti, ett_redbackli);
	}

	len=tvb_length(tvb);
	offset=0;
	eoh=FALSE;
	while(!eoh && (len > 2)) {
		avptype = tvb_get_guint8(tvb, offset+0);
		avplen = tvb_get_guint8(tvb, offset+1);

		if ((len-2) < avplen)		/* AVP Complete ? */
			break;

		if (tree)
			redbackli_dissect_avp(avptype, avplen, tvb, offset, redbackli_tree);

		if (avptype == RB_AVP_EOH)
			eoh=TRUE;

		offset+=2+avplen;
		len-=2+avplen;
	}

	next_tvb = tvb_new_subset_remaining(tvb, offset);
	call_dissector(ip_handle, next_tvb, pinfo, tree);
}


#define REDBACKLI_INTSIZE	6
#define REDBACKLI_EOHSIZE	2
#define MIN_REDBACKLI_SIZE	(3*REDBACKLI_INTSIZE+REDBACKLI_EOHSIZE)

static gboolean
redbackli_dissect_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	gint		len, offset=0;
	gboolean	eoh=FALSE;
	guint8		avptype, avplen;
	guint32		avpfound=0;

	len=tvb_length(tvb);
	if (len < MIN_REDBACKLI_SIZE)
		return FALSE;

	/*
	 * We scan the possible AVPs and look out for mismatches.
	 * An int AVP needs to be 4 byte long, and the eoh must be 0 or 1
	 * long .. Unknown AVPs also mean not for us ...
	 *
	 */
	while((len > 2) && !eoh) {
		avptype = tvb_get_guint8(tvb, offset+0);
		avplen = tvb_get_guint8(tvb, offset+1);

		switch(avptype) {
			case(RB_AVP_SEQNO):
			case(RB_AVP_LIID):
			case(RB_AVP_SESSID):
				if (avplen != 4)
					return FALSE;
				avpfound|=1<<avptype;
				break;
			case(RB_AVP_EOH):
				if (avplen > 1 || offset == 0)
					return FALSE;
				eoh=TRUE;
				break;
			case(RB_AVP_LABEL):
			case(RB_AVP_DIR):   /* Is this correct? the hf_ originally had FT_UINT8 for DIR */
			case(RB_AVP_ACCTID):
				break;
			default:
				return FALSE;
		}
		offset+=2+avplen;
		len-=2+avplen;
	}

	if (!(avpfound & (1<<RB_AVP_SEQNO)))
		return FALSE;
	if (!(avpfound & (1<<RB_AVP_SESSID)))
		return FALSE;
	if (!(avpfound & (1<<RB_AVP_LIID)))
		return FALSE;

	redbackli_dissect(tvb, pinfo, tree);

	return TRUE;
}
void proto_register_redbackli(void) {
	static hf_register_info hf[] = {
		{ &hf_redbackli_seqno,
			{ "Sequence No", "redbackli.seqno", FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }},
		{ &hf_redbackli_liid,
			{ "Lawful Intercept Id", "redbackli.liid", FT_UINT32, BASE_DEC, NULL, 0x0,
			"LI Identifier", HFILL }},
		{ &hf_redbackli_sessid,
			{ "Session Id", "redbackli.sessid", FT_UINT32, BASE_DEC, NULL, 0x0,
			"Session Identifier", HFILL }},
		{ &hf_redbackli_dir,
#if 0 /* XXX: If one goes by the heuristic then this field can be variable length ??
         In the absence of any documentation We'll assume that's the case
         (even though 'direction' sounds like a fixed length field */
			{ "Direction", "redbackli.dir", FT_UINT8, BASE_DEC, NULL, 0x0,
#endif
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

	static gint *ett[] = {
		&ett_redbackli
	};

	proto_redbackli = proto_register_protocol("Redback Lawful Intercept",
						  "RedbackLI","redbackli");

	proto_register_field_array(proto_redbackli,hf,array_length(hf));
	proto_register_subtree_array(ett,array_length(ett));

	register_dissector("redbackli", redbackli_dissect, proto_redbackli);
}

void proto_reg_handoff_redbackli(void) {
	dissector_handle_t redbackli_handle;

	ip_handle = find_dissector("ip");

	redbackli_handle = find_dissector("redbackli");
	dissector_add_handle("udp.port", redbackli_handle);  /* for 'decode-as' */

	heur_dissector_add("udp", redbackli_dissect_heur, proto_redbackli);
}
