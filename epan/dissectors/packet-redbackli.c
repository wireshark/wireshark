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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>

static int proto_redbackli = -1;

static int hf_redbackli_seqno = -1;		/* Sequence No */
static int hf_redbackli_liid = -1;		/* LI Id */
static int hf_redbackli_sessid = -1;		/* Session Id */
static int hf_redbackli_label = -1;		/* Label */
static int hf_redbackli_eohpad = -1;		/* End Of Header Padding */
static int hf_redbackli_unknownavp = -1;	/* Unknown AVP */

static int ett_redbackli = -1;

static dissector_handle_t ip_handle;

#define RB_AVP_SEQNO	1
#define RB_AVP_LIID	2
#define RB_AVP_SESSID	3
#define RB_AVP_LABEL	20
#define RB_AVP_EOH	0

static const value_string avp_names[] = {
	{RB_AVP_SEQNO,		"Sequence No"},
	{RB_AVP_LIID,		"Lawful Intercept Id"},
	{RB_AVP_SESSID,		"Session Id"},
	{RB_AVP_LABEL,		"Label"},
	{RB_AVP_EOH,		"End Of Header"},
	{0,			NULL},
};

static int
redbackli_dissect_avp(guint8 avptype, guint8 avplen, tvbuff_t *tvb, gint offset, proto_tree *tree)
{
	guint32		avpintval;
	char		*avpcharval;
	const char	*avpname;
	proto_tree	*ti, *st=NULL;

	avpname=val_to_str(avptype, avp_names, "Unknown");

	if (tree) {
		ti = proto_tree_add_text(tree, tvb, offset, avplen+2, "%s AVP", avpname);
		st = proto_item_add_subtree(ti, ett_redbackli);

		proto_tree_add_text(st, tvb, offset, 1, "AVP Type: %d", avptype);
		proto_tree_add_text(st, tvb, offset+1, 1, "AVP Length: %d", avplen);
	}

	switch(avptype) {
		case(RB_AVP_SEQNO):
			avpintval=tvb_get_ntohl(tvb, offset+2);
			if (tree)
				proto_tree_add_uint(st, hf_redbackli_seqno, tvb,
						    offset+2, avplen, avpintval);
			break;
		case(RB_AVP_LIID):
			avpintval=tvb_get_ntohl(tvb, offset+2);
			if (tree)
				proto_tree_add_uint(st, hf_redbackli_liid, tvb,
						    offset+2, avplen, avpintval);
			break;
		case(RB_AVP_SESSID):
			avpintval=tvb_get_ntohl(tvb, offset+2);
			if (tree)
				proto_tree_add_uint(st, hf_redbackli_sessid, tvb,
						    offset+2, avplen, avpintval);
			break;
		case(RB_AVP_LABEL):
			avpcharval=tvb_get_string(tvb, offset+2, avplen);
			if (tree)
				proto_tree_add_string(st, hf_redbackli_label, tvb,
						    offset+2, avplen, avpcharval);
			break;
		case(RB_AVP_EOH):
			if (tree && avplen)
				proto_tree_add_item(st, hf_redbackli_eohpad, tvb,
						    offset+2, avplen, FALSE);
			return 1;
		default:
			if (tree && avplen)
				proto_tree_add_item(st, hf_redbackli_unknownavp, tvb,
						    offset+2, avplen, FALSE);
			return 0;
	}

	return 0;
}

static void
redbackli_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8		avptype, avplen;
	gint		len, offset=0, eoh=0;
	proto_tree	*ti, *redbackli_tree=NULL;
	tvbuff_t	*next_tvb;

	if(check_col(pinfo->cinfo,COL_PROTOCOL))
		col_add_str(pinfo->cinfo,COL_PROTOCOL,"RBLI");

	if (tree) {
		ti = proto_tree_add_item(tree, proto_redbackli,
					 tvb, 0, -1, FALSE);
		redbackli_tree = proto_item_add_subtree(ti, ett_redbackli);
	}

	len=tvb_length(tvb);
	offset=0;
	eoh=0;
	while(!eoh && len > 2) {
		avptype = tvb_get_guint8(tvb, offset+0);
		avplen = tvb_get_guint8(tvb, offset+1);

		if (len < avplen+2)		/* AVP Complete ? */
			break;

		eoh=redbackli_dissect_avp(avptype, avplen, tvb, offset, redbackli_tree);

		offset+=2+avplen;
		len-=2+avplen;
	}

	next_tvb = tvb_new_subset(tvb, offset, -1, -1);
	call_dissector(ip_handle, next_tvb, pinfo, tree);
}


#define REDBACKLI_INTSIZE	6
#define REDBACKLI_EOHSIZE	2
#define MIN_REDBACKLI_SIZE	(3*REDBACKLI_INTSIZE+REDBACKLI_EOHSIZE)

static gboolean
redbackli_dissect_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint		len, offset=0, eoh=0;
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
	while(len > 2 && !eoh) {
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
			case(RB_AVP_LABEL):
				avpfound|=1<<avptype;
				break;
			case(RB_AVP_EOH):
				if (avplen > 1 || offset == 0)
					return FALSE;
				eoh=1;
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
			"Sequence No", HFILL }},
		{ &hf_redbackli_liid,
			{ "Lawful Intercept Id", "redbackli.liid", FT_UINT32, BASE_DEC, NULL, 0x0,
			"LI Identifier", HFILL }},
		{ &hf_redbackli_sessid,
			{ "Session Id", "redbackli.sessid", FT_UINT32, BASE_DEC, NULL, 0x0,
			"Session Identifier", HFILL }},
		{ &hf_redbackli_label,
			{ "Label", "redbackli.label", FT_STRING, BASE_NONE, NULL, 0x0,
			"Label", HFILL }},
		{ &hf_redbackli_eohpad,
			{ "End of Header Padding", "redbackli.eohpad", FT_BYTES, BASE_HEX, NULL, 0x0,
			"", HFILL }},
		{ &hf_redbackli_unknownavp,
			{ "Unknown AVP", "redbackli.unknownavp", FT_BYTES, BASE_HEX, NULL, 0x0,
			"", HFILL }},
		};

	static gint *ett[] = {
		&ett_redbackli,
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
