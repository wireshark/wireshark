/* packet-snego.c
 * Routines for the simple and protected GSS-API negotiation mechanism
 * as described in rfc2478.
 * Copyright 2002, Tim Potter <tpot@samba.org>
 *
 * $Id: packet-snego.c,v 1.2 2002/08/28 21:00:34 jmayer Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <glib.h>
#include <epan/packet.h>

#include "asn1.h"
#include "format-oid.h"

#include "packet-gssapi.h"

static int proto_snego = -1;

static int hf_snego = -1;

static gint ett_snego = -1;

static void
dissect_snego(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
	proto_item *item;
	proto_tree *subtree;
	int length = tvb_length_remaining(tvb, 0);
	int offset = 0;

	item = proto_tree_add_item(
		tree, hf_snego, tvb, offset, length, FALSE);

	subtree = proto_item_add_subtree(item, ett_snego);
}

void
proto_register_snego(void)
{
	static hf_register_info hf[] = {
		{ &hf_snego,
		  { "SNEGO", "Snego", FT_NONE, BASE_NONE, NULL, 0x0,
		    "SNEGO", HFILL }},
	};

	static gint *ett[] = {
		&ett_snego,
	};

	proto_snego = proto_register_protocol(
		"Snego", "Snego", "snego");

	proto_register_field_array(proto_snego, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("snego", dissect_snego, proto_snego);
}

void
proto_reg_handoff_snego(void)
{
	/* Register protocol with GSS-API module */

	gssapi_init_oid("1.3.6.1.5.5.2", proto_snego, ett_snego, "snego");
}
