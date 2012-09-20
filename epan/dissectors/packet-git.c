/* packet-git.c
 * Routines for git packet dissection
 * RFC 1939
 * Copyright 2010, Jelmer Vernooij <jelmer@samba.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pop.c
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

#include <stdio.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/prefs.h>
#include "packet-tcp.h"

static int proto_git = -1;

static gint ett_git = -1;

static gint hf_git_packet_len = -1;
static gint hf_git_packet_data = -1;
static gint hf_git_packet_terminator = -1;

#define TCP_PORT_GIT			9418

/* desegmentation of Git over TCP */
static gboolean git_desegment = TRUE;

static gboolean tvb_get_packet_length(tvbuff_t *tvb, int offset,
									  guint16 *length)
{
	guint8 *lenstr;

	lenstr = tvb_get_ephemeral_string(tvb, offset, 4);

	return (sscanf(lenstr, "%hx", length) == 1);
}

static guint
get_git_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint16 plen;

	if (!tvb_get_packet_length(tvb, offset, &plen))
		return 0; /* No idea what this is */

	if (plen == 0) {
		/* Terminator packet */
		return 4;
	} else {
		return plen;
	}
}

static void
dissect_git_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree             *git_tree;
  proto_item             *ti;
  int offset = 0;
  guint16 plen;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "GIT");

  col_set_str(pinfo->cinfo, COL_INFO, "Git Smart Protocol");

  ti = proto_tree_add_item(tree, proto_git, tvb, offset, -1, ENC_NA);
  git_tree = proto_item_add_subtree(ti, ett_git);

  if (!tvb_get_packet_length(tvb, 0, &plen))
	  return;

  if (plen == 0) {
	  proto_tree_add_uint(git_tree, hf_git_packet_terminator, tvb, offset,
								4, plen);
	  return;
  }

  if (git_tree)
  {
	  proto_tree_add_uint(git_tree, hf_git_packet_len, tvb, offset,
								4, plen);

	  proto_tree_add_item(git_tree, hf_git_packet_data, tvb, offset+4,
								plen-4, ENC_NA);
	}
}

static void
dissect_git(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, git_desegment, 4, get_git_pdu_len,
			 dissect_git_pdu);
}

void
proto_register_git(void)
{
  static hf_register_info hf[] = {
	{ &hf_git_packet_len,
		{ "Packet length", "git.length", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
	},
	{ &hf_git_packet_data,
		{ "Packet data", "git.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL },
	},
	{ &hf_git_packet_terminator,
		{ "Terminator packet", "git.terminator", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL },
	},
  };

  static gint *ett[] = {
    &ett_git,
  };

  module_t *git_module;
  proto_git = proto_register_protocol("Git Smart Protocol", "GIT", "git");
  register_dissector("git", dissect_git, proto_git);
  proto_register_field_array(proto_git, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  git_module = prefs_register_protocol(proto_git, NULL);

  prefs_register_bool_preference(git_module, "desegment",
				 "Reassemble GIT messages spanning multiple TCP segments",
				 "Whether the GIT dissector should reassemble messages spanning multiple TCP segments."
				 " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
				 &git_desegment);
}

void
proto_reg_handoff_git(void)
{
  dissector_handle_t git_handle;

  git_handle = find_dissector("git");
  dissector_add_uint("tcp.port", TCP_PORT_GIT, git_handle);
}
