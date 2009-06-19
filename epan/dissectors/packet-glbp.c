/* packet-glbp.c
 *
 * Cisco's GLBP:  Gateway Load Balancing Protocol
 *
 * $Id$
 *
 * Copyright 2007 Joerg Mayer (see AUTHORS file)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * Documentation:
 * http://www.cisco.com/en/US/docs/ios/12_2t/12_2t15/feature/guide/ft_glbp.pdf
 *
 * TODO: This dissector has been written without specs, so much of it is
 *    guesswork. Candidate values that might be somewhere in the packet:
 *    - weight (current/lower/upper)
 *    - group#
 *    - forwarder#
 *    - preempt (capable/delay)
 *    - vg state
 *    - vf state
 *    - authentication
 *    - ipv6 support
 *    - sso capable
 *    - secondary IP addresses
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>

static int proto_glbp = -1;
/* glbp header? */
static gint hf_glbp_version = -1;
static gint hf_glbp_type1 = -1;
static gint hf_glbp_unknown1 = -1;
static gint hf_glbp_unknown2 = -1;
static gint hf_glbp_somemac = -1;
static gint hf_glbp_type2 = -1;
static gint hf_glbp_length2 = -1;
/* glbp type2 = 1 - hello */
static gint hf_glbp_unknown11 = -1;
static gint hf_glbp_priority = -1;
static gint hf_glbp_unknown12 = -1;
static gint hf_glbp_helloint = -1;
static gint hf_glbp_holdint = -1;
static gint hf_glbp_redirect = -1;
static gint hf_glbp_timeout = -1;
static gint hf_glbp_unknown13 = -1;
static gint hf_glbp_numips = -1;
static gint hf_glbp_lenip = -1;
static gint hf_glbp_virtualip = -1;
/* glbp type2 = 2 - Request/Response??? */
static gint hf_glbp_subtype = -1;
static gint hf_glbp_unknown21 = -1;
static gint hf_glbp_virtualmac = -1;
/* unknown type */
static gint hf_glbp_unknown6 = -1;

static gint ett_glbp = -1;

static const value_string glbp_type2_vals[] = {
	{ 1,	"Hello" },
	{ 2,	"Request/Response?" },

	{ 0, NULL }
};

static const value_string glbp_subtype_vals[] = {
	{ 0,	"Request?" },
	{ 2,	"Response?" },

	{ 0, NULL }
};

#if 0
static const value_string glbp_loadbalancing_vals[] = {
	{ x,	"None (AVG only)" },
	{ x,	"Weighted" },
	{ x,	"Host dependent" },
	{ x,	"Round robin" },

	{ 0, NULL }
};


static const value_string glbp_authentication_vals[] = {
	{ x,	"None" },
	{ x,	"Plain text" },
	{ x,	"MD5" },

	{ 0, NULL }
};

static const value_string glbp_vgstate_vals[] = {
	{ x,	"Active" },
	{ x,	"Standby" },
	{ x,	"Listen" },
	{ x,	"Initial" },
	{ x,	"Speak" },
	{ x,	"Disabled" },

	{ 0, NULL }
};

static const value_string glbp_vfstate_vals[] = {
	{ x,	"Active" },
	{ x,	"Listen" },
	{ x,	"Initial" },
	{ x,	"Disabled" },

	{ 0, NULL }
};
#endif

static int
dissect_glbp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *glbp_tree = NULL;
  proto_item *ti = NULL;
  guint32 type2;
  guint32 length2;
  int offset = 0;

  type2 = tvb_get_guint8(tvb, 12);

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GLBP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(type2,
      glbp_type2_vals, "Type 0x%02x"));

  if (tree) {
    ti = proto_tree_add_item(tree, proto_glbp, tvb, 0, -1, FALSE);
    glbp_tree = proto_item_add_subtree(ti, ett_glbp);

    /* glbp header? */
    proto_tree_add_item(glbp_tree, hf_glbp_version, tvb, 0, 1,  FALSE);
    proto_tree_add_item(glbp_tree, hf_glbp_type1, tvb, 1, 1,  FALSE);
    proto_tree_add_item(glbp_tree, hf_glbp_unknown1, tvb, 2, 2,  FALSE);
    proto_tree_add_item(glbp_tree, hf_glbp_unknown2, tvb, 4, 2,  FALSE);
    proto_tree_add_item(glbp_tree, hf_glbp_somemac, tvb, 6, 6, FALSE);
    offset += 12;
    proto_tree_add_item(glbp_tree, hf_glbp_type2, tvb, 12, 1,  FALSE);
    proto_tree_add_item(glbp_tree, hf_glbp_length2, tvb, 13, 1,  FALSE);
    length2 = tvb_get_guint8(tvb, 13);

    switch(type2) {
      case 1: /* Hello */
        proto_tree_add_item(glbp_tree, hf_glbp_unknown11, tvb, 14, 3,  FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_priority, tvb, 17, 1,  FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_unknown12, tvb, 18, 2, FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_helloint, tvb, 20, 4, FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_holdint, tvb, 24, 4, FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_redirect, tvb, 28, 2, FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_timeout, tvb, 30, 2, FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_unknown13, tvb, 32, 2, FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_numips, tvb, 34, 1, FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_lenip, tvb, 35, 1, FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_virtualip, tvb, 36, 4, FALSE);
	break;
      case 2:
        proto_tree_add_item(glbp_tree, hf_glbp_subtype, tvb, 14, 1, FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_unknown21, tvb, 15, 11, FALSE);
        proto_tree_add_item(glbp_tree, hf_glbp_virtualmac, tvb, 26, 6, FALSE);
	break;
      default:
        proto_tree_add_item(glbp_tree, hf_glbp_unknown6, tvb, 14, length2-2, FALSE);
	break;
    }

  }
  return offset + length2;
}

static gboolean
test_glbp(tvbuff_t *tvb, packet_info *pinfo)
{
	guint32 type1;
	if ( tvb_length(tvb) < 2)
		return FALSE;
	type1 = tvb_get_guint8(tvb, 1);
	if (tvb_get_guint8(tvb, 0) != 1 /* version? */
		|| type1 > 2
		|| pinfo->srcport != pinfo->destport
#if 0 /* XXX */
		|| type1 == 0 && pinfo->net_dst != ipv4:224.0.0.102
		|| type1 == 0 && pinfo->dl_src != ether:c2-00-7c-b8-00-00
#endif
	) {
		return FALSE;
	}
	return TRUE;
}

static int
dissect_glbp_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	if ( !test_glbp(tvb, pinfo) ) {
		return 0;
	}
	return dissect_glbp(tvb, pinfo, tree);
}


void
proto_register_glbp(void)
{
  static hf_register_info hf[] = {
	/* Header */
	{ &hf_glbp_version,
	   { "Version?",      "glbp.version", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_type1,
	   { "Type1???",      "glbp.type1", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_unknown1,
	   { "Unknown1",      "glbp.unknown1", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_unknown2,
	   { "Unknown2",      "glbp.unknown2", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_somemac,
	   { "Somemac?",       "glbp.somemac", FT_ETHER, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_type2,
	   { "Type2???",      "glbp.type2", FT_UINT8, BASE_DEC, VALS(glbp_type2_vals),
	     0x0, NULL, HFILL }},

	{ &hf_glbp_length2,
	   { "Length2?",      "glbp.length2", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	/* type = 1 - hello */
	{ &hf_glbp_unknown11,
	   { "Unknown1-1",      "glbp.unknown11", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_priority,
	   { "Priority",      "glbp.priority", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_unknown12,
	   { "Unknown1-2",      "glbp.unknown12", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_helloint,
	   { "Helloint",      "glbp.helloint", FT_UINT32, BASE_DEC, NULL,
	     0x0, "Hello interval [msec]", HFILL }},

	{ &hf_glbp_holdint,
	   { "Holdint",      "glbp.holdint", FT_UINT32, BASE_DEC, NULL,
	     0x0, "Hold interval [msec]", HFILL }},

	{ &hf_glbp_redirect,
	   { "Redirect",      "glbp.redirect", FT_UINT16, BASE_DEC, NULL,
	     0x0, "Redirect interval [sec]", HFILL }},

	{ &hf_glbp_timeout,
	   { "Timeout",      "glbp.timeout", FT_UINT16, BASE_DEC, NULL,
	     0x0, "Forwarder timeout interval [sec]", HFILL }},

	{ &hf_glbp_unknown13,
	   { "Unknown1-3",      "glbp.unknown13", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_numips,
	   { "Number IPs???",      "glbp.numips", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_lenip,
	   { "Length IP???",      "glbp.lenip", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_virtualip,
	   { "Virtual IP",      "glbp.virtualip", FT_IPv4, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	/* type = 2 - request/response??? */
	{ &hf_glbp_subtype,
	   { "Subtype???",      "glbp.subtype", FT_UINT8, BASE_DEC, VALS(glbp_subtype_vals),
	     0x0, NULL, HFILL }},

	{ &hf_glbp_unknown21,
	   { "Unknown2-1",      "glbp.unknown21", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_virtualmac,
	   { "Virtualmac",       "glbp.virtualmac", FT_ETHER, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	/* type = unknown */
	{ &hf_glbp_unknown6,
	   { "Unknown6",      "glbp.unknown6", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

  };
  static gint *ett[] = {
    &ett_glbp,
  };

  proto_glbp = proto_register_protocol(
	"Gateway Load Balancing Protocol", "GLBP", "glbp");
  proto_register_field_array(proto_glbp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_glbp(void)
{
  dissector_handle_t glbp_handle;

  glbp_handle = new_create_dissector_handle(dissect_glbp_static, proto_glbp);
  dissector_add("udp.port", 3222, glbp_handle);
}
