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
static gint hf_glbp_forwarder = -1;
static gint hf_glbp_group = -1;
static gint hf_glbp_unknown2 = -1;
static gint hf_glbp_somemac = -1;
static gint hf_glbp_tlv = -1;
static gint hf_glbp_type = -1;
static gint hf_glbp_length = -1;
/* glbp type = 1 - hello */
static gint hf_glbp_hello_unknown11 = -1;
static gint hf_glbp_hello_priority = -1;
static gint hf_glbp_hello_unknown12 = -1;
static gint hf_glbp_hello_helloint = -1;
static gint hf_glbp_hello_holdint = -1;
static gint hf_glbp_hello_redirect = -1;
static gint hf_glbp_hello_timeout = -1;
static gint hf_glbp_hello_unknown13 = -1;
static gint hf_glbp_hello_numips = -1;
static gint hf_glbp_hello_lenip = -1;
static gint hf_glbp_hello_virtualip = -1;
/* glbp type = 2 - Request/Response??? */
static gint hf_glbp_reqresp_type = -1;
static gint hf_glbp_reqresp_unknown21 = -1;
static gint hf_glbp_reqresp_virtualmac = -1;
/* glbp type = 3 - Auth */
static gint hf_glbp_auth_authtype = -1;
static gint hf_glbp_auth_authlength = -1;
static gint hf_glbp_auth_plainpass = -1;
static gint hf_glbp_auth_md5hash = -1;
static gint hf_glbp_auth_md5chainindex = -1;
static gint hf_glbp_auth_md5chainhash = -1;
static gint hf_glbp_auth_authunknown = -1;
/* unknown type */
static gint hf_glbp_unknown_data = -1;

static gint ett_glbp = -1;
static gint ett_glbp_tlv = -1;

static const value_string glbp_type_vals[] = {
	{ 1,	"Hello" },
	{ 2,	"Request/Response?" },
	{ 3,	"Auth" },

	{ 0, NULL }
};

static const value_string glbp_reqresp_type_vals[] = {
	{ 0,	"Request?" },
	{ 2,	"Response?" },

	{ 0, NULL }
};

static const value_string glbp_auth_type_vals[] = {
	{ 0,	"None" },
	{ 1,	"Plain text" },
	{ 2,	"MD5 string" },
	{ 3,	"MD5 chain" },

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

static void
dissect_glbp_hello(tvbuff_t *tvb, int offset, guint32 length _U_,
	packet_info *pinfo _U_, proto_tree *tlv_tree)
{
  proto_tree_add_item(tlv_tree, hf_glbp_hello_unknown11, tvb, offset, 3,  FALSE);
  offset += 3;
  proto_tree_add_item(tlv_tree, hf_glbp_hello_priority, tvb, offset, 1,  FALSE);
  offset++;
  proto_tree_add_item(tlv_tree, hf_glbp_hello_unknown12, tvb, offset, 2, FALSE);
  offset += 2;
  proto_tree_add_item(tlv_tree, hf_glbp_hello_helloint, tvb, offset, 4, FALSE);
  offset += 4;
  proto_tree_add_item(tlv_tree, hf_glbp_hello_holdint, tvb, offset, 4, FALSE);
  offset += 4;
  proto_tree_add_item(tlv_tree, hf_glbp_hello_redirect, tvb, offset, 2, FALSE);
  offset += 2;
  proto_tree_add_item(tlv_tree, hf_glbp_hello_timeout, tvb, offset, 2, FALSE);
  offset += 2;
  proto_tree_add_item(tlv_tree, hf_glbp_hello_unknown13, tvb, offset, 2, FALSE);
  offset += 2;
  proto_tree_add_item(tlv_tree, hf_glbp_hello_numips, tvb, offset, 1, FALSE);
  offset++;
  proto_tree_add_item(tlv_tree, hf_glbp_hello_lenip, tvb, offset, 1, FALSE);
  offset++;
  proto_tree_add_item(tlv_tree, hf_glbp_hello_virtualip, tvb, offset, 4, FALSE);
  offset += 4;
}


static void
dissect_glbp_reqresp(tvbuff_t *tvb, int offset, guint32 length _U_,
	packet_info *pinfo _U_, proto_tree *tlv_tree)
{
  proto_tree_add_item(tlv_tree, hf_glbp_reqresp_type, tvb, offset, 1, FALSE);
  offset++;
  proto_tree_add_item(tlv_tree, hf_glbp_reqresp_unknown21, tvb, offset, 11, FALSE);
  offset += 11;
  proto_tree_add_item(tlv_tree, hf_glbp_reqresp_virtualmac, tvb, offset, 6, FALSE);
  offset += 6 ;
}

static void
dissect_glbp_auth(tvbuff_t *tvb, int offset, guint32 length,
	packet_info *pinfo _U_, proto_tree *tlv_tree)
{
  guint32 authtype;
  guint32 authlength;

  proto_tree_add_item(tlv_tree, hf_glbp_auth_authtype, tvb, offset, 1,  FALSE);
  authtype = tvb_get_guint8(tvb, offset);
  offset++;
  proto_tree_add_item(tlv_tree, hf_glbp_auth_authlength, tvb, offset, 1,  FALSE);
  authlength = tvb_get_guint8(tvb, offset);
  offset++;
  switch(authtype) {
  case 1:
    proto_tree_add_item(tlv_tree, hf_glbp_auth_plainpass, tvb, offset, authlength, FALSE);
    break;
  case 2:
    proto_tree_add_item(tlv_tree, hf_glbp_auth_md5hash, tvb, offset, authlength, FALSE);
    break;
  case 3:
    proto_tree_add_item(tlv_tree, hf_glbp_auth_md5chainindex, tvb, offset, 4, FALSE);
    proto_tree_add_item(tlv_tree, hf_glbp_auth_md5chainhash, tvb, offset+4, authlength-4, FALSE);
    break;
  default:
    proto_tree_add_item(tlv_tree, hf_glbp_auth_authunknown, tvb, offset, authlength, FALSE);
    break;
  }
  offset += length;
}

static void
dissect_glbp_unknown(tvbuff_t *tvb, int offset, guint32 length,
	packet_info *pinfo _U_, proto_tree *tlv_tree)
{
  proto_tree_add_item(tlv_tree, hf_glbp_unknown_data, tvb, offset, length, FALSE);
  offset += length;
}

static int
dissect_glbp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *glbp_tree = NULL;
  proto_tree *tlv_tree = NULL;
  proto_item *ti = NULL;
  guint32 type;
  int offset = 0;
  guint32 length;
  guint32 group;

  group = tvb_get_ntohs(tvb, 2);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "GLBP");
  col_add_fstr(pinfo->cinfo, COL_INFO, "G: %d", group);

  if (tree) {
    ti = proto_tree_add_item(tree, proto_glbp, tvb, 0, -1, FALSE);
    glbp_tree = proto_item_add_subtree(ti, ett_glbp);

    /* glbp header? */
    proto_tree_add_item(glbp_tree, hf_glbp_version, tvb, offset, 1,  FALSE);
    offset++;
    proto_tree_add_item(glbp_tree, hf_glbp_forwarder, tvb, offset, 1,  FALSE);
    offset++;
    proto_tree_add_item(glbp_tree, hf_glbp_group, tvb, offset, 2,  FALSE);
    offset += 2;
    proto_tree_add_item(glbp_tree, hf_glbp_unknown2, tvb, offset, 2,  FALSE);
    offset += 2;
    proto_tree_add_item(glbp_tree, hf_glbp_somemac, tvb, offset, 6, FALSE);
    offset += 6;
    while (tvb_length_remaining(tvb, offset) > 0) {

      type = tvb_get_guint8(tvb, offset);
      length = tvb_get_guint8(tvb, offset+1) - 2;

      ti = proto_tree_add_item(glbp_tree, hf_glbp_tlv, tvb, offset, length+2, FALSE);
      tlv_tree = proto_item_add_subtree(ti, ett_glbp_tlv);
      proto_item_append_text(ti, " l=%d, t=%s", length+2,
        val_to_str(type, glbp_type_vals, "%d"));

      proto_tree_add_item(tlv_tree, hf_glbp_type, tvb, offset, 1,  FALSE);
      offset++;
      proto_tree_add_item(tlv_tree, hf_glbp_length, tvb, offset, 1,  FALSE);
      offset++;
      col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
        val_to_str(type, glbp_type_vals, "%d"));
  
      switch(type) {
        case 1: /* Hello */
	  dissect_glbp_hello(tvb, offset, length, pinfo, tlv_tree);
  	break;
        case 2: /* Request/Response */
	  dissect_glbp_reqresp(tvb, offset, length, pinfo, tlv_tree);
  	break;
        case 3: /* Plaintext auth */
	  dissect_glbp_auth(tvb, offset, length, pinfo, tlv_tree);
  	break;
        default:
	  dissect_glbp_unknown(tvb, offset, length, pinfo, tlv_tree);
  	break;
      }
      offset += length;
    }
  }
  return offset;
}

static gboolean
test_glbp(tvbuff_t *tvb, packet_info *pinfo)
{
	guint32 forwarder;
	if ( tvb_length(tvb) < 2)
		return FALSE;
	forwarder = tvb_get_guint8(tvb, 1);
	if (tvb_get_guint8(tvb, 0) != 1 /* version? */
		|| forwarder > 4
		|| pinfo->srcport != pinfo->destport
#if 0 /* XXX */
		|| forwarder == 0 && pinfo->net_dst != ipv4:224.0.0.102
		|| forwarder == 0 && pinfo->dl_src != ether:c2-00-7c-b8-00-00
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
	   { "Version?",	"glbp.version", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_forwarder,
	   { "Forwarder???",	"glbp.forwarder", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_group,
	   { "Group",		"glbp.group", FT_UINT16, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_unknown2,
	   { "Unknown2",      "glbp.unknown2", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_somemac,
	   { "Somemac?",       "glbp.somemac", FT_ETHER, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_tlv,
	   { "TLV",       "glbp.tlv", FT_PROTOCOL, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_type,
	   { "Type",         "glbp.type", FT_UINT8, BASE_DEC, VALS(glbp_type_vals),
	     0x0, NULL, HFILL }},

	{ &hf_glbp_length,
	   { "Length",       "glbp.length", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	/* type = 1 - hello */
	{ &hf_glbp_hello_unknown11,
	   { "Unknown1-1",      "glbp.hello.unknown11", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_hello_priority,
	   { "Priority",      "glbp.hello.priority", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_hello_unknown12,
	   { "Unknown1-2",      "glbp.hello.unknown12", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_hello_helloint,
	   { "Helloint",      "glbp.hello.helloint", FT_UINT32, BASE_DEC, NULL,
	     0x0, "Hello interval [msec]", HFILL }},

	{ &hf_glbp_hello_holdint,
	   { "Holdint",      "glbp.hello.holdint", FT_UINT32, BASE_DEC, NULL,
	     0x0, "Hold interval [msec]", HFILL }},

	{ &hf_glbp_hello_redirect,
	   { "Redirect",      "glbp.hello.redirect", FT_UINT16, BASE_DEC, NULL,
	     0x0, "Redirect interval [sec]", HFILL }},

	{ &hf_glbp_hello_timeout,
	   { "Timeout",      "glbp.hello.timeout", FT_UINT16, BASE_DEC, NULL,
	     0x0, "Forwarder timeout interval [sec]", HFILL }},

	{ &hf_glbp_hello_unknown13,
	   { "Unknown1-3",      "glbp.hello.unknown13", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_hello_numips,
	   { "Number IPs???",      "glbp.hello.numips", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_hello_lenip,
	   { "Length IP???",      "glbp.hello.lenip", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_hello_virtualip,
	   { "Virtual IP",      "glbp.hello.virtualip", FT_IPv4, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	/* type = 2 - request/response??? */
	{ &hf_glbp_reqresp_type,
	   { "Type???",      "glbp.reqresp.type", FT_UINT8, BASE_DEC, VALS(glbp_reqresp_type_vals),
	     0x0, NULL, HFILL }},

	{ &hf_glbp_reqresp_unknown21,
	   { "Unknown2-1",      "glbp.reqresp.unknown21", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_reqresp_virtualmac,
	   { "Virtualmac",       "glbp.reqresp.virtualmac", FT_ETHER, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	/* type = 3 - auth */
	{ &hf_glbp_auth_authtype,
	   { "Authtype",         "glbp.auth.authtype", FT_UINT8, BASE_DEC, VALS(glbp_auth_type_vals),
	     0x0, NULL, HFILL }},

	{ &hf_glbp_auth_authlength,
	   { "Authlength",       "glbp.auth.authlength", FT_UINT8, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_auth_plainpass,
	   { "Plain pass",       "glbp.auth.plainpass", FT_STRING, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_auth_md5hash,
	   { "MD5-string hash",       "glbp.auth.md5hash", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_auth_md5chainindex,
	   { "MD5-chain index",       "glbp.auth.md5chainindex", FT_UINT32, BASE_DEC, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_auth_md5chainhash,
	   { "MD5-chain hash",       "glbp.auth.md5chainhash", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	{ &hf_glbp_auth_authunknown,
	   { "Unknown auth value",       "glbp.auth.authunknown", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

	/* type = unknown */
	{ &hf_glbp_unknown_data,
	   { "Unknown TLV data",      "glbp.unknown.data", FT_BYTES, BASE_NONE, NULL,
	     0x0, NULL, HFILL }},

  };
  static gint *ett[] = {
    &ett_glbp,
    &ett_glbp_tlv,
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
