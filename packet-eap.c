/* packet-eap.c
 * Routines for EAP Extensible Authentication Protocol dissection
 * RFC 2284
 *
 * $Id: packet-eap.c,v 1.15 2002/02/26 11:55:37 guy Exp $
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

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-ieee8023.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "etypes.h"
#include "ppptypes.h"

static int proto_eap = -1;
static int hf_eap_code = -1;
static int hf_eap_identifier = -1;
static int hf_eap_len = -1;
static int hf_eap_type = -1;

static gint ett_eap = -1;

static dissector_handle_t ssl_handle;

#define EAP_REQUEST	1
#define EAP_RESPONSE	2
#define EAP_SUCCESS	3
#define EAP_FAILURE	4

static const value_string eap_code_vals[] = { 
    { EAP_REQUEST,  "Request" },
    { EAP_RESPONSE, "Response" },
    { EAP_SUCCESS,  "Success" },
    { EAP_FAILURE,  "Failure" },
    { 0,            NULL }
};

#define EAP_TYPE_TLS	13

static const value_string eap_type_vals[] = { 
    { 1,            "Identity" },
    { 2,            "Notification" },
    { 3,            "Nak (Response only)" },
    { 4,            "MD5-Challenge" },
    { 5,            "One-Time Password (OTP) (RFC 1938)" },
    { 6,            "Generic Token Card" },
    { EAP_TYPE_TLS, "EAP/TLS (RFC2716)" },
    { 0,            NULL }
};

static int
dissect_eap_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		 gboolean fragmented)
{
  guint8      eap_code;
  guint8      eap_id;
  guint16     eap_len;
  guint8      eap_type;
  gint        len;
  proto_tree *ti;
  proto_tree *eap_tree = NULL;

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "EAP");
  if (check_col(pinfo->cinfo, COL_INFO))
    col_clear(pinfo->cinfo, COL_INFO);

  eap_code = tvb_get_guint8(tvb, 0);
  if (check_col(pinfo->cinfo, COL_INFO))
    col_add_str(pinfo->cinfo, COL_INFO,
		val_to_str(eap_code, eap_code_vals, "Unknown code (0x%02X)"));

  eap_len = tvb_get_ntohs(tvb, 2);
  len = eap_len;

  if (fragmented) {
    /*
     * This is an EAP fragment inside, for example, RADIUS.  If we don't
     * have all of the packet data, return the negative of the amount of
     * additional data we need.
     */
    int reported_len = tvb_reported_length_remaining(tvb, 0);

    if (reported_len < len)
      return -(len - reported_len);
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_eap, tvb, 0, len, FALSE);
    eap_tree = proto_item_add_subtree(ti, ett_eap);

    proto_tree_add_uint(eap_tree, hf_eap_code, tvb, 0, 1, eap_code);
  }

  if (tree)
    proto_tree_add_item(eap_tree, hf_eap_identifier, tvb, 1, 1, FALSE);

  if (tree)
    proto_tree_add_uint(eap_tree, hf_eap_len, tvb, 2, 2, eap_len);

  switch (eap_code) {

  case EAP_REQUEST:
  case EAP_RESPONSE:
    eap_type = tvb_get_guint8(tvb, 4);
    if (check_col(pinfo->cinfo, COL_INFO))
      col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
		      val_to_str(eap_type, eap_type_vals,
				 "Unknown type (0x%02X)"));
    if (tree) {
      proto_tree_add_uint(eap_tree, hf_eap_type, tvb, 4, 1, eap_type);

      if (len > 5) {
	int     offset = 5;
	gint    size   = len - offset;

	switch (eap_type) {

	case EAP_TYPE_TLS:
	  {
	  guint8 flags = tvb_get_guint8(tvb, offset);

	  proto_tree_add_text(eap_tree, tvb, offset, 1, "Flags(%i): %s%s%s",
			      flags,
			      flags & 128 ? "Length " : "",
			      flags &  64 ? "More " : "",
			      flags &  32 ? "Start " : "");
	  size--;
	  offset++;

	  if (flags >> 7) {
	    guint32 length = tvb_get_ntohl(tvb, offset);
	    proto_tree_add_text(eap_tree, tvb, offset, 4, "Length: %i",
				length);
	    size   -= 4;
	    offset += 4;
	  }

	  if (size>0) {
	    tvbuff_t *next_tvb;
	    gint tvb_len; 

	    tvb_len = tvb_length_remaining(tvb, offset);
	    if (size < tvb_len)
		tvb_len = size;
	    next_tvb = tvb_new_subset(tvb, offset, tvb_len, size);
	    call_dissector(ssl_handle, next_tvb, pinfo, eap_tree);
	  }
	  }
	  break;

	default:
	  proto_tree_add_text(eap_tree, tvb, offset, size, 
			      "Type-Data (%d byte%s) Value: %s",
			      size, plurality(size, "", "s"),
			      tvb_format_text(tvb, offset, size));
	  break;
	}
      }
    }
  }

  return tvb_length(tvb);
}

static int
dissect_eap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return dissect_eap_data(tvb, pinfo, tree, FALSE);
}

static int
dissect_eap_fragment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  return dissect_eap_data(tvb, pinfo, tree, TRUE);
}

void
proto_register_eap(void)
{
  static hf_register_info hf[] = {
	{ &hf_eap_code, { 
		"Code", "eap.code", FT_UINT8, BASE_DEC, 
		VALS(eap_code_vals), 0x0, "", HFILL }},
	{ &hf_eap_identifier, {
		"Id", "eap.id", FT_UINT8, BASE_DEC,
		NULL, 0x0, "", HFILL }},
	{ &hf_eap_len, {
		"Length", "eap.len", FT_UINT16, BASE_DEC,
		NULL, 0x0, "", HFILL }},
	{ &hf_eap_type, { 
		"Type", "eap.type", FT_UINT8, BASE_DEC, 
		VALS(eap_type_vals), 0x0, "", HFILL }},
  };
  static gint *ett[] = {
	&ett_eap,
  };

  proto_eap = proto_register_protocol("Extensible Authentication Protocol", 
				      "EAP", "eap");
  proto_register_field_array(proto_eap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector("eap", dissect_eap, proto_eap);
  new_register_dissector("eap_fragment", dissect_eap_fragment, proto_eap);
}

void
proto_reg_handoff_eap(void)
{
  dissector_handle_t eap_handle;

  /*
   * Get a handle for the SSL/TLS dissector.
   */
  ssl_handle = find_dissector("ssl");

  eap_handle = find_dissector("eap");
  dissector_add("ppp.protocol", PPP_EAP, eap_handle);
}
