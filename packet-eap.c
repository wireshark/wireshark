/* packet-eap.c
 * Routines for EAP Extensible Authentication Protocol dissection
 * RFC 2284
 *
 * $Id: packet-eap.c,v 1.19 2002/03/19 20:55:40 guy Exp $
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
static int hf_eap_type_nak = -1;

static gint ett_eap = -1;

static int leap_state = -1;

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

/*
References:
  1) http://www.iana.org/assignments/ppp-numbers	
			PPP EAP REQUEST/RESPONSE TYPES
  2) http://www.ietf.org/internet-drafts/draft-ietf-pppext-rfc2284bis-02.txt
  3) RFC2284
*/

#define EAP_TYPE_ID     1
#define EAP_TYPE_NOTIFY 2
#define EAP_TYPE_NAK    3
#define EAP_TYPE_TLS	13
#define EAP_TYPE_LEAP	17

static const value_string eap_type_vals[] = { 
  {EAP_TYPE_ID,  "Identity [RFC2284]" },
  {EAP_TYPE_NOTIFY,"Notification [RFC2284]" },
  {EAP_TYPE_NAK, "Nak (Response only) [RFC2284]" },
  {  4,          "MD5-Challenge [RFC2284]" },
  {  5,          "One Time Password (OTP) [RFC2289]" },
  {  6,          "Generic Token Card [RFC2284]" },
  {  7,          "?? RESERVED ?? " }, /* ??? */
  {  8,          "?? RESERVED ?? " }, /* ??? */
  {  9,          "RSA Public Key Authentication [Whelan]" },
  { 10,          "DSS Unilateral [Nace]" },
  { 11,          "KEA [Nace]" },
  { 12,          "KEA-VALIDATE [Nace]" },
  {EAP_TYPE_TLS, "EAP-TLS [RFC2716] [Aboba]" },
  { 14,          "Defender Token (AXENT) [Rosselli]" },
  { 15,          "Windows 2000 EAP [Asnes]" },
  { 16,          "Arcot Systems EAP [Jerdonek]" },
  {EAP_TYPE_LEAP,"EAP-Cisco Wireless (LEAP) [Norman]" }, 
  { 18,          "Nokia IP smart card authentication [Haverinen]" },  
  { 19,          "SRP-SHA1 Part 1 [Carlson]" },
  { 20,          "SRP-SHA1 Part 2 [Carlson]" },
  { 21,          "EAP-TTLS [Funk]" },
  { 22,          "Remote Access Service [Fields]" },
  { 23,          "UMTS Authentication and Key Argreement [Haverinen]" }, 
  { 24,          "EAP-3Com Wireless [Young]" }, 
  { 25,          "PEAP [Palekar]" },
  { 26,          "MS-EAP-Authentication [Palekar]" },
  { 27,          "Mutual Authentication w/Key Exchange (MAKE)[Berrendonner]" },
  { 28,          "CRYPTOCard [Webb]" },
  { 29,          "EAP-MSCHAP-V2 [Potter]" },
  { 30,          "DynamID [Merlin]" },
  { 31,          "Rob EAP [Ullah]" },
  { 32,          "SecurID EAP [Josefsson]" },
  { 255,         "Vendor-specific [draft-ietf-pppext-rfc2284bis-02.txt]" },
  { 0,          NULL }

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

  if (eap_code == EAP_FAILURE)
    leap_state = -1;

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

	case EAP_TYPE_ID:
	  proto_tree_add_text(eap_tree, tvb, offset, size, 
			      "Identity (%d byte%s): %s",
			      size, plurality(size, "", "s"),
			      tvb_format_text(tvb, offset, size));
	  leap_state = 0;
	  break;

	case EAP_TYPE_NOTIFY:
	  proto_tree_add_text(eap_tree, tvb, offset, size, 
			      "Notification (%d byte%s): %s",
			      size, plurality(size, "", "s"),
			      tvb_format_text(tvb, offset, size));
	  break;

	case EAP_TYPE_NAK:
	  proto_tree_add_uint(eap_tree, hf_eap_type_nak, tvb,
			      offset, size, eap_type);
	  break;

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

	  /*
	    Cisco's LEAP
	    http://www.missl.cs.umd.edu/wireless/ethereal/leap.txt
	  */

	case EAP_TYPE_LEAP:
	  {
	    guint8  field,count,namesize;

	    /* Version (byte) */
	    field = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(eap_tree, tvb, offset, 1, 
				"Version: %i",field);
	    size--;
	    offset++;

	    /* Unused  (byte) */
	    field = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(eap_tree, tvb, offset, 1, 
				"Reserved: %i",field);
	    size--;
	    offset++;

	    /* Count   (byte) */
	    count = tvb_get_guint8(tvb, offset);
	    proto_tree_add_text(eap_tree, tvb, offset, 1, 
				"Count: %i",count);
	    size--;
	    offset++;

	    /* Data    (byte*Count)
	       This part is state-dependent. */
	    if (leap_state==0) {
	      proto_tree_add_text(eap_tree, tvb, offset, count, 
			       "Peer Challenge [R8] (%d byte%s) Value:'%s'",
				  count, plurality(count, "", "s"),
				  tvb_bytes_to_str(tvb, offset, count));
	      leap_state++;
	    } else if (leap_state==1) {
	      proto_tree_add_text(eap_tree, tvb, offset, count, 
				  "Peer Response MSCHAP [24] (%d byte%s) NtChallengeResponse(%s)",
				  count, plurality(count, "", "s"),
				  tvb_bytes_to_str(tvb, offset, count));
	      leap_state++;
	    } else if (leap_state==2) {
	      proto_tree_add_text(eap_tree, tvb, offset, count, 
			       "AP Challenge [R8] (%d byte%s) Value:'%s'",
				  count, plurality(count, "", "s"),
				  tvb_bytes_to_str(tvb, offset, count));
	      leap_state++;
	    } else if (leap_state==3) {
	      proto_tree_add_text(eap_tree, tvb, offset, count, 
				  "AP Response [24] (%d byte%s) NtChallengeResponse(%s)",
				  count, plurality(count, "", "s"),
				  tvb_bytes_to_str(tvb, offset, count));
	      leap_state++;
	    } else 
	      proto_tree_add_text(eap_tree, tvb, offset, count, 
				"Data (%d byte%s): %s",
				count, plurality(count, "", "s"),
				tvb_bytes_to_str(tvb, offset, count));

	    size   -= count;
	    offset += count;

	    /* Name    (Length-(8+Count)) */
	    namesize = eap_len - (8+count);
	    proto_tree_add_text(eap_tree, tvb, offset, namesize, 
				"Name (%d byte%s): %s",
				namesize, plurality(count, "", "s"),
				tvb_format_text(tvb, offset, namesize));
	    size   -= namesize;
	    offset += namesize;
	  }
	  break;

	default:
	  proto_tree_add_text(eap_tree, tvb, offset, size, 
			      "Type-Data (%d byte%s) Value: %s",
			      size, plurality(size, "", "s"),
			      tvb_bytes_to_str(tvb, offset, size));
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
	{ &hf_eap_type_nak, { 
		"Desired Auth Type", "eap.type", FT_UINT8, BASE_DEC, 
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
