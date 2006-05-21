/* packet-mip.c
 * Routines for Mobile IP dissection
 * Copyright 2000, Stefan Raab <sraab@cisco.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <glib.h>
#include <time.h>

#include <epan/packet.h>
#include "packet-ntp.h"

/* Initialize the protocol and registered fields */
static int proto_mip = -1;
static int hf_mip_type = -1;
static int hf_mip_flags = -1;
static int hf_mip_s = -1;
static int hf_mip_b = -1;
static int hf_mip_d = -1;
static int hf_mip_m = -1;
static int hf_mip_g = -1;
static int hf_mip_v = -1;
static int hf_mip_t = -1;
static int hf_mip_code = -1;
static int hf_mip_life = -1;
static int hf_mip_homeaddr = -1;
static int hf_mip_haaddr = -1;
static int hf_mip_coa = -1;
static int hf_mip_ident = -1;
static int hf_mip_ext_type = -1;
static int hf_mip_ext_stype = -1;
static int hf_mip_ext_len = -1;
static int hf_mip_ext = -1;
static int hf_mip_aext_spi = -1;
static int hf_mip_aext_auth = -1;
static int hf_mip_next_nai = -1;

/* Initialize the subtree pointers */
static gint ett_mip = -1;
static gint ett_mip_flags = -1;
static gint ett_mip_ext = -1;
static gint ett_mip_exts = -1;

/* Port used for Mobile IP */
#define UDP_PORT_MIP    434

typedef enum {
    REGISTRATION_REQUEST = 1,
    REGISTRATION_REPLY = 3
} mipMessageTypes;

static const value_string mip_types[] = {
  {REGISTRATION_REQUEST, "Registration Request"},
  {REGISTRATION_REPLY,   "Registration Reply"},
  {0, NULL},
};

static const value_string mip_reply_codes[]= {
  {0, "Reg Accepted"},
  {1, "Reg Accepted, but Simultaneous Bindings Unsupported."},
  {64, "Reg Deny (FA)- Unspecified Reason"},
  {65, "Reg Deny (FA)- Administratively Prohibited"},
  {66, "Reg Deny (FA)- Insufficient Resources"},
  {67, "Reg Deny (FA)- MN failed Authentication"},
  {68, "Reg Deny (FA)- HA failed Authentication"},
  {69, "Reg Deny (FA)- Requested Lifetime too Long"},
  {70, "Reg Deny (FA)- Poorly Formed Request"},
  {71, "Reg Deny (FA)- Poorly Formed Reply"},
  {72, "Reg Deny (FA)- Requested Encapsulation Unavailable"},
  {73, "Reg Deny (FA)- VJ Compression Unavailable"},
  {74, "Reg Deny (FA)- Requested Reverse Tunnel Unavailable"},
  {75, "Reg Deny (FA)- Reverse Tunnel is Mandatory and 'T' Bit Not Set"},
  {76, "Reg Deny (FA)- Mobile Node Too Distant"},
  {77, "Reg Deny (FA)- Invalid Care-of Address"},
  {79, "Reg Deny (FA)- Delivery Style Not Supported"},
  {80, "Reg Deny (FA)- Home Network Unreachable"},
  {81, "Reg Deny (FA)- HA Host Unreachable"},
  {82, "Reg Deny (FA)- HA Port Unreachable"},
  {88, "Reg Deny (FA)- HA Unreachable"},
  {96, "Reg Deny (FA)(NAI) - Non Zero Home Address Required"},
  {97, "Reg Deny (FA)(NAI) - Missing NAI"},
  {98, "Reg Deny (FA)(NAI) - Missing Home Agent"},
  {99, "Reg Deny (FA)(NAI) - Missing Home Address"},
  {128, "Reg Deny (HA)- Unspecified"},
  {129, "Reg Deny (HA)- Administratively Prohibited"},
  {130, "Reg Deny (HA)- Insufficient Resources"},
  {131, "Reg Deny (HA)- MN Failed Authentication"},
  {132, "Reg Deny (HA)- FA Failed Authentication"},
  {133, "Reg Deny (HA)- Registration ID Mismatch"},
  {134, "Reg Deny (HA)- Poorly Formed Request"},
  {135, "Reg Deny (HA)- Too Many Simultaneous Bindings"},
  {136, "Reg Deny (HA)- Unknown HA Address"},
  {137, "Reg Deny (HA)- Requested Reverse Tunnel Unavailable"},
  {138, "Reg Deny (HA)- Reverse Tunnel is Mandatory and 'T' Bit Not Set"},
  {139, "Reg Deny (HA)- Requested Encapsulation Unavailable"},
  {0, NULL},
};

typedef enum {
  MH_AUTH_EXT = 32,
  MF_AUTH_EXT = 33,
  FH_AUTH_EXT = 34,
  GEN_AUTH_EXT = 36,      /* RFC 3012 */
  OLD_CVSE_EXT = 37,      /* RFC 3115 */
  CVSE_EXT = 38,          /* RFC 3115 */
  MN_NAI_EXT = 131,
  MF_CHALLENGE_EXT = 132, /* RFC 3012 */
  OLD_NVSE_EXT = 133,     /* RFC 3115 */
  NVSE_EXT = 134          /* RFC 3115 */
} MIP_EXTS;
static const value_string mip_ext_types[]= {
  {MH_AUTH_EXT, "Mobile-Home Authentication Extension"},
  {MF_AUTH_EXT, "Mobile-Foreign Authentication Extension"},
  {FH_AUTH_EXT, "Foreign-Home Authentication Extension"},
  {MN_NAI_EXT,  "Mobile Node NAI Extension"},
  {GEN_AUTH_EXT, "Generalized Mobile-IP Authentication Extension"},
  {MF_CHALLENGE_EXT, "MN-FA Challenge Extension"},
  {CVSE_EXT, "Critical Vendor/Organization Specific Extension"},
  {OLD_CVSE_EXT, "Critical Vendor/Organization Specific Extension"},
  {NVSE_EXT, "Normal Vendor/Organization Specific Extension"},
  {OLD_NVSE_EXT, "Normal Vendor/Organization Specific Extension"},
  {0, NULL},
};

static const value_string mip_ext_stypes[]= {
  {1, "MN AAA Extension"},
  {0, NULL},
};
/* Code to dissect extensions */
static void
dissect_mip_extensions( tvbuff_t *tvb, int offset, proto_tree *tree)
{
  proto_item   *ti;
  proto_tree   *exts_tree=NULL;
  proto_tree   *ext_tree;
  size_t        ext_len;
  guint8        ext_type;
  guint8        ext_subtype=0;
  size_t        hdrLen;

  /* None of this really matters if we don't have a tree */
  if (!tree) return;

  /* Add our tree, if we have extensions */
  ti = proto_tree_add_text(tree, tvb, offset, -1, "Extensions");
  exts_tree = proto_item_add_subtree(ti, ett_mip_exts);

  /* And, handle each extension */
  while (tvb_reported_length_remaining(tvb, offset) > 0) {

	/* Get our extension info */
	ext_type = tvb_get_guint8(tvb, offset);
	if (ext_type == GEN_AUTH_EXT) {
	  /*
	   * Very nasty . . breaks normal extensions, since the length is
	   * in the wrong place :(
	   */
	  ext_subtype = tvb_get_guint8(tvb, offset + 1);
	  ext_len = tvb_get_ntohs(tvb, offset + 2);
	  hdrLen = 4;
	} else {
	  ext_len = tvb_get_guint8(tvb, offset + 1);
	  hdrLen = 2;
	}

	ti = proto_tree_add_text(exts_tree, tvb, offset, ext_len + hdrLen,
				 "Extension: %s",
				 val_to_str(ext_type, mip_ext_types,
				            "Unknown Extension %u"));
	ext_tree = proto_item_add_subtree(ti, ett_mip_ext);

	proto_tree_add_item(ext_tree, hf_mip_ext_type, tvb, offset, 1, ext_type);
	offset++;
	if (ext_type != GEN_AUTH_EXT) {
	  /* Another nasty hack since GEN_AUTH_EXT broke everything */
	  proto_tree_add_uint(ext_tree, hf_mip_ext_len, tvb, offset, 1, ext_len);
	  offset++;
	}

	switch(ext_type) {
	case MH_AUTH_EXT:
	case MF_AUTH_EXT:
	case FH_AUTH_EXT:
	  /* All these extensions look the same.  4 byte SPI followed by a key */
	  proto_tree_add_item(ext_tree, hf_mip_aext_spi, tvb, offset, 4, FALSE);
	  proto_tree_add_item(ext_tree, hf_mip_aext_auth, tvb, offset+4, ext_len-4,
						  FALSE);
	  break;
	case MN_NAI_EXT:
	  proto_tree_add_item(ext_tree, hf_mip_next_nai, tvb, offset,
						  ext_len, FALSE);
	  break;

	case GEN_AUTH_EXT:      /* RFC 3012 */
	  /*
	   * Very nasty . . breaks normal extensions, since the length is
	   * in the wrong place :(
	   */
	  proto_tree_add_uint(ext_tree, hf_mip_ext_stype, tvb, offset, 1, ext_subtype);
	  offset++;
	  proto_tree_add_uint(ext_tree, hf_mip_ext_len, tvb, offset, 2, ext_len);
	  offset+=2;
	  /* SPI */
	  proto_tree_add_item(ext_tree, hf_mip_aext_spi, tvb, offset, 4, FALSE);
	  /* Key */
	  proto_tree_add_item(ext_tree, hf_mip_aext_auth, tvb, offset + 4,
						  ext_len - 4, FALSE);

	  break;
	case OLD_CVSE_EXT:      /* RFC 3115 */
	case CVSE_EXT:          /* RFC 3115 */
	case OLD_NVSE_EXT:      /* RFC 3115 */
	case NVSE_EXT:          /* RFC 3115 */
	case MF_CHALLENGE_EXT:  /* RFC 3012 */
	  /* The default dissector is good here.  The challenge is all hex anyway. */
	default:
	  proto_tree_add_item(ext_tree, hf_mip_ext, tvb, offset, ext_len, FALSE);
	  break;
	} /* ext type */

	offset += ext_len;
  } /* while data remaining */

} /* dissect_mip_extensions */

/* Code to actually dissect the packets */
static void
dissect_mip( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* Set up structures we will need to add the protocol subtree and manage it */
  proto_item	*ti;
  proto_tree	*mip_tree=NULL;
  proto_item    *tf;
  proto_tree    *flags_tree;
  guint8         type;
  guint8         flags;
  size_t         offset=0;
  const guint8  *reftime;

  /* Make entries in Protocol column and Info column on summary display */

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MobileIP");
  if (check_col(pinfo->cinfo, COL_INFO))
	col_clear(pinfo->cinfo, COL_INFO);

  type = tvb_get_guint8(tvb, offset);
  switch (type) {
  case REGISTRATION_REQUEST:
	if (check_col(pinfo->cinfo, COL_INFO))
	  col_add_fstr(pinfo->cinfo, COL_INFO, "Reg Request: HAddr=%s COA=%s",
				   ip_to_str(tvb_get_ptr(tvb, 4, 4)),
				   ip_to_str(tvb_get_ptr(tvb,12,4)));

	if (tree) {
	  ti = proto_tree_add_item(tree, proto_mip, tvb, offset, -1, FALSE);
	  mip_tree = proto_item_add_subtree(ti, ett_mip);

	  /* type */
	  proto_tree_add_uint(mip_tree, hf_mip_type, tvb, offset, 1, type);
	  offset++;

	  /* flags */
	  flags = tvb_get_guint8(tvb, offset);
	  tf = proto_tree_add_uint(mip_tree, hf_mip_flags, tvb,
							   offset, 1, flags);
	  flags_tree = proto_item_add_subtree(tf, ett_mip_flags);
	  proto_tree_add_boolean(flags_tree, hf_mip_s, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_mip_b, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_mip_d, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_mip_m, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_mip_g, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_mip_v, tvb, offset, 1, flags);
	  proto_tree_add_boolean(flags_tree, hf_mip_t, tvb, offset, 1, flags);
	  offset++;

	  /* lifetime */
	  proto_tree_add_item(mip_tree, hf_mip_life, tvb, offset, 2, FALSE);
	  offset +=2;

	  /* home address */
	  proto_tree_add_item(mip_tree, hf_mip_homeaddr, tvb, offset, 4, FALSE);
	  offset += 4;

	  /* home agent address */
	  proto_tree_add_item(mip_tree, hf_mip_haaddr, tvb, offset, 4, FALSE);
	  offset += 4;

	  /* Care of Address */
	  proto_tree_add_item(mip_tree, hf_mip_coa, tvb, offset, 4, FALSE);
	  offset += 4;

	  /* Identifier - assumed to be an NTP time here */
	  reftime = tvb_get_ptr(tvb, offset, 8);
	  proto_tree_add_bytes_format(mip_tree, hf_mip_ident, tvb, offset, 8,
				      reftime,
				      "Identification: %s",
				      ntp_fmt_ts(reftime));
	  offset += 8;

	} /* if tree */
	break;
  case REGISTRATION_REPLY:
	if (check_col(pinfo->cinfo, COL_INFO))
	  col_add_fstr(pinfo->cinfo, COL_INFO, "Reg Reply: HAddr=%s, Code=%u",
				   ip_to_str(tvb_get_ptr(tvb,4,4)), tvb_get_guint8(tvb,1));

	if (tree) {
	  /* Add Subtree */
	  ti = proto_tree_add_item(tree, proto_mip, tvb, offset, -1, FALSE);
	  mip_tree = proto_item_add_subtree(ti, ett_mip);

	  /* Type */
  	  proto_tree_add_uint(mip_tree, hf_mip_type, tvb, offset, 1, type);
	  offset++;

	  /* Reply Code */
	  proto_tree_add_item(mip_tree, hf_mip_code, tvb, offset, 1, FALSE);
	  offset++;

	  /* Registration Lifetime */
	  proto_tree_add_item(mip_tree, hf_mip_life, tvb, offset, 2, FALSE);
	  offset += 2;

	  /* Home address */
	  proto_tree_add_item(mip_tree, hf_mip_homeaddr, tvb, offset, 4, FALSE);
	  offset += 4;

	  /* Home Agent Address */
	  proto_tree_add_item(mip_tree, hf_mip_haaddr, tvb, offset, 4, FALSE);
	  offset += 4;

	  /* Identifier - assumed to be an NTP time here */
	  reftime = tvb_get_ptr(tvb, offset, 8);
	  proto_tree_add_bytes_format(mip_tree, hf_mip_ident, tvb, offset, 8,
				      reftime,
				      "Identification: %s",
				      ntp_fmt_ts(reftime));
	  offset += 8;
	} /* if tree */

	break;
  } /* End switch */

  if (tree) {
	if (tvb_reported_length_remaining(tvb, offset) > 0)
	  dissect_mip_extensions(tvb, offset, mip_tree);
  }
} /* dissect_mip */

/* Register the protocol with Wireshark */
void proto_register_mip(void)
{

/* Setup list of header fields */
	static hf_register_info hf[] = {
	  { &hf_mip_type,
		 { "Message Type",           "mip.type",
			FT_UINT8, BASE_DEC, VALS(mip_types), 0,
			"Mobile IP Message type.", HFILL }
	  },
	  { &hf_mip_flags,
		{"Flags", "mip.flags",
		 FT_UINT8, BASE_HEX, NULL, 0x0,
		 "", HFILL}
	  },
	  { &hf_mip_s,
		 {"Simultaneous Bindings",           "mip.s",

		   FT_BOOLEAN, 8, NULL, 128,
		   "Simultaneous Bindings Allowed", HFILL }
	  },
	  { &hf_mip_b,
		 {"Broadcast Datagrams",           "mip.b",
		   FT_BOOLEAN, 8, NULL, 64,
		   "Broadcast Datagrams requested", HFILL }
	  },
	  { &hf_mip_d,
		 { "Co-located Care-of Address",           "mip.d",
		   FT_BOOLEAN, 8, NULL, 32,
		   "MN using Co-located Care-of address", HFILL }
	  },
	  { &hf_mip_m,
		 {"Minimal Encapsulation",           "mip.m",
		   FT_BOOLEAN, 8, NULL, 16,
		   "MN wants Minimal encapsulation", HFILL }
	  },
	  { &hf_mip_g,
		 {"GRE",           "mip.g",
		   FT_BOOLEAN, 8, NULL, 8,
		   "MN wants GRE encapsulation", HFILL }
	  },
	  { &hf_mip_v,
		 { "Van Jacobson",           "mip.v",
		   FT_BOOLEAN, 8, NULL, 4,
		   "Van Jacobson", HFILL }
	  },
	  { &hf_mip_t,
		 { "Reverse Tunneling",           "mip.t",
		   FT_BOOLEAN, 8, NULL, 2,
		   "Reverse tunneling requested", HFILL }
	  },
	  { &hf_mip_code,
		 { "Reply Code",           "mip.code",
			FT_UINT8, BASE_DEC, VALS(mip_reply_codes), 0,
			"Mobile IP Reply code.", HFILL }
	  },
	  { &hf_mip_life,
		 { "Lifetime",           "mip.life",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Mobile IP Lifetime.", HFILL }
	  },
	  { &hf_mip_homeaddr,
		 { "Home Address",           "mip.homeaddr",
			FT_IPv4, BASE_NONE, NULL, 0,
			"Mobile Node's home address.", HFILL }
	  },

	  { &hf_mip_haaddr,
		 { "Home Agent",           "mip.haaddr",
			FT_IPv4, BASE_NONE, NULL, 0,
			"Home agent IP Address.", HFILL }
	  },
	  { &hf_mip_coa,
		 { "Care of Address",           "mip.coa",
			FT_IPv4, BASE_NONE, NULL, 0,
			"Care of Address.", HFILL }
	  },
	  { &hf_mip_ident,
		 { "Identification",           "mip.ident",
			FT_BYTES, BASE_NONE, NULL, 0,
			"MN Identification.", HFILL }
	  },
	  { &hf_mip_ext_type,
		 { "Extension Type",           "mip.ext.type",
			FT_UINT8, BASE_DEC, VALS(mip_ext_types), 0,
			"Mobile IP Extension Type.", HFILL }
	  },
	  { &hf_mip_ext_stype,
		 { "Gen Auth Ext SubType",           "mip.ext.auth.subtype",
			FT_UINT8, BASE_DEC, VALS(mip_ext_stypes), 0,
			"Mobile IP Auth Extension Sub Type.", HFILL }
	  },
	  { &hf_mip_ext_len,
		 { "Extension Length",         "mip.ext.len",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Mobile IP Extension Length.", HFILL }
	  },
	  { &hf_mip_ext,
		 { "Extension",                      "mip.extension",
			FT_BYTES, BASE_HEX, NULL, 0,
			"Extension", HFILL }
	  },
	  { &hf_mip_aext_spi,
		 { "SPI",                      "mip.auth.spi",
			FT_UINT32, BASE_HEX, NULL, 0,
			"Authentication Header Security Parameter Index.", HFILL }
	  },
	  { &hf_mip_aext_auth,
		 { "Authenticator",            "mip.auth.auth",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Authenticator.", HFILL }
	  },
	  { &hf_mip_next_nai,
		 { "NAI",                      "mip.nai",
			FT_STRING, BASE_NONE, NULL, 0,
			"NAI", HFILL }
	  },
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_mip,
		&ett_mip_flags,
		&ett_mip_ext,
		&ett_mip_exts,
	};

	/* Register the protocol name and description */
	proto_mip = proto_register_protocol("Mobile IP", "Mobile IP", "mip");

	/* Register the dissector by name */
	register_dissector("mip", dissect_mip, proto_mip);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_mip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_mip(void)
{
	dissector_handle_t mip_handle;

	mip_handle = find_dissector("mip");
	dissector_add("udp.port", UDP_PORT_MIP, mip_handle);
}
