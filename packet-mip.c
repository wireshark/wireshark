/* packet-mip.c
 * Routines for Mobile IP dissection
 * Copyright 2000, Stefan Raab <Stefan.Raab@nextel.com>
 *
 * $Id: packet-mip.c,v 1.12 2001/01/09 06:31:38 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>
#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"

/* Initialize the protocol and registered fields */
static int proto_mip = -1;
static int hf_mip_type = -1;
static int hf_mip_s = -1;
static int hf_mip_b = -1;
static int hf_mip_d = -1;
static int hf_mip_m = -1;
static int hf_mip_g = -1;
static int hf_mip_v = -1;
static int hf_mip_code = -1;
static int hf_mip_life = -1;
static int hf_mip_homeaddr = -1;
static int hf_mip_haaddr = -1;
static int hf_mip_coa = -1;
static int hf_mip_ident = -1;

/* Initialize the subtree pointers */
static gint ett_mip = -1;

/* Port used for Mobile IP */
#define UDP_PORT_MIP    434


/*
struct mip_packet{
  unsigned char type;
};


struct mip_request_packet{
  unsigned char type;
  unsigned char code;
  unsigned char life[2];
  unsigned char homeaddr[4];
  unsigned char haaddr[4];
  unsigned char coa[4];
  unsigned char ident[8];

};


struct mip_reply_packet{
  unsigned char type;
  unsigned char code;
  unsigned char life[2];
  unsigned char homeaddr[4];
  unsigned char haaddr[4];
  unsigned char ident[8];

};
*/

static const value_string mip_types[] = {
  {1, "Registration Request"},
  {3, "Registration Reply"},
  {0, NULL},
};

static const value_string mip_reply_codes[]= {
  {0, "Registration Accepted"},
  {1, "Registration Accepted, no simul bindings"},
  {64, "Registration Denied by FA, unspecified reason"},
  {65, "Registration Denied by FA, Admin Prohibit"},
  {66, "Registration Denied by FA, Insufficient Resources"},
  {67, "Registration Denied by FA, MN failed Auth"},
  {68, "Registration Denied by FA, HA failed Auth"},
  {69, "Registration Denied by FA, Lifetime to long"},
  {70, "Registration Denied by FA, Poorly Formed Request"},
  {71, "Registration Denied by FA, Poorly Formed Reply"},
  {72, "Registration Denied by FA, encap unavailable"},
  {73, "Registration Denied by FA, VJ unavailable"},
  {80, "Registration Denied by FA, Home net unreachable"},
  {81, "Registration Denied by FA, Home Agent host unreachable"},
  {82, "Registration Denied by FA, Home Agent port unreachable"},
  {88, "Registration Denied by FA, Home Agent unreachable"},
  {128, "Registration Denied by HA, unspecified"},
  {129, "Registration Denied by HA, Admin Prohibit"},
  {130, "Registration Denied by HA, insufficient resources"},
  {131, "Registration Denied by HA, MN failed Auth"},
  {132, "Registration Denied by HA, FA failed Auth"},
  {133, "Registration Denied by HA, registration ID Mismatch"},
  {134, "Registration Denied by HA, poorly formed request"},
  {135, "Registration Denied by HA, too many simul bindings"},
  {136, "Registration Denied by HA, unknown HA address"},
  {0, NULL},
};

/* Code to actually dissect the packets */
static void
dissect_mip(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{

/* Set up structures we will need to add the protocol subtree and manage it */
	proto_item	*ti;
	proto_tree	*mip_tree;
	guint8		type, code;

	/* Make our own tvb until the function call includes one */
	tvbuff_t	*tvb;
	packet_info	*pinfo = &pi;
	tvb = tvb_create_from_top(offset);

	CHECK_DISPLAY_AS_DATA(proto_mip, tvb, pinfo, tree);

/* Make entries in Protocol column and Info column on summary display */

	pinfo->current_proto = "Mobile IP";
	if (check_col(fd, COL_PROTOCOL)) 
		col_set_str(fd, COL_PROTOCOL, "mip");
    
	type = tvb_get_guint8(tvb, 0);

	if (type==1) {

	  if (check_col(fd, COL_INFO)) 
		 col_set_str(fd, COL_INFO, "Mobile IP Registration Request");
	
	  if (tree) {
		 ti = proto_tree_add_item(tree, proto_mip, tvb, 0, tvb_length(tvb), FALSE);
	   	 mip_tree = proto_item_add_subtree(ti, ett_mip);
		 proto_tree_add_int(mip_tree, hf_mip_type, tvb, 0, 1, type);

		 code = tvb_get_guint8(tvb, 1);
		 proto_tree_add_boolean(mip_tree, hf_mip_s, tvb, 1, 1, code);
		 proto_tree_add_boolean(mip_tree, hf_mip_b, tvb, 1, 1, code);
		 proto_tree_add_boolean(mip_tree, hf_mip_d, tvb, 1, 1, code);
		 proto_tree_add_boolean(mip_tree, hf_mip_m, tvb, 1, 1, code);
		 proto_tree_add_boolean(mip_tree, hf_mip_g, tvb, 1, 1, code);
		 proto_tree_add_boolean(mip_tree, hf_mip_v, tvb, 1, 1, code);

		 proto_tree_add_int(mip_tree, hf_mip_life, tvb, 2, 2, tvb_get_ntohs(tvb, 2));
		 proto_tree_add_ipv4(mip_tree, hf_mip_homeaddr, tvb, 4, 4, tvb_get_letohl(tvb, 4));
		 proto_tree_add_ipv4(mip_tree, hf_mip_haaddr, tvb, 8, 4, tvb_get_letohl(tvb, 8));
		 proto_tree_add_ipv4(mip_tree, hf_mip_coa, tvb, 12, 4, tvb_get_letohl(tvb, 12));
		 proto_tree_add_bytes(mip_tree, hf_mip_ident, tvb, 16, 8, tvb_get_ptr(tvb, 16, 8));
	  }
	}


	if (type==3){
	  if (check_col(fd, COL_INFO)) 
		 col_set_str(fd, COL_INFO, "Mobile IP Registration Reply");

	  if (tree) {
		 ti = proto_tree_add_item(tree, proto_mip, tvb, 0, tvb_length(tvb), FALSE);
	   	 mip_tree = proto_item_add_subtree(ti, ett_mip);
		 proto_tree_add_int(mip_tree, hf_mip_type, tvb, 0, 1, type);

		 code = tvb_get_guint8(tvb, 1);
		 proto_tree_add_uint(mip_tree, hf_mip_code, tvb, 1, 1, code);
		 proto_tree_add_int(mip_tree, hf_mip_life, tvb, 2, 2, tvb_get_ntohs(tvb, 2));
		 proto_tree_add_ipv4(mip_tree, hf_mip_homeaddr, tvb, 4, 4, tvb_get_letohl(tvb, 4));
		 proto_tree_add_ipv4(mip_tree, hf_mip_haaddr, tvb, 8, 4, tvb_get_letohl(tvb, 8));
		 proto_tree_add_bytes(mip_tree, hf_mip_ident, tvb, 12, 8, tvb_get_ptr(tvb, 12, 8));
	  }
	}
}

/* Register the protocol with Ethereal */
void proto_register_mip(void)
{                 

/* Setup list of header fields */
	static hf_register_info hf[] = {
	  { &hf_mip_type,
		 { "Message Type",           "mip.type",
			FT_INT8, BASE_DEC, VALS(mip_types), 0,          
			"Mobile IP Message type." }
	  },
	  { &hf_mip_s,
		 {"Simultaneous Bindings",           "mip.s",
		   FT_BOOLEAN, 8, NULL, 128,          
		   "Simultaneous Bindings Allowed" }
	  },
	  { &hf_mip_b,
		 {"Broadcast Datagrams",           "mip.b",
		   FT_BOOLEAN, 8, NULL, 64,          
		   "Broadcast Datagrams requested" }
	  },
	  { &hf_mip_d,
		 { "Co-lcated Care-of Address",           "mip.d",
		   FT_BOOLEAN, 8, NULL, 32,          
		   "MN using Co-located Care-of address" }
	  },
	  { &hf_mip_m,
		 {"Minimal Encapsulation",           "mip.m",
		   FT_BOOLEAN, 8, NULL, 16,          
		   "MN wants Minimal encapsulation" }
	  },
	  { &hf_mip_g,
		 {"GRE",           "mip.g",
		   FT_BOOLEAN, 8, NULL, 8,          
		   "MN wants GRE encapsulation" }
	  },
	  { &hf_mip_v,
		 { "Van Jacobson",           "mip.v",
		   FT_BOOLEAN, 8, NULL, 4,          
		   "Van Jacobson" }
	  },
	  { &hf_mip_code,
		 { "Reply Code",           "mip.code",
			FT_UINT8, BASE_DEC, VALS(mip_reply_codes), 0,          
			"Mobile IP Reply code." }
	  },
	  { &hf_mip_life,
		 { "Lifetime",           "mip.life",
			FT_INT16, BASE_DEC, NULL, 0,          
			"Mobile IP Lifetime." }
	  },
	  { &hf_mip_homeaddr,
		 { "Home Address",           "mip.homeaddr",
			FT_IPv4, BASE_NONE, NULL, 0,          
			"Mobile Node's home address." }
	  },
	  
	  { &hf_mip_haaddr,
		 { "Home Agent",           "mip.haaddr",
			FT_IPv4, BASE_NONE, NULL, 0,          
			"Home agent IP Address." }
	  },
	  { &hf_mip_coa,
		 { "Care of Address",           "mip.coa",
			FT_IPv4, BASE_NONE, NULL, 0,          
			"Care of Address." }
	  },
	  { &hf_mip_ident,
		 { "Identification",           "mip.ident",
			FT_BYTES, BASE_NONE, NULL, 0,          
			"MN Identification." }
	  },




	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_mip,
	};

/* Register the protocol name and description */
	proto_mip = proto_register_protocol("Mobile IP", "Mobile IP", "mip");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_mip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
};

void
proto_reg_handoff_mip(void)
{
	old_dissector_add("udp.port", UDP_PORT_MIP, dissect_mip, proto_mip);
}
