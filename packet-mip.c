/* packet-mip.c
 * Routines for Mobile IP dissection
 * Copyright 2000, Stefan Raab <sraab@cisco.com>
 *
 * $Id: packet-mip.c,v 1.16 2001/02/27 00:27:26 guy Exp $
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
#include <time.h>

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
static int hf_mip_t = -1;
static int hf_mip_code = -1;
static int hf_mip_life = -1;
static int hf_mip_homeaddr = -1;
static int hf_mip_haaddr = -1;
static int hf_mip_coa = -1;
static int hf_mip_ident = -1;
static int hf_mip_ext_type = -1;
static int hf_mip_ext_len = -1;
static int hf_mip_aext_spi = -1;
static int hf_mip_aext_auth = -1;
static int hf_mip_next_nai = -1;

/* Initialize the subtree pointers */
static gint ett_mip = -1;
static gint ett_mip_ext = -1;

/* Port used for Mobile IP */
#define UDP_PORT_MIP    434
#define NTP_BASETIME 2208988800ul

static const value_string mip_types[] = {
  {1, "Registration Request"},
  {3, "Registration Reply"},
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

static const value_string mip_ext_types[]= {
  {32, "Mobile-Home Authentication Extension"},
  {33, "Mobile-Foreign Authentication Extension"},
  {34, "Foreign-Home Authentication Extension"},
  {131, "Mobile Node NAI Extension"},
  {0, NULL},
};

/* Code to actually dissect the packets */
static void
dissect_mip( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures we will need to add the protocol subtree and manage it */
	proto_item	*ti;
	proto_tree	*mip_tree=NULL, *ext_tree=NULL;
	guint8		type, code;
	struct timeval      ident_time;
	int eoffset, elen;
	
/* Make entries in Protocol column and Info column on summary display */

	if (check_col(pinfo->fd, COL_PROTOCOL)) 
		col_set_str(pinfo->fd, COL_PROTOCOL, "MobileIP");
	if (check_col(pinfo->fd, COL_INFO)) 
		col_clear(pinfo->fd, COL_INFO);
    
	type = tvb_get_guint8(tvb, 0);

	if (type==1) {

	  if (check_col(pinfo->fd, COL_INFO)) 
		 col_add_fstr(pinfo->fd, COL_INFO, "Reg Request: HAddr=%s COA=%s", 
						  ip_to_str(tvb_get_ptr(tvb, 4, 4)), ip_to_str(tvb_get_ptr(tvb,12,4)));
	
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
		 proto_tree_add_boolean(mip_tree, hf_mip_t, tvb, 1, 1, code);
		 
		 proto_tree_add_item(mip_tree, hf_mip_life, tvb, 2, 2, FALSE);
		 proto_tree_add_item(mip_tree, hf_mip_homeaddr, tvb, 4, 4, FALSE);
		 proto_tree_add_item(mip_tree, hf_mip_haaddr, tvb, 8, 4, FALSE);
		 proto_tree_add_item(mip_tree, hf_mip_coa, tvb, 12, 4, FALSE);
		 ident_time.tv_sec =  tvb_get_ntohl(tvb,16)-(guint32) NTP_BASETIME;
		 ident_time.tv_usec = tvb_get_ntohl(tvb,20);
		 proto_tree_add_time(mip_tree, hf_mip_ident, tvb, 16, 8, &ident_time);
		 
		 eoffset = 24;
		 while (eoffset < tvb_length(tvb)) {             /* Registration Extensions */
			if (eoffset ==24) {
			  ti = proto_tree_add_text(mip_tree, tvb, 24, tvb_length(tvb)-24, "Extensions");
			  ext_tree = proto_item_add_subtree(ti, ett_mip_ext);
			}

			proto_tree_add_item(ext_tree, hf_mip_ext_type, tvb, eoffset, 1, FALSE);
			elen = tvb_get_guint8(tvb, eoffset+1);
			proto_tree_add_int(ext_tree, hf_mip_ext_len, tvb, eoffset+1, 1, elen);

			switch (tvb_get_guint8(tvb, eoffset)) {
			case 32:
			case 33:
			case 34:
			  proto_tree_add_item(ext_tree, hf_mip_aext_spi, tvb, eoffset+2, 4, FALSE);
			  proto_tree_add_item(ext_tree, hf_mip_aext_auth, tvb, eoffset+6, elen-4, FALSE);
			  break;
			case 131:
			  proto_tree_add_string(ext_tree, hf_mip_next_nai, tvb, eoffset+2, 
											tvb_get_guint8(tvb, eoffset+1), 
											tvb_get_ptr(tvb, eoffset+2,tvb_get_guint8(tvb, eoffset+1)));
			  break;
			default:
			  proto_tree_add_text(ext_tree, tvb, eoffset + 2,  tvb_get_guint8(tvb, eoffset+1), 
										 "Unknown Extension");
			  break;
			  
			}
			eoffset += tvb_get_guint8(tvb, eoffset+1) + 2;
		 }
	  }
	}

	
	if (type==3){
	  if (check_col(pinfo->fd, COL_INFO)) 
		 col_add_fstr(pinfo->fd, COL_INFO, "Reg Reply: HAddr=%s, Code=%u", 
						  ip_to_str(tvb_get_ptr(tvb,4,4)), tvb_get_guint8(tvb,1));
	  
	  if (tree) {
		 ti = proto_tree_add_item(tree, proto_mip, tvb, 0, tvb_length(tvb), FALSE);
		 mip_tree = proto_item_add_subtree(ti, ett_mip);
		 proto_tree_add_int(mip_tree, hf_mip_type, tvb, 0, 1, type);
		 
		 /*	 code = tvb_get_guint8(tvb, 1);
				 proto_tree_add_uint(mip_tree, hf_mip_code, tvb, 1, 1, code);*/
		 proto_tree_add_item(mip_tree, hf_mip_code, tvb, 1, 1, FALSE);
		 proto_tree_add_item(mip_tree, hf_mip_life, tvb, 2, 2, FALSE);
		 proto_tree_add_item(mip_tree, hf_mip_homeaddr, tvb, 4, 4, FALSE);
  		 proto_tree_add_item(mip_tree, hf_mip_haaddr, tvb, 8, 4, FALSE);
		 ident_time.tv_sec =  tvb_get_ntohl(tvb,12)-(guint32) NTP_BASETIME;
		 ident_time.tv_usec = tvb_get_ntohl(tvb,16);
		 proto_tree_add_time(mip_tree, hf_mip_ident, tvb, 12, 8, &ident_time);
		 
		 eoffset = 20;
		 while (eoffset < tvb_length(tvb)) {             /* Registration Extensions */
			if (eoffset==20) {
			  ti = proto_tree_add_text(mip_tree, tvb, 20, tvb_length(tvb)-20, "Extensions");
			  ext_tree = proto_item_add_subtree(ti, ett_mip_ext);
			}
			
			proto_tree_add_int(ext_tree, hf_mip_ext_type, tvb, eoffset, 1, 
									 tvb_get_guint8(tvb, eoffset));
			elen = tvb_get_guint8(tvb, eoffset+1);
			proto_tree_add_int(ext_tree, hf_mip_ext_len, tvb, eoffset+1, 1, elen);
			
			switch (tvb_get_guint8(tvb, eoffset)) {
			case 32:
			case 33:
			case 34:                             
			  proto_tree_add_item(ext_tree, hf_mip_aext_spi, tvb, eoffset+2, 4, FALSE);
			  proto_tree_add_item(ext_tree, hf_mip_aext_auth, tvb, eoffset+6, elen-4, FALSE);
			  break;
			case 131:
			  proto_tree_add_item(ext_tree, hf_mip_next_nai, tvb, eoffset+2, 
											tvb_get_guint8(tvb, eoffset+1), FALSE);
			  break;
			default:
			  proto_tree_add_text(ext_tree, tvb, eoffset + 2,  tvb_get_guint8(tvb, eoffset+1), 
										 "Unknown Extension");
			  break;
			}
			eoffset += tvb_get_guint8(tvb, eoffset+1) + 2;
		 }
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
	  { &hf_mip_t,
		 { "Reverse Tunneling",           "mip.t",
		   FT_BOOLEAN, 8, NULL, 2,          
		   "Reverse tunneling requested" }
	  },
	  { &hf_mip_code,
		 { "Reply Code",           "mip.code",
			FT_UINT8, BASE_DEC, VALS(mip_reply_codes), 0,          
			"Mobile IP Reply code." }
	  },
	  { &hf_mip_life,
		 { "Lifetime",           "mip.life",
			FT_UINT16, BASE_DEC, NULL, 0,          
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
			FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0,          
			"MN Identification." }
	  },
	  { &hf_mip_ext_type,
		 { "Extension Type",           "mip.ext.type",
			FT_INT8, BASE_DEC, VALS(mip_ext_types), 0,          
			"Mobile IP Extension Type." }
	  },
	  { &hf_mip_ext_len,
		 { "Extension Length",         "mip.ext.len",
			FT_INT8, BASE_DEC, NULL, 0,
			"Mobile IP Extension Length."}
	  },
	  { &hf_mip_aext_spi,
		 { "SPI",                      "mip.auth.spi",
			FT_INT32, BASE_HEX, NULL, 0,
			"Authentication Header Security Parameter Index."}
	  },
	  { &hf_mip_aext_auth,
		 { "Authenticator",            "mip.auth.auth",
			FT_BYTES, BASE_NONE, NULL, 0,
			"Authenticator."}
	  },
	  { &hf_mip_next_nai,
		 { "NAI",                      "mip.nai",
			FT_STRING, BASE_NONE, NULL, 0,
			"NAI"}
	  },
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_mip,
		&ett_mip_ext,
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
	dissector_add("udp.port", UDP_PORT_MIP, dissect_mip, proto_mip);
}
