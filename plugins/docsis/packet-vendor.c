/* packet-vendor.c
 * Routines for Vendor Specific Encodings dissection
 * Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
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


/* Notes to Adding dissectors for Vendor specific TLV's:
 * 1. Create a dissect_<vendorname> function with the following prototype:
 *   dissect_foovendor(tvbuff_t *tvb, proto_tree *tree, gint vsif_len)
 * 2. vsif_len will be the *entire* length of the vsif TLV (including the 
 *   Vendor Id TLV, which is 5 bytes long).
 * 3. Create a new 'case' statement in dissect_vsif, for your specific Vendor
 *   id.  
 * 4. In that 'case' statement you will make the following calls:
 *   (assume for this example that your vendor id is 0x000054)
 *   #define VENDOR_FOOVENDOR 0x00054 
 *   case VENDOR_FOOVENDOR:
 *      proto_item_append_text (it, " (foo vendor)");
 *      dissect_foovendor (tvb, vsif_tree, vsif_len);
 *      break;
 * 5.  Please see dissect_cisco for an example of how to do this.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "moduleinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <gmodule.h>

#include <epan/packet.h>

/* Define Vendor ID's here */
#define VENDOR_CISCO 0x00000C

/* Initialize the protocol and registered fields */
static int proto_docsis_vsif = -1;
static int hf_docsis_vsif = -1;
static int hf_docsis_vsif_vendorid = -1;
static int hf_docsis_vsif_vendor_unknown = -1;
static int hf_docsis_vsif_cisco_numphones = -1;
static int hf_docsis_vsif_cisco_ipprec = -1;
static int hf_docsis_vsif_cisco_ipprec_val = -1;
static int hf_docsis_vsif_cisco_ipprec_bw = -1;
static int hf_docsis_vsif_cisco_config_file = -1;

/* Initialize the subtree pointers */
static gint ett_docsis_vsif = -1;
static gint ett_docsis_vsif_ipprec = -1;

static const value_string vendorid_vals[] = {
	{VENDOR_CISCO, "Cisco Systems, Inc."},
	{0, NULL},
};



/* Forward Declarations for vendor specific dissectors */
static void dissect_cisco (tvbuff_t * tvb, proto_tree * tree,
			   gint vsif_len);

/* Code to actually dissect the packets */
static void
dissect_vsif (tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * tree)
{
  proto_item *it;
  proto_tree *vsif_tree;
  guint8 type;
  guint8 length;
  guint32 value;
  gint vsif_len;

/* get the reported length of the VSIF TLV */
  vsif_len = tvb_reported_length_remaining (tvb, 0);

/* The first TLV in the VSIF encodings must be type 0x08 (Vendor ID) and
 * length 3.
 */
  type = tvb_get_guint8 (tvb, 0);
  if (type != 0x08)
    {
      THROW (ReportedBoundsError);
    }

  length = tvb_get_guint8 (tvb, 1);
  if (length != 3)
    {
      THROW (ReportedBoundsError);
    }

  /* Extract the Value of the Vendor ID */
  value = tvb_get_ntoh24 (tvb, 2);
  if (tree)
    {
      it =
	proto_tree_add_protocol_format (tree, proto_docsis_vsif, tvb, 0, -1,
					"VSIF Encodings");
      vsif_tree = proto_item_add_subtree (it, ett_docsis_vsif);
      proto_tree_add_item (vsif_tree, hf_docsis_vsif_vendorid, tvb, 2, 3, FALSE);

      /* switch on the Vendor ID */
      switch (value)
	{
	case VENDOR_CISCO:
	  proto_item_append_text (it, " (Cisco)");
	  dissect_cisco (tvb, vsif_tree, vsif_len);
	  break;
	default:
	  proto_item_append_text (it, " (Unknown)");
	  proto_tree_add_item (vsif_tree, hf_docsis_vsif_vendor_unknown, tvb,
			       0, -1, FALSE);
	  break;
	}

    }				/* if(tree) */


}


/* Dissector for Cisco Vendor Specific TLV's */

#define NUM_PHONES 0x0a
#define IOS_CONFIG_FILE 0x80
#define IP_PREC 0x0b
#define IP_PREC_VAL 0x01
#define IP_PREC_BW  0x02

static void
dissect_cisco (tvbuff_t * tvb, proto_tree * tree, gint vsif_len)
{
  /* Start at pos = 5, since tvb includes the Vendor ID field */
  int pos = 5;
  guint8 type, length;
  proto_item *ipprec_it;
  proto_tree *ipprec_tree;
  int templen;

  while (pos < vsif_len)
    {
      /* Extract the type and length Fields from the TLV */
      type = tvb_get_guint8 (tvb, pos++);
      length = tvb_get_guint8 (tvb, pos++);
      switch (type)
	{
	case NUM_PHONES:
	  proto_tree_add_item (tree, hf_docsis_vsif_cisco_numphones, tvb,
			       pos, length, FALSE);
	  break;
	case IP_PREC:
	  ipprec_it =
	    proto_tree_add_text (tree, tvb, pos, length, "IP Precedence");
	  ipprec_tree =
	    proto_item_add_subtree (ipprec_it, ett_docsis_vsif_ipprec);
	  /* Handle Sub-TLVs in IP Precedence */
	  templen = pos + length;
	  while (pos < templen)
	    {
	      type = tvb_get_guint8 (tvb, pos++);
	      length = tvb_get_guint8 (tvb, pos++);
	      switch (type)
		{
		case IP_PREC_VAL:
		  if (length != 1)
		    THROW (ReportedBoundsError);
		  proto_tree_add_item (ipprec_tree,
				       hf_docsis_vsif_cisco_ipprec_val, tvb,
				       pos, length, FALSE);
		  break;
		case IP_PREC_BW:
		  if (length != 4)
		    THROW (ReportedBoundsError);
		  proto_tree_add_item (ipprec_tree,
				       hf_docsis_vsif_cisco_ipprec_bw, tvb,
				       pos, length, FALSE);
		  break;
		default:
		  THROW (ReportedBoundsError);
		}
	      pos += length;
	    }
	  break;
	case IOS_CONFIG_FILE:
	  proto_tree_add_item (tree, hf_docsis_vsif_cisco_config_file, tvb,
			       pos, length, FALSE);
	}
      pos += length;
    }

}



/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/


void
proto_register_docsis_vsif (void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf[] = {
    {&hf_docsis_vsif,
     {"VSIF Encodings", "docsis.vsif",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Vendor Specific Encodings", HFILL}
     },
    {&hf_docsis_vsif_vendorid,
     {"Vendor Id", "docsis.vsif.vendorid",
      FT_UINT24, BASE_HEX, VALS(vendorid_vals), 0x0,
      "Vendor Identifier", HFILL}
     },
    {&hf_docsis_vsif_vendor_unknown,
     {"VSIF Encodings", "docsis.vsif.unknown",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "Unknown Vendor", HFILL}
     },
    {&hf_docsis_vsif_cisco_numphones,
     {"Number of phone lines", "docsis.vsif.cisco.numphones",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "Number of phone lines", HFILL}
     },
    {&hf_docsis_vsif_cisco_ipprec,
     {"IP Precedence Encodings", "docsis.vsif.cisco.ipprec",
      FT_BYTES, BASE_HEX, NULL, 0x0,
      "IP Precedence Encodings", HFILL}
     },
    {&hf_docsis_vsif_cisco_ipprec_val,
     {"IP Precedence Value", "docsis.vsif.cisco.ipprec.value",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "IP Precedence Value", HFILL}
     },
    {&hf_docsis_vsif_cisco_ipprec_bw,
     {"IP Precedence Bandwidth", "docsis.vsif.cisco.ipprec.bw",
      FT_UINT8, BASE_DEC, NULL, 0x0,
      "IP Precedence Bandwidth", HFILL}
     },
    {&hf_docsis_vsif_cisco_config_file,
     {"IOS Config File", "docsis.vsif.cisco.iosfile",
      FT_STRING, BASE_DEC, NULL, 0x0,
      "IOS Config File", HFILL}
     },
  };

/* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_docsis_vsif,
    &ett_docsis_vsif_ipprec,
  };

/* Register the protocol name and description */
  proto_docsis_vsif =
    proto_register_protocol ("DOCSIS Vendor Specific Encodings",
			     "DOCSIS VSIF", "docsis_vsif");

/* Required function calls to register the header fields and subtrees used */
  proto_register_field_array (proto_docsis_vsif, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));

  register_dissector ("docsis_vsif", dissect_vsif, proto_docsis_vsif);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_docsis_vsif (void)
{
  dissector_handle_t docsis_vsif_handle;

  docsis_vsif_handle = find_dissector ("docsis_vsif");
  dissector_add ("docsis", 0xFD, docsis_vsif_handle);

}
