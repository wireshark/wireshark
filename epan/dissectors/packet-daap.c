/* packet-daap.c
 * Routines for Digital Audio Access Protocol dissection
 * Copyright 2004, Kelly Byrd <kbyrd@memcpy.com>
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

#include <glib.h>

#include <epan/packet.h>
#include <epan/dissectors/packet-http.h>

#define TCP_PORT_DAAP 3689

/* DAAP tags */
/* Container tags */
#define daap_mcon       0x6d636f6e
#define daap_msrv       0x6d737276
#define daap_mccr       0x6d636372
#define daap_mdcl       0x6d64636c
#define daap_mlog       0x6d6c6f67
#define daap_mupd       0x6d757064
#define daap_avdb       0x61766462
#define daap_mlcl       0x6d6c636c
#define daap_mlit       0x6d6c6974
#define daap_mbcl       0x6d62636c
#define daap_adbs       0x61646273
#define daap_aply       0x61706c79
#define daap_apso       0x6170736f
#define daap_mudl       0x6d75646c
#define daap_abro       0x6162726f
#define daap_abal       0x6162616c
#define daap_abcp       0x61626370
#define daap_abgn       0x6162676e
#define daap_prsv       0x70727376
#define daap_arif       0x61726966
/* String tags */
#define daap_minm       0x6d696e6d
#define daap_msts       0x6d737473
#define daap_mcnm       0x6d636e6d
#define daap_mcna       0x6d636e61
#define daap_asal       0x6173616c
#define daap_asar       0x61736172
#define daap_ascm       0x6173636d
#define daap_asfm       0x6173666d
#define daap_aseq       0x61736571
#define daap_asgn       0x6173676e
#define daap_asdt       0x61736474
#define daap_asul       0x6173756c
/* uint64 tags */
#define daap_mper       0x6d706572
/* uint32 tags */
#define daap_mstt       0x6d737474
#define daap_musr       0x6d757372
#define daap_miid       0x6d696964
#define daap_mcti       0x6d637469
#define daap_mpco       0x6d70636f
#define daap_mimc       0x6d696d63
#define daap_mrco       0x6d72636f
#define daap_mtco       0x6d74636f
#define daap_mstm       0x6d73746d
#define daap_msdc       0x6d736463
#define daap_mlid       0x6d6c6964
#define daap_msur       0x6d737572
#define daap_asda       0x61736461
#define daap_asdm       0x6173646d
#define daap_assr       0x61737372
#define daap_assz       0x6173737a
#define daap_asst       0x61737374
#define daap_assp       0x61737370
#define daap_astm       0x6173746d
#define daap_aeNV       0x61654e56
/* uint16 tags */
#define daap_mcty       0x6d637479
#define daap_asbt       0x61736274
#define daap_asbr       0x61736272
#define daap_asdc       0x61736463
#define daap_asdn       0x6173646e
#define daap_astc       0x61737463
#define daap_astn       0x6173746e
#define daap_asyr       0x61737972
/* byte  tags */
#define daap_mikd       0x6d696b64
#define daap_msau       0x6d736175
#define daap_msty       0x6d737479
#define daap_asrv       0x61737276
#define daap_asur       0x61737572
#define daap_asdk       0x6173646b
/* boolean  tags */
#define daap_mslr       0x6d736c72
#define daap_msal       0x6d73616c
#define daap_msup       0x6d737570
#define daap_mspi       0x6d737069
#define daap_msex       0x6d736578
#define daap_msbr       0x6d736272
#define daap_msqy       0x6d737179
#define daap_msix       0x6d736978
#define daap_msrs       0x6d737273
#define daap_asco       0x6173636f
#define daap_asdb       0x61736462
#define daap_abpl       0x6162706c
#define daap_aeSP       0x61655350
/* version (32-bit)*/
#define daap_mpro       0x6d70726f
#define daap_apro       0x6170726f


/* Initialize the protocol and registered fields */
static int proto_daap = -1;
static int hf_daap_name = -1;
static int hf_daap_size = -1;

/* Initialize the subtree pointers */
static gint ett_daap = -1;
static gint ett_daap_sub = -1;

/* Forward declarations */
static int dissect_daap_one_tag(proto_tree *tree, tvbuff_t *tvb, int offset, int length);

static void
dissect_daap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *daap_tree;
   int offset = 0;
   gboolean is_request = (pinfo->destport == TCP_PORT_DAAP);

   if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "DAAP");

   /*
    * XXX - what if the body is gzipped?  This isn't the only protocol
    * running atop HTTP that might have a problem with that....
    */
   if (check_col(pinfo->cinfo, COL_INFO)) {
      if (is_request) {
	 col_add_str(pinfo->cinfo, COL_INFO, "DAAP Request");
      } else {
	 /* This is done in two functions on purpose. If the tvb_get_xxx()
	  * functions fail, at least something will be in the info column
	  */
	 col_add_str(pinfo->cinfo, COL_INFO, "DAAP Response");
	 col_append_fstr(pinfo->cinfo, COL_INFO, " [tag: %s, size: %d]",
	 	 tvb_format_text(tvb, offset, 4), tvb_get_ntohl(tvb, offset+4));
      }
   }

   if (tree) {
      ti = proto_tree_add_item(tree, proto_daap, tvb, 0, -1, FALSE);
      daap_tree = proto_item_add_subtree(ti, ett_daap);     
      dissect_daap_one_tag(daap_tree, tvb, offset, 0);
   }
}

static int
dissect_daap_one_tag(proto_tree *tree, tvbuff_t *tvb, int offset, int length)
{
   unsigned int tagname;
   int tagsize;
   int new_offset;
   proto_item *ti = NULL;
   proto_item *ti2 = NULL;
   proto_tree *new_tree = NULL;

   do {
      if (!tvb_offset_exists(tvb, offset)) 
	 break;

      tagname = tvb_get_ntohl(tvb, offset);
      tagsize = tvb_get_ntohl(tvb, offset+4);
      tvb_ensure_bytes_exist(tvb, offset, tagsize+8);
      ti = proto_tree_add_text(tree, tvb, offset, tagsize+8, 
			       "Tag: %c%c%c%c, Size: %d", 
			       tvb_get_guint8(tvb, offset),
			       tvb_get_guint8(tvb, offset+1),
			       tvb_get_guint8(tvb, offset+2),
			       tvb_get_guint8(tvb, offset+3),
			       tagsize);

      ti2 = proto_tree_add_item(tree, hf_daap_name, tvb, offset, 4, FALSE);
      PROTO_ITEM_SET_HIDDEN(ti2);
      ti2 = proto_tree_add_item(tree, hf_daap_size, tvb, offset+4, 4, FALSE);
      PROTO_ITEM_SET_HIDDEN(ti2);
      offset += 8;
      length -= 8;

      switch (tagname) {
      case daap_mcon:
      case daap_msrv:
      case daap_mccr:
      case daap_mdcl:
      case daap_mlog:
      case daap_mupd:
      case daap_avdb:
      case daap_mlcl:
      case daap_mlit:
      case daap_mbcl:
      case daap_adbs:
      case daap_aply:
      case daap_apso:
      case daap_mudl:
      case daap_abro:
      case daap_abal:
      case daap_abcp:
      case daap_abgn:
      case daap_prsv:
      case daap_arif:
	 /* Container tags */
	 new_tree = proto_item_add_subtree(ti, ett_daap_sub);
	 new_offset = dissect_daap_one_tag(new_tree, tvb, offset, 
					   tagsize);
	 break;
      case daap_minm:
      case daap_msts:
      case daap_mcnm:
      case daap_mcna:
      case daap_asal:
      case daap_asar:
      case daap_ascm:
      case daap_asfm:
      case daap_aseq:
      case daap_asgn:
      case daap_asdt:
      case daap_asul:
	 /* Tags contain strings */
	 proto_item_append_text(ti, ", Data: %s",
				tvb_format_text(tvb, offset, tagsize));
	 break;
      case daap_mper:
	 /* Tags conain uint64 */
	 proto_item_append_text(ti, ", Persistent Id: %" PRIu64, 
				tvb_get_ntoh64(tvb, offset));
	 break;
      case daap_mstt:
	 proto_item_append_text(ti, ", Status: %d", 
				tvb_get_ntohl(tvb, offset));
	 break;
      case daap_musr:
      case daap_msur:
	 proto_item_append_text(ti, ", Revision: %d", 
				tvb_get_ntohl(tvb, offset));
	 break;
      case daap_miid:
      case daap_mcti:
      case daap_mpco:
      case daap_mlid:
	 proto_item_append_text(ti, ", Id: %d", 
				tvb_get_ntohl(tvb, offset));
	 break;
      case daap_mrco:
      case daap_mtco:
      case daap_mimc:
      case daap_msdc:
	 proto_item_append_text(ti, ", Count: %d", 
				tvb_get_ntohl(tvb, offset));
	 break;
      case daap_mstm:
	 proto_item_append_text(ti, ", Timeout: %d seconds", 
				tvb_get_ntohl(tvb, offset));
	 break;
      case daap_asda:
      case daap_asdm:
      case daap_assr:
      case daap_assz:
      case daap_asst:
      case daap_assp:
      case daap_astm:
      case daap_aeNV:
	 /* Tags conain uint32 */
	 proto_item_append_text(ti, ", Data: %d", 
				tvb_get_ntohl(tvb, offset));
	 break;

      case daap_mcty:
      case daap_asbt:
      case daap_asbr:
      case daap_asdc:
      case daap_asdn:
      case daap_astc:
      case daap_astn:
      case daap_asyr:
	 /* Tags conain uint16 */
	 proto_item_append_text(ti, ", Data: %d", 
				tvb_get_ntohs(tvb, offset));
	 break;

      case daap_mikd:
      case daap_msau:
      case daap_msty:
      case daap_asrv:
      case daap_asur:
      case daap_asdk:
	 /* Tags conain uint8 */
	 proto_item_append_text(ti, ", Data: %d", 
				tvb_get_guint8(tvb, offset));

	 break;

      case daap_mslr:
      case daap_msal:
      case daap_msup:
      case daap_mspi:
      case daap_msex:
      case daap_msbr:
      case daap_msqy:
      case daap_msix:
      case daap_msrs:
      case daap_asco:
      case daap_asdb:
      case daap_abpl:
      case daap_aeSP:
	 /* Tags ARE boolean. Data is (uint8), but it seems
	  * the value is always zero. So, if the tag is present
	  * the "bool" is true. 
	  */
	 proto_item_append_text(ti, ", Data: True");
	 break;

      case daap_mpro:
      case daap_apro:
	 /* Tags conain version (uint32) */
	 proto_item_append_text(ti, ", Version: %d.%d.%d.%d",
				tvb_get_guint8(tvb, offset),
				tvb_get_guint8(tvb, offset+1),
				tvb_get_guint8(tvb, offset+2),
				tvb_get_guint8(tvb, offset+3));
	 break;

      default: 
	 break;
      }
      offset += tagsize;
      length -= tagsize;
   } while (length > 0);
   return offset;
}


/* Register the protocol with Wireshark */
void
proto_register_daap(void)
{        
   
   static hf_register_info hf[] = {
      { &hf_daap_name,
	{ "Name", "daap.name", FT_STRING, BASE_NONE, NULL, 0x0, 
	  "Tag Name", HFILL}
      },
      { &hf_daap_size,
	{ "Size", "daap.size", FT_UINT32, BASE_DEC, NULL, 0x0, 
	  "Tag Size", HFILL }
      }
   };

   static gint *ett[] = {
      &ett_daap,
      &ett_daap_sub,
   };

   proto_daap = proto_register_protocol("Digital Audio Access Protocol",
					"DAAP", "daap");

   proto_register_field_array(proto_daap, hf, array_length(hf));
   proto_register_subtree_array(ett, array_length(ett));
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_daap(void)
{
    dissector_handle_t daap_handle;

    daap_handle = create_dissector_handle(dissect_daap, proto_daap);
    http_dissector_add(TCP_PORT_DAAP, daap_handle);
}
