/* packet-nv.c
 * Routines for ethercat packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

#include "packet-nv.h"

/* Define the nv proto */
int proto_nv  = -1;

static int ett_nv = -1;
static int ett_nv_header = -1;
static int ett_nv_var = -1;
static int ett_nv_varheader = -1;

static int hf_nv_summary = -1;
static int hf_nv_header = -1;
static int hf_nv_publisher = -1;
static int hf_nv_count = -1;
static int hf_nv_cycleindex = -1;
static int hf_nv_variable = -1;
static int hf_nv_varheader = -1;
static int hf_nv_id = -1;
static int hf_nv_hash = -1;
static int hf_nv_length = -1;
static int hf_nv_quality = -1;
static int hf_nv_data = -1;

/*nv*/
static void NvSummaryFormater(tvbuff_t *tvb, gint offset, char *szText, int nMax)
{
   guint32 nvOffset = offset;

   g_snprintf ( szText, nMax, "Network Vars from %d.%d.%d.%d.%d.%d - %d Var(s)",
      tvb_get_guint8(tvb, nvOffset),
      tvb_get_guint8(tvb, nvOffset+1),
      tvb_get_guint8(tvb, nvOffset+2),
      tvb_get_guint8(tvb, nvOffset+3),
      tvb_get_guint8(tvb, nvOffset+4),
      tvb_get_guint8(tvb, nvOffset+5),
      tvb_get_letohs(tvb, nvOffset+6));
}

static void NvPublisherFormater(tvbuff_t *tvb, gint offset, char *szText, int nMax)
{
   guint32 nvOffset = offset;

   g_snprintf ( szText, nMax, "Publisher %d.%d.%d.%d.%d.%d",
      tvb_get_guint8(tvb, nvOffset),
      tvb_get_guint8(tvb, nvOffset+1),
      tvb_get_guint8(tvb, nvOffset+2),
      tvb_get_guint8(tvb, nvOffset+3),
      tvb_get_guint8(tvb, nvOffset+4),
      tvb_get_guint8(tvb, nvOffset+5));    
}

static void NvVarHeaderFormater(tvbuff_t *tvb, gint offset, char *szText, int nMax)
{ 
   g_snprintf ( szText, nMax, "Variable - Id = %d, Length = %d",
      tvb_get_letohs(tvb, offset),
      tvb_get_letohs(tvb, offset+4));
}

static void dissect_nv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
   proto_item *ti;
   proto_tree *nv_tree, *nv_header_tree, *nv_var_tree,*nv_varheader_tree;
   gint offset = 0;
   char szText[200];
   int nMax = sizeof(szText)-1;

   gint i;
 
   col_set_str(pinfo->cinfo, COL_PROTOCOL, "TC-NV");

   col_clear(pinfo->cinfo, COL_INFO);
   
   NvSummaryFormater(tvb, offset, szText, nMax);
   col_append_str(pinfo->cinfo, COL_INFO, szText);

   if (tree) 
   {
      guint16 nv_count;

      ti = proto_tree_add_item(tree, proto_nv, tvb, 0, -1, TRUE);
      nv_tree = proto_item_add_subtree(ti, ett_nv);
      proto_item_append_text(ti,": %s",szText);

      ti = proto_tree_add_item(nv_tree, hf_nv_header, tvb, offset, NvParserHDR_Len, ENC_NA);

      nv_header_tree = proto_item_add_subtree(ti, ett_nv_header);

      ti= proto_tree_add_item(nv_header_tree, hf_nv_publisher, tvb, offset, sizeof(guint8)*6, ENC_NA);
      NvPublisherFormater(tvb, offset, szText, nMax);
      proto_item_set_text(ti, "%s", szText);
      offset+=(sizeof(guint8)*6);

      proto_tree_add_item(nv_header_tree, hf_nv_count, tvb, offset, sizeof(guint16), TRUE);
      nv_count = tvb_get_letohs(tvb, offset);
      offset+=sizeof(guint16);

      proto_tree_add_item(nv_header_tree, hf_nv_cycleindex, tvb, offset, sizeof(guint16), TRUE);
      offset = NvParserHDR_Len;

      for ( i=0; i < nv_count; i++ )
      {
         guint16 var_length = tvb_get_letohs(tvb, offset+4);

         ti = proto_tree_add_item(nv_tree, hf_nv_variable, tvb, offset, ETYPE_88A4_NV_DATA_HEADER_Len+var_length, ENC_NA);
         NvVarHeaderFormater(tvb, offset, szText, nMax);
         proto_item_set_text(ti, "%s", szText);

         nv_var_tree = proto_item_add_subtree(ti, ett_nv_var);
         ti = proto_tree_add_item(nv_var_tree, hf_nv_varheader, tvb, offset, ETYPE_88A4_NV_DATA_HEADER_Len, ENC_NA);

         nv_varheader_tree = proto_item_add_subtree(ti, ett_nv_varheader);
         proto_tree_add_item(nv_varheader_tree, hf_nv_id, tvb, offset, sizeof(guint16), TRUE);
         offset+=sizeof(guint16);

         proto_tree_add_item(nv_varheader_tree, hf_nv_hash, tvb, offset, sizeof(guint16), TRUE);
         offset+=sizeof(guint16);

         proto_tree_add_item(nv_varheader_tree, hf_nv_length, tvb, offset, sizeof(guint16), TRUE);
         offset+=sizeof(guint16);

         proto_tree_add_item(nv_varheader_tree, hf_nv_quality, tvb, offset, sizeof(guint16), TRUE);
         offset+=sizeof(guint16);

         proto_tree_add_item(nv_var_tree, hf_nv_data, tvb, offset, var_length, ENC_NA);
         offset+=var_length;            
      }
   }   
}

void proto_register_nv(void)
{
   static hf_register_info hf[] =
   {
      { &hf_nv_summary,
      { "Summary of the Nv Packet", "tc_nv.summary",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_header, { "Header", "tc_nv.header",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_publisher, { "Publisher", "tc_nv.publisher",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_count, { "Count", "tc_nv.count",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_cycleindex, { "CycleIndex", "tc_nv.cycleindex",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_variable, { "Variable", "tc_nv.variable",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_varheader, { "VarHeader", "tc_nv.varheader",
      FT_NONE, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_id, { "Id", "tc_nv.id",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_hash, { "Hash", "tc_nv.hash",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_length, { "Length", "tc_nv.length",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_quality, { "Quality", "tc_nv.quality",
      FT_UINT16, BASE_HEX, NULL, 0x0,
      NULL, HFILL }
      },
      { &hf_nv_data, { "Data", "tc_nv.data",
      FT_BYTES, BASE_NONE, NULL, 0x0,
      NULL, HFILL }
      },
   };

   static gint *ett[] =
   {
      &ett_nv,
      &ett_nv_header,
      &ett_nv_var,
      &ett_nv_varheader
   };

   proto_nv = proto_register_protocol("TwinCAT NV",
      "TC-NV","tc_nv");
   proto_register_field_array(proto_nv,hf,array_length(hf));
   proto_register_subtree_array(ett,array_length(ett));
}

void proto_reg_handoff_nv(void)
{
   dissector_handle_t nv_handle;

   nv_handle = create_dissector_handle(dissect_nv, proto_nv);  
   dissector_add_uint("ecatf.type", 4, nv_handle);
}
