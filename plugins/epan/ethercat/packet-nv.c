/* packet-nv.c
 * Routines for ethercat packet disassembly
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Include files */

#include "config.h"

#include <epan/packet.h>

#include "packet-nv.h"

void proto_register_nv(void);
void proto_reg_handoff_nv(void);

/* Define the nv proto */
int proto_nv;

static dissector_handle_t nv_handle;

static int ett_nv;
static int ett_nv_header;
static int ett_nv_var;
static int ett_nv_varheader;

/* static int hf_nv_summary; */
static int hf_nv_header;
static int hf_nv_publisher;
static int hf_nv_count;
static int hf_nv_cycleindex;
static int hf_nv_variable;
static int hf_nv_varheader;
static int hf_nv_id;
static int hf_nv_hash;
static int hf_nv_length;
static int hf_nv_quality;
static int hf_nv_data;

/*nv*/
static void NvSummaryFormater(tvbuff_t *tvb, int offset, char *szText, int nMax)
{
   uint32_t nvOffset = offset;

   snprintf ( szText, nMax, "Network Vars from %d.%d.%d.%d.%d.%d - %d Var(s)",
      tvb_get_uint8(tvb, nvOffset),
      tvb_get_uint8(tvb, nvOffset+1),
      tvb_get_uint8(tvb, nvOffset+2),
      tvb_get_uint8(tvb, nvOffset+3),
      tvb_get_uint8(tvb, nvOffset+4),
      tvb_get_uint8(tvb, nvOffset+5),
      tvb_get_letohs(tvb, nvOffset+6));
}

static void NvPublisherFormater(tvbuff_t *tvb, int offset, char *szText, int nMax)
{
   uint32_t nvOffset = offset;

   snprintf ( szText, nMax, "Publisher %d.%d.%d.%d.%d.%d",
      tvb_get_uint8(tvb, nvOffset),
      tvb_get_uint8(tvb, nvOffset+1),
      tvb_get_uint8(tvb, nvOffset+2),
      tvb_get_uint8(tvb, nvOffset+3),
      tvb_get_uint8(tvb, nvOffset+4),
      tvb_get_uint8(tvb, nvOffset+5));
}

static void NvVarHeaderFormater(tvbuff_t *tvb, int offset, char *szText, int nMax)
{
   snprintf ( szText, nMax, "Variable - Id = %d, Length = %d",
      tvb_get_letohs(tvb, offset),
      tvb_get_letohs(tvb, offset+4));
}

static int dissect_nv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   proto_item *ti;
   proto_tree *nv_tree, *nv_header_tree, *nv_var_tree,*nv_varheader_tree;
   int offset = 0;
   char szText[200];
   int nMax = (int)sizeof(szText)-1;

   int i;

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "TC-NV");

   col_clear(pinfo->cinfo, COL_INFO);

   NvSummaryFormater(tvb, offset, szText, nMax);
   col_append_str(pinfo->cinfo, COL_INFO, szText);

   if (tree)
   {
      uint16_t nv_count;

      ti = proto_tree_add_item(tree, proto_nv, tvb, 0, -1, ENC_NA);
      nv_tree = proto_item_add_subtree(ti, ett_nv);
      proto_item_append_text(ti,": %s",szText);

      ti = proto_tree_add_item(nv_tree, hf_nv_header, tvb, offset, NvParserHDR_Len, ENC_NA);

      nv_header_tree = proto_item_add_subtree(ti, ett_nv_header);

      ti= proto_tree_add_item(nv_header_tree, hf_nv_publisher, tvb, offset, (int)sizeof(uint8_t)*6, ENC_NA);
      NvPublisherFormater(tvb, offset, szText, nMax);
      proto_item_set_text(ti, "%s", szText);
      offset+=((int)sizeof(uint8_t)*6);

      proto_tree_add_item(nv_header_tree, hf_nv_count, tvb, offset, (int)sizeof(uint16_t), ENC_LITTLE_ENDIAN);
      nv_count = tvb_get_letohs(tvb, offset);
      offset+=(int)sizeof(uint16_t);

      proto_tree_add_item(nv_header_tree, hf_nv_cycleindex, tvb, offset, (int)sizeof(uint16_t), ENC_LITTLE_ENDIAN);
      offset = NvParserHDR_Len;

      for ( i=0; i < nv_count; i++ )
      {
         uint16_t var_length = tvb_get_letohs(tvb, offset+4);

         ti = proto_tree_add_item(nv_tree, hf_nv_variable, tvb, offset, ETYPE_88A4_NV_DATA_HEADER_Len+var_length, ENC_NA);
         NvVarHeaderFormater(tvb, offset, szText, nMax);
         proto_item_set_text(ti, "%s", szText);

         nv_var_tree = proto_item_add_subtree(ti, ett_nv_var);
         ti = proto_tree_add_item(nv_var_tree, hf_nv_varheader, tvb, offset, ETYPE_88A4_NV_DATA_HEADER_Len, ENC_NA);

         nv_varheader_tree = proto_item_add_subtree(ti, ett_nv_varheader);
         proto_tree_add_item(nv_varheader_tree, hf_nv_id, tvb, offset, (int)sizeof(uint16_t), ENC_LITTLE_ENDIAN);
         offset+=(int)sizeof(uint16_t);

         proto_tree_add_item(nv_varheader_tree, hf_nv_hash, tvb, offset, (int)sizeof(uint16_t), ENC_LITTLE_ENDIAN);
         offset+=(int)sizeof(uint16_t);

         proto_tree_add_item(nv_varheader_tree, hf_nv_length, tvb, offset, (int)sizeof(uint16_t), ENC_LITTLE_ENDIAN);
         offset+=(int)sizeof(uint16_t);

         proto_tree_add_item(nv_varheader_tree, hf_nv_quality, tvb, offset, (int)sizeof(uint16_t), ENC_LITTLE_ENDIAN);
         offset+=(int)sizeof(uint16_t);

         proto_tree_add_item(nv_var_tree, hf_nv_data, tvb, offset, var_length, ENC_NA);
         offset+=var_length;
      }
   }
   return tvb_captured_length(tvb);
}

void proto_register_nv(void)
{
   static hf_register_info hf[] =
      {
#if 0
         { &hf_nv_summary, { "Summary of the Nv Packet", "tc_nv.summary",
                             FT_BYTES, BASE_NONE, NULL, 0x0,
                             NULL, HFILL }
         },
#endif
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

   static int *ett[] =
      {
         &ett_nv,
         &ett_nv_header,
         &ett_nv_var,
         &ett_nv_varheader
      };

   proto_nv = proto_register_protocol("TwinCAT NV", "TC-NV","tc_nv");
   proto_register_field_array(proto_nv,hf,array_length(hf));
   proto_register_subtree_array(ett,array_length(ett));
   nv_handle = register_dissector("tc_nv", dissect_nv, proto_nv);
}

void proto_reg_handoff_nv(void)
{
   dissector_add_uint("ecatf.type", 4, nv_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 3
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
