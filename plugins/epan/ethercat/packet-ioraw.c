/* packet-ioraw.c
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

#include "packet-ioraw.h"

void proto_register_ioraw(void);
void proto_reg_handoff_ioraw(void);

/* Define the ioraw proto */
int proto_ioraw;

static int ett_ioraw;

static dissector_handle_t ioraw_handle;

/* static int hf_ioraw_summary; */
static int hf_ioraw_header;
static int hf_ioraw_data;

/*ioraw*/
static void IoRawSummaryFormater( char *szText, int nMax)
{
   snprintf ( szText, nMax, "Raw IO Data" );
}

static int dissect_ioraw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
   proto_item *ti;
   proto_tree *ioraw_tree;
   int offset = 0;
   char szText[200];
   int nMax = sizeof(szText)-1;

   unsigned ioraw_length = tvb_reported_length(tvb);

   col_set_str(pinfo->cinfo, COL_PROTOCOL, "IO-RAW");

   IoRawSummaryFormater(szText, nMax);
   col_add_str(pinfo->cinfo, COL_INFO, szText);

   if (tree)
   {
      ti = proto_tree_add_item(tree, proto_ioraw, tvb, 0, -1, ENC_NA);
      ioraw_tree = proto_item_add_subtree(ti, ett_ioraw);

      proto_item_append_text(ti,": %s",szText);
      proto_tree_add_item(ioraw_tree, hf_ioraw_header, tvb, offset, IoRawParserHDR_Len, ENC_NA);
      offset+=IoRawParserHDR_Len;

      proto_tree_add_item(ioraw_tree, hf_ioraw_data, tvb, offset, ioraw_length - offset, ENC_NA);
   }
   return tvb_captured_length(tvb);
}

void proto_register_ioraw(void)
{
   static hf_register_info hf[] =
      {
#if 0
         { &hf_ioraw_summary,
           { "Summary of the IoRaw Packet", "ioraw.summary",
             FT_STRING, BASE_NONE, NULL, 0x0,
             NULL, HFILL }
         },
#endif
         { &hf_ioraw_header, { "Header", "ioraw.header",
                               FT_NONE, BASE_NONE, NULL, 0x0,
                               NULL, HFILL }
         },
         { &hf_ioraw_data, { "VarData", "ioraw.data",
                             FT_NONE, BASE_NONE, NULL, 0x0,
                             NULL, HFILL }
         }
      };

   static int *ett[] =
      {
         &ett_ioraw
      };

   proto_ioraw = proto_register_protocol("TwinCAT IO-RAW",
                                         "IO-RAW","ioraw");
   proto_register_field_array(proto_ioraw,hf,array_length(hf));
   proto_register_subtree_array(ett,array_length(ett));
   ioraw_handle = register_dissector("ioraw", dissect_ioraw, proto_ioraw);
}

void proto_reg_handoff_ioraw(void)
{
   dissector_add_uint("ecatf.type", 3, ioraw_handle);
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
 * vi: set shiftwidth=3 tabstop=8 expandtab:
 * :indentSize=3:tabSize=8:noTabs=true:
 */
