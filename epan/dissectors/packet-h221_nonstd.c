/* packet-nonstd.c
 * Routines for H.221 nonstandard parameters disassembly
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
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/dissectors/packet-per.h>

/* Define the nonstd proto */
static int proto_nonstd = -1;

/*
 * Define the trees for nonstd
 * We need one for nonstd itself and one for the nonstd paramters
 */
static int ett_nonstd = -1;

static void
dissect_ms_nonstd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;
    gint tvb_len;
    guint16 codec_value, codec_extra;
    char codec_string[200];

	it=proto_tree_add_protocol_format(tree, proto_nonstd, tvb, 0, tvb_length(tvb), "Microsoft NonStd");
	tr=proto_item_add_subtree(it, ett_nonstd);


      tvb_len = tvb_length(tvb);

      if(tvb_len >= 23)
      {

        codec_value = tvb_get_ntohs(tvb,offset+20);
        codec_extra = tvb_get_ntohs(tvb,offset+22);

        if(codec_extra == 0x0100)
        {

           if(codec_value == 0x0111)
           {
              strcpy(codec_string,"L&H CELP 4.8k");
           }
           else if(codec_value == 0x0200)
           {
              strcpy(codec_string,"MS-ADPCM");
           } 
           else if(codec_value == 0x0211)
           {
              strcpy(codec_string,"L&H CELP 8k");
           }
           else if(codec_value == 0x0311)
           {
              strcpy(codec_string,"L&H CELP 12k");
           }
           else if(codec_value == 0x0411)
           {
              strcpy(codec_string,"L&H CELP 16k");
           }
           else if(codec_value == 0x1100)
           {
              strcpy(codec_string,"IMA-ADPCM");
           }
           else if(codec_value == 0x3100)
           {
              strcpy(codec_string,"MS-GSM");
           }
           else if(codec_value == 0xFEFF)
           {
              strcpy(codec_string,"E-AMR");
           }
           else
           {
              strcpy(codec_string,"Unknown");
           }


           proto_tree_add_text(tree, tvb, offset+20,2, "Microsoft NetMeeting Codec=0x%04X %s",codec_value,codec_string);

        }
        else
        {

           proto_tree_add_text(tree, tvb, offset,-1, "Microsoft NetMeeting Non Standard");

        }

      }
            

}
/* Register all the bits needed with the filtering engine */

void
proto_register_nonstd(void)
{
  static gint *ett[] = {
    &ett_nonstd,
		};


  proto_nonstd = proto_register_protocol("H221NonStandard","h221nonstd", "h221nonstd");

  proto_register_subtree_array(ett, array_length(ett));
}

/* The registration hand-off routine */
void
proto_reg_handoff_nonstd(void)
{
  static dissector_handle_t nonstd_handle;
  static dissector_handle_t ms_nonstd_handle;


  ms_nonstd_handle = create_dissector_handle(dissect_ms_nonstd, proto_nonstd);


  dissector_add("h245.nsp.h221",0xb500534c, ms_nonstd_handle);
  dissector_add("h225.nsp.h221",0xb500534c, ms_nonstd_handle);

}
