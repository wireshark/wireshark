/* packet-sercosiii_1v1_at.c
 * Routines for SERCOS III dissection
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>

#include "packet-sercosiii.h"

static gint ett_siii_at = -1;
static gint ett_siii_at_svc = -1;
static gint ett_siii_at_devstats = -1;

static gint ett_siii_at_svc_channel[MAX_SERCOS_DEVICES];
static gint ett_siii_at_dev_status[MAX_SERCOS_DEVICES];

static void dissect_siii_at_cp0(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  guint16 seqcnt; /* sequence counter */
  guint16 tfield; /* topology field for sercos addresses */
  guint16 i;
  char devices[]="Recognized Devices"; /* fixme: it would be nice to have this as subtree */
  static char outbuf[200];

  proto_tree_add_text(tree, tvb, 0, 1024, "%s", devices);

  /* check sequence count field */
  seqcnt = tvb_get_letohs(tvb, 0);
  g_snprintf(outbuf, sizeof(outbuf), "Number of Devices: %u", (0x1FF & seqcnt)-1);
  proto_tree_add_text(tree, tvb, 0, 2, "%s", outbuf);

  /* check SERCOS address of each topology field */
  for(i=1;i < MAX_SERCOS_DEVICES; ++i)
  {
    tfield = tvb_get_letohs(tvb, i*2);

    if(tfield == 0)
    {
      g_snprintf(outbuf, sizeof(outbuf), "Device Address %u: No SERCOS Address", i);
    }
    else if(tfield == 0xFFFF)
    {
      g_snprintf(outbuf, sizeof(outbuf), "Device Address %u: No Device", i);
    }
    else
    {
      g_snprintf(outbuf, sizeof(outbuf), "Device Address %u: %u", i, tfield);
    }
    proto_tree_add_text(tree, tvb, i*2, 2, "%s", outbuf);
  }
}

static void dissect_siii_at_cp1_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint telno)
{
  guint devstart = telno * 128; /* AT0: slaves 0-127; AT1: slaves 128-255; ... */
  tvbuff_t* tvb_n;

  guint idx;

  proto_item* ti; /* temporary item */
  proto_tree* subtree;
  proto_tree* subtree_svc;
  proto_tree* subtree_devstat;

  ti = proto_tree_add_text(tree, tvb, 0, 128 * 6, "Service Channel");
  subtree_svc = proto_item_add_subtree(ti, ett_siii_at_svc);

  ti = proto_tree_add_text(tree, tvb, 128 * 6, 512, "Device Status");
  subtree_devstat = proto_item_add_subtree(ti, ett_siii_at_devstats);

  for(idx = 0; idx < 128; ++idx) /* each AT of CP1/2 has data of 128 different slaves */
  {
    tvb_n = tvb_new_subset(tvb, 6 * idx, 6, 6); /* subset for service channel data */

    ti = proto_tree_add_text(subtree_svc, tvb_n, 0, 6, "Device %u", idx + devstart);
    subtree = proto_item_add_subtree(ti, ett_siii_at_svc_channel[idx]);
    dissect_siii_at_svc(tvb_n, pinfo, subtree, idx + devstart);

    tvb_n = tvb_new_subset(tvb, 128 * 6 + 4 * idx, 2, 2); /* subset for device status information */

    ti = proto_tree_add_text(subtree_devstat, tvb_n, 0, 2, "Device %u", idx + devstart);
    subtree = proto_item_add_subtree(ti, ett_siii_at_dev_status[idx]);
    dissect_siii_at_devstat(tvb_n, pinfo, subtree);
  }
}

static void dissect_siii_at_cp3_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint telno)
{

  if(0 == telno) /* dissect hotplug field in AT0 only */
    dissect_siii_at_hp(tvb, pinfo, tree);

  /* offsets of service channel, device status and connections are unknown
   * this data could be extracted from svc communication during CP2
   */
  proto_tree_add_text(tree, tvb, 0, 0, "Service Channels");  
  proto_tree_add_text(tree, tvb, 0, 0, "Device Status");
}


void dissect_siii_at(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item*  ti; /* temporary item */
  proto_tree* subtree;
  tvbuff_t* tvb_n;

  guint8 phase;
  guint telno;

  phase = (tvb_get_guint8(tvb, 1)&0x8F); /* read communication phase out of SERCOS III header*/
  telno = (tvb_get_guint8(tvb, 0) & 0xF); /* read number of AT out of SERCOS III header */

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIII AT");

  if(phase & 0x80) /* communication phase switching in progress */
  {
    col_append_fstr(pinfo->cinfo, COL_INFO, " Phase=CP?s -> CP%u",
          (phase&0x0f));
  }
  else /* communication as usual */
  {
     col_append_fstr(pinfo->cinfo, COL_INFO, " Phase=CP%u",
          (phase&0x0f));
  }

  ti = proto_tree_add_text(tree, tvb, 0, -1, "AT%u", telno);
  subtree = proto_item_add_subtree(ti, ett_siii_at);

  dissect_siii_mst(tvb, pinfo, subtree); /* dissect SERCOS III header */

    switch(phase) /* call the AT dissector depending on the current communication phase */
    {
    case COMMUNICATION_PHASE_0: /* CP0 */
      tvb_n = tvb_new_subset(tvb, 6, 1024, 1024);
      dissect_siii_at_cp0(tvb_n, pinfo, subtree);
    break;

    case COMMUNICATION_PHASE_1: /* CP1 */
    case COMMUNICATION_PHASE_2: /* CP2 */
      tvb_n = tvb_new_subset(tvb, 6, 1280, 1280);
      dissect_siii_at_cp1_2(tvb_n, pinfo, subtree, telno);
    break;

    case COMMUNICATION_PHASE_3: /* CP3 */
    case COMMUNICATION_PHASE_4: /* CP4 */
      tvb_n = tvb_new_subset_remaining(tvb, 6);
      dissect_siii_at_cp3_4(tvb_n, pinfo, subtree, telno);
    break;

    default:
      proto_tree_add_text(tree, tvb, 6, -1, "CP is unknown");
    break;
    }
}

void dissect_siii_at_init(gint proto_siii _U_)
{
  gint idx;

  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_siii_at,
    &ett_siii_at_svc,
    &ett_siii_at_devstats
  };

  gint* etts[MAX_SERCOS_DEVICES];

  for(idx = 0; idx < MAX_SERCOS_DEVICES; ++idx)
  {
    ett_siii_at_svc_channel[idx] = -1;
    etts[idx] = &ett_siii_at_svc_channel[idx];
  }
  proto_register_subtree_array(etts, array_length(etts));

  for(idx = 0; idx < MAX_SERCOS_DEVICES; ++idx)
  {
    ett_siii_at_dev_status[idx] = -1;
    etts[idx] = &ett_siii_at_dev_status[idx];
  }
  proto_register_subtree_array(etts, array_length(etts));

  /* Required function calls to register the header fields and subtrees used */
  proto_register_subtree_array(ett, array_length(ett));
}
