/* packet-sercosiii_1v1_mdt.c
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

static gint hf_siii_mdt_version = -1;
static gint hf_siii_mdt_version_initprocvers = -1;
static gint hf_siii_mdt_version_num_mdt_at_cp1_2 = -1;
static gint hf_siii_mdt_version_revision = -1;

static const value_string siii_mdt_version_num_mdtat_cp1_2_text[]=
{
  {0x00, "2 MDTs/ATs in CP1/2"},
  {0x01, "4 MDTs/ATs in CP1/2"},
  {0, NULL}
};

static const value_string siii_mdt_version_initprocvers_text[]=
{
  {0x00, "No remote address allocation"},
  {0x01, "Remote address allocation"},
  {0, NULL}
};

static gint ett_siii_mdt = -1;
static gint ett_siii_mdt_svc = -1;
static gint ett_siii_mdt_devctrls = -1;
static gint ett_siii_mdt_version = -1;
static gint ett_siii_mdt_svc_channel[MAX_SERCOS_DEVICES];
static gint ett_siii_mdt_dev_control[MAX_SERCOS_DEVICES];

static void dissect_siii_mdt_cp0(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_item* ti;
  proto_tree* subtree;
  ti = proto_tree_add_item(tree, hf_siii_mdt_version, tvb, 0, 4, TRUE);
  subtree = proto_item_add_subtree(ti, ett_siii_mdt_version);

  proto_tree_add_item(subtree, hf_siii_mdt_version_num_mdt_at_cp1_2, tvb, 0, 4, TRUE);
  proto_tree_add_item(subtree, hf_siii_mdt_version_initprocvers, tvb, 0, 4, TRUE);
  proto_tree_add_item(subtree, hf_siii_mdt_version_revision, tvb, 0, 4, TRUE);

}

static void dissect_siii_mdt_cp1_2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint telno)
{
  guint devstart = telno * 128; /* MDT0: slaves 0-127; MDT1: slaves 128-255; ... */
  tvbuff_t* tvb_n;

  guint idx;

  proto_item* ti;
  proto_tree* subtree;
  proto_tree* subtree_svc;
  proto_tree* subtree_devctrl;

  ti = proto_tree_add_text(tree, tvb, 0, 128 * 6, "Service Channels");
  subtree_svc = proto_item_add_subtree(ti, ett_siii_mdt_svc);

  ti = proto_tree_add_text(tree, tvb, 128 * 6, 512, "Device Control");
  subtree_devctrl = proto_item_add_subtree(ti, ett_siii_mdt_svc);

  for(idx = 0; idx < 128; ++idx) /* each MDT of CP1/2 has data for 128 different slaves */
  {
    tvb_n = tvb_new_subset(tvb, 6 * idx, 6, 6); /* subset for service channel data */

    ti = proto_tree_add_text(subtree_svc, tvb_n, 0, 6, "Device %u", idx + devstart);
    subtree = proto_item_add_subtree(ti, ett_siii_mdt_svc_channel[idx]);
    dissect_siii_mdt_svc(tvb_n, pinfo, subtree, idx + devstart);

    tvb_n = tvb_new_subset(tvb, 128 * 6 + 4 * idx, 2, 2); /* subset for device control information */

    ti = proto_tree_add_text(subtree_devctrl, tvb_n, 0, 2, "Device %u", idx + devstart);
    subtree = proto_item_add_subtree(ti, ett_siii_mdt_dev_control[idx]);

    dissect_siii_mdt_devctrl(tvb_n, pinfo, subtree);
  }
}

static void dissect_siii_mdt_cp3_4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint telno)
{
  guint devstart _U_ = telno * 128;

  if(0 == telno) /* dissect hotplug field in MDT0 only */
    dissect_siii_mdt_hp(tvb, pinfo, tree);

  /* offsets of service channel, device status and connections are unknown
   * this data could be extracted from svc communication during CP2
   */
  proto_tree_add_text(tree, tvb, 0, 0, "Service Channels");
  
  proto_tree_add_text(tree, tvb, 0, 0, "Device Controls");
}


void dissect_siii_mdt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item* ti;
  proto_tree* subtree;
  tvbuff_t* tvb_n;

  guint t_phase;
  guint telno;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SIII MDT");

  t_phase = (tvb_get_guint8(tvb, 1)&0x8F); /* read communication phase out of SERCOS III header */
  telno = (tvb_get_guint8(tvb, 0) & 0xF); /* read number of MDT out of SERCOS III header */

  if(t_phase & 0x80) /* communication phase switching in progress */
  {
    col_append_fstr(pinfo->cinfo, COL_INFO, " Phase=CP?s -> CP%u",
          (t_phase&0x0f));
  }
  else /* communication as usual */
  {
    col_append_fstr(pinfo->cinfo, COL_INFO, " Phase=CP%u",
          (t_phase&0x0f));
  }

  ti = proto_tree_add_text(tree, tvb, 0, -1, "MDT%u", telno);
  subtree = proto_item_add_subtree(ti, ett_siii_mdt);

  dissect_siii_mst(tvb, pinfo, subtree); /* dissect SERCOS III header */

  switch(t_phase) /* call the MDT dissector depending on the current communication phase */
  {
  case COMMUNICATION_PHASE_0: /* CP0 */
    tvb_n = tvb_new_subset(tvb, 6, 40, 40);
    dissect_siii_mdt_cp0(tvb_n, pinfo, subtree);
  break;

  case COMMUNICATION_PHASE_1: /* CP1 */
  case COMMUNICATION_PHASE_2: /* CP2 */
    tvb_n = tvb_new_subset(tvb, 6, 1280, 1280);
    dissect_siii_mdt_cp1_2(tvb_n, pinfo, subtree, telno);
  break;

  case COMMUNICATION_PHASE_3: /* CP3 */
  case COMMUNICATION_PHASE_4: /* CP4 */
    tvb_n = tvb_new_subset_remaining(tvb, 6);
    dissect_siii_mdt_cp3_4(tvb_n, pinfo, subtree, telno);
  break;

  default:
    proto_tree_add_text(tree, tvb, 6, -1, "CP is unknown");
  }
}

void dissect_siii_mdt_init(gint proto_siii)
{
  gint idx;

  /* Setup list of header fields  See Section 1.6.1 for details*/
  static hf_register_info hf_siii_header[] = {
    { &hf_siii_mdt_version,
      { "Communication Version", "siii.mdt.version",
      FT_UINT32, BASE_HEX, NULL, 0,
      NULL, HFILL }
    },
    { &hf_siii_mdt_version_revision,
      { "Revision Number", "siii.mdt.version.revision",
      FT_UINT32, BASE_HEX, NULL, 0x7F,
      NULL, HFILL }
    },
    { &hf_siii_mdt_version_num_mdt_at_cp1_2,
      { "Number of MDTs and ATS in CP1 and CP2", "siii.mdt.version.num_mdt_at_cp1_2",
      FT_UINT32, BASE_HEX, VALS(siii_mdt_version_num_mdtat_cp1_2_text), 0x30000,
      NULL, HFILL }
    },
    { &hf_siii_mdt_version_initprocvers,
      { "Initialization Procedure Version Number", "siii.mdt.version.initprocvers",
      FT_UINT32, BASE_HEX, VALS(siii_mdt_version_initprocvers_text), 0xFF00,
      NULL, HFILL }
    }
  };
  /* Setup protocol subtree array */
  static gint *ett[] = {
    &ett_siii_mdt,
    &ett_siii_mdt_version,
    &ett_siii_mdt_svc,
    &ett_siii_mdt_devctrls
  };

  gint* etts[MAX_SERCOS_DEVICES];

  for(idx = 0; idx < MAX_SERCOS_DEVICES; ++idx)
  {
    ett_siii_mdt_svc_channel[idx] = -1;
    etts[idx] = &ett_siii_mdt_svc_channel[idx];
  }
  proto_register_subtree_array(etts, array_length(etts));

  for(idx = 0; idx < MAX_SERCOS_DEVICES; ++idx)
  {
    ett_siii_mdt_dev_control[idx] = -1;
    etts[idx] = &ett_siii_mdt_dev_control[idx];
  }
  proto_register_subtree_array(etts, array_length(etts));

  proto_register_field_array(proto_siii, hf_siii_header, array_length(hf_siii_header));
  proto_register_subtree_array(ett, array_length(ett));
}
