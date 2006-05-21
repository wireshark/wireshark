/* packet-msnlb.c
 * Routines for MS NLB dissection
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
#include "config.h"
#endif

#include <gmodule.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/etypes.h>
#include "packet-smb-common.h"

/* Initialize the protocol and registered fields */
static int proto_msnlb = -1;

static int hf_msnlb_unknown = -1;
static int hf_msnlb_hpn = -1;
static int hf_msnlb_cls_virt_ip = -1;
static int hf_msnlb_host_ip = -1;
static int hf_msnlb_count = -1;
static int hf_msnlb_host_name = -1;

/* Initialize the subtree pointers */
static gint ett_msnlb = -1;

/* Code to actually dissect the packets */
static void
dissect_msnlb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item  *ti;
  proto_tree  *msnlb_tree;
  guint16     offset = 0;

  guint8 type = 0; /* Blatent assumption of name and size */

  if (check_col(pinfo->cinfo, COL_PROTOCOL))
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MS NLB");

  if (check_col(pinfo->cinfo, COL_INFO)) {
    col_clear(pinfo->cinfo, COL_INFO);
    col_append_fstr(pinfo->cinfo, COL_INFO, "MS NLB heartbeat");
  }

  if (tree) {
    ti = proto_tree_add_item(tree, proto_msnlb, tvb, 0, -1, FALSE);
    msnlb_tree = proto_item_add_subtree(ti, ett_msnlb);

    type = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
    offset += 4;

    proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
    offset += 4;

    proto_tree_add_item(msnlb_tree, hf_msnlb_hpn, tvb, offset, 4, TRUE);
    offset += 4;

    proto_tree_add_item(msnlb_tree, hf_msnlb_cls_virt_ip, tvb, offset, 4, FALSE);
    offset += 4;

    proto_tree_add_item(msnlb_tree, hf_msnlb_host_ip, tvb, offset, 4, FALSE);
    offset += 4;

    proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
    offset += 4;

    proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
    offset += 4;

    switch (type) {
      case 0xc0:
        offset = display_unicode_string(tvb, msnlb_tree, offset, hf_msnlb_host_name, NULL);
        break;

      case 0xbf:
        proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
        offset += 4;

        proto_tree_add_item(msnlb_tree, hf_msnlb_count, tvb, offset, 4, TRUE);
        offset += 4;

        proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
        offset += 4;

        proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
        offset += 4;

        proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
        offset += 4;

        proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
        offset += 4;

        proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
        offset += 4;

        proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
        offset += 4;

        proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
        offset += 4;

        proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, 4, FALSE);
        offset += 4;

      default:
        proto_tree_add_item(msnlb_tree, hf_msnlb_unknown, tvb, offset, tvb_length_remaining(tvb, offset), FALSE);
        offset += 4;
    }
  }
}

void
proto_register_msnlb(void)
{
  static hf_register_info hf[] = {
    { &hf_msnlb_unknown,
      { "Unknown", "msnlb.unknown",
        FT_BYTES, BASE_HEX,
        NULL, 0,
        "", HFILL }
    },
    { &hf_msnlb_hpn,
      { "Host Priority Number", "msnlb.hpn",
        FT_UINT32, BASE_DEC,
        NULL, 0,
        "Host Priority Number", HFILL }
    },
    { &hf_msnlb_host_ip,
      { "Host IP", "msnlb.host_ip",
        FT_IPv4, BASE_HEX,
        NULL, 0,
        "Host IP address", HFILL }
    },
    { &hf_msnlb_cls_virt_ip,
      { "Cluster Virtual IP", "msnlb.cluster_virtual_ip",
        FT_IPv4, BASE_HEX,
        NULL, 0,
        "Cluster Virtual IP address", HFILL }
    },
    { &hf_msnlb_count,
      { "Count", "msnlb.count",
        FT_UINT32, BASE_HEX,
        NULL, 0,
        "Count", HFILL }
    },
    { &hf_msnlb_host_name,
      { "Host name", "msnlb.host_name",
        FT_STRING, BASE_NONE,
        NULL, 0,
        "Host name", HFILL }
    }
  };

  static gint *ett[] = {
    &ett_msnlb
  };

  proto_msnlb = proto_register_protocol("MS Network Load Balancing", "MS NLB", "msnlb");
  proto_register_field_array(proto_msnlb, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_msnlb(void)
{
  dissector_handle_t msnlb_handle;

  msnlb_handle = create_dissector_handle(dissect_msnlb, proto_msnlb);
  dissector_add("ethertype", ETHERTYPE_MS_NLB_HEARTBEAT, msnlb_handle);
}
