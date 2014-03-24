/* packet-msnlb.c
 * Routines for MS NLB dissection
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/to_str.h>
#include "packet-smb-common.h"

void proto_register_msnlb(void);
void proto_reg_handoff_msnlb(void);

/* Initialize the protocol and registered fields */
static int proto_msnlb = -1;

static int hf_msnlb_signature = -1;
static int hf_msnlb_version = -1;
static int hf_msnlb_uniquehostid = -1;
static int hf_msnlb_clusterip = -1;
static int hf_msnlb_dedicatedip = -1;
static int hf_msnlb_signature_data = -1;

static int hf_msnlb_myhostid = -1;
static int hf_msnlb_defaulthostid = -1;
static int hf_msnlb_convergencestate = -1;
static int hf_msnlb_numberofportrules = -1;
static int hf_msnlb_uniquehostcode = -1;
static int hf_msnlb_packetshandled = -1;
static int hf_msnlb_teamingcfg = -1;
static int hf_msnlb_teamingcfg_reserved = -1;
static int hf_msnlb_teamingcfg_xorclusterip = -1;
static int hf_msnlb_teamingcfg_numberofparticipants = -1;
static int hf_msnlb_teamingcfg_hashing = -1;
static int hf_msnlb_teamingcfg_master = -1;
static int hf_msnlb_teamingcfg_active = -1;
static int hf_msnlb_reserved = -1;
static int hf_msnlb_portruleconfiguration = -1;
static int hf_msnlb_portruleconfiguration_data = -1;
static int hf_msnlb_currentmap = -1;
static int hf_msnlb_currentmap_data = -1;
static int hf_msnlb_newmap = -1;
static int hf_msnlb_newmap_data = -1;
static int hf_msnlb_idlemap = -1;
static int hf_msnlb_idlemap_data = -1;
static int hf_msnlb_readymap = -1;
static int hf_msnlb_readymap_data = -1;
static int hf_msnlb_loadweights = -1;
static int hf_msnlb_loadweights_data = -1;
static int hf_msnlb_reserved2 = -1;
static int hf_msnlb_reserved2_data = -1;

static int hf_msnlb_extended_hb = -1;
static int hf_msnlb_extended_hb_type = -1;
static int hf_msnlb_length = -1;
static int hf_msnlb_address_family = -1;
static int hf_msnlb_host_name = -1;
static int hf_msnlb_host_ipv4 = -1;
static int hf_msnlb_host_ipv6 = -1;
static int hf_msnlb_host_unknown = -1;
static int hf_msnlb_padding = -1;
static int hf_msnlb_extended_hb_unknown = -1;

static gint ett_msnlb = -1;
static gint ett_msnlb_signature = -1;
static gint ett_msnlb_teamingcfg = -1;
static gint ett_msnlb_portruleconfiguration = -1;
static gint ett_msnlb_currentmap = -1;
static gint ett_msnlb_newmap = -1;
static gint ett_msnlb_idlemap = -1;
static gint ett_msnlb_readymap = -1;
static gint ett_msnlb_loadweights = -1;
static gint ett_msnlb_reserved = -1;
static gint ett_msnlb_extended_hb = -1;

#define NLB_CLUSTER_MEMBERSHIP_HB 0xC0DE01BF
#define NLB_EXTENDED_HB 0xC0DE01C0
#define NLB_RELIABLE_PROTOCOL 0xC0DE01DE

static const value_string nlb_signature_vals[] = {
  { NLB_CLUSTER_MEMBERSHIP_HB, "NLB Cluster Membership HeartBeat" },
  { NLB_EXTENDED_HB, "NLB Extended HeartBeat" },
  { NLB_RELIABLE_PROTOCOL, "NLB Reliable Protocol" },
  { 0, NULL }
};

static const value_string nlb_extended_hb_type_vals[] = {
  { 1, "Host name" },
  { 2, "IP Address" },
  { 0, NULL }
};

static const value_string nlb_address_family_vals[] = {
  { 0x2, "IPv4" },
  { 0x17, "IPv6" },
  { 0, NULL }
};

true_false_string tfs_reverse_normal = { "Reverse", "Normal" };

static void
version_base_custom(gchar *result, guint32 version)
{
  g_snprintf(result, ITEM_LABEL_LENGTH, "%d.%d", (version  >> 8) & 0xFF, (version & 0xFF));
}

static void
dissect_msnlb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_item  *ti;
  proto_tree  *msnlb_tree = NULL, *msnlb_subtree;
  guint16     offset = 0;
  guint32     signature;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "MS NLB");

  col_set_str(pinfo->cinfo, COL_INFO, "MS NLB heartbeat");

  if (tree) {
    ti = proto_tree_add_item(tree, proto_msnlb, tvb, 0, -1, ENC_NA);
    msnlb_tree = proto_item_add_subtree(ti, ett_msnlb);
  }

  proto_tree_add_item(msnlb_tree, hf_msnlb_signature, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  signature = tvb_get_letohl(tvb, offset);
  offset += 4;

  proto_tree_add_item(msnlb_tree, hf_msnlb_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(msnlb_tree, hf_msnlb_uniquehostid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(msnlb_tree, hf_msnlb_clusterip, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(msnlb_tree, hf_msnlb_dedicatedip, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  ti = proto_tree_add_item(msnlb_tree, hf_msnlb_signature_data, tvb, offset, -1, ENC_NA);
  proto_item_append_text(ti, " - %s", val_to_str(signature, nlb_signature_vals, "Unknown (%u)"));
  col_append_fstr(pinfo->cinfo, COL_INFO, " - %s", val_to_str(signature, nlb_signature_vals, "Unknown (%u)"));
  msnlb_subtree = proto_item_add_subtree(ti, ett_msnlb_signature);

  switch(signature){
    case NLB_CLUSTER_MEMBERSHIP_HB:{
      guint32 i;
      proto_tree *teamingcfg_tree, *subtree;

      proto_tree_add_item(msnlb_subtree, hf_msnlb_myhostid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset += 2;

      proto_tree_add_item(msnlb_subtree, hf_msnlb_defaulthostid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset += 2;

      proto_tree_add_item(msnlb_subtree, hf_msnlb_convergencestate, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset += 2;

      proto_tree_add_item(msnlb_subtree, hf_msnlb_numberofportrules, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset += 2;

      proto_tree_add_item(msnlb_subtree, hf_msnlb_uniquehostcode, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      offset += 4;

      proto_tree_add_item(msnlb_subtree, hf_msnlb_packetshandled, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      offset += 4;

      /* Teaming configuration/state code, which is of the form:

         -------------------------------------
         |XXXXXXXX|PPPPPPPP|PPPPPPPP|NNNNNHMA|
         -------------------------------------

         X: Reserved
         P: XOR of the least significant 16 bits of each participant's cluster IP address
         N: Number of participants
         H: Hashing (Reverse=1, Normal=0)
         M: Master (Yes=1, No=0)
         A: Teaming active (Yes=1, No=0)
      */

      ti = proto_tree_add_item(msnlb_subtree, hf_msnlb_teamingcfg, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      teamingcfg_tree = proto_item_add_subtree(ti, ett_msnlb_teamingcfg);
      proto_tree_add_item(teamingcfg_tree, hf_msnlb_teamingcfg_reserved, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(teamingcfg_tree, hf_msnlb_teamingcfg_xorclusterip, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(teamingcfg_tree, hf_msnlb_teamingcfg_numberofparticipants, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(teamingcfg_tree, hf_msnlb_teamingcfg_hashing, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(teamingcfg_tree, hf_msnlb_teamingcfg_master, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      proto_tree_add_item(teamingcfg_tree, hf_msnlb_teamingcfg_active, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      offset += 4;

      proto_tree_add_item(msnlb_subtree, hf_msnlb_reserved, tvb, offset, 4, ENC_NA);
      offset += 4;

      ti = proto_tree_add_item(msnlb_subtree, hf_msnlb_portruleconfiguration, tvb, offset, 4*33, ENC_NA);
      subtree = proto_item_add_subtree(ti, ett_msnlb_portruleconfiguration);
      for(i = 1; i <= 33; i++){
        proto_tree_add_item(subtree, hf_msnlb_portruleconfiguration_data, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
      }

      ti = proto_tree_add_item(msnlb_subtree, hf_msnlb_currentmap, tvb, offset, 8*33, ENC_NA);
      subtree = proto_item_add_subtree(ti, ett_msnlb_currentmap);
      for(i = 1; i <= 33; i++){
        proto_tree_add_item(subtree, hf_msnlb_currentmap_data, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
      }

      ti = proto_tree_add_item(msnlb_subtree, hf_msnlb_newmap, tvb, offset, 8*33, ENC_NA);
      subtree = proto_item_add_subtree(ti, ett_msnlb_newmap);
      for(i = 1; i <= 33; i++){
        proto_tree_add_item(subtree, hf_msnlb_newmap_data, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
      }

      ti = proto_tree_add_item(msnlb_subtree, hf_msnlb_idlemap, tvb, offset, 8*33, ENC_NA);
      subtree = proto_item_add_subtree(ti, ett_msnlb_idlemap);
      for(i = 1; i <= 33; i++){
        proto_tree_add_item(subtree, hf_msnlb_idlemap_data, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
      }

      ti = proto_tree_add_item(msnlb_subtree, hf_msnlb_readymap, tvb, offset, 8*33, ENC_NA);
      subtree = proto_item_add_subtree(ti, ett_msnlb_readymap);
      for(i = 1; i <= 33; i++){
        proto_tree_add_item(subtree, hf_msnlb_readymap_data, tvb, offset, 8, ENC_LITTLE_ENDIAN);
        offset += 8;
      }

      ti = proto_tree_add_item(msnlb_subtree, hf_msnlb_loadweights, tvb, offset, 4*33, ENC_NA);
      subtree = proto_item_add_subtree(ti, ett_msnlb_loadweights);
      for(i = 1; i <= 33; i++){
        proto_tree_add_item(subtree, hf_msnlb_loadweights_data, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
      }

      ti = proto_tree_add_item(msnlb_subtree, hf_msnlb_reserved2, tvb, offset, 4*33, ENC_NA);
      subtree = proto_item_add_subtree(ti, ett_msnlb_reserved);
      for(i = 1; i <= 33; i++){
        proto_tree_add_item(subtree, hf_msnlb_reserved2_data, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;
      }
    }
    break;
    case NLB_EXTENDED_HB:{
      guint8 hb_type;
      proto_tree *hb_tree;
      while (tvb_reported_length_remaining(tvb, offset) > 0) {
        ti = proto_tree_add_item(msnlb_subtree, hf_msnlb_extended_hb, tvb, offset, -1, ENC_NA);
        hb_tree = proto_item_add_subtree(ti, ett_msnlb_extended_hb);

        proto_tree_add_item(hb_tree, hf_msnlb_extended_hb_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        hb_type = tvb_get_guint8(tvb, offset);
        proto_item_append_text(ti, " - %s", val_to_str(hb_type, nlb_extended_hb_type_vals, "Unknown (%u)"));
        offset += 1;

        switch(hb_type){
          case 1:{ /* FQDN */
            char *fqdn = NULL;
            proto_tree_add_item(hb_tree, hf_msnlb_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(hb_tree, hf_msnlb_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(hb_tree, hf_msnlb_reserved, tvb, offset, 4, ENC_NA);
            offset += 4;
            offset = display_unicode_string(tvb, hb_tree, offset, hf_msnlb_host_name, &fqdn);
            offset += 6;
            proto_item_append_text(ti, ": %s", fqdn);
            }
          break;
          case 2:{ /* IP */
            guint16 address_family;
            proto_tree_add_item(hb_tree, hf_msnlb_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset += 1;
            proto_tree_add_item(hb_tree, hf_msnlb_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(hb_tree, hf_msnlb_reserved, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(hb_tree, hf_msnlb_address_family, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            address_family = tvb_get_letohs(tvb, offset);
            offset += 2;
            switch(address_family){
              case 0x2: /* IPv4 */
                proto_tree_add_item(hb_tree, hf_msnlb_host_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_item_append_text(ti, ": %s", tvb_ip_to_str(tvb, offset));
                offset += 4;
                break;
              case 0x17: /* IPv6 */
                proto_tree_add_item(hb_tree, hf_msnlb_host_ipv6, tvb, offset, 16, ENC_NA);
                proto_item_append_text(ti, ": %s", tvb_ip6_to_str(tvb, offset));
                offset += 16;
                break;
              default: /* Unknown */
                proto_tree_add_item(hb_tree, hf_msnlb_host_unknown, tvb, offset, -1, ENC_NA);
                offset += tvb_reported_length_remaining(tvb, offset);
              break;
            }
            proto_tree_add_item(hb_tree, hf_msnlb_padding, tvb, offset, -1, ENC_NA);
            offset += tvb_reported_length_remaining(tvb, offset);
          }
          break;
          default: /* default ?! */
            proto_tree_add_item(hb_tree, hf_msnlb_extended_hb_unknown, tvb, offset, -1, ENC_NA);
            offset += tvb_reported_length_remaining(tvb, offset);
          break;
        }
      }


    }
    break;

    default:
    break;
  }

}

void
proto_register_msnlb(void)
{
  static hf_register_info hf[] = {
    { &hf_msnlb_signature,
      { "Signature", "msnlb.signature",
        FT_UINT32, BASE_HEX,
        VALS(nlb_signature_vals), 0,
        NULL, HFILL }
    },
    { &hf_msnlb_version,
      { "Version", "msnlb.version",
        FT_UINT32, BASE_CUSTOM,
        version_base_custom, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_uniquehostid,
      { "Unique Host ID", "msnlb.unique_host_id",
        FT_UINT32, BASE_DEC,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_clusterip,
      { "Cluster IP", "msnlb.cluster_ip",
        FT_IPv4, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_dedicatedip,
      { "Host IP", "msnlb.host_ip",
        FT_IPv4, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_signature_data,
      { "Signature Data", "msnlb.signature_data",
        FT_NONE, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_myhostid,
      { "My Host id", "msnlb.my_host_ip",
        FT_UINT16, BASE_DEC,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_defaulthostid,
      { "Default Host id", "msnlb.default_host_ip",
        FT_UINT16, BASE_DEC,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_convergencestate,
      { "Convergence State", "msnlb.convergence_state",
        FT_UINT16, BASE_DEC,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_numberofportrules,
      { "Number of Port Rules", "msnlb.number_of_port_rules",
        FT_UINT16, BASE_DEC,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_uniquehostcode,
      { "Unique Host Code", "msnlb.unique_host_code",
        FT_UINT32, BASE_DEC,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_packetshandled,
      { "Packets Handled", "msnlb.packets_handled",
        FT_UINT32, BASE_DEC,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_teamingcfg,
      { "Teaming Configuration", "msnlb.teamincfg",
        FT_UINT32, BASE_HEX,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_teamingcfg_reserved,
      { "Reserved", "msnlb.teamincfg.reserved",
        FT_UINT32, BASE_HEX,
        NULL, 0xFF000000,
        "Must be zero", HFILL }
    },
    { &hf_msnlb_teamingcfg_xorclusterip,
      { "XOR of the least significant 16 bits of each participant's cluster IP address", "msnlb.teamingcfg.xorclusterip",
        FT_UINT32, BASE_HEX,
        NULL, 0x00FFFF00,
        NULL, HFILL }
    },
    { &hf_msnlb_teamingcfg_numberofparticipants,
      { "Number of Participants", "msnlb.teamingcfg.number_of_participants",
        FT_UINT32, BASE_HEX,
        NULL, 0x000000F8,
        NULL, HFILL }
    },
    { &hf_msnlb_teamingcfg_hashing,
      { "Hashing", "msnlb.teamingcfg.hashing",
        FT_BOOLEAN, 32,
        TFS(&tfs_reverse_normal), 0x00000004,
        NULL, HFILL }
    },
    { &hf_msnlb_teamingcfg_master,
      { "Master", "msnlb.teamingcfg.master",
        FT_BOOLEAN, 32,
        NULL, 0x00000002,
        NULL, HFILL }
    },
    { &hf_msnlb_teamingcfg_active,
      { "Active", "msnlb.teamingcfg.active",
        FT_BOOLEAN, 32,
        NULL, 0x00000001,
        NULL, HFILL }
    },
    { &hf_msnlb_reserved,
      { "Reserved", "msnlb.reserved",
        FT_BYTES, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_portruleconfiguration,
      { "Port Rule Configuration", "msnlb.portruleconfiguration",
        FT_NONE, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_portruleconfiguration_data,
      { "Port Rule Configuration Data", "msnlb.portruleconfiguration.data",
        FT_UINT32, BASE_DEC_HEX,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_currentmap,
      { "Current Map", "msnlb.currentmap",
        FT_NONE, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_currentmap_data,
      { "Current Map Data", "msnlb.currentmap.data",
        FT_UINT64, BASE_DEC_HEX,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_newmap,
      { "New Map", "msnlb.newmap",
        FT_NONE, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_newmap_data,
      { "New Map Data", "msnlb.newmap.data",
        FT_UINT64, BASE_DEC_HEX,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_idlemap,
      { "Idle Map", "msnlb.idlemap",
        FT_NONE, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_idlemap_data,
      { "Idle Map Data", "msnlb.idlemap.data",
        FT_UINT64, BASE_DEC_HEX,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_readymap,
      { "Ready Map", "msnlb.readymap",
        FT_NONE, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_readymap_data,
      { "Ready Map Data", "msnlb.readymap.data",
        FT_UINT64, BASE_DEC_HEX,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_loadweights,
      { "Load Weights", "msnlb.loadweights",
        FT_NONE, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_loadweights_data,
      { "Load Weights Data", "msnlb.loadweights.data",
        FT_UINT32, BASE_DEC_HEX,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_reserved2,
      { "Reserved", "msnlb.reserved",
        FT_NONE, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_reserved2_data,
      { "Reserved Data", "msnlb.reserved.data",
        FT_UINT32, BASE_DEC_HEX,
        NULL, 0,
        NULL, HFILL }
    },

    { &hf_msnlb_extended_hb,
      { "Extended HB", "msnlb.extended_hb",
        FT_NONE, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },

    { &hf_msnlb_extended_hb_type,
      { "Type", "msnlb.extended_hb.type",
        FT_UINT8, BASE_DEC,
        VALS(nlb_extended_hb_type_vals), 0,
        NULL, HFILL }
    },
    { &hf_msnlb_length,
      { "Length", "msnlb.length",
        FT_UINT8, BASE_DEC,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_address_family,
      { "Address Family", "msnlb.address_family",
        FT_UINT8, BASE_HEX_DEC,
        VALS(nlb_address_family_vals), 0,
        NULL, HFILL }
    },
    { &hf_msnlb_host_name,
      { "Host name", "msnlb.host_name",
        FT_STRING, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_host_ipv4,
      { "Host IPv4", "msnlb.host_ipv4",
        FT_IPv4, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_host_ipv6,
      { "Host IPv6", "msnlb.host_ipv6",
        FT_IPv6, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_host_unknown,
      { "Host Unknown", "msnlb.host_unknown",
        FT_BYTES, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_padding,
      { "Padding", "msnlb.padding",
        FT_BYTES, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    },
    { &hf_msnlb_extended_hb_unknown,
      { "Unknown HB Data", "msnlb.extended_hb.unknown",
        FT_BYTES, BASE_NONE,
        NULL, 0,
        NULL, HFILL }
    }
  };

  static gint *ett[] = {
    &ett_msnlb,
    &ett_msnlb_signature,
    &ett_msnlb_teamingcfg,
    &ett_msnlb_portruleconfiguration,
    &ett_msnlb_currentmap,
    &ett_msnlb_newmap,
    &ett_msnlb_idlemap,
    &ett_msnlb_readymap,
    &ett_msnlb_loadweights,
    &ett_msnlb_reserved,
    &ett_msnlb_extended_hb
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
  dissector_add_uint("ethertype", ETHERTYPE_MS_NLB_HEARTBEAT, msnlb_handle);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
