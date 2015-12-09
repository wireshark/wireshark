/* packet-cpha.c
 * Routines for the Check Point High-Availability Protocol (CPHAP)
 * Copyright 2002, Yaniv Kaul <mykaul -at- gmail.com>
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

#include <epan/packet.h>

void proto_register_cpha(void);
void proto_reg_handoff_cpha(void);

static int proto_cphap = -1;

static int hf_magic_number = -1;
static int hf_cpha_protocol_ver = -1;
static int hf_cluster_number = -1;
static int hf_opcode = -1;
static int hf_payload = -1;
static int hf_src_if_num = -1;
static int hf_random_id = -1;
static int hf_src_machine_id = -1;
static int hf_dst_machine_id = -1;
static int hf_policy_id = -1;
static int hf_filler = -1;
static int hf_unknown_data = -1;
static int hf_id_num = -1;
static int hf_report_code = -1;
static int hf_ha_mode = -1;
static int hf_ha_time_unit = -1;
static int hf_machine_states = -1;
static int hf_state_node = -1;
static int hf_interface_states = -1;
static int hf_num_reported_ifs = -1;
static int hf_ethernet_add = -1;
static int hf_is_if_trusted = -1;
static int hf_ip = -1;
static int hf_slot_num = -1;
static int hf_machine_num = -1;
static int hf_seed = -1;
static int hf_hash_len = -1;
static int hf_status = -1;
static int hf_in_up_num = -1;
static int hf_in_assumed_up_num = -1;
static int hf_out_up_num = -1;
static int hf_out_assumed_up_num = -1;
static int hf_cluster_last_packet = -1;
static int hf_ifn = -1;

static gint ett_cphap = -1;

#define UDP_PORT_CPHA        8116
#define CPHA_MAGIC 0x1A90

#if 0
static const value_string opcode_type_short_vals[] = {
  { 0, "Unknown" },
  { 1, "FWHA_MY_STATE" },
  { 2, "FWHA_QUERY_STATE" },
  { 3, "FWHA_IF_PROBE_REQ" },
  { 4, "FWHA_IF_PROBE_REPLY" },
  { 5, "FWHA_IFCONF_REQ" },
  { 6, "FWHA_IFCONF_REPLY" },
  { 7, "FWHA_LB_CONF" },
  { 8, "FWHA_LB_CONFIRM" },
  { 9, "FWHA_POLICY_CHANGE" },
  { 10, "FWHAP_SYNC" },
  { 0, NULL }
};
#endif

static const value_string opcode_type_vals[] = {
  { 0, "Unknown OpCode" },
  { 1, "FWHA_MY_STATE - Report source machine's state" },
  { 2, "FWHA_QUERY_STATE - Query other machine's state" },
  { 3, "FWHA_IF_PROBE_REQ - Interface active check request" },
  { 4, "FWHA_IF_PROBE_REPLY - Interface active check reply" },
  { 5, "FWHA_IFCONF_REQ - Interface configuration request" },
  { 6, "FWHA_IFCONF_REPLY - Interface configuration reply" },
  { 7, "FWHA_LB_CONF - LB configuration report request" },
  { 8, "FWHA_LB_CONFIRM - LB configuration report reply" },
  { 9, "FWHA_POLICY_CHANGE - Policy ID change request/notification" },
  { 10, "FWHAP_SYNC - New Sync packet" },
  { 0, NULL }
};

static const value_string state_vals[] = {
  { 0, "Down/Dead" },
  { 1, "Initializing" },
  { 2, "Standby" },
  { 3, "Ready" },
  { 4, "Active/Active-Attention" },
  { 0, NULL }
};

static const value_string status_vals[] = {
  { 1, "New policy arrived - no need to modify HA configuration" },
  { 2, "New policy arrived - need to modify HA configuration" },
  { 3, "Ready to change configuration" },
  { 0, NULL }
};

static const value_string ha_mode_vals[] = {
  { 0, "FWHA_UNDEF_MODE" },
  { 1, "FWHA_NOT_ACTIVE_MODE - CPHA is not active" },
  { 2, "FWHA_BALANCE_MODE - More than one machine active" },
  { 3, "FWHA_PRIMARY_UP_MODE" },
  { 4, "FWHA_ONE_UP_MODE" },
  { 0, NULL }
};

static const value_string ha_version_vals[] = {
  { 1, "4.1" },
  { 2, "NG (FP0)" },
  { 3, "NG FP1" },
  { 6, "NG FP2" },
  { 530, "NG FP3" },
  { 534, "VSX NG AIR2" },
  { 537, "VSX NGX EA" },
  { 538, "VSX NGX GA" },
  { 540, "NG AIR54 EA" },
  { 541, "NG AIR54 GA" },
  { 550, "NG AIR55 (up to HFA_16)" },
  { 551, "NG AIR55 HFA_17" },
  { 552, "NG AIR55W" },
  { 553, "NG AIR55 HFA_18" },
  { 591, "NG AIR55 LSV" },
  { 593, "NGXR60 EA" },
  { 601, "NGXR60 GA / NGXR60 HFA_01" },
  { 602, "NGXR60 HFA_02" },
  { 646, "NGXR60 Multicast acceleration" },
  { 650, "NGXR60 with Anti-Virus" },
  { 665, "NGXR61 EA2" },
  { 667, "NGXR61 GA" },
  { 690, "NGXR62 EA" },
  { 691, "NGXR62 GA" },
  { 700, "Connectra NGXR61 EA" },
  { 705, "Connectra NGXR61 GA" },
  { 710, "Connectra NGXR66 GA" },
  { 800, "NGXR65 EA" },
  { 801, "NGXR65 GA" },
  { 802, "NGXR65 HFA_01" },
  { 803, "NGXR65 HFA_02" },
  { 804, "NGXR65 HFA_02 / Connectra NGXR66.1" },
  { 805, "NGXR65 HFA_03" },
  { 810, "NGXR65 HFA_03 GA" },
  { 811, "NGXR65 HFA_40" },
  { 813, "NGXR65 HFA_50" },
  { 814, "NGXR65 HFA_50" },
  { 815, "NGXR65 HFA_60" },
  { 816, "NGXR65 HFA_70" },
  { 850, "VSX NGX Scalability Pack" },
  { 900, "VSX NGXR65 GA" },
  { 901, "VSX NGXR65 HFA_10" },
  { 902, "VSX NGXR65 HFA_20" },
  { 1000, "NGXR65 with CoreXL LE" },
  { 1001, "VSX NGXR67 GA" },
  { 1010, "VSX NGXR67 EA" },
  { 1100, "VSX NGXR68 GA" },
  { 1500, "R70 EA" },
  { 1501, "R70 GA" },
  { 1502, "R70.1 EA /R70.1 IPv6Pack HCC" },
  { 1505, "R70.1 GA" },
  { 1506, "2R70.1 IPv6Pack" },
  { 1508, "R70.12" },
  { 1516, "R70.20" },
  { 1518, "R70.30" },
  { 1520, "R70.40 / GX 5.0 HCC" },
  { 1523, "R70.50" },
  { 1555, "R71.10 /R71 VE" },
  { 1557, "R71.20" },
  { 1559, "R71.30" },
  { 1561, "R71.40" },
  { 1562, "R71.45" },
  { 1563, "R71.50" },
  { 2000, "R75 GA / R75.050 for 61000 /R75.051 for 61000 /R75.052 for 61000" },
  { 2005, "R75.10" },
  { 2010, "R75.20" },
  { 2020, "R75.30" },
  { 2210, "R75.40 32-bit" },
  { 2211, "R75.40 64-bit" },
  { 2220, "R75.45 32-bit" },
  { 2221, "R75.45 64-bit" },
  { 2225, "R75.46 32-bit" },
  { 2226, "R75.46 64-bit" },
  { 2230, "R75.47 32-bit" },
  { 2231, "R75.47 64-bit" },
  { 2500, "R75.40VS 32-bit" },
  { 2501, "R75.40VS 64-bit" },
  { 2502, "R75.40VS in VSX mode" },
  { 2700, "R76 32-bit" },
  { 2701, "DR76 64-bit" },
  { 2702, "R76 in VSX mode" },
  { 2720, "R76.10 32-bit" },
  { 2721, "R76.10 64-bit" },
  { 2722, "R76.10 in VSX mode" },
  { 2900, "R77 32-bit" },
  { 2901, "R77 64-bit" },
  { 2902, "R77 in VSX mode" },
  { 2905, "R77.10 32-bit" },
  { 2906, "R77.10 64-bit" },
  { 2907, "R77.10 in VSX mode" },
  { 2910, "R77.20 32-bit" },
  { 2911, "R77.20 64-bit" },
  { 2912, "R77.20 in VSX mode" },
  { 2920, "R77.30 32-bit" },
  { 2921, "R77.30 64-bit" },
  { 2922, "R77.30 in VSX mode" },
  { 62700, "R76SP for 61000 32-bit" },
  { 62701, "R76SP for 61000 64-bit" },
  { 62702, "R76SP for 61000 in VSX mode" },
  { 62710, "R76SP.10 for 61000 32-bit" },
  { 62711, "R76SP.10 for 61000 64-bit" },
  { 62712, "R76SP.10 for 61000 in VSX mode" },
  { 0, NULL },
};

static value_string_ext ha_version_vals_ext = VALUE_STRING_EXT_INIT(ha_version_vals);


static const value_string report_code_vals[] = {
  { 1, "Machine information included" },
  { 2, "Interface information included" },
  { 3, "Machine & Interface information included" },
  { 0, NULL },
};
static int dissect_my_state(tvbuff_t *, int, proto_tree *);
static int dissect_lb_conf(tvbuff_t *, int, proto_tree *);
static int dissect_policy_change(tvbuff_t *, int, proto_tree *);
static int dissect_probe(tvbuff_t *, int, proto_tree *);
static int dissect_conf_reply(tvbuff_t *, int, proto_tree *);

static int
dissect_cpha(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  int                   offset = 0;
  proto_item *          ti;
  proto_item *          nti;
  proto_tree *          cpha_tree = NULL;
  proto_tree *          ntree = NULL;
  guint16               opcode;
  guint16               magic_number;
  guint16               ha_version;
  /*
   * If the magic number or protocol version is unknown, don't treat this
   * frame as a CPHA frame.
   */
  if (tvb_reported_length(tvb) < 4) {
    /* Not enough data for the magic number or protocol version */
    return 0;
  }
  magic_number = tvb_get_ntohs(tvb, 0);
  ha_version = tvb_get_ntohs(tvb, 2);
  if (magic_number != CPHA_MAGIC) {
    /* Bad magic number */
    return 0;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CPHA");
  col_clear(pinfo->cinfo, COL_INFO);

  opcode  = tvb_get_ntohs(tvb, 6);

  col_add_fstr(pinfo->cinfo, COL_INFO, "CPHAv%d: %s",
      ha_version, val_to_str(opcode, opcode_type_vals, "Unknown %d"));

  if (tree) {
    ti = proto_tree_add_item(tree, proto_cphap, tvb, offset, -1, ENC_NA);
    cpha_tree = proto_item_add_subtree(ti, ett_cphap);
  }
  if (tree) {
    proto_tree_add_item(cpha_tree, hf_magic_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(cpha_tree, hf_cpha_protocol_ver, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(cpha_tree, hf_cluster_number, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(cpha_tree, hf_opcode, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(cpha_tree, hf_src_if_num, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(cpha_tree, hf_random_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(cpha_tree, hf_src_machine_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(cpha_tree, hf_dst_machine_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    if(ha_version != 1) {/* 4.1 - no policy_id and filler*/
        proto_tree_add_item(cpha_tree, hf_policy_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(cpha_tree, hf_filler, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }
    nti = proto_tree_add_item(cpha_tree, hf_payload, tvb, offset, -1, ENC_NA);
    proto_item_append_text(nti, " - %s", val_to_str(opcode, opcode_type_vals, "Unknown %d"));
    ntree = proto_item_add_subtree(nti, ett_cphap);

    switch(opcode) {
        case 1: dissect_my_state(tvb, offset, ntree); /* FWHAP_MY_STATE */
                break;
        case 2: break;
        case 3:                                      /* FWHAP_IF_PROBE_REQ */
        case 4: dissect_probe(tvb, offset, ntree);   /* FWHAP_IF_PROBE_RPLY */
                break;
        case 5: break;
        case 6: dissect_conf_reply(tvb, offset, ntree); /* FWHAP_IFCONF_RPLY */
                break;
        case 7: dissect_lb_conf(tvb, offset, ntree); /* FWHAP_LB_CONF */
                break;
        case 9: dissect_policy_change(tvb, offset, ntree); /* FWHAP_POLICY_CHANGE */
                break;
        default: proto_tree_add_item(ntree, hf_unknown_data, tvb, offset, -1, ENC_NA);
                break;
    }
  }

  return tvb_reported_length(tvb);
}

static int dissect_my_state(tvbuff_t * tvb, int offset, proto_tree * tree) {
  int i;
  proto_item *  nti = NULL;
  proto_tree *  ntree = NULL;
  guint16       report_code, id_num;

  proto_tree_add_item(tree, hf_id_num, tvb, offset, 2, ENC_BIG_ENDIAN);
  id_num = tvb_get_ntohs(tvb, offset);
  offset += 2;

  proto_tree_add_item(tree, hf_report_code, tvb, offset, 2, ENC_BIG_ENDIAN);
  report_code = tvb_get_ntohs(tvb, offset);
  offset += 2;

  proto_tree_add_item(tree, hf_ha_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_ha_time_unit, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  if (report_code & 1) {
        /* states */
        nti = proto_tree_add_item(tree, hf_machine_states, tvb, offset, id_num, ENC_NA);
        ntree = proto_item_add_subtree(nti, ett_cphap);
        for(i=0; i < id_num; i++) {
                nti = proto_tree_add_item(ntree, hf_state_node, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_item_append_text(nti, " (Nodes %d)", i);
                offset += 1;
        }
  }
  if (report_code & 2) {
        /* interface information */
        nti = proto_tree_add_item(tree, hf_interface_states, tvb, offset, 4, ENC_NA);
        ntree = proto_item_add_subtree(nti, ett_cphap);
        proto_tree_add_item(ntree, hf_in_up_num, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(ntree, hf_in_assumed_up_num, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(ntree, hf_out_up_num, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_tree_add_item(ntree, hf_out_assumed_up_num, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        for(i=0; i < id_num; i++) {
                proto_tree_add_item(tree, hf_cluster_last_packet, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_item_append_text(nti, " (Cluster %d)", i);
                offset += 1;
        }
  }
  return offset;
}

static int dissect_lb_conf(tvbuff_t * tvb, int offset, proto_tree * tree) {

  proto_tree_add_item(tree, hf_slot_num, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_machine_num, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_seed, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_hash_len, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  return offset;
}

static int dissect_policy_change(tvbuff_t * tvb, int offset, proto_tree * tree) {

  proto_tree_add_item(tree, hf_status, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  return offset;
}

static int dissect_probe(tvbuff_t * tvb, int offset, proto_tree * tree) {

  proto_tree_add_item(tree, hf_ifn, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  return offset;
}

static int dissect_conf_reply(tvbuff_t * tvb, int offset, proto_tree * tree) {

  proto_tree_add_item(tree, hf_num_reported_ifs, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_ethernet_add, tvb, offset, 6, ENC_NA);
  offset += 6;

  proto_tree_add_item(tree, hf_is_if_trusted, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;

  proto_tree_add_item(tree, hf_ip, tvb, offset, 4, ENC_NA);
  offset += 4;

  return offset;
}

void
proto_register_cpha(void)
{
  static hf_register_info hf[] = {
    { &hf_magic_number,
    { "Magic Number", "cpha.magic_number", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}},
    { &hf_cpha_protocol_ver,
    { "Protocol Version", "cpha.version", FT_UINT16, BASE_DEC|BASE_EXT_STRING, &ha_version_vals_ext, 0x0, "CPHAP Version", HFILL}},
    { &hf_cluster_number,
    { "Cluster Number", "cpha.cluster_number", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_opcode,
    { "HA OpCode", "cpha.opcode", FT_UINT16, BASE_DEC, VALS(opcode_type_vals), 0x0, NULL, HFILL}},
    { &hf_payload,
    { "Payload", "cpha.payload", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_src_if_num,
    { "Source Interface", "cpha.src_if", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_random_id,
    { "Random ID", "cpha.random_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_src_machine_id,
    { "Source Machine ID", "cpha.src_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_dst_machine_id,
    { "Destination Machine ID", "cpha.dst_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_policy_id,
    { "Policy ID", "cpha.policy_id", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_filler,
    { "Filler", "cpha.filler", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_unknown_data,
    { "Data", "cpha.unknown_data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_id_num,
    { "Number of IDs reported", "cpha.id_num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_report_code,
    { "Report code", "cpha.report_code", FT_UINT16, BASE_DEC, VALS(report_code_vals), 0x0, NULL, HFILL}},
    { &hf_ha_mode,
    { "HA mode", "cpha.ha_mode", FT_UINT16, BASE_DEC, VALS(ha_mode_vals), 0x0, NULL, HFILL}},
    { &hf_ha_time_unit,
    { "HA Time unit", "cpha.ha_time_unit", FT_UINT16, BASE_DEC, NULL, 0x0, "HA Time unit (ms)", HFILL}},
    { &hf_machine_states,
    { "Machines States", "cpha.machine_states", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_state_node,
    { "State node", "cpha.state_node", FT_UINT8, BASE_DEC, VALS(state_vals), 0x0, NULL, HFILL}},
    { &hf_interface_states,
    { "Interface States", "cpha.interface_states", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_num_reported_ifs,
    { "Reported Interfaces", "cpha.reported_ifs", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_ethernet_add,
    { "Ethernet Address", "cpha.ethernet_addr", FT_ETHER, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_is_if_trusted,
    { "Interface Trusted", "cpha.if_trusted", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_ip,
    { "IP Address", "cpha.ip", FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    { &hf_slot_num,
    { "Slot Number", "cpha.slot_num", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_machine_num,
    { "Machine Number", "cpha.machine_num", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_seed,
    { "Seed", "cpha.seed", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_hash_len,
    { "Hash list length", "cpha.hash_len", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_in_up_num,
    { "Interfaces up in the Inbound", "cpha.in_up", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_in_assumed_up_num,
    { "Interfaces assumed up in the Inbound", "cpha.in_assume_up", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_out_up_num,
    { "Interfaces up in the Outbound", "cpha.out_up", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_out_assumed_up_num,
    { "Interfaces assumed up in the Outbound", "cpha.out_assume_up", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    { &hf_cluster_last_packet,
    { "Last packet seen", "cpha.cluster_last_packet", FT_INT8, BASE_DEC, NULL, 0x0, "Time units ago", HFILL}},
    { &hf_status,
    { "Status", "cpha.status", FT_UINT32, BASE_DEC, VALS(status_vals), 0x0, NULL, HFILL}},
    { &hf_ifn,
    { "Interface Number", "cpha.ifn", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
  };
  static gint *ett[] = {
    &ett_cphap,
  };

  proto_cphap = proto_register_protocol("Check Point High Availability Protocol",
                                              "CPHA", "cpha");
  proto_register_field_array(proto_cphap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_cpha(void)
{
  dissector_handle_t cpha_handle;

  cpha_handle = create_dissector_handle(dissect_cpha, proto_cphap);
  dissector_add_uint("udp.port", UDP_PORT_CPHA, cpha_handle);
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
