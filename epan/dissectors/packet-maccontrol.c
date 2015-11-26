/* packet-maccontrol.c
 * Routines for MAC Control ethernet header disassembly
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

/*
 * 04/26/2010: WMeier: "Class-Based Flow Control [CBFC] Pause Frame"  dissection added
 *             See: http://www.ieee802.org/1/files/public/docs2007/new-cm-barrass-pause-proposal.pdf
 * 2014-04:    David Miller <d.miller[at]cablelabs.com> and
 *             Philip Rosenberg-Watt <p.rosenberg-watt[at]cablelabs.com>
 *             + Added MPCP Gate, Report, and Register messages.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/etypes.h>

void proto_register_macctrl(void);
void proto_reg_handoff_macctrl(void);

static int proto_macctrl = -1;

static int hf_macctrl_opcode       = -1;
static int hf_macctrl_timestamp    = -1;
static int hf_macctrl_pause_time   = -1;
static int hf_macctrl_cbfc_enbv    = -1;
static int hf_macctrl_cbfc_enbv_c0 = -1;
static int hf_macctrl_cbfc_enbv_c1 = -1;
static int hf_macctrl_cbfc_enbv_c2 = -1;
static int hf_macctrl_cbfc_enbv_c3 = -1;
static int hf_macctrl_cbfc_enbv_c4 = -1;
static int hf_macctrl_cbfc_enbv_c5 = -1;
static int hf_macctrl_cbfc_enbv_c6 = -1;
static int hf_macctrl_cbfc_enbv_c7 = -1;
static int hf_macctrl_cbfc_pause_time_c0 = -1;
static int hf_macctrl_cbfc_pause_time_c1 = -1;
static int hf_macctrl_cbfc_pause_time_c2 = -1;
static int hf_macctrl_cbfc_pause_time_c3 = -1;
static int hf_macctrl_cbfc_pause_time_c4 = -1;
static int hf_macctrl_cbfc_pause_time_c5 = -1;
static int hf_macctrl_cbfc_pause_time_c6 = -1;
static int hf_macctrl_cbfc_pause_time_c7 = -1;

static int hf_reg_flags      = -1;
static int hf_reg_req_grants = -1;
static int hf_reg_grants     = -1;
static int hf_reg_port       = -1;
static int hf_reg_ack_port   = -1;
static int hf_reg_time       = -1;
static int hf_reg_ack_time   = -1;

static gint ett_macctrl            = -1;
static gint ett_macctrl_cbfc_enbv  = -1;
static gint ett_macctrl_cbfc_pause_times = -1;

static expert_field ei_macctrl_opcode = EI_INIT;
static expert_field ei_macctrl_cbfc_enbv = EI_INIT;
static expert_field ei_macctrl_dst_address = EI_INIT;

static const int *macctrl_cbfc_enbv_list[] = {
  &hf_macctrl_cbfc_enbv_c0,
  &hf_macctrl_cbfc_enbv_c1,
  &hf_macctrl_cbfc_enbv_c2,
  &hf_macctrl_cbfc_enbv_c3,
  &hf_macctrl_cbfc_enbv_c4,
  &hf_macctrl_cbfc_enbv_c5,
  &hf_macctrl_cbfc_enbv_c6,
  &hf_macctrl_cbfc_enbv_c7,
  NULL
};

static const int *macctrl_cbfc_pause_times_list[] = {
  &hf_macctrl_cbfc_pause_time_c0,
  &hf_macctrl_cbfc_pause_time_c1,
  &hf_macctrl_cbfc_pause_time_c2,
  &hf_macctrl_cbfc_pause_time_c3,
  &hf_macctrl_cbfc_pause_time_c4,
  &hf_macctrl_cbfc_pause_time_c5,
  &hf_macctrl_cbfc_pause_time_c6,
  &hf_macctrl_cbfc_pause_time_c7
};

#define MACCTRL_PAUSE                        0x0001
#define MACCTRL_GATE                         0x0002
#define MACCTRL_REPORT                       0x0003
#define MACCTRL_REGISTER_REQ                 0x0004
#define MACCTRL_REGISTER                     0x0005
#define MACCTRL_REGISTER_ACK                 0x0006
#define MACCTRL_CLASS_BASED_FLOW_CNTRL_PAUSE 0x0101

static const value_string opcode_vals[] = {
  { MACCTRL_PAUSE,                        "Pause" },
  { MACCTRL_GATE,                         "Gate" },
  { MACCTRL_REPORT,                       "Report" },
  { MACCTRL_REGISTER_REQ,                 "Register Req" },
  { MACCTRL_REGISTER,                     "Register" },
  { MACCTRL_REGISTER_ACK,                 "Register Ack" },
  { MACCTRL_CLASS_BASED_FLOW_CNTRL_PAUSE, "Class Based Flow Control [CBFC] Pause" },
  { 0, NULL }
};

static const value_string reg_flags_vals[] = {
  { 1, "Register" },
  { 2, "Deregister" },
  { 3, "Ack" },
  { 4, "Nack" },
  { 0, NULL }
};

static const guint8 dst_addr[] = {0x01, 0x80, 0xC2, 0x00, 0x00, 0x01};
static const address macctrl_dst_address = ADDRESS_INIT(AT_ETHER, 6, dst_addr);

static int
dissect_macctrl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  proto_item *ti, *opcode_item;
  proto_tree *macctrl_tree = NULL;
  proto_tree *pause_times_tree = NULL;
  guint16     opcode;
  guint16     pause_time;
  int i;
  gint offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC CTRL");
  col_clear(pinfo->cinfo, COL_INFO);

  opcode = tvb_get_ntohs(tvb, 0);

  ti = proto_tree_add_item(tree, proto_macctrl, tvb, 0, 46, ENC_NA);
  macctrl_tree = proto_item_add_subtree(ti, ett_macctrl);

  opcode_item = proto_tree_add_uint(macctrl_tree, hf_macctrl_opcode, tvb, offset, 2, opcode);
  offset += 2;
  if ((opcode >= MACCTRL_GATE) && (opcode <= MACCTRL_REGISTER_ACK)) {
    proto_tree_add_item(macctrl_tree, hf_macctrl_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
  }
  col_add_str(pinfo->cinfo, COL_INFO, val_to_str(opcode, opcode_vals, "Unknown"));

  switch (opcode) {

    case MACCTRL_PAUSE:
      if (!addresses_equal(&pinfo->dst, &macctrl_dst_address)) {
        expert_add_info(pinfo, opcode_item, &ei_macctrl_dst_address);
      }

      pause_time = tvb_get_ntohs(tvb, offset);
      col_append_fstr(pinfo->cinfo, COL_INFO, ": pause_time: %u quanta",
                      pause_time);
      proto_tree_add_uint(macctrl_tree, hf_macctrl_pause_time, tvb, offset, 2,
                          pause_time);
      break;

    case MACCTRL_GATE:
      break;

    case MACCTRL_REPORT:
      break;

    case MACCTRL_REGISTER_REQ:
      /* Flags */
      proto_tree_add_item(macctrl_tree, hf_reg_flags, tvb,
                          offset, 1, ENC_BIG_ENDIAN);
      offset++;

      /* Pending Grants */
      proto_tree_add_item(macctrl_tree, hf_reg_req_grants, tvb,
                          offset, 1, ENC_BIG_ENDIAN);
      break;

    case MACCTRL_REGISTER:

      /* Assigned Port */
      proto_tree_add_item(macctrl_tree, hf_reg_port, tvb,
                          offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      /* Flags */
      proto_tree_add_item(macctrl_tree, hf_reg_flags, tvb,
                          offset, 1, ENC_BIG_ENDIAN);
      offset++;

      /* Synch Time */
      proto_tree_add_item(macctrl_tree, hf_reg_time, tvb,
                          offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      /* Echoed Pending Grants */
      proto_tree_add_item(macctrl_tree, hf_reg_grants, tvb,
                          offset, 1, ENC_BIG_ENDIAN);
      break;

    case MACCTRL_REGISTER_ACK:

      /* Flags */
      proto_tree_add_item(macctrl_tree, hf_reg_flags, tvb,
                          offset, 1, ENC_BIG_ENDIAN);
      offset++;

      /* Echoed Assigned Port */
      proto_tree_add_item(macctrl_tree, hf_reg_ack_port, tvb,
                          offset, 2, ENC_BIG_ENDIAN);
      offset += 2;

      /* Echoed Synch Time */
      proto_tree_add_item(macctrl_tree, hf_reg_ack_time, tvb,
                          offset, 2, ENC_BIG_ENDIAN);
      break;

    case MACCTRL_CLASS_BASED_FLOW_CNTRL_PAUSE:
      if (!addresses_equal(&pinfo->dst, &macctrl_dst_address)) {
        expert_add_info(pinfo, opcode_item, &ei_macctrl_dst_address);
      }

      ti = proto_tree_add_bitmask(macctrl_tree, tvb, offset, hf_macctrl_cbfc_enbv,
                             ett_macctrl_cbfc_enbv, macctrl_cbfc_enbv_list, ENC_BIG_ENDIAN);
      if (tvb_get_guint8(tvb, offset) != 0) {
        expert_add_info(pinfo, ti, &ei_macctrl_cbfc_enbv);
      }
      offset += 2;

      pause_times_tree = proto_tree_add_subtree(macctrl_tree, tvb, offset, 8*2, ett_macctrl_cbfc_pause_times, NULL, "CBFC Class Pause Times");

      for (i=0; i<8; i++) {
        proto_tree_add_item(pause_times_tree, *macctrl_cbfc_pause_times_list[i], tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
      }
      break;

    default:
      expert_add_info(pinfo, opcode_item, &ei_macctrl_opcode);
     break;
  }
  return tvb_captured_length(tvb);
}

void
proto_register_macctrl(void)
{
  static hf_register_info hf[] = {
    { &hf_macctrl_opcode,
      { "Opcode", "macc.opcode", FT_UINT16, BASE_HEX,
        VALS(opcode_vals), 0x0, "MAC Control Opcode", HFILL}},

    { &hf_macctrl_timestamp,
      { "Timestamp", "macc.timestamp", FT_UINT32, BASE_DEC,
        NULL, 0x0, "MAC Control Timestamp", HFILL }},

    { &hf_macctrl_pause_time,
      { "pause_time", "macc.pause_time", FT_UINT16, BASE_DEC,
        NULL, 0x0, "MAC control PAUSE frame pause_time", HFILL }},

    { &hf_macctrl_cbfc_enbv,
      { "CBFC Class Enable Vector", "macc.cbfc.enbv", FT_UINT16, BASE_HEX,
        NULL, 0x0, NULL, HFILL }},

    { &hf_macctrl_cbfc_enbv_c0,
      { "C0", "macc.cbfc.enbv.c0", FT_BOOLEAN, 16,
        NULL, 0x01, NULL, HFILL }},

    { &hf_macctrl_cbfc_enbv_c1,
      { "C1", "macc.cbfc.enbv.c1", FT_BOOLEAN, 16,
        NULL, 0x02, NULL, HFILL }},

    { &hf_macctrl_cbfc_enbv_c2,
      { "C2", "macc.cbfc.enbv.c2", FT_BOOLEAN, 16,
        NULL, 0x04, NULL, HFILL }},

    { &hf_macctrl_cbfc_enbv_c3,
      { "C3", "macc.cbfc.enbv.c3", FT_BOOLEAN, 16,
        NULL, 0x08, NULL, HFILL }},

    { &hf_macctrl_cbfc_enbv_c4,
      { "C4", "macc.cbfc.enbv.c4", FT_BOOLEAN, 16,
        NULL, 0x10, NULL, HFILL }},

    { &hf_macctrl_cbfc_enbv_c5,
      { "C5", "macc.cbfc.enbv.c5", FT_BOOLEAN, 16,
        NULL, 0x20, NULL, HFILL }},

    { &hf_macctrl_cbfc_enbv_c6,
      { "C6", "macc.cbfc.enbv.c6", FT_BOOLEAN, 16,
        NULL, 0x40, NULL, HFILL }},

    { &hf_macctrl_cbfc_enbv_c7,
      { "C7", "macc.cbfc.enbv.c7", FT_BOOLEAN, 16,
        NULL, 0x80, NULL, HFILL }},

    { &hf_macctrl_cbfc_pause_time_c0,
      { "C0", "macc.cbfc.pause_time.c0", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_macctrl_cbfc_pause_time_c1,
      { "C1", "macc.cbfc.pause_time.c1", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_macctrl_cbfc_pause_time_c2,
      { "C2", "macc.cbfc.pause_time.c2", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_macctrl_cbfc_pause_time_c3,
      { "C3", "macc.cbfc.pause_time.c3", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_macctrl_cbfc_pause_time_c4,
      { "C4", "macc.cbfc.pause_time.c4", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_macctrl_cbfc_pause_time_c5,
      { "C5", "macc.cbfc.pause_time.c5", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_macctrl_cbfc_pause_time_c6,
      { "C6", "macc.cbfc.pause_time.c6", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_macctrl_cbfc_pause_time_c7,
      { "C7", "macc.cbfc.pause_time.c7", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_reg_flags,
      { "Flags", "macc.reg.flags", FT_UINT8, BASE_HEX,
        VALS(reg_flags_vals), 0x00, NULL, HFILL }},

    { &hf_reg_req_grants,
      { "Pending Grants", "macc.regreq.grants", FT_UINT8, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_reg_grants,
      { "Echoed Pending Grants", "macc.reg.grants", FT_UINT8, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_reg_port,
      { "Assigned Port (LLID)", "macc.reg.assignedport", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_reg_ack_port,
      { "Echoed Assigned Port (LLID)", "macc.regack.assignedport", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_reg_time,
      { "Sync Time", "macc.reg.synctime", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }},

    { &hf_reg_ack_time,
      { "Echoed Sync Time", "macc.regack.synctime", FT_UINT16, BASE_DEC,
        NULL, 0x00, NULL, HFILL }}
  };

  static gint *ett[] = {
        &ett_macctrl,
        &ett_macctrl_cbfc_enbv,
        &ett_macctrl_cbfc_pause_times
  };

  static ei_register_info ei[] = {
      { &ei_macctrl_opcode, { "macc.opcode.unknown", PI_PROTOCOL, PI_WARN, "Unknown opcode", EXPFILL }},
      { &ei_macctrl_cbfc_enbv, { "macc.cbfc.enbv.not_zero", PI_PROTOCOL, PI_WARN, "8 MSbs of ENBV must be 0", EXPFILL }},
      { &ei_macctrl_dst_address, { "macc.dst_address_invalid", PI_PROTOCOL, PI_WARN, "Destination address must be 01-80-C2-00-00-01", EXPFILL }},
  };

  expert_module_t* expert_macctrl;

  proto_macctrl = proto_register_protocol("MAC Control", "MACC", "macc");
  proto_register_field_array(proto_macctrl, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_macctrl = expert_register_protocol(proto_macctrl);
  expert_register_field_array(expert_macctrl, ei, array_length(ei));
}

void
proto_reg_handoff_macctrl(void)
{
  dissector_handle_t macctrl_handle;

  macctrl_handle = create_dissector_handle(dissect_macctrl, proto_macctrl);
  dissector_add_uint("ethertype", ETHERTYPE_MAC_CONTROL, macctrl_handle);
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
