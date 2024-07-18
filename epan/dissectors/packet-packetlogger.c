/* packet-packetlogger.c
 * Routines for Apple's PacketLogger Types
 *
 * Copyright 2009, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

#include "packet-bluetooth.h"

void proto_register_packetlogger(void);
void proto_reg_handoff_packetlogger(void);

#define PNAME  "PacketLogger"
#define PSNAME "PKTLOG"
#define PFNAME "packetlogger"

static int proto_packetlogger;

static int hf_type;
static int hf_info;
static int hf_syslog;
static int hf_syslog_process_id;
static int hf_syslog_message_type;
static int hf_syslog_process;
static int hf_syslog_sender;
static int hf_syslog_subsystem;
static int hf_syslog_category;
static int hf_syslog_message;

static int ett_packetlogger;
static int ett_syslog;

static dissector_handle_t packetlogger_handle;
static dissector_table_t hci_h1_table;

/*
 * Packet types.
 *
 * NOTE: if you add a new type here, you MUST also add it to
 * wiretap/packetlogger.c's list of packet types *AND* to the
 * packet types it checks for in its "does this look like a
 * Packetlogger file?" heuristics; otherwise, some valid
 * Packetlogger files will not be recognize as Packetlogger
 * files.
 */
#define PKT_HCI_COMMAND     0x00
#define PKT_HCI_EVENT       0x01
#define PKT_SENT_ACL_DATA   0x02
#define PKT_RECV_ACL_DATA   0x03
#define PKT_SENT_SCO_DATA   0x08
#define PKT_RECV_SCO_DATA   0x09
#define PKT_LMP_SEND        0x0A
#define PKT_LMP_RECV        0x0B
#define PKT_SYSLOG          0xF7
#define PKT_KERNEL          0xF8
#define PKT_KERNEL_DEBUG    0xF9
#define PKT_ERROR           0xFA
#define PKT_POWER           0xFB
#define PKT_NOTE            0xFC
#define PKT_CONFIG          0xFD
#define PKT_NEW_CONTROLLER  0xFE

static const value_string type_vals[] = {
  { PKT_HCI_COMMAND,     "HCI Command"     },
  { PKT_HCI_EVENT,       "HCI Event"       },
  { PKT_SENT_ACL_DATA,   "Sent ACL Data"   },
  { PKT_RECV_ACL_DATA,   "Recv ACL Data"   },
  { PKT_SENT_SCO_DATA,   "Sent SCO Data"   },
  { PKT_RECV_SCO_DATA,   "Recv SCO Data"   },
  { PKT_LMP_SEND,        "Sent LMP Data"   },
  { PKT_LMP_RECV,        "Recv LMP Data"   },
  { PKT_SYSLOG,          "Syslog"          },
  { PKT_KERNEL,          "Kernel"          },
  { PKT_KERNEL_DEBUG,    "Kernel Debug"    },
  { PKT_ERROR,           "Error"           },
  { PKT_POWER,           "Power"           },
  { PKT_NOTE,            "Note"            },
  { PKT_CONFIG,          "Config"          },
  { PKT_NEW_CONTROLLER,  "New Controller"  },
  { 0, NULL }
};

static void dissect_bthci_h1(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, proto_item *ti, uint8_t pl_type, uint32_t channel,
        bool sent, bluetooth_data_t *bluetooth_data)
{
  struct bthci_phdr  bthci;

  bthci.channel = channel;
  bthci.sent = sent;
  pinfo->p2p_dir = sent ? P2P_DIR_SENT : P2P_DIR_RECV;

  bluetooth_data->previous_protocol_data.bthci = &bthci;
  proto_item_set_len (ti, 1);

  col_add_str (pinfo->cinfo, COL_INFO, val_to_str(pl_type, type_vals, "Unknown 0x%02x"));
  if (!dissector_try_uint_new (hci_h1_table, bthci.channel,
          tvb, pinfo, tree, true, bluetooth_data)) {
    call_data_dissector (tvb, pinfo, tree);
  }
}

static void dissect_syslog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti = NULL;
    proto_tree *sub_tree = NULL;
    int         offset = 0;
    int         len;

    ti = proto_tree_add_item (tree, hf_syslog, tvb, 0, -1, ENC_NA);
    sub_tree = proto_item_add_subtree (ti, ett_syslog);

    proto_tree_add_item (sub_tree, hf_syslog_process_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item (sub_tree, hf_syslog_message_type, tvb, offset, 1, ENC_NA);
    offset += 1;

    len = tvb_strsize (tvb, offset);
    proto_tree_add_item (sub_tree, hf_syslog_process, tvb, offset, len, ENC_ASCII);
    offset += len;

    len = tvb_strsize (tvb, offset);
    proto_tree_add_item (sub_tree, hf_syslog_sender, tvb, offset, len, ENC_ASCII);
    offset += len;

    len = tvb_strsize (tvb, offset);
    proto_tree_add_item (sub_tree, hf_syslog_subsystem, tvb, offset, len, ENC_ASCII);
    offset += len;

    len = tvb_strsize (tvb, offset);
    proto_tree_add_item (sub_tree, hf_syslog_category, tvb, offset, len, ENC_ASCII);
    offset += len;

    len = tvb_strsize (tvb, offset);
    proto_tree_add_item (sub_tree, hf_syslog_message, tvb, offset, len, ENC_ASCII);
    col_add_str (pinfo->cinfo, COL_INFO, tvb_format_stringzpad_wsp (pinfo->pool, tvb, offset, len));
}

static int dissect_packetlogger(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
  proto_tree        *packetlogger_tree = NULL;
  tvbuff_t          *next_tvb;
  proto_item        *ti = NULL;
  uint8_t            pl_type;
  int                len;
  bluetooth_data_t  *bluetooth_data;

  bluetooth_data = (bluetooth_data_t *) data;

  col_set_str (pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear (pinfo->cinfo, COL_INFO);

  ti = proto_tree_add_item (tree, proto_packetlogger, tvb, 0, -1, ENC_NA);
  packetlogger_tree = proto_item_add_subtree (ti, ett_packetlogger);

  pl_type = tvb_get_uint8 (tvb, 0);
  proto_tree_add_item (packetlogger_tree, hf_type, tvb, 0, 1, ENC_BIG_ENDIAN);
  proto_item_append_text (ti, " %s", val_to_str (pl_type, type_vals, "Unknown 0x%02x"));

  len = tvb_reported_length_remaining (tvb, 1);
  next_tvb = tvb_new_subset_remaining (tvb, 1);

  switch (pl_type) {
  case PKT_HCI_COMMAND:
    dissect_bthci_h1 (next_tvb, pinfo, tree, ti, pl_type, BTHCI_CHANNEL_COMMAND,
            true, bluetooth_data);
    break;
  case PKT_HCI_EVENT:
    dissect_bthci_h1 (next_tvb, pinfo, tree, ti, pl_type, BTHCI_CHANNEL_EVENT,
            false, bluetooth_data);
    break;
  case PKT_SENT_ACL_DATA:
    dissect_bthci_h1 (next_tvb, pinfo, tree, ti, pl_type, BTHCI_CHANNEL_ACL,
            true, bluetooth_data);
    break;
  case PKT_RECV_ACL_DATA:
    dissect_bthci_h1 (next_tvb, pinfo, tree, ti, pl_type, BTHCI_CHANNEL_ACL,
            false, bluetooth_data);
    break;
  case PKT_SENT_SCO_DATA:
    dissect_bthci_h1 (next_tvb, pinfo, tree, ti, pl_type, BTHCI_CHANNEL_SCO,
            true, bluetooth_data);
    break;
  case PKT_RECV_SCO_DATA:
    dissect_bthci_h1 (next_tvb, pinfo, tree, ti, pl_type, BTHCI_CHANNEL_SCO,
            false, bluetooth_data);
    break;
  case PKT_SYSLOG:
    dissect_syslog (next_tvb, pinfo, packetlogger_tree);
    break;
  case PKT_KERNEL:
  case PKT_KERNEL_DEBUG:
  case PKT_ERROR:
  case PKT_POWER:
  case PKT_NOTE:
  case PKT_CONFIG:
  case PKT_NEW_CONTROLLER:
    proto_tree_add_item (packetlogger_tree, hf_info, next_tvb, 0, len, ENC_ASCII);
    col_add_str (pinfo->cinfo, COL_INFO, tvb_format_stringzpad_wsp (pinfo->pool, next_tvb, 0, len));
    break;
  default:
    call_data_dissector(next_tvb, pinfo, tree);
    col_add_str (pinfo->cinfo, COL_INFO, val_to_str(pl_type, type_vals, "Unknown 0x%02x"));
    break;
  }

  return tvb_captured_length(tvb);
}

void proto_register_packetlogger (void)
{
  static hf_register_info hf[] = {
    { &hf_type,
      { "Type", "packetlogger.type", FT_UINT8, BASE_HEX, VALS(type_vals), 0x0, NULL, HFILL } },
    { &hf_info,
      { "Info", "packetlogger.info", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_syslog,
      { "Syslog", "packetlogger.syslog", FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_syslog_process_id,
      { "ProcessID", "packetlogger.syslog.process_id", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_syslog_message_type,
      { "Message Type", "packetlogger.syslog.message_type", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
    { &hf_syslog_process,
      { "Process", "packetlogger.syslog.process", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_syslog_sender,
      { "Sender", "packetlogger.syslog.sender", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_syslog_subsystem,
      { "Subsystem", "packetlogger.syslog.subsystem", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_syslog_category,
      { "Category", "packetlogger.syslog.category", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
    { &hf_syslog_message,
      { "Message", "packetlogger.syslog.message", FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } }
  };

  static int *ett[] = {
    &ett_packetlogger,
    &ett_syslog
  };

  proto_packetlogger = proto_register_protocol (PNAME, PSNAME, PFNAME);

  packetlogger_handle = register_dissector (PFNAME, dissect_packetlogger, proto_packetlogger);

  proto_register_field_array (proto_packetlogger, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}

void proto_reg_handoff_packetlogger (void)
{
  hci_h1_table = find_dissector_table("hci_h1.type");
  dissector_add_uint ("bluetooth.encap", WTAP_ENCAP_PACKETLOGGER, packetlogger_handle);
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
