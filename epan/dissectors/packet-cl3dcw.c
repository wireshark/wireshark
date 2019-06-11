/* packet-cl3dcw.c
 * Routines for CableLabs Dual-Channel Wi-Fi Messaging Protocol Dissection
 * Copyright 2019 Jon Dennis <j.dennis[at]cablelabs.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * CableLabs Specifications Can Be Found At:
 *  https://www.cablelabs.com/specs
 */


#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>

void proto_register_cl3dcw(void);
void proto_reg_handoff_cl3dcw(void);

#define SSID_MAX_LENGTH 32

/* persistent handles for this dissector */
static int           proto_cl3dcw               = -1;
static gint          ett_cl3dcw                 = -1;
static int           hf_cl3dcw_type             = -1;
static int           hf_cl3dcw_dccount          = -1;
static int           hf_cl3dcw_datamacaddrcount = -1;
static int           hf_cl3dcw_datassidcount    = -1;
static int           hf_cl3dcw_pcmacaddr        = -1;
static int           hf_cl3dcw_dcmacaddr        = -1;
static int           hf_cl3dcw_dcssid           = -1;
static int           hf_cl3dcw_dcbond           = -1;
static gint          ett_cl3dcw_dcbond          = -1;
static expert_field  ei_cl3dcw_unknown_type     = EI_INIT;
static expert_field  ei_cl3dcw_nodc             = EI_INIT;
static expert_field  ei_cl3dcw_ssid_too_big     = EI_INIT;


/* message id types */
#define DCWMSG_STA_JOIN           0x01
#define DCWMSG_STA_UNJOIN         0x02
#define DCWMSG_STA_ACK            0x11
#define DCWMSG_STA_NACK           0x12
#define DCWMSG_AP_ACCEPT_STA      0x21
#define DCWMSG_AP_REJECT_STA      0x22
#define DCWMSG_AP_ACK_DISCONNECT  0x41
#define DCWMSG_AP_QUIT            0x99

/* message type strings */
static const value_string cl3dcw_msg_types[] = {
  {DCWMSG_STA_JOIN,          "Station Join"        },
  {DCWMSG_STA_UNJOIN,        "Station Unjoin"      },
  {DCWMSG_STA_ACK,           "Station Ack"         },
  {DCWMSG_STA_NACK,          "Station Nack"        },
  {DCWMSG_AP_ACCEPT_STA,     "AP Accept Station"   },
  {DCWMSG_AP_REJECT_STA,     "AP Reject Station"   },
  {DCWMSG_AP_ACK_DISCONNECT, "AP Ack Disconnect"   },
  {DCWMSG_AP_QUIT,           "AQ Quit"             },
  {0, NULL}
};


static gint
dissect_sta_join(tvbuff_t * const tvb, packet_info * const pinfo, proto_tree * const tree _U_, proto_item * const ti) {
  guint32 data_macaddr_count;
  gint    offset;

  proto_tree_add_item_ret_uint(tree, hf_cl3dcw_datamacaddrcount, tvb, 0, 1, ENC_NA, &data_macaddr_count);
  if (data_macaddr_count < 1) {
    expert_add_info(pinfo, ti, &ei_cl3dcw_nodc);
  }

  offset = 1;
  while(data_macaddr_count--) {
    proto_tree_add_item(tree, hf_cl3dcw_dcmacaddr, tvb, offset, 6, ENC_NA);
    offset += 6;
  }

  return offset;
}

static gint
dissect_sta_unjoin(tvbuff_t * const tvb, packet_info * const pinfo, proto_tree * const tree _U_, proto_item * const ti) {
  guint32 data_macaddr_count;
  gint    offset;

  proto_tree_add_item_ret_uint(tree, hf_cl3dcw_datamacaddrcount, tvb, 0, 1, ENC_NA, &data_macaddr_count);
  if (data_macaddr_count < 1) {
    expert_add_info(pinfo, ti, &ei_cl3dcw_nodc);
  }

  offset = 1;
  while (data_macaddr_count--) {
    proto_tree_add_item(tree, hf_cl3dcw_dcmacaddr, tvb, offset, 6, ENC_NA);
    offset += 6;
  }

  return offset;
}

static gint
dissect_sta_ack(tvbuff_t * const tvb, packet_info * const pinfo, proto_tree * const tree _U_, proto_item * const ti) {

  proto_item *bond_item;
  proto_tree *bond_tree;

  guint32  data_channel_count;
  guint8   ssid_len;
  guint8  *ssidbuf;

  gint     offset;

  proto_tree_add_item_ret_uint(tree, hf_cl3dcw_dccount, tvb, 0, 1, ENC_NA, &data_channel_count);
  if (data_channel_count < 1) {
    expert_add_info(pinfo, ti, &ei_cl3dcw_nodc);
  }

  offset = 1;
  while (data_channel_count--) {
    /* parse each data channel bond...
     * format is 6-byte mac addr + 1 byte ssid string length + ssid string
     */
    ssid_len = tvb_get_guint8(tvb, offset + 6); /* +6 = skip over mac address */
    if (ssid_len > SSID_MAX_LENGTH) {
      expert_add_info(pinfo, ti, &ei_cl3dcw_ssid_too_big);
    }
    ssidbuf = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 6 + 1, ssid_len, ENC_ASCII); /* +6+1 = skip over mac address and length field */

    /* add the data channel bond sub-tree item */
    bond_item = proto_tree_add_item(tree, hf_cl3dcw_dcbond, tvb, offset, 6, ENC_NA);
    proto_item_append_text(bond_item, " -> \"%.*s\"", (guint)ssid_len, ssidbuf);
    proto_item_set_len(bond_item, 6 + 1 + ssid_len);
    bond_tree = proto_item_add_subtree(bond_item, ett_cl3dcw_dcbond);

    /* add the MAC address... */
    proto_tree_add_item(bond_tree, hf_cl3dcw_dcmacaddr, tvb, offset, 6, ENC_NA);
    offset += 6;

    /* add the SSID string
     * XXX the intent here is to highlight the leading length byte in the hex dump
     *     without printing it in the string... i suspect there is a better way of doing this
     */
    proto_tree_add_string_format(bond_tree, hf_cl3dcw_dcssid, tvb, offset, 1 + ssid_len,
                                 "", "Data Channel SSID: %.*s",
                                 (guint)ssid_len, ssidbuf);
    offset += 1 + ssid_len;
  }

  return offset;
}

static gint
dissect_sta_nack(tvbuff_t * const tvb, packet_info * const pinfo, proto_tree * const tree _U_, proto_item * const ti) {
  guint32  data_macaddr_count;
  gint     offset;

  proto_tree_add_item_ret_uint(tree, hf_cl3dcw_datamacaddrcount, tvb, 0, 1, ENC_NA, &data_macaddr_count);
  if (data_macaddr_count < 1) {
    expert_add_info(pinfo, ti, &ei_cl3dcw_nodc);
  }

  offset = 1;
  while (data_macaddr_count--) {
    proto_tree_add_item(tree, hf_cl3dcw_dcmacaddr, tvb, offset, 6, ENC_NA);
    offset += 6;
  }

  return offset;
}

static gint
dissect_ap_accept_sta(tvbuff_t * const tvb, packet_info * const pinfo, proto_tree * const tree _U_, proto_item * const ti) {

  guint32  data_ssid_count;
  guint8   ssid_len;
  guint8  *ssidbuf;

  gint     offset;

  proto_tree_add_item_ret_uint(tree, hf_cl3dcw_datassidcount, tvb, 0, 1, ENC_NA, &data_ssid_count);
  if (data_ssid_count < 1) {
    expert_add_info(pinfo, ti, &ei_cl3dcw_nodc);
  }

  offset = 1;
  while (data_ssid_count--) {
    ssid_len = tvb_get_guint8(tvb, offset);
    if (ssid_len > SSID_MAX_LENGTH) {
      expert_add_info(pinfo, ti, &ei_cl3dcw_ssid_too_big);
    }
    ssidbuf = tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 1, ssid_len, ENC_ASCII); /* +1 = skip over length field */

    /* add the SSID string
     * XXX the intent here is to highlight the leading length byte in the hex dump
     *     without printing it in the string... i suspect there is a better way of doing this
     */
    proto_tree_add_string_format(tree, hf_cl3dcw_dcssid, tvb, offset, 1 + ssid_len,
                                 "", "Data Channel SSID: %.*s",
                                 (guint)ssid_len, ssidbuf);
    offset += 1 + ssid_len;
  }

  return offset;
}

static gint
dissect_ap_reject_sta(tvbuff_t * const tvb, packet_info * const pinfo, proto_tree * const tree _U_, proto_item * const ti) {
  guint32 data_macaddr_count;
  gint    offset;

  proto_tree_add_item_ret_uint(tree, hf_cl3dcw_datamacaddrcount, tvb, 0, 1, ENC_NA, &data_macaddr_count);
  if (data_macaddr_count < 1) {
    expert_add_info(pinfo, ti, &ei_cl3dcw_nodc);
  }

  offset = 1;
  while (data_macaddr_count--) {
    proto_tree_add_item(tree, hf_cl3dcw_dcmacaddr, tvb, offset, 6, ENC_NA);
    offset += 6;
  }

  return offset;
}

/* called for each incomming framing matching our CL3 (sub-)protocol id: */
static int
dissect_cl3dcw(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {

  proto_item   *ti;
  proto_tree   *cl3dcw_tree;
  tvbuff_t     *tvb_msg;
  gint          total_dcw_message_len;

  guint8 type;

  /* parse the header fields */
  total_dcw_message_len = 1;
  type = tvb_get_guint8(tvb, 0);

  /* setup the "packet summary view" fields */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, "CL3-DCW");
  col_clear(pinfo->cinfo, COL_INFO);
  col_add_fstr(pinfo->cinfo, COL_INFO, "Dual-Channel Wi-Fi %s [Type 0x%02X]", val_to_str_const(type, cl3dcw_msg_types, "Unknown"), (guint)type);

  /* create a tree node for us... */
  ti = proto_tree_add_protocol_format(tree, proto_cl3dcw, tvb, 0, tvb_captured_length(tvb), "Dual-Channel Wi-Fi Control Message");
  cl3dcw_tree = proto_item_add_subtree(ti, ett_cl3dcw);
  tvb_msg = tvb_new_subset_remaining(tvb, 1);

  /* display dcw fields: */
  proto_tree_add_uint(cl3dcw_tree, hf_cl3dcw_type, tvb, 0, 1, type);

  /* parse the message by type... */
  switch (type) {
  case DCWMSG_STA_JOIN:          total_dcw_message_len += dissect_sta_join(tvb_msg, pinfo, cl3dcw_tree, ti);        break;
  case DCWMSG_STA_UNJOIN:        total_dcw_message_len += dissect_sta_unjoin(tvb_msg, pinfo, cl3dcw_tree, ti);      break;
  case DCWMSG_STA_ACK:           total_dcw_message_len += dissect_sta_ack(tvb_msg, pinfo, cl3dcw_tree, ti);         break;
  case DCWMSG_STA_NACK:          total_dcw_message_len += dissect_sta_nack(tvb_msg, pinfo, cl3dcw_tree, ti);        break;
  case DCWMSG_AP_ACCEPT_STA:     total_dcw_message_len += dissect_ap_accept_sta(tvb_msg, pinfo, cl3dcw_tree, ti);   break;
  case DCWMSG_AP_REJECT_STA:     total_dcw_message_len += dissect_ap_reject_sta(tvb_msg, pinfo, cl3dcw_tree, ti);   break;
  case DCWMSG_AP_ACK_DISCONNECT: /* nothing to really dissect */ break;
  case DCWMSG_AP_QUIT:           /* nothing to really dissect */ break;
  default:
    expert_add_info(pinfo, ti, &ei_cl3dcw_unknown_type);
    return tvb_captured_length(tvb);
  }

  /* now that the individual message dissection functions have ran,
     update the tree item length so that the hex dissection dieplay
     highlighting does not include any ethernet frame padding */
  proto_item_set_len(ti, total_dcw_message_len);
  return total_dcw_message_len; /* is this correct ? */
}

/* initializes this dissector */
void
proto_register_cl3dcw(void) {
  static hf_register_info hf[] = {
    { &hf_cl3dcw_type,
      { "Type",                            "cl3dcw.type",
        FT_UINT8,      BASE_HEX,           VALS(cl3dcw_msg_types), 0x0,
        NULL, HFILL }},
    { &hf_cl3dcw_dccount,
      { "Data Channel Count",             "cl3dcw.dccount",
        FT_UINT8,      BASE_DEC,           NULL, 0x0,
        NULL, HFILL }},
    { &hf_cl3dcw_datamacaddrcount,
      { "Data MAC Address Count",          "cl3dcw.datamacaddrcount",
        FT_UINT8,      BASE_DEC,           NULL, 0x0,
        NULL, HFILL }},
    { &hf_cl3dcw_datassidcount,
      { "Data SSID Count",                 "cl3dcw.datassidcount",
        FT_UINT8,      BASE_DEC,           NULL, 0x0,
        NULL, HFILL }},
    { &hf_cl3dcw_pcmacaddr,
      { "Primary Channel MAC Address",     "cl3dcw.pcmacaddr",
        FT_ETHER,      BASE_NONE,          NULL, 0x0,
        NULL, HFILL }},
    { &hf_cl3dcw_dcmacaddr,
      { "Data Channel MAC Address",        "cl3dcw.dcmacaddr",
        FT_ETHER,      BASE_NONE,          NULL, 0x0,
        NULL, HFILL }},
    { &hf_cl3dcw_dcssid,
      { "Data Channel SSID",               "cl3dcw.dcssid",
        FT_STRING,     BASE_NONE,          NULL, 0x0,
        NULL, HFILL }},
    { &hf_cl3dcw_dcbond,
      { "Data Channel Bond",               "cl3dcw.dcbond",
        FT_BYTES,      SEP_COLON,          NULL, 0x0,
        NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_cl3dcw,
    &ett_cl3dcw_dcbond,
  };
  static ei_register_info ei[] = {
     { &ei_cl3dcw_unknown_type,   { "cl3dcw.unknown_type",       PI_MALFORMED, PI_ERROR, "Unknown DCW message type", EXPFILL }},
     { &ei_cl3dcw_nodc,           { "cl3dcw.no_data_channels",   PI_MALFORMED, PI_WARN,  "No data-channels provided", EXPFILL }},
     { &ei_cl3dcw_ssid_too_big,   { "cl3dcw.ssid_too_big",       PI_MALFORMED, PI_WARN,  "Data channel SSID too big (expecting 32-byte maximum SSID)", EXPFILL }},
  };

  expert_module_t* expert_cl3dcw;

  proto_cl3dcw = proto_register_protocol(
    "CableLabs Dual-Channel Wi-Fi",  /* name */
    "cl3dcw",                        /* short name */
    "cl3dcw"                         /* abbrev */
  );

  proto_register_field_array(proto_cl3dcw, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_cl3dcw = expert_register_protocol(proto_cl3dcw);
  expert_register_field_array(expert_cl3dcw, ei, array_length(ei));
}

/* hooks in our dissector to be called on matching CL3 (sub-)protocol id */
void
proto_reg_handoff_cl3dcw(void) {
  dissector_handle_t cl3dcw_handle;
  cl3dcw_handle = create_dissector_handle(&dissect_cl3dcw, proto_cl3dcw);
  dissector_add_uint("cl3.subprotocol", 0x00DC, cl3dcw_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
