/* packet-openvpn.c
 * routines for openvpn packet dissasembly
 * - http://www.openvpn.net
 * - http://fengnet.com/book/vpns%20illustrated%20tunnels%20%20vpnsand%20ipsec/ch08lev1sec5.html
 *
 * Created as part of a semester project at the University of Applied Sciences Hagenberg
 * (http://www.fh-ooe.at/en/hagenberg-campus/)
 *
 * Copyright (c) 2013:
 *   Hofer Manuel (manuel@mnlhfr.at)
 *   Nemeth Franz
 *   Scheipner Alexander
 *   Stiftinger Thomas
 *   Werner Sebastian
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/conversation.h>
#include "packet-tcp.h"

void proto_register_openvpn(void);
void proto_reg_handoff_openvpn(void);

#define PFNAME "openvpn"
#define PNAME  "OpenVPN Protocol"
#define PSNAME "OpenVPN"

#define OPENVPN_PORT 1194

/* packet opcode and key-id are combined in one byte */
#define P_OPCODE_MASK 0xF8 /* packet opcode (high 5 bits) */
#define P_KEY_ID_MASK 0x07 /* key-id (low 3 bits) */
#define HMAC_KEY_LENGTH_MAX 64 /* 512 Bit HMAC is maximum */

/* Opcodes */
#define P_CONTROL_HARD_RESET_CLIENT_V1  1
#define P_CONTROL_HARD_RESET_SERVER_V1  2
#define P_CONTROL_SOFT_RESET_V1         3
#define P_CONTROL_V1                    4
#define P_ACK_V1                        5
#define P_DATA_V1                       6
#define P_CONTROL_HARD_RESET_CLIENT_V2  7
#define P_CONTROL_HARD_RESET_SERVER_V2  8
#define P_DATA_V2                       9
#define P_CONTROL_HARD_RESET_CLIENT_V3  10
#define P_CONTROL_WKC_V1                11

static int ett_openvpn;
static int ett_openvpn_data;
static int ett_openvpn_packetarray;
static int ett_openvpn_type;
static int ett_openvpn_wkc;
static int hf_openvpn_data;
static int hf_openvpn_wkc_data;
static int hf_openvpn_wkc_length;
static int hf_openvpn_fragment_bytes;
static int hf_openvpn_hmac;
static int hf_openvpn_keyid;
static int hf_openvpn_mpid;
static int hf_openvpn_mpid_arrayelement;
static int hf_openvpn_mpid_arraylength;
static int hf_openvpn_net_time;
static int hf_openvpn_opcode;
static int hf_openvpn_pdu_type;
static int hf_openvpn_pid;
static int hf_openvpn_plen;
static int hf_openvpn_rsessionid;
static int hf_openvpn_sessionid;
static int hf_openvpn_peerid;
static int proto_openvpn;

static dissector_handle_t openvpn_udp_handle;
static dissector_handle_t openvpn_tcp_handle;

static dissector_handle_t tls_handle;

/* Preferences */
static bool     pref_long_format       = true;
static bool     pref_tls_auth;
static bool     pref_tls_auth_override;
static bool     pref_tls_crypt_override;
static unsigned tls_auth_hmac_size     = 20; /* Default SHA-1 160 Bits */

static const value_string openvpn_message_types[] =
{
  {   P_CONTROL_HARD_RESET_CLIENT_V1,  "P_CONTROL_HARD_RESET_CLIENT_V1" },
  {   P_CONTROL_HARD_RESET_SERVER_V1,  "P_CONTROL_HARD_RESET_SERVER_V1" },
  {   P_CONTROL_SOFT_RESET_V1,         "P_CONTROL_SOFT_RESET_V1" },
  {   P_CONTROL_V1,                    "P_CONTROL_V1" },
  {   P_ACK_V1,                        "P_ACK_V1" },
  {   P_DATA_V1,                       "P_DATA_V1" },
  {   P_CONTROL_HARD_RESET_CLIENT_V2,  "P_CONTROL_HARD_RESET_CLIENT_V2" },
  {   P_CONTROL_HARD_RESET_SERVER_V2,  "P_CONTROL_HARD_RESET_SERVER_V2" },
  {   P_DATA_V2,                       "P_DATA_V2" },
  {   P_CONTROL_HARD_RESET_CLIENT_V3,  "P_CONTROL_HARD_RESET_CLIENT_V3" },
  {   P_CONTROL_WKC_V1,                "P_CONTROL_WKC_V1" },
  {   0, NULL }
};

/* everything used during the reassembly process */
static reassembly_table msg_reassembly_table;

static int ett_openvpn_fragment;
static int ett_openvpn_fragments;
static int hf_openvpn_fragment;
static int hf_openvpn_fragment_count;
static int hf_openvpn_fragment_error;
static int hf_openvpn_fragment_multiple_tails;
static int hf_openvpn_fragment_overlap;
static int hf_openvpn_fragment_overlap_conflicts;
static int hf_openvpn_fragment_too_long_fragment;
static int hf_openvpn_fragments;
static int hf_openvpn_reassembled_in;
static int hf_openvpn_reassembled_length;

static const fragment_items openvpn_frag_items = {
  /* Fragment subtrees */
  &ett_openvpn_fragment,
  &ett_openvpn_fragments,
  /* Fragment fields */
  &hf_openvpn_fragments,
  &hf_openvpn_fragment,
  &hf_openvpn_fragment_overlap,
  &hf_openvpn_fragment_overlap_conflicts,
  &hf_openvpn_fragment_multiple_tails,
  &hf_openvpn_fragment_too_long_fragment,
  &hf_openvpn_fragment_error,
  &hf_openvpn_fragment_count,
  /* Reassembled in field */
  &hf_openvpn_reassembled_in,
  /* Reassembled length field */
  &hf_openvpn_reassembled_length,
  /* Reassembled data field */
  NULL,
  /* Tag */
  "Message fragments"
};

/* we check the leading 4 byte of a suspected hmac for 0x00 bytes,
   if more than 1 byte out of the 4 provided contains 0x00, the
   hmac is considered not valid, which suggests that no tls auth is used.
   unfortunately there is no other way to detect tls auth on the fly */
static bool
check_for_valid_hmac(uint32_t hmac)
{
  int c = 0;
  if ((hmac & 0x000000FF) == 0x00000000) {
    c++;
  }
  if ((hmac & 0x0000FF00) == 0x00000000) {
    c++;
  }
  if ((hmac & 0x00FF0000) == 0x00000000) {
    c++;
  }
  if ((hmac & 0xFF000000) == 0x00000000) {
    c++;
  }
  if (c > 1) {
    return false;
  } else {
    return true;
  }
}

static int
dissect_openvpn_msg_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *openvpn_tree, proto_tree *parent_tree, int offset)
{
  bool           tls_auth;
  bool           tls_crypt = false;
  unsigned       openvpn_keyid;
  unsigned       openvpn_opcode;
  uint32_t       msg_sessionid = -1;
  uint8_t        openvpn_predict_tlsauth_arraylength;
  proto_item    *ti2;
  proto_tree    *packetarray_tree, *type_tree;
  uint32_t       msg_length_remaining;
  int            wkc_offset = -1;

  /* Clear out stuff in the info column */
  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear(pinfo->cinfo,COL_INFO);

  /* read opcode and write to info column */
  openvpn_opcode = tvb_get_bits8(tvb, offset*8, 5);
  col_append_fstr(pinfo->cinfo, COL_INFO, "MessageType: %s",
                  val_to_str_const(openvpn_opcode, openvpn_message_types, "Unknown Messagetype"));


  openvpn_keyid = tvb_get_bits8(tvb, offset*8 + 5, 3);
  proto_item_append_text(parent_tree, ", Opcode: %s, Key ID: %d",
                         val_to_str(openvpn_opcode, openvpn_message_types, "Unknown (0x%02x)"),
                         openvpn_keyid);

  ti2 = proto_tree_add_item(openvpn_tree, hf_openvpn_pdu_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_append_text(ti2, " [opcode/key_id]");

  type_tree = proto_item_add_subtree(ti2, ett_openvpn_type);
  proto_tree_add_item(type_tree, hf_openvpn_opcode, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(type_tree, hf_openvpn_keyid, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset += 1;

  if (openvpn_opcode == P_DATA_V2) {
    proto_tree_add_item(openvpn_tree, hf_openvpn_peerid, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset += 3;
  } else if (openvpn_opcode != P_DATA_V1) {
    /* if we have a P_CONTROL or P_ACK packet */

    /* read sessionid */
    msg_sessionid = tvb_get_bits32(tvb, offset*8+32, 32, ENC_BIG_ENDIAN);
    proto_tree_add_item(openvpn_tree, hf_openvpn_sessionid, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    /* tls-auth detection (this can be overridden by preferences */
    openvpn_predict_tlsauth_arraylength = tvb_get_uint8(tvb, offset);

    /* if the first 4 bytes that would, if tls-auth is used, contain part of the hmac,
       lack entropy, we assume no tls-auth is used */
    if (pref_tls_auth_override == false) {
      if ((openvpn_opcode != P_DATA_V1)
          && (openvpn_predict_tlsauth_arraylength > 0)
          && check_for_valid_hmac(tvb_get_ntohl(tvb, offset))) {
        tls_auth = true;
      } else {
        tls_auth = false;
      }
    } else {
      tls_auth = pref_tls_auth;
    }

    if (openvpn_opcode == P_CONTROL_HARD_RESET_CLIENT_V3 || openvpn_opcode == P_CONTROL_WKC_V1 || pref_tls_crypt_override == true) {
      /* these opcodes are always tls-crypt*/
      tls_crypt = true;
      tls_auth = false;
    }

    if (tls_auth == true) {
      proto_tree_add_item(openvpn_tree, hf_openvpn_hmac, tvb, offset, tls_auth_hmac_size, ENC_NA);
      offset += tls_auth_hmac_size;
    }

    if (tls_auth == true || tls_crypt == true) {
      if (tvb_reported_length_remaining(tvb, offset) >= 8) {
        proto_tree_add_item(openvpn_tree, hf_openvpn_pid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (pref_long_format || tls_crypt == true) {
          proto_tree_add_item(openvpn_tree, hf_openvpn_net_time, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
      }
      if (tls_crypt == true) {
        /* tls-crypt uses HMAC-SHA256 */
        proto_tree_add_item(openvpn_tree, hf_openvpn_hmac, tvb, offset, 32, ENC_NA);
        offset += 32;
      }
    }

    if (tvb_reported_length_remaining(tvb, offset) >= 1 && tls_crypt == false) {
      /* read P_ACK packet-id array length */
      int pid_arraylength = tvb_get_uint8(tvb, offset);
      int i;
      proto_tree_add_item(openvpn_tree, hf_openvpn_mpid_arraylength, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;

      if (pid_arraylength > 0) {

        packetarray_tree = proto_tree_add_subtree(openvpn_tree, tvb, offset, 0, ett_openvpn_packetarray, NULL, "Packet-ID Array");
        for (i = 0; i < pid_arraylength; i++) {
          proto_tree_add_item(packetarray_tree, hf_openvpn_mpid_arrayelement, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }

        if (tvb_reported_length_remaining(tvb, offset) >= 8) {
          proto_tree_add_item(openvpn_tree, hf_openvpn_rsessionid, tvb, offset, 8, ENC_BIG_ENDIAN);
          offset += 8;
        }
      }
    }

    /* if we have a P_CONTROL packet */
    if (openvpn_opcode != P_ACK_V1 && tls_crypt == false) {
      /* read Message Packet-ID */
      if (tvb_reported_length_remaining(tvb, offset) >= 4) {
        proto_tree_add_item(openvpn_tree, hf_openvpn_mpid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
      }
    }
  }

  /* if we have more data left, determine what to do */
  msg_length_remaining = tvb_reported_length_remaining(tvb, offset);

  if (msg_length_remaining == 0) {
    return tvb_captured_length(tvb);
  }

  int data_len = msg_length_remaining;
  int wkc_len = -1;
  if ((openvpn_opcode == P_CONTROL_HARD_RESET_CLIENT_V3 || openvpn_opcode == P_CONTROL_WKC_V1)
      &&  msg_length_remaining >= 2) {

    wkc_len = tvb_get_ntohs(tvb, tvb_reported_length(tvb) - 2);
    data_len = msg_length_remaining - wkc_len;
  }

  if (openvpn_opcode != P_CONTROL_V1) {
    proto_tree *data_tree;
    data_tree = proto_tree_add_subtree_format(openvpn_tree, tvb, offset, data_len,
                              ett_openvpn_data, NULL, "Data (%d bytes)",
                              data_len);

    proto_tree_add_item(data_tree, hf_openvpn_data, tvb, offset, data_len, ENC_NA);

    if (wkc_len > 0)
    {
      proto_tree *wkc_tree;
      wkc_offset = tvb_reported_length(tvb) - wkc_len;

      wkc_tree = proto_tree_add_subtree_format(openvpn_tree, tvb, offset, data_len,
						ett_openvpn_wkc, NULL, "Wrapped client key (%d bytes)",
						tvb_captured_length_remaining(tvb, wkc_offset));

      proto_tree_add_item(wkc_tree, hf_openvpn_wkc_data, tvb, wkc_offset, wkc_len, ENC_NA);
      proto_tree_add_item(wkc_tree, hf_openvpn_wkc_length, tvb,  tvb_reported_length(tvb) - 2, 2, ENC_BIG_ENDIAN);
    }

    return tvb_captured_length(tvb);
  }

  /* Control message, possibly fragmented, carrying TLS. Try to reassemble. */

  streaming_reassembly_info_t *streaming_reassembly_info = NULL;

  conversation_t *conv = find_or_create_conversation_by_id(pinfo, CONVERSATION_OPENVPN, msg_sessionid);
  streaming_reassembly_info = conversation_get_proto_data(conv, proto_openvpn);
  if (!streaming_reassembly_info) {
    streaming_reassembly_info = streaming_reassembly_info_new();
    conversation_add_proto_data(conv, proto_openvpn, streaming_reassembly_info);
  }

  reassemble_streaming_data_and_call_subdissector(tvb, pinfo, offset,
    msg_length_remaining, openvpn_tree, parent_tree, msg_reassembly_table,
    streaming_reassembly_info, get_virtual_frame_num64(tvb, pinfo, offset),
    tls_handle, parent_tree, NULL /* should it be tcpinfo if we have it? */, "OpenVPN Message",
    &openvpn_frag_items, hf_openvpn_fragment_bytes);

  return tvb_captured_length(tvb);
}

static unsigned
get_msg_length(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  return (unsigned)tvb_get_ntohs(tvb, offset) + 2; /* length field is at offset 0,
                                                   +2 to account for the length field itself */
}

static int
dissect_openvpn_msg_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item    *ti;
    proto_tree    *openvpn_tree;

    ti = proto_tree_add_item(tree, proto_openvpn, tvb, 0, -1, ENC_NA);
    openvpn_tree = proto_item_add_subtree(ti, ett_openvpn);

    proto_tree_add_item(openvpn_tree, hf_openvpn_plen, tvb, 0, 2, ENC_BIG_ENDIAN);

    return dissect_openvpn_msg_common(tvb, pinfo, openvpn_tree, tree, 2);
}

static int
dissect_openvpn_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    tcp_dissect_pdus( tvb, pinfo, tree,
      true,           /* should data be reassembled? */
      2,              /* how much bytes do we need for get_msg_length to be successful,
                         since the length is the first thing in an openvpn packet we choose 2 */
      get_msg_length, /* fptr for function to get the packetlength of current frame */
      dissect_openvpn_msg_tcp, data);
    return tvb_captured_length(tvb);
}

static int
dissect_openvpn_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item    *ti;
    proto_tree    *openvpn_tree;

    ti = proto_tree_add_item(tree, proto_openvpn, tvb, 0, -1, ENC_NA);
    openvpn_tree = proto_item_add_subtree(ti, ett_openvpn);

    return dissect_openvpn_msg_common(tvb, pinfo, openvpn_tree, tree, 0);
}

void
proto_register_openvpn(void)
{
  static hf_register_info hf[] = {
    { &hf_openvpn_plen,
      { "Packet Length", "openvpn.plen",
      FT_UINT16, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_pdu_type,
      { "Type", "openvpn.type",
      FT_UINT8, BASE_HEX,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_opcode,
      { "Opcode", "openvpn.opcode",
      FT_UINT8, BASE_HEX,
      VALS(openvpn_message_types), P_OPCODE_MASK,
      NULL, HFILL }
    },
    { &hf_openvpn_keyid,
      { "Key ID", "openvpn.keyid",
      FT_UINT8, BASE_DEC,
      NULL, P_KEY_ID_MASK,
      NULL, HFILL }
    },
    { &hf_openvpn_peerid,
      { "Peer ID", "openvpn.peerid",
      FT_UINT24, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_sessionid,
      { "Session ID", "openvpn.sessionid",
      FT_UINT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_hmac,
      { "HMAC", "openvpn.hmac",
      FT_BYTES, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_pid,
      { "Replay-Packet-ID", "openvpn.pid",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_net_time,
      { "Net Time", "openvpn.net_time",
      FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_rsessionid,
      { "Remote Session ID", "openvpn.rsessionid",
      FT_UINT64, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_mpid,
      { "Message Packet-ID", "openvpn.mpid",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_mpid_arraylength,
      { "Message Packet-ID Array Length", "openvpn.mpidarraylength",
      FT_UINT8, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_mpid_arrayelement,
      { "Message Packet-ID Array Element", "openvpn.mpidarrayelement",
      FT_UINT32, BASE_DEC,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_data,
      { "Data", "openvpn.data",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_openvpn_wkc_data,
      { "Wrapped client key", "openvpn.wkc",
        FT_BYTES, BASE_NONE,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_openvpn_wkc_length,
      { "Wrapped client key length", "openvpn.wkc_len",
        FT_UINT16, BASE_DEC,
        NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_openvpn_fragment_bytes,
      { "Fragment bytes", "openvpn.fragment_bytes",
      FT_BYTES, BASE_NONE,
      NULL, 0x0,
      NULL, HFILL }
    },
    { &hf_openvpn_fragments,
      { "Message fragments", "openvpn.fragments",
      FT_NONE, BASE_NONE,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_fragment,
      { "Message fragment", "openvpn.fragment",
      FT_FRAMENUM, BASE_NONE,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_fragment_overlap,
      { "Message fragment overlap", "openvpn.fragment.overlap",
      FT_BOOLEAN, BASE_NONE,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_fragment_overlap_conflicts,
      { "Message fragment overlapping with conflicting data", "openvpn.fragment.overlap.conflicts",
      FT_BOOLEAN, BASE_NONE,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_fragment_multiple_tails,
      { "Message has multiple tail fragments", "openvpn.fragment.multiple_tails",
      FT_BOOLEAN, BASE_NONE,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_fragment_too_long_fragment,
      { "Message fragment too long", "openvpn.fragment.too_long_fragment",
      FT_BOOLEAN, BASE_NONE,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_fragment_error,
      { "Message defragmentation error", "openvpn.fragment.error",
      FT_FRAMENUM, BASE_NONE,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_fragment_count,
      { "Message fragment count", "openvpn.fragment.count",
      FT_UINT32, BASE_DEC,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_reassembled_in,
      { "Reassembled message in frame", "openvpn.reassembled.in",
      FT_FRAMENUM, BASE_NONE,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_reassembled_length,
      {"Reassembled message length", "openvpn.reassembled.length",
      FT_UINT32, BASE_DEC,
      NULL, 0x00,
      NULL, HFILL }
    }
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_openvpn,
    &ett_openvpn_type,
    &ett_openvpn_data,
    &ett_openvpn_wkc,
    &ett_openvpn_packetarray,
    &ett_openvpn_fragment,
    &ett_openvpn_fragments
  };
  module_t *openvpn_module;

  proto_openvpn = proto_register_protocol (
    PNAME,   /* name       */
    PSNAME,  /* short name */
    PFNAME   /* abbrev     */
    );

  proto_register_field_array(proto_openvpn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  openvpn_udp_handle = register_dissector("openvpn.udp", dissect_openvpn_udp, proto_openvpn);
  openvpn_tcp_handle = register_dissector("openvpn.tcp", dissect_openvpn_tcp, proto_openvpn);

  reassembly_table_register(&msg_reassembly_table,
                        &addresses_reassembly_table_functions);

  openvpn_module = prefs_register_protocol(proto_openvpn, NULL);

  prefs_register_bool_preference(openvpn_module,
                "tls_auth_detection_override",
                "override tls-auth detection",
                "If tls-auth detection fails, you can choose to override detection and set tls-auth yourself",
                &pref_tls_auth_override);

  prefs_register_bool_preference(openvpn_module,
                "tls_crypt",
                "assume tls-crypt",
                "Assume the connection uses tls-crypt",
                &pref_tls_crypt_override);
  prefs_register_bool_preference(openvpn_module,
                "tls_auth",
                "--tls-auth used?",
                "If the parameter --tls-auth is used, the following preferences must also be defined.",
                &pref_tls_auth);
  prefs_register_uint_preference(openvpn_module,
                "tls_auth_hmac_size",
                "size of the HMAC header in bytes",
                "If the parameter --tls-auth is used, a HMAC header is being inserted.\n"
                "The default HMAC algorithm is SHA-1 which generates a 160 bit HMAC,"
                " therefore 20 bytes should be ok.\n"
                "The value must be between 20 (160 bits) and 64 (512 bits).",
                10, &tls_auth_hmac_size);

  prefs_register_bool_preference(openvpn_module,
                "long_format",
                "packet-id for replay protection includes optional time_t timestamp?",
                "If the parameter --tls-auth is used, an additional packet-id for replay protection"
                " is inserted after the HMAC signature."
                " This field can either be 4 bytes or 8 bytes including an optional time_t timestamp long.\n"
                " This option is only evaluated if tls_auth_hmac_size > 0.\n"
                " The default value is true.",
                &pref_long_format);
}

void
proto_reg_handoff_openvpn(void)
{
  tls_handle     = find_dissector_add_dependency("tls", proto_openvpn);
  dissector_add_uint_with_preference("tcp.port", OPENVPN_PORT, openvpn_tcp_handle);
  dissector_add_uint_with_preference("udp.port", OPENVPN_PORT, openvpn_udp_handle);
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
 * :indentSize=2:tabSize=8:noTabs=true
 */
