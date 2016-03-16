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
#include <epan/prefs.h>
#include <epan/reassemble.h>
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

static gint ett_openvpn = -1;
static gint ett_openvpn_data = -1;
static gint ett_openvpn_packetarray = -1;
static gint ett_openvpn_type = -1;
static gint hf_openvpn_data = -1;
static gint hf_openvpn_fragment_bytes = -1;
static gint hf_openvpn_hmac = -1;
static gint hf_openvpn_keyid = -1;
static gint hf_openvpn_mpid = -1;
static gint hf_openvpn_mpid_arrayelement = -1;
static gint hf_openvpn_mpid_arraylength = -1;
static gint hf_openvpn_net_time = -1;
static gint hf_openvpn_opcode = -1;
static gint hf_openvpn_pdu_type = -1;
static gint hf_openvpn_pid = -1;
static gint hf_openvpn_plen = -1;
static gint hf_openvpn_rsessionid = -1;
static gint hf_openvpn_sessionid = -1;
static gint hf_openvpn_peerid = -1;
static gint proto_openvpn = -1;

static dissector_handle_t openvpn_udp_handle;
static dissector_handle_t openvpn_tcp_handle;

static dissector_handle_t ssl_handle;

/* Preferences */
static gboolean pref_long_format       = TRUE;
static gboolean pref_tls_auth          = FALSE;
static gboolean pref_tls_auth_override = FALSE;
static guint    pref_tcp_port          = OPENVPN_PORT;
static guint    pref_udp_port          = OPENVPN_PORT;
static guint    tls_auth_hmac_size     = 20; /* Default SHA-1 160 Bits */

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
  {   0, NULL }
};

/* everything used during the reassembly process */
static reassembly_table msg_reassembly_table;

static gint ett_openvpn_fragment = -1;
static gint ett_openvpn_fragments = -1;
static gint hf_openvpn_fragment = -1;
static gint hf_openvpn_fragment_count = -1;
static gint hf_openvpn_fragment_error = -1;
static gint hf_openvpn_fragment_multiple_tails = -1;
static gint hf_openvpn_fragment_overlap = -1;
static gint hf_openvpn_fragment_overlap_conflicts = -1;
static gint hf_openvpn_fragment_too_long_fragment = -1;
static gint hf_openvpn_fragments = -1;
static gint hf_openvpn_reassembled_in = -1;
static gint hf_openvpn_reassembled_length = -1;

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

static void
openvpn_reassemble_init(void)
{
  reassembly_table_init(&msg_reassembly_table,
                        &addresses_reassembly_table_functions);
}

static void
openvpn_reassemble_cleanup(void)
{
  reassembly_table_destroy(&msg_reassembly_table);
}

/* we check the leading 4 byte of a suspected hmac for 0x00 bytes,
   if more than 1 byte out of the 4 provided contains 0x00, the
   hmac is considered not valid, which suggests that no tls auth is used.
   unfortunatly there is no other way to detect tls auth on the fly */
static gboolean
check_for_valid_hmac(guint32 hmac)
{
  gint c = 0;
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
    return FALSE;
  } else {
    return TRUE;
  }
}

static int
dissect_openvpn_msg_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *openvpn_tree, proto_tree *parent_tree, gint offset)
{
  gboolean       tls_auth;
  guint          openvpn_keyid;
  guint          openvpn_opcode;
  guint32        msg_mpid      = -1;
  guint32        msg_sessionid = -1;
  guint8         openvpn_predict_tlsauth_arraylength;
  proto_item    *ti2;
  proto_tree    *packetarray_tree, *type_tree;
  guint32        msg_length_remaining;
  gboolean       msg_lastframe;
  fragment_head *frag_msg;
  tvbuff_t      *new_tvb;
  gboolean       save_fragmented;

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
    openvpn_predict_tlsauth_arraylength = tvb_get_guint8(tvb, offset);
    /* if the first 4 bytes that would, if tls-auth is used, contain part of the hmac,
       lack entropy, we asume no tls-auth is used */
    if (pref_tls_auth_override == FALSE) {
      if ((openvpn_opcode != P_DATA_V1)
          && (openvpn_predict_tlsauth_arraylength > 0)
          && check_for_valid_hmac(tvb_get_ntohl(tvb, offset))) {
        tls_auth = TRUE;
      } else {
        tls_auth = FALSE;
      }
    } else {
      tls_auth = pref_tls_auth;
    }

    if (tls_auth == TRUE) {
      proto_tree_add_item(openvpn_tree, hf_openvpn_hmac, tvb, offset, tls_auth_hmac_size, ENC_NA);
      offset += tls_auth_hmac_size;

      if (tvb_reported_length_remaining(tvb, offset) >= 8) {
        proto_tree_add_item(openvpn_tree, hf_openvpn_pid, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        if (pref_long_format) {
          proto_tree_add_item(openvpn_tree, hf_openvpn_net_time, tvb, offset, 4, ENC_BIG_ENDIAN);
          offset += 4;
        }
      }
    }

    if (tvb_reported_length_remaining(tvb, offset) >= 1) {
      /* read P_ACK packet-id array length */
      gint pid_arraylength = tvb_get_guint8(tvb, offset);
      gint i;
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
    if (openvpn_opcode != P_ACK_V1) {
      /* read Message Packet-ID */
      if (tvb_reported_length_remaining(tvb, offset) >= 4) {
        msg_mpid = tvb_get_bits32(tvb, offset*8, 32, ENC_BIG_ENDIAN);
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

  if (openvpn_opcode != P_CONTROL_V1) {
    proto_tree *data_tree;
    data_tree = proto_tree_add_subtree_format(openvpn_tree, tvb, offset, -1,
                              ett_openvpn_data, NULL, "Data (%d bytes)",
                              tvb_captured_length_remaining(tvb, offset));

    proto_tree_add_item(data_tree, hf_openvpn_data, tvb, offset, -1, ENC_NA);
    return tvb_captured_length(tvb);
  }

  /* Try to reassemble */

  /* an ordinary openvpn control packet contains 100 bytes only if it is part of a
     fragmented message and is not the last fragment of the current transmission.
     Note that the tvb contains exactly one openvpn PDU:
     UDP: by definition;
     TCP: because of the use of tcp_dissect_pdus().
  */
  if (msg_length_remaining == 100) {
    msg_lastframe = FALSE;
  } else {
    msg_lastframe = TRUE;
  }

  save_fragmented = pinfo->fragmented;
  pinfo->fragmented = TRUE;

  frag_msg = fragment_add_seq_next(
    &msg_reassembly_table,
    tvb,
    offset,
    pinfo,
    msg_sessionid,         /* ID for fragments belonging together */
    NULL,
    msg_length_remaining,  /* fragment length - to the end        */
    !(msg_lastframe));     /* More fragments ?                    */

  /* show "data" fragment on tree unless "reassembled" message has just one part.       */
  /* i.e., show if ("not reassembled") or ("reassembled" and "has multiple fragments")  */
  if ((frag_msg == NULL) || (frag_msg->next != NULL)) {
    proto_tree *data_tree;
    data_tree = proto_tree_add_subtree_format(openvpn_tree, tvb, offset, -1,
                              ett_openvpn_data, NULL, "Message fragment (%d bytes)",
                              tvb_captured_length_remaining(tvb, offset));

    proto_tree_add_item(data_tree, hf_openvpn_fragment_bytes, tvb, offset, -1, ENC_NA);
    }

  new_tvb = NULL;
  if (frag_msg) {
    if (msg_lastframe) { /* Reassembled */
      new_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Message",
                                         frag_msg, &openvpn_frag_items, NULL, openvpn_tree);
      if (frag_msg->next != NULL) { /* multiple frags ? */
        col_append_str(pinfo->cinfo, COL_INFO, " (Message Reassembled "); /* overwritten by next dissector */
      }

    } else { /* Not last packet of reassembled Short Message */
      col_append_fstr(pinfo->cinfo, COL_INFO, " (Message fragment %d) ", msg_mpid);
      if (pinfo->num != frag_msg->reassembled_in) {
        /* Add a "Reassembled in" link if not reassembled in this frame */
        proto_tree_add_uint(openvpn_tree, hf_openvpn_reassembled_in,
                            tvb, 0, 0, frag_msg->reassembled_in);
      }
    }
  } /* if (frag_msg) */

  pinfo->fragmented = save_fragmented;

  /* Now see if we need to call subdissector.
     new_tvb is non-null if we "reassembled* a message (even just one fragment) */

  if (new_tvb) {
    /* call SSL/TLS dissector if we just processed the last fragment */
    call_dissector(ssl_handle, new_tvb, pinfo, parent_tree);
  }

  return tvb_captured_length(tvb);
}

static guint
get_msg_length(packet_info *pinfo _U_, tvbuff_t *tvb, gint offset, void *data _U_)
{
  return (guint)tvb_get_ntohs(tvb, offset) + 2; /* length field is at offset 0,
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
      TRUE,           /* should data be reassembled? */
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
      { "Packet-ID", "openvpn.pid",
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
      FT_BOOLEAN, 0,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_fragment_overlap_conflicts,
      { "Message fragment overlapping with conflicting data", "openvpn.fragment.overlap.conflicts",
      FT_BOOLEAN, 0,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_fragment_multiple_tails,
      { "Message has multiple tail fragments", "openvpn.fragment.multiple_tails",
      FT_BOOLEAN, 0,
      NULL, 0x00,
      NULL, HFILL }
    },
    { &hf_openvpn_fragment_too_long_fragment,
      { "Message fragment too long", "openvpn.fragment.too_long_fragment",
      FT_BOOLEAN, 0,
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
  static gint *ett[] = {
    &ett_openvpn,
    &ett_openvpn_type,
    &ett_openvpn_data,
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

  register_init_routine(&openvpn_reassemble_init);
  register_cleanup_routine(&openvpn_reassemble_cleanup);

  openvpn_module = prefs_register_protocol(proto_openvpn, proto_reg_handoff_openvpn);

  prefs_register_uint_preference(openvpn_module,
                "tcp.port",
                "OpenVPN TCP Port",
                "TCP Port of the OpenVPN tunnel",
                10, &pref_tcp_port);
  prefs_register_uint_preference(openvpn_module,
                "udp.port",
                "OpenVPN UDP Port",
                "UDP Port of the OpenVPN tunnel",
                10, &pref_udp_port);
  prefs_register_bool_preference(openvpn_module,
                "tls_auth_detection_override",
                "override tls-auth detection",
                "If tls-auth detection fails, you can choose to override detection and set tls-auth yourself",
                &pref_tls_auth_override);
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
                " The default value is TRUE.",
                &pref_long_format);
}

void
proto_reg_handoff_openvpn(void)
{
  static guint    tcp_port;
  static guint    udp_port;
  static gboolean initialized = FALSE;

  if (! initialized) {
    ssl_handle     = find_dissector_add_dependency("ssl", proto_openvpn);
    initialized    = TRUE;
  } else {
    if (tcp_port > 0)
      dissector_delete_uint("tcp.port", tcp_port, openvpn_tcp_handle);
    if (udp_port > 0)
      dissector_delete_uint("udp.port", udp_port, openvpn_udp_handle);
  }

  tcp_port = pref_tcp_port;
  udp_port = pref_udp_port;

  if (tcp_port > 0)
    dissector_add_uint("tcp.port", tcp_port, openvpn_tcp_handle);
  if (udp_port > 0)
    dissector_add_uint("udp.port", udp_port, openvpn_udp_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
