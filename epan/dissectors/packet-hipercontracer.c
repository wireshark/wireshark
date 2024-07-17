/* packet-hipercontracer.c
 * Routines for the HiPerConTracer protocol
 * https://www.uni-due.de/~be0001/hipercontracer/
 *
 * Copyright 2021 by Thomas Dreibholz <dreibh [AT] simula.no>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/sctpppids.h>
#include <epan/stat_tap_ui.h>


void proto_register_hipercontracer(void);
void proto_reg_handoff_hipercontracer(void);

/* Initialize the protocol and registered fields */
static int proto_hipercontracer;

/* Initialize the subtree pointers */
static int ett_hipercontracer;

static int hf_magic_number;
static int hf_send_ttl;
static int hf_round;
static int hf_checksum_tweak;
static int hf_seq_number;
static int hf_send_timestamp;

/* Setup list of header fields */
static hf_register_info hf[] = {
  { &hf_magic_number,   { "Magic Number",    "hipercontracer.magic_number",   FT_UINT32, BASE_HEX, NULL,                 0x0, "An identifier chosen by the sender upon startup",                       HFILL } },
  { &hf_send_ttl,       { "Send TTL",        "hipercontracer.send_ttl",       FT_UINT8,  BASE_DEC, NULL,                 0x0, "The IP TTL/IPv6 Hop Count used by the sender",                          HFILL } },
  { &hf_round,          { "Round",           "hipercontracer.round",          FT_UINT8,  BASE_DEC, NULL,                 0x0, "The round number the packet belongs to",                                HFILL } },
  { &hf_checksum_tweak, { "Checksum Tweak",  "hipercontracer.checksum_tweak", FT_UINT16, BASE_HEX, NULL,                 0x0, "A 16-bit value to ensure a given checksum for the ICMP/ICMPv6 message", HFILL } },
  { &hf_seq_number,     { "Sequence Number", "hipercontracer.seq_number",     FT_UINT16, BASE_DEC, NULL,                 0x0, "A 16-bit sequence number",                                              HFILL } },
  { &hf_send_timestamp, { "Send Time Stamp", "hipercontracer.send_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0, "The send time stamp (microseconds since September 29, 1976, 00:00:00)", HFILL } }
};


static int
heur_dissect_hipercontracer(tvbuff_t *message_tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item* hipercontracer_item;
  proto_tree* hipercontracer_tree;
  uint64_t    timestamp;
  nstime_t    t;

  // Check length
  const unsigned length = tvb_captured_length(message_tvb);
  if (length < 16)
    return false;

  const uint32_t magic = tvb_get_ntohl(message_tvb, 0);

  // Send TTL cannot be < 1
  const uint8_t sendTTL = tvb_get_uint8(message_tvb, 4);
  if (sendTTL < 1)
    return false;

  const uint8_t round = tvb_get_uint8(message_tvb, 5);

  const uint16_t checksumTweak = tvb_get_ntohs(message_tvb, 6);

  uint64_t sendTimeStamp = tvb_get_ntoh64(message_tvb, 8);

  /*
   * Don't dissect a SASL ldap message, which starts with the
   * first 12 bytes like this:
   *
   * Length: 00000091 (very, very unlikely larger than 24bits).
   * Magic:  0504 (KRB_TOKEN_CFX_WRAP)
   * Flags:  04  (0x01, 0x02, 0x04 are defined)
   * Filler: ff
   * EC:     000c
   * RRC:    0000 or 000c
   */
  if ((magic & 0xff000000) == 0 &&
      (magic & 0x00ffffff) != 0 &&
      sendTTL == 0x05 &&
      round == 0x04 &&
      (checksumTweak & 0xf8ff) == 0x00ff &&
      (sendTimeStamp & UINT64_C(0xff00ff0000000000)) == 0)
    return false;

  // Check for plausible send time stamp:
  // * After:  01.01.2016 00:00:00.000000
  // * Before: 31.12.2099 23:59.59.999999
  // Time stamp is microseconds since 29.09.1976 00:00:00.000000.
  sendTimeStamp += UINT64_C(212803200000000);
  if ( (sendTimeStamp < UINT64_C(1451602800000000)) ||
       (sendTimeStamp > UINT64_C(4102441199999999)) )
    return false;

  col_append_sep_fstr(pinfo->cinfo, COL_PROTOCOL, NULL, "HiPerConTracer");

  // Create the HiPerConTracer protocol tree
  hipercontracer_item = proto_tree_add_item(tree, proto_hipercontracer, message_tvb, 0, -1, ENC_NA);
  hipercontracer_tree = proto_item_add_subtree(hipercontracer_item, ett_hipercontracer);

  // Dissect the message
  proto_tree_add_item(hipercontracer_tree, hf_magic_number,   message_tvb, 0, 4, ENC_BIG_ENDIAN);
  proto_tree_add_item(hipercontracer_tree, hf_send_ttl,       message_tvb, 4, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(hipercontracer_tree, hf_round,          message_tvb, 5, 1, ENC_BIG_ENDIAN);
  if (pinfo->ptype == PT_NONE) {
     // ICMP or ICMPv6 do not have ports -> Checksum Tweak field
     proto_tree_add_item(hipercontracer_tree, hf_checksum_tweak, message_tvb, 6, 2, ENC_BIG_ENDIAN);
  }
  else {
     // Otherwise, there are ports -> Sequence Number field
     proto_tree_add_item(hipercontracer_tree, hf_seq_number, message_tvb, 6, 2, ENC_BIG_ENDIAN);
  }

  // Time stamp is microseconds since 29.09.1976 00:00:00.000000.
  timestamp = tvb_get_ntoh64(message_tvb, 8) + UINT64_C(212803200000000);
  t.secs  = (time_t)(timestamp / 1000000);
  t.nsecs = (int)((timestamp - 1000000 * t.secs) * 1000);
  proto_tree_add_time(hipercontracer_tree, hf_send_timestamp, message_tvb, 8, 8, &t);

  col_append_fstr(pinfo->cinfo, COL_INFO, " (SendTTL=%u, Round=%u)",
                  (unsigned int)tvb_get_uint8(message_tvb, 4),
                  (unsigned int)tvb_get_uint8(message_tvb, 5));

  return tvb_reported_length(message_tvb);
}

static bool
heur_dissect_hipercontracer_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    return heur_dissect_hipercontracer(tvb, pinfo, tree, data) > 0;
}

/* Register the protocol with Wireshark */
void
proto_register_hipercontracer(void)
{
  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_hipercontracer
  };

  /* Register the protocol name and description */
  proto_hipercontracer = proto_register_protocol("HiPerConTracer Trace Service", "HiPerConTracer", "hipercontracer");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_hipercontracer, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("hipercontracer", heur_dissect_hipercontracer, proto_hipercontracer);
}

void
proto_reg_handoff_hipercontracer(void)
{
  /* Heuristic dissector for ICMP/ICMPv6 */
  heur_dissector_add("icmp",   heur_dissect_hipercontracer_heur, "HiPerConTracer over ICMP",   "hipercontracer_icmp",   proto_hipercontracer, HEURISTIC_ENABLE);
  heur_dissector_add("icmpv6", heur_dissect_hipercontracer_heur, "HiPerConTracer over ICMPv6", "hipercontracer_icmpv6", proto_hipercontracer, HEURISTIC_ENABLE);
  heur_dissector_add("udp",    heur_dissect_hipercontracer_heur, "HiPerConTracer over UDP",    "hipercontracer_udp",    proto_hipercontracer, HEURISTIC_ENABLE);
  heur_dissector_add("tcp",    heur_dissect_hipercontracer_heur, "HiPerConTracer over TCP",    "hipercontracer_tcp",    proto_hipercontracer, HEURISTIC_ENABLE);
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
