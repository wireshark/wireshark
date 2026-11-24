/* packet-nanoprobe.c
 * Routines for the Nanoprobe protocol
 * https://github.com/simosund/nanoprobe
 *
 * Copyright 2026 by Thomas Dreibholz <dreibh [AT] simula.no>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#define NANOPROBE_DEFAULT_PORT      10666
#define NANOPROBE_HEADER_LEN        16
#define NANOPROBE_CLIENT_OPTS_LEN   28
#define NANOPROBE_SYN_LEN           (NANOPROBE_HEADER_LEN + NANOPROBE_CLIENT_OPTS_LEN)

#define NANOPROBE_MSG_SYN           1
#define NANOPROBE_MSG_SYN_ACK       2
#define NANOPROBE_MSG_SYN_RST       3
#define NANOPROBE_MSG_PING          5
#define NANOPROBE_MSG_PONG          6
#define NANOPROBE_MSG_FIN           7
#define NANOPROBE_MSG_FIN_ACK       8

void proto_register_nanoprobe(void);
void proto_reg_handoff_nanoprobe(void);

/* Initialize the protocol and registered fields */
static int proto_nanoprobe;
static dissector_handle_t nanoprobe_handle;

/* Initialize the subtree pointers */
static int ett_nanoprobe;
static int ett_nanoprobe_client_opts;

static int hf_nanoprobe_seq;
static int hf_nanoprobe_type;
static int hf_nanoprobe_reserved;

static int hf_nanoprobe_opts_count;
static int hf_nanoprobe_opts_delay;
static int hf_nanoprobe_opts_ping_pad;
static int hf_nanoprobe_opts_pong_pad;
static int hf_nanoprobe_opts_pong_every;
static int hf_nanoprobe_opts_timer;
static int hf_nanoprobe_opts_direction;
static int hf_nanoprobe_opts_compensate_drift;
static int hf_nanoprobe_opts_padding;

static int hf_nanoprobe_payload;


/* Nanoprobe message types */
static const value_string nanoprobe_msg_type_vals[] = {
  { NANOPROBE_MSG_SYN,     "SYN" },
  { NANOPROBE_MSG_SYN_ACK, "SYN-ACK" },
  { NANOPROBE_MSG_SYN_RST, "SYN-RST" },
  { NANOPROBE_MSG_PING,    "PING" },
  { NANOPROBE_MSG_PONG,    "PONG" },
  { NANOPROBE_MSG_FIN,     "FIN" },
  { NANOPROBE_MSG_FIN_ACK, "FIN-ACK" },
  { 0,                     NULL }
};

/* Nanoprobe timer types */
static const value_string nanoprobe_timer_type_vals[] = {
  { 0, "sleep" },
  { 1, "busy" },
  { 0, NULL }
};

/* Nanoprobe directions */
static const value_string nanoprobe_direction_vals[] = {
  { 0, "forward" },
  { 1, "reverse" },
  { 2, "duplex" },
  { 0, NULL }
};


static int
dissect_nanoprobe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *nanoprobe_item;
  proto_tree *nanoprobe_tree;

  const unsigned length = tvb_captured_length(tvb);
  if (length < NANOPROBE_HEADER_LEN)
    return 0;

  const uint8_t type = tvb_get_uint8(tvb, 8);
  const char *type_str = try_val_to_str(type, nanoprobe_msg_type_vals);
  if (!type_str)
    return 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Nanoprobe");

  // Create the Nanoprobe protocol tree
  nanoprobe_item = proto_tree_add_item(tree, proto_nanoprobe, tvb, 0, -1, ENC_NA);
  nanoprobe_tree = proto_item_add_subtree(nanoprobe_item, ett_nanoprobe);

  const uint64_t seq = tvb_get_letoh64(tvb, 0);

  // Common 16-byte header (struct nanoping_msg)
  proto_tree_add_item(nanoprobe_tree, hf_nanoprobe_seq,      tvb, 0, 8, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(nanoprobe_tree, hf_nanoprobe_type,     tvb, 8, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(nanoprobe_tree, hf_nanoprobe_reserved, tvb, 9, 7, ENC_NA);

  switch (type) {
    case NANOPROBE_MSG_SYN:
      if (length >= NANOPROBE_SYN_LEN) {
        const uint32_t count     = tvb_get_letohl(tvb, 16);
        const uint32_t delay     = tvb_get_letohl(tvb, 20);
        const uint32_t direction = tvb_get_letohl(tvb, 36);

        col_append_fstr(pinfo->cinfo, COL_INFO, " %s (Direction=%s, Count=%u, Delay=%u)",
                        type_str,
                        val_to_str_const(direction, nanoprobe_direction_vals, "Unknown"),
                        count, delay);

        proto_tree *opts_tree = proto_tree_add_subtree(nanoprobe_tree, tvb, 16, NANOPROBE_CLIENT_OPTS_LEN,
                                                       ett_nanoprobe_client_opts, NULL, "Client Options");
        proto_tree_add_item(opts_tree, hf_nanoprobe_opts_count,            tvb, 16, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(opts_tree, hf_nanoprobe_opts_delay,            tvb, 20, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(opts_tree, hf_nanoprobe_opts_ping_pad,         tvb, 24, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(opts_tree, hf_nanoprobe_opts_pong_pad,         tvb, 26, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(opts_tree, hf_nanoprobe_opts_pong_every,       tvb, 28, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(opts_tree, hf_nanoprobe_opts_timer,            tvb, 32, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(opts_tree, hf_nanoprobe_opts_direction,        tvb, 36, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(opts_tree, hf_nanoprobe_opts_compensate_drift, tvb, 40, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(opts_tree, hf_nanoprobe_opts_padding,          tvb, 41, 3, ENC_NA);
      } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, " %s (Truncated)", type_str);
      }
      break;

    case NANOPROBE_MSG_PING:
    case NANOPROBE_MSG_PONG:
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s (Seq=%" PRIu64 ", PayloadLen=%u)",
                      type_str, seq, length - NANOPROBE_HEADER_LEN);
      if (length > NANOPROBE_HEADER_LEN) {
        proto_tree_add_item(nanoprobe_tree, hf_nanoprobe_payload, tvb, NANOPROBE_HEADER_LEN,
                            length - NANOPROBE_HEADER_LEN, ENC_NA);
      }
      break;

    case NANOPROBE_MSG_FIN:
    case NANOPROBE_MSG_FIN_ACK:
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s (Seq=%" PRIu64 ")", type_str, seq);
      break;

    case NANOPROBE_MSG_SYN_ACK:
    case NANOPROBE_MSG_SYN_RST:
    default:
      col_append_fstr(pinfo->cinfo, COL_INFO, " %s", type_str);
      break;
  }

  return tvb_reported_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_nanoprobe(void)
{
  /* Setup list of header fields */
  static hf_register_info hf[] = {
    { &hf_nanoprobe_seq,                   { "Sequence Number",  "nanoprobe.seq",                   FT_UINT64,  BASE_DEC, NULL,                            0x0, "Packet sequence number",                            HFILL } },
    { &hf_nanoprobe_type,                  { "Type",             "nanoprobe.type",                  FT_UINT8,   BASE_DEC, VALS(nanoprobe_msg_type_vals),   0x0, "Nanoprobe message type",                            HFILL } },
    { &hf_nanoprobe_reserved,              { "Reserved",         "nanoprobe.reserved",              FT_BYTES,   BASE_NONE, NULL,                           0x0, "Reserved padding bytes",                            HFILL } },
    { &hf_nanoprobe_opts_count,            { "Count",            "nanoprobe.opts.count",            FT_UINT32,  BASE_DEC, NULL,                            0x0, "Test duration in seconds",                          HFILL } },
    { &hf_nanoprobe_opts_delay,            { "Delay",            "nanoprobe.opts.delay",            FT_UINT32,  BASE_DEC, NULL,                            0x0, "Inter-packet delay in microseconds",                HFILL } },
    { &hf_nanoprobe_opts_ping_pad,         { "Ping Padding",     "nanoprobe.opts.ping_pad",         FT_UINT16,  BASE_DEC, NULL,                            0x0, "Padding bytes appended to PING packets",            HFILL } },
    { &hf_nanoprobe_opts_pong_pad,         { "Pong Padding",     "nanoprobe.opts.pong_pad",         FT_UINT16,  BASE_DEC, NULL,                            0x0, "Padding bytes appended to PONG packets",            HFILL } },
    { &hf_nanoprobe_opts_pong_every,       { "Pong Every",       "nanoprobe.opts.pong_every",       FT_UINT32,  BASE_DEC, NULL,                            0x0, "Reply with PONG every N-th PING",                   HFILL } },
    { &hf_nanoprobe_opts_timer,            { "Timer",            "nanoprobe.opts.timer",            FT_UINT32,  BASE_DEC, VALS(nanoprobe_timer_type_vals), 0x0, "Timer mode used by sender",                         HFILL } },
    { &hf_nanoprobe_opts_direction,        { "Direction",        "nanoprobe.opts.direction",        FT_UINT32,  BASE_DEC, VALS(nanoprobe_direction_vals),  0x0, "Probe test direction",                              HFILL } },
    { &hf_nanoprobe_opts_compensate_drift, { "Compensate Drift", "nanoprobe.opts.compensate_drift", FT_BOOLEAN, BASE_NONE, NULL,                           0x0, "Whether sender compensates for scheduling drift",   HFILL } },
    { &hf_nanoprobe_opts_padding,          { "Padding",          "nanoprobe.opts.padding",          FT_BYTES,   BASE_NONE, NULL,                           0x0, "Trailing struct alignment padding",                 HFILL } },
    { &hf_nanoprobe_payload,               { "Payload",          "nanoprobe.payload",               FT_BYTES,   BASE_NONE, NULL,                           0x0, "Probe padding payload",                             HFILL } }
  };

  /* Setup protocol subtree array */
  static int *ett[] = {
    &ett_nanoprobe,
    &ett_nanoprobe_client_opts
  };

  /* Register the protocol name and description */
  proto_nanoprobe = proto_register_protocol("Nanoprobe", "Nanoprobe", "nanoprobe");

  /* Required function calls to register the header fields and subtrees used */
  proto_register_field_array(proto_nanoprobe, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register the dissector */
  nanoprobe_handle = register_dissector("nanoprobe", dissect_nanoprobe, proto_nanoprobe);
}

void
proto_reg_handoff_nanoprobe(void)
{
  /* Nanoprobe default port and "Decode As" */
  dissector_add_uint_with_preference("udp.port", NANOPROBE_DEFAULT_PORT, nanoprobe_handle);
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
