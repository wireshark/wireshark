/* packet-bblog.c
 * Routines for Black Box Log dissection
 * Copyright 2021 Michael Tuexen <tuexen [AT] wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include "packet-bblog.h"

void proto_register_bblog(void);
void proto_reg_handoff_bblog(void);

static int proto_bblog                      = -1;

static int hf_ticks                         = -1;
static int hf_serial_nr                     = -1;
static int hf_stack_id                      = -1;
static int hf_event_id                      = -1;
static int hf_event_flags                   = -1;
static int hf_event_flags_rxbuf             = -1;
static int hf_event_flags_txbuf             = -1;
static int hf_event_flags_hdr               = -1;
static int hf_event_flags_verbose           = -1;
static int hf_event_flags_stack             = -1;
static int hf_errno                         = -1;
static int hf_rxb_acc                       = -1;
static int hf_rxb_ccc                       = -1;
static int hf_rxb_spare                     = -1;
static int hf_txb_acc                       = -1;
static int hf_txb_ccc                       = -1;
static int hf_txb_spare                     = -1;
static int hf_state                         = -1;
static int hf_starttime                     = -1;
static int hf_iss                           = -1;
static int hf_t_flags                       = -1;
static int hf_t_flags_ack_now               = -1;
static int hf_t_flags_delayed_ack           = -1;
static int hf_t_flags_no_delay              = -1;
static int hf_t_flags_no_opt                = -1;
static int hf_t_flags_sent_fin              = -1;
static int hf_t_flags_request_window_scale  = -1;
static int hf_t_flags_received_window_scale = -1;
static int hf_t_flags_request_timestamp     = -1;
static int hf_t_flags_received_timestamp    = -1;
static int hf_t_flags_sack_permitted        = -1;
static int hf_t_flags_need_syn              = -1;
static int hf_t_flags_need_fin              = -1;
static int hf_t_flags_no_push               = -1;
static int hf_t_flags_prev_valid            = -1;
static int hf_t_flags_wake_socket_receive   = -1;
static int hf_t_flags_goodput_in_progress   = -1;
static int hf_t_flags_more_to_come          = -1;
static int hf_t_flags_listen_queue_overflow = -1;
static int hf_t_flags_last_idle             = -1;
static int hf_t_flags_zero_recv_window_sent = -1;
static int hf_t_flags_be_in_fast_recovery   = -1;
static int hf_t_flags_was_in_fast_recovery  = -1;
static int hf_t_flags_signature             = -1;
static int hf_t_flags_force_data            = -1;
static int hf_t_flags_tso                   = -1;
static int hf_t_flags_toe                   = -1;
static int hf_t_flags_unused_0              = -1;
static int hf_t_flags_unused_1              = -1;
static int hf_t_flags_lost_rtx_detection    = -1;
static int hf_t_flags_be_in_cong_recovery   = -1;
static int hf_t_flags_was_in_cong_recovery  = -1;
static int hf_t_flags_fast_open             = -1;
static int hf_snd_una                       = -1;
static int hf_snd_max                       = -1;
static int hf_snd_cwnd                      = -1;
static int hf_snd_nxt                       = -1;
static int hf_snd_recover                   = -1;
static int hf_snd_wnd                       = -1;
static int hf_snd_ssthresh                  = -1;
static int hf_srtt                          = -1;
static int hf_rttvar                        = -1;
static int hf_rcv_up                        = -1;
static int hf_rcv_adv                       = -1;
static int hf_t_flags2                      = -1;
static int hf_t_flags2_plpmtu_blackhole     = -1;
static int hf_t_flags2_plpmtu_pmtud         = -1;
static int hf_t_flags2_plpmtu_maxsegsnt     = -1;
static int hf_t_flags2_log_auto             = -1;
static int hf_t_flags2_drop_after_data      = -1;
static int hf_t_flags2_ecn_permit           = -1;
static int hf_t_flags2_ecn_snd_cwr          = -1;
static int hf_t_flags2_ecn_snd_ece          = -1;
static int hf_t_flags2_ace_permit           = -1;
static int hf_t_flags2_first_bytes_complete = -1;
static int hf_rcv_nxt                       = -1;
static int hf_rcv_wnd                       = -1;
static int hf_dupacks                       = -1;
static int hf_seg_qlen                      = -1;
static int hf_snd_num_holes                 = -1;
static int hf_flex_1                        = -1;
static int hf_flex_2                        = -1;
static int hf_first_byte_in                 = -1;
static int hf_first_byte_out                = -1;
static int hf_snd_scale                     = -1;
static int hf_rcv_scale                     = -1;
static int hf_pad_1                         = -1;
static int hf_pad_2                         = -1;
static int hf_pad_3                         = -1;
static int hf_payload_len                   = -1;

static gint ett_bblog                       = -1;
static gint ett_bblog_flags                 = -1;
static gint ett_bblog_t_flags               = -1;
static gint ett_bblog_t_flags2              = -1;

static int * const bblog_event_flags[] = {
  &hf_event_flags_rxbuf,
  &hf_event_flags_txbuf,
  &hf_event_flags_hdr,
  &hf_event_flags_verbose,
  &hf_event_flags_stack,
  NULL
};

static int * const bblog_t_flags[] = {
  &hf_t_flags_ack_now,
  &hf_t_flags_delayed_ack,
  &hf_t_flags_no_delay,
  &hf_t_flags_no_opt,
  &hf_t_flags_sent_fin,
  &hf_t_flags_request_window_scale,
  &hf_t_flags_received_window_scale,
  &hf_t_flags_request_timestamp,
  &hf_t_flags_received_timestamp,
  &hf_t_flags_sack_permitted,
  &hf_t_flags_need_syn,
  &hf_t_flags_need_fin,
  &hf_t_flags_no_push,
  &hf_t_flags_prev_valid,
  &hf_t_flags_wake_socket_receive,
  &hf_t_flags_goodput_in_progress,
  &hf_t_flags_more_to_come,
  &hf_t_flags_listen_queue_overflow,
  &hf_t_flags_last_idle,
  &hf_t_flags_zero_recv_window_sent,
  &hf_t_flags_be_in_fast_recovery,
  &hf_t_flags_was_in_fast_recovery,
  &hf_t_flags_signature,
  &hf_t_flags_force_data,
  &hf_t_flags_tso,
  &hf_t_flags_toe,
  &hf_t_flags_unused_0,
  &hf_t_flags_unused_1,
  &hf_t_flags_lost_rtx_detection,
  &hf_t_flags_be_in_cong_recovery,
  &hf_t_flags_was_in_cong_recovery,
  &hf_t_flags_fast_open,
  NULL
};

static int * const bblog_t_flags2[] = {
  &hf_t_flags2_plpmtu_blackhole,
  &hf_t_flags2_plpmtu_pmtud,
  &hf_t_flags2_plpmtu_maxsegsnt,
  &hf_t_flags2_log_auto,
  &hf_t_flags2_drop_after_data,
  &hf_t_flags2_ecn_permit,
  &hf_t_flags2_ecn_snd_cwr,
  &hf_t_flags2_ecn_snd_ece,
  &hf_t_flags2_ace_permit,
  &hf_t_flags2_first_bytes_complete,
  NULL
};

/*
 * The structures used here are defined in
 * https://cgit.freebsd.org/src/tree/sys/netinet/tcp_log_buf.h
 */

static int
dissect_bblog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *bblog_item;
    proto_tree *bblog_tree;
    guint16 event_flags;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BBLog");
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str_const(tvb_get_guint8(tvb, 25), event_identifier_values, "Unknown"));

    bblog_item = proto_tree_add_item(tree, proto_bblog, tvb, 0, -1, ENC_NA);
    bblog_tree = proto_item_add_subtree(bblog_item, ett_bblog);

    proto_tree_add_item(bblog_tree, hf_ticks,     tvb, 16, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_serial_nr, tvb, 20, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_stack_id,  tvb, 24, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_event_id,  tvb, 25, 1, ENC_LITTLE_ENDIAN);

    event_flags = tvb_get_letohs(tvb, 26);
    proto_tree_add_bitmask(bblog_tree, tvb, 26, hf_event_flags, ett_bblog_flags, bblog_event_flags, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_errno, tvb, 28, 4, ENC_LITTLE_ENDIAN);
    if (event_flags & BBLOG_EVENT_FLAG_RXBUF) {
        proto_tree_add_item(bblog_tree, hf_rxb_acc,   tvb, 32, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(bblog_tree, hf_rxb_ccc,   tvb, 36, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(bblog_tree, hf_rxb_spare, tvb, 40, 4, ENC_LITTLE_ENDIAN);
    }
    if (event_flags & BBLOG_EVENT_FLAG_TXBUF) {
        proto_tree_add_item(bblog_tree, hf_txb_acc,   tvb, 44, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(bblog_tree, hf_txb_ccc,   tvb, 48, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(bblog_tree, hf_txb_spare, tvb, 52, 4, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item(bblog_tree, hf_state,          tvb,  56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_starttime,      tvb,  60, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_iss,            tvb,  64, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(bblog_tree, tvb, 68, hf_t_flags, ett_bblog_t_flags, bblog_t_flags, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_snd_una,        tvb,  72, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_snd_max,        tvb,  76, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_snd_cwnd,       tvb,  80, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_snd_nxt,        tvb,  84, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_snd_recover,    tvb,  88, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_snd_wnd,        tvb,  92, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_snd_ssthresh,   tvb,  96, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_srtt,           tvb, 100, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_rttvar,         tvb, 104, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_rcv_up,         tvb, 108, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_rcv_adv,        tvb, 112, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(bblog_tree, tvb, 116, hf_t_flags2, ett_bblog_t_flags2, bblog_t_flags2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_rcv_nxt,        tvb, 120, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_rcv_wnd,        tvb, 124, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_dupacks,        tvb, 128, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_seg_qlen,       tvb, 132, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_snd_num_holes,  tvb, 136, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_flex_1,         tvb, 140, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_flex_2,         tvb, 144, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_first_byte_in,  tvb, 148, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_first_byte_out, tvb, 152, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_snd_scale,      tvb, 156, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_rcv_scale,      tvb, 156, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_pad_1,          tvb, 157, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_pad_2,          tvb, 158, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_pad_3,          tvb, 159, 1, ENC_LITTLE_ENDIAN);
    if (event_flags & BBLOG_EVENT_FLAG_STACKINFO) {
        /* stack specific data */
    }
    proto_tree_add_item(bblog_tree, hf_payload_len,    tvb, 264, 4, ENC_LITTLE_ENDIAN);
    return tvb_captured_length(tvb);
}

void
proto_register_bblog(void)
{
    static hf_register_info hf[] = {
        { &hf_ticks,                          { "Ticks",                                                "bblog.ticks",                         FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_serial_nr,                      { "Serial Number",                                        "bblog.serial_nr",                     FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_stack_id,                       { "Stack Identifier",                                     "bblog.stack_id",                      FT_UINT8,   BASE_DEC,  NULL ,                             0x0,                                 NULL, HFILL} },
        { &hf_event_id,                       { "Event Identifier",                                     "bblog.event_id",                      FT_UINT8,   BASE_DEC,  VALS(event_identifier_values),     0x0,                                 NULL, HFILL} },
        { &hf_event_flags,                    { "Event Flags",                                          "bblog.event_flags",                   FT_UINT16,  BASE_HEX,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_event_flags_rxbuf,              { "Receive buffer information",                           "bblog.event_flags_rxbuf",             FT_BOOLEAN, 16,        TFS(&tfs_available_not_available), BBLOG_EVENT_FLAG_RXBUF,              NULL, HFILL} },
        { &hf_event_flags_txbuf,              { "Send buffer information",                              "bblog.event_flags_txbuf",             FT_BOOLEAN, 16,        TFS(&tfs_available_not_available), BBLOG_EVENT_FLAG_TXBUF,              NULL, HFILL} },
        { &hf_event_flags_hdr,                { "TCP header",                                           "bblog.event_flags_hdr",               FT_BOOLEAN, 16,        TFS(&tfs_available_not_available), BBLOG_EVENT_FLAG_HDR,                NULL, HFILL} },
        { &hf_event_flags_verbose,            { "Additional information",                               "bblog.event_flags_verbose",           FT_BOOLEAN, 16,        TFS(&tfs_available_not_available), BBLOG_EVENT_FLAG_VERBOSE,            NULL, HFILL} },
        { &hf_event_flags_stack,              { "Stack specific information",                           "bblog.event_flags_stack",             FT_BOOLEAN, 16,        TFS(&tfs_available_not_available), BBLOG_EVENT_FLAG_STACKINFO,          NULL, HFILL} },
        { &hf_errno,                          { "Error Number",                                         "bblog.errno",                         FT_INT32,   BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_rxb_acc,                        { "Receive Buffer ACC",                                   "bblog.rxb_acc",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_rxb_ccc,                        { "Receive Buffer CCC",                                   "bblog.rxb_ccc",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_rxb_spare,                      { "Receive Buffer Spare",                                 "bblog.rxb_spare",                     FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_txb_acc,                        { "Send Buffer ACC",                                      "bblog.txb_acc",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_txb_ccc,                        { "Send Buffer CCC",                                      "bblog.txb_accs",                      FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_txb_spare,                      { "Send Buffer Spare",                                    "bblog.txb_spare",                     FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_state,                          { "TCP State",                                            "bblog.state",                         FT_UINT32,  BASE_DEC,  VALS(tcp_state_values),            0x0,                                 NULL, HFILL} },
        { &hf_starttime,                      { "Starttime",                                            "bblog.starttime",                     FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_iss,                            { "Initial Sending Sequence Number (ISS)",                "bblog.iss",                           FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_t_flags,                        { "TCB Flags",                                            "bblog.t_flags",                       FT_UINT32,  BASE_HEX,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_t_flags_ack_now,                { "Ack now",                                              "bblog.t_flags_ack_now",               FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS_ACKNOW,                NULL, HFILL} },
        { &hf_t_flags_delayed_ack,            { "Delayed ack",                                          "bblog.t_flags_delayed_ack",           FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS_DELACK,                NULL, HFILL} },
        { &hf_t_flags_no_delay,               { "No delay",                                             "bblog.t_flags_no_delay",              FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS_NODELAY,               NULL, HFILL} },
        { &hf_t_flags_no_opt,                 { "No options",                                           "bblog.t_flags_no_opt",                FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS_NOOPT,                 NULL, HFILL} },
        { &hf_t_flags_sent_fin,               { "Sent FIN",                                             "bblog.t_flags_sent_fin",              FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS_SENTFIN,               NULL, HFILL} },
        { &hf_t_flags_request_window_scale,   { "Have or will request Window Scaling",                  "bblog.t_flags_request_window_scale",  FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_REQ_SCALE,             NULL, HFILL} },
        { &hf_t_flags_received_window_scale,  { "Peer has requested Window Scaling",                    "bblog.t_flags_received_window_scale", FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_RCVD_SCALE,            NULL, HFILL} },
        { &hf_t_flags_request_timestamp,      { "Have or will request Timestamps",                      "bblog.t_flags_request_timestamp",     FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_REQ_TSTMP,             NULL, HFILL} },
        { &hf_t_flags_received_timestamp,     { "Peer has requested Timestamp",                         "bblog.t_flags_received_timestamp",    FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_RCVD_TSTMP,            NULL, HFILL} },
        { &hf_t_flags_sack_permitted,         { "SACK permitted",                                       "bblog.t_flags_sack_permitted",        FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_SACK_PERMIT,           NULL, HFILL} },
        { &hf_t_flags_need_syn,               { "Need SYN",                                             "bblog.t_flags_need_syn",              FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_NEEDSYN,               NULL, HFILL} },
        { &hf_t_flags_need_fin,               { "Need FIN",                                             "bblog.t_flags_need_fin",              FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_NEEDFIN,               NULL, HFILL} },
        { &hf_t_flags_no_push,                { "No push",                                              "bblog.t_flags_no_push",               FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS_NOPUSH,                NULL, HFILL} },
        { &hf_t_flags_prev_valid,             { "Saved values for bad retransmission valid",            "bblog.t_flags_prev_valid",            FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_PREVVALID,             NULL, HFILL} },
        { &hf_t_flags_wake_socket_receive,    { "Wakeup receive socket",                                "bblog.t_flags_wake_socket_receive",   FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_WAKESOR,               NULL, HFILL} },
        { &hf_t_flags_goodput_in_progress,    { "Goodput measurement in progress",                      "bblog.t_flags_goodput_in_progress",   FT_BOOLEAN, 32,        TFS(&tfs_true_false),              BBLOG_T_FLAGS_GPUTINPROG,            NULL, HFILL} },
        { &hf_t_flags_more_to_come,           { "More to come",                                         "bblog.t_flags_more_to_come",          FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_MORETOCOME,            NULL, HFILL} },
        { &hf_t_flags_listen_queue_overflow,  { "Listen queue overflow",                                "bblog.t_flags_listen_queue_overflow", FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_LQ_OVERFLOW,           NULL, HFILL} },
        { &hf_t_flags_last_idle,              { "Connection was previously idle",                       "bblog.t_flags_last_idle",             FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_LASTIDLE,              NULL, HFILL} },
        { &hf_t_flags_zero_recv_window_sent,  { "Sent a RCV.WND = 0 in response",                       "bblog.t_flags_zero_recv_window_sent", FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_RXWIN0SENT,            NULL, HFILL} },
        { &hf_t_flags_be_in_fast_recovery,    { "Currently in fast recovery",                           "bblog.t_flags_be_in_fast_recovery",   FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_FASTRECOVERY,          NULL, HFILL} },
        { &hf_t_flags_was_in_fast_recovery,   { "Was in fast recovery",                                 "bblog.t_flags_was_in_fast_recovery",  FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_WASFRECOVERY,          NULL, HFILL} },
        { &hf_t_flags_signature,              { "MD5 signature required",                               "bblog.t_flags_signature",             FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_SIGNATURE,             NULL, HFILL} },
        { &hf_t_flags_force_data,             { "Force data",                                           "bblog.t_flags_force_data",            FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_FORCEDATA,             NULL, HFILL} },
        { &hf_t_flags_tso,                    { "TSO",                                                  "bblog.t_flags_tso",                   FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS_TSO,                   NULL, HFILL} },
        { &hf_t_flags_toe,                    { "TOE",                                                  "bblog.t_flags_toe",                   FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS_TOE,                   NULL, HFILL} },
        { &hf_t_flags_unused_0,               { "Unused 1",                                             "bblog.t_flags_unused_0",              FT_BOOLEAN, 32,        TFS(&tfs_true_false),              BBLOG_T_FLAGS_UNUSED0,               NULL, HFILL} },
        { &hf_t_flags_unused_1,               { "Unused 2",                                             "bblog.t_flags_unused_1",              FT_BOOLEAN, 32,        TFS(&tfs_true_false),              BBLOG_T_FLAGS_UNUSED1,               NULL, HFILL} },
        { &hf_t_flags_lost_rtx_detection,     { "Lost retransmission detection",                        "bblog.t_flags_lost_rtx_detection",    FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS_LRD,                   NULL, HFILL} },
        { &hf_t_flags_be_in_cong_recovery,    { "Currently in congestion avoidance",                    "bblog.t_flags_be_in_cong_recovery",   FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_CONGRECOVERY,          NULL, HFILL} },
        { &hf_t_flags_was_in_cong_recovery,   { "Was in congestion avoidance",                          "bblog.t_flags_was_in_cong_recovery",  FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS_WASCRECOVERY,          NULL, HFILL} },
        { &hf_t_flags_fast_open,              { "TFO",                                                  "bblog.t_flags_tfo",                   FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS_FASTOPEN,              NULL, HFILL} },
        { &hf_snd_una,                        { "Oldest Unacknowledged Sequence Number (SND.UNA)",      "bblog.snd_una",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_snd_max,                        { "Newest Sequence Number Sent (SND.MAX)",                "bblog.snd_max",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_snd_cwnd,                       { "Congestion Window",                                    "bblog.snd_cwnd",                      FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_snd_nxt,                        { "Next Sequence Number (SND.NXT)",                       "bblog.snd_nxt",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_snd_recover,                    { "Recovery Sequence Number (SND.RECOVER)",               "bblog.snd_recover",                   FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_snd_wnd,                        { "Send Window (SND.WND)",                                "bblog.snd_wnd",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_snd_ssthresh,                   { "Slowstart Threshold (SSTHREASH)",                      "bblog.snd_ssthresh",                  FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_srtt,                           { "Smoothed Round Trip Time (SRTT)",                      "bblog.srtt",                          FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_rttvar,                         { "Round Trip Timer Variance (RTTVAR)",                   "bblog.rttvar",                        FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_rcv_up,                         { "Receive Urgent Pointer (RCV.UP)",                      "bblog.rcv_up",                        FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_rcv_adv,                        { "Receive Advanced (RCV.ADV)",                           "bblog.rcv_adv",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_t_flags2,                       { "TCB Flags2",                                           "bblog.t_flags2",                      FT_UINT32,  BASE_HEX,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_t_flags2_plpmtu_blackhole,      { "PMTU blackhole detection",                             "bblog.t_flags2_plpmtu_blackhole",     FT_BOOLEAN, 32,        TFS(&tfs_active_inactive),         BBLOG_T_FLAGS2_PLPMTU_BLACKHOLE,     NULL, HFILL} },
        { &hf_t_flags2_plpmtu_pmtud,          { "Path MTU discovery",                                   "bblog.t_flags2_plpmtu_pmtud",         FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS2_PLPMTU_PMTUD,         NULL, HFILL} },
        { &hf_t_flags2_plpmtu_maxsegsnt,      { "Last segment sent was a full segment",                 "bblog.t_flags2_plpmtu_maxsegsnt",     FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS2_PLPMTU_MAXSEGSNT,     NULL, HFILL} },
        { &hf_t_flags2_log_auto,              { "Connection auto-logging",                              "bblog.t_flags2_log_auto",             FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS2_LOG_AUTO,             NULL, HFILL} },
        { &hf_t_flags2_drop_after_data,       { "Drop connection after all data has been acknowledged", "bblog.t_flags2_drop_after_data",      FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS2_DROP_AFTER_DATA,      NULL, HFILL} },
        { &hf_t_flags2_ecn_permit,            { "ECN",                                                  "bblog.t_flags2_ecn_permit",           FT_BOOLEAN, 32,        TFS(&tfs_supported_not_supported), BBLOG_T_FLAGS2_ECN_PERMIT,           NULL, HFILL} },
        { &hf_t_flags2_ecn_snd_cwr,           { "ECN CWR queued",                                       "bblog.t_flags2_ecn_snd_cwr",          FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS2_ECN_SND_CWR,          NULL, HFILL} },
        { &hf_t_flags2_ecn_snd_ece,           { "ECN ECE queued",                                       "bblog.t_flags2_ecn_snd_ece",          FT_BOOLEAN, 32,        TFS(&tfs_yes_no),                  BBLOG_T_FLAGS2_ECN_SND_ECE,          NULL, HFILL} },
        { &hf_t_flags2_ace_permit,            { "Accurate ECN mode",                                    "bblog.t_flags2_ace_permit",           FT_BOOLEAN, 32,        TFS(&tfs_enabled_disabled),        BBLOG_T_FLAGS2_ACE_PERMIT,           NULL, HFILL} },
        { &hf_t_flags2_first_bytes_complete,  { "First bytes in/out",                                   "bblog.t_flags2_first_bytes_complete", FT_BOOLEAN, 32,        TFS(&tfs_available_not_available), BBLOG_T_FLAGS2_FIRST_BYTES_COMPLETE, NULL, HFILL} },
        { &hf_rcv_nxt,                        { "Receive Next (RCV.NXT)",                               "bblog.rcv_nxt",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_rcv_wnd,                        { "Receive Window (RCV.WND)",                             "bblog.rcv_wnd",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_dupacks,                        { "Duplicate Acknowledgements",                           "bblog.dupacks",                       FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_seg_qlen,                       { "Segment Queue Length",                                 "bblog.seg_qlen",                      FT_INT32,   BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_snd_num_holes,                  { "Number of Holes",                                      "bblog.snd_num_holes",                 FT_INT32,   BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_flex_1,                         { "Flex 1",                                               "bblog.flex_1",                        FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_flex_2,                         { "Flex 2",                                               "bblog.flex_2",                        FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_first_byte_in,                  { "Time of First Byte In",                                "bblog.first_byte_in",                 FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_first_byte_out,                 { "Time of First Byte Out",                               "bblog.first_byte_out",                FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_snd_scale,                      { "Snd.Wind.Shift",                                       "bblog.snd_shift",                     FT_UINT8,   BASE_DEC,  NULL,                              BBLOG_SND_SCALE_MASK,                NULL, HFILL} },
        { &hf_rcv_scale,                      { "Rcv.Wind.Shift",                                       "bblog.rcv_shift",                     FT_UINT8,   BASE_DEC,  NULL,                              BBLOG_RCV_SCALE_MASK,                NULL, HFILL} },
        { &hf_pad_1,                          { "Padding",                                              "bblog.pad_1",                         FT_UINT8,   BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_pad_2,                          { "Padding",                                              "bblog.pad_2",                         FT_UINT8,   BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_pad_3,                          { "Padding",                                              "bblog.pad_3",                         FT_UINT8,   BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
        { &hf_payload_len,                    { "TCP Payload Length",                                   "bblog.payload_length",                FT_UINT32,  BASE_DEC,  NULL,                              0x0,                                 NULL, HFILL} },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_bblog,
        &ett_bblog_flags,
        &ett_bblog_t_flags,
        &ett_bblog_t_flags2
    };

    /* Register the protocol name and description */
    proto_bblog = proto_register_protocol("Black Box Log", "BBLog", "bblog");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_bblog, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("bblog", dissect_bblog, proto_bblog);
}

void
proto_reg_handoff_bblog(void)
{
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
