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

#include <wiretap/wtap.h>
#include <epan/packet.h>
#include "packet-bblog.h"

#define PEN_NFLX 10949

void proto_register_bblog(void);
void proto_reg_handoff_bblog(void);

static dissector_handle_t bblog_handle;

static int proto_bblog;

static int hf_ticks;
static int hf_serial_nr;
static int hf_stack_id;
static int hf_event_id;
static int hf_event_flags;
static int hf_event_flags_rxbuf;
static int hf_event_flags_txbuf;
static int hf_event_flags_hdr;
static int hf_event_flags_verbose;
static int hf_event_flags_stack;
static int hf_errno;
static int hf_rxb_acc;
static int hf_rxb_ccc;
static int hf_rxb_spare;
static int hf_txb_acc;
static int hf_txb_ccc;
static int hf_txb_spare;
static int hf_state;
static int hf_starttime;
static int hf_iss;
static int hf_t_flags;
static int hf_t_flags_ack_now;
static int hf_t_flags_delayed_ack;
static int hf_t_flags_no_delay;
static int hf_t_flags_no_opt;
static int hf_t_flags_sent_fin;
static int hf_t_flags_request_window_scale;
static int hf_t_flags_received_window_scale;
static int hf_t_flags_request_timestamp;
static int hf_t_flags_received_timestamp;
static int hf_t_flags_sack_permitted;
static int hf_t_flags_need_syn;
static int hf_t_flags_need_fin;
static int hf_t_flags_no_push;
static int hf_t_flags_prev_valid;
static int hf_t_flags_wake_socket_receive;
static int hf_t_flags_goodput_in_progress;
static int hf_t_flags_more_to_come;
static int hf_t_flags_listen_queue_overflow;
static int hf_t_flags_last_idle;
static int hf_t_flags_zero_recv_window_sent;
static int hf_t_flags_be_in_fast_recovery;
static int hf_t_flags_was_in_fast_recovery;
static int hf_t_flags_signature;
static int hf_t_flags_force_data;
static int hf_t_flags_tso;
static int hf_t_flags_toe;
static int hf_t_flags_unused_1;
static int hf_t_flags_unused_2;
static int hf_t_flags_lost_rtx_detection;
static int hf_t_flags_be_in_cong_recovery;
static int hf_t_flags_was_in_cong_recovery;
static int hf_t_flags_fast_open;
static int hf_snd_una;
static int hf_snd_max;
static int hf_snd_cwnd;
static int hf_snd_nxt;
static int hf_snd_recover;
static int hf_snd_wnd;
static int hf_snd_ssthresh;
static int hf_srtt;
static int hf_rttvar;
static int hf_rcv_up;
static int hf_rcv_adv;
static int hf_t_flags2;
static int hf_t_flags2_plpmtu_blackhole;
static int hf_t_flags2_plpmtu_pmtud;
static int hf_t_flags2_plpmtu_maxsegsnt;
static int hf_t_flags2_log_auto;
static int hf_t_flags2_drop_after_data;
static int hf_t_flags2_ecn_permit;
static int hf_t_flags2_ecn_snd_cwr;
static int hf_t_flags2_ecn_snd_ece;
static int hf_t_flags2_ace_permit;
static int hf_t_flags2_first_bytes_complete;
static int hf_rcv_nxt;
static int hf_rcv_wnd;
static int hf_dupacks;
static int hf_seg_qlen;
static int hf_snd_num_holes;
static int hf_flex_1;
static int hf_flex_2;
static int hf_first_byte_in;
static int hf_first_byte_out;
static int hf_snd_scale;
static int hf_rcv_scale;
static int hf_pad_1;
static int hf_pad_2;
static int hf_pad_3;
static int hf_payload_len;

static int ett_bblog;
static int ett_bblog_flags;
static int ett_bblog_t_flags;
static int ett_bblog_t_flags2;

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
  &hf_t_flags_unused_1,
  &hf_t_flags_unused_2,
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
 * The PRU constants are taken from
 * https://cgit.freebsd.org/src/tree/sys/netinet/in_kdrace.h
 */

#define BBLOG_TCP_PRU_ATTACH      0
#define BBLOG_TCP_PRU_DETACH      1
#define BBLOG_TCP_PRU_BIND        2
#define BBLOG_TCP_PRU_LISTEN      3
#define BBLOG_TCP_PRU_CONNECT     4
#define BBLOG_TCP_PRU_ACCEPT      5
#define BBLOG_TCP_PRU_DISCONNECT  6
#define BBLOG_TCP_PRU_SHUTDOWN    7
#define BBLOG_TCP_PRU_RCVD        8
#define BBLOG_TCP_PRU_SEND        9
#define BBLOG_TCP_PRU_ABORT      10
#define BBLOG_TCP_PRU_CONTROL    11
#define BBLOG_TCP_PRU_SENSE      12
#define BBLOG_TCP_PRU_RCVOOB     13
#define BBLOG_TCP_PRU_SENDOOB    14
#define BBLOG_TCP_PRU_SOCKADDR   15
#define BBLOG_TCP_PRU_PEERADDR   16
#define BBLOG_TCP_PRU_CONNECT2   17
#define BBLOG_TCP_PRU_FASTTIMO   18
#define BBLOG_TCP_PRU_SLOWTIMO   19
#define BBLOG_TCP_PRU_PROTORCV   20
#define BBLOG_TCP_PRU_PROTOSEND  21
#define BBLOG_TCP_PRU_SEND_EOF   22
#define BBLOG_TCP_PRU_SOSETLABEL 23
#define BBLOG_TCP_PRU_CLOSE      24
#define BBLOG_TCP_PRU_FLUSH      25

static const value_string tcp_pru_values[] = {
  { BBLOG_TCP_PRU_ATTACH,     "ATTACH" },
  { BBLOG_TCP_PRU_DETACH,     "DETACH" },
  { BBLOG_TCP_PRU_BIND,       "BIND" },
  { BBLOG_TCP_PRU_LISTEN,     "LISTEN" },
  { BBLOG_TCP_PRU_CONNECT,    "CONNECT" },
  { BBLOG_TCP_PRU_ACCEPT,     "ACCEPT" },
  { BBLOG_TCP_PRU_DISCONNECT, "DISCONNECT" },
  { BBLOG_TCP_PRU_SHUTDOWN,   "SHUTDOWN" },
  { BBLOG_TCP_PRU_RCVD,       "RCVD" },
  { BBLOG_TCP_PRU_SEND,       "SEND" },
  { BBLOG_TCP_PRU_ABORT,      "ABORT" },
  { BBLOG_TCP_PRU_CONTROL,    "CONTROL" },
  { BBLOG_TCP_PRU_SENSE,      "SENSE" },
  { BBLOG_TCP_PRU_RCVOOB,     "RCVOOB" },
  { BBLOG_TCP_PRU_SENDOOB,    "SENDOOB" },
  { BBLOG_TCP_PRU_SOCKADDR,   "SOCKADDR" },
  { BBLOG_TCP_PRU_PEERADDR,   "PEERADDR" },
  { BBLOG_TCP_PRU_CONNECT2,   "CONNECT2" },
  { BBLOG_TCP_PRU_FASTTIMO,   "FASTTIMO" },
  { BBLOG_TCP_PRU_SLOWTIMO,   "SLOWTIMO" },
  { BBLOG_TCP_PRU_PROTORCV,   "PROTORCV" },
  { BBLOG_TCP_PRU_PROTOSEND,  "PROTOSEND" },
  { BBLOG_TCP_PRU_SEND_EOF,   "SEND_EOF" },
  { BBLOG_TCP_PRU_SOSETLABEL, "SOSETLABEL" },
  { BBLOG_TCP_PRU_CLOSE,      "CLOSE" },
  { BBLOG_TCP_PRU_FLUSH,      "FLUSH" },
  { 0, NULL } };

#define BBLOG_TCP_PRU_MASK   0x000000ff
#define BBLOG_TCP_PRU_SHIFT  0

#define BBLOG_TCP_TIMER_TYPE_RETRANSMIT 0
#define BBLOG_TCP_TIMER_TYPE_PERSIST    1
#define BBLOG_TCP_TIMER_TYPE_KEEPALIVE  2
#define BBLOG_TCP_TIMER_TYPE_2MSL       3
#define BBLOG_TCP_TIMER_TYPE_DELACK     4

static const value_string tcp_timer_type_values[] = {
  { BBLOG_TCP_TIMER_TYPE_RETRANSMIT, "Retransmission" },
  { BBLOG_TCP_TIMER_TYPE_PERSIST,    "Persist" },
  { BBLOG_TCP_TIMER_TYPE_KEEPALIVE,  "Keepalive" },
  { BBLOG_TCP_TIMER_TYPE_2MSL,       "2 MSL" },
  { BBLOG_TCP_TIMER_TYPE_DELACK,     "Delayed ACK" },
  { 0, NULL } };

#define BBLOG_TCP_TIMER_EVENT_PROCESSING 0
#define BBLOG_TCP_TIMER_EVENT_PROCESSED  1
#define BBLOG_TCP_TIMER_EVENT_STARTING   2
#define BBLOG_TCP_TIMER_EVENT_STOPPING   3

static const value_string tcp_timer_event_values[] = {
  { BBLOG_TCP_TIMER_EVENT_PROCESSING, "Processing" },
  { BBLOG_TCP_TIMER_EVENT_PROCESSED,  "Processed" },
  { BBLOG_TCP_TIMER_EVENT_STARTING,   "Starting" },
  { BBLOG_TCP_TIMER_EVENT_STOPPING,   "Stopping" },
  { 0, NULL } };

#define BBLOG_TCP_TIMER_TYPE_MASK   0x000000ff
#define BBLOG_TCP_TIMER_TYPE_SHIFT  0
#define BBLOG_TCP_TIMER_EVENT_MASK  0x0000ff00
#define BBLOG_TCP_TIMER_EVENT_SHIFT 8

/*
 * The structures used here are defined in
 * https://cgit.freebsd.org/src/tree/sys/netinet/tcp_log_buf.h
 */

static int
dissect_bblog_event(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *bblog_item;
    proto_tree *bblog_tree;
    const char *event_name;
    uint32_t flex1, flex2;
    uint16_t event_flags;
    uint8_t event_identifier;
    uint8_t pru;
    uint8_t timer_type, timer_event;

    event_identifier = tvb_get_uint8(tvb, 25);
    flex1 = tvb_get_letohl(tvb, 140);
    flex2 = tvb_get_letohl(tvb, 144);
    switch (event_identifier) {
    case TCP_LOG_PRU:
        pru = (flex1 & BBLOG_TCP_PRU_MASK) >> BBLOG_TCP_PRU_SHIFT;
        col_append_fstr(pinfo->cinfo, COL_INFO, "PRU: %s",
                        val_to_str(pru, tcp_pru_values, "UNKNOWN (0x%02x)"));
        break;
    case BBLOG_TCP_LOG_TIMER:
        timer_type = (flex1 & BBLOG_TCP_TIMER_TYPE_MASK) >> BBLOG_TCP_TIMER_TYPE_SHIFT;
        timer_event = (flex1 & BBLOG_TCP_TIMER_EVENT_MASK) >> BBLOG_TCP_TIMER_EVENT_SHIFT;
        col_append_fstr(pinfo->cinfo, COL_INFO, "%s %s timer",
                        val_to_str(timer_event, tcp_timer_event_values, "Unknown operation (0x%02x) for"),
                        val_to_str(timer_type, tcp_timer_type_values, "Unknown (0x%02x)"));
        if (timer_event == BBLOG_TCP_TIMER_EVENT_STARTING) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ": %u ms", flex2);
        }
        break;
    default:
        event_name = try_val_to_str(event_identifier, event_identifier_values);
        if (event_name != NULL) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "%s", event_name);
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, "Unknown (flex1 0x%08x, flex2 0x%08x0)", flex1, flex2);
        }
        break;
    }

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

static int
dissect_bblog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BBLog");
    switch (pinfo->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type) {
    case BBLOG_TYPE_SKIPPED_BLOCK:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Number of skipped events: %u",
                     pinfo->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.skipped);
        break;
    case BBLOG_TYPE_EVENT_BLOCK:
        dissect_bblog_event(tvb, pinfo, tree, data);
        break;
    default:
        col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown type: %u",
                     pinfo->rec->rec_header.custom_block_header.custom_data_header.nflx_custom_data_header.type);
        break;
    }
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
        { &hf_errno,                          { "Error Number",                                         "bblog.errno",                         FT_INT32,   BASE_DEC,  VALS(errno_values),                0x0,                                 NULL, HFILL} },
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
        { &hf_t_flags_goodput_in_progress,    { "Goodput measurement in progress",                      "bblog.t_flags_goodput_in_progress",   FT_BOOLEAN, 32,        NULL,              BBLOG_T_FLAGS_GPUTINPROG,            NULL, HFILL} },
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
        { &hf_t_flags_unused_1,               { "Unused 1",                                             "bblog.t_flags_unused_1",              FT_BOOLEAN, 32,        NULL,              BBLOG_T_FLAGS_UNUSED0,               NULL, HFILL} },
        { &hf_t_flags_unused_2,               { "Unused 2",                                             "bblog.t_flags_unused_2",              FT_BOOLEAN, 32,        NULL,              BBLOG_T_FLAGS_UNUSED1,               NULL, HFILL} },
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
    static int *ett[] = {
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

    bblog_handle = register_dissector("bblog", dissect_bblog, proto_bblog);
}

void
proto_reg_handoff_bblog(void)
{
    dissector_add_uint("pcapng_custom_block", PEN_NFLX, bblog_handle);
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
