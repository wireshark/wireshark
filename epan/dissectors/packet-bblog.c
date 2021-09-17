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

void proto_register_bblog(void);
void proto_reg_handoff_bblog(void);

static int proto_bblog            = -1;

static int hf_ticks               = -1;
static int hf_serial_nr           = -1;
static int hf_stack_id            = -1;
static int hf_event_id            = -1;
static int hf_event_flags         = -1;
static int hf_event_flags_rxbuf   = -1;
static int hf_event_flags_txbuf   = -1;
static int hf_event_flags_hdr     = -1;
static int hf_event_flags_verbose = -1;
static int hf_event_flags_stack   = -1;
static int hf_errno               = -1;
static int hf_rxb_acc             = -1;
static int hf_rxb_ccc             = -1;
static int hf_rxb_spare           = -1;
static int hf_txb_acc             = -1;
static int hf_txb_ccc             = -1;
static int hf_txb_spare           = -1;
static int hf_state               = -1;
static int hf_starttime           = -1;
static int hf_iss                 = -1;
static int hf_flags               = -1;
static int hf_snd_una             = -1;
static int hf_snd_max             = -1;
static int hf_snd_cwnd            = -1;
static int hf_snd_nxt             = -1;
static int hf_snd_recover         = -1;
static int hf_snd_wnd             = -1;
static int hf_snd_ssthresh        = -1;
static int hf_srtt                = -1;
static int hf_rttvar              = -1;
static int hf_rcv_up              = -1;
static int hf_rcv_adv             = -1;
static int hf_flags2              = -1;
static int hf_rcv_nxt             = -1;
static int hf_rcv_wnd             = -1;
static int hf_dupacks             = -1;
static int hf_seg_qlen            = -1;
static int hf_snd_num_holes       = -1;
static int hf_flex_1              = -1;
static int hf_flex_2              = -1;
static int hf_first_byte_in       = -1;
static int hf_first_byte_out      = -1;
static int hf_snd_scale           = -1;
static int hf_rcv_scale           = -1;
static int hf_pad_1               = -1;
static int hf_pad_2               = -1;
static int hf_pad_3               = -1;
static int hf_payload_len         = -1;

static gint ett_bblog             = -1;
static gint ett_bblog_flags       = -1;

#define TCP_LOG_IN               1
#define TCP_LOG_OUT              2
#define TCP_LOG_RTO              3
#define TCP_LOG_SB_WAKE          4
#define TCP_LOG_BAD_RETRAN       5
#define TCP_LOG_PRR              6
#define TCP_LOG_REORDER          7
#define TCP_LOG_HPTS             8
#define BBR_LOG_BBRUPD           9
#define BBR_LOG_BBRSND          10
#define BBR_LOG_ACKCLEAR        11
#define BBR_LOG_INQUEUE         12
#define BBR_LOG_TIMERSTAR       13
#define BBR_LOG_TIMERCANC       14
#define BBR_LOG_ENTREC          15
#define BBR_LOG_EXITREC         16
#define BBR_LOG_CWND            17
#define BBR_LOG_BWSAMP          18
#define BBR_LOG_MSGSIZE         19
#define BBR_LOG_BBRRTT          20
#define BBR_LOG_JUSTRET         21
#define BBR_LOG_STATE           22
#define BBR_LOG_PKT_EPOCH       23
#define BBR_LOG_PERSIST         24
#define TCP_LOG_FLOWEND         25
#define BBR_LOG_RTO             26
#define BBR_LOG_DOSEG_DONE      27
#define BBR_LOG_EXIT_GAIN       28
#define BBR_LOG_THRESH_CALC     29
#define TCP_LOG_MAPCHG          30
#define TCP_LOG_USERSEND        31
#define BBR_RSM_CLEARED         32
#define BBR_LOG_STATE_TARGET    33
#define BBR_LOG_TIME_EPOCH      34
#define BBR_LOG_TO_PROCESS      35
#define BBR_LOG_BBRTSO          36
#define BBR_LOG_HPTSDIAG        37
#define BBR_LOG_LOWGAIN         38
#define BBR_LOG_PROGRESS        39
#define TCP_LOG_SOCKET_OPT      40
#define BBR_LOG_TIMERPREP       41
#define BBR_LOG_ENOBUF_JMP      42
#define BBR_LOG_HPTSI_CALC      43
#define BBR_LOG_RTT_SHRINKS     44
#define BBR_LOG_BW_RED_EV       45
#define BBR_LOG_REDUCE          46
#define TCP_LOG_RTT             47
#define BBR_LOG_SETTINGS_CHG    48
#define BBR_LOG_SRTT_GAIN_EVENT 49
#define TCP_LOG_REASS           50
#define TCP_HDWR_TLS            51
#define BBR_LOG_HDWR_PACE       52
#define BBR_LOG_TSTMP_VAL       53
#define TCP_LOG_CONNEND         54
#define TCP_LOG_LRO             55
#define TCP_SACK_FILTER_RES     56
#define TCP_SAD_DETECTION       57
#define TCP_TIMELY_WORK         58
#define TCP_LOG_USER_EVENT      59
#define TCP_LOG_SENDFILE        60
#define TCP_LOG_HTTP_T          61
#define TCP_LOG_ACCOUNTING      62
#define TCP_LOG_FSB             63


static const value_string event_identifier_values[] = {
  { TCP_LOG_IN,              "Incoming packet" },
  { TCP_LOG_OUT,             "Transmit (without other event)" },
  { TCP_LOG_RTO,             "Retransmit timeout" },
  { TCP_LOG_SB_WAKE,         "Awaken socket buffer" },
  { TCP_LOG_BAD_RETRAN,      "Detected bad retransmission" },
  { TCP_LOG_PRR,             "Doing PRR" },
  { TCP_LOG_REORDER,         "Detected reorder" },
  { TCP_LOG_HPTS,            "Hpts sending a packet" },
  { BBR_LOG_BBRUPD,          "We updated BBR info" },
  { BBR_LOG_BBRSND,          "We did a slot calculation and sending is done" },
  { BBR_LOG_ACKCLEAR,        "A ack clears all outstanding" },
  { BBR_LOG_INQUEUE,         "The tcb had a packet input to it" },
  { BBR_LOG_TIMERSTAR,       "Start a timer" },
  { BBR_LOG_TIMERCANC,       "Cancel a timer" },
  { BBR_LOG_ENTREC,          "Entered recovery" },
  { BBR_LOG_EXITREC,         "Exited recovery" },
  { BBR_LOG_CWND,            "Cwnd change" },
  { BBR_LOG_BWSAMP,          "LT B/W sample has been made" },
  { BBR_LOG_MSGSIZE,         "We received a EMSGSIZE error" },
  { BBR_LOG_BBRRTT,          "BBR RTT is updated" },
  { BBR_LOG_JUSTRET,         "We just returned out of output" },
  { BBR_LOG_STATE,           "A BBR state change occurred" },
  { BBR_LOG_PKT_EPOCH,       "A BBR packet epoch occurred" },
  { BBR_LOG_PERSIST,         "BBR changed to/from a persists" },
  { TCP_LOG_FLOWEND,         "End of a flow" },
  { BBR_LOG_RTO,             "BBR's timeout includes BBR info" },
  { BBR_LOG_DOSEG_DONE,      "hpts do_segment completes" },
  { BBR_LOG_EXIT_GAIN,       "hpts do_segment completes" },
  { BBR_LOG_THRESH_CALC,     "Doing threshold calculation" },
  { TCP_LOG_MAPCHG,          "Map Changes to the sendmap" },
  { TCP_LOG_USERSEND,        "User level sends data" },
  { BBR_RSM_CLEARED,         "RSM cleared of ACK flags" },
  { BBR_LOG_STATE_TARGET,    "Log of target at state" },
  { BBR_LOG_TIME_EPOCH,      "A timed based Epoch occurred" },
  { BBR_LOG_TO_PROCESS,      "A to was processed" },
  { BBR_LOG_BBRTSO,          "TSO update" },
  { BBR_LOG_HPTSDIAG,        "Hpts diag insert" },
  { BBR_LOG_LOWGAIN,         "Low gain accounting" },
  { BBR_LOG_PROGRESS,        "Progress timer event" },
  { TCP_LOG_SOCKET_OPT,      "A socket option is set" },
  { BBR_LOG_TIMERPREP,       "A BBR var to debug out TLP issues" },
  { BBR_LOG_ENOBUF_JMP,      "We had a enobuf jump" },
  { BBR_LOG_HPTSI_CALC,      "calc the hptsi time" },
  { BBR_LOG_RTT_SHRINKS,     "We had a log reduction of rttProp" },
  { BBR_LOG_BW_RED_EV,       "B/W reduction events" },
  { BBR_LOG_REDUCE,          "old bbr log reduce for 4.1 and earlier" },
  { TCP_LOG_RTT,             "A rtt (in useconds) is being sampled and applied to the srtt algo" },
  { BBR_LOG_SETTINGS_CHG,    "Settings changed for loss response 48" },
  { BBR_LOG_SRTT_GAIN_EVENT, "SRTT gaining -- now not used" },
  { TCP_LOG_REASS,           "Reassembly buffer logging" },
  { TCP_HDWR_TLS,            "TCP Hardware TLS logs" },
  { BBR_LOG_HDWR_PACE,       "TCP Hardware pacing log" },
  { BBR_LOG_TSTMP_VAL,       "Temp debug timestamp validation" },
  { TCP_LOG_CONNEND,         "End of connection" },
  { TCP_LOG_LRO,             "LRO entry" },
  { TCP_SACK_FILTER_RES,     "Results of SACK Filter" },
  { TCP_SAD_DETECTION,       "Sack Attack Detection" },
  { TCP_TIMELY_WORK,         "Logs regarding Timely CC tweaks" },
  { TCP_LOG_USER_EVENT,      "User space event data" },
  { TCP_LOG_SENDFILE,        "sendfile() logging for TCP connections" },
  { TCP_LOG_HTTP_T,          "logging of http request tracking" },
  { TCP_LOG_ACCOUNTING,      "Log of TCP Accounting data" },
  { TCP_LOG_FSB,             "FSB information 63" },
  { 0,      NULL } };

static const value_string tcp_state_values[] = {
  {  0, "CLOSED" },
  {  1, "LISTEN" },
  {  2, "SYN SENT" },
  {  3, "SYN RECEIVED" },
  {  4, "ESTABLISHED" },
  {  5, "CLOSE WAIT" },
  {  6, "FIN WAIT 1" },
  {  7, "CLOSING" },
  {  8, "LAST ACK" },
  {  9, "FIN WAIT 2" },
  { 10, "TIME WAIT" },
  {  0, NULL } };

#define EVENT_FLAG_RXBUF     0x0001
#define EVENT_FLAG_TXBUF     0x0002
#define EVENT_FLAG_HDR       0x0004
#define EVENT_FLAG_VERBOSE   0x0008
#define EVENT_FLAG_STACKINFO 0x0010

static const true_false_string event_flags_rxbuf = {
  "Receive buffer information available",
  "Receive buffer information not available"
};

static const true_false_string event_flags_txbuf = {
  "Send buffer information available",
  "Send buffer information not available"
};

static const true_false_string event_flags_hdr = {
  "TCP header available",
  "TCP header not available"
};

static const true_false_string event_flags_verbose = {
  "Additional information available",
  "Additional information not available"
};

static const true_false_string event_flags_stack = {
  "Stack specific information available",
  "Stack specific information not available"
};

#define SND_SCALE_MASK 0xf0
#define RCV_SCALE_MASK 0x0f

/*
 * The structures used here are defined in
 * https://cgit.freebsd.org/src/tree/sys/netinet/tcp_log_buf.h
 */

static int
dissect_bblog(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *bblog_item, *event_flags_item;
    proto_tree *bblog_tree, *event_flags_tree;
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
    event_flags_item = proto_tree_add_item(bblog_tree, hf_event_flags, tvb, 26,   2,   ENC_LITTLE_ENDIAN);
    event_flags_tree = proto_item_add_subtree(event_flags_item, ett_bblog_flags);
    proto_tree_add_item(event_flags_tree, hf_event_flags_rxbuf,   tvb, 26, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(event_flags_tree, hf_event_flags_txbuf,   tvb, 26, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(event_flags_tree, hf_event_flags_hdr,     tvb, 26, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(event_flags_tree, hf_event_flags_verbose, tvb, 26, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(event_flags_tree, hf_event_flags_stack,   tvb, 26, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_errno, tvb, 28, 4, ENC_LITTLE_ENDIAN);
    if (event_flags & EVENT_FLAG_RXBUF) {
        proto_tree_add_item(bblog_tree, hf_rxb_acc,   tvb, 32, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(bblog_tree, hf_rxb_ccc,   tvb, 36, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(bblog_tree, hf_rxb_spare, tvb, 40, 4, ENC_LITTLE_ENDIAN);
    }
    if (event_flags & EVENT_FLAG_TXBUF) {
        proto_tree_add_item(bblog_tree, hf_txb_acc,   tvb, 44, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(bblog_tree, hf_txb_ccc,   tvb, 48, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(bblog_tree, hf_txb_spare, tvb, 52, 4, ENC_LITTLE_ENDIAN);
    }
    proto_tree_add_item(bblog_tree, hf_state,          tvb,  56, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_starttime,      tvb,  60, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_iss,            tvb,  64, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(bblog_tree, hf_flags,          tvb,  68, 4, ENC_LITTLE_ENDIAN);
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
    proto_tree_add_item(bblog_tree, hf_flags2,         tvb, 116, 4, ENC_LITTLE_ENDIAN);
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
    if (event_flags & EVENT_FLAG_STACKINFO) {
        /* stack specific data */
    }
    proto_tree_add_item(bblog_tree, hf_payload_len,    tvb, 264, 4, ENC_LITTLE_ENDIAN);
    return tvb_captured_length(tvb);
}

void
proto_register_bblog(void)
{
    static hf_register_info hf[] = {
        { &hf_ticks,               { "Ticks",                                           "bblog.ticks",               FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_serial_nr,           { "Serial Number",                                   "bblog.serial_nr",           FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_stack_id,            { "Stack Identifier",                                "bblog.stack_id",            FT_UINT8,   BASE_DEC,  NULL                         , 0x0,                  NULL, HFILL} },
        { &hf_event_id,            { "Event Identifier",                                "bblog.event_id",            FT_UINT8,   BASE_DEC,  VALS(event_identifier_values), 0x0,                  NULL, HFILL} },
        { &hf_event_flags,         { "Event Flags",                                     "bblog.event_flags",         FT_UINT16,  BASE_HEX,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_event_flags_rxbuf,   { "Bit",                                             "bblog.event_flags_rxbuf",   FT_BOOLEAN, 8,         TFS(&event_flags_rxbuf),       EVENT_FLAG_RXBUF,     NULL, HFILL} },
        { &hf_event_flags_txbuf,   { "Bit",                                             "bblog.event_flags_txbuf",   FT_BOOLEAN, 8,         TFS(&event_flags_txbuf),       EVENT_FLAG_TXBUF,     NULL, HFILL} },
        { &hf_event_flags_hdr,     { "Bit",                                             "bblog.event_flags_hdr",     FT_BOOLEAN, 8,         TFS(&event_flags_hdr),         EVENT_FLAG_HDR,       NULL, HFILL} },
        { &hf_event_flags_verbose, { "Bit",                                             "bblog.event_flags_verbose", FT_BOOLEAN, 8,         TFS(&event_flags_verbose),     EVENT_FLAG_VERBOSE,   NULL, HFILL} },
        { &hf_event_flags_stack,   { "Bit",                                             "bblog.event_flags_stack",   FT_BOOLEAN, 8,         TFS(&event_flags_stack),       EVENT_FLAG_STACKINFO, NULL, HFILL} },
        { &hf_errno,               { "Error Number",                                    "bblog.errno",               FT_INT32,   BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_rxb_acc,             { "Receive Buffer ACC",                              "bblog.rxb_acc",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_rxb_ccc,             { "Receive Buffer CCC",                              "bblog.rxb_ccc",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_rxb_spare,           { "Receive Buffer Spare",                            "bblog.rxb_spare",           FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_txb_acc,             { "Send Buffer ACC",                                 "bblog.txb_acc",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_txb_ccc,             { "Send Buffer CCC",                                 "bblog.txb_accs",            FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_txb_spare,           { "Send Buffer Spare",                               "bblog.txb_spare",           FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_state,               { "TCP State",                                       "bblog.state",               FT_UINT32,  BASE_DEC,  VALS(tcp_state_values),        0x0,                  NULL, HFILL} },
        { &hf_starttime,           { "Starttime",                                       "bblog.starttime",           FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_iss,                 { "Initial Sending Sequence Number (ISS)",           "bblog.iss",                 FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_flags,               { "TCB Flags",                                       "bblog.flags",               FT_UINT32,  BASE_HEX,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_snd_una,             { "Oldest Unacknowledged Sequence Number (SND.UNA)", "bblog.snd_una",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_snd_max,             { "Newest Sequence Number Sent (SND.MAX)",           "bblog.snd_max",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_snd_cwnd,            { "Congestion Window",                               "bblog.snd_cwnd",            FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_snd_nxt,             { "Next Sequence Number (SND.NXT)",                  "bblog.snd_nxt",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_snd_recover,         { "Recovery Sequence Number (SND.RECOVER)",          "bblog.snd_recover",         FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_snd_wnd,             { "Send Window (SND.WND)",                           "bblog.snd_wnd",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_snd_ssthresh,        { "Slowstart Threshold (SSTHREASH)",                 "bblog.snd_ssthresh",        FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_srtt,                { "Smoothed Round Trip Time (SRTT)",                 "bblog.srtt",                FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_rttvar,              { "Round Trip Timer Variance (RTTVAR)",              "bblog.rttvar",              FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_rcv_up,              { "Receive Urgent Pointer (RCV.UP)",                 "bblog.rcv_up",              FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_rcv_adv,             { "Receive Advanced (RCV.ADV)",                      "bblog.rcv_adv",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_flags2,              { "TCB Flags2",                                      "bblog.flags2",              FT_UINT32,  BASE_HEX,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_rcv_nxt,             { "Receive Next (RCV.NXT)",                          "bblog.rcv_nxt",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_rcv_wnd,             { "Receive Window (RCV.WND)",                        "bblog.rcv_wnd",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_dupacks,             { "Duplicate Acknowledgements",                      "bblog.dupacks",             FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_seg_qlen,            { "Segment Queue Length",                            "bblog.seg_qlen",            FT_INT32,   BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_snd_num_holes,       { "Number of Holes",                                 "bblog.snd_num_holes",       FT_INT32,   BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_flex_1,              { "Flex 1",                                          "bblog.flex_1",              FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_flex_2,              { "Flex 2",                                          "bblog.flex_2",              FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_first_byte_in,       { "Time of First Byte In",                           "bblog.first_byte_in",       FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_first_byte_out,      { "Time of First Byte Out",                          "bblog.first_byte_out",      FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_snd_scale,           { "Shift Count for Send Window",                     "bblog.snd_shift",           FT_UINT8,   BASE_DEC,  NULL,                          SND_SCALE_MASK,       NULL, HFILL} },
        { &hf_rcv_scale,           { "Shift Count for Receive Window",                  "bblog.rcv_shift",           FT_UINT8,   BASE_DEC,  NULL,                          RCV_SCALE_MASK,       NULL, HFILL} },
        { &hf_pad_1,               { "Padding",                                         "bblog.pad_1",               FT_UINT8,   BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_pad_2,               { "Padding",                                         "bblog.pad_2",               FT_UINT8,   BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_pad_3,               { "Padding",                                         "bblog.pad_3",               FT_UINT8,   BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
        { &hf_payload_len,         { "TCP Payload Length",                              "bblog.payload_length",      FT_UINT32,  BASE_DEC,  NULL,                          0x0,                  NULL, HFILL} },
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_bblog,
        &ett_bblog_flags
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
