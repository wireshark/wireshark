/* packet-bblog.h
 * Constants for Black Box Log dissection
 * Copyright 2022 Michael Tuexen <tuexen [AT] wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_BBLOG_H_
#define __PACKET_BBLOG_H_

/*
 * The t_state values used here are defined in
 * https://cgit.freebsd.org/src/tree/sys/netinet/tcp_fsm.h
 */
static const value_string tcp_state_values[] = {
  {  0, "CLOSED" },
  {  1, "LISTEN" },
  {  2, "SYN-SENT" },
  {  3, "SYN-RECEIVED" },
  {  4, "ESTABLISHED" },
  {  5, "CLOSE-WAIT" },
  {  6, "FIN-WAIT-1" },
  {  7, "CLOSING" },
  {  8, "LAST-ACK" },
  {  9, "FIN-WAIT-2" },
  { 10, "TIME-WAIT" },
  {  0, NULL } };

/*
 * The event types used here are defined in
 * https://cgit.freebsd.org/src/tree/sys/netinet/tcp_log_buf.h
 */

#define BBLOG_TCP_LOG_IN               1
#define BBLOG_TCP_LOG_OUT              2
/* Use a better name for the event used for various timer events */
#define BBLOG_TCP_LOG_TIMER            3
#define BBLOG_TCP_LOG_SB_WAKE          4
#define BBLOG_TCP_LOG_BAD_RETRAN       5
#define BBLOG_TCP_LOG_PRR              6
#define BBLOG_TCP_LOG_REORDER          7
#define BBLOG_TCP_LOG_HPTS             8
#define BBLOG_BBR_LOG_BBRUPD           9
#define BBLOG_BBR_LOG_BBRSND          10
#define BBLOG_BBR_LOG_ACKCLEAR        11
#define BBLOG_BBR_LOG_INQUEUE         12
#define BBLOG_BBR_LOG_TIMERSTAR       13
#define BBLOG_BBR_LOG_TIMERCANC       14
#define BBLOG_BBR_LOG_ENTREC          15
#define BBLOG_BBR_LOG_EXITREC         16
#define BBLOG_BBR_LOG_CWND            17
#define BBLOG_BBR_LOG_BWSAMP          18
#define BBLOG_BBR_LOG_MSGSIZE         19
#define BBLOG_BBR_LOG_BBRRTT          20
#define BBLOG_BBR_LOG_JUSTRET         21
#define BBLOG_BBR_LOG_STATE           22
#define BBLOG_BBR_LOG_PKT_EPOCH       23
#define BBLOG_BBR_LOG_PERSIST         24
#define BBLOG_TCP_LOG_FLOWEND         25
#define BBLOG_BBR_LOG_RTO             26
#define BBLOG_BBR_LOG_DOSEG_DONE      27
#define BBLOG_BBR_LOG_EXIT_GAIN       28
#define BBLOG_BBR_LOG_THRESH_CALC     29
#define BBLOG_TCP_LOG_MAPCHG          30
#define BBLOG_TCP_LOG_USERSEND        31
#define BBLOG_BBR_RSM_CLEARED         32
#define BBLOG_BBR_LOG_STATE_TARGET    33
#define BBLOG_BBR_LOG_TIME_EPOCH      34
#define BBLOG_BBR_LOG_TO_PROCESS      35
#define BBLOG_BBR_LOG_BBRTSO          36
#define BBLOG_BBR_LOG_HPTSDIAG        37
#define BBLOG_BBR_LOG_LOWGAIN         38
#define BBLOG_BBR_LOG_PROGRESS        39
#define BBLOG_TCP_LOG_SOCKET_OPT      40
#define BBLOG_BBR_LOG_TIMERPREP       41
#define BBLOG_BBR_LOG_ENOBUF_JMP      42
#define BBLOG_BBR_LOG_HPTSI_CALC      43
#define BBLOG_BBR_LOG_RTT_SHRINKS     44
#define BBLOG_BBR_LOG_BW_RED_EV       45
#define BBLOG_BBR_LOG_REDUCE          46
#define BBLOG_TCP_LOG_RTT             47
#define BBLOG_BBR_LOG_SETTINGS_CHG    48
#define BBLOG_BBR_LOG_SRTT_GAIN_EVENT 49
#define BBLOG_TCP_LOG_REASS           50
#define BBLOG_TCP_HDWR_TLS            51
#define BBLOG_BBR_LOG_HDWR_PACE       52
#define BBLOG_BBR_LOG_TSTMP_VAL       53
#define BBLOG_TCP_LOG_CONNEND         54
#define BBLOG_TCP_LOG_LRO             55
#define BBLOG_TCP_SACK_FILTER_RES     56
#define BBLOG_TCP_SAD_DETECTION       57
#define BBLOG_TCP_TIMELY_WORK         58
#define BBLOG_TCP_LOG_USER_EVENT      59
#define BBLOG_TCP_LOG_SENDFILE        60
#define BBLOG_TCP_LOG_HTTP_T          61
#define BBLOG_TCP_LOG_ACCOUNTING      62
#define BBLOG_TCP_LOG_FSB             63
#define BBLOG_RACK_DSACK_HANDLING     64
#define BBLOG_TCP_HYSTART             65
#define BBLOG_TCP_CHG_QUERY           66
#define BBLOG_TCP_RACK_LOG_COLLAPSE   67
#define TCP_RACK_TP_TRIGGERED         68
#define TCP_HYBRID_PACING_LOG         69
#define TCP_LOG_PRU                   70
#define BBLOG_TCP_LOG_END             71

static const value_string event_identifier_values[] = {
  { BBLOG_TCP_LOG_IN,              "Incoming packet" },
  { BBLOG_TCP_LOG_OUT,             "Transmit (without other event)" },
  { BBLOG_TCP_LOG_TIMER,           "Timer" },
  { BBLOG_TCP_LOG_SB_WAKE,         "Awaken socket buffer" },
  { BBLOG_TCP_LOG_BAD_RETRAN,      "Detected bad retransmission" },
  { BBLOG_TCP_LOG_PRR,             "Doing PRR" },
  { BBLOG_TCP_LOG_REORDER,         "Detected reorder" },
  { BBLOG_TCP_LOG_HPTS,            "Hpts sending a packet" },
  { BBLOG_BBR_LOG_BBRUPD,          "We updated BBR info" },
  { BBLOG_BBR_LOG_BBRSND,          "We did a slot calculation and sending is done" },
  { BBLOG_BBR_LOG_ACKCLEAR,        "An ack clears all outstanding" },
  { BBLOG_BBR_LOG_INQUEUE,         "The tcb had a packet input to it" },
  { BBLOG_BBR_LOG_TIMERSTAR,       "Start a timer" },
  { BBLOG_BBR_LOG_TIMERCANC,       "Cancel a timer" },
  { BBLOG_BBR_LOG_ENTREC,          "Entered recovery" },
  { BBLOG_BBR_LOG_EXITREC,         "Exited recovery" },
  { BBLOG_BBR_LOG_CWND,            "Cwnd change" },
  { BBLOG_BBR_LOG_BWSAMP,          "LT B/W sample has been made" },
  { BBLOG_BBR_LOG_MSGSIZE,         "We received a EMSGSIZE error" },
  { BBLOG_BBR_LOG_BBRRTT,          "BBR RTT is updated" },
  { BBLOG_BBR_LOG_JUSTRET,         "We just returned out of output" },
  { BBLOG_BBR_LOG_STATE,           "A BBR state change occurred" },
  { BBLOG_BBR_LOG_PKT_EPOCH,       "A BBR packet epoch occurred" },
  { BBLOG_BBR_LOG_PERSIST,         "BBR changed to/from a persists" },
  { BBLOG_TCP_LOG_FLOWEND,         "End of a flow" },
  { BBLOG_BBR_LOG_RTO,             "BBR's timeout includes BBR info" },
  { BBLOG_BBR_LOG_DOSEG_DONE,      "hpts do_segment completes" },
  { BBLOG_BBR_LOG_EXIT_GAIN,       "BBR exiting gain" },
  { BBLOG_BBR_LOG_THRESH_CALC,     "Doing threshold calculation" },
  { BBLOG_TCP_LOG_MAPCHG,          "Map Changes to the sendmap" },
  { BBLOG_TCP_LOG_USERSEND,        "User level sends data" },
  { BBLOG_BBR_RSM_CLEARED,         "RSM cleared of ACK flags" },
  { BBLOG_BBR_LOG_STATE_TARGET,    "Log of target at state" },
  { BBLOG_BBR_LOG_TIME_EPOCH,      "A timed based Epoch occurred" },
  { BBLOG_BBR_LOG_TO_PROCESS,      "A timeout was processed" },
  { BBLOG_BBR_LOG_BBRTSO,          "TSO update" },
  { BBLOG_BBR_LOG_HPTSDIAG,        "HPTS diag insert" },
  { BBLOG_BBR_LOG_LOWGAIN,         "Low gain accounting" },
  { BBLOG_BBR_LOG_PROGRESS,        "Progress timer event" },
  { BBLOG_TCP_LOG_SOCKET_OPT,      "A socket option is set" },
  { BBLOG_BBR_LOG_TIMERPREP,       "A BBR var to debug out TLP issues" },
  { BBLOG_BBR_LOG_ENOBUF_JMP,      "We had a ENOBUF jump" },
  { BBLOG_BBR_LOG_HPTSI_CALC,      "calc the hptsi time" },
  { BBLOG_BBR_LOG_RTT_SHRINKS,     "We had a log reduction of rttProp" },
  { BBLOG_BBR_LOG_BW_RED_EV,       "B/W reduction events" },
  { BBLOG_BBR_LOG_REDUCE,          "old bbr log reduce for 4.1 and earlier" },
  { BBLOG_TCP_LOG_RTT,             "A RTT (in useconds) is being sampled and applied to the SRTT algorithm" },
  { BBLOG_BBR_LOG_SETTINGS_CHG,    "Settings changed for loss response 48" },
  { BBLOG_BBR_LOG_SRTT_GAIN_EVENT, "SRTT gaining -- now not used" },
  { BBLOG_TCP_LOG_REASS,           "Reassembly buffer logging" },
  { BBLOG_TCP_HDWR_TLS,            "TCP Hardware TLS logs" },
  { BBLOG_BBR_LOG_HDWR_PACE,       "TCP Hardware pacing log" },
  { BBLOG_BBR_LOG_TSTMP_VAL,       "Temp debug timestamp validation" },
  { BBLOG_TCP_LOG_CONNEND,         "End of connection" },
  { BBLOG_TCP_LOG_LRO,             "LRO entry" },
  { BBLOG_TCP_SACK_FILTER_RES,     "Results of SACK Filter" },
  { BBLOG_TCP_SAD_DETECTION,       "Sack Attack Detection" },
  { BBLOG_TCP_TIMELY_WORK,         "Logs regarding Timely CC tweaks" },
  { BBLOG_TCP_LOG_USER_EVENT,      "User space event data" },
  { BBLOG_TCP_LOG_SENDFILE,        "sendfile() logging for TCP connections" },
  { BBLOG_TCP_LOG_HTTP_T,          "logging of http request tracking" },
  { BBLOG_TCP_LOG_ACCOUNTING,      "Log of TCP Accounting data" },
  { BBLOG_TCP_LOG_FSB,             "FSB information" },
  { BBLOG_RACK_DSACK_HANDLING,     "Handling of DSACK in rack for reordering window" },
  { BBLOG_TCP_HYSTART,             "TCP Hystart logging" },
  { BBLOG_TCP_CHG_QUERY,           "Change query during fnc_init()" },
  { BBLOG_TCP_RACK_LOG_COLLAPSE,   "Window collapse by peer" },
  { TCP_RACK_TP_TRIGGERED,         "A RACK tracepoint is triggered" },
  { TCP_HYBRID_PACING_LOG,         "Hybrid pacing log" },
  { TCP_LOG_PRU,                   "TCP protocol user request" },
  { 0,                             NULL } };

/*
 * The event flag values used here are defined in
 * https://cgit.freebsd.org/src/tree/sys/netinet/tcp_log_buf.h
 */

#define BBLOG_EVENT_FLAG_RXBUF              0x0001
#define BBLOG_EVENT_FLAG_TXBUF              0x0002
#define BBLOG_EVENT_FLAG_HDR                0x0004
#define BBLOG_EVENT_FLAG_VERBOSE            0x0008
#define BBLOG_EVENT_FLAG_STACKINFO          0x0010

/*
 * The t_flags values used here are defined in
 * https://cgit.freebsd.org/src/tree/sys/netinet/tcp_var.h
 */

#define BBLOG_T_FLAGS_ACKNOW                0x00000001
#define BBLOG_T_FLAGS_DELACK                0x00000002
#define BBLOG_T_FLAGS_NODELAY               0x00000004
#define BBLOG_T_FLAGS_NOOPT                 0x00000008
#define BBLOG_T_FLAGS_SENTFIN               0x00000010
#define BBLOG_T_FLAGS_REQ_SCALE             0x00000020
#define BBLOG_T_FLAGS_RCVD_SCALE            0x00000040
#define BBLOG_T_FLAGS_REQ_TSTMP             0x00000080
#define BBLOG_T_FLAGS_RCVD_TSTMP            0x00000100
#define BBLOG_T_FLAGS_SACK_PERMIT           0x00000200
#define BBLOG_T_FLAGS_NEEDSYN               0x00000400
#define BBLOG_T_FLAGS_NEEDFIN               0x00000800
#define BBLOG_T_FLAGS_NOPUSH                0x00001000
#define BBLOG_T_FLAGS_PREVVALID             0x00002000
#define BBLOG_T_FLAGS_WAKESOR               0x00004000
#define BBLOG_T_FLAGS_GPUTINPROG            0x00008000
#define BBLOG_T_FLAGS_MORETOCOME            0x00010000
#define BBLOG_T_FLAGS_LQ_OVERFLOW           0x00020000
#define BBLOG_T_FLAGS_LASTIDLE              0x00040000
#define BBLOG_T_FLAGS_RXWIN0SENT            0x00080000
#define BBLOG_T_FLAGS_FASTRECOVERY          0x00100000
#define BBLOG_T_FLAGS_WASFRECOVERY          0x00200000
#define BBLOG_T_FLAGS_SIGNATURE             0x00400000
#define BBLOG_T_FLAGS_FORCEDATA             0x00800000
#define BBLOG_T_FLAGS_TSO                   0x01000000
#define BBLOG_T_FLAGS_TOE                   0x02000000
#define BBLOG_T_FLAGS_UNUSED0               0x04000000
#define BBLOG_T_FLAGS_UNUSED1               0x08000000
#define BBLOG_T_FLAGS_LRD                   0x10000000
#define BBLOG_T_FLAGS_CONGRECOVERY          0x20000000
#define BBLOG_T_FLAGS_WASCRECOVERY          0x40000000
#define BBLOG_T_FLAGS_FASTOPEN              0x80000000

/*
 * The t_flags2 values used here are defined in
 * https://cgit.freebsd.org/src/tree/sys/netinet/tcp_var.h
 */

#define BBLOG_T_FLAGS2_PLPMTU_BLACKHOLE     0x00000001
#define BBLOG_T_FLAGS2_PLPMTU_PMTUD         0x00000002
#define BBLOG_T_FLAGS2_PLPMTU_MAXSEGSNT     0x00000004
#define BBLOG_T_FLAGS2_LOG_AUTO             0x00000008
#define BBLOG_T_FLAGS2_DROP_AFTER_DATA      0x00000010
#define BBLOG_T_FLAGS2_ECN_PERMIT           0x00000020
#define BBLOG_T_FLAGS2_ECN_SND_CWR          0x00000040
#define BBLOG_T_FLAGS2_ECN_SND_ECE          0x00000080
#define BBLOG_T_FLAGS2_ACE_PERMIT           0x00000100
#define BBLOG_T_FLAGS2_FIRST_BYTES_COMPLETE 0x00000400

#define BBLOG_SND_SCALE_MASK 0x0f
#define BBLOG_RCV_SCALE_MASK 0xf0

/*
 * The errno values used here are defined in
 * https://cgit.freebsd.org/src/tree/sys/sys/errno.h
 */

#define BBLOG_ERRNO_UNKNOWN         -1
#define BBLOG_ERRNO_NOERROR          0
#define BBLOG_ERRNO_EPERM            1
#define BBLOG_ERRNO_ENOENT           2
#define BBLOG_ERRNO_ESRCH            3
#define BBLOG_ERRNO_EINTR            4
#define BBLOG_ERRNO_EIO              5
#define BBLOG_ERRNO_ENXIO            6
#define BBLOG_ERRNO_E2BIG            7
#define BBLOG_ERRNO_ENOEXEC          8
#define BBLOG_ERRNO_EBADF            9
#define BBLOG_ERRNO_ECHILD          10
#define BBLOG_ERRNO_EDEADLK         11
#define BBLOG_ERRNO_ENOMEM          12
#define BBLOG_ERRNO_EACCES          13
#define BBLOG_ERRNO_EFAULT          14
#define BBLOG_ERRNO_ENOTBLK         15
#define BBLOG_ERRNO_EBUSY           16
#define BBLOG_ERRNO_EEXIST          17
#define BBLOG_ERRNO_EXDEV           18
#define BBLOG_ERRNO_ENODEV          19
#define BBLOG_ERRNO_ENOTDIR         20
#define BBLOG_ERRNO_EISDIR          21
#define BBLOG_ERRNO_EINVAL          22
#define BBLOG_ERRNO_ENFILE          23
#define BBLOG_ERRNO_EMFILE          24
#define BBLOG_ERRNO_ENOTTY          25
#define BBLOG_ERRNO_ETXTBSY         26
#define BBLOG_ERRNO_EFBIG           27
#define BBLOG_ERRNO_ENOSPC          28
#define BBLOG_ERRNO_ESPIPE          29
#define BBLOG_ERRNO_EROFS           30
#define BBLOG_ERRNO_EMLINK          31
#define BBLOG_ERRNO_EPIPE           32
#define BBLOG_ERRNO_EDOM            33
#define BBLOG_ERRNO_ERANGE          34
#define BBLOG_ERRNO_EAGAIN          35
#define BBLOG_ERRNO_EWOULDBLOCK     35
#define BBLOG_ERRNO_EAGAIN          35
#define BBLOG_ERRNO_EINPROGRESS     36
#define BBLOG_ERRNO_EALREADY        37
#define BBLOG_ERRNO_ENOTSOCK        38
#define BBLOG_ERRNO_EDESTADDRREQ    39
#define BBLOG_ERRNO_EMSGSIZE        40
#define BBLOG_ERRNO_EPROTOTYPE      41
#define BBLOG_ERRNO_ENOPROTOOPT     42
#define BBLOG_ERRNO_EPROTONOSUPPORT 43
#define BBLOG_ERRNO_ESOCKTNOSUPPORT 44
#define BBLOG_ERRNO_EOPNOTSUPP      45
#define BBLOG_ERRNO_EPFNOSUPPORT    46
#define BBLOG_ERRNO_EAFNOSUPPORT    47
#define BBLOG_ERRNO_EADDRINUSE      48
#define BBLOG_ERRNO_EADDRNOTAVAIL   49
#define BBLOG_ERRNO_ENETDOWN        50
#define BBLOG_ERRNO_ENETUNREACH     51
#define BBLOG_ERRNO_ENETRESET       52
#define BBLOG_ERRNO_ECONNABORTED    53
#define BBLOG_ERRNO_ECONNRESET      54
#define BBLOG_ERRNO_ENOBUFS         55
#define BBLOG_ERRNO_EISCONN         56
#define BBLOG_ERRNO_ENOTCONN        57
#define BBLOG_ERRNO_ESHUTDOWN       58
#define BBLOG_ERRNO_ETOOMANYREFS    59
#define BBLOG_ERRNO_ETIMEDOUT       60
#define BBLOG_ERRNO_ECONNREFUSED    61
#define BBLOG_ERRNO_ELOOP           62
#define BBLOG_ERRNO_ENAMETOOLONG    63
#define BBLOG_ERRNO_EHOSTDOWN       64
#define BBLOG_ERRNO_EHOSTUNREACH    65
#define BBLOG_ERRNO_ENOTEMPTY       66
#define BBLOG_ERRNO_EPROCLIM        67
#define BBLOG_ERRNO_EUSERS          68
#define BBLOG_ERRNO_EDQUOT          69
#define BBLOG_ERRNO_ESTALE          70
#define BBLOG_ERRNO_EREMOTE         71
#define BBLOG_ERRNO_EBADRPC         72
#define BBLOG_ERRNO_ERPCMISMATCH    73
#define BBLOG_ERRNO_EPROGUNAVAIL    74
#define BBLOG_ERRNO_EPROGMISMATCH   75
#define BBLOG_ERRNO_EPROCUNAVAIL    76
#define BBLOG_ERRNO_ENOLCK          77
#define BBLOG_ERRNO_ENOSYS          78
#define BBLOG_ERRNO_EFTYPE          79
#define BBLOG_ERRNO_EAUTH           80
#define BBLOG_ERRNO_ENEEDAUTH       81
#define BBLOG_ERRNO_EIDRM           82
#define BBLOG_ERRNO_ENOMSG          83
#define BBLOG_ERRNO_EOVERFLOW       84
#define BBLOG_ERRNO_ECANCELED       85
#define BBLOG_ERRNO_EILSEQ          86
#define BBLOG_ERRNO_ENOATTR         87
#define BBLOG_ERRNO_EDOOFUS         88
#define BBLOG_ERRNO_EBADMSG         89
#define BBLOG_ERRNO_EMULTIHOP       90
#define BBLOG_ERRNO_ENOLINK         91
#define BBLOG_ERRNO_EPROTO          92
#define BBLOG_ERRNO_ENOTCAPABLE     93
#define BBLOG_ERRNO_ECAPMODE        94
#define BBLOG_ERRNO_ENOTRECOVERABLE 95
#define BBLOG_ERRNO_EOWNERDEAD      96
#define BBLOG_ERRNO_EINTEGRITY      97

static const value_string errno_values[] = {
  { BBLOG_ERRNO_UNKNOWN,            "Not known" },
  { BBLOG_ERRNO_NOERROR,            "No error" },
  { BBLOG_ERRNO_EPERM,              "EPERM (Operation not permitted)" },
  { BBLOG_ERRNO_ENOENT,             "ENOENT (No such file or directory)" },
  { BBLOG_ERRNO_ESRCH,              "ESRCH (No such process)" },
  { BBLOG_ERRNO_EINTR,              "EINTR (Interrupted system call)" },
  { BBLOG_ERRNO_EIO,                "EIO (Input/output error)" },
  { BBLOG_ERRNO_ENXIO,              "ENXIO (Device not configured)" },
  { BBLOG_ERRNO_E2BIG,              "E2BIG (Argument list too long)" },
  { BBLOG_ERRNO_ENOEXEC,            "ENOEXEC (Exec format error)" },
  { BBLOG_ERRNO_EBADF,              "EBADF (Bad file descriptor)" },
  { BBLOG_ERRNO_ECHILD,             "ECHILD (No child processes)" },
  { BBLOG_ERRNO_EDEADLK,            "EDEADLK (Resource deadlock avoided)" },
  { BBLOG_ERRNO_ENOMEM,             "ENOMEM (Cannot allocate memory)" },
  { BBLOG_ERRNO_EACCES,             "EACCES (Permission denied)" },
  { BBLOG_ERRNO_EFAULT,             "EFAULT (Bad address)" },
  { BBLOG_ERRNO_ENOTBLK,            "ENOTBLK (Block device required)" },
  { BBLOG_ERRNO_EBUSY,              "EBUSY (Device busy)" },
  { BBLOG_ERRNO_EEXIST,             "EEXIST (File exists)" },
  { BBLOG_ERRNO_EXDEV,              "EXDEV (Cross-device link)" },
  { BBLOG_ERRNO_ENODEV,             "ENODEV (Operation not supported by device)" },
  { BBLOG_ERRNO_ENOTDIR,            "ENOTDIR (Not a directory)" },
  { BBLOG_ERRNO_EISDIR,             "EISDIR (Is a directory)" },
  { BBLOG_ERRNO_EINVAL,             "EINVAL (Invalid argument)" },
  { BBLOG_ERRNO_ENFILE,             "ENFILE (Too many open files in system)" },
  { BBLOG_ERRNO_EMFILE,             "EMFILE (Too many open files)" },
  { BBLOG_ERRNO_ENOTTY,             "ENOTTY (Inappropriate ioctl for device)" },
  { BBLOG_ERRNO_ETXTBSY,            "ETXTBSY (Text file busy)" },
  { BBLOG_ERRNO_EFBIG,              "EFBIG (File too large)" },
  { BBLOG_ERRNO_ENOSPC,             "ENOSPC (No space left on device)" },
  { BBLOG_ERRNO_ESPIPE,             "ESPIPE (Illegal seek)" },
  { BBLOG_ERRNO_EROFS,              "EROFS (Read-only filesystem)" },
  { BBLOG_ERRNO_EMLINK,             "EMLINK (Too many links)" },
  { BBLOG_ERRNO_EPIPE,              "EPIPE (Broken pipe)" },
  { BBLOG_ERRNO_EDOM,               "EDOM (Numerical argument out of domain)" },
  { BBLOG_ERRNO_ERANGE,             "ERANGE (Result too large)" },
  { BBLOG_ERRNO_EWOULDBLOCK,        "EWOULDBLOCK (Operation would block)" },
  { BBLOG_ERRNO_EINPROGRESS,        "EINPROGRESS (Operation now in progress)" },
  { BBLOG_ERRNO_EALREADY,           "EALREADY (Operation already in progress)" },
  { BBLOG_ERRNO_ENOTSOCK,           "ENOTSOCK (Socket operation on non-socket)" },
  { BBLOG_ERRNO_EDESTADDRREQ,       "EDESTADDRREQ (Destination address required)" },
  { BBLOG_ERRNO_EMSGSIZE,           "EMSGSIZE (Message too long)" },
  { BBLOG_ERRNO_EPROTOTYPE,         "EPROTOTYPE (Protocol wrong type for sockets)" },
  { BBLOG_ERRNO_ENOPROTOOPT,        "ENOPROTOOPT (Protocol not available)" },
  { BBLOG_ERRNO_EPROTONOSUPPORT,    "EPROTONOSUPPORT (Protocol not supported)" },
  { BBLOG_ERRNO_ESOCKTNOSUPPORT,    "ESOCKTNOSUPPORT (Socket type not supported)" },
  { BBLOG_ERRNO_EOPNOTSUPP,         "EOPNOTSUPP (Operation not supported)" },
  { BBLOG_ERRNO_EPFNOSUPPORT,       "EPFNOSUPPORT (Protocol family not supported)" },
  { BBLOG_ERRNO_EAFNOSUPPORT,       "EAFNOSUPPORT (Address family not supported by protocol family)" },
  { BBLOG_ERRNO_EADDRINUSE,         "EADDRINUSE (Address already in use)" },
  { BBLOG_ERRNO_EADDRNOTAVAIL,      "EADDRNOTAVAIL (Can't assign requested address)" },
  { BBLOG_ERRNO_ENETDOWN,           "ENETDOWN (Network is down)" },
  { BBLOG_ERRNO_ENETUNREACH,        "ENETUNREACH (Network is unreachable)" },
  { BBLOG_ERRNO_ENETRESET,          "ENETRESET (Network dropped connection on reset)" },
  { BBLOG_ERRNO_ECONNABORTED,       "ECONNABORTED (Software caused connection abort)" },
  { BBLOG_ERRNO_ECONNRESET,         "ECONNRESET (Connection reset by peer)" },
  { BBLOG_ERRNO_ENOBUFS,            "ENOBUFS (No buffer space available)" },
  { BBLOG_ERRNO_EISCONN,            "EISCONN (Socket is already connected)" },
  { BBLOG_ERRNO_ENOTCONN,           "ENOTCONN (Socket is not connected)" },
  { BBLOG_ERRNO_ESHUTDOWN,          "ESHUTDOWN (Can't send after socket shutdown)" },
  { BBLOG_ERRNO_ETOOMANYREFS,       "ETOOMANYREFS (Too many references: can't splice)" },
  { BBLOG_ERRNO_ETIMEDOUT,          "ETIMEDOUT (Operation timed out)" },
  { BBLOG_ERRNO_ECONNREFUSED,       "ECONNREFUSED (Connection refused)" },
  { BBLOG_ERRNO_ELOOP,              "ELOOP (Too many levels of symbolic links)" },
  { BBLOG_ERRNO_ENAMETOOLONG,       "ENAMETOOLONG (File name too long)" },
  { BBLOG_ERRNO_EHOSTDOWN,          "EHOSTDOWN (Host is down)" },
  { BBLOG_ERRNO_EHOSTUNREACH,       "EHOSTUNREACH (No route to host)" },
  { BBLOG_ERRNO_ENOTEMPTY,          "ENOTEMPTY (Directory not empty)" },
  { BBLOG_ERRNO_EPROCLIM,           "EPROCLIM (Too many processes)" },
  { BBLOG_ERRNO_EUSERS,             "EUSERS (Too many users)" },
  { BBLOG_ERRNO_EDQUOT,             "EDQUOT (Disc quota exceeded)" },
  { BBLOG_ERRNO_ESTALE,             "ESTALE (Stale NFS file handle)" },
  { BBLOG_ERRNO_EREMOTE,            "EREMOTE (Too many levels of remote in path)" },
  { BBLOG_ERRNO_EBADRPC,            "EBADRPC (RPC struct is bad)" },
  { BBLOG_ERRNO_ERPCMISMATCH,       "ERPCMISMATCH (RPC version wrong)" },
  { BBLOG_ERRNO_EPROGUNAVAIL,       "EPROGUNAVAIL (RPC prog. not avail)" },
  { BBLOG_ERRNO_EPROGMISMATCH,      "EPROGMISMATCH (Program version wrong)" },
  { BBLOG_ERRNO_EPROCUNAVAIL,       "EPROCUNAVAIL (Bad procedure for program)" },
  { BBLOG_ERRNO_ENOLCK,             "ENOLCK (No locks available)" },
  { BBLOG_ERRNO_ENOSYS,             "ENOSYS (Function not implemented)" },
  { BBLOG_ERRNO_EFTYPE,             "EFTYPE (Inappropriate file type or format)" },
  { BBLOG_ERRNO_EAUTH,              "EAUTH (Authentication error)" },
  { BBLOG_ERRNO_ENEEDAUTH,          "ENEEDAUTH (Need authenticator)" },
  { BBLOG_ERRNO_EIDRM,              "EIDRM (Identifier removed)" },
  { BBLOG_ERRNO_ENOMSG,             "ENOMSG (No message of desired type)" },
  { BBLOG_ERRNO_EOVERFLOW,          "EOVERFLOW (Value too large to be stored in data type)" },
  { BBLOG_ERRNO_ECANCELED,          "ECANCELED (Operation canceled)" },
  { BBLOG_ERRNO_EILSEQ,             "EILSEQ (Illegal byte sequence)" },
  { BBLOG_ERRNO_ENOATTR,            "ENOATTR (Attribute not found)" },
  { BBLOG_ERRNO_EDOOFUS,            "EDOOFUS (Programming error)" },
  { BBLOG_ERRNO_EBADMSG,            "EBADMSG (Bad message)" },
  { BBLOG_ERRNO_EMULTIHOP,          "EMULTIHOP (Multihop attempted)" },
  { BBLOG_ERRNO_ENOLINK,            "ENOLINK (Link has been severed)" },
  { BBLOG_ERRNO_EPROTO,             "EPROTO (Protocol error)" },
  { BBLOG_ERRNO_ENOTCAPABLE,        "ENOTCAPABLE (Capabilities insufficient)" },
  { BBLOG_ERRNO_ECAPMODE,           "ECAPMODE (Not permitted in capability mode)" },
  { BBLOG_ERRNO_ENOTRECOVERABLE,    "ENOTRECOVERABLE (State not recoverable)" },
  { BBLOG_ERRNO_EOWNERDEAD,         "EOWNERDEAD (Previous owner died)" },
  { BBLOG_ERRNO_EINTEGRITY,         "EINTEGRITY (Integrity check failed)" },
  { 0,                              NULL } };

#endif
